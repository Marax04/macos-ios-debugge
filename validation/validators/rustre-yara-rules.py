#!/usr/bin/env python3
"""
Standalone validator for the `rustre-yara-rules` crate.

Reimplements deterministic, externally-testable helpers (YARA rule-text
parsing, metadata extraction, severity/category mapping, saturating casts,
quality scoring, FP/detection-rate estimation, repo stats) in pure Python
(stdlib only) so the Rust crate can be cross-checked.

Based on: validation/reports/rustre-yara-rules.md

Usage:
    echo '{"fn":"parse_metadata_from_yara","text":"rule x { meta: author = \"a\" condition: true }"}' \
        | python rustre-yara-rules.py
    python rustre-yara-rules.py             # built-in self-test
"""

import hashlib
import json
import re
import sys
from typing import Any


# ---------------------------------------------------------------------------
# casts.rs — saturating numeric casts
# ---------------------------------------------------------------------------

_U32_MAX = 0xFFFF_FFFF
_U64_MAX = 0xFFFF_FFFF_FFFF_FFFF
_U8_MAX = 0xFF
_I32_MIN, _I32_MAX = -0x8000_0000, 0x7FFF_FFFF


def usize_to_f64(x: int) -> float:
    return float(x)


def u64_to_f64(x: int) -> float:
    return float(x & _U64_MAX)


def f64_to_u32_sat(x: float) -> int:
    if x != x:  # NaN
        return 0
    if x <= 0.0:
        return 0
    if x >= float(_U32_MAX):
        return _U32_MAX
    return int(x)


def i32_to_u8_sat(x: int) -> int:
    if x < 0:
        return 0
    if x > _U8_MAX:
        return _U8_MAX
    return x


def usize_to_i32_sat(x: int) -> int:
    if x > _I32_MAX:
        return _I32_MAX
    return x


def usize_to_u32_sat(x: int) -> int:
    if x > _U32_MAX:
        return _U32_MAX
    return x


def u64_to_u8_sat(x: int) -> int:
    x &= _U64_MAX
    return x if x <= _U8_MAX else _U8_MAX


def u128_to_u64_sat(x: int) -> int:
    return x if x <= _U64_MAX else _U64_MAX


# ---------------------------------------------------------------------------
# rule_metadata.rs — parse_metadata_from_yara / validate_metadata
# ---------------------------------------------------------------------------

_RULE_HEADER_RE = re.compile(
    r"\brule\s+([A-Za-z_][A-Za-z0-9_]*)\s*(?::\s*([A-Za-z0-9_ \t]+))?\s*\{",
)
_META_BLOCK_RE = re.compile(r"\bmeta\s*:\s*(.*?)(?=\b(?:strings|condition)\s*:)",
                            re.DOTALL)
_META_KV_STRING_RE = re.compile(r'([A-Za-z_][A-Za-z0-9_]*)\s*=\s*"((?:[^"\\]|\\.)*)"')
_META_KV_NUM_RE = re.compile(r'([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(-?\d+)')
_META_KV_BOOL_RE = re.compile(r'([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(true|false)\b')


def parse_metadata_from_yara(text: str, source_name: str | None = None) -> dict | None:
    """Mirror of `parse_metadata_from_yara(rule_text, source_name) -> Option<RuleMetadata>`.

    Returns None if no `rule NAME { ... }` header is found.
    """
    m = _RULE_HEADER_RE.search(text)
    if not m:
        return None
    name = m.group(1)
    tags_str = m.group(2) or ""
    tags = [t for t in tags_str.split() if t]

    meta: dict[str, Any] = {}
    mb = _META_BLOCK_RE.search(text)
    if mb:
        block = mb.group(1)
        for k, v in _META_KV_STRING_RE.findall(block):
            meta[k] = bytes(v, "utf-8").decode("unicode_escape")
        for k, v in _META_KV_NUM_RE.findall(block):
            meta.setdefault(k, int(v))
        for k, v in _META_KV_BOOL_RE.findall(block):
            meta.setdefault(k, v == "true")

    return {
        "name": name,
        "tags": tags,
        "source": source_name,
        "meta": meta,
        "author": meta.get("author"),
        "description": meta.get("description"),
        "reference": meta.get("reference"),
        "date": meta.get("date"),
        "hash": meta.get("hash"),
        "tlp": _normalize_tlp(meta.get("tlp")),
        "severity": _severity_from_meta(meta),
    }


def _normalize_tlp(v: Any) -> str | None:
    if not isinstance(v, str):
        return None
    s = v.strip().upper().replace("TLP:", "").strip()
    return s if s in {"RED", "AMBER", "GREEN", "WHITE", "CLEAR"} else None


def _severity_from_meta(meta: dict) -> str:
    s = meta.get("severity")
    if isinstance(s, str):
        s = s.strip().lower()
        if s in {"critical", "high", "medium", "low", "info"}:
            return s
    score = meta.get("score")
    if isinstance(score, int):
        if score >= 90: return "critical"
        if score >= 70: return "high"
        if score >= 40: return "medium"
        if score >= 10: return "low"
        return "info"
    return "info"


def validate_metadata(meta: dict) -> list[dict]:
    """Mirror of `validate_metadata(meta) -> Vec<ValidationIssue>`.

    Issues: missing required fields (author, description, reference, date),
    bad TLP, name not snake-or-PascalCase.
    """
    issues: list[dict] = []
    name = meta.get("name", "")
    if not re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", name):
        issues.append({"severity": "error", "field": "name",
                       "msg": "invalid rule identifier"})
    for field in ("author", "description", "reference", "date"):
        if not meta.get(field):
            issues.append({"severity": "warn", "field": field,
                           "msg": f"missing recommended field `{field}`"})
    tlp = meta.get("tlp")
    if tlp is not None and tlp not in {"RED", "AMBER", "GREEN", "WHITE", "CLEAR"}:
        issues.append({"severity": "error", "field": "tlp",
                       "msg": "invalid TLP level"})
    return issues


# ---------------------------------------------------------------------------
# rule_compiler.rs — minimal YARA rule tokenizer (header + strings + condition)
# ---------------------------------------------------------------------------

_STRINGS_BLOCK_RE = re.compile(
    r"\bstrings\s*:\s*(.*?)(?=\bcondition\s*:)", re.DOTALL,
)
_COND_BLOCK_RE = re.compile(r"\bcondition\s*:\s*(.*?)\}\s*$", re.DOTALL)
_STR_DECL_RE = re.compile(
    r'(\$[A-Za-z0-9_]*)\s*=\s*(?:"((?:[^"\\]|\\.)*)"|\{([0-9A-Fa-f ?\-\[\]]+)\}|/((?:[^/\\]|\\.)*)/)'
    r"([a-z]*)"
)


def parse_yara_rule(text: str) -> dict | None:
    """Minimal parse: returns {name, tags, strings:[{id,kind,value,modifiers}], condition}."""
    m = _RULE_HEADER_RE.search(text)
    if not m:
        return None
    name, tags_str = m.group(1), m.group(2) or ""
    tags = [t for t in tags_str.split() if t]

    strings: list[dict] = []
    sb = _STRINGS_BLOCK_RE.search(text)
    if sb:
        for ident, sval, hval, rval, mods in _STR_DECL_RE.findall(sb.group(1)):
            if sval or (not hval and not rval):
                kind, value = "text", sval
            elif hval:
                kind, value = "hex", re.sub(r"\s+", "", hval)
            else:
                kind, value = "regex", rval
            strings.append({
                "id": ident,
                "kind": kind,
                "value": value,
                "modifiers": sorted(set(mods)),
            })

    cb = _COND_BLOCK_RE.search(text)
    condition = cb.group(1).strip() if cb else ""

    return {"name": name, "tags": tags, "strings": strings, "condition": condition}


# ---------------------------------------------------------------------------
# rule_testing.rs — estimate_fp_rate / estimate_detection_rate / quality_score
# ---------------------------------------------------------------------------

def _rule_matches_sample(rule_text: str, sample: bytes) -> bool:
    """Best-effort: a rule matches a sample iff at least one text string occurs
    or any hex pattern (without wildcards) occurs verbatim."""
    parsed = parse_yara_rule(rule_text)
    if not parsed or not parsed["strings"]:
        return False
    for s in parsed["strings"]:
        if s["kind"] == "text":
            try:
                if s["value"].encode("utf-8") in sample:
                    return True
            except UnicodeEncodeError:
                continue
        elif s["kind"] == "hex" and "?" not in s["value"]:
            try:
                if bytes.fromhex(s["value"]) in sample:
                    return True
            except ValueError:
                continue
    return False


def estimate_fp_rate(rule_text: str, benign_samples: list[bytes]) -> float:
    if not benign_samples:
        return 0.0
    hits = sum(1 for s in benign_samples if _rule_matches_sample(rule_text, s))
    return hits / len(benign_samples)


def estimate_detection_rate(rule_text: str, malicious_samples: list[bytes]) -> float:
    if not malicious_samples:
        return 0.0
    hits = sum(1 for s in malicious_samples if _rule_matches_sample(rule_text, s))
    return hits / len(malicious_samples)


def compute_quality_score(fp_rate: float, detection_rate: float,
                          string_count: int) -> dict:
    """Mirror of `compute_quality_score(...)`: weighted blend in [0, 100]."""
    fp_rate = max(0.0, min(1.0, fp_rate))
    detection_rate = max(0.0, min(1.0, detection_rate))
    structure = min(1.0, string_count / 4.0)
    score = 100.0 * (0.55 * detection_rate + 0.30 * (1.0 - fp_rate) + 0.15 * structure)
    if   score >= 85: grade = "A"
    elif score >= 70: grade = "B"
    elif score >= 50: grade = "C"
    elif score >= 30: grade = "D"
    else:             grade = "F"
    return {"score": round(score, 2), "grade": grade,
            "fp_rate": fp_rate, "detection_rate": detection_rate,
            "string_count": string_count}


# ---------------------------------------------------------------------------
# rule_db.rs / rule_repository.rs — repo stats + filtering
# ---------------------------------------------------------------------------

def repo_stats(entries: list[dict]) -> dict:
    by_cat: dict[str, int] = {}
    by_sev: dict[str, int] = {}
    for e in entries:
        by_cat[e.get("category", "unknown")] = by_cat.get(e.get("category", "unknown"), 0) + 1
        by_sev[e.get("severity", "info")] = by_sev.get(e.get("severity", "info"), 0) + 1
    return {
        "total": len(entries),
        "by_category": dict(sorted(by_cat.items())),
        "by_severity": dict(sorted(by_sev.items())),
    }


def filter_rules(entries: list[dict], flt: dict) -> list[dict]:
    cats = set(flt.get("categories") or [])
    sevs = set(flt.get("severities") or [])
    tags = set(flt.get("tags") or [])
    name_sub = (flt.get("name_contains") or "").lower()
    out = []
    for e in entries:
        if cats and e.get("category") not in cats: continue
        if sevs and e.get("severity") not in sevs: continue
        if tags and not (tags & set(e.get("tags") or [])): continue
        if name_sub and name_sub not in e.get("name", "").lower(): continue
        out.append(e)
    return out


# ---------------------------------------------------------------------------
# Content hashing (rule_repository version tracking) — sha256 of normalised text
# ---------------------------------------------------------------------------

def rule_content_hash(text: str) -> str:
    normalized = re.sub(r"\s+", " ", text).strip()
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Dispatcher
# ---------------------------------------------------------------------------

_DISPATCH = {
    "parse_metadata_from_yara":  lambda r: parse_metadata_from_yara(r["text"], r.get("source")),
    "validate_metadata":         lambda r: validate_metadata(r["meta"]),
    "parse_yara_rule":           lambda r: parse_yara_rule(r["text"]),
    "estimate_fp_rate":          lambda r: estimate_fp_rate(r["rule"], [bytes.fromhex(s) for s in r["samples"]]),
    "estimate_detection_rate":   lambda r: estimate_detection_rate(r["rule"], [bytes.fromhex(s) for s in r["samples"]]),
    "compute_quality_score":     lambda r: compute_quality_score(r["fp_rate"], r["detection_rate"], r["string_count"]),
    "repo_stats":                lambda r: repo_stats(r["entries"]),
    "filter_rules":              lambda r: filter_rules(r["entries"], r["filter"]),
    "rule_content_hash":         lambda r: rule_content_hash(r["text"]),
    "f64_to_u32_sat":            lambda r: f64_to_u32_sat(r["x"]),
    "i32_to_u8_sat":             lambda r: i32_to_u8_sat(r["x"]),
    "usize_to_u32_sat":          lambda r: usize_to_u32_sat(r["x"]),
    "u64_to_u8_sat":             lambda r: u64_to_u8_sat(r["x"]),
    "u128_to_u64_sat":           lambda r: u128_to_u64_sat(r["x"]),
}


def dispatch(req: dict) -> Any:
    fn = req.get("fn")
    if fn not in _DISPATCH:
        return {"error": f"unknown fn `{fn}`", "available": sorted(_DISPATCH)}
    return _DISPATCH[fn](req)


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------

def main() -> None:
    # If JSON arrives on stdin, run it; otherwise self-test.
    if not sys.stdin.isatty():
        data = sys.stdin.read().strip()
        if data:
            print(json.dumps(dispatch(json.loads(data)), indent=2, default=list))
            return

    results: dict[str, Any] = {}

    # 1) saturating casts
    assert f64_to_u32_sat(-1.0) == 0
    assert f64_to_u32_sat(1e20) == _U32_MAX
    assert i32_to_u8_sat(-5) == 0 and i32_to_u8_sat(300) == 255
    assert u128_to_u64_sat(2**70) == _U64_MAX
    results["casts"] = "ok"

    # 2) parse_metadata_from_yara
    rt = (
        'rule Demo_Rule : apt malware {\n'
        '  meta:\n'
        '    author = "alice"\n'
        '    description = "test"\n'
        '    reference = "https://x"\n'
        '    date = "2024-01-01"\n'
        '    tlp = "TLP:AMBER"\n'
        '    score = 80\n'
        '  strings:\n'
        '    $a = "evil"\n'
        '    $b = { DE AD BE EF }\n'
        '  condition:\n'
        '    any of them\n'
        '}\n'
    )
    md = parse_metadata_from_yara(rt, "src.yar")
    assert md and md["name"] == "Demo_Rule"
    assert md["tags"] == ["apt", "malware"]
    assert md["author"] == "alice"
    assert md["tlp"] == "AMBER"
    assert md["severity"] == "high"
    results["parse_metadata_from_yara"] = md

    # 3) validate_metadata
    issues = validate_metadata({"name": "Demo_Rule", "author": "a",
                                "description": "d", "reference": "r",
                                "date": "2024", "tlp": "BOGUS"})
    assert any(i["field"] == "tlp" for i in issues)
    results["validate_metadata"] = issues

    # 4) parse_yara_rule
    pr = parse_yara_rule(rt)
    assert pr["name"] == "Demo_Rule" and len(pr["strings"]) == 2
    assert pr["strings"][0]["kind"] == "text" and pr["strings"][0]["value"] == "evil"
    assert pr["strings"][1]["kind"] == "hex" and pr["strings"][1]["value"].upper() == "DEADBEEF"
    results["parse_yara_rule"] = pr

    # 5) FP / detection / quality
    benign = [b"hello world", b"nothing here"]
    malic  = [b"this is evil code", b"\xde\xad\xbe\xefXXX"]
    fp = estimate_fp_rate(rt, benign)
    dr = estimate_detection_rate(rt, malic)
    assert fp == 0.0 and dr == 1.0
    q = compute_quality_score(fp, dr, len(pr["strings"]))
    assert q["grade"] in {"A", "B"}
    results["quality"] = {"fp_rate": fp, "detection_rate": dr, "score": q}

    # 6) repo_stats / filter_rules
    entries = [
        {"name": "Apt1",  "category": "apt",     "severity": "high",    "tags": ["china"]},
        {"name": "Pack1", "category": "packer",  "severity": "medium",  "tags": ["upx"]},
        {"name": "Rans1", "category": "ransom",  "severity": "critical","tags": ["lockbit"]},
    ]
    rs = repo_stats(entries)
    assert rs["total"] == 3 and rs["by_category"]["apt"] == 1
    flt = filter_rules(entries, {"severities": ["high", "critical"]})
    assert {e["name"] for e in flt} == {"Apt1", "Rans1"}
    results["repo_stats"] = rs
    results["filter_rules"] = flt

    # 7) content hash determinism (whitespace-insensitive)
    h1 = rule_content_hash("rule x { condition: true }")
    h2 = rule_content_hash("rule x {\n  condition:\n    true\n}")
    assert h1 == h2
    h3 = rule_content_hash("rule y { condition: true }")
    assert h1 != h3
    results["rule_content_hash"] = {"a": h1, "b": h3}

    print(json.dumps({"self_test": "ok", "results": results}, indent=2, default=list))


if __name__ == "__main__":
    main()
