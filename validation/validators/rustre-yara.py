#!/usr/bin/env python3
"""
Independent Python validator for crate `rustre-yara`.

Reimplements core YARA-like primitives (pattern matching, hex tokens,
fullword check, xor scan, wide/nocase variants, rule-set bookkeeping,
ELF magic detection) using only Python stdlib.

Each validator_<name>(input) returns a value mirroring the expected
Rust output so the test harness can cross-check the Rust crate against
an independent oracle.

CLI:
    - `python rustre-yara.py`               -> runs main() with fixed inputs
    - `python rustre-yara.py --stdin`       -> reads JSON from stdin: {func, input}
                                                returns JSON: {output}
"""
from __future__ import annotations

import json
import re
import struct
import sys
from typing import Any


# ---------------------------------------------------------------------------
# Hex token model (mirrors HexToken variants in rustre-yara)
# ---------------------------------------------------------------------------
# A hex token is one of:
#   {"kind": "byte",     "value": int}
#   {"kind": "wildcard"}                          # ??
#   {"kind": "nibble_hi","value": int}            # ?X
#   {"kind": "nibble_lo","value": int}            # X?
#   {"kind": "jump",     "min": int, "max": int}  # [a-b]


def _parse_hex_pattern(s: str) -> list[dict]:
    """Tokenize a YARA hex string body like 'AA BB ?? [2-4] CC'."""
    tokens: list[dict] = []
    i = 0
    s = s.strip()
    while i < len(s):
        c = s[i]
        if c.isspace():
            i += 1
            continue
        if c == "[":
            j = s.index("]", i)
            inside = s[i + 1 : j].strip()
            if "-" in inside:
                a, b = inside.split("-", 1)
                tokens.append({"kind": "jump", "min": int(a), "max": int(b)})
            else:
                n = int(inside)
                tokens.append({"kind": "jump", "min": n, "max": n})
            i = j + 1
            continue
        # two-char nibble
        if i + 1 >= len(s):
            raise ValueError("dangling nibble")
        a, b = s[i], s[i + 1]
        if a == "?" and b == "?":
            tokens.append({"kind": "wildcard"})
        elif a == "?":
            tokens.append({"kind": "nibble_lo", "value": int(b, 16)})
        elif b == "?":
            tokens.append({"kind": "nibble_hi", "value": int(a, 16)})
        else:
            tokens.append({"kind": "byte", "value": int(a + b, 16)})
        i += 2
    return tokens


def _hex_match_here(tokens: list[dict], data: bytes, off: int) -> int | None:
    """Try matching the token list at exactly `off`. Returns end-offset or None.

    Jumps are non-greedy: try min..=max consecutive byte advances.
    """
    if not tokens:
        return off
    tok = tokens[0]
    rest = tokens[1:]
    k = tok["kind"]
    if k == "jump":
        for skip in range(tok["min"], tok["max"] + 1):
            if off + skip > len(data):
                continue
            r = _hex_match_here(rest, data, off + skip)
            if r is not None:
                return r
        return None
    if off >= len(data):
        return None
    b = data[off]
    ok = False
    if k == "byte":
        ok = b == tok["value"]
    elif k == "wildcard":
        ok = True
    elif k == "nibble_hi":
        ok = (b >> 4) == tok["value"]
    elif k == "nibble_lo":
        ok = (b & 0x0F) == tok["value"]
    if not ok:
        return None
    return _hex_match_here(rest, data, off + 1)


def validator_match_hex(pattern: str | list[dict], data: bytes) -> list[int]:
    """Mirror of `match_hex(pattern, data) -> Vec<usize>`. Returns offsets."""
    tokens = pattern if isinstance(pattern, list) else _parse_hex_pattern(pattern)
    hits: list[int] = []
    for off in range(0, len(data) + 1):
        if _hex_match_here(tokens, data, off) is not None:
            hits.append(off)
    return hits


# ---------------------------------------------------------------------------
# Text / nocase / wide / xor / fullword
# ---------------------------------------------------------------------------

def _find_all(haystack: bytes, needle: bytes) -> list[int]:
    out: list[int] = []
    if not needle or len(needle) > len(haystack):
        return out
    i = 0
    while True:
        off = haystack.find(needle, i)
        if off < 0:
            return out
        out.append(off)
        i = off + 1


def validator_match_text(text: str, modifiers: dict, data: bytes) -> list[int]:
    """Mirror of `match_text(text, modifiers, data)`.

    modifiers = {"nocase": bool, "wide": bool, "ascii": bool, "fullword": bool}
    """
    mods = modifiers or {}
    nocase = bool(mods.get("nocase"))
    wide = bool(mods.get("wide"))
    ascii_flag = bool(mods.get("ascii", True))  # ascii is default unless only wide
    fullword = bool(mods.get("fullword"))
    candidates: list[tuple[bytes, int]] = []  # (needle, char_stride)
    raw = text.encode("utf-8", errors="replace")
    if ascii_flag or not wide:
        candidates.append((raw, 1))
    if wide:
        wide_bytes = b"".join(bytes([b, 0]) for b in raw)
        candidates.append((wide_bytes, 2))

    hits: list[int] = []
    for needle, stride in candidates:
        if nocase:
            # scan via lowercased comparison (ASCII only)
            n_low = needle.lower()
            for off in range(0, len(data) - len(needle) + 1):
                if data[off:off + len(needle)].lower() == n_low:
                    if not fullword or _check_fullword(data, off, len(needle), stride):
                        hits.append(off)
        else:
            for off in _find_all(data, needle):
                if not fullword or _check_fullword(data, off, len(needle), stride):
                    hits.append(off)
    hits.sort()
    return hits


def validator_match_nocase(text: str, data: bytes) -> list[int]:
    return validator_match_text(text, {"nocase": True, "ascii": True}, data)


def validator_match_wide(text: str, data: bytes) -> list[int]:
    return validator_match_text(text, {"wide": True, "ascii": False}, data)


def validator_match_xor(text: str, xor_min: int, xor_max: int, data: bytes) -> list[list[int]]:
    """Mirror of `match_xor` -> Vec<(offset, key)>."""
    raw = text.encode("utf-8", errors="replace")
    out: list[list[int]] = []
    for key in range(xor_min, xor_max + 1):
        needle = bytes(b ^ key for b in raw)
        for off in _find_all(data, needle):
            out.append([off, key])
    out.sort()
    return out


def _is_wordchar(b: int) -> bool:
    return (
        (0x30 <= b <= 0x39)
        or (0x41 <= b <= 0x5A)
        or (0x61 <= b <= 0x7A)
        or b == 0x5F
    )


def _check_fullword(data: bytes, off: int, length: int, stride: int = 1) -> bool:
    """Mirror of `check_fullword(data, offset, len)`.

    stride=1 -> ASCII; stride=2 -> wide (UTF-16LE), check the ASCII byte.
    """
    if stride == 1:
        before_ok = off == 0 or not _is_wordchar(data[off - 1])
        end = off + length
        after_ok = end >= len(data) or not _is_wordchar(data[end])
        return before_ok and after_ok
    # wide: look one wide char before and after
    before_ok = off < 2 or not _is_wordchar(data[off - 2])
    end = off + length
    after_ok = end + 1 >= len(data) or not _is_wordchar(data[end])
    return before_ok and after_ok


def validator_check_fullword(data: bytes, off: int, length: int) -> bool:
    return _check_fullword(data, off, length, 1)


# ---------------------------------------------------------------------------
# Rule set bookkeeping
# ---------------------------------------------------------------------------

def validator_rule_set_ops(ops: list[dict]) -> dict:
    """Mirror of YaraRuleSet add_rule + rule_by_name.

    ops = [{"op":"add", "name":"r1"}, {"op":"get","name":"r1"}, ...]
    Returns {"rules":[names], "lookups":[bool,...]}
    """
    rules: list[str] = []
    lookups: list[bool] = []
    for op in ops:
        if op["op"] == "add":
            rules.append(op["name"])
        elif op["op"] == "get":
            lookups.append(op["name"] in rules)
    return {"rules": rules, "lookups": lookups}


# ---------------------------------------------------------------------------
# ELF module (yara_module_elf) — just verify magic + class/data fields
# ---------------------------------------------------------------------------

def validator_parse_elf32(data: bytes) -> dict:
    if len(data) < 52 or data[:4] != b"\x7fELF":
        return {"error": "BadMagic"}
    if data[4] != 1:
        return {"error": "NotElf32"}
    little = data[5] == 1
    fmt = "<HHIIIIIHHHHHH" if little else ">HHIIIIIHHHHHH"
    fields = struct.unpack_from(fmt, data, 16)
    e_type, e_machine, e_version, e_entry, e_phoff, e_shoff, e_flags, \
        e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx = fields
    return {
        "class": 32, "little": little,
        "e_type": e_type, "e_machine": e_machine, "e_entry": e_entry,
        "e_phoff": e_phoff, "e_shoff": e_shoff, "e_phnum": e_phnum, "e_shnum": e_shnum,
    }


def validator_parse_elf64(data: bytes) -> dict:
    if len(data) < 64 or data[:4] != b"\x7fELF":
        return {"error": "BadMagic"}
    if data[4] != 2:
        return {"error": "NotElf64"}
    little = data[5] == 1
    fmt = "<HHIQQQIHHHHHH" if little else ">HHIQQQIHHHHHH"
    fields = struct.unpack_from(fmt, data, 16)
    e_type, e_machine, e_version, e_entry, e_phoff, e_shoff, e_flags, \
        e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx = fields
    return {
        "class": 64, "little": little,
        "e_type": e_type, "e_machine": e_machine, "e_entry": e_entry,
        "e_phoff": e_phoff, "e_shoff": e_shoff, "e_phnum": e_phnum, "e_shnum": e_shnum,
    }


# ---------------------------------------------------------------------------
# Tiny rule parser (subset) — `rule NAME { strings: $a = "..." condition: $a }`
# ---------------------------------------------------------------------------

_RULE_RE = re.compile(
    r"rule\s+(\w+)\s*(?::\s*([\w\s]+?))?\s*\{(.+?)\}", re.DOTALL,
)
_META_RE = re.compile(r"meta\s*:(.*?)(?:strings\s*:|condition\s*:)", re.DOTALL)
_STR_RE = re.compile(r"(\$\w+)\s*=\s*\"((?:\\.|[^\"\\])*)\"\s*([a-z ]*)")
_COND_RE = re.compile(r"condition\s*:\s*(.+?)\s*$", re.DOTALL)


def validator_parse_rules(src: str) -> list[dict]:
    """Mirror of rule_parser::parse_rules — return rule descriptors."""
    out: list[dict] = []
    for m in _RULE_RE.finditer(src):
        name, tags, body = m.group(1), (m.group(2) or "").split(), m.group(3)
        meta: dict[str, str] = {}
        mm = _META_RE.search(body)
        if mm:
            for line in mm.group(1).strip().splitlines():
                line = line.strip()
                if "=" in line:
                    k, v = line.split("=", 1)
                    meta[k.strip()] = v.strip().strip("\"")
        strings: list[dict] = []
        for sm in _STR_RE.finditer(body):
            ident, text, mods = sm.group(1), sm.group(2), sm.group(3).split()
            strings.append({
                "id": ident,
                "text": text,
                "modifiers": {m: True for m in mods},
            })
        cm = _COND_RE.search(body)
        cond = cm.group(1).strip() if cm else ""
        out.append({
            "name": name,
            "tags": [t for t in tags if t],
            "meta": meta,
            "strings": strings,
            "condition": cond,
        })
    return out


# ---------------------------------------------------------------------------
# Tiny condition evaluator: supports "$a", "$a and $b", "$a or $b", "any of them"
# ---------------------------------------------------------------------------

def validator_eval_condition(cond: str, matched: dict[str, bool]) -> bool:
    cond = cond.strip()
    if cond == "any of them":
        return any(matched.values())
    if cond == "all of them":
        return bool(matched) and all(matched.values())
    # naive boolean: replace $ids with True/False, then eval safely.
    expr = cond
    for k, v in matched.items():
        expr = re.sub(re.escape(k) + r"\b", "True" if v else "False", expr)
    expr = expr.replace(" and ", " and ").replace(" or ", " or ").replace(" not ", " not ")
    # any remaining $x -> False (string not matched)
    expr = re.sub(r"\$\w+", "False", expr)
    try:
        return bool(eval(expr, {"__builtins__": {}}, {}))
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------

DISPATCH = {
    "match_hex":         lambda i: validator_match_hex(i["pattern"], bytes(i["data"])),
    "match_text":        lambda i: validator_match_text(i["text"], i.get("modifiers", {}), bytes(i["data"])),
    "match_nocase":      lambda i: validator_match_nocase(i["text"], bytes(i["data"])),
    "match_wide":        lambda i: validator_match_wide(i["text"], bytes(i["data"])),
    "match_xor":         lambda i: validator_match_xor(i["text"], i["xor_min"], i["xor_max"], bytes(i["data"])),
    "check_fullword":    lambda i: validator_check_fullword(bytes(i["data"]), i["offset"], i["len"]),
    "rule_set_ops":      lambda i: validator_rule_set_ops(i),
    "parse_elf32":       lambda i: validator_parse_elf32(bytes(i)),
    "parse_elf64":       lambda i: validator_parse_elf64(bytes(i)),
    "parse_rules":       lambda i: validator_parse_rules(i if isinstance(i, str) else i.get("src", "")),
    "eval_condition":    lambda i: validator_eval_condition(i["condition"], i.get("matched", {})),
}


def main_stdin() -> None:
    req = json.loads(sys.stdin.read())
    func = req["func"]
    inp = req.get("input", [])
    if func not in DISPATCH:
        print(json.dumps({"error": f"unknown function {func}"}))
        return
    out = DISPATCH[func](inp)
    print(json.dumps({"output": out}))


def main() -> None:
    sample = b"the quick BROWN fox jumps over the lazy dog\x00\x00MZP\x90\x90\x90"
    hex_pat = "?? 90 [1-3] 90"
    rules_src = """
    rule Demo : test tag2 {
        meta:
            author = "frax"
            description = "demo rule"
        strings:
            $a = "BROWN" nocase
            $b = "lazy"
        condition:
            $a and $b
    }
    """
    elf32 = bytes.fromhex(
        "7f454c46010100000000000000000000"  # ident
        "0200030001000000540080040000000034000000"
        "00000000000000003400200001002800000000"
        + "00" * 64
    )
    report = {
        "match_text_basic":       validator_match_text("the", {"ascii": True}, sample),
        "match_text_nocase":      validator_match_nocase("brown", sample),
        "match_text_fullword":    validator_match_text("the", {"fullword": True, "ascii": True}, sample),
        "match_hex_wild_jump":    validator_match_hex(hex_pat, sample),
        "match_hex_byte_seq":     validator_match_hex("90 90 90", sample),
        "match_xor_key_42":       validator_match_xor("hi", 0x42, 0x42,
                                       bytes(b ^ 0x42 for b in b"hello hi world")),
        "check_fullword_yes":     validator_check_fullword(sample, 4, 5),  # "quick"
        "check_fullword_no":      validator_check_fullword(sample, 0, 2),  # "th" inside "the"
        "rule_set_ops":           validator_rule_set_ops([
                                       {"op": "add", "name": "r1"},
                                       {"op": "add", "name": "r2"},
                                       {"op": "get", "name": "r1"},
                                       {"op": "get", "name": "nope"},
                                   ]),
        "parse_rules":            validator_parse_rules(rules_src),
        "eval_condition_all":     validator_eval_condition("$a and $b", {"$a": True, "$b": True}),
        "eval_condition_partial": validator_eval_condition("$a and $b", {"$a": True, "$b": False}),
        "eval_condition_any":     validator_eval_condition("any of them", {"$a": False, "$b": True}),
        "parse_elf32_magic_ok":   "error" not in validator_parse_elf32(elf32),
        "parse_elf32_bad_magic":  validator_parse_elf32(b"NOTELF" + bytes(64)),
        "parse_elf64_bad_magic":  validator_parse_elf64(b"NOTELF" + bytes(128)),
    }
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    if "--stdin" in sys.argv:
        main_stdin()
    else:
        main()
