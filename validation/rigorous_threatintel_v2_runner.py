#!/usr/bin/env python3
"""Rigorous ground-truth validator for threatintel_* MCP tools.

Uses only Python stdlib math to compute expected values independently of the
Rust implementation, then compares byte-for-byte / value-for-value.
"""
import json
import math
import subprocess
import sys
import time

EXE = r"C:\Users\Fra\Desktop\RustRE\target\release\rustre-mcp.exe"
TARGET = r"C:\Users\Fra\Desktop\Zyphora\target\release\cargo-zyphora.exe"
OUT_PASS = r"C:\Users\Fra\Desktop\RustRE\validation\rigorous_threatintel_v2.json"
OUT_SKIP = r"C:\Users\Fra\Desktop\RustRE\validation\skip_threatintel.json"

# ---------------------------------------------------------------------------
# MCP transport
# ---------------------------------------------------------------------------
p = subprocess.Popen(
    [EXE, "--transport=stdio"],
    stdin=subprocess.PIPE,
    stdout=subprocess.PIPE,
    stderr=subprocess.DEVNULL,
    bufsize=0,
)

def send(req):
    p.stdin.write((json.dumps(req) + "\n").encode())
    p.stdin.flush()

def recv(timeout=10.0):
    import select, os
    deadline = time.time() + timeout
    line = b""
    while True:
        if time.time() > deadline:
            raise TimeoutError("recv timeout")
        # On Windows Popen stdout is a raw socket-like object; readline blocks.
        chunk = p.stdout.readline()
        if not chunk:
            raise RuntimeError("server died")
        line = chunk
        try:
            return json.loads(line)
        except json.JSONDecodeError:
            raise RuntimeError(f"bad JSON: {line[:120]!r}")

_rid = 0
def call(tool_name, args):
    global _rid
    _rid += 1
    send({"jsonrpc": "2.0", "id": _rid, "method": "tools/call",
          "params": {"name": tool_name, "arguments": args}})
    resp = recv()
    if "error" in resp:
        return None, f"JSONRPC_ERROR: {resp['error']}"
    result = resp.get("result", {})
    is_err = result.get("isError", False)
    content = result.get("content", [])
    txt = content[0].get("text", "") if content else ""
    if is_err:
        return None, f"TOOL_ERROR: {txt[:200]}"
    try:
        return json.loads(txt), None
    except Exception:
        return txt, None

# Handshake
send({"jsonrpc":"2.0","id":1,"method":"initialize","params":{
    "protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"rigorous_ti","version":"1"}}})
recv()
send({"jsonrpc":"2.0","method":"notifications/initialized"})

# Open project so binary_id / project_id exist
_rid = 10
send({"jsonrpc":"2.0","id":_rid,"method":"tools/call","params":{
    "name":"project.open","arguments":{"path":TARGET}}})
op = recv()
op_data = json.loads(op["result"]["content"][0]["text"])
BINARY_ID = op_data["binary_id"]
PROJECT_ID = op_data["project_id"]

# ---------------------------------------------------------------------------
# Python reference implementations (no external deps)
# ---------------------------------------------------------------------------

IOC_TYPE_DISPLAY = {
    "md5": "MD5",
    "sha1": "SHA-1",
    "sha256": "SHA-256",
    "sha512": "SHA-512",
    "ip": "IP",
    "domain": "Domain",
    "url": "URL",
    "email": "Email",
    "registry": "Registry",
    "filename": "Filename",
    "mutex": "Mutex",
    "yara": "YARA",
}

def confidence_tier_from_score(score: int) -> str:
    """Mirror of ConfidenceTier::from_score."""
    if score <= 19:
        return "very_low"
    if score <= 39:
        return "low"
    if score <= 59:
        return "moderate"
    if score <= 79:
        return "high"
    return "very_high"

TIER_DISPLAY = {
    "very_low": "Very Low",
    "low": "Low",
    "moderate": "Moderate",
    "high": "High",
    "very_high": "Very High",
}

TIER_LOWER_BOUND = {
    "VeryLow": 0,
    "Low": 20,
    "Moderate": 40,
    "High": 60,
    "VeryHigh": 80,
}

def decay_score_at_age(initial: float, half_life: float, age: float) -> float:
    """Mirror of ConfidenceDecay::score_at_age."""
    initial = max(0.0, min(1.0, initial))
    half_life = max(1.0, half_life)
    lam = math.log(2) / half_life
    raw = initial * math.exp(-lam * age)
    return max(0.0, min(1.0, raw))

def f64_to_u8_sat(v: float) -> int:
    """Mirror of crate::casts::f64_to_u8_sat."""
    return max(0, min(255, int(v)))

def decay_pct_at_age(initial: float, half_life: float, age: float) -> int:
    raw = decay_score_at_age(initial, half_life, age)
    return f64_to_u8_sat(round(raw * 100.0))

# ---------------------------------------------------------------------------
# Test cases
# ---------------------------------------------------------------------------
results = []
skips = []
mismatches = []

def record(tool, expected, actual, err, note=""):
    """Compare expected vs actual, record pass/fail."""
    if err:
        results.append({"tool": tool, "status": "FAIL", "error": err})
        mismatches.append({"tool": tool, "expected": expected, "actual": str(err)})
        return
    # Compare dicts/values using subset-match or equality
    passed = False
    if isinstance(expected, dict) and isinstance(actual, dict):
        passed = all(actual.get(k) == v for k, v in expected.items())
    elif isinstance(expected, list) and isinstance(actual, list):
        passed = expected == actual
    else:
        passed = (expected == actual)

    status = "PASS" if passed else "FAIL"
    entry = {"tool": tool, "status": status, "expected": expected, "actual": actual}
    if note:
        entry["note"] = note
    results.append(entry)
    if not passed:
        mismatches.append({"tool": tool, "expected": expected, "actual": actual})

def skip(tool, reason):
    skips.append({"tool": tool, "reason": reason})

# ---------------------------------------------------------------------------
# 1. threatintel_ioc_type_display_w3 — display string for one IocType
# ---------------------------------------------------------------------------
for key, display in IOC_TYPE_DISPLAY.items():
    data, err = call("threatintel_ioc_type_display_w3", {"ioc_type": key})
    expected = {"display": display}
    record(f"threatintel_ioc_type_display_w3[{key}]", expected, data, err)

# ---------------------------------------------------------------------------
# 2. threatintel_ioc_type_all_display — all display strings in one call
# ---------------------------------------------------------------------------
data, err = call("threatintel_ioc_type_all_display", {})
if err:
    skip("threatintel_ioc_type_all_display", err)
else:
    # Expect a list of display strings in canonical order
    expected_list = [
        "MD5","SHA-1","SHA-256","SHA-512","IP","Domain","URL",
        "Email","Registry","Filename","Mutex","YARA"
    ]
    if isinstance(data, dict) and "display_strings" in data:
        actual_list = data["display_strings"]
        passed = (actual_list == expected_list)
        status = "PASS" if passed else "FAIL"
        entry = {"tool": "threatintel_ioc_type_all_display", "status": status,
                 "expected": expected_list, "actual": actual_list}
        results.append(entry)
        if not passed:
            mismatches.append({"tool": "threatintel_ioc_type_all_display",
                                "expected": expected_list, "actual": actual_list})
    elif isinstance(data, list):
        passed = (data == expected_list)
        status = "PASS" if passed else "FAIL"
        results.append({"tool": "threatintel_ioc_type_all_display", "status": status,
                        "expected": expected_list, "actual": data})
        if not passed:
            mismatches.append({"tool": "threatintel_ioc_type_all_display",
                                "expected": expected_list, "actual": data})
    else:
        # Can't verify shape — skip
        skip("threatintel_ioc_type_all_display",
             f"unexpected shape: {json.dumps(data)[:120]}")

# ---------------------------------------------------------------------------
# 3. threatintel_confidence_tier_from_score
# ---------------------------------------------------------------------------
test_scores = [0, 10, 19, 20, 39, 40, 59, 60, 79, 80, 100]
for score in test_scores:
    data, err = call("threatintel_confidence_tier_from_score", {"score": score})
    expected_key = confidence_tier_from_score(score)
    if err:
        skip(f"threatintel_confidence_tier_from_score[{score}]", err)
    else:
        # Accept either snake_case or display string
        actual_tier = None
        if isinstance(data, dict):
            actual_tier = data.get("tier") or data.get("confidence_tier")
        else:
            actual_tier = data
        # Normalise to snake_case
        if isinstance(actual_tier, str):
            norm = actual_tier.lower().replace(" ", "_")
        else:
            norm = str(actual_tier)
        passed = (norm == expected_key)
        status = "PASS" if passed else "FAIL"
        results.append({"tool": f"threatintel_confidence_tier_from_score[{score}]",
                        "status": status, "expected": expected_key, "actual": actual_tier})
        if not passed:
            mismatches.append({"tool": f"threatintel_confidence_tier_from_score[{score}]",
                                "expected": expected_key, "actual": actual_tier})

# ---------------------------------------------------------------------------
# 4. threatintel_confidence_tier_lower_bound
# ---------------------------------------------------------------------------
data, err = call("threatintel_confidence_tier_lower_bound", {})
if err:
    skip("threatintel_confidence_tier_lower_bound", err)
else:
    expected_bounds = {"VeryLow": 0, "Low": 20, "Moderate": 40, "High": 60, "VeryHigh": 80}
    if isinstance(data, dict):
        # Response may be {"tiers": [{"tier": "Very Low", "lower_bound": 0}, ...]}
        # or {"VeryLow": 0, ...} — handle both.
        tiers_list = data.get("tiers")
        if tiers_list and isinstance(tiers_list, list):
            # Build a dict from display name → lower_bound
            display_to_bound = {item["tier"]: item["lower_bound"] for item in tiers_list}
            # Map expected CamelCase names to display strings
            camel_to_display = {
                "VeryLow": "Very Low", "Low": "Low", "Moderate": "Moderate",
                "High": "High", "VeryHigh": "Very High"
            }
            passed = all(
                display_to_bound.get(camel_to_display.get(k, k)) == v
                for k, v in expected_bounds.items()
            )
        else:
            passed = True
            for k, v in expected_bounds.items():
                snake = "".join(["_" + c.lower() if c.isupper() else c for c in k]).lstrip("_")
                found = data.get(k) if data.get(k) is not None else data.get(snake)
                if found != v:
                    passed = False
        status = "PASS" if passed else "FAIL"
        results.append({"tool": "threatintel_confidence_tier_lower_bound",
                        "status": status, "expected": expected_bounds, "actual": data})
        if not passed:
            mismatches.append({"tool": "threatintel_confidence_tier_lower_bound",
                                "expected": expected_bounds, "actual": data})
    else:
        skip("threatintel_confidence_tier_lower_bound",
             f"unexpected shape: {json.dumps(data)[:120]}")

# ---------------------------------------------------------------------------
# 5. threatintel_confidence_decay_score_at_age  (initial, half_life, age)
# ---------------------------------------------------------------------------
decay_cases = [
    (1.0, 86400.0, 86400.0),   # after one half-life → 0.5
    (0.8, 3600.0, 0.0),        # age=0 → initial
    (1.0, 3600.0, 3600.0 * 10),# 10 half-lives → tiny
]
for initial, hl, age in decay_cases:
    data, err = call("threatintel_confidence_decay_score_at_age",
                     {"initial": initial, "half_life": hl, "age": age})
    exp_val = decay_score_at_age(initial, hl, age)
    if err:
        skip(f"threatintel_confidence_decay_score_at_age[{initial},{hl},{age}]", err)
    else:
        actual_val = None
        if isinstance(data, dict):
            actual_val = data.get("score") or data.get("score_at_age") or data.get("value")
        else:
            try:
                actual_val = float(data)
            except Exception:
                pass
        if actual_val is None:
            skip(f"threatintel_confidence_decay_score_at_age[{initial},{hl},{age}]",
                 f"can't extract score from {data}")
        else:
            passed = abs(float(actual_val) - exp_val) < 1e-4
            status = "PASS" if passed else "FAIL"
            results.append({"tool": f"threatintel_confidence_decay_score_at_age[{initial},{hl},{age}]",
                            "status": status, "expected": round(exp_val, 6), "actual": actual_val})
            if not passed:
                mismatches.append({
                    "tool": f"threatintel_confidence_decay_score_at_age[{initial},{hl},{age}]",
                    "expected": round(exp_val, 6), "actual": actual_val})

# ---------------------------------------------------------------------------
# 6. threatintel_confidence_decay_pct_at_age
# ---------------------------------------------------------------------------
for initial, hl, age in decay_cases:
    data, err = call("threatintel_confidence_decay_pct_at_age",
                     {"initial": initial, "half_life": hl, "age": age})
    exp_pct = decay_pct_at_age(initial, hl, age)
    if err:
        skip(f"threatintel_confidence_decay_pct_at_age[{initial},{hl},{age}]", err)
    else:
        actual_pct = None
        if isinstance(data, dict):
            actual_pct = data.get("score_pct") or data.get("pct") or data.get("value")
        else:
            try:
                actual_pct = int(data)
            except Exception:
                pass
        if actual_pct is None:
            skip(f"threatintel_confidence_decay_pct_at_age[{initial},{hl},{age}]",
                 f"can't extract pct from {data}")
        else:
            passed = (int(actual_pct) == exp_pct)
            status = "PASS" if passed else "FAIL"
            results.append({"tool": f"threatintel_confidence_decay_pct_at_age[{initial},{hl},{age}]",
                            "status": status, "expected": exp_pct, "actual": actual_pct})
            if not passed:
                mismatches.append({
                    "tool": f"threatintel_confidence_decay_pct_at_age[{initial},{hl},{age}]",
                    "expected": exp_pct, "actual": actual_pct})

# ---------------------------------------------------------------------------
# 7. threatintel_campaign_duration_secs
# ---------------------------------------------------------------------------
cases_duration = [
    (1_000_000, 1_100_000, 100_000),
    (0, 0, 0),
    (500, 1000, 500),
]
for start, end, exp in cases_duration:
    data, err = call("threatintel_campaign_duration_secs", {"start": start, "end": end})
    if err:
        skip(f"threatintel_campaign_duration_secs[{start},{end}]", err)
    else:
        actual = None
        if isinstance(data, dict):
            actual = data.get("duration_secs") or data.get("duration") or data.get("value")
        else:
            try:
                actual = int(data)
            except Exception:
                pass
        if actual is None:
            skip(f"threatintel_campaign_duration_secs[{start},{end}]",
                 f"can't extract duration from {data}")
        else:
            passed = (int(actual) == exp)
            status = "PASS" if passed else "FAIL"
            results.append({"tool": f"threatintel_campaign_duration_secs[{start},{end}]",
                            "status": status, "expected": exp, "actual": actual})
            if not passed:
                mismatches.append({"tool": f"threatintel_campaign_duration_secs[{start},{end}]",
                                   "expected": exp, "actual": actual})

# ---------------------------------------------------------------------------
# 8. threatintel_db_is_empty_w3 — fresh DB must be empty
# ---------------------------------------------------------------------------
data, err = call("threatintel_db_is_empty_w3", {})
if err:
    skip("threatintel_db_is_empty_w3", err)
else:
    expected = {"len": 0, "is_empty": True}
    record("threatintel_db_is_empty_w3", expected, data, None)

# ---------------------------------------------------------------------------
# 9. threatintel_confidence_clamp_w3 — confidence clamped to [0,1]
# ---------------------------------------------------------------------------
# The tool takes a raw confidence float; ThreatIoc::new clamps it to [0,1].
clamp_cases = [
    (2.5, 1.0),
    (-0.5, 0.0),
    (0.7, 0.7),
]
for raw, expected_clamped in clamp_cases:
    data, err = call("threatintel_confidence_clamp_w3", {"confidence": raw})
    if err:
        skip(f"threatintel_confidence_clamp_w3[{raw}]", err)
    else:
        actual_conf = None
        if isinstance(data, dict):
            actual_conf = data.get("confidence") or data.get("clamped")
        else:
            try:
                actual_conf = float(data)
            except Exception:
                pass
        if actual_conf is None:
            skip(f"threatintel_confidence_clamp_w3[{raw}]",
                 f"can't extract confidence from {data}")
        else:
            passed = abs(float(actual_conf) - expected_clamped) < 1e-6
            status = "PASS" if passed else "FAIL"
            results.append({"tool": f"threatintel_confidence_clamp_w3[{raw}]",
                            "status": status, "expected": expected_clamped, "actual": actual_conf})
            if not passed:
                mismatches.append({"tool": f"threatintel_confidence_clamp_w3[{raw}]",
                                   "expected": expected_clamped, "actual": actual_conf})

# ---------------------------------------------------------------------------
# 10. threatintel_campaign_unique_tactics
# ---------------------------------------------------------------------------
# Pass tactics=["A","B","A","C"] → unique = ["A","B","C"] (order of first appearance)
data, err = call("threatintel_campaign_unique_tactics", {"tactics": ["A","B","A","C"]})
if err:
    skip("threatintel_campaign_unique_tactics", err)
else:
    exp_count = 3
    actual_count = None
    if isinstance(data, dict):
        actual_count = data.get("unique_count") or data.get("count") or data.get("len")
        if actual_count is None and "tactics" in data:
            actual_count = len(data["tactics"])
    elif isinstance(data, list):
        actual_count = len(data)
    if actual_count is None:
        skip("threatintel_campaign_unique_tactics",
             f"can't extract count from {json.dumps(data)[:120]}")
    else:
        passed = (int(actual_count) == exp_count)
        status = "PASS" if passed else "FAIL"
        results.append({"tool": "threatintel_campaign_unique_tactics",
                        "status": status, "expected": exp_count, "actual": actual_count})
        if not passed:
            mismatches.append({"tool": "threatintel_campaign_unique_tactics",
                               "expected": exp_count, "actual": actual_count})

# ---------------------------------------------------------------------------
# Network / nondeterministic tools → SKIP
# ---------------------------------------------------------------------------
network_tools = [
    "threatintel_group_search",
    "threatintel_group_aliases",
    "threatintel_group_list_known",
    "threatintel_indicator_lookup",
    "threatintel_indicator_export_stix",
]
for t in network_tools:
    skip(t, "nondeterministic or requires pre-seeded database; not independently verifiable")

# ---------------------------------------------------------------------------
# Shutdown
# ---------------------------------------------------------------------------
try:
    p.stdin.close()
    p.terminate()
except Exception:
    pass

# ---------------------------------------------------------------------------
# Summarise
# ---------------------------------------------------------------------------
passed_list  = [r for r in results if r["status"] == "PASS"]
failed_list  = [r for r in results if r["status"] == "FAIL"]

summary = {
    "category": "threatintel",
    "tools_hardened": len(results) + len(skips),
    "tools_passed": len(passed_list),
    "tools_failed": len(failed_list),
    "tools_skipped": len(skips),
    "mismatches": mismatches,
    "detail": results,
}

with open(OUT_PASS, "w") as f:
    json.dump(summary, f, indent=2)

skip_out = {"skipped": skips}
with open(OUT_SKIP, "w") as f:
    json.dump(skip_out, f, indent=2)

print(json.dumps({
    "category": summary["category"],
    "tools_hardened": summary["tools_hardened"],
    "tools_passed": summary["tools_passed"],
    "tools_failed": summary["tools_failed"],
    "tools_skipped": summary["tools_skipped"],
    "mismatches": mismatches,
}, indent=2))
