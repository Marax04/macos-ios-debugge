#!/usr/bin/env python3
"""
Rigorous ground-truth validation for all MCP tools prefixed with sandbox_.

Each test calls the MCP tool via json-rpc-over-stdio (same mechanism as
exercise_v3.py) and compares the result against an independently computed
Python reference.  Non-deterministic tools are recorded as SKIP.
"""
import json
import subprocess
import sys
from pathlib import Path

EXE = r"C:\Users\Fra\Desktop\RustRE\target\release\rustre-mcp.exe"
TARGET = r"C:\Users\Fra\Desktop\Zyphora\target\release\cargo-zyphora.exe"
OUT_V2 = r"C:\Users\Fra\Desktop\RustRE\validation\rigorous_sandbox_v2.json"
SKIP_OUT = r"C:\Users\Fra\Desktop\RustRE\validation\skip_sandbox.json"

# ---------------------------------------------------------------------------
# MCP transport helpers (identical pattern to exercise_v3.py)
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


def recv():
    line = p.stdout.readline()
    if not line:
        raise RuntimeError("MCP server died")
    try:
        return json.loads(line)
    except json.JSONDecodeError:
        return {"error": {"message": f"bad-line: {line[:120]!r}"}}


def call_tool(name, arguments):
    """Call a tool and return (ok:bool, parsed_json_or_text:any)."""
    send({
        "jsonrpc": "2.0",
        "id": _next_id(),
        "method": "tools/call",
        "params": {"name": name, "arguments": arguments},
    })
    resp = recv()
    if "error" in resp:
        return False, str(resp["error"])
    result = resp.get("result", {})
    is_err = result.get("isError", False)
    content = result.get("content", [])
    txt = content[0].get("text", "") if content else ""
    if is_err:
        return False, txt
    try:
        return True, json.loads(txt)
    except Exception:
        return True, txt


_id_counter = [200]


def _next_id():
    _id_counter[0] += 1
    return _id_counter[0]


# ---------------------------------------------------------------------------
# Initialize
# ---------------------------------------------------------------------------

send({
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
        "protocolVersion": "2024-11-05",
        "capabilities": {},
        "clientInfo": {"name": "rigorous_sandbox_v2", "version": "1"},
    },
})
recv()
send({"jsonrpc": "2.0", "method": "notifications/initialized"})

# Open project so the server is in a valid state
send({
    "jsonrpc": "2.0",
    "id": 2,
    "method": "tools/call",
    "params": {"name": "project.open", "arguments": {"path": TARGET}},
})
recv()

# ---------------------------------------------------------------------------
# Independent Python reference implementations (pure Python, no shelling out)
# ---------------------------------------------------------------------------

# Severity score table (from rustre-sandbox-report/src/lib.rs)
SEVERITY_SCORE = {"info": 0, "low": 25, "medium": 50, "high": 75, "critical": 100}
SEVERITY_DISPLAY = {"info": "info", "low": "low", "medium": "medium",
                    "high": "high", "critical": "critical"}

# ScoreEngine category weights (from lib.rs ScoreEngine::new())
CAT_WEIGHTS = {
    "injection": 25, "ransomware": 30, "keylogging": 20,
    "persistence": 15, "network": 10, "evasion": 15,
    "dropper": 15, "crypto": 5, "reconnaissance": 5, "other": 5,
}

# Mock SandboxReport indicators (from SandboxReport::mock())
MOCK_INDICATORS = [
    # (name, severity_str, category_str)
    ("Code injection",       "critical", "injection"),
    ("Network beacon",       "high",     "network"),
    ("Registry persistence", "medium",   "persistence"),
    ("Anti-debug",           "high",     "evasion"),
]


def py_compute_score(indicators=MOCK_INDICATORS):
    score = 0
    for _name, sev, cat in indicators:
        base = SEVERITY_SCORE[sev]
        w = CAT_WEIGHTS.get(cat, 5)
        score += base * w // 100
    return min(score, 100)


def py_verdict(score: int) -> str:
    if score == 0:
        return "clean"
    if score <= 30:
        return "low"
    if score <= 70:
        return "suspicious"
    return "malicious"


def py_has_critical(indicators=MOCK_INDICATORS) -> bool:
    return any(sev == "critical" for _, sev, _ in indicators)


# MemoryMap::mock() regions (from lib.rs)
MOCK_REGIONS = [
    # (start, end, label, readable, writable, executable, mapped_file)
    (0x0000_0000_0040_0000, 0x0000_0000_0050_0000, "[exe]",      True,  False, True,  "malware.exe"),
    (0x0000_7fff_0000_0000, 0x0000_7fff_0010_0000, "[stack]",    True,  True,  False, None),
    (0x0000_0001_0000_0000, 0x0000_0001_0001_0000, "[injected]", True,  True,  True,  None),
    (0x0000_7ffe_0000_0000, 0x0000_7ffe_0100_0000, "[ntdll]",    True,  False, True,  "ntdll.dll"),
]

PY_REGION_COUNT = len(MOCK_REGIONS)
PY_TOTAL_SIZE = sum(end - start for (start, end, *_) in MOCK_REGIONS)
# RWX = readable AND writable AND executable
PY_RWX_COUNT = sum(1 for (_, __, ___, r, w, x, ____)  in MOCK_REGIONS if r and w and x)

# IocSet::mock() IOCs (from lib.rs)
MOCK_IOCS = [
    # (kind_str, value, confidence, context)
    ("ip",           "185.220.101.1",                             95,  "C2 beacon"),
    ("domain",       "c2server.evil",                             90,  "DNS query"),
    ("filepath",     r"C:\Windows\Temp\payload.exe",              100, "dropped file"),
    ("filehash",     "deadbeefcafe0123456789abcdef0123456789ab",  100, "SHA-1 of payload"),
    ("registry_key", r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run", 85, "persistence"),
    ("mutex",        "Global\\MalwareMutex_v2",                   70,  "mutex seen during run"),
]

PY_IOC_COUNT_BEFORE_DEDUP = len(MOCK_IOCS)
# deduplicate by (kind, value) — all are unique
PY_IOC_COUNT_AFTER_DEDUP = len(set((k, v) for k, v, _, __ in MOCK_IOCS))
PY_CONFIDENT_80 = sum(1 for _, __, c, ___ in MOCK_IOCS if c >= 80)

# SandboxReport::mock() derived values
PY_MOCK_SAMPLE = "malware.exe"
PY_MOCK_SHA256 = "deadbeef0123456789abcdef0123456789abcdef"
PY_MOCK_SCORE = py_compute_score()   # = 50
PY_MOCK_VERDICT = "malicious"        # compute_score() forces Malicious when has_critical
PY_MOCK_FAMILY = "trojan"            # has_injection + has_network → trojan
PY_MOCK_INDICATOR_COUNT = 4
PY_MOCK_BEHAVIOR_COUNT = 1
PY_MOCK_IOC_COUNT = 6
# build_attack_mapping from tags ["injection","c2","persistence","anti-analysis"]
PY_MOCK_TECHNIQUE_COUNT = 4  # injection→1, c2→1, persistence→1, anti-analysis→1
PY_MOCK_TAGS = ["injection", "c2", "persistence", "anti-analysis"]

# SandboxPolicy::balanced()
PY_POLICY_TIMEOUT = 120
PY_POLICY_MAX_MEM = 1024
PY_POLICY_PERMS_BITS = 0x01 | 0x02 | 0x04 | 0x08  # = 15
PY_POLICY_FS_WRITE_PATHS = ["/tmp", "C:\\Windows\\Temp"]
PY_POLICY_VALID = True

# ResourceLimits::tight()
PY_LIMITS_MAX_MEM = 256
PY_LIMITS_MAX_DISK = 32

# ---------------------------------------------------------------------------
# Test cases
# ---------------------------------------------------------------------------

results = []
skips = []

PASS = "PASS"
FAIL = "FAIL"
SKIP = "SKIP"


def record(tool, status, expected=None, actual=None, note=""):
    entry = {"tool": tool, "status": status}
    if expected is not None:
        entry["expected"] = expected
    if actual is not None:
        entry["actual"] = actual
    if note:
        entry["note"] = note
    results.append(entry)


def record_skip(tool, reason):
    skips.append({"tool": tool, "reason": reason})
    results.append({"tool": tool, "status": SKIP, "note": reason})


# --- sandbox_vm_memory_map_mock ---
expected_mm = {
    "pid": 42,
    "region_count": PY_REGION_COUNT,
    "total_size": PY_TOTAL_SIZE,
    "rwx_region_count": PY_RWX_COUNT,
}
ok, actual = call_tool("sandbox_vm_memory_map_mock", {"pid": 42})
if not ok:
    record("sandbox_vm_memory_map_mock", FAIL,
           expected_mm, actual, "tool returned error")
else:
    mismatches = {k: (expected_mm[k], actual.get(k))
                  for k in expected_mm if actual.get(k) != expected_mm[k]}
    if mismatches:
        record("sandbox_vm_memory_map_mock", FAIL, expected_mm, actual,
               f"field mismatches: {mismatches}")
    else:
        record("sandbox_vm_memory_map_mock", PASS, expected_mm, actual)

# --- sandbox_vm_qemu_build_args: SKIP (UUID-based QMP socket is non-deterministic) ---
record_skip("sandbox_vm_qemu_build_args",
            "QMP socket path uses uuid::Uuid::new_v4() — non-deterministic")

# --- sandbox_report_severity_parse ---
for sev_str, exp_score in SEVERITY_SCORE.items():
    expected_sp = {"input": sev_str, "severity": sev_str, "score": exp_score}
    ok, actual = call_tool("sandbox_report_severity_parse", {"severity": sev_str})
    tool_name = f"sandbox_report_severity_parse({sev_str})"
    if not ok:
        record(tool_name, FAIL, expected_sp, actual, "tool error")
    else:
        if actual.get("score") == exp_score and actual.get("severity") == sev_str:
            record(tool_name, PASS, expected_sp, actual)
        else:
            record(tool_name, FAIL, expected_sp, actual)

# --- sandbox_report_iocset_mock (default threshold=80) ---
expected_ioc = {
    "count_before_dedup": PY_IOC_COUNT_BEFORE_DEDUP,
    "count_after_dedup": PY_IOC_COUNT_AFTER_DEDUP,
    "confident_count": PY_CONFIDENT_80,
    "threshold": 80,
}
ok, actual = call_tool("sandbox_report_iocset_mock", {"confidence_threshold": 80})
if not ok:
    record("sandbox_report_iocset_mock", FAIL, expected_ioc, actual, "tool error")
else:
    mismatches = {k: (expected_ioc[k], actual.get(k))
                  for k in expected_ioc if actual.get(k) != expected_ioc[k]}
    if mismatches:
        record("sandbox_report_iocset_mock", FAIL, expected_ioc, actual,
               f"field mismatches: {mismatches}")
    else:
        record("sandbox_report_iocset_mock", PASS, expected_ioc, actual)

# --- sandbox_report_mock_summary ---
expected_ms = {
    "sample": PY_MOCK_SAMPLE,
    "sha256": PY_MOCK_SHA256,
    "verdict": PY_MOCK_VERDICT,
    "score": PY_MOCK_SCORE,
    "family": PY_MOCK_FAMILY,
    "indicator_count": PY_MOCK_INDICATOR_COUNT,
    "behavior_count": PY_MOCK_BEHAVIOR_COUNT,
    "ioc_count": PY_MOCK_IOC_COUNT,
    "technique_count": PY_MOCK_TECHNIQUE_COUNT,
}
ok, actual = call_tool("sandbox_report_mock_summary", {})
if not ok:
    record("sandbox_report_mock_summary", FAIL, expected_ms, actual, "tool error")
else:
    mismatches = {k: (expected_ms[k], actual.get(k))
                  for k in expected_ms if actual.get(k) != expected_ms[k]}
    if mismatches:
        record("sandbox_report_mock_summary", FAIL, expected_ms, actual,
               f"field mismatches: {mismatches}")
    else:
        record("sandbox_report_mock_summary", PASS, expected_ms, actual)

# --- sandbox_report_score_engine_compute ---
py_score = py_compute_score()
expected_se = {
    "indicator_count": PY_MOCK_INDICATOR_COUNT,
    "score": py_score,
    "verdict": py_verdict(py_score),   # "suspicious" (50 is in 31..=70)
    "has_critical": py_has_critical(),  # True
}
ok, actual = call_tool("sandbox_report_score_engine_compute", {})
if not ok:
    record("sandbox_report_score_engine_compute", FAIL, expected_se, actual, "tool error")
else:
    mismatches = {k: (expected_se[k], actual.get(k))
                  for k in expected_se if actual.get(k) != expected_se[k]}
    if mismatches:
        record("sandbox_report_score_engine_compute", FAIL, expected_se, actual,
               f"field mismatches: {mismatches}")
    else:
        record("sandbox_report_score_engine_compute", PASS, expected_se, actual)

# --- sandbox_report_critical_indicators ---
expected_ci = {"count": 1}   # only "Code injection" is Critical
ok, actual = call_tool("sandbox_report_critical_indicators", {})
if not ok:
    record("sandbox_report_critical_indicators", FAIL, expected_ci, actual, "tool error")
else:
    if actual.get("count") == 1:
        record("sandbox_report_critical_indicators", PASS, expected_ci, actual)
    else:
        record("sandbox_report_critical_indicators", FAIL, expected_ci, actual,
               f"expected count=1, got {actual.get('count')}")

# --- sandbox_policy_balanced_validate ---
expected_pv = {
    "timeout_secs": PY_POLICY_TIMEOUT,
    "max_memory_mb": PY_POLICY_MAX_MEM,
    "perms_bits": PY_POLICY_PERMS_BITS,
    "valid": PY_POLICY_VALID,
}
ok, actual = call_tool("sandbox_policy_balanced_validate", {})
if not ok:
    record("sandbox_policy_balanced_validate", FAIL, expected_pv, actual, "tool error")
else:
    mismatches = {k: (expected_pv[k], actual.get(k))
                  for k in expected_pv if actual.get(k) != expected_pv[k]}
    if mismatches:
        record("sandbox_policy_balanced_validate", FAIL, expected_pv, actual,
               f"field mismatches: {mismatches}")
    else:
        record("sandbox_policy_balanced_validate", PASS, expected_pv, actual)

# --- sandbox_resource_limits_check (used_mb=100, written_mb=10) ---
expected_rl = {
    "memory_exceeded": False,    # 100 > 256 = False
    "disk_exceeded": False,      # 10 > 32 = False
    "max_memory_mb": PY_LIMITS_MAX_MEM,
    "max_disk_write_mb": PY_LIMITS_MAX_DISK,
    "used_mb": 100,
    "written_mb": 10,
}
ok, actual = call_tool("sandbox_resource_limits_check", {"used_mb": 100, "written_mb": 10})
if not ok:
    record("sandbox_resource_limits_check", FAIL, expected_rl, actual, "tool error")
else:
    mismatches = {k: (expected_rl[k], actual.get(k))
                  for k in expected_rl if actual.get(k) != expected_rl[k]}
    if mismatches:
        record("sandbox_resource_limits_check", FAIL, expected_rl, actual,
               f"field mismatches: {mismatches}")
    else:
        record("sandbox_resource_limits_check", PASS, expected_rl, actual)

# Also test exceeded case: used_mb=300 > 256 → memory_exceeded=True
expected_rl_exc = {
    "memory_exceeded": True,
    "disk_exceeded": False,
    "used_mb": 300,
    "written_mb": 10,
}
ok, actual = call_tool("sandbox_resource_limits_check", {"used_mb": 300, "written_mb": 10})
if not ok:
    record("sandbox_resource_limits_check(exceeded)", FAIL, expected_rl_exc, actual, "tool error")
else:
    if actual.get("memory_exceeded") is True and actual.get("disk_exceeded") is False:
        record("sandbox_resource_limits_check(exceeded)", PASS, expected_rl_exc, actual)
    else:
        record("sandbox_resource_limits_check(exceeded)", FAIL, expected_rl_exc, actual)

# --- sandbox_report_severity_score_all_v3 ---
expected_sv3 = {"info": 0, "low": 25, "medium": 50, "high": 75, "critical": 100}
ok, actual = call_tool("sandbox_report_severity_score_all_v3", {})
if not ok:
    record("sandbox_report_severity_score_all_v3", FAIL, expected_sv3, actual, "tool error")
else:
    mismatches = {k: (expected_sv3[k], actual.get(k))
                  for k in expected_sv3 if actual.get(k) != expected_sv3[k]}
    if mismatches:
        record("sandbox_report_severity_score_all_v3", FAIL, expected_sv3, actual,
               f"field mismatches: {mismatches}")
    else:
        record("sandbox_report_severity_score_all_v3", PASS, expected_sv3, actual)

# --- sandbox_report_verdict_all_display_v3 ---
expected_vd = {"verdicts": ["clean", "low", "suspicious", "malicious", "unknown"]}
ok, actual = call_tool("sandbox_report_verdict_all_display_v3", {})
if not ok:
    record("sandbox_report_verdict_all_display_v3", FAIL, expected_vd, actual, "tool error")
else:
    if actual.get("verdicts") == ["clean", "low", "suspicious", "malicious", "unknown"]:
        record("sandbox_report_verdict_all_display_v3", PASS, expected_vd, actual)
    else:
        record("sandbox_report_verdict_all_display_v3", FAIL, expected_vd, actual)

# --- sandbox_report_score_engine_verdict_sweep_v3 ---
expected_vs = {
    "s0": "clean",
    "s15": "low",
    "s50": "suspicious",
    "s85": "malicious",
}
ok, actual = call_tool("sandbox_report_score_engine_verdict_sweep_v3", {})
if not ok:
    record("sandbox_report_score_engine_verdict_sweep_v3", FAIL, expected_vs, actual, "tool error")
else:
    mismatches = {k: (expected_vs[k], actual.get(k))
                  for k in expected_vs if actual.get(k) != expected_vs[k]}
    if mismatches:
        record("sandbox_report_score_engine_verdict_sweep_v3", FAIL, expected_vs, actual,
               f"field mismatches: {mismatches}")
    else:
        record("sandbox_report_score_engine_verdict_sweep_v3", PASS, expected_vs, actual)

# --- sandbox_report_attack_mapping_from_behaviors ---
# injection → T1055.001, persistence → T1547.001 → 2 techniques
expected_am = {"technique_count": 2}
ok, actual = call_tool("sandbox_report_attack_mapping_from_behaviors",
                       {"tags": ["injection", "persistence"]})
if not ok:
    record("sandbox_report_attack_mapping_from_behaviors", FAIL, expected_am, actual, "tool error")
else:
    ids = actual.get("technique_ids", [])
    if len(ids) == 2 and "T1055.001" in ids and "T1547.001" in ids:
        record("sandbox_report_attack_mapping_from_behaviors", PASS, expected_am, actual)
    else:
        record("sandbox_report_attack_mapping_from_behaviors", FAIL, expected_am,
               actual, f"expected T1055.001 + T1547.001, got {ids}")

# --- sandbox_report_ioc_is_confident ---
# confidence=95, threshold=80 → True (95 >= 80)
expected_ic = {"is_confident": True}
ok, actual = call_tool("sandbox_report_ioc_is_confident",
                       {"confidence": 95, "threshold": 80})
if not ok:
    record("sandbox_report_ioc_is_confident(95,80)", FAIL, expected_ic, actual, "tool error")
else:
    if actual.get("is_confident") is True:
        record("sandbox_report_ioc_is_confident(95,80)", PASS, expected_ic, actual)
    else:
        record("sandbox_report_ioc_is_confident(95,80)", FAIL, expected_ic, actual)

# confidence=50, threshold=80 → False (50 < 80)
expected_ic2 = {"is_confident": False}
ok, actual = call_tool("sandbox_report_ioc_is_confident",
                       {"confidence": 50, "threshold": 80})
if not ok:
    record("sandbox_report_ioc_is_confident(50,80)", FAIL, expected_ic2, actual, "tool error")
else:
    if actual.get("is_confident") is False:
        record("sandbox_report_ioc_is_confident(50,80)", PASS, expected_ic2, actual)
    else:
        record("sandbox_report_ioc_is_confident(50,80)", FAIL, expected_ic2, actual)

# --- sandbox_behavior_record_mock_summary: SKIP (complex internal state) ---
record_skip("sandbox_behavior_record_mock_summary",
            "BehaviorRecord::mock() has complex nested state; "
            "independent Python reference would duplicate non-trivial Rust logic")

# ---------------------------------------------------------------------------
# Wrap up
# ---------------------------------------------------------------------------

p.stdin.close()
p.terminate()

passed = sum(1 for r in results if r["status"] == PASS)
failed = sum(1 for r in results if r["status"] == FAIL)
skipped = sum(1 for r in results if r["status"] == SKIP)
hardened = passed + failed  # tools that were actually exercised with ground truth

mismatches = [
    {"tool": r["tool"], "expected": r.get("expected"), "actual": r.get("actual")}
    for r in results
    if r["status"] == FAIL
]

print(f"sandbox rigorous v2: passed={passed} failed={failed} skipped={skipped}")
for r in results:
    status = r["status"]
    note = r.get("note", "")
    print(f"  {status:<4}  {r['tool']}{(' — ' + note) if note else ''}")

# Write outputs
with open(OUT_V2, "w") as f:
    json.dump(results, f, indent=2)

with open(SKIP_OUT, "w") as f:
    json.dump(skips, f, indent=2)

print(f"\nResults written to {OUT_V2}")
print(f"Skip list written to {SKIP_OUT}")
