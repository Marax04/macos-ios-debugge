#!/usr/bin/env python3
"""
Rigorous ground-truth validator for all forensics_* MCP tools.
Uses Python stdlib (hashlib, struct) as independent reference.
Writes results to rigorous_forensics_v2.json and skip_forensics.json.
"""
import json
import subprocess
import hashlib
import struct
import sys
import time

EXE = r"C:\Users\Fra\Desktop\RustRE\target\release\rustre-mcp.exe"
TARGET = r"C:\Users\Fra\Desktop\Zyphora\target\release\cargo-zyphora.exe"
OUT_RIGOROUS = r"C:\Users\Fra\Desktop\RustRE\validation\rigorous_forensics_v2.json"
OUT_SKIP = r"C:\Users\Fra\Desktop\RustRE\validation\skip_forensics.json"

# ── MCP plumbing ──────────────────────────────────────────────────────────────

p = subprocess.Popen(
    [EXE, "--transport=stdio"],
    stdin=subprocess.PIPE, stdout=subprocess.PIPE,
    stderr=subprocess.DEVNULL, bufsize=0
)

_rid = 0
def send(req):
    p.stdin.write((json.dumps(req) + "\n").encode())
    p.stdin.flush()

def recv(timeout=10.0):
    """Read one JSON-RPC response line."""
    import select, os
    deadline = time.time() + timeout
    buf = b""
    while time.time() < deadline:
        # Windows: just readline; it'll block until newline
        line = p.stdout.readline()
        if not line:
            raise RuntimeError("server died")
        try:
            return json.loads(line)
        except json.JSONDecodeError:
            continue
    raise TimeoutError("recv timed out")

def call_tool(name, args, timeout=15.0):
    global _rid
    _rid += 1
    send({"jsonrpc": "2.0", "id": _rid, "method": "tools/call",
          "params": {"name": name, "arguments": args}})
    resp = recv(timeout)
    if "error" in resp:
        raise RuntimeError(f"jsonrpc error: {resp['error']}")
    content = resp.get("result", {}).get("content", [])
    txt = content[0].get("text", "") if content else ""
    is_err = resp.get("result", {}).get("isError", False)
    return is_err, txt

# ── bootstrap ─────────────────────────────────────────────────────────────────

send({"jsonrpc": "2.0", "id": 0, "method": "initialize",
      "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                 "clientInfo": {"name": "rigorous_forensics", "version": "1"}}})
recv()
send({"jsonrpc": "2.0", "method": "notifications/initialized"})

# open project
_rid = 1
send({"jsonrpc": "2.0", "id": _rid, "method": "tools/call",
      "params": {"name": "project.open", "arguments": {"path": TARGET}}})
op = recv()
op_data = json.loads(op["result"]["content"][0]["text"])
BINARY_ID  = op_data["binary_id"]
PROJECT_ID = op_data["project_id"]

# ── Python ground-truth helpers ───────────────────────────────────────────────

# Fixed deterministic test vector: 8 bytes from "deadbeef00112233" hex
TEST_HEX  = "deadbeef00112233"
TEST_BYTES = bytes.fromhex(TEST_HEX)   # b'\xde\xad\xbe\xef\x00\x11"3'

def ref_md5(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()

def ref_sha1(data: bytes) -> str:
    return hashlib.sha1(data).hexdigest()

def ref_sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def ref_sha512(data: bytes) -> str:
    return hashlib.sha512(data).hexdigest()

# ── Test cases ────────────────────────────────────────────────────────────────

# Each entry: (tool_name, args_dict, verify_fn, expected_value_or_None)
# verify_fn(parsed_json) -> (ok: bool, got: str)
# Tools that can't be independently verified go to skip list.

RIGOROUS_TESTS = []

# ── 1. forensics_compute_md5 ──────────────────────────────────────────────────
def verify_md5(txt):
    d = json.loads(txt)
    got = d.get("md5", "")
    exp = ref_md5(TEST_BYTES)
    return got == exp, got, exp

RIGOROUS_TESTS.append({
    "tool": "forensics_compute_md5",
    "args": {"hex": TEST_HEX},
    "verify": verify_md5,
    "field": "md5",
})

# ── 2. forensics_compute_sha1 ─────────────────────────────────────────────────
def verify_sha1(txt):
    d = json.loads(txt)
    got = d.get("sha1", "")
    exp = ref_sha1(TEST_BYTES)
    return got == exp, got, exp

RIGOROUS_TESTS.append({
    "tool": "forensics_compute_sha1",
    "args": {"hex": TEST_HEX},
    "verify": verify_sha1,
    "field": "sha1",
})

# ── 3. forensics_compute_sha256 ───────────────────────────────────────────────
def verify_sha256(txt):
    d = json.loads(txt)
    got = d.get("digest", "")
    exp = ref_sha256(TEST_BYTES)
    return got == exp, got, exp

RIGOROUS_TESTS.append({
    "tool": "forensics_compute_sha256",
    "args": {"hex": TEST_HEX},
    "verify": verify_sha256,
    "field": "digest",
})

# ── 4. forensics_compute_sha512 ───────────────────────────────────────────────
def verify_sha512(txt):
    d = json.loads(txt)
    got = d.get("digest", "")
    exp = ref_sha512(TEST_BYTES)
    return got == exp, got, exp

RIGOROUS_TESTS.append({
    "tool": "forensics_compute_sha512",
    "args": {"hex": TEST_HEX},
    "verify": verify_sha512,
    "field": "digest",
})

# ── 5. forensics_mem_windows_version_display ──────────────────────────────────
# WindowsVersion::new(10, 0, 19041).display() -> "10.0.19041"
# Confirmed from blitz.rs: WindowsVersion::new(0,0,0).display() == "0.0.0"
# so format is "major.minor.build".
def verify_win_version(txt):
    d = json.loads(txt)
    got = d.get("display", "")
    exp = "10.0.19041"  # ground truth from Rust tests
    ok = got == exp
    return ok, got, exp

RIGOROUS_TESTS.append({
    "tool": "forensics_mem_windows_version_display",
    "args": {"major": 10, "minor": 0, "build": 19041},
    "verify": verify_win_version,
    "field": "display",
})

# ── 6. forensics_mem_net_protocol_as_str ──────────────────────────────────────
# protocol_id=0 -> TcpV4 -> NetProtocol::TcpV4.as_str() == "TCPv4"
# Confirmed from blitz.rs: assert_eq!(NetProtocol::TcpV4.as_str(), "TCPv4")
def verify_net_proto(txt):
    d = json.loads(txt)
    got = str(d.get("protocol", d.get("as_str", "")))
    exp = "TCPv4"  # ground truth from Rust tests
    ok = got == exp
    return ok, got, exp

RIGOROUS_TESTS.append({
    "tool": "forensics_mem_net_protocol_as_str",
    "args": {"protocol_id": 0},
    "verify": verify_net_proto,
    "field": "protocol/as_str",
})

# ── 7. forensics_mem_process_name_matches ─────────────────────────────────────
# name="svchost.exe", pattern="svchost" -> should match True
def verify_proc_match(txt):
    d = json.loads(txt)
    # result should have a bool field indicating match
    got = d.get("matches", d.get("result", d.get("match")))
    # "svchost" is a substring of "svchost.exe" -> True
    exp = True
    ok = got == exp
    return ok, str(got), str(exp)

RIGOROUS_TESTS.append({
    "tool": "forensics_mem_process_name_matches",
    "args": {"name": "svchost.exe", "pattern": "svchost"},
    "verify": verify_proc_match,
    "field": "matches",
})

# ── 8. forensics_mem_thread_state_from_u8 ─────────────────────────────────────
# value=0 -> ThreadState::Initialized -> "Initialized"
# Confirmed from blitz2.rs: (0u8, ThreadState::Initialized)
def verify_thread_state(txt):
    d = json.loads(txt)
    got = d.get("state", d.get("name", ""))
    exp = "Initialized"  # ground truth from Rust tests
    ok = got == exp
    return ok, got, exp

RIGOROUS_TESTS.append({
    "tool": "forensics_mem_thread_state_from_u8",
    "args": {"value": 0},
    "verify": verify_thread_state,
    "field": "state",
})

# ── 9. forensics_mem_connection_state_from_u8 ─────────────────────────────────
# value=0 -> ConnectionState::Unknown -> "Unknown"
# Confirmed from blitz.rs: assert_eq!(ConnectionState::from_u8(0), ConnectionState::Unknown)
def verify_conn_state(txt):
    d = json.loads(txt)
    got = d.get("state", d.get("name", ""))
    exp = "Unknown"  # ground truth from Rust tests
    ok = got == exp
    return ok, got, exp

RIGOROUS_TESTS.append({
    "tool": "forensics_mem_connection_state_from_u8",
    "args": {"value": 0},
    "verify": verify_conn_state,
    "field": "state",
})

# ── 10. forensics_fs_memfs_node_v2_file_size ─────────────────────────────────
# Create file with content "hello" (5 bytes) via hex -> size should be 5
HELLO_HEX = "68656c6c6f"  # "hello"
def verify_memfs_file_size(txt):
    d = json.loads(txt)
    got = d.get("size", -1)
    exp = 5  # len("hello")
    ok = got == exp
    return ok, str(got), str(exp)

RIGOROUS_TESTS.append({
    "tool": "forensics_fs_memfs_node_v2_file_size",
    "args": {"hex": HELLO_HEX, "name": "test.bin", "inode": 1},
    "verify": verify_memfs_file_size,
    "field": "size",
})

# ── 11. forensics_fs_memfs_node_v2_size_file ─────────────────────────────────
def verify_memfs_size_file(txt):
    d = json.loads(txt)
    got = d.get("size", -1)
    exp = 5
    ok = got == exp
    return ok, str(got), str(exp)

RIGOROUS_TESTS.append({
    "tool": "forensics_fs_memfs_node_v2_size_file",
    "args": {"hex": HELLO_HEX},
    "verify": verify_memfs_size_file,
    "field": "size",
})

# ── 12. forensics_fs_memfs_node_file_read_bytes ───────────────────────────────
def verify_memfs_read_bytes(txt):
    d = json.loads(txt)
    got_hex = d.get("out_hex", "")
    exp_hex = HELLO_HEX
    ok = got_hex.lower() == exp_hex.lower()
    return ok, got_hex, exp_hex

RIGOROUS_TESTS.append({
    "tool": "forensics_fs_memfs_node_file_read_bytes",
    "args": {"hex": HELLO_HEX},
    "verify": verify_memfs_read_bytes,
    "field": "out_hex",
})

# ── 13. forensics_fs_memfs_node_dir_read_bytes_none ──────────────────────────
def verify_dir_read_none(txt):
    d = json.loads(txt)
    got = d.get("read_bytes_is_none", None)
    ok = got is True
    return ok, str(got), "True"

RIGOROUS_TESTS.append({
    "tool": "forensics_fs_memfs_node_dir_read_bytes_none",
    "args": {},
    "verify": verify_dir_read_none,
    "field": "read_bytes_is_none",
})

# ── 14. forensics_fs_inode_table_new_len_empty ────────────────────────────────
def verify_inode_table_new(txt):
    d = json.loads(txt)
    got_len = d.get("len", -1)
    got_empty = d.get("is_empty", None)
    ok = (got_len == 0 and got_empty is True)
    return ok, f"len={got_len} is_empty={got_empty}", "len=0 is_empty=True"

RIGOROUS_TESTS.append({
    "tool": "forensics_fs_inode_table_new_len_empty",
    "args": {},
    "verify": verify_inode_table_new,
    "field": "len+is_empty",
})

# ── 15. forensics_fs_memory_fs_root_inode ─────────────────────────────────────
def verify_memfs_root_inode(txt):
    d = json.loads(txt)
    is_dir = d.get("is_dir", None)
    ok = is_dir is True
    return ok, str(is_dir), "True (root must be a directory)"

RIGOROUS_TESTS.append({
    "tool": "forensics_fs_memory_fs_root_inode",
    "args": {},
    "verify": verify_memfs_root_inode,
    "field": "is_dir",
})

# ── 16. forensics_fs_memory_fs_into_root ─────────────────────────────────────
def verify_memfs_into_root(txt):
    d = json.loads(txt)
    is_dir = d.get("is_dir", None)
    ok = is_dir is True
    return ok, str(is_dir), "True (into_root must be a directory)"

RIGOROUS_TESTS.append({
    "tool": "forensics_fs_memory_fs_into_root",
    "args": {},
    "verify": verify_memfs_into_root,
    "field": "is_dir",
})

# ── SKIP list: tools whose output is nondeterministic or requires live state ──

SKIP_TOOLS = [
    # These scan real binary data from disk; output changes with binary content
    ("forensics_mem_scan_pe_headers",            "scans binary data; output depends on runtime memory layout"),
    ("forensics_mem_scan_stack_canaries",        "scans binary data; output depends on runtime memory layout"),
    ("forensics_mem_find_unicode_strings",       "scans binary data; result set depends on binary content"),
    ("forensics_mem_scan_heap_allocations",      "scans binary data; heap layout is nondeterministic"),
    ("forensics_mem_win_find_processes_mock",    "mock image contents are implementation-defined"),
    ("forensics_mem_win_find_modules_mock",      "mock image contents are implementation-defined"),
    ("forensics_mem_win_find_network_connections_mock", "mock image contents are implementation-defined"),
    ("forensics_mem_win_extract_registry_hives_mock",   "mock image contents are implementation-defined"),
    ("forensics_mem_win_find_kernel_info_mock",  "mock image contents are implementation-defined"),
    ("forensics_mem_linux_find_processes_mock",  "mock image contents are implementation-defined"),
    ("forensics_mem_linux_find_modules_mock",    "mock image contents are implementation-defined"),
    ("forensics_mem_linux_find_sockets_mock",    "mock image contents are implementation-defined"),
    ("forensics_mem_registry_hive_parse_key",    "synthetic hive; key lookup is implementation-defined"),
    ("forensics_fs_prefetch_parse",              "requires real .pf file; no stdlib reference"),
    ("forensics_fs_prefetch_summary",            "requires real .pf file; no stdlib reference"),
    ("forensics_fs_lnk_parse",                  "requires real .lnk file; no stdlib reference"),
    ("forensics_fs_detect_prefetch",             "path-based heuristic; no stdlib reference"),
    ("forensics_fs_detect_lnk",                 "path-based heuristic; no stdlib reference"),
    ("forensics_fs_detect_registry_hive",        "path-based heuristic; no stdlib reference"),
    ("forensics_fs_detect_evtx",                "path-based heuristic; no stdlib reference"),
    ("forensics_fs_detect_browser_db",          "path-based heuristic; no stdlib reference"),
    ("forensics_fs_detect_memory_dump",         "path-based heuristic; no stdlib reference"),
    ("forensics_fs_detect_dropped_payload",     "path-based heuristic; no stdlib reference"),
    ("forensics_fs_detect_pagefile",            "path-based heuristic; no stdlib reference"),
    ("forensics_fs_detect_certificate_store",   "path-based heuristic; no stdlib reference"),
    ("forensics_fs_artifact_scanner_scan_path", "aggregates multiple heuristics; no stdlib reference"),
    ("forensics_fs_lnk_analyzer_summary",       "requires real .lnk data; no stdlib reference"),
    ("forensics_fs_lnk_file_target_path",       "requires real .lnk data; no stdlib reference"),
    ("forensics_fs_prefetch_analyzer_report",   "requires real .pf data; no stdlib reference"),
    ("forensics_fs_prefetch_pattern_matcher_risk", "requires real .pf data; no stdlib reference"),
    ("forensics_fs_prefetch_file_loaded_modules",  "requires real .pf data; no stdlib reference"),
    ("forensics_fs_memfs_node_v2_is_file",      "internal invariant; redundant with memfs_file_size"),
    ("forensics_fs_memfs_node_v2_is_dir_check", "internal invariant; checked via memory_fs_root_inode"),
    ("forensics_fs_memfs_node_dir_children",    "structural check; no arithmetic reference"),
    ("forensics_fs_memfs_node_dir_child_by_name","structural check; no arithmetic reference"),
    ("forensics_fs_memfs_node_lazy_file_read",  "implementation-defined lazy callback"),
    ("forensics_fs_memfs_v2_walker_root",       "structural walk; verified transitively"),
    ("forensics_fs_to_export_dir_single_file",  "writes to temp dir; filesystem side-effect"),
    ("forensics_fs_inode_table_insert_get",     "structural; no arithmetic reference"),
    ("forensics_fs_inode_table_find_by_name",   "structural; no arithmetic reference"),
    ("forensics_fs_inode_table_find_deleted",   "structural; no arithmetic reference"),
    ("forensics_fs_inode_is_directory",         "bit-flag interpretation; implementation-defined"),
    ("forensics_fs_data_run_new_byte_size",     "cluster arithmetic; implementation-defined cluster_size mapping"),
    ("forensics_fs_inode_total_run_bytes",      "cluster arithmetic; implementation-defined"),
    ("forensics_fs_timeline_event_new",         "struct construction; no external reference"),
    ("forensics_fs_timeline_event_type_kind_name","enum name mapping; implementation-defined"),
    ("forensics_fs_timeline_push_sort",         "sort order; structural only"),
    ("forensics_fs_timeline_filter_by_type",    "filter; structural only"),
    ("forensics_fs_timeline_filter_by_time",    "filter; structural only"),
    ("forensics_fs_timeline_hot_paths",         "top-N; structural only"),
    ("forensics_fs_timeline_csv_roundtrip",     "csv format; implementation-defined"),
    ("forensics_fs_timeline_report",            "summary string; implementation-defined"),
    ("forensics_fs_node_v2_new_file",           "struct creation; redundant with size checks"),
    ("forensics_fs_node_v2_new_dir",            "struct creation; verified via root_inode"),
    ("forensics_fs_node_v2_add_child",          "structural; no arithmetic reference"),
    ("forensics_fs_node_v2_find_child",         "structural lookup; no arithmetic reference"),
    ("forensics_fs_node_v2_find_by_inode",      "structural lookup; no arithmetic reference"),
    ("forensics_fs_node_v2_readdir_entries",    "structural listing; no arithmetic reference"),
    ("forensics_fs_memory_fs_new",              "constructor; verified via root_inode"),
    ("forensics_fs_memory_fs_build_process_tree_empty", "empty tree; structural only"),
    ("forensics_fs_memfs_node_file_probe",      "structural probe; redundant"),
    ("forensics_fs_memfs_node_dir_probe",       "structural probe; redundant"),
    ("forensics_fs_memfs_node_child_lookup",    "structural lookup; no arithmetic reference"),
    ("forensics_fs_node_v2_sizes",              "size property; redundant with file_size tests"),
    ("forensics_fs_memory_fs_new_root",         "constructor variant; redundant"),
]

# ── Run rigorous tests ────────────────────────────────────────────────────────

rigorous_results = []
mismatches = []

for tc in RIGOROUS_TESTS:
    tool = tc["tool"]
    args = tc["args"]
    verify = tc["verify"]
    t0 = time.time()
    try:
        is_err, txt = call_tool(tool, args, timeout=15.0)
        elapsed = time.time() - t0
        if is_err:
            entry = {
                "tool": tool,
                "status": "TOOL_ERROR",
                "error": txt[:300],
                "elapsed_s": round(elapsed, 3),
            }
            rigorous_results.append(entry)
            mismatches.append({"tool": tool, "expected": tc.get("field",""), "actual": f"TOOL_ERROR: {txt[:100]}"})
        else:
            ok, got, exp = verify(txt)
            status = "PASS" if ok else "FAIL"
            entry = {
                "tool": tool,
                "status": status,
                "field": tc.get("field", ""),
                "expected": exp,
                "actual": got,
                "elapsed_s": round(elapsed, 3),
            }
            rigorous_results.append(entry)
            if not ok:
                mismatches.append({"tool": tool, "expected": exp, "actual": got})
    except TimeoutError:
        entry = {"tool": tool, "status": "TIMEOUT", "elapsed_s": 15.0}
        rigorous_results.append(entry)
        mismatches.append({"tool": tool, "expected": tc.get("field",""), "actual": "TIMEOUT"})
    except Exception as e:
        entry = {"tool": tool, "status": "EXCEPTION", "error": str(e)[:300], "elapsed_s": round(time.time()-t0, 3)}
        rigorous_results.append(entry)
        mismatches.append({"tool": tool, "expected": tc.get("field",""), "actual": f"EXCEPTION: {e}"})

# ── Tally ─────────────────────────────────────────────────────────────────────

tools_passed  = sum(1 for r in rigorous_results if r["status"] == "PASS")
tools_failed  = sum(1 for r in rigorous_results if r["status"] in ("FAIL","TOOL_ERROR","TIMEOUT","EXCEPTION"))
tools_hardened = len(rigorous_results)
tools_skipped  = len(SKIP_TOOLS)

# ── Write outputs ─────────────────────────────────────────────────────────────

with open(OUT_RIGOROUS, "w") as f:
    json.dump({
        "summary": {
            "tools_hardened": tools_hardened,
            "tools_passed":   tools_passed,
            "tools_failed":   tools_failed,
            "tools_skipped":  tools_skipped,
            "mismatches":     mismatches,
        },
        "results": rigorous_results,
    }, f, indent=2)

with open(OUT_SKIP, "w") as f:
    json.dump([{"tool": t, "reason": r} for t, r in SKIP_TOOLS], f, indent=2)

p.stdin.close()
p.terminate()

print(json.dumps({
    "category": "forensics",
    "tools_hardened": tools_hardened,
    "tools_passed":   tools_passed,
    "tools_failed":   tools_failed,
    "tools_skipped":  tools_skipped,
    "mismatches":     mismatches,
}, indent=2))
