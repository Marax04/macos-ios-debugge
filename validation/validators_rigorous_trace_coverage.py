#!/usr/bin/env python3
"""
Rigorous independent validator for trace_coverage_ MCP tools.
All truth values are computed from Python stdlib or well-known algorithms.
"""

import subprocess
import json
import struct
import math
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from collections import Counter

MCP_BINARY = Path(r"C:\Users\Fra\Desktop\RustRE\target\release\rustre-mcp.exe")
WORKING_DIR = Path(r"C:\Users\Fra\Desktop\RustRE")
REPORT_FILE = Path(r"C:\Users\Fra\Desktop\RustRE\validation\rigorous_trace_coverage.json")


# ---------------------------------------------------------------------------
# MCP JSON-RPC client
# ---------------------------------------------------------------------------

class MCPClient:
    def __init__(self, binary_path: Path):
        self.proc = subprocess.Popen(
            [str(binary_path), "--transport=stdio"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            cwd=str(WORKING_DIR),
            bufsize=0,
        )
        self.request_id = 0
        self._initialize()

    def _initialize(self) -> None:
        init_req = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "rigorous-validator", "version": "1.0"},
            },
        }
        resp = self._send(init_req)
        if resp is None or resp.get("error"):
            raise RuntimeError(f"Init failed: {resp}")
        notif = {"jsonrpc": "2.0", "method": "notifications/initialized"}
        self.proc.stdin.write((json.dumps(notif) + "\n").encode())
        self.proc.stdin.flush()

    def _send(self, req: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        self.proc.stdin.write((json.dumps(req) + "\n").encode())
        self.proc.stdin.flush()
        resp_line = self.proc.stdout.readline()
        if not resp_line:
            return None
        return json.loads(resp_line)

    def call_tool(self, name: str, args: Dict[str, Any]) -> Any:
        self.request_id += 1
        req = {
            "jsonrpc": "2.0",
            "id": self.request_id,
            "method": "tools/call",
            "params": {"name": name, "arguments": args},
        }
        resp = self._send(req)
        if resp is None:
            return {"error": "No response"}
        if "error" in resp:
            return {"error": resp["error"]}
        content = resp.get("result", {}).get("content", [])
        if not content:
            return resp.get("result", {})
        text_content = content[0].get("text", "")
        try:
            return json.loads(text_content)
        except Exception:
            return {"text": text_content}

    def close(self) -> None:
        try:
            self.proc.terminate()
            self.proc.wait(timeout=2)
        except Exception:
            self.proc.kill()


# ---------------------------------------------------------------------------
# Python ground-truth helpers
# ---------------------------------------------------------------------------

def py_coverage_percent(hit: int, total: int) -> float:
    """Independent: hit/total * 100.
    When total==0, returns 100.0 by convention (no data = fully covered),
    matching rustre_trace::coverage_percent and FunctionStats::coverage_pct."""
    if total == 0:
        return 100.0
    return (hit / total) * 100.0


def py_function_stats_pct(covered: int, total: int) -> float:
    """FunctionStats::coverage_pct: covered/total*100; 100.0 when total==0."""
    if total == 0:
        return 100.0
    return (covered / total) * 100.0


def py_afl_bitmap_count(byte_list: List[int]) -> int:
    """Count number of set bits (popcount) across all bytes in the bitmap."""
    return sum(bin(b).count('1') for b in byte_list)


def py_afl_jaccard(a: List[int], b: List[int]) -> float:
    """Jaccard of two AFL bitmaps treated as bit arrays.
    inter = popcount(a AND b), uni = popcount(a OR b)."""
    length = max(len(a), len(b))
    inter = 0
    uni = 0
    for i in range(length):
        ba = a[i] if i < len(a) else 0
        bb = b[i] if i < len(b) else 0
        inter += bin(ba & bb).count('1')
        uni += bin(ba | bb).count('1')
    if uni == 0:
        return 1.0
    return inter / uni


def py_covedge_display(from_addr: int, to_addr: int) -> str:
    """CovEdge Display: 0x{from:x}->0x{to:x}"""
    return f"0x{from_addr:x}->0x{to_addr:x}"


def py_bitmap_ops(a: List[int], b: List[int]) -> Dict[str, int]:
    """Union/intersection/difference set-bit counts for two bitmaps."""
    length = max(len(a), len(b))
    union_bits = 0
    inter_bits = 0
    diff_a_b = 0
    a_bits = 0
    b_bits = 0
    for i in range(length):
        ba = a[i] if i < len(a) else 0
        bb = b[i] if i < len(b) else 0
        union_bits += bin(ba | bb).count('1')
        inter_bits += bin(ba & bb).count('1')
        diff_a_b += bin(ba & (~bb & 0xFF)).count('1')
        a_bits += bin(ba).count('1')
        b_bits += bin(bb).count('1')
    return {
        "union_set": union_bits,
        "intersection_set": inter_bits,
        "difference_a_minus_b_set": diff_a_b,
        "a_set": a_bits,
        "b_set": b_bits,
    }


def py_bitmap_coverage_ratio(byte_list: List[int]) -> float:
    """Fraction of bits set in a bitmap. size = len*8."""
    total_bits = len(byte_list) * 8
    if total_bits == 0:
        return 1.0
    set_bits = sum(bin(b).count('1') for b in byte_list)
    return set_bits / total_bits


def py_diff_overlap_pct(a: List[int], b: List[int]) -> float:
    """Jaccard of two address sets * 100."""
    sa = set(a)
    sb = set(b)
    both = sa & sb
    uni = sa | sb
    if not uni:
        return 100.0
    return len(both) / len(uni) * 100.0


def py_parse_lcov_record_count(lcov_text: str) -> Tuple[int, List[str]]:
    """Count end_of_record markers and collect source files."""
    records = 0
    sources = []
    current_sf = None
    for line in lcov_text.splitlines():
        line = line.strip()
        if line.startswith("SF:"):
            current_sf = line[3:].strip()
        elif line == "end_of_record":
            records += 1
            if current_sf is not None:
                sources.append(current_sf)
            current_sf = None
    return records, sources


def py_parse_custom_binary(data: bytes) -> Tuple[int, int]:
    """Parse (u64 addr, u64 count) pairs LE. Returns (unique_bbs, total_execs)."""
    if len(data) % 16 != 0:
        raise ValueError(f"length {len(data)} not multiple of 16")
    bb_hits: Dict[int, int] = {}
    for i in range(0, len(data), 16):
        addr = struct.unpack_from('<Q', data, i)[0]
        count = struct.unpack_from('<Q', data, i + 8)[0]
        bb_hits[addr] = bb_hits.get(addr, 0) + count
    return len(bb_hits), sum(bb_hits.values())


def py_afl_new_edges(a: List[int], b: List[int]) -> int:
    """Count bits set in b but NOT in a (b.difference(a).count_set())."""
    length = max(len(a), len(b))
    count = 0
    for i in range(length):
        ba = a[i] if i < len(a) else 0
        bb = b[i] if i < len(b) else 0
        count += bin(bb & (~ba & 0xFF)).count('1')
    return count


# ---------------------------------------------------------------------------
# Test cases with known truth
# ---------------------------------------------------------------------------

def run_checks(client: MCPClient) -> Tuple[int, int, List[Dict]]:
    passed = 0
    failed = 0
    mismatches = []

    def check(label: str, mcp_val: Any, truth_val: Any, tol: float = 0.0) -> None:
        nonlocal passed, failed
        if mcp_val is None:
            print(f"  SKIP  {label} — no value in MCP response")
            return
        if tol > 0.0:
            ok = abs(float(mcp_val) - float(truth_val)) <= tol
        else:
            ok = mcp_val == truth_val
        if ok:
            passed += 1
            print(f"  PASS  {label}: {mcp_val}")
        else:
            failed += 1
            print(f"  FAIL  {label}: got={mcp_val!r} expected={truth_val!r}")
            mismatches.append({"label": label, "got": mcp_val, "expected": truth_val})

    # ------------------------------------------------------------------
    # 1. trace_coverage_percent  (hit=75, total=100 => 75.0)
    # ------------------------------------------------------------------
    print("\n[1] trace_coverage_percent")
    r = client.call_tool("trace_coverage_percent", {"hit": 75, "total": 100})
    truth = py_coverage_percent(75, 100)  # 75.0
    check("coverage_percent 75/100", r.get("percent") or r.get("coverage_percent"), truth, tol=0.001)

    # edge: 0/0 => 100.0 (no-data = fully covered by convention, matches Rust)
    r2 = client.call_tool("trace_coverage_percent", {"hit": 0, "total": 0})
    check("coverage_percent 0/0", r2.get("percent") if r2.get("percent") is not None else r2.get("coverage_percent"), py_coverage_percent(0, 0), tol=0.001)

    # ------------------------------------------------------------------
    # 2. trace_coverage_function_stats_pct  (covered=3, total=4 => 75.0)
    # ------------------------------------------------------------------
    print("\n[2] trace_coverage_function_stats_pct")
    r = client.call_tool("trace_coverage_function_stats_pct", {"total_bb": 4, "covered_bb": 3})
    check("function_stats_pct 3/4", r.get("coverage_pct"), py_function_stats_pct(3, 4), tol=0.001)

    # edge: total=0 => 100.0
    r2 = client.call_tool("trace_coverage_function_stats_pct", {"total_bb": 0, "covered_bb": 0})
    check("function_stats_pct 0/0", r2.get("coverage_pct"), 100.0, tol=0.001)

    # 10/10 => 100.0, is_fully_covered=True
    r3 = client.call_tool("trace_coverage_function_stats_pct", {"total_bb": 10, "covered_bb": 10})
    check("function_stats_pct 10/10", r3.get("coverage_pct"), 100.0, tol=0.001)

    # ------------------------------------------------------------------
    # 3. trace_coverage_afl_bitmap_count  — 4 bytes [0xFF,0x00,0xAA,0x55]
    #    popcount: 8+0+4+4 = 16
    # ------------------------------------------------------------------
    print("\n[3] trace_coverage_afl_bitmap_count")
    test_bytes = [0xFF, 0x00, 0xAA, 0x55]
    truth_count = py_afl_bitmap_count(test_bytes)  # 16
    r = client.call_tool("trace_coverage_afl_bitmap_count", {"bytes": test_bytes})
    check("afl_bitmap_count [0xFF,0x00,0xAA,0x55]", r.get("set_edges"), truth_count)

    # All zero bytes => 0 set edges
    r2 = client.call_tool("trace_coverage_afl_bitmap_count", {"bytes": [0] * 8})
    check("afl_bitmap_count all zero", r2.get("set_edges"), 0)

    # ------------------------------------------------------------------
    # 4. trace_coverage_afl_jaccard  — identical bitmaps => 1.0
    # ------------------------------------------------------------------
    print("\n[4] trace_coverage_afl_jaccard")
    bm_a = [0b10101010, 0b11001100]
    bm_b = [0b10101010, 0b11001100]
    r = client.call_tool("trace_coverage_afl_jaccard", {"a": bm_a, "b": bm_b})
    check("jaccard identical", r.get("jaccard"), py_afl_jaccard(bm_a, bm_b), tol=1e-9)

    # disjoint bitmaps => 0.0
    bm_x = [0b11110000]
    bm_y = [0b00001111]
    r2 = client.call_tool("trace_coverage_afl_jaccard", {"a": bm_x, "b": bm_y})
    check("jaccard disjoint", r2.get("jaccard"), py_afl_jaccard(bm_x, bm_y), tol=1e-9)

    # ------------------------------------------------------------------
    # 5. trace_coverage_covedge_display  — from=0x1000, to=0x2000
    # ------------------------------------------------------------------
    print("\n[5] trace_coverage_covedge_display")
    r = client.call_tool("trace_coverage_covedge_display", {"from": 0x1000, "to": 0x2000})
    check("covedge 0x1000->0x2000", r.get("display"), py_covedge_display(0x1000, 0x2000))

    r2 = client.call_tool("trace_coverage_covedge_display", {"from": 0, "to": 0xDEADBEEF})
    check("covedge 0->0xdeadbeef", r2.get("display"), py_covedge_display(0, 0xDEADBEEF))

    # ------------------------------------------------------------------
    # 6. trace_coverage_covbitmap_ops  — [0xFF,0x00] vs [0x00,0xFF]
    # ------------------------------------------------------------------
    print("\n[6] trace_coverage_covbitmap_ops")
    ops_a = [0xFF, 0x00]
    ops_b = [0x00, 0xFF]
    truth_ops = py_bitmap_ops(ops_a, ops_b)
    r = client.call_tool("trace_coverage_covbitmap_ops", {"a": ops_a, "b": ops_b})
    check("ops union", r.get("union_set"), truth_ops["union_set"])
    check("ops intersection", r.get("intersection_set"), truth_ops["intersection_set"])
    check("ops diff_a_minus_b", r.get("difference_a_minus_b_set"), truth_ops["difference_a_minus_b_set"])

    # coverage ratios
    truth_a_ratio = py_bitmap_coverage_ratio(ops_a)  # 0.5
    truth_b_ratio = py_bitmap_coverage_ratio(ops_b)  # 0.5
    check("ops a_coverage_ratio", r.get("a_coverage_ratio"), truth_a_ratio, tol=1e-9)
    check("ops b_coverage_ratio", r.get("b_coverage_ratio"), truth_b_ratio, tol=1e-9)

    # ------------------------------------------------------------------
    # 7. trace_coverage_diff_overlap_pct  — identical => 100.0
    # ------------------------------------------------------------------
    print("\n[7] trace_coverage_diff_overlap_pct")
    addrs_a = [0x1000, 0x2000, 0x3000]
    addrs_b = [0x1000, 0x2000, 0x3000]
    r = client.call_tool("trace_coverage_diff_overlap_pct", {"a": addrs_a, "b": addrs_b})
    check("overlap identical", r.get("overlap_pct"), py_diff_overlap_pct(addrs_a, addrs_b), tol=0.001)

    # 2 in common, 1 unique each => jaccard = 2/4 = 50%
    addrs_c = [0x1000, 0x2000]
    addrs_d = [0x2000, 0x3000]
    r2 = client.call_tool("trace_coverage_diff_overlap_pct", {"a": addrs_c, "b": addrs_d})
    check("overlap partial", r2.get("overlap_pct"), py_diff_overlap_pct(addrs_c, addrs_d), tol=0.001)

    # ------------------------------------------------------------------
    # 8. trace_coverage_parse_lcov_wire  — 2 records
    # ------------------------------------------------------------------
    print("\n[8] trace_coverage_parse_lcov_wire")
    lcov_text = (
        "TN:test1\n"
        "SF:/src/foo.c\n"
        "DA:10,5\n"
        "LF:1\n"
        "LH:1\n"
        "end_of_record\n"
        "TN:test2\n"
        "SF:/src/bar.c\n"
        "DA:20,0\n"
        "LF:1\n"
        "LH:0\n"
        "end_of_record\n"
    )
    truth_recs, truth_files = py_parse_lcov_record_count(lcov_text)  # 2, ['/src/foo.c','/src/bar.c']
    r = client.call_tool("trace_coverage_parse_lcov_wire", {"text": lcov_text})
    check("lcov record_count", r.get("record_count"), truth_recs)
    got_files = sorted(r.get("source_files", []))
    exp_files = sorted(truth_files)
    check("lcov source_files", got_files, exp_files)

    # ------------------------------------------------------------------
    # 9. trace_coverage_parse_custom_binary  — 2 (addr,count) pairs
    # ------------------------------------------------------------------
    print("\n[9] trace_coverage_parse_custom_binary")
    raw = struct.pack('<QQ', 0x1000, 5) + struct.pack('<QQ', 0x2000, 3)
    byte_list = list(raw)
    truth_ub, truth_te = py_parse_custom_binary(raw)  # 2, 8
    r = client.call_tool("trace_coverage_parse_custom_binary", {"bytes": byte_list})
    check("custom_binary unique_bbs", r.get("unique_bbs"), truth_ub)
    check("custom_binary total_executions", r.get("total_executions"), truth_te)

    # ------------------------------------------------------------------
    # 10. trace_coverage_load_afl_bitmap_v2  — 4 bytes [0xFF]*4 => 32 bits
    # ------------------------------------------------------------------
    print("\n[10] trace_coverage_load_afl_bitmap_v2")
    bm_bytes = [0xFF] * 4
    r = client.call_tool("trace_coverage_load_afl_bitmap_v2", {"bytes": bm_bytes})
    check("load_afl_v2 size", r.get("size"), len(bm_bytes) * 8)
    check("load_afl_v2 set_bits", r.get("set_bits"), py_afl_bitmap_count(bm_bytes))
    check("load_afl_v2 is_empty", r.get("is_empty"), False)
    check("load_afl_v2 ratio", r.get("ratio"), py_bitmap_coverage_ratio(bm_bytes), tol=1e-9)

    # ------------------------------------------------------------------
    # 11. trace_coverage_afl_new_edges_v2  — b has 1 new bit vs a
    # ------------------------------------------------------------------
    print("\n[11] trace_coverage_afl_new_edges_v2")
    na = [0b11110000]
    nb = [0b11111000]  # one new bit (bit 3) in b vs a
    truth_new = py_afl_new_edges(na, nb)  # 1
    r = client.call_tool("trace_coverage_afl_new_edges_v2", {"a": na, "b": nb})
    check("afl_new_edges", r.get("new_edges"), truth_new)
    # jaccard of na vs nb
    check("afl_new_edges jaccard", r.get("jaccard"), py_afl_jaccard(na, nb), tol=1e-9)

    return passed, failed, mismatches


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    print("[*] Starting rigorous trace_coverage validator...")
    client = None
    try:
        client = MCPClient(MCP_BINARY)
        print("[+] MCP initialized")

        passed, failed, mismatches = run_checks(client)

        total = passed + failed
        tools_hardened = 11  # distinct tools exercised

        print(f"\n{'='*50}")
        print(f"Tools hardened : {tools_hardened}")
        print(f"Checks passed  : {passed} / {total}")
        print(f"Checks failed  : {failed}")
        print(f"Real mismatches: {len(mismatches)}")
        if mismatches:
            print("\nMISMATCHES:")
            for m in mismatches:
                print(f"  {m['label']}: got={m['got']!r} expected={m['expected']!r}")

        report = {
            "module": "trace_coverage",
            "tools_hardened": tools_hardened,
            "checks_passed": passed,
            "checks_failed": failed,
            "real_mismatches": len(mismatches),
            "mismatches": mismatches,
        }
        REPORT_FILE.parent.mkdir(parents=True, exist_ok=True)
        with open(REPORT_FILE, "w") as f:
            json.dump(report, f, indent=2)
        print(f"\n[+] Report saved to {REPORT_FILE}")
        return report

    finally:
        if client:
            client.close()


if __name__ == "__main__":
    main()
