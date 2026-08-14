#!/usr/bin/env python3
"""
Rigorous ground-truth validation for all iadl_* MCP tools.
Each tool is called via json-rpc-over-stdio and the result is compared
against an inline Python reference implementation.
"""
import json
import math
import subprocess
import sys

EXE = r"C:\Users\Fra\Desktop\RustRE\target\release\rustre-mcp.exe"
TARGET = r"C:\Users\Fra\Desktop\Zyphora\target\release\cargo-zyphora.exe"
OUT = r"C:\Users\Fra\Desktop\RustRE\validation\rigorous_iadl_v2.json"
SKIP_OUT = r"C:\Users\Fra\Desktop\RustRE\validation\skip_iadl.json"

# ── Python reference implementations ─────────────────────────────────────────

def ref_moving_average(history, window):
    if window == 0 or not history:
        return []
    result = []
    for i in range(len(history) - window + 1):
        result.append(sum(history[i:i+window]) / window)
    return result

def ref_ema(history, alpha):
    if not history:
        return []
    alpha = max(1e-12, min(1.0, alpha))
    ema = [history[0]]
    for v in history[1:]:
        ema.append(alpha * v + (1.0 - alpha) * ema[-1])
    return ema

def ref_trend_slope(history):
    n = len(history)
    if n < 2:
        return 0.0
    x_mean = (n - 1) / 2.0
    y_mean = sum(history) / n
    num = sum((i - x_mean) * (y - y_mean) for i, y in enumerate(history))
    den = sum((i - x_mean) ** 2 for i in range(n))
    if abs(den) < 1e-12:
        return 0.0
    return num / den

def ref_compute_hash(data: bytes, algorithm: str) -> int:
    algo = algorithm.lower()
    if algo == "djb2":
        h = 5381
        for b in data:
            h = ((h * 33) + b) & 0xFFFFFFFF
        return h
    elif algo == "fnv1a32":
        PRIME = 0x01000193
        BASIS = 0x811C9DC5
        h = BASIS
        for b in data:
            h ^= b
            h = (h * PRIME) & 0xFFFFFFFF
        return h
    elif algo == "sdbm":
        h = 0
        for b in data:
            h = (b + (h << 6) + (h << 16) - h) & 0xFFFFFFFF
        return h
    elif algo == "crc32":
        crc = 0xFFFFFFFF
        for b in data:
            crc ^= b
            for _ in range(8):
                if crc & 1:
                    crc = (crc >> 1) ^ 0xEDB88320
                else:
                    crc >>= 1
        return (~crc) & 0xFFFFFFFF
    elif algo == "adler32":
        MOD = 65521
        a = 1
        b_val = 0
        for byte in data:
            a = (a + byte) % MOD
            b_val = (b_val + a) % MOD
        return ((b_val << 16) | a) & 0xFFFFFFFF
    elif algo in ("ror_hash", "rorhash", "ror"):
        h = 0
        for b in data:
            # rotate_right(13) on u32
            h = ((h >> 13) | (h << (32 - 13))) & 0xFFFFFFFF
            h = (h + b) & 0xFFFFFFFF
        return h
    else:
        raise ValueError(f"unsupported algorithm: {algorithm}")

def ref_analyze_binary_for_protections(data: bytes) -> dict:
    """Reference implementation matching Rust analyze_binary_for_protections."""
    def shannon_entropy(chunk: bytes) -> float:
        if not chunk:
            return 0.0
        freq = [0] * 256
        for b in chunk:
            freq[b] += 1
        n = len(chunk)
        ent = 0.0
        for f in freq:
            if f > 0:
                p = f / n
                ent -= p * math.log2(p)
        return ent

    def contains_bytes(haystack: bytes, needle: bytes) -> bool:
        return needle in haystack

    def count_pattern_nonoverlap(data: bytes, pattern: bytes) -> int:
        if not pattern or len(data) < len(pattern):
            return 0
        count = 0
        i = 0
        plen = len(pattern)
        while i + plen <= len(data):
            if data[i:i+plen] == pattern:
                count += 1
                i += plen
            else:
                i += 1
        return count

    WINDOW = 256
    binary_size = len(data)
    high_entropy_sections = []

    for window_idx, start in enumerate(range(0, binary_size, WINDOW)):
        chunk = data[start:start+WINDOW]
        if shannon_entropy(chunk) > 7.0:
            high_entropy_sections.append(f"window_{(window_idx * WINDOW):06x}")

    for marker in [b"UPX0", b"UPX1", b"UPX!"]:
        if contains_bytes(data, marker):
            high_entropy_sections.append(marker.decode())

    antidebug = [
        b"IsDebuggerPresent",
        b"CheckRemoteDebuggerPresent",
        b"NtQueryInformationProcess",
        b"OutputDebugString",
        b"FindWindow",
        b"ZwSetInformationThread",
    ]
    for name in antidebug:
        if contains_bytes(data, name):
            high_entropy_sections.append(name.decode())

    fc_x86 = count_pattern_nonoverlap(data, bytes([0x55, 0x8B, 0xEC]))
    fc_x64 = count_pattern_nonoverlap(data, bytes([0x55, 0x48, 0x89, 0xE5]))
    function_count = min(fc_x86 + fc_x64, 0xFFFFFFFF)

    return {
        "binary_size": binary_size,
        "function_count": function_count,
        "high_entropy_sections": high_entropy_sections,
    }

# ── MCP stdio helpers ─────────────────────────────────────────────────────────

def start_server():
    return subprocess.Popen(
        [EXE, "--transport=stdio"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        bufsize=0,
    )

def send(p, req):
    p.stdin.write((json.dumps(req) + "\n").encode())
    p.stdin.flush()

def recv(p):
    line = p.stdout.readline()
    if not line:
        raise RuntimeError("server died")
    try:
        return json.loads(line)
    except json.JSONDecodeError:
        return {"error": {"message": f"bad-line: {line[:100]!r}"}}

def call_tool(p, rid, name, arguments):
    send(p, {"jsonrpc": "2.0", "id": rid, "method": "tools/call",
             "params": {"name": name, "arguments": arguments}})
    resp = recv(p)
    if "error" in resp:
        return None, str(resp["error"])
    result = resp.get("result", {})
    if result.get("isError"):
        content = result.get("content", [])
        txt = content[0].get("text", "") if content else ""
        return None, txt
    content = result.get("content", [])
    txt = content[0].get("text", "") if content else ""
    try:
        return json.loads(txt), None
    except Exception:
        return txt, None

def setup_server(p):
    send(p, {"jsonrpc": "2.0", "id": 1, "method": "initialize",
             "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                        "clientInfo": {"name": "rigorous_iadl", "version": "1"}}})
    recv(p)
    send(p, {"jsonrpc": "2.0", "method": "notifications/initialized"})
    send(p, {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
             "params": {"name": "project.open", "arguments": {"path": TARGET}}})
    recv(p)

# ── Test cases ────────────────────────────────────────────────────────────────

HISTORY = [1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0]
WINDOW = 3
ALPHA = 0.3
TEST_HEX = "deadbeef00112233"
TEST_BYTES = bytes.fromhex(TEST_HEX)
BINARY_DATA = bytes([0x55, 0x8B, 0xEC, 0x00, 0x55, 0x48, 0x89, 0xE5] + [0xAA] * 248)

def float_list_close(a, b, tol=1e-9):
    if len(a) != len(b):
        return False
    return all(abs(x - y) < tol for x, y in zip(a, b))

def run_all():
    results = []
    mismatches = []
    skipped = []

    p = start_server()
    try:
        setup_server(p)
        rid = 100

        # ── 1. iadl_convergence_moving_average ────────────────────────────────
        rid += 1
        args = {"history": HISTORY, "window": WINDOW}
        actual, err = call_tool(p, rid, "iadl_convergence_moving_average", args)
        expected = ref_moving_average(HISTORY, WINDOW)
        if err:
            results.append({"tool": "iadl_convergence_moving_average", "status": "FAIL",
                            "reason": f"tool error: {err}"})
            mismatches.append({"tool": "iadl_convergence_moving_average",
                               "expected": expected, "actual": f"ERROR: {err}"})
        else:
            got = actual.get("moving_average", [])
            if float_list_close(got, expected):
                results.append({"tool": "iadl_convergence_moving_average", "status": "PASS"})
            else:
                results.append({"tool": "iadl_convergence_moving_average", "status": "FAIL",
                                "expected": expected, "actual": got})
                mismatches.append({"tool": "iadl_convergence_moving_average",
                                   "expected": expected, "actual": got})

        # ── 2. iadl_convergence_ema ───────────────────────────────────────────
        rid += 1
        args = {"history": HISTORY, "alpha": ALPHA}
        actual, err = call_tool(p, rid, "iadl_convergence_ema", args)
        expected = ref_ema(HISTORY, ALPHA)
        if err:
            results.append({"tool": "iadl_convergence_ema", "status": "FAIL",
                            "reason": f"tool error: {err}"})
            mismatches.append({"tool": "iadl_convergence_ema",
                               "expected": expected, "actual": f"ERROR: {err}"})
        else:
            got = actual.get("ema", [])
            if float_list_close(got, expected):
                results.append({"tool": "iadl_convergence_ema", "status": "PASS"})
            else:
                results.append({"tool": "iadl_convergence_ema", "status": "FAIL",
                                "expected": expected, "actual": got})
                mismatches.append({"tool": "iadl_convergence_ema",
                                   "expected": expected, "actual": got})

        # ── 3. iadl_convergence_trend_slope ──────────────────────────────────
        rid += 1
        args = {"history": HISTORY}
        actual, err = call_tool(p, rid, "iadl_convergence_trend_slope", args)
        expected = ref_trend_slope(HISTORY)
        if err:
            results.append({"tool": "iadl_convergence_trend_slope", "status": "FAIL",
                            "reason": f"tool error: {err}"})
            mismatches.append({"tool": "iadl_convergence_trend_slope",
                               "expected": expected, "actual": f"ERROR: {err}"})
        else:
            got = actual.get("slope", None)
            if got is not None and abs(got - expected) < 1e-9:
                results.append({"tool": "iadl_convergence_trend_slope", "status": "PASS"})
            else:
                results.append({"tool": "iadl_convergence_trend_slope", "status": "FAIL",
                                "expected": expected, "actual": got})
                mismatches.append({"tool": "iadl_convergence_trend_slope",
                                   "expected": expected, "actual": got})

        # ── 4. iadl_compute_hash — all algorithms ─────────────────────────────
        for algo in ["djb2", "fnv1a32", "sdbm", "crc32", "adler32", "ror_hash"]:
            rid += 1
            tool = "iadl_compute_hash"
            args = {"hex": TEST_HEX, "algorithm": algo}
            actual, err = call_tool(p, rid, tool, args)
            expected = ref_compute_hash(TEST_BYTES, algo)
            label = f"{tool}[{algo}]"
            if err:
                results.append({"tool": label, "status": "FAIL",
                                "reason": f"tool error: {err}"})
                mismatches.append({"tool": label, "expected": expected,
                                   "actual": f"ERROR: {err}"})
            else:
                got = actual.get("hash", None)
                if got == expected:
                    results.append({"tool": label, "status": "PASS"})
                else:
                    results.append({"tool": label, "status": "FAIL",
                                    "expected": expected, "actual": got})
                    mismatches.append({"tool": label, "expected": expected, "actual": got})

        # ── 5. iadl_analyze_binary_for_protections ────────────────────────────
        rid += 1
        args = {"hex": BINARY_DATA.hex()}
        actual, err = call_tool(p, rid, "iadl_analyze_binary_for_protections", args)
        expected = ref_analyze_binary_for_protections(BINARY_DATA)
        if err:
            results.append({"tool": "iadl_analyze_binary_for_protections", "status": "FAIL",
                            "reason": f"tool error: {err}"})
            mismatches.append({"tool": "iadl_analyze_binary_for_protections",
                               "expected": expected, "actual": f"ERROR: {err}"})
        else:
            ok = (
                actual.get("binary_size") == expected["binary_size"]
                and actual.get("function_count") == expected["function_count"]
                and actual.get("identified_layers_count", 0) == 0
            )
            if ok:
                results.append({"tool": "iadl_analyze_binary_for_protections", "status": "PASS"})
            else:
                results.append({"tool": "iadl_analyze_binary_for_protections", "status": "FAIL",
                                "expected": expected, "actual": actual})
                mismatches.append({"tool": "iadl_analyze_binary_for_protections",
                                   "expected": expected, "actual": actual})

    finally:
        try:
            p.stdin.close()
            p.terminate()
        except Exception:
            pass

    return results, mismatches, skipped

def main():
    results, mismatches, skipped = run_all()

    passed = sum(1 for r in results if r["status"] == "PASS")
    failed = sum(1 for r in results if r["status"] == "FAIL")

    # Count hardened: all tools we attempted (not skipped)
    tools_hardened = len(results)  # each result entry is one test case
    # But for the summary, count distinct tool names (not algo variants)
    distinct_tools = {"iadl_convergence_moving_average", "iadl_convergence_ema",
                      "iadl_convergence_trend_slope", "iadl_compute_hash",
                      "iadl_analyze_binary_for_protections"}
    tools_hardened = len(distinct_tools)

    summary = {
        "category": "iadl",
        "tools_hardened": tools_hardened,
        "tools_passed": passed,
        "tools_failed": failed,
        "tools_skipped": len(skipped),
        "mismatches": mismatches,
        "detail": results,
    }

    with open(OUT, "w") as f:
        json.dump(summary, f, indent=2)

    with open(SKIP_OUT, "w") as f:
        json.dump(skipped, f, indent=2)

    print(json.dumps({k: v for k, v in summary.items() if k != "detail"}, indent=2))
    return 0 if failed == 0 else 1

if __name__ == "__main__":
    sys.exit(main())
