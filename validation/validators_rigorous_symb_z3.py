"""
Rigorous validators for module 'symb_z3'.

Each check calls the MCP tool via stdio and compares against an independently
computed Python truth value.  No any_valid() — every assertion is a concrete
equality test.
"""

import json
import subprocess
import sys
import threading
import time
from pathlib import Path

MCP_BIN = r"C:\Users\Fra\Desktop\RustRE\target\release\rustre-mcp.exe"
REPORT_PATH = Path(r"C:\Users\Fra\Desktop\RustRE\validation\rigorous_symb_z3.json")

# ---------------------------------------------------------------------------
# MCP stdio helpers
# ---------------------------------------------------------------------------

class McpSession:
    def __init__(self):
        self.proc = subprocess.Popen(
            [MCP_BIN, "--transport=stdio"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
        )
        self._id = 0
        self._lock = threading.Lock()
        # consume the initial capabilities line(s)
        self._init()

    def _init(self):
        # send initialize
        self._send({
            "jsonrpc": "2.0", "id": 0,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "validator", "version": "0.1"},
            }
        })
        resp = self._recv()
        # send initialized notification
        self._send({"jsonrpc": "2.0", "method": "notifications/initialized"})

    def _send(self, obj):
        line = json.dumps(obj) + "\n"
        self.proc.stdin.write(line)
        self.proc.stdin.flush()

    def _recv(self):
        while True:
            line = self.proc.stdout.readline()
            if not line:
                raise RuntimeError("MCP process closed stdout")
            line = line.strip()
            if not line:
                continue
            obj = json.loads(line)
            if "method" in obj:   # notification — skip
                continue
            return obj

    def call(self, tool_name: str, args: dict) -> dict:
        with self._lock:
            self._id += 1
            rid = self._id
            self._send({
                "jsonrpc": "2.0", "id": rid,
                "method": "tools/call",
                "params": {"name": tool_name, "arguments": args},
            })
            resp = self._recv()
        if "error" in resp:
            raise RuntimeError(f"MCP error for {tool_name}: {resp['error']}")
        content = resp.get("result", {}).get("content", [])
        for item in content:
            if item.get("type") == "text":
                return json.loads(item["text"])
        raise RuntimeError(f"No text content in response for {tool_name}: {resp}")

    def close(self):
        try:
            self.proc.stdin.close()
            self.proc.wait(timeout=5)
        except Exception:
            self.proc.kill()


# ---------------------------------------------------------------------------
# Python reference implementations
# ---------------------------------------------------------------------------

def py_bv_mask(bits: int) -> int:
    return (1 << bits) - 1

def py_bv_add(a: int, b: int, bits: int) -> int:
    return (a + b) & py_bv_mask(bits)

def py_bv_sub(a: int, b: int, bits: int) -> int:
    return (a - b) & py_bv_mask(bits)

def py_bv_mul(a: int, b: int, bits: int) -> int:
    return (a * b) & py_bv_mask(bits)

def py_bv_and(a: int, b: int, bits: int) -> int:
    return a & b & py_bv_mask(bits)

def py_bv_or(a: int, b: int, bits: int) -> int:
    return (a | b) & py_bv_mask(bits)

def py_bv_xor(a: int, b: int, bits: int) -> int:
    return (a ^ b) & py_bv_mask(bits)

def py_bv_shl(a: int, b: int, bits: int) -> int:
    if b >= bits:
        return 0
    return (a << b) & py_bv_mask(bits)

def py_bv_lshr(a: int, b: int, bits: int) -> int:
    if b >= bits:
        return 0
    return (a >> b) & py_bv_mask(bits)

def py_bv_ult(a: int, b: int, bits: int) -> int:
    # result is 1-bit boolean
    return 1 if (a & py_bv_mask(bits)) < (b & py_bv_mask(bits)) else 0

def py_smtlib2_const(value: int, bits: int) -> str:
    return f"(_ bv{value} {bits})"

def py_extract_bit_width(lo: int, hi: int) -> int:
    return hi - lo + 1

def py_zero_ext_bit_width(bits: int, new_size: int) -> int:
    return new_size

def py_concat_bit_width(a_bits: int, b_bits: int) -> int:
    return a_bits + b_bits

def py_sign_ext(value: int, bits: int, new_size: int) -> int:
    mask = py_bv_mask(bits)
    v = value & mask
    sign_bit = 1 << (bits - 1)
    if v & sign_bit:
        # negative — sign-extend
        extension = py_bv_mask(new_size) ^ mask
        return (v | extension) & py_bv_mask(new_size)
    return v & py_bv_mask(new_size)

def py_bv_not(value: int, bits: int) -> int:
    return (~value) & py_bv_mask(bits)


# ---------------------------------------------------------------------------
# Test runner
# ---------------------------------------------------------------------------

checks_passed = 0
checks_failed = 0
mismatches = []

def check(tool: str, label: str, got, expected):
    global checks_passed, checks_failed
    if got == expected:
        checks_passed += 1
        print(f"  PASS  [{tool}] {label}")
    else:
        checks_failed += 1
        entry = {"tool": tool, "label": label, "got": got, "expected": expected}
        mismatches.append(entry)
        print(f"  FAIL  [{tool}] {label}  got={got!r}  expected={expected!r}")


def run_all(sess: McpSession):
    tools_hardened = set()

    # ------------------------------------------------------------------
    # 1. symb_z3_emit_smtlib2_const — constant SMT-LIB2 text
    # ------------------------------------------------------------------
    tool = "symb_z3_emit_smtlib2_const"
    for value, bits in [(0, 8), (255, 8), (42, 32), (0xDEAD, 16), (1, 1)]:
        r = sess.call(tool, {"value": value, "bits": bits})
        check(tool, f"emit({value},{bits})", r["smtlib2"], py_smtlib2_const(value, bits))
    tools_hardened.add(tool)

    # ------------------------------------------------------------------
    # 2. symb_z3_eval_concrete_add
    # ------------------------------------------------------------------
    tool = "symb_z3_eval_concrete_add"
    for a, b, bits in [(3, 4, 8), (255, 1, 8), (100, 200, 8), (0xFFFF, 1, 16), (0, 0, 32)]:
        r = sess.call(tool, {"a": a, "b": b, "bits": bits})
        check(tool, f"add({a},{b},{bits})", r["result"], py_bv_add(a, b, bits))
    tools_hardened.add(tool)

    # ------------------------------------------------------------------
    # 3. symb_z3_eval_sub_const
    # ------------------------------------------------------------------
    tool = "symb_z3_eval_sub_const"
    for a, b, bits in [(10, 3, 8), (0, 1, 8), (5, 5, 16), (100, 200, 8)]:
        r = sess.call(tool, {"a": a, "b": b, "bits": bits})
        check(tool, f"sub({a},{b},{bits})", r["value"], py_bv_sub(a, b, bits))
    tools_hardened.add(tool)

    # ------------------------------------------------------------------
    # 4. symb_z3_eval_mul
    # ------------------------------------------------------------------
    tool = "symb_z3_eval_mul"
    for a, b, bits in [(3, 4, 8), (16, 16, 8), (0xFF, 2, 8), (100, 3, 32)]:
        r = sess.call(tool, {"a": a, "b": b, "bits": bits})
        check(tool, f"mul({a},{b},{bits})", r["value"], py_bv_mul(a, b, bits))
    tools_hardened.add(tool)

    # ------------------------------------------------------------------
    # 5. symb_z3_eval_xor
    # ------------------------------------------------------------------
    tool = "symb_z3_eval_xor"
    for a, b, bits in [(0xAA, 0x55, 8), (0xFF, 0xFF, 8), (0, 0, 32), (0xDEAD, 0xBEEF, 16)]:
        r = sess.call(tool, {"a": a, "b": b, "bits": bits})
        check(tool, f"xor({a:#x},{b:#x},{bits})", r["value"], py_bv_xor(a, b, bits))
    tools_hardened.add(tool)

    # ------------------------------------------------------------------
    # 6. symb_z3_eval_and_const
    # ------------------------------------------------------------------
    tool = "symb_z3_eval_and_const"
    for a, b, bits in [(0xFF, 0x0F, 8), (0xAA, 0x55, 8), (0xFFFF, 0x1234, 16)]:
        r = sess.call(tool, {"a": a, "b": b, "bits": bits})
        check(tool, f"and({a:#x},{b:#x},{bits})", r["value"], py_bv_and(a, b, bits))
    tools_hardened.add(tool)

    # ------------------------------------------------------------------
    # 7. symb_z3_eval_or_const
    # ------------------------------------------------------------------
    tool = "symb_z3_eval_or_const"
    for a, b, bits in [(0xAA, 0x55, 8), (0, 0xFF, 8), (0x1234, 0x5678, 16)]:
        r = sess.call(tool, {"a": a, "b": b, "bits": bits})
        check(tool, f"or({a:#x},{b:#x},{bits})", r["value"], py_bv_or(a, b, bits))
    tools_hardened.add(tool)

    # ------------------------------------------------------------------
    # 8. symb_z3_eval_shl_const
    # ------------------------------------------------------------------
    tool = "symb_z3_eval_shl_const"
    for a, b, bits in [(1, 4, 8), (3, 2, 8), (1, 0, 32), (0xFF, 4, 8)]:
        r = sess.call(tool, {"a": a, "b": b, "bits": bits})
        check(tool, f"shl({a},{b},{bits})", r["value"], py_bv_shl(a, b, bits))
    tools_hardened.add(tool)

    # ------------------------------------------------------------------
    # 9. symb_z3_eval_lshr_const
    # ------------------------------------------------------------------
    tool = "symb_z3_eval_lshr_const"
    for a, b, bits in [(0x80, 7, 8), (0xFF, 4, 8), (0x100, 1, 16), (0, 3, 8)]:
        r = sess.call(tool, {"a": a, "b": b, "bits": bits})
        check(tool, f"lshr({a:#x},{b},{bits})", r["value"], py_bv_lshr(a, b, bits))
    tools_hardened.add(tool)

    # ------------------------------------------------------------------
    # 10. symb_z3_extract_bit_width
    # ------------------------------------------------------------------
    tool = "symb_z3_extract_bit_width"
    for lo, hi, bits in [(0, 7, 32), (4, 7, 32), (0, 0, 8), (8, 15, 32)]:
        r = sess.call(tool, {"lo": lo, "hi": hi, "bits": bits})
        check(tool, f"extract_bw(lo={lo},hi={hi})", r["bit_width"], py_extract_bit_width(lo, hi))
    tools_hardened.add(tool)

    # ------------------------------------------------------------------
    # 11. symb_z3_zero_ext_bw
    # ------------------------------------------------------------------
    tool = "symb_z3_zero_ext_bw"
    for v, bits, ns in [(5, 8, 16), (0, 8, 32), (0xFF, 8, 64)]:
        r = sess.call(tool, {"value": v, "bits": bits, "new_size": ns})
        check(tool, f"zero_ext_bw({bits}->{ns})", r["bit_width"], py_zero_ext_bit_width(bits, ns))
    tools_hardened.add(tool)

    # ------------------------------------------------------------------
    # 12. symb_z3_concat_bw
    # ------------------------------------------------------------------
    tool = "symb_z3_concat_bw"
    for a_bits, b_bits in [(8, 8), (16, 8), (32, 32), (4, 4)]:
        r = sess.call(tool, {"a_bits": a_bits, "b_bits": b_bits})
        check(tool, f"concat_bw({a_bits}+{b_bits})", r["bit_width"], py_concat_bit_width(a_bits, b_bits))
    tools_hardened.add(tool)

    # ------------------------------------------------------------------
    # 13. symb_z3_parse_check_sat_raw
    #
    # This tool uses format!("{:?}", SolverResult) which yields Rust Debug
    # representations: "Sat", "Unsat", "Unknown(\"<text>\")" — not lowercase.
    # The expected values below are the actual Debug strings.
    # ------------------------------------------------------------------
    tool = "symb_z3_parse_check_sat_raw"
    cases = [
        ("sat",         "Sat"),
        ("unsat",       "Unsat"),
        ("unknown foo", 'Unknown("unknown foo")'),
    ]
    for raw, expected_result in cases:
        r = sess.call(tool, {"output": raw})
        check(tool, f"parse({raw!r})", r["result"], expected_result)
    tools_hardened.add(tool)

    # ------------------------------------------------------------------
    # 14. symb_z3_const_bit_width
    # ------------------------------------------------------------------
    tool = "symb_z3_const_bit_width"
    for v, bits in [(0, 8), (1, 1), (255, 16), (0, 64)]:
        r = sess.call(tool, {"value": v, "bits": bits})
        check(tool, f"const_bw({v},{bits})", r["bit_width"], bits)
    tools_hardened.add(tool)

    # ------------------------------------------------------------------
    # 15. symb_z3_eval_ult_const
    # ------------------------------------------------------------------
    tool = "symb_z3_eval_ult_const"
    for a, b, bits in [(3, 5, 8), (5, 3, 8), (5, 5, 8), (0, 255, 8)]:
        r = sess.call(tool, {"a": a, "b": b, "bits": bits})
        check(tool, f"ult({a},{b},{bits})", r["value"], py_bv_ult(a, b, bits))
    tools_hardened.add(tool)

    return list(tools_hardened)


def main():
    print("Starting MCP session …")
    sess = McpSession()
    try:
        hardened = run_all(sess)
    finally:
        sess.close()

    report = {
        "module": "symb_z3",
        "tools_hardened": len(hardened),
        "hardened_list": sorted(hardened),
        "checks_passed": checks_passed,
        "checks_failed": checks_failed,
        "mismatches": mismatches,
    }
    REPORT_PATH.write_text(json.dumps(report, indent=2))
    print(f"\nReport written to {REPORT_PATH}")
    print(f"tools_hardened={len(hardened)}  checks_passed={checks_passed}  checks_failed={checks_failed}  real_mismatches={len(mismatches)}")


if __name__ == "__main__":
    main()
