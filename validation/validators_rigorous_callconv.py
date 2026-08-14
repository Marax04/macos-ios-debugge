"""
Rigorous validator for the 'callconv' MCP module.

All expected values are derived directly from the Rust source
(crates/rustre-analysis-callconv/src/lib.rs) — no network,
no hashing, just literal known values from ABI specifications
and the Rust implementation.
"""
from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

MCP_EXE = r"C:\Users\Fra\Desktop\RustRE\target\release\rustre-mcp.exe"
REPORT_PATH = Path(r"C:\Users\Fra\Desktop\RustRE\validation\rigorous_callconv.json")

# ---------------------------------------------------------------------------
# Ground truth (read from crates/rustre-analysis-callconv/src/lib.rs)
# ---------------------------------------------------------------------------

SYSV_X64 = {
    "name": "System V AMD64 ABI",
    "arg_registers": ["rdi", "rsi", "rdx", "rcx", "r8", "r9"],
    "fp_arg_registers": ["xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7"],
    "retval_registers": ["rax", "rdx"],
    "callee_saved": ["rbx", "rbp", "r12", "r13", "r14", "r15"],
    "stack_alignment": 16,
    "caller_cleanup": True,
    "hidden_this_ptr": False,
    "max_reg_args": 6,
    "supports_variadic": True,
    "shadow_space_bytes": 0,
    "caller_saved": ["rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11"],
}

MSVC_X64 = {
    "name": "Microsoft x64",
    "arg_registers": ["rcx", "rdx", "r8", "r9"],
    "fp_arg_registers": ["xmm0", "xmm1", "xmm2", "xmm3"],
    "retval_registers": ["rax"],
    "callee_saved": ["rbx", "rbp", "rdi", "rsi", "r12", "r13", "r14", "r15"],
    "stack_alignment": 16,
    "caller_cleanup": True,
    "hidden_this_ptr": False,
    "max_reg_args": 4,
    "supports_variadic": True,
    "shadow_space_bytes": 32,
    "caller_saved": ["rax", "rcx", "rdx", "r8", "r9", "r10", "r11"],
}

AAPCS64 = {
    "name": "AAPCS64",
    "arg_registers": ["x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"],
    "fp_arg_registers": ["v0", "v1", "v2", "v3", "v4", "v5", "v6", "v7"],
    "retval_registers": ["x0", "x1"],
    "callee_saved": ["x19", "x20", "x21", "x22", "x23", "x24", "x25", "x26", "x27", "x28", "x29"],
    "stack_alignment": 16,
    "caller_cleanup": True,
    "hidden_this_ptr": False,
    "max_reg_args": 8,
    "supports_variadic": True,
    "shadow_space_bytes": 0,
}

# name_v2 wrapper returns: name, max_reg_args, stack_alignment, caller_cleanup, shadow_space_bytes
NAME_V2_TRUTH = {
    "callconv_cdecl_x86_name_v2": {
        "name": "cdecl (x86)", "max_reg_args": 0, "stack_alignment": 4,
        "caller_cleanup": True, "shadow_space_bytes": 0,
    },
    "callconv_stdcall_x86_name_v2": {
        "name": "stdcall (x86)", "max_reg_args": 0, "stack_alignment": 4,
        "caller_cleanup": False, "shadow_space_bytes": 0,
    },
    "callconv_fastcall_x86_name_v2": {
        "name": "fastcall (x86)", "max_reg_args": 2, "stack_alignment": 4,
        "caller_cleanup": False, "shadow_space_bytes": 0,
    },
    "callconv_thiscall_x86_name_v2": {
        "name": "thiscall (x86)", "max_reg_args": 1, "stack_alignment": 4,
        "caller_cleanup": False, "shadow_space_bytes": 0,
    },
    "callconv_vectorcall_x64_name_v2": {
        "name": "vectorcall (x64)", "max_reg_args": 4, "stack_alignment": 16,
        "caller_cleanup": True, "shadow_space_bytes": 0,
    },
    "callconv_aapcs32_name_v2": {
        "name": "AAPCS32", "max_reg_args": 4, "stack_alignment": 8,
        "caller_cleanup": True, "shadow_space_bytes": 0,
    },
    "callconv_mips_o32_name_v2": {
        "name": "MIPS O32", "max_reg_args": 4, "stack_alignment": 8,
        "caller_cleanup": True, "shadow_space_bytes": 16,
    },
    "callconv_riscv64_lp64d_name_v2": {
        "name": "RISC-V LP64D", "max_reg_args": 8, "stack_alignment": 16,
        "caller_cleanup": True, "shadow_space_bytes": 0,
    },
}

# ---------------------------------------------------------------------------
# MCP stdio helpers
# ---------------------------------------------------------------------------

def start_mcp() -> subprocess.Popen:
    return subprocess.Popen(
        [MCP_EXE, "--transport=stdio"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        encoding="utf-8",
    )


def send_request(proc: subprocess.Popen, req: dict) -> dict:
    line = json.dumps(req) + "\n"
    proc.stdin.write(line)
    proc.stdin.flush()
    while True:
        raw = proc.stdout.readline()
        if not raw:
            raise RuntimeError("MCP process closed stdout")
        raw = raw.strip()
        if not raw:
            continue
        msg = json.loads(raw)
        if "id" in msg and msg.get("id") == req.get("id"):
            return msg


def call_tool(proc: subprocess.Popen, req_id: int, tool: str, args: dict) -> Any:
    """Call a tool and return the parsed JSON content from the first text item."""
    req = {
        "jsonrpc": "2.0",
        "id": req_id,
        "method": "tools/call",
        "params": {"name": tool, "arguments": args},
    }
    resp = send_request(proc, req)
    if "error" in resp:
        raise RuntimeError(f"MCP error for {tool}: {resp['error']}")
    result = resp["result"]
    # result["content"] is a list of {"type":"text","text":"..."}
    text = result["content"][0]["text"]
    return json.loads(text)


def initialize(proc: subprocess.Popen) -> None:
    req = {
        "jsonrpc": "2.0",
        "id": 0,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "rigorous-validator", "version": "1.0"},
        },
    }
    send_request(proc, req)
    # send initialized notification
    proc.stdin.write(json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}) + "\n")
    proc.stdin.flush()


# ---------------------------------------------------------------------------
# Check helpers
# ---------------------------------------------------------------------------

checks_passed = 0
checks_failed = 0
mismatches: list[dict] = []


def check(tool: str, field: str, got: Any, want: Any) -> bool:
    global checks_passed, checks_failed
    ok = got == want
    if ok:
        checks_passed += 1
    else:
        checks_failed += 1
        mismatches.append({"tool": tool, "field": field, "got": got, "expected": want})
        print(f"  MISMATCH [{tool}] {field}: got={got!r} want={want!r}", file=sys.stderr)
    return ok


def check_list_unordered(tool: str, field: str, got: list, want: list) -> bool:
    """Order-insensitive list comparison."""
    return check(tool, field, sorted(got), sorted(want))


# ---------------------------------------------------------------------------
# Individual tool tests
# ---------------------------------------------------------------------------

def test_callconv_sysv_x64(proc: subprocess.Popen, rid: int) -> int:
    data = call_tool(proc, rid, "callconv_sysv_x64", {})
    pattern = data.get("pattern", data)  # some wrappers nest under "pattern"
    tool = "callconv_sysv_x64"
    check(tool, "name", pattern.get("name"), SYSV_X64["name"])
    check(tool, "stack_alignment", pattern.get("stack_alignment"), SYSV_X64["stack_alignment"])
    check(tool, "caller_cleanup", pattern.get("caller_cleanup"), SYSV_X64["caller_cleanup"])
    check(tool, "max_reg_args", pattern.get("max_reg_args"), SYSV_X64["max_reg_args"])
    check(tool, "shadow_space_bytes", pattern.get("shadow_space_bytes"), SYSV_X64["shadow_space_bytes"])
    check(tool, "supports_variadic", pattern.get("supports_variadic"), SYSV_X64["supports_variadic"])
    check_list_unordered(tool, "arg_registers", pattern.get("arg_registers", []), SYSV_X64["arg_registers"])
    check_list_unordered(tool, "callee_saved", pattern.get("callee_saved", []), SYSV_X64["callee_saved"])
    check_list_unordered(tool, "retval_registers", pattern.get("retval_registers", []), SYSV_X64["retval_registers"])
    return rid + 1


def test_callconv_msvc_x64(proc: subprocess.Popen, rid: int) -> int:
    data = call_tool(proc, rid, "callconv_msvc_x64", {})
    pattern = data.get("pattern", data)
    tool = "callconv_msvc_x64"
    check(tool, "name", pattern.get("name"), MSVC_X64["name"])
    check(tool, "stack_alignment", pattern.get("stack_alignment"), MSVC_X64["stack_alignment"])
    check(tool, "caller_cleanup", pattern.get("caller_cleanup"), MSVC_X64["caller_cleanup"])
    check(tool, "max_reg_args", pattern.get("max_reg_args"), MSVC_X64["max_reg_args"])
    check(tool, "shadow_space_bytes", pattern.get("shadow_space_bytes"), MSVC_X64["shadow_space_bytes"])
    check_list_unordered(tool, "arg_registers", pattern.get("arg_registers", []), MSVC_X64["arg_registers"])
    check_list_unordered(tool, "callee_saved", pattern.get("callee_saved", []), MSVC_X64["callee_saved"])
    return rid + 1


def test_callconv_aapcs64(proc: subprocess.Popen, rid: int) -> int:
    data = call_tool(proc, rid, "callconv_aapcs64", {})
    pattern = data.get("pattern", data)
    tool = "callconv_aapcs64"
    check(tool, "name", pattern.get("name"), AAPCS64["name"])
    check(tool, "max_reg_args", pattern.get("max_reg_args"), AAPCS64["max_reg_args"])
    check(tool, "stack_alignment", pattern.get("stack_alignment"), AAPCS64["stack_alignment"])
    check_list_unordered(tool, "arg_registers", pattern.get("arg_registers", []), AAPCS64["arg_registers"])
    check_list_unordered(tool, "callee_saved", pattern.get("callee_saved", []), AAPCS64["callee_saved"])
    return rid + 1


def test_name_v2_tools(proc: subprocess.Popen, rid: int) -> int:
    for tool_name, want in NAME_V2_TRUTH.items():
        data = call_tool(proc, rid, tool_name, {})
        rid += 1
        for field, expected in want.items():
            check(tool_name, field, data.get(field), expected)
    return rid


def test_callconv_sysv_x64_is_arg_register(proc: subprocess.Popen, rid: int) -> int:
    tool = "callconv_sysv_x64_is_arg_register"
    # rdi is an arg register in SysV x64
    data = call_tool(proc, rid, tool, {"reg": "rdi"})
    check(tool, "is_arg_register(rdi)", data.get("is_arg_register"), True)
    rid += 1
    # rbx is NOT an arg register
    data = call_tool(proc, rid, tool, {"reg": "rbx"})
    check(tool, "is_arg_register(rbx)", data.get("is_arg_register"), False)
    rid += 1
    # xmm0 is an fp arg register -> is_arg_register returns True
    data = call_tool(proc, rid, tool, {"reg": "xmm0"})
    check(tool, "is_arg_register(xmm0)", data.get("is_arg_register"), True)
    rid += 1
    return rid


def test_callconv_msvc_x64_is_callee_saved(proc: subprocess.Popen, rid: int) -> int:
    tool = "callconv_msvc_x64_is_callee_saved"
    # rbx is callee-saved in MSVC x64
    data = call_tool(proc, rid, tool, {"reg": "rbx"})
    check(tool, "is_callee_saved(rbx)", data.get("is_callee_saved"), True)
    rid += 1
    # rdi is callee-saved in MSVC x64
    data = call_tool(proc, rid, tool, {"reg": "rdi"})
    check(tool, "is_callee_saved(rdi)", data.get("is_callee_saved"), True)
    rid += 1
    # rcx is NOT callee-saved in MSVC x64
    data = call_tool(proc, rid, tool, {"reg": "rcx"})
    check(tool, "is_callee_saved(rcx)", data.get("is_callee_saved"), False)
    rid += 1
    return rid


def test_callconv_sysv_x64_arg_register_at(proc: subprocess.Popen, rid: int) -> int:
    tool = "callconv_sysv_x64_arg_register_at"
    # SysV x64 arg registers: rdi, rsi, rdx, rcx, r8, r9
    expected_regs = SYSV_X64["arg_registers"]
    for n, want_reg in enumerate(expected_regs):
        data = call_tool(proc, rid, tool, {"n": n})
        check(tool, f"arg_register_at({n})", data.get("reg"), want_reg)
        rid += 1
    # index 6 is out of range -> null/None
    data = call_tool(proc, rid, tool, {"n": 6})
    check(tool, "arg_register_at(6)", data.get("reg"), None)
    rid += 1
    return rid


def test_callconv_aapcs64_arg_register_count(proc: subprocess.Popen, rid: int) -> int:
    tool = "callconv_aapcs64_arg_register_count"
    data = call_tool(proc, rid, tool, {})
    # AAPCS64 has 8 integer arg registers: x0..x7
    check(tool, "count", data.get("count"), 8)
    return rid + 1


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    print("Starting MCP process...")
    proc = start_mcp()
    try:
        initialize(proc)
        time.sleep(0.2)

        rid = 1
        rid = test_callconv_sysv_x64(proc, rid)
        rid = test_callconv_msvc_x64(proc, rid)
        rid = test_callconv_aapcs64(proc, rid)
        rid = test_name_v2_tools(proc, rid)
        rid = test_callconv_sysv_x64_is_arg_register(proc, rid)
        rid = test_callconv_msvc_x64_is_callee_saved(proc, rid)
        rid = test_callconv_sysv_x64_arg_register_at(proc, rid)
        rid = test_callconv_aapcs64_arg_register_count(proc, rid)

    finally:
        proc.stdin.close()
        proc.wait(timeout=5)

    # Count distinct tools hardened
    tools_hardened = len({
        "callconv_sysv_x64",
        "callconv_msvc_x64",
        "callconv_aapcs64",
        *NAME_V2_TRUTH.keys(),
        "callconv_sysv_x64_is_arg_register",
        "callconv_msvc_x64_is_callee_saved",
        "callconv_sysv_x64_arg_register_at",
        "callconv_aapcs64_arg_register_count",
    })

    report = {
        "module": "callconv",
        "tools_hardened": tools_hardened,
        "checks_passed": checks_passed,
        "checks_failed": checks_failed,
        "mismatches": mismatches,
    }
    REPORT_PATH.write_text(json.dumps(report, indent=2), encoding="utf-8")

    print(f"\nResults: {checks_passed} passed, {checks_failed} failed, {len(mismatches)} mismatches")
    print(f"Report written to {REPORT_PATH}")

    if checks_failed:
        sys.exit(1)


if __name__ == "__main__":
    main()
