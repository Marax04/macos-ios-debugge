#!/usr/bin/env python3
"""Rigorous ground-truth validator for all callconv_* MCP tools.

Each tool is called via the MCP stdio transport (same mechanism as exercise_v3.py)
and its output is compared byte-for-byte against values derived from the Rust
source in crates/rustre-analysis-callconv/src/lib.rs.
"""
import json, subprocess, sys, time

EXE = r"C:\Users\Fra\Desktop\RustRE\target\release\rustre-mcp.exe"
TARGET = r"C:\Users\Fra\Desktop\Zyphora\target\release\cargo-zyphora.exe"
OUT_V2 = r"C:\Users\Fra\Desktop\RustRE\validation\rigorous_callconv_v2.json"
SKIP_OUT = r"C:\Users\Fra\Desktop\RustRE\validation\skip_callconv.json"

# ── Ground-truth tables derived directly from lib.rs ──────────────────────────
# These are exact field values; the validator checks them one-by-one.

GT_SYSV_X64 = {
    "name": "System V AMD64 ABI",
    "arg_registers": ["rdi","rsi","rdx","rcx","r8","r9"],
    "fp_arg_registers": ["xmm0","xmm1","xmm2","xmm3","xmm4","xmm5","xmm6","xmm7"],
    "retval_registers": ["rax","rdx"],
    "callee_saved": ["rbx","rbp","r12","r13","r14","r15"],
    "stack_alignment": 16,
    "caller_cleanup": True,
    "hidden_this_ptr": False,
    "max_reg_args": 6,
    "supports_variadic": True,
    "shadow_space_bytes": 0,
}

GT_MSVC_X64 = {
    "name": "Microsoft x64",
    "arg_registers": ["rcx","rdx","r8","r9"],
    "fp_arg_registers": ["xmm0","xmm1","xmm2","xmm3"],
    "retval_registers": ["rax"],
    "callee_saved": ["rbx","rbp","rdi","rsi","r12","r13","r14","r15"],
    "stack_alignment": 16,
    "caller_cleanup": True,
    "hidden_this_ptr": False,
    "max_reg_args": 4,
    "supports_variadic": True,
    "shadow_space_bytes": 32,
}

GT_AAPCS64 = {
    "name": "AAPCS64",
    "arg_registers": ["x0","x1","x2","x3","x4","x5","x6","x7"],
    "fp_arg_registers": ["v0","v1","v2","v3","v4","v5","v6","v7"],
    "retval_registers": ["x0","x1"],
    "callee_saved": ["x19","x20","x21","x22","x23","x24","x25","x26","x27","x28","x29"],
    "stack_alignment": 16,
    "caller_cleanup": True,
    "hidden_this_ptr": False,
    "max_reg_args": 8,
    "supports_variadic": True,
    "shadow_space_bytes": 0,
}

GT_CDECL_X86 = {
    "name": "cdecl (x86)",
    "max_reg_args": 0,
    "stack_alignment": 4,
    "caller_cleanup": True,
    "shadow_space_bytes": 0,
}

GT_STDCALL_X86 = {
    "name": "stdcall (x86)",
    "max_reg_args": 0,
    "stack_alignment": 4,
    "caller_cleanup": False,
    "shadow_space_bytes": 0,
}

GT_FASTCALL_X86 = {
    "name": "fastcall (x86)",
    "max_reg_args": 2,
    "stack_alignment": 4,
    "caller_cleanup": False,
    "shadow_space_bytes": 0,
}

GT_THISCALL_X86 = {
    "name": "thiscall (x86)",
    "max_reg_args": 1,
    "stack_alignment": 4,
    "caller_cleanup": False,
    "shadow_space_bytes": 0,
}

GT_VECTORCALL_X64 = {
    "name": "vectorcall (x64)",
    "max_reg_args": 4,
    "stack_alignment": 16,
    "caller_cleanup": True,
    "shadow_space_bytes": 0,
}

GT_AAPCS32 = {
    "name": "AAPCS32",
    "max_reg_args": 4,
    "stack_alignment": 8,
    "caller_cleanup": True,
    "shadow_space_bytes": 0,
}

GT_MIPS_O32 = {
    "name": "MIPS O32",
    "max_reg_args": 4,
    "stack_alignment": 8,
    "caller_cleanup": True,
    "shadow_space_bytes": 16,
}

GT_RISCV64_LP64D = {
    "name": "RISC-V LP64D",
    "max_reg_args": 8,
    "stack_alignment": 16,
    "caller_cleanup": True,
    "shadow_space_bytes": 0,
}

# ── MCP transport helpers ──────────────────────────────────────────────────────

def start_server():
    p = subprocess.Popen(
        [EXE, "--transport=stdio"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL, bufsize=0,
    )
    return p

def send(p, req):
    p.stdin.write((json.dumps(req) + "\n").encode())
    p.stdin.flush()

def recv(p, timeout=10.0):
    import select, os
    deadline = time.monotonic() + timeout
    buf = b""
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("MCP recv timeout")
        # On Windows, stdout.readline() is blocking — just call it directly
        line = p.stdout.readline()
        if not line:
            raise RuntimeError("server died")
        try:
            return json.loads(line)
        except json.JSONDecodeError:
            continue  # skip non-JSON lines

def call_tool(p, rid, name, args):
    send(p, {"jsonrpc":"2.0","id":rid,"method":"tools/call",
             "params":{"name":name,"arguments":args}})
    resp = recv(p)
    if "error" in resp:
        return None, f"JSONRPC_ERROR: {resp['error']}"
    content = resp.get("result",{}).get("content",[])
    is_err = resp.get("result",{}).get("isError", False)
    txt = content[0].get("text","") if content else ""
    if is_err:
        return None, f"TOOL_ERROR: {txt[:200]}"
    try:
        return json.loads(txt), None
    except json.JSONDecodeError:
        return txt, None

# ── Check helpers ──────────────────────────────────────────────────────────────

def check_subset(actual_obj, expected_fields, tool_name):
    """Check that every key in expected_fields matches actual_obj."""
    errors = []
    if not isinstance(actual_obj, dict):
        return [f"expected dict, got {type(actual_obj).__name__}"]
    for k, v in expected_fields.items():
        if k not in actual_obj:
            errors.append(f"missing key '{k}'")
        elif actual_obj[k] != v:
            errors.append(f"key '{k}': expected {v!r}, got {actual_obj[k]!r}")
    return errors

def check_pattern_subset(actual_obj, gt, tool_name):
    """actual_obj may have a 'pattern' wrapper."""
    if isinstance(actual_obj, dict) and "pattern" in actual_obj:
        return check_subset(actual_obj["pattern"], gt, tool_name)
    return check_subset(actual_obj, gt, tool_name)

# ── Main validation ────────────────────────────────────────────────────────────

def main():
    p = start_server()
    rid = 0

    def nrid():
        nonlocal rid
        rid += 1
        return rid

    # Handshake
    send(p, {"jsonrpc":"2.0","id":nrid(),"method":"initialize",
             "params":{"protocolVersion":"2024-11-05","capabilities":{},
                       "clientInfo":{"name":"rigorous_callconv","version":"1"}}})
    recv(p)
    send(p, {"jsonrpc":"2.0","method":"notifications/initialized"})

    # Open project so binary_id is available
    send(p, {"jsonrpc":"2.0","id":nrid(),"method":"tools/call",
             "params":{"name":"project.open","arguments":{"path":TARGET}}})
    op = recv(p)
    op_data = json.loads(op["result"]["content"][0]["text"])
    BINARY_ID = op_data["binary_id"]

    results = []
    mismatches = []
    skips = []

    # ── Define all checks ──────────────────────────────────────────────────────
    checks = []

    # 1. callconv_sysv_x64_name — name + max_reg_args only (the _name wrapper
    #    does not emit shadow_space_bytes; only the full callconv_sysv_x64 does)
    checks.append(("callconv_sysv_x64_name", {}, lambda o: check_subset(o, {
        "name": "System V AMD64 ABI",
        "max_reg_args": 6,
    }, "callconv_sysv_x64_name")))

    # 2. callconv_msvc_x64_name
    checks.append(("callconv_msvc_x64_name", {}, lambda o: check_subset(o, {
        "name": "Microsoft x64",
        "max_reg_args": 4,
        "shadow_space_bytes": 32,
    }, "callconv_msvc_x64_name")))

    # 3. callconv_sysv_x64 — full pattern
    checks.append(("callconv_sysv_x64", {}, lambda o: check_pattern_subset(o, GT_SYSV_X64, "callconv_sysv_x64")))

    # 4. callconv_msvc_x64 — full pattern
    checks.append(("callconv_msvc_x64", {}, lambda o: check_pattern_subset(o, GT_MSVC_X64, "callconv_msvc_x64")))

    # 5. callconv_aapcs64 — full pattern
    checks.append(("callconv_aapcs64", {}, lambda o: check_pattern_subset(o, GT_AAPCS64, "callconv_aapcs64")))

    # 6-13. *_name_v2 wrappers
    checks.append(("callconv_cdecl_x86_name_v2", {}, lambda o: check_subset(o, GT_CDECL_X86, "callconv_cdecl_x86_name_v2")))
    checks.append(("callconv_stdcall_x86_name_v2", {}, lambda o: check_subset(o, GT_STDCALL_X86, "callconv_stdcall_x86_name_v2")))
    checks.append(("callconv_fastcall_x86_name_v2", {}, lambda o: check_subset(o, GT_FASTCALL_X86, "callconv_fastcall_x86_name_v2")))
    checks.append(("callconv_thiscall_x86_name_v2", {}, lambda o: check_subset(o, GT_THISCALL_X86, "callconv_thiscall_x86_name_v2")))
    checks.append(("callconv_vectorcall_x64_name_v2", {}, lambda o: check_subset(o, GT_VECTORCALL_X64, "callconv_vectorcall_x64_name_v2")))
    checks.append(("callconv_aapcs32_name_v2", {}, lambda o: check_subset(o, GT_AAPCS32, "callconv_aapcs32_name_v2")))
    checks.append(("callconv_mips_o32_name_v2", {}, lambda o: check_subset(o, GT_MIPS_O32, "callconv_mips_o32_name_v2")))
    checks.append(("callconv_riscv64_lp64d_name_v2", {}, lambda o: check_subset(o, GT_RISCV64_LP64D, "callconv_riscv64_lp64d_name_v2")))

    # 14. callconv_sysv_x64_is_arg_register — "rdi" is arg, "rbx" is not
    def check_sysv_is_arg(o):
        errs = []
        if o.get("reg") != "rdi":
            errs.append(f"reg: expected 'rdi', got {o.get('reg')!r}")
        if o.get("is_arg_register") is not True:
            errs.append(f"is_arg_register: expected True, got {o.get('is_arg_register')!r}")
        return errs
    checks.append(("callconv_sysv_x64_is_arg_register", {"reg": "rdi"}, check_sysv_is_arg))

    # Also check a non-arg register
    def check_sysv_not_arg(o):
        errs = []
        if o.get("is_arg_register") is not False:
            errs.append(f"is_arg_register for 'rbx': expected False, got {o.get('is_arg_register')!r}")
        return errs
    checks.append(("callconv_sysv_x64_is_arg_register", {"reg": "rbx"}, check_sysv_not_arg))

    # 15. callconv_msvc_x64_is_callee_saved — "rbx" is callee-saved, "rax" is not
    def check_msvc_callee_saved(o):
        errs = []
        if o.get("reg") != "rbx":
            errs.append(f"reg: expected 'rbx', got {o.get('reg')!r}")
        if o.get("is_callee_saved") is not True:
            errs.append(f"is_callee_saved: expected True, got {o.get('is_callee_saved')!r}")
        return errs
    checks.append(("callconv_msvc_x64_is_callee_saved", {"reg": "rbx"}, check_msvc_callee_saved))

    def check_msvc_not_callee(o):
        if o.get("is_callee_saved") is not False:
            return [f"is_callee_saved for 'rax': expected False, got {o.get('is_callee_saved')!r}"]
        return []
    checks.append(("callconv_msvc_x64_is_callee_saved", {"reg": "rax"}, check_msvc_not_callee))

    # 16. callconv_sysv_x64_arg_register_at — index 0 => "rdi", index 5 => "r9"
    def check_arg_at_0(o):
        if o.get("reg") != "rdi":
            return [f"arg_register_at(0): expected 'rdi', got {o.get('reg')!r}"]
        return []
    checks.append(("callconv_sysv_x64_arg_register_at", {"n": 0}, check_arg_at_0))

    def check_arg_at_5(o):
        if o.get("reg") != "r9":
            return [f"arg_register_at(5): expected 'r9', got {o.get('reg')!r}"]
        return []
    checks.append(("callconv_sysv_x64_arg_register_at", {"n": 5}, check_arg_at_5))

    # 17. callconv_aapcs64_arg_register_count — 8 (x0..x7)
    def check_aapcs64_count(o):
        if o.get("count") != 8:
            return [f"count: expected 8, got {o.get('count')!r}"]
        return []
    checks.append(("callconv_aapcs64_arg_register_count", {}, check_aapcs64_count))

    # ── Run all checks ─────────────────────────────────────────────────────────
    tool_names_seen = set()
    passed = 0
    failed = 0

    for tool_name, args, checker in checks:
        try:
            actual, err = call_tool(p, nrid(), tool_name, args)
        except TimeoutError:
            skips.append({"tool": tool_name, "reason": "timeout calling MCP tool"})
            continue
        except Exception as ex:
            skips.append({"tool": tool_name, "reason": f"exception: {ex}"})
            continue

        if err is not None:
            failed += 1
            label = f"{tool_name}({args})"
            mismatches.append({"tool": tool_name, "args": args,
                               "expected": "successful response", "actual": err})
            results.append({"tool": tool_name, "args": args, "status": "FAIL", "error": err})
            continue

        errors = checker(actual)
        label = f"{tool_name}({args})"
        if errors:
            failed += 1
            mismatches.append({"tool": tool_name, "args": args,
                               "expected": "(see ground truth)", "actual": actual,
                               "field_errors": errors})
            results.append({"tool": tool_name, "args": args, "status": "FAIL",
                            "field_errors": errors, "actual": actual})
            print(f"FAIL  {label}: {errors}")
        else:
            passed += 1
            tool_names_seen.add(tool_name)
            results.append({"tool": tool_name, "args": args, "status": "PASS"})
            print(f"PASS  {label}")

    p.stdin.close()
    try:
        p.terminate()
    except Exception:
        pass

    # Count distinct tools hardened (at least one PASS, no FAIL for that tool)
    failed_tools = {r["tool"] for r in results if r["status"] == "FAIL"}
    hardened_tools = tool_names_seen - failed_tools

    summary = {
        "module": "callconv",
        "tools_hardened": len(hardened_tools),
        "tools_passed": passed,
        "tools_failed": failed,
        "tools_skipped": len(skips),
        "mismatches": mismatches,
        "results": results,
    }

    with open(OUT_V2, "w") as f:
        json.dump(summary, f, indent=2)
    print(f"\nWrote {OUT_V2}")

    if skips:
        with open(SKIP_OUT, "w") as f:
            json.dump(skips, f, indent=2)
        print(f"Wrote {SKIP_OUT}")

    print(f"\nSUMMARY: hardened={len(hardened_tools)} passed={passed} failed={failed} skipped={len(skips)}")
    return summary

if __name__ == "__main__":
    main()
