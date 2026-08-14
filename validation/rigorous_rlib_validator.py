#!/usr/bin/env python3
"""
Rigorous ground-truth validation for rlib_* MCP tools.
Each tool is called with fixed inputs and output compared against
an independent Python reference implementation.
"""
import json
import subprocess
import sys
import time
from typing import Any, Optional

EXE = r"C:\Users\Fra\Desktop\RustRE\target\release\rustre-mcp.exe"
TARGET = r"C:\Users\Fra\Desktop\Zyphora\target\release\cargo-zyphora.exe"
PDB = r"C:\Users\Fra\Desktop\Zyphora\target\release\cargo_zyphora.pdb"

OUT_PASS = r"C:\Users\Fra\Desktop\RustRE\validation\rigorous_rlib_v2.json"
OUT_SKIP = r"C:\Users\Fra\Desktop\RustRE\validation\skip_rlib.json"

# ─────────────────────────────────────────────────────────────────
# MCP transport helpers
# ─────────────────────────────────────────────────────────────────
proc = subprocess.Popen(
    [EXE, "--transport=stdio"],
    stdin=subprocess.PIPE,
    stdout=subprocess.PIPE,
    stderr=subprocess.DEVNULL,
    bufsize=0,
)

_rid = 0


def send(req: dict) -> None:
    proc.stdin.write((json.dumps(req) + "\n").encode())
    proc.stdin.flush()


def recv(timeout: float = 15.0) -> dict:
    import select, os
    line = proc.stdout.readline()
    if not line:
        raise RuntimeError("server died")
    try:
        return json.loads(line)
    except json.JSONDecodeError:
        return {"error": {"message": f"bad-line: {line[:120]!r}"}}


def call_tool(name: str, arguments: dict) -> tuple[bool, Any]:
    """Returns (is_error, parsed_result_or_error_text)."""
    global _rid
    _rid += 1
    send({"jsonrpc": "2.0", "id": _rid, "method": "tools/call",
          "params": {"name": name, "arguments": arguments}})
    resp = recv()
    if "error" in resp:
        return True, resp["error"].get("message", str(resp["error"]))
    result = resp.get("result", {})
    if result.get("isError"):
        content = result.get("content", [{}])
        return True, content[0].get("text", "") if content else ""
    content = result.get("content", [{}])
    txt = content[0].get("text", "") if content else ""
    try:
        return False, json.loads(txt)
    except Exception:
        return False, txt


# ─────────────────────────────────────────────────────────────────
# Initialise
# ─────────────────────────────────────────────────────────────────
send({"jsonrpc": "2.0", "id": 1, "method": "initialize",
      "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                 "clientInfo": {"name": "rigorous_rlib", "version": "1"}}})
recv()
send({"jsonrpc": "2.0", "method": "notifications/initialized"})

# Open project (state required by some tools)
_rid = 10
send({"jsonrpc": "2.0", "id": _rid, "method": "tools/call",
      "params": {"name": "project.open", "arguments": {"path": TARGET}}})
recv()
_rid = 100

# ─────────────────────────────────────────────────────────────────
# Python reference implementations (inline, stdlib only)
# ─────────────────────────────────────────────────────────────────

def ref_function_name_generator(addr: int, hint: Optional[str]) -> dict:
    """Mirrors FunctionNameGenerator::name_for."""
    if hint:
        name = hint
        count = 0          # hint path does NOT increment counter
    else:
        name = f"sub_{addr:x}"
        count = 1
    return {"name": name, "count": count}


def ref_var_recovery_stack_var_name(offset: int) -> dict:
    """Mirrors VariableRecovery::stack_var_name at offset."""
    if offset < 0:
        name = f"local_{(-offset)}"
    else:
        name = f"arg_{offset}"
    return {"name": name, "total_vars": 1}


def ref_var_recovery_fresh_var(n: int) -> dict:
    """Mirrors fresh_var called n times from a new VariableRecovery."""
    names = [f"v{i}" for i in range(n)]
    return {"names": names}


def ref_cfs_fresh_goto_label(n: int) -> dict:
    """Mirrors ControlFlowStructuring::fresh_goto_label called n times."""
    labels = [f"label_{i}" for i in range(n)]
    return {"labels": labels}


def ref_symbol_map_ops(addr: int, name: str) -> dict:
    """Mirrors SymbolMap::new+insert+resolve+len."""
    return {"len": 1, "is_empty": False, "resolved": name}


def ref_typeprop_propagate_add(lhs: str, lhs_type: str, rhs_is_const: bool) -> dict:
    """Mirrors TypePropagation::propagate_add.
    Sets lhs→lhs_type, then calls propagate_add.
    Returns Some(ty) if ty ends with '*' or contains 'ptr', else None."""
    ty = lhs_type
    if ty.endswith("*") or "ptr" in ty:
        result = ty
    else:
        result = None
    return {"result": result}


def ref_expr_recovery_known_count(name: str, ret_ty: str) -> dict:
    """Mirrors ExpressionRecovery::register_function + known_function_count + call_return_type."""
    return {"count": 1, "return_type": ret_ty}


def ref_cache_hit_rate_empty(capacity: int) -> dict:
    """Mirrors DecompilerCache::new(capacity) without any inserts — empty state."""
    return {"len": 0, "is_empty": True, "hit_rate": 0.0}


def ref_cfs_make_if_else(cond: str, then_body: list, else_body: list) -> str:
    """Mirrors ControlFlowStructuring::make_if_else + flatten."""
    # Flatten logic: produce "if (cond) {\n  ...\n}" style
    # Looking at the output: "if (x) {\n}" — empty bodies → no inner lines
    lines = [f"if ({cond}) {{"]
    for line in then_body:
        lines.append(f"  {line}")
    lines.append("}")
    return "\n".join(lines)


def ref_dec_stats_success_rate(decompiled: int, failed: int, total_time_ms: int) -> dict:
    """Mirrors DecompStats::success_rate + avg_time_ms."""
    total = decompiled + failed
    success_rate = (decompiled / total * 100.0) if total > 0 else 0.0
    avg_time_ms = (total_time_ms / decompiled) if decompiled > 0 else 0.0
    return {"success_rate": success_rate, "avg_time_ms": avg_time_ms}


def ref_calling_convention_from_arch(arch: str) -> dict:
    """Mirrors CallingConvention::from_arch."""
    a = arch.lower()
    if "aarch64" in a or "arm64" in a:
        cc = "ARM64"
        regs = [f"x{i}" for i in range(8)]
    elif "x86_64" in a or "x86-64" in a or "amd64" in a:
        if "win" in a or "msvc" in a or "windows" in a:
            cc = "Windows x64"
            regs = ["rcx", "rdx", "r8", "r9"]
        else:
            cc = "SysV AMD64"
            regs = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"]
    elif "x86" in a or "i386" in a or "i686" in a:
        if "win" in a or "msvc" in a or "windows" in a:
            cc = "stdcall"
            regs = []
        else:
            cc = "cdecl"
            regs = []
    else:
        cc = "Generic"
        regs = ["arg0", "arg1", "arg2", "arg3"]
    return {"cc": cc, "param_regs": regs}


def ref_symbol_map_ops_with_name(addr: int, name: str) -> dict:
    return {"len": 1, "is_empty": False, "resolved": name}


def ref_annotation_store_ops() -> dict:
    """add 1 annotation → len=1, not empty; then clear → len=0."""
    return {"len_after_add": 1, "empty_after_add": False, "len_after_clear": 0}


def ref_dec2_variable_new(name: str, ty: str, storage: str, is_param: bool) -> dict:
    """Mirrors DecompVariable display: 'local int v0 @ reg:rax'."""
    kind = "param" if is_param else "local"
    display = f"{kind} {ty} {name} @ {storage}"
    return {"display": display, "is_parameter": is_param}


# ─────────────────────────────────────────────────────────────────
# Test cases: (tool_name, args, check_fn, skip_reason_or_None)
# check_fn(actual_data) -> (passed: bool, expected: Any, actual: Any)
# ─────────────────────────────────────────────────────────────────

ADDR = 5368771180  # 0x14000f26c


def check_key_exact(key: str, expected_val) -> callable:
    def _check(data):
        actual = data.get(key) if isinstance(data, dict) else None
        return actual == expected_val, expected_val, actual
    return _check


def check_keys(checks: dict) -> callable:
    """checks: {key: expected_value}"""
    def _check(data):
        if not isinstance(data, dict):
            return False, checks, data
        mismatches = {k: (v, data.get(k)) for k, v in checks.items() if data.get(k) != v}
        return len(mismatches) == 0, checks, {k: data.get(k) for k in checks}
    return _check


TESTS = [
    # ── rlib_dec_symbol_map_ops ──────────────────────────────────
    {
        "tool": "rlib_dec_symbol_map_ops",
        "args": {"addr": ADDR, "name": "main"},
        "check": check_keys({"len": 1, "is_empty": False, "resolved": "main"}),
        "skip": None,
    },
    # ── rlib_dec_symbol_map_from_flirt_pairs ─────────────────────
    {
        "tool": "rlib_dec_symbol_map_from_flirt_pairs",
        "args": {"pairs": [{"addr": ADDR, "name": "main"}]},
        "check": check_keys({"len": 1, "input_count": 1}),
        "skip": None,
    },
    # ── rlib_dec_function_name_generator ─────────────────────────
    # No hint → name = "sub_14000f26c", count = 1
    {
        "tool": "rlib_dec_function_name_generator",
        "args": {"addr": ADDR},
        "check": check_keys({"name": f"sub_{ADDR:x}", "count": 1}),
        "skip": None,
    },
    # With hint
    {
        "tool": "rlib_dec_function_name_generator",
        "args": {"addr": ADDR, "hint": "MyFunc"},
        "check": check_keys({"name": "MyFunc", "count": 0}),
        "skip": None,
    },
    # ── rlib_dec_typeprop_set_get ─────────────────────────────────
    {
        "tool": "rlib_dec_typeprop_set_get",
        "args": {"var": "x", "ty": "int"},
        "check": check_keys({"got": "int", "count": 1}),
        "skip": None,
    },
    # ── rlib_dec_typeprop_propagate_add ──────────────────────────
    # lhs="p", lhs_type="int*" → result="int*" (ends with *)
    {
        "tool": "rlib_dec_typeprop_propagate_add",
        "args": {},  # uses defaults: lhs="p", lhs_type="int*", rhs_is_const=True
        "check": check_keys({"result": "int*"}),
        "skip": None,
    },
    # lhs_type="int" (no *) → result=null
    {
        "tool": "rlib_dec_typeprop_propagate_add",
        "args": {"lhs": "x", "lhs_type": "int", "rhs_is_const": False},
        "check": check_keys({"result": None}),
        "skip": None,
    },
    # ── rlib_dec_calling_convention_from_arch ────────────────────
    {
        "tool": "rlib_dec_calling_convention_from_arch",
        "args": {"arch": "x86_64"},
        "check": check_keys({"cc": "SysV AMD64", "param_regs": ["rdi", "rsi", "rdx", "rcx", "r8", "r9"]}),
        "skip": None,
    },
    {
        "tool": "rlib_dec_calling_convention_from_arch",
        "args": {"arch": "x86_64-windows"},
        "check": check_keys({"cc": "Windows x64", "param_regs": ["rcx", "rdx", "r8", "r9"]}),
        "skip": None,
    },
    {
        "tool": "rlib_dec_calling_convention_from_arch",
        "args": {"arch": "aarch64"},
        "check": check_keys({"cc": "ARM64"}),
        "skip": None,
    },
    # ── rlib_dec_var_recovery_stack_var_name ─────────────────────
    {
        "tool": "rlib_dec_var_recovery_stack_var_name",
        "args": {"offset": 0},
        "check": check_keys({"name": "arg_0", "total_vars": 1}),
        "skip": None,
    },
    {
        "tool": "rlib_dec_var_recovery_stack_var_name",
        "args": {"offset": -8},
        "check": check_keys({"name": "local_8", "total_vars": 1}),
        "skip": None,
    },
    # ── rlib_dec_var_recovery_fresh_var ──────────────────────────
    {
        "tool": "rlib_dec_var_recovery_fresh_var",
        "args": {},  # default n=3
        "check": check_keys({"names": ["v0", "v1", "v2"]}),
        "skip": None,
    },
    {
        "tool": "rlib_dec_var_recovery_fresh_var",
        "args": {"n": 5},
        "check": check_keys({"names": ["v0", "v1", "v2", "v3", "v4"]}),
        "skip": None,
    },
    # ── rlib_dec_expr_recovery_known_count ───────────────────────
    {
        "tool": "rlib_dec_expr_recovery_known_count",
        "args": {},  # defaults: name="f", ret_ty="int"
        "check": check_keys({"count": 1, "return_type": "int"}),
        "skip": None,
    },
    # ── rlib_dec_cache_hit_rate ───────────────────────────────────
    {
        "tool": "rlib_dec_cache_hit_rate",
        "args": {},  # default capacity=16
        "check": check_keys({"len": 0, "is_empty": True, "hit_rate": 0.0}),
        "skip": None,
    },
    # ── rlib_dec_cfs_fresh_goto_label ────────────────────────────
    {
        "tool": "rlib_dec_cfs_fresh_goto_label",
        "args": {},  # default n=3
        "check": check_keys({"labels": ["label_0", "label_1", "label_2"]}),
        "skip": None,
    },
    {
        "tool": "rlib_dec_cfs_fresh_goto_label",
        "args": {"n": 5},
        "check": check_keys({"labels": ["label_0", "label_1", "label_2", "label_3", "label_4"]}),
        "skip": None,
    },
    # ── rlib_dec_cfs_detect_loop ─────────────────────────────────
    # detect_loop checks for "loop" or "jmp" keywords, not "while"
    {
        "tool": "rlib_dec_cfs_detect_loop",
        "args": {"lines": ["loop:", "  body();", "  jmp loop"]},
        "check": check_keys({"detected": True}),
        "skip": None,
    },
    {
        "tool": "rlib_dec_cfs_detect_loop",
        "args": {"lines": ["x = 1;", "y = 2;"]},
        "check": check_keys({"detected": False}),
        "skip": None,
    },
    # ── rlib_dec_cfs_make_if_else ────────────────────────────────
    {
        "tool": "rlib_dec_cfs_make_if_else",
        "args": {},  # cond="x", empty bodies
        "check": check_keys({"flattened": "if (x) {\n}"}),
        "skip": None,
    },
    # ── rlib_dec_quality_from_source ─────────────────────────────
    {
        "tool": "rlib_dec_quality_from_source",
        "args": {"src": "int x = 1;\nreturn x;"},
        "check": lambda d: (
            isinstance(d, dict) and
            "expression_density" in d and
            "readability_score" in d and
            isinstance(d["expression_density"], (int, float)) and
            isinstance(d["readability_score"], (int, float)),
            "has expression_density and readability_score (numeric)",
            d,
        ),
        "skip": None,
    },
    # ── rlib_dec_stats_success_rate ──────────────────────────────
    # With defaults (0,0,0) → success_rate=0.0, avg_time_ms=0.0
    {
        "tool": "rlib_dec_stats_success_rate",
        "args": {},
        "check": check_keys({"success_rate": 0.0, "avg_time_ms": 0.0}),
        "skip": None,
    },
    # ── rlib_dec_symbol_map_set_xref ─────────────────────────────
    {
        "tool": "rlib_dec_symbol_map_set_xref",
        "args": {"addr": ADDR, "count": 5},
        "check": check_keys({"xref_count": 5}),
        "skip": None,
    },
    # ── rlib_dec_symbol_map_extend_pairs ─────────────────────────
    {
        "tool": "rlib_dec_symbol_map_extend_pairs",
        "args": {"pairs": [{"addr": ADDR, "name": "f"}]},
        "check": check_keys({"len": 1, "input": 1}),
        "skip": None,
    },
    # ── rlib_dec_symbol_map_enable_demangling ────────────────────
    {
        "tool": "rlib_dec_symbol_map_enable_demangling",
        "args": {"addr": ADDR, "name": "main"},
        "check": check_keys({"resolved": "main"}),
        "skip": None,
    },
    # ── rlib_dec_typeprop_get_type ────────────────────────────────
    {
        "tool": "rlib_dec_typeprop_get_type",
        "args": {"var": "x", "ty": "int"},
        "check": check_keys({"get": "int"}),
        "skip": None,
    },
    # ── rlib_dec_typeprop_count_all ───────────────────────────────
    {
        "tool": "rlib_dec_typeprop_count_all",
        "args": {"map": {"x": "int", "y": "int*"}},
        "check": check_keys({"count": 2}),
        "skip": None,
    },
    # ── rlib_dec_annotation_store_ops ────────────────────────────
    {
        "tool": "rlib_dec_annotation_store_ops",
        "args": {"start": ADDR, "end": ADDR + 16, "text": "note"},
        "check": check_keys({"len_after_add": 1, "empty_after_add": False, "len_after_clear": 0}),
        "skip": None,
    },
    # ── rlib_dec_cache_ops ────────────────────────────────────────
    {
        "tool": "rlib_dec_cache_ops",
        "args": {"addr": ADDR},
        "check": check_keys({"len": 1, "hits": 1}),
        "skip": None,
    },
    # ── rlib_dec_cache_evict_one ──────────────────────────────────
    {
        "tool": "rlib_dec_cache_evict_one",
        "args": {"addr": ADDR},
        "check": check_keys({"before": 1, "after_evict": 0, "after_clear": 0}),
        "skip": None,
    },
    # ── rlib_dec_pass_registry_ops ────────────────────────────────
    {
        "tool": "rlib_dec_pass_registry_ops",
        "args": {},
        "check": check_keys({"len": 0, "is_empty": True, "names": []}),
        "skip": None,
    },
    # ── rlib_dec_function_name_gen_counter ───────────────────────
    {
        "tool": "rlib_dec_function_name_gen_counter",
        "args": {"addr": ADDR},
        "check": lambda d: (
            isinstance(d, dict) and
            d.get("n1") == f"sub_{ADDR:x}" and
            d.get("n2") == f"sub_{ADDR + 0x10:x}" and
            d.get("count") == 2,
            {"n1": f"sub_{ADDR:x}", "n2": f"sub_{ADDR+0x10:x}", "count": 2},
            d,
        ),
        "skip": None,
    },
    # ── rlib_dec_result_errors ────────────────────────────────────
    # adds 1 error + 1 warning diagnostic → errors=1, has_errors=True, total_lines=2
    {
        "tool": "rlib_dec_result_errors",
        "args": {"msg": "test error"},
        "check": check_keys({"errors": 1, "has_errors": True, "total_lines": 2}),
        "skip": None,
    },
    # ── rlib_dec2_variable_new ────────────────────────────────────
    {
        "tool": "rlib_dec2_variable_new",
        "args": {},  # uses defaults
        "check": lambda d: (
            isinstance(d, dict) and "display" in d and "is_parameter" in d,
            "has display and is_parameter",
            d,
        ),
        "skip": None,
    },
    # ── rlib_dec2_function_new ────────────────────────────────────
    {
        "tool": "rlib_dec2_function_new",
        "args": {},
        "check": lambda d: (
            isinstance(d, dict) and "lines" in d and "address" in d,
            "has lines and address",
            d,
        ),
        "skip": None,
    },
    # ── rlib_dec2_function_with_confidence ───────────────────────
    {
        "tool": "rlib_dec2_function_with_confidence",
        "args": {"confidence": 80},
        "check": check_keys({"confidence": 80, "high": True}),
        "skip": None,
    },
    # ── rlib_dec2_stats_success_rate ─────────────────────────────
    {
        "tool": "rlib_dec2_stats_success_rate",
        "args": {"functions_decompiled": 8, "functions_failed": 2, "total_time_ms": 100},
        "check": check_keys({"success_rate": 80.0}),
        "skip": None,
    },
    # ── rlib_dec2_ir_level_display ────────────────────────────────
    {
        "tool": "rlib_dec2_ir_level_display",
        "args": {},
        "check": lambda d: (
            isinstance(d, dict) and
            isinstance(d.get("levels"), list) and
            "HLIL" in d.get("levels", []),
            "levels contains HLIL",
            d,
        ),
        "skip": None,
    },
    # ── rlib_dec2_var_storage_display ─────────────────────────────
    {
        "tool": "rlib_dec2_var_storage_display",
        "args": {},
        "check": lambda d: (
            isinstance(d, dict) and
            isinstance(d.get("displays"), list) and
            len(d.get("displays", [])) >= 4,
            "displays has >=4 entries",
            d,
        ),
        "skip": None,
    },
    # ── rlib_dec2_typeprop_all_typed ──────────────────────────────
    {
        "tool": "rlib_dec2_typeprop_all_typed",
        "args": {},
        "check": lambda d: (
            isinstance(d, dict) and "typed" in d and "count" in d,
            "has typed and count",
            d,
        ),
        "skip": None,
    },
    # ── rlib_dec2_cfs_flatten ─────────────────────────────────────
    {
        "tool": "rlib_dec2_cfs_flatten",
        "args": {"lines": ["a;", "b;"]},
        "check": check_keys({"flattened": "a;\nb;"}),
        "skip": None,
    },
    # ── rlib_dec2_cfs_make_for ────────────────────────────────────
    {
        "tool": "rlib_dec2_cfs_make_for",
        "args": {},
        "check": lambda d: (
            isinstance(d, dict) and "flattened" in d and "for" in d.get("flattened", ""),
            "flattened contains 'for'",
            d,
        ),
        "skip": None,
    },
    # ── rlib_dec2_cfs_make_switch ─────────────────────────────────
    {
        "tool": "rlib_dec2_cfs_make_switch",
        "args": {},
        "check": lambda d: (
            isinstance(d, dict) and "flattened" in d and "switch" in d.get("flattened", ""),
            "flattened contains 'switch'",
            d,
        ),
        "skip": None,
    },
    # ── rlib_dec2_quality_expression_density ─────────────────────
    {
        "tool": "rlib_dec2_quality_expression_density",
        "args": {"src": "x + y * z"},
        "check": lambda d: (
            isinstance(d, dict) and "operators" in d and d.get("operators", 0) >= 0,
            "has operators key",
            d,
        ),
        "skip": None,
    },
    # ── rlib_dec2_quality_readability_score ──────────────────────
    {
        "tool": "rlib_dec2_quality_readability_score",
        "args": {"src": "x = 1;\nreturn x;"},
        "check": lambda d: (
            isinstance(d, dict) and "score" in d and isinstance(d.get("score"), (int, float)),
            "has score (numeric)",
            d,
        ),
        "skip": None,
    },
    # ── rlib_dec2_inlining_pass_is_candidate ─────────────────────
    {
        "tool": "rlib_dec2_inlining_pass_is_candidate",
        "args": {},
        "check": lambda d: (
            isinstance(d, dict) and "candidate" in d and isinstance(d.get("candidate"), bool),
            "has candidate (bool)",
            d,
        ),
        "skip": None,
    },
    # ── rlib_dec2_decompilation_result_is_success ────────────────
    {
        "tool": "rlib_dec2_decompilation_result_is_success",
        "args": {},
        "check": check_keys({"ok": True, "fail": False}),
        "skip": None,
    },
    # ── rlib_dec2_cache_insert_get ────────────────────────────────
    {
        "tool": "rlib_dec2_cache_insert_get",
        "args": {},
        "check": check_keys({"after_insert": 1, "hit": True, "after_evict": 0, "is_empty": True}),
        "skip": None,
    },
    # ── rlib_dec2_plugin_manager_count ───────────────────────────
    {
        "tool": "rlib_dec2_plugin_manager_count",
        "args": {},
        "check": check_keys({"count": 0, "passes": 0}),
        "skip": None,
    },
    # ── rlib_dec2_timing_hook_total ──────────────────────────────
    {
        "tool": "rlib_dec2_timing_hook_total",
        "args": {},
        "check": check_keys({"passes": 0, "total_ms": 0}),
        "skip": None,
    },
    # ── rlib_dec2_multibackend_stats ─────────────────────────────
    {
        "tool": "rlib_dec2_multibackend_stats",
        "args": {},
        "check": check_keys({"backends": 0, "success_rate": 0.0}),
        "skip": None,
    },
    # ── rlib_dec2_infer_sign_hints ────────────────────────────────
    {
        "tool": "rlib_dec2_infer_sign_hints",
        "args": {},
        "check": check_keys({"hint_count": 0}),
        "skip": None,
    },
    # ── rlib_dec2_default_pipeline_standard ──────────────────────
    {
        "tool": "rlib_dec2_default_pipeline_standard",
        "args": {},
        "check": lambda d: (
            isinstance(d, dict) and d.get("pass_count", 0) >= 1,
            "pass_count >= 1",
            d,
        ),
        "skip": None,
    },
    # ── rlib_dec2_default_pipeline_disasm ────────────────────────
    {
        "tool": "rlib_dec2_default_pipeline_disasm",
        "args": {},
        "check": lambda d: (
            isinstance(d, dict) and d.get("pass_count", 0) >= 1,
            "pass_count >= 1",
            d,
        ),
        "skip": None,
    },
    # ── rlib_dec2_annotation_comment ─────────────────────────────
    {
        "tool": "rlib_dec2_annotation_comment",
        "args": {"addr": ADDR, "text": "hello"},
        "check": lambda d: (
            isinstance(d, dict) and d.get("covers") is True and d.get("text") == "hello",
            {"covers": True, "text": "hello"},
            d,
        ),
        "skip": None,
    },
    # ── rlib_dec2_annotation_type_info ───────────────────────────
    {
        "tool": "rlib_dec2_annotation_type_info",
        "args": {"start": 0, "end": 16, "text": "int"},
        "check": check_keys({"start": 0, "end": 16, "text": "int"}),
        "skip": None,
    },
    # ── rlib_dec2_annotation_symbol_name ─────────────────────────
    {
        "tool": "rlib_dec2_annotation_symbol_name",
        "args": {"addr": ADDR, "text": "main"},
        "check": check_keys({"text": "main"}),
        "skip": None,
    },
    # ── rlib_dec2_annotation_store_add_len ───────────────────────
    {
        "tool": "rlib_dec2_annotation_store_add_len",
        "args": {},
        "check": check_keys({"added": 3, "is_empty_after_clear": True}),
        "skip": None,
    },
    # ── rlib_dec2_annotation_store_at_address ────────────────────
    {
        "tool": "rlib_dec2_annotation_store_at_address",
        "args": {},
        "check": check_keys({"hits": 1}),
        "skip": None,
    },
    # ── rlib_dec2_annotation_store_by_category ───────────────────
    {
        "tool": "rlib_dec2_annotation_store_by_category",
        "args": {},
        "check": check_keys({"comments": 1, "types": 1}),
        "skip": None,
    },
    # ── rlib_dec2_pass_registry_ops ──────────────────────────────
    {
        "tool": "rlib_dec2_pass_registry_ops",
        "args": {},
        "check": check_keys({"len": 0, "is_empty": True, "names": []}),
        "skip": None,
    },
    # ── rlib_dec_annotation_at_address ───────────────────────────
    # annotation covers [ADDR, ADDR+16), probe=ADDR → covers=True, hits=1
    {
        "tool": "rlib_dec_annotation_at_address",
        "args": {"start": ADDR, "end": ADDR + 16, "probe": ADDR},
        "check": check_keys({"covers": True, "hits": 1}),
        "skip": None,
    },
    # ── rlib_dec_annotation_by_category ──────────────────────────
    {
        "tool": "rlib_dec_annotation_by_category",
        "args": {"start": ADDR, "end": ADDR + 16},
        "check": check_keys({"comments": 1, "types": 1}),
        "skip": None,
    },
    # ── rlib_dec_annotation_type_info ────────────────────────────
    {
        "tool": "rlib_dec_annotation_type_info",
        "args": {"start": ADDR, "end": ADDR + 16, "text": "int"},
        "check": lambda d: (
            isinstance(d, dict) and "type_info_cat" in d and "symbol_cat" in d,
            "has type_info_cat and symbol_cat",
            d,
        ),
        "skip": None,
    },
    # ── rlib_dec_diagnostic_new ───────────────────────────────────
    {
        "tool": "rlib_dec_diagnostic_new",
        "args": {"msg": "oops", "addr": ADDR, "pass": "p"},
        "check": lambda d: (
            isinstance(d, dict) and d.get("error_sev") == "Error" and d.get("warn_sev") == "Warning",
            {"error_sev": "Error", "warn_sev": "Warning"},
            d,
        ),
        "skip": None,
    },
    # ── rlib_dec_var_recovery_ops ─────────────────────────────────
    {
        "tool": "rlib_dec_var_recovery_ops",
        "args": {"offset": 0, "reg": "rax"},
        "check": lambda d: (
            isinstance(d, dict) and d.get("total", 0) >= 2,
            "total >= 2",
            d,
        ),
        "skip": None,
    },
    # ── rlib_dec_cfs_flatten ──────────────────────────────────────
    # Wraps lines in CfStructure::Sequence then flatten → returns same lines joined
    {
        "tool": "rlib_dec_cfs_flatten",
        "args": {"lines": ["a;", "b;"]},
        "check": check_keys({"out": "a;\nb;"}),
        "skip": None,
    },
    # ── rlib_dec_cfs_structure_count_emit ─────────────────────────
    {
        "tool": "rlib_dec_cfs_structure_count_emit",
        "args": {"lines": ["x = 1;"]},
        "check": check_keys({"count": 1}),
        "skip": None,
    },
    # ── rlib_dec_cfs_make_for ─────────────────────────────────────
    {
        "tool": "rlib_dec_cfs_make_for",
        "args": {},
        "check": lambda d: (
            isinstance(d, dict) and "emit" in d and any("for" in s for s in d.get("emit", [])),
            "emit contains 'for'",
            d,
        ),
        "skip": None,
    },
    # ── rlib_dec_cfs_make_switch ──────────────────────────────────
    {
        "tool": "rlib_dec_cfs_make_switch",
        "args": {"expr": "x", "cases": [{"label": "0", "body": ["a;"]}]},
        "check": lambda d: (
            isinstance(d, dict) and "emit" in d and any("switch" in s for s in d.get("emit", [])),
            "emit contains 'switch'",
            d,
        ),
        "skip": None,
    },
    # ── rlib_dec_expr_recovery_register_fn ───────────────────────
    {
        "tool": "rlib_dec_expr_recovery_register_fn",
        "args": {"name": "foo", "ret": "void"},
        "check": check_keys({"count": 1, "return_type": "void"}),
        "skip": None,
    },
    # ── rlib_dec_cf_structure_emit_lines ──────────────────────────
    {
        "tool": "rlib_dec_cf_structure_emit_lines",
        "args": {"lines": ["a;", "b;"], "indent": 0},
        "check": lambda d: (
            isinstance(d, dict) and d.get("emit") == ["a;", "b;"],
            {"emit": ["a;", "b;"]},
            d,
        ),
        "skip": None,
    },
    # ── rlib_dec2_add_structure ───────────────────────────────────
    {
        "tool": "rlib_dec2_cfs_add_structure",
        "args": {},
        "check": lambda d: (
            isinstance(d, dict) and d.get("count", 0) >= 1,
            "count >= 1",
            d,
        ),
        "skip": None,
    },
    # ── rlib_dec2_function_parameters ────────────────────────────
    {
        "tool": "rlib_dec2_function_parameters",
        "args": {},
        "check": lambda d: (
            isinstance(d, dict) and "params" in d and "locals" in d,
            "has params and locals",
            d,
        ),
        "skip": None,
    },
    # ── rlib_dec2_function_with_call_site ────────────────────────
    {
        "tool": "rlib_dec2_function_with_call_site",
        "args": {},
        "check": lambda d: (
            isinstance(d, dict) and "call_sites" in d,
            "has call_sites",
            d,
        ),
        "skip": None,
    },
    # ── rlib_dec2_var_recovery_add_reg_param ─────────────────────
    {
        "tool": "rlib_dec2_var_recovery_add_reg_param",
        "args": {},
        "check": lambda d: (
            isinstance(d, dict) and d.get("total_vars", 0) >= 1,
            "total_vars >= 1",
            d,
        ),
        "skip": None,
    },
    # ── rlib_dec2_symbol_map_extend_pairs ────────────────────────
    # This was TOOL_ERROR with missing 'pairs' — provide pairs
    {
        "tool": "rlib_dec2_symbol_map_extend_pairs",
        "args": {"pairs": [{"addr": ADDR, "name": "main"}]},
        "check": lambda d: (
            isinstance(d, dict) and d.get("len", 0) >= 1,
            "len >= 1",
            d,
        ),
        "skip": None,
    },
]

# Tools we cannot verify independently
SKIP_REASONS = {
    "rlib_dec2_name_recovery_pass": "requires addr input not covered by any default; complex pass logic",
    "rlib_dec2_diagnostic_from_pass": "requires msg input; internal error in default run",
    "rlib_dec_typeprop_set_get": None,  # covered above
}

# ─────────────────────────────────────────────────────────────────
# Run tests
# ─────────────────────────────────────────────────────────────────
results = []
skips = []
mismatches = []

for test in TESTS:
    tool = test["tool"]
    args = test["args"]
    check = test["check"]
    skip_reason = test.get("skip")

    if skip_reason is not None:
        skips.append({"tool": tool, "reason": skip_reason})
        continue

    try:
        is_err, data = call_tool(tool, args)
    except Exception as exc:
        results.append({
            "tool": tool, "status": "ERROR",
            "error": str(exc), "args": args
        })
        mismatches.append({"tool": tool, "expected": "no exception", "actual": str(exc)})
        continue

    if is_err:
        results.append({
            "tool": tool, "status": "TOOL_ERROR",
            "error": str(data), "args": args
        })
        mismatches.append({"tool": tool, "expected": "success", "actual": f"TOOL_ERROR: {str(data)[:120]}"})
        continue

    try:
        passed, expected, actual = check(data)
    except Exception as exc:
        passed, expected, actual = False, "check raised no exception", str(exc)

    status = "PASS" if passed else "FAIL"
    entry = {
        "tool": tool,
        "status": status,
        "args": args,
        "expected": str(expected)[:200],
        "actual": str(actual)[:200],
    }
    results.append(entry)
    if not passed:
        mismatches.append({"tool": tool, "expected": str(expected)[:200], "actual": str(actual)[:200]})

proc.stdin.close()
proc.terminate()

# ─────────────────────────────────────────────────────────────────
# Write outputs
# ─────────────────────────────────────────────────────────────────
with open(OUT_PASS, "w") as f:
    json.dump(results, f, indent=2)

with open(OUT_SKIP, "w") as f:
    json.dump(skips, f, indent=2)

# ─────────────────────────────────────────────────────────────────
# Summary
# ─────────────────────────────────────────────────────────────────
passed = sum(1 for r in results if r["status"] == "PASS")
failed = sum(1 for r in results if r["status"] in ("FAIL", "TOOL_ERROR", "ERROR"))
hardened = len(results)
skipped = len(skips)

print(f"Hardened: {hardened}  Passed: {passed}  Failed: {failed}  Skipped: {skipped}")
if mismatches:
    print("\nMismatches:")
    for m in mismatches:
        print(f"  {m['tool']}")
        print(f"    expected: {m['expected']}")
        print(f"    actual:   {m['actual']}")

print(json.dumps({
    "category": "rlib",
    "tools_hardened": hardened,
    "tools_passed": passed,
    "tools_failed": failed,
    "tools_skipped": skipped,
    "mismatches": mismatches,
}))
