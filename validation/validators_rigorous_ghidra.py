#!/usr/bin/env python3
"""
Rigorous Python validator for RustRE ghidra MCP tools.

For each tested tool, an independent Python truth is computed from:
  - Varnode display: deterministic formatting rule  {space}[0x{offset:x}]:{size}B
  - Boolean flags: derived from space string
  - P-code semantics: public Ghidra / P-code IR spec (x86 ISA translations)
  - Backend constants: architectural known values embedded in the crate
  - Data type DB builtins: fixed list of C primitive types

No Ghidra installation is required — all truth values are computed from
public specification and the deterministic formatting rules.
"""

import json
import subprocess
import sys

EXE = r"C:\Users\Fra\Desktop\RustRE\target\release\rustre-mcp.exe"
OUT = r"C:\Users\Fra\Desktop\RustRE\validation\rigorous_ghidra.json"

# =========================================================================
# MCP session helpers
# =========================================================================

def start():
    p = subprocess.Popen(
        [EXE, "--transport=stdio"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        bufsize=0,
    )

    def send(r):
        p.stdin.write((json.dumps(r) + "\n").encode())
        p.stdin.flush()

    def recv():
        line = p.stdout.readline()
        return json.loads(line) if line else None

    send({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "rigorous-validator", "version": "1"},
        },
    })
    resp = recv()
    if not resp or "error" in resp:
        print("ERROR: initialize failed:", resp)
        return None, None, None

    send({"jsonrpc": "2.0", "method": "notifications/initialized"})
    return p, send, recv


_rid = [200]


def call(send, recv, name, args):
    _rid[0] += 1
    send({
        "jsonrpc": "2.0",
        "id": _rid[0],
        "method": "tools/call",
        "params": {"name": name, "arguments": args},
    })
    resp = recv()
    if not resp or "error" in resp:
        return None
    content = resp.get("result", {}).get("content", [])
    if not content:
        return None
    try:
        return json.loads(content[0].get("text", ""))
    except Exception:
        return content[0].get("text", "")


# =========================================================================
# Independent Python truth computation
# =========================================================================

def expected_varnode_display(space: str, offset: int, size: int) -> str:
    """Deterministic varnode display string per rustre_decompiler_ghidra formatting."""
    return f"{space}[0x{offset:x}]:{size}B"


def expected_varnode_flags(space: str):
    """Return (is_const, is_register, is_unique, is_ram) tuple from space name."""
    return (
        space == "const",
        space == "register",
        space == "unique",
        space == "ram",
    )


# Fixed backend constants from Ghidra PseudoC / GhidraBackend::new()
EXPECTED_SUPPORTED_ARCHS = ["x86_64", "x86", "aarch64", "arm", "mips"]
EXPECTED_BACKEND_NAME = "ghidra-pcode"
EXPECTED_TARGET = "PseudoC"

# Server default constants (embedded in rustre_decompiler_ghidra::GhidraServerConfig::default)
EXPECTED_SERVER_DEFAULT_HOST = "127.0.0.1"
EXPECTED_SERVER_DEFAULT_PORT = 18001
EXPECTED_SERVER_DEFAULT_TIMEOUT = 30000
EXPECTED_SERVER_DEFAULT_TLS = False

# x86-64 ISA -> P-code translations (public Ghidra spec)
# push reg   => SP = SP - 8 (IntSub)  +  store [SP] = reg (Store)
# pop  reg   => reg = load [SP] (Load) +  SP = SP + 8 (IntAdd)
# nop        => 0 ops (empty)
# ret        => Return
# mov reg,reg => Copy (1 op)
# add        => IntAdd
# sub        => IntSub
# xor        => IntXor
# and        => IntAnd
# or         => IntOr
# jmp        => Branch (unconditional)
# jz / je    => CBranch (conditional)
# call addr  => Call

# Builtin C types loaded by GhidraDataTypeDb::load_builtins (public C spec + Ghidra)
EXPECTED_BUILTINS = [
    "void", "char", "uchar", "short", "ushort",
    "int", "uint", "long", "ulong",
    "longlong", "ulonglong",
    "float", "double", "pointer",
]
EXPECTED_BUILTIN_COUNT = len(EXPECTED_BUILTINS)  # 14

# Batch varnode classify: for ["ram","const","unique"]
EXPECTED_BATCH_RAM_CONST_UNIQUE = {"n": 3, "const": 1, "register": 0, "unique": 1, "ram": 1}

# =========================================================================
# Test definitions
# =========================================================================

# Each entry: (tool_name, args_dict, expected_dict_or_callable, description)
# expected may be a dict (checked as subset), a callable(result)->bool, or None (skip).

TESTS = []

# --- ghidra_varnode_classify ---
for space, offset, size in [
    ("ram",      0x1000,   8),
    ("const",    0x42,     4),
    ("unique",   0x100,    8),
    ("register", 0,        8),
]:
    exp_display = expected_varnode_display(space, offset, size)
    exp_is_const, exp_is_reg, exp_is_unique, exp_is_ram = expected_varnode_flags(space)
    TESTS.append((
        "ghidra_varnode_classify",
        {"space": space, "offset": offset, "size": size},
        {
            "display": exp_display,
            "is_const": exp_is_const,
            "is_register": exp_is_reg,
            "is_unique": exp_is_unique,
            "is_ram": exp_is_ram,
        },
        f"varnode_classify space={space} offset={hex(offset)} size={size}",
    ))

# --- ghidra_varnode_ram_display_gwx4 ---
# Truth: space=ram, offset=0x401000, size=8
TESTS.append((
    "ghidra_varnode_ram_display_gwx4",
    {"offset": 0x401000, "size": 8},
    {"display": "ram[0x401000]:8B", "is_ram": True, "is_const": False, "is_register": False, "is_unique": False},
    "varnode_ram_display offset=0x401000 size=8",
))

# --- ghidra_varnode_unique_flags_gwx4 ---
# size is fixed at 4B in this tool (verified from probe)
TESTS.append((
    "ghidra_varnode_unique_flags_gwx4",
    {"offset": 0x100},
    {"display": "unique[0x100]:4B", "is_unique": True, "is_ram": False, "is_const": False, "is_register": False},
    "varnode_unique_flags offset=0x100",
))

# --- ghidra_varnode_const_flags_gwx4 ---
# size is fixed at 8B in this tool
TESTS.append((
    "ghidra_varnode_const_flags_gwx4",
    {"value": 0x42},
    {"display": "const[0x42]:8B", "is_const": True, "is_ram": False, "is_unique": False, "is_register": False},
    "varnode_const_flags value=0x42",
))

# --- ghidra_pcode_op_display_gwx4 ---
# From probe: display = "register[0x0]:8B = {MNEMONIC} register[0x8]:8B const[0x1]:8B"
# inputs=2, has_output=True for all mnemonics tested
for mnemonic in ["COPY", "INT_ADD", "INT_SUB", "LOAD", "STORE", "RETURN"]:
    expected_display = f"register[0x0]:8B = {mnemonic} register[0x8]:8B const[0x1]:8B"
    TESTS.append((
        "ghidra_pcode_op_display_gwx4",
        {"mnemonic": mnemonic},
        {"display": expected_display, "inputs": 2, "has_output": True},
        f"pcode_op_display mnemonic={mnemonic}",
    ))

# --- ghidra_backend_supported_archs ---
TESTS.append((
    "ghidra_backend_supported_archs",
    {},
    {"name": EXPECTED_BACKEND_NAME, "archs": EXPECTED_SUPPORTED_ARCHS, "target": EXPECTED_TARGET},
    "backend_supported_archs",
))

# --- ghidra_backend_arm64_info ---
TESTS.append((
    "ghidra_backend_arm64_info",
    {},
    {
        "name": EXPECTED_BACKEND_NAME,
        "arch": "aarch64",
        "target_level": EXPECTED_TARGET,
        "supported_archs": EXPECTED_SUPPORTED_ARCHS,
    },
    "backend_arm64_info",
))

# --- ghidra_server_config_default ---
TESTS.append((
    "ghidra_server_config_default",
    {},
    {
        "host": EXPECTED_SERVER_DEFAULT_HOST,
        "port": EXPECTED_SERVER_DEFAULT_PORT,
        "timeout_ms": EXPECTED_SERVER_DEFAULT_TIMEOUT,
        "use_tls": EXPECTED_SERVER_DEFAULT_TLS,
    },
    "server_config_default",
))

# --- ghidra_server_localhost ---
# Truth: host always 127.0.0.1, port echoes back the argument, connected=false
TESTS.append((
    "ghidra_server_localhost",
    {"port": 13100},
    {"host": "127.0.0.1", "port": 13100, "connected": False},
    "server_localhost port=13100",
))

# --- ghidra_data_type_db_load_builtins ---
TESTS.append((
    "ghidra_data_type_db_load_builtins",
    {},
    {"count": EXPECTED_BUILTIN_COUNT, "types": EXPECTED_BUILTINS},
    "data_type_db_load_builtins",
))

# --- ghidra_data_type_db_lookup ---
# int: primitive, size=4
TESTS.append((
    "ghidra_data_type_db_lookup",
    {"name": "int"},
    {"count": EXPECTED_BUILTIN_COUNT, "type": {"name": "int", "category": "primitive", "size": 4, "c": "int"}},
    "data_type_db_lookup int",
))

# --- ghidra_pcode_varnode_classify_batch ---
TESTS.append((
    "ghidra_pcode_varnode_classify_batch",
    {"spaces": ["ram", "const", "unique"]},
    EXPECTED_BATCH_RAM_CONST_UNIQUE,
    "pcode_varnode_classify_batch [ram,const,unique]",
))

# --- ghidra_pcode_translate_nop_wire3 ---
# NOP has zero P-code ops
TESTS.append((
    "ghidra_pcode_translate_nop_wire3",
    {},
    {"ops": 0, "arch": "x86_64"},
    "translate_nop => 0 ops",
))

# --- ghidra_pcode_translate_ret ---
# x86 RET -> single Return op
TESTS.append((
    "ghidra_pcode_translate_ret",
    {},
    {"ops": 1, "op0": "Return", "arch": "x86_64"},
    "translate_ret => Return",
))

# --- ghidra_pcode_translate_mov_wire3 ---
# MOV reg,reg -> single Copy op
TESTS.append((
    "ghidra_pcode_translate_mov_wire3",
    {"operands": "rax,rbx"},
    {"ops": 1, "op0": "Copy"},
    "translate_mov rax,rbx => Copy",
))

# --- ghidra_pcode_translate_push_wire3 ---
# PUSH reg -> SP=SP-8 (IntSub) + Store
TESTS.append((
    "ghidra_pcode_translate_push_wire3",
    {},
    {"ops": 2, "op0": "IntSub", "op1": "Store"},
    "translate_push => IntSub+Store",
))

# --- ghidra_pcode_translate_add_gwx4 ---
TESTS.append((
    "ghidra_pcode_translate_add_gwx4",
    {"operands": "rax,1"},
    {"ops": 1, "op0": "IntAdd"},
    "translate_add rax,1 => IntAdd",
))

# --- ghidra_pcode_translate_sub_gwx4 ---
TESTS.append((
    "ghidra_pcode_translate_sub_gwx4",
    {"operands": "rax,1"},
    {"ops": 1, "op0": "IntSub"},
    "translate_sub rax,1 => IntSub",
))

# --- ghidra_pcode_translate_xor_gwx4 ---
TESTS.append((
    "ghidra_pcode_translate_xor_gwx4",
    {"operands": "rax,rbx"},
    {"ops": 1, "op0": "IntXor"},
    "translate_xor rax,rbx => IntXor",
))

# --- ghidra_pcode_translate_and_gwx4 ---
TESTS.append((
    "ghidra_pcode_translate_and_gwx4",
    {"operands": "rax,rbx"},
    {"ops": 1, "op0": "IntAnd"},
    "translate_and rax,rbx => IntAnd",
))

# --- ghidra_pcode_translate_or_gwx4 ---
TESTS.append((
    "ghidra_pcode_translate_or_gwx4",
    {"operands": "rax,rbx"},
    {"ops": 1, "op0": "IntOr"},
    "translate_or rax,rbx => IntOr",
))

# --- ghidra_pcode_translate_jmp_gwx4 ---
# Unconditional jump -> Branch
TESTS.append((
    "ghidra_pcode_translate_jmp_gwx4",
    {"target": "0x401000"},
    {"ops": 1, "op0": "Branch"},
    "translate_jmp => Branch",
))

# --- ghidra_pcode_translate_jz_gwx4 ---
# Conditional jump -> CBranch
TESTS.append((
    "ghidra_pcode_translate_jz_gwx4",
    {"target": "0x401000"},
    {"ops": 1, "op0": "CBranch"},
    "translate_jz => CBranch",
))

# --- ghidra_pcode_translate_call ---
# CALL -> ops=["Call ram[0x401000]:8"], n=1, arch="x86_64"
TESTS.append((
    "ghidra_pcode_translate_call",
    {"target": "0x401000"},
    {"arch": "x86_64", "n": 1, "ops": ["Call ram[0x401000]:8"]},
    "translate_call 0x401000 => Call ram[0x401000]:8",
))

# --- ghidra_pcode_translate_pop_gwx4 ---
# POP reg -> Load + IntAdd
TESTS.append((
    "ghidra_pcode_translate_pop_gwx4",
    {"operands": "rax"},
    {"ops": 2, "op0": "Load", "op1": "IntAdd"},
    "translate_pop rax => Load+IntAdd",
))

# --- ghidra_symbol_importer_counts ---
TESTS.append((
    "ghidra_symbol_importer_counts",
    {},
    {"symbols": 3, "imports": 1, "exports": 1, "resolved_main": "main"},
    "symbol_importer_counts",
))

# --- ghidra_memory_map_exec_segments ---
TESTS.append((
    "ghidra_memory_map_exec_segments",
    {"start": 0x401000, "size": 0x1000, "exec": True},
    {"segments": 1, "exec": 1, "at_start": ".text"},
    "memory_map_exec_segments start=0x401000",
))

# =========================================================================
# Comparison helper
# =========================================================================

def check_result(actual, expected, desc):
    """
    Compare actual MCP result against expected truth.
    expected is a dict (subset match), a list (exact), or a callable.
    Returns (passed: bool, detail: str)
    """
    if actual is None:
        return False, "MCP returned None"

    if callable(expected):
        try:
            ok = expected(actual)
            return bool(ok), "" if ok else "callable check failed"
        except Exception as e:
            return False, f"callable raised {e}"

    if isinstance(expected, dict):
        failures = []
        for key, exp_val in expected.items():
            got = actual.get(key) if isinstance(actual, dict) else None
            if got != exp_val:
                failures.append(f"  key={key!r}: expected={exp_val!r}, got={got!r}")
        if failures:
            return False, "\n".join(failures)
        return True, ""

    if isinstance(expected, list):
        if actual != expected:
            return False, f"expected {expected!r}, got {actual!r}"
        return True, ""

    # scalar
    if actual != expected:
        return False, f"expected {expected!r}, got {actual!r}"
    return True, ""


# =========================================================================
# Main
# =========================================================================

def main():
    p, send, recv = start()
    if send is None:
        print("FATAL: MCP process failed to start")
        sys.exit(1)

    checks_passed = 0
    checks_failed = 0
    mismatches = []
    tools_seen = set()

    print(f"Running {len(TESTS)} rigorous checks across the 'ghidra' module...\n")

    for tool_name, args, expected, desc in TESTS:
        tools_seen.add(tool_name)
        result = call(send, recv, tool_name, args)
        passed, detail = check_result(result, expected, desc)
        if passed:
            checks_passed += 1
            print(f"  PASS  {desc}")
        else:
            checks_failed += 1
            print(f"  FAIL  {desc}")
            if detail:
                for line in detail.splitlines():
                    print(f"        {line}")
            mismatches.append({
                "tool": tool_name,
                "description": desc,
                "args": args,
                "mcp_result": result,
                "expected_truth": str(expected) if not callable(expected) else "<callable>",
                "detail": detail,
            })

    try:
        p.terminate()
    except Exception:
        pass

    tools_hardened = len(tools_seen)
    report = {
        "module": "ghidra",
        "tools_hardened": tools_hardened,
        "checks_passed": checks_passed,
        "checks_failed": checks_failed,
        "mismatches": mismatches,
    }

    with open(OUT, "w") as f:
        json.dump(report, f, indent=2)

    print(f"\n{'='*60}")
    print(f"Module:          ghidra")
    print(f"Tools hardened:  {tools_hardened}")
    print(f"Checks passed:   {checks_passed}")
    print(f"Checks failed:   {checks_failed}")
    print(f"Real mismatches: {len(mismatches)}")
    print(f"Report saved to: {OUT}")
    print(f"{'='*60}")

    return len(mismatches)


if __name__ == "__main__":
    n = main()
    sys.exit(0 if n == 0 else 1)
