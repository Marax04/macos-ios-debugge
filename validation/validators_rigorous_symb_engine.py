#!/usr/bin/env python3
"""
Rigorous validators for module: symb_engine
Independently computes expected values from Rust source constants and
compares them against live MCP responses.
"""
import json
import subprocess
import sys

EXE = r"C:\Users\Fra\Desktop\RustRE\target\release\rustre-mcp.exe"
REPORT_PATH = r"C:\Users\Fra\Desktop\RustRE\validation\rigorous_symb_engine.json"

# ── MCP session helpers ──────────────────────────────────────────────────────

proc = subprocess.Popen(
    [EXE, "--transport=stdio"],
    stdin=subprocess.PIPE,
    stdout=subprocess.PIPE,
    stderr=subprocess.DEVNULL,
    bufsize=0,
)

_id = 0

def send(req):
    proc.stdin.write((json.dumps(req) + "\n").encode())
    proc.stdin.flush()

def recv():
    line = proc.stdout.readline()
    if not line:
        raise RuntimeError("MCP server died")
    return json.loads(line)

def call(name, args=None):
    global _id
    _id += 1
    send({"jsonrpc": "2.0", "id": _id, "method": "tools/call",
          "params": {"name": name, "arguments": args or {}}})
    resp = recv()
    if "error" in resp:
        return None, resp["error"].get("message", str(resp["error"]))
    content = resp.get("result", {}).get("content", [])
    if not content:
        return None, "empty content"
    try:
        return json.loads(content[0]["text"]), None
    except Exception as e:
        return None, f"json parse error: {e} — raw: {content[0]['text'][:200]}"

# Handshake
send({"jsonrpc": "2.0", "id": 0, "method": "initialize",
      "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                 "clientInfo": {"name": "rigorous", "version": "1"}}})
recv()
send({"jsonrpc": "2.0", "method": "notifications/initialized"})

# ── Test registry ────────────────────────────────────────────────────────────

checks_passed = 0
checks_failed = 0
mismatches = []

def check(label, got, expected_key, expected_val, tool_name):
    global checks_passed, checks_failed
    actual = got.get(expected_key) if got else None
    if actual == expected_val:
        checks_passed += 1
        print(f"  PASS  {label}: {expected_key}={actual!r}")
    else:
        checks_failed += 1
        msg = f"{label}: expected {expected_key}={expected_val!r}, got {actual!r}"
        print(f"  FAIL  {msg}")
        mismatches.append({"tool": tool_name, "field": expected_key,
                           "expected": expected_val, "actual": actual,
                           "label": label})

# ── Tool 1: symb_engine_default_solver ──────────────────────────────────────
# Rust: SolverType::default() -> BitBlasting (marked #[default])
print("[1] symb_engine_default_solver")
data, err = call("symb_engine_default_solver")
if err:
    print(f"  ERROR: {err}"); checks_failed += 1
else:
    check("default solver", data, "solver", "BitBlasting", "symb_engine_default_solver")

# ── Tool 2: symb_engine_default_strategy ────────────────────────────────────
# Rust: ExplorationStrategy::default() -> Dfs (marked #[default])
print("[2] symb_engine_default_strategy")
data, err = call("symb_engine_default_strategy")
if err:
    print(f"  ERROR: {err}"); checks_failed += 1
else:
    check("default strategy", data, "strategy", "Dfs", "symb_engine_default_strategy")

# ── Tool 3: symb_engine_state_manager_new_len ───────────────────────────────
# Rust: StateManager::new().len() == 0, .is_empty() == true
print("[3] symb_engine_state_manager_new_len")
data, err = call("symb_engine_state_manager_new_len")
if err:
    print(f"  ERROR: {err}"); checks_failed += 1
else:
    check("state_manager len", data, "len", 0, "symb_engine_state_manager_new_len")
    check("state_manager is_empty", data, "is_empty", True, "symb_engine_state_manager_new_len")

# ── Tool 4: symb_engine_executor_config_default ─────────────────────────────
# Rust ExecutorConfig::default(): max_states=1024, max_depth=512,
#   state_merging=false, timeout_ms=0
print("[4] symb_engine_executor_config_default")
data, err = call("symb_engine_executor_config_default")
if err:
    print(f"  ERROR: {err}"); checks_failed += 1
else:
    check("exec_cfg max_states", data, "max_states", 1024, "symb_engine_executor_config_default")
    check("exec_cfg max_depth", data, "max_depth", 512, "symb_engine_executor_config_default")
    check("exec_cfg state_merging", data, "state_merging", False, "symb_engine_executor_config_default")
    check("exec_cfg timeout_ms", data, "timeout_ms", 0, "symb_engine_executor_config_default")

# ── Tool 5: symb_engine_exec_config_default ─────────────────────────────────
# Rust ExecConfig::default(): max_steps=1000, max_paths=64, explore_both_branches=true
print("[5] symb_engine_exec_config_default")
data, err = call("symb_engine_exec_config_default")
if err:
    print(f"  ERROR: {err}"); checks_failed += 1
else:
    check("exec_config max_steps", data, "max_steps", 1000, "symb_engine_exec_config_default")
    check("exec_config max_paths", data, "max_paths", 64, "symb_engine_exec_config_default")
    check("exec_config explore_both", data, "explore_both_branches", True, "symb_engine_exec_config_default")

# ── Tool 6: symb_engine_vuln_detector_new ───────────────────────────────────
# Rust VulnDetector::new().findings().len() == 0
print("[6] symb_engine_vuln_detector_new")
data, err = call("symb_engine_vuln_detector_new")
if err:
    print(f"  ERROR: {err}"); checks_failed += 1
else:
    check("vuln_detector findings_count", data, "findings_count", 0, "symb_engine_vuln_detector_new")

# ── Tool 7: symb_engine_lifted_instr_new ────────────────────────────────────
# Rust LiftedInstr::new(addr, mnemonic): address=addr, original_mnemonic=mnemonic,
#   ir_text=mnemonic (same string)
print("[7] symb_engine_lifted_instr_new")
data, err = call("symb_engine_lifted_instr_new", {"address": 0x1000, "mnemonic": "mov rax, rbx"})
if err:
    print(f"  ERROR: {err}"); checks_failed += 1
else:
    check("lifted_instr address", data, "address", 0x1000, "symb_engine_lifted_instr_new")
    check("lifted_instr mnemonic", data, "original_mnemonic", "mov rax, rbx", "symb_engine_lifted_instr_new")

# ── Tool 8: symb_engine_symbolic_interpreter_state_new ──────────────────────
# Rust SymbolicInterpreterState::new(): regs=HashMap::new().len()==0, memory==0
print("[8] symb_engine_symbolic_interpreter_state_new")
data, err = call("symb_engine_symbolic_interpreter_state_new")
if err:
    print(f"  ERROR: {err}"); checks_failed += 1
else:
    check("interp_state regs", data, "regs", 0, "symb_engine_symbolic_interpreter_state_new")
    check("interp_state memory", data, "memory", 0, "symb_engine_symbolic_interpreter_state_new")

# ── Tool 9: symb_engine_function_summary_new ────────────────────────────────
# Rust FunctionSummary::new(0x4000): address=0x4000, may_not_return=false
print("[9] symb_engine_function_summary_new")
data, err = call("symb_engine_function_summary_new", {"address": 0x4000})
if err:
    print(f"  ERROR: {err}"); checks_failed += 1
else:
    check("func_summary address", data, "address", 0x4000, "symb_engine_function_summary_new")
    check("func_summary may_not_return", data, "may_not_return", False, "symb_engine_function_summary_new")

# ── Tool 10: symb_engine_widen_sequence_check (uniform → widenable) ─────────
# Python truth: [0,2,4,6,8] has uniform step=2 → widenable=True, count=5
print("[10] symb_engine_widen_sequence_check (uniform sequence)")
data, err = call("symb_engine_widen_sequence_check", {"values": [0, 2, 4, 6, 8]})
if err:
    print(f"  ERROR: {err}"); checks_failed += 1
else:
    # Independent Python computation:
    values = [0, 2, 4, 6, 8]
    steps = [values[i+1] - values[i] for i in range(len(values)-1)]
    expected_widenable = len(set(steps)) == 1  # True: all steps are 2
    check("widen uniform widenable", data, "widenable", expected_widenable, "symb_engine_widen_sequence_check")
    check("widen uniform count", data, "count", len(values), "symb_engine_widen_sequence_check")

# ── Tool 11: symb_engine_widen_sequence_check (non-uniform → not widenable) ─
# Python truth: [1,3,7] steps=[2,4] non-uniform → widenable=False
print("[11] symb_engine_widen_sequence_check (non-uniform)")
data, err = call("symb_engine_widen_sequence_check", {"values": [1, 3, 7]})
if err:
    print(f"  ERROR: {err}"); checks_failed += 1
else:
    values = [1, 3, 7]
    steps = [values[i+1] - values[i] for i in range(len(values)-1)]
    expected_widenable = len(set(steps)) == 1  # False: steps are 2,4
    check("widen non-uniform widenable", data, "widenable", expected_widenable, "symb_engine_widen_sequence_check")

# ── Tool 12: symb_engine_widen_sequence_expr ────────────────────────────────
# [10,20,30]: uniform step=10 → widenable=True
print("[12] symb_engine_widen_sequence_expr")
data, err = call("symb_engine_widen_sequence_expr", {"values": [10, 20, 30]})
if err:
    print(f"  ERROR: {err}"); checks_failed += 1
else:
    values = [10, 20, 30]
    steps = [values[i+1] - values[i] for i in range(len(values)-1)]
    expected_widenable = len(set(steps)) == 1
    check("widen_expr widenable", data, "widenable", expected_widenable, "symb_engine_widen_sequence_expr")

# ── Tool 13: symb_engine_executor_config_defaults ───────────────────────────
# Same constants as tool 4 but different wrapper
print("[13] symb_engine_executor_config_defaults")
data, err = call("symb_engine_executor_config_defaults")
if err:
    print(f"  ERROR: {err}"); checks_failed += 1
else:
    check("exec_defaults max_states", data, "max_states", 1024, "symb_engine_executor_config_defaults")
    check("exec_defaults max_depth", data, "max_depth", 512, "symb_engine_executor_config_defaults")
    check("exec_defaults state_merging", data, "state_merging", False, "symb_engine_executor_config_defaults")
    check("exec_defaults timeout_ms", data, "timeout_ms", 0, "symb_engine_executor_config_defaults")

# ── Tool 14: symb_engine_state_manager_new ──────────────────────────────────
# StateManager::new(): len=0, is_empty=true, total_enqueued=0, pruned=0
print("[14] symb_engine_state_manager_new")
data, err = call("symb_engine_state_manager_new")
if err:
    print(f"  ERROR: {err}"); checks_failed += 1
else:
    check("sm_new len", data, "len", 0, "symb_engine_state_manager_new")
    check("sm_new is_empty", data, "is_empty", True, "symb_engine_state_manager_new")
    check("sm_new total_enqueued", data, "total_enqueued", 0, "symb_engine_state_manager_new")
    check("sm_new pruned", data, "pruned", 0, "symb_engine_state_manager_new")

# ── Tool 15: symb_engine_executor_config_defaults_v3 ────────────────────────
# Same ExecutorConfig constants; also exposes strategy="Dfs"
print("[15] symb_engine_executor_config_defaults_v3")
data, err = call("symb_engine_executor_config_defaults_v3")
if err:
    print(f"  ERROR: {err}"); checks_failed += 1
else:
    check("cfg_v3 max_states", data, "max_states", 1024, "symb_engine_executor_config_defaults_v3")
    check("cfg_v3 max_depth", data, "max_depth", 512, "symb_engine_executor_config_defaults_v3")
    check("cfg_v3 state_merging", data, "state_merging", False, "symb_engine_executor_config_defaults_v3")
    check("cfg_v3 timeout_ms", data, "timeout_ms", 0, "symb_engine_executor_config_defaults_v3")
    check("cfg_v3 strategy", data, "strategy", "Dfs", "symb_engine_executor_config_defaults_v3")

# ── Tool 16: symb_engine_solver_type_list ───────────────────────────────────
# SolverType variants: BitBlasting, SmtLib2, Z3; default=BitBlasting
print("[16] symb_engine_solver_type_list")
data, err = call("symb_engine_solver_type_list")
if err:
    print(f"  ERROR: {err}"); checks_failed += 1
else:
    check("solver_list default", data, "default", "BitBlasting", "symb_engine_solver_type_list")
    solvers = data.get("solvers") if data else None
    expected_solvers = ["BitBlasting", "SmtLib2", "Z3"]
    if solvers == expected_solvers:
        checks_passed += 1
        print(f"  PASS  solver_list solvers: {solvers!r}")
    else:
        checks_failed += 1
        msg = f"solver_list: expected solvers={expected_solvers!r}, got {solvers!r}"
        print(f"  FAIL  {msg}")
        mismatches.append({"tool": "symb_engine_solver_type_list", "field": "solvers",
                           "expected": expected_solvers, "actual": solvers, "label": "solver_list"})

# ── Teardown ──────────────────────────────────────────────────────────────────
proc.stdin.close()
proc.wait(timeout=5)

# ── Report ────────────────────────────────────────────────────────────────────
tools_hardened = 16
report = {
    "module": "symb_engine",
    "tools_hardened": tools_hardened,
    "checks_passed": checks_passed,
    "checks_failed": checks_failed,
    "mismatches": mismatches,
}
with open(REPORT_PATH, "w") as f:
    json.dump(report, f, indent=2)

print()
print(f"=== REPORT ===")
print(f"tools_hardened : {tools_hardened}")
print(f"checks_passed  : {checks_passed}")
print(f"checks_failed  : {checks_failed}")
print(f"real_mismatches: {len(mismatches)}")
if mismatches:
    print("MISMATCHES:")
    for m in mismatches:
        print(f"  {m['tool']} [{m['field']}]: expected={m['expected']!r} actual={m['actual']!r}")

sys.exit(0 if checks_failed == 0 else 1)
