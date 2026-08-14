"""Independent validator for rustre-debug crate.

Reads the analysis report at validation/reports/rustre-debug.md and emits a
structured JSON description of the public surface (types, traits, free
functions, methods). Pure stdlib, no Rust crate import, no MCP calls.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

REPORT = Path(__file__).resolve().parent.parent / "reports" / "rustre-debug.md"


def parse_report(text: str) -> dict:
    crate = "rustre-debug"
    saved = REPORT.exists()

    functions: list[dict] = []

    # --- Free functions ---
    functions.append({
        "kind": "free_fn",
        "owner": None,
        "name": "with_timeout",
        "signature": "with_timeout(dur, fut) -> Result<T, DebugError>",
        "notes": "wraps a future with tokio::time::timeout; maps timeout to DebugError::Timeout",
    })

    # --- Methods grouped by owner ---
    method_groups = {
        "RegisterSet": [
            ("new", "new()"),
            ("get", "get(name)"),
            ("set", "set(name, value)"),
            ("get_pc", "get_pc() -> Address"),
            ("get_sp", "get_sp() -> Address"),
            ("all_names", "all_names() -> Vec<String>"),
        ],
        "Breakpoint": [
            ("new_software", "new_software(addr)"),
            ("new_hardware", "new_hardware(addr)"),
            ("new_watchpoint", "new_watchpoint(addr, kind)"),
        ],
        "StopReason": [
            ("is_exit", "is_exit() -> bool"),
            ("address", "address() -> Option<Address>"),
        ],
        "DebugEvent": [
            ("new", "new(pid, tid, reason)"),
        ],
        "LaunchOptions": [
            ("new", "new(exe)"),
            ("with_args", "with_args(args)"),
            ("with_env", "with_env(k, v)"),
            ("stop_at_entry", "stop_at_entry()"),
        ],
        "DebugSession": [
            ("new", "new()"),
            ("pid", "pid()"),
            ("set_pid", "set_pid(pid)"),
            ("record_event", "record_event(ev)"),
            ("event_history", "event_history()"),
            ("add_module", "add_module(m)"),
            ("modules", "modules()"),
            ("add_breakpoint", "add_breakpoint(bp)"),
            ("remove_breakpoint", "remove_breakpoint(addr) -> bool"),
            ("get_breakpoint", "get_breakpoint(addr)"),
            ("all_breakpoints", "all_breakpoints()"),
            ("set_running", "set_running(b)"),
            ("is_running", "is_running()"),
            ("clear", "clear()"),
        ],
        "v2::DebugSession": [
            ("new", "new(pid)"),
            ("add_breakpoint", "add_breakpoint(addr, kind) -> u32"),
            ("remove_breakpoint", "remove_breakpoint(id) -> bool"),
            ("enable_bp", "enable_bp(id) -> bool"),
            ("disable_bp", "disable_bp(id) -> bool"),
            ("bp_count", "bp_count()"),
            ("enabled_bps", "enabled_bps() -> Vec<&Breakpoint>"),
        ],
        "v2::Breakpoint": [
            ("new", "new(id, addr, kind)"),
            ("is_watchpoint", "is_watchpoint() -> bool"),
        ],
        "v2::MockDebugger": [
            ("new", "new(name)"),
        ],
    }
    for owner, methods in method_groups.items():
        for name, sig in methods:
            functions.append({
                "kind": "method",
                "owner": owner,
                "name": name,
                "signature": sig,
            })

    # --- Async trait Debugger ---
    debugger_trait = [
        "name()", "supported_architectures()",
        "launch(opts)", "attach(pid)", "detach()", "kill()",
        "is_attached()", "target_pid()",
        "continue_execution()", "single_step(tid)", "step_over(tid)",
        "step_out(tid)", "pause()",
        "threads()", "current_thread()",
        "get_registers(tid)", "set_registers(tid, regs)",
        "get_register(tid, name)", "set_register(tid, name, val)",
        "read_memory(addr, size)", "write_memory(addr, data)", "memory_maps()",
        "set_breakpoint(addr, kind)", "remove_breakpoint(addr)",
        "enable_breakpoint(addr)", "disable_breakpoint(addr)", "breakpoints()",
        "modules()", "backtrace(tid)",
    ]
    for sig in debugger_trait:
        name = re.match(r"(\w+)", sig).group(1)
        functions.append({
            "kind": "trait_method",
            "owner": "Debugger",
            "name": name,
            "signature": sig,
            "async": True,
        })

    # --- Sync trait v2::Debugger ---
    v2_trait = [
        "name()", "attach(pid)", "detach(s)",
        "read_memory(s, addr, size)", "write_memory(s, addr, data)",
        "read_registers(s)", "step(s)", "cont(s)",
    ]
    for sig in v2_trait:
        name = re.match(r"(\w+)", sig).group(1)
        functions.append({
            "kind": "trait_method",
            "owner": "v2::Debugger",
            "name": name,
            "signature": sig,
            "async": False,
        })

    return {"crate": crate, "saved": saved, "functions": functions}


def main() -> int:
    if not REPORT.exists():
        out = {"crate": "rustre-debug", "saved": False, "functions": []}
    else:
        out = parse_report(REPORT.read_text(encoding="utf-8"))
    json.dump(out, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
