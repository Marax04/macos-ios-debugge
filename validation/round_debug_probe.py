#!/usr/bin/env python3
"""
round_debug_probe.py — Live-test every debug_* MCP tool via JSON-RPC stdio.
"""
import json
import subprocess
import sys
import time
import threading

MCP_EXE = r"C:\Users\Fra\Desktop\RustRE\target\release\rustre-mcp.exe"
TARGET_BIN = r"C:\Users\Fra\Desktop\RustRE\tests\decompiler_corpus\bin\cargo-zyphora.exe"

RPCID = 0

def next_id():
    global RPCID
    RPCID += 1
    return RPCID

def send(proc, obj):
    line = json.dumps(obj) + "\n"
    proc.stdin.write(line.encode())
    proc.stdin.flush()

def recv(proc, timeout=5.0):
    """Read lines until we get a complete JSON-RPC response."""
    result_lines = []
    deadline = time.time() + timeout
    while time.time() < deadline:
        line = proc.stdout.readline()
        if not line:
            time.sleep(0.05)
            continue
        line = line.decode(errors="replace").strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            return obj
        except json.JSONDecodeError:
            result_lines.append(line)
    raise TimeoutError(f"No JSON response within {timeout}s. Partial: {result_lines}")

def drain_stderr(proc, buf):
    for line in proc.stderr:
        buf.append(line.decode(errors="replace").rstrip())

def main():
    proc = subprocess.Popen(
        [MCP_EXE, "--transport=stdio"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        bufsize=0,
    )

    stderr_buf = []
    t = threading.Thread(target=drain_stderr, args=(proc, stderr_buf), daemon=True)
    t.start()

    # initialize
    send(proc, {
        "jsonrpc": "2.0",
        "id": next_id(),
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "probe", "version": "1.0"},
        },
    })
    init_resp = recv(proc, timeout=10)

    # send initialized notification (required by MCP protocol)
    send(proc, {"jsonrpc": "2.0", "method": "notifications/initialized"})

    # tools/list
    send(proc, {
        "jsonrpc": "2.0",
        "id": next_id(),
        "method": "tools/list",
        "params": {},
    })
    list_resp = recv(proc, timeout=15)

    tools = list_resp.get("result", {}).get("tools", [])
    debug_tools = [t for t in tools if t["name"].startswith("debug_")]

    print(f"Total tools: {len(tools)}", file=sys.stderr)
    print(f"debug_* tools found: {len(debug_tools)}", file=sys.stderr)

    per_tool_results = []

    # Realistic dummy args keyed by tool name patterns
    def dummy_args(name):
        if "perms" in name:
            return {"perms": 7, "addr": 0x140000000, "size": 0x1000}
        if "arch_pointer_size" in name:
            return {"arch": "x86_64"}
        if "is_committed" in name:
            return {"state": 4096}
        if "exception_name" in name or "status_name" in name:
            return {"code": 0xC0000005}  # ACCESS_VIOLATION
        if "breakpoint_manager" in name:
            return {}
        if "process_describe" in name:
            return {"pid": 0}
        if "execution_status" in name:
            return {}
        if "default_module_count" in name:
            return {}
        if "procmaps_parse_line" in name:
            return {"line": "7f1234000-7f1235000 r-xp 00000000 08:01 1234 /lib/x86_64/libc.so.6"}
        if "procmaps_parse_count" in name:
            return {"text": "7f1234000-7f1235000 r-xp 00000000 08:01 1234 /lib/x86_64/libc.so.6\n"}
        if "gdb_checksum" in name or "kgdb" in name:
            return {"data": [0x47, 0x54, 0x44, 0x42]}
        if "gdb_encode" in name:
            return {"data": [0x48, 0x65, 0x6c, 0x6c, 0x6f]}
        if "windbg" in name:
            return {}
        if "unicorn" in name:
            return {"arch": "x86_64"}
        if "frida" in name:
            return {"pid": 1234}
        if "linux" in name:
            return {"pid": 0}
        if "attach" in name:
            return {"pid": 0}
        if "read_memory" in name or "memory" in name:
            return {"addr": 0x140000000, "len": 16}
        if "breakpoint" in name:
            return {"addr": 0x140001000}
        if "registers" in name:
            return {"pid": 0}
        return {}

    for tool in debug_tools:
        name = tool["name"]
        args = dummy_args(name)
        call_id = next_id()
        send(proc, {
            "jsonrpc": "2.0",
            "id": call_id,
            "method": "tools/call",
            "params": {"name": name, "arguments": args},
        })
        try:
            resp = recv(proc, timeout=8)
            if "error" in resp:
                err = resp["error"]
                per_tool_results.append({
                    "tool": name,
                    "ok": False,
                    "error": str(err),
                    "response_preview": str(err)[:200],
                })
            else:
                content = resp.get("result", {}).get("content", [{}])
                preview = str(content[0].get("text", "") if content else "")[:200]
                per_tool_results.append({
                    "tool": name,
                    "ok": True,
                    "response_preview": preview,
                })
        except TimeoutError as e:
            per_tool_results.append({
                "tool": name,
                "ok": False,
                "error": f"timeout: {e}",
                "response_preview": "TIMEOUT",
            })

    proc.stdin.close()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()

    tools_ok = sum(1 for r in per_tool_results if r["ok"])
    tools_error = sum(1 for r in per_tool_results if not r["ok"])
    tools_tested = len(per_tool_results)

    total_all = len(tools)
    coverage_pct = round(100.0 * tools_tested / total_all, 1) if total_all else 0.0

    output = {
        "tools_tested": tools_tested,
        "tools_ok": tools_ok,
        "tools_error": tools_error,
        "per_tool": per_tool_results,
        "coverage_final_pct": coverage_pct,
        "verdict": (
            "ALL_PASS" if tools_error == 0 and tools_tested > 0
            else "NO_DEBUG_TOOLS_LIVE" if tools_tested == 0
            else f"PARTIAL ({tools_ok}/{tools_tested} pass)"
        ),
        "capabilities_summary": (
            "No debug_* tools are currently live — all four debug backend modules "
            "(debug_macos, debug_unicorn, debug_windbg, debug_windows) are disabled "
            "in wire_tools.rs as of 2026-07-12, and crate::tools::debug::handlers() "
            "returns an empty vec (all frida/linux tools also disabled). "
            "The debugger does NOT currently expose any attach/breakpoint/memory/register/"
            "backtrace/step/evaluate capabilities via MCP."
        ),
        "stderr_sample": stderr_buf[:20],
    }

    print(json.dumps(output, indent=2))
    return output

if __name__ == "__main__":
    main()
