#!/usr/bin/env python3
"""
bench_baseline.py -- Latency / memory / throughput benchmark for rustre-mcp.exe.

Spawns the MCP server in stdio mode, performs:
  - initialize + initialized handshake
  - tools/list (size + parse time)
  - 100-run latency sampling for each debug-adjacent tool call
  - resident-memory snapshot via tasklist

Outputs a JSON result to stdout.

Usage:
  python validation/bench_baseline.py [path/to/rustre-mcp.exe]
"""
from __future__ import annotations

import json
import os
import statistics
import subprocess
import sys
import threading
import time

# ---------------------------------------------------------------------------
# Locate binary
# ---------------------------------------------------------------------------

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_DEFAULT_EXE = os.path.join(_REPO, "target", "release", "rustre-mcp.exe")
MCP_EXE = sys.argv[1] if len(sys.argv) > 1 else _DEFAULT_EXE

if not os.path.isfile(MCP_EXE):
    print(json.dumps({"error": f"rustre-mcp.exe not found at {MCP_EXE}"}))
    sys.exit(1)

# ---------------------------------------------------------------------------
# MCP stdio transport helpers (binary mode, newline-delimited JSON)
# ---------------------------------------------------------------------------

_id_counter = 0


def _next_id() -> int:
    global _id_counter
    _id_counter += 1
    return _id_counter


class McpClient:
    def __init__(self, exe: str) -> None:
        self.proc = subprocess.Popen(
            [exe],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
        self._lock = threading.Lock()

    def _send(self, msg: dict) -> None:
        line = (json.dumps(msg) + "\n").encode()
        self.proc.stdin.write(line)
        self.proc.stdin.flush()

    def _recv(self, timeout: float = 10.0) -> dict | None:
        """Read one newline-terminated JSON line from stdout."""
        result: list[bytes] = []

        def _reader():
            try:
                line = self.proc.stdout.readline()
                result.append(line)
            except Exception:
                pass

        t = threading.Thread(target=_reader, daemon=True)
        t.start()
        t.join(timeout=timeout)
        if not result or not result[0]:
            return None
        return json.loads(result[0].decode(errors="replace"))

    def notify(self, method: str, params: dict | None = None) -> None:
        msg: dict = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            msg["params"] = params
        self._send(msg)

    def request(self, method: str, params: dict | None = None,
                timeout: float = 10.0) -> tuple[dict | None, float]:
        """Send a request and return (response, elapsed_ms)."""
        req_id = _next_id()
        msg = {"jsonrpc": "2.0", "id": req_id, "method": method,
               "params": params or {}}
        t0 = time.perf_counter()
        self._send(msg)
        resp = self._recv(timeout=timeout)
        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        return resp, elapsed_ms

    def close(self) -> None:
        try:
            self.proc.stdin.close()
            self.proc.terminate()
            self.proc.wait(timeout=3)
        except Exception:
            try:
                self.proc.kill()
            except Exception:
                pass

    @property
    def pid(self) -> int:
        return self.proc.pid


# ---------------------------------------------------------------------------
# Percentile helpers
# ---------------------------------------------------------------------------

def _stats(samples: list[float]) -> dict:
    s = sorted(samples)
    n = len(s)
    if n == 0:
        return {"p50": 0.0, "p95": 0.0, "p99": 0.0}
    p50 = s[int(n * 0.50)]
    p95 = s[min(int(n * 0.95), n - 1)]
    p99 = s[min(int(n * 0.99), n - 1)]
    return {"p50": round(p50, 3), "p95": round(p95, 3), "p99": round(p99, 3)}


# ---------------------------------------------------------------------------
# Memory via tasklist
# ---------------------------------------------------------------------------

def _resident_mb(pid: int) -> float:
    try:
        out = subprocess.check_output(
            ["tasklist", "/fi", f"PID eq {pid}", "/fo", "csv", "/nh"],
            text=True, stderr=subprocess.DEVNULL, timeout=5
        )
        for line in out.strip().splitlines():
            # Format: "rustre-mcp.exe","PID","...", "...", "N,NNN K"
            parts = [p.strip('"') for p in line.split('","')]
            if len(parts) >= 5:
                mem_str = parts[4].replace(",", "").replace(" K", "").strip()
                try:
                    return round(float(mem_str) / 1024, 2)
                except ValueError:
                    pass
    except Exception:
        pass
    return 0.0


# ---------------------------------------------------------------------------
# Benchmark
# ---------------------------------------------------------------------------

RUNS = 100


def _handshake(client: McpClient) -> float:
    resp, ms = client.request("initialize", {
        "protocolVersion": "2024-11-05",
        "clientInfo": {"name": "bench", "version": "1.0"},
        "capabilities": {},
    })
    # Send required initialized notification
    client.notify("notifications/initialized", {})
    return ms


def run_bench() -> dict:
    client = McpClient(MCP_EXE)

    # 1. Handshake
    init_ms = _handshake(client)

    # 2. tools/list -- size + latency
    tl_resp, tl_ms = client.request("tools/list")
    tools_json_bytes = len(json.dumps(tl_resp).encode()) if tl_resp else 0
    tools_list_size_kb = round(tools_json_bytes / 1024, 2)

    registered_tools: list[str] = []
    if tl_resp and "result" in tl_resp:
        registered_tools = [t.get("name", "") for t in tl_resp["result"].get("tools", [])]

    # 3. Latency sampling for debug tools (100 runs each)
    # These are called via tools/call regardless of registration status;
    # the server returns method-not-found or tool-not-found for disabled tools,
    # which is still a valid measured round-trip.
    TARGET_TOOLS: dict[str, tuple[str, dict]] = {
        "debug.launch": ("tools/call", {
            "name": "debug.launch",
            "arguments": {"pid": 0},
        }),
        "debug.detach": ("tools/call", {
            "name": "debug.detach",
            "arguments": {},
        }),
        "debug.read_memory": ("tools/call", {
            "name": "debug.read_memory",
            "arguments": {"address": 0, "size": 4096},
        }),
        "debug.backtrace": ("tools/call", {
            "name": "debug.backtrace",
            "arguments": {},
        }),
        "debug.watch": ("tools/call", {
            "name": "debug.watch",
            "arguments": {"exprs": ["rax", "rbx", "rcx", "rdx", "rsp"]},
        }),
        "debug.nl_query": ("tools/call", {
            "name": "debug.nl_query",
            "arguments": {"query": "what is rax?"},
        }),
        "debug.retroactive_print": ("tools/call", {
            "name": "debug.retroactive_print",
            "arguments": {"expr": "x"},
        }),
    }

    latency: dict[str, dict] = {}

    for tool_label, (method, params) in TARGET_TOOLS.items():
        samples: list[float] = []
        for _ in range(RUNS):
            _, ms = client.request(method, params, timeout=15.0)
            samples.append(ms)
        latency[tool_label] = _stats(samples)

    # 4. Resident memory at steady state (sample now, process is still alive)
    pid = client.pid
    mem_mb = _resident_mb(pid)

    # 5. Throughput via ping (50 runs, ops/sec)
    ping_samples: list[float] = []
    for _ in range(50):
        _, ms = client.request("ping", {}, timeout=5.0)
        ping_samples.append(ms)
    avg_ping_ms = statistics.mean(ping_samples) if ping_samples else 1.0
    throughput_ops_sec = round(1000.0 / avg_ping_ms, 1) if avg_ping_ms > 0 else 0.0

    client.close()

    absent = [n for n in TARGET_TOOLS if n not in registered_tools]
    notes_parts = [
        f"exe={MCP_EXE}",
        f"initialize_ms={round(init_ms, 3)}",
        f"tools_list_ms={round(tl_ms, 3)}",
        f"registered_tool_count={len(registered_tools)}",
        f"ping_p50_ms={_stats(ping_samples)['p50']}",
    ]
    if absent:
        notes_parts.append(
            f"debug_tools_absent_from_registry={len(absent)}/7"
            " -- latency is tools/call round-trip yielding MethodNotFound"
        )

    return {
        "latency_ms": latency,
        "memory_mb": mem_mb,
        "tools_list_size_kb": tools_list_size_kb,
        "throughput_ops_sec": throughput_ops_sec,
        "notes": "; ".join(notes_parts),
    }


if __name__ == "__main__":
    result = run_bench()
    print(json.dumps(result, indent=2))
