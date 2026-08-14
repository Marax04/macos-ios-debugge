#!/usr/bin/env python3
"""
Rigorous validator for RustRE MCP il_lift_* tools.
Each check compares MCP output against independently computed Python truth.
"""

import json
import subprocess
import sys
import time
from typing import Any, Dict, List, Optional
from dataclasses import dataclass, field

MCP_BINARY = r"C:\Users\Fra\Desktop\RustRE\target\release\rustre-mcp.exe"
REPORT_PATH = r"C:\Users\Fra\Desktop\RustRE\validation\rigorous_il_lift.json"


@dataclass
class Mismatch:
    tool: str
    args: Dict[str, Any]
    mcp_output: Any
    expected_output: Any
    note: str


class MCPClient:
    def __init__(self, binary_path: str):
        self.binary_path = binary_path
        self.process = None
        self.request_id = 0

    def start(self):
        self.process = subprocess.Popen(
            [self.binary_path],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
        time.sleep(0.5)
        init_msg = {
            "jsonrpc": "2.0",
            "id": 0,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "rigorous-validator", "version": "1.0.0"},
            },
        }
        self._send(init_msg)
        for _ in range(30):
            resp = self._recv()
            if resp:
                if resp.get("error"):
                    raise RuntimeError(f"MCP init error: {resp['error']}")
                print(f"[MCP] Initialized: {resp.get('result', {}).get('serverInfo', '')}")
                # MCP protocol requires 'notifications/initialized' after initialize
                self._send({"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}})
                time.sleep(0.2)
                return
            time.sleep(0.1)
        raise RuntimeError("MCP init timeout")

    def _send(self, msg: Dict) -> None:
        self.process.stdin.write(json.dumps(msg) + "\n")
        self.process.stdin.flush()

    def _recv(self) -> Optional[Dict]:
        try:
            line = self.process.stdout.readline()
            if line:
                return json.loads(line)
        except Exception as e:
            print(f"[RECV ERROR] {e}", file=sys.stderr)
        return None

    def alive(self) -> bool:
        return self.process is not None and self.process.poll() is None

    def call(self, tool_name: str, args: Dict) -> Any:
        if not self.alive():
            print(f"  [WARN] MCP process dead before calling {tool_name}", file=sys.stderr)
            return None
        self.request_id += 1
        req_id = self.request_id
        self._send({
            "jsonrpc": "2.0",
            "id": req_id,
            "method": "tools/call",
            "params": {"name": tool_name, "arguments": args},
        })
        # Read until we get our response ID (skip notifications)
        for _ in range(100):
            if not self.alive():
                print(f"  [WARN] MCP process died while waiting for {tool_name}", file=sys.stderr)
                break
            resp = self._recv()
            if resp is None:
                time.sleep(0.05)
                continue
            if resp.get("id") == req_id:
                if "result" in resp:
                    return resp["result"]
                if "error" in resp:
                    return {"error": resp["error"]}
        return None

    def close(self):
        if self.process:
            self.process.terminate()
            self.process.wait(timeout=5)


def extract_text(result: Any) -> Optional[str]:
    """Extract text content from MCP ToolResult."""
    if isinstance(result, dict):
        content = result.get("content", [])
        if isinstance(content, list) and content:
            return content[0].get("text", "")
    return None


def parse_json_result(result: Any) -> Optional[Dict]:
    text = extract_text(result)
    if text:
        try:
            return json.loads(text)
        except Exception:
            return None
    return None


def run_checks(mcp: MCPClient) -> tuple[int, int, List[Mismatch]]:
    passed = 0
    failed = 0
    mismatches: List[Mismatch] = []

    def check(tool: str, args: Dict, key: str, expected: Any, note: str = ""):
        nonlocal passed, failed
        result = mcp.call(tool, args)
        data = parse_json_result(result)
        if data is None:
            print(f"  [FAIL] {tool}: could not parse result — {result}")
            failed += 1
            mismatches.append(Mismatch(tool, args, result, {key: expected}, note or "no parseable result"))
            return
        actual = data.get(key)
        label = note or f"{key}={expected}"
        if actual == expected:
            print(f"  [PASS] {tool}: {label}")
            passed += 1
        else:
            print(f"  [FAIL] {tool}: {key} expected={expected!r} got={actual!r}")
            failed += 1
            mismatches.append(Mismatch(tool, args, data, {key: expected}, f"{key}: expected {expected!r}, got {actual!r}"))

    def check_approx(tool: str, args: Dict, key: str, expected: float, note: str = ""):
        nonlocal passed, failed
        result = mcp.call(tool, args)
        data = parse_json_result(result)
        if data is None:
            print(f"  [FAIL] {tool}: could not parse result — {result}")
            failed += 1
            mismatches.append(Mismatch(tool, args, result, {key: expected}, note or "no parseable result"))
            return
        actual = data.get(key)
        label = note or f"{key}≈{expected}"
        try:
            if abs(float(actual) - expected) < 1e-9:
                print(f"  [PASS] {tool}: {label}")
                passed += 1
            else:
                print(f"  [FAIL] {tool}: {key} expected≈{expected!r} got={actual!r}")
                failed += 1
                mismatches.append(Mismatch(tool, args, data, {key: expected}, f"{key}: expected≈{expected!r}, got {actual!r}"))
        except (TypeError, ValueError):
            print(f"  [FAIL] {tool}: {key} not numeric: {actual!r}")
            failed += 1
            mismatches.append(Mismatch(tool, args, data, {key: expected}, f"{key} not numeric: {actual!r}"))

    # ── TOOL 1: il_lift_level_at_least_reflexive_n3 ─────────────────────────
    # Truth: at_least(x, x) is always true for any level -> all_reflexive=true
    # Python reference: trivially true by reflexivity of >=
    print("\n[1] il_lift_level_at_least_reflexive_n3")
    check("il_lift_level_at_least_reflexive_n3", {}, "all_reflexive", True,
          "reflexive: level.at_least(level) must always be true")

    # ── TOOL 2: il_lift_result_new_empty_n3 -> total_count=0 ─────────────────
    # Truth: LiftResult::new() has 0 lifted and 0 errors -> total_count = 0
    print("\n[2] il_lift_result_new_empty_n3 (total_count)")
    check("il_lift_result_new_empty_n3", {}, "total_count", 0,
          "new LiftResult total_count = lifted + errors = 0")

    # ── TOOL 3: il_lift_result_new_empty_n3 -> is_complete=true ──────────────
    # Truth: is_complete means "no errors remain"; vacuously, 0 errors = complete
    print("\n[3] il_lift_result_new_empty_n3 (is_complete)")
    check("il_lift_result_new_empty_n3", {}, "is_complete", True,
          "new LiftResult is_complete=true (vacuously: 0 errors)")

    # ── TOOL 4: il_lift_result_failed_addresses_empty_n3 -> is_empty=true ────
    # Truth: no errors -> failed_addresses is empty
    print("\n[4] il_lift_result_failed_addresses_empty_n3 (is_empty)")
    check("il_lift_result_failed_addresses_empty_n3", {}, "is_empty", True,
          "new LiftResult has no failed addresses")

    # ── TOOL 5: il_lift_result_failed_addresses_empty_n3 -> failed_count=0 ───
    print("\n[5] il_lift_result_failed_addresses_empty_n3 (failed_count)")
    check("il_lift_result_failed_addresses_empty_n3", {}, "failed_count", 0,
          "new LiftResult failed_count=0")

    # ── TOOL 6: il_lift_stats_cache_hit_rate_empty_n3 -> 0.0 ────────────────
    # Truth: hits=0, misses=0 -> hit_rate = 0/(0+0) -> defined as 0.0
    print("\n[6] il_lift_stats_cache_hit_rate_empty_n3")
    check_approx("il_lift_stats_cache_hit_rate_empty_n3", {}, "cache_hit_rate", 0.0,
                 "empty LiftStats: cache_hit_rate = 0.0")

    # ── TOOL 7: il_lift_stats_success_rate_empty_n3 -> 1.0 ──────────────────
    # Truth: succeeded=0, total=0 -> success_rate = 1.0 (vacuously: no failures)
    print("\n[7] il_lift_stats_success_rate_empty_n3")
    check_approx("il_lift_stats_success_rate_empty_n3", {}, "success_rate", 1.0,
                 "empty LiftStats: success_rate = 1.0 (vacuous)")

    # ── TOOL 8: il_lift_cache_default_capacity_ops_n3 -> is_empty=true ───────
    # Truth: newly created LiftCache has 0 entries
    print("\n[8] il_lift_cache_default_capacity_ops_n3 (is_empty)")
    check("il_lift_cache_default_capacity_ops_n3", {}, "is_empty", True,
          "new LiftCache is_empty=true")

    # ── TOOL 9: il_lift_cache_default_capacity_ops_n3 -> hits=0 ─────────────
    print("\n[9] il_lift_cache_default_capacity_ops_n3 (hits)")
    check("il_lift_cache_default_capacity_ops_n3", {}, "hits", 0,
          "new LiftCache hits=0")

    # ── TOOL 10: il_lift_x86_lift_cache_empty_state_n3 -> is_empty=true ──────
    # Truth: X86LiftCache::new() starts empty
    print("\n[10] il_lift_x86_lift_cache_empty_state_n3 (is_empty)")
    check("il_lift_x86_lift_cache_empty_state_n3", {}, "is_empty", True,
          "X86LiftCache::new() is_empty=true")

    # ── TOOL 11: il_lift_x86_lift_cache_empty_state_n3 -> hits=0 ─────────────
    print("\n[11] il_lift_x86_lift_cache_empty_state_n3 (hits)")
    check("il_lift_x86_lift_cache_empty_state_n3", {}, "hits", 0,
          "X86LiftCache::new() hits=0")

    # ── TOOL 12: il_lift_x86_cached_addresses_empty_n3 -> count=0 ────────────
    # Truth: empty X86LiftCache has no cached addresses
    print("\n[12] il_lift_x86_cached_addresses_empty_n3 (count)")
    check("il_lift_x86_cached_addresses_empty_n3", {}, "count", 0,
          "X86LiftCache::new() cached_addresses count=0")

    # ── TOOL 13: il_lift_metadata_with_hash_n3 -> has_hash=true ──────────────
    # Truth: set binary_hash -> has_hash() returns true; the stored hash equals input
    print("\n[13] il_lift_metadata_with_hash_n3 (has_hash)")
    check("il_lift_metadata_with_hash_n3",
          {"arch": "x86_64", "hash": "deadbeef"},
          "has_hash", True,
          "LiftMetadata.with_hash sets has_hash=true")

    # ── TOOL 14: il_lift_metadata_with_hash_n3 -> binary_hash echoed ─────────
    # Truth: stored hash equals the input string "deadbeef"
    print("\n[14] il_lift_metadata_with_hash_n3 (binary_hash)")
    check("il_lift_metadata_with_hash_n3",
          {"arch": "x86_64", "hash": "deadbeef"},
          "binary_hash", "deadbeef",
          "LiftMetadata.binary_hash == supplied hash")

    # ── TOOL 15: il_lift_metadata_add_note_n3 -> notes=1 ─────────────────────
    # Truth: add_note once -> notes.len() == 1
    print("\n[15] il_lift_metadata_add_note_n3 (notes count)")
    check("il_lift_metadata_add_note_n3",
          {"arch": "x86_64", "note": "test note"},
          "notes", 1,
          "add_note once -> notes.len()=1")

    # ── TOOL 16: il_lift_metadata_add_note_n3 -> arch echoed ─────────────────
    # Truth: source_arch set from constructor arg
    print("\n[16] il_lift_metadata_add_note_n3 (arch)")
    check("il_lift_metadata_add_note_n3",
          {"arch": "x86_64", "note": "test note"},
          "arch", "x86_64",
          "LiftMetadata.source_arch == supplied arch")

    # ── TOOL 17: il_lift_registry_supports_x86_64_n3 -> supported=true ───────
    # Truth: with_defaults() includes x86_64 lifter
    print("\n[17] il_lift_registry_supports_x86_64_n3 (x86_64 supported)")
    check("il_lift_registry_supports_x86_64_n3",
          {"arch": "x86_64"},
          "supported", True,
          "LifterRegistry::with_defaults supports x86_64")

    # ── TOOL 18: il_lift_registry_supports_x86_64_n3 (arm64 supported) ──────
    # Truth: with_defaults() also includes arm64 lifter
    print("\n[18] il_lift_registry_supports_x86_64_n3 (arm64 supported)")
    check("il_lift_registry_supports_x86_64_n3",
          {"arch": "arm64"},
          "supported", True,
          "LifterRegistry::with_defaults supports arm64")

    # ── TOOL 19: il_lift_level_at_least_pair_r7: Hlil at_least Raw -> true ───
    # Truth: Hlil > MlilSsa > Llil > Raw so Hlil.at_least(Raw) = true
    # ── TOOL 19: il_lift_level_at_least_pair_r7: Hlil at_least Raw -> true ──
    # Truth: Hlil > MlilSsa > Llil > Raw, so Hlil.at_least(Raw) = true.
    # Response key is "a_at_least_b".
    print("\n[19] il_lift_level_at_least_pair_r7 (hlil >= raw)")
    check("il_lift_level_at_least_pair_r7", {"a": "hlil", "b": "raw"},
          "a_at_least_b", True, "hlil.at_least(raw) must be true")

    # ── TOOL 20: il_lift_level_at_least_pair_r7: Raw at_least Hlil -> false ─
    # Truth: Raw < Hlil, so Raw.at_least(Hlil) = false.
    print("\n[20] il_lift_level_at_least_pair_r7 (raw >= hlil = false)")
    check("il_lift_level_at_least_pair_r7", {"a": "raw", "b": "hlil"},
          "a_at_least_b", False, "raw.at_least(hlil) must be false")

    return passed, failed, mismatches


def main():
    print("=" * 70)
    print("Rigorous Validator: il_lift_* (20 checks, 10+ tools)")
    print("=" * 70)

    tools_hardened = 10  # distinct tools exercised

    mcp = MCPClient(MCP_BINARY)
    try:
        mcp.start()
        passed, failed, mismatches = run_checks(mcp)
    finally:
        mcp.close()

    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)
    print(f"  checks_passed : {passed}")
    print(f"  checks_failed : {failed}")
    print(f"  real_mismatches: {len(mismatches)}")

    report = {
        "module": "il_lift",
        "tools_hardened": tools_hardened,
        "checks_passed": passed,
        "checks_failed": failed,
        "mismatches": [
            {
                "tool": m.tool,
                "args": m.args,
                "mcp_output": m.mcp_output,
                "expected": m.expected_output,
                "note": m.note,
            }
            for m in mismatches
        ],
    }

    with open(REPORT_PATH, "w") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"\nReport saved -> {REPORT_PATH}")

    return failed


if __name__ == "__main__":
    sys.exit(main())
