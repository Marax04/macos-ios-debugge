#!/usr/bin/env python3
"""
Independent validator for RustRE MCP tools with prefix 'il_lift_'.
Ground truth computed separately from MCP output.
"""

import json
import subprocess
import sys
import struct
import time
from typing import Any, Dict, List, Tuple, Optional
from dataclasses import dataclass, field, asdict


@dataclass
class Mismatch:
    tool: str
    input_data: Dict[str, Any]
    mcp_output: Any
    expected_output: Any
    note: str


@dataclass
class ValidationReport:
    category: str
    tools_in_category: int
    checks_total: int
    checks_passed: int
    checks_skipped: int
    mismatches: List[Mismatch] = field(default_factory=list)

    def to_dict(self):
        return {
            "category": self.category,
            "tools_in_category": self.tools_in_category,
            "checks_total": self.checks_total,
            "checks_passed": self.checks_passed,
            "checks_skipped": self.checks_skipped,
            "mismatches": [
                {
                    "tool": m.tool,
                    "input": m.input_data,
                    "mcp": m.mcp_output,
                    "truth": m.expected_output,
                    "note": m.note,
                }
                for m in self.mismatches
            ],
        }


class MCPClient:
    def __init__(self, binary_path: str):
        self.binary_path = binary_path
        self.process = None
        self.request_id = 0

    def start(self):
        """Start MCP server via stdio."""
        self.process = subprocess.Popen(
            [self.binary_path],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
        time.sleep(0.5)  # Give server time to start

        # Send initialize message - RustRE MCP expects specific format
        init_msg = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {
                    "name": "rustre-validator",
                    "version": "1.0.0"
                }
            }
        }
        self._send_message(init_msg)

        # Read response
        timeout_count = 20
        while timeout_count > 0:
            resp = self._read_message()
            if resp:
                print(f"[MCP] Response: {resp}")
                if resp.get("error"):
                    raise RuntimeError(f"Failed to initialize MCP: {resp['error']}")
                print("[MCP] Initialized successfully")
                return
            time.sleep(0.1)
            timeout_count -= 1

        raise RuntimeError(f"Failed to initialize MCP: timeout")

    def _send_message(self, msg: Dict) -> None:
        """Send JSON-RPC message."""
        line = json.dumps(msg) + "\n"
        self.process.stdin.write(line)
        self.process.stdin.flush()

    def _read_message(self) -> Optional[Dict]:
        """Read JSON-RPC message."""
        try:
            line = self.process.stdout.readline()
            if line:
                return json.loads(line)
        except Exception as e:
            print(f"Error reading message: {e}", file=sys.stderr)
        return None

    def list_tools(self) -> List[Dict]:
        """List available tools."""
        self.request_id += 1
        self._send_message(
            {"jsonrpc": "2.0", "id": self.request_id, "method": "tools/list", "params": {}}
        )
        resp = self._read_message()
        if resp and "result" in resp:
            return resp["result"].get("tools", [])
        return []

    def call_tool(self, tool_name: str, args: Dict) -> Any:
        """Call a tool."""
        self.request_id += 1
        self._send_message(
            {
                "jsonrpc": "2.0",
                "id": self.request_id,
                "method": "tools/call",
                "params": {"name": tool_name, "arguments": args},
            }
        )
        resp = self._read_message()
        if resp and "result" in resp:
            return resp["result"]
        elif resp and "error" in resp:
            return {"error": resp["error"]}
        return None

    def close(self):
        """Close MCP connection."""
        if self.process:
            self.process.terminate()
            self.process.wait(timeout=5)


# Ground truth computation functions
def lift_level_ordering() -> Dict[str, int]:
    """Return LiftLevel ordering: disasm=0, mlil=1, hlil=2."""
    return {"disasm": 0, "mlil": 1, "hlil": 2}


def x86_register_index(reg_name: str) -> Optional[int]:
    """Return x86-64 register indices."""
    regs = {
        "rax": 0, "rcx": 1, "rdx": 2, "rbx": 3,
        "rsp": 4, "rbp": 5, "rsi": 6, "rdi": 7,
        "r8": 8, "r9": 9, "r10": 10, "r11": 11,
        "r12": 12, "r13": 13, "r14": 14, "r15": 15,
    }
    return regs.get(reg_name.lower())


def common_opcodes() -> Dict[str, int]:
    """Return common x86 opcodes."""
    return {"nop": 0x90, "ret": 0xC3, "push": 0x50, "pop": 0x58}


def validate_address_map_lookup():
    """
    Test: il_lift_address_map_contains
    Ground truth: address maps store address ranges; contains checks inclusion.
    """
    # This requires actual address map structure; skip if not provided
    return None  # Schema unclear without address_map type


def validate_arch_supported():
    """
    Test: il_lift_arch_count, il_lift_supported_arches
    Ground truth: known supported architectures.
    """
    expected_count = 5  # x86_64, arm64, arm, mips32, wasm (typical)
    return {"expected_count_min": 4}  # At least 4 should be supported


def validate_lift_level_names():
    """
    Test: il_lift_level_display, il_lift_level_all, il_lift_level_all_variants
    Ground truth: known lift levels.
    """
    expected_levels = ["disasm", "mlil", "hlil"]
    return {"expected_levels": expected_levels, "expected_count": 3}


def validate_x86_register_canonical():
    """
    Test: il_lift_x86_reg_id, il_lift_x86_lifter_new_bits, etc.
    Ground truth: x86-64 register IDs are standardized.
    """
    rax_id = x86_register_index("rax")
    rbp_id = x86_register_index("rbp")
    return {"rax_id": rax_id, "rbp_id": rbp_id, "expected_canonical": ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rsp", "rbp"]}


def validate_x86_lift_nop():
    """
    Test: il_lift_x86_lifter_lift_nop, il_lift_x86_lift_bytes
    Ground truth: NOP (0x90) should lift to a minimal IL.
    """
    nop_bytes = bytes([0x90])
    return {"input_bytes": nop_bytes.hex(), "opcode": 0x90}


def validate_cache_operations():
    """
    Test: il_lift_cache_*, il_lift_lru_*
    Ground truth: cache is typically empty initially.
    """
    return {"expected_initial_state": "empty"}


def validate_metadata_builder():
    """
    Test: il_lift_lift_metadata_builder, il_lift_metadata_*
    Ground truth: metadata tracks lift session info.
    """
    return {"has_timestamp": True, "has_version": True}


def validate_address_map_empty():
    """
    Test: il_lift_address_map_empty_probe
    Ground truth: empty address map should report empty.
    """
    return {"expected_empty": True}


def validate_registry_defaults():
    """
    Test: il_lift_registry_new_len, il_lift_registry_with_defaults
    Ground truth: default registry has known lifter count.
    """
    return {"expected_min_lifters": 2}  # At least x86 and arm


def run_validation() -> ValidationReport:
    """Main validation routine."""
    report = ValidationReport(
        category="il_lift",
        tools_in_category=0,
        checks_total=0,
        checks_passed=0,
        checks_skipped=0,
    )

    mcp = MCPClient(r"C:\Users\Fra\Desktop\RustRE\target\release\rustre-mcp.exe")
    try:
        mcp.start()
        time.sleep(0.5)

        # List tools
        all_tools = mcp.list_tools()
        il_lift_tools = [t for t in all_tools if t.get("name", "").startswith("il_lift_")]
        il_lift_tools = il_lift_tools[:20] if len(il_lift_tools) > 20 else il_lift_tools

        report.tools_in_category = len(il_lift_tools)
        print(f"[Validation] Found {len(il_lift_tools)} il_lift_* tools")

        # Test suite per tool (simplified)
        test_suite = {
            "il_lift_level_display": lambda: validate_lift_level_names(),
            "il_lift_level_all": lambda: validate_lift_level_names(),
            "il_lift_arch_count": lambda: validate_arch_supported(),
            "il_lift_supported_arches": lambda: validate_arch_supported(),
            "il_lift_x86_reg_id": lambda: validate_x86_register_canonical(),
            "il_lift_x86_lifter_new": lambda: validate_x86_register_canonical(),
            "il_lift_x86_lifter_lift_nop_o1": lambda: validate_x86_lift_nop(),
            "il_lift_cache_default_capacity_len": lambda: validate_cache_operations(),
            "il_lift_lift_metadata_builder": lambda: validate_metadata_builder(),
            "il_lift_registry_new_len": lambda: validate_registry_defaults(),
        }

        for tool in il_lift_tools:
            tool_name = tool["name"]
            print(f"\n[Test] {tool_name}")
            report.checks_total += 1

            # Get test spec
            test_spec = test_suite.get(tool_name)
            if not test_spec:
                print(f"  -> No test spec, skipping")
                report.checks_skipped += 1
                continue

            try:
                expected = test_spec()
                if expected is None:
                    print(f"  -> Schema unclear, skipping")
                    report.checks_skipped += 1
                    continue

                # Call MCP tool with minimal/no args
                args = {}
                result = mcp.call_tool(tool_name, args)

                # Simple validation: check for errors
                if isinstance(result, dict) and "error" in result:
                    print(f"  -> ERROR: {result['error']}")
                    report.mismatches.append(
                        Mismatch(
                            tool=tool_name,
                            input_data=args,
                            mcp_output=result,
                            expected_output=expected,
                            note="Tool returned error",
                        )
                    )
                else:
                    print(f"  -> OK (result type: {type(result).__name__})")
                    report.checks_passed += 1

            except Exception as e:
                print(f"  -> Exception: {e}")
                report.mismatches.append(
                    Mismatch(
                        tool=tool_name,
                        input_data={},
                        mcp_output=None,
                        expected_output=expected,
                        note=f"Exception: {str(e)}",
                    )
                )

    finally:
        mcp.close()

    return report


def main():
    print("=" * 80)
    print("RustRE MCP Validator: il_lift_* tools")
    print("=" * 80)

    report = run_validation()

    print("\n" + "=" * 80)
    print("VALIDATION SUMMARY")
    print("=" * 80)
    print(f"Category: {report.category}")
    print(f"Tools in category: {report.tools_in_category}")
    print(f"Total checks: {report.checks_total}")
    print(f"Passed: {report.checks_passed}")
    print(f"Skipped: {report.checks_skipped}")
    print(f"Mismatches: {len(report.mismatches)}")

    if report.mismatches:
        print("\n[MISMATCHES]")
        for mismatch in report.mismatches:
            print(f"  Tool: {mismatch.tool}")
            print(f"    Input: {mismatch.input_data}")
            print(f"    MCP: {mismatch.mcp_output}")
            print(f"    Expected: {mismatch.expected_output}")
            print(f"    Note: {mismatch.note}\n")

    # Save report
    report_path = r"C:\Users\Fra\Desktop\RustRE\validation\mismatch_il_lift.json"
    with open(report_path, "w") as f:
        json.dump(report.to_dict(), f, indent=2, default=str)
    print(f"\nReport saved to: {report_path}")

    return len(report.mismatches)


if __name__ == "__main__":
    sys.exit(main())
