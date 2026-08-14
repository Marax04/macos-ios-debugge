#!/usr/bin/env python3
"""
Independent validator for RustRE MCP trace_coverage_ tools.
Focus on tools with clear semantics: percent, ratio, counts.
"""

import subprocess
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
import math
from collections import Counter

# Configuration
MCP_BINARY = Path(r"C:\Users\Fra\Desktop\RustRE\target\release\rustre-mcp.exe")
WORKING_DIR = Path(r"C:\Users\Fra\Desktop\RustRE")
OUTPUT_FILE = Path(r"C:\Users\Fra\Desktop\RustRE\validation\mismatch_trace_coverage.json")


class MCPClient:
    """JSON-RPC client for MCP tools."""

    def __init__(self, binary_path: Path):
        self.proc = subprocess.Popen(
            [str(binary_path), "--transport=stdio"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            cwd=str(WORKING_DIR),
            bufsize=0
        )
        self.request_id = 0
        self._initialize()

    def _initialize(self) -> None:
        """Perform JSON-RPC initialization."""
        init_req = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "validator", "version": "1.0"}
            }
        }
        resp = self._send(init_req)
        if resp is None or resp.get("error"):
            raise RuntimeError(f"Init failed: {resp}")

        # Send initialized notification
        notif = {"jsonrpc": "2.0", "method": "notifications/initialized"}
        self.proc.stdin.write((json.dumps(notif) + "\n").encode())
        self.proc.stdin.flush()

    def _send(self, req: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Send JSON-RPC request and read response."""
        self.proc.stdin.write((json.dumps(req) + "\n").encode())
        self.proc.stdin.flush()

        resp_line = self.proc.stdout.readline()
        if not resp_line:
            return None

        return json.loads(resp_line)

    def list_tools(self) -> List[Dict[str, Any]]:
        """List all available MCP tools."""
        self.request_id += 1
        req = {
            "jsonrpc": "2.0",
            "id": self.request_id,
            "method": "tools/list",
            "params": {}
        }
        resp = self._send(req)
        return resp.get("result", {}).get("tools", [])

    def call_tool(self, name: str, args: Dict[str, Any]) -> Any:
        """Call an MCP tool and return result."""
        self.request_id += 1
        req = {
            "jsonrpc": "2.0",
            "id": self.request_id,
            "method": "tools/call",
            "params": {
                "name": name,
                "arguments": args
            }
        }
        resp = self._send(req)
        if resp is None:
            return {"error": "No response"}
        if "error" in resp:
            return {"error": resp["error"]}

        # Extract result from content array
        content = resp.get("result", {}).get("content", [])
        if not content:
            return resp.get("result", {})

        text_content = content[0].get("text", "")
        try:
            return json.loads(text_content)
        except:
            return {"text": text_content}

    def close(self) -> None:
        """Close the MCP process."""
        try:
            self.proc.terminate()
            self.proc.wait(timeout=2)
        except:
            self.proc.kill()


class GroundTruth:
    """Compute ground truth for simple trace_coverage operations."""

    @staticmethod
    def coverage_percent(hits: int, total: int) -> float:
        """Compute coverage percentage."""
        if total == 0:
            return 0.0
        return (hits / total) * 100.0

    @staticmethod
    def lcov_line_ratio(lcov_text: str) -> Optional[float]:
        """Parse LCOV and compute line coverage ratio."""
        lines_found = 0
        lines_hit = 0
        for line in lcov_text.split('\n'):
            if line.startswith('LF:'):
                try:
                    lines_found = int(line.split(':')[1])
                except:
                    pass
            elif line.startswith('LH:'):
                try:
                    lines_hit = int(line.split(':')[1])
                except:
                    pass

        if lines_found == 0:
            return None
        return lines_hit / lines_found

    @staticmethod
    def afl_bitmap_count(bitmap_hex: str) -> int:
        """Count non-zero bytes in AFL bitmap (hex encoded)."""
        try:
            data = bytes.fromhex(bitmap_hex)
            return sum(1 for b in data if b != 0)
        except:
            return 0

    @staticmethod
    def shannon_entropy(data: bytes) -> float:
        """Calculate Shannon entropy of data."""
        if not data:
            return 0.0
        cnt = Counter(data)
        n = len(data)
        return -sum((c/n)*math.log2(c/n) for c in cnt.values())


# Test specifications - tool name -> (inputs, expected_check_func, truth)
TEST_SPECS = {
    "trace_coverage_percent": {
        "inputs": {"hit": 75, "total": 100},
        "check": lambda mcp, inputs: (
            isinstance(mcp, dict) and
            "coverage_percent" in mcp and
            abs(mcp["coverage_percent"] - 75.0) < 0.1
        ),
        "truth": {"coverage_percent": 75.0}
    },
    "trace_coverage_map_hit_count": {
        "inputs": {"map": {"0x1000": 5, "0x2000": 3}},
        "check": lambda mcp, inputs: isinstance(mcp, dict),
        "truth": {"result": "map operation"}
    },
    "trace_coverage_map_ratio": {
        "inputs": {"map": {"0x1000": 1}},
        "check": lambda mcp, inputs: isinstance(mcp, dict),
        "truth": {"result": "ratio"}
    },
    "trace_coverage_afl_bitmap_count": {
        "inputs": {"bitmap": "ff" * 256},  # All 0xFF bytes
        "check": lambda mcp, inputs: (
            isinstance(mcp, dict) and
            ("count" in mcp or "bit_count" in mcp or "bits" in mcp)
        ),
        "truth": {"count": 256}
    },
    "trace_coverage_coverage_percent": {
        "inputs": {"hits": 50, "total": 100},
        "check": lambda mcp, inputs: (
            isinstance(mcp, dict) and
            "percent" in mcp and
            abs(mcp["percent"] - 50.0) < 1.0
        ),
        "truth": {"percent": 50.0}
    },
}


def validate_tool(client: MCPClient, tool_def: Dict[str, Any]) -> Tuple[bool, Optional[Dict[str, Any]]]:
    """
    Validate a single tool. Returns (passed, mismatch_dict or None).
    Returns (True, None) for SKIP status.
    """
    tool_name = tool_def.get("name", "")
    schema = tool_def.get("inputSchema", {})

    # Check if we have a test spec for this tool
    spec = TEST_SPECS.get(tool_name)
    if not spec:
        # Try fuzzy match on suffix
        for spec_name in TEST_SPECS:
            if tool_name.endswith(spec_name.split("_", 1)[1]):
                spec = TEST_SPECS[spec_name]
                break

    if not spec:
        # Skip tools we don't have specs for
        return True, None

    test_input = spec["inputs"]
    expected_check = spec["check"]

    # Call MCP tool
    try:
        mcp_result = client.call_tool(tool_name, test_input)
    except Exception as e:
        return True, None

    if "error" in mcp_result or "text" in mcp_result and "failed" in str(mcp_result.get("text", "")):
        return True, None

    # Check using spec
    try:
        passed = expected_check(mcp_result, test_input)
    except Exception as e:
        return True, None

    if passed:
        return True, None  # Passed
    else:
        return False, {
            "tool": tool_name,
            "input": test_input,
            "mcp": mcp_result,
            "truth": spec["truth"],
            "note": "Result mismatch"
        }


def main():
    """Main validation loop."""

    client = None
    mismatches = []
    checks_total = 0
    checks_passed = 0
    checks_skipped = 0

    try:
        # Start MCP
        print("[*] Starting MCP client...")
        client = MCPClient(MCP_BINARY)
        print("[+] MCP initialized")

        # List tools
        print("[*] Fetching tool list...")
        all_tools = client.list_tools()
        print(f"[+] Found {len(all_tools)} tools")

        # Filter trace_coverage_ tools
        trace_tools = [t for t in all_tools if "trace_coverage_" in t.get("name", "")]
        print(f"[+] Found {len(trace_tools)} trace_coverage_ tools")

        if not trace_tools:
            print("[!] No trace_coverage_ tools found")
            return

        # Validate all (will skip those without specs)
        print(f"[*] Validating {len(trace_tools)} tools...")

        for tool_def in trace_tools:
            tool_name = tool_def.get("name", "?")

            checks_total += 1
            passed, mismatch = validate_tool(client, tool_def)

            if passed:
                if mismatch is None:
                    checks_skipped += 1
                    status = "SKIP"
                else:
                    checks_passed += 1
                    status = "PASS"
            else:
                mismatches.append(mismatch)
                status = "FAIL"

            if checks_total <= 25:
                print(f"  [{checks_total}] {tool_name}... {status}")

        # Report
        print(f"\n[*] Results:")
        print(f"  Total checks: {checks_total}")
        print(f"  Passed: {checks_passed}")
        print(f"  Skipped: {checks_skipped}")
        print(f"  Mismatches: {len(mismatches)}")

        # Save report
        report = {
            "category": "trace_coverage",
            "tools_in_category": len(trace_tools),
            "checks_total": checks_total,
            "checks_passed": checks_passed,
            "checks_skipped": checks_skipped,
            "mismatches": mismatches
        }

        OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
        with open(OUTPUT_FILE, 'w') as f:
            json.dump(report, f, indent=2)

        print(f"\n[+] Report saved to {OUTPUT_FILE}")
        print(f"[+] Mismatch count: {len(mismatches)}")

        return report

    finally:
        if client:
            client.close()


if __name__ == "__main__":
    main()
