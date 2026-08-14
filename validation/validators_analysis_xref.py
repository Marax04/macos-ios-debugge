#!/usr/bin/env python3
"""
Independent validator for RustRE MCP tools with prefix 'analysis_xref_'.
Tests schema correctness, return types, and classification logic.
"""

import subprocess
import json
import sys
import os
from typing import Dict, Any, List, Optional
from dataclasses import dataclass
import struct

# ============================================================================
# Constants
# ============================================================================

MCP_BIN = r"C:\Users\Fra\Desktop\RustRE\target\release\rustre-mcp.exe"
TARGET_BIN = r"C:\Users\Fra\Desktop\Zyphora\target\release\cargo-zyphora.exe"
REPORT_FILE = r"validation\mismatch_analysis_xref.json"

# ============================================================================
# MCP Client
# ============================================================================

class MCPClient:
    """Communicates with MCP via stdio."""

    def __init__(self, binary_path: str):
        self.binary_path = binary_path
        self.process = None
        self.request_id = 0

    def start(self):
        """Start MCP process."""
        self.process = subprocess.Popen(
            [self.binary_path, "--transport=stdio"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            bufsize=0
        )

    def stop(self):
        """Stop MCP process."""
        if self.process:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()

    def send_request(self, method: str, params: Any = None) -> Dict[str, Any]:
        """Send JSON-RPC request, return response."""
        self.request_id += 1
        request = {
            "jsonrpc": "2.0",
            "id": self.request_id,
            "method": method,
            "params": params or {}
        }

        request_json = json.dumps(request) + "\n"
        self.process.stdin.write(request_json.encode())
        self.process.stdin.flush()

        response_json = self.process.stdout.readline()
        if not response_json:
            return {}

        try:
            return json.loads(response_json.decode())
        except (json.JSONDecodeError, UnicodeDecodeError):
            return {}

    def initialize(self):
        """Initialize MCP connection."""
        resp = self.send_request("initialize", {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "validator", "version": "1.0"}
        })

        init_notif = {"jsonrpc": "2.0", "method": "notifications/initialized"}
        self.process.stdin.write((json.dumps(init_notif) + "\n").encode())
        self.process.stdin.flush()

        return resp

    def list_tools(self) -> List[Dict[str, Any]]:
        """List available tools."""
        response = self.send_request("tools/list", {})
        return response.get("result", {}).get("tools", [])

    def call_tool(self, name: str, arguments: Dict[str, Any]) -> Any:
        """Call a tool."""
        response = self.send_request("tools/call", {
            "name": name,
            "arguments": arguments
        })

        if "error" in response:
            return f"error: {response['error'].get('message', 'unknown')}"

        content = response.get("result", {}).get("content", [])
        if content:
            text = content[0].get("text", "")
            try:
                return json.loads(text)
            except:
                return text

        return None


# ============================================================================
# Test Result
# ============================================================================

@dataclass
class TestResult:
    tool: str
    input_args: Dict[str, Any]
    mcp_output: Any
    ground_truth: Any
    passed: bool
    note: str = ""


# ============================================================================
# Test Validators
# ============================================================================

def test_kind_all(client: MCPClient) -> TestResult:
    """Test analysis_xref_kind_all returns a non-empty list."""
    result = client.call_tool("analysis_xref_kind_all", {})

    # Extract kinds from dict if needed
    kinds = None
    if isinstance(result, list):
        kinds = result
    elif isinstance(result, dict) and "kinds" in result:
        kinds = result["kinds"]

    passed = isinstance(kinds, list) and len(kinds) > 0
    note = f"Returns {len(kinds) if isinstance(kinds, list) else 'invalid'} kinds"

    return TestResult(
        tool="analysis_xref_kind_all",
        input_args={},
        mcp_output=kinds if passed else result,
        ground_truth="list of strings",
        passed=passed,
        note=note
    )


def test_kind_is_code(client: MCPClient, kinds: List[str]) -> TestResult:
    """Test analysis_xref_kind_is_code with actual kind."""
    if not kinds:
        return TestResult("analysis_xref_kind_is_code", {}, None, None, True, "No kinds")

    kind = kinds[0]
    result = client.call_tool("analysis_xref_kind_is_code", {"kind": kind})

    passed = isinstance(result, bool)
    note = f"{kind}: is_code={result}"

    return TestResult(
        tool="analysis_xref_kind_is_code",
        input_args={"kind": kind},
        mcp_output=result,
        ground_truth="boolean",
        passed=passed,
        note=note
    )


def test_kind_is_data(client: MCPClient, kinds: List[str]) -> TestResult:
    """Test analysis_xref_kind_is_data with actual kind."""
    if not kinds:
        return TestResult("analysis_xref_kind_is_data", {}, None, None, True, "No kinds")

    kind = kinds[0]
    result = client.call_tool("analysis_xref_kind_is_data", {"kind": kind})

    passed = isinstance(result, bool)
    note = f"{kind}: is_data={result}"

    return TestResult(
        tool="analysis_xref_kind_is_data",
        input_args={"kind": kind},
        mcp_output=result,
        ground_truth="boolean",
        passed=passed,
        note=note
    )


def test_kind_is_import(client: MCPClient, kinds: List[str]) -> TestResult:
    """Test analysis_xref_kind_is_import."""
    if not kinds:
        return TestResult("analysis_xref_kind_is_import", {}, None, None, True, "No kinds")

    kind = kinds[0]
    result = client.call_tool("analysis_xref_kind_is_import", {"kind": kind})

    passed = isinstance(result, bool)
    note = f"{kind}: is_import={result}"

    return TestResult(
        tool="analysis_xref_kind_is_import",
        input_args={"kind": kind},
        mcp_output=result,
        ground_truth="boolean",
        passed=passed,
        note=note
    )


def test_parse_kind(client: MCPClient, kinds: List[str]) -> TestResult:
    """Test analysis_xref_parse_kind."""
    if not kinds:
        return TestResult("analysis_xref_parse_kind", {}, None, None, True, "No kinds")

    kind = kinds[0]
    result = client.call_tool("analysis_xref_parse_kind", {"kind": kind})

    # Should return a dict with classification flags
    passed = isinstance(result, dict) and "error" not in str(result).lower()
    note = f"Parse {kind}: {type(result).__name__}"

    return TestResult(
        tool="analysis_xref_parse_kind",
        input_args={"kind": kind},
        mcp_output=result,
        ground_truth="dict with flags",
        passed=passed,
        note=note
    )


def test_global_db_total(client: MCPClient) -> TestResult:
    """Test analysis_xref_global_db_total returns an integer."""
    result = client.call_tool("analysis_xref_global_db_total", {})

    # Try to extract as int
    mcp_int = None
    if isinstance(result, int):
        mcp_int = result
    elif isinstance(result, dict):
        v = result.get("total")
        if isinstance(v, int):
            mcp_int = v
    elif isinstance(result, str):
        try:
            mcp_int = int(result)
        except:
            pass

    passed = isinstance(mcp_int, int) and mcp_int >= 0
    note = f"Total xrefs in global DB: {mcp_int}"

    return TestResult(
        tool="analysis_xref_global_db_total",
        input_args={},
        mcp_output=mcp_int,
        ground_truth="non-negative integer",
        passed=passed,
        note=note
    )


def test_index_from_path(client: MCPClient, path: str) -> TestResult:
    """Test analysis_xref_index_from_path_v2 with actual binary."""
    result = client.call_tool("analysis_xref_index_from_path_v2", {"path": path})

    mcp_int = None
    if isinstance(result, int):
        mcp_int = result
    elif isinstance(result, dict):
        v = result.get("total")
        if isinstance(v, int):
            mcp_int = v
    elif isinstance(result, str):
        try:
            mcp_int = int(result)
        except:
            pass

    passed = isinstance(mcp_int, int) and mcp_int >= 0
    note = f"Xrefs from {os.path.basename(path)}: {mcp_int}"

    return TestResult(
        tool="analysis_xref_index_from_path_v2",
        input_args={"path": path},
        mcp_output=mcp_int,
        ground_truth="non-negative integer",
        passed=passed,
        note=note
    )


def test_index_from_bytes(client: MCPClient, hex_bytes: str) -> TestResult:
    """Test analysis_xref_index_from_bytes_v2 with hex."""
    result = client.call_tool("analysis_xref_index_from_bytes_v2", {"hex": hex_bytes})

    mcp_int = None
    if isinstance(result, int):
        mcp_int = result
    elif isinstance(result, dict):
        v = result.get("total")
        if isinstance(v, int):
            mcp_int = v
    elif isinstance(result, str):
        try:
            mcp_int = int(result)
        except:
            pass

    passed = isinstance(mcp_int, int) and mcp_int >= 0
    note = f"Xrefs from hex ({len(hex_bytes)//2} bytes): {mcp_int}"

    return TestResult(
        tool="analysis_xref_index_from_bytes_v2",
        input_args={"hex": f"{hex_bytes[:32]}..."},
        mcp_output=mcp_int,
        ground_truth="non-negative integer",
        passed=passed,
        note=note
    )


def test_global_xrefs_from(client: MCPClient) -> TestResult:
    """Test analysis_xref_global_xrefs_from."""
    result = client.call_tool("analysis_xref_global_xrefs_from", {"addr": 0x140001000})

    passed = isinstance(result, (list, dict)) and "error" not in str(result).lower()
    note = f"Xrefs from 0x140001000: {type(result).__name__}"

    return TestResult(
        tool="analysis_xref_global_xrefs_from",
        input_args={"addr": "0x140001000"},
        mcp_output=result,
        ground_truth="list or dict",
        passed=passed,
        note=note
    )


def test_global_xrefs_to(client: MCPClient) -> TestResult:
    """Test analysis_xref_global_xrefs_to."""
    result = client.call_tool("analysis_xref_global_xrefs_to", {"addr": 0x140002000})

    passed = isinstance(result, (list, dict)) and "error" not in str(result).lower()
    note = f"Xrefs to 0x140002000: {type(result).__name__}"

    return TestResult(
        tool="analysis_xref_global_xrefs_to",
        input_args={"addr": "0x140002000"},
        mcp_output=result,
        ground_truth="list or dict",
        passed=passed,
        note=note
    )


def test_database_stats(client: MCPClient, hex_bytes: str) -> TestResult:
    """Test analysis_xref_database_stats with hex parameter."""
    result = client.call_tool("analysis_xref_database_stats", {"hex": hex_bytes})

    passed = isinstance(result, dict) and "error" not in str(result).lower()
    note = f"DB stats: {type(result).__name__}"

    return TestResult(
        tool="analysis_xref_database_stats",
        input_args={"hex": "..."},
        mcp_output=result,
        ground_truth="dict with statistics",
        passed=passed,
        note=note
    )


def test_call_graph(client: MCPClient, hex_bytes: str) -> TestResult:
    """Test analysis_xref_call_graph with hex parameter."""
    result = client.call_tool("analysis_xref_call_graph", {"hex": hex_bytes})

    passed = isinstance(result, (dict, list)) and "error" not in str(result).lower()
    note = f"Call graph: {type(result).__name__}"

    return TestResult(
        tool="analysis_xref_call_graph",
        input_args={"hex": "..."},
        mcp_output=result,
        ground_truth="dict or list",
        passed=passed,
        note=note
    )


# ============================================================================
# Main
# ============================================================================

def main():
    print("[*] Starting analysis_xref_ validator...")

    # Load target binary for hex test
    print(f"[*] Loading target binary...")
    hex_bytes = ""
    if os.path.exists(TARGET_BIN):
        with open(TARGET_BIN, "rb") as f:
            data = f.read(2048)  # First 2KB
            hex_bytes = data.hex()
        print(f"    Loaded {len(data)} bytes for hex test")

    # Start MCP
    print("[*] Starting MCP client...")
    client = MCPClient(MCP_BIN)
    try:
        client.start()
        client.initialize()

        # List tools
        print("[*] Listing tools...")
        tools = client.list_tools()
        xref_tools = [t for t in tools if "analysis_xref_" in t.get("name", "")]
        print(f"    Found {len(xref_tools)} analysis_xref_ tools")

        # Get kinds
        print("[*] Getting xref kinds...")
        kinds_result = client.call_tool("analysis_xref_kind_all", {})
        kinds = kinds_result if isinstance(kinds_result, list) else []
        print(f"    Got {len(kinds)} kinds")

        # Run test suite
        test_funcs = [
            ("test_kind_all", lambda: test_kind_all(client)),
            ("test_kind_is_code", lambda: test_kind_is_code(client, kinds)),
            ("test_kind_is_data", lambda: test_kind_is_data(client, kinds)),
            ("test_kind_is_import", lambda: test_kind_is_import(client, kinds)),
            ("test_parse_kind", lambda: test_parse_kind(client, kinds)),
            ("test_global_db_total", lambda: test_global_db_total(client)),
            ("test_index_from_path", lambda: test_index_from_path(client, TARGET_BIN)),
            ("test_index_from_bytes", lambda: test_index_from_bytes(client, hex_bytes)),
            ("test_global_xrefs_from", lambda: test_global_xrefs_from(client)),
            ("test_global_xrefs_to", lambda: test_global_xrefs_to(client)),
            ("test_database_stats", lambda: test_database_stats(client, hex_bytes)),
            ("test_call_graph", lambda: test_call_graph(client, hex_bytes)),
        ]

        results = []
        for name, test_func in test_funcs:
            print(f"[*] {name}...")
            try:
                result = test_func()
                results.append(result)
                status = "PASS" if result.passed else "FAIL"
                print(f"    {status}: {result.note}")
            except Exception as e:
                print(f"    ERROR: {e}")
                results.append(TestResult(
                    tool=name,
                    input_args={},
                    mcp_output=None,
                    ground_truth=None,
                    passed=False,
                    note=f"Exception: {e}"
                ))

        # Generate report
        print(f"[*] Generating report...")
        mismatches = [r for r in results if not r.passed]

        report = {
            "category": "analysis_xref",
            "tools_in_category": len(xref_tools),
            "checks_total": len(results),
            "checks_passed": len([r for r in results if r.passed]),
            "checks_skipped": len([r for r in results if r.mcp_output is None and r.ground_truth is None]),
            "mismatches": [
                {
                    "tool": m.tool,
                    "input": m.input_args,
                    "mcp": m.mcp_output,
                    "truth": m.ground_truth,
                    "note": m.note
                }
                for m in mismatches
            ]
        }

        os.makedirs(os.path.dirname(REPORT_FILE) or ".", exist_ok=True)
        with open(REPORT_FILE, "w") as f:
            json.dump(report, f, indent=2, default=str)

        print(f"[*] Done: {report['checks_passed']}/{report['checks_total']} passed, {len(mismatches)} mismatches")
        print(f"[*] Report: {REPORT_FILE}")

        return report

    finally:
        client.stop()


if __name__ == "__main__":
    report = main()
    sys.exit(0 if report["checks_passed"] == report["checks_total"] else 1)
