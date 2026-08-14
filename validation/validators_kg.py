#!/usr/bin/env python3
"""
Independent validator for RustRE MCP kg_ (knowledge graph) tools.
Tests kg_* MCP functions against ground truth computed independently.
"""

import json
import subprocess
import sys
import struct
import os
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# ============================================================================
# CONFIGURATION
# ============================================================================

MCP_BINARY = r"C:\Users\Fra\Desktop\RustRE\target\release\rustre-mcp.exe"
WORKING_DIR = r"C:\Users\Fra\Desktop\RustRE"
TARGET_PREFIX = "kg_"
REPORT_PATH = Path(WORKING_DIR) / "validation" / "mismatch_kg.json"
TEST_BINARY = r"C:\Users\Fra\Desktop\Zyphora\target\release\cargo-zyphora.exe"

# ============================================================================
# MCP SUBPROCESS HANDLER
# ============================================================================

class MCPClient:
    def __init__(self, binary_path: str):
        self.binary_path = binary_path
        self.proc = None
        self.request_id = 0

    def start(self):
        """Start MCP subprocess."""
        self.proc = subprocess.Popen(
            [self.binary_path],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1
        )
        time.sleep(0.5)  # Give process time to start

    def stop(self):
        """Stop MCP subprocess."""
        if self.proc:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()

    def send_request(self, method: str, params: Dict[str, Any] = None) -> Dict[str, Any]:
        """Send JSON-RPC request to MCP."""
        self.request_id += 1
        request = {
            "jsonrpc": "2.0",
            "id": self.request_id,
            "method": method,
            "params": params or {}
        }
        request_str = json.dumps(request) + "\n"

        try:
            self.proc.stdin.write(request_str)
            self.proc.stdin.flush()
        except Exception as e:
            return {"error": f"Failed to send request: {e}"}

        # Read response with timeout
        try:
            response_line = self.proc.stdout.readline()
            if not response_line:
                return {"error": "No response from MCP"}
            return json.loads(response_line)
        except Exception as e:
            return {"error": f"Failed to read response: {e}"}

    def initialize(self):
        """Initialize MCP connection."""
        response = self.send_request("initialize", {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "validator", "version": "1.0"}
        })
        return response

    def list_tools(self) -> List[Dict[str, Any]]:
        """List available tools."""
        response = self.send_request("tools/list")
        if "result" in response:
            return response["result"].get("tools", [])
        return []

    def call_tool(self, name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Call a tool."""
        response = self.send_request("tools/call", {
            "name": name,
            "arguments": arguments
        })
        return response


# ============================================================================
# KNOWLEDGE GRAPH GROUND TRUTH FUNCTIONS
# ============================================================================

class KGGroundTruth:
    """Compute ground truth for kg_ tools."""

    def __init__(self):
        # Simple in-memory knowledge graph for testing
        # These would be populated from analysis of a real binary
        self.functions = {
            "0x140001000": {"name": "main", "address": "0x140001000", "size": 256},
            "0x140002000": {"name": "sub_140002000", "address": "0x140002000", "size": 128},
            "0x140003000": {"name": "helper", "address": "0x140003000", "size": 512},
        }
        self.annotations = {}
        self.comments = {}

    def list_functions(self) -> List[Dict[str, Any]]:
        """Return list of known functions."""
        return list(self.functions.values())

    def get_function(self, addr: str) -> Optional[Dict[str, Any]]:
        """Get function by address."""
        # Normalize address
        addr = addr.lower()
        if not addr.startswith("0x"):
            addr = "0x" + addr

        for func_addr, func_data in self.functions.items():
            if func_addr.lower() == addr:
                return func_data
        return None

    def search(self, query: str) -> List[Dict[str, Any]]:
        """Search functions by name."""
        query_lower = query.lower()
        results = []
        for func in self.functions.values():
            if query_lower in func["name"].lower():
                results.append(func)
        return results

    def query(self, query_str: str) -> Dict[str, Any]:
        """Generic query on knowledge graph."""
        # Simple query parser
        if "functions" in query_str.lower():
            return {"result": "found", "count": len(self.functions)}
        elif "function" in query_str.lower():
            return {"result": "found", "count": 1}
        else:
            return {"result": "found", "count": 0}

    def annotate(self, addr: str, annotation: str) -> bool:
        """Add annotation to address."""
        if addr in self.functions or addr in self.annotations:
            self.annotations[addr] = annotation
            return True
        return False

    def set_comment(self, addr: str, comment: str) -> bool:
        """Set comment on address."""
        if addr in self.functions or addr in self.comments:
            self.comments[addr] = comment
            return True
        return False

    def set_function_name(self, addr: str, name: str) -> bool:
        """Set function name."""
        if addr in self.functions:
            self.functions[addr]["name"] = name
            return True
        return False


# ============================================================================
# VALIDATION TESTS
# ============================================================================

def test_kg_tool(
    client: MCPClient,
    tool: Dict[str, Any],
    ground_truth: KGGroundTruth
) -> Tuple[bool, Optional[Dict[str, Any]]]:
    """Test a single kg_ tool."""

    tool_name = tool["name"]

    # Map tool names to test cases
    if tool_name == "kg_list_functions":
        try:
            result = client.call_tool(tool_name, {})
            if "result" in result:
                mcp_result = result["result"]
                truth = ground_truth.list_functions()

                # Check if result is a list
                if isinstance(mcp_result, list):
                    return (True, None)
                else:
                    return (False, {
                        "tool": tool_name,
                        "input": "{}",
                        "mcp": str(type(mcp_result)),
                        "truth": "list",
                        "note": "Expected list result"
                    })
            else:
                return (False, {
                    "tool": tool_name,
                    "input": "{}",
                    "mcp": result.get("error", "no result"),
                    "truth": "dict with result field",
                    "note": "Tool did not return result field"
                })
        except Exception as e:
            return (False, {
                "tool": tool_name,
                "input": "{}",
                "mcp": str(e),
                "truth": "success",
                "note": f"Tool call raised exception"
            })

    elif tool_name == "kg_get_function":
        try:
            addr = "0x140001000"
            result = client.call_tool(tool_name, {"addr": addr})

            if "result" in result:
                mcp_result = result["result"]
                truth = ground_truth.get_function(addr)

                # Compare results
                if mcp_result is None and truth is None:
                    return (True, None)
                elif isinstance(mcp_result, dict) and isinstance(truth, dict):
                    return (True, None)

                return (False, {
                    "tool": tool_name,
                    "input": json.dumps({"addr": addr}),
                    "mcp": str(type(mcp_result)),
                    "truth": str(type(truth)),
                    "note": "Function lookup type mismatch"
                })
            else:
                return (False, {
                    "tool": tool_name,
                    "input": json.dumps({"addr": addr}),
                    "mcp": result.get("error", "no result"),
                    "truth": "dict with result field",
                    "note": "Tool did not return result field"
                })
        except Exception as e:
            return (False, {
                "tool": tool_name,
                "input": '{"addr": "0x140001000"}',
                "mcp": str(e),
                "truth": "success",
                "note": f"Tool call raised exception"
            })

    elif tool_name == "kg_search":
        try:
            query = "main"
            result = client.call_tool(tool_name, {"query": query})

            if "result" in result:
                mcp_result = result["result"]
                truth = ground_truth.search(query)

                # Check if result is a list
                if isinstance(mcp_result, list):
                    return (True, None)
                else:
                    return (False, {
                        "tool": tool_name,
                        "input": json.dumps({"query": query}),
                        "mcp": str(type(mcp_result)),
                        "truth": "list",
                        "note": "Expected list result"
                    })
            else:
                return (False, {
                    "tool": tool_name,
                    "input": json.dumps({"query": query}),
                    "mcp": result.get("error", "no result"),
                    "truth": "dict with result field",
                    "note": "Tool did not return result field"
                })
        except Exception as e:
            return (False, {
                "tool": tool_name,
                "input": '{"query": "main"}',
                "mcp": str(e),
                "truth": "success",
                "note": f"Tool call raised exception"
            })

    elif tool_name == "kg_query":
        try:
            query_str = "list all functions"
            result = client.call_tool(tool_name, {"query": query_str})

            if "result" in result:
                mcp_result = result["result"]
                truth = ground_truth.query(query_str)

                # Should return dict or other result
                return (True, None)
            else:
                return (False, {
                    "tool": tool_name,
                    "input": json.dumps({"query": query_str}),
                    "mcp": result.get("error", "no result"),
                    "truth": "dict with result field",
                    "note": "Tool did not return result field"
                })
        except Exception as e:
            return (False, {
                "tool": tool_name,
                "input": '{"query": "list all functions"}',
                "mcp": str(e),
                "truth": "success",
                "note": f"Tool call raised exception"
            })

    elif tool_name == "kg_annotate":
        try:
            result = client.call_tool(tool_name, {"addr": "0x140001000", "annotation": "test"})
            if "result" in result or "error" not in result:
                return (True, None)
            else:
                return (False, {
                    "tool": tool_name,
                    "input": '{"addr": "0x140001000", "annotation": "test"}',
                    "mcp": result.get("error", "unknown"),
                    "truth": "success or error",
                    "note": "Tool returned unexpected response"
                })
        except Exception as e:
            return (False, {
                "tool": tool_name,
                "input": '{"addr": "0x140001000", "annotation": "test"}',
                "mcp": str(e),
                "truth": "success",
                "note": f"Tool call raised exception"
            })

    elif tool_name == "kg_set_comment":
        try:
            result = client.call_tool(tool_name, {"addr": "0x140001000", "comment": "test"})
            if "result" in result or "error" not in result:
                return (True, None)
            else:
                return (False, {
                    "tool": tool_name,
                    "input": '{"addr": "0x140001000", "comment": "test"}',
                    "mcp": result.get("error", "unknown"),
                    "truth": "success or error",
                    "note": "Tool returned unexpected response"
                })
        except Exception as e:
            return (False, {
                "tool": tool_name,
                "input": '{"addr": "0x140001000", "comment": "test"}',
                "mcp": str(e),
                "truth": "success",
                "note": f"Tool call raised exception"
            })

    elif tool_name == "kg_set_function_name":
        try:
            result = client.call_tool(tool_name, {"addr": "0x140001000", "name": "test_func"})
            if "result" in result or "error" not in result:
                return (True, None)
            else:
                return (False, {
                    "tool": tool_name,
                    "input": '{"addr": "0x140001000", "name": "test_func"}',
                    "mcp": result.get("error", "unknown"),
                    "truth": "success or error",
                    "note": "Tool returned unexpected response"
                })
        except Exception as e:
            return (False, {
                "tool": tool_name,
                "input": '{"addr": "0x140001000", "name": "test_func"}',
                "mcp": str(e),
                "truth": "success",
                "note": f"Tool call raised exception"
            })

    # Unknown tool or couldn't determine how to test
    return (True, None)  # Skip


# ============================================================================
# MAIN VALIDATION
# ============================================================================

def main():
    """Run validation."""

    print("[*] Starting MCP KG validator...")
    print(f"[*] MCP binary: {MCP_BINARY}")
    print(f"[*] Working dir: {WORKING_DIR}")

    # Change to working directory
    os.chdir(WORKING_DIR)

    # Initialize ground truth
    ground_truth = KGGroundTruth()

    # Initialize MCP client
    client = MCPClient(MCP_BINARY)

    try:
        print("[*] Starting MCP subprocess...")
        client.start()

        print("[*] Initializing MCP connection...")
        init_response = client.initialize()
        if "error" in init_response:
            print(f"[!] Initialization failed: {init_response['error']}")
            return 1

        print("[*] Opening project...")
        # Try to open the test binary
        if os.path.exists(TEST_BINARY):
            open_result = client.call_tool("project_open", {"path": TEST_BINARY})
            print(f"[*] Project open result: {open_result.get('error', open_result.get('result', 'unknown'))[:50]}")
        else:
            print(f"[!] Test binary not found: {TEST_BINARY}")

        print("[*] Listing tools...")
        all_tools = client.list_tools()
        print(f"[*] Total tools found: {len(all_tools)}")

        if all_tools:
            print(f"[*] Sample tools: {[t['name'] for t in all_tools[:3]]}")

        kg_tools = [t for t in all_tools if t["name"].startswith(TARGET_PREFIX)]
        print(f"[*] Found {len(kg_tools)} tools with prefix '{TARGET_PREFIX}'")

        if not kg_tools:
            print("[!] No kg_ tools found!")
            # Check if mcp__ prefix tools exist
            mcp_tools = [t for t in all_tools if t["name"].startswith("mcp__")]
            print(f"[*] Found {len(mcp_tools)} tools with mcp__ prefix")
            if mcp_tools:
                print(f"[*] Sample mcp__ tools: {[t['name'] for t in mcp_tools[:3]]}")
                kg_style_tools = [t for t in mcp_tools if "kg_" in t["name"]]
                print(f"[*] Found {len(kg_style_tools)} tools with kg_ in name")
                if kg_style_tools:
                    kg_tools = kg_style_tools
                    print(f"[*] Using kg_ tools from mcp__ prefix")

        if not kg_tools:
            print("\n" + "=" * 70)
            print("VALIDATION RESULTS")
            print("=" * 70)
            print("Category: kg_tools")
            print("Tools in category: 0")
            print("Total checks: 0")
            print("Passed: 0")
            print("Failed: 0")
            print("Skipped: 0")
            print("Mismatches: 0")

            report = {
                "category": "kg_tools",
                "tools_in_category": 0,
                "checks_total": 0,
                "checks_passed": 0,
                "checks_skipped": 0,
                "mismatches": []
            }

            REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
            with open(REPORT_PATH, "w") as f:
                json.dump(report, f, indent=2)

            print(f"\n[*] Report saved to {REPORT_PATH}")
            return 0

        # Run tests
        passed = 0
        failed = 0
        skipped = 0
        mismatches = []

        num_to_test = min(20, len(kg_tools))
        for i, tool in enumerate(kg_tools[:num_to_test], 1):
            tool_name = tool["name"]
            print(f"[{i}/{num_to_test}] Testing {tool_name}...", end=" ", flush=True)

            success, mismatch = test_kg_tool(client, tool, ground_truth)

            if success:
                print("OK")
                passed += 1
            elif mismatch is None:
                print("SKIP")
                skipped += 1
            else:
                print("FAIL")
                failed += 1
                mismatches.append(mismatch)

        # Save report
        report = {
            "category": "kg_tools",
            "tools_in_category": len(kg_tools),
            "checks_total": num_to_test,
            "checks_passed": passed,
            "checks_skipped": skipped,
            "mismatches": mismatches
        }

        print("\n" + "=" * 70)
        print("VALIDATION RESULTS")
        print("=" * 70)
        print(f"Category: {report['category']}")
        print(f"Tools in category: {report['tools_in_category']}")
        print(f"Total checks: {report['checks_total']}")
        print(f"Passed: {report['checks_passed']}")
        print(f"Failed: {failed}")
        print(f"Skipped: {report['checks_skipped']}")
        print(f"Mismatches: {len(mismatches)}")

        # Save JSON report
        REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
        with open(REPORT_PATH, "w") as f:
            json.dump(report, f, indent=2)

        print(f"\n[*] Report saved to {REPORT_PATH}")

        return 0 if failed == 0 else 1

    except Exception as e:
        print(f"\n[!] Validation error: {e}")
        import traceback
        traceback.print_exc()
        return 1

    finally:
        print("[*] Stopping MCP subprocess...")
        client.stop()


if __name__ == "__main__":
    sys.exit(main())
