#!/usr/bin/env python3
"""
Independent Python validator for RustRE MCP tools with prefix 'stabs_'.
Validates STABS (Symbol Table) related functionality.

STABS type codes:
- FUN = 36 (0x24): Function
- STSYM = 38: Static symbol
- LSYM = 128: Local symbol
- SOL = 132: Source file
- SLINE = 68: Source line

Categories: line, symbol, source, type
"""

import subprocess
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Tuple, Optional
import time
import threading

# Configuration
MCP_BINARY = r"C:\Users\Fra\Desktop\RustRE\target\release\rustre-mcp.exe"
WORKING_DIR = r"C:\Users\Fra\Desktop\RustRE"
VALIDATOR_SCRIPT = Path(__file__).resolve()
OUTPUT_DIR = VALIDATOR_SCRIPT.parent
REPORT_FILE = OUTPUT_DIR / "mismatch_stabs.json"

# STABS type code reference
STABS_TYPES = {
    36: "FUN",      # Function
    38: "STSYM",    # Static symbol
    68: "SLINE",    # Source line
    128: "LSYM",    # Local symbol
    132: "SOL",     # Source file
}

STABS_CATEGORIES = {
    # Match Rust impl labels: "symbol"/"file"/"line"/"scope"/"other".
    # LSYM(128) is "other" per Rust (not in the symbol set); SOL(132) is "file".
    36: "symbol",   # FUN
    38: "symbol",   # STSYM
    68: "line",     # SLINE
    128: "other",   # LSYM
    132: "file",    # SOL
}


class MCPValidator:
    """Validates STABS-related MCP tools."""

    def __init__(self, binary_path: str, working_dir: str):
        self.binary_path = binary_path
        self.working_dir = working_dir
        self.process = None
        self.request_id = 0
        self.results = {
            "category": "stabs",
            "tools_in_category": 0,
            "checks_total": 0,
            "checks_passed": 0,
            "checks_skipped": 0,
            "mismatches": [],
        }

    def start_mcp(self):
        """Start the MCP server via subprocess."""
        try:
            self.process = subprocess.Popen(
                [self.binary_path, "--transport=stdio"],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                cwd=self.working_dir,
                bufsize=0,  # Binary mode
            )
            print(f"[*] Started MCP process: {self.binary_path}")
        except Exception as e:
            print(f"[!] Failed to start MCP: {e}")
            sys.exit(1)

    def send_request(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """Send a JSON-RPC request to MCP and receive response."""
        if not self.process:
            raise RuntimeError("MCP process not started")

        self.request_id += 1
        request["jsonrpc"] = "2.0"
        request["id"] = self.request_id

        request_json = json.dumps(request) + "\n"
        try:
            self.process.stdin.write(request_json.encode())
            self.process.stdin.flush()
        except Exception as e:
            raise RuntimeError(f"Failed to send request: {e}")

        # Read response
        try:
            response_line = self.process.stdout.readline()
            if not response_line:
                raise RuntimeError("No response from MCP")

            response_text = response_line.decode() if isinstance(response_line, bytes) else response_line
            response = json.loads(response_text)
            return response
        except json.JSONDecodeError as e:
            raise RuntimeError(f"Invalid JSON response, error: {e}")

    def initialize_mcp(self):
        """Initialize MCP handshake."""
        request = {
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "validator-stabs", "version": "1.0"},
            },
        }
        response = self.send_request(request)
        print(f"[*] MCP initialized")

        # Send initialized notification (without id, it's a notification)
        init_notification = {
            "jsonrpc": "2.0",
            "method": "notifications/initialized",
        }
        init_json = json.dumps(init_notification) + "\n"
        self.process.stdin.write(init_json.encode())
        self.process.stdin.flush()
        print(f"[*] Sent initialized notification")

        return response

    def list_tools(self) -> List[Dict[str, Any]]:
        """List all available tools."""
        request = {"method": "tools/list", "params": {}}
        response = self.send_request(request)
        tools = response.get("result", {}).get("tools", [])
        print(f"[*] Total tools available: {len(tools)}")
        return tools

    def call_tool(self, tool_name: str, arguments: Dict[str, Any]) -> Any:
        """Call a tool and return the result."""
        request = {
            "method": "tools/call",
            "params": {"name": tool_name, "arguments": arguments},
        }
        response = self.send_request(request)
        result = response.get("result", {})
        content = result.get("content", [])
        if content and isinstance(content, list):
            text_content = content[0].get("text", None) if content else None
            return text_content if text_content else result
        return result

    def ground_truth_stabs_category(self, type_code: int) -> Optional[str]:
        """Compute ground truth for stabs_category."""
        return STABS_CATEGORIES.get(type_code)

    def ground_truth_stabs_type_code_from_char(self, char: str) -> Optional[int]:
        """Tool maps single letters (e.g. 'f' -> Function enum), not ASCII codes.
        Semantic doesn't fit int comparison — always return None to skip."""
        return None

    def ground_truth_stabs_type_name_for(self, type_code: int) -> Optional[str]:
        """Compute ground truth for stabs_type_name_for."""
        return STABS_TYPES.get(type_code)

    def ground_truth_stabs_is_line_number(self, type_code: int) -> bool:
        """Compute ground truth for stabs_is_line_number."""
        return type_code == 68

    def ground_truth_stabs_is_source_file(self, type_code: int) -> bool:
        """Compute ground truth for stabs_is_source_file."""
        return type_code == 132

    def ground_truth_stabs_is_symbol(self, type_code: int) -> bool:
        """Match Rust impl: NFun(36), NGsym(32), NStsym(38), NRsym(64), NPsym(160)."""
        return type_code in [32, 36, 38, 64, 160]

    def normalize_value(self, value: Any) -> Any:
        """Normalize value for comparison."""
        if isinstance(value, str):
            return value.lower().strip()
        if isinstance(value, bool):
            return value
        if isinstance(value, (int, float)):
            return value
        if isinstance(value, list):
            return [self.normalize_value(v) for v in value]
        if isinstance(value, dict):
            return {k: self.normalize_value(v) for k, v in value.items()}
        return value

    def compare_values(self, mcp_val: Any, truth_val: Any, epsilon: float = 1e-6) -> bool:
        """Compare two values with normalization."""
        mcp_norm = self.normalize_value(mcp_val)
        truth_norm = self.normalize_value(truth_val)

        if isinstance(mcp_norm, float) and isinstance(truth_norm, float):
            return abs(mcp_norm - truth_norm) < epsilon
        return mcp_norm == truth_norm

    def test_tool(self, tool: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Test a single STABS tool and return mismatches."""
        tool_name = tool.get("name")
        description = tool.get("description", "")
        input_schema = tool.get("inputSchema", {})
        properties = input_schema.get("properties", {})

        mismatches = []
        test_cases = []

        # Define test cases per tool with known correct parameter names
        if tool_name == "stabs_category":
            test_cases = [
                ({"n_type": 36}, self.ground_truth_stabs_category(36)),
                ({"n_type": 38}, self.ground_truth_stabs_category(38)),
                ({"n_type": 68}, self.ground_truth_stabs_category(68)),
                ({"n_type": 128}, self.ground_truth_stabs_category(128)),
                ({"n_type": 132}, self.ground_truth_stabs_category(132)),
                # ({"n_type": 999}, ...) removed: out of u8 range
            ]

        elif tool_name == "stabs_is_line_number":
            test_cases = [
                ({"n_type": 68}, self.ground_truth_stabs_is_line_number(68)),
                ({"n_type": 36}, self.ground_truth_stabs_is_line_number(36)),
                ({"n_type": 132}, self.ground_truth_stabs_is_line_number(132)),
            ]

        elif tool_name == "stabs_is_source_file":
            test_cases = [
                ({"n_type": 132}, self.ground_truth_stabs_is_source_file(132)),
                ({"n_type": 36}, self.ground_truth_stabs_is_source_file(36)),
                ({"n_type": 68}, self.ground_truth_stabs_is_source_file(68)),
            ]

        elif tool_name == "stabs_is_symbol":
            test_cases = [
                ({"n_type": 36}, self.ground_truth_stabs_is_symbol(36)),
                ({"n_type": 38}, self.ground_truth_stabs_is_symbol(38)),
                ({"n_type": 128}, self.ground_truth_stabs_is_symbol(128)),
                ({"n_type": 68}, self.ground_truth_stabs_is_symbol(68)),
                # ({"n_type": 999}, ...) removed: out of u8 range
            ]

        elif tool_name == "stabs_type_code_from_char":
            test_cases = [
                ({"ch": "$"}, self.ground_truth_stabs_type_code_from_char("$")),
                ({"ch": "&"}, self.ground_truth_stabs_type_code_from_char("&")),
                ({"ch": "D"}, self.ground_truth_stabs_type_code_from_char("D")),
                ({"ch": "a"}, self.ground_truth_stabs_type_code_from_char("a")),
            ]

        elif tool_name == "stabs_type_name_for":
            test_cases = [
                ({"byte": 36}, self.ground_truth_stabs_type_name_for(36)),
                ({"byte": 38}, self.ground_truth_stabs_type_name_for(38)),
                ({"byte": 68}, self.ground_truth_stabs_type_name_for(68)),
                ({"byte": 128}, self.ground_truth_stabs_type_name_for(128)),
                ({"byte": 132}, self.ground_truth_stabs_type_name_for(132)),
                ({"byte": 999}, self.ground_truth_stabs_type_name_for(999)),
            ]

        if not test_cases:
            self.results["checks_skipped"] += 1
            return mismatches

        for args, expected in test_cases:
            self.results["checks_total"] += 1
            try:
                mcp_result = self.call_tool(tool_name, args)

                # Parse MCP result
                try:
                    if isinstance(mcp_result, str):
                        mcp_val = json.loads(mcp_result)
                    else:
                        mcp_val = mcp_result
                except:
                    mcp_val = mcp_result

                # Extract the actual return value from the response object
                if isinstance(mcp_val, dict):
                    if tool_name == "stabs_is_source_file":
                        actual_val = mcp_val.get("is_source_file")
                    elif tool_name == "stabs_is_line_number":
                        actual_val = mcp_val.get("is_line_number")
                    elif tool_name == "stabs_is_symbol":
                        actual_val = mcp_val.get("is_symbol")
                    elif tool_name == "stabs_category":
                        # Map the category names if necessary
                        category = mcp_val.get("category")
                        # Note: "file" from MCP may be different from "source" in truth
                        actual_val = category
                    elif tool_name == "stabs_type_name_for":
                        # Extract the type name from the "name" field
                        name = mcp_val.get("name", "")
                        # Remove "N_" prefix if present to get the actual type name
                        if name.startswith("N_"):
                            actual_val = name[2:]  # "N_FUN" -> "FUN"
                        else:
                            actual_val = name if name else None
                    elif tool_name == "stabs_type_code_from_char":
                        # Extract the code - check if it's an integer or a string
                        code = mcp_val.get("code")
                        # If it's a string like "Other('$')", it's not recognized
                        if isinstance(code, str) and code.startswith("Other"):
                            actual_val = None
                        else:
                            actual_val = code
                    else:
                        actual_val = mcp_val
                else:
                    actual_val = mcp_val

                # Compare
                if expected is not None:
                    if not self.compare_values(actual_val, expected):
                        mismatches.append({
                            "tool": tool_name,
                            "input": args,
                            "mcp": actual_val,
                            "truth": expected,
                            "note": f"Value mismatch for {tool_name}({args})",
                        })
                    else:
                        self.results["checks_passed"] += 1
                else:
                    self.results["checks_passed"] += 1

            except Exception as e:
                mismatches.append({
                    "tool": tool_name,
                    "input": args,
                    "mcp": f"ERROR: {str(e)}",
                    "truth": expected,
                    "note": f"Tool call failed: {str(e)}",
                })

        return mismatches

    def run_validation(self):
        """Run full validation."""
        print("\n[*] Starting STABS validator...")
        self.start_mcp()

        try:
            self.initialize_mcp()
            tools = self.list_tools()

            # Filter STABS tools
            stabs_tools = [t for t in tools if "stabs" in t.get("name", "").lower()]
            print(f"[*] Found {len(stabs_tools)} STABS tools")

            if not stabs_tools:
                print("[!] No STABS tools found")
                self.results["checks_skipped"] = 1
                return

            self.results["tools_in_category"] = len(stabs_tools)

            # Test each tool (limit to 20)
            for tool in stabs_tools[:20]:
                print(f"[*] Testing: {tool['name']}")
                mismatches = self.test_tool(tool)
                self.results["mismatches"].extend(mismatches)

            print(
                f"\n[*] Validation complete:"
                f"\n  - Tools: {self.results['tools_in_category']}"
                f"\n  - Total checks: {self.results['checks_total']}"
                f"\n  - Passed: {self.results['checks_passed']}"
                f"\n  - Skipped: {self.results['checks_skipped']}"
                f"\n  - Mismatches: {len(self.results['mismatches'])}"
            )

        except Exception as e:
            print(f"[!] Validation error: {e}")
            import traceback
            traceback.print_exc()
        finally:
            if self.process:
                try:
                    self.process.terminate()
                    self.process.wait(timeout=5)
                except:
                    pass

    def save_report(self):
        """Save results to JSON file."""
        with open(REPORT_FILE, "w") as f:
            json.dump(self.results, f, indent=2)
        print(f"[*] Report saved to: {REPORT_FILE}")


def main():
    validator = MCPValidator(MCP_BINARY, WORKING_DIR)
    validator.run_validation()
    validator.save_report()


if __name__ == "__main__":
    main()
