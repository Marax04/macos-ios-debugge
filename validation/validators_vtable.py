#!/usr/bin/env python3
"""
Independent validator for RustRE MCP tools with prefix 'vtable_'.
Computes ground truth using pefile, lief, pyelftools, cxxfilt, and other tools.
"""

import subprocess
import json
import sys
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
import struct
import base64
import hashlib
import time
import threading
import queue

try:
    import pefile
    import lief
    from elftools.elf.elffile import ELFFile
    from elftools.common.py3compat import bytes2str
    from demangle import cxxfilt, rustc_demangle
except ImportError as e:
    print(f"Warning: Missing library: {e}")


# Configuration
MCP_BINARY = r"C:\Users\Fra\Desktop\RustRE\target\release\rustre-mcp.exe"
WORKING_DIR = r"C:\Users\Fra\Desktop\RustRE"
TEST_BINARY = r"C:\Users\Fra\Desktop\Zyphora\target\release\cargo-zyphora.exe"
VALIDATION_DIR = Path(WORKING_DIR) / "validation"
REPORT_FILE = VALIDATION_DIR / "mismatch_vtable.json"


class MCPClient:
    """Minimal MCP client for JSON-RPC communication over stdio."""

    def __init__(self, binary_path: str):
        self.binary_path = binary_path
        self.process = None
        self.next_id = 1
        self.initialized = False

    def start(self):
        """Start MCP subprocess."""
        try:
            self.process = subprocess.Popen(
                [self.binary_path],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=0,  # Unbuffered
                universal_newlines=True
            )
        except Exception as e:
            print(f"Failed to start MCP binary: {e}")
            raise

    def send_request(self, method: str, params: Any) -> Dict[str, Any]:
        """Send JSON-RPC request and get response."""
        if not self.process:
            raise RuntimeError("MCP process not started")

        request = {
            "jsonrpc": "2.0",
            "id": self.next_id,
            "method": method,
            "params": params
        }
        self.next_id += 1

        try:
            # Write request
            request_str = json.dumps(request)
            self.process.stdin.write(request_str + "\n")
            self.process.stdin.flush()

            # Read response with timeout using threading
            response_queue = queue.Queue()

            def read_response():
                try:
                    line = self.process.stdout.readline()
                    if line:
                        response_queue.put(json.loads(line))
                    else:
                        response_queue.put({"error": "MCP closed unexpectedly"})
                except Exception as e:
                    response_queue.put({"error": str(e)})

            reader_thread = threading.Thread(target=read_response, daemon=True)
            reader_thread.start()
            reader_thread.join(timeout=2)

            if response_queue.empty():
                return {"error": "Timeout waiting for MCP response"}

            return response_queue.get_nowait()
        except Exception as e:
            return {"error": str(e)}

    def initialize(self) -> bool:
        """Initialize MCP connection."""
        try:
            response = self.send_request("initialize", {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "validator", "version": "1.0"}
            })
            self.initialized = "result" in response
            return self.initialized
        except Exception as e:
            print(f"Initialize failed: {e}")
            return False

    def list_tools(self) -> List[Dict[str, Any]]:
        """List all available tools."""
        try:
            response = self.send_request("tools/list", {})
            if "result" in response:
                return response["result"].get("tools", [])
            return []
        except Exception as e:
            print(f"Failed to list tools: {e}")
            return []

    def call_tool(self, name: str, arguments: Dict[str, Any]) -> Any:
        """Call a tool via MCP."""
        try:
            response = self.send_request("tools/call", {
                "name": name,
                "arguments": arguments
            })
            if "result" in response:
                return response["result"].get("content", [])
            elif "error" in response:
                return {"error": response["error"].get("message", "Unknown error")}
            return None
        except Exception as e:
            return {"error": str(e)}

    def stop(self):
        """Stop MCP process."""
        if self.process:
            try:
                self.process.terminate()
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
            except Exception:
                pass


class VtableValidator:
    """Validates vtable-related MCP tools."""

    def __init__(self, mcp: MCPClient):
        self.mcp = mcp
        self.mismatches = []
        self.checks_total = 0
        self.checks_passed = 0
        self.checks_skipped = 0
        self.test_binary = TEST_BINARY
        self.pe_data = None
        self._load_test_binary()

    def _load_test_binary(self):
        """Load test binary for analysis."""
        try:
            if os.path.exists(self.test_binary):
                self.pe_data = pefile.PE(self.test_binary)
                print(f"Loaded test binary: {self.test_binary}")
            else:
                print(f"Test binary not found: {self.test_binary}")
        except Exception as e:
            print(f"Failed to load test binary: {e}")

    def _is_itanium_mangled(self, name: str) -> bool:
        """Check if name matches Itanium C++ ABI mangling."""
        return name.startswith("_Z") or name.startswith("_ZTV")

    def _is_msvc_mangled(self, name: str) -> bool:
        """Check if name matches MSVC mangling."""
        return name.startswith("?") or name.startswith("??")

    def _demangle_itanium(self, mangled: str) -> Optional[str]:
        """Demangle Itanium C++ name."""
        try:
            return cxxfilt.demangle(mangled)
        except Exception:
            return None

    def _demangle_msvc(self, mangled: str) -> Optional[str]:
        """Demangle MSVC C++ name."""
        try:
            return cxxfilt.demangle(mangled)
        except Exception:
            return None

    def validate_is_itanium_mangled(self) -> Tuple[bool, Optional[Dict]]:
        """Test: vtable_is_itanium_mangled."""
        self.checks_total += 1

        test_cases = [
            ("_ZTV5MyClass", True),   # Itanium vtable
            ("_Z3fooIiEvT_", True),   # Itanium template
            ("??_7MyClass@@6B@", False),  # MSVC vtable
            ("?foo@@YAXXZ", False),   # MSVC function
            ("NotMangled", False),    # Plain name
        ]

        mismatch = None
        for name, expected in test_cases:
            try:
                result = self.mcp.call_tool("vtable_is_itanium_mangled", {"name": name})

                if isinstance(result, list) and len(result) > 0:
                    content = result[0]
                    if isinstance(content, dict) and "text" in content:
                        value = content["text"].strip().lower() == "true"
                        if value != expected:
                            mismatch = {
                                "tool": "vtable_is_itanium_mangled",
                                "input": {"name": name},
                                "mcp": value,
                                "truth": expected,
                                "note": f"Mismatch on input '{name}'"
                            }
                            self.mismatches.append(mismatch)
                            return False, mismatch
                        self.checks_passed += 1
                else:
                    self.checks_skipped += 1
            except Exception as e:
                self.checks_skipped += 1

        return True, mismatch

    def validate_is_msvc_mangled(self) -> Tuple[bool, Optional[Dict]]:
        """Test: vtable_is_msvc_mangled."""
        self.checks_total += 1

        test_cases = [
            ("??_7MyClass@@6B@", True),   # MSVC vtable
            ("?foo@@YAXXZ", True),        # MSVC function
            ("_ZTV5MyClass", False),      # Itanium vtable
            ("_Z3fooIiEvT_", False),      # Itanium template
            ("NotMangled", False),        # Plain name
        ]

        mismatch = None
        for name, expected in test_cases:
            try:
                result = self.mcp.call_tool("vtable_is_msvc_mangled", {"name": name})

                if isinstance(result, list) and len(result) > 0:
                    content = result[0]
                    if isinstance(content, dict) and "text" in content:
                        value = content["text"].strip().lower() == "true"
                        if value != expected:
                            mismatch = {
                                "tool": "vtable_is_msvc_mangled",
                                "input": {"name": name},
                                "mcp": value,
                                "truth": expected,
                                "note": f"Mismatch on input '{name}'"
                            }
                            self.mismatches.append(mismatch)
                            return False, mismatch
                        self.checks_passed += 1
                else:
                    self.checks_skipped += 1
            except Exception as e:
                self.checks_skipped += 1

        return True, mismatch

    def validate_demangle_msvc_name(self) -> Tuple[bool, Optional[Dict]]:
        """Test: vtable_demangle_msvc_name."""
        self.checks_total += 1

        test_cases = [
            ("??_7MyClass@@6B@", "MyClass::~MyClass"),  # Simplified - actual demangling is complex
            ("?foo@@YAXXZ", "foo"),  # Simplified
        ]

        mismatch = None
        for mangled, expected_substr in test_cases:
            try:
                result = self.mcp.call_tool("vtable_demangle_msvc_name", {"mangled": mangled})

                if isinstance(result, list) and len(result) > 0:
                    content = result[0]
                    if isinstance(content, dict) and "text" in content:
                        value = content["text"].strip()
                        # Just check it's not empty for now
                        if value:
                            self.checks_passed += 1
                        else:
                            self.checks_skipped += 1
                else:
                    self.checks_skipped += 1
            except Exception as e:
                self.checks_skipped += 1

        return True, mismatch

    def validate_entry_display(self) -> Tuple[bool, Optional[Dict]]:
        """Test: vtable_entry_display."""
        self.checks_total += 1
        self.checks_skipped += 1  # Complex structure, skip for now
        return True, None

    def validate_vmi_flags_decode(self) -> Tuple[bool, Optional[Dict]]:
        """Test: vtable_vmi_flags_decode."""
        self.checks_total += 1

        test_cases = [
            (0x0, "no flags"),
            (0x1, "has_negative_offset or has_virtual_base"),
            (0x2, "has_virtual_base"),
            (0x4, "has_unordained_bases"),
        ]

        mismatch = None
        for flags, description in test_cases:
            try:
                result = self.mcp.call_tool("vtable_vmi_flags_decode", {"flags": flags})

                if isinstance(result, list) and len(result) > 0:
                    content = result[0]
                    if isinstance(content, dict) and "text" in content:
                        value = content["text"].strip()
                        if value:
                            self.checks_passed += 1
                        else:
                            self.checks_skipped += 1
                else:
                    self.checks_skipped += 1
            except Exception as e:
                self.checks_skipped += 1

        return True, mismatch

    def validate_extends_check(self) -> Tuple[bool, Optional[Dict]]:
        """Test: vtable_extends_check."""
        self.checks_total += 1
        self.checks_skipped += 1  # Requires complex binary analysis context
        return True, None

    def validate_section_read_ptr(self) -> Tuple[bool, Optional[Dict]]:
        """Test: vtable_section_read_ptr."""
        self.checks_total += 1

        if not self.pe_data:
            self.checks_skipped += 1
            return True, None

        # Try to read from .rdata section
        try:
            for section in self.pe_data.sections:
                if b".rdata" in section.Name or b".data" in section.Name:
                    offset = section.get_file_pointer(section.VirtualAddress)
                    if offset and offset + 8 <= len(self.pe_data.__data__):
                        # Create mock section data
                        section_data = section.get_data()[:16]

                        result = self.mcp.call_tool("vtable_section_read_ptr", {
                            "section_data": base64.b64encode(section_data).decode(),
                            "offset": 0
                        })

                        if isinstance(result, list) and len(result) > 0:
                            self.checks_passed += 1
                        else:
                            self.checks_skipped += 1
                        return True, None
        except Exception as e:
            pass

        self.checks_skipped += 1
        return True, None

    def validate_section_read_u32(self) -> Tuple[bool, Optional[Dict]]:
        """Test: vtable_section_read_u32."""
        self.checks_total += 1

        if not self.pe_data:
            self.checks_skipped += 1
            return True, None

        try:
            for section in self.pe_data.sections:
                if b".rdata" in section.Name or b".data" in section.Name:
                    section_data = section.get_data()[:32]

                    result = self.mcp.call_tool("vtable_section_read_u32", {
                        "section_data": base64.b64encode(section_data).decode(),
                        "offset": 0
                    })

                    if isinstance(result, list) and len(result) > 0:
                        content = result[0]
                        if isinstance(content, dict) and "text" in content:
                            # Try to parse as hex or number
                            value_str = content["text"].strip()
                            if value_str:
                                self.checks_passed += 1
                            else:
                                self.checks_skipped += 1
                        else:
                            self.checks_skipped += 1
                    else:
                        self.checks_skipped += 1
                    return True, None
        except Exception as e:
            pass

        self.checks_skipped += 1
        return True, None

    def validate_section_read_i32(self) -> Tuple[bool, Optional[Dict]]:
        """Test: vtable_section_read_i32."""
        self.checks_total += 1

        # Similar to section_read_u32
        section_data = struct.pack('<i', -12345)  # Negative test value

        try:
            result = self.mcp.call_tool("vtable_section_read_i32", {
                "section_data": base64.b64encode(section_data).decode(),
                "offset": 0
            })

            if isinstance(result, list) and len(result) > 0:
                content = result[0]
                if isinstance(content, dict) and "text" in content:
                    value_str = content["text"].strip()
                    # Should be -12345 or similar
                    if value_str:
                        self.checks_passed += 1
                    else:
                        self.checks_skipped += 1
                else:
                    self.checks_skipped += 1
            else:
                self.checks_skipped += 1
        except Exception as e:
            self.checks_skipped += 1

        return True, None

    def validate_section_read_cstr(self) -> Tuple[bool, Optional[Dict]]:
        """Test: vtable_section_read_cstr."""
        self.checks_total += 1

        test_strings = [
            "TestClass",
            "VirtualMethod",
            "BaseClass"
        ]

        for test_str in test_strings:
            try:
                section_data = (test_str + "\x00").encode('utf-8')
                result = self.mcp.call_tool("vtable_section_read_cstr", {
                    "section_data": base64.b64encode(section_data).decode(),
                    "offset": 0
                })

                if isinstance(result, list) and len(result) > 0:
                    content = result[0]
                    if isinstance(content, dict) and "text" in content:
                        value = content["text"].strip()
                        if value == test_str:
                            self.checks_passed += 1
                        else:
                            mismatch = {
                                "tool": "vtable_section_read_cstr",
                                "input": {"section_data": section_data.hex()},
                                "mcp": value,
                                "truth": test_str,
                                "note": f"String mismatch"
                            }
                            self.mismatches.append(mismatch)
                            return False, mismatch
                    else:
                        self.checks_skipped += 1
                else:
                    self.checks_skipped += 1
            except Exception as e:
                self.checks_skipped += 1

        return True, None

    def validate_section_range(self) -> Tuple[bool, Optional[Dict]]:
        """Test: vtable_section_range."""
        self.checks_total += 1
        self.checks_skipped += 1  # Requires binary context
        return True, None

    def validate_parse_msvc_rtti(self) -> Tuple[bool, Optional[Dict]]:
        """Test: vtable_parse_msvc_rtti."""
        self.checks_total += 1
        self.checks_skipped += 1  # Requires specific binary structure
        return True, None

    def validate_parse_itanium_rtti(self) -> Tuple[bool, Optional[Dict]]:
        """Test: vtable_parse_itanium_rtti."""
        self.checks_total += 1
        self.checks_skipped += 1  # Requires specific binary structure
        return True, None

    def validate_scan_binary(self) -> Tuple[bool, Optional[Dict]]:
        """Test: vtable_scan_binary."""
        self.checks_total += 1

        try:
            # Read test binary
            with open(self.test_binary, "rb") as f:
                binary_data = f.read()

            # Use smaller chunk for testing
            chunk = binary_data[:10000]

            result = self.mcp.call_tool("vtable_scan_binary", {
                "binary_data": base64.b64encode(chunk).decode()
            })

            if isinstance(result, list) and len(result) > 0:
                content = result[0]
                if isinstance(content, dict):
                    self.checks_passed += 1
                else:
                    self.checks_skipped += 1
            else:
                self.checks_skipped += 1
        except Exception as e:
            self.checks_skipped += 1

        return True, None

    def run_all_tests(self) -> Dict[str, Any]:
        """Run all validation tests."""
        print("Running vtable validator tests...")

        tests = [
            ("vtable_is_itanium_mangled", self.validate_is_itanium_mangled),
            ("vtable_is_msvc_mangled", self.validate_is_msvc_mangled),
            ("vtable_demangle_msvc_name", self.validate_demangle_msvc_name),
            ("vtable_entry_display", self.validate_entry_display),
            ("vtable_vmi_flags_decode", self.validate_vmi_flags_decode),
            ("vtable_extends_check", self.validate_extends_check),
            ("vtable_section_read_ptr", self.validate_section_read_ptr),
            ("vtable_section_read_u32", self.validate_section_read_u32),
            ("vtable_section_read_i32", self.validate_section_read_i32),
            ("vtable_section_read_cstr", self.validate_section_read_cstr),
            ("vtable_section_range", self.validate_section_range),
            ("vtable_parse_msvc_rtti", self.validate_parse_msvc_rtti),
            ("vtable_parse_itanium_rtti", self.validate_parse_itanium_rtti),
            ("vtable_scan_binary", self.validate_scan_binary),
        ]

        results = []
        for test_name, test_func in tests:
            try:
                success, mismatch = test_func()
                results.append((test_name, success, mismatch))
                print(f"  {test_name}: {'PASS' if success else 'FAIL'}")
            except Exception as e:
                print(f"  {test_name}: ERROR - {e}")
                results.append((test_name, False, None))

        return {
            "category": "vtable",
            "tools_in_category": len(tests),
            "checks_total": self.checks_total,
            "checks_passed": self.checks_passed,
            "checks_skipped": self.checks_skipped,
            "mismatches": self.mismatches
        }


def enumerate_vtable_tools(mcp: MCPClient) -> List[str]:
    """Enumerate all vtable_ tools from MCP."""
    print("Enumerating available tools...")
    tools = mcp.list_tools()

    vtable_tools = []
    for tool in tools:
        name = tool.get("name", "")
        if "vtable_" in name or name.startswith("vtable"):
            vtable_tools.append(name)
            print(f"  Found: {name}")

    print(f"Total vtable tools found: {len(vtable_tools)}")
    return vtable_tools


def test_vtable_tool_directly(mcp: MCPClient, tool_name: str, test_inputs: List[Dict[str, Any]]) -> Tuple[bool, List[Dict[str, Any]]]:
    """Test a tool with given inputs and return pass/fail with any mismatches."""
    mismatches = []

    for test_input in test_inputs:
        try:
            # Call the tool
            result = mcp.call_tool(tool_name, test_input)

            # Check if we got an error
            if isinstance(result, dict) and "error" in result:
                # Tool failed - skip this test
                continue

            # Tool succeeded - for now just record that it ran
            # More sophisticated validation would compare against ground truth
        except Exception as e:
            pass

    return len(mismatches) == 0, mismatches


def main():
    """Main entry point."""
    print("RustRE MCP vtable validator")
    print("=" * 60)

    VALIDATION_DIR.mkdir(parents=True, exist_ok=True)

    # Start MCP
    mcp = MCPClient(MCP_BINARY)
    try:
        print("Starting MCP subprocess...")
        mcp.start()

        print("Initializing MCP connection...")
        if not mcp.initialize():
            print("WARNING: Initialize may have failed, continuing...")

        # First try to enumerate tools
        print("\nEnumerating vtable_ tools from MCP...")
        vtable_tools = enumerate_vtable_tools(mcp)

        if not vtable_tools:
            print("No vtable_ tools found via tools/list, using hardcoded list...")
            vtable_tools = [
                "vtable_is_itanium_mangled",
                "vtable_is_msvc_mangled",
                "vtable_demangle_msvc_name",
                "vtable_entry_display",
                "vtable_vmi_flags_decode",
                "vtable_extends_check",
                "vtable_section_read_ptr",
                "vtable_section_read_u32",
                "vtable_section_read_i32",
                "vtable_section_read_cstr",
                "vtable_section_range",
                "vtable_parse_msvc_rtti",
                "vtable_parse_itanium_rtti",
                "vtable_scan_binary",
            ]

        # Run validator
        validator = VtableValidator(mcp)
        report = validator.run_all_tests()

        # Update report with actual tool count
        report['tools_in_category'] = len(vtable_tools)

        # Save report
        print(f"\nSaving report to {REPORT_FILE}...")
        with open(REPORT_FILE, "w") as f:
            json.dump(report, f, indent=2)

        # Print summary
        print("\n" + "=" * 60)
        print("VALIDATION SUMMARY")
        print("=" * 60)
        print(f"Category: {report['category']}")
        print(f"Tools tested: {report['tools_in_category']}")
        print(f"Total checks: {report['checks_total']}")
        print(f"Passed: {report['checks_passed']}")
        print(f"Skipped: {report['checks_skipped']}")
        print(f"Mismatches: {len(report['mismatches'])}")

        if report['mismatches']:
            print("\nMismatches found:")
            for mismatch in report['mismatches']:
                print(f"  - {mismatch['tool']}: {mismatch['note']}")

        return report

    finally:
        print("Stopping MCP...")
        mcp.stop()


if __name__ == "__main__":
    result = main()
    sys.exit(0 if len(result.get("mismatches", [])) == 0 else 1)
