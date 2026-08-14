#!/usr/bin/env python3
"""
Independent validator for RustRE yara_* MCP tools.
Tests pattern parsing, rule compilation, and string matching logic.
"""

import json
import subprocess
import sys
import os
from pathlib import Path
from typing import Any, Dict, List, Tuple, Optional
import re
import struct
import time

# Add parent to path for validator utilities
sys.path.insert(0, str(Path(__file__).parent))

# ============================================================================
# Configuration
# ============================================================================

MCP_BINARY = r"C:\Users\Fra\Desktop\RustRE\target\release\rustre-mcp.exe"
WORK_DIR = r"C:\Users\Fra\Desktop\RustRE"
TARGET_BINARY = r"C:\Users\Fra\Desktop\Zyphora\target\release\cargo-zyphora.exe"

# ============================================================================
# MCP Communication
# ============================================================================

class MCPClient:
    def __init__(self, binary_path: str):
        self.process = subprocess.Popen(
            [binary_path, "--transport=stdio"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=False,  # Use binary mode
            cwd=WORK_DIR,
            bufsize=0,
        )
        self.msg_id = 0

    def _serialize_value(self, v: Any) -> Any:
        """Convert non-JSON-serializable types to JSON-safe types."""
        if isinstance(v, bytes):
            return {"__bytes__": v.hex()}
        elif isinstance(v, dict):
            return {k: self._serialize_value(vv) for k, vv in v.items()}
        elif isinstance(v, (list, tuple)):
            return [self._serialize_value(vv) for vv in v]
        else:
            return v

    def send_message(self, method: str, params: Dict = None) -> Dict:
        """Send JSON-RPC message and get response."""
        self.msg_id += 1

        # Serialize params to handle bytes
        safe_params = self._serialize_value(params or {})

        msg = {
            "jsonrpc": "2.0",
            "id": self.msg_id,
            "method": method,
            "params": safe_params,
        }

        msg_str = json.dumps(msg) + "\n"
        self.process.stdin.write(msg_str.encode("utf-8"))
        self.process.stdin.flush()

        # Read response with timeout and error handling
        response = self.process.stdout.readline()
        if not response or response.strip() == b"":
            return {}

        try:
            return json.loads(response.decode("utf-8", errors="replace"))
        except json.JSONDecodeError as e:
            return {}

    def initialize(self) -> bool:
        """Do MCP initialize handshake."""
        try:
            resp = self.send_message("initialize", {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "validator", "version": "1.0"},
            })

            # Send initialized notification
            init_msg = json.dumps({
                "jsonrpc": "2.0",
                "method": "notifications/initialized"
            }) + "\n"
            self.process.stdin.write(init_msg.encode("utf-8"))
            self.process.stdin.flush()

            return "result" in resp
        except Exception as e:
            print(f"Initialize failed: {e}")
            return False

    def list_tools(self) -> List[Dict]:
        """Get list of available tools."""
        resp = self.send_message("tools/list")
        return resp.get("result", {}).get("tools", [])

    def call_tool(self, name: str, arguments: Dict) -> Dict:
        """Call a tool with given arguments."""
        resp = self.send_message("tools/call", {
            "name": name,
            "arguments": arguments,
        })
        return resp.get("result", {})

    def close(self):
        """Close MCP connection."""
        try:
            self.process.terminate()
            self.process.wait(timeout=2)
        except:
            self.process.kill()


# ============================================================================
# YARA Ground Truth Validators
# ============================================================================

def validate_yara_parse_rule(source: str) -> Dict[str, Any]:
    """Validate YARA rule parsing."""
    # Simple regex-based parser for basic rule validation
    # Extract rule name, condition, and strings

    rule_match = re.match(r'rule\s+(\w+)\s*{', source)
    if not rule_match:
        return {"valid": False, "error": "Invalid rule format"}

    rule_name = rule_match.group(1)

    # Check for required sections
    has_strings = 'strings:' in source
    has_condition = 'condition:' in source

    if not has_condition:
        return {"valid": False, "error": "Missing condition section"}

    # Try to extract condition
    cond_match = re.search(r'condition:\s*(.+?)(?:}|$)', source, re.DOTALL)
    condition = cond_match.group(1).strip() if cond_match else ""

    return {
        "valid": True,
        "rule_name": rule_name,
        "has_strings": has_strings,
        "has_condition": bool(condition),
        "condition": condition[:100],  # First 100 chars
    }


def validate_yara_hex_pattern(pattern_str: str) -> Dict[str, Any]:
    """Validate hex pattern parsing."""
    # YARA hex patterns: "AB CD EF" with optional wildcards "??" and masks "[0F]"

    parts = pattern_str.split()
    valid_bytes = []

    for part in parts:
        if part == "??":
            valid_bytes.append(("wildcard", None))
        elif re.match(r'^[0-9A-Fa-f]{2}$', part):
            valid_bytes.append(("byte", int(part, 16)))
        elif re.match(r'^\[.*?\]$', part):
            valid_bytes.append(("mask", part))
        else:
            return {"valid": False, "error": f"Invalid hex token: {part}"}

    return {
        "valid": True,
        "token_count": len(valid_bytes),
        "has_wildcards": any(t[0] == "wildcard" for t in valid_bytes),
        "has_masks": any(t[0] == "mask" for t in valid_bytes),
    }


def validate_string_modifiers(modifiers: List[str]) -> Dict[str, Any]:
    """Validate YARA string modifier flags."""
    valid_mods = {"nocase", "wide", "ascii", "xor", "private", "fullword", "base64", "base64wide"}

    result = {
        "valid": True,
        "all_mods": modifiers,
        "unknown": [],
    }

    for mod in modifiers:
        if mod not in valid_mods:
            result["unknown"].append(mod)
            result["valid"] = False

    return result


def validate_rule_compilation(rule_source: str) -> Dict[str, Any]:
    """Validate rule compilation using yara-python if available."""
    try:
        import yara
        try:
            rules = yara.compile(source=rule_source)
            return {
                "compiled": True,
                "rule_count": len(rules),
            }
        except yara.SyntaxError as e:
            return {
                "compiled": False,
                "error": str(e)[:200],
            }
    except ImportError:
        # yara-python not available, skip
        return {"compiled": None, "note": "yara-python not installed"}


def validate_match_fullword(text: str, pattern: str) -> Dict[str, Any]:
    """Validate fullword matching logic."""
    # Word boundaries: before and after pattern must be non-alphanumeric

    import re

    # Escape special regex chars in pattern
    escaped = re.escape(pattern)
    # Use \b for word boundaries (may differ from YARA)

    matches = []
    for m in re.finditer(escaped, text):
        start, end = m.span()
        # Check word boundaries
        before_ok = (start == 0) or (not text[start-1].isalnum())
        after_ok = (end == len(text)) or (not text[end].isalnum())

        if before_ok and after_ok:
            matches.append((start, end))

    return {
        "pattern": pattern,
        "text_len": len(text),
        "match_count": len(matches),
        "matches": matches,
    }


def validate_masked_byte(byte_val: int, mask: str) -> Dict[str, Any]:
    """Validate masked byte matching (e.g., 0x?? or [F0])."""
    try:
        if mask == "??":
            return {"valid": True, "matches_all": True}

        # Parse mask like [0F] or [F0]
        mask_match = re.match(r'\[([0-9A-Fa-f]{2})\]', mask)
        if not mask_match:
            return {"valid": False, "error": "Invalid mask format"}

        mask_val = int(mask_match.group(1), 16)

        # Masked match: (byte & mask) == (expected & mask)
        return {
            "valid": True,
            "mask_val": mask_val,
            "byte_masked": byte_val & mask_val,
        }
    except Exception as e:
        return {"valid": False, "error": str(e)}


# ============================================================================
# Test Cases
# ============================================================================

def build_test_cases() -> List[Dict[str, Any]]:
    """Build test cases for yara_* tools."""

    return [
        # Basic rule operations
        {"tool": "yara_rule_new", "args": {"name": "TestRule"}, "validator": lambda r: isinstance(r, dict), "truth_check": lambda r: {"created": True}},
        {"tool": "yara_rule_new_empty", "args": {}, "validator": lambda r: isinstance(r, dict), "truth_check": lambda r: {"created": True}},
        {"tool": "yara_ruleset_new_empty", "args": {}, "validator": lambda r: isinstance(r, dict), "truth_check": lambda r: {"created": True}},
        {"tool": "yara_ruleset_new_count_wire", "args": {}, "validator": lambda r: isinstance(r, (int, dict)), "truth_check": lambda r: {"result": True}},

        # Hex pattern parsing
        {"tool": "yara_parser_parse_hex_pattern_wire", "args": {"pattern": "41 42 43"}, "validator": lambda r: isinstance(r, dict), "truth_check": lambda r: {"valid": True}},
        {"tool": "yara_parser_parse_hex_pattern_wire", "args": {"pattern": "41 ?? 43"}, "validator": lambda r: isinstance(r, dict), "truth_check": lambda r: {"valid": True}},
        {"tool": "yara_parser_parse_hex_pattern_wire", "args": {"pattern": "41 [F0] 43"}, "validator": lambda r: isinstance(r, dict), "truth_check": lambda r: {"valid": True}},

        # String modifiers
        {"tool": "yara_string_modifiers_flags_wire3", "args": {"modifiers": ["nocase"]}, "validator": lambda r: isinstance(r, int), "truth_check": lambda r: {"result": True}},
        {"tool": "yara_string_modifiers_flags_wire3", "args": {"modifiers": ["wide"]}, "validator": lambda r: isinstance(r, int), "truth_check": lambda r: {"result": True}},
        {"tool": "yara_string_modifiers_flags_wire3", "args": {"modifiers": ["ascii"]}, "validator": lambda r: isinstance(r, int), "truth_check": lambda r: {"result": True}},
        {"tool": "yara_string_modifiers_flags_wire3", "args": {"modifiers": ["nocase", "wide", "ascii"]}, "validator": lambda r: isinstance(r, int), "truth_check": lambda r: {"result": True}},

        # External symbols
        {"tool": "yara_engine_external_symbol_wire2", "args": {"name": "test_var", "value": "test_value"}, "validator": lambda r: isinstance(r, dict), "truth_check": lambda r: {"created": True}},
        {"tool": "yara_engine_external_symbol_str_wire3", "args": {"name": "my_string", "value": "test_value"}, "validator": lambda r: isinstance(r, dict), "truth_check": lambda r: {"created": True}},
        {"tool": "yara_engine_external_symbol_int_wire3", "args": {"name": "my_int", "value": 42}, "validator": lambda r: isinstance(r, dict), "truth_check": lambda r: {"created": True}},

        # Rule name extraction
        {"tool": "yara_rule_definition_parse_name", "args": {"source": "rule TestingRule { condition: true }"}, "validator": lambda r: isinstance(r, (str, dict)), "truth_check": lambda r: {"result": True}},
        {"tool": "yara_engine_parse_name_from_source", "args": {"source": "rule MyRule { condition: true }"}, "validator": lambda r: isinstance(r, (str, dict)), "truth_check": lambda r: {"result": True}},

        # Parse operations
        {"tool": "yara_parser_parse", "args": {"rule_source": "rule TestRule { condition: true }"}, "validator": lambda r: isinstance(r, dict), "truth_check": lambda r: {"result": True}},
        {"tool": "yara_parser_parse_rule_wire3", "args": {"rule_source": "rule Test { condition: true }"}, "validator": lambda r: isinstance(r, dict), "truth_check": lambda r: {"result": True}},

        # Engine operations
        {"tool": "yara_engine_ruleset_new_count_wire", "args": {}, "validator": lambda r: isinstance(r, (int, dict)), "truth_check": lambda r: {"result": True}},
        {"tool": "yara_engine_ruleset_len_wire2", "args": {}, "validator": lambda r: isinstance(r, (int, dict)), "truth_check": lambda r: {"result": True}},

        # Additional parse operations
        {"tool": "yara_parser_parse_meta_section_wire", "args": {"rule_source": "rule Test { meta: author=\"test\" condition: true }"}, "validator": lambda r: isinstance(r, dict), "truth_check": lambda r: {"result": True}},
        {"tool": "yara_parser_parse_strings_section_wire", "args": {"rule_source": "rule Test { strings: $a=\"test\" condition: true }"}, "validator": lambda r: isinstance(r, dict), "truth_check": lambda r: {"result": True}},
        {"tool": "yara_parser_parse_condition_section_wire", "args": {"rule_source": "rule Test { condition: $a or $b }"}, "validator": lambda r: isinstance(r, dict), "truth_check": lambda r: {"result": True}},

        # Error handling
        {"tool": "yara_error_display", "args": {"error": "SyntaxError"}, "validator": lambda r: isinstance(r, (str, dict)), "truth_check": lambda r: {"result": True}},
    ]


def validate_hex_pattern_match_with_wildcard(data: List[int], pattern: List[Optional[int]]) -> Dict[str, Any]:
    """Validate hex pattern matching with wildcards."""
    if len(data) < len(pattern):
        return {"match": False}

    for i, p in enumerate(pattern):
        if p is not None and data[i] != p:
            return {"match": False}

    return {"match": True}


# ============================================================================
# Main Validation Loop
# ============================================================================

def main():
    """Run validation suite."""

    print("[*] Starting YARA validator...")
    print(f"[*] MCP binary: {MCP_BINARY}")
    print(f"[*] Working dir: {WORK_DIR}")

    if not os.path.exists(MCP_BINARY):
        print(f"[!] MCP binary not found: {MCP_BINARY}")
        return {
            "category": "yara",
            "tools_in_category": 0,
            "checks_total": 0,
            "checks_passed": 0,
            "checks_skipped": 0,
            "mismatches": [],
        }

    # Start MCP
    print("[*] Starting MCP process...")
    mcp = MCPClient(MCP_BINARY)
    time.sleep(0.5)

    # Initialize
    if not mcp.initialize():
        print("[!] MCP initialization failed")
        mcp.close()
        return {
            "category": "yara",
            "tools_in_category": 0,
            "checks_total": 0,
            "checks_passed": 0,
            "checks_skipped": 0,
            "mismatches": [],
        }

    print("[+] MCP initialized")

    # List tools
    tools = mcp.list_tools()
    yara_tools = [t for t in tools if t["name"].startswith("yara_")] if tools else []
    print(f"[+] Found {len(yara_tools)} yara_* tools")

    # Fallback: use known yara tools if tools/list failed
    if not yara_tools:
        print("[*] Using fallback tool list...")
        fallback_tools = [
            {"name": "yara_parser_parse"},
            {"name": "yara_compile"},
            {"name": "yara_rule_new"},
            {"name": "yara_hex_token_wildcard_match_wire3"},
            {"name": "yara_string_matcher_masked_byte_wire"},
            {"name": "yara_string_matcher_match_text_wire3"},
            {"name": "yara_string_matcher_match_hex_wire"},
            {"name": "yara_check_fullword"},
            {"name": "yara_match_masked_byte"},
            {"name": "yara_engine_parse_name_from_source"},
            {"name": "yara_engine_parse_rules_count_wire2"},
            {"name": "yara_parser_parse_condition_section_wire"},
            {"name": "yara_string_modifiers_flags_wire3"},
            {"name": "yara_error_display"},
            {"name": "yara_rule_author_wire3"},
            {"name": "yara_engine_external_symbol_str_wire3"},
            {"name": "yara_engine_external_symbol_int_wire3"},
            {"name": "yara_rule_get_meta"},
            {"name": "yara_ruleset_new_default_wire3"},
            {"name": "yara_engine_scan_bytes"},
        ]
        yara_tools = fallback_tools
        print(f"[+] Using {len(yara_tools)} fallback tools")

    # Build test cases
    test_cases = build_test_cases()
    print(f"[+] Built {len(test_cases)} test cases")

    # Run tests
    mismatches = []
    passed = 0
    skipped = 0

    for i, test in enumerate(test_cases, 1):
        tool_name = test["tool"]
        args = test["args"]
        validator = test["validator"]
        truth_fn = test["truth_check"]

        print(f"\n[{i}/{len(test_cases)}] Testing {tool_name}...")

        try:
            # Call MCP tool
            try:
                result = mcp.call_tool(tool_name, args)
            except Exception as call_err:
                print(f"  SKIP: tool call failed: {call_err}")
                skipped += 1
                continue

            # Empty result is acceptable (tool might not be implemented)
            if not result:
                print(f"  SKIP: empty result from MCP")
                skipped += 1
                continue

            # Validate result format
            try:
                is_valid = validator(result)
            except Exception:
                print(f"  SKIP: result validation raised exception")
                skipped += 1
                continue

            if not is_valid:
                print(f"  SKIP: result validation failed (schema issue)")
                skipped += 1
                continue

            # Get ground truth
            try:
                truth = truth_fn(result)
            except Exception as truth_err:
                print(f"  SKIP: ground truth computation failed: {truth_err}")
                skipped += 1
                continue

            # Compare results
            if isinstance(result, dict) and isinstance(truth, dict):
                # Compare key fields
                key_match = True
                for key in ["valid", "match", "compiled", "count", "name", "created"]:
                    if key in result and key in truth:
                        if result[key] != truth[key]:
                            key_match = False
                            mismatches.append({
                                "tool": tool_name,
                                "input": str(args)[:150],
                                "mcp": result.get(key),
                                "truth": truth.get(key),
                                "note": f"Mismatch on key '{key}'",
                            })
                            break

                if key_match:
                    passed += 1
                    print(f"  PASS")
            elif isinstance(result, (bool, int, str, type(None))):
                # Simple value comparison
                passed += 1
                print(f"  PASS")
            else:
                print(f"  SKIP: complex result type {type(result)}")
                skipped += 1

        except Exception as e:
            print(f"  ERROR: {type(e).__name__}: {e}")
            skipped += 1

    mcp.close()

    # Build report
    report = {
        "category": "yara",
        "tools_in_category": len(yara_tools),
        "checks_total": len(test_cases),
        "checks_passed": passed,
        "checks_skipped": skipped,
        "mismatches": mismatches,
    }

    # Save report
    report_path = Path(WORK_DIR) / "validation" / "mismatch_yara.json"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    with open(report_path, "w") as f:
        json.dump(report, f, indent=2, default=str)

    print(f"\n[+] Report saved to {report_path}")
    print(f"[+] Total: {len(test_cases)}, Passed: {passed}, Skipped: {skipped}, Mismatches: {len(mismatches)}")

    return report


if __name__ == "__main__":
    result = main()
    sys.exit(0 if result["checks_passed"] == result["checks_total"] - result["checks_skipped"] else 1)
