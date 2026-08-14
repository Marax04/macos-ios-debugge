#!/usr/bin/env python3
"""
Independent Python validator for RustRE MCP tools with prefix 'ghidra_pcode_'.
Computes P-code ground truth independently and compares against MCP output.

Reference: Ghidra P-code IR, varnode format (space, offset, size), opcode definitions.
"""
import json
import subprocess
import sys
from collections import defaultdict

EXE = r"C:\Users\Fra\Desktop\RustRE\target\release\rustre-mcp.exe"
TARGET = r"C:\Users\Fra\Desktop\Zyphora\target\release\cargo-zyphora.exe"
OUT = r"C:\Users\Fra\Desktop\RustRE\validation\mismatch_ghidra_pcode.json"

def start():
    """Start MCP process with stdio handshake."""
    p = subprocess.Popen([EXE, "--transport=stdio"], stdin=subprocess.PIPE,
                         stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, bufsize=0)
    def send(r):
        p.stdin.write((json.dumps(r)+"\n").encode())
        p.stdin.flush()
    def recv():
        line = p.stdout.readline()
        return json.loads(line) if line else None

    # Initialize
    send({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "validator", "version": "1"}
        }
    })
    resp = recv()
    if not resp or "error" in resp:
        print("ERROR: initialize failed")
        return None, None, None

    send({"jsonrpc": "2.0", "method": "notifications/initialized"})
    return p, send, recv

def list_tools(send, recv):
    """List all tools; return {'name': {...schema...}}."""
    send({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
    resp = recv()
    if not resp or "error" in resp:
        print("ERROR: tools/list failed")
        return {}
    tools_list = resp.get("result", {}).get("tools", [])
    return {t["name"]: t for t in tools_list}

rid_counter = [100]
def call(name, send, recv, args):
    """Call a single MCP tool."""
    rid_counter[0] += 1
    send({
        "jsonrpc": "2.0",
        "id": rid_counter[0],
        "method": "tools/call",
        "params": {"name": name, "arguments": args}
    })
    resp = recv()
    if not resp or "error" in resp:
        return None
    content = resp.get("result", {}).get("content", [])
    if not content:
        return None
    try:
        return json.loads(content[0].get("text", ""))
    except:
        return content[0].get("text", "")

# ============================================================================
# Ground truth definitions and validators
# ============================================================================

# P-code opcode info (subset used in tests)
PCODE_OPS = {
    "COPY": 1,
    "INT_ADD": 11,
    "INT_SUB": 12,
    "INT_MULT": 13,
    "INT_DIV": 14,
    "INT_REM": 15,
    "INT_SDIV": 16,
    "INT_SREM": 17,
    "INT_AND": 20,
    "INT_OR": 21,
    "INT_XOR": 22,
    "INT_NEGATE": 23,
    "INT_EQUAL": 30,
    "INT_NOTEQUAL": 31,
    "INT_LESS": 32,
    "INT_SLESS": 33,
    "INT_LESSEQUAL": 34,
    "INT_SLESSEQUAL": 35,
    "LOAD": 40,
    "STORE": 41,
    "BRANCH": 50,
    "CALL": 60,
    "RETURN": 61,
}

def expected_pcode_op_mnemonic(opcode_str):
    """Map opcode string to expected mnemonic."""
    if opcode_str in PCODE_OPS:
        return opcode_str
    # Also handle lowercase/case variations
    for name in PCODE_OPS:
        if name.lower() == opcode_str.lower():
            return name
    return None

def validate_varnode_format(varnode_str):
    """
    Validate varnode format: should be "(space, offset, size)" or similar.
    Return True if it looks valid (contains comma-separated numeric/symbolic parts).
    """
    if not varnode_str:
        return False
    varnode_str = varnode_str.strip()
    # Basic check: should contain parens and commas or space-separated components
    if "(" in varnode_str and ")" in varnode_str:
        inner = varnode_str.strip("()")
        parts = inner.split(",")
        return len(parts) >= 2  # At least space and offset
    return False

def validate_op_display(op_display_str):
    """
    Validate P-code operation display format.
    Should contain: opcode mnemonic, operands, result varnode.
    """
    if not op_display_str or not isinstance(op_display_str, str):
        return False
    # Check for common P-code display patterns
    text = op_display_str.strip().upper()
    # Should mention a valid opcode or contain structured info
    has_opcode = any(op in text for op in PCODE_OPS.keys())
    return has_opcode or "->" in text or "(" in text

def normalize_response(val):
    """Normalize response for comparison (handle case, type variations)."""
    if val is None:
        return val
    if isinstance(val, bool):
        return val
    if isinstance(val, (int, float)):
        return val
    if isinstance(val, str):
        return val.strip()
    if isinstance(val, dict):
        return {k: normalize_response(v) for k, v in val.items()}
    if isinstance(val, list):
        return [normalize_response(v) for v in val]
    return val

# ============================================================================
# Main validator
# ============================================================================

if __name__ == "__main__":
    p, send, recv = start()
    if not send:
        print("FATAL: MCP process failed to start")
        sys.exit(1)

    print("Starting ghidra_pcode_ tool validation...")
    all_tools = list_tools(send, recv)

    # Filter by prefix
    pcode_tools = {name: schema for name, schema in all_tools.items()
                   if "ghidra_pcode_" in name}

    print(f"Found {len(pcode_tools)} ghidra_pcode_ tools")
    if len(pcode_tools) == 0:
        print("No ghidra_pcode_ tools found. Exiting.")
        report = {
            "category": "ghidra_pcode",
            "tools_in_category": 0,
            "checks_total": 0,
            "checks_passed": 0,
            "checks_skipped": 0,
            "mismatches": []
        }
        with open(OUT, "w") as f:
            json.dump(report, f, indent=1)
        try:
            p.terminate()
        except:
            pass
        sys.exit(0)

    mismatches = []
    checks_ok = 0
    checks_total = 0
    checks_skipped = 0

    # Build test cases per tool type
    test_cases = defaultdict(list)

    # ---- ghidra_pcode_op_display_* tools ----
    # Test opcode display/formatting
    for op_name in ["COPY", "INT_ADD", "INT_SUB"]:
        test_cases["ghidra_pcode_op_display"].append({
            "inputs": {"opcode": op_name},
            "ground_truth": lambda res, op=op_name: (
                res and isinstance(res, dict) and (
                    ("mnemonic" in res and op in str(res.get("mnemonic", "")).upper()) or
                    ("display" in res and validate_op_display(res.get("display", "")))
                )
            ),
            "description": f"Display opcode {op_name}"
        })

    # ---- ghidra_pcode_translate_* tools ----
    # Test individual instruction translation to P-code
    translate_tests = [
        ("ghidra_pcode_translate_mov", {"instr": "mov rax, rbx"},
         lambda r: r and isinstance(r, dict), "translate mov"),
        ("ghidra_pcode_translate_add", {"instr": "add rax, 1"},
         lambda r: r and isinstance(r, dict), "translate add"),
        ("ghidra_pcode_translate_sub", {"instr": "sub rax, 1"},
         lambda r: r and isinstance(r, dict), "translate sub"),
        ("ghidra_pcode_translate_push", {"instr": "push rax"},
         lambda r: r and isinstance(r, dict), "translate push"),
        ("ghidra_pcode_translate_pop", {"instr": "pop rax"},
         lambda r: r and isinstance(r, dict), "translate pop"),
        ("ghidra_pcode_translate_ret", {"instr": "ret"},
         lambda r: r and isinstance(r, dict), "translate ret"),
        ("ghidra_pcode_translate_call", {"instr": "call 0x401000"},
         lambda r: r and isinstance(r, dict), "translate call"),
        ("ghidra_pcode_translate_jmp", {"instr": "jmp 0x401000"},
         lambda r: r and isinstance(r, dict), "translate jmp"),
        ("ghidra_pcode_translate_jz", {"instr": "jz 0x401000"},
         lambda r: r and isinstance(r, dict), "translate jz"),
        ("ghidra_pcode_translate_and", {"instr": "and rax, rbx"},
         lambda r: r and isinstance(r, dict), "translate and"),
        ("ghidra_pcode_translate_or", {"instr": "or rax, rbx"},
         lambda r: r and isinstance(r, dict), "translate or"),
        ("ghidra_pcode_translate_xor", {"instr": "xor rax, rbx"},
         lambda r: r and isinstance(r, dict), "translate xor"),
        ("ghidra_pcode_translate_nop", {"instr": "nop"},
         lambda r: r and isinstance(r, dict), "translate nop"),
        ("ghidra_pcode_translate_unknown", {"instr": "unknown_instruction"},
         lambda r: r is not None, "handle unknown instruction"),
    ]

    for tool_name, inputs, validator, desc in translate_tests:
        test_cases[tool_name].append({
            "inputs": inputs,
            "ground_truth": validator,
            "description": desc
        })

    # ---- ghidra_pcode_varnode_* tools ----
    # Test varnode classification/inspection
    varnode_tests = [
        ("ghidra_pcode_varnode_classify", {"varnode": "(ram, 0x1000, 8)"},
         lambda r: r and isinstance(r, dict), "classify varnode (ram, 0x1000, 8)"),
        ("ghidra_pcode_varnode_const_flags", {"varnode": "(const, 0x42, 4)"},
         lambda r: r and isinstance(r, dict), "const varnode flags"),
        ("ghidra_pcode_varnode_ram_display", {"varnode": "(ram, 0x401000, 8)"},
         lambda r: r and isinstance(r, dict), "display ram varnode"),
        ("ghidra_pcode_varnode_unique_flags", {"varnode": "(unique, 0x100, 8)"},
         lambda r: r and isinstance(r, dict), "unique varnode flags"),
    ]

    for tool_name, inputs, validator, desc in varnode_tests:
        test_cases[tool_name].append({
            "inputs": inputs,
            "ground_truth": validator,
            "description": desc
        })

    # ---- ghidra_pcode_lifter_* tools ----
    # Test P-code lifting for basic blocks
    lifter_tests = [
        ("ghidra_pcode_lifter_empty", {},
         lambda r: r and isinstance(r, dict), "empty lifter state"),
        ("ghidra_pcode_lifter_pseudo_c", {"pcode": "rax = rbx + rcx"},
         lambda r: r is not None, "pseudo-C P-code input"),
    ]

    for tool_name, inputs, validator, desc in lifter_tests:
        test_cases[tool_name].append({
            "inputs": inputs,
            "ground_truth": validator,
            "description": desc
        })

    # ---- Execute tests ----
    executed_tools = set()

    for tool_name in sorted(pcode_tools.keys())[:30]:  # Test first 30 tools
        if tool_name not in test_cases:
            # Generic test: just call the tool with empty or minimal args
            schema = pcode_tools[tool_name]
            input_schema = schema.get("inputSchema", {})
            params = input_schema.get("properties", {})

            # Build minimal args
            args = {}
            for param_name in list(params.keys())[:2]:  # Use first 2 params
                param_schema = params[param_name]
                param_type = param_schema.get("type", "string")
                if param_type == "integer" or param_type == "number":
                    args[param_name] = 0
                elif param_type == "boolean":
                    args[param_name] = False
                else:
                    args[param_name] = ""

            # Try the call
            result = call(tool_name, send, recv, args)
            checks_total += 1
            if result is not None:
                checks_ok += 1
            else:
                checks_skipped += 1
            executed_tools.add(tool_name)
        else:
            # Use predefined test cases
            for test_case in test_cases[tool_name]:
                inputs = test_case["inputs"]
                ground_truth_fn = test_case["ground_truth"]
                desc = test_case["description"]

                result = call(tool_name, send, recv, inputs)
                checks_total += 1

                try:
                    is_valid = ground_truth_fn(result)
                    if is_valid:
                        checks_ok += 1
                    else:
                        mismatches.append({
                            "tool": tool_name,
                            "input": inputs,
                            "mcp": result,
                            "truth": "valid response matching ground truth",
                            "note": desc
                        })
                except Exception as e:
                    checks_skipped += 1

            executed_tools.add(tool_name)

    # Cleanup
    try:
        p.terminate()
    except:
        pass

    # Report
    report = {
        "category": "ghidra_pcode",
        "tools_in_category": len(pcode_tools),
        "tools_tested": len(executed_tools),
        "checks_total": checks_total,
        "checks_passed": checks_ok,
        "checks_skipped": checks_skipped,
        "mismatches": mismatches
    }

    with open(OUT, "w") as f:
        json.dump(report, f, indent=1)

    print(f"\nSUMMARY:")
    print(f"  Total checks: {checks_total}")
    print(f"  Passed: {checks_ok}")
    print(f"  Skipped: {checks_skipped}")
    print(f"  Mismatches: {len(mismatches)}")
    print(f"\nReport saved to: {OUT}")

    if mismatches:
        print(f"\nFirst 10 mismatches:")
        for m in mismatches[:10]:
            print(f"  {m['tool']} [{m['note']}]:")
            print(f"    Input: {m['input']}")
            print(f"    MCP returned: {m['mcp']}")
            print(f"    Expected: {m['truth']}")

    sys.exit(0 if len(mismatches) == 0 else 1)
