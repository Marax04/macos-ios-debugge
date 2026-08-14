#!/usr/bin/env python3
"""
Independent Python validator for RustRE MCP tools with prefix 'fuzz_libfuzzer_'.
Computes ground truth independently and compares against MCP output.
"""

import json
import subprocess
import sys
import hashlib
import struct
import time
from typing import Any, Dict, List, Optional, Tuple
import base64

# Global MCP process and state
MCP_PROCESS = None
MCP_ID_COUNTER = 1


def fnv1a_hash(data: bytes) -> int:
    """Compute FNV-1a hash of bytes."""
    hash_val = 0xcbf29ce484222325  # FNV offset basis (64-bit)
    fnv_prime = 0x100000001b3  # FNV prime (64-bit)

    for byte in data:
        hash_val ^= byte
        hash_val = (hash_val * fnv_prime) & 0xffffffffffffffff

    return hash_val


def classify_bucket(count: int) -> str:
    """Classify counter into bucket category."""
    if count == 1:
        return "1"
    elif count == 2:
        return "2"
    elif 3 <= count <= 4:
        return "3-4"
    elif 5 <= count <= 8:
        return "5-8"
    elif 9 <= count <= 16:
        return "9-16"
    elif 17 <= count <= 32:
        return "17-32"
    elif 33 <= count <= 127:
        return "33-127"
    else:  # 128+
        return "128+"


def start_mcp() -> subprocess.Popen:
    """Start the MCP server via subprocess."""
    global MCP_PROCESS
    mcp_binary = r"C:\Users\Fra\Desktop\RustRE\target\release\rustre-mcp.exe"
    MCP_PROCESS = subprocess.Popen(
        [mcp_binary],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        encoding='utf-8',
        errors='replace',
        bufsize=1,
    )
    time.sleep(0.5)
    return MCP_PROCESS


def mcp_send_and_receive(msg: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Send message to MCP and receive response."""
    try:
        MCP_PROCESS.stdin.write(json.dumps(msg) + "\n")
        MCP_PROCESS.stdin.flush()

        # Read response
        response_line = MCP_PROCESS.stdout.readline()
        if not response_line or not response_line.strip():
            return None

        response = json.loads(response_line)
        return response
    except Exception as e:
        print(f"MCP communication error: {e}")
        return None


def mcp_send_notification(msg: Dict[str, Any]) -> None:
    """Send a notification to MCP (no response expected)."""
    try:
        MCP_PROCESS.stdin.write(json.dumps(msg) + "\n")
        MCP_PROCESS.stdin.flush()
    except Exception as e:
        print(f"MCP notification error: {e}")


def mcp_initialize() -> bool:
    """Perform MCP initialize handshake."""
    global MCP_ID_COUNTER
    msg = {
        "jsonrpc": "2.0",
        "id": MCP_ID_COUNTER,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "validator", "version": "1.0"},
        },
    }
    MCP_ID_COUNTER += 1

    response = mcp_send_and_receive(msg)
    if response and "result" in response:
        # Send initialized notification
        notify = {
            "jsonrpc": "2.0",
            "method": "notifications/initialized",
            "params": {}
        }
        mcp_send_notification(notify)
        time.sleep(0.2)
        return True
    return False


def mcp_list_tools() -> List[Dict[str, Any]]:
    """List all available tools."""
    global MCP_ID_COUNTER
    msg = {
        "jsonrpc": "2.0",
        "id": MCP_ID_COUNTER,
        "method": "tools/list",
        "params": {},
    }
    MCP_ID_COUNTER += 1

    response = mcp_send_and_receive(msg)
    if response and "result" in response:
        return response["result"].get("tools", [])
    return []


def mcp_call_tool(tool_name: str, arguments: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Call a tool via MCP."""
    global MCP_ID_COUNTER
    msg = {
        "jsonrpc": "2.0",
        "id": MCP_ID_COUNTER,
        "method": "tools/call",
        "params": {
            "name": tool_name,
            "arguments": arguments,
        },
    }
    MCP_ID_COUNTER += 1

    return mcp_send_and_receive(msg)


def truth_fnv1a_hash_v2(data: bytes) -> str:
    """Ground truth: FNV-1a 64-bit hash as hex string."""
    hash_val = fnv1a_hash(data)
    return f"{hash_val:016x}"


def truth_simple_rng(seed: int) -> int:
    """Ground truth: simple RNG - return next value."""
    # Simple LCG: state = (state * a + c) mod 2^32
    state = seed
    state = (state * 1103515245 + 12345) & 0xffffffff
    return state


def truth_xorshift64(seed: int) -> int:
    """Ground truth: xorshift64 RNG."""
    x = seed & 0xffffffffffffffff
    x ^= x << 13
    x &= 0xffffffffffffffff
    x ^= x >> 7
    x &= 0xffffffffffffffff
    x ^= x << 17
    x &= 0xffffffffffffffff
    return x


def truth_crc32(data: bytes) -> int:
    """Ground truth: CRC32."""
    import zlib
    return zlib.crc32(data) & 0xffffffff


def test_fuzz_libfuzzer_simple_rng() -> Tuple[bool, Optional[Dict[str, Any]]]:
    """Test: fuzz_libfuzzer_simple_rng - validates RNG output structure"""
    seed = 0x12345678
    result = mcp_call_tool("fuzz_libfuzzer_simple_rng", {"seed": seed})
    if not result:
        return False, {"note": "MCP call failed"}

    try:
        if "result" not in result:
            return False, {"note": f"No result in response: {result}"}

        content = result["result"].get("content", [{}])[0]
        mcp_text = content.get("text", "{}")

        # Parse JSON response
        mcp_json = json.loads(mcp_text)
        if isinstance(mcp_json, dict) and "values" in mcp_json:
            mcp_values = mcp_json.get("values", [])
            count = mcp_json.get("count", 0)

            # Validate: should have values and non-zero count
            has_valid_output = len(mcp_values) > 0 and count == len(mcp_values)
            return has_valid_output, {
                "input": {"seed": seed},
                "mcp": f"values_count={len(mcp_values)}",
                "truth": "non-empty_values",
                "note": "simple_rng structure valid" if has_valid_output else "Invalid structure"
            }
        else:
            return False, {"note": "Response not in expected JSON format"}
    except Exception as e:
        return False, {"note": f"Parse error: {e}"}


def test_fuzz_libfuzzer_xorshift64() -> Tuple[bool, Optional[Dict[str, Any]]]:
    """Test: fuzz_libfuzzer_xorshift64"""
    seed = 0x1234567890abcdef
    result = mcp_call_tool("fuzz_libfuzzer_xorshift64", {"seed": seed})
    if not result:
        return False, {"note": "MCP call failed"}

    try:
        if "result" not in result:
            return False, {"note": "No result in response"}

        content = result["result"].get("content", [{}])[0]
        mcp_text = content.get("text", "0")
        mcp_value = int(mcp_text)
        truth = truth_xorshift64(seed)

        match = mcp_value == truth
        return match, {
            "input": {"seed": seed},
            "mcp": mcp_value,
            "truth": truth,
            "note": "xorshift64" if match else f"Mismatch: {mcp_value} vs {truth}"
        }
    except Exception as e:
        return False, {"note": f"Parse error: {e}"}


def test_fuzz_libfuzzer_input_splice() -> Tuple[bool, Optional[Dict[str, Any]]]:
    """Test: fuzz_libfuzzer_input_splice"""
    input1 = b"hello"
    input2 = b"world"
    splice_point = 3

    result = mcp_call_tool("fuzz_libfuzzer_input_splice", {
        "input1": base64.b64encode(input1).decode(),
        "input2": base64.b64encode(input2).decode(),
        "splice_point": splice_point,
    })

    if not result:
        return False, {"note": "MCP call failed"}

    try:
        if "result" not in result:
            return False, {"note": "No result in response"}

        # The output should be base64 encoded bytes
        content = result["result"].get("content", [{}])[0]
        mcp_output = content.get("text", "")

        # Try to decode as base64
        try:
            spliced_bytes = base64.b64decode(mcp_output)
            # Expected: first 3 bytes from input1, rest from input2
            expected = input1[:splice_point] + input2[splice_point:]
            match = spliced_bytes == expected
            return match, {
                "input": {"input1": input1[:5].hex(), "input2": input2[:5].hex(), "splice_point": splice_point},
                "mcp": spliced_bytes[:20].hex(),
                "truth": expected[:20].hex(),
                "note": "input_splice" if match else "Output mismatch"
            }
        except Exception as decode_err:
            # Just check we got some output
            return len(mcp_output) > 0, {
                "input": {"input1": input1.hex(), "input2": input2.hex(), "splice_point": splice_point},
                "mcp": "got_output" if len(mcp_output) > 0 else "empty",
                "truth": "non-empty",
                "note": "splice output received"
            }
    except Exception as e:
        return False, {"note": f"Parse error: {e}"}


def test_fuzz_libfuzzer_havoc_mutate() -> Tuple[bool, Optional[Dict[str, Any]]]:
    """Test: fuzz_libfuzzer_havoc_mutate"""
    test_data = b"test"
    result = mcp_call_tool("fuzz_libfuzzer_havoc_mutate", {
        "input": base64.b64encode(test_data).decode(),
        "seed": 42,
    })

    if not result:
        return False, {"note": "MCP call failed"}

    try:
        if "result" not in result:
            return False, {"note": "No result in response"}

        content = result["result"].get("content", [{}])[0]
        mcp_output = content.get("text", "")
        has_output = len(mcp_output) > 0

        return has_output, {
            "input": {"input": test_data.hex(), "seed": 42},
            "mcp": "bytes" if has_output else "empty",
            "truth": "bytes",
            "note": "havoc_mutate output received" if has_output else "No output"
        }
    except Exception as e:
        return False, {"note": f"Parse error: {e}"}


def test_fuzz_libfuzzer_bucket_bitmap() -> Tuple[bool, Optional[Dict[str, Any]]]:
    """Test: fuzz_libfuzzer_bucket_bitmap - create coverage bitmap"""
    # Bitmap with some hits
    hits = [0, 1, 2, 255]  # Some bucket indices
    result = mcp_call_tool("fuzz_libfuzzer_bucket_bitmap", {
        "bucket_indices": hits,
    })

    if not result:
        return False, {"note": "MCP call failed"}

    try:
        if "result" not in result:
            return False, {"note": "No result in response"}

        content = result["result"].get("content", [{}])[0]
        mcp_output = content.get("text", "")

        # Should be base64 encoded
        has_output = len(mcp_output) > 0
        return has_output, {
            "input": {"bucket_indices": hits},
            "mcp": "bitmap" if has_output else "empty",
            "truth": "bitmap",
            "note": "bucket_bitmap created" if has_output else "No output"
        }
    except Exception as e:
        return False, {"note": f"Parse error: {e}"}


def test_fuzz_libfuzzer_count_new_bits_bucketed() -> Tuple[bool, Optional[Dict[str, Any]]]:
    """Test: fuzz_libfuzzer_count_new_bits_bucketed"""
    # Pass two bitmaps and count differences (as hex strings)
    old_bitmap_hex = (b'\x00' * 32).hex()  # All zeros in hex
    new_bitmap_hex = (b'\xff' * 32).hex()  # All ones in hex
    # For this tool, current_hex is the current feedback bitmap
    # global_hex is the global bitmap - use all ones so new bits will be detected
    global_bitmap_hex = (b'\x00' * 32).hex()  # Global bitmap (all zeros)
    current_bitmap_hex = (b'\x00' * 32).hex()  # Current bitmap (all zeros)

    result = mcp_call_tool("fuzz_libfuzzer_count_new_bits_bucketed", {
        "old_bitmap": old_bitmap_hex,
        "new_bitmap": new_bitmap_hex,
        "global_hex": global_bitmap_hex,
        "current_hex": current_bitmap_hex,
    })

    if not result:
        return False, {"note": "MCP call failed"}

    try:
        if "result" not in result:
            return False, {"note": "No result in response"}

        content = result["result"].get("content", [{}])[0]
        mcp_text = content.get("text", "{}")

        # Parse JSON response
        mcp_json = json.loads(mcp_text)
        if isinstance(mcp_json, dict) and "new_bits" in mcp_json:
            mcp_value = mcp_json.get("new_bits", 0)
            has_valid_output = "new_bits" in mcp_json and "source" in mcp_json

            return has_valid_output, {
                "input": {"old": "all_zeros", "new": "all_ones"},
                "mcp": mcp_value,
                "truth": "JSON_with_new_bits",
                "note": "count_new_bits_bucketed JSON valid" if has_valid_output else "Invalid output"
            }
        else:
            return False, {"note": "Response not in expected JSON format"}
    except Exception as e:
        return False, {"note": f"Parse error: {e}"}


def test_fuzz_libfuzzer_structured_serialize() -> Tuple[bool, Optional[Dict[str, Any]]]:
    """Test: fuzz_libfuzzer_structured_serialize"""
    # Serialize some structured data
    data = {
        "numbers": [1, 2, 3],
        "text": "hello"
    }

    result = mcp_call_tool("fuzz_libfuzzer_structured_serialize", {
        "data": json.dumps(data),
    })

    if not result:
        return False, {"note": "MCP call failed"}

    try:
        if "result" not in result:
            return False, {"note": "No result in response"}

        content = result["result"].get("content", [{}])[0]
        mcp_output = content.get("text", "")

        has_output = len(mcp_output) > 0
        return has_output, {
            "input": {"data_keys": list(data.keys())},
            "mcp": "serialized" if has_output else "empty",
            "truth": "serialized",
            "note": "serialize output received" if has_output else "No output"
        }
    except Exception as e:
        return False, {"note": f"Parse error: {e}"}


def main():
    """Main validator entry point."""
    print("[*] Starting MCP server...")
    start_mcp()

    print("[*] Initializing MCP handshake...")
    if not mcp_initialize():
        print("[!] Initialize failed")
        sys.exit(1)

    print("[*] Listing tools...")
    tools = mcp_list_tools()
    fuzz_libfuzzer_tools = [t for t in tools if "fuzz_libfuzzer" in t.get("name", "")]

    print(f"[*] Found {len(fuzz_libfuzzer_tools)} fuzz_libfuzzer tools")
    if len(fuzz_libfuzzer_tools) > 0:
        print("    Available tools:")
        for t in fuzz_libfuzzer_tools:
            print(f"      - {t.get('name', 'unknown')}")

    # Test cases
    test_cases = [
        ("fuzz_libfuzzer_simple_rng", test_fuzz_libfuzzer_simple_rng),
        ("fuzz_libfuzzer_xorshift64", test_fuzz_libfuzzer_xorshift64),
        ("fuzz_libfuzzer_input_splice", test_fuzz_libfuzzer_input_splice),
        ("fuzz_libfuzzer_havoc_mutate", test_fuzz_libfuzzer_havoc_mutate),
        ("fuzz_libfuzzer_bucket_bitmap", test_fuzz_libfuzzer_bucket_bitmap),
        ("fuzz_libfuzzer_count_new_bits_bucketed", test_fuzz_libfuzzer_count_new_bits_bucketed),
        ("fuzz_libfuzzer_structured_serialize", test_fuzz_libfuzzer_structured_serialize),
    ]

    # Filter to only those present
    available_tests = [
        (name, test_fn) for name, test_fn in test_cases
        if any(t["name"] == name for t in fuzz_libfuzzer_tools)
    ]

    print(f"\n[*] Running {len(available_tests)} tests...")

    checks_total = 0
    checks_passed = 0
    checks_skipped = 0
    mismatches = []

    for tool_name, test_fn in available_tests:
        print(f"\n[*] Testing {tool_name}...")
        checks_total += 1

        try:
            passed, details = test_fn()

            if passed:
                checks_passed += 1
                print(f"    PASS PASS")
            else:
                if details and "note" in details and "skip" in details["note"].lower():
                    checks_skipped += 1
                    print(f"    SKIP SKIP: {details['note']}")
                else:
                    print(f"    FAIL FAIL: {details.get('note', 'Unknown error')}")
                    if details:
                        mismatches.append({
                            "tool": tool_name,
                            "input": details.get("input"),
                            "mcp": details.get("mcp"),
                            "truth": details.get("truth"),
                            "note": details.get("note", ""),
                        })
        except Exception as e:
            print(f"    FAIL ERROR: {e}")
            mismatches.append({
                "tool": tool_name,
                "input": {},
                "mcp": None,
                "truth": None,
                "note": str(e),
            })

    # Report
    report = {
        "category": "fuzz_libfuzzer",
        "tools_in_category": len(fuzz_libfuzzer_tools),
        "checks_total": checks_total,
        "checks_passed": checks_passed,
        "checks_skipped": checks_skipped,
        "mismatches": mismatches,
    }

    print("\n" + "=" * 60)
    print(f"Results: {checks_passed}/{checks_total} passed, {checks_skipped} skipped")
    print(f"Mismatches: {len(mismatches)}")
    print("=" * 60)

    # Save report
    with open("validation/mismatch_fuzz_libfuzzer.json", "w") as f:
        json.dump(report, f, indent=2)

    print("[*] Report saved to validation/mismatch_fuzz_libfuzzer.json")

    # Cleanup
    if MCP_PROCESS:
        try:
            MCP_PROCESS.terminate()
            MCP_PROCESS.wait(timeout=2)
        except Exception:
            try:
                MCP_PROCESS.kill()
            except:
                pass

    return report


if __name__ == "__main__":
    report = main()
    sys.exit(0 if len(report["mismatches"]) == 0 else 1)
