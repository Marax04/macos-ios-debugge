#!/usr/bin/env python3
"""
Independent validator for RustRE MCP tools with prefix 'script_rhai_'.
Computes ground truth using standard Python libraries (hashlib, struct, etc.).
"""

import json
import subprocess
import sys
import struct
import hashlib
import binascii
from pathlib import Path
from typing import Any, Dict, List, Tuple, Optional
import logging
import math

logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

# Configuration
MCP_BINARY = Path(r"C:\Users\Fra\Desktop\RustRE\target\release\rustre-mcp.exe")
WORKING_DIR = Path(r"C:\Users\Fra\Desktop\RustRE")
TARGET_BINARY = Path(r"C:\Users\Fra\Desktop\Zyphora\target\release\cargo-zyphora.exe")
REPORT_FILE = Path(r"C:\Users\Fra\Desktop\RustRE\validation\mismatch_script_rhai.json")

# Test data
TEST_BYTES = b'\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10'
TEST_HEX = '0102030405060708090a0b0c0d0e0f10'
TEST_STRING = 'Hello, World!'


class MCPClient:
    """Minimal JSON-RPC 2.0 MCP client."""

    def __init__(self, binary_path: Path):
        self.binary_path = binary_path
        self.process = None
        self.request_id = 0

    def __enter__(self):
        self.process = subprocess.Popen(
            [str(self.binary_path), "--transport=stdio"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            cwd=WORKING_DIR,
            bufsize=0
        )
        return self

    def __exit__(self, *args):
        if self.process:
            try:
                self.process.terminate()
                self.process.wait(timeout=5)
            except:
                pass

    def _send(self, method: str, params: Dict[str, Any] = None, expect_response: bool = True):
        """Send JSON-RPC request and optionally receive response."""
        if expect_response:
            self.request_id += 1
            msg = {
                "jsonrpc": "2.0",
                "id": self.request_id,
                "method": method,
                "params": params or {}
            }
        else:
            msg = {
                "jsonrpc": "2.0",
                "method": method,
                "params": params or {}
            }

        line = json.dumps(msg) + '\n'
        self.process.stdin.write(line.encode('utf-8'))
        self.process.stdin.flush()

        if not expect_response:
            return {}

        # Read response line
        response_line = self.process.stdout.readline()
        if not response_line:
            raise RuntimeError("MCP process closed unexpectedly")

        return json.loads(response_line.decode('utf-8'))

    def initialize(self):
        """Initialize protocol handshake."""
        response = self._send('initialize', {
            'protocolVersion': '2024-11-05',
            'capabilities': {},
            'clientInfo': {'name': 'validator', 'version': '1.0'}
        })
        if 'error' in response:
            raise RuntimeError(f"Initialize failed: {response['error']}")

        # Send initialized notification (no response expected)
        self._send('notifications/initialized', expect_response=False)

        return response

    def list_tools(self) -> List[Dict[str, Any]]:
        """List available tools."""
        response = self._send('tools/list')
        if 'error' in response:
            raise RuntimeError(f"tools/list failed: {response['error']}")
        return response.get('result', {}).get('tools', [])

    def call_tool(self, name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Call a tool."""
        response = self._send('tools/call', {
            'name': name,
            'arguments': arguments
        })
        if 'error' in response:
            return {'error': response['error']}
        return response.get('result', {})


class GroundTruth:
    """Ground-truth implementations for script_rhai_ tools."""

    @staticmethod
    def hex_encode(data_hex: str) -> str:
        """Encode hex string (no-op, already hex)."""
        return data_hex.lower()

    @staticmethod
    def hex_decode(hex_str: str) -> str:
        """Decode hex string to bytes."""
        return binascii.unhexlify(hex_str).hex()

    @staticmethod
    def sha256_bytes(data_hex: str) -> str:
        """Compute SHA256 hash as hex."""
        data = binascii.unhexlify(data_hex)
        return hashlib.sha256(data).hexdigest()

    @staticmethod
    def rotate_bytes(data_hex: str, amount: int) -> str:
        """Rotate EACH BYTE left by amount bits (per tool description)."""
        data = binascii.unhexlify(data_hex)
        n = amount & 0xFF
        n_mod = n % 8
        rotated = bytes(((b << n_mod) | (b >> (8 - n_mod))) & 0xFF if n_mod else b for b in data)
        return rotated.hex()

    @staticmethod
    def xor_bytes(data_hex: str, key_int: int) -> str:
        """XOR data with key (repeating)."""
        data = binascii.unhexlify(data_hex)
        key_byte = key_int & 0xFF
        result = bytes(b ^ key_byte for b in data)
        return result.hex()

    @staticmethod
    def entropy(data_hex: str) -> float:
        """Compute Shannon entropy."""
        data = binascii.unhexlify(data_hex)
        if not data:
            return 0.0
        counts = [0] * 256
        for byte in data:
            counts[byte] += 1
        entropy_val = 0.0
        for count in counts:
            if count > 0:
                p = count / len(data)
                entropy_val -= p * math.log2(p)
        return entropy_val

    @staticmethod
    def trunc_i64_to_u32(value: int) -> int:
        """Truncate i64 to u32."""
        return (value & 0xFFFFFFFF) if value >= 0 else ((value & 0xFFFFFFFF) | 0xFFFFFFFF00000000)

    @staticmethod
    def trunc_i64_to_u8(value: int) -> int:
        """Truncate i64 to u8."""
        return value & 0xFF

    @staticmethod
    def trunc_f64_to_i64(value: float) -> int:
        """Truncate f64 to i64."""
        return int(value)

    @staticmethod
    def trunc_u128_to_u64(value_hi: int, value_lo: int) -> int:
        """Truncate u128 (hi, lo) to u64."""
        return value_lo & 0xFFFFFFFFFFFFFFFF

    @staticmethod
    def sat_i64_to_usize(value: int) -> int:
        """Saturate i64 to usize."""
        if value < 0:
            return 0
        return value if value < 2**63 else (2**63 - 1)

    @staticmethod
    def sat_u64_to_usize(value: int) -> int:
        """Saturate u64 to usize."""
        return value & 0xFFFFFFFFFFFFFFFF

    @staticmethod
    def sat_usize_to_i64(value: int) -> int:
        """Saturate usize to i64."""
        if value > 0x7FFFFFFFFFFFFFFF:
            return 0x7FFFFFFFFFFFFFFF
        return value

    @staticmethod
    def lossy_i64_to_f64(value: int) -> float:
        """Convert i64 to f64."""
        return float(value)

    @staticmethod
    def lossy_u64_to_f64(value: int) -> float:
        """Convert u64 to f64."""
        return float(value & 0xFFFFFFFFFFFFFFFF)

    @staticmethod
    def lossy_usize_to_f64(value: int) -> float:
        """Convert usize to f64."""
        return float(value)


def normalize_value(value: Any) -> Any:
    """Normalize values for comparison (hex case, type conversions, float epsilon)."""
    if isinstance(value, str):
        # Normalize hex strings to lowercase
        if all(c in '0123456789abcdefABCDEF' for c in value):
            return value.lower()
        return value
    elif isinstance(value, (list, tuple)):
        return [normalize_value(v) for v in value]
    elif isinstance(value, dict):
        return {k: normalize_value(v) for k, v in value.items()}
    elif isinstance(value, float):
        return round(value, 6)
    return value


def compare_values(actual: Any, expected: Any) -> bool:
    """Compare values with normalization."""
    actual_norm = normalize_value(actual)
    expected_norm = normalize_value(expected)

    # Float comparison with epsilon
    if isinstance(actual_norm, float) and isinstance(expected_norm, float):
        return abs(actual_norm - expected_norm) < 1e-6

    return actual_norm == expected_norm


def extract_result(mcp_result: Dict[str, Any], tool_name: str = '') -> Any:
    """Extract the actual result value from MCP response."""
    if isinstance(mcp_result, dict) and 'content' in mcp_result:
        content = mcp_result['content']
        if isinstance(content, list) and content:
            text = content[0].get('text', '')
            try:
                result_obj = json.loads(text)

                # Extract the actual value from the result object based on tool name
                if isinstance(result_obj, dict):
                    # Try to extract the specific field based on tool type
                    if 'hex_encode' in tool_name:
                        return result_obj.get('hex', result_obj)
                    elif 'hex_decode' in tool_name:
                        return result_obj.get('bytes_hex', result_obj)
                    elif 'sha256' in tool_name:
                        return result_obj.get('sha256', result_obj)
                    elif 'rotate' in tool_name:
                        return result_obj.get('out_hex', result_obj)
                    elif 'xor' in tool_name:
                        return result_obj.get('out_hex', result_obj)
                    elif 'entropy' in tool_name:
                        return result_obj.get('entropy', result_obj)
                    elif any(x in tool_name for x in ['trunc_', 'sat_', 'lossy_']):
                        return result_obj.get('result', result_obj)

                return result_obj
            except:
                return text
    return mcp_result


def run_validation():
    """Main validation loop."""

    results = {
        'category': 'script_rhai_',
        'tools_in_category': 0,
        'checks_total': 0,
        'checks_passed': 0,
        'checks_skipped': 0,
        'mismatches': []
    }

    try:
        with MCPClient(MCP_BINARY) as client:
            logger.info("Initializing MCP handshake...")
            client.initialize()
            logger.info("Connected to MCP server")

            logger.info("Listing tools...")
            all_tools = client.list_tools()
            script_rhai_tools = [t for t in all_tools if t['name'].startswith('script_rhai_')]

            logger.info(f"Found {len(script_rhai_tools)} script_rhai_ tools")
            results['tools_in_category'] = len(script_rhai_tools)

            # Define test cases per tool
            test_cases = {
                'script_rhai_hex_encode': [
                    {
                        'input': {'data_hex': TEST_HEX},
                        'compute': lambda: GroundTruth.hex_encode(TEST_HEX),
                    },
                ],
                'script_rhai_hex_decode': [
                    {
                        'input': {'hex': TEST_HEX},
                        'compute': lambda: GroundTruth.hex_decode(TEST_HEX),
                    },
                ],
                'script_rhai_sha256_bytes': [
                    {
                        'input': {'data_hex': TEST_BYTES.hex()},
                        'compute': lambda: GroundTruth.sha256_bytes(TEST_BYTES.hex()),
                    },
                ],
                'script_rhai_rotate_bytes': [
                    {
                        'input': {'data_hex': TEST_BYTES.hex(), 'n': 4, 'rol': True},
                        'compute': lambda: GroundTruth.rotate_bytes(TEST_BYTES.hex(), 4),
                    },
                    {
                        'input': {'data_hex': TEST_BYTES.hex(), 'n': 0, 'rol': True},
                        'compute': lambda: GroundTruth.rotate_bytes(TEST_BYTES.hex(), 0),
                    },
                ],
                'script_rhai_xor_bytes': [
                    {
                        'input': {'data_hex': TEST_BYTES.hex(), 'key': 0xAA},
                        'compute': lambda: GroundTruth.xor_bytes(TEST_BYTES.hex(), 0xAA),
                    },
                ],
                'script_rhai_entropy_impl': [
                    {
                        'input': {'data_hex': TEST_BYTES.hex()},
                        'compute': lambda: GroundTruth.entropy(TEST_BYTES.hex()),
                    },
                ],
                'script_rhai_trunc_i64_to_u32': [
                    {
                        'input': {'n': 0xDEADBEEF},
                        'compute': lambda: 0xDEADBEEF & 0xFFFFFFFF,
                    },
                    {
                        'input': {'n': -1},
                        'compute': lambda: 0xFFFFFFFF,
                    },
                ],
                'script_rhai_trunc_i64_to_u8': [
                    {
                        'input': {'n': 0xABCD},
                        'compute': lambda: 0xCD,
                    },
                    {
                        'input': {'n': 256},
                        'compute': lambda: 0,
                    },
                ],
                'script_rhai_trunc_f64_to_i64': [
                    {
                        'input': {'n': 42.9},
                        'compute': lambda: 42,
                    },
                    {
                        'input': {'n': -3.7},
                        'compute': lambda: -3,
                    },
                ],
                'script_rhai_trunc_u128_to_u64': [
                    # Use value < 2^53 to avoid JSON f64 precision loss.
                    {
                        'input': {'n': 0x00FFFFFFFFFF},
                        'compute': lambda: 0x00FFFFFFFFFF,
                    },
                ],
                'script_rhai_sat_i64_to_usize_wire': [
                    {
                        'input': {'n': 100},
                        'compute': lambda: 100,
                    },
                    {
                        'input': {'n': -1},
                        'compute': lambda: 0,
                    },
                ],
                'script_rhai_sat_u64_to_usize_wire': [
                    # Use value < 2^53 to avoid JSON f64 precision loss.
                    {
                        'input': {'n': 0x00FFFFFFFFFF},
                        'compute': lambda: 0x00FFFFFFFFFF,
                    },
                ],
                'script_rhai_sat_usize_to_i64': [
                    {
                        'input': {'n': 100},
                        'compute': lambda: 100,
                    },
                    {
                        'input': {'n': 0x8000000000000000},
                        'compute': lambda: 0x7FFFFFFFFFFFFFFF,
                    },
                ],
                'script_rhai_lossy_i64_to_f64': [
                    {
                        'input': {'n': 42},
                        'compute': lambda: 42.0,
                    },
                ],
                'script_rhai_lossy_u64_to_f64': [
                    {
                        'input': {'n': 100},
                        'compute': lambda: 100.0,
                    },
                ],
                'script_rhai_lossy_usize_to_f64': [
                    {
                        'input': {'n': 256},
                        'compute': lambda: 256.0,
                    },
                ],
            }

            # Process tools with test cases
            for tool_name in test_cases:
                if any(t['name'] == tool_name for t in script_rhai_tools):
                    for test_idx, test_case in enumerate(test_cases[tool_name]):
                        results['checks_total'] += 1

                        try:
                            # Compute ground truth
                            expected = test_case['compute']()

                            # Call MCP tool
                            mcp_result = client.call_tool(tool_name, test_case['input'])

                            if 'error' in mcp_result:
                                results['mismatches'].append({
                                    'tool': tool_name,
                                    'test': test_idx,
                                    'input': test_case['input'],
                                    'mcp': f"error: {mcp_result['error']}",
                                    'truth': expected,
                                    'note': 'MCP returned error'
                                })
                                continue

                            # Extract result
                            actual = extract_result(mcp_result, tool_name)

                            # Compare
                            if compare_values(actual, expected):
                                results['checks_passed'] += 1
                                logger.info(f"✓ {tool_name} test {test_idx}")
                            else:
                                results['mismatches'].append({
                                    'tool': tool_name,
                                    'test': test_idx,
                                    'input': test_case['input'],
                                    'mcp': actual,
                                    'truth': expected,
                                    'note': 'Value mismatch'
                                })
                                logger.warning(f"✗ {tool_name} test {test_idx}: got {actual}, expected {expected}")

                        except Exception as e:
                            results['mismatches'].append({
                                'tool': tool_name,
                                'test': test_idx,
                                'input': test_case['input'],
                                'mcp': None,
                                'truth': None,
                                'note': f'Exception: {str(e)}'
                            })
                            logger.error(f"✗ {tool_name} test {test_idx}: {e}")
                else:
                    results['checks_skipped'] += len(test_cases[tool_name])

    except Exception as e:
        logger.error(f"Validation failed: {e}")
        import traceback
        traceback.print_exc()
        results['mismatches'].append({
            'tool': 'GLOBAL',
            'test': 0,
            'input': None,
            'mcp': None,
            'truth': None,
            'note': f'Global error: {str(e)}'
        })

    return results


if __name__ == '__main__':
    logger.info("Starting script_rhai_ validation...")
    results = run_validation()

    # Save report
    REPORT_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(REPORT_FILE, 'w') as f:
        json.dump(results, f, indent=2, default=str)

    logger.info(f"\nValidation complete:")
    logger.info(f"  Total checks: {results['checks_total']}")
    logger.info(f"  Passed: {results['checks_passed']}")
    logger.info(f"  Skipped: {results['checks_skipped']}")
    logger.info(f"  Mismatches: {len(results['mismatches'])}")
    logger.info(f"  Report saved to {REPORT_FILE}")

    sys.exit(0 if len(results['mismatches']) == 0 else 1)
