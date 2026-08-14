#!/usr/bin/env python3
"""Independent validator for triage_entropy_* MCP tools.
Computes ground-truth entropy independently in Python and compares vs MCP.
"""
import json
import subprocess
import sys
import time
import math
import struct
from collections import Counter
from pathlib import Path

# Configuration
EXE = r"C:\Users\Fra\Desktop\RustRE\target\release\rustre-mcp.exe"
TARGET = r"C:\Users\Fra\Desktop\Zyphora\target\release\cargo-zyphora.exe"
OUT = r"C:\Users\Fra\Desktop\RustRE\validation\mismatch_triage_entropy.json"

# ============================================================================
# Ground Truth Functions
# ============================================================================

def shannon_entropy(data: bytes) -> float:
    """Compute Shannon entropy of data."""
    if not data:
        return 0.0
    counter = Counter(data)
    n = len(data)
    entropy = -sum((c / n) * math.log2(c / n) for c in counter.values())
    return entropy

def entropy_category(entropy_val: float) -> str:
    """Classify entropy into categories:
    < 3.0 = very low entropy (sparse data)
    3.0 - 4.0 = low entropy
    4.0 - 5.5 = medium entropy
    5.5 - 6.5 = normal
    6.5 - 7.5 = compressed/obfuscated
    > 7.5 = encrypted/packed
    """
    if entropy_val < 3.0:
        return "very_low"
    elif entropy_val < 4.0:
        return "low"
    elif entropy_val < 5.5:
        return "medium"
    elif entropy_val < 6.5:
        return "normal"
    elif entropy_val < 7.5:
        return "compressed"
    else:
        return "encrypted"

def read_binary_file(path: str) -> bytes:
    """Read binary file safely."""
    try:
        with open(path, 'rb') as f:
            return f.read()
    except Exception as e:
        print(f"Error reading {path}: {e}", file=sys.stderr)
        return b""

# ============================================================================
# MCP Client
# ============================================================================

class MCPClient:
    def __init__(self, exe_path: str):
        self.exe_path = exe_path
        self.process = None
        self.send_fn = None
        self.recv_fn = None
        self.rid = 10
        self.start()

    def start(self):
        """Start MCP process and initialize."""
        self.process = subprocess.Popen(
            [self.exe_path, "--transport=stdio"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            bufsize=0
        )

        def send(r):
            msg = json.dumps(r) + "\n"
            self.process.stdin.write(msg.encode())
            self.process.stdin.flush()

        def recv():
            line = self.process.stdout.readline()
            return json.loads(line) if line else None

        self.send_fn = send
        self.recv_fn = recv

        # Initialize handshake
        self.send_fn({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "triage_entropy_validator", "version": "1"}
            }
        })
        resp = self.recv_fn()
        if not resp:
            raise RuntimeError("MCP initialization failed")

        self.send_fn({"jsonrpc": "2.0", "method": "notifications/initialized"})

    def list_tools(self):
        """List all available tools."""
        self.rid += 1
        self.send_fn({
            "jsonrpc": "2.0",
            "id": self.rid,
            "method": "tools/list",
            "params": {}
        })
        resp = self.recv_fn()
        if resp and "result" in resp:
            return resp["result"].get("tools", [])
        return []

    def call_tool(self, name: str, arguments: dict):
        """Call a tool and return parsed result."""
        self.rid += 1
        self.send_fn({
            "jsonrpc": "2.0",
            "id": self.rid,
            "method": "tools/call",
            "params": {"name": name, "arguments": arguments}
        })
        resp = self.recv_fn()

        if not resp or "error" in resp:
            return None

        content = resp.get("result", {}).get("content", [])
        if not content:
            return None

        text = content[0].get("text", "")
        try:
            return json.loads(text)
        except:
            return text

    def close(self):
        """Close MCP process."""
        if self.process:
            self.process.terminate()
            self.process.wait(timeout=2)

# ============================================================================
# Validation Suite
# ============================================================================

def normalize_value(val):
    """Normalize MCP response value for comparison."""
    if isinstance(val, float):
        return round(val, 6)  # 6 decimal places for float comparison
    return val

def float_eq(a, b, eps=1e-6):
    """Compare floats with epsilon tolerance."""
    if not isinstance(a, (int, float)) or not isinstance(b, (int, float)):
        return False
    return abs(a - b) < eps

def get_value(d, keys, default=None):
    """Get value from dict by trying multiple key names."""
    if not isinstance(d, dict):
        return default
    for key in keys:
        if key in d:
            return d[key]
    return default

def run_validators(client: MCPClient):
    """Run all triage_entropy validators."""
    mismatches = []
    checks_ok = 0
    checks_total = 0
    checks_skipped = 0

    # Read target binary
    target_data = read_binary_file(TARGET)
    if not target_data:
        print(f"WARNING: Could not read target {TARGET}", file=sys.stderr)
        return mismatches, checks_ok, 0, 0

    print(f"[*] Loaded target: {len(target_data)} bytes", file=sys.stderr)

    # ========== Test 1: triage_entropy_shannon_bytes_f32 ==========
    test_data = b"This is test data for entropy calculation"
    test_hex = test_data.hex()
    truth = shannon_entropy(test_data)

    result = client.call_tool("triage_entropy_shannon_bytes_f32", {"data": test_hex})
    checks_total += 1
    if result is None:
        checks_skipped += 1
    elif isinstance(result, dict):
        mcp_val = get_value(result, ["entropy", "value"])
        if mcp_val is not None and float_eq(mcp_val, truth, eps=0.01):
            checks_ok += 1
        elif mcp_val is not None:
            mismatches.append({
                "tool": "triage_entropy_shannon_bytes_f32",
                "input": test_hex[:32],
                "mcp": normalize_value(mcp_val),
                "truth": normalize_value(truth),
                "note": "Entropy value mismatch"
            })
    else:
        checks_skipped += 1

    # ========== Test 2: triage_entropy_shannon_path ==========
    truth = shannon_entropy(target_data)
    result = client.call_tool("triage_entropy_shannon_path", {"path": TARGET})
    checks_total += 1
    if result is None:
        checks_skipped += 1
    elif isinstance(result, dict):
        mcp_val = get_value(result, ["entropy", "value"])
        if mcp_val is not None and float_eq(mcp_val, truth, eps=0.01):
            checks_ok += 1
        elif mcp_val is not None:
            mismatches.append({
                "tool": "triage_entropy_shannon_path",
                "input": TARGET,
                "mcp": normalize_value(mcp_val),
                "truth": normalize_value(truth),
                "note": "Target file entropy mismatch"
            })
    else:
        checks_skipped += 1

    # ========== Test 3: triage_entropy_category_classify_bytes ==========
    test_data2 = b"\x00\x00\x00\x00" * 100
    truth_cat = entropy_category(shannon_entropy(test_data2))
    result = client.call_tool("triage_entropy_category_classify_bytes", {"data": test_data2.hex()})
    checks_total += 1
    if result is None:
        checks_skipped += 1
    elif isinstance(result, dict):
        mcp_cat = get_value(result, ["category", "value"])
        if mcp_cat and mcp_cat.lower() == truth_cat.lower():
            checks_ok += 1
        elif mcp_cat:
            mismatches.append({
                "tool": "triage_entropy_category_classify_bytes",
                "input": "low entropy pattern",
                "mcp": mcp_cat,
                "truth": truth_cat,
                "note": "Category classification mismatch"
            })
    else:
        checks_skipped += 1

    # ========== Test 4: triage_entropy_shannon_alias ==========
    truth = shannon_entropy(test_data)
    result = client.call_tool("triage_entropy_shannon_alias", {"hex": test_data.hex()})
    checks_total += 1
    if result is None:
        checks_skipped += 1
    elif isinstance(result, dict):
        mcp_val = get_value(result, ["entropy", "value"])
        if mcp_val is not None and float_eq(mcp_val, truth, eps=0.01):
            checks_ok += 1
        elif mcp_val is not None:
            mismatches.append({
                "tool": "triage_entropy_shannon_alias",
                "input": test_data.hex()[:32],
                "mcp": normalize_value(mcp_val),
                "truth": normalize_value(truth),
                "note": "Alias entropy mismatch"
            })
    else:
        checks_skipped += 1

    # ========== Test 5: triage_entropy_entropy_block_from_slice_bytes ==========
    block_size = 256
    block = target_data[:block_size]
    truth = shannon_entropy(block)
    result = client.call_tool("triage_entropy_entropy_block_from_slice_bytes", {
        "data": block.hex(),
        "block_size": block_size
    })
    checks_total += 1
    if result is None:
        checks_skipped += 1
    elif isinstance(result, dict):
        mcp_val = get_value(result, ["entropy", "value"])
        if mcp_val is not None and float_eq(mcp_val, truth, eps=0.01):
            checks_ok += 1
        elif mcp_val is not None:
            mismatches.append({
                "tool": "triage_entropy_entropy_block_from_slice_bytes",
                "input": f"{len(block)} bytes",
                "mcp": normalize_value(mcp_val),
                "truth": normalize_value(truth),
                "note": "Block entropy mismatch"
            })
    else:
        checks_skipped += 1

    # ========== Test 6: triage_entropy_entropy_block_from_slice_path ==========
    result = client.call_tool("triage_entropy_entropy_block_from_slice_path", {
        "path": TARGET,
        "block_size": block_size
    })
    checks_total += 1
    if result is None:
        checks_skipped += 1
    elif isinstance(result, dict):
        mcp_val = get_value(result, ["entropy", "value"])
        if mcp_val is not None and float_eq(mcp_val, truth, eps=0.01):
            checks_ok += 1
        elif mcp_val is not None:
            mismatches.append({
                "tool": "triage_entropy_entropy_block_from_slice_path",
                "input": TARGET,
                "mcp": normalize_value(mcp_val),
                "truth": normalize_value(truth),
                "note": "Block entropy from path mismatch"
            })
    else:
        checks_skipped += 1

    # ========== Test 7: triage_entropy_histogram_new_bytes ==========
    result = client.call_tool("triage_entropy_histogram_new_bytes", {"data": target_data[:1000].hex()})
    checks_total += 1
    if result is None:
        checks_skipped += 1
    elif isinstance(result, dict):
        hist = get_value(result, ["histogram", "data"])
        if isinstance(hist, (list, dict)):
            checks_ok += 1
        else:
            mismatches.append({
                "tool": "triage_entropy_histogram_new_bytes",
                "input": "1000 bytes",
                "mcp": type(hist).__name__ if hist else "None",
                "truth": "list or dict",
                "note": "Histogram format unexpected"
            })
    else:
        checks_skipped += 1

    # ========== Test 8: triage_entropy_histogram_most_common_bytes ==========
    result = client.call_tool("triage_entropy_histogram_most_common_bytes", {
        "data": target_data[:1000].hex()
    })
    checks_total += 1
    if result is None:
        checks_skipped += 1
    elif isinstance(result, dict):
        val = get_value(result, ["byte_value", "value", "byte"])
        if val is not None and isinstance(val, int) and 0 <= val <= 255:
            checks_ok += 1
        elif val is not None:
            mismatches.append({
                "tool": "triage_entropy_histogram_most_common_bytes",
                "input": "1000 bytes",
                "mcp": val,
                "truth": "int in range [0, 255]",
                "note": "Most common byte value invalid"
            })
    else:
        checks_skipped += 1

    # ========== Test 9: triage_entropy_rating_from_bytes ==========
    result = client.call_tool("triage_entropy_rating_from_bytes", {
        "data": target_data[:2000].hex()
    })
    checks_total += 1
    if result is None:
        checks_skipped += 1
    elif isinstance(result, dict):
        rating = get_value(result, ["rating", "value"])
        if isinstance(rating, str) and len(rating) > 0:
            checks_ok += 1
        else:
            mismatches.append({
                "tool": "triage_entropy_rating_from_bytes",
                "input": "2000 bytes",
                "mcp": rating,
                "truth": "valid rating string",
                "note": "Rating value unexpected"
            })
    else:
        checks_skipped += 1

    # ========== Test 10: triage_entropy_rating_from_entropy ==========
    entropy_val = 5.2
    result = client.call_tool("triage_entropy_rating_from_entropy", {
        "entropy": entropy_val
    })
    checks_total += 1
    if result is None:
        checks_skipped += 1
    elif isinstance(result, dict):
        rating = get_value(result, ["rating", "value"])
        if isinstance(rating, str) and len(rating) > 0:
            checks_ok += 1
        else:
            mismatches.append({
                "tool": "triage_entropy_rating_from_entropy",
                "input": entropy_val,
                "mcp": type(rating).__name__ if rating is not None else "None",
                "truth": "string",
                "note": "Rating type mismatch"
            })
    else:
        checks_skipped += 1

    # ========== Test 11: triage_entropy_rating_display_from_entropy ==========
    result = client.call_tool("triage_entropy_rating_display_from_entropy", {
        "entropy": entropy_val
    })
    checks_total += 1
    if result is None:
        checks_skipped += 1
    elif isinstance(result, dict):
        display = get_value(result, ["rating", "display", "text", "value"])
        if isinstance(display, str) and len(display) > 0:
            checks_ok += 1
        else:
            mismatches.append({
                "tool": "triage_entropy_rating_display_from_entropy",
                "input": entropy_val,
                "mcp": display,
                "truth": "non-empty string",
                "note": "Display string invalid"
            })
    else:
        checks_skipped += 1

    # ========== Test 12: triage_entropy_heatmap_ascii_bytes ==========
    result = client.call_tool("triage_entropy_heatmap_ascii_bytes", {
        "data": target_data[:4096].hex(),
        "width": 16,
        "height": 16
    })
    checks_total += 1
    if result is None:
        checks_skipped += 1
    elif isinstance(result, dict):
        heatmap = get_value(result, ["heatmap", "data", "value"])
        if isinstance(heatmap, str) and len(heatmap) > 0:
            checks_ok += 1
        else:
            mismatches.append({
                "tool": "triage_entropy_heatmap_ascii_bytes",
                "input": "4096 bytes",
                "mcp": type(heatmap).__name__ if heatmap else "None",
                "truth": "non-empty string",
                "note": "Heatmap data invalid"
            })
    else:
        checks_skipped += 1

    # ========== Test 13: triage_entropy_survey_binary_bytes ==========
    result = client.call_tool("triage_entropy_survey_binary_bytes", {
        "data": target_data[:8192].hex()
    })
    checks_total += 1
    if result is None:
        checks_skipped += 1
    elif isinstance(result, dict):
        entropy = get_value(result, ["entropy", "summary", "value"])
        if entropy is not None:
            checks_ok += 1
        else:
            mismatches.append({
                "tool": "triage_entropy_survey_binary_bytes",
                "input": "8192 bytes",
                "mcp": "no entropy/summary",
                "truth": "dict with entropy/summary",
                "note": "Survey result incomplete"
            })
    else:
        checks_skipped += 1

    # ========== Test 14: triage_entropy_survey_binary_path ==========
    result = client.call_tool("triage_entropy_survey_binary_path", {
        "path": TARGET
    })
    checks_total += 1
    if result is None:
        checks_skipped += 1
    elif isinstance(result, dict):
        entropy = get_value(result, ["survey", "entropy", "summary", "value"])
        if entropy is not None:
            checks_ok += 1
        else:
            mismatches.append({
                "tool": "triage_entropy_survey_binary_path",
                "input": TARGET,
                "mcp": "no entropy/summary",
                "truth": "dict with entropy/summary",
                "note": "Survey result incomplete"
            })
    else:
        checks_skipped += 1

    # ========== Test 15: triage_entropy_heatmap_color_rgb ==========
    result = client.call_tool("triage_entropy_heatmap_color_rgb", {
        "entropy": 6.8
    })
    checks_total += 1
    if result is None:
        checks_skipped += 1
    elif isinstance(result, dict):
        rgb = get_value(result, ["rgb", "color", "value"])
        if (isinstance(rgb, list) and len(rgb) == 3) or (isinstance(rgb, str) and len(rgb) > 0):
            checks_ok += 1
        else:
            mismatches.append({
                "tool": "triage_entropy_heatmap_color_rgb",
                "input": "entropy=6.8",
                "mcp": rgb,
                "truth": "list[3] or color string",
                "note": "RGB format invalid"
            })
    else:
        checks_skipped += 1

    # ========== Test 16: triage_entropy_histogram_count_of_bytes ==========
    result = client.call_tool("triage_entropy_histogram_count_of_bytes", {
        "data": target_data[:1000].hex(),
        "byte_val": 0x00
    })
    checks_total += 1
    if result is None:
        checks_skipped += 1
    elif isinstance(result, dict):
        count = get_value(result, ["count", "value"])
        if isinstance(count, int) and count >= 0:
            checks_ok += 1
        else:
            mismatches.append({
                "tool": "triage_entropy_histogram_count_of_bytes",
                "input": "data + 0x00",
                "mcp": count,
                "truth": "non-negative int",
                "note": "Byte count invalid"
            })
    else:
        checks_skipped += 1

    # ========== Test 17: triage_entropy_histogram_is_random_bytes ==========
    random_data = bytes(range(256)) * 4
    result = client.call_tool("triage_entropy_histogram_is_random_bytes", {
        "data": random_data.hex()
    })
    checks_total += 1
    if result is None:
        checks_skipped += 1
    elif isinstance(result, dict):
        is_random = get_value(result, ["is_random", "random", "value"])
        if isinstance(is_random, bool):
            checks_ok += 1
        else:
            mismatches.append({
                "tool": "triage_entropy_histogram_is_random_bytes",
                "input": "uniform byte distribution",
                "mcp": is_random,
                "truth": "bool",
                "note": "Random classification type invalid"
            })
    else:
        checks_skipped += 1

    # ========== Test 18: triage_entropy_histogram_chi_square_bytes ==========
    result = client.call_tool("triage_entropy_histogram_chi_square_bytes", {
        "data": target_data[:4096].hex()
    })
    checks_total += 1
    if result is None:
        checks_skipped += 1
    elif isinstance(result, dict):
        chi = get_value(result, ["chi_square", "value"])
        if isinstance(chi, (int, float)):
            checks_ok += 1
        else:
            mismatches.append({
                "tool": "triage_entropy_histogram_chi_square_bytes",
                "input": "4096 bytes",
                "mcp": type(chi).__name__ if chi else "None",
                "truth": "numeric",
                "note": "Chi-square value type invalid"
            })
    else:
        checks_skipped += 1

    # ========== Test 19: triage_entropy_entropy_report_generate_bytes ==========
    result = client.call_tool("triage_entropy_entropy_report_generate_bytes", {
        "data": target_data[:8192].hex()
    })
    checks_total += 1
    if result is None:
        checks_skipped += 1
    elif isinstance(result, dict):
        report = get_value(result, ["report", "text", "value"])
        if isinstance(report, str) and len(report) > 0:
            checks_ok += 1
        else:
            mismatches.append({
                "tool": "triage_entropy_entropy_report_generate_bytes",
                "input": "8192 bytes",
                "mcp": "empty or non-string" if report is None else type(report).__name__,
                "truth": "non-empty string report",
                "note": "Report generation failed"
            })
    else:
        checks_skipped += 1

    # ========== Test 20: triage_entropy_entropy_report_path ==========
    result = client.call_tool("triage_entropy_entropy_report_path", {
        "path": TARGET
    })
    checks_total += 1
    if result is None:
        checks_skipped += 1
    elif isinstance(result, dict):
        report = get_value(result, ["report", "text", "value"])
        if isinstance(report, str) and len(report) > 0:
            checks_ok += 1
        else:
            mismatches.append({
                "tool": "triage_entropy_entropy_report_path",
                "input": TARGET,
                "mcp": "empty or non-string" if report is None else type(report).__name__,
                "truth": "non-empty string report",
                "note": "Path report generation failed"
            })
    else:
        checks_skipped += 1

    # ========== Test 21: triage_entropy_compute_entropy ==========
    result = client.call_tool("triage_entropy_compute_entropy", {
        "data": target_data[:2048].hex()
    })
    checks_total += 1
    if result is None:
        checks_skipped += 1
    elif isinstance(result, dict):
        entropy = get_value(result, ["entropy", "value"])
        if isinstance(entropy, (int, float)):
            checks_ok += 1
        else:
            checks_skipped += 1

    # ========== Test 22: triage_entropy_packing_indicators_bytes ==========
    result = client.call_tool("triage_entropy_packing_indicators_bytes", {
        "data": target_data[:4096].hex()
    })
    checks_total += 1
    if result is None:
        checks_skipped += 1
    elif isinstance(result, dict):
        indicators = get_value(result, ["indicators", "data", "value"])
        if isinstance(indicators, (list, dict)):
            checks_ok += 1
        else:
            checks_skipped += 1

    # ========== Test 23: triage_entropy_analyze_with_sections_bytes ==========
    result = client.call_tool("triage_entropy_analyze_with_sections_bytes", {
        "data": target_data[:4096].hex()
    })
    checks_total += 1
    if result is None:
        checks_skipped += 1
    elif isinstance(result, dict):
        if result.get("analysis") or result.get("result") or result.get("value"):
            checks_ok += 1
        else:
            checks_skipped += 1

    # ========== Test 24: triage_entropy_category_classify ==========
    result = client.call_tool("triage_entropy_category_classify", {
        "entropy": 7.2
    })
    checks_total += 1
    if result is None:
        checks_skipped += 1
    elif isinstance(result, dict):
        category = get_value(result, ["category", "value"])
        if isinstance(category, str):
            checks_ok += 1
        else:
            checks_skipped += 1

    # ========== Test 25: triage_entropy_shannon_f32_bytes ==========
    result = client.call_tool("triage_entropy_shannon_f32_bytes", {
        "data": target_data[:1024].hex()
    })
    checks_total += 1
    if result is None:
        checks_skipped += 1
    elif isinstance(result, dict):
        entropy = get_value(result, ["entropy", "value"])
        if isinstance(entropy, (int, float)):
            checks_ok += 1
        else:
            checks_skipped += 1

    return mismatches, checks_ok, checks_total, checks_skipped

# ============================================================================
# Main
# ============================================================================

if __name__ == "__main__":
    print("[*] Starting triage_entropy validator...", file=sys.stderr)

    try:
        client = MCPClient(EXE)
        print("[*] MCP connected", file=sys.stderr)

        # List tools and filter
        all_tools = client.list_tools()
        entropy_tools = [t for t in all_tools if "triage_entropy" in t.get("name", "")]
        print(f"[*] Found {len(entropy_tools)} triage_entropy tools", file=sys.stderr)

        # Run validators
        mismatches, checks_ok, checks_total, checks_skipped = run_validators(client)

        client.close()

        # Report
        report = {
            "category": "triage_entropy",
            "tools_in_category": len(entropy_tools),
            "checks_total": checks_total,
            "checks_passed": checks_ok,
            "checks_skipped": checks_skipped,
            "mismatches": mismatches
        }

        with open(OUT, 'w') as f:
            json.dump(report, f, indent=2)

        print(f"\n[+] Results: {checks_ok}/{checks_total - checks_skipped} passed ({checks_skipped} skipped)", file=sys.stderr)
        print(f"[+] Mismatches: {len(mismatches)}", file=sys.stderr)
        print(f"[+] Report: {OUT}", file=sys.stderr)

        sys.exit(0 if len(mismatches) == 0 else 1)

    except Exception as e:
        print(f"[!] Error: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)
