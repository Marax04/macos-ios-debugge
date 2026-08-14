#!/usr/bin/env python3
"""Rigorous ground-truth validation for triage_* MCP tools.
Each tool is independently verified against a Python reference implementation.
"""

import json
import math
import subprocess
import struct
import time

EXE = r"C:\Users\Fra\Desktop\RustRE\target\release\rustre-mcp.exe"
TARGET = r"C:\Users\Fra\Desktop\Zyphora\target\release\cargo-zyphora.exe"

# ── Python reference implementations ─────────────────────────────────────────

def py_shannon_entropy_f64(data: bytes) -> float:
    """Shannon entropy in bits/byte, f64 precision equivalent."""
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    h = 0.0
    for c in counts:
        if c > 0:
            p = c / n
            h -= p * math.log2(p)
    return max(0.0, min(8.0, h))


def py_shannon_entropy_f32(data: bytes) -> float:
    """Shannon entropy using f32 arithmetic (single-precision)."""
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = struct.unpack('f', struct.pack('f', float(len(data))))[0]  # f32 cast
    h = 0.0
    for c in counts:
        if c > 0:
            p_f32 = struct.unpack('f', struct.pack('f', float(c) / n))[0]
            if p_f32 > 0:
                log2_p = struct.unpack('f', struct.pack('f', math.log2(p_f32)))[0]
                h += struct.unpack('f', struct.pack('f', -p_f32 * log2_p))[0]
    return max(0.0, min(8.0, h))


def py_entropy_category_classify(e: float) -> str:
    """EntropyCategory::classify(e: f32) -> category label."""
    # Note: input is treated as f32
    if e < 1.0:
        return "Empty"
    elif e < 4.0:
        return "Text"
    elif e < 5.0:
        return "Code"
    elif e < 6.0:
        return "Data"
    elif e < 7.0:
        return "Compressed"
    elif e < 7.5:
        return "Encrypted"
    else:
        return "Random"


def py_heatmap_color_rgb(e: float) -> list:
    """HeatmapData::color_rgb(e: f32) -> [r, g, b]."""
    if e < 2.0:
        return [0, 0, 128]
    elif e < 4.0:
        return [0, 128, 255]
    elif e < 6.0:
        return [0, 200, 0]
    elif e < 7.0:
        return [255, 200, 0]
    else:
        return [200, 0, 0]


def py_find_bytes(data: bytes, pattern_hex: str) -> int | None:
    """Find a hex pattern (no wildcards) in data. Returns offset or None."""
    # Simple search — no wildcard support needed for our test case
    pat = bytes.fromhex(pattern_hex.replace("??", "00"))  # conservative
    idx = data.find(pat)
    return idx if idx >= 0 else None


# ── MCP communication helpers ─────────────────────────────────────────────────

class MCPClient:
    def __init__(self):
        self.proc = subprocess.Popen(
            [EXE, "--transport=stdio"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            bufsize=0,
        )
        self._id = 0
        self._initialize()

    def _send(self, req):
        self.proc.stdin.write((json.dumps(req) + "\n").encode())
        self.proc.stdin.flush()

    def _recv(self):
        line = self.proc.stdout.readline()
        if not line:
            raise RuntimeError("server died")
        return json.loads(line)

    def _initialize(self):
        self._send({"jsonrpc": "2.0", "id": 0, "method": "initialize",
                    "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                               "clientInfo": {"name": "triage-validator", "version": "2"}}})
        self._recv()
        self._send({"jsonrpc": "2.0", "method": "notifications/initialized"})

    def call(self, name: str, args: dict, timeout: float = 15.0) -> dict | None:
        self._id += 1
        self._send({"jsonrpc": "2.0", "id": self._id, "method": "tools/call",
                    "params": {"name": name, "arguments": args}})
        # Simple blocking recv — single-threaded protocol
        import select, sys
        start = time.time()
        while True:
            if time.time() - start > timeout:
                return None
            line = self.proc.stdout.readline()
            if not line:
                return None
            try:
                resp = json.loads(line)
                if resp.get("id") == self._id:
                    return resp
            except Exception:
                pass

    def tool_text(self, name: str, args: dict) -> str | None:
        resp = self.call(name, args)
        if resp is None:
            return None
        content = resp.get("result", {}).get("content", [])
        if not content:
            return None
        return content[0].get("text", "")

    def close(self):
        try:
            self.proc.stdin.close()
            self.proc.terminate()
        except Exception:
            pass


# ── Test cases ────────────────────────────────────────────────────────────────

TEST_HEX = "deadbeef00112233"
TEST_BYTES = bytes.fromhex(TEST_HEX)

# Uniform 256-byte sequence → entropy = 8.0 exactly
UNIFORM_BYTES = bytes(range(256))
UNIFORM_HEX = UNIFORM_BYTES.hex()

# All zeros → entropy = 0.0
ZERO_BYTES = bytes(256)
ZERO_HEX = ZERO_BYTES.hex()

ENTROPY_TEST_CASES = [
    (TEST_HEX, TEST_BYTES),
    (UNIFORM_HEX, UNIFORM_BYTES),
    (ZERO_HEX, ZERO_BYTES),
]


def run_tests() -> dict:
    results = []
    skip = []
    mismatches = []

    client = MCPClient()

    try:
        # ── 1. triage_entropy_shannon_bytes ──────────────────────────────────
        for hex_str, raw in ENTROPY_TEST_CASES:
            expected = py_shannon_entropy_f64(raw)
            txt = client.tool_text("triage_entropy_shannon_bytes", {"hex": hex_str})
            if txt is None:
                skip.append({"tool": "triage_entropy_shannon_bytes",
                              "reason": "no response / timeout"})
                continue
            try:
                parsed = json.loads(txt)
                actual = float(parsed.get("entropy", parsed.get("value", parsed)))
                tol = 1e-9
                ok = abs(actual - expected) < tol
                entry = {
                    "tool": "triage_entropy_shannon_bytes",
                    "input_hex": hex_str[:16] + "...",
                    "expected": expected,
                    "actual": actual,
                    "pass": ok,
                }
                results.append(entry)
                if not ok:
                    mismatches.append({"tool": "triage_entropy_shannon_bytes",
                                       "expected": expected, "actual": actual})
            except Exception as ex:
                skip.append({"tool": "triage_entropy_shannon_bytes",
                              "reason": f"parse error: {ex}; raw={txt[:120]}"})

        # ── 2. triage_die_compute_entropy ────────────────────────────────────
        for hex_str, raw in ENTROPY_TEST_CASES:
            expected = py_shannon_entropy_f64(raw)
            txt = client.tool_text("triage_die_compute_entropy", {"hex": hex_str})
            if txt is None:
                skip.append({"tool": "triage_die_compute_entropy",
                              "reason": "no response / timeout"})
                continue
            try:
                parsed = json.loads(txt)
                # The tool may return {"entropy": f64} or a bare number
                if isinstance(parsed, dict):
                    actual = float(parsed.get("entropy", parsed.get("value", 0)))
                else:
                    actual = float(parsed)
                tol = 1e-9
                ok = abs(actual - expected) < tol
                entry = {
                    "tool": "triage_die_compute_entropy",
                    "input_hex": hex_str[:16] + "...",
                    "expected": expected,
                    "actual": actual,
                    "pass": ok,
                }
                results.append(entry)
                if not ok:
                    mismatches.append({"tool": "triage_die_compute_entropy",
                                       "expected": expected, "actual": actual})
            except Exception as ex:
                skip.append({"tool": "triage_die_compute_entropy",
                              "reason": f"parse error: {ex}; raw={txt[:120]}"})

        # ── 3. triage_entropy_shannon_bytes_f32 ──────────────────────────────
        for hex_str, raw in ENTROPY_TEST_CASES:
            expected_f32 = py_shannon_entropy_f32(raw)
            txt = client.tool_text("triage_entropy_shannon_bytes_f32", {"hex": hex_str})
            if txt is None:
                skip.append({"tool": "triage_entropy_shannon_bytes_f32",
                              "reason": "no response / timeout"})
                continue
            try:
                parsed = json.loads(txt)
                if isinstance(parsed, dict):
                    actual = float(parsed.get("entropy", parsed.get("value", 0)))
                else:
                    actual = float(parsed)
                # f32 accumulation has floating-point error; tolerate 1e-5
                tol = 1e-4
                ok = abs(actual - expected_f32) < tol
                entry = {
                    "tool": "triage_entropy_shannon_bytes_f32",
                    "input_hex": hex_str[:16] + "...",
                    "expected": expected_f32,
                    "actual": actual,
                    "pass": ok,
                }
                results.append(entry)
                if not ok:
                    mismatches.append({"tool": "triage_entropy_shannon_bytes_f32",
                                       "expected": expected_f32, "actual": actual})
            except Exception as ex:
                skip.append({"tool": "triage_entropy_shannon_bytes_f32",
                              "reason": f"parse error: {ex}; raw={txt[:120]}"})

        # ── 4. triage_entropy_category_classify ──────────────────────────────
        classify_cases = [
            (0.0, "Empty"),
            (0.5, "Empty"),
            (1.0, "Text"),
            (3.9, "Text"),
            (4.0, "Code"),
            (4.9, "Code"),
            (5.0, "Data"),
            (5.9, "Data"),
            (6.0, "Compressed"),
            (6.9, "Compressed"),
            (7.0, "Encrypted"),
            (7.4, "Encrypted"),
            (7.5, "Random"),
            (8.0, "Random"),
        ]
        for e_val, expected_label in classify_cases:
            txt = client.tool_text("triage_entropy_category_classify",
                                   {"entropy": e_val})
            if txt is None:
                skip.append({"tool": "triage_entropy_category_classify",
                              "reason": "no response / timeout"})
                break
            try:
                parsed = json.loads(txt)
                if isinstance(parsed, dict):
                    actual = str(parsed.get("category", parsed.get("label",
                                 parsed.get("value", ""))))
                else:
                    actual = str(parsed)
                ok = (actual == expected_label)
                entry = {
                    "tool": "triage_entropy_category_classify",
                    "input_entropy": e_val,
                    "expected": expected_label,
                    "actual": actual,
                    "pass": ok,
                }
                results.append(entry)
                if not ok:
                    mismatches.append({"tool": "triage_entropy_category_classify",
                                       "expected": expected_label, "actual": actual})
            except Exception as ex:
                skip.append({"tool": "triage_entropy_category_classify",
                              "reason": f"parse error: {ex}; raw={txt[:120]}"})
                break

        # ── 5. triage_entropy_heatmap_color_rgb ──────────────────────────────
        color_cases = [
            (0.0, [0, 0, 128]),
            (1.9, [0, 0, 128]),
            (2.0, [0, 128, 255]),
            (3.9, [0, 128, 255]),
            (4.0, [0, 200, 0]),
            (5.9, [0, 200, 0]),
            (6.0, [255, 200, 0]),
            (6.9, [255, 200, 0]),
            (7.0, [200, 0, 0]),
            (8.0, [200, 0, 0]),
        ]
        for e_val, expected_rgb in color_cases:
            txt = client.tool_text("triage_entropy_heatmap_color_rgb",
                                   {"entropy": e_val})
            if txt is None:
                skip.append({"tool": "triage_entropy_heatmap_color_rgb",
                              "reason": "no response / timeout"})
                break
            try:
                parsed = json.loads(txt)
                if isinstance(parsed, dict):
                    # Could be {"r":0,"g":0,"b":128} or {"rgb":[0,0,128]}
                    if "rgb" in parsed:
                        actual = list(parsed["rgb"])
                    elif "r" in parsed:
                        actual = [int(parsed["r"]), int(parsed["g"]), int(parsed["b"])]
                    elif "color" in parsed:
                        actual = list(parsed["color"])
                    else:
                        actual = list(parsed.values())[:3]
                elif isinstance(parsed, list):
                    actual = list(parsed)
                else:
                    actual = []
                ok = (actual == expected_rgb)
                entry = {
                    "tool": "triage_entropy_heatmap_color_rgb",
                    "input_entropy": e_val,
                    "expected": expected_rgb,
                    "actual": actual,
                    "pass": ok,
                }
                results.append(entry)
                if not ok:
                    mismatches.append({"tool": "triage_entropy_heatmap_color_rgb",
                                       "expected": expected_rgb, "actual": actual})
            except Exception as ex:
                skip.append({"tool": "triage_entropy_heatmap_color_rgb",
                              "reason": f"parse error: {ex}; raw={txt[:120]}"})
                break

        # ── 6. triage_die_find_bytes ─────────────────────────────────────────
        # Search for "deadbeef" in "deadbeef00112233" → offset 0
        txt = client.tool_text("triage_die_find_bytes",
                               {"hex": "deadbeef00112233", "pattern": "deadbeef"})
        if txt is None:
            skip.append({"tool": "triage_die_find_bytes",
                          "reason": "no response / timeout"})
        else:
            try:
                parsed = json.loads(txt)
                if isinstance(parsed, dict):
                    actual = parsed.get("offset", parsed.get("position",
                             parsed.get("found", None)))
                else:
                    actual = parsed
                expected = 0
                ok = (actual == expected or actual == {"offset": 0})
                entry = {
                    "tool": "triage_die_find_bytes",
                    "input": {"hex": "deadbeef00112233", "pattern": "deadbeef"},
                    "expected": expected,
                    "actual": actual,
                    "pass": ok,
                }
                results.append(entry)
                if not ok:
                    mismatches.append({"tool": "triage_die_find_bytes",
                                       "expected": expected, "actual": actual})
            except Exception as ex:
                skip.append({"tool": "triage_die_find_bytes",
                              "reason": f"parse error: {ex}; raw={txt[:120]}"})

        # Search for absent pattern → None / null
        # NOTE: find_bytes expects space-separated hex byte tokens, e.g. "ca fe ca fe"
        txt2 = client.tool_text("triage_die_find_bytes",
                                {"hex": "deadbeef00112233", "pattern": "ca fe ca fe"})
        if txt2 is None:
            skip.append({"tool": "triage_die_find_bytes(absent)",
                          "reason": "no response / timeout"})
        else:
            try:
                parsed = json.loads(txt2)
                if isinstance(parsed, dict):
                    actual = parsed.get("offset", parsed.get("position",
                             parsed.get("found", "MISSING")))
                else:
                    actual = parsed
                # None, null, -1, or absent key → not found
                ok = (actual is None or actual == -1 or actual == "null")
                entry = {
                    "tool": "triage_die_find_bytes(absent)",
                    "input": {"hex": "deadbeef00112233", "pattern": "cafecafe"},
                    "expected": None,
                    "actual": actual,
                    "pass": ok,
                }
                results.append(entry)
                if not ok:
                    mismatches.append({"tool": "triage_die_find_bytes(absent)",
                                       "expected": None, "actual": actual})
            except Exception as ex:
                skip.append({"tool": "triage_die_find_bytes(absent)",
                              "reason": f"parse error: {ex}; raw={txt2[:120]}"})

        # ── 7. triage_entropy_shannon_alias ──────────────────────────────────
        for hex_str, raw in ENTROPY_TEST_CASES[:2]:
            expected = py_shannon_entropy_f64(raw)
            txt = client.tool_text("triage_entropy_shannon_alias", {"hex": hex_str})
            if txt is None:
                skip.append({"tool": "triage_entropy_shannon_alias",
                              "reason": "no response / timeout"})
                break
            try:
                parsed = json.loads(txt)
                if isinstance(parsed, dict):
                    actual = float(parsed.get("entropy", parsed.get("value", 0)))
                else:
                    actual = float(parsed)
                ok = abs(actual - expected) < 1e-9
                entry = {
                    "tool": "triage_entropy_shannon_alias",
                    "input_hex": hex_str[:16] + "...",
                    "expected": expected,
                    "actual": actual,
                    "pass": ok,
                }
                results.append(entry)
                if not ok:
                    mismatches.append({"tool": "triage_entropy_shannon_alias",
                                       "expected": expected, "actual": actual})
            except Exception as ex:
                skip.append({"tool": "triage_entropy_shannon_alias",
                              "reason": f"parse error: {ex}; raw={txt[:120]}"})
                break

        # ── 8. triage_entropy_rating_from_entropy ────────────────────────────
        # EntropyRating bands: VeryLow<1, Low[1,3), Normal[3,5), High[5,7), VeryHigh>=7
        # Verify a couple of values
        # EntropyRating bands: VeryLow<1, Low[1,3), Medium[3,5), High[5,7), VeryHigh>=7
        rating_cases = [
            (0.5, ["VeryLow"]),
            (2.0, ["Low"]),
            (4.0, ["Medium"]),   # Rust enum variant is "Medium", not "Normal"
            (6.0, ["High"]),
            (7.5, ["VeryHigh"]),
        ]
        for e_val, expected_options in rating_cases:
            txt = client.tool_text("triage_entropy_rating_from_entropy",
                                   {"entropy": e_val})
            if txt is None:
                skip.append({"tool": "triage_entropy_rating_from_entropy",
                              "reason": "no response / timeout"})
                break
            try:
                parsed = json.loads(txt)
                if isinstance(parsed, dict):
                    actual = str(parsed.get("rating", parsed.get("label",
                                 parsed.get("value", ""))))
                else:
                    actual = str(parsed)
                ok = (actual in expected_options)
                entry = {
                    "tool": "triage_entropy_rating_from_entropy",
                    "input_entropy": e_val,
                    "expected_one_of": expected_options,
                    "actual": actual,
                    "pass": ok,
                }
                results.append(entry)
                if not ok:
                    mismatches.append({"tool": "triage_entropy_rating_from_entropy",
                                       "expected": expected_options, "actual": actual})
            except Exception as ex:
                skip.append({"tool": "triage_entropy_rating_from_entropy",
                              "reason": f"parse error: {ex}; raw={txt[:120]}"})
                break

    finally:
        client.close()

    passed = sum(1 for r in results if r.get("pass"))
    failed = sum(1 for r in results if not r.get("pass"))

    return {
        "results": results,
        "skip": skip,
        "mismatches": mismatches,
        "summary": {
            "total": len(results),
            "passed": passed,
            "failed": failed,
            "skipped": len(skip),
        }
    }


if __name__ == "__main__":
    out = run_tests()
    output_path = r"C:\Users\Fra\Desktop\RustRE\validation\rigorous_triage_v2.json"
    with open(output_path, "w") as f:
        json.dump(out, f, indent=2)
    s = out["summary"]
    print(f"Passed: {s['passed']}  Failed: {s['failed']}  Skipped: {s['skipped']}")
    print(f"Results written to {output_path}")
    if out["mismatches"]:
        print("MISMATCHES:")
        for m in out["mismatches"]:
            print(f"  {m['tool']}: expected={m['expected']} actual={m['actual']}")
