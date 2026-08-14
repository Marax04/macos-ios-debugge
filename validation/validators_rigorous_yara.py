#!/usr/bin/env python3
"""
Rigorous independent validator for RustRE yara_* MCP tools.
Replaces any_valid() with independently computed Python truth for each check.
"""

import json
import subprocess
import sys
import math
import re
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

MCP_BINARY = r"C:\Users\Fra\Desktop\RustRE\target\release\rustre-mcp.exe"
WORK_DIR   = r"C:\Users\Fra\Desktop\RustRE"
REPORT_OUT = r"C:\Users\Fra\Desktop\RustRE\validation\rigorous_yara.json"


# ---------------------------------------------------------------------------
# MCP client (stdio JSON-RPC)
# ---------------------------------------------------------------------------

class MCPClient:
    def __init__(self, binary: str):
        self.proc = subprocess.Popen(
            [binary, "--transport=stdio"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=False,
            cwd=WORK_DIR,
            bufsize=0,
        )
        self._id = 0

    def _rpc(self, method: str, params: Dict) -> Dict:
        self._id += 1
        msg = json.dumps({"jsonrpc": "2.0", "id": self._id, "method": method, "params": params}) + "\n"
        self.proc.stdin.write(msg.encode())
        self.proc.stdin.flush()
        raw = self.proc.stdout.readline()
        if not raw:
            return {}
        try:
            return json.loads(raw.decode("utf-8", errors="replace"))
        except Exception:
            return {}

    def initialize(self) -> bool:
        r = self._rpc("initialize", {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "rigorous_yara", "version": "1.0"},
        })
        notif = json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}) + "\n"
        self.proc.stdin.write(notif.encode())
        self.proc.stdin.flush()
        return "result" in r

    def call_tool(self, name: str, args: Dict) -> Any:
        r = self._rpc("tools/call", {"name": name, "arguments": args})
        result = r.get("result", {})
        # content is usually [{"type":"text","text":"..."}]
        content = result.get("content", [])
        if content and isinstance(content, list):
            text = content[0].get("text", "")
            try:
                return json.loads(text)
            except Exception:
                return text
        return result

    def close(self):
        try:
            self.proc.terminate()
            self.proc.wait(timeout=2)
        except Exception:
            self.proc.kill()


# ---------------------------------------------------------------------------
# Independent Python truth functions
# ---------------------------------------------------------------------------

def py_match_masked_byte(value: int, mask: int, data_byte: int) -> bool:
    """(data_byte & mask) == (value & mask)"""
    return (data_byte & mask) == (value & mask)


def py_check_fullword(data: List[int], offset: int, length: int) -> bool:
    """True if data[offset..offset+length] is word-boundary-bounded."""
    def is_word(b: int) -> bool:
        c = chr(b)
        return c.isascii() and (c.isalnum() or c == '_')
    before_ok = (offset == 0) or (not is_word(data[offset - 1]))
    end = offset + length
    after_ok = (end >= len(data)) or (not is_word(data[end]))
    return before_ok and after_ok


def py_match_nocase(text: str, data_hex: str) -> List[int]:
    """Case-insensitive ASCII search; returns list of offsets."""
    data = bytes.fromhex(data_hex)
    needle = text.lower().encode("ascii")
    if not needle or len(data) < len(needle):
        return []
    results = []
    for i in range(len(data) - len(needle) + 1):
        if data[i:i+len(needle)].lower() == needle:
            results.append(i)
    return results


def py_match_wide(text: str, data_hex: str) -> List[int]:
    """UTF-16 LE search; returns list of offsets."""
    data = bytes.fromhex(data_hex)
    wide = text.encode("utf-16-le")
    if not wide or len(data) < len(wide):
        return []
    results = []
    for i in range(len(data) - len(wide) + 1):
        if data[i:i+len(wide)] == wide:
            results.append(i)
    return results


def py_shannon_entropy(data_hex: str) -> float:
    """Shannon entropy in bits (0..8), same formula as Rust compute_entropy."""
    data = bytes.fromhex(data_hex)
    if not data:
        return 0.0
    n = len(data)
    freq = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    entropy = 0.0
    for count in freq.values():
        p = count / n
        entropy += -p * math.log2(p)
    return entropy


def py_parse_rule_name(source: str) -> Optional[str]:
    """Extract rule name from YARA source using same regex pattern as Rust."""
    m = re.search(r'\brule\s+(\w+)', source)
    return m.group(1) if m else None


def py_xor_match(text: str, data_hex: str, xor_min: int = 0, xor_max: int = 255) -> List[Dict]:
    """XOR keyed search; returns list of {offset, key}."""
    data = bytes.fromhex(data_hex)
    needle = text.encode("ascii")
    if not needle or len(data) < len(needle):
        return []
    results = []
    for key in range(xor_min, xor_max + 1):
        for i in range(len(data) - len(needle) + 1):
            chunk = data[i:i+len(needle)]
            if all((chunk[j] ^ key) == needle[j] for j in range(len(needle))):
                results.append({"offset": i, "key": key})
    # Sort by offset then key, deduplicate
    seen = set()
    deduped = []
    for r in sorted(results, key=lambda x: (x["offset"], x["key"])):
        k = (r["offset"], r["key"])
        if k not in seen:
            seen.add(k)
            deduped.append(r)
    return deduped


# ---------------------------------------------------------------------------
# Harness helpers
# ---------------------------------------------------------------------------

def extract_float(val: Any, key: str) -> Optional[float]:
    if isinstance(val, dict):
        v = val.get(key)
        if v is not None:
            return float(v)
    return None


def extract_int(val: Any, key: str) -> Optional[int]:
    if isinstance(val, dict):
        v = val.get(key)
        if v is not None:
            return int(v)
    return None


def extract_bool(val: Any, key: str) -> Optional[bool]:
    if isinstance(val, dict):
        v = val.get(key)
        if v is not None:
            return bool(v)
    return None


def extract_list(val: Any, key: str) -> Optional[List]:
    if isinstance(val, dict):
        v = val.get(key)
        if isinstance(v, list):
            return v
    return None


def extract_str(val: Any, key: str) -> Optional[str]:
    if isinstance(val, dict):
        v = val.get(key)
        if v is not None:
            return str(v)
    return None


# ---------------------------------------------------------------------------
# Test definitions
# ---------------------------------------------------------------------------

def build_rigorous_tests(mcp: MCPClient) -> List[Dict]:
    """
    Each entry: {tool, args, check_fn, description}
    check_fn(mcp_result) -> (passed: bool, detail: str)
    """
    tests = []

    # ---- 1. yara_match_masked_byte: (data_byte & mask) == (value & mask) ----
    cases_mb = [
        (0xF0, 0xFF, 0xF0, True),   # exact match
        (0xF0, 0xFF, 0xF1, False),  # different low nibble, mask=FF -> no match
        (0xF0, 0xF0, 0xF1, True),   # masked: F1 & F0 == F0 & F0
        (0x00, 0x00, 0xFF, True),   # mask=0 -> always matches
        (0xAB, 0xFF, 0xAB, True),
        (0xAB, 0xFF, 0xAC, False),
    ]
    for value, mask, data_byte, expected in cases_mb:
        v, m, d, exp = value, mask, data_byte, expected  # capture
        def _check(result, v=v, m=m, d=d, exp=exp):
            got = extract_bool(result, "matched")
            if got is None:
                return False, f"no 'matched' key in {result}"
            if got == exp:
                return True, f"matched={got} == {exp}"
            return False, f"matched={got} != expected {exp} for value={v} mask={m} data_byte={d}"
        tests.append({
            "tool": "yara_match_masked_byte",
            "args": {"value": v, "mask": m, "data_byte": d},
            "check": _check,
            "description": f"masked_byte({v:#04x},{m:#04x},{d:#04x}) => {exp}",
        })

    # ---- 2. yara_string_matcher_masked_byte_wire ----
    for value, mask, data_byte, expected in cases_mb[:3]:
        v, m, d, exp = value, mask, data_byte, expected
        def _check2(result, v=v, m=m, d=d, exp=exp):
            # wire tool returns key "match" (not "matched")
            got = extract_bool(result, "match")
            if got is None:
                return False, f"no 'match' key in {result}"
            return (got == exp), f"match={got} expected={exp}"
        tests.append({
            "tool": "yara_string_matcher_masked_byte_wire",
            "args": {"value": v, "mask": m, "data_byte": d},
            "check": _check2,
            "description": f"wire_masked_byte({v:#04x},{m:#04x},{d:#04x}) => {exp}",
        })

    # ---- 3. yara_check_fullword ----
    # data: [32, 72, 101, 108, 108, 111, 32, 87, 111, 114, 108, 100, 32]
    # " Hello World "  -> "Hello" starts at offset 1, len 5, bounded by spaces (32)
    fw_data = [32, 72, 101, 108, 108, 111, 32, 87, 111, 114, 108, 100, 32]
    fw_tests = [
        (fw_data, 1, 5, True),   # " Hello " — fullword
        (fw_data, 0, 1, True),   # offset 0, before=start, after=H (alpha) -> False actually
        ([72, 101, 108, 108, 111], 0, 5, True),  # entire buffer "Hello" at 0..5
        ([65, 72, 101, 108, 108, 111, 66], 1, 5, False),  # "AHelloB" — not fullword
    ]
    # Recompute expected with Python truth
    fw_tests_corrected = []
    for data, offset, length, _ in fw_tests:
        exp = py_check_fullword(data, offset, length)
        fw_tests_corrected.append((data, offset, length, exp))

    for data, offset, length, expected in fw_tests_corrected:
        da, of, le, exp = data, offset, length, expected
        def _check_fw(result, da=da, of=of, le=le, exp=exp):
            got = extract_bool(result, "fullword")
            if got is None:
                return False, f"no 'fullword' key in {result}"
            return (got == exp), f"fullword={got} expected={exp}"
        tests.append({
            "tool": "yara_check_fullword",
            "args": {"data": da, "offset": of, "len": le},
            "check": _check_fw,
            "description": f"check_fullword(data[{of}..{of+le}]) => {exp}",
        })

    # ---- 4. yara_string_matcher_check_fullword_wire ----
    # This wire takes data_hex instead of array
    fw_wire_tests = [
        ("20 48 65 6C 6C 6F 20", 1, 5),  # " Hello "
        ("48 65 6C 6C 6F", 0, 5),        # "Hello" entire buffer
        ("41 48 65 6C 6C 6F 42", 1, 5),  # "AHelloB"
    ]
    for hex_data, offset, length in fw_wire_tests:
        data_bytes = list(bytes.fromhex(hex_data.replace(" ", "")))
        exp = py_check_fullword(data_bytes, offset, length)
        he, of, le, ex = hex_data.replace(" ", ""), offset, length, exp
        def _check_fww(result, he=he, of=of, le=le, ex=ex):
            got = extract_bool(result, "fullword")
            if got is None:
                return False, f"no 'fullword' key in {result}"
            return (got == ex), f"fullword={got} expected={ex} hex={he} off={of} len={le}"
        tests.append({
            "tool": "yara_string_matcher_check_fullword_wire",
            "args": {"data_hex": he, "offset": of, "len": le},
            "check": _check_fww,
            "description": f"wire_check_fullword(hex={he}, off={of}, len={le}) => {ex}",
        })

    # ---- 5. yara_string_matcher_match_nocase_wire ----
    nocase_tests = [
        ("Hello", "48656c6c6f", [0]),      # exact lowercase data
        ("hello", "48 45 4c 4c 4f".replace(" ",""), [0]),  # "HELLO" in data
        ("xyz", "61626364", []),            # "abcd" — no match
        ("ab", "41424142", [0, 2]),         # "ABAB"
    ]
    for text, data_hex, expected_offsets in nocase_tests:
        t, dh, exp = text, data_hex, expected_offsets
        # Verify our truth
        truth = py_match_nocase(t, dh)
        exp = truth  # trust our Python impl as the reference
        def _check_nc(result, t=t, dh=dh, exp=exp):
            offsets = extract_list(result, "offsets")
            count = extract_int(result, "count")
            if offsets is None:
                return False, f"no 'offsets' key in {result}"
            got = list(offsets)
            if got == exp:
                return True, f"count={count} offsets={got}"
            return False, f"offsets={got} != expected {exp} text='{t}' data={dh}"
        tests.append({
            "tool": "yara_string_matcher_match_nocase_wire",
            "args": {"text": t, "data_hex": dh},
            "check": _check_nc,
            "description": f"match_nocase('{t}', {dh}) => offsets={exp}",
        })

    # ---- 6. yara_string_matcher_match_wide_wire ----
    wide_tests = [
        ("AB", "41004200", [0]),  # "AB" as UTF-16LE
        ("AB", "41424300", []),   # ASCII bytes, no wide match
        ("Hi", "480069006800", [3]),  # "Hi" at offset 3
    ]
    for text, data_hex, _ in wide_tests:
        t, dh = text, data_hex
        exp = py_match_wide(t, dh)
        def _check_wide(result, t=t, dh=dh, exp=exp):
            offsets = extract_list(result, "offsets")
            if offsets is None:
                return False, f"no 'offsets' key in {result}"
            got = list(offsets)
            return (got == exp), f"offsets={got} expected={exp} text='{t}'"
        tests.append({
            "tool": "yara_string_matcher_match_wide_wire",
            "args": {"text": t, "data_hex": dh},
            "check": _check_wide,
            "description": f"match_wide('{t}', {dh}) => {exp}",
        })

    # ---- 7. yara_engine_compute_entropy_wire2 ----
    entropy_tests = [
        ("",            0.0),    # empty -> 0
        ("aa" * 100,    0.0),    # uniform -> 0
        ("".join(f"{i:02x}" for i in range(256)), None),  # all bytes -> 8.0
    ]
    for dh, fixed_expected in entropy_tests:
        if fixed_expected is None:
            exp = py_shannon_entropy(dh)
        else:
            exp = fixed_expected
        dh2, ex2 = dh, exp
        def _check_ent(result, dh2=dh2, ex2=ex2):
            entropy = extract_float(result, "entropy")
            if entropy is None:
                return False, f"no 'entropy' key in {result}"
            if abs(entropy - ex2) < 1e-6:
                return True, f"entropy={entropy:.6f} ~ {ex2:.6f}"
            return False, f"entropy={entropy:.6f} != expected {ex2:.6f}"
        tests.append({
            "tool": "yara_engine_compute_entropy_wire2",
            "args": {"data_hex": dh2},
            "check": _check_ent,
            "description": f"entropy(hex={dh2[:20]}...) => {ex2:.4f}",
        })

    # ---- 8. yara_engine_compute_entropy_hex_wire3 ----
    for dh, fixed_expected in [("aabbcc", None), ("000000", 0.0)]:
        if fixed_expected is None:
            exp = py_shannon_entropy(dh)
        else:
            exp = fixed_expected
        dh2, ex2 = dh, exp
        def _check_ent3(result, dh2=dh2, ex2=ex2):
            entropy = extract_float(result, "entropy")
            if entropy is None:
                return False, f"no 'entropy' key in {result}"
            if abs(entropy - ex2) < 1e-6:
                return True, f"entropy={entropy:.6f} ~ {ex2:.6f}"
            return False, f"entropy={entropy:.6f} != expected {ex2:.6f}"
        tests.append({
            "tool": "yara_engine_compute_entropy_hex_wire3",
            "args": {"hex": dh2},
            "check": _check_ent3,
            "description": f"entropy_wire3(hex={dh2}) => {ex2:.4f}",
        })

    # ---- 9. yara_ruleset_new_count_wire: fresh ruleset -> count == 0 ----
    def _check_rs(result):
        count = extract_int(result, "count")
        if count is None:
            return False, f"no 'count' key in {result}"
        return (count == 0), f"count={count} expected=0"
    tests.append({
        "tool": "yara_ruleset_new_count_wire",
        "args": {},
        "check": _check_rs,
        "description": "fresh YaraRuleSet::rule_count() == 0",
    })

    # ---- 10. yara_engine_scanner_new_count: fresh scanner -> rule_count == 0 ----
    def _check_sc(result):
        count = extract_int(result, "rule_count")
        if count is None:
            return False, f"no 'rule_count' key in {result}"
        return (count == 0), f"rule_count={count} expected=0"
    tests.append({
        "tool": "yara_engine_scanner_new_count",
        "args": {},
        "check": _check_sc,
        "description": "fresh YaraScanner::rule_count() == 0",
    })

    # ---- 11. yara_engine_parse_name_from_source: extract rule name ----
    name_cases = [
        ("rule MyRule { condition: true }", "MyRule"),
        ("rule Foo123 { strings: $a=\"test\" condition: $a }", "Foo123"),
        ("rule TestRule { condition: false }", "TestRule"),
    ]
    for source, expected_name in name_cases:
        src, en = source, expected_name
        def _check_name(result, src=src, en=en):
            name = extract_str(result, "name")
            if name is None:
                return False, f"no 'name' key in {result}"
            return (name == en), f"name='{name}' expected='{en}'"
        tests.append({
            "tool": "yara_engine_parse_name_from_source",
            "args": {"source": src},
            "check": _check_name,
            "description": f"parse_name_from_source => '{en}'",
        })

    # ---- 12. yara_engine_rule_def_parse_name_wire3 ----
    for source, expected_name in name_cases[:2]:
        src, en = source, expected_name
        def _check_name3(result, src=src, en=en):
            name = extract_str(result, "name")
            if name is None:
                return False, f"no 'name' key in {result}"
            return (name == en), f"name='{name}' expected='{en}'"
        tests.append({
            "tool": "yara_engine_rule_def_parse_name_wire3",
            "args": {"src": src},
            "check": _check_name3,
            "description": f"rule_def_parse_name_wire3 => '{en}'",
        })

    # ---- 13. yara_engine_scanner_add_rule_wire2: after add_rule, rule_count == 1 ----
    def _check_add(result):
        count = extract_int(result, "rule_count")
        if count is None:
            return False, f"no 'rule_count' key in {result}"
        return (count == 1), f"rule_count={count} expected=1"
    tests.append({
        "tool": "yara_engine_scanner_add_rule_wire2",
        "args": {"name": "TestAddRule"},
        "check": _check_add,
        "description": "scanner.add_rule -> rule_count == 1",
    })

    # ---- 14. yara_string_matcher_match_xor_wire: XOR key 0x00 is plain text match ----
    # "AB" XOR 0x00 = "AB"; data = "414200" -> match at offset 0 with key 0
    xor_data = "414200"
    xor_text = "AB"
    truth_xor = py_xor_match(xor_text, xor_data, xor_min=0, xor_max=0)
    exp_xor_count = len(truth_xor)
    def _check_xor(result, exc=exp_xor_count):
        count = extract_int(result, "count")
        if count is None:
            return False, f"no 'count' key in {result}"
        # count should be >= 1 for xor_min=xor_max=0 on matching data
        return (count == exc), f"count={count} expected={exc}"
    tests.append({
        "tool": "yara_string_matcher_match_xor_wire",
        "args": {"text": xor_text, "data_hex": xor_data, "xor_min": 0, "xor_max": 0},
        "check": _check_xor,
        "description": f"match_xor('AB', key=0) => count={exp_xor_count}",
    })

    return tests


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    print("[*] Rigorous YARA validator starting...")

    import os
    if not os.path.exists(MCP_BINARY):
        print(f"[!] MCP binary not found: {MCP_BINARY}")
        sys.exit(1)

    mcp = MCPClient(MCP_BINARY)
    time.sleep(0.3)

    if not mcp.initialize():
        print("[!] MCP initialization failed")
        mcp.close()
        sys.exit(1)

    print("[+] MCP initialized")

    tests = build_rigorous_tests(mcp)
    print(f"[+] Built {len(tests)} rigorous test cases")

    checks_passed = 0
    checks_failed = 0
    mismatches = []

    for i, t in enumerate(tests, 1):
        tool = t["tool"]
        args = t["args"]
        desc = t["description"]
        check_fn = t["check"]

        print(f"\n[{i:02d}/{len(tests)}] {tool}")
        print(f"     desc: {desc}")

        try:
            result = mcp.call_tool(tool, args)
        except Exception as e:
            print(f"     SKIP: tool call error: {e}")
            checks_failed += 1
            mismatches.append({
                "tool": tool, "description": desc,
                "error": str(e), "verdict": "TOOL_ERROR",
            })
            continue

        if not result and result != 0 and result is not False:
            print(f"     SKIP: empty result")
            checks_failed += 1
            mismatches.append({
                "tool": tool, "description": desc,
                "mcp_result": repr(result), "verdict": "EMPTY_RESULT",
            })
            continue

        try:
            passed, detail = check_fn(result)
        except Exception as e:
            print(f"     ERROR in check fn: {e}")
            checks_failed += 1
            mismatches.append({
                "tool": tool, "description": desc,
                "error": str(e), "verdict": "CHECK_ERROR",
            })
            continue

        if passed:
            checks_passed += 1
            print(f"     PASS: {detail}")
        else:
            checks_failed += 1
            print(f"     FAIL: {detail}")
            mismatches.append({
                "tool": tool,
                "args": {k: str(v)[:80] for k, v in args.items()},
                "description": desc,
                "detail": detail,
                "mcp_result": result if isinstance(result, (dict, list, int, float, bool, str)) else repr(result),
                "verdict": "MISMATCH",
            })

    mcp.close()

    # Count real Rust defects (MISMATCH verdict, not EMPTY/ERROR)
    real_mismatches = [m for m in mismatches if m.get("verdict") == "MISMATCH"]

    # Deduplicate hardened tools
    tools_hardened = len(set(t["tool"] for t in tests))

    report = {
        "module": "yara",
        "tools_hardened": tools_hardened,
        "checks_passed": checks_passed,
        "checks_failed": checks_failed,
        "mismatches": mismatches,
    }

    Path(REPORT_OUT).parent.mkdir(parents=True, exist_ok=True)
    with open(REPORT_OUT, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, default=str)

    print(f"\n[+] Report saved: {REPORT_OUT}")
    print(f"[+] Tools hardened: {tools_hardened}")
    print(f"[+] Checks passed: {checks_passed}")
    print(f"[+] Checks failed: {checks_failed}")
    print(f"[+] Real mismatches (Rust wrong): {len(real_mismatches)}")
    for m in real_mismatches:
        print(f"    >> {m['tool']}: {m['detail']}")

    return report


if __name__ == "__main__":
    main()
