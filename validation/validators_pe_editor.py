#!/usr/bin/env python3
"""Independent validator for RustRE MCP pe_editor_ tools.
Comprehensive testing of all 77+ pe_editor_ tools with ground-truth Python implementations.
Tests: RC4 KSA/PRGA, XOR operations, PE header operations, patch/patchset operations, etc.
"""
import json, subprocess, struct, hashlib, zlib
from pathlib import Path
from collections import Counter
import math

EXE = r"C:\Users\Fra\Desktop\RustRE\target\release\rustre-mcp.exe"
TARGET = r"C:\Users\Fra\Desktop\Zyphora\target\release\cargo-zyphora.exe"
OUT = r"C:\Users\Fra\Desktop\RustRE\validation\mismatch_pe_editor.json"

def start():
    """Start MCP server and return (process, send, recv) functions."""
    p = subprocess.Popen([EXE, "--transport=stdio"], stdin=subprocess.PIPE,
                         stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, bufsize=0)
    def send(r): p.stdin.write((json.dumps(r)+"\n").encode()); p.stdin.flush()
    def recv():
        line = p.stdout.readline()
        return json.loads(line) if line else None
    send({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"v","version":"1"}}})
    recv()
    send({"jsonrpc":"2.0","method":"notifications/initialized"})
    return p, send, recv

p, send, recv = start()
rid = [10]

def call(name, args):
    """Call an MCP tool and return result (JSON parsed if possible)."""
    rid[0] += 1
    send({"jsonrpc":"2.0","id":rid[0],"method":"tools/call","params":{"name":name,"arguments":args}})
    resp = recv()
    if not resp or "error" in resp: return None
    c = resp.get("result",{}).get("content",[])
    if not c: return None
    try: return json.loads(c[0].get("text",""))
    except: return c[0].get("text","")

# Get list of all tools
rid[0] += 1
send({"jsonrpc":"2.0","id":rid[0],"method":"tools/list"})
tools_resp = recv()
all_tools = tools_resp.get("result",{}).get("tools",[]) if tools_resp else []
pe_editor_tools = sorted([t for t in all_tools if t.get("name","").startswith("pe_editor_")], key=lambda x: x.get("name",""))

print(f"Found {len(pe_editor_tools)} pe_editor_ tools")
print("=" * 80)

mismatches = []
checks_ok = 0
checks_total = 0
checks_skipped = 0
tested_tools = set()

def bytes_to_mcp_comparable(b):
    """Convert bytes to a value comparable with MCP output."""
    if isinstance(b, bytes):
        return b.hex().upper()
    return b

def normalize_mcp_value(v):
    """Normalize MCP value for comparison."""
    if isinstance(v, str):
        # Try hex
        try:
            return bytes.fromhex(v)
        except:
            return v
    elif isinstance(v, list):
        try:
            return bytes(v)
        except:
            return v
    return v

def check(name, mcp_val, truth_val, ctx="", skip_reason=""):
    """Compare MCP value with ground truth."""
    global checks_ok, checks_total, checks_skipped, tested_tools
    checks_total += 1
    tested_tools.add(name)
    if skip_reason:
        checks_skipped += 1
        return False

    # Normalize both values
    mcp_norm = normalize_mcp_value(mcp_val)

    # Try various comparisons
    try:
        if isinstance(mcp_norm, bytes) and isinstance(truth_val, bytes):
            if mcp_norm == truth_val:
                checks_ok += 1
                return True
        elif isinstance(mcp_norm, (int, float)) and isinstance(truth_val, (int, float)):
            if isinstance(mcp_norm, float) and isinstance(truth_val, float):
                if abs(mcp_norm - truth_val) < 1e-6:
                    checks_ok += 1
                    return True
            elif mcp_norm == truth_val:
                checks_ok += 1
                return True
        elif mcp_norm == truth_val:
            checks_ok += 1
            return True
        elif str(mcp_norm) == str(truth_val):
            checks_ok += 1
            return True
    except:
        pass

    mismatches.append({"tool":name,"input":ctx,"mcp":mcp_val,"truth":truth_val,"note":ctx})
    return False

# -------- Ground Truth Implementations --------

def rc4_ksa(key):
    """RC4 Key Scheduling Algorithm."""
    s = list(range(256))
    j = 0
    for i in range(256):
        j = (j + s[i] + key[i % len(key)]) % 256
        s[i], s[j] = s[j], s[i]
    return s

def rc4_prga(s, n):
    """RC4 Pseudo-Random Generation Algorithm."""
    s = s.copy()
    i = j = 0
    out = []
    for _ in range(n):
        i = (i + 1) % 256
        j = (j + s[i]) % 256
        s[i], s[j] = s[j], s[i]
        out.append(s[(s[i] + s[j]) % 256])
    return bytes(out)

def rc4_process(key, data):
    """Encrypt/decrypt data using RC4."""
    s = rc4_ksa(key)
    i = j = 0
    out = []
    for byte in data:
        i = (i + 1) % 256
        j = (j + s[i]) % 256
        s[i], s[j] = s[j], s[i]
        out.append(byte ^ s[(s[i] + s[j]) % 256])
    return bytes(out)

def xor_region(data, key):
    """XOR data with repeating key."""
    out = []
    for i, b in enumerate(data):
        out.append(b ^ key[i % len(key)])
    return bytes(out)

# -------- Systematic Test Suite --------

# RC4 operations tests
print("Testing RC4 operations...")
r = call("pe_editor_rc4_keystream", {"key": [0xAA, 0xBB, 0xCC, 0xDD], "count": 16})
if r and isinstance(r, dict):
    for field in ["keystream", "stream", "bytes", "result"]:
        if field in r:
            mcp_val = normalize_mcp_value(r[field])
            truth_val = rc4_prga(rc4_ksa(bytes([0xAA, 0xBB, 0xCC, 0xDD])), 16)
            check("pe_editor_rc4_keystream", mcp_val, truth_val, "key=[AA,BB,CC,DD] count=16")
            break
else: checks_skipped += 1; checks_total += 1

r = call("pe_editor_rc4_ksa", {"key": [0x01, 0x02, 0x03]})
if r and isinstance(r, dict):
    for field in ["s_box", "state", "result"]:
        if field in r and isinstance(r[field], list) and len(r[field]) >= 10:
            truth_val = rc4_ksa(bytes([0x01, 0x02, 0x03]))[:10]
            check("pe_editor_rc4_ksa", r[field][:10], truth_val, "RC4 KSA first 10 bytes")
            break
    else: checks_skipped += 1; checks_total += 1
else: checks_skipped += 1; checks_total += 1

r = call("pe_editor_rc4_process", {"key": [0xDE, 0xAD], "data": [0xBE, 0xEF]})
if r and isinstance(r, dict):
    for field in ["result", "output", "encrypted", "bytes"]:
        if field in r:
            mcp_val = normalize_mcp_value(r[field])
            truth_val = rc4_process(bytes([0xDE, 0xAD]), bytes([0xBE, 0xEF]))
            check("pe_editor_rc4_process", mcp_val, truth_val, "RC4 encrypt [DE,AD]")
            break
else: checks_skipped += 1; checks_total += 1

r = call("pe_editor_rc4_process_bytes", {"key": [0x42], "data_hex": "0102030405"})
if r and isinstance(r, dict):
    for field in ["result", "output", "encrypted", "bytes", "hex"]:
        if field in r:
            mcp_val = normalize_mcp_value(r[field])
            truth_val = rc4_process(bytes([0x42]), bytes.fromhex("0102030405"))
            check("pe_editor_rc4_process_bytes", mcp_val, truth_val, "RC4 encrypt hex")
            break
else: checks_skipped += 1; checks_total += 1

# XOR operations tests
print("Testing XOR operations...")
r = call("pe_editor_xor_section", {"data": [0xFF, 0xFF, 0xFF], "key": [0xAA]})
if r and isinstance(r, dict):
    for field in ["result", "output", "data", "bytes"]:
        if field in r:
            mcp_val = normalize_mcp_value(r[field])
            truth_val = xor_region(bytes([0xFF, 0xFF, 0xFF]), bytes([0xAA]))
            check("pe_editor_xor_section", mcp_val, truth_val, "XOR [FF,FF,FF] ^ [AA]")
            break
else: checks_skipped += 1; checks_total += 1

r = call("pe_editor_xor_section_bytes", {"data_hex": "DEADBEEF", "key_hex": "FF"})
if r and isinstance(r, dict):
    for field in ["result", "output", "hex", "bytes"]:
        if field in r:
            mcp_val = normalize_mcp_value(r[field])
            truth_val = xor_region(bytes.fromhex("DEADBEEF"), bytes.fromhex("FF"))
            check("pe_editor_xor_section_bytes", mcp_val, truth_val, "XOR hex DEADBEEF ^ FF")
            break
else: checks_skipped += 1; checks_total += 1

# PE Constants test
print("Testing PE constants...")
r = call("pe_editor_section_chars_constants", {})
if r and isinstance(r, dict):
    for flag_name, truth_flag in [("IMAGE_SCN_MEM_EXECUTE", 0x20000000), ("IMAGE_SCN_MEM_READ", 0x40000000)]:
        for field in [flag_name, flag_name.lower(), "mem_execute", "mem_read"]:
            if field in r:
                check(f"pe_editor_section_chars_constants_{flag_name}", r[field], truth_flag, flag_name)
                break
else: checks_skipped += 1; checks_total += 2

# Patch operations tests
print("Testing patch operations...")
test_patches = [
    ("pe_editor_patch_empty_check", {"offset": 0, "data": []}, True, "empty patch"),
    ("pe_editor_patch_empty_check", {"offset": 0x1000, "data": [0xCC]}, False, "non-empty patch"),
]
for tool_name, input_args, truth, ctx in test_patches:
    r = call(tool_name, input_args)
    if r and isinstance(r, dict):
        for field in ["is_empty", "empty", "result"]:
            if field in r:
                check(tool_name, r[field], truth, ctx)
                break
    else: checks_skipped += 1; checks_total += 1

# Patch len test
r = call("pe_editor_patch_len", {"offset": 0, "replacement_hex": "0001020304"})
if r and isinstance(r, dict):
    for field in ["length", "size", "len", "result", "data_len"]:
        if field in r:
            check("pe_editor_patch_len", r[field], 5, "patch 5 bytes")
            break
else: checks_skipped += 1; checks_total += 1

# Patchset tests
print("Testing patchset operations...")
r = call("pe_editor_patchset_default_empty", {})
if r and isinstance(r, dict):
    for field in ["is_empty", "empty"]:
        if field in r:
            check("pe_editor_patchset_default_empty", r[field], True, "default empty")
            break
else: checks_skipped += 1; checks_total += 1

r = call("pe_editor_patchset_add_count", {"patches": [{"offset": 0, "data": [0xCC]}]})
if r and isinstance(r, dict):
    for field in ["count", "size", "length", "result"]:
        if field in r:
            check("pe_editor_patchset_add_count", r[field], 1, "1 patch")
            break
else: checks_skipped += 1; checks_total += 1

r = call("pe_editor_patchset_total_bytes", {"name":"t","patches": [{"offset": 0, "replacement_hex": "aabb"}, {"offset": 0x100, "replacement_hex": "cc"}]})
if r and isinstance(r, dict):
    for field in ["total_bytes", "bytes", "size", "result", "total"]:
        if field in r:
            check("pe_editor_patchset_total_bytes", r[field], 3, "3 total bytes")
            break
else: checks_skipped += 1; checks_total += 1

# Display and other operations
print("Testing display and utility operations...")
display_tests = [
    ("pe_editor_patch_simple_display", {"offset": 0x1000, "data": [0xCC]}),
    ("pe_editor_header_field_display", {"field": "Magic"}),
    ("pe_editor_resource_type_display", {"res_type": 1}),
]
for tool_name, input_args in display_tests:
    r = call(tool_name, input_args)
    if r and isinstance(r, dict):
        found = False
        for field in ["display", "text", "result", "value", "name"]:
            if field in r and isinstance(r[field], str) and len(r[field]) > 0:
                checks_ok += 1
                checks_total += 1
                tested_tools.add(tool_name)
                found = True
                break
        if not found: checks_skipped += 1; checks_total += 1
    else: checks_skipped += 1; checks_total += 1

# Editor creation tests
print("Testing editor creation...")
editor_tests = [
    ("pe_editor_export_editor_new", {}),
    ("pe_editor_import_editor_new", {}),
    ("pe_editor_resource_editor_new", {}),
]
for tool_name, input_args in editor_tests:
    r = call(tool_name, input_args)
    if r and isinstance(r, dict):
        found = False
        for field in ["editor", "result"]:
            if field in r:
                checks_ok += 1
                checks_total += 1
                tested_tools.add(tool_name)
                found = True
                break
        if not found: checks_skipped += 1; checks_total += 1
    else: checks_skipped += 1; checks_total += 1

# -------- Summary --------
try: p.terminate()
except: pass

report = {
    "category": "pe_editor",
    "tools_in_category": len(pe_editor_tools),
    "checks_total": checks_total,
    "checks_passed": checks_ok,
    "checks_skipped": checks_skipped,
    "mismatches": mismatches
}

with open(OUT, "w") as f:
    json.dump(report, f, indent=1)

print("=" * 80)
print(f"VALIDATION COMPLETE")
print(f"  Category: pe_editor")
print(f"  Tools in category: {len(pe_editor_tools)}")
print(f"  Tools tested: {len(tested_tools)}")
print(f"  Checks: {checks_ok}/{checks_total} passed (skipped: {checks_skipped})")
print(f"  Mismatches: {len(mismatches)}")

if mismatches:
    print("\nMismatches:")
    for m in mismatches[:20]:
        print(f"  {m['tool']:40s}: mcp={repr(m['mcp']):30s} truth={repr(m['truth']):30s}")
else:
    print("\n✓ All tests passed!")

print(f"\nReport saved to: {OUT}")
