#!/usr/bin/env python3
"""Independent validator for dwarf_* MCP tools."""
import json, subprocess, os, struct

EXE = r"C:\Users\Fra\Desktop\RustRE\target\release\rustre-mcp.exe"
OUT = r"C:\Users\Fra\Desktop\RustRE\validation\mismatch_dwarf.json"

def start():
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
    rid[0] += 1
    send({"jsonrpc":"2.0","id":rid[0],"method":"tools/call","params":{"name":name,"arguments":args}})
    resp = recv()
    if not resp or "error" in resp: return None
    c = resp.get("result",{}).get("content",[])
    if not c: return None
    try: return json.loads(c[0].get("text",""))
    except: return c[0].get("text","")

# List tools
rid[0] += 1
send({"jsonrpc":"2.0","id":rid[0],"method":"tools/list","params":{}})
resp = recv()
tools = resp.get("result",{}).get("tools",[])
dwarf_tools = [t for t in tools if t["name"].startswith("dwarf_")]
tools_by_name = {t["name"]: t for t in dwarf_tools}
print(f"Found {len(dwarf_tools)} dwarf_* tools")

mismatches = []
checks_total = 0
checks_passed = 0
checks_skipped = 0

def check(tool, mcp, truth, inp, note=""):
    global checks_total, checks_passed
    checks_total += 1
    def norm(v):
        if isinstance(v, float): return round(v, 6)
        return v
    if norm(mcp) == norm(truth):
        checks_passed += 1
        return True
    mismatches.append({"tool":tool,"input":inp,"mcp":mcp,"truth":truth,"note":note})
    return False

def extract(r, keys):
    if not isinstance(r, dict): return None
    for k in keys:
        if k in r: return r[k]
    return None

# ULEB128 truth
def uleb128(bs):
    result = 0; shift = 0; consumed = 0
    for b in bs:
        consumed += 1
        result |= (b & 0x7F) << shift
        if (b & 0x80) == 0: break
        shift += 7
    return result, consumed

def sleb128(bs):
    result = 0; shift = 0; consumed = 0; last = 0
    for b in bs:
        consumed += 1
        result |= (b & 0x7F) << shift
        shift += 7
        last = b
        if (b & 0x80) == 0: break
    if last & 0x40:
        result |= -(1 << shift)
    return result, consumed

# --- ULEB128 tests ---
if "dwarf_abbrev_read_uleb128" in tools_by_name:
    for hexstr in ["00", "7f", "8001", "e58e26"]:
        r = call("dwarf_abbrev_read_uleb128", {"hex": hexstr, "pos": 0})
        if r is None:
            checks_skipped += 1; continue
        v = extract(r, ["value","result","decoded"])
        truth, consumed = uleb128(bytes.fromhex(hexstr))
        check("dwarf_abbrev_read_uleb128", v, truth, hexstr)
        pa = extract(r, ["pos_after"])
        if pa is not None:
            check("dwarf_abbrev_read_uleb128", pa, consumed, hexstr, "pos_after")

# --- SLEB128 tests ---
if "dwarf_abbrev_read_sleb128" in tools_by_name:
    for hexstr in ["00", "7f", "3f", "41", "c000"]:
        r = call("dwarf_abbrev_read_sleb128", {"hex": hexstr, "pos": 0})
        if r is None:
            checks_skipped += 1; continue
        v = extract(r, ["value","result","decoded"])
        truth, consumed = sleb128(bytes.fromhex(hexstr))
        check("dwarf_abbrev_read_sleb128", v, truth, hexstr)

# --- Cast tests ---
# NOTE: dwarf_casts_* are SATURATING (not wrapping/truncating).
# See crates/rustre-symbols-dwarf/src/casts.rs — module doc:
# "Saturating / wrapping numeric cast helpers". i64->u32 saturates negatives to 0
# and values > u32::MAX to u32::MAX; u64->uN uses try_from(...).unwrap_or(MAX).
cast_tests = [
    ("dwarf_casts_i64_to_u32", -1, 0),                       # saturating: neg -> 0
    ("dwarf_casts_i64_to_u32", 100, 100),
    ("dwarf_casts_i64_to_u32", 0x1_0000_0001, 0xFFFFFFFF),   # saturating: > u32::MAX
    ("dwarf_casts_i64_to_u64", -1, 0xFFFFFFFFFFFFFFFF),
    ("dwarf_casts_i64_to_u64", 42, 42),
    ("dwarf_casts_i64_to_usize", 999, 999),
    ("dwarf_casts_u64_to_i64", 0xFFFFFFFFFFFFFFFF, -1),
    ("dwarf_casts_u64_to_i64", 0, 0),
    ("dwarf_casts_u64_to_u16", 0x12345, 0x2345),             # truncating (wrapping)
    ("dwarf_casts_u64_to_u32", 0x1_0000_0000, 0xFFFFFFFF),   # saturating
    ("dwarf_casts_u64_to_u32", 0x1_2345_6789, 0xFFFFFFFF),   # saturating (4886718345 > u32::MAX)
    ("dwarf_casts_u64_to_u8", 0x1FF, 0xFF),                  # saturating
    ("dwarf_casts_u64_to_u8", 0x100, 0xFF),                  # saturating (256 -> 255)
    ("dwarf_casts_u64_to_usize", 12345, 12345),
    ("dwarf_casts_u8_to_i8", 0xFF, -1),
    ("dwarf_casts_u8_to_i8", 0x7F, 127),
    ("dwarf_casts_u8_to_i8", 0x80, -128),
    ("dwarf_casts_usize_to_i64", 100, 100),
    ("dwarf_casts_usize_to_u32", 0x1_0000_0001, 0xFFFFFFFF), # saturating
]

for name, inp, truth in cast_tests:
    if name not in tools_by_name:
        continue
    schema = tools_by_name[name].get("inputSchema",{}).get("properties",{})
    key = None
    for k in ["value","input","x","n","v"]:
        if k in schema:
            key = k; break
    if key is None and schema:
        key = list(schema.keys())[0]
    if key is None:
        checks_skipped += 1; continue
    r = call(name, {key: inp})
    if r is None:
        checks_skipped += 1; continue
    if isinstance(r, dict):
        v = extract(r, ["output","value","result","cast","converted"])
        if v is None and len(r) == 1:
            v = list(r.values())[0]
    else:
        v = r
    check(name, v, truth, {key: inp})

# Clean up
try: p.terminate()
except: pass

report = {
    "category": "dwarf",
    "tools_in_category": len(dwarf_tools),
    "checks_total": checks_total,
    "checks_passed": checks_passed,
    "checks_skipped": checks_skipped,
    "mismatches": mismatches,
}
with open(OUT,"w") as f: json.dump(report, f, indent=1)
print(f"Total={checks_total} passed={checks_passed} skipped={checks_skipped} mismatches={len(mismatches)}")
for m in mismatches[:10]:
    print(f"  {m['tool']} inp={m['input']} mcp={m['mcp']} truth={m['truth']}")
