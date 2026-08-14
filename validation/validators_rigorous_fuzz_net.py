#!/usr/bin/env python3
"""
Rigorous validators for fuzz_net_* MCP tools.
Each check compares the MCP output against an independently computed Python truth.
"""
import json, subprocess, sys, struct

EXE = r"C:\Users\Fra\Desktop\RustRE\target\release\rustre-mcp.exe"
OUT = r"C:\Users\Fra\Desktop\RustRE\validation\rigorous_fuzz_net.json"

# -- MCP session --------------------------------------------------------------

def start():
    p = subprocess.Popen([EXE, "--transport=stdio"], stdin=subprocess.PIPE,
                         stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, bufsize=0)
    def send(r): p.stdin.write((json.dumps(r)+"\n").encode()); p.stdin.flush()
    def recv():
        line = p.stdout.readline()
        return json.loads(line) if line else None
    send({"jsonrpc":"2.0","id":1,"method":"initialize","params":{
        "protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"v","version":"1"}}})
    recv()
    send({"jsonrpc":"2.0","method":"notifications/initialized"})
    return p, send, recv

p, send, recv = start()
rid = [10]

def call(name, args):
    rid[0] += 1
    send({"jsonrpc":"2.0","id":rid[0],"method":"tools/call","params":{"name":name,"arguments":args}})
    resp = recv()
    if not resp: return ("no_resp", None)
    if "error" in resp: return ("err", resp["error"])
    c = resp.get("result",{}).get("content",[])
    if not c: return ("empty", None)
    txt = c[0].get("text","")
    try: return ("ok", json.loads(txt))
    except: return ("ok_str", txt)

# -- Bookkeeping --------------------------------------------------------------

mismatches = []
checks_passed = 0
checks_failed = 0
tools_hardened = set()

def norm(v):
    if isinstance(v, str):
        try: return int(v, 0)
        except: return v.lower()   # hex strings: case-insensitive comparison
    return v

def check(tool, field, mcp_val, truth_val, note=""):
    global checks_passed, checks_failed
    tools_hardened.add(tool)
    if norm(mcp_val) == norm(truth_val):
        checks_passed += 1
        return True
    checks_failed += 1
    mismatches.append({"tool": tool, "field": field,
                       "mcp": mcp_val, "truth": truth_val, "note": note})
    print(f"  MISMATCH {tool}.{field}: mcp={mcp_val!r} truth={truth_val!r}", file=sys.stderr)
    return False

def fail(tool, note):
    global checks_failed
    checks_failed += 1
    tools_hardened.add(tool)
    mismatches.append({"tool": tool, "note": note})
    print(f"  FAIL {tool}: {note}", file=sys.stderr)

# =============================================================================
# Python ground-truth helpers
# =============================================================================

def py_xor_checksum(data):
    acc = 0
    for b in data:
        acc ^= b
    return acc

def py_add_checksum(data):
    return sum(data) & 0xFF

def py_frame_u32_le(payload):
    return struct.pack("<I", len(payload)) + payload

def py_frame_u32_be(payload):
    return struct.pack(">I", len(payload)) + payload

def py_decode_frame_u32_le(buf):
    if len(buf) < 4:
        return None
    n = struct.unpack_from("<I", buf)[0]
    total = 4 + n
    if len(buf) < total:
        return None
    return (total, buf[4:total])

def py_decode_frame_u32_be(buf):
    if len(buf) < 4:
        return None
    n = struct.unpack_from(">I", buf)[0]
    total = 4 + n
    if len(buf) < total:
        return None
    return (total, buf[4:total])

# Known constants from Rust source
PY_INTERESTING_U8  = [0x00, 0x01, 0x7f, 0x80, 0xfe, 0xff]
PY_INTERESTING_U16 = [0x0000,0x0001,0x007f,0x0080,0x00ff,0x0100,
                       0x7fff,0x8000,0xfffe,0xffff]
PY_INTERESTING_U32 = [0x00000000,0x00000001,0x0000007f,0x00000080,
                       0x000000ff,0x00000100,0x00007fff,0x00008000,
                       0x0000ffff,0x00010000,0x7fffffff,0x80000000,
                       0xfffffffe,0xffffffff]

# =============================================================================
# Tests
# =============================================================================

print("Running fuzz_net rigorous validators ...", file=sys.stderr)

# 1. fuzz_net_xor_checksum ----------------------------------------------------
TOOL = "fuzz_net_xor_checksum"
for data in [b"", b"\x00", b"\xff", b"\x41\x42\x43", b"\xde\xad\xbe\xef"]:
    truth = py_xor_checksum(data)
    status, r = call(TOOL, {"data_hex": data.hex()})
    if status == "ok":
        check(TOOL, "checksum", r.get("checksum"), truth, f"data={data.hex()!r}")
        check(TOOL, "len",      r.get("len"),      len(data))
    else:
        fail(TOOL, f"call failed: {status} {r}")

# 2. fuzz_net_add_checksum ----------------------------------------------------
TOOL = "fuzz_net_add_checksum"
for data in [b"", b"\x00", b"\xff", b"\x41\x42\x43", b"\xde\xad\xbe\xef", b"\x80\x80"]:
    truth = py_add_checksum(data)
    status, r = call(TOOL, {"data_hex": data.hex()})
    if status == "ok":
        check(TOOL, "checksum", r.get("checksum"), truth, f"data={data.hex()!r}")
    else:
        fail(TOOL, f"call failed: {status} {r}")

# 3. fuzz_net_frame_u32_le ----------------------------------------------------
# args_to_bytes accepts key "hex" or "bytes"
TOOL = "fuzz_net_frame_u32_le"
for data in [b"", b"hello", b"\xde\xad\xbe\xef", b"A" * 100]:
    truth = py_frame_u32_le(data)
    status, r = call(TOOL, {"hex": data.hex()})
    if status == "ok":
        check(TOOL, "hex",    r.get("hex"),    truth.hex(), f"payload={data.hex()!r}")
        check(TOOL, "length", r.get("length"), len(truth))
    else:
        fail(TOOL, f"call failed: {status} {r}")

# 4. fuzz_net_frame_u32_be ----------------------------------------------------
TOOL = "fuzz_net_frame_u32_be"
for data in [b"", b"hello", b"\xde\xad\xbe\xef"]:
    truth = py_frame_u32_be(data)
    status, r = call(TOOL, {"hex": data.hex()})
    if status == "ok":
        check(TOOL, "hex",    r.get("hex"),    truth.hex(), f"payload={data.hex()!r}")
        check(TOOL, "length", r.get("length"), len(truth))
    else:
        fail(TOOL, f"call failed: {status} {r}")

# 5. fuzz_net_decode_frame_u32_le ---------------------------------------------
TOOL = "fuzz_net_decode_frame_u32_le"
# complete frame (payload = b"AB")
framed = py_frame_u32_le(b"AB")
status, r = call(TOOL, {"hex": framed.hex()})
truth = py_decode_frame_u32_le(framed)   # (6, b"AB")
if status == "ok":
    check(TOOL, "found",       r.get("found"),       True,       "complete AB le")
    check(TOOL, "payload_hex", r.get("payload_hex"), b"AB".hex())
    check(TOOL, "total_len",   r.get("total_len"),   truth[0])
else:
    fail(TOOL, f"complete frame: {status} {r}")

# truncated frame (header only)
buf = struct.pack("<I", 5)
status, r = call(TOOL, {"hex": buf.hex()})
if status == "ok":
    check(TOOL, "found", r.get("found"), False, "truncated le")
else:
    fail(TOOL, f"truncated: {status} {r}")

# empty
status, r = call(TOOL, {"hex": ""})
if status == "ok":
    check(TOOL, "found", r.get("found"), False, "empty le")
else:
    fail(TOOL, f"empty: {status} {r}")

# 6. fuzz_net_decode_frame_u32_be_ext -----------------------------------------
TOOL = "fuzz_net_decode_frame_u32_be_ext"
# complete
framed = py_frame_u32_be(b"XY")
status, r = call(TOOL, {"data_hex": framed.hex()})
truth = py_decode_frame_u32_be(framed)   # (6, b"XY")
if status == "ok":
    check(TOOL, "consumed",    r.get("consumed"),    truth[0],        "complete XY be")
    check(TOOL, "payload_len", r.get("payload_len"), len(truth[1]))
else:
    fail(TOOL, f"complete: {status} {r}")

# truncated
buf = struct.pack(">I", 10)
status, r = call(TOOL, {"data_hex": buf.hex()})
if status == "ok":
    check(TOOL, "incomplete", r.get("incomplete", False), True, "truncated be")
else:
    fail(TOOL, f"truncated: {status} {r}")

# 7. fuzz_net_interesting_constants -------------------------------------------
TOOL = "fuzz_net_interesting_constants"
status, r = call(TOOL, {})
if status == "ok":
    check(TOOL, "u8",  sorted(r.get("u8",  [])), sorted(PY_INTERESTING_U8))
    check(TOOL, "u16", sorted(r.get("u16", [])), sorted(PY_INTERESTING_U16))
    check(TOOL, "u32", sorted(r.get("u32", [])), sorted(PY_INTERESTING_U32))
else:
    fail(TOOL, f"call failed: {status} {r}")

# 8. fuzz_net_response_matcher_find -------------------------------------------
TOOL = "fuzz_net_response_matcher_find"
CASES_F = [
    (b"\xde\xad", b"\x00\xde\xad\xbe", 1),      # found at 1
    (b"\xbe\xef", b"\x00\xde\xad\xbe", None),   # not found
    (b"",          b"\x00\x01\x02",     0),      # empty pattern -> 0
    (b"\xaa",     b"\xaa\xbb\xcc",      0),      # found at 0
]
for pat, buf, truth_idx in CASES_F:
    status, r = call(TOOL, {"pattern_hex": pat.hex(), "buf_hex": buf.hex()})
    if status == "ok":
        check(TOOL, "index", r.get("index"), truth_idx,
              f"pat={pat.hex()} buf={buf.hex()}")
        check(TOOL, "found", r.get("found"), truth_idx is not None,
              f"pat={pat.hex()} buf={buf.hex()}")
    else:
        fail(TOOL, f"call failed: {status} {r}")

# 9. fuzz_net_response_matcher_matches ----------------------------------------
TOOL = "fuzz_net_response_matcher_matches"
CASES_M = [
    (b"\xde\xad", b"\x00\xde\xad\xbe", True),
    (b"\xbe\xef", b"\x00\xde\xad\xbe", False),
    (b"",          b"\x00\x01",          True),
    (b"\xaa\xbb\xcc", b"\xaa\xbb",       False),  # pattern longer than buf
]
for pat, buf, truth_match in CASES_M:
    status, r = call(TOOL, {"pattern_hex": pat.hex(), "buf_hex": buf.hex()})
    if status == "ok":
        check(TOOL, "matches", r.get("matches"), truth_match,
              f"pat={pat.hex()} buf={buf.hex()}")
    else:
        fail(TOOL, f"call failed: {status} {r}")

# 10. fuzz_net_crash_classify -------------------------------------------------
TOOL = "fuzz_net_crash_classify"
# resp == expected -> no crash
status, r = call(TOOL, {"response_hex": "414243", "expected_hex": "414243"})
if status == "ok":
    check(TOOL, "is_crash", r.get("is_crash"), False, "resp==expected")
else:
    fail(TOOL, f"match case: {status} {r}")

# empty resp with non-empty expected -> likely crash or interesting
status, r = call(TOOL, {"response_hex": "", "expected_hex": "414243"})
if status == "ok":
    tools_hardened.add(TOOL)
    kind = r.get("kind", "")
    if isinstance(kind, str) and len(kind) > 0:
        checks_passed += 1
    else:
        fail(TOOL, "empty kind string for mismatch case")

# 11. fuzz_net_crash_classify_reason ------------------------------------------
TOOL = "fuzz_net_crash_classify_reason"
status, r = call(TOOL, {"reason": "disconnected"})
if status == "ok":
    check(TOOL, "is_crash", r.get("is_crash"), True, "reason=disconnected")
    check(TOOL, "reason",   r.get("reason"),   "disconnected")
else:
    fail(TOOL, f"disconnected: {status} {r}")

status, r = call(TOOL, {"reason": "timeout"})
if status == "ok":
    tools_hardened.add(TOOL)
    kind = r.get("kind", "")
    if isinstance(kind, str) and len(kind) > 0:
        checks_passed += 1
    else:
        fail(TOOL, "empty kind for timeout reason")
else:
    fail(TOOL, f"timeout: {status} {r}")

# 12. fuzz_net_protocol_load_yaml ---------------------------------------------
# Correct list-based YAML format (from tests in lib.rs)
TOOL = "fuzz_net_protocol_load_yaml"
YAML = """initial_state: start
states:
  - name: start
    transitions:
      - to: done
  - name: done
"""
status, r = call(TOOL, {"yaml": YAML})
if status == "ok":
    check(TOOL, "state_count",       r.get("state_count"),       2, "2-state proto")
    check(TOOL, "validation_errors", r.get("validation_errors"), [], "no errors")
    edges = r.get("edges", [])
    tools_hardened.add(TOOL)
    has_edge = any("start" in e and "done" in e for e in edges)
    if has_edge:
        checks_passed += 1
    else:
        fail(TOOL, f"start->done edge not found in {edges}")
else:
    fail(TOOL, f"call failed: {status} {r}")

# =============================================================================
# Finalise
# =============================================================================
p.stdin.close()
p.wait()

report = {
    "module": "fuzz_net",
    "tools_hardened": len(tools_hardened),
    "tool_names": sorted(tools_hardened),
    "checks_passed": checks_passed,
    "checks_failed": checks_failed,
    "mismatches": mismatches,
}

with open(OUT, "w") as f:
    json.dump(report, f, indent=2)

print(f"Done. passed={checks_passed} failed={checks_failed} "
      f"tools_hardened={len(tools_hardened)}", file=sys.stderr)
print(f"Report -> {OUT}", file=sys.stderr)
if mismatches:
    print("\nMISMATCHES:", file=sys.stderr)
    for m in mismatches:
        print(f"  {m}", file=sys.stderr)

sys.exit(0 if checks_failed == 0 else 1)
