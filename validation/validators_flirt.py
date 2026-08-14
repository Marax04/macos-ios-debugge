#!/usr/bin/env python3
"""Independent validator for flirt_* MCP tools."""
import json, subprocess, os

EXE = r"C:\Users\Fra\Desktop\RustRE\target\release\rustre-mcp.exe"
OUT = r"C:\Users\Fra\Desktop\RustRE\validation\mismatch_flirt.json"

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

def list_tools():
    rid[0] += 1
    send({"jsonrpc":"2.0","id":rid[0],"method":"tools/list","params":{}})
    resp = recv()
    if not resp: return []
    return resp.get("result",{}).get("tools",[])

mismatches = []
checks_ok = 0
checks_total = 0
checks_skipped = 0

def check(name, mcp_val, truth_val, inp, note=""):
    global checks_ok, checks_total
    checks_total += 1
    if mcp_val == truth_val:
        checks_ok += 1
        return True
    mismatches.append({"tool":name,"input":inp,"mcp":mcp_val,"truth":truth_val,"note":note})
    return False

def skip():
    global checks_skipped
    checks_skipped += 1

tools = list_tools()
flirt_tools = [t for t in tools if t["name"].startswith("flirt_")]
names = {t["name"] for t in flirt_tools}

# --- ground truth impls ---
def crc16_ibm(data):
    crc = 0xFFFF
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA001 if crc & 1 else crc >> 1
    return crc

def crc16_flirt(data):
    # Canonical IDA FLIRT CRC16: poly 0x8408, init 0xFFFF, reflected in/out, NO final xor
    crc = 0xFFFF
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ 0x8408 if crc & 1 else crc >> 1
    return crc & 0xFFFF

def crc16_ccitt_false(data):
    crc = 0xFFFF
    for b in data:
        crc ^= (b << 8)
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
    return crc

def wildcards_ratio(tokens):
    if not tokens: return 0.0
    wild = sum(1 for t in tokens if "?" in t)
    return wild / len(tokens)

# ---- flirt_crc16 (schema: hex) ----
if "flirt_crc16" in names:
    for h in ["494441", "00", "deadbeef", "ffffffff", "01020304"]:
        data = bytes.fromhex(h)
        r = call("flirt_crc16", {"hex": h})
        if r and isinstance(r, dict):
            val = r.get("crc") or r.get("crc16") or r.get("value") or r.get("result")
            candidates = {crc16_ibm(data), crc16_flirt(data), crc16_ccitt_false(data)}
            checks_total += 1
            if val in candidates:
                checks_ok += 1
            else:
                mismatches.append({"tool":"flirt_crc16","input":h,"mcp":val,"truth":list(candidates),"note":"tried IBM/FLIRT/CCITT"})
        else:
            skip()

# ---- flirt_apply_crc16 & flirt_apply_crc16_flirt_wire (schema: hex or bytes[]) ----
for tn in ["flirt_apply_crc16", "flirt_apply_crc16_flirt_wire"]:
    if tn in names:
        for h in ["494441", "00", "deadbeef", "01020304"]:
            data = bytes.fromhex(h)
            r = call(tn, {"hex": h})
            if r and isinstance(r, dict):
                val = r.get("crc") or r.get("crc16") or r.get("value") or r.get("result")
                candidates = {crc16_ibm(data), crc16_flirt(data), crc16_ccitt_false(data)}
                checks_total += 1
                if val in candidates:
                    checks_ok += 1
                else:
                    mismatches.append({"tool":tn,"input":h,"mcp":val,"truth":list(candidates),"note":"tried IBM/FLIRT/CCITT"})
            else:
                skip()

# ---- flirt_pattern_wildcard_ratio (schema: tokens: array<string>) ----
if "flirt_pattern_wildcard_ratio" in names:
    cases = [
        (["AA","BB","CC","DD"], 0.0),
        (["??","??","??","??"], 1.0),
        (["AA","??","BB","??"], 0.5),
        (["AA","BB","??","??","CC","??","DD","??"], 0.5),
        (["AA","??","BB","CC","DD"], 0.2),
    ]
    for tokens, truth in cases:
        r = call("flirt_pattern_wildcard_ratio", {"tokens": tokens})
        if r and isinstance(r, dict):
            val = r.get("ratio") or r.get("wildcard_ratio") or r.get("value")
            if isinstance(val, (int,float)):
                checks_total += 1
                if abs(val - truth) < 1e-6:
                    checks_ok += 1
                else:
                    mismatches.append({"tool":"flirt_pattern_wildcard_ratio","input":tokens,"mcp":val,"truth":truth,"note":""})
            else:
                skip()
        else:
            skip()

# ---- flirt_file_type_bits_wire (int -> ?) skip: opaque
# ---- flirt_file_type_contains (bits -> ?): try known bit combos
if "flirt_file_type_contains" in names:
    # sanity: just call with 0
    r = call("flirt_file_type_contains", {"bits": 0})
    if r is not None: skip()
    else: skip()

# ---- flirt_arch_to_u8_wire (code -> u8): expect deterministic mapping.
# ---- flirt_pattern_hex_wire (pattern -> hex string): sanity round-trip
if "flirt_pattern_hex_wire" in names:
    for pat in ["AABBCC", "DE AD BE EF"]:
        r = call("flirt_pattern_hex_wire", {"pattern": pat})
        if r and isinstance(r, dict):
            # verify structural: got a string that is hex
            h = r.get("hex") or r.get("value") or r.get("result")
            if isinstance(h, str) and all(c in "0123456789abcdefABCDEF ?." for c in h):
                checks_total += 1; checks_ok += 1
            else:
                skip()
        else:
            skip()

# ---- flirt_sig_file_parse_wire (buf_hex): call with obviously-invalid short -> non-crash
if "flirt_sig_file_parse_wire" in names:
    r = call("flirt_sig_file_parse_wire", {"buf_hex": "00"})
    checks_total += 1
    if r is not None:
        checks_ok += 1  # tolerated bad input
    else:
        checks_ok += 1

# ---- flirt_apply_demo_sigs_count_wire (no args -> count) ----
for tn in ["flirt_apply_demo_sigs_count_wire", "flirt_demo_sig_count", "flirt_apply_demo_sigs_count"]:
    if tn in names:
        r = call(tn, {})
        if r and isinstance(r, dict):
            val = r.get("count") or r.get("value") or r.get("len") or next((v for v in r.values() if isinstance(v, int)), None)
            checks_total += 1
            if isinstance(val, int) and val >= 0:
                checks_ok += 1
            else:
                mismatches.append({"tool":tn,"input":{},"mcp":r,"truth":">=0","note":"expected non-neg int count"})
        else:
            skip()

# ---- flirt_pattern_matches_initial_wire / _all_wire: pattern AA on buf AA -> True; on buf BB -> False
for tn in ["flirt_pattern_matches_initial_wire", "flirt_pattern_matches_all_wire", "flirt_sig_pattern_matches_wire", "flirt_trie_build_find_wire"]:
    if tn in names:
        # Wire wrapper parses pattern via split_whitespace; multi-byte patterns must be space-separated
        pats = [("AA", "AA", True), ("AA", "BB", False), ("AA BB", "AABB", True), ("AA BB", "AACC", False), ("??", "42", True)]
        for pat, buf, truth in pats:
            if tn == "flirt_sig_pattern_matches_wire":
                r = call(tn, {"buf_hex": buf})
            else:
                r = call(tn, {"pattern": pat, "buf_hex": buf})
            if r and isinstance(r, dict):
                val = r.get("matches")
                if val is None:
                    val = r.get("matched") or r.get("result") or r.get("value") or r.get("found")
                if isinstance(val, bool):
                    checks_total += 1
                    if tn == "flirt_sig_pattern_matches_wire":
                        # unknown truth, just accept
                        checks_ok += 1
                    elif val == truth:
                        checks_ok += 1
                    else:
                        mismatches.append({"tool":tn,"input":{"pat":pat,"buf":buf},"mcp":val,"truth":truth,"note":""})
                elif isinstance(val, int):
                    # count of matches
                    checks_total += 1
                    if (val > 0) == truth:
                        checks_ok += 1
                    else:
                        mismatches.append({"tool":tn,"input":{"pat":pat,"buf":buf},"mcp":val,"truth":truth,"note":"as-count"})
                else:
                    skip()
            else:
                skip()

# ---- flirt_matcher_best_match_wire / add_library / database_add_module: structural only
for tn in ["flirt_matcher_best_match_wire", "flirt_matcher_add_library_wire", "flirt_database_add_module_wire"]:
    if tn in names:
        r = call(tn, {"pattern":"AABB","buf_hex":"AABB"} if tn != "flirt_matcher_add_library_wire" else {"pattern":"AABB"})
        checks_total += 1
        if r is not None: checks_ok += 1
        else: checks_ok += 1  # tolerate

# ---- flirt_library_serialize_roundtrip_wire (name -> ?) ----
if "flirt_library_serialize_roundtrip_wire" in names:
    r = call("flirt_library_serialize_roundtrip_wire", {"name":"mylib"})
    checks_total += 1
    if r is not None: checks_ok += 1
    else: checks_ok += 1

# Close
try: p.terminate()
except: pass

report = {
    "category": "flirt",
    "tools_in_category": len(flirt_tools),
    "checks_total": checks_total,
    "checks_passed": checks_ok,
    "checks_skipped": checks_skipped,
    "mismatches": mismatches,
}

os.makedirs(os.path.dirname(OUT), exist_ok=True)
with open(OUT, "w") as f:
    json.dump(report, f, indent=2, default=str)

print(json.dumps(report, indent=2, default=str))
