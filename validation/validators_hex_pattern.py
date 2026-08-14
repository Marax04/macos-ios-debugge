#!/usr/bin/env python3
"""Independent Python validator for hex_pattern_* MCP tools."""
import json, subprocess, re

EXE = r"C:\Users\Fra\Desktop\RustRE\target\release\rustre-mcp.exe"
OUT = r"C:\Users\Fra\Desktop\RustRE\validation\mismatch_hex_pattern.json"

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
    if not resp: return None, "no_resp"
    if "error" in resp: return None, "err:"+str(resp["error"])[:200]
    result = resp.get("result",{})
    c = result.get("content",[])
    if not c: return None, "empty"
    txt = c[0].get("text","")
    if result.get("isError"):
        return None, "tool_err:"+txt[:200]
    try: return json.loads(txt), None
    except: return txt, None

send({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}})
tl = recv()
tools = [t for t in tl["result"]["tools"] if t["name"].startswith("hex_pattern_")]
tool_names = {t["name"]: t for t in tools}

mismatches = []
passed = 0
total = 0
skipped_tools = set()
skipped_calls = 0

def check(name, mcp, truth, inp, note=""):
    global passed, total
    total += 1
    if mcp == truth:
        passed += 1
        return True
    mismatches.append({"tool":name,"input":inp,"mcp":mcp,"truth":truth,"note":note})
    return False

def skip(name, reason):
    global skipped_calls
    skipped_calls += 1
    skipped_tools.add(name)

def parse_pat(pat):
    s = pat.replace(" ", "")
    out = []
    i = 0
    while i < len(s):
        t = s[i:i+2]
        if t == "??":
            out.append(None)
        else:
            try: out.append(int(t,16))
            except: return None
        i += 2
    return out

def wildcard_count(pat):
    parsed = parse_pat(pat)
    return sum(1 for b in parsed if b is None) if parsed is not None else None

def specificity(pat):
    parsed = parse_pat(pat)
    if not parsed: return None
    concrete = sum(1 for b in parsed if b is not None)
    return concrete / len(parsed)

def search_all(pat, data):
    parsed = parse_pat(pat)
    if parsed is None: return []
    hits = []
    for i in range(len(data) - len(parsed) + 1):
        ok = True
        for j,b in enumerate(parsed):
            if b is not None and data[i+j] != b:
                ok = False; break
        if ok: hits.append(i)
    return hits

data_hex = "AABBCCDDEE00112233AABBCCDDFF"
data = bytes.fromhex(data_hex)
data_list = list(data)

def get_val(r, *keys):
    if not isinstance(r, dict): return None
    for k in keys:
        if k in r: return r[k]
    return None

def norm_positions(val):
    if not isinstance(val, list): return None
    out = []
    for x in val:
        if isinstance(x, dict):
            out.append(x.get("offset", x.get("position", x.get("index"))))
        elif isinstance(x, list) and len(x) >= 1:
            # [start,end] pair -> take start
            out.append(x[0])
        else:
            out.append(x)
    return sorted(out)

# helper: bytes arg may accept list of ints
BYTES_ARG = data_list

# 1. hex_pattern_wildcard_count
tn = "hex_pattern_wildcard_count"
if tn in tool_names:
    for pat in ["AA ?? BB ?? ?? CC", "DEADBEEF", "?? ?? ?? ??"]:
        r,e = call(tn, {"pattern": pat})
        if r is None: skip(tn, e); continue
        val = get_val(r, "wildcard_count","count","wildcards","n","result")
        check(tn, val, wildcard_count(pat), {"pattern":pat})

# 2. hex_pattern_specificity  (spec = concrete/total)
tn = "hex_pattern_specificity"
if tn in tool_names:
    for pat in ["AA BB CC DD", "AA ?? BB ??", "?? ?? ?? ??", "AABBCC"]:
        r,e = call(tn, {"pattern": pat})
        if r is None: skip(tn, e); continue
        val = get_val(r, "specificity","score","value","result")
        t = specificity(pat)
        if isinstance(val,(int,float)) and t is not None:
            ok = abs(val-t)<1e-6 or abs(val-t*100.0)<1e-4
            check(tn, ok, True, {"pattern":pat}, f"val={val} t={t}")
        else:
            skip(tn, "no numeric returned")

# 3. hex_pattern_exact_count
tn = "hex_pattern_exact_count"
if tn in tool_names:
    for pat in ["AA BB ?? CC ??", "AABB", "?? ??"]:
        r,e = call(tn, {"pattern": pat})
        if r is None: skip(tn, e); continue
        val = get_val(r, "exact_count","count","concrete","exact_bytes","result")
        parsed = parse_pat(pat)
        truth = sum(1 for b in parsed if b is not None)
        check(tn, val, truth, {"pattern":pat})

# 4. hex_pattern_to_bytes
tn = "hex_pattern_to_bytes"
if tn in tool_names:
    for pat in ["DEADBEEF", "00112233"]:
        r,e = call(tn, {"pattern": pat})
        if r is None: skip(tn, e); continue
        val = get_val(r, "bytes","value","result")
        truth = list(bytes.fromhex(pat))
        if isinstance(val, str):
            try: val = list(bytes.fromhex(val))
            except: pass
        check(tn, val, truth, {"pattern":pat})

# 5. hex_pattern_matches_at (uses bytes as list of ints)
tn = "hex_pattern_matches_at"
if tn in tool_names:
    cases = [("AABBCC", 0, True), ("AABBCC", 1, False),
             ("??BBCC", 0, True), ("001122", 5, True), ("001122", 4, False)]
    for pat, off, truth in cases:
        r,e = call(tn, {"pattern": pat, "bytes": BYTES_ARG, "offset": off})
        if r is None: skip(tn, e); continue
        val = get_val(r, "matches","result","match","matched")
        check(tn, bool(val), truth, {"pattern":pat,"offset":off})

# 6. hex_pattern_search  (bytes = list)
tn = "hex_pattern_search"
if tn in tool_names:
    # Note: hex_pattern_search seems to require spaced tokens
    cases = [("AA BB CC DD", [0, 9]), ("00 11 22 33", [5]), ("AA BB CC", [0,9])]
    for pat, truth in cases:
        r,e = call(tn, {"pattern": pat, "bytes": BYTES_ARG})
        if r is None: skip(tn, e); continue
        val = get_val(r, "offsets","matches","positions","results","hits")
        norm = norm_positions(val)
        check(tn, norm, sorted(truth), {"pattern":pat})

# 7. hex_pattern_canonicalize
tn = "hex_pattern_canonicalize"
if tn in tool_names:
    for pat, truth in [("aa bb cc", "AABBCC"), ("de ad ?? ef", "DEAD??EF")]:
        r,e = call(tn, {"pattern": pat})
        if r is None: skip(tn, e); continue
        val = get_val(r, "canonical","pattern","result","normalized")
        if isinstance(val, str):
            norm = val.replace(" ","").upper()
            check(tn, norm, truth, {"pattern":pat})
        else: skip(tn,"not str")

# 8. hex_pattern_parse - length
tn = "hex_pattern_parse"
if tn in tool_names:
    for pat, truth in [("AABBCC",3),("AA ?? BB",3),("DEADBEEF",4)]:
        r,e = call(tn, {"pattern": pat})
        if r is None: skip(tn, e); continue
        val = get_val(r, "length","len","size","byte_count","count")
        # sometimes parse returns nested pattern with bytes list
        if val is None and isinstance(r, dict):
            for k in ("bytes","tokens","pattern"):
                if k in r and isinstance(r[k], list):
                    val = len(r[k]); break
        check(tn, val, truth, {"pattern":pat})

# 9. hex_pattern_masked_len_v4
tn = "hex_pattern_masked_len_v4"
if tn in tool_names:
    for pat, truth in [("AABBCC",3),("AA ?? BB",3),("DEADBEEF",4)]:
        r,e = call(tn, {"pattern": pat})
        if r is None: skip(tn, e); continue
        val = get_val(r, "length","len","size","result")
        check(tn, val, truth, {"pattern":pat})

# 10. hex_pattern_byte_mask_specificity_v3 (mask,value)
# ground truth: fraction of mask bits set = popcount(mask)/8
tn = "hex_pattern_byte_mask_specificity_v3"
if tn in tool_names:
    for mask, value in [(0xFF, 0xAA), (0x0F, 0x0A), (0x00, 0x00), (0xF0, 0xA0)]:
        r,e = call(tn, {"mask": mask, "value": value})
        if r is None: skip(tn, e); continue
        val = get_val(r, "specificity","score","value","result")
        truth = bin(mask).count("1") / 8.0
        if isinstance(val,(int,float)):
            ok = abs(val-truth)<1e-6 or abs(val-truth*100.0)<1e-4 or val==bin(mask).count("1")
            check(tn, ok, True, {"mask":mask,"value":value}, f"val={val} t={truth}")

# 11. hex_pattern_bmh_search_v3
tn = "hex_pattern_bmh_search_v3"
if tn in tool_names:
    for needle, truth in [("AABBCC", [0,9]), ("001122", [5]), ("FF", [13])]:
        r,e = call(tn, {"needle_hex": needle, "haystack_hex": data_hex})
        if r is None: skip(tn, e); continue
        val = get_val(r, "offsets","matches","positions","hits","results")
        norm = norm_positions(val)
        check(tn, norm, sorted(truth), {"needle":needle})

# 12. hex_pattern_range_expand_v3 (lo, hi)
tn = "hex_pattern_range_expand_v3"
if tn in tool_names:
    r,e = call(tn, {"lo": 0xAA, "hi": 0xCC})
    if r is None: skip(tn, e)
    else:
        val = get_val(r, "bytes","values","range","result")
        truth = list(range(0xAA, 0xCD))
        check(tn, val, truth, {"lo":0xAA,"hi":0xCC})
    r,e = call(tn, {"lo": 0x10, "hi": 0x12})
    if r is None: skip(tn, e)
    else:
        val = get_val(r, "bytes","values","range","result")
        check(tn, val, [0x10,0x11,0x12], {"lo":0x10,"hi":0x12})

# 13. hex_pattern_to_hex_string_v3 (arg name: pat)
tn = "hex_pattern_to_hex_string_v3"
if tn in tool_names:
    for pat, truth in [("AA BB CC", "AABBCC"), ("DE AD BE EF", "DEADBEEF")]:
        r,e = call(tn, {"pat": pat})
        if r is None: skip(tn, e); continue
        val = get_val(r, "hex","hex_string","result","string","pat")
        if isinstance(val, str):
            check(tn, val.replace(" ","").upper(), truth, {"pat":pat})

# 14. hex_pattern_nfa_find_first_v3
tn = "hex_pattern_nfa_find_first_v3"
if tn in tool_names:
    r,e = call(tn, {"pat": "AA BB CC", "data_hex": data_hex})
    if r is None: skip(tn, e)
    else:
        val = get_val(r, "hit","offset","position","index","match","result")
        # hit is [start,end] pair
        if isinstance(val, list) and val: val = val[0]
        elif isinstance(val, dict): val = val.get("offset", val.get("position"))
        check(tn, val, 0, {"pat":"AA BB CC"})
    # miss case
    r,e = call(tn, {"pat": "EE EE EE", "data_hex": data_hex})
    if r is None: skip(tn, e)
    else:
        val = get_val(r, "hit","offset","position","index","match","result")
        no_match = val is None or val == -1
        check(tn, no_match, True, {"pat":"EE EE EE"}, "no-match sentinel")

# 15. hex_pattern_nfa_find_all_v3
tn = "hex_pattern_nfa_find_all_v3"
if tn in tool_names:
    r,e = call(tn, {"pat": "AA BB CC", "data_hex": data_hex})
    if r is None: skip(tn, e)
    else:
        val = get_val(r, "offsets","matches","positions","hits","results")
        check(tn, norm_positions(val), [0,9], {"pat":"AA BB CC"})

# 16. hex_pattern_dfa_search_v3
tn = "hex_pattern_dfa_search_v3"
if tn in tool_names:
    r,e = call(tn, {"pat": "AA BB CC", "data_hex": data_hex})
    if r is None: skip(tn, e)
    else:
        val = get_val(r, "offsets","matches","positions","hits","results")
        check(tn, norm_positions(val), [0,9], {"pat":"AA BB CC"})

# 17. hex_pattern_masked_search  (bytes list)
tn = "hex_pattern_masked_search"
if tn in tool_names:
    for pat, truth in [("AABBCC", [0,9]), ("??BBCC", [0,9])]:
        r,e = call(tn, {"pattern": pat, "bytes": BYTES_ARG})
        if r is None: skip(tn, e); continue
        val = get_val(r, "offsets","matches","positions","hits")
        check(tn, norm_positions(val), sorted(truth), {"pattern":pat})

# 18. hex_pattern_compiled_search
tn = "hex_pattern_compiled_search"
if tn in tool_names:
    r,e = call(tn, {"pattern": "AABBCC", "bytes": BYTES_ARG})
    if r is None: skip(tn, e)
    else:
        val = get_val(r, "offsets","matches","positions","hits")
        check(tn, norm_positions(val), [0,9], {"pattern":"AABBCC"})

# 19. hex_pattern_compiled_matches_at
tn = "hex_pattern_compiled_matches_at"
if tn in tool_names:
    for pat, off, truth in [("AABBCC",0,True),("AABBCC",1,False),("001122",5,True)]:
        r,e = call(tn, {"pattern": pat, "bytes": BYTES_ARG, "offset": off})
        if r is None: skip(tn, e); continue
        val = get_val(r, "matches","result","match","matched")
        check(tn, bool(val), truth, {"pattern":pat,"offset":off})

# 20. hex_pattern_masked_matches_at (bytes, mask, data, offset)
# mask: 0xFF=must match, 0x00=wildcard. bytes = target pattern.
tn = "hex_pattern_masked_matches_at"
if tn in tool_names:
    # want to match AABBCC at offset 0 in data
    cases = [
        ([0xAA,0xBB,0xCC], [0xFF,0xFF,0xFF], 0, True),
        ([0xAA,0xBB,0xCC], [0xFF,0xFF,0xFF], 1, False),
        ([0x00,0xBB,0xCC], [0x00,0xFF,0xFF], 0, True),  # first byte wildcard
        ([0xAA,0xBB,0xDD], [0xFF,0xFF,0xFF], 0, False),
    ]
    for bs, mask, off, truth in cases:
        r,e = call(tn, {"bytes": bs, "mask": mask, "data": data_list, "offset": off})
        if r is None: skip(tn, e); continue
        val = get_val(r, "matches","result","match","matched")
        check(tn, bool(val), truth, {"bytes":bs,"mask":mask,"offset":off})

# 21. hex_pattern_masked_new  (bytes, mask) -> should return a struct
tn = "hex_pattern_masked_new"
if tn in tool_names:
    r,e = call(tn, {"bytes":[0xAA,0xBB], "mask":[0xFF,0x00]})
    if r is None: skip(tn, e)
    else:
        # just verify len/size field or that bytes/mask are echoed
        # ground truth: length 2
        found_bytes = get_val(r, "bytes")
        if found_bytes == [0xAA,0xBB]:
            check(tn, True, True, {"bytes":[0xAA,0xBB],"mask":[0xFF,0x00]}, "roundtrip bytes")
        else:
            # try length field
            ln = get_val(r, "length","len","size")
            check(tn, ln, 2, {"bytes":[0xAA,0xBB]})

# 22. hex_pattern_crc16_ibm
# CRC-16/IBM (aka ARC): poly 0xA001 reflected, init 0
def crc16_ibm(data):
    crc = 0
    for b in data:
        crc ^= b
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ 0xA001
            else:
                crc >>= 1
    return crc & 0xFFFF
tn = "hex_pattern_crc16_ibm"
if tn in tool_names:
    for bs in [[0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x39], [0xAA,0xBB,0xCC]]:
        r,e = call(tn, {"bytes": bs})
        if r is None: skip(tn, e); continue
        val = get_val(r, "crc","crc16","value","result")
        check(tn, val, crc16_ibm(bs), {"bytes":bs})

# 23. hex_pattern_sequence_search_v3 (entries, data_hex)
# entries likely list of hex strings; check first match offset
tn = "hex_pattern_sequence_search_v3"
if tn in tool_names:
    # try both entry shapes
    tried = False
    for entries in [["AABBCC","001122"], [{"hex":"AABBCC"},{"hex":"001122"}], [{"pat":"AABBCC"}]]:
        r,e = call(tn, {"entries": entries, "data_hex": data_hex})
        if r is not None:
            tried = True
            val = get_val(r, "offsets","matches","positions","hits","results","found")
            # We just verify some list is returned with expected count>=1 for AABBCC (present)
            if isinstance(val, list):
                # If entries contain AABBCC and 001122 both present, result should be nonempty
                check(tn, len(val)>0, True, {"entries":entries}, f"got {val}")
                break
    if not tried: skip(tn, "no working schema")

# ---- report ----
try: p.terminate()
except: pass

report = {
    "category": "hex_pattern",
    "tools_in_category": len(tools),
    "checks_total": total,
    "checks_passed": passed,
    "checks_skipped": skipped_calls,
    "mismatches": mismatches,
}
with open(OUT, "w") as f: json.dump(report, f, indent=2, default=str)
print(json.dumps({k:v for k,v in report.items() if k!="mismatches"}, indent=2))
print(f"MISMATCHES: {len(mismatches)}")
for m in mismatches[:15]:
    print(" -", m["tool"], m.get("note",""), "mcp=",str(m["mcp"])[:80],"truth=",str(m["truth"])[:80])
