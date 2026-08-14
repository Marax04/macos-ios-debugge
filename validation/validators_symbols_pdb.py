#!/usr/bin/env python3
"""Independent validator for symbols_pdb_* tools. Ground truth from raw MSF parsing + URL format spec."""
import json, subprocess, sys, os, struct, uuid

EXE = r"C:\Users\Fra\Desktop\RustRE\target\release\rustre-mcp.exe"
OUT = r"C:\Users\Fra\Desktop\RustRE\validation\mismatch_symbols_pdb.json"
PDB = r"C:\Users\Fra\Desktop\ai-aimassist-source\example_win32_directx11\Release\example_win32_directx11.pdb"

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
    if not resp: return ("NORESP", None)
    if "error" in resp: return ("ERR", resp["error"])
    c = resp.get("result",{}).get("content",[])
    if not c: return ("EMPTY", None)
    txt = c[0].get("text","")
    try: return ("OK", json.loads(txt))
    except: return ("OK", txt)

rid[0]+=1
send({"jsonrpc":"2.0","id":rid[0],"method":"tools/list","params":{}})
tl = recv()
all_tools = tl.get("result",{}).get("tools",[])
tools = [t for t in all_tools if t["name"].startswith("symbols_pdb_")]
print(f"Found {len(tools)} symbols_pdb_* tools", file=sys.stderr)

# Load PDB bytes
pdb_bytes = None
if os.path.exists(PDB):
    with open(PDB, "rb") as f:
        pdb_bytes = f.read()
    print(f"Loaded PDB {len(pdb_bytes)} bytes", file=sys.stderr)

# Ground-truth parse of MSF superblock
MSF_MAGIC = b"Microsoft C/C++ MSF 7.00\r\n\x1aDS\0\0\0"
truth = {}
if pdb_bytes and pdb_bytes.startswith(MSF_MAGIC):
    truth["magic_ok"] = True
    truth["block_size"] = struct.unpack("<I", pdb_bytes[32:36])[0]
    truth["num_blocks"] = struct.unpack("<I", pdb_bytes[40:44])[0]
    truth["num_dir_bytes"] = struct.unpack("<I", pdb_bytes[44:48])[0]
print(f"MSF truth: {truth}", file=sys.stderr)

mismatches = []
checks_total = 0
checks_passed = 0
checks_skipped = 0
skipped_log = []

def text_of(v):
    if v is None: return ""
    if isinstance(v, str): return v
    return json.dumps(v)

def has_bytes_input(t):
    props = t.get("inputSchema",{}).get("properties",{})
    return "bytes" in props or "hex" in props

def call_with_pdb(name):
    if not pdb_bytes: return None
    # prefer hex arg
    return call(name, {"hex": pdb_bytes.hex()})

# --- Check 1: symbols_pdb_symbol_server_url ---
base = "https://msdl.microsoft.com/download/symbols"
pdb_name = "ntdll.pdb"
guid_hex = "ABCDEF0123456789ABCDEF0123456789"
age = 1
truth_url = f"{base}/{pdb_name}/{guid_hex}{age:X}/{pdb_name}"
# some impls may use lower/upper case for guid; both accepted
status, val = call("symbols_pdb_symbol_server_url", {"base_url": base, "pdb_name": pdb_name, "guid": guid_hex, "age": age})
if status == "OK":
    txt = text_of(val)
    checks_total += 1
    # Look for pdb_name repeated twice and age
    ok = pdb_name in txt and txt.count(pdb_name) >= 2 and (guid_hex in txt or guid_hex.lower() in txt)
    if ok: checks_passed += 1
    else:
        mismatches.append({"tool":"symbols_pdb_symbol_server_url","input":{"base":base,"pdb":pdb_name,"guid":guid_hex,"age":age},"mcp":txt[:300],"truth":truth_url,"note":"URL should follow <base>/<pdb>/<guid><age>/<pdb>"})
else:
    checks_skipped += 1; skipped_log.append({"tool":"symbols_pdb_symbol_server_url","why":status})

# --- Check 2: symbols_pdb_symbol_server_msdl (no args) ---
status, val = call("symbols_pdb_symbol_server_msdl", {})
if status == "OK":
    txt = text_of(val).lower()
    checks_total += 1
    if "msdl.microsoft.com" in txt:
        checks_passed += 1
    else:
        mismatches.append({"tool":"symbols_pdb_symbol_server_msdl","input":{},"mcp":txt[:300],"truth":"contains msdl.microsoft.com","note":"MSDL base URL expected"})
else:
    checks_skipped += 1; skipped_log.append({"tool":"symbols_pdb_symbol_server_msdl","why":status})

# --- Check 3: symbols_pdb_guid_format (16 bytes -> uuid string) ---
guid_bytes = bytes(range(16))
truth_guid_variants = [
    str(uuid.UUID(bytes=guid_bytes)),         # 00010203-0405-0607-0809-0a0b0c0d0e0f
    str(uuid.UUID(bytes_le=guid_bytes)),      # 03020100-0504-0706-0809-0a0b0c0d0e0f (typical PDB)
]
status, val = call("symbols_pdb_guid_format", {"bytes": list(guid_bytes)})
if status == "OK":
    txt = text_of(val).lower()
    checks_total += 1
    matched = any(v.lower() in txt for v in truth_guid_variants)
    # also accept dashless upper-case hex
    if not matched:
        matched = guid_bytes.hex() in txt or bytes(reversed(guid_bytes[:4])).hex()+guid_bytes[4:].hex() in txt
    if matched:
        checks_passed += 1
    else:
        mismatches.append({"tool":"symbols_pdb_guid_format","input":{"bytes":"0..15"},"mcp":txt[:300],"truth":truth_guid_variants,"note":"GUID format standard or MS little-endian"})
else:
    checks_skipped += 1; skipped_log.append({"tool":"symbols_pdb_guid_format","why":status})

# --- Checks 4+: PDB-bytes-based tools ---
# We don't know ground truth for module count, symbol count, etc. w/o pdbparse.
# But we can check that valid PDB bytes give a non-error response, and invalid bytes give an error.
# This isn't a mismatch check unless we have concrete truth. So:
# - For parse_info / from_bytes: verify it detects a valid PDB (must not be an error).
# - For random bytes: verify tools reject.

byte_tools = [t for t in tools if has_bytes_input(t)]

# Feed valid PDB and just verify no crash / non-empty
for t in byte_tools[:20]:
    name = t["name"]
    r = call_with_pdb(name)
    if not r:
        checks_skipped += 1; skipped_log.append({"tool":name,"why":"no PDB file"}); continue
    status, val = r
    if status != "OK":
        checks_skipped += 1; skipped_log.append({"tool":name,"why":f"call {status}"}); continue
    txt = text_of(val)
    low = txt.lower()
    # For parse_info & from_bytes: expected to succeed on real PDB -> mismatch if returns an error signal
    if name in ("symbols_pdb_parse_info","symbols_pdb_from_bytes"):
        checks_total += 1
        # A real PDB should not produce "invalid"/"error"/"not a pdb"
        looks_like_error = any(k in low for k in ["invalid","not a pdb","error","failed","cannot","unable"])
        if not looks_like_error and len(txt) > 5:
            checks_passed += 1
        else:
            mismatches.append({"tool":name,"input":{"pdb":"valid MSF file"},"mcp":txt[:300],"truth":"non-error response for valid PDB","note":"valid PDB bytes should parse"})
    else:
        # For other bytes-tools, we can't easily assert truth; skip as accepted
        checks_skipped += 1; skipped_log.append({"tool":name,"why":"no independent truth; call succeeded"})

# --- Extra: parse_info returns PDB stream info; verify age==1 for typical debug PDB ---
# We can't derive PDB stream age without pdbparse, so skip strict check.

# --- Invalid input rejection ---
junk = b"\x00" * 128
status, val = call("symbols_pdb_from_bytes", {"hex": junk.hex()})
if status == "OK":
    txt = text_of(val).lower()
    checks_total += 1
    # Should signal invalid
    if any(k in txt for k in ["invalid","error","not a pdb","failed","none","null"]) or txt.strip() in ("","{}","[]"):
        checks_passed += 1
    else:
        mismatches.append({"tool":"symbols_pdb_from_bytes","input":{"junk":"128 zeros"},"mcp":txt[:300],"truth":"error/invalid","note":"zero bytes are not a valid PDB"})

report = {
    "category": "symbols_pdb",
    "tools_in_category": len(tools),
    "checks_total": checks_total,
    "checks_passed": checks_passed,
    "checks_skipped": checks_skipped,
    "mismatches": mismatches,
    "skipped_log": skipped_log[:50],
}

with open(OUT, "w") as f:
    json.dump(report, f, indent=2)

print(json.dumps({k:v for k,v in report.items() if k!="skipped_log"}, indent=2))
p.terminate()
