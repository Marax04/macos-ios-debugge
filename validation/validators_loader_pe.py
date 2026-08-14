#!/usr/bin/env python3
"""Independent validator for loader_pe_* MCP tools.

Ground truth computed via pefile + hand-parsed structures.
"""
import json, subprocess, sys, os, struct

EXE = r"C:\Users\Fra\Desktop\RustRE\target\release\rustre-mcp.exe"
TARGET = r"C:\Users\Fra\Desktop\Zyphora\target\release\cargo-zyphora.exe"
OUT = r"C:\Users\Fra\Desktop\RustRE\validation\mismatch_loader_pe.json"

try:
    import pefile
    HAVE_PEFILE = True
except Exception:
    HAVE_PEFILE = False

with open(TARGET, "rb") as f:
    RAW = f.read()

# Hand-parse minimal PE
assert RAW[:2] == b"MZ"
PE_OFF = struct.unpack_from("<I", RAW, 0x3C)[0]
assert RAW[PE_OFF:PE_OFF+4] == b"PE\x00\x00"
COFF = PE_OFF + 4
NUM_SECTIONS = struct.unpack_from("<H", RAW, COFF+2)[0]
OPT_HDR_SIZE = struct.unpack_from("<H", RAW, COFF+16)[0]
OPT_HDR_OFF = COFF + 20
MAGIC = struct.unpack_from("<H", RAW, OPT_HDR_OFF)[0]
IS_PE32PLUS = MAGIC == 0x20b
if IS_PE32PLUS:
    ENTRY_RVA = struct.unpack_from("<I", RAW, OPT_HDR_OFF+16)[0]
    IMAGE_BASE = struct.unpack_from("<Q", RAW, OPT_HDR_OFF+24)[0]
else:
    ENTRY_RVA = struct.unpack_from("<I", RAW, OPT_HDR_OFF+16)[0]
    IMAGE_BASE = struct.unpack_from("<I", RAW, OPT_HDR_OFF+28)[0]

if HAVE_PEFILE:
    PE = pefile.PE(TARGET, fast_load=True)
    PE.parse_data_directories(directories=[
        pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT'],
        pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT'],
    ])
    IMPORT_DLLS = [d.dll.decode(errors='replace') for d in (PE.DIRECTORY_ENTRY_IMPORT or [])]
    IMPORT_COUNT = sum(len(d.imports) for d in (PE.DIRECTORY_ENTRY_IMPORT or []))
else:
    IMPORT_DLLS, IMPORT_COUNT = [], None

# ------------------------------------------------------------
# MCP client
# ------------------------------------------------------------
proc = subprocess.Popen([EXE, "--transport=stdio"], stdin=subprocess.PIPE,
                        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, bufsize=0)
rid = [1]
def send(r): proc.stdin.write((json.dumps(r)+"\n").encode()); proc.stdin.flush()
def recv():
    line = proc.stdout.readline()
    return json.loads(line) if line else None

send({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"v","version":"1"}}})
recv()
send({"jsonrpc":"2.0","method":"notifications/initialized"})

def call(name, args):
    rid[0] += 1
    myid = rid[0]
    send({"jsonrpc":"2.0","id":myid,"method":"tools/call","params":{"name":name,"arguments":args}})
    # loop until matching id
    for _ in range(20):
        resp = recv()
        if not resp: return None, "no-response"
        if resp.get("id") != myid: continue
        if "error" in resp: return None, resp["error"].get("message","err")
        result = resp.get("result", {})
        if result.get("isError"):
            txt = ""
            for c in result.get("content", []):
                txt += c.get("text","")
            return None, "TOOL_ERROR:"+txt[:200]
        content = result.get("content", [])
        if not content: return None, "empty"
        t = content[0].get("text","")
        try: return json.loads(t), None
        except: return t, None
    return None, "no-match"

# tools/list
rid[0] += 1
send({"jsonrpc":"2.0","id":rid[0],"method":"tools/list"})
tools_resp = recv()
while tools_resp.get("id") != rid[0]:
    tools_resp = recv()
tools = tools_resp["result"]["tools"]
loader_pe_tools = [t for t in tools if t["name"].startswith("loader_pe_")]
print(f"[info] found {len(loader_pe_tools)} loader_pe_ tools")

mismatches = []
passed = 0
skipped = 0
total = 0

def add_mismatch(tool, inp, mcp, truth, note):
    mismatches.append({"tool":tool,"input":inp,"mcp":mcp,"truth":truth,"note":note})

def check(tool, inp, mcp, truth, note=""):
    global passed, total
    total += 1
    if mcp == truth:
        passed += 1
        return True
    add_mismatch(tool, inp, mcp, truth, note or "mcp != truth")
    return False

TOOL_NAMES = {t["name"]: t for t in loader_pe_tools}

def try_call(name, arg_variants):
    """Try each arg dict; return (result, arg_used, err) on first non-error, else (None,None,last_err)."""
    if name not in TOOL_NAMES:
        return None, None, "not-in-list"
    last_err = None
    for a in arg_variants:
        r, err = call(name, a)
        if r is not None:
            return r, a, None
        last_err = err
        if err and "TOOL_ERROR" not in err and "no-response" not in err:
            # invalid schema -> keep trying
            pass
    return None, None, last_err

def val(d, *keys):
    if not isinstance(d, dict): return None
    for k in keys:
        if k in d: return d[k]
    return None

# ==============================================
# TESTS
# ==============================================

# loader_pe_parse_info / loader_pe_parse_summary etc: pass path or bytes
PATH_ARG_VARIANTS = [
    {"path": TARGET},
    {"file_path": TARGET},
    {"binary_path": TARGET},
]
BYTES_ARG_VARIANTS = [
    {"data": list(RAW[:4096])},
    {"bytes": list(RAW[:4096])},
    {"hex": RAW[:4096].hex()},
]
FULL_BYTES_ARGS = [
    {"data": list(RAW)},
    {"bytes": list(RAW)},
    {"hex": RAW.hex()},
]

# 1) loader_pe_parse_info (path-based typically)
name = "loader_pe_parse_info"
if name in TOOL_NAMES:
    r, a, err = try_call(name, PATH_ARG_VARIANTS + FULL_BYTES_ARGS)
    if r is None:
        skipped += 1
        print(f"[skip] {name}: {err}")
    else:
        # Look for image_base, entry, section count
        ib = val(r, "image_base", "imageBase", "base") or (val(r.get("info") or {}, "image_base") if isinstance(r,dict) else None)
        ep = val(r, "entry_point", "entryPoint", "entry", "address_of_entry_point")
        sc = val(r, "sections", "section_count", "num_sections")
        if isinstance(sc, list): sc = len(sc)
        checked = False
        if ib is not None:
            checked = True
            check(name, a, int(ib) if isinstance(ib,(int,float)) else ib, IMAGE_BASE, f"image_base 0x{IMAGE_BASE:x}")
        if ep is not None:
            checked = True
            # entry may be RVA or VA
            ep_i = int(ep) if isinstance(ep,(int,float)) else ep
            ok = ep_i == ENTRY_RVA or ep_i == ENTRY_RVA + IMAGE_BASE
            if not ok:
                check(name, a, ep_i, f"{ENTRY_RVA} or {ENTRY_RVA+IMAGE_BASE}", "entry mismatch")
            else:
                total += 1; passed += 1
        if sc is not None:
            checked = True
            check(name, a, sc, NUM_SECTIONS, f"section count")
        if not checked:
            skipped += 1
            print(f"[skip-nofield] {name}: keys={list(r.keys()) if isinstance(r,dict) else type(r)}")

# 2) loader_pe_entry_points
name = "loader_pe_entry_points"
if name in TOOL_NAMES:
    r, a, err = try_call(name, PATH_ARG_VARIANTS + FULL_BYTES_ARGS)
    if r is None:
        skipped += 1
        print(f"[skip] {name}: {err}")
    else:
        ep = val(r, "entry_point", "entry", "address_of_entry_point", "aep")
        if ep is None and isinstance(r, dict):
            eps = r.get("entry_points") or r.get("entries")
            if isinstance(eps, list) and eps:
                first = eps[0]
                ep = first if isinstance(first,int) else val(first if isinstance(first,dict) else {}, "address","rva","va")
        if ep is None:
            skipped += 1
            print(f"[skip-nofield] {name}: {r}")
        else:
            ep_i = int(ep)
            ok = ep_i in (ENTRY_RVA, ENTRY_RVA + IMAGE_BASE)
            total += 1
            if ok: passed += 1
            else: add_mismatch(name, a, ep_i, f"{ENTRY_RVA} or {ENTRY_RVA+IMAGE_BASE}", "entry mismatch")

# 3) loader_pe_imports_from_dll
name = "loader_pe_imports_from_dll"
if name in TOOL_NAMES and HAVE_PEFILE and IMPORT_DLLS:
    target_dll = None
    target_names = None
    for d in (PE.DIRECTORY_ENTRY_IMPORT or []):
        if d.imports:
            target_dll = d.dll.decode(errors='replace')
            target_names = set(i.name.decode(errors='replace') for i in d.imports if i.name)
            break
    for a in [
        {"path": TARGET, "dll": target_dll},
        {"path": TARGET, "dll_name": target_dll},
        {"file_path": TARGET, "dll": target_dll},
    ]:
        r, err = call(name, a)
        if r is not None:
            names_out = None
            if isinstance(r, list):
                names_out = r
            elif isinstance(r, dict):
                names_out = r.get("imports") or r.get("functions") or r.get("names") or r.get("symbols")
            if names_out and isinstance(names_out, list):
                # normalize
                got = set()
                for x in names_out:
                    if isinstance(x, str): got.add(x)
                    elif isinstance(x, dict):
                        n = x.get("name") or x.get("symbol")
                        if n: got.add(n)
                overlap = len(got & target_names)
                total += 1
                if overlap > 0 and overlap >= min(3, len(target_names)):
                    passed += 1
                else:
                    add_mismatch(name, a, list(got)[:5], list(target_names)[:5], f"overlap={overlap}/{len(target_names)}")
            else:
                skipped += 1
            break
    else:
        skipped += 1

# 4) loader_pe_is_signed
name = "loader_pe_is_signed"
if name in TOOL_NAMES:
    r, a, err = try_call(name, PATH_ARG_VARIANTS + FULL_BYTES_ARGS)
    if r is None:
        skipped += 1; print(f"[skip] {name}: {err}")
    else:
        signed = val(r, "signed", "is_signed", "has_signature")
        if HAVE_PEFILE:
            sec_dir = None
            try:
                sec_dir = PE.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']]
            except Exception: pass
            truth_signed = bool(sec_dir and sec_dir.Size > 0)
        else:
            truth_signed = False  # cargo builds usually not signed
        if signed is not None:
            check(name, a, bool(signed), truth_signed, "IMAGE_DIRECTORY_ENTRY_SECURITY")
        else:
            skipped += 1

# 5) loader_pe_pdb_path
name = "loader_pe_pdb_path"
if name in TOOL_NAMES:
    r, a, err = try_call(name, PATH_ARG_VARIANTS + FULL_BYTES_ARGS)
    if r is None:
        skipped += 1; print(f"[skip] {name}: {err}")
    else:
        p = val(r, "pdb_path", "path", "pdb")
        # pefile CV_INFO_PDB70
        truth_p = None
        if HAVE_PEFILE:
            try:
                PE.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_DEBUG']])
                for e in (PE.DIRECTORY_ENTRY_DEBUG or []):
                    if hasattr(e, 'entry') and hasattr(e.entry, 'PdbFileName'):
                        truth_p = e.entry.PdbFileName.rstrip(b'\x00').decode(errors='replace')
                        break
            except Exception: pass
        if p is not None and truth_p is not None:
            # normalize: basename compare
            mcp_base = os.path.basename(str(p)).lower()
            tr_base = os.path.basename(truth_p).lower()
            total += 1
            if mcp_base == tr_base and mcp_base:
                passed += 1
            else:
                add_mismatch(name, a, p, truth_p, "pdb path mismatch")
        else:
            skipped += 1

# ---- Simpler helper wrappers ----
# is_pe / is_elf / is_macho / is_dotnet / is_java_class : classification of raw bytes.
CLASSIFIERS = {
    "loader_is_pe": True,
    "loader_is_elf": False,
    "loader_is_macho": False,
    "loader_is_java_class": False,
    "loader_dotnet_is_dotnet": False,
    "loader_dotnet_has_clr_header": False,
    "loader_dotnet_has_clr_header_wire": False,
    "loader_dotnet_is_dotnet_wire": False,
    "loader_pe_is_signed": None,  # handled above
}

# Filter to only pe-prefixed classifiers that exist
for tname, truth in list(CLASSIFIERS.items()):
    if not tname.startswith("loader_pe_"):
        continue
    if tname not in TOOL_NAMES: continue
    if truth is None: continue
    r, a, err = try_call(tname, BYTES_ARG_VARIANTS + FULL_BYTES_ARGS + PATH_ARG_VARIANTS)
    if r is None:
        skipped += 1; print(f"[skip] {tname}: {err}"); continue
    v = r if isinstance(r,bool) else val(r, "is_pe","result","value","signed","is_signed")
    if v is None:
        skipped += 1; continue
    check(tname, a, bool(v), truth, f"raw PE classifier truth={truth}")

# ---- Loop through remaining loader_pe_ tools we haven't touched:
# For any tool that takes a "path" or bytes and returns something structural,
# just verify it doesn't crash on cargo-zyphora.exe (weak liveness check).
HANDLED = {"loader_pe_parse_info","loader_pe_entry_points","loader_pe_imports_from_dll",
           "loader_pe_is_signed","loader_pe_pdb_path"}

for tname in [t["name"] for t in loader_pe_tools]:
    if tname in HANDLED: continue
    schema = TOOL_NAMES[tname].get("inputSchema", {})
    props = schema.get("properties", {})
    required = set(schema.get("required", []))
    # If schema requires fields we can't fill, skip
    unknown_req = required - {"path","file_path","binary_path","data","bytes","hex"}
    if unknown_req:
        skipped += 1
        continue
    variants = []
    if "path" in props or "file_path" in props or "binary_path" in props:
        variants.extend(PATH_ARG_VARIANTS)
    if "data" in props or "bytes" in props or "hex" in props:
        variants.extend(FULL_BYTES_ARGS)
    if not variants:
        variants = PATH_ARG_VARIANTS + FULL_BYTES_ARGS
    r, a, err = try_call(tname, variants)
    if r is None:
        skipped += 1
        continue
    # Weak check: if it returns anything, count as pass (no independent truth for structural summary)
    # Only count as mismatch if it returns something clearly wrong (e.g., is_pe:false on a PE)
    if isinstance(r, dict):
        for k,v in r.items():
            if k in ("is_pe","valid_pe") and v is False:
                total += 1
                add_mismatch(tname, a, {k:v}, {k:True}, "target IS a PE")
                break
            if k in ("image_base","imageBase") and isinstance(v,(int,float)) and int(v) != IMAGE_BASE:
                total += 1
                add_mismatch(tname, a, {k:int(v)}, {k:IMAGE_BASE}, "image_base mismatch")
                break

# ---- Report ----
try: proc.terminate()
except: pass

report = {
    "category": "loader_pe",
    "tools_in_category": len(loader_pe_tools),
    "checks_total": total,
    "checks_passed": passed,
    "checks_skipped": skipped,
    "mismatches": mismatches,
}
with open(OUT, "w") as f: json.dump(report, f, indent=2)
print(json.dumps({k:v for k,v in report.items() if k!="mismatches"}, indent=2))
print(f"mismatches: {len(mismatches)}")
for m in mismatches[:10]:
    print(" ", m["tool"], m["note"], "mcp=", str(m["mcp"])[:80], "truth=", str(m["truth"])[:80])
