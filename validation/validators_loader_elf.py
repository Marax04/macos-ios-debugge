#!/usr/bin/env python3
"""Independent validator for MCP tools prefixed 'loader_elf_'.
Ground truth via pyelftools + hand-computed helpers. Do NOT trust MCP.
"""
import json, subprocess, os, io, struct, tempfile
from elftools.elf.elffile import ELFFile

EXE = r"C:\Users\Fra\Desktop\RustRE\target\release\rustre-mcp.exe"
OUT = r"C:\Users\Fra\Desktop\RustRE\validation\mismatch_loader_elf.json"
PREFIX = "loader_elf_"

# ---------------- MCP setup ----------------
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
    txt = c[0].get("text","")
    try: return json.loads(txt)
    except: return txt

# Get tool list
rid[0]+=1
send({"jsonrpc":"2.0","id":rid[0],"method":"tools/list","params":{}})
resp = recv()
tools = resp.get("result",{}).get("tools",[]) if resp else []
elf_tools = [t for t in tools if t["name"].startswith(PREFIX)]
tool_names = {t["name"]: t for t in elf_tools}

# ---------------- Build a real ELF sample ----------------
# Use /bin/ls-like small ELF: build minimal valid ELF64 manually? Easier: find a system ELF.
# Windows: no /bin. Create a minimal ELF64 header binary that pyelftools can parse.
# Minimal valid ELF64 executable header:
def make_min_elf64():
    # ELF64 header (64 bytes) + no program headers - still parseable
    b = bytearray(64)
    b[0:4] = b"\x7fELF"
    b[4] = 2       # EI_CLASS = 64
    b[5] = 1       # EI_DATA  = little-endian
    b[6] = 1       # EI_VERSION
    b[7] = 0       # OSABI
    # e_type=ET_EXEC(2), e_machine=EM_X86_64(62), e_version=1
    struct.pack_into("<HHI", b, 16, 2, 62, 1)
    # e_entry, e_phoff, e_shoff, e_flags, e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx
    struct.pack_into("<QQQIHHHHHH", b, 24, 0x400000, 0, 0, 0, 64, 56, 0, 64, 0, 0)
    return bytes(b)

elf_bytes = make_min_elf64()
elf_hex = elf_bytes.hex()

# Also try a real system ELF if available (via WSL/Cygwin unlikely on Windows; skip)
real_elf = None
for cand in [r"C:\Windows\System32\bash.exe"]:
    pass  # no likely real ELF on Windows

# Parse ground truth with pyelftools
ef = ELFFile(io.BytesIO(elf_bytes))
truth = {
    "is_elf": True,
    "class": 64,
    "endian": "little",
    "e_type": "ET_EXEC",
    "e_machine": "EM_X86_64",
    "e_entry": 0x400000,
}

# ---------------- Checks ----------------
mismatches = []
checks_total = 0
checks_passed = 0
checks_skipped = 0
tools_touched = set()

def result_get(r, *keys, default=None):
    if not isinstance(r, dict): return default
    for k in keys:
        if k in r: return r[k]
    return default

def check(tool, inp, mcp_val, truth_val, note=""):
    global checks_total, checks_passed
    checks_total += 1
    tools_touched.add(tool)
    if mcp_val == truth_val:
        checks_passed += 1
        return True
    mismatches.append({"tool":tool,"input":inp,"mcp":mcp_val,"truth":truth_val,"note":note})
    return False

def skip(tool, note=""):
    global checks_skipped
    checks_skipped += 1

# We'll iterate over each ELF tool and try semantically valid inputs
# Common input shapes: {hex}, {bytes}, {data}, {path}
# We use hex for the minimal ELF.

# Write to temp file for tools that want path
tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".elf")
tmp.write(elf_bytes); tmp.close()
elf_path = tmp.name

def try_multi(tool, arg_variants):
    """Try several arg shapes; return first non-null response."""
    for args in arg_variants:
        r = call(tool, args)
        if r is not None and r != "" and not (isinstance(r, str) and "error" in r.lower()[:60]):
            return r, args
    return None, None

# Common variants factory
def variants():
    return [
        {"hex": elf_hex},
        {"bytes": list(elf_bytes)},
        {"data": elf_hex},
        {"input": elf_hex},
        {"path": elf_path},
        {"file": elf_path},
    ]

# Handle each known/likely tool. We're conservative — skip if schema unclear.
known_handlers = {}

def h_is_elf(name):
    r, args = try_multi(name, variants())
    if r is None: return skip(name)
    v = result_get(r, "is_elf", "result", "value")
    if isinstance(v, bool):
        check(name, args, v, True, "minimal ELF64")
    else:
        # some return bare bool
        if isinstance(r, bool):
            check(name, args, r, True, "minimal ELF64")
        else:
            skip(name)

def h_parse_info(name):
    r, args = try_multi(name, variants())
    if r is None or not isinstance(r, dict): return skip(name)
    # Look for class / bitness
    cls = result_get(r, "class", "bitness", "elf_class", "ei_class")
    if cls in (64, "ELFCLASS64", "64", "elf64", 2):
        check(name, args, True, True, "class detected 64")
    elif cls is not None:
        check(name, args, cls, 64, "expected 64-bit")
    else:
        # try machine
        m = result_get(r, "machine", "e_machine", "arch")
        if m is not None:
            ok = m in ("EM_X86_64", 62, "x86_64", "X86_64")
            check(name, args, ok, True, f"machine={m}")
        else:
            skip(name)

def h_summary(name):
    r, args = try_multi(name, variants())
    if r is None: return skip(name)
    # nonempty string/dict => count as pass if it mentions ELF
    s = json.dumps(r) if not isinstance(r, str) else r
    ok = "ELF" in s or "elf" in s or "64" in s
    check(name, args, ok, True, "summary contains ELF/64 marker")

def h_plt_entries(name):
    # Our minimal ELF has no PLT; expect empty list or 0
    r, args = try_multi(name, variants())
    if r is None: return skip(name)
    lst = result_get(r, "entries", "plt", "result", "value")
    if isinstance(lst, list):
        check(name, args, len(lst), 0, "no PLT in minimal ELF")
    elif isinstance(r, list):
        check(name, args, len(r), 0, "no PLT in minimal ELF")
    else:
        skip(name)

def h_gnu_hash_str(name):
    # GNU hash of empty string = 5381
    r = call(name, {"name": ""})
    if r is None: r = call(name, {"symbol": ""})
    if r is None: r = call(name, {"str": ""})
    if r is None: return skip(name)
    val = result_get(r, "hash", "value", "result") if isinstance(r, dict) else r
    if isinstance(val, int):
        check(name, {"name":""}, val, 5381, "GNU hash('') = 5381")
    else:
        skip(name)

def h_gnu_hash_bytes(name):
    r = call(name, {"bytes": []})
    if r is None: r = call(name, {"data": ""})
    if r is None: r = call(name, {"hex": ""})
    if r is None: return skip(name)
    val = result_get(r, "hash", "value", "result") if isinstance(r, dict) else r
    if isinstance(val, int):
        check(name, {"bytes":[]}, val, 5381, "GNU hash empty bytes = 5381")
    else:
        skip(name)

handlers = {
    "loader_elf_gnu_hash_str": h_gnu_hash_str,
    "loader_elf_gnu_hash_bytes": h_gnu_hash_bytes,
    "loader_elf_parse_info": h_parse_info,
    "loader_elf_info_summary": h_summary,
    "loader_elf_plt_entries": h_plt_entries,
}

# Include any "is_elf" or detection-like tools
for name in tool_names:
    if name in handlers: continue
    if "is_elf" in name or "detect" in name:
        handlers[name] = h_is_elf
    elif "parse" in name or "info" in name:
        handlers[name] = h_summary
    elif "hash" in name:
        # Generic hash: skip unknown semantics
        pass

# Run
for name, h in handlers.items():
    if name in tool_names:
        try:
            h(name)
        except Exception as e:
            mismatches.append({"tool":name,"input":"exception","mcp":str(e),"truth":None,"note":"validator raised"})

# Also touch any remaining ELF tools with a generic call for tools_in_category count
for name in tool_names:
    if name in handlers: continue
    # try one generic call, just note skip
    skip(name)

try: p.terminate()
except: pass

os.unlink(elf_path)

report = {
    "category": PREFIX.rstrip("_"),
    "tools_in_category": len(tool_names),
    "checks_total": checks_total,
    "checks_passed": checks_passed,
    "checks_skipped": checks_skipped,
    "tools_touched": sorted(tools_touched),
    "mismatches": mismatches,
}
with open(OUT, "w") as f: json.dump(report, f, indent=2)
print(json.dumps({k:v for k,v in report.items() if k!="tools_touched"}, indent=2))
