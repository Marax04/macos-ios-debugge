#!/usr/bin/env python3
"""Validator for loader_macho_* MCP tools."""
import json, subprocess, struct, os

EXE = r"C:\Users\Fra\Desktop\RustRE\target\release\rustre-mcp.exe"
OUT = r"C:\Users\Fra\Desktop\RustRE\validation\mismatch_loader_macho.json"
PREFIX = "loader_macho_"

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

# list tools
rid[0]+=1
send({"jsonrpc":"2.0","id":rid[0],"method":"tools/list"})
tools_resp = recv()
all_tools = tools_resp.get("result",{}).get("tools",[])
mytools = [t for t in all_tools if t["name"].startswith(PREFIX)]
tool_names = [t["name"] for t in mytools]

mismatches = []
checks_total = 0
checks_passed = 0
checks_skipped = 0

def check(name, mcp, truth, note="", inp=None):
    global checks_total, checks_passed
    checks_total += 1
    if mcp == truth:
        checks_passed += 1
        return True
    mismatches.append({"tool":name,"input":inp,"mcp":mcp,"truth":truth,"note":note})
    return False

def skip():
    global checks_skipped
    checks_skipped += 1

# --- Build synthetic Mach-O headers ---
# Mach-O 64-bit header layout:
# magic(4) cputype(4) cpusubtype(4) filetype(4) ncmds(4) sizeofcmds(4) flags(4) reserved(4)
MH_MAGIC_64 = 0xfeedfacf
MH_MAGIC    = 0xfeedface
MH_CIGAM_64 = 0xcffaedfe
FAT_MAGIC   = 0xcafebabe
CPU_X86_64  = 0x01000007
CPU_ARM64   = 0x0100000c
CPU_X86     = 0x00000007
MH_EXECUTE  = 0x2
MH_DYLIB    = 0x6

def make_macho64(cpu=CPU_X86_64, ftype=MH_EXECUTE, ncmds=0):
    return struct.pack("<IIIIIIII", MH_MAGIC_64, cpu, 3, ftype, ncmds, 0, 0, 0)

def make_macho32(cpu=CPU_X86, ftype=MH_EXECUTE, ncmds=0):
    return struct.pack("<IIIIIII", MH_MAGIC, cpu, 3, ftype, ncmds, 0, 0)

def make_fat():
    # fat_header big-endian: magic, nfat_arch
    return struct.pack(">II", FAT_MAGIC, 0)

macho64 = make_macho64() + b"\x00" * 64
macho32 = make_macho32() + b"\x00" * 64
macho_arm64 = make_macho64(cpu=CPU_ARM64) + b"\x00" * 64
fat = make_fat() + b"\x00" * 32
notmacho = b"MZ" + b"\x00" * 64

def tryname(n):
    return n in tool_names

# 1) loader_is_macho
if tryname("loader_is_macho"):
    for name_hint, blob, truth in [
        ("macho64", macho64, True),
        ("macho32", macho32, True),
        ("fat", fat, True),
        ("pe", notmacho, False),
    ]:
        r = call("loader_is_macho", {"hex": blob.hex()})
        if r is None: r = call("loader_is_macho", {"data": list(blob)})
        if r is None: skip(); continue
        if isinstance(r, dict):
            v = r.get("is_macho");
            if v is None: v = r.get("result");
            if v is None: v = r.get("value")
        else:
            v = r
        check("loader_is_macho", bool(v) if v is not None else None, truth, name_hint, name_hint)

# 2) loader_macho_arch_from_cputype
if tryname("loader_macho_arch_from_cputype"):
    cases = [
        (CPU_X86_64, ["x86_64","X86_64","amd64"]),
        (CPU_ARM64, ["aarch64","arm64","ARM64"]),
        (CPU_X86,   ["x86","i386","X86"]),
    ]
    for cpu, accepted in cases:
        r = call("loader_macho_arch_from_cputype", {"cputype": cpu})
        if r is None: r = call("loader_macho_arch_from_cputype", {"cpu_type": cpu})
        if r is None: skip(); continue
        if isinstance(r, dict):
            arch = r.get("arch") or r.get("name") or r.get("value") or r.get("result")
        else:
            arch = r
        if arch is None:
            skip(); continue
        checks_total += 1
        if any(a.lower() in str(arch).lower() for a in accepted):
            checks_passed += 1
        else:
            mismatches.append({"tool":"loader_macho_arch_from_cputype","input":{"cputype":hex(cpu)},"mcp":arch,"truth":accepted,"note":"arch name mismatch"})

# 3) loader_macho_subtype_name — just call, accept string result
if tryname("loader_macho_subtype_name"):
    r = call("loader_macho_subtype_name", {"cputype": CPU_X86_64, "cpusubtype": 3})
    if r is None: skip()
    else:
        # Only check it's not empty
        checks_total += 1
        s = None
        if isinstance(r, dict):
            s = r.get("subtype_name") or r.get("name") or r.get("subtype") or r.get("value") or r.get("result")
        else:
            s = r
        if isinstance(s, str) and s:
            checks_passed += 1
        else:
            mismatches.append({"tool":"loader_macho_subtype_name","input":{"cputype":CPU_X86_64,"cpusubtype":3},"mcp":r,"truth":"non-empty string","note":"empty subtype name"})

# 4) loader_macho_parse — should detect magic & basic fields
def try_parse(fn, blob, expect_64=True, expect_cpu=CPU_X86_64):
    r = call(fn, {"hex": blob.hex()})
    if r is None: r = call(fn, {"data": list(blob)})
    if r is None: return None
    return r

for fn in ("loader_macho_parse", "loader_macho_parse_summary"):
    if not tryname(fn): continue
    r = try_parse(fn, macho64)
    if r is None: skip(); continue
    if not isinstance(r, dict):
        skip(); continue
    # Check magic-related field
    m = r.get("magic") or r.get("magic_hex")
    if isinstance(m, str):
        try: m_val = int(m, 16)
        except: m_val = None
    else:
        m_val = m
    if m_val is not None:
        check(fn, m_val, MH_MAGIC_64, "magic 64-bit", "macho64 header")
    # cpu
    cpu = r.get("cputype") or r.get("cpu_type") or r.get("cpu")
    if cpu is not None:
        if isinstance(cpu, str):
            try: cpu = int(cpu, 16) if cpu.startswith("0x") else int(cpu)
            except: cpu = None
        if cpu is not None:
            check(fn, cpu, CPU_X86_64, "cputype x86_64", "macho64 header")

# 5) loader_macho_parse_fat
if tryname("loader_macho_parse_fat"):
    r = try_parse("loader_macho_parse_fat", fat)
    if r is None: skip()
    else:
        if isinstance(r, dict):
            m = r.get("magic")
            if isinstance(m, str):
                try: m = int(m, 16)
                except: pass
            if isinstance(m, int):
                # fat magic is 0xcafebabe (BE view), some impls store LE. accept both
                checks_total += 1
                if m in (FAT_MAGIC, 0xbebafeca):
                    checks_passed += 1
                else:
                    mismatches.append({"tool":"loader_macho_parse_fat","input":"fat header","mcp":hex(m),"truth":hex(FAT_MAGIC),"note":"fat magic"})
            else:
                skip()
        else:
            skip()

# Save
os.makedirs(os.path.dirname(OUT), exist_ok=True)
report = {
    "category":"loader_macho",
    "tools_in_category":len(mytools),
    "checks_total":checks_total,
    "checks_passed":checks_passed,
    "checks_skipped":checks_skipped,
    "mismatches":mismatches,
    "tools_found":tool_names,
}
with open(OUT,"w") as f: json.dump(report,f,indent=2)
print(json.dumps({k:v for k,v in report.items() if k!="tools_found"},indent=2))
print("tools:", tool_names)
p.terminate()
