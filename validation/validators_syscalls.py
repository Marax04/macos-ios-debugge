#!/usr/bin/env python3
"""Independent validators for syscalls_* MCP tools."""
import json, subprocess, sys

EXE = r"C:\Users\Fra\Desktop\RustRE\target\release\rustre-mcp.exe"
OUT = r"C:\Users\Fra\Desktop\RustRE\validation\mismatch_syscalls.json"

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
    if not resp: return None, "no_response"
    if "error" in resp: return None, "error:" + str(resp["error"])[:100]
    c = resp.get("result",{}).get("content",[])
    if not c: return None, "empty"
    txt = c[0].get("text","")
    # detect tool-level error text
    low = txt.lower() if isinstance(txt,str) else ""
    if "execution failed" in low or "invalid params" in low or "missing '" in low:
        return None, "tool_err:" + txt[:80]
    try: return json.loads(txt), None
    except: return txt, None

# list tools
rid[0] += 1
send({"jsonrpc":"2.0","id":rid[0],"method":"tools/list","params":{}})
resp = recv()
tools = resp.get("result",{}).get("tools",[])
sys_tools = [t for t in tools if t["name"].startswith("syscalls_")]
tools_by_name = {t["name"]: t for t in sys_tools}

mismatches = []
passed = 0
skipped = 0
total = 0

def extract(val, keys):
    if not isinstance(val, dict): return val
    for k in keys:
        if k in val: return val[k]
    return None

def check(tool, args, mcp_val, truth, note=""):
    global passed, total
    total += 1
    if mcp_val == truth:
        passed += 1
        return True
    # numeric tolerant
    try:
        if isinstance(mcp_val,(int,float)) and isinstance(truth,(int,float)) and mcp_val == truth:
            passed += 1
            return True
    except: pass
    # str case-insensitive
    if isinstance(mcp_val, str) and isinstance(truth, str) and mcp_val.lower() == truth.lower():
        passed += 1
        return True
    mismatches.append({"tool":tool,"input":args,"mcp":mcp_val,"truth":truth,"note":note})
    return False

def skip(reason):
    global skipped
    skipped += 1

# --- Linux x86_64 syscall table ---
LINUX_X86_64 = {
    0: "read", 1: "write", 2: "open", 3: "close", 9: "mmap",
    59: "execve", 60: "exit", 257: "openat",
}
LINUX_AARCH64 = {
    63: "read", 64: "write", 56: "openat", 57: "close",
}
SIGNALS = {9:"SIGKILL", 11:"SIGSEGV", 15:"SIGTERM", 2:"SIGINT", 1:"SIGHUP"}

# --- Tests ---

def try_call(name, args):
    """Only call if tool exists. Returns (result, err) or (None,'not_available')"""
    if name not in tools_by_name:
        return None, "not_available"
    return call(name, args)

# 1. syscalls_linux_x86_64_name (nr -> name)
for nr, expected in LINUX_X86_64.items():
    r, err = try_call("syscalls_linux_x86_64_name", {"nr": nr})
    if err == "not_available": break
    if err: skip(err); continue
    v = extract(r, ["name","syscall","result"])
    if v is None: skip("no name field"); continue
    check("syscalls_linux_x86_64_name", {"nr":nr}, v, expected, "Linux x86_64 syscall table")

# 2. syscalls_linux_x86_64_nr (name -> nr)
for expected_nr, name in LINUX_X86_64.items():
    r, err = try_call("syscalls_linux_x86_64_nr", {"name": name})
    if err == "not_available": break
    if err: skip(err); continue
    v = extract(r, ["nr","number","syscall_nr","result"])
    if v is None: skip("no nr field"); continue
    check("syscalls_linux_x86_64_nr", {"name":name}, v, expected_nr, "Linux x86_64 name->nr")

# 3. syscalls_linux_aarch64_name (schema uses 'number')
for nr, expected in LINUX_AARCH64.items():
    r, err = try_call("syscalls_linux_aarch64_name", {"number": nr})
    if err and err.startswith("tool_err"):
        r, err = try_call("syscalls_linux_aarch64_name", {"nr": nr})
    if err == "not_available": break
    if err: skip(err); continue
    v = extract(r, ["name","syscall","result"])
    if v is None: skip("no name field"); continue
    check("syscalls_linux_aarch64_name", {"nr":nr}, v, expected, "Linux arm64 table")

# 4. syscalls_linux_aarch64_nr
for expected_nr, name in LINUX_AARCH64.items():
    r, err = try_call("syscalls_linux_aarch64_nr", {"name": name})
    if err == "not_available": break
    if err: skip(err); continue
    v = extract(r, ["nr","number","result"])
    if v is None: skip("no nr field"); continue
    check("syscalls_linux_aarch64_nr", {"name":name}, v, expected_nr, "Linux arm64 name->nr")

# 5. syscalls_signal_name (schema uses 'sig')
for nr, expected in SIGNALS.items():
    r, err = try_call("syscalls_signal_name", {"sig": nr})
    if err and err.startswith("tool_err"):
        r, err = try_call("syscalls_signal_name", {"nr": nr})
    if err == "not_available": break
    if err: skip(err); continue
    v = extract(r, ["name","signal","result"])
    if v is None: skip("no name"); continue
    check("syscalls_signal_name", {"nr":nr}, v, expected, "POSIX signal number")

# 6. syscalls_signal_name_lookup
for nr, expected in SIGNALS.items():
    for arg in [{"sig":nr},{"signal":nr},{"nr":nr},{"num":nr}]:
        r, err = try_call("syscalls_signal_name_lookup", arg)
        if err == "not_available": break
        if err: continue
        v = extract(r, ["name","signal","result"])
        if v:
            check("syscalls_signal_name_lookup", arg, v, expected, "POSIX signal")
            break
    else:
        skip("no working arg")

# 7. syscalls_signal_name_lookup_wire
for nr, expected in SIGNALS.items():
    r, err = try_call("syscalls_signal_name_lookup_wire", {"signal": nr})
    if err == "not_available":
        r, err = try_call("syscalls_signal_name_lookup_wire", {"nr": nr})
    if err == "not_available": break
    if err: skip(err); continue
    v = extract(r, ["name","signal","result"])
    if v is None: skip("no name"); continue
    check("syscalls_signal_name_lookup_wire", {"nr":nr}, v, expected, "POSIX signal wire")

# 8. syscalls_errno_name — POSIX errno numbers
ERRNOS = {1:"EPERM", 2:"ENOENT", 9:"EBADF", 12:"ENOMEM", 13:"EACCES"}
for nr, expected in ERRNOS.items():
    r, err = try_call("syscalls_errno_name", {"errno": nr})
    if err == "not_available":
        r, err = try_call("syscalls_errno_name", {"nr": nr})
    if err == "not_available": break
    if err: skip(err); continue
    v = extract(r, ["name","errno","result"])
    if v is None: skip("no name"); continue
    check("syscalls_errno_name", {"nr":nr}, v, expected, "POSIX errno")

# 9. syscalls_errno_name_lookup
for nr, expected in ERRNOS.items():
    r, err = try_call("syscalls_errno_name_lookup", {"errno": nr})
    if err == "not_available":
        r, err = try_call("syscalls_errno_name_lookup", {"nr": nr})
    if err == "not_available": break
    if err: skip(err); continue
    v = extract(r, ["name","errno","result"])
    if v is None: skip("no name"); continue
    check("syscalls_errno_name_lookup", {"nr":nr}, v, expected, "POSIX errno lookup")

# 10. syscalls_errno_name_lookup_wire
for nr, expected in ERRNOS.items():
    r, err = try_call("syscalls_errno_name_lookup_wire", {"errno": nr})
    if err == "not_available":
        r, err = try_call("syscalls_errno_name_lookup_wire", {"nr": nr})
    if err == "not_available": break
    if err: skip(err); continue
    v = extract(r, ["name","errno","result"])
    if v is None: skip("no name"); continue
    check("syscalls_errno_name_lookup_wire", {"nr":nr}, v, expected, "POSIX errno wire")

# 11. syscalls_table_name_to_number (multi-arch dispatcher, try Linux x86_64)
for expected_nr, name in list(LINUX_X86_64.items())[:5]:
    for arg in [{"arch":"linux_x86_64","name":name},{"arch":"x86_64","name":name},{"os":"linux","arch":"x86_64","name":name}]:
        r, err = try_call("syscalls_table_name_to_number", arg)
        if err == "not_available": break
        if err: continue
        v = extract(r, ["nr","number","result","value"])
        if v is not None:
            check("syscalls_table_name_to_number", arg, v, expected_nr, "table dispatcher x86_64")
            break
    else:
        skip("no working arg combo")

# 12. syscalls_table_number_to_name
for nr, expected in list(LINUX_X86_64.items())[:5]:
    for arg in [{"arch":"linux_x86_64","nr":nr},{"arch":"x86_64","nr":nr},{"os":"linux","arch":"x86_64","nr":nr}]:
        r, err = try_call("syscalls_table_number_to_name", arg)
        if err == "not_available": break
        if err: continue
        v = extract(r, ["name","result"])
        if v is not None:
            check("syscalls_table_number_to_name", arg, v, expected, "table dispatcher nr->name")
            break
    else:
        skip("no working arg")

# 13. syscalls_table_max_number_x86_64_v2 - should be a large positive integer
r, err = try_call("syscalls_table_max_number_x86_64_v2", {})
if err is None:
    v = extract(r, ["max","max_nr","result","value"])
    # Truth: linux x86_64 max SSN ~ 450 (2024-era). We check "is a plausible positive int"
    if isinstance(v,int) and 300 <= v <= 1000:
        passed += 1; total += 1
    elif v is None:
        skip("no max field")
    else:
        total += 1
        mismatches.append({"tool":"syscalls_table_max_number_x86_64_v2","input":{},
                           "mcp":v,"truth":"300<=x<=1000","note":"Linux x86_64 max SSN out of plausible range"})
else:
    skip(err or "n/a")

# 14. syscalls_signal_name unknown signal -> should return unknown/None/error
r, err = try_call("syscalls_signal_name", {"nr": 9999})
if err is None:
    v = extract(r, ["name","signal","result"])
    # truth: None-ish or contains "unknown"
    total += 1
    if v is None or (isinstance(v,str) and ("unknown" in v.lower() or v == "")):
        passed += 1
    else:
        mismatches.append({"tool":"syscalls_signal_name","input":{"nr":9999},"mcp":v,"truth":"unknown/None","note":"9999 is not a valid signal"})

# 15. syscalls_linux_x86_64_name unknown nr
r, err = try_call("syscalls_linux_x86_64_name", {"nr": 999999})
if err is None:
    v = extract(r, ["name","syscall","result"])
    total += 1
    if v is None or (isinstance(v,str) and ("unknown" in v.lower() or v == "")):
        passed += 1
    else:
        mismatches.append({"tool":"syscalls_linux_x86_64_name","input":{"nr":999999},"mcp":v,
                           "truth":"unknown/None","note":"999999 is out of Linux x86_64 syscall range"})

# 16. syscalls_ia32_to_x86_64_nr - convert ia32 syscall to x86_64 equivalent
# Truth: ia32 read=3 -> x86_64 read=0, ia32 write=4 -> x86_64 write=1
IA32_MAP = {3:0, 4:1, 5:2, 6:3}  # read, write, open, close
for ia32_nr, expected in IA32_MAP.items():
    r, err = try_call("syscalls_ia32_to_x86_64_nr", {"nr": ia32_nr})
    if err == "not_available":
        r, err = try_call("syscalls_ia32_to_x86_64_nr", {"ia32_nr": ia32_nr})
    if err == "not_available": break
    if err: skip(err); continue
    v = extract(r, ["nr","x86_64_nr","result","value"])
    if v is None: skip("no nr"); continue
    check("syscalls_ia32_to_x86_64_nr", {"nr":ia32_nr}, v, expected, "ia32 syscall equivalence")

# 17. syscalls_linux_x86_64_nr unknown name
r, err = try_call("syscalls_linux_x86_64_nr", {"name": "definitely_not_a_syscall_xyz"})
if err is None:
    v = extract(r, ["nr","number","result"])
    total += 1
    if v is None or v == -1 or (isinstance(v,int) and v < 0):
        passed += 1
    else:
        mismatches.append({"tool":"syscalls_linux_x86_64_nr","input":{"name":"definitely_not_a_syscall_xyz"},
                           "mcp":v,"truth":"None/-1","note":"unknown syscall name should not resolve"})

# cleanup
try: p.terminate()
except: pass

report = {
    "category": "syscalls",
    "tools_in_category": len(sys_tools),
    "checks_total": total,
    "checks_passed": passed,
    "checks_skipped": skipped,
    "mismatches": mismatches,
}
with open(OUT, "w") as f:
    json.dump(report, f, indent=2, default=str)

print(json.dumps({k:v for k,v in report.items() if k!="mismatches"}))
print(f"MISMATCHES: {len(mismatches)}")
for m in mismatches[:10]:
    print(f"  {m['tool']}: mcp={m['mcp']!r} truth={m['truth']!r} note={m['note']}")
