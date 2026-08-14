#!/usr/bin/env python3
"""Independent validator for loader_java_* tools."""
import json, subprocess, struct, io, zipfile, os, sys

EXE = r"C:\Users\Fra\Desktop\RustRE\target\release\rustre-mcp.exe"
OUT = r"C:\Users\Fra\Desktop\RustRE\validation\mismatch_loader_java.json"
PREFIX = "loader_java_"

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

# tools/list
rid[0] += 1
send({"jsonrpc":"2.0","id":rid[0],"method":"tools/list","params":{}})
resp = recv()
tools = resp.get("result",{}).get("tools",[]) if resp else []
java_tools = [t for t in tools if t["name"].startswith(PREFIX)]
print(f"Found {len(java_tools)} tools with prefix {PREFIX}")
for t in java_tools:
    print(" ", t["name"])

# --- Build synthetic Java class file ---
# CAFEBABE + minor(0) + major(52 = Java 8) + constant pool count (1 = empty)
CLASS_MAGIC = b"\xCA\xFE\xBA\xBE"
minor = 0
major = 52
class_bytes = CLASS_MAGIC + struct.pack(">HH", minor, major) + struct.pack(">H", 1) \
    + struct.pack(">HHH", 0x0021, 0x0001, 0x0000) + b"\x00"*20
class_hex = class_bytes.hex()
class_b64_list = list(class_bytes)

# Build a valid JAR (zip) in memory
jar_buf = io.BytesIO()
with zipfile.ZipFile(jar_buf, "w") as z:
    z.writestr("Foo.class", class_bytes)
    z.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\n")
jar_bytes = jar_buf.getvalue()
jar_hex = jar_bytes.hex()

# Not-a-class bytes
bad_bytes = b"\x00\x01\x02\x03NOTCLASS"
bad_hex = bad_bytes.hex()

mismatches = []
checks_total = 0
checks_passed = 0
checks_skipped = 0

def try_variants(name, base_data_key_variants):
    """Try calling tool with various arg names/shapes; return first non-None."""
    for args in base_data_key_variants:
        r = call(name, args)
        if r is not None and not (isinstance(r,str) and ("error" in r.lower() or "invalid" in r.lower())):
            return r, args
    return None, None

def value_of(r, *keys):
    if not isinstance(r, dict): return r
    for k in keys:
        if k in r: return r[k]
    if len(r) == 1: return list(r.values())[0]
    return r

def record(tool, inp, mcp, truth, note=""):
    global checks_total, checks_passed
    checks_total += 1
    if mcp == truth:
        checks_passed += 1
        return True
    mismatches.append({"tool":tool,"input":inp,"mcp":mcp,"truth":truth,"note":note})
    return False

def skip(reason=""):
    global checks_skipped
    checks_skipped += 1

# candidate arg shapes for byte-taking tools
def arg_shapes(data_bytes):
    return [
        {"data": list(data_bytes)},
        {"bytes": list(data_bytes)},
        {"data": data_bytes.hex()},
        {"bytes": data_bytes.hex()},
        {"hex": data_bytes.hex()},
        {"input": list(data_bytes)},
    ]

TOOLS = {t["name"]: t.get("inputSchema",{}) for t in java_tools}

# --- Specific checks ---

# is_class / is_java_class : True on CAFEBABE, False on garbage
for tname in ["loader_java_is_class", "loader_java_is_java_class"]:
    if tname in TOOLS:
        r, ai = try_variants(tname, arg_shapes(class_bytes))
        if r is None: skip(); continue
        v = value_of(r, "is_class", "is_java_class", "value", "result")
        record(tname, {"data":"CAFEBABE-class"}, bool(v), True, "valid class")
        r2, ai2 = try_variants(tname, arg_shapes(bad_bytes))
        if r2 is not None:
            v2 = value_of(r2, "is_class", "is_java_class", "value", "result")
            record(tname, {"data":"garbage"}, bool(v2), False, "not a class")
        else:
            skip()

# is_jar : True on valid JAR bytes, False on class bytes
if "loader_java_is_jar" in TOOLS:
    tname = "loader_java_is_jar"
    r, ai = try_variants(tname, arg_shapes(jar_bytes))
    if r is not None:
        v = value_of(r, "is_jar", "value", "result")
        record(tname, {"data":"JAR"}, bool(v), True, "valid JAR/zip")
    else:
        skip()
    r2, ai2 = try_variants(tname, arg_shapes(class_bytes))
    if r2 is not None:
        v2 = value_of(r2, "is_jar", "value", "result")
        record(tname, {"data":"class"}, bool(v2), False, "class not jar")
    else:
        skip()

# parse_class : returns minor/major
if "loader_java_parse_class" in TOOLS:
    tname = "loader_java_parse_class"
    r, ai = try_variants(tname, arg_shapes(class_bytes))
    if r is not None and isinstance(r, dict):
        # check version fields if present
        found_any = False
        for kmaj in ("major", "major_version", "majorVersion"):
            if kmaj in r:
                record(tname, {"data":"class"}, r[kmaj], major, "major version")
                found_any = True
                break
        for kmin in ("minor", "minor_version", "minorVersion"):
            if kmin in r:
                record(tname, {"data":"class"}, r[kmin], minor, "minor version")
                found_any = True
                break
        if not found_any:
            skip()
    else:
        skip()

# Report unknown/unhandled tools as skips
handled = {"loader_java_is_class", "loader_java_is_java_class",
           "loader_java_is_jar", "loader_java_parse_class"}
for tname in TOOLS:
    if tname not in handled:
        skip()

result = {
    "category": "loader_java",
    "tools_in_category": len(java_tools),
    "checks_total": checks_total,
    "checks_passed": checks_passed,
    "checks_skipped": checks_skipped,
    "mismatches": mismatches,
}

with open(OUT, "w") as f:
    json.dump(result, f, indent=2, default=str)

print(json.dumps({k:v for k,v in result.items() if k!="mismatches"}, indent=2))
print(f"Mismatches: {len(mismatches)}")
p.terminate()
