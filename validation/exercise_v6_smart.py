#!/usr/bin/env python3
"""V6: smart per-tool inputs — semanticamente validi per ridurre falsi TOOL_ERROR.
Solo tool che ancora falliscono con input smart sono BUG reali."""
import json, subprocess, time
from collections import Counter

EXE = r"C:\Users\Fra\Desktop\RustRE\target\release\rustre-mcp.exe"
TARGET = r"C:\Users\Fra\Desktop\Zyphora\target\release\cargo-zyphora.exe"
PDB = r"C:\Users\Fra\Desktop\Zyphora\target\release\cargo_zyphora.pdb"
OUT = r"C:\Users\Fra\Desktop\RustRE\validation\mcp_outputs\R61_SMART.json"

# Load target bytes once
with open(TARGET, "rb") as f:
    PE_BYTES_HEX = f.read(4096).hex()  # first 4KB, plenty for parsers

# Real YARA rule
YARA_RULE = 'rule test { strings: $a = "MZ" condition: $a }'

BINARY_ID = "bin-0001"
PROJECT_ID = "proj-0001"

def start_server():
    p = subprocess.Popen([EXE, "--transport=stdio"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, bufsize=0)
    def send(req):
        p.stdin.write((json.dumps(req)+"\n").encode())
        p.stdin.flush()
    def recv():
        line = p.stdout.readline()
        return json.loads(line) if line else None

    send({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"v6","version":"1"}}})
    recv()
    send({"jsonrpc":"2.0","method":"notifications/initialized"})
    send({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"project.open","arguments":{"path":TARGET}}})
    recv()
    return p, send, recv

p, send, recv = start_server()
send({"jsonrpc":"2.0","id":3,"method":"tools/list","params":{}})
tools_list = recv()["result"]["tools"]
print(f"Total tools: {len(tools_list)}")

def make_input(name, schema):
    props = (schema or {}).get("properties", {}) or {}
    req_fields = (schema or {}).get("required", []) or []
    args = {}
    n = name.lower()

    for pname, spec in props.items():
        t = spec.get("type")
        p = pname.lower()

        # Smart per-name inputs
        if pname == "binary_id": args[pname] = BINARY_ID
        elif pname == "project_id": args[pname] = PROJECT_ID
        elif pname == "session_id": args[pname] = "dbg-0001"
        elif pname in ("path","pe_path","binary_path","exe_path","input","file","file_path"): args[pname] = TARGET
        elif pname == "pdb_path": args[pname] = PDB
        elif pname in ("address","addr","va","start","addr1","addr_1","func_addr","function_address","function_addr","function"):
            args[pname] = 5368771180
        elif pname in ("end","addr2","addr_2"): args[pname] = 5368771260
        # HEX inputs: use real PE bytes for parsers, generic hex for others
        elif pname in ("hex","bytes_hex","data_hex","input_hex","raw_hex","body_hex","content_hex","payload_hex","code_hex","header_hex","dos_hex","file_hex"):
            if any(k in n for k in ("pe", "dos", "coff", "elf", "macho", "wasm", "pdf", "lua", "dex", "class", "jar", "smali")):
                args[pname] = PE_BYTES_HEX
            else:
                args[pname] = "deadbeef00112233445566778899aabbccddeeff" * 4  # 160 bytes
        elif pname in ("bytes", "data", "buffer") and t != "string":
            args[pname] = [0xde, 0xad, 0xbe, 0xef, 0x00, 0x11, 0x22, 0x33] * 8
        elif pname in ("mangled","symbol"): args[pname] = "_RNvNtCs6CKzx_3foo3bar4baz"
        elif pname == "name": args[pname] = "main"
        elif pname == "count": args[pname] = 5
        elif pname in ("bits","width","bit_width"): args[pname] = 64
        elif pname in ("size","length","len","limit","access_size"):
            # If the schema restricts to an enum (e.g. HwBpSize: "byte"/"word"/"dword"/"qword"),
            # pick the first valid enum value rather than the generic integer default.
            _size_enum = spec.get("enum", [])
            args[pname] = _size_enum[0] if _size_enum else 16
        elif pname == "offset": args[pname] = 0
        elif pname == "expression": args[pname] = "x + y"
        elif pname in ("pattern","pattern_hex","needle","needle_hex"): args[pname] = "deadbeef"
        elif pname in ("haystack","haystack_hex","input_hex_v4","data_hex_v4"): args[pname] = "deadbeef00112233" * 4
        elif pname == "query":
            if "kg" in n: args[pname] = "SELECT * FROM functions LIMIT 5"
            else: args[pname] = "main"
        elif pname == "type_str": args[pname] = "int"
        elif pname == "var_name": args[pname] = "x"
        elif pname in ("direction","dir"): args[pname] = "backward"
        elif pname == "addresses": args[pname] = [5368771180]
        elif pname in ("a","b","x","y","lhs","rhs","operand","val","value","cap","capacity","code_base","framesize","page_size","ptr_size","access_size","width","depth"):
            # Guard against zero
            args[pname] = 8
        elif pname in ("code_limit",): args[pname] = 4096
        elif pname == "min_slots": args[pname] = 3
        elif pname == "rule":
            # net_rules tools use Snort/Suricata syntax, not YARA
            if "net_rules" in n or "snort" in n:
                args[pname] = 'alert tcp any any -> any 80 (msg:"test rule"; content:"test"; sid:1000001; rev:1;)'
            else:
                args[pname] = YARA_RULE
        elif pname in ("rule_source","source","yara_source","content"):
            args[pname] = YARA_RULE
        elif pname == "bp_id": args[pname] = "bp-0001"
        elif pname in ("kind","level","state","protocol","proto","format","mechanism","packet_type","access_kind","stop_reason","distribution_level","threat_level","severity","category","priority","ioc_type","confidence_level","report_format","io_type","perms","perm","flag"):
            # Common enums — try safe defaults
            if "level" in p: args[pname] = "info"
            elif "protocol" in p or "proto" in p: args[pname] = "tcp"
            elif "format" in p: args[pname] = "json"
            elif "kind" in p or "type" in p: args[pname] = "call"
            elif "perm" in p: args[pname] = "rwx"
            else: args[pname] = "default"
        elif pname == "line": args[pname] = "test line data"
        elif pname == "text": args[pname] = "hello world"
        elif pname == "arch":
            if "arm" in n or "aarch64" in n: args[pname] = "arm64"
            elif "mips" in n: args[pname] = "mips"
            elif "riscv" in n or "rv" in n: args[pname] = "riscv"
            elif "wasm" in n: args[pname] = "wasm"
            else: args[pname] = "x86_64"
        elif pname == "language" or pname == "lang":
            args[pname] = "c"
        elif pname == "encoding":
            args[pname] = "utf-8"
        elif pname == "endian":
            args[pname] = "little"
        elif pname in req_fields:
            # Fallback based on type — prefer first enum value when schema restricts choices
            _enum_vals = spec.get("enum", [])
            if _enum_vals: args[pname] = _enum_vals[0]
            elif t == "string": args[pname] = "default"
            elif t in ("integer","number"): args[pname] = 1
            elif t == "boolean": args[pname] = False
            elif t == "array": args[pname] = []
            elif t == "object": args[pname] = {}
    return args

results = []
rid = 100
t0 = time.time()
restarts = 0

for i, tool in enumerate(tools_list):
    name = tool["name"]
    schema = tool.get("inputSchema", {})
    args = make_input(name, schema)
    rid += 1
    try:
        send({"jsonrpc":"2.0","id":rid,"method":"tools/call","params":{"name":name,"arguments":args}})
        resp = recv()
    except Exception:
        try: p.terminate()
        except: pass
        p, send, recv = start_server()
        restarts += 1
        try:
            send({"jsonrpc":"2.0","id":rid,"method":"tools/call","params":{"name":name,"arguments":args}})
            resp = recv()
        except Exception as e:
            resp = {"error":{"message":f"restart-fail: {e}"}}

    if resp is None:
        status = "SERVER_DIED"
        excerpt = ""
    elif "error" in resp:
        status = "JSONRPC_ERROR"
        excerpt = str(resp["error"])[:200]
    else:
        is_err = resp.get("result",{}).get("isError", False)
        content = resp.get("result",{}).get("content",[])
        txt = content[0].get("text","") if content else ""
        if is_err:
            status = "TOOL_ERROR"
            excerpt = txt[:200]
        elif not txt or txt == "{}":
            status = "EMPTY"
            excerpt = ""
        else:
            try:
                parsed = json.loads(txt)
                status = "STUB" if (isinstance(parsed, dict) and parsed.get("stub") is True) else "OK"
            except Exception:
                status = "OK_TEXT"
            excerpt = txt[:200]
    results.append({"tool":name,"status":status,"input":args,"output_excerpt":excerpt})

try: p.terminate()
except: pass

with open(OUT, "w") as f:
    json.dump(results, f, indent=1)

counts = Counter(r["status"] for r in results)
print(f"FINAL: {dict(counts)}")
print(f"Total: {len(results)} restarts: {restarts}")
