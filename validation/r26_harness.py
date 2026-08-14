import json, subprocess, sys, threading, queue, time, os, re

EXE = r"C:\Users\Fra\Desktop\RustRE\target\release\rustre-mcp.exe"
BIN = r"C:\Users\Fra\Desktop\RustRE\target\release\cargo-zyphora.exe"
GENERIC_PATH = r"C:\Users\Fra\Desktop\RustRE\Cargo.toml"
OUT = r"C:\Users\Fra\Desktop\RustRE\validation\R26_FUNCTIONAL.json"

proc = subprocess.Popen([EXE], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, bufsize=0)

_id = 0
def send(method, params=None, notify=False):
    global _id
    msg = {"jsonrpc": "2.0", "method": method}
    if params is not None:
        msg["params"] = params
    if not notify:
        _id += 1
        msg["id"] = _id
    data = (json.dumps(msg) + "\n").encode("utf-8")
    proc.stdin.write(data); proc.stdin.flush()
    if notify:
        return None
    return _id

def read_response(target_id, timeout=30):
    end = time.time() + timeout
    while time.time() < end:
        line = proc.stdout.readline()
        if not line:
            return None
        try:
            r = json.loads(line.decode("utf-8","ignore"))
        except Exception:
            continue
        if r.get("id") == target_id:
            return r
    return None

# init
i = send("initialize", {"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"t","version":"1"}})
read_response(i)
send("notifications/initialized", {}, notify=True)

# list tools
i = send("tools/list", {})
resp = read_response(i, timeout=60)
tools = resp.get("result", {}).get("tools", []) if resp else []
print(f"Found {len(tools)} tools", file=sys.stderr)

# Open project first for tools that need it
i = send("tools/call", {"name":"project_open","arguments":{"path": BIN}})
po = read_response(i, timeout=120)
print(f"project_open: {str(po)[:200]}", file=sys.stderr)

def build_input(schema, tname):
    if not schema or schema.get("type") != "object":
        return {}
    props = schema.get("properties", {}) or {}
    required = schema.get("required", []) or []
    args = {}
    # Fill required (and optionally a few extras to make it meaningful)
    keys = list(props.keys())
    for k in keys:
        if k not in required and len(args) >= 4:
            continue
        p = props.get(k, {})
        t = p.get("type")
        if isinstance(t, list):
            t = t[0]
        name = k.lower()
        if "enum" in p and p["enum"]:
            args[k] = p["enum"][0]; continue
        if t == "string":
            if "hex" in name:
                args[k] = "deadbeef"
            elif "path" in name or "file" in name or name == "binary":
                args[k] = BIN
            elif "addr" in name or "va" in name or "ea" in name or "offset" in name:
                args[k] = "0x140001000"
            elif "name" in name:
                args[k] = "main"
            elif "query" in name or "pattern" in name or "text" in name or "search" in name:
                args[k] = "main"
            elif "lang" in name or "demangle" in name:
                args[k] = "_ZN4test3fooE"
            elif "algo" in name or "hash" in name:
                args[k] = "md5"
            elif "rule" in name or "yara" in name:
                args[k] = 'rule t { strings: $a = "MZ" condition: $a }'
            else:
                args[k] = "test"
        elif t == "integer" or t == "number":
            if "addr" in name or "va" in name or "ea" in name or "offset" in name:
                args[k] = 0x140001000
            elif "size" in name or "len" in name or "count" in name or "limit" in name or "max" in name:
                args[k] = 16
            else:
                args[k] = 1
        elif t == "boolean":
            args[k] = False
        elif t == "array":
            items = p.get("items", {})
            it = items.get("type")
            if it == "string":
                args[k] = ["main"]
            elif it == "integer" or it == "number":
                args[k] = [1]
            else:
                args[k] = []
        elif t == "object":
            args[k] = {}
    return args

results = []
counts = {"WORKING":0,"STUB":0,"ERROR":0,"INPUT_DEPENDENT":0,"sanity":0}
broken = []

for t in tools:
    name = t["name"]
    schema = t.get("inputSchema") or t.get("input_schema") or {}
    args = build_input(schema, name)
    if name == "project_open":
        args = {"path": BIN}
    if name == "project_close":
        # skip closing until end
        results.append({"tool":name,"status":"SKIPPED","sample_input":args,"sample_output_excerpt":"","sanity_pass":False,"notes":"skipped to keep project open"})
        continue
    i = send("tools/call", {"name": name, "arguments": args})
    resp = read_response(i, timeout=60)
    if resp is None:
        status = "ERROR"; excerpt = "timeout/no response"; sanity = False; notes = "no response"
        broken.append(name)
    else:
        if "error" in resp:
            emsg = str(resp["error"])[:300]
            low = emsg.lower()
            if any(x in low for x in ["invalid","missing","required","parse","expected","schema","not found","no such","does not exist","unknown field"]):
                status = "INPUT_DEPENDENT"
            else:
                status = "ERROR"; broken.append(name)
            excerpt = emsg; sanity = False; notes = "error response"
        else:
            r = resp.get("result", {})
            is_err = r.get("isError", False)
            content = r.get("content", [])
            text = ""
            if isinstance(content, list):
                for c in content:
                    if isinstance(c, dict) and "text" in c:
                        text += c["text"]
            excerpt = text[:300]
            low_text = text.lower().strip()
            if is_err:
                if any(x in low_text for x in ["invalid","missing","required","parse","expected","not found","no such","does not exist","cannot find"]):
                    status = "INPUT_DEPENDENT"
                else:
                    status = "ERROR"; broken.append(name)
                sanity = False; notes = "isError=true"
            elif not text or low_text in ("{}","null","[]"):
                status = "STUB"; sanity = False; notes = "empty output"
            elif '"stub"' in low_text and "true" in low_text:
                status = "STUB"; sanity = False; notes = "stub flag"
            else:
                status = "WORKING"
                # sanity: try parse json
                sanity = False
                try:
                    j = json.loads(text)
                    if isinstance(j, (dict, list)) and (len(j) > 0):
                        sanity = True
                except Exception:
                    sanity = len(text.strip()) > 10
                notes = "ok"
    counts[status] = counts.get(status,0)+1
    if status == "WORKING" and sanity:
        counts["sanity"] += 1
    results.append({"tool":name,"status":status,"sample_input":args,"sample_output_excerpt":excerpt,"sanity_pass":sanity,"notes":notes})

with open(OUT,"w",encoding="utf-8") as f:
    json.dump(results, f, indent=2, default=str)

summary = {
    "total": len(results),
    "working": counts.get("WORKING",0),
    "stub": counts.get("STUB",0),
    "error": counts.get("ERROR",0),
    "input_dep": counts.get("INPUT_DEPENDENT",0),
    "sanity_pass": counts.get("sanity",0),
    "broken_tools": broken,
}
print(json.dumps(summary))
try:
    proc.stdin.close()
    proc.terminate()
except Exception:
    pass
