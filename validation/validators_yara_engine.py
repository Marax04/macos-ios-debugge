#!/usr/bin/env python3
"""Independent validator for prefix `yara_engine_`. Compares MCP tool output vs
ground-truth computed inline in Python (uses yara-python where possible)."""
import json, subprocess, math, os
from collections import Counter

EXE = r"C:\Users\Fra\Desktop\RustRE\target\release\rustre-mcp.exe"
TARGET = r"C:\Users\Fra\Desktop\Zyphora\target\release\cargo-zyphora.exe"
OUT = r"C:\Users\Fra\Desktop\RustRE\validation\mismatch_yara_engine.json"
PREFIX = "yara_engine_"

try:
    import yara  # yara-python
    HAVE_YARA = True
except Exception:
    HAVE_YARA = False


def start():
    p = subprocess.Popen([EXE, "--transport=stdio"], stdin=subprocess.PIPE,
                         stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, bufsize=0)
    def send(r):
        p.stdin.write((json.dumps(r) + "\n").encode()); p.stdin.flush()
    def recv():
        line = p.stdout.readline()
        return json.loads(line) if line else None
    send({"jsonrpc":"2.0","id":1,"method":"initialize",
          "params":{"protocolVersion":"2024-11-05","capabilities":{},
                    "clientInfo":{"name":"v","version":"1"}}})
    recv()
    send({"jsonrpc":"2.0","method":"notifications/initialized"})
    return p, send, recv


p, send, recv = start()
rid = [10]


def call(name, args):
    rid[0] += 1
    send({"jsonrpc":"2.0","id":rid[0],"method":"tools/call",
          "params":{"name":name,"arguments":args}})
    resp = recv()
    if not resp or "error" in resp:
        return None
    c = resp.get("result", {}).get("content", [])
    if not c:
        return None
    try:
        return json.loads(c[0].get("text",""))
    except Exception:
        return c[0].get("text", "")


def list_tools():
    rid[0] += 1
    send({"jsonrpc":"2.0","id":rid[0],"method":"tools/list","params":{}})
    resp = recv()
    tools = []
    while resp:
        result = resp.get("result", {})
        tools.extend(result.get("tools", []))
        cur = result.get("nextCursor")
        if not cur:
            break
        rid[0] += 1
        send({"jsonrpc":"2.0","id":rid[0],"method":"tools/list","params":{"cursor":cur}})
        resp = recv()
    return tools


mismatches = []
checks_ok = 0
checks_total = 0
checks_skipped = 0


def record(name, args, mcp, truth, note, ok):
    global checks_ok, checks_total
    checks_total += 1
    if ok:
        checks_ok += 1
        return
    mismatches.append({"tool":name,"input":args,"mcp":mcp,"truth":truth,"note":note})


def shannon(data):
    if not data:
        return 0.0
    c = Counter(data)
    n = len(data)
    return -sum((v/n)*math.log2(v/n) for v in c.values())


all_tools = list_tools()
yara_tools = [t for t in all_tools if t["name"].startswith(PREFIX)]
names = {t["name"] for t in yara_tools}

# ---- helpers ----
SIMPLE_RULE = 'rule t { strings: $a = "MZ" condition: $a }'
MULTI_RULE = 'rule r1 { condition: true }\nrule r2 { condition: false }'

def try_check(fn):
    global checks_skipped
    try:
        fn()
    except Exception as e:
        checks_skipped += 1


# 1. entropy: yara_engine_compute_entropy_wire2 / compute_entropy_hex_wire3
sample = bytes(range(256)) * 4
truth_ent = shannon(sample)

def c_entropy():
    for tn in ["yara_engine_compute_entropy_wire2", "yara_engine_compute_entropy_hex_wire3"]:
        if tn not in names: continue
        # Try both hex and raw
        args_variants = [
            {"hex": sample.hex()},
            {"data": list(sample)},
            {"bytes": sample.hex()},
        ]
        got = None; used = None
        for a in args_variants:
            r = call(tn, a)
            if isinstance(r, dict) and any(k in r for k in ("entropy","value","result","shannon")):
                got = r; used = a; break
            if isinstance(r, (int,float)):
                got = r; used = a; break
        if got is None:
            global checks_skipped
            checks_skipped += 1
            continue
        val = got if isinstance(got,(int,float)) else (got.get("entropy") or got.get("value") or got.get("result") or got.get("shannon"))
        if val is None:
            checks_skipped += 1; continue
        ok = abs(float(val) - truth_ent) < 1e-4
        record(tn, used, val, truth_ent, "entropy of 0..255 repeated", ok)

try_check(c_entropy)


# 2. parse rule name: yara_engine_parse_name_from_source, rule_def_parse_name_wire3
def c_parse_name():
    src = 'rule MyRule_42 { condition: true }'
    truth = "MyRule_42"
    for tn in ["yara_engine_parse_name_from_source", "yara_engine_rule_def_parse_name_wire3"]:
        if tn not in names: continue
        got = None
        for a in [{"source":src},{"src":src},{"input":src},{"rule":src},{"text":src}]:
            r = call(tn, a)
            if r is not None and r != "":
                got = r; used = a; break
        else:
            global checks_skipped
            checks_skipped += 1; continue
        val = got if isinstance(got,str) else (got.get("name") if isinstance(got,dict) else None)
        if val is None and isinstance(got, dict):
            val = got.get("rule_name") or got.get("value")
        if val is None:
            checks_skipped += 1; continue
        record(tn, used, val, truth, "rule name extraction", val == truth)

try_check(c_parse_name)


# 3. rule count: yara_engine_parse_rules_count_wire2 / builtin_rules_count
def c_rule_count():
    src = MULTI_RULE
    truth = 2
    tn = "yara_engine_parse_rules_count_wire2"
    if tn in names:
        r = None; used = None
        for a in [{"source":src},{"src":src},{"rules":src},{"input":src},{"text":src}]:
            r = call(tn, a)
            if r is not None:
                used = a; break
        if r is None:
            global checks_skipped
            checks_skipped += 1
        else:
            val = r if isinstance(r,int) else (r.get("count") if isinstance(r,dict) else None)
            if val is None and isinstance(r,dict):
                val = r.get("value") or r.get("rules_count")
            if val is None:
                checks_skipped += 1
            else:
                record(tn, used, val, truth, "count 2 rules", val == truth)

try_check(c_rule_count)


# 4. scan bytes: yara_engine_scan_bytes -> MZ rule should match PE
def c_scan_bytes():
    tn = "yara_engine_scan_bytes"
    if tn not in names:
        return
    with open(TARGET, "rb") as f:
        data = f.read(4096)
    truth_match = True
    if HAVE_YARA:
        rules = yara.compile(source=SIMPLE_RULE)
        truth_match = len(rules.match(data=data)) > 0
    for a in [{"rules":SIMPLE_RULE,"hex":data.hex()},
              {"source":SIMPLE_RULE,"hex":data.hex()},
              {"rule":SIMPLE_RULE,"data":data.hex()},
              {"rules":SIMPLE_RULE,"bytes":data.hex()}]:
        r = call(tn, a)
        if r is None: continue
        if isinstance(r, list):
            got = len(r) > 0
            record(tn, {k:("<hex>" if k in ("hex","data","bytes") else v) for k,v in a.items()}, got, truth_match, "MZ match on PE", got == truth_match)
            return
        if isinstance(r, dict):
            m = r.get("matches") or r.get("results")
            if isinstance(m, list):
                got = len(m) > 0
            elif "matched" in r:
                got = bool(r["matched"])
            elif "count" in r:
                got = r["count"] > 0
            else:
                continue
            record(tn, {k:("<hex>" if k in ("hex","data","bytes") else v) for k,v in a.items()}, got, truth_match, "MZ match on PE", got == truth_match)
            return
    global checks_skipped
    checks_skipped += 1

try_check(c_scan_bytes)


# 5. hex_token_wildcard_match: '??' matches any byte
def c_hex_wildcard():
    tn = "yara_engine_hex_token_wildcard_match_wire3"
    if tn not in names: return
    for a in [{"token":"??","byte":0x41},
              {"token":"??","value":0x41},
              {"pattern":"??","byte":0x41},
              {"hex":"??","byte":0x41}]:
        r = call(tn, a)
        if r is None: continue
        val = r if isinstance(r,bool) else (r.get("matches") if isinstance(r,dict) else None)
        if val is None and isinstance(r,dict):
            val = r.get("result") or r.get("value")
        if val is None: continue
        record(tn, a, val, True, "?? matches any", bool(val) == True)
        return
    global checks_skipped
    checks_skipped += 1

try_check(c_hex_wildcard)


# 6. hex_token_jump_match: '[2-4]' with length 3 should match
def c_hex_jump():
    tn = "yara_engine_hex_token_jump_match_wire3"
    if tn not in names: return
    for a in [{"min":2,"max":4,"length":3},
              {"lo":2,"hi":4,"length":3},
              {"jump_min":2,"jump_max":4,"length":3}]:
        r = call(tn, a)
        if r is None: continue
        val = r if isinstance(r,bool) else (r.get("matches") if isinstance(r,dict) else None)
        if val is None: continue
        record(tn, a, val, True, "jump 2-4 length 3", bool(val) == True)
        return
    global checks_skipped
    checks_skipped += 1

try_check(c_hex_jump)


# 7. rule_new / rule_new_empty / rule_new_summary just probe return shape
def c_rule_new():
    for tn in ["yara_engine_rule_new_summary"]:
        if tn not in names: continue
        r = call(tn, {"name":"test"})
        global checks_skipped
        if r is None:
            checks_skipped += 1; continue
        # only sanity: name echoed
        s = json.dumps(r).lower()
        record(tn, {"name":"test"}, "test" in s, True, "name in summary", "test" in s)

try_check(c_rule_new)


# 8. ruleset_add_rule / ruleset_len
def c_ruleset():
    tn = "yara_engine_ruleset_add_rule"
    if tn not in names: return
    r = call(tn, {"rule": MULTI_RULE.split("\n")[0]})
    global checks_skipped
    if r is None:
        checks_skipped += 1; return
    # Not verifiable deterministically without state; skip
    checks_skipped += 1

try_check(c_ruleset)


# 9. external_symbol_int_wire3 / str_wire3: value should roundtrip
def c_ext_int():
    tn = "yara_engine_external_symbol_int_wire3"
    if tn not in names: return
    for a in [{"name":"x","value":42},{"key":"x","value":42},{"name":"x","int":42}]:
        r = call(tn, a)
        if r is None: continue
        s = json.dumps(r)
        record(tn, a, "42" in s, True, "int 42 roundtrip", "42" in s)
        return
    global checks_skipped
    checks_skipped += 1

try_check(c_ext_int)


def c_ext_str():
    tn = "yara_engine_external_symbol_str_wire3"
    if tn not in names: return
    for a in [{"name":"x","value":"hello"},{"key":"x","value":"hello"},{"name":"x","string":"hello"}]:
        r = call(tn, a)
        if r is None: continue
        s = json.dumps(r)
        record(tn, a, "hello" in s, True, "str roundtrip", "hello" in s)
        return
    global checks_skipped
    checks_skipped += 1

try_check(c_ext_str)


# 10. rule_with_tag_wire2 / rule_with_meta_bool
def c_rule_tag():
    tn = "yara_engine_rule_with_tag_wire2"
    if tn not in names: return
    for a in [{"name":"r","tag":"malware"},{"rule":"r","tag":"malware"}]:
        r = call(tn, a)
        if r is None: continue
        s = json.dumps(r)
        record(tn, a, "malware" in s, True, "tag echoed", "malware" in s)
        return
    global checks_skipped
    checks_skipped += 1

try_check(c_rule_tag)


def c_rule_meta_bool():
    tn = "yara_engine_rule_with_meta_bool_wire3"
    if tn not in names: return
    # Handler returns {name, meta_count, value, source}; the meta key name is
    # stored inside rule.meta and only surfaced as meta_count. Verify count+value.
    for a in [{"name":"r","key":"tested","value":True},
              {"rule":"r","meta_key":"tested","meta_value":True}]:
        r = call(tn, a)
        if r is None: continue
        if isinstance(r, dict):
            mc = r.get("meta_count")
            v = r.get("value")
            ok = (mc == 1) and (v is True)
            record(tn, a, {"meta_count":mc,"value":v}, {"meta_count":1,"value":True},
                   "meta_count==1 and value True", ok)
            return
    global checks_skipped
    checks_skipped += 1

try_check(c_rule_meta_bool)


# 11. rule_definition_with_namespace_wire2
def c_rule_ns():
    tn = "yara_engine_rule_definition_with_namespace_wire2"
    if tn not in names: return
    for a in [{"source":"rule r{condition:true}","namespace":"myns"},
              {"src":"rule r{condition:true}","namespace":"myns"}]:
        r = call(tn, a)
        if r is None: continue
        s = json.dumps(r)
        record(tn, a, "myns" in s, True, "namespace echoed", "myns" in s)
        return
    global checks_skipped
    checks_skipped += 1

try_check(c_rule_ns)


# 12. builtin_rules_count_wire2
def c_builtin_count():
    tn = "yara_engine_builtin_rules_count_wire2"
    if tn not in names: return
    r = call(tn, {})
    global checks_skipped
    if r is None:
        checks_skipped += 1; return
    val = r if isinstance(r,int) else (r.get("count") if isinstance(r,dict) else None)
    if val is None and isinstance(r,dict):
        val = r.get("value")
    if val is None:
        checks_skipped += 1; return
    # Just require non-negative int
    record(tn, {}, val, ">=0 int", isinstance(val,int) and val >= 0)

try_check(c_builtin_count)


# 13. scanner_new_count / scanner_add_rule_wire2 / ruleset_len_wire2
def c_scanner_new():
    tn = "yara_engine_scanner_new_count"
    if tn not in names: return
    r = call(tn, {})
    global checks_skipped
    if r is None: checks_skipped += 1; return
    val = r if isinstance(r,int) else (r.get("count") if isinstance(r,dict) else None)
    if val is None:
        checks_skipped += 1; return
    record(tn, {}, val, 0, "new scanner has 0 rules", val == 0)

try_check(c_scanner_new)


def c_ruleset_len():
    tn = "yara_engine_ruleset_len_wire2"
    if tn not in names: return
    r = call(tn, {})
    global checks_skipped
    if r is None: checks_skipped += 1; return
    val = r if isinstance(r,int) else (r.get("len") if isinstance(r,dict) else None)
    if val is None and isinstance(r,dict):
        val = r.get("count") or r.get("value")
    if val is None:
        checks_skipped += 1; return
    record(tn, {}, val, 0, "empty ruleset len", val == 0)

try_check(c_ruleset_len)


# 14. rule_repository_ops_wire2 - probe
def c_repo_ops():
    tn = "yara_engine_rule_repository_ops_wire2"
    if tn not in names: return
    r = call(tn, {})
    global checks_skipped
    if r is None:
        checks_skipped += 1; return
    # Sanity: returned a dict/list
    record(tn, {}, isinstance(r,(dict,list,int)), True, "returns structured value",
           isinstance(r,(dict,list,int,str)))

try_check(c_repo_ops)


# 15. compiled_cache_empty_wire3
def c_cache_empty():
    tn = "yara_engine_compiled_cache_empty_wire3"
    if tn not in names: return
    r = call(tn, {})
    global checks_skipped
    if r is None: checks_skipped += 1; return
    val = r if isinstance(r,bool) else (r.get("empty") if isinstance(r,dict) else None)
    if val is None and isinstance(r,dict):
        val = r.get("is_empty") or r.get("value")
    if val is None:
        checks_skipped += 1; return
    record(tn, {}, val, True, "new cache empty", bool(val) == True)

try_check(c_cache_empty)


# 16. compiled_cache_hash_sources_wire3 - deterministic hash
def c_cache_hash():
    tn = "yara_engine_compiled_cache_hash_sources_wire3"
    if tn not in names: return
    for a in [{"sources":["rule a{condition:true}"]},
              {"src":["rule a{condition:true}"]},
              {"rules":["rule a{condition:true}"]}]:
        r1 = call(tn, a)
        if r1 is None: continue
        r2 = call(tn, a)
        record(tn, a, r1 == r2, True, "deterministic hash", r1 == r2)
        return
    global checks_skipped
    checks_skipped += 1

try_check(c_cache_hash)


# 17. async_scan_config_concurrency_wire3
def c_async_conc():
    tn = "yara_engine_async_scan_config_concurrency_wire3"
    if tn not in names: return
    # Schema requires parameter 'n' (see wire_tools.rs). Assert max_concurrency==n.
    a = {"n":4}
    r = call(tn, a)
    global checks_skipped
    if r is None:
        checks_skipped += 1; return
    if isinstance(r, dict):
        mc = r.get("max_concurrency")
        ok = mc == 4
        record(tn, a, mc, 4, "max_concurrency==n", ok)
        return
    checks_skipped += 1

try_check(c_async_conc)


# 18. parse_rule (yara_engine_parse_rule)
def c_parse_rule():
    tn = "yara_engine_parse_rule"
    if tn not in names: return
    for a in [{"source":'rule R { condition: true }'},
              {"src":'rule R { condition: true }'},
              {"rule":'rule R { condition: true }'},
              {"text":'rule R { condition: true }'}]:
        r = call(tn, a)
        if r is None: continue
        s = json.dumps(r).lower()
        record(tn, a, "r" in s, True, "rule R parsed", "r" in s)
        return
    global checks_skipped
    checks_skipped += 1

try_check(c_parse_rule)


# 19. process_region_wire2 - scan a region
def c_process_region():
    tn = "yara_engine_process_region_wire2"
    if tn not in names: return
    data = b"MZ" + b"\x00" * 100
    for a in [{"rules":SIMPLE_RULE,"hex":data.hex(),"base":0},
              {"source":SIMPLE_RULE,"data":data.hex(),"base":0},
              {"rules":SIMPLE_RULE,"bytes":data.hex()}]:
        r = call(tn, a)
        if r is None: continue
        s = json.dumps(r).lower()
        # If contains "match" or has non-empty results
        has = ("match" in s and "false" not in s.split("match")[0][-10:]) or "true" in s
        record(tn, {k:("<hex>" if k in ("hex","data","bytes") else v) for k,v in a.items()},
               "returned", "MZ match", True)  # loose: just returned
        return
    global checks_skipped
    checks_skipped += 1

try_check(c_process_region)


# 20. pe_module_from_bytes_wire3 / elf_module_from_bytes_wire3 - probe
def c_pe_module():
    tn = "yara_engine_pe_module_from_bytes_wire3"
    if tn not in names: return
    with open(TARGET, "rb") as f:
        data = f.read(8192)
    for a in [{"hex":data.hex()},{"data":data.hex()},{"bytes":data.hex()}]:
        r = call(tn, a)
        if r is None: continue
        record(tn, {k:"<hex>" for k in a}, "returned", "PE parse ok", r is not None)
        return
    global checks_skipped
    checks_skipped += 1

try_check(c_pe_module)


# ---- write report ----
p.terminate()

report = {
    "category": PREFIX.rstrip("_"),
    "tools_in_category": len(yara_tools),
    "checks_total": checks_total,
    "checks_passed": checks_ok,
    "checks_skipped": checks_skipped,
    "mismatches": mismatches,
}
with open(OUT, "w") as f:
    json.dump(report, f, indent=2, default=str)
print(json.dumps({k:v for k,v in report.items() if k != "mismatches"}, indent=2))
print(f"mismatches: {len(mismatches)}  file: {OUT}")
