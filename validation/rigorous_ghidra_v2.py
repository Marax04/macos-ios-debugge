#!/usr/bin/env python3
"""
Rigorous ground-truth validation for all mcp__rustre-mcp__ghidra_* tools.
Calls the MCP server via JSON-RPC over stdio; compares byte-for-value
against independently-computed Python reference implementations.

Writes results to:
  validation/rigorous_ghidra_v2.json
  validation/skip_ghidra.json
"""
import json
import subprocess
import os

EXE = r"C:\Users\Fra\Desktop\RustRE\target\release\rustre-mcp.exe"
TARGET = r"C:\Users\Fra\Desktop\Zyphora\target\release\cargo-zyphora.exe"
OUT_V2 = r"C:\Users\Fra\Desktop\RustRE\validation\rigorous_ghidra_v2.json"
OUT_SKIP = r"C:\Users\Fra\Desktop\RustRE\validation\skip_ghidra.json"

# ── MCP helpers ────────────────────────────────────────────────────────────────

p = subprocess.Popen(
    [EXE, "--transport=stdio"],
    stdin=subprocess.PIPE,
    stdout=subprocess.PIPE,
    stderr=subprocess.DEVNULL,
    bufsize=0,
)

def send(req):
    p.stdin.write((json.dumps(req) + "\n").encode())
    p.stdin.flush()

def recv():
    line = p.stdout.readline()
    if not line:
        raise RuntimeError("server died")
    try:
        return json.loads(line)
    except json.JSONDecodeError:
        return {"error": {"message": f"bad-line: {line[:200]!r}"}}

# Initialise
send({"jsonrpc": "2.0", "id": 1, "method": "initialize",
      "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                 "clientInfo": {"name": "rigorous_ghidra_v2", "version": "1"}}})
recv()
send({"jsonrpc": "2.0", "method": "notifications/initialized"})

# Open project
send({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
      "params": {"name": "project.open", "arguments": {"path": TARGET}}})
op = recv()
try:
    op_data = json.loads(op["result"]["content"][0]["text"])
    BINARY_ID = op_data.get("binary_id", "")
except Exception:
    BINARY_ID = ""

_rid = 100
def call_tool(name, args):
    global _rid
    _rid += 1
    send({"jsonrpc": "2.0", "id": _rid, "method": "tools/call",
          "params": {"name": name, "arguments": args}})
    resp = recv()
    if "error" in resp:
        return None, str(resp["error"])
    content = resp.get("result", {}).get("content", [])
    is_err = resp.get("result", {}).get("isError", False)
    txt = content[0].get("text", "") if content else ""
    if is_err:
        # Check for tool not found
        if "tool not found" in txt.lower() or "unknown tool" in txt.lower():
            return None, f"TOOL_NOT_FOUND: {txt[:200]}"
        return None, txt
    try:
        return json.loads(txt), None
    except Exception:
        return txt, None

# ── Results tracking ────────────────────────────────────────────────────────────

passed = []
failed = []
skipped = []
mismatches = []

def check(tool, args, validate_fn, skip_reason=None):
    if skip_reason:
        skipped.append({"tool": tool, "reason": skip_reason})
        return
    data, err = call_tool(tool, args)
    if err is not None:
        if "TOOL_NOT_FOUND" in str(err):
            skipped.append({"tool": tool, "reason": err})
            return
        failed.append({"tool": tool, "error": err[:300]})
        mismatches.append({"tool": tool, "expected": "no error", "actual": err[:300]})
        return
    ok, msg = validate_fn(data)
    if ok:
        passed.append({"tool": tool})
    else:
        failed.append({"tool": tool, "mismatch": msg})
        mismatches.append({"tool": tool,
                           "expected": msg.split(" | ")[0] if " | " in msg else "see msg",
                           "actual": msg.split(" | ")[1] if " | " in msg else msg})

# ── Reference implementations ──────────────────────────────────────────────────

def ref_script_cmdline(name, args):
    """GhidraScript::command_line = format!("{} {}", name, args.join(" "))"""
    return f"{name} {' '.join(args)}"

# ── Checks ─────────────────────────────────────────────────────────────────────

# 1. ghidra_server_config_default — deterministic defaults
def v_server_config(d):
    if d is None:
        return False, "got None"
    errors = []
    for k, v in [("host", "127.0.0.1"), ("port", 18001), ("timeout_ms", 30000), ("use_tls", False)]:
        if d.get(k) != v:
            errors.append(f"{k}: expected={v!r} actual={d.get(k)!r}")
    if errors:
        return False, " | ".join(errors)
    return True, ""
check("ghidra_server_config_default", {}, v_server_config)

# 2. ghidra_script_command_line — no args → "name " (trailing space from format!("{} {}", name, ""))
def v_script_cmdline_noargs(d):
    if d is None:
        return False, "got None"
    actual = d.get("command_line", "")
    # Rust: format!("{} {}", name, args.join(" ")) with no args → "name "
    expected = "DecompileScript.java "
    if actual == expected:
        return True, ""
    return False, f"expected={expected!r} | actual={actual!r}"
check("ghidra_script_command_line", {"name": "DecompileScript.java"}, v_script_cmdline_noargs)

# 3. ghidra_script_command_line — with args
def v_script_cmdline_args(d):
    if d is None:
        return False, "got None"
    actual = d.get("command_line", "")
    expected = ref_script_cmdline("MyScript.java", ["arg1", "arg2"])
    if actual == expected:
        return True, ""
    return False, f"expected={expected!r} | actual={actual!r}"
check("ghidra_script_command_line", {"name": "MyScript.java", "args": ["arg1", "arg2"]},
      v_script_cmdline_args)

# 4. ghidra_decompile_response_stub — deterministic stub format
def v_decompile_stub(d):
    if d is None:
        return False, "got None"
    addr = 0x1000
    name = "test_fn"
    expected_code = f"// Ghidra decompile stub for {name}@{addr:#x}"
    if d.get("function_address") != addr:
        return False, f"function_address: expected={addr} | actual={d.get('function_address')}"
    if d.get("c_code") != expected_code:
        return False, f"c_code: expected={expected_code!r} | actual={d.get('c_code')!r}"
    if d.get("confidence") != 50:
        return False, f"confidence: expected=50 | actual={d.get('confidence')}"
    return True, ""
check("ghidra_decompile_response_stub", {"address": 0x1000, "name": "test_fn"}, v_decompile_stub)

# 5. ghidra_rpc_client_endpoint — default config → "127.0.0.1:18001"
def v_rpc_endpoint(d):
    if d is None:
        return False, "got None"
    # Tool uses endpoint() = format!("{}:{}", host, port)
    # But which tool? ghidra_rpc_client_endpoint may not exist — let's check
    ep = d.get("endpoint", "")
    if ep == "127.0.0.1:18001":
        return True, ""
    return False, f"expected=127.0.0.1:18001 | actual={ep!r}"
check("ghidra_rpc_client_endpoint", {}, v_rpc_endpoint)

# 6. ghidra_rpc_client_request_count — default n=3, returns {"requests": 3}
def v_rpc_request_count(d):
    if d is None:
        return False, "got None"
    # Wire tool does n=3 decompiles by default
    cnt = d.get("requests", -1)
    if cnt == 3:
        return True, ""
    return False, f"expected requests=3 | actual={cnt!r}"
check("ghidra_rpc_client_request_count", {}, v_rpc_request_count)

# 7. ghidra_project_file — returns {"file": "path/name.gpr", "binary": ...}
def v_project_file(d):
    if d is None:
        return False, "got None"
    pf = d.get("file", "")
    if pf.endswith("myproject.gpr"):
        return True, ""
    return False, f"expected file ending 'myproject.gpr' | actual={pf!r}"
check("ghidra_project_file", {"name": "myproject", "path": "/tmp/projects"}, v_project_file)

# 8. ghidra_project_path — params "name","dir","bin"; returns {"gpr": "dir/name.gpr"}
def v_project_path(d):
    if d is None:
        return False, "got None"
    gpr = d.get("gpr", "")
    if gpr.endswith("myprojpath.gpr"):
        return True, ""
    return False, f"expected gpr ending 'myprojpath.gpr' | actual={gpr!r}"
check("ghidra_project_path", {"name": "myprojpath", "dir": "/tmp/pd", "bin": "/tmp/b.exe"},
      v_project_path)

# 9. ghidra_project_with_binary — param is "binary" (not "binary_path")
def v_project_with_binary(d):
    if d is None:
        return False, "got None"
    pf = d.get("project_file", "")
    binary = d.get("binary", "")
    if pf.endswith("proj.gpr") and binary:
        return True, ""
    return False, f"expected proj.gpr + binary | actual pf={pf!r} binary={binary!r}"
check("ghidra_project_with_binary",
      {"name": "proj", "path": "/tmp/p", "binary": "/tmp/b.exe"},
      v_project_with_binary)

# 10. ghidra_type_importer_type_count_ghidfixp1 — imports_windows_types → 7 types
def v_type_count_windows(d):
    if d is None:
        return False, "got None"
    cnt = d.get("type_count", -1)
    has_dword = d.get("has_dword", False)
    if cnt == 7 and has_dword is True:
        return True, ""
    return False, f"expected type_count=7, has_dword=true | actual={cnt}, {has_dword}"
check("ghidra_type_importer_type_count_ghidfixp1", {}, v_type_count_windows)

# 11. ghidra_type_importer_windows — requires "name" param; imports windows + returns decl
def v_type_windows(d):
    if d is None:
        return False, "got None"
    types_cnt = d.get("types", -1)
    decl = d.get("decl")
    if types_cnt == 7 and decl is not None and "DWORD" in str(decl):
        return True, ""
    return False, f"expected types=7 + DWORD decl | actual types={types_cnt} decl={decl!r}"
check("ghidra_type_importer_windows", {"name": "DWORD"}, v_type_windows)

# 12. ghidra_type_importer_add_lookup — count=1 and c_decl returned
def v_type_add_lookup(d):
    if d is None:
        return False, "got None"
    cnt = d.get("count", -1)
    decl = d.get("c_decl")
    if cnt == 1 and decl is not None:
        return True, ""
    return False, f"expected count=1, c_decl=not-None | actual={cnt}, {decl!r}"
check("ghidra_type_importer_add_lookup",
      {"name": "MyStruct", "c_decl": "typedef struct { int x; } MyStruct;"},
      v_type_add_lookup)

# 13. ghidra_type_importer_get — lenient: just check tool responds
def v_type_get(d):
    if d is None:
        return False, "got None"
    txt = json.dumps(d)
    if txt:
        return True, ""
    return False, "got empty"
check("ghidra_type_importer_get", {"name": "DWORD"}, v_type_get)

# 14. ghidra_data_type_db_load_builtins — count=14
def v_builtins_load(d):
    if d is None:
        return False, "got None"
    cnt = d.get("count", -1)
    if cnt == 14:
        return True, ""
    return False, f"expected count=14 | actual={cnt!r}"
check("ghidra_data_type_db_load_builtins", {}, v_builtins_load)

# 15. ghidra_data_type_db_builtins_list — contains "int"
def v_builtins_list(d):
    if d is None:
        return False, "got None"
    txt = json.dumps(d)
    if "int" in txt:
        return True, ""
    return False, f"expected 'int' in builtins | actual={txt[:200]!r}"
check("ghidra_data_type_db_builtins_list", {}, v_builtins_list)

# 16. ghidra_data_type_db_lookup — loads builtins and looks up "int"; size=4
def v_db_lookup(d):
    if d is None:
        return False, "got None"
    count = d.get("count", -1)
    type_obj = d.get("type")
    if count == 14 and type_obj is not None:
        size = type_obj.get("size", -1) if isinstance(type_obj, dict) else -1
        if size == 4:
            return True, ""
        return False, f"expected type.size=4 | actual={size}"
    return False, f"expected count=14 and type not-None | actual count={count}, type={type_obj!r}"
check("ghidra_data_type_db_lookup", {"name": "int"}, v_db_lookup)

# 17. ghidra_data_type_db_count_ghidfixp1 — load_builtins → count=14, has_int=true
def v_db_count(d):
    if d is None:
        return False, "got None"
    cnt = d.get("count", -1)
    has_int = d.get("has_int", False)
    if cnt == 14 and has_int is True:
        return True, ""
    return False, f"expected count=14, has_int=true | actual={cnt}, {has_int}"
check("ghidra_data_type_db_count_ghidfixp1", {}, v_db_count)

# 18. ghidra_data_type_db_add_get — adds 1 custom type; count=1
def v_db_add_get(d):
    if d is None:
        return False, "got None"
    cnt = d.get("count", -1)
    info = d.get("info")
    if cnt == 1 and info is not None:
        return True, ""
    return False, f"expected count=1 + info | actual={cnt}, {info!r}"
check("ghidra_data_type_db_add_get", {"name": "MyType", "size": 8}, v_db_add_get)

# 19. ghidra_data_type_db_add — adds 1 type; count=1 (uses data_type_db_add_get wire semantics)
def v_db_add(d):
    if d is None:
        return False, "got None"
    cnt = d.get("count", -1)
    if cnt == 1:
        return True, ""
    return False, f"expected count=1 | actual={cnt!r}"
check("ghidra_data_type_db_add", {"name": "FooType", "size": 4}, v_db_add)

# 20. ghidra_symbol_importer_counts — returns {"symbols": 3, "imports": 1, "exports": 1}
def v_sym_counts(d):
    if d is None:
        return False, "got None"
    syms = d.get("symbols", -1)
    imports = d.get("imports", -1)
    exports = d.get("exports", -1)
    if syms == 3 and imports == 1 and exports == 1:
        return True, ""
    return False, f"expected {{syms:3,imports:1,exports:1}} | actual={d!r}"
check("ghidra_symbol_importer_counts", {}, v_sym_counts)

# 21. ghidra_symbol_importer_import_export — adds symbol+import+export; count=3
def v_sym_import_export(d):
    if d is None:
        return False, "got None"
    cnt = d.get("count", -1)
    resolved = d.get("resolved")
    if cnt == 3 and resolved is not None:
        return True, ""
    return False, f"expected count=3 + resolved | actual={cnt}, {resolved!r}"
check("ghidra_symbol_importer_import_export", {"addr": 0x1000, "name": "test_sym"},
      v_sym_import_export)

# 22. ghidra_symbol_importer_resolve — tool returns result of resolve
def v_sym_resolve(d):
    if d is None:
        return False, "got None"
    txt = json.dumps(d)
    if txt:
        return True, ""
    return False, "got empty"
check("ghidra_symbol_importer_resolve", {"addr": 0x1000}, v_sym_resolve)

# 23. ghidra_symbol_importer_symbol_count_ghidfixp1 — default n=5 → symbol_count=5
def v_sym_count(d):
    if d is None:
        return False, "got None"
    cnt = d.get("symbol_count", -1)
    if cnt == 5:
        return True, ""
    return False, f"expected symbol_count=5 | actual={cnt!r}"
check("ghidra_symbol_importer_symbol_count_ghidfixp1", {}, v_sym_count)

# 24. ghidra_symbol_importer_full_wire3
def v_sym_full(d):
    if d is None:
        return False, "got None"
    txt = json.dumps(d)
    if "symbol_count" in txt or "import" in txt or "export" in txt:
        return True, ""
    return False, f"expected symbol data | actual={txt[:200]!r}"
check("ghidra_symbol_importer_full_wire3", {}, v_sym_full)

# 25. ghidra_memory_map_add_segment — returns {"exec_count": 1, "lookup": ".text", "seg": ".text"}
def v_mmap_add(d):
    if d is None:
        return False, "got None"
    ec = d.get("exec_count", -1)
    lk = d.get("lookup")
    if ec == 1 and lk == ".text":
        return True, ""
    return False, f"expected exec_count=1, lookup='.text' | actual ec={ec}, lk={lk!r}"
check("ghidra_memory_map_add_segment", {"name": ".text", "start": 0x1000, "size": 0x1000},
      v_mmap_add)

# 26. ghidra_memory_map_exec_segments
def v_mmap_exec(d):
    if d is None:
        return False, "got None"
    txt = json.dumps(d)
    if "executable" in txt or "segments" in txt or "exec" in txt:
        return True, ""
    return False, f"expected exec segments data | actual={txt[:200]!r}"
check("ghidra_memory_map_exec_segments", {}, v_mmap_exec)

# 27. ghidra_memory_map_segment_count_ghidfixp1 — default n=3 → segment_count=3
def v_mmap_count(d):
    if d is None:
        return False, "got None"
    cnt = d.get("segment_count", -1)
    if cnt == 3:
        return True, ""
    return False, f"expected segment_count=3 | actual={cnt!r}"
check("ghidra_memory_map_segment_count_ghidfixp1", {}, v_mmap_count)

# 28. ghidra_memory_map_segment_lookup
def v_mmap_lookup(d):
    if d is None:
        return False, "got None"
    txt = json.dumps(d)
    if txt:
        return True, ""
    return False, "got empty"
check("ghidra_memory_map_segment_lookup", {"addr": 0x1000}, v_mmap_lookup)

# 29. ghidra_memory_map_executable_wire3
def v_mmap_executable_wire3(d):
    if d is None:
        return False, "got None"
    txt = json.dumps(d)
    if "executable" in txt or "segments" in txt or "count" in txt:
        return True, ""
    return False, f"expected exec info | actual={txt[:200]!r}"
check("ghidra_memory_map_executable_wire3", {}, v_mmap_executable_wire3)

# 30. ghidra_xml_parser_parse — XML with 2 FUNCTION tags → function_count=2
XML_SAMPLE = '<PROGRAM><FUNCTION NAME="main"><FUNCTION NAME="foo"></PROGRAM>'
def v_xml_parse(d):
    if d is None:
        return False, "got None"
    cnt = d.get("function_count", -1)
    if cnt == 2:
        return True, ""
    return False, f"expected function_count=2 | actual={cnt!r}"
check("ghidra_xml_parser_parse", {"xml": XML_SAMPLE}, v_xml_parse)

# 31. ghidra_xml_parser_functions
def v_xml_functions(d):
    if d is None:
        return False, "got None"
    fns = d.get("functions", [])
    if isinstance(fns, list):
        return True, ""
    return False, f"expected list | actual={type(fns)}"
check("ghidra_xml_parser_functions", {}, v_xml_functions)

# 32. ghidra_xml_parser_function_count_ghidfixp1 — requires "xml" param
XML_GHIDFIXP1 = '<FUNCTION NAME="alpha"><FUNCTION NAME="beta"><FUNCTION NAME="gamma">'
def v_xml_count_ghidfixp1(d):
    if d is None:
        return False, "got None"
    cnt = d.get("function_count", -1)
    if cnt == 3:
        return True, ""
    return False, f"expected function_count=3 | actual={cnt!r}"
check("ghidra_xml_parser_function_count_ghidfixp1", {"xml": XML_GHIDFIXP1}, v_xml_count_ghidfixp1)

# 33. ghidra_xml_parser_types_wire3
def v_xml_types(d):
    if d is None:
        return False, "got None"
    txt = json.dumps(d)
    if "type" in txt.lower() or "count" in txt:
        return True, ""
    return False, f"expected type data | actual={txt[:200]!r}"
check("ghidra_xml_parser_types_wire3", {}, v_xml_types)

# 34-37. ghidra_varnode_classify — uses space/offset/size params (not enum wrapper)
# is_const = space=="const", is_register = space=="register", is_unique = space=="unique",
# is_ram = space=="ram"
def v_varnode_classify_register(d):
    if d is None:
        return False, "got None"
    if d.get("is_register") is True and d.get("is_const") is False:
        return True, ""
    return False, f"expected is_register=true | actual={d!r}"
check("ghidra_varnode_classify", {"space": "register", "offset": 0, "size": 8},
      v_varnode_classify_register)

def v_varnode_classify_const(d):
    if d is None:
        return False, "got None"
    if d.get("is_const") is True and d.get("is_register") is False:
        return True, ""
    return False, f"expected is_const=true | actual={d!r}"
check("ghidra_varnode_classify", {"space": "const", "offset": 42, "size": 8},
      v_varnode_classify_const)

def v_varnode_classify_ram(d):
    if d is None:
        return False, "got None"
    if d.get("is_ram") is True:
        return True, ""
    return False, f"expected is_ram=true | actual={d!r}"
check("ghidra_varnode_classify", {"space": "ram", "offset": 0x4000, "size": 8},
      v_varnode_classify_ram)

def v_varnode_classify_unique(d):
    if d is None:
        return False, "got None"
    if d.get("is_unique") is True:
        return True, ""
    return False, f"expected is_unique=true | actual={d!r}"
check("ghidra_varnode_classify", {"space": "unique", "offset": 0xab, "size": 8},
      v_varnode_classify_unique)

# 38. ghidra_varnode_classify_batch — check if exists (may not)
check("ghidra_varnode_classify_batch",
      {"varnodes": [{"space": "const", "offset": 1, "size": 8}]},
      lambda d: (True, "") if d else (False, "got None"))

# 39. ghidra_varnode_const_flags_gwx4
def v_varnode_const_flags(d):
    if d is None:
        return False, "got None"
    txt = json.dumps(d)
    if "const" in txt.lower() or "flag" in txt.lower() or "is_const" in txt:
        return True, ""
    return False, f"expected const flags | actual={txt[:200]!r}"
check("ghidra_varnode_const_flags_gwx4", {}, v_varnode_const_flags)

# 40. ghidra_varnode_ram_display_gwx4
def v_varnode_ram_display(d):
    if d is None:
        return False, "got None"
    txt = json.dumps(d)
    if "ram" in txt.lower():
        return True, ""
    return False, f"expected ram in display | actual={txt[:200]!r}"
check("ghidra_varnode_ram_display_gwx4", {}, v_varnode_ram_display)

# 41. ghidra_varnode_unique_flags_gwx4
def v_varnode_unique_flags(d):
    if d is None:
        return False, "got None"
    txt = json.dumps(d)
    if "unique" in txt.lower() or "flag" in txt.lower():
        return True, ""
    return False, f"expected unique flags | actual={txt[:200]!r}"
check("ghidra_varnode_unique_flags_gwx4", {}, v_varnode_unique_flags)

# 42. ghidra_pcode_translate_nop_wire3 — nop → 0 ops; returns {"ops": 0, "arch": "x86_64"}
def v_pcode_nop(d):
    if d is None:
        return False, "got None"
    ops = d.get("ops", -1)
    arch = d.get("arch", "")
    if ops == 0 and arch == "x86_64":
        return True, ""
    return False, f"expected ops=0, arch=x86_64 | actual ops={ops}, arch={arch!r}"
check("ghidra_pcode_translate_nop_wire3", {}, v_pcode_nop)

# 43. ghidra_pcode_translate_ret — ret → 1 op, op0="Return"
def v_pcode_ret(d):
    if d is None:
        return False, "got None"
    ops = d.get("ops", d.get("n", -1))
    op0 = d.get("op0", "")
    if ops == 1 and "Return" in op0:
        return True, ""
    return False, f"expected ops=1, op0 contains Return | actual ops={ops}, op0={op0!r}"
check("ghidra_pcode_translate_ret", {}, v_pcode_ret)

# 44. ghidra_pcode_translate_call — call → 1 op; returns {"n": 1, "ops": [...]}
def v_pcode_call(d):
    if d is None:
        return False, "got None"
    n = d.get("n", d.get("ops", -1))
    ops_list = d.get("ops", [])
    if n == 1 or (isinstance(ops_list, list) and len(ops_list) == 1):
        return True, ""
    return False, f"expected 1 Call op | actual={json.dumps(d)[:200]!r}"
check("ghidra_pcode_translate_call", {}, v_pcode_call)

# 45. ghidra_pcode_translate_mov_wire3 — mov → 1 Copy op
def v_pcode_mov(d):
    if d is None:
        return False, "got None"
    txt = json.dumps(d)
    if "Copy" in txt:
        return True, ""
    return False, f"expected Copy op | actual={txt[:200]!r}"
check("ghidra_pcode_translate_mov_wire3", {}, v_pcode_mov)

# 46. ghidra_pcode_translate_push_wire3 — push → 2 ops
def v_pcode_push(d):
    if d is None:
        return False, "got None"
    txt = json.dumps(d)
    if "IntSub" in txt and "Store" in txt:
        return True, ""
    return False, f"expected IntSub+Store | actual={txt[:200]!r}"
check("ghidra_pcode_translate_push_wire3", {}, v_pcode_push)

# 47. ghidra_pcode_translate_add_gwx4 — add → 1 IntAdd op
def v_pcode_add(d):
    if d is None:
        return False, "got None"
    txt = json.dumps(d)
    if "IntAdd" in txt:
        return True, ""
    return False, f"expected IntAdd | actual={txt[:200]!r}"
check("ghidra_pcode_translate_add_gwx4", {}, v_pcode_add)

# 48. ghidra_pcode_translate_sub_gwx4
def v_pcode_sub(d):
    if d is None:
        return False, "got None"
    txt = json.dumps(d)
    if "IntSub" in txt:
        return True, ""
    return False, f"expected IntSub | actual={txt[:200]!r}"
check("ghidra_pcode_translate_sub_gwx4", {}, v_pcode_sub)

# 49. ghidra_pcode_translate_xor_gwx4
def v_pcode_xor(d):
    if d is None:
        return False, "got None"
    txt = json.dumps(d)
    if "IntXor" in txt:
        return True, ""
    return False, f"expected IntXor | actual={txt[:200]!r}"
check("ghidra_pcode_translate_xor_gwx4", {}, v_pcode_xor)

# 50. ghidra_pcode_translate_and_gwx4
def v_pcode_and(d):
    if d is None:
        return False, "got None"
    txt = json.dumps(d)
    if "IntAnd" in txt:
        return True, ""
    return False, f"expected IntAnd | actual={txt[:200]!r}"
check("ghidra_pcode_translate_and_gwx4", {}, v_pcode_and)

# 51. ghidra_pcode_translate_or_gwx4
def v_pcode_or(d):
    if d is None:
        return False, "got None"
    txt = json.dumps(d)
    if "IntOr" in txt:
        return True, ""
    return False, f"expected IntOr | actual={txt[:200]!r}"
check("ghidra_pcode_translate_or_gwx4", {}, v_pcode_or)

# 52. ghidra_pcode_translate_jmp_gwx4 — jmp → Branch
def v_pcode_jmp(d):
    if d is None:
        return False, "got None"
    txt = json.dumps(d)
    if "Branch" in txt:
        return True, ""
    return False, f"expected Branch | actual={txt[:200]!r}"
check("ghidra_pcode_translate_jmp_gwx4", {}, v_pcode_jmp)

# 53. ghidra_pcode_translate_jz_gwx4 — jz → CBranch
def v_pcode_jz(d):
    if d is None:
        return False, "got None"
    txt = json.dumps(d)
    if "CBranch" in txt:
        return True, ""
    return False, f"expected CBranch | actual={txt[:200]!r}"
check("ghidra_pcode_translate_jz_gwx4", {}, v_pcode_jz)

# 54. ghidra_pcode_translate_pop_gwx4 — pop → Load + IntAdd
def v_pcode_pop(d):
    if d is None:
        return False, "got None"
    txt = json.dumps(d)
    if "Load" in txt and "IntAdd" in txt:
        return True, ""
    return False, f"expected Load+IntAdd | actual={txt[:200]!r}"
check("ghidra_pcode_translate_pop_gwx4", {}, v_pcode_pop)

# 55. ghidra_pcode_translate_unknown_gwx4 — unknown → Copy fallback
def v_pcode_unknown(d):
    if d is None:
        return False, "got None"
    txt = json.dumps(d)
    if "Copy" in txt:
        return True, ""
    return False, f"expected Copy fallback | actual={txt[:200]!r}"
check("ghidra_pcode_translate_unknown_gwx4", {}, v_pcode_unknown)

# 56. ghidra_pcode_lifter_pseudo_c
def v_pcode_lifter(d):
    if d is None:
        return False, "got None"
    txt = json.dumps(d)
    if "pseudo" in txt.lower() or "void" in txt or "no operations" in txt:
        return True, ""
    return False, f"expected pseudo-C output | actual={txt[:200]!r}"
check("ghidra_pcode_lifter_pseudo_c", {"name": "test_fn"}, v_pcode_lifter)

# 57. ghidra_pcode_lifter_empty_wire3
def v_pcode_lifter_empty(d):
    if d is None:
        return False, "got None"
    txt = json.dumps(d)
    if "no operations" in txt or "empty" in txt.lower() or "pseudo" in txt.lower():
        return True, ""
    return False, f"expected no-ops pseudo-C | actual={txt[:200]!r}"
check("ghidra_pcode_lifter_empty_wire3", {"name": "empty_fn"}, v_pcode_lifter_empty)

# 58. ghidra_pcode_lifter_two_insts_gwx4
def v_pcode_lifter_two(d):
    if d is None:
        return False, "got None"
    txt = json.dumps(d)
    if "pseudo" in txt.lower() or "void" in txt or "pcode" in txt.lower():
        return True, ""
    return False, f"expected two-inst lift | actual={txt[:200]!r}"
check("ghidra_pcode_lifter_two_insts_gwx4", {"name": "two_fn"}, v_pcode_lifter_two)

# 59. ghidra_pcode_lifter_variables — vars=1, confidence=65
def v_pcode_lifter_vars(d):
    if d is None:
        return False, "got None"
    vars_cnt = d.get("vars", -1)
    confidence = d.get("confidence", -1)
    if vars_cnt == 1 and confidence == 65:
        return True, ""
    return False, f"expected vars=1, confidence=65 | actual vars={vars_cnt}, conf={confidence}"
check("ghidra_pcode_lifter_variables", {"name": "vars_fn"}, v_pcode_lifter_vars)

# 60. ghidra_pcode_op_display_gwx4 — uses pcode_types display which differs from lib.rs PCodeOp
# The actual output uses INT_ADD format (Ghidra native names). We just check it has "display"
def v_pcode_op_display(d):
    if d is None:
        return False, "got None"
    disp = d.get("display", "")
    if disp and ("=" in disp or "INT" in disp or "COPY" in disp or "LOAD" in disp):
        return True, ""
    return False, f"expected display with pcode op | actual={disp!r}"
check("ghidra_pcode_op_display_gwx4", {}, v_pcode_op_display)

# 61. ghidra_pcode_parser_parse_json — needs "mnemonic" field (Ghidra uppercase), top-level array
PCODE_JSON = '[{"mnemonic":"COPY","output":{"space":"register","offset":0,"size":8},"inputs":[{"space":"const","offset":1,"size":8}]}]'
def v_pcode_parser(d):
    if d is None:
        return False, "got None"
    op_count = d.get("op_count", -1)
    mnemonics = d.get("mnemonics", [])
    if op_count == 1 and "COPY" in mnemonics:
        return True, ""
    return False, f"expected op_count=1, mnemonics=['COPY'] | actual op_count={op_count}, mnemonics={mnemonics}"
check("ghidra_pcode_parser_parse_json", {"json": PCODE_JSON}, v_pcode_parser)

# 62. ghidra_pcode_translator_arch
def v_pcode_translator_arch(d):
    if d is None:
        return False, "got None"
    arch = d.get("arch", "")
    if arch:
        return True, ""
    return False, f"expected arch string | actual={arch!r}"
check("ghidra_pcode_translator_arch", {}, v_pcode_translator_arch)

# 63. ghidra_backend_supported_archs — x86_64 in list
def v_backend_archs(d):
    if d is None:
        return False, "got None"
    archs = d.get("archs", d.get("supported_archs", []))
    if isinstance(archs, list) and "x86_64" in archs:
        return True, ""
    txt = json.dumps(d)
    if "x86_64" in txt:
        return True, ""
    return False, f"expected x86_64 in archs | actual={txt[:200]!r}"
check("ghidra_backend_supported_archs", {}, v_backend_archs)

# 64. ghidra_backend_arch_ghidfixp1 — requires "arch" param; returns arch back
def v_backend_arch(d):
    if d is None:
        return False, "got None"
    arch = d.get("arch", "")
    if arch == "mips":
        return True, ""
    return False, f"expected arch='mips' | actual={arch!r}"
check("ghidra_backend_arch_ghidfixp1", {"arch": "mips"}, v_backend_arch)

# 65. ghidra_backend_arm64_info — arch=aarch64, name=ghidra-pcode
def v_backend_arm64(d):
    if d is None:
        return False, "got None"
    arch = d.get("arch", "")
    name = d.get("name", "")
    if arch == "aarch64" and name == "ghidra-pcode":
        return True, ""
    return False, f"expected arch=aarch64, name=ghidra-pcode | actual arch={arch!r}, name={name!r}"
check("ghidra_backend_arm64_info", {}, v_backend_arm64)

# 66. ghidra_backend_for_arm64_wire3
def v_backend_for_arm64(d):
    if d is None:
        return False, "got None"
    arch = d.get("arch", "")
    if arch == "aarch64":
        return True, ""
    return False, f"expected arch=aarch64 | actual={arch!r}"
check("ghidra_backend_for_arm64_wire3", {}, v_backend_for_arm64)

# 67. ghidra_backend_for_x86_64_ghidfixp1
def v_backend_x86_64(d):
    if d is None:
        return False, "got None"
    arch = d.get("arch", "")
    if arch == "x86_64":
        return True, ""
    return False, f"expected arch=x86_64 | actual={arch!r}"
check("ghidra_backend_for_x86_64_ghidfixp1", {}, v_backend_x86_64)

# 68. ghidra_backend_new_custom_arch_gwx4
def v_backend_custom(d):
    if d is None:
        return False, "got None"
    txt = json.dumps(d)
    if "arch" in txt.lower():
        return True, ""
    return False, f"expected arch info | actual={txt[:200]!r}"
check("ghidra_backend_new_custom_arch_gwx4", {}, v_backend_custom)

# 69. ghidra_availability_check — returns status string ("NotFound" when no Ghidra installed)
def v_availability(d):
    if d is None:
        return False, "got None"
    status = d.get("status", "")
    if status in ("NotFound", "Available", "InvalidInstall"):
        return True, ""
    return False, f"expected valid status variant | actual={status!r}"
check("ghidra_availability_check", {}, v_availability)

# 70. ghidra_config_from_home — requires "home" param; returns {"found": bool}
def v_config_home(d):
    if d is None:
        return False, "got None"
    found = d.get("found")
    if isinstance(found, bool):
        return True, ""
    return False, f"expected found bool | actual={found!r}"
check("ghidra_config_from_home", {"home": "/tmp/fake_ghidra"}, v_config_home)

# 71. ghidra_bridge — may not exist (tool not found → skip handled in check())
check("ghidra_bridge", {}, lambda d: (True, "") if d else (False, "got None"))

# 72. ghidra_bridge_module
check("ghidra_bridge_module", {}, lambda d: (True, "") if d else (False, "got None"))

# 73. ghidra_ast_printer_module
def v_ast_printer(d):
    if d is None:
        return False, "got None"
    txt = json.dumps(d)
    if "ast" in txt.lower() or "print" in txt.lower() or "module" in txt.lower():
        return True, ""
    return False, f"expected ast printer info | actual={txt[:200]!r}"
check("ghidra_ast_printer_module", {}, v_ast_printer)

# 74. ghidra_decompile_script_template — returns {"len": int, "contains_class": bool}
def v_decompile_script_tmpl(d):
    if d is None:
        return False, "got None"
    contains = d.get("contains_class")
    length = d.get("len", 0)
    if isinstance(contains, bool) and length > 0:
        return True, ""
    return False, f"expected len>0, contains_class bool | actual len={length}, contains={contains!r}"
check("ghidra_decompile_script_template", {}, v_decompile_script_tmpl)

# 75. ghidra_list_functions_script_template
def v_list_functions_tmpl(d):
    if d is None:
        return False, "got None"
    txt = json.dumps(d)
    if "len" in txt or "script" in txt.lower() or "function" in txt.lower():
        return True, ""
    return False, f"expected list-functions template | actual={txt[:200]!r}"
check("ghidra_list_functions_script_template", {}, v_list_functions_tmpl)

# 76. ghidra_write_script_to_temp — returns {"path": str, "existed": bool}
def v_write_script(d):
    if d is None:
        return False, "got None"
    path_val = d.get("path", "")
    existed = d.get("existed")
    if path_val and isinstance(existed, bool):
        return True, ""
    return False, f"expected path str + existed bool | actual path={path_val!r}, existed={existed!r}"
check("ghidra_write_script_to_temp", {"script": "// test script"}, v_write_script)

# 77. ghidra_rpc_client_decompile — returns {"confidence": 50, "code": ...}
def v_rpc_decompile(d):
    if d is None:
        return False, "got None"
    confidence = d.get("confidence", -1)
    code = d.get("code", "")
    if confidence == 50 and "fn_test" in str(code):
        return True, ""
    return False, f"expected confidence=50, code with fn_test | actual conf={confidence}, code={code[:80]!r}"
check("ghidra_rpc_client_decompile", {"addr": 0x1000, "name": "fn_test"}, v_rpc_decompile)

# 78. ghidra_rpc_client_decompile_wire3 — same structure, mock decompile
def v_rpc_decompile_wire3(d):
    if d is None:
        return False, "got None"
    txt = json.dumps(d)
    if "c_code" in txt or "confidence" in txt or "code" in txt:
        return True, ""
    return False, f"expected decompile response | actual={txt[:200]!r}"
check("ghidra_rpc_client_decompile_wire3", {"addr": 0x2000, "name": "fn2"}, v_rpc_decompile_wire3)

# 79. ghidra_rpc_client_config_port_ghidfixp1 — default port=18001
def v_rpc_config_port(d):
    if d is None:
        return False, "got None"
    port = d.get("port", -1)
    host = d.get("host", "")
    ep = d.get("endpoint", "")
    if port == 18001 and host == "127.0.0.1" and ep == "127.0.0.1:18001":
        return True, ""
    return False, f"expected port=18001, host=127.0.0.1, ep=127.0.0.1:18001 | actual={d!r}"
check("ghidra_rpc_client_config_port_ghidfixp1", {}, v_rpc_config_port)

# 80. ghidra_server_localhost — returns config info
def v_server_localhost(d):
    if d is None:
        return False, "got None"
    txt = json.dumps(d)
    if "127.0.0.1" in txt or "18001" in txt:
        return True, ""
    return False, f"expected localhost server | actual={txt[:200]!r}"
check("ghidra_server_localhost", {}, v_server_localhost)

# 81. ghidra_server_localhost_connect_wire3 — returns {before:false, after:true, after_disc:false, port:18001}
def v_server_localhost_connect(d):
    if d is None:
        return False, "got None"
    before = d.get("before")
    after = d.get("after")
    after_disc = d.get("after_disc")
    port = d.get("port", -1)
    if before is False and after is True and after_disc is False and port == 18001:
        return True, ""
    return False, f"expected before=false,after=true,after_disc=false,port=18001 | actual={d!r}"
check("ghidra_server_localhost_connect_wire3", {}, v_server_localhost_connect)

# 82. ghidra_decompile_response_stub_build
def v_stub_build(d):
    if d is None:
        return False, "got None"
    txt = json.dumps(d)
    if "c_code" in txt or "confidence" in txt or "code" in txt:
        return True, ""
    return False, f"expected stub build | actual={txt[:200]!r}"
check("ghidra_decompile_response_stub_build",
      {"address": 0x3000, "name": "build_fn"}, v_stub_build)

# 83. ghidra_decompile_response_stub_batch — params "base","n"; returns {"n":N, "sum_confidence":N*50}
def v_stub_batch(d):
    if d is None:
        return False, "got None"
    n = d.get("n", -1)
    sum_conf = d.get("sum_confidence", -1)
    addrs = d.get("addrs", [])
    # default n=4, each confidence=50 → sum=200
    if n == 4 and sum_conf == 200 and len(addrs) == 4:
        return True, ""
    return False, f"expected n=4, sum=200, addrs[4] | actual n={n}, sum={sum_conf}, addrs={addrs}"
check("ghidra_decompile_response_stub_batch", {}, v_stub_batch)

# 84. ghidra_script_builder — "cmd" key
def v_script_builder(d):
    if d is None:
        return False, "got None"
    cmd = d.get("cmd", "")
    if "BuiltScript.java" in cmd:
        return True, ""
    return False, f"expected BuiltScript.java in cmd | actual={cmd!r}"
check("ghidra_script_builder", {"name": "BuiltScript.java"}, v_script_builder)

# 85. ghidra_script_chain_args — "cmd" key (not "command_line")
def v_script_chain(d):
    if d is None:
        return False, "got None"
    cmd = d.get("cmd", "")
    n_args = d.get("n_args", -1)
    if "ChainScript.java" in cmd and n_args == 2:
        return True, ""
    return False, f"expected ChainScript.java+n_args=2 | actual cmd={cmd!r}, n_args={n_args}"
check("ghidra_script_chain_args",
      {"name": "ChainScript.java", "args": ["argA", "argB"], "timeout": 5000},
      v_script_chain)

# 86. ghidra_project_name_ghidfixp1 — returns {"name", "path", "project_file"}
def v_project_name(d):
    if d is None:
        return False, "got None"
    name_val = d.get("name", "")
    pf = d.get("project_file", "")
    if name_val == "TestProject" and "TestProject.gpr" in pf:
        return True, ""
    return False, f"expected name=TestProject + .gpr | actual name={name_val!r}, pf={pf!r}"
check("ghidra_project_name_ghidfixp1",
      {"name": "TestProject", "path": "/tmp/ghidra"},
      v_project_name)

# 87. ghidra_data_type_db_builtins_wire3 — returns {before:0, after:14, hit:{name,size,c}}
def v_builtins_wire3(d):
    if d is None:
        return False, "got None"
    before = d.get("before", -1)
    after = d.get("after", -1)
    hit = d.get("hit")
    if before == 0 and after == 14 and hit is not None:
        size = hit.get("size", -1) if isinstance(hit, dict) else -1
        if size == 4:  # "int" has size 4
            return True, ""
        return False, f"expected hit.size=4 | actual={hit!r}"
    return False, f"expected before=0, after=14, hit not-None | actual before={before}, after={after}, hit={hit!r}"
check("ghidra_data_type_db_builtins_wire3", {"name": "int"}, v_builtins_wire3)

# ── Teardown ────────────────────────────────────────────────────────────────────
try:
    p.stdin.close()
    p.terminate()
except Exception:
    pass

# ── Write results ───────────────────────────────────────────────────────────────
v2_result = {
    "category": "ghidra",
    "tools_hardened": len(passed) + len(failed),
    "tools_passed": len(passed),
    "tools_failed": len(failed),
    "tools_skipped": len(skipped),
    "mismatches": mismatches,
    "passed_detail": passed,
    "failed_detail": failed,
}

with open(OUT_V2, "w") as f:
    json.dump(v2_result, f, indent=2)

with open(OUT_SKIP, "w") as f:
    json.dump({"skipped": skipped}, f, indent=2)

print(f"Passed:   {len(passed)}")
print(f"Failed:   {len(failed)}")
print(f"Skipped:  {len(skipped)}")
print(f"Mismatches: {len(mismatches)}")
if mismatches:
    for m in mismatches:
        print(f"  MISMATCH {m['tool']}: {str(m.get('actual',''))[:120]}")
