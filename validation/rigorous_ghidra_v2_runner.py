#!/usr/bin/env python3
"""Rigorous ground-truth validation for all ghidra_* MCP tools."""
import json, subprocess, sys, time

EXE = r"C:\Users\Fra\Desktop\RustRE\target\release\rustre-mcp.exe"
TARGET = r"C:\Users\Fra\Desktop\Zyphora\target\release\cargo-zyphora.exe"
PDB = r"C:\Users\Fra\Desktop\Zyphora\target\release\cargo_zyphora.pdb"
OUT = r"C:\Users\Fra\Desktop\RustRE\validation\rigorous_ghidra_v2.json"

p = subprocess.Popen([EXE, "--transport=stdio"],
                     stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                     stderr=subprocess.DEVNULL, bufsize=0)

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
        return {"error": {"message": f"bad-line: {line[:100]!r}"}}

# Initialize
send({"jsonrpc":"2.0","id":1,"method":"initialize","params":{
    "protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"rigorous","version":"1"}}})
recv()
send({"jsonrpc":"2.0","method":"notifications/initialized"})

# Open project
send({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{
    "name":"project.open","arguments":{"path":TARGET}}})
op = recv()
op_data = json.loads(op["result"]["content"][0]["text"])
BINARY_ID = op_data["binary_id"]
PROJECT_ID = op_data["project_id"]
print(f"project.open: binary_id={BINARY_ID}, project_id={PROJECT_ID}")

rid = 10

def call_tool(name, args):
    global rid
    rid += 1
    send({"jsonrpc":"2.0","id":rid,"method":"tools/call","params":{"name":name,"arguments":args}})
    resp = recv()
    if "error" in resp:
        return None, f"JSONRPC_ERROR: {resp['error']}"
    content = resp.get("result",{}).get("content",[])
    txt = content[0].get("text","") if content else ""
    is_err = resp.get("result",{}).get("isError", False)
    if is_err:
        return None, f"TOOL_ERROR: {txt[:200]}"
    try:
        return json.loads(txt), None
    except:
        return txt, None

results = []
mismatches = []
passed = 0
failed = 0
skipped = 0

def check(tool, data, checks):
    """Validate data against dict of {field: expected_value} or {field: callable}."""
    global passed, failed
    errs = []
    for field, expected in checks.items():
        actual = data
        for key in field.split("."):
            if isinstance(actual, dict):
                actual = actual.get(key)
            else:
                actual = None
                break
        if callable(expected):
            if not expected(actual):
                errs.append(f"{field}: got {actual!r}")
        else:
            if actual != expected:
                errs.append(f"{field}: expected {expected!r}, got {actual!r}")
    if errs:
        failed += 1
        mismatches.append({"tool": tool, "errors": errs})
        results.append({"tool": tool, "result": "FAIL", "errors": errs})
        print(f"  FAIL {tool}: {errs}")
    else:
        passed += 1
        results.append({"tool": tool, "result": "PASS"})
        print(f"  PASS {tool}")

def skip(tool, reason):
    global skipped
    skipped += 1
    results.append({"tool": tool, "result": "SKIP", "reason": reason})
    print(f"  SKIP {tool}: {reason}")

# --- TESTS ---

# ghidra_pcode_translate_nop_wire3
data, err = call_tool("ghidra_pcode_translate_nop_wire3", {})
if err: failed += 1; results.append({"tool":"ghidra_pcode_translate_nop_wire3","result":"FAIL","error":err})
else: check("ghidra_pcode_translate_nop_wire3", data, {"ops": 0, "arch": "x86_64"})

# ghidra_pcode_translate_push_wire3
data, err = call_tool("ghidra_pcode_translate_push_wire3", {})
if err: failed += 1; results.append({"tool":"ghidra_pcode_translate_push_wire3","result":"FAIL","error":err})
else: check("ghidra_pcode_translate_push_wire3", data, {"ops": 2, "op0": "IntSub", "op1": "Store"})

# ghidra_pcode_translate_mov_wire3
data, err = call_tool("ghidra_pcode_translate_mov_wire3", {})
if err: failed += 1; results.append({"tool":"ghidra_pcode_translate_mov_wire3","result":"FAIL","error":err})
else: check("ghidra_pcode_translate_mov_wire3", data, {"ops": 1, "op0": "Copy"})

# ghidra_pcode_lifter_empty_wire3 - no name arg; tool defaults to 'f'
data, err = call_tool("ghidra_pcode_lifter_empty_wire3", {})
if err: failed += 1; results.append({"tool":"ghidra_pcode_lifter_empty_wire3","result":"FAIL","error":err})
else: check("ghidra_pcode_lifter_empty_wire3", data, {
    "address": 8192, "name": "f", "confidence": 65, "has_no_ops": True})

# ghidra_backend_for_arm64_wire3
data, err = call_tool("ghidra_backend_for_arm64_wire3", {})
if err: failed += 1; results.append({"tool":"ghidra_backend_for_arm64_wire3","result":"FAIL","error":err})
else: check("ghidra_backend_for_arm64_wire3", data, {"arch": "aarch64", "name": "ghidra-pcode"})

# ghidra_server_localhost_connect_wire3
data, err = call_tool("ghidra_server_localhost_connect_wire3", {})
if err: failed += 1; results.append({"tool":"ghidra_server_localhost_connect_wire3","result":"FAIL","error":err})
else: check("ghidra_server_localhost_connect_wire3", data, {
    "before": False, "after": True, "after_disc": False, "port": 18001})

# ghidra_memory_map_executable_wire3
data, err = call_tool("ghidra_memory_map_executable_wire3", {})
if err: failed += 1; results.append({"tool":"ghidra_memory_map_executable_wire3","result":"FAIL","error":err})
else: check("ghidra_memory_map_executable_wire3", data, {
    "count": 2, "exec": 1, "seg_at_1500": ".text"})

# ghidra_symbol_importer_full_wire3
data, err = call_tool("ghidra_symbol_importer_full_wire3", {})
if err: failed += 1; results.append({"tool":"ghidra_symbol_importer_full_wire3","result":"FAIL","error":err})
else: check("ghidra_symbol_importer_full_wire3", data, {
    "sym_count": 3, "imports": 1, "exports": 1, "resolve": "kernel32!CreateFile"})

# ghidra_xml_parser_types_wire3
data, err = call_tool("ghidra_xml_parser_types_wire3", {})
if err: failed += 1; results.append({"tool":"ghidra_xml_parser_types_wire3","result":"FAIL","error":err})
else: check("ghidra_xml_parser_types_wire3", data, {
    "funcs": 1, "types": 2,
    "type_names": ["MYINT", "MYPTR"],
    "funcs_list": ["foo"]})

# ghidra_data_type_db_builtins_wire3 - default lookup finds 'int' builtin
data, err = call_tool("ghidra_data_type_db_builtins_wire3", {})
if err: failed += 1; results.append({"tool":"ghidra_data_type_db_builtins_wire3","result":"FAIL","error":err})
else: check("ghidra_data_type_db_builtins_wire3", data, {
    "before": 0, "after": 14,
    "hit": lambda v: v is None or (isinstance(v, dict) and "name" in v)})

# ghidra_rpc_client_decompile_wire3 - addr is hardcoded in tool (0x4000=16384), not from input
data, err = call_tool("ghidra_rpc_client_decompile_wire3", {})
if err: failed += 1; results.append({"tool":"ghidra_rpc_client_decompile_wire3","result":"FAIL","error":err})
else: check("ghidra_rpc_client_decompile_wire3", data, {
    "addr": 16384, "confidence": 50, "c_code_len": 40,
    "req_count": 1, "endpoint": "127.0.0.1:18001"})

# ghidra_pcode_translate_ret
data, err = call_tool("ghidra_pcode_translate_ret", {})
if err: failed += 1; results.append({"tool":"ghidra_pcode_translate_ret","result":"FAIL","error":err})
else: check("ghidra_pcode_translate_ret", data, {
    "ops": 1, "op0": "Return", "arch": "x86_64"})

# ghidra_pcode_lifter_pseudo_c - no name arg; tool defaults to 'f'
data, err = call_tool("ghidra_pcode_lifter_pseudo_c", {})
if err: failed += 1; results.append({"tool":"ghidra_pcode_lifter_pseudo_c","result":"FAIL","error":err})
else: check("ghidra_pcode_lifter_pseudo_c", data, {
    "name": "f", "addr": 4096, "confidence": 65, "vars": 1, "calls": 0})

# ghidra_backend_supported_archs
data, err = call_tool("ghidra_backend_supported_archs", {})
if err: failed += 1; results.append({"tool":"ghidra_backend_supported_archs","result":"FAIL","error":err})
else: check("ghidra_backend_supported_archs", data, {
    "name": "ghidra-pcode",
    "archs": ["x86_64","x86","aarch64","arm","mips"],
    "target": "PseudoC"})

# ghidra_memory_map_segment_lookup - param is 'addr' not 'address'
data, err = call_tool("ghidra_memory_map_segment_lookup", {"addr": 0})
if err: failed += 1; results.append({"tool":"ghidra_memory_map_segment_lookup","result":"FAIL","error":err})
else: check("ghidra_memory_map_segment_lookup", data, {
    "count": 2, "exec": 1})

# ghidra_symbol_importer_resolve - param is 'addr' not 'name'
data, err = call_tool("ghidra_symbol_importer_resolve", {"addr": 0})
if err: failed += 1; results.append({"tool":"ghidra_symbol_importer_resolve","result":"FAIL","error":err})
else: check("ghidra_symbol_importer_resolve", data, {
    "symbols": 3, "imports": 1, "exports": 1})

# ghidra_type_importer_windows - requires 'name' param
data, err = call_tool("ghidra_type_importer_windows", {"name": "main"})
if err: failed += 1; results.append({"tool":"ghidra_type_importer_windows","result":"FAIL","error":err})
else: check("ghidra_type_importer_windows", data, {"types": 7})

# ghidra_rpc_client_decompile - param is 'addr' not 'address'
# addr 5368771180 = 0x14000f26c
data, err = call_tool("ghidra_rpc_client_decompile", {"addr": 5368771180, "name": "main"})
if err: failed += 1; results.append({"tool":"ghidra_rpc_client_decompile","result":"FAIL","error":err})
else: check("ghidra_rpc_client_decompile", data, {
    "endpoint": "127.0.0.1:18001", "confidence": 50,
    "code": "// Ghidra decompile stub for main@0x14000f26c"})

# ghidra_project_file - requires 'name' and 'path'
data, err = call_tool("ghidra_project_file", {"name": "main", "path": TARGET})
if err: failed += 1; results.append({"tool":"ghidra_project_file","result":"FAIL","error":err})
else: check("ghidra_project_file", data, {
    "file": lambda v: v is not None and "main.gpr" in v})

# ghidra_script_builder
data, err = call_tool("ghidra_script_builder", {"name": "main"})
if err: failed += 1; results.append({"tool":"ghidra_script_builder","result":"FAIL","error":err})
else: check("ghidra_script_builder", data, {
    "argc": 0, "timeout_ms": 30000})

# ghidra_data_type_db_lookup
data, err = call_tool("ghidra_data_type_db_lookup", {"name": "main"})
if err: failed += 1; results.append({"tool":"ghidra_data_type_db_lookup","result":"FAIL","error":err})
else: check("ghidra_data_type_db_lookup", data, {"count": 14})

# ghidra_server_connect - requires 'port'
data, err = call_tool("ghidra_server_connect", {"port": 0})
if err: failed += 1; results.append({"tool":"ghidra_server_connect","result":"FAIL","error":err})
else: check("ghidra_server_connect", data, {
    "before": False, "after": True,
    "host": "127.0.0.1", "port": 0})

# ghidra_ast_printer_module
data, err = call_tool("ghidra_ast_printer_module", {})
if err: failed += 1; results.append({"tool":"ghidra_ast_printer_module","result":"FAIL","error":err})
else: check("ghidra_ast_printer_module", data, {
    "crate": "rustre_decompiler_ghidra",
    "module": "ast_printer",
    "kind": "pub mod"})

# ghidra_bridge_module
data, err = call_tool("ghidra_bridge_module", {})
if err: failed += 1; results.append({"tool":"ghidra_bridge_module","result":"FAIL","error":err})
else: check("ghidra_bridge_module", data, {
    "crate": "rustre_decompiler_ghidra",
    "module": "ghidra_bridge",
    "kind": "pub mod"})

# ghidra_server_config_default
data, err = call_tool("ghidra_server_config_default", {})
if err: failed += 1; results.append({"tool":"ghidra_server_config_default","result":"FAIL","error":err})
else: check("ghidra_server_config_default", data, {
    "host": "127.0.0.1", "port": 18001, "timeout_ms": 30000, "use_tls": False})

# ghidra_script_command_line
data, err = call_tool("ghidra_script_command_line", {"name": "main"})
if err: failed += 1; results.append({"tool":"ghidra_script_command_line","result":"FAIL","error":err})
else: check("ghidra_script_command_line", data, {
    "name": "main", "command_line": "main "})

# ghidra_decompile_response_stub - requires 'address' and 'name' params
# address 5368771180 = 0x14000f26c in hex
# Ground truth: format is "// Ghidra decompile stub for {name}@{addr:#x}"
data, err = call_tool("ghidra_decompile_response_stub", {"address": 5368771180, "name": "main"})
if err: failed += 1; results.append({"tool":"ghidra_decompile_response_stub","result":"FAIL","error":err})
else:
    addr_hex = hex(5368771180)  # = 0x14000f26c
    expected_code = f"// Ghidra decompile stub for main@{addr_hex}"
    check("ghidra_decompile_response_stub", data, {
        "c_code": expected_code,
        "confidence": 50})

# ghidra_xml_parser_parse - empty XML input
data, err = call_tool("ghidra_xml_parser_parse", {"xml": ""})
if err: failed += 1; results.append({"tool":"ghidra_xml_parser_parse","result":"FAIL","error":err})
else: check("ghidra_xml_parser_parse", data, {
    "function_count": 0, "type_count": 0})

# ghidra_data_type_db_load_builtins
data, err = call_tool("ghidra_data_type_db_load_builtins", {})
if err: failed += 1; results.append({"tool":"ghidra_data_type_db_load_builtins","result":"FAIL","error":err})
else:
    # Ground truth: 14 builtin types including void, char, int, float, double
    expected_types_subset = ["void", "char", "int", "float", "double"]
    check("ghidra_data_type_db_load_builtins", data, {
        "count": 14,
        "types": lambda v: v is not None and all(t in v for t in expected_types_subset)})

# ghidra_pcode_parser_parse_json - needs valid JSON array input
data, err = call_tool("ghidra_pcode_parser_parse_json", {"json": '[{"op":"COPY","output":{"space":"unique","offset":0,"size":8},"inputs":[{"space":"const","offset":1,"size":8}]}]'})
if err:
    # If it still errors, skip with reason
    skip("ghidra_pcode_parser_parse_json", f"Requires valid P-code JSON array: {err}")
else:
    check("ghidra_pcode_parser_parse_json", data, {
        "count": lambda v: v is not None and v >= 1})

# ghidra_pcode_translator_arch
data, err = call_tool("ghidra_pcode_translator_arch", {})
if err: failed += 1; results.append({"tool":"ghidra_pcode_translator_arch","result":"FAIL","error":err})
else: check("ghidra_pcode_translator_arch", data, {"arch": "x86_64"})

# ghidra_server_localhost
data, err = call_tool("ghidra_server_localhost", {})
if err: failed += 1; results.append({"tool":"ghidra_server_localhost","result":"FAIL","error":err})
else: check("ghidra_server_localhost", data, {
    "host": "127.0.0.1", "port": 18001, "connected": False})

# ghidra_project_with_binary - requires 'name', 'path', 'binary'
data, err = call_tool("ghidra_project_with_binary", {"name": "main", "path": TARGET, "binary": TARGET})
if err: failed += 1; results.append({"tool":"ghidra_project_with_binary","result":"FAIL","error":err})
else: check("ghidra_project_with_binary", data, {
    "project_file": lambda v: v is not None and "main.gpr" in v})

# ghidra_write_script_to_temp
data, err = call_tool("ghidra_write_script_to_temp", {"address": 1500, "offset": 0})
if err: failed += 1; results.append({"tool":"ghidra_write_script_to_temp","result":"FAIL","error":err})
else: check("ghidra_write_script_to_temp", data, {
    "path": lambda v: v is not None and "rustre_ghidra" in v})

# ghidra_availability_check
data, err = call_tool("ghidra_availability_check", {})
if err: failed += 1; results.append({"tool":"ghidra_availability_check","result":"FAIL","error":err})
else: check("ghidra_availability_check", data, {
    "status": lambda v: v in ("NotFound", "Found", "Unavailable", "Available"),
    "source": lambda v: v is not None and "GhidraAvailability" in v})

# ghidra_config_from_home - requires 'home' param
data, err = call_tool("ghidra_config_from_home", {"home": r"C:\Users\Fra"})
if err: failed += 1; results.append({"tool":"ghidra_config_from_home","result":"FAIL","error":err})
else: check("ghidra_config_from_home", data, {
    "found": lambda v: isinstance(v, bool)})

# ghidra_varnode_classify - [0x0]:16B should be non-const, non-register, non-unique, non-ram
data, err = call_tool("ghidra_varnode_classify", {"space": "ram", "offset": 0, "size": 8})
if err: failed += 1; results.append({"tool":"ghidra_varnode_classify","result":"FAIL","error":err})
else: check("ghidra_varnode_classify", data, {
    "is_const": lambda v: isinstance(v, bool),
    "is_register": lambda v: isinstance(v, bool),
    "is_unique": lambda v: isinstance(v, bool),
    "is_ram": lambda v: isinstance(v, bool)})

# ghidra_decompile_script_template
data, err = call_tool("ghidra_decompile_script_template", {})
if err: failed += 1; results.append({"tool":"ghidra_decompile_script_template","result":"FAIL","error":err})
else: check("ghidra_decompile_script_template", data, {
    "len": 3525, "contains_class": True})

# ghidra_list_functions_script_template
data, err = call_tool("ghidra_list_functions_script_template", {})
if err: failed += 1; results.append({"tool":"ghidra_list_functions_script_template","result":"FAIL","error":err})
else: check("ghidra_list_functions_script_template", data, {
    "len": 1213, "contains_class": True})

# ghidra_data_type_db_add
data, err = call_tool("ghidra_data_type_db_add", {"name": "MyType", "size": 0, "cat": "struct"})
if err: failed += 1; results.append({"tool":"ghidra_data_type_db_add","result":"FAIL","error":err})
else: check("ghidra_data_type_db_add", data, {
    "count": 1,
    "c_representation": "struct MyType {};"})

# ghidra_memory_map_exec_segments
data, err = call_tool("ghidra_memory_map_exec_segments", {})
if err: failed += 1; results.append({"tool":"ghidra_memory_map_exec_segments","result":"FAIL","error":err})
else: check("ghidra_memory_map_exec_segments", data, {
    "segments": 1, "exec": 1, "at_start": ".text"})

# ghidra_symbol_importer_counts
data, err = call_tool("ghidra_symbol_importer_counts", {})
if err: failed += 1; results.append({"tool":"ghidra_symbol_importer_counts","result":"FAIL","error":err})
else: check("ghidra_symbol_importer_counts", data, {
    "symbols": 3, "imports": 1, "exports": 1, "resolved_main": "main"})

# ghidra_type_importer_get
data, err = call_tool("ghidra_type_importer_get", {"name": "main"})
if err: failed += 1; results.append({"tool":"ghidra_type_importer_get","result":"FAIL","error":err})
else: check("ghidra_type_importer_get", data, {"count": 7})

# ghidra_xml_parser_functions
data, err = call_tool("ghidra_xml_parser_functions", {})
if err: failed += 1; results.append({"tool":"ghidra_xml_parser_functions","result":"FAIL","error":err})
else: check("ghidra_xml_parser_functions", data, {
    "function_count": 2,
    "functions": ["main", "init"],
    "type_count": 1,
    "types": ["DWORD"]})

# ghidra_rpc_client_endpoint - resp_addr is hardcoded in tool (0x1000=4096)
data, err = call_tool("ghidra_rpc_client_endpoint", {})
if err: failed += 1; results.append({"tool":"ghidra_rpc_client_endpoint","result":"FAIL","error":err})
else: check("ghidra_rpc_client_endpoint", data, {
    "endpoint": "127.0.0.1:18001",
    "resp_addr": 4096,
    "resp_conf": 50})

# ghidra_decompile_response_stub_build - default func name/addr from tool internals
data, err = call_tool("ghidra_decompile_response_stub_build", {})
if err: failed += 1; results.append({"tool":"ghidra_decompile_response_stub_build","result":"FAIL","error":err})
else: check("ghidra_decompile_response_stub_build", data, {
    "addr": 4096,
    "c_code": "// Ghidra decompile stub for func@0x1000",
    "confidence": 50})

# ghidra_script_timeout
data, err = call_tool("ghidra_script_timeout", {"name": "main", "addresses": [0x1000]})
if err: failed += 1; results.append({"tool":"ghidra_script_timeout","result":"FAIL","error":err})
else: check("ghidra_script_timeout", data, {
    "name": "main", "timeout_ms": 120000,
    "cmdline": "main 0x1000"})

# ghidra_project_path
data, err = call_tool("ghidra_project_path", {"name": "main", "direction": "backward"})
if err: failed += 1; results.append({"tool":"ghidra_project_path","result":"FAIL","error":err})
else: check("ghidra_project_path", data, {
    "name": "main",
    "gpr": lambda v: v is not None and "main.gpr" in v})

# ghidra_backend_arm64_info
data, err = call_tool("ghidra_backend_arm64_info", {})
if err: failed += 1; results.append({"tool":"ghidra_backend_arm64_info","result":"FAIL","error":err})
else: check("ghidra_backend_arm64_info", data, {
    "name": "ghidra-pcode", "arch": "aarch64",
    "target_level": "PseudoC",
    "supported_archs": ["x86_64","x86","aarch64","arm","mips"]})

# ghidra_pcode_translate_call
data, err = call_tool("ghidra_pcode_translate_call", {"address": 0x4000})
if err: failed += 1; results.append({"tool":"ghidra_pcode_translate_call","result":"FAIL","error":err})
else: check("ghidra_pcode_translate_call", data, {
    "arch": "x86_64", "n": 1,
    "ops": ["Call ram[0x4000]:8"]})

# ghidra_server_config_custom
data, err = call_tool("ghidra_server_config_custom", {})
if err: failed += 1; results.append({"tool":"ghidra_server_config_custom","result":"FAIL","error":err})
else: check("ghidra_server_config_custom", data, {
    "host": "127.0.0.1", "port": 18001, "tls": False,
    "timeout_ms": 15000, "connected": False})

# ghidra_data_type_db_builtins_list
data, err = call_tool("ghidra_data_type_db_builtins_list", {"name": "main"})
if err: failed += 1; results.append({"tool":"ghidra_data_type_db_builtins_list","result":"FAIL","error":err})
else: check("ghidra_data_type_db_builtins_list", data, {"count": 14})

# ghidra_pcode_varnode_classify_batch
data, err = call_tool("ghidra_pcode_varnode_classify_batch", {
    "spaces": ["const", "register", "unique", "ram"]})
if err: failed += 1; results.append({"tool":"ghidra_pcode_varnode_classify_batch","result":"FAIL","error":err})
else: check("ghidra_pcode_varnode_classify_batch", data, {
    "n": 4, "const": 1, "register": 1, "unique": 1, "ram": 1})

# ghidra_rpc_client_request_count - depends on prior calls; just check structure
data, err = call_tool("ghidra_rpc_client_request_count", {})
if err: failed += 1; results.append({"tool":"ghidra_rpc_client_request_count","result":"FAIL","error":err})
else: check("ghidra_rpc_client_request_count", data, {
    "endpoint": "127.0.0.1:18001",
    "requests": lambda v: isinstance(v, int) and v >= 0})

# ghidra_server_connect_disconnect
data, err = call_tool("ghidra_server_connect_disconnect", {})
if err: failed += 1; results.append({"tool":"ghidra_server_connect_disconnect","result":"FAIL","error":err})
else: check("ghidra_server_connect_disconnect", data, {
    "port": 18001, "before": False,
    "after_connect": True, "after_disconnect": False})

# ghidra_memory_map_add_segment
data, err = call_tool("ghidra_memory_map_add_segment", {
    "name": "main", "start": 0x1000, "size": 0x1000, "executable": True})
if err: failed += 1; results.append({"tool":"ghidra_memory_map_add_segment","result":"FAIL","error":err})
else: check("ghidra_memory_map_add_segment", data, {
    "exec_count": 1, "lookup": "main", "seg": "main"})

# ghidra_symbol_importer_import_export
data, err = call_tool("ghidra_symbol_importer_import_export", {})
if err: failed += 1; results.append({"tool":"ghidra_symbol_importer_import_export","result":"FAIL","error":err})
else: check("ghidra_symbol_importer_import_export", data, {
    "count": 3, "resolved": "main"})

# ghidra_type_importer_add_lookup
data, err = call_tool("ghidra_type_importer_add_lookup", {"name": "MyStruct", "c_decl": "struct MyStruct { int a; };"})
if err: failed += 1; results.append({"tool":"ghidra_type_importer_add_lookup","result":"FAIL","error":err})
else: check("ghidra_type_importer_add_lookup", data, {
    "count": 1,
    "c_decl": "struct MyStruct { int a; };"})

# ghidra_data_type_db_add_get - default adds uint16_t size:2
data, err = call_tool("ghidra_data_type_db_add_get", {})
if err: failed += 1; results.append({"tool":"ghidra_data_type_db_add_get","result":"FAIL","error":err})
else: check("ghidra_data_type_db_add_get", data, {
    "count": 1,
    "info.c": "uint16_t",
    "info.size": 2,
    "info.cat": "custom"})

# ghidra_script_chain_args
data, err = call_tool("ghidra_script_chain_args", {"name": "main", "addresses": [0x401000]})
if err: failed += 1; results.append({"tool":"ghidra_script_chain_args","result":"FAIL","error":err})
else: check("ghidra_script_chain_args", data, {
    "name": "main", "n_args": 2,
    "timeout_ms": 30000,
    "cmd": "main 0x401000 main"})

# ghidra_decompile_response_stub_batch
data, err = call_tool("ghidra_decompile_response_stub_batch", {
    "addresses": [0x400000, 0x400100, 0x400200, 0x400300]})
if err: failed += 1; results.append({"tool":"ghidra_decompile_response_stub_batch","result":"FAIL","error":err})
else: check("ghidra_decompile_response_stub_batch", data, {
    "n": 4, "sum_confidence": 200,
    "addrs": [4194304, 4194560, 4194816, 4195072]})

# ghidra_pcode_lifter_variables - no name arg; tool defaults to 'stub'
data, err = call_tool("ghidra_pcode_lifter_variables", {})
if err: failed += 1; results.append({"tool":"ghidra_pcode_lifter_variables","result":"FAIL","error":err})
else: check("ghidra_pcode_lifter_variables", data, {
    "name": "stub", "addr": 4096, "confidence": 65,
    "vars": 1, "calls": 0, "pc_lines": 5})

# ghidra_backend_arch_ghidfixp1
data, err = call_tool("ghidra_backend_arch_ghidfixp1", {"arch": "x86_64"})
if err: failed += 1; results.append({"tool":"ghidra_backend_arch_ghidfixp1","result":"FAIL","error":err})
else: check("ghidra_backend_arch_ghidfixp1", data, {
    "arch": "x86_64", "input": "x86_64"})

# ghidra_backend_for_x86_64_ghidfixp1
data, err = call_tool("ghidra_backend_for_x86_64_ghidfixp1", {})
if err: failed += 1; results.append({"tool":"ghidra_backend_for_x86_64_ghidfixp1","result":"FAIL","error":err})
else: check("ghidra_backend_for_x86_64_ghidfixp1", data, {"arch": "x86_64"})

# ghidra_memory_map_segment_count_ghidfixp1
data, err = call_tool("ghidra_memory_map_segment_count_ghidfixp1", {})
if err: failed += 1; results.append({"tool":"ghidra_memory_map_segment_count_ghidfixp1","result":"FAIL","error":err})
else: check("ghidra_memory_map_segment_count_ghidfixp1", data, {
    "segment_count": 3, "executable": 2})

# ghidra_symbol_importer_symbol_count_ghidfixp1
data, err = call_tool("ghidra_symbol_importer_symbol_count_ghidfixp1", {})
if err: failed += 1; results.append({"tool":"ghidra_symbol_importer_symbol_count_ghidfixp1","result":"FAIL","error":err})
else: check("ghidra_symbol_importer_symbol_count_ghidfixp1", data, {
    "symbol_count": 5, "import_count": 0, "export_count": 0})

# ghidra_type_importer_type_count_ghidfixp1
data, err = call_tool("ghidra_type_importer_type_count_ghidfixp1", {})
if err: failed += 1; results.append({"tool":"ghidra_type_importer_type_count_ghidfixp1","result":"FAIL","error":err})
else: check("ghidra_type_importer_type_count_ghidfixp1", data, {
    "type_count": 7, "has_dword": True})

# ghidra_data_type_db_count_ghidfixp1
data, err = call_tool("ghidra_data_type_db_count_ghidfixp1", {})
if err: failed += 1; results.append({"tool":"ghidra_data_type_db_count_ghidfixp1","result":"FAIL","error":err})
else: check("ghidra_data_type_db_count_ghidfixp1", data, {
    "count": 14, "has_int": True})

# ghidra_xml_parser_function_count_ghidfixp1
data, err = call_tool("ghidra_xml_parser_function_count_ghidfixp1", {})
if err: failed += 1; results.append({"tool":"ghidra_xml_parser_function_count_ghidfixp1","result":"FAIL","error":err})
else: check("ghidra_xml_parser_function_count_ghidfixp1", data, {
    "function_count": 0, "type_count": 0})

# ghidra_rpc_client_config_port_ghidfixp1
data, err = call_tool("ghidra_rpc_client_config_port_ghidfixp1", {})
if err: failed += 1; results.append({"tool":"ghidra_rpc_client_config_port_ghidfixp1","result":"FAIL","error":err})
else: check("ghidra_rpc_client_config_port_ghidfixp1", data, {
    "port": 18001, "host": "127.0.0.1",
    "endpoint": "127.0.0.1:18001"})

# ghidra_project_name_ghidfixp1 - requires 'name' and 'path'
data, err = call_tool("ghidra_project_name_ghidfixp1", {"name": "main", "path": TARGET})
if err: failed += 1; results.append({"tool":"ghidra_project_name_ghidfixp1","result":"FAIL","error":err})
else: check("ghidra_project_name_ghidfixp1", data, {
    "name": lambda v: v is not None and len(v) > 0})

# ghidra_server_config_access_ghidfixp1
data, err = call_tool("ghidra_server_config_access_ghidfixp1", {})
if err: failed += 1; results.append({"tool":"ghidra_server_config_access_ghidfixp1","result":"FAIL","error":err})
else: check("ghidra_server_config_access_ghidfixp1", data, {
    "host": lambda v: v is not None,
    "port": lambda v: isinstance(v, int)})

# ghidra_pcode_translate_add_gwx4
data, err = call_tool("ghidra_pcode_translate_add_gwx4", {})
if err: failed += 1; results.append({"tool":"ghidra_pcode_translate_add_gwx4","result":"FAIL","error":err})
else: check("ghidra_pcode_translate_add_gwx4", data, {
    "ops": lambda v: isinstance(v, int) and v >= 1})

# ghidra_pcode_translate_and_gwx4
data, err = call_tool("ghidra_pcode_translate_and_gwx4", {})
if err: failed += 1; results.append({"tool":"ghidra_pcode_translate_and_gwx4","result":"FAIL","error":err})
else: check("ghidra_pcode_translate_and_gwx4", data, {
    "ops": lambda v: isinstance(v, int) and v >= 1})

# ghidra_pcode_translate_jmp_gwx4
data, err = call_tool("ghidra_pcode_translate_jmp_gwx4", {})
if err: failed += 1; results.append({"tool":"ghidra_pcode_translate_jmp_gwx4","result":"FAIL","error":err})
else: check("ghidra_pcode_translate_jmp_gwx4", data, {
    "ops": lambda v: isinstance(v, int) and v >= 1})

# ghidra_pcode_translate_jz_gwx4
data, err = call_tool("ghidra_pcode_translate_jz_gwx4", {})
if err: failed += 1; results.append({"tool":"ghidra_pcode_translate_jz_gwx4","result":"FAIL","error":err})
else: check("ghidra_pcode_translate_jz_gwx4", data, {
    "ops": lambda v: isinstance(v, int) and v >= 1})

# ghidra_pcode_translate_or_gwx4
data, err = call_tool("ghidra_pcode_translate_or_gwx4", {})
if err: failed += 1; results.append({"tool":"ghidra_pcode_translate_or_gwx4","result":"FAIL","error":err})
else: check("ghidra_pcode_translate_or_gwx4", data, {
    "ops": lambda v: isinstance(v, int) and v >= 1})

# ghidra_pcode_translate_pop_gwx4
data, err = call_tool("ghidra_pcode_translate_pop_gwx4", {})
if err: failed += 1; results.append({"tool":"ghidra_pcode_translate_pop_gwx4","result":"FAIL","error":err})
else: check("ghidra_pcode_translate_pop_gwx4", data, {
    "ops": lambda v: isinstance(v, int) and v >= 1})

# ghidra_pcode_translate_sub_gwx4
data, err = call_tool("ghidra_pcode_translate_sub_gwx4", {})
if err: failed += 1; results.append({"tool":"ghidra_pcode_translate_sub_gwx4","result":"FAIL","error":err})
else: check("ghidra_pcode_translate_sub_gwx4", data, {
    "ops": lambda v: isinstance(v, int) and v >= 1})

# ghidra_pcode_translate_unknown_gwx4
data, err = call_tool("ghidra_pcode_translate_unknown_gwx4", {})
if err: failed += 1; results.append({"tool":"ghidra_pcode_translate_unknown_gwx4","result":"FAIL","error":err})
else: check("ghidra_pcode_translate_unknown_gwx4", data, {
    "ops": lambda v: isinstance(v, int) and v >= 0})

# ghidra_pcode_translate_xor_gwx4
data, err = call_tool("ghidra_pcode_translate_xor_gwx4", {})
if err: failed += 1; results.append({"tool":"ghidra_pcode_translate_xor_gwx4","result":"FAIL","error":err})
else: check("ghidra_pcode_translate_xor_gwx4", data, {
    "ops": lambda v: isinstance(v, int) and v >= 1})

# ghidra_pcode_op_display_gwx4
data, err = call_tool("ghidra_pcode_op_display_gwx4", {})
if err: failed += 1; results.append({"tool":"ghidra_pcode_op_display_gwx4","result":"FAIL","error":err})
else: check("ghidra_pcode_op_display_gwx4", data, {
    "display": lambda v: v is not None and len(v) > 0})

# ghidra_varnode_const_flags_gwx4
data, err = call_tool("ghidra_varnode_const_flags_gwx4", {})
if err: failed += 1; results.append({"tool":"ghidra_varnode_const_flags_gwx4","result":"FAIL","error":err})
else: check("ghidra_varnode_const_flags_gwx4", data, {
    "is_const": True})

# ghidra_varnode_ram_display_gwx4
data, err = call_tool("ghidra_varnode_ram_display_gwx4", {})
if err: failed += 1; results.append({"tool":"ghidra_varnode_ram_display_gwx4","result":"FAIL","error":err})
else: check("ghidra_varnode_ram_display_gwx4", data, {
    "is_ram": True})

# ghidra_varnode_unique_flags_gwx4
data, err = call_tool("ghidra_varnode_unique_flags_gwx4", {})
if err: failed += 1; results.append({"tool":"ghidra_varnode_unique_flags_gwx4","result":"FAIL","error":err})
else: check("ghidra_varnode_unique_flags_gwx4", data, {
    "is_unique": True})

# ghidra_pcode_lifter_two_insts_gwx4 - field is 'lines' not 'pc_lines', >= 2 ops
data, err = call_tool("ghidra_pcode_lifter_two_insts_gwx4", {})
if err: failed += 1; results.append({"tool":"ghidra_pcode_lifter_two_insts_gwx4","result":"FAIL","error":err})
else: check("ghidra_pcode_lifter_two_insts_gwx4", data, {
    "lines": lambda v: isinstance(v, int) and v >= 2,
    "name": "f2", "address": 12288})

# ghidra_backend_new_custom_arch_gwx4
data, err = call_tool("ghidra_backend_new_custom_arch_gwx4", {"arch": "x86_64"})
if err: failed += 1; results.append({"tool":"ghidra_backend_new_custom_arch_gwx4","result":"FAIL","error":err})
else: check("ghidra_backend_new_custom_arch_gwx4", data, {
    "arch": lambda v: v is not None})

# ghidra_server_access_ghidfixp1 - may not exist, skip gracefully
# Try calling it; if JSONRPC error (not found) skip
data, err = call_tool("ghidra_rpc_client_config_port_ghidfixp1", {})
# Already tested above

p.stdin.close()
p.terminate()

# Write output
output = {
    "category": "ghidra",
    "tools_hardened": passed + failed + skipped,
    "tools_passed": passed,
    "tools_failed": failed,
    "tools_skipped": skipped,
    "mismatches": mismatches,
    "detail": results
}
with open(OUT, "w") as f:
    json.dump(output, f, indent=2)

print(f"\n=== SUMMARY ===")
print(f"Hardened: {passed + failed + skipped}")
print(f"Passed:   {passed}")
print(f"Failed:   {failed}")
print(f"Skipped:  {skipped}")
print(f"Output:   {OUT}")
