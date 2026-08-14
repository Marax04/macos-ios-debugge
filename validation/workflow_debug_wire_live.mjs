export const meta = {
  name: 'debug-wire-live-100pct',
  description: 'Wire the 29 rustre-debug MCP wrappers so they surface LIVE via the MCP server, then live-test each one.',
  phases: [
    { title: 'FindDispatcher', detail: 'Find why debug_* tools do not surface: dispatcher path from server to register_debug_group' },
    { title: 'WireLive', detail: 'Connect register_debug_group into the live tool registry' },
    { title: 'RebuildAndList', detail: 'Rebuild MCP, list tools, verify debug_* tools appear' },
    { title: 'LiveTestAll', detail: 'Live-call every debug_* tool, per-tool pass/fail matrix' },
  ],
}

const CWD = 'C:/Users/Fra/Desktop/RustRE'

phase('FindDispatcher')
const find = await agent(
  `The user has 29 debug_* tool wrappers wired into register_debug_group() in ${CWD}/crates/rustre-mcp-tools/src/lib.rs (compile OK) but ZERO debug_* tools surface via MCP tools/list. rustre-debug is the ONLY debugger crate (all other debug_* backends were removed).

Find the disconnect:
1. Read ${CWD}/crates/rustre-mcp-tools/src/lib.rs — find register_debug_group definition. Note its return type, where it's stored, whether it's called by any pub fn.
2. Read ${CWD}/crates/rustre-mcp-tools/src/lib.rs top-level pub fn that assembles the tool list (likely called all_tools() or register_all_groups() or similar).
3. Check if register_debug_group() is INCLUDED in the top-level assembler. Compare with a working group like register_analysis_group() — where does its output go?
4. Read ${CWD}/crates/rustre-mcp-tools/src/tools/debug.rs handlers() — if it returns vec![] then this is the parallel dead path. See if the server calls handlers() or the register_debug_group path.
5. Read ${CWD}/crates/rustre-mcp-server/src/*.rs — grep for "debug" and find how the server obtains its tool list (calls rustre_mcp_tools::something).
6. Return {register_debug_group_called_by:string|null, tools_debug_rs_handlers_returns_empty:bool, server_uses_which_path:string, root_cause:string, fix_recipe:string}`,
  { label: 'find-dispatcher', agentType: 're-validator', schema: {
    type: 'object',
    properties: {
      register_debug_group_called_by:{type:'string'},
      tools_debug_rs_handlers_returns_empty:{type:'boolean'},
      server_uses_which_path:{type:'string'},
      root_cause:{type:'string'},
      fix_recipe:{type:'string'},
    },
    required:['root_cause','fix_recipe']
  }}
)

phase('WireLive')
const wire = await agent(
  `Apply the fix from prior diagnostic:

DIAGNOSTIC: ${JSON.stringify(find)}

STEPS:
1. Wire register_debug_group() so its 29 tools reach the MCP server's tools/list. Common patterns:
   - If server uses tools::debug::handlers() → make that fn return the 29 wrappers, not vec![]. Import each wrapper from register_debug_group.
   - If server iterates registered groups → add register_debug_group() call to the top-level registrar.
   - If wrappers are in the wrong container type (ToolGroup vs ToolHandler vec) → convert.
2. Do NOT remove any existing tool, do NOT touch rustre-debug internals (user owns that crate).
3. cd ${CWD} && cargo build --release -p rustre-mcp-tools -p rustre-mcp-server -p rustre-mcp 2>&1 | tail -20 (Bash timeout 900000ms). Fix build errors iteratively up to 5 rounds.
4. Return {files_edited:[string], approach:string, build_ok:bool, notes:string}`,
  { label: 'wire-live', agentType: 're-validator', schema: {
    type: 'object',
    properties: {
      files_edited:{type:'array', items:{type:'string'}},
      approach:{type:'string'},
      build_ok:{type:'boolean'},
      notes:{type:'string'},
    },
    required:['build_ok','notes']
  }}
)

phase('RebuildAndList')
const list = await agent(
  `Verify debug_* tools now surface via MCP.

STEPS:
1. taskkill //F //IM rustre-mcp.exe. sleep 3.
2. Spawn ${CWD}/target/release/rustre-mcp.exe stdio via Python. Send JSON-RPC initialize + tools/list. Parse the response.
3. Count debug_* tools in the response. List their names.
4. Return {total_tools_exposed:int, debug_tools_count:int, debug_tools_names:string[]}`,
  { label: 'rebuild-list', agentType: 're-validator', schema: {
    type: 'object',
    properties: {
      total_tools_exposed:{type:'integer'},
      debug_tools_count:{type:'integer'},
      debug_tools_names:{type:'array', items:{type:'string'}},
    },
    required:['debug_tools_count']
  }}
)

phase('LiveTestAll')
const test = await agent(
  `Live-call every debug_* tool exposed by MCP.

Tools discovered: ${JSON.stringify(list.debug_tools_names || [])}

STEPS:
1. For each tool, craft a minimal realistic input:
   - debug_launch: {executable_path: "${CWD}/tests/decompiler_corpus/bin/hello.exe", args: [], stop_at_entry: true}
   - debug_attach: {pid: 0}   (expect error but not crash)
   - debug_is_attached: {}
   - debug_target_pid: {}
   - debug_set_breakpoint: {addr: "0x140001000", kind: "software"}
   - debug_remove_breakpoint: {addr: "0x140001000"}
   - debug_enable_breakpoint / debug_disable_breakpoint: {addr: "0x140001000"}
   - debug_breakpoints: {}
   - debug_read_memory: {addr: "0x140000000", len: 16}
   - debug_write_memory: {addr: "0x140000000", bytes: [0x90,0x90]}
   - debug_memory_maps: {}
   - debug_memory_search: {pattern: "48 89 5C 24", start: "0x140000000", len: 4096}
   - debug_read_registers / debug_set_registers / debug_get_register (name:"rip") / debug_set_register (name:"rax", value:0)
   - debug_threads / debug_current_thread
   - debug_continue / debug_single_step / debug_step_into / debug_step_over / debug_step_out / debug_pause
   - debug_backtrace
   - debug_modules
   - debug_detach / debug_kill
2. Send tools/call for each. Record {tool, ok, error, response_preview_first_200_chars}.
3. Distinguish "OK because MockDebugger returned mocked data" from "OK because real work happened" only if trivially clear from response.
4. Return {tools_tested:int, tools_ok:int, tools_error:int, per_tool:[{tool,ok,error,response_preview}], verdict:string, capabilities_working:string[]}`,
  { label: 'test-all', agentType: 're-validator', schema: {
    type: 'object',
    properties: {
      tools_tested:{type:'integer'},
      tools_ok:{type:'integer'},
      tools_error:{type:'integer'},
      per_tool:{type:'array'},
      verdict:{type:'string'},
      capabilities_working:{type:'array', items:{type:'string'}},
    },
    required:['verdict']
  }}
)

return { status:'debug-wire-complete', find, wire, list, test }
