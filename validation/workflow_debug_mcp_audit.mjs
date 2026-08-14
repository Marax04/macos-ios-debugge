export const meta = {
  name: 'debug-mcp-audit-and-complete',
  description: 'Audit rustre-debug MCP coverage, complete missing wrappers, test each tool live via MCP',
  phases: [
    { title: 'AuditDebugCrate', detail: 'Map every public API in rustre-debug: functions, structs, backends' },
    { title: 'AuditMcpCoverage', detail: 'Find which of those APIs have MCP wrappers in tools/debug.rs and which are missing' },
    { title: 'CompleteWrappers', detail: 'Add MCP wrapper for every missing API — FULL coverage' },
    { title: 'RebuildAndTest', detail: 'Rebuild release, live-call every debug_* MCP tool, report pass/fail matrix' },
  ],
}

const CWD = 'C:/Users/Fra/Desktop/RustRE'

phase('AuditDebugCrate')
const crateAudit = await agent(
  `Deep audit of ${CWD}/crates/rustre-debug (the debugger crate the user is actively developing).

STEPS:
1. Read ${CWD}/crates/rustre-debug/Cargo.toml — list features and dependencies.
2. Read ${CWD}/crates/rustre-debug/src/lib.rs and every module (backends/, engine/, session/, breakpoints/, memory/, registers/, etc.). Use Glob crates/rustre-debug/src/**/*.rs.
3. For every public function, struct, enum, and trait: record name + module path + short purpose (1 line).
4. Identify backends supported (windbg? gdb? lldb? dbgeng? native win32? ptrace?). List them.
5. Identify high-level operations: attach, launch, detach, run, pause, step_into, step_over, step_out, continue, breakpoints (set/remove/list/conditional), memory (read/write/search), registers (read/write), threads (list/switch/suspend/resume), modules (list/base/symbols), stack (backtrace/frames/locals), evaluate expression, watchpoints, exceptions, disasm-at-pc, source-line lookup.
6. Categorize each operation: fully implemented / stub / not-present.
7. Return JSON: {backends:string[], total_public_apis:int, apis:[{path:string,kind:'fn'|'struct'|'enum'|'trait',purpose:string,status:'impl'|'stub'|'missing'}], high_level_ops_status:{op_name:string_status_map}, notes:string}`,
  { label: 'audit-crate', agentType: 're-validator', schema: {
    type: 'object',
    properties: {
      backends:{type:'array', items:{type:'string'}},
      total_public_apis:{type:'integer'},
      apis:{type:'array'},
      high_level_ops_status:{type:'object'},
      notes:{type:'string'},
    },
    required:['backends','total_public_apis','notes']
  }}
)

phase('AuditMcpCoverage')
const mcpAudit = await agent(
  `Audit MCP wrapper coverage for rustre-debug.

STEPS:
1. Read ${CWD}/crates/rustre-mcp-tools/src/tools/debug.rs (or wherever debug_* tools live — grep for "debug_attach", "debug_set_breakpoint", "debug_read_memory" in tools/).
2. Read ${CWD}/crates/rustre-mcp/src/tool_handlers.rs — grep for "debug_" handler cases.
3. For each API from the previous crate audit (see the prior phase result — you have access to it via context in this workflow), check: is there a corresponding MCP tool wrapper? Is the wrapper actually wired (registered in the tools registry, not just defined)?
4. Compare with the announced MCP tools list — there are ~12 debug_* tools already visible (debug_attach, debug_launch, debug_backtrace, debug_continue, debug_evaluate, debug_read_memory, debug_write_memory, debug_read_registers, debug_set_breakpoint, debug_remove_breakpoint, debug_step_into, debug_step_over). Check if these correspond to real backends or are stubs.
5. Return JSON: {mcp_tools_present:string[], mcp_tools_stubbed:string[], apis_without_mcp_wrapper:string[], coverage_pct:number, notes:string, files_to_edit:[{path:string, why:string}]}`,
  { label: 'audit-mcp', agentType: 're-validator', schema: {
    type: 'object',
    properties: {
      mcp_tools_present:{type:'array', items:{type:'string'}},
      mcp_tools_stubbed:{type:'array', items:{type:'string'}},
      apis_without_mcp_wrapper:{type:'array', items:{type:'string'}},
      coverage_pct:{type:'number'},
      notes:{type:'string'},
      files_to_edit:{type:'array'},
    },
    required:['coverage_pct','notes']
  }}
)

phase('CompleteWrappers')
const complete = await agent(
  `Complete FULL MCP coverage for rustre-debug based on prior audits:

CRATE AUDIT: ${JSON.stringify(crateAudit).slice(0,3000)}
MCP AUDIT: ${JSON.stringify(mcpAudit).slice(0,3000)}

STEPS:
1. For every API in apis_without_mcp_wrapper: add a wrapper following the existing pattern in ${CWD}/crates/rustre-mcp-tools/src/tools/debug.rs. Each wrapper: input struct, output struct, execute() calling the real rustre_debug function (NOT stubbing).
2. For every tool in mcp_tools_stubbed: unstub by wiring the real rustre_debug call.
3. Register each new tool in the tools registry / dispatcher so MCP surfaces it.
4. Add matching handler case in ${CWD}/crates/rustre-mcp/src/tool_handlers.rs if that layer is required.
5. cd ${CWD} && cargo build --release -p rustre-debug -p rustre-mcp-tools -p rustre-mcp-server -p rustre-mcp 2>&1 | tail -30. Iterate max 5 times on errors.
6. Do NOT delete or refactor rustre-debug internals (the user is developing that crate). Only ADD wrappers.
7. Return JSON: {new_wrappers_added:int, stubs_unstubbed:int, tools_registered:string[], build_ok:bool, notes:string}`,
  { label: 'complete-wrappers', agentType: 're-validator', schema: {
    type: 'object',
    properties: {
      new_wrappers_added:{type:'integer'},
      stubs_unstubbed:{type:'integer'},
      tools_registered:{type:'array', items:{type:'string'}},
      build_ok:{type:'boolean'},
      notes:{type:'string'},
    },
    required:['build_ok','notes']
  }}
)

phase('RebuildAndTest')
const test = await agent(
  `Live-test EVERY debug_* MCP tool.

STEPS:
1. taskkill //F //IM rustre-mcp.exe (ignore not-found). sleep 3.
2. cd ${CWD} && cargo build --release -p rustre-mcp -p rustre-mcp-server 2>&1 | tail -10. Fail fast if build breaks.
3. Write ${CWD}/validation/round_debug_probe.py: a Python script that spawns ${CWD}/target/release/rustre-mcp.exe stdio, sends JSON-RPC initialize, tools/list, then for each debug_* tool sends a tools/call with realistic dummy args (e.g. debug_attach with pid=0, debug_read_memory with addr=0x140000000 len=16, debug_set_breakpoint with addr=0x140001000). Uses cargo-zyphora.exe target where sensible.
4. Run the probe. Capture per-tool result: {tool:string, ok:bool, error?:string, response_preview:string}.
5. Return JSON: {tools_tested:int, tools_ok:int, tools_error:int, per_tool:[{tool,ok,error,response_preview}], verdict:string, coverage_final_pct:number}
6. Also include a short user-readable summary of what the debugger can DO now (attach, breakpoints, memory, registers, backtrace, step, evaluate) — 1 sentence per capability.`,
  { label: 'test-live', agentType: 're-validator', schema: {
    type: 'object',
    properties: {
      tools_tested:{type:'integer'},
      tools_ok:{type:'integer'},
      tools_error:{type:'integer'},
      per_tool:{type:'array'},
      verdict:{type:'string'},
      coverage_final_pct:{type:'number'},
      capabilities_summary:{type:'string'},
    },
    required:['verdict']
  }}
)

return { status:'debug-mcp-complete', crateAudit, mcpAudit, complete, test }
