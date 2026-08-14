export const meta = {
  name: 'debug-only-rustre-debug',
  description: 'Remove MockDebugger + all references to deleted debug sub-crates. Wire ONLY rustre-debug (the user\'s crate). Then full audit of rustre-debug.',
  phases: [
    { title: 'PurgeMock', detail: 'Remove MockDebugger + references to rustre-debug-{windows,windbg,gdb,frida,linux,macos,kgdb,unicorn} from MCP wrappers' },
    { title: 'WireRustreDebug', detail: 'Wire the 29 MCP tools to real rustre-debug APIs (the single crate)' },
    { title: 'AuditRustreDebug', detail: 'Full audit: files, modules, public APIs, capabilities status (impl/stub/todo), missing pieces' },
    { title: 'VerifyLive', detail: 'MCP live-call every debug_* tool; report per-tool actual vs expected' },
  ],
}

const CWD = 'C:/Users/Fra/Desktop/RustRE'

phase('PurgeMock')
const purge = await agent(
  `The user has ONLY ONE debugger crate: ${CWD}/crates/rustre-debug. All sub-crates (rustre-debug-windows, rustre-debug-windbg, rustre-debug-gdb, rustre-debug-frida, rustre-debug-linux, rustre-debug-macos, rustre-debug-kgdb, rustre-debug-unicorn) were removed/moved to oldcreates on 2026-07-12. MockDebugger must also be removed from the MCP wrapper path.

STEPS:
1. Read ${CWD}/crates/rustre-debug/Cargo.toml — list REAL current dependencies (path deps in workspace). Confirm which sub-crates still exist as workspace members.
2. Grep ${CWD}/crates/rustre-mcp-tools -rn "MockDebugger" — list every occurrence.
3. Grep ${CWD}/crates/rustre-mcp-tools -rn "rustre_debug_windows\\|rustre_debug_windbg\\|rustre_debug_gdb\\|rustre_debug_frida\\|rustre_debug_linux\\|rustre_debug_macos\\|rustre_debug_kgdb\\|rustre_debug_unicorn" — list every reference to a moved sub-crate.
4. Same greps on rustre-mcp-server and rustre-mcp.
5. Same greps on ${CWD}/Cargo.toml (workspace) — check for any lingering workspace members pointing to the removed sub-crates.
6. Verify ${CWD}/oldcreates contains those moved sub-crates (as user confirmed).
7. Do NOT delete anything yet — return a plan.

Return {mock_debugger_files:[string], subcrate_refs_by_file:{file:[refs]}, workspace_members_stale:[string], real_current_deps_of_rustre_debug:[string], plan:string}`,
  { label: 'purge-plan', agentType: 're-validator', schema: {
    type: 'object',
    properties: {
      mock_debugger_files:{type:'array', items:{type:'string'}},
      subcrate_refs_by_file:{type:'object'},
      workspace_members_stale:{type:'array', items:{type:'string'}},
      real_current_deps_of_rustre_debug:{type:'array', items:{type:'string'}},
      plan:{type:'string'},
    },
    required:['plan']
  }}
)

phase('WireRustreDebug')
const wire = await agent(
  `Purge plan: ${JSON.stringify(purge)}

STEPS:
1. In every file listed in mock_debugger_files, replace uses of rustre_debug::v2::MockDebugger with the REAL debugger type from ${CWD}/crates/rustre-debug (whatever the current single-implementation type is — check lib.rs re-exports; the trait is Debugger; find the concrete impl, likely named Debugger, RustreDebugger, or WindowsDebugger inside rustre-debug itself).
2. If rustre-debug has ONLY the trait and no concrete impl (because backends were moved), then the closures cannot call actual OS APIs — in that case, WIRE THEM TO A CROSS-PLATFORM DebugSession stub that lives INSIDE rustre-debug (search ${CWD}/crates/rustre-debug/src for anything DebugSession-like). Do NOT create a new MockDebugger.
3. Remove every stale import of a moved sub-crate (rustre_debug_windows etc). Fix each file that referenced them.
4. Do NOT touch rustre-debug internals (user is developing).
5. cd ${CWD} && cargo build --release -p rustre-mcp-tools -p rustre-mcp-server -p rustre-mcp 2>&1 | tail -25. Iterate max 5 times.

Return {files_edited:[string], concrete_debugger_type_used:string, subcrate_refs_removed:int, build_ok:bool, notes:string}`,
  { label: 'wire-real', agentType: 're-validator', schema: {
    type: 'object',
    properties: {
      files_edited:{type:'array', items:{type:'string'}},
      concrete_debugger_type_used:{type:'string'},
      subcrate_refs_removed:{type:'integer'},
      build_ok:{type:'boolean'},
      notes:{type:'string'},
    },
    required:['build_ok','notes']
  }}
)

phase('AuditRustreDebug')
const audit = await agent(
  `Full audit of ${CWD}/crates/rustre-debug (user's SINGLE debugger crate).

STEPS:
1. Glob ${CWD}/crates/rustre-debug/src/**/*.rs — list every file with line count.
2. Read Cargo.toml — features, deps, workspace path.
3. For each module (top-level lib.rs + every mod file), list pub items with 1-line purpose.
4. For each Debugger trait method (attach/launch/detach/kill/continue/step_*/read_memory/write_memory/read_registers/set_registers/breakpoints/threads/modules/backtrace/pause/is_attached), classify as:
   - "impl" — has a concrete implementation calling actual APIs
   - "stub" — returns Err(Unsupported) or hardcoded mock data
   - "todo" — todo!() or unimplemented!() macro
   - "trait_only" — only trait definition, no impl in this crate
5. Identify capabilities beyond the base trait: TTD, watchpoints, expression eval, memory search, conditional breakpoints, session recording, symbol integration (codeview absorbed), etc. Status for each.
6. Backends question: with all sub-crates moved to oldcreates, does rustre-debug still contain OS-specific code? Or is it now purely trait+cross-platform utilities? Report honestly.
7. Return JSON: {files:[{path,lines,purpose}], trait_methods_status:{method:status}, extra_capabilities:{cap:status}, os_support_actual:string, is_pure_trait_crate:bool, total_pub_items:int, what_the_user_still_needs_to_finish:[string]}`,
  { label: 'audit-real', agentType: 're-validator', schema: {
    type: 'object',
    properties: {
      files:{type:'array'},
      trait_methods_status:{type:'object'},
      extra_capabilities:{type:'object'},
      os_support_actual:{type:'string'},
      is_pure_trait_crate:{type:'boolean'},
      total_pub_items:{type:'integer'},
      what_the_user_still_needs_to_finish:{type:'array', items:{type:'string'}},
    },
    required:['os_support_actual','is_pure_trait_crate','total_pub_items']
  }}
)

phase('VerifyLive')
const verify = await agent(
  `Live-verify debug tools via MCP after Mock purge + real rustre-debug wiring.

STEPS:
1. taskkill //F //IM rustre-mcp.exe. sleep 3.
2. cd ${CWD} && cargo build --release -p rustre-mcp -p rustre-mcp-server 2>&1 | tail -10.
3. Python probe: spawn rustre-mcp.exe stdio, tools/list, then call each debug_* / debug.* tool.
4. For each: capture response, note if it references MockDebugger (should be gone), what actual rustre-debug type is used.
5. Return {tools_exposed:int, mock_references_remaining:int, per_tool:[{tool,ok,response_has_mock_string:bool,response_preview:string}], verdict:string}`,
  { label: 'verify-live', agentType: 're-validator', schema: {
    type: 'object',
    properties: {
      tools_exposed:{type:'integer'},
      mock_references_remaining:{type:'integer'},
      per_tool:{type:'array'},
      verdict:{type:'string'},
    },
    required:['verdict']
  }}
)

return { status:'debug-mock-purged', purge, wire, audit, verify }
