export const meta = {
  name: 'audit-decomp-debug-v2',
  description: 'Full re-audit of rustre-decompiler + rustre-debug after 2h of user work: current state, wiring, capabilities, live MCP verification',
  phases: [
    { title: 'AuditDecomp', detail: 'rustre-decompiler + orbit crates: files, wiring, pipeline, gaps' },
    { title: 'AuditDebug', detail: 'rustre-debug: modules, backends per OS, real impl status' },
    { title: 'QualityAndMcp', detail: 'Corpus regen + gcc + MCP live sample decomp + MCP live sample debug tools' },
    { title: 'Delta', detail: 'Compare with prior audit, list what changed in the last 2h' },
  ],
}

const CWD = 'C:/Users/Fra/Desktop/RustRE'

phase('AuditDecomp')
const decomp = await agent(
  `Full audit of rustre-decompiler and orbit crates AS THEY ARE NOW.

STEPS:
1. Glob ${CWD}/crates/rustre-decompiler/src/**/*.rs — file+lines.
2. Read Cargo.toml — enumerate deps.
3. Identify pipeline: read pass_pipeline.rs, pipeline_coordinator.rs, standard_pipeline entry — list every pass in wire order.
4. For each orbit crate report {name, lines_total (glob src/**/*.rs), completeness_pct, features_impl:[string], gaps:[string], wired_into_decompiler:bool, imports_used:[which pub types imported by rustre-decompiler]}.
   Orbit list: rustre-il-{llil,mlil,hlil,passes}, rustre-analysis-{cfg,dataflow,typerecov,vsa,vtable,callconv,fn,xref,type}, rustre-decompiler-{cfs,expr,type,c,ghidra}, rustre-flirt-{apply,gen}, rustre-demangle.
5. Grep for "todo!" "unimplemented!" "FIXME" occurrences per crate.
6. Emission feature status: DCE, struct field, WinAPI sig prop, string literal, switch table, indirect call via VSA, HLIL structured, FLIRT rename, forward decls, casts, TLS/segment, JUMPOUT emit.
7. Report {orbit_crates_summary, dead_crates:[names not imported], pipeline_pass_count, emission_feature_status:{feat:status}, decompiler_lib_lines, notes}`,
  { label: 'audit-decomp', agentType: 're-validator', schema: {
    type: 'object',
    properties: {
      orbit_crates_summary:{type:'array'},
      dead_crates:{type:'array', items:{type:'string'}},
      pipeline_pass_count:{type:'integer'},
      emission_feature_status:{type:'object'},
      decompiler_lib_lines:{type:'integer'},
      notes:{type:'string'},
    },
    required:['notes']
  }}
)

phase('AuditDebug')
const dbg = await agent(
  `Full audit of ${CWD}/crates/rustre-debug (user's ONLY debugger crate, 2h of recent work).

STEPS:
1. Glob src/**/*.rs — file+lines with 1-line purpose.
2. Read Cargo.toml — deps (winapi/windows/libc/mach/nix/ptrace/etc).
3. Grep src for cfg(target_os = "windows"|"linux"|"macos"|"ios") to detect real OS backends.
4. For each Debugger trait method (25 in v1) classify per OS: impl/partial/stub/trait_only. Also list any concrete impl Debugger for Xxx types.
5. Advanced modules status: expression_evaluator, watchpoint_engine, watchpoint_manager, memory_search, memory_layout_view, cross_platform_debug, time_travel_debug, session_manager, session_recorder, multi_target, omniscient_query, register_context, source_map, codeview, conditional_breakpoint. Each: complete/partial/stub.
6. MCP wiring: how many debug_* tools exposed; does register_debug_group() call MockDebugger or WindowsDebugger?
7. Grep todo!/unimplemented!/FIXME count.
8. Report {files_summary:[{path,lines,purpose}], concrete_impls:[string], trait_methods_per_os:{method:{win:string,lin:string,mac:string,ios:string,cross:string}}, capabilities:{module:status}, mcp_wired_to:string, mcp_tools_count:int, todo_count:int, readiness_pct:{win,lin,mac,ios,cross}, notes:string}`,
  { label: 'audit-debug', agentType: 're-validator', schema: {
    type: 'object',
    properties: {
      files_summary:{type:'array'},
      concrete_impls:{type:'array', items:{type:'string'}},
      trait_methods_per_os:{type:'object'},
      capabilities:{type:'object'},
      mcp_wired_to:{type:'string'},
      mcp_tools_count:{type:'integer'},
      todo_count:{type:'integer'},
      readiness_pct:{type:'object'},
      notes:{type:'string'},
    },
    required:['notes']
  }}
)

phase('QualityAndMcp')
const q = await agent(
  `Live quality measurement.

STEPS:
1. taskkill //F //IM rustre-mcp.exe (ignore fail). sleep 3.
2. cd ${CWD} && cargo build --release -p rustre-decompiler -p rustre-mcp -p rustre-mcp-server 2>&1 | tail -10.
3. Regenerate corpus: for each ${CWD}/tests/decompiler_corpus/bin/*.exe run examples/dump_decompile.exe <bin> tests/decompiler_corpus/out/<name>/. Count: total .c files, gcc -std=gnu89 -fsyntax-only pass count with ida_defs.h prelude, brace balance per file (strip string literals first with regex), JUMPOUT count, sub_ ratio, DCE(df) count, named WinAPI count.
4. MCP live: spawn rustre-mcp.exe stdio, tools/list, count total. Sample decompile_function on cargo-zyphora.exe at addresses [0x140001000, 0x1400f1190, 0x140026ad0, 0x1400f2a00]; extract per-fn: name, confidence, hlil_pseudo_code != pseudo_code, presence of __readgsqword, // DCE(df):, struct field access, named calls.
5. MCP debug tools: enumerate debug.* + debug_* tools listed; call each with minimal args; count OK / error / mock-source / real-source.
6. Report {corpus_total_c:int, gcc_pass:int, recompilability_pct:number, brace_balanced:int, jumpout_total:int, dce_total:int, named_api_total:int, avg_confidence_sampled:number, mcp_total_tools:int, mcp_debug_tools:int, mcp_debug_ok:int, mcp_debug_real_source:int, sample_hlil_real:int, verdict:string}`,
  { label: 'quality', agentType: 're-validator', schema: {
    type: 'object',
    properties: {
      corpus_total_c:{type:'integer'},
      gcc_pass:{type:'integer'},
      recompilability_pct:{type:'number'},
      brace_balanced:{type:'integer'},
      jumpout_total:{type:'integer'},
      dce_total:{type:'integer'},
      named_api_total:{type:'integer'},
      avg_confidence_sampled:{type:'number'},
      mcp_total_tools:{type:'integer'},
      mcp_debug_tools:{type:'integer'},
      mcp_debug_ok:{type:'integer'},
      mcp_debug_real_source:{type:'integer'},
      sample_hlil_real:{type:'integer'},
      verdict:{type:'string'},
    },
    required:['verdict']
  }}
)

phase('Delta')
const delta = await agent(
  `Compare current audit with prior audit findings and synthesize what changed in the last 2 hours.

PRIOR AUDIT KEY FINDINGS:
- Decompiler: 99.9% gcc pass (11136/11144), avg_confidence 89, 339 JUMPOUTs, 15798 DCE, named API 109/binary
- Orbit dead crates: il-passes, analysis-cfg, analysis-dataflow, analysis-vsa (partial), analysis-xref
- Debugger: WindowsDebugger real Win32 in-crate but MCP still MockDebugger, readiness Win 70% code / 15% via MCP, Lin/iOS 0%
- MCP debug tools: 10 helper + 29 with MockDebugger source
- HLIL populated but register-level (unknown var_r10, goto goto goto)

CURRENT AUDIT (from prior phases):
DECOMP: ${JSON.stringify(decomp).slice(0,3500)}
DEBUG: ${JSON.stringify(dbg).slice(0,3500)}
QUALITY: ${JSON.stringify(q).slice(0,2500)}

Produce:
1. delta_decomp: bullet list of concrete changes (crates newly wired, passes added, features working now that didn't before, regressions if any).
2. delta_debug: same for debugger — new backends wired, MCP moved from Mock to real, new modules exposed.
3. delta_quality: recompilability change, confidence change, JUMPOUT change, HLIL structure change.
4. honest_new_state: 1 paragraph, no marketing, current % vs IDA + current % Win/Lin/iOS debugger readiness.
5. next_5_highest_impact: top 5 items to work on next based on the current gaps.

Return {delta_decomp:[string], delta_debug:[string], delta_quality:[string], honest_new_state:string, next_5_highest_impact:[string]}`,
  { label: 'delta', agentType: 're-validator', schema: {
    type: 'object',
    properties: {
      delta_decomp:{type:'array', items:{type:'string'}},
      delta_debug:{type:'array', items:{type:'string'}},
      delta_quality:{type:'array', items:{type:'string'}},
      honest_new_state:{type:'string'},
      next_5_highest_impact:{type:'array', items:{type:'string'}},
    },
    required:['honest_new_state']
  }}
)

return { status:'audit-v2-complete', decomp, dbg, q, delta }
