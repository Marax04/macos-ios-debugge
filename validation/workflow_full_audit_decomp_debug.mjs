export const meta = {
  name: 'full-audit-decomp-debug',
  description: 'Full audit of rustre-decompiler + rustre-debug after many piecemeal fixes: current state, capabilities, gaps, quality metrics',
  phases: [
    { title: 'AuditDecompiler', detail: 'Deep audit rustre-decompiler + orbit crates (il, analysis, cfs, expr, type, c)' },
    { title: 'AuditDebugger', detail: 'Deep audit rustre-debug: modules, backends (iOS/Linux/Windows), impl status' },
    { title: 'MeasureQuality', detail: 'Run corpus decompilation, gcc -fsyntax-only, count passes/fails, per-feature metrics' },
    { title: 'Roadmap', detail: 'Synthesize both audits + quality metrics into a prioritized next-work list' },
  ],
}

const CWD = 'C:/Users/Fra/Desktop/RustRE'

phase('AuditDecompiler')
const decomp = await agent(
  `Full audit of rustre-decompiler and its orbit crates after many recent fixes.

STEPS:
1. Glob ${CWD}/crates/rustre-decompiler/src/**/*.rs — file+lines each.
2. Read ${CWD}/crates/rustre-decompiler/Cargo.toml — deps list.
3. Read lib.rs (may be large — read first 500 lines then grep for pub fn / pub struct / IlAnalysisPass / decompile / emit).
4. Enumerate pipeline passes actually wired in the current standard_pipeline_arc() (or equivalent).
5. For each orbit crate: rustre-il-{llil,mlil,hlil,passes}, rustre-analysis-{cfg,dataflow,typerecov,vsa,callconv,fn,xref,vtable,type}, rustre-decompiler-{cfs,expr,type,c,ghidra}, rustre-flirt-{apply,gen}, rustre-demangle. For EACH crate report:
   - lines of code (glob src/**/*.rs count)
   - completeness: 0-100% subjective based on file coverage
   - key features implemented
   - known gaps/todos (grep for todo! unimplemented! FIXME TODO XXX)
   - is it wired into decompiler pipeline? (grep from lib.rs for imports)
6. Emission features status: DCE, struct field access, WinAPI signature prop, string literal detect, switch table, indirect call resolve via VSA, HLIL structured, FLIRT rename, type recovery, forward decls, casts, TLS/segment access, JUMPOUT emission.
7. Return JSON: {decompiler_files:[{path,lines}], pipeline_passes:[string], orbit_crates:[{name,lines,pct_complete,features:[string],gaps:[string],wired:bool}], emission_features_status:{feature:status}, total_lines_orbit:int, notes:string}`,
  { label: 'audit-decomp', agentType: 're-validator', schema: {
    type: 'object',
    properties: {
      decompiler_files:{type:'array'},
      pipeline_passes:{type:'array', items:{type:'string'}},
      orbit_crates:{type:'array'},
      emission_features_status:{type:'object'},
      total_lines_orbit:{type:'integer'},
      notes:{type:'string'},
    },
    required:['notes']
  }}
)

phase('AuditDebugger')
const dbg = await agent(
  `Full audit of ${CWD}/crates/rustre-debug (user's ONLY debugger, building from scratch with iOS/Linux/Windows backends in-crate).

STEPS:
1. Glob ${CWD}/crates/rustre-debug/src/**/*.rs — file+lines each.
2. Read Cargo.toml — deps (winapi/libc/mach/objc/ptrace/etc)?
3. Read src/lib.rs, module list.
4. For each module: 1-line purpose + is it OS-specific or cross-platform.
5. For each Debugger trait method: classify concrete impl status per OS (iOS/Linux/Windows/cross): impl / partial / stub / trait_only.
6. Advanced capabilities status (per OS where relevant):
   - TTD/time-travel
   - watchpoints (DR0-DR3 x86, DBGWVR ARM64)
   - expression evaluator
   - memory search
   - conditional breakpoints
   - session recording
   - omniscient query (Pernosco-style)
   - multi-target
   - CodeView PDB parser (absorbed)
   - DWARF parser
   - source_map / line info
   - symbol integration
   - iOS-specific: mach, task_for_pid, thread_get_state
   - Linux-specific: ptrace, /proc, procfs
   - Windows-specific: DebugActiveProcess, WaitForDebugEvent, ContinueDebugEvent, ReadProcessMemory, SetThreadContext
7. Check MCP wiring: how many debug_* tools exposed, are they wired to real trait impl or MockDebugger?
8. Grep todo!/unimplemented!/FIXME/TODO in rustre-debug/src.
9. Return JSON: {files:[{path,lines,purpose,os:string}], trait_methods_per_os:{method:{ios,linux,windows,cross}}, capabilities:{cap:{status,per_os}}, mcp_tools_live:int, mcp_uses_mock:bool, todos_count:int, gaps:[string], strengths:[string], readiness_pct:{ios:int,linux:int,windows:int,cross:int}}`,
  { label: 'audit-dbg', agentType: 're-validator', schema: {
    type: 'object',
    properties: {
      files:{type:'array'},
      trait_methods_per_os:{type:'object'},
      capabilities:{type:'object'},
      mcp_tools_live:{type:'integer'},
      mcp_uses_mock:{type:'boolean'},
      todos_count:{type:'integer'},
      gaps:{type:'array', items:{type:'string'}},
      strengths:{type:'array', items:{type:'string'}},
      readiness_pct:{type:'object'},
    },
    required:['readiness_pct']
  }}
)

phase('MeasureQuality')
const quality = await agent(
  `Measure current DECOMPILER quality on the corpus.

STEPS:
1. cd ${CWD} && cargo build --release -p rustre-decompiler 2>&1 | tail -5.
2. For each binary in ${CWD}/tests/decompiler_corpus/bin/*.exe: run ${CWD}/target/release/examples/dump_decompile.exe <bin> ${CWD}/tests/decompiler_corpus/out_audit_$(basename bin .exe)/
3. For each generated .c file, prepend the ida_defs.h prelude and run "gcc -std=gnu89 -fsyntax-only -w" (or clang if gcc not available). Count pass/fail per binary.
4. Grep the generated .c files for quality markers:
   - brace balance (open vs close)
   - "unknown" type occurrences
   - "sub_" undecoded name count vs total function count
   - JUMPOUT() count
   - "goto" count
   - Named WinAPI calls (Sleep, HeapAlloc, memcpy, etc)
   - "// DCE(df):" count
5. Report per-binary + overall aggregate:
   - recompilability_pct = passing files / total
   - avg_confidence (mean of decompile_function output)
   - unknown_type_ratio
   - named_func_ratio
   - jumpout_per_file avg
6. Return JSON: {per_binary:[{name,gcc_pass:bool,brace_balanced:bool,unknown_count:int,sub_ratio:number,jumpout:int,goto:int,dce:int,named_api:int}], overall_recompilability_pct:number, avg_confidence:number, avg_unknown:number, avg_named_api:number, verdict:string}`,
  { label: 'quality', agentType: 're-validator', schema: {
    type: 'object',
    properties: {
      per_binary:{type:'array'},
      overall_recompilability_pct:{type:'number'},
      avg_confidence:{type:'number'},
      avg_unknown:{type:'number'},
      avg_named_api:{type:'number'},
      verdict:{type:'string'},
    },
    required:['verdict']
  }}
)

phase('Roadmap')
const road = await agent(
  `Synthesize the 3 prior audits into a prioritized roadmap.

DECOMP AUDIT: ${JSON.stringify(decomp).slice(0,4000)}
DBG AUDIT: ${JSON.stringify(dbg).slice(0,4000)}
QUALITY: ${JSON.stringify(quality).slice(0,3000)}

Output a structured roadmap with:
1. Top 5 quick wins (< 1 day each, high impact) for decompiler.
2. Top 5 quick wins for debugger.
3. Top 5 deep-work items (multi-day) for decompiler.
4. Top 5 deep-work items for debugger.
5. Cross-cutting concerns (perf, symbols, workspace hygiene).
6. Honest current state summary in one paragraph (no marketing, no rounding up).

Return JSON: {quick_wins_decomp:[string], quick_wins_dbg:[string], deep_decomp:[string], deep_dbg:[string], cross_cutting:[string], honest_state:string}`,
  { label: 'roadmap', agentType: 're-validator', schema: {
    type: 'object',
    properties: {
      quick_wins_decomp:{type:'array', items:{type:'string'}},
      quick_wins_dbg:{type:'array', items:{type:'string'}},
      deep_decomp:{type:'array', items:{type:'string'}},
      deep_dbg:{type:'array', items:{type:'string'}},
      cross_cutting:{type:'array', items:{type:'string'}},
      honest_state:{type:'string'},
    },
    required:['honest_state']
  }}
)

return { status:'full-audit-complete', decomp, dbg, quality, road }
