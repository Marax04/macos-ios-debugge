export const meta = {
  name: 'decomp-reaudit-post-stub-fix',
  description: 'Re-test decompiler quality via MCP after the stub-handler fix. READ-ONLY on decompiler crates.',
  phases: [
    { title: 'VerifyStubFix', detail: 'confirm handle_decompile_function no longer returns fake void sub_X' },
    { title: 'FreshBuild', detail: 'cargo build --workspace --release' },
    { title: 'LiveDecompile', detail: 'exercise real decompile_function on 20 functions' },
    { title: 'QualityScore', detail: 'run decomp_quality_score_v2.py on live outputs' },
    { title: 'CompareVsIda', detail: 'per-function comparison vs IDA baseline' },
    { title: 'Report', detail: 'final verdict' },
  ],
}

const CWD = 'C:/Users/Fra/Desktop/RustRE'

phase('VerifyStubFix')
const stubCheck = await agent(
  `READ-ONLY. Verify that the stub handler fix landed.
Steps:
1. Grep ${CWD}/crates/rustre-mcp/src/ for 'handle_decompile_function'. Read the function.
2. Confirm it does NOT return a hardcoded string like "void sub_X() { return; }". Confirm it calls the real decompiler pipeline (probably via rustre-mcp-server).
3. Same check for ${CWD}/crates/rustre-mcp-server/src/ handle_decompile_function.
4. Same check for binary_analysis_server.rs if present.
Return JSON {mcp_handler_real:bool, mcp_server_handler_real:bool, binary_analysis_handler_real:bool, other_stubs_found:[string], notes:string}.`,
  { label: 'verify-stub-fix', agentType: 're-validator', schema: {
    type: 'object',
    properties: {
      mcp_handler_real: {type:'boolean'},
      mcp_server_handler_real: {type:'boolean'},
      binary_analysis_handler_real: {type:'boolean'},
      other_stubs_found: {type:'array', items:{type:'string'}},
      notes: {type:'string'},
    },
    required: ['mcp_handler_real']
  }}
)

phase('FreshBuild')
const build = await agent(
  `cd ${CWD} && cargo build --workspace --release  (Bash timeout 900000ms). Verify ${CWD}/target/release/rustre-mcp.exe mtime is fresh. Return JSON {build_ok:bool, errors:int, warnings:int, binary_mtime:string}.`,
  { label: 'fresh-build', agentType: 're-validator', schema: {
    type: 'object',
    properties: {
      build_ok: {type:'boolean'},
      errors: {type:'integer'},
      warnings: {type:'integer'},
      binary_mtime: {type:'string'},
    },
    required: ['build_ok']
  }}
)

phase('LiveDecompile')
const live = await agent(
  `LIVE MCP test with the FIXED handler. Do NOT modify decompiler source.
Steps:
1. Use fresh binary ${CWD}/target/release/rustre-mcp.exe.
2. Write or update ${CWD}/validation/decomp_live_probe_v2.py:
   - Spawn server via stdio
   - initialize
   - project.open path=${CWD}/samples/cargo-zyphora.exe (or Zyphora build path if that's where cargo-zyphora.exe lives — check the previous probe out file for the correct path)
   - analyze.full to discover functions
   - Pick 20 non-trivial function addresses (skip synthetic / drop-glue / tiny). Pick by descending code size.
   - For each: tools/call decompile_function
   - Also call: rustre_decompiler_default_pipeline_standard, rustre_decompiler_quality_from_source on each output
   - Save all raw outputs to ${CWD}/validation/decomp_live_probe_v2_out.json
3. Compute per-function metrics on the live C:
   - has_typed_params, has_typed_locals, typed_var_ratio
   - has_if/has_while/has_for/has_switch (structured control flow)
   - goto_count (should be ~0 with real handler)
   - named_calls_ratio (calls that resolve to a symbol vs sub_XXXXXX)
   - lines_of_c
Return JSON {
  probe_file:string,
  functions_attempted:20,
  functions_decompiled:int,
  avg_lines:number,
  avg_typed_var_ratio:number,
  avg_structured_cf_ratio:number,
  avg_goto_count:number,
  avg_named_calls_ratio:number,
  sample_output:string (800 chars of best),
  verdict:"REAL_DECOMPILE"|"STILL_STUB"|"PARTIAL"
}.`,
  { label: 'live-decompile-v2', agentType: 're-validator', schema: {
    type: 'object',
    properties: {
      probe_file: {type:'string'},
      functions_attempted: {type:'integer'},
      functions_decompiled: {type:'integer'},
      avg_lines: {type:'number'},
      avg_typed_var_ratio: {type:'number'},
      avg_structured_cf_ratio: {type:'number'},
      avg_goto_count: {type:'number'},
      avg_named_calls_ratio: {type:'number'},
      sample_output: {type:'string'},
      verdict: {type:'string'},
    },
    required: ['verdict']
  }}
)

phase('QualityScore')
const quality = await agent(
  `Run ${CWD}/validation/decomp_quality_score_v2.py on ${CWD}/validation/decomp_live_probe_v2_out.json.
Report the 10-dimension score breakdown. Also run V1 if present for comparison. Return JSON {
  v2_overall:number,
  v2_dimensions:{types:number,names:number,cfg:number,readability:number,call_resolution:number,var_naming:number,literals:number,structs:number,idioms:number,noise:number},
  v1_overall:number|null,
  notes:string
}.`,
  { label: 'quality-score', agentType: 're-validator', schema: {
    type: 'object',
    properties: {
      v2_overall: {type:'number'},
      v2_dimensions: {type:'object'},
      v1_overall: {type:['number','null']},
      notes: {type:'string'},
    },
    required: ['v2_overall']
  }}
)

phase('CompareVsIda')
const cmp = await agent(
  `Compare the 20 live-decompiled functions from ${CWD}/validation/decomp_live_probe_v2_out.json against IDA baseline for cargo-zyphora.exe. Read any ${CWD}/validation/ida_*.json for baseline C outputs. Per-function score 0-10 across types/symbols/cfg/readability. Return JSON {
  functions_compared:int,
  avg_type_score:number, avg_symbol_score:number, avg_cfg_score:number, avg_readability_score:number,
  overall_vs_ida_pct:number,
  strengths:[string], gaps:[string],
  vs_last_audit:{prev_pct:35, delta_pct:number},
  verdict:"MATCHES_IDA"|"APPROACHING_IDA"|"BEHIND_IDA"|"FAR_BEHIND"
}.`,
  { label: 'vs-ida-v2', agentType: 're-validator', schema: {
    type: 'object',
    properties: {
      functions_compared: {type:'integer'},
      avg_type_score: {type:'number'},
      avg_symbol_score: {type:'number'},
      avg_cfg_score: {type:'number'},
      avg_readability_score: {type:'number'},
      overall_vs_ida_pct: {type:'number'},
      strengths: {type:'array', items:{type:'string'}},
      gaps: {type:'array', items:{type:'string'}},
      vs_last_audit: {type:'object'},
      verdict: {type:'string'},
    },
    required: ['verdict']
  }}
)

phase('Report')
return {
  status: 'reaudit-complete',
  stub_fix: stubCheck,
  build,
  live: live,
  quality,
  vs_ida: cmp,
}
