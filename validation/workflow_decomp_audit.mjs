export const meta = {
  name: 'decompiler-audit-and-live-test',
  description: 'READ-ONLY audit of decompiler crates + LIVE MCP tool exercise vs IDA baseline. NO MODIFICATIONS.',
  phases: [
    { title: 'AuditRound3Changes', detail: 'find what round3 changed in decompiler crates' },
    { title: 'AuditCurrentState', detail: 'measure current decompiler quality metrics from source' },
    { title: 'LiveMcpTest', detail: 'exercise decompile_function via MCP against cargo-zyphora.exe' },
    { title: 'CompareToIda', detail: 'compare live output vs IDA Pro baseline on same functions' },
    { title: 'Report', detail: 'summary + verdict' },
  ],
}

const CWD = 'C:/Users/Fra/Desktop/RustRE'
const TARGET = 'C:/Users/Fra/Desktop/RustRE/samples/cargo-zyphora.exe'

// --- Phase 1: what did round 3 touch in decompiler? ---
phase('AuditRound3Changes')
const round3Audit = await agent(
  `READ-ONLY audit. Do NOT modify any file.
Task: identify every change made to decompiler-related crates by the round 3 workflow.
Steps:
1. Read ${CWD}/validation/workflow_round3.mjs and the journal at ${CWD}/.claude/projects/C--Users-Fra-Desktop-RustRE/b56d9ffc-3e22-4a1c-ba87-e9c414af631c/subagents/workflows/wf_3d8ca641-f3b/journal.jsonl (if accessible) to find every entry where a 'fix-tools' agent targeted rustre-decompiler or rustre-rlib-dec* or rustre-decompiler-*.
2. For each, extract: crate, tools_fixed count, files_changed list, summary.
3. Do NOT read the modified files' content — just enumerate them.
Return JSON {round3_decomp_touches: [{crate, tools_fixed, files_changed, summary}], total_files_touched: int, total_tools_fixed: int, verdict: string}. Verdict = short paragraph: "SAFE" if changes look surface-level (wrapper glue), "RISKY" if they touched core lifting/emission logic.`,
  { label: 'round3-decomp-audit', agentType: 're-validator', schema: {
    type: 'object',
    properties: {
      round3_decomp_touches: { type: 'array', items: { type: 'object' } },
      total_files_touched: { type: 'integer' },
      total_tools_fixed: { type: 'integer' },
      verdict: { type: 'string' },
    },
    required: ['verdict']
  }}
)

// --- Phase 2: measure current source-level quality ---
phase('AuditCurrentState')
const currentAudit = await agent(
  `READ-ONLY. Do NOT modify anything.
Task: measure the CURRENT quality of the decompiler in ${CWD}/crates/rustre-decompiler/ and related crates.
Steps:
1. Grep for TODO / FIXME / unimplemented!() / todo!() / panic!() in rustre-decompiler/src/, rustre-decompiler-type/src/, rustre-decompiler-core/src/. Count them.
2. Count exported functions in rustre-decompiler/src/lib.rs (fn / pub fn).
3. Check if parse_c_type is still present in rustre-decompiler-type/src/lib.rs and if emit_structured_code in rustre-decompiler/src/lib.rs uses it (grep for 'parse_c_type').
4. Count uses of DecompType::Unknown — high count means type inference not wiring in.
5. cargo check -p rustre-decompiler --release (timeout 300000ms) — report if it compiles cleanly.
6. cargo test -p rustre-decompiler --release --lib --no-run (timeout 300000ms) — report if tests compile.
Return JSON {
  todo_count: int, fixme_count: int, unimplemented_count: int, todo_macro_count: int, panic_count: int,
  exported_fn_count: int,
  parse_c_type_present: bool, parse_c_type_wired_in_emit: bool,
  decomp_unknown_uses: int,
  cargo_check_ok: bool, cargo_test_compile_ok: bool,
  compile_errors: [string],
  overall_health: "GOOD"|"OK"|"DEGRADED"|"BROKEN",
  notes: string
}`,
  { label: 'source-quality-check', agentType: 're-validator', schema: {
    type: 'object',
    properties: {
      todo_count: {type:'integer'}, fixme_count: {type:'integer'},
      unimplemented_count: {type:'integer'}, todo_macro_count: {type:'integer'}, panic_count: {type:'integer'},
      exported_fn_count: {type:'integer'},
      parse_c_type_present: {type:'boolean'}, parse_c_type_wired_in_emit: {type:'boolean'},
      decomp_unknown_uses: {type:'integer'},
      cargo_check_ok: {type:'boolean'}, cargo_test_compile_ok: {type:'boolean'},
      compile_errors: {type:'array', items:{type:'string'}},
      overall_health: {type:'string'},
      notes: {type:'string'}
    },
    required: ['overall_health']
  }}
)

// --- Phase 3: LIVE MCP test — exercise decompile_function ---
phase('LiveMcpTest')
const liveTest = await agent(
  `LIVE MCP TEST. Do NOT modify decompiler source.
Task: launch the built MCP server binary and exercise decompilation tools against ${TARGET}.
Steps:
1. Ensure the MCP server is built: cargo build -p rustre-mcp-server --release from ${CWD} (timeout 600000ms). Skip build if a fresh binary already exists (check mtime > 30 min old is stale).
2. Locate the built binary (likely ${CWD}/target/release/rustre-mcp-server.exe).
3. Write a small Python script in ${CWD}/validation/decomp_live_probe.py that spawns the server via stdio, sends JSON-RPC:
   - initialize
   - tools/call project.open with path=${TARGET}
   - tools/call decompile_function for 8 known function addresses (pick from IDA baseline: main, panic_fmt, alloc, dealloc, and 4 others by listing exports first if needed)
   - tools/call decompiler_detect_functions
   - tools/call analysis_fn_detect_functions_path with same path
   - tools/call rustre_decompiler_load_binary_info
4. Capture: response time, TOOL_ERROR count, output length, presence of "unknown"/"???"/"UNKNOWN" placeholders in decompiled C, count of typed variables vs Unknown.
5. Save all outputs to ${CWD}/validation/decomp_live_probe_out.json.
Return JSON {
  binary_built_ok: bool,
  server_started_ok: bool,
  project_open_ok: bool,
  functions_detected: int,
  decompile_calls_ok: int, decompile_calls_error: int,
  avg_decompile_ms: number,
  typed_vars: int, unknown_vars: int,
  c_output_sample: string (first 800 chars of first successful decompile),
  quality_signals: {has_types:bool, has_casts:bool, has_function_names:bool, has_control_flow:bool},
  verdict: "WORKING"|"PARTIAL"|"BROKEN",
  notes: string
}`,
  { label: 'live-mcp-decompile', agentType: 're-validator', schema: {
    type: 'object',
    properties: {
      binary_built_ok: {type:'boolean'},
      server_started_ok: {type:'boolean'},
      project_open_ok: {type:'boolean'},
      functions_detected: {type:'integer'},
      decompile_calls_ok: {type:'integer'}, decompile_calls_error: {type:'integer'},
      avg_decompile_ms: {type:'number'},
      typed_vars: {type:'integer'}, unknown_vars: {type:'integer'},
      c_output_sample: {type:'string'},
      quality_signals: {type:'object'},
      verdict: {type:'string'},
      notes: {type:'string'}
    },
    required: ['verdict']
  }}
)

// --- Phase 4: compare to IDA baseline ---
phase('CompareToIda')
const idaCompare = await agent(
  `READ-ONLY comparison. Do NOT modify decompiler source.
Task: compare RustRE decompile output vs IDA Pro baseline for cargo-zyphora.exe.
Steps:
1. Read ${CWD}/validation/decomp_live_probe_out.json (from previous phase) — this has RustRE output for 8 functions.
2. Read IDA baseline references. From memory: IDA reports 1456 functions, 395 named, has full decompiler.
   Look at any ${CWD}/validation/ida_baseline_*.json / ${CWD}/validation/ida_decompile_*.json / ${CWD}/validation/ground_truth_*.json for reference C outputs on the same 8 functions.
3. For each function comparable, score 0-10 across:
   - correct_types (does it recover int/ptr/struct? IDA=10 baseline)
   - named_symbols (function names / var names)
   - control_flow (if/while/for vs goto spaghetti)
   - readability (subjective — how close to IDA output)
4. Compute avg score and gap vs IDA.
5. Also apply ${CWD}/validation/decomp_quality_score_v2.py to the C output if the script exists.
Return JSON {
  functions_compared: int,
  avg_type_score: number, avg_symbol_score: number, avg_cfg_score: number, avg_readability_score: number,
  overall_vs_ida_pct: number,
  quality_v2_score: number,
  gaps: [string] (top 5 weaknesses vs IDA),
  strengths: [string] (top 3),
  verdict: "APPROACHING_IDA"|"BEHIND_IDA"|"FAR_BEHIND"|"UNCOMPARABLE"
}`,
  { label: 'ida-comparison', agentType: 're-validator', schema: {
    type: 'object',
    properties: {
      functions_compared: {type:'integer'},
      avg_type_score: {type:'number'}, avg_symbol_score: {type:'number'},
      avg_cfg_score: {type:'number'}, avg_readability_score: {type:'number'},
      overall_vs_ida_pct: {type:'number'},
      quality_v2_score: {type:'number'},
      gaps: {type:'array', items:{type:'string'}},
      strengths: {type:'array', items:{type:'string'}},
      verdict: {type:'string'}
    },
    required: ['verdict']
  }}
)

phase('Report')
return {
  status: 'decomp-audit-complete',
  round3_touched_decomp: round3Audit,
  source_health: currentAudit,
  live_mcp_test: liveTest,
  vs_ida: idaCompare,
}
