export const meta = {
  name: 'round3-diagnostic-fix',
  description: 'Round 3: diagnose why FLIRT/VSA/HLIL wire code produces no visible effect, then fix at the exact broken point.',
  phases: [
    { title: 'DiagnoseHlil', detail: 'Add eprintln! to HLIL emit path, rebuild, capture MCP stderr on decompile_function' },
    { title: 'DiagnoseFlirt', detail: 'Add eprintln! to FlirtApplier::scan showing sig count + match count' },
    { title: 'DiagnoseVsa', detail: 'Check if emission reads vsa_resolved_calls annotation; add consumer if missing' },
    { title: 'FixAndVerify', detail: 'Apply targeted fixes based on diagnostics, rebuild, verify via MCP' },
  ],
}

const CWD = 'C:/Users/Fra/Desktop/RustRE'

phase('DiagnoseHlil')
const hlilDiag = await agent(
  `Sprint 6 HLIL is wired: lib.rs line 13111-13114 inserts hlil_pseudo_code into ctx.annotations, ctx.finish() at line 619 moves to DecompiledFunction.hlil_pseudo_code, and wrapper propagates. But MCP returns empty string.

DIAGNOSTIC STEPS:
1. Read ${CWD}/crates/rustre-decompiler/src/lib.rs around line 13100-13130. Find the HLIL emission block.
2. Add eprintln! DEBUG traces:
   - Right BEFORE the CCodePrinter call: eprintln!("[HLIL] entering emit, mlil blocks: {}", mlil_blocks.len());
   - Right AFTER emit_pseudo_c returns: eprintln!("[HLIL] emit output len: {} chars", hlil_text.len());
   - When inserting annotation: eprintln!("[HLIL] annotation inserted: {} chars", hlil_text.len());
   - In ctx.finish() around line 619 where hlil_pseudo_code is assigned: eprintln!("[HLIL_FIN] pseudo_code = Some(len={})", text.len()); or eprintln!("[HLIL_FIN] annotation not present"); in the else branch.
3. cd ${CWD} && cargo build --release -p rustre-decompiler -p rustre-mcp-server -p rustre-mcp 2>&1 | tail -30 (Bash timeout 900000ms). Iterate on syntax errors.
4. taskkill //F //IM rustre-mcp.exe (ignore fail). Then run mcp probe: manually invoke ${CWD}/target/release/rustre-mcp.exe stdio with a JSON-RPC decompile_function call on 0x140001000 via a python subprocess, capture stderr, grep [HLIL] lines. Use ${CWD}/validation/round3_probe.py — write this file first.
5. Return {stderr_lines:string[], hlil_emit_reached:bool, hlil_emit_output_chars:int, hlil_annotation_present_at_finish:bool, diagnosis:string, cargo_build_ok:bool}

RULES: preserve existing code, ONLY add eprintln! lines. Do not modify structure or logic.`,
  { label: 'diag-hlil', agentType: 're-validator', schema: {
    type: 'object',
    properties: {
      stderr_lines:{type:'array', items:{type:'string'}},
      hlil_emit_reached:{type:'boolean'},
      hlil_emit_output_chars:{type:'integer'},
      hlil_annotation_present_at_finish:{type:'boolean'},
      diagnosis:{type:'string'},
      cargo_build_ok:{type:'boolean'},
    },
    required:['diagnosis','cargo_build_ok']
  }}
)

phase('DiagnoseFlirt')
const flirtDiag = await agent(
  `Sprint 1 FLIRT: 526 signatures added via load_extended_sigs() but 0 matches on cargo-zyphora.exe.

DIAGNOSTIC STEPS:
1. Read ${CWD}/crates/rustre-flirt-apply/src/lib.rs — find FlirtApplier::scan.
2. Add eprintln! traces:
   - At start of scan(): eprintln!("[FLIRT] scan bytes.len={}, sigs.len={}", bytes.len(), self.db.sigs.len());
   - Before returning matches: eprintln!("[FLIRT] scan complete: {} matches", matches.len());
   - Optional: for each sig that matches, eprintln!("[FLIRT] match: {} at 0x{:x}", sig.name, offset);
3. Read ${CWD}/crates/rustre-decompiler/src/symbol_enrichment.rs FlirtDemanglerResolver::from_binary — add eprintln!("[FLIRT-DB] merged demo+extended: {} sigs total", db.sigs.len());
4. Read one of the actual signature patterns added by Round 2 (e.g. the __chkstk pattern) and print it: eprintln!("[FLIRT-CHK] __chkstk pattern first 8 bytes: {:02X?} mask {:02X?}", pattern.bytes.iter().take(8).collect::<Vec<_>>(), pattern.mask.iter().take(8).collect::<Vec<_>>());
5. cd ${CWD} && cargo build --release -p rustre-flirt-apply -p rustre-decompiler -p rustre-mcp 2>&1 | tail -30.
6. Kill rustre-mcp, run python probe on 0x1400f1190, capture stderr, grep [FLIRT] lines.
7. Return {sig_count:int, match_count:int, chkstk_pattern_first_bytes:string, diagnosis:string, cargo_build_ok:bool}`,
  { label: 'diag-flirt', agentType: 're-validator', schema: {
    type: 'object',
    properties: {
      sig_count:{type:'integer'},
      match_count:{type:'integer'},
      chkstk_pattern_first_bytes:{type:'string'},
      diagnosis:{type:'string'},
      cargo_build_ok:{type:'boolean'},
    },
    required:['diagnosis','cargo_build_ok']
  }}
)

phase('DiagnoseVsa')
const vsaDiag = await agent(
  `Sprint 5 VSA: analysis_bridge::run_vsa called from IlAnalysisPass, writes vsa_resolved_calls annotation. But NO indirect call in emitted C shows a resolved name.

DIAGNOSTIC STEPS:
1. Grep ${CWD}/crates/rustre-decompiler/src -rn "vsa_resolved_calls" — find ALL readers. If only the writer exists, VSA output is never consumed by C emission — that's the bug.
2. Read the C emission path in ${CWD}/crates/rustre-decompiler/src/lib.rs. Find where indirect calls are emitted (search for "((__int64(*)()" or "call_indirect" or similar patterns in emission code).
3. Add eprintln! traces:
   - In run_vsa branch of IlAnalysisPass: eprintln!("[VSA] resolved_calls_count: {}", resolved_calls.len());
   - When emitting an indirect call: eprintln!("[VSA-EMIT] indirect call at MLIL_{}: checking VSA annotation", idx);
4. If NO consumer exists, add one: in the C emission function that handles indirect calls, read ctx.annotation("vsa_resolved_calls") once at start of function emission, deserialize the JSON, and for each call site whose target-instruction-index matches, substitute the name.
5. cd ${CWD} && cargo build --release -p rustre-decompiler -p rustre-mcp 2>&1 | tail -30.
6. Run python probe, capture stderr, grep [VSA] lines.
7. Return {consumer_exists_before_fix:bool, resolved_calls_count_seen:int, consumer_added_this_round:bool, diagnosis:string, cargo_build_ok:bool}`,
  { label: 'diag-vsa', agentType: 're-validator', schema: {
    type: 'object',
    properties: {
      consumer_exists_before_fix:{type:'boolean'},
      resolved_calls_count_seen:{type:'integer'},
      consumer_added_this_round:{type:'boolean'},
      diagnosis:{type:'string'},
      cargo_build_ok:{type:'boolean'},
    },
    required:['diagnosis','cargo_build_ok']
  }}
)

phase('FixAndVerify')
const fix = await agent(
  `Based on the 3 diagnostics from prior phases, apply the RIGHT fix for each broken sprint. Diagnostics available:

HLIL: ${JSON.stringify(hlilDiag)}
FLIRT: ${JSON.stringify(flirtDiag)}
VSA: ${JSON.stringify(vsaDiag)}

FIX STEPS (do for each sprint that had a real problem identified):
1. If HLIL emit returns empty text: find why (maybe emit_pseudo_c fails on empty MLIL blocks). Add a fallback: if emit returns empty, use the pseudo_code (LLIL-based) as hlil_pseudo_code so the field is at least non-empty.
2. If FLIRT sig patterns are malformed: fix the pattern generation in the code that added them (probably in symbol_enrichment.rs or a new sigpack file). Common mistake: mask 0x00 means "match exactly" and 0xFF means "wildcard" (or vice versa depending on the impl). Verify against the FlirtApplier::scan impl.
3. If VSA consumer was missing: it should have been added in phase 3. Verify build is clean.
4. Remove ALL eprintln! debug lines added during diagnosis (do not ship debug prints in production).
5. cd ${CWD} && cargo build --release -p rustre-decompiler -p rustre-mcp-server -p rustre-mcp 2>&1 | tail -20. Timeout 1800000ms.
6. Kill rustre-mcp, wait 3s.
7. Run python probe on 8 addresses. Report per-sprint delta:
   - Sprint 1: how many named calls (was 0)?
   - Sprint 4: how many DCE annotations (was 4)?
   - Sprint 5: how many resolved indirect calls (was 0)?
   - Sprint 6: how many functions have non-empty hlil_pseudo_code (was 0)?
8. Return {sprint1_flirt_matches:int, sprint4_dce_present:int, sprint5_vsa_resolved:int, sprint6_hlil_populated:int, avg_confidence:number, build_ok:bool, verdict:string, remaining_issues:string[]}`,
  { label: 'fix-verify', agentType: 're-validator', schema: {
    type: 'object',
    properties: {
      sprint1_flirt_matches:{type:'integer'},
      sprint4_dce_present:{type:'integer'},
      sprint5_vsa_resolved:{type:'integer'},
      sprint6_hlil_populated:{type:'integer'},
      avg_confidence:{type:'number'},
      build_ok:{type:'boolean'},
      verdict:{type:'string'},
      remaining_issues:{type:'array', items:{type:'string'}},
    },
    required:['verdict','build_ok']
  }}
)

return { status:'round3-diagnostic-complete', hlilDiag, flirtDiag, vsaDiag, fix }
