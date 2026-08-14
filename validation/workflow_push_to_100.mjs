export const meta = {
  name: 'push-decompiler-to-100pct',
  description: 'Enormous workflow: close the 5 remaining gaps to reach 100% vs IDA — stride bug, deref bug, FLIRT rename, HLIL structuring residual, HLIL type inference on unknowns',
  phases: [
    { title: 'Diagnose', detail: 'Find exact code paths for the 5 gaps + measure baseline' },
    { title: 'FixStride', detail: 'Fix dst -= 512 → 0x1000 on __chkstk pointer stride pattern' },
    { title: 'FixDerefBug', detail: 'Fix *sub_140107430(); spurious deref on resolved indirect calls' },
    { title: 'FlirtNames', detail: 'Populate name_store: off_14012C420/418 → WinAPI names via extended FLIRT sigs + IAT resolver' },
    { title: 'HlilResidualGoto', detail: 'Close remaining HLIL goto on large CFGs via decompiler-cfs::make_if_else + region-based structuring' },
    { title: 'TypeInferenceLastUnknowns', detail: 'Type inference on sp/flag_cf/fp/var_rXXl remaining unknowns' },
    { title: 'VerifyLive', detail: 'MCP live 3 probe + corpus regen + gcc + score delta' },
  ],
}

const CWD = 'C:/Users/Fra/Desktop/RustRE'

phase('Diagnose')
const diag = await agent(
  `Baseline + diagnosis for 5 remaining gaps in the decompiler emission.

STEPS:
1. Read ${CWD}/crates/rustre-decompiler/src/lib.rs — find the __chkstk pattern recognition for pointer-stride do/while loop. Search for "0x1000" "4096" "512" "0x200" stride patterns in loop emission. Report the file:line and current stride value.
2. Read the indirect-call resolver in the same lib.rs. Search for how "sub_XXX()" gets emitted when it's actually an off_XXX indirect thunk. Grep for "*sub_" pattern and find where it's produced.
3. Read ${CWD}/crates/rustre-mcp-server/src/lib.rs — find BinaryRegistry::load_file (project.open handler). Check if FlirtScanner is called + how name_store is populated. Report if extended sigs (load_extended_sigs) reach cargo-zyphora.exe scan.
4. Read ${CWD}/crates/rustre-decompiler/src/lib.rs FunctionBodyPass HLIL emission. Find where HLIL emitter transitions to next block on unstructured CFG. Report if decompiler_cfs::make_if_else is called on HLIL layer or only on pseudo_code.
5. Read ${CWD}/crates/rustre-il-hlil/src/lib.rs and MlilToHlilLifter type inference. Find why sp/flag_cf/fp/var_rXXl remain "unknown" instead of getting a type.
6. MCP live probe on cargo-zyphora.exe address 0x1400f1190 — confirm stride bug still present in output.
Return {stride_file_line:string, stride_current:string, deref_bug_file_line:string, flirt_scanner_call_present:bool, extended_sigs_reached_flag:bool, hlil_structuring_called_at_hlil:bool, missing_type_inference_reason:string, notes:string}`,
  { label: 'diagnose', agentType: 're-validator', schema: {
    type: 'object',
    properties: {
      stride_file_line:{type:'string'},
      stride_current:{type:'string'},
      deref_bug_file_line:{type:'string'},
      flirt_scanner_call_present:{type:'boolean'},
      extended_sigs_reached_flag:{type:'boolean'},
      hlil_structuring_called_at_hlil:{type:'boolean'},
      missing_type_inference_reason:{type:'string'},
      notes:{type:'string'},
    },
    required:['notes']
  }}
)

phase('FixStride')
const fixStride = await agent(
  `Fix pointer-stride bug: dst -= 512 must become dst -= 0x1000 on __chkstk-like patterns.

Diagnosis: ${JSON.stringify(diag)}

STEPS:
1. Locate the stride emission logic at file/line from diagnose. Usually in loop emit or memset-like pattern recognition.
2. Fix the constant: __chkstk decrements by 4096 (page size), not 512. Check if the wrong constant is hardcoded or derived from wrong SSA node.
3. If the stride is scaled by a factor (e.g. mm/simd), verify the scale factor. Preserve any correct simd stride cases.
4. Add a regression test in ${CWD}/crates/rustre-decompiler/tests/ that decompiles 0x1400f1190 and checks stride equals 4096.
5. cd ${CWD} && cargo build --release -p rustre-decompiler -p rustre-mcp-server -p rustre-mcp 2>&1 | tail -15. Iterate max 3 times.
Return {stride_fixed:bool, new_value:string, test_added:bool, build_ok:bool, notes:string}`,
  { label: 'fix-stride', agentType: 're-validator', schema: {
    type: 'object',
    properties: {
      stride_fixed:{type:'boolean'},
      new_value:{type:'string'},
      test_added:{type:'boolean'},
      build_ok:{type:'boolean'},
      notes:{type:'string'},
    },
    required:['build_ok','notes']
  }}
)

phase('FixDerefBug')
const fixDeref = await agent(
  `Fix spurious deref bug: "*sub_140107430();" should be "sub_140107430();" (16 occurrences on sub_140001000).

Diagnosis: ${JSON.stringify(diag)}

STEPS:
1. Locate the emission at file/line from diagnose. Usually a substitution from off_XXX to sub_XXX that forgets to strip the leading * (data-pointer indicator).
2. Fix: when substituting an off_XXX symbol for a function pointer that resolves to a sub_XXX (i.e. that particular indirect-call target maps to a known function), emit "sub_XXX()" not "*sub_XXX()".
3. Preserve the * for genuine data pointer derefs.
4. Grep to ensure no regressions on other emission patterns using leading * (data reads, xmm loads).
5. cd ${CWD} && cargo build --release -p rustre-decompiler -p rustre-mcp 2>&1 | tail -15.
Return {deref_fixed:bool, occurrences_now:integer, build_ok:bool, notes:string}`,
  { label: 'fix-deref', agentType: 're-validator', schema: {
    type: 'object',
    properties: {
      deref_fixed:{type:'boolean'},
      occurrences_now:{type:'integer'},
      build_ok:{type:'boolean'},
      notes:{type:'string'},
    },
    required:['build_ok','notes']
  }}
)

phase('FlirtNames')
const flirt = await agent(
  `Populate FLIRT names on cargo-zyphora.exe: off_14012C420/418 must resolve to WinAPI names (kernel32 imports).

Diagnosis: ${JSON.stringify(diag)}

STEPS:
1. Read ${CWD}/crates/rustre-mcp-server/src/lib.rs BinaryRegistry::load_file. Verify FlirtScanner::scan runs at project.open and calls FlirtSigDb::load_demo_sigs().merge(load_extended_sigs()).
2. Additionally, wire an IAT (Import Address Table) resolver: for each off_XXXXXXXX (data at .rdata section that is a PE import thunk), read the corresponding IAT entry's dll+name and populate name_store[addr] = "kernel32!HeapAlloc" (or whatever the import is).
3. Read ${CWD}/crates/rustre-loader-pe/src/lib.rs — use existing PE parser to enumerate imports. Cross-reference with off_XXX addresses in the decompiled binary.
4. Wire name_store BEFORE decompile_function emission runs, so off_14012C420 shows up as e.g. HeapAlloc or HeapFree.
5. cd ${CWD} && cargo build --release -p rustre-flirt-apply -p rustre-mcp-server -p rustre-decompiler -p rustre-mcp 2>&1 | tail -20.
Return {flirt_wired_at_project_open:bool, iat_resolver_added:bool, expected_renames_cargo_zyphora:int, build_ok:bool, notes:string}`,
  { label: 'flirt-names', agentType: 're-validator', schema: {
    type: 'object',
    properties: {
      flirt_wired_at_project_open:{type:'boolean'},
      iat_resolver_added:{type:'boolean'},
      expected_renames_cargo_zyphora:{type:'integer'},
      build_ok:{type:'boolean'},
      notes:{type:'string'},
    },
    required:['build_ok','notes']
  }}
)

phase('HlilResidualGoto')
const hlilStruct = await agent(
  `Close HLIL residual goto on large CFGs. Currently 136 goto residui on sub_140001000 HLIL.

Diagnosis: ${JSON.stringify(diag)}

STEPS:
1. Read ${CWD}/crates/rustre-decompiler/src/lib.rs FunctionBodyPass HLIL section. Find where HLIL is emitted.
2. Call decompiler_cfs::ControlFlowStructurer on HLIL blocks BEFORE emission. Use existing make_if_else / make_for / make_switch primitives.
3. If the CFG is irreducible, apply node splitting via decompiler_cfs::split_irreducible.
4. Prefer region-based structuring (Cifuentes-Simon algorithm) over goto chain.
5. Alternatively call analysis_cfg::LoopAnalysis + DominatorTree from rustre-analysis-cfg (currently dead crate) — wire it in Cargo.toml.
6. Add HLIL structuring pass BEFORE the emitter reaches sub_140001000-size functions.
7. Measure: goto count in HLIL output of sub_140001000 before/after.
8. cd ${CWD} && cargo build --release -p rustre-decompiler -p rustre-il-hlil -p rustre-decompiler-cfs -p rustre-mcp 2>&1 | tail -20.
Return {cfs_called_at_hlil:bool, analysis_cfg_wired:bool, goto_before:int, goto_after:int, build_ok:bool, notes:string}`,
  { label: 'hlil-struct', agentType: 're-validator', schema: {
    type: 'object',
    properties: {
      cfs_called_at_hlil:{type:'boolean'},
      analysis_cfg_wired:{type:'boolean'},
      goto_before:{type:'integer'},
      goto_after:{type:'integer'},
      build_ok:{type:'boolean'},
      notes:{type:'string'},
    },
    required:['build_ok','notes']
  }}
)

phase('TypeInferenceLastUnknowns')
const types = await agent(
  `Type inference on last HLIL unknowns: sp, flag_cf, flag_zf, fp, var_rXXl.

Diagnosis: ${JSON.stringify(diag)}

STEPS:
1. Read ${CWD}/crates/rustre-il-hlil/src/lib.rs MlilToHlilLifter type inference.
2. For each residual "unknown" in HLIL output:
   - sp/fp: assign uint64_t * (stack/frame pointer)
   - flag_cf/flag_zf/flag_sf/flag_of: assign bool
   - var_rXXl (r8l, r9l, r10l, r12l, r13l): assign uint8_t (low byte register)
   - var_rXXd (r8d, r9d, r10d): assign uint32_t (dword register — probably already done)
   - var_rXXw: assign uint16_t (word register)
3. If a var is still unknown after these rules, run rustre-analysis-typerecov constraint solver.
4. cd ${CWD} && cargo build --release -p rustre-il-hlil -p rustre-analysis-typerecov -p rustre-decompiler -p rustre-mcp 2>&1 | tail -15.
Return {unknown_count_before:int, unknown_count_after:int, rules_added:[string], build_ok:bool, notes:string}`,
  { label: 'types', agentType: 're-validator', schema: {
    type: 'object',
    properties: {
      unknown_count_before:{type:'integer'},
      unknown_count_after:{type:'integer'},
      rules_added:{type:'array', items:{type:'string'}},
      build_ok:{type:'boolean'},
      notes:{type:'string'},
    },
    required:['build_ok','notes']
  }}
)

phase('VerifyLive')
const verify = await agent(
  `Full verification of the 100% push.

STEPS:
1. taskkill //F //IM rustre-mcp.exe. sleep 3.
2. cd ${CWD} && cargo build --release -p rustre-mcp -p rustre-mcp-server 2>&1 | tail -5.
3. MCP live spawn probe on cargo-zyphora.exe [0x1400f1190, 0x140026ad0, 0x140001000]. For each measure:
   - stride 512 vs 4096 on 0x1400f1190
   - "*sub_" occurrences (should be 0)
   - named calls (HeapAlloc/HeapFree/memcpy etc — should be non-zero)
   - goto count in HLIL of sub_140001000
   - unknown var count in HLIL of sub_140001000
   - confidence
4. Corpus regen: for each ${CWD}/tests/decompiler_corpus/bin/*.exe run examples/dump_decompile.exe. gcc -std=gnu89 -fsyntax-only per file. Count pass/fail.
5. Return {stride_now:string, deref_bug_now:int, named_calls_now:int, hlil_goto_now:int, hlil_unknown_now:int, confidence_by_fn:object, corpus_gcc_pass:int, corpus_total:int, recompilability_pct:number, verdict:string, remaining_gaps:[string], score_delta_vs_ida:number}`,
  { label: 'verify', agentType: 're-validator', schema: {
    type: 'object',
    properties: {
      stride_now:{type:'string'},
      deref_bug_now:{type:'integer'},
      named_calls_now:{type:'integer'},
      hlil_goto_now:{type:'integer'},
      hlil_unknown_now:{type:'integer'},
      confidence_by_fn:{type:'object'},
      corpus_gcc_pass:{type:'integer'},
      corpus_total:{type:'integer'},
      recompilability_pct:{type:'number'},
      verdict:{type:'string'},
      remaining_gaps:{type:'array', items:{type:'string'}},
      score_delta_vs_ida:{type:'number'},
    },
    required:['verdict']
  }}
)

return { status:'push-to-100-complete', diag, fixStride, fixDeref, flirt, hlilStruct, types, verify }
