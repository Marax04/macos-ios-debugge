export const meta = {
  name: 'full-decompiler-pipeline-integration',
  description: 'FULL integration: demangle + flirt-apply + callconv + typerecov + dataflow + VSA + HLIL + cfs/expr/type/c orchestrator. All wired into decompile() with regression tests between sprints.',
  phases: [
    { title: 'Sprint1_Symbols', detail: 'wire rustre-demangle + rustre-flirt-apply for symbol enrichment' },
    { title: 'Sprint2_Callconv', detail: 'wire rustre-analysis-callconv for function signature inference' },
    { title: 'Sprint3_Typerecov', detail: 'wire rustre-analysis-typerecov + rustre-decompiler-type deeply' },
    { title: 'Sprint4_Dataflow', detail: 'wire rustre-analysis-dataflow for dead-code + copy propagation' },
    { title: 'Sprint5_VSA', detail: 'wire rustre-analysis-vsa for indirect call + jump table resolution' },
    { title: 'Sprint6_HLIL_CFS', detail: 'wire rustre-il-hlil real structuring + populate hlil_pseudo_code; deepen rustre-decompiler-cfs + expr + c' },
    { title: 'FinalVerify', detail: 'MCP live sample of 10 functions + measure quality delta' },
  ],
}

const CWD = 'C:/Users/Fra/Desktop/RustRE'
const DECOMP = `${CWD}/crates/rustre-decompiler`

// Helper: sample MCP decompile for regression check
const SAMPLE_FUNCS = [
  { addr: '0x140001000', kind: 'large-parser' },
  { addr: '0x14000d880', kind: 'loop' },
  { addr: '0x140026ad0', kind: 'call-site' },
  { addr: '0x1400a4a90', kind: 'SIMD' },
  { addr: '0x1400f2a00', kind: 'small-jumpout' },
  { addr: '0x1400f1190', kind: 'stack-probe' },
  { addr: '0x1400f206c', kind: 'mainCRTStartup' },
  { addr: '0x140009a90', kind: 'small-return-int' },
]

phase('Sprint1_Symbols')
const sprint1 = await agent(
  `SPRINT 1 — Wire rustre-demangle and rustre-flirt-apply into ${DECOMP}/src/lib.rs decompile() pipeline.

Goal: for every function name and call-site symbol, run through:
1. rustre-flirt-apply::apply_signatures(binary_data, functions) → identifies known library funcs (HeapAlloc, __chkstk, memcpy, etc.). Renames sub_XXX → real name.
2. rustre-demangle::auto_demangle(name) → decodes Rust/C++/Itanium/MSVC mangling into readable names.

Steps:
1. Read ${DECOMP}/src/lib.rs to locate the point where DecompiledFunction is built with its .name field, and where call_sites are emitted.
2. Add helper module ${DECOMP}/src/symbol_enrichment.rs with:
   \`\`\`rust
   use rustre_flirt_apply as flirt;
   use rustre_demangle as dem;

   pub struct SymbolResolver {
       // FLIRT signature database
       flirt_db: flirt::SignatureDatabase,
   }

   impl SymbolResolver {
       pub fn new() -> Self { Self { flirt_db: flirt::SignatureDatabase::builtin_crt() } }

       /// Resolve address to human-friendly name via FLIRT + demangler.
       pub fn resolve(&self, addr: u64, raw_bytes: &[u8], fallback: &str) -> String {
           // Try FLIRT first
           if let Some(m) = self.flirt_db.match_function(raw_bytes) {
               return m.name.to_string();
           }
           // Try demangling the fallback name (which might be a mangled Rust/C++ symbol)
           if let Ok(demangled) = dem::auto_demangle(fallback) {
               return demangled;
           }
           fallback.to_string()
       }
   }
   \`\`\`
3. In lib.rs decompile(), wire the resolver: create one instance, use it to enrich function.name and each call_site name.
4. If flirt::SignatureDatabase / builtin_crt / match_function / dem::auto_demangle don't exist exactly, GREP the real API and adapt. Use the closest fn that returns a Result<String>.
5. cd ${CWD} && cargo check --release -p rustre-decompiler --message-format=short (Bash timeout 300000ms). Iterate up to 5 rounds.

RULES: additive only, don't change existing signatures. If a call site cannot be resolved, use existing fallback.
Return JSON {refs_added:int, api_adjustments:[string], cargo_check_ok:bool, notes:string}.`,
  { label: 'sprint1-symbols', agentType: 're-validator', schema: {
    type: 'object',
    properties: {
      refs_added:{type:'integer'},
      api_adjustments:{type:'array', items:{type:'string'}},
      cargo_check_ok:{type:'boolean'},
      notes:{type:'string'},
    },
    required:['cargo_check_ok']
  }}
)

phase('Sprint2_Callconv')
const sprint2 = await agent(
  `SPRINT 2 — Wire rustre-analysis-callconv into decompile() for correct function signature inference.

Goal: replace hand-coded __fastcall signatures with real callconv analysis that inspects register usage in the prologue.

Steps:
1. Read ${DECOMP}/src/lib.rs to locate where the function signature (return type + params) is decided.
2. Look at rustre-analysis-callconv public API (grep pub fn / pub struct in its src/lib.rs).
3. At the point where DecompiledFunction is created, ADD a step:
   \`\`\`rust
   let callconv = rustre_analysis_callconv::analyze(&mlil_blocks, arch);
   let sig = callconv.infer_signature();  // params + return
   \`\`\`
   Then use \`sig\` to set the function's parameter list and return type.
4. If the exact API differs, adapt. Grep the actual API and use zero-arg / minimal calls that link.
5. cargo check --release -p rustre-decompiler. Iterate up to 5 rounds.

Return JSON {refs_added:int, api_adjustments:[string], cargo_check_ok:bool, notes:string}.`,
  { label: 'sprint2-callconv', agentType: 're-validator', schema: {
    type: 'object',
    properties: {
      refs_added:{type:'integer'},
      api_adjustments:{type:'array', items:{type:'string'}},
      cargo_check_ok:{type:'boolean'},
      notes:{type:'string'},
    },
    required:['cargo_check_ok']
  }}
)

phase('Sprint3_Typerecov')
const sprint3 = await agent(
  `SPRINT 3 — Wire rustre-analysis-typerecov AND deepen rustre-decompiler-type usage.

Goal: for every local variable in the MLIL, infer its type from access patterns (byte-size access, signed-ops, ptr-deref, struct-field).

Steps:
1. Read the currently 4-ref usage of rustre_decompiler_type in ${DECOMP}/src/lib.rs.
2. Grep rustre-analysis-typerecov public API. Look for TypeRecovery, TypeInference, TypePropagation, StructFieldDetector.
3. After MLIL construction, add:
   \`\`\`rust
   let mut typerecov = rustre_analysis_typerecov::TypeRecovery::new();
   for block in &mlil_blocks {
       for instr in &block.instrs {
           typerecov.observe_instr(&instr.instr);
       }
   }
   typerecov.propagate();
   \`\`\`
4. Use typerecov results to enrich rustre_decompiler_type's variable type map.
5. Adapt to real API.
6. cargo check --release -p rustre-decompiler.

Return JSON {refs_added:int, api_adjustments:[string], cargo_check_ok:bool, notes:string}.`,
  { label: 'sprint3-typerecov', agentType: 're-validator', schema: {
    type: 'object',
    properties: {
      refs_added:{type:'integer'},
      api_adjustments:{type:'array', items:{type:'string'}},
      cargo_check_ok:{type:'boolean'},
      notes:{type:'string'},
    },
    required:['cargo_check_ok']
  }}
)

phase('Sprint4_Dataflow')
const sprint4 = await agent(
  `SPRINT 4 — Wire rustre-analysis-dataflow (reaching defs + liveness) for dead-code elimination and copy propagation.

Goal: eliminate the \`int v_1240; int v_1250; int v_1260; ...\` noise the user sees. These are stack slots that get loaded but never used semantically.

Steps:
1. Grep rustre-analysis-dataflow public API. Look for compute_reaching_defs, compute_liveness, eliminate_dead_code, copy_propagate, LivenessResult.
2. After MLIL construction (and after Sprint 3's typerecov), add a pass:
   \`\`\`rust
   let reaching = rustre_analysis_dataflow::compute_reaching_defs(&mlil_blocks);
   let liveness = rustre_analysis_dataflow::compute_liveness(&mlil_blocks);
   let mlil_blocks = rustre_analysis_dataflow::eliminate_dead_code(mlil_blocks, &liveness);
   let mlil_blocks = rustre_analysis_dataflow::copy_propagate(mlil_blocks, &reaching);
   \`\`\`
3. Replace the smoke stub in analysis_bridge.rs with a real call (or delete the stub — depends on if anything imports it).
4. Adapt to real API.
5. cargo check --release -p rustre-decompiler.

Return JSON {refs_added:int, api_adjustments:[string], smoke_stub_removed:bool, cargo_check_ok:bool, notes:string}.`,
  { label: 'sprint4-dataflow', agentType: 're-validator', schema: {
    type: 'object',
    properties: {
      refs_added:{type:'integer'},
      api_adjustments:{type:'array', items:{type:'string'}},
      smoke_stub_removed:{type:'boolean'},
      cargo_check_ok:{type:'boolean'},
      notes:{type:'string'},
    },
    required:['cargo_check_ok']
  }}
)

phase('Sprint5_VSA')
const sprint5 = await agent(
  `SPRINT 5 — Wire rustre-analysis-vsa for indirect call resolution and jump table detection.

Goal: transform \`((__int64(*)())v9)(10, v5, v6)\` into \`HeapAlloc(10, v5, v6)\` when VSA proves v9 is always &HeapAlloc. Also detect switch/jump tables.

Steps:
1. Grep rustre-analysis-vsa public API. Look for ValueSet, run_forward, resolve_indirect_calls, detect_jump_tables, StridedInterval.
2. After dataflow (Sprint 4), before HLIL structuring, add:
   \`\`\`rust
   let vsa_state = rustre_analysis_vsa::run_forward(&mlil_blocks, &reaching);
   let resolved_calls = rustre_analysis_vsa::resolve_indirect_calls(&vsa_state, &mlil_blocks);
   let jump_tables = rustre_analysis_vsa::detect_jump_tables(&vsa_state, &mlil_blocks);
   \`\`\`
3. Feed resolved_calls into the C emission so \`((__int64(*)()...)\` becomes \`RealName(...)\`.
4. Replace analysis_bridge.rs smoke stub with real call.
5. cargo check --release -p rustre-decompiler.

Return JSON {refs_added:int, api_adjustments:[string], cargo_check_ok:bool, notes:string}.`,
  { label: 'sprint5-vsa', agentType: 're-validator', schema: {
    type: 'object',
    properties: {
      refs_added:{type:'integer'},
      api_adjustments:{type:'array', items:{type:'string'}},
      cargo_check_ok:{type:'boolean'},
      notes:{type:'string'},
    },
    required:['cargo_check_ok']
  }}
)

phase('Sprint6_HLIL_CFS')
const sprint6 = await agent(
  `SPRINT 6 — Wire rustre-il-hlil real structuring + populate DecompiledFunction.hlil_pseudo_code. Deepen rustre-decompiler-cfs + rustre-decompiler-expr + rustre-decompiler-c usage.

Goal: populate the currently-always-None field \`hlil_pseudo_code\` with a real HLIL-based pseudo-C output. This is the ULTIMATE pipeline.

Steps:
1. Add rustre-decompiler-expr as dep in ${DECOMP}/Cargo.toml (currently NOT a dep).
2. Grep rustre-il-hlil for structure_analysis(), HlilLifter, HlilStatement, emit_pseudo_c(), HlilBuilder.
3. After VSA (Sprint 5), add HLIL construction:
   \`\`\`rust
   let hlil_blocks = rustre_il_hlil::HlilLifter::from_mlil(&mlil_blocks, &resolved_calls);
   let hlil_structured = rustre_il_hlil::structure_analysis(hlil_blocks);
   let hlil_pseudo = rustre_il_hlil::emit_pseudo_c(&hlil_structured);
   \`\`\`
4. In DecompiledFunction construction, set \`hlil_pseudo_code: Some(hlil_pseudo)\`.
5. Also enhance rustre-decompiler-cfs usage (from 2 → 10+ refs) with real structuring calls:
   \`\`\`rust
   let structured = rustre_decompiler_cfs::structure(&hlil_structured, ...);
   \`\`\`
6. And rustre-decompiler-expr for expression simplification pass:
   \`\`\`rust
   for stmt in &mut structured {
       rustre_decompiler_expr::simplify(&mut stmt.expr);
   }
   \`\`\`
7. Adapt to real API.
8. cargo check --release -p rustre-decompiler.

Return JSON {refs_added:int, hlil_pseudo_populated:bool, new_deps:[string], api_adjustments:[string], cargo_check_ok:bool, notes:string}.`,
  { label: 'sprint6-hlil-cfs', agentType: 're-validator', schema: {
    type: 'object',
    properties: {
      refs_added:{type:'integer'},
      hlil_pseudo_populated:{type:'boolean'},
      new_deps:{type:'array', items:{type:'string'}},
      api_adjustments:{type:'array', items:{type:'string'}},
      cargo_check_ok:{type:'boolean'},
      notes:{type:'string'},
    },
    required:['cargo_check_ok']
  }}
)

phase('FinalVerify')
const finalVerify = await agent(
  `FINAL — Full build + MCP live regression + quality delta.

1. taskkill /F /IM rustre-mcp.exe (ignore not found).
2. cd ${CWD} && cargo build --release -p rustre-mcp -p rustre-mcp-server > /tmp/full_int_build.log 2>&1 (Bash timeout 1800000ms).
3. If build fails, iterate fix ONLY on the wire-glue files (analysis_bridge.rs, symbol_enrichment.rs, or the areas touched by sprints 1-6). Do NOT touch the underlying analysis/il crates.
4. Once build clean, spawn a Python subprocess to sample decompile_function on these 8 test addresses on ${CWD}/../Zyphora/target/release/cargo-zyphora.exe (via MCP JSON-RPC to ${CWD}/target/release/rustre-mcp.exe):
   ${SAMPLE_FUNCS.map(f => `${f.addr} (${f.kind})`).join(', ')}
5. For each sample, capture: confidence, pseudo_code length, hlil_pseudo_code populated? (Some/None), number of resolved call names (no more \`sub_XXXX\` for common WinAPI), presence of jump table structure (switch statement), presence of clean C-like structure (no \`v_1240, v_1250, v_1260\` noise).
6. Compare against baseline from earlier audit: confidence 72 for sub_140001000, 56 for sub_14000d880, 92 for sub_140026ad0, etc.
7. Report {build_ok:bool, samples_ok:int, samples_regressed:int, avg_confidence_delta:number, hlil_populated_ratio:number, resolved_symbols_avg:number, verdict:string}.`,
  { label: 'final-verify', agentType: 're-validator', schema: {
    type: 'object',
    properties: {
      build_ok:{type:'boolean'},
      samples_ok:{type:'integer'},
      samples_regressed:{type:'integer'},
      avg_confidence_delta:{type:'number'},
      hlil_populated_ratio:{type:'number'},
      resolved_symbols_avg:{type:'number'},
      verdict:{type:'string'},
    },
    required:['verdict']
  }}
)

return { status:'full-integration-complete', sprint1, sprint2, sprint3, sprint4, sprint5, sprint6, finalVerify }
