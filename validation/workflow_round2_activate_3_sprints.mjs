export const meta = {
  name: 'round2-activate-flirt-vsa-hlil',
  description: 'Complete the 3 missing sprints: (1) expand FLIRT sigpack with MSVCRT+Rust stdlib, (2) wire analysis_bridge::run_vsa into decompile pipeline, (3) make hlil_pseudo_code populate the MCP response.',
  phases: [
    { title: 'ExpandFlirtSigpack', detail: 'add MSVCRT + Rust stdlib + __chkstk signatures to FLIRT sigpack' },
    { title: 'WireVSA', detail: 'call analysis_bridge::run_vsa from decompile() and use resolved_calls in emission' },
    { title: 'FixHlilPropagation', detail: 'ensure hlil_pseudo_code is Some(...) in DecompiledFunction and reaches MCP response' },
    { title: 'RebuildAndVerify', detail: 'rebuild, MCP live sample 8 fns, measure delta on 6 dimensions' },
  ],
}

const CWD = 'C:/Users/Fra/Desktop/RustRE'

phase('ExpandFlirtSigpack')
const flirt = await agent(
  `SPRINT 1 activation — expand FLIRT sigpack so real matches happen on cargo-zyphora.exe.

Current state: sigpack only 25 patterns, 0 matches on cargo-zyphora.exe. Goal: 500+ signatures covering MSVCRT/UCRT + Rust stdlib + Windows CRT stub.

Steps:
1. Grep the current FLIRT sigpack loading in ${CWD}/crates/rustre-decompiler/src/symbol_enrichment.rs and rustre-flirt-apply crate. Find where FlirtSigDb::load_demo_sigs() is defined and what it contains.
2. Grep ${CWD}/crates/rustre-flirt-gen/src/ for signature generation helpers.
3. Add to the demo sigpack (or create a new bundled sigpack) common patterns for:
   - MSVCRT/UCRT: memcpy, memset, memmove, strlen, strcpy, strcmp, malloc, free, realloc, printf, sprintf, fprintf, fopen, fclose, exit, __chkstk, __stdcall entry stubs
   - Rust stdlib: __rust_alloc, __rust_dealloc, __rust_realloc, __rust_panic, core::panicking::panic, core::str::from_utf8, alloc::vec::Vec::push, alloc::string::String::new, ThreadLocal::new
   - Windows loader stubs: __security_check_cookie, __security_init_cookie, _CRT_INIT, mainCRTStartup, __scrt_common_main, __GSHandlerCheck
   - Use pattern-based signatures: hash of first 32 bytes with wildcard for immediates/relocs. Use FlirtSigBuilder::from_bytes helper if available; otherwise synthesize FlirtSignature{name, bytes, mask, arch} entries directly.
4. If a proper .sig file format is used, write a small .sig file at ${CWD}/crates/rustre-decompiler/src/sigpack_extra.rs (or as bundled bytes) with 500+ entries.
5. Modify FlirtDemanglerResolver::new() to load BOTH the demo sigs AND the extra ones.
6. cd ${CWD} && cargo check --release -p rustre-decompiler --message-format=short (Bash timeout 300000ms). Iterate.

RULES: preserve existing demo_sigs load. Don't modify unrelated symbol resolution logic. Every added signature must include the function name string and a matchable byte pattern (with wildcard mask).

Return JSON {signatures_added:int, source_of_signatures:[string], cargo_check_ok:bool, notes:string}.`,
  { label: 'flirt-expand', agentType: 're-validator', schema: {
    type: 'object',
    properties: {
      signatures_added:{type:'integer'},
      source_of_signatures:{type:'array', items:{type:'string'}},
      cargo_check_ok:{type:'boolean'},
      notes:{type:'string'},
    },
    required:['cargo_check_ok']
  }}
)

phase('WireVSA')
const vsa = await agent(
  `SPRINT 5 activation — wire analysis_bridge::run_vsa into the real decompile() pipeline.

Current state: analysis_bridge.rs exports run_vsa, resolve_indirect_calls, bound_jump_tables. But NONE of them are called from rustre-decompiler/src/lib.rs::decompile. They are dead code.

Steps:
1. Read ${CWD}/crates/rustre-decompiler/src/analysis_bridge.rs — confirm run_vsa signature and see what VsaState / IndirectCallResolution look like.
2. Read ${CWD}/crates/rustre-decompiler/src/lib.rs — find IlAnalysisPass::run or Decompiler::decompile method, locate the point AFTER dataflow (Sprint 4) and BEFORE HLIL structuring (Sprint 6). This is where VSA belongs.
3. Add VSA invocation:
   \`\`\`rust
   // After dataflow pass, before HLIL
   let vsa_cfg = build_vsa_cfg_from_mlil(&mlil_blocks);   // small helper — convert MlilBasicBlock to VsaCfg
   if let Ok(vsa_states) = analysis_bridge::run_vsa(&vsa_cfg) {
       let resolved_calls = analysis_bridge::resolve_indirect_calls(&vsa_states, &vsa_cfg);
       // Store resolved_calls in ctx.annotations["vsa_resolved_calls"] as JSON
       ctx.set_annotation("vsa_resolved_calls_count", resolved_calls.len().to_string());
       ctx.set_annotation("vsa_resolved_calls", serde_json::to_string(&resolved_calls).unwrap_or_default());
       let jump_tables = analysis_bridge::bound_jump_tables(&vsa_states, &vsa_cfg);
       ctx.set_annotation("vsa_jump_tables_count", jump_tables.len().to_string());
   }
   \`\`\`
4. build_vsa_cfg_from_mlil is a small conversion — if MlilBasicBlock and VsaCfg differ, do minimal mapping (linear cfg with instrs converted to VsaInstr).
5. Also in emit_structured_code (or wherever indirect calls are emitted): read ctx.annotation["vsa_resolved_calls"] and, for each call site whose target matches a resolved entry, replace \`((__int64(*)()...)v9)(...)\` with \`RESOLVED_NAME(...)\`.
6. cd ${CWD} && cargo check --release -p rustre-decompiler --message-format=short (Bash timeout 300000ms). Iterate.

Return JSON {vsa_wired:bool, resolved_calls_annotation_added:bool, cargo_check_ok:bool, notes:string}.`,
  { label: 'wire-vsa', agentType: 're-validator', schema: {
    type: 'object',
    properties: {
      vsa_wired:{type:'boolean'},
      resolved_calls_annotation_added:{type:'boolean'},
      cargo_check_ok:{type:'boolean'},
      notes:{type:'string'},
    },
    required:['cargo_check_ok']
  }}
)

phase('FixHlilPropagation')
const hlil = await agent(
  `SPRINT 6 activation — ensure hlil_pseudo_code populates DecompiledFunction and reaches MCP response.

Current state: HLIL runs (produces .hlil.c side file) but DecompiledFunction.hlil_pseudo_code stays None. Wrapper adds hlil_pseudo field to DecompileResponse but it's always null.

Steps:
1. Read ${CWD}/crates/rustre-decompiler/src/lib.rs — find where HLIL emission happens. Search for hlil_pseudo_code, HlilLifter, ControlFlowStructurer, emit_pseudo_c (from Sprint 6 of we41jdzlj).
2. Confirm that when HLIL runs, its output text is stored in a variable in scope. Verify it's assigned to the DecompiledFunction.hlil_pseudo_code field before returning.
3. If it writes to a file BUT NOT to the struct field: fix the assignment. Look for something like:
   \`\`\`rust
   let hlil_text = rustre_il_hlil::emit_pseudo_c(&hlil_structured);
   // WRITE to side file (keep this if user wants disk output)
   std::fs::write(format!("...{}.hlil.c", addr), &hlil_text).ok();
   // NOW ALSO assign to struct:
   decompiled.hlil_pseudo_code = Some(hlil_text);
   \`\`\`
4. Read ${CWD}/crates/rustre-mcp-server/src/binary_analysis_server.rs::DecompileResponse::decompile — verify it reads func.hlil_pseudo_code and assigns to self.hlil_pseudo.
5. Read ${CWD}/crates/rustre-mcp/src/tool_handlers.rs::handle_decompile_function — verify the returned JSON includes "hlil_pseudo_code": resp.hlil_pseudo.
6. cd ${CWD} && cargo check --release -p rustre-decompiler -p rustre-mcp-server -p rustre-mcp --message-format=short (Bash timeout 300000ms).

Return JSON {hlil_field_assigned:bool, wrapper_propagates:bool, handler_returns_hlil:bool, cargo_check_ok:bool, notes:string}.`,
  { label: 'fix-hlil', agentType: 're-validator', schema: {
    type: 'object',
    properties: {
      hlil_field_assigned:{type:'boolean'},
      wrapper_propagates:{type:'boolean'},
      handler_returns_hlil:{type:'boolean'},
      cargo_check_ok:{type:'boolean'},
      notes:{type:'string'},
    },
    required:['cargo_check_ok']
  }}
)

phase('RebuildAndVerify')
const verify = await agent(
  `Rebuild + full verification.

1. taskkill /F /IM rustre-mcp.exe (ignore not-found). sleep 3.
2. cd ${CWD} && cargo build --release -p rustre-mcp -p rustre-mcp-server > /tmp/round2_build.log 2>&1 (Bash timeout 1800000ms). Iterate fixes up to 5 rounds if build errors — only touching the 3 files added in this round.
3. Once build clean: spawn Python probe at ${CWD}/validation/round2_probe.py to call decompile_function on 8 test addresses [0x140001000, 0x14000d880, 0x140026ad0, 0x1400a4a90, 0x1400f1190, 0x140009a90, 0x1400f2a00, 0x1400f206c]. For each:
   - Check response has "hlil_pseudo_code" key with non-null value (Sprint 6 visible)
   - Count "// DCE(df):" occurrences in pseudo_code (Sprint 4 visible)
   - Grep pseudo_code for resolved names: HeapAlloc, memcpy, __chkstk, malloc, printf, RtlAllocate, etc. (Sprint 1 visible)
   - Grep pseudo_code for VSA-resolved indirect calls: NOT "((__int64(*)()...)v_)(", but named calls (Sprint 5 visible)
4. Compare with pre-round2 baseline (Sprint 1=0 matches, Sprint 5=0 VSA calls, Sprint 6=0 hlil populated).
5. Report {
   build_ok:bool,
   sprint1_flirt_matches:int,
   sprint4_dce_present_in_functions:int,
   sprint5_vsa_indirect_resolved:int,
   sprint6_hlil_populated_count:int,
   avg_confidence:number,
   verdict:string
}`,
  { label: 'verify-round2', agentType: 're-validator', schema: {
    type: 'object',
    properties: {
      build_ok:{type:'boolean'},
      sprint1_flirt_matches:{type:'integer'},
      sprint4_dce_present_in_functions:{type:'integer'},
      sprint5_vsa_indirect_resolved:{type:'integer'},
      sprint6_hlil_populated_count:{type:'integer'},
      avg_confidence:{type:'number'},
      verdict:{type:'string'},
    },
    required:['verdict']
  }}
)

return { status:'round2-complete', flirt, vsa, hlil, verify }
