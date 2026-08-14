export const meta = {
  name: 'round4-real-activation',
  description: 'Round 4: fix the 3 remaining wire issues — real HLIL path, FLIRT name propagation, VSA convergence on cargo-zyphora',
  phases: [
    { title: 'RealHlilPath', detail: 'Route decompile.function through decompile_function_from_binary so IlAnalysisPass actually runs' },
    { title: 'FlirtNameStore', detail: 'Populate name_store at project.open with FLIRT matches; use load_extended_sigs everywhere' },
    { title: 'VsaConverge', detail: 'Debug why resolved_calls_count=0 on cargo-zyphora; fix VSA CFG build or lattice' },
    { title: 'Verify', detail: 'MCP live verify 8 test addresses; measure real delta per sprint' },
  ],
}

const CWD = 'C:/Users/Fra/Desktop/RustRE'

phase('RealHlilPath')
const hlil = await agent(
  `Sprint 6 HLIL: hlil_pseudo_code is now populated but AS A FALLBACK FROM pseudo_code (identical to LLIL output). The RealDecompileFunctionHandler at the MCP layer does NOT run IlAnalysisPass which would produce the real HLIL emit (up to 4236 chars in prior traces).

STEPS:
1. Grep ${CWD}/crates/rustre-mcp -rn "RealDecompileFunctionHandler" and ${CWD}/crates/rustre-mcp-server -rn "RealDecompileFunctionHandler". Find its handle() body.
2. Compare with decompile_function_from_binary in ${CWD}/crates/rustre-decompiler/src/lib.rs — that is the path that runs the full pipeline including IlAnalysisPass.
3. Replace RealDecompileFunctionHandler's decompile call so it invokes decompile_function_from_binary (or equivalent full-pipeline entry). Remove the fallback that copies pseudo_code into hlil_pseudo_code — instead read the real annotation.
4. If decompile_function_from_binary needs setup (config, options) that RealDecompileFunctionHandler doesn't currently do, wire it minimally.
5. cd ${CWD} && cargo build --release -p rustre-decompiler -p rustre-mcp-server -p rustre-mcp 2>&1 | tail -20. Iterate.
6. Do NOT delete existing behavior, DO NOT touch rustre-debug or rustre-decompiler-*.

Return {handler_updated:bool, fallback_removed:bool, real_pipeline_wired:bool, build_ok:bool, notes:string}`,
  { label: 'real-hlil', agentType: 're-validator', schema: {
    type: 'object',
    properties: {
      handler_updated:{type:'boolean'},
      fallback_removed:{type:'boolean'},
      real_pipeline_wired:{type:'boolean'},
      build_ok:{type:'boolean'},
      notes:{type:'string'},
    },
    required:['build_ok','notes']
  }}
)

phase('FlirtNameStore')
const flirt = await agent(
  `Sprint 1 FLIRT: 535 sigs loaded, 10 real matches on cargo-zyphora.exe, but 0 functions renamed in MCP output because name_store is not populated at project.open with FLIRT results, AND flirt_apply_auto MCP tool uses baseline_packs (25 sigs) instead of load_extended_sigs (535 sigs).

STEPS:
1. Grep ${CWD}/crates/rustre-mcp -rn "project.open" or "handle_project_open". Find where a project/binary is loaded.
2. In that path, after loading the binary, invoke FlirtDemanglerResolver::from_binary(&bytes) to get matches, then populate the project's name_store: for each match at addr X, insert name_store[X] = match.name. Grep for "name_store" or "symbol_table" to find the right container.
3. If name_store is per-binary, store on Binary struct. If per-project, on Project struct. Make sure decompile_function looks it up when generating "name" in the response.
4. Grep flirt_apply_auto tool implementation. Change it to call FlirtSigDb::load_demo_sigs().merge(load_extended_sigs()) instead of just baseline_packs.
5. cd ${CWD} && cargo build --release -p rustre-flirt-apply -p rustre-mcp-tools -p rustre-mcp 2>&1 | tail -20.

Return {project_open_populates_names:bool, flirt_apply_auto_uses_extended:bool, expected_renames_on_cargo_zyphora:int, build_ok:bool, notes:string}`,
  { label: 'flirt-name', agentType: 're-validator', schema: {
    type: 'object',
    properties: {
      project_open_populates_names:{type:'boolean'},
      flirt_apply_auto_uses_extended:{type:'boolean'},
      expected_renames_on_cargo_zyphora:{type:'integer'},
      build_ok:{type:'boolean'},
      notes:{type:'string'},
    },
    required:['build_ok','notes']
  }}
)

phase('VsaConverge')
const vsa = await agent(
  `Sprint 5 VSA: analysis_bridge::run_vsa is called from IlAnalysisPass but resolved_calls_count = 0 on cargo-zyphora.exe. Cause unknown: either (a) VSA CFG built from MLIL is empty/malformed, (b) VSA lattice doesn't propagate values, (c) resolve_indirect_calls filter is too strict, (d) cargo-zyphora has few "call [reg]" sites.

STEPS:
1. Read ${CWD}/crates/rustre-decompiler/src/analysis_bridge.rs — build_vsa_cfg_from_mlil and resolve_indirect_calls.
2. Add temporary eprintln!:
   - Before run_vsa: eprintln!("[VSA-CFG] nodes={}, edges={}", cfg.nodes.len(), cfg.edges.len());
   - After run_vsa: eprintln!("[VSA-STATE] states={}", vsa_states.len());
   - In resolve_indirect_calls loop: eprintln!("[VSA-SITE] call at 0x{:x}, target_valueset_size={}", addr, target_vs.len());
3. Also count how many indirect call sites (call [reg], call qword ptr [...]) exist across the 8 test functions. Grep the pseudo_code output for "((__int64(*)()".
4. cd ${CWD} && cargo build --release -p rustre-decompiler -p rustre-mcp 2>&1 | tail -15.
5. Run python probe on 8 test addresses. Capture stderr [VSA-*] lines.
6. Analyze: is the CFG empty? Are states missing? Do value sets have 0 concrete targets? Report the actual failure mode.
7. If the fix is clear (e.g. build_vsa_cfg_from_mlil is stubbed), apply it. Otherwise report what's needed.

Return {cfg_nodes:int, cfg_edges:int, states_count:int, call_sites_seen:int, concrete_targets_avg:number, root_cause:string, fix_applied:bool, build_ok:bool}`,
  { label: 'vsa-converge', agentType: 're-validator', schema: {
    type: 'object',
    properties: {
      cfg_nodes:{type:'integer'},
      cfg_edges:{type:'integer'},
      states_count:{type:'integer'},
      call_sites_seen:{type:'integer'},
      concrete_targets_avg:{type:'number'},
      root_cause:{type:'string'},
      fix_applied:{type:'boolean'},
      build_ok:{type:'boolean'},
    },
    required:['root_cause','build_ok']
  }}
)

phase('Verify')
const verify = await agent(
  `Full verification of Round 4.

STEPS:
1. Remove ALL eprintln! debug lines added in prior phases. Grep for "[HLIL]" "[FLIRT]" "[VSA" and clean.
2. taskkill //F //IM rustre-mcp.exe. sleep 3.
3. cd ${CWD} && cargo build --release -p rustre-mcp -p rustre-mcp-server 2>&1 | tail -10.
4. Python probe on 8 addresses: 0x140001000, 0x14000d880, 0x140026ad0, 0x1400a4a90, 0x1400f1190, 0x140009a90, 0x1400f2a00, 0x1400f206c.
5. For each, extract:
   - name (should be real for FLIRT-matched functions, sub_XXX otherwise)
   - hlil_pseudo_code non-null AND different from pseudo_code (means real HLIL, not fallback)
   - // DCE(df): count in pseudo_code
   - VSA-resolved names in pseudo_code (not just "((__int64(*)()"
6. Report {
   sprint1_named_functions:int,
   sprint4_dce_present:int,
   sprint5_vsa_resolved:int,
   sprint6_hlil_populated_and_real:int,
   sprint6_hlil_is_fallback_only:int,
   avg_confidence:number,
   build_ok:bool,
   verdict:string,
   what_still_broken:string[]
}`,
  { label: 'verify-round4', agentType: 're-validator', schema: {
    type: 'object',
    properties: {
      sprint1_named_functions:{type:'integer'},
      sprint4_dce_present:{type:'integer'},
      sprint5_vsa_resolved:{type:'integer'},
      sprint6_hlil_populated_and_real:{type:'integer'},
      sprint6_hlil_is_fallback_only:{type:'integer'},
      avg_confidence:{type:'number'},
      build_ok:{type:'boolean'},
      verdict:{type:'string'},
      what_still_broken:{type:'array', items:{type:'string'}},
    },
    required:['verdict','build_ok']
  }}
)

return { status:'round4-complete', hlil, flirt, vsa, verify }
