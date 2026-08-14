export const meta = {
  name: 'fix-mcp-wrapper-redirect-to-full-pipeline',
  description: 'Redirect the MCP decompile_function wrapper (and analyze_full / disasm_function) to call the FULL rustre-decompiler::Decompiler::decompile pipeline with all 6-sprint integrations (FLIRT+demangle, callconv, typerecov, dataflow, VSA, HLIL+CFS+expr). Verify every improvement is now visible via MCP live.',
  phases: [
    { title: 'DiagnoseWrapper', detail: 'find every MCP entry point that calls decompilation, map their code paths' },
    { title: 'RedirectDecompile', detail: 'rewrite decompile_function wrapper to use Decompiler::decompile()' },
    { title: 'ExposeHlil', detail: 'add hlil_pseudo_code field to DecompileResponse + MCP JSON schema' },
    { title: 'BuildRebuild', detail: 'kill mcp.exe, cargo build --release, verify binary mtime fresh' },
    { title: 'LiveVerify', detail: 'MCP live call decompile_function on 8 test funcs; measure delta vs pre-fix baseline' },
    { title: 'DeepVerify', detail: 'confirm each sprint effect visible: hlil_pseudo populated, DCE noise removed, WinAPI resolved, params correct, tipi ricostruiti' },
  ],
}

const CWD = 'C:/Users/Fra/Desktop/RustRE'

phase('DiagnoseWrapper')
const diagnose = await agent(
  `Diagnose the MCP wrapper path issue.

Steps:
1. Read ${CWD}/crates/rustre-mcp-server/src/binary_analysis_server.rs and find:
   - the ToolDefinition for "decompile_function"
   - the handler function (probably \`handle_decompile\` or similar) that processes the tools/call
   - what code path it invokes to actually decompile (grep for Decompiler::, decompile(, DecompileResponse::)
2. Read ${CWD}/crates/rustre-mcp/src/tool_handlers.rs and find:
   - \`handle_decompile_function\` — the ROUTER that gets called for mcp__rustre-mcp__decompile_function
   - what it calls in binary_analysis_server (should be DecompileResponse::decompile or handle_decompile)
3. Read the DecompileResponse struct — what fields does it have? (pseudo_c, function_name, duration_ms, confidence, but probably NOT hlil_pseudo_code)
4. Compare with the REAL pipeline in ${CWD}/crates/rustre-decompiler/src/lib.rs — grep for \`pub struct DecompiledFunction\` (should have hlil_pseudo_code: Option<String>) and \`impl Decompiler\` / \`pub fn decompile\`.
5. Grep binary_analysis_server for any use of \`rustre_decompiler::Decompiler\` or if it does its own quick x86 disasm + string emit.

Return JSON {
  wrapper_file: string,
  wrapper_fn_name: string,
  wrapper_calls_real_pipeline: bool,
  wrapper_shortcuts_to_disasm: bool,
  decompile_response_has_hlil: bool,
  real_pipeline_class: string,
  gap_summary: string
}`,
  { label: 'diagnose', agentType: 're-validator', schema: {
    type: 'object',
    properties: {
      wrapper_file:{type:'string'},
      wrapper_fn_name:{type:'string'},
      wrapper_calls_real_pipeline:{type:'boolean'},
      wrapper_shortcuts_to_disasm:{type:'boolean'},
      decompile_response_has_hlil:{type:'boolean'},
      real_pipeline_class:{type:'string'},
      gap_summary:{type:'string'},
    },
    required:['wrapper_file','gap_summary']
  }}
)

phase('RedirectDecompile')
const redirect = await agent(
  `Redirect the MCP decompile_function wrapper to use the FULL rustre-decompiler pipeline.

Steps:
1. Read ${CWD}/crates/rustre-mcp-server/src/binary_analysis_server.rs — locate DecompileRequest, DecompileResponse, and handle_decompile / DecompileResponse::decompile.
2. Read the real pipeline entry point — \`pub fn decompile\` in ${CWD}/crates/rustre-decompiler/src/lib.rs (look for the \`impl Decompiler\` block). This is the ONE that has all 6 sprints integrated (FLIRT+demangle, callconv, typerecov, dataflow, VSA, HLIL+CFS+expr).
3. Also look at ${CWD}/crates/rustre-decompiler/src/binary_entry.rs for \`pub fn decompile_function_in_load_bounded\` — this is likely the path-based entry point that goes through the full pipeline including DefaultPipelineFactory.
4. Rewrite the DecompileResponse::decompile(request: &DecompileRequest) fn so it:
   a. Loads the binary from request.binary_id (as path).
   b. Calls decompile_function_in_load_bounded(binary_path, addr) or an equivalent that runs the full Decompiler pipeline.
   c. Reads the DecompiledFunction returned — including its hlil_pseudo_code field.
   d. Populates DecompileResponse with pseudo_c=func.pseudo_code, hlil_pseudo=func.hlil_pseudo_code, confidence=func.confidence, function_name=func.name.
5. If DecompileResponse struct doesn't have hlil_pseudo field: add \`pub hlil_pseudo: Option<String>\` to it and initialize as None in constructors.
6. cd ${CWD} && cargo check --release -p rustre-mcp-server --message-format=short (Bash timeout 300000ms). Iterate fixes up to 5 rounds.

RULES: additive to DecompileResponse (add hlil_pseudo field). Do not change the response JSON shape in a way that breaks other callers — always keep pseudo_c present. Don't touch decompiler-* crates (already integrated correctly), only rewire the wrapper.

Return JSON {
  wrapper_rewritten: bool,
  new_deps_added: [string],
  hlil_field_added_to_response: bool,
  cargo_check_ok: bool,
  errors_final: int,
  notes: string
}`,
  { label: 'redirect', agentType: 're-validator', schema: {
    type: 'object',
    properties: {
      wrapper_rewritten:{type:'boolean'},
      new_deps_added:{type:'array', items:{type:'string'}},
      hlil_field_added_to_response:{type:'boolean'},
      cargo_check_ok:{type:'boolean'},
      errors_final:{type:'integer'},
      notes:{type:'string'},
    },
    required:['cargo_check_ok']
  }}
)

phase('ExposeHlil')
const exposeHlil = await agent(
  `Expose hlil_pseudo_code in the MCP JSON response of decompile_function.

Steps:
1. Read ${CWD}/crates/rustre-mcp/src/tool_handlers.rs — find handle_decompile_function (it currently returns a json! with binary_id, address, source, function_name, duration_ms, confidence).
2. Update the returned JSON to also include:
   - "hlil_pseudo_code": resp.hlil_pseudo (Option<String>, may be null if HLIL didn't produce output)
3. Read ${CWD}/crates/rustre-mcp-server/src/binary_analysis_server.rs — find the ToolDefinition for decompile_function and the output schema description. Update the description to mention hlil_pseudo_code field.
4. Also check ${CWD}/crates/rustre-mcp-server/src/lib.rs or wire_tools.rs for any other decompile_function tool wrapper that might have its own schema — grep "decompile_function" and update ALL locations.
5. cd ${CWD} && cargo check --release -p rustre-mcp -p rustre-mcp-server --message-format=short (Bash timeout 300000ms).

Return JSON {
  handlers_updated: int,
  schemas_updated: int,
  cargo_check_ok: bool,
  notes: string
}`,
  { label: 'expose-hlil', agentType: 're-validator', schema: {
    type: 'object',
    properties: {
      handlers_updated:{type:'integer'},
      schemas_updated:{type:'integer'},
      cargo_check_ok:{type:'boolean'},
      notes:{type:'string'},
    },
    required:['cargo_check_ok']
  }}
)

phase('BuildRebuild')
const build = await agent(
  `Rebuild MCP binary.

1. taskkill /F /IM rustre-mcp.exe 2>&1 (ignore not-found).
2. sleep 3.
3. cd ${CWD} && cargo build --release -p rustre-mcp -p rustre-mcp-server > /tmp/wrap_fix_build.log 2>&1 (Bash timeout 1800000ms).
4. Verify ${CWD}/target/release/rustre-mcp.exe mtime is after workflow start.

Return JSON {build_ok:bool, warnings:int, build_time_min:number, binary_mtime:string}.`,
  { label: 'build', agentType: 're-validator', schema: {
    type: 'object',
    properties: {
      build_ok:{type:'boolean'},
      warnings:{type:'integer'},
      build_time_min:{type:'number'},
      binary_mtime:{type:'string'},
    },
    required:['build_ok']
  }}
)

phase('LiveVerify')
const liveVerify = await agent(
  `Live-invoke decompile_function via MCP and compare vs pre-fix baseline.

Steps:
1. Ensure ${CWD}/target/release/rustre-mcp.exe is fresh.
2. Write Python probe at ${CWD}/validation/wrapper_fix_probe.py that:
   a. Spawns rustre-mcp via stdio.
   b. project.open(path=C:\\\\Users\\\\Fra\\\\Desktop\\\\Zyphora\\\\target\\\\release\\\\cargo-zyphora.exe).
   c. For each address in [0x140001000, 0x14000d880, 0x140026ad0, 0x1400a4a90, 0x1400f1190, 0x140009a90, 0x1400f2a00, 0x1400f206c]:
      - calls tools/call decompile_function with {binary_id, addr}
      - captures: confidence, has_hlil_pseudo (is hlil_pseudo_code non-null?), has_dce_comment (does pseudo_code contain "// DCE("), resolved_winapi (does pseudo_code contain "HeapAlloc" or "GetProcAddress" or similar?), noise_vars (count of v_XXXX in output)
   d. Saves results to ${CWD}/validation/wrapper_fix_probe_out.json.
3. Run the probe.
4. Compare with pre-fix baseline (unchanged output, confidence 72/56/92/etc, no hlil_pseudo, tons of v_XXXX noise).

Return JSON {
  probe_ok: bool,
  samples_ok: int,
  hlil_pseudo_populated_count: int,
  dce_comment_present_count: int,
  winapi_resolved_count: int,
  avg_noise_var_delta: number,
  confidence_delta: number,
  verdict: string
}`,
  { label: 'live-verify', agentType: 're-validator', schema: {
    type: 'object',
    properties: {
      probe_ok:{type:'boolean'},
      samples_ok:{type:'integer'},
      hlil_pseudo_populated_count:{type:'integer'},
      dce_comment_present_count:{type:'integer'},
      winapi_resolved_count:{type:'integer'},
      avg_noise_var_delta:{type:'number'},
      confidence_delta:{type:'number'},
      verdict:{type:'string'},
    },
    required:['verdict']
  }}
)

phase('DeepVerify')
const deepVerify = await agent(
  `Deep verify each sprint effect is visible.

For each of the 6 sprints, verify its specific expected effect on the MCP decompile_function output:
1. Sprint 1 (FLIRT + demangle) — call sites should have real names when FLIRT matches (e.g. __chkstk for sub_1400f1190). Grep pseudo_code for one of the standard CRT names.
2. Sprint 2 (callconv) — function signature parameters should match callconv analysis. Compare with baseline hand-coded __fastcall.
3. Sprint 3 (typerecov) — local variables should have specific types beyond generic __int64 (e.g. char, short, int, T*, or upgraded typedef).
4. Sprint 4 (dataflow) — dead-store lines should be commented with // DCE(df): prefix, and dead variable declarations removed.
5. Sprint 5 (VSA) — indirect calls should show resolved names when VSA has a singleton value; jump tables reflected as switch or JUMPOUT list.
6. Sprint 6 (HLIL) — hlil_pseudo_code Some(...) with real content, not None.

Test on address 0x140001000 (large parser) and 0x1400f1190 (stack probe, most likely to trigger FLIRT match).

Report {
  sprint1_flirt_visible: bool,
  sprint2_callconv_visible: bool,
  sprint3_types_upgraded: bool,
  sprint4_dce_visible: bool,
  sprint5_vsa_visible: bool,
  sprint6_hlil_populated: bool,
  overall_percent_active: number,
  verdict: string
}`,
  { label: 'deep-verify', agentType: 're-validator', schema: {
    type: 'object',
    properties: {
      sprint1_flirt_visible:{type:'boolean'},
      sprint2_callconv_visible:{type:'boolean'},
      sprint3_types_upgraded:{type:'boolean'},
      sprint4_dce_visible:{type:'boolean'},
      sprint5_vsa_visible:{type:'boolean'},
      sprint6_hlil_populated:{type:'boolean'},
      overall_percent_active:{type:'number'},
      verdict:{type:'string'},
    },
    required:['verdict']
  }}
)

return { status:'wrapper-fix-complete', diagnose, redirect, exposeHlil, build, liveVerify, deepVerify }
