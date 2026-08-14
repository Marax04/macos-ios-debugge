export const meta = {
  name: 'round5-finish-to-100pct',
  description: 'Fix last 29 TOOL_ERROR + harden all remaining ~1620 loose tools + verify workspace tests. DECOMPILER UNTOUCHED.',
  phases: [
    { title: 'Rebuild', detail: 'fresh MCP binary' },
    { title: 'Fix29Errors', detail: 'fix exercise_v3.py inputs for the 29 remaining tool_errors' },
    { title: 'HardenRemaining', detail: 'convert ~1620 loose tools to rigorous by category (parallel)' },
    { title: 'WorkspaceTests', detail: 'ensure every crate compiles and passes cargo test' },
    { title: 'FinalHonest', detail: 'union rigorous count + fresh exercise + workspace test' },
  ],
}

const CWD = 'C:/Users/Fra/Desktop/RustRE'
const BANNED = ['rustre-decompiler', 'rustre-decompiler-type', 'rustre-decompiler-ghidra', 'rustre-rlib-dec', 'rustre-rlib-dec2']
const BAN_LIST = BANNED.join(', ')

// ------- Phase 1: rebuild -------
phase('Rebuild')
const build = await agent(
  `cd ${CWD} && cargo build --workspace --release  (Bash tool, timeout 900000ms). Report {build_ok:bool, errors:int, warnings:int, binary_mtime:string}.`,
  { label: 'rebuild', agentType: 're-validator', schema: {
    type: 'object',
    properties: { build_ok:{type:'boolean'}, errors:{type:'integer'}, warnings:{type:'integer'}, binary_mtime:{type:'string'} },
    required: ['build_ok']
  }}
)

// ------- Phase 2: fix the 29 tool_errors in exercise_v3.py -------
phase('Fix29Errors')
const FAILING_29 = [
  {tool:'pe_editor_parse_dos_header', hint:'buffer needs at least 64 bytes DOS header'},
  {tool:'pe_editor_parse_file_header', hint:'buffer needs at least 20 bytes COFF file header'},
  {tool:'pe_editor_parse_optional_header64', hint:'buffer needs at least 112 bytes PE32+ optional header'},
  {tool:'diff_bindiff_hungarian_solve', hint:'cost_matrix must be non-empty 2D array of floats'},
  {tool:'diff_bindiff_hungarian_from_similarity', hint:'similarity_matrix must be non-empty 2D array'},
  {tool:'debug_unicorn_script_gen', hint:'kind must be one of the accepted enum values (e.g. "x86_64" or similar)'},
  {tool:'kgdb_read_u64_le_hex', hint:'hex string must be exactly 16 chars (u64), not 32'},
  {tool:'dotnet_metadata_parse_direct_summary', hint:'blob must be a valid .NET metadata table stream'},
  {tool:'dotnet_metadata_type_full_names', hint:'valid .NET metadata blob required'},
  {tool:'dotnet_metadata_all_method_names', hint:'valid .NET metadata blob required'},
  {tool:'dotnet_metadata_find_type', hint:'valid .NET metadata blob required + type_name string'},
  {tool:'dotnet_metadata_table_summary', hint:'valid .NET metadata blob required'},
  {tool:'dotnet_metadata_validate', hint:'valid .NET metadata blob required'},
  {tool:'dotnet_metadata_assembly_manifest', hint:'valid .NET metadata blob required'},
  {tool:'dotnet_metadata_all_module_names', hint:'valid .NET metadata blob required'},
  {tool:'dotnet_metadata_exported_type_names', hint:'valid .NET metadata blob required'},
  {tool:'dotnet_metadata_resource_names', hint:'valid .NET metadata blob required'},
  {tool:'dotnet_metadata_file_names', hint:'valid .NET metadata blob required'},
  {tool:'dotnet_metadata_has_entry_point', hint:'valid .NET metadata blob required'},
  {tool:'dotnet_metadata_find_methods_by_name', hint:'valid .NET metadata blob required + method_name'},
  {tool:'dotnet_metadata_method_index', hint:'valid .NET metadata blob required'},
  {tool:'dotnet_metadata_methods_for_type', hint:'valid .NET metadata blob required + type_index'},
  {tool:'dotnet_metadata_fields_for_type', hint:'valid .NET metadata blob required + type_index'},
  {tool:'dotnet_metadata_type_is_abstract', hint:'valid .NET metadata blob required + type_index'},
  {tool:'dotnet_metadata_type_is_sealed', hint:'valid .NET metadata blob required + type_index'},
  {tool:'decompiler_type_recovery_from_access_size_wp', hint:'wrapper needs bytes argument — check make_input'},
  {tool:'decompiler_type_access_width_sizer_wp', hint:'wrapper needs bytes argument — check make_input'},
  {tool:'hex_pattern_byte_mask_specificity_v3', hint:'missing mask input'},
  {tool:'mem_diff_span_len_v5', hint:'length mismatch between the two byte inputs'},
]

const fix29 = await agent(
  `Fix the 29 remaining TOOL_ERRORs by patching ${CWD}/validation/exercise_v3.py make_input() function so it sends valid inputs to each failing tool.
Failing tools with hints (JSON):
${JSON.stringify(FAILING_29, null, 2).slice(0, 6000)}

Steps:
1. Read ${CWD}/validation/exercise_v3.py to understand the make_input dispatcher.
2. For each tool_name in the list, add or fix a special-case branch that returns valid input.
3. For dotnet_metadata_*, generate a valid minimal .NET metadata blob (COR20 header + tables stream) as a hex string. Look at ${CWD}/crates/rustre-dotnet/ tests for a sample blob.
4. For pe_editor_parse_*, pass a real 512-byte hex-encoded PE prefix (a valid MZ+PE header).
5. For diff_bindiff_hungarian_*, pass a 2x2 identity-like matrix (e.g. [[1.0,0.0],[0.0,1.0]]).
6. For kgdb_read_u64_le_hex, pass exactly 16 hex chars like 'deadbeefcafebabe'.
7. For decompiler_type_recovery_from_access_size_wp / decompiler_type_access_width_sizer_wp, if these belong to the decompiler crate (BANNED — ${BAN_LIST}), fix ONLY the wrapper wire input in ${CWD}/crates/rustre-mcp-tools/src/wire_tools.rs or exercise_v3.py. Do NOT modify the decompiler crate source.
8. After patching, run: cd ${CWD}/validation && python3 exercise_v3.py 2>&1 | grep -E "FINAL|TOOL_ERROR" (Bash timeout 300s).
9. Report the new TOOL_ERROR count.

RULES: never touch decompiler crate source (${BAN_LIST}). Prefer fixing exercise_v3.py inputs; only touch wire_tools.rs if the wrapper is genuinely broken.

Return JSON {tools_targeted:29, tools_fixed:int, tool_error_count_before:29, tool_error_count_after:int, files_changed:[string], remaining_errors:[string], summary:string}.`,
  { label: 'fix-29-errors', agentType: 're-validator', schema: {
    type: 'object',
    properties: {
      tools_targeted: {type:'integer'},
      tools_fixed: {type:'integer'},
      tool_error_count_before: {type:'integer'},
      tool_error_count_after: {type:'integer'},
      files_changed: {type:'array', items:{type:'string'}},
      remaining_errors: {type:'array', items:{type:'string'}},
      summary: {type:'string'},
    },
    required: ['tools_fixed','summary']
  }}
)

// ------- Phase 3: harden all remaining ~1620 loose tools by category -------
phase('HardenRemaining')

// Categories to sweep — the ones with lowest current coverage. Same 79 as round 2 but focus on remainders.
const CATEGORIES = [
  'adb','adf','agent','agent_llm','agent_workflow','analysis','arch','arch_wasm','arm','avr','axr','binary','bpf',
  'callconv','codeview','crypto','db','debug','debug_macos','debug_unicorn','debug_windows','decomp','decompiler','demangle','deobf','diff',
  'disasm','dotnet','dotnet_edit','dotnet_metadata','dwarf','emu','emu_qiling','emu_unicorn','events','events_bus','events_ext',
  'firmware','flirt','flirt_apply','flirt_gen','forensics','forensics_fs','forensics_mem','frida','fuzz','fuzz_afl','fuzz_cov','fuzz_libfuzzer','fuzz_net','fuzz_san',
  'gdb','ghidra','hex','hex_pattern','hex_template','hex_tplx','hex_tply','hex_view','iadl',
  'il','il_lift','il_passes','ios','kg','kgdb','llm','loader','lua','luajit',
  'm68k','malpedia','mem','mhcde','mips','mobile','msp430','net','net_dissect','net_dns','net_pcap','net_proxy','net_rules','noreturn',
  'patch','pe','pe_editor','pe_rebuild','pe_tools','plugin','ppc','project','python','rhai',
  'rlib_dec','rlib_dec2','rustre','rustre_symbols_core','rustre_symbols_ext','rustre_symbols_v3','rustre_vsa','rv',
  'sandbox','sandbox_report','script','script_lua','script_python','script_rhai','smali','sparc','stabs','survey','symb','symb_engine','symb_z3','symbols',
  'symbols_pdb','symbols_v6','symbols_v7','syscalls','sysinternals','threatintel','ti','ti_malpedia','ti_misp','ti_vt',
  'trace','trace_coverage','trace_navigate','trace_pt','triage','triage_die','triage_entropy','ttd','ttd_query','ttd_recorder','ttd_replay','ttd_replayer',
  'vmlift','vsa','vtable','windbg','wire','yara','yara_engine','z80',
]

const harden = await parallel(CATEGORIES.map(cat => () =>
  agent(
    `Harden loose validation for MCP tools matching category "${cat}" in ${CWD}/validation/.
Steps:
1. Read ${CWD}/validation/exercise_v3.py.
2. Read existing ${CWD}/validation/rigorous_${cat}.json / rigorous_${cat}_v2.json / rigorous_${cat}_v3.json if present. Tools already covered = skip.
3. Enumerate all remaining MCP tools with prefix mcp__rustre-mcp__${cat}_* that are NOT yet in a rigorous file.
4. For each remaining tool:
   - Find its Rust implementation via grep in ${CWD}/crates/
   - Write a Python reference computation INLINE
   - Call the tool via subprocess JSON-RPC to ${CWD}/target/release/rustre-mcp.exe
   - Compare with tolerance
   - Record pass/fail in ${CWD}/validation/rigorous_${cat}_v3.json (append if v2 exists, create new if not)
5. Tools that cannot be verified independently (nondeterministic, need network, need special binary): add to ${CWD}/validation/skip_${cat}.json with reason.

RULES: never modify Rust crates. Never touch decompiler crates (${BAN_LIST}). Only write to validation/*.json and validation/*.py.

Return JSON {category:"${cat}", tools_hardened:int, tools_passed:int, tools_failed:int, tools_skipped:int, mismatches:[{tool,expected,actual}], notes:string}.
Time budget: 15 minutes.`,
    { label: `harden:${cat}`, phase: 'HardenRemaining', agentType: 're-validator', schema: {
      type: 'object',
      properties: {
        category: {type:'string'},
        tools_hardened: {type:'integer'},
        tools_passed: {type:'integer'},
        tools_failed: {type:'integer'},
        tools_skipped: {type:'integer'},
        mismatches: {type:'array', items:{type:'object'}},
        notes: {type:'string'},
      },
      required: ['category','tools_hardened']
    }}
  )
))

const totalHardened = harden.filter(Boolean).reduce((s,r)=>s+(r.tools_hardened||0),0)
const totalPassed = harden.filter(Boolean).reduce((s,r)=>s+(r.tools_passed||0),0)
const totalFailedHarden = harden.filter(Boolean).reduce((s,r)=>s+(r.tools_failed||0),0)
const totalSkipped = harden.filter(Boolean).reduce((s,r)=>s+(r.tools_skipped||0),0)

// ------- Phase 4: verify workspace test compiles + passes -------
phase('WorkspaceTests')
const wsTest = await agent(
  `Verify every crate in ${CWD} passes cargo test.
Steps:
1. cd ${CWD} && cargo test --workspace --release --lib --no-fail-fast --no-run --message-format=short  (Bash timeout 900000ms). Parse compile errors per crate.
2. For each crate that fails to compile: read the errors, fix the source. RULES: never delete code, never add #[allow], never panic!/todo!/unimplemented!, NEVER touch decompiler crates (${BAN_LIST}). If a test itself is stale (asserts against old API), update the test.
3. Iterate until 'cargo test --workspace --release --lib --no-fail-fast --no-run' completes with 0 compile errors.
4. Then run cargo test --workspace --release --lib --no-fail-fast (Bash timeout 900000ms). Parse total tests passed/failed across all crates. Report which crates have runtime failures.
5. If any crate has runtime failures, attempt one fix pass per crate — root cause the failure and fix source (same rules).
Return JSON {
  compile_ok:bool,
  compile_errors_per_crate:{},
  fixes_applied:[{crate,files_changed:[string],summary:string}],
  total_tests_passed:int, total_tests_failed:int,
  crates_with_runtime_failures:[string],
  notes:string
}.`,
  { label: 'workspace-tests', phase: 'WorkspaceTests', agentType: 're-validator', schema: {
    type: 'object',
    properties: {
      compile_ok:{type:'boolean'},
      compile_errors_per_crate:{type:'object'},
      fixes_applied:{type:'array', items:{type:'object'}},
      total_tests_passed:{type:'integer'},
      total_tests_failed:{type:'integer'},
      crates_with_runtime_failures:{type:'array', items:{type:'string'}},
      notes:{type:'string'},
    },
    required: ['compile_ok']
  }}
)

// ------- Phase 5: final honest verify -------
phase('FinalHonest')
const final = await agent(
  `HONEST final verify.
1. cd ${CWD} && cargo build --workspace --release  (Bash timeout 900000ms).
2. cd ${CWD}/validation && python3 exercise_v3.py 2>&1 | grep -E "FINAL|TOOL_ERROR" (Bash timeout 300s). Parse the FINAL {OK, TOOL_ERROR, STUB} dict.
3. Enumerate all mcp__rustre-mcp__* tools registered (grep rustre-mcp-server).
4. Union rigorous coverage: for every ${CWD}/validation/rigorous_*.json and rigorous_*_v2.json and rigorous_*_v3.json:
   - Sum tools_hardened (with dedup by module) OR count unique tool names appearing with pass/verified status
5. Sum skip counts from skip_*.json.
6. Report:
{
  total_tools: int,
  ok: int,
  tool_errors: int,
  stubs: int,
  rigorous_hardened_union: int,
  rigorous_pct: number,
  skip_count: int,
  workspace_build_ok: bool,
  verdict: string
}`,
  { label: 'final-honest-v2', agentType: 're-validator', schema: {
    type: 'object',
    properties: {
      total_tools: {type:'integer'},
      ok: {type:'integer'},
      tool_errors: {type:'integer'},
      stubs: {type:'integer'},
      rigorous_hardened_union: {type:'integer'},
      rigorous_pct: {type:'number'},
      skip_count: {type:'integer'},
      workspace_build_ok: {type:'boolean'},
      verdict: {type:'string'},
    },
    required: ['verdict']
  }}
)

return {
  status: 'round5-complete',
  build,
  fix29,
  harden_totals: { totalHardened, totalPassed, totalFailedHarden, totalSkipped },
  ws_test: wsTest,
  final,
}
