export const meta = {
  name: 'round5b-finish',
  description: 'Complete round5: workspace tests + honest final verify. Skips HardenRemaining (already done, 3634 hardened).',
  phases: [
    { title: 'WorkspaceTests', detail: 'cargo test --workspace --release; fix any breaks' },
    { title: 'FinalHonest', detail: 'union rigorous count + fresh exercise + workspace test' },
  ],
}

const CWD = 'C:/Users/Fra/Desktop/RustRE'
const BANNED = ['rustre-decompiler', 'rustre-decompiler-type', 'rustre-decompiler-ghidra', 'rustre-rlib-dec', 'rustre-rlib-dec2']
const BAN_LIST = BANNED.join(', ')

phase('WorkspaceTests')
const wsTest = await agent(
  `Verify every crate in ${CWD} passes cargo test in RELEASE mode.
Steps:
1. cd ${CWD} && cargo test --workspace --release --lib --no-fail-fast --no-run --message-format=short  (Bash timeout 900000ms). Parse compile errors per crate.
2. For each crate that fails to compile in test-mode: read errors, fix source. RULES: never delete code, never add #[allow], never panic!/todo!/unimplemented!, NEVER touch decompiler crates (${BAN_LIST}). If a test itself is stale (asserts against old API), update the test.
3. Iterate until 'cargo test --workspace --release --lib --no-fail-fast --no-run' completes with 0 compile errors.
4. Then cargo test --workspace --release --lib --no-fail-fast (Bash timeout 900000ms). Parse "test result: ok. X passed; Y failed" across ALL crates. Sum totals honestly. Do NOT report 0 unless truly 0.
5. Attempt one fix pass per crate with runtime failures — root cause + fix (same rules).

CRITICAL: always use --release flag. Never use debug build.

Return JSON {
  compile_ok:bool,
  compile_errors_per_crate:{},
  fixes_applied:[{crate,files_changed:[string],summary:string}],
  total_tests_passed:int, total_tests_failed:int,
  crates_with_runtime_failures:[string],
  notes:string
}.`,
  { label: 'workspace-tests-final', phase: 'WorkspaceTests', agentType: 're-validator', schema: {
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

phase('FinalHonest')
const final = await agent(
  `HONEST final verify.
1. Verify ${CWD}/target/release/rustre-mcp.exe is fresh (mtime today). If not, cd ${CWD} && cargo build --release -p rustre-mcp -p rustre-mcp-server (Bash timeout 900000ms).
2. cd ${CWD}/validation && python3 exercise_v3.py 2>&1 | grep -E "FINAL|TOOL_ERROR" (Bash timeout 600s). Parse the FINAL {OK, TOOL_ERROR, STUB} dict.
3. Enumerate all mcp__rustre-mcp__* tools registered (grep ${CWD}/crates/rustre-mcp-server/src/lib.rs for tool_list! or similar).
4. Union rigorous coverage: for every ${CWD}/validation/rigorous_*.json and rigorous_*_v2.json and rigorous_*_v3.json:
   - Sum tools_hardened (dedup by module) OR count unique tool names with pass/verified status
5. Sum skip counts from ${CWD}/validation/skip_*.json.
6. Report:
{
  total_tools_registered: int,
  total_tools_exercised: int,
  ok: int,
  tool_errors: int,
  stubs: int,
  rigorous_hardened_union: int,
  rigorous_pct: number,
  skip_count: int,
  workspace_build_ok: bool,
  workspace_tests_passed: int,
  workspace_tests_failed: int,
  verdict: string
}
Cite the file paths and counts you added up.`,
  { label: 'final-honest-round5b', phase: 'FinalHonest', agentType: 're-validator', schema: {
    type: 'object',
    properties: {
      total_tools_registered: {type:'integer'},
      total_tools_exercised: {type:'integer'},
      ok: {type:'integer'},
      tool_errors: {type:'integer'},
      stubs: {type:'integer'},
      rigorous_hardened_union: {type:'integer'},
      rigorous_pct: {type:'number'},
      skip_count: {type:'integer'},
      workspace_build_ok: {type:'boolean'},
      workspace_tests_passed: {type:'integer'},
      workspace_tests_failed: {type:'integer'},
      verdict: {type:'string'},
    },
    required: ['verdict']
  }}
)

return { status: 'round5b-complete', ws_test: wsTest, final }
