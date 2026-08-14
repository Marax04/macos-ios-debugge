export const meta = {
  name: 'round4-fix-persistent-errors',
  description: 'Rebuild MCP + fix 564 persistent tool_errors + 2 broken crates + 101 mismatches. DECOMPILER UNTOUCHED.',
  phases: [
    { title: 'RebuildMcp', detail: 'cargo build --workspace --release fresh binary' },
    { title: 'FixNewBroken', detail: 'fix rustre-flirt-apply + rustre-forensics-plugins compile in test-mode' },
    { title: 'CollectPersistent', detail: 'exercise_v3.py against FRESH binary, collect real remaining tool_errors' },
    { title: 'FixToolErrors', detail: 'fix persistent tool_errors grouped by crate (NO decompiler)' },
    { title: 'FixMismatches', detail: 'fix 101 remaining mismatches' },
    { title: 'FinalVerifyHonest', detail: 'union of all rigorous_*.json files + fresh exercise + workspace test' },
  ],
}

const CWD = 'C:/Users/Fra/Desktop/RustRE'
const DECOMP_CRATES_BANNED = ['rustre-decompiler', 'rustre-decompiler-type', 'rustre-decompiler-ghidra', 'rustre-rlib-dec', 'rustre-rlib-dec2']
const BANNED_LIST = DECOMP_CRATES_BANNED.join(', ')

// ---------- Phase 1: rebuild MCP binary FIRST ----------
phase('RebuildMcp')
const rebuild = await agent(
  `Rebuild the MCP server binary at ${CWD}. Steps:
1. cd ${CWD} && cargo build --workspace --release   (Bash tool, timeout 900000ms)
2. Verify ${CWD}/target/release/rustre-mcp.exe exists and mtime is fresh (< 10 min old).
3. Report build errors, warnings, and binary mtime.
Return JSON {build_ok:bool, errors:int, warnings:int, binary_path:string, binary_mtime:string, notes:string}.`,
  { label: 'rebuild-mcp', agentType: 're-validator', schema: {
    type: 'object',
    properties: {
      build_ok: {type:'boolean'},
      errors: {type:'integer'},
      warnings: {type:'integer'},
      binary_path: {type:'string'},
      binary_mtime: {type:'string'},
      notes: {type:'string'},
    },
    required: ['build_ok']
  }}
)

// ---------- Phase 2: fix 2 new broken crates ----------
phase('FixNewBroken')
const NEW_BROKEN = ['rustre-flirt-apply', 'rustre-forensics-plugins']
const newBrokenFixes = await parallel(NEW_BROKEN.map(crate => () =>
  agent(
    `Fix compile / test errors in ${crate} at ${CWD}/crates/${crate}.
Steps:
1. cd ${CWD} && cargo test -p ${crate} --release --lib --no-run --message-format=short  (Bash, timeout 300000ms)
2. Read every compile error, fix the source, iterate.
3. Then cargo test -p ${crate} --release --lib to run and count.
RULES: never delete code, never add #[allow], never panic!/todo!/unimplemented!, NEVER touch decompiler crates (${BANNED_LIST}).
Return JSON {crate, compile_ok, tests_passed, tests_failed, files_changed:[string], summary}.`,
    { label: `fix-broken:${crate}`, phase: 'FixNewBroken', agentType: 're-validator', schema: {
      type: 'object',
      properties: {
        crate: {type:'string'},
        compile_ok: {type:'boolean'},
        tests_passed: {type:'integer'},
        tests_failed: {type:'integer'},
        files_changed: {type:'array', items:{type:'string'}},
        summary: {type:'string'},
      },
      required: ['crate','summary']
    }}
  )
))

// ---------- Phase 3: collect REAL persistent tool_errors ----------
phase('CollectPersistent')
const collect = await agent(
  `Run ${CWD}/validation/exercise_v3.py against the FRESHLY BUILT MCP binary (${CWD}/target/release/rustre-mcp.exe). Use Bash with timeout 900000ms.
Parse output. Collect every tool with TOOL_ERROR, capturing tool_name, error_message (first 400 chars), and inferred crate.
ALSO: read every ${CWD}/validation/rigorous_*.json and rigorous_*_v2.json and collect entries where verified=false or status=MISMATCH.
Return JSON {
  total_run: int,
  tool_errors: [{tool, error, crate}] (max 700),
  mismatches: [{tool, expected, actual, file}] (max 200),
  stubs: int,
  fresh_binary_mtime: string
}.`,
  { label: 'collect-persistent', agentType: 're-validator', schema: {
    type: 'object',
    properties: {
      total_run: {type:'integer'},
      tool_errors: {type:'array', items:{type:'object'}},
      mismatches: {type:'array', items:{type:'object'}},
      stubs: {type:'integer'},
      fresh_binary_mtime: {type:'string'},
    },
    required: ['total_run']
  }}
)

const toolErrors = collect?.tool_errors || []
const mismatches = collect?.mismatches || []

const errorsByCrate = {}
for (const te of toolErrors) {
  if (DECOMP_CRATES_BANNED.some(b => (te.crate||'').includes(b))) continue
  const crate = te.crate || 'unknown'
  ;(errorsByCrate[crate] ||= []).push(te)
}
const crateGroups = Object.entries(errorsByCrate).map(([crate, errs]) => ({crate, errs}))
log(`Persistent: ${toolErrors.length} tool_errors → ${crateGroups.length} crate groups (decompiler crates excluded)`)

// ---------- Phase 4: fix persistent tool_errors per crate ----------
phase('FixToolErrors')
const toolFixes = crateGroups.length ? await parallel(crateGroups.map(g => () =>
  agent(
    `Fix persistent MCP tool_errors in crate ${g.crate}. ${g.errs.length} tools return TOOL_ERROR at runtime after round 3 supposedly fixed them — this means the previous fix was wrong or in the wrong place.
Sample failing tools (first 20):
${JSON.stringify(g.errs.slice(0, 20)).slice(0, 4500)}

All failing tool names: ${g.errs.map(e => e.tool).join(', ').slice(0, 8000)}

CRITICAL: Do the fix END-TO-END. Steps:
1. Grep ${CWD}/crates/rustre-mcp-server/src/ for the wrapper of each failing tool. Read it.
2. Grep ${CWD}/crates/${g.crate}/src/ for the underlying implementation. Read it.
3. Reproduce the failure with a manual test: build a small Python script or Bash sequence that calls the tool via JSON-RPC to the fresh binary at ${CWD}/target/release/rustre-mcp.exe. Confirm you get the same error.
4. Identify the ACTUAL root cause. Distinguish between:
   - wrapper bug (missing default in tools/lib.rs)
   - schema mismatch (input JSON schema wrong)
   - crate bug (panic on empty input, unwrap on None, wrong output type)
   - validator test-side bug (exercise_v3.py sends bad input) — if this, fix the exercise_v3.py test-input generator
5. Apply the fix in the correct place. RULES: never delete code, never add #[allow], never panic!/todo!/unimplemented!, NEVER touch decompiler crates (${BANNED_LIST}). If ${g.crate} is a decompiler crate, ONLY fix the mcp-server wrapper or exercise_v3.py, never the crate itself.
6. cargo check -p ${g.crate} --release   AND   cargo check -p rustre-mcp-server --release
7. Verify with the manual JSON-RPC test that the tool now succeeds.
8. Return JSON {crate:"${g.crate}", tools_targeted:${g.errs.length}, tools_fixed_and_verified:int, files_changed:[string], root_causes:[string] (unique categories), summary, remaining:[string]}.
Time budget: 20 minutes. If stuck on a specific tool, skip it and continue.`,
    { label: `fix-tools:${g.crate}`, phase: 'FixToolErrors', agentType: 're-validator', schema: {
      type: 'object',
      properties: {
        crate: {type:'string'},
        tools_targeted: {type:'integer'},
        tools_fixed_and_verified: {type:'integer'},
        files_changed: {type:'array', items:{type:'string'}},
        root_causes: {type:'array', items:{type:'string'}},
        summary: {type:'string'},
        remaining: {type:'array', items:{type:'string'}},
      },
      required: ['crate','tools_fixed_and_verified','summary']
    }}
  )
)) : []

const totalToolsFixed = toolFixes.filter(Boolean).reduce((s,r)=>s+(r.tools_fixed_and_verified||0),0)

// ---------- Phase 5: fix remaining mismatches ----------
phase('FixMismatches')
const mFixes = mismatches.length ? await parallel(mismatches.slice(0, 120).map((m, i) => () =>
  agent(
    `Fix MCP mismatch. Tool: ${m.tool}. Expected: ${JSON.stringify(m.expected).slice(0,400)}. Actual: ${JSON.stringify(m.actual).slice(0,400)}. File: ${m.file || 'unknown'}.
Steps:
1. Grep for the tool. Read mcp-server wrapper AND underlying implementation AND Python truth in validation/.
2. Determine which side is wrong.
3. Fix. RULES: never delete, never #[allow], never panic!/todo!/unimplemented!, NEVER touch decompiler crates (${BANNED_LIST}).
4. Verify with a manual JSON-RPC call to ${CWD}/target/release/rustre-mcp.exe.
5. Return JSON {tool, side_fixed:"rust"|"python", files_changed:[string], summary, verified:bool}.`,
    { label: `mismatch:${i}:${m.tool||'?'}`, phase: 'FixMismatches', agentType: 're-validator', schema: {
      type: 'object',
      properties: {
        tool: {type:'string'},
        side_fixed: {type:'string'},
        files_changed: {type:'array', items:{type:'string'}},
        summary: {type:'string'},
        verified: {type:'boolean'},
      },
      required: ['tool','summary']
    }}
  )
)) : []

const mismatchesVerified = mFixes.filter(Boolean).filter(r => r.verified).length

// ---------- Phase 6: HONEST final verify ----------
phase('FinalVerifyHonest')
const finalVerify = await agent(
  `HONEST final verify. Steps:
1. Rebuild MCP: cd ${CWD} && cargo build --workspace --release   (Bash timeout 900000ms). REQUIRED — do not skip.
2. Run ${CWD}/validation/exercise_v3.py against fresh binary. Get {total_tools, tool_errors, stubs, mismatches}.
3. Enumerate the FULL set of registered mcp__rustre-mcp__* tools (grep rustre-mcp-server for tool_list! or registrations).
4. Compute rigorous coverage UNION: read every rigorous_*.json AND rigorous_*_v2.json AND rigorous_*_v3.json in ${CWD}/validation/. Union all tools with status pass/verified/OK. Show your work (list files read + tool count contributed).
5. Read every skip_*.json for SKIP count.
6. cargo test --workspace --release --lib --no-fail-fast (Bash timeout 900000ms). Parse "test result: ok. X passed; Y failed" lines. Sum across ALL crates. Do NOT report 0 unless truly 0.
Return JSON {
  binary_rebuilt: bool,
  total_tools_registered: int,
  total_tools_exercised: int,
  tool_errors_current: int,
  stubs_current: int,
  mismatches_current: int,
  rigorous_covered_union: int,
  rigorous_pct: number,
  skip_count: int,
  workspace_test: {crates_passed:int, crates_failed:int, tests_passed:int, tests_failed:int, failed_crates:[string]},
  gap_to_full_rigorous: int,
  verdict: string
}.`,
  { label: 'honest-final', agentType: 're-validator', schema: {
    type: 'object',
    properties: {
      binary_rebuilt: {type:'boolean'},
      total_tools_registered: {type:'integer'},
      total_tools_exercised: {type:'integer'},
      tool_errors_current: {type:'integer'},
      stubs_current: {type:'integer'},
      mismatches_current: {type:'integer'},
      rigorous_covered_union: {type:'integer'},
      rigorous_pct: {type:'number'},
      skip_count: {type:'integer'},
      workspace_test: {type:'object'},
      gap_to_full_rigorous: {type:'integer'},
      verdict: {type:'string'},
    },
    required: ['verdict']
  }}
)

return {
  status: 'round4-complete',
  rebuild,
  new_broken_fixed: newBrokenFixes.filter(Boolean).filter(r=>r.compile_ok).length,
  new_broken_details: newBrokenFixes.filter(Boolean),
  persistent_errors_collected: toolErrors.length,
  tool_errors_fixed_and_verified: totalToolsFixed,
  tool_fixes_by_crate: toolFixes.filter(Boolean).map(r => ({crate:r.crate, fixed:r.tools_fixed_and_verified, remaining:(r.remaining||[]).length})),
  mismatches_verified: mismatchesVerified,
  final_honest: finalVerify,
}
