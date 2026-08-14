export const meta = {
  name: 'round3-fix-everything',
  description: 'Fix 564 tool_errors + 2 broken test-mode crates + 42 mismatch + 64 rigorous fails + warnings + honest final verify',
  phases: [
    { title: 'CollectErrors', detail: 'run exercise_v3 and collect all 564 tool_error names+traces' },
    { title: 'FixCompileErrors', detail: 'fix rustre-ttd-replayer + rustre-project test-mode compile errors' },
    { title: 'FixToolErrors', detail: 'fix the 564 MCP tool_errors grouped by crate' },
    { title: 'FixMismatches', detail: 'fix 42 round-2 mismatches + 64 rigorous failures' },
    { title: 'FixWarnings', detail: 'fix 8 release warnings in 5 crates' },
    { title: 'FinalVerify', detail: 'honest count of ALL rigorous_*.json + rigorous_*_v2.json + workspace test' },
  ],
}

const CWD = 'C:/Users/Fra/Desktop/RustRE'

// ---------- Phase 1: Collect the actual 564 tool_error list ----------
phase('CollectErrors')
const errorCollection = await agent(
  `Run ${CWD}/validation/exercise_v3.py against the built MCP server. Collect every tool that returned TOOL_ERROR (not just the count). For each, capture: tool_name, error_message (first 300 chars), and the crate it likely belongs to (infer from the tool name prefix — e.g. adb_* -> rustre-adb-utils, analysis_* -> rustre-analysis, etc). Also list the 42 unresolved round-2 mismatches from validation/rigorous_*_v2.json (any entry with mismatch, not the ones already marked fixed) and the 64 rigorous-failed entries.
Return JSON {tool_errors: [{tool, error, crate}], round2_mismatches: [{tool, expected, actual, file}], rigorous_failures: [{tool, expected, actual, category}]}. Cap each array at 700 items.`,
  { label: 'collect-all-failures', agentType: 're-validator', schema: {
    type: 'object',
    properties: {
      tool_errors: { type: 'array', items: { type: 'object' } },
      round2_mismatches: { type: 'array', items: { type: 'object' } },
      rigorous_failures: { type: 'array', items: { type: 'object' } },
    },
    required: ['tool_errors'],
  }}
)

const toolErrors = errorCollection?.tool_errors || []
const round2 = errorCollection?.round2_mismatches || []
const rigorFails = errorCollection?.rigorous_failures || []

log(`Collected ${toolErrors.length} tool_errors, ${round2.length} round-2 mismatches, ${rigorFails.length} rigorous fails`)

// Group tool_errors by inferred crate
const errorsByCrate = {}
for (const te of toolErrors) {
  const crate = te.crate || 'unknown'
  ;(errorsByCrate[crate] ||= []).push(te)
}
const crateGroups = Object.entries(errorsByCrate).map(([crate, errs]) => ({crate, errs}))
log(`Grouped into ${crateGroups.length} crates`)

// ---------- Phase 2: Fix compile errors in test-mode-broken crates (parallel) ----------
phase('FixCompileErrors')
const COMPILE_BROKEN = ['rustre-ttd-replayer', 'rustre-project']
const compileFixes = await parallel(COMPILE_BROKEN.map(crate => () =>
  agent(
    `The crate ${crate} at ${CWD}/crates/${crate} builds in release mode but FAILS TO COMPILE in test mode (cargo test -p ${crate} --release --lib). Fix every compile error. Use Bash to run cargo test -p ${crate} --release --lib --no-run --message-format=short with timeout 300000ms to see errors. Read each broken file, apply fixes, iterate until 'cargo test -p ${crate} --release --lib --no-run' completes without error. Then run 'cargo test -p ${crate} --release --lib' and report test counts.
RULES: never delete non-test code, never add #[allow], never use panic!/todo!/unimplemented!, never touch decompiler crates.
Return JSON {crate, compile_ok:bool, tests_passed:int, tests_failed:int, files_changed:[string], summary:string}.`,
    { label: `compile-fix:${crate}`, phase: 'FixCompileErrors', agentType: 're-validator', schema: {
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

const compileFixed = compileFixes.filter(Boolean).filter(r => r.compile_ok).length

// ---------- Phase 3: Fix the 564 tool_errors by crate group ----------
phase('FixToolErrors')
const toolFixes = crateGroups.length ? await parallel(crateGroups.map(g => () =>
  agent(
    `Fix MCP tool errors in crate ${g.crate}. There are ${g.errs.length} tools returning TOOL_ERROR at runtime. Sample of failing tools + errors (JSON, first 20 shown):
${JSON.stringify(g.errs.slice(0, 20)).slice(0, 4000)}

Full list of failing tool names: ${g.errs.map(e => e.tool).join(', ').slice(0, 8000)}

Steps:
1. Grep ${CWD}/crates/rustre-mcp-server/src/ for the wrapper of each failing tool.
2. Grep ${CWD}/crates/${g.crate || 'rustre-*'}/src/ for the underlying implementation.
3. Identify the root cause of the runtime error. Common causes: wrong JSON schema, missing required field default, uninitialized state, wrong path handling, panic on empty input, unwrap on Option that can be None.
4. Fix the Rust source code. RULES: never delete code, never add #[allow], never use panic!/todo!/unimplemented!, never touch the decompiler crate.
5. After each fix, do NOT rerun the full MCP server (too slow) — just cargo check -p ${g.crate} --release with timeout 120000ms to verify it compiles.
6. Return JSON {crate: "${g.crate}", tools_targeted: ${g.errs.length}, tools_fixed: int, files_changed: [string], summary: string, remaining_failures: [string]}.
Time budget: 20 minutes. If a specific tool is intractable, skip it and continue with the rest.`,
    { label: `fix-tools:${g.crate}`, phase: 'FixToolErrors', agentType: 're-validator', schema: {
      type: 'object',
      properties: {
        crate: {type:'string'},
        tools_targeted: {type:'integer'},
        tools_fixed: {type:'integer'},
        files_changed: {type:'array', items:{type:'string'}},
        summary: {type:'string'},
        remaining_failures: {type:'array', items:{type:'string'}},
      },
      required: ['crate','tools_fixed','summary']
    }}
  )
)) : []

const totalToolsFixed = toolFixes.filter(Boolean).reduce((s,r) => s + (r.tools_fixed||0), 0)

// ---------- Phase 4: Fix the 42+64 mismatches ----------
phase('FixMismatches')
const allMismatches = [...round2, ...rigorFails].slice(0, 120)
const mismatchFixes = allMismatches.length ? await parallel(allMismatches.map((m, i) => () =>
  agent(
    `Fix MCP validation mismatch. Tool: ${m.tool}. Expected (Python truth): ${JSON.stringify(m.expected).slice(0,500)}. Actual (Rust output): ${JSON.stringify(m.actual).slice(0,500)}. Source: ${m.file || m.category || 'unknown'}.
Steps:
1. Grep ${CWD}/crates/ for the tool. Both mcp-server wrapper and underlying implementation.
2. Read ${CWD}/validation/ for the Python truth reference.
3. Determine which side is wrong. If Rust is wrong, fix the Rust source (never delete, never #[allow], never touch decompiler). If Python truth is wrong, fix the validator script.
4. cargo check -p <crate> --release to verify compile.
5. Return JSON {tool, side_fixed:"rust"|"python", files_changed:[string], summary, verified:bool}.`,
    { label: `mismatch-fix:${i}:${m.tool || 'unknown'}`, phase: 'FixMismatches', agentType: 're-validator', schema: {
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

const mismatchesFixed = mismatchFixes.filter(Boolean).filter(r => r.verified).length

// ---------- Phase 5: Fix 8 release warnings ----------
phase('FixWarnings')
const warningFix = await agent(
  `Run cargo build --workspace --release from ${CWD} with timeout 600000ms. Parse the 8 warnings. For each: read the file, understand the warning, FIX BY WIRING CODE IN (never delete, never #[allow], never remove). Dead-code warnings mean untabled functionality — connect it to a real caller. Return JSON {warnings_before:int, warnings_after:int, fixes:[{file, warning, fix_summary}]}.
Crates known to warn: rustre-demangle, rustre-trace-pt, rustre-arch-z80, rustre-hex-view, rustre-mcp-tools.`,
  { label: 'fix-warnings', phase: 'FixWarnings', agentType: 're-validator', schema: {
    type: 'object',
    properties: {
      warnings_before: {type:'integer'},
      warnings_after: {type:'integer'},
      fixes: {type:'array', items:{type:'object'}},
    },
    required: ['warnings_before','warnings_after']
  }}
)

// ---------- Phase 6: Honest final verify ----------
phase('FinalVerify')
const honestVerify = await agent(
  `Compute the HONEST rigorous coverage of RustRE MCP tools.
1. Enumerate every mcp__rustre-mcp__* tool advertised by the built MCP server (grep ${CWD}/crates/rustre-mcp-server/src/lib.rs for registrations, or run the server and call list_tools).
2. Read EVERY file matching ${CWD}/validation/rigorous_*.json AND ${CWD}/validation/rigorous_*_v2.json AND ${CWD}/validation/rigorous_*_v3.json.
3. Union the set of tools that appear with status "pass" / "verified" / "OK" across ALL these files. This is the RIGOROUS SET.
4. Read ${CWD}/validation/skip_*.json to identify SKIP tools (nondeterministic).
5. Now run ${CWD}/validation/exercise_v3.py fresh to get the current TOOL_ERROR count and total exercised count. Timeout 900000ms.
6. Finally, run cargo test --workspace --release --lib --no-fail-fast from ${CWD} timeout 900000ms and parse the actual "test result: ok. X passed; Y failed" lines.
Return JSON {
  total_tools_registered: int,
  total_tools_exercised: int,
  tool_errors_current: int,
  rigorous_covered_union: int,
  rigorous_pct: number,
  skip_count: int,
  workspace_test: {passed:int, failed:int, crates_failed:[string]},
  gap_to_100pct: int
}. Show your work: cite the file paths you read and how many tools each contributed.`,
  { label: 'honest-verify', phase: 'FinalVerify', agentType: 're-validator', schema: {
    type: 'object',
    properties: {
      total_tools_registered: {type:'integer'},
      total_tools_exercised: {type:'integer'},
      tool_errors_current: {type:'integer'},
      rigorous_covered_union: {type:'integer'},
      rigorous_pct: {type:'number'},
      skip_count: {type:'integer'},
      workspace_test: {type:'object'},
      gap_to_100pct: {type:'integer'},
    },
    required: ['total_tools_registered']
  }}
)

return {
  status: 'round3-complete',
  errors_collected: toolErrors.length,
  compile_broken_fixed: compileFixed,
  compile_details: compileFixes.filter(Boolean),
  tool_errors_fixed: totalToolsFixed,
  tool_fixes_by_crate: toolFixes.filter(Boolean).map(r => ({crate: r.crate, fixed: r.tools_fixed, remaining: (r.remaining_failures||[]).length})),
  mismatches_fixed: mismatchesFixed,
  warnings: warningFix,
  final_honest: honestVerify,
}
