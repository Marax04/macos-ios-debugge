export const meta = {
  name: 'finish-all-100',
  description: 'Fix 10 mismatches + fix 8 broken crate tests + push rigorous coverage 2900->4130',
  phases: [
    { title: 'FixMismatches', detail: 'analyze 10 real_mismatches, fix Rust or Python' },
    { title: 'FixBrokenCrates', detail: 'fix 8 failing crate test suites' },
    { title: 'HardenRigorous', detail: 'convert ~1200 remaining loose checks to rigorous' },
    { title: 'FullBuildAndTest', detail: 'cargo build + cargo test workspace' },
    { title: 'FinalVerify', detail: 'exercise_v3.py + count remaining' },
    { title: 'Report', detail: 'final counts' },
  ],
}

const CWD = 'C:/Users/Fra/Desktop/RustRE'

// ------------- Phase 1: Fix the 10 real mismatches -------------
phase('FixMismatches')
const mismatchFiles = await agent(
  `List all files matching C:/Users/Fra/Desktop/RustRE/validation/rigorous_*.json. For each file, read it and extract any entry where the Rust MCP output disagrees with Python truth. Return a JSON array of {file, tool_name, rust_output, python_truth, category} for every real mismatch. Return only JSON, no prose.`,
  { label: 'collect-mismatches', schema: {
    type: 'object',
    properties: { mismatches: { type: 'array', items: {
      type: 'object',
      properties: { file: {type:'string'}, tool_name: {type:'string'}, rust_output: {type:'string'}, python_truth: {type:'string'}, category: {type:'string'} },
      required: ['file','tool_name']
    }}},
    required: ['mismatches']
  }, agentType: 're-validator' }
)

const mismatches = (mismatchFiles?.mismatches || []).slice(0, 20)
log(`Collected ${mismatches.length} real mismatches to fix`)

const mismatchFixes = mismatches.length ? await parallel(mismatches.map(m => () =>
  agent(
    `You are fixing a validation mismatch in the RustRE workspace at ${CWD}. Tool: ${m.tool_name}. Rust output: ${m.rust_output}. Python truth: ${m.python_truth}. Category: ${m.category}. Source mismatch file: ${m.file}.
Steps:
1. Find the tool implementation via grep in ${CWD}/crates/rustre-mcp-server/src/ and its underlying crate.
2. Read the Python reference in ${CWD}/validation/ that computed the truth.
3. Determine whether Rust is wrong (fix Rust) or Python truth is wrong (fix Python validator). Rules: never delete code, never add #[allow], never use panic!/todo!.
4. Apply the fix with the Edit tool.
5. Return JSON {tool: string, side_fixed: "rust"|"python", files_changed: [string], summary: string}.`,
    { label: `fix:${m.tool_name}`, phase: 'FixMismatches', agentType: 're-validator', schema: {
      type: 'object',
      properties: { tool:{type:'string'}, side_fixed:{type:'string'}, files_changed:{type:'array',items:{type:'string'}}, summary:{type:'string'} },
      required: ['tool','side_fixed','summary']
    }}
  )
)) : []

const mismatchesFixed = mismatchFixes.filter(Boolean).length

// ------------- Phase 2: Fix 8 broken crate test suites -------------
phase('FixBrokenCrates')
const BROKEN_CRATES = [
  'rustre-agent-llm',
  'rustre-agent-workflow',
  'rustre-dotnet-decompile',
  'rustre-emu-qiling',
  'rustre-script-lua',
  'rustre-script-python',
  'rustre-script-rhai',
  'rustre-yara-engine',
]

const crateFixes = await parallel(BROKEN_CRATES.map(crate => () =>
  agent(
    `Fix all failing tests in crate ${crate} at ${CWD}/crates/${crate}. Steps:
1. cd ${CWD} && cargo test -p ${crate} --release --lib --no-fail-fast  --  --nocapture   (use Bash tool, timeout 300000ms)
2. Read every failure. Identify root cause in the crate source (not the test).
3. Fix the crate source code so tests pass. RULES: never delete code, never add #[allow], never panic!/todo!/unimplemented!, never touch the decompiler crate (rustre-decompiler / rustre-decompiler-*). If a test itself is wrong (asserts against outdated behavior), you may fix the test.
4. Re-run cargo test -p ${crate} --release --lib to confirm.
5. Return JSON {crate, tests_before:{passed:int,failed:int}, tests_after:{passed:int,failed:int}, files_changed:[string], summary:string}.
If a test cannot be fixed after 3 attempts, document why in summary and return with tests_after showing remaining failures.`,
    { label: `fix-crate:${crate}`, phase: 'FixBrokenCrates', agentType: 're-validator', schema: {
      type: 'object',
      properties: {
        crate: {type:'string'},
        tests_before: {type:'object'},
        tests_after: {type:'object'},
        files_changed: {type:'array', items:{type:'string'}},
        summary: {type:'string'},
      },
      required: ['crate','summary']
    }}
  )
))

const cratesFixed = crateFixes.filter(Boolean).filter(r => (r.tests_after?.failed ?? 1) === 0).length

// ------------- Phase 3: Harden remaining loose checks -------------
phase('HardenRigorous')
const HARDEN_CATEGORIES = [
  'analysis','adb','adf','agent','arch','arm','avr','axr','binary','bpf',
  'callconv','codeview','crypto','db','debug','decomp','decompiler','demangle','deobf','diff',
  'disasm','dotnet','dwarf','emu','events','firmware','flirt','forensics','frida','fuzz',
  'gdb','ghidra','hex','iadl','il','ios','kg','kgdb','llm','loader',
  'lua','luajit','m68k','mem','mips','mobile','msp430','net','patch','pe',
  'plugin','ppc','project','python','rhai','rlib','rustre','rv','sandbox','script',
  'smali','sparc','stabs','symb','symbols','syscalls','sysinternals','threatintel','ti','trace',
  'triage','ttd','vmlift','vsa','vtable','windbg','wire','yara','z80',
]

const hardenResults = await parallel(HARDEN_CATEGORIES.map(cat => () =>
  agent(
    `Category: ${cat}. Working dir: ${CWD}/validation.
Task: harden loose validation checks to rigorous ground-truth checks for all MCP tools prefixed with "${cat}_".
Steps:
1. Read ${CWD}/validation/exercise_v3.py to see the current test dispatch pattern.
2. Read ${CWD}/validation/rigorous_${cat}.json if it exists (skip already-rigorous tools).
3. For each MCP tool matching pattern mcp__rustre-mcp__${cat}_* that still uses a loose check (any_valid(), presence-only, no independent ground truth):
   - Find the underlying Rust implementation via grep in ${CWD}/crates/
   - Compute the expected output using a Python reference implementation (write the reference INLINE in the validation file, no shelling to unrelated libs)
   - Call the MCP tool via subprocess with json-rpc-over-stdio (see how exercise_v3.py already does it) — do NOT invent a new mechanism
   - Compare byte-for-byte / value-for-value with tolerance appropriate to the type
   - Record pass/fail in a new file ${CWD}/validation/rigorous_${cat}_v2.json
4. If a tool cannot be independently verified (nondeterministic, requires network, etc.), record it as SKIP with reason in ${CWD}/validation/skip_${cat}.json — do NOT count it as passed.
5. Return JSON {category:"${cat}", tools_hardened:int, tools_passed:int, tools_failed:int, tools_skipped:int, mismatches:[{tool,expected,actual}]}.
RULES: never modify Rust crates from this phase (that is done in FixMismatches). Only add Python validation. Do not use panic/todo. Time budget: 15 min max — if a tool takes too long, mark it SKIP.`,
    { label: `harden:${cat}`, phase: 'HardenRigorous', agentType: 're-validator', schema: {
      type: 'object',
      properties: {
        category:{type:'string'},
        tools_hardened:{type:'integer'},
        tools_passed:{type:'integer'},
        tools_failed:{type:'integer'},
        tools_skipped:{type:'integer'},
        mismatches:{type:'array', items:{type:'object'}},
      },
      required:['category','tools_hardened']
    }}
  )
))

const totalHardened = hardenResults.filter(Boolean).reduce((s,r)=>s+(r.tools_hardened||0),0)
const totalPassed = hardenResults.filter(Boolean).reduce((s,r)=>s+(r.tools_passed||0),0)
const totalFailedRigor = hardenResults.filter(Boolean).reduce((s,r)=>s+(r.tools_failed||0),0)
const allNewMismatches = hardenResults.filter(Boolean).flatMap(r => r.mismatches||[])

// ------------- Phase 3b: Fix the newly-found mismatches -------------
phase('FixMismatches')
const round2Fixes = allNewMismatches.slice(0, 40).length ? await parallel(allNewMismatches.slice(0, 40).map((m,i) => () =>
  agent(
    `Fix MCP tool mismatch found in round 2 rigorous check. Tool: ${m.tool || 'unknown'}. Expected: ${JSON.stringify(m.expected).slice(0,500)}. Actual: ${JSON.stringify(m.actual).slice(0,500)}.
Steps:
1. Grep ${CWD}/crates/ for the tool definition.
2. Identify root cause (Rust bug vs bad test truth).
3. Fix Rust code (never delete, never #[allow], never touch decompiler crate) OR fix the Python truth if it was wrong.
4. Return JSON {tool, side_fixed:"rust"|"python", files_changed:[string], summary:string, verified_now:bool}.`,
    { label: `round2-fix:${i}`, phase: 'FixMismatches', agentType: 're-validator', schema: {
      type: 'object',
      properties: { tool:{type:'string'}, side_fixed:{type:'string'}, files_changed:{type:'array',items:{type:'string'}}, summary:{type:'string'}, verified_now:{type:'boolean'} },
      required: ['tool','summary']
    }}
  )
)) : []

const round2Fixed = round2Fixes.filter(Boolean).filter(r => r.verified_now).length

// ------------- Phase 4: Full build + workspace test -------------
phase('FullBuildAndTest')
const buildResult = await agent(
  `Run cargo build --workspace --release from ${CWD} using Bash tool with timeout 600000ms. Then run cargo test --workspace --release --lib --no-fail-fast with timeout 600000ms. Parse the output carefully. Return JSON {build_ok:bool, build_errors:int, build_warnings:int, tests_passed:int, tests_failed:int, crates_with_failures:[string], notes:string}. Parse the "test result: ok. X passed; Y failed" lines from cargo output — count them all, do not report 0 unless truly 0.`,
  { label: 'workspace-build-test', phase: 'FullBuildAndTest', agentType: 're-validator', schema: {
    type: 'object',
    properties: {
      build_ok:{type:'boolean'},
      build_errors:{type:'integer'},
      build_warnings:{type:'integer'},
      tests_passed:{type:'integer'},
      tests_failed:{type:'integer'},
      crates_with_failures:{type:'array', items:{type:'string'}},
      notes:{type:'string'},
    },
    required: ['build_ok']
  }}
)

// ------------- Phase 5: Final verify (exercise_v3.py) -------------
phase('FinalVerify')
const finalVerify = await agent(
  `Run ${CWD}/validation/exercise_v3.py against the freshly built MCP server binary. Count total tools exercised, TOOL_ERROR count, STUB count, mismatch count. Also read all rigorous_*.json and rigorous_*_v2.json files to compute the total number of tools with rigorous ground-truth coverage. Return JSON {total_tools_run:int, tool_errors:int, stubs:int, mismatches:int, rigorous_coverage:int, rigorous_pct:number, remaining_loose:int}.`,
  { label: 'final-verify', phase: 'FinalVerify', agentType: 're-validator', schema: {
    type: 'object',
    properties: {
      total_tools_run:{type:'integer'},
      tool_errors:{type:'integer'},
      stubs:{type:'integer'},
      mismatches:{type:'integer'},
      rigorous_coverage:{type:'integer'},
      rigorous_pct:{type:'number'},
      remaining_loose:{type:'integer'},
    },
    required: ['total_tools_run']
  }}
)

// ------------- Report -------------
phase('Report')
return {
  status: 'complete',
  mismatches_round1_fixed: mismatchesFixed,
  broken_crates_fixed: cratesFixed,
  crate_details: crateFixes.filter(Boolean).map(r => ({crate: r.crate, after: r.tests_after, summary: r.summary})),
  rigorous_hardened_round2: totalHardened,
  rigorous_passed_round2: totalPassed,
  rigorous_failed_round2: totalFailedRigor,
  mismatches_round2_found: allNewMismatches.length,
  mismatches_round2_fixed: round2Fixed,
  build: buildResult,
  final: finalVerify,
}
