export const meta = {
  name: 'round3-fix-all-259-tool-errors',
  description: 'Fix the 259 remaining TOOL_ERROR one at a time: validator smart defaults + wrapper defensive fixes. Loop until 4130 OK / 0 err / 0 stub / 0 crash.',
  phases: [
    { title: 'Collect', detail: 'exercise_v3.py fresh, extract 259 tool errors with reasons' },
    { title: 'FixByCategory', detail: '~15 parallel agents, one per error category' },
    { title: 'Verify', detail: 'exercise_v3.py again, count remaining errors' },
    { title: 'Loop', detail: 'if any error remains, drop next round' },
  ],
}

const CWD = 'C:/Users/Fra/Desktop/RustRE'
const CRATE = `${CWD}/crates/rustre-mcp-tools`
const BANNED = 'rustre-decompiler, rustre-decompiler-type, rustre-decompiler-ghidra, rustre-rlib-dec, rustre-rlib-dec2'

phase('Collect')
const collect = await agent(
  `Collect current TOOL_ERROR list.
1. taskkill /F /IM rustre-mcp.exe (ignore not found).
2. cd ${CWD}/validation && python3 exercise_v3.py > /tmp/r3_ex.log 2>&1 (Bash timeout 600000ms).
3. Parse FINAL line + Remaining TOOL_ERROR section.
4. For each failing tool: capture tool name, error message (first 300 chars), and infer error category from message: MISSING_PARAM, WRONG_TYPE, UNKNOWN_KIND, INVALID_JSON, INVALID_FORMAT, INTERNAL_ERROR, etc.
5. Group by category and by underlying crate prefix.
6. Save JSON manifest to ${CWD}/validation/tool_errors_r3.json with schema:
   {
     "final_ok": int, "final_error": int, "final_stub": int, "final_total": int,
     "categories": {"CAT": [{"tool": name, "error": msg, "prefix": "..."}]},
     "by_prefix": {"prefix": [tool_name]}
   }
Return JSON {ok:int, error:int, stub:int, category_count:int, top_categories:[{cat,count}], notes:string}.`,
  { label: 'collect', agentType: 're-validator', schema: {
    type: 'object',
    properties: {
      ok:{type:'integer'},
      error:{type:'integer'},
      stub:{type:'integer'},
      category_count:{type:'integer'},
      top_categories:{type:'array', items:{type:'object'}},
      notes:{type:'string'},
    },
    required:['ok','error']
  }}
)

const CATEGORIES_TO_FIX = [
  'MISSING_PARAM', 'WRONG_TYPE', 'UNKNOWN_KIND', 'INVALID_JSON', 'INVALID_FORMAT',
  'INTERNAL_ERROR', 'PARSE_ERROR', 'UNKNOWN_VARIANT', 'EMPTY_INPUT', 'EMPTY_PATTERN',
  'INVALID_PROXY', 'MALFORMED_STATUS', 'MALFORMED_REQUEST', 'DATA_TOO_SHORT', 'MISC'
]

phase('FixByCategory')
const fixes = await parallel(CATEGORIES_TO_FIX.map(cat => () =>
  agent(
    `Fix all TOOL_ERROR entries in category "${cat}" from ${CWD}/validation/tool_errors_r3.json.
For each tool in this category:
1. Read the entry: {tool, error, prefix}.
2. Grep ${CRATE}/src/tools/<prefix>.rs for the tool wrapper.
3. Determine fix:
   - MISSING_PARAM: the tool needs a param the validator isn't sending — either add to exercise_v3.py's TOOL_ARG_OVERRIDES or fix schema to include as required.
   - WRONG_TYPE: validator sends string when array needed, or vice versa — fix validator's default in make_input() or TOOL_ARG_OVERRIDES.
   - UNKNOWN_KIND / UNKNOWN_VARIANT: validator sends empty enum value — find valid enum value in the underlying crate source, use it as default.
   - INVALID_JSON: validator sends non-JSON where JSON expected — set a valid minimal JSON default.
   - EMPTY_PATTERN / EMPTY_INPUT: wrapper crashes on empty input — add defensive guard in wrapper.
   - INTERNAL_ERROR / DATA_TOO_SHORT: wrapper doesn't validate input length — add defensive guard.
   - MISC: analyze case-by-case.
4. Apply the fix in the SMALLEST scope: prefer validator (${CWD}/validation/exercise_v3.py) over Rust wrapper, prefer wrapper over underlying crate.

RULES:
- Never touch decompiler crates (${BANNED}).
- Never delete code, never add #[allow], never panic!/todo!/unimplemented!.
- Never change struct names.
- Always use --release.

After fixing all tools in category, run cargo check --release -p rustre-mcp-tools (Bash timeout 300000ms) to verify.
Return JSON {category:"${cat}", tools_targeted:int, tools_fixed:int, files_changed:[string], summary:string, remaining:[string]}.
Time budget: 20 minutes.`,
    { label: `fix:${cat}`, phase: 'FixByCategory', agentType: 're-validator', schema: {
      type: 'object',
      properties: {
        category:{type:'string'},
        tools_targeted:{type:'integer'},
        tools_fixed:{type:'integer'},
        files_changed:{type:'array', items:{type:'string'}},
        summary:{type:'string'},
        remaining:{type:'array', items:{type:'string'}},
      },
      required:['category','tools_fixed']
    }}
  )
))

const totalFixed = fixes.filter(Boolean).reduce((s,r)=>s+(r.tools_fixed||0),0)

phase('Verify')
const verify = await agent(
  `Verify fixes.
1. cd ${CWD} && cargo build --release -p rustre-mcp -p rustre-mcp-server (Bash timeout 1800000ms).
2. taskkill /F /IM rustre-mcp.exe.
3. cd ${CWD}/validation && python3 exercise_v3.py > /tmp/r3_v.log 2>&1 (Bash timeout 600000ms).
4. Parse FINAL. Baseline before: OK=3712, TOOL_ERROR=259.
5. Report {ok:int, tool_error:int, stub:int, delta_ok:int, delta_err:int, verdict:string}.`,
  { label: 'verify', agentType: 're-validator', schema: {
    type: 'object',
    properties: {
      ok:{type:'integer'},
      tool_error:{type:'integer'},
      stub:{type:'integer'},
      delta_ok:{type:'integer'},
      delta_err:{type:'integer'},
      verdict:{type:'string'},
    },
    required:['verdict']
  }}
)

return { status:'round3-attempt', collect, fixes_count:totalFixed, verify }
