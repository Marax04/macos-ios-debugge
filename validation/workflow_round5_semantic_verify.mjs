export const meta = {
  name: 'round5-semantic-deep-verify',
  description: 'Send realistic test data to ~30 tools that return valid error messages, verify they process real data correctly. Distinguish real bugs from validator-weakness. Fix real bugs.',
  phases: [
    { title: 'Categorize', detail: 'read R30v3_full.json, list tools with error-in-body responses, classify' },
    { title: 'ImproveValidator', detail: 'send real WASM, real PE, real Rust symbols, real binary IDs — see how tools respond' },
    { title: 'FixRealBugs', detail: 'for tools that STILL fail with real data, fix real bugs' },
    { title: 'Verify', detail: 'rerun exercise_v3 — expect zero remaining false positives' },
  ],
}

const CWD = 'C:/Users/Fra/Desktop/RustRE'
const BANNED = 'rustre-decompiler, rustre-decompiler-type, rustre-decompiler-ghidra, rustre-rlib-dec, rustre-rlib-dec2'

phase('Categorize')
const cat = await agent(
  `Read ${CWD}/validation/mcp_outputs/R30v3_full.json.
Extract every entry with status=OK where output_excerpt contains "error" (case-insensitive) but is not "success"/"is_ok:true".

Classify each into groups:
- WASM_GARBAGE: arch_wasm_* tools rejecting invalid bytes
- DEMANGLE_INAPPLICABLE: demangle_* tools saying "not a X-mangled name" (expected legit rejection)
- DOTNET_PE_TOO_SMALL: dotnet_edit_* tools rejecting empty PE
- FRIDA_NO_AGENT: debug_frida_* tools reporting no agent injected (expected)
- SEMANTIC_MISMATCH: tools where result is suspicious given the input
- OTHER: everything else

For SEMANTIC_MISMATCH and OTHER, list them tool by tool.
Also check tools with output_excerpt=='[]' or '{}' or 'null' — for each, note if the tool NAME suggests it should return data (e.g. "list_..." or "get_..." should have items).

Write ${CWD}/validation/round5_categorize.json:
{
  "wasm_garbage": [names],
  "demangle_inapplicable": [names],
  "dotnet_pe_too_small": [names],
  "frida_no_agent": [names],
  "semantic_mismatch": [{"tool":..., "reason":...}],
  "other_error_body": [{"tool":..., "reason":...}],
  "empty_result": [{"tool":..., "expected_content":bool}]
}

Return JSON {total_error_in_body:int, wasm_garbage:int, demangle_inapplicable:int, dotnet_pe_too_small:int, frida_no_agent:int, semantic_mismatch:int, other:int, empty_result:int}.`,
  { label: 'categorize', agentType: 're-validator', schema: {
    type: 'object',
    properties: {
      total_error_in_body:{type:'integer'},
      wasm_garbage:{type:'integer'},
      demangle_inapplicable:{type:'integer'},
      dotnet_pe_too_small:{type:'integer'},
      frida_no_agent:{type:'integer'},
      semantic_mismatch:{type:'integer'},
      other:{type:'integer'},
      empty_result:{type:'integer'},
    },
    required:['total_error_in_body']
  }}
)

phase('ImproveValidator')
const improve = await agent(
  `Improve ${CWD}/validation/exercise_v3.py with realistic test data for ~30 tools that currently return legitimate-but-shallow errors.

Read ${CWD}/validation/round5_categorize.json.

Add TOOL_ARG_OVERRIDES for:
1. WASM tools (arch_wasm_*): use a valid minimal WASM module hex: "0061 736d 0100 0000 0100 0402 6001 7f01 7f" (magic + version 1 + type section)
2. DOTNET_EDIT tools: use a minimal PE with CLR header. Skip if too complex; the "PE too small" is legit.
3. DIFF tools (diff.compare, diff.exports): pass a_id="bin-0001" and b_id="bin-0001" (use existing loaded binary twice)
4. DEMANGLE_* tools: use appropriate mangled names per demangler:
   - demangle_rust_v0_wire: "_RINvNtCsbmNqQUJIY6D_4core5sliceINtB6_4Iter3newRSlBH_hEE"
   - demangle_rust_legacy_wire: "_ZN4core3fmt5write17hb52bd1a25d234addE"
   - demangle_cpp_itanium_wire: "_ZN3fooC1Ev"
   - demangle_cpp_msvc_wire: "?foo@@YAHXZ"
5. Any other TOOL where the LEGIT rejection can be avoided with better default input, add override.

After adding overrides:
1. taskkill /F /IM rustre-mcp.exe
2. cd ${CWD}/validation && python3 exercise_v3.py > /tmp/r5_ex.log 2>&1 (Bash timeout 600000ms)
3. Diff results: how many tools moved from error-in-body → clean success? How many still show errors (real bugs)?
4. Save ${CWD}/validation/mcp_outputs/R5_full.json.

Return JSON {overrides_added:int, moved_to_clean:int, still_erroring:int, real_bugs:[tool_name], notes:string}.`,
  { label: 'improve', agentType: 're-validator', schema: {
    type: 'object',
    properties: {
      overrides_added:{type:'integer'},
      moved_to_clean:{type:'integer'},
      still_erroring:{type:'integer'},
      real_bugs:{type:'array', items:{type:'string'}},
      notes:{type:'string'},
    },
    required:['overrides_added']
  }}
)

phase('FixRealBugs')
const fixBugs = await agent(
  `Fix real bugs identified. Read ${CWD}/validation/round5_categorize.json semantic_mismatch and improve.real_bugs.
For each tool that STILL returns invalid results despite realistic input:
1. Grep the tool wrapper in ${CWD}/crates/rustre-mcp-tools/src/tools/<prefix>.rs.
2. Investigate the underlying crate function.
3. Determine if:
   - Wrapper has bug (wrong args passing) — fix wrapper
   - Crate has bug (real code defect) — fix crate (never decompiler crates: ${BANNED})
   - Test data still not right — improve override
4. Rebuild, retest.
5. Return JSON {bugs_investigated:int, bugs_fixed:int, files_changed:[string], notes:string}.

RULES: never touch decompiler crates. Never delete code. Never #[allow]. Never panic/todo. Always --release.`,
  { label: 'fix-bugs', agentType: 're-validator', schema: {
    type: 'object',
    properties: {
      bugs_investigated:{type:'integer'},
      bugs_fixed:{type:'integer'},
      files_changed:{type:'array', items:{type:'string'}},
      notes:{type:'string'},
    },
    required:['bugs_investigated']
  }}
)

phase('Verify')
const verify = await agent(
  `Final semantic verify.
1. cd ${CWD} && cargo build --release -p rustre-mcp -p rustre-mcp-server (Bash timeout 1800000ms).
2. taskkill /F /IM rustre-mcp.exe.
3. cd ${CWD}/validation && python3 exercise_v3.py > /tmp/r5_v.log 2>&1 (Bash timeout 600000ms).
4. Read the fresh JSON output. Count:
   - total OK
   - OK with "error" in body (legit vs suspicious)
   - empty/short suspicious outputs
5. Report {ok:int, tool_error:int, stub:int, error_in_body_count:int, empty_output_count:int, suspicious_count:int, verdict:string}.`,
  { label: 'verify', agentType: 're-validator', schema: {
    type: 'object',
    properties: {
      ok:{type:'integer'},
      tool_error:{type:'integer'},
      stub:{type:'integer'},
      error_in_body_count:{type:'integer'},
      empty_output_count:{type:'integer'},
      suspicious_count:{type:'integer'},
      verdict:{type:'string'},
    },
    required:['verdict']
  }}
)

return { status:'round5-complete', categorize:cat, improve, fix_bugs:fixBugs, verify }
