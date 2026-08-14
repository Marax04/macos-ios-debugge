export const meta = {
  name: 'round2-slim-wire-tools',
  description: 'Slim wire_tools.rs from ~36922 lines → ~500 orchestrator by extracting remaining helpers into src/tools/misc.rs and dedicated sub-modules.',
  phases: [
    { title: 'Analyze', detail: 'catalog what helper items remain in wire_tools.rs' },
    { title: 'Extract', detail: 'move helpers into tools/misc.rs and appropriate sub-modules' },
    { title: 'Build', detail: 'cargo build --release iteratively fix compile errors' },
    { title: 'Verify', detail: 'exercise_v3.py: total should stay 4130, ideally OK >= 3712 still' },
  ],
}

const CWD = 'C:/Users/Fra/Desktop/RustRE'
const CRATE = `${CWD}/crates/rustre-mcp-tools`
const WT = `${CRATE}/src/wire_tools.rs`

phase('Analyze')
const analyze = await agent(
  `Analyze current ${WT} (~36922 lines) to find what remains after Round 1 split.
Steps:
1. wc -l ${WT} and du -h ${WT}. Report.
2. Enumerate every top-level item: pub fn, pub struct, pub trait, pub impl, macros. Categorize:
   - "all_wire_handlers" and "wire_into_server": KEEP in wire_tools.rs (orchestrator)
   - anything named "*_extra_handlers" or "*_wire_handlers": KEEP in wire_tools.rs
   - "WireToolAdapter", "wire_def_to_catalog", "vmlift_parse_semantic_wl": belongs in tools/misc.rs
   - Any leftover "pub struct XxxTool" (should be very few if Round 1 was correct): belongs in tools/misc.rs
   - Any helper function whose name starts with a known crate prefix (analysis_*, ttd_*, emu_*, etc.): belongs in the corresponding tools/<prefix>.rs
3. Produce a Python script at ${CWD}/validation/analyze_wire_leftover.py that outputs ${CWD}/validation/wire_leftover.json with schema:
   {
     "keep_in_wire_tools": [item names],
     "move_to_misc": [item names + their line ranges],
     "move_to_prefix_module": [{item, prefix, line_range}]
   }
4. Return JSON {total_lines_in_wt:int, item_counts:{keep:int, misc:int, per_prefix:int}, notes:string}.

RULES: read-only analysis. Do NOT modify files yet.`,
  { label: 'analyze', agentType: 're-validator', schema: {
    type: 'object',
    properties: {
      total_lines_in_wt:{type:'integer'},
      item_counts:{type:'object'},
      notes:{type:'string'},
    },
    required:['total_lines_in_wt']
  }}
)

phase('Extract')
const extract = await agent(
  `Extract remaining items from ${WT} into ${CRATE}/src/tools/misc.rs (and appropriate prefix modules).
Use the manifest at ${CWD}/validation/wire_leftover.json.

Steps:
1. Create ${CRATE}/src/tools/misc.rs. Copy the "move_to_misc" items verbatim (their line ranges from wire_tools.rs).
2. For "move_to_prefix_module" items, append them to the corresponding ${CRATE}/src/tools/<prefix>.rs.
3. Rewrite ${WT} to keep ONLY:
   - "//! Wire orchestrator ..." header comment
   - use statements (updated as needed)
   - pub fn all_wire_handlers()
   - pub fn wire_into_server()
   - any *_extra_handlers helper functions marked "keep"
4. Add pub mod misc; to ${CRATE}/src/tools/mod.rs.
5. If misc.rs has an XxxTool struct, add its (definition, Box::new) to the tools/misc.rs handlers() fn, and add extend(crate::tools::misc::handlers()) to wire_tools.rs::all_wire_handlers.

Use a Python script at ${CWD}/validation/do_slim_wire_tools.py — mechanical text moves.

RULES:
- Preserve all struct/function bodies verbatim.
- Never touch the decompiler crate.
- Use --release always for cargo commands.

Return JSON {misc_lines:int, wire_tools_lines_after:int, items_moved:int, notes:string}.`,
  { label: 'extract', agentType: 're-validator', schema: {
    type: 'object',
    properties: {
      misc_lines:{type:'integer'},
      wire_tools_lines_after:{type:'integer'},
      items_moved:{type:'integer'},
      notes:{type:'string'},
    },
    required:['wire_tools_lines_after']
  }}
)

phase('Build')
const build = await agent(
  `Build the crate --release and iteratively fix compile errors.
1. cd ${CWD} && cargo build --release -p rustre-mcp-tools --message-format=short 2>&1 (Bash timeout 900000ms). Capture output.
2. Categorize errors and fix (missing use, undefined items now in different module, path adjustments).
3. Iterate up to 8 times.
4. Once mcp-tools builds clean: cd ${CWD} && cargo build --release -p rustre-mcp -p rustre-mcp-server (Bash timeout 1800000ms).
5. Report {compile_ok:bool, iterations:int, errors_final:int, build_time_min:number}.

RULES: never touch decompiler. always --release.`,
  { label: 'build', agentType: 're-validator', schema: {
    type: 'object',
    properties: {
      compile_ok:{type:'boolean'},
      iterations:{type:'integer'},
      errors_final:{type:'integer'},
      build_time_min:{type:'number'},
    },
    required:['compile_ok']
  }}
)

phase('Verify')
const verify = await agent(
  `Verify functional preservation.
1. taskkill /F /IM rustre-mcp.exe (ignore not-found).
2. cd ${CWD}/validation && python3 exercise_v3.py > /tmp/round2_verify.log 2>&1 (Bash timeout 600000ms).
3. Parse FINAL line and count OK, TOOL_ERROR, STUB, SERVER DIED occurrences.
4. Baseline before Round 2: OK=3712, TOOL_ERROR=259.
5. If server dies: capture killer tool name, note for Round 3.
6. Report {ok:int, tool_error:int, stub:int, server_dies:int, wire_tools_lines:int, delta_ok_vs_baseline:int, verdict:string}.`,
  { label: 'verify', agentType: 're-validator', schema: {
    type: 'object',
    properties: {
      ok:{type:'integer'},
      tool_error:{type:'integer'},
      stub:{type:'integer'},
      server_dies:{type:'integer'},
      wire_tools_lines:{type:'integer'},
      delta_ok_vs_baseline:{type:'integer'},
      verdict:{type:'string'},
    },
    required:['verdict']
  }}
)

return { status:'round2-complete', analyze, extract, build, verify }
