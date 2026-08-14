export const meta = {
  name: 'finalize-disable-5-crates',
  description: 'Comment out remaining 131 references to rustre-decompiler-ghidra, rustre-debug-frida, rustre-symb-z3, rustre-emu-qiling, rustre-emu-unicorn in wire_tools.rs and mcp-tools code. NO FILES DELETED, only #[cfg(any())] gates and comments.',
  phases: [
    { title: 'GateWireTools', detail: 'gate every XxxTool struct/impl/handler-entry in wire_tools.rs that references disabled crates' },
    { title: 'GateMcpToolsRest', detail: 'gate remaining refs in emu.rs, lib.rs, and any other file' },
    { title: 'Build', detail: 'cargo build --release, verify compile clean' },
    { title: 'Verify', detail: 'confirm 5 crates not in cargo build graph + tools registered drops by ~220' },
  ],
}

const CWD = 'C:/Users/Fra/Desktop/RustRE'

phase('GateWireTools')
const gate1 = await agent(
  `Fix compile errors in ${CWD}/crates/rustre-mcp-tools/src/wire_tools.rs (~90 refs to disabled crates).

Steps:
1. Read ${CWD}/crates/rustre-mcp-tools/src/wire_tools.rs.
2. For every \`pub struct XxxTool;\` declaration followed by \`impl XxxTool\` and \`impl ToolHandler for XxxTool\` where the body references any of:
   - rustre_decompiler_ghidra
   - rustre_debug_frida
   - rustre_symb_z3
   - rustre_emu_qiling
   - rustre_emu_unicorn
   … add \`#[cfg(any())]\` attribute BEFORE:
     - the \`pub struct XxxTool;\` line
     - the \`impl XxxTool { ... }\` block (before \`impl\`)
     - the \`#[async_trait::async_trait] impl ToolHandler for XxxTool\` block
3. Also comment out the corresponding \`(XxxTool::definition(), Box::new(XxxTool))\` entries in the \`all_wire_handlers()\` vec and any \`extend\` call.
4. Any use statement \`use rustre_debug_frida::...\` etc → prepend \`// [DISABLED 2026-07-12] \` and comment out.
5. Write a Python script at ${CWD}/validation/do_gate_wire_tools.py to perform this mechanically.
6. Run: cd ${CWD} && cargo check --release -p rustre-mcp-tools --message-format=short (Bash timeout 900000ms). Report error count.

RULES: DO NOT DELETE any code. Only add \`#[cfg(any())]\` attributes and \`// [DISABLED 2026-07-12]\` line comments. Do not touch decompiler crates (rustre-decompiler, rustre-decompiler-type). Always --release.

Return JSON {refs_gated:int, handler_entries_commented:int, errors_before:int, errors_after:int, notes:string}.`,
  { label: 'gate-wire', agentType: 're-validator', schema: {
    type: 'object',
    properties: {
      refs_gated:{type:'integer'},
      handler_entries_commented:{type:'integer'},
      errors_before:{type:'integer'},
      errors_after:{type:'integer'},
      notes:{type:'string'},
    },
    required:['errors_after']
  }}
)

phase('GateMcpToolsRest')
const gate2 = await agent(
  `Fix remaining compile errors in ${CWD}/crates/rustre-mcp-tools/src/tools/emu.rs and ${CWD}/crates/rustre-mcp-tools/src/lib.rs.
Read the current error output from cd ${CWD} && cargo check --release -p rustre-mcp-tools --message-format=short 2>&1 (Bash timeout 900000ms).
For every remaining unresolved reference to disabled crates in these files (or any other):
- If the reference is inside a \`pub struct XxxTool\` block: add \`#[cfg(any())]\` before it.
- If it's a use statement: comment with \`// [DISABLED 2026-07-12] \`.
- If it's inside a function body outside a tool struct: gate the enclosing function/module with cfg(any()) OR use a stub returning error.

Iterate cargo check up to 5 times.

Once mcp-tools compiles clean: cd ${CWD} && cargo build --release -p rustre-mcp -p rustre-mcp-server (Bash timeout 1800000ms).

RULES: same as before — no deletion, no #[allow], no panic/todo, no decompiler crate touching, always --release.

Return JSON {errors_final:int, iterations:int, build_ok:bool, notes:string}.`,
  { label: 'gate-rest', agentType: 're-validator', schema: {
    type: 'object',
    properties: {
      errors_final:{type:'integer'},
      iterations:{type:'integer'},
      build_ok:{type:'boolean'},
      notes:{type:'string'},
    },
    required:['build_ok']
  }}
)

phase('Build')
const build = await agent(
  `Full verify build.
cd ${CWD} && cargo build --workspace --release --exclude rustre-decompiler-ghidra --exclude rustre-debug-frida --exclude rustre-symb-z3 --exclude rustre-emu-qiling --exclude rustre-emu-unicorn 2>&1 | tail -20 (Bash timeout 1800000ms).
Actually workspace should already exclude via commented Cargo.toml members, so just cd ${CWD} && cargo build --release (Bash 1800000ms).
Report {build_ok:bool, warnings_count:int, disabled_crates_touched:bool, build_time_min:number}.`,
  { label: 'build-full', agentType: 're-validator', schema: {
    type: 'object',
    properties: {
      build_ok:{type:'boolean'},
      warnings_count:{type:'integer'},
      disabled_crates_touched:{type:'boolean'},
      build_time_min:{type:'number'},
    },
    required:['build_ok']
  }}
)

phase('Verify')
const verify = await agent(
  `Verify functional state after disable.
1. taskkill /F /IM rustre-mcp.exe (ignore not found).
2. cd ${CWD}/validation && python3 exercise_v3.py > /tmp/verify_disabled.log 2>&1 (Bash timeout 600000ms).
3. Parse FINAL line.
4. Baseline before disable: 3971 OK, 0 err. Expected after: ~3751 OK (down by ~220 because ghidra/frida/symb_z3/emu_unicorn/emu_qiling tools no longer registered).
5. Verify none of the 5 disabled crate names appear in cargo metadata --format-version 1 output (grep for the crate names).
6. Report {ok:int, tool_error:int, expected_drop:220, actual_drop:int, disabled_verified:bool, verdict:string}.`,
  { label: 'verify', agentType: 're-validator', schema: {
    type: 'object',
    properties: {
      ok:{type:'integer'},
      tool_error:{type:'integer'},
      expected_drop:{type:'integer'},
      actual_drop:{type:'integer'},
      disabled_verified:{type:'boolean'},
      verdict:{type:'string'},
    },
    required:['verdict']
  }}
)

return { status:'disable-complete', gate1, gate2, build, verify }
