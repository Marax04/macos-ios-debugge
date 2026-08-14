export const meta = {
  name: 'phase2-disable-8-debuggers-and-absorb-codeview',
  description: 'Disable 8 rustre-debug-* backend crates (keep rustre-debug core). Absorb rustre-symbols-codeview into rustre-debug/src/codeview/. Then audit rustre-debug custom debugger state.',
  phases: [
    { title: 'DisableBackends', detail: 'comment out 8 debug backend crates + gate refs in wire_tools.rs / tools/*.rs' },
    { title: 'AbsorbCodeview', detail: 'move rustre-symbols-codeview src into rustre-debug/src/codeview/ and update consumers' },
    { title: 'Build', detail: 'cargo build --workspace --release, iterate fix' },
    { title: 'Verify', detail: 'exercise_v3.py — expected drop of ~300-500 tools' },
  ],
}

const CWD = 'C:/Users/Fra/Desktop/RustRE'
const BACKENDS = [
  'rustre-debug-gdb','rustre-debug-kgdb','rustre-debug-linux','rustre-debug-macos',
  'rustre-debug-registry','rustre-debug-unicorn','rustre-debug-windbg','rustre-debug-windows'
]

phase('DisableBackends')
const disable = await agent(
  `Disable 8 rustre-debug backend crates. KEEP rustre-debug (core trait crate) fully working.
Crates to disable: ${BACKENDS.join(', ')}.

For EACH of these crates, apply the same pattern used for rustre-decompiler-ghidra / rustre-debug-frida / rustre-symb-z3 / rustre-emu-qiling / rustre-emu-unicorn:

1. Comment out its line in ${CWD}/Cargo.toml (workspace members list). Add [DISABLED 2026-07-12] rationale comment.
2. Comment out its dep line in ${CWD}/crates/rustre-mcp-tools/Cargo.toml (some may not be referenced there — skip if absent).
3. Comment out its dep line in ${CWD}/crates/rustre-debug-registry/Cargo.toml (if rustre-debug-registry is being disabled, that's fine — just make sure other crates don't depend on it).
4. Comment out any \`pub mod <name>;\` in ${CWD}/crates/rustre-mcp-tools/src/tools/mod.rs. Common names: debug_windbg, debug_macos, debug_windows, debug_unicorn.
5. Comment out any \`all.extend(crate::tools::<name>::handlers());\` in ${CWD}/crates/rustre-mcp-tools/src/wire_tools.rs.
6. Gate every \`pub struct XxxTool;\` + its impl blocks with \`#[cfg(any())]\` in wire_tools.rs and tools/*.rs where the body references any of these 8 disabled crates.
7. Prepend a top-of-file "MODULE DISABLED 2026-07-12" doc-comment header to each disabled crate's src/lib.rs explaining rationale (user wants custom debugger only; these 8 platform backends will be replaced by rustre-debug internal modules).

CRITICAL: preserve rustre-debug itself — that IS the user's custom debugger core. Do NOT touch:
- crates/rustre-debug/**
- crates/rustre-decompiler/**
- crates/rustre-decompiler-type/**
- crates/rustre-decompiler-ghidra/** (already disabled)
- crates/rustre-rlib-dec/**, crates/rustre-rlib-dec2/**

Write a Python script at ${CWD}/validation/do_phase2_disable.py to do all this mechanically.

After edits: cd ${CWD} && cargo check --release -p rustre-mcp-tools --message-format=short (Bash timeout 900000ms). Iterate fixes up to 8 times until 0 errors.

Return JSON {crates_disabled:int, files_modified:int, tools_gated:int, cargo_check_ok:bool, errors_final:int, notes:string}.`,
  { label: 'disable-8', agentType: 're-validator', schema: {
    type: 'object',
    properties: {
      crates_disabled:{type:'integer'},
      files_modified:{type:'integer'},
      tools_gated:{type:'integer'},
      cargo_check_ok:{type:'boolean'},
      errors_final:{type:'integer'},
      notes:{type:'string'},
    },
    required:['cargo_check_ok']
  }}
)

phase('AbsorbCodeview')
const absorb = await agent(
  `Absorb rustre-symbols-codeview into rustre-debug as a sub-module.

Goal: rustre-debug will have codeview parsing built-in so the custom debugger can resolve PDB symbols without a separate crate dependency.

Steps:
1. Read structure of ${CWD}/crates/rustre-symbols-codeview/src/.
2. For each .rs file in there, copy it to ${CWD}/crates/rustre-debug/src/codeview/ (create dir first).
3. In ${CWD}/crates/rustre-debug/src/lib.rs, add:
   \`\`\`rust
   /// CodeView / PDB parser (absorbed from former rustre-symbols-codeview crate on 2026-07-12).
   pub mod codeview;
   \`\`\`
4. In the moved files, update any \`use crate::\` that referred to the ex-crate top-level. Add mod entries if the crate had a mod.rs.
5. In ${CWD}/crates/rustre-symbols/src/lib.rs (if it depends on rustre-symbols-codeview) update to use \`rustre_debug::codeview::*\` instead of \`rustre_symbols_codeview::*\`.
6. Update ${CWD}/crates/rustre-symbols/Cargo.toml: remove rustre-symbols-codeview dep, add rustre-debug dep (if not already).
7. Same for ${CWD}/crates/rustre-mcp-tools/src/tools/codeview.rs (if present) and any other consumer — grep for \`rustre_symbols_codeview\` and replace with \`rustre_debug::codeview\`.
8. Comment out \`"crates/rustre-symbols-codeview"\` in ${CWD}/Cargo.toml workspace members with rationale comment.
9. Add [DISABLED — ABSORBED INTO rustre-debug 2026-07-12] header to ${CWD}/crates/rustre-symbols-codeview/src/lib.rs.
10. cd ${CWD} && cargo check --release (Bash timeout 900000ms) — iterate fixes.

RULES: preserve rustre-debug files (only ADD to it). Never touch decompiler crates.

Return JSON {files_moved:int, consumers_updated:int, cargo_check_ok:bool, errors_final:int, notes:string}.`,
  { label: 'absorb-codeview', agentType: 're-validator', schema: {
    type: 'object',
    properties: {
      files_moved:{type:'integer'},
      consumers_updated:{type:'integer'},
      cargo_check_ok:{type:'boolean'},
      errors_final:{type:'integer'},
      notes:{type:'string'},
    },
    required:['cargo_check_ok']
  }}
)

phase('Build')
const build = await agent(
  `Full workspace build.
cd ${CWD} && cargo build --release --workspace > /tmp/phase2_build.log 2>&1 (Bash timeout 1800000ms).
Report {build_ok:bool, warnings:int, build_time_min:number, errors_if_any:[string], notes:string}.`,
  { label: 'build', agentType: 're-validator', schema: {
    type: 'object',
    properties: {
      build_ok:{type:'boolean'},
      warnings:{type:'integer'},
      build_time_min:{type:'number'},
      errors_if_any:{type:'array', items:{type:'string'}},
      notes:{type:'string'},
    },
    required:['build_ok']
  }}
)

phase('Verify')
const verify = await agent(
  `Verify functional state.
1. taskkill /F /IM rustre-mcp.exe.
2. cd ${CWD}/validation && python3 exercise_v3.py > /tmp/phase2_ex.log 2>&1 (Bash timeout 600000ms).
3. Parse FINAL. Baseline before phase 2: 3705 OK, 0 err. Expected after phase 2: ~3200-3500 OK (drop of 200-500 tools for the 8 disabled debug backends + codeview being reachable via rustre-debug now).
4. Verify none of the 8 disabled crate names are in cargo metadata (grep them out).
5. Verify rustre-symbols-codeview is also removed.
6. Report {ok:int, tool_error:int, disabled_crates_verified:bool, expected_drop_range:"200-500", actual_drop:int, verdict:string}.`,
  { label: 'verify', agentType: 're-validator', schema: {
    type: 'object',
    properties: {
      ok:{type:'integer'},
      tool_error:{type:'integer'},
      disabled_crates_verified:{type:'boolean'},
      actual_drop:{type:'integer'},
      verdict:{type:'string'},
    },
    required:['verdict']
  }}
)

return { status:'phase2-complete', disable, absorb, build, verify }
