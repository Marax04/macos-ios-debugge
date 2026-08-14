export const meta = {
  name: 'round5-deepen',
  description: 'Round 5: fix FLIRT chkstk pattern, add HLIL structuring passes, interprocedural VSA hint, fix JUMPOUT emission',
  phases: [
    { title: 'FlirtChkstkFix', detail: 'Correct __chkstk pattern to match actual cargo-zyphora prologue bytes' },
    { title: 'HlilStructuring', detail: 'Run goto→if/else + register→var-lifting passes on HLIL output' },
    { title: 'VsaInterproc', detail: 'Add caller-arg propagation so version-0 SSA regs get value hints' },
    { title: 'FixJumpoutEmit', detail: 'Emit JUMPOUT as valid C (fall-through label or comment)' },
    { title: 'Verify', detail: 'MCP live 8 addresses, count each metric' },
  ],
}

const CWD = 'C:/Users/Fra/Desktop/RustRE'

phase('FlirtChkstkFix')
const flirt = await agent(
  `FLIRT __chkstk pattern is wrong: sig pack has "51 48 8B C4 48 83 E8 10" but 0x1400f1190 in cargo-zyphora.exe starts with "4C 89 14 24 4C 89 5C 24 08" (push r10/r11 storage pattern). Only 1/8 test functions currently get named.

STEPS:
1. Read the first 32 bytes of 0x1400f1190 from ${CWD}/tests/decompiler_corpus or by reopening cargo-zyphora. If not available, disasm the function using disasm_dump.exe.
2. Compare with the real __chkstk source from MSVC 2019 x64 CRT. The typical modern layout: 48 83 EC 10 4C 89 14 24 4C 89 5C 24 08 4D 33 DB 4C 8D 54 24 18 4C 2B D0 ...
3. Update the FLIRT sig for __chkstk in ${CWD}/crates/rustre-flirt-apply/src/lib.rs load_extended_sigs() — use the CORRECT byte prefix with wildcards for immediates, and long enough to be discriminative.
4. Add 3-4 more common Rust CRT thunk patterns from cargo-zyphora that stand out as prologues.
5. cd ${CWD} && cargo build --release -p rustre-flirt-apply -p rustre-decompiler -p rustre-mcp-server -p rustre-mcp 2>&1 | tail -20.
6. Return {chkstk_new_bytes_hex:string, new_sigs_added:int, build_ok:bool, notes:string}`,
  { label: 'flirt-fix', agentType: 're-validator', schema: {
    type: 'object',
    properties: {
      chkstk_new_bytes_hex:{type:'string'},
      new_sigs_added:{type:'integer'},
      build_ok:{type:'boolean'},
      notes:{type:'string'},
    },
    required:['build_ok','notes']
  }}
)

phase('HlilStructuring')
const hlil = await agent(
  `HLIL output is register-level: emits "unknown var_r11" "var_flag_cf" goto/while blocks instead of structured if/else + named vars.

STEPS:
1. Read ${CWD}/crates/rustre-il-hlil/src/lib.rs or wherever emit_pseudo_c lives. Find where HLIL instructions are printed.
2. Ensure the HLIL emitter runs these passes BEFORE printing:
   - flag_var elimination (fold flag_cf/flag_zf comparisons into their producing cmp)
   - register-to-variable lifting (rax → v1, rsp → stack, etc — same naming as LLIL emitter)
   - goto → structured control flow (using CFG structurer if available in rustre-decompiler-cfs)
3. If the structurer exists (decompiler_cfs_make_if_else etc.), call it on the HLIL block list before emission.
4. Reduce "unknown" type annotations — use int/int64/void* based on width.
5. cd ${CWD} && cargo build --release -p rustre-il-hlil -p rustre-decompiler -p rustre-mcp 2>&1 | tail -15.
6. Return {passes_added:[string], structurer_called:bool, build_ok:bool, notes:string}`,
  { label: 'hlil-struct', agentType: 're-validator', schema: {
    type: 'object',
    properties: {
      passes_added:{type:'array', items:{type:'string'}},
      structurer_called:{type:'boolean'},
      build_ok:{type:'boolean'},
      notes:{type:'string'},
    },
    required:['build_ok','notes']
  }}
)

phase('VsaInterproc')
const vsa = await agent(
  `VSA resolved 0 concrete targets: 65 indirect-call target regs are version-0 SSA (caller-set), lattice returns Top.

STEPS:
1. Read ${CWD}/crates/rustre-analysis-vsa/src/lib.rs IndirectCallResolver.
2. Add a simple caller-arg hint pass: for each call to fn F, if the caller has set a register (RAX/RCX/RDX/R8/R9) to a constant or a global variable address before the call, pass that value as an initial VSA fact for F's entry version-0 register.
3. Scope: intraprocedural for now — just look at the SAME function's prior blocks for constant assigns to the register used as the indirect call target. Even without full interprocedural VSA, a "look 5 instructions back" heuristic will catch many "mov rax, [rip+off]; call rax" patterns.
4. cd ${CWD} && cargo build --release -p rustre-analysis-vsa -p rustre-decompiler -p rustre-mcp 2>&1 | tail -15.
5. Return {heuristic_added:string, build_ok:bool, notes:string}`,
  { label: 'vsa-interproc', agentType: 're-validator', schema: {
    type: 'object',
    properties: {
      heuristic_added:{type:'string'},
      build_ok:{type:'boolean'},
      notes:{type:'string'},
    },
    required:['build_ok','notes']
  }}
)

phase('FixJumpoutEmit')
const jumpout = await agent(
  `JUMPOUT() is emitted in pseudo_code but is not valid recompilable C.

STEPS:
1. Grep ${CWD}/crates/rustre-decompiler/src -rn "JUMPOUT" — find the emit path.
2. Replace JUMPOUT(0xADDR) with either:
   - "goto label_ADDR;" if a corresponding label can be added at the target (best for tail calls within same fn)
   - "/* JUMPOUT(0xADDR) — external jump */" as a comment + fall-through if truly external
3. If the JUMPOUT target is inside the same function's disasm range: prefer real goto. Else: comment.
4. cd ${CWD} && cargo build --release -p rustre-decompiler -p rustre-mcp 2>&1 | tail -15.
5. Return {strategy:string, build_ok:bool, notes:string}`,
  { label: 'jumpout', agentType: 're-validator', schema: {
    type: 'object',
    properties: {
      strategy:{type:'string'},
      build_ok:{type:'boolean'},
      notes:{type:'string'},
    },
    required:['build_ok','notes']
  }}
)

phase('Verify')
const verify = await agent(
  `Full Round 5 verification.

STEPS:
1. taskkill //F //IM rustre-mcp.exe. sleep 3.
2. cd ${CWD} && cargo build --release -p rustre-mcp -p rustre-mcp-server 2>&1 | tail -10.
3. Python probe on 8 addresses [0x140001000, 0x14000d880, 0x140026ad0, 0x1400a4a90, 0x1400f1190, 0x140009a90, 0x1400f2a00, 0x1400f206c].
4. For each:
   - name: is it a real name or sub_XXX?
   - hlil_pseudo_code: still register-level or structured now?
   - JUMPOUT() count: should be 0 (or converted to goto/comment)
   - DCE(df) count
   - VSA-resolved indirect calls (named vs "((__int64(*)()")
5. Compute overall recompilability score: try to gcc -std=gnu89 -fsyntax-only each pseudo_code with ida_defs.h prelude. Report pass/fail per function.
6. Return {sprint1_named:int, sprint4_dce:int, sprint5_vsa_resolved_named:int, sprint6_hlil_structured:int, jumpout_count:int, recompilable_count:int, avg_confidence:number, verdict:string, remaining_issues:[string]}`,
  { label: 'verify5', agentType: 're-validator', schema: {
    type: 'object',
    properties: {
      sprint1_named:{type:'integer'},
      sprint4_dce:{type:'integer'},
      sprint5_vsa_resolved_named:{type:'integer'},
      sprint6_hlil_structured:{type:'integer'},
      jumpout_count:{type:'integer'},
      recompilable_count:{type:'integer'},
      avg_confidence:{type:'number'},
      verdict:{type:'string'},
      remaining_issues:{type:'array', items:{type:'string'}},
    },
    required:['verdict']
  }}
)

return { status:'round5-complete', flirt, hlil, vsa, jumpout, verify }
