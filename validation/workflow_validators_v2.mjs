export const meta = {
  name: 'rustre-mcp-validators-v2',
  description: 'Second wave — validate 15 more categories with independent Python truth (loader/arch/pdb/dwarf/flirt/etc)',
  phases: [
    { title: 'Validate2', detail: 'One agent per category, parallel' },
    { title: 'Triage2', detail: 'Confirm real bugs' },
    { title: 'Fix2', detail: 'Fix confirmed bugs' },
    { title: 'Confirm2', detail: 'Rebuild + re-validate' },
  ],
}

const CATEGORIES = [
  { name: 'loader_elf', prefix: 'loader_elf_', hint: 'Use pyelftools if importable, else hand-parse: ELF magic 7f 45 4c 46, class 32/64 at [4], data endian at [5], e_type at 16.' },
  { name: 'loader_macho', prefix: 'loader_macho_', hint: 'Mach-O magic: 0xfeedface (32 LE), 0xfeedfacf (64 LE), 0xcafebabe (fat). CPU type ARM64=0x0100000c, X86_64=0x01000007.' },
  { name: 'loader_java', prefix: 'loader_java_', hint: 'Java class magic 0xCAFEBABE, minor/major version u16 BE at offset 4/6. JAR/APK: ZIP magic 50 4B 03 04.' },
  { name: 'loader_wasm', prefix: 'loader_wasm_', hint: 'WASM magic 00 61 73 6d, version 01 00 00 00. Section IDs: type=1, import=2, function=3, table=4, memory=5, global=6, export=7, start=8, elem=9, code=10, data=11.' },
  { name: 'arch_wasm', prefix: 'arch_wasm_', hint: 'WASM opcode table: nop=0x01, block=0x02, loop=0x03, br=0x0c, return=0x0f, call=0x10. valtype i32=0x7f, i64=0x7e, f32=0x7d, f64=0x7c.' },
  { name: 'arch_x86', prefix: 'arch_x86_', hint: 'x86_64 registers rax=0, rcx=1, rdx=2, rbx=3, rsp=4, rbp=5, rsi=6, rdi=7, r8-r15=8-15. Sys-V arg regs: rdi, rsi, rdx, rcx, r8, r9. MSVC: rcx, rdx, r8, r9.' },
  { name: 'symbols_pdb', prefix: 'symbols_pdb_', hint: 'Symbol server URL format: <base>/<pdbname>/<guid_hex><age>/<pdbname>. Use pdbparse if importable for ground truth.' },
  { name: 'dwarf', prefix: 'dwarf_', hint: 'ULEB128/SLEB128 decoding: standard algorithm. DWARF version u16, unit_length. Cast tests: check truncation semantics (i64 as u32 = low 32 bits).' },
  { name: 'flirt', prefix: 'flirt_', hint: 'CRC16 IBM (poly 0xA001 reflected) OR FLIRT variant. Test with known input like b"IDA" → known checksum. Pattern wildcard ratio = wildcards / total_bytes.' },
  { name: 'yara_engine', prefix: 'yara_engine_', hint: 'Use yara-python if importable. Simple rule: "rule t { strings: $a = \\"MZ\\" condition: $a }" should match any PE file at offset 0.' },
  { name: 'fuzz_cov', prefix: 'fuzz_cov_', hint: 'AFL bucket classify same as fuzz_afl. LCOV format: TN:name/SF:file/DA:line,count/end_of_record. Coverage percent = hit_lines / total_lines * 100.' },
  { name: 'net_parse', prefix: 'net_parse_', hint: 'Standard packet parsing: Ethernet 14 bytes, IPv4 version=4 top nibble, IHL bottom nibble (*4 bytes), IP checksum = ~sum16(header). TCP flags: SYN=2, ACK=16, FIN=1, RST=4.' },
  { name: 'net_rules', prefix: 'net_rules_', hint: 'Aho-Corasick: build trie, follow failure links. Snort rule format known. Test with simple patterns like ["ab", "abc"].' },
  { name: 'kgdb_gdb', prefix: 'kgdb_', hint: 'GDB RSP escape: bytes 0x24, 0x23, 0x7d, 0x2a need prefix 0x7d then byte^0x20. Hex→bytes u64 LE. Same checksum as gdb.' },
  { name: 'codeview_pdb', prefix: 'codeview_', hint: 'CodeView signatures: RSDS=0x53445352 (LE bytes 52 53 44 53), NB10, NB09. GUID format: 4-2-2-2-6 hex bytes. Primitive types: T_VOID=0x03, T_CHAR=0x10, T_INT4=0x74.' },
]

phase('Validate2')

const validators = await parallel(CATEGORIES.map(cat => () =>
  agent(`Independent Python validator for RustRE MCP tools with prefix "${cat.prefix}".

Env:
- MCP binary: C:\\Users\\Fra\\Desktop\\RustRE\\target\\release\\rustre-mcp.exe
- Working dir: C:\\Users\\Fra\\Desktop\\RustRE
- Reference: validation/validators_v1.py
- pip modules that may be available: pefile, lief, pyelftools, macholib, capstone, keystone-engine, yara-python, cxxfilt, rustc_demangle, cryptography, pycparser
- Target file for real bytes: C:\\Users\\Fra\\Desktop\\Zyphora\\target\\release\\cargo-zyphora.exe (PE64, image_base 0x140000000)

Task (Python only, DO NOT touch .rs files):
1. Start MCP via subprocess/stdio, do initialize handshake.
2. tools/list, filter by prefix "${cat.prefix}".
3. For AT LEAST 20 tools (all if fewer), pick semantically valid inputs based on inputSchema+description. Compute ground truth INDEPENDENTLY. Never trust MCP output as truth.
4. Ground-truth hint: ${cat.hint}
5. Save script: validation/validators_${cat.name}.py (overwrite ok)
6. Run it: python validation/validators_${cat.name}.py
7. Save report: validation/mismatch_${cat.name}.json

Rules:
- Skip cleanly if you can't figure out a tool's schema — that's NOT a mismatch.
- A mismatch requires: MCP returned a concrete value that disagrees with your independent computation.
- Normalize types (bytes vs list, hex case, float epsilon 1e-6).
- Do NOT edit any Rust source.

Return: { category, tools_in_category, checks_total, checks_passed, checks_skipped, mismatches[{tool,input,mcp,truth,note}] }`, {
    label: `validate2:${cat.name}`,
    phase: 'Validate2',
    schema: {
      type: 'object',
      properties: {
        category: { type: 'string' },
        tools_in_category: { type: 'integer' },
        checks_total: { type: 'integer' },
        checks_passed: { type: 'integer' },
        checks_skipped: { type: 'integer' },
        mismatches: {
          type: 'array',
          items: {
            type: 'object',
            properties: {
              tool: { type: 'string' },
              input: {},
              mcp: {},
              truth: {},
              note: { type: 'string' },
            },
            required: ['tool', 'note']
          }
        }
      },
      required: ['category', 'checks_total', 'checks_passed', 'mismatches']
    }
  })
))

const good = validators.filter(Boolean)
const allMismatches = good.flatMap(v => (v.mismatches || []).map(m => ({...m, category: v.category})))
const totalChecks = good.reduce((s,v) => s + (v.checks_total || 0), 0)
const totalPassed = good.reduce((s,v) => s + (v.checks_passed || 0), 0)
const totalSkipped = good.reduce((s,v) => s + (v.checks_skipped || 0), 0)

log(`Validate2: ${good.length}/${CATEGORIES.length} categories, ${totalPassed}/${totalChecks} checks (${totalSkipped} skipped), ${allMismatches.length} candidate mismatches`)

const BEFORE = { totalChecks, totalPassed, mismatches: allMismatches.length }

if (allMismatches.length === 0) {
  return { status: 'all_ok_v2', before: BEFORE, real_bugs: 0 }
}

// TRIAGE
phase('Triage2')
const triaged = await parallel(allMismatches.slice(0, 80).map(m => () =>
  agent(`Triage MCP mismatch (real bug or false positive?).

Tool: ${m.tool}
Category: ${m.category}
Input: ${JSON.stringify(m.input)}
MCP: ${JSON.stringify(m.mcp)}
Python truth: ${JSON.stringify(m.truth)}
Note: ${m.note}

Steps:
1. Grep wire_tools.rs for the tool name.
2. Follow to workspace crate implementation.
3. Determine verdict:
   - real_bug: MCP output demonstrably wrong per spec
   - false_positive: Python truth wrong, tool schema misunderstood, or legitimate error handler

Return: {tool, verdict:"real_bug"|"false_positive", reason, file, line, fix_hint}`, {
    label: `triage2:${m.tool.replace(/[^a-z0-9_]/gi,'_').slice(0,40)}`,
    phase: 'Triage2',
    schema: {
      type: 'object',
      properties: {
        tool: { type: 'string' },
        verdict: { enum: ['real_bug', 'false_positive'] },
        reason: { type: 'string' },
        file: { type: 'string' },
        line: { type: 'integer' },
        fix_hint: { type: 'string' },
      },
      required: ['tool', 'verdict', 'reason']
    }
  })
))

const realBugs = triaged.filter(Boolean).filter(t => t.verdict === 'real_bug')
log(`Triage2: ${realBugs.length} real bugs / ${triaged.filter(Boolean).length} triaged`)

if (realBugs.length === 0) {
  return { status: 'no_real_bugs_v2', before: BEFORE, candidates: triaged.filter(Boolean).length }
}

// FIX serialized
phase('Fix2')
const fixed = []
for (const bug of realBugs.slice(0, 40)) {
  const r = await agent(`Fix confirmed MCP bug.

Tool: ${bug.tool}
File: ${bug.file || '?'}${bug.line ? ':' + bug.line : ''}
Reason: ${bug.reason}
Hint: ${bug.fix_hint || ''}

Rules:
- Modify only crates/rustre-* workspace code
- No #[allow], no panic/todo/unimplemented, no dead-code deletion
- Put business logic in domain crates, not wrappers

Return: {tool, fixed, file_edited, summary}`, {
    label: `fix2:${bug.tool.replace(/[^a-z0-9_]/gi,'_').slice(0,40)}`,
    phase: 'Fix2',
    schema: {
      type: 'object',
      properties: {
        tool: { type: 'string' },
        fixed: { type: 'boolean' },
        file_edited: { type: 'string' },
        summary: { type: 'string' },
      },
      required: ['tool', 'fixed']
    }
  })
  if (r) fixed.push(r)
}

const applied = fixed.filter(f => f.fixed).length
log(`Fix2: ${applied}/${realBugs.length} applied`)

if (applied === 0) return { status: 'no_fixes_v2', before: BEFORE, real_bugs: realBugs.length }

// CONFIRM
phase('Confirm2')
const confirm = await agent(`Rebuild rustre-mcp and re-run validators.
Steps:
1. cd C:\\Users\\Fra\\Desktop\\RustRE
2. cargo build --release --bin rustre-mcp (~15-20 min, wait patiently)
3. Re-run each: python validation/validators_<cat>.py for ${CATEGORIES.map(c=>c.name).join(', ')}
4. Aggregate mismatches from validation/mismatch_<cat>.json

Return: {build_ok, before_mismatches: ${allMismatches.length}, after_mismatches, summary}`, {
    label: 'rebuild+revalidate2',
    phase: 'Confirm2',
    schema: {
      type: 'object',
      properties: {
        build_ok: { type: 'boolean' },
        before_mismatches: { type: 'integer' },
        after_mismatches: { type: 'integer' },
        summary: { type: 'string' }
      },
      required: ['build_ok', 'before_mismatches', 'after_mismatches']
    }
  })

return {
  status: 'completed_v2',
  categories_validated: good.length,
  before: BEFORE,
  real_bugs: realBugs.length,
  fixes_applied: applied,
  confirm,
}
