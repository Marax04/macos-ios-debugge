export const meta = {
  name: 'rustre-mcp-massive-validation',
  description: '30 categories in parallel — validate residual RustRE MCP tools, triage, fix, rebuild+revalidate loop-until-zero',
  phases: [
    { title: 'ValidateMass', detail: 'Fan out one agent per category' },
    { title: 'TriageMass', detail: 'Adversarially confirm real bugs' },
    { title: 'FixMass', detail: 'Apply MCP fixes' },
    { title: 'FixValidatorsMass', detail: 'Correct validator false positives' },
    { title: 'VerifyMass', detail: 'Rebuild + full re-validation' },
  ],
}

const CATEGORIES = [
  { name: 'analysis_cfg', prefix: 'analysis_cfg_', hint: 'CFG: dominator tree via Lengauer-Tarjan, natural loops = back-edge tail dominates head, cyclomatic = edges - nodes + 2*components. Test with small hand-built graphs.' },
  { name: 'analysis_dataflow', prefix: 'analysis_dataflow_', hint: 'Reaching defs / liveness lattice: forward/backward union. Dominance frontier trivially computable on small CFG. Constant propagation.' },
  { name: 'analysis_xref', prefix: 'analysis_xref_', hint: 'Xref index: build from list of (src,dst,kind), verify callees/callers lookups return exact expected sets.' },
  { name: 'analysis_type', prefix: 'analysis_type_', hint: 'WinAPI type db: known signatures (CreateFileA takes 7 params). Type join/meet: void ⊔ int = top, int ⊔ int = int.' },
  { name: 'decompiler_type', prefix: 'decompiler_type_', hint: 'C type sizes: int=4, ptr=8 on 64-bit, char=1. C keyword list. Function arity from prototype string.' },
  { name: 'demangle', prefix: 'demangle_', hint: 'Use cxxfilt for Itanium C++, rustc-demangle for Rust v0. MSVC "??_C@_..." forms. Standard substitutions.' },
  { name: 'dotnet_metadata', prefix: 'dotnet_metadata_', hint: 'ECMA-335: tokens are (table<<24)|rid. TypeDef=0x02, MethodDef=0x06, Field=0x04. Signature blob compressed uints.' },
  { name: 'emu_unicorn', prefix: 'emu_unicorn_', hint: 'Perm bits: READ=1, WRITE=2, EXEC=4. Mode LE/BE, ptr size 4 (32-bit) or 8 (64-bit).' },
  { name: 'events', prefix: 'events_', hint: 'Event bus counters: publish N events → total_sent >= N. Correlator groups by variant.' },
  { name: 'forensics_fs', prefix: 'forensics_fs_', hint: 'Prefetch signature "SCCA", LNK signature 0x0000004C then GUID {00021401-0000-0000-C000-000000000046}.' },
  { name: 'forensics_mem', prefix: 'forensics_mem_', hint: 'Unicode string scan: alternating [char,0] bytes. Connection states TCP: 1=established, 2=syn_sent, 3=syn_recv, etc.' },
  { name: 'fuzz_libfuzzer', prefix: 'fuzz_libfuzzer_', hint: 'FNV-1a hash algorithm. Bucket counter classification: 1,2,3-4,5-8,9-16,17-32,33-127,128+.' },
  { name: 'fuzz_san', prefix: 'fuzz_san_', hint: 'Log line pattern parsers for compiler sanitizer output. Severity classification by keyword.' },
  { name: 'ghidra_pcode', prefix: 'ghidra_pcode_', hint: 'P-code ops: COPY, INT_ADD, INT_SUB, LOAD, STORE, BRANCH, CALL, RETURN. Varnode = (space, offset, size).' },
  { name: 'il_lift', prefix: 'il_lift_', hint: 'LiftLevel ordering: disasm < mlil < hlil. x86 REG rax=0, rbp=5. Simple opcodes: NOP=0x90, RET=0xC3.' },
  { name: 'il_passes', prefix: 'il_passes_', hint: 'GVN pass, loop bound analysis, integer range. Constant count in expr tree = count of leaves that are Const.' },
  { name: 'kg', prefix: 'kg_', hint: 'Knowledge graph functions: schema wants string "addr" as hex. Test list, query returning known nodes.' },
  { name: 'net_dissect', prefix: 'net_dissect_', hint: 'DNS type A=1, NS=2, CNAME=5, MX=15, AAAA=28, TXT=16. ICMP echo request=8, reply=0.' },
  { name: 'net_pcap', prefix: 'net_pcap_', hint: 'pcap magic 0xa1b2c3d4 (μs) or 0xa1b23c4d (ns). Link type ETHERNET=1, RAW=101.' },
  { name: 'patch', prefix: 'patch_', hint: 'PE checksum: standard algorithm. NOP byte 0x90. Code cave = contiguous 0x00 or 0xCC bytes in .text of size >= N.' },
  { name: 'pe_editor', prefix: 'pe_editor_', hint: 'RC4 KSA/PRGA standard. PE section chars IMAGE_SCN_MEM_EXECUTE=0x20000000, READ=0x40000000, WRITE=0x80000000.' },
  { name: 'sandbox_report', prefix: 'sandbox_report_', hint: 'Report severity ordering: info < low < med < high < crit. Category label formatting and enum roundtrips.' },
  { name: 'script_rhai', prefix: 'script_rhai_', hint: 'Standard hex encode/decode, SHA256 via hashlib, byte rotate.' },
  { name: 'stabs', prefix: 'stabs_', hint: 'STABS type codes: FUN=36 (0x24), STSYM=38, LSYM=128, SOL=132, SLINE=68. Category: line, symbol, source, type.' },
  { name: 'symbols_v7', prefix: 'symbols_v7_', hint: 'Symbol source priority: PDB > DWARF > FLIRT > synthetic. Symbol contains: [start, start+size).' },
  { name: 'ti_vt', prefix: 'ti_vt_', hint: 'Report parser: ratio = flagged / total. Result enum classification. Token bucket rate limiter arithmetic.' },
  { name: 'trace_coverage', prefix: 'trace_coverage_', hint: 'LCOV format standard. Coverage % = covered_lines / total_lines * 100. Basic block hit count.' },
  { name: 'triage_entropy', prefix: 'triage_entropy_', hint: 'Shannon entropy < 6.5 = normal, 6.5-7.5 = compressed, >7.5 = encrypted/packed.' },
  { name: 'ttd', prefix: 'ttd_', hint: 'TTD positions ordering (u128 or (sequence, step)). Position min/max/next semantics. Memory read u32/u64 LE.' },
  { name: 'vmlift', prefix: 'vmlift_', hint: 'ISA lookup by opcode. Empty ISA has 0 opcodes. Dispatch detection heuristic.' },
  { name: 'vtable', prefix: 'vtable_', hint: 'C++ ABI name-mangling formats: Itanium _ZTV<class>, MSVC "??_7...". Type info pointer layout at negative offsets.' },
  { name: 'windbg', prefix: 'windbg_', hint: 'WinDbg command tokens: bp, g, k, dt, u. Module list from lm output.' },
  { name: 'yara', prefix: 'yara_', hint: 'Pattern matching rule parser: identifier grammar, string modifier flags (nocase, wide, ascii).' },
]

phase('ValidateMass')

const validators = await parallel(CATEGORIES.map(cat => () =>
  agent(`Independent Python validator for RustRE MCP tools with prefix "${cat.prefix}".

Env:
- MCP binary: C:\\Users\\Fra\\Desktop\\RustRE\\target\\release\\rustre-mcp.exe
- Working dir: C:\\Users\\Fra\\Desktop\\RustRE
- Reference validator: validation/validators_v1.py
- Available: pefile, lief, pyelftools, macholib, capstone, keystone-engine, yara-python, cxxfilt, rustc_demangle, cryptography, hashlib, zlib, base64, struct
- Real bytes target: C:\\Users\\Fra\\Desktop\\Zyphora\\target\\release\\cargo-zyphora.exe (PE64, image_base 0x140000000)

Task (Python only, DO NOT touch .rs files):
1. Start MCP via subprocess/stdio, do initialize handshake.
2. tools/list, filter by prefix "${cat.prefix}".
3. For AT LEAST 20 tools (or all if fewer), pick correct inputs from inputSchema and description. Compute ground truth INDEPENDENTLY. Never trust MCP output as truth.
4. Ground-truth hint: ${cat.hint}
5. Save script: validation/validators_${cat.name}.py (overwrite ok)
6. Run: python validation/validators_${cat.name}.py
7. Save report: validation/mismatch_${cat.name}.json

Rules:
- Skip cleanly if schema unclear — NOT a mismatch.
- A mismatch = MCP returned concrete value AND disagrees with independent Python truth.
- Normalize types (bytes/list, hex case, float eps 1e-6).
- Do NOT edit any Rust source.

Return: { category, tools_in_category, checks_total, checks_passed, checks_skipped, mismatches[{tool,input,mcp,truth,note}] }`, {
    label: `val:${cat.name}`,
    phase: 'ValidateMass',
    model: 'haiku',
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
              input: {}, mcp: {}, truth: {},
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

log(`ValidateMass: ${good.length}/${CATEGORIES.length} cats, ${totalPassed}/${totalChecks} checks, ${allMismatches.length} candidates`)

const BEFORE = { totalChecks, totalPassed, mismatches: allMismatches.length }

if (allMismatches.length === 0) return { status: 'all_ok_first_pass', before: BEFORE, real_bugs: 0 }

// TRIAGE
phase('TriageMass')
const triaged = await parallel(allMismatches.slice(0, 120).map(m => () =>
  agent(`Review MCP validator mismatch. Is it a real code defect or validator misinterpretation?

Tool: ${m.tool}
Category: ${m.category}
Input: ${JSON.stringify(m.input)}
MCP: ${JSON.stringify(m.mcp)}
Python truth: ${JSON.stringify(m.truth)}
Note: ${m.note}

Steps:
1. Grep wire_tools.rs for the tool name, find wrapper.
2. Follow to workspace crate impl.
3. Independently compute expected output with a fresh reference (do NOT trust the validator's truth blindly).
4. Verdict: real_bug (MCP wrong) or validator_fp (Python wrong / misunderstood tool / edge case).

Return: {tool, verdict:"real_bug"|"validator_fp", reason, file, line, fix_hint}`, {
    label: `tri:${m.tool.replace(/[^a-z0-9_]/gi,'_').slice(0,40)}`,
    phase: 'TriageMass',
    model: 'haiku',
    schema: {
      type: 'object',
      properties: {
        tool: { type: 'string' },
        verdict: { enum: ['real_bug','validator_fp'] },
        reason: { type: 'string' },
        file: { type: 'string' },
        line: { type: 'integer' },
        fix_hint: { type: 'string' },
      },
      required: ['tool','verdict','reason']
    }
  })
))

const realBugs = triaged.filter(Boolean).filter(t => t.verdict === 'real_bug')
const fps = triaged.filter(Boolean).filter(t => t.verdict === 'validator_fp')
log(`TriageMass: ${realBugs.length} real bugs, ${fps.length} validator FPs`)

if (realBugs.length === 0 && fps.length === 0) {
  return { status: 'triage_empty', before: BEFORE }
}

// FIX TOOLS serialized
if (realBugs.length > 0) {
  phase('FixMass')
  for (const bug of realBugs.slice(0, 60)) {
    await agent(`Fix confirmed MCP bug — minimal change.

Tool: ${bug.tool}
File: ${bug.file || '?'}${bug.line ? ':' + bug.line : ''}
Reason: ${bug.reason}
Fix hint: ${bug.fix_hint || ''}

HARD Rules:
- Only crates/rustre-* workspace code
- NEVER touch Desktop\\mcp\\rustre-mcp\\
- No #[allow], no panic/todo/unimplemented, no dead-code deletion
- Business logic in domain crate

Return: {tool, fixed, file_edited, summary}`, {
      label: `fix:${bug.tool.replace(/[^a-z0-9_]/gi,'_').slice(0,40)}`,
      phase: 'FixMass',
      model: 'haiku',
        schema: {
        type:'object',
        properties: {
          tool: {type:'string'}, fixed: {type:'boolean'},
          file_edited: {type:'string'}, summary: {type:'string'}
        },
        required:['tool','fixed']
      }
    })
  }
}

// FIX VALIDATORS grouped by category
if (fps.length > 0) {
  phase('FixValidatorsMass')
  const byCat = {}
  for (const fp of fps) {
    const cat = allMismatches.find(m => m.tool === fp.tool)?.category
    if (cat) (byCat[cat] ||= []).push(fp)
  }
  await parallel(Object.entries(byCat).map(([cat, list]) => () =>
    agent(`Fix Python validator for category "${cat}" — correct or skip these false positives.

Validator: C:\\Users\\Fra\\Desktop\\RustRE\\validation\\validators_${cat}.py

FPs (${list.length}):
${JSON.stringify(list.map(f=>({tool:f.tool, reason:f.reason, fix_hint:f.fix_hint})), null, 2)}

Task:
1. Read validator.
2. For each FP: correct the ground truth or skip cleanly with comment.
3. Run: python validation/validators_${cat}.py
4. Confirm mismatch_${cat}.json shows fewer/zero mismatches.

Return: {category, fps_addressed, validator_ok, remaining_mismatches, summary}`, {
      label: `fv:${cat}`,
      phase: 'FixValidatorsMass',
      model: 'haiku',
        schema: {
        type:'object',
        properties: {
          category:{type:'string'}, fps_addressed:{type:'integer'},
          validator_ok:{type:'boolean'}, remaining_mismatches:{type:'integer'},
          summary:{type:'string'}
        },
        required:['category','fps_addressed']
      }
    })
  ))
}

// VERIFY
phase('VerifyMass')
const verify = await agent(`Verify final state after MASSIVE validation.

1. If any .rs file was edited this workflow, run: cd C:\\Users\\Fra\\Desktop\\RustRE; cargo build --release --bin rustre-mcp (~15-20 min; WAIT patiently do NOT time out)
2. If build fails, capture error and set build_ok=false.
3. Re-run every validator for these categories: ${CATEGORIES.map(c=>c.name).join(', ')}
   Command per cat: python validation/validators_<cat>.py
4. Read validation/mismatch_<cat>.json for each; count total.

Return: {build_ok, final_mismatches, per_category, summary}`, {
    label: 'verify-massive',
    phase: 'VerifyMass',
    model: 'haiku',
    schema: {
      type:'object',
      properties: {
        build_ok:{type:'boolean'}, final_mismatches:{type:'integer'},
        per_category:{}, summary:{type:'string'}
      },
      required:['final_mismatches']
    }
  })

return {
  status: 'massive_complete',
  before: BEFORE,
  real_bugs: realBugs.length,
  validator_fps: fps.length,
  final: verify
}
