export const meta = {
  name: 'rustre-mcp-validators',
  description: 'Validate RustRE MCP tool correctness with independent Python ground truth per category, then fix real bugs',
  phases: [
    { title: 'Validate', detail: 'One agent per category writes+runs Python validator' },
    { title: 'Triage', detail: 'Verify each mismatch is a real bug or false positive' },
    { title: 'Fix', detail: 'Fix confirmed bugs in workspace crates' },
    { title: 'Confirm', detail: 'Rebuild + re-validate before/after' },
  ],
}

const CATEGORIES = [
  { name: 'hex_pattern', prefix: 'hex_pattern_', hint: 'Pure Python: hex parsing, wildcard counting, byte matching, specificity = concrete_bytes / total_bytes.' },
  { name: 'mem', prefix: 'mem_', hint: 'Pure Python: page align (va & ~(ps-1)) and ((va + ps - 1) & ~(ps-1)); Shannon entropy via math.log2; struct.unpack for LE/BE ints; page index = va // page_size.' },
  { name: 'crypto_id', prefix: 'crypto_id_', hint: 'Hardcoded constants: AES S-box, Rijndael Rcon starts at 0x8D then 0x01,0x02,0x04..., CRC32 reversed poly 0xEDB88320, DES initial S-box row 0, SHA256 K[0]=0x428a2f98, ChaCha "expand 32-byte k", Blowfish P[0]=0x243f6a88, TEA delta 0x9E3779B9.' },
  { name: 'deobf_crypto', prefix: 'deobf_', hint: 'Standard algos: zlib.crc32("123456789")==0xCBF43926; zlib.adler32 or manual (a=1+bytes,b=cumulative); base64 stdlib round-trip; RC4 KSA/PRGA reference; XOR cyclic trivial.' },
  { name: 'forensics_compute', prefix: 'forensics_compute_', hint: 'Schema takes {"data": string} (UTF-8), NOT hex. hashlib.md5/sha1/sha256/sha512(bytes).hexdigest(). sha256("hello world")==b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9.' },
  { name: 'syscalls', prefix: 'syscalls_', hint: 'Linux x86_64: read=0, write=1, open=2, close=3, mmap=9, execve=59, exit=60, openat=257. Windows NtCreateFile has SSN varying by build. Signal SIGKILL=9, SIGSEGV=11, SIGTERM=15.' },
  { name: 'fuzz_afl', prefix: 'fuzz_afl_', hint: 'AFL classify: 1->1, 2->2, 3->4, 4..7->8, 8..15->16, 16..31->32, 32..127->64, 128..255->128. FNV1a: hash=0xcbf29ce484222325; for b: hash^=b; hash*=0x100000001b3. Bit-flip mutation trivial.' },
  { name: 'gdb_packet', prefix: 'gdb_', hint: 'RSP checksum = sum(payload_bytes) & 0xFF as 2-hex-lowercase. Packet format $payload#checksum. Escaped chars ($,#,},*): 0x7D then (byte XOR 0x20).' },
  { name: 'symbols_demangle', prefix: 'symbols_demangle_', hint: 'Rust v0 "_RNvNtCs6CKzx_3foo3bar4baz" demangles to path with foo,bar,baz. Itanium _Z3fooi -> foo(int). Try to spawn "rustfilt" or "c++filt" via subprocess for ground truth; if unavailable, verify presence of expected substrings.' },
  { name: 'loader_pe', prefix: 'loader_pe_', hint: 'Use pefile (if importable) to parse cargo-zyphora.exe: 106 imports, image_base=0x140000000, entry point, section count. If pefile absent, hand-parse: DOS magic MZ, PE offset at 0x3C, NT signature "PE\\0\\0".' },
]

phase('Validate')

const validators = await parallel(CATEGORIES.map(cat => () =>
  agent(`You are writing an independent Python validator for RustRE MCP tools with prefix "${cat.prefix}".

Environment:
- Windows, PowerShell/Bash both work
- MCP binary: C:\\Users\\Fra\\Desktop\\RustRE\\target\\release\\rustre-mcp.exe
- Working dir: C:\\Users\\Fra\\Desktop\\RustRE
- Example reference validator: validation/validators_v1.py

Task (DO NOT modify Rust code, only write Python):
1. Start the MCP server via subprocess with stdio; do initialize + notifications/initialized handshake.
2. Call tools/list, filter tools whose name starts with "${cat.prefix}".
3. For AT LEAST 20 tools (or all if fewer), pick semantically correct inputs based on each tool's inputSchema and description. Compute the ground truth INDEPENDENTLY in Python; do not just accept whatever MCP returns.
4. Ground-truth hint for this category: ${cat.hint}
5. Save your validator script to: validation/validators_${cat.name}.py (overwrite ok)
6. Run it: python validation/validators_${cat.name}.py
7. Save mismatch report to: validation/mismatch_${cat.name}.json

Rules:
- If a tool's schema requires fields you don't understand, skip it (log_skipped); this is NOT a mismatch.
- If a tool returns TOOL_ERROR that clearly means "unsupported input for this build" (e.g. "not a PE" when you sent a hash), skip; not a mismatch.
- A MISMATCH is: MCP returned a concrete value AND your independent Python truth disagrees.
- Normalize types before comparing (bytes vs list-of-ints, hex case, integer vs number).
- If you find that a tool consistently fails on inputs the schema says should work — that's a candidate mismatch, log it.
- Do NOT edit any .rs files.

Return structured object:
{
  "category": "${cat.name}",
  "tools_in_category": <int>,
  "checks_total": <int>,     // how many tools you compared against truth
  "checks_passed": <int>,
  "checks_skipped": <int>,
  "mismatches": [ {"tool":..., "input":..., "mcp":..., "truth":..., "note":"why this is a real mismatch"} ]
}`, {
    label: `validate:${cat.name}`,
    phase: 'Validate',
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

log(`Validate phase: ${good.length}/${CATEGORIES.length} categories, ${totalPassed}/${totalChecks} checks passed (${totalSkipped} skipped), ${allMismatches.length} candidate mismatches`)

const BEFORE = { totalChecks, totalPassed, mismatches: allMismatches.length }

if (allMismatches.length === 0) {
  return { status: 'all_ok_first_pass', before: BEFORE, after: BEFORE, real_bugs: 0, fixes: 0 }
}

// ─────── TRIAGE ───────
phase('Triage')
const triaged = await parallel(allMismatches.slice(0, 60).map(m => () =>
  agent(`Triage a candidate MCP mismatch. Determine: is it a real MCP bug or a false positive in the validator?

Tool: ${m.tool}
Category: ${m.category}
Input sent: ${JSON.stringify(m.input)}
MCP returned: ${JSON.stringify(m.mcp)}
Python ground truth: ${JSON.stringify(m.truth)}
Validator's note: ${m.note}

Steps:
1. Locate the wire wrapper for "${m.tool}" via Grep on C:\\Users\\Fra\\Desktop\\RustRE\\crates\\rustre-mcp-tools\\src\\wire_tools.rs
2. Follow through to the actual implementation in the workspace crate under crates/rustre-*
3. Read the impl carefully. Determine whether:
   (a) MCP output is correct and the Python truth is wrong (false_positive)
   (b) MCP output is genuinely wrong (real_bug)
   (c) MCP output is a legitimate error handler for edge-case input (false_positive/edge)
4. Provide file path and line number of the offending code if verdict is real_bug.

Return: {"tool":..., "verdict":"real_bug"|"false_positive", "reason":..., "file":..., "line":..., "fix_hint":...}`, {
    label: `triage:${m.tool.replace(/[^a-z0-9_]/gi,'_').slice(0,40)}`,
    phase: 'Triage',
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
log(`Triage: ${realBugs.length}/${triaged.filter(Boolean).length} confirmed real bugs`)

if (realBugs.length === 0) {
  return { status: 'no_real_bugs_after_triage', before: BEFORE, after: BEFORE,
           candidates_triaged: triaged.filter(Boolean).length, real_bugs: 0, fixes: 0 }
}

// ─────── FIX (serialized to avoid rustc conflicts) ───────
phase('Fix')
const fixed = []
for (const bug of realBugs.slice(0, 40)) {
  const r = await agent(`Fix confirmed MCP bug. Apply the minimum change to make behavior correct.

Tool: ${bug.tool}
Suspected file: ${bug.file || 'unknown'}${bug.line ? ':' + bug.line : ''}
Root cause: ${bug.reason}
Fix hint: ${bug.fix_hint || ''}

Hard constraints:
- Modify ONLY workspace crates under C:\\Users\\Fra\\Desktop\\RustRE\\crates\\rustre-* (mcp-tools or the specific domain crate).
- NEVER touch C:\\Users\\Fra\\Desktop\\mcp\\rustre-mcp\\ (legacy binary).
- NO #[allow] to silence warnings; NO panic!/todo!/unimplemented!.
- Do NOT delete dead code.
- Preserve existing tests.
- If the fix requires business logic, put it in the domain crate not the wrapper.

After the edit: return {"tool":..., "fixed": true|false, "file_edited":..., "summary":"one-line what changed and why"}`, {
    label: `fix:${bug.tool.replace(/[^a-z0-9_]/gi,'_').slice(0,40)}`,
    phase: 'Fix',
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
log(`Fix: ${applied}/${realBugs.length} fixes applied`)

if (applied === 0) {
  return { status: 'no_fixes_applied', before: BEFORE, after: BEFORE,
           real_bugs: realBugs.length, fixes: 0 }
}

// ─────── CONFIRM ───────
phase('Confirm')
const confirm = await agent(`Rebuild and re-validate. Report before/after.

Steps:
1. cd C:\\Users\\Fra\\Desktop\\RustRE
2. Run: cargo build --release --bin rustre-mcp (this takes 15-20 minutes; be patient, do NOT time out early)
3. If build fails, report failure with error excerpt.
4. If build succeeds, re-run each validator: python validation/validators_${'${cat}'}.py for each of these categories: ${CATEGORIES.map(c=>c.name).join(', ')}
5. Read each validation/mismatch_<cat>.json and aggregate the new total mismatch count.
6. Compare to BEFORE:
   - BEFORE total mismatches: ${allMismatches.length}
   - AFTER: <read from new mismatch json files>

Return: {"build_ok": bool, "before_mismatches": ${allMismatches.length}, "after_mismatches": <int>, "summary": "..."}`, {
    label: 'rebuild+revalidate',
    phase: 'Confirm',
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
  status: 'completed',
  categories_validated: good.length,
  before: BEFORE,
  real_bugs_confirmed: realBugs.length,
  fixes_applied: applied,
  confirm,
}
