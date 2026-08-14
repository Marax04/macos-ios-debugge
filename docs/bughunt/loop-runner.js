export const meta = {
  name: 'rustre-loop',
  description: 'Robust continuous bug-hunt + optimization + release-build iteration',
  phases: [
    { title: 'Hunt' },
    { title: 'Verify' },
    { title: 'Fix' },
    { title: 'Optimize' },
    { title: 'Build' },
    { title: 'Persist' },
  ],
}

const ROOT = 'C:/Users/Fra/Desktop/RustRE'
const STATE = `${ROOT}/docs/bughunt/state.json`

const ALL_CRATES = [
  'rustre-adb','rustre-agent','rustre-agent-llm','rustre-agent-prompts','rustre-agent-workflow',
  'rustre-analysis','rustre-analysis-callconv','rustre-analysis-cfg','rustre-analysis-dataflow',
  'rustre-analysis-fn','rustre-analysis-string','rustre-analysis-type','rustre-analysis-vsa',
  'rustre-analysis-vtable','rustre-analysis-xref','rustre-arch','rustre-arch-6502','rustre-arch-68k',
  'rustre-arch-arm','rustre-arch-arm64','rustre-arch-avr','rustre-arch-bpf','rustre-arch-cil',
  'rustre-arch-dex','rustre-arch-jvm','rustre-arch-lua','rustre-arch-luajit','rustre-arch-mips',
  'rustre-arch-msp430','rustre-arch-ppc','rustre-arch-riscv','rustre-arch-sparc','rustre-arch-wasm',
  'rustre-arch-x86','rustre-arch-z80','rustre-bin','rustre-cli','rustre-core','rustre-crypto-id',
  'rustre-crypto-oracle','rustre-crypto-whitebox','rustre-daemon','rustre-debug','rustre-debug-frida',
  'rustre-debug-gdb','rustre-debug-kgdb','rustre-debug-linux','rustre-debug-macos','rustre-debug-unicorn',
  'rustre-debug-windbg','rustre-debug-windows','rustre-decompiler','rustre-decompiler-c',
  'rustre-decompiler-cfs','rustre-decompiler-expr','rustre-decompiler-ghidra','rustre-decompiler-type',
  'rustre-demangle','rustre-deobf','rustre-deobf-antianti','rustre-deobf-cff','rustre-deobf-iadl',
  'rustre-deobf-mba','rustre-deobf-mhcde','rustre-deobf-opaque','rustre-deobf-smc','rustre-deobf-string',
  'rustre-deobf-vm','rustre-deobf-vmlift','rustre-diff','rustre-diff-bindiff','rustre-diff-semantic',
  'rustre-dotnet','rustre-dotnet-decompile','rustre-dotnet-edit','rustre-dotnet-metadata','rustre-emu',
  'rustre-emu-qiling','rustre-emu-shellcode','rustre-emu-unicorn','rustre-events','rustre-flirt',
  'rustre-flirt-apply','rustre-flirt-gen','rustre-forensics','rustre-forensics-fs','rustre-forensics-mem',
  'rustre-forensics-plugins','rustre-fuzz','rustre-fuzz-afl','rustre-fuzz-cov','rustre-fuzz-libfuzzer',
  'rustre-fuzz-net','rustre-fuzz-sanitizers','rustre-graph','rustre-hex','rustre-hex-pattern',
  'rustre-hex-template','rustre-hex-view','rustre-il-hlil','rustre-il-lift','rustre-il-llil',
  'rustre-il-mlil','rustre-il-passes','rustre-loader','rustre-loader-android','rustre-loader-console',
  'rustre-loader-dotnet','rustre-loader-elf','rustre-loader-firmware','rustre-loader-java',
  'rustre-loader-lua','rustre-loader-luajit','rustre-loader-macho','rustre-loader-ole','rustre-loader-pdf',
  'rustre-loader-pe','rustre-loader-wasm','rustre-mcp','rustre-mcp-federation','rustre-mcp-server',
  'rustre-mcp-tools','rustre-mem','rustre-mobile-android','rustre-mobile-apktool','rustre-mobile-dyld',
  'rustre-mobile-ios','rustre-mobile-ipa','rustre-mobile-jadx','rustre-mobile-smali','rustre-net',
  'rustre-net-dissect','rustre-net-pcap','rustre-net-proxy','rustre-net-rules','rustre-pe-editor',
  'rustre-pe-rebuild','rustre-pe-tools','rustre-plugin-api','rustre-plugin-host','rustre-project',
  'rustre-sandbox','rustre-sandbox-extract','rustre-sandbox-monitor','rustre-sandbox-report',
  'rustre-sandbox-vm','rustre-script','rustre-script-lua','rustre-script-python','rustre-script-rhai',
  'rustre-symb','rustre-symb-engine','rustre-symb-taint','rustre-symb-z3','rustre-symbols',
  'rustre-symbols-codeview','rustre-symbols-dwarf','rustre-symbols-pdb','rustre-symbols-stabs',
  'rustre-syscalls','rustre-syscalls-linux','rustre-syscalls-windows','rustre-sysinternals',
  'rustre-threatintel','rustre-ti-correlate','rustre-ti-malpedia','rustre-ti-misp','rustre-ti-vt',
  'rustre-trace','rustre-trace-coresight','rustre-trace-coverage','rustre-trace-navigate','rustre-trace-pt',
  'rustre-triage','rustre-triage-die','rustre-triage-entropy','rustre-triage-peid','rustre-triage-yara',
  'rustre-ttd','rustre-ttd-query','rustre-ttd-recorder','rustre-ttd-replay','rustre-ttd-replayer',
  'rustre-yara','rustre-yara-engine','rustre-yara-rules',
]

// Read iteration counter via a no-schema agent (text response is more reliable than StructuredOutput)
async function readIteration() {
  try {
    const txt = await agent(
      `Read the file ${STATE} with the Read tool and output ONLY the value of the "iteration" field as a bare integer (no JSON, no prose, just the number). If the file doesn't exist or has no iteration, output 0.`,
      { phase: 'Hunt', label: 'read-iter' }
    )
    const n = parseInt(String(txt ?? '').trim().match(/\d+/)?.[0] ?? '0', 10)
    return Number.isFinite(n) ? n : 0
  } catch (e) { return 0 }
}

async function safe(fn) {
  try { return await fn() } catch (e) { return null }
}

const iteration = await readIteration()
const BATCH_SIZE = 20
const start = (iteration * BATCH_SIZE) % ALL_CRATES.length
const batch = []
for (let i = 0; i < BATCH_SIZE; i++) batch.push(ALL_CRATES[(start + i) % ALL_CRATES.length])
log(`Iteration ${iteration} | batch[${start}..]: ${batch.slice(0, 5).join(', ')}…`)

phase('Hunt')
// Single combined hunter per crate — no schema, plain text output that we parse loosely.
const hunts = await parallel(batch.map(c => () => safe(() => agent(
  `Hunt bugs in crate ${ROOT}/crates/${c}/. Read src/**/*.rs files.
Look for: logic errors, off-by-one, wrong endianness, missing bounds checks, unwrap/panic in lib code, unsafe soundness, concurrency issues, integer overflow/truncation, security (path traversal, injection, deserialization).
Output format: ONE bug per line, format:
SEVERITY|crate|file:line|category|short title|one-sentence why
Use SEVERITY in {CRIT,HIGH,MED,LOW}. Output up to 6 bugs. If none, output exactly "NONE". No prose, no markdown, no preamble.`,
  { phase: 'Hunt', label: `hunt:${c}` }
))))

// Parse text findings
const findings = []
for (const txt of hunts) {
  if (!txt || typeof txt !== 'string') continue
  for (const line of txt.split('\n')) {
    const m = line.match(/^(CRIT|HIGH|MED|LOW)\|([^|]+)\|([^|]+)\|([^|]+)\|([^|]+)\|(.+)$/)
    if (m) findings.push({
      severity: m[1].toLowerCase().replace('crit','critical').replace('med','medium'),
      crate: m[2].trim(), file: m[3].trim(), category: m[4].trim(),
      title: m[5].trim(), description: m[6].trim(),
    })
  }
}
log(`Parsed ${findings.length} findings`)

phase('Verify')
// Single-agent text verify, default-skeptical
const verified = await parallel(findings.map((f, i) => () => safe(async () => {
  const txt = await agent(
    `Verify bug claim. Read ${ROOT}/${f.file.split(':')[0].replace(/^.*?crates\//, 'crates/')} or under ${ROOT}/crates/${f.crate}/. Decide if the bug is real and reachable.
Bug: ${f.title} — ${f.description}
Output a single line: REAL or FAKE. Nothing else.`,
    { phase: 'Verify', label: `v:${i}:${f.crate}` }
  )
  return { ...f, real: /REAL/i.test(String(txt ?? '')) }
})))
const confirmed = verified.filter(Boolean).filter(v => v.real)
log(`${confirmed.length}/${findings.length} confirmed`)

phase('Fix')
const toFix = confirmed.slice(0, 25)
const fixes = await parallel(toFix.map((b, i) => () => safe(async () => {
  const txt = await agent(
    `Apply minimal fix in ${ROOT}.
Bug: ${b.title}
File: ${b.file} (crate ${b.crate})
Description: ${b.description}

Steps:
1. Read the file, find the exact line.
2. Use Edit to apply the smallest correct change. Do NOT add #[allow(...)], do NOT silence warnings.
3. Run: cargo check -p ${b.crate} --message-format short 2>&1 | tail -30
4. If it fails to compile, revert your Edit (apply the inverse Edit) and report FAILED.
5. Output exactly one line: APPLIED or REVERTED or FAILED. No prose.`,
    { phase: 'Fix', label: `fix:${i}:${b.crate}` }
  )
  return { bug: b, status: String(txt ?? '').trim().split('\n').pop() }
})))
const applied = fixes.filter(Boolean).filter(f => /APPLIED/i.test(f.status))
log(`Applied ${applied.length} fixes`)

phase('Optimize')
// Optimization pass on this batch's crates — perf hotspots, allocation, async patterns
const optimizations = await parallel(batch.slice(0, 10).map(c => () => safe(async () => {
  const txt = await agent(
    `Audit ${ROOT}/crates/${c}/src/ for performance/quality optimizations.
Look for: needless clones, Vec::push in tight loops without with_capacity, String allocation in hot paths, blocking I/O in async, Arc<Mutex<T>> where RwLock or per-task ownership would do, missing #[inline] on tiny hot functions, repeated HashMap lookups, eager collect() before iter chains.

For each high-confidence improvement, apply it with Edit. DO NOT use #[allow(...)]. After edits, run \`cargo check -p ${c} --message-format short 2>&1 | tail -20\`. If broken, revert.
Output: comma-separated list of "file:line description" for applied optimizations, or "NONE".`,
    { phase: 'Optimize', label: `opt:${c}` }
  )
  return { crate: c, applied: String(txt ?? '').trim() }
})))
const optimized = optimizations.filter(Boolean).filter(o => o.applied && o.applied !== 'NONE')
log(`Optimizations on ${optimized.length} crates`)

phase('Build')
// Build release, parse warnings/errors, fix any that exist
const buildOutput = await safe(() => agent(
  `Build the entire RustRE workspace in release.
Run: cd ${ROOT} && cargo build --workspace --release --exclude rustre-gui --message-format short 2>&1 | tail -200

Capture warnings (lines with "warning:") and errors (lines with "error"). Output JUST the captured warnings+errors text, one per line. If clean, output "CLEAN".`,
  { phase: 'Build', label: 'release-build' }
))

let buildIssues = []
if (buildOutput && typeof buildOutput === 'string' && !/^CLEAN/i.test(buildOutput)) {
  buildIssues = buildOutput.split('\n').filter(l => /warning:|error\[|error:/.test(l)).slice(0, 30)
}
log(`Build: ${buildIssues.length} warnings/errors`)

if (buildIssues.length > 0) {
  await parallel(buildIssues.map((issue, i) => () => safe(() => agent(
    `Fix this Rust build warning/error in ${ROOT}. NO #[allow(...)] — make the real fix.
Issue: ${issue}

Read the cited file:line, apply a minimal correct Edit. Then verify with \`cargo check --workspace --message-format short 2>&1 | grep -c "warning:\\|error"\`.
Output one line: FIXED or SKIPPED. No prose.`,
    { phase: 'Build', label: `wfix:${i}` }
  ))))
}

phase('Persist')
await safe(() => agent(
  `Update bug-hunt state.
1. Read ${STATE} (with Read tool). Parse JSON.
2. Bump iteration by 1. Add ${applied.length} to fixed_count. Add ${confirmed.length} to confirmed_count.
3. Write back the JSON to ${STATE} using Write.
4. Append to ${ROOT}/docs/bughunt/iteration-log.md a section:

## Iteration ${iteration}
- Batch: ${batch.join(', ')}
- Findings: ${findings.length}, Confirmed: ${confirmed.length}, Fixed: ${applied.length}
- Optimizations applied on crates: ${optimized.map(o => o.crate).join(', ') || 'none'}
- Build issues remaining: ${buildIssues.length}
- Confirmed bug titles:
${confirmed.map(c => `  - [${c.severity}] ${c.crate} ${c.file} — ${c.title}`).join('\n')}

5. Append confirmed bugs as one JSON object per line to ${ROOT}/docs/bughunt/confirmed.jsonl. Data: ${JSON.stringify(confirmed).slice(0, 40000)}
6. Append applied fixes to ${ROOT}/docs/bughunt/fixed.jsonl. Data: ${JSON.stringify(applied.map(a => a.bug)).slice(0, 20000)}

Output exactly: OK`,
  { phase: 'Persist', label: 'persist' }
))

return {
  iteration,
  batch_start: start,
  findings: findings.length,
  confirmed: confirmed.length,
  applied: applied.length,
  optimized_crates: optimized.length,
  build_issues_after_fix: buildIssues.length,
}
