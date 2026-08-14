export const meta = {
  name: 'rustre-mcp-iterate-to-zero',
  description: 'Read all validator mismatch reports, triage, fix, rebuild, re-run; iterate until zero mismatches',
  phases: [
    { title: 'Aggregate', detail: 'Collect all current mismatches' },
    { title: 'Triage', detail: 'Confirm real bugs' },
    { title: 'Fix', detail: 'Apply fixes in workspace crates' },
    { title: 'Rebuild+Retest', detail: 'Build and re-run every validator' },
    { title: 'Report', detail: 'Before/after summary' },
  ],
}

const CATEGORIES = ['hex_pattern','mem','crypto_id','deobf_crypto','forensics_compute','syscalls','fuzz_afl','gdb_packet','symbols_demangle','loader_pe',
                    'loader_elf','loader_macho','loader_java','loader_wasm','arch_wasm','arch_x86','symbols_pdb','dwarf','flirt','yara_engine','fuzz_cov','net_parse','net_rules','kgdb_gdb','codeview_pdb']

// STEP 1: aggregate current mismatches
phase('Aggregate')
const agg = await agent(`Aggregate current MCP validator mismatches.

For each of these categories, read C:\\Users\\Fra\\Desktop\\RustRE\\validation\\mismatch_<cat>.json if it exists and collect its mismatches array:
${CATEGORIES.join(', ')}

Return the full aggregated list with category attached:
{"total": <int>, "mismatches": [{"category":..., "tool":..., "input":..., "mcp":..., "truth":..., "note":...}]}`, {
  label: 'aggregate-mismatches',
  phase: 'Aggregate',
  schema: {
    type: 'object',
    properties: {
      total: { type: 'integer' },
      mismatches: {
        type: 'array',
        items: {
          type: 'object',
          properties: {
            category: {type:'string'}, tool: {type:'string'}, input: {},
            mcp: {}, truth: {}, note: {type:'string'}
          },
          required: ['tool']
        }
      }
    },
    required: ['total','mismatches']
  }
})

if (!agg || !agg.mismatches || agg.mismatches.length === 0) {
  return { status: 'nothing_to_do', totals: agg?.total ?? 0 }
}

const BEFORE = agg.mismatches.length
log(`Aggregated ${BEFORE} mismatches`)

// STEP 2: triage in parallel
phase('Triage')
const triaged = await parallel(agg.mismatches.slice(0, 60).map(m => () =>
  agent(`Triage MCP validator mismatch. Determine real_bug vs false_positive.

Tool: ${m.tool}
Category: ${m.category}
Input: ${JSON.stringify(m.input)}
MCP output: ${JSON.stringify(m.mcp)}
Python truth: ${JSON.stringify(m.truth)}
Note: ${m.note}

Steps:
1. Grep for the tool name in C:\\Users\\Fra\\Desktop\\RustRE\\crates\\rustre-mcp-tools\\src\\wire_tools.rs
2. Find the wire wrapper impl.
3. Follow to the underlying workspace crate impl if needed.
4. Compare wrapper/impl output vs the Python truth claim.
5. Verdict: real_bug (MCP wrong) or false_positive (validator wrong / edge case).

Return: {tool, verdict:"real_bug"|"false_positive", reason, file, line, fix_hint}`, {
    label: `triage:${m.tool.replace(/[^a-z0-9_]/gi,'_').slice(0,40)}`,
    phase: 'Triage',
    schema: {
      type: 'object',
      properties: {
        tool: { type: 'string' },
        verdict: { enum: ['real_bug','false_positive'] },
        reason: { type: 'string' },
        file: { type: 'string' },
        line: { type: 'integer' },
        fix_hint: { type: 'string' }
      },
      required: ['tool','verdict','reason']
    }
  })
))

const realBugs = triaged.filter(Boolean).filter(t => t.verdict === 'real_bug')
log(`Triage: ${realBugs.length} real bugs / ${triaged.filter(Boolean).length} triaged`)

if (realBugs.length === 0) {
  return { status: 'all_false_positives', before: BEFORE, triaged: triaged.filter(Boolean).length }
}

// STEP 3: fix serialized
phase('Fix')
const fixed = []
for (const bug of realBugs.slice(0, 50)) {
  const r = await agent(`Fix confirmed MCP bug — minimal change.

Tool: ${bug.tool}
File: ${bug.file || '?'}${bug.line ? ':' + bug.line : ''}
Reason: ${bug.reason}
Fix hint: ${bug.fix_hint || ''}

Rules (HARD):
- Only crates/rustre-* (workspace or mcp-tools)
- NEVER touch Desktop\\mcp\\rustre-mcp\\ (legacy)
- No #[allow], no panic/todo/unimplemented, no dead-code deletion
- Preserve existing tests
- Business logic in domain crate, not wrapper

Return: {tool, fixed, file_edited, summary}`, {
    label: `fix:${bug.tool.replace(/[^a-z0-9_]/gi,'_').slice(0,40)}`,
    phase: 'Fix',
    schema: {
      type: 'object',
      properties: {
        tool: { type: 'string' },
        fixed: { type: 'boolean' },
        file_edited: { type: 'string' },
        summary: { type: 'string' }
      },
      required: ['tool','fixed']
    }
  })
  if (r) fixed.push(r)
}

const applied = fixed.filter(f => f.fixed).length
log(`Fix: ${applied}/${realBugs.length} applied`)

if (applied === 0) return { status: 'no_fixes_applied', before: BEFORE, real_bugs: realBugs.length }

// STEP 4: rebuild + retest all validators
phase('Rebuild+Retest')
const rebuild = await agent(`Rebuild rustre-mcp release and re-run all validators. Do NOT skip categories.

1. cd C:\\Users\\Fra\\Desktop\\RustRE
2. cargo build --release --bin rustre-mcp  (wait 15-20 min, DO NOT timeout)
3. If build fails, capture error excerpt and return build_ok=false
4. For each category, run: python validation/validators_<cat>.py
   Categories: ${CATEGORIES.join(', ')}
5. For each, read validation/mismatch_<cat>.json and count mismatches
6. Aggregate after_total

Return: {build_ok, before: ${BEFORE}, after_total, per_category: {cat: count}, summary}`, {
  label: 'rebuild+retest',
  phase: 'Rebuild+Retest',
  schema: {
    type: 'object',
    properties: {
      build_ok: { type: 'boolean' },
      before: { type: 'integer' },
      after_total: { type: 'integer' },
      per_category: {},
      summary: { type: 'string' }
    },
    required: ['build_ok','before','after_total']
  }
})

phase('Report')
return {
  status: 'iteration_complete',
  before: BEFORE,
  real_bugs_confirmed: realBugs.length,
  fixes_applied: applied,
  after: rebuild?.after_total,
  delta: rebuild ? (BEFORE - rebuild.after_total) : null,
  rebuild
}
