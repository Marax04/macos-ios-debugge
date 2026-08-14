export const meta = {
  name: 'rustre-mcp-deepdive-v2',
  description: 'Deep-dive 7 residual categories: demangle, stabs, patch, analysis_xref, script_rhai, triage_entropy, pe_editor',
  phases: [
    { title: 'DeepDive', detail: 'Per-category exhaustive triage' },
    { title: 'FixTool', detail: 'Fix real MCP bugs' },
    { title: 'FixValidator', detail: 'Correct validator FPs' },
    { title: 'Verify', detail: 'Rebuild + retest all categories' },
  ],
}

const REMAINING = [
  { cat: 'demangle', file: 'validation/mismatch_demangle.json', script: 'validation/validators_demangle.py' },
  { cat: 'stabs', file: 'validation/mismatch_stabs.json', script: 'validation/validators_stabs.py' },
  { cat: 'patch', file: 'validation/mismatch_patch.json', script: 'validation/validators_patch.py' },
  { cat: 'analysis_xref', file: 'validation/mismatch_analysis_xref.json', script: 'validation/validators_analysis_xref.py' },
  { cat: 'script_rhai', file: 'validation/mismatch_script_rhai.json', script: 'validation/validators_script_rhai.py' },
  { cat: 'triage_entropy', file: 'validation/mismatch_triage_entropy.json', script: 'validation/validators_triage_entropy.py' },
  { cat: 'pe_editor', file: 'validation/mismatch_pe_editor.json', script: 'validation/validators_pe_editor.py' },
]

phase('DeepDive')

const results = await parallel(REMAINING.map(r => () =>
  agent(`Deep-dive on residual mismatches for category "${r.cat}".

Steps:
1. Read C:\\Users\\Fra\\Desktop\\RustRE\\${r.file} — list of mismatches.
2. Read C:\\Users\\Fra\\Desktop\\RustRE\\${r.script} — the validator.
3. For each mismatch, do BOTH:
   (a) Read MCP wire wrapper in crates/rustre-mcp-tools/src/wire_tools.rs (grep the tool name)
   (b) Read the domain crate impl
   (c) Independently compute the correct value with fresh Python reference (hashlib/zlib/base64/struct/rustc-demangle/cxxfilt/pefile).
4. For EACH mismatch decide:
   - "real_bug": MCP output wrong; specify file:line and root cause
   - "validator_fp": Python truth wrong; specify what validator got wrong
5. Return the list.

Env: MCP at C:\\Users\\Fra\\Desktop\\RustRE\\target\\release\\rustre-mcp.exe

Return: {category, items:[{tool,verdict,reason,file,line,fix_hint}], real_bugs, validator_fps}`, {
    label: `dd:${r.cat}`,
    phase: 'DeepDive',
    model: 'haiku',
    schema: {
      type: 'object',
      properties: {
        category: {type:'string'},
        items: {
          type:'array',
          items: {
            type:'object',
            properties: {
              tool: {type:'string'},
              verdict: {enum:['real_bug','validator_fp']},
              reason: {type:'string'},
              file: {type:'string'},
              line: {type:'integer'},
              fix_hint: {type:'string'}
            },
            required: ['tool','verdict','reason']
          }
        },
        real_bugs: {type:'integer'},
        validator_fps: {type:'integer'}
      },
      required: ['category','items','real_bugs','validator_fps']
    }
  })
))

const good = results.filter(Boolean)
const allItems = good.flatMap(r => r.items.map(i => ({...i, category: r.category})))
const realBugs = allItems.filter(i => i.verdict === 'real_bug')
const fps = allItems.filter(i => i.verdict === 'validator_fp')

log(`DeepDive: ${realBugs.length} real bugs, ${fps.length} FPs`)

// FIX TOOL
if (realBugs.length > 0) {
  phase('FixTool')
  for (const bug of realBugs) {
    await agent(`Fix confirmed MCP bug.

Tool: ${bug.tool}
Category: ${bug.category}
File: ${bug.file || '?'}${bug.line ? ':' + bug.line : ''}
Reason: ${bug.reason}
Fix hint: ${bug.fix_hint || ''}

Rules: crates/rustre-* only; no #[allow]; no panic/todo/unimplemented; no dead-code deletion.

Return: {tool, fixed, file_edited, summary}`, {
      label: `ft:${bug.tool.replace(/[^a-z0-9_]/gi,'_').slice(0,40)}`,
      phase: 'FixTool',
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

// FIX VALIDATOR
if (fps.length > 0) {
  phase('FixValidator')
  const byCategory = {}
  for (const fp of fps) { (byCategory[fp.category] ||= []).push(fp) }

  await parallel(Object.entries(byCategory).map(([cat, list]) => () =>
    agent(`Fix Python validator for category "${cat}" — correct/skip false positives.

Validator: C:\\Users\\Fra\\Desktop\\RustRE\\validation\\validators_${cat}.py

FPs (${list.length}):
${JSON.stringify(list.map(f => ({tool: f.tool, reason: f.reason, fix_hint: f.fix_hint})), null, 2)}

Task:
1. Read validator.
2. Correct ground truth or skip cleanly.
3. Run: python validation/validators_${cat}.py
4. Verify mismatch_${cat}.json shows 0 or fewer mismatches.

Return: {category, fps_addressed, validator_ok, remaining_mismatches, summary}`, {
      label: `fv:${cat}`,
      phase: 'FixValidator',
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
phase('Verify')
const verify = await agent(`Verify final state.

1. If any .rs file was edited, run: cd C:\\Users\\Fra\\Desktop\\RustRE; cargo build --release --bin rustre-mcp (WAIT patiently 15-20 min).
2. Re-run every validator: python validation/validators_<cat>.py for:
   demangle, stabs, patch, analysis_xref, script_rhai, triage_entropy, pe_editor
3. Read mismatch_<cat>.json for each; total.

Return: {build_ok, final_mismatches, per_category, summary}`, {
    label: 'verify-final',
    phase: 'Verify',
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
  status: 'deepdive_v2_complete',
  input_mismatches: 38,
  real_bugs: realBugs.length,
  validator_fps: fps.length,
  final: verify
}
