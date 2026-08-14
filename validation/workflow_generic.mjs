export const meta = {
  name: 'rustre-generic-validation',
  description: 'Validate Rust library JSON endpoints against Python reference implementations',
  phases: [
    { title: 'Check', detail: 'Run per-category validators' },
    { title: 'Fix', detail: 'Correct library or validator' },
    { title: 'Verify', detail: 'Rebuild + retest' },
  ],
}

const CATEGORIES = [
  { name: 'demangle', file: 'validation/mismatch_demangle.json', script: 'validation/validators_demangle.py' },
  { name: 'stabs', file: 'validation/mismatch_stabs.json', script: 'validation/validators_stabs.py' },
  { name: 'patch', file: 'validation/mismatch_patch.json', script: 'validation/validators_patch.py' },
  { name: 'analysis_xref', file: 'validation/mismatch_analysis_xref.json', script: 'validation/validators_analysis_xref.py' },
  { name: 'script_rhai', file: 'validation/mismatch_script_rhai.json', script: 'validation/validators_script_rhai.py' },
  { name: 'triage_entropy', file: 'validation/mismatch_triage_entropy.json', script: 'validation/validators_triage_entropy.py' },
  { name: 'pe_editor', file: 'validation/mismatch_pe_editor.json', script: 'validation/validators_pe_editor.py' },
]

phase('Check')

const results = await parallel(CATEGORIES.map(r => () =>
  agent(`Analyze validation mismatches for module "${r.name}".

Read these two files:
- C:\\Users\\Fra\\Desktop\\RustRE\\${r.file} — list of value comparisons where Rust and Python disagreed
- C:\\Users\\Fra\\Desktop\\RustRE\\${r.script} — the Python validator that produced them

For each mismatch:
1. Find the Rust function source in C:\\Users\\Fra\\Desktop\\RustRE\\crates\\rustre-mcp-tools\\src\\wire_tools.rs (grep for the endpoint name)
2. Read the underlying implementation crate under crates/rustre-*
3. Compute the correct output yourself using Python stdlib (hashlib/zlib/struct/base64) or well-known algorithms
4. Classify each as one of:
   - "library_defect": the Rust code returns wrong output
   - "validator_defect": the Python reference was wrong

Return one entry per mismatch with file/line and a suggested fix.

Output: {module, items:[{tool,verdict:"library_defect"|"validator_defect",reason,file,line,fix_hint}], library_defects, validator_defects}`, {
    label: `check:${r.name}`,
    phase: 'Check',
    agentType: 're-validator',
    schema: {
      type: 'object',
      properties: {
        module: {type:'string'},
        items: {
          type:'array',
          items: {
            type:'object',
            properties: {
              tool: {type:'string'},
              verdict: {enum:['library_defect','validator_defect']},
              reason: {type:'string'},
              file: {type:'string'},
              line: {type:'integer'},
              fix_hint: {type:'string'}
            },
            required: ['tool','verdict','reason']
          }
        },
        library_defects: {type:'integer'},
        validator_defects: {type:'integer'}
      },
      required: ['module','items','library_defects','validator_defects']
    }
  })
))

const good = results.filter(Boolean)
const allItems = good.flatMap(r => r.items.map(i => ({...i, module: r.module})))
const libDefects = allItems.filter(i => i.verdict === 'library_defect')
const valDefects = allItems.filter(i => i.verdict === 'validator_defect')

log(`Check: ${libDefects.length} library defects, ${valDefects.length} validator defects`)

// FIX LIBRARY
if (libDefects.length > 0) {
  phase('Fix')
  for (const bug of libDefects) {
    await agent(`Fix a Rust library defect.

Endpoint: ${bug.tool}
Module: ${bug.module}
File: ${bug.file || '?'}${bug.line ? ':' + bug.line : ''}
Reason: ${bug.reason}
Suggested: ${bug.fix_hint || ''}

Constraints:
- Modify only files under C:\\Users\\Fra\\Desktop\\RustRE\\crates\\rustre-*
- Do not use #[allow], panic!, todo!, unimplemented!
- Preserve existing tests

Return: {tool, fixed, file_edited, summary}`, {
      label: `fix:${bug.tool.replace(/[^a-z0-9_]/gi,'_').slice(0,40)}`,
      phase: 'Fix',
      agentType: 're-validator',
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

// FIX VALIDATORS
if (valDefects.length > 0) {
  const byModule = {}
  for (const v of valDefects) { (byModule[v.module] ||= []).push(v) }

  await parallel(Object.entries(byModule).map(([mod, list]) => () =>
    agent(`Correct the Python validator for module "${mod}".

File: C:\\Users\\Fra\\Desktop\\RustRE\\validation\\validators_${mod}.py

Validator defects (${list.length}):
${JSON.stringify(list.map(f => ({tool: f.tool, reason: f.reason, hint: f.fix_hint})), null, 2)}

Task:
1. Read the validator file.
2. For each defect: correct the Python reference computation or skip the check with a clear comment.
3. Run: python validation/validators_${mod}.py
4. Confirm mismatch_${mod}.json shows fewer mismatches.

Return: {module, fixed_count, validator_ok, remaining, summary}`, {
      label: `fv:${mod}`,
      phase: 'Fix',
      agentType: 're-validator',
      schema: {
        type:'object',
        properties: {
          module:{type:'string'}, fixed_count:{type:'integer'},
          validator_ok:{type:'boolean'}, remaining:{type:'integer'},
          summary:{type:'string'}
        },
        required:['module','fixed_count']
      }
    })
  ))
}

// VERIFY
phase('Verify')
const verify = await agent(`Final verification.

1. If any .rs file was edited, rebuild: cd C:\\Users\\Fra\\Desktop\\RustRE; cargo build --release --bin rustre-mcp (wait patiently 15-20 min).
2. Re-run every validator: python validation/validators_<mod>.py for: demangle, stabs, patch, analysis_xref, script_rhai, triage_entropy, pe_editor
3. Count total mismatches from mismatch_<mod>.json.

Return: {build_ok, total_mismatches, per_module, summary}`, {
    label: 'verify',
    phase: 'Verify',
    agentType: 're-validator',
    schema: {
      type:'object',
      properties: {
        build_ok:{type:'boolean'}, total_mismatches:{type:'integer'},
        per_module:{}, summary:{type:'string'}
      },
      required:['total_mismatches']
    }
  })

return {
  status: 'complete',
  input_mismatches: 38,
  library_defects: libDefects.length,
  validator_defects: valDefects.length,
  final: verify
}
