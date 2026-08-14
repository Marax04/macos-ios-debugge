export const meta = {
  name: 'rustre-mcp-deepdive-remaining',
  description: 'Deep-dive each remaining category: for every mismatch, decide real_bug vs validator_fp with adversarial verification, then fix root cause (tool or validator)',
  phases: [
    { title: 'DeepDive', detail: 'Per-category exhaustive analysis of residual mismatches' },
    { title: 'FixTool', detail: 'Apply MCP fixes for confirmed real bugs' },
    { title: 'FixValidator', detail: 'Fix Python validator for confirmed FP' },
    { title: 'Verify', detail: 'Rebuild+retest' },
  ],
}

const REMAINING = [
  { cat: 'flirt', file: 'validation/mismatch_flirt.json', script: 'validation/validators_flirt.py' },
  { cat: 'dwarf', file: 'validation/mismatch_dwarf.json', script: 'validation/validators_dwarf.py' },
  { cat: 'net_rules', file: 'validation/mismatch_net_rules.json', script: 'validation/validators_net_rules.py' },
  { cat: 'yara_engine', file: 'validation/mismatch_yara_engine.json', script: 'validation/validators_yara_engine.py' },
  { cat: 'fuzz_cov', file: 'validation/mismatch_fuzz_cov.json', script: 'validation/validators_fuzz_cov.py' },
  { cat: 'crypto_id', file: 'validation/mismatch_crypto_id.json', script: 'validation/validators_crypto_id.py' },
  { cat: 'gdb_packet', file: 'validation/mismatch_gdb_packet.json', script: 'validation/validators_gdb_packet.py' },
  { cat: 'loader_macho', file: 'validation/mismatch_loader_macho.json', script: 'validation/validators_loader_macho.py' },
  { cat: 'arch_x86', file: 'validation/mismatch_arch_x86.json', script: 'validation/validators_arch_x86.py' },
  { cat: 'net_parse', file: 'validation/mismatch_net_parse.json', script: 'validation/validators_net_parse.py' },
]

phase('DeepDive')

const results = await parallel(REMAINING.map(r => () =>
  agent(`Deep-dive on residual mismatches for category "${r.cat}".

Steps:
1. Read C:\\Users\\Fra\\Desktop\\RustRE\\${r.file} — list of current mismatches for this category.
2. Read C:\\Users\\Fra\\Desktop\\RustRE\\${r.script} — the validator you'll assess.
3. For each mismatch, do BOTH:
   (a) Read the MCP wire wrapper in crates/rustre-mcp-tools/src/wire_tools.rs (grep the tool name)
   (b) Read the domain crate impl it calls
   (c) Independently compute the correct value using a fresh Python reference (write it inline in your reasoning, or use pip modules like pefile/lief/pyelftools/hashlib/zlib/base64/struct/rustc-demangle/cxxfilt)
4. For EACH mismatch decide:
   - "real_bug": MCP output is wrong; specify file:line and root cause
   - "validator_fp": Python truth was wrong or misunderstood the tool; specify what the validator got wrong
5. Return the list, plus a proposed change to the validator script for the FP cases (as unified-diff-friendly hints).

Environment note: MCP binary at C:\\Users\\Fra\\Desktop\\RustRE\\target\\release\\rustre-mcp.exe; target file for real bytes: C:\\Users\\Fra\\Desktop\\Zyphora\\target\\release\\cargo-zyphora.exe (PE64).

Return: {
  "category": "${r.cat}",
  "items": [
     { "tool": ..., "verdict": "real_bug"|"validator_fp", "reason": ..., "file": (if real_bug), "line": (if real_bug), "fix_hint": (tool fix or validator fix) }
  ],
  "real_bugs": <int>,
  "validator_fps": <int>
}`, {
    label: `deepdive:${r.cat}`,
    phase: 'DeepDive',
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

log(`DeepDive: ${realBugs.length} real bugs, ${fps.length} validator FPs across ${allItems.length} items`)

// FIX TOOL for real bugs
if (realBugs.length > 0) {
  phase('FixTool')
  for (const bug of realBugs) {
    await agent(`Fix confirmed MCP bug.

Tool: ${bug.tool}
Category: ${bug.category}
File: ${bug.file || '?'}${bug.line ? ':' + bug.line : ''}
Reason: ${bug.reason}
Fix hint: ${bug.fix_hint || ''}

HARD Rules:
- Only crates/rustre-* workspace code
- NEVER touch Desktop\\mcp\\rustre-mcp\\
- No #[allow], no panic/todo/unimplemented, no dead-code deletion
- Business logic in domain crate

Return: {tool, fixed, file_edited, summary}`, {
      label: `fix_tool:${bug.tool.replace(/[^a-z0-9_]/gi,'_').slice(0,40)}`,
      phase: 'FixTool',
      schema: {
        type:'object',
        properties: {
          tool: {type:'string'},
          fixed: {type:'boolean'},
          file_edited: {type:'string'},
          summary: {type:'string'}
        },
        required:['tool','fixed']
      }
    })
  }
}

// FIX VALIDATOR for FPs
if (fps.length > 0) {
  phase('FixValidator')
  const byCategory = {}
  for (const fp of fps) { (byCategory[fp.category] ||= []).push(fp) }

  for (const [cat, fpList] of Object.entries(byCategory)) {
    await agent(`Fix Python validator for category "${cat}" — remove or correct false-positive checks.

Validator file: C:\\Users\\Fra\\Desktop\\RustRE\\validation\\validators_${cat}.py

False positives to fix (${fpList.length}):
${JSON.stringify(fpList.map(f => ({tool: f.tool, reason: f.reason, fix_hint: f.fix_hint})), null, 2)}

Task:
1. Read the current validator script.
2. For each FP: either correct the ground-truth computation, or skip the check with a clear log/comment explaining why.
3. Rewrite the script.
4. Run: python validation/validators_${cat}.py
5. Verify the fixed check now passes (or is cleanly skipped).

Return: {category, fps_addressed, validator_ok, remaining_mismatches, summary}`, {
      label: `fix_validator:${cat}`,
      phase: 'FixValidator',
      schema: {
        type:'object',
        properties: {
          category: {type:'string'},
          fps_addressed: {type:'integer'},
          validator_ok: {type:'boolean'},
          remaining_mismatches: {type:'integer'},
          summary: {type:'string'}
        },
        required:['category','fps_addressed']
      }
    })
  }
}

// VERIFY
phase('Verify')
const verify = await agent(`Verify final state.

1. If any Rust file was edited during this workflow, run: cd C:\\Users\\Fra\\Desktop\\RustRE; cargo build --release --bin rustre-mcp (~15 min; wait patiently)
2. Re-run every validator: python validation/validators_<cat>.py for these categories:
   flirt, dwarf, net_rules, yara_engine, fuzz_cov, crypto_id, gdb_packet, loader_macho, arch_x86, net_parse
3. Read validation/mismatch_<cat>.json for each and count total remaining mismatches.

Return: {build_ok, final_mismatches, per_category: {cat:count}, summary}`, {
  label: 'final-verify',
  phase: 'Verify',
  schema: {
    type:'object',
    properties: {
      build_ok: {type:'boolean'},
      final_mismatches: {type:'integer'},
      per_category: {},
      summary: {type:'string'}
    },
    required: ['final_mismatches']
  }
})

return {
  status: 'deepdive_complete',
  input_mismatches: 32,
  real_bugs_found: realBugs.length,
  validator_fps: fps.length,
  final: verify
}
