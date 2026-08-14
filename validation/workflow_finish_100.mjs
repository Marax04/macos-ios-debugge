export const meta = {
  name: 'finish-to-100pct',
  description: 'Fix decompiler bottlenecks + convert loose to rigorous + fix broken tests + expand findcrypt',
  phases: [
    { title: 'DecompilerFix', detail: 'Wire CFS if/while, PDB call resolution, function dedup' },
    { title: 'BrokenTestsFix', detail: 'Fix 3 broken crate integration tests' },
    { title: 'FullBuild', detail: 'Rebuild release binary after fixes' },
    { title: 'RigorousChecks', detail: 'Convert loose validators to rigorous ground truth' },
    { title: 'FinalScore', detail: 'Re-run decompiler quality + e2e + report' },
  ],
}

// ── Phase 1: Decompiler bottleneck fixes (parallel independent tasks) ──
phase('DecompilerFix')
const decompFixes = await parallel([
  () => agent(`Improve control flow emission in the Rust library at C:\\Users\\Fra\\Desktop\\RustRE.

Context:
- The pseudo-C output of decompile.function currently emits sequential statements even for functions with branches.
- Goal: for functions where conditional branches (jne/je/etc) exist in the disassembly, the emitted C should show 'if (cond) { ... } else { ... }' instead of goto-soup.

Investigate:
- crates/rustre-decompiler/src/lib.rs — look at build_cfg_from_instructions (line ~680), emit_structured_code (line ~3800)
- crates/rustre-decompiler-cfs/src/lib.rs — ControlFlowStructurer
- crates/rustre-decompiler-c/src/lib.rs — CPrinter emits StructuredNode::If/IfElse/Loop

Task:
- The ControlFlowStructurer takes blocks and returns an AST. But even when blocks have proper predecessors/successors (with parse_branch_stmt fusion), the resulting AST rarely contains If/While nodes for our target binary.
- Find why the structurer bails to raw goto blocks in most cases.
- Fix it. A test binary is at C:\\Users\\Fra\\Desktop\\Zyphora\\target\\release\\cargo-zyphora.exe.
- After code change, run: cd C:\\Users\\Fra\\Desktop\\RustRE && cargo build --release --bin rustre-mcp (wait patiently 15-20 min).
- Then run: python validation/decomp_quality_score_v2.py and report the score delta.

Rules:
- Modify only crates/rustre-* code, no #[allow], no panic!/todo!/unimplemented!
- Keep existing tests passing
- Report: {file_edited, lines_changed_approx, control_flow_pct_before, control_flow_pct_after, notes}`,
  {
    label: 'fix:control-flow-emission',
    phase: 'DecompilerFix',
    agentType: 're-validator',
    schema: {
      type: 'object',
      properties: {
        file_edited: {type:'string'},
        lines_changed_approx: {type:'integer'},
        control_flow_pct_before: {type:'number'},
        control_flow_pct_after: {type:'number'},
        notes: {type:'string'},
      },
      required: ['file_edited','notes']
    }
  }),

  () => agent(`Improve function-call name resolution in the Rust library at C:\\Users\\Fra\\Desktop\\RustRE.

Context:
- The pseudo-C output currently prints calls as sub_140F1450() etc. Very rarely resolves to real names like mainCRTStartup.
- A SymbolMap is built from name_store at crates/rustre-mcp-server/src/lib.rs line ~4760 and attached to pipeline via set_symbol_resolver.
- name_store is populated from PDB via reader.symbols() AND reader.module_proc_symbols() at line ~1538.
- module_proc_symbols yields (segment, code_offset) which needs conversion to VA using PE sections.

Investigate:
- Whether the addresses in name_store actually match the addresses the decompiler prints as sub_HEX
- If not, why. Compare a sample: PDB proc addresses vs sub_HEX call targets in decomp output on cargo-zyphora.exe

Task:
- Fix the address mismatch so at least 30% of sub_HEX calls resolve to real names.
- The target binary is C:\\Users\\Fra\\Desktop\\Zyphora\\target\\release\\cargo-zyphora.exe (PE64, image_base 0x140000000).
- After code change, rebuild: cd C:\\Users\\Fra\\Desktop\\RustRE && cargo build --release --bin rustre-mcp
- Then run python validation/decomp_quality_score_v2.py — the 5_call_resolve criterion should climb from 7% to 30%+.

Rules:
- crates/rustre-* only, no #[allow], no panic
- Keep existing tests passing
- Report: {file_edited, call_resolve_pct_before, call_resolve_pct_after, notes}`,
  {
    label: 'fix:pdb-call-resolution',
    phase: 'DecompilerFix',
    agentType: 're-validator',
    schema: {
      type: 'object',
      properties: {
        file_edited: {type:'string'},
        call_resolve_pct_before: {type:'number'},
        call_resolve_pct_after: {type:'number'},
        notes: {type:'string'},
      },
      required: ['file_edited','notes']
    }
  }),

  () => agent(`Reduce function over-detection in the Rust library at C:\\Users\\Fra\\Desktop\\RustRE.

Context:
- The function detector at crates/rustre-analysis-fn/src/lib.rs currently emits 2336 candidates for cargo-zyphora.exe.
- IDA reports 1456 for the same binary. The extra ~880 candidates are overlapping detections of the same function by HeuristicGap and ProloguePattern.
- Example: 0x140000000 (HeuristicGap, Low) and 0x14000040a (ProloguePattern, Medium) are both flagged, but 0x14000040a is inside the range of 0x140000000.

Task:
- Add a dedup pass on FunctionBoundarySet that removes any Low-confidence entry whose range fully contains a Medium+ entry (i.e., the low one is a false-positive over-approximation).
- After code change, rebuild: cd C:\\Users\\Fra\\Desktop\\RustRE && cargo build --release --bin rustre-mcp
- Then verify: python -c "..." pattern — call analyze.function via MCP and count. Target: <1800 unique.

Rules:
- crates/rustre-analysis-fn/* only, no #[allow], no panic
- Keep existing unit tests passing
- Report: {file_edited, count_before, count_after, notes}`,
  {
    label: 'fix:function-dedup',
    phase: 'DecompilerFix',
    agentType: 're-validator',
    schema: {
      type: 'object',
      properties: {
        file_edited: {type:'string'},
        count_before: {type:'integer'},
        count_after: {type:'integer'},
        notes: {type:'string'},
      },
      required: ['file_edited','notes']
    }
  }),
])

log(`DecompilerFix: ${decompFixes.filter(Boolean).length}/3 agents completed`)

// ── Phase 2: Fix 3 broken crate tests ──
phase('BrokenTestsFix')
const testFixes = await parallel([
  () => agent(`Fix compile-time drift in a Rust integration test file.

File: C:\\Users\\Fra\\Desktop\\RustRE\\crates\\rustre-project\\tests\\blitz2.rs
Issue: cargo test --package rustre-project --test blitz2 fails to compile with errors about types.

Steps:
1. cd C:\\Users\\Fra\\Desktop\\RustRE && cargo test --package rustre-project --test blitz2 --no-run 2>&1 | head -30
2. Read the error messages, identify the API drift between the test and the current library.
3. Update the TEST file (not the library) to match the current API. Don't change the library semantics.
4. Verify: cargo test --package rustre-project --test blitz2 --no-run  should exit 0.

Rules:
- Only modify test files. No library changes.
- Report: {errors_before, errors_after, changes_summary}`,
  {
    label: 'fix:test-rustre-project',
    phase: 'BrokenTestsFix',
    agentType: 're-validator',
    schema: {
      type: 'object',
      properties: {
        errors_before: {type:'integer'},
        errors_after: {type:'integer'},
        changes_summary: {type:'string'},
      },
      required: ['changes_summary']
    }
  }),

  () => agent(`Fix compile-time drift in a Rust integration test file.

File: C:\\Users\\Fra\\Desktop\\RustRE\\crates\\rustre-flirt-gen\\tests\\blitz.rs
Issue: cargo test --package rustre-flirt-gen --test blitz fails to compile.

Steps:
1. cd C:\\Users\\Fra\\Desktop\\RustRE && cargo test --package rustre-flirt-gen --test blitz --no-run 2>&1 | head -30
2. Read the error messages, identify the API drift between the test and the current library.
3. Update the TEST file (not the library) to match the current API. Don't change library semantics.
4. Verify: cargo test --package rustre-flirt-gen --test blitz --no-run should exit 0.

Rules:
- Only modify test files.
- Report: {errors_before, errors_after, changes_summary}`,
  {
    label: 'fix:test-rustre-flirt-gen',
    phase: 'BrokenTestsFix',
    agentType: 're-validator',
    schema: {
      type: 'object',
      properties: {
        errors_before: {type:'integer'},
        errors_after: {type:'integer'},
        changes_summary: {type:'string'},
      },
      required: ['changes_summary']
    }
  }),

  () => agent(`Fix compile-time drift in a Rust integration test file.

File: C:\\Users\\Fra\\Desktop\\RustRE\\crates\\rustre-il-hlil\\tests\\blitz.rs (integration test)
And also: crates\\rustre-il-hlil (lib test) — may have missing hlil_function_to_json etc.

Issue: cargo test --package rustre-il-hlil fails to compile.

Steps:
1. cd C:\\Users\\Fra\\Desktop\\RustRE && cargo test --package rustre-il-hlil --no-run 2>&1 | head -40
2. For each error, identify if it's a test-side or library-side drift.
   - If TEST calls a non-existent function or with wrong signature: fix the TEST.
   - If library REMOVED a public API the test needs: add back a minimal wrapper (safe re-export or thin fn) that satisfies the test without changing library semantics.
3. Iterate until: cargo test --package rustre-il-hlil --no-run exits 0.

Rules:
- Prefer fixing tests over adding library API. Only add lib API if the test genuinely tests a missing feature.
- Report: {errors_before, errors_after, changes_summary, files_edited}`,
  {
    label: 'fix:test-rustre-il-hlil',
    phase: 'BrokenTestsFix',
    agentType: 're-validator',
    schema: {
      type: 'object',
      properties: {
        errors_before: {type:'integer'},
        errors_after: {type:'integer'},
        changes_summary: {type:'string'},
        files_edited: {type:'array', items:{type:'string'}},
      },
      required: ['changes_summary']
    }
  }),
])

log(`BrokenTestsFix: ${testFixes.filter(Boolean).length}/3 agents completed`)

// ── Phase 3: Full rebuild ──
phase('FullBuild')
const build = await agent(`Rebuild the release binary and verify the workspace still compiles.

Steps:
1. cd C:\\Users\\Fra\\Desktop\\RustRE
2. Kill any running rustre-mcp.exe: powershell -c "Get-Process -Name rustre-mcp,cargo,rustc -EA SilentlyContinue | Stop-Process -Force"
3. cargo build --release --bin rustre-mcp 2>&1 | Out-File -Encoding utf8 validation/build_after_fixes.log
4. Check errors: powershell -c "(Select-String -Path validation/build_after_fixes.log -Pattern '^error' | Measure-Object).Count"
5. If errors, report them and try to fix. Iterate up to 2 times.

Wait patiently — the build takes 15-20 min. Do NOT time out.

Return: {build_ok, errors, warnings_count, elapsed_min}`,
{
  label: 'fullbuild',
  phase: 'FullBuild',
  agentType: 're-validator',
  schema: {
    type: 'object',
    properties: {
      build_ok: {type:'boolean'},
      errors: {type:'integer'},
      warnings_count: {type:'integer'},
      elapsed_min: {type:'integer'},
    },
    required: ['build_ok']
  }
})

// ── Phase 4: Convert loose to rigorous checks ──
phase('RigorousChecks')
const CATEGORIES_TO_HARDEN = [
  'arch_wasm', 'arch_x86', 'callconv', 'codeview', 'db_base',
  'dotnet_edit', 'dotnet_metadata', 'events', 'flirt_apply', 'flirt_gen',
  'fuzz_afl', 'fuzz_cov', 'fuzz_libfuzzer', 'fuzz_net', 'fuzz_san',
  'gdb', 'ghidra', 'hex_pattern', 'il_lift', 'kgdb',
  'loader', 'mem', 'net_dissect', 'net_proxy', 'net_rules',
  'symbols_v6', 'symb_engine', 'symb_z3', 'trace_coverage',
  'ttd_query', 'ttd_replay', 'yara',
]

const hardened = await parallel(CATEGORIES_TO_HARDEN.map(cat => () =>
  agent(`Convert loose validator checks to rigorous ones for the module '${cat}'.

Context:
- A Python validator exists at C:\\Users\\Fra\\Desktop\\RustRE\\validation\\validators_${cat}*.py (may be several batches).
- Currently many checks use any_valid() — a loose check that just verifies the response is non-empty.
- Goal: for at least 10 tools in the module, replace loose checks with rigorous ones that verify the response value matches an independently computed Python truth (using hashlib, zlib, struct, base64, or literal known values).

Steps:
1. Read all validators_${cat}*.py files.
2. Identify tools currently using any_valid() with well-known algorithms or constants.
3. For each: replace the loose check with a real comparison against an independent Python calculation.
4. Run the modified validator and confirm all rigorous checks pass.
5. Save the report as validation/rigorous_${cat}.json summarizing: {tools_hardened, before_loose_count, after_rigorous_count, mismatches_found}

Rules:
- Do NOT edit .rs files.
- If you find a real mismatch (Rust wrong vs Python truth), record it — do not hide it.
- The MCP binary is at target/release/rustre-mcp.exe

Return: {module, tools_hardened, mismatches_found, notes}`,
  {
    label: `harden:${cat}`,
    phase: 'RigorousChecks',
    agentType: 're-validator',
    schema: {
      type: 'object',
      properties: {
        module: {type:'string'},
        tools_hardened: {type:'integer'},
        mismatches_found: {type:'integer'},
        notes: {type:'string'},
      },
      required: ['module','tools_hardened','mismatches_found']
    }
  })
))

const totalHardened = hardened.filter(Boolean).reduce((s,r) => s + (r.tools_hardened || 0), 0)
const totalMismatches = hardened.filter(Boolean).reduce((s,r) => s + (r.mismatches_found || 0), 0)
log(`RigorousChecks: ${totalHardened} tools hardened, ${totalMismatches} real mismatches found`)

// ── Phase 5: Final scoring ──
phase('FinalScore')
const final = await agent(`Run the final scoring on the improved system.

Steps:
1. cd C:\\Users\\Fra\\Desktop\\RustRE
2. Run: python validation/decomp_quality_score_v2.py > validation/FINAL_SCORE.txt
3. Run: python validation/e2e_full_decompile.py > validation/FINAL_E2E.txt
4. Extract: decomp score, findcrypt hits, PDB overlap, function count.

Return: {decomp_score, findcrypt_hits, pdb_overlap, function_count, notes}`,
{
  label: 'final-score',
  phase: 'FinalScore',
  agentType: 're-validator',
  schema: {
    type: 'object',
    properties: {
      decomp_score: {type:'number'},
      findcrypt_hits: {type:'integer'},
      pdb_overlap: {type:'integer'},
      function_count: {type:'integer'},
      notes: {type:'string'},
    },
    required: ['notes']
  }
})

return {
  status: 'workflow_complete',
  decomp_fixes: decompFixes.filter(Boolean).length,
  test_fixes: testFixes.filter(Boolean).length,
  build_ok: build?.build_ok,
  tools_hardened: totalHardened,
  real_mismatches: totalMismatches,
  final,
}
