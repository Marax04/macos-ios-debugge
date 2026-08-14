export const meta = {
  name: 'finish-100-no-decomp',
  description: 'Rigorous checks + broken tests + findcrypt expansion + full workspace test. NO decompiler work.',
  phases: [
    { title: 'BrokenTestsFix', detail: 'Fix 3 broken crate integration tests (test-side drift)' },
    { title: 'FindcryptExpand', detail: 'Add missing crypto constant scanners (14% gap vs IDA)' },
    { title: 'FullBuild', detail: 'Rebuild release binary after fixes' },
    { title: 'RigorousChecks', detail: 'Convert loose validators to rigorous ground truth (32 modules)' },
    { title: 'WorkspaceTest', detail: 'Run cargo test --workspace --lib and collect pass/fail counts' },
    { title: 'FinalReport', detail: 'Aggregate all results' },
  ],
}

// ── Phase 1: Fix 3 broken crate tests (parallel) ──
phase('BrokenTestsFix')
const testFixes = await parallel([
  () => agent(`Fix compile-time drift in a Rust integration test file.

File: C:\\Users\\Fra\\Desktop\\RustRE\\crates\\rustre-project\\tests\\blitz2.rs

Steps:
1. cd C:\\Users\\Fra\\Desktop\\RustRE && cargo test --package rustre-project --test blitz2 --no-run 2>&1 | head -30
2. Read the compile error messages, identify API drift between test and library.
3. Update the TEST file only. Do NOT change the library.
4. Verify: cargo test --package rustre-project --test blitz2 --no-run should exit 0.

Rules: modify only test files. No library changes.

Return: {errors_before, errors_after, changes_summary}`,
  {
    label: 'fix-test:rustre-project',
    phase: 'BrokenTestsFix',
    agentType: 're-validator',
    schema: {
      type: 'object',
      properties: {
        errors_before: {type:'integer'}, errors_after: {type:'integer'}, changes_summary: {type:'string'}
      },
      required: ['changes_summary']
    }
  }),

  () => agent(`Fix compile-time drift in a Rust integration test file.

File: C:\\Users\\Fra\\Desktop\\RustRE\\crates\\rustre-flirt-gen\\tests\\blitz.rs

Steps:
1. cd C:\\Users\\Fra\\Desktop\\RustRE && cargo test --package rustre-flirt-gen --test blitz --no-run 2>&1 | head -30
2. Read the compile error messages, identify API drift.
3. Update the TEST file only. Do NOT change the library.
4. Verify: cargo test --package rustre-flirt-gen --test blitz --no-run should exit 0.

Rules: modify only test files.

Return: {errors_before, errors_after, changes_summary}`,
  {
    label: 'fix-test:rustre-flirt-gen',
    phase: 'BrokenTestsFix',
    agentType: 're-validator',
    schema: {
      type: 'object',
      properties: {
        errors_before: {type:'integer'}, errors_after: {type:'integer'}, changes_summary: {type:'string'}
      },
      required: ['changes_summary']
    }
  }),

  () => agent(`Fix compile-time drift in a Rust integration test file.

File: C:\\Users\\Fra\\Desktop\\RustRE\\crates\\rustre-il-hlil\\tests\\blitz.rs
Note: rustre-il-hlil lib test may also have errors — investigate both.

Steps:
1. cd C:\\Users\\Fra\\Desktop\\RustRE && cargo test --package rustre-il-hlil --no-run 2>&1 | head -40
2. For each error identify test-side vs library-side drift.
   - If TEST calls a non-existent function or with wrong signature: fix the TEST.
   - If library REMOVED a public API that the test needs: add back a minimal wrapper (thin fn or re-export) so the test compiles.
3. Iterate until cargo test --package rustre-il-hlil --no-run exits 0.

Rules: prefer test edits. Only add lib API if genuinely required.

Return: {errors_before, errors_after, changes_summary, files_edited}`,
  {
    label: 'fix-test:rustre-il-hlil',
    phase: 'BrokenTestsFix',
    agentType: 're-validator',
    schema: {
      type: 'object',
      properties: {
        errors_before: {type:'integer'}, errors_after: {type:'integer'},
        changes_summary: {type:'string'}, files_edited: {type:'array', items:{type:'string'}}
      },
      required: ['changes_summary']
    }
  }),
])

log(`BrokenTestsFix: ${testFixes.filter(Boolean).length}/3 agents completed`)

// ── Phase 2: Findcrypt expansion (6 missing signatures for parity with IDA 43) ──
phase('FindcryptExpand')
const findcryptExpand = await agent(`Add missing constant scanners to reach parity with an external tool.

Context:
- The Rust library at C:\\Users\\Fra\\Desktop\\RustRE\\crates\\rustre-crypto-id\\src\\lib.rs has a scanner pipeline at fn scan_binary_for_crypto_constants (line ~3727).
- Currently returns 37 hits on cargo-zyphora.exe. External IDA baseline: 43 hits. Gap of ~6.
- Existing scanners: AES sbox, SHA256/512/1 init+K, CRC32 table, ChaCha magic, MD5 init/T, TEA delta, Blowfish P, Camellia sigma, DES sbox, extended set (PEM/OpenSSL/etc).

Task:
- Investigate which specific patterns IDA finds that our scanner misses. Common candidates that IDA finds but we may miss:
  1. Rijndael Rcon (0x8D, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36 ...) — as a 10-byte array
  2. Additional Blowfish S-boxes (S1, S2, S3 — beyond just P-array)
  3. MD5 magic 4-byte deltas per round
  4. SHA-1 magic constants K1..K4 (0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6)
  5. secp256r1 curve base point coordinates
  6. GOST 28147-89 S-box
- Add a new scanner function scan_for_extra_constants that finds these.
- Wire it into scan_binary_for_crypto_constants.
- Rebuild: cd C:\\Users\\Fra\\Desktop\\RustRE && cargo build --release --bin rustre-mcp (wait patiently)
- Re-run the MCP call crypto_id_scan_and_summarize with the cargo-zyphora path and count total_hits.

Target: 43 or more hits (parity with IDA).

Rules:
- Only modify crates/rustre-crypto-id/src/*.rs, no #[allow], no panic
- Keep existing tests passing

Return: {file_edited, hits_before, hits_after, scanners_added, notes}`,
{
  label: 'expand-findcrypt',
  phase: 'FindcryptExpand',
  agentType: 're-validator',
  schema: {
    type: 'object',
    properties: {
      file_edited: {type:'string'}, hits_before: {type:'integer'}, hits_after: {type:'integer'},
      scanners_added: {type:'integer'}, notes: {type:'string'},
    },
    required: ['notes']
  }
})

// ── Phase 3: Rebuild ──
phase('FullBuild')
const build = await agent(`Rebuild the release binary and verify workspace compiles.

Steps:
1. cd C:\\Users\\Fra\\Desktop\\RustRE
2. Kill running processes: powershell -c "Get-Process -Name rustre-mcp,cargo,rustc -EA SilentlyContinue | Stop-Process -Force"
3. cargo build --release --bin rustre-mcp 2>&1 | Out-File -Encoding utf8 validation/build_no_decomp.log
4. Count errors and warnings.
5. Wait patiently — build takes 15-20 min.

Return: {build_ok, errors, warnings_count, elapsed_min}`,
{
  label: 'fullbuild',
  phase: 'FullBuild',
  agentType: 're-validator',
  schema: {
    type: 'object',
    properties: {
      build_ok: {type:'boolean'}, errors: {type:'integer'},
      warnings_count: {type:'integer'}, elapsed_min: {type:'integer'},
    },
    required: ['build_ok']
  }
})

// ── Phase 4: Rigorous checks (parallel over 32 modules) ──
phase('RigorousChecks')
const CATEGORIES = [
  'arch_wasm', 'arch_x86', 'callconv', 'codeview', 'db_base',
  'dotnet_edit', 'dotnet_metadata', 'events', 'flirt_apply', 'flirt_gen',
  'fuzz_afl', 'fuzz_cov', 'fuzz_libfuzzer', 'fuzz_net', 'fuzz_san',
  'gdb', 'ghidra', 'hex_pattern', 'il_lift', 'kgdb',
  'loader', 'mem', 'net_dissect', 'net_proxy', 'net_rules',
  'symbols_v6', 'symb_engine', 'symb_z3', 'trace_coverage',
  'ttd_query', 'ttd_replay', 'yara',
]

const hardened = await parallel(CATEGORIES.map(cat => () =>
  agent(`Convert loose validator checks to rigorous ones for module '${cat}'.

Context:
- Python validators live in C:\\Users\\Fra\\Desktop\\RustRE\\validation\\ (validators_${cat}*.py may exist as multiple files across batches).
- Many use any_valid() — only verifies the response is non-empty.
- Goal: for AT LEAST 10 tools in the module, replace any_valid() with a rigorous comparison against an independently computed Python truth (hashlib, zlib, struct, base64, or literal known values from public specs).

Steps:
1. Find all validators_${cat}*.py files: powershell -c "Get-ChildItem C:\\Users\\Fra\\Desktop\\RustRE\\validation\\validators_${cat}*.py"
2. Look for tools with well-known algorithms/constants where independent Python truth is easy to write.
3. Write a new consolidated file validation/validators_rigorous_${cat}.py that:
   - Starts a fresh rustre-mcp.exe --transport=stdio session
   - Calls at least 10 tools with proper inputs from their schema
   - Compares MCP outputs against Python truth
   - Saves report to validation/rigorous_${cat}.json with fields {module, tools_hardened, checks_passed, checks_failed, mismatches}
4. Run: python validation/validators_rigorous_${cat}.py

Rules:
- Do NOT edit .rs files. Only Python.
- Real mismatches (Rust output wrong) go in the mismatches array — do not hide them.
- MCP binary path: C:\\Users\\Fra\\Desktop\\RustRE\\target\\release\\rustre-mcp.exe

Return: {module, tools_hardened, checks_passed, checks_failed, real_mismatches, notes}`,
  {
    label: `harden:${cat}`,
    phase: 'RigorousChecks',
    agentType: 're-validator',
    schema: {
      type: 'object',
      properties: {
        module: {type:'string'}, tools_hardened: {type:'integer'},
        checks_passed: {type:'integer'}, checks_failed: {type:'integer'},
        real_mismatches: {type:'integer'}, notes: {type:'string'},
      },
      required: ['module','tools_hardened']
    }
  })
))

const totalHardened = hardened.filter(Boolean).reduce((s,r) => s + (r.tools_hardened || 0), 0)
const totalPassed = hardened.filter(Boolean).reduce((s,r) => s + (r.checks_passed || 0), 0)
const totalFailed = hardened.filter(Boolean).reduce((s,r) => s + (r.checks_failed || 0), 0)
const totalMismatches = hardened.filter(Boolean).reduce((s,r) => s + (r.real_mismatches || 0), 0)
log(`RigorousChecks: ${totalHardened} tools hardened, ${totalPassed} passed, ${totalFailed} failed, ${totalMismatches} real mismatches`)

// ── Phase 5: Workspace test ──
phase('WorkspaceTest')
const wsTest = await agent(`Run the workspace lib tests and collect pass/fail counts.

Steps:
1. cd C:\\Users\\Fra\\Desktop\\RustRE
2. Kill running: powershell -c "Get-Process -Name cargo,rustc -EA SilentlyContinue | Stop-Process -Force"
3. cargo test --workspace --release --lib --no-fail-fast 2>&1 | Out-File -Encoding utf8 validation/ws_test_final.log
4. Parse the log:
   - Total 'test result: ok' lines
   - Total 'test result: FAILED' lines
   - Sum of "N passed" and "N failed" across all crates
   - List crates with any failures
5. Report totals.

Wait patiently — full workspace test takes 20-40 min.

Return: {crates_passed, crates_failed, total_tests_passed, total_tests_failed, failed_crate_names, notes}`,
{
  label: 'workspace-test',
  phase: 'WorkspaceTest',
  agentType: 're-validator',
  schema: {
    type: 'object',
    properties: {
      crates_passed: {type:'integer'}, crates_failed: {type:'integer'},
      total_tests_passed: {type:'integer'}, total_tests_failed: {type:'integer'},
      failed_crate_names: {type:'array', items:{type:'string'}}, notes: {type:'string'},
    },
    required: ['notes']
  }
})

// ── Phase 6: Aggregate final report ──
phase('FinalReport')
return {
  status: 'workflow_complete',
  broken_tests_fixed: testFixes.filter(Boolean).length,
  findcrypt: {
    hits_before: findcryptExpand?.hits_before,
    hits_after: findcryptExpand?.hits_after,
    ida_baseline: 43,
  },
  build_ok: build?.build_ok,
  rigorous: {
    tools_hardened: totalHardened,
    checks_passed: totalPassed,
    checks_failed: totalFailed,
    real_mismatches: totalMismatches,
  },
  workspace_test: {
    crates_passed: wsTest?.crates_passed,
    crates_failed: wsTest?.crates_failed,
    total_tests_passed: wsTest?.total_tests_passed,
    total_tests_failed: wsTest?.total_tests_failed,
    failed_crates: wsTest?.failed_crate_names,
  },
}
