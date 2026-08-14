export const meta = {
  name: 'debugger-final-polish',
  description: 'Final polish: max performance (SIMD/parallel/mmap/arena/lockfree), safety (fuzz+audit), reliability (panic-free+retry), speed benchmarks, marginal features',
  phases: [
    { title: 'BaselineBenchmark', detail: 'Measure baseline: MCP tool latency p50/p95/p99, memory footprint, throughput' },
    { title: 'SpeedOptimize', detail: 'SIMD hot paths, rayon parallel, mmap zero-copy, arena bumpalo everywhere, lockfree structures, jemalloc/mimalloc, LTO fat' },
    { title: 'SafetyHardening', detail: 'Fuzz all parsers (TTD/PDB/DWARF/minidump), unsafe audit, integer overflow checks, poison recovery, memory-safety proofs where possible' },
    { title: 'ReliabilityPolish', detail: 'Panic-free (no unwrap on external input), retry+backoff on transient errors, timeout guards, health checks, graceful degradation' },
    { title: 'MarginalFeatures', detail: 'Polish: better UX defaults, richer error messages, docs on every pub item, examples, self-diagnostic tool' },
    { title: 'FinalBenchmark', detail: 'Compare vs baseline: expected 3-10x on hot paths, memory 30-50% down, zero panics under fuzz' },
    { title: 'Verify', detail: 'cargo test Win+Linux, cargo bench, MCP live latency probe, all 88 debug tools smoke test' },
  ],
}

const CWD = 'C:/Users/Fra/Desktop/RustRE'

phase('BaselineBenchmark')
const baseline = await agent(
  `Baseline benchmark of rustre-debug + MCP surface.

STEPS:
1. cd ${CWD} && cargo build --release -p rustre-debug -p rustre-mcp 2>&1 | tail -3.
2. Write ${CWD}/validation/bench_baseline.py — spawn rustre-mcp.exe stdio, measure:
   - debug.launch/detach latency (p50/p95/p99, 100 runs)
   - debug.read_memory 4KB latency
   - debug.backtrace latency
   - debug.watch (5 exprs) latency
   - debug.nl_query latency (rule-based path)
   - debug.retroactive_print latency (empty index)
3. Measure resident memory of rustre-mcp.exe at steady state via tasklist.
4. Measure MCP tools/list response size + parse time.
5. Return {latency_ms:{tool:{p50,p95,p99}}, memory_mb:number, tools_list_size_kb:number, throughput_ops_sec:number, notes:string}`,
  { label: 'baseline', agentType: 're-validator', schema: {
    type: 'object',
    properties: {
      latency_ms:{type:'object'},
      memory_mb:{type:'number'},
      tools_list_size_kb:{type:'number'},
      throughput_ops_sec:{type:'number'},
      notes:{type:'string'},
    },
    required:['notes']
  }}
)

phase('SpeedOptimize')
const speed = await agent(
  `Maximum speed optimizations. All must be additive (no API break).

Baseline: ${JSON.stringify(baseline).slice(0,1200)}

TARGETS:
1. **Global allocator swap** to mimalloc via #[global_allocator] in rustre-mcp bin. Measure heap fragmentation.
2. **SIMD for memory scan** — extend simd_scan_hw_registers pattern to memory_search::search_buffer (AVX2 memcmp-style, NEON on ARM). Use runtime detection.
3. **rayon parallelism** where safe: batch tool calls (session_list, tools/list generation), TTD event scanning, symbol resolution over module list.
4. **mmap zero-copy for PDB/PE parsing** — replace Vec<u8> reads with memmap2::Mmap, use bytemuck for header casts. Applies to codeview, windbg_ttd_backend, minidump parsers.
5. **Arena allocation (bumpalo)** everywhere trace/session events allocate — extend the arena from opt-1 to session_recorder, omniscient_query hot loop, and dataflow_dsl temporary strings.
6. **Lockfree structures**: replace Mutex<HashMap<session_id, Session>> with dashmap in the LiveSession registry (tools/debug.rs).
7. **LTO fat + codegen-units=1** already in Cargo.toml — verify + add profile.release-fast with panic=abort for even faster builds.
8. **Cold path attributes** on error branches (#[cold], #[inline(never)]).
9. **Cache-line align hot atomics** (breakpoint hit counters, event stream indices) with #[repr(align(64))].
10. **std::hint::likely/unlikely** on branch-heavy hot paths (event dispatch, register read decode).

For each opt: measure before/after with cargo bench (create ${CWD}/crates/rustre-debug/benches/hot_paths.rs if missing).

cd ${CWD} && cargo build --release -p rustre-debug -p rustre-mcp-tools -p rustre-mcp 2>&1 | tail -15. Iterate.

Return {optimizations_applied:[string], expected_speedup:{op:multiplier}, api_break:bool, build_ok:bool, bench_added:bool, notes:string}`,
  { label: 'speed', agentType: 're-validator', schema: {
    type: 'object',
    properties: {
      optimizations_applied:{type:'array', items:{type:'string'}},
      expected_speedup:{type:'object'},
      api_break:{type:'boolean'},
      build_ok:{type:'boolean'},
      bench_added:{type:'boolean'},
      notes:{type:'string'},
    },
    required:['build_ok','notes']
  }}
)

phase('SafetyHardening')
const safety = await agent(
  `Safety hardening pass.

TARGETS:
1. **Fuzz all external-input parsers** using cargo-fuzz. Add fuzz targets under ${CWD}/crates/rustre-debug/fuzz/fuzz_targets/:
   - fuzz_windbg_ttd_idx.rs — feed random bytes to WinDbgTtdBackend::open
   - fuzz_rr_trace_dir.rs — random directory structures to rr_trace::open
   - fuzz_minidump.rs — random bytes to minidump_analyze
   - fuzz_pdb_codeview.rs — random bytes to CodeView parser
   - fuzz_dwarf_cfi.rs — random bytes to CFI unwind
   Each 60s smoke run. cargo-fuzz not required to actually RUN — just ensure the targets COMPILE.
2. **Unsafe audit**: grep for 'unsafe fn' + 'unsafe {' across rustre-debug/src. For each, verify preconditions in doc comment and add debug_assert! for invariants.
3. **Integer overflow checks**: wrap arithmetic on user-supplied offsets/sizes with checked_add / checked_mul / saturating_sub. Especially in PDB/PE/DWARF/minidump readers.
4. **Poison recovery**: replace .lock().unwrap() with .lock().unwrap_or_else(|p| p.into_inner()) in session registry.
5. **Timeout guards** on external subprocess (rr replay spawn) — kill after N seconds if unresponsive.
6. **Zeroize sensitive memory** (register set snapshots may contain passwords/keys) using zeroize crate.
7. **Deny warnings** for the polished crate: add #![deny(unsafe_op_in_unsafe_fn, missing_debug_implementations)] where feasible.

For each change: build + tests pass. cargo test --release -p rustre-debug --lib 2>&1 | tail -5.

Return {fuzz_targets_added:[string], unsafe_blocks_audited:int, overflow_checks_added:int, poison_recovery_sites:int, timeouts_added:[string], zeroize_applied:bool, build_ok:bool, tests_passing:int, notes:string}`,
  { label: 'safety', agentType: 're-validator', schema: {
    type: 'object',
    properties: {
      fuzz_targets_added:{type:'array', items:{type:'string'}},
      unsafe_blocks_audited:{type:'integer'},
      overflow_checks_added:{type:'integer'},
      poison_recovery_sites:{type:'integer'},
      timeouts_added:{type:'array', items:{type:'string'}},
      zeroize_applied:{type:'boolean'},
      build_ok:{type:'boolean'},
      tests_passing:{type:'integer'},
      notes:{type:'string'},
    },
    required:['build_ok','notes']
  }}
)

phase('ReliabilityPolish')
const rel = await agent(
  `Reliability polish.

TARGETS:
1. **No .unwrap() on external input** — grep for '.unwrap()' in public API paths (MCP handlers, parser entry points). Replace with proper Result and structured error.
2. **Retry+backoff** on transient errors: rr subprocess spawn, PDB Symbol Server HTTP, TCP GDB RSP connect. Add helper retry_with_backoff(op, max_tries, initial_delay).
3. **Health check tool** debug.health — returns backend availability, memory usage, session count, hit rate.
4. **Graceful degradation**: when TTD backend fails to open, still return a functional mock TtdSession with clear "live=false" hint (already partial — extend to all backends).
5. **Structured errors** with typed variants (thiserror-derived) covering: NotAttached, TimedOut, TraceCorrupt, SymbolServerUnreachable, RrNotInstalled, PermissionDenied.
6. **Idempotent operations**: debug.set_breakpoint twice at same addr is safe; debug.kill on already-dead session returns success.
7. **Circuit breaker** for external services (PDB server): after 3 failures in 60s, stop trying for 60s.

cargo build --release -p rustre-debug -p rustre-mcp-tools -p rustre-mcp 2>&1 | tail -10.
cargo test --release -p rustre-debug --lib 2>&1 | tail -3.

Return {unwraps_removed:int, retry_sites:[string], health_tool_added:bool, circuit_breakers:int, error_variants:int, build_ok:bool, tests_passing:int, notes:string}`,
  { label: 'reliability', agentType: 're-validator', schema: {
    type: 'object',
    properties: {
      unwraps_removed:{type:'integer'},
      retry_sites:{type:'array', items:{type:'string'}},
      health_tool_added:{type:'boolean'},
      circuit_breakers:{type:'integer'},
      error_variants:{type:'integer'},
      build_ok:{type:'boolean'},
      tests_passing:{type:'integer'},
      notes:{type:'string'},
    },
    required:['build_ok','notes']
  }}
)

phase('MarginalFeatures')
const marg = await agent(
  `Polish marginal features + UX.

TARGETS:
1. **Rich MCP error messages** — every error returns actionable hint (e.g. "session id not found; call debug.session_list").
2. **Doc comments** on every pub item in rustre-debug — where missing, add 3+ lines: purpose, usage example, panic/error conditions.
3. **Examples directory** ${CWD}/crates/rustre-debug/examples/:
   - hello_debug.rs — attach, backtrace, kill (basic tutorial)
   - trace_analysis.rs — open trace, run nl_query, print result
   - retroactive_print_demo.rs — annotate + evaluate
4. **Self-diagnostic tool** debug.self_test — runs internal invariant checks, returns pass/fail per subsystem.
5. **Better defaults**: watchpoint size default to word size, timeout defaults to 30s, retry defaults to 3.
6. **Progress reporting** for long ops (TTD trace scan): callback / streaming events.
7. **Icon/name hints** for MCP tools list (short display names).

Build + tests.

Return {docs_added:int, examples_added:[string], self_test_tool:bool, defaults_improved:[string], build_ok:bool, notes:string}`,
  { label: 'marginal', agentType: 're-validator', schema: {
    type: 'object',
    properties: {
      docs_added:{type:'integer'},
      examples_added:{type:'array', items:{type:'string'}},
      self_test_tool:{type:'boolean'},
      defaults_improved:{type:'array', items:{type:'string'}},
      build_ok:{type:'boolean'},
      notes:{type:'string'},
    },
    required:['build_ok','notes']
  }}
)

phase('FinalBenchmark')
const finalBench = await agent(
  `Post-optimization benchmark. Compare vs baseline.

Baseline: ${JSON.stringify(baseline).slice(0,1500)}

STEPS:
1. Rerun ${CWD}/validation/bench_baseline.py (same suite as baseline phase).
2. Compute speedup ratio per operation: baseline_p50 / current_p50.
3. Measure memory footprint change.
4. Run cargo bench --package rustre-debug (if benches defined).

Return {latency_ms_after:{tool:{p50,p95,p99}}, speedup_ratio:{tool:number}, memory_mb_after:number, memory_delta_pct:number, cargo_bench_summary:string, notes:string}`,
  { label: 'final-bench', agentType: 're-validator', schema: {
    type: 'object',
    properties: {
      latency_ms_after:{type:'object'},
      speedup_ratio:{type:'object'},
      memory_mb_after:{type:'number'},
      memory_delta_pct:{type:'number'},
      cargo_bench_summary:{type:'string'},
      notes:{type:'string'},
    },
    required:['notes']
  }}
)

phase('Verify')
const verify = await agent(
  `Final full verification.

STEPS:
1. taskkill //F //IM rustre-mcp.exe. sleep 3.
2. cd ${CWD} && cargo build --release -p rustre-mcp -p rustre-mcp-server 2>&1 | tail -10.
3. Windows tests: cargo test --release -p rustre-debug --lib 2>&1 | tail -3.
4. Linux tests: wsl -d Ubuntu -- bash -lc "cd /mnt/c/Users/Fra/Desktop/RustRE && /home/marax/.cargo/bin/cargo test --release -p rustre-debug --lib 2>&1 | tail -3".
5. MCP smoke test ALL debug.* tools (should be 88+). Call each with sensible args; count OK vs error.
6. debug.self_test if implemented.
7. Return {
   windows_tests:{passed,failed},
   linux_tests:{passed,failed},
   mcp_debug_tools_count:int,
   smoke_test_ok_ratio:number,
   speedup_summary:string,
   memory_reduction_pct:number,
   safety_improvements:string,
   reliability_improvements:string,
   final_verdict:string
}`,
  { label: 'verify', agentType: 're-validator', schema: {
    type: 'object',
    properties: {
      windows_tests:{type:'object'},
      linux_tests:{type:'object'},
      mcp_debug_tools_count:{type:'integer'},
      smoke_test_ok_ratio:{type:'number'},
      speedup_summary:{type:'string'},
      memory_reduction_pct:{type:'number'},
      safety_improvements:{type:'string'},
      reliability_improvements:{type:'string'},
      final_verdict:{type:'string'},
    },
    required:['final_verdict']
  }}
)

return { status:'final-polish-complete', baseline, speed, safety, reliability:rel, marginal:marg, finalBench, verify }
