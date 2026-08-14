//! 360° benchmark suite for `rustre-debug`.
//!
//! Run with: `cargo bench --release -p rustre-debug --bench full_coverage`
//! One group:  `cargo bench --release -p rustre-debug --bench full_coverage -- omniscient`
//!
//! # Why this exists alongside `hot_paths.rs`
//!
//! `hot_paths` measures four leaf functions. It answers "is our memchr scan
//! fast", which was never in doubt. It does not answer the questions that
//! actually decide whether this debugger is usable on a real target:
//!
//! - Does `who_wrote` stay usable after a long recording, or does it degrade
//!   into a linear scan of millions of writes? (`OmniscientIndex` stores writes
//!   in a `Vec` and `who_wrote` filters it — so cost grows with the length of
//!   the RECORDING, not with the number of answers. The scaling groups below
//!   are written to make that visible rather than to hide it.)
//! - How expensive is one conditional-breakpoint evaluation? That runs once per
//!   breakpoint HIT, so a slow evaluator turns a hot breakpoint into a hang.
//! - What does re-parsing an expression per hit cost versus parsing it once?
//!
//! # What is deliberately NOT benchmarked here
//!
//! Anything that needs a live process (ptrace / Win32 round-trips, real
//! `read_memory`, real single-step). Those dominate wall-clock time in practice
//! but cannot be measured reproducibly in a criterion harness: the numbers
//! would be OS-scheduler noise, and every sample would spawn a process. They
//! belong in the live test suites. Everything here is deterministic and
//! host-independent, so a regression in these numbers is a regression in OUR
//! code, not in the machine.
//!
//! Groups:
//!   1.  memory_search      — pattern scanning (exact / wildcard / miss)
//!   2.  omniscient         — who_wrote / last_writer / trace_origin scaling
//!   3.  omniscient_ingest  — cost of RECORDING writes (the write path)
//!   4.  expr_parse         — expression parsing (per conditional-bp hit)
//!   5.  expr_eval          — expression evaluation, incl. parse-vs-cached
//!   6.  watchpoints        — DR slot allocation, DR7 encoding, scanning
//!   7.  ttd                — trace recording + reverse seek
//!   8.  heatmap            — execution heatmap bucketing
//!   9.  race_detector      — O(n²)-shaped race scan, scaling
//!   10. dataflow_dsl       — query parse + execute
//!   11. root_cause         — Bayesian prefilter + causal slice
//!   12. registers          — RegisterSet get/set/enumerate (every tool call)

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use std::hint::black_box;

use rustre_core::address::Address;
use rustre_debug::ThreadId;

// ═════════════════════════════════════════════════════════════════════════════
// 1. memory_search
// ═════════════════════════════════════════════════════════════════════════════

fn bench_memory_search(c: &mut Criterion) {
    use rustre_debug::memory_search::{MemorySearch, SearchPattern};

    let mut group = c.benchmark_group("memory_search");
    for &sz in &[64 * 1024usize, 1024 * 1024, 8 * 1024 * 1024] {
        let mut data = vec![0u8; sz];
        let hit = sz - 64;
        data[hit..hit + 4].copy_from_slice(b"\xDE\xAD\xBE\xEF");
        group.throughput(Throughput::Bytes(sz as u64));

        // Hit near the end: the honest cost, since an early hit would let the
        // scan exit immediately and flatter the number.
        let exact = SearchPattern::bytes(b"\xDE\xAD\xBE\xEF".to_vec()).unwrap();
        group.bench_with_input(BenchmarkId::new("exact_hit_at_end", sz), &sz, |b, _| {
            b.iter(|| {
                MemorySearch::default_options()
                    .search_buffer(black_box(&data), 0, &exact, 0, None)
                    .unwrap()
            });
        });

        // Worst case: the pattern is not present at all, so the whole buffer is
        // scanned with no early exit. This is the number that matters when a
        // user searches a 2 GB address space for something that is not there.
        let miss = SearchPattern::bytes(b"\x11\x22\x33\x44\x55\x66".to_vec()).unwrap();
        group.bench_with_input(BenchmarkId::new("exact_miss", sz), &sz, |b, _| {
            b.iter(|| {
                MemorySearch::default_options()
                    .search_buffer(black_box(&data), 0, &miss, 0, None)
                    .unwrap()
            });
        });
    }
    group.finish();
}

// ═════════════════════════════════════════════════════════════════════════════
// 2-3. omniscient query — the differentiating feature, and the one most at risk
// ═════════════════════════════════════════════════════════════════════════════

fn synth_writes(n: u64, distinct_addrs: u64) -> Vec<rustre_debug::omniscient_query::MemoryWrite> {
    use rustre_debug::omniscient_query::MemoryWrite;
    (0..n)
        .map(|i| MemoryWrite {
            sequence: i,
            // Spread over `distinct_addrs` slots so a query matches roughly
            // n/distinct_addrs writes — a realistic "this field was written
            // many times" shape rather than one giant match or none.
            address: Address::new(0x1_0000 + (i % distinct_addrs) * 8),
            size: 8,
            tid: ThreadId((i % 4) as u32),
            writer_pc: Some(Address::new(0x14_0000 + (i % 64) * 16)),
            source_address: if i % 3 == 0 {
                Some(Address::new(0x1_0000 + ((i + 1) % distinct_addrs) * 8))
            } else {
                None
            },
        })
        .collect()
}

fn bench_omniscient(c: &mut Criterion) {
    use rustre_debug::omniscient_query::OmniscientIndex;

    let mut group = c.benchmark_group("omniscient");
    // Scaling is the point: if these times grow linearly with the recording
    // size, `who_wrote` is a full scan and long sessions will not be usable.
    for &n in &[1_000u64, 10_000, 100_000, 1_000_000] {
        let index = OmniscientIndex::from_writes(synth_writes(n, 512));
        let target = Address::new(0x1_0000 + 128 * 8);
        group.throughput(Throughput::Elements(n));

        group.bench_with_input(BenchmarkId::new("who_wrote", n), &n, |b, _| {
            b.iter(|| index.who_wrote(black_box(target), u64::MAX));
        });
        group.bench_with_input(BenchmarkId::new("last_writer", n), &n, |b, _| {
            b.iter(|| index.last_writer(black_box(target), u64::MAX));
        });
        // trace_origin walks source_address hops, so it is who_wrote repeated
        // once per hop — the compounding case.
        group.bench_with_input(BenchmarkId::new("trace_origin", n), &n, |b, _| {
            b.iter(|| index.trace_origin(black_box(target), u64::MAX));
        });
        group.bench_with_input(BenchmarkId::new("writes_by_thread", n), &n, |b, _| {
            b.iter(|| index.writes_by_thread(black_box(ThreadId(2))));
        });
        group.bench_with_input(BenchmarkId::new("all_addresses", n), &n, |b, _| {
            b.iter(|| index.all_addresses());
        });
    }
    group.finish();
}

fn bench_omniscient_ingest(c: &mut Criterion) {
    use rustre_debug::omniscient_query::OmniscientIndex;

    // The RECORD path, not the query path. Every live `write_memory` pushes
    // here, so a slow push taxes the whole session even if nobody ever queries.
    let mut group = c.benchmark_group("omniscient_ingest");
    for &n in &[10_000u64, 100_000] {
        let writes = synth_writes(n, 512);
        group.throughput(Throughput::Elements(n));
        group.bench_with_input(BenchmarkId::new("push_n", n), &n, |b, _| {
            b.iter(|| {
                let mut idx = OmniscientIndex::new();
                for w in &writes {
                    idx.push(black_box(w.clone()));
                }
                idx.len()
            });
        });
        group.bench_with_input(BenchmarkId::new("from_writes_bulk", n), &n, |b, _| {
            b.iter(|| OmniscientIndex::from_writes(black_box(writes.clone())));
        });
    }
    group.finish();
}

// ═════════════════════════════════════════════════════════════════════════════
// 4-5. expression evaluator — runs once per conditional-breakpoint HIT
// ═════════════════════════════════════════════════════════════════════════════

/// Fixed register file, so evaluation cost is the evaluator's and not a
/// backend's.
struct BenchRegs;
impl rustre_debug::expression_evaluator::RegisterState for BenchRegs {
    fn read_register(&self, name: &str) -> Option<u64> {
        match name {
            "rip" => Some(0x1_4000_1000),
            "rsp" => Some(0x7FFF_0000),
            "rbp" => Some(0x7FFF_0100),
            "rax" => Some(42),
            "rbx" => Some(7),
            _ => None,
        }
    }
    fn all_registers(&self) -> Vec<(String, u64)> {
        vec![
            ("rip".into(), 0x1_4000_1000),
            ("rsp".into(), 0x7FFF_0000),
            ("rbp".into(), 0x7FFF_0100),
            ("rax".into(), 42),
            ("rbx".into(), 7),
        ]
    }
}

/// In-memory buffer standing in for the target's address space, so the
/// benchmark measures deref/type-walk cost without an OS round-trip.
struct BenchMem {
    base: u64,
    bytes: Vec<u8>,
}
impl rustre_debug::expression_evaluator::MemoryProvider for BenchMem {
    fn read_bytes(
        &self,
        addr: u64,
        len: usize,
    ) -> rustre_debug::expression_evaluator::error::DebugResult<Vec<u8>> {
        use rustre_debug::expression_evaluator::error::DebugError;
        let off = addr.wrapping_sub(self.base) as usize;
        self.bytes
            .get(off..off + len)
            .map(<[u8]>::to_vec)
            .ok_or_else(|| DebugError(format!("oob read at {addr:#x}")))
    }
}

struct BenchSyms;
impl rustre_debug::expression_evaluator::SymbolTable for BenchSyms {
    fn lookup_symbol(&self, name: &str) -> Option<u64> {
        (name == "g_counter").then_some(0x7FFF_0000)
    }
    fn reverse_lookup(&self, addr: u64) -> Option<String> {
        (addr == 0x7FFF_0000).then(|| "g_counter".to_string())
    }
}

/// Expressions ordered by increasing work, so a regression can be attributed to
/// a stage (lexing, precedence climbing, deref, symbol lookup) instead of just
/// "expressions got slower".
const EXPRS: &[(&str, &str)] = &[
    ("register", "$rax"),
    ("arith", "$rax + $rbx * 2 - 1"),
    ("compare", "$rax > 40 && $rbx < 10"),
    ("deref_u32", "*(u32*)$rsp"),
    ("deref_chain", "*(u64*)(*(u64*)$rsp + 8)"),
    ("symbol", "g_counter"),
    (
        "deep_nested",
        "((($rax + 1) * ($rbx + 2)) - (($rax - 1) * ($rbx - 2))) / 2",
    ),
];

fn bench_expr_parse(c: &mut Criterion) {
    use rustre_debug::expression_evaluator::parse_expression;
    let mut group = c.benchmark_group("expr_parse");
    for (label, src) in EXPRS {
        group.bench_function(*label, |b| {
            b.iter(|| parse_expression(black_box(src)).unwrap());
        });
    }
    group.finish();
}

fn bench_expr_eval(c: &mut Criterion) {
    use rustre_debug::expression_evaluator::{
        EvalContext, ExprEvaluator, TypeSystem, parse_expression,
    };

    let regs = BenchRegs;
    let mem = BenchMem {
        base: 0x7FFF_0000,
        bytes: {
            let mut v = vec![0u8; 4096];
            // Make `deref_chain` resolve: [rsp] -> rsp+0x100, [that+8] -> value.
            v[0..8].copy_from_slice(&0x7FFF_0100u64.to_le_bytes());
            v[0x108..0x110].copy_from_slice(&0xCAFEu64.to_le_bytes());
            v
        },
    };
    let syms = BenchSyms;
    let types = TypeSystem::with_primitives();
    let ctx = EvalContext::new(&regs, &mem, &syms, &types);

    let mut group = c.benchmark_group("expr_eval");
    for (label, src) in EXPRS {
        let Ok(ast) = parse_expression(src) else { continue };
        // Eval of a pre-parsed AST: what a breakpoint SHOULD cost per hit.
        group.bench_function(BenchmarkId::new("cached_ast", *label), |b| {
            b.iter(|| ExprEvaluator::eval(black_box(&ast), &ctx));
        });
        // Parse + eval: what it costs today if the condition string is re-parsed
        // on every hit. The gap between the two is exactly what caching the AST
        // on the breakpoint would save.
        group.bench_function(BenchmarkId::new("parse_and_eval", *label), |b| {
            b.iter(|| {
                let ast = parse_expression(black_box(src)).unwrap();
                ExprEvaluator::eval(&ast, &ctx)
            });
        });
    }
    group.finish();
}

// ═════════════════════════════════════════════════════════════════════════════
// 6. watchpoint engine
// ═════════════════════════════════════════════════════════════════════════════

fn bench_watchpoints(c: &mut Criterion) {
    use rustre_debug::watchpoint_engine::{
        TargetArch, WatchpointEngine, WatchpointType, simd_scan_hw_registers_runtime,
    };

    let mut group = c.benchmark_group("watchpoints");

    // Fill all four x86 debug-register slots and tear them down again. This is
    // what every debug.set_watchpoint / remove_watchpoint pair costs before the
    // OS call, so it should be negligible next to the ptrace/Win32 round-trip.
    group.bench_function("fill_and_drain_4_slots", |b| {
        b.iter(|| {
            let mut e = WatchpointEngine::new(TargetArch::X86_64);
            let mut ids = [0u64; 4];
            for (i, id) in ids.iter_mut().enumerate() {
                *id = e
                    .add_hardware(
                        0x1000 + (i as u64) * 8,
                        8,
                        WatchpointType::Write,
                        None,
                        false,
                        None,
                    )
                    .unwrap();
            }
            let dr7 = e.x86_dr7();
            for id in ids {
                e.remove(id).unwrap();
            }
            dr7
        });
    });

    // DR7 encoding runs on every watchpoint mutation, and again whenever the
    // live registers are reprogrammed.
    let mut engine = WatchpointEngine::new(TargetArch::X86_64);
    for i in 0..4u64 {
        engine
            .add_hardware(0x2000 + i * 8, 8, WatchpointType::Write, None, false, None)
            .unwrap();
    }
    group.bench_function("x86_dr7_encode", |b| {
        b.iter(|| black_box(engine.x86_dr7()));
    });
    group.bench_function("hw_register_addresses", |b| {
        b.iter(|| black_box(engine.hw_register_addresses()));
    });

    // The scan that decides which watchpoint a trap belongs to. Runs on EVERY
    // SIGTRAP / EXCEPTION_SINGLE_STEP, so it is on the stepping hot path.
    let addrs = engine.hw_register_addresses();
    group.bench_function("simd_scan/hit", |b| {
        b.iter(|| simd_scan_hw_registers_runtime(black_box(0x2018), addrs));
    });
    group.bench_function("simd_scan/miss", |b| {
        b.iter(|| simd_scan_hw_registers_runtime(black_box(0xDEAD_BEEF), addrs));
    });
    group.finish();
}

// ═════════════════════════════════════════════════════════════════════════════
// 7. time-travel debugging
// ═════════════════════════════════════════════════════════════════════════════

fn bench_ttd(c: &mut Criterion) {
    use rustre_debug::time_travel_debug::{SnapshotReplayBackend, TracePosition, TtdState};

    let mut group = c.benchmark_group("ttd");
    for &n in &[1_000u64, 50_000] {
        // `record` keeps the log sorted via binary search + Vec::insert. Feeding
        // states in ASCENDING order is the append-only shape a real recording
        // has, and it is the cheap case (insert at the end).
        group.throughput(Throughput::Elements(n));
        group.bench_with_input(BenchmarkId::new("record_ascending", n), &n, |b, _| {
            b.iter(|| {
                let mut backend = SnapshotReplayBackend::new();
                for i in 0..n {
                    backend.record(TtdState::new(
                        TracePosition { sequence: i, offset: 0 },
                        0x14_0000 + i * 4,
                        0x7FFF_0000 - i * 8,
                    ));
                }
                backend
            });
        });

        // Out-of-order recording forces mid-Vec inserts (memmove per insert).
        // If this is dramatically worse than ascending, the log wants a
        // different structure before anyone records a real out-of-order trace.
        group.bench_with_input(BenchmarkId::new("record_interleaved", n), &n, |b, _| {
            b.iter(|| {
                let mut backend = SnapshotReplayBackend::new();
                for i in 0..n {
                    // Bit-reverse-ish scramble: deterministic, poorly ordered.
                    let seq = (i * 2_654_435_761) % n.max(1);
                    backend.record(TtdState::new(
                        TracePosition { sequence: seq, offset: 0 },
                        0x14_0000 + seq * 4,
                        0x7FFF_0000,
                    ));
                }
                backend
            });
        });
    }
    group.finish();
}

// ═════════════════════════════════════════════════════════════════════════════
// 8. execution heatmap
// ═════════════════════════════════════════════════════════════════════════════

fn bench_heatmap(c: &mut Criterion) {
    use rustre_debug::execution_heatmap::ExecutionHeatmap;
    use rustre_debug::time_travel_debug::TracePosition;

    let mut group = c.benchmark_group("heatmap");
    for &n in &[10_000usize, 200_000] {
        let history: Vec<(TracePosition, u64)> = (0..n as u64)
            .map(|i| {
                (
                    TracePosition { sequence: i, offset: 0 },
                    // 256 distinct pcs with a hot spike, so `hottest` has real
                    // work to rank instead of a flat distribution.
                    if i % 10 == 0 { 0x14_0000 } else { 0x14_0000 + (i % 256) * 16 },
                )
            })
            .collect();
        group.throughput(Throughput::Elements(n as u64));
        group.bench_with_input(BenchmarkId::new("from_ttd_history/128", n), &n, |b, _| {
            b.iter(|| ExecutionHeatmap::from_ttd_history(black_box(&history), 128));
        });
        let hm = ExecutionHeatmap::from_ttd_history(&history, 128);
        group.bench_with_input(BenchmarkId::new("hottest_10", n), &n, |b, _| {
            b.iter(|| hm.hottest(black_box(10)));
        });
    }
    group.finish();
}

// ═════════════════════════════════════════════════════════════════════════════
// 9. race detector — the shape most likely to be quadratic
// ═════════════════════════════════════════════════════════════════════════════

fn bench_race_detector(c: &mut Criterion) {
    use rustre_debug::race_detector::{AccessKind, MemoryAccess, detect_races,
        detect_write_write_races};

    let mut group = c.benchmark_group("race_detector");
    // Deliberately small steps: if this is O(n²), 2000 vs 1000 shows a ~4x jump
    // and the suite says so instead of silently taking minutes at 100k.
    for &n in &[500u64, 1_000, 2_000] {
        let accesses: Vec<MemoryAccess> = (0..n)
            .map(|i| MemoryAccess {
                sequence: i,
                // 64 addresses shared across 4 threads → genuine contention, so
                // the detector actually produces candidates rather than
                // bailing out early on a no-overlap fast path.
                address: Address::new(0x1_0000 + (i % 64) * 8),
                size: 8,
                tid: ThreadId((i % 4) as u32),
                kind: if i % 3 == 0 { AccessKind::Read } else { AccessKind::Write },
            })
            .collect();
        group.throughput(Throughput::Elements(n));
        group.bench_with_input(BenchmarkId::new("detect_races", n), &n, |b, _| {
            b.iter(|| detect_races(black_box(&accesses)));
        });
        group.bench_with_input(BenchmarkId::new("write_write", n), &n, |b, _| {
            b.iter(|| detect_write_write_races(black_box(&accesses)));
        });
    }
    group.finish();
}

// ═════════════════════════════════════════════════════════════════════════════
// 10. dataflow DSL
// ═════════════════════════════════════════════════════════════════════════════

fn bench_dataflow_dsl(c: &mut Criterion) {
    use rustre_debug::dataflow_dsl;
    use rustre_debug::omniscient_query::OmniscientIndex;

    let index = OmniscientIndex::from_writes(synth_writes(50_000, 512));
    let queries = [
        "FIND writes TO 0x11400",
        "TRACE value AT 0x11400 BACKWARD",
    ];

    let mut group = c.benchmark_group("dataflow_dsl");
    for q in queries {
        // Parse alone: cheap, but it happens per query from an agent.
        group.bench_function(BenchmarkId::new("parse", q), |b| {
            b.iter(|| dataflow_dsl::parse(black_box(q)));
        });
        // Parse + execute against a 50k-write index: the end-to-end number an
        // agent actually waits on. Queries that fail to parse are skipped so a
        // DSL syntax change turns into a missing group, not a bogus timing.
        if dataflow_dsl::parse(q).is_ok() {
            group.bench_function(BenchmarkId::new("run", q), |b| {
                b.iter(|| dataflow_dsl::run(black_box(q), &index));
            });
        }
    }
    group.finish();
}

// ═════════════════════════════════════════════════════════════════════════════
// 11. root-cause assistant
// ═════════════════════════════════════════════════════════════════════════════

fn bench_root_cause(c: &mut Criterion) {
    use rustre_debug::omniscient_query::OmniscientIndex;
    use rustre_debug::root_cause_assistant::{bayesian_prefilter, root_cause};

    let mut group = c.benchmark_group("root_cause");
    for &n in &[10_000u64, 100_000] {
        let bad = OmniscientIndex::from_writes(synth_writes(n, 512));
        // The "good" baseline is a second recording of the same shape — this is
        // the two-recording comparison the assistant is designed around.
        let good = OmniscientIndex::from_writes(synth_writes(n, 512));
        let target = Address::new(0x1_0000 + 128 * 8);
        group.throughput(Throughput::Elements(n));
        group.bench_with_input(BenchmarkId::new("bayesian_prefilter", n), &n, |b, _| {
            b.iter(|| bayesian_prefilter(&bad, black_box(target), u64::MAX, &good));
        });
        // root_cause = trace_origin (causal slice) + prefilter, so it should
        // land near the sum of its two parts; a bigger gap means duplicated work.
        group.bench_with_input(BenchmarkId::new("root_cause_full", n), &n, |b, _| {
            b.iter(|| root_cause(&bad, black_box(target), u64::MAX, &good));
        });
    }
    group.finish();
}

// ═════════════════════════════════════════════════════════════════════════════
// 12. RegisterSet — touched by essentially every debug.* tool call
// ═════════════════════════════════════════════════════════════════════════════

fn bench_registers(c: &mut Criterion) {
    use rustre_debug::RegisterSet;

    const NAMES: &[&str] = &[
        "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "r8", "r9", "r10", "r11", "r12",
        "r13", "r14", "r15", "rip", "rflags",
    ];

    let mut group = c.benchmark_group("registers");
    // Building a full x86-64 set is what every get_registers does after the OS
    // hands back a CONTEXT / user_regs_struct.
    group.bench_function("build_full_x86_64", |b| {
        b.iter(|| {
            let mut rs = RegisterSet::new();
            for (i, n) in NAMES.iter().enumerate() {
                rs.set(n, i as u64);
            }
            rs
        });
    });

    let mut rs = RegisterSet::new();
    for (i, n) in NAMES.iter().enumerate() {
        rs.set(n, i as u64);
    }
    group.bench_function("get_hit", |b| b.iter(|| rs.get(black_box("r11"))));
    group.bench_function("get_miss", |b| b.iter(|| rs.get(black_box("xmm0"))));
    // all_names allocates a Vec<String>; it is called per debug.read_registers
    // and per expression evaluation that touches `all_registers`.
    group.bench_function("all_names", |b| b.iter(|| rs.all_names()));
    group.finish();
}

criterion_group!(
    benches,
    bench_memory_search,
    bench_omniscient,
    bench_omniscient_ingest,
    bench_expr_parse,
    bench_expr_eval,
    bench_watchpoints,
    bench_ttd,
    bench_heatmap,
    bench_race_detector,
    bench_dataflow_dsl,
    bench_root_cause,
    bench_registers,
);
criterion_main!(benches);
