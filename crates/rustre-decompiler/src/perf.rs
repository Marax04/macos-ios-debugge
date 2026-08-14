//! Opt-in stage timing instrumentation (OFF by default).
//!
//! Enabled only when the environment variable `RUSTRE_PERF` is set to a
//! non-empty value. When disabled, `scope()` returns immediately after a
//! single relaxed atomic-bool read and records nothing, so the hot path is
//! unaffected. Nothing in the normal pipeline reads these numbers; the only
//! consumer is `dump()`, which the batch driver calls at the end of a run when
//! the variable is set.
//!
//! Counters are global atomics in nanoseconds, so the numbers aggregate
//! correctly across the Rayon workers the batch loop uses (the totals are
//! CPU-time sums, not wall clock — which is exactly what a share table wants).

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::Instant;

/// Stage identifiers. Keep in sync with `NAMES`.
#[derive(Copy, Clone, Debug)]
#[repr(usize)]
pub enum Stage {
    DetectFunctions = 0,
    Disassemble = 1,
    JumpTables = 2,
    SymbolsLiterals = 3,
    CalleeArities = 4,
    Passes = 5,
    BuildCfg = 6,
    SsaSplit = 7,
    EmitStructured = 8,
    TextPasses = 9,
    SyntacticRepair = 10,
    ScoreConfidence = 11,
    EmitOutputs = 12,
}

pub const N_STAGES: usize = 13;

pub const NAMES: [&str; N_STAGES] = [
    "detect_functions",
    "disassemble",
    "jump_tables",
    "symbols_literals",
    "callee_arities",
    "passes(analysis bridges + LLIL/MLIL)",
    "build_cfg (structuring)",
    "ssa_split",
    "emit_structured",
    "TEXT REWRITE PASSES",
    "syntactic_repair_net",
    "score_confidence",
    "emit_outputs(io)",
];

static COUNTERS: [AtomicU64; N_STAGES] = {
    #[allow(clippy::declare_interior_mutable_const)]
    const Z: AtomicU64 = AtomicU64::new(0);
    [Z; N_STAGES]
};

static ENABLED: OnceLock<bool> = OnceLock::new();
static PASS_ENABLED: AtomicBool = AtomicBool::new(false);

#[inline]
pub fn enabled() -> bool {
    *ENABLED.get_or_init(|| {
        let on = std::env::var("RUSTRE_PERF").is_ok_and(|v| !v.is_empty());
        PASS_ENABLED.store(on, Ordering::Relaxed);
        on
    })
}

/// Per-function record: (address, instruction count, total ns, text-pass ns).
static FUNCS: OnceLock<Mutex<Vec<(u64, usize, u64, u64)>>> = OnceLock::new();
/// Per named sub-pass (the `self.passes` pipeline entries) ns totals.
static SUBPASS: OnceLock<Mutex<std::collections::HashMap<String, u64>>> = OnceLock::new();

pub fn record_function(addr: u64, insns: usize, total_ns: u64, text_ns: u64) {
    if !enabled() {
        return;
    }
    FUNCS
        .get_or_init(|| Mutex::new(Vec::new()))
        .lock()
        .unwrap()
        .push((addr, insns, total_ns, text_ns));
}

pub fn record_subpass(name: &str, ns: u64) {
    if !enabled() {
        return;
    }
    *SUBPASS
        .get_or_init(|| Mutex::new(std::collections::HashMap::new()))
        .lock()
        .unwrap()
        .entry(name.to_string())
        .or_insert(0) += ns;
}

pub fn add(stage: Stage, ns: u64) {
    if !enabled() {
        return;
    }
    COUNTERS[stage as usize].fetch_add(ns, Ordering::Relaxed);
}

/// RAII scope timer. No-op (and does not even read the clock) when disabled.
pub struct Scope {
    stage: Stage,
    start: Option<Instant>,
}

#[inline]
#[must_use]
pub fn scope(stage: Stage) -> Scope {
    Scope {
        stage,
        start: if enabled() { Some(Instant::now()) } else { None },
    }
}

impl Drop for Scope {
    fn drop(&mut self) {
        if let Some(s) = self.start {
            COUNTERS[self.stage as usize]
                .fetch_add(s.elapsed().as_nanos() as u64, Ordering::Relaxed);
        }
    }
}

/// Print the stage share table + per-function distribution to stderr.
pub fn dump(label: &str, wall_ms: u64) {
    if !enabled() {
        return;
    }
    let vals: Vec<u64> = (0..N_STAGES)
        .map(|i| COUNTERS[i].load(Ordering::Relaxed))
        .collect();
    let total: u64 = vals.iter().sum();
    let t = total.max(1) as f64;
    eprintln!("=== RUSTRE_PERF {label} wall_ms={wall_ms} attributed_ms={} ===", total / 1_000_000);
    let mut idx: Vec<usize> = (0..N_STAGES).collect();
    idx.sort_by_key(|&i| std::cmp::Reverse(vals[i]));
    for i in idx {
        eprintln!(
            "PERF_STAGE\t{}\t{:.3}\t{:.2}",
            NAMES[i],
            vals[i] as f64 / 1e6,
            100.0 * vals[i] as f64 / t
        );
    }
    if let Some(m) = SUBPASS.get() {
        let mut v: Vec<(String, u64)> = m.lock().unwrap().iter().map(|(k, &n)| (k.clone(), n)).collect();
        v.sort_by_key(|(_, n)| std::cmp::Reverse(*n));
        for (k, n) in v.iter().take(200) {
            eprintln!("PERF_SUBPASS\t{k}\t{:.3}\t{:.2}", *n as f64 / 1e6, 100.0 * *n as f64 / t);
        }
    }
    if let Some(f) = FUNCS.get() {
        let mut v = f.lock().unwrap().clone();
        v.sort_by_key(|r| std::cmp::Reverse(r.2));
        let n = v.len();
        let sum: u64 = v.iter().map(|r| r.2).sum();
        let s = sum.max(1) as f64;
        let cum = |k: usize| -> f64 {
            100.0 * v.iter().take(k).map(|r| r.2).sum::<u64>() as f64 / s
        };
        eprintln!(
            "PERF_DIST\tfuncs={n}\tsum_ms={:.1}\ttop1={:.1}%\ttop5={:.1}%\ttop10={:.1}%\ttop1pct={:.1}%\ttop10pct={:.1}%",
            sum as f64 / 1e6,
            cum(1.min(n)),
            cum(5.min(n)),
            cum(10.min(n)),
            cum((n / 100).max(1)),
            cum((n / 10).max(1))
        );
        for r in v.iter().take(10) {
            eprintln!(
                "PERF_FUNC\t{:#x}\tinsns={}\ttotal_ms={:.2}\ttext_ms={:.2}",
                r.0,
                r.1,
                r.2 as f64 / 1e6,
                r.3 as f64 / 1e6
            );
        }
    }
}
