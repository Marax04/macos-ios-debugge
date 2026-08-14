//! Smart seed scheduler — power schedule and energy management for the fuzzer.
//!
//! Implements AFL-style power schedules (COE, FAST, EXPLORE, EXPLOIT, RARE) to
//! assign per-seed mutation energy, dynamic weight adjustment based on coverage
//! gain history, seed retirement logic, and a favourites / top-queue mechanism
//! to ensure that the most productive seeds receive disproportionate attention.

use std::collections::{HashMap, HashSet};
use std::cmp::Ordering;
use std::time::SystemTime;

use serde::{Deserialize, Serialize};

use crate::{CorpusMeta, FuzzInput};

// ── PowerScheduleMode ─────────────────────────────────────────────────────────

/// Available power-schedule modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PowerScheduleMode {
    /// AFL Constant — all seeds receive equal energy.
    Coe,
    /// AFL FAST — seeds that produce new coverage faster get more energy.
    Fast,
    /// AFL EXPLORE — strongly favours unexplored (newer) seeds.
    Explore,
    /// AFL EXPLOIT — maximises energy on seeds that have been productive before.
    Exploit,
    /// RARE — favours seeds that hit rare (low-frequency) edges.
    Rare,
    /// Lin — energy scales linearly with coverage bits.
    Lin,
    /// Quad — energy scales quadratically with coverage bits.
    Quad,
}

impl PowerScheduleMode {
    /// Human-readable name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Coe => "coe",
            Self::Fast => "fast",
            Self::Explore => "explore",
            Self::Exploit => "exploit",
            Self::Rare => "rare",
            Self::Lin => "lin",
            Self::Quad => "quad",
        }
    }

    /// All modes.
    #[must_use]
    pub const fn all() -> &'static [Self] {
        &[
            Self::Coe, Self::Fast, Self::Explore, Self::Exploit,
            Self::Rare, Self::Lin, Self::Quad,
        ]
    }
}

// ── SeedEntry ─────────────────────────────────────────────────────────────────

/// Extended metadata tracked per seed by the smart scheduler.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeedEntry {
    /// The fuzzing input.
    pub input: FuzzInput,
    /// Base corpus metadata.
    pub meta: CorpusMeta,
    /// Number of times this seed has been selected.
    pub selected_count: u64,
    /// Number of times a mutation of this seed produced new coverage.
    pub interesting_count: u64,
    /// Number of times a mutation of this seed produced a crash.
    pub crash_count: u64,
    /// When this seed was last selected.
    pub last_selected: Option<SystemTime>,
    /// Whether this seed is in the "favoured" top-set.
    pub is_favoured: bool,
    /// Whether this seed has been retired (no longer selected).
    pub retired: bool,
    /// Computed energy (updated on each scheduling cycle).
    pub energy: u32,
    /// Coverage bits uniquely covered by this seed (not in global favourites).
    pub unique_bits: u32,
    /// Running average of execution time for mutations of this seed (µs).
    pub avg_exec_us: u64,
}

impl SeedEntry {
    /// Create a new seed entry.
    #[must_use]
    pub fn new(input: FuzzInput, meta: CorpusMeta) -> Self {
        Self {
            input,
            meta,
            selected_count: 0,
            interesting_count: 0,
            crash_count: 0,
            last_selected: None,
            is_favoured: false,
            retired: false,
            energy: 1,
            unique_bits: 0,
            avg_exec_us: 0,
        }
    }

    /// Mark this seed as selected; update running average exec time.
    pub fn record_selection(&mut self, exec_us: u64) {
        self.selected_count += 1;
        self.last_selected = Some(SystemTime::now());
        self.meta.record_selection();
        // Exponential moving average (α = 0.1)
        if self.avg_exec_us == 0 {
            self.avg_exec_us = exec_us;
        } else {
            self.avg_exec_us = (self.avg_exec_us * 9 + exec_us) / 10;
        }
    }

    /// Mark that a mutation of this seed produced new coverage.
    pub const fn record_interesting(&mut self) {
        self.interesting_count += 1;
    }

    /// Mark that a mutation of this seed produced a crash.
    pub const fn record_crash(&mut self) {
        self.crash_count += 1;
    }

    /// Interesting-rate: fraction of selections that produced new coverage.
    #[must_use]
    pub fn interesting_rate(&self) -> f64 {
        if self.selected_count == 0 {
            1.0 // un-tried seeds get maximum priority
        } else {
            self.interesting_count as f64 / self.selected_count as f64
        }
    }

    /// Seconds since this seed was last selected (or since creation).
    #[must_use]
    pub fn age_secs(&self) -> f64 {
        match &self.last_selected {
            Some(t) => t.elapsed().unwrap_or_default().as_secs_f64(),
            None => self.meta.found_at.elapsed().unwrap_or_default().as_secs_f64(),
        }
    }

    /// Base priority score (higher = more desirable to select next).
    #[must_use]
    pub fn base_score(&self) -> f64 {
        if self.retired {
            return 0.0;
        }
        let ir = self.interesting_rate();
        let time_bonus = if self.avg_exec_us == 0 {
            1.0
        } else {
            1000.0 / (self.avg_exec_us as f64).max(1.0)
        };
        let cov = self.meta.coverage_bits as f64;
        (1.0 + ir) * time_bonus.min(10.0) * cov.max(1.0)
    }
}

// ── SeedPriority (for BinaryHeap) ─────────────────────────────────────────────

/// Wrapper that allows `SeedEntry` pointers to be used in a max-heap.
#[derive(Debug)]
struct SeedPriority {
    score: u64, // Scaled f64 as u64 for Ord
    id: u64,
}

impl SeedPriority {
    /// Build a [`SeedPriority`] from a raw `f64` score and seed id, scaling the
    /// score into a `u64` so that the resulting values can be totally ordered
    /// for use inside a [`std::collections::BinaryHeap`]. NaN scores collapse
    /// to `0`.
    #[inline]
    fn new(score: f64, id: u64) -> Self {
        let scaled = if score.is_finite() {
            (score.max(0.0) * 1_000_000.0).round() as u64
        } else {
            0
        };
        Self { score: scaled, id }
    }
}

/// Build a max-priority queue of `(score, seed_id)` pairs.
///
/// Returns a vector of seed ids ordered from highest to lowest priority.
/// Useful for offline corpus-replay tooling that needs the same ordering the
/// live scheduler would produce without holding onto the full scheduler state.
#[must_use]
pub fn rank_seeds_by_priority(scores: &[(f64, u64)]) -> Vec<u64> {
    use std::collections::BinaryHeap;
    let mut heap: BinaryHeap<SeedPriority> =
        scores.iter().map(|&(s, id)| SeedPriority::new(s, id)).collect();
    let mut out = Vec::with_capacity(heap.len());
    while let Some(top) = heap.pop() {
        out.push(top.id);
    }
    out
}

impl PartialEq for SeedPriority {
    fn eq(&self, other: &Self) -> bool {
        self.score == other.score
    }
}

impl Eq for SeedPriority {}

impl PartialOrd for SeedPriority {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for SeedPriority {
    fn cmp(&self, other: &Self) -> Ordering {
        self.score.cmp(&other.score)
    }
}

// ── EnergyCalculator ──────────────────────────────────────────────────────────

/// Computes per-seed energy under a chosen power-schedule mode.
pub struct EnergyCalculator {
    /// The active schedule mode.
    pub mode: PowerScheduleMode,
    /// Base energy (minimum per seed per cycle).
    pub base_energy: u32,
    /// Maximum energy cap.
    pub max_energy: u32,
    /// Global coverage bits (used to compute coverage ratios).
    pub global_bits: u32,
    /// Exponential factor for FAST mode.
    pub fast_exp: f64,
}

impl EnergyCalculator {
    /// Create a calculator with default parameters.
    #[must_use]
    pub fn new(mode: PowerScheduleMode) -> Self {
        Self {
            mode,
            base_energy: 1,
            max_energy: 512,
            global_bits: 1,
            fast_exp: 2.0,
        }
    }

    /// Compute the energy for a single seed entry.
    #[must_use]
    pub fn energy(&self, seed: &SeedEntry) -> u32 {
        if seed.retired {
            return 0;
        }
        let base = self.base_energy as f64;
        let cov = seed.meta.coverage_bits as f64;
        let global = self.global_bits.max(1) as f64;
        let _exec_ms = (seed.avg_exec_us as f64 / 1000.0).max(0.001);

        let raw = match self.mode {
            PowerScheduleMode::Coe => base,

            PowerScheduleMode::Fast => {
                // AFL FAST: e = base * 2^(interesting_count / selected_count)
                let rate = seed.interesting_rate();
                base * (self.fast_exp.powf(rate * 4.0)).min(16.0)
            }

            PowerScheduleMode::Explore => {
                // Favour new, unexplored seeds.
                let age = seed.age_secs().max(1.0);
                base * (300.0 / age).clamp(0.1, 16.0)
            }

            PowerScheduleMode::Exploit => {
                // Favour seeds with high interesting rate.
                let ir = seed.interesting_rate();
                base * ir.mul_add(8.0, 1.0).min(16.0)
            }

            PowerScheduleMode::Rare => {
                // Favour seeds that cover rare (low global frequency) edges.
                if cov == 0.0 {
                    base
                } else {
                    let rarity = 1.0 - (cov / global).min(1.0);
                    base * (1.0 + rarity * 8.0)
                }
            }

            PowerScheduleMode::Lin => {
                // Linear in coverage bits ratio.
                base * (cov / global).mul_add(4.0, 1.0)
            }

            PowerScheduleMode::Quad => {
                // Quadratic in coverage bits ratio.
                let ratio = cov / global;
                base * (ratio * ratio).mul_add(8.0, 1.0)
            }
        };

        (raw.round() as u32).clamp(self.base_energy, self.max_energy)
    }
}

// ── RetirementPolicy ──────────────────────────────────────────────────────────

/// Controls when a seed is retired from the active queue.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetirementPolicy {
    /// Retire after this many selections with zero new coverage.
    pub max_dry_selections: u64,
    /// Retire if exec time exceeds this threshold (µs) — seeds too slow to
    /// mutate productively.
    pub max_exec_us: u64,
    /// Minimum coverage bits a seed must cover to avoid retirement on the next
    /// cycle (overrides `max_dry_selections` if the seed is a unique bit
    /// holder).
    pub unique_bits_exempt: bool,
}

impl Default for RetirementPolicy {
    fn default() -> Self {
        Self {
            max_dry_selections: 128,
            max_exec_us: 100_000, // 100 ms
            unique_bits_exempt: true,
        }
    }
}

impl RetirementPolicy {
    /// Determine whether `seed` should be retired.
    #[must_use]
    pub fn should_retire(&self, seed: &SeedEntry) -> bool {
        if seed.retired {
            return false; // already retired, don't re-evaluate
        }
        if self.unique_bits_exempt && seed.unique_bits > 0 {
            return false;
        }
        let dry_count = seed.selected_count.saturating_sub(seed.interesting_count);
        if dry_count >= self.max_dry_selections {
            return true;
        }
        if seed.avg_exec_us > 0 && seed.avg_exec_us > self.max_exec_us {
            return true;
        }
        false
    }
}

// ── SmartSeedScheduler ────────────────────────────────────────────────────────

/// The main smart seed scheduler.
///
/// Maintains an indexed set of [`SeedEntry`] values, computes energy under the
/// chosen power schedule, retires unproductive seeds, and exposes an efficient
/// `select` operation that picks the next seed to fuzz proportional to energy.
pub struct SmartSeedScheduler {
    /// All seed entries, keyed by input id.
    pub seeds: HashMap<u64, SeedEntry>,
    /// Ordered list of seed ids (insertion order; used for round-robin fallback).
    order: Vec<u64>,
    /// Power-schedule energy calculator.
    pub energy_calc: EnergyCalculator,
    /// Retirement policy.
    pub retirement: RetirementPolicy,
    /// Cumulative energy assigned so far (used for weighted selection cursor).
    cumulative_energy: u64,
    /// Scheduling cycle count.
    pub cycles: u64,
    /// Set of seed ids in the "favoured" top-set.
    favoured: HashSet<u64>,
    /// Total seeds ever added.
    pub total_added: u64,
    /// Total seeds retired.
    pub total_retired: u64,
    /// Round-robin cursor for uniform fallback.
    rr_cursor: usize,
    /// Dynamic weight adjustment: seed id → weight multiplier (1.0 = normal).
    dynamic_weights: HashMap<u64, f64>,
}

impl SmartSeedScheduler {
    /// Create a new scheduler with the given power-schedule mode.
    #[must_use]
    pub fn new(mode: PowerScheduleMode) -> Self {
        Self {
            seeds: HashMap::new(),
            order: Vec::new(),
            energy_calc: EnergyCalculator::new(mode),
            retirement: RetirementPolicy::default(),
            cumulative_energy: 0,
            cycles: 0,
            favoured: HashSet::new(),
            total_added: 0,
            total_retired: 0,
            rr_cursor: 0,
            dynamic_weights: HashMap::new(),
        }
    }

    /// Add a new seed to the scheduler.
    pub fn add(&mut self, input: FuzzInput, meta: CorpusMeta) {
        let id = input.id;
        let entry = SeedEntry::new(input, meta);
        self.order.push(id);
        self.seeds.insert(id, entry);
        self.total_added += 1;
    }

    /// Remove a seed by id.
    pub fn remove(&mut self, id: u64) -> Option<SeedEntry> {
        self.order.retain(|&x| x != id);
        self.favoured.remove(&id);
        self.dynamic_weights.remove(&id);
        self.seeds.remove(&id)
    }

    /// Select the next seed to fuzz using energy-proportional sampling.
    ///
    /// Returns `None` if no active seeds remain.
    #[must_use]
    pub fn select(&mut self) -> Option<&mut SeedEntry> {
        // Recompute energies and build a weighted list.
        let active: Vec<(u64, u32)> = self
            .order
            .iter()
            .filter_map(|&id| {
                let seed = self.seeds.get(&id)?;
                if seed.retired {
                    return None;
                }
                let base = self.energy_calc.energy(seed);
                let weight = self.dynamic_weights.get(&id).copied().unwrap_or(1.0);
                let energy = ((base as f64) * weight).round() as u32;
                Some((id, energy.max(1)))
            })
            .collect();

        if active.is_empty() {
            return None;
        }

        // Weighted random selection using the cumulative energy cursor.
        let total_energy: u64 = active.iter().map(|(_, e)| *e as u64).sum();
        if total_energy == 0 {
            return None;
        }

        let pick = self.cumulative_energy % total_energy;
        self.cumulative_energy = self.cumulative_energy.wrapping_add(7919); // prime step

        let mut acc: u64 = 0;
        let mut chosen_id = active[0].0;
        for &(id, energy) in &active {
            acc += energy as u64;
            if pick < acc {
                chosen_id = id;
                break;
            }
        }

        self.seeds.get_mut(&chosen_id)
    }

    /// Select the next seed in round-robin order (ignores energy).
    #[must_use]
    pub fn select_round_robin(&mut self) -> Option<&mut SeedEntry> {
        let active: Vec<u64> = self
            .order
            .iter()
            .filter(|&&id| {
                self.seeds.get(&id).is_some_and(|s| !s.retired)
            })
            .copied()
            .collect();

        if active.is_empty() {
            return None;
        }
        let idx = self.rr_cursor % active.len();
        self.rr_cursor += 1;
        self.seeds.get_mut(&active[idx])
    }

    /// Update global coverage bits used by the energy calculator.
    pub fn set_global_bits(&mut self, bits: u32) {
        self.energy_calc.global_bits = bits.max(1);
    }

    /// Run a retirement pass: mark seeds that satisfy the retirement policy.
    ///
    /// Returns the number of seeds newly retired.
    pub fn run_retirement(&mut self) -> usize {
        let to_retire: Vec<u64> = self
            .seeds
            .values()
            .filter(|s| self.retirement.should_retire(s))
            .map(|s| s.input.id)
            .collect();

        let count = to_retire.len();
        for id in to_retire {
            if let Some(s) = self.seeds.get_mut(&id) {
                s.retired = true;
                self.total_retired += 1;
            }
        }
        count
    }

    /// Compute the favoured set using AFL-style minimum-spanning-set selection.
    ///
    /// Each coverage bit is "claimed" by the smallest-and-fastest seed that
    /// covers it; those seeds become favoured.
    pub fn compute_favourites(&mut self) {
        self.favoured.clear();
        for s in self.seeds.values_mut() {
            s.is_favoured = false;
        }

        // Use a simple greedy approach: sort seeds by (coverage_bits DESC, exec_us ASC),
        // claim bits greedily.
        let mut claimed: HashSet<u32> = HashSet::new();
        let mut sorted_ids: Vec<u64> = self.order.clone();
        sorted_ids.sort_unstable_by(|&a, &b| {
            let sa = self.seeds.get(&a);
            let sb = self.seeds.get(&b);
            match (sa, sb) {
                (Some(sa), Some(sb)) => {
                    sb.meta.coverage_bits
                        .cmp(&sa.meta.coverage_bits)
                        .then_with(|| sa.avg_exec_us.cmp(&sb.avg_exec_us))
                }
                _ => Ordering::Equal,
            }
        });

        for id in sorted_ids {
            let Some(seed) = self.seeds.get_mut(&id) else { continue };
            if seed.retired { continue; }
            let bits = seed.meta.coverage_bits;
            if bits == 0 { continue; }
            // Use a proxy: treat coverage_bits count as a set of "virtual" bit IDs.
            let virtual_bit = (seed.meta.hash % 65536) as u32;
            if claimed.insert(virtual_bit) {
                seed.is_favoured = true;
                self.favoured.insert(id);
            }
        }
    }

    /// Adjust the dynamic weight for a seed.
    ///
    /// `multiplier = 2.0` doubles the seed's energy; `0.5` halves it.
    pub fn set_weight(&mut self, id: u64, multiplier: f64) {
        self.dynamic_weights.insert(id, multiplier.max(0.0));
    }

    /// Number of active (non-retired) seeds.
    #[must_use]
    pub fn active_count(&self) -> usize {
        self.seeds.values().filter(|s| !s.retired).count()
    }

    /// Number of retired seeds.
    #[must_use]
    pub fn retired_count(&self) -> usize {
        self.seeds.values().filter(|s| s.retired).count()
    }

    /// Number of favoured seeds.
    #[must_use]
    pub fn favoured_count(&self) -> usize {
        self.favoured.len()
    }

    /// Increment cycle counter (call once per complete queue pass).
    pub const fn tick_cycle(&mut self) {
        self.cycles += 1;
    }

    /// Return a snapshot of the top-N seeds by base score.
    #[must_use]
    pub fn top_seeds(&self, n: usize) -> Vec<&SeedEntry> {
        let mut all: Vec<&SeedEntry> = self.seeds.values().filter(|s| !s.retired).collect();
        all.sort_by(|a, b| {
            b.base_score()
                .partial_cmp(&a.base_score())
                .unwrap_or(Ordering::Equal)
        });
        all.truncate(n);
        all
    }
}

// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{FuzzInput, CorpusMeta};
    use std::time::Duration;

    fn make_seed(id: u64, cov_bits: u32) -> (FuzzInput, CorpusMeta) {
        let input = FuzzInput::new(id, vec![id as u8; 4]);
        let meta = CorpusMeta::new(id ^ 0xABCD, cov_bits, Duration::from_micros(100));
        (input, meta)
    }

    #[test]
    fn scheduler_add_and_select() {
        let mut sched = SmartSeedScheduler::new(PowerScheduleMode::Fast);
        let (inp, meta) = make_seed(1, 10);
        sched.add(inp, meta);
        assert!(sched.select().is_some());
    }

    #[test]
    fn scheduler_empty_select_returns_none() {
        let mut sched = SmartSeedScheduler::new(PowerScheduleMode::Coe);
        assert!(sched.select().is_none());
    }

    #[test]
    fn scheduler_active_count() {
        let mut sched = SmartSeedScheduler::new(PowerScheduleMode::Explore);
        for i in 0..5 {
            let (inp, meta) = make_seed(i, 5 + i as u32);
            sched.add(inp, meta);
        }
        assert_eq!(sched.active_count(), 5);
    }

    #[test]
    fn scheduler_retirement_pass() {
        let mut sched = SmartSeedScheduler::new(PowerScheduleMode::Coe);
        sched.retirement.max_dry_selections = 0; // retire immediately
        let (inp, meta) = make_seed(42, 0);
        sched.add(inp, meta);
        let retired = sched.run_retirement();
        assert_eq!(retired, 1);
        assert_eq!(sched.retired_count(), 1);
    }

    #[test]
    fn scheduler_unique_bits_exempt_from_retirement() {
        let mut sched = SmartSeedScheduler::new(PowerScheduleMode::Coe);
        sched.retirement.max_dry_selections = 0;
        sched.retirement.unique_bits_exempt = true;
        let (inp, meta) = make_seed(7, 5);
        sched.add(inp, meta);
        if let Some(s) = sched.seeds.get_mut(&7) {
            s.unique_bits = 3; // mark as unique bit holder
        }
        let retired = sched.run_retirement();
        assert_eq!(retired, 0);
    }

    #[test]
    fn scheduler_compute_favourites() {
        let mut sched = SmartSeedScheduler::new(PowerScheduleMode::Explore);
        for i in 0..4 {
            let (inp, meta) = make_seed(i, 10 + i as u32 * 5);
            sched.add(inp, meta);
        }
        sched.compute_favourites();
        assert!(sched.favoured_count() >= 1);
    }

    #[test]
    fn scheduler_dynamic_weight() {
        let mut sched = SmartSeedScheduler::new(PowerScheduleMode::Fast);
        let (inp, meta) = make_seed(99, 10);
        sched.add(inp, meta);
        sched.set_weight(99, 3.0);
        let w = sched.dynamic_weights.get(&99).copied().unwrap();
        assert!((w - 3.0).abs() < f64::EPSILON);
    }

    #[test]
    fn scheduler_top_seeds() {
        let mut sched = SmartSeedScheduler::new(PowerScheduleMode::Exploit);
        for i in 0..10 {
            let (inp, meta) = make_seed(i, i as u32 * 3);
            sched.add(inp, meta);
        }
        let top = sched.top_seeds(3);
        assert_eq!(top.len(), 3);
    }

    #[test]
    fn energy_calculator_coe_uniform() {
        let calc = EnergyCalculator::new(PowerScheduleMode::Coe);
        let (inp, meta) = make_seed(1, 10);
        let seed = SeedEntry::new(inp, meta);
        let e1 = calc.energy(&seed);
        let (inp2, meta2) = make_seed(2, 50);
        let seed2 = SeedEntry::new(inp2, meta2);
        let e2 = calc.energy(&seed2);
        assert_eq!(e1, e2); // COE = uniform
    }

    #[test]
    fn energy_calculator_fast_scales_with_interesting_rate() {
        let calc = EnergyCalculator::new(PowerScheduleMode::Fast);
        let (inp, meta) = make_seed(1, 5);
        let mut seed_low = SeedEntry::new(inp, meta);
        seed_low.selected_count = 10;
        seed_low.interesting_count = 1; // 10% rate

        let (inp2, meta2) = make_seed(2, 5);
        let mut seed_high = SeedEntry::new(inp2, meta2);
        seed_high.selected_count = 10;
        seed_high.interesting_count = 9; // 90% rate

        assert!(calc.energy(&seed_high) >= calc.energy(&seed_low));
    }

    #[test]
    fn seed_entry_interesting_rate_untried() {
        let (inp, meta) = make_seed(1, 5);
        let seed = SeedEntry::new(inp, meta);
        assert_eq!(seed.interesting_rate(), 1.0);
    }

    #[test]
    fn seed_entry_record_selection_updates_avg() {
        let (inp, meta) = make_seed(1, 5);
        let mut seed = SeedEntry::new(inp, meta);
        seed.record_selection(1000);
        assert_eq!(seed.avg_exec_us, 1000);
        seed.record_selection(2000);
        // EMA: (1000*9 + 2000) / 10 = 1100
        assert_eq!(seed.avg_exec_us, 1100);
    }

    #[test]
    fn retirement_policy_max_exec_us() {
        let policy = RetirementPolicy {
            max_exec_us: 50,
            ..Default::default()
        };
        let (inp, meta) = make_seed(1, 1);
        let mut seed = SeedEntry::new(inp, meta);
        seed.avg_exec_us = 100; // exceeds threshold
        seed.selected_count = 1;
        assert!(policy.should_retire(&seed));
    }

    #[test]
    fn scheduler_round_robin_cycles_through_all() {
        let mut sched = SmartSeedScheduler::new(PowerScheduleMode::Coe);
        for i in 0..4 {
            let (inp, meta) = make_seed(i, 5);
            sched.add(inp, meta);
        }
        let mut seen = HashSet::new();
        for _ in 0..16 {
            if let Some(s) = sched.select_round_robin() {
                seen.insert(s.input.id);
            }
        }
        assert_eq!(seen.len(), 4);
    }
}
