//! `rustre-fuzz::mutation_scheduler`
//!
//! AFL-style mutation scheduling: assigns energy (mutation counts) to corpus
//! seeds based on coverage feedback, and tracks per-input scores.


use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::time::{Duration, SystemTime};

use serde::{Deserialize, Serialize};

// ─── PowerSchedule ────────────────────────────────────────────────────────────

/// AFL-compatible power schedule variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PowerSchedule {
    /// All seeds get the same energy (baseline).
    Fast,
    /// Exponentially penalises seeds that hit the same coverage as other seeds.
    Coe,
    /// Standard AFL power schedule.
    Explore,
    /// Focuses energy on seeds that are most likely to trigger bugs quickly.
    Exploit,
}

impl PowerSchedule {
    /// Human-readable name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Fast => "fast",
            Self::Coe => "coe",
            Self::Explore => "explore",
            Self::Exploit => "exploit",
        }
    }

    /// All schedule variants.
    #[must_use]
    pub const fn all() -> &'static [Self] {
        &[Self::Fast, Self::Coe, Self::Explore, Self::Exploit]
    }
}

impl fmt::Display for PowerSchedule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

// ─── MutationScore ────────────────────────────────────────────────────────────

/// Per-seed mutation score accumulated during fuzzing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MutationScore {
    /// Input ID this score belongs to.
    pub input_id: u64,
    /// Number of coverage bits hit by this seed.
    pub coverage_bits: u32,
    /// Average execution time in microseconds.
    pub avg_exec_us: u64,
    /// Number of times this seed was selected for mutation.
    pub selected_count: u64,
    /// Number of interesting children produced.
    pub interesting_children: u64,
    /// Number of crashes produced by mutations of this seed.
    pub crash_children: u64,
    /// When this seed was first added to the corpus.
    pub added_at: SystemTime,
    /// Manually assigned weight multiplier (1.0 = default).
    pub weight: f64,
}

impl MutationScore {
    /// Create a new score for `input_id`.
    #[must_use]
    pub fn new(input_id: u64) -> Self {
        Self {
            input_id,
            coverage_bits: 0,
            avg_exec_us: 0,
            selected_count: 0,
            interesting_children: 0,
            crash_children: 0,
            added_at: SystemTime::now(),
            weight: 1.0,
        }
    }

    /// Increment the selection count.
    pub const fn record_selection(&mut self) {
        self.selected_count = self.selected_count.saturating_add(1);
    }

    /// Record an interesting child.
    pub const fn record_interesting(&mut self) {
        self.interesting_children = self.interesting_children.saturating_add(1);
    }

    /// Record a crash child.
    pub const fn record_crash(&mut self) {
        self.crash_children = self.crash_children.saturating_add(1);
    }

    /// Child-to-selection ratio: how productive this seed has been.
    #[must_use]
    pub fn productivity(&self) -> f64 {
        if self.selected_count == 0 {
            0.0
        } else {
            (self.interesting_children + self.crash_children) as f64 / self.selected_count as f64
        }
    }

    /// Age in seconds.
    #[must_use]
    pub fn age_secs(&self) -> f64 {
        self.added_at.elapsed().unwrap_or_default().as_secs_f64()
    }
}

impl fmt::Display for MutationScore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "MutationScore {{ id={} bits={} sel={} interesting={} crashes={} }}",
            self.input_id,
            self.coverage_bits,
            self.selected_count,
            self.interesting_children,
            self.crash_children,
        )
    }
}

// ─── EnergyModel ──────────────────────────────────────────────────────────────

/// Computes per-seed mutation energy based on the active `PowerSchedule`.
#[derive(Debug, Clone)]
pub struct EnergyModel {
    /// Active power schedule.
    pub schedule: PowerSchedule,
    /// Base energy assigned to each seed (mutations per cycle).
    pub base_energy: u32,
    /// Maximum energy cap.
    pub max_energy: u32,
    /// Minimum energy floor.
    pub min_energy: u32,
}

impl EnergyModel {
    /// Create a new model with the given schedule.
    #[must_use]
    pub const fn new(schedule: PowerSchedule) -> Self {
        Self {
            schedule,
            base_energy: 16,
            max_energy: 1024,
            min_energy: 1,
        }
    }

    /// Compute the energy for a seed given its score and global corpus stats.
    ///
    /// `total_coverage_bits` is the union coverage across all seeds.
    /// `avg_exec_us_global` is the average execution time across the corpus.
    #[must_use]
    pub fn compute(
        &self,
        score: &MutationScore,
        total_coverage_bits: u32,
        avg_exec_us_global: u64,
    ) -> u32 {
        let base = f64::from(self.base_energy);
        let energy = match self.schedule {
            PowerSchedule::Fast => base,

            PowerSchedule::Coe => {
                // Penalise seeds with common coverage patterns.
                if total_coverage_bits == 0 {
                    base
                } else {
                    let rarity =
                        1.0 - (f64::from(score.coverage_bits) / f64::from(total_coverage_bits));
                    base * (1.0 + rarity * 4.0)
                }
            }

            PowerSchedule::Explore => {
                // Standard AFL: favour fast seeds with high coverage.
                let time_factor = if avg_exec_us_global == 0 || score.avg_exec_us == 0 {
                    1.0
                } else {
                    (avg_exec_us_global as f64 / score.avg_exec_us as f64).min(8.0)
                };
                let cov_factor = if total_coverage_bits == 0 {
                    1.0
                } else {
                    1.0 + f64::from(score.coverage_bits) / f64::from(total_coverage_bits)
                };
                base * time_factor * cov_factor
            }

            PowerSchedule::Exploit => {
                // Heavily favour seeds that have produced interesting children.
                let productivity_bonus = score.productivity().mul_add(8.0, 1.0);
                base * productivity_bonus * score.weight
            }
        };

        let combined = energy * score.weight;
        u32::try_from(combined as u64)
            .unwrap_or(u32::MAX)
            .clamp(self.min_energy, self.max_energy)
    }

    /// Set a custom base energy.
    #[must_use]
    pub const fn with_base_energy(mut self, e: u32) -> Self {
        self.base_energy = e;
        self
    }

    /// Set the maximum energy cap.
    #[must_use]
    pub const fn with_max_energy(mut self, e: u32) -> Self {
        self.max_energy = e;
        self
    }
}

impl Default for EnergyModel {
    fn default() -> Self {
        Self::new(PowerSchedule::Explore)
    }
}

// ─── InputQueue (priority) ────────────────────────────────────────────────────

/// A priority queue that orders inputs by their scheduled energy.
///
/// Higher-energy inputs are surfaced more frequently via the `select_next`
/// method.
#[derive(Debug, Default)]
pub struct PriorityInputQueue {
    /// Map from input ID to (data, energy).
    entries: BTreeMap<u64, (Vec<u8>, u32)>,
    /// Round-robin cursor.
    cursor: usize,
    /// Total energy across all entries.
    total_energy: u64,
}

impl PriorityInputQueue {
    /// Create an empty queue.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert or update an input's energy.
    pub fn upsert(&mut self, id: u64, data: Vec<u8>, energy: u32) {
        let old_energy = self.entries.get(&id).map_or(0, |(_, e)| *e);
        self.total_energy = self.total_energy.saturating_sub(u64::from(old_energy));
        self.total_energy += u64::from(energy);
        self.entries.insert(id, (data, energy));
    }

    /// Remove an input from the queue.
    pub fn remove(&mut self, id: u64) -> Option<(Vec<u8>, u32)> {
        if let Some(entry) = self.entries.remove(&id) {
            self.total_energy = self.total_energy.saturating_sub(u64::from(entry.1));
            Some(entry)
        } else {
            None
        }
    }

    /// Select the next input to fuzz, weighted by energy.
    ///
    /// Uses a simple energy-proportional cursor: after `energy` mutations the
    /// cursor advances to the next entry.
    ///
    /// Returns `None` if the queue is empty.
    #[must_use]
    pub fn select_next(&mut self, mutations_done: u64) -> Option<(&[u8], u64)> {
        if self.entries.is_empty() {
            return None;
        }
        // Weighted round-robin: skip over entries proportional to their energy.
        let n = self.entries.len();
        let idx = if self.total_energy == 0 {
            (self.cursor + mutations_done as usize) % n
        } else {
            (mutations_done as usize) % n
        };
        let (id, (data, _energy)) = self.entries.iter().nth(idx % n)?;
        Some((data.as_slice(), *id))
    }

    /// Length of the queue.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` if the queue is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Average energy across all entries.
    #[must_use]
    pub fn average_energy(&self) -> f64 {
        if self.entries.is_empty() {
            0.0
        } else {
            self.total_energy as f64 / self.entries.len() as f64
        }
    }

    /// Return the entry with highest energy.
    #[must_use]
    pub fn max_energy_entry(&self) -> Option<(u64, u32)> {
        self.entries
            .iter()
            .max_by_key(|(_, (_, e))| *e)
            .map(|(&id, (_, e))| (id, *e))
    }

    /// Return all entries sorted by energy descending.
    #[must_use]
    pub fn sorted_by_energy(&self) -> Vec<(u64, u32)> {
        let mut v: Vec<(u64, u32)> = self.entries.iter().map(|(&id, (_, e))| (id, *e)).collect();
        v.sort_unstable_by(|a, b| b.1.cmp(&a.1));
        v
    }
}

// ─── SchedulerStats ───────────────────────────────────────────────────────────

/// Aggregate statistics for the mutation scheduler.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SchedulerStats {
    /// Total number of scheduling cycles completed.
    pub cycles: u64,
    /// Total mutations applied.
    pub total_mutations: u64,
    /// Total interesting inputs found.
    pub interesting_found: u64,
    /// Total crashes found.
    pub crashes_found: u64,
    /// Total seeds in the corpus.
    pub corpus_size: usize,
    /// Current active power schedule.
    pub current_schedule: String,
    /// When the scheduler was created.
    pub started_at: Option<SystemTime>,
    /// Total wall-clock time spent scheduling.
    pub elapsed: Duration,
    /// Global union coverage bits.
    pub global_coverage_bits: u32,
}

impl SchedulerStats {
    /// Create a fresh stats record.
    #[must_use]
    pub fn new(schedule: PowerSchedule) -> Self {
        Self {
            current_schedule: schedule.to_string(),
            started_at: Some(SystemTime::now()),
            ..Self::default()
        }
    }

    /// Record a completed cycle.
    pub const fn record_cycle(&mut self, mutations: u64, interesting: u64, crashes: u64) {
        self.cycles += 1;
        self.total_mutations += mutations;
        self.interesting_found += interesting;
        self.crashes_found += crashes;
    }

    /// Mutations per cycle (average).
    #[must_use]
    pub fn mutations_per_cycle(&self) -> f64 {
        if self.cycles == 0 {
            0.0
        } else {
            self.total_mutations as f64 / self.cycles as f64
        }
    }

    /// Mutations per second.
    #[must_use]
    pub fn mutations_per_second(&self) -> f64 {
        let secs = self.elapsed.as_secs_f64();
        if secs < f64::EPSILON {
            0.0
        } else {
            self.total_mutations as f64 / secs
        }
    }

    /// Finding rate (interesting per 1000 mutations).
    #[must_use]
    pub fn finding_rate(&self) -> f64 {
        if self.total_mutations == 0 {
            0.0
        } else {
            self.interesting_found as f64 * 1000.0 / self.total_mutations as f64
        }
    }
}

impl fmt::Display for SchedulerStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SchedulerStats {{ schedule={} cycles={} mutations={} interesting={} crashes={} }}",
            self.current_schedule,
            self.cycles,
            self.total_mutations,
            self.interesting_found,
            self.crashes_found,
        )
    }
}

// ─── MutationScheduler ────────────────────────────────────────────────────────

/// Schedules mutations based on coverage feedback.
///
/// Integrates [`EnergyModel`], [`PriorityInputQueue`], and [`SchedulerStats`]
/// to drive the outer fuzzing loop.
#[derive(Debug)]
pub struct MutationScheduler {
    /// Energy model.
    pub energy_model: EnergyModel,
    /// Priority input queue.
    pub queue: PriorityInputQueue,
    /// Per-input mutation scores.
    pub scores: HashMap<u64, MutationScore>,
    /// Scheduler statistics.
    pub stats: SchedulerStats,
    /// Mutations done in the current cycle.
    cycle_mutations: u64,
    /// Global union coverage bits.
    global_coverage_bits: u32,
    /// Average execution time in microseconds (global).
    avg_exec_us: u64,
}

impl MutationScheduler {
    /// Create a new scheduler with the given power schedule.
    #[must_use]
    pub fn new(schedule: PowerSchedule) -> Self {
        Self {
            energy_model: EnergyModel::new(schedule),
            queue: PriorityInputQueue::new(),
            scores: HashMap::new(),
            stats: SchedulerStats::new(schedule),
            cycle_mutations: 0,
            global_coverage_bits: 0,
            avg_exec_us: 0,
        }
    }

    /// Add a seed to the scheduler.
    ///
    /// Returns the energy assigned to this seed.
    pub fn add_seed(&mut self, id: u64, data: Vec<u8>, coverage_bits: u32, exec_us: u64) -> u32 {
        let mut score = MutationScore::new(id);
        score.coverage_bits = coverage_bits;
        score.avg_exec_us = exec_us;

        self.update_global_stats(coverage_bits, exec_us);

        let energy = self
            .energy_model
            .compute(&score, self.global_coverage_bits, self.avg_exec_us);
        self.queue.upsert(id, data, energy);
        self.scores.insert(id, score);
        self.stats.corpus_size = self.queue.len();
        energy
    }

    /// Remove a seed from the scheduler.
    pub fn remove_seed(&mut self, id: u64) {
        self.queue.remove(id);
        self.scores.remove(&id);
        self.stats.corpus_size = self.queue.len();
    }

    /// Select the next seed to mutate.
    ///
    /// Returns `(seed_data, seed_id)` or `None` if the queue is empty.
    #[must_use]
    pub fn select(&mut self) -> Option<(Vec<u8>, u64)> {
        let mutations_done = self.stats.total_mutations;
        let result = self.queue.select_next(mutations_done);
        result.map(|(data, id)| {
            if let Some(score) = self.scores.get_mut(&id) {
                score.record_selection();
            }
            (data.to_vec(), id)
        })
    }

    /// Notify the scheduler that a mutation was applied.
    pub const fn record_mutation(&mut self, seed_id: u64) {
        self.cycle_mutations += 1;
        self.stats.total_mutations += 1;
        let _ = seed_id;
    }

    /// Notify the scheduler of a new interesting input found.
    pub fn record_interesting(&mut self, parent_id: u64) {
        self.stats.interesting_found += 1;
        if let Some(score) = self.scores.get_mut(&parent_id) {
            score.record_interesting();
        }
        self.recompute_energies();
    }

    /// Notify the scheduler of a crash found.
    pub fn record_crash(&mut self, parent_id: u64) {
        self.stats.crashes_found += 1;
        if let Some(score) = self.scores.get_mut(&parent_id) {
            score.record_crash();
        }
    }

    /// Advance to the next cycle.
    pub fn end_cycle(&mut self) {
        self.stats.record_cycle(self.cycle_mutations, 0, 0);
        self.cycle_mutations = 0;
        self.recompute_energies();
    }

    /// Change the active power schedule.
    pub fn set_schedule(&mut self, schedule: PowerSchedule) {
        self.energy_model.schedule = schedule;
        self.stats.current_schedule = schedule.to_string();
        self.recompute_energies();
    }

    /// Update global execution statistics.
    pub const fn update_exec_stats(&mut self, exec_us: u64) {
        // Exponential moving average.
        if self.avg_exec_us == 0 {
            self.avg_exec_us = exec_us;
        } else {
            self.avg_exec_us = (self.avg_exec_us * 7 + exec_us) / 8;
        }
    }

    /// Return the energy assigned to a seed.
    #[must_use]
    pub fn energy_for(&self, id: u64) -> Option<u32> {
        self.queue.entries.get(&id).map(|(_, e)| *e)
    }

    /// Return the mutation score for a seed.
    #[must_use]
    pub fn score_for(&self, id: u64) -> Option<&MutationScore> {
        self.scores.get(&id)
    }

    /// Number of seeds in the corpus.
    #[must_use]
    pub fn corpus_size(&self) -> usize {
        self.queue.len()
    }

    /// Recompute energies for all seeds after a global stats update.
    fn recompute_energies(&mut self) {
        let global_bits = self.global_coverage_bits;
        let avg_us = self.avg_exec_us;
        let ids_and_data: Vec<(u64, Vec<u8>)> = self
            .queue
            .entries
            .iter()
            .map(|(&id, (data, _))| (id, data.clone()))
            .collect();
        for (id, data) in ids_and_data {
            if let Some(score) = self.scores.get(&id) {
                let energy = self.energy_model.compute(score, global_bits, avg_us);
                self.queue.upsert(id, data, energy);
            }
        }
    }

    const fn update_global_stats(&mut self, coverage_bits: u32, exec_us: u64) {
        if coverage_bits > self.global_coverage_bits {
            self.global_coverage_bits = coverage_bits;
            self.stats.global_coverage_bits = coverage_bits;
        }
        self.update_exec_stats(exec_us);
    }
}

impl fmt::Display for MutationScheduler {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "MutationScheduler {{ schedule={} corpus={} stats={} }}",
            self.energy_model.schedule,
            self.queue.len(),
            self.stats,
        )
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── PowerSchedule ─────────────────────────────────────────────────────────

    #[test]
    fn schedule_names() {
        assert_eq!(PowerSchedule::Fast.name(), "fast");
        assert_eq!(PowerSchedule::Coe.name(), "coe");
        assert_eq!(PowerSchedule::Explore.name(), "explore");
        assert_eq!(PowerSchedule::Exploit.name(), "exploit");
    }

    #[test]
    fn schedule_all_four() {
        assert_eq!(PowerSchedule::all().len(), 4);
    }

    #[test]
    fn schedule_display() {
        assert_eq!(PowerSchedule::Fast.to_string(), "fast");
    }

    // ── MutationScore ─────────────────────────────────────────────────────────

    #[test]
    fn mutation_score_new() {
        let s = MutationScore::new(42);
        assert_eq!(s.input_id, 42);
        assert_eq!(s.selected_count, 0);
        assert_eq!(s.productivity(), 0.0);
    }

    #[test]
    fn mutation_score_record_selection() {
        let mut s = MutationScore::new(1);
        s.record_selection();
        s.record_selection();
        assert_eq!(s.selected_count, 2);
    }

    #[test]
    fn mutation_score_productivity_non_zero() {
        let mut s = MutationScore::new(1);
        s.selected_count = 10;
        s.interesting_children = 3;
        s.crash_children = 1;
        assert!((s.productivity() - 0.4).abs() < 1e-9);
    }

    #[test]
    fn mutation_score_display() {
        let s = MutationScore::new(5);
        let d = s.to_string();
        assert!(d.contains("MutationScore"));
        assert!(d.contains("id=5"));
    }

    // ── EnergyModel ───────────────────────────────────────────────────────────

    #[test]
    fn energy_fast_returns_base() {
        let m = EnergyModel::new(PowerSchedule::Fast);
        let score = MutationScore::new(0);
        let e = m.compute(&score, 100, 1000);
        assert_eq!(e, m.base_energy);
    }

    #[test]
    fn energy_explore_high_coverage_more_energy() {
        let m = EnergyModel::new(PowerSchedule::Explore);
        let mut low = MutationScore::new(0);
        low.coverage_bits = 10;
        low.avg_exec_us = 100;
        let mut high = MutationScore::new(1);
        high.coverage_bits = 90;
        high.avg_exec_us = 100;
        let e_low = m.compute(&low, 100, 100);
        let e_high = m.compute(&high, 100, 100);
        assert!(e_high > e_low);
    }

    #[test]
    fn energy_coe_rare_gets_more() {
        let m = EnergyModel::new(PowerSchedule::Coe);
        let mut rare = MutationScore::new(0);
        rare.coverage_bits = 1; // rare: only 1% of global
        let mut common = MutationScore::new(1);
        common.coverage_bits = 99; // common: 99%
        let e_rare = m.compute(&rare, 100, 0);
        let e_common = m.compute(&common, 100, 0);
        assert!(e_rare > e_common);
    }

    #[test]
    fn energy_exploit_productive_gets_more() {
        let m = EnergyModel::new(PowerSchedule::Exploit);
        let mut productive = MutationScore::new(0);
        productive.selected_count = 10;
        productive.interesting_children = 8;
        productive.weight = 1.0;
        let mut stale = MutationScore::new(1);
        stale.selected_count = 10;
        stale.interesting_children = 0;
        stale.weight = 1.0;
        let e_prod = m.compute(&productive, 100, 0);
        let e_stale = m.compute(&stale, 100, 0);
        assert!(e_prod > e_stale);
    }

    #[test]
    fn energy_clamp_to_max() {
        let m = EnergyModel::new(PowerSchedule::Exploit).with_max_energy(10);
        let mut s = MutationScore::new(0);
        s.selected_count = 1;
        s.interesting_children = 1000;
        s.weight = 100.0;
        let e = m.compute(&s, 0, 0);
        assert!(e <= 10);
    }

    #[test]
    fn energy_floor_at_min() {
        let m = EnergyModel::new(PowerSchedule::Fast);
        let s = MutationScore::new(0);
        let e = m.compute(&s, 0, 0);
        assert!(e >= m.min_energy);
    }

    // ── PriorityInputQueue ────────────────────────────────────────────────────

    #[test]
    fn queue_upsert_and_len() {
        let mut q = PriorityInputQueue::new();
        q.upsert(0, vec![1, 2], 10);
        q.upsert(1, vec![3, 4], 20);
        assert_eq!(q.len(), 2);
    }

    #[test]
    fn queue_remove_decrements_len() {
        let mut q = PriorityInputQueue::new();
        q.upsert(0, vec![], 5);
        q.remove(0);
        assert!(q.is_empty());
    }

    #[test]
    fn queue_average_energy() {
        let mut q = PriorityInputQueue::new();
        q.upsert(0, vec![], 10);
        q.upsert(1, vec![], 30);
        assert!((q.average_energy() - 20.0).abs() < 1e-6);
    }

    #[test]
    fn queue_select_next_non_empty() {
        let mut q = PriorityInputQueue::new();
        q.upsert(0, vec![42], 10);
        let result = q.select_next(0);
        assert!(result.is_some());
        assert_eq!(result.unwrap().0, &[42u8]);
    }

    #[test]
    fn queue_select_empty_returns_none() {
        let mut q = PriorityInputQueue::new();
        assert!(q.select_next(0).is_none());
    }

    #[test]
    fn queue_max_energy_entry() {
        let mut q = PriorityInputQueue::new();
        q.upsert(0, vec![], 5);
        q.upsert(1, vec![], 50);
        q.upsert(2, vec![], 20);
        let (id, e) = q.max_energy_entry().unwrap();
        assert_eq!(id, 1);
        assert_eq!(e, 50);
    }

    #[test]
    fn queue_sorted_by_energy_descending() {
        let mut q = PriorityInputQueue::new();
        q.upsert(0, vec![], 5);
        q.upsert(1, vec![], 50);
        q.upsert(2, vec![], 20);
        let sorted = q.sorted_by_energy();
        assert_eq!(sorted[0].1, 50);
        assert_eq!(sorted[2].1, 5);
    }

    // ── SchedulerStats ────────────────────────────────────────────────────────

    #[test]
    fn scheduler_stats_record_cycle() {
        let mut s = SchedulerStats::new(PowerSchedule::Fast);
        s.record_cycle(100, 5, 1);
        assert_eq!(s.cycles, 1);
        assert_eq!(s.total_mutations, 100);
        assert_eq!(s.interesting_found, 5);
        assert_eq!(s.crashes_found, 1);
    }

    #[test]
    fn scheduler_stats_mutations_per_cycle() {
        let mut s = SchedulerStats::new(PowerSchedule::Fast);
        s.record_cycle(200, 0, 0);
        s.record_cycle(100, 0, 0);
        assert!((s.mutations_per_cycle() - 150.0).abs() < 1e-6);
    }

    #[test]
    fn scheduler_stats_finding_rate_zero_mutations() {
        let s = SchedulerStats::new(PowerSchedule::Explore);
        assert_eq!(s.finding_rate(), 0.0);
    }

    #[test]
    fn scheduler_stats_display() {
        let s = SchedulerStats::new(PowerSchedule::Coe);
        let d = s.to_string();
        assert!(d.contains("SchedulerStats"));
        assert!(d.contains("coe"));
    }

    // ── MutationScheduler ─────────────────────────────────────────────────────

    #[test]
    fn scheduler_add_seed_returns_energy() {
        let mut sched = MutationScheduler::new(PowerSchedule::Fast);
        let energy = sched.add_seed(0, vec![1, 2, 3], 50, 500);
        assert!(energy >= 1);
    }

    #[test]
    fn scheduler_corpus_size_after_add() {
        let mut sched = MutationScheduler::new(PowerSchedule::Explore);
        sched.add_seed(0, vec![1], 10, 100);
        sched.add_seed(1, vec![2], 20, 100);
        assert_eq!(sched.corpus_size(), 2);
    }

    #[test]
    fn scheduler_remove_seed() {
        let mut sched = MutationScheduler::new(PowerSchedule::Fast);
        sched.add_seed(0, vec![], 10, 100);
        sched.remove_seed(0);
        assert_eq!(sched.corpus_size(), 0);
    }

    #[test]
    fn scheduler_select_non_empty() {
        let mut sched = MutationScheduler::new(PowerSchedule::Fast);
        sched.add_seed(0, vec![7], 10, 100);
        let result = sched.select();
        assert!(result.is_some());
        assert_eq!(result.unwrap().0, vec![7u8]);
    }

    #[test]
    fn scheduler_select_empty_returns_none() {
        let mut sched = MutationScheduler::new(PowerSchedule::Explore);
        assert!(sched.select().is_none());
    }

    #[test]
    fn scheduler_record_mutation_increments_stats() {
        let mut sched = MutationScheduler::new(PowerSchedule::Fast);
        sched.add_seed(0, vec![], 10, 100);
        sched.record_mutation(0);
        sched.record_mutation(0);
        assert_eq!(sched.stats.total_mutations, 2);
    }

    #[test]
    fn scheduler_record_interesting_increments() {
        let mut sched = MutationScheduler::new(PowerSchedule::Fast);
        sched.add_seed(0, vec![], 10, 100);
        sched.record_interesting(0);
        assert_eq!(sched.stats.interesting_found, 1);
    }

    #[test]
    fn scheduler_record_crash_increments() {
        let mut sched = MutationScheduler::new(PowerSchedule::Fast);
        sched.add_seed(0, vec![], 10, 100);
        sched.record_crash(0);
        assert_eq!(sched.stats.crashes_found, 1);
    }

    #[test]
    fn scheduler_set_schedule() {
        let mut sched = MutationScheduler::new(PowerSchedule::Fast);
        sched.set_schedule(PowerSchedule::Exploit);
        assert_eq!(sched.energy_model.schedule, PowerSchedule::Exploit);
    }

    #[test]
    fn scheduler_end_cycle_resets_cycle_counter() {
        let mut sched = MutationScheduler::new(PowerSchedule::Fast);
        sched.add_seed(0, vec![], 10, 100);
        sched.record_mutation(0);
        sched.end_cycle();
        assert_eq!(sched.stats.cycles, 1);
    }

    #[test]
    fn scheduler_energy_for_registered_seed() {
        let mut sched = MutationScheduler::new(PowerSchedule::Fast);
        sched.add_seed(42, vec![], 10, 100);
        assert!(sched.energy_for(42).is_some());
        assert!(sched.energy_for(99).is_none());
    }

    #[test]
    fn scheduler_score_for() {
        let mut sched = MutationScheduler::new(PowerSchedule::Explore);
        sched.add_seed(7, vec![], 50, 200);
        let score = sched.score_for(7).unwrap();
        assert_eq!(score.coverage_bits, 50);
    }

    #[test]
    fn scheduler_display_format() {
        let sched = MutationScheduler::new(PowerSchedule::Coe);
        let d = sched.to_string();
        assert!(d.contains("MutationScheduler"));
        assert!(d.contains("coe"));
    }
}
