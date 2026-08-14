//! `protocol_state_fuzzer.rs` — Stateful protocol state-machine fuzzer.
//!
//! Models a protocol as a set of [`ProtocolState`]s connected by
//! [`StateTransition`]s, generates valid prefix sequences up to a target
//! state, then fuzzes the next message on each transition.  Tracks which
//! states were reached ([`StateReach`]) and records generated sequences
//! ([`FuzzSequence`]).

use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;
use std::time::SystemTime;

use rustre_fuzz_afl::XorShiftRng;
use rustre_fuzz_afl::RngCore;

// ---------------------------------------------------------------------------
// ProtocolState
// ---------------------------------------------------------------------------

/// A named node in the protocol state machine.
#[derive(Debug, Clone)]
pub struct ProtocolState {
    /// Unique state identifier.
    pub id: String,
    /// Human-readable description.
    pub description: String,
    /// Transitions out of this state.
    pub transitions: Vec<String>,
    /// Whether this is a terminal (accepting) state.
    pub is_terminal: bool,
    /// Whether this state has been reached during fuzzing.
    pub reached: bool,
}

impl ProtocolState {
    /// Create a new non-terminal state with no transitions.
    #[must_use]
    pub fn new(id: impl Into<String>, description: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            description: description.into(),
            transitions: Vec::new(),
            is_terminal: false,
            reached: false,
        }
    }

    /// Mark this state as terminal.
    #[must_use]
    pub fn terminal(mut self) -> Self {
        self.is_terminal = true;
        self
    }

    /// Add a transition to `target_id`.
    pub fn add_transition(&mut self, target_id: impl Into<String>) {
        self.transitions.push(target_id.into());
    }
}

// ---------------------------------------------------------------------------
// StateTransition
// ---------------------------------------------------------------------------

/// A directed edge between two protocol states.
#[derive(Debug, Clone)]
pub struct StateTransition {
    /// Source state ID.
    pub from: String,
    /// Target state ID.
    pub to: String,
    /// Name/label for this transition (e.g. `"CONNECT"`, `"HELLO"`).
    pub label: String,
    /// Raw bytes to send when taking this transition.
    pub message_template: Vec<u8>,
    /// Bytes the target is expected to send back (empty = no check).
    pub expected_response: Vec<u8>,
    /// Whether this transition has been exercised.
    pub covered: bool,
    /// Number of times this transition has been taken.
    pub take_count: u64,
}

impl StateTransition {
    /// Create a transition with a message template.
    #[must_use]
    pub fn new(
        from: impl Into<String>,
        to: impl Into<String>,
        label: impl Into<String>,
        message_template: Vec<u8>,
    ) -> Self {
        Self {
            from: from.into(),
            to: to.into(),
            label: label.into(),
            message_template,
            expected_response: Vec::new(),
            covered: false,
            take_count: 0,
        }
    }

    /// Attach an expected response pattern.
    #[must_use]
    pub fn with_response(mut self, resp: Vec<u8>) -> Self {
        self.expected_response = resp;
        self
    }

    /// Mutate the message template bytes using `rng`.
    #[must_use]
    pub fn mutated_message(&self, rng: &mut dyn RngCore) -> Vec<u8> {
        let mut msg = self.message_template.clone();
        if msg.is_empty() {
            return msg;
        }
        let strategy = rng.next_usize(4);
        match strategy {
            0 => {
                // Bit flip
                let idx = rng.next_usize(msg.len());
                let bit = rng.next_usize(8);
                msg[idx] ^= 1 << bit;
            }
            1 => {
                // Byte substitute with interesting value
                let idx = rng.next_usize(msg.len());
                let interesting = [0x00u8, 0x01, 0x7f, 0x80, 0xfe, 0xff];
                msg[idx] = interesting[rng.next_usize(interesting.len())];
            }
            2 => {
                // Append random bytes
                let extra = rng.next_usize(16) + 1;
                for _ in 0..extra {
                    msg.push((rng.next_u32() & 0xff) as u8);
                }
            }
            _ => {
                // Truncate
                if msg.len() > 1 {
                    let new_len = 1 + rng.next_usize(msg.len());
                    msg.truncate(new_len);
                }
            }
        }
        msg
    }
}

// ---------------------------------------------------------------------------
// StateReach — which states were reached and how
// ---------------------------------------------------------------------------

/// Tracks which states and transitions have been reached during fuzzing.
#[derive(Debug, Default, Clone)]
pub struct StateReach {
    /// States that have been entered at least once.
    pub visited_states: HashSet<String>,
    /// Transitions (from→to) that have been taken at least once.
    pub covered_transitions: HashSet<(String, String)>,
    /// Number of times each state was entered.
    pub state_entry_count: HashMap<String, u64>,
    /// Timestamp of first reach per state.
    pub first_reached: HashMap<String, SystemTime>,
}

impl StateReach {
    /// Create a new empty reach tracker.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record entering `state`.
    pub fn record_state(&mut self, state: &str) {
        self.visited_states.insert(state.to_owned());
        *self.state_entry_count.entry(state.to_owned()).or_insert(0) += 1;
        self.first_reached.entry(state.to_owned()).or_insert_with(SystemTime::now);
    }

    /// Record taking a transition.
    pub fn record_transition(&mut self, from: &str, to: &str) {
        self.covered_transitions.insert((from.to_owned(), to.to_owned()));
    }

    /// Coverage percentage of reachable states.
    #[must_use]
    pub fn state_coverage_pct(&self, total_states: usize) -> f64 {
        if total_states == 0 { return 100.0; }
        self.visited_states.len() as f64 / total_states as f64 * 100.0
    }

    /// Coverage percentage of transitions.
    #[must_use]
    pub fn transition_coverage_pct(&self, total_transitions: usize) -> f64 {
        if total_transitions == 0 { return 100.0; }
        self.covered_transitions.len() as f64 / total_transitions as f64 * 100.0
    }

    /// True if `state_id` has been entered.
    #[must_use]
    pub fn has_reached(&self, state_id: &str) -> bool {
        self.visited_states.contains(state_id)
    }

    /// Most-visited state.
    #[must_use]
    pub fn most_visited(&self) -> Option<&str> {
        self.state_entry_count
            .iter()
            .max_by_key(|&(_, &v)| v)
            .map(|(k, _)| k.as_str())
    }
}

// ---------------------------------------------------------------------------
// FuzzSequence — a generated sequence of (transition, payload) pairs
// ---------------------------------------------------------------------------

/// One generated fuzz sequence: a series of messages sent along a path
/// through the state machine.
#[derive(Debug, Clone)]
pub struct FuzzSequence {
    /// States visited in order (initial → final).
    pub path: Vec<String>,
    /// Mutated messages sent at each step.
    pub messages: Vec<Vec<u8>>,
    /// Labels of transitions taken.
    pub labels: Vec<String>,
    /// Whether a protocol violation was detected.
    pub violation_detected: bool,
    /// Iteration index when this sequence was generated.
    pub iteration: u64,
    /// Timestamp of generation.
    pub generated_at: SystemTime,
}

impl FuzzSequence {
    /// Create an empty sequence.
    #[must_use]
    pub fn new(iteration: u64) -> Self {
        Self {
            path: Vec::new(),
            messages: Vec::new(),
            labels: Vec::new(),
            violation_detected: false,
            iteration,
            generated_at: SystemTime::now(),
        }
    }

    /// Append a step to this sequence.
    pub fn push_step(&mut self, from: impl Into<String>, to: impl Into<String>, label: impl Into<String>, msg: Vec<u8>) {
        if self.path.is_empty() {
            self.path.push(from.into());
        }
        self.path.push(to.into());
        self.labels.push(label.into());
        self.messages.push(msg);
    }

    /// Total bytes sent in this sequence.
    #[must_use]
    pub fn total_bytes(&self) -> usize {
        self.messages.iter().map(Vec::len).sum()
    }

    /// Number of steps (transitions) in this sequence.
    #[must_use]
    pub fn depth(&self) -> usize {
        self.labels.len()
    }
}

impl fmt::Display for FuzzSequence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "FuzzSequence(iter={}, steps={}, bytes={})", self.iteration, self.depth(), self.total_bytes())
    }
}

// ---------------------------------------------------------------------------
// ProtocolViolation
// ---------------------------------------------------------------------------

/// A detected protocol violation.
#[derive(Debug, Clone)]
pub struct ProtocolViolation {
    pub kind: ViolationKind,
    pub state_id: String,
    pub transition_label: String,
    pub message: Vec<u8>,
    pub description: String,
    pub detected_at: SystemTime,
}

/// Kind of protocol violation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ViolationKind {
    /// Server disconnected unexpectedly.
    UnexpectedDisconnect,
    /// Server sent a response that doesn't match the expected pattern.
    BadResponse,
    /// Transition led to an undefined state.
    UndefinedState,
    /// Length field mismatch.
    LengthMismatch,
    /// Timeout waiting for response.
    Timeout,
    /// Custom violation type.
    Custom(String),
}

impl fmt::Display for ViolationKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnexpectedDisconnect => write!(f, "UnexpectedDisconnect"),
            Self::BadResponse => write!(f, "BadResponse"),
            Self::UndefinedState => write!(f, "UndefinedState"),
            Self::LengthMismatch => write!(f, "LengthMismatch"),
            Self::Timeout => write!(f, "Timeout"),
            Self::Custom(s) => write!(f, "Custom({s})"),
        }
    }
}

// ---------------------------------------------------------------------------
// StateFuzzer
// ---------------------------------------------------------------------------

/// Stateful protocol fuzzer.
///
/// Maintains the state graph and drives fuzzing by:
/// 1. BFS-walking to a target depth.
/// 2. Picking a random transition and mutating its message.
/// 3. Recording violations and coverage.
pub struct StateFuzzer {
    /// All states keyed by ID.
    pub states: HashMap<String, ProtocolState>,
    /// All transitions keyed by `"{from}→{to}"`.
    pub transitions: HashMap<String, StateTransition>,
    /// Initial state ID.
    pub initial_state: String,
    /// Reach tracker.
    pub reach: StateReach,
    /// Violations detected.
    pub violations: Vec<ProtocolViolation>,
    /// Generated sequences.
    pub sequences: Vec<FuzzSequence>,
    /// Internal PRNG.
    rng: XorShiftRng,
    /// Total fuzzing iterations.
    pub iterations: u64,
    /// Maximum depth to fuzz per iteration.
    pub max_depth: usize,
}

impl StateFuzzer {
    /// Create a fuzzer from an initial state ID, states map, and transitions list.
    #[must_use]
    pub fn new(
        initial_state: impl Into<String>,
        states: HashMap<String, ProtocolState>,
        transitions: Vec<StateTransition>,
    ) -> Self {
        let initial = initial_state.into();
        let mut t_map = HashMap::new();
        for t in transitions {
            let key = format!("{}→{}", t.from, t.to);
            t_map.insert(key, t);
        }
        Self {
            states,
            transitions: t_map,
            initial_state: initial,
            reach: StateReach::new(),
            violations: Vec::new(),
            sequences: Vec::new(),
            rng: XorShiftRng::default(),
            iterations: 0,
            max_depth: 16,
        }
    }

    /// Find all transitions from `state_id`.
    #[must_use]
    pub fn outgoing(&self, state_id: &str) -> Vec<&StateTransition> {
        self.transitions
            .values()
            .filter(|t| t.from == state_id)
            .collect()
    }

    /// BFS to find a path from `start` to `target` (returns transition labels).
    #[must_use]
    pub fn find_path(&self, start: &str, target: &str) -> Option<Vec<String>> {
        if start == target {
            return Some(Vec::new());
        }
        let mut queue: VecDeque<(String, Vec<String>)> = VecDeque::new();
        let mut visited: HashSet<String> = HashSet::new();
        queue.push_back((start.to_owned(), Vec::new()));
        visited.insert(start.to_owned());
        while let Some((current, path)) = queue.pop_front() {
            for t in self.outgoing(&current) {
                if visited.contains(&t.to) {
                    continue;
                }
                let mut new_path = path.clone();
                new_path.push(format!("{}→{}", t.from, t.to));
                if t.to == target {
                    return Some(new_path);
                }
                visited.insert(t.to.clone());
                queue.push_back((t.to.clone(), new_path));
            }
        }
        None
    }

    /// Generate one fuzz sequence starting at `initial_state`.
    ///
    /// Walks `max_depth` transitions, mutating the last message.
    /// Returns the sequence and any violation detected.
    pub fn generate_sequence(&mut self) -> FuzzSequence {
        self.iterations += 1;
        let mut seq = FuzzSequence::new(self.iterations);
        let mut current = self.initial_state.clone();

        self.reach.record_state(&current);

        for step in 0..self.max_depth {
            let outgoing: Vec<(String, String, Vec<u8>)> = {
                let outs = self.outgoing(&current);
                if outs.is_empty() { break; }
                outs.iter().map(|t| (t.from.clone(), t.to.clone(), t.message_template.clone())).collect()
            };

            let idx = self.rng.next_usize(outgoing.len());
            let (from, to, template) = &outgoing[idx];
            let key = format!("{from}→{to}");

            // Mutate on last step, use template otherwise
            let msg = if step == self.max_depth.saturating_sub(1) {
                // Build a temporary StateTransition to use mutated_message
                let tmp = StateTransition::new(from.clone(), to.clone(), "tmp", template.clone());
                tmp.mutated_message(&mut self.rng)
            } else {
                template.clone()
            };

            seq.push_step(from.clone(), to.clone(), key.clone(), msg);

            // Update coverage
            if let Some(t) = self.transitions.get_mut(&key) {
                t.covered = true;
                t.take_count += 1;
            }
            self.reach.record_state(to);
            self.reach.record_transition(from, to);

            // Detect undefined state
            if !self.states.contains_key(to.as_str()) {
                let v = ProtocolViolation {
                    kind: ViolationKind::UndefinedState,
                    state_id: to.clone(),
                    transition_label: key.clone(),
                    message: seq.messages.last().cloned().unwrap_or_default(),
                    description: format!("state '{to}' not in state graph"),
                    detected_at: SystemTime::now(),
                };
                self.violations.push(v);
                seq.violation_detected = true;
                break;
            }

            current = to.clone();

            if self.states.get(&current).is_some_and(|s| s.is_terminal) {
                break;
            }
        }

        seq
    }

    /// Run `count` fuzzing iterations, storing each sequence.
    pub fn run(&mut self, count: u64) {
        for _ in 0..count {
            let seq = self.generate_sequence();
            self.sequences.push(seq);
        }
    }

    /// State coverage percentage.
    #[must_use]
    pub fn state_coverage_pct(&self) -> f64 {
        self.reach.state_coverage_pct(self.states.len())
    }

    /// Transition coverage percentage.
    #[must_use]
    pub fn transition_coverage_pct(&self) -> f64 {
        self.reach.transition_coverage_pct(self.transitions.len())
    }

    /// Total violations detected.
    #[must_use]
    pub fn violation_count(&self) -> usize {
        self.violations.len()
    }

    /// Validate the state graph: every transition target must exist.
    #[must_use]
    pub fn validate(&self) -> Vec<String> {
        let mut errors = Vec::new();
        if !self.states.contains_key(&self.initial_state) {
            errors.push(format!("initial state '{}' not in graph", self.initial_state));
        }
        for t in self.transitions.values() {
            if !self.states.contains_key(&t.from) {
                errors.push(format!("transition from unknown state '{}'", t.from));
            }
            if !self.states.contains_key(&t.to) {
                errors.push(format!("transition to unknown state '{}'", t.to));
            }
        }
        errors
    }

    /// Return uncovered transitions.
    #[must_use]
    pub fn uncovered_transitions(&self) -> Vec<&StateTransition> {
        self.transitions.values().filter(|t| !t.covered).collect()
    }

    /// Statistics snapshot.
    #[must_use]
    pub fn stats(&self) -> FuzzerStats {
        FuzzerStats {
            iterations: self.iterations,
            states_reached: self.reach.visited_states.len(),
            total_states: self.states.len(),
            transitions_covered: self.reach.covered_transitions.len(),
            total_transitions: self.transitions.len(),
            violations: self.violations.len(),
            sequences_stored: self.sequences.len(),
        }
    }
}

/// Snapshot of fuzzer statistics.
#[derive(Debug, Clone)]
pub struct FuzzerStats {
    pub iterations: u64,
    pub states_reached: usize,
    pub total_states: usize,
    pub transitions_covered: usize,
    pub total_transitions: usize,
    pub violations: usize,
    pub sequences_stored: usize,
}

impl fmt::Display for FuzzerStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "iters={} states={}/{} trans={}/{} violations={}",
            self.iterations,
            self.states_reached,
            self.total_states,
            self.transitions_covered,
            self.total_transitions,
            self.violations,
        )
    }
}

// ---------------------------------------------------------------------------
// Builder
// ---------------------------------------------------------------------------

/// Fluent builder for [`StateFuzzer`].
#[derive(Debug, Default)]
pub struct StateFuzzerBuilder {
    initial: String,
    states: HashMap<String, ProtocolState>,
    transitions: Vec<StateTransition>,
}

impl StateFuzzerBuilder {
    /// Start with an initial state.
    #[must_use]
    pub fn new(initial: impl Into<String>) -> Self {
        let name = initial.into();
        let mut b = Self { initial: name.clone(), ..Self::default() };
        b.states.insert(name.clone(), ProtocolState::new(name, "initial"));
        b
    }

    /// Add a state.
    #[must_use]
    pub fn add_state(mut self, state: ProtocolState) -> Self {
        self.states.insert(state.id.clone(), state);
        self
    }

    /// Add a transition with a message template.
    #[must_use]
    pub fn add_transition(mut self, from: impl Into<String>, to: impl Into<String>, label: impl Into<String>, template: Vec<u8>) -> Self {
        let f: String = from.into();
        let t: String = to.into();
        self.states.entry(t.clone()).or_insert_with(|| ProtocolState::new(t.clone(), t.clone()));
        self.transitions.push(StateTransition::new(f, t, label, template));
        self
    }

    /// Build the fuzzer.
    #[must_use]
    pub fn build(self) -> StateFuzzer {
        StateFuzzer::new(self.initial, self.states, self.transitions)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn simple_fuzzer() -> StateFuzzer {
        StateFuzzerBuilder::new("init")
            .add_state(ProtocolState::new("auth", "Authenticated"))
            .add_state(ProtocolState::new("data", "Data exchange").terminal())
            .add_transition("init", "auth", "HELLO", b"HELLO\r\n".to_vec())
            .add_transition("auth", "data", "DATA", b"DATA\r\n".to_vec())
            .build()
    }

    #[test]
    fn validate_clean_graph() {
        let fuzzer = simple_fuzzer();
        assert!(fuzzer.validate().is_empty());
    }

    #[test]
    fn generate_sequence_has_correct_depth() {
        let mut fuzzer = simple_fuzzer();
        let seq = fuzzer.generate_sequence();
        assert!(seq.depth() > 0 && seq.depth() <= fuzzer.max_depth);
    }

    #[test]
    fn reach_records_initial_state() {
        let mut fuzzer = simple_fuzzer();
        fuzzer.generate_sequence();
        assert!(fuzzer.reach.has_reached("init"));
    }

    #[test]
    fn coverage_increases_after_run() {
        let mut fuzzer = simple_fuzzer();
        fuzzer.run(20);
        assert!(fuzzer.state_coverage_pct() > 0.0);
        assert!(fuzzer.transition_coverage_pct() > 0.0);
    }

    #[test]
    fn iterations_tracked() {
        let mut fuzzer = simple_fuzzer();
        fuzzer.run(10);
        assert_eq!(fuzzer.iterations, 10);
    }

    #[test]
    fn find_path_known_route() {
        let fuzzer = simple_fuzzer();
        let path = fuzzer.find_path("init", "data");
        assert!(path.is_some());
        assert_eq!(path.unwrap().len(), 2);
    }

    #[test]
    fn find_path_unreachable_returns_none() {
        let fuzzer = simple_fuzzer();
        let path = fuzzer.find_path("data", "init");
        assert!(path.is_none());
    }

    #[test]
    fn find_path_same_start_end_returns_empty() {
        let fuzzer = simple_fuzzer();
        let path = fuzzer.find_path("init", "init");
        assert_eq!(path, Some(Vec::new()));
    }

    #[test]
    fn state_reach_coverage_pct() {
        let mut reach = StateReach::new();
        reach.record_state("a");
        reach.record_state("b");
        let pct = reach.state_coverage_pct(4);
        assert!((pct - 50.0).abs() < 0.1);
    }

    #[test]
    fn state_reach_most_visited() {
        let mut reach = StateReach::new();
        reach.record_state("a");
        reach.record_state("a");
        reach.record_state("b");
        assert_eq!(reach.most_visited(), Some("a"));
    }

    #[test]
    fn fuzz_sequence_total_bytes() {
        let mut seq = FuzzSequence::new(1);
        seq.push_step("a", "b", "AB", vec![0u8; 10]);
        seq.push_step("b", "c", "BC", vec![0u8; 5]);
        assert_eq!(seq.total_bytes(), 15);
        assert_eq!(seq.depth(), 2);
    }

    #[test]
    fn state_transition_mutated_message_changes() {
        let t = StateTransition::new("a", "b", "lbl", b"HELLO".to_vec());
        let mut rng = XorShiftRng::default();
        let mut changed = false;
        for _ in 0..50 {
            if t.mutated_message(&mut rng) != b"HELLO".to_vec() {
                changed = true;
                break;
            }
        }
        assert!(changed, "mutation should change the message at least once");
    }

    #[test]
    fn violation_kind_display() {
        assert_eq!(ViolationKind::Timeout.to_string(), "Timeout");
        assert_eq!(ViolationKind::Custom("X".into()).to_string(), "Custom(X)");
    }

    #[test]
    fn fuzzer_stats_snapshot() {
        let mut fuzzer = simple_fuzzer();
        fuzzer.run(5);
        let stats = fuzzer.stats();
        assert_eq!(stats.iterations, 5);
        assert!(stats.states_reached <= stats.total_states);
    }

    #[test]
    fn transition_take_count_increments() {
        let mut fuzzer = simple_fuzzer();
        fuzzer.run(30);
        let total_takes: u64 = fuzzer.transitions.values().map(|t| t.take_count).sum();
        assert!(total_takes > 0);
    }
}
