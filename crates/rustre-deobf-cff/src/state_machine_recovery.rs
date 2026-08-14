//! State-machine recovery for CFF-deobfuscated code.
//!
//! After the CFF dispatcher loop has been identified, this module re-constructs
//! the underlying state machine: its states, transitions, and structured
//! control flow, ready for further decompilation passes.

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::fmt;
use std::fmt::Write as FmtWrite;

// ─────────────────────────────────────────────────────────────────────────────
// StateVariable — the dispatcher variable that drives the state machine
// ─────────────────────────────────────────────────────────────────────────────

/// Represents the dispatcher (state) variable inside a CFF-flattened function.
///
/// In OLLVM-style CFF the state variable is a single integer local.  The
/// dispatcher loop reads it, switches on it, and jumps to the matching basic
/// block; the block then writes the next-state value back.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct StateVariable {
    /// Name or symbolic register the variable lives in.
    pub name: String,
    /// Byte offset in the frame (if stack-allocated).
    pub frame_offset: Option<i32>,
    /// Bit width (typically 32 or 64).
    pub width_bits: u8,
    /// The initial (entry) state value.
    pub initial_value: u64,
}

impl StateVariable {
    /// Create a new state variable with the given name and initial value.
    #[must_use]
    pub fn new(name: impl Into<String>, initial_value: u64) -> Self {
        Self {
            name: name.into(),
            frame_offset: None,
            width_bits: 32,
            initial_value,
        }
    }

    #[must_use]
    pub fn with_frame_offset(mut self, off: i32) -> Self {
        self.frame_offset = Some(off);
        self
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// StateMachine — the recovered state automaton
// ─────────────────────────────────────────────────────────────────────────────

/// A node in the recovered state machine.
#[derive(Debug, Clone)]
pub struct State {
    /// The numeric state identifier (maps to the dispatch value).
    pub id: u64,
    /// Human-friendly label (may be auto-generated).
    pub label: String,
    /// Whether this is the entry state.
    pub is_entry: bool,
    /// Whether this is a terminal state (no outgoing transitions or returns).
    pub is_terminal: bool,
    /// The basic-block address in the original binary that corresponds to this
    /// state.
    pub bb_address: Option<u64>,
    /// Estimated size of the original basic block in bytes.
    pub bb_size: usize,
}

impl State {
    #[must_use]
    pub fn new(id: u64) -> Self {
        Self {
            id,
            label: format!("state_{id:#x}"),
            is_entry: false,
            is_terminal: false,
            bb_address: None,
            bb_size: 0,
        }
    }
}

/// An edge in the state machine.
#[derive(Debug, Clone)]
pub struct Transition {
    pub from: u64,
    pub to: u64,
    pub condition: TransitionCondition,
    /// The value written to the state variable to trigger this transition.
    pub next_state_value: u64,
}

/// The condition under which a transition is taken.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransitionCondition {
    /// Always taken (unconditional).
    Always,
    /// Taken when the given flag / expression is true.
    Conditional(String),
    /// Taken when the switch value matches.
    SwitchCase(u64),
}

/// The complete recovered state machine.
#[derive(Debug, Default)]
pub struct StateMachine {
    /// All recovered states, keyed by state id.
    pub states: BTreeMap<u64, State>,
    /// All transitions.
    pub transitions: Vec<Transition>,
    /// The dispatcher variable for this machine.
    pub state_var: Option<StateVariable>,
    /// Entry state id.
    pub entry_state: Option<u64>,
}

impl StateMachine {
    /// Create an empty state machine.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a state, returning it.
    pub fn add_state(&mut self, state: State) -> u64 {
        let id = state.id;
        self.states.insert(id, state);
        id
    }

    /// Add a transition.
    pub fn add_transition(&mut self, t: Transition) {
        self.transitions.push(t);
    }

    /// Return all successors of a state.
    #[must_use]
    pub fn successors(&self, state_id: u64) -> Vec<u64> {
        self.transitions
            .iter()
            .filter(|t| t.from == state_id)
            .map(|t| t.to)
            .collect()
    }

    /// Return all predecessors of a state.
    #[must_use]
    pub fn predecessors(&self, state_id: u64) -> Vec<u64> {
        self.transitions
            .iter()
            .filter(|t| t.to == state_id)
            .map(|t| t.from)
            .collect()
    }

    /// Return the number of states.
    #[must_use]
    pub fn state_count(&self) -> usize {
        self.states.len()
    }

    /// Return the number of transitions.
    #[must_use]
    pub fn transition_count(&self) -> usize {
        self.transitions.len()
    }

    /// Export the state machine as a Graphviz `digraph` string.
    ///
    /// Emits one node per state (with entry/terminal styling) and one edge per
    /// transition (labelled by its [`TransitionCondition`]). Uses
    /// [`std::fmt::Write`] under the hood so allocations are kept to a single
    /// growable [`String`].
    #[must_use]
    pub fn to_dot(&self) -> String {
        let mut out = String::new();
        // `write!`/`writeln!` on `String` requires `std::fmt::Write` in scope.
        writeln!(out, "digraph state_machine {{").unwrap();
        writeln!(out, "  rankdir=TB;").unwrap();
        writeln!(out, "  node [shape=rectangle];").unwrap();
        for (&id, state) in &self.states {
            let style = if state.is_entry {
                " style=filled fillcolor=lightgreen"
            } else if state.is_terminal {
                " style=filled fillcolor=lightcoral"
            } else {
                ""
            };
            writeln!(
                out,
                "  s{id} [label=\"{label} ({id:#x})\"{style}];",
                id = id,
                label = state.label,
                style = style,
            )
            .unwrap();
        }
        for t in &self.transitions {
            match &t.condition {
                TransitionCondition::Always => {
                    writeln!(out, "  s{} -> s{};", t.from, t.to).unwrap();
                }
                TransitionCondition::Conditional(c) => {
                    writeln!(out, "  s{} -> s{} [label=\"{}\"];", t.from, t.to, c).unwrap();
                }
                TransitionCondition::SwitchCase(v) => {
                    writeln!(out, "  s{} -> s{} [label=\"case {}\"];", t.from, t.to, v)
                        .unwrap();
                }
            }
        }
        writeln!(out, "}}").unwrap();
        out
    }

    /// Verify that all transition endpoints refer to known states.
    #[must_use]
    pub fn validate(&self) -> Vec<String> {
        let mut errors = Vec::new();
        for t in &self.transitions {
            if !self.states.contains_key(&t.from) {
                errors.push(format!("transition from unknown state {:#x}", t.from));
            }
            if !self.states.contains_key(&t.to) {
                errors.push(format!("transition to unknown state {:#x}", t.to));
            }
        }
        errors

    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TransitionMap — compact adjacency map
// ─────────────────────────────────────────────────────────────────────────────

/// A compact map from state id to its outgoing transitions.
#[derive(Debug, Default)]
pub struct TransitionMap {
    inner: HashMap<u64, Vec<Transition>>,
}

impl TransitionMap {
    /// Build from a [`StateMachine`].
    pub fn from_machine(sm: &StateMachine) -> Self {
        let mut map = TransitionMap::default();
        for t in &sm.transitions {
            map.inner.entry(t.from).or_default().push(t.clone());
        }
        map
    }

    /// Get the outgoing transitions from a state.
    pub fn get(&self, state_id: u64) -> &[Transition] {
        self.inner
            .get(&state_id)
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }

    /// Return all source states.
    pub fn sources(&self) -> impl Iterator<Item = u64> + '_ {
        self.inner.keys().copied()
    }

    /// Total transition count.
    pub fn len(&self) -> usize {
        self.inner.values().map(|v| v.len()).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// StructuredState — a state annotated with high-level structure
// ─────────────────────────────────────────────────────────────────────────────

/// High-level structured annotation for a recovered state.
#[derive(Debug, Clone)]
pub struct StructuredState {
    pub state_id: u64,
    /// The inferred high-level construct.
    pub structure: HighLevelStructure,
    /// Depth in the dominator tree (0 = entry).
    pub dom_depth: usize,
}

/// A high-level control-flow construct inferred from the state graph.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HighLevelStructure {
    /// Sequential (no branching).
    Sequence,
    /// If-then construct.
    IfThen { condition: String },
    /// If-then-else construct.
    IfThenElse { condition: String },
    /// While loop.
    WhileLoop { condition: String },
    /// Return from function.
    Return,
    /// Unknown / not yet classified.
    Unknown,
}

impl fmt::Display for HighLevelStructure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sequence => write!(f, "seq"),
            Self::IfThen { condition } => write!(f, "if({condition})"),
            Self::IfThenElse { condition } => write!(f, "if-else({condition})"),
            Self::WhileLoop { condition } => write!(f, "while({condition})"),
            Self::Return => write!(f, "return"),
            Self::Unknown => write!(f, "?"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// StateElimination — reduce the state machine by merging simple chains
// ─────────────────────────────────────────────────────────────────────────────

/// Eliminates "pass-through" states: states with exactly one predecessor and
/// one successor, which can be merged into a sequence without changing
/// semantics.
#[derive(Debug, Default)]
pub struct StateElimination;

impl StateElimination {
    /// Compute which states are eliminatable (single in, single out).
    pub fn eliminatable_states(sm: &StateMachine) -> HashSet<u64> {
        let tmap = TransitionMap::from_machine(sm);
        let mut result = HashSet::new();
        for (&id, state) in &sm.states {
            if state.is_entry || state.is_terminal {
                continue;
            }
            let preds = sm.predecessors(id);
            let succs = sm.successors(id);
            if preds.len() == 1 && succs.len() == 1 {
                let succ = succs[0];
                // Avoid self-loops.
                if succ != id && preds[0] != id {
                    let _ = &tmap;
                    result.insert(id);
                }
            }
        }
        result
    }

    /// Apply elimination in-place.  Returns the number of states eliminated.
    pub fn apply(sm: &mut StateMachine) -> usize {
        let targets = Self::eliminatable_states(sm);
        let count = targets.len();
        for id in &targets {
            sm.states.remove(id);
            // Re-route transitions through the eliminated state.
            let succs: Vec<_> = sm
                .transitions
                .iter()
                .filter(|t| t.from == *id)
                .map(|t| t.to)
                .collect();
            let preds: Vec<_> = sm
                .transitions
                .iter()
                .filter(|t| t.to == *id)
                .map(|t| t.from)
                .collect();
            sm.transitions.retain(|t| t.from != *id && t.to != *id);
            for pred in &preds {
                for &succ in &succs {
                    sm.transitions.push(Transition {
                        from: *pred,
                        to: succ,
                        condition: TransitionCondition::Always,
                        next_state_value: succ,
                    });
                }
            }
        }
        count
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// StateGraphExport — serialise the graph
// ─────────────────────────────────────────────────────────────────────────────

/// Exports the state machine to various text formats.
pub struct StateGraphExport;

impl StateGraphExport {
    /// Generate a DOT representation of the state machine.
    pub fn to_dot(sm: &StateMachine) -> String {
        let mut out = String::from("digraph state_machine {\n");
        out += "  rankdir=TB;\n";
        out += "  node [shape=rectangle];\n";
        for (&id, state) in &sm.states {
            let color = if state.is_entry {
                " style=filled fillcolor=lightgreen"
            } else if state.is_terminal {
                " style=filled fillcolor=lightcoral"
            } else {
                ""
            };
            out += &format!(
                "  s{} [label=\"{} ({:#x})\"{}];\n",
                id, state.label, id, color
            );
        }
        for t in &sm.transitions {
            let label = match &t.condition {
                TransitionCondition::Always => String::new(),
                TransitionCondition::Conditional(c) => format!(" [label=\"{}\"]", c),
                TransitionCondition::SwitchCase(v) => format!(" [label=\"case {}\"]", v),
            };
            out += &format!("  s{} -> s{}{};\n", t.from, t.to, label);
        }
        out += "}\n";
        out
    }

    /// Generate a JSON representation.
    pub fn to_json(sm: &StateMachine) -> String {
        let states: Vec<_> = sm
            .states
            .values()
            .map(|s| {
                format!(
                    r#"{{"id":{},"label":"{}","entry":{},"terminal":{}}}"#,
                    s.id, s.label, s.is_entry, s.is_terminal
                )
            })
            .collect();
        let edges: Vec<_> = sm
            .transitions
            .iter()
            .map(|t| format!(r#"{{"from":{},"to":{}}}"#, t.from, t.to))
            .collect();
        format!(
            r#"{{"states":[{}],"transitions":[{}]}}"#,
            states.join(","),
            edges.join(",")
        )
    }

    /// Generate a simple Mermaid stateDiagram.
    pub fn to_mermaid(sm: &StateMachine) -> String {
        let mut out = String::from("stateDiagram-v2\n");
        if let Some(entry) = sm.entry_state {
            out += &format!("  [*] --> s{}\n", entry);
        }
        for t in &sm.transitions {
            out += &format!("  s{} --> s{}\n", t.from, t.to);
        }
        for (&id, state) in &sm.states {
            if state.is_terminal {
                out += &format!("  s{} --> [*]\n", id);
            }
        }
        out
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// StateMachineRecovery — orchestrator
// ─────────────────────────────────────────────────────────────────────────────

/// The main entry point for state-machine recovery from a CFF-flattened
/// function.
pub struct StateMachineRecovery {
    /// Minimum number of states to consider a function CFF-protected.
    pub min_states: usize,
    /// Whether to run state-elimination as a post-pass.
    pub eliminate_pass_throughs: bool,
}

impl Default for StateMachineRecovery {
    fn default() -> Self {
        StateMachineRecovery {
            min_states: 3,
            eliminate_pass_throughs: true,
        }
    }
}

impl StateMachineRecovery {
    pub fn new() -> Self {
        Self::default()
    }

    /// Recover a state machine from a list of `(state_value, successor_values)`
    /// pairs (simplified IR-level input).
    pub fn recover_from_pairs(
        &self,
        pairs: &[(u64, Vec<u64>)],
        entry: u64,
        state_var: StateVariable,
    ) -> StateMachine {
        let mut sm = StateMachine::new();
        sm.state_var = Some(state_var);
        sm.entry_state = Some(entry);

        for (from, succs) in pairs {
            if !sm.states.contains_key(from) {
                let mut s = State::new(*from);
                if *from == entry {
                    s.is_entry = true;
                }
                sm.add_state(s);
            }
            for &to in succs {
                if !sm.states.contains_key(&to) {
                    let s = State::new(to);
                    sm.add_state(s);
                }
                sm.add_transition(Transition {
                    from: *from,
                    to,
                    condition: if succs.len() == 1 {
                        TransitionCondition::Always
                    } else {
                        TransitionCondition::Conditional("?".into())
                    },
                    next_state_value: to,
                });
            }
        }

        // Mark terminal states.
        let mut all_ids: Vec<u64> = Vec::with_capacity(sm.states.len());
        all_ids.extend(sm.states.keys().copied());
        for id in all_ids {
            if sm.successors(id).is_empty() && let Some(s) = sm.states.get_mut(&id) {
                s.is_terminal = true;
            }
        }

        if self.eliminate_pass_throughs {
            StateElimination::apply(&mut sm);
        }

        sm
    }

    /// Annotate states with high-level structure based on successor count.
    pub fn annotate(&self, sm: &StateMachine) -> Vec<StructuredState> {
        let mut result = Vec::with_capacity(sm.states.len());
        for (&id, state) in &sm.states {
            let succs = sm.successors(id);
            let structure = if state.is_terminal {
                HighLevelStructure::Return
            } else {
                match succs.len() {
                    0 => HighLevelStructure::Return,
                    1 => HighLevelStructure::Sequence,
                    2 => HighLevelStructure::IfThenElse {
                        condition: "?".into(),
                    },
                    _ => HighLevelStructure::Unknown,
                }
            };
            result.push(StructuredState {
                state_id: id,
                structure,
                dom_depth: 0, // depth analysis not implemented here
            });
        }
        result
    }

    /// BFS reachability from the entry state.
    pub fn reachable_states(&self, sm: &StateMachine) -> HashSet<u64> {
        let entry = match sm.entry_state {
            Some(e) => e,
            None => return HashSet::new(),
        };
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        queue.push_back(entry);
        while let Some(id) = queue.pop_front() {
            if visited.insert(id) {
                for succ in sm.successors(id) {
                    if !visited.contains(&succ) {
                        queue.push_back(succ);
                    }
                }
            }
        }
        visited
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_simple_machine() -> StateMachine {
        // 0 → 1 → 2 (terminal)
        let mut sm = StateMachine::new();
        let mut s0 = State::new(0);
        s0.is_entry = true;
        let s1 = State::new(1);
        let mut s2 = State::new(2);
        s2.is_terminal = true;
        sm.add_state(s0);
        sm.add_state(s1);
        sm.add_state(s2);
        sm.add_transition(Transition {
            from: 0,
            to: 1,
            condition: TransitionCondition::Always,
            next_state_value: 1,
        });
        sm.add_transition(Transition {
            from: 1,
            to: 2,
            condition: TransitionCondition::Always,
            next_state_value: 2,
        });
        sm.entry_state = Some(0);
        sm
    }

    // ── StateMachine ─────────────────────────────────────────────────────────

    #[test]
    fn sm_state_count() {
        let sm = make_simple_machine();
        assert_eq!(sm.state_count(), 3);
    }

    #[test]
    fn sm_transition_count() {
        let sm = make_simple_machine();
        assert_eq!(sm.transition_count(), 2);
    }

    #[test]
    fn sm_successors() {
        let sm = make_simple_machine();
        assert_eq!(sm.successors(0), vec![1]);
        assert_eq!(sm.successors(1), vec![2]);
        assert!(sm.successors(2).is_empty());
    }

    #[test]
    fn sm_predecessors() {
        let sm = make_simple_machine();
        assert!(sm.predecessors(0).is_empty());
        assert_eq!(sm.predecessors(1), vec![0]);
        assert_eq!(sm.predecessors(2), vec![1]);
    }

    #[test]
    fn sm_validate_ok() {
        let sm = make_simple_machine();
        assert!(sm.validate().is_empty());
    }

    #[test]
    fn sm_validate_bad_transition() {
        let mut sm = make_simple_machine();
        sm.add_transition(Transition {
            from: 99,
            to: 0,
            condition: TransitionCondition::Always,
            next_state_value: 0,
        });
        let errs = sm.validate();
        assert!(!errs.is_empty());
    }

    #[test]
    fn sm_entry_state_marked() {
        let sm = make_simple_machine();
        assert!(sm.states[&0].is_entry);
    }

    #[test]
    fn sm_terminal_state_marked() {
        let sm = make_simple_machine();
        assert!(sm.states[&2].is_terminal);
    }

    // ── StateVariable ─────────────────────────────────────────────────────────

    #[test]
    fn state_var_default_width() {
        let sv = StateVariable::new("disp", 0);
        assert_eq!(sv.width_bits, 32);
    }

    #[test]
    fn state_var_with_offset() {
        let sv = StateVariable::new("x", 0).with_frame_offset(-8);
        assert_eq!(sv.frame_offset, Some(-8));
    }

    // ── TransitionMap ─────────────────────────────────────────────────────────

    #[test]
    fn tmap_from_machine() {
        let sm = make_simple_machine();
        let tmap = TransitionMap::from_machine(&sm);
        assert_eq!(tmap.len(), 2);
    }

    #[test]
    fn tmap_get_known() {
        let sm = make_simple_machine();
        let tmap = TransitionMap::from_machine(&sm);
        assert_eq!(tmap.get(0).len(), 1);
    }

    #[test]
    fn tmap_get_unknown() {
        let sm = make_simple_machine();
        let tmap = TransitionMap::from_machine(&sm);
        assert!(tmap.get(99).is_empty());
    }

    #[test]
    fn tmap_sources() {
        let sm = make_simple_machine();
        let tmap = TransitionMap::from_machine(&sm);
        let sources: HashSet<_> = tmap.sources().collect();
        assert!(sources.contains(&0));
        assert!(sources.contains(&1));
    }

    // ── StateElimination ─────────────────────────────────────────────────────

    #[test]
    fn elimination_identifies_pass_through() {
        let sm = make_simple_machine();
        let targets = StateElimination::eliminatable_states(&sm);
        // State 1 has 1 pred (0) and 1 succ (2) → eliminatable.
        assert!(targets.contains(&1));
    }

    #[test]
    fn elimination_does_not_eliminate_entry() {
        let sm = make_simple_machine();
        let targets = StateElimination::eliminatable_states(&sm);
        assert!(!targets.contains(&0));
    }

    #[test]
    fn elimination_apply_reduces_count() {
        let mut sm = make_simple_machine();
        let before = sm.state_count();
        let removed = StateElimination::apply(&mut sm);
        assert!(removed > 0);
        assert!(sm.state_count() < before);
    }

    // ── StateGraphExport ─────────────────────────────────────────────────────

    #[test]
    fn export_dot_contains_digraph() {
        let sm = make_simple_machine();
        let dot = StateGraphExport::to_dot(&sm);
        assert!(dot.contains("digraph"));
    }

    #[test]
    fn export_dot_contains_all_states() {
        let sm = make_simple_machine();
        let dot = StateGraphExport::to_dot(&sm);
        assert!(dot.contains("s0"));
        assert!(dot.contains("s1"));
        assert!(dot.contains("s2"));
    }

    #[test]
    fn export_json_is_valid_looking() {
        let sm = make_simple_machine();
        let json = StateGraphExport::to_json(&sm);
        assert!(json.starts_with('{'));
        assert!(json.ends_with('}'));
        assert!(json.contains("states"));
        assert!(json.contains("transitions"));
    }

    #[test]
    fn export_mermaid_contains_header() {
        let sm = make_simple_machine();
        let mm = StateGraphExport::to_mermaid(&sm);
        assert!(mm.contains("stateDiagram"));
    }

    // ── StructuredState ───────────────────────────────────────────────────────

    #[test]
    fn structured_state_display_sequence() {
        assert_eq!(HighLevelStructure::Sequence.to_string(), "seq");
    }

    #[test]
    fn structured_state_display_return() {
        assert_eq!(HighLevelStructure::Return.to_string(), "return");
    }

    #[test]
    fn structured_state_if_then_display() {
        let s = HighLevelStructure::IfThen {
            condition: "x>0".into(),
        };
        assert!(s.to_string().contains("x>0"));
    }

    // ── StateMachineRecovery ──────────────────────────────────────────────────

    #[test]
    fn recovery_from_pairs() {
        let r = StateMachineRecovery::new();
        let sv = StateVariable::new("disp", 0x10);
        let pairs = vec![
            (0x10, vec![0x20, 0x30]),
            (0x20, vec![0x40]),
            (0x30, vec![0x40]),
            (0x40, vec![]),
        ];
        let sm = r.recover_from_pairs(&pairs, 0x10, sv);
        assert!(sm.state_count() > 0);
    }

    #[test]
    fn recovery_entry_state_set() {
        let r = StateMachineRecovery {
            eliminate_pass_throughs: false,
            ..Default::default()
        };
        let sv = StateVariable::new("x", 1);
        let pairs = vec![(1, vec![2]), (2, vec![])];
        let sm = r.recover_from_pairs(&pairs, 1, sv);
        assert_eq!(sm.entry_state, Some(1));
    }

    #[test]
    fn recovery_terminal_state_detected() {
        let r = StateMachineRecovery {
            eliminate_pass_throughs: false,
            ..Default::default()
        };
        let sv = StateVariable::new("x", 1);
        let pairs = vec![(1, vec![2]), (2, vec![])];
        let sm = r.recover_from_pairs(&pairs, 1, sv);
        assert!(sm.states[&2].is_terminal);
    }

    #[test]
    fn recovery_annotate_sequence() {
        let r = StateMachineRecovery {
            eliminate_pass_throughs: false,
            ..Default::default()
        };
        let sv = StateVariable::new("x", 1);
        let pairs = vec![(1, vec![2]), (2, vec![])];
        let sm = r.recover_from_pairs(&pairs, 1, sv);
        let annotated = r.annotate(&sm);
        assert!(!annotated.is_empty());
    }

    #[test]
    fn recovery_reachable_bfs() {
        let r = StateMachineRecovery::new();
        let sv = StateVariable::new("d", 0);
        let pairs = vec![(0, vec![1, 2]), (1, vec![3]), (2, vec![3]), (3, vec![])];
        let sm = r.recover_from_pairs(&pairs, 0, sv);
        let reach = r.reachable_states(&sm);
        // All states should be reachable from 0.
        for id in [0u64, 1, 2, 3] {
            if sm.states.contains_key(&id) {
                assert!(reach.contains(&id), "state {} not reachable", id);
            }
        }
    }

    #[test]
    fn recovery_reachable_empty_machine() {
        let r = StateMachineRecovery::new();
        let sm = StateMachine::new();
        let reach = r.reachable_states(&sm);
        assert!(reach.is_empty());
    }

    #[test]
    fn sm_default_is_empty() {
        let sm = StateMachine::new();
        assert_eq!(sm.state_count(), 0);
        assert_eq!(sm.transition_count(), 0);
    }

    #[test]
    fn tmap_is_empty_initially() {
        let sm = StateMachine::new();
        let tmap = TransitionMap::from_machine(&sm);
        assert!(tmap.is_empty());
    }

    #[test]
    fn elimination_empty_machine_no_panic() {
        let mut sm = StateMachine::new();
        let removed = StateElimination::apply(&mut sm);
        assert_eq!(removed, 0);
    }

    #[test]
    fn high_level_while_loop_display() {
        let s = HighLevelStructure::WhileLoop {
            condition: "x < 10".into(),
        };
        assert!(s.to_string().contains("while"));
    }

    #[test]
    fn state_var_initial_value() {
        let sv = StateVariable::new("disp", 0xBEEF);
        assert_eq!(sv.initial_value, 0xBEEF);
    }
}
