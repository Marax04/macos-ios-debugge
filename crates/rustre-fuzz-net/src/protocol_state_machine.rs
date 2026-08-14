//! Protocol state machine for deterministic fuzzing.
//!
//! Models a binary protocol as a directed graph of [`State`] nodes connected by
//! [`Transition`] edges.  At runtime the [`ProtocolStateMachine`] walks the
//! graph, optionally sending and receiving messages at each step, and exposes
//! the current state so that higher-level harnesses can decide what to mutate.

use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;

// ── Errors ────────────────────────────────────────────────────────────────────

/// Errors specific to state-machine operations.
#[derive(Debug)]
pub enum StateMachineError {
    /// The state referred to by name was not found in the graph.
    UnknownState(String),
    /// The graph contains a cycle that prevents a topological traversal.
    CyclicGraph,
    /// The machine was asked to follow a transition that is not present on the
    /// current state.
    NoTransition {
        /// The source state.
        from: String,
        /// The destination state requested.
        to: String,
    },
    /// A state was added that already exists.
    DuplicateState(String),
}

impl fmt::Display for StateMachineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownState(s) => write!(f, "unknown state: {s}"),
            Self::CyclicGraph => write!(f, "state graph contains a cycle"),
            Self::NoTransition { from, to } => {
                write!(f, "no transition from '{from}' to '{to}'")
            }
            Self::DuplicateState(s) => write!(f, "duplicate state: {s}"),
        }
    }
}

impl std::error::Error for StateMachineError {}

// ── TransitionAction ──────────────────────────────────────────────────────────

/// The action performed when following a transition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransitionAction {
    /// Send a byte payload to the target.
    Send(Vec<u8>),
    /// Wait for a byte payload from the target (the slice is a required prefix).
    Recv(Vec<u8>),
    /// Send then wait.
    SendRecv {
        /// Payload to send.
        payload: Vec<u8>,
        /// Required response prefix.
        expected: Vec<u8>,
    },
    /// No I/O — pure state change.
    Silent,
}

impl TransitionAction {
    /// Returns the payload that would be sent, if any.
    #[must_use]
    pub fn send_payload(&self) -> Option<&[u8]> {
        match self {
            Self::Send(p) | Self::SendRecv { payload: p, .. } => Some(p),
            _ => None,
        }
    }

    /// Returns the expected response prefix, if any.
    #[must_use]
    pub fn expected_response(&self) -> Option<&[u8]> {
        match self {
            Self::Recv(e) | Self::SendRecv { expected: e, .. } => Some(e),
            _ => None,
        }
    }

    /// Returns `true` if this action involves sending data.
    #[must_use]
    pub const fn is_send(&self) -> bool {
        matches!(self, Self::Send(_) | Self::SendRecv { .. })
    }

    /// Returns `true` if this action involves receiving data.
    #[must_use]
    pub const fn is_recv(&self) -> bool {
        matches!(self, Self::Recv(_) | Self::SendRecv { .. })
    }
}

// ── Transition ────────────────────────────────────────────────────────────────

/// A directed edge in the state graph.
#[derive(Debug, Clone)]
pub struct Transition {
    /// Unique name of this transition within the source state.
    pub name: String,
    /// Destination state.
    pub to: String,
    /// I/O action to perform when following this edge.
    pub action: TransitionAction,
    /// Weight used when randomly choosing among outgoing transitions.  Defaults
    /// to 1.  Higher weights are chosen more often.
    pub weight: u32,
    /// Optional human-readable description.
    pub description: Option<String>,
}

impl Transition {
    /// Create a new silent transition (no I/O).
    #[must_use]
    pub fn silent(name: impl Into<String>, to: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            to: to.into(),
            action: TransitionAction::Silent,
            weight: 1,
            description: None,
        }
    }

    /// Create a send-only transition.
    #[must_use]
    pub fn send(name: impl Into<String>, to: impl Into<String>, payload: Vec<u8>) -> Self {
        Self {
            name: name.into(),
            to: to.into(),
            action: TransitionAction::Send(payload),
            weight: 1,
            description: None,
        }
    }

    /// Create a send-then-receive transition.
    #[must_use]
    pub fn send_recv(
        name: impl Into<String>,
        to: impl Into<String>,
        payload: Vec<u8>,
        expected: Vec<u8>,
    ) -> Self {
        Self {
            name: name.into(),
            to: to.into(),
            action: TransitionAction::SendRecv { payload, expected },
            weight: 1,
            description: None,
        }
    }

    /// Attach a description.
    #[must_use]
    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = Some(desc.into());
        self
    }

    /// Override the selection weight.
    #[must_use]
    pub const fn with_weight(mut self, w: u32) -> Self {
        self.weight = w;
        self
    }
}

// ── State ─────────────────────────────────────────────────────────────────────

/// A single node in the state graph.
#[derive(Debug, Clone)]
pub struct State {
    /// Unique name.
    pub name: String,
    /// Outgoing transitions.
    pub transitions: Vec<Transition>,
    /// True for sink states that have no outgoing edges.
    pub is_terminal: bool,
    /// Optional entry action performed when first entering this state.
    pub entry_action: Option<TransitionAction>,
    /// Arbitrary metadata key/value pairs attached by the user.
    pub metadata: HashMap<String, String>,
}

impl State {
    /// Create a new non-terminal state with no outgoing transitions.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            transitions: Vec::new(),
            is_terminal: false,
            entry_action: None,
            metadata: HashMap::new(),
        }
    }

    /// Mark this state as terminal.
    #[must_use]
    pub const fn terminal(mut self) -> Self {
        self.is_terminal = true;
        self
    }

    /// Add a transition.
    pub fn add_transition(&mut self, t: Transition) {
        self.transitions.push(t);
    }

    /// Look up an outgoing transition by name.
    #[must_use]
    pub fn transition_by_name(&self, name: &str) -> Option<&Transition> {
        self.transitions.iter().find(|t| t.name == name)
    }

    /// Look up an outgoing transition leading to `dest`.
    #[must_use]
    pub fn transition_to(&self, dest: &str) -> Option<&Transition> {
        self.transitions.iter().find(|t| t.to == dest)
    }

    /// Total weight of all outgoing transitions (used for weighted random selection).
    #[must_use]
    pub fn total_weight(&self) -> u32 {
        self.transitions.iter().map(|t| t.weight).sum()
    }

    /// Select a transition by weighted random index drawn from `[0, total_weight)`.
    #[must_use]
    pub fn weighted_pick(&self, rnd: u32) -> Option<&Transition> {
        let total = self.total_weight();
        if total == 0 {
            return None;
        }
        let mut bucket = rnd % total;
        for t in &self.transitions {
            if bucket < t.weight {
                return Some(t);
            }
            bucket -= t.weight;
        }
        self.transitions.last()
    }
}

// ── StateGraph ────────────────────────────────────────────────────────────────

/// The directed graph of states.  States are stored by name.
#[derive(Debug, Default)]
pub struct StateGraph {
    states: HashMap<String, State>,
    /// Insertion-order list of state names (for deterministic iteration).
    order: Vec<String>,
}

impl StateGraph {
    /// Create an empty graph.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a state.  Returns an error if a state with the same name already
    /// exists.
    ///
    /// # Errors
    /// [`StateMachineError::DuplicateState`] when `state.name` is already registered.
    pub fn add_state(&mut self, state: State) -> Result<(), StateMachineError> {
        if self.states.contains_key(&state.name) {
            return Err(StateMachineError::DuplicateState(state.name));
        }
        self.order.push(state.name.clone());
        self.states.insert(state.name.clone(), state);
        Ok(())
    }

    /// Look up a state by name.
    #[must_use]
    pub fn state(&self, name: &str) -> Option<&State> {
        self.states.get(name)
    }

    /// Mutable look-up.
    pub fn state_mut(&mut self, name: &str) -> Option<&mut State> {
        self.states.get_mut(name)
    }

    /// Number of states in the graph.
    #[must_use]
    pub fn len(&self) -> usize {
        self.states.len()
    }

    /// Returns `true` when the graph is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.states.is_empty()
    }

    /// Iterate over all states in insertion order.
    pub fn states(&self) -> impl Iterator<Item = &State> {
        self.order.iter().filter_map(|n| self.states.get(n))
    }

    /// Returns all state names in insertion order.
    #[must_use]
    pub fn state_names(&self) -> Vec<&str> {
        self.order.iter().map(String::as_str).collect()
    }

    /// Collect all edges as `(from_name, to_name)` pairs.
    #[must_use]
    pub fn edges(&self) -> Vec<(&str, &str)> {
        let mut out = Vec::new();
        for s in self.states() {
            for t in &s.transitions {
                out.push((s.name.as_str(), t.to.as_str()));
            }
        }
        out
    }

    /// Validate the graph: every transition target must name an existing state.
    ///
    /// Returns a list of error descriptions; empty means the graph is valid.
    #[must_use]
    pub fn validate(&self) -> Vec<String> {
        let mut errors = Vec::new();
        for s in self.states() {
            for t in &s.transitions {
                if !self.states.contains_key(&t.to) {
                    errors.push(format!(
                        "state '{}' transition '{}' targets unknown state '{}'",
                        s.name, t.name, t.to
                    ));
                }
            }
        }
        errors
    }

    /// Topological sort of the state names (Kahn's algorithm).
    ///
    /// Returns the sorted order, or [`StateMachineError::CyclicGraph`] when a
    /// cycle is detected.
    ///
    /// # Errors
    /// [`StateMachineError::CyclicGraph`]
    pub fn topo_sort(&self) -> Result<Vec<String>, StateMachineError> {
        let mut in_degree: HashMap<&str, usize> = HashMap::new();
        for n in &self.order {
            in_degree.entry(n.as_str()).or_insert(0);
        }
        for s in self.states() {
            for t in &s.transitions {
                *in_degree.entry(t.to.as_str()).or_insert(0) += 1;
            }
        }
        let mut queue: VecDeque<&str> = in_degree
            .iter()
            .filter(|&(_, &deg)| deg == 0)
            .map(|(n, _)| *n)
            .collect();
        let mut result = Vec::new();
        while let Some(node) = queue.pop_front() {
            result.push(node.to_string());
            if let Some(s) = self.states.get(node) {
                for t in &s.transitions {
                    if let Some(deg) = in_degree.get_mut(t.to.as_str()) {
                        *deg = deg.saturating_sub(1);
                        if *deg == 0 {
                            queue.push_back(t.to.as_str());
                        }
                    }
                }
            }
        }
        if result.len() == self.states.len() {
            Ok(result)
        } else {
            Err(StateMachineError::CyclicGraph)
        }
    }

    /// BFS reachability from `start`.  Returns all state names reachable
    /// (including `start` itself).
    #[must_use]
    pub fn reachable_from(&self, start: &str) -> Vec<String> {
        let mut visited: HashSet<String> = HashSet::new();
        let mut queue: VecDeque<String> = VecDeque::new();
        queue.push_back(start.to_string());
        while let Some(cur) = queue.pop_front() {
            if visited.contains(&cur) {
                continue;
            }
            visited.insert(cur.clone());
            if let Some(s) = self.states.get(&cur) {
                for t in &s.transitions {
                    if !visited.contains(&t.to) {
                        queue.push_back(t.to.clone());
                    }
                }
            }
        }
        let mut v: Vec<String> = visited.into_iter().collect();
        v.sort_unstable();
        v
    }
}

// ── ProtocolStateMachine ──────────────────────────────────────────────────────

/// Tracks the current position in a [`StateGraph`] and advances along
/// transitions.  Intended for use by a fuzzing harness that drives the protocol
/// step by step.
#[derive(Debug)]
pub struct ProtocolStateMachine {
    /// The underlying state graph.
    pub graph: StateGraph,
    /// Name of the initial state.
    pub initial: String,
    /// Current state name.
    current: String,
    /// Ordered history of visited state names (most-recent last).
    history: Vec<String>,
    /// Number of transitions taken.
    pub steps: u64,
}

impl ProtocolStateMachine {
    /// Create a new machine with the given graph and initial state.
    ///
    /// # Errors
    /// [`StateMachineError::UnknownState`] if `initial` is not in `graph`.
    pub fn new(
        graph: StateGraph,
        initial: impl Into<String>,
    ) -> Result<Self, StateMachineError> {
        let initial = initial.into();
        if graph.state(&initial).is_none() {
            return Err(StateMachineError::UnknownState(initial));
        }
        Ok(Self {
            current: initial.clone(),
            graph,
            initial,
            history: Vec::new(),
            steps: 0,
        })
    }

    /// Name of the current state.
    #[must_use]
    pub fn current_state(&self) -> &str {
        &self.current
    }

    /// The [`State`] object for the current position.
    ///
    /// # Panics
    /// Panics if the internal state name is not in the graph — this is a
    /// programming error.
    #[must_use]
    pub fn current(&self) -> &State {
        self.graph
            .state(&self.current)
            .expect("current state must exist in graph")
    }

    /// Returns `true` if the machine is in a terminal state.
    #[must_use]
    pub fn is_terminal(&self) -> bool {
        self.current().is_terminal || self.current().transitions.is_empty()
    }

    /// Reset the machine to the initial state without clearing history.
    pub fn reset(&mut self) {
        self.current.clone_from(&self.initial);
    }

    /// Reset and also clear the history and step counter.
    pub fn full_reset(&mut self) {
        self.current.clone_from(&self.initial);
        self.history.clear();
        self.steps = 0;
    }

    /// Advance to `dest` if a direct transition exists.
    ///
    /// Returns a reference to the transition that was followed.
    ///
    /// # Errors
    /// [`StateMachineError::NoTransition`] if no outgoing edge to `dest` exists.
    pub fn advance_to(&mut self, dest: &str) -> Result<&Transition, StateMachineError> {
        let t = self
            .graph
            .state(&self.current)
            .and_then(|s| s.transition_to(dest))
            .ok_or_else(|| StateMachineError::NoTransition {
                from: self.current.clone(),
                to: dest.to_string(),
            })?;
        // We need to clone `to` before mutating `self.current`.
        let to = t.to.clone();
        self.history.push(self.current.clone());
        self.current = to;
        self.steps += 1;
        // Return the transition from the new current state's predecessor.
        let idx = self.history.len() - 1;
        let prev = &self.history[idx];
        self.graph
            .state(prev)
            .and_then(|s| s.transition_to(&self.current))
            .ok_or_else(|| StateMachineError::NoTransition {
                from: prev.clone(),
                to: self.current.clone(),
            })
    }

    /// Advance using the weighted-random index `rnd`.
    ///
    /// Returns the transition followed, or `None` if the current state is
    /// terminal.
    pub fn advance_random(&mut self, rnd: u32) -> Option<&Transition> {
        let state = self.graph.state(&self.current)?;
        let t = state.weighted_pick(rnd)?;
        let to = t.to.clone();
        self.history.push(self.current.clone());
        self.current = to;
        self.steps += 1;
        let idx = self.history.len() - 1;
        let prev = &self.history[idx];
        self.graph
            .state(prev)
            .and_then(|s| s.transition_to(&self.current))
    }

    /// The full history of visited state names.
    #[must_use]
    pub fn history(&self) -> &[String] {
        &self.history
    }

    /// How many times each state has been visited (counts current).
    #[must_use]
    pub fn visit_counts(&self) -> HashMap<String, usize> {
        let mut counts: HashMap<String, usize> = HashMap::new();
        for s in &self.history {
            *counts.entry(s.clone()).or_insert(0) += 1;
        }
        *counts.entry(self.current.clone()).or_insert(0) += 1;
        counts
    }

    /// Compute the next state name that would result from following the
    /// transition named `transition_name` without actually advancing.
    ///
    /// # Errors
    /// [`StateMachineError::NoTransition`] when no such transition exists on the
    /// current state.
    pub fn next_state(&self, transition_name: &str) -> Result<&str, StateMachineError> {
        self.graph
            .state(&self.current)
            .and_then(|s| s.transition_by_name(transition_name))
            .map(|t| t.to.as_str())
            .ok_or_else(|| StateMachineError::NoTransition {
                from: self.current.clone(),
                to: transition_name.to_string(),
            })
    }

    /// All states reachable from the current position.
    #[must_use]
    pub fn reachable(&self) -> Vec<String> {
        self.graph.reachable_from(&self.current)
    }
}

// ── Convenience builder ───────────────────────────────────────────────────────

/// Fluent builder for [`ProtocolStateMachine`].
#[derive(Default)]
pub struct StateMachineBuilder {
    graph: StateGraph,
    initial: Option<String>,
}

impl StateMachineBuilder {
    /// Create a new builder.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the initial state name.  The state must be added before calling
    /// [`build`].
    #[must_use]
    pub fn initial(mut self, name: impl Into<String>) -> Self {
        self.initial = Some(name.into());
        self
    }

    /// Add a state to the graph.  Panics on duplicate state name (use
    /// [`try_add_state`] for fallible operation).
    ///
    /// # Panics
    /// Panics if `state.name` is already registered in the graph.
    #[must_use]
    pub fn add_state(mut self, state: State) -> Self {
        self.graph
            .add_state(state)
            .expect("duplicate state name in builder");
        self
    }

    /// Fallible state addition.
    ///
    /// # Errors
    /// [`StateMachineError::DuplicateState`]
    pub fn try_add_state(mut self, state: State) -> Result<Self, StateMachineError> {
        self.graph.add_state(state)?;
        Ok(self)
    }

    /// Build the [`ProtocolStateMachine`].
    ///
    /// # Errors
    /// [`StateMachineError::UnknownState`] when the initial state was not added.
    pub fn build(self) -> Result<ProtocolStateMachine, StateMachineError> {
        let initial = self.initial.ok_or_else(|| {
            StateMachineError::UnknownState("<initial state not set>".to_string())
        })?;
        ProtocolStateMachine::new(self.graph, initial)
    }
}

// ── next_state free function ──────────────────────────────────────────────────

/// Look up the next state in `graph` when following the transition named
/// `transition_name` from `from_state`.
///
/// Returns the destination state name, or `None` when no such transition exists.
#[must_use]
pub fn next_state<'a>(graph: &'a StateGraph, from_state: &str, transition_name: &str) -> Option<&'a str> {
    graph
        .state(from_state)?
        .transition_by_name(transition_name)
        .map(|t| t.to.as_str())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn build_simple_machine() -> ProtocolStateMachine {
        let mut connect = State::new("connect");
        connect.add_transition(Transition::send(
            "send_hello",
            "auth",
            b"HELLO\n".to_vec(),
        ));

        let mut auth = State::new("auth");
        auth.add_transition(Transition::send_recv(
            "authenticate",
            "ready",
            b"USER admin\n".to_vec(),
            b"+OK".to_vec(),
        ));

        let mut ready = State::new("ready");
        ready.add_transition(Transition::silent("logout", "done"));

        let done = State::new("done").terminal();

        StateMachineBuilder::new()
            .initial("connect")
            .add_state(connect)
            .add_state(auth)
            .add_state(ready)
            .add_state(done)
            .build()
            .unwrap()
    }

    #[test]
    fn initial_state_is_set() {
        let m = build_simple_machine();
        assert_eq!(m.current_state(), "connect");
        assert!(!m.is_terminal());
    }

    #[test]
    fn advance_to_moves_state() {
        let mut m = build_simple_machine();
        m.advance_to("auth").unwrap();
        assert_eq!(m.current_state(), "auth");
        assert_eq!(m.steps, 1);
    }

    #[test]
    fn advance_to_unknown_fails() {
        let mut m = build_simple_machine();
        let err = m.advance_to("nonexistent").unwrap_err();
        assert!(matches!(err, StateMachineError::NoTransition { .. }));
    }

    #[test]
    fn terminal_state_detected() {
        let mut m = build_simple_machine();
        m.advance_to("auth").unwrap();
        m.advance_to("ready").unwrap();
        m.advance_to("done").unwrap();
        assert!(m.is_terminal());
    }

    #[test]
    fn full_reset_clears_history() {
        let mut m = build_simple_machine();
        m.advance_to("auth").unwrap();
        m.full_reset();
        assert_eq!(m.current_state(), "connect");
        assert_eq!(m.steps, 0);
        assert!(m.history().is_empty());
    }

    #[test]
    fn visit_counts_track_history() {
        let mut m = build_simple_machine();
        m.advance_to("auth").unwrap();
        m.advance_to("ready").unwrap();
        let counts = m.visit_counts();
        assert_eq!(counts.get("connect").copied(), Some(1));
        assert_eq!(counts.get("auth").copied(), Some(1));
        assert_eq!(counts.get("ready").copied(), Some(1));
    }

    #[test]
    fn next_state_function_works() {
        let m = build_simple_machine();
        let dest = next_state(&m.graph, "connect", "send_hello");
        assert_eq!(dest, Some("auth"));
    }

    #[test]
    fn next_state_missing_transition_returns_none() {
        let m = build_simple_machine();
        assert!(next_state(&m.graph, "connect", "nonexistent").is_none());
    }

    #[test]
    fn state_graph_validate_passes() {
        let m = build_simple_machine();
        let errors = m.graph.validate();
        assert!(errors.is_empty(), "unexpected errors: {errors:?}");
    }

    #[test]
    fn state_graph_validate_detects_bad_target() {
        let mut g = StateGraph::new();
        let mut s = State::new("a");
        s.add_transition(Transition::silent("goto_ghost", "ghost"));
        g.add_state(s).unwrap();
        let errors = g.validate();
        assert!(!errors.is_empty());
    }

    #[test]
    fn reachable_from_includes_all() {
        let m = build_simple_machine();
        let r = m.graph.reachable_from("connect");
        assert!(r.contains(&"connect".to_string()));
        assert!(r.contains(&"auth".to_string()));
        assert!(r.contains(&"ready".to_string()));
        assert!(r.contains(&"done".to_string()));
    }

    #[test]
    fn weighted_pick_returns_transition() {
        let mut s = State::new("s");
        s.add_transition(Transition::silent("t1", "a").with_weight(3));
        s.add_transition(Transition::silent("t2", "b").with_weight(7));
        assert!(s.weighted_pick(0).is_some());
        assert!(s.weighted_pick(9).is_some());
    }

    #[test]
    fn advance_random_picks_transition() {
        let mut m = build_simple_machine();
        // The "connect" state has one outgoing transition; any rnd works.
        let t = m.advance_random(42).unwrap();
        assert_eq!(t.to, "auth");
    }

    #[test]
    fn state_machine_builder_unknown_initial_fails() {
        let err = StateMachineBuilder::new()
            .initial("ghost")
            .build()
            .unwrap_err();
        assert!(matches!(err, StateMachineError::UnknownState(_)));
    }

    #[test]
    fn transition_action_helpers() {
        let t = Transition::send("t", "dst", b"payload".to_vec());
        assert!(t.action.is_send());
        assert!(!t.action.is_recv());
        assert_eq!(t.action.send_payload(), Some(b"payload".as_slice()));
    }

    #[test]
    fn send_recv_action_helpers() {
        let action = TransitionAction::SendRecv {
            payload: b"send".to_vec(),
            expected: b"ok".to_vec(),
        };
        assert!(action.is_send());
        assert!(action.is_recv());
    }

    #[test]
    fn state_graph_edges() {
        let m = build_simple_machine();
        let edges = m.graph.edges();
        assert!(edges.contains(&("connect", "auth")));
        assert!(edges.contains(&("auth", "ready")));
        assert!(edges.contains(&("ready", "done")));
    }

    #[test]
    fn state_machine_next_state_method() {
        let m = build_simple_machine();
        assert_eq!(m.next_state("send_hello").unwrap(), "auth");
    }

    #[test]
    fn duplicate_state_returns_error() {
        let mut g = StateGraph::new();
        g.add_state(State::new("dup")).unwrap();
        let err = g.add_state(State::new("dup")).unwrap_err();
        assert!(matches!(err, StateMachineError::DuplicateState(_)));
    }
}
