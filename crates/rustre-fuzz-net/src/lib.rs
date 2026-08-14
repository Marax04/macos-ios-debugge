//! `rustre-fuzz-net`
//!
//! Network/stateful protocol fuzzer inspired by Boofuzz.  Lets you describe
//! a protocol as a state-machine with typed fields, then drives the state
//! machine while mutating fuzz-marked fields on each iteration.

pub mod protocol_model;
pub mod crash_analyzer;
pub mod dns_fuzzer;
pub mod grammar_fuzzer;
pub mod mutation_engine;
pub mod network_harness;
pub mod network_state_machine;
pub mod coverage_guided_fuzzer;
pub mod protocol_fuzzer;
pub mod tls_fuzzer;
pub mod protocol_state_fuzzer;
pub mod packet_mutator;
pub mod crash_detector;
pub mod protocol_state_machine;
pub mod replay_engine;

use std::collections::HashMap;
use std::time::SystemTime;

use async_trait::async_trait;
use thiserror::Error;

use rustre_fuzz_afl::{RngCore, XorShiftRng};

// ── Errors ────────────────────────────────────────────────────────────────────

/// Errors that can occur in the network transport layer.
#[derive(Debug, Error)]
pub enum TransportError {
    /// Could not establish a connection.
    #[error("connection failed: {0}")]
    ConnectionFailed(String),
    /// A send operation failed.
    #[error("send failed: {0}")]
    SendFailed(String),
    /// A receive operation failed or timed out.
    #[error("recv failed: {0}")]
    RecvFailed(String),
    /// The remote end disconnected unexpectedly.
    #[error("disconnected")]
    Disconnected,
    /// The operation timed out.
    #[error("timeout")]
    Timeout,
}

/// Errors produced by the protocol fuzzer.
#[derive(Debug, Error)]
pub enum FuzzNetError {
    /// Transport-layer error.
    #[error("transport: {0}")]
    Transport(#[from] TransportError),
    /// The target state was not found in the protocol definition.
    #[error("unknown state: {0}")]
    UnknownState(String),
    /// A `SizeOf` field referenced a field that doesn't exist in the message.
    #[error("size-of field not found: {0}")]
    SizeOfFieldNotFound(String),
    /// An async tokio error.
    #[error("async error: {0}")]
    Async(String),
    /// Payload is too large to be encoded in a u32 length prefix.
    #[error("payload too large: {0} bytes exceeds u32::MAX")]
    PayloadTooLarge(usize),
}

// ── Field types ───────────────────────────────────────────────────────────────

/// Types of fields in a protocol message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FieldType {
    /// A fixed byte sequence; never mutated.
    Static(Vec<u8>),
    /// A random byte sequence of length in `[min, max]`.
    Random {
        /// Minimum number of bytes.
        min: usize,
        /// Maximum number of bytes.
        max: usize,
    },
    /// A fixed- or variable-width integer.
    Integer {
        /// Width in bytes (1, 2, 4, or 8).
        size: u8,
        /// Whether the integer is signed.
        signed: bool,
        /// Current value.
        value: i64,
    },
    /// A variable-length string (UTF-8) of at most `max_len` bytes.
    String {
        /// Maximum length in bytes.
        max_len: usize,
    },
    /// An arbitrary blob of bytes.
    Blob {
        /// Raw bytes.
        data: Vec<u8>,
    },
    /// A length field whose value equals the serialised length of another field.
    SizeOf {
        /// Name of the target field.
        field: String,
    },
}

// ── FieldDef ──────────────────────────────────────────────────────────────────

/// A named field inside a message, with a type and a fuzz flag.
#[derive(Debug, Clone)]
pub struct FieldDef {
    /// Name of the field (must be unique within a message).
    pub name: String,
    /// Type and value of the field.
    pub field_type: FieldType,
    /// If `true` this field will be mutated during fuzzing.
    pub fuzz: bool,
}

impl FieldDef {
    /// Create a new field definition.
    #[must_use]
    pub fn new(name: impl Into<String>, field_type: FieldType, fuzz: bool) -> Self {
        Self {
            name: name.into(),
            field_type,
            fuzz,
        }
    }
}

// ── MessageDef ────────────────────────────────────────────────────────────────

/// A protocol message consisting of an ordered list of fields.
#[derive(Debug, Clone)]
pub struct MessageDef {
    /// Message name.
    pub name: String,
    /// Ordered fields.
    pub fields: Vec<FieldDef>,
}

impl MessageDef {
    /// Create a new message definition.
    #[must_use]
    pub fn new(name: impl Into<String>, fields: Vec<FieldDef>) -> Self {
        Self {
            name: name.into(),
            fields,
        }
    }

    /// Serialise the message to bytes, resolving `SizeOf` fields.
    ///
    /// # Errors
    /// Returns [`FuzzNetError::SizeOfFieldNotFound`] when a `SizeOf` target does
    /// not exist.
    pub fn serialise(&self) -> Result<Vec<u8>, FuzzNetError> {
        // First pass: build a map of field-name → serialised bytes
        let mut field_bytes: HashMap<&str, Vec<u8>> = HashMap::new();
        for field in &self.fields {
            let bytes = serialise_field(&field.field_type, None)?;
            field_bytes.insert(&field.name, bytes);
        }

        // Second pass: resolve SizeOf
        let mut out = Vec::new();
        for field in &self.fields {
            let bytes = match &field.field_type {
                FieldType::SizeOf { field: target } => {
                    let target_bytes = field_bytes
                        .get(target.as_str())
                        .ok_or_else(|| FuzzNetError::SizeOfFieldNotFound(target.clone()))?;
                    let len = target_bytes.len() as u64;
                    len.to_le_bytes().to_vec()
                }
                other => serialise_field(other, None)?,
            };
            out.extend(bytes);
        }
        Ok(out)
    }

    /// Mutate all `fuzz = true` fields using `rng`.
    pub fn mutate(&mut self, rng: &mut dyn RngCore) {
        for field in &mut self.fields {
            if !field.fuzz {
                continue;
            }
            field.field_type = mutate_field(&field.field_type, rng);
        }
    }

    /// Return the total serialised length of the message without resolving
    /// `SizeOf` fields (uses placeholder length 8 for those).
    #[must_use]
    pub fn estimated_len(&self) -> usize {
        self.fields
            .iter()
            .map(|f| field_estimated_len(&f.field_type))
            .sum()
    }

    /// Return the number of fuzz-marked fields.
    #[must_use]
    pub fn fuzz_field_count(&self) -> usize {
        self.fields.iter().filter(|f| f.fuzz).count()
    }

    /// Look up a field by name.
    #[must_use]
    pub fn field(&self, name: &str) -> Option<&FieldDef> {
        self.fields.iter().find(|f| f.name == name)
    }

    /// Look up a field mutably by name.
    #[must_use]
    pub fn field_mut(&mut self, name: &str) -> Option<&mut FieldDef> {
        self.fields.iter_mut().find(|f| f.name == name)
    }
}

/// Return the expected serialised byte length of a field type (without context).
const fn field_estimated_len(ft: &FieldType) -> usize {
    match ft {
        FieldType::Static(b) => b.len(),
        FieldType::Random { min, .. } => *min,
        FieldType::Integer { size, .. } => *size as usize,
        FieldType::String { max_len } => *max_len,
        FieldType::Blob { data } => data.len(),
        FieldType::SizeOf { .. } => 8,
    }
}

/// Serialise a single `FieldType` to bytes.  `_context` is reserved for
/// future use (`SizeOf` resolution in the caller).
fn serialise_field(
    ft: &FieldType,
    _context: Option<&HashMap<&str, Vec<u8>>>,
) -> Result<Vec<u8>, FuzzNetError> {
    Ok(match ft {
        FieldType::Static(bytes) => bytes.clone(),
        FieldType::Random { min, max } => {
            // Produce `min` bytes as a deterministic default
            vec![0u8; *min.min(max)]
        }
        FieldType::Integer { size, value, .. } => {
            let v = *value as u64;
            match size {
                1 => vec![v as u8],
                2 => (v as u16).to_le_bytes().to_vec(),
                4 => (v as u32).to_le_bytes().to_vec(),
                _ => v.to_le_bytes().to_vec(),
            }
        }
        FieldType::String { max_len } => {
            let s = "A".repeat(*max_len);
            s.into_bytes()
        }
        FieldType::Blob { data } => data.clone(),
        FieldType::SizeOf { .. } => {
            // Resolved in two-pass serialisation above
            vec![0u8; 8]
        }
    })
}

/// Produce a mutated version of `ft`.
fn mutate_field(ft: &FieldType, rng: &mut dyn RngCore) -> FieldType {
    match ft {
        FieldType::Static(b) => FieldType::Static(b.clone()),
        FieldType::Random { min, max } => {
            let len = if max == min {
                *min
            } else {
                *min + rng.next_usize(max - min + 1)
            };
            let bytes: Vec<u8> = (0..len).map(|_| (rng.next_u32() & 0xff) as u8).collect();
            FieldType::Blob { data: bytes }
        }
        FieldType::Integer {
            size,
            signed,
            value,
        } => {
            let delta = (rng.next_usize(35) + 1) as i64;
            let new_val = if rng.next_u64() & 1 == 0 {
                value.wrapping_add(delta)
            } else {
                value.wrapping_sub(delta)
            };
            FieldType::Integer {
                size: *size,
                signed: *signed,
                value: new_val,
            }
        }
        FieldType::String { max_len } => {
            let len = rng.next_usize(*max_len + 1);
            let bytes: Vec<u8> = (0..len)
                .map(|_| b'A' + (rng.next_u32() % 26) as u8)
                .collect();
            FieldType::Blob { data: bytes }
        }
        FieldType::Blob { data } => {
            let mut mutated = data.clone();
            if !mutated.is_empty() {
                let idx = rng.next_usize(mutated.len());
                mutated[idx] ^= 0xff;
            }
            FieldType::Blob { data: mutated }
        }
        FieldType::SizeOf { field } => FieldType::SizeOf {
            field: field.clone(),
        },
    }
}

// ── Protocol state machine ────────────────────────────────────────────────────

/// A pattern to match against bytes received from the target.
#[derive(Debug, Clone)]
pub struct PatternMatch {
    /// Expected bytes.
    pub pattern: Vec<u8>,
    /// How long to wait for the pattern before declaring a timeout.
    pub timeout_ms: u64,
}

/// A transition from one protocol state to another.
#[derive(Debug, Clone)]
pub struct Transition {
    /// Name of the state to move to.
    pub to_state: String,
    /// Optional message to send before moving.
    pub send: Option<MessageDef>,
    /// Optional response pattern to wait for.
    pub expect: Option<PatternMatch>,
}

/// A named state in the protocol state machine.
#[derive(Debug, Clone)]
pub struct ProtocolState {
    /// Name of the state.
    pub name: String,
    /// Possible transitions out of this state.
    pub transitions: Vec<Transition>,
}

/// A complete protocol definition.
#[derive(Debug, Clone)]
pub struct ProtocolDef {
    /// Name of the initial state.
    pub initial_state: String,
    /// All states keyed by name.
    pub states: HashMap<String, ProtocolState>,
}

impl ProtocolDef {
    /// Create a new protocol definition.
    #[must_use]
    pub fn new(initial_state: impl Into<String>, states: HashMap<String, ProtocolState>) -> Self {
        Self {
            initial_state: initial_state.into(),
            states,
        }
    }

    /// Return all state names in the protocol.
    #[must_use]
    pub fn state_names(&self) -> Vec<&str> {
        self.states.keys().map(std::string::String::as_str).collect()
    }

    /// Return the number of states.
    #[must_use]
    pub fn state_count(&self) -> usize {
        self.states.len()
    }

    /// Return all transition edges as `(from, to)` pairs.
    #[must_use]
    pub fn edges(&self) -> Vec<(&str, &str)> {
        let mut edges = Vec::new();
        for (name, state) in &self.states {
            for t in &state.transitions {
                edges.push((name.as_str(), t.to_state.as_str()));
            }
        }
        edges
    }

    /// Validate the protocol: check that every transition target exists.
    ///
    /// Returns a list of errors, empty when the protocol is valid.
    #[must_use]
    pub fn validate(&self) -> Vec<String> {
        let mut errors = Vec::new();
        if !self.states.contains_key(&self.initial_state) {
            errors.push(format!("initial state '{}' not found", self.initial_state));
        }
        for (name, state) in &self.states {
            for t in &state.transitions {
                if !self.states.contains_key(&t.to_state) {
                    errors.push(format!(
                        "state '{}' has transition to unknown state '{}'",
                        name, t.to_state
                    ));
                }
            }
        }
        errors
    }
}

// ── Transport trait ───────────────────────────────────────────────────────────

/// Abstraction over a network transport (TCP, UDP, …).
#[async_trait]
pub trait Transport: Send {
    /// Connect to the target.
    async fn connect(&mut self) -> Result<(), TransportError>;
    /// Send `data` to the target.
    async fn send(&mut self, data: &[u8]) -> Result<(), TransportError>;
    /// Receive data, waiting up to `timeout_ms` milliseconds.
    async fn recv(&mut self, timeout_ms: u64) -> Result<Vec<u8>, TransportError>;
    /// Disconnect from the target.
    async fn disconnect(&mut self) -> Result<(), TransportError>;
    /// True when the transport is currently connected.
    fn is_connected(&self) -> bool;
}

// ── TcpTransport ─────────────────────────────────────────────────────────────

/// A basic TCP transport.
pub struct TcpTransport {
    /// Remote host:port.
    pub addr: String,
    /// Internal connected state (stub — full impl would hold tokio `TcpStream`).
    connected: bool,
}

impl TcpTransport {
    /// Create a new TCP transport that will connect to `addr`.
    #[must_use]
    pub fn new(addr: impl Into<String>) -> Self {
        Self {
            addr: addr.into(),
            connected: false,
        }
    }
}

#[async_trait]
impl Transport for TcpTransport {
    async fn connect(&mut self) -> Result<(), TransportError> {
        // Stub: a real implementation would call tokio::net::TcpStream::connect
        self.connected = true;
        Ok(())
    }

    async fn send(&mut self, _data: &[u8]) -> Result<(), TransportError> {
        if !self.connected {
            return Err(TransportError::ConnectionFailed(
                "not connected".to_string(),
            ));
        }
        Ok(())
    }

    async fn recv(&mut self, _timeout_ms: u64) -> Result<Vec<u8>, TransportError> {
        if !self.connected {
            return Err(TransportError::Disconnected);
        }
        Ok(vec![])
    }

    async fn disconnect(&mut self) -> Result<(), TransportError> {
        self.connected = false;
        Ok(())
    }

    fn is_connected(&self) -> bool {
        self.connected
    }
}

// ── UdpTransport ─────────────────────────────────────────────────────────────

/// A basic UDP transport.
pub struct UdpTransport {
    /// Remote host:port.
    pub addr: String,
    connected: bool,
}

impl UdpTransport {
    /// Create a new UDP transport.
    #[must_use]
    pub fn new(addr: impl Into<String>) -> Self {
        Self {
            addr: addr.into(),
            connected: false,
        }
    }
}

#[async_trait]
impl Transport for UdpTransport {
    async fn connect(&mut self) -> Result<(), TransportError> {
        // UDP is connectionless; we just mark ourselves as "open"
        self.connected = true;
        Ok(())
    }

    async fn send(&mut self, _data: &[u8]) -> Result<(), TransportError> {
        if !self.connected {
            return Err(TransportError::ConnectionFailed("not bound".to_string()));
        }
        Ok(())
    }

    async fn recv(&mut self, _timeout_ms: u64) -> Result<Vec<u8>, TransportError> {
        if !self.connected {
            return Err(TransportError::Disconnected);
        }
        Ok(vec![])
    }

    async fn disconnect(&mut self) -> Result<(), TransportError> {
        self.connected = false;
        Ok(())
    }

    fn is_connected(&self) -> bool {
        self.connected
    }
}

// ── CrashLogger ───────────────────────────────────────────────────────────────

/// Records inputs that caused the target server to disconnect or error.
#[derive(Debug, Default)]
pub struct CrashLogger {
    /// Logged crash entries.
    pub entries: Vec<CrashEntry>,
}

/// A single crash log entry.
#[derive(Debug, Clone)]
pub struct CrashEntry {
    /// The message bytes that triggered the crash.
    pub input: Vec<u8>,
    /// Reason for logging (e.g. "disconnected", "timeout").
    pub reason: String,
    /// When the crash was logged.
    pub timestamp: SystemTime,
    /// Which state the fuzzer was in when the crash occurred.
    pub state: String,
}

impl CrashLogger {
    /// Create a new empty logger.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Log a crash event.
    pub fn log(&mut self, input: Vec<u8>, reason: impl Into<String>, state: impl Into<String>) {
        self.entries.push(CrashEntry {
            input,
            reason: reason.into(),
            timestamp: SystemTime::now(),
            state: state.into(),
        });
    }

    /// Number of logged crashes.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.entries.len()
    }

    /// True when no crashes have been logged.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Return all unique crash reasons seen so far.
    #[must_use]
    pub fn unique_reasons(&self) -> Vec<&str> {
        let mut seen: Vec<&str> = Vec::new();
        for entry in &self.entries {
            let r = entry.reason.as_str();
            if !seen.contains(&r) {
                seen.push(r);
            }
        }
        seen
    }

    /// Return all entries that match the given reason string.
    #[must_use]
    pub fn by_reason(&self, reason: &str) -> Vec<&CrashEntry> {
        self.entries.iter().filter(|e| e.reason == reason).collect()
    }

    /// Return all entries that occurred in the given protocol state.
    #[must_use]
    pub fn by_state(&self, state: &str) -> Vec<&CrashEntry> {
        self.entries.iter().filter(|e| e.state == state).collect()
    }

    /// Clear all logged entries.
    pub fn clear(&mut self) {
        self.entries.clear();
    }

    /// Deduplicate entries by keeping only the first occurrence of each unique
    /// (reason, state) pair, discarding later duplicates.
    pub fn dedup(&mut self) {
        let mut seen: std::collections::HashSet<(String, String)> = std::collections::HashSet::new();
        self.entries.retain(|e| {
            let key = (e.reason.clone(), e.state.clone());
            seen.insert(key)
        });
    }

    /// Return a summary string listing crash counts by state.
    #[must_use]
    pub fn summary(&self) -> String {
        let mut counts: HashMap<&str, usize> = HashMap::new();
        for entry in &self.entries {
            *counts.entry(entry.state.as_str()).or_insert(0) += 1;
        }
        let mut parts: Vec<String> = counts
            .iter()
            .map(|(state, count)| format!("{state}:{count}"))
            .collect();
        parts.sort();
        parts.join(", ")
    }
}

// ── FuzzSession ───────────────────────────────────────────────────────────────

/// Drives the protocol state machine, mutating fuzz-marked fields each
/// iteration.
pub struct FuzzSession {
    /// Protocol definition.
    pub protocol: ProtocolDef,
    /// Underlying transport.
    pub transport: Box<dyn Transport>,
    /// Crash logger.
    pub crash_logger: CrashLogger,
    /// Internal PRNG.
    rng: XorShiftRng,
    /// Current state name.
    current_state: String,
    /// Number of iterations performed.
    pub iterations: u64,
    /// Total bytes sent across all iterations.
    pub total_bytes_sent: u64,
    /// Statistics: how many times each state was visited.
    pub state_visit_counts: HashMap<String, u64>,
}

impl FuzzSession {
    /// Create a new fuzz session.
    #[must_use]
    pub fn new(protocol: ProtocolDef, transport: Box<dyn Transport>) -> Self {
        let initial = protocol.initial_state.clone();
        Self {
            protocol,
            transport,
            crash_logger: CrashLogger::new(),
            rng: XorShiftRng::default(),
            current_state: initial,
            iterations: 0,
            total_bytes_sent: 0,
            state_visit_counts: HashMap::new(),
        }
    }

    /// Reset to the initial state.
    pub fn reset(&mut self) {
        self.current_state.clone_from(&self.protocol.initial_state);
    }

    /// Return the current state name.
    #[must_use]
    pub fn current_state(&self) -> &str {
        &self.current_state
    }

    /// Execute a single fuzzing iteration: run through the state machine once.
    ///
    /// # Errors
    /// Returns [`FuzzNetError`] on transport failures or unknown states.
    pub async fn run_once(&mut self) -> Result<(), FuzzNetError> {
        self.reset();
        // Disconnect any leftover connection before opening a new one to avoid
        // silently re-entering the Connected state from an already-connected
        // transport (state-machine-double-enter).
        if self.transport.is_connected() {
            self.transport.disconnect().await.ok();
        }
        self.transport.connect().await?;
        self.iterations += 1;

        const MAX_STEPS: u32 = 1000;
        let mut steps: u32 = 0;
        loop {
            if steps >= MAX_STEPS {
                self.crash_logger.log(
                    vec![],
                    "max_steps_exceeded".to_string(),
                    self.current_state.clone(),
                );
                self.transport.disconnect().await.ok();
                return Ok(());
            }
            steps += 1;

            // Track state visits
            *self
                .state_visit_counts
                .entry(self.current_state.clone())
                .or_insert(0) += 1;

            let state = self
                .protocol
                .states
                .get(&self.current_state)
                .ok_or_else(|| FuzzNetError::UnknownState(self.current_state.clone()))?
                .clone();

            if state.transitions.is_empty() {
                break;
            }

            let t_idx = self.rng.next_usize(state.transitions.len());
            let mut transition = state.transitions[t_idx].clone();

            if let Some(ref mut msg) = transition.send {
                msg.mutate(&mut self.rng);
                match msg.serialise() {
                    Ok(bytes) => {
                        self.total_bytes_sent += bytes.len() as u64;
                        if let Err(e) = self.transport.send(&bytes).await {
                            self.crash_logger.log(
                                bytes.clone(),
                                e.to_string(),
                                self.current_state.clone(),
                            );
                            self.transport.disconnect().await.ok();
                            return Ok(());
                        }
                    }
                    Err(e) => return Err(e),
                }
            }

            if let Some(ref pattern) = transition.expect {
                match self.transport.recv(pattern.timeout_ms).await {
                    Ok(_) => {}
                    Err(TransportError::Timeout) => {
                        self.crash_logger.log(
                            vec![],
                            "timeout".to_string(),
                            self.current_state.clone(),
                        );
                        self.transport.disconnect().await.ok();
                        return Ok(());
                    }
                    Err(TransportError::Disconnected) => {
                        self.crash_logger.log(
                            vec![],
                            "disconnected".to_string(),
                            self.current_state.clone(),
                        );
                        return Ok(());
                    }
                    Err(e) => return Err(FuzzNetError::Transport(e)),
                }
            }

            self.current_state.clone_from(&transition.to_state);

            // Break if the next state doesn't exist (terminal state)
            if !self.protocol.states.contains_key(&self.current_state) {
                break;
            }
        }

        self.transport.disconnect().await?;
        Ok(())
    }

    /// Run `count` fuzzing iterations.
    ///
    /// # Errors
    /// Propagates transport / state-machine errors.
    pub async fn run(&mut self, count: u64) -> Result<(), FuzzNetError> {
        for _ in 0..count {
            self.run_once().await?;
        }
        Ok(())
    }

    /// Return a snapshot of the current session statistics.
    #[must_use]
    pub fn stats(&self) -> SessionStats {
        SessionStats {
            iterations: self.iterations,
            total_bytes_sent: self.total_bytes_sent,
            crash_count: self.crash_logger.len(),
            state_visit_counts: self.state_visit_counts.clone(),
        }
    }
}

// ── SessionStats ──────────────────────────────────────────────────────────────

/// A snapshot of session statistics.
#[derive(Debug, Clone)]
pub struct SessionStats {
    /// Number of completed iterations.
    pub iterations: u64,
    /// Total bytes transmitted.
    pub total_bytes_sent: u64,
    /// Number of crashes logged.
    pub crash_count: usize,
    /// Per-state visit counts.
    pub state_visit_counts: HashMap<String, u64>,
}

impl SessionStats {
    /// Returns the most-visited state, or `None` if no states have been visited.
    #[must_use]
    pub fn most_visited_state(&self) -> Option<&str> {
        self.state_visit_counts
            .iter()
            .max_by_key(|&(_, &v)| v)
            .map(|(k, _)| k.as_str())
    }

    /// Returns the average bytes sent per iteration, or 0 when no iterations
    /// have completed.
    #[must_use]
    pub const fn avg_bytes_per_iter(&self) -> u64 {
        if self.iterations == 0 {
            0
        } else {
            self.total_bytes_sent / self.iterations
        }
    }
}

// ── ProtocolFuzzer ────────────────────────────────────────────────────────────

/// High-level API wrapping a [`FuzzSession`].
pub struct ProtocolFuzzer {
    /// The underlying fuzz session.
    pub session: FuzzSession,
}

impl ProtocolFuzzer {
    /// Create a new protocol fuzzer.
    #[must_use]
    pub fn new(protocol: ProtocolDef, transport: Box<dyn Transport>) -> Self {
        Self {
            session: FuzzSession::new(protocol, transport),
        }
    }

    /// Run the fuzzer for `count` iterations.
    ///
    /// # Errors
    /// Propagates errors from the session.
    pub async fn fuzz(&mut self, count: u64) -> Result<(), FuzzNetError> {
        self.session.run(count).await
    }

    /// Return current statistics.
    #[must_use]
    pub fn stats(&self) -> SessionStats {
        self.session.stats()
    }

    /// True if any crashes have been logged.
    #[must_use]
    pub const fn has_crashes(&self) -> bool {
        !self.session.crash_logger.is_empty()
    }
}

// ── ProtocolBuilder ───────────────────────────────────────────────────────────

/// Fluent builder for [`ProtocolDef`].
///
/// # Example
/// ```rust
/// use rustre_fuzz_net::ProtocolBuilder;
/// let proto = ProtocolBuilder::new("start")
///     .add_terminal("done")
///     .build();
/// assert!(proto.validate().is_empty());
/// ```
#[derive(Debug, Default)]
pub struct ProtocolBuilder {
    initial_state: String,
    states: HashMap<String, ProtocolState>,
}

impl ProtocolBuilder {
    /// Create a new builder with `initial_state` as the starting state.
    #[must_use]
    pub fn new(initial_state: impl Into<String>) -> Self {
        let name = initial_state.into();
        let mut b = Self {
            initial_state: name.clone(),
            states: HashMap::new(),
        };
        b.states.insert(
            name.clone(),
            ProtocolState {
                name,
                transitions: Vec::new(),
            },
        );
        b
    }

    /// Add a terminal (no-transition) state.
    #[must_use]
    pub fn add_terminal(mut self, name: impl Into<String>) -> Self {
        let n = name.into();
        self.states.entry(n.clone()).or_insert(ProtocolState {
            name: n,
            transitions: Vec::new(),
        });
        self
    }

    /// Add a transition from `from_state` to `to_state` with an optional
    /// message to send.
    #[must_use]
    pub fn add_transition(
        mut self,
        from_state: impl Into<String>,
        to_state: impl Into<String>,
        message: Option<MessageDef>,
    ) -> Self {
        let from = from_state.into();
        let to = to_state.into();
        // Ensure both states exist
        self.states.entry(from.clone()).or_insert(ProtocolState {
            name: from.clone(),
            transitions: Vec::new(),
        });
        self.states.entry(to.clone()).or_insert(ProtocolState {
            name: to.clone(),
            transitions: Vec::new(),
        });
        let t = Transition {
            to_state: to,
            send: message,
            expect: None,
        };
        if let Some(state) = self.states.get_mut(&from) {
            state.transitions.push(t);
        }
        self
    }

    /// Add a transition that also waits for a response pattern.
    #[must_use]
    pub fn add_transition_with_expect(
        mut self,
        from_state: impl Into<String>,
        to_state: impl Into<String>,
        message: Option<MessageDef>,
        pattern: PatternMatch,
    ) -> Self {
        let from = from_state.into();
        let to = to_state.into();
        self.states.entry(from.clone()).or_insert(ProtocolState {
            name: from.clone(),
            transitions: Vec::new(),
        });
        self.states.entry(to.clone()).or_insert(ProtocolState {
            name: to.clone(),
            transitions: Vec::new(),
        });
        let t = Transition {
            to_state: to,
            send: message,
            expect: Some(pattern),
        };
        if let Some(state) = self.states.get_mut(&from) {
            state.transitions.push(t);
        }
        self
    }

    /// Consume the builder and produce a [`ProtocolDef`].
    #[must_use]
    pub fn build(self) -> ProtocolDef {
        ProtocolDef {
            initial_state: self.initial_state,
            states: self.states,
        }
    }
}

// ── MessageBuilder ────────────────────────────────────────────────────────────

/// Fluent builder for [`MessageDef`].
#[derive(Debug)]
pub struct MessageBuilder {
    name: String,
    fields: Vec<FieldDef>,
}

impl MessageBuilder {
    /// Create a new message builder.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            fields: Vec::new(),
        }
    }

    /// Append a static (non-fuzzed) byte field.
    #[must_use]
    pub fn static_bytes(mut self, name: impl Into<String>, data: Vec<u8>) -> Self {
        self.fields
            .push(FieldDef::new(name, FieldType::Static(data), false));
        self
    }

    /// Append a fuzzable blob field with the given initial content.
    #[must_use]
    pub fn fuzz_blob(mut self, name: impl Into<String>, data: Vec<u8>) -> Self {
        self.fields
            .push(FieldDef::new(name, FieldType::Blob { data }, true));
        self
    }

    /// Append a fuzzable integer field.
    #[must_use]
    pub fn fuzz_u8(mut self, name: impl Into<String>, value: u8) -> Self {
        self.fields.push(FieldDef::new(
            name,
            FieldType::Integer {
                size: 1,
                signed: false,
                value: i64::from(value),
            },
            true,
        ));
        self
    }

    /// Append a fuzzable u16 field.
    #[must_use]
    pub fn fuzz_u16(mut self, name: impl Into<String>, value: u16) -> Self {
        self.fields.push(FieldDef::new(
            name,
            FieldType::Integer {
                size: 2,
                signed: false,
                value: i64::from(value),
            },
            true,
        ));
        self
    }

    /// Append a fuzzable u32 field.
    #[must_use]
    pub fn fuzz_u32(mut self, name: impl Into<String>, value: u32) -> Self {
        self.fields.push(FieldDef::new(
            name,
            FieldType::Integer {
                size: 4,
                signed: false,
                value: i64::from(value),
            },
            true,
        ));
        self
    }

    /// Append a fuzzable random field.
    #[must_use]
    pub fn fuzz_random(mut self, name: impl Into<String>, min: usize, max: usize) -> Self {
        self.fields
            .push(FieldDef::new(name, FieldType::Random { min, max }, true));
        self
    }

    /// Append a fuzzable string field.
    #[must_use]
    pub fn fuzz_string(mut self, name: impl Into<String>, max_len: usize) -> Self {
        self.fields
            .push(FieldDef::new(name, FieldType::String { max_len }, true));
        self
    }

    /// Append a size-of length field (not fuzzed).
    #[must_use]
    pub fn size_of(mut self, name: impl Into<String>, target_field: impl Into<String>) -> Self {
        self.fields.push(FieldDef::new(
            name,
            FieldType::SizeOf {
                field: target_field.into(),
            },
            false,
        ));
        self
    }

    /// Consume the builder and produce a [`MessageDef`].
    #[must_use]
    pub fn build(self) -> MessageDef {
        MessageDef {
            name: self.name,
            fields: self.fields,
        }
    }
}

// ── MutationStrategy ─────────────────────────────────────────────────────────

/// Controls how aggressively fields are mutated per iteration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MutationStrategy {
    /// Mutate exactly one randomly chosen fuzz field per iteration.
    SingleField,
    /// Mutate all fuzz fields on every iteration.
    AllFields,
    /// Flip a single random bit in a randomly chosen fuzz field.
    BitFlip,
    /// Replace all bytes in a fuzz field with a boundary value (0x00 or 0xff).
    BoundaryValues,
}

/// Apply a mutation strategy to a message, using `rng`.
pub fn apply_strategy(msg: &mut MessageDef, strategy: MutationStrategy, rng: &mut dyn RngCore) {
    let fuzz_indices: Vec<usize> = msg
        .fields
        .iter()
        .enumerate()
        .filter(|(_, f)| f.fuzz)
        .map(|(i, _)| i)
        .collect();

    if fuzz_indices.is_empty() {
        return;
    }

    match strategy {
        MutationStrategy::AllFields => {
            for &i in &fuzz_indices {
                msg.fields[i].field_type = mutate_field(&msg.fields[i].field_type.clone(), rng);
            }
        }
        MutationStrategy::SingleField => {
            let pick = fuzz_indices[rng.next_usize(fuzz_indices.len())];
            msg.fields[pick].field_type = mutate_field(&msg.fields[pick].field_type.clone(), rng);
        }
        MutationStrategy::BitFlip => {
            let pick = fuzz_indices[rng.next_usize(fuzz_indices.len())];
            msg.fields[pick].field_type = bit_flip_field(&msg.fields[pick].field_type.clone(), rng);
        }
        MutationStrategy::BoundaryValues => {
            let pick = fuzz_indices[rng.next_usize(fuzz_indices.len())];
            msg.fields[pick].field_type = boundary_field(&msg.fields[pick].field_type.clone(), rng);
        }
    }
}

/// Flip a single random bit in the serialised representation of a field.
fn bit_flip_field(ft: &FieldType, rng: &mut dyn RngCore) -> FieldType {
    // Serialise → flip → wrap as blob
    let mut bytes = match ft {
        FieldType::Blob { data } => data.clone(),
        FieldType::Static(b) => b.clone(),
        FieldType::Integer { size, value, .. } => {
            let v = *value as u64;
            match size {
                1 => vec![v as u8],
                2 => (v as u16).to_le_bytes().to_vec(),
                4 => (v as u32).to_le_bytes().to_vec(),
                _ => v.to_le_bytes().to_vec(),
            }
        }
        _ => vec![0u8; 4],
    };
    if !bytes.is_empty() {
        let byte_idx = rng.next_usize(bytes.len());
        let bit_idx = rng.next_usize(8);
        bytes[byte_idx] ^= 1 << bit_idx;
    }
    FieldType::Blob { data: bytes }
}

/// Replace a field's bytes with all-zeros or all-ones boundary value.
fn boundary_field(ft: &FieldType, rng: &mut dyn RngCore) -> FieldType {
    let len = field_estimated_len(ft).max(1);
    let fill: u8 = if rng.next_u32() & 1 == 0 { 0x00 } else { 0xff };
    FieldType::Blob {
        data: vec![fill; len],
    }
}

// ── Coverage tracking ─────────────────────────────────────────────────────────

/// Tracks which (state, transition-index) pairs have been exercised.
#[derive(Debug, Default)]
pub struct CoverageMap {
    /// Set of (`state_name`, `transition_index`) pairs visited.
    visited: Vec<(String, usize)>,
}

impl CoverageMap {
    /// Create a new, empty coverage map.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a visit to `(state, transition_idx)`.
    pub fn record(&mut self, state: impl Into<String>, transition_idx: usize) {
        let key = (state.into(), transition_idx);
        if !self.visited.contains(&key) {
            self.visited.push(key);
        }
    }

    /// Return the number of unique (state, transition) pairs covered.
    #[must_use]
    pub const fn covered(&self) -> usize {
        self.visited.len()
    }

    /// Compute coverage percentage given the total number of transitions in a
    /// protocol.
    ///
    /// Returns a value in `[0.0, 100.0]`.
    #[must_use]
    pub fn coverage_pct(&self, total_transitions: usize) -> f64 {
        if total_transitions == 0 {
            return 100.0;
        }
        (self.covered() as f64 / total_transitions as f64) * 100.0
    }

    /// True if `(state, transition_idx)` has been visited.
    #[must_use]
    pub fn is_covered(&self, state: &str, transition_idx: usize) -> bool {
        self.visited
            .iter()
            .any(|(s, i)| s == state && *i == transition_idx)
    }
}

// ── ResponseMatcher ───────────────────────────────────────────────────────────

/// Checks whether a received byte buffer contains an expected pattern.
#[derive(Debug, Clone)]
pub struct ResponseMatcher {
    /// Byte pattern to search for.
    pub pattern: Vec<u8>,
}

impl ResponseMatcher {
    /// Create a new matcher for `pattern`.
    #[must_use]
    pub const fn new(pattern: Vec<u8>) -> Self {
        Self { pattern }
    }

    /// Return `true` if `buf` contains `self.pattern` as a contiguous
    /// subsequence.
    #[must_use]
    pub fn matches(&self, buf: &[u8]) -> bool {
        if self.pattern.is_empty() {
            return true;
        }
        if self.pattern.len() > buf.len() {
            return false;
        }
        buf.windows(self.pattern.len())
            .any(|w| w == self.pattern.as_slice())
    }

    /// Return the index of the first occurrence of the pattern in `buf`, or
    /// `None` if not found.
    #[must_use]
    pub fn find(&self, buf: &[u8]) -> Option<usize> {
        if self.pattern.is_empty() {
            return Some(0);
        }
        buf.windows(self.pattern.len())
            .position(|w| w == self.pattern.as_slice())
    }
}

// ── FuzzCorpus ────────────────────────────────────────────────────────────────

/// A corpus of interesting inputs discovered during fuzzing.
///
/// Interesting inputs are those that triggered new coverage or unusual
/// behaviour.
#[derive(Debug, Default)]
pub struct FuzzCorpus {
    /// Stored interesting inputs.
    entries: Vec<CorpusEntry>,
}

/// A single entry in the corpus.
#[derive(Debug, Clone)]
pub struct CorpusEntry {
    /// The raw bytes of the input.
    pub data: Vec<u8>,
    /// Reason this input was considered interesting.
    pub tag: String,
    /// Protocol state in which it was generated.
    pub state: String,
}

impl FuzzCorpus {
    /// Create an empty corpus.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an entry to the corpus.
    pub fn add(&mut self, data: Vec<u8>, tag: impl Into<String>, state: impl Into<String>) {
        self.entries.push(CorpusEntry {
            data,
            tag: tag.into(),
            state: state.into(),
        });
    }

    /// Number of entries in the corpus.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.entries.len()
    }

    /// True when the corpus is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Randomly select an entry for mutation seeding, using `rng`.
    #[must_use]
    pub fn pick<'a>(&'a self, rng: &mut dyn RngCore) -> Option<&'a CorpusEntry> {
        if self.entries.is_empty() {
            return None;
        }
        Some(&self.entries[rng.next_usize(self.entries.len())])
    }

    /// Return all entries tagged with `tag`.
    #[must_use]
    pub fn by_tag(&self, tag: &str) -> Vec<&CorpusEntry> {
        self.entries.iter().filter(|e| e.tag == tag).collect()
    }

    /// Remove duplicate entries (same data), keeping only the first.
    pub fn dedup(&mut self) {
        let mut seen: std::collections::HashSet<Vec<u8>> = std::collections::HashSet::new();
        self.entries.retain(|e| seen.insert(e.data.clone()));
    }
}

// ── Packet framing helpers ────────────────────────────────────────────────────

/// Encode `payload` with a 4-byte little-endian length prefix.
///
/// # Errors
/// Returns an error if the payload length exceeds `u32::MAX`.
pub fn frame_u32_le(payload: &[u8]) -> Result<Vec<u8>, FuzzNetError> {
    let len = u32::try_from(payload.len())
        .map_err(|_| FuzzNetError::PayloadTooLarge(payload.len()))?;
    let mut out = Vec::with_capacity(4 + payload.len());
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}

/// Encode `payload` with a 4-byte big-endian length prefix.
///
/// # Errors
/// Returns an error if the payload length exceeds `u32::MAX`.
pub fn frame_u32_be(payload: &[u8]) -> Result<Vec<u8>, FuzzNetError> {
    let len = u32::try_from(payload.len())
        .map_err(|_| FuzzNetError::PayloadTooLarge(payload.len()))?;
    let mut out = Vec::with_capacity(4 + payload.len());
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}

/// Decode a length-prefixed (u32 LE) frame from `buf`.
///
/// Returns `Some((header_len, payload))` when a complete frame is present, or
/// `None` when not enough bytes are available.
#[must_use]
pub fn decode_frame_u32_le(buf: &[u8]) -> Option<(usize, Vec<u8>)> {
    if buf.len() < 4 {
        return None;
    }
    let len = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    // Use saturating_add to prevent integer overflow on 32-bit platforms when
    // an attacker supplies a length near usize::MAX.
    let total = (4usize).saturating_add(len);
    if buf.len() < total {
        return None;
    }
    Some((total, buf[4..total].to_vec()))
}

/// Decode a length-prefixed (u32 BE) frame from `buf`.
///
/// Returns `Some((header_len, payload))` when a complete frame is present, or
/// `None` when not enough bytes are available.
#[must_use]
pub fn decode_frame_u32_be(buf: &[u8]) -> Option<(usize, Vec<u8>)> {
    if buf.len() < 4 {
        return None;
    }
    let len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    // Use saturating_add to prevent integer overflow on 32-bit platforms when
    // an attacker supplies a length near usize::MAX.
    let total = (4usize).saturating_add(len);
    if buf.len() < total {
        return None;
    }
    Some((total, buf[4..total].to_vec()))
}

/// Compute a simple 8-bit XOR checksum over `data`.
#[must_use]
pub fn xor_checksum(data: &[u8]) -> u8 {
    data.iter().fold(0u8, |acc, &b| acc ^ b)
}

/// Compute a simple additive (wrapping) 8-bit checksum over `data`.
#[must_use]
pub fn add_checksum(data: &[u8]) -> u8 {
    data.iter().fold(0u8, |acc, &b| acc.wrapping_add(b))
}

// ── Interesting integer values ────────────────────────────────────────────────

/// A hardcoded list of boundary/interesting integer values commonly used in
/// protocol fuzzing (mimics boofuzz / sulley interesting values).
pub const INTERESTING_U8: &[u8] = &[0x00, 0x01, 0x7f, 0x80, 0xfe, 0xff];

/// Interesting 16-bit unsigned values.
pub const INTERESTING_U16: &[u16] = &[
    0x0000, 0x0001, 0x007f, 0x0080, 0x00ff, 0x0100, 0x7fff, 0x8000, 0xfffe, 0xffff,
];

/// Interesting 32-bit unsigned values.
pub const INTERESTING_U32: &[u32] = &[
    0x0000_0000,
    0x0000_0001,
    0x0000_007f,
    0x0000_0080,
    0x0000_00ff,
    0x0000_0100,
    0x0000_7fff,
    0x0000_8000,
    0x0000_ffff,
    0x0001_0000,
    0x7fff_ffff,
    0x8000_0000,
    0xffff_fffe,
    0xffff_ffff,
];

/// Generate a mutated integer field value by picking from the interesting table
/// or applying a random delta.
///
/// Returns the mutated value.
#[must_use]
pub fn interesting_int_mutation(current: i64, size_bytes: u8, rng: &mut dyn RngCore) -> i64 {
    let use_interesting = rng.next_usize(4) == 0; // 25 % chance
    if use_interesting {
        match size_bytes {
            1 => i64::from(INTERESTING_U8[rng.next_usize(INTERESTING_U8.len())]),
            2 => i64::from(INTERESTING_U16[rng.next_usize(INTERESTING_U16.len())]),
            _ => i64::from(INTERESTING_U32[rng.next_usize(INTERESTING_U32.len())]),
        }
    } else {
        let delta = (rng.next_usize(256) + 1) as i64;
        if rng.next_u32() & 1 == 0 {
            current.wrapping_add(delta)
        } else {
            current.wrapping_sub(delta)
        }
    }
}

// ── ReplaySession ─────────────────────────────────────────────────────────────

/// Replays a list of pre-recorded byte sequences through a transport,
/// useful for reproducing crashes found during fuzzing.
pub struct ReplaySession {
    /// Inputs to replay.
    pub inputs: Vec<Vec<u8>>,
    /// Underlying transport.
    pub transport: Box<dyn Transport>,
    /// Delay between sends, in milliseconds.
    pub delay_ms: u64,
}

impl ReplaySession {
    /// Create a new replay session.
    #[must_use]
    pub fn new(inputs: Vec<Vec<u8>>, transport: Box<dyn Transport>) -> Self {
        Self {
            inputs,
            transport,
            delay_ms: 0,
        }
    }

    /// Run all replays.
    ///
    /// # Errors
    /// Returns [`FuzzNetError`] on transport failure.
    pub async fn run(&mut self) -> Result<ReplayResult, FuzzNetError> {
        self.transport.connect().await?;
        let mut result = ReplayResult::default();

        for (idx, input) in self.inputs.iter().enumerate() {
            match self.transport.send(input).await {
                Ok(()) => result.successes += 1,
                Err(e) => {
                    result.failures.push(ReplayFailure {
                        input_index: idx,
                        reason: e.to_string(),
                    });
                }
            }
        }

        self.transport.disconnect().await.ok();
        Ok(result)
    }
}

/// Result of a replay session.
#[derive(Debug, Default)]
pub struct ReplayResult {
    /// Number of inputs sent without error.
    pub successes: usize,
    /// Inputs that triggered an error.
    pub failures: Vec<ReplayFailure>,
}

/// A single replay failure.
#[derive(Debug)]
pub struct ReplayFailure {
    /// Index of the failing input in the original list.
    pub input_index: usize,
    /// Error reason.
    pub reason: String,
}

// ── MutationHistory ───────────────────────────────────────────────────────────

/// Records the last N mutations applied to a message, enabling rollback.
#[derive(Debug, Default)]
pub struct MutationHistory {
    snapshots: Vec<MessageDef>,
    max_depth: usize,
}

impl MutationHistory {
    /// Create a new history buffer that keeps up to `max_depth` snapshots.
    #[must_use]
    pub fn new(max_depth: usize) -> Self {
        Self {
            snapshots: Vec::new(),
            max_depth: max_depth.max(1),
        }
    }

    /// Push a snapshot of `msg`.
    pub fn push(&mut self, msg: &MessageDef) {
        if self.snapshots.len() >= self.max_depth {
            self.snapshots.remove(0);
        }
        self.snapshots.push(msg.clone());
    }

    /// Pop the most recent snapshot, returning it as the rolled-back message.
    pub fn pop(&mut self) -> Option<MessageDef> {
        self.snapshots.pop()
    }

    /// Number of snapshots stored.
    #[must_use]
    pub const fn depth(&self) -> usize {
        self.snapshots.len()
    }
}

// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Mock transport ────────────────────────────────────────────────────────

    struct MockTransport {
        connected: bool,
        crash_after: Option<usize>,
        send_count: usize,
        recv_response: Vec<u8>,
    }

    impl MockTransport {
        fn always_ok() -> Self {
            Self {
                connected: false,
                crash_after: None,
                send_count: 0,
                recv_response: vec![0x4f, 0x4b], // "OK"
            }
        }

        fn crash_on_send(n: usize) -> Self {
            Self {
                connected: false,
                crash_after: Some(n),
                send_count: 0,
                recv_response: vec![],
            }
        }
    }

    #[async_trait]
    impl Transport for MockTransport {
        async fn connect(&mut self) -> Result<(), TransportError> {
            self.connected = true;
            Ok(())
        }

        async fn send(&mut self, _data: &[u8]) -> Result<(), TransportError> {
            if !self.connected {
                return Err(TransportError::ConnectionFailed("not connected".into()));
            }
            self.send_count += 1;
            if let Some(n) = self.crash_after
                && self.send_count >= n {
                    self.connected = false;
                    return Err(TransportError::Disconnected);
                }
            Ok(())
        }

        async fn recv(&mut self, _timeout_ms: u64) -> Result<Vec<u8>, TransportError> {
            Ok(self.recv_response.clone())
        }

        async fn disconnect(&mut self) -> Result<(), TransportError> {
            self.connected = false;
            Ok(())
        }

        fn is_connected(&self) -> bool {
            self.connected
        }
    }

    fn simple_protocol() -> ProtocolDef {
        let mut states = HashMap::new();
        states.insert(
            "start".to_string(),
            ProtocolState {
                name: "start".to_string(),
                transitions: vec![Transition {
                    to_state: "done".to_string(),
                    send: Some(MessageDef::new(
                        "hello",
                        vec![FieldDef::new(
                            "data",
                            FieldType::Blob {
                                data: b"HELLO".to_vec(),
                            },
                            true,
                        )],
                    )),
                    expect: None,
                }],
            },
        );
        // "done" is a terminal state (no transitions)
        states.insert(
            "done".to_string(),
            ProtocolState {
                name: "done".to_string(),
                transitions: vec![],
            },
        );
        ProtocolDef::new("start", states)
    }

    // ── FieldType / FieldDef ──────────────────────────────────────────────────

    #[test]
    fn field_type_static_serialise() {
        let ft = FieldType::Static(vec![1, 2, 3]);
        let bytes = serialise_field(&ft, None).unwrap();
        assert_eq!(bytes, vec![1, 2, 3]);
    }

    #[test]
    fn field_type_integer_serialise() {
        let ft = FieldType::Integer {
            size: 4,
            signed: false,
            value: 42,
        };
        let bytes = serialise_field(&ft, None).unwrap();
        assert_eq!(bytes, 42u32.to_le_bytes().to_vec());
    }

    #[test]
    fn field_type_blob_serialise() {
        let ft = FieldType::Blob {
            data: b"test".to_vec(),
        };
        let bytes = serialise_field(&ft, None).unwrap();
        assert_eq!(bytes, b"test");
    }

    #[test]
    fn message_def_serialise() {
        let msg = MessageDef::new(
            "ping",
            vec![
                FieldDef::new("hdr", FieldType::Static(b"PING".to_vec()), false),
                FieldDef::new(
                    "val",
                    FieldType::Integer {
                        size: 1,
                        signed: false,
                        value: 0x42,
                    },
                    true,
                ),
            ],
        );
        let bytes = msg.serialise().unwrap();
        assert!(bytes.starts_with(b"PING"));
        assert_eq!(bytes[4], 0x42);
    }

    #[test]
    fn message_def_size_of() {
        let msg = MessageDef::new(
            "framed",
            vec![
                FieldDef::new(
                    "len",
                    FieldType::SizeOf {
                        field: "body".to_string(),
                    },
                    false,
                ),
                FieldDef::new(
                    "body",
                    FieldType::Blob {
                        data: b"hello".to_vec(),
                    },
                    false,
                ),
            ],
        );
        let bytes = msg.serialise().unwrap();
        // First 8 bytes are the length (u64 LE) of "body" = 5
        let len = u64::from_le_bytes(bytes[..8].try_into().unwrap());
        assert_eq!(len, 5);
    }

    #[test]
    fn message_def_size_of_missing_field() {
        let msg = MessageDef::new(
            "bad",
            vec![FieldDef::new(
                "len",
                FieldType::SizeOf {
                    field: "nonexistent".to_string(),
                },
                false,
            )],
        );
        assert!(msg.serialise().is_err());
    }

    // ── CrashLogger ───────────────────────────────────────────────────────────

    #[test]
    fn crash_logger_new_empty() {
        let logger = CrashLogger::new();
        assert!(logger.is_empty());
    }

    #[test]
    fn crash_logger_log() {
        let mut logger = CrashLogger::new();
        logger.log(vec![1, 2, 3], "disconnected", "start");
        assert_eq!(logger.len(), 1);
        assert_eq!(logger.entries[0].reason, "disconnected");
    }

    #[test]
    fn crash_logger_multiple_entries() {
        let mut logger = CrashLogger::new();
        for i in 0..5u8 {
            logger.log(vec![i], "reason", "state");
        }
        assert_eq!(logger.len(), 5);
    }

    // ── TcpTransport ─────────────────────────────────────────────────────────

    #[tokio::test]
    async fn tcp_transport_connect() {
        let mut t = TcpTransport::new("127.0.0.1:9999");
        assert!(!t.is_connected());
        t.connect().await.unwrap();
        assert!(t.is_connected());
    }

    #[tokio::test]
    async fn tcp_transport_send_when_disconnected() {
        let mut t = TcpTransport::new("127.0.0.1:9999");
        assert!(t.send(b"hello").await.is_err());
    }

    #[tokio::test]
    async fn tcp_transport_disconnect() {
        let mut t = TcpTransport::new("127.0.0.1:9999");
        t.connect().await.unwrap();
        t.disconnect().await.unwrap();
        assert!(!t.is_connected());
    }

    // ── UdpTransport ─────────────────────────────────────────────────────────

    #[tokio::test]
    async fn udp_transport_connect() {
        let mut t = UdpTransport::new("127.0.0.1:9999");
        t.connect().await.unwrap();
        assert!(t.is_connected());
    }

    #[tokio::test]
    async fn udp_transport_send_ok() {
        let mut t = UdpTransport::new("127.0.0.1:9999");
        t.connect().await.unwrap();
        assert!(t.send(b"data").await.is_ok());
    }

    // ── FuzzSession ───────────────────────────────────────────────────────────

    #[tokio::test]
    async fn fuzz_session_run_once_ok() {
        let proto = simple_protocol();
        let transport = Box::new(MockTransport::always_ok());
        let mut session = FuzzSession::new(proto, transport);
        session.run_once().await.unwrap();
        assert_eq!(session.iterations, 1);
    }

    #[tokio::test]
    async fn fuzz_session_run_multiple() {
        let proto = simple_protocol();
        let transport = Box::new(MockTransport::always_ok());
        let mut session = FuzzSession::new(proto, transport);
        session.run(3).await.unwrap();
        assert_eq!(session.iterations, 3);
    }

    #[tokio::test]
    async fn fuzz_session_logs_disconnect_crash() {
        let proto = simple_protocol();
        let transport = Box::new(MockTransport::crash_on_send(1));
        let mut session = FuzzSession::new(proto, transport);
        session.run_once().await.unwrap();
        assert!(!session.crash_logger.is_empty());
    }

    // ── ProtocolFuzzer ────────────────────────────────────────────────────────

    #[tokio::test]
    async fn protocol_fuzzer_fuzz() {
        let proto = simple_protocol();
        let transport = Box::new(MockTransport::always_ok());
        let mut fuzzer = ProtocolFuzzer::new(proto, transport);
        fuzzer.fuzz(5).await.unwrap();
        assert_eq!(fuzzer.session.iterations, 5);
    }

    // ── ProtocolBuilder ───────────────────────────────────────────────────────

    #[test]
    fn protocol_builder_basic() {
        let proto = ProtocolBuilder::new("start")
            .add_terminal("done")
            .add_transition("start", "done", None)
            .build();
        assert!(proto.validate().is_empty());
        assert_eq!(proto.state_count(), 2);
    }

    #[test]
    fn protocol_builder_validate_detects_missing_state() {
        let proto = ProtocolBuilder::new("start").build();
        // Manually add a broken transition via direct ProtocolDef construction
        let mut states = proto.states;
        states
            .get_mut("start")
            .unwrap()
            .transitions
            .push(Transition {
                to_state: "ghost".to_string(),
                send: None,
                expect: None,
            });
        let proto2 = ProtocolDef::new("start", states);
        let errors = proto2.validate();
        assert!(!errors.is_empty());
    }

    #[test]
    fn protocol_builder_edges() {
        let proto = ProtocolBuilder::new("a")
            .add_transition("a", "b", None)
            .add_transition("b", "c", None)
            .add_terminal("c")
            .build();
        let edges = proto.edges();
        assert_eq!(edges.len(), 2);
    }

    // ── MessageBuilder ────────────────────────────────────────────────────────

    #[test]
    fn message_builder_builds_correctly() {
        let msg = MessageBuilder::new("test")
            .static_bytes("magic", b"RUST".to_vec())
            .fuzz_u8("cmd", 0x01)
            .size_of("len", "body")
            .fuzz_blob("body", b"payload".to_vec())
            .build();
        assert_eq!(msg.fields.len(), 4);
        assert_eq!(msg.fuzz_field_count(), 2);
        let serialised = msg.serialise().unwrap();
        assert!(serialised.starts_with(b"RUST"));
    }

    #[test]
    fn message_builder_fuzz_random_field() {
        let msg = MessageBuilder::new("rand_msg")
            .fuzz_random("blob", 4, 16)
            .build();
        assert_eq!(msg.fuzz_field_count(), 1);
    }

    #[test]
    fn message_builder_fuzz_string_field() {
        let msg = MessageBuilder::new("str_msg")
            .fuzz_string("str", 32)
            .build();
        let serialised = msg.serialise().unwrap();
        assert_eq!(serialised.len(), 32);
    }

    // ── CrashLogger extras ────────────────────────────────────────────────────

    #[test]
    fn crash_logger_by_reason() {
        let mut logger = CrashLogger::new();
        logger.log(b"a".to_vec(), "timeout", "start");
        logger.log(b"b".to_vec(), "disconnected", "start");
        logger.log(b"c".to_vec(), "timeout", "done");
        assert_eq!(logger.by_reason("timeout").len(), 2);
        assert_eq!(logger.by_reason("disconnected").len(), 1);
    }

    #[test]
    fn crash_logger_by_state() {
        let mut logger = CrashLogger::new();
        logger.log(b"a".to_vec(), "x", "alpha");
        logger.log(b"b".to_vec(), "y", "beta");
        logger.log(b"c".to_vec(), "z", "alpha");
        assert_eq!(logger.by_state("alpha").len(), 2);
    }

    #[test]
    fn crash_logger_dedup() {
        let mut logger = CrashLogger::new();
        logger.log(b"a".to_vec(), "timeout", "start");
        logger.log(b"b".to_vec(), "timeout", "start");
        logger.log(b"c".to_vec(), "disconnected", "start");
        logger.dedup();
        assert_eq!(logger.len(), 2);
    }

    #[test]
    fn crash_logger_clear() {
        let mut logger = CrashLogger::new();
        logger.log(b"x".to_vec(), "r", "s");
        logger.clear();
        assert!(logger.is_empty());
    }

    #[test]
    fn crash_logger_summary() {
        let mut logger = CrashLogger::new();
        logger.log(b"a".to_vec(), "t", "start");
        logger.log(b"b".to_vec(), "t", "start");
        logger.log(b"c".to_vec(), "t", "done");
        let s = logger.summary();
        assert!(s.contains("start:2"));
        assert!(s.contains("done:1"));
    }

    #[test]
    fn crash_logger_unique_reasons() {
        let mut logger = CrashLogger::new();
        logger.log(vec![], "timeout", "s");
        logger.log(vec![], "timeout", "s");
        logger.log(vec![], "disconnected", "s");
        let reasons = logger.unique_reasons();
        assert_eq!(reasons.len(), 2);
    }

    // ── ResponseMatcher ───────────────────────────────────────────────────────

    #[test]
    fn response_matcher_matches_present() {
        let m = ResponseMatcher::new(b"OK".to_vec());
        assert!(m.matches(b"HTTP/1.1 200 OK\r\n"));
    }

    #[test]
    fn response_matcher_no_match() {
        let m = ResponseMatcher::new(b"ERR".to_vec());
        assert!(!m.matches(b"HTTP/1.1 200 OK\r\n"));
    }

    #[test]
    fn response_matcher_empty_pattern() {
        let m = ResponseMatcher::new(vec![]);
        assert!(m.matches(b"anything"));
    }

    #[test]
    fn response_matcher_find() {
        let m = ResponseMatcher::new(b"CD".to_vec());
        assert_eq!(m.find(b"ABCDE"), Some(2));
    }

    // ── Framing helpers ───────────────────────────────────────────────────────

    #[test]
    fn frame_u32_le_round_trip() {
        let payload = b"hello world";
        let framed = frame_u32_le(payload).unwrap();
        let (consumed, decoded) = decode_frame_u32_le(&framed).unwrap();
        assert_eq!(consumed, framed.len());
        assert_eq!(decoded, payload);
    }

    #[test]
    fn frame_u32_be_round_trip() {
        let payload = b"test data";
        let framed = frame_u32_be(payload).unwrap();
        let (consumed, decoded) = decode_frame_u32_be(&framed).unwrap();
        assert_eq!(consumed, framed.len());
        assert_eq!(decoded, payload);
    }

    #[test]
    fn decode_frame_too_short_returns_none() {
        assert!(decode_frame_u32_le(b"AB").is_none());
    }

    #[test]
    fn decode_frame_incomplete_payload() {
        // 4-byte header says length 100, but only 5 bytes of payload follow
        let mut buf = 100u32.to_le_bytes().to_vec();
        buf.extend_from_slice(b"HELLO");
        assert!(decode_frame_u32_le(&buf).is_none());
    }

    #[test]
    fn xor_checksum_basic() {
        assert_eq!(xor_checksum(b"\x01\x02\x03"), 0x01 ^ 0x02 ^ 0x03);
    }

    #[test]
    fn add_checksum_basic() {
        assert_eq!(add_checksum(b"\x01\x02\x03"), 0x06);
    }

    // ── CoverageMap ───────────────────────────────────────────────────────────

    #[test]
    fn coverage_map_records_unique() {
        let mut cov = CoverageMap::new();
        cov.record("start", 0);
        cov.record("start", 0); // duplicate
        cov.record("start", 1);
        assert_eq!(cov.covered(), 2);
    }

    #[test]
    fn coverage_map_pct() {
        let mut cov = CoverageMap::new();
        cov.record("a", 0);
        cov.record("a", 1);
        assert!((cov.coverage_pct(4) - 50.0).abs() < 0.001);
    }

    #[test]
    fn coverage_map_is_covered() {
        let mut cov = CoverageMap::new();
        cov.record("s", 3);
        assert!(cov.is_covered("s", 3));
        assert!(!cov.is_covered("s", 4));
    }

    // ── FuzzCorpus ────────────────────────────────────────────────────────────

    #[test]
    fn corpus_add_and_len() {
        let mut corpus = FuzzCorpus::new();
        corpus.add(b"abc".to_vec(), "crash", "start");
        assert_eq!(corpus.len(), 1);
    }

    #[test]
    fn corpus_dedup() {
        let mut corpus = FuzzCorpus::new();
        corpus.add(b"abc".to_vec(), "crash", "start");
        corpus.add(b"abc".to_vec(), "timeout", "done");
        corpus.dedup();
        assert_eq!(corpus.len(), 1);
    }

    #[test]
    fn corpus_by_tag() {
        let mut corpus = FuzzCorpus::new();
        corpus.add(b"a".to_vec(), "crash", "s");
        corpus.add(b"b".to_vec(), "timeout", "s");
        corpus.add(b"c".to_vec(), "crash", "s");
        assert_eq!(corpus.by_tag("crash").len(), 2);
    }

    // ── MutationHistory ───────────────────────────────────────────────────────

    #[test]
    fn mutation_history_push_pop() {
        let msg = MessageBuilder::new("m").fuzz_u8("v", 0).build();
        let mut hist = MutationHistory::new(3);
        hist.push(&msg);
        assert_eq!(hist.depth(), 1);
        let popped = hist.pop().unwrap();
        assert_eq!(popped.name, "m");
        assert_eq!(hist.depth(), 0);
    }

    #[test]
    fn mutation_history_max_depth_evicts_oldest() {
        let msg = MessageBuilder::new("m").fuzz_u8("v", 0).build();
        let mut hist = MutationHistory::new(2);
        hist.push(&msg);
        hist.push(&msg);
        hist.push(&msg); // should evict oldest
        assert_eq!(hist.depth(), 2);
    }

    // ── SessionStats ──────────────────────────────────────────────────────────

    #[test]
    fn session_stats_avg_bytes() {
        let stats = SessionStats {
            iterations: 4,
            total_bytes_sent: 100,
            crash_count: 0,
            state_visit_counts: HashMap::new(),
        };
        assert_eq!(stats.avg_bytes_per_iter(), 25);
    }

    #[test]
    fn session_stats_most_visited_state() {
        let mut counts = HashMap::new();
        counts.insert("alpha".to_string(), 5u64);
        counts.insert("beta".to_string(), 10u64);
        let stats = SessionStats {
            iterations: 1,
            total_bytes_sent: 0,
            crash_count: 0,
            state_visit_counts: counts,
        };
        assert_eq!(stats.most_visited_state(), Some("beta"));
    }

    // ── MutationStrategy ─────────────────────────────────────────────────────

    #[test]
    fn apply_strategy_all_fields_changes_fuzz_fields() {
        let mut msg = MessageBuilder::new("m")
            .static_bytes("hdr", b"HDR".to_vec())
            .fuzz_blob("body", b"AAAA".to_vec())
            .build();
        let mut rng = XorShiftRng::default();
        apply_strategy(&mut msg, MutationStrategy::AllFields, &mut rng);
        // Static field should be unchanged
        assert_eq!(msg.fields[0].field_type, FieldType::Static(b"HDR".to_vec()));
    }

    #[test]
    fn apply_strategy_single_field_runs_without_panic() {
        let mut msg = MessageBuilder::new("m").fuzz_u32("val", 0xdeadbeef).build();
        let mut rng = XorShiftRng::default();
        apply_strategy(&mut msg, MutationStrategy::SingleField, &mut rng);
    }

    #[test]
    fn apply_strategy_bit_flip_produces_blob() {
        let mut msg = MessageBuilder::new("m")
            .fuzz_blob("data", vec![0xaa; 8])
            .build();
        let mut rng = XorShiftRng::default();
        apply_strategy(&mut msg, MutationStrategy::BitFlip, &mut rng);
        // After bit flip the field should be a Blob
        assert!(matches!(msg.fields[0].field_type, FieldType::Blob { .. }));
    }

    #[test]
    fn apply_strategy_boundary_produces_blob() {
        let mut msg = MessageBuilder::new("m")
            .fuzz_blob("data", vec![0x55; 4])
            .build();
        let mut rng = XorShiftRng::default();
        apply_strategy(&mut msg, MutationStrategy::BoundaryValues, &mut rng);
        if let FieldType::Blob { data } = &msg.fields[0].field_type {
            // All bytes should be the same boundary value
            assert!(data.iter().all(|&b| b == 0x00 || b == 0xff));
        } else {
            panic!("expected Blob");
        }
    }

    // ── interesting_int_mutation ──────────────────────────────────────────────

    #[test]
    fn interesting_int_mutation_u8_range() {
        let mut rng = XorShiftRng::default();
        for _ in 0..64 {
            let v = interesting_int_mutation(50, 1, &mut rng);
            // Should fit in i8/u8 range when picking from interesting table
            let _ = v; // just must not panic
        }
    }

    // ── ReplaySession ─────────────────────────────────────────────────────────

    #[tokio::test]
    async fn replay_session_all_succeed() {
        let inputs = vec![b"test1".to_vec(), b"test2".to_vec()];
        let transport = Box::new(MockTransport::always_ok());
        let mut replay = ReplaySession::new(inputs, transport);
        let result = replay.run().await.unwrap();
        assert_eq!(result.successes, 2);
        assert!(result.failures.is_empty());
    }

    #[tokio::test]
    async fn replay_session_records_failures() {
        let inputs = vec![b"a".to_vec(), b"b".to_vec(), b"c".to_vec()];
        let transport = Box::new(MockTransport::crash_on_send(2));
        let mut replay = ReplaySession::new(inputs, transport);
        let result = replay.run().await.unwrap();
        assert!(!result.failures.is_empty());
    }

    // ── FuzzSession stats ─────────────────────────────────────────────────────

    #[tokio::test]
    async fn fuzz_session_stats_bytes_sent() {
        let proto = simple_protocol();
        let transport = Box::new(MockTransport::always_ok());
        let mut session = FuzzSession::new(proto, transport);
        session.run(2).await.unwrap();
        // Each iteration sends a blob derived from "HELLO" (5 bytes, possibly mutated)
        assert!(session.total_bytes_sent > 0);
    }

    #[tokio::test]
    async fn fuzz_session_tracks_state_visits() {
        let proto = simple_protocol();
        let transport = Box::new(MockTransport::always_ok());
        let mut session = FuzzSession::new(proto, transport);
        session.run(3).await.unwrap();
        assert!(session.state_visit_counts.contains_key("start"));
    }
}

// ── ProtocolDef YAML loading ──────────────────────────────────────────────────

/// Minimal YAML value type — enough to parse protocol definitions without an
/// external YAML library.  Supports maps, sequences, and scalar strings.
#[derive(Debug, Clone)]
enum YamlValue {
    Scalar(String),
    Sequence(Vec<Self>),
    Mapping(Vec<(String, Self)>),
}

impl YamlValue {
    const fn as_str(&self) -> Option<&str> {
        match self {
            Self::Scalar(s) => Some(s.as_str()),
            _ => None,
        }
    }

    const fn as_sequence(&self) -> Option<&Vec<Self>> {
        match self {
            Self::Sequence(v) => Some(v),
            _ => None,
        }
    }

    const fn as_mapping(&self) -> Option<&Vec<(String, Self)>> {
        match self {
            Self::Mapping(m) => Some(m),
            _ => None,
        }
    }

    fn get(&self, key: &str) -> Option<&Self> {
        self.as_mapping()?
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v)
    }
}

/// Parse a very small subset of YAML (no anchors, no multi-line literals).
/// Supports:
/// - Top-level and nested mappings (`key: value`)
/// - Sequences (`- item`)
/// - Scalar strings (quoted or bare)
fn parse_yaml_simple(yaml: &str) -> Result<YamlValue, FuzzNetError> {
    let lines: Vec<&str> = yaml.lines().collect();
    parse_yaml_lines(&lines, 0).map(|(v, _)| v)
}

fn yaml_indent(line: &str) -> usize {
    line.len() - line.trim_start().len()
}

fn parse_yaml_lines(
    lines: &[&str],
    base_indent: usize,
) -> Result<(YamlValue, usize), FuzzNetError> {
    // Peek at the first non-empty line to determine type.
    let mut i = 0;
    while i < lines.len() {
        let line = lines[i];
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            i += 1;
            continue;
        }
        let indent = yaml_indent(line);
        if indent < base_indent {
            break;
        }

        // Is this a sequence entry?
        if trimmed.starts_with("- ") || trimmed == "-" {
            return parse_yaml_sequence(lines, base_indent);
        }
        // Otherwise parse as a mapping.
        return parse_yaml_mapping(lines, base_indent);
    }
    Ok((YamlValue::Scalar(String::new()), i))
}

fn parse_yaml_sequence(
    lines: &[&str],
    base_indent: usize,
) -> Result<(YamlValue, usize), FuzzNetError> {
    let mut items = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        let line = lines[i];
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            i += 1;
            continue;
        }
        let indent = yaml_indent(line);
        if indent < base_indent {
            break;
        }
        if let Some(__stripped) = trimmed.strip_prefix("- ") {
            let rest = __stripped.trim();
            // The item may be inline scalar or a nested mapping on next lines.
            if rest.is_empty() {
                // Multi-line item; parse the next lines as a mapping.
                let child_indent = base_indent + 2;
                let (child, consumed) = parse_yaml_lines(&lines[i + 1..], child_indent)?;
                items.push(child);
                i += 1 + consumed;
            } else if rest.contains(':') {
                // Inline mapping entry at same line, followed by children.
                let child_indent = indent + 2;
                let colon = rest.find(':').unwrap();
                let key = rest[..colon].trim().to_string();
                let val = rest[colon + 1..].trim();
                let mut mapping = vec![(key, YamlValue::Scalar(yaml_unquote(val)))];
                let (child, consumed) = parse_yaml_lines(&lines[i + 1..], child_indent)?;
                if let YamlValue::Mapping(child_map) = child {
                    mapping.extend(child_map);
                }
                items.push(YamlValue::Mapping(mapping));
                i += 1 + consumed;
            } else {
                items.push(YamlValue::Scalar(yaml_unquote(rest)));
                i += 1;
            }
        } else {
            break;
        }
    }
    Ok((YamlValue::Sequence(items), i))
}

fn parse_yaml_mapping(
    lines: &[&str],
    base_indent: usize,
) -> Result<(YamlValue, usize), FuzzNetError> {
    let mut entries: Vec<(String, YamlValue)> = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        let line = lines[i];
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            i += 1;
            continue;
        }
        let indent = yaml_indent(line);
        if indent < base_indent {
            break;
        }
        if let Some(colon) = trimmed.find(':') {
            let key = trimmed[..colon].trim().to_string();
            let rest = trimmed[colon + 1..].trim();
            if rest.is_empty() {
                // Value is on the following lines (either mapping or sequence).
                i += 1;
                // Find child indent.
                let child_indent = indent + 2;
                let (child, consumed) = parse_yaml_lines(&lines[i..], child_indent)?;
                entries.push((key, child));
                i += consumed;
            } else {
                entries.push((key, YamlValue::Scalar(yaml_unquote(rest))));
                i += 1;
            }
        } else {
            i += 1;
        }
    }
    Ok((YamlValue::Mapping(entries), i))
}

fn yaml_unquote(s: &str) -> String {
    let s = s.trim();
    if (s.starts_with('"') && s.ends_with('"')) || (s.starts_with('\'') && s.ends_with('\'')) {
        s[1..s.len() - 1].to_string()
    } else {
        s.to_string()
    }
}

impl ProtocolDef {
    /// Load a [`ProtocolDef`] from a YAML string.
    ///
    /// Expected format:
    /// ```yaml
    /// initial_state: start
    /// states:
    ///   - name: start
    ///     transitions:
    ///       - to: done
    ///         message: HELLO
    ///   - name: done
    /// ```
    ///
    /// # Errors
    /// Returns [`FuzzNetError::UnknownState`] when the YAML is malformed or
    /// required fields are missing.
    pub fn load_from_yaml(yaml: &str) -> Result<Self, FuzzNetError> {
        let root = parse_yaml_simple(yaml)
            .map_err(|e| FuzzNetError::UnknownState(format!("yaml parse error: {e}")))?;

        let initial_state = root
            .get("initial_state")
            .and_then(|v| v.as_str())
            .unwrap_or("start")
            .to_string();

        let mut states: HashMap<String, ProtocolState> = HashMap::new();

        if let Some(states_val) = root.get("states")
            && let Some(seq) = states_val.as_sequence() {
                for item in seq {
                    let name = item
                        .get("name")
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| {
                            FuzzNetError::UnknownState("state missing 'name' field".to_string())
                        })?
                        .to_string();

                    let mut transitions = Vec::new();
                    if let Some(trans_val) = item.get("transitions")
                        && let Some(trans_seq) = trans_val.as_sequence() {
                            for t in trans_seq {
                                let to_state = t
                                    .get("to")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or(&name)
                                    .to_string();
                                let message =
                                    t.get("message").and_then(|v| v.as_str()).map(|msg| {
                                        MessageDef::new(
                                            "yaml_msg",
                                            vec![FieldDef::new(
                                                "data",
                                                FieldType::Static(msg.as_bytes().to_vec()),
                                                false,
                                            )],
                                        )
                                    });
                                let timeout_ms = t
                                    .get("timeout_ms")
                                    .and_then(|v| v.as_str())
                                    .and_then(|s| s.parse::<u64>().ok())
                                    .unwrap_or(1000);
                                let expect_pattern =
                                    t.get("expect").and_then(|v| v.as_str()).map(|p| {
                                        PatternMatch {
                                            pattern: p.as_bytes().to_vec(),
                                            timeout_ms,
                                        }
                                    });
                                transitions.push(Transition {
                                    to_state,
                                    send: message,
                                    expect: expect_pattern,
                                });
                            }
                        }

                    states.insert(name.clone(), ProtocolState { name, transitions });
                }
            }

        Ok(Self {
            initial_state,
            states,
        })
    }

    /// Load a [`ProtocolDef`] from a YAML file on disk.
    ///
    /// # Errors
    /// Returns [`FuzzNetError::Async`] on I/O error, or propagates YAML parse
    /// errors from [`Self::load_from_yaml`].
    pub fn load_from_file(path: &std::path::Path) -> Result<Self, FuzzNetError> {
        let yaml = std::fs::read_to_string(path)
            .map_err(|e| FuzzNetError::Async(format!("read {}: {e}", path.display())))?;
        Self::load_from_yaml(&yaml)
    }
}

// ── StateMachineDriver ────────────────────────────────────────────────────────

/// Drives a [`ProtocolDef`] through its states without a network transport,
/// useful for testing or pre-fuzzing sequence validation.
pub struct StateMachineDriver {
    /// The protocol definition being driven.
    pub protocol: ProtocolDef,
    /// Name of the current state.
    current_state: String,
    /// Ordered history of state names visited (including the initial state).
    transition_history: Vec<String>,
}

impl StateMachineDriver {
    /// Create a new driver starting at the protocol's initial state.
    #[must_use]
    pub fn new(protocol: ProtocolDef) -> Self {
        let initial = protocol.initial_state.clone();
        let history = vec![initial.clone()];
        Self {
            protocol,
            current_state: initial,
            transition_history: history,
        }
    }

    /// Return the name of the current state.
    #[must_use]
    pub fn current_state(&self) -> &str {
        &self.current_state
    }

    /// Return the full ordered slice of states visited so far (including the
    /// starting state).
    #[must_use]
    pub fn transition_history(&self) -> &[String] {
        &self.transition_history
    }

    /// Drive the state machine toward `target`, executing transitions in order
    /// until the current state equals `target` or no outgoing transition leads
    /// toward it.
    ///
    /// This performs a simple BFS-path walk: it first finds the shortest path
    /// from the current state to the target state, then executes each
    /// transition along that path one by one.
    ///
    /// # Errors
    /// Returns [`FuzzNetError::UnknownState`] when `target` is not a valid
    /// state name, or when no path exists from the current state to `target`.
    pub fn drive_to_state(&mut self, target: &str) -> Result<(), FuzzNetError> {
        if !self.protocol.states.contains_key(target) {
            return Err(FuzzNetError::UnknownState(target.to_string()));
        }
        if self.current_state == target {
            return Ok(());
        }

        // BFS to find a path from current_state to target.
        let path = self
            .bfs_path(&self.current_state.clone(), target)
            .ok_or_else(|| {
                FuzzNetError::UnknownState(format!(
                    "no path from '{}' to '{target}'",
                    self.current_state
                ))
            })?;

        // Walk the path (path[0] is current_state, already visited).
        for next in path.into_iter().skip(1) {
            self.current_state.clone_from(&next);
            self.transition_history.push(next);
        }
        Ok(())
    }

    /// Reset the driver to the protocol's initial state, clearing history.
    pub fn reset(&mut self) {
        self.current_state.clone_from(&self.protocol.initial_state);
        self.transition_history.clear();
        self.transition_history.push(self.current_state.clone());
    }

    /// Return whether there is at least one outgoing transition from the
    /// current state.
    #[must_use]
    pub fn can_advance(&self) -> bool {
        self.protocol
            .states
            .get(&self.current_state)
            .is_some_and(|s| !s.transitions.is_empty())
    }

    /// BFS over the state graph, returning the shortest path from `start` to
    /// `goal` as a `Vec<String>`, or `None` if unreachable.
    fn bfs_path(&self, start: &str, goal: &str) -> Option<Vec<String>> {
        use std::collections::VecDeque;
        let mut queue: VecDeque<Vec<String>> = VecDeque::new();
        queue.push_back(vec![start.to_string()]);
        let mut visited = std::collections::HashSet::new();
        visited.insert(start.to_string());

        while let Some(path) = queue.pop_front() {
            let last = path.last().unwrap();
            if last == goal {
                return Some(path);
            }
            if let Some(state) = self.protocol.states.get(last) {
                for t in &state.transitions {
                    if visited.insert(t.to_state.clone()) {
                        let mut new_path = path.clone();
                        new_path.push(t.to_state.clone());
                        queue.push_back(new_path);
                    }
                }
            }
        }
        None
    }
}

// ── FuzzCrashClassifier ───────────────────────────────────────────────────────

/// Classification of a response received from a fuzz target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CrashKind {
    /// The target closed the connection.
    Disconnect,
    /// The target did not respond within the expected window.
    Timeout,
    /// The target replied but the response was not what the protocol expects.
    UnexpectedResponse,
    /// The target replied with a well-formed but semantically incorrect
    /// protocol message (e.g. a protocol-level error code).
    ProtocolError,
    /// The target replied correctly — no anomaly detected.
    Success,
}

impl CrashKind {
    /// Human-readable label.
    #[must_use]
    pub const fn label(&self) -> &'static str {
        match self {
            Self::Disconnect => "DISCONNECT",
            Self::Timeout => "TIMEOUT",
            Self::UnexpectedResponse => "UNEXPECTED_RESPONSE",
            Self::ProtocolError => "PROTOCOL_ERROR",
            Self::Success => "SUCCESS",
        }
    }
}

/// Classifier that compares a received response to an expected byte pattern
/// and returns the appropriate [`CrashKind`].
pub struct FuzzCrashClassifier;

impl FuzzCrashClassifier {
    /// Classify the result of a single fuzz iteration.
    ///
    /// Rules applied in order:
    /// 1. Empty response → [`CrashKind::Disconnect`].
    /// 2. `response` starts with a known error prefix (e.g. `ERR`, `500`) → [`CrashKind::ProtocolError`].
    /// 3. `response` contains `expected` as a subsequence → [`CrashKind::Success`].
    /// 4. `response` is non-empty but does not contain `expected` → [`CrashKind::UnexpectedResponse`].
    #[must_use]
    pub fn classify(response: &[u8], expected: &[u8]) -> CrashKind {
        if response.is_empty() {
            return CrashKind::Disconnect;
        }
        // Check for protocol-level error indicators.
        if Self::looks_like_protocol_error(response) {
            return CrashKind::ProtocolError;
        }
        // Check whether the expected pattern appears in the response.
        if expected.is_empty() || Self::contains(response, expected) {
            CrashKind::Success
        } else {
            CrashKind::UnexpectedResponse
        }
    }

    /// Classify using only a transport-level outcome string (for integration
    /// with [`CrashLogger`] entries).
    #[must_use]
    pub fn classify_reason(reason: &str) -> CrashKind {
        match reason {
            r if r.contains("disconnect") || r.contains("Disconnected") => CrashKind::Disconnect,
            r if r.contains("timeout") || r.contains("Timeout") => CrashKind::Timeout,
            r if r.contains("protocol") => CrashKind::ProtocolError,
            "success" | "ok" | "OK" => CrashKind::Success,
            _ => CrashKind::UnexpectedResponse,
        }
    }

    /// Returns `true` when `kind` is worth storing in the crash corpus (i.e.
    /// anything other than [`CrashKind::Success`]).
    #[must_use]
    pub fn is_interesting(kind: CrashKind) -> bool {
        kind != CrashKind::Success
    }

    /// Returns `true` when `kind` represents a target crash (Disconnect or
    /// Timeout) rather than a benign anomaly.
    #[must_use]
    pub const fn is_crash(kind: CrashKind) -> bool {
        matches!(kind, CrashKind::Disconnect | CrashKind::Timeout)
    }

    // ── private helpers ──────────────────────────────────────────────────────

    /// Heuristic: does the response look like a protocol-level error?
    fn looks_like_protocol_error(response: &[u8]) -> bool {
        // HTTP 4xx / 5xx status codes
        if response.len() >= 12
            && response.starts_with(b"HTTP/") {
                let code_start = response.iter().position(|&b| b == b' ').unwrap_or(0).saturating_add(1);
                if response.len() > code_start + 3 {
                    let code = &response[code_start..code_start + 3];
                    if code[0] >= b'4' && code[0] <= b'5' {
                        return true;
                    }
                }
            }
        // Common error prefixes
        let error_prefixes: &[&[u8]] = &[
            b"ERR ", b"ERROR", b"500 ", b"501 ", b"-ERR", b"FAIL", b"NACK",
        ];
        for prefix in error_prefixes {
            if response.starts_with(prefix) {
                return true;
            }
        }
        false
    }

    /// Returns `true` if `haystack` contains `needle` as a contiguous slice.
    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        if needle.is_empty() {
            return true;
        }
        if needle.len() > haystack.len() {
            return false;
        }
        haystack.windows(needle.len()).any(|w| w == needle)
    }
}

// ── Additional tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod extended_tests {
    use super::*;

    // ── ProtocolDef::load_from_yaml ───────────────────────────────────────────

    const SIMPLE_YAML: &str = r"
initial_state: start
states:
  - name: start
    transitions:
      - to: done
        message: HELLO
  - name: done
";

    #[test]
    fn yaml_load_initial_state() {
        let proto = ProtocolDef::load_from_yaml(SIMPLE_YAML).unwrap();
        assert_eq!(proto.initial_state, "start");
    }

    #[test]
    fn yaml_load_state_count() {
        let proto = ProtocolDef::load_from_yaml(SIMPLE_YAML).unwrap();
        assert_eq!(proto.state_count(), 2);
    }

    #[test]
    fn yaml_load_state_names_correct() {
        let proto = ProtocolDef::load_from_yaml(SIMPLE_YAML).unwrap();
        let names = proto.state_names();
        assert!(names.contains(&"start"));
        assert!(names.contains(&"done"));
    }

    #[test]
    fn yaml_load_transition_present() {
        let proto = ProtocolDef::load_from_yaml(SIMPLE_YAML).unwrap();
        let start = proto.states.get("start").unwrap();
        assert_eq!(start.transitions.len(), 1);
        assert_eq!(start.transitions[0].to_state, "done");
    }

    #[test]
    fn yaml_load_message_bytes_correct() {
        let proto = ProtocolDef::load_from_yaml(SIMPLE_YAML).unwrap();
        let start = proto.states.get("start").unwrap();
        let msg = start.transitions[0].send.as_ref().unwrap();
        let bytes = msg.serialise().unwrap();
        assert_eq!(bytes, b"HELLO");
    }

    #[test]
    fn yaml_load_validates_successfully() {
        let proto = ProtocolDef::load_from_yaml(SIMPLE_YAML).unwrap();
        assert!(proto.validate().is_empty());
    }

    #[test]
    fn yaml_load_with_expect_field() {
        let yaml = r#"
initial_state: auth
states:
  - name: auth
    transitions:
      - to: ready
        message: "USER admin"
        expect: "+OK"
        timeout_ms: 2000
  - name: ready
"#;
        let proto = ProtocolDef::load_from_yaml(yaml).unwrap();
        let auth = proto.states.get("auth").unwrap();
        let expect = auth.transitions[0].expect.as_ref().unwrap();
        assert_eq!(expect.pattern, b"+OK");
        assert_eq!(expect.timeout_ms, 2000);
    }

    #[test]
    fn yaml_load_no_transitions_state_is_terminal() {
        let proto = ProtocolDef::load_from_yaml(SIMPLE_YAML).unwrap();
        let done = proto.states.get("done").unwrap();
        assert!(done.transitions.is_empty());
    }

    #[test]
    fn yaml_load_multi_state_chain() {
        let yaml = r"
initial_state: a
states:
  - name: a
    transitions:
      - to: b
  - name: b
    transitions:
      - to: c
  - name: c
";
        let proto = ProtocolDef::load_from_yaml(yaml).unwrap();
        assert_eq!(proto.state_count(), 3);
        assert!(proto.validate().is_empty());
    }

    // ── StateMachineDriver ────────────────────────────────────────────────────

    fn three_state_proto() -> ProtocolDef {
        ProtocolBuilder::new("a")
            .add_transition("a", "b", None)
            .add_transition("b", "c", None)
            .add_terminal("c")
            .build()
    }

    #[test]
    fn driver_initial_state_matches_protocol() {
        let proto = three_state_proto();
        let driver = StateMachineDriver::new(proto.clone());
        assert_eq!(driver.current_state(), proto.initial_state.as_str());
    }

    #[test]
    fn driver_history_starts_with_initial() {
        let proto = three_state_proto();
        let driver = StateMachineDriver::new(proto);
        assert_eq!(driver.transition_history(), &["a".to_string()]);
    }

    #[test]
    fn driver_drive_to_adjacent_state() {
        let proto = three_state_proto();
        let mut driver = StateMachineDriver::new(proto);
        driver.drive_to_state("b").unwrap();
        assert_eq!(driver.current_state(), "b");
    }

    #[test]
    fn driver_drive_to_non_adjacent_state() {
        let proto = three_state_proto();
        let mut driver = StateMachineDriver::new(proto);
        driver.drive_to_state("c").unwrap();
        assert_eq!(driver.current_state(), "c");
    }

    #[test]
    fn driver_history_records_path() {
        let proto = three_state_proto();
        let mut driver = StateMachineDriver::new(proto);
        driver.drive_to_state("c").unwrap();
        let h = driver.transition_history();
        assert!(h.contains(&"a".to_string()));
        assert!(h.contains(&"b".to_string()));
        assert!(h.contains(&"c".to_string()));
    }

    #[test]
    fn driver_drive_to_current_state_is_noop() {
        let proto = three_state_proto();
        let mut driver = StateMachineDriver::new(proto);
        driver.drive_to_state("a").unwrap();
        assert_eq!(driver.current_state(), "a");
    }

    #[test]
    fn driver_drive_to_unknown_state_errors() {
        let proto = three_state_proto();
        let mut driver = StateMachineDriver::new(proto);
        let result = driver.drive_to_state("ghost");
        assert!(result.is_err());
    }

    #[test]
    fn driver_drive_to_unreachable_state_errors() {
        // Create a disconnected graph: "a→b" and isolated "c"
        let proto = ProtocolBuilder::new("a")
            .add_transition("a", "b", None)
            .add_terminal("b")
            .add_terminal("c")
            .build();
        let mut driver = StateMachineDriver::new(proto);
        let result = driver.drive_to_state("c");
        assert!(result.is_err(), "c is unreachable from a");
    }

    #[test]
    fn driver_reset_returns_to_initial() {
        let proto = three_state_proto();
        let mut driver = StateMachineDriver::new(proto);
        driver.drive_to_state("c").unwrap();
        driver.reset();
        assert_eq!(driver.current_state(), "a");
        assert_eq!(driver.transition_history(), &["a".to_string()]);
    }

    #[test]
    fn driver_can_advance_from_non_terminal() {
        let proto = three_state_proto();
        let driver = StateMachineDriver::new(proto);
        assert!(driver.can_advance());
    }

    #[test]
    fn driver_cannot_advance_from_terminal() {
        let proto = three_state_proto();
        let mut driver = StateMachineDriver::new(proto);
        driver.drive_to_state("c").unwrap();
        assert!(!driver.can_advance());
    }

    // ── FuzzCrashClassifier ───────────────────────────────────────────────────

    #[test]
    fn classifier_empty_response_is_disconnect() {
        assert_eq!(
            FuzzCrashClassifier::classify(&[], b"+OK"),
            CrashKind::Disconnect
        );
    }

    #[test]
    fn classifier_matching_response_is_success() {
        assert_eq!(
            FuzzCrashClassifier::classify(b"+OK ready", b"+OK"),
            CrashKind::Success
        );
    }

    #[test]
    fn classifier_non_matching_response_is_unexpected() {
        assert_eq!(
            FuzzCrashClassifier::classify(b"garbage data", b"+OK"),
            CrashKind::UnexpectedResponse
        );
    }

    #[test]
    fn classifier_error_prefix_is_protocol_error() {
        assert_eq!(
            FuzzCrashClassifier::classify(b"ERR invalid command", b"+OK"),
            CrashKind::ProtocolError
        );
    }

    #[test]
    fn classifier_http_5xx_is_protocol_error() {
        assert_eq!(
            FuzzCrashClassifier::classify(b"HTTP/1.1 500 Internal Server Error", b"200"),
            CrashKind::ProtocolError
        );
    }

    #[test]
    fn classifier_http_4xx_is_protocol_error() {
        assert_eq!(
            FuzzCrashClassifier::classify(b"HTTP/1.1 404 Not Found", b"200"),
            CrashKind::ProtocolError
        );
    }

    #[test]
    fn classifier_empty_expected_any_response_is_success() {
        assert_eq!(
            FuzzCrashClassifier::classify(b"anything at all", &[]),
            CrashKind::Success
        );
    }

    #[test]
    fn classifier_nack_prefix_is_protocol_error() {
        assert_eq!(
            FuzzCrashClassifier::classify(b"NACK bad frame", b"ACK"),
            CrashKind::ProtocolError
        );
    }

    #[test]
    fn classifier_classify_reason_disconnect() {
        assert_eq!(
            FuzzCrashClassifier::classify_reason("disconnected"),
            CrashKind::Disconnect
        );
    }

    #[test]
    fn classifier_classify_reason_timeout() {
        assert_eq!(
            FuzzCrashClassifier::classify_reason("timeout"),
            CrashKind::Timeout
        );
    }

    #[test]
    fn classifier_classify_reason_unknown_is_unexpected() {
        assert_eq!(
            FuzzCrashClassifier::classify_reason("something weird happened"),
            CrashKind::UnexpectedResponse
        );
    }

    #[test]
    fn classifier_is_interesting_not_success() {
        assert!(FuzzCrashClassifier::is_interesting(CrashKind::Disconnect));
        assert!(FuzzCrashClassifier::is_interesting(CrashKind::Timeout));
        assert!(FuzzCrashClassifier::is_interesting(
            CrashKind::UnexpectedResponse
        ));
        assert!(FuzzCrashClassifier::is_interesting(
            CrashKind::ProtocolError
        ));
    }

    #[test]
    fn classifier_is_interesting_success_is_false() {
        assert!(!FuzzCrashClassifier::is_interesting(CrashKind::Success));
    }

    #[test]
    fn classifier_is_crash_disconnect_and_timeout() {
        assert!(FuzzCrashClassifier::is_crash(CrashKind::Disconnect));
        assert!(FuzzCrashClassifier::is_crash(CrashKind::Timeout));
        assert!(!FuzzCrashClassifier::is_crash(
            CrashKind::UnexpectedResponse
        ));
        assert!(!FuzzCrashClassifier::is_crash(CrashKind::ProtocolError));
        assert!(!FuzzCrashClassifier::is_crash(CrashKind::Success));
    }

    #[test]
    fn crash_kind_labels_correct() {
        assert_eq!(CrashKind::Disconnect.label(), "DISCONNECT");
        assert_eq!(CrashKind::Timeout.label(), "TIMEOUT");
        assert_eq!(CrashKind::UnexpectedResponse.label(), "UNEXPECTED_RESPONSE");
        assert_eq!(CrashKind::ProtocolError.label(), "PROTOCOL_ERROR");
        assert_eq!(CrashKind::Success.label(), "SUCCESS");
    }

    // ── Integration: yaml load → driver → classifier ──────────────────────────

    #[test]
    fn integration_yaml_to_driver_to_target_state() {
        let yaml = r"
initial_state: init
states:
  - name: init
    transitions:
      - to: auth
  - name: auth
    transitions:
      - to: session
  - name: session
";
        let proto = ProtocolDef::load_from_yaml(yaml).unwrap();
        let mut driver = StateMachineDriver::new(proto);
        driver.drive_to_state("session").unwrap();
        assert_eq!(driver.current_state(), "session");
        assert_eq!(driver.transition_history().len(), 3);
    }

    #[test]
    fn integration_classifier_on_crash_logger_entries() {
        let mut logger = CrashLogger::new();
        logger.log(b"ERR bad cmd".to_vec(), "protocol", "auth");
        logger.log(vec![], "disconnected", "auth");
        logger.log(b"+OK fine".to_vec(), "ok", "session");

        for entry in &logger.entries {
            let kind = FuzzCrashClassifier::classify_reason(&entry.reason);
            if entry.reason == "protocol" {
                assert_eq!(kind, CrashKind::ProtocolError);
            }
            if entry.reason == "disconnected" {
                assert_eq!(kind, CrashKind::Disconnect);
            }
        }
    }
}
