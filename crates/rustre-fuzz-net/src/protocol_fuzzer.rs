//! `protocol_fuzzer` — network protocol fuzzer with state-machine awareness,
//! field-aware mutations, TLS/TCP/UDP targets, and session replay.

use std::collections::HashMap;
use std::time::{Duration, Instant};

pub use crate::FieldDef;
use crate::{FieldType, MessageDef, ProtocolDef, ProtocolState, Transition};
use rustre_fuzz_afl::{RngCore, XorShiftRng};

// ── FuzzTarget ────────────────────────────────────────────────────────────────

/// Transport target type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FuzzTarget {
    /// Plain TCP target (host, port).
    Tcp { host: String, port: u16 },
    /// UDP target (host, port).
    Udp { host: String, port: u16 },
    /// TLS-wrapped TCP target (host, port).
    Tls {
        host: String,
        port: u16,
        verify_peer: bool,
    },
}

impl FuzzTarget {
    /// Create a plain TCP target.
    #[must_use]
    pub fn tcp(host: impl Into<String>, port: u16) -> Self {
        Self::Tcp {
            host: host.into(),
            port,
        }
    }

    /// Create a UDP target.
    #[must_use]
    pub fn udp(host: impl Into<String>, port: u16) -> Self {
        Self::Udp {
            host: host.into(),
            port,
        }
    }

    /// Create a TLS target.
    #[must_use]
    pub fn tls(host: impl Into<String>, port: u16, verify_peer: bool) -> Self {
        Self::Tls {
            host: host.into(),
            port,
            verify_peer,
        }
    }

    /// Human-readable address string.
    #[must_use]
    pub fn address(&self) -> String {
        match self {
            Self::Tcp { host, port } => format!("{host}:{port}"),
            Self::Udp { host, port } => format!("{host}:{port}"),
            Self::Tls { host, port, .. } => format!("{host}:{port}"),
        }
    }

    /// Protocol label string.
    #[must_use]
    pub const fn protocol(&self) -> &'static str {
        match self {
            Self::Tcp { .. } => "tcp",
            Self::Udp { .. } => "udp",
            Self::Tls { .. } => "tls",
        }
    }
}

// ── MessageMutator ────────────────────────────────────────────────────────────

/// Types of field-aware mutations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldMutationKind {
    /// Flip a single random bit.
    BitFlip,
    /// Set a byte to 0x00, 0xff, or a boundary value.
    ByteSet,
    /// Apply a boundary/interesting integer value.
    NumberBoundary,
    /// Inject a format-string payload (`%s`, `%x`, …).
    FormatString,
    /// Corrupt a length field (set to 0, max-u32, etc.).
    LengthManipulation,
    /// Replace or append a protocol delimiter (CRLF, NUL, etc.).
    DelimiterInjection,
}

/// Record of a single mutation applied to a field.
#[derive(Debug, Clone)]
pub struct FieldMutationRecord {
    /// Field name that was mutated.
    pub field_name: String,
    /// Kind of mutation applied.
    pub kind: FieldMutationKind,
    /// Original bytes before mutation.
    pub original: Vec<u8>,
    /// Mutated bytes.
    pub mutated: Vec<u8>,
}

/// Field-aware message mutator that applies semantic mutations.
#[derive(Debug, Clone)]
pub struct MessageMutator {
    /// Enable integer boundary mutations.
    pub enable_boundary: bool,
    /// Enable format-string injections.
    pub enable_format_string: bool,
    /// Enable delimiter injections.
    pub enable_delimiter: bool,
    /// Maximum format-string payload depth.
    pub format_depth: usize,
}

impl Default for MessageMutator {
    fn default() -> Self {
        Self {
            enable_boundary: true,
            enable_format_string: true,
            enable_delimiter: true,
            format_depth: 8,
        }
    }
}

impl MessageMutator {
    /// Create a new mutator with defaults.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Mutate `msg` using `rng` and record what changed.
    pub fn mutate(&self, msg: &mut MessageDef, rng: &mut dyn RngCore) -> Vec<FieldMutationRecord> {
        let mut records = Vec::new();
        for field in &mut msg.fields {
            if !field.fuzz {
                continue;
            }
            let kind = self.choose_kind(rng, &field.field_type);
            let original = field_to_bytes(&field.field_type);
            let new_type = self.apply_mutation(kind, &field.field_type, rng);
            let mutated = field_to_bytes(&new_type);
            records.push(FieldMutationRecord {
                field_name: field.name.clone(),
                kind,
                original,
                mutated,
            });
            field.field_type = new_type;
        }
        records
    }

    /// Mutate a single named field by kind.
    pub fn mutate_field(
        &self,
        msg: &mut MessageDef,
        field_name: &str,
        kind: FieldMutationKind,
        rng: &mut dyn RngCore,
    ) -> Option<FieldMutationRecord> {
        let field = msg.fields.iter_mut().find(|f| f.name == field_name)?;
        let original = field_to_bytes(&field.field_type);
        let new_type = self.apply_mutation(kind, &field.field_type, rng);
        let mutated = field_to_bytes(&new_type);
        let rec = FieldMutationRecord {
            field_name: field_name.to_owned(),
            kind,
            original,
            mutated,
        };
        field.field_type = new_type;
        Some(rec)
    }

    fn choose_kind(&self, rng: &mut dyn RngCore, ft: &FieldType) -> FieldMutationKind {
        let choices: Vec<FieldMutationKind> = {
            let mut v = vec![FieldMutationKind::BitFlip, FieldMutationKind::ByteSet];
            if matches!(ft, FieldType::Integer { .. }) || self.enable_boundary {
                v.push(FieldMutationKind::NumberBoundary);
            }
            if self.enable_format_string {
                v.push(FieldMutationKind::FormatString);
            }
            if self.enable_delimiter {
                v.push(FieldMutationKind::DelimiterInjection);
            }
            if matches!(ft, FieldType::SizeOf { .. }) {
                v.push(FieldMutationKind::LengthManipulation);
            }
            v
        };
        choices[rng.next_usize(choices.len())]
    }

    fn apply_mutation(
        &self,
        kind: FieldMutationKind,
        ft: &FieldType,
        rng: &mut dyn RngCore,
    ) -> FieldType {
        match kind {
            FieldMutationKind::BitFlip => {
                let mut bytes = field_to_bytes(ft);
                if !bytes.is_empty() {
                    let idx = rng.next_usize(bytes.len());
                    bytes[idx] ^= 1 << (rng.next_u32() & 7);
                }
                FieldType::Blob { data: bytes }
            }
            FieldMutationKind::ByteSet => {
                let len = field_estimated_len(ft).max(1);
                let fill: u8 = *[0x00u8, 0xff, 0x7f, 0x80, 0x01, 0xfe]
                    .get(rng.next_usize(6))
                    .unwrap_or(&0);
                FieldType::Blob {
                    data: vec![fill; len],
                }
            }
            FieldMutationKind::NumberBoundary => {
                let interesting: &[u64] = &[
                    0,
                    1,
                    0x7f,
                    0x80,
                    0xff,
                    0x100,
                    0x7fff,
                    0x8000,
                    0xffff,
                    0x1_0000,
                    0x7fff_ffff,
                    0x8000_0000,
                    0xffff_ffff,
                    0x7fff_ffff_ffff_ffff,
                    0xffff_ffff_ffff_ffff,
                ];
                let val = interesting[rng.next_usize(interesting.len())];
                let size = if let FieldType::Integer { size, .. } = ft {
                    *size
                } else {
                    4
                };
                let bytes = val.to_le_bytes()[..size as usize].to_vec();
                FieldType::Blob { data: bytes }
            }
            FieldMutationKind::FormatString => {
                let payloads: &[&[u8]] = &[
                    b"%s%s%s%s%s%s%s%s",
                    b"%x%x%x%x%x%x%x%x",
                    b"%n%n%n%n",
                    b"%.2147483647d",
                    b"%99999999s",
                    b"AAAA%08x%08x%08x%08x",
                    b"%p%p%p%p%p%p",
                    b"${IFS}",
                ];
                let depth = self.format_depth.min(payloads.len());
                let count = rng.next_usize(depth) + 1;
                let mut data = Vec::new();
                for _ in 0..count {
                    data.extend_from_slice(payloads[rng.next_usize(payloads.len())]);
                }
                FieldType::Blob { data }
            }
            FieldMutationKind::LengthManipulation => {
                let vals: &[u64] = &[0, 1, 0xffff, 0xffff_ffff, u64::MAX];
                let val = vals[rng.next_usize(vals.len())];
                FieldType::Blob {
                    data: val.to_le_bytes().to_vec(),
                }
            }
            FieldMutationKind::DelimiterInjection => {
                let delimiters: &[&[u8]] = &[
                    b"\r\n",
                    b"\n",
                    b"\r",
                    b"\x00",
                    b"\xff",
                    b"\r\n\r\n",
                    b"\n\n",
                    b"//",
                    b"/../",
                    b"&&",
                ];
                let orig = field_to_bytes(ft);
                let delim = delimiters[rng.next_usize(delimiters.len())];
                let mut data = orig;
                data.extend_from_slice(delim);
                FieldType::Blob { data }
            }
        }
    }
}

fn field_to_bytes(ft: &FieldType) -> Vec<u8> {
    match ft {
        FieldType::Static(b) | FieldType::Blob { data: b } => b.clone(),
        FieldType::Integer { size, value, .. } => {
            let v = *value as u64;
            match size {
                1 => vec![v as u8],
                2 => (v as u16).to_le_bytes().to_vec(),
                4 => (v as u32).to_le_bytes().to_vec(),
                _ => v.to_le_bytes().to_vec(),
            }
        }
        FieldType::Random { min, .. } => vec![0u8; *min],
        FieldType::String { max_len } => vec![b'A'; *max_len],
        FieldType::SizeOf { .. } => vec![0u8; 8],
    }
}

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

// ── ProtocolStateMachine ──────────────────────────────────────────────────────

/// A state-machine description that can be loaded from YAML/JSON-style maps.
#[derive(Debug, Clone)]
pub struct ProtocolStateMachine {
    /// Protocol definition driving the machine.
    pub protocol: ProtocolDef,
    /// Current state name.
    current: String,
    /// History of visited states (last N).
    history: Vec<String>,
    /// Max history length.
    history_max: usize,
}

impl ProtocolStateMachine {
    /// Create a new state machine from a protocol definition.
    #[must_use]
    pub fn new(protocol: ProtocolDef) -> Self {
        let initial = protocol.initial_state.clone();
        Self {
            protocol,
            current: initial,
            history: Vec::new(),
            history_max: 64,
        }
    }

    /// Reset to the initial state.
    pub fn reset(&mut self) {
        self.current = self.protocol.initial_state.clone();
        self.history.clear();
    }

    /// Current state name.
    #[must_use]
    pub fn current_state(&self) -> &str {
        &self.current
    }

    /// Advance to the given state, recording history.
    pub fn advance(&mut self, to: impl Into<String>) {
        if self.history.len() >= self.history_max {
            self.history.remove(0);
        }
        self.history.push(self.current.clone());
        self.current = to.into();
    }

    /// Return available transitions from the current state.
    #[must_use]
    pub fn available_transitions(&self) -> &[Transition] {
        self.protocol
            .states
            .get(&self.current)
            .map_or(&[], |s| s.transitions.as_slice())
    }

    /// Whether the machine is in a terminal state (no outgoing transitions).
    #[must_use]
    pub fn is_terminal(&self) -> bool {
        self.available_transitions().is_empty()
    }

    /// Pick a random transition using `rng`.
    pub fn pick_transition<'a>(&'a self, rng: &mut dyn RngCore) -> Option<&'a Transition> {
        let t = self.available_transitions();
        if t.is_empty() {
            return None;
        }
        Some(&t[rng.next_usize(t.len())])
    }

    /// State visit history (oldest first).
    #[must_use]
    pub fn history(&self) -> &[String] {
        &self.history
    }

    /// Build a state machine from a simple map of `state → [(to_state, message_name)]`.
    #[must_use]
    pub fn from_edge_map(
        initial: impl Into<String>,
        edges: &[(&str, &str, Option<MessageDef>)],
    ) -> Self {
        let initial = initial.into();
        let mut states: HashMap<String, ProtocolState> = HashMap::new();
        states.entry(initial.clone()).or_insert(ProtocolState {
            name: initial.clone(),
            transitions: Vec::new(),
        });
        for (from, to, msg) in edges {
            states.entry(from.to_string()).or_insert(ProtocolState {
                name: from.to_string(),
                transitions: Vec::new(),
            });
            states.entry(to.to_string()).or_insert(ProtocolState {
                name: to.to_string(),
                transitions: Vec::new(),
            });
            states.get_mut(*from).unwrap().transitions.push(Transition {
                to_state: to.to_string(),
                send: msg.clone(),
                expect: None,
            });
        }
        let protocol = ProtocolDef::new(initial, states);
        Self::new(protocol)
    }
}

// ── StateAwareMutator ─────────────────────────────────────────────────────────

/// Chooses messages that are valid for the current state when mutating.
#[derive(Debug, Clone)]
pub struct StateAwareMutator {
    pub mutator: MessageMutator,
}

impl Default for StateAwareMutator {
    fn default() -> Self {
        Self {
            mutator: MessageMutator::new(),
        }
    }
}

impl StateAwareMutator {
    /// Create a new state-aware mutator.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Pick a valid transition for the current state, mutate its message if
    /// present, and return `(to_state, maybe_mutated_message)`.
    pub fn choose_and_mutate(
        &self,
        machine: &ProtocolStateMachine,
        rng: &mut dyn RngCore,
    ) -> Option<(String, Option<MessageDef>)> {
        let t = machine.pick_transition(rng)?;
        let msg = t.send.as_ref().map(|m| {
            let mut cloned = m.clone();
            self.mutator.mutate(&mut cloned, rng);
            cloned
        });
        Some((t.to_state.clone(), msg))
    }

    /// Return all valid message templates for the current state.
    #[must_use]
    pub fn valid_messages<'a>(&self, machine: &'a ProtocolStateMachine) -> Vec<&'a MessageDef> {
        machine
            .available_transitions()
            .iter()
            .filter_map(|t| t.send.as_ref())
            .collect()
    }
}

// ── SessionReplay ─────────────────────────────────────────────────────────────

/// A recorded sequence of sends for reproducing a crash or interesting path.
#[derive(Debug, Clone)]
pub struct SessionReplay {
    /// Ordered list of byte sequences that were sent.
    pub sends: Vec<Vec<u8>>,
    /// Protocol state name at each corresponding send.
    pub states: Vec<String>,
    /// Optional note about why this session is being replayed.
    pub note: String,
}

impl SessionReplay {
    /// Create a new empty replay.
    #[must_use]
    pub fn new(note: impl Into<String>) -> Self {
        Self {
            sends: Vec::new(),
            states: Vec::new(),
            note: note.into(),
        }
    }

    /// Record a send event.
    pub fn record(&mut self, data: Vec<u8>, state: impl Into<String>) {
        self.sends.push(data);
        self.states.push(state.into());
    }

    /// Number of recorded sends.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.sends.len()
    }

    /// True if no sends have been recorded.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.sends.is_empty()
    }

    /// Total bytes across all sends.
    #[must_use]
    pub fn total_bytes(&self) -> usize {
        self.sends.iter().map(std::vec::Vec::len).sum()
    }

    /// Verify that the replay data matches an expected sequence of sends.
    #[must_use]
    pub fn matches(&self, expected: &[Vec<u8>]) -> bool {
        if self.sends.len() != expected.len() {
            return false;
        }
        self.sends.iter().zip(expected).all(|(a, b)| a == b)
    }

    /// Export the replay as a newline-delimited hex dump.
    #[must_use]
    pub fn to_hex_dump(&self) -> String {
        self.sends
            .iter()
            .enumerate()
            .map(|(i, s)| {
                let hex: String = s.iter().fold(String::new(), |mut acc, b| { use std::fmt::Write; let _ = write!(acc, "{b:02x}"); acc });
                format!(
                    "[{}] state={} data={}",
                    i,
                    self.states.get(i).map_or("?", |s| s.as_str()),
                    hex
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    }
}

// ── ProtocolFuzzerExt ─────────────────────────────────────────────────────────

/// Extended protocol fuzzer that integrates `ProtocolStateMachine`,
/// `MessageMutator`, and `SessionReplay`.
pub struct ProtocolFuzzerExt {
    pub machine: ProtocolStateMachine,
    pub mutator: StateAwareMutator,
    pub replays: Vec<SessionReplay>,
    pub target: FuzzTarget,
    rng: XorShiftRng,
    pub iterations: u64,
    pub crash_count: u64,
    pub bytes_sent: u64,
}

impl ProtocolFuzzerExt {
    /// Create a new extended fuzzer.
    #[must_use]
    pub fn new(protocol: ProtocolDef, target: FuzzTarget) -> Self {
        Self {
            machine: ProtocolStateMachine::new(protocol),
            mutator: StateAwareMutator::new(),
            replays: Vec::new(),
            target,
            rng: XorShiftRng::default(),
            iterations: 0,
            crash_count: 0,
            bytes_sent: 0,
        }
    }

    /// Run a single simulated fuzzing iteration.
    ///
    /// In a real implementation this would drive a real transport;
    /// here it tracks state and accumulates metrics.
    pub fn run_iteration(&mut self) -> Vec<FieldMutationRecord> {
        self.machine.reset();
        let all_records = Vec::new();
        let mut replay = SessionReplay::new(format!("iter-{}", self.iterations));

        loop {
            if self.machine.is_terminal() {
                break;
            }
            match self.mutator.choose_and_mutate(&self.machine, &mut self.rng) {
                None => break,
                Some((next_state, maybe_msg)) => {
                    if let Some(ref msg) = maybe_msg
                        && let Ok(bytes) = msg.serialise() {
                            let len = bytes.len() as u64;
                            self.bytes_sent += len;
                            replay.record(bytes, self.machine.current_state().to_owned());
                        }
                    self.machine.advance(next_state);
                }
            }
        }

        self.iterations += 1;
        self.replays.push(replay);

        // Keep only the last 100 replays.
        if self.replays.len() > 100 {
            self.replays.remove(0);
        }

        all_records
    }

    /// Get the most recent replay.
    #[must_use]
    pub fn last_replay(&self) -> Option<&SessionReplay> {
        self.replays.last()
    }

    /// Statistics snapshot.
    #[must_use]
    pub const fn stats_snapshot(&self) -> FuzzerExtStats {
        FuzzerExtStats {
            iterations: self.iterations,
            crash_count: self.crash_count,
            bytes_sent: self.bytes_sent,
            replay_count: self.replays.len(),
        }
    }
}

/// Stats snapshot for the extended fuzzer.
#[derive(Debug, Clone)]
pub struct FuzzerExtStats {
    pub iterations: u64,
    pub crash_count: u64,
    pub bytes_sent: u64,
    pub replay_count: usize,
}

// ── Timing helpers ─────────────────────────────────────────────────────────────

/// Rate limiter to pace fuzzing iterations.
pub struct FuzzRateLimiter {
    /// Target iterations per second.
    pub target_ips: f64,
    last: Option<Instant>,
}

impl FuzzRateLimiter {
    /// Create a new rate limiter.
    #[must_use]
    pub const fn new(target_ips: f64) -> Self {
        Self {
            target_ips,
            last: None,
        }
    }

    /// Call this once per iteration; returns how long to sleep (may be zero).
    pub fn throttle(&mut self) -> Duration {
        let now = Instant::now();
        if let Some(last) = self.last {
            let elapsed = now.duration_since(last);
            let target = Duration::from_secs_f64(1.0 / self.target_ips.max(0.001));
            if elapsed < target {
                let sleep = target.checked_sub(elapsed).unwrap();
                self.last = Some(now + sleep);
                return sleep;
            }
        }
        self.last = Some(now);
        Duration::ZERO
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{MessageBuilder, ProtocolBuilder};

    fn http_like_protocol() -> ProtocolDef {
        let request = MessageBuilder::new("request")
            .static_bytes("method", b"GET ".to_vec())
            .fuzz_string("path", 256)
            .static_bytes("http_ver", b" HTTP/1.0\r\n\r\n".to_vec())
            .build();
        ProtocolBuilder::new("idle")
            .add_transition("idle", "sent", Some(request))
            .add_terminal("sent")
            .build()
    }

    #[test]
    fn test_fuzz_target_tcp() {
        let t = FuzzTarget::tcp("127.0.0.1", 80);
        assert_eq!(t.address(), "127.0.0.1:80");
        assert_eq!(t.protocol(), "tcp");
    }

    #[test]
    fn test_fuzz_target_udp() {
        let t = FuzzTarget::udp("0.0.0.0", 53);
        assert_eq!(t.protocol(), "udp");
    }

    #[test]
    fn test_fuzz_target_tls() {
        let t = FuzzTarget::tls("example.com", 443, false);
        assert_eq!(t.protocol(), "tls");
        assert_eq!(t.address(), "example.com:443");
    }

    #[test]
    fn test_message_mutator_bit_flip() {
        let mut msg = MessageBuilder::new("m")
            .fuzz_blob("body", vec![0xAA, 0xBB])
            .build();
        let mut rng = XorShiftRng::default();
        let mutator = MessageMutator::new();
        let records = mutator.mutate(&mut msg, &mut rng);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].field_name, "body");
    }

    #[test]
    fn test_message_mutator_no_fuzz_fields() {
        let mut msg = MessageBuilder::new("m")
            .static_bytes("magic", b"MAGIC".to_vec())
            .build();
        let mut rng = XorShiftRng::default();
        let records = MessageMutator::new().mutate(&mut msg, &mut rng);
        assert!(records.is_empty());
    }

    #[test]
    fn test_message_mutator_format_string() {
        let mut msg = MessageBuilder::new("m").fuzz_string("s", 64).build();
        let mut rng = XorShiftRng::with_seed(42);
        let mutator = MessageMutator::new();
        let r = mutator.mutate_field(&mut msg, "s", FieldMutationKind::FormatString, &mut rng);
        assert!(r.is_some());
        let r = r.unwrap();
        assert!(r.mutated.contains(&b'%'));
    }

    #[test]
    fn test_message_mutator_delimiter_injection() {
        let mut msg = MessageBuilder::new("m")
            .fuzz_blob("d", b"hello".to_vec())
            .build();
        let mut rng = XorShiftRng::with_seed(1);
        let mutator = MessageMutator::new();
        let r = mutator.mutate_field(
            &mut msg,
            "d",
            FieldMutationKind::DelimiterInjection,
            &mut rng,
        );
        assert!(r.is_some());
        assert!(r.unwrap().mutated.len() > 5); // delimiter was appended
    }

    #[test]
    fn test_message_mutator_number_boundary() {
        let mut msg = MessageBuilder::new("m").fuzz_u32("val", 1234).build();
        let mut rng = XorShiftRng::default();
        let r = MessageMutator::new().mutate_field(
            &mut msg,
            "val",
            FieldMutationKind::NumberBoundary,
            &mut rng,
        );
        assert!(r.is_some());
    }

    #[test]
    fn test_message_mutator_length_manipulation() {
        let mut msg = MessageBuilder::new("m").fuzz_u32("len", 0).build();
        let mut rng = XorShiftRng::default();
        let r = MessageMutator::new().mutate_field(
            &mut msg,
            "len",
            FieldMutationKind::LengthManipulation,
            &mut rng,
        );
        assert!(r.is_some());
    }

    #[test]
    fn test_state_machine_basic() {
        let proto = http_like_protocol();
        let mut sm = ProtocolStateMachine::new(proto);
        assert_eq!(sm.current_state(), "idle");
        assert!(!sm.is_terminal());
        sm.advance("sent");
        assert_eq!(sm.current_state(), "sent");
        assert!(sm.is_terminal());
    }

    #[test]
    fn test_state_machine_history() {
        let proto = http_like_protocol();
        let mut sm = ProtocolStateMachine::new(proto);
        sm.advance("sent");
        assert_eq!(sm.history(), &["idle"]);
    }

    #[test]
    fn test_state_machine_reset() {
        let proto = http_like_protocol();
        let mut sm = ProtocolStateMachine::new(proto);
        sm.advance("sent");
        sm.reset();
        assert_eq!(sm.current_state(), "idle");
        assert!(sm.history().is_empty());
    }

    #[test]
    fn test_state_machine_from_edge_map() {
        let sm = ProtocolStateMachine::from_edge_map("a", &[("a", "b", None), ("b", "c", None)]);
        assert_eq!(sm.current_state(), "a");
        assert_eq!(sm.available_transitions().len(), 1);
    }

    #[test]
    fn test_state_aware_mutator_choose() {
        let proto = http_like_protocol();
        let sm = ProtocolStateMachine::new(proto);
        let mutator = StateAwareMutator::new();
        let mut rng = XorShiftRng::default();
        let result = mutator.choose_and_mutate(&sm, &mut rng);
        assert!(result.is_some());
        let (next, msg) = result.unwrap();
        assert_eq!(next, "sent");
        assert!(msg.is_some());
    }

    #[test]
    fn test_state_aware_mutator_valid_messages() {
        let proto = http_like_protocol();
        let sm = ProtocolStateMachine::new(proto);
        let mutator = StateAwareMutator::new();
        let msgs = mutator.valid_messages(&sm);
        assert_eq!(msgs.len(), 1);
    }

    #[test]
    fn test_session_replay_record_and_len() {
        let mut r = SessionReplay::new("test");
        r.record(b"GET / HTTP/1.0\r\n\r\n".to_vec(), "idle");
        assert_eq!(r.len(), 1);
        assert!(!r.is_empty());
    }

    #[test]
    fn test_session_replay_total_bytes() {
        let mut r = SessionReplay::new("test");
        r.record(vec![1, 2, 3], "a");
        r.record(vec![4, 5], "b");
        assert_eq!(r.total_bytes(), 5);
    }

    #[test]
    fn test_session_replay_matches() {
        let mut r = SessionReplay::new("t");
        r.record(b"abc".to_vec(), "s");
        assert!(r.matches(&[b"abc".to_vec()]));
        assert!(!r.matches(&[b"xyz".to_vec()]));
    }

    #[test]
    fn test_session_replay_hex_dump() {
        let mut r = SessionReplay::new("t");
        r.record(vec![0xde, 0xad], "start");
        let dump = r.to_hex_dump();
        assert!(dump.contains("dead"));
        assert!(dump.contains("start"));
    }

    #[test]
    fn test_protocol_fuzzer_ext_run_iteration() {
        let proto = http_like_protocol();
        let target = FuzzTarget::tcp("127.0.0.1", 8080);
        let mut fuzzer = ProtocolFuzzerExt::new(proto, target);
        fuzzer.run_iteration();
        assert_eq!(fuzzer.iterations, 1);
        assert!(fuzzer.bytes_sent > 0);
        assert!(fuzzer.last_replay().is_some());
    }

    #[test]
    fn test_protocol_fuzzer_ext_stats() {
        let proto = http_like_protocol();
        let target = FuzzTarget::tcp("127.0.0.1", 8080);
        let mut fuzzer = ProtocolFuzzerExt::new(proto, target);
        for _ in 0..5 {
            fuzzer.run_iteration();
        }
        let stats = fuzzer.stats_snapshot();
        assert_eq!(stats.iterations, 5);
    }

    #[test]
    fn test_fuzz_rate_limiter_zero_sleep() {
        let mut rl = FuzzRateLimiter::new(1_000_000.0); // very high → zero sleep
        let _ = rl.throttle();
        let d = rl.throttle();
        assert!(d.as_millis() < 10);
    }

    #[test]
    fn test_fuzz_rate_limiter_returns_duration() {
        let mut rl = FuzzRateLimiter::new(1.0);
        let d = rl.throttle();
        // First call: no previous instant → zero sleep.
        assert_eq!(d, Duration::ZERO);
    }

    #[test]
    fn test_field_mutation_record_fields() {
        let rec = FieldMutationRecord {
            field_name: "payload".to_owned(),
            kind: FieldMutationKind::BitFlip,
            original: vec![0xAA],
            mutated: vec![0xBA],
        };
        assert_eq!(rec.field_name, "payload");
        assert_ne!(rec.original, rec.mutated);
    }

    #[test]
    fn test_message_mutator_byte_set_fills() {
        let mut msg = MessageBuilder::new("m")
            .fuzz_blob("b", vec![1, 2, 3, 4])
            .build();
        let mut rng = XorShiftRng::with_seed(7);
        let r = MessageMutator::new()
            .mutate_field(&mut msg, "b", FieldMutationKind::ByteSet, &mut rng)
            .unwrap();
        // All bytes should be the same fill value.
        let first = r.mutated[0];
        assert!(r.mutated.iter().all(|&b| b == first));
    }

    #[test]
    fn test_protocol_fuzzer_ext_keeps_last_100_replays() {
        let proto = http_like_protocol();
        let target = FuzzTarget::tcp("127.0.0.1", 8080);
        let mut fuzzer = ProtocolFuzzerExt::new(proto, target);
        for _ in 0..120 {
            fuzzer.run_iteration();
        }
        assert_eq!(fuzzer.replays.len(), 100);
    }

    #[test]
    fn test_state_machine_pick_transition() {
        let proto = http_like_protocol();
        let sm = ProtocolStateMachine::new(proto);
        let mut rng = XorShiftRng::default();
        let t = sm.pick_transition(&mut rng);
        assert!(t.is_some());
        assert_eq!(t.unwrap().to_state, "sent");
    }

    #[test]
    fn test_state_machine_terminal_has_no_transition() {
        let proto = http_like_protocol();
        let mut sm = ProtocolStateMachine::new(proto);
        sm.advance("sent");
        let mut rng = XorShiftRng::default();
        assert!(sm.pick_transition(&mut rng).is_none());
    }

    #[test]
    fn test_fuzzer_ext_stats_zero_initially() {
        let proto = http_like_protocol();
        let target = FuzzTarget::tcp("127.0.0.1", 8080);
        let fuzzer = ProtocolFuzzerExt::new(proto, target);
        let s = fuzzer.stats_snapshot();
        assert_eq!(s.iterations, 0);
        assert_eq!(s.crash_count, 0);
    }
}
