use std::collections::HashMap;

// ─── Lossy cast helpers (deliberate boundaries) ──────────────────────────────

#[inline]
fn usize_to_f32_lossy(n: usize) -> f32 {
    // Deliberate lossy conversion for entropy/scoring.
    let lo = u16::try_from(n & 0xFFFF).unwrap_or(0);
    let mid = u16::try_from((n >> 16) & 0xFFFF).unwrap_or(0);
    let hi = u16::try_from((n >> 32) & 0xFFFF).unwrap_or(0);
    f32::from(hi).mul_add(65536.0 * 65536.0, f32::from(mid).mul_add(65536.0, f32::from(lo)))
}

#[inline]
fn u32_to_f32_lossy(n: u32) -> f32 {
    let lo = u16::try_from(n & 0xFFFF).unwrap_or(0);
    let hi = u16::try_from(n >> 16).unwrap_or(0);
    f32::from(hi).mul_add(65536.0, f32::from(lo))
}

#[inline]
fn usize_to_u32_trunc(n: usize) -> u32 { u32::try_from(n).unwrap_or(u32::MAX) }

// ── Protocol signature types ───────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ProtocolSignature {
    pub id: u32,
    pub name: String,
    pub protocol: TransportProtocol,
    pub port: Option<u16>,
    pub confidence: f32,
    pub patterns: Vec<PatternMatcher>,
    pub state_machine: Option<ProtocolStateMachine>,
    pub metadata: HashMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportProtocol {
    Tcp,
    Udp,
    TcpOrUdp,
    Icmp,
    Any,
}

#[derive(Debug, Clone)]
pub enum PatternMatcher {
    Exact { offset: Option<usize>, bytes: Vec<u8> },
    Regex { pattern: String },
    Entropy { min: f32, max: f32, window: usize },
    Length { min: usize, max: usize },
    PortRange { min: u16, max: u16 },
    PayloadContains { substr: Vec<u8> },
    PayloadStartsWith { prefix: Vec<u8> },
    PayloadEndsWith { suffix: Vec<u8> },
    FieldValue { offset: usize, size: FieldSize, value: u64, mask: Option<u64> },
    AsciiPrintable { min_ratio: f32 },
    Composite(CompositeLogic, Vec<Self>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompositeLogic { And, Or, Not }

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FieldSize { U8, U16Be, U16Le, U32Be, U32Le, U64Be, U64Le }

// ── Pattern evaluation ────────────────────────────────────────────────────────

pub struct PatternEvaluator;

impl PatternEvaluator {
    #[must_use]
    pub fn matches(pattern: &PatternMatcher, payload: &[u8]) -> bool {
        match pattern {
            PatternMatcher::Exact { offset, bytes } => {
                if let Some(off) = offset {
                    if *off + bytes.len() > payload.len() { return false; }
                    payload[*off..*off + bytes.len()] == *bytes
                } else {
                    payload.windows(bytes.len()).any(|w| w == bytes.as_slice())
                }
            }
            PatternMatcher::PayloadStartsWith { prefix } => {
                payload.starts_with(prefix)
            }
            PatternMatcher::PayloadEndsWith { suffix } => {
                payload.ends_with(suffix)
            }
            PatternMatcher::PayloadContains { substr } => {
                payload.windows(substr.len()).any(|w| w == substr.as_slice())
            }
            PatternMatcher::Length { min, max } => {
                payload.len() >= *min && payload.len() <= *max
            }
            PatternMatcher::Entropy { min, max, window } => {
                let e = Self::compute_entropy(&payload[..(*window).min(payload.len())]);
                e >= *min && e <= *max
            }
            PatternMatcher::FieldValue { offset, size, value, mask } => {
                if *offset >= payload.len() { return false; }
                let field_val = Self::read_field(payload, *offset, size);
                let (fv, v) = mask.as_ref().map_or((field_val, *value), |m| (field_val & m, value & m));
                fv == v
            }
            PatternMatcher::AsciiPrintable { min_ratio } => {
                let printable = payload.iter().filter(|&&b| (0x20..0x7f).contains(&b)).count();
                usize_to_f32_lossy(printable) / usize_to_f32_lossy(payload.len()) >= *min_ratio
            }
            PatternMatcher::Composite(logic, sub_patterns) => {
                match logic {
                    CompositeLogic::And => sub_patterns.iter().all(|p| Self::matches(p, payload)),
                    CompositeLogic::Or => sub_patterns.iter().any(|p| Self::matches(p, payload)),
                    CompositeLogic::Not => !sub_patterns.iter().any(|p| Self::matches(p, payload)),
                }
            }
            PatternMatcher::Regex { .. } => false,
            PatternMatcher::PortRange { .. } => true,
        }
    }

    fn compute_entropy(data: &[u8]) -> f32 {
        if data.is_empty() { return 0.0; }
        let mut counts = [0u32; 256];
        for &b in data { counts[b as usize] += 1; }
        let len = usize_to_f32_lossy(data.len());
        let mut entropy = 0f32;
        for &c in &counts {
            if c > 0 {
                let p = u32_to_f32_lossy(c) / len;
                entropy = p.mul_add(-p.log2(), entropy);
            }
        }
        entropy
    }

    fn read_field(data: &[u8], offset: usize, size: &FieldSize) -> u64 {
        match size {
            FieldSize::U8 => data.get(offset).map_or(0, |&b| u64::from(b)),
            FieldSize::U16Be => {
                if offset + 2 > data.len() { return 0; }
                u64::from(u16::from_be_bytes([data[offset], data[offset+1]]))
            }
            FieldSize::U16Le => {
                if offset + 2 > data.len() { return 0; }
                u64::from(u16::from_le_bytes([data[offset], data[offset+1]]))
            }
            FieldSize::U32Be => {
                if offset + 4 > data.len() { return 0; }
                u64::from(u32::from_be_bytes(data[offset..offset+4].try_into().unwrap_or([0;4])))
            }
            FieldSize::U32Le => {
                if offset + 4 > data.len() { return 0; }
                u64::from(u32::from_le_bytes(data[offset..offset+4].try_into().unwrap_or([0;4])))
            }
            FieldSize::U64Be => {
                if offset + 8 > data.len() { return 0; }
                u64::from_be_bytes(data[offset..offset+8].try_into().unwrap_or([0;8]))
            }
            FieldSize::U64Le => {
                if offset + 8 > data.len() { return 0; }
                u64::from_le_bytes(data[offset..offset+8].try_into().unwrap_or([0;8]))
            }
        }
    }
}

// ── Protocol state machine ─────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ProtocolStateMachine {
    pub states: Vec<PsmState>,
    pub initial_state: usize,
    pub accept_states: Vec<usize>,
    pub current_state: usize,
}

#[derive(Debug, Clone)]
pub struct PsmState {
    pub id: usize,
    pub name: String,
    pub transitions: Vec<PsmTransition>,
}

#[derive(Debug, Clone)]
pub struct PsmTransition {
    pub target_state: usize,
    pub trigger: PatternMatcher,
    pub action: Option<PsmAction>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PsmAction {
    RecordPayload,
    ExtractField { name: String, offset: usize, size: FieldSize },
    EmitAlert(String),
    Terminate,
}

impl ProtocolStateMachine {
    #[must_use]
    pub const fn new(states: Vec<PsmState>, initial: usize, accept: Vec<usize>) -> Self {
        Self { states, initial_state: initial, accept_states: accept, current_state: initial }
    }

    pub fn advance(&mut self, payload: &[u8]) -> PsmResult {
        let state = match self.states.get(self.current_state) {
            Some(s) => s.clone(),
            None => return PsmResult::Invalid,
        };
        for trans in &state.transitions {
            if PatternEvaluator::matches(&trans.trigger, payload) {
                let prev = self.current_state;
                self.current_state = trans.target_state;
                let accepted = self.accept_states.contains(&self.current_state);
                let action = trans.action.clone();
                return PsmResult::Transition { from: prev, to: self.current_state, accepted, action };
            }
        }
        PsmResult::NoTransition
    }

    pub const fn reset(&mut self) { self.current_state = self.initial_state; }
    #[must_use]
    pub fn is_accepted(&self) -> bool { self.accept_states.contains(&self.current_state) }
}

#[derive(Debug, Clone)]
pub enum PsmResult {
    Transition { from: usize, to: usize, accepted: bool, action: Option<PsmAction> },
    NoTransition,
    Invalid,
}

// ── Protocol signature library ─────────────────────────────────────────────────

pub struct ProtocolSignatureLibrary {
    pub signatures: Vec<ProtocolSignature>,
    pub by_port: HashMap<u16, Vec<u32>>,
    pub by_name: HashMap<String, u32>,
}

impl Default for ProtocolSignatureLibrary {
    fn default() -> Self {
        Self::new()
    }
}

impl ProtocolSignatureLibrary {
    #[must_use]
    pub fn new() -> Self {
        let mut lib = Self { signatures: Vec::new(), by_port: HashMap::new(), by_name: HashMap::new() };
        lib.load_builtin();
        lib
    }

    fn load_builtin(&mut self) {
        // HTTP
        self.add(ProtocolSignature {
            id: 0, name: "HTTP".into(), protocol: TransportProtocol::Tcp, port: Some(80), confidence: 0.95,
            patterns: vec![PatternMatcher::Composite(CompositeLogic::Or, vec![
                PatternMatcher::PayloadStartsWith { prefix: b"GET ".to_vec() },
                PatternMatcher::PayloadStartsWith { prefix: b"POST ".to_vec() },
                PatternMatcher::PayloadStartsWith { prefix: b"HTTP/".to_vec() },
                PatternMatcher::PayloadStartsWith { prefix: b"PUT ".to_vec() },
                PatternMatcher::PayloadStartsWith { prefix: b"HEAD ".to_vec() },
            ])],
            state_machine: None, metadata: HashMap::new(),
        });
        // HTTPS/TLS
        self.add(ProtocolSignature {
            id: 1, name: "TLS".into(), protocol: TransportProtocol::Tcp, port: Some(443), confidence: 0.98,
            patterns: vec![PatternMatcher::FieldValue { offset: 0, size: FieldSize::U8, value: 0x16, mask: None }, PatternMatcher::FieldValue { offset: 1, size: FieldSize::U8, value: 0x03, mask: None }],
            state_machine: None, metadata: HashMap::new(),
        });
        // DNS
        self.add(ProtocolSignature {
            id: 2, name: "DNS".into(), protocol: TransportProtocol::Udp, port: Some(53), confidence: 0.85,
            patterns: vec![PatternMatcher::Length { min: 12, max: 512 }, PatternMatcher::FieldValue { offset: 2, size: FieldSize::U8, value: 0x01, mask: Some(0x80) }],
            state_machine: None, metadata: HashMap::new(),
        });
        // SMB
        self.add(ProtocolSignature {
            id: 3, name: "SMB".into(), protocol: TransportProtocol::Tcp, port: Some(445), confidence: 0.97,
            patterns: vec![PatternMatcher::Composite(CompositeLogic::Or, vec![
                PatternMatcher::PayloadContains { substr: b"\xFFSMB".to_vec() },
                PatternMatcher::PayloadContains { substr: b"\xFESMB".to_vec() },
            ])],
            state_machine: None, metadata: HashMap::new(),
        });
        // SSH
        self.add(ProtocolSignature {
            id: 4, name: "SSH".into(), protocol: TransportProtocol::Tcp, port: Some(22), confidence: 0.99,
            patterns: vec![PatternMatcher::PayloadStartsWith { prefix: b"SSH-".to_vec() }],
            state_machine: None, metadata: HashMap::new(),
        });
        // FTP
        self.add(ProtocolSignature {
            id: 5, name: "FTP".into(), protocol: TransportProtocol::Tcp, port: Some(21), confidence: 0.92,
            patterns: vec![PatternMatcher::Composite(CompositeLogic::Or, vec![
                PatternMatcher::PayloadStartsWith { prefix: b"220 ".to_vec() },
                PatternMatcher::PayloadStartsWith { prefix: b"USER ".to_vec() },
                PatternMatcher::PayloadStartsWith { prefix: b"PASS ".to_vec() },
            ])],
            state_machine: None, metadata: HashMap::new(),
        });
        // SMTP
        self.add(ProtocolSignature {
            id: 6, name: "SMTP".into(), protocol: TransportProtocol::Tcp, port: Some(25), confidence: 0.93,
            patterns: vec![PatternMatcher::Composite(CompositeLogic::Or, vec![
                PatternMatcher::PayloadStartsWith { prefix: b"220 ".to_vec() },
                PatternMatcher::PayloadStartsWith { prefix: b"EHLO ".to_vec() },
                PatternMatcher::PayloadStartsWith { prefix: b"HELO ".to_vec() },
                PatternMatcher::PayloadStartsWith { prefix: b"MAIL FROM:".to_vec() },
            ])],
            state_machine: None, metadata: HashMap::new(),
        });
        // MQTT
        self.add(ProtocolSignature {
            id: 7, name: "MQTT".into(), protocol: TransportProtocol::Tcp, port: Some(1883), confidence: 0.88,
            patterns: vec![PatternMatcher::FieldValue { offset: 0, size: FieldSize::U8, value: 0x10, mask: None }],
            state_machine: None, metadata: HashMap::new(),
        });
        // RDP
        self.add(ProtocolSignature {
            id: 8, name: "RDP".into(), protocol: TransportProtocol::Tcp, port: Some(3389), confidence: 0.90,
            patterns: vec![PatternMatcher::PayloadContains { substr: b"Cookie: mstshash=".to_vec() }],
            state_machine: None, metadata: HashMap::new(),
        });
    }

    pub fn add(&mut self, mut sig: ProtocolSignature) {
        let id = usize_to_u32_trunc(self.signatures.len());
        sig.id = id;
        if let Some(port) = sig.port {
            self.by_port.entry(port).or_default().push(id);
        }
        self.by_name.insert(sig.name.clone(), id);
        self.signatures.push(sig);
    }

    #[must_use]
    pub fn identify(&self, payload: &[u8], port: Option<u16>) -> Vec<ProtocolMatch> {
        let mut matches = Vec::new();
        let candidates: Vec<&ProtocolSignature> = port.map_or_else(
            || self.signatures.iter().collect(),
            |p| {
                let port_sigs = self.by_port.get(&p).map(|ids| ids.iter().filter_map(|&id| self.signatures.get(id as usize)).collect::<Vec<_>>()).unwrap_or_default();
                if port_sigs.is_empty() { self.signatures.iter().collect() } else { port_sigs }
            },
        );
        for sig in candidates {
            let matched_patterns = sig.patterns.iter().filter(|p| PatternEvaluator::matches(p, payload)).count();
            if matched_patterns > 0 {
                let score = sig.confidence * (usize_to_f32_lossy(matched_patterns) / usize_to_f32_lossy(sig.patterns.len()));
                matches.push(ProtocolMatch { signature_id: sig.id, name: sig.name.clone(), score, matched_patterns, total_patterns: sig.patterns.len() });
            }
        }
        matches.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal));
        matches
    }

    #[must_use]
    pub fn best_match(&self, payload: &[u8], port: Option<u16>) -> Option<ProtocolMatch> {
        self.identify(payload, port).into_iter().next()
    }

    #[must_use]
    pub fn get_by_name(&self, name: &str) -> Option<&ProtocolSignature> {
        let id = self.by_name.get(name)?;
        self.signatures.get(*id as usize)
    }

    #[must_use]
    pub fn stats(&self) -> SigLibStats {
        SigLibStats { total: self.signatures.len(), by_protocol: { let mut m = HashMap::new(); for sig in &self.signatures { *m.entry(format!("{:?}", sig.protocol)).or_insert(0) += 1; } m } }
    }
}

#[derive(Debug, Clone)]
pub struct ProtocolMatch {
    pub signature_id: u32,
    pub name: String,
    pub score: f32,
    pub matched_patterns: usize,
    pub total_patterns: usize,
}

#[derive(Debug, Clone)]
pub struct SigLibStats {
    pub total: usize,
    pub by_protocol: HashMap<String, usize>,
}

// ── Deep packet inspection engine ─────────────────────────────────────────────

pub struct DpiEngine {
    pub library: ProtocolSignatureLibrary,
    pub flow_state: HashMap<FlowKey, FlowContext>,
    pub detections: Vec<DpiDetection>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FlowKey {
    pub src_ip: [u8; 4],
    pub dst_ip: [u8; 4],
    pub src_port: u16,
    pub dst_port: u16,
    pub proto: u8,
}

#[derive(Debug, Clone)]
pub struct FlowContext {
    pub key: FlowKey,
    pub identified_protocol: Option<String>,
    pub packets_seen: u64,
    pub bytes_seen: u64,
    pub first_seen: u64,
    pub last_seen: u64,
    pub reassembled: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct DpiDetection {
    pub flow: FlowKey,
    pub protocol: String,
    pub confidence: f32,
    pub offset: usize,
    pub payload_len: usize,
}

impl Default for DpiEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl DpiEngine {
    #[must_use]
    pub fn new() -> Self {
        Self { library: ProtocolSignatureLibrary::new(), flow_state: HashMap::new(), detections: Vec::new() }
    }

    pub fn process_packet(&mut self, flow: &FlowKey, payload: &[u8], timestamp: u64) {
        let ctx = self.flow_state.entry(flow.clone()).or_insert_with(|| FlowContext {
            key: flow.clone(), identified_protocol: None, packets_seen: 0, bytes_seen: 0, first_seen: timestamp, last_seen: timestamp, reassembled: Vec::new(),
        });
        ctx.packets_seen += 1;
        ctx.bytes_seen += payload.len() as u64;
        ctx.last_seen = timestamp;
        if ctx.identified_protocol.is_none() {
            ctx.reassembled.extend_from_slice(payload);
            let port = Some(flow.dst_port);
            if let Some(m) = self.library.best_match(&ctx.reassembled, port).filter(|m| m.score > 0.7) {
                ctx.identified_protocol = Some(m.name.clone());
                self.detections.push(DpiDetection { flow: flow.clone(), protocol: m.name, confidence: m.score, offset: 0, payload_len: ctx.reassembled.len() });
            }
        }
    }

    #[must_use]
    pub fn get_flow_protocol(&self, flow: &FlowKey) -> Option<&str> {
        self.flow_state.get(flow)?.identified_protocol.as_deref()
    }

    #[must_use]
    pub fn stats(&self) -> DpiStats {
        DpiStats { total_flows: self.flow_state.len(), identified_flows: self.flow_state.values().filter(|f| f.identified_protocol.is_some()).count(), total_detections: self.detections.len() }
    }
}

#[derive(Debug, Clone)]
pub struct DpiStats {
    pub total_flows: usize,
    pub identified_flows: usize,
    pub total_detections: usize,
}
