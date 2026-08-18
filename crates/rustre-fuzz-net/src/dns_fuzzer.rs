//! DNS protocol fuzzer: query type mutations, label compression attacks,
//! EDNS0 fuzzing, and recursion overflow attempts.

use std::net::SocketAddr;
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::time::timeout;

use serde::{Deserialize, Serialize};

// ── DNS constants ─────────────────────────────────────────────────────────────

/// DNS record types.
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DnsQType {
    A     = 1,
    NS    = 2,
    CNAME = 5,
    SOA   = 6,
    PTR   = 12,
    MX    = 15,
    TXT   = 16,
    AAAA  = 28,
    SRV   = 33,
    OPT   = 41,  // EDNS0 pseudo-RR
    ANY   = 255,
    /// An arbitrary raw value for fuzzing.
    Raw(u16),
}

impl DnsQType {
    #[must_use]
    pub fn as_u16(self) -> u16 {
        match self {
            Self::A => 1, Self::NS => 2, Self::CNAME => 5, Self::SOA => 6,
            Self::PTR => 12, Self::MX => 15, Self::TXT => 16, Self::AAAA => 28,
            Self::SRV => 33, Self::OPT => 41, Self::ANY => 255,
            Self::Raw(v) => v,
        }
    }
}

/// DNS classes.
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsClass {
    IN = 1,
    CH = 3,
    ANY = 255,
    Raw(u16),
}

impl DnsClass {
    #[must_use]
    pub fn as_u16(self) -> u16 {
        match self {
            Self::IN => 1, Self::CH => 3, Self::ANY => 255,
            Self::Raw(v) => v,
        }
    }
}

// ── DNS message builder ───────────────────────────────────────────────────────

/// DNS message flags field.
#[derive(Debug, Clone, Copy, Default)]
pub struct DnsFlags {
    pub qr: bool,          // 0 = query, 1 = response
    pub opcode: u8,        // 4 bits
    pub aa: bool,          // authoritative answer
    pub tc: bool,          // truncated
    pub rd: bool,          // recursion desired
    pub ra: bool,          // recursion available
    pub z: u8,             // 3 bits (reserved/AD/CD)
    pub rcode: u8,         // 4 bits
}

impl DnsFlags {
    #[must_use]
    pub const fn query_recursive() -> Self {
        Self { rd: true, ..Self::const_default() }
    }

    const fn const_default() -> Self {
        Self { qr: false, opcode: 0, aa: false, tc: false, rd: false, ra: false, z: 0, rcode: 0 }
    }

    #[must_use]
    pub fn to_u16(self) -> u16 {
        let mut v: u16 = 0;
        if self.qr { v |= 0x8000; }
        v |= (u16::from(self.opcode & 0x0F)) << 11;
        if self.aa { v |= 0x0400; }
        if self.tc { v |= 0x0200; }
        if self.rd { v |= 0x0100; }
        if self.ra { v |= 0x0080; }
        v |= (u16::from(self.z & 0x07)) << 4;
        v |= u16::from(self.rcode & 0x0F);
        v
    }
}

/// DNS question record.
#[derive(Debug, Clone)]
pub struct DnsQuestion {
    pub name: String,
    pub qtype: DnsQType,
    pub qclass: DnsClass,
}

impl DnsQuestion {
    #[must_use]
    pub fn new(name: impl Into<String>, qtype: DnsQType) -> Self {
        Self { name: name.into(), qtype, qclass: DnsClass::IN }
    }

    #[must_use]
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = encode_dns_name(&self.name);
        out.extend_from_slice(&self.qtype.as_u16().to_be_bytes());
        out.extend_from_slice(&self.qclass.as_u16().to_be_bytes());
        out
    }
}

/// A full DNS message.
#[derive(Debug, Clone)]
pub struct DnsMessage {
    pub id: u16,
    pub flags: DnsFlags,
    pub questions: Vec<DnsQuestion>,
    /// Raw additional records bytes (e.g. EDNS0 OPT).
    pub additional: Vec<u8>,
}

impl DnsMessage {
    #[must_use]
    pub fn new_query(id: u16, question: DnsQuestion) -> Self {
        Self {
            id,
            flags: DnsFlags::query_recursive(),
            questions: vec![question],
            additional: Vec::new(),
        }
    }

    #[must_use]
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.id.to_be_bytes());
        out.extend_from_slice(&self.flags.to_u16().to_be_bytes());
        // Clamp to u16::MAX to avoid silent truncation when the question list
        // is crafted to exceed 65535 entries (e.g. via MultipleQuestions fuzz).
        out.extend_from_slice(&(self.questions.len().min(u16::MAX as usize) as u16).to_be_bytes());
        out.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
        out.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
        out.extend_from_slice(&(if self.additional.is_empty() { 0u16 } else { 1u16 }).to_be_bytes()); // ARCOUNT
        for q in &self.questions {
            out.extend(q.serialize());
        }
        out.extend_from_slice(&self.additional);
        out
    }
}

/// Encode a DNS name to wire format labels.
#[must_use]
pub fn encode_dns_name(name: &str) -> Vec<u8> {
    let mut out = Vec::new();
    let name = name.trim_end_matches('.');
    if name.is_empty() {
        out.push(0);
        return out;
    }
    for label in name.split('.') {
        let b = label.as_bytes();
        // RFC 1035 limits labels to 63 octets; silently truncate rather than
        // producing a malformed length byte via as-cast overflow.
        let label_len = b.len().min(63);
        out.push(label_len as u8);
        out.extend_from_slice(&b[..label_len]);
    }
    out.push(0); // root label
    out
}

/// Build an EDNS0 OPT record.
#[must_use]
pub fn build_edns0(udp_payload_size: u16, dnssec_ok: bool, options: Vec<u8>) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(0x00); // root name
    out.extend_from_slice(&DnsQType::OPT.as_u16().to_be_bytes()); // type = OPT
    out.extend_from_slice(&udp_payload_size.to_be_bytes()); // class = UDP payload size
    // TTL encodes extended RCODE and flags
    let ttl_flags: u32 = if dnssec_ok { 0x8000 } else { 0 };
    out.extend_from_slice(&ttl_flags.to_be_bytes());
    // RDLENGTH is a u16; clamp to avoid silent truncation if options are large.
    out.extend_from_slice(&(options.len().min(u16::MAX as usize) as u16).to_be_bytes()); // RDLENGTH
    out.extend(options);
    out
}

// ── DNS fuzz mutations ────────────────────────────────────────────────────────

/// A DNS fuzz mutation to apply.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DnsMutation {
    /// Query for a specific record type.
    QueryType(u16),
    /// Use a very long domain name (total > 253 chars).
    LongDomainName { len: usize },
    /// Label with length exceeding 63.
    OversizedLabel,
    /// Insert a label compression pointer into the question.
    CompressionPointer { offset: u16 },
    /// Send many questions in one message.
    MultipleQuestions { count: usize },
    /// EDNS0 with extremely large UDP payload size.
    EdnsLargeUdpSize,
    /// EDNS0 with unknown option codes.
    EdnsUnknownOption { code: u16 },
    /// Set the TC (truncated) flag.
    TruncatedFlag,
    /// Set opcode to a reserved value.
    BadOpcode(u8),
    /// Recursion depth overflow: CNAME chain in additional section.
    RecursionLoop,
    /// Zero-length query name.
    EmptyQName,
    /// ID = 0 (some implementations reject this).
    ZeroId,
    /// QR bit set in a query (response masquerading as query).
    QrBitInQuery,
    /// Truncate the message to `n` bytes.
    TruncateMessage(usize),
    /// ALL record types in rapid succession.
    AllRecordTypes,
}

/// A mutated DNS packet ready to send.
#[derive(Debug, Clone)]
pub struct DnsPacket {
    pub bytes: Vec<u8>,
    pub label: String,
    pub mutation: String,
}

impl DnsPacket {
    #[must_use]
    pub fn new(bytes: Vec<u8>, label: impl Into<String>, mutation: impl Into<String>) -> Self {
        Self { bytes, label: label.into(), mutation: mutation.into() }
    }
}

/// Apply a `DnsMutation` to generate one or more `DnsPacket`s.
#[must_use]
pub fn apply_dns_mutation(
    mutation: &DnsMutation,
    base_name: &str,
    base_id: u16,
) -> Vec<DnsPacket> {
    match mutation {
        DnsMutation::QueryType(qtype) => {
            let q = DnsQuestion { name: base_name.to_string(), qtype: DnsQType::Raw(*qtype), qclass: DnsClass::IN };
            let msg = DnsMessage::new_query(base_id, q);
            vec![DnsPacket::new(msg.serialize(), format!("qtype_{}", qtype), "QueryType")]
        }
        DnsMutation::LongDomainName { len } => {
            // Cap the generated domain name length to prevent memory exhaustion:
            // an uncapped `len` value (dos-memory-exhaustion) could allocate an
            // unbounded Vec before the DNS packet is serialised.
            const MAX_NAME_LEN: usize = 8192;
            let len = (*len).min(MAX_NAME_LEN);
            let label = "a".repeat(63);
            let repeats = (len / 64) + 1;
            let name: String = (0..repeats).map(|_| label.as_str()).collect::<Vec<_>>().join(".");
            let q = DnsQuestion::new(&name[..len.min(name.len())], DnsQType::A);
            let msg = DnsMessage::new_query(base_id, q);
            vec![DnsPacket::new(msg.serialize(), "long_name", "LongDomainName")]
        }
        DnsMutation::OversizedLabel => {
            // A label with length byte = 64 (exceeds RFC limit of 63)
            let mut bytes = vec![0u8; 14]; // minimal DNS header
            bytes[..2].copy_from_slice(&base_id.to_be_bytes());
            bytes[2..4].copy_from_slice(&DnsFlags::query_recursive().to_u16().to_be_bytes());
            bytes[4..6].copy_from_slice(&1u16.to_be_bytes()); // QDCOUNT
            bytes[6..12].copy_from_slice(&[0u8; 6]);
            // Question with 64-byte label
            bytes.push(64); // label length
            bytes.extend_from_slice(&[b'a'; 64]); // 64 bytes (invalid)
            bytes.push(0); // root
            bytes.extend_from_slice(&1u16.to_be_bytes()); // QTYPE A
            bytes.extend_from_slice(&1u16.to_be_bytes()); // QCLASS IN
            vec![DnsPacket::new(bytes, "oversized_label", "OversizedLabel")]
        }
        DnsMutation::CompressionPointer { offset } => {
            // Craft a message with a compression pointer in the QNAME
            let mut msg = DnsMessage::new_query(base_id, DnsQuestion::new(base_name, DnsQType::A));
            msg.questions.clear();
            let mut question_bytes = Vec::new();
            // Use compression pointer: 0xC0 | (offset >> 8), offset & 0xFF
            question_bytes.push(0xC0 | ((*offset >> 8) as u8));
            question_bytes.push((*offset & 0xFF) as u8);
            question_bytes.extend_from_slice(&DnsQType::A.as_u16().to_be_bytes());
            question_bytes.extend_from_slice(&DnsClass::IN.as_u16().to_be_bytes());
            let mut raw = msg.serialize();
            raw.extend(question_bytes);
            vec![DnsPacket::new(raw, format!("compress_ptr_{}", offset), "CompressionPointer")]
        }
        DnsMutation::MultipleQuestions { count } => {
            // Cap the number of questions to prevent memory exhaustion: an
            // uncapped loop on attacker-controlled `count` can allocate
            // gigabytes before the packet is sent (dos-memory-exhaustion).
            const MAX_QUESTIONS: usize = 1024;
            let effective_count = (*count).min(MAX_QUESTIONS);
            let mut out = vec![0u8; 12];
            out[..2].copy_from_slice(&base_id.to_be_bytes());
            out[2..4].copy_from_slice(&DnsFlags::query_recursive().to_u16().to_be_bytes());
            out[4..6].copy_from_slice(&(effective_count.min(u16::MAX as usize) as u16).to_be_bytes()); // QDCOUNT
            out[6..12].copy_from_slice(&[0u8; 6]);
            for i in 0..effective_count {
                let name = format!("question{}.example.com", i);
                out.extend(encode_dns_name(&name));
                out.extend_from_slice(&DnsQType::A.as_u16().to_be_bytes());
                out.extend_from_slice(&DnsClass::IN.as_u16().to_be_bytes());
            }
            vec![DnsPacket::new(out, format!("multi_q_{}", count), "MultipleQuestions")]
        }
        DnsMutation::EdnsLargeUdpSize => {
            let edns = build_edns0(65535, false, vec![]);
            let mut msg = DnsMessage::new_query(base_id, DnsQuestion::new(base_name, DnsQType::A));
            msg.additional = edns;
            vec![DnsPacket::new(msg.serialize(), "edns_large_udp", "EdnsLargeUdpSize")]
        }
        DnsMutation::EdnsUnknownOption { code } => {
            // EDNS option: code (2) + length (2) + data
            let mut opt_data = Vec::new();
            opt_data.extend_from_slice(&code.to_be_bytes());
            opt_data.extend_from_slice(&4u16.to_be_bytes());
            opt_data.extend_from_slice(&[0xFF; 4]);
            let edns = build_edns0(4096, false, opt_data);
            let mut msg = DnsMessage::new_query(base_id, DnsQuestion::new(base_name, DnsQType::A));
            msg.additional = edns;
            vec![DnsPacket::new(msg.serialize(), format!("edns_opt_{}", code), "EdnsUnknownOption")]
        }
        DnsMutation::TruncatedFlag => {
            let q = DnsQuestion::new(base_name, DnsQType::A);
            let mut flags = DnsFlags::query_recursive();
            flags.tc = true;
            let msg = DnsMessage { id: base_id, flags, questions: vec![q], additional: Vec::new() };
            vec![DnsPacket::new(msg.serialize(), "tc_flag", "TruncatedFlag")]
        }
        DnsMutation::BadOpcode(opcode) => {
            let q = DnsQuestion::new(base_name, DnsQType::A);
            let mut flags = DnsFlags::query_recursive();
            flags.opcode = *opcode;
            let msg = DnsMessage { id: base_id, flags, questions: vec![q], additional: Vec::new() };
            vec![DnsPacket::new(msg.serialize(), format!("opcode_{}", opcode), "BadOpcode")]
        }
        DnsMutation::RecursionLoop => {
            // Self-referencing pointer: QNAME points back to offset 12 (the start of QNAME)
            apply_dns_mutation(&DnsMutation::CompressionPointer { offset: 12 }, base_name, base_id)
        }
        DnsMutation::EmptyQName => {
            let mut out = vec![0u8; 12];
            out[..2].copy_from_slice(&base_id.to_be_bytes());
            out[2..4].copy_from_slice(&DnsFlags::query_recursive().to_u16().to_be_bytes());
            out[4..6].copy_from_slice(&1u16.to_be_bytes());
            out.push(0); // empty QNAME (just root)
            out.extend_from_slice(&DnsQType::A.as_u16().to_be_bytes());
            out.extend_from_slice(&DnsClass::IN.as_u16().to_be_bytes());
            vec![DnsPacket::new(out, "empty_qname", "EmptyQName")]
        }
        DnsMutation::ZeroId => {
            let q = DnsQuestion::new(base_name, DnsQType::A);
            let msg = DnsMessage { id: 0, flags: DnsFlags::query_recursive(), questions: vec![q], additional: Vec::new() };
            vec![DnsPacket::new(msg.serialize(), "zero_id", "ZeroId")]
        }
        DnsMutation::QrBitInQuery => {
            let q = DnsQuestion::new(base_name, DnsQType::A);
            let mut flags = DnsFlags::query_recursive();
            flags.qr = true; // pretend this is a response
            let msg = DnsMessage { id: base_id, flags, questions: vec![q], additional: Vec::new() };
            vec![DnsPacket::new(msg.serialize(), "qr_in_query", "QrBitInQuery")]
        }
        DnsMutation::TruncateMessage(n) => {
            let q = DnsQuestion::new(base_name, DnsQType::A);
            let msg = DnsMessage::new_query(base_id, q);
            let mut bytes = msg.serialize();
            bytes.truncate(*n);
            vec![DnsPacket::new(bytes, format!("trunc_{}", n), "TruncateMessage")]
        }
        DnsMutation::AllRecordTypes => {
            let types = [1u16, 2, 5, 6, 12, 15, 16, 28, 33, 255, 0, 65535, 257, 0xFFFF];
            types.iter().map(|&t| {
                let q = DnsQuestion { name: base_name.to_string(), qtype: DnsQType::Raw(t), qclass: DnsClass::IN };
                let msg = DnsMessage::new_query(base_id, q);
                DnsPacket::new(msg.serialize(), format!("qtype_{}", t), "AllRecordTypes")
            }).collect()
        }
    }
}

// ── DNS fuzzer ────────────────────────────────────────────────────────────────

/// Result of sending one DNS fuzz probe.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DnsFuzzOutcome {
    /// A valid-looking DNS response was received.
    Response { id: u16, rcode: u8, answers: u16 },
    /// The response was malformed or too short.
    MalformedResponse(Vec<u8>),
    /// No response was received within the timeout.
    Timeout,
    /// An IO error occurred.
    Error(String),
    /// ID mismatch in response.
    IdMismatch { sent: u16, received: u16 },
}

impl DnsFuzzOutcome {
    #[must_use]
    pub fn is_anomalous(&self) -> bool {
        matches!(self, Self::MalformedResponse(_) | Self::Error(_) | Self::IdMismatch { .. })
    }
}

/// Async DNS fuzzer.
pub struct DnsFuzzer {
    target: SocketAddr,
    recv_timeout_ms: u64,
    mutations: Vec<DnsMutation>,
    base_name: String,
    results: Vec<(DnsPacket, DnsFuzzOutcome)>,
    state: u64, // PRNG state for ID generation
}

impl DnsFuzzer {
    #[must_use]
    pub fn new(target: SocketAddr) -> Self {
        Self {
            target,
            recv_timeout_ms: 2000,
            mutations: Self::default_mutations(),
            base_name: "example.com".into(),
            results: Vec::new(),
            state: 0x1234_5678_9ABC_DEF0,
        }
    }

    fn default_mutations() -> Vec<DnsMutation> {
        vec![
            DnsMutation::QueryType(DnsQType::ANY.as_u16()),
            DnsMutation::QueryType(0xFFFF),
            DnsMutation::QueryType(0x0000),
            DnsMutation::LongDomainName { len: 253 },
            DnsMutation::LongDomainName { len: 255 },
            DnsMutation::OversizedLabel,
            DnsMutation::CompressionPointer { offset: 12 },
            DnsMutation::CompressionPointer { offset: 0 },
            DnsMutation::MultipleQuestions { count: 64 },
            DnsMutation::EdnsLargeUdpSize,
            DnsMutation::EdnsUnknownOption { code: 0xFFFF },
            DnsMutation::TruncatedFlag,
            DnsMutation::BadOpcode(0x0F),
            DnsMutation::RecursionLoop,
            DnsMutation::EmptyQName,
            DnsMutation::ZeroId,
            DnsMutation::QrBitInQuery,
            DnsMutation::TruncateMessage(2),
            DnsMutation::TruncateMessage(12),
            DnsMutation::AllRecordTypes,
        ]
    }

    fn next_id(&mut self) -> u16 {
        self.state ^= self.state << 13;
        self.state ^= self.state >> 7;
        self.state ^= self.state << 17;
        (self.state & 0xFFFF) as u16
    }

    pub fn set_base_name(&mut self, name: impl Into<String>) {
        self.base_name = name.into();
    }

    pub fn set_recv_timeout_ms(&mut self, ms: u64) {
        self.recv_timeout_ms = ms;
    }

    pub fn add_mutation(&mut self, m: DnsMutation) {
        self.mutations.push(m);
    }

    /// Run all configured mutations against the DNS target.
    pub async fn run_all(&mut self) -> Vec<(DnsPacket, DnsFuzzOutcome)> {
        let mutations = std::mem::take(&mut self.mutations);
        for mutation in &mutations {
            let id = self.next_id();
            let packets = apply_dns_mutation(mutation, &self.base_name.clone(), id);
            for packet in packets {
                let outcome = self.probe(&packet, id).await;
                self.results.push((packet, outcome));
            }
        }
        self.mutations = mutations;
        self.results.clone()
    }

    async fn probe(&self, packet: &DnsPacket, sent_id: u16) -> DnsFuzzOutcome {
        let socket = match UdpSocket::bind("0.0.0.0:0").await {
            Ok(s) => s,
            Err(e) => return DnsFuzzOutcome::Error(e.to_string()),
        };

        if let Err(e) = socket.send_to(&packet.bytes, self.target).await {
            return DnsFuzzOutcome::Error(e.to_string());
        }

        let mut buf = vec![0u8; 4096];
        match timeout(Duration::from_millis(self.recv_timeout_ms), socket.recv_from(&mut buf)).await {
            Err(_) => DnsFuzzOutcome::Timeout,
            Ok(Err(e)) => DnsFuzzOutcome::Error(e.to_string()),
            Ok(Ok((n, _src))) => {
                let resp = &buf[..n];
                if resp.len() < 12 {
                    return DnsFuzzOutcome::MalformedResponse(resp.to_vec());
                }
                let recv_id = u16::from_be_bytes([resp[0], resp[1]]);
                if recv_id != sent_id {
                    return DnsFuzzOutcome::IdMismatch { sent: sent_id, received: recv_id };
                }
                let rcode = resp[3] & 0x0F;
                let answers = u16::from_be_bytes([resp[6], resp[7]]);
                DnsFuzzOutcome::Response { id: recv_id, rcode, answers }
            }
        }
    }

    #[must_use]
    pub fn results(&self) -> &[(DnsPacket, DnsFuzzOutcome)] { &self.results }

    #[must_use]
    pub fn anomalous_results(&self) -> Vec<&(DnsPacket, DnsFuzzOutcome)> {
        self.results.iter().filter(|(_, o)| o.is_anomalous()).collect()
    }

    /// Summary statistics.
    #[must_use]
    pub fn stats(&self) -> DnsFuzzStats {
        let total = self.results.len();
        let responses = self.results.iter().filter(|(_, o)| matches!(o, DnsFuzzOutcome::Response { .. })).count();
        let timeouts = self.results.iter().filter(|(_, o)| matches!(o, DnsFuzzOutcome::Timeout)).count();
        let malformed = self.results.iter().filter(|(_, o)| matches!(o, DnsFuzzOutcome::MalformedResponse(_))).count();
        let errors = self.results.iter().filter(|(_, o)| matches!(o, DnsFuzzOutcome::Error(_))).count();
        let id_mismatches = self.results.iter().filter(|(_, o)| matches!(o, DnsFuzzOutcome::IdMismatch { .. })).count();
        DnsFuzzStats { total, responses, timeouts, malformed, errors, id_mismatches }
    }
}

/// DNS fuzzer statistics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsFuzzStats {
    pub total: usize,
    pub responses: usize,
    pub timeouts: usize,
    pub malformed: usize,
    pub errors: usize,
    pub id_mismatches: usize,
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_dns_name_simple() {
        let encoded = encode_dns_name("example.com");
        // 7 'e' + 3 'c' + root = 0x07 + example + 0x03 + com + 0x00
        assert_eq!(encoded[0], 7);
        assert_eq!(&encoded[1..8], b"example");
        assert_eq!(encoded[8], 3);
        assert_eq!(&encoded[9..12], b"com");
        assert_eq!(encoded[12], 0);
    }

    #[test]
    fn encode_dns_name_root() {
        let encoded = encode_dns_name(".");
        assert_eq!(encoded, vec![0u8]);
    }

    #[test]
    fn dns_message_serialize_has_header() {
        let q = DnsQuestion::new("example.com", DnsQType::A);
        let msg = DnsMessage::new_query(0x1234, q);
        let bytes = msg.serialize();
        assert_eq!(&bytes[0..2], &[0x12, 0x34]); // ID
        assert!(bytes.len() > 12);
    }

    #[test]
    fn dns_flags_query_recursive() {
        let flags = DnsFlags::query_recursive();
        let v = flags.to_u16();
        assert_eq!(v & 0x0100, 0x0100); // RD bit set
        assert_eq!(v & 0x8000, 0); // QR bit clear (query)
    }

    #[test]
    fn edns0_opt_record() {
        let edns = build_edns0(4096, true, vec![]);
        assert_eq!(edns[0], 0x00); // root name
        assert_eq!(&edns[1..3], &[0x00, 0x29]); // OPT type = 41
        assert_eq!(&edns[3..5], &[0x10, 0x00]); // UDP payload = 4096
    }

    #[test]
    fn mutation_long_name() {
        let packets = apply_dns_mutation(&DnsMutation::LongDomainName { len: 253 }, "example.com", 0x0001);
        assert!(!packets.is_empty());
        assert!(packets[0].bytes.len() > 12 + 253);
    }

    #[test]
    fn mutation_empty_qname() {
        let packets = apply_dns_mutation(&DnsMutation::EmptyQName, "example.com", 0x0001);
        assert_eq!(packets.len(), 1);
        // The packet should have minimal question with just root label
        assert!(packets[0].bytes.len() < 30);
    }

    #[test]
    fn mutation_zero_id() {
        let packets = apply_dns_mutation(&DnsMutation::ZeroId, "example.com", 0x1234);
        assert_eq!(packets[0].bytes[0], 0); // ID high byte
        assert_eq!(packets[0].bytes[1], 0); // ID low byte
    }

    #[test]
    fn mutation_truncate_message() {
        let packets = apply_dns_mutation(&DnsMutation::TruncateMessage(2), "example.com", 0x0001);
        assert_eq!(packets[0].bytes.len(), 2);
    }

    #[test]
    fn mutation_all_record_types() {
        let packets = apply_dns_mutation(&DnsMutation::AllRecordTypes, "example.com", 0x0001);
        assert!(packets.len() > 5);
    }

    #[test]
    fn mutation_multiple_questions() {
        let packets = apply_dns_mutation(&DnsMutation::MultipleQuestions { count: 5 }, "example.com", 0x0001);
        assert_eq!(packets.len(), 1);
        let qdcount = u16::from_be_bytes([packets[0].bytes[4], packets[0].bytes[5]]);
        assert_eq!(qdcount, 5);
    }

    #[test]
    fn dns_fuzz_outcome_anomalous() {
        assert!(DnsFuzzOutcome::MalformedResponse(vec![]).is_anomalous());
        assert!(DnsFuzzOutcome::Error("test".into()).is_anomalous());
        assert!(DnsFuzzOutcome::IdMismatch { sent: 1, received: 2 }.is_anomalous());
        assert!(!DnsFuzzOutcome::Timeout.is_anomalous());
        assert!(!DnsFuzzOutcome::Response { id: 1, rcode: 0, answers: 1 }.is_anomalous());
    }

    #[test]
    fn qtype_as_u16() {
        assert_eq!(DnsQType::A.as_u16(), 1);
        assert_eq!(DnsQType::AAAA.as_u16(), 28);
        assert_eq!(DnsQType::ANY.as_u16(), 255);
        assert_eq!(DnsQType::Raw(12345).as_u16(), 12345);
    }
}
