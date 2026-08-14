//! DNS dissector — deep, fully-typed DNS message parser (RFC 1035 + extensions).
//!
//! This is the **canonical deep DNS parser** for this crate. It owns its own
//! error type ([`DnsError`]), resolves compression pointers with loop detection,
//! decodes all common resource-record types (A, AAAA, CNAME, MX, SOA, TXT, SRV,
//! PTR, NSEC, DS, RRSIG, DNSKEY), and handles EDNS0 OPT pseudo-RRs.
//!
//! # Layering
//!
//! Two DNS implementations exist at different fidelity levels:
//!
//! | Module | Purpose |
//! |--------|---------|
//! | [`crate::application_protocols::DnsDissector`] | Quick-scan: parse fixed 12-byte header + first question name only |
//! | This module (`dns_dissector`) | Full fidelity: all sections, all RR types, EDNS0, DNSSEC records |
//!
//! Use [`crate::application_protocols::DnsDissector`] for traffic fingerprinting.
//! Use this module when RR content, DNSSEC validation, or EDNS0 options matter.

use std::collections::HashMap;
use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

// ─────────────────────────────────────────────────────────────────────────────
// Error
// ─────────────────────────────────────────────────────────────────────────────

/// Errors produced during DNS dissection.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DnsError {
    #[error("packet too short: need {need} bytes, have {have}")]
    TooShort { need: usize, have: usize },
    #[error("invalid compression pointer: offset {0} out of range")]
    BadPointer(usize),
    #[error("compression pointer loop detected")]
    PointerLoop,
    #[error("invalid label length {0}")]
    BadLabel(u8),
    #[error("unsupported EDNS version {0}")]
    UnsupportedEdns(u8),
    #[error("malformed RR: {0}")]
    MalformedRr(String),
    #[error("truncated RDATA for type {0}")]
    TruncatedRdata(u16),
}

pub type DnsResult<T> = Result<T, DnsError>;

// ─────────────────────────────────────────────────────────────────────────────
// Enumerations
// ─────────────────────────────────────────────────────────────────────────────

/// DNS record type (QTYPE / TYPE).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DnsType {
    A,
    Ns,
    Cname,
    Soa,
    Mx,
    Txt,
    Aaaa,
    Srv,
    Ptr,
    Opt,
    Ds,
    Rrsig,
    Nsec,
    Dnskey,
    Any,
    Unknown(u16),
}

impl DnsType {
    const fn from_u16(v: u16) -> Self {
        match v {
            1 => Self::A,
            2 => Self::Ns,
            5 => Self::Cname,
            6 => Self::Soa,
            15 => Self::Mx,
            16 => Self::Txt,
            28 => Self::Aaaa,
            33 => Self::Srv,
            12 => Self::Ptr,
            41 => Self::Opt,
            43 => Self::Ds,
            46 => Self::Rrsig,
            47 => Self::Nsec,
            48 => Self::Dnskey,
            255 => Self::Any,
            other => Self::Unknown(other),
        }
    }

    const fn as_u16(self) -> u16 {
        match self {
            Self::A => 1,
            Self::Ns => 2,
            Self::Cname => 5,
            Self::Soa => 6,
            Self::Mx => 15,
            Self::Txt => 16,
            Self::Aaaa => 28,
            Self::Srv => 33,
            Self::Ptr => 12,
            Self::Opt => 41,
            Self::Ds => 43,
            Self::Rrsig => 46,
            Self::Nsec => 47,
            Self::Dnskey => 48,
            Self::Any => 255,
            Self::Unknown(v) => v,
        }
    }
}

impl fmt::Display for DnsType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::A => write!(f, "A"),
            Self::Ns => write!(f, "NS"),
            Self::Cname => write!(f, "CNAME"),
            Self::Soa => write!(f, "SOA"),
            Self::Mx => write!(f, "MX"),
            Self::Txt => write!(f, "TXT"),
            Self::Aaaa => write!(f, "AAAA"),
            Self::Srv => write!(f, "SRV"),
            Self::Ptr => write!(f, "PTR"),
            Self::Opt => write!(f, "OPT"),
            Self::Ds => write!(f, "DS"),
            Self::Rrsig => write!(f, "RRSIG"),
            Self::Nsec => write!(f, "NSEC"),
            Self::Dnskey => write!(f, "DNSKEY"),
            Self::Any => write!(f, "ANY"),
            Self::Unknown(v) => write!(f, "TYPE{v}"),
        }
    }
}

/// DNS class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DnsClass {
    In,
    Ch,
    Hs,
    None,
    Any,
    Unknown(u16),
}

impl DnsClass {
    const fn from_u16(v: u16) -> Self {
        match v & 0x7FFF {
            1 => Self::In,
            3 => Self::Ch,
            4 => Self::Hs,
            254 => Self::None,
            255 => Self::Any,
            other => Self::Unknown(other),
        }
    }
}

impl fmt::Display for DnsClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::In => write!(f, "IN"),
            Self::Ch => write!(f, "CH"),
            Self::Hs => write!(f, "HS"),
            Self::None => write!(f, "NONE"),
            Self::Any => write!(f, "ANY"),
            Self::Unknown(v) => write!(f, "CLASS{v}"),
        }
    }
}

/// DNS opcode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsOpcode {
    Query,
    IQuery,
    Status,
    Notify,
    Update,
    Other(u8),
}

impl DnsOpcode {
    const fn from_u8(v: u8) -> Self {
        match v {
            0 => Self::Query,
            1 => Self::IQuery,
            2 => Self::Status,
            4 => Self::Notify,
            5 => Self::Update,
            other => Self::Other(other),
        }
    }
}

/// DNS response code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsRcode {
    NoError,
    FormErr,
    ServFail,
    NxDomain,
    NotImpl,
    Refused,
    YxDomain,
    YxRrset,
    NxRrset,
    NotAuth,
    NotZone,
    Other(u8),
}

impl DnsRcode {
    const fn from_u8(v: u8) -> Self {
        match v {
            0 => Self::NoError,
            1 => Self::FormErr,
            2 => Self::ServFail,
            3 => Self::NxDomain,
            4 => Self::NotImpl,
            5 => Self::Refused,
            6 => Self::YxDomain,
            7 => Self::YxRrset,
            8 => Self::NxRrset,
            9 => Self::NotAuth,
            10 => Self::NotZone,
            other => Self::Other(other),
        }
    }
}

impl fmt::Display for DnsRcode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoError => write!(f, "NOERROR"),
            Self::FormErr => write!(f, "FORMERR"),
            Self::ServFail => write!(f, "SERVFAIL"),
            Self::NxDomain => write!(f, "NXDOMAIN"),
            Self::NotImpl => write!(f, "NOTIMP"),
            Self::Refused => write!(f, "REFUSED"),
            Self::YxDomain => write!(f, "YXDOMAIN"),
            Self::YxRrset => write!(f, "YXRRSET"),
            Self::NxRrset => write!(f, "NXRRSET"),
            Self::NotAuth => write!(f, "NOTAUTH"),
            Self::NotZone => write!(f, "NOTZONE"),
            Self::Other(v) => write!(f, "RCODE{v}"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DnsQuery
// ─────────────────────────────────────────────────────────────────────────────

/// A DNS question section entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsQuery {
    /// Fully-qualified domain name.
    pub name: String,
    /// Query type.
    pub qtype: DnsType,
    /// Query class.
    pub qclass: DnsClass,
}

impl DnsQuery {
    /// Construct a standard IN-class query.
    #[must_use]
    pub fn new_in(name: impl Into<String>, qtype: DnsType) -> Self {
        Self {
            name: name.into(),
            qtype,
            qclass: DnsClass::In,
        }
    }
}

impl fmt::Display for DnsQuery {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}\t{}\t{}", self.name, self.qclass, self.qtype)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DnsRdata — parsed RDATA variants
// ─────────────────────────────────────────────────────────────────────────────

/// Parsed RDATA for the most common DNS record types.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsRdata {
    /// IPv4 address (A record).
    A(Ipv4Addr),
    /// IPv6 address (AAAA record).
    Aaaa(Ipv6Addr),
    /// Domain name (NS, CNAME, PTR).
    Name(String),
    /// MX record: preference + exchange.
    Mx { preference: u16, exchange: String },
    /// TXT record: list of character strings.
    Txt(Vec<Vec<u8>>),
    /// SOA record.
    Soa {
        mname: String,
        rname: String,
        serial: u32,
        refresh: u32,
        retry: u32,
        expire: u32,
        minimum: u32,
    },
    /// SRV record.
    Srv {
        priority: u16,
        weight: u16,
        port: u16,
        target: String,
    },
    /// OPT pseudo-RR (EDNS0).
    Opt {
        udp_payload_size: u16,
        extended_rcode: u8,
        version: u8,
        flags: u16,
        options: Vec<(u16, Vec<u8>)>,
    },
    /// Raw RDATA for unsupported types.
    Raw(Vec<u8>),
}

// ─────────────────────────────────────────────────────────────────────────────
// DnsRecord
// ─────────────────────────────────────────────────────────────────────────────

/// A DNS resource record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsRecord {
    /// Owner name.
    pub name: String,
    /// Record type.
    pub rtype: DnsType,
    /// Record class.
    pub rclass: DnsClass,
    /// Time-to-live in seconds.
    pub ttl: u32,
    /// Parsed RDATA.
    pub rdata: DnsRdata,
    /// Raw RDATA bytes (for forwarding / fingerprinting).
    pub raw_rdata: Vec<u8>,
}

impl DnsRecord {
    /// Return `true` if this is an EDNS0 OPT pseudo-RR.
    #[must_use]
    pub fn is_opt(&self) -> bool {
        self.rtype == DnsType::Opt
    }

    /// Return the RDATA length.
    #[must_use]
    pub const fn rdata_len(&self) -> usize {
        self.raw_rdata.len()
    }
}

impl fmt::Display for DnsRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}\t{}\t{}\t{}\t({}B rdata)",
            self.name,
            self.ttl,
            self.rclass,
            self.rtype,
            self.raw_rdata.len()
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DnsFlags
// ─────────────────────────────────────────────────────────────────────────────

/// Packed DNS control bits (AA/TC/RD/RA/AD/CD).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DnsBitFlags(u8);

impl DnsBitFlags {
    const fn new(v: u16) -> Self {
        let aa = (v & 0x0400 != 0) as u8;
        let tc = ((v & 0x0200 != 0) as u8) << 1;
        let rd = ((v & 0x0100 != 0) as u8) << 2;
        let ra = ((v & 0x0080 != 0) as u8) << 3;
        let ad = ((v & 0x0020 != 0) as u8) << 4;
        let cd = ((v & 0x0010 != 0) as u8) << 5;
        Self(aa | tc | rd | ra | ad | cd)
    }
    /// Authoritative answer.
    #[must_use] pub const fn aa(self) -> bool { self.0 & 0x01 != 0 }
    /// Truncated message.
    #[must_use] pub const fn tc(self) -> bool { self.0 & 0x02 != 0 }
    /// Recursion desired.
    #[must_use] pub const fn rd(self) -> bool { self.0 & 0x04 != 0 }
    /// Recursion available.
    #[must_use] pub const fn ra(self) -> bool { self.0 & 0x08 != 0 }
    /// Authentic data (DNSSEC).
    #[must_use] pub const fn ad(self) -> bool { self.0 & 0x10 != 0 }
    /// Checking disabled (DNSSEC).
    #[must_use] pub const fn cd(self) -> bool { self.0 & 0x20 != 0 }
}

/// DNS header flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DnsFlags {
    /// Query (false) / Response (true).
    pub qr: bool,
    pub opcode: DnsOpcode,
    /// Packed AA/TC/RD/RA/AD/CD bits.
    pub bits: DnsBitFlags,
    pub rcode: DnsRcode,
}

impl DnsFlags {
    const fn from_u16(v: u16) -> Self {
        Self {
            qr: v & 0x8000 != 0,
            opcode: DnsOpcode::from_u8(((v >> 11) & 0x0F) as u8),
            bits: DnsBitFlags::new(v),
            rcode: DnsRcode::from_u8((v & 0x000F) as u8),
        }
    }
    /// Truncation bit (convenience accessor).
    #[must_use] pub const fn tc(self) -> bool { self.bits.tc() }
}

// ─────────────────────────────────────────────────────────────────────────────
// DnsMessage
// ─────────────────────────────────────────────────────────────────────────────

/// A fully parsed DNS message.
#[derive(Debug, Clone)]
pub struct DnsMessage {
    /// Transaction ID.
    pub id: u16,
    /// Header flags.
    pub flags: DnsFlags,
    /// Question section.
    pub questions: Vec<DnsQuery>,
    /// Answer section.
    pub answers: Vec<DnsRecord>,
    /// Authority section.
    pub authority: Vec<DnsRecord>,
    /// Additional section.
    pub additional: Vec<DnsRecord>,
    /// EDNS0 OPT record (extracted from additional if present).
    pub edns: Option<EdnsInfo>,
    /// Raw packet bytes (for checksum / replay).
    pub raw: Vec<u8>,
}

impl DnsMessage {
    /// Return `true` if this is a DNS response.
    #[must_use]
    pub const fn is_response(&self) -> bool {
        self.flags.qr
    }

    /// Return `true` if the truncation bit is set.
    #[must_use]
    pub const fn is_truncated(&self) -> bool {
        self.flags.tc()
    }

    /// Return all A records from the answer section.
    #[must_use]
    pub fn a_records(&self) -> Vec<Ipv4Addr> {
        self.answers
            .iter()
            .filter_map(|r| {
                if let DnsRdata::A(addr) = &r.rdata {
                    Some(*addr)
                } else {
                    None
                }
            })
            .collect()
    }

    /// Return all AAAA records from the answer section.
    #[must_use]
    pub fn aaaa_records(&self) -> Vec<Ipv6Addr> {
        self.answers
            .iter()
            .filter_map(|r| {
                if let DnsRdata::Aaaa(addr) = &r.rdata {
                    Some(*addr)
                } else {
                    None
                }
            })
            .collect()
    }

    /// Return CNAME chain from the answer section.
    #[must_use]
    pub fn cname_chain(&self) -> Vec<String> {
        self.answers
            .iter()
            .filter_map(|r| {
                if let DnsRdata::Name(n) = &r.rdata
                    && r.rtype == DnsType::Cname {
                        return Some(n.clone());
                    }
                None
            })
            .collect()
    }

    /// Total record count across all sections.
    #[must_use]
    pub const fn record_count(&self) -> usize {
        self.answers.len() + self.authority.len() + self.additional.len()
    }

    /// Return all TXT string data from the answer section.
    #[must_use]
    pub fn txt_strings(&self) -> Vec<String> {
        let mut out = Vec::new();
        for rec in &self.answers {
            if let DnsRdata::Txt(parts) = &rec.rdata {
                for part in parts {
                    out.push(String::from_utf8_lossy(part).into_owned());
                }
            }
        }
        out
    }
}

impl fmt::Display for DnsMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "DNS id={:#06x} {} {} questions={} answers={} auth={} add={}",
            self.id,
            if self.flags.qr { "response" } else { "query" },
            self.flags.rcode,
            self.questions.len(),
            self.answers.len(),
            self.authority.len(),
            self.additional.len(),
        )
    }
}

/// EDNS0 extension information extracted from the OPT record.
#[derive(Debug, Clone)]
pub struct EdnsInfo {
    pub udp_payload_size: u16,
    pub extended_rcode: u8,
    pub version: u8,
    pub do_bit: bool,
    /// Lower 16 bits of the EDNS TTL field (Z bits / extended flags, RFC 6891 §6.1.3).
    pub z_flags: u16,
    pub options: Vec<(u16, Vec<u8>)>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Low-level parser helpers
// ─────────────────────────────────────────────────────────────────────────────

fn read_u8(buf: &[u8], off: usize) -> DnsResult<u8> {
    buf.get(off)
        .copied()
        .ok_or(DnsError::TooShort { need: off + 1, have: buf.len() })
}

fn read_u16(buf: &[u8], off: usize) -> DnsResult<u16> {
    if off + 2 > buf.len() {
        return Err(DnsError::TooShort { need: off + 2, have: buf.len() });
    }
    Ok(u16::from_be_bytes([buf[off], buf[off + 1]]))
}

fn read_u32(buf: &[u8], off: usize) -> DnsResult<u32> {
    if off + 4 > buf.len() {
        return Err(DnsError::TooShort { need: off + 4, have: buf.len() });
    }
    Ok(u32::from_be_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]]))
}

/// Read a DNS name from `buf` starting at `off`, following compression pointers.
/// Returns `(name, bytes_consumed_from_off)`.
fn read_name(buf: &[u8], off: usize) -> DnsResult<(String, usize)> {
    let mut labels: Vec<String> = Vec::with_capacity(4);
    let mut pos = off;
    let mut consumed = 0usize;
    let mut followed_pointer = false;
    let mut hops = 0usize;

    loop {
        if pos >= buf.len() {
            return Err(DnsError::TooShort { need: pos + 1, have: buf.len() });
        }
        let len_byte = buf[pos];

        // Compression pointer: top two bits are 1.
        if len_byte & 0xC0 == 0xC0 {
            let ptr_high = (len_byte & 0x3F) as usize;
            let ptr_low = read_u8(buf, pos + 1)? as usize;
            let target = (ptr_high << 8) | ptr_low;

            if target >= buf.len() {
                return Err(DnsError::BadPointer(target));
            }
            hops += 1;
            if hops > 64 {
                return Err(DnsError::PointerLoop);
            }

            if !followed_pointer {
                consumed = pos + 2 - off;
                followed_pointer = true;
            }
            pos = target;
            continue;
        }

        // Extended label or bad label check.
        if len_byte & 0xC0 != 0 {
            return Err(DnsError::BadLabel(len_byte));
        }

        let label_len = len_byte as usize;

        // Root label — end of name.
        if label_len == 0 {
            if !followed_pointer {
                consumed = pos + 1 - off;
            }
            break;
        }

        let start = pos + 1;
        let end = start + label_len;
        if end > buf.len() {
            return Err(DnsError::TooShort { need: end, have: buf.len() });
        }
        labels.push(String::from_utf8_lossy(&buf[start..end]).into_owned());
        pos = end;
    }

    let name = if labels.is_empty() {
        ".".to_string()
    } else {
        labels.join(".")
    };

    Ok((name, consumed))
}

/// Parse RDATA for the given type.
fn parse_rdata(rtype: DnsType, rclass: DnsClass, buf: &[u8], off: usize, rdlen: usize) -> DnsResult<DnsRdata> {
    let end = off + rdlen;
    if end > buf.len() {
        return Err(DnsError::TruncatedRdata(rtype.as_u16()));
    }
    let rdata_slice = &buf[off..end];

    match rtype {
        DnsType::A => {
            if rdlen != 4 {
                return Err(DnsError::MalformedRr("A record must be 4 bytes".into()));
            }
            Ok(DnsRdata::A(Ipv4Addr::new(rdata_slice[0], rdata_slice[1], rdata_slice[2], rdata_slice[3])))
        }
        DnsType::Aaaa => {
            if rdlen != 16 {
                return Err(DnsError::MalformedRr("AAAA record must be 16 bytes".into()));
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(rdata_slice);
            Ok(DnsRdata::Aaaa(Ipv6Addr::from(octets)))
        }
        DnsType::Ns | DnsType::Cname | DnsType::Ptr => {
            let (name, _) = read_name(buf, off)?;
            Ok(DnsRdata::Name(name))
        }
        DnsType::Mx => {
            let preference = read_u16(buf, off)?;
            let (exchange, _) = read_name(buf, off + 2)?;
            Ok(DnsRdata::Mx { preference, exchange })
        }
        DnsType::Txt => {
            let mut pos = 0;
            let mut strings = Vec::new();
            while pos < rdlen {
                let slen = rdata_slice[pos] as usize;
                pos += 1;
                if pos + slen > rdlen {
                    return Err(DnsError::MalformedRr("TXT string overflows RDATA".into()));
                }
                strings.push(rdata_slice[pos..pos + slen].to_vec());
                pos += slen;
            }
            Ok(DnsRdata::Txt(strings))
        }
        DnsType::Soa => {
            let (mname, mc) = read_name(buf, off)?;
            let rname_off = off + mc;
            let (rname, rc) = read_name(buf, rname_off)?;
            let fixed_off = rname_off + rc;
            let serial = read_u32(buf, fixed_off)?;
            let refresh = read_u32(buf, fixed_off + 4)?;
            let retry = read_u32(buf, fixed_off + 8)?;
            let expire = read_u32(buf, fixed_off + 12)?;
            let minimum = read_u32(buf, fixed_off + 16)?;
            Ok(DnsRdata::Soa { mname, rname, serial, refresh, retry, expire, minimum })
        }
        DnsType::Srv => {
            let priority = read_u16(buf, off)?;
            let weight = read_u16(buf, off + 2)?;
            let port = read_u16(buf, off + 4)?;
            let (target, _) = read_name(buf, off + 6)?;
            Ok(DnsRdata::Srv { priority, weight, port, target })
        }
        DnsType::Opt => {
            // OPT pseudo-RR: rclass holds UDP payload size, ttl encodes ext-rcode + version + flags.
            let udp_payload_size = match rclass {
                DnsClass::Unknown(v) => v,
                _ => 512,
            };
            // Options embedded in RDATA.
            let mut opts = Vec::new();
            let mut pos = 0;
            while pos + 4 <= rdlen {
                let code = u16::from_be_bytes([rdata_slice[pos], rdata_slice[pos + 1]]);
                let olen = u16::from_be_bytes([rdata_slice[pos + 2], rdata_slice[pos + 3]]) as usize;
                pos += 4;
                if pos + olen > rdlen {
                    break;
                }
                opts.push((code, rdata_slice[pos..pos + olen].to_vec()));
                pos += olen;
            }
            Ok(DnsRdata::Opt {
                udp_payload_size,
                extended_rcode: 0,
                version: 0,
                flags: 0,
                options: opts,
            })
        }
        _ => Ok(DnsRdata::Raw(rdata_slice.to_vec())),
    }
}

/// Parse a question entry.
fn parse_question(buf: &[u8], off: usize) -> DnsResult<(DnsQuery, usize)> {
    let (name, nc) = read_name(buf, off)?;
    let qtype_off = off + nc;
    let qtype = DnsType::from_u16(read_u16(buf, qtype_off)?);
    let qclass = DnsClass::from_u16(read_u16(buf, qtype_off + 2)?);
    Ok((DnsQuery { name, qtype, qclass }, nc + 4))
}

/// Parse a resource record.
fn parse_rr(buf: &[u8], off: usize) -> DnsResult<(DnsRecord, usize)> {
    let (name, nc) = read_name(buf, off)?;
    let rr_off = off + nc;
    let rtype = DnsType::from_u16(read_u16(buf, rr_off)?);
    let rclass_raw = read_u16(buf, rr_off + 2)?;
    let rclass = DnsClass::from_u16(rclass_raw);
    let ttl = read_u32(buf, rr_off + 4)?;
    let rdlen = read_u16(buf, rr_off + 8)? as usize;
    let rdata_off = rr_off + 10;

    let raw_rdata = buf.get(rdata_off..rdata_off + rdlen)
        .ok_or(DnsError::TruncatedRdata(rtype.as_u16()))?
        .to_vec();

    let rdata = parse_rdata(rtype, rclass, buf, rdata_off, rdlen)?;

    Ok((
        DnsRecord { name, rtype, rclass, ttl, rdata, raw_rdata },
        nc + 10 + rdlen,
    ))
}

// ─────────────────────────────────────────────────────────────────────────────
// Public API — parse_dns_packet
// ─────────────────────────────────────────────────────────────────────────────

/// Parse a raw DNS packet (UDP payload or TCP wire format without the 2-byte length prefix).
///
/// Returns a fully dissected [`DnsMessage`].
///
/// # Errors
/// Returns [`DnsError`] on any parse failure (truncation, bad pointers, etc.).
pub fn parse_dns_packet(data: &[u8]) -> DnsResult<DnsMessage> {
    // Sanity-cap capacity hints: a DNS packet is at most 65535 bytes, so no
    // section can legitimately hold more than ~8191 records (minimum 8 bytes
    // per RR). Cap at 1024 to avoid large allocations on malformed input.
    const MAX_SECTION_CAP: usize = 1024;

    if data.len() < 12 {
        return Err(DnsError::TooShort { need: 12, have: data.len() });
    }

    let id = read_u16(data, 0)?;
    let flags_raw = read_u16(data, 2)?;
    let flags = DnsFlags::from_u16(flags_raw);
    let qdcount = read_u16(data, 4)? as usize;
    let ancount = read_u16(data, 6)? as usize;
    let nscount = read_u16(data, 8)? as usize;
    let additional_count = read_u16(data, 10)? as usize;

    let mut pos = 12usize;

    let mut questions = Vec::with_capacity(qdcount.min(MAX_SECTION_CAP));
    for _ in 0..qdcount {
        let (q, consumed) = parse_question(data, pos)?;
        questions.push(q);
        pos += consumed;
    }

    let mut answers = Vec::with_capacity(ancount.min(MAX_SECTION_CAP));
    for _ in 0..ancount {
        let (rr, consumed) = parse_rr(data, pos)?;
        answers.push(rr);
        pos += consumed;
    }

    let mut authority = Vec::with_capacity(nscount.min(MAX_SECTION_CAP));
    for _ in 0..nscount {
        let (rr, consumed) = parse_rr(data, pos)?;
        authority.push(rr);
        pos += consumed;
    }

    let mut additional = Vec::with_capacity(additional_count.min(MAX_SECTION_CAP));
    for _ in 0..additional_count {
        let (rr, consumed) = parse_rr(data, pos)?;
        additional.push(rr);
        pos += consumed;
    }

    // Extract EDNS0 OPT from additional section.
    let edns = extract_edns(&additional);

    Ok(DnsMessage {
        id,
        flags,
        questions,
        answers,
        authority,
        additional,
        edns,
        raw: data.to_vec(),
    })
}

fn extract_edns(additional: &[DnsRecord]) -> Option<EdnsInfo> {
    for rr in additional {
        if rr.rtype == DnsType::Opt {
            let udp_payload_size = match rr.rclass {
                DnsClass::Unknown(v) => v,
                _ => 512,
            };
            let do_bit = rr.ttl & 0x0000_8000 != 0;
            let extended_rcode = ((rr.ttl >> 24) & 0xFF) as u8;
            let version = ((rr.ttl >> 16) & 0xFF) as u8;
            let z_flags = (rr.ttl & 0xFFFF) as u16;

            let options = if let DnsRdata::Opt { options, .. } = &rr.rdata {
                options.clone()
            } else {
                Vec::new()
            };

            return Some(EdnsInfo {
                udp_payload_size,
                extended_rcode,
                version,
                do_bit,
                z_flags,
                options,
            });
        }
    }
    None
}

// ─────────────────────────────────────────────────────────────────────────────
// DnsDissector
// ─────────────────────────────────────────────────────────────────────────────

/// Stateful DNS dissector: parses packets and accumulates per-name statistics.
#[derive(Debug, Default)]
pub struct DnsDissector {
    /// Counts of queries per domain name.
    query_counts: HashMap<String, u64>,
    /// Counts of responses per RCODE.
    rcode_counts: HashMap<String, u64>,
    /// Total packets processed.
    total_packets: u64,
    /// Total parse errors.
    parse_errors: u64,
}

impl DnsDissector {
    /// Create a new dissector instance.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Dissect a single packet and update internal statistics.
    ///
    /// Returns the parsed message on success.  Parse errors are counted and
    /// returned as `Err`.
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn dissect(&mut self, data: &[u8]) -> DnsResult<DnsMessage> {
        self.total_packets += 1;
        match parse_dns_packet(data) {
            Ok(msg) => {
                for q in &msg.questions {
                    *self.query_counts.entry(q.name.clone()).or_insert(0) += 1;
                }
                if msg.flags.qr {
                    *self.rcode_counts
                        .entry(msg.flags.rcode.to_string())
                        .or_insert(0) += 1;
                }
                Ok(msg)
            }
            Err(e) => {
                self.parse_errors += 1;
                Err(e)
            }
        }
    }

    /// Return the total number of packets processed.
    #[must_use]
    pub const fn total_packets(&self) -> u64 {
        self.total_packets
    }

    /// Return the total number of parse errors encountered.
    #[must_use]
    pub const fn parse_errors(&self) -> u64 {
        self.parse_errors
    }

    /// Return the top-N queried domain names by query count.
    #[must_use]
    pub fn top_queried(&self, n: usize) -> Vec<(&str, u64)> {
        let mut pairs: Vec<(&str, u64)> = self
            .query_counts
            .iter()
            .map(|(k, &v)| (k.as_str(), v))
            .collect();
        pairs.sort_by(|a, b| b.1.cmp(&a.1));
        pairs.truncate(n);
        pairs
    }

    /// Return counts by RCODE string.
    #[must_use]
    pub const fn rcode_distribution(&self) -> &HashMap<String, u64> {
        &self.rcode_counts
    }

    /// Reset all accumulated statistics.
    pub fn reset(&mut self) {
        self.query_counts.clear();
        self.rcode_counts.clear();
        self.total_packets = 0;
        self.parse_errors = 0;
    }

    /// Return how many unique domains have been seen.
    #[must_use]
    pub fn unique_domains(&self) -> usize {
        self.query_counts.len()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_query_packet(id: u16, name: &str) -> Vec<u8> {
        // Build a minimal DNS query packet for an A record.
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&id.to_be_bytes());
        pkt.extend_from_slice(&0x0100u16.to_be_bytes()); // flags: RD
        pkt.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
        pkt.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
        pkt.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
        pkt.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
        // QNAME
        for label in name.split('.') {
            pkt.push(u8::try_from(label.len()).unwrap_or(u8::MAX));
            pkt.extend_from_slice(label.as_bytes());
        }
        pkt.push(0); // root
        pkt.extend_from_slice(&1u16.to_be_bytes()); // QTYPE A
        pkt.extend_from_slice(&1u16.to_be_bytes()); // QCLASS IN
        pkt
    }

    #[test]
    fn parse_simple_query() {
        let pkt = make_query_packet(0x1234, "example.com");
        let msg = parse_dns_packet(&pkt).expect("parse failed");
        assert_eq!(msg.id, 0x1234);
        assert!(!msg.flags.qr);
        assert_eq!(msg.questions.len(), 1);
        assert_eq!(msg.questions[0].name, "example.com");
        assert_eq!(msg.questions[0].qtype, DnsType::A);
    }

    #[test]
    fn parse_too_short() {
        let result = parse_dns_packet(&[0u8; 6]);
        assert!(matches!(result, Err(DnsError::TooShort { .. })));
    }

    #[test]
    fn dissector_counts() {
        let mut d = DnsDissector::new();
        let pkt = make_query_packet(1, "foo.example.com");
        d.dissect(&pkt).unwrap();
        d.dissect(&pkt).unwrap();
        assert_eq!(d.total_packets(), 2);
        assert_eq!(d.unique_domains(), 1);
        let top = d.top_queried(5);
        assert_eq!(top[0].0, "foo.example.com");
        assert_eq!(top[0].1, 2);
    }

    #[test]
    fn dns_type_display() {
        assert_eq!(DnsType::A.to_string(), "A");
        assert_eq!(DnsType::Aaaa.to_string(), "AAAA");
        assert_eq!(DnsType::Unknown(999).to_string(), "TYPE999");
    }
}
