//! `rustre-net-rules` — Network traffic rules and signature engine.
//!
//! Implements Snort-style rule parsing, a rule engine that evaluates rules
//! against packets, and a persistent `RuleStore` backed by both `SQLite` and
//! `MySQL`.

#![forbid(unsafe_code)]

pub mod packet_matcher;
pub mod rule_compiler;
pub mod rule_engine_full;
pub mod snort_extended;
pub mod snort_rules;
pub mod suricata_rules;
pub mod protocol_signatures;
pub mod suricata_rule_parser;
pub mod protocol_fingerprinter;
pub mod traffic_classifier;
pub mod rule_engine;
pub mod signature_matcher;
pub mod alert_correlator;

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::net::IpAddr;

use mysql::prelude::Queryable;
use parking_lot::RwLock;
use regex::Regex;
use rusqlite::Connection as SqliteConnection;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use rustre_net::{TcpFlags, parse_tcp, parse_udp};

// ────────────────────────────────────────────────────────────────────────────
// Error type
// ────────────────────────────────────────────────────────────────────────────

/// Errors that can occur in the rules subsystem.
#[derive(Debug, Error)]
pub enum RuleError {
    #[error("parse error at token '{token}': {msg}")]
    ParseError { token: String, msg: String },

    #[error("invalid rule ID: {0}")]
    InvalidId(u32),

    #[error("rule not found: {0}")]
    NotFound(u32),

    #[error("SQLite error: {0}")]
    Sqlite(#[from] rusqlite::Error),

    #[error("MySQL error: {0}")]
    Mysql(String),

    #[error("serialization error: {0}")]
    Serialization(String),

    #[error("duplicate rule ID: {0}")]
    DuplicateId(u32),

    #[error("unsupported condition: {0}")]
    UnsupportedCondition(String),
}

// ────────────────────────────────────────────────────────────────────────────
// Rule action
// ────────────────────────────────────────────────────────────────────────────

/// Action taken when a rule matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RuleAction {
    Alert,
    Pass,
    Drop,
    Log,
    Reject,
}

impl fmt::Display for RuleAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Alert => "alert",
            Self::Pass => "pass",
            Self::Drop => "drop",
            Self::Log => "log",
            Self::Reject => "reject",
        };
        write!(f, "{s}")
    }
}

pub type Action = RuleAction;

// ────────────────────────────────────────────────────────────────────────────
// Protocol
// ────────────────────────────────────────────────────────────────────────────

/// IP protocol selector.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Proto {
    Tcp,
    Udp,
    Icmp,
    Any,
}

impl fmt::Display for Proto {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
            Self::Icmp => "icmp",
            Self::Any => "any",
        };
        write!(f, "{s}")
    }
}

// ────────────────────────────────────────────────────────────────────────────
// IP specification
// ────────────────────────────────────────────────────────────────────────────

/// An IP address specification for rule matching.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IpSpec {
    /// Match any address.
    Any,
    /// Match a single address.
    Single(IpAddr),
    /// Match an inclusive address range.
    Range(IpAddr, IpAddr),
    /// Match a CIDR prefix.
    Cidr(IpAddr, u8),
    /// Match multiple alternatives.
    Group(Vec<Self>),
    /// Negate the inner spec.
    Not(Box<Self>),
}

impl IpSpec {
    /// Returns `true` if `addr` matches this specification.
    #[must_use]
    pub fn matches(&self, addr: IpAddr) -> bool {
        match self {
            Self::Any => true,
            Self::Single(a) => *a == addr,
            Self::Range(lo, hi) => addr >= *lo && addr <= *hi,
            Self::Cidr(net, prefix) => cidr_contains(*net, *prefix, addr),
            Self::Group(specs) => specs.iter().any(|s| s.matches(addr)),
            Self::Not(inner) => !inner.matches(addr),
        }
    }
}

fn cidr_contains(net: IpAddr, prefix: u8, addr: IpAddr) -> bool {
    match (net, addr) {
        (IpAddr::V4(n), IpAddr::V4(a)) => {
            if prefix == 0 {
                return true;
            }
            if prefix > 32 {
                return false;
            }
            let mask = u32::MAX << (32 - prefix);
            (u32::from(n) & mask) == (u32::from(a) & mask)
        }
        (IpAddr::V6(n), IpAddr::V6(a)) => {
            if prefix == 0 {
                return true;
            }
            if prefix > 128 {
                return false;
            }
            let n_bits = u128::from(n);
            let a_bits = u128::from(a);
            let mask = u128::MAX << (128 - prefix);
            (n_bits & mask) == (a_bits & mask)
        }
        _ => false,
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Port specification
// ────────────────────────────────────────────────────────────────────────────

/// A port specification for rule matching.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PortSpec {
    Any,
    Single(u16),
    Range(u16, u16),
    List(Vec<u16>),
    Not(Box<Self>),
}

impl PortSpec {
    /// Returns `true` if `port` matches this specification.
    #[must_use]
    pub fn matches(&self, port: u16) -> bool {
        match self {
            Self::Any => true,
            Self::Single(p) => *p == port,
            Self::Range(lo, hi) => port >= *lo && port <= *hi,
            Self::List(ports) => ports.contains(&port),
            Self::Not(inner) => !inner.matches(port),
        }
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Network specification (IP + port)
// ────────────────────────────────────────────────────────────────────────────

/// Combined IP + port network specification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkSpec {
    pub addr: IpSpec,
    pub port: PortSpec,
}

impl NetworkSpec {
    #[must_use]
    pub const fn any() -> Self {
        Self {
            addr: IpSpec::Any,
            port: PortSpec::Any,
        }
    }

    #[must_use]
    pub fn matches(&self, addr: IpAddr, port: u16) -> bool {
        self.addr.matches(addr) && self.port.matches(port)
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Condition
// ────────────────────────────────────────────────────────────────────────────

/// A rule condition evaluated against the packet payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Condition {
    /// Match if payload contains the given byte pattern.
    Content(Vec<u8>),
    /// Match by Perl-compatible regex string (evaluated as substring search here).
    Pcre(String),
    /// Match if payload size is within [min, max].
    DSize { min: u32, max: u32 },
    /// Match TCP flags.
    Flags(TcpFlags),
    /// Byte offset within the payload for the next Content match.
    Offset(usize),
    /// Maximum depth from start for Content match.
    Depth(usize),
    /// Within N bytes of the last match.
    Within(usize),
    /// Distance N bytes from the last match.
    Distance(usize),
    /// Match if IP TTL equals value.
    Ttl(u8),
    /// Match if source port equals value.
    SrcPort(u16),
    /// Match if destination port equals value.
    DstPort(u16),
}

impl fmt::Display for Condition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Content(b) => {
                let s = String::from_utf8_lossy(b);
                write!(f, "content:\"{s}\"")
            }
            Self::Pcre(s) => write!(f, "pcre:\"{s}\""),
            Self::DSize { min, max } => write!(f, "dsize:{min}<>{max}"),
            Self::Flags(fl) => write!(f, "flags:{fl}"),
            Self::Offset(o) => write!(f, "offset:{o}"),
            Self::Depth(d) => write!(f, "depth:{d}"),
            Self::Within(w) => write!(f, "within:{w}"),
            Self::Distance(d) => write!(f, "distance:{d}"),
            Self::Ttl(t) => write!(f, "ttl:{t}"),
            Self::SrcPort(p) => write!(f, "src_port:{p}"),
            Self::DstPort(p) => write!(f, "dst_port:{p}"),
        }
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Rule
// ────────────────────────────────────────────────────────────────────────────

/// A complete network traffic rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub id: u32,
    pub action: RuleAction,
    pub proto: Proto,
    pub src: NetworkSpec,
    pub dst: NetworkSpec,
    pub conditions: Vec<Condition>,
    pub msg: String,
    /// Whether the rule is currently active.
    pub enabled: bool,
}

impl Rule {
    pub fn new(
        id: u32,
        action: RuleAction,
        proto: Proto,
        src: NetworkSpec,
        dst: NetworkSpec,
        msg: impl Into<String>,
    ) -> Self {
        Self {
            id,
            action,
            proto,
            src,
            dst,
            conditions: Vec::new(),
            msg: msg.into(),
            enabled: true,
        }
    }
}

impl fmt::Display for Rule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} ... (msg:\"{}\", id:{})",
            self.action, self.proto, self.msg, self.id
        )
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Match result
// ────────────────────────────────────────────────────────────────────────────

/// Result of evaluating a rule set against a packet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchResult {
    pub matched: bool,
    pub rule_id: u32,
    pub action: RuleAction,
    pub msg: String,
}

impl fmt::Display for MatchResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.matched {
            write!(
                f,
                "MATCH rule={} action={} msg=\"{}\"",
                self.rule_id, self.action, self.msg
            )
        } else {
            write!(f, "NO MATCH rule={}", self.rule_id)
        }
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Packet context for rule evaluation
// ────────────────────────────────────────────────────────────────────────────

/// Minimal packet information needed for rule evaluation.
#[derive(Debug, Clone)]
pub struct PacketContext {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    /// IP protocol number.
    pub ip_proto: u8,
    pub ttl: u8,
    pub payload: Vec<u8>,
    /// TCP flags (0 if not TCP).
    pub tcp_flags: TcpFlags,
}

impl PacketContext {
    /// Build a context from a raw IPv4 packet buffer.
    #[must_use]
    pub fn from_ipv4(data: &[u8]) -> Option<Self> {
        let ip = rustre_net::parse_ipv4(data).ok()?;
        let (src_port, dst_port, tcp_flags, payload) = match ip.protocol {
            6 => {
                let tcp = parse_tcp(&ip.payload).ok()?;
                (tcp.src_port, tcp.dst_port, tcp.flags, tcp.payload)
            }
            17 => {
                let udp = parse_udp(&ip.payload).ok()?;
                (udp.src_port, udp.dst_port, TcpFlags::empty(), udp.payload)
            }
            _ => (0, 0, TcpFlags::empty(), ip.payload),
        };
        Some(Self {
            src_ip: ip.src,
            dst_ip: ip.dst,
            src_port,
            dst_port,
            ip_proto: ip.protocol,
            ttl: ip.ttl,
            payload,
            tcp_flags,
        })
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Rule engine
// ────────────────────────────────────────────────────────────────────────────

/// Evaluates rules against packets.
pub struct RuleEngine {
    rules: RwLock<Vec<Rule>>,
}

impl RuleEngine {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            rules: RwLock::new(Vec::new()),
        }
    }

    /// Add a rule to the engine.
    pub fn add_rule(&self, rule: Rule) {
        self.rules.write().push(rule);
    }

    /// Remove a rule by ID.
    pub fn remove_rule(&self, id: u32) {
        self.rules.write().retain(|r| r.id != id);
    }

    /// Return all rules.
    pub fn rules(&self) -> Vec<Rule> {
        self.rules.read().clone()
    }

    /// Evaluate all enabled rules against a packet context.
    /// Returns the first matching result (highest-priority first).
    pub fn evaluate(&self, ctx: &PacketContext) -> Option<MatchResult> {
        self.rules
            .read()
            .iter()
            .find(|rule| rule.enabled && rule_matches(rule, ctx))
            .map(|rule| MatchResult {
                matched: true,
                rule_id: rule.id,
                action: rule.action,
                msg: rule.msg.clone(),
            })
    }

    /// Evaluate all rules and return all matches.
    pub fn evaluate_all(&self, ctx: &PacketContext) -> Vec<MatchResult> {
        let rules = self.rules.read();
        rules
            .iter()
            .filter(|r| r.enabled && rule_matches(r, ctx))
            .map(|r| MatchResult {
                matched: true,
                rule_id: r.id,
                action: r.action,
                msg: r.msg.clone(),
            })
            .collect()
    }
}

impl Default for RuleEngine {
    fn default() -> Self {
        Self::new()
    }
}

fn rule_matches(rule: &Rule, ctx: &PacketContext) -> bool {
    // Check protocol
    match rule.proto {
        Proto::Tcp if ctx.ip_proto != 6 => return false,
        Proto::Udp if ctx.ip_proto != 17 => return false,
        Proto::Icmp if ctx.ip_proto != 1 => return false,
        _ => {}
    }
    // Check source and destination
    if !rule.src.matches(ctx.src_ip, ctx.src_port) {
        return false;
    }
    if !rule.dst.matches(ctx.dst_ip, ctx.dst_port) {
        return false;
    }

    // Evaluate conditions
    let mut last_match_end: usize = 0;
    let mut current_offset: usize = 0;
    let mut current_depth: usize = ctx.payload.len();

    for cond in &rule.conditions {
        match cond {
            Condition::Content(pattern) => {
                let search_start = current_offset;
                let search_end = current_depth.min(ctx.payload.len());
                if search_start > search_end {
                    return false;
                }
                let search_space = &ctx.payload[search_start..search_end];
                if let Some(pos) = find_bytes(search_space, pattern) {
                    last_match_end = search_start + pos + pattern.len();
                    // Reset depth for next content match
                    current_offset = 0;
                    current_depth = ctx.payload.len();
                } else {
                    return false;
                }
            }
            Condition::Pcre(pattern) => {
                let haystack = std::str::from_utf8(&ctx.payload).unwrap_or("");
                match Regex::new(pattern.as_str()) {
                    Ok(re) => {
                        if !re.is_match(haystack) {
                            return false;
                        }
                    }
                    Err(_) => {
                        // Invalid regex pattern: treat as non-match to avoid silently passing
                        return false;
                    }
                }
            }
            Condition::DSize { min, max } => {
                let sz = u32::try_from(ctx.payload.len()).unwrap_or(u32::MAX);
                if sz < *min || sz > *max {
                    return false;
                }
            }
            Condition::Flags(required) => {
                if !ctx.tcp_flags.contains(*required) {
                    return false;
                }
            }
            Condition::Offset(o) => {
                current_offset = *o;
            }
            Condition::Depth(d) => {
                current_depth = current_offset.saturating_add(*d);
            }
            Condition::Within(w) => {
                current_offset = last_match_end;
                current_depth = last_match_end.saturating_add(*w);
            }
            Condition::Distance(d) => {
                current_offset = last_match_end.saturating_add(*d);
            }
            Condition::Ttl(t) => {
                if ctx.ttl != *t {
                    return false;
                }
            }
            Condition::SrcPort(p) => {
                if ctx.src_port != *p {
                    return false;
                }
            }
            Condition::DstPort(p) => {
                if ctx.dst_port != *p {
                    return false;
                }
            }
        }
    }
    true
}

/// Naive byte-pattern search (Boyer-Moore-like would be better, but this is correct).
fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

// ────────────────────────────────────────────────────────────────────────────
// Rule parser (Snort-style syntax)
// ────────────────────────────────────────────────────────────────────────────

/// Parses Snort-style rule strings.
///
/// Minimal supported syntax:
/// ```text
/// alert tcp 192.168.1.0/24 any -> $EXTERNAL_NET 80 (msg:"Test"; content:"evil"; sid:1001; rev:1;)
/// ```
pub struct RuleParser;

impl RuleParser {
    /// Parse a single rule string.
    ///
    /// # Errors
    ///
    /// Returns [`RuleError::ParseError`] if the input is not a valid rule.
    pub fn parse(input: &str) -> Result<Rule, RuleError> {
        let input = input.trim();
        if input.is_empty() || input.starts_with('#') {
            return Err(RuleError::ParseError {
                token: input.to_string(),
                msg: "empty or comment line".to_string(),
            });
        }

        // Split header and options: "action proto src srcport dir dst dstport (options)"
        let paren_start = input.find('(').ok_or_else(|| RuleError::ParseError {
            token: input.to_string(),
            msg: "missing options block '('".to_string(),
        })?;
        let paren_end = input.rfind(')').ok_or_else(|| RuleError::ParseError {
            token: input.to_string(),
            msg: "missing options block ')'".to_string(),
        })?;
        if paren_end <= paren_start {
            return Err(RuleError::ParseError {
                token: input.to_string(),
                msg: "options block ')' precedes '('".to_string(),
            });
        }

        let header = &input[..paren_start].trim();
        let options_str = &input[paren_start + 1..paren_end];

        let tokens: Vec<&str> = header.split_whitespace().collect();
        if tokens.len() < 7 {
            return Err(RuleError::ParseError {
                token: (*header).to_string(),
                msg: format!("expected 7 header tokens, got {}", tokens.len()),
            });
        }

        let action = parse_action(tokens[0])?;
        let proto = parse_proto(tokens[1])?;
        let src_ip = parse_ip_spec(tokens[2])?;
        let src_port = parse_port_spec(tokens[3])?;
        // tokens[4] is direction ("->", "<>", "<-") — ignored for now
        let dst_ip = parse_ip_spec(tokens[5])?;
        let dst_port = parse_port_spec(tokens[6])?;

        let src = NetworkSpec {
            addr: src_ip,
            port: src_port,
        };
        let dst = NetworkSpec {
            addr: dst_ip,
            port: dst_port,
        };

        let (id, msg, conditions) = parse_options(options_str)?;

        Ok(Rule {
            id,
            action,
            proto,
            src,
            dst,
            conditions,
            msg,
            enabled: true,
        })
    }

    /// Parse multiple rules from a multi-line string, skipping blank lines and comments.
    pub fn parse_many(input: &str) -> Vec<Result<Rule, RuleError>> {
        input
            .lines()
            .filter(|l| {
                let t = l.trim();
                !t.is_empty() && !t.starts_with('#')
            })
            .map(Self::parse)
            .collect()
    }
}

fn parse_action(s: &str) -> Result<RuleAction, RuleError> {
    match s {
        "alert" => Ok(RuleAction::Alert),
        "pass" => Ok(RuleAction::Pass),
        "drop" => Ok(RuleAction::Drop),
        "log" => Ok(RuleAction::Log),
        "reject" => Ok(RuleAction::Reject),
        other => Err(RuleError::ParseError {
            token: other.to_string(),
            msg: "unknown action".to_string(),
        }),
    }
}

fn parse_proto(s: &str) -> Result<Proto, RuleError> {
    match s {
        "tcp" => Ok(Proto::Tcp),
        "udp" => Ok(Proto::Udp),
        "icmp" => Ok(Proto::Icmp),
        "any" | "ip" => Ok(Proto::Any),
        other => Err(RuleError::ParseError {
            token: other.to_string(),
            msg: "unknown protocol".to_string(),
        }),
    }
}

/// Parse a Snort-style IP spec (bare IP, `any`, `$VAR`, CIDR, or `[a,b,...]` group) into an [`IpSpec`].
///
/// Public entry point over the internal [`parse_ip_spec`] used by [`RuleParser::parse`].
///
/// # Errors
/// Returns [`RuleError::ParseError`] if the input is not a recognized IP spec.
pub fn parse_ip_spec_str(s: &str) -> Result<IpSpec, RuleError> {
    parse_ip_spec(s)
}

fn parse_ip_spec(s: &str) -> Result<IpSpec, RuleError> {
    if s == "any" || s.starts_with('$') {
        return Ok(IpSpec::Any);
    }
    if s.contains('/') {
        let parts: Vec<&str> = s.splitn(2, '/').collect();
        let addr: IpAddr = parts[0].parse().map_err(|_| RuleError::ParseError {
            token: s.to_string(),
            msg: "invalid IP address".to_string(),
        })?;
        let prefix: u8 = parts[1].parse().map_err(|_| RuleError::ParseError {
            token: s.to_string(),
            msg: "invalid prefix length".to_string(),
        })?;
        return Ok(IpSpec::Cidr(addr, prefix));
    }
    // Group: [addr1,addr2]
    if s.starts_with('[') && s.ends_with(']') {
        let inner = &s[1..s.len() - 1];
        let specs: Result<Vec<IpSpec>, _> =
            inner.split(',').map(|x| parse_ip_spec(x.trim())).collect();
        return Ok(IpSpec::Group(specs?));
    }
    let addr: IpAddr = s.parse().map_err(|_| RuleError::ParseError {
        token: s.to_string(),
        msg: "invalid IP address".to_string(),
    })?;
    Ok(IpSpec::Single(addr))
}

fn parse_port_spec(s: &str) -> Result<PortSpec, RuleError> {
    if s == "any" {
        return Ok(PortSpec::Any);
    }
    if let Some(stripped) = s.strip_prefix('!') {
        let inner = parse_port_spec(stripped)?;
        return Ok(PortSpec::Not(Box::new(inner)));
    }
    if s.contains(':') {
        let parts: Vec<&str> = s.splitn(2, ':').collect();
        let lo: u16 = parts[0].parse().map_err(|_| RuleError::ParseError {
            token: s.to_string(),
            msg: "invalid port range start".to_string(),
        })?;
        let hi: u16 = parts[1].parse().map_err(|_| RuleError::ParseError {
            token: s.to_string(),
            msg: "invalid port range end".to_string(),
        })?;
        return Ok(PortSpec::Range(lo, hi));
    }
    if s.starts_with('[') && s.ends_with(']') {
        let inner = &s[1..s.len() - 1];
        let ports: Result<Vec<u16>, _> =
            inner.split(',').map(|x| x.trim().parse::<u16>()).collect();
        let ports = ports.map_err(|_| RuleError::ParseError {
            token: s.to_string(),
            msg: "invalid port list".to_string(),
        })?;
        return Ok(PortSpec::List(ports));
    }
    let port: u16 = s.parse().map_err(|_| RuleError::ParseError {
        token: s.to_string(),
        msg: "invalid port number".to_string(),
    })?;
    Ok(PortSpec::Single(port))
}

fn parse_options(options: &str) -> Result<(u32, String, Vec<Condition>), RuleError> {
    let mut sid: u32 = 0;
    let mut msg = String::new();
    let mut conditions = Vec::new();

    // Split on ';' — but quoted strings may contain semicolons; handle simple case
    let parts = split_options(options);
    for part in &parts {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if let Some(rest) = part.strip_prefix("msg:") {
            msg = strip_one_quote_pair(rest).to_string();
        } else if let Some(rest) = part.strip_prefix("sid:") {
            sid = rest.trim().parse().map_err(|_| RuleError::ParseError {
                token: rest.to_string(),
                msg: "invalid sid".to_string(),
            })?;
        } else if let Some(rest) = part.strip_prefix("content:") {
            let pattern = parse_content_value(rest)?;
            conditions.push(Condition::Content(pattern));
        } else if let Some(rest) = part.strip_prefix("pcre:") {
            let s = strip_one_quote_pair(rest).to_string();
            conditions.push(Condition::Pcre(s));
        } else if let Some(rest) = part.strip_prefix("dsize:") {
            let cond = parse_dsize(rest)?;
            conditions.push(cond);
        } else if let Some(rest) = part.strip_prefix("flags:") {
            let flags = parse_tcp_flags_str(rest.trim());
            conditions.push(Condition::Flags(flags));
        } else if let Some(rest) = part.strip_prefix("offset:") {
            let o: usize = rest.trim().parse().map_err(|_| RuleError::ParseError {
                token: rest.to_string(),
                msg: "invalid offset".to_string(),
            })?;
            conditions.push(Condition::Offset(o));
        } else if let Some(rest) = part.strip_prefix("depth:") {
            let d: usize = rest.trim().parse().map_err(|_| RuleError::ParseError {
                token: rest.to_string(),
                msg: "invalid depth".to_string(),
            })?;
            conditions.push(Condition::Depth(d));
        } else if let Some(rest) = part.strip_prefix("within:") {
            let w: usize = rest.trim().parse().map_err(|_| RuleError::ParseError {
                token: rest.to_string(),
                msg: "invalid within".to_string(),
            })?;
            conditions.push(Condition::Within(w));
        } else if let Some(rest) = part.strip_prefix("distance:") {
            let d: usize = rest.trim().parse().map_err(|_| RuleError::ParseError {
                token: rest.to_string(),
                msg: "invalid distance".to_string(),
            })?;
            conditions.push(Condition::Distance(d));
        } else if let Some(rest) = part.strip_prefix("ttl:") {
            let t: u8 = rest.trim().parse().map_err(|_| RuleError::ParseError {
                token: rest.to_string(),
                msg: "invalid ttl".to_string(),
            })?;
            conditions.push(Condition::Ttl(t));
        }
        // rev: and other meta-fields are silently skipped
    }
    Ok((sid, msg, conditions))
}

fn strip_one_quote_pair(s: &str) -> &str {
    let s = s.trim();
    for q in ['"', '\''] {
        if s.len() >= 2 && s.starts_with(q) && s.ends_with(q) {
            return &s[1..s.len() - 1];
        }
    }
    s
}

fn split_options(options: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut in_quote = false;
    let mut quote_char = '"';
    for ch in options.chars() {
        if in_quote {
            current.push(ch);
            if ch == quote_char {
                in_quote = false;
            }
        } else if ch == '"' || ch == '\'' {
            in_quote = true;
            quote_char = ch;
            current.push(ch);
        } else if ch == ';' {
            parts.push(current.trim().to_string());
            current.clear();
        } else {
            current.push(ch);
        }
    }
    if !current.trim().is_empty() {
        parts.push(current.trim().to_string());
    }
    parts
}

fn parse_content_value(s: &str) -> Result<Vec<u8>, RuleError> {
    let s = s.trim();
    if s.starts_with('"') && s.ends_with('"') && s.len() >= 2 {
        return Ok(s.as_bytes()[1..s.len() - 1].to_vec());
    }
    // Hex pattern like |DE AD BE EF|
    if s.starts_with('|') && s.ends_with('|') {
        let hex = &s[1..s.len() - 1];
        let bytes: Result<Vec<u8>, _> = hex
            .split_whitespace()
            .map(|h| u8::from_str_radix(h, 16))
            .collect();
        return bytes.map_err(|_| RuleError::ParseError {
            token: s.to_string(),
            msg: "invalid hex content".to_string(),
        });
    }
    Ok(s.as_bytes().to_vec())
}

fn parse_dsize(s: &str) -> Result<Condition, RuleError> {
    // Formats: "100", "<>100:200", "100<>200"
    if s.contains("<>") {
        let parts: Vec<&str> = s.splitn(2, "<>").collect();
        let min: u32 = parts[0].trim().parse().unwrap_or(0);
        let max: u32 = parts[1].trim().parse().map_err(|_| RuleError::ParseError {
            token: s.to_string(),
            msg: "invalid dsize range".to_string(),
        })?;
        return Ok(Condition::DSize { min, max });
    }
    if let Some(stripped) = s.strip_prefix('<') {
        let max: u32 = stripped.trim().parse().map_err(|_| RuleError::ParseError {
            token: s.to_string(),
            msg: "invalid dsize".to_string(),
        })?;
        return Ok(Condition::DSize { min: 0, max });
    }
    if let Some(stripped) = s.strip_prefix('>') {
        let min: u32 = stripped.trim().parse().map_err(|_| RuleError::ParseError {
            token: s.to_string(),
            msg: "invalid dsize".to_string(),
        })?;
        return Ok(Condition::DSize { min, max: u32::MAX });
    }
    let exact: u32 = s.trim().parse().map_err(|_| RuleError::ParseError {
        token: s.to_string(),
        msg: "invalid dsize".to_string(),
    })?;
    Ok(Condition::DSize {
        min: exact,
        max: exact,
    })
}

fn parse_tcp_flags_str(s: &str) -> TcpFlags {
    let mut flags = TcpFlags::empty();
    for ch in s.chars() {
        match ch {
            'S' => flags |= TcpFlags::SYN,
            'A' => flags |= TcpFlags::ACK,
            'F' => flags |= TcpFlags::FIN,
            'R' => flags |= TcpFlags::RST,
            'P' => flags |= TcpFlags::PSH,
            'U' => flags |= TcpFlags::URG,
            _ => {}
        }
    }
    flags
}

// ────────────────────────────────────────────────────────────────────────────
// RuleStore — SQLite + MySQL persistence
// ────────────────────────────────────────────────────────────────────────────

/// Persistent rule storage backed by `SQLite`.
pub struct RuleStore {
    conn: RwLock<SqliteConnection>,
}

impl RuleStore {
    /// Open (or create) an `SQLite` rule store at the given path.
    ///
    /// # Errors
    ///
    /// Returns [`RuleError`] if the database cannot be opened or the schema cannot be created.
    pub fn open(path: &str) -> Result<Self, RuleError> {
        let conn = SqliteConnection::open(path)?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS rules (
                id      INTEGER PRIMARY KEY,
                action  TEXT NOT NULL,
                proto   TEXT NOT NULL,
                msg     TEXT NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 1,
                json    TEXT NOT NULL
            );",
        )?;
        Ok(Self {
            conn: RwLock::new(conn),
        })
    }

    /// Open an in-memory `SQLite` rule store (useful for testing).
    ///
    /// # Errors
    /// Returns [`RuleError::Sqlite`] when the underlying connection cannot be opened.
    pub fn in_memory() -> Result<Self, RuleError> {
        Self::open(":memory:")
    }

    /// Insert or replace a rule.
    ///
    /// # Errors
    /// Returns [`RuleError::Serialization`] if the rule cannot be encoded to JSON,
    /// or [`RuleError::Sqlite`] when the database operation fails.
    pub fn save_rule(&self, rule: &Rule) -> Result<(), RuleError> {
        let json =
            serde_json::to_string(rule).map_err(|e| RuleError::Serialization(e.to_string()))?;
        self.conn.write().execute(
            "INSERT OR REPLACE INTO rules (id, action, proto, msg, enabled, json)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params![
                rule.id,
                rule.action.to_string(),
                rule.proto.to_string(),
                rule.msg,
                i64::from(rule.enabled),
                json
            ],
        )?;
        Ok(())
    }

    /// Load all rules from the store.
    ///
    /// # Errors
    /// Returns [`RuleError::Sqlite`] when the query fails or
    /// [`RuleError::Serialization`] when a stored rule cannot be decoded.
    pub fn load_all(&self) -> Result<Vec<Rule>, RuleError> {
        let conn = self.conn.read();
        let mut stmt = conn.prepare("SELECT json FROM rules ORDER BY id")?;
        let rules: Result<Vec<Rule>, _> = stmt
            .query_map([], |row| {
                let json: String = row.get(0)?;
                Ok(json)
            })?
            .map(|r| {
                let json = r.map_err(RuleError::Sqlite)?;
                serde_json::from_str(&json).map_err(|e| RuleError::Serialization(e.to_string()))
            })
            .collect();
        drop(stmt);
        drop(conn);
        rules
    }

    /// Delete a rule by ID.
    ///
    /// # Errors
    /// Returns [`RuleError::NotFound`] when no rule has the given id,
    /// or [`RuleError::Sqlite`] when the database operation fails.
    pub fn delete_rule(&self, id: u32) -> Result<(), RuleError> {
        let affected = self
            .conn
            .write()
            .execute("DELETE FROM rules WHERE id = ?1", rusqlite::params![id])?;
        if affected == 0 {
            return Err(RuleError::NotFound(id));
        }
        Ok(())
    }

    /// Enable or disable a rule.
    ///
    /// # Errors
    /// Returns [`RuleError::NotFound`] when no rule has the given id,
    /// or [`RuleError::Sqlite`] when the database operation fails.
    pub fn set_enabled(&self, id: u32, enabled: bool) -> Result<(), RuleError> {
        let conn = self.conn.write();
        let json: String = match conn.query_row(
            "SELECT json FROM rules WHERE id = ?1",
            rusqlite::params![id],
            |row| row.get(0),
        ) {
            Ok(j) => j,
            Err(rusqlite::Error::QueryReturnedNoRows) => return Err(RuleError::NotFound(id)),
            Err(e) => return Err(RuleError::Sqlite(e)),
        };
        let mut rule: Rule = serde_json::from_str(&json)
            .map_err(|e| RuleError::Serialization(e.to_string()))?;
        rule.enabled = enabled;
        let new_json = serde_json::to_string(&rule)
            .map_err(|e| RuleError::Serialization(e.to_string()))?;
        let affected = conn.execute(
            "UPDATE rules SET enabled = ?1, json = ?2 WHERE id = ?3",
            rusqlite::params![i64::from(enabled), new_json, id],
        )?;
        drop(conn);
        if affected == 0 {
            return Err(RuleError::NotFound(id));
        }
        Ok(())
    }

    /// Count rules in the store.
    ///
    /// # Errors
    /// Returns [`RuleError::Sqlite`] when the query fails.
    pub fn count(&self) -> Result<u64, RuleError> {
        let n: i64 = self
            .conn
            .read()
            .query_row("SELECT COUNT(*) FROM rules", [], |r| r.get(0))?;
        Ok(n.cast_unsigned())
    }
}

// ────────────────────────────────────────────────────────────────────────────
// MySQL rule store
// ────────────────────────────────────────────────────────────────────────────

/// Persistent rule storage backed by `MySQL`.
///
/// Uses the `mysql` crate's synchronous connection pool.
pub struct MySqlRuleStore {
    pool: mysql::Pool,
}

impl MySqlRuleStore {
    /// Connect to a `MySQL` server and ensure the schema exists.
    ///
    /// # Errors
    /// Returns [`RuleError::Mysql`] when the connection or schema setup fails.
    pub fn connect(url: &str) -> Result<Self, RuleError> {
        let pool = mysql::Pool::new(url).map_err(|e| RuleError::Mysql(e.to_string()))?;
        let mut conn = pool
            .get_conn()
            .map_err(|e| RuleError::Mysql(e.to_string()))?;
        conn.query_drop(
            "CREATE TABLE IF NOT EXISTS rules (
                id      INT UNSIGNED PRIMARY KEY,
                action  VARCHAR(16) NOT NULL,
                proto   VARCHAR(8) NOT NULL,
                msg     TEXT NOT NULL,
                enabled TINYINT NOT NULL DEFAULT 1,
                json    MEDIUMTEXT NOT NULL
            )",
        )
        .map_err(|e| RuleError::Mysql(e.to_string()))?;
        Ok(Self { pool })
    }

    /// Insert or update a rule.
    ///
    /// # Errors
    /// Returns [`RuleError::Serialization`] when the rule cannot be encoded
    /// or [`RuleError::Mysql`] when the database operation fails.
    pub fn save_rule(&self, rule: &Rule) -> Result<(), RuleError> {
        let json =
            serde_json::to_string(rule).map_err(|e| RuleError::Serialization(e.to_string()))?;
        let mut conn = self
            .pool
            .get_conn()
            .map_err(|e| RuleError::Mysql(e.to_string()))?;
        conn.exec_drop(
            "INSERT INTO rules (id, action, proto, msg, enabled, json)
             VALUES (?, ?, ?, ?, ?, ?)
             ON DUPLICATE KEY UPDATE action=VALUES(action), proto=VALUES(proto),
               msg=VALUES(msg), enabled=VALUES(enabled), json=VALUES(json)",
            (
                rule.id,
                rule.action.to_string(),
                rule.proto.to_string(),
                &rule.msg,
                u8::from(rule.enabled),
                &json,
            ),
        )
        .map_err(|e| RuleError::Mysql(e.to_string()))?;
        Ok(())
    }

    /// Load all rules.
    ///
    /// # Errors
    /// Returns [`RuleError::Mysql`] when the query fails or
    /// [`RuleError::Serialization`] when a stored rule cannot be decoded.
    pub fn load_all(&self) -> Result<Vec<Rule>, RuleError> {
        let mut conn = self
            .pool
            .get_conn()
            .map_err(|e| RuleError::Mysql(e.to_string()))?;
        let rows: Vec<String> = conn
            .query_map("SELECT json FROM rules ORDER BY id", |json: String| json)
            .map_err(|e| RuleError::Mysql(e.to_string()))?;
        rows.iter()
            .map(|json| {
                serde_json::from_str(json).map_err(|e| RuleError::Serialization(e.to_string()))
            })
            .collect()
    }

    /// Delete a rule by ID.
    ///
    /// # Errors
    /// Returns [`RuleError::NotFound`] when no rule has the given id,
    /// or [`RuleError::Mysql`] when the database operation fails.
    pub fn delete_rule(&self, id: u32) -> Result<(), RuleError> {
        let mut conn = self
            .pool
            .get_conn()
            .map_err(|e| RuleError::Mysql(e.to_string()))?;
        conn.exec_drop("DELETE FROM rules WHERE id = ?", (id,))
            .map_err(|e| RuleError::Mysql(e.to_string()))?;
        Ok(())
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Spec-required types: Action, RuleProtocol, RuleDir, RuleOption, SpecRule,
// MatchPacket, SpecMatchResult, RuleSet, SpecRuleEngine
// ────────────────────────────────────────────────────────────────────────────

/// Spec-required protocol enum for rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RuleProtocol {
    Tcp,
    Udp,
    Icmp,
    Any,
}

impl fmt::Display for RuleProtocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
            Self::Icmp => "icmp",
            Self::Any => "any",
        };
        write!(f, "{s}")
    }
}

/// Spec-required direction enum for rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RuleDir {
    Unidirectional,
    Bidirectional,
}

impl fmt::Display for RuleDir {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Unidirectional => "->",
            Self::Bidirectional => "<>",
        };
        write!(f, "{s}")
    }
}

/// Spec-required rule option enum.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RuleOption {
    Content(Vec<u8>),
    Nocase,
    Offset(usize),
    Depth(usize),
    Pcre(String),
    Msg(String),
    Sid(u32),
    Rev(u32),
    Classtype(String),
    Within(usize),
}

impl fmt::Display for RuleOption {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Content(b) => write!(f, "content:\"{}\"", String::from_utf8_lossy(b)),
            Self::Nocase => write!(f, "nocase"),
            Self::Offset(o) => write!(f, "offset:{o}"),
            Self::Depth(d) => write!(f, "depth:{d}"),
            Self::Pcre(s) => write!(f, "pcre:\"{s}\""),
            Self::Msg(s) => write!(f, "msg:\"{s}\""),
            Self::Sid(n) => write!(f, "sid:{n}"),
            Self::Rev(n) => write!(f, "rev:{n}"),
            Self::Classtype(s) => write!(f, "classtype:{s}"),
            Self::Within(w) => write!(f, "within:{w}"),
        }
    }
}

/// Spec-required rule struct.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpecRule {
    pub action: RuleAction,
    pub proto: RuleProtocol,
    pub src: String,
    pub src_port: String,
    pub dir: RuleDir,
    pub dst: String,
    pub dst_port: String,
    pub options: Vec<RuleOption>,
}

impl SpecRule {
    /// Return the SID from options, if present.
    #[must_use]
    pub fn sid(&self) -> Option<u32> {
        self.options.iter().find_map(|o| {
            if let RuleOption::Sid(n) = o {
                Some(*n)
            } else {
                None
            }
        })
    }

    /// Return the message from options, if present.
    #[must_use]
    pub fn msg(&self) -> Option<&str> {
        self.options.iter().find_map(|o| {
            if let RuleOption::Msg(s) = o {
                Some(s.as_str())
            } else {
                None
            }
        })
    }

    /// Return all byte content patterns from options.
    #[must_use]
    pub fn content_patterns(&self) -> Vec<&[u8]> {
        self.options
            .iter()
            .filter_map(|o| {
                if let RuleOption::Content(b) = o {
                    Some(b.as_slice())
                } else {
                    None
                }
            })
            .collect()
    }
}

/// Spec-required packet for rule matching.
#[derive(Debug, Clone)]
pub struct MatchPacket {
    pub src_ip: String,
    pub dst_ip: String,
    pub src_port: u16,
    pub dst_port: u16,
    pub proto: RuleProtocol,
    pub payload: Vec<u8>,
}

/// Spec-required match result.
#[derive(Debug, Clone)]
pub struct SpecMatchResult {
    pub rule_sid: u32,
    pub action: RuleAction,
    pub msg: String,
    pub offsets: Vec<usize>,
}

/// Spec-required rule set container.
#[derive(Debug, Default)]
pub struct RuleSet {
    pub rules: Vec<SpecRule>,
}

impl RuleSet {
    /// Create an empty rule set.
    #[must_use]
    pub const fn new() -> Self {
        Self { rules: Vec::new() }
    }

    /// Add a rule to the set.
    pub fn add(&mut self, r: SpecRule) {
        self.rules.push(r);
    }

    /// Look up a rule by SID.
    #[must_use]
    pub fn by_sid(&self, sid: u32) -> Option<&SpecRule> {
        self.rules.iter().find(|r| r.sid() == Some(sid))
    }

    /// Return the number of rules in the set.
    #[must_use]
    pub const fn count(&self) -> usize {
        self.rules.len()
    }
}

/// Spec-required rule engine.
pub struct SpecRuleEngine {
    pub ruleset: RuleSet,
}

impl SpecRuleEngine {
    /// Create a new engine with the given rule set.
    #[must_use]
    pub const fn new(ruleset: RuleSet) -> Self {
        Self { ruleset }
    }

    /// Match a packet against all rules, returning all matching results.
    #[must_use]
    pub fn match_packet(&self, pkt: &MatchPacket) -> Vec<SpecMatchResult> {
        let mut results = Vec::with_capacity(self.ruleset.rules.len().min(8));
        for rule in &self.ruleset.rules {
            // Protocol check
            let proto_match = match rule.proto {
                RuleProtocol::Any => true,
                RuleProtocol::Tcp => pkt.proto == RuleProtocol::Tcp,
                RuleProtocol::Udp => pkt.proto == RuleProtocol::Udp,
                RuleProtocol::Icmp => pkt.proto == RuleProtocol::Icmp,
            };
            if !proto_match {
                continue;
            }

            // Port check (simple: "any" matches all)
            let src_port_ok =
                rule.src_port == "any" || rule.src_port.parse::<u16>().ok() == Some(pkt.src_port);
            let dst_port_ok =
                rule.dst_port == "any" || rule.dst_port.parse::<u16>().ok() == Some(pkt.dst_port);
            if !src_port_ok || !dst_port_ok {
                continue;
            }

            // IP check
            let src_ok = rule.src == "any" || rule.src == pkt.src_ip;
            let dst_ok = rule.dst == "any" || rule.dst == pkt.dst_ip;
            if !src_ok || !dst_ok {
                continue;
            }

            // Content pattern matching with sliding window
            let patterns = rule.content_patterns();
            let mut all_matched = true;
            let mut offsets = Vec::with_capacity(patterns.len());
            for pattern in &patterns {
                if let Some(pos) = find_first_occurrence(&pkt.payload, pattern) {
                    offsets.push(pos);
                } else {
                    all_matched = false;
                    break;
                }
            }
            if !all_matched && !patterns.is_empty() {
                continue;
            }

            let sid = rule.sid().unwrap_or(0);
            let msg = rule.msg().unwrap_or("").to_string();
            results.push(SpecMatchResult {
                rule_sid: sid,
                action: rule.action,
                msg,
                offsets,
            });
        }
        results
    }
}

#[inline]
fn find_first_occurrence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    if needle.len() > haystack.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Spec-required rule error.
#[derive(Debug, thiserror::Error)]
pub enum SpecRuleError {
    #[error("parse error: {0}")]
    ParseError(String),
    #[error("missing SID in rule")]
    MissingSid,
    #[error("invalid SID: {0}")]
    InvalidSid(u32),
}

// ────────────────────────────────────────────────────────────────────────────
// Aho-Corasick multi-pattern matcher
// ────────────────────────────────────────────────────────────────────────────

/// A match produced by the Aho-Corasick automaton.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AcMatch {
    /// Index of the matched pattern.
    pub pattern_idx: usize,
    /// Byte offset in the haystack where the match begins.
    pub start: usize,
    /// Byte offset just past the end of the match.
    pub end: usize,
}

/// Aho-Corasick automaton for simultaneous multi-pattern byte search.
///
/// Build-time complexity: O(Σ |pattern|). Search complexity: O(|text| + |matches|).
pub struct AhoCorasick {
    // goto[state][byte] = next_state (u32::MAX = no transition)
    goto: Vec<[u32; 256]>,
    // output[state] = list of pattern indices that end at this state
    output: Vec<Vec<usize>>,
    // lengths[pattern_idx] = length of the pattern
    lengths: Vec<usize>,
}

impl AhoCorasick {
    /// Build the automaton from a list of byte patterns.
    ///
    /// # Panics
    ///
    /// Panics if the number of states would overflow `u32`.
    #[must_use]
    pub fn build(patterns: &[&[u8]]) -> Self {
        const FAIL: u32 = u32::MAX;

        // State 0 is root
        let mut goto: Vec<[u32; 256]> = vec![[FAIL; 256]];
        let mut output: Vec<Vec<usize>> = vec![Vec::new()];
        let mut lengths: Vec<usize> = Vec::with_capacity(patterns.len());

        // Build goto trie
        for (pi, pattern) in patterns.iter().enumerate() {
            let mut state = 0usize;
            for &byte in *pattern {
                let b = byte as usize;
                if goto[state][b] == FAIL {
                    goto[state][b] = u32::try_from(goto.len()).expect("trie state overflow");
                    goto.push([FAIL; 256]);
                    output.push(Vec::new());
                }
                state = goto[state][b] as usize;
            }
            output[state].push(pi);
            lengths.push(pattern.len());
        }

        // Complete root state: missing transitions -> root (BFS-style)
        for cell in &mut goto[0] {
            if *cell == FAIL {
                *cell = 0;
            }
        }

        // Build failure function via BFS
        let n = goto.len();
        let mut fail: Vec<u32> = vec![0; n];
        let mut queue: std::collections::VecDeque<usize> = std::collections::VecDeque::new();

        // Depth-1 states: failure = root
        for &cell in &goto[0] {
            let s = cell as usize;
            if s != 0 {
                fail[s] = 0;
                queue.push_back(s);
            }
        }

        while let Some(r) = queue.pop_front() {
            for (b, &s_raw) in goto[r].iter().enumerate() {
                if s_raw == FAIL {
                    continue;
                }
                let s = s_raw as usize;
                queue.push_back(s);
                let mut state = fail[r] as usize;
                while goto[state][b] == FAIL {
                    state = fail[state] as usize;
                }
                fail[s] = goto[state][b];
                // Propagate outputs
                let fs = fail[s] as usize;
                let extra: Vec<usize> = output[fs].clone();
                output[s].extend_from_slice(&extra);
            }
            // Fill missing transitions (goto-complete)
            let snapshot: [u32; 256] = goto[r];
            for (b, &cell) in snapshot.iter().enumerate() {
                if cell == FAIL {
                    let mut state = fail[r] as usize;
                    while goto[state][b] == FAIL && state != 0 {
                        state = fail[state] as usize;
                    }
                    let next = goto[state][b];
                    goto[r][b] = if next == FAIL { 0 } else { next };
                }
            }
        }

        let _ = fail; // used only during build; not needed at search time
        Self {
            goto,
            output,
            lengths,
        }
    }

    /// Search `text` for all pattern occurrences, returning all matches.
    #[must_use]
    pub fn find_all(&self, text: &[u8]) -> Vec<AcMatch> {
        let mut matches = Vec::new();
        let mut state = 0usize;
        for (i, &byte) in text.iter().enumerate() {
            state = self.goto[state][byte as usize] as usize;
            for &pi in &self.output[state] {
                let end = i + 1;
                let pat_len = self.lengths[pi];
                // Guard against underflow: pat_len should never exceed end for a
                // correct AC build, but malformed state could violate this.
                let start = end.saturating_sub(pat_len);
                matches.push(AcMatch {
                    pattern_idx: pi,
                    start,
                    end,
                });
            }
        }
        matches
    }

    /// Returns the first match found, or `None` if no pattern matches.
    #[must_use]
    pub fn find_first(&self, text: &[u8]) -> Option<AcMatch> {
        let mut state = 0usize;
        for (i, &byte) in text.iter().enumerate() {
            state = self.goto[state][byte as usize] as usize;
            if let Some(&pi) = self.output[state].first() {
                let end = i + 1;
                let pat_len = self.lengths[pi];
                let start = end.saturating_sub(pat_len);
                return Some(AcMatch {
                    pattern_idx: pi,
                    start,
                    end,
                });
            }
        }
        None
    }

    /// Returns `true` if any pattern occurs in `text`.
    #[must_use]
    pub fn contains_any(&self, text: &[u8]) -> bool {
        self.find_first(text).is_some()
    }

    /// Returns the number of states in the automaton.
    #[must_use]
    pub const fn state_count(&self) -> usize {
        self.goto.len()
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Multi-pattern rule engine using Aho-Corasick
// ────────────────────────────────────────────────────────────────────────────

/// A compiled multi-pattern rule set that uses Aho-Corasick for efficient
/// simultaneous matching of all content patterns.
pub struct CompiledRuleSet {
    rules: Vec<Rule>,
    automaton: AhoCorasick,
    // rule_idx → list of pattern indices in the automaton
    rule_pattern_map: Vec<Vec<usize>>,
    // pattern_idx → rule_idx
    pattern_rule_map: Vec<usize>,
}

impl CompiledRuleSet {
    /// Compile a rule set into a `CompiledRuleSet` for fast matching.
    ///
    /// Only `Condition::Content` conditions are compiled into the automaton;
    /// other conditions are evaluated inline at match time.
    #[must_use]
    pub fn compile(rules: Vec<Rule>) -> Self {
        let mut all_patterns: Vec<Vec<u8>> = Vec::with_capacity(rules.len());
        let mut pattern_rule_map: Vec<usize> = Vec::with_capacity(rules.len());
        let mut rule_pattern_map: Vec<Vec<usize>> = Vec::with_capacity(rules.len());

        for (ri, rule) in rules.iter().enumerate() {
            let mut indices = Vec::new();
            for cond in &rule.conditions {
                if let Condition::Content(pattern) = cond {
                    let pi = all_patterns.len();
                    all_patterns.push(pattern.clone());
                    pattern_rule_map.push(ri);
                    indices.push(pi);
                }
            }
            rule_pattern_map.push(indices);
        }

        let slices: Vec<&[u8]> = all_patterns.iter().map(std::vec::Vec::as_slice).collect();
        let automaton = AhoCorasick::build(&slices);

        Self {
            rules,
            automaton,
            rule_pattern_map,
            pattern_rule_map,
        }
    }

    /// Evaluate the compiled rule set against a packet context.
    /// Returns all matching rules.
    #[must_use]
    pub fn evaluate(&self, ctx: &PacketContext) -> Vec<MatchResult> {
        // First, find all content pattern hits in the payload
        let matches = self.automaton.find_all(&ctx.payload);
        let mut hit_patterns: HashSet<usize> = matches.iter().map(|m| m.pattern_idx).collect();

        // For rules with no content patterns, every packet is a candidate
        let mut results = Vec::with_capacity(self.rules.len().min(8));

        for (ri, rule) in self.rules.iter().enumerate() {
            if !rule.enabled {
                continue;
            }

            // Protocol check
            match rule.proto {
                Proto::Tcp if ctx.ip_proto != 6 => continue,
                Proto::Udp if ctx.ip_proto != 17 => continue,
                Proto::Icmp if ctx.ip_proto != 1 => continue,
                _ => {}
            }

            // IP + port check
            if !rule.src.matches(ctx.src_ip, ctx.src_port) {
                continue;
            }
            if !rule.dst.matches(ctx.dst_ip, ctx.dst_port) {
                continue;
            }

            // Check that all content patterns for this rule matched
            let required = &self.rule_pattern_map[ri];
            if !required.iter().all(|pi| hit_patterns.contains(pi)) {
                continue;
            }

            // Evaluate non-content conditions
            let mut pass = true;
            for cond in &rule.conditions {
                match cond {
                    Condition::DSize { min, max } => {
                        let sz = u32::try_from(ctx.payload.len()).unwrap_or(u32::MAX);
                        if sz < *min || sz > *max {
                            pass = false;
                            break;
                        }
                    }
                    Condition::Flags(required_flags) => {
                        if !ctx.tcp_flags.contains(*required_flags) {
                            pass = false;
                            break;
                        }
                    }
                    Condition::Ttl(t) => {
                        if ctx.ttl != *t {
                            pass = false;
                            break;
                        }
                    }
                    Condition::SrcPort(p) => {
                        if ctx.src_port != *p {
                            pass = false;
                            break;
                        }
                    }
                    Condition::DstPort(p) => {
                        if ctx.dst_port != *p {
                            pass = false;
                            break;
                        }
                    }
                    Condition::Pcre(pattern) => {
                        let hay = std::str::from_utf8(&ctx.payload).unwrap_or("");
                        let is_hit = Regex::new(pattern.as_str())
                            .is_ok_and(|re| re.is_match(hay)); // invalid regex → non-match
                        if !is_hit {
                            pass = false;
                            break;
                        }
                    }
                    // Positional conditions: evaluated in the second pass below.
                    // Content(_): already checked via AC.
                    Condition::Content(_)
                    | Condition::Offset(_)
                    | Condition::Depth(_)
                    | Condition::Within(_)
                    | Condition::Distance(_) => {}
                }
            }

            // Second pass: re-evaluate positional conditions sequentially using the
            // same cursor-tracking logic as rule_matches, seeded by AC match offsets.
            if pass {
                // Build a sorted list of (start, end) for each content pattern of this rule.
                let rule_patterns = &self.rule_pattern_map[ri];
                // Map pattern_idx → first match start offset in the payload.
                let mut pattern_match_start: HashMap<usize, usize> = HashMap::new();
                for m in &matches {
                    if rule_patterns.contains(&m.pattern_idx) {
                        pattern_match_start.entry(m.pattern_idx).or_insert(m.start);
                    }
                }

                let mut last_match_end: usize = 0;
                let mut current_offset: usize = 0;
                let mut current_depth: usize = ctx.payload.len();
                let mut content_pattern_iter = rule_patterns.iter();

                for cond in &rule.conditions {
                    match cond {
                        Condition::Content(_) => {
                            // Advance to the next content pattern's AC match, within the
                            // current window.
                            if let Some(&pi) = content_pattern_iter.next() {
                                if let Some(&start) = pattern_match_start.get(&pi) {
                                    let pat_len = self.automaton.lengths[pi];
                                    // Verify the match falls within the current window.
                                    if start < current_offset || start + pat_len > current_depth {
                                        pass = false;
                                        break;
                                    }
                                    last_match_end = start + pat_len;
                                    current_offset = 0;
                                    current_depth = ctx.payload.len();
                                } else {
                                    pass = false;
                                    break;
                                }
                            }
                        }
                        Condition::Offset(o) => {
                            current_offset = *o;
                        }
                        Condition::Depth(d) => {
                            current_depth = current_offset + *d;
                        }
                        Condition::Within(w) => {
                            current_offset = last_match_end;
                            current_depth = last_match_end + *w;
                        }
                        Condition::Distance(d) => {
                            current_offset = last_match_end + *d;
                        }
                        _ => {}
                    }
                    if !pass {
                        break;
                    }
                }
            }

            if pass {
                results.push(MatchResult {
                    matched: true,
                    rule_id: rule.id,
                    action: rule.action,
                    msg: rule.msg.clone(),
                });
            }

            let _ = &mut hit_patterns;
        }
        results
    }

    /// Returns the number of rules in the compiled set.
    #[must_use]
    pub const fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// Returns the number of unique content patterns in the automaton.
    #[must_use]
    pub const fn pattern_count(&self) -> usize {
        self.pattern_rule_map.len()
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Threshold rules
// ────────────────────────────────────────────────────────────────────────────

/// Threshold type for rate-limiting alerts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ThresholdType {
    /// Alert only after N occurrences.
    Threshold,
    /// Alert only once per time window, regardless of occurrences.
    Limit,
    /// Alert once for every N occurrences.
    Both,
}

impl fmt::Display for ThresholdType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Threshold => write!(f, "threshold"),
            Self::Limit => write!(f, "limit"),
            Self::Both => write!(f, "both"),
        }
    }
}

/// Threshold tracking key.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ThresholdTrack {
    /// Track by source IP.
    BySrc,
    /// Track by destination IP.
    ByDst,
    /// Track rule-wide (all hosts combined).
    ByRule,
}

/// A threshold configuration for a rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThresholdConfig {
    pub rule_id: u32,
    pub threshold_type: ThresholdType,
    pub track: ThresholdTrack,
    /// Number of occurrences before triggering.
    pub count: u32,
    /// Time window in seconds.
    pub seconds: u64,
}

/// State tracked per (`rule_id`, `track_key`).
#[derive(Debug, Clone)]
struct ThresholdState {
    count: u32,
    window_start: u64,
    alerted: bool,
}

/// Threshold engine that wraps a `RuleEngine` with count-based rate limiting.
pub struct ThresholdEngine {
    engine: RuleEngine,
    thresholds: Vec<ThresholdConfig>,
    state: parking_lot::Mutex<HashMap<(u32, String), ThresholdState>>,
}

impl ThresholdEngine {
    /// Create a new threshold engine wrapping `engine`.
    #[must_use]
    pub fn new(engine: RuleEngine) -> Self {
        Self {
            engine,
            thresholds: Vec::new(),
            state: parking_lot::Mutex::new(HashMap::new()),
        }
    }

    /// Register a threshold configuration for a rule.
    pub fn add_threshold(&mut self, config: ThresholdConfig) {
        self.thresholds.push(config);
    }

    /// Evaluate the packet, respecting threshold rules.  `now_secs` is the
    /// current Unix timestamp in seconds.
    ///
    /// Returns `None` if no rule matches or the threshold suppresses the alert.
    #[must_use]
    pub fn evaluate(&self, ctx: &PacketContext, now_secs: u64) -> Option<MatchResult> {
        let result = self.engine.evaluate(ctx)?;
        let rid = result.rule_id;

        // Find threshold config for this rule
        let config = self.thresholds.iter().find(|t| t.rule_id == rid);
        let Some(cfg) = config else {
            return Some(result); // no threshold: always fire
        };

        let track_key = match cfg.track {
            ThresholdTrack::BySrc => ctx.src_ip.to_string(),
            ThresholdTrack::ByDst => ctx.dst_ip.to_string(),
            ThresholdTrack::ByRule => "__rule__".to_string(),
        };
        let map_key = (rid, track_key);

        let mut state_map = self.state.lock();
        let entry = state_map.entry(map_key).or_insert(ThresholdState {
            count: 0,
            window_start: now_secs,
            alerted: false,
        });

        // Check window expiry
        if now_secs.saturating_sub(entry.window_start) >= cfg.seconds {
            entry.count = 0;
            entry.window_start = now_secs;
            entry.alerted = false;
        }

        entry.count += 1;

        let should_alert = match cfg.threshold_type {
            ThresholdType::Threshold => entry.count >= cfg.count,
            ThresholdType::Limit => !entry.alerted,
            ThresholdType::Both => cfg.count != 0 && entry.count.is_multiple_of(cfg.count),
        };

        let out = if should_alert {
            entry.alerted = true;
            Some(result)
        } else {
            None
        };
        drop(state_map);
        out
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Suppression rules
// ────────────────────────────────────────────────────────────────────────────

/// A suppression entry that prevents alerts from firing for a given source/destination.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Suppression {
    pub rule_id: u32,
    pub track: ThresholdTrack,
    pub ip_spec: IpSpec,
}

impl Suppression {
    /// Returns `true` if this suppression applies to the given packet context for the given rule.
    #[must_use]
    pub fn suppresses(&self, rule_id: u32, ctx: &PacketContext) -> bool {
        if self.rule_id != rule_id {
            return false;
        }
        match self.track {
            ThresholdTrack::BySrc => self.ip_spec.matches(ctx.src_ip),
            ThresholdTrack::ByDst => self.ip_spec.matches(ctx.dst_ip),
            // ByRule suppresses all traffic for the matched rule regardless of
            // source or destination IP. The ip_spec is intentionally ignored here:
            // ByRule means "suppress this rule for everyone", not just a CIDR subset.
            ThresholdTrack::ByRule => true,
        }
    }
}

/// A rule engine with suppression support.
pub struct SuppressedEngine {
    engine: RuleEngine,
    suppressions: RwLock<Vec<Suppression>>,
}

impl SuppressedEngine {
    /// Create a new suppressed engine wrapping `engine`.
    #[must_use]
    pub const fn new(engine: RuleEngine) -> Self {
        Self {
            engine,
            suppressions: RwLock::new(Vec::new()),
        }
    }

    /// Add a suppression rule.
    pub fn add_suppression(&self, sup: Suppression) {
        self.suppressions.write().push(sup);
    }

    /// Evaluate, returning `None` if no rule fires or the result is suppressed.
    #[must_use]
    pub fn evaluate(&self, ctx: &PacketContext) -> Option<MatchResult> {
        let result = self.engine.evaluate(ctx)?;
        let suppressions = self.suppressions.read();
        let suppressed = suppressions.iter().any(|sup| sup.suppresses(result.rule_id, ctx));
        drop(suppressions);
        if suppressed { None } else { Some(result) }
    }

    /// Return all matches, filtering out suppressed ones.
    #[must_use]
    pub fn evaluate_all(&self, ctx: &PacketContext) -> Vec<MatchResult> {
        let results = self.engine.evaluate_all(ctx);
        let suppressions = self.suppressions.read();
        results
            .into_iter()
            .filter(|r| {
                !suppressions
                    .iter()
                    .any(|sup| sup.suppresses(r.rule_id, ctx))
            })
            .collect()
    }

    /// Returns the number of active suppressions.
    #[must_use]
    pub fn suppression_count(&self) -> usize {
        self.suppressions.read().len()
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Rule categories
// ────────────────────────────────────────────────────────────────────────────

/// Rule category for classification and filtering.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RuleCategory {
    MalwareC2,
    Exploitation,
    Reconnaissance,
    DataExfiltration,
    PolicyViolation,
    BruteForce,
    DoS,
    Trojan,
    Backdoor,
    Other,
}

impl fmt::Display for RuleCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MalwareC2 => write!(f, "malware-c2"),
            Self::Exploitation => write!(f, "exploitation"),
            Self::Reconnaissance => write!(f, "reconnaissance"),
            Self::DataExfiltration => write!(f, "data-exfiltration"),
            Self::PolicyViolation => write!(f, "policy-violation"),
            Self::BruteForce => write!(f, "brute-force"),
            Self::DoS => write!(f, "dos"),
            Self::Trojan => write!(f, "trojan"),
            Self::Backdoor => write!(f, "backdoor"),
            Self::Other => write!(f, "other"),
        }
    }
}

/// A rule with an associated category.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CategorizedRule {
    pub rule: Rule,
    pub category: RuleCategory,
    pub severity: u8, // 1 (low) … 5 (critical)
    pub references: Vec<String>,
}

impl CategorizedRule {
    /// Create a new categorized rule.
    #[must_use]
    pub fn new(rule: Rule, category: RuleCategory, severity: u8) -> Self {
        Self {
            rule,
            category,
            severity: severity.clamp(1, 5),
            references: Vec::new(),
        }
    }

    /// Add a CVE or URL reference.
    pub fn add_reference(&mut self, reference: impl Into<String>) {
        self.references.push(reference.into());
    }
}

/// A catalogue of categorized rules with category-level filtering.
pub struct RuleCatalogue {
    rules: RwLock<Vec<CategorizedRule>>,
}

impl RuleCatalogue {
    /// Create an empty catalogue.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            rules: RwLock::new(Vec::new()),
        }
    }

    /// Add a categorized rule.
    pub fn add(&self, rule: CategorizedRule) {
        self.rules.write().push(rule);
    }

    /// Get all rules for a category.
    #[must_use]
    pub fn by_category(&self, cat: RuleCategory) -> Vec<CategorizedRule> {
        self.rules
            .read()
            .iter()
            .filter(|r| r.category == cat)
            .cloned()
            .collect()
    }

    /// Get all rules with severity >= `min_severity`.
    #[must_use]
    pub fn by_min_severity(&self, min_severity: u8) -> Vec<CategorizedRule> {
        self.rules
            .read()
            .iter()
            .filter(|r| r.severity >= min_severity)
            .cloned()
            .collect()
    }

    /// Return the total number of rules.
    #[must_use]
    pub fn count(&self) -> usize {
        self.rules.read().len()
    }

    /// Build a `RuleEngine` from all rules in the catalogue.
    #[must_use]
    pub fn build_engine(&self) -> RuleEngine {
        let engine = RuleEngine::new();
        for cr in self.rules.read().iter() {
            engine.add_rule(cr.rule.clone());
        }
        engine
    }
}

impl Default for RuleCatalogue {
    fn default() -> Self {
        Self::new()
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Built-in rule sets
// ────────────────────────────────────────────────────────────────────────────

/// Build a catalogue with a minimal set of built-in detection rules covering
/// common attack categories.
#[must_use]
pub fn builtin_catalogue() -> RuleCatalogue {
    let cat = RuleCatalogue::new();

    // Malware C2: Cobalt Strike beacon check-in
    {
        let mut rule = Rule::new(
            10001,
            RuleAction::Alert,
            Proto::Tcp,
            NetworkSpec::any(),
            NetworkSpec::any(),
            "Cobalt Strike HTTP C2 beacon",
        );
        rule.conditions.push(Condition::Content(
            b"Content-Type: application/octet-stream".to_vec(),
        ));
        rule.conditions
            .push(Condition::DSize { min: 48, max: 4096 });
        let mut cr = CategorizedRule::new(rule, RuleCategory::MalwareC2, 5);
        cr.add_reference("https://www.cobaltstrike.com");
        cat.add(cr);
    }

    // Malware C2: Metasploit meterpreter reverse shell
    {
        let mut rule = Rule::new(
            10002,
            RuleAction::Alert,
            Proto::Tcp,
            NetworkSpec::any(),
            NetworkSpec::any(),
            "Meterpreter reverse shell",
        );
        rule.conditions
            .push(Condition::Content(b"\x4d\x5a\x90\x00".to_vec())); // MZ header
        let cr = CategorizedRule::new(rule, RuleCategory::MalwareC2, 5);
        cat.add(cr);
    }

    // Exploitation: EternalBlue SMB exploit
    {
        let mut rule = Rule::new(
            10003,
            RuleAction::Alert,
            Proto::Tcp,
            NetworkSpec::any(),
            NetworkSpec {
                addr: IpSpec::Any,
                port: PortSpec::Single(445),
            },
            "EternalBlue SMB exploit",
        );
        rule.conditions
            .push(Condition::Content(b"\xFFSMB".to_vec()));
        rule.conditions.push(Condition::DSize {
            min: 200,
            max: 65535,
        });
        let mut cr = CategorizedRule::new(rule, RuleCategory::Exploitation, 5);
        cr.add_reference("CVE-2017-0144");
        cat.add(cr);
    }

    // Exploitation: Shellshock
    {
        let mut rule = Rule::new(
            10004,
            RuleAction::Alert,
            Proto::Tcp,
            NetworkSpec::any(),
            NetworkSpec::any(),
            "Shellshock bash exploit",
        );
        rule.conditions
            .push(Condition::Content(b"() { :; };".to_vec()));
        let mut cr = CategorizedRule::new(rule, RuleCategory::Exploitation, 5);
        cr.add_reference("CVE-2014-6271");
        cat.add(cr);
    }

    // Reconnaissance: Nmap SYN scan
    {
        let mut rule = Rule::new(
            10005,
            RuleAction::Alert,
            Proto::Tcp,
            NetworkSpec::any(),
            NetworkSpec::any(),
            "Nmap SYN scan signature",
        );
        rule.conditions.push(Condition::Flags(TcpFlags::SYN));
        rule.conditions.push(Condition::DSize { min: 0, max: 0 }); // empty payload
        let cr = CategorizedRule::new(rule, RuleCategory::Reconnaissance, 2);
        cat.add(cr);
    }

    // Reconnaissance: DNS zone transfer
    {
        let mut rule = Rule::new(
            10006,
            RuleAction::Alert,
            Proto::Tcp,
            NetworkSpec::any(),
            NetworkSpec {
                addr: IpSpec::Any,
                port: PortSpec::Single(53),
            },
            "DNS zone transfer (AXFR)",
        );
        // AXFR qtype = 252 (0x00FC)
        rule.conditions
            .push(Condition::Content(b"\x00\xFC".to_vec()));
        let cr = CategorizedRule::new(rule, RuleCategory::Reconnaissance, 3);
        cat.add(cr);
    }

    // Data exfiltration: Large DNS TXT response
    {
        let mut rule = Rule::new(
            10007,
            RuleAction::Alert,
            Proto::Udp,
            NetworkSpec::any(),
            NetworkSpec::any(),
            "DNS data exfiltration (large TXT record)",
        );
        rule.conditions.push(Condition::DSize {
            min: 300,
            max: u32::MAX,
        });
        let cr = CategorizedRule::new(rule, RuleCategory::DataExfiltration, 3);
        cat.add(cr);
    }

    // Brute force: SSH login attempts
    {
        let mut rule = Rule::new(
            10008,
            RuleAction::Alert,
            Proto::Tcp,
            NetworkSpec::any(),
            NetworkSpec {
                addr: IpSpec::Any,
                port: PortSpec::Single(22),
            },
            "SSH brute force login attempt",
        );
        rule.conditions.push(Condition::Content(b"SSH-".to_vec()));
        let cr = CategorizedRule::new(rule, RuleCategory::BruteForce, 3);
        cat.add(cr);
    }

    // Backdoor: Bind shell on non-standard port
    {
        let mut rule = Rule::new(
            10009,
            RuleAction::Alert,
            Proto::Tcp,
            NetworkSpec::any(),
            NetworkSpec {
                addr: IpSpec::Any,
                port: PortSpec::Range(1024, 65534),
            },
            "Possible bind shell (non-standard port command shell)",
        );
        rule.conditions
            .push(Condition::Content(b"/bin/sh".to_vec()));
        let cr = CategorizedRule::new(rule, RuleCategory::Backdoor, 4);
        cat.add(cr);
    }

    // DoS: UDP flood
    {
        let mut rule = Rule::new(
            10010,
            RuleAction::Alert,
            Proto::Udp,
            NetworkSpec::any(),
            NetworkSpec::any(),
            "UDP flood (large payload)",
        );
        rule.conditions.push(Condition::DSize {
            min: 1024,
            max: u32::MAX,
        });
        let cr = CategorizedRule::new(rule, RuleCategory::DoS, 2);
        cat.add(cr);
    }

    // Trojan: XOR-encrypted payload heuristic
    {
        let rule = Rule::new(
            10011,
            RuleAction::Alert,
            Proto::Any,
            NetworkSpec::any(),
            NetworkSpec::any(),
            "XOR-encrypted C2 beacon heuristic",
        );
        let cr = CategorizedRule::new(rule, RuleCategory::Trojan, 2);
        cat.add(cr);
    }

    // Policy violation: Cleartext credentials over FTP
    {
        let mut rule = Rule::new(
            10012,
            RuleAction::Alert,
            Proto::Tcp,
            NetworkSpec::any(),
            NetworkSpec {
                addr: IpSpec::Any,
                port: PortSpec::Single(21),
            },
            "FTP cleartext credentials",
        );
        rule.conditions.push(Condition::Content(b"PASS ".to_vec()));
        let cr = CategorizedRule::new(rule, RuleCategory::PolicyViolation, 3);
        cat.add(cr);
    }

    cat
}

// ────────────────────────────────────────────────────────────────────────────
// Rule compiler
// ────────────────────────────────────────────────────────────────────────────

/// Severity threshold for the compiled rule set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompileProfile {
    /// Include all rules.
    All,
    /// Only rules with severity >= 3.
    MediumAndAbove,
    /// Only rules with severity >= 4.
    HighAndAbove,
    /// Only critical rules (severity 5).
    CriticalOnly,
}

/// Compiler that converts a `RuleCatalogue` into a `CompiledRuleSet`.
pub struct RuleCompiler;

impl RuleCompiler {
    /// Compile the given catalogue using the specified profile.
    ///
    /// # Panics
    ///
    /// Panics if `AhoCorasick::build` would overflow `u32` states
    /// (requires more than ~4 billion states, practically impossible).
    #[must_use]
    pub fn compile(catalogue: &RuleCatalogue, profile: CompileProfile) -> CompiledRuleSet {
        let min_severity = match profile {
            CompileProfile::All => 1,
            CompileProfile::MediumAndAbove => 3,
            CompileProfile::HighAndAbove => 4,
            CompileProfile::CriticalOnly => 5,
        };
        let rules: Vec<Rule> = catalogue
            .by_min_severity(min_severity)
            .into_iter()
            .map(|cr| cr.rule)
            .collect();
        CompiledRuleSet::compile(rules)
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Flow-aware rule state
// ────────────────────────────────────────────────────────────────────────────

/// A canonical bidirectional flow key (sorted so (A→B) == (B→A)).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FlowKey {
    pub addr_a: IpAddr,
    pub port_a: u16,
    pub addr_b: IpAddr,
    pub port_b: u16,
    pub proto: u8,
}

impl FlowKey {
    /// Create a canonical flow key from a packet context.
    #[must_use]
    pub fn from_ctx(ctx: &PacketContext) -> Self {
        // Canonical ordering: smaller (addr, port) pair first
        let (addr_a, port_a, addr_b, port_b) =
            if (ctx.src_ip, ctx.src_port) <= (ctx.dst_ip, ctx.dst_port) {
                (ctx.src_ip, ctx.src_port, ctx.dst_ip, ctx.dst_port)
            } else {
                (ctx.dst_ip, ctx.dst_port, ctx.src_ip, ctx.src_port)
            };
        Self {
            addr_a,
            port_a,
            addr_b,
            port_b,
            proto: ctx.ip_proto,
        }
    }
}

impl fmt::Display for FlowKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}:{} <-> {}:{} proto={}",
            self.addr_a, self.port_a, self.addr_b, self.port_b, self.proto
        )
    }
}

/// Per-flow rule state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowState {
    pub key: FlowKey,
    pub packet_count: u64,
    pub byte_count: u64,
    pub first_seen: u64,
    pub last_seen: u64,
    pub alerts: Vec<u32>, // rule IDs that have fired
    pub flags: u32,       // user-defined flow flags
}

impl FlowState {
    /// Create a new flow state.
    #[must_use]
    pub const fn new(key: FlowKey, now: u64) -> Self {
        Self {
            key,
            packet_count: 0,
            byte_count: 0,
            first_seen: now,
            last_seen: now,
            alerts: Vec::new(),
            flags: 0,
        }
    }

    /// Update statistics from a packet context.
    pub const fn update(&mut self, ctx: &PacketContext, now: u64) {
        self.packet_count += 1;
        self.byte_count += ctx.payload.len() as u64;
        self.last_seen = now;
    }

    /// Record that a rule has fired for this flow.
    pub fn record_alert(&mut self, rule_id: u32) {
        if !self.alerts.contains(&rule_id) {
            self.alerts.push(rule_id);
        }
    }

    /// Returns `true` if the given rule has already fired for this flow.
    #[must_use]
    pub fn has_alerted(&self, rule_id: u32) -> bool {
        self.alerts.contains(&rule_id)
    }

    /// Returns the flow duration in seconds.
    #[must_use]
    pub const fn duration_secs(&self) -> u64 {
        self.last_seen.saturating_sub(self.first_seen)
    }
}

/// Flow-aware rule engine that deduplicates per-flow alerts.
pub struct FlowAwareEngine {
    engine: RuleEngine,
    flows: parking_lot::Mutex<HashMap<FlowKey, FlowState>>,
}

impl FlowAwareEngine {
    /// Create a new flow-aware engine wrapping `engine`.
    #[must_use]
    pub fn new(engine: RuleEngine) -> Self {
        Self {
            engine,
            flows: parking_lot::Mutex::new(HashMap::new()),
        }
    }

    /// Evaluate a packet and return alerts that have not yet fired for this flow.
    ///
    /// `now` is a Unix timestamp in seconds.
    #[must_use]
    pub fn evaluate(&self, ctx: &PacketContext, now: u64) -> Vec<MatchResult> {
        let results = self.engine.evaluate_all(ctx);
        let key = FlowKey::from_ctx(ctx);

        let mut flows = self.flows.lock();
        let flow = flows
            .entry(key.clone())
            .or_insert_with(|| FlowState::new(key, now));
        flow.update(ctx, now);

        let new_alerts: Vec<MatchResult> = results
            .into_iter()
            .filter(|r| !flow.has_alerted(r.rule_id))
            .collect();

        for r in &new_alerts {
            flow.record_alert(r.rule_id);
        }
        drop(flows);
        new_alerts
    }

    /// Return a snapshot of all tracked flows.
    #[must_use]
    pub fn flow_count(&self) -> usize {
        self.flows.lock().len()
    }

    /// Expire flows not seen for more than `idle_secs` seconds.
    pub fn expire_flows(&self, now: u64, idle_secs: u64) {
        self.flows
            .lock()
            .retain(|_, v| now.saturating_sub(v.last_seen) < idle_secs);
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Rule test framework
// ────────────────────────────────────────────────────────────────────────────

/// A test case for a rule.
#[derive(Debug, Clone)]
pub struct RuleTestCase {
    pub name: String,
    pub ctx: PacketContext,
    pub should_match: bool,
    pub expected_rule_id: Option<u32>,
}

/// Result of a rule test case.
#[derive(Debug, Clone)]
pub struct RuleTestResult {
    pub name: String,
    pub passed: bool,
    pub actual_match: Option<MatchResult>,
    pub error: Option<String>,
}

/// Run a suite of test cases against the given engine.
#[must_use]
pub fn run_rule_tests(engine: &RuleEngine, cases: &[RuleTestCase]) -> Vec<RuleTestResult> {
    cases
        .iter()
        .map(|tc| {
            let result = engine.evaluate(&tc.ctx);
            let matched = result.is_some();
            let passed = if tc.should_match {
                matched
                    && tc
                        .expected_rule_id
                        .is_none_or(|id| result.as_ref().map(|r| r.rule_id) == Some(id))
            } else {
                !matched
            };
            RuleTestResult {
                name: tc.name.clone(),
                passed,
                actual_match: result,
                error: None,
            }
        })
        .collect()
}

// ────────────────────────────────────────────────────────────────────────────
// Tests
// ────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn make_ip_buf(src: [u8; 4], dst: [u8; 4], proto: u8, payload: &[u8]) -> Vec<u8> {
        let total = 20 + payload.len();
        let mut buf = vec![0u8; total];
        buf[0] = 0x45;
        buf[2] = u8::try_from((total >> 8) & 0xFF).unwrap_or(0);
        buf[3] = u8::try_from(total & 0xFF).unwrap_or(0);
        buf[8] = 64;
        buf[9] = proto;
        buf[12..16].copy_from_slice(&src);
        buf[16..20].copy_from_slice(&dst);
        buf[20..].copy_from_slice(payload);
        buf
    }

    fn make_tcp_buf(src_port: u16, dst_port: u16, flags: TcpFlags, payload: &[u8]) -> Vec<u8> {
        let mut buf = vec![0u8; 20 + payload.len()];
        buf[0] = (src_port >> 8) as u8;
        buf[1] = (src_port & 0xFF) as u8;
        buf[2] = (dst_port >> 8) as u8;
        buf[3] = (dst_port & 0xFF) as u8;
        buf[12] = 0x50;
        buf[13] = flags.bits();
        buf[14] = 0xFF;
        buf[15] = 0xFF;
        buf[20..].copy_from_slice(payload);
        buf
    }

    // ─── RuleParser ───────────────────────────────────────────────────────

    #[test]
    fn parse_rule_basic() {
        let rule_str = r#"alert tcp any any -> any 80 (msg:"Test HTTP"; sid:1001; rev:1;)"#;
        let rule = RuleParser::parse(rule_str).unwrap();
        assert_eq!(rule.id, 1001);
        assert_eq!(rule.action, RuleAction::Alert);
        assert_eq!(rule.proto, Proto::Tcp);
        assert_eq!(rule.msg, "Test HTTP");
    }

    #[test]
    fn parse_rule_with_content() {
        let rule_str =
            r#"alert tcp any any -> any 80 (msg:"Evil"; content:"evil_payload"; sid:2;)"#;
        let rule = RuleParser::parse(rule_str).unwrap();
        assert_eq!(rule.conditions.len(), 1);
        assert!(matches!(&rule.conditions[0], Condition::Content(b) if b == b"evil_payload"));
    }

    #[test]
    fn parse_rule_with_cidr() {
        let rule_str = r#"drop tcp 192.168.0.0/24 any -> any 443 (msg:"Blocked"; sid:3;)"#;
        let rule = RuleParser::parse(rule_str).unwrap();
        assert_eq!(rule.action, RuleAction::Drop);
        assert!(matches!(rule.src.addr, IpSpec::Cidr(_, 24)));
    }

    #[test]
    fn parse_rule_with_port_range() {
        let rule_str = r#"alert udp any any -> any 1024:65535 (msg:"High port"; sid:4;)"#;
        let rule = RuleParser::parse(rule_str).unwrap();
        assert!(matches!(rule.dst.port, PortSpec::Range(1024, 65535)));
    }

    #[test]
    fn parse_rule_with_flags() {
        let rule_str = r#"alert tcp any any -> any any (msg:"SYN"; flags:S; sid:5;)"#;
        let rule = RuleParser::parse(rule_str).unwrap();
        assert!(
            rule.conditions
                .iter()
                .any(|c| matches!(c, Condition::Flags(_)))
        );
    }

    #[test]
    fn parse_rule_pass_action() {
        let rule_str = r#"pass tcp any any -> any any (msg:"Allow"; sid:6;)"#;
        let rule = RuleParser::parse(rule_str).unwrap();
        assert_eq!(rule.action, RuleAction::Pass);
    }

    #[test]
    fn parse_rule_invalid_action() {
        let rule_str = r#"invalid tcp any any -> any any (msg:"x"; sid:7;)"#;
        assert!(RuleParser::parse(rule_str).is_err());
    }

    #[test]
    fn parse_rule_empty() {
        assert!(RuleParser::parse("").is_err());
    }

    #[test]
    fn parse_rule_many() {
        let input = "# comment\nalert tcp any any -> any 80 (msg:\"A\"; sid:100;)\nalert udp any any -> any 53 (msg:\"B\"; sid:101;)";
        let results = RuleParser::parse_many(input);
        assert_eq!(results.len(), 2);
        assert!(results[0].is_ok());
        assert!(results[1].is_ok());
    }

    #[test]
    fn parse_rule_dsize() {
        let rule_str = r#"alert tcp any any -> any any (msg:"sz"; dsize:10<>100; sid:8;)"#;
        let rule = RuleParser::parse(rule_str).unwrap();
        assert!(
            rule.conditions
                .iter()
                .any(|c| matches!(c, Condition::DSize { min: 10, max: 100 }))
        );
    }

    // ─── Rule engine ──────────────────────────────────────────────────────

    #[test]
    fn engine_match_any_any() {
        let engine = RuleEngine::new();
        let mut rule = Rule::new(
            1,
            RuleAction::Alert,
            Proto::Any,
            NetworkSpec::any(),
            NetworkSpec::any(),
            "catch all",
        );
        rule.conditions.push(Condition::Content(b"test".to_vec()));
        engine.add_rule(rule);

        let ctx = PacketContext {
            src_ip: IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8)),
            src_port: 12345,
            dst_port: 80,
            ip_proto: 6,
            ttl: 64,
            payload: b"send test data".to_vec(),
            tcp_flags: TcpFlags::empty(),
        };

        let result = engine.evaluate(&ctx).unwrap();
        assert_eq!(result.rule_id, 1);
        assert_eq!(result.action, RuleAction::Alert);
    }

    #[test]
    fn engine_no_match() {
        let engine = RuleEngine::new();
        let mut rule = Rule::new(
            99,
            RuleAction::Drop,
            Proto::Tcp,
            NetworkSpec::any(),
            NetworkSpec::any(),
            "no match",
        );
        rule.conditions
            .push(Condition::Content(b"xyz_not_present".to_vec()));
        engine.add_rule(rule);

        let ctx = PacketContext {
            src_ip: IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(2, 2, 2, 2)),
            src_port: 1000,
            dst_port: 443,
            ip_proto: 6,
            ttl: 64,
            payload: b"hello world".to_vec(),
            tcp_flags: TcpFlags::empty(),
        };

        assert!(engine.evaluate(&ctx).is_none());
    }

    #[test]
    fn engine_proto_filter() {
        let engine = RuleEngine::new();
        engine.add_rule(Rule::new(
            1,
            RuleAction::Alert,
            Proto::Tcp,
            NetworkSpec::any(),
            NetworkSpec::any(),
            "tcp only",
        ));

        let udp_ctx = PacketContext {
            src_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            dst_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            src_port: 0,
            dst_port: 0,
            ip_proto: 17, // UDP
            ttl: 64,
            payload: vec![],
            tcp_flags: TcpFlags::empty(),
        };

        assert!(engine.evaluate(&udp_ctx).is_none());
    }

    #[test]
    fn engine_remove_rule() {
        let engine = RuleEngine::new();
        engine.add_rule(Rule::new(
            42,
            RuleAction::Log,
            Proto::Any,
            NetworkSpec::any(),
            NetworkSpec::any(),
            "removable",
        ));
        assert_eq!(engine.rules().len(), 1);
        engine.remove_rule(42);
        assert!(engine.rules().is_empty());
    }

    #[test]
    fn engine_evaluate_all() {
        let engine = RuleEngine::new();
        engine.add_rule(Rule::new(
            1,
            RuleAction::Alert,
            Proto::Any,
            NetworkSpec::any(),
            NetworkSpec::any(),
            "r1",
        ));
        engine.add_rule(Rule::new(
            2,
            RuleAction::Log,
            Proto::Any,
            NetworkSpec::any(),
            NetworkSpec::any(),
            "r2",
        ));

        let ctx = PacketContext {
            src_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            dst_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            src_port: 0,
            dst_port: 0,
            ip_proto: 6,
            ttl: 64,
            payload: vec![],
            tcp_flags: TcpFlags::empty(),
        };

        let all = engine.evaluate_all(&ctx);
        assert_eq!(all.len(), 2);
    }

    #[test]
    fn engine_dsize_condition() {
        let engine = RuleEngine::new();
        let mut rule = Rule::new(
            5,
            RuleAction::Alert,
            Proto::Any,
            NetworkSpec::any(),
            NetworkSpec::any(),
            "size",
        );
        rule.conditions.push(Condition::DSize { min: 5, max: 20 });
        engine.add_rule(rule);

        let ctx_ok = PacketContext {
            src_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            dst_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            src_port: 0,
            dst_port: 0,
            ip_proto: 6,
            ttl: 64,
            payload: vec![0u8; 10],
            tcp_flags: TcpFlags::empty(),
        };
        assert!(engine.evaluate(&ctx_ok).is_some());

        let ctx_bad = PacketContext {
            payload: vec![0u8; 100],
            ..ctx_ok
        };
        assert!(engine.evaluate(&ctx_bad).is_none());
    }

    // ─── RuleStore (SQLite) ───────────────────────────────────────────────

    #[test]
    fn rule_store_save_and_load() {
        let store = RuleStore::in_memory().unwrap();
        let rule = Rule::new(
            1,
            RuleAction::Alert,
            Proto::Tcp,
            NetworkSpec::any(),
            NetworkSpec::any(),
            "test",
        );
        store.save_rule(&rule).unwrap();
        let loaded = store.load_all().unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].id, 1);
        assert_eq!(loaded[0].msg, "test");
    }

    #[test]
    fn rule_store_delete() {
        let store = RuleStore::in_memory().unwrap();
        let rule = Rule::new(
            42,
            RuleAction::Drop,
            Proto::Any,
            NetworkSpec::any(),
            NetworkSpec::any(),
            "del",
        );
        store.save_rule(&rule).unwrap();
        store.delete_rule(42).unwrap();
        assert_eq!(store.count().unwrap(), 0);
    }

    #[test]
    fn rule_store_delete_not_found() {
        let store = RuleStore::in_memory().unwrap();
        assert!(matches!(
            store.delete_rule(999),
            Err(RuleError::NotFound(999))
        ));
    }

    #[test]
    fn rule_store_set_enabled() {
        let store = RuleStore::in_memory().unwrap();
        let mut rule = Rule::new(
            7,
            RuleAction::Log,
            Proto::Any,
            NetworkSpec::any(),
            NetworkSpec::any(),
            "toggle",
        );
        rule.enabled = true;
        store.save_rule(&rule).unwrap();
        store.set_enabled(7, false).unwrap();
        // Re-save and reload to check
        let mut updated = rule;
        updated.enabled = false;
        store.save_rule(&updated).unwrap();
        let loaded = store.load_all().unwrap();
        assert!(!loaded[0].enabled);
    }

    #[test]
    fn rule_store_count() {
        let store = RuleStore::in_memory().unwrap();
        for i in 1u32..=5 {
            store
                .save_rule(&Rule::new(
                    i,
                    RuleAction::Alert,
                    Proto::Any,
                    NetworkSpec::any(),
                    NetworkSpec::any(),
                    "x",
                ))
                .unwrap();
        }
        assert_eq!(store.count().unwrap(), 5);
    }

    // ─── IpSpec / PortSpec ────────────────────────────────────────────────

    #[test]
    fn ipspec_any_matches_all() {
        assert!(IpSpec::Any.matches(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))));
    }

    #[test]
    fn ipspec_cidr_match() {
        let spec = IpSpec::Cidr(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 0)), 24);
        assert!(spec.matches(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50))));
        assert!(!spec.matches(IpAddr::V4(Ipv4Addr::new(192, 168, 2, 1))));
    }

    #[test]
    fn portspec_range() {
        let spec = PortSpec::Range(1024, 65535);
        assert!(!spec.matches(80));
        assert!(spec.matches(8080));
    }

    #[test]
    fn portspec_not() {
        let spec = PortSpec::Not(Box::new(PortSpec::Single(80)));
        assert!(spec.matches(443));
        assert!(!spec.matches(80));
    }

    // ─── Display impls ────────────────────────────────────────────────────

    #[test]
    fn rule_display() {
        let r = Rule::new(
            1,
            RuleAction::Alert,
            Proto::Tcp,
            NetworkSpec::any(),
            NetworkSpec::any(),
            "hello",
        );
        let s = r.to_string();
        assert!(s.contains("alert"));
        assert!(s.contains("hello"));
    }

    #[test]
    fn match_result_display() {
        let mr = MatchResult {
            matched: true,
            rule_id: 5,
            action: RuleAction::Alert,
            msg: "hit".to_string(),
        };
        assert!(mr.to_string().contains("MATCH"));
        let mr2 = MatchResult {
            matched: false,
            rule_id: 5,
            action: RuleAction::Alert,
            msg: "miss".to_string(),
        };
        assert!(mr2.to_string().contains("NO MATCH"));
    }

    #[test]
    fn condition_display() {
        let c = Condition::Content(b"evil".to_vec());
        assert!(c.to_string().contains("evil"));
        let c2 = Condition::DSize { min: 1, max: 100 };
        assert!(c2.to_string().contains("100"));
    }

    #[test]
    fn packet_context_from_ipv4() {
        let tcp_payload = b"GET / HTTP/1.1\r\n";
        let tcp = make_tcp_buf(12345, 80, TcpFlags::PSH | TcpFlags::ACK, tcp_payload);
        let ip = make_ip_buf([1, 2, 3, 4], [5, 6, 7, 8], 6, &tcp);
        let ctx = PacketContext::from_ipv4(&ip).unwrap();
        assert_eq!(ctx.src_port, 12345);
        assert_eq!(ctx.dst_port, 80);
        assert!(ctx.tcp_flags.contains(TcpFlags::PSH));
        assert_eq!(ctx.payload, tcp_payload);
    }

    // ── Spec-required: Action, RuleProtocol, RuleDir ──────────────────────

    #[test]
    fn action_display() {
        assert_eq!(Action::Alert.to_string(), "alert");
        assert_eq!(Action::Drop.to_string(), "drop");
        assert_eq!(Action::Pass.to_string(), "pass");
        assert_eq!(Action::Reject.to_string(), "reject");
    }

    #[test]
    fn rule_protocol_display() {
        assert_eq!(RuleProtocol::Tcp.to_string(), "tcp");
        assert_eq!(RuleProtocol::Udp.to_string(), "udp");
        assert_eq!(RuleProtocol::Icmp.to_string(), "icmp");
        assert_eq!(RuleProtocol::Any.to_string(), "any");
    }

    #[test]
    fn rule_dir_display() {
        assert_eq!(RuleDir::Unidirectional.to_string(), "->");
        assert_eq!(RuleDir::Bidirectional.to_string(), "<>");
    }

    // ── Spec-required: RuleOption ─────────────────────────────────────────

    #[test]
    fn rule_option_display() {
        assert!(
            RuleOption::Msg("evil".to_string())
                .to_string()
                .contains("evil")
        );
        assert!(RuleOption::Sid(1001).to_string().contains("1001"));
        assert!(
            RuleOption::Content(b"abc".to_vec())
                .to_string()
                .contains("abc")
        );
        assert_eq!(RuleOption::Nocase.to_string(), "nocase");
        assert!(
            RuleOption::Pcre("foo".to_string())
                .to_string()
                .contains("foo")
        );
    }

    // ── Spec-required: SpecRule ────────────────────────────────────────────

    fn make_spec_rule(sid: u32, msg: &str, proto: RuleProtocol) -> SpecRule {
        SpecRule {
            action: Action::Alert,
            proto,
            src: "any".to_string(),
            src_port: "any".to_string(),
            dir: RuleDir::Unidirectional,
            dst: "any".to_string(),
            dst_port: "any".to_string(),
            options: vec![RuleOption::Sid(sid), RuleOption::Msg(msg.to_string())],
        }
    }

    #[test]
    fn spec_rule_sid_and_msg() {
        let rule = make_spec_rule(42, "test msg", RuleProtocol::Tcp);
        assert_eq!(rule.sid(), Some(42));
        assert_eq!(rule.msg(), Some("test msg"));
    }

    #[test]
    fn spec_rule_content_patterns() {
        let mut rule = make_spec_rule(1, "test", RuleProtocol::Any);
        rule.options.push(RuleOption::Content(b"evil".to_vec()));
        rule.options.push(RuleOption::Content(b"bad".to_vec()));
        let patterns = rule.content_patterns();
        assert_eq!(patterns.len(), 2);
        assert_eq!(patterns[0], b"evil");
        assert_eq!(patterns[1], b"bad");
    }

    // ── Spec-required: RuleSet ────────────────────────────────────────────

    #[test]
    fn rule_set_add_and_count() {
        let mut rs = RuleSet::new();
        rs.add(make_spec_rule(100, "r1", RuleProtocol::Tcp));
        rs.add(make_spec_rule(101, "r2", RuleProtocol::Udp));
        assert_eq!(rs.count(), 2);
    }

    #[test]
    fn rule_set_by_sid() {
        let mut rs = RuleSet::new();
        rs.add(make_spec_rule(200, "match me", RuleProtocol::Any));
        assert!(rs.by_sid(200).is_some());
        assert!(rs.by_sid(999).is_none());
    }

    // ── Spec-required: SpecRuleEngine::match_packet ───────────────────────

    #[test]
    fn spec_engine_match_any_proto() {
        let mut rs = RuleSet::new();
        rs.add(make_spec_rule(1, "any-proto", RuleProtocol::Any));
        let engine = SpecRuleEngine::new(rs);
        let pkt = MatchPacket {
            src_ip: "1.2.3.4".to_string(),
            dst_ip: "5.6.7.8".to_string(),
            src_port: 1234,
            dst_port: 80,
            proto: RuleProtocol::Tcp,
            payload: vec![],
        };
        let results = engine.match_packet(&pkt);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].rule_sid, 1);
        assert_eq!(results[0].action, Action::Alert);
    }

    #[test]
    fn spec_engine_content_match() {
        let mut rs = RuleSet::new();
        let mut rule = make_spec_rule(5, "content rule", RuleProtocol::Tcp);
        rule.options.push(RuleOption::Content(b"evil".to_vec()));
        rs.add(rule);
        let engine = SpecRuleEngine::new(rs);

        let pkt_match = MatchPacket {
            src_ip: "any".to_string(),
            dst_ip: "any".to_string(),
            src_port: 0,
            dst_port: 0,
            proto: RuleProtocol::Tcp,
            payload: b"prefix_evil_suffix".to_vec(),
        };
        let results = engine.match_packet(&pkt_match);
        assert!(!results.is_empty());
        assert!(!results[0].offsets.is_empty());

        let pkt_no_match = MatchPacket {
            src_ip: "any".to_string(),
            dst_ip: "any".to_string(),
            src_port: 0,
            dst_port: 0,
            proto: RuleProtocol::Tcp,
            payload: b"innocent data".to_vec(),
        };
        assert!(engine.match_packet(&pkt_no_match).is_empty());
    }

    #[test]
    fn spec_engine_proto_filter() {
        let mut rs = RuleSet::new();
        rs.add(make_spec_rule(10, "tcp only", RuleProtocol::Tcp));
        let engine = SpecRuleEngine::new(rs);
        let udp_pkt = MatchPacket {
            src_ip: "any".to_string(),
            dst_ip: "any".to_string(),
            src_port: 0,
            dst_port: 0,
            proto: RuleProtocol::Udp,
            payload: vec![],
        };
        assert!(engine.match_packet(&udp_pkt).is_empty());
    }

    // ── Spec-required: SpecRuleError ─────────────────────────────────────

    #[test]
    fn spec_rule_error_display() {
        assert!(
            SpecRuleError::ParseError("bad token".to_string())
                .to_string()
                .contains("bad token")
        );
        assert!(SpecRuleError::MissingSid.to_string().contains("SID"));
        assert!(SpecRuleError::InvalidSid(0).to_string().contains('0'));
    }

    // ── Aho-Corasick ──────────────────────────────────────────────────────

    #[test]
    fn ac_single_pattern_match() {
        let ac = AhoCorasick::build(&[b"hello"]);
        let text = b"say hello world";
        let matches = ac.find_all(text);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].pattern_idx, 0);
        assert_eq!(matches[0].start, 4);
        assert_eq!(matches[0].end, 9);
    }

    #[test]
    fn ac_multi_pattern_match() {
        let ac = AhoCorasick::build(&[b"he", b"she", b"his", b"hers"]);
        let text = b"ushers";
        let matches = ac.find_all(text);
        assert!(!matches.is_empty());
        let found_patterns: Vec<usize> = matches.iter().map(|m| m.pattern_idx).collect();
        assert!(found_patterns.contains(&1)); // "she"
        assert!(found_patterns.contains(&0)); // "he"
    }

    #[test]
    fn ac_no_match() {
        let ac = AhoCorasick::build(&[b"xyz"]);
        assert!(ac.find_all(b"hello world").is_empty());
    }

    #[test]
    fn ac_contains_any() {
        let ac = AhoCorasick::build(&[b"evil", b"bad"]);
        assert!(ac.contains_any(b"some evil payload"));
        assert!(!ac.contains_any(b"innocent data"));
    }

    #[test]
    fn ac_find_first() {
        let ac = AhoCorasick::build(&[b"abc", b"abcdef"]);
        let m = ac.find_first(b"prefix abcdef suffix").unwrap();
        assert_eq!(&b"prefix abcdef suffix"[m.start..m.end], b"abc");
    }

    #[test]
    fn ac_empty_text() {
        let ac = AhoCorasick::build(&[b"abc"]);
        assert!(ac.find_all(b"").is_empty());
    }

    #[test]
    fn ac_state_count() {
        let ac = AhoCorasick::build(&[b"abc", b"def"]);
        assert!(ac.state_count() > 1);
    }

    // ── CompiledRuleSet ───────────────────────────────────────────────────

    #[test]
    fn compiled_rule_set_match() {
        let mut rule = Rule::new(
            1,
            RuleAction::Alert,
            Proto::Any,
            NetworkSpec::any(),
            NetworkSpec::any(),
            "content match",
        );
        rule.conditions
            .push(Condition::Content(b"exploit".to_vec()));
        let crs = CompiledRuleSet::compile(vec![rule]);
        assert_eq!(crs.rule_count(), 1);
        assert_eq!(crs.pattern_count(), 1);

        let ctx = PacketContext {
            src_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            dst_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            src_port: 1234,
            dst_port: 80,
            ip_proto: 6,
            ttl: 64,
            payload: b"send exploit now".to_vec(),
            tcp_flags: TcpFlags::empty(),
        };
        let results = crs.evaluate(&ctx);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].rule_id, 1);
    }

    #[test]
    fn compiled_rule_set_no_match() {
        let mut rule = Rule::new(
            2,
            RuleAction::Alert,
            Proto::Any,
            NetworkSpec::any(),
            NetworkSpec::any(),
            "no match",
        );
        rule.conditions
            .push(Condition::Content(b"nomatch".to_vec()));
        let crs = CompiledRuleSet::compile(vec![rule]);
        let ctx = PacketContext {
            src_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            dst_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            src_port: 0,
            dst_port: 0,
            ip_proto: 6,
            ttl: 64,
            payload: b"innocent payload".to_vec(),
            tcp_flags: TcpFlags::empty(),
        };
        assert!(crs.evaluate(&ctx).is_empty());
    }

    #[test]
    fn compiled_rule_set_no_content_conditions() {
        let mut rule = Rule::new(
            3,
            RuleAction::Alert,
            Proto::Any,
            NetworkSpec::any(),
            NetworkSpec::any(),
            "size",
        );
        rule.conditions.push(Condition::DSize { min: 1, max: 100 });
        let crs = CompiledRuleSet::compile(vec![rule]);
        assert_eq!(crs.pattern_count(), 0);
        let ctx = PacketContext {
            src_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            dst_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            src_port: 0,
            dst_port: 0,
            ip_proto: 6,
            ttl: 64,
            payload: b"hi".to_vec(),
            tcp_flags: TcpFlags::empty(),
        };
        assert_eq!(crs.evaluate(&ctx).len(), 1);
    }

    // ── ThresholdEngine ───────────────────────────────────────────────────

    #[test]
    fn threshold_fires_after_n() {
        let engine = RuleEngine::new();
        engine.add_rule(Rule::new(
            1,
            RuleAction::Alert,
            Proto::Any,
            NetworkSpec::any(),
            NetworkSpec::any(),
            "thresh",
        ));
        let mut te = ThresholdEngine::new(engine);
        te.add_threshold(ThresholdConfig {
            rule_id: 1,
            threshold_type: ThresholdType::Threshold,
            track: ThresholdTrack::ByRule,
            count: 3,
            seconds: 60,
        });

        let ctx = PacketContext {
            src_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            dst_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            src_port: 0,
            dst_port: 0,
            ip_proto: 6,
            ttl: 64,
            payload: vec![],
            tcp_flags: TcpFlags::empty(),
        };
        assert!(te.evaluate(&ctx, 0).is_none()); // count=1
        assert!(te.evaluate(&ctx, 0).is_none()); // count=2
        assert!(te.evaluate(&ctx, 0).is_some()); // count=3, fires
    }

    #[test]
    fn threshold_limit_fires_once() {
        let engine = RuleEngine::new();
        engine.add_rule(Rule::new(
            1,
            RuleAction::Alert,
            Proto::Any,
            NetworkSpec::any(),
            NetworkSpec::any(),
            "limit",
        ));
        let mut te = ThresholdEngine::new(engine);
        te.add_threshold(ThresholdConfig {
            rule_id: 1,
            threshold_type: ThresholdType::Limit,
            track: ThresholdTrack::ByRule,
            count: 1,
            seconds: 60,
        });

        let ctx = PacketContext {
            src_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            dst_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            src_port: 0,
            dst_port: 0,
            ip_proto: 6,
            ttl: 64,
            payload: vec![],
            tcp_flags: TcpFlags::empty(),
        };
        assert!(te.evaluate(&ctx, 0).is_some());
        assert!(te.evaluate(&ctx, 0).is_none());
    }

    #[test]
    fn threshold_window_resets() {
        let engine = RuleEngine::new();
        engine.add_rule(Rule::new(
            1,
            RuleAction::Alert,
            Proto::Any,
            NetworkSpec::any(),
            NetworkSpec::any(),
            "win",
        ));
        let mut te = ThresholdEngine::new(engine);
        te.add_threshold(ThresholdConfig {
            rule_id: 1,
            threshold_type: ThresholdType::Threshold,
            track: ThresholdTrack::ByRule,
            count: 2,
            seconds: 10,
        });

        let ctx = PacketContext {
            src_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            dst_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            src_port: 0,
            dst_port: 0,
            ip_proto: 6,
            ttl: 64,
            payload: vec![],
            tcp_flags: TcpFlags::empty(),
        };
        let _ = te.evaluate(&ctx, 0); // count=1
        assert!(te.evaluate(&ctx, 20).is_none()); // window reset, count=1 again
        assert!(te.evaluate(&ctx, 20).is_some()); // count=2, fires
    }

    // ── Suppression ───────────────────────────────────────────────────────

    #[test]
    fn suppression_blocks_alert() {
        let engine = RuleEngine::new();
        engine.add_rule(Rule::new(
            1,
            RuleAction::Alert,
            Proto::Any,
            NetworkSpec::any(),
            NetworkSpec::any(),
            "sup",
        ));
        let se = SuppressedEngine::new(engine);
        se.add_suppression(Suppression {
            rule_id: 1,
            track: ThresholdTrack::BySrc,
            ip_spec: IpSpec::Any,
        });

        let ctx = PacketContext {
            src_ip: IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
            dst_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            src_port: 0,
            dst_port: 0,
            ip_proto: 6,
            ttl: 64,
            payload: vec![],
            tcp_flags: TcpFlags::empty(),
        };
        assert!(se.evaluate(&ctx).is_none());
    }

    #[test]
    fn suppression_allows_other_rules() {
        let engine = RuleEngine::new();
        engine.add_rule(Rule::new(
            1,
            RuleAction::Alert,
            Proto::Any,
            NetworkSpec::any(),
            NetworkSpec::any(),
            "r1",
        ));
        engine.add_rule(Rule::new(
            2,
            RuleAction::Alert,
            Proto::Any,
            NetworkSpec::any(),
            NetworkSpec::any(),
            "r2",
        ));
        let se = SuppressedEngine::new(engine);
        se.add_suppression(Suppression {
            rule_id: 1,
            track: ThresholdTrack::ByRule,
            ip_spec: IpSpec::Any,
        });

        let ctx = PacketContext {
            src_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            dst_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            src_port: 0,
            dst_port: 0,
            ip_proto: 6,
            ttl: 64,
            payload: vec![],
            tcp_flags: TcpFlags::empty(),
        };
        let results = se.evaluate_all(&ctx);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].rule_id, 2);
    }

    #[test]
    fn suppression_count() {
        let engine = RuleEngine::new();
        let se = SuppressedEngine::new(engine);
        se.add_suppression(Suppression {
            rule_id: 1,
            track: ThresholdTrack::ByRule,
            ip_spec: IpSpec::Any,
        });
        se.add_suppression(Suppression {
            rule_id: 2,
            track: ThresholdTrack::BySrc,
            ip_spec: IpSpec::Any,
        });
        assert_eq!(se.suppression_count(), 2);
    }

    // ── RuleCategory / CategorizedRule ────────────────────────────────────

    #[test]
    fn rule_category_display() {
        assert_eq!(RuleCategory::MalwareC2.to_string(), "malware-c2");
        assert_eq!(RuleCategory::Exploitation.to_string(), "exploitation");
        assert_eq!(
            RuleCategory::DataExfiltration.to_string(),
            "data-exfiltration"
        );
        assert_eq!(RuleCategory::BruteForce.to_string(), "brute-force");
    }

    #[test]
    fn categorized_rule_severity_clamp() {
        let rule = Rule::new(
            1,
            RuleAction::Alert,
            Proto::Any,
            NetworkSpec::any(),
            NetworkSpec::any(),
            "x",
        );
        let cr = CategorizedRule::new(rule, RuleCategory::MalwareC2, 10);
        assert_eq!(cr.severity, 5);
    }

    #[test]
    fn rule_catalogue_by_category() {
        let cat = RuleCatalogue::new();
        let rule1 = Rule::new(
            1,
            RuleAction::Alert,
            Proto::Any,
            NetworkSpec::any(),
            NetworkSpec::any(),
            "c2",
        );
        cat.add(CategorizedRule::new(rule1, RuleCategory::MalwareC2, 5));
        let rule2 = Rule::new(
            2,
            RuleAction::Alert,
            Proto::Any,
            NetworkSpec::any(),
            NetworkSpec::any(),
            "exploit",
        );
        cat.add(CategorizedRule::new(rule2, RuleCategory::Exploitation, 4));

        let c2 = cat.by_category(RuleCategory::MalwareC2);
        assert_eq!(c2.len(), 1);
        assert_eq!(c2[0].rule.id, 1);
    }

    #[test]
    fn rule_catalogue_by_severity() {
        let cat = RuleCatalogue::new();
        for (id, sev) in [(1u32, 2u8), (2, 3), (3, 5)] {
            let rule = Rule::new(
                id,
                RuleAction::Alert,
                Proto::Any,
                NetworkSpec::any(),
                NetworkSpec::any(),
                "x",
            );
            cat.add(CategorizedRule::new(rule, RuleCategory::Other, sev));
        }
        assert_eq!(cat.by_min_severity(3).len(), 2);
        assert_eq!(cat.by_min_severity(5).len(), 1);
        assert_eq!(cat.by_min_severity(1).len(), 3);
    }

    #[test]
    fn rule_catalogue_build_engine() {
        let cat = RuleCatalogue::new();
        let rule = Rule::new(
            99,
            RuleAction::Alert,
            Proto::Any,
            NetworkSpec::any(),
            NetworkSpec::any(),
            "eng",
        );
        cat.add(CategorizedRule::new(rule, RuleCategory::Other, 3));
        let engine = cat.build_engine();
        assert_eq!(engine.rules().len(), 1);
    }

    // ── RuleCompiler ──────────────────────────────────────────────────────

    #[test]
    fn rule_compiler_all_profile() {
        let cat = builtin_catalogue();
        let total = cat.count();
        let crs = RuleCompiler::compile(&cat, CompileProfile::All);
        assert_eq!(crs.rule_count(), total);
    }

    #[test]
    fn rule_compiler_high_profile() {
        let cat = builtin_catalogue();
        let high = cat.by_min_severity(4).len();
        let crs = RuleCompiler::compile(&cat, CompileProfile::HighAndAbove);
        assert_eq!(crs.rule_count(), high);
    }

    // ── FlowKey / FlowState ───────────────────────────────────────────────

    #[test]
    fn flow_key_canonical() {
        let ctx_a = PacketContext {
            src_ip: IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8)),
            src_port: 1234,
            dst_port: 80,
            ip_proto: 6,
            ttl: 64,
            payload: vec![],
            tcp_flags: TcpFlags::empty(),
        };
        let ctx_b = PacketContext {
            src_ip: IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
            src_port: 80,
            dst_port: 1234,
            ip_proto: 6,
            ttl: 64,
            payload: vec![],
            tcp_flags: TcpFlags::empty(),
        };
        assert_eq!(FlowKey::from_ctx(&ctx_a), FlowKey::from_ctx(&ctx_b));
    }

    #[test]
    fn flow_state_update_and_alert() {
        let key = FlowKey::from_ctx(&PacketContext {
            src_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            dst_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            src_port: 0,
            dst_port: 0,
            ip_proto: 6,
            ttl: 64,
            payload: b"hello".to_vec(),
            tcp_flags: TcpFlags::empty(),
        });
        let mut state = FlowState::new(key, 1000);
        let ctx = PacketContext {
            src_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            dst_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            src_port: 0,
            dst_port: 0,
            ip_proto: 6,
            ttl: 64,
            payload: b"hello".to_vec(),
            tcp_flags: TcpFlags::empty(),
        };
        state.update(&ctx, 1005);
        assert_eq!(state.packet_count, 1);
        assert_eq!(state.byte_count, 5);
        assert_eq!(state.duration_secs(), 5);

        state.record_alert(42);
        assert!(state.has_alerted(42));
        assert!(!state.has_alerted(99));

        state.record_alert(42);
        assert_eq!(state.alerts.len(), 1);
    }

    // ── FlowAwareEngine ───────────────────────────────────────────────────

    #[test]
    fn flow_aware_deduplicates() {
        let engine = RuleEngine::new();
        engine.add_rule(Rule::new(
            1,
            RuleAction::Alert,
            Proto::Any,
            NetworkSpec::any(),
            NetworkSpec::any(),
            "dedup",
        ));
        let fae = FlowAwareEngine::new(engine);

        let ctx = PacketContext {
            src_ip: IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8)),
            src_port: 1234,
            dst_port: 80,
            ip_proto: 6,
            ttl: 64,
            payload: vec![],
            tcp_flags: TcpFlags::empty(),
        };
        let first = fae.evaluate(&ctx, 0);
        assert_eq!(first.len(), 1);
        let second = fae.evaluate(&ctx, 1);
        assert!(second.is_empty());
        assert_eq!(fae.flow_count(), 1);
    }

    #[test]
    fn flow_aware_expire() {
        let engine = RuleEngine::new();
        let fae = FlowAwareEngine::new(engine);
        {
            let ctx = PacketContext {
                src_ip: IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
                dst_ip: IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8)),
                src_port: 0,
                dst_port: 0,
                ip_proto: 6,
                ttl: 64,
                payload: vec![],
                tcp_flags: TcpFlags::empty(),
            };
            let _ = fae.evaluate(&ctx, 0);
        }
        assert_eq!(fae.flow_count(), 1);
        fae.expire_flows(1000, 60);
        assert_eq!(fae.flow_count(), 0);
    }

    // ── builtin_catalogue ─────────────────────────────────────────────────

    #[test]
    fn builtin_catalogue_has_rules() {
        let cat = builtin_catalogue();
        assert!(cat.count() >= 10);
    }

    #[test]
    fn builtin_catalogue_categories_populated() {
        let cat = builtin_catalogue();
        assert!(!cat.by_category(RuleCategory::MalwareC2).is_empty());
        assert!(!cat.by_category(RuleCategory::Exploitation).is_empty());
        assert!(!cat.by_category(RuleCategory::Reconnaissance).is_empty());
        assert!(!cat.by_category(RuleCategory::DataExfiltration).is_empty());
    }

    // ── run_rule_tests ────────────────────────────────────────────────────

    #[test]
    fn rule_test_framework_pass_and_fail() {
        let engine = RuleEngine::new();
        let mut rule = Rule::new(
            1,
            RuleAction::Alert,
            Proto::Any,
            NetworkSpec::any(),
            NetworkSpec::any(),
            "fw",
        );
        rule.conditions.push(Condition::Content(b"test".to_vec()));
        engine.add_rule(rule);

        let match_ctx = PacketContext {
            src_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            dst_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            src_port: 0,
            dst_port: 0,
            ip_proto: 6,
            ttl: 64,
            payload: b"this is a test".to_vec(),
            tcp_flags: TcpFlags::empty(),
        };
        let no_match_ctx = PacketContext {
            payload: b"no match here".to_vec(),
            ..match_ctx
        };

        let cases = vec![
            RuleTestCase {
                name: "should match".to_string(),
                ctx: match_ctx,
                should_match: true,
                expected_rule_id: Some(1),
            },
            RuleTestCase {
                name: "should not match".to_string(),
                ctx: no_match_ctx,
                should_match: false,
                expected_rule_id: None,
            },
        ];
        let results = run_rule_tests(&engine, &cases);
        assert_eq!(results.len(), 2);
        assert!(results[0].passed);
        assert!(results[1].passed);
    }

    // ── ThresholdType display ─────────────────────────────────────────────

    #[test]
    fn threshold_type_display() {
        assert_eq!(ThresholdType::Threshold.to_string(), "threshold");
        assert_eq!(ThresholdType::Limit.to_string(), "limit");
        assert_eq!(ThresholdType::Both.to_string(), "both");
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Rule statistics
// ────────────────────────────────────────────────────────────────────────────

/// Per-rule match statistics.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RuleStats {
    pub rule_id: u32,
    pub match_count: u64,
    pub last_matched_ts: u64,
    pub total_bytes_matched: u64,
}

impl RuleStats {
    /// Create empty statistics for a rule.
    #[must_use]
    pub fn new(rule_id: u32) -> Self {
        Self {
            rule_id,
            ..Default::default()
        }
    }

    /// Record a match with the given payload size and timestamp.
    pub const fn record(&mut self, payload_bytes: usize, ts: u64) {
        self.match_count += 1;
        self.total_bytes_matched += payload_bytes as u64;
        self.last_matched_ts = ts;
    }

    /// Returns `true` if this rule has ever matched.
    #[must_use]
    pub const fn ever_matched(&self) -> bool {
        self.match_count > 0
    }
}

impl fmt::Display for RuleStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "rule={} matches={} bytes={} last={}",
            self.rule_id, self.match_count, self.total_bytes_matched, self.last_matched_ts
        )
    }
}

/// Aggregated statistics for a rule engine.
pub struct RuleStatsTracker {
    stats: parking_lot::Mutex<HashMap<u32, RuleStats>>,
}

impl RuleStatsTracker {
    /// Create an empty stats tracker.
    #[must_use]
    pub fn new() -> Self {
        Self {
            stats: parking_lot::Mutex::new(HashMap::new()),
        }
    }

    /// Record a match for the given rule, payload size, and timestamp.
    pub fn record_match(&self, rule_id: u32, payload_bytes: usize, ts: u64) {
        let mut map = self.stats.lock();
        map.entry(rule_id)
            .or_insert_with(|| RuleStats::new(rule_id))
            .record(payload_bytes, ts);
    }

    /// Get a snapshot of stats for a rule.
    #[must_use]
    pub fn get(&self, rule_id: u32) -> Option<RuleStats> {
        self.stats.lock().get(&rule_id).cloned()
    }

    /// Get all stats, sorted by `rule_id`.
    #[must_use]
    pub fn all(&self) -> Vec<RuleStats> {
        let mut v: Vec<RuleStats> = self.stats.lock().values().cloned().collect();
        v.sort_by_key(|s| s.rule_id);
        v
    }

    /// Return the number of rules that have been tracked.
    #[must_use]
    pub fn tracked_rule_count(&self) -> usize {
        self.stats.lock().len()
    }

    /// Reset all statistics.
    pub fn reset(&self) {
        self.stats.lock().clear();
    }

    /// Return the total match count across all rules.
    #[must_use]
    pub fn total_matches(&self) -> u64 {
        self.stats.lock().values().map(|s| s.match_count).sum()
    }
}

impl Default for RuleStatsTracker {
    fn default() -> Self {
        Self::new()
    }
}

/// A rule engine that tracks per-rule statistics.
pub struct StatsRuleEngine {
    engine: RuleEngine,
    tracker: RuleStatsTracker,
}

impl StatsRuleEngine {
    /// Create a new stats-tracking engine.
    #[must_use]
    pub fn new(engine: RuleEngine) -> Self {
        Self {
            engine,
            tracker: RuleStatsTracker::new(),
        }
    }

    /// Evaluate and record stats. `ts` is Unix timestamp in seconds.
    #[must_use]
    pub fn evaluate(&self, ctx: &PacketContext, ts: u64) -> Vec<MatchResult> {
        let results = self.engine.evaluate_all(ctx);
        for r in &results {
            self.tracker.record_match(r.rule_id, ctx.payload.len(), ts);
        }
        results
    }

    /// Access the underlying stats tracker.
    #[must_use]
    pub const fn tracker(&self) -> &RuleStatsTracker {
        &self.tracker
    }

    /// Add a rule to the underlying engine.
    pub fn add_rule(&self, rule: Rule) {
        self.engine.add_rule(rule);
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Extended rule options (byte_test, byte_jump, byte_extract, isdataat,
// rawbytes, fast_pattern, nocase, within_distance combinators)
// ────────────────────────────────────────────────────────────────────────────

/// Extended Snort/Suricata rule option.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ExtOption {
    /// `rawbytes` — match in the raw (pre-normalisation) payload.
    Rawbytes,
    /// `fast_pattern` — designate the content for multi-pattern pre-filter.
    FastPattern,
    /// `nocase` — previous content match should be case-insensitive.
    Nocase,
    /// `byte_test:count,op,value,offset[,relative][,string]`
    ByteTest {
        count: u8,
        op: ByteTestOp,
        value: u64,
        offset: usize,
        relative: bool,
    },
    /// `byte_jump:count,offset[,relative][,align][,from_beginning][,post_offset]`
    ByteJump {
        count: u8,
        offset: usize,
        relative: bool,
        align: bool,
        from_beginning: bool,
        post_offset: i32,
    },
    /// `byte_extract:count,offset,name[,relative]`
    ByteExtract {
        count: u8,
        offset: usize,
        name: String,
        relative: bool,
    },
    /// `isdataat:pos[,relative]` — assert data exists at position.
    IsDataAt { pos: usize, relative: bool },
    /// `seq:n` — TCP sequence number equals n.
    Seq(u32),
    /// `ack:n` — TCP acknowledgement number equals n.
    Ack(u32),
    /// `window:n` — TCP window equals n.
    Window(u16),
    /// `itype:n` — ICMP type equals n.
    IType(u8),
    /// `icode:n` — ICMP code equals n.
    ICode(u8),
    /// `icmp_id:n` — ICMP identifier equals n.
    IcmpId(u16),
    /// `icmp_seq:n` — ICMP sequence equals n.
    IcmpSeq(u16),
    /// `tos:n` — IP TOS equals n.
    Tos(u8),
    /// `id:n` — IP identification equals n.
    IpId(u16),
    /// `ipopts:opt` — IP has option of given type.
    IpOpts(IpOptType),
    /// `fragbits:flags` — IP fragmentation bits check.
    FragBits(FragBitsCheck),
    /// `fragoffset:n` — IP fragment offset equals n.
    FragOffset(u16),
    /// `stream_size:op,size` — stream buffer size check.
    StreamSize { op: SizeOp, size: u32 },
    /// `detection_filter:track,count,seconds` — per-rule rate-limit.
    DetectionFilter {
        track: ThresholdTrack,
        count: u32,
        seconds: u64,
    },
    /// `priority:n` — rule priority override.
    Priority(u8),
    /// `classtype:name` — rule class type.
    Classtype(String),
    /// `reference:type,ref` — rule reference.
    Reference { ref_type: String, ref_value: String },
    /// `gid:n` — generator ID.
    Gid(u32),
    /// `tag:host|session,count,type` — tagging.
    Tag(String),
    /// `metadata:key,value` — arbitrary metadata.
    Metadata(String, String),
}

/// Comparison operators for `byte_test`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ByteTestOp {
    Lt,
    Gt,
    Le,
    Ge,
    Eq,
    Ne,
    And,
    Or,
}

impl fmt::Display for ByteTestOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Lt => "<",
            Self::Gt => ">",
            Self::Le => "<=",
            Self::Ge => ">=",
            Self::Eq => "=",
            Self::Ne => "!=",
            Self::And => "&",
            Self::Or => "|",
        };
        write!(f, "{s}")
    }
}

/// Size comparison operators for `stream_size`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SizeOp {
    Lt,
    Gt,
    Eq,
    Ne,
}

impl fmt::Display for SizeOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Lt => "<",
            Self::Gt => ">",
            Self::Eq => "=",
            Self::Ne => "!=",
        };
        write!(f, "{s}")
    }
}

/// IP option types for `ipopts`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IpOptType {
    Rr,    // Record Route
    Eool,  // End of Option List
    Nop,   // No Operation
    Ts,    // Timestamp
    Sec,   // Security
    Lsrr,  // Loose Source Route
    Ssrr,  // Strict Source Route
    Satid, // Stream Identifier
    Any,
}

impl fmt::Display for IpOptType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Rr => "rr",
            Self::Eool => "eool",
            Self::Nop => "nop",
            Self::Ts => "ts",
            Self::Sec => "sec",
            Self::Lsrr => "lsrr",
            Self::Ssrr => "ssrr",
            Self::Satid => "satid",
            Self::Any => "any",
        };
        write!(f, "{s}")
    }
}

/// Fragment bits check for `fragbits`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FragBitsCheck {
    /// Check for More Fragments (MF).
    pub more_frag: bool,
    /// Check for Don't Fragment (DF).
    pub dont_frag: bool,
    /// Check for Reserved (RB).
    pub reserved: bool,
}

impl fmt::Display for FragBitsCheck {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut s = String::new();
        if self.more_frag {
            s.push('M');
        }
        if self.dont_frag {
            s.push('D');
        }
        if self.reserved {
            s.push('R');
        }
        write!(f, "{s}")
    }
}

/// An extended rule that carries both base conditions and extended options.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtendedRule {
    pub base: Rule,
    pub ext_options: Vec<ExtOption>,
}

impl ExtendedRule {
    /// Create a new extended rule.
    #[must_use]
    pub const fn new(base: Rule) -> Self {
        Self {
            base,
            ext_options: Vec::new(),
        }
    }

    /// Append an extended option.
    pub fn add_ext_option(&mut self, opt: ExtOption) {
        self.ext_options.push(opt);
    }

    /// Returns `true` if this rule has `fast_pattern` designated.
    #[must_use]
    pub fn has_fast_pattern(&self) -> bool {
        self.ext_options
            .iter()
            .any(|o| matches!(o, ExtOption::FastPattern))
    }

    /// Returns `true` if this rule has `rawbytes`.
    #[must_use]
    pub fn has_rawbytes(&self) -> bool {
        self.ext_options
            .iter()
            .any(|o| matches!(o, ExtOption::Rawbytes))
    }

    /// Returns the priority override, if any.
    #[must_use]
    pub fn priority(&self) -> Option<u8> {
        self.ext_options.iter().find_map(|o| {
            if let ExtOption::Priority(p) = o {
                Some(*p)
            } else {
                None
            }
        })
    }

    /// Returns the classtype, if any.
    #[must_use]
    pub fn classtype(&self) -> Option<&str> {
        self.ext_options.iter().find_map(|o| {
            if let ExtOption::Classtype(s) = o {
                Some(s.as_str())
            } else {
                None
            }
        })
    }

    /// Returns all references.
    #[must_use]
    pub fn references(&self) -> Vec<(&str, &str)> {
        self.ext_options
            .iter()
            .filter_map(|o| {
                if let ExtOption::Reference {
                    ref_type,
                    ref_value,
                } = o
                {
                    Some((ref_type.as_str(), ref_value.as_str()))
                } else {
                    None
                }
            })
            .collect()
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Byte-test evaluation helper
// ────────────────────────────────────────────────────────────────────────────

/// Evaluate a `byte_test` condition against a payload.
///
/// # Errors
///
/// Returns `false` if the slice is too short.
#[must_use]
pub fn eval_byte_test(
    payload: &[u8],
    count: u8,
    op: ByteTestOp,
    value: u64,
    offset: usize,
) -> bool {
    let count = count as usize;
    if offset + count > payload.len() {
        return false;
    }
    let slice = &payload[offset..offset + count];
    let actual: u64 = slice.iter().fold(0u64, |acc, &b| (acc << 8) | u64::from(b));
    match op {
        ByteTestOp::Lt => actual < value,
        ByteTestOp::Gt => actual > value,
        ByteTestOp::Le => actual <= value,
        ByteTestOp::Ge => actual >= value,
        ByteTestOp::Eq => actual == value,
        ByteTestOp::Ne => actual != value,
        ByteTestOp::And => (actual & value) != 0,
        ByteTestOp::Or => (actual | value) != 0,
    }
}

/// Evaluate a `byte_jump`: read `count` bytes at `offset`, return new offset.
///
/// Returns `None` if out of bounds.
#[must_use]
pub fn eval_byte_jump(
    payload: &[u8],
    count: u8,
    offset: usize,
    align: bool,
    post_offset: i32,
) -> Option<usize> {
    let count = count as usize;
    if offset + count > payload.len() {
        return None;
    }
    let slice = &payload[offset..offset + count];
    let jump = slice.iter().fold(0usize, |acc, &b| (acc << 8) | b as usize);
    let base = offset + count + jump;
    let aligned = if align { (base + 3) & !3 } else { base };
    let new_offset = if post_offset >= 0 {
        aligned.saturating_add(usize::try_from(post_offset).unwrap_or(0))
    } else {
        aligned.saturating_sub(usize::try_from(post_offset.unsigned_abs()).unwrap_or(0))
    };
    if new_offset <= payload.len() {
        Some(new_offset)
    } else {
        None
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Rule group — grouping rules by a shared property
// ────────────────────────────────────────────────────────────────────────────

/// A named group of rules.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleGroup {
    pub name: String,
    pub description: String,
    pub rules: Vec<Rule>,
}

impl RuleGroup {
    /// Create an empty rule group.
    #[must_use]
    pub fn new(name: impl Into<String>, description: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            description: description.into(),
            rules: Vec::new(),
        }
    }

    /// Add a rule to the group.
    pub fn add(&mut self, rule: Rule) {
        self.rules.push(rule);
    }

    /// Number of rules in the group.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.rules.len()
    }

    /// Returns `true` if the group is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// Build a `RuleEngine` from all rules in the group.
    #[must_use]
    pub fn build_engine(&self) -> RuleEngine {
        let engine = RuleEngine::new();
        for rule in &self.rules {
            engine.add_rule(rule.clone());
        }
        engine
    }
}

impl fmt::Display for RuleGroup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "RuleGroup[{}]: {} rules — {}",
            self.name,
            self.rules.len(),
            self.description
        )
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Rule diff — compare two rule sets and produce a changelog
// ────────────────────────────────────────────────────────────────────────────

/// A change to a rule between two versions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RuleDiff {
    Added(Rule),
    Removed(u32),
    Modified {
        id: u32,
        old_msg: String,
        new_msg: String,
    },
}

impl fmt::Display for RuleDiff {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Added(r) => write!(f, "+ rule {} ({})", r.id, r.msg),
            Self::Removed(id) => write!(f, "- rule {id}"),
            Self::Modified {
                id,
                old_msg,
                new_msg,
            } => write!(f, "~ rule {id}: \"{old_msg}\" -> \"{new_msg}\""),
        }
    }
}

/// Compute the diff between two slices of rules.
#[must_use]
pub fn diff_rules(old: &[Rule], new: &[Rule]) -> Vec<RuleDiff> {
    let old_map: HashMap<u32, &Rule> = old.iter().map(|r| (r.id, r)).collect();
    let new_map: HashMap<u32, &Rule> = new.iter().map(|r| (r.id, r)).collect();
    let mut diffs = Vec::new();

    for (&id, &nr) in &new_map {
        if let Some(&or) = old_map.get(&id) {
            if or.msg != nr.msg {
                diffs.push(RuleDiff::Modified {
                    id,
                    old_msg: or.msg.clone(),
                    new_msg: nr.msg.clone(),
                });
            }
        } else {
            diffs.push(RuleDiff::Added(nr.clone()));
        }
    }
    for &id in old_map.keys() {
        if !new_map.contains_key(&id) {
            diffs.push(RuleDiff::Removed(id));
        }
    }
    diffs.sort_by_key(|d| match d {
        RuleDiff::Added(r) => r.id,
        RuleDiff::Removed(id) | RuleDiff::Modified { id, .. } => *id,
    });
    diffs
}

// ────────────────────────────────────────────────────────────────────────────
// Rule import / export
// ────────────────────────────────────────────────────────────────────────────

/// Serialize a slice of rules to JSON.
///
/// # Errors
///
/// Returns an error string if serialization fails.
pub fn export_rules_json(rules: &[Rule]) -> Result<String, RuleError> {
    serde_json::to_string_pretty(rules).map_err(|e| RuleError::Serialization(e.to_string()))
}

/// Deserialize rules from JSON.
///
/// # Errors
///
/// Returns an error string if deserialization fails.
pub fn import_rules_json(json: &str) -> Result<Vec<Rule>, RuleError> {
    serde_json::from_str(json).map_err(|e| RuleError::Serialization(e.to_string()))
}

/// Serialize a slice of rules to Snort-style text format (one rule per line).
#[must_use]
pub fn export_rules_snort(rules: &[Rule]) -> String {
    rules
        .iter()
        .map(snort_format_rule)
        .collect::<Vec<_>>()
        .join("\n")
}

fn snort_format_rule(r: &Rule) -> String {
    let action = r.action.to_string();
    let proto = r.proto.to_string();
    let src_ip = "any";
    let src_port = "any";
    let dst_ip = "any";
    let dst_port = "any";
    let conds: String = r.conditions.iter().fold(String::new(), |mut acc, c| { use std::fmt::Write; let _ = write!(acc, "{c}; "); acc });
    format!(
        "{action} {proto} {src_ip} {src_port} -> {dst_ip} {dst_port} (msg:\"{}\"; {conds}sid:{}; rev:1;)",
        r.msg, r.id
    )
}

// ────────────────────────────────────────────────────────────────────────────
// Event log
// ────────────────────────────────────────────────────────────────────────────

/// A logged alert event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertEvent {
    pub rule_id: u32,
    pub action: RuleAction,
    pub msg: String,
    pub src_ip: String,
    pub dst_ip: String,
    pub src_port: u16,
    pub dst_port: u16,
    pub proto: u8,
    pub timestamp: u64,
    pub payload_len: usize,
}

impl AlertEvent {
    /// Create an event from a match result and packet context.
    #[must_use]
    pub fn from_match(result: &MatchResult, ctx: &PacketContext, ts: u64) -> Self {
        Self {
            rule_id: result.rule_id,
            action: result.action,
            msg: result.msg.clone(),
            src_ip: ctx.src_ip.to_string(),
            dst_ip: ctx.dst_ip.to_string(),
            src_port: ctx.src_port,
            dst_port: ctx.dst_port,
            proto: ctx.ip_proto,
            timestamp: ts,
            payload_len: ctx.payload.len(),
        }
    }
}

impl fmt::Display for AlertEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{}] rule={} action={} {} {}:{} -> {}:{} len={}",
            self.timestamp,
            self.rule_id,
            self.action,
            self.msg,
            self.src_ip,
            self.src_port,
            self.dst_ip,
            self.dst_port,
            self.payload_len
        )
    }
}

/// An in-memory circular event log.
pub struct EventLog {
    events: parking_lot::Mutex<std::collections::VecDeque<AlertEvent>>,
    capacity: usize,
}

impl EventLog {
    /// Create a new event log with the given capacity.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            events: parking_lot::Mutex::new(std::collections::VecDeque::with_capacity(capacity)),
            capacity,
        }
    }

    /// Append an event, dropping the oldest if over capacity.
    pub fn push(&self, event: AlertEvent) {
        let mut q = self.events.lock();
        if q.len() >= self.capacity {
            q.pop_front();
        }
        q.push_back(event);
    }

    /// Return a snapshot of all events in order.
    #[must_use]
    pub fn snapshot(&self) -> Vec<AlertEvent> {
        self.events.lock().iter().cloned().collect()
    }

    /// Return the number of events currently stored.
    #[must_use]
    pub fn len(&self) -> usize {
        self.events.lock().len()
    }

    /// Returns `true` if no events are stored.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.events.lock().is_empty()
    }

    /// Clear all events.
    pub fn clear(&self) {
        self.events.lock().clear();
    }

    /// Return events filtered by `rule_id`.
    #[must_use]
    pub fn by_rule(&self, rule_id: u32) -> Vec<AlertEvent> {
        self.events
            .lock()
            .iter()
            .filter(|e| e.rule_id == rule_id)
            .cloned()
            .collect()
    }

    /// Return events filtered by source IP string.
    #[must_use]
    pub fn by_src(&self, src_ip: &str) -> Vec<AlertEvent> {
        self.events
            .lock()
            .iter()
            .filter(|e| e.src_ip == src_ip)
            .cloned()
            .collect()
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Full pipeline: engine + stats + log
// ────────────────────────────────────────────────────────────────────────────

/// Complete detection pipeline: rule engine + stats tracking + event logging.
pub struct DetectionPipeline {
    engine: RuleEngine,
    tracker: RuleStatsTracker,
    log: EventLog,
}

impl DetectionPipeline {
    /// Create a new pipeline with the given event log capacity.
    #[must_use]
    pub fn new(log_capacity: usize) -> Self {
        Self {
            engine: RuleEngine::new(),
            tracker: RuleStatsTracker::new(),
            log: EventLog::new(log_capacity),
        }
    }

    /// Add a rule.
    pub fn add_rule(&self, rule: Rule) {
        self.engine.add_rule(rule);
    }

    /// Process a packet at timestamp `ts`.  Returns all match results and
    /// logs each match.
    #[must_use]
    pub fn process(&self, ctx: &PacketContext, ts: u64) -> Vec<MatchResult> {
        let results = self.engine.evaluate_all(ctx);
        for r in &results {
            self.tracker.record_match(r.rule_id, ctx.payload.len(), ts);
            self.log.push(AlertEvent::from_match(r, ctx, ts));
        }
        results
    }

    /// Access the stats tracker.
    #[must_use]
    pub const fn stats(&self) -> &RuleStatsTracker {
        &self.tracker
    }

    /// Access the event log.
    #[must_use]
    pub const fn log(&self) -> &EventLog {
        &self.log
    }

    /// Return the number of rules loaded.
    #[must_use]
    pub fn rule_count(&self) -> usize {
        self.engine.rules().len()
    }
}

// ────────────────────────────────────────────────────────────────────────────
// PCRE stub integration
// ────────────────────────────────────────────────────────────────────────────

/// A compiled PCRE-stub pattern.  In production this would wrap the
/// `pcre2` crate; here we use simple substring matching as a stub.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PcrePattern {
    raw: String,
    flags: PcreFlags,
}

/// PCRE modifier flags.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct PcreFlags {
    /// Case-insensitive (`/i`).
    pub case_insensitive: bool,
    /// Single-line (dot matches `\n`) (`/s`).
    pub single_line: bool,
    /// Multi-line (`/m`).
    pub multi_line: bool,
    /// Extended (whitespace/comments ignored) (`/x`).
    pub extended: bool,
    /// Match relative to last content match (`/R`).
    pub relative: bool,
    /// Inverted match (`/!`).
    pub negate: bool,
}

impl PcrePattern {
    /// Parse a PCRE option string like `"/pattern/flags"`.
    ///
    /// # Errors
    ///
    /// Returns [`RuleError::ParseError`] if the delimiter `/` is missing.
    pub fn parse(s: &str) -> Result<Self, RuleError> {
        let s = s.trim_matches('"');
        if !s.starts_with('/') {
            return Err(RuleError::ParseError {
                token: s.to_string(),
                msg: "PCRE must start with '/'".to_string(),
            });
        }
        // Find closing delimiter
        let rest = &s[1..];
        let close = rest.rfind('/').ok_or_else(|| RuleError::ParseError {
            token: s.to_string(),
            msg: "PCRE missing closing '/'".to_string(),
        })?;
        let raw = rest[..close].to_string();
        let flags_str = &rest[close + 1..];
        let mut flags = PcreFlags::default();
        for ch in flags_str.chars() {
            match ch {
                'i' => flags.case_insensitive = true,
                's' => flags.single_line = true,
                'm' => flags.multi_line = true,
                'x' => flags.extended = true,
                'R' => flags.relative = true,
                '!' => flags.negate = true,
                _ => {}
            }
        }
        Ok(Self { raw, flags })
    }

    /// Test whether `haystack` matches this pattern.
    ///
    /// This is a stub: it performs a substring search, optionally
    /// case-insensitive, and respects the `!` (negate) flag.
    #[must_use]
    pub fn matches(&self, haystack: &[u8]) -> bool {
        let text = std::str::from_utf8(haystack).unwrap_or("");
        let found = if self.flags.case_insensitive {
            text.to_lowercase().contains(&self.raw.to_lowercase())
        } else {
            text.contains(self.raw.as_str())
        };
        if self.flags.negate { !found } else { found }
    }

    /// Returns the raw pattern string.
    #[must_use]
    pub fn raw(&self) -> &str {
        &self.raw
    }

    /// Returns the parsed flags.
    #[must_use]
    pub const fn flags(&self) -> PcreFlags {
        self.flags
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Flowbit state machine
// ────────────────────────────────────────────────────────────────────────────

/// Flowbit operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FlowbitOp {
    Set(String),
    Unset(String),
    Toggle(String),
    IsSet(String),
    IsNotSet(String),
    NoAlert,
}

impl fmt::Display for FlowbitOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Set(s) => write!(f, "set,{s}"),
            Self::Unset(s) => write!(f, "unset,{s}"),
            Self::Toggle(s) => write!(f, "toggle,{s}"),
            Self::IsSet(s) => write!(f, "isset,{s}"),
            Self::IsNotSet(s) => write!(f, "isnotset,{s}"),
            Self::NoAlert => write!(f, "noalert"),
        }
    }
}

/// Per-flow flowbit storage.
pub struct FlowbitStore {
    bits: parking_lot::Mutex<HashMap<String, HashSet<String>>>,
}

impl FlowbitStore {
    /// Create an empty flowbit store.
    #[must_use]
    pub fn new() -> Self {
        Self {
            bits: parking_lot::Mutex::new(HashMap::new()),
        }
    }

    /// Set a bit for a flow key.
    pub fn set(&self, flow: &str, bit: &str) {
        self.bits
            .lock()
            .entry(flow.to_string())
            .or_default()
            .insert(bit.to_string());
    }

    /// Unset a bit.
    pub fn unset(&self, flow: &str, bit: &str) {
        if let Some(set) = self.bits.lock().get_mut(flow) {
            set.remove(bit);
        }
    }

    /// Toggle a bit (set if unset, unset if set).
    pub fn toggle(&self, flow: &str, bit: &str) {
        let mut map = self.bits.lock();
        let set = map.entry(flow.to_string()).or_default();
        if set.contains(bit) {
            set.remove(bit);
        } else {
            set.insert(bit.to_string());
        }
        drop(map);
    }

    /// Returns `true` if the bit is set.
    #[must_use]
    pub fn is_set(&self, flow: &str, bit: &str) -> bool {
        self.bits.lock().get(flow).is_some_and(|s| s.contains(bit))
    }

    /// Evaluate a flowbit operation and return `true` if the condition passes.
    #[must_use]
    pub fn eval(&self, flow: &str, op: &FlowbitOp) -> bool {
        match op {
            FlowbitOp::Set(b) => {
                self.set(flow, b);
                true
            }
            FlowbitOp::Unset(b) => {
                self.unset(flow, b);
                true
            }
            FlowbitOp::Toggle(b) => {
                self.toggle(flow, b);
                true
            }
            FlowbitOp::IsSet(b) => self.is_set(flow, b),
            FlowbitOp::IsNotSet(b) => !self.is_set(flow, b),
            FlowbitOp::NoAlert => false,
        }
    }

    /// Return the number of flows tracked.
    #[must_use]
    pub fn flow_count(&self) -> usize {
        self.bits.lock().len()
    }
}

impl Default for FlowbitStore {
    fn default() -> Self {
        Self::new()
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Variable substitution table ($HOME_NET, $EXTERNAL_NET, etc.)
// ────────────────────────────────────────────────────────────────────────────

/// A table of named network/port variables for rule substitution.
#[derive(Debug, Clone, Default)]
pub struct VarTable {
    ip_vars: HashMap<String, IpSpec>,
    port_vars: HashMap<String, PortSpec>,
}

impl VarTable {
    /// Create an empty variable table.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a table with common Snort variables pre-populated.
    ///
    /// # Panics
    /// Panics if any of the built-in default IP literals fail to parse,
    /// which should never occur for the hard-coded RFC1918 strings used here.
    #[must_use]
    pub fn with_defaults() -> Self {
        let mut t = Self::new();
        t.set_ip("HOME_NET", IpSpec::Cidr("192.168.0.0".parse().unwrap(), 16));
        t.set_ip(
            "EXTERNAL_NET",
            IpSpec::Not(Box::new(IpSpec::Cidr("192.168.0.0".parse().unwrap(), 16))),
        );
        t.set_ip("HTTP_SERVERS", IpSpec::Any);
        t.set_ip("SQL_SERVERS", IpSpec::Any);
        t.set_ip("DNS_SERVERS", IpSpec::Any);
        t.set_ip("SMTP_SERVERS", IpSpec::Any);
        t.set_port("HTTP_PORTS", PortSpec::Range(80, 80));
        t.set_port("HTTPS_PORTS", PortSpec::Single(443));
        t.set_port("SSH_PORTS", PortSpec::Single(22));
        t.set_port("FTP_PORTS", PortSpec::Single(21));
        t.set_port("DNS_PORTS", PortSpec::Single(53));
        t
    }

    /// Define an IP variable.
    pub fn set_ip(&mut self, name: &str, spec: IpSpec) {
        self.ip_vars.insert(name.to_string(), spec);
    }

    /// Define a port variable.
    pub fn set_port(&mut self, name: &str, spec: PortSpec) {
        self.port_vars.insert(name.to_string(), spec);
    }

    /// Resolve a `$VAR` IP reference, returning `IpSpec::Any` if not found.
    #[must_use]
    pub fn resolve_ip(&self, name: &str) -> IpSpec {
        self.ip_vars.get(name).cloned().unwrap_or(IpSpec::Any)
    }

    /// Resolve a `$VAR` port reference, returning `PortSpec::Any` if not found.
    #[must_use]
    pub fn resolve_port(&self, name: &str) -> PortSpec {
        self.port_vars.get(name).cloned().unwrap_or(PortSpec::Any)
    }

    /// Returns all IP variable names.
    #[must_use]
    pub fn ip_var_names(&self) -> Vec<&str> {
        self.ip_vars
            .keys()
            .map(std::string::String::as_str)
            .collect()
    }

    /// Returns all port variable names.
    #[must_use]
    pub fn port_var_names(&self) -> Vec<&str> {
        self.port_vars
            .keys()
            .map(std::string::String::as_str)
            .collect()
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Nocase content matching helper
// ────────────────────────────────────────────────────────────────────────────

/// Case-insensitive byte-pattern search.
///
/// Returns the start index of the first match, or `None`.
#[must_use]
pub fn find_bytes_nocase(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    let n = needle.len();
    if haystack.len() < n {
        return None;
    }
    (0..=(haystack.len() - n)).find(|&i| haystack[i..i + n].eq_ignore_ascii_case(needle))
}

// ────────────────────────────────────────────────────────────────────────────
// Detection filter (per-rule rate-limit as Suricata "detection_filter")
// ────────────────────────────────────────────────────────────────────────────

/// Detection filter for a rule: suppress alerts until a rate threshold is met.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionFilter {
    pub rule_id: u32,
    pub track: ThresholdTrack,
    pub count: u32,
    pub seconds: u64,
}

/// State for a detection filter key.
#[derive(Debug, Clone)]
struct DetectionFilterState {
    hit_count: u32,
    window_start: u64,
}

/// Detection filter engine layer.
pub struct DetectionFilterEngine {
    engine: RuleEngine,
    filters: Vec<DetectionFilter>,
    state: parking_lot::Mutex<HashMap<(u32, String), DetectionFilterState>>,
}

impl DetectionFilterEngine {
    /// Create a new detection filter engine.
    #[must_use]
    pub fn new(engine: RuleEngine) -> Self {
        Self {
            engine,
            filters: Vec::new(),
            state: parking_lot::Mutex::new(HashMap::new()),
        }
    }

    /// Register a detection filter for a rule.
    pub fn add_filter(&mut self, f: DetectionFilter) {
        self.filters.push(f);
    }

    /// Evaluate a packet at `now_secs`, returning matches only when detection
    /// filter thresholds are exceeded.
    #[must_use]
    pub fn evaluate(&self, ctx: &PacketContext, now_secs: u64) -> Vec<MatchResult> {
        let raw = self.engine.evaluate_all(ctx);
        let mut out = Vec::new();
        for result in raw {
            let rid = result.rule_id;
            if let Some(flt) = self.filters.iter().find(|f| f.rule_id == rid) {
                let key = match flt.track {
                    ThresholdTrack::BySrc => ctx.src_ip.to_string(),
                    ThresholdTrack::ByDst => ctx.dst_ip.to_string(),
                    ThresholdTrack::ByRule => "__rule__".to_string(),
                };
                let map_key = (rid, key);
                let mut state_map = self.state.lock();
                let entry = state_map.entry(map_key).or_insert(DetectionFilterState {
                    hit_count: 0,
                    window_start: now_secs,
                });
                if now_secs.saturating_sub(entry.window_start) >= flt.seconds {
                    entry.hit_count = 0;
                    entry.window_start = now_secs;
                }
                entry.hit_count += 1;
                let above = entry.hit_count >= flt.count;
                drop(state_map);
                if above {
                    out.push(result);
                }
            } else {
                out.push(result);
            }
        }
        out
    }
}

// ────────────────────────────────────────────────────────────────────────────
// DSL-based NetworkRule, NetworkRuleCompiler, NetworkRuleMatcher, RuleDatabase
// ────────────────────────────────────────────────────────────────────────────

/// A parsed network rule produced by [`NetworkRuleCompiler`].
///
/// The rule uses the simplified Snort/Suricata DSL:
/// ```text
/// alert tcp any any -> any 80 (msg:"HTTP"; content:"GET /"; nocase; sid:1; rev:1;)
/// ```
///
/// [`RuleOption`] is the existing option type already defined in this crate
/// (with `Content(Vec<u8>)`, `Nocase`, `Offset(usize)`, `Depth(usize)`, etc.).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkRule {
    pub action: RuleAction,
    pub proto: Proto,
    pub src: NetworkSpec,
    pub dst: NetworkSpec,
    pub options: Vec<RuleOption>,
}

impl NetworkRule {
    /// Return the `Msg` string if present.
    #[must_use]
    pub fn msg(&self) -> Option<&str> {
        self.options.iter().find_map(|o| {
            if let RuleOption::Msg(m) = o {
                Some(m.as_str())
            } else {
                None
            }
        })
    }

    /// Return the `Sid` if present.
    #[must_use]
    pub fn sid(&self) -> Option<u32> {
        self.options.iter().find_map(|o| {
            if let RuleOption::Sid(s) = o {
                Some(*s)
            } else {
                None
            }
        })
    }

    /// Return the `Rev` if present.
    #[must_use]
    pub fn rev(&self) -> Option<u32> {
        self.options.iter().find_map(|o| {
            if let RuleOption::Rev(r) = o {
                Some(*r)
            } else {
                None
            }
        })
    }
}

/// Compiles a simplified rule DSL string into a [`NetworkRule`].
///
/// # Syntax
/// ```text
/// <action> <proto> <src-addr> <src-port> -> <dst-addr> <dst-port> (<options>)
/// ```
/// where `<options>` is a semicolon-separated list of keyword arguments,
/// e.g. `msg:"label"; content:"GET /"; nocase; offset:0; depth:10; sid:1001; rev:1;`.
pub struct NetworkRuleCompiler;

impl NetworkRuleCompiler {
    /// Parse a single DSL rule string and return a [`NetworkRule`].
    ///
    /// # Errors
    /// Returns [`RuleError::ParseError`] for any malformed input.
    pub fn compile(input: &str) -> Result<NetworkRule, RuleError> {
        let input = input.trim();
        let paren_open = input.find('(').ok_or_else(|| RuleError::ParseError {
            token: input.to_string(),
            msg: "missing opening '('".to_string(),
        })?;
        let paren_close = input.rfind(')').ok_or_else(|| RuleError::ParseError {
            token: input.to_string(),
            msg: "missing closing ')'".to_string(),
        })?;
        if paren_close <= paren_open {
            return Err(RuleError::ParseError {
                token: input.to_string(),
                msg: "malformed options block".to_string(),
            });
        }

        let header = input[..paren_open].trim();
        let options_raw = &input[paren_open + 1..paren_close];

        // Header: action proto src_addr src_port -> dst_addr dst_port
        let parts: Vec<&str> = header.split_whitespace().collect();
        if parts.len() < 7 {
            return Err(RuleError::ParseError {
                token: header.to_string(),
                msg: format!("expected 7 header tokens, found {}", parts.len()),
            });
        }

        let action = parse_action(parts[0])?;
        let proto = parse_proto(parts[1])?;
        let src = NetworkSpec {
            addr: parse_ip_spec(parts[2])?,
            port: parse_port_spec(parts[3])?,
        };
        // parts[4] should be "->" (direction, currently ignored)
        let dst = NetworkSpec {
            addr: parse_ip_spec(parts[5])?,
            port: parse_port_spec(parts[6])?,
        };

        let options = parse_rule_options(options_raw)?;

        Ok(NetworkRule {
            action,
            proto,
            src,
            dst,
            options,
        })
    }

    /// Parse multiple rules, one per non-empty/non-comment line.
    /// Lines starting with `#` are skipped. Parse errors are returned for the
    /// first offending line.
    ///
    /// # Errors
    /// Returns the first [`RuleError`] encountered.
    pub fn compile_all(input: &str) -> Result<Vec<NetworkRule>, RuleError> {
        input
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .map(Self::compile)
            .collect()
    }
}

/// Parse the options block `"msg:\"x\"; content:\"y\"; nocase; ..."` into
/// a list of [`RuleOption`] values.
///
/// Uses the existing [`RuleOption`] type:
/// `Content(Vec<u8>)`, `Offset(usize)`, `Depth(usize)`, etc.
fn parse_rule_options(raw: &str) -> Result<Vec<RuleOption>, RuleError> {
    let mut opts = Vec::new();
    // Split on ';' but keep strings with escaped quotes intact
    let segments = split_option_segments(raw);
    for seg in segments {
        let seg = seg.trim();
        if seg.is_empty() {
            continue;
        }
        if seg.eq_ignore_ascii_case("nocase") {
            opts.push(RuleOption::Nocase);
        } else if let Some(rest) = strip_keyword_ci(seg, "msg:") {
            opts.push(RuleOption::Msg(unquote(rest)));
        } else if let Some(rest) = strip_keyword_ci(seg, "content:") {
            opts.push(RuleOption::Content(unquote(rest).into_bytes()));
        } else if let Some(rest) = strip_keyword_ci(seg, "offset:") {
            let n = rest
                .trim()
                .parse::<usize>()
                .map_err(|_| RuleError::ParseError {
                    token: seg.to_string(),
                    msg: "invalid offset value".to_string(),
                })?;
            opts.push(RuleOption::Offset(n));
        } else if let Some(rest) = strip_keyword_ci(seg, "depth:") {
            let n = rest
                .trim()
                .parse::<usize>()
                .map_err(|_| RuleError::ParseError {
                    token: seg.to_string(),
                    msg: "invalid depth value".to_string(),
                })?;
            opts.push(RuleOption::Depth(n));
        } else if let Some(rest) = strip_keyword_ci(seg, "sid:") {
            let n = rest
                .trim()
                .parse::<u32>()
                .map_err(|_| RuleError::ParseError {
                    token: seg.to_string(),
                    msg: "invalid sid value".to_string(),
                })?;
            opts.push(RuleOption::Sid(n));
        } else if let Some(rest) = strip_keyword_ci(seg, "rev:") {
            let n = rest
                .trim()
                .parse::<u32>()
                .map_err(|_| RuleError::ParseError {
                    token: seg.to_string(),
                    msg: "invalid rev value".to_string(),
                })?;
            opts.push(RuleOption::Rev(n));
        }
        // Unknown keywords are silently ignored (forward-compat)
    }
    Ok(opts)
}

/// Split the options string on `;` while preserving quoted strings.
fn split_option_segments(s: &str) -> Vec<String> {
    let mut segments = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        match c {
            '"' => {
                in_quotes = !in_quotes;
                current.push(c);
            }
            '\\' if in_quotes => {
                current.push(c);
                if let Some(nc) = chars.next() {
                    current.push(nc);
                }
            }
            ';' if !in_quotes => {
                segments.push(current.clone());
                current.clear();
            }
            _ => current.push(c),
        }
    }
    if !current.trim().is_empty() {
        segments.push(current);
    }
    segments
}

/// Strip a keyword prefix (case-insensitive) and return the remainder.
fn strip_keyword_ci<'a>(s: &'a str, keyword: &str) -> Option<&'a str> {
    if s.len() >= keyword.len() && s[..keyword.len()].eq_ignore_ascii_case(keyword) {
        Some(&s[keyword.len()..])
    } else {
        None
    }
}

/// Remove surrounding double-quotes and unescape `\"` sequences.
fn unquote(s: &str) -> String {
    let s = s.trim();
    let s = if s.starts_with('"') && s.ends_with('"') && s.len() >= 2 {
        &s[1..s.len() - 1]
    } else {
        s
    };
    s.replace("\\\"", "\"")
}

// ────────────────────────────────────────────────────────────────────────────
// NetworkRuleMatcher
// ────────────────────────────────────────────────────────────────────────────

/// Matches packet payloads against a [`NetworkRule`] respecting `content`,
/// `nocase`, `offset`, and `depth` modifiers.
pub struct NetworkRuleMatcher;

impl NetworkRuleMatcher {
    /// Returns `true` when `payload` satisfies all content/modifier options in
    /// `rule`.  Header fields (IP, port, protocol) are *not* checked here —
    /// use [`RuleDatabase`] or [`RuleEngine`] for full packet matching.
    #[must_use]
    pub fn match_packet(rule: &NetworkRule, payload: &[u8]) -> bool {
        let opts = &rule.options;
        let mut i = 0usize;
        while i < opts.len() {
            if let RuleOption::Content(pattern) = &opts[i] {
                // Collect modifiers that follow this Content keyword
                let mut nocase = false;
                let mut offset: usize = 0;
                let mut depth: Option<usize> = None;
                let mut j = i + 1;
                while j < opts.len() {
                    match &opts[j] {
                        RuleOption::Nocase => {
                            nocase = true;
                            j += 1;
                        }
                        RuleOption::Offset(o) => {
                            offset = *o;
                            j += 1;
                        }
                        RuleOption::Depth(d) => {
                            depth = Some(*d);
                            j += 1;
                        }
                        RuleOption::Content(_) => break,
                        _ => {
                            j += 1;
                        }
                    }
                }
                // Determine the search window
                let start = offset.min(payload.len());
                let end = depth.map_or(payload.len(), |d| (offset + d).min(payload.len()));
                if start > end {
                    return false;
                }
                let window = &payload[start..end];
                let found = if nocase {
                    find_bytes_nocase(window, pattern).is_some()
                } else {
                    find_bytes(window, pattern).is_some()
                };
                if !found {
                    return false;
                }
                i = j;
            } else {
                i += 1;
            }
        }
        true
    }
}

// ────────────────────────────────────────────────────────────────────────────
// RuleDatabase
// ────────────────────────────────────────────────────────────────────────────

/// Statistics about a [`RuleDatabase`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleDbStats {
    /// Number of rules currently stored.
    pub rule_count: usize,
    /// Whether the database has been compiled / frozen for matching.
    /// In this implementation it is always `true` (rules are matched
    /// directly without a separate compilation step).
    pub compiled: bool,
}

impl fmt::Display for RuleDbStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "RuleDatabase {{ rules: {}, compiled: {} }}",
            self.rule_count, self.compiled
        )
    }
}

/// An in-memory database of [`NetworkRule`]s that supports bulk matching.
///
/// Rules are stored in insertion order. Both [`Self::match_all`] and
/// [`Self::match_first`] use [`NetworkRuleMatcher`] for payload checking.
#[derive(Debug, Default)]
pub struct RuleDatabase {
    rules: Vec<NetworkRule>,
}

impl RuleDatabase {
    /// Create an empty database.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a compiled [`NetworkRule`] to the database.
    pub fn add_rule(&mut self, rule: NetworkRule) {
        self.rules.push(rule);
    }

    /// Compile and add a DSL string.
    ///
    /// # Errors
    /// Returns [`RuleError::ParseError`] if the DSL string is invalid.
    pub fn add_rule_str(&mut self, dsl: &str) -> Result<(), RuleError> {
        let rule = NetworkRuleCompiler::compile(dsl)?;
        self.rules.push(rule);
        Ok(())
    }

    /// Returns references to all rules that match `payload`.
    #[must_use]
    pub fn match_all<'a>(&'a self, payload: &[u8]) -> Vec<&'a NetworkRule> {
        self.rules
            .iter()
            .filter(|r| NetworkRuleMatcher::match_packet(r, payload))
            .collect()
    }

    /// Returns a reference to the first rule that matches `payload`, if any.
    #[must_use]
    pub fn match_first(&self, payload: &[u8]) -> Option<&NetworkRule> {
        self.rules
            .iter()
            .find(|r| NetworkRuleMatcher::match_packet(r, payload))
    }

    /// Return database statistics.
    #[must_use]
    pub const fn stats(&self) -> RuleDbStats {
        RuleDbStats {
            rule_count: self.rules.len(),
            compiled: true,
        }
    }

    /// Return an iterator over all stored rules.
    pub fn iter(&self) -> impl Iterator<Item = &NetworkRule> {
        self.rules.iter()
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Additional tests
// ────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod extended_tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn simple_ctx(payload: &[u8]) -> PacketContext {
        PacketContext {
            src_ip: IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8)),
            src_port: 1234,
            dst_port: 80,
            ip_proto: 6,
            ttl: 64,
            payload: payload.to_vec(),
            tcp_flags: TcpFlags::empty(),
        }
    }

    // ── RuleStats ──────────────────────────────────────────────────────────

    #[test]
    fn rule_stats_record_and_display() {
        let mut stats = RuleStats::new(42);
        assert!(!stats.ever_matched());
        stats.record(100, 1000);
        stats.record(200, 2000);
        assert_eq!(stats.match_count, 2);
        assert_eq!(stats.total_bytes_matched, 300);
        assert_eq!(stats.last_matched_ts, 2000);
        assert!(stats.ever_matched());
        let s = stats.to_string();
        assert!(s.contains("42"));
        assert!(s.contains("300"));
    }

    #[test]
    fn rule_stats_tracker_aggregate() {
        let tracker = RuleStatsTracker::new();
        tracker.record_match(1, 50, 100);
        tracker.record_match(1, 75, 200);
        tracker.record_match(2, 30, 150);
        assert_eq!(tracker.tracked_rule_count(), 2);
        assert_eq!(tracker.total_matches(), 3);
        let s1 = tracker.get(1).unwrap();
        assert_eq!(s1.match_count, 2);
        assert_eq!(s1.total_bytes_matched, 125);
    }

    #[test]
    fn rule_stats_tracker_reset() {
        let tracker = RuleStatsTracker::new();
        tracker.record_match(1, 10, 0);
        tracker.reset();
        assert_eq!(tracker.tracked_rule_count(), 0);
        assert_eq!(tracker.total_matches(), 0);
    }

    #[test]
    fn rule_stats_tracker_all_sorted() {
        let tracker = RuleStatsTracker::new();
        tracker.record_match(3, 1, 0);
        tracker.record_match(1, 1, 0);
        tracker.record_match(2, 1, 0);
        let all = tracker.all();
        let ids: Vec<u32> = all.iter().map(|s| s.rule_id).collect();
        assert_eq!(ids, [1, 2, 3]);
    }

    // ── StatsRuleEngine ────────────────────────────────────────────────────

    #[test]
    fn stats_engine_tracks_matches() {
        let engine = RuleEngine::new();
        let mut rule = Rule::new(
            99,
            RuleAction::Alert,
            Proto::Any,
            NetworkSpec::any(),
            NetworkSpec::any(),
            "stats-rule",
        );
        rule.conditions.push(Condition::Content(b"hit".to_vec()));
        engine.add_rule(rule);

        let se = StatsRuleEngine::new(engine);
        let ctx = simple_ctx(b"please hit me");
        let _ = se.evaluate(&ctx, 1000);
        let _ = se.evaluate(&ctx, 2000);

        let stats = se.tracker().get(99).unwrap();
        assert_eq!(stats.match_count, 2);
        assert_eq!(stats.last_matched_ts, 2000);
    }

    // ── byte_test / byte_jump ──────────────────────────────────────────────

    #[test]
    fn byte_test_eq() {
        let payload = [0x00, 0x10, 0xFF, 0xAB];
        assert!(eval_byte_test(&payload, 2, ByteTestOp::Eq, 0x0010, 0));
        assert!(!eval_byte_test(&payload, 2, ByteTestOp::Eq, 0x0011, 0));
    }

    #[test]
    fn byte_test_gt_lt() {
        let payload = [0x00, 0x10];
        assert!(eval_byte_test(&payload, 2, ByteTestOp::Gt, 0x000F, 0));
        assert!(eval_byte_test(&payload, 2, ByteTestOp::Lt, 0x0011, 0));
    }

    #[test]
    fn byte_test_and_or() {
        let payload = [0b1010_1010, 0b0101_0101];
        assert!(eval_byte_test(&payload, 1, ByteTestOp::And, 0b1000_0000, 0));
        assert!(!eval_byte_test(
            &payload,
            1,
            ByteTestOp::And,
            0b0100_0000,
            0
        ));
        assert!(eval_byte_test(&payload, 1, ByteTestOp::Or, 0b1111_1111, 0));
    }

    #[test]
    fn byte_test_out_of_bounds() {
        let payload = [0x01];
        assert!(!eval_byte_test(&payload, 2, ByteTestOp::Eq, 0x0100, 0));
    }

    #[test]
    fn byte_jump_basic() {
        let payload = [0x00, 0x04, b'h', b'e', b'l', b'l', b'o'];
        // count=2 bytes at offset=0: value=4, jump past offset 2 by 4 → new offset=6
        let new_off = eval_byte_jump(&payload, 2, 0, false, 0).unwrap();
        assert_eq!(new_off, 6);
    }

    #[test]
    fn byte_jump_post_offset() {
        let payload = [0x00, 0x02, b'a', b'b', b'c'];
        // value=2, base=4, post_offset=1 → 5
        let new_off = eval_byte_jump(&payload, 2, 0, false, 1).unwrap();
        assert_eq!(new_off, 5);
    }

    #[test]
    fn byte_jump_align() {
        let payload = [0x00, 0x01, b'a', b'b', b'c', b'd'];
        // value=1, base=3, aligned to 4 boundary: (3+3)&!3 = 4
        let new_off = eval_byte_jump(&payload, 2, 0, true, 0).unwrap();
        assert_eq!(new_off, 4);
    }

    // ── ExtendedRule ───────────────────────────────────────────────────────

    #[test]
    fn extended_rule_flags() {
        let base = Rule::new(
            1,
            RuleAction::Alert,
            Proto::Any,
            NetworkSpec::any(),
            NetworkSpec::any(),
            "ext",
        );
        let mut er = ExtendedRule::new(base);
        assert!(!er.has_fast_pattern());
        er.add_ext_option(ExtOption::FastPattern);
        er.add_ext_option(ExtOption::Rawbytes);
        assert!(er.has_fast_pattern());
        assert!(er.has_rawbytes());
    }

    #[test]
    fn extended_rule_priority_classtype() {
        let base = Rule::new(
            2,
            RuleAction::Drop,
            Proto::Tcp,
            NetworkSpec::any(),
            NetworkSpec::any(),
            "ext2",
        );
        let mut er = ExtendedRule::new(base);
        assert!(er.priority().is_none());
        er.add_ext_option(ExtOption::Priority(3));
        er.add_ext_option(ExtOption::Classtype("exploit".to_string()));
        assert_eq!(er.priority(), Some(3));
        assert_eq!(er.classtype(), Some("exploit"));
    }

    #[test]
    fn extended_rule_references() {
        let base = Rule::new(
            3,
            RuleAction::Alert,
            Proto::Any,
            NetworkSpec::any(),
            NetworkSpec::any(),
            "ref-rule",
        );
        let mut er = ExtendedRule::new(base);
        er.add_ext_option(ExtOption::Reference {
            ref_type: "cve".to_string(),
            ref_value: "2017-0144".to_string(),
        });
        let refs = er.references();
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0], ("cve", "2017-0144"));
    }

    // ── ByteTestOp display ─────────────────────────────────────────────────

    #[test]
    fn byte_test_op_display() {
        assert_eq!(ByteTestOp::Lt.to_string(), "<");
        assert_eq!(ByteTestOp::Gt.to_string(), ">");
        assert_eq!(ByteTestOp::Eq.to_string(), "=");
        assert_eq!(ByteTestOp::Ne.to_string(), "!=");
        assert_eq!(ByteTestOp::And.to_string(), "&");
    }

    // ── RuleGroup ─────────────────────────────────────────────────────────

    #[test]
    fn rule_group_add_and_build() {
        let mut g = RuleGroup::new("web", "HTTP detection rules");
        assert!(g.is_empty());
        g.add(Rule::new(
            1,
            RuleAction::Alert,
            Proto::Tcp,
            NetworkSpec::any(),
            NetworkSpec::any(),
            "g1",
        ));
        g.add(Rule::new(
            2,
            RuleAction::Alert,
            Proto::Tcp,
            NetworkSpec::any(),
            NetworkSpec::any(),
            "g2",
        ));
        assert_eq!(g.len(), 2);
        let engine = g.build_engine();
        assert_eq!(engine.rules().len(), 2);
        assert!(g.to_string().contains("web"));
    }

    // ── diff_rules ─────────────────────────────────────────────────────────

    #[test]
    fn rule_diff_added_removed_modified() {
        let old = vec![
            Rule::new(
                1,
                RuleAction::Alert,
                Proto::Any,
                NetworkSpec::any(),
                NetworkSpec::any(),
                "old msg",
            ),
            Rule::new(
                2,
                RuleAction::Drop,
                Proto::Any,
                NetworkSpec::any(),
                NetworkSpec::any(),
                "removed",
            ),
        ];
        let new = vec![
            Rule::new(
                1,
                RuleAction::Alert,
                Proto::Any,
                NetworkSpec::any(),
                NetworkSpec::any(),
                "new msg",
            ),
            Rule::new(
                3,
                RuleAction::Alert,
                Proto::Any,
                NetworkSpec::any(),
                NetworkSpec::any(),
                "added",
            ),
        ];
        let diffs = diff_rules(&old, &new);
        assert!(
            diffs
                .iter()
                .any(|d| matches!(d, RuleDiff::Modified { id: 1, .. }))
        );
        assert!(diffs.iter().any(|d| matches!(d, RuleDiff::Removed(2))));
        assert!(
            diffs
                .iter()
                .any(|d| matches!(d, RuleDiff::Added(r) if r.id == 3))
        );
        // Check Display
        for d in &diffs {
            let _ = d.to_string();
        }
    }

    // ── export / import ────────────────────────────────────────────────────

    #[test]
    fn export_import_json_roundtrip() {
        let rules = vec![
            Rule::new(
                1,
                RuleAction::Alert,
                Proto::Tcp,
                NetworkSpec::any(),
                NetworkSpec::any(),
                "r1",
            ),
            Rule::new(
                2,
                RuleAction::Drop,
                Proto::Udp,
                NetworkSpec::any(),
                NetworkSpec::any(),
                "r2",
            ),
        ];
        let json = export_rules_json(&rules).unwrap();
        let imported = import_rules_json(&json).unwrap();
        assert_eq!(imported.len(), 2);
        assert_eq!(imported[0].id, 1);
        assert_eq!(imported[1].msg, "r2");
    }

    #[test]
    fn export_rules_snort_format() {
        let rules = vec![Rule::new(
            100,
            RuleAction::Alert,
            Proto::Tcp,
            NetworkSpec::any(),
            NetworkSpec::any(),
            "snort-export",
        )];
        let text = export_rules_snort(&rules);
        assert!(text.contains("alert"));
        assert!(text.contains("tcp"));
        assert!(text.contains("snort-export"));
        assert!(text.contains("sid:100"));
    }

    // ── EventLog ──────────────────────────────────────────────────────────

    #[test]
    fn event_log_capacity_eviction() {
        let log = EventLog::new(3);
        for i in 0u32..5 {
            let event = AlertEvent {
                rule_id: i,
                action: RuleAction::Alert,
                msg: format!("event {i}"),
                src_ip: "1.2.3.4".to_string(),
                dst_ip: "5.6.7.8".to_string(),
                src_port: 1234,
                dst_port: 80,
                proto: 6,
                timestamp: u64::from(i),
                payload_len: 0,
            };
            log.push(event);
        }
        assert_eq!(log.len(), 3);
        // Oldest events (0,1) should have been evicted; remaining: 2,3,4
        let snap = log.snapshot();
        assert_eq!(snap[0].rule_id, 2);
    }

    #[test]
    fn event_log_filter_by_rule() {
        let log = EventLog::new(100);
        for rule_id in [1u32, 2, 1, 3, 1] {
            log.push(AlertEvent {
                rule_id,
                action: RuleAction::Alert,
                msg: String::new(),
                src_ip: "1.1.1.1".to_string(),
                dst_ip: "2.2.2.2".to_string(),
                src_port: 0,
                dst_port: 0,
                proto: 6,
                timestamp: 0,
                payload_len: 0,
            });
        }
        assert_eq!(log.by_rule(1).len(), 3);
        assert_eq!(log.by_rule(2).len(), 1);
    }

    #[test]
    fn event_log_filter_by_src() {
        let log = EventLog::new(100);
        for (i, src) in ["1.1.1.1", "2.2.2.2", "1.1.1.1"].iter().enumerate() {
            log.push(AlertEvent {
                rule_id: 1,
                action: RuleAction::Alert,
                msg: String::new(),
                src_ip: src.to_string(),
                dst_ip: "3.3.3.3".to_string(),
                src_port: u16::try_from(i).unwrap_or(0),
                dst_port: 0,
                proto: 6,
                timestamp: 0,
                payload_len: 0,
            });
        }
        assert_eq!(log.by_src("1.1.1.1").len(), 2);
    }

    #[test]
    fn event_log_clear_and_empty() {
        let log = EventLog::new(10);
        log.push(AlertEvent {
            rule_id: 1,
            action: RuleAction::Alert,
            msg: String::new(),
            src_ip: "x".to_string(),
            dst_ip: "y".to_string(),
            src_port: 0,
            dst_port: 0,
            proto: 0,
            timestamp: 0,
            payload_len: 0,
        });
        assert!(!log.is_empty());
        log.clear();
        assert!(log.is_empty());
    }

    // ── DetectionPipeline ─────────────────────────────────────────────────

    #[test]
    fn detection_pipeline_process() {
        let pipeline = DetectionPipeline::new(100);
        let mut rule = Rule::new(
            7,
            RuleAction::Alert,
            Proto::Any,
            NetworkSpec::any(),
            NetworkSpec::any(),
            "pipe",
        );
        rule.conditions.push(Condition::Content(b"pipe".to_vec()));
        pipeline.add_rule(rule);

        let ctx = simple_ctx(b"test pipe data");
        let results = pipeline.process(&ctx, 1000);
        assert_eq!(results.len(), 1);

        let stats = pipeline.stats().get(7).unwrap();
        assert_eq!(stats.match_count, 1);

        let log = pipeline.log();
        assert_eq!(log.len(), 1);
        assert_eq!(log.snapshot()[0].rule_id, 7);
    }

    // ── PCRE stub ─────────────────────────────────────────────────────────

    #[test]
    fn pcre_pattern_parse_and_match() {
        let p = PcrePattern::parse("/hello/i").unwrap();
        assert!(p.flags().case_insensitive);
        assert!(p.matches(b"say HELLO world"));
        assert!(!p.matches(b"say goodbye"));
    }

    #[test]
    fn pcre_pattern_negate() {
        let p = PcrePattern::parse("/evil/!").unwrap();
        assert!(p.matches(b"innocent data"));
        assert!(!p.matches(b"evil payload"));
    }

    #[test]
    fn pcre_pattern_missing_delimiter() {
        assert!(PcrePattern::parse("no_slash").is_err());
    }

    // ── Flowbits ──────────────────────────────────────────────────────────

    #[test]
    fn flowbit_set_and_check() {
        let store = FlowbitStore::new();
        store.set("flow1", "http.request");
        assert!(store.is_set("flow1", "http.request"));
        assert!(!store.is_set("flow1", "ftp.login"));
        store.unset("flow1", "http.request");
        assert!(!store.is_set("flow1", "http.request"));
    }

    #[test]
    fn flowbit_toggle() {
        let store = FlowbitStore::new();
        store.toggle("flow", "bit");
        assert!(store.is_set("flow", "bit"));
        store.toggle("flow", "bit");
        assert!(!store.is_set("flow", "bit"));
    }

    #[test]
    fn flowbit_eval_isset_condition() {
        let store = FlowbitStore::new();
        let op_set = FlowbitOp::Set("auth.failed".to_string());
        let op_check = FlowbitOp::IsSet("auth.failed".to_string());
        let op_notset = FlowbitOp::IsNotSet("auth.failed".to_string());
        assert!(store.eval("flow", &op_set));
        assert!(store.eval("flow", &op_check));
        assert!(!store.eval("flow", &op_notset));
        assert_eq!(store.flow_count(), 1);
    }

    #[test]
    fn flowbit_op_display() {
        assert_eq!(FlowbitOp::Set("x".to_string()).to_string(), "set,x");
        assert_eq!(FlowbitOp::IsSet("y".to_string()).to_string(), "isset,y");
        assert_eq!(FlowbitOp::NoAlert.to_string(), "noalert");
    }

    // ── VarTable ──────────────────────────────────────────────────────────

    #[test]
    fn var_table_resolve_defaults() {
        let t = VarTable::with_defaults();
        let ip = t.resolve_ip("HOME_NET");
        assert!(ip.matches(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
        assert!(!ip.matches(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
        let port = t.resolve_port("HTTP_PORTS");
        assert!(port.matches(80));
        assert!(!port.matches(443));
    }

    #[test]
    fn var_table_custom_vars() {
        let mut t = VarTable::new();
        t.set_ip(
            "MY_NET",
            IpSpec::Cidr(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)), 8),
        );
        t.set_port("MY_PORT", PortSpec::Single(9000));
        assert!(
            t.resolve_ip("MY_NET")
                .matches(IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3)))
        );
        assert!(t.resolve_port("MY_PORT").matches(9000));
        assert!(!t.resolve_port("MY_PORT").matches(9001));
    }

    #[test]
    fn var_table_unknown_returns_any() {
        let t = VarTable::new();
        assert!(matches!(t.resolve_ip("UNKNOWN"), IpSpec::Any));
        assert!(matches!(t.resolve_port("UNKNOWN"), PortSpec::Any));
    }

    // ── nocase content search ─────────────────────────────────────────────

    #[test]
    fn find_bytes_nocase_basic() {
        let result = find_bytes_nocase(b"Hello World", b"hello");
        assert_eq!(result, Some(0));
        let result2 = find_bytes_nocase(b"Hello World", b"WORLD");
        assert_eq!(result2, Some(6));
        assert!(find_bytes_nocase(b"hello", b"xyz").is_none());
    }

    #[test]
    fn find_bytes_nocase_empty_needle() {
        assert_eq!(find_bytes_nocase(b"anything", b""), Some(0));
    }

    // ── FragBitsCheck display ─────────────────────────────────────────────

    #[test]
    fn frag_bits_display() {
        let fb = FragBitsCheck {
            more_frag: true,
            dont_frag: false,
            reserved: true,
        };
        let s = fb.to_string();
        assert!(s.contains('M'));
        assert!(s.contains('R'));
        assert!(!s.contains('D'));
    }

    // ── IpOptType display ─────────────────────────────────────────────────

    #[test]
    fn ip_opt_type_display() {
        assert_eq!(IpOptType::Rr.to_string(), "rr");
        assert_eq!(IpOptType::Lsrr.to_string(), "lsrr");
        assert_eq!(IpOptType::Any.to_string(), "any");
    }

    // ── DetectionFilterEngine ─────────────────────────────────────────────

    #[test]
    fn detection_filter_suppresses_below_count() {
        let engine = RuleEngine::new();
        engine.add_rule(Rule::new(
            1,
            RuleAction::Alert,
            Proto::Any,
            NetworkSpec::any(),
            NetworkSpec::any(),
            "dfe",
        ));
        let mut dfe = DetectionFilterEngine::new(engine);
        dfe.add_filter(DetectionFilter {
            rule_id: 1,
            track: ThresholdTrack::ByRule,
            count: 3,
            seconds: 60,
        });
        let ctx = simple_ctx(b"");
        assert!(dfe.evaluate(&ctx, 0).is_empty()); // 1
        assert!(dfe.evaluate(&ctx, 0).is_empty()); // 2
        assert!(!dfe.evaluate(&ctx, 0).is_empty()); // 3: fires
    }

    // ── SizeOp display ────────────────────────────────────────────────────

    #[test]
    fn size_op_display() {
        assert_eq!(SizeOp::Lt.to_string(), "<");
        assert_eq!(SizeOp::Gt.to_string(), ">");
        assert_eq!(SizeOp::Eq.to_string(), "=");
        assert_eq!(SizeOp::Ne.to_string(), "!=");
    }

    // ── AlertEvent display ────────────────────────────────────────────────

    #[test]
    fn alert_event_display_and_from_match() {
        let mr = MatchResult {
            matched: true,
            rule_id: 42,
            action: RuleAction::Alert,
            msg: "evt".to_string(),
        };
        let ctx = simple_ctx(b"test");
        let ev = AlertEvent::from_match(&mr, &ctx, 9999);
        assert_eq!(ev.rule_id, 42);
        assert_eq!(ev.timestamp, 9999);
        let s = ev.to_string();
        assert!(s.contains("42"));
        assert!(s.contains("evt"));
    }

    // ── IpSpec::Not ───────────────────────────────────────────────────────

    #[test]
    fn ipspec_not_cidr() {
        let spec = IpSpec::Not(Box::new(IpSpec::Cidr(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)),
            8,
        )));
        assert!(spec.matches(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
        assert!(!spec.matches(IpAddr::V4(Ipv4Addr::new(10, 5, 6, 7))));
    }

    // ── RuleError variants ────────────────────────────────────────────────

    #[test]
    fn rule_error_display() {
        let e = RuleError::ParseError {
            token: "tok".to_string(),
            msg: "bad".to_string(),
        };
        assert!(e.to_string().contains("tok"));
        let e2 = RuleError::InvalidId(5);
        assert!(e2.to_string().contains('5'));
        let e3 = RuleError::DuplicateId(99);
        assert!(e3.to_string().contains("99"));
        let e4 = RuleError::UnsupportedCondition("xyz".to_string());
        assert!(e4.to_string().contains("xyz"));
    }

    // ── DetectionPipeline rule_count ──────────────────────────────────────

    #[test]
    fn detection_pipeline_rule_count() {
        let p = DetectionPipeline::new(10);
        assert_eq!(p.rule_count(), 0);
        p.add_rule(Rule::new(
            1,
            RuleAction::Alert,
            Proto::Any,
            NetworkSpec::any(),
            NetworkSpec::any(),
            "a",
        ));
        p.add_rule(Rule::new(
            2,
            RuleAction::Alert,
            Proto::Any,
            NetworkSpec::any(),
            NetworkSpec::any(),
            "b",
        ));
        assert_eq!(p.rule_count(), 2);
    }
}
