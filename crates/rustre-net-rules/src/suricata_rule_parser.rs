//! Suricata/Snort network detection rule parser.
//!
//! Parses the full rule syntax including the header (action, protocol, source,
//! destination) and the options block (key:value pairs separated by `;`).
//! The result is a [`SuricataRule`] that can be inspected, serialised, and fed
//! into a rule engine.

use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use thiserror::Error;

// ── Error ─────────────────────────────────────────────────────────────────────

/// Errors returned by the Suricata rule parser.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum SuricataParseError {
    #[error("empty input")]
    Empty,
    #[error("missing options block (expected parentheses)")]
    MissingOptions,
    #[error("header has wrong token count: expected 7, got {0}")]
    BadHeaderTokenCount(usize),
    #[error("unknown action '{0}'")]
    UnknownAction(String),
    #[error("unknown protocol '{0}'")]
    UnknownProtocol(String),
    #[error("invalid IP specification '{0}': {1}")]
    InvalidIpSpec(String, String),
    #[error("invalid port specification '{0}': {1}")]
    InvalidPortSpec(String, String),
    #[error("missing required option '{0}'")]
    MissingRequiredOption(String),
    #[error("invalid option value for '{0}': {1}")]
    InvalidOptionValue(String, String),
}

// ── Rule action ───────────────────────────────────────────────────────────────

/// The action to take when a rule matches a packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RuleAction {
    /// Generate an alert.
    Alert,
    /// Pass the packet silently.
    Pass,
    /// Drop the packet (inline mode only).
    Drop,
    /// Reject the packet and send a RST/ICMP unreachable.
    Reject,
    /// Log the packet without alerting.
    Log,
    /// Rewrite the packet (Suricata stream re-injection).
    Rewrite,
}

impl RuleAction {
    /// Parse a lowercase action string.
    ///
    /// # Errors
    /// Returns `SuricataParseError::UnknownAction` if `s` is not a recognized action keyword.
    pub fn from_str_case(s: &str) -> Result<Self, SuricataParseError> {
        match s {
            "alert"   => Ok(Self::Alert),
            "pass"    => Ok(Self::Pass),
            "drop"    => Ok(Self::Drop),
            "reject"  => Ok(Self::Reject),
            "log"     => Ok(Self::Log),
            "rewrite" => Ok(Self::Rewrite),
            other => Err(SuricataParseError::UnknownAction(other.to_string())),
        }
    }
}

impl fmt::Display for RuleAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Alert   => "alert",
            Self::Pass    => "pass",
            Self::Drop    => "drop",
            Self::Reject  => "reject",
            Self::Log     => "log",
            Self::Rewrite => "rewrite",
        };
        f.write_str(s)
    }
}

// ── Protocol ──────────────────────────────────────────────────────────────────

/// Layer-3/4 protocol selector used in a rule header.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Protocol {
    Tcp,
    Udp,
    Icmp,
    Ip,
    Http,
    Tls,
    Dns,
    Smtp,
    Ftp,
    Ssh,
    Pkthdr,
    Any,
}

impl Protocol {
    /// Parse a case-insensitive protocol string.
    ///
    /// # Errors
    /// Returns `SuricataParseError::UnknownProtocol` if `s` is not a recognized protocol keyword.
    pub fn from_str_case(s: &str) -> Result<Self, SuricataParseError> {
        match s.to_ascii_lowercase().as_str() {
            "tcp"    => Ok(Self::Tcp),
            "udp"    => Ok(Self::Udp),
            "icmp"   => Ok(Self::Icmp),
            "ip"     => Ok(Self::Ip),
            "http"   => Ok(Self::Http),
            "tls" | "ssl" => Ok(Self::Tls),
            "dns"    => Ok(Self::Dns),
            "smtp"   => Ok(Self::Smtp),
            "ftp"    => Ok(Self::Ftp),
            "ssh"    => Ok(Self::Ssh),
            "pkthdr" => Ok(Self::Pkthdr),
            "any"    => Ok(Self::Any),
            other => Err(SuricataParseError::UnknownProtocol(other.to_string())),
        }
    }

    /// Returns `true` if the protocol operates above the transport layer.
    #[must_use]
    pub const fn is_application_layer(self) -> bool {
        matches!(self, Self::Http | Self::Tls | Self::Dns | Self::Smtp | Self::Ftp | Self::Ssh)
    }
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Tcp    => "tcp",
            Self::Udp    => "udp",
            Self::Icmp   => "icmp",
            Self::Ip     => "ip",
            Self::Http   => "http",
            Self::Tls    => "tls",
            Self::Dns    => "dns",
            Self::Smtp   => "smtp",
            Self::Ftp    => "ftp",
            Self::Ssh    => "ssh",
            Self::Pkthdr => "pkthdr",
            Self::Any    => "any",
        };
        f.write_str(s)
    }
}

// ── IP specification ──────────────────────────────────────────────────────────

/// A network address specification in a rule header.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum IpSpec {
    /// Match any address.
    Any,
    /// Named variable (e.g. `$HOME_NET`).
    Variable(String),
    /// A single host address.
    Single(IpAddr),
    /// A CIDR prefix.
    Cidr { network: IpAddr, prefix_len: u8 },
    /// A group of sub-specifications (`[spec1,spec2,...]`).
    Group(Vec<Self>),
    /// Negation of an inner specification.
    Not(Box<Self>),
}

impl IpSpec {
    /// Parse an IP specification string.
    ///
    /// # Errors
    /// Returns `SuricataParseError::InvalidIpSpec` when the string is not a valid IP/CIDR/group.
    ///
    /// # Panics
    /// Panics only if internal parsing invariants are violated; should not occur in practice.
    pub fn parse(s: &str) -> Result<Self, SuricataParseError> {
        let s = s.trim();
        if s == "any" {
            return Ok(Self::Any);
        }
        if let Some(rest) = s.strip_prefix('!') {
            let inner = Self::parse(rest)?;
            return Ok(Self::Not(Box::new(inner)));
        }
        if s.starts_with('$') {
            return Ok(Self::Variable(s.to_string()));
        }
        if s.starts_with('[') && s.ends_with(']') {
            let inner = &s[1..s.len() - 1];
            let parts = split_comma_respecting_brackets(inner);
            let specs: Result<Vec<Self>, _> = parts.iter().map(|p| Self::parse(p.trim())).collect();
            return Ok(Self::Group(specs?));
        }
        if s.contains('/') {
            let (addr_part, pfx) = s.split_once('/').unwrap();
            let addr = IpAddr::from_str(addr_part).map_err(|e| {
                SuricataParseError::InvalidIpSpec(s.to_string(), e.to_string())
            })?;
            let prefix_len: u8 = pfx.parse().map_err(|_| {
                SuricataParseError::InvalidIpSpec(s.to_string(), "invalid prefix length".to_string())
            })?;
            return Ok(Self::Cidr { network: addr, prefix_len });
        }
        let addr = IpAddr::from_str(s).map_err(|e| {
            SuricataParseError::InvalidIpSpec(s.to_string(), e.to_string())
        })?;
        Ok(Self::Single(addr))
    }

    /// Returns `true` if the given address matches this specification.
    #[must_use]
    pub fn matches(&self, addr: IpAddr) -> bool {
        match self {
            Self::Any | Self::Variable(_) => true, // unresolved → permissive
            Self::Single(a) => *a == addr,
            Self::Cidr { network, prefix_len } => cidr_contains(*network, *prefix_len, addr),
            Self::Group(specs) => specs.iter().any(|s| s.matches(addr)),
            Self::Not(inner) => !inner.matches(addr),
        }
    }
}

fn cidr_contains(network: IpAddr, prefix_len: u8, addr: IpAddr) -> bool {
    match (network, addr) {
        (IpAddr::V4(n), IpAddr::V4(a)) => {
            if prefix_len == 0 { return true; }
            if prefix_len > 32 { return false; }
            let mask = u32::MAX << (32 - prefix_len);
            (u32::from(n) & mask) == (u32::from(a) & mask)
        }
        (IpAddr::V6(n), IpAddr::V6(a)) => {
            if prefix_len == 0 { return true; }
            if prefix_len > 128 { return false; }
            let nm = u128::from(n);
            let am = u128::from(a);
            let mask = u128::MAX << (128 - prefix_len);
            (nm & mask) == (am & mask)
        }
        _ => false,
    }
}

// ── Port specification ────────────────────────────────────────────────────────

/// A port specification used in rule headers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PortSpec {
    Any,
    Variable(String),
    Single(u16),
    Range(u16, u16),
    List(Vec<Self>),
    Not(Box<Self>),
}

impl PortSpec {
    /// Parse a port specification string.
    ///
    /// # Errors
    /// Returns `SuricataParseError::InvalidPortSpec` when the string is not a valid port/range/list.
    ///
    /// # Panics
    /// Panics only if internal parsing invariants are violated; should not occur in practice.
    pub fn parse(s: &str) -> Result<Self, SuricataParseError> {
        let s = s.trim();
        if s == "any" {
            return Ok(Self::Any);
        }
        if let Some(rest) = s.strip_prefix('!') {
            let inner = Self::parse(rest)?;
            return Ok(Self::Not(Box::new(inner)));
        }
        if s.starts_with('$') {
            return Ok(Self::Variable(s.to_string()));
        }
        if s.starts_with('[') && s.ends_with(']') {
            let inner = &s[1..s.len() - 1];
            let parts = split_comma_respecting_brackets(inner);
            let specs: Result<Vec<Self>, _> = parts.iter().map(|p| Self::parse(p.trim())).collect();
            return Ok(Self::List(specs?));
        }
        if s.contains(':') {
            let (lo, hi) = s.split_once(':').unwrap();
            let lo_port: u16 = lo.trim().parse().map_err(|_| {
                SuricataParseError::InvalidPortSpec(s.to_string(), "invalid range start".to_string())
            })?;
            let hi_port: u16 = hi.trim().parse().map_err(|_| {
                SuricataParseError::InvalidPortSpec(s.to_string(), "invalid range end".to_string())
            })?;
            return Ok(Self::Range(lo_port, hi_port));
        }
        let port: u16 = s.parse().map_err(|_| {
            SuricataParseError::InvalidPortSpec(s.to_string(), "not a valid port number".to_string())
        })?;
        Ok(Self::Single(port))
    }

    /// Returns `true` if `port` matches this specification.
    #[must_use]
    pub fn matches(&self, port: u16) -> bool {
        match self {
            Self::Any | Self::Variable(_) => true,
            Self::Single(p) => *p == port,
            Self::Range(lo, hi) => port >= *lo && port <= *hi,
            Self::List(specs) => specs.iter().any(|s| s.matches(port)),
            Self::Not(inner) => !inner.matches(port),
        }
    }
}

// ── Rule option ───────────────────────────────────────────────────────────────

/// A single option from the Suricata rule options block.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RuleOption {
    /// `msg:"..."` — human-readable alert message.
    Msg(String),
    /// `sid:NNN` — signature identifier.
    Sid(u32),
    /// `rev:NNN` — revision number.
    Rev(u32),
    /// `gid:NNN` — group identifier.
    Gid(u32),
    /// `classtype:name` — classification type string.
    Classtype(String),
    /// `content:"..."` — byte content pattern.
    Content { pattern: Vec<u8>, nocase: bool, negated: bool },
    /// `pcre:"/regex/flags"` — Perl-compatible regular expression.
    Pcre(String),
    /// `offset:N` — byte offset for next content match.
    Offset(u32),
    /// `depth:N` — maximum depth for content match.
    Depth(u32),
    /// `within:N` — require next content within N bytes of last match.
    Within(u32),
    /// `distance:N` — require next content at least N bytes from last match.
    Distance(u32),
    /// `dsize:N` or `dsize:N<>M` — payload size constraint.
    Dsize { min: u32, max: u32 },
    /// `flow:keyword,...` — flow direction/state keywords.
    Flow(Vec<String>),
    /// `flags:SA` — TCP flags.
    Flags(String),
    /// `ttl:N` — IP TTL exact match.
    Ttl(u8),
    /// `threshold:type limit,track by_src,count N,seconds N`
    Threshold {
        threshold_type: String,
        track: String,
        count: u32,
        seconds: u32,
    },
    /// `metadata:key value,...` — arbitrary key-value metadata.
    Metadata(Vec<(String, String)>),
    /// `reference:type,value` — CVE/URL reference.
    Reference { ref_type: String, value: String },
    /// `noalert` — suppress alert generation.
    Noalert,
    /// Any other option stored as raw (key, value).
    Raw(String, String),
}

impl RuleOption {
    /// Return the option keyword name.
    #[must_use]
    pub const fn keyword(&self) -> &str {
        match self {
            Self::Msg(_)       => "msg",
            Self::Sid(_)       => "sid",
            Self::Rev(_)       => "rev",
            Self::Gid(_)       => "gid",
            Self::Classtype(_) => "classtype",
            Self::Content { .. } => "content",
            Self::Pcre(_)      => "pcre",
            Self::Offset(_)    => "offset",
            Self::Depth(_)     => "depth",
            Self::Within(_)    => "within",
            Self::Distance(_)  => "distance",
            Self::Dsize { .. } => "dsize",
            Self::Flow(_)      => "flow",
            Self::Flags(_)     => "flags",
            Self::Ttl(_)       => "ttl",
            Self::Threshold { .. } => "threshold",
            Self::Metadata(_)  => "metadata",
            Self::Reference { .. } => "reference",
            Self::Noalert      => "noalert",
            Self::Raw(k, _)    => k.as_str(),
        }
    }
}

// ── Suricata rule ─────────────────────────────────────────────────────────────

/// A fully parsed Suricata/Snort detection rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuricataRule {
    /// The action to take on match.
    pub action: RuleAction,
    /// Layer-3/4 or application-layer protocol.
    pub protocol: Protocol,
    /// Source IP specification.
    pub src_ip: IpSpec,
    /// Source port specification.
    pub src_port: PortSpec,
    /// Rule direction (`true` = bidirectional `<>`, `false` = `->` unidirectional).
    pub bidirectional: bool,
    /// Destination IP specification.
    pub dst_ip: IpSpec,
    /// Destination port specification.
    pub dst_port: PortSpec,
    /// Parsed rule options.
    pub options: Vec<RuleOption>,
}

impl SuricataRule {
    /// Return the signature ID, if present.
    #[must_use]
    pub fn sid(&self) -> Option<u32> {
        self.options.iter().find_map(|o| {
            if let RuleOption::Sid(n) = o { Some(*n) } else { None }
        })
    }

    /// Return the alert message, if present.
    #[must_use]
    pub fn msg(&self) -> Option<&str> {
        self.options.iter().find_map(|o| {
            if let RuleOption::Msg(s) = o { Some(s.as_str()) } else { None }
        })
    }

    /// Return all content patterns in order.
    #[must_use]
    pub fn content_patterns(&self) -> Vec<&[u8]> {
        self.options.iter().filter_map(|o| {
            if let RuleOption::Content { pattern, .. } = o { Some(pattern.as_slice()) } else { None }
        }).collect()
    }

    /// Return `true` if the rule has a PCRE option.
    #[must_use]
    pub fn has_pcre(&self) -> bool {
        self.options.iter().any(|o| matches!(o, RuleOption::Pcre(_)))
    }

    /// Return `true` if this rule would match a packet from `src` to `dst` on the
    /// given ports.
    #[must_use]
    pub fn header_matches(
        &self,
        src_ip: IpAddr,
        src_port: u16,
        dst_ip: IpAddr,
        dst_port: u16,
    ) -> bool {
        let fwd = self.src_ip.matches(src_ip)
            && self.src_port.matches(src_port)
            && self.dst_ip.matches(dst_ip)
            && self.dst_port.matches(dst_port);
        if fwd {
            return true;
        }
        if self.bidirectional {
            return self.src_ip.matches(dst_ip)
                && self.src_port.matches(dst_port)
                && self.dst_ip.matches(src_ip)
                && self.dst_port.matches(src_port);
        }
        false
    }
}

impl fmt::Display for SuricataRule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let dir = if self.bidirectional { "<>" } else { "->" };
        write!(
            f,
            "{} {} ... {} ... (sid:{:?}; msg:{:?})",
            self.action,
            self.protocol,
            dir,
            self.sid(),
            self.msg(),
        )
    }
}

// ── Parser ────────────────────────────────────────────────────────────────────

/// Stateless parser for Suricata/Snort rule strings.
pub struct SuricataParser;

impl SuricataParser {
    /// Parse a single rule string into a [`SuricataRule`].
    ///
    /// # Errors
    ///
    /// Returns [`SuricataParseError`] when the input does not conform to the
    /// Suricata rule syntax.
    pub fn parse(input: &str) -> Result<SuricataRule, SuricataParseError> {
        let input = input.trim();
        if input.is_empty() || input.starts_with('#') {
            return Err(SuricataParseError::Empty);
        }

        // Split header from options block.
        let paren_open = input.find('(').ok_or(SuricataParseError::MissingOptions)?;
        let paren_close = input.rfind(')').ok_or(SuricataParseError::MissingOptions)?;

        let header = input[..paren_open].trim();
        let options_str = &input[paren_open + 1..paren_close];

        // Parse header tokens.
        let tokens: Vec<&str> = header.split_whitespace().collect();
        if tokens.len() < 7 {
            return Err(SuricataParseError::BadHeaderTokenCount(tokens.len()));
        }

        let action   = RuleAction::from_str_case(tokens[0])?;
        let protocol = Protocol::from_str_case(tokens[1])?;
        let src_ip   = IpSpec::parse(tokens[2])?;
        let src_port = PortSpec::parse(tokens[3])?;
        let bidirectional = tokens[4] == "<>";
        let dst_ip   = IpSpec::parse(tokens[5])?;
        let dst_port = PortSpec::parse(tokens[6])?;

        // Parse options.
        let options = Self::parse_options(options_str)?;

        Ok(SuricataRule {
            action,
            protocol,
            src_ip,
            src_port,
            bidirectional,
            dst_ip,
            dst_port,
            options,
        })
    }

    /// Parse multiple rules from a newline-separated string, returning only
    /// successfully parsed rules and ignoring blank lines and comments.
    #[must_use]
    pub fn parse_many(input: &str) -> Vec<SuricataRule> {
        input
            .lines()
            .filter(|l| {
                let t = l.trim();
                !t.is_empty() && !t.starts_with('#')
            })
            .filter_map(|l| Self::parse(l).ok())
            .collect()
    }

    /// Parse multiple rules and return both successes and errors.
    pub fn parse_many_with_errors(input: &str) -> Vec<Result<SuricataRule, SuricataParseError>> {
        input
            .lines()
            .filter(|l| {
                let t = l.trim();
                !t.is_empty() && !t.starts_with('#')
            })
            .map(Self::parse)
            .collect()
    }

    // ── Options parser ────────────────────────────────────────────────────────

    fn parse_options(options_str: &str) -> Result<Vec<RuleOption>, SuricataParseError> {
        let raw_parts = split_options_str(options_str);
        let mut opts = Vec::new();
        let mut idx = 0;

        while idx < raw_parts.len() {
            let part = raw_parts[idx].trim();
            idx += 1;

            if part.is_empty() {
                continue;
            }

            // Option key and optional value separated by `:`.
            let (key, val) = part.find(':').map_or((part, ""), |colon_pos| (&part[..colon_pos], part[colon_pos + 1..].trim()));

            let opt = match key.trim() {
                "msg"       => RuleOption::Msg(strip_quotes(val).to_string()),
                "sid"       => {
                    let n: u32 = val.trim().parse().map_err(|_| {
                        SuricataParseError::InvalidOptionValue("sid".to_string(), val.to_string())
                    })?;
                    RuleOption::Sid(n)
                }
                "rev"       => {
                    let n: u32 = val.trim().parse().map_err(|_| {
                        SuricataParseError::InvalidOptionValue("rev".to_string(), val.to_string())
                    })?;
                    RuleOption::Rev(n)
                }
                "gid"       => {
                    let n: u32 = val.trim().parse().map_err(|_| {
                        SuricataParseError::InvalidOptionValue("gid".to_string(), val.to_string())
                    })?;
                    RuleOption::Gid(n)
                }
                "classtype" => RuleOption::Classtype(val.trim().to_string()),
                "content"   => {
                    let (pattern, negated) = parse_content_pattern(val);
                    RuleOption::Content { pattern, nocase: false, negated }
                }
                "nocase"    => {
                    // Retroactively mark the previous content as nocase.
                    if let Some(RuleOption::Content { nocase, .. }) = opts.last_mut() {
                        *nocase = true;
                    }
                    continue;
                }
                "pcre"      => RuleOption::Pcre(strip_quotes(val).to_string()),
                "offset"    => {
                    let n: u32 = val.trim().parse().map_err(|_| {
                        SuricataParseError::InvalidOptionValue("offset".to_string(), val.to_string())
                    })?;
                    RuleOption::Offset(n)
                }
                "depth"     => {
                    let n: u32 = val.trim().parse().map_err(|_| {
                        SuricataParseError::InvalidOptionValue("depth".to_string(), val.to_string())
                    })?;
                    RuleOption::Depth(n)
                }
                "within"    => {
                    let n: u32 = val.trim().parse().map_err(|_| {
                        SuricataParseError::InvalidOptionValue("within".to_string(), val.to_string())
                    })?;
                    RuleOption::Within(n)
                }
                "distance"  => {
                    let n: u32 = val.trim().parse().map_err(|_| {
                        SuricataParseError::InvalidOptionValue("distance".to_string(), val.to_string())
                    })?;
                    RuleOption::Distance(n)
                }
                "dsize"     => parse_dsize_option(val)?,
                "flow"      => {
                    let keywords: Vec<String> = val
                        .split(',')
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .collect();
                    RuleOption::Flow(keywords)
                }
                "flags"     => RuleOption::Flags(val.trim().to_string()),
                "ttl"       => {
                    let n: u8 = val.trim().parse().map_err(|_| {
                        SuricataParseError::InvalidOptionValue("ttl".to_string(), val.to_string())
                    })?;
                    RuleOption::Ttl(n)
                }
                "noalert"   => RuleOption::Noalert,
                "metadata"  => {
                    let pairs = val
                        .split(',')
                        .filter_map(|kv| {
                            let mut it = kv.splitn(2, ' ');
                            let k = it.next()?.trim().to_string();
                            let v = it.next().unwrap_or("").trim().to_string();
                            Some((k, v))
                        })
                        .collect();
                    RuleOption::Metadata(pairs)
                }
                "reference" => {
                    let (rtype, rval) = val.split_once(',').unwrap_or((val, ""));
                    RuleOption::Reference {
                        ref_type: rtype.trim().to_string(),
                        value: rval.trim().to_string(),
                    }
                }
                "threshold" => parse_threshold_option(val),
                other       => RuleOption::Raw(other.to_string(), val.to_string()),
            };
            opts.push(opt);
        }
        Ok(opts)
    }
}

// ── Helper functions ──────────────────────────────────────────────────────────

fn strip_quotes(s: &str) -> &str {
    let s = s.trim();
    if s.len() >= 2 && s.starts_with('"') && s.ends_with('"') {
        &s[1..s.len() - 1]
    } else {
        s
    }
}

fn parse_content_pattern(val: &str) -> (Vec<u8>, bool) {
    let val = val.trim();
    let negated = val.starts_with('!');
    let val = if negated { val[1..].trim() } else { val };

    if val.starts_with('"') && val.ends_with('"') && val.len() >= 2 {
        let inner = &val[1..val.len() - 1];
        // Handle mixed text and hex escapes: |XX XX|
        return (parse_mixed_content(inner), negated);
    }
    (val.as_bytes().to_vec(), negated)
}

fn parse_mixed_content(s: &str) -> Vec<u8> {
    let mut result = Vec::new();
    let mut in_hex = false;
    let mut hex_buf = String::new();

    for ch in s.chars() {
        if in_hex {
            if ch == '|' {
                // Decode accumulated hex bytes.
                for h in hex_buf.split_whitespace() {
                    if let Ok(b) = u8::from_str_radix(h, 16) {
                        result.push(b);
                    }
                }
                hex_buf.clear();
                in_hex = false;
            } else {
                hex_buf.push(ch);
            }
        } else if ch == '|' {
            in_hex = true;
        } else {
            // Handle common escape sequences.
            result.push(ch as u8);
        }
    }
    result
}

fn parse_dsize_option(val: &str) -> Result<RuleOption, SuricataParseError> {
    let val = val.trim();
    if val.contains("<>") {
        let (lo, hi) = val.split_once("<>").unwrap();
        let min: u32 = lo.trim().parse().unwrap_or(0);
        let max: u32 = hi.trim().parse().map_err(|_| {
            SuricataParseError::InvalidOptionValue("dsize".to_string(), val.to_string())
        })?;
        return Ok(RuleOption::Dsize { min, max });
    }
    if let Some(stripped) = val.strip_prefix('>') {
        let min: u32 = stripped.trim().parse().map_err(|_| {
            SuricataParseError::InvalidOptionValue("dsize".to_string(), val.to_string())
        })?;
        return Ok(RuleOption::Dsize { min, max: u32::MAX });
    }
    if let Some(stripped) = val.strip_prefix('<') {
        let max: u32 = stripped.trim().parse().map_err(|_| {
            SuricataParseError::InvalidOptionValue("dsize".to_string(), val.to_string())
        })?;
        return Ok(RuleOption::Dsize { min: 0, max });
    }
    let exact: u32 = val.parse().map_err(|_| {
        SuricataParseError::InvalidOptionValue("dsize".to_string(), val.to_string())
    })?;
    Ok(RuleOption::Dsize { min: exact, max: exact })
}

fn parse_threshold_option(val: &str) -> RuleOption {
    let mut threshold_type = String::new();
    let mut track = String::new();
    let mut count = 0u32;
    let mut seconds = 0u32;

    for kv in val.split(',') {
        let kv = kv.trim();
        if let Some(v) = kv.strip_prefix("type ") {
            threshold_type = v.trim().to_string();
        } else if let Some(v) = kv.strip_prefix("track ") {
            track = v.trim().to_string();
        } else if let Some(v) = kv.strip_prefix("count ") {
            count = v.trim().parse().unwrap_or(0);
        } else if let Some(v) = kv.strip_prefix("seconds ") {
            seconds = v.trim().parse().unwrap_or(0);
        }
    }
    RuleOption::Threshold { threshold_type, track, count, seconds }
}

/// Split a comma-separated string while respecting nested brackets.
fn split_comma_respecting_brackets(s: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut depth = 0i32;
    let mut current = String::new();
    for ch in s.chars() {
        match ch {
            '[' | '(' => { depth += 1; current.push(ch); }
            ']' | ')' => { depth -= 1; current.push(ch); }
            ',' if depth == 0 => {
                parts.push(current.trim().to_string());
                current.clear();
            }
            _ => { current.push(ch); }
        }
    }
    if !current.trim().is_empty() {
        parts.push(current.trim().to_string());
    }
    parts
}

/// Split the options block into individual option strings, honouring quoted
/// values (which may contain semicolons).
fn split_options_str(options: &str) -> Vec<String> {
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
            let trimmed = current.trim().to_string();
            if !trimmed.is_empty() {
                parts.push(trimmed);
            }
            current.clear();
        } else {
            current.push(ch);
        }
    }
    let trimmed = current.trim().to_string();
    if !trimmed.is_empty() {
        parts.push(trimmed);
    }
    parts
}

// ── RuleStore ─────────────────────────────────────────────────────────────────

/// An in-memory store for parsed Suricata rules indexed by SID.
#[derive(Debug, Default)]
pub struct SuricataRuleStore {
    rules: Vec<SuricataRule>,
}

impl SuricataRuleStore {
    /// Create an empty store.
    #[must_use]
    pub const fn new() -> Self {
        Self { rules: Vec::new() }
    }

    /// Add a rule.
    pub fn add(&mut self, rule: SuricataRule) {
        self.rules.push(rule);
    }

    /// Parse and load all rules from a multi-line string.
    pub fn load_str(&mut self, input: &str) {
        for rule in SuricataParser::parse_many(input) {
            self.rules.push(rule);
        }
    }

    /// Look up a rule by SID.
    #[must_use]
    pub fn by_sid(&self, sid: u32) -> Option<&SuricataRule> {
        self.rules.iter().find(|r| r.sid() == Some(sid))
    }

    /// Find all rules whose protocol matches.
    #[must_use]
    pub fn by_protocol(&self, proto: Protocol) -> Vec<&SuricataRule> {
        self.rules.iter().filter(|r| r.protocol == proto).collect()
    }

    /// Return all rules.
    #[must_use]
    pub fn all(&self) -> &[SuricataRule] {
        &self.rules
    }

    /// Number of rules in the store.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.rules.len()
    }

    /// Returns `true` if the store is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// Return all content patterns across all rules (deduplicated).
    #[must_use]
    pub fn all_content_patterns(&self) -> Vec<Vec<u8>> {
        let mut seen = std::collections::HashSet::new();
        let mut result = Vec::new();
        for rule in &self.rules {
            for p in rule.content_patterns() {
                if seen.insert(p.to_vec()) {
                    result.push(p.to_vec());
                }
            }
        }
        result
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_RULE: &str = r#"alert tcp $HOME_NET any -> $EXTERNAL_NET 80 (msg:"Test HTTP"; content:"GET"; sid:1001; rev:1;)"#;

    #[test]
    fn test_parse_basic_rule() {
        let rule = SuricataParser::parse(SAMPLE_RULE).unwrap();
        assert_eq!(rule.action, RuleAction::Alert);
        assert_eq!(rule.protocol, Protocol::Tcp);
        assert_eq!(rule.sid(), Some(1001));
        assert_eq!(rule.msg(), Some("Test HTTP"));
    }

    #[test]
    fn test_content_pattern() {
        let rule = SuricataParser::parse(SAMPLE_RULE).unwrap();
        let patterns = rule.content_patterns();
        assert_eq!(patterns.len(), 1);
        assert_eq!(patterns[0], b"GET");
    }

    #[test]
    fn test_parse_drop_rule() {
        let r = r#"drop tcp any any -> any 443 (msg:"Drop TLS"; sid:2000; rev:1;)"#;
        let rule = SuricataParser::parse(r).unwrap();
        assert_eq!(rule.action, RuleAction::Drop);
        assert_eq!(rule.protocol, Protocol::Tcp);
    }

    #[test]
    fn test_bidirectional_rule() {
        let r = r#"alert tcp any any <> any 22 (msg:"SSH"; sid:3000; rev:1;)"#;
        let rule = SuricataParser::parse(r).unwrap();
        assert!(rule.bidirectional);
    }

    #[test]
    fn test_unidirectional_rule() {
        let r = r#"alert tcp any any -> any 22 (msg:"SSH"; sid:3001; rev:1;)"#;
        let rule = SuricataParser::parse(r).unwrap();
        assert!(!rule.bidirectional);
    }

    #[test]
    fn test_unknown_action_error() {
        let r = r#"block tcp any any -> any 80 (msg:"X"; sid:1;)"#;
        assert!(matches!(SuricataParser::parse(r), Err(SuricataParseError::UnknownAction(_))));
    }

    #[test]
    fn test_empty_input_error() {
        assert!(matches!(SuricataParser::parse(""), Err(SuricataParseError::Empty)));
    }

    #[test]
    fn test_comment_error() {
        assert!(matches!(SuricataParser::parse("# comment"), Err(SuricataParseError::Empty)));
    }

    #[test]
    fn test_dsize_range() {
        let r = r#"alert tcp any any -> any 80 (msg:"X"; dsize:100<>200; sid:5000; rev:1;)"#;
        let rule = SuricataParser::parse(r).unwrap();
        let dsize = rule.options.iter().find_map(|o| {
            if let RuleOption::Dsize { min, max } = o { Some((*min, *max)) } else { None }
        });
        assert_eq!(dsize, Some((100, 200)));
    }

    #[test]
    fn test_flow_option() {
        let r = r#"alert tcp any any -> any 80 (msg:"X"; flow:established,to_server; sid:6000; rev:1;)"#;
        let rule = SuricataParser::parse(r).unwrap();
        let flow = rule.options.iter().find_map(|o| {
            if let RuleOption::Flow(kws) = o { Some(kws.clone()) } else { None }
        });
        assert!(flow.unwrap().contains(&"established".to_string()));
    }

    #[test]
    fn test_parse_many() {
        let input = "# comment\nalert tcp any any -> any 80 (msg:\"A\"; sid:1;)\nalert udp any any -> any 53 (msg:\"B\"; sid:2;)\n";
        let rules = SuricataParser::parse_many(input);
        assert_eq!(rules.len(), 2);
    }

    #[test]
    fn test_ip_spec_cidr() {
        let spec = IpSpec::parse("192.168.1.0/24").unwrap();
        assert!(spec.matches("192.168.1.50".parse().unwrap()));
        assert!(!spec.matches("192.168.2.1".parse().unwrap()));
    }

    #[test]
    fn test_port_spec_range() {
        let spec = PortSpec::parse("1024:65535").unwrap();
        assert!(spec.matches(8080));
        assert!(!spec.matches(80));
    }

    #[test]
    fn test_store_by_sid() {
        let mut store = SuricataRuleStore::new();
        store.load_str(r#"alert tcp any any -> any 80 (msg:"A"; sid:42; rev:1;)"#);
        assert!(store.by_sid(42).is_some());
        assert!(store.by_sid(99).is_none());
    }

    #[test]
    fn test_store_by_protocol() {
        let mut store = SuricataRuleStore::new();
        store.load_str("alert tcp any any -> any 80 (msg:\"A\"; sid:1;)\nalert udp any any -> any 53 (msg:\"B\"; sid:2;)\n");
        assert_eq!(store.by_protocol(Protocol::Tcp).len(), 1);
        assert_eq!(store.by_protocol(Protocol::Udp).len(), 1);
    }

    #[test]
    fn test_header_matches() {
        let rule = SuricataParser::parse(SAMPLE_RULE).unwrap();
        let src: IpAddr = "192.168.1.1".parse().unwrap();
        let dst: IpAddr = "8.8.8.8".parse().unwrap();
        // Variable specs match anything.
        assert!(rule.header_matches(src, 54321, dst, 80));
    }

    #[test]
    fn test_metadata_option() {
        let r = r#"alert tcp any any -> any 80 (msg:"X"; metadata:created 2023-01-01, affected_product WebServer; sid:99; rev:1;)"#;
        let rule = SuricataParser::parse(r).unwrap();
        let has_meta = rule.options.iter().any(|o| matches!(o, RuleOption::Metadata(_)));
        assert!(has_meta);
    }
}
