//! Suricata rule parser and generator.
//!
//! Parses the Suricata rule format (action proto `src_ip` `src_port` direction
//! `dst_ip` `dst_port` (options;)) and produces `SuricataRule` structs that can
//! be round-tripped back to text.

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use thiserror::Error;

// ─── Error ────────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum SuricataParseError {
    #[error("unexpected end of input")]
    UnexpectedEof,
    #[error("unknown action: {0}")]
    UnknownAction(String),
    #[error("unknown protocol: {0}")]
    UnknownProto(String),
    #[error("invalid direction: {0}")]
    InvalidDirection(String),
    #[error("malformed option: {0}")]
    MalformedOption(String),
    #[error("missing options block")]
    MissingOptions,
    #[error("invalid sid: {0}")]
    InvalidSid(String),
    #[error("duplicate option key: {0}")]
    DuplicateKey(String),
}

pub type ParseResult<T> = Result<T, SuricataParseError>;

// ─── Action ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SuricataAction {
    Alert,
    Pass,
    Drop,
    Reject,
    RejectSrc,
    RejectDst,
    RejectBoth,
}

impl SuricataAction {
    fn parse(s: &str) -> ParseResult<Self> {
        match s {
            "alert" => Ok(Self::Alert),
            "pass" => Ok(Self::Pass),
            "drop" => Ok(Self::Drop),
            "reject" => Ok(Self::Reject),
            "rejectsrc" => Ok(Self::RejectSrc),
            "rejectdst" => Ok(Self::RejectDst),
            "rejectboth" => Ok(Self::RejectBoth),
            other => Err(SuricataParseError::UnknownAction(other.into())),
        }
    }
}

impl fmt::Display for SuricataAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Alert => write!(f, "alert"),
            Self::Pass => write!(f, "pass"),
            Self::Drop => write!(f, "drop"),
            Self::Reject => write!(f, "reject"),
            Self::RejectSrc => write!(f, "rejectsrc"),
            Self::RejectDst => write!(f, "rejectdst"),
            Self::RejectBoth => write!(f, "rejectboth"),
        }
    }
}

// ─── Protocol ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SuricataProto {
    Tcp,
    Udp,
    Icmp,
    Ip,
    Http,
    Ftp,
    Tls,
    Smb,
    Dns,
    Dcerpc,
    Smtp,
    Imap,
    Ssh,
    Pkthdr,
    Custom(String),
}

impl SuricataProto {
    fn parse(s: &str) -> Self {
        match s {
            "tcp" => Self::Tcp,
            "udp" => Self::Udp,
            "icmp" => Self::Icmp,
            "ip" => Self::Ip,
            "http" => Self::Http,
            "ftp" => Self::Ftp,
            "tls" | "ssl" => Self::Tls,
            "smb" => Self::Smb,
            "dns" => Self::Dns,
            "dcerpc" => Self::Dcerpc,
            "smtp" => Self::Smtp,
            "imap" => Self::Imap,
            "ssh" => Self::Ssh,
            "pkthdr" => Self::Pkthdr,
            other => Self::Custom(other.to_string()),
        }
    }
}

impl fmt::Display for SuricataProto {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tcp => write!(f, "tcp"),
            Self::Udp => write!(f, "udp"),
            Self::Icmp => write!(f, "icmp"),
            Self::Ip => write!(f, "ip"),
            Self::Http => write!(f, "http"),
            Self::Ftp => write!(f, "ftp"),
            Self::Tls => write!(f, "tls"),
            Self::Smb => write!(f, "smb"),
            Self::Dns => write!(f, "dns"),
            Self::Dcerpc => write!(f, "dcerpc"),
            Self::Smtp => write!(f, "smtp"),
            Self::Imap => write!(f, "imap"),
            Self::Ssh => write!(f, "ssh"),
            Self::Pkthdr => write!(f, "pkthdr"),
            Self::Custom(s) => write!(f, "{s}"),
        }
    }
}

// ─── Address / Port ──────────────────────────────────────────────────────────

/// Represents a Suricata address specification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AddrSpec {
    Any,
    Negated(Box<Self>),
    Ip(String),
    Cidr(String),
    Group(Vec<Self>),
    Variable(String),
}

impl AddrSpec {
    fn parse(s: &str) -> Self {
        let s = s.trim();
        if s == "any" {
            return Self::Any;
        }
        if let Some(inner) = s.strip_prefix('!') {
            return Self::Negated(Box::new(Self::parse(inner)));
        }
        if let Some(inner) = s.strip_prefix('[').and_then(|r| r.strip_suffix(']')) {
            let parts = split_group(inner);
            return Self::Group(parts.into_iter().map(Self::parse).collect());
        }
        if let Some(rest) = s.strip_prefix('$') {
            return Self::Variable(rest.to_string());
        }
        if s.contains('/') {
            return Self::Cidr(s.to_string());
        }
        Self::Ip(s.to_string())
    }
}

impl fmt::Display for AddrSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Any => write!(f, "any"),
            Self::Negated(inner) => write!(f, "!{inner}"),
            Self::Ip(ip) => write!(f, "{ip}"),
            Self::Cidr(cidr) => write!(f, "{cidr}"),
            Self::Group(parts) => {
                write!(f, "[")?;
                for (i, p) in parts.iter().enumerate() {
                    if i > 0 { write!(f, ",")?; }
                    write!(f, "{p}")?;
                }
                write!(f, "]")
            }
            Self::Variable(v) => write!(f, "${v}"),
        }
    }
}

/// Represents a Suricata port specification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PortSpec {
    Any,
    Negated(Box<Self>),
    Single(u16),
    Range(u16, u16),
    Group(Vec<Self>),
    Variable(String),
}

impl PortSpec {
    fn parse(s: &str) -> Self {
        let s = s.trim();
        if s == "any" {
            return Self::Any;
        }
        if let Some(inner) = s.strip_prefix('!') {
            return Self::Negated(Box::new(Self::parse(inner)));
        }
        if let Some(inner) = s.strip_prefix('[').and_then(|r| r.strip_suffix(']')) {
            let parts = split_group(inner);
            return Self::Group(parts.into_iter().map(Self::parse).collect());
        }
        if let Some(rest) = s.strip_prefix('$') {
            return Self::Variable(rest.to_string());
        }
        if let Some(pos) = s.find(':') {
            let lo: u16 = s[..pos].parse().unwrap_or(0);
            let hi: u16 = s[pos + 1..].parse().unwrap_or(65535);
            return Self::Range(lo, hi);
        }
        if let Ok(p) = s.parse::<u16>() {
            return Self::Single(p);
        }
        Self::Variable(s.to_string())
    }
}

impl fmt::Display for PortSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Any => write!(f, "any"),
            Self::Negated(inner) => write!(f, "!{inner}"),
            Self::Single(p) => write!(f, "{p}"),
            Self::Range(lo, hi) => write!(f, "{lo}:{hi}"),
            Self::Group(parts) => {
                write!(f, "[")?;
                for (i, p) in parts.iter().enumerate() {
                    if i > 0 { write!(f, ",")?; }
                    write!(f, "{p}")?;
                }
                write!(f, "]")
            }
            Self::Variable(v) => write!(f, "${v}"),
        }
    }
}

// ─── Direction ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Direction {
    Uni,     // ->
    Bi,      // <>
}

impl fmt::Display for Direction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Uni => write!(f, "->"),
            Self::Bi => write!(f, "<>"),
        }
    }
}

// ─── Options ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleOption {
    pub keyword: String,
    pub value: Option<String>,
}

impl RuleOption {
    pub fn new(keyword: impl Into<String>, value: Option<impl Into<String>>) -> Self {
        Self {
            keyword: keyword.into(),
            value: value.map(Into::into),
        }
    }

    pub fn flag(keyword: impl Into<String>) -> Self {
        Self { keyword: keyword.into(), value: None }
    }
}

impl fmt::Display for RuleOption {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(v) = &self.value {
            write!(f, "{}:{}", self.keyword, v)
        } else {
            write!(f, "{}", self.keyword)
        }
    }
}

// ─── SuricataRule ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuricataRule {
    pub action: SuricataAction,
    pub proto: SuricataProto,
    pub src_addr: AddrSpec,
    pub src_port: PortSpec,
    pub direction: Direction,
    pub dst_addr: AddrSpec,
    pub dst_port: PortSpec,
    pub options: Vec<RuleOption>,
    /// Whether the rule is disabled (prefixed with `#`).
    pub disabled: bool,
    pub raw_line: Option<String>,
}

impl SuricataRule {
    /// Return the `sid` option value if present.
    #[must_use]
    pub fn sid(&self) -> Option<u64> {
        self.options
            .iter()
            .find(|o| o.keyword == "sid")
            .and_then(|o| o.value.as_ref())
            .and_then(|v| v.parse().ok())
    }

    /// Return the `msg` option value if present.
    #[must_use]
    pub fn msg(&self) -> Option<&str> {
        self.options
            .iter()
            .find(|o| o.keyword == "msg")
            .and_then(|o| o.value.as_deref())
            .map(|v| v.trim_matches('"'))
    }

    /// Return all `content` option values.
    #[must_use]
    pub fn content_patterns(&self) -> Vec<&str> {
        self.options
            .iter()
            .filter(|o| o.keyword == "content")
            .filter_map(|o| o.value.as_deref())
            .map(|v| v.trim_matches('"'))
            .collect()
    }

    /// Return the `classtype` if present.
    #[must_use]
    pub fn classtype(&self) -> Option<&str> {
        self.options
            .iter()
            .find(|o| o.keyword == "classtype")
            .and_then(|o| o.value.as_deref())
    }

    /// Return the `rev` value.
    #[must_use]
    pub fn rev(&self) -> Option<u32> {
        self.options
            .iter()
            .find(|o| o.keyword == "rev")
            .and_then(|o| o.value.as_ref())
            .and_then(|v| v.parse().ok())
    }
}

impl fmt::Display for SuricataRule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.disabled {
            write!(f, "# ")?;
        }
        write!(
            f,
            "{} {} {} {} {} {} {} (",
            self.action,
            self.proto,
            self.src_addr,
            self.src_port,
            self.direction,
            self.dst_addr,
            self.dst_port
        )?;
        for (i, opt) in self.options.iter().enumerate() {
            if i > 0 {
                write!(f, " ")?;
            }
            write!(f, "{opt};")?;
        }
        write!(f, ")")
    }
}

// ─── Parser ──────────────────────────────────────────────────────────────────

pub struct SuricataParser;

impl SuricataParser {
    /// Parse a single Suricata rule line.
    ///
    /// # Errors
    /// Returns `SuricataParseError` when the line is empty, the action/proto/direction
    /// is unknown, or the options block is missing or malformed.
    pub fn parse_rule(line: &str) -> ParseResult<SuricataRule> {
        let raw_line = line.to_string();
        let line = line.trim();
        let (line, disabled) = line.strip_prefix('#')
            .map_or((line, false), |rest| (rest.trim(), true));

        if line.is_empty() {
            return Err(SuricataParseError::UnexpectedEof);
        }

        let mut tokens = Tokenizer::new(line);

        let action_tok = tokens.next_word().ok_or(SuricataParseError::UnexpectedEof)?;
        let action = SuricataAction::parse(action_tok)?;

        let proto_tok = tokens.next_word().ok_or(SuricataParseError::UnexpectedEof)?;
        let proto = SuricataProto::parse(proto_tok);

        let src_addr_tok = tokens.next_addr_or_port().ok_or(SuricataParseError::UnexpectedEof)?;
        let src_addr = AddrSpec::parse(src_addr_tok);

        let src_port_tok = tokens.next_addr_or_port().ok_or(SuricataParseError::UnexpectedEof)?;
        let src_port = PortSpec::parse(src_port_tok);

        let dir_tok = tokens.next_word().ok_or(SuricataParseError::UnexpectedEof)?;
        let direction = match dir_tok {
            "->" => Direction::Uni,
            "<>" => Direction::Bi,
            other => return Err(SuricataParseError::InvalidDirection(other.into())),
        };

        let dst_addr_tok = tokens.next_addr_or_port().ok_or(SuricataParseError::UnexpectedEof)?;
        let dst_addr = AddrSpec::parse(dst_addr_tok);

        let dst_port_tok = tokens.next_addr_or_port().ok_or(SuricataParseError::UnexpectedEof)?;
        let dst_port = PortSpec::parse(dst_port_tok);

        let options = tokens.parse_options()?;

        Ok(SuricataRule {
            action,
            proto,
            src_addr,
            src_port,
            direction,
            dst_addr,
            dst_port,
            options,
            disabled,
            raw_line: Some(raw_line),
        })
    }

    /// Parse a Suricata rules file, skipping empty lines and pure comments.
    #[must_use]
    pub fn parse_file(content: &str) -> Vec<ParseResult<SuricataRule>> {
        content
            .lines()
            .filter(|l| {
                let trimmed = l.trim();
                if trimmed.is_empty() {
                    return false;
                }
                trimmed.strip_prefix('#').is_none_or(|rest| rest.trim().starts_with(['a', 'p', 'd', 'r']))
            })
            .map(Self::parse_rule)
            .collect()
    }

    /// Parse only valid rules, dropping errors.
    #[must_use]
    pub fn parse_file_lenient(content: &str) -> Vec<SuricataRule> {
        Self::parse_file(content)
            .into_iter()
            .filter_map(Result::ok)
            .collect()
    }
}

// ─── Generator ───────────────────────────────────────────────────────────────

pub struct SuricataGenerator;

impl SuricataGenerator {
    /// Convert a `SuricataRule` back to its text representation.
    #[must_use]
    pub fn generate(rule: &SuricataRule) -> String {
        rule.to_string()
    }

    /// Build a fresh alert rule for a TCP content match.
    #[must_use]
    pub fn tcp_content_alert(
        sid: u64,
        msg: impl AsRef<str>,
        src: AddrSpec,
        dst: AddrSpec,
        port: PortSpec,
        content: impl AsRef<str>,
        classtype: Option<&str>,
    ) -> SuricataRule {
        let mut opts = vec![
            RuleOption::new("msg", Some(format!("\"{}\"", msg.as_ref()))),
            RuleOption::new("content", Some(format!("\"{}\"", content.as_ref()))),
        ];
        if let Some(ct) = classtype {
            opts.push(RuleOption::new("classtype", Some(ct)));
        }
        opts.push(RuleOption::new("sid", Some(sid.to_string())));
        opts.push(RuleOption::new("rev", Some("1")));

        SuricataRule {
            action: SuricataAction::Alert,
            proto: SuricataProto::Tcp,
            src_addr: src,
            src_port: PortSpec::Any,
            direction: Direction::Uni,
            dst_addr: dst,
            dst_port: port,
            options: opts,
            disabled: false,
            raw_line: None,
        }
    }

    /// Build an alert rule for a DNS query match.
    #[must_use]
    pub fn dns_alert(sid: u64, msg: impl AsRef<str>, domain_content: impl AsRef<str>) -> SuricataRule {
        let opts = vec![
            RuleOption::new("msg", Some(format!("\"{}\"", msg.as_ref()))),
            RuleOption::new("dns.query", None as Option<String>),
            RuleOption::new("content", Some(format!("\"{}\"", domain_content.as_ref()))),
            RuleOption::new("nocase", None as Option<String>),
            RuleOption::new("sid", Some(sid.to_string())),
            RuleOption::new("rev", Some("1")),
        ];
        SuricataRule {
            action: SuricataAction::Alert,
            proto: SuricataProto::Dns,
            src_addr: AddrSpec::Any,
            src_port: PortSpec::Any,
            direction: Direction::Uni,
            dst_addr: AddrSpec::Any,
            dst_port: PortSpec::Any,
            options: opts,
            disabled: false,
            raw_line: None,
        }
    }
}

// ─── Rule Set ─────────────────────────────────────────────────────────────────

/// Holds a collection of parsed Suricata rules indexed by SID.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct SuricataRuleSet {
    pub rules: Vec<SuricataRule>,
    sid_index: HashMap<u64, usize>,
}

impl SuricataRuleSet {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(&mut self, rule: SuricataRule) {
        if let Some(sid) = rule.sid() {
            let idx = self.rules.len();
            self.sid_index.insert(sid, idx);
        }
        self.rules.push(rule);
    }

    #[must_use]
    pub fn load_file(content: &str) -> Self {
        let mut set = Self::new();
        for rule in SuricataParser::parse_file_lenient(content) {
            set.add(rule);
        }
        set
    }

    #[must_use]
    pub fn find_by_sid(&self, sid: u64) -> Option<&SuricataRule> {
        self.sid_index.get(&sid).and_then(|&i| self.rules.get(i))
    }

    pub fn enabled_rules(&self) -> impl Iterator<Item = &SuricataRule> {
        self.rules.iter().filter(|r| !r.disabled)
    }

    #[must_use]
    pub fn rules_for_proto(&self, proto: &SuricataProto) -> Vec<&SuricataRule> {
        self.rules.iter().filter(|r| &r.proto == proto).collect()
    }

    #[must_use]
    pub fn to_file_content(&self) -> String {
        self.rules
            .iter()
            .map(SuricataRule::to_string)
            .collect::<Vec<_>>()
            .join("\n")
    }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn split_group(s: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut depth = 0i32;
    let mut start = 0;
    for (i, c) in s.char_indices() {
        match c {
            '[' => depth += 1,
            ']' => depth -= 1,
            ',' if depth == 0 => {
                parts.push(s[start..i].trim());
                start = i + 1;
            }
            _ => {}
        }
    }
    let last = s[start..].trim();
    if !last.is_empty() {
        parts.push(last);
    }
    parts
}

/// Simple tokenizer for a single rule line.
struct Tokenizer<'a> {
    input: &'a str,
    pos: usize,
}

impl<'a> Tokenizer<'a> {
    const fn new(input: &'a str) -> Self {
        Self { input, pos: 0 }
    }

    fn skip_whitespace(&mut self) {
        while self.pos < self.input.len()
            && self.input.as_bytes()[self.pos].is_ascii_whitespace()
        {
            self.pos += 1;
        }
    }

    fn next_word(&mut self) -> Option<&'a str> {
        self.skip_whitespace();
        let start = self.pos;
        while self.pos < self.input.len()
            && !self.input.as_bytes()[self.pos].is_ascii_whitespace()
        {
            self.pos += 1;
        }
        if self.pos == start {
            None
        } else {
            Some(&self.input[start..self.pos])
        }
    }

    /// Read either a plain word or a `[...]` bracketed group (possibly nested).
    fn next_addr_or_port(&mut self) -> Option<&'a str> {
        self.skip_whitespace();
        if self.pos >= self.input.len() {
            return None;
        }
        if self.input.as_bytes()[self.pos] == b'[' {
            let start = self.pos;
            let mut depth = 0i32;
            while self.pos < self.input.len() {
                let b = self.input.as_bytes()[self.pos];
                if b == b'[' { depth += 1; }
                else if b == b']' {
                    depth -= 1;
                    if depth == 0 { self.pos += 1; break; }
                }
                self.pos += 1;
            }
            Some(&self.input[start..self.pos])
        } else {
            self.next_word()
        }
    }

    /// Parse the `(options;)` block at the current position.
    fn parse_options(&mut self) -> ParseResult<Vec<RuleOption>> {
        self.skip_whitespace();
        if self.pos >= self.input.len() || self.input.as_bytes()[self.pos] != b'(' {
            return Err(SuricataParseError::MissingOptions);
        }
        self.pos += 1; // skip '('

        // Find the matching ')'.
        let close = self.input[self.pos..]
            .rfind(')')
            .map(|i| self.pos + i)
            .ok_or(SuricataParseError::MissingOptions)?;
        let opts_str = &self.input[self.pos..close];

        Ok(parse_options_block(opts_str))
    }
}

fn parse_options_block(s: &str) -> Vec<RuleOption> {
    let mut options = Vec::new();
    let parts = split_options(s);
    for part in parts {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if let Some(colon_pos) = part.find(':') {
            let key = part[..colon_pos].trim().to_string();
            let value = part[colon_pos + 1..].trim().to_string();
            options.push(RuleOption { keyword: key, value: Some(value) });
        } else {
            options.push(RuleOption { keyword: part.to_string(), value: None });
        }
    }
    options
}

/// Split `(options;)` content by `;`, respecting quoted strings.
fn split_options(s: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut in_quote = false;
    let mut escape = false;
    let mut start = 0;

    for (i, c) in s.char_indices() {
        if escape {
            escape = false;
            continue;
        }
        match c {
            '\\' => escape = true,
            '"' => in_quote = !in_quote,
            ';' if !in_quote => {
                parts.push(&s[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    let last = s[start..].trim();
    if !last.is_empty() {
        parts.push(last);
    }
    parts
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_RULE: &str = r#"alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"ET MALWARE test"; content:"evil.exe"; nocase; sid:1000001; rev:1;)"#;

    #[test]
    fn test_parse_basic_rule() {
        let rule = SuricataParser::parse_rule(SAMPLE_RULE).unwrap();
        assert_eq!(rule.action, SuricataAction::Alert);
        assert_eq!(rule.proto, SuricataProto::Tcp);
        assert_eq!(rule.direction, Direction::Uni);
        assert_eq!(rule.sid(), Some(1_000_001));
        assert!(rule.msg().unwrap().contains("test"));
    }

    #[test]
    fn test_content_patterns() {
        let rule = SuricataParser::parse_rule(SAMPLE_RULE).unwrap();
        let patterns = rule.content_patterns();
        assert_eq!(patterns, vec!["evil.exe"]);
    }

    #[test]
    fn test_rule_roundtrip() {
        let rule = SuricataParser::parse_rule(SAMPLE_RULE).unwrap();
        let generated = SuricataGenerator::generate(&rule);
        let reparsed = SuricataParser::parse_rule(&generated).unwrap();
        assert_eq!(reparsed.sid(), rule.sid());
        assert_eq!(reparsed.proto, rule.proto);
    }

    #[test]
    fn test_disabled_rule() {
        let disabled = format!("# {SAMPLE_RULE}");
        let rule = SuricataParser::parse_rule(&disabled).unwrap();
        assert!(rule.disabled);
    }

    #[test]
    fn test_dns_generator() {
        let rule = SuricataGenerator::dns_alert(9_999_999, "DNS evil domain", "evil.example.com");
        assert_eq!(rule.proto, SuricataProto::Dns);
        assert_eq!(rule.sid(), Some(9_999_999));
        let s = rule.to_string();
        assert!(s.contains("evil.example.com"));
    }

    #[test]
    fn test_rule_set() {
        let mut set = SuricataRuleSet::new();
        let rule = SuricataParser::parse_rule(SAMPLE_RULE).unwrap();
        set.add(rule);
        assert!(set.find_by_sid(1_000_001).is_some());
        assert_eq!(set.rules_for_proto(&SuricataProto::Tcp).len(), 1);
    }

    #[test]
    fn test_port_parse() {
        assert_eq!(PortSpec::parse("any"), PortSpec::Any);
        assert_eq!(PortSpec::parse("80"), PortSpec::Single(80));
        assert_eq!(PortSpec::parse("1024:65535"), PortSpec::Range(1024, 65535));
    }

    #[test]
    fn test_addr_cidr() {
        let a = AddrSpec::parse("192.168.1.0/24");
        assert!(matches!(a, AddrSpec::Cidr(_)));
    }

    #[test]
    fn test_negated_addr() {
        let a = AddrSpec::parse("!10.0.0.0/8");
        assert!(matches!(a, AddrSpec::Negated(_)));
    }
}
