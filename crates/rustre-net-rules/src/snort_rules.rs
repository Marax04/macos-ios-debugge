//! `snort_rules` — Parse and generate Snort/Suricata IDS rules.
//!
//! Provides a dedicated high-fidelity rule representation (`SnortRule`) that
//! models the full Snort 3 / Suricata rule syntax, a streaming parser
//! (`SnortRuleParser`), and a `RuleGenerator` that serialises rules back to
//! the canonical wire format.

use serde::{Deserialize, Serialize};
use std::fmt;

// ---------------------------------------------------------------------------
// RuleHeader
// ---------------------------------------------------------------------------

/// Action field of a Snort/Suricata rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SnortAction {
    Alert,
    Pass,
    Drop,
    Reject,
    Log,
    Rewrite,
}

impl SnortAction {
    /// Parse from a lowercase keyword.
    #[must_use]
    pub fn parse_keyword(s: &str) -> Option<Self> {
        match s {
            "alert" => Some(Self::Alert),
            "pass" => Some(Self::Pass),
            "drop" => Some(Self::Drop),
            "reject" => Some(Self::Reject),
            "log" => Some(Self::Log),
            "rewrite" => Some(Self::Rewrite),
            _ => None,
        }
    }
}

impl fmt::Display for SnortAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Alert => "alert",
            Self::Pass => "pass",
            Self::Drop => "drop",
            Self::Reject => "reject",
            Self::Log => "log",
            Self::Rewrite => "rewrite",
        };
        write!(f, "{s}")
    }
}

/// Protocol field of a Snort/Suricata rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SnortProtocol {
    Tcp,
    Udp,
    Icmp,
    Http,
    Dns,
    Tls,
    Smtp,
    Ssh,
    Ftp,
    Any,
    Other(String),
}

impl SnortProtocol {
    /// Parse from a string keyword.
    #[must_use]
    pub fn parse_keyword(s: &str) -> Self {
        match s {
            "tcp" => Self::Tcp,
            "udp" => Self::Udp,
            "icmp" => Self::Icmp,
            "http" => Self::Http,
            "dns" => Self::Dns,
            "tls" => Self::Tls,
            "smtp" => Self::Smtp,
            "ssh" => Self::Ssh,
            "ftp" => Self::Ftp,
            "any" => Self::Any,
            other => Self::Other(other.to_string()),
        }
    }
}

impl fmt::Display for SnortProtocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
            Self::Icmp => "icmp",
            Self::Http => "http",
            Self::Dns => "dns",
            Self::Tls => "tls",
            Self::Smtp => "smtp",
            Self::Ssh => "ssh",
            Self::Ftp => "ftp",
            Self::Any => "any",
            Self::Other(s) => s.as_str(),
        };
        write!(f, "{s}")
    }
}

/// Direction indicator for a Snort/Suricata rule header.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SnortDirection {
    /// Unidirectional (`->`).
    Unidirectional,
    /// Bidirectional (`<>`).
    Bidirectional,
}

impl fmt::Display for SnortDirection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unidirectional => write!(f, "->"),
            Self::Bidirectional => write!(f, "<>"),
        }
    }
}

/// The five-element rule header: `action proto src direction dst`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleHeader {
    pub action: SnortAction,
    pub protocol: SnortProtocol,
    /// Source address/group (e.g. `any`, `$HOME_NET`, `192.168.0.0/16`).
    pub src: String,
    /// Source port specifier (e.g. `any`, `80`, `1024:65535`).
    pub src_port: String,
    pub direction: SnortDirection,
    /// Destination address/group.
    pub dst: String,
    /// Destination port specifier.
    pub dst_port: String,
}

impl RuleHeader {
    /// Create a simple header matching any TCP traffic.
    #[must_use]
    pub fn any_tcp() -> Self {
        Self {
            action: SnortAction::Alert,
            protocol: SnortProtocol::Tcp,
            src: "any".into(),
            src_port: "any".into(),
            direction: SnortDirection::Unidirectional,
            dst: "any".into(),
            dst_port: "any".into(),
        }
    }
}

impl fmt::Display for RuleHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} {} {} {} {} {}",
            self.action,
            self.protocol,
            self.src,
            self.src_port,
            self.direction,
            self.dst,
            self.dst_port,
        )
    }
}

// ---------------------------------------------------------------------------
// RuleOption
// ---------------------------------------------------------------------------

/// A single key-value option within the options block `( ... )`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RuleOption {
    /// `msg:"<text>"` — human-readable alert message.
    Msg(String),
    /// `content:"<bytes>"` — byte content to search for.
    Content(Vec<u8>),
    /// `nocase` — make the preceding content match case-insensitive.
    Nocase,
    /// `offset:<n>` — start content search at byte offset `n`.
    Offset(u32),
    /// `depth:<n>` — limit content search to first `n` bytes.
    Depth(u32),
    /// `within:<n>` — limit content search to `n` bytes after previous match.
    Within(u32),
    /// `distance:<n>` — require `n` bytes between previous and current match.
    Distance(u32),
    /// `pcre:"<pattern>"` — PCRE regular expression.
    Pcre(String),
    /// `sid:<n>` — unique rule identifier.
    Sid(u32),
    /// `rev:<n>` — revision number.
    Rev(u32),
    /// `classtype:<type>` — classification category.
    Classtype(String),
    /// `priority:<n>` — rule priority (1 = highest).
    Priority(u8),
    /// `dsize:<spec>` — payload size constraint.
    Dsize(String),
    /// `flow:<flags>` — flow state constraint.
    Flow(String),
    /// `flags:<tcp-flags>` — TCP flag constraint.
    Flags(String),
    /// `ttl:<value>` — IP TTL constraint.
    Ttl(String),
    /// `metadata:<key-value pairs>` — arbitrary metadata.
    Metadata(String),
    /// `reference:<type,id>` — CVE or external reference.
    Reference(String, String),
    /// `http_method` — match HTTP method field.
    HttpMethod,
    /// `http_uri` — match HTTP URI.
    HttpUri,
    /// `http_header` — match HTTP header content.
    HttpHeader,
    /// `http_client_body` — match HTTP client body.
    HttpClientBody,
    /// `rawbytes` — disable content decoders.
    Rawbytes,
    /// Any option not covered above, stored as raw `key:value`.
    Unknown { key: String, value: Option<String> },
}

impl RuleOption {
    /// Return the keyword name for this option.
    #[must_use]
    pub fn keyword(&self) -> &str {
        match self {
            Self::Msg(_) => "msg",
            Self::Content(_) => "content",
            Self::Nocase => "nocase",
            Self::Offset(_) => "offset",
            Self::Depth(_) => "depth",
            Self::Within(_) => "within",
            Self::Distance(_) => "distance",
            Self::Pcre(_) => "pcre",
            Self::Sid(_) => "sid",
            Self::Rev(_) => "rev",
            Self::Classtype(_) => "classtype",
            Self::Priority(_) => "priority",
            Self::Dsize(_) => "dsize",
            Self::Flow(_) => "flow",
            Self::Flags(_) => "flags",
            Self::Ttl(_) => "ttl",
            Self::Metadata(_) => "metadata",
            Self::Reference(_, _) => "reference",
            Self::HttpMethod => "http_method",
            Self::HttpUri => "http_uri",
            Self::HttpHeader => "http_header",
            Self::HttpClientBody => "http_client_body",
            Self::Rawbytes => "rawbytes",
            Self::Unknown { key, .. } => key,
        }
    }
}

impl fmt::Display for RuleOption {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Msg(s) => write!(f, r#"msg:"{s}""#),
            Self::Content(b) => {
                let s = String::from_utf8_lossy(b);
                write!(f, r#"content:"{s}""#)
            }
            Self::Nocase => write!(f, "nocase"),
            Self::Offset(n) => write!(f, "offset:{n}"),
            Self::Depth(n) => write!(f, "depth:{n}"),
            Self::Within(n) => write!(f, "within:{n}"),
            Self::Distance(n) => write!(f, "distance:{n}"),
            Self::Pcre(s) => write!(f, r#"pcre:"{s}""#),
            Self::Sid(n) => write!(f, "sid:{n}"),
            Self::Rev(n) => write!(f, "rev:{n}"),
            Self::Classtype(s) => write!(f, "classtype:{s}"),
            Self::Priority(n) => write!(f, "priority:{n}"),
            Self::Dsize(s) => write!(f, "dsize:{s}"),
            Self::Flow(s) => write!(f, "flow:{s}"),
            Self::Flags(s) => write!(f, "flags:{s}"),
            Self::Ttl(s) => write!(f, "ttl:{s}"),
            Self::Metadata(s) => write!(f, "metadata:{s}"),
            Self::Reference(t, id) => write!(f, "reference:{t},{id}"),
            Self::HttpMethod => write!(f, "http_method"),
            Self::HttpUri => write!(f, "http_uri"),
            Self::HttpHeader => write!(f, "http_header"),
            Self::HttpClientBody => write!(f, "http_client_body"),
            Self::Rawbytes => write!(f, "rawbytes"),
            Self::Unknown { key, value } => {
                if let Some(v) = value {
                    write!(f, "{key}:{v}")
                } else {
                    write!(f, "{key}")
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// SnortRule
// ---------------------------------------------------------------------------

/// A complete Snort 3 / Suricata rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnortRule {
    /// The five-token rule header.
    pub header: RuleHeader,
    /// Ordered list of options within the parentheses block.
    pub options: Vec<RuleOption>,
    /// Original raw text (preserved from parsing, `None` for generated rules).
    pub raw: Option<String>,
}

impl SnortRule {
    /// Create a rule with the given header and an empty options list.
    #[must_use]
    pub const fn new(header: RuleHeader) -> Self {
        Self {
            header,
            options: Vec::new(),
            raw: None,
        }
    }

    /// Add an option and return `self` for chaining.
    #[must_use]
    pub fn with_option(mut self, option: RuleOption) -> Self {
        self.options.push(option);
        self
    }

    /// Return the SID if one exists in the options.
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

    /// Return the message string if present.
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

    /// Return all content patterns.
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

    /// Return the classtype if present.
    #[must_use]
    pub fn classtype(&self) -> Option<&str> {
        self.options.iter().find_map(|o| {
            if let RuleOption::Classtype(s) = o {
                Some(s.as_str())
            } else {
                None
            }
        })
    }

    /// Return `true` if this rule uses any HTTP sticky-buffer keywords.
    #[must_use]
    pub fn is_http_rule(&self) -> bool {
        matches!(self.header.protocol, SnortProtocol::Http)
            || self.options.iter().any(|o| {
                matches!(
                    o,
                    RuleOption::HttpMethod
                        | RuleOption::HttpUri
                        | RuleOption::HttpHeader
                        | RuleOption::HttpClientBody
                )
            })
    }

    /// Render to the canonical Snort rule wire format.
    #[must_use]
    pub fn to_rule_string(&self) -> String {
        RuleGenerator::generate(self)
    }
}

impl fmt::Display for SnortRule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_rule_string())
    }
}

// ---------------------------------------------------------------------------
// SnortRuleParser
// ---------------------------------------------------------------------------

/// Error returned by [`SnortRuleParser`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError {
    pub message: String,
    pub position: usize,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "parse error at position {}: {}",
            self.position, self.message
        )
    }
}

impl std::error::Error for ParseError {}

/// Streaming Snort/Suricata rule parser.
///
/// Supports the full header syntax and a large subset of option keywords.
pub struct SnortRuleParser;

impl SnortRuleParser {
    /// Parse a single rule string.
    ///
    /// # Errors
    /// Returns a [`ParseError`] if the string is not a valid rule.
    pub fn parse(input: &str) -> Result<SnortRule, ParseError> {
        let input = input.trim();

        // Skip blank lines and comments
        if input.is_empty() || input.starts_with('#') {
            return Err(ParseError {
                message: "empty or comment".into(),
                position: 0,
            });
        }

        // Split header from options block
        let paren_open = input.find('(').ok_or_else(|| ParseError {
            message: "missing '(' options block".into(),
            position: input.len(),
        })?;
        let paren_close = input.rfind(')').ok_or_else(|| ParseError {
            message: "missing ')' to close options block".into(),
            position: input.len(),
        })?;

        if paren_close < paren_open {
            return Err(ParseError {
                message: "')' appears before '('".into(),
                position: paren_close,
            });
        }

        let header_str = input[..paren_open].trim();
        let options_str = &input[paren_open + 1..paren_close];

        let header = Self::parse_header(header_str)?;
        let options = Self::parse_options(options_str)?;

        Ok(SnortRule {
            header,
            options,
            raw: Some(input.to_string()),
        })
    }

    /// Parse multiple rules from a newline-delimited string.
    /// Returns `(successes, errors)`.
    #[must_use]
    pub fn parse_many(input: &str) -> (Vec<SnortRule>, Vec<ParseError>) {
        let mut rules = Vec::new();
        let mut errors = Vec::new();

        for line in input.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            match Self::parse(line) {
                Ok(r) => rules.push(r),
                Err(e) => errors.push(e),
            }
        }
        (rules, errors)
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    fn parse_header(s: &str) -> Result<RuleHeader, ParseError> {
        let tokens: Vec<&str> = s.split_whitespace().collect();
        if tokens.len() < 7 {
            return Err(ParseError {
                message: format!(
                    "rule header requires 7 tokens (action proto src srcport dir dst dstport), found {}",
                    tokens.len()
                ),
                position: 0,
            });
        }

        let action = SnortAction::parse_keyword(tokens[0]).ok_or_else(|| ParseError {
            message: format!("unknown action '{}'", tokens[0]),
            position: 0,
        })?;

        let protocol = SnortProtocol::parse_keyword(tokens[1]);

        let direction = match tokens[4] {
            "->" => SnortDirection::Unidirectional,
            "<>" => SnortDirection::Bidirectional,
            d => {
                return Err(ParseError {
                    message: format!("unknown direction '{d}'"),
                    position: 0,
                });
            }
        };

        Ok(RuleHeader {
            action,
            protocol,
            src: tokens[2].to_string(),
            src_port: tokens[3].to_string(),
            direction,
            dst: tokens[5].to_string(),
            dst_port: tokens[6].to_string(),
        })
    }

    fn parse_options(opts: &str) -> Result<Vec<RuleOption>, ParseError> {
        let mut result = Vec::new();

        // Tokenise respecting quoted strings and semi-colon delimiters
        for token in tokenise_options(opts) {
            let token = token.trim();
            if token.is_empty() {
                continue;
            }

            if let Some(opt) = Self::parse_one_option(token)? {
                result.push(opt);
            }
        }

        Ok(result)
    }

    fn parse_one_option(token: &str) -> Result<Option<RuleOption>, ParseError> {
        // Keyword-only options
        match token {
            "nocase" => return Ok(Some(RuleOption::Nocase)),
            "http_method" => return Ok(Some(RuleOption::HttpMethod)),
            "http_uri" => return Ok(Some(RuleOption::HttpUri)),
            "http_header" => return Ok(Some(RuleOption::HttpHeader)),
            "http_client_body" => return Ok(Some(RuleOption::HttpClientBody)),
            "rawbytes" => return Ok(Some(RuleOption::Rawbytes)),
            _ => {}
        }

        // Split on first ':'
        let Some(colon) = token.find(':') else {
            return Ok(Some(RuleOption::Unknown {
                key: token.to_string(),
                value: None,
            }));
        };
        let key = token[..colon].trim();
        let value = token[colon + 1..].trim();

        let opt = match key {
            "msg" => RuleOption::Msg(strip_quotes(value).to_string()),
            "content" => {
                let bytes = parse_content_bytes(value);
                RuleOption::Content(bytes)
            }
            "offset" => RuleOption::Offset(parse_u32(value, "offset")?),
            "depth" => RuleOption::Depth(parse_u32(value, "depth")?),
            "within" => RuleOption::Within(parse_u32(value, "within")?),
            "distance" => RuleOption::Distance(parse_u32(value, "distance")?),
            "pcre" => RuleOption::Pcre(strip_quotes(value).to_string()),
            "sid" => RuleOption::Sid(parse_u32(value, "sid")?),
            "rev" => RuleOption::Rev(parse_u32(value, "rev")?),
            "classtype" => RuleOption::Classtype(value.to_string()),
            "priority" => {
                let n = u8::try_from(parse_u32(value, "priority")?).unwrap_or(u8::MAX);
                RuleOption::Priority(n)
            }
            "dsize" => RuleOption::Dsize(value.to_string()),
            "flow" => RuleOption::Flow(value.to_string()),
            "flags" => RuleOption::Flags(value.to_string()),
            "ttl" => RuleOption::Ttl(value.to_string()),
            "metadata" => RuleOption::Metadata(value.to_string()),
            "reference" => {
                let comma = value.find(',').unwrap_or(value.len());
                let ref_type = value[..comma].to_string();
                let ref_id = if comma < value.len() {
                    value[comma + 1..].to_string()
                } else {
                    String::new()
                };
                RuleOption::Reference(ref_type, ref_id)
            }
            _ => RuleOption::Unknown {
                key: key.to_string(),
                value: Some(value.to_string()),
            },
        };

        Ok(Some(opt))
    }
}

// ---------------------------------------------------------------------------
// Private parsing utilities
// ---------------------------------------------------------------------------

/// Split an options string on `;` while respecting quoted strings.
fn tokenise_options(opts: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut in_quote = false;
    let mut quote_char = '"';

    for ch in opts.chars() {
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
            tokens.push(current.trim().to_string());
            current.clear();
        } else {
            current.push(ch);
        }
    }
    if !current.trim().is_empty() {
        tokens.push(current.trim().to_string());
    }
    tokens
}

/// Strip leading/trailing quote characters from a value.
fn strip_quotes(s: &str) -> &str {
    let s = s.trim();
    if (s.starts_with('"') && s.ends_with('"')) || (s.starts_with('\'') && s.ends_with('\'')) {
        &s[1..s.len() - 1]
    } else {
        s
    }
}

/// Parse `content:` bytes, handling `"ascii"` and `|hex bytes|` notation.
fn parse_content_bytes(s: &str) -> Vec<u8> {
    let s = s.trim();
    let inner = if s.starts_with('"') && s.ends_with('"') && s.len() >= 2 {
        &s[1..s.len() - 1]
    } else {
        s
    };
    let mut out = Vec::with_capacity(inner.len());
    let mut in_hex = false;
    let mut hex_buf = String::new();
    for c in inner.chars() {
        if c == '|' {
            if in_hex {
                for tok in hex_buf.split_whitespace() {
                    if let Ok(b) = u8::from_str_radix(tok, 16) {
                        out.push(b);
                    }
                }
                hex_buf.clear();
                in_hex = false;
            } else {
                in_hex = true;
            }
        } else if in_hex {
            hex_buf.push(c);
        } else {
            let mut buf = [0u8; 4];
            out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
        }
    }
    out
}

fn parse_u32(s: &str, field: &str) -> Result<u32, ParseError> {
    s.trim().parse::<u32>().map_err(|_| ParseError {
        message: format!("invalid {field} value '{s}'"),
        position: 0,
    })
}

// ---------------------------------------------------------------------------
// RuleGenerator
// ---------------------------------------------------------------------------

/// Generates canonical Snort/Suricata rule strings from [`SnortRule`] structs.
pub struct RuleGenerator;

/// Source and destination endpoints used when generating alert rules.
#[derive(Debug, Clone, Copy)]
pub struct AlertEndpoints<'a> {
    pub src: &'a str,
    pub src_port: &'a str,
    pub dst: &'a str,
    pub dst_port: &'a str,
}

impl RuleGenerator {
    /// Render `rule` to the canonical Snort wire format.
    #[must_use]
    pub fn generate(rule: &SnortRule) -> String {
        let header = rule.header.to_string();
        if rule.options.is_empty() {
            return format!("{header} ()");
        }
        let opts: Vec<String> = rule
            .options
            .iter()
            .map(std::string::ToString::to_string)
            .collect();
        format!("{header} ({})", opts.join("; "))
    }

    /// Build a minimal alert rule for a content pattern.
    #[must_use]
    pub fn alert_content(
        proto: SnortProtocol,
        endpoints: AlertEndpoints<'_>,
        msg: &str,
        content: &[u8],
        sid: u32,
    ) -> SnortRule {
        let AlertEndpoints {
            src,
            src_port,
            dst,
            dst_port,
        } = endpoints;
        let header = RuleHeader {
            action: SnortAction::Alert,
            protocol: proto,
            src: src.to_string(),
            src_port: src_port.to_string(),
            direction: SnortDirection::Unidirectional,
            dst: dst.to_string(),
            dst_port: dst_port.to_string(),
        };

        SnortRule::new(header)
            .with_option(RuleOption::Msg(msg.to_string()))
            .with_option(RuleOption::Content(content.to_vec()))
            .with_option(RuleOption::Sid(sid))
            .with_option(RuleOption::Rev(1))
    }

    /// Build a rule with PCRE matching.
    #[must_use]
    pub fn alert_pcre(
        proto: SnortProtocol,
        dst_port: &str,
        msg: &str,
        pcre: &str,
        sid: u32,
    ) -> SnortRule {
        let header = RuleHeader {
            action: SnortAction::Alert,
            protocol: proto,
            src: "any".into(),
            src_port: "any".into(),
            direction: SnortDirection::Unidirectional,
            dst: "any".into(),
            dst_port: dst_port.to_string(),
        };

        SnortRule::new(header)
            .with_option(RuleOption::Msg(msg.to_string()))
            .with_option(RuleOption::Pcre(pcre.to_string()))
            .with_option(RuleOption::Sid(sid))
            .with_option(RuleOption::Rev(1))
    }

    /// Render multiple rules, one per line.
    #[must_use]
    pub fn generate_many(rules: &[SnortRule]) -> String {
        rules
            .iter()
            .map(Self::generate)
            .collect::<Vec<_>>()
            .join("\n")
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn simple_alert_rule() -> &'static str {
        r#"alert tcp any any -> any 80 (msg:"Test Rule"; content:"evil"; sid:1001; rev:1;)"#
    }

    // ── SnortAction ───────────────────────────────────────────────────────────

    #[test]
    fn action_from_str_known() {
        assert_eq!(
            SnortAction::parse_keyword("alert"),
            Some(SnortAction::Alert)
        );
        assert_eq!(SnortAction::parse_keyword("drop"), Some(SnortAction::Drop));
        assert_eq!(SnortAction::parse_keyword("pass"), Some(SnortAction::Pass));
    }

    #[test]
    fn action_from_str_unknown() {
        assert_eq!(SnortAction::parse_keyword("explode"), None);
    }

    #[test]
    fn action_display() {
        assert_eq!(SnortAction::Alert.to_string(), "alert");
        assert_eq!(SnortAction::Reject.to_string(), "reject");
    }

    // ── SnortProtocol ─────────────────────────────────────────────────────────

    #[test]
    fn protocol_from_str_known() {
        assert_eq!(SnortProtocol::parse_keyword("tcp"), SnortProtocol::Tcp);
        assert_eq!(SnortProtocol::parse_keyword("http"), SnortProtocol::Http);
        assert_eq!(SnortProtocol::parse_keyword("any"), SnortProtocol::Any);
    }

    #[test]
    fn protocol_from_str_custom() {
        if let SnortProtocol::Other(s) = SnortProtocol::parse_keyword("quic") {
            assert_eq!(s, "quic");
        } else {
            panic!("expected Other");
        }
    }

    #[test]
    fn protocol_display() {
        assert_eq!(SnortProtocol::Udp.to_string(), "udp");
        assert_eq!(SnortProtocol::Other("quic".into()).to_string(), "quic");
    }

    // ── RuleHeader ────────────────────────────────────────────────────────────

    #[test]
    fn rule_header_display() {
        let h = RuleHeader::any_tcp();
        let s = h.to_string();
        assert!(s.contains("alert") && s.contains("tcp") && s.contains("->"));
    }

    // ── RuleOption ────────────────────────────────────────────────────────────

    #[test]
    fn rule_option_keyword() {
        assert_eq!(RuleOption::Sid(42).keyword(), "sid");
        assert_eq!(RuleOption::Nocase.keyword(), "nocase");
    }

    #[test]
    fn rule_option_display_sid() {
        assert_eq!(RuleOption::Sid(9999).to_string(), "sid:9999");
    }

    #[test]
    fn rule_option_display_content() {
        let o = RuleOption::Content(b"GET ".to_vec());
        assert!(o.to_string().contains("GET"));
    }

    #[test]
    fn rule_option_display_msg() {
        let o = RuleOption::Msg("Hello world".into());
        assert_eq!(o.to_string(), r#"msg:"Hello world""#);
    }

    // ── SnortRuleParser ───────────────────────────────────────────────────────

    #[test]
    fn parser_basic_rule() {
        let rule = SnortRuleParser::parse(simple_alert_rule()).unwrap();
        assert_eq!(rule.header.action, SnortAction::Alert);
        assert_eq!(rule.header.protocol, SnortProtocol::Tcp);
        assert_eq!(rule.sid(), Some(1001));
        assert_eq!(rule.msg(), Some("Test Rule"));
    }

    #[test]
    fn parser_content_bytes_extracted() {
        let rule = SnortRuleParser::parse(simple_alert_rule()).unwrap();
        let patterns = rule.content_patterns();
        assert_eq!(patterns.len(), 1);
        assert_eq!(patterns[0], b"evil");
    }

    #[test]
    fn parser_hex_content() {
        let input = r#"alert tcp any any -> any any (content:"|DE AD BE EF|"; sid:2;)"#;
        let rule = SnortRuleParser::parse(input).unwrap();
        let patterns = rule.content_patterns();
        assert_eq!(patterns[0], &[0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn parser_pcre_option() {
        let input = r#"alert tcp any any -> any 80 (msg:"x"; pcre:"/evil/i"; sid:3;)"#;
        let rule = SnortRuleParser::parse(input).unwrap();
        let has_pcre = rule
            .options
            .iter()
            .any(|o| matches!(o, RuleOption::Pcre(_)));
        assert!(has_pcre);
    }

    #[test]
    fn parser_classtype_option() {
        let input = r"alert tcp any any -> any any (classtype:trojan-activity; sid:4;)";
        let rule = SnortRuleParser::parse(input).unwrap();
        assert_eq!(rule.classtype(), Some("trojan-activity"));
    }

    #[test]
    fn parser_priority_option() {
        let input = r"alert tcp any any -> any any (priority:1; sid:5;)";
        let rule = SnortRuleParser::parse(input).unwrap();
        assert!(
            rule.options
                .iter()
                .any(|o| matches!(o, RuleOption::Priority(1)))
        );
    }

    #[test]
    fn parser_rejects_empty() {
        assert!(SnortRuleParser::parse("").is_err());
        assert!(SnortRuleParser::parse("# comment").is_err());
    }

    #[test]
    fn parser_rejects_missing_parens() {
        assert!(SnortRuleParser::parse("alert tcp any any -> any any").is_err());
    }

    #[test]
    fn parser_rejects_bad_action() {
        let input = r"attack tcp any any -> any any (sid:1;)";
        assert!(SnortRuleParser::parse(input).is_err());
    }

    #[test]
    fn parser_many_collects_errors() {
        let input = "# comment\nalert tcp any any -> any 80 (msg:\"A\"; sid:1;)\nNOT_A_RULE";
        let (rules, errors) = SnortRuleParser::parse_many(input);
        assert_eq!(rules.len(), 1);
        assert_eq!(errors.len(), 1);
    }

    // ── SnortRule helpers ─────────────────────────────────────────────────────

    #[test]
    fn rule_is_http_rule_by_protocol() {
        let header = RuleHeader {
            action: SnortAction::Alert,
            protocol: SnortProtocol::Http,
            src: "any".into(),
            src_port: "any".into(),
            direction: SnortDirection::Unidirectional,
            dst: "any".into(),
            dst_port: "any".into(),
        };
        let rule = SnortRule::new(header);
        assert!(rule.is_http_rule());
    }

    #[test]
    fn rule_is_http_rule_by_sticky_buffer() {
        let rule = SnortRule::new(RuleHeader::any_tcp()).with_option(RuleOption::HttpUri);
        assert!(rule.is_http_rule());
    }

    // ── RuleGenerator ─────────────────────────────────────────────────────────

    #[test]
    fn generator_roundtrip() {
        let rule = SnortRuleParser::parse(simple_alert_rule()).unwrap();
        let generated = RuleGenerator::generate(&rule);
        // Must still parse successfully
        let rule2 = SnortRuleParser::parse(&generated).unwrap();
        assert_eq!(rule2.sid(), rule.sid());
    }

    #[test]
    fn generator_alert_content_builds_rule() {
        let rule = RuleGenerator::alert_content(
            SnortProtocol::Tcp,
            AlertEndpoints {
                src: "any",
                src_port: "any",
                dst: "any",
                dst_port: "80",
            },
            "Test",
            b"malware",
            1000,
        );
        assert_eq!(rule.sid(), Some(1000));
        assert!(!rule.content_patterns().is_empty());
    }

    #[test]
    fn generator_alert_pcre_builds_rule() {
        let rule = RuleGenerator::alert_pcre(
            SnortProtocol::Http,
            "80",
            "HTTP exploit",
            "/exploit\\.php/i",
            9001,
        );
        assert_eq!(rule.sid(), Some(9001));
        let has_pcre = rule
            .options
            .iter()
            .any(|o| matches!(o, RuleOption::Pcre(_)));
        assert!(has_pcre);
    }

    #[test]
    fn generator_many_produces_newline_delimited() {
        let r1 = RuleGenerator::alert_content(
            SnortProtocol::Tcp,
            AlertEndpoints {
                src: "any",
                src_port: "any",
                dst: "any",
                dst_port: "80",
            },
            "A",
            b"aaa",
            1,
        );
        let r2 = RuleGenerator::alert_content(
            SnortProtocol::Udp,
            AlertEndpoints {
                src: "any",
                src_port: "any",
                dst: "any",
                dst_port: "53",
            },
            "B",
            b"bbb",
            2,
        );
        let output = RuleGenerator::generate_many(&[r1, r2]);
        assert_eq!(output.lines().count(), 2);
    }

    #[test]
    fn generator_empty_options_rule() {
        let rule = SnortRule::new(RuleHeader::any_tcp());
        let s = RuleGenerator::generate(&rule);
        assert!(s.ends_with("()"));
    }
}
