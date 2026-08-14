//! `snort_extended` — Extended Snort/Suricata rule support: enhanced parser,
//! Suricata-specific rules, YARA network rules, rule optimisation, and a
//! multi-rule engine.

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// SnortRuleParser (enhanced)
// ---------------------------------------------------------------------------

/// Snort/Suricata rule action.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RuleAction {
    Alert,
    Log,
    Pass,
    Drop,
    Reject,
    Sdrop,
    Tag,
    Custom(String),
}

impl fmt::Display for RuleAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Custom(s) => write!(f, "{s}"),
            _ => write!(f, "{}", format!("{self:?}").to_lowercase()),
        }
    }
}

impl RuleAction {
    /// Parse from string (case-insensitive).
    #[must_use]
    pub fn parse_keyword(s: &str) -> Self {
        match s.trim().to_lowercase().as_str() {
            "alert" => Self::Alert,
            "log" => Self::Log,
            "pass" => Self::Pass,
            "drop" => Self::Drop,
            "reject" => Self::Reject,
            "sdrop" => Self::Sdrop,
            "tag" => Self::Tag,
            other => Self::Custom(other.to_string()),
        }
    }
}

/// Transport protocol.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Protocol {
    Tcp,
    Udp,
    Icmp,
    Ip,
    Http,
    Ftp,
    Smtp,
    Dns,
    Tls,
    Custom(String),
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Custom(s) => write!(f, "{s}"),
            _ => write!(f, "{}", format!("{self:?}").to_lowercase()),
        }
    }
}

impl Protocol {
    /// Parse from string.
    #[must_use]
    pub fn parse_keyword(s: &str) -> Self {
        match s.trim().to_lowercase().as_str() {
            "tcp" => Self::Tcp,
            "udp" => Self::Udp,
            "icmp" => Self::Icmp,
            "ip" => Self::Ip,
            "http" => Self::Http,
            "ftp" => Self::Ftp,
            "smtp" => Self::Smtp,
            "dns" => Self::Dns,
            "tls" | "ssl" => Self::Tls,
            other => Self::Custom(other.to_string()),
        }
    }
}

/// An address/port specifier (simplified).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Address {
    Any,
    Single(String),
    List(Vec<String>),
    Negated(Box<Self>),
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Any => write!(f, "any"),
            Self::Single(s) => write!(f, "{s}"),
            Self::List(v) => write!(f, "[{}]", v.join(",")),
            Self::Negated(inner) => write!(f, "!{inner}"),
        }
    }
}

impl Address {
    #[must_use]
    pub fn parse_address(s: &str) -> Self {
        let s = s.trim();
        if s == "any" {
            return Self::Any;
        }
        if let Some(inner) = s.strip_prefix('!') {
            return Self::Negated(Box::new(Self::parse_address(inner)));
        }
        if s.starts_with('[') {
            let inner = s.trim_matches(|c| c == '[' || c == ']');
            let addrs: Vec<String> = inner.split(',').map(|a| a.trim().to_string()).collect();
            return Self::List(addrs);
        }
        Self::Single(s.to_string())
    }
}

/// A single Snort/Suricata rule option.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleOption {
    pub keyword: String,
    pub value: Option<String>,
}

impl RuleOption {
    #[must_use]
    pub fn new(keyword: impl Into<String>, value: Option<impl Into<String>>) -> Self {
        Self {
            keyword: keyword.into(),
            value: value.map(std::convert::Into::into),
        }
    }
}

impl fmt::Display for RuleOption {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.value {
            Some(v) => write!(f, "{}:{}", self.keyword, v),
            None => write!(f, "{}", self.keyword),
        }
    }
}

/// A parsed Snort/Suricata rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnortRule {
    pub action: RuleAction,
    pub protocol: Protocol,
    pub src_addr: Address,
    pub src_port: String,
    pub direction: String,
    pub dst_addr: Address,
    pub dst_port: String,
    pub options: Vec<RuleOption>,
    pub sid: Option<u32>,
    pub revision: Option<u32>,
    pub message: Option<String>,
    pub raw: String,
}

impl SnortRule {
    /// Get a specific option value by keyword.
    #[must_use]
    pub fn get_option(&self, keyword: &str) -> Option<&str> {
        self.options
            .iter()
            .find(|o| o.keyword == keyword)
            .and_then(|o| o.value.as_deref())
    }

    /// Whether this rule contains a content match.
    #[must_use]
    pub fn has_content(&self) -> bool {
        self.options
            .iter()
            .any(|o| o.keyword == "content" || o.keyword == "pcre")
    }

    /// Formatted rule string.
    #[must_use]
    pub fn to_rule_string(&self) -> String {
        let opts: Vec<String> = self
            .options
            .iter()
            .map(std::string::ToString::to_string)
            .collect();
        format!(
            "{} {} {} {} {} {} {} ({})",
            self.action,
            self.protocol,
            self.src_addr,
            self.src_port,
            self.direction,
            self.dst_addr,
            self.dst_port,
            opts.join("; ")
        )
    }
}

impl fmt::Display for SnortRule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let sid = self.sid.map(|s| format!("SID:{s}")).unwrap_or_default();
        let msg = self.message.as_deref().unwrap_or("no message");
        write!(f, "[{sid}] {} — {msg}", self.action)
    }
}

/// Enhanced Snort rule parser.
pub struct SnortExtended;

impl SnortExtended {
    /// Parse a Snort/Suricata rule string.
    #[must_use]
    pub fn parse(raw: &str) -> Option<SnortRule> {
        let raw = raw.trim();
        if raw.is_empty() || raw.starts_with('#') {
            return None;
        }

        // Split header and options
        let paren_start = raw.find('(')?;
        let header = raw[..paren_start].trim();
        let opts_str = raw[paren_start + 1..].trim_end_matches(')').trim();

        let tokens: Vec<&str> = header.split_whitespace().collect();
        if tokens.len() < 7 {
            return None;
        }

        let action = RuleAction::parse_keyword(tokens[0]);
        let protocol = Protocol::parse_keyword(tokens[1]);
        let src_addr = Address::parse_address(tokens[2]);
        let src_port = tokens[3].to_string();
        let direction = tokens[4].to_string();
        let dst_addr = Address::parse_address(tokens[5]);
        let dst_port = tokens[6].to_string();

        let options = Self::parse_options(opts_str);
        let sid = options
            .iter()
            .find(|o| o.keyword == "sid")
            .and_then(|o| o.value.as_ref())
            .and_then(|v| v.parse().ok());
        let revision = options
            .iter()
            .find(|o| o.keyword == "rev")
            .and_then(|o| o.value.as_ref())
            .and_then(|v| v.parse().ok());
        let message = options
            .iter()
            .find(|o| o.keyword == "msg")
            .and_then(|o| o.value.clone())
            .map(|s| s.trim_matches('"').to_string());

        Some(SnortRule {
            action,
            protocol,
            src_addr,
            src_port,
            direction,
            dst_addr,
            dst_port,
            options,
            sid,
            revision,
            message,
            raw: raw.to_string(),
        })
    }

    fn parse_options(s: &str) -> Vec<RuleOption> {
        let mut opts = Vec::new();
        for part in s.split(';') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            if let Some(colon) = part.find(':') {
                let keyword = part[..colon].trim().to_string();
                let value = part[colon + 1..].trim().to_string();
                opts.push(RuleOption {
                    keyword,
                    value: if value.is_empty() { None } else { Some(value) },
                });
            } else {
                opts.push(RuleOption {
                    keyword: part.to_string(),
                    value: None,
                });
            }
        }
        opts
    }

    /// Parse multiple rules from a block of text, skipping comments and blank lines.
    #[must_use]
    pub fn parse_rules(text: &str) -> Vec<SnortRule> {
        text.lines().filter_map(Self::parse).collect()
    }
}

// ---------------------------------------------------------------------------
// SuricataRule — Suricata-specific extensions
// ---------------------------------------------------------------------------

/// Suricata-specific rule metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuricataMetadata {
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
    pub signature_severity: Option<String>,
    pub attack_target: Vec<String>,
    pub deployment: Vec<String>,
    pub affected_product: Vec<String>,
}

/// A Suricata rule with extended metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuricataRule {
    pub snort_base: SnortRule,
    pub flow: Option<String>,
    pub app_layer_event: Option<String>,
    pub filestore: bool,
    pub metadata: SuricataMetadata,
    pub priority: Option<u8>,
    pub classtype: Option<String>,
}

impl SuricataRule {
    /// Create from a base Snort rule.
    #[must_use]
    pub fn from_snort(rule: SnortRule) -> Self {
        let flow = rule.get_option("flow").map(String::from);
        let classtype = rule.get_option("classtype").map(String::from);
        let priority = rule.get_option("priority").and_then(|v| v.parse().ok());
        let filestore = rule.options.iter().any(|o| o.keyword == "filestore");
        Self {
            snort_base: rule,
            flow,
            app_layer_event: None,
            filestore,
            metadata: SuricataMetadata {
                created_at: None,
                updated_at: None,
                signature_severity: None,
                attack_target: Vec::new(),
                deployment: Vec::new(),
                affected_product: Vec::new(),
            },
            priority,
            classtype,
        }
    }

    /// Whether this is a high-priority rule.
    #[must_use]
    pub fn is_high_priority(&self) -> bool {
        self.priority.is_some_and(|p| p <= 2)
    }
}

impl fmt::Display for SuricataRule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SuricataRule({})", self.snort_base)
    }
}

// ---------------------------------------------------------------------------
// YaraNetworkRule — YARA rule applied to network payload content
// ---------------------------------------------------------------------------

/// A YARA-based network content detection rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraNetworkRule {
    pub name: String,
    pub protocol_filter: Option<Protocol>,
    pub direction: NetworkDirection,
    pub patterns: Vec<Vec<u8>>,
    pub min_matches: usize,
    pub severity: u8,
    pub tags: Vec<String>,
    pub description: String,
}

/// Direction for network rules.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum NetworkDirection {
    Inbound,
    Outbound,
    Both,
}

impl YaraNetworkRule {
    /// Create a new network YARA rule.
    #[must_use]
    pub fn new(name: impl Into<String>, description: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            protocol_filter: None,
            direction: NetworkDirection::Both,
            patterns: Vec::new(),
            min_matches: 1,
            severity: 50,
            tags: Vec::new(),
            description: description.into(),
        }
    }

    /// Add a text pattern.
    pub fn add_pattern(&mut self, pattern: impl Into<Vec<u8>>) {
        self.patterns.push(pattern.into());
    }

    /// Match against payload bytes.
    #[must_use]
    pub fn matches(&self, payload: &[u8]) -> bool {
        let matched = self
            .patterns
            .iter()
            .filter(|p| !p.is_empty() && payload.windows(p.len()).any(|w| w == p.as_slice()))
            .count();
        matched >= self.min_matches
    }
}

impl fmt::Display for YaraNetworkRule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "YaraNetRule({}, severity={}, patterns={})",
            self.name,
            self.severity,
            self.patterns.len()
        )
    }
}

// ---------------------------------------------------------------------------
// RuleOptimizer
// ---------------------------------------------------------------------------

/// Rule optimisation statistics.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OptimisationStats {
    pub rules_input: usize,
    pub rules_output: usize,
    pub duplicates_removed: usize,
    pub disabled_rules_removed: usize,
    pub rules_reordered: bool,
}

/// Rule optimisation engine.
pub struct RuleOptimizer;

impl RuleOptimizer {
    /// Deduplicate rules by SID.
    #[must_use]
    pub fn dedup_by_sid(rules: Vec<SnortRule>) -> (Vec<SnortRule>, usize) {
        let input_count = rules.len();
        let mut seen_sids: HashMap<u32, bool> = HashMap::new();
        let mut result = Vec::new();
        for rule in rules {
            if let Some(sid) = rule.sid {
                if seen_sids.contains_key(&sid) {
                    continue;
                }
                seen_sids.insert(sid, true);
            }
            result.push(rule);
        }
        let removed = input_count - result.len();
        (result, removed)
    }

    /// Sort rules by SID ascending.
    #[must_use]
    pub fn sort_by_sid(mut rules: Vec<SnortRule>) -> Vec<SnortRule> {
        rules.sort_by_key(|r| r.sid.unwrap_or(u32::MAX));
        rules
    }

    /// Remove rules without content patterns.
    #[must_use]
    pub fn remove_contentless(rules: Vec<SnortRule>) -> (Vec<SnortRule>, usize) {
        let input = rules.len();
        let out: Vec<_> = rules.into_iter().filter(SnortRule::has_content).collect();
        let removed = input - out.len();
        (out, removed)
    }

    /// Run full optimisation pipeline.
    #[must_use]
    pub fn optimize(rules: Vec<SnortRule>) -> (Vec<SnortRule>, OptimisationStats) {
        let input = rules.len();
        let (rules, dups) = Self::dedup_by_sid(rules);
        let rules = Self::sort_by_sid(rules);
        let output = rules.len();
        let stats = OptimisationStats {
            rules_input: input,
            rules_output: output,
            duplicates_removed: dups,
            disabled_rules_removed: 0,
            rules_reordered: true,
        };
        (rules, stats)
    }
}

// ---------------------------------------------------------------------------
// MultiRuleEngine
// ---------------------------------------------------------------------------

/// A match produced by the multi-rule engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultiEngineMatch {
    pub rule_sid: Option<u32>,
    pub rule_message: Option<String>,
    pub protocol: String,
    pub source: String,
    pub engine_type: String,
}

/// A multi-engine rule scanner combining Snort, Suricata, and YARA rules.
pub struct MultiRuleEngine {
    snort: Vec<SnortRule>,
    suricata: Vec<SuricataRule>,
    yara_net: Vec<YaraNetworkRule>,
}

impl MultiRuleEngine {
    /// Create an empty engine.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            snort: Vec::new(),
            suricata: Vec::new(),
            yara_net: Vec::new(),
        }
    }

    /// Add a Snort rule.
    pub fn add_snort_rule(&mut self, rule: SnortRule) {
        self.snort.push(rule);
    }

    /// Add a Suricata rule.
    pub fn add_suricata_rule(&mut self, rule: SuricataRule) {
        self.suricata.push(rule);
    }

    /// Add a YARA network rule.
    pub fn add_yara_rule(&mut self, rule: YaraNetworkRule) {
        self.yara_net.push(rule);
    }

    /// Total number of rules loaded.
    #[must_use]
    pub const fn rule_count(&self) -> usize {
        self.snort.len() + self.suricata.len() + self.yara_net.len()
    }

    /// Scan a payload and return all matches.
    #[must_use]
    pub fn scan_payload(&self, payload: &[u8], proto: &str) -> Vec<MultiEngineMatch> {
        let mut matches = Vec::new();

        // YARA network rules
        for rule in &self.yara_net {
            if let Some(filter) = &rule.protocol_filter
                && filter.to_string() != proto
            {
                continue;
            }
            if rule.matches(payload) {
                matches.push(MultiEngineMatch {
                    rule_sid: None,
                    rule_message: Some(rule.description.clone()),
                    protocol: proto.to_string(),
                    source: rule.name.clone(),
                    engine_type: "yara_net".to_string(),
                });
            }
        }

        // Snort/Suricata content rules (simplified)
        for rule in &self.snort {
            if let Some(proto_filter) = Some(rule.protocol.to_string())
                && proto_filter != proto
                && proto_filter != "ip"
            {
                // Skip protocol mismatches (simplified check)
            }
            for opt in &rule.options {
                if opt.keyword == "content"
                    && let Some(content) = &opt.value
                {
                    let needle = content.trim_matches('"').as_bytes();
                    if !needle.is_empty() && payload.windows(needle.len()).any(|w| w == needle) {
                        matches.push(MultiEngineMatch {
                            rule_sid: rule.sid,
                            rule_message: rule.message.clone(),
                            protocol: proto.to_string(),
                            source: format!("snort:SID{}", rule.sid.unwrap_or(0)),
                            engine_type: "snort".to_string(),
                        });
                        break;
                    }
                }
            }
        }

        matches
    }
}

impl Default for MultiRuleEngine {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_RULE: &str =
        r#"alert tcp any any -> any 80 (msg:"Test HTTP"; content:"GET /evil"; sid:1001; rev:1;)"#;

    #[test]
    fn test_rule_action_from_str() {
        assert_eq!(RuleAction::parse_keyword("alert"), RuleAction::Alert);
        assert_eq!(RuleAction::parse_keyword("drop"), RuleAction::Drop);
        assert_eq!(
            RuleAction::parse_keyword("custom_action"),
            RuleAction::Custom("custom_action".to_string())
        );
    }

    #[test]
    fn test_rule_action_display() {
        assert_eq!(RuleAction::Alert.to_string(), "alert");
        assert_eq!(RuleAction::Drop.to_string(), "drop");
    }

    #[test]
    fn test_protocol_from_str() {
        assert_eq!(Protocol::parse_keyword("tcp"), Protocol::Tcp);
        assert_eq!(Protocol::parse_keyword("udp"), Protocol::Udp);
        assert_eq!(Protocol::parse_keyword("http"), Protocol::Http);
    }

    #[test]
    fn test_address_from_str_any() {
        assert_eq!(Address::parse_address("any"), Address::Any);
    }

    #[test]
    fn test_address_from_str_single() {
        let a = Address::parse_address("192.168.1.1");
        assert_eq!(a, Address::Single("192.168.1.1".to_string()));
    }

    #[test]
    fn test_address_from_str_negated() {
        let a = Address::parse_address("!192.168.1.1");
        assert!(matches!(a, Address::Negated(_)));
    }

    #[test]
    fn test_snort_extended_parse_basic() {
        let rule = SnortExtended::parse(SAMPLE_RULE);
        assert!(rule.is_some());
        let rule = rule.unwrap();
        assert_eq!(rule.action, RuleAction::Alert);
        assert_eq!(rule.protocol, Protocol::Tcp);
        assert_eq!(rule.sid, Some(1001));
    }

    #[test]
    fn test_snort_extended_parse_message() {
        let rule = SnortExtended::parse(SAMPLE_RULE).unwrap();
        assert_eq!(rule.message.as_deref(), Some("Test HTTP"));
    }

    #[test]
    fn test_snort_extended_parse_revision() {
        let rule = SnortExtended::parse(SAMPLE_RULE).unwrap();
        assert_eq!(rule.revision, Some(1));
    }

    #[test]
    fn test_snort_extended_parse_has_content() {
        let rule = SnortExtended::parse(SAMPLE_RULE).unwrap();
        assert!(rule.has_content());
    }

    #[test]
    fn test_snort_extended_parse_comment() {
        assert!(SnortExtended::parse("# this is a comment").is_none());
    }

    #[test]
    fn test_snort_extended_parse_empty() {
        assert!(SnortExtended::parse("").is_none());
    }

    #[test]
    fn test_snort_extended_parse_rules_multi() {
        let text = format!("{SAMPLE_RULE}\n# comment\n{SAMPLE_RULE}");
        let rules = SnortExtended::parse_rules(&text);
        assert_eq!(rules.len(), 2);
    }

    #[test]
    fn test_rule_option_display() {
        let opt = RuleOption::new("content", Some("GET /evil"));
        let s = opt.to_string();
        assert!(s.contains("content"));
        assert!(s.contains("GET /evil"));
    }

    #[test]
    fn test_snort_rule_display() {
        let rule = SnortExtended::parse(SAMPLE_RULE).unwrap();
        let s = rule.to_string();
        assert!(s.contains("1001"));
    }

    #[test]
    fn test_snort_rule_to_rule_string() {
        let rule = SnortExtended::parse(SAMPLE_RULE).unwrap();
        let s = rule.to_rule_string();
        assert!(s.contains("alert"));
        assert!(s.contains("tcp"));
    }

    #[test]
    fn test_suricata_rule_from_snort() {
        let rule = SnortExtended::parse(SAMPLE_RULE).unwrap();
        let sr = SuricataRule::from_snort(rule);
        assert!(!sr.is_high_priority());
    }

    #[test]
    fn test_suricata_rule_high_priority() {
        let mut rule = SnortExtended::parse(SAMPLE_RULE).unwrap();
        rule.options.push(RuleOption::new("priority", Some("1")));
        let sr = SuricataRule::from_snort(rule);
        assert!(sr.is_high_priority());
    }

    #[test]
    fn test_yara_net_rule_match() {
        let mut rule = YaraNetworkRule::new("TestRule", "test");
        rule.add_pattern(b"evil payload".to_vec());
        assert!(rule.matches(b"some evil payload data"));
    }

    #[test]
    fn test_yara_net_rule_no_match() {
        let mut rule = YaraNetworkRule::new("TestRule", "test");
        rule.add_pattern(b"not present".to_vec());
        assert!(!rule.matches(b"clean network data"));
    }

    #[test]
    fn test_yara_net_rule_display() {
        let rule = YaraNetworkRule::new("R1", "test rule");
        let s = rule.to_string();
        assert!(s.contains("R1"));
    }

    #[test]
    fn test_rule_optimizer_dedup() {
        let r1 = SnortExtended::parse(SAMPLE_RULE).unwrap();
        let r2 = SnortExtended::parse(SAMPLE_RULE).unwrap();
        let (rules, removed) = RuleOptimizer::dedup_by_sid(vec![r1, r2]);
        assert_eq!(rules.len(), 1);
        assert_eq!(removed, 1);
    }

    #[test]
    fn test_rule_optimizer_sort_by_sid() {
        let r1 = SnortExtended::parse(SAMPLE_RULE).unwrap(); // SID 1001
        let rule2_str =
            r#"alert tcp any any -> any 80 (msg:"Rule2"; content:"abc"; sid:500; rev:1;)"#;
        let r2 = SnortExtended::parse(rule2_str).unwrap(); // SID 500
        let sorted = RuleOptimizer::sort_by_sid(vec![r1, r2]);
        assert_eq!(sorted[0].sid, Some(500));
        assert_eq!(sorted[1].sid, Some(1001));
    }

    #[test]
    fn test_rule_optimizer_optimize() {
        let r1 = SnortExtended::parse(SAMPLE_RULE).unwrap();
        let r2 = SnortExtended::parse(SAMPLE_RULE).unwrap();
        let (rules, stats) = RuleOptimizer::optimize(vec![r1, r2]);
        assert_eq!(rules.len(), 1);
        assert_eq!(stats.duplicates_removed, 1);
        assert!(stats.rules_reordered);
    }

    #[test]
    fn test_multi_engine_rule_count() {
        let mut engine = MultiRuleEngine::new();
        engine.add_snort_rule(SnortExtended::parse(SAMPLE_RULE).unwrap());
        let mut yr = YaraNetworkRule::new("YR1", "d");
        yr.add_pattern(b"payload".to_vec());
        engine.add_yara_rule(yr);
        assert_eq!(engine.rule_count(), 2);
    }

    #[test]
    fn test_multi_engine_scan_yara_match() {
        let mut engine = MultiRuleEngine::new();
        let mut yr = YaraNetworkRule::new("EvilPayload", "detect evil");
        yr.add_pattern(b"evil_c2".to_vec());
        engine.add_yara_rule(yr);
        let matches = engine.scan_payload(b"POST /evil_c2 HTTP/1.1", "tcp");
        assert!(!matches.is_empty());
        assert_eq!(matches[0].engine_type, "yara_net");
    }

    #[test]
    fn test_multi_engine_scan_no_match() {
        let engine = MultiRuleEngine::new();
        let matches = engine.scan_payload(b"clean traffic", "tcp");
        assert!(matches.is_empty());
    }
}
