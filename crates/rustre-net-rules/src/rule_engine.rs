//! `rule_engine` — Lightweight network rule engine.
//!
//! Provides [`RuleEngine`], [`NetworkRule`], [`RuleAction`], and
//! [`evaluate_packet`] for matching packets against a priority-ordered rule set.

use std::collections::HashMap;
use std::fmt;
use std::net::IpAddr;

// ─────────────────────────────────────────────────────────────────────────────
// RuleAction
// ─────────────────────────────────────────────────────────────────────────────

/// Action taken when a rule matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RuleAction {
    /// Generate an alert and continue evaluating.
    Alert,
    /// Pass the packet silently (no further evaluation).
    Pass,
    /// Drop the packet and stop evaluation.
    Drop,
    /// Log the packet and continue.
    Log,
    /// Reject with TCP RST / ICMP unreachable and stop.
    Reject,
}

impl fmt::Display for RuleAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Alert => write!(f, "alert"),
            Self::Pass => write!(f, "pass"),
            Self::Drop => write!(f, "drop"),
            Self::Log => write!(f, "log"),
            Self::Reject => write!(f, "reject"),
        }
    }
}

impl RuleAction {
    /// Return `true` if this action terminates rule evaluation.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Pass | Self::Drop | Self::Reject)
    }

    /// Return `true` if this action generates an observable event.
    #[must_use]
    pub const fn generates_event(self) -> bool {
        matches!(self, Self::Alert | Self::Log | Self::Drop | Self::Reject)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Protocol
// ─────────────────────────────────────────────────────────────────────────────

/// IP/transport protocol selector.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Protocol {
    Tcp,
    Udp,
    Icmp,
    Any,
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tcp => write!(f, "tcp"),
            Self::Udp => write!(f, "udp"),
            Self::Icmp => write!(f, "icmp"),
            Self::Any => write!(f, "any"),
        }
    }
}

impl Protocol {
    /// Return `true` if `ip_proto` satisfies this selector.
    #[must_use]
    pub const fn matches_ip_proto(self, ip_proto: u8) -> bool {
        match self {
            Self::Tcp => ip_proto == 6,
            Self::Udp => ip_proto == 17,
            Self::Icmp => ip_proto == 1,
            Self::Any => true,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PortRange
// ─────────────────────────────────────────────────────────────────────────────

/// A port specification (single, range, list, or any).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PortRange {
    Any,
    Single(u16),
    Range(u16, u16),
    List(Vec<u16>),
}

impl PortRange {
    /// Return `true` if `port` satisfies this range.
    #[must_use]
    pub fn matches(&self, port: u16) -> bool {
        match self {
            Self::Any => true,
            Self::Single(p) => *p == port,
            Self::Range(lo, hi) => port >= *lo && port <= *hi,
            Self::List(ps) => ps.contains(&port),
        }
    }
}

impl fmt::Display for PortRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Any => write!(f, "any"),
            Self::Single(p) => write!(f, "{p}"),
            Self::Range(lo, hi) => write!(f, "{lo}:{hi}"),
            Self::List(ps) => {
                write!(f, "[")?;
                for (i, p) in ps.iter().enumerate() {
                    if i > 0 { write!(f, ",")?; }
                    write!(f, "{p}")?;
                }
                write!(f, "]")
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// IpMatcher
// ─────────────────────────────────────────────────────────────────────────────

/// An IP address matcher (any, single, CIDR, or negated).
#[derive(Debug, Clone)]
pub enum IpMatcher {
    Any,
    Single(IpAddr),
    Cidr(IpAddr, u8),
    Not(Box<Self>),
    Group(Vec<Self>),
}

impl IpMatcher {
    /// Return `true` if `addr` matches.
    #[must_use]
    pub fn matches(&self, addr: IpAddr) -> bool {
        match self {
            Self::Any => true,
            Self::Single(a) => *a == addr,
            Self::Cidr(net, prefix) => cidr_match(*net, *prefix, addr),
            Self::Not(inner) => !inner.matches(addr),
            Self::Group(matchers) => matchers.iter().any(|m| m.matches(addr)),
        }
    }
}

fn cidr_match(net: IpAddr, prefix: u8, addr: IpAddr) -> bool {
    match (net, addr) {
        (IpAddr::V4(n), IpAddr::V4(a)) => {
            if prefix == 0 { return true; }
            if prefix > 32 { return false; }
            let mask = u32::MAX << (32 - prefix);
            (u32::from(n) & mask) == (u32::from(a) & mask)
        }
        (IpAddr::V6(n), IpAddr::V6(a)) => {
            if prefix == 0 { return true; }
            if prefix > 128 { return false; }
            let mask = u128::MAX << (128 - prefix);
            (u128::from(n) & mask) == (u128::from(a) & mask)
        }
        _ => false,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// RuleCondition
// ─────────────────────────────────────────────────────────────────────────────

/// A single condition within a network rule.
#[derive(Debug, Clone)]
pub enum RuleCondition {
    /// Payload contains the given byte pattern.
    ContentMatch(Vec<u8>),
    /// Payload size is within [min, max].
    PayloadSize { min: usize, max: usize },
    /// TCP flags must include the given bits.
    TcpFlags(u8),
    /// IP TTL must equal the value.
    Ttl(u8),
    /// Source port must match.
    SrcPort(PortRange),
    /// Destination port must match.
    DstPort(PortRange),
    /// Source IP must match.
    SrcIp(IpMatcher),
    /// Destination IP must match.
    DstIp(IpMatcher),
}

impl RuleCondition {
    /// Evaluate this condition against a [`PacketInfo`].
    #[must_use]
    pub fn evaluate(&self, pkt: &PacketInfo) -> bool {
        match self {
            Self::ContentMatch(pat) => {
                if pat.is_empty() {
                    return true;
                }
                pkt.payload.windows(pat.len()).any(|w| w == pat.as_slice())
            }
            Self::PayloadSize { min, max } => {
                pkt.payload.len() >= *min && pkt.payload.len() <= *max
            }
            Self::TcpFlags(flags) => pkt.tcp_flags & flags == *flags,
            Self::Ttl(t) => pkt.ttl == *t,
            Self::SrcPort(pr) => pr.matches(pkt.src_port),
            Self::DstPort(pr) => pr.matches(pkt.dst_port),
            Self::SrcIp(m) => m.matches(pkt.src_ip),
            Self::DstIp(m) => m.matches(pkt.dst_ip),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PacketInfo
// ─────────────────────────────────────────────────────────────────────────────

/// Decoded packet information passed to the rule engine.
#[derive(Debug, Clone)]
pub struct PacketInfo {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub ip_proto: u8,
    pub ttl: u8,
    pub tcp_flags: u8,
    pub payload: Vec<u8>,
}

impl PacketInfo {
    /// Create a minimal TCP packet info for testing.
    #[must_use]
    pub const fn new_tcp(src: IpAddr, dst: IpAddr, sport: u16, dport: u16, payload: Vec<u8>) -> Self {
        Self {
            src_ip: src,
            dst_ip: dst,
            src_port: sport,
            dst_port: dport,
            ip_proto: 6,
            ttl: 64,
            tcp_flags: 0,
            payload,
        }
    }

    /// Create a minimal UDP packet info.
    #[must_use]
    pub const fn new_udp(src: IpAddr, dst: IpAddr, sport: u16, dport: u16, payload: Vec<u8>) -> Self {
        Self {
            src_ip: src,
            dst_ip: dst,
            src_port: sport,
            dst_port: dport,
            ip_proto: 17,
            ttl: 64,
            tcp_flags: 0,
            payload,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// NetworkRule
// ─────────────────────────────────────────────────────────────────────────────

/// A complete network detection rule.
#[derive(Debug, Clone)]
pub struct NetworkRule {
    /// Unique rule ID (SID).
    pub id: u32,
    /// Priority (lower = evaluated first).
    pub priority: u32,
    /// Action taken on match.
    pub action: RuleAction,
    /// Protocol this rule applies to.
    pub proto: Protocol,
    /// Human-readable description.
    pub message: String,
    /// All conditions that must hold for the rule to match (AND logic).
    pub conditions: Vec<RuleCondition>,
    /// Whether the rule is active.
    pub enabled: bool,
    /// Optional revision number.
    pub revision: u32,
    /// Optional category string.
    pub category: Option<String>,
}

impl NetworkRule {
    /// Create a new rule with sensible defaults.
    #[must_use]
    pub fn new(id: u32, action: RuleAction, proto: Protocol, message: impl Into<String>) -> Self {
        Self {
            id,
            priority: 1,
            action,
            proto,
            message: message.into(),
            conditions: Vec::new(),
            enabled: true,
            revision: 1,
            category: None,
        }
    }

    /// Add a condition to this rule (builder pattern).
    #[must_use]
    pub fn with_condition(mut self, cond: RuleCondition) -> Self {
        self.conditions.push(cond);
        self
    }

    /// Set the priority (builder pattern).
    #[must_use]
    pub const fn with_priority(mut self, p: u32) -> Self {
        self.priority = p;
        self
    }

    /// Set the category (builder pattern).
    #[must_use]
    pub fn with_category(mut self, cat: impl Into<String>) -> Self {
        self.category = Some(cat.into());
        self
    }

    /// Return `true` if `pkt` satisfies all conditions of this rule.
    #[must_use]
    pub fn matches(&self, pkt: &PacketInfo) -> bool {
        if !self.enabled {
            return false;
        }
        if !self.proto.matches_ip_proto(pkt.ip_proto) {
            return false;
        }
        self.conditions.iter().all(|c| c.evaluate(pkt))
    }
}

impl fmt::Display for NetworkRule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{}] {} {} (sid:{}, rev:{})",
            self.action, self.proto, self.message, self.id, self.revision
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// RuleMatchResult
// ─────────────────────────────────────────────────────────────────────────────

/// The result of evaluating a packet against a single rule.
#[derive(Debug, Clone)]
pub struct RuleMatchResult {
    pub rule_id: u32,
    pub action: RuleAction,
    pub message: String,
    pub priority: u32,
}

impl fmt::Display for RuleMatchResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "MATCH(sid={}, action={}, msg=\"{}\")",
            self.rule_id, self.action, self.message
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// evaluate_packet
// ─────────────────────────────────────────────────────────────────────────────

/// Evaluate `pkt` against all rules in `rules` (pre-sorted by priority).
///
/// Returns all matching results.  Stops after the first terminal action
/// (Pass / Drop / Reject).
#[must_use]
pub fn evaluate_packet(pkt: &PacketInfo, rules: &[NetworkRule]) -> Vec<RuleMatchResult> {
    let mut results = Vec::new();
    for rule in rules {
        if rule.matches(pkt) {
            let res = RuleMatchResult {
                rule_id: rule.id,
                action: rule.action,
                message: rule.message.clone(),
                priority: rule.priority,
            };
            let terminal = res.action.is_terminal();
            results.push(res);
            if terminal {
                break;
            }
        }
    }
    results
}

// ─────────────────────────────────────────────────────────────────────────────
// RuleEngine
// ─────────────────────────────────────────────────────────────────────────────

/// Stateful rule engine that stores rules and accumulates statistics.
pub struct RuleEngine {
    /// All rules, sorted by priority after each insertion.
    rules: Vec<NetworkRule>,
    /// Hit counters per rule ID.
    hit_counts: HashMap<u32, u64>,
    /// Total packets evaluated.
    packets_evaluated: u64,
    /// Total matches (any action).
    total_matches: u64,
}

impl RuleEngine {
    /// Create an empty rule engine.
    #[must_use]
    pub fn new() -> Self {
        Self {
            rules: Vec::new(),
            hit_counts: HashMap::new(),
            packets_evaluated: 0,
            total_matches: 0,
        }
    }

    /// Add a rule.  The internal list is kept sorted by `priority` ascending.
    pub fn add_rule(&mut self, rule: NetworkRule) {
        self.rules.push(rule);
        self.rules.sort_by_key(|r| r.priority);
    }

    /// Remove a rule by ID.  Returns `true` if a rule was found and removed.
    pub fn remove_rule(&mut self, id: u32) -> bool {
        let before = self.rules.len();
        self.rules.retain(|r| r.id != id);
        self.rules.len() < before
    }

    /// Enable or disable a rule by ID.
    pub fn set_enabled(&mut self, id: u32, enabled: bool) {
        for r in &mut self.rules {
            if r.id == id {
                r.enabled = enabled;
            }
        }
    }

    /// Evaluate `pkt` and return all matching results.
    pub fn evaluate(&mut self, pkt: &PacketInfo) -> Vec<RuleMatchResult> {
        self.packets_evaluated += 1;
        let results = evaluate_packet(pkt, &self.rules);
        for res in &results {
            *self.hit_counts.entry(res.rule_id).or_insert(0) += 1;
            self.total_matches += 1;
        }
        results
    }

    /// Return the first result from evaluating `pkt`, if any.
    pub fn evaluate_first(&mut self, pkt: &PacketInfo) -> Option<RuleMatchResult> {
        self.evaluate(pkt).into_iter().next()
    }

    /// Return the hit count for a rule.
    #[must_use]
    pub fn hit_count(&self, id: u32) -> u64 {
        self.hit_counts.get(&id).copied().unwrap_or(0)
    }

    /// Return the total number of packets evaluated.
    #[must_use]
    pub const fn packets_evaluated(&self) -> u64 {
        self.packets_evaluated
    }

    /// Return the total number of rule matches.
    #[must_use]
    pub const fn total_matches(&self) -> u64 {
        self.total_matches
    }

    /// Return a slice of all rules.
    #[must_use]
    pub fn rules(&self) -> &[NetworkRule] {
        &self.rules
    }

    /// Return the number of rules currently loaded.
    #[must_use]
    pub const fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// Return rules in a specific category.
    #[must_use]
    pub fn rules_by_category(&self, cat: &str) -> Vec<&NetworkRule> {
        self.rules
            .iter()
            .filter(|r| r.category.as_deref() == Some(cat))
            .collect()
    }

    /// Clear all accumulated statistics.
    pub fn reset_stats(&mut self) {
        self.hit_counts.clear();
        self.packets_evaluated = 0;
        self.total_matches = 0;
    }
}

impl Default for RuleEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for RuleEngine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RuleEngine")
            .field("rules", &self.rules.len())
            .field("packets_evaluated", &self.packets_evaluated)
            .field("total_matches", &self.total_matches)
            .finish_non_exhaustive()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn loopback_tcp(payload: Vec<u8>) -> PacketInfo {
        PacketInfo::new_tcp(
            "127.0.0.1".parse().unwrap(),
            "127.0.0.1".parse().unwrap(),
            12345,
            80,
            payload,
        )
    }

    fn simple_alert_rule(id: u32, pattern: Vec<u8>) -> NetworkRule {
        NetworkRule::new(id, RuleAction::Alert, Protocol::Tcp, "test alert")
            .with_condition(RuleCondition::ContentMatch(pattern))
    }

    #[test]
    fn rule_matches_content() {
        let rule = simple_alert_rule(1, b"evil".to_vec());
        let pkt = loopback_tcp(b"GET /evil HTTP/1.1".to_vec());
        assert!(rule.matches(&pkt));
    }

    #[test]
    fn rule_no_match_wrong_proto() {
        let rule = NetworkRule::new(2, RuleAction::Alert, Protocol::Udp, "udp-only");
        let pkt = loopback_tcp(b"data".to_vec());
        assert!(!rule.matches(&pkt));
    }

    #[test]
    fn rule_disabled_never_matches() {
        let mut rule = simple_alert_rule(3, b"test".to_vec());
        rule.enabled = false;
        let pkt = loopback_tcp(b"test".to_vec());
        assert!(!rule.matches(&pkt));
    }

    #[test]
    fn evaluate_packet_returns_matches() {
        let rules = vec![
            simple_alert_rule(1, b"evil".to_vec()),
            simple_alert_rule(2, b"bad".to_vec()),
        ];
        let pkt = loopback_tcp(b"evil and bad payload".to_vec());
        let results = evaluate_packet(&pkt, &rules);
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn evaluate_packet_terminal_stops_early() {
        let drop_rule = NetworkRule::new(1, RuleAction::Drop, Protocol::Any, "drop all")
            .with_priority(1);
        let alert_rule = NetworkRule::new(2, RuleAction::Alert, Protocol::Any, "alert all")
            .with_priority(2);
        let rules = vec![drop_rule, alert_rule];
        let pkt = loopback_tcp(b"anything".to_vec());
        let results = evaluate_packet(&pkt, &rules);
        // Drop is terminal; only 1 result.
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].action, RuleAction::Drop);
    }

    #[test]
    fn rule_engine_add_and_evaluate() {
        let mut engine = RuleEngine::new();
        engine.add_rule(simple_alert_rule(1, b"malware".to_vec()));
        let pkt = loopback_tcp(b"download malware here".to_vec());
        let results = engine.evaluate(&pkt);
        assert_eq!(results.len(), 1);
        assert_eq!(engine.hit_count(1), 1);
        assert_eq!(engine.packets_evaluated(), 1);
    }

    #[test]
    fn rule_engine_remove_rule() {
        let mut engine = RuleEngine::new();
        engine.add_rule(simple_alert_rule(1, b"x".to_vec()));
        assert_eq!(engine.rule_count(), 1);
        let removed = engine.remove_rule(1);
        assert!(removed);
        assert_eq!(engine.rule_count(), 0);
    }

    #[test]
    fn rule_engine_set_enabled() {
        let mut engine = RuleEngine::new();
        engine.add_rule(simple_alert_rule(1, b"test".to_vec()));
        engine.set_enabled(1, false);
        let pkt = loopback_tcp(b"test".to_vec());
        let results = engine.evaluate(&pkt);
        assert!(results.is_empty());
    }

    #[test]
    fn rule_engine_reset_stats() {
        let mut engine = RuleEngine::new();
        engine.add_rule(simple_alert_rule(1, b"x".to_vec()));
        engine.evaluate(&loopback_tcp(b"x".to_vec()));
        engine.reset_stats();
        assert_eq!(engine.packets_evaluated(), 0);
        assert_eq!(engine.total_matches(), 0);
    }

    #[test]
    fn condition_payload_size() {
        let cond = RuleCondition::PayloadSize { min: 10, max: 100 };
        let pkt = loopback_tcp(vec![0u8; 50]);
        assert!(cond.evaluate(&pkt));
        let small = loopback_tcp(vec![0u8; 5]);
        assert!(!cond.evaluate(&small));
    }

    #[test]
    fn condition_ttl() {
        let cond = RuleCondition::Ttl(128);
        let mut pkt = loopback_tcp(b"data".to_vec());
        pkt.ttl = 128;
        assert!(cond.evaluate(&pkt));
        pkt.ttl = 64;
        assert!(!cond.evaluate(&pkt));
    }

    #[test]
    fn condition_src_port_range() {
        let cond = RuleCondition::SrcPort(PortRange::Range(1024, 65535));
        let pkt = loopback_tcp(b"hi".to_vec()); // src_port = 12345
        assert!(cond.evaluate(&pkt));
    }

    #[test]
    fn ip_matcher_cidr() {
        let net: IpAddr = "192.168.1.0".parse().unwrap();
        let m = IpMatcher::Cidr(net, 24);
        assert!(m.matches("192.168.1.100".parse().unwrap()));
        assert!(!m.matches("192.168.2.1".parse().unwrap()));
    }

    #[test]
    fn ip_matcher_not() {
        let m = IpMatcher::Not(Box::new(IpMatcher::Single("10.0.0.1".parse().unwrap())));
        assert!(m.matches("10.0.0.2".parse().unwrap()));
        assert!(!m.matches("10.0.0.1".parse().unwrap()));
    }

    #[test]
    fn rule_action_terminal() {
        assert!(RuleAction::Drop.is_terminal());
        assert!(RuleAction::Pass.is_terminal());
        assert!(!RuleAction::Alert.is_terminal());
        assert!(!RuleAction::Log.is_terminal());
    }

    #[test]
    fn rule_action_generates_event() {
        assert!(RuleAction::Alert.generates_event());
        assert!(!RuleAction::Pass.generates_event());
    }

    #[test]
    fn rule_display() {
        let r = NetworkRule::new(42, RuleAction::Alert, Protocol::Tcp, "test");
        let s = r.to_string();
        assert!(s.contains("alert"));
        assert!(s.contains("sid:42"));
    }

    #[test]
    fn protocol_matches_ip_proto() {
        assert!(Protocol::Tcp.matches_ip_proto(6));
        assert!(!Protocol::Tcp.matches_ip_proto(17));
        assert!(Protocol::Any.matches_ip_proto(99));
    }

    #[test]
    fn port_range_list() {
        let pr = PortRange::List(vec![80, 443, 8080]);
        assert!(pr.matches(80));
        assert!(pr.matches(443));
        assert!(!pr.matches(22));
    }

    #[test]
    fn rules_sorted_by_priority() {
        let mut engine = RuleEngine::new();
        engine.add_rule(simple_alert_rule(2, b"b".to_vec()).with_priority(10));
        engine.add_rule(simple_alert_rule(1, b"a".to_vec()).with_priority(1));
        assert_eq!(engine.rules()[0].id, 1);
        assert_eq!(engine.rules()[1].id, 2);
    }

    #[test]
    fn rule_engine_by_category() {
        let mut engine = RuleEngine::new();
        engine.add_rule(
            simple_alert_rule(1, b"a".to_vec()).with_category("malware"),
        );
        engine.add_rule(simple_alert_rule(2, b"b".to_vec()).with_category("recon"));
        let malware = engine.rules_by_category("malware");
        assert_eq!(malware.len(), 1);
        assert_eq!(malware[0].id, 1);
    }
}
