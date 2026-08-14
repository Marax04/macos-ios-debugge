//! `rule_engine_full` — Complete network rule engine.
//!
//! Provides [`RuleEngineFull`] which hosts a [`RuleSet`], compiles rules via
//! [`RuleCompiler`], matches packets through [`RuleMatcher`], and produces
//! [`MatchResult`]s.  [`RuleStats`] aggregates per-rule counters and
//! [`RuleDebugger`] provides a textual trace of the matching process.

use std::collections::HashMap;
use std::fmt;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use parking_lot::{Mutex, RwLock};
use serde::{Deserialize, Serialize};
use thiserror::Error;

// ─── Error ────────────────────────────────────────────────────────────────────

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum RuleFullError {
    #[error("parse error: {0}")]
    ParseError(String),
    #[error("duplicate rule id: {0}")]
    DuplicateId(u32),
    #[error("rule not found: {0}")]
    NotFound(u32),
    #[error("compile error: {0}")]
    CompileError(String),
    #[error("invalid field: {0}")]
    InvalidField(String),
    #[error("rule set is locked")]
    Locked,
    #[error("too many rules: max {0}")]
    TooManyRules(usize),
}

// ─── RuleAction ───────────────────────────────────────────────────────────────

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
        write!(f, "{self:?}")
    }
}

// ─── Protocol ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Protocol {
    Tcp,
    Udp,
    Icmp,
    Any,
}

impl Protocol {
    #[must_use]
    pub const fn matches(self, proto: u8) -> bool {
        match self {
            Self::Tcp => proto == 6,
            Self::Udp => proto == 17,
            Self::Icmp => proto == 1,
            Self::Any => true,
        }
    }
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

// ─── PortSpec ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PortSpec {
    Any,
    Single(u16),
    Range(u16, u16),
    List(Vec<u16>),
    Negated(Box<Self>),
}

impl PortSpec {
    #[must_use]
    pub fn matches(&self, port: u16) -> bool {
        match self {
            Self::Any => true,
            Self::Single(p) => *p == port,
            Self::Range(lo, hi) => port >= *lo && port <= *hi,
            Self::List(v) => v.contains(&port),
            Self::Negated(inner) => !inner.matches(port),
        }
    }
}

// ─── IpSpec ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum IpSpec {
    Any,
    Host(Ipv4Addr),
    Net(Ipv4Addr, u8),
    Negated(Box<Self>),
    List(Vec<Self>),
}

impl IpSpec {
    #[must_use]
    pub fn matches(&self, addr: Ipv4Addr) -> bool {
        match self {
            Self::Any => true,
            Self::Host(h) => *h == addr,
            Self::Net(network, prefix) => {
                let mask: u32 = if *prefix == 0 {
                    0
                } else {
                    !0u32 << (32 - prefix)
                };
                let net = u32::from(*network) & mask;
                u32::from(addr) & mask == net
            }
            Self::Negated(inner) => !inner.matches(addr),
            Self::List(specs) => specs.iter().any(|s| s.matches(addr)),
        }
    }
}

// ─── ContentOption ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ContentOption {
    Contains(Vec<u8>),
    NotContains(Vec<u8>),
    Pcre(String),
    Offset(usize),
    Depth(usize),
    Nocase,
}

// ─── Rule ─────────────────────────────────────────────────────────────────────

/// A single detection rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub id: u32,
    pub action: RuleAction,
    pub protocol: Protocol,
    pub src_ip: IpSpec,
    pub src_port: PortSpec,
    pub dst_ip: IpSpec,
    pub dst_port: PortSpec,
    pub msg: String,
    pub content: Vec<ContentOption>,
    pub enabled: bool,
    pub priority: u8,
    pub metadata: HashMap<String, String>,
}

impl Rule {
    pub fn new(id: u32, action: RuleAction, protocol: Protocol, msg: impl Into<String>) -> Self {
        Self {
            id,
            action,
            protocol,
            src_ip: IpSpec::Any,
            src_port: PortSpec::Any,
            dst_ip: IpSpec::Any,
            dst_port: PortSpec::Any,
            msg: msg.into(),
            content: Vec::new(),
            enabled: true,
            priority: 2,
            metadata: HashMap::new(),
        }
    }

    #[must_use]
    pub fn with_src(mut self, ip: IpSpec, port: PortSpec) -> Self {
        self.src_ip = ip;
        self.src_port = port;
        self
    }

    #[must_use]
    pub fn with_dst(mut self, ip: IpSpec, port: PortSpec) -> Self {
        self.dst_ip = ip;
        self.dst_port = port;
        self
    }

    pub fn add_content(&mut self, opt: ContentOption) {
        self.content.push(opt);
    }

    pub const fn disable(&mut self) {
        self.enabled = false;
    }

    pub const fn enable(&mut self) {
        self.enabled = true;
    }
}

impl fmt::Display for Rule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{}] {} {} id={} msg=\"{}\"",
            self.id, self.action, self.protocol, self.id, self.msg
        )
    }
}

// ─── RuleSet ──────────────────────────────────────────────────────────────────

/// An ordered, indexed collection of [`Rule`]s.
#[derive(Debug, Default)]
pub struct RuleSet {
    rules: Vec<Rule>,
    index: HashMap<u32, usize>,
    max_rules: usize,
    locked: bool,
}

impl RuleSet {
    #[must_use]
    pub fn new(max_rules: usize) -> Self {
        Self {
            rules: Vec::new(),
            index: HashMap::new(),
            max_rules,
            locked: false,
        }
    }

    /// Add a rule to the set.
    ///
    /// # Errors
    /// Returns [`RuleFullError::Locked`] if the set is locked, [`RuleFullError::TooManyRules`]
    /// if the capacity is exhausted, or [`RuleFullError::DuplicateId`] if the rule id is already present.
    pub fn add(&mut self, rule: Rule) -> Result<(), RuleFullError> {
        if self.locked {
            return Err(RuleFullError::Locked);
        }
        if self.rules.len() >= self.max_rules {
            return Err(RuleFullError::TooManyRules(self.max_rules));
        }
        if self.index.contains_key(&rule.id) {
            return Err(RuleFullError::DuplicateId(rule.id));
        }
        let pos = self.rules.len();
        self.index.insert(rule.id, pos);
        self.rules.push(rule);
        Ok(())
    }

    /// Remove a rule by id.
    ///
    /// # Errors
    /// Returns [`RuleFullError::Locked`] if the set is locked, or [`RuleFullError::NotFound`]
    /// when no rule matches `id`.
    pub fn remove(&mut self, id: u32) -> Result<Rule, RuleFullError> {
        if self.locked {
            return Err(RuleFullError::Locked);
        }
        let pos = self.index.remove(&id).ok_or(RuleFullError::NotFound(id))?;
        let rule = self.rules.remove(pos);
        // Re-index
        self.index.clear();
        for (i, r) in self.rules.iter().enumerate() {
            self.index.insert(r.id, i);
        }
        Ok(rule)
    }

    #[must_use]
    pub fn get(&self, id: u32) -> Option<&Rule> {
        self.index.get(&id).and_then(|&pos| self.rules.get(pos))
    }

    pub fn get_mut(&mut self, id: u32) -> Option<&mut Rule> {
        self.index
            .get(&id)
            .copied()
            .and_then(|pos| self.rules.get_mut(pos))
    }

    #[must_use]
    pub fn all(&self) -> &[Rule] {
        &self.rules
    }

    pub fn enabled(&self) -> impl Iterator<Item = &Rule> {
        self.rules.iter().filter(|r| r.enabled)
    }

    #[must_use]
    pub const fn count(&self) -> usize {
        self.rules.len()
    }

    pub const fn lock(&mut self) {
        self.locked = true;
    }

    pub const fn unlock(&mut self) {
        self.locked = false;
    }
}

// ─── CompiledRule ─────────────────────────────────────────────────────────────

/// A pre-processed rule with fast-path content matchers.
#[derive(Debug, Clone)]
pub struct CompiledRule {
    pub rule_id: u32,
    pub action: RuleAction,
    pub protocol: Protocol,
    pub src_ip: IpSpec,
    pub src_port: PortSpec,
    pub dst_ip: IpSpec,
    pub dst_port: PortSpec,
    pub content_patterns: Vec<Vec<u8>>,
    pub neg_patterns: Vec<Vec<u8>>,
    pub msg: String,
    pub priority: u8,
}

impl CompiledRule {
    #[must_use]
    pub const fn fast_match_proto(&self, proto: u8) -> bool {
        self.protocol.matches(proto)
    }
}

// ─── RuleCompiler ─────────────────────────────────────────────────────────────

/// Converts a [`RuleSet`] into a list of [`CompiledRule`]s for fast matching.
#[derive(Debug, Default)]
pub struct RuleCompiler;

impl RuleCompiler {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Compile every enabled rule in `rule_set`.
    ///
    /// # Errors
    /// Propagates any [`RuleFullError`] returned by [`Self::compile_rule`].
    pub fn compile_set(&self, rule_set: &RuleSet) -> Result<Vec<CompiledRule>, RuleFullError> {
        rule_set.enabled().map(|r| self.compile_rule(r)).collect()
    }

    /// Compile a single rule.
    ///
    /// # Errors
    /// Returns a [`RuleFullError`] when content patterns or conditions are malformed.
    pub fn compile_rule(&self, rule: &Rule) -> Result<CompiledRule, RuleFullError> {
        let mut content_patterns = Vec::with_capacity(rule.content.len());
        let mut neg_patterns = Vec::with_capacity(rule.content.len());
        for opt in &rule.content {
            match opt {
                ContentOption::Contains(p) => content_patterns.push(p.clone()),
                ContentOption::NotContains(p) => neg_patterns.push(p.clone()),
                _ => {}
            }
        }
        Ok(CompiledRule {
            rule_id: rule.id,
            action: rule.action,
            protocol: rule.protocol,
            src_ip: rule.src_ip.clone(),
            src_port: rule.src_port.clone(),
            dst_ip: rule.dst_ip.clone(),
            dst_port: rule.dst_port.clone(),
            content_patterns,
            neg_patterns,
            msg: rule.msg.clone(),
            priority: rule.priority,
        })
    }
}

// ─── PacketInfo ───────────────────────────────────────────────────────────────

/// Minimal packet descriptor used by the rule matcher.
#[derive(Debug, Clone)]
pub struct PacketInfo {
    pub proto: u8,
    pub src_ip: Ipv4Addr,
    pub dst_ip: Ipv4Addr,
    pub src_port: u16,
    pub dst_port: u16,
    pub payload: Vec<u8>,
}

impl PacketInfo {
    #[must_use]
    pub const fn tcp(src: Ipv4Addr, sp: u16, dst: Ipv4Addr, dp: u16, payload: Vec<u8>) -> Self {
        Self {
            proto: 6,
            src_ip: src,
            dst_ip: dst,
            src_port: sp,
            dst_port: dp,
            payload,
        }
    }

    #[must_use]
    pub const fn udp(src: Ipv4Addr, sp: u16, dst: Ipv4Addr, dp: u16) -> Self {
        Self {
            proto: 17,
            src_ip: src,
            dst_ip: dst,
            src_port: sp,
            dst_port: dp,
            payload: vec![],
        }
    }
}

// ─── MatchResult ──────────────────────────────────────────────────────────────

/// Result of matching a packet against the rule set.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchResult {
    pub rule_id: u32,
    pub action: RuleAction,
    pub msg: String,
    pub priority: u8,
}

impl MatchResult {
    #[must_use]
    pub fn is_alert(&self) -> bool {
        self.action == RuleAction::Alert
    }

    #[must_use]
    pub fn is_drop(&self) -> bool {
        self.action == RuleAction::Drop
    }
}

// ─── RuleMatcher ──────────────────────────────────────────────────────────────

/// Runs compiled rules against packets.
#[derive(Debug)]
pub struct RuleMatcher {
    rules: Vec<CompiledRule>,
}

impl RuleMatcher {
    #[must_use]
    pub fn new(rules: Vec<CompiledRule>) -> Self {
        let mut sorted = rules;
        sorted.sort_by_key(|r| r.priority);
        Self { rules: sorted }
    }

    #[must_use]
    pub fn match_packet(&self, pkt: &PacketInfo) -> Vec<MatchResult> {
        self.rules
            .iter()
            .filter(|r| Self::rule_matches(r, pkt))
            .map(|r| MatchResult {
                rule_id: r.rule_id,
                action: r.action,
                msg: r.msg.clone(),
                priority: r.priority,
            })
            .collect()
    }

    #[must_use]
    pub fn first_match(&self, pkt: &PacketInfo) -> Option<MatchResult> {
        self.rules
            .iter()
            .find(|r| Self::rule_matches(r, pkt))
            .map(|r| MatchResult {
                rule_id: r.rule_id,
                action: r.action,
                msg: r.msg.clone(),
                priority: r.priority,
            })
    }

    fn rule_matches(rule: &CompiledRule, pkt: &PacketInfo) -> bool {
        if !rule.fast_match_proto(pkt.proto) {
            return false;
        }
        if !rule.src_ip.matches(pkt.src_ip) {
            return false;
        }
        if !rule.src_port.matches(pkt.src_port) {
            return false;
        }
        if !rule.dst_ip.matches(pkt.dst_ip) {
            return false;
        }
        if !rule.dst_port.matches(pkt.dst_port) {
            return false;
        }
        // Content patterns: all must be present
        for pat in &rule.content_patterns {
            if !pkt.payload.windows(pat.len()).any(|w| w == pat.as_slice()) {
                return false;
            }
        }
        // Neg patterns: none must be present
        for pat in &rule.neg_patterns {
            if pkt.payload.windows(pat.len()).any(|w| w == pat.as_slice()) {
                return false;
            }
        }
        true
    }

    #[must_use]
    pub const fn rule_count(&self) -> usize {
        self.rules.len()
    }
}

// ─── RuleStats ────────────────────────────────────────────────────────────────

/// Per-rule counters for matches and non-matches.
#[derive(Debug, Default)]
pub struct RuleStats {
    matches: Mutex<HashMap<u32, u64>>,
    misses: Mutex<HashMap<u32, u64>>,
    total_packets: AtomicU64,
    total_matches: AtomicU64,
}

impl RuleStats {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record_match(&self, rule_id: u32) {
        *self.matches.lock().entry(rule_id).or_insert(0) += 1;
        self.total_matches.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_miss(&self, rule_id: u32) {
        *self.misses.lock().entry(rule_id).or_insert(0) += 1;
    }

    pub fn record_packet(&self) {
        self.total_packets.fetch_add(1, Ordering::Relaxed);
    }

    pub fn match_count(&self, rule_id: u32) -> u64 {
        self.matches.lock().get(&rule_id).copied().unwrap_or(0)
    }

    pub fn miss_count(&self, rule_id: u32) -> u64 {
        self.misses.lock().get(&rule_id).copied().unwrap_or(0)
    }

    pub fn total_packets(&self) -> u64 {
        self.total_packets.load(Ordering::Relaxed)
    }

    pub fn total_matches(&self) -> u64 {
        self.total_matches.load(Ordering::Relaxed)
    }

    pub fn top_rules(&self, n: usize) -> Vec<(u32, u64)> {
        let mut v: Vec<(u32, u64)> = self.matches.lock().iter().map(|(&k, &v)| (k, v)).collect();
        v.sort_by(|a, b| b.1.cmp(&a.1));
        v.truncate(n);
        v
    }

    pub fn match_rate(&self) -> f64 {
        let total = self.total_packets();
        if total == 0 {
            0.0
        } else {
            let numer = u32::try_from(self.total_matches()).unwrap_or(u32::MAX);
            let denom = u32::try_from(total).unwrap_or(u32::MAX);
            f64::from(numer) / f64::from(denom)
        }
    }
}

// ─── RuleDebugger ─────────────────────────────────────────────────────────────

/// Records a detailed trace of rule evaluation steps.
#[derive(Debug, Default)]
pub struct RuleDebugger {
    entries: Mutex<Vec<DebugEntry>>,
    enabled: bool,
}

#[derive(Debug, Clone)]
pub struct DebugEntry {
    pub rule_id: u32,
    pub step: String,
    pub result: bool,
}

impl RuleDebugger {
    #[must_use]
    pub const fn new(enabled: bool) -> Self {
        Self {
            entries: Mutex::new(Vec::new()),
            enabled,
        }
    }

    pub fn log(&self, rule_id: u32, step: impl Into<String>, result: bool) {
        if self.enabled {
            self.entries.lock().push(DebugEntry {
                rule_id,
                step: step.into(),
                result,
            });
        }
    }

    pub fn entries(&self) -> Vec<DebugEntry> {
        self.entries.lock().clone()
    }

    pub fn clear(&self) {
        self.entries.lock().clear();
    }

    pub const fn is_enabled(&self) -> bool {
        self.enabled
    }

    pub fn format(&self) -> String {
        self.entries
            .lock()
            .iter()
            .map(|e| format!("rule={} step=\"{}\" result={}", e.rule_id, e.step, e.result))
            .collect::<Vec<_>>()
            .join("\n")
    }
}

// ─── RuleEngineFull ───────────────────────────────────────────────────────────

/// Complete rule engine orchestrating compilation, matching, stats, and debug.
#[derive(Debug)]
pub struct RuleEngineFull {
    rule_set: RwLock<RuleSet>,
    matcher: RwLock<Option<RuleMatcher>>,
    stats: Arc<RuleStats>,
    debugger: Arc<RuleDebugger>,
    compiled: RwLock<bool>,
}

impl RuleEngineFull {
    #[must_use]
    pub fn new() -> Self {
        Self {
            rule_set: RwLock::new(RuleSet::new(65536)),
            matcher: RwLock::new(None),
            stats: Arc::new(RuleStats::new()),
            debugger: Arc::new(RuleDebugger::new(false)),
            compiled: RwLock::new(false),
        }
    }

    #[must_use]
    pub fn with_debug() -> Self {
        Self {
            rule_set: RwLock::new(RuleSet::new(65536)),
            matcher: RwLock::new(None),
            stats: Arc::new(RuleStats::new()),
            debugger: Arc::new(RuleDebugger::new(true)),
            compiled: RwLock::new(false),
        }
    }

    // ── Rule management ───────────────────────────────────────────────────

    /// Add a rule.
    ///
    /// # Errors
    /// Propagates [`RuleSet::add`] errors such as duplicate id or capacity exhaustion.
    pub fn add_rule(&self, rule: Rule) -> Result<(), RuleFullError> {
        self.rule_set.write().add(rule)?;
        *self.compiled.write() = false;
        Ok(())
    }

    /// Remove a rule by id.
    ///
    /// # Errors
    /// Returns [`RuleFullError::NotFound`] when no rule has the given id.
    pub fn remove_rule(&self, id: u32) -> Result<Rule, RuleFullError> {
        let r = self.rule_set.write().remove(id)?;
        *self.compiled.write() = false;
        Ok(r)
    }

    /// Disable a rule by id.
    ///
    /// # Errors
    /// Returns [`RuleFullError::NotFound`] when no rule has the given id.
    pub fn disable_rule(&self, id: u32) -> Result<(), RuleFullError> {
        self.rule_set
            .write()
            .get_mut(id)
            .ok_or(RuleFullError::NotFound(id))?
            .disable();
        *self.compiled.write() = false;
        Ok(())
    }

    /// Enable a rule by id.
    ///
    /// # Errors
    /// Returns [`RuleFullError::NotFound`] when no rule has the given id.
    pub fn enable_rule(&self, id: u32) -> Result<(), RuleFullError> {
        self.rule_set
            .write()
            .get_mut(id)
            .ok_or(RuleFullError::NotFound(id))?
            .enable();
        *self.compiled.write() = false;
        Ok(())
    }

    pub fn rule_count(&self) -> usize {
        self.rule_set.read().count()
    }

    // ── Compilation ───────────────────────────────────────────────────────

    /// Compile every enabled rule into the matcher.
    ///
    /// # Errors
    /// Propagates compilation errors from [`RuleCompiler::compile_set`].
    pub fn compile(&self) -> Result<(), RuleFullError> {
        let compiler = RuleCompiler::new();
        let compiled_rules = compiler.compile_set(&self.rule_set.read())?;
        *self.matcher.write() = Some(RuleMatcher::new(compiled_rules));
        *self.compiled.write() = true;
        Ok(())
    }

    pub fn is_compiled(&self) -> bool {
        *self.compiled.read()
    }

    // ── Matching ──────────────────────────────────────────────────────────

    pub fn process_packet(&self, pkt: &PacketInfo) -> Vec<MatchResult> {
        self.stats.record_packet();
        let matcher_guard = self.matcher.read();
        let results = {
            let Some(m) = matcher_guard.as_ref() else {
                drop(matcher_guard);
                return vec![];
            };
            m.match_packet(pkt)
        };
        drop(matcher_guard);
        for r in &results {
            self.stats.record_match(r.rule_id);
            self.debugger.log(r.rule_id, "matched", true);
        }
        results
    }

    pub fn process_batch(&self, packets: &[PacketInfo]) -> Vec<Vec<MatchResult>> {
        packets.iter().map(|p| self.process_packet(p)).collect()
    }

    // ── Stats / Debug ─────────────────────────────────────────────────────

    pub fn stats(&self) -> &RuleStats {
        &self.stats
    }

    pub fn debugger(&self) -> &RuleDebugger {
        &self.debugger
    }
}

impl Default for RuleEngineFull {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    fn make_tcp_pkt() -> PacketInfo {
        PacketInfo::tcp(
            ip("10.0.0.1"),
            54321,
            ip("10.0.0.2"),
            80,
            b"GET / HTTP/1.1".to_vec(),
        )
    }

    fn make_alert_rule(id: u32) -> Rule {
        Rule::new(
            id,
            RuleAction::Alert,
            Protocol::Tcp,
            format!("Test alert {id}"),
        )
    }

    // --- PortSpec ---

    #[test]
    fn test_port_spec_any() {
        assert!(PortSpec::Any.matches(1));
        assert!(PortSpec::Any.matches(65535));
    }

    #[test]
    fn test_port_spec_single() {
        assert!(PortSpec::Single(80).matches(80));
        assert!(!PortSpec::Single(80).matches(443));
    }

    #[test]
    fn test_port_spec_range() {
        let spec = PortSpec::Range(1024, 65535);
        assert!(spec.matches(8080));
        assert!(!spec.matches(80));
    }

    #[test]
    fn test_port_spec_list() {
        let spec = PortSpec::List(vec![80, 443, 8080]);
        assert!(spec.matches(443));
        assert!(!spec.matches(22));
    }

    #[test]
    fn test_port_spec_negated() {
        let spec = PortSpec::Negated(Box::new(PortSpec::Single(80)));
        assert!(!spec.matches(80));
        assert!(spec.matches(443));
    }

    // --- IpSpec ---

    #[test]
    fn test_ip_spec_any() {
        assert!(IpSpec::Any.matches(ip("1.2.3.4")));
    }

    #[test]
    fn test_ip_spec_host() {
        let spec = IpSpec::Host(ip("10.0.0.1"));
        assert!(spec.matches(ip("10.0.0.1")));
        assert!(!spec.matches(ip("10.0.0.2")));
    }

    #[test]
    fn test_ip_spec_net() {
        let spec = IpSpec::Net(ip("192.168.0.0"), 24);
        assert!(spec.matches(ip("192.168.0.100")));
        assert!(!spec.matches(ip("192.168.1.1")));
    }

    #[test]
    fn test_ip_spec_negated() {
        let spec = IpSpec::Negated(Box::new(IpSpec::Host(ip("10.0.0.1"))));
        assert!(!spec.matches(ip("10.0.0.1")));
        assert!(spec.matches(ip("10.0.0.2")));
    }

    // --- Protocol ---

    #[test]
    fn test_protocol_matches() {
        assert!(Protocol::Tcp.matches(6));
        assert!(!Protocol::Tcp.matches(17));
        assert!(Protocol::Any.matches(6));
        assert!(Protocol::Any.matches(17));
        assert!(Protocol::Icmp.matches(1));
    }

    // --- Rule ---

    #[test]
    fn test_rule_new() {
        let r = make_alert_rule(1);
        assert_eq!(r.id, 1);
        assert!(r.enabled);
        assert_eq!(r.action, RuleAction::Alert);
    }

    #[test]
    fn test_rule_disable_enable() {
        let mut r = make_alert_rule(1);
        r.disable();
        assert!(!r.enabled);
        r.enable();
        assert!(r.enabled);
    }

    #[test]
    fn test_rule_display() {
        let r = make_alert_rule(42);
        let s = r.to_string();
        assert!(s.contains("42"));
        assert!(s.contains("Alert"));
    }

    // --- RuleSet ---

    #[test]
    fn test_rule_set_add_and_get() {
        let mut rs = RuleSet::new(100);
        rs.add(make_alert_rule(1)).unwrap();
        assert!(rs.get(1).is_some());
        assert_eq!(rs.count(), 1);
    }

    #[test]
    fn test_rule_set_duplicate_id_error() {
        let mut rs = RuleSet::new(100);
        rs.add(make_alert_rule(1)).unwrap();
        assert!(matches!(
            rs.add(make_alert_rule(1)),
            Err(RuleFullError::DuplicateId(1))
        ));
    }

    #[test]
    fn test_rule_set_remove() {
        let mut rs = RuleSet::new(100);
        rs.add(make_alert_rule(1)).unwrap();
        rs.remove(1).unwrap();
        assert_eq!(rs.count(), 0);
    }

    #[test]
    fn test_rule_set_remove_not_found() {
        let mut rs = RuleSet::new(100);
        assert!(matches!(rs.remove(999), Err(RuleFullError::NotFound(999))));
    }

    #[test]
    fn test_rule_set_lock_prevents_add() {
        let mut rs = RuleSet::new(100);
        rs.lock();
        assert!(matches!(
            rs.add(make_alert_rule(1)),
            Err(RuleFullError::Locked)
        ));
    }

    #[test]
    fn test_rule_set_max_rules() {
        let mut rs = RuleSet::new(2);
        rs.add(make_alert_rule(1)).unwrap();
        rs.add(make_alert_rule(2)).unwrap();
        assert!(matches!(
            rs.add(make_alert_rule(3)),
            Err(RuleFullError::TooManyRules(2))
        ));
    }

    // --- RuleCompiler ---

    #[test]
    fn test_compiler_compile_rule() {
        let r = make_alert_rule(1);
        let compiled = RuleCompiler::new().compile_rule(&r).unwrap();
        assert_eq!(compiled.rule_id, 1);
        assert_eq!(compiled.action, RuleAction::Alert);
    }

    #[test]
    fn test_compiler_compile_set_skips_disabled() {
        let mut rs = RuleSet::new(100);
        let mut r = make_alert_rule(1);
        r.disable();
        rs.add(r).unwrap();
        let compiled = RuleCompiler::new().compile_set(&rs).unwrap();
        assert_eq!(compiled.len(), 0);
    }

    // --- RuleMatcher ---

    #[test]
    fn test_matcher_simple_match() {
        let r = make_alert_rule(1);
        let compiled = RuleCompiler::new().compile_rule(&r).unwrap();
        let matcher = RuleMatcher::new(vec![compiled]);
        let results = matcher.match_packet(&make_tcp_pkt());
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].rule_id, 1);
    }

    #[test]
    fn test_matcher_no_match_proto() {
        let r = Rule::new(1, RuleAction::Alert, Protocol::Udp, "udp rule");
        let compiled = RuleCompiler::new().compile_rule(&r).unwrap();
        let matcher = RuleMatcher::new(vec![compiled]);
        // TCP packet should not match UDP rule
        assert!(matcher.match_packet(&make_tcp_pkt()).is_empty());
    }

    #[test]
    fn test_matcher_content_match() {
        let mut r = make_alert_rule(1);
        r.add_content(ContentOption::Contains(b"HTTP".to_vec()));
        let compiled = RuleCompiler::new().compile_rule(&r).unwrap();
        let matcher = RuleMatcher::new(vec![compiled]);
        let results = matcher.match_packet(&make_tcp_pkt());
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn test_matcher_content_no_match() {
        let mut r = make_alert_rule(1);
        r.add_content(ContentOption::Contains(b"SMTP".to_vec()));
        let compiled = RuleCompiler::new().compile_rule(&r).unwrap();
        let matcher = RuleMatcher::new(vec![compiled]);
        assert!(matcher.match_packet(&make_tcp_pkt()).is_empty());
    }

    #[test]
    fn test_matcher_neg_content_blocks_match() {
        let mut r = make_alert_rule(1);
        r.add_content(ContentOption::NotContains(b"HTTP".to_vec()));
        let compiled = RuleCompiler::new().compile_rule(&r).unwrap();
        let matcher = RuleMatcher::new(vec![compiled]);
        // Payload contains "HTTP" so neg should prevent match
        assert!(matcher.match_packet(&make_tcp_pkt()).is_empty());
    }

    #[test]
    fn test_matcher_first_match() {
        let rules: Vec<CompiledRule> = (1..=3)
            .map(|i| {
                RuleCompiler::new()
                    .compile_rule(&make_alert_rule(i))
                    .unwrap()
            })
            .collect();
        let matcher = RuleMatcher::new(rules);
        let first = matcher.first_match(&make_tcp_pkt());
        assert!(first.is_some());
    }

    // --- RuleStats ---

    #[test]
    fn test_stats_record_match() {
        let stats = RuleStats::new();
        stats.record_match(1);
        stats.record_match(1);
        assert_eq!(stats.match_count(1), 2);
        assert_eq!(stats.total_matches(), 2);
    }

    #[test]
    fn test_stats_match_rate() {
        let stats = RuleStats::new();
        stats.record_packet();
        stats.record_packet();
        stats.record_match(1);
        assert!((stats.match_rate() - 0.5).abs() < 1e-9);
    }

    #[test]
    fn test_stats_top_rules() {
        let stats = RuleStats::new();
        stats.record_match(1);
        stats.record_match(2);
        stats.record_match(2);
        let top = stats.top_rules(1);
        assert_eq!(top[0].0, 2);
        assert_eq!(top[0].1, 2);
    }

    // --- RuleDebugger ---

    #[test]
    fn test_debugger_disabled() {
        let dbg = RuleDebugger::new(false);
        dbg.log(1, "step", true);
        assert!(dbg.entries().is_empty());
    }

    #[test]
    fn test_debugger_enabled() {
        let dbg = RuleDebugger::new(true);
        dbg.log(1, "proto_check", true);
        dbg.log(1, "content_check", false);
        assert_eq!(dbg.entries().len(), 2);
    }

    #[test]
    fn test_debugger_clear() {
        let dbg = RuleDebugger::new(true);
        dbg.log(1, "x", true);
        dbg.clear();
        assert!(dbg.entries().is_empty());
    }

    #[test]
    fn test_debugger_format() {
        let dbg = RuleDebugger::new(true);
        dbg.log(42, "test_step", true);
        let s = dbg.format();
        assert!(s.contains("rule=42"));
        assert!(s.contains("test_step"));
    }

    // --- RuleEngineFull ---

    #[test]
    fn test_engine_compile_and_match() {
        let engine = RuleEngineFull::new();
        engine.add_rule(make_alert_rule(1)).unwrap();
        engine.compile().unwrap();
        assert!(engine.is_compiled());
        let results = engine.process_packet(&make_tcp_pkt());
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn test_engine_no_matcher_returns_empty() {
        let engine = RuleEngineFull::new();
        let results = engine.process_packet(&make_tcp_pkt());
        assert!(results.is_empty());
    }

    #[test]
    fn test_engine_disable_rule() {
        let engine = RuleEngineFull::new();
        engine.add_rule(make_alert_rule(1)).unwrap();
        engine.disable_rule(1).unwrap();
        engine.compile().unwrap();
        assert!(engine.process_packet(&make_tcp_pkt()).is_empty());
    }

    #[test]
    fn test_engine_remove_rule() {
        let engine = RuleEngineFull::new();
        engine.add_rule(make_alert_rule(1)).unwrap();
        engine.remove_rule(1).unwrap();
        assert_eq!(engine.rule_count(), 0);
    }

    #[test]
    fn test_engine_stats_updated() {
        let engine = RuleEngineFull::new();
        engine.add_rule(make_alert_rule(1)).unwrap();
        engine.compile().unwrap();
        engine.process_packet(&make_tcp_pkt());
        assert_eq!(engine.stats().total_packets(), 1);
        assert_eq!(engine.stats().total_matches(), 1);
    }

    #[test]
    fn test_engine_batch_processing() {
        let engine = RuleEngineFull::new();
        engine.add_rule(make_alert_rule(1)).unwrap();
        engine.compile().unwrap();
        let packets = vec![make_tcp_pkt(), make_tcp_pkt()];
        let all = engine.process_batch(&packets);
        assert_eq!(all.len(), 2);
    }

    #[test]
    fn test_match_result_is_alert() {
        let r = MatchResult {
            rule_id: 1,
            action: RuleAction::Alert,
            msg: "x".into(),
            priority: 1,
        };
        assert!(r.is_alert());
        assert!(!r.is_drop());
    }
}
