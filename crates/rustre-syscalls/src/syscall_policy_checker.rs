//! `syscall_policy_checker` — Evaluate syscall traces against configurable
//! security policies, returning violation reports.
//!
//! # Design
//! A [`SyscallPolicyChecker`] holds a set of [`Policy`] definitions. Each
//! [`Policy`] contains one or more [`PolicyRule`]s that match against a
//! [`SyscallCall`] and decide whether to *allow*, *deny*, or *alert* on it.
//! After all calls in a trace have been evaluated, the checker returns a
//! [`PolicyReport`] that lists every [`Violation`] found.

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::{OsFamily, RiskLevel, SyscallCall, SyscallCategory};

// ─── Action ───────────────────────────────────────────────────────────────────

/// What the policy engine should do when a rule fires.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RuleAction {
    /// Allow the call and continue evaluation.
    Allow,
    /// Log the call but treat it as allowed.
    Alert,
    /// Deny the call and record a violation.
    Deny,
    /// Block the call and terminate evaluation immediately.
    Block,
}

impl fmt::Display for RuleAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Allow => write!(f, "allow"),
            Self::Alert => write!(f, "alert"),
            Self::Deny => write!(f, "deny"),
            Self::Block => write!(f, "block"),
        }
    }
}

// ─── PolicyRule ───────────────────────────────────────────────────────────────

/// A single matching rule within a [`Policy`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRule {
    /// Unique identifier for this rule within its policy.
    pub id: String,
    /// Human-readable description.
    pub description: String,
    /// Syscall name pattern. `"*"` matches any name.
    pub syscall_name: String,
    /// Restrict to a specific OS family, or `None` for any.
    pub os: Option<OsFamily>,
    /// Minimum risk level required for a match.
    pub min_risk: Option<RiskLevel>,
    /// Restrict to a specific category, or `None` for any.
    pub category: Option<SyscallCategory>,
    /// Restrict to a specific PID, or `None` for any PID.
    pub pid: Option<u32>,
    /// Maximum allowed return value (inclusive). `None` = no check.
    pub max_retval: Option<i64>,
    /// Only fire when `call.is_error()` matches this value.
    pub on_error: Option<bool>,
    /// The action to take when this rule fires.
    pub action: RuleAction,
    /// Priority — lower is evaluated first.
    pub priority: i32,
}

impl PolicyRule {
    /// Create a new rule with sensible defaults.
    #[must_use]
    pub fn new(
        id: impl Into<String>,
        description: impl Into<String>,
        syscall_name: impl Into<String>,
        action: RuleAction,
    ) -> Self {
        Self {
            id: id.into(),
            description: description.into(),
            syscall_name: syscall_name.into(),
            os: None,
            min_risk: None,
            category: None,
            pid: None,
            max_retval: None,
            on_error: None,
            action,
            priority: 0,
        }
    }

    /// Restrict to a specific OS family.
    #[must_use]
    pub const fn with_os(mut self, os: OsFamily) -> Self {
        self.os = Some(os);
        self
    }

    /// Require at least this risk level.
    #[must_use]
    pub const fn with_min_risk(mut self, risk: RiskLevel) -> Self {
        self.min_risk = Some(risk);
        self
    }

    /// Restrict to a specific syscall category.
    #[must_use]
    pub const fn with_category(mut self, cat: SyscallCategory) -> Self {
        self.category = Some(cat);
        self
    }

    /// Restrict to a specific PID.
    #[must_use]
    pub const fn with_pid(mut self, pid: u32) -> Self {
        self.pid = Some(pid);
        self
    }

    /// Only fire when the call returned an error (or not).
    #[must_use]
    pub const fn on_error(mut self, flag: bool) -> Self {
        self.on_error = Some(flag);
        self
    }

    /// Set evaluation priority (lower = first).
    #[must_use]
    pub const fn with_priority(mut self, p: i32) -> Self {
        self.priority = p;
        self
    }

    /// Returns `true` when this rule matches the given call.
    #[must_use]
    pub fn matches(&self, call: &SyscallCall) -> bool {
        // Syscall name
        if self.syscall_name != "*" && self.syscall_name != call.syscall.name {
            return false;
        }
        // OS family
        if let Some(os) = self.os && call.syscall.os != os {
                return false;
        }
        // Minimum risk
        if let Some(min) = self.min_risk && call.syscall.risk < min {
                return false;
        }
        // Category
        if let Some(cat) = self.category && call.syscall.category != cat {
                return false;
        }
        // PID
        if let Some(pid) = self.pid && call.pid != pid {
                return false;
        }
        // Error predicate
        if let Some(want_err) = self.on_error && call.is_error() != want_err {
                return false;
        }
        // Max return value
        if let Some(max_ret) = self.max_retval && call.ret > max_ret {
                return false;
        }
        true
    }
}

// ─── Policy ───────────────────────────────────────────────────────────────────

/// A named collection of [`PolicyRule`]s evaluated in priority order.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    /// Unique policy name.
    pub name: String,
    /// Human-readable description.
    pub description: String,
    /// The ordered list of rules.
    pub rules: Vec<PolicyRule>,
    /// Default action when no rule matches.
    pub default_action: RuleAction,
    /// Whether to stop evaluating further policies after this one fires.
    pub terminal: bool,
}

impl Policy {
    /// Create an empty policy with a permissive default action.
    #[must_use]
    pub fn new(name: impl Into<String>, description: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            description: description.into(),
            rules: Vec::new(),
            default_action: RuleAction::Allow,
            terminal: false,
        }
    }

    /// Add a rule to the policy. Rules are kept sorted by priority.
    pub fn add_rule(&mut self, rule: PolicyRule) {
        self.rules.push(rule);
        self.rules.sort_by_key(|r| r.priority);
    }

    /// Set the default action (used when no rule matches).
    #[must_use]
    pub const fn with_default(mut self, action: RuleAction) -> Self {
        self.default_action = action;
        self
    }

    /// Mark the policy as terminal.
    #[must_use]
    pub const fn terminal(mut self) -> Self {
        self.terminal = true;
        self
    }

    /// Evaluate this policy against a single call.
    ///
    /// Returns `(action, matched_rule_id)` — the action may come from a matching
    /// rule or from `default_action` when no rule fires.
    #[must_use]
    pub fn check_call(&self, call: &SyscallCall) -> (RuleAction, Option<String>) {
        for rule in &self.rules {
            if rule.matches(call) {
                return (rule.action, Some(rule.id.clone()));
            }
        }
        (self.default_action, None)
    }

    /// Number of rules in this policy.
    #[must_use]
    pub const fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// Return all rules with a given action.
    #[must_use]
    pub fn rules_by_action(&self, action: RuleAction) -> Vec<&PolicyRule> {
        self.rules.iter().filter(|r| r.action == action).collect()
    }
}

// ─── Violation ────────────────────────────────────────────────────────────────

/// A single policy violation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Violation {
    /// Name of the policy that produced this violation.
    pub policy_name: String,
    /// ID of the rule that fired (or `None` for the default action).
    pub rule_id: Option<String>,
    /// The action taken.
    pub action: RuleAction,
    /// PID of the process that made the call.
    pub pid: u32,
    /// Nanosecond timestamp of the call.
    pub timestamp: u64,
    /// Name of the syscall.
    pub syscall_name: String,
    /// Syscall return value.
    pub retval: i64,
    /// Optional human-readable explanation.
    pub explanation: String,
}

impl Violation {
    /// Returns `true` when this violation blocks further processing.
    #[must_use]
    pub const fn is_blocking(&self) -> bool {
        matches!(self.action, RuleAction::Block | RuleAction::Deny)
    }

    /// Returns `true` when this is only an informational alert.
    #[must_use]
    pub const fn is_alert_only(&self) -> bool {
        matches!(self.action, RuleAction::Alert)
    }
}

impl fmt::Display for Violation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{}] policy={} rule={} pid={} syscall={} ret={}",
            self.action,
            self.policy_name,
            self.rule_id.as_deref().unwrap_or("default"),
            self.pid,
            self.syscall_name,
            self.retval,
        )
    }
}

// ─── PolicyReport ─────────────────────────────────────────────────────────────

/// The result of running a [`SyscallPolicyChecker`] over a trace.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PolicyReport {
    /// All violations found.
    pub violations: Vec<Violation>,
    /// Total number of syscall calls evaluated.
    pub calls_evaluated: usize,
    /// Number of calls allowed without any rule firing.
    pub calls_allowed: usize,
    /// Number of calls that triggered at least one alert.
    pub calls_alerted: usize,
    /// Number of calls denied or blocked.
    pub calls_blocked: usize,
}

impl PolicyReport {
    /// Returns `true` when the report contains no violations.
    #[must_use]
    pub const fn is_clean(&self) -> bool {
        self.violations.is_empty()
    }

    /// Return only the blocking violations.
    #[must_use]
    pub fn blocking_violations(&self) -> Vec<&Violation> {
        self.violations.iter().filter(|v| v.is_blocking()).collect()
    }

    /// Return only alert violations.
    #[must_use]
    pub fn alert_violations(&self) -> Vec<&Violation> {
        self.violations
            .iter()
            .filter(|v| v.is_alert_only())
            .collect()
    }

    /// Return violations grouped by policy name.
    #[must_use]
    pub fn by_policy(&self) -> HashMap<String, Vec<&Violation>> {
        let mut map: HashMap<String, Vec<&Violation>> = HashMap::new();
        for v in &self.violations {
            map.entry(v.policy_name.clone()).or_default().push(v);
        }
        map
    }

    /// Return violations grouped by syscall name.
    #[must_use]
    pub fn by_syscall(&self) -> HashMap<String, Vec<&Violation>> {
        let mut map: HashMap<String, Vec<&Violation>> = HashMap::new();
        for v in &self.violations {
            map.entry(v.syscall_name.clone()).or_default().push(v);
        }
        map
    }

    /// Highest-severity action seen across all violations.
    #[must_use]
    pub fn max_severity(&self) -> Option<RuleAction> {
        let severity = |a: &RuleAction| match a {
            RuleAction::Block => 3,
            RuleAction::Deny => 2,
            RuleAction::Alert => 1,
            RuleAction::Allow => 0,
        };
        self.violations
            .iter()
            .max_by_key(|v| severity(&v.action))
            .map(|v| v.action)
    }
}

// ─── SyscallPolicyChecker ─────────────────────────────────────────────────────

/// Evaluates a sequence of [`SyscallCall`]s against a set of [`Policy`]s and
/// returns a [`PolicyReport`].
#[derive(Debug, Clone, Default)]
pub struct SyscallPolicyChecker {
    /// Ordered list of policies (evaluated front-to-back per call).
    policies: Vec<Policy>,
    /// Stop after the first blocking violation per call.
    pub fail_fast: bool,
}

impl SyscallPolicyChecker {
    /// Create an empty checker.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a policy to the checker.
    pub fn add_policy(&mut self, policy: Policy) {
        self.policies.push(policy);
    }

    /// Enable fail-fast mode: skip remaining policies after a block/deny.
    #[must_use]
    pub const fn with_fail_fast(mut self) -> Self {
        self.fail_fast = true;
        self
    }

    /// Number of registered policies.
    #[must_use]
    pub const fn policy_count(&self) -> usize {
        self.policies.len()
    }

    /// Evaluate a single call and return zero or more violations.
    #[must_use]
    pub fn check_call(&self, call: &SyscallCall) -> Vec<Violation> {
        let mut violations = Vec::new();
        for policy in &self.policies {
            let (action, rule_id) = policy.check_call(call);
            match action {
                RuleAction::Allow => {}
                RuleAction::Alert | RuleAction::Deny | RuleAction::Block => {
                    violations.push(Violation {
                        policy_name: policy.name.clone(),
                        rule_id,
                        action,
                        pid: call.pid,
                        timestamp: call.timestamp,
                        syscall_name: call.syscall.name.clone(),
                        retval: call.ret,
                        explanation: format!(
                            "policy='{}' fired on syscall='{}'",
                            policy.name, call.syscall.name
                        ),
                    });
                    if self.fail_fast && matches!(action, RuleAction::Deny | RuleAction::Block) {
                        return violations;
                    }
                }
            }
            if policy.terminal && action != RuleAction::Allow {
                break;
            }
        }
        violations
    }

    /// Evaluate an entire slice of calls and return a consolidated report.
    #[must_use]
    pub fn check_trace(&self, calls: &[SyscallCall]) -> PolicyReport {
        let mut report = PolicyReport {
            calls_evaluated: calls.len(),
            ..Default::default()
        };
        for call in calls {
            let violations = self.check_call(call);
            if violations.is_empty() {
                report.calls_allowed += 1;
            } else {
                let has_block = violations.iter().any(Violation::is_blocking);
                let has_alert = violations.iter().any(Violation::is_alert_only);
                if has_block {
                    report.calls_blocked += 1;
                }
                if has_alert {
                    report.calls_alerted += 1;
                }
                report.violations.extend(violations);
            }
        }
        report
    }

    /// Look up a policy by name.
    #[must_use]
    pub fn find_policy(&self, name: &str) -> Option<&Policy> {
        self.policies.iter().find(|p| p.name == name)
    }

    /// Remove a policy by name. Returns `true` when the policy existed.
    pub fn remove_policy(&mut self, name: &str) -> bool {
        let before = self.policies.len();
        self.policies.retain(|p| p.name != name);
        self.policies.len() < before
    }

    /// Return a copy of the current policy list.
    #[must_use]
    pub fn policies(&self) -> &[Policy] {
        &self.policies
    }

    /// Build a default security policy set suitable for malware analysis.
    ///
    /// Raises alerts for common reconnaissance syscalls and denies
    /// critical-risk calls.
    #[must_use]
    pub fn default_security_policy() -> Self {
        let mut checker = Self::new();

        // ── Execution control ────────────────────────────────────────────────
        let mut exec_policy = Policy::new(
            "execution_control",
            "Alert on process spawning and module injection",
        );
        exec_policy.add_rule(
            PolicyRule::new("ec-001", "execve detected", "execve", RuleAction::Alert)
                .with_priority(-10),
        );
        exec_policy.add_rule(PolicyRule::new(
            "ec-002",
            "fork detected",
            "fork",
            RuleAction::Alert,
        ));
        exec_policy.add_rule(PolicyRule::new(
            "ec-003",
            "vfork detected",
            "vfork",
            RuleAction::Alert,
        ));
        checker.add_policy(exec_policy);

        // ── Memory operations ────────────────────────────────────────────────
        let mut mem_policy =
            Policy::new("memory_ops", "Alert on suspicious memory operations");
        mem_policy.add_rule(
            PolicyRule::new("mo-001", "mmap with PROT_EXEC", "mmap", RuleAction::Alert)
                .with_min_risk(RiskLevel::Medium),
        );
        mem_policy.add_rule(PolicyRule::new(
            "mo-002",
            "mprotect detected",
            "mprotect",
            RuleAction::Alert,
        ));
        mem_policy.add_rule(PolicyRule::new(
            "mo-003",
            "ptrace detected",
            "ptrace",
            RuleAction::Deny,
        ));
        checker.add_policy(mem_policy);

        // ── Network activity ────────────────────────────────────────────────
        let mut net_policy = Policy::new("network", "Alert on network calls");
        net_policy.add_rule(PolicyRule::new(
            "net-001",
            "socket created",
            "socket",
            RuleAction::Alert,
        ));
        net_policy.add_rule(PolicyRule::new(
            "net-002",
            "connect called",
            "connect",
            RuleAction::Alert,
        ));
        net_policy.add_rule(PolicyRule::new(
            "net-003",
            "bind called",
            "bind",
            RuleAction::Alert,
        ));
        checker.add_policy(net_policy);

        checker
    }
}

/// Standalone `check_call` convenience function.
///
/// Evaluates a single [`SyscallCall`] against a slice of policies and returns
/// the first non-`Allow` action along with the matching policy and rule IDs.
#[must_use]
pub fn check_call(
    call: &SyscallCall,
    policies: &[Policy],
) -> Option<(RuleAction, String, Option<String>)> {
    for policy in policies {
        let (action, rule_id) = policy.check_call(call);
        if action != RuleAction::Allow {
            return Some((action, policy.name.clone(), rule_id));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        OsFamily, Syscall, SyscallArch, SyscallCall, SyscallCategory,
        SyscallTarget, SyscallType,
    };

    fn make_call(name: &str, pid: u32, ret: i64) -> SyscallCall {
        let sc = Syscall::new(
            1,
            name,
            SyscallTarget::new(OsFamily::Linux, SyscallArch::X86_64),
            vec![],
            SyscallType::Int,
            SyscallCategory::Process,
            "test",
        );
        SyscallCall::new(sc, vec![], ret, 0, pid, pid)
    }

    #[test]
    fn test_rule_matches_wildcard() {
        let rule = PolicyRule::new("r1", "any", "*", RuleAction::Alert);
        let call = make_call("read", 100, 0);
        assert!(rule.matches(&call));
    }

    #[test]
    fn test_rule_matches_specific() {
        let rule = PolicyRule::new("r1", "exec", "execve", RuleAction::Deny);
        assert!(!rule.matches(&make_call("read", 1, 0)));
        assert!(rule.matches(&make_call("execve", 1, 0)));
    }

    #[test]
    fn test_rule_pid_filter() {
        let rule = PolicyRule::new("r1", "pid", "*", RuleAction::Alert).with_pid(42);
        assert!(rule.matches(&make_call("read", 42, 0)));
        assert!(!rule.matches(&make_call("read", 99, 0)));
    }

    #[test]
    fn test_policy_default_action() {
        let policy = Policy::new("p", "test").with_default(RuleAction::Alert);
        let call = make_call("read", 1, 0);
        let (action, rule_id) = policy.check_call(&call);
        assert_eq!(action, RuleAction::Alert);
        assert!(rule_id.is_none());
    }

    #[test]
    fn test_policy_rule_fires() {
        let mut policy = Policy::new("p", "test");
        policy.add_rule(PolicyRule::new("r1", "execve", "execve", RuleAction::Deny));
        let (action, rule_id) = policy.check_call(&make_call("execve", 1, 0));
        assert_eq!(action, RuleAction::Deny);
        assert_eq!(rule_id.as_deref(), Some("r1"));
    }

    #[test]
    fn test_checker_clean_trace() {
        let checker = SyscallPolicyChecker::new();
        let calls: Vec<SyscallCall> = (0..5).map(|i| make_call("read", i, 0)).collect();
        let report = checker.check_trace(&calls);
        assert!(report.is_clean());
        assert_eq!(report.calls_evaluated, 5);
    }

    #[test]
    fn test_checker_violation_recorded() {
        let mut checker = SyscallPolicyChecker::new();
        let mut p = Policy::new("sec", "security");
        p.add_rule(PolicyRule::new("r1", "execve", "execve", RuleAction::Deny));
        checker.add_policy(p);
        let calls = vec![make_call("execve", 1, 0)];
        let report = checker.check_trace(&calls);
        assert!(!report.is_clean());
        assert_eq!(report.calls_blocked, 1);
    }

    #[test]
    fn test_report_by_policy() {
        let mut checker = SyscallPolicyChecker::new();
        let mut p = Policy::new("net", "network");
        p.add_rule(PolicyRule::new("n1", "socket", "socket", RuleAction::Alert));
        checker.add_policy(p);
        let calls = vec![make_call("socket", 1, 0), make_call("socket", 2, 0)];
        let report = checker.check_trace(&calls);
        let by_policy = report.by_policy();
        assert_eq!(by_policy.get("net").map(std::vec::Vec::len), Some(2));
    }

    #[test]
    fn test_default_security_policy_exec() {
        let checker = SyscallPolicyChecker::default_security_policy();
        let v = checker.check_call(&make_call("execve", 1, 0));
        assert!(!v.is_empty());
    }

    #[test]
    fn test_remove_policy() {
        let mut checker = SyscallPolicyChecker::new();
        checker.add_policy(Policy::new("p1", "first"));
        checker.add_policy(Policy::new("p2", "second"));
        assert!(checker.remove_policy("p1"));
        assert_eq!(checker.policy_count(), 1);
        assert!(!checker.remove_policy("nonexistent"));
    }

    #[test]
    fn test_violation_display() {
        let v = Violation {
            policy_name: "pol".to_string(),
            rule_id: Some("r1".to_string()),
            action: RuleAction::Deny,
            pid: 42,
            timestamp: 0,
            syscall_name: "fork".to_string(),
            retval: 0,
            explanation: String::new(),
        };
        let s = v.to_string();
        assert!(s.contains("deny"));
        assert!(s.contains("fork"));
    }

    #[test]
    fn test_on_error_filter() {
        let rule = PolicyRule::new("r1", "err", "*", RuleAction::Alert).on_error(true);
        assert!(rule.matches(&make_call("read", 1, -1)));
        assert!(!rule.matches(&make_call("read", 1, 0)));
    }

    #[test]
    fn test_rules_by_action() {
        let mut policy = Policy::new("p", "test");
        policy.add_rule(PolicyRule::new("r1", "a", "execve", RuleAction::Deny));
        policy.add_rule(PolicyRule::new("r2", "b", "fork", RuleAction::Alert));
        assert_eq!(policy.rules_by_action(RuleAction::Deny).len(), 1);
        assert_eq!(policy.rules_by_action(RuleAction::Alert).len(), 1);
    }
}
