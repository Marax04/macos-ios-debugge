//! Syscall interception model for Linux.
//!
//! Provides a policy-based mechanism for intercepting, filtering, logging,
//! blocking, modifying and redirecting Linux syscalls at the abstraction level
//! used by `rustre-syscalls-linux`.  The actual low-level hook mechanism is
//! left to the caller (ptrace, eBPF, seccomp-notify, etc.).

pub use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::LinuxSyscall;
pub use crate::{LinuxSyscallError, SyscallParam};
use rustre_syscalls::SyscallArch;

// ─── InterceptPoint ───────────────────────────────────────────────────────────

/// Where in the syscall lifecycle the intercept fires.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum InterceptPoint {
    /// Before the kernel executes the syscall (arguments are readable/modifiable).
    Pre,
    /// After the kernel returns from the syscall (return value is readable/modifiable).
    Post,
    /// Fire at both pre- and post- points.
    Both,
}

impl InterceptPoint {
    /// Returns `true` if this point includes the pre-entry phase.
    #[must_use]
    pub const fn includes_pre(self) -> bool {
        matches!(self, Self::Pre | Self::Both)
    }

    /// Returns `true` if this point includes the post-return phase.
    #[must_use]
    pub const fn includes_post(self) -> bool {
        matches!(self, Self::Post | Self::Both)
    }
}

impl std::fmt::Display for InterceptPoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pre => write!(f, "pre"),
            Self::Post => write!(f, "post"),
            Self::Both => write!(f, "both"),
        }
    }
}

// ─── SyscallFilter ────────────────────────────────────────────────────────────

/// Describes which syscalls an intercept rule applies to.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SyscallFilter {
    /// Match any syscall number.
    Any,
    /// Match exactly one syscall number.
    Number(u32),
    /// Match a set of syscall numbers.
    NumberSet(Vec<u32>),
    /// Match by exact syscall name.
    Name(String),
    /// Match any of the given names.
    NameSet(Vec<String>),
    /// Match all syscalls whose number falls in `[lo, hi]` (inclusive).
    NumberRange { lo: u32, hi: u32 },
}

impl SyscallFilter {
    /// Return `true` if `syscall` is matched by this filter.
    ///
    /// # Panics
    ///
    /// Panics if a `NumberRange` filter has `lo > hi`.
    #[must_use]
    pub fn matches(&self, syscall: &LinuxSyscall) -> bool {
        match self {
            Self::Any => true,
            Self::Number(n) => syscall.number == *n,
            Self::NumberSet(ns) => ns.contains(&syscall.number),
            Self::Name(n) => syscall.name == *n,
            Self::NameSet(ns) => ns.contains(&syscall.name),
            Self::NumberRange { lo, hi } => {
                if lo > hi {
                    return false;
                }
                syscall.number >= *lo && syscall.number <= *hi
            }
        }
    }

    /// Build a filter matching a single name.
    #[must_use]
    pub fn by_name(name: impl Into<String>) -> Self {
        Self::Name(name.into())
    }

    /// Build a filter matching one number.
    #[must_use]
    pub const fn by_number(n: u32) -> Self {
        Self::Number(n)
    }
}

// ─── ArgModifier ──────────────────────────────────────────────────────────────

/// Describes how a single syscall argument should be modified before the kernel
/// sees it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArgModifier {
    /// Zero-based index of the argument to modify.
    pub arg_index: usize,
    /// New raw value to write into the register that carries this argument.
    pub new_value: u64,
    /// Human-readable reason for the modification (for logging).
    pub reason: String,
}

impl ArgModifier {
    /// Construct a new [`ArgModifier`].
    #[must_use]
    pub fn new(arg_index: usize, new_value: u64, reason: impl Into<String>) -> Self {
        Self {
            arg_index,
            new_value,
            reason: reason.into(),
        }
    }
}

// ─── ReturnModifier ───────────────────────────────────────────────────────────

/// Describes how the syscall return value should be modified after the kernel
/// returns.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReturnModifier {
    /// New return value to inject.
    pub new_retval: i64,
    /// If `true`, also modify `errno` derived from the new return value.
    pub update_errno: bool,
    /// Human-readable reason.
    pub reason: String,
}

impl ReturnModifier {
    /// Construct a new [`ReturnModifier`].
    #[must_use]
    pub fn new(new_retval: i64, update_errno: bool, reason: impl Into<String>) -> Self {
        Self {
            new_retval,
            update_errno,
            reason: reason.into(),
        }
    }
}

// ─── InterceptAction ──────────────────────────────────────────────────────────

/// What to do when an intercept rule fires.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum InterceptAction {
    /// Record the syscall event without changing anything.
    Log,
    /// Block the syscall entirely; return `error_code` to the tracee.
    Block { error_code: i32 },
    /// Modify one or more arguments before the kernel sees them.
    ModifyArgs(Vec<ArgModifier>),
    /// Modify the return value after the kernel returns.
    ModifyReturn(ReturnModifier),
    /// Replace this syscall with a different syscall number.
    Redirect { to_syscall: u32 },
    /// Execute a chain of actions in order.
    Chain(Vec<Self>),
}

impl InterceptAction {
    /// Returns `true` if this action will prevent the kernel syscall.
    #[must_use]
    pub fn is_blocking(&self) -> bool {
        match self {
            Self::Block { .. } => true,
            Self::Chain(actions) => actions.iter().any(Self::is_blocking),
            _ => false,
        }
    }

    /// Returns a brief label for display / logging.
    #[must_use]
    pub const fn label(&self) -> &'static str {
        match self {
            Self::Log => "log",
            Self::Block { .. } => "block",
            Self::ModifyArgs(_) => "modify_args",
            Self::ModifyReturn(_) => "modify_return",
            Self::Redirect { .. } => "redirect",
            Self::Chain(_) => "chain",
        }
    }
}

// ─── InterceptRule ────────────────────────────────────────────────────────────

/// A single interception rule: filter + point + action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterceptRule {
    /// Unique identifier for this rule.
    pub id: u64,
    /// Which syscalls this rule applies to.
    pub filter: SyscallFilter,
    /// Whether to fire on entry, exit, or both.
    pub point: InterceptPoint,
    /// What to do when the rule fires.
    pub action: InterceptAction,
    /// Whether the rule is currently active.
    pub enabled: bool,
    /// Optional tag for grouping rules.
    pub tag: Option<String>,
}

impl InterceptRule {
    /// Build a new enabled rule with the given id, filter, point and action.
    #[must_use]
    pub const fn new(
        id: u64,
        filter: SyscallFilter,
        point: InterceptPoint,
        action: InterceptAction,
    ) -> Self {
        Self {
            id,
            filter,
            point,
            action,
            enabled: true,
            tag: None,
        }
    }

    /// Attach a tag and return `self` (builder style).
    #[must_use]
    pub fn with_tag(mut self, tag: impl Into<String>) -> Self {
        self.tag = Some(tag.into());
        self
    }

    /// Disable this rule.
    pub const fn disable(&mut self) {
        self.enabled = false;
    }

    /// Enable this rule.
    pub const fn enable(&mut self) {
        self.enabled = true;
    }
}

// ─── InterceptEvent ───────────────────────────────────────────────────────────

/// An event emitted by the interceptor whenever a rule fires.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterceptEvent {
    /// The rule that fired.
    pub rule_id: u64,
    /// Architecture of the traced process.
    pub arch: SyscallArch,
    /// Syscall number.
    pub syscall_number: u32,
    /// Syscall name (may be `"unknown"` if not in the table).
    pub syscall_name: String,
    /// Raw argument values captured at the intercept point.
    pub raw_args: Vec<u64>,
    /// Return value (only meaningful at `Post` / `Both`).
    pub return_value: Option<i64>,
    /// Which point this event was generated at.
    pub point: InterceptPoint,
    /// Whether the rule blocked the syscall.
    pub was_blocked: bool,
}

// ─── SyscallInterceptor ───────────────────────────────────────────────────────

/// Central registry that evaluates a set of [`InterceptRule`]s against incoming
/// syscall events and produces [`InterceptEvent`]s.
///
/// The interceptor is intentionally stateless regarding the traced process; it
/// only holds policy and accumulated events.  The low-level hook adapter is
/// responsible for feeding raw data in and applying the resulting actions.
#[derive(Debug, Default)]
pub struct SyscallInterceptor {
    rules: Vec<InterceptRule>,
    next_rule_id: u64,
    events: Vec<InterceptEvent>,
    pub arch: Option<SyscallArch>,
}

impl SyscallInterceptor {
    /// Create an empty interceptor with no rules.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create an interceptor locked to a specific architecture.
    #[must_use]
    pub fn for_arch(arch: SyscallArch) -> Self {
        Self {
            arch: Some(arch),
            ..Default::default()
        }
    }

    /// Add a rule and return its assigned id.
    pub fn add_rule(
        &mut self,
        filter: SyscallFilter,
        point: InterceptPoint,
        action: InterceptAction,
    ) -> u64 {
        let id = self.next_rule_id;
        self.next_rule_id += 1;
        self.rules
            .push(InterceptRule::new(id, filter, point, action));
        id
    }

    /// Remove the rule with the given id.  Returns `true` if a rule was removed.
    pub fn remove_rule(&mut self, id: u64) -> bool {
        let before = self.rules.len();
        self.rules.retain(|r| r.id != id);
        self.rules.len() < before
    }

    /// Enable or disable a rule by id.
    pub fn set_rule_enabled(&mut self, id: u64, enabled: bool) {
        for rule in &mut self.rules {
            if rule.id == id {
                rule.enabled = enabled;
            }
        }
    }

    /// Evaluate all enabled rules against a syscall at a given point.
    ///
    /// Returns a vec of events (one per matching rule).  The caller is
    /// responsible for applying the resulting [`InterceptAction`]s.
    pub fn evaluate(
        &mut self,
        syscall: &LinuxSyscall,
        arch: SyscallArch,
        raw_args: &[u64],
        return_value: Option<i64>,
        point: InterceptPoint,
    ) -> Vec<InterceptEvent> {
        let mut events = Vec::with_capacity(self.rules.len());
        for rule in &self.rules {
            if !rule.enabled {
                continue;
            }
            if !rule.point.includes_pre() && point == InterceptPoint::Pre {
                continue;
            }
            if !rule.point.includes_post() && point == InterceptPoint::Post {
                continue;
            }
            if !rule.filter.matches(syscall) {
                continue;
            }
            let was_blocked = rule.action.is_blocking();
            let ev = InterceptEvent {
                rule_id: rule.id,
                arch,
                syscall_number: syscall.number,
                syscall_name: syscall.name.clone(),
                raw_args: raw_args.to_vec(),
                return_value,
                point,
                was_blocked,
            };
            events.push(ev.clone());
            self.events.push(ev);
        }
        events
    }

    /// Return a reference to all recorded events.
    #[must_use]
    pub fn events(&self) -> &[InterceptEvent] {
        &self.events
    }

    /// Clear the accumulated event log.
    pub fn clear_events(&mut self) {
        self.events.clear();
    }

    /// Number of rules currently registered.
    #[must_use]
    pub const fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// Number of events accumulated so far.
    #[must_use]
    pub const fn event_count(&self) -> usize {
        self.events.len()
    }

    /// Return a slice of all rules.
    #[must_use]
    pub fn rules(&self) -> &[InterceptRule] {
        &self.rules
    }

    /// Return all rules tagged with `tag`.
    #[must_use]
    pub fn rules_by_tag(&self, tag: &str) -> Vec<&InterceptRule> {
        self.rules
            .iter()
            .filter(|r| r.tag.as_deref() == Some(tag))
            .collect()
    }

    /// Convenience: add a logging rule for every syscall at both points.
    pub fn add_log_all(&mut self) -> u64 {
        self.add_rule(
            SyscallFilter::Any,
            InterceptPoint::Both,
            InterceptAction::Log,
        )
    }

    /// Convenience: block a specific syscall number.
    pub fn add_block_number(&mut self, nr: u32, error_code: i32) -> u64 {
        self.add_rule(
            SyscallFilter::Number(nr),
            InterceptPoint::Pre,
            InterceptAction::Block { error_code },
        )
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    
    use rustre_syscalls::SyscallArch;

    fn make_sc(number: u32, name: &str) -> LinuxSyscall {
        LinuxSyscall::new(number, name, vec![], "long")
    }

    // --- InterceptPoint ---

    #[test]
    fn intercept_point_pre_includes_pre() {
        assert!(InterceptPoint::Pre.includes_pre());
        assert!(!InterceptPoint::Pre.includes_post());
    }

    #[test]
    fn intercept_point_post_includes_post() {
        assert!(InterceptPoint::Post.includes_post());
        assert!(!InterceptPoint::Post.includes_pre());
    }

    #[test]
    fn intercept_point_both_includes_both() {
        assert!(InterceptPoint::Both.includes_pre());
        assert!(InterceptPoint::Both.includes_post());
    }

    #[test]
    fn intercept_point_display() {
        assert_eq!(InterceptPoint::Pre.to_string(), "pre");
        assert_eq!(InterceptPoint::Post.to_string(), "post");
        assert_eq!(InterceptPoint::Both.to_string(), "both");
    }

    // --- SyscallFilter ---

    #[test]
    fn filter_any_matches_everything() {
        let sc = make_sc(1, "write");
        assert!(SyscallFilter::Any.matches(&sc));
    }

    #[test]
    fn filter_number_matches_exact() {
        let sc = make_sc(1, "write");
        assert!(SyscallFilter::Number(1).matches(&sc));
        assert!(!SyscallFilter::Number(2).matches(&sc));
    }

    #[test]
    fn filter_number_set() {
        let sc = make_sc(3, "close");
        assert!(SyscallFilter::NumberSet(vec![1, 2, 3]).matches(&sc));
        assert!(!SyscallFilter::NumberSet(vec![4, 5]).matches(&sc));
    }

    #[test]
    fn filter_name_exact() {
        let sc = make_sc(0, "read");
        assert!(SyscallFilter::Name("read".into()).matches(&sc));
        assert!(!SyscallFilter::Name("write".into()).matches(&sc));
    }

    #[test]
    fn filter_name_set() {
        let sc = make_sc(0, "read");
        let f = SyscallFilter::NameSet(vec!["read".into(), "write".into()]);
        assert!(f.matches(&sc));
    }

    #[test]
    fn filter_range() {
        let sc = make_sc(5, "fstat");
        assert!(SyscallFilter::NumberRange { lo: 0, hi: 10 }.matches(&sc));
        assert!(!SyscallFilter::NumberRange { lo: 10, hi: 20 }.matches(&sc));
    }

    #[test]
    fn filter_by_name_constructor() {
        let f = SyscallFilter::by_name("open");
        assert!(matches!(f, SyscallFilter::Name(ref n) if n == "open"));
    }

    #[test]
    fn filter_by_number_constructor() {
        let f = SyscallFilter::by_number(42);
        assert!(matches!(f, SyscallFilter::Number(42)));
    }

    // --- InterceptAction ---

    #[test]
    fn action_log_not_blocking() {
        assert!(!InterceptAction::Log.is_blocking());
    }

    #[test]
    fn action_block_is_blocking() {
        assert!(InterceptAction::Block { error_code: 1 }.is_blocking());
    }

    #[test]
    fn action_chain_blocking_if_any_child_blocks() {
        let chain = InterceptAction::Chain(vec![
            InterceptAction::Log,
            InterceptAction::Block { error_code: -1 },
        ]);
        assert!(chain.is_blocking());
    }

    #[test]
    fn action_chain_not_blocking_if_no_child_blocks() {
        let chain = InterceptAction::Chain(vec![InterceptAction::Log]);
        assert!(!chain.is_blocking());
    }

    #[test]
    fn action_labels() {
        assert_eq!(InterceptAction::Log.label(), "log");
        assert_eq!(InterceptAction::Block { error_code: 0 }.label(), "block");
        assert_eq!(
            InterceptAction::Redirect { to_syscall: 1 }.label(),
            "redirect"
        );
    }

    // --- ArgModifier / ReturnModifier ---

    #[test]
    fn arg_modifier_fields() {
        let m = ArgModifier::new(2, 0xDEAD, "test");
        assert_eq!(m.arg_index, 2);
        assert_eq!(m.new_value, 0xDEAD);
        assert_eq!(m.reason, "test");
    }

    #[test]
    fn return_modifier_fields() {
        let m = ReturnModifier::new(-1, true, "fake error");
        assert_eq!(m.new_retval, -1);
        assert!(m.update_errno);
    }

    // --- InterceptRule ---

    #[test]
    fn rule_enable_disable() {
        let mut rule = InterceptRule::new(
            0,
            SyscallFilter::Any,
            InterceptPoint::Pre,
            InterceptAction::Log,
        );
        assert!(rule.enabled);
        rule.disable();
        assert!(!rule.enabled);
        rule.enable();
        assert!(rule.enabled);
    }

    #[test]
    fn rule_with_tag() {
        let rule = InterceptRule::new(
            0,
            SyscallFilter::Any,
            InterceptPoint::Pre,
            InterceptAction::Log,
        )
        .with_tag("security");
        assert_eq!(rule.tag.as_deref(), Some("security"));
    }

    // --- SyscallInterceptor ---

    #[test]
    fn interceptor_add_remove_rule() {
        let mut ic = SyscallInterceptor::new();
        let id = ic.add_rule(
            SyscallFilter::Any,
            InterceptPoint::Pre,
            InterceptAction::Log,
        );
        assert_eq!(ic.rule_count(), 1);
        assert!(ic.remove_rule(id));
        assert_eq!(ic.rule_count(), 0);
        assert!(!ic.remove_rule(id)); // double remove
    }

    #[test]
    fn interceptor_evaluate_log_all() {
        let mut ic = SyscallInterceptor::new();
        ic.add_log_all();
        let sc = make_sc(0, "read");
        let events = ic.evaluate(
            &sc,
            SyscallArch::X86_64,
            &[3, 0, 128],
            None,
            InterceptPoint::Pre,
        );
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].syscall_name, "read");
        assert!(!events[0].was_blocked);
    }

    #[test]
    fn interceptor_evaluate_block() {
        let mut ic = SyscallInterceptor::new();
        ic.add_block_number(0, -1);
        let sc = make_sc(0, "read");
        let events = ic.evaluate(&sc, SyscallArch::X86_64, &[], None, InterceptPoint::Pre);
        assert_eq!(events.len(), 1);
        assert!(events[0].was_blocked);
    }

    #[test]
    fn interceptor_disabled_rule_not_fired() {
        let mut ic = SyscallInterceptor::new();
        let id = ic.add_log_all();
        ic.set_rule_enabled(id, false);
        let sc = make_sc(1, "write");
        let events = ic.evaluate(&sc, SyscallArch::X86_64, &[], None, InterceptPoint::Pre);
        assert!(events.is_empty());
    }

    #[test]
    fn interceptor_rules_by_tag() {
        let mut ic = SyscallInterceptor::new();
        let id = ic.add_log_all();
        for rule in &mut ic.rules {
            if rule.id == id {
                rule.tag = Some("audit".into());
            }
        }
        assert_eq!(ic.rules_by_tag("audit").len(), 1);
        assert!(ic.rules_by_tag("other").is_empty());
    }

    #[test]
    fn interceptor_clear_events() {
        let mut ic = SyscallInterceptor::new();
        ic.add_log_all();
        let sc = make_sc(0, "read");
        ic.evaluate(&sc, SyscallArch::X86_64, &[], None, InterceptPoint::Pre);
        assert!(!ic.events().is_empty());
        ic.clear_events();
        assert!(ic.events().is_empty());
    }

    #[test]
    fn interceptor_post_only_rule_not_fired_on_pre() {
        let mut ic = SyscallInterceptor::new();
        ic.add_rule(
            SyscallFilter::Any,
            InterceptPoint::Post,
            InterceptAction::Log,
        );
        let sc = make_sc(0, "read");
        let events = ic.evaluate(&sc, SyscallArch::X86_64, &[], None, InterceptPoint::Pre);
        assert!(events.is_empty());
    }

    #[test]
    fn interceptor_post_only_rule_fired_on_post() {
        let mut ic = SyscallInterceptor::new();
        ic.add_rule(
            SyscallFilter::Any,
            InterceptPoint::Post,
            InterceptAction::Log,
        );
        let sc = make_sc(0, "read");
        let events = ic.evaluate(
            &sc,
            SyscallArch::X86_64,
            &[],
            Some(128),
            InterceptPoint::Post,
        );
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].return_value, Some(128));
    }

    #[test]
    fn interceptor_event_count_accumulates() {
        let mut ic = SyscallInterceptor::new();
        ic.add_log_all();
        let sc = make_sc(1, "write");
        for _ in 0..5 {
            ic.evaluate(&sc, SyscallArch::X86_64, &[], None, InterceptPoint::Pre);
        }
        assert_eq!(ic.event_count(), 5);
    }

    #[test]
    fn interceptor_for_arch() {
        let ic = SyscallInterceptor::for_arch(SyscallArch::Arm64);
        assert_eq!(ic.arch, Some(SyscallArch::Arm64));
    }
}
