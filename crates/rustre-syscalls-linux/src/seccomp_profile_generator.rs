//! Generate seccomp-BPF profiles: allowlist/denylist policies with argument
//! filtering, producing a textual BPF filter description.

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

// ─── PolicyKind ───────────────────────────────────────────────────────────────

/// Whether the profile allows or denies matched syscalls.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PolicyKind {
    /// Allow listed syscalls; kill on anything else.
    Allowlist,
    /// Deny listed syscalls; allow everything else.
    Denylist,
    /// Audit listed syscalls (log and allow); kill on unlisted (allowlist mode).
    AuditAllowlist,
    /// Audit listed syscalls (log and allow); allow everything else.
    AuditDenylist,
}

impl fmt::Display for PolicyKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Allowlist => write!(f, "allowlist"),
            Self::Denylist => write!(f, "denylist"),
            Self::AuditAllowlist => write!(f, "audit-allowlist"),
            Self::AuditDenylist => write!(f, "audit-denylist"),
        }
    }
}

// ─── ArgFilter ────────────────────────────────────────────────────────────────

/// A filter on a single syscall argument.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ArgFilter {
    /// Argument must equal `value`.
    Eq(u64),
    /// Argument must not equal `value`.
    Ne(u64),
    /// Argument must be < `value`.
    Lt(u64),
    /// Argument must be <= `value`.
    Le(u64),
    /// Argument must be > `value`.
    Gt(u64),
    /// Argument must be >= `value`.
    Ge(u64),
    /// Argument `& mask == flags` (flag set check).
    MaskedEq { mask: u64, value: u64 },
    /// Argument `& mask != 0` (any flag set).
    AnyBit(u64),
}

impl ArgFilter {
    /// Evaluate the filter against `value`.
    #[must_use]
    pub fn matches(&self, arg: u64) -> bool {
        match self {
            Self::Eq(v) => arg == *v,
            Self::Ne(v) => arg != *v,
            Self::Lt(v) => arg < *v,
            Self::Le(v) => arg <= *v,
            Self::Gt(v) => arg > *v,
            Self::Ge(v) => arg >= *v,
            Self::MaskedEq { mask, value } => (arg & mask) == *value,
            Self::AnyBit(mask) => (arg & mask) != 0,
        }
    }

    /// Render as a BPF-like condition string.
    #[must_use]
    pub fn to_bpf_expr(&self, arg_index: usize) -> String {
        let a = format!("args[{arg_index}]");
        match self {
            Self::Eq(v) => format!("{a} == {v:#x}"),
            Self::Ne(v) => format!("{a} != {v:#x}"),
            Self::Lt(v) => format!("{a} < {v:#x}"),
            Self::Le(v) => format!("{a} <= {v:#x}"),
            Self::Gt(v) => format!("{a} > {v:#x}"),
            Self::Ge(v) => format!("{a} >= {v:#x}"),
            Self::MaskedEq { mask, value } => format!("({a} & {mask:#x}) == {value:#x}"),
            Self::AnyBit(mask) => format!("({a} & {mask:#x}) != 0"),
        }
    }
}

impl fmt::Display for ArgFilter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_bpf_expr(0))
    }
}

// ─── SeccompRule ──────────────────────────────────────────────────────────────

/// A single seccomp rule that matches a syscall number with optional argument
/// filters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeccompRule {
    /// Syscall number this rule applies to.
    pub syscall_nr: u64,
    /// Optional canonical syscall name (for documentation).
    pub syscall_name: Option<String>,
    /// Argument filters: index (0..5) → filter.  All filters must match.
    pub arg_filters: HashMap<usize, ArgFilter>,
    /// The action taken when this rule matches.
    pub action: SeccompAction,
    /// Optional human-readable comment.
    pub comment: Option<String>,
}

impl SeccompRule {
    /// Create a rule for `syscall_nr` with action `Allow` and no arg filters.
    #[must_use]
    pub fn allow(syscall_nr: u64) -> Self {
        Self {
            syscall_nr,
            syscall_name: None,
            arg_filters: HashMap::new(),
            action: SeccompAction::Allow,
            comment: None,
        }
    }

    /// Create a rule for `syscall_nr` with action `KillProcess`.
    #[must_use]
    pub fn deny(syscall_nr: u64) -> Self {
        Self {
            syscall_nr,
            syscall_name: None,
            arg_filters: HashMap::new(),
            action: SeccompAction::KillProcess,
            comment: None,
        }
    }

    /// Attach a syscall name.
    #[must_use]
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.syscall_name = Some(name.into());
        self
    }

    /// Attach an argument filter.
    #[must_use]
    pub fn with_arg(mut self, index: usize, filter: ArgFilter) -> Self {
        self.arg_filters.insert(index, filter);
        self
    }

    /// Attach a comment.
    #[must_use]
    pub fn with_comment(mut self, comment: impl Into<String>) -> Self {
        self.comment = Some(comment.into());
        self
    }

    /// Return `true` if `syscall_nr` matches and all arg filters pass.
    #[must_use]
    pub fn matches(&self, nr: u64, args: &[u64; 6]) -> bool {
        if self.syscall_nr != nr {
            return false;
        }
        for (&idx, filter) in &self.arg_filters {
            if idx >= 6 || !filter.matches(args[idx]) {
                return false;
            }
        }
        true
    }
}

impl fmt::Display for SeccompRule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = self
            .syscall_name
            .as_deref()
            .map(|n| format!("/* {n} */"))
            .unwrap_or_default();
        write!(f, "[nr={}] {name} {:?}", self.syscall_nr, self.action)?;
        let mut filters: Vec<_> = self.arg_filters.iter().collect();
        filters.sort_by_key(|&(&i, _)| i);
        for (idx, filt) in filters {
            write!(f, " && {}", filt.to_bpf_expr(*idx))?;
        }
        if let Some(ref c) = self.comment {
            write!(f, "  // {c}")?;
        }
        Ok(())
    }
}

// ─── SeccompAction ────────────────────────────────────────────────────────────

/// The action taken by the kernel when a seccomp filter matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SeccompAction {
    /// Allow the syscall.
    Allow,
    /// Kill the offending thread.
    KillThread,
    /// Kill the entire process.
    KillProcess,
    /// Return `ENOSYS` to the caller.
    Errno(u32),
    /// Send SIGSYS to the process.
    Trap,
    /// Log the syscall and allow it.
    Log,
    /// Notify a userspace supervisor.
    Notify,
}

impl fmt::Display for SeccompAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Allow => write!(f, "ALLOW"),
            Self::KillThread => write!(f, "KILL_THREAD"),
            Self::KillProcess => write!(f, "KILL_PROCESS"),
            Self::Errno(e) => write!(f, "ERRNO({e})"),
            Self::Trap => write!(f, "TRAP"),
            Self::Log => write!(f, "LOG"),
            Self::Notify => write!(f, "NOTIFY"),
        }
    }
}

// ─── BpfFilter ────────────────────────────────────────────────────────────────

/// A simple textual representation of the BPF filter program generated from
/// a set of rules.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BpfFilter {
    /// Lines of the pseudo-BPF program.
    pub instructions: Vec<String>,
    /// Number of rules encoded.
    pub rule_count: usize,
    /// Default action (applied when no rule matches).
    pub default_action: SeccompAction,
}

impl BpfFilter {
    const fn new(default_action: SeccompAction) -> Self {
        Self {
            instructions: Vec::new(),
            rule_count: 0,
            default_action,
        }
    }

    fn push(&mut self, line: impl Into<String>) {
        self.instructions.push(line.into());
    }
}

impl fmt::Display for BpfFilter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "; seccomp BPF filter ({} rules)", self.rule_count)?;
        writeln!(f, "; default action: {}", self.default_action)?;
        for line in &self.instructions {
            writeln!(f, "{line}")?;
        }
        Ok(())
    }
}

// ─── SeccompProfileGenerator ─────────────────────────────────────────────────

/// Builds a seccomp-BPF profile from a set of rules.
///
/// Usage:
/// ```ignore
/// let mut gen = SeccompProfileGenerator::new(PolicyKind::Allowlist);
/// gen.add_rule(SeccompRule::allow(0).with_name("read"));
/// gen.add_rule(SeccompRule::allow(1).with_name("write"));
/// let filter = gen.generate();
/// println!("{filter}");
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeccompProfileGenerator {
    /// The overall policy kind.
    pub policy: PolicyKind,
    /// Registered rules.
    rules: Vec<SeccompRule>,
    /// Default action override (derived from policy if `None`).
    default_action: Option<SeccompAction>,
}

impl SeccompProfileGenerator {
    /// Create a generator with the given policy.
    #[must_use]
    pub const fn new(policy: PolicyKind) -> Self {
        Self {
            policy,
            rules: Vec::new(),
            default_action: None,
        }
    }

    /// Override the default (fallthrough) action.
    #[must_use]
    pub const fn with_default_action(mut self, action: SeccompAction) -> Self {
        self.default_action = Some(action);
        self
    }

    /// Add a rule.
    pub fn add_rule(&mut self, rule: SeccompRule) {
        self.rules.push(rule);
    }

    /// Add a syscall number to the allowlist (simple, no arg filters).
    pub fn allow(&mut self, nr: u64) {
        self.rules.push(SeccompRule::allow(nr));
    }

    /// Add a syscall number to the allowlist with a name annotation.
    pub fn allow_named(&mut self, nr: u64, name: &str) {
        self.rules.push(SeccompRule::allow(nr).with_name(name));
    }

    /// Add a syscall number to the denylist (kills the process on match).
    pub fn deny(&mut self, nr: u64) {
        self.rules.push(SeccompRule::deny(nr));
    }

    /// Add a syscall number to the denylist with a name annotation.
    pub fn deny_named(&mut self, nr: u64, name: &str) {
        self.rules.push(SeccompRule::deny(nr).with_name(name));
    }

    /// Return all registered rules.
    #[must_use]
    pub fn rules(&self) -> &[SeccompRule] {
        &self.rules
    }

    /// Return the effective default action for this policy.
    #[must_use]
    pub const fn effective_default_action(&self) -> SeccompAction {
        if let Some(a) = self.default_action {
            return a;
        }
        match self.policy {
            PolicyKind::Allowlist | PolicyKind::AuditAllowlist => SeccompAction::KillProcess,
            PolicyKind::Denylist | PolicyKind::AuditDenylist => SeccompAction::Allow,
        }
    }

    /// Simulate running the profile against `(nr, args)` and return the action.
    #[must_use]
    pub fn simulate(&self, nr: u64, args: &[u64; 6]) -> SeccompAction {
        for rule in &self.rules {
            if rule.matches(nr, args) {
                return rule.action;
            }
        }
        self.effective_default_action()
    }

    /// Generate the textual BPF filter representation.
    #[must_use]
    pub fn generate(&self) -> BpfFilter {
        let default = self.effective_default_action();
        let mut filter = BpfFilter::new(default);

        filter.push(format!("; policy: {}", self.policy));
        filter.push(format!("; {} rules", self.rules.len()));
        filter.push(String::new());

        // Preamble: load architecture word and validate.
        filter.push("ld  [offsetof(seccomp_data, arch)]".to_owned());
        filter.push("jne #AUDIT_ARCH_X86_64, bad_arch".to_owned());
        filter.push(String::new());

        // Load syscall number.
        filter.push("ld  [offsetof(seccomp_data, nr)]".to_owned());
        filter.push(String::new());

        // Emit one block per rule.
        let mut rule_count = 0usize;
        for rule in &self.rules {
            let name_comment = rule
                .syscall_name
                .as_deref()
                .map(|n| format!("  ; {n}"))
                .unwrap_or_default();

            filter.push(format!("jne #{}, next_{rule_count}{name_comment}", rule.syscall_nr));

            // Arg filters.
            let mut sorted_filters: Vec<(&usize, &ArgFilter)> = rule.arg_filters.iter().collect();
            sorted_filters.sort_by_key(|&(&i, _)| i);
            for (idx, filt) in sorted_filters {
                filter.push(format!("  ; arg check: {}", filt.to_bpf_expr(*idx)));
                filter.push(format!(
                    "  ld  [offsetof(seccomp_data, args[{idx}])]"
                ));
                // Emit a pseudo-instruction for the comparison.
                match filt {
                    ArgFilter::Eq(v) => filter.push(format!("  jne #{v:#x}, next_{rule_count}")),
                    ArgFilter::Ne(v) => filter.push(format!("  jeq #{v:#x}, next_{rule_count}")),
                    ArgFilter::MaskedEq { mask, value } => {
                        filter.push(format!("  and #{mask:#x}"));
                        filter.push(format!("  jne #{value:#x}, next_{rule_count}"));
                    }
                    _ => filter.push(format!("  ; (complex filter: {filt})")),
                }
            }

            filter.push(format!("  ret #{}", action_constant(rule.action)));
            filter.push(format!("next_{rule_count}:"));
            filter.push(String::new());

            rule_count += 1;
        }

        // Default action.
        filter.push("bad_arch:".to_string());
        filter.push(format!("ret #{}", action_constant(SeccompAction::KillProcess)));
        filter.push("default:".to_string());
        filter.push(format!("ret #{}", action_constant(default)));

        filter.rule_count = rule_count;
        filter
    }

    /// Return statistics: counts of rules by action type.
    #[must_use]
    pub fn rule_statistics(&self) -> HashMap<String, usize> {
        let mut map: HashMap<String, usize> = HashMap::new();
        for rule in &self.rules {
            *map.entry(rule.action.to_string()).or_insert(0) += 1;
        }
        map
    }

    /// Return all syscall numbers present in the rule set (deduplicated).
    #[must_use]
    pub fn covered_syscall_numbers(&self) -> Vec<u64> {
        let mut nrs: Vec<u64> = self.rules.iter().map(|r| r.syscall_nr).collect();
        nrs.sort_unstable();
        nrs.dedup();
        nrs
    }

    /// Return `true` if syscall `nr` is explicitly listed in the rules.
    #[must_use]
    pub fn is_covered(&self, nr: u64) -> bool {
        self.rules.iter().any(|r| r.syscall_nr == nr)
    }
}

/// Return the kernel constant string for an action.
const fn action_constant(action: SeccompAction) -> &'static str {
    match action {
        SeccompAction::Allow => "SECCOMP_RET_ALLOW",
        SeccompAction::KillThread => "SECCOMP_RET_KILL_THREAD",
        SeccompAction::KillProcess => "SECCOMP_RET_KILL_PROCESS",
        SeccompAction::Errno(_) => "SECCOMP_RET_ERRNO",
        SeccompAction::Trap => "SECCOMP_RET_TRAP",
        SeccompAction::Log => "SECCOMP_RET_LOG",
        SeccompAction::Notify => "SECCOMP_RET_USER_NOTIF",
    }
}

// ─── Convenience builders ─────────────────────────────────────────────────────

/// Build a minimal allowlist profile for a sandboxed process that only needs
/// `read`, `write`, `exit`, and `exit_group`.
#[must_use]
pub fn minimal_sandbox_profile() -> SeccompProfileGenerator {
    let mut generator = SeccompProfileGenerator::new(PolicyKind::Allowlist);
    generator.allow_named(0, "read");
    generator.allow_named(1, "write");
    generator.allow_named(60, "exit");
    generator.allow_named(231, "exit_group");
    generator
}

/// Build a denylist that blocks `ptrace` and `process_vm_readv/writev`.
#[must_use]
pub fn anti_debug_profile() -> SeccompProfileGenerator {
    let mut generator = SeccompProfileGenerator::new(PolicyKind::Denylist);
    generator.deny_named(101, "ptrace");
    generator.deny_named(310, "process_vm_readv");
    generator.deny_named(311, "process_vm_writev");
    generator.deny_named(62, "kill");
    generator
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_allowlist_default_kills() {
        let generator = SeccompProfileGenerator::new(PolicyKind::Allowlist);
        assert_eq!(generator.effective_default_action(), SeccompAction::KillProcess);
    }

    #[test]
    fn test_denylist_default_allows() {
        let generator = SeccompProfileGenerator::new(PolicyKind::Denylist);
        assert_eq!(generator.effective_default_action(), SeccompAction::Allow);
    }

    #[test]
    fn test_simulate_allowlist_allows_listed() {
        let mut generator = SeccompProfileGenerator::new(PolicyKind::Allowlist);
        generator.allow(0); // read
        let action = generator.simulate(0, &[0u64; 6]);
        assert_eq!(action, SeccompAction::Allow);
    }

    #[test]
    fn test_simulate_allowlist_kills_unlisted() {
        let mut generator = SeccompProfileGenerator::new(PolicyKind::Allowlist);
        generator.allow(0);
        let action = generator.simulate(1, &[0u64; 6]);
        assert_eq!(action, SeccompAction::KillProcess);
    }

    #[test]
    fn test_arg_filter_eq_matches() {
        let f = ArgFilter::Eq(0x5000);
        assert!(f.matches(0x5000));
        assert!(!f.matches(0x5001));
    }

    #[test]
    fn test_arg_filter_masked_eq() {
        let f = ArgFilter::MaskedEq { mask: 0xffff, value: 0x0002 };
        assert!(f.matches(0xdead_0002));
        assert!(!f.matches(0xdead_0003));
    }

    #[test]
    fn test_rule_with_arg_filter() {
        let rule = SeccompRule::allow(0).with_arg(0, ArgFilter::Eq(3));
        assert!(rule.matches(0, &[3, 0, 0, 0, 0, 0]));
        assert!(!rule.matches(0, &[4, 0, 0, 0, 0, 0]));
        assert!(!rule.matches(1, &[3, 0, 0, 0, 0, 0]));
    }

    #[test]
    fn test_generate_produces_instructions() {
        let mut generator = SeccompProfileGenerator::new(PolicyKind::Allowlist);
        generator.allow_named(0, "read");
        generator.allow_named(1, "write");
        let filter = generator.generate();
        assert!(!filter.instructions.is_empty());
        assert_eq!(filter.rule_count, 2);
    }

    #[test]
    fn test_covered_syscall_numbers() {
        let mut generator = SeccompProfileGenerator::new(PolicyKind::Allowlist);
        generator.allow(5);
        generator.allow(5); // duplicate
        generator.allow(10);
        let nrs = generator.covered_syscall_numbers();
        assert_eq!(nrs, vec![5, 10]);
    }

    #[test]
    fn test_minimal_sandbox_profile_covers_exit() {
        let generator = minimal_sandbox_profile();
        assert!(generator.is_covered(60));
        assert!(generator.is_covered(231));
    }

    #[test]
    fn test_anti_debug_blocks_ptrace() {
        let generator = anti_debug_profile();
        let action = generator.simulate(101, &[0u64; 6]);
        assert_eq!(action, SeccompAction::KillProcess);
    }

    #[test]
    fn test_anti_debug_allows_read() {
        let generator = anti_debug_profile();
        let action = generator.simulate(0, &[0u64; 6]);
        assert_eq!(action, SeccompAction::Allow);
    }
}
