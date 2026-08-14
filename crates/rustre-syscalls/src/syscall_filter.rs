//! Syscall filtering and policy engine.
//!
//! Provides:
//! - **seccomp-BPF analyzer**: decodes raw BPF filter programs into
//!   human-readable allowlist/denylist rules.
//! - **Policy generator**: emits Rust code or JSON for seccomp policy.
//! - **Violation predictor**: given a known policy, flags dangerous calls.
//! - **Audit trail**: structured log with severity classification.

use std::collections::HashSet;
use std::fmt::Write as _;

use serde::{Deserialize, Serialize};

use crate::{OsFamily, SyscallArch};
use crate::{SyscallCategory};
use crate::syscall_table::SyscallDb;

// ─── BPF opcodes (seccomp subset) ─────────────────────────────────────────────

const BPF_LD: u16 = 0x00;
const BPF_JMP: u16 = 0x05;
const BPF_RET: u16 = 0x06;

const BPF_ABS: u16 = 0x20;

const BPF_JEQ: u16 = 0x10;

const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
const SECCOMP_RET_KILL_THREAD: u32 = 0x0000_0000;
const SECCOMP_RET_TRAP: u32 = 0x0003_0000;
const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
const SECCOMP_RET_TRACE: u32 = 0x7ff0_0000;
const SECCOMP_RET_LOG: u32 = 0x7ffc_0000;
const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
const SECCOMP_RET_DATA_MASK: u32 = 0x0000_ffff;

// ─── BPF instruction ──────────────────────────────────────────────────────────

/// A single BPF instruction (8 bytes, classic BPF encoding).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BpfInsn {
    pub code: u16,
    pub jt: u8,
    pub jf: u8,
    pub k: u32,
}

impl BpfInsn {
    /// Parse a slice of 8 bytes (little-endian) into a BPF instruction.
    #[must_use] 
    pub fn from_bytes(b: &[u8]) -> Option<Self> {
        if b.len() < 8 { return None; }
        Some(Self {
            code: u16::from_le_bytes([b[0], b[1]]),
            jt: b[2],
            jf: b[3],
            k: u32::from_le_bytes([b[4], b[5], b[6], b[7]]),
        })
    }
}

// ─── Seccomp action ───────────────────────────────────────────────────────────

/// Decoded seccomp return action.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SeccompAction {
    Allow,
    KillProcess,
    KillThread,
    Trap,
    Errno(u16),
    Trace(u16),
    Log,
    Unknown(u32),
}

impl SeccompAction {
    #[must_use] 
    pub const fn from_retval(v: u32) -> Self {
        let action = v & !SECCOMP_RET_DATA_MASK;
        let data = (v & SECCOMP_RET_DATA_MASK) as u16;
        match action {
            x if x == SECCOMP_RET_ALLOW => Self::Allow,
            x if x == SECCOMP_RET_KILL_PROCESS => Self::KillProcess,
            x if x == SECCOMP_RET_KILL_THREAD => Self::KillThread,
            x if x == SECCOMP_RET_TRAP => Self::Trap,
            x if x == SECCOMP_RET_ERRNO => Self::Errno(data),
            x if x == SECCOMP_RET_TRACE => Self::Trace(data),
            x if x == SECCOMP_RET_LOG => Self::Log,
            other => Self::Unknown(other),
        }
    }
}

impl std::fmt::Display for SeccompAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Allow => write!(f, "ALLOW"),
            Self::KillProcess => write!(f, "KILL_PROCESS"),
            Self::KillThread => write!(f, "KILL_THREAD"),
            Self::Trap => write!(f, "TRAP"),
            Self::Errno(e) => write!(f, "ERRNO({e})"),
            Self::Trace(t) => write!(f, "TRACE({t:#x})"),
            Self::Log => write!(f, "LOG"),
            Self::Unknown(v) => write!(f, "UNKNOWN({v:#x})"),
        }
    }
}

// ─── Decoded rule ─────────────────────────────────────────────────────────────

/// A single human-readable rule extracted from a seccomp BPF program.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeccompRule {
    /// Syscall number this rule applies to (None = any / default).
    pub syscall_nr: Option<u64>,
    /// Symbolic name, if resolvable.
    pub syscall_name: Option<String>,
    /// Additional argument conditions.
    pub arg_conditions: Vec<ArgCondition>,
    /// Action to apply when rule matches.
    pub action: SeccompAction,
}

/// A condition on a single syscall argument.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArgCondition {
    pub arg_index: u8,
    pub op: CondOp,
    pub value: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CondOp {
    Eq,
    Ne,
    Gt,
    Ge,
    Lt,
    Le,
    MaskedEq(u64),
}

impl std::fmt::Display for CondOp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Eq => write!(f, "=="),
            Self::Ne => write!(f, "!="),
            Self::Gt => write!(f, ">"),
            Self::Ge => write!(f, ">="),
            Self::Lt => write!(f, "<"),
            Self::Le => write!(f, "<="),
            Self::MaskedEq(m) => write!(f, "& {m:#x} =="),
        }
    }
}

// ─── BPF analyzer ─────────────────────────────────────────────────────────────

/// Decompiles a raw seccomp-BPF filter program into human-readable rules.
pub struct BpfAnalyzer {
    db: SyscallDb,
    os: OsFamily,
    arch: SyscallArch,
}

impl BpfAnalyzer {
    #[must_use] 
    pub fn new(os: OsFamily, arch: SyscallArch) -> Self {
        Self { db: SyscallDb::new(), os, arch }
    }

    /// Parse raw bytes into a BPF instruction list.
    pub fn parse_program(bytes: &[u8]) -> Vec<BpfInsn> {
        bytes.chunks_exact(8).filter_map(BpfInsn::from_bytes).collect()
    }

    /// Decompile a program into human-readable rules.
    #[must_use] 
    pub fn decompile(&self, program: &[BpfInsn]) -> Vec<SeccompRule> {
        let mut rules = Vec::new();
        let mut i = 0;
        let mut current_syscall: Option<u64> = None;
        let mut arg_conditions: Vec<ArgCondition> = Vec::new();

        while i < program.len() {
            let insn = &program[i];
            let class = insn.code & 0x07;

            match class {
                x if x == BPF_LD => {
                    // LD ABS offset 0 = architecture; offset 4 = syscall nr
                    if insn.code & 0x38 == BPF_ABS && insn.k == 4 {
                            // next instruction probably does JEQ to syscall nr
                    }
                }
                x if x == BPF_JMP => {
                    let op = insn.code & 0xf0;
                    if op == BPF_JEQ {
                        // Heuristic: if a BPF_LD ABS 4 preceded this, it's a syscall nr check
                        if i > 0 && (program[i - 1].code & 0x38 == BPF_ABS) && program[i - 1].k == 4 {
                            current_syscall = Some(u64::from(insn.k));
                        } else if i > 0 && (program[i - 1].code & 0x38 == BPF_ABS) {
                            // arg condition
                            let arg_off = program[i - 1].k;
                            let arg_idx = u8::try_from((arg_off.saturating_sub(16)) / 8).unwrap_or(u8::MAX);
                            arg_conditions.push(ArgCondition {
                                arg_index: arg_idx,
                                op: CondOp::Eq,
                                value: u64::from(insn.k),
                            });
                        }
                    }
                }
                x if x == BPF_RET => {
                    let action = SeccompAction::from_retval(insn.k);
                    let syscall_name = current_syscall
                        .and_then(|nr| self.db.lookup_by_number(self.os, nr))
                        .map(|e| e.name.clone());
                    rules.push(SeccompRule {
                        syscall_nr: current_syscall,
                        syscall_name,
                        arg_conditions: std::mem::take(&mut arg_conditions),
                        action,
                    });
                    current_syscall = None;
                }
                _ => {}
            }
            i += 1;
        }
        rules
    }

    /// Format rules as an annotated text report.
    #[must_use] 
    pub fn format_report(&self, rules: &[SeccompRule]) -> String {
        let mut out = String::new();
        writeln!(out, "=== seccomp-BPF Filter Analysis ===").ok();
        writeln!(out, "OS: {:?}  Arch: {:?}", self.os, self.arch).ok();
        writeln!(out, "Rules: {}", rules.len()).ok();
        writeln!(out).ok();

        for (i, rule) in rules.iter().enumerate() {
            let name = rule.syscall_name.as_deref().unwrap_or("?");
            let nr_str = rule.syscall_nr.map_or_else(|| "any".into(), |n| format!("#{n}"));
            write!(out, "[{i:3}] syscall {nr_str} ({name})").ok();
            if !rule.arg_conditions.is_empty() {
                write!(out, " when ").ok();
                for (j, cond) in rule.arg_conditions.iter().enumerate() {
                    if j > 0 { write!(out, " && ").ok(); }
                    write!(out, "arg{} {} {:#x}", cond.arg_index, cond.op, cond.value).ok();
                }
            }
            writeln!(out, " → {}", rule.action).ok();
        }
        out
    }
}

// ─── Policy types ─────────────────────────────────────────────────────────────

/// Disposition for syscalls not explicitly listed in a policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DefaultAction {
    Allow,
    Deny,
    KillProcess,
}

/// A high-level seccomp policy: allowlist + denylist + default action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeccompPolicy {
    pub name: String,
    pub default_action: DefaultAction,
    pub allowlist: HashSet<String>,
    pub denylist: HashSet<String>,
    pub arch: SyscallArch,
    pub os: OsFamily,
}

impl SeccompPolicy {
    /// Create a strict allowlist policy (deny-by-default).
    pub fn strict(name: impl Into<String>, arch: SyscallArch, os: OsFamily) -> Self {
        Self {
            name: name.into(),
            default_action: DefaultAction::KillProcess,
            allowlist: HashSet::new(),
            denylist: HashSet::new(),
            arch,
            os,
        }
    }

    /// Add syscalls to the allowlist by name.
    pub fn allow(&mut self, syscalls: impl IntoIterator<Item = impl Into<String>>) {
        for s in syscalls { self.allowlist.insert(s.into()); }
    }

    /// Add syscalls to the denylist.
    pub fn deny(&mut self, syscalls: impl IntoIterator<Item = impl Into<String>>) {
        for s in syscalls { self.denylist.insert(s.into()); }
    }

    /// Check whether a syscall name would be allowed by this policy.
    #[must_use] 
    pub fn is_allowed(&self, name: &str) -> bool {
        if self.denylist.contains(name) { return false; }
        if self.allowlist.contains(name) { return true; }
        self.default_action == DefaultAction::Allow
    }

    /// Generate a minimal Rust snippet that installs this policy via `seccomp`.
    #[must_use] 
    pub fn generate_rust_code(&self) -> String {
        let mut out = String::new();
        writeln!(out, "// Auto-generated seccomp policy: {}", self.name).ok();
        writeln!(out, "fn install_seccomp_policy() {{").ok();
        writeln!(out, "    use libseccomp::{{ScmpFilterContext, ScmpAction, ScmpSyscall}};").ok();
        let default = match self.default_action {
            DefaultAction::Allow => "ScmpAction::Allow",
            DefaultAction::Deny => "ScmpAction::Errno(1)",
            DefaultAction::KillProcess => "ScmpAction::KillProcess",
        };
        writeln!(out, "    let mut ctx = ScmpFilterContext::new_filter({default}).unwrap();").ok();
        if !self.allowlist.is_empty() {
            writeln!(out, "    // Allowlist").ok();
            for s in &self.allowlist {
                writeln!(out, "    ctx.add_rule(ScmpAction::Allow, ScmpSyscall::new(\"{s}\")).unwrap();").ok();
            }
        }
        if !self.denylist.is_empty() {
            writeln!(out, "    // Denylist").ok();
            for s in &self.denylist {
                writeln!(out, "    ctx.add_rule(ScmpAction::KillProcess, ScmpSyscall::new(\"{s}\")).unwrap();").ok();
            }
        }
        writeln!(out, "    ctx.load().unwrap();").ok();
        writeln!(out, "}}").ok();
        out
    }

    /// Generate JSON representation of the policy.
    #[must_use] 
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "name": self.name,
            "default_action": format!("{:?}", self.default_action),
            "allowlist": sorted_vec(&self.allowlist),
            "denylist": sorted_vec(&self.denylist),
        })
    }
}

fn sorted_vec(set: &HashSet<String>) -> Vec<&str> {
    let mut v: Vec<&str> = set.iter().map(std::string::String::as_str).collect();
    v.sort_unstable();
    v
}

// ─── Common policy presets ───────────────────────────────────────────────────

/// Return a policy suitable for a sandboxed network service (no exec, no fork,
/// no filesystem writes, network I/O allowed).
#[must_use] 
pub fn preset_network_service(arch: SyscallArch) -> SeccompPolicy {
    let mut p = SeccompPolicy::strict("network_service", arch, OsFamily::Linux);
    p.allow([
        "read", "write", "recvfrom", "sendto", "recvmsg", "sendmsg",
        "accept", "accept4", "connect", "bind", "listen", "getsockopt", "setsockopt",
        "socket", "close", "epoll_wait", "epoll_ctl", "epoll_create1",
        "poll", "select", "nanosleep", "clock_gettime", "gettimeofday",
        "mmap", "mprotect", "munmap", "brk",
        "futex", "exit_group", "exit", "getpid", "gettid",
        "sigreturn", "rt_sigreturn", "rt_sigaction", "rt_sigprocmask",
    ]);
    p.deny(["execve", "execveat", "fork", "vfork", "clone", "ptrace", "perf_event_open", "kexec_load"]);
    p
}

/// Return a minimal policy suitable for a read-only file processing tool.
#[must_use] 
pub fn preset_file_reader(arch: SyscallArch) -> SeccompPolicy {
    let mut p = SeccompPolicy::strict("file_reader", arch, OsFamily::Linux);
    p.allow([
        "read", "write", "open", "openat", "close", "stat", "fstat", "lstat",
        "lseek", "mmap", "mprotect", "munmap", "brk",
        "exit_group", "exit", "futex",
        "sigreturn", "rt_sigreturn",
    ]);
    p
}

// ─── Violation predictor ──────────────────────────────────────────────────────

/// Severity of a policy violation.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ViolationSeverity {
    Info,
    Warning,
    Critical,
}

/// A predicted or observed policy violation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyViolation {
    pub syscall_name: String,
    pub syscall_nr: u64,
    pub severity: ViolationSeverity,
    pub reason: String,
    pub category: SyscallCategory,
}

/// Checks a list of observed syscall names against a policy and returns violations.
#[must_use] 
pub fn predict_violations(
    policy: &SeccompPolicy,
    observed: &[(&str, u64)],
    db: &SyscallDb,
) -> Vec<PolicyViolation> {
    let mut violations = Vec::new();
    for &(name, nr) in observed {
        if !policy.is_allowed(name) {
            let category = db.lookup_by_number(policy.os, nr)
                .map_or(SyscallCategory::Unknown, |e| crate::categorize_by_name(&e.name));
            let severity = match &category {
                SyscallCategory::Process => ViolationSeverity::Critical,
                SyscallCategory::Memory => ViolationSeverity::Warning,
                _ => ViolationSeverity::Info,
            };
            violations.push(PolicyViolation {
                syscall_name: name.to_string(),
                syscall_nr: nr,
                severity,
                reason: format!("syscall '{name}' not permitted by policy '{}'", policy.name),
                category,
            });
        }
    }
    violations.sort_by(|a, b| b.severity.cmp(&a.severity));
    violations
}

// ─── Audit trail ──────────────────────────────────────────────────────────────

/// A structured audit log entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub timestamp_ns: u64,
    pub pid: u32,
    pub tid: u32,
    pub syscall_name: String,
    pub syscall_nr: u64,
    pub args_hex: Vec<u64>,
    pub retval: i64,
    pub category: SyscallCategory,
    pub policy_violation: Option<PolicyViolation>,
}

/// In-memory audit trail with ring-buffer semantics.
pub struct AuditTrail {
    entries: std::collections::VecDeque<AuditEntry>,
    max_entries: usize,
    violation_count: usize,
}

impl AuditTrail {
    #[must_use] 
    pub const fn new(max_entries: usize) -> Self {
        Self { entries: std::collections::VecDeque::new(), max_entries, violation_count: 0 }
    }

    pub fn push(&mut self, entry: AuditEntry) {
        if entry.policy_violation.is_some() { self.violation_count += 1; }
        if self.entries.len() >= self.max_entries { self.entries.pop_front(); }
        self.entries.push_back(entry);
    }

    pub fn entries(&self) -> impl Iterator<Item = &AuditEntry> {
        self.entries.iter()
    }

    #[must_use] 
    pub const fn violation_count(&self) -> usize { self.violation_count }

    pub fn violations(&self) -> impl Iterator<Item = &AuditEntry> {
        self.entries.iter().filter(|e| e.policy_violation.is_some())
    }

    /// Export the audit trail as JSON lines.
    #[must_use] 
    pub fn export_jsonl(&self) -> String {
        self.entries
            .iter()
            .filter_map(|e| serde_json::to_string(e).ok())
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Generate a summary report.
    #[must_use] 
    pub fn summary(&self) -> String {
        let mut freq: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
        for e in &self.entries { *freq.entry(&e.syscall_name).or_insert(0) += 1; }
        let mut out = String::new();
        writeln!(out, "Audit Trail Summary").ok();
        writeln!(out, "  Total entries : {}", self.entries.len()).ok();
        writeln!(out, "  Violations    : {}", self.violation_count).ok();
        writeln!(out, "  Top syscalls  :").ok();
        let mut freq_vec: Vec<_> = freq.into_iter().collect();
        freq_vec.sort_by(|a, b| b.1.cmp(&a.1));
        for (name, count) in freq_vec.iter().take(10) {
            writeln!(out, "    {name:20} {count}").ok();
        }
        out
    }
}

// ─── Policy diff and merge ────────────────────────────────────────────────────

/// Compute the difference between two policies.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyDiff {
    /// Syscalls allowed in A but not B.
    pub only_in_a: Vec<String>,
    /// Syscalls allowed in B but not A.
    pub only_in_b: Vec<String>,
    /// Syscalls allowed in both.
    pub in_both: Vec<String>,
}

#[must_use] 
pub fn diff_policies(a: &SeccompPolicy, b: &SeccompPolicy) -> PolicyDiff {
    let mut only_in_a: Vec<String> = a.allowlist.difference(&b.allowlist).cloned().collect();
    let mut only_in_b: Vec<String> = b.allowlist.difference(&a.allowlist).cloned().collect();
    let mut in_both: Vec<String> = a.allowlist.intersection(&b.allowlist).cloned().collect();
    only_in_a.sort();
    only_in_b.sort();
    in_both.sort();
    PolicyDiff { only_in_a, only_in_b, in_both }
}

/// Merge two policies: allowlist = union; denylist = union; default = stricter.
pub fn merge_policies(a: &SeccompPolicy, b: &SeccompPolicy, name: impl Into<String>) -> SeccompPolicy {
    let mut merged = SeccompPolicy::strict(name, a.arch, a.os);
    merged.allowlist = a.allowlist.union(&b.allowlist).cloned().collect();
    merged.denylist = a.denylist.union(&b.denylist).cloned().collect();
    // Stricter default action
    merged.default_action = if a.default_action == DefaultAction::KillProcess
        || b.default_action == DefaultAction::KillProcess
    {
        DefaultAction::KillProcess
    } else if a.default_action == DefaultAction::Deny || b.default_action == DefaultAction::Deny {
        DefaultAction::Deny
    } else {
        DefaultAction::Allow
    };
    merged
}

// ─── BPF instruction disassembler ────────────────────────────────────────────

/// Disassemble a BPF program to a textual representation.
#[must_use] 
pub fn disassemble_bpf(program: &[BpfInsn]) -> String {
    let mut out = String::new();
    for (i, insn) in program.iter().enumerate() {
        let class = insn.code & 0x07;
        let mnemonic = match class {
            0 => "LD",
            1 => "LDX",
            2 => "ST",
            3 => "STX",
            4 => "ALU",
            5 => {
                let op = insn.code & 0xf0;
                match op {
                    0x00 => "JA",
                    0x10 => "JEQ",
                    0x20 => "JGT",
                    0x30 => "JGE",
                    0x40 => "JSET",
                    _ => "JMP",
                }
            }
            6 => "RET",
            7 => "MISC",
            _ => "???",
        };
        writeln!(
            out,
            "  [{i:3}] {mnemonic:6} code={:#06x} jt={} jf={} k={:#010x}",
            insn.code, insn.jt, insn.jf, insn.k
        ).ok();
        // Annotate RET instructions
        if class == 6 {
            let action = SeccompAction::from_retval(insn.k);
            writeln!(out, "         → return {action}").ok();
        }
    }
    out
}

// ─── Policy coverage checker ─────────────────────────────────────────────────

/// Check which syscalls in a policy are actually used by a known workload.
pub struct PolicyCoverageChecker<'a> {
    policy: &'a SeccompPolicy,
}

impl<'a> PolicyCoverageChecker<'a> {
    #[must_use] 
    pub const fn new(policy: &'a SeccompPolicy) -> Self { Self { policy } }

    /// Given a list of (name, count) observed syscalls, compute:
    /// - Which allowlisted syscalls were actually used.
    /// - Which allowlisted syscalls were never used (over-permissive).
    pub fn check(&self, observed: &[(&str, u64)]) -> PolicyCoverageReport {
        let observed_names: HashSet<&str> = observed.iter().map(|(n, _)| *n).collect();
        let mut used: Vec<String> = self.policy.allowlist.iter()
            .filter(|n| observed_names.contains(n.as_str()))
            .cloned()
            .collect();
        let mut unused: Vec<String> = self.policy.allowlist.iter()
            .filter(|n| !observed_names.contains(n.as_str()))
            .cloned()
            .collect();
        let mut not_in_policy: Vec<String> = observed_names.iter()
            .filter(|&&n| !self.policy.allowlist.contains(n) && !self.policy.denylist.contains(n))
            .map(std::string::ToString::to_string)
            .collect();
        used.sort();
        unused.sort();
        not_in_policy.sort();
        PolicyCoverageReport { used, unused, not_in_policy }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyCoverageReport {
    /// Syscalls in the allowlist that were observed.
    pub used: Vec<String>,
    /// Syscalls in the allowlist that were never observed (can be removed).
    pub unused: Vec<String>,
    /// Observed syscalls not explicitly in the policy (potential additions).
    pub not_in_policy: Vec<String>,
}

impl PolicyCoverageReport {
    #[must_use] 
    pub fn format(&self) -> String {
        let mut out = String::new();
        writeln!(out, "Policy Coverage Report").ok();
        writeln!(out, "  Used syscalls    : {} (keep)", self.used.len()).ok();
        writeln!(out, "  Unused allowlist : {} (consider removing)", self.unused.len()).ok();
        writeln!(out, "  Not in policy    : {} (consider adding or investigating)", self.not_in_policy.len()).ok();
        if !self.unused.is_empty() {
            writeln!(out, "\n  Unused:").ok();
            for s in &self.unused { writeln!(out, "    - {s}").ok(); }
        }
        if !self.not_in_policy.is_empty() {
            writeln!(out, "\n  Not in policy:").ok();
            for s in &self.not_in_policy { writeln!(out, "    - {s}").ok(); }
        }
        out
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_seccomp_action_decode() {
        assert_eq!(SeccompAction::from_retval(SECCOMP_RET_ALLOW), SeccompAction::Allow);
        assert_eq!(SeccompAction::from_retval(SECCOMP_RET_KILL_PROCESS), SeccompAction::KillProcess);
        assert_eq!(SeccompAction::from_retval(SECCOMP_RET_ERRNO | 13), SeccompAction::Errno(13));
    }

    #[test]
    fn test_policy_allow_deny() {
        let mut p = SeccompPolicy::strict("test", SyscallArch::X86_64, OsFamily::Linux);
        p.allow(["read", "write", "close"]);
        assert!(p.is_allowed("read"));
        assert!(!p.is_allowed("execve"));
    }

    #[test]
    fn test_policy_rust_codegen() {
        let p = preset_network_service(SyscallArch::X86_64);
        let code = p.generate_rust_code();
        assert!(code.contains("ScmpFilterContext"));
        assert!(code.contains("execve") || code.contains("KillProcess"));
    }

    #[test]
    fn test_audit_trail_ring_buffer() {
        let mut trail = AuditTrail::new(3);
        for i in 0..5u64 {
            trail.push(AuditEntry {
                timestamp_ns: i * 1000,
                pid: 1, tid: 1,
                syscall_name: format!("sc{i}"),
                syscall_nr: i,
                args_hex: vec![],
                retval: 0,
                category: SyscallCategory::Unknown,
                policy_violation: None,
            });
        }
        assert_eq!(trail.entries().count(), 3);
    }
}
