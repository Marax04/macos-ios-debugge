//! Memory protection and permission modelling.
//!
//! This module provides:
//!
//! - [`Permissions`] — a compact bitflag set for page-level memory protection
//!   with `READ`, `WRITE`, `EXECUTE` and several platform extension bits.
//! - [`PermissionSet`] — a time-ordered log of permission changes on a range.
//! - [`MemoryProtection`] — platform-specific constants (`PROT_*`, `PAGE_*`,
//!   `VM_PROT_*`) with bidirectional conversion from/to [`Permissions`].
//! - [`PermissionPolicy`] — a simple allow/deny rule set.
//! - [`InheritFlags`] — semantics for how child processes inherit memory regions.

use serde::{Deserialize, Deserializer, Serialize, Serializer};

// ─────────────────────────────────────────────────────────────────────────────
// Permissions
// ─────────────────────────────────────────────────────────────────────────────

bitflags::bitflags! {
    /// Page-level memory protection flags.
    ///
    /// | Flag              | Meaning                                                |
    /// |-------------------|--------------------------------------------------------|
    /// | `READ`            | Page is readable.                                      |
    /// | `WRITE`           | Page is writable.                                      |
    /// | `EXECUTE`         | Page is executable.                                    |
    /// | `COPY_ON_WRITE`   | Copy-on-write semantics (e.g. shared library mappings).|
    /// | `SHARED`          | Region is shared with other processes.                 |
    /// | `GUARD`           | Guard page — access raises an exception.               |
    /// | `NOCACHE`         | Mapped as uncacheable (device memory, MMIO).           |
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct Permissions: u8 {
        /// No access.
        const NONE          = 0;
        /// Read access.
        const READ          = 1 << 0;
        /// Write access.
        const WRITE         = 1 << 1;
        /// Execute access.
        const EXECUTE       = 1 << 2;
        /// Copy-on-write semantics.
        const COPY_ON_WRITE = 1 << 3;
        /// Shared mapping.
        const SHARED        = 1 << 4;
        /// Guard page.
        const GUARD         = 1 << 5;
        /// Non-cacheable.
        const NOCACHE       = 1 << 6;
    }
}

impl Permissions {
    /// Return `true` if the `READ` flag is set.
    #[must_use]
    pub const fn is_readable(self) -> bool {
        self.contains(Self::READ)
    }

    /// Return `true` if the `WRITE` flag is set.
    #[must_use]
    pub const fn is_writable(self) -> bool {
        self.contains(Self::WRITE)
    }

    /// Return `true` if the `EXECUTE` flag is set.
    #[must_use]
    pub const fn is_executable(self) -> bool {
        self.contains(Self::EXECUTE)
    }

    /// Return `true` if the `COPY_ON_WRITE` flag is set.
    #[must_use]
    pub const fn is_copy_on_write(self) -> bool {
        self.contains(Self::COPY_ON_WRITE)
    }

    /// Return `true` if the `SHARED` flag is set.
    #[must_use]
    pub const fn is_shared(self) -> bool {
        self.contains(Self::SHARED)
    }

    /// Return `true` if this is a guard page.
    #[must_use]
    pub const fn is_guard(self) -> bool {
        self.contains(Self::GUARD)
    }

    /// Return `true` if the mapping is uncacheable.
    #[must_use]
    pub const fn is_nocache(self) -> bool {
        self.contains(Self::NOCACHE)
    }

    /// Return `true` if no access flags are set.
    #[must_use]
    pub const fn is_none(self) -> bool {
        self.bits() == 0
    }

    /// Common read-write combination.
    pub const RW: Self = Self::READ.union(Self::WRITE);

    /// Common read-execute combination (code segment).
    pub const RX: Self = Self::READ.union(Self::EXECUTE);

    /// Full read-write-execute (dangerous, but modelled for completeness).
    pub const RWX: Self = Self::READ.union(Self::WRITE).union(Self::EXECUTE);

    /// Return a short ASCII string like `"r-x"` (similar to `/proc/maps`).
    #[must_use]
    pub fn as_rwx_string(self) -> String {
        let r = if self.is_readable() { 'r' } else { '-' };
        let w = if self.is_writable() { 'w' } else { '-' };
        let x = if self.is_executable() { 'x' } else { '-' };
        format!("{r}{w}{x}")
    }

    /// Parse a three-character `"rwx"` string (dashes allowed for absent bits).
    ///
    /// # Errors
    /// Returns `None` if the string has the wrong length or contains invalid characters.
    #[must_use]
    pub fn from_rwx_string(s: &str) -> Option<Self> {
        let chars: Vec<char> = s.chars().collect();
        if chars.len() != 3 {
            return None;
        }
        let mut perms = Self::NONE;
        match chars[0] {
            'r' => perms |= Self::READ,
            '-' => {}
            _ => return None,
        }
        match chars[1] {
            'w' => perms |= Self::WRITE,
            '-' => {}
            _ => return None,
        }
        match chars[2] {
            'x' => perms |= Self::EXECUTE,
            '-' => {}
            _ => return None,
        }
        Some(perms)
    }

    /// Add the given flags, returning a new `Permissions`.
    #[must_use]
    pub const fn with(self, other: Self) -> Self {
        self.union(other)
    }

    /// Remove the given flags, returning a new `Permissions`.
    #[must_use]
    pub const fn without(self, other: Self) -> Self {
        self.difference(other)
    }
}

impl std::fmt::Display for Permissions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_rwx_string())
    }
}

impl Serialize for Permissions {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u8(self.bits())
    }
}

impl<'de> Deserialize<'de> for Permissions {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bits = u8::deserialize(deserializer)?;
        Ok(Self::from_bits_truncate(bits))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PermissionChange & PermissionSet
// ─────────────────────────────────────────────────────────────────────────────

/// A single permission-change event recorded for an address range.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PermissionChange {
    /// The old permissions (before the change).
    pub old: Permissions,
    /// The new permissions (after the change).
    pub new: Permissions,
    /// An optional textual reason (e.g. `"mprotect syscall"`, `"loader mapping"`).
    pub reason: Option<String>,
    /// Sequence number (monotonically increasing within a `PermissionSet`).
    pub seq: u64,
}

impl PermissionChange {
    /// Construct a new change entry.
    #[must_use]
    pub const fn new(old: Permissions, new: Permissions, seq: u64) -> Self {
        Self {
            old,
            new,
            reason: None,
            seq,
        }
    }

    /// Attach a reason string.
    #[must_use]
    pub fn with_reason(mut self, reason: impl Into<String>) -> Self {
        self.reason = Some(reason.into());
        self
    }

    /// Return the flags that were *added* by this change.
    #[must_use]
    pub const fn flags_added(&self) -> Permissions {
        self.new.difference(self.old)
    }

    /// Return the flags that were *removed* by this change.
    #[must_use]
    pub const fn flags_removed(&self) -> Permissions {
        self.old.difference(self.new)
    }
}

/// Ordered log of permission changes for a single region.
///
/// The `current` field always reflects the latest state, while the `history`
/// vector records every prior transition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PermissionSet {
    /// The currently-effective permissions.
    current: Permissions,
    /// Ordered history of changes (oldest first).
    history: Vec<PermissionChange>,
    /// Next sequence number.
    next_seq: u64,
}

impl PermissionSet {
    /// Create a new set with the given initial permissions.
    #[must_use]
    pub const fn new(initial: Permissions) -> Self {
        Self {
            current: initial,
            history: Vec::new(),
            next_seq: 0,
        }
    }

    /// Return the current permissions.
    #[must_use]
    pub const fn current(&self) -> Permissions {
        self.current
    }

    /// Apply a new permission state, recording the transition.
    ///
    /// If the new permissions are identical to the current ones, the change is
    /// a no-op and nothing is recorded.
    pub fn apply(&mut self, new: Permissions, reason: Option<String>) {
        if new == self.current {
            return;
        }
        let change = PermissionChange {
            old: self.current,
            new,
            reason,
            seq: self.next_seq,
        };
        self.next_seq += 1;
        self.history.push(change);
        self.current = new;
    }

    /// Return the full change history (oldest-first).
    #[must_use]
    pub fn history(&self) -> &[PermissionChange] {
        &self.history
    }

    /// Number of changes recorded.
    #[must_use]
    pub const fn change_count(&self) -> usize {
        self.history.len()
    }

    /// Roll back to the *previous* permission state.
    ///
    /// Returns `true` if a rollback was performed, `false` if there is no history.
    pub fn rollback(&mut self) -> bool {
        if let Some(last) = self.history.pop() {
            self.current = last.old;
            true
        } else {
            false
        }
    }

    /// Return `true` if the permissions have ever been changed.
    #[must_use]
    pub const fn has_history(&self) -> bool {
        !self.history.is_empty()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// MemoryProtection — platform constant mapping
// ─────────────────────────────────────────────────────────────────────────────

/// Platform-specific memory protection constant.
///
/// Each variant carries the platform-native integer representation of the
/// protection flags, along with helper methods to convert to/from
/// [`Permissions`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MemoryProtection {
    // ── Linux (mmap/mprotect) PROT_* ─────────────────────────────────────────
    /// `PROT_NONE` — no access.
    LinuxNone,
    /// `PROT_READ` — pages may be read.
    LinuxRead,
    /// `PROT_WRITE` — pages may be written.
    LinuxWrite,
    /// `PROT_EXEC` — pages may be executed.
    LinuxExec,
    /// `PROT_READ | PROT_WRITE`
    LinuxReadWrite,
    /// `PROT_READ | PROT_EXEC`
    LinuxReadExec,
    /// `PROT_READ | PROT_WRITE | PROT_EXEC`
    LinuxReadWriteExec,

    // ── Windows VirtualAlloc/VirtualProtect PAGE_* ────────────────────────────
    /// `PAGE_NOACCESS`
    WinNoAccess,
    /// `PAGE_READONLY`
    WinReadOnly,
    /// `PAGE_READWRITE`
    WinReadWrite,
    /// `PAGE_WRITECOPY`
    WinWriteCopy,
    /// `PAGE_EXECUTE`
    WinExecute,
    /// `PAGE_EXECUTE_READ`
    WinExecuteRead,
    /// `PAGE_EXECUTE_READWRITE`
    WinExecuteReadWrite,
    /// `PAGE_EXECUTE_WRITECOPY`
    WinExecuteWriteCopy,
    /// `PAGE_GUARD` — guard page modifier.
    WinGuard,

    // ── macOS (mach_vm_protect) VM_PROT_* ─────────────────────────────────────
    /// `VM_PROT_NONE`
    MacNone,
    /// `VM_PROT_READ`
    MacRead,
    /// `VM_PROT_WRITE`
    MacWrite,
    /// `VM_PROT_EXECUTE`
    MacExecute,
    /// `VM_PROT_READ | VM_PROT_WRITE`
    MacReadWrite,
    /// `VM_PROT_READ | VM_PROT_EXECUTE`
    MacReadExecute,
    /// `VM_PROT_ALL`
    MacAll,
}

impl MemoryProtection {
    /// Convert this platform constant to a [`Permissions`] bitset.
    #[must_use]
    pub fn to_permissions(self) -> Permissions {
        match self {
            Self::LinuxNone | Self::WinNoAccess | Self::MacNone => Permissions::NONE,
            Self::LinuxRead | Self::WinReadOnly | Self::MacRead => Permissions::READ,
            Self::LinuxWrite | Self::MacWrite => Permissions::WRITE,
            Self::LinuxExec | Self::WinExecute | Self::MacExecute => Permissions::EXECUTE,
            Self::LinuxReadWrite | Self::WinReadWrite | Self::MacReadWrite => Permissions::RW,
            Self::LinuxReadExec | Self::WinExecuteRead | Self::MacReadExecute => Permissions::RX,
            Self::LinuxReadWriteExec | Self::WinExecuteReadWrite | Self::MacAll => Permissions::RWX,
            Self::WinWriteCopy => Permissions::WRITE | Permissions::COPY_ON_WRITE,
            Self::WinExecuteWriteCopy => {
                Permissions::EXECUTE | Permissions::WRITE | Permissions::COPY_ON_WRITE
            }
            Self::WinGuard => Permissions::GUARD,
        }
    }

    /// Best-effort mapping from [`Permissions`] to a Linux `PROT_*` integer.
    ///
    /// Returns the bitwise OR of `PROT_READ` (1), `PROT_WRITE` (2), `PROT_EXEC` (4).
    #[must_use]
    pub const fn linux_prot_bits(perms: Permissions) -> u32 {
        let mut bits = 0u32;
        if perms.is_readable() {
            bits |= 1;
        }
        if perms.is_writable() {
            bits |= 2;
        }
        if perms.is_executable() {
            bits |= 4;
        }
        bits
    }

    /// Best-effort mapping from [`Permissions`] to a Windows `PAGE_*` constant.
    ///
    /// Guard pages are represented separately; the returned value is the base
    /// `PAGE_*` constant without any modifier.
    #[must_use]
    pub const fn windows_page_constant(perms: Permissions) -> u32 {
        if perms.is_guard() {
            return 0x0100;
        } // PAGE_GUARD
        match (
            perms.is_readable(),
            perms.is_writable(),
            perms.is_executable(),
        ) {
            // PAGE_NOACCESS
            (true, false, false) => 0x02, // PAGE_READONLY
            (true, true, false) => 0x04,  // PAGE_READWRITE
            (false, false, true) => 0x10, // PAGE_EXECUTE
            (true, false, true) => 0x20,  // PAGE_EXECUTE_READ
            (true, true, true) => 0x40,   // PAGE_EXECUTE_READWRITE
            _ => 0x01,                    // fallback to PAGE_NOACCESS
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PermissionPolicy
// ─────────────────────────────────────────────────────────────────────────────

/// A simple allow/deny rule set for memory protection operations.
///
/// Rules are evaluated in insertion order; the first matching rule wins.
/// If no rule matches, the default is to **allow**.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PermissionPolicy {
    rules: Vec<PermissionRule>,
}

/// A single rule in a [`PermissionPolicy`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PermissionRule {
    /// The required flags for this rule to match.
    pub required_flags: Permissions,
    /// Whether matching this rule allows (`true`) or denies (`false`) the
    /// operation.
    pub allow: bool,
    /// Optional human-readable label.
    pub label: Option<String>,
}

impl PermissionRule {
    /// Create an *allow* rule.
    #[must_use]
    pub const fn allow(required_flags: Permissions) -> Self {
        Self {
            required_flags,
            allow: true,
            label: None,
        }
    }

    /// Create a *deny* rule.
    #[must_use]
    pub const fn deny(required_flags: Permissions) -> Self {
        Self {
            required_flags,
            allow: false,
            label: None,
        }
    }

    /// Attach a human-readable label.
    #[must_use]
    pub fn with_label(mut self, label: impl Into<String>) -> Self {
        self.label = Some(label.into());
        self
    }

    /// Return `true` if `perms` matches this rule.
    #[must_use]
    pub const fn matches(&self, perms: Permissions) -> bool {
        perms.contains(self.required_flags)
    }
}

impl PermissionPolicy {
    /// Create an empty policy (default: allow everything).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a rule at the end of the evaluation chain.
    pub fn add_rule(&mut self, rule: PermissionRule) {
        self.rules.push(rule);
    }

    /// Check whether `perms` is allowed by this policy.
    ///
    /// Returns `true` if the first matching rule is an *allow* rule, or if no
    /// rule matches (default-allow).
    #[must_use]
    pub fn is_allowed(&self, perms: Permissions) -> bool {
        for rule in &self.rules {
            if rule.matches(perms) {
                return rule.allow;
            }
        }
        true // default-allow
    }

    /// Check whether `perms` is denied by this policy.
    #[must_use]
    pub fn is_denied(&self, perms: Permissions) -> bool {
        !self.is_allowed(perms)
    }

    /// Return the number of rules.
    #[must_use]
    pub const fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// Iterate over all rules.
    pub fn rules(&self) -> impl Iterator<Item = &PermissionRule> {
        self.rules.iter()
    }

    /// Remove all rules, resetting to default-allow.
    pub fn clear(&mut self) {
        self.rules.clear();
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// InheritFlags
// ─────────────────────────────────────────────────────────────────────────────

/// Controls how a memory region is inherited by child processes (e.g. after
/// `fork(2)` on Linux, or `CreateProcess` on Windows).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum InheritFlags {
    /// Child process shares the mapping (copy-on-write).
    Share,
    /// Child process gets its own private copy.
    Copy,
    /// Region is not mapped in the child.
    None,
    /// Region becomes the child's new copy upon first write (deferred copy).
    DeferredCopy,
}

impl InheritFlags {
    /// Return `true` if child inherits the region in any form.
    #[must_use]
    pub const fn is_inherited(self) -> bool {
        !matches!(self, Self::None)
    }

    /// Return `true` if the child receives a private copy.
    #[must_use]
    pub const fn is_private_copy(self) -> bool {
        matches!(self, Self::Copy | Self::DeferredCopy)
    }
}

impl std::fmt::Display for InheritFlags {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Share => write!(f, "share"),
            Self::Copy => write!(f, "copy"),
            Self::None => write!(f, "none"),
            Self::DeferredCopy => write!(f, "deferred-copy"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Permissions ───────────────────────────────────────────────────────────

    #[test]
    fn permissions_basic_flags() {
        let p = Permissions::READ | Permissions::EXECUTE;
        assert!(p.is_readable());
        assert!(!p.is_writable());
        assert!(p.is_executable());
        assert!(!p.is_copy_on_write());
        assert!(!p.is_guard());
        assert!(!p.is_nocache());
    }

    #[test]
    fn permissions_none_is_none() {
        assert!(Permissions::NONE.is_none());
        assert!(!Permissions::READ.is_none());
    }

    #[test]
    fn permissions_rwx_constants() {
        assert!(Permissions::RW.is_readable());
        assert!(Permissions::RW.is_writable());
        assert!(!Permissions::RW.is_executable());

        assert!(Permissions::RX.is_readable());
        assert!(!Permissions::RX.is_writable());
        assert!(Permissions::RX.is_executable());

        assert!(Permissions::RWX.is_readable());
        assert!(Permissions::RWX.is_writable());
        assert!(Permissions::RWX.is_executable());
    }

    #[test]
    fn permissions_as_rwx_string() {
        assert_eq!(Permissions::READ.as_rwx_string(), "r--");
        assert_eq!(Permissions::WRITE.as_rwx_string(), "-w-");
        assert_eq!(Permissions::EXECUTE.as_rwx_string(), "--x");
        assert_eq!(Permissions::RWX.as_rwx_string(), "rwx");
        assert_eq!(Permissions::NONE.as_rwx_string(), "---");
    }

    #[test]
    fn permissions_from_rwx_string() {
        assert_eq!(
            Permissions::from_rwx_string("r--").unwrap(),
            Permissions::READ
        );
        assert_eq!(
            Permissions::from_rwx_string("rwx").unwrap(),
            Permissions::RWX
        );
        assert_eq!(
            Permissions::from_rwx_string("---").unwrap(),
            Permissions::NONE
        );
        assert!(Permissions::from_rwx_string("zy").is_none());
        assert!(Permissions::from_rwx_string("rwxx").is_none());
    }

    #[test]
    fn permissions_with_without() {
        let p = Permissions::READ;
        let rw = p.with(Permissions::WRITE);
        assert_eq!(rw, Permissions::RW);
        let r_only = rw.without(Permissions::WRITE);
        assert_eq!(r_only, Permissions::READ);
    }

    #[test]
    fn permissions_display() {
        assert_eq!(Permissions::RX.to_string(), "r-x");
    }

    #[test]
    fn permissions_serialize_round_trip() {
        let p = Permissions::READ | Permissions::EXECUTE | Permissions::GUARD;
        let bits = p.bits();
        let reconstructed = Permissions::from_bits_truncate(bits);
        assert_eq!(p, reconstructed);
    }

    #[test]
    fn permissions_from_bits_truncate() {
        // Unknown bits are silently dropped.
        let p = Permissions::from_bits_truncate(0xFF);
        // All known bits should be set.
        assert!(p.is_readable());
        assert!(p.is_writable());
        assert!(p.is_executable());
    }

    // ── PermissionChange ──────────────────────────────────────────────────────

    #[test]
    fn permission_change_flags_added_removed() {
        let change = PermissionChange::new(Permissions::READ, Permissions::RWX, 0);
        assert_eq!(
            change.flags_added(),
            Permissions::WRITE | Permissions::EXECUTE
        );
        assert_eq!(change.flags_removed(), Permissions::NONE);
    }

    #[test]
    fn permission_change_with_reason() {
        let c = PermissionChange::new(Permissions::NONE, Permissions::READ, 1)
            .with_reason("initial mapping");
        assert_eq!(c.reason.as_deref(), Some("initial mapping"));
    }

    // ── PermissionSet ─────────────────────────────────────────────────────────

    #[test]
    fn permission_set_apply_and_rollback() {
        let mut ps = PermissionSet::new(Permissions::READ);
        assert_eq!(ps.current(), Permissions::READ);
        assert!(!ps.has_history());

        ps.apply(Permissions::RWX, Some("mprotect".into()));
        assert_eq!(ps.current(), Permissions::RWX);
        assert_eq!(ps.change_count(), 1);

        ps.apply(Permissions::READ, None);
        assert_eq!(ps.change_count(), 2);

        let rolled = ps.rollback();
        assert!(rolled);
        assert_eq!(ps.current(), Permissions::RWX);

        let rolled2 = ps.rollback();
        assert!(rolled2);
        assert_eq!(ps.current(), Permissions::READ);

        let rolled3 = ps.rollback();
        assert!(!rolled3);
        assert_eq!(ps.current(), Permissions::READ);
    }

    #[test]
    fn permission_set_noop_on_same_value() {
        let mut ps = PermissionSet::new(Permissions::READ);
        ps.apply(Permissions::READ, None);
        assert_eq!(ps.change_count(), 0);
    }

    #[test]
    fn permission_set_history_slice() {
        let mut ps = PermissionSet::new(Permissions::NONE);
        ps.apply(Permissions::READ, None);
        ps.apply(Permissions::RWX, None);
        let h = ps.history();
        assert_eq!(h.len(), 2);
        assert_eq!(h[0].old, Permissions::NONE);
        assert_eq!(h[0].new, Permissions::READ);
        assert_eq!(h[1].old, Permissions::READ);
        assert_eq!(h[1].new, Permissions::RWX);
    }

    // ── MemoryProtection ──────────────────────────────────────────────────────

    #[test]
    fn memory_protection_to_permissions() {
        assert_eq!(
            MemoryProtection::LinuxNone.to_permissions(),
            Permissions::NONE
        );
        assert_eq!(
            MemoryProtection::LinuxRead.to_permissions(),
            Permissions::READ
        );
        assert_eq!(
            MemoryProtection::LinuxReadExec.to_permissions(),
            Permissions::RX
        );
        assert_eq!(
            MemoryProtection::WinReadWrite.to_permissions(),
            Permissions::RW
        );
        assert_eq!(MemoryProtection::MacAll.to_permissions(), Permissions::RWX);
        assert!(MemoryProtection::WinGuard.to_permissions().is_guard());
    }

    #[test]
    fn memory_protection_linux_prot_bits() {
        assert_eq!(MemoryProtection::linux_prot_bits(Permissions::NONE), 0);
        assert_eq!(MemoryProtection::linux_prot_bits(Permissions::READ), 1);
        assert_eq!(MemoryProtection::linux_prot_bits(Permissions::WRITE), 2);
        assert_eq!(MemoryProtection::linux_prot_bits(Permissions::EXECUTE), 4);
        assert_eq!(MemoryProtection::linux_prot_bits(Permissions::RWX), 7);
    }

    #[test]
    fn memory_protection_windows_page_constant() {
        assert_eq!(
            MemoryProtection::windows_page_constant(Permissions::NONE),
            0x01
        );
        assert_eq!(
            MemoryProtection::windows_page_constant(Permissions::READ),
            0x02
        );
        assert_eq!(
            MemoryProtection::windows_page_constant(Permissions::RW),
            0x04
        );
        assert_eq!(
            MemoryProtection::windows_page_constant(Permissions::EXECUTE),
            0x10
        );
        assert_eq!(
            MemoryProtection::windows_page_constant(Permissions::RX),
            0x20
        );
        assert_eq!(
            MemoryProtection::windows_page_constant(Permissions::RWX),
            0x40
        );
        assert_eq!(
            MemoryProtection::windows_page_constant(Permissions::GUARD),
            0x0100
        );
    }

    // ── PermissionPolicy ──────────────────────────────────────────────────────

    #[test]
    fn policy_default_allow() {
        let policy = PermissionPolicy::new();
        assert!(policy.is_allowed(Permissions::RWX));
        assert!(!policy.is_denied(Permissions::READ));
    }

    #[test]
    fn policy_deny_execute() {
        let mut policy = PermissionPolicy::new();
        policy.add_rule(PermissionRule::deny(Permissions::EXECUTE).with_label("no execute"));
        assert!(!policy.is_allowed(Permissions::RX));
        assert!(!policy.is_allowed(Permissions::RWX));
        assert!(policy.is_allowed(Permissions::RW));
        assert!(policy.is_allowed(Permissions::READ));
    }

    #[test]
    fn policy_first_match_wins() {
        let mut policy = PermissionPolicy::new();
        // Allow READ first, then deny EXECUTE.
        policy.add_rule(PermissionRule::allow(Permissions::READ));
        policy.add_rule(PermissionRule::deny(Permissions::EXECUTE));
        // READ alone matches the first rule → allowed.
        assert!(policy.is_allowed(Permissions::READ));
        // RX also matches the first rule (contains READ) → allowed.
        assert!(policy.is_allowed(Permissions::RX));
    }

    #[test]
    fn policy_rule_count_and_clear() {
        let mut policy = PermissionPolicy::new();
        policy.add_rule(PermissionRule::deny(Permissions::WRITE));
        policy.add_rule(PermissionRule::deny(Permissions::EXECUTE));
        assert_eq!(policy.rule_count(), 2);
        policy.clear();
        assert_eq!(policy.rule_count(), 0);
    }

    #[test]
    fn policy_rules_iter() {
        let mut policy = PermissionPolicy::new();
        policy.add_rule(PermissionRule::allow(Permissions::READ));
        policy.add_rule(PermissionRule::deny(Permissions::WRITE));
        let labels: Vec<bool> = policy.rules().map(|r| r.allow).collect();
        assert_eq!(labels, [true, false]);
    }

    // ── InheritFlags ──────────────────────────────────────────────────────────

    #[test]
    fn inherit_flags_is_inherited() {
        assert!(InheritFlags::Share.is_inherited());
        assert!(InheritFlags::Copy.is_inherited());
        assert!(InheritFlags::DeferredCopy.is_inherited());
        assert!(!InheritFlags::None.is_inherited());
    }

    #[test]
    fn inherit_flags_is_private_copy() {
        assert!(InheritFlags::Copy.is_private_copy());
        assert!(InheritFlags::DeferredCopy.is_private_copy());
        assert!(!InheritFlags::Share.is_private_copy());
        assert!(!InheritFlags::None.is_private_copy());
    }

    #[test]
    fn inherit_flags_display() {
        assert_eq!(InheritFlags::Share.to_string(), "share");
        assert_eq!(InheritFlags::None.to_string(), "none");
        assert_eq!(InheritFlags::DeferredCopy.to_string(), "deferred-copy");
    }
}
