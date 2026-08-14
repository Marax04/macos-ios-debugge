//! Extended permissions model for memory regions.
//!
//! Goes beyond the core `READ | WRITE | EXECUTE` triad to support:
//! - Copy-on-write semantics flag
//! - Shared / private flags
//! - `GUARD` / `NOACCESS` pages
//! - RELRO (read-only after relocation) detection helper
//! - Windows-style `PAGE_*` constant conversion
//! - Linux `/proc/maps` rwxp field parsing
//! - Permission change audit log

use rustre_core::permissions::Permissions;
use serde::{Deserialize, Serialize};

// ─────────────────────────────────────────────────────────────────────────────
// ExtendedPerms
// ─────────────────────────────────────────────────────────────────────────────

bitflags::bitflags! {
    /// Extended page-level permission / attribute flags.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
    pub struct ExtendedPerms: u32 {
        /// Read access.
        const READ       = 0x0001;
        /// Write access.
        const WRITE      = 0x0002;
        /// Execute access.
        const EXECUTE    = 0x0004;
        /// Copy-on-write (anonymous mapping, shared-library private pages).
        const COW        = 0x0008;
        /// Shared mapping (visible to other processes / shared memory).
        const SHARED     = 0x0010;
        /// Guard page — trap on first access (Windows stack guard / Linux).
        const GUARD      = 0x0020;
        /// No access at all.
        const NOACCESS   = 0x0040;
        /// Large/huge page.
        const HUGE       = 0x0080;
        /// No-execute bit (alias, for x86 PAE / AMD64 paging).
        const NX         = 0x0100;
        /// RELRO: was writable during relocation, now mapped read-only.
        const RELRO      = 0x0200;
        /// Locked into physical RAM (`mlock`/`VirtualLock`).
        const LOCKED     = 0x0400;
        /// Transparent huge page (Linux THP).
        const THP        = 0x0800;
        /// Write-combined caching policy.
        const WRITE_COMBINED = 0x1000;
    }
}

impl ExtendedPerms {
    /// Convert a basic `Permissions` value to an `ExtendedPerms` value.
    #[must_use]
    pub fn from_basic(p: Permissions) -> Self {
        let mut ep = Self::empty();
        if p.is_readable() {
            ep |= Self::READ;
        }
        if p.is_writable() {
            ep |= Self::WRITE;
        }
        if p.is_executable() {
            ep |= Self::EXECUTE;
        }
        ep
    }

    /// Convert to the basic `Permissions` triad (discards extended flags).
    #[must_use]
    pub fn to_basic(self) -> Permissions {
        let mut p = Permissions::NONE;
        if self.contains(Self::READ) {
            p |= Permissions::READ;
        }
        if self.contains(Self::WRITE) {
            p |= Permissions::WRITE;
        }
        if self.contains(Self::EXECUTE) {
            p |= Permissions::EXECUTE;
        }
        p
    }

    /// Returns `true` if the page is both writable and executable (W^X violation).
    #[must_use]
    pub const fn is_wx_page(self) -> bool {
        self.contains(Self::WRITE) && self.contains(Self::EXECUTE)
    }

    /// Returns `true` if the page is accessible at all (not GUARD and not NOACCESS).
    #[must_use]
    pub fn is_accessible(self) -> bool {
        !self.intersects(Self::GUARD | Self::NOACCESS)
    }

    /// Returns `true` if the mapping is private (COW, not SHARED).
    #[must_use]
    pub const fn is_private(self) -> bool {
        !self.contains(Self::SHARED)
    }

    /// Parse Linux `/proc/maps` permission field, e.g. `"r-xp"` or `"rwxs"`.
    ///
    /// # Errors
    /// Returns `Err(String)` if the field is not exactly 4 characters long or
    /// contains unexpected characters.
    pub fn parse_proc_maps_perms(field: &str) -> Result<Self, String> {
        let bytes: Vec<u8> = field.bytes().collect();
        if bytes.len() != 4 {
            return Err(format!("expected 4-char perms field, got: {field}"));
        }
        let mut ep = Self::empty();

        match bytes[0] {
            b'r' => ep |= Self::READ,
            b'-' => {}
            c => return Err(format!("unexpected read char: {}", c as char)),
        }
        match bytes[1] {
            b'w' => ep |= Self::WRITE,
            b'-' => {}
            c => return Err(format!("unexpected write char: {}", c as char)),
        }
        match bytes[2] {
            b'x' => ep |= Self::EXECUTE,
            b'-' => {}
            c => return Err(format!("unexpected exec char: {}", c as char)),
        }
        match bytes[3] {
            b'p' => {} // private
            b's' => ep |= Self::SHARED,
            c => return Err(format!("unexpected private/shared char: {}", c as char)),
        }

        Ok(ep)
    }

    /// Render back to a Linux `/proc/maps`-style 4-char string.
    #[must_use]
    pub fn to_proc_maps_string(self) -> String {
        let mut s = String::with_capacity(4);
        s.push(if self.contains(Self::READ) { 'r' } else { '-' });
        s.push(if self.contains(Self::WRITE) { 'w' } else { '-' });
        s.push(if self.contains(Self::EXECUTE) {
            'x'
        } else {
            '-'
        });
        s.push(if self.contains(Self::SHARED) {
            's'
        } else {
            'p'
        });
        s
    }

    /// Convert Windows `PAGE_*` protection constants to `ExtendedPerms`.
    ///
    /// Handles the common subset:
    /// - `PAGE_NOACCESS` (0x01)
    /// - `PAGE_READONLY` (0x02)
    /// - `PAGE_READWRITE` (0x04)
    /// - `PAGE_WRITECOPY` (0x08)
    /// - `PAGE_EXECUTE` (0x10)
    /// - `PAGE_EXECUTE_READ` (0x20)
    /// - `PAGE_EXECUTE_READWRITE` (0x40)
    /// - `PAGE_EXECUTE_WRITECOPY` (0x80)
    /// - `PAGE_GUARD` modifier (0x100)
    /// - `PAGE_WRITECOMBINE` modifier (0x400)
    #[must_use]
    pub fn from_windows_protect(protect: u32) -> Self {
        let base = protect & 0xFF;
        let modifiers = protect & !0xFF;

        let mut ep = match base {
            0x01 => Self::NOACCESS,
            0x02 => Self::READ,
            0x04 => Self::READ | Self::WRITE,
            0x08 => Self::READ | Self::WRITE | Self::COW,
            0x10 => Self::EXECUTE,
            0x20 => Self::EXECUTE | Self::READ,
            0x40 => Self::EXECUTE | Self::READ | Self::WRITE,
            0x80 => Self::EXECUTE | Self::READ | Self::WRITE | Self::COW,
            _ => Self::empty(),
        };

        if modifiers & 0x100 != 0 {
            ep |= Self::GUARD;
        }
        if modifiers & 0x400 != 0 {
            ep |= Self::WRITE_COMBINED;
        }

        ep
    }
}

impl std::fmt::Display for ExtendedPerms {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_proc_maps_string())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PermissionChange — one entry in the audit log
// ─────────────────────────────────────────────────────────────────────────────

/// One permission-change event, suitable for an audit trail.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PermissionChange {
    /// Virtual address range that was changed.
    pub start: u64,
    pub end: u64,
    /// Permissions before the change.
    pub before: ExtendedPerms,
    /// Permissions after the change.
    pub after: ExtendedPerms,
    /// Optional label (e.g. "mprotect", "relro applied", "stack guard").
    pub reason: Option<String>,
    /// Sequential change index.
    pub seq: u64,
}

impl std::fmt::Display for PermissionChange {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "#{}: 0x{:x}..0x{:x} {} → {}",
            self.seq, self.start, self.end, self.before, self.after,
        )?;
        if let Some(reason) = &self.reason {
            write!(f, " [{reason}]")?;
        }
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PermissionAuditLog
// ─────────────────────────────────────────────────────────────────────────────

/// An ordered log of permission-change events.
#[derive(Debug, Clone, Default)]
pub struct PermissionAuditLog {
    changes: Vec<PermissionChange>,
    next_seq: u64,
}

impl PermissionAuditLog {
    /// Create an empty log.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a change.
    pub fn record(
        &mut self,
        start: u64,
        end: u64,
        before: ExtendedPerms,
        after: ExtendedPerms,
        reason: Option<String>,
    ) {
        let seq = self.next_seq;
        self.next_seq += 1;
        self.changes.push(PermissionChange {
            start,
            end,
            before,
            after,
            reason,
            seq,
        });
    }

    /// Number of recorded changes.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.changes.len()
    }

    /// Returns `true` if no changes have been recorded.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.changes.is_empty()
    }

    /// All changes that affected address `addr`.
    #[must_use]
    pub fn changes_for(&self, addr: u64) -> Vec<&PermissionChange> {
        self.changes
            .iter()
            .filter(|c| addr >= c.start && addr < c.end)
            .collect()
    }

    /// All changes where W^X pages were created.
    #[must_use]
    pub fn wx_escalations(&self) -> Vec<&PermissionChange> {
        self.changes
            .iter()
            .filter(|c| c.after.is_wx_page() && !c.before.is_wx_page())
            .collect()
    }

    /// All changes where write permission was added to a previously
    /// non-writable region (potential dangerous escalation).
    #[must_use]
    pub fn write_escalations(&self) -> Vec<&PermissionChange> {
        self.changes
            .iter()
            .filter(|c| {
                c.after.contains(ExtendedPerms::WRITE) && !c.before.contains(ExtendedPerms::WRITE)
            })
            .collect()
    }

    /// Serialize the log to JSON.
    ///
    /// # Errors
    /// Returns an error if serialization fails.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(&self.changes)
    }

    /// Clear all records.
    pub fn clear(&mut self) {
        self.changes.clear();
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// RELRO detection helper
// ─────────────────────────────────────────────────────────────────────────────

/// RELRO status of a binary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelroStatus {
    /// No RELRO (the GOT / data sections remain writable at runtime).
    None,
    /// Partial RELRO: `.got` is read-only but `.got.plt` is still writable.
    Partial,
    /// Full RELRO: all relocations are resolved at startup, `.got.plt` is
    /// also made read-only.
    Full,
}

impl std::fmt::Display for RelroStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::None => f.write_str("None"),
            Self::Partial => f.write_str("Partial"),
            Self::Full => f.write_str("Full"),
        }
    }
}

/// Infer the RELRO status from the permission-change audit log.
///
/// Heuristic: after the initial load, a region that was first `rw-` and was
/// later made `r--` (without going through `rwx`) is likely a RELRO segment.
/// Full RELRO also applies this to the `.got.plt` section.
///
/// # Arguments
/// * `log` — the audit log to scan.
/// * `got_plt_addr` — the virtual address of `.got.plt`, if known.
#[must_use]
pub fn infer_relro_status(log: &PermissionAuditLog, got_plt_addr: Option<u64>) -> RelroStatus {
    let rw = ExtendedPerms::READ | ExtendedPerms::WRITE;
    let ro = ExtendedPerms::READ;

    // Find any rw→ro transition in the log.
    let any_partial = log.changes.iter().any(|c| c.before == rw && c.after == ro);

    if !any_partial {
        return RelroStatus::None;
    }

    // Full RELRO: if the .got.plt address is covered by a rw→ro transition.
    if let Some(got) = got_plt_addr {
        let full = log
            .changes
            .iter()
            .any(|c| c.before == rw && c.after == ro && got >= c.start && got < c.end);
        if full {
            return RelroStatus::Full;
        }
    }

    RelroStatus::Partial
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── ExtendedPerms::from_basic / to_basic ─────────────────────────────────

    #[test]
    fn test_from_basic_rx() {
        let ep = ExtendedPerms::from_basic(Permissions::READ | Permissions::EXECUTE);
        assert!(ep.contains(ExtendedPerms::READ));
        assert!(ep.contains(ExtendedPerms::EXECUTE));
        assert!(!ep.contains(ExtendedPerms::WRITE));
    }

    #[test]
    fn test_to_basic_roundtrip() {
        let ep = ExtendedPerms::READ | ExtendedPerms::WRITE | ExtendedPerms::EXECUTE;
        let basic = ep.to_basic();
        assert!(basic.is_readable());
        assert!(basic.is_writable());
        assert!(basic.is_executable());
    }

    // ── WX detection ─────────────────────────────────────────────────────────

    #[test]
    fn test_wx_page_detection() {
        let ep = ExtendedPerms::READ | ExtendedPerms::WRITE | ExtendedPerms::EXECUTE;
        assert!(ep.is_wx_page());
    }

    #[test]
    fn test_no_wx_on_rx() {
        let ep = ExtendedPerms::READ | ExtendedPerms::EXECUTE;
        assert!(!ep.is_wx_page());
    }

    // ── proc_maps parsing ────────────────────────────────────────────────────

    #[test]
    fn test_parse_proc_maps_rxp() {
        let ep = ExtendedPerms::parse_proc_maps_perms("r-xp").unwrap();
        assert!(ep.contains(ExtendedPerms::READ));
        assert!(ep.contains(ExtendedPerms::EXECUTE));
        assert!(!ep.contains(ExtendedPerms::WRITE));
        assert!(!ep.contains(ExtendedPerms::SHARED));
    }

    #[test]
    fn test_parse_proc_maps_rwxs() {
        let ep = ExtendedPerms::parse_proc_maps_perms("rwxs").unwrap();
        assert!(ep.contains(ExtendedPerms::WRITE));
        assert!(ep.contains(ExtendedPerms::SHARED));
    }

    #[test]
    fn test_parse_proc_maps_invalid_length() {
        assert!(ExtendedPerms::parse_proc_maps_perms("rxp").is_err());
        assert!(ExtendedPerms::parse_proc_maps_perms("r-xpp").is_err());
    }

    #[test]
    fn test_parse_proc_maps_invalid_char() {
        assert!(ExtendedPerms::parse_proc_maps_perms("z-xp").is_err());
    }

    #[test]
    fn test_to_proc_maps_string_roundtrip() {
        let ep = ExtendedPerms::READ | ExtendedPerms::WRITE;
        let s = ep.to_proc_maps_string();
        let back = ExtendedPerms::parse_proc_maps_perms(&s).unwrap();
        assert_eq!(ep.to_basic(), back.to_basic());
    }

    // ── Windows PAGE_* constants ─────────────────────────────────────────────

    #[test]
    fn test_from_windows_page_execute_readwrite() {
        let ep = ExtendedPerms::from_windows_protect(0x40);
        assert!(ep.contains(ExtendedPerms::READ));
        assert!(ep.contains(ExtendedPerms::WRITE));
        assert!(ep.contains(ExtendedPerms::EXECUTE));
    }

    #[test]
    fn test_from_windows_page_noaccess() {
        let ep = ExtendedPerms::from_windows_protect(0x01);
        assert!(ep.contains(ExtendedPerms::NOACCESS));
        assert!(!ep.is_accessible());
    }

    #[test]
    fn test_from_windows_page_guard_modifier() {
        // PAGE_READONLY | PAGE_GUARD
        let ep = ExtendedPerms::from_windows_protect(0x02 | 0x100);
        assert!(ep.contains(ExtendedPerms::GUARD));
        assert!(ep.contains(ExtendedPerms::READ));
        assert!(!ep.is_accessible());
    }

    #[test]
    fn test_from_windows_page_writecopy() {
        let ep = ExtendedPerms::from_windows_protect(0x08);
        assert!(ep.contains(ExtendedPerms::COW));
    }

    // ── PermissionAuditLog ───────────────────────────────────────────────────

    #[test]
    fn test_audit_log_record_and_query() {
        let mut log = PermissionAuditLog::new();
        log.record(
            0x1000,
            0x2000,
            ExtendedPerms::READ | ExtendedPerms::WRITE,
            ExtendedPerms::READ,
            Some("relro".into()),
        );
        assert_eq!(log.len(), 1);
        let changes = log.changes_for(0x1500);
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].reason.as_deref(), Some("relro"));
    }

    #[test]
    fn test_audit_log_wx_escalation() {
        let mut log = PermissionAuditLog::new();
        // rw → rwx (W^X escalation)
        log.record(
            0x4000,
            0x5000,
            ExtendedPerms::READ | ExtendedPerms::WRITE,
            ExtendedPerms::READ | ExtendedPerms::WRITE | ExtendedPerms::EXECUTE,
            Some("jit".into()),
        );
        assert_eq!(log.wx_escalations().len(), 1);
    }

    #[test]
    fn test_audit_log_write_escalation() {
        let mut log = PermissionAuditLog::new();
        log.record(
            0x2000,
            0x3000,
            ExtendedPerms::READ,
            ExtendedPerms::READ | ExtendedPerms::WRITE,
            None,
        );
        assert_eq!(log.write_escalations().len(), 1);
    }

    #[test]
    fn test_audit_log_changes_for_no_match() {
        let mut log = PermissionAuditLog::new();
        log.record(
            0x1000,
            0x2000,
            ExtendedPerms::READ,
            ExtendedPerms::READ | ExtendedPerms::WRITE,
            None,
        );
        assert!(log.changes_for(0x9000).is_empty());
    }

    #[test]
    fn test_audit_log_clear() {
        let mut log = PermissionAuditLog::new();
        log.record(0, 0x100, ExtendedPerms::READ, ExtendedPerms::WRITE, None);
        log.clear();
        assert!(log.is_empty());
    }

    #[test]
    fn test_permission_change_display() {
        let pc = PermissionChange {
            start: 0x1000,
            end: 0x2000,
            before: ExtendedPerms::READ | ExtendedPerms::WRITE,
            after: ExtendedPerms::READ,
            reason: Some("relro".into()),
            seq: 0,
        };
        let s = pc.to_string();
        assert!(s.contains("relro"));
        assert!(s.contains("1000"));
    }

    // ── RELRO inference ──────────────────────────────────────────────────────

    #[test]
    fn test_relro_none_when_no_rw_to_ro() {
        let log = PermissionAuditLog::new();
        assert_eq!(infer_relro_status(&log, None), RelroStatus::None);
    }

    #[test]
    fn test_relro_partial() {
        let mut log = PermissionAuditLog::new();
        log.record(
            0x60_1000,
            0x60_2000,
            ExtendedPerms::READ | ExtendedPerms::WRITE,
            ExtendedPerms::READ,
            Some("relro".into()),
        );
        assert_eq!(
            infer_relro_status(&log, Some(0x60_5000)),
            RelroStatus::Partial
        );
    }

    #[test]
    fn test_relro_full() {
        let mut log = PermissionAuditLog::new();
        // The .got.plt at 0x60_3000 is within the rw→ro range.
        log.record(
            0x60_1000,
            0x60_4000,
            ExtendedPerms::READ | ExtendedPerms::WRITE,
            ExtendedPerms::READ,
            Some("full relro".into()),
        );
        assert_eq!(infer_relro_status(&log, Some(0x60_3000)), RelroStatus::Full);
    }

    #[test]
    fn test_extended_perms_display() {
        let ep = ExtendedPerms::READ | ExtendedPerms::EXECUTE;
        let s = ep.to_string();
        assert_eq!(s, "r-xp");
    }

    #[test]
    fn test_extended_perms_is_private() {
        let ep = ExtendedPerms::READ;
        assert!(ep.is_private());
        let shared = ExtendedPerms::READ | ExtendedPerms::SHARED;
        assert!(!shared.is_private());
    }

    #[test]
    fn test_audit_log_json_roundtrip() {
        let mut log = PermissionAuditLog::new();
        log.record(
            0x1000,
            0x2000,
            ExtendedPerms::READ,
            ExtendedPerms::READ | ExtendedPerms::WRITE,
            None,
        );
        let json = log.to_json().unwrap();
        // 0x1000 == 4096 in decimal; JSON serializes integers as decimal.
        assert!(json.contains("4096"));
    }

    #[test]
    fn test_relro_display() {
        assert_eq!(RelroStatus::None.to_string(), "None");
        assert_eq!(RelroStatus::Partial.to_string(), "Partial");
        assert_eq!(RelroStatus::Full.to_string(), "Full");
    }
}
