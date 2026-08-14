//! `filesystem_timeline` — Build filesystem change timelines from forensic artifacts.
//!
//! [`FilesystemTimeline`] aggregates filesystem events collected from triage
//! artifacts into an ordered timeline.  Suspicious changes (system file
//! modification, hidden file creation, permission escalation) are flagged
//! automatically via [`SuspiciousChange`].

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

// ---------------------------------------------------------------------------
// FsEvent
// ---------------------------------------------------------------------------

/// The type of filesystem change represented by a [`TimelineEntry`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FsEvent {
    /// A new file or directory was created.
    Create,
    /// An existing file was modified (content or metadata).
    Modify,
    /// A file or directory was deleted.
    Delete,
    /// A file or directory was renamed (old path → new path).
    Rename {
        /// Previous name/path.
        old_path: PathBuf,
    },
    /// File permissions were changed.
    PermissionChange {
        /// Unix-style octal permission bits before the change.
        old_mode: u32,
        /// Unix-style octal permission bits after the change.
        new_mode: u32,
    },
    /// File ownership was changed.
    OwnerChange {
        /// Previous UID.
        old_uid: u32,
        /// New UID.
        new_uid: u32,
    },
    /// A hard or symbolic link was created.
    LinkCreated { target: PathBuf },
    /// Extended attributes were modified.
    XattrModified { key: String },
}

impl fmt::Display for FsEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Create => write!(f, "CREATE"),
            Self::Modify => write!(f, "MODIFY"),
            Self::Delete => write!(f, "DELETE"),
            Self::Rename { old_path } => write!(f, "RENAME(from={})", old_path.display()),
            Self::PermissionChange { old_mode, new_mode } => {
                write!(f, "CHMOD({old_mode:#o}→{new_mode:#o})")
            }
            Self::OwnerChange { old_uid, new_uid } => {
                write!(f, "CHOWN({old_uid}→{new_uid})")
            }
            Self::LinkCreated { target } => write!(f, "LINK(→{})", target.display()),
            Self::XattrModified { key } => write!(f, "XATTR({key})"),
        }
    }
}

// ---------------------------------------------------------------------------
// TimelineEntry
// ---------------------------------------------------------------------------

/// A single entry in the filesystem change timeline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineEntry {
    /// When the event occurred (Unix timestamp in nanoseconds).
    pub timestamp_ns: u128,
    /// Absolute path affected by the event.
    pub path: PathBuf,
    /// Type of filesystem event.
    pub event: FsEvent,
    /// User account associated with the change (or "unknown").
    pub user: String,
    /// Process ID associated with the change (optional).
    pub pid: Option<u32>,
    /// Source artifact that recorded this entry.
    pub source: String,
}

impl TimelineEntry {
    /// Create a new entry.
    #[must_use]
    pub fn new(
        timestamp_ns: u128,
        path: impl Into<PathBuf>,
        event: FsEvent,
        user: impl Into<String>,
        source: impl Into<String>,
    ) -> Self {
        Self {
            timestamp_ns,
            path: path.into(),
            event,
            user: user.into(),
            pid: None,
            source: source.into(),
        }
    }

    /// Attach a PID.
    #[must_use]
    pub const fn with_pid(mut self, pid: u32) -> Self {
        self.pid = Some(pid);
        self
    }

    /// Return the timestamp as a [`SystemTime`].
    #[must_use]
    pub fn system_time(&self) -> SystemTime {
        // timestamp_ns is u128; split into whole seconds and sub-second nanos
        // to avoid the silent truncation that `as u64` would cause for timestamps
        // beyond year ~2554 (> u64::MAX nanoseconds from epoch).
        let secs = (self.timestamp_ns / 1_000_000_000) as u64;
        let subsec_nanos = (self.timestamp_ns % 1_000_000_000) as u32;
        UNIX_EPOCH
            + Duration::from_secs(secs)
            + Duration::from_nanos(u64::from(subsec_nanos))
    }

    /// Return the path as a string (lossless on UTF-8 systems).
    #[must_use]
    pub fn path_str(&self) -> &str {
        self.path.to_str().unwrap_or("<non-utf8>")
    }

    /// Return `true` if this event is a creation.
    #[must_use]
    pub const fn is_create(&self) -> bool {
        matches!(self.event, FsEvent::Create)
    }

    /// Return `true` if this event is a deletion.
    #[must_use]
    pub const fn is_delete(&self) -> bool {
        matches!(self.event, FsEvent::Delete)
    }

    /// Return `true` if this event is a modification.
    #[must_use]
    pub const fn is_modify(&self) -> bool {
        matches!(self.event, FsEvent::Modify)
    }
}

impl fmt::Display for TimelineEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:020}  {:<8}  {}  {}",
            self.timestamp_ns,
            self.user,
            self.event,
            self.path.display()
        )
    }
}

// ---------------------------------------------------------------------------
// SuspiciousChange
// ---------------------------------------------------------------------------

/// A flagged suspicious filesystem change detected during timeline analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuspiciousChange {
    /// Human-readable description of the suspicion.
    pub reason: String,
    /// The underlying timeline entry that triggered the flag.
    pub entry_index: usize,
    /// Severity level (1 = low, 5 = critical).
    pub severity: u8,
}

impl SuspiciousChange {
    /// Create a new suspicious-change record.
    #[must_use]
    pub fn new(reason: impl Into<String>, entry_index: usize, severity: u8) -> Self {
        Self {
            reason: reason.into(),
            entry_index,
            severity: severity.clamp(1, 5),
        }
    }
}

impl fmt::Display for SuspiciousChange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[sev={}] {} (entry={})",
            self.severity, self.reason, self.entry_index
        )
    }
}

// ---------------------------------------------------------------------------
// SuspiciousChangeDetector (internal)
// ---------------------------------------------------------------------------

/// Rules for flagging suspicious timeline entries.
struct SuspiciousChangeDetector;

/// Common system-critical path prefixes.
const SYSTEM_DIRS: &[&str] = &[
    "/bin",
    "/sbin",
    "/usr/bin",
    "/usr/sbin",
    "/usr/lib",
    "/usr/lib64",
    "/lib",
    "/lib64",
    "/etc/init.d",
    "/etc/cron.d",
    "/etc/systemd",
    "C:\\Windows\\System32",
    "C:\\Windows\\SysWOW64",
    "C:\\Windows\\System",
];

impl SuspiciousChangeDetector {
    /// Test whether `path` falls under a system-critical prefix.
    fn is_system_path(path: &Path) -> bool {
        let s = path.to_str().unwrap_or("");
        SYSTEM_DIRS.iter().any(|prefix| s.starts_with(prefix))
    }

    /// Test whether a filename indicates a hidden file (`.` prefix on Unix,
    /// or known Windows system-file extensions).
    fn is_hidden_file(path: &Path) -> bool {
        path.file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.starts_with('.') || n.starts_with('$'))
    }

    /// Check if a permission change represents a potential escalation.
    const fn is_privilege_escalation(old_mode: u32, new_mode: u32) -> bool {
        // Setuid (04000) or setgid (02000) bit added
        let setuid_added = (new_mode & 0o4000) != 0 && (old_mode & 0o4000) == 0;
        let setgid_added = (new_mode & 0o2000) != 0 && (old_mode & 0o2000) == 0;
        // World-writable bit added to a non-world-writable file
        let world_write_added = (new_mode & 0o002) != 0 && (old_mode & 0o002) == 0;
        setuid_added || setgid_added || world_write_added
    }

    /// Analyse a slice of `entries` and return all flagged entries.
    fn detect(entries: &[TimelineEntry]) -> Vec<SuspiciousChange> {
        let mut flags = Vec::new();

        for (i, entry) in entries.iter().enumerate() {
            // Rule 1: system file modified
            if Self::is_system_path(&entry.path) && matches!( &entry.event, FsEvent::Modify | FsEvent::Delete | FsEvent::Rename { .. } ) {
                flags.push(SuspiciousChange::new(
                    format!("System file modified/deleted: {}", entry.path.display()),
                    i,
                    4,
                ));
            }

            // Rule 2: system file created in system dir (new executable dropped)
            if Self::is_system_path(&entry.path) && matches!(&entry.event, FsEvent::Create) {
                flags.push(SuspiciousChange::new(
                    format!(
                        "New file created in system directory: {}",
                        entry.path.display()
                    ),
                    i,
                    3,
                ));
            }

            // Rule 3: hidden file created
            if Self::is_hidden_file(&entry.path) && matches!(&entry.event, FsEvent::Create) {
                flags.push(SuspiciousChange::new(
                    format!("Hidden file created: {}", entry.path.display()),
                    i,
                    2,
                ));
            }

            // Rule 4: permission escalation
            if let FsEvent::PermissionChange { old_mode, new_mode } = &entry.event && Self::is_privilege_escalation(*old_mode, *new_mode) {
                flags.push(SuspiciousChange::new(
                    format!(
                        "Privilege escalation via chmod on {}: {:#o}→{:#o}",
                        entry.path.display(),
                        old_mode,
                        new_mode
                    ),
                    i,
                    5,
                ));
            }

            // Rule 5: owner changed to root (uid 0)
            if let FsEvent::OwnerChange { old_uid, new_uid } = &entry.event && *new_uid == 0 && *old_uid != 0 {
                flags.push(SuspiciousChange::new(
                    format!(
                        "Ownership changed to root on {}: uid {}→0",
                        entry.path.display(),
                        old_uid
                    ),
                    i,
                    4,
                ));
            }

            // Rule 6: link created to sensitive target
            if let FsEvent::LinkCreated { target } = &entry.event && Self::is_system_path(target) {
                flags.push(SuspiciousChange::new(
                    format!(
                        "Link to system path created: {} → {}",
                        entry.path.display(),
                        target.display()
                    ),
                    i,
                    3,
                ));
            }
        }

        flags
    }
}

// ---------------------------------------------------------------------------
// FsTimelineBuilder
// ---------------------------------------------------------------------------

/// Builder for constructing a [`FilesystemTimeline`] from raw events.
#[derive(Debug, Default)]
pub struct FsTimelineBuilder {
    entries: Vec<TimelineEntry>,
}

impl FsTimelineBuilder {
    /// Create an empty builder.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a single entry.
    #[must_use] 
    pub fn add_entry(mut self, entry: TimelineEntry) -> Self {
        self.entries.push(entry);
        self
    }

    /// Add multiple entries.
    pub fn add_entries(mut self, entries: impl IntoIterator<Item = TimelineEntry>) -> Self {
        self.entries.extend(entries);
        self
    }

    /// Convenience: record a simple create event.
    pub fn create(
        mut self,
        ts_ns: u128,
        path: impl Into<PathBuf>,
        user: impl Into<String>,
    ) -> Self {
        self.entries.push(TimelineEntry::new(
            ts_ns,
            path,
            FsEvent::Create,
            user,
            "builder",
        ));
        self
    }

    /// Convenience: record a modify event.
    pub fn modify(
        mut self,
        ts_ns: u128,
        path: impl Into<PathBuf>,
        user: impl Into<String>,
    ) -> Self {
        self.entries.push(TimelineEntry::new(
            ts_ns,
            path,
            FsEvent::Modify,
            user,
            "builder",
        ));
        self
    }

    /// Convenience: record a delete event.
    pub fn delete(
        mut self,
        ts_ns: u128,
        path: impl Into<PathBuf>,
        user: impl Into<String>,
    ) -> Self {
        self.entries.push(TimelineEntry::new(
            ts_ns,
            path,
            FsEvent::Delete,
            user,
            "builder",
        ));
        self
    }

    /// Convenience: record a permission change.
    pub fn chmod(
        mut self,
        ts_ns: u128,
        path: impl Into<PathBuf>,
        user: impl Into<String>,
        old_mode: u32,
        new_mode: u32,
    ) -> Self {
        self.entries.push(TimelineEntry::new(
            ts_ns,
            path,
            FsEvent::PermissionChange { old_mode, new_mode },
            user,
            "builder",
        ));
        self
    }

    /// Consume the builder and produce a sorted [`FilesystemTimeline`].
    #[must_use]
    pub fn build(mut self) -> FilesystemTimeline {
        self.entries.sort_by_key(|e| e.timestamp_ns);
        let suspicious = SuspiciousChangeDetector::detect(&self.entries);
        FilesystemTimeline {
            entries: self.entries,
            suspicious,
        }
    }
}

// ---------------------------------------------------------------------------
// FilesystemTimeline
// ---------------------------------------------------------------------------

/// An ordered filesystem change timeline with suspicious-change annotations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilesystemTimeline {
    /// All recorded entries, sorted by timestamp ascending.
    pub entries: Vec<TimelineEntry>,
    /// Suspicious changes flagged by the built-in detector.
    pub suspicious: Vec<SuspiciousChange>,
}

impl FilesystemTimeline {
    /// Create an empty timeline.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            entries: Vec::new(),
            suspicious: Vec::new(),
        }
    }

    /// Number of entries in the timeline.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.entries.len()
    }

    /// Return `true` if the timeline has no entries.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Return all entries whose path starts with `prefix`.
    #[must_use]
    pub fn entries_under(&self, prefix: &Path) -> Vec<&TimelineEntry> {
        self.entries
            .iter()
            .filter(|e| e.path.starts_with(prefix))
            .collect()
    }

    /// Return all entries attributed to `user`.
    #[must_use]
    pub fn entries_by_user(&self, user: &str) -> Vec<&TimelineEntry> {
        self.entries.iter().filter(|e| e.user == user).collect()
    }

    /// Return all entries for a specific event kind (checked via discriminant).
    #[must_use]
    pub fn entries_by_kind(&self, kind: &str) -> Vec<&TimelineEntry> {
        self.entries
            .iter()
            .filter(|e| {
                let name = match &e.event {
                    FsEvent::Create => "Create",
                    FsEvent::Modify => "Modify",
                    FsEvent::Delete => "Delete",
                    FsEvent::Rename { .. } => "Rename",
                    FsEvent::PermissionChange { .. } => "PermissionChange",
                    FsEvent::OwnerChange { .. } => "OwnerChange",
                    FsEvent::LinkCreated { .. } => "LinkCreated",
                    FsEvent::XattrModified { .. } => "XattrModified",
                };
                name == kind
            })
            .collect()
    }

    /// Return entries in a time window `[start_ns, end_ns]`.
    #[must_use]
    pub fn window(&self, start_ns: u128, end_ns: u128) -> Vec<&TimelineEntry> {
        self.entries
            .iter()
            .filter(|e| e.timestamp_ns >= start_ns && e.timestamp_ns <= end_ns)
            .collect()
    }

    /// Return all suspicious changes with severity >= `min_severity`.
    #[must_use]
    pub fn high_severity_flags(&self, min_severity: u8) -> Vec<&SuspiciousChange> {
        self.suspicious
            .iter()
            .filter(|s| s.severity >= min_severity)
            .collect()
    }

    /// Return a count of events per user.
    #[must_use]
    pub fn events_per_user(&self) -> HashMap<String, usize> {
        let mut map: HashMap<String, usize> = HashMap::new();
        for e in &self.entries {
            *map.entry(e.user.clone()).or_insert(0) += 1;
        }
        map
    }

    /// Return a count of events per event kind.
    #[must_use]
    pub fn events_per_kind(&self) -> HashMap<String, usize> {
        let mut map: HashMap<String, usize> = HashMap::new();
        for e in &self.entries {
            let name = match &e.event {
                FsEvent::Create => "Create",
                FsEvent::Modify => "Modify",
                FsEvent::Delete => "Delete",
                FsEvent::Rename { .. } => "Rename",
                FsEvent::PermissionChange { .. } => "PermissionChange",
                FsEvent::OwnerChange { .. } => "OwnerChange",
                FsEvent::LinkCreated { .. } => "LinkCreated",
                FsEvent::XattrModified { .. } => "XattrModified",
            };
            *map.entry(name.to_string()).or_insert(0) += 1;
        }
        map
    }

    /// Serialize to JSON.
    ///
    /// # Errors
    /// Returns a `serde_json::Error` if serialization fails.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    /// Deserialize from JSON.
    ///
    /// # Errors
    /// Returns a `serde_json::Error` if deserialization fails.
    pub fn from_json(s: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(s)
    }

    /// Human-readable summary of the timeline.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "FilesystemTimeline {{ entries: {}, suspicious: {} }}",
            self.entries.len(),
            self.suspicious.len()
        )
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn ts(secs: u64) -> u128 {
        (secs as u128) * 1_000_000_000
    }

    fn build_basic_timeline() -> FilesystemTimeline {
        FsTimelineBuilder::new()
            .create(ts(100), "/home/user/.hidden_file", "user")
            .modify(ts(200), "/tmp/notes.txt", "user")
            .delete(ts(300), "/tmp/old.log", "root")
            .build()
    }

    // ── FsEvent display ───────────────────────────────────────────────────────

    #[test]
    fn fs_event_create_display() {
        assert_eq!(FsEvent::Create.to_string(), "CREATE");
    }

    #[test]
    fn fs_event_modify_display() {
        assert_eq!(FsEvent::Modify.to_string(), "MODIFY");
    }

    #[test]
    fn fs_event_delete_display() {
        assert_eq!(FsEvent::Delete.to_string(), "DELETE");
    }

    #[test]
    fn fs_event_rename_display() {
        let e = FsEvent::Rename {
            old_path: "/tmp/old".into(),
        };
        let s = e.to_string();
        assert!(s.contains("RENAME") && s.contains("old"));
    }

    #[test]
    fn fs_event_permission_change_display() {
        let e = FsEvent::PermissionChange {
            old_mode: 0o644,
            new_mode: 0o777,
        };
        let s = e.to_string();
        assert!(s.contains("CHMOD"));
    }

    // ── TimelineEntry ─────────────────────────────────────────────────────────

    #[test]
    fn timeline_entry_new_and_display() {
        let entry = TimelineEntry::new(ts(50), "/foo/bar.txt", FsEvent::Create, "alice", "test");
        assert_eq!(entry.user, "alice");
        assert!(entry.is_create());
        assert!(!entry.is_delete());
        let s = format!("{entry}");
        assert!(s.contains("alice"));
        assert!(s.contains("bar.txt"));
    }

    #[test]
    fn timeline_entry_with_pid() {
        let entry =
            TimelineEntry::new(ts(1), "/tmp/x", FsEvent::Modify, "root", "src").with_pid(1234);
        assert_eq!(entry.pid, Some(1234));
    }

    #[test]
    fn timeline_entry_system_time_not_epoch() {
        let entry = TimelineEntry::new(1_000_000_000_000, "/a", FsEvent::Create, "u", "s");
        let st = entry.system_time();
        assert!(st > UNIX_EPOCH);
    }

    // ── FsTimelineBuilder ─────────────────────────────────────────────────────

    #[test]
    fn builder_entries_sorted_by_timestamp() {
        let timeline = FsTimelineBuilder::new()
            .create(ts(300), "/c", "u")
            .create(ts(100), "/a", "u")
            .create(ts(200), "/b", "u")
            .build();
        let tss: Vec<u128> = timeline.entries.iter().map(|e| e.timestamp_ns).collect();
        assert_eq!(tss, vec![ts(100), ts(200), ts(300)]);
    }

    #[test]
    fn builder_chmod_event_stored() {
        let timeline = FsTimelineBuilder::new()
            .chmod(ts(1), "/etc/passwd", "root", 0o644, 0o777)
            .build();
        assert_eq!(timeline.len(), 1);
        assert!(matches!(
            &timeline.entries[0].event,
            FsEvent::PermissionChange { .. }
        ));
    }

    // ── FilesystemTimeline ────────────────────────────────────────────────────

    #[test]
    fn timeline_len_and_is_empty() {
        let t = FilesystemTimeline::empty();
        assert!(t.is_empty());
        assert_eq!(t.len(), 0);
    }

    #[test]
    fn timeline_entries_under_prefix() {
        let timeline = build_basic_timeline();
        let under_home = timeline.entries_under(Path::new("/home"));
        assert_eq!(under_home.len(), 1);
        assert!(under_home[0].path.to_str().unwrap().contains("hidden_file"));
    }

    #[test]
    fn timeline_entries_by_user() {
        let timeline = build_basic_timeline();
        let root_entries = timeline.entries_by_user("root");
        assert_eq!(root_entries.len(), 1);
        assert!(root_entries[0].is_delete());
    }

    #[test]
    fn timeline_entries_by_kind() {
        let timeline = build_basic_timeline();
        let creates = timeline.entries_by_kind("Create");
        assert_eq!(creates.len(), 1);
        let modifies = timeline.entries_by_kind("Modify");
        assert_eq!(modifies.len(), 1);
    }

    #[test]
    fn timeline_window_filters_correctly() {
        let timeline = FsTimelineBuilder::new()
            .create(ts(100), "/a", "u")
            .create(ts(200), "/b", "u")
            .create(ts(300), "/c", "u")
            .build();
        let window = timeline.window(ts(150), ts(250));
        assert_eq!(window.len(), 1);
        assert_eq!(window[0].path.to_str().unwrap(), "/b");
    }

    #[test]
    fn timeline_events_per_user_counts() {
        let timeline = build_basic_timeline();
        let counts = timeline.events_per_user();
        assert_eq!(counts["user"], 2);
        assert_eq!(counts["root"], 1);
    }

    #[test]
    fn timeline_events_per_kind_counts() {
        let timeline = build_basic_timeline();
        let counts = timeline.events_per_kind();
        assert_eq!(counts["Create"], 1);
        assert_eq!(counts["Modify"], 1);
        assert_eq!(counts["Delete"], 1);
    }

    #[test]
    fn timeline_json_roundtrip() {
        let timeline = build_basic_timeline();
        let json = timeline.to_json().unwrap();
        let restored = FilesystemTimeline::from_json(&json).unwrap();
        assert_eq!(restored.len(), timeline.len());
    }

    #[test]
    fn timeline_summary_contains_counts() {
        let timeline = build_basic_timeline();
        let s = timeline.summary();
        assert!(s.contains("entries"));
    }

    // ── SuspiciousChangeDetector ──────────────────────────────────────────────

    #[test]
    fn hidden_file_create_is_flagged() {
        let timeline = FsTimelineBuilder::new()
            .create(ts(1), "/home/user/.evil", "attacker")
            .build();
        let sus = &timeline.suspicious;
        assert!(!sus.is_empty(), "hidden file creation should be flagged");
        assert!(sus.iter().any(|s| s.reason.contains("Hidden")));
    }

    #[test]
    fn system_file_modify_is_flagged() {
        let timeline = FsTimelineBuilder::new()
            .modify(ts(1), "/bin/ls", "root")
            .build();
        let sus = &timeline.suspicious;
        assert!(sus.iter().any(|s| s.reason.contains("System file")));
    }

    #[test]
    fn system_file_create_is_flagged() {
        let timeline = FsTimelineBuilder::new()
            .create(ts(1), "/usr/bin/backdoor", "root")
            .build();
        assert!(!timeline.suspicious.is_empty());
    }

    #[test]
    fn setuid_permission_change_is_critical() {
        let timeline = FsTimelineBuilder::new()
            .chmod(ts(1), "/usr/local/bin/tool", "root", 0o755, 0o4755)
            .build();
        let high = timeline.high_severity_flags(5);
        assert!(!high.is_empty(), "setuid chmod should be severity 5");
    }

    #[test]
    fn normal_chmod_not_flagged_as_escalation() {
        let timeline = FsTimelineBuilder::new()
            .chmod(ts(1), "/home/user/file.txt", "user", 0o644, 0o600)
            .build();
        // No privilege escalation: removing world-read is not suspicious
        let high = timeline.high_severity_flags(5);
        assert!(
            high.is_empty(),
            "non-escalation chmod should not be severity 5"
        );
    }

    #[test]
    fn owner_change_to_root_flagged() {
        let entry = TimelineEntry::new(
            ts(1),
            "/home/user/exe",
            FsEvent::OwnerChange {
                old_uid: 1000,
                new_uid: 0,
            },
            "root",
            "test",
        );
        let timeline = FsTimelineBuilder::new().add_entry(entry).build();
        assert!(
            timeline
                .suspicious
                .iter()
                .any(|s| s.reason.contains("root"))
        );
    }

    #[test]
    fn link_to_system_path_flagged() {
        let entry = TimelineEntry::new(
            ts(1),
            "/tmp/evil_link",
            FsEvent::LinkCreated {
                target: "/bin/bash".into(),
            },
            "attacker",
            "test",
        );
        let timeline = FsTimelineBuilder::new().add_entry(entry).build();
        assert!(
            timeline
                .suspicious
                .iter()
                .any(|s| s.reason.contains("Link"))
        );
    }

    #[test]
    fn high_severity_flags_filters_by_severity() {
        let timeline = FsTimelineBuilder::new()
            .create(ts(1), "/home/user/.dot", "u") // sev 2
            .chmod(ts(2), "/usr/bin/x", "root", 0o755, 0o4755) // sev 5
            .build();
        let flags_3plus = timeline.high_severity_flags(3);
        // chmod to setuid should be ≥ 3
        assert!(!flags_3plus.is_empty());
        let flags_6 = timeline.high_severity_flags(6);
        assert!(flags_6.is_empty(), "no severity > 5");
    }
}
