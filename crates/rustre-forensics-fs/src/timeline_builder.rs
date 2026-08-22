use std::fmt::Write as _;
// timeline_builder.rs — Filesystem forensic timeline builder
// Assembles MAC(b) timestamps into chronological event streams,
// detects timestomping anomalies, and exports CSV reports.

use std::cmp::Ordering;
use std::collections::HashMap;
use std::fmt;

// ── Timestamp types ───────────────────────────────────────────────────────────

/// Timestamp source tells us which metadata field a time came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TimestampSource {
    /// $`STANDARD_INFORMATION` Modified
    SiModified,
    /// $`STANDARD_INFORMATION` Accessed
    SiAccessed,
    /// $`STANDARD_INFORMATION` Changed (MFT entry change)
    SiChanged,
    /// $`STANDARD_INFORMATION` Created
    SiCreated,
    /// $`FILE_NAME` Modified
    FnModified,
    /// $`FILE_NAME` Accessed
    FnAccessed,
    /// $`FILE_NAME` Changed
    FnChanged,
    /// $`FILE_NAME` Created
    FnCreated,
    /// FAT32 modified
    FatModified,
    /// FAT32 created
    FatCreated,
    /// FAT32 accessed
    FatAccessed,
    /// Ext4 mtime
    Ext4Mtime,
    /// Ext4 atime
    Ext4Atime,
    /// Ext4 ctime
    Ext4Ctime,
    /// Ext4 crtime (creation)
    Ext4Crtime,
    /// User-provided label
    Custom(u8),
}

impl fmt::Display for TimestampSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SiModified => write!(f, "$SI_Modified"),
            Self::SiAccessed => write!(f, "$SI_Accessed"),
            Self::SiChanged => write!(f, "$SI_Changed"),
            Self::SiCreated => write!(f, "$SI_Created"),
            Self::FnModified => write!(f, "$FN_Modified"),
            Self::FnAccessed => write!(f, "$FN_Accessed"),
            Self::FnChanged => write!(f, "$FN_Changed"),
            Self::FnCreated => write!(f, "$FN_Created"),
            Self::FatModified => write!(f, "FAT_Modified"),
            Self::FatCreated => write!(f, "FAT_Created"),
            Self::FatAccessed => write!(f, "FAT_Accessed"),
            Self::Ext4Mtime => write!(f, "Ext4_mtime"),
            Self::Ext4Atime => write!(f, "Ext4_atime"),
            Self::Ext4Ctime => write!(f, "Ext4_ctime"),
            Self::Ext4Crtime => write!(f, "Ext4_crtime"),
            Self::Custom(n) => write!(f, "Custom({n})"),
        }
    }
}

/// A single file timestamp with its provenance.
#[derive(Debug, Clone)]
pub struct FileTimestamp {
    /// Unix timestamp in seconds (UTC).
    pub unix_secs: i64,
    /// Fractional nanoseconds (`0..999_999_999`).
    pub nanoseconds: u32,
    pub source: TimestampSource,
    pub file_path: String,
    pub file_inode: Option<u64>,
    pub is_deleted: bool,
}

impl FileTimestamp {
    pub fn new(unix_secs: i64, source: TimestampSource, file_path: impl Into<String>) -> Self {
        Self {
            unix_secs,
            nanoseconds: 0,
            source,
            file_path: file_path.into(),
            file_inode: None,
            is_deleted: false,
        }
    }

    #[must_use] 
    pub fn with_ns(mut self, nanoseconds: u32) -> Self {
        self.nanoseconds = nanoseconds.min(999_999_999);
        self
    }

    #[must_use] 
    pub const fn with_inode(mut self, inode: u64) -> Self {
        self.file_inode = Some(inode);
        self
    }

    #[must_use] 
    pub const fn deleted(mut self) -> Self {
        self.is_deleted = true;
        self
    }

    /// Format as ISO-8601 UTC string.
    #[must_use] 
    pub fn iso8601(&self) -> String {
        format_unix_ts(self.unix_secs, self.nanoseconds)
    }

    /// Canonical sort key: (`unix_secs`, nanoseconds).
    #[must_use] 
    pub const fn sort_key(&self) -> (i64, u32) {
        (self.unix_secs, self.nanoseconds)
    }
}

fn format_unix_ts(secs: i64, ns: u32) -> String {
    // Manual UTC conversion without chrono.
    let (sign, abs) = if secs < 0 {
        ("-", (-secs).cast_unsigned())
    } else {
        ("", secs.cast_unsigned())
    };
    let s_of_day = abs % 86400;
    let days = abs / 86400;
    let hour = (s_of_day / 3600) as u32;
    let min = ((s_of_day % 3600) / 60) as u32;
    let sec = (s_of_day % 60) as u32;
    let (y, mo, d) = days_to_ymd(days);
    if ns == 0 {
        format!("{sign}{y:04}-{mo:02}-{d:02}T{hour:02}:{min:02}:{sec:02}Z")
    } else {
        format!("{sign}{y:04}-{mo:02}-{d:02}T{hour:02}:{min:02}:{sec:02}.{ns:09}Z")
    }
}

const fn days_to_ymd(days: u64) -> (u64, u32, u32) {
    // Algorithm by Richards (civil calendar).
    let days = days + 2_440_588; // Julian date of Unix epoch
    let a = days + 32044;
    let b = (4 * a + 3) / 146_097;
    let c = a - (146_097 * b) / 4;
    let d = (4 * c + 3) / 1461;
    let e = c - (1461 * d) / 4;
    let m = (5 * e + 2) / 153;
    let day = e - (153 * m + 2) / 5 + 1;
    let month = m + 3 - 12 * (m / 10);
    let year = 100 * b + d - 4800 + m / 10;
    (year, month as u32, day as u32)
}

// ── Timeline event ────────────────────────────────────────────────────────────

/// The type of filesystem activity represented by a timeline event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EventKind {
    FileCreated,
    FileModified,
    FileAccessed,
    MetadataChanged,
    FileDeleted,
    FileRenamed { old_name: String },
    AnomalyTimestomp,
    AnomalyFuture,
    AnomalyPrecisionLoss,
}

impl fmt::Display for EventKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FileCreated => write!(f, "Created"),
            Self::FileModified => write!(f, "Modified"),
            Self::FileAccessed => write!(f, "Accessed"),
            Self::MetadataChanged => write!(f, "MetaChanged"),
            Self::FileDeleted => write!(f, "Deleted"),
            Self::FileRenamed { old_name } => write!(f, "Renamed(from:{old_name})"),
            Self::AnomalyTimestomp => write!(f, "ANOMALY:Timestomp"),
            Self::AnomalyFuture => write!(f, "ANOMALY:FutureTime"),
            Self::AnomalyPrecisionLoss => write!(f, "ANOMALY:PrecisionLoss"),
        }
    }
}

/// A single event in the timeline, combining a timestamp with an event type.
#[derive(Debug, Clone)]
pub struct TimelineEvent {
    pub timestamp: FileTimestamp,
    pub kind: EventKind,
    pub description: String,
}

impl TimelineEvent {
    pub fn new(ts: FileTimestamp, kind: EventKind, desc: impl Into<String>) -> Self {
        Self { timestamp: ts, kind, description: desc.into() }
    }
}

// ── Timestomp detection ───────────────────────────────────────────────────────

/// Result of comparing $SI and $FN timestamps for timestomping indicators.
#[derive(Debug, Clone)]
pub struct TimestompDetect {
    pub file_path: String,
    pub si_modified: Option<i64>,
    pub fn_modified: Option<i64>,
    /// $SI is earlier than $FN (strongly suggests timestomping).
    pub si_before_fn: bool,
    /// $SI has suspiciously round precision (e.g. on-the-second).
    pub si_round_precision: bool,
    /// $SI timestamp is in the future relative to analysis time.
    pub si_future: bool,
    pub confidence: f32,
}

impl TimestompDetect {
    pub fn new(file_path: impl Into<String>) -> Self {
        Self {
            file_path: file_path.into(),
            si_modified: None,
            fn_modified: None,
            si_before_fn: false,
            si_round_precision: false,
            si_future: false,
            confidence: 0.0,
        }
    }

    pub fn compute_confidence(&mut self) {
        let mut score: f32 = 0.0;
        if self.si_before_fn {
            score += 0.65;
        }
        if self.si_round_precision {
            score += 0.21;
        }
        if self.si_future {
            score += 0.15;
        }
        self.confidence = score.min(1.0);
    }

    #[must_use] 
    pub fn is_suspicious(&self) -> bool {
        self.confidence >= 0.60
    }
}

// ── Timeline builder ──────────────────────────────────────────────────────────

/// Configuration for the timeline builder.
#[derive(Debug, Clone)]
pub struct TimelineConfig {
    /// If Some, only include events at or after this Unix timestamp.
    pub start_time: Option<i64>,
    /// If Some, only include events at or before this Unix timestamp.
    pub end_time: Option<i64>,
    /// Include deleted file entries.
    pub include_deleted: bool,
    /// Include anomaly events.
    pub include_anomalies: bool,
    /// Unix timestamp considered "now" for future-time detection.
    pub now_unix: i64,
}

impl Default for TimelineConfig {
    fn default() -> Self {
        Self {
            start_time: None,
            end_time: None,
            include_deleted: true,
            include_anomalies: true,
            now_unix: 0,
        }
    }
}

/// Builds a chronological filesystem timeline from raw timestamps.
pub struct TimelineBuilder {
    config: TimelineConfig,
    /// All raw timestamps collected.
    raw_timestamps: Vec<FileTimestamp>,
    /// Accumulated events (set by `build`).
    events: Vec<TimelineEvent>,
    /// Per-file timestomp analyses.
    timestomp_results: HashMap<String, TimestompDetect>,
}

impl TimelineBuilder {
    #[must_use] 
    pub fn new(config: TimelineConfig) -> Self {
        Self {
            config,
            raw_timestamps: Vec::new(),
            events: Vec::new(),
            timestomp_results: HashMap::new(),
        }
    }

    #[must_use] 
    pub fn with_defaults() -> Self {
        Self::new(TimelineConfig::default())
    }

    /// Add a raw timestamp to the collection.
    pub fn add_timestamp(&mut self, ts: FileTimestamp) {
        self.raw_timestamps.push(ts);
    }

    /// Add multiple timestamps at once.
    pub fn add_timestamps(&mut self, iter: impl IntoIterator<Item = FileTimestamp>) {
        self.raw_timestamps.extend(iter);
    }

    /// Add a complete MAC(b) set for an NTFS file.
    pub fn add_ntfs_file(
        &mut self,
        path: &str,
        inode: u64,
        si_created: i64,
        si_modified: i64,
        si_accessed: i64,
        si_changed: i64,
        fn_created: i64,
        fn_modified: i64,
        fn_accessed: i64,
        fn_changed: i64,
        is_deleted: bool,
    ) {
        let make = |secs: i64, src: TimestampSource| {
            let mut ts = FileTimestamp::new(secs, src, path).with_inode(inode);
            if is_deleted {
                ts = ts.deleted();
            }
            ts
        };
        self.add_timestamp(make(si_created, TimestampSource::SiCreated));
        self.add_timestamp(make(si_modified, TimestampSource::SiModified));
        self.add_timestamp(make(si_accessed, TimestampSource::SiAccessed));
        self.add_timestamp(make(si_changed, TimestampSource::SiChanged));
        self.add_timestamp(make(fn_created, TimestampSource::FnCreated));
        self.add_timestamp(make(fn_modified, TimestampSource::FnModified));
        self.add_timestamp(make(fn_accessed, TimestampSource::FnAccessed));
        self.add_timestamp(make(fn_changed, TimestampSource::FnChanged));
    }

    /// Add a FAT32 file entry (created / modified / accessed).
    pub fn add_fat32_file(
        &mut self,
        path: &str,
        created: i64,
        modified: i64,
        accessed: i64,
        is_deleted: bool,
    ) {
        let make = |secs: i64, src: TimestampSource| {
            let mut ts = FileTimestamp::new(secs, src, path);
            if is_deleted {
                ts = ts.deleted();
            }
            ts
        };
        self.add_timestamp(make(created, TimestampSource::FatCreated));
        self.add_timestamp(make(modified, TimestampSource::FatModified));
        self.add_timestamp(make(accessed, TimestampSource::FatAccessed));
    }

    /// Build the timeline: convert raw timestamps to sorted events and run anomaly detection.
    pub fn build(&mut self) {
        self.events.clear();
        self.timestomp_results.clear();

        // Convert raw timestamps into events.
        for ts in &self.raw_timestamps {
            if !self.config.include_deleted && ts.is_deleted {
                continue;
            }
            if let Some(start) = self.config.start_time
                && ts.unix_secs < start {
                    continue;
                }
            if let Some(end) = self.config.end_time
                && ts.unix_secs > end {
                    continue;
                }
            let kind = source_to_event_kind(ts.source);
            let desc = format!("{} {} {}", ts.iso8601(), ts.source, ts.file_path);
            self.events.push(TimelineEvent::new(ts.clone(), kind, desc));
        }

        // Sort by timestamp.
        self.events.sort_by(|a, b| {
            a.timestamp
                .sort_key()
                .partial_cmp(&b.timestamp.sort_key())
                .unwrap_or(Ordering::Equal)
        });

        if self.config.include_anomalies {
            self.detect_anomalies();
        }
    }

    fn detect_anomalies(&mut self) {
        // Collect SI and FN timestamps per file for timestomp detection.
        let mut si_mod: HashMap<String, i64> = HashMap::new();
        let mut fn_mod: HashMap<String, i64> = HashMap::new();
        let now = self.config.now_unix;
        let mut anomaly_events: Vec<TimelineEvent> = Vec::new();

        for ts in &self.raw_timestamps {
            match ts.source {
                TimestampSource::SiModified => {
                    si_mod.insert(ts.file_path.clone(), ts.unix_secs);
                }
                TimestampSource::FnModified => {
                    fn_mod.insert(ts.file_path.clone(), ts.unix_secs);
                }
                _ => {}
            }
            // Future time anomaly.
            if now > 0 && ts.unix_secs > now + 86400 {
                let mut anom_ts = ts.clone();
                anom_ts.source = ts.source;
                let desc = format!(
                    "FUTURE timestamp {} on {} (now={})",
                    ts.iso8601(),
                    ts.file_path,
                    format_unix_ts(now, 0)
                );
                anomaly_events.push(TimelineEvent::new(
                    anom_ts,
                    EventKind::AnomalyFuture,
                    desc,
                ));
            }
            // Precision loss: FAT2s resolution — timestamps on even seconds only.
            if matches!(
                ts.source,
                TimestampSource::FatModified
                    | TimestampSource::FatCreated
                    | TimestampSource::FatAccessed
            ) && ts.unix_secs % 2 == 1
            {
                // Odd-second FAT timestamp is suspicious (FAT has 2s resolution).
                let desc = format!(
                    "Odd-second FAT timestamp {} on {} (FAT has 2s resolution)",
                    ts.iso8601(),
                    ts.file_path
                );
                anomaly_events.push(TimelineEvent::new(
                    ts.clone(),
                    EventKind::AnomalyPrecisionLoss,
                    desc,
                ));
            }
        }

        // Timestomp: collect all files with both SI and FN modified.
        let mut all_paths: Vec<String> = si_mod.keys().cloned().collect();
        all_paths.extend(fn_mod.keys().cloned());
        all_paths.sort();
        all_paths.dedup();

        for path in &all_paths {
            let si = si_mod.get(path).copied();
            let fn_ = fn_mod.get(path).copied();
            let mut det = TimestompDetect::new(path);
            det.si_modified = si;
            det.fn_modified = fn_;
            if let (Some(s), Some(f)) = (si, fn_) {
                det.si_before_fn = s < f;
                det.si_round_precision = s % 60 == 0;
                det.si_future = now > 0 && s > now + 86400;
                det.compute_confidence();
                if det.is_suspicious() {
                    let ts = FileTimestamp::new(s, TimestampSource::SiModified, path.clone());
                    let desc = format!(
                        "Timestomp detected on {} (SI_mod={} FN_mod={} conf={:.0}%)",
                        path,
                        format_unix_ts(s, 0),
                        format_unix_ts(f, 0),
                        det.confidence * 100.0
                    );
                    anomaly_events.push(TimelineEvent::new(
                        ts,
                        EventKind::AnomalyTimestomp,
                        desc,
                    ));
                }
            }
            self.timestomp_results.insert(path.clone(), det);
        }

        // Insert anomaly events sorted into main event list.
        anomaly_events.sort_by(|a, b| {
            a.timestamp
                .sort_key()
                .partial_cmp(&b.timestamp.sort_key())
                .unwrap_or(Ordering::Equal)
        });
        self.events.extend(anomaly_events);
        self.events.sort_by(|a, b| {
            a.timestamp
                .sort_key()
                .partial_cmp(&b.timestamp.sort_key())
                .unwrap_or(Ordering::Equal)
        });
    }

    #[must_use] 
    pub fn events(&self) -> &[TimelineEvent] {
        &self.events
    }

    #[must_use] 
    pub const fn timestomp_results(&self) -> &HashMap<String, TimestompDetect> {
        &self.timestomp_results
    }

    #[must_use] 
    pub fn suspicious_files(&self) -> Vec<&TimestompDetect> {
        let mut v: Vec<_> =
            self.timestomp_results.values().filter(|d| d.is_suspicious()).collect();
        v.sort_by(|a, b| {
            b.confidence
                .partial_cmp(&a.confidence)
                .unwrap_or(Ordering::Equal)
        });
        v
    }

    /// Export the timeline as CSV text (RFC 4180 compatible).
    #[must_use] 
    pub fn export_csv(&self) -> String {
        let mut out = String::with_capacity(self.events.len() * 128);
        // Header
        out.push_str(
            "timestamp,source,event_kind,file_path,inode,is_deleted,description\r\n",
        );
        for ev in &self.events {
            let ts = &ev.timestamp;
            let inode_str = ts
                .file_inode
                .map(|i| i.to_string())
                .unwrap_or_default();
            let deleted = if ts.is_deleted { "1" } else { "0" };
            let desc_esc = ev.description.replace('"', "\"\"");
            let _ = write!(out, 
                "{},{},{},{},{},{},\"{}\"\r\n",
                ts.iso8601(),
                ts.source,
                ev.kind,
                csv_escape(&ts.file_path),
                inode_str,
                deleted,
                desc_esc
            );
        }
        out
    }

    /// Export only anomaly events as CSV.
    #[must_use] 
    pub fn export_anomalies_csv(&self) -> String {
        let mut out = String::with_capacity(512);
        out.push_str("timestamp,event_kind,file_path,description\r\n");
        for ev in &self.events {
            match ev.kind {
                EventKind::AnomalyTimestomp
                | EventKind::AnomalyFuture
                | EventKind::AnomalyPrecisionLoss => {
                    let ts = &ev.timestamp;
                    let desc_esc = ev.description.replace('"', "\"\"");
                    let _ = write!(out, 
                        "{},{},{},\"{}\"\r\n",
                        ts.iso8601(),
                        ev.kind,
                        csv_escape(&ts.file_path),
                        desc_esc
                    );
                }
                _ => {}
            }
        }
        out
    }

    /// Count events by kind.
    #[must_use] 
    pub fn event_counts(&self) -> HashMap<String, usize> {
        let mut map: HashMap<String, usize> = HashMap::new();
        for ev in &self.events {
            *map.entry(ev.kind.to_string()).or_insert(0) += 1;
        }
        map
    }

    /// Return a summary string.
    #[must_use] 
    pub fn summary(&self) -> String {
        let total = self.events.len();
        let anomalies = self
            .events
            .iter()
            .filter(|e| {
                matches!(
                    e.kind,
                    EventKind::AnomalyTimestomp
                        | EventKind::AnomalyFuture
                        | EventKind::AnomalyPrecisionLoss
                )
            })
            .count();
        let suspicious = self.suspicious_files().len();
        format!(
            "Timeline: {total} events, {anomalies} anomalies, {suspicious} suspicious files"
        )
    }

    #[must_use] 
    pub const fn raw_count(&self) -> usize {
        self.raw_timestamps.len()
    }
}

const fn source_to_event_kind(src: TimestampSource) -> EventKind {
    match src {
        TimestampSource::SiCreated
        | TimestampSource::FnCreated
        | TimestampSource::FatCreated
        | TimestampSource::Ext4Crtime => EventKind::FileCreated,
        TimestampSource::SiModified
        | TimestampSource::FnModified
        | TimestampSource::FatModified
        | TimestampSource::Ext4Mtime | TimestampSource::Custom(_) => EventKind::FileModified,
        TimestampSource::SiAccessed
        | TimestampSource::FnAccessed
        | TimestampSource::FatAccessed
        | TimestampSource::Ext4Atime => EventKind::FileAccessed,
        TimestampSource::SiChanged
        | TimestampSource::FnChanged
        | TimestampSource::Ext4Ctime => EventKind::MetadataChanged,
        }
}

fn csv_escape(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_unix_epoch() {
        let s = format_unix_ts(0, 0);
        assert_eq!(s, "1970-01-01T00:00:00Z");
    }

    #[test]
    fn test_format_known_date() {
        // 2023-07-15 12:34:56 UTC
        let secs: i64 = 1689421696;
        let s = format_unix_ts(secs, 0);
        assert!(s.starts_with("2023-07-1"), "got {s}");
    }

    #[test]
    fn test_timestamp_iso8601() {
        let ts = FileTimestamp::new(0, TimestampSource::SiModified, "/test.txt");
        assert_eq!(ts.iso8601(), "1970-01-01T00:00:00Z");
    }

    #[test]
    fn test_timestamp_with_ns() {
        let ts =
            FileTimestamp::new(1000, TimestampSource::SiModified, "/x").with_ns(500_000_000);
        assert!(ts.iso8601().contains(".500000000Z"));
    }

    #[test]
    fn test_timeline_builder_basic() {
        let mut builder = TimelineBuilder::with_defaults();
        builder.add_timestamp(FileTimestamp::new(
            100,
            TimestampSource::SiModified,
            "/a.txt",
        ));
        builder.add_timestamp(FileTimestamp::new(
            50,
            TimestampSource::SiCreated,
            "/a.txt",
        ));
        builder.build();
        let evs = builder.events();
        assert_eq!(evs.len(), 2);
        // Should be sorted: 50 before 100.
        assert_eq!(evs[0].timestamp.unix_secs, 50);
        assert_eq!(evs[1].timestamp.unix_secs, 100);
    }

    #[test]
    fn test_timestomp_detection() {
        let mut builder = TimelineBuilder::with_defaults();
        // SI_modified = 60 (round, divisible by 60), FN_modified = 2000 → SI before FN
        builder.add_timestamp(FileTimestamp::new(
            60, // divisible by 60 → round, and < FN
            TimestampSource::SiModified,
            "/sus.exe",
        ));
        builder.add_timestamp(FileTimestamp::new(
            2000,
            TimestampSource::FnModified,
            "/sus.exe",
        ));
        builder.build();
        let det = builder.timestomp_results().get("/sus.exe").unwrap();
        assert!(det.si_before_fn);
        assert!(det.si_round_precision);
        assert!(det.confidence >= 0.60);
        assert!(det.is_suspicious());
    }

    #[test]
    fn test_no_timestomp_when_si_after_fn() {
        let mut builder = TimelineBuilder::with_defaults();
        builder.add_timestamp(FileTimestamp::new(
            2000,
            TimestampSource::SiModified,
            "/ok.txt",
        ));
        builder.add_timestamp(FileTimestamp::new(
            1000,
            TimestampSource::FnModified,
            "/ok.txt",
        ));
        builder.build();
        let det = builder.timestomp_results().get("/ok.txt").unwrap();
        assert!(!det.si_before_fn);
        assert!(!det.is_suspicious());
    }

    #[test]
    fn test_future_anomaly() {
        let mut cfg = TimelineConfig::default();
        cfg.now_unix = 1000;
        cfg.include_anomalies = true;
        let mut builder = TimelineBuilder::new(cfg);
        builder.add_timestamp(FileTimestamp::new(
            1000 + 2 * 86400,
            TimestampSource::SiModified,
            "/future.txt",
        ));
        builder.build();
        let anomalies: Vec<_> = builder
            .events()
            .iter()
            .filter(|e| e.kind == EventKind::AnomalyFuture)
            .collect();
        assert!(!anomalies.is_empty());
    }

    #[test]
    fn test_export_csv() {
        let mut builder = TimelineBuilder::with_defaults();
        builder.add_timestamp(FileTimestamp::new(
            0,
            TimestampSource::SiModified,
            "/x.txt",
        ));
        builder.build();
        let csv = builder.export_csv();
        assert!(csv.contains("timestamp"));
        assert!(csv.contains("/x.txt"));
        assert!(csv.contains("1970-01-01"));
    }

    #[test]
    fn test_export_csv_special_chars() {
        let mut builder = TimelineBuilder::with_defaults();
        builder.add_timestamp(FileTimestamp::new(
            0,
            TimestampSource::SiModified,
            "/path with, comma/file.txt",
        ));
        builder.build();
        let csv = builder.export_csv();
        // Comma in path should be quoted.
        assert!(csv.contains('"'));
    }

    #[test]
    fn test_add_ntfs_file() {
        let mut builder = TimelineBuilder::with_defaults();
        builder.add_ntfs_file(
            "/ntfs_file.dat",
            1234,
            100, 200, 300, 400, 100, 200, 300, 400,
            false,
        );
        assert_eq!(builder.raw_count(), 8);
        builder.build();
        assert!(builder.events().len() >= 8);
    }

    #[test]
    fn test_add_fat32_file() {
        let mut builder = TimelineBuilder::with_defaults();
        builder.add_fat32_file("/fat_file.txt", 100, 200, 300, false);
        assert_eq!(builder.raw_count(), 3);
        builder.build();
        assert_eq!(builder.events().len(), 3);
    }

    #[test]
    fn test_summary() {
        let mut builder = TimelineBuilder::with_defaults();
        builder.add_timestamp(FileTimestamp::new(
            0,
            TimestampSource::SiModified,
            "/a",
        ));
        builder.build();
        let s = builder.summary();
        assert!(s.contains("Timeline:"));
    }

    #[test]
    fn test_event_counts() {
        let mut builder = TimelineBuilder::with_defaults();
        builder.add_timestamp(FileTimestamp::new(
            0,
            TimestampSource::SiModified,
            "/a",
        ));
        builder.add_timestamp(FileTimestamp::new(
            1,
            TimestampSource::SiCreated,
            "/a",
        ));
        builder.build();
        let counts = builder.event_counts();
        assert_eq!(counts.get("Modified").copied().unwrap_or(0), 1);
        assert_eq!(counts.get("Created").copied().unwrap_or(0), 1);
    }

    #[test]
    fn test_filter_by_time_range() {
        let mut cfg = TimelineConfig::default();
        cfg.start_time = Some(50);
        cfg.end_time = Some(150);
        let mut builder = TimelineBuilder::new(cfg);
        builder.add_timestamp(FileTimestamp::new(
            10,
            TimestampSource::SiModified,
            "/early",
        ));
        builder.add_timestamp(FileTimestamp::new(
            100,
            TimestampSource::SiModified,
            "/mid",
        ));
        builder.add_timestamp(FileTimestamp::new(
            200,
            TimestampSource::SiModified,
            "/late",
        ));
        builder.build();
        let evs = builder.events();
        // Only "/mid" should survive — anomaly detection may add more if conditions met.
        let files: Vec<&str> =
            evs.iter().map(|e| e.timestamp.file_path.as_str()).collect();
        assert!(!files.contains(&"/early"));
        assert!(!files.contains(&"/late"));
    }

    #[test]
    fn test_timestomp_detect_confidence() {
        let mut d = TimestompDetect::new("/test");
        d.si_before_fn = true;
        d.si_round_precision = true;
        d.compute_confidence();
        assert!(d.confidence >= 0.85);
    }
}
