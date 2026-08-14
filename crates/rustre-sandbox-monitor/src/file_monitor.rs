// file_monitor.rs — file system monitor for sandbox analysis
// Tracks file creates, writes, deletes, renames; hashes written files.

use anyhow::{Context, Result};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

// ─── File operation types ────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FileOpKind {
    Create,
    Open,
    Read,
    Write,
    Delete,
    Rename,
    SetInfo,
    QueryInfo,
    DirectoryEnum,
    Close,
    Flush,
    SetSecurity,
    QuerySecurity,
    CreateHardLink,
    CreateSymLink,
}

impl FileOpKind {
    #[must_use]
    pub const fn is_write_op(self) -> bool {
        matches!(self, Self::Create | Self::Write | Self::Delete | Self::Rename | Self::SetInfo | Self::SetSecurity | Self::CreateHardLink | Self::CreateSymLink)
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Create => "CREATE",
            Self::Open => "OPEN",
            Self::Read => "READ",
            Self::Write => "WRITE",
            Self::Delete => "DELETE",
            Self::Rename => "RENAME",
            Self::SetInfo => "SETINFO",
            Self::QueryInfo => "QUERYINFO",
            Self::DirectoryEnum => "DIRENUEM",
            Self::Close => "CLOSE",
            Self::Flush => "FLUSH",
            Self::SetSecurity => "SETSECURITY",
            Self::QuerySecurity => "QUERYSECURITY",
            Self::CreateHardLink => "HARDLINK",
            Self::CreateSymLink => "SYMLINK",
        }
    }
}

// ─── File event ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileEvent {
    pub timestamp: u64,
    pub pid: u32,
    pub tid: u32,
    pub process_name: String,
    pub op: FileOpKind,
    pub path: String,
    pub dest_path: Option<String>,
    pub bytes_transferred: u64,
    pub status: u32,
    pub is_directory: bool,
    pub sha256: Option<String>,
    pub entropy: Option<f64>,
    pub file_size: Option<u64>,
}

impl FileEvent {
    #[must_use]
    pub fn new(pid: u32, tid: u32, process_name: String, op: FileOpKind, path: String) -> Self {
        let timestamp = u64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or(Duration::ZERO)
                .as_millis(),
        )
        .unwrap_or(u64::MAX);
        Self {
            timestamp,
            pid,
            tid,
            process_name,
            op,
            path,
            dest_path: None,
            bytes_transferred: 0,
            status: 0,
            is_directory: false,
            sha256: None,
            entropy: None,
            file_size: None,
        }
    }

    #[must_use]
    pub fn with_dest(mut self, dest: String) -> Self {
        self.dest_path = Some(dest);
        self
    }

    #[must_use]
    pub const fn with_bytes(mut self, n: u64) -> Self {
        self.bytes_transferred = n;
        self
    }

    #[must_use]
    pub const fn with_status(mut self, s: u32) -> Self {
        self.status = s;
        self
    }

    #[must_use]
    pub const fn succeeded(&self) -> bool {
        self.status == 0
    }

    #[must_use]
    pub fn extension(&self) -> Option<&str> {
        Path::new(&self.path).extension().and_then(|e| e.to_str())
    }

    #[must_use]
    pub fn filename(&self) -> &str {
        Path::new(&self.path).file_name().and_then(|n| n.to_str()).unwrap_or("")
    }
}

// ─── File categories ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FileCategory {
    Executable,
    Script,
    Document,
    Archive,
    Database,
    Configuration,
    Temp,
    SystemFile,
    Network,
    Crypto,
    Other,
}

impl FileCategory {
    #[must_use]
    pub fn from_extension(ext: &str) -> Self {
        match ext.to_ascii_lowercase().as_str() {
            "exe" | "dll" | "ocx" | "scr" | "cpl" => Self::Executable,
            "bat" | "cmd" | "ps1" | "vbs" | "js" | "wsf" | "hta" | "sh" | "py" | "rb" | "pl" => Self::Script,
            "doc" | "docx" | "xls" | "xlsx" | "ppt" | "pptx" | "pdf" | "rtf" | "odt" => Self::Document,
            "zip" | "rar" | "7z" | "tar" | "gz" | "bz2" | "xz" | "cab" | "iso" => Self::Archive,
            "db" | "sqlite" | "mdb" | "accdb" | "ldf" | "mdf" => Self::Database,
            "ini" | "cfg" | "conf" | "xml" | "json" | "toml" | "yaml" | "reg" => Self::Configuration,
            "tmp" | "temp" | "bak" | "swp" => Self::Temp,
            "sys" | "inf" | "cat" | "drv" => Self::SystemFile,
            "pcap" | "pcapng" | "cap" => Self::Network,
            "pem" | "key" | "crt" | "cer" | "pfx" | "p12" | "asc" | "gpg" => Self::Crypto,
            _ => Self::Other,
        }
    }
}

// ─── Persistence path detection ──────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PersistenceLocation {
    StartupFolder,
    StartupFolderAllUsers,
    TaskSchedulerXml,
    WinlogonScript,
    ServiceBinary,
    Other(String),
}

impl PersistenceLocation {
    #[must_use]
    pub fn detect(path: &str) -> Option<Self> {
        let lower = path.to_ascii_lowercase();
        let ext = std::path::Path::new(&lower)
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("");
        if lower.contains("\\start menu\\programs\\startup") && !lower.contains("\\all users") {
            return Some(Self::StartupFolder);
        }
        if lower.contains("\\common startup") || (lower.contains("\\all users") && lower.contains("startup")) {
            return Some(Self::StartupFolderAllUsers);
        }
        if lower.contains("\\system32\\tasks") || lower.contains("\\syswow64\\tasks") {
            return Some(Self::TaskSchedulerXml);
        }
        if lower.contains("\\winlogon") && (ext == "exe" || ext == "dll") {
            return Some(Self::WinlogonScript);
        }
        if lower.contains("\\system32\\drivers") && ext == "sys" {
            return Some(Self::ServiceBinary);
        }
        None
    }
}

// ─── SHA-256 implementation (software, no external dep) ──────────────────────

fn sha256_bytes(data: &[u8]) -> [u8; 32] {
    const K: [u32; 64] = [
        0x428a_2f98,0x7137_4491,0xb5c0_fbcf,0xe9b5_dba5,0x3956_c25b,0x59f1_11f1,0x923f_82a4,0xab1c_5ed5,
        0xd807_aa98,0x1283_5b01,0x2431_85be,0x550c_7dc3,0x72be_5d74,0x80de_b1fe,0x9bdc_06a7,0xc19b_f174,
        0xe49b_69c1,0xefbe_4786,0x0fc1_9dc6,0x240c_a1cc,0x2de9_2c6f,0x4a74_84aa,0x5cb0_a9dc,0x76f9_88da,
        0x983e_5152,0xa831_c66d,0xb003_27c8,0xbf59_7fc7,0xc6e0_0bf3,0xd5a7_9147,0x06ca_6351,0x1429_2967,
        0x27b7_0a85,0x2e1b_2138,0x4d2c_6dfc,0x5338_0d13,0x650a_7354,0x766a_0abb,0x81c2_c92e,0x9272_2c85,
        0xa2bf_e8a1,0xa81a_664b,0xc24b_8b70,0xc76c_51a3,0xd192_e819,0xd699_0624,0xf40e_3585,0x106a_a070,
        0x19a4_c116,0x1e37_6c08,0x2748_774c,0x34b0_bcb5,0x391c_0cb3,0x4ed8_aa4a,0x5b9c_ca4f,0x682e_6ff3,
        0x748f_82ee,0x78a5_636f,0x84c8_7814,0x8cc7_0208,0x90be_fffa,0xa450_6ceb,0xbef9_a3f7,0xc671_78f2,
    ];

    let mut h: [u32; 8] = [
        0x6a09_e667,0xbb67_ae85,0x3c6e_f372,0xa54f_f53a,
        0x510e_527f,0x9b05_688c,0x1f83_d9ab,0x5be0_cd19,
    ];

    let bit_len = u64::try_from(data.len()).unwrap_or(u64::MAX).saturating_mul(8);
    let mut padded = data.to_vec();
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in padded.chunks_exact(64) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([chunk[i*4], chunk[i*4+1], chunk[i*4+2], chunk[i*4+3]]);
        }
        for i in 16..64 {
            let s0 = w[i-15].rotate_right(7) ^ w[i-15].rotate_right(18) ^ (w[i-15] >> 3);
            let s1 = w[i-2].rotate_right(17) ^ w[i-2].rotate_right(19) ^ (w[i-2] >> 10);
            w[i] = w[i-16].wrapping_add(s0).wrapping_add(w[i-7]).wrapping_add(s1);
        }
        let (mut ha,mut hb,mut hc,mut hd,mut he,mut hf,mut hg,mut hh) = (h[0],h[1],h[2],h[3],h[4],h[5],h[6],h[7]);
        for i in 0..64 {
            let s1 = he.rotate_right(6) ^ he.rotate_right(11) ^ he.rotate_right(25);
            let ch = (he & hf) ^ ((!he) & hg);
            let temp1 = hh.wrapping_add(s1).wrapping_add(ch).wrapping_add(K[i]).wrapping_add(w[i]);
            let s0 = ha.rotate_right(2) ^ ha.rotate_right(13) ^ ha.rotate_right(22);
            let maj = (ha & hb) ^ (ha & hc) ^ (hb & hc);
            let temp2 = s0.wrapping_add(maj);
            hh=hg; hg=hf; hf=he; he=hd.wrapping_add(temp1);
            hd=hc; hc=hb; hb=ha; ha=temp1.wrapping_add(temp2);
        }
        h[0]=h[0].wrapping_add(ha); h[1]=h[1].wrapping_add(hb); h[2]=h[2].wrapping_add(hc); h[3]=h[3].wrapping_add(hd);
        h[4]=h[4].wrapping_add(he); h[5]=h[5].wrapping_add(hf); h[6]=h[6].wrapping_add(hg); h[7]=h[7].wrapping_add(hh);
    }

    let mut out = [0u8; 32];
    for (i, &v) in h.iter().enumerate() {
        out[i*4..i*4+4].copy_from_slice(&v.to_be_bytes());
    }
    out
}

#[must_use]
pub fn sha256_hex(data: &[u8]) -> String {
    sha256_bytes(data).iter().fold(String::with_capacity(64), |mut s, b| {
        use std::fmt::Write as _;
        let _ = write!(s, "{b:02x}");
        s
    })
}

// ─── Shannon entropy ─────────────────────────────────────────────────────────

#[must_use]
pub fn byte_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut freq = [0u64; 256];
    for &b in data {
        freq[b as usize] += 1;
    }
    let n = f64::from(u32::try_from(data.len()).unwrap_or(u32::MAX));
    freq.iter().filter(|&&c| c > 0).fold(0.0, |acc, &c| {
        let p = f64::from(u32::try_from(c).unwrap_or(u32::MAX)) / n;
        p.log2().mul_add(-p, acc)
    })
}

// ─── File hash cache ─────────────────────────────────────────────────────────

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct FileHashCache {
    entries: HashMap<String, FileHashEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileHashEntry {
    pub sha256: String,
    pub entropy: f64,
    pub size: u64,
    pub computed_at: u64,
}

impl FileHashCache {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, path: String, entry: FileHashEntry) {
        self.entries.insert(path, entry);
    }

    #[must_use]
    pub fn get(&self, path: &str) -> Option<&FileHashEntry> {
        self.entries.get(path)
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    #[must_use]
    pub fn high_entropy_files(&self, threshold: f64) -> Vec<(&str, &FileHashEntry)> {
        self.entries.iter()
            .filter(|(_, e)| e.entropy >= threshold)
            .map(|(p, e)| (p.as_str(), e))
            .collect()
    }

    /// # Panics
    ///
    /// Panics if the entry just inserted cannot be retrieved (impossible in practice).
    pub fn compute_and_cache(&mut self, path: &str, data: &[u8]) -> &FileHashEntry {
        let sha256 = sha256_hex(data);
        let entropy = byte_entropy(data);
        let ts = u64::try_from(
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or(Duration::ZERO).as_millis(),
        ).unwrap_or(u64::MAX);
        let size = u64::try_from(data.len()).unwrap_or(u64::MAX);
        let entry = FileHashEntry { sha256, entropy, size, computed_at: ts };
        self.entries.insert(path.to_string(), entry);
        self.entries.get(path).unwrap()
    }
}

// ─── File access pattern ─────────────────────────────────────────────────────

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FileAccessPattern {
    pub path: String,
    pub pids_reading: HashSet<u32>,
    pub pids_writing: HashSet<u32>,
    pub total_bytes_written: u64,
    pub total_bytes_read: u64,
    pub create_count: u32,
    pub delete_count: u32,
    pub rename_count: u32,
    pub write_count: u32,
    pub read_count: u32,
    pub first_seen: u64,
    pub last_seen: u64,
}

impl FileAccessPattern {
    #[must_use]
    pub fn new(path: String, ts: u64) -> Self {
        Self { path, first_seen: ts, last_seen: ts, ..Default::default() }
    }

    pub fn update(&mut self, event: &FileEvent) {
        self.last_seen = self.last_seen.max(event.timestamp);
        self.first_seen = self.first_seen.min(event.timestamp);
        match event.op {
            FileOpKind::Create => self.create_count += 1,
            FileOpKind::Delete => self.delete_count += 1,
            FileOpKind::Rename => self.rename_count += 1,
            FileOpKind::Write => {
                self.write_count += 1;
                self.total_bytes_written += event.bytes_transferred;
                self.pids_writing.insert(event.pid);
            }
            FileOpKind::Read => {
                self.read_count += 1;
                self.total_bytes_read += event.bytes_transferred;
                self.pids_reading.insert(event.pid);
            }
            _ => {}
        }
        if event.op.is_write_op() {
            self.pids_writing.insert(event.pid);
        }
    }

    #[must_use]
    pub fn is_contested(&self) -> bool {
        self.pids_writing.len() > 1
    }

    #[must_use]
    pub fn is_dropped_and_executed(&self, exec_pids: &HashSet<u32>) -> bool {
        self.create_count > 0 && !self.pids_writing.is_disjoint(exec_pids)
    }

    #[must_use]
    pub const fn lifetime_ms(&self) -> u64 {
        self.last_seen.saturating_sub(self.first_seen)
    }
}

// ─── Suspicious file indicators ──────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuspiciousFileIndicator {
    pub path: String,
    pub kind: SuspiciousKind,
    pub confidence: f32,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SuspiciousKind {
    HighEntropyExecutable,
    DropAndExecute,
    SuspiciousExtension,
    DoubleExtension,
    PersistenceLocation,
    TempExecWrite,
    ShadowCopyDeletion,
    LargeWriteToSystemDir,
    MassFileDeletion,
    RansomwareLikePattern,
    ScriptInStartup,
}

impl SuspiciousKind {
    #[must_use]
    pub const fn severity(&self) -> u8 {
        match self {
            Self::RansomwareLikePattern => 10,
            Self::DropAndExecute | Self::ShadowCopyDeletion => 9,
            Self::HighEntropyExecutable => 8,
            Self::PersistenceLocation | Self::ScriptInStartup | Self::MassFileDeletion => 7,
            Self::TempExecWrite | Self::LargeWriteToSystemDir => 6,
            Self::DoubleExtension => 5,
            Self::SuspiciousExtension => 4,
        }
    }
}

// ─── File session ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FileSession {
    pub pid: u32,
    pub process_name: String,
    pub path: String,
    pub open_time: u64,
    pub close_time: Option<u64>,
    pub bytes_written: u64,
    pub bytes_read: u64,
    pub ops: Vec<FileOpKind>,
}

impl FileSession {
    #[must_use]
    pub fn new(pid: u32, process_name: String, path: String, ts: u64) -> Self {
        Self { pid, process_name, path, open_time: ts, ..Default::default() }
    }

    pub const fn close(&mut self, ts: u64) {
        self.close_time = Some(ts);
    }

    pub fn add_op(&mut self, op: FileOpKind, bytes: u64) {
        self.ops.push(op);
        match op {
            FileOpKind::Write => self.bytes_written += bytes,
            FileOpKind::Read => self.bytes_read += bytes,
            _ => {}
        }
    }

    #[must_use]
    pub fn duration_ms(&self) -> Option<u64> {
        self.close_time.map(|c| c.saturating_sub(self.open_time))
    }

    #[must_use]
    pub fn had_write(&self) -> bool {
        self.ops.contains(&FileOpKind::Write)
    }
}

// ─── Directory statistics ─────────────────────────────────────────────────────

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DirectoryStats {
    pub path: String,
    pub files_created: u32,
    pub files_deleted: u32,
    pub files_written: u32,
    pub files_read: u32,
    pub bytes_written: u64,
    pub unique_pids: HashSet<u32>,
}

impl DirectoryStats {
    #[must_use] 
    pub fn new(path: String) -> Self {
        Self { path, ..Default::default() }
    }

    pub fn add_event(&mut self, event: &FileEvent) {
        self.unique_pids.insert(event.pid);
        match event.op {
            FileOpKind::Create => self.files_created += 1,
            FileOpKind::Delete => self.files_deleted += 1,
            FileOpKind::Write => { self.files_written += 1; self.bytes_written += event.bytes_transferred; }
            FileOpKind::Read => self.files_read += 1,
            _ => {}
        }
    }

    #[must_use] 
    pub fn delete_ratio(&self) -> f32 {
        let total = self.files_created + self.files_deleted + self.files_written;
        if total == 0 { return 0.0; }
        self.files_deleted as f32 / total as f32
    }

    #[must_use] 
    pub fn is_ransomware_like(&self) -> bool {
        self.delete_ratio() > 0.4 && self.files_written > 10 && self.bytes_written > 1024 * 1024
    }
}

// ─── File monitor core ───────────────────────────────────────────────────────

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct FileMonitor {
    events: Vec<FileEvent>,
    patterns: HashMap<String, FileAccessPattern>,
    hash_cache: FileHashCache,
    sessions: Vec<FileSession>,
    dir_stats: HashMap<String, DirectoryStats>,
    indicators: Vec<SuspiciousFileIndicator>,
    watched_extensions: HashSet<String>,
    ignored_paths: Vec<String>,
}

impl FileMonitor {
    #[must_use] 
    pub fn new() -> Self {
        let mut m = Self::default();
        // default extensions to hash on write
        for ext in &["exe","dll","sys","bat","cmd","ps1","vbs","js","py","rb"] {
            m.watched_extensions.insert(ext.to_string());
        }
        m
    }

    pub fn with_watched_extensions(mut self, exts: impl IntoIterator<Item = String>) -> Self {
        for e in exts { self.watched_extensions.insert(e); }
        self
    }

    pub fn with_ignored_paths(mut self, paths: impl IntoIterator<Item = String>) -> Self {
        for p in paths { self.ignored_paths.push(p.to_ascii_lowercase()); }
        self
    }

    #[must_use] 
    pub fn is_ignored(&self, path: &str) -> bool {
        let lower = path.to_ascii_lowercase();
        self.ignored_paths.iter().any(|ign| lower.starts_with(ign.as_str()))
    }

    pub fn ingest(&mut self, event: FileEvent) {
        if self.is_ignored(&event.path) {
            return;
        }
        // Update access pattern
        let ts = event.timestamp;
        let pattern = self.patterns.entry(event.path.clone()).or_insert_with(|| FileAccessPattern::new(event.path.clone(), ts));
        pattern.update(&event);

        // Update directory stats
        if let Some(dir) = Path::new(&event.path).parent().and_then(|p| p.to_str()) {
            let ds = self.dir_stats.entry(dir.to_string()).or_insert_with(|| DirectoryStats::new(dir.to_string()));
            ds.add_event(&event);
        }

        self.events.push(event);
    }

    pub fn ingest_with_content(&mut self, mut event: FileEvent, content: &[u8]) {
        if event.op == FileOpKind::Write || event.op == FileOpKind::Create {
            let entry = self.hash_cache.compute_and_cache(&event.path, content);
            event.sha256 = Some(entry.sha256.clone());
            event.entropy = Some(entry.entropy);
            event.file_size = Some(entry.size);

            // High entropy executable?
            if let Some(ext) = event.extension() {
                let cat = FileCategory::from_extension(ext);
                if matches!(cat, FileCategory::Executable) && entry.entropy > 7.0 {
                    self.indicators.push(SuspiciousFileIndicator {
                        path: event.path.clone(),
                        kind: SuspiciousKind::HighEntropyExecutable,
                        confidence: ((entry.entropy - 7.0) * 5.0).min(1.0) as f32,
                        detail: format!("entropy={:.3}", entry.entropy),
                    });
                }
            }
        }
        self.ingest(event);
    }

    pub fn analyze_suspicious(&mut self) {
        self.check_drop_and_execute();
        self.check_double_extensions();
        self.check_persistence_drops();
        self.check_temp_exec_writes();
        self.check_mass_deletion();
        self.check_ransomware_patterns();
    }

    fn check_drop_and_execute(&mut self) {
        let exec_exts: HashSet<&str> = ["exe","dll","sys","bat","cmd","ps1","vbs"].iter().copied().collect();
        let write_pids: HashMap<String, HashSet<u32>> = self.patterns.iter()
            .filter(|(_, p)| p.write_count > 0 || p.create_count > 0)
            .map(|(path, p)| (path.clone(), p.pids_writing.clone()))
            .collect();

        let read_pids: HashMap<String, HashSet<u32>> = self.patterns.iter()
            .filter(|(_, p)| p.read_count > 0)
            .map(|(path, p)| (path.clone(), p.pids_reading.clone()))
            .collect();

        for (path, writers) in &write_pids {
            if let Some(ext) = Path::new(path).extension().and_then(|e| e.to_str())
                && exec_exts.contains(ext)
                    && let Some(readers) = read_pids.get(path) {
                        // Different PID wrote and another read (likely executed)
                        let executors: HashSet<_> = readers.difference(writers).copied().collect();
                        if !executors.is_empty() {
                            self.indicators.push(SuspiciousFileIndicator {
                                path: path.clone(),
                                kind: SuspiciousKind::DropAndExecute,
                                confidence: 0.85,
                                detail: format!("written by {writers:?}, executed by {executors:?}"),
                            });
                        }
                    }
        }
    }

    fn check_double_extensions(&mut self) {
        for event in &self.events {
            let name = event.filename();
            let parts: Vec<&str> = name.split('.').collect();
            if parts.len() >= 3 {
                let real_ext = parts.last().unwrap_or(&"");
                let fake_ext = parts[parts.len()-2];
                let doc_exts = ["pdf","doc","docx","xls","xlsx","jpg","png","txt"];
                if doc_exts.contains(&fake_ext) {
                    self.indicators.push(SuspiciousFileIndicator {
                        path: event.path.clone(),
                        kind: SuspiciousKind::DoubleExtension,
                        confidence: 0.75,
                        detail: format!("apparent .{fake_ext} but real extension .{real_ext}"),
                    });
                }
            }
        }
    }

    fn check_persistence_drops(&mut self) {
        for event in &self.events {
            if !event.op.is_write_op() { continue; }
            if let Some(loc) = PersistenceLocation::detect(&event.path) {
                let (kind, conf) = match &loc {
                    PersistenceLocation::StartupFolder | PersistenceLocation::StartupFolderAllUsers => (SuspiciousKind::ScriptInStartup, 0.90),
                    PersistenceLocation::TaskSchedulerXml => (SuspiciousKind::PersistenceLocation, 0.85),
                    _ => (SuspiciousKind::PersistenceLocation, 0.80),
                };
                self.indicators.push(SuspiciousFileIndicator {
                    path: event.path.clone(),
                    kind,
                    confidence: conf,
                    detail: format!("{loc:?}"),
                });
            }
        }
    }

    fn check_temp_exec_writes(&mut self) {
        let temp_prefixes = [
            "\\temp\\", "\\tmp\\", "\\appdata\\local\\temp\\",
            "\\windows\\temp\\", "%temp%",
        ];
        for event in &self.events {
            if !event.op.is_write_op() { continue; }
            let lower = event.path.to_ascii_lowercase();
            let in_temp = temp_prefixes.iter().any(|p| lower.contains(p));
            if in_temp
                && let Some(ext) = event.extension() {
                    let cat = FileCategory::from_extension(ext);
                    if matches!(cat, FileCategory::Executable | FileCategory::Script) {
                        self.indicators.push(SuspiciousFileIndicator {
                            path: event.path.clone(),
                            kind: SuspiciousKind::TempExecWrite,
                            confidence: 0.70,
                            detail: format!("executable/script written to temp dir by pid {}", event.pid),
                        });
                    }
                }
        }
    }

    fn check_mass_deletion(&mut self) {
        let mut pid_deletes: HashMap<u32, Vec<&str>> = HashMap::new();
        for event in &self.events {
            if event.op == FileOpKind::Delete {
                pid_deletes.entry(event.pid).or_default().push(&event.path);
            }
        }
        for (pid, paths) in &pid_deletes {
            if paths.len() >= 20 {
                self.indicators.push(SuspiciousFileIndicator {
                    path: format!("pid:{pid}"),
                    kind: SuspiciousKind::MassFileDeletion,
                    confidence: 0.80,
                    detail: format!("pid {} deleted {} files", pid, paths.len()),
                });
            }
        }
    }

    fn check_ransomware_patterns(&mut self) {
        for (dir, stats) in &self.dir_stats {
            if stats.is_ransomware_like() {
                self.indicators.push(SuspiciousFileIndicator {
                    path: dir.clone(),
                    kind: SuspiciousKind::RansomwareLikePattern,
                    confidence: 0.88,
                    detail: format!(
                        "created={} deleted={} written={} bytes={}",
                        stats.files_created, stats.files_deleted, stats.files_written, stats.bytes_written
                    ),
                });
            }
        }
    }

    // ─── Queries ──────────────────────────────────────────────────────────────

    #[must_use] 
    pub fn events_for_pid(&self, pid: u32) -> Vec<&FileEvent> {
        self.events.iter().filter(|e| e.pid == pid).collect()
    }

    #[must_use] 
    pub fn events_for_path(&self, path: &str) -> Vec<&FileEvent> {
        let lower = path.to_ascii_lowercase();
        self.events.iter().filter(|e| e.path.to_ascii_lowercase() == lower).collect()
    }

    #[must_use] 
    pub fn writes_only(&self) -> Vec<&FileEvent> {
        self.events.iter().filter(|e| e.op == FileOpKind::Write || e.op == FileOpKind::Create).collect()
    }

    #[must_use] 
    pub fn high_entropy_writes(&self, threshold: f64) -> Vec<&FileEvent> {
        self.events.iter().filter(|e| e.entropy.is_some_and(|en| en >= threshold)).collect()
    }

    #[must_use] 
    pub fn unique_pids(&self) -> HashSet<u32> {
        self.events.iter().map(|e| e.pid).collect()
    }

    #[must_use] 
    pub fn unique_paths(&self) -> HashSet<&str> {
        self.events.iter().map(|e| e.path.as_str()).collect()
    }

    #[must_use] 
    pub fn total_bytes_written(&self) -> u64 {
        self.events.iter().filter(|e| e.op == FileOpKind::Write).map(|e| e.bytes_transferred).sum()
    }

    #[must_use] 
    pub fn indicators(&self) -> &[SuspiciousFileIndicator] {
        &self.indicators
    }

    #[must_use] 
    pub fn high_severity_indicators(&self, min_severity: u8) -> Vec<&SuspiciousFileIndicator> {
        self.indicators.iter().filter(|i| i.kind.severity() >= min_severity).collect()
    }

    #[must_use] 
    pub fn events(&self) -> &[FileEvent] {
        &self.events
    }

    #[must_use] 
    pub const fn event_count(&self) -> usize {
        self.events.len()
    }

    #[must_use] 
    pub const fn hash_cache(&self) -> &FileHashCache {
        &self.hash_cache
    }

    #[must_use] 
    pub const fn patterns(&self) -> &HashMap<String, FileAccessPattern> {
        &self.patterns
    }

    #[must_use] 
    pub const fn dir_stats(&self) -> &HashMap<String, DirectoryStats> {
        &self.dir_stats
    }
}

// ─── File monitor report ─────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileMonitorReport {
    pub total_events: usize,
    pub unique_files: usize,
    pub unique_processes: usize,
    pub total_bytes_written: u64,
    pub high_entropy_files: Vec<String>,
    pub suspicious_indicators: Vec<SuspiciousFileIndicator>,
    pub top_writers: Vec<(u32, String, u64)>,
    pub persistence_drops: Vec<String>,
    pub ransomware_dirs: Vec<String>,
    pub summary: String,
}

impl FileMonitorReport {
    #[must_use] 
    pub fn generate(monitor: &FileMonitor) -> Self {
        let total_events = monitor.event_count();
        let unique_files = monitor.unique_paths().len();
        let unique_processes = monitor.unique_pids().len();
        let total_bytes_written = monitor.total_bytes_written();

        let high_entropy_files = monitor.hash_cache()
            .high_entropy_files(7.2)
            .iter()
            .map(|(p, _)| p.to_string())
            .collect();

        let suspicious_indicators = monitor.indicators().to_vec();

        // top writers by bytes
        let mut pid_bytes: HashMap<(u32, String), u64> = HashMap::new();
        for e in monitor.events() {
            if e.op == FileOpKind::Write {
                *pid_bytes.entry((e.pid, e.process_name.clone())).or_default() += e.bytes_transferred;
            }
        }
        let mut top_writers: Vec<(u32, String, u64)> = pid_bytes.into_iter().map(|((pid, name), b)| (pid, name, b)).collect();
        top_writers.sort_by(|a, b| b.2.cmp(&a.2));
        top_writers.truncate(10);

        let persistence_drops: Vec<String> = suspicious_indicators.iter()
            .filter(|i| matches!(i.kind, SuspiciousKind::PersistenceLocation | SuspiciousKind::ScriptInStartup))
            .map(|i| i.path.clone())
            .collect();

        let ransomware_dirs: Vec<String> = suspicious_indicators.iter()
            .filter(|i| i.kind == SuspiciousKind::RansomwareLikePattern)
            .map(|i| i.path.clone())
            .collect();

        let high_sev = suspicious_indicators.iter().filter(|i| i.kind.severity() >= 7).count();
        let summary = format!(
            "{} events across {} files from {} processes; {} MiB written; {} high-severity indicators",
            total_events, unique_files, unique_processes,
            total_bytes_written / (1024 * 1024),
            high_sev
        );

        Self {
            total_events, unique_files, unique_processes, total_bytes_written,
            high_entropy_files, suspicious_indicators, top_writers,
            persistence_drops, ransomware_dirs, summary,
        }
    }

    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string_pretty(self).context("serialize FileMonitorReport")
    }
}

// ─── Thread-safe shared monitor ───────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct SharedFileMonitor(Arc<Mutex<FileMonitor>>);

impl SharedFileMonitor {
    #[must_use] 
    pub fn new() -> Self {
        Self(Arc::new(Mutex::new(FileMonitor::new())))
    }

    pub fn ingest(&self, event: FileEvent) {
        if let Ok(mut m) = self.0.lock() {
            m.ingest(event);
        }
    }

    pub fn ingest_with_content(&self, event: FileEvent, content: &[u8]) {
        if let Ok(mut m) = self.0.lock() {
            m.ingest_with_content(event, content);
        }
    }

    pub fn analyze_suspicious(&self) {
        if let Ok(mut m) = self.0.lock() {
            m.analyze_suspicious();
        }
    }

    #[must_use] 
    pub fn report(&self) -> Option<FileMonitorReport> {
        self.0.lock().ok().map(|m| FileMonitorReport::generate(&m))
    }

    #[must_use] 
    pub fn event_count(&self) -> usize {
        self.0.lock().map(|m| m.event_count()).unwrap_or(0)
    }
}

impl Default for SharedFileMonitor {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Batch scan ──────────────────────────────────────────────────────────────

#[must_use] 
pub fn scan_events_parallel(events: Vec<FileEvent>) -> FileMonitorReport {
    let monitor = Arc::new(Mutex::new(FileMonitor::new()));
    events.into_par_iter().for_each(|event| {
        if let Ok(mut m) = monitor.lock() {
            m.ingest(event);
        }
    });
    let mut m = monitor.lock().unwrap();
    m.analyze_suspicious();
    FileMonitorReport::generate(&m)
}

/// Convert a raw path string into an owned [`PathBuf`], canonicalising
/// separators so downstream consumers can compare paths reliably.
#[must_use]
pub fn normalize_event_path(path: &str) -> PathBuf {
    PathBuf::from(path.replace('/', "\\"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_known() {
        // SHA-256 of empty string
        let h = sha256_hex(b"");
        assert_eq!(h, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    }

    #[test]
    fn test_entropy_uniform() {
        let data: Vec<u8> = (0u8..=255).collect();
        let e = byte_entropy(&data);
        assert!((e - 8.0).abs() < 0.01, "uniform entropy should be 8.0, got {}", e);
    }

    #[test]
    fn test_entropy_constant() {
        let data = vec![0xABu8; 1024];
        let e = byte_entropy(&data);
        assert!(e < 0.001, "constant entropy should be 0, got {}", e);
    }

    #[test]
    fn test_file_event_extension() {
        let e = FileEvent::new(1, 1, "test.exe".into(), FileOpKind::Write, "C:\\Windows\\temp\\payload.exe".into());
        assert_eq!(e.extension(), Some("exe"));
    }

    #[test]
    fn test_double_extension_detection() {
        let mut m = FileMonitor::new();
        let e = FileEvent::new(100, 1, "malware".into(), FileOpKind::Create, "C:\\Users\\victim\\invoice.pdf.exe".into());
        m.ingest(e);
        m.analyze_suspicious();
        let double_ext: Vec<_> = m.indicators().iter().filter(|i| i.kind == SuspiciousKind::DoubleExtension).collect();
        assert!(!double_ext.is_empty(), "double extension should be detected");
    }

    #[test]
    fn test_persistence_startup() {
        let loc = PersistenceLocation::detect("C:\\Users\\Victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\updater.exe");
        assert!(matches!(loc, Some(PersistenceLocation::StartupFolder)));
    }

    #[test]
    fn test_file_category() {
        assert_eq!(FileCategory::from_extension("exe"), FileCategory::Executable);
        assert_eq!(FileCategory::from_extension("ps1"), FileCategory::Script);
        assert_eq!(FileCategory::from_extension("zip"), FileCategory::Archive);
    }

    #[test]
    fn test_hash_cache() {
        let mut cache = FileHashCache::new();
        cache.compute_and_cache("test.bin", b"hello world");
        let e = cache.get("test.bin").unwrap();
        // The real SHA-256 of "hello world". The constant here used to diverge
        // after 19 bytes and carried the comment "not real but tests structure",
        // which made the assertion contradict the (correct) implementation.
        assert_eq!(e.sha256, "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9");
        // just verify it produced some 64-char hex
        assert_eq!(e.sha256.len(), 64);
    }

    #[test]
    fn test_directory_stats_ransomware() {
        let mut ds = DirectoryStats::new("C:\\Users\\victim\\Documents".into());
        for i in 0..30 {
            let mut e = FileEvent::new(1, 1, "ransomware".into(), FileOpKind::Write, format!("C:\\Users\\victim\\Documents\\file{}.txt.enc", i));
            e.bytes_transferred = 50_000;
            ds.add_event(&e);
        }
        for i in 0..25 {
            let e = FileEvent::new(1, 1, "ransomware".into(), FileOpKind::Delete, format!("C:\\Users\\victim\\Documents\\file{}.txt", i));
            ds.add_event(&e);
        }
        assert!(ds.is_ransomware_like(), "should detect ransomware-like pattern");
    }
}
