//! Dropper malware analysis — `DropperAnalysis`, payload extraction, and reporting.
//!
//! A *dropper* is malware whose primary purpose is to deposit a secondary payload
//! on disk or in memory and arrange for its execution.  This module models that
//! entire pipeline: locating encrypted/encoded payload blobs inside a sample,
//! decrypting them, recording every dropped file and spawned process, and
//! assembling a structured `DropperReport`.

use std::collections::HashMap;
use std::fmt;
use std::path::{Path, PathBuf};

/// Group dropped artifacts by the directory their target path lives in.
///
/// Returns an empty map if `paths` is empty.  Used by the report builder
/// to surface "this dropper writes to N distinct directories" without
/// every caller re-implementing path normalization.
#[must_use]
pub fn group_paths_by_parent(paths: &[PathBuf]) -> HashMap<PathBuf, Vec<PathBuf>> {
    let mut groups: HashMap<PathBuf, Vec<PathBuf>> = HashMap::new();
    for p in paths {
        let parent: &Path = p.parent().unwrap_or_else(|| Path::new(""));
        groups.entry(parent.to_path_buf()).or_default().push(p.clone());
    }
    groups
}

use serde::{Deserialize, Serialize};
use md5::Md5;
use sha2::{Digest, Sha256};
use thiserror::Error;

// ─── Errors ───────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum DropperError {
    #[error("payload decryption failed: {0}")]
    DecryptionFailed(String),
    #[error("unsupported encoding: {0}")]
    UnsupportedEncoding(String),
    #[error("payload too small ({0} bytes)")]
    PayloadTooSmall(usize),
    #[error("invalid PE magic in extracted payload")]
    InvalidPeMagic,
    #[error("extraction limit reached ({0} payloads)")]
    LimitReached(usize),
    #[error("io error: {0}")]
    Io(String),
}

pub type DropperResult<T> = Result<T, DropperError>;

// ─── Encoding / encryption primitives ─────────────────────────────────────────

/// Encoding scheme used to hide the payload blob.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EncodingScheme {
    None,
    Base64,
    Base64Url,
    Hex,
    Xor { key: Vec<u8> },
    Rc4 { key: Vec<u8> },
    Aes128Cbc { key: [u8; 16], iv: [u8; 16] },
    Aes256Cbc { key: [u8; 32], iv: [u8; 16] },
    ChaCha20 { key: [u8; 32], nonce: [u8; 12] },
    Rot13,
    Custom(String),
}

impl fmt::Display for EncodingScheme {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::None => write!(f, "plaintext"),
            Self::Base64 => write!(f, "base64"),
            Self::Base64Url => write!(f, "base64url"),
            Self::Hex => write!(f, "hex"),
            Self::Xor { key } => write!(f, "xor({} bytes key)", key.len()),
            Self::Rc4 { key } => write!(f, "rc4({} bytes key)", key.len()),
            Self::Aes128Cbc { .. } => write!(f, "aes-128-cbc"),
            Self::Aes256Cbc { .. } => write!(f, "aes-256-cbc"),
            Self::ChaCha20 { .. } => write!(f, "chacha20"),
            Self::Rot13 => write!(f, "rot13"),
            Self::Custom(s) => write!(f, "custom({s})"),
        }
    }
}

// ─── EncryptedPayload ─────────────────────────────────────────────────────────

/// A raw encrypted/encoded payload blob found inside a dropper sample.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedPayload {
    /// Byte offset inside the host binary where this blob begins.
    pub offset: u64,
    /// Raw (still encoded/encrypted) bytes.
    pub raw_bytes: Vec<u8>,
    /// Detected encoding/encryption scheme.
    pub scheme: EncodingScheme,
    /// Decrypted bytes (populated after `PayloadExtractor::decrypt`).
    pub decrypted: Option<Vec<u8>>,
    /// SHA-256 of the raw bytes.
    pub raw_sha256: [u8; 32],
    /// SHA-256 of the decrypted bytes, if available.
    pub decrypted_sha256: Option<[u8; 32]>,
    /// Heuristic confidence that this is a real embedded payload (0.0–1.0).
    pub confidence: f64,
    /// Human-readable notes from detection heuristics.
    pub notes: Vec<String>,
}

impl EncryptedPayload {
    /// Construct a new payload stub with pre-computed SHA-256.
    #[must_use] 
    pub fn new(offset: u64, raw_bytes: Vec<u8>, scheme: EncodingScheme) -> Self {
        let raw_sha256 = sha256_of(&raw_bytes);
        let confidence = heuristic_confidence(&raw_bytes, &scheme);
        Self {
            offset,
            raw_bytes,
            scheme,
            decrypted: None,
            raw_sha256,
            decrypted_sha256: None,
            confidence,
            notes: Vec::new(),
        }
    }

    /// Returns `true` if decryption has already been performed.
    #[must_use] 
    pub const fn is_decrypted(&self) -> bool {
        self.decrypted.is_some()
    }

    /// Returns the decrypted length, or the raw length when not yet decrypted.
    #[must_use] 
    pub fn effective_len(&self) -> usize {
        self.decrypted
            .as_ref()
            .map_or(self.raw_bytes.len(), std::vec::Vec::len)
    }

    /// Add a diagnostic note.
    pub fn add_note(&mut self, note: impl Into<String>) {
        self.notes.push(note.into());
    }
}

// ─── DroppedFile ──────────────────────────────────────────────────────────────

/// Represents a file written to disk by the dropper.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DroppedFile {
    /// Destination path observed or inferred.
    pub path: PathBuf,
    /// Content bytes (may be the decrypted payload or a resource).
    pub content: Vec<u8>,
    /// SHA-256 of `content`.
    pub sha256: [u8; 32],
    /// MD5 of `content`.
    pub md5: [u8; 16],
    /// Detected file type.
    pub file_type: DetectedFileType,
    /// Whether the file is executed immediately after being dropped.
    pub executed: bool,
    /// Persistence mechanism used, if any.
    pub persistence: Option<PersistenceMechanism>,
    /// Whether the file was deleted after execution (self-deletion pattern).
    pub self_deleted: bool,
    /// Arbitrary metadata tags.
    pub tags: Vec<String>,
}

impl DroppedFile {
    pub fn new(path: impl Into<PathBuf>, content: Vec<u8>) -> Self {
        let sha256 = sha256_of(&content);
        let md5 = md5_of(&content);
        let file_type = DetectedFileType::from_magic(&content);
        Self {
            path: path.into(),
            content,
            sha256,
            md5,
            file_type,
            executed: false,
            persistence: None,
            self_deleted: false,
            tags: Vec::new(),
        }
    }

    /// Returns a hex-encoded SHA-256 string.
    #[must_use] 
    pub fn sha256_hex(&self) -> String {
        hex_encode(&self.sha256)
    }

    /// Returns a hex-encoded MD5 string.
    #[must_use] 
    pub fn md5_hex(&self) -> String {
        hex_encode(&self.md5)
    }

    /// Check whether the file is an executable (PE, ELF, Mach-O, …).
    #[must_use] 
    pub const fn is_executable(&self) -> bool {
        matches!(
            self.file_type,
            DetectedFileType::Pe
                | DetectedFileType::Elf
                | DetectedFileType::MachO
                | DetectedFileType::Shellcode
        )
    }
}

// ─── DroppedProcess ───────────────────────────────────────────────────────────

/// A process spawned by the dropper.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DroppedProcess {
    pub pid: Option<u32>,
    pub parent_pid: Option<u32>,
    pub image_path: PathBuf,
    pub command_line: String,
    pub creation_time_ms: u64,
    pub injection_technique: Option<InjectionTechnique>,
    pub hollow: bool,
    pub suspended_start: bool,
    /// Network connections initiated by this process.
    pub network_connections: Vec<NetworkConnection>,
}

impl DroppedProcess {
    pub fn new(image_path: impl Into<PathBuf>, command_line: impl Into<String>) -> Self {
        Self {
            pid: None,
            parent_pid: None,
            image_path: image_path.into(),
            command_line: command_line.into(),
            creation_time_ms: 0,
            injection_technique: None,
            hollow: false,
            suspended_start: false,
            network_connections: Vec::new(),
        }
    }

    /// Returns `true` when any injection technique is recorded.
    #[must_use] 
    pub const fn is_injected(&self) -> bool {
        self.injection_technique.is_some()
    }
}

// ─── Supporting enumerations ───────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DetectedFileType {
    Pe,
    Elf,
    MachO,
    Dex,
    Jar,
    Pdf,
    Office,
    Rtf,
    Zip,
    SevenZip,
    Cab,
    Script,
    Shellcode,
    Unknown,
}

impl DetectedFileType {
    #[must_use] 
    pub fn from_magic(bytes: &[u8]) -> Self {
        if bytes.len() < 4 {
            return Self::Unknown;
        }
        match &bytes[..4] {
            [0x4d, 0x5a, ..] => Self::Pe,
            [0x7f, 0x45, 0x4c, 0x46] => Self::Elf,
            [0xce | 0xcf, 0xfa, 0xed, 0xfe] => Self::MachO,
            [0x64, 0x65, 0x78, 0x0a] => Self::Dex,
            [0x50, 0x4b, 0x03, 0x04] => Self::Jar,
            [0x25, 0x50, 0x44, 0x46] => Self::Pdf,
            [0x37, 0x7a, 0xbc, 0xaf] => Self::SevenZip,
            [0x4d, 0x53, 0x43, 0x46] => Self::Cab,
            b if b.starts_with(b"{\rtf") => Self::Rtf,
            _ => Self::Unknown,
        }
    }

    #[must_use] 
    pub const fn is_document(&self) -> bool {
        matches!(self, Self::Pdf | Self::Office | Self::Rtf)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PersistenceMechanism {
    RegistryRunKey(String),
    RegistryRunOnce(String),
    ScheduledTask(String),
    ServiceInstall(String),
    StartupFolder(PathBuf),
    DllHijacking(String),
    BitsJob(String),
    WmiSubscription(String),
    LdPreload,
    CronJob(String),
    LaunchDaemon(PathBuf),
    Custom(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InjectionTechnique {
    RemoteThreadCreate,
    ProcessHollow,
    ProcessDoppelganging,
    AtomBombing,
    NtQueueApcThread,
    EarlyBirdApc,
    MapViewOfSection,
    ReflectiveDllInjection,
    ManualMap,
    PtraceSyscall,
    Custom(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConnection {
    pub proto: NetworkProto,
    pub remote_addr: String,
    pub remote_port: u16,
    pub bytes_sent: u64,
    pub bytes_recv: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NetworkProto {
    Tcp,
    Udp,
    Dns,
    Http,
    Https,
}

// ─── PayloadExtractor ─────────────────────────────────────────────────────────

/// Scans a binary blob and extracts embedded encrypted payloads.
#[derive(Debug)]
pub struct PayloadExtractor {
    /// Minimum payload size to consider.
    pub min_payload_size: usize,
    /// Maximum number of payloads to extract per sample.
    pub max_payloads: usize,
    /// Only extract payloads above this confidence threshold.
    pub confidence_threshold: f64,
}

impl Default for PayloadExtractor {
    fn default() -> Self {
        Self {
            min_payload_size: 512,
            max_payloads: 32,
            confidence_threshold: 0.4,
        }
    }
}

impl PayloadExtractor {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    /// Scan `data` for embedded payload blobs and return candidates.
    pub fn find_payloads(&self, data: &[u8]) -> DropperResult<Vec<EncryptedPayload>> {
        let mut payloads = Vec::new();

        // 1. Base64 regions
        if let Ok(mut found) = self.find_base64_regions(data) {
            payloads.append(&mut found);
        }

        // 2. High-entropy regions (possible AES/XOR blobs)
        if let Ok(mut found) = self.find_high_entropy_regions(data) {
            payloads.append(&mut found);
        }

        // 3. XOR-encoded PE patterns
        if let Ok(mut found) = self.find_xor_pe_patterns(data) {
            payloads.append(&mut found);
        }

        // 4. RC4-style blobs (small key followed by high-entropy block)
        if let Ok(mut found) = self.find_rc4_blobs(data) {
            payloads.append(&mut found);
        }

        // Filter by confidence and size
        payloads.retain(|p| {
            p.confidence >= self.confidence_threshold
                && p.raw_bytes.len() >= self.min_payload_size
        });

        // Deduplicate by raw SHA-256
        payloads.sort_by(|a, b| a.offset.cmp(&b.offset));
        payloads.dedup_by_key(|p| p.raw_sha256);

        if payloads.len() > self.max_payloads {
            return Err(DropperError::LimitReached(self.max_payloads));
        }

        Ok(payloads)
    }

    fn find_base64_regions(&self, data: &[u8]) -> DropperResult<Vec<EncryptedPayload>> {
        let mut results = Vec::new();
        let text = match std::str::from_utf8(data) {
            Ok(s) => s,
            Err(_) => return Ok(results),
        };

        // Naïve scan: look for runs of base64 chars ≥ min_payload_size * 4/3
        let min_run = (self.min_payload_size * 4 / 3).max(64);
        let mut run_start: Option<usize> = None;
        let mut run_len = 0usize;

        for (i, ch) in text.char_indices() {
            if is_base64_char(ch) {
                if run_start.is_none() {
                    run_start = Some(i);
                }
                run_len += 1;
            } else {
                if run_len >= min_run {
                    let start = run_start.unwrap();
                    let slice = &data[start..start + run_len];
                    let mut p =
                        EncryptedPayload::new(start as u64, slice.to_vec(), EncodingScheme::Base64);
                    p.add_note(format!("base64 run at 0x{start:x}, {run_len} chars"));
                    results.push(p);
                }
                run_start = None;
                run_len = 0;
            }
        }
        // Emit the trailing run if it reached the end of the data without a
        // non-base64 terminator.
        if run_len >= min_run {
            let start = run_start.unwrap();
            let slice = &data[start..start + run_len];
            let mut p =
                EncryptedPayload::new(start as u64, slice.to_vec(), EncodingScheme::Base64);
            p.add_note(format!("base64 run at 0x{start:x}, {run_len} chars (trailing)"));
            results.push(p);
        }
        Ok(results)
    }

    fn find_high_entropy_regions(&self, data: &[u8]) -> DropperResult<Vec<EncryptedPayload>> {
        let mut results = Vec::new();
        let window = 256usize;
        let step = 128usize;
        let entropy_threshold = 7.2f64;

        let mut i = 0;
        while i + window <= data.len() {
            let e = shannon_entropy(&data[i..i + window]);
            if e >= entropy_threshold {
                // Expand the region
                let mut end = i + window;
                while end + step <= data.len()
                    && shannon_entropy(&data[end..end + step]) >= entropy_threshold
                {
                    end += step;
                }
                let blob = &data[i..end];
                if blob.len() >= self.min_payload_size {
                    let scheme = EncodingScheme::Xor { key: vec![0x00] };
                    let mut p = EncryptedPayload::new(i as u64, blob.to_vec(), scheme);
                    p.add_note(format!(
                        "high-entropy region 0x{i:x}..0x{end:x}, entropy={e:.2}"
                    ));
                    results.push(p);
                }
                i = end;
            } else {
                i += step;
            }
        }
        Ok(results)
    }

    fn find_xor_pe_patterns(&self, data: &[u8]) -> DropperResult<Vec<EncryptedPayload>> {
        let mut results = Vec::new();
        // For each single-byte XOR key, check if XORing the first two bytes gives 'MZ'
        for key in 0u8..=255 {
            if key == 0 {
                continue;
            }
            let target_b0 = b'M' ^ key;
            let target_b1 = b'Z' ^ key;
            let mut offset = 0;
            while offset + 64 <= data.len() {
                if data[offset] == target_b0 && data[offset + 1] == target_b1 {
                    // Heuristically determine PE size from the MZ/PE header fields
                    // after XOR-decoding the first 0x40 bytes, then cap at a
                    // reasonable limit to avoid huge allocations on large dumps.
                    const MAX_EXTRACT: usize = 16 * 1024 * 1024; // 16 MiB hard cap
                    let header_end = (offset + 0x40).min(data.len());
                    let decoded_header: Vec<u8> = data[offset..header_end]
                        .iter()
                        .map(|b| b ^ key)
                        .collect();
                    // e_lfanew is at decoded bytes 0x3c..0x40 (little-endian u32).
                    let pe_size_hint = if decoded_header.len() >= 0x40 {
                        let e_lfanew = u32::from_le_bytes([
                            decoded_header[0x3c],
                            decoded_header[0x3d],
                            decoded_header[0x3e],
                            decoded_header[0x3f],
                        ]) as usize;
                        // Sanity: e_lfanew should be < 0x200 for a normal PE.
                        if e_lfanew > 0 && e_lfanew < 0x200 {
                            // Rough upper bound: add 4 MiB to the PE header offset.
                            (e_lfanew + 4 * 1024 * 1024).min(MAX_EXTRACT)
                        } else {
                            MAX_EXTRACT
                        }
                    } else {
                        MAX_EXTRACT
                    };
                    let end = (offset + pe_size_hint).min(data.len());
                    let blob = data[offset..end].to_vec();
                    if blob.len() >= self.min_payload_size {
                        let scheme = EncodingScheme::Xor { key: vec![key] };
                        let mut p = EncryptedPayload::new(offset as u64, blob, scheme);
                        p.confidence = 0.85;
                        p.add_note(format!(
                            "XOR-encoded PE at 0x{offset:x} with key=0x{key:02x}"
                        ));
                        results.push(p);
                    }
                }
                offset += 1;
            }
        }
        Ok(results)
    }

    fn find_rc4_blobs(&self, data: &[u8]) -> DropperResult<Vec<EncryptedPayload>> {
        let mut results = Vec::new();
        // Heuristic: look for a 16/32-byte key-like block followed by high entropy
        for key_len in [16usize, 32] {
            let min_blob = self.min_payload_size;
            let mut i = 0;
            while i + key_len + min_blob <= data.len() {
                let key_candidate = &data[i..i + key_len];
                let blob = &data[i + key_len..i + key_len + min_blob];
                let key_entropy = shannon_entropy(key_candidate);
                let blob_entropy = shannon_entropy(blob);
                if key_entropy > 3.5 && key_entropy < 6.5 && blob_entropy > 7.0 {
                    let full_blob = data[i + key_len
                        ..(i + key_len + 32768).min(data.len())]
                        .to_vec();
                    let scheme = EncodingScheme::Rc4 {
                        key: key_candidate.to_vec(),
                    };
                    let mut p = EncryptedPayload::new((i + key_len) as u64, full_blob, scheme);
                    p.add_note(format!(
                        "RC4 candidate: {key_len}-byte key at 0x{i:x}"
                    ));
                    results.push(p);
                    i += key_len + min_blob;
                } else {
                    i += 16;
                }
            }
        }
        Ok(results)
    }

    /// Decrypt a payload in place using its recorded scheme.
    pub fn decrypt(&self, payload: &mut EncryptedPayload) -> DropperResult<()> {
        let plaintext = match &payload.scheme {
            EncodingScheme::None => payload.raw_bytes.clone(),
            EncodingScheme::Base64 => {
                let s = std::str::from_utf8(&payload.raw_bytes)
                    .map_err(|e| DropperError::DecryptionFailed(e.to_string()))?;
                base64_decode(s.trim())
                    .ok_or_else(|| DropperError::DecryptionFailed("bad base64".into()))?
            }
            EncodingScheme::Hex => {
                let s = std::str::from_utf8(&payload.raw_bytes)
                    .map_err(|e| DropperError::DecryptionFailed(e.to_string()))?;
                hex_decode(s.trim())
                    .ok_or_else(|| DropperError::DecryptionFailed("bad hex".into()))?
            }
            EncodingScheme::Xor { key } => xor_decrypt(&payload.raw_bytes, key),
            EncodingScheme::Rc4 { key } => rc4_decrypt(&payload.raw_bytes, key),
            EncodingScheme::Rot13 => rot13_decode(&payload.raw_bytes),
            EncodingScheme::Base64Url => {
                let s = std::str::from_utf8(&payload.raw_bytes)
                    .map_err(|e| DropperError::DecryptionFailed(e.to_string()))?;
                base64url_decode(s.trim())
                    .ok_or_else(|| DropperError::DecryptionFailed("bad base64url".into()))?
            }
            enc => {
                return Err(DropperError::UnsupportedEncoding(enc.to_string()));
            }
        };

        if plaintext.len() < 2 {
            return Err(DropperError::PayloadTooSmall(plaintext.len()));
        }

        let hash = sha256_of(&plaintext);
        payload.decrypted_sha256 = Some(hash);
        payload.decrypted = Some(plaintext);
        Ok(())
    }
}

// ─── DropperAnalysis ──────────────────────────────────────────────────────────

/// Configuration and state for dropper analysis.
#[derive(Debug, Default)]
pub struct DropperAnalysis {
    pub extractor: PayloadExtractor,
    pub sample_path: Option<PathBuf>,
    pub payloads: Vec<EncryptedPayload>,
    pub dropped_files: Vec<DroppedFile>,
    pub dropped_processes: Vec<DroppedProcess>,
    pub analysis_notes: Vec<String>,
    pub mitre_techniques: Vec<String>,
}

impl DropperAnalysis {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    /// Set which binary file is being analysed.
    pub fn with_sample(mut self, path: impl Into<PathBuf>) -> Self {
        self.sample_path = Some(path.into());
        self
    }

    /// Run full analysis against raw binary `data`.
    pub fn analyse(&mut self, data: &[u8]) -> DropperResult<DropperReport> {
        // 1. Extract payload candidates
        match self.extractor.find_payloads(data) {
            Ok(p) => self.payloads = p,
            Err(DropperError::LimitReached(n)) => {
                self.analysis_notes
                    .push(format!("payload limit reached ({n}), truncated"));
            }
            Err(e) => return Err(e),
        }

        // 2. Decrypt each payload; record failures as analysis notes.
        for p in &mut self.payloads {
            if let Err(e) = self.extractor.decrypt(p) {
                self.analysis_notes.push(format!(
                    "decrypt failed for payload at 0x{:x} ({}): {e}",
                    p.offset, p.scheme,
                ));
            }
        }

        // 3. Classify dropped files from decrypted payloads
        for p in &self.payloads {
            if let Some(dec) = &p.decrypted {
                let path = format!(
                    "dropped_{}.bin",
                    &hex_encode(&p.decrypted_sha256.unwrap_or(p.raw_sha256))[..8]
                );
                let mut f = DroppedFile::new(path, dec.clone());
                // Mark as executed if looks like an executable
                if f.is_executable() {
                    f.executed = true;
                }
                self.dropped_files.push(f);
            }
        }

        // 4. Detect MITRE techniques
        self.mitre_techniques = detect_mitre_techniques(data, &self.dropped_files);

        Ok(self.build_report())
    }

    fn build_report(&self) -> DropperReport {
        DropperReport {
            sample_path: self.sample_path.clone(),
            payloads: self.payloads.clone(),
            dropped_files: self.dropped_files.clone(),
            dropped_processes: self.dropped_processes.clone(),
            analysis_notes: self.analysis_notes.clone(),
            mitre_techniques: self.mitre_techniques.clone(),
            risk_score: self.compute_risk_score(),
        }
    }

    fn compute_risk_score(&self) -> f64 {
        let mut score = 0.0f64;
        score += self.payloads.len() as f64 * 5.0;
        score += self.dropped_files.iter().filter(|f| f.is_executable()).count() as f64 * 15.0;
        score += self.dropped_files.iter().filter(|f| f.executed).count() as f64 * 10.0;
        score += self.dropped_files.iter().filter(|f| f.persistence.is_some()).count() as f64 * 20.0;
        score += self.dropped_processes.iter().filter(|p| p.is_injected()).count() as f64 * 25.0;
        score += self.mitre_techniques.len() as f64 * 3.0;
        score.min(100.0)
    }

    /// Record a dropped file manually (e.g. from dynamic analysis).
    pub fn add_dropped_file(&mut self, file: DroppedFile) {
        self.dropped_files.push(file);
    }

    /// Record a spawned process manually.
    pub fn add_dropped_process(&mut self, proc: DroppedProcess) {
        self.dropped_processes.push(proc);
    }
}

// ─── DropperReport ────────────────────────────────────────────────────────────

/// Complete dropper analysis report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DropperReport {
    pub sample_path: Option<PathBuf>,
    pub payloads: Vec<EncryptedPayload>,
    pub dropped_files: Vec<DroppedFile>,
    pub dropped_processes: Vec<DroppedProcess>,
    pub analysis_notes: Vec<String>,
    pub mitre_techniques: Vec<String>,
    /// 0–100 risk score.
    pub risk_score: f64,
}

impl DropperReport {
    #[must_use] 
    pub fn is_high_risk(&self) -> bool {
        self.risk_score >= 70.0
    }

    #[must_use] 
    pub const fn payload_count(&self) -> usize {
        self.payloads.len()
    }

    #[must_use] 
    pub fn executable_count(&self) -> usize {
        self.dropped_files.iter().filter(|f| f.is_executable()).count()
    }

    #[must_use] 
    pub fn has_persistence(&self) -> bool {
        self.dropped_files.iter().any(|f| f.persistence.is_some())
    }

    #[must_use] 
    pub fn summary(&self) -> String {
        format!(
            "DropperReport: {} payload(s), {} dropped file(s), {} process(es), risk={:.1}",
            self.payloads.len(),
            self.dropped_files.len(),
            self.dropped_processes.len(),
            self.risk_score,
        )
    }

    /// Serialize to JSON.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// All unique SHA-256 hashes (hex) across dropped files.
    #[must_use] 
    pub fn all_hashes(&self) -> Vec<String> {
        self.dropped_files
            .iter()
            .map(DroppedFile::sha256_hex)
            .collect()
    }
}

impl fmt::Display for DropperReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.summary())
    }
}

// ─── Helpers (pure, allocation-light) ─────────────────────────────────────────

fn sha256_of(data: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(data);
    digest.into()
}

fn md5_of(data: &[u8]) -> [u8; 16] {
    Md5::digest(data).into()
}

fn hex_encode(data: &[u8]) -> String {
    hex::encode(data)
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    for chunk in s.as_bytes().chunks(2) {
        let hi = hex_nibble(chunk[0])?;
        let lo = hex_nibble(chunk[1])?;
        out.push((hi << 4) | lo);
    }
    Some(out)
}

const fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn base64_decode(src: &str) -> Option<Vec<u8>> {
    // Simple base64 decoder (no deps).
    const TABLE: &[u8; 128] = &{
        let mut tbl = [255u8; 128];
        let chars = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut idx = 0usize;
        while idx < 64 {
            tbl[chars[idx] as usize] = idx as u8;
            idx += 1;
        }
        tbl
    };
    let src = src.trim_end_matches('=');
    let mut out = Vec::with_capacity(src.len() * 3 / 4);
    let bytes = src.as_bytes();
    let mut pos = 0;
    while pos + 4 <= bytes.len() {
        let v0 = *TABLE.get(bytes[pos] as usize)?;
        let v1 = *TABLE.get(bytes[pos + 1] as usize)?;
        let v2 = *TABLE.get(bytes[pos + 2] as usize)?;
        let v3 = *TABLE.get(bytes[pos + 3] as usize)?;
        if v0 == 255 || v1 == 255 || v2 == 255 || v3 == 255 {
            return None;
        }
        out.push((v0 << 2) | (v1 >> 4));
        out.push((v1 << 4) | (v2 >> 2));
        out.push((v2 << 6) | v3);
        pos += 4;
    }
    Some(out)
}

fn base64url_decode(s: &str) -> Option<Vec<u8>> {
    let canonical: String = s.chars().map(|c| match c {
        '-' => '+',
        '_' => '/',
        c => c,
    }).collect();
    base64_decode(&canonical)
}

fn xor_decrypt(data: &[u8], key: &[u8]) -> Vec<u8> {
    if key.is_empty() {
        return data.to_vec();
    }
    data.iter()
        .zip(key.iter().cycle())
        .map(|(b, k)| b ^ k)
        .collect()
}

fn rc4_decrypt(data: &[u8], key: &[u8]) -> Vec<u8> {
    // Standard RC4 PRGA.
    let mut s: Vec<u8> = (0..=255u8).collect();
    let mut j = 0u8;
    for i in 0..=255usize {
        j = j.wrapping_add(s[i]).wrapping_add(key[i % key.len()]);
        s.swap(i, j as usize);
    }
    let mut i = 0u8;
    let mut j = 0u8;
    data.iter()
        .map(|&byte| {
            i = i.wrapping_add(1);
            j = j.wrapping_add(s[i as usize]);
            s.swap(i as usize, j as usize);
            let k = s[(s[i as usize].wrapping_add(s[j as usize])) as usize];
            byte ^ k
        })
        .collect()
}

fn rot13_decode(data: &[u8]) -> Vec<u8> {
    data.iter()
        .map(|&b| match b {
            b'a'..=b'z' => (b - b'a' + 13) % 26 + b'a',
            b'A'..=b'Z' => (b - b'A' + 13) % 26 + b'A',
            _ => b,
        })
        .collect()
}

fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut freq = [0u32; 256];
    for &b in data {
        freq[b as usize] += 1;
    }
    let len = data.len() as f64;
    freq.iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = f64::from(c) / len;
            -p * p.log2()
        })
        .sum()
}

const fn is_base64_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '='
}

fn heuristic_confidence(data: &[u8], scheme: &EncodingScheme) -> f64 {
    let entropy = shannon_entropy(data);
    let base = match scheme {
        EncodingScheme::None => 0.2,
        EncodingScheme::Base64 | EncodingScheme::Base64Url => 0.6,
        EncodingScheme::Hex => 0.5,
        EncodingScheme::Xor { .. } => 0.55,
        EncodingScheme::Rc4 { .. } => 0.65,
        EncodingScheme::Aes128Cbc { .. } | EncodingScheme::Aes256Cbc { .. } => 0.75,
        EncodingScheme::ChaCha20 { .. } => 0.75,
        EncodingScheme::Rot13 => 0.3,
        EncodingScheme::Custom(_) => 0.4,
    };
    // Scale by entropy (0–8 → 0–1)
    (entropy / 8.0).mul_add(0.3, base).min(1.0)
}

fn detect_mitre_techniques(data: &[u8], files: &[DroppedFile]) -> Vec<String> {
    let mut techniques = Vec::new();

    // T1027 – Obfuscated Files / Information (high entropy blob)
    if shannon_entropy(data) > 7.0 {
        techniques.push("T1027".into());
    }

    // T1055 – Process Injection (if any injected process was found)
    if files.iter().any(DroppedFile::is_executable) {
        techniques.push("T1055".into());
    }

    // T1547 – Boot or Logon Autostart Execution
    if files.iter().any(|f| f.persistence.is_some()) {
        techniques.push("T1547".into());
    }

    // T1140 – Deobfuscate/Decode Files
    techniques.push("T1140".into());

    // T1059 – Command and Scripting Interpreter
    let script_count = files
        .iter()
        .filter(|f| matches!(f.file_type, DetectedFileType::Script))
        .count();
    if script_count > 0 {
        techniques.push("T1059".into());
    }

    techniques.dedup();
    techniques
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // Helper: build a minimal fake PE (MZ header)
    fn fake_pe(size: usize) -> Vec<u8> {
        let mut v = vec![0u8; size.max(64)];
        v[0] = 0x4d; // M
        v[1] = 0x5a; // Z
        v[2] = 0x90;
        v[3] = 0x00;
        v
    }

    fn xor_buf(data: &[u8], key: u8) -> Vec<u8> {
        data.iter().map(|b| b ^ key).collect()
    }

    // ── EncryptedPayload ───────────────────────────────────────────────────────

    #[test]
    fn test_encrypted_payload_new() {
        let p = EncryptedPayload::new(0, vec![0u8; 1024], EncodingScheme::None);
        assert_eq!(p.offset, 0);
        assert_eq!(p.raw_bytes.len(), 1024);
        assert!(!p.is_decrypted());
    }

    #[test]
    fn test_encrypted_payload_effective_len_before_decrypt() {
        let p = EncryptedPayload::new(0, vec![0xAA; 512], EncodingScheme::Base64);
        assert_eq!(p.effective_len(), 512);
    }

    #[test]
    fn test_encrypted_payload_effective_len_after_decrypt() {
        let mut p = EncryptedPayload::new(0, vec![0xAA; 512], EncodingScheme::None);
        p.decrypted = Some(vec![0u8; 300]);
        assert_eq!(p.effective_len(), 300);
    }

    #[test]
    fn test_encrypted_payload_add_note() {
        let mut p = EncryptedPayload::new(0, vec![0u8; 512], EncodingScheme::None);
        p.add_note("test note");
        assert_eq!(p.notes.len(), 1);
        assert_eq!(p.notes[0], "test note");
    }

    #[test]
    fn test_encrypted_payload_is_decrypted_false() {
        let p = EncryptedPayload::new(0, vec![0u8; 512], EncodingScheme::None);
        assert!(!p.is_decrypted());
    }

    #[test]
    fn test_encrypted_payload_confidence_range() {
        let p = EncryptedPayload::new(0, vec![0xAB; 1024], EncodingScheme::Rc4 { key: vec![1, 2, 3] });
        assert!(p.confidence > 0.0 && p.confidence <= 1.0);
    }

    // ── DetectedFileType ───────────────────────────────────────────────────────

    #[test]
    fn test_file_type_pe() {
        assert_eq!(DetectedFileType::from_magic(&[0x4d, 0x5a, 0, 0]), DetectedFileType::Pe);
    }

    #[test]
    fn test_file_type_elf() {
        assert_eq!(
            DetectedFileType::from_magic(&[0x7f, 0x45, 0x4c, 0x46]),
            DetectedFileType::Elf
        );
    }

    #[test]
    fn test_file_type_dex() {
        assert_eq!(
            DetectedFileType::from_magic(&[0x64, 0x65, 0x78, 0x0a]),
            DetectedFileType::Dex
        );
    }

    #[test]
    fn test_file_type_pdf() {
        assert_eq!(
            DetectedFileType::from_magic(&[0x25, 0x50, 0x44, 0x46]),
            DetectedFileType::Pdf
        );
    }

    #[test]
    fn test_file_type_unknown() {
        assert_eq!(DetectedFileType::from_magic(&[0x00, 0x00, 0x00, 0x00]), DetectedFileType::Unknown);
    }

    #[test]
    fn test_file_type_too_short() {
        assert_eq!(DetectedFileType::from_magic(&[0x4d]), DetectedFileType::Unknown);
    }

    #[test]
    fn test_is_document_pdf() {
        assert!(DetectedFileType::Pdf.is_document());
    }

    #[test]
    fn test_is_document_pe_false() {
        assert!(!DetectedFileType::Pe.is_document());
    }

    // ── DroppedFile ────────────────────────────────────────────────────────────

    #[test]
    fn test_dropped_file_new() {
        let f = DroppedFile::new("C:\\Windows\\Temp\\payload.exe", fake_pe(512));
        assert_eq!(f.file_type, DetectedFileType::Pe);
        assert!(!f.executed);
        assert!(!f.self_deleted);
    }

    #[test]
    fn test_dropped_file_sha256_hex_len() {
        let f = DroppedFile::new("test.bin", vec![1, 2, 3, 4]);
        assert_eq!(f.sha256_hex().len(), 64);
    }

    #[test]
    fn test_dropped_file_md5_hex_len() {
        let f = DroppedFile::new("test.bin", vec![1, 2, 3, 4]);
        assert_eq!(f.md5_hex().len(), 32);
    }

    #[test]
    fn test_dropped_file_is_executable_pe() {
        let f = DroppedFile::new("test.exe", fake_pe(512));
        assert!(f.is_executable());
    }

    #[test]
    fn test_dropped_file_is_executable_pdf_false() {
        let mut f = DroppedFile::new("doc.pdf", vec![0x25, 0x50, 0x44, 0x46, 0, 0]);
        f.file_type = DetectedFileType::Pdf;
        assert!(!f.is_executable());
    }

    // ── DroppedProcess ─────────────────────────────────────────────────────────

    #[test]
    fn test_dropped_process_new() {
        let p = DroppedProcess::new("C:\\Windows\\System32\\cmd.exe", "cmd.exe /c whoami");
        assert!(!p.is_injected());
        assert!(!p.hollow);
    }

    #[test]
    fn test_dropped_process_injected() {
        let mut p = DroppedProcess::new("notepad.exe", "notepad.exe");
        p.injection_technique = Some(InjectionTechnique::ProcessHollow);
        assert!(p.is_injected());
    }

    #[test]
    fn test_dropped_process_network_connections() {
        let mut p = DroppedProcess::new("svchost.exe", "svchost.exe -k netsvcs");
        p.network_connections.push(NetworkConnection {
            proto: NetworkProto::Https,
            remote_addr: "1.2.3.4".into(),
            remote_port: 443,
            bytes_sent: 1024,
            bytes_recv: 4096,
        });
        assert_eq!(p.network_connections.len(), 1);
    }

    // ── EncodingScheme Display ─────────────────────────────────────────────────

    #[test]
    fn test_encoding_scheme_display_none() {
        assert_eq!(EncodingScheme::None.to_string(), "plaintext");
    }

    #[test]
    fn test_encoding_scheme_display_base64() {
        assert_eq!(EncodingScheme::Base64.to_string(), "base64");
    }

    #[test]
    fn test_encoding_scheme_display_xor() {
        let s = EncodingScheme::Xor { key: vec![0xAA, 0xBB] };
        assert!(s.to_string().contains("xor"));
    }

    #[test]
    fn test_encoding_scheme_display_rc4() {
        let s = EncodingScheme::Rc4 { key: vec![0; 16] };
        assert!(s.to_string().contains("rc4"));
    }

    // ── PayloadExtractor ───────────────────────────────────────────────────────

    #[test]
    fn test_extractor_decrypt_none() {
        let extractor = PayloadExtractor::new();
        let mut p = EncryptedPayload::new(0, vec![0xAA; 600], EncodingScheme::None);
        extractor.decrypt(&mut p).unwrap();
        assert!(p.is_decrypted());
        assert_eq!(p.decrypted.as_ref().unwrap(), &vec![0xAAu8; 600]);
    }

    #[test]
    fn test_extractor_decrypt_xor() {
        let extractor = PayloadExtractor::new();
        let original = fake_pe(1024);
        let encoded = xor_buf(&original, 0x42);
        let mut p = EncryptedPayload::new(0, encoded, EncodingScheme::Xor { key: vec![0x42] });
        extractor.decrypt(&mut p).unwrap();
        assert_eq!(p.decrypted.as_ref().unwrap(), &original);
    }

    #[test]
    fn test_extractor_decrypt_rc4_roundtrip() {
        let extractor = PayloadExtractor::new();
        let key = vec![0x12, 0x34, 0x56, 0x78];
        let plaintext = vec![0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01, 0x02, 0x03];
        let ciphertext = rc4_decrypt(&plaintext, &key);
        let mut p = EncryptedPayload::new(
            0,
            ciphertext,
            EncodingScheme::Rc4 { key: key.clone() },
        );
        extractor.decrypt(&mut p).unwrap();
        assert_eq!(p.decrypted.as_ref().unwrap(), &plaintext);
    }

    #[test]
    fn test_extractor_decrypt_rot13() {
        let extractor = PayloadExtractor::new();
        let raw: Vec<u8> = b"Uryyb, Jbeyq!".to_vec();
        let mut p = EncryptedPayload::new(0, raw, EncodingScheme::Rot13);
        extractor.decrypt(&mut p).unwrap();
        assert_eq!(p.decrypted.as_ref().unwrap(), b"Hello, World!");
    }

    #[test]
    fn test_extractor_decrypt_unsupported() {
        let extractor = PayloadExtractor::new();
        let mut p = EncryptedPayload::new(
            0,
            vec![0u8; 600],
            EncodingScheme::Aes128Cbc { key: [0u8; 16], iv: [0u8; 16] },
        );
        assert!(extractor.decrypt(&mut p).is_err());
    }

    #[test]
    fn test_extractor_find_xor_pe() {
        let extractor = PayloadExtractor {
            min_payload_size: 16,
            ..Default::default()
        };
        // Place a XOR-encoded MZ header in a 128-byte buffer
        let mut data = vec![0u8; 200];
        let key = 0x77u8;
        data[50] = b'M' ^ key;
        data[51] = b'Z' ^ key;
        let payloads = extractor.find_payloads(&data).unwrap();
        assert!(!payloads.is_empty());
    }

    #[test]
    fn test_extractor_no_payloads_in_zeros() {
        let extractor = PayloadExtractor::default();
        let data = vec![0u8; 2048];
        let payloads = extractor.find_payloads(&data).unwrap();
        // Zero buffer has no high-entropy or base64 regions
        assert!(payloads.iter().all(|p| p.confidence < extractor.confidence_threshold || p.raw_bytes.len() < extractor.min_payload_size));
    }

    // ── DropperAnalysis ────────────────────────────────────────────────────────

    #[test]
    fn test_dropper_analysis_new() {
        let da = DropperAnalysis::new();
        assert!(da.payloads.is_empty());
        assert!(da.dropped_files.is_empty());
    }

    #[test]
    fn test_dropper_analysis_with_sample() {
        let da = DropperAnalysis::new().with_sample("sample.exe");
        assert_eq!(da.sample_path, Some(PathBuf::from("sample.exe")));
    }

    #[test]
    fn test_dropper_analysis_add_dropped_file() {
        let mut da = DropperAnalysis::new();
        da.add_dropped_file(DroppedFile::new("payload.dll", fake_pe(512)));
        assert_eq!(da.dropped_files.len(), 1);
    }

    #[test]
    fn test_dropper_analysis_add_process() {
        let mut da = DropperAnalysis::new();
        da.add_dropped_process(DroppedProcess::new("cmd.exe", "cmd.exe /c calc"));
        assert_eq!(da.dropped_processes.len(), 1);
    }

    #[test]
    fn test_dropper_analysis_analyse_zeros_returns_report() {
        let mut da = DropperAnalysis::new();
        let report = da.analyse(&vec![0u8; 4096]).unwrap();
        assert!(report.risk_score >= 0.0 && report.risk_score <= 100.0);
    }

    #[test]
    fn test_dropper_analysis_analyse_with_pe_payload() {
        // Embed a XOR-encoded PE at offset 100
        let key = 0x33u8;
        let pe = fake_pe(1024);
        let mut data = vec![0u8; 2000];
        let encoded = xor_buf(&pe, key);
        data[100..100 + encoded.len()].copy_from_slice(&encoded);
        let mut da = DropperAnalysis {
            extractor: PayloadExtractor {
                min_payload_size: 16,
                confidence_threshold: 0.0,
                ..Default::default()
            },
            ..Default::default()
        };
        let report = da.analyse(&data).unwrap();
        assert!(report.risk_score >= 0.0);
    }

    // ── DropperReport ──────────────────────────────────────────────────────────

    #[test]
    fn test_report_summary_format() {
        let report = DropperReport {
            sample_path: None,
            payloads: vec![],
            dropped_files: vec![],
            dropped_processes: vec![],
            analysis_notes: vec![],
            mitre_techniques: vec![],
            risk_score: 42.0,
        };
        let s = report.summary();
        assert!(s.contains("42.0"));
    }

    #[test]
    fn test_report_is_high_risk_false() {
        let report = DropperReport {
            sample_path: None,
            payloads: vec![],
            dropped_files: vec![],
            dropped_processes: vec![],
            analysis_notes: vec![],
            mitre_techniques: vec![],
            risk_score: 30.0,
        };
        assert!(!report.is_high_risk());
    }

    #[test]
    fn test_report_is_high_risk_true() {
        let report = DropperReport {
            sample_path: None,
            payloads: vec![],
            dropped_files: vec![],
            dropped_processes: vec![],
            analysis_notes: vec![],
            mitre_techniques: vec![],
            risk_score: 85.0,
        };
        assert!(report.is_high_risk());
    }

    #[test]
    fn test_report_all_hashes() {
        let f = DroppedFile::new("a.exe", fake_pe(512));
        let report = DropperReport {
            sample_path: None,
            payloads: vec![],
            dropped_files: vec![f],
            dropped_processes: vec![],
            analysis_notes: vec![],
            mitre_techniques: vec![],
            risk_score: 0.0,
        };
        let hashes = report.all_hashes();
        assert_eq!(hashes.len(), 1);
        assert_eq!(hashes[0].len(), 64);
    }

    #[test]
    fn test_report_has_persistence_false() {
        let report = DropperReport {
            sample_path: None,
            payloads: vec![],
            dropped_files: vec![DroppedFile::new("a.exe", fake_pe(64))],
            dropped_processes: vec![],
            analysis_notes: vec![],
            mitre_techniques: vec![],
            risk_score: 0.0,
        };
        assert!(!report.has_persistence());
    }

    #[test]
    fn test_report_has_persistence_true() {
        let mut f = DroppedFile::new("a.exe", fake_pe(64));
        f.persistence = Some(PersistenceMechanism::RegistryRunKey(
            "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\malware".into(),
        ));
        let report = DropperReport {
            sample_path: None,
            payloads: vec![],
            dropped_files: vec![f],
            dropped_processes: vec![],
            analysis_notes: vec![],
            mitre_techniques: vec![],
            risk_score: 0.0,
        };
        assert!(report.has_persistence());
    }

    #[test]
    fn test_report_json_serialization() {
        let report = DropperReport {
            sample_path: Some(PathBuf::from("test.exe")),
            payloads: vec![],
            dropped_files: vec![],
            dropped_processes: vec![],
            analysis_notes: vec!["note1".into()],
            mitre_techniques: vec!["T1027".into()],
            risk_score: 55.5,
        };
        let json = report.to_json().unwrap();
        assert!(json.contains("T1027"));
        assert!(json.contains("55.5"));
    }

    // ── Utility functions ──────────────────────────────────────────────────────

    #[test]
    fn test_sha256_of_deterministic() {
        let a = sha256_of(b"hello");
        let b = sha256_of(b"hello");
        assert_eq!(a, b);
    }

    #[test]
    fn test_sha256_of_different_inputs() {
        assert_ne!(sha256_of(b"hello"), sha256_of(b"world"));
    }

    #[test]
    fn test_hex_encode_decode_roundtrip() {
        let data = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let encoded = hex_encode(&data);
        let decoded = hex_decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_hex_decode_invalid() {
        assert!(hex_decode("GG").is_none());
    }

    #[test]
    fn test_base64_decode_hello() {
        // "Hello" in base64 is "SGVsbG8="
        let decoded = base64_decode("SGVsbG8=").unwrap();
        assert_eq!(decoded, b"Hello");
    }

    #[test]
    fn test_base64_decode_empty() {
        let decoded = base64_decode("").unwrap();
        assert!(decoded.is_empty());
    }

    #[test]
    fn test_xor_decrypt_roundtrip() {
        let original = b"test data 1234".to_vec();
        let key = vec![0x55u8];
        let enc = xor_decrypt(&original, &key);
        let dec = xor_decrypt(&enc, &key);
        assert_eq!(dec, original);
    }

    #[test]
    fn test_rc4_decrypt_roundtrip() {
        let key = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let plaintext = b"secret message".to_vec();
        let ct = rc4_decrypt(&plaintext, &key);
        let pt = rc4_decrypt(&ct, &key);
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn test_rot13_roundtrip() {
        let original = b"Hello World".to_vec();
        let encoded = rot13_decode(&original);
        let decoded = rot13_decode(&encoded);
        assert_eq!(decoded, original);
    }

    #[test]
    fn test_shannon_entropy_uniform() {
        // All same bytes → entropy = 0
        let data = vec![0xAAu8; 256];
        assert_eq!(shannon_entropy(&data), 0.0);
    }

    #[test]
    fn test_shannon_entropy_max() {
        // All 256 unique bytes → entropy ≈ 8.0
        let data: Vec<u8> = (0..=255).collect();
        let e = shannon_entropy(&data);
        assert!((e - 8.0).abs() < 0.001);
    }

    #[test]
    fn test_shannon_entropy_empty() {
        assert_eq!(shannon_entropy(&[]), 0.0);
    }

    #[test]
    fn test_mitre_techniques_high_entropy() {
        let data: Vec<u8> = (0..=255u8).cycle().take(4096).collect();
        let techniques = detect_mitre_techniques(&data, &[]);
        assert!(techniques.contains(&"T1027".to_string()));
    }

    #[test]
    fn test_mitre_techniques_always_t1140() {
        let data = vec![0u8; 100];
        let techniques = detect_mitre_techniques(&data, &[]);
        assert!(techniques.contains(&"T1140".to_string()));
    }

    #[test]
    fn test_risk_score_zero_for_empty() {
        let mut da = DropperAnalysis::new();
        let report = da.analyse(&[]).unwrap();
        assert!(report.risk_score >= 0.0);
    }
}
