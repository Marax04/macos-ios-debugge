//! Shellcode heuristics: detection and classification.
//!
//! Provides [`ShellcodeDetector`], [`ShellcodeFeature`], [`ShellcodeScore`],
//! and [`ShellcodeClassifier`].

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ─────────────────────────────────────────────────────────────────────────────
// ShellcodeFeature
// ─────────────────────────────────────────────────────────────────────────────

/// A detectable feature that indicates shellcode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ShellcodeFeature {
    /// CALL $+5 / POP reg (get-PC thunk) — common in position-independent shellcode.
    GetPcThunk,
    /// PEB access via fs:[0x30] or gs:[0x60] — Windows shellcode module enumeration.
    PebAccess,
    /// API hashing pattern — XOR/ROR/ADD hash loop over export names.
    ApiHash,
    /// Stack string construction — character-by-character string building.
    StackString,
    /// CALL over data — CALL instruction followed by a string literal.
    CallOverString,
    /// Egg hunter sequence — scanning memory for a specific marker value.
    EggHunter,
    /// Alphanumeric only — all bytes are printable ASCII.
    Alphanumeric,
    /// XOR decode loop — decoding payload at runtime.
    XorDecodeLoop,
    /// HIGH entropy data block (entropy > 6.5 bits/byte).
    HighEntropy,
    /// NTSTATUS / Windows error constant hashing.
    NtStatusHash,
    /// `LoadLibraryA` / `GetProcAddress` import stubs.
    LoadLibraryPattern,
    /// Socket creation (`WSASocket` / socket syscall).
    SocketCreation,
    /// Connect-back pattern (common in reverse shell).
    ConnectBack,
    /// Bind-listen pattern (common in bind shell).
    BindListen,
    /// `VirtualAlloc` / mmap for secondary payload.
    MemAlloc,
    /// Download + execute pattern (`URLDownloadToFile` / curl / wget strings).
    DownloadExec,
    /// Shellcode is likely encoded/packed (low ASCII byte density).
    Encoded,
}

impl std::fmt::Display for ShellcodeFeature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::GetPcThunk => "GetPC_thunk",
            Self::PebAccess => "PEB_access",
            Self::ApiHash => "API_hash",
            Self::StackString => "StackString",
            Self::CallOverString => "CALL_over_string",
            Self::EggHunter => "EggHunter",
            Self::Alphanumeric => "Alphanumeric",
            Self::XorDecodeLoop => "XOR_decode",
            Self::HighEntropy => "HighEntropy",
            Self::NtStatusHash => "NtStatus_hash",
            Self::LoadLibraryPattern => "LoadLibrary",
            Self::SocketCreation => "Socket",
            Self::ConnectBack => "ConnectBack",
            Self::BindListen => "BindListen",
            Self::MemAlloc => "MemAlloc",
            Self::DownloadExec => "DownloadExec",
            Self::Encoded => "Encoded",
        };
        write!(f, "{s}")
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ShellcodeScore
// ─────────────────────────────────────────────────────────────────────────────

/// Confidence score and detected features for a shellcode candidate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShellcodeScore {
    /// Overall shellcode confidence [0.0, 100.0].
    pub score: f64,
    /// Set of detected features.
    pub features: Vec<ShellcodeFeature>,
    /// Per-feature confidence contributions.
    pub feature_scores: HashMap<String, f64>,
    /// Byte entropy.
    pub entropy: f64,
    /// Ratio of printable ASCII bytes.
    pub ascii_ratio: f64,
    /// Number of unique byte values.
    pub unique_bytes: usize,
}

impl ShellcodeScore {
    /// Return `true` if this region is likely shellcode.
    #[must_use]
    pub fn is_shellcode(&self) -> bool {
        self.score >= 40.0
    }

    /// Return `true` if this is very likely shellcode.
    #[must_use]
    pub fn is_high_confidence(&self) -> bool {
        self.score >= 70.0
    }

    /// Human-readable confidence label.
    #[must_use]
    pub fn label(&self) -> &'static str {
        if self.score >= 80.0 {
            "HIGH"
        } else if self.score >= 50.0 {
            "MEDIUM"
        } else if self.score >= 30.0 {
            "LOW"
        } else {
            "UNLIKELY"
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ShellcodeCategory (for classifier)
// ─────────────────────────────────────────────────────────────────────────────

/// Classification of shellcode type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ShellcodeCategory {
    /// Multi-stage dropper (downloads or decompresses a stage-2 payload).
    Staged,
    /// Complete payload with no second stage.
    Unstaged,
    /// Reverse shell (connects back to attacker).
    ReverseShell,
    /// Bind shell (listens on a port).
    BindShell,
    /// Download-and-execute payload.
    DownloadAndExec,
    /// Command execution (exec / system / `WinExec`).
    CmdExec,
    /// Egghunter shellcode.
    EggHunter,
    /// Unknown / unclassified.
    Unknown,
}

impl std::fmt::Display for ShellcodeCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Staged => "Staged",
            Self::Unstaged => "Unstaged",
            Self::ReverseShell => "ReverseShell",
            Self::BindShell => "BindShell",
            Self::DownloadAndExec => "DownloadAndExec",
            Self::CmdExec => "CmdExec",
            Self::EggHunter => "EggHunter",
            Self::Unknown => "Unknown",
        };
        write!(f, "{s}")
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal feature checker
// ─────────────────────────────────────────────────────────────────────────────

struct FeatureCheck {
    feature: ShellcodeFeature,
    pattern: Vec<u8>,
    mask: Option<Vec<u8>>,
    /// Weight added to score on detection.
    weight: f64,
    description: &'static str,
}

impl FeatureCheck {
    fn matches(&self, data: &[u8], offset: usize) -> bool {
        if offset + self.pattern.len() > data.len() {
            return false;
        }
        let s = &data[offset..offset + self.pattern.len()];
        match &self.mask {
            Some(m) => s
                .iter()
                .zip(self.pattern.iter())
                .zip(m.iter())
                .all(|((&d, &p), &mk)| (d & mk) == (p & mk)),
            None => s == self.pattern.as_slice(),
        }
    }

    /// Human-readable description of what this feature matches — used by
    /// callers that build a report explaining why a sample scored highly.
    const fn describe(&self) -> &'static str {
        self.description
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ShellcodeDetector
// ─────────────────────────────────────────────────────────────────────────────

/// Detects shellcode features in binary data and computes a score.
pub struct ShellcodeDetector {
    checks: Vec<FeatureCheck>,
    min_size: usize,
}

impl ShellcodeDetector {
    /// Create a detector with the built-in feature patterns.
    #[must_use]
    pub fn new() -> Self {
        let mut d = Self {
            checks: Vec::new(),
            min_size: 16,
        };
        d.populate();
        d
    }

    /// Set minimum region size to consider for detection.
    pub const fn set_min_size(&mut self, sz: usize) {
        self.min_size = sz;
    }

    /// Human-readable descriptions of every feature this detector can match,
    /// one entry per registered `FeatureCheck`. Useful for explaining a score
    /// to an end user.
    #[must_use]
    pub fn feature_descriptions(&self) -> Vec<&'static str> {
        self.checks.iter().map(FeatureCheck::describe).collect()
    }

    /// Analyse `data` and return a [`ShellcodeScore`].
    #[must_use]
    pub fn analyse(&self, data: &[u8]) -> ShellcodeScore {
        if data.len() < self.min_size {
            return ShellcodeScore {
                score: 0.0,
                features: Vec::new(),
                feature_scores: HashMap::new(),
                entropy: 0.0,
                ascii_ratio: 0.0,
                unique_bytes: 0,
            };
        }

        let entropy = shannon_entropy(data);
        let ascii_ratio = ascii_ratio(data);
        let unique_bytes = unique_byte_count(data);

        let mut found_features: HashMap<ShellcodeFeature, f64> = HashMap::new();
        for check in &self.checks {
            for offset in 0..data
                .len()
                .saturating_sub(check.pattern.len().saturating_sub(1))
            {
                if check.matches(data, offset) {
                    found_features
                        .entry(check.feature)
                        .and_modify(|w| *w = w.max(check.weight))
                        .or_insert(check.weight);
                    break; // count once per feature kind
                }
            }
        }

        // Alphanumeric check: all bytes in printable ASCII range.
        if data.iter().all(|&b| (0x21..=0x7E).contains(&b)) {
            found_features.insert(ShellcodeFeature::Alphanumeric, 15.0);
        }

        // High entropy bonus.
        if entropy > 6.5 {
            found_features
                .entry(ShellcodeFeature::HighEntropy)
                .or_insert(10.0);
        }

        // XOR decode loop heuristic: look for XOR r/m8, imm8 pattern.
        if has_xor_loop(data) {
            found_features
                .entry(ShellcodeFeature::XorDecodeLoop)
                .or_insert(20.0);
        }

        let mut raw_score: f64 = found_features.values().sum();
        // Penalty for very low entropy (unlikely to be code).
        if entropy < 2.0 {
            raw_score *= 0.3;
        }
        let score = raw_score.min(100.0);

        let feature_scores: HashMap<String, f64> = found_features
            .iter()
            .map(|(k, &v)| (k.to_string(), v))
            .collect();
        let features: Vec<_> = found_features.keys().copied().collect();

        ShellcodeScore {
            score,
            features,
            feature_scores,
            entropy,
            ascii_ratio,
            unique_bytes,
        }
    }

    fn populate(&mut self) {
        // CALL $+5 (E8 00 00 00 00) — get-PC thunk.
        self.checks.push(FeatureCheck {
            feature: ShellcodeFeature::GetPcThunk,
            pattern: vec![0xE8, 0x00, 0x00, 0x00, 0x00],
            mask: None,
            weight: 25.0,
            description: "CALL $+5 get-PC thunk",
        });
        // PEB access: mov eax, fs:[30h]
        self.checks.push(FeatureCheck {
            feature: ShellcodeFeature::PebAccess,
            pattern: vec![0x64, 0xA1, 0x30, 0x00, 0x00, 0x00],
            mask: None,
            weight: 30.0,
            description: "mov eax, fs:[0x30] (PEB)",
        });
        // PEB 64-bit: mov rax, gs:[0x60]
        self.checks.push(FeatureCheck {
            feature: ShellcodeFeature::PebAccess,
            pattern: vec![0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00],
            mask: None,
            weight: 30.0,
            description: "mov rax, gs:[0x60] (PEB 64-bit)",
        });
        // API hash: ROR EDI, 0x0D (common Metasploit ROR13 hash)
        self.checks.push(FeatureCheck {
            feature: ShellcodeFeature::ApiHash,
            pattern: vec![0xC1, 0xCF, 0x0D],
            mask: None,
            weight: 35.0,
            description: "ROR EDI, 0x0D (API hashing loop)",
        });
        // Stack string: mov byte ptr [esp+offset], char
        self.checks.push(FeatureCheck {
            feature: ShellcodeFeature::StackString,
            pattern: vec![0xC6, 0x44, 0x24], // MOV BYTE PTR [ESP+offset], imm
            mask: Some(vec![0xFF, 0xFF, 0xFF]),
            weight: 20.0,
            description: "MOV BYTE PTR [esp+x] (stack string)",
        });
        // CALL over string: CALL + printable string
        self.checks.push(FeatureCheck {
            feature: ShellcodeFeature::CallOverString,
            pattern: vec![0xE8, 0x00, 0x00, 0x00, 0x00, b'h', b't', b't', b'p'],
            mask: None,
            weight: 40.0,
            description: "CALL over 'http' string",
        });
        // Egg hunter: look for 0x6681CAxx00 (NT egg-hunter pattern).
        self.checks.push(FeatureCheck {
            feature: ShellcodeFeature::EggHunter,
            pattern: vec![0x66, 0x81, 0xCA, 0xFF, 0x0F],
            mask: None,
            weight: 40.0,
            description: "Egg hunter NT pattern",
        });
        // LoadLibraryA string
        self.checks.push(FeatureCheck {
            feature: ShellcodeFeature::LoadLibraryPattern,
            pattern: b"LoadLibraryA".to_vec(),
            mask: None,
            weight: 25.0,
            description: "LoadLibraryA string",
        });
        self.checks.push(FeatureCheck {
            feature: ShellcodeFeature::LoadLibraryPattern,
            pattern: b"GetProcAddress".to_vec(),
            mask: None,
            weight: 25.0,
            description: "GetProcAddress string",
        });
        // WSASocket / socket
        self.checks.push(FeatureCheck {
            feature: ShellcodeFeature::SocketCreation,
            pattern: b"WSASocket".to_vec(),
            mask: None,
            weight: 30.0,
            description: "WSASocket string",
        });
        self.checks.push(FeatureCheck {
            feature: ShellcodeFeature::SocketCreation,
            pattern: b"ws2_32".to_vec(),
            mask: None,
            weight: 28.0,
            description: "ws2_32 DLL string",
        });
        // Connect-back
        self.checks.push(FeatureCheck {
            feature: ShellcodeFeature::ConnectBack,
            pattern: b"connect".to_vec(),
            mask: None,
            weight: 20.0,
            description: "'connect' string (reverse shell)",
        });
        // Bind shell
        self.checks.push(FeatureCheck {
            feature: ShellcodeFeature::BindListen,
            pattern: b"bind".to_vec(),
            mask: None,
            weight: 20.0,
            description: "'bind' string (bind shell)",
        });
        // VirtualAlloc
        self.checks.push(FeatureCheck {
            feature: ShellcodeFeature::MemAlloc,
            pattern: b"VirtualAlloc".to_vec(),
            mask: None,
            weight: 22.0,
            description: "VirtualAlloc string",
        });
        // Download pattern
        self.checks.push(FeatureCheck {
            feature: ShellcodeFeature::DownloadExec,
            pattern: b"URLDownloadToFile".to_vec(),
            mask: None,
            weight: 45.0,
            description: "URLDownloadToFile string",
        });
        self.checks.push(FeatureCheck {
            feature: ShellcodeFeature::DownloadExec,
            pattern: b"http://".to_vec(),
            mask: None,
            weight: 30.0,
            description: "'http://' URL string",
        });
        self.checks.push(FeatureCheck {
            feature: ShellcodeFeature::DownloadExec,
            pattern: b"https://".to_vec(),
            mask: None,
            weight: 30.0,
            description: "'https://' URL string",
        });
    }
}

impl Default for ShellcodeDetector {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ShellcodeClassifier
// ─────────────────────────────────────────────────────────────────────────────

/// Classifies shellcode into a category based on detected features.
pub struct ShellcodeClassifier;

impl ShellcodeClassifier {
    /// Classify shellcode based on its score and features.
    #[must_use]
    pub fn classify(score: &ShellcodeScore) -> ShellcodeCategory {
        let features = &score.features;

        if features.contains(&ShellcodeFeature::EggHunter) {
            return ShellcodeCategory::EggHunter;
        }
        if features.contains(&ShellcodeFeature::DownloadExec) {
            return ShellcodeCategory::DownloadAndExec;
        }
        if features.contains(&ShellcodeFeature::ConnectBack) {
            return ShellcodeCategory::ReverseShell;
        }
        if features.contains(&ShellcodeFeature::BindListen) {
            return ShellcodeCategory::BindShell;
        }
        if features.contains(&ShellcodeFeature::GetPcThunk)
            || features.contains(&ShellcodeFeature::PebAccess)
        {
            if features.contains(&ShellcodeFeature::ApiHash) {
                return ShellcodeCategory::Staged; // likely loader stage
            }
            return ShellcodeCategory::Unstaged;
        }
        if score.is_shellcode() {
            return ShellcodeCategory::Unstaged;
        }
        ShellcodeCategory::Unknown
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Entropy / statistics helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Compute Shannon entropy in bits/byte.
#[must_use]
pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let len = data.len() as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum()
}

/// Compute ratio of printable ASCII bytes.
#[must_use]
pub fn ascii_ratio(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let printable = data.iter().filter(|&&b| (0x20..=0x7E).contains(&b)).count();
    printable as f64 / data.len() as f64
}

/// Return number of unique byte values in `data`.
#[must_use]
pub fn unique_byte_count(data: &[u8]) -> usize {
    let mut seen = [false; 256];
    for &b in data {
        seen[b as usize] = true;
    }
    seen.iter().filter(|&&s| s).count()
}

/// Heuristic XOR decode loop detector.
fn has_xor_loop(data: &[u8]) -> bool {
    // Look for XOR r8, imm8 (0x80 0x30 imm) or XOR [esi], al (0x30 0x06) in close proximity.
    for i in 0..data.len().saturating_sub(8) {
        // XOR BYTE PTR [REG], REG
        if data[i] == 0x30 && (data[i + 1] & 0xC7 == 0x06 || data[i + 1] == 0x07) {
            return true;
        }
        // XOR BYTE PTR [mem], imm8
        if data[i] == 0x80 && (data[i + 1] >> 3 & 0x07 == 0x06) {
            return true;
        }
    }
    false
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

// ─────────────────────────────────────────────────────────────────────────────
// ShellcodeReport — aggregate report for a scanned region
// ─────────────────────────────────────────────────────────────────────────────

/// Full analysis report for a potential shellcode region.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShellcodeReport {
    /// Starting offset of the region in the binary.
    pub offset: usize,
    /// Length of the region.
    pub length: usize,
    /// Base virtual address.
    pub base_address: u64,
    /// Detection score.
    pub score: ShellcodeScore,
    /// Classifier result.
    pub category: ShellcodeCategory,
    /// Human-readable summary.
    pub summary: String,
}

impl ShellcodeReport {
    /// Analyse a region and produce a report.
    #[must_use]
    pub fn analyse(data: &[u8], offset: usize, base_address: u64) -> Self {
        let detector = ShellcodeDetector::new();
        let score = detector.analyse(data);
        let category = ShellcodeClassifier::classify(&score);
        let summary = format!(
            "{} @ {:#010x}+{:#x}: score={:.0} entropy={:.2} cat={}",
            score.label(),
            base_address,
            offset,
            score.score,
            score.entropy,
            category,
        );
        Self {
            offset,
            length: data.len(),
            base_address,
            score,
            category,
            summary,
        }
    }

    /// Return `true` if this region should be flagged for further analysis.
    #[must_use]
    pub fn should_flag(&self) -> bool {
        self.score.is_shellcode()
    }
}

/// Scan a binary for executable regions that may contain shellcode.
///
/// Splits `data` into overlapping windows of `window_size` bytes and
/// scores each window using [`ShellcodeDetector`].
#[must_use]
pub fn scan_for_shellcode(
    data: &[u8],
    window_size: usize,
    stride: usize,
    base_address: u64,
) -> Vec<ShellcodeReport> {
    let detector = ShellcodeDetector::new();
    let mut reports = Vec::new();

    let stride = stride.max(1);
    let window = window_size.max(16);
    let mut offset = 0;

    while offset + window <= data.len() {
        let chunk = &data[offset..offset + window];
        let score = detector.analyse(chunk);
        if score.is_shellcode() {
            let category = ShellcodeClassifier::classify(&score);
            let summary = format!(
                "{} @ {:#010x}+{:#x}: score={:.0} cat={}",
                score.label(),
                base_address,
                offset,
                score.score,
                category,
            );
            reports.push(ShellcodeReport {
                offset,
                length: window,
                base_address,
                score,
                category,
                summary,
            });
        }
        offset += stride;
    }

    reports
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- ShellcodeFeature ----------------------------------------------------

    #[test]
    fn test_feature_display() {
        assert_eq!(ShellcodeFeature::GetPcThunk.to_string(), "GetPC_thunk");
        assert_eq!(ShellcodeFeature::ApiHash.to_string(), "API_hash");
    }

    // -- Entropy helpers -----------------------------------------------------

    #[test]
    fn test_entropy_uniform() {
        let data: Vec<u8> = (0..=255).collect();
        let e = shannon_entropy(&data);
        assert!((e - 8.0).abs() < 0.01, "entropy should be ~8.0, got {e}");
    }

    #[test]
    fn test_entropy_constant() {
        let data = vec![0x42u8; 256];
        let e = shannon_entropy(&data);
        assert!(e < 0.01);
    }

    #[test]
    fn test_entropy_empty() {
        assert_eq!(shannon_entropy(&[]), 0.0);
    }

    #[test]
    fn test_ascii_ratio_all_printable() {
        let data = b"Hello World".to_vec();
        assert!((ascii_ratio(&data) - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_ascii_ratio_none() {
        let data = vec![0xFFu8; 16];
        assert_eq!(ascii_ratio(&data), 0.0);
    }

    #[test]
    fn test_unique_byte_count() {
        let data = vec![0x00, 0x01, 0x00, 0x02];
        assert_eq!(unique_byte_count(&data), 3);
    }

    // -- ShellcodeDetector ---------------------------------------------------

    #[test]
    fn test_detect_peb_access_32bit() {
        let d = ShellcodeDetector::new();
        let data = vec![
            0x64, 0xA1, 0x30, 0x00, 0x00, 0x00, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
            0x90, 0x90,
        ];
        let score = d.analyse(&data);
        assert!(score.features.contains(&ShellcodeFeature::PebAccess));
    }

    #[test]
    fn test_detect_get_pc_thunk() {
        let d = ShellcodeDetector::new();
        let mut data = vec![0u8; 32];
        data[0..5].copy_from_slice(&[0xE8, 0x00, 0x00, 0x00, 0x00]);
        let score = d.analyse(&data);
        assert!(score.features.contains(&ShellcodeFeature::GetPcThunk));
    }

    #[test]
    fn test_detect_api_hash_ror13() {
        let d = ShellcodeDetector::new();
        let mut data = vec![0x90u8; 32];
        data[4..7].copy_from_slice(&[0xC1, 0xCF, 0x0D]);
        let score = d.analyse(&data);
        assert!(score.features.contains(&ShellcodeFeature::ApiHash));
    }

    #[test]
    fn test_detect_load_library() {
        let d = ShellcodeDetector::new();
        let data = b"LoadLibraryAxxxxxxxxxxxxxxxx".to_vec();
        let score = d.analyse(&data);
        assert!(
            score
                .features
                .contains(&ShellcodeFeature::LoadLibraryPattern)
        );
    }

    #[test]
    fn test_detect_url() {
        let d = ShellcodeDetector::new();
        let data = b"http://evil.example.com/payload.bin\0AAAAAAAAAA".to_vec();
        let score = d.analyse(&data);
        assert!(score.features.contains(&ShellcodeFeature::DownloadExec));
        // A bare URL string is an INDICATOR, not code: it carries no instruction,
        // so it must stay below the shellcode threshold. `DownloadExec` alone is
        // worth 30 and `is_shellcode()` starts at 40 — reaching the threshold
        // requires a second, code-bearing feature.
        assert!(
            !score.is_shellcode(),
            "a URL string with no code must not be classified as shellcode (score {})",
            score.score
        );
    }

    #[test]
    fn test_detect_egg_hunter() {
        let d = ShellcodeDetector::new();
        let mut data = vec![0x90u8; 32];
        data[0..5].copy_from_slice(&[0x66, 0x81, 0xCA, 0xFF, 0x0F]);
        let score = d.analyse(&data);
        assert!(score.features.contains(&ShellcodeFeature::EggHunter));
    }

    #[test]
    fn test_detect_alphanumeric() {
        let d = ShellcodeDetector::new();
        // All printable ASCII: likely alphanumeric shellcode.
        let data: Vec<u8> = (0x41..0x5Bu8).cycle().take(64).collect();
        let score = d.analyse(&data);
        assert!(score.features.contains(&ShellcodeFeature::Alphanumeric));
    }

    #[test]
    fn test_min_size_too_small() {
        let d = ShellcodeDetector::new();
        let data = vec![0x90u8; 4]; // less than min_size (16)
        let score = d.analyse(&data);
        assert_eq!(score.score, 0.0);
    }

    #[test]
    fn test_score_is_shellcode() {
        let score = ShellcodeScore {
            score: 45.0,
            features: vec![ShellcodeFeature::GetPcThunk],
            feature_scores: HashMap::new(),
            entropy: 5.5,
            ascii_ratio: 0.3,
            unique_bytes: 120,
        };
        assert!(score.is_shellcode());
    }

    #[test]
    fn test_score_label() {
        let s = ShellcodeScore {
            score: 85.0,
            features: vec![],
            feature_scores: HashMap::new(),
            entropy: 6.0,
            ascii_ratio: 0.0,
            unique_bytes: 200,
        };
        assert_eq!(s.label(), "HIGH");
    }

    // -- ShellcodeClassifier -------------------------------------------------

    #[test]
    fn test_classify_egg_hunter() {
        let score = ShellcodeScore {
            score: 60.0,
            features: vec![ShellcodeFeature::EggHunter],
            feature_scores: HashMap::new(),
            entropy: 5.0,
            ascii_ratio: 0.2,
            unique_bytes: 100,
        };
        assert_eq!(
            ShellcodeClassifier::classify(&score),
            ShellcodeCategory::EggHunter
        );
    }

    #[test]
    fn test_classify_reverse_shell() {
        let score = ShellcodeScore {
            score: 70.0,
            features: vec![ShellcodeFeature::PebAccess, ShellcodeFeature::ConnectBack],
            feature_scores: HashMap::new(),
            entropy: 5.5,
            ascii_ratio: 0.3,
            unique_bytes: 150,
        };
        assert_eq!(
            ShellcodeClassifier::classify(&score),
            ShellcodeCategory::ReverseShell
        );
    }

    #[test]
    fn test_classify_download_exec() {
        let score = ShellcodeScore {
            score: 75.0,
            features: vec![ShellcodeFeature::DownloadExec],
            feature_scores: HashMap::new(),
            entropy: 5.0,
            ascii_ratio: 0.5,
            unique_bytes: 80,
        };
        assert_eq!(
            ShellcodeClassifier::classify(&score),
            ShellcodeCategory::DownloadAndExec
        );
    }

    #[test]
    fn test_classify_staged() {
        let score = ShellcodeScore {
            score: 60.0,
            features: vec![ShellcodeFeature::GetPcThunk, ShellcodeFeature::ApiHash],
            feature_scores: HashMap::new(),
            entropy: 5.8,
            ascii_ratio: 0.2,
            unique_bytes: 190,
        };
        assert_eq!(
            ShellcodeClassifier::classify(&score),
            ShellcodeCategory::Staged
        );
    }

    #[test]
    fn test_classify_unknown() {
        let score = ShellcodeScore {
            score: 5.0,
            features: vec![],
            feature_scores: HashMap::new(),
            entropy: 1.0,
            ascii_ratio: 0.99,
            unique_bytes: 26,
        };
        assert_eq!(
            ShellcodeClassifier::classify(&score),
            ShellcodeCategory::Unknown
        );
    }

    #[test]
    fn test_shellcode_category_display() {
        assert_eq!(ShellcodeCategory::ReverseShell.to_string(), "ReverseShell");
    }

    #[test]
    fn test_high_confidence() {
        let score = ShellcodeScore {
            score: 80.0,
            features: vec![ShellcodeFeature::PebAccess, ShellcodeFeature::ApiHash],
            feature_scores: HashMap::new(),
            entropy: 5.8,
            ascii_ratio: 0.3,
            unique_bytes: 180,
        };
        assert!(score.is_high_confidence());
        assert_eq!(score.label(), "HIGH");
    }

    #[test]
    fn test_medium_confidence() {
        let score = ShellcodeScore {
            score: 55.0,
            features: vec![ShellcodeFeature::StackString],
            feature_scores: HashMap::new(),
            entropy: 4.5,
            ascii_ratio: 0.4,
            unique_bytes: 100,
        };
        assert!(score.is_shellcode());
        assert!(!score.is_high_confidence());
        assert_eq!(score.label(), "MEDIUM");
    }

    #[test]
    fn test_unlikely_label() {
        let score = ShellcodeScore {
            score: 5.0,
            features: vec![],
            feature_scores: HashMap::new(),
            entropy: 0.5,
            ascii_ratio: 1.0,
            unique_bytes: 2,
        };
        assert_eq!(score.label(), "UNLIKELY");
    }

    #[test]
    fn test_ws2_32_detection() {
        let d = ShellcodeDetector::new();
        let data = b"ws2_32AAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_vec();
        let score = d.analyse(&data);
        assert!(score.features.contains(&ShellcodeFeature::SocketCreation));
    }

    #[test]
    fn test_bind_string() {
        let d = ShellcodeDetector::new();
        let data = b"bind AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_vec();
        let score = d.analyse(&data);
        assert!(score.features.contains(&ShellcodeFeature::BindListen));
    }

    #[test]
    fn test_virtual_alloc_string() {
        let d = ShellcodeDetector::new();
        let data = b"VirtualAllocAAAAAAAAAAAAAAAAAAAAAAAA".to_vec();
        let score = d.analyse(&data);
        assert!(score.features.contains(&ShellcodeFeature::MemAlloc));
    }

    #[test]
    fn test_unique_byte_count_all_same() {
        assert_eq!(unique_byte_count(&[0x42; 64]), 1);
    }

    #[test]
    fn test_entropy_high_for_random_like() {
        let data: Vec<u8> = (0..=255u8).collect();
        let e = shannon_entropy(&data);
        assert!(e > 7.9);
    }

    #[test]
    fn test_classify_bind_shell() {
        let score = ShellcodeScore {
            score: 65.0,
            features: vec![
                ShellcodeFeature::BindListen,
                ShellcodeFeature::SocketCreation,
            ],
            feature_scores: HashMap::new(),
            entropy: 5.0,
            ascii_ratio: 0.3,
            unique_bytes: 140,
        };
        assert_eq!(
            ShellcodeClassifier::classify(&score),
            ShellcodeCategory::BindShell
        );
    }

    #[test]
    fn test_score_not_shellcode() {
        let score = ShellcodeScore {
            score: 15.0,
            features: vec![],
            feature_scores: HashMap::new(),
            entropy: 1.0,
            ascii_ratio: 0.95,
            unique_bytes: 30,
        };
        assert!(!score.is_shellcode());
    }
}
