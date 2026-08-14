//! Ransomware behavioral detection:
//! file-extension enumeration, shadow-copy deletion, ransom-note patterns,
//! encryption key storage, and wallet-address detection.
//!
//! # Relationship to `ransomware_analysis`
//! This module is the **behavioral detector** layer: it processes raw strings,
//! API-call logs, and binary blobs and emits MITRE ATT\&CK-tagged
//! [`RansomwareIndicator`]s and a [`RansomwareVerdict`].
//!
//! [`crate::ransomware_analysis`] is the **analysis layer**: it works with
//! higher-level, already-classified sandbox events and maintains richer
//! per-family data (encryption algorithms, note filenames, double-extortion
//! flags, etc.).  The two layers intentionally have separate [`WalletAddress`]
//! and [`CryptoCurrency`] types because their schemas differ — the detector's
//! wallet record carries a `context` string (raw surrounding text), while the
//! analysis layer's carries a `source` tag and a numeric `confidence` score.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use thiserror::Error;

// ─── Error ────────────────────────────────────────────────────────────────────

#[derive(Debug, Error, Clone)]
pub enum DetectionError {
    #[error("analysis error: {0}")]
    Analysis(String),
    #[error("empty input")]
    EmptyInput,
}

// ─── RansomwareIndicator ──────────────────────────────────────────────────────

/// A single behavioral indicator of ransomware activity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RansomwareIndicator {
    /// Short code identifying the indicator type.
    pub code: RansomwareIndicatorCode,
    /// Human-readable description.
    pub description: String,
    /// Evidence that triggered this indicator (e.g. matched string, API call).
    pub evidence: String,
    /// Severity of this indicator [0, 100].
    pub severity: u8,
    /// MITRE ATT&CK technique ID.
    pub mitre_id: Option<String>,
    /// Confidence [0.0, 1.0].
    pub confidence: f32,
}

impl RansomwareIndicator {
    #[must_use]
    pub fn new(
        code: RansomwareIndicatorCode,
        description: impl Into<String>,
        evidence: impl Into<String>,
        severity: u8,
        confidence: f32,
    ) -> Self {
        let mitre_id = code.mitre_id().map(std::string::ToString::to_string);
        Self {
            code,
            description: description.into(),
            evidence: evidence.into(),
            severity,
            mitre_id,
            confidence: confidence.clamp(0.0, 1.0),
        }
    }
}

/// Specific type of ransomware behavioral indicator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RansomwareIndicatorCode {
    /// Enumerates file extensions to identify encryptable files.
    FileExtensionEnumeration,
    /// Deletes volume shadow copies to prevent recovery.
    ShadowCopyDeletion,
    /// Creates or drops a ransom note file.
    RansomNoteCreation,
    /// Stores or generates an encryption key.
    EncryptionKeyStorage,
    /// Contacts a Bitcoin / Monero / crypto wallet address.
    WalletAddressReference,
    /// Disables Windows Recovery Environment.
    DisablesWinRe,
    /// Deletes backups.
    BackupDeletion,
    /// Terminates processes holding open file handles.
    ProcessTermination,
    /// Encrypts the Master Boot Record.
    MbrEncryption,
    /// Uses the `CryptEncrypt` / `BCryptEncrypt` API.
    CryptEncryptApiUsage,
    /// Renames / changes extension of encrypted files.
    FileRenamePattern,
    /// Propagates across the network.
    NetworkPropagation,
    /// Other / unclassified.
    Other(String),
}

impl RansomwareIndicatorCode {
    /// MITRE ATT&CK technique ID for this indicator.
    #[must_use]
    pub const fn mitre_id(&self) -> Option<&'static str> {
        match self {
            Self::FileExtensionEnumeration => Some("T1083"),
            Self::ShadowCopyDeletion => Some("T1490"),
            Self::RansomNoteCreation => Some("T1486"),
            Self::EncryptionKeyStorage => Some("T1486"),
            Self::WalletAddressReference => Some("T1486"),
            Self::DisablesWinRe => Some("T1490"),
            Self::BackupDeletion => Some("T1490"),
            Self::ProcessTermination => Some("T1489"),
            Self::MbrEncryption => Some("T1561.002"),
            Self::CryptEncryptApiUsage => Some("T1486"),
            Self::FileRenamePattern => Some("T1486"),
            Self::NetworkPropagation => Some("T1210"),
            Self::Other(_) => None,
        }
    }
}

impl std::fmt::Display for RansomwareIndicatorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::FileExtensionEnumeration => write!(f, "file_extension_enum"),
            Self::ShadowCopyDeletion => write!(f, "shadow_copy_deletion"),
            Self::RansomNoteCreation => write!(f, "ransom_note_creation"),
            Self::EncryptionKeyStorage => write!(f, "encryption_key_storage"),
            Self::WalletAddressReference => write!(f, "wallet_address"),
            Self::DisablesWinRe => write!(f, "disables_winre"),
            Self::BackupDeletion => write!(f, "backup_deletion"),
            Self::ProcessTermination => write!(f, "process_termination"),
            Self::MbrEncryption => write!(f, "mbr_encryption"),
            Self::CryptEncryptApiUsage => write!(f, "crypt_encrypt_api"),
            Self::FileRenamePattern => write!(f, "file_rename_pattern"),
            Self::NetworkPropagation => write!(f, "network_propagation"),
            Self::Other(s) => write!(f, "other({s})"),
        }
    }
}

// ─── RansomwareVerdict ────────────────────────────────────────────────────────

/// Overall verdict from the ransomware detector.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RansomwareVerdict {
    /// Very likely ransomware (score >= 80).
    Ransomware,
    /// Possible ransomware or ransomware component (score 40–79).
    Suspicious,
    /// Some artifacts present but insufficient evidence (score 10–39).
    PossibleRansomware,
    /// No significant indicators found (score < 10).
    Clean,
}

impl std::fmt::Display for RansomwareVerdict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ransomware => write!(f, "RANSOMWARE"),
            Self::Suspicious => write!(f, "SUSPICIOUS"),
            Self::PossibleRansomware => write!(f, "POSSIBLE_RANSOMWARE"),
            Self::Clean => write!(f, "CLEAN"),
        }
    }
}

// ─── RansomwareDetectionResult ────────────────────────────────────────────────

/// Complete result from a ransomware detection run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RansomwareDetectionResult {
    /// Aggregated threat score (0–100).
    pub score: u32,
    /// Verdict.
    pub verdict: RansomwareVerdict,
    /// All individual indicators found.
    pub indicators: Vec<RansomwareIndicator>,
    /// Detected wallet addresses.
    pub wallet_addresses: Vec<WalletAddress>,
    /// Ransom note samples found (first N chars).
    pub ransom_note_samples: Vec<String>,
    /// Detected file extension patterns used by this sample.
    pub extension_patterns: Vec<String>,
    /// Shadow copy deletion commands detected.
    pub shadow_copy_commands: Vec<String>,
    /// Inferred ransomware family (best guess).
    pub family_guess: Option<String>,
    /// MITRE ATT&CK technique IDs triggered.
    pub mitre_techniques: Vec<String>,
}

impl RansomwareDetectionResult {
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            score: 0,
            verdict: RansomwareVerdict::Clean,
            indicators: Vec::new(),
            wallet_addresses: Vec::new(),
            ransom_note_samples: Vec::new(),
            extension_patterns: Vec::new(),
            shadow_copy_commands: Vec::new(),
            family_guess: None,
            mitre_techniques: Vec::new(),
        }
    }

    /// Compute the score from the current indicators and set the verdict.
    pub fn finalize(&mut self) {
        let raw: u32 = self.indicators.iter()
            .fold(0u32, |acc, i| {
                let contribution = u32::from(i.severity)
                    .saturating_mul((i.confidence.clamp(0.0, 1.0) * 100.0) as u32)
                    / 100;
                acc.saturating_add(contribution)
            });
        self.score = raw.min(100);

        self.verdict = match self.score {
            0..=9 => RansomwareVerdict::Clean,
            10..=39 => RansomwareVerdict::PossibleRansomware,
            40..=79 => RansomwareVerdict::Suspicious,
            _ => RansomwareVerdict::Ransomware,
        };

        // Collect unique MITRE technique IDs.
        let mut techniques: Vec<String> = self
            .indicators
            .iter()
            .filter_map(|i| i.mitre_id.clone())
            .collect();
        techniques.sort();
        techniques.dedup();
        self.mitre_techniques = techniques;
    }
}

// ─── WalletAddress ────────────────────────────────────────────────────────────

/// A cryptocurrency wallet address found in the sample during behavioral
/// detection.
///
/// Note: [`crate::ransomware_analysis`] defines its own `WalletAddress` with a
/// different schema (`source` + `confidence` instead of `context`). The two
/// types are intentionally separate because the detector emits raw scan results
/// while the analysis layer tracks provenance and certainty scores.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletAddress {
    pub address: String,
    pub currency: CryptoCurrency,
    pub context: String,
}

/// Cryptocurrency type used by the behavioral detector output.
///
/// This enum differs from `ransomware_analysis::CryptoCurrency` in that it
/// includes `BitcoinCash` and `Unknown` rather than `Zcash` and `Other(String)`,
/// reflecting the coarser classification needed at the detection stage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CryptoCurrency {
    Bitcoin,
    Monero,
    Ethereum,
    BitcoinCash,
    Unknown,
}

impl std::fmt::Display for CryptoCurrency {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Bitcoin => write!(f, "BTC"),
            Self::Monero => write!(f, "XMR"),
            Self::Ethereum => write!(f, "ETH"),
            Self::BitcoinCash => write!(f, "BCH"),
            Self::Unknown => write!(f, "UNKNOWN"),
        }
    }
}

// ─── RansomwareDetector ───────────────────────────────────────────────────────

/// Detects ransomware behavioral patterns in strings, API call logs, and binary data.
pub struct RansomwareDetector {
    /// Common ransom note filename patterns.
    note_filenames: Vec<&'static str>,
    /// Common ransom note text patterns.
    note_text_patterns: Vec<&'static str>,
    /// Shadow copy deletion command patterns.
    shadow_copy_patterns: Vec<&'static str>,
    /// Known ransomware-related file extensions.
    ransomware_extensions: Vec<&'static str>,
    /// Known encrypted-file extension patterns (regexes as simple substrings).
    encrypted_extension_patterns: Vec<&'static str>,
    /// Known ransomware families and their signature strings.
    family_signatures: HashMap<&'static str, Vec<&'static str>>,
}

impl RansomwareDetector {
    /// Return the list of substring patterns that identify encrypted-file
    /// extensions (e.g. `.crypted`, `.locked`). Public so external scoring
    /// passes can reuse the same vocabulary the in-crate detection uses.
    #[must_use]
    pub fn encrypted_extension_patterns(&self) -> &[&'static str] {
        &self.encrypted_extension_patterns
    }

    /// Returns `true` if `name` (a file basename) matches any of the
    /// encrypted-extension substrings registered with this detector.
    #[must_use]
    pub fn matches_encrypted_extension(&self, name: &str) -> bool {
        let lower = name.to_ascii_lowercase();
        self.encrypted_extension_patterns
            .iter()
            .any(|pat| lower.contains(*pat))
    }

    /// Create a detector with built-in rules.
    #[must_use]
    pub fn new() -> Self {
        let mut family_signatures: HashMap<&'static str, Vec<&'static str>> = HashMap::new();
        family_signatures.insert("WannaCry", vec!["WanaCrypt0r", "wncry", "tasksche.exe", "WANACRY!"]);
        family_signatures.insert("LockBit", vec!["LockBit", "lockbit", "LOCKBIT", "Restore-My-Files"]);
        family_signatures.insert("Ryuk", vec!["RyukReadMe", "HERMES", "ryuk"]);
        family_signatures.insert("REvil", vec!["REvil", "revil", "Sodinokibi", "-readme.txt"]);
        family_signatures.insert("Conti", vec!["CONTI_README", "conti_readme", "ContiDecryptor"]);
        family_signatures.insert("BlackCat", vec!["ALPHV", "BlackCat", "RECOVER", "noname"]);
        family_signatures.insert("Maze", vec!["MAZE", "maze_decryptor"]);
        family_signatures.insert("Emotet", vec!["Heodo", "emotet", "mealybug"]);
        family_signatures.insert("NotPetya", vec!["NotPetya", "perfc.dat", "MFT"]);
        family_signatures.insert("GandCrab", vec!["GANDCRAB", "GandCrab", "krab"]);

        Self {
            note_filenames: vec![
                "README", "readme", "HELP_DECRYPT", "HOW_TO_DECRYPT", "DECRYPT",
                "YOUR_FILES_ARE_ENCRYPTED", "recovery_key", "RECOVERY", "pay_ransom",
                "ransom_note", "HOW TO RECOVER", "RESTORE_FILES",
                "!HELP_YOUR_FILES", "_HELP_", "ENCRYPTED_",
            ],
            note_text_patterns: vec![
                "your files have been encrypted",
                "your files are encrypted",
                "all your files",
                "ransom",
                "bitcoin",
                "decrypt",
                "payment",
                "tor browser",
                "onion",
                ".onion",
                "unique ID",
                "private key",
                "recovery key",
                "pay within",
                "deadline",
                "do not contact police",
                "do not attempt to recover",
                "contact us at",
                "guaranteed recovery",
                "data has been encrypted",
            ],
            shadow_copy_patterns: vec![
                "vssadmin delete shadows",
                "vssadmin.exe delete shadows",
                "wmic shadowcopy delete",
                "wmic.exe shadowcopy delete",
                "wbadmin delete catalog",
                "bcdedit /set {default} recoveryenabled no",
                "bcdedit.exe /set",
                "vssadmin resize shadowstorage",
                "DisableAntiSpyware",
                "wevtutil cl",
                "wevtutil.exe cl",
                "fsutil usn deletejournal",
                "cipher /w:",
                "net stop vss",
            ],
            ransomware_extensions: vec![
                ".locked", ".encrypted", ".crypt", ".enc", ".cerber", ".locky",
                ".zepto", ".zzzzz", ".breaking_bad", ".fun", ".kraken",
                ".WANNACRY", ".WNCRY", ".wnry", ".wcry",
                ".ryuk", ".RYK", ".lockbit", ".LOCKBIT",
                ".revil", ".sodinokibi", ".krab", ".maze",
                ".conti", ".alphv", ".blackcat",
            ],
            encrypted_extension_patterns: vec![
                ".[a-z0-9]{6,10}$",
                "\\.[A-Z0-9]{4,8}$",
                ".locked",
                ".crypt",
                ".enc",
            ],
            family_signatures,
        }
    }

    // ── Public API ────────────────────────────────────────────────────────────

    /// Analyze a list of strings (e.g. API call arguments, dropped file names,
    /// ransom note contents) for ransomware indicators.
    #[must_use]
    pub fn analyze_strings(&self, strings: &[&str]) -> RansomwareDetectionResult {
        let mut result = RansomwareDetectionResult::empty();
        let combined = strings.join("\n");

        self.detect_shadow_copy_deletion(strings, &mut result);
        self.detect_ransom_notes(strings, &mut result);
        self.detect_file_extension_enumeration(strings, &mut result);
        self.detect_wallet_addresses(strings, &mut result);
        self.detect_encryption_apis(&combined, &mut result);
        self.detect_backup_deletion(strings, &mut result);
        self.detect_mbr_attacks(&combined, &mut result);
        self.detect_file_rename_pattern(strings, &mut result);
        self.guess_family(strings, &mut result);

        result.finalize();
        result
    }

    /// Analyze raw binary data (extract strings then analyze).
    #[must_use]
    pub fn analyze_binary(&self, data: &[u8]) -> RansomwareDetectionResult {
        let strings = extract_ascii_strings(data, 6);
        let str_refs: Vec<&str> = strings.iter().map(std::string::String::as_str).collect();
        self.analyze_strings(&str_refs)
    }

    /// Analyze a list of API call names.
    #[must_use]
    pub fn analyze_api_calls(&self, api_names: &[&str]) -> RansomwareDetectionResult {
        let mut result = RansomwareDetectionResult::empty();

        // Encryption APIs.
        let crypt_apis = [
            "CryptEncrypt", "BCryptEncrypt", "CryptEncryptMessage",
            "AES", "RijndaelManaged",
        ];
        for &api in api_names {
            if crypt_apis.iter().any(|&c| api.contains(c)) {
                result.indicators.push(RansomwareIndicator::new(
                    RansomwareIndicatorCode::CryptEncryptApiUsage,
                    "Encryption API called",
                    api.to_string(),
                    30,
                    0.75,
                ));
            }
        }

        // Volume shadow copy APIs.
        if api_names.iter().any(|&a| a.contains("Wbem") || a.contains("CreateService")) {
            result.indicators.push(RansomwareIndicator::new(
                RansomwareIndicatorCode::ShadowCopyDeletion,
                "WMI/service API (may relate to VSS deletion)",
                "WMI or CreateService API observed".to_string(),
                20,
                0.40,
            ));
        }

        // File enumeration APIs.
        let enum_apis = ["FindFirstFileW", "FindNextFileW", "FindFirstFileA", "FindNextFileA"];
        let enum_count = api_names.iter().filter(|&&a| enum_apis.iter().any(|&e| a.contains(e))).count();
        if enum_count >= 3 {
            result.indicators.push(RansomwareIndicator::new(
                RansomwareIndicatorCode::FileExtensionEnumeration,
                format!("File enumeration APIs called {enum_count} times"),
                "FindFirstFile/FindNextFile called repeatedly".to_string(),
                40,
                0.70,
            ));
        }

        // Process termination APIs.
        if api_names.iter().any(|&a| a.contains("TerminateProcess") || a.contains("NtTerminateProcess")) {
            result.indicators.push(RansomwareIndicator::new(
                RansomwareIndicatorCode::ProcessTermination,
                "Process termination API (may kill AV/backup agents)",
                "TerminateProcess API observed".to_string(),
                25,
                0.50,
            ));
        }

        result.finalize();
        result
    }

    // ── Private detection methods ─────────────────────────────────────────────

    fn detect_shadow_copy_deletion(&self, strings: &[&str], result: &mut RansomwareDetectionResult) {
        for &s in strings {
            let lower = s.to_ascii_lowercase();
            for &pattern in &self.shadow_copy_patterns {
                let pat_lower = pattern.to_ascii_lowercase();
                if lower.contains(&pat_lower) {
                    result.shadow_copy_commands.push(s.to_string());
                    result.indicators.push(RansomwareIndicator::new(
                        RansomwareIndicatorCode::ShadowCopyDeletion,
                        "Shadow copy deletion command detected",
                        s.to_string(),
                        80,
                        0.95,
                    ));
                    break;
                }
            }
        }
    }

    fn detect_ransom_notes(&self, strings: &[&str], result: &mut RansomwareDetectionResult) {
        for &s in strings {
            let lower = s.to_ascii_lowercase();

            // Check filename patterns.
            for &fname in &self.note_filenames {
                if lower.contains(&fname.to_ascii_lowercase()) {
                    result.ransom_note_samples.push(s[..s.len().min(256)].to_string());
                    result.indicators.push(RansomwareIndicator::new(
                        RansomwareIndicatorCode::RansomNoteCreation,
                        format!("Ransom note filename pattern: {fname}"),
                        s.to_string(),
                        70,
                        0.85,
                    ));
                    break;
                }
            }

            // Check text content.
            let mut matches = 0u32;
            for &pattern in &self.note_text_patterns {
                if lower.contains(pattern) {
                    matches += 1;
                }
            }
            if matches >= 3 {
                result.ransom_note_samples.push(s[..s.len().min(512)].to_string());
                result.indicators.push(RansomwareIndicator::new(
                    RansomwareIndicatorCode::RansomNoteCreation,
                    format!("Ransom note text ({matches} patterns matched)"),
                    s[..s.len().min(80)].to_string(),
                    75,
                    0.80 + (matches as f32 * 0.01).min(0.15),
                ));
            }
        }
    }

    fn detect_file_extension_enumeration(&self, strings: &[&str], result: &mut RansomwareDetectionResult) {
        for &s in strings {
            for &ext in &self.ransomware_extensions {
                if s.contains(ext) {
                    if !result.extension_patterns.contains(&ext.to_string()) {
                        result.extension_patterns.push(ext.to_string());
                    }
                    result.indicators.push(RansomwareIndicator::new(
                        RansomwareIndicatorCode::FileExtensionEnumeration,
                        format!("Known ransomware extension: {ext}"),
                        s.to_string(),
                        60,
                        0.80,
                    ));
                }
            }

            // Check for mass file extension enumeration patterns (*.doc, *.xls, etc.).
            let ext_count = COMMON_DOCUMENT_EXTENSIONS
                .iter()
                .filter(|&&e| s.contains(e))
                .count();
            if ext_count >= 4 {
                result.indicators.push(RansomwareIndicator::new(
                    RansomwareIndicatorCode::FileExtensionEnumeration,
                    format!("Document file type enumeration ({ext_count} types in one string)"),
                    s[..s.len().min(128)].to_string(),
                    50,
                    0.70,
                ));
            }
        }
    }

    fn detect_wallet_addresses(&self, strings: &[&str], result: &mut RansomwareDetectionResult) {
        for &s in strings {
            // Bitcoin P2PKH: starts with 1 or 3, length 25–34.
            let words: Vec<&str> = s.split_whitespace().collect();
            for word in words {
                if let Some(addr) = detect_btc_address(word) {
                    result.wallet_addresses.push(WalletAddress {
                        address: addr.clone(),
                        currency: CryptoCurrency::Bitcoin,
                        context: s[..s.len().min(80)].to_string(),
                    });
                    result.indicators.push(RansomwareIndicator::new(
                        RansomwareIndicatorCode::WalletAddressReference,
                        "Bitcoin wallet address found",
                        addr,
                        50,
                        0.80,
                    ));
                }
                if let Some(addr) = detect_monero_address(word) {
                    result.wallet_addresses.push(WalletAddress {
                        address: addr.clone(),
                        currency: CryptoCurrency::Monero,
                        context: s[..s.len().min(80)].to_string(),
                    });
                    result.indicators.push(RansomwareIndicator::new(
                        RansomwareIndicatorCode::WalletAddressReference,
                        "Monero wallet address found",
                        addr,
                        50,
                        0.85,
                    ));
                }
            }
        }
    }

    fn detect_encryption_apis(&self, combined: &str, result: &mut RansomwareDetectionResult) {
        let lower = combined.to_ascii_lowercase();
        let crypt_apis = [
            "cryptencrypt", "bcryptencrypt", "cryptsetkeyparam",
            "aescryptoserviceprovider", "rijndaelmanaged", "aesgcm",
        ];
        for &api in &crypt_apis {
            if lower.contains(api) {
                result.indicators.push(RansomwareIndicator::new(
                    RansomwareIndicatorCode::CryptEncryptApiUsage,
                    format!("Crypto API usage: {api}"),
                    api.to_string(),
                    35,
                    0.70,
                ));
            }
        }

        // Encryption key storage patterns.
        let key_patterns = ["aes_key", "rsa_key", "session_key", "encryption_key", "private_key"];
        for &kp in &key_patterns {
            if lower.contains(kp) {
                result.indicators.push(RansomwareIndicator::new(
                    RansomwareIndicatorCode::EncryptionKeyStorage,
                    format!("Encryption key reference: {kp}"),
                    kp.to_string(),
                    30,
                    0.55,
                ));
            }
        }
    }

    fn detect_backup_deletion(&self, strings: &[&str], result: &mut RansomwareDetectionResult) {
        let backup_patterns = [
            "wbadmin",
            "ntbackup",
            "shadowcopy",
            "veeam",
            "acronis",
            "backup",
            "System State",
        ];
        for &s in strings {
            let lower = s.to_ascii_lowercase();
            for &bp in &backup_patterns {
                if lower.contains(&bp.to_ascii_lowercase())
                    && (lower.contains("delete") || lower.contains("stop") || lower.contains("disable"))
                {
                    result.indicators.push(RansomwareIndicator::new(
                        RansomwareIndicatorCode::BackupDeletion,
                        format!("Backup deletion: {bp}"),
                        s[..s.len().min(128)].to_string(),
                        65,
                        0.80,
                    ));
                }
            }
        }
    }

    fn detect_mbr_attacks(&self, combined: &str, result: &mut RansomwareDetectionResult) {
        let lower = combined.to_ascii_lowercase();
        let mbr_patterns = [
            "\\\\.\\physicaldrive",
            "physicaldriveobject",
            "mbr",
            "master boot record",
            "bootsect",
        ];
        for &mp in &mbr_patterns {
            if lower.contains(mp) {
                result.indicators.push(RansomwareIndicator::new(
                    RansomwareIndicatorCode::MbrEncryption,
                    format!("MBR / physical disk access: {mp}"),
                    mp.to_string(),
                    70,
                    0.75,
                ));
            }
        }
    }

    fn detect_file_rename_pattern(&self, strings: &[&str], result: &mut RansomwareDetectionResult) {
        // Look for MoveFile calls with known encrypted extension targets.
        for &s in strings {
            for &ext in &self.ransomware_extensions {
                if s.ends_with(ext) || s.contains(&format!("{ext}\"")) {
                    result.indicators.push(RansomwareIndicator::new(
                        RansomwareIndicatorCode::FileRenamePattern,
                        format!("File renamed to encrypted extension {ext}"),
                        s[..s.len().min(128)].to_string(),
                        55,
                        0.75,
                    ));
                    break;
                }
            }
        }
    }

    fn guess_family(&self, strings: &[&str], result: &mut RansomwareDetectionResult) {
        let combined = strings.join(" ").to_ascii_lowercase();
        let mut best: Option<(&str, usize)> = None;
        for (&family, sigs) in &self.family_signatures {
            let matches = sigs
                .iter()
                .filter(|&&sig| combined.contains(&sig.to_ascii_lowercase()))
                .count();
            if matches > 0
                && best.as_ref().is_none_or(|(_, c)| matches > *c) {
                    best = Some((family, matches));
                }
        }
        if let Some((family, _)) = best {
            result.family_guess = Some(family.to_string());
        }
    }
}

impl Default for RansomwareDetector {
    fn default() -> Self { Self::new() }
}

// ─── Wallet address detection ─────────────────────────────────────────────────

const BASE58_ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

fn is_base58(c: char) -> bool {
    BASE58_ALPHABET.contains(&(c as u8))
}

fn detect_btc_address(word: &str) -> Option<String> {
    let word = word.trim_matches(|c: char| !c.is_alphanumeric());
    if word.len() < 25 || word.len() > 35 {
        return None;
    }
    // P2PKH: starts with 1 or 3; Bech32: starts with bc1.
    let is_legacy = (word.starts_with('1') || word.starts_with('3'))
        && word.chars().all(is_base58);
    let is_bech32 = word.starts_with("bc1") && word.chars().all(|c| c.is_ascii_alphanumeric());

    if is_legacy || is_bech32 {
        Some(word.to_string())
    } else {
        None
    }
}

fn detect_monero_address(word: &str) -> Option<String> {
    let word = word.trim_matches(|c: char| !c.is_alphanumeric());
    // Monero standard address: 95 chars, starts with 4.
    if word.len() == 95 && word.starts_with('4') && word.chars().all(is_base58) {
        return Some(word.to_string());
    }
    // Monero subaddress: 95 chars, starts with 8.
    if word.len() == 95 && word.starts_with('8') && word.chars().all(is_base58) {
        return Some(word.to_string());
    }
    None
}

// ─── Common document extensions ──────────────────────────────────────────────

const COMMON_DOCUMENT_EXTENSIONS: &[&str] = &[
    ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".pdf", ".jpg", ".png", ".mp4", ".mp3", ".zip",
    ".7z", ".rar", ".sql", ".db", ".mdb", ".bak",
    ".pst", ".ost", ".odt", ".ods", ".odp", ".csv",
];

// ─── Helpers ──────────────────────────────────────────────────────────────────

fn extract_ascii_strings(data: &[u8], min_len: usize) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    for &b in data {
        if b.is_ascii_graphic() || b == b' ' {
            cur.push(b as char);
        } else {
            if cur.len() >= min_len {
                out.push(cur.clone());
            }
            cur.clear();
        }
    }
    if cur.len() >= min_len {
        out.push(cur);
    }
    out
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn detector() -> RansomwareDetector {
        RansomwareDetector::new()
    }

    // ── Shadow copy deletion ──────────────────────────────────────────────────

    #[test]
    fn test_shadow_copy_vssadmin() {
        let d = detector();
        let result = d.analyze_strings(&[
            "vssadmin delete shadows /all /quiet",
            "cmd.exe /c",
        ]);
        assert!(result.indicators.iter().any(|i| i.code == RansomwareIndicatorCode::ShadowCopyDeletion));
        assert!(!result.shadow_copy_commands.is_empty());
    }

    #[test]
    fn test_shadow_copy_wmic() {
        let d = detector();
        let result = d.analyze_strings(&["wmic shadowcopy delete"]);
        assert!(result.indicators.iter().any(|i| i.code == RansomwareIndicatorCode::ShadowCopyDeletion));
    }

    #[test]
    fn test_shadow_copy_wbadmin() {
        let d = detector();
        let result = d.analyze_strings(&["wbadmin delete catalog -quiet"]);
        assert!(result.indicators.iter().any(|i| i.code == RansomwareIndicatorCode::BackupDeletion));
    }

    // ── Ransom notes ──────────────────────────────────────────────────────────

    #[test]
    fn test_ransom_note_filename() {
        let d = detector();
        let result = d.analyze_strings(&["HOW_TO_DECRYPT.txt", "data.enc"]);
        assert!(result.indicators.iter().any(|i| i.code == RansomwareIndicatorCode::RansomNoteCreation));
    }

    #[test]
    fn test_ransom_note_text() {
        let d = detector();
        let note = "All your files have been encrypted. \
                    To decrypt your files, send bitcoin to the following address. \
                    Contact us via tor browser. Your unique ID is X1234.";
        let result = d.analyze_strings(&[note]);
        assert!(result.indicators.iter().any(|i| i.code == RansomwareIndicatorCode::RansomNoteCreation));
        assert!(!result.ransom_note_samples.is_empty());
    }

    // ── File extension enumeration ────────────────────────────────────────────

    #[test]
    fn test_extension_locked() {
        let d = detector();
        let result = d.analyze_strings(&["document.docx.locked", "photo.jpg.locked"]);
        assert!(result.indicators.iter().any(|i| i.code == RansomwareIndicatorCode::FileExtensionEnumeration));
        assert!(!result.extension_patterns.is_empty());
    }

    #[test]
    fn test_extension_wncry() {
        let d = detector();
        let result = d.analyze_strings(&["C:\\Users\\victim\\Desktop\\important.docx.WNCRY"]);
        assert!(result.indicators.iter().any(|i| i.code == RansomwareIndicatorCode::FileExtensionEnumeration));
    }

    #[test]
    fn test_mass_extension_enumeration() {
        let d = detector();
        // A string containing many document extensions (common in ransom target lists).
        let exts = ".doc .docx .xls .xlsx .ppt .pptx .pdf .jpg .png .mp4 .mp3 .zip";
        let result = d.analyze_strings(&[exts]);
        assert!(result.indicators.iter().any(|i| i.code == RansomwareIndicatorCode::FileExtensionEnumeration));
    }

    // ── Wallet addresses ──────────────────────────────────────────────────────

    #[test]
    fn test_btc_address_p2pkh() {
        let addr = "1A1zP1eP5QGefi2DMPTfTL5SLmv7Divf"; // genesis block address
        let d = detector();
        let result = d.analyze_strings(&[addr]);
        assert!(!result.wallet_addresses.is_empty());
        assert_eq!(result.wallet_addresses[0].currency, CryptoCurrency::Bitcoin);
    }

    #[test]
    fn test_btc_address_too_short() {
        let result = detect_btc_address("1shortaddr");
        assert!(result.is_none());
    }

    #[test]
    fn test_monero_address_not_95_chars() {
        let result = detect_monero_address("4short");
        assert!(result.is_none());
    }

    // ── Encryption APIs ───────────────────────────────────────────────────────

    #[test]
    fn test_crypt_encrypt_api() {
        let d = detector();
        let result = d.analyze_strings(&["CryptEncrypt called at 0x401000"]);
        assert!(result.indicators.iter().any(|i| i.code == RansomwareIndicatorCode::CryptEncryptApiUsage));
    }

    // ── MBR attacks ────────────────────────────────────────────────────────────

    #[test]
    fn test_mbr_attack() {
        let d = detector();
        let result = d.analyze_strings(&[r"\\.\PhysicalDrive0"]);
        assert!(result.indicators.iter().any(|i| i.code == RansomwareIndicatorCode::MbrEncryption));
    }

    // ── Family detection ──────────────────────────────────────────────────────

    #[test]
    fn test_family_wannacry() {
        let d = detector();
        let result = d.analyze_strings(&["WanaCrypt0r 2.0", "tasksche.exe", ".WNCRY"]);
        assert_eq!(result.family_guess.as_deref(), Some("WannaCry"));
    }

    #[test]
    fn test_family_lockbit() {
        let d = detector();
        let result = d.analyze_strings(&["LockBit 3.0", "Restore-My-Files.txt"]);
        assert_eq!(result.family_guess.as_deref(), Some("LockBit"));
    }

    #[test]
    fn test_family_ryuk() {
        let d = detector();
        let result = d.analyze_strings(&["RyukReadMe.html", "HERMES", ".ryuk"]);
        assert_eq!(result.family_guess.as_deref(), Some("Ryuk"));
    }

    // ── Verdict scoring ───────────────────────────────────────────────────────

    #[test]
    fn test_verdict_ransomware_high_score() {
        let d = detector();
        let result = d.analyze_strings(&[
            "vssadmin delete shadows /all /quiet",
            "HOW_TO_DECRYPT.txt",
            "all your files have been encrypted by bitcoin decrypt payment tor browser",
            ".WNCRY",
            "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
        ]);
        // Multiple indicators should push score high.
        assert!(result.score >= 40, "score was {}", result.score);
    }

    #[test]
    fn test_verdict_clean() {
        let d = detector();
        let result = d.analyze_strings(&["normal program output", "Hello, world!"]);
        assert_eq!(result.verdict, RansomwareVerdict::Clean);
    }

    #[test]
    fn test_mitre_techniques_deduped() {
        let d = detector();
        let result = d.analyze_strings(&[
            "vssadmin delete shadows /all",
            "wmic shadowcopy delete",
        ]);
        // Both should map to T1490; after dedup only one entry.
        let t1490_count = result.mitre_techniques.iter().filter(|t| t.as_str() == "T1490").count();
        assert_eq!(t1490_count, 1);
    }

    // ── API-call analysis ─────────────────────────────────────────────────────

    #[test]
    fn test_analyze_api_calls_encrypt() {
        let d = detector();
        let result = d.analyze_api_calls(&["CryptEncrypt", "FindFirstFileW", "FindNextFileW"]);
        assert!(result.indicators.iter().any(|i| i.code == RansomwareIndicatorCode::CryptEncryptApiUsage));
    }

    #[test]
    fn test_analyze_api_calls_mass_enum() {
        let d = detector();
        let apis = ["FindFirstFileW", "FindNextFileW", "FindFirstFileA", "FindNextFileA", "FindFirstFileW"];
        let result = d.analyze_api_calls(&apis);
        assert!(result.indicators.iter().any(|i| i.code == RansomwareIndicatorCode::FileExtensionEnumeration));
    }

    // ── Binary analysis ───────────────────────────────────────────────────────

    #[test]
    fn test_analyze_binary_no_panic() {
        let d = detector();
        let data: Vec<u8> = (0..512).map(|i| (i % 256) as u8).collect();
        let _result = d.analyze_binary(&data);
    }

    #[test]
    fn test_analyze_binary_with_embedded_strings() {
        let d = detector();
        let note = b"vssadmin delete shadows /all /quiet\x00HOW_TO_DECRYPT.txt\x00";
        let result = d.analyze_binary(note);
        assert!(result.score > 0);
    }

    // ── Indicator code display ────────────────────────────────────────────────

    #[test]
    fn test_indicator_code_display() {
        assert_eq!(RansomwareIndicatorCode::ShadowCopyDeletion.to_string(), "shadow_copy_deletion");
        assert_eq!(RansomwareIndicatorCode::RansomNoteCreation.to_string(), "ransom_note_creation");
        assert_eq!(RansomwareIndicatorCode::WalletAddressReference.to_string(), "wallet_address");
    }

    #[test]
    fn test_verdict_display() {
        assert_eq!(RansomwareVerdict::Ransomware.to_string(), "RANSOMWARE");
        assert_eq!(RansomwareVerdict::Clean.to_string(), "CLEAN");
    }

    #[test]
    fn test_mitre_ids_set() {
        assert_eq!(RansomwareIndicatorCode::ShadowCopyDeletion.mitre_id(), Some("T1490"));
        assert_eq!(RansomwareIndicatorCode::RansomNoteCreation.mitre_id(), Some("T1486"));
        assert_eq!(RansomwareIndicatorCode::Other("x".into()).mitre_id(), None);
    }
}
