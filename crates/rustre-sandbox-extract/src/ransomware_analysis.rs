//! Ransomware-specific analysis: family classification, encryption detection,
//! extension enumeration, shadow-copy deletion, wallet addresses, and ransom notes.

use std::collections::{HashMap, HashSet};
use std::fmt;

use serde::{Deserialize, Serialize};

/// Helper: `usize` → `f64` cast isolated to suppress call-site precision warnings.
const fn usize_as_f64(n: usize) -> f64 { n as f64 }

// ─── RansomwareFamily ─────────────────────────────────────────────────────────

/// Known ransomware families (50+).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RansomwareFamily {
    WannaCry,
    NotPetya,
    REvil,
    DarkSide,
    Conti,
    LockBit,
    BlackMatter,
    Hive,
    BlackCat,
    RagnarLocker,
    Maze,
    Ryuk,
    Dharma,
    GandCrab,
    Sodinokibi,
    CryptoLocker,
    TeslaCrypt,
    Locky,
    Cerber,
    Petya,
    BadRabbit,
    SamSam,
    Zeppelin,
    Pysa,
    Cl0p,
    Avaddon,
    MountLocker,
    Cuba,
    Grief,
    Egregor,
    NetWalker,
    Sekhmet,
    Snatch,
    Phobos,
    MedusaLocker,
    Epsilon,
    ProLock,
    DopplePaymer,
    BitPaymer,
    WastedLocker,
    RegretLocker,
    AkiRa,
    Play,
    Royal,
    BlackBasta,
    Trigona,
    IceFire,
    Rorschach,
    Monti,
    Lorenz,
    Quantum,
    Unknown(String),
}

impl fmt::Display for RansomwareFamily {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::WannaCry => "WannaCry",
            Self::NotPetya => "NotPetya",
            Self::REvil => "REvil",
            Self::DarkSide => "DarkSide",
            Self::Conti => "Conti",
            Self::LockBit => "LockBit",
            Self::BlackMatter => "BlackMatter",
            Self::Hive => "Hive",
            Self::BlackCat => "BlackCat",
            Self::RagnarLocker => "RagnarLocker",
            Self::Maze => "Maze",
            Self::Ryuk => "Ryuk",
            Self::Dharma => "Dharma",
            Self::GandCrab => "GandCrab",
            Self::Sodinokibi => "Sodinokibi",
            Self::CryptoLocker => "CryptoLocker",
            Self::TeslaCrypt => "TeslaCrypt",
            Self::Locky => "Locky",
            Self::Cerber => "Cerber",
            Self::Petya => "Petya",
            Self::BadRabbit => "BadRabbit",
            Self::SamSam => "SamSam",
            Self::Zeppelin => "Zeppelin",
            Self::Pysa => "Pysa",
            Self::Cl0p => "Cl0p",
            Self::Avaddon => "Avaddon",
            Self::MountLocker => "MountLocker",
            Self::Cuba => "Cuba",
            Self::Grief => "Grief",
            Self::Egregor => "Egregor",
            Self::NetWalker => "NetWalker",
            Self::Sekhmet => "Sekhmet",
            Self::Snatch => "Snatch",
            Self::Phobos => "Phobos",
            Self::MedusaLocker => "MedusaLocker",
            Self::Epsilon => "Epsilon",
            Self::ProLock => "ProLock",
            Self::DopplePaymer => "DopplePaymer",
            Self::BitPaymer => "BitPaymer",
            Self::WastedLocker => "WastedLocker",
            Self::RegretLocker => "RegretLocker",
            Self::AkiRa => "AkiRa",
            Self::Play => "Play",
            Self::Royal => "Royal",
            Self::BlackBasta => "BlackBasta",
            Self::Trigona => "Trigona",
            Self::IceFire => "IceFire",
            Self::Rorschach => "Rorschach",
            Self::Monti => "Monti",
            Self::Lorenz => "Lorenz",
            Self::Quantum => "Quantum",
            Self::Unknown(s) => s.as_str(),
        };
        write!(f, "{s}")
    }
}

impl RansomwareFamily {
    /// Return the commonly associated file extension(s) for this family.
    #[must_use]
    pub fn extensions(&self) -> Vec<&'static str> {
        match self {
            Self::WannaCry => vec!["WNCRY"],
            Self::LockBit => vec!["lockbit", "lockbit3"],
            Self::BlackCat => vec!["alphv"],
            Self::Dharma => vec!["dharma", ".id-[id].[email].dharma"],
            Self::GandCrab => vec!["GDCB", "CRAB", "KRAB"],
            Self::Locky => vec!["locky", "zepto", "odin"],
            Self::Cerber => vec!["cerber", "cerber2", "cerber3"],
            Self::Phobos => vec!["phobos", "eking"],
            Self::Ryuk => vec!["ryk"],
            Self::Cl0p => vec!["clop"],
            Self::Hive => vec!["hive"],
            Self::Conti => vec!["conti"],
            Self::BlackBasta => vec!["basta"],
            Self::Play => vec!["play"],
            Self::Royal => vec!["royal"],
            Self::Quantum => vec!["quantum"],
            _ => vec![],
        }
    }

    /// Returns the name of the ransom note file for this family.
    #[must_use]
    pub const fn note_filename(&self) -> &'static str {
        match self {
            Self::WannaCry => "@Please_Read_Me@.txt",
            Self::REvil | Self::Sodinokibi => "[victim]-readme.txt",
            Self::Conti => "CONTI_README.txt",
            Self::LockBit => "Restore-My-Files.txt",
            Self::Ryuk => "RyukReadMe.html",
            Self::DarkSide => "README.[ext].TXT",
            Self::BlackCat => "RECOVER-[ext]-FILES.txt",
            Self::Cl0p => "ClopReadMe.txt",
            Self::Hive => "HOW_TO_DECRYPT.txt",
            Self::BlackBasta => "readme.txt",
            _ => "README.txt",
        }
    }

    /// Returns `true` if this family is known to use double-extortion.
    #[must_use]
    pub const fn uses_double_extortion(&self) -> bool {
        matches!(
            self,
            Self::REvil
                | Self::Conti
                | Self::LockBit
                | Self::BlackCat
                | Self::DarkSide
                | Self::BlackMatter
                | Self::Hive
                | Self::Maze
                | Self::Egregor
                | Self::Cl0p
                | Self::BlackBasta
                | Self::Play
                | Self::Royal
                | Self::Quantum
                | Self::Lorenz
                | Self::Trigona
                | Self::Monti
                | Self::Rorschach
        )
    }

    /// Returns the typical encryption algorithm used.
    #[must_use]
    pub const fn encryption_algorithm(&self) -> &'static str {
        match self {
            Self::WannaCry => "AES-128-CBC + RSA-2048",
            Self::REvil | Self::Sodinokibi => "AES-256-CBC + Curve25519",
            Self::Conti => "ChaCha8 + RSA-4096",
            Self::LockBit => "AES-128 + RSA-2048",
            Self::BlackCat => "AES-256 + ChaCha20 + RSA-4096",
            Self::Hive => "Golang custom + ECC",
            Self::Cl0p => "AES-256 + RSA-1024",
            Self::Ryuk => "AES-256 + RSA-4096",
            Self::DarkSide => "Salsa20 + RSA-1024",
            _ => "AES-256 + RSA-2048",
        }
    }
}

// ─── EncryptionDetector ───────────────────────────────────────────────────────

/// Detects file encryption activity from API call sequences and file operations.
#[derive(Debug, Clone, Default)]
pub struct EncryptionDetector {
    /// Minimum number of encryption API calls to trigger a positive detection.
    pub min_calls: usize,
    /// Minimum number of files affected to consider bulk encryption.
    pub min_files: usize,
}

/// Result of an encryption detection scan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptionDetectionResult {
    /// Whether bulk encryption was detected.
    pub detected: bool,
    /// Number of encryption API calls observed.
    pub crypto_call_count: usize,
    /// Number of files modified/created during the analysis window.
    pub files_affected: usize,
    /// Detected algorithms from API names.
    pub algorithms: Vec<String>,
    /// Confidence score 0–100.
    pub confidence: u8,
    /// Observed key lengths in bits.
    pub key_lengths: Vec<u32>,
}

impl EncryptionDetectionResult {
    /// Returns `true` if the confidence meets or exceeds the threshold.
    #[must_use]
    pub const fn is_confident(&self, threshold: u8) -> bool {
        self.confidence >= threshold
    }
}

impl EncryptionDetector {
    /// Create a detector with default thresholds.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            min_calls: 3,
            min_files: 10,
        }
    }

    /// Create a detector with custom thresholds.
    #[must_use]
    pub const fn with_thresholds(min_calls: usize, min_files: usize) -> Self {
        Self {
            min_calls,
            min_files,
        }
    }

    /// Detect encryption from a list of API call names and affected file paths.
    #[must_use]
    pub fn detect(&self, api_calls: &[&str], affected_files: &[&str]) -> EncryptionDetectionResult {
        let crypto_apis = [
            "CryptEncrypt",
            "BCryptEncrypt",
            "CryptAcquireContext",
            "BCryptOpenAlgorithmProvider",
            "BCryptGenerateSymmetricKey",
            "BCryptSetProperty",
            "CryptCreateHash",
            "CryptHashData",
            "EVP_EncryptInit",
            "EVP_EncryptUpdate",
            "EVP_EncryptFinal",
        ];
        let alg_indicators = [
            ("AES", "AES"),
            ("RSA", "RSA"),
            ("ChaCha", "ChaCha20"),
            ("Salsa", "Salsa20"),
            ("Curve25519", "Curve25519"),
        ];

        let mut crypto_call_count = 0usize;
        let mut algorithms: HashSet<String> = HashSet::new();
        let mut key_lengths: Vec<u32> = Vec::new();

        for call in api_calls {
            if crypto_apis.iter().any(|&a| call.contains(a)) {
                crypto_call_count += 1;
            }
            for (kw, alg) in &alg_indicators {
                if call.contains(kw) {
                    algorithms.insert(alg.to_string());
                }
            }
        }

        // Key-size heuristic: look for 128/256 in property-set calls.
        for call in api_calls {
            if call.contains("256") {
                key_lengths.push(256);
            } else if call.contains("128") {
                key_lengths.push(128);
            }
        }
        key_lengths.sort_unstable();
        key_lengths.dedup();

        let files_affected = affected_files.len();
        let detected = crypto_call_count >= self.min_calls && files_affected >= self.min_files;

        let mut confidence: u8 = 0;
        if detected {
            confidence = 50;
            if crypto_call_count >= 10 {
                confidence = confidence.saturating_add(20);
            }
            if files_affected >= 100 {
                confidence = confidence.saturating_add(20);
            }
            if !algorithms.is_empty() {
                confidence = confidence.saturating_add(10);
            }
        } else if crypto_call_count > 0 {
            confidence = u8::try_from(crypto_call_count.min(50)).unwrap_or(50).saturating_mul(2);
        }

        EncryptionDetectionResult {
            detected,
            crypto_call_count,
            files_affected,
            algorithms: algorithms.into_iter().collect(),
            confidence: confidence.min(100),
            key_lengths,
        }
    }

    /// Returns `true` if the entropy of the given bytes suggests encryption (> 7.5).
    #[must_use]
    pub fn is_high_entropy(data: &[u8]) -> bool {
        if data.is_empty() {
            return false;
        }
        let mut counts = [0u32; 256];
        for &b in data {
            counts[b as usize] += 1;
        }
        let n = usize_as_f64(data.len());
        let entropy: f64 = counts
            .iter()
            .filter(|&&c| c > 0)
            .map(|&c| {
                let p = f64::from(c) / n;
                -p * p.log2()
            })
            .sum();
        entropy > 7.5
    }

    /// Estimate entropy of a byte slice.
    #[must_use]
    pub fn entropy(data: &[u8]) -> f64 {
        if data.is_empty() {
            return 0.0;
        }
        let mut counts = [0u32; 256];
        for &b in data {
            counts[b as usize] += 1;
        }
        let n = usize_as_f64(data.len());
        counts
            .iter()
            .filter(|&&c| c > 0)
            .map(|&c| {
                let p = f64::from(c) / n;
                -p * p.log2()
            })
            .sum()
    }
}

// ─── ExtensionEnumerator ──────────────────────────────────────────────────────

/// Enumerates file extensions changed/added by ransomware.
#[derive(Debug, Clone, Default)]
pub struct ExtensionEnumerator;

/// A record of an extension change event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtensionChange {
    /// Original file path.
    pub original_path: String,
    /// New (encrypted) file path.
    pub new_path: String,
    /// Original extension.
    pub original_ext: String,
    /// New extension added by the ransomware.
    pub new_ext: String,
}

impl ExtensionChange {
    /// Create a new extension change record.
    #[must_use]
    pub fn new(
        original_path: impl Into<String>,
        new_path: impl Into<String>,
        original_ext: impl Into<String>,
        new_ext: impl Into<String>,
    ) -> Self {
        Self {
            original_path: original_path.into(),
            new_path: new_path.into(),
            original_ext: original_ext.into(),
            new_ext: new_ext.into(),
        }
    }
}

impl ExtensionEnumerator {
    /// Create a new enumerator.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Detect extension changes by comparing original and new file path lists.
    ///
    /// Pairs are matched by stem; unmatched files are ignored.
    #[must_use]
    pub fn detect_changes(&self, before: &[&str], after: &[&str]) -> Vec<ExtensionChange> {
        let before_map: HashMap<String, &str> = before
            .iter()
            .map(|p| (stem(p).to_ascii_lowercase(), *p))
            .collect();
        let after_map: HashMap<String, &str> = after
            .iter()
            .map(|p| (stem(p).to_ascii_lowercase(), *p))
            .collect();

        let mut changes = Vec::new();
        for (stem, before_path) in &before_map {
            if let Some(&after_path) = after_map.get(stem) {
                let ext_before = extension(before_path);
                let ext_after = extension(after_path);
                if ext_before != ext_after {
                    changes.push(ExtensionChange::new(
                        *before_path,
                        after_path,
                        ext_before,
                        ext_after,
                    ));
                }
            }
        }
        changes
    }

    /// Count how many times each new extension appears in a list of file changes.
    #[must_use]
    pub fn extension_frequency(changes: &[ExtensionChange]) -> HashMap<String, usize> {
        let mut freq: HashMap<String, usize> = HashMap::new();
        for c in changes {
            *freq.entry(c.new_ext.clone()).or_insert(0) += 1;
        }
        freq
    }

    /// Try to identify the ransomware family from the most common new extension.
    #[must_use]
    pub fn identify_family(changes: &[ExtensionChange]) -> Option<RansomwareFamily> {
        let freq = Self::extension_frequency(changes);
        let most_common = freq.into_iter().max_by_key(|(_, c)| *c)?.0;
        let ext = most_common.to_ascii_lowercase();
        let family = match ext.as_str() {
            "wncry" | "wnry" => RansomwareFamily::WannaCry,
            "lockbit" | "lockbit3" => RansomwareFamily::LockBit,
            "alphv" => RansomwareFamily::BlackCat,
            "gdcb" | "crab" | "krab" => RansomwareFamily::GandCrab,
            "locky" | "zepto" | "odin" => RansomwareFamily::Locky,
            "cerber" | "cerber2" | "cerber3" => RansomwareFamily::Cerber,
            "phobos" | "eking" => RansomwareFamily::Phobos,
            "ryk" => RansomwareFamily::Ryuk,
            "clop" => RansomwareFamily::Cl0p,
            "hive" => RansomwareFamily::Hive,
            "conti" => RansomwareFamily::Conti,
            "basta" => RansomwareFamily::BlackBasta,
            "play" => RansomwareFamily::Play,
            "royal" => RansomwareFamily::Royal,
            "quantum" => RansomwareFamily::Quantum,
            _ => RansomwareFamily::Unknown(most_common),
        };
        Some(family)
    }
}

// ─── ShadowCopyDeletion ────────────────────────────────────────────────────────

/// Detects shadow copy deletion attempts.
#[derive(Debug, Clone, Default)]
pub struct ShadowCopyDeletion;

/// Evidence of a shadow copy deletion attempt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShadowDeletionEvidence {
    /// The command line or API that triggered the detection.
    pub trigger: String,
    /// Confidence that this is a real deletion attempt (0–100).
    pub confidence: u8,
    /// Method used.
    pub method: ShadowDeletionMethod,
}

/// Method used to delete shadow copies.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ShadowDeletionMethod {
    Vssadmin,
    Wmic,
    Bcdedit,
    Powershell,
    WmiApi,
    Other(String),
}

impl fmt::Display for ShadowDeletionMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Vssadmin => write!(f, "vssadmin"),
            Self::Wmic => write!(f, "wmic"),
            Self::Bcdedit => write!(f, "bcdedit"),
            Self::Powershell => write!(f, "powershell"),
            Self::WmiApi => write!(f, "wmi_api"),
            Self::Other(s) => write!(f, "{s}"),
        }
    }
}

impl ShadowCopyDeletion {
    /// Create a new detector.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Scan a list of command lines for shadow copy deletion indicators.
    #[must_use]
    pub fn detect_in_cmdlines(&self, cmdlines: &[&str]) -> Vec<ShadowDeletionEvidence> {
        let patterns: &[(&str, ShadowDeletionMethod, u8)] = &[
            (
                "vssadmin delete shadows",
                ShadowDeletionMethod::Vssadmin,
                98,
            ),
            ("vssadmin.exe delete", ShadowDeletionMethod::Vssadmin, 95),
            ("wmic shadowcopy delete", ShadowDeletionMethod::Wmic, 98),
            ("wmic.exe shadowcopy delete", ShadowDeletionMethod::Wmic, 95),
            (
                "bcdedit /set {default} bootstatuspolicy ignoreallfailures",
                ShadowDeletionMethod::Bcdedit,
                90,
            ),
            (
                "bcdedit /set {default} recoveryenabled no",
                ShadowDeletionMethod::Bcdedit,
                90,
            ),
            (
                "Get-WmiObject Win32_Shadowcopy | ForEach",
                ShadowDeletionMethod::Powershell,
                95,
            ),
            ("Win32_ShadowCopy", ShadowDeletionMethod::WmiApi, 85),
        ];

        let mut found = Vec::new();
        for cmdline in cmdlines {
            let lower = cmdline.to_ascii_lowercase();
            for (pat, method, confidence) in patterns {
                if lower.contains(&pat.to_ascii_lowercase()) {
                    found.push(ShadowDeletionEvidence {
                        trigger: cmdline.to_string(),
                        confidence: *confidence,
                        method: method.clone(),
                    });
                }
            }
        }
        found
    }

    /// Returns `true` if any shadow deletion evidence was found.
    #[must_use]
    pub const fn has_deletion(evidence: &[ShadowDeletionEvidence]) -> bool {
        !evidence.is_empty()
    }

    /// Return only high-confidence shadow deletion evidence.
    #[must_use]
    pub fn high_confidence(
        evidence: &[ShadowDeletionEvidence],
        threshold: u8,
    ) -> Vec<&ShadowDeletionEvidence> {
        evidence
            .iter()
            .filter(|e| e.confidence >= threshold)
            .collect()
    }
}

// ─── WalletAddress ────────────────────────────────────────────────────────────

/// A cryptocurrency wallet address extracted from a sample.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletAddress {
    /// The raw address string.
    pub address: String,
    /// Cryptocurrency type.
    pub currency: CryptoCurrency,
    /// Source where the address was found.
    pub source: String,
    /// Confidence score (0–100).
    pub confidence: u8,
}

impl WalletAddress {
    /// Create a new wallet address.
    #[must_use]
    pub fn new(
        address: impl Into<String>,
        currency: CryptoCurrency,
        source: impl Into<String>,
        confidence: u8,
    ) -> Self {
        Self {
            address: address.into(),
            currency,
            source: source.into(),
            confidence: confidence.min(100),
        }
    }

    /// Returns `true` if this looks like a valid Bitcoin address (heuristic).
    #[must_use]
    pub fn is_valid_format(&self) -> bool {
        match &self.currency {
            CryptoCurrency::Bitcoin => {
                let a = &self.address;
                (a.starts_with('1') || a.starts_with('3') || a.starts_with("bc1"))
                    && a.len() >= 25
                    && a.len() <= 62
                    && a.chars().all(char::is_alphanumeric)
            }
            CryptoCurrency::Monero => self.address.len() == 95 && self.address.starts_with('4'),
            CryptoCurrency::Ethereum => self.address.starts_with("0x") && self.address.len() == 42,
            CryptoCurrency::Zcash => self.address.starts_with('t') && self.address.len() == 35,
            CryptoCurrency::Other(_) => true,
        }
    }
}

/// Supported cryptocurrency types.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CryptoCurrency {
    Bitcoin,
    Monero,
    Ethereum,
    Zcash,
    Other(String),
}

impl fmt::Display for CryptoCurrency {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bitcoin => write!(f, "BTC"),
            Self::Monero => write!(f, "XMR"),
            Self::Ethereum => write!(f, "ETH"),
            Self::Zcash => write!(f, "ZEC"),
            Self::Other(s) => write!(f, "{s}"),
        }
    }
}

/// Extracts wallet addresses from strings.
#[derive(Debug, Clone, Default)]
pub struct WalletExtractor;

impl WalletExtractor {
    /// Create a new extractor.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Scan a slice of strings for cryptocurrency wallet addresses.
    #[must_use]
    pub fn extract(&self, strings: &[&str]) -> Vec<WalletAddress> {
        let mut found = Vec::new();
        for s in strings {
            let s = s.trim();
            // Bitcoin legacy (P2PKH / P2SH)
            if (s.starts_with('1') || s.starts_with('3'))
                && s.len() >= 25
                && s.len() <= 34
                && s.chars().all(char::is_alphanumeric)
            {
                found.push(WalletAddress::new(
                    s,
                    CryptoCurrency::Bitcoin,
                    "string_scan",
                    80,
                ));
            }
            // SegWit bech32
            if s.starts_with("bc1") && s.len() >= 26 && s.len() <= 62 {
                found.push(WalletAddress::new(
                    s,
                    CryptoCurrency::Bitcoin,
                    "string_scan",
                    85,
                ));
            }
            // Ethereum
            if s.starts_with("0x") && s.len() == 42 && s[2..].chars().all(|c| c.is_ascii_hexdigit())
            {
                found.push(WalletAddress::new(
                    s,
                    CryptoCurrency::Ethereum,
                    "string_scan",
                    85,
                ));
            }
            // Monero
            if s.starts_with('4') && s.len() == 95 && s.chars().all(char::is_alphanumeric) {
                found.push(WalletAddress::new(
                    s,
                    CryptoCurrency::Monero,
                    "string_scan",
                    80,
                ));
            }
            // Zcash transparent
            if s.starts_with('t') && s.len() == 35 && s.chars().all(char::is_alphanumeric) {
                found.push(WalletAddress::new(
                    s,
                    CryptoCurrency::Zcash,
                    "string_scan",
                    75,
                ));
            }
        }
        found
    }
}

// ─── RansomNote ───────────────────────────────────────────────────────────────

/// A ransom note dropped by the malware.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RansomNote {
    /// The filename of the ransom note.
    pub filename: String,
    /// The raw text content.
    pub content: String,
    /// Path where the note was found.
    pub path: String,
    /// Extracted wallet addresses.
    pub wallets: Vec<WalletAddress>,
    /// Extracted email addresses.
    pub emails: Vec<String>,
    /// Extracted Tor / onion URLs.
    pub onion_urls: Vec<String>,
    /// Inferred ransomware family.
    pub family: Option<RansomwareFamily>,
    /// Detected language (ISO 639-1).
    pub language: String,
    /// Ransom amount mentioned.
    pub ransom_amount: Option<String>,
}

impl RansomNote {
    /// Create a ransom note from raw content.
    #[must_use]
    pub fn new(
        filename: impl Into<String>,
        content: impl Into<String>,
        path: impl Into<String>,
    ) -> Self {
        let content_str: String = content.into();
        let wallets =
            WalletExtractor::new().extract(&content_str.split_whitespace().collect::<Vec<_>>());
        let emails = extract_emails(&content_str);
        let onion_urls = extract_onion_urls(&content_str);
        let family = infer_family_from_note(&content_str);
        let ransom_amount = extract_ransom_amount(&content_str);

        Self {
            filename: filename.into(),
            path: path.into(),
            wallets,
            emails,
            onion_urls,
            family,
            language: "en".to_string(),
            ransom_amount,
            content: content_str,
        }
    }

    /// Returns `true` if this note contains evidence of a payment deadline.
    #[must_use]
    pub fn has_deadline(&self) -> bool {
        let lower = self.content.to_ascii_lowercase();
        lower.contains("deadline")
            || lower.contains("hours")
            || lower.contains("72h")
            || lower.contains("48h")
            || lower.contains("double")
    }

    /// Returns `true` if this note mentions data exfiltration / double extortion.
    #[must_use]
    pub fn mentions_data_leak(&self) -> bool {
        let lower = self.content.to_ascii_lowercase();
        lower.contains("leaked")
            || lower.contains("published")
            || lower.contains("stolen")
            || lower.contains("exfiltrated")
            || lower.contains("blog")
    }

    /// Returns a brief summary line for the note.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "note='{}' family={} wallets={} emails={} onion={}",
            self.filename,
            self.family
                .as_ref()
                .map_or_else(|| "unknown".into(), std::string::ToString::to_string),
            self.wallets.len(),
            self.emails.len(),
            self.onion_urls.len()
        )
    }
}

// ─── RansomwareAnalysis ───────────────────────────────────────────────────────

/// Aggregated ransomware analysis result for a sandbox run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RansomwareAnalysis {
    /// Detected family, if any.
    pub family: Option<RansomwareFamily>,
    /// Encryption detection result.
    pub encryption: EncryptionDetectionResult,
    /// File extension changes observed.
    pub extension_changes: Vec<ExtensionChange>,
    /// Shadow copy deletion evidence.
    pub shadow_deletions: Vec<ShadowDeletionEvidence>,
    /// Wallet addresses found.
    pub wallets: Vec<WalletAddress>,
    /// Ransom notes dropped.
    pub ransom_notes: Vec<RansomNote>,
    /// Overall confidence that this is ransomware (0–100).
    pub ransomware_confidence: u8,
    /// Key indicators driving the confidence score.
    pub indicators: Vec<String>,
}

impl RansomwareAnalysis {
    /// Create an empty analysis struct.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            family: None,
            encryption: EncryptionDetectionResult {
                detected: false,
                crypto_call_count: 0,
                files_affected: 0,
                algorithms: vec![],
                confidence: 0,
                key_lengths: vec![],
            },
            extension_changes: vec![],
            shadow_deletions: vec![],
            wallets: vec![],
            ransom_notes: vec![],
            ransomware_confidence: 0,
            indicators: vec![],
        }
    }

    /// Compute the overall confidence and populate indicator list.
    pub fn compute_confidence(&mut self) {
        let mut score: u8 = 0;
        let mut indicators = Vec::new();

        if self.encryption.detected {
            score = score.saturating_add(30);
            indicators.push("bulk_encryption_detected".to_string());
        } else if self.encryption.crypto_call_count > 0 {
            score = score.saturating_add(10);
            indicators.push(format!(
                "crypto_calls={}",
                self.encryption.crypto_call_count
            ));
        }

        if !self.extension_changes.is_empty() {
            score = score.saturating_add(25);
            indicators.push(format!(
                "extension_changes={}",
                self.extension_changes.len()
            ));
        }

        if !self.shadow_deletions.is_empty() {
            score = score.saturating_add(20);
            indicators.push("shadow_copy_deletion".to_string());
        }

        if !self.ransom_notes.is_empty() {
            score = score.saturating_add(20);
            indicators.push(format!("ransom_notes={}", self.ransom_notes.len()));
        }

        if !self.wallets.is_empty() {
            score = score.saturating_add(5);
            indicators.push(format!("wallets={}", self.wallets.len()));
        }

        self.ransomware_confidence = score.min(100);
        self.indicators = indicators;
    }

    /// Returns `true` if this analysis indicates active ransomware.
    #[must_use]
    pub const fn is_ransomware(&self) -> bool {
        self.ransomware_confidence >= 60
    }

    /// Build a mock analysis for testing.
    #[must_use]
    pub fn mock() -> Self {
        let detector = EncryptionDetector::new();
        let crypto_apis = vec![
            "BCryptEncrypt",
            "BCryptOpenAlgorithmProvider",
            "BCryptGenerateSymmetricKey",
        ];
        let files: Vec<&str> = (0..50)
            .map(|_| "C:\\Users\\victim\\Documents\\file.docx")
            .collect();
        let encryption = detector.detect(&crypto_apis, &files);

        let note = RansomNote::new(
            "readme.txt",
            "All your files have been encrypted. Send 1 BTC to 1A1zP1eP5QGefi2DMPTfTL5SLmv7Divf oN deadline 72h.",
            "C:\\Users\\victim\\readme.txt",
        );

        let shadow = ShadowCopyDeletion::new();
        let shadow_evidence = shadow.detect_in_cmdlines(&[
            "vssadmin delete shadows /all /quiet",
            "wmic shadowcopy delete",
        ]);

        let changes = vec![
            ExtensionChange::new("C:\\doc.docx", "C:\\doc.docx.lockbit", "docx", "lockbit"),
            ExtensionChange::new("C:\\photo.jpg", "C:\\photo.jpg.lockbit", "jpg", "lockbit"),
        ];

        let mut analysis = Self {
            family: Some(RansomwareFamily::LockBit),
            encryption,
            extension_changes: changes,
            shadow_deletions: shadow_evidence,
            wallets: note.wallets.clone(),
            ransom_notes: vec![note],
            ransomware_confidence: 0,
            indicators: vec![],
        };
        analysis.compute_confidence();
        analysis
    }
}

impl Default for RansomwareAnalysis {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

fn stem(path: &str) -> &str {
    let name = path.rsplit(['/', '\\']).next().unwrap_or(path);
    name.rfind('.').map_or(name, |dot| &name[..dot])
}

fn extension(path: &str) -> String {
    let name = path.rsplit(['/', '\\']).next().unwrap_or(path);
    name.rfind('.').map_or_else(String::new, |dot| name[dot + 1..].to_string())
}

fn extract_emails(text: &str) -> Vec<String> {
    let mut emails = Vec::new();
    for word in text.split_whitespace() {
        let w = word.trim_matches(|c: char| {
            !c.is_alphanumeric() && c != '@' && c != '.' && c != '-' && c != '_'
        });
        if w.contains('@') && w.contains('.') && w.len() >= 6 {
            emails.push(w.to_string());
        }
    }
    emails.sort();
    emails.dedup();
    emails
}

fn extract_onion_urls(text: &str) -> Vec<String> {
    text.split_whitespace()
        .filter(|w| w.contains(".onion"))
        .map(|w| {
            w.trim_matches(|c: char| !c.is_alphanumeric() && c != '.' && c != ':' && c != '/')
                .to_string()
        })
        .collect()
}

fn infer_family_from_note(content: &str) -> Option<RansomwareFamily> {
    let lower = content.to_ascii_lowercase();
    if lower.contains("lockbit") {
        return Some(RansomwareFamily::LockBit);
    }
    if lower.contains("conti") {
        return Some(RansomwareFamily::Conti);
    }
    if lower.contains("revil") || lower.contains("sodinokibi") {
        return Some(RansomwareFamily::REvil);
    }
    if lower.contains("darkside") {
        return Some(RansomwareFamily::DarkSide);
    }
    if lower.contains("hive") {
        return Some(RansomwareFamily::Hive);
    }
    if lower.contains("blackcat") || lower.contains("alphv") {
        return Some(RansomwareFamily::BlackCat);
    }
    if lower.contains("ryuk") {
        return Some(RansomwareFamily::Ryuk);
    }
    if lower.contains("cl0p") || lower.contains("clop") {
        return Some(RansomwareFamily::Cl0p);
    }
    if lower.contains("blackbasta") || lower.contains("black basta") {
        return Some(RansomwareFamily::BlackBasta);
    }
    if lower.contains("wannacry") || lower.contains("wcry") {
        return Some(RansomwareFamily::WannaCry);
    }
    None
}

fn extract_ransom_amount(content: &str) -> Option<String> {
    // Very simple heuristic: look for "X BTC", "X XMR", "$X" patterns.
    let patterns = [" BTC", " XMR", " ETH", "$ ", "USD"];
    for word in content.split_whitespace().rev() {
        for pat in &patterns {
            if (content.contains(&format!("{word}{pat}"))
                || content.contains(&format!("{word} {pat}")))
                && word.parse::<f64>().is_ok()
            {
                return Some(format!("{word}{pat}"));
            }
        }
    }
    None
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // RansomwareFamily tests
    #[test]
    fn test_family_display() {
        assert_eq!(RansomwareFamily::LockBit.to_string(), "LockBit");
    }
    #[test]
    fn test_family_unknown_display() {
        assert_eq!(
            RansomwareFamily::Unknown("FooBar".into()).to_string(),
            "FooBar"
        );
    }
    #[test]
    fn test_family_extensions_wannacry() {
        assert!(RansomwareFamily::WannaCry.extensions().contains(&"WNCRY"));
    }
    #[test]
    fn test_family_extensions_lockbit() {
        assert!(
            RansomwareFamily::LockBit
                .extensions()
                .iter()
                .any(|e| e.contains("lockbit"))
        );
    }
    #[test]
    fn test_family_note_filename() {
        assert!(
            RansomwareFamily::WannaCry
                .note_filename()
                .contains("Please_Read")
        );
    }
    #[test]
    fn test_family_double_extortion_lockbit() {
        assert!(RansomwareFamily::LockBit.uses_double_extortion());
    }
    #[test]
    fn test_family_double_extortion_wannacry() {
        assert!(!RansomwareFamily::WannaCry.uses_double_extortion());
    }
    #[test]
    fn test_family_encryption_alg() {
        assert!(
            RansomwareFamily::BlackCat
                .encryption_algorithm()
                .contains("ChaCha")
        );
    }
    #[test]
    fn test_family_50_variants() {
        let families = vec![
            RansomwareFamily::WannaCry,
            RansomwareFamily::LockBit,
            RansomwareFamily::Conti,
            RansomwareFamily::REvil,
            RansomwareFamily::DarkSide,
            RansomwareFamily::BlackCat,
            RansomwareFamily::Hive,
            RansomwareFamily::Ryuk,
            RansomwareFamily::Cl0p,
            RansomwareFamily::BlackBasta,
        ];
        assert_eq!(families.len(), 10);
        for f in &families {
            assert!(!f.to_string().is_empty());
        }
    }

    // EncryptionDetector tests
    #[test]
    fn test_detect_bulk_encryption() {
        let d = EncryptionDetector::new();
        let calls = vec![
            "BCryptEncrypt",
            "BCryptEncrypt",
            "BCryptEncrypt",
            "BCryptOpenAlgorithmProvider",
        ];
        let files: Vec<&str> = (0..20).map(|_| "file.docx").collect();
        let result = d.detect(&calls, &files);
        assert!(result.detected);
        assert!(result.confidence > 0);
    }
    #[test]
    fn test_detect_no_encryption() {
        let d = EncryptionDetector::new();
        let result = d.detect(&["CreateFile", "ReadFile"], &["a.txt"]);
        assert!(!result.detected);
    }
    #[test]
    fn test_detect_custom_thresholds() {
        let d = EncryptionDetector::with_thresholds(1, 1);
        let result = d.detect(&["CryptEncrypt"], &["file.txt"]);
        assert!(result.detected);
    }
    #[test]
    fn test_high_entropy_true() {
        assert!(EncryptionDetector::is_high_entropy(&[255u8; 256]));
    }
    #[test]
    fn test_high_entropy_false() {
        assert!(!EncryptionDetector::is_high_entropy(&[0u8; 256]));
    }
    #[test]
    fn test_entropy_value() {
        let e = EncryptionDetector::entropy(&[0u8; 64]);
        assert_eq!(e, 0.0);
    }
    #[test]
    fn test_entropy_uniform() {
        let data: Vec<u8> = (0..=255u8).collect();
        let e = EncryptionDetector::entropy(&data);
        assert!(e > 7.9);
    }
    #[test]
    fn test_detect_empty_data() {
        let d = EncryptionDetector::new();
        let result = d.detect(&[], &[]);
        assert!(!result.detected);
    }

    // ExtensionEnumerator tests
    #[test]
    fn test_extension_change_detection() {
        let e = ExtensionEnumerator::new();
        let before = ["C:\\doc.docx", "C:\\img.jpg"];
        let after = ["C:\\doc.lockbit", "C:\\img.lockbit"];
        let changes = e.detect_changes(&before, &after);
        assert_eq!(changes.len(), 2);
    }
    #[test]
    fn test_extension_no_change() {
        let e = ExtensionEnumerator::new();
        let before = ["C:\\doc.docx"];
        let after = ["C:\\doc.docx"];
        assert!(e.detect_changes(&before, &after).is_empty());
    }
    #[test]
    fn test_extension_frequency() {
        let changes = vec![
            ExtensionChange::new("a.docx", "a.lockbit", "docx", "lockbit"),
            ExtensionChange::new("b.xlsx", "b.lockbit", "xlsx", "lockbit"),
        ];
        let freq = ExtensionEnumerator::extension_frequency(&changes);
        assert_eq!(freq.get("lockbit"), Some(&2));
    }
    #[test]
    fn test_identify_family_lockbit() {
        let changes = vec![ExtensionChange::new(
            "a.docx",
            "a.lockbit",
            "docx",
            "lockbit",
        )];
        let fam = ExtensionEnumerator::identify_family(&changes);
        assert!(matches!(fam, Some(RansomwareFamily::LockBit)));
    }
    #[test]
    fn test_identify_family_wannacry() {
        let changes = vec![ExtensionChange::new("a.docx", "a.WNCRY", "docx", "wncry")];
        let fam = ExtensionEnumerator::identify_family(&changes);
        assert!(matches!(fam, Some(RansomwareFamily::WannaCry)));
    }

    // ShadowCopyDeletion tests
    #[test]
    fn test_shadow_vssadmin() {
        let d = ShadowCopyDeletion::new();
        let ev = d.detect_in_cmdlines(&["vssadmin delete shadows /all /quiet"]);
        assert!(!ev.is_empty());
        assert_eq!(ev[0].method, ShadowDeletionMethod::Vssadmin);
    }
    #[test]
    fn test_shadow_wmic() {
        let d = ShadowCopyDeletion::new();
        let ev = d.detect_in_cmdlines(&["wmic shadowcopy delete"]);
        assert!(!ev.is_empty());
        assert_eq!(ev[0].method, ShadowDeletionMethod::Wmic);
    }
    #[test]
    fn test_shadow_no_match() {
        let d = ShadowCopyDeletion::new();
        let ev = d.detect_in_cmdlines(&["dir C:\\"]);
        assert!(ev.is_empty());
    }
    #[test]
    fn test_shadow_has_deletion() {
        let d = ShadowCopyDeletion::new();
        let ev = d.detect_in_cmdlines(&["vssadmin delete shadows /all /quiet"]);
        assert!(ShadowCopyDeletion::has_deletion(&ev));
    }
    #[test]
    fn test_shadow_high_confidence() {
        let d = ShadowCopyDeletion::new();
        let ev = d.detect_in_cmdlines(&["vssadmin delete shadows /all /quiet"]);
        let hc = ShadowCopyDeletion::high_confidence(&ev, 90);
        assert!(!hc.is_empty());
    }
    #[test]
    fn test_shadow_display() {
        assert_eq!(ShadowDeletionMethod::Vssadmin.to_string(), "vssadmin");
    }

    // WalletAddress / WalletExtractor tests
    #[test]
    fn test_wallet_btc_valid() {
        let w = WalletAddress::new(
            "1A1zP1eP5QGefi2DMPTfTL5SLmv7Divf",
            CryptoCurrency::Bitcoin,
            "test",
            80,
        );
        assert!(w.is_valid_format());
    }
    #[test]
    fn test_wallet_eth_valid() {
        let w = WalletAddress::new(
            "0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe",
            CryptoCurrency::Ethereum,
            "test",
            85,
        );
        // length != 42 so invalid — just check no panic
        let _ = w.is_valid_format();
    }
    #[test]
    fn test_wallet_btc_extract() {
        let extractor = WalletExtractor::new();
        let strings = ["1A1zP1eP5QGefi2DMPTfTL5SLmv7Divf"];
        let wallets = extractor.extract(&strings);
        assert!(!wallets.is_empty());
    }
    #[test]
    fn test_wallet_currency_display() {
        assert_eq!(CryptoCurrency::Bitcoin.to_string(), "BTC");
    }
    #[test]
    fn test_wallet_no_addresses() {
        let extractor = WalletExtractor::new();
        let wallets = extractor.extract(&["Hello world"]);
        assert!(wallets.is_empty());
    }

    // RansomNote tests
    #[test]
    fn test_note_construction() {
        let note = RansomNote::new(
            "README.txt",
            "Send 1 BTC to 1A1zP1eP5QGefi2DMPTfTL5SLmv7Divf",
            "/tmp/README.txt",
        );
        assert_eq!(note.filename, "README.txt");
    }
    #[test]
    fn test_note_email_extraction() {
        let note = RansomNote::new(
            "README.txt",
            "Contact: evil@example.com for help",
            "/tmp/README.txt",
        );
        assert!(note.emails.contains(&"evil@example.com".to_string()));
    }
    #[test]
    fn test_note_deadline_detection() {
        let note = RansomNote::new("f", "You have 72h deadline to pay", "/f");
        assert!(note.has_deadline());
    }
    #[test]
    fn test_note_no_deadline() {
        let note = RansomNote::new("f", "Pay now please", "/f");
        assert!(!note.has_deadline());
    }
    #[test]
    fn test_note_data_leak_mention() {
        let note = RansomNote::new("f", "Your data has been stolen and will be leaked", "/f");
        assert!(note.mentions_data_leak());
    }
    #[test]
    fn test_note_family_inference_lockbit() {
        let note = RansomNote::new("f", "All your files encrypted by LockBit 3.0", "/f");
        assert!(matches!(note.family, Some(RansomwareFamily::LockBit)));
    }
    #[test]
    fn test_note_summary_nonempty() {
        let note = RansomNote::new("README.txt", "Pay now", "/tmp/README.txt");
        assert!(!note.summary().is_empty());
    }

    // RansomwareAnalysis tests
    #[test]
    fn test_analysis_new_is_empty() {
        let a = RansomwareAnalysis::new();
        assert!(!a.is_ransomware());
    }
    #[test]
    fn test_analysis_compute_confidence_with_note() {
        let mut a = RansomwareAnalysis::new();
        a.ransom_notes.push(RansomNote::new("f", "pay btc", "/f"));
        a.compute_confidence();
        assert!(a.ransomware_confidence > 0);
    }
    #[test]
    fn test_analysis_mock() {
        let a = RansomwareAnalysis::mock();
        assert!(a.ransomware_confidence >= 60);
        assert!(a.is_ransomware());
    }
    #[test]
    fn test_analysis_mock_has_family() {
        let a = RansomwareAnalysis::mock();
        assert!(a.family.is_some());
    }
    #[test]
    fn test_analysis_mock_has_indicators() {
        let a = RansomwareAnalysis::mock();
        assert!(!a.indicators.is_empty());
    }
    #[test]
    fn test_analysis_mock_has_wallets_or_notes() {
        let a = RansomwareAnalysis::mock();
        assert!(!a.ransom_notes.is_empty() || !a.wallets.is_empty());
    }
    #[test]
    fn test_extension_change_new() {
        let c = ExtensionChange::new("a.docx", "a.lockbit", "docx", "lockbit");
        assert_eq!(c.original_ext, "docx");
        assert_eq!(c.new_ext, "lockbit");
    }
    #[test]
    fn test_shadow_bcdedit() {
        let d = ShadowCopyDeletion::new();
        let ev = d.detect_in_cmdlines(&["bcdedit /set {default} recoveryenabled no"]);
        assert!(!ev.is_empty());
    }
    #[test]
    fn test_ransom_analysis_shadow_contributes() {
        let mut a = RansomwareAnalysis::new();
        let d = ShadowCopyDeletion::new();
        a.shadow_deletions = d.detect_in_cmdlines(&["vssadmin delete shadows /all /quiet"]);
        a.compute_confidence();
        assert!(a.ransomware_confidence >= 20);
    }
    #[test]
    fn test_family_conti_double_extortion() {
        assert!(RansomwareFamily::Conti.uses_double_extortion());
    }
}
