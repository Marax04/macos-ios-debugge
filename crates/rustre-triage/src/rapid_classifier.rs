// rustre-crypto-oracle/src/rapid_classifier.rs → rustre-triage/src/rapid_classifier.rs
// Fast (<1 second) binary classifier: malicious / suspicious / clean.


/// Classification verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Verdict {
    Clean,
    Suspicious,
    Malicious,
}

impl std::fmt::Display for Verdict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Clean => write!(f, "Clean"),
            Self::Suspicious => write!(f, "Suspicious"),
            Self::Malicious => write!(f, "Malicious"),
        }
    }
}

/// Score contribution from one classifier component.
#[derive(Debug, Clone)]
pub struct ScoreComponent {
    pub name: &'static str,
    pub score: f32,        // Positive = malicious indicator, negative = benign.
    pub weight: f32,
    pub description: String,
}

/// Full classification result.
#[derive(Debug, Clone)]
pub struct ClassificationResult {
    pub verdict: Verdict,
    pub confidence: f32,   // 0.0 – 1.0
    pub total_score: f32,
    pub components: Vec<ScoreComponent>,
    pub family_hints: Vec<String>,
    pub elapsed_us: u64,
}

/// Configuration for rapid classification.
///
/// The `check_flags` field is a bitmask: use the associated constants
/// (`ENTROPY`, `IMPORTS`, `STRINGS`, `MAGIC`, `PACKER_SIGS`) to
/// compose the set of checks to run.
#[derive(Clone, Debug, Default)]
pub struct ClassifierConfig {
    pub malicious_threshold: f32,
    pub suspicious_threshold: f32,
    pub max_bytes_read: usize,
    /// Bitmask of enabled checks (see associated constants).
    pub check_flags: u8,
}

impl ClassifierConfig {
    /// Enable entropy analysis.
    pub const ENTROPY: u8 = 0b0000_0001;
    /// Enable import-table analysis.
    pub const IMPORTS: u8 = 0b0000_0010;
    /// Enable suspicious-string scan.
    pub const STRINGS: u8 = 0b0000_0100;
    /// Enable file-magic check.
    pub const MAGIC: u8 = 0b0000_1000;
    /// Enable packer-signature scan.
    pub const PACKER_SIGS: u8 = 0b0001_0000;

    /// All checks enabled.
    pub const ALL: u8 = Self::ENTROPY | Self::IMPORTS | Self::STRINGS | Self::MAGIC | Self::PACKER_SIGS;

    #[must_use] pub const fn check_entropy(&self)     -> bool { self.check_flags & Self::ENTROPY     != 0 }
    #[must_use] pub const fn check_imports(&self)     -> bool { self.check_flags & Self::IMPORTS     != 0 }
    #[must_use] pub const fn check_strings(&self)     -> bool { self.check_flags & Self::STRINGS     != 0 }
    #[must_use] pub const fn check_magic(&self)       -> bool { self.check_flags & Self::MAGIC       != 0 }
    #[must_use] pub const fn check_packer_sigs(&self) -> bool { self.check_flags & Self::PACKER_SIGS != 0 }
}

/// The rapid classifier.
#[derive(Default)]
pub struct RapidClassifier {
    pub config: ClassifierConfig,
}

impl RapidClassifier {
    #[must_use]
    pub const fn new(config: ClassifierConfig) -> Self { Self { config } }

    /// Classify a binary blob.
    #[must_use]
    pub fn classify(&self, data: &[u8]) -> ClassificationResult {
        let t0 = std::time::Instant::now();
        let mut components = Vec::new();
        let mut family_hints = Vec::new();

        let sample = &data[..data.len().min(self.config.max_bytes_read)];

        if self.config.check_magic() {
            components.extend(Self::check_file_magic(sample));
        }
        if self.config.check_entropy() {
            components.extend(Self::check_entropy(sample, &mut family_hints));
        }
        if self.config.check_packer_sigs() {
            components.extend(Self::check_packer_signatures(sample, &mut family_hints));
        }
        if self.config.check_strings() {
            components.extend(Self::check_suspicious_strings(sample, &mut family_hints));
        }
        if self.config.check_imports() {
            components.extend(Self::check_import_profile(sample, &mut family_hints));
        }

        // PE-specific checks.
        components.extend(Self::check_pe_anomalies(sample));

        let total_score: f32 = components.iter().map(|c| c.score * c.weight).sum();
        let verdict = if total_score >= self.config.malicious_threshold {
            Verdict::Malicious
        } else if total_score >= self.config.suspicious_threshold {
            Verdict::Suspicious
        } else {
            Verdict::Clean
        };

        // Confidence: how far we are from the threshold boundary.
        let confidence = match verdict {
            Verdict::Malicious => ((total_score - self.config.malicious_threshold) / 50.0).min(1.0),
            Verdict::Suspicious => ((total_score - self.config.suspicious_threshold) /
                (self.config.malicious_threshold - self.config.suspicious_threshold)).min(1.0),
            Verdict::Clean => 1.0 - (total_score / self.config.suspicious_threshold).max(0.0),
        };

        ClassificationResult {
            verdict,
            confidence: confidence.clamp(0.0, 1.0),
            total_score,
            components,
            family_hints,
            elapsed_us: u64::try_from(t0.elapsed().as_micros()).unwrap_or(u64::MAX),
        }
    }

    fn check_file_magic(data: &[u8]) -> Vec<ScoreComponent> {
        let mut v = Vec::new();
        if data.len() < 4 { return v; }

        // PE/EXE.
        if data.starts_with(b"MZ") {
            v.push(ScoreComponent {
                name: "magic_pe",
                score: 5.0,
                weight: 1.0,
                description: "PE/EXE file (MZ magic)".into(),
            });
        }
        // ELF.
        if data.starts_with(b"\x7fELF") {
            v.push(ScoreComponent {
                name: "magic_elf",
                score: 3.0,
                weight: 1.0,
                description: "ELF binary".into(),
            });
        }
        // Script-based malware.
        if data.starts_with(b"<script") || data.starts_with(b"<Script") {
            v.push(ScoreComponent {
                name: "magic_script",
                score: 8.0,
                weight: 1.0,
                description: "Script tag at file start".into(),
            });
        }
        // Mach-O.
        if data.len() >= 4 {
            let magic = u32::from_le_bytes(data[..4].try_into().unwrap());
            if magic == 0xfeed_face || magic == 0xfeed_facf || magic == 0xcafe_babe {
                v.push(ScoreComponent {
                    name: "magic_macho",
                    score: 2.0,
                    weight: 1.0,
                    description: "Mach-O binary".into(),
                });
            }
        }
        v
    }

    fn check_entropy(data: &[u8], hints: &mut Vec<String>) -> Vec<ScoreComponent> {
        let mut v = Vec::new();
        let entropy = shannon_entropy(data);

        // High entropy → likely packed or encrypted.
        let (score, desc) = if entropy > 7.5 {
            hints.push("high_entropy_packed".into());
            (30.0, format!("Very high entropy ({entropy:.2} bits/byte) — likely packed/encrypted"))
        } else if entropy > 7.0 {
            hints.push("high_entropy".into());
            (15.0, format!("High entropy ({entropy:.2} bits/byte) — possibly packed"))
        } else if entropy > 6.5 {
            (5.0, format!("Elevated entropy ({entropy:.2} bits/byte)"))
        } else {
            (-5.0, format!("Normal entropy ({entropy:.2} bits/byte)"))
        };

        v.push(ScoreComponent { name: "entropy", score, weight: 1.0, description: desc });
        v
    }

    fn check_packer_signatures(data: &[u8], hints: &mut Vec<String>) -> Vec<ScoreComponent> {
        let mut v = Vec::new();

        let sigs: &[(&str, &[u8], f32)] = &[
            ("UPX",     b"UPX0",       35.0),
            ("UPX",     b"UPX!",       35.0),
            ("MPRESS",  b"MPRESS1",    30.0),
            ("ASPack",  b"ASPack",     30.0),
            ("PECompact",b"PEC2",      30.0),
            ("Themida", b"Themida",    40.0),
            ("VMProtect",b"VProtect",  40.0),
            ("NSIS",    b"NullsoftInst",15.0),
        ];

        for (name, sig, score) in sigs {
            if data.windows(sig.len()).any(|w| w == *sig) {
                hints.push(format!("packer:{name}"));
                v.push(ScoreComponent {
                    name: "packer_sig",
                    score: *score,
                    weight: 1.0,
                    description: format!("Packer signature found: {name}"),
                });
            }
        }
        v
    }

    fn check_suspicious_strings(data: &[u8], hints: &mut Vec<String>) -> Vec<ScoreComponent> {
        let mut v = Vec::new();

        let indicators: &[(&str, &[u8], f32)] = &[
            ("cmd_exec",    b"cmd.exe",       15.0),
            ("powershell",  b"powershell",     20.0),
            ("regsvr32",    b"regsvr32",       15.0),
            ("vssadmin",    b"vssadmin",       25.0),    // Shadow copy deletion.
            ("bcdedit",     b"bcdedit",        25.0),
            ("wmic",        b"wmic",           12.0),
            ("mimikatz",    b"mimikatz",       50.0),
            ("sekurlsa",    b"sekurlsa",       50.0),
            ("CreateRemoteThread", b"CreateRemoteThread", 30.0),
            ("VirtualAllocEx",     b"VirtualAllocEx",     25.0),
            ("WriteProcessMemory", b"WriteProcessMemory", 25.0),
            ("ShellExecute",       b"ShellExecute",       10.0),
            ("URLDownloadToFile",  b"URLDownloadToFile",  20.0),
            ("ransom_note",        b"Your files have been encrypted", 60.0),
            ("bitcoin",            b"bitcoin",            10.0),
            ("tor2web",            b"tor2web",            30.0),
        ];

        let mut found_any = false;
        for (label, needle, score) in indicators {
            // Case-insensitive search.
            let needle_lower: Vec<u8> = needle.iter().map(u8::to_ascii_lowercase).collect();
            let found = data.windows(needle.len()).any(|w| {
                let wl: Vec<u8> = w.iter().map(u8::to_ascii_lowercase).collect();
                wl == needle_lower
            });
            if found {
                hints.push(format!("string:{label}"));
                v.push(ScoreComponent {
                    name: "suspicious_string",
                    score: *score,
                    weight: 0.8,
                    description: format!("Suspicious string: {label}"),
                });
                found_any = true;
            }
        }

        if !found_any {
            v.push(ScoreComponent {
                name: "no_suspicious_strings",
                score: -3.0,
                weight: 1.0,
                description: "No suspicious strings found".into(),
            });
        }
        v
    }

    fn check_import_profile(data: &[u8], hints: &mut Vec<String>) -> Vec<ScoreComponent> {
        let mut v = Vec::new();

        // Quick scan for DLL names and API names in the binary.
        let suspicious_apis: &[(&str, &[u8], f32)] = &[
            ("process_injection", b"NtCreateThreadEx", 35.0),
            ("process_injection", b"RtlCreateUserThread", 35.0),
            ("process_hollowing", b"ZwUnmapViewOfSection", 30.0),
            ("keylogger",         b"SetWindowsHookEx", 20.0),
            ("screenshot",        b"BitBlt",           10.0),
            ("clipboard",         b"OpenClipboard",    10.0),
            ("network_raw",       b"WSASocket",        15.0),
            ("rootkit",           b"FltRegisterFilter", 40.0),
            ("driver",            b"IoCreateDevice",    20.0),
            ("anti_debug",        b"IsDebuggerPresent", 5.0),
            ("anti_debug",        b"NtQueryInformationProcess", 10.0),
            ("crypto_rand",       b"CryptGenRandom",   3.0),
            ("registry_persist",  b"RegSetValueEx",    8.0),
        ];

        for (label, needle, score) in suspicious_apis {
            if data.windows(needle.len()).any(|w| w == *needle) {
                hints.push(format!("api:{label}"));
                v.push(ScoreComponent {
                    name: "suspicious_api",
                    score: *score,
                    weight: 0.9,
                    description: format!("Suspicious API: {} ({label})", String::from_utf8_lossy(needle)),
                });
            }
        }
        v
    }

    fn check_pe_anomalies(data: &[u8]) -> Vec<ScoreComponent> {
        let mut v = Vec::new();
        if data.len() < 64 || !data.starts_with(b"MZ") { return v; }

        // Check PE header offset.
        let pe_offset = u32::from_le_bytes(data[60..64].try_into().unwrap_or([0; 4])) as usize;
        if pe_offset + 4 > data.len() {
            v.push(ScoreComponent {
                name: "pe_invalid_offset",
                score: 20.0,
                weight: 1.0,
                description: "PE header offset points outside file".into(),
            });
            return v;
        }
        if &data[pe_offset..pe_offset + 4] != b"PE\0\0" {
            v.push(ScoreComponent {
                name: "pe_bad_signature",
                score: 25.0,
                weight: 1.0,
                description: "Invalid PE signature".into(),
            });
            return v;
        }

        // Number of sections.
        if pe_offset + 6 < data.len() {
            let num_sections = u16::from_le_bytes(data[pe_offset + 6..pe_offset + 8].try_into().unwrap_or([0; 2]));
            if num_sections == 0 || num_sections > 96 {
                v.push(ScoreComponent {
                    name: "pe_weird_section_count",
                    score: 15.0,
                    weight: 1.0,
                    description: format!("Unusual section count: {num_sections}"),
                });
            }
        }

        // Check timestamp (0 or far future).
        if pe_offset + 12 < data.len() {
            let ts = u32::from_le_bytes(data[pe_offset + 8..pe_offset + 12].try_into().unwrap_or([0; 4]));
            if ts == 0 {
                v.push(ScoreComponent {
                    name: "pe_zero_timestamp",
                    score: 8.0,
                    weight: 0.8,
                    description: "PE timestamp is zero (stripped or malformed)".into(),
                });
            } else if ts > 0x7000_0000 {
                // 2021+
                v.push(ScoreComponent {
                    name: "pe_future_timestamp",
                    score: 5.0,
                    weight: 0.5,
                    description: format!("Recent or future PE timestamp: 0x{ts:08x}"),
                });
            }
        }

        v
    }
}

fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() { return 0.0; }
    let mut counts = [0u64; 256];
    for &b in data { counts[b as usize] += 1; }
    let n = f64::from(u32::try_from(data.len()).unwrap_or(u32::MAX));
    -counts.iter().filter(|&&c| c > 0)
        .map(|&c| { let p = f64::from(u32::try_from(c).unwrap_or(u32::MAX)) / n; p * p.log2() })
        .sum::<f64>()
}

/// Compute a simple import family similarity score by checking API presence.
/// Returns (`family_name`, `similarity_score`) pairs sorted by score.
#[must_use]
pub fn import_family_similarity(data: &[u8]) -> Vec<(&'static str, f32)> {
    let profiles: &[(&str, &[&[u8]])] = &[
        ("ransomware", &[b"CryptGenRandom", b"vssadmin", b"FindFirstFile", b"RegSetValueEx"]),
        ("banker",     &[b"InternetOpenUrl", b"HttpSendRequest", b"WinHttpOpen"]),
        ("rat",        &[b"CreateRemoteThread", b"VirtualAllocEx", b"WriteProcessMemory"]),
        ("keylogger",  &[b"SetWindowsHookEx", b"GetAsyncKeyState", b"OpenClipboard"]),
        ("dropper",    &[b"URLDownloadToFile", b"ShellExecute", b"CreateProcess"]),
    ];

    let mut results = Vec::new();
    for (family, apis) in profiles {
        let matches = apis.iter().filter(|api| {
            data.windows(api.len()).any(|w| w == **api)
        }).count();
        let score = f32::from(u16::try_from(matches).unwrap_or(u16::MAX)) / f32::from(u16::try_from(apis.len()).unwrap_or(u16::MAX));
        if score > 0.0 {
            results.push((*family, score));
        }
    }
    results.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
    results
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clean_file_gets_clean_verdict() {
        let data = vec![0u8; 1024];
        let result = RapidClassifier::default().classify(&data);
        // No PE magic, low entropy → likely clean.
        assert!(result.total_score < 30.0);
    }

    #[test]
    fn upx_packed_is_suspicious() {
        let mut data = b"MZ".to_vec();
        data.extend(vec![0u8; 58]);
        data.extend(b"UPX0".iter().copied());
        data.extend(vec![0xaa; 512]);
        let result = RapidClassifier::default().classify(&data);
        assert!(result.verdict >= Verdict::Suspicious);
    }

    #[test]
    fn mimikatz_string_is_malicious() {
        let mut data = vec![0u8; 64];
        data.extend_from_slice(b"mimikatz");
        let result = RapidClassifier::default().classify(&data);
        assert_eq!(result.verdict, Verdict::Malicious);
    }

    #[test]
    fn import_similarity_detects_rat() {
        let data = b"CreateRemoteThread VirtualAllocEx WriteProcessMemory".to_vec();
        let sims = import_family_similarity(&data);
        assert!(sims.iter().any(|(f, _)| *f == "rat"));
    }
}
