// rustre-emu-shellcode/src/shellcode_classifier.rs
//
// Shellcode classification: type, platform, encoding, framework patterns.
// Identifies bind/reverse shell, download-and-exec, process injection,
// reflective DLL, Metasploit stager, Cobalt Strike beacon, shikata-ga-nai.



// ─── Classification results ───────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShellcodeType {
    BindShell,
    ReverseShell,
    DownloadAndExec,
    PrivilegeEscalation,
    ProcessInjection,
    ReflectiveDll,
    PositionIndependent,
    ApiHashing,
    Dropper,
    Loader,
    Unknown,
}

impl ShellcodeType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::BindShell           => "bind_shell",
            Self::ReverseShell        => "reverse_shell",
            Self::DownloadAndExec     => "download_and_exec",
            Self::PrivilegeEscalation => "privilege_escalation",
            Self::ProcessInjection    => "process_injection",
            Self::ReflectiveDll       => "reflective_dll",
            Self::PositionIndependent => "position_independent",
            Self::ApiHashing          => "api_hashing",
            Self::Dropper             => "dropper",
            Self::Loader              => "loader",
            Self::Unknown             => "unknown",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShellcodePlatform {
    Windows32,
    Windows64,
    Linux32,
    Linux64,
    MacOS32,
    MacOS64,
    Generic,
    Unknown,
}

impl ShellcodePlatform {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Windows32 => "windows_x86",
            Self::Windows64 => "windows_x64",
            Self::Linux32   => "linux_x86",
            Self::Linux64   => "linux_x64",
            Self::MacOS32   => "macos_x86",
            Self::MacOS64   => "macos_x64",
            Self::Generic   => "generic",
            Self::Unknown   => "unknown",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShellcodeEncoding {
    Raw,
    Xor,
    ShikataGaNai,
    AlphaUpper,
    AlphaLower,
    Unicode,
    Base64Like,
    Custom,
    Unknown,
}

impl ShellcodeEncoding {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Raw          => "raw",
            Self::Xor          => "xor",
            Self::ShikataGaNai => "shikata_ga_nai",
            Self::AlphaUpper   => "alpha_upper",
            Self::AlphaLower   => "alpha_lower",
            Self::Unicode      => "unicode",
            Self::Base64Like   => "base64_like",
            Self::Custom       => "custom",
            Self::Unknown      => "unknown",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrameworkPattern {
    Metasploit,
    CobaltStrike,
    Sliver,
    Havoc,
    Custom,
    None,
}

impl FrameworkPattern {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Metasploit   => "metasploit",
            Self::CobaltStrike => "cobalt_strike",
            Self::Sliver       => "sliver",
            Self::Havoc        => "havoc",
            Self::Custom       => "custom",
            Self::None         => "none",
        }
    }
}

// ─── Classification result ────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ClassificationResult {
    pub shellcode_type: ShellcodeType,
    pub platform:       ShellcodePlatform,
    pub encoding:       ShellcodeEncoding,
    pub framework:      FrameworkPattern,
    pub confidence:     f32,
    pub evidence:       Vec<String>,
    pub size:           usize,
    pub entropy:        f64,
}

impl ClassificationResult {
    pub fn unknown(size: usize) -> Self {
        Self {
            shellcode_type: ShellcodeType::Unknown,
            platform: ShellcodePlatform::Unknown,
            encoding: ShellcodeEncoding::Unknown,
            framework: FrameworkPattern::None,
            confidence: 0.0,
            evidence: Vec::new(),
            size,
            entropy: 0.0,
        }
    }

    pub fn is_likely_malicious(&self) -> bool {
        self.confidence >= 0.5
            && !matches!(self.shellcode_type, ShellcodeType::Unknown | ShellcodeType::PositionIndependent)
    }

    pub fn summary(&self) -> String {
        format!(
            "type={} platform={} encoding={} framework={} confidence={:.1}%",
            self.shellcode_type.as_str(),
            self.platform.as_str(),
            self.encoding.as_str(),
            self.framework.as_str(),
            self.confidence * 100.0
        )
    }
}

// ─── Known byte signatures ────────────────────────────────────────────────────

// Metasploit x64 stager prologue
const MSF_REV_SHELL_X64:  &[u8] = &[0xFC, 0x48, 0x83, 0xE4, 0xF0, 0xE8];
// Metasploit x86 stager prologue
const MSF_X86_STAGER:     &[u8] = &[0xFC, 0xE8, 0x82, 0x00, 0x00, 0x00];
// Shikata ga Nai FPU decoder stub
const SHIKATA_FPU:        &[u8] = &[0xD9, 0x74, 0x24, 0xF4];
const SHIKATA_ALT:        &[u8] = &[0xD9, 0xEB];
// Cobalt Strike beacon prologue
const CS_BEACON:          &[u8] = &[0xFC, 0x48, 0x83, 0xE4, 0xF0, 0xE8, 0xC0, 0x00, 0x00, 0x00];
// MZ header
const MZ_HEADER:          &[u8] = b"MZ";
// Linux /bin/sh
const BIN_SH:             &[u8] = b"/bin/sh";
const BIN_BASH:           &[u8] = b"/bin/bash";
// HTTP/HTTPS download
const URL_HTTP:           &[u8] = b"http://";
const URL_HTTPS:          &[u8] = b"https://";
// cmd.exe
const CMD_EXE:            &[u8] = b"cmd.exe";
const CMD_NUL:            &[u8] = &[0x63, 0x6D, 0x64, 0x00]; // "cmd\0"
// Windows ROR13 API hash loop markers
const ROR13_LOOP:         &[u8] = &[0xC1, 0xCF, 0x0D]; // ror edi, 13
const ROR13_EAX:          &[u8] = &[0xC1, 0xC8, 0x0D]; // ror eax, 13
// Process injection Windows APIs (hashes / patterns)
const VIRTUAL_ALLOC_EX:  &[u8] = b"VirtualAllocEx";
const WRITE_PROC_MEM:    &[u8] = b"WriteProcessMemory";
const CREATE_REMOTE_THR: &[u8] = b"CreateRemoteThread";
const PUSH_PAGE_RWX:     &[u8] = &[0x6A, 0x40]; // push PAGE_EXECUTE_READWRITE
// Syscall / int 0x80
const LINUX_INT80:        &[u8] = &[0xCD, 0x80];
const X64_SYSCALL:        &[u8] = &[0x0F, 0x05];
// WinSock
const WINSOCK_INIT:       &[u8] = &[0x02, 0x02]; // WSAStartup version 2.2
// Socket connect stub (push ip:port)
const PUSH_PORT_PATTERN:  &[u8] = &[0x68, 0x02]; // push 0x02?? (sin_family + port)
// Bind shell listen pattern (push SOMAXCONN)
const LISTEN_SOMAXCONN:  &[u8] = &[0x6A, 0x7F]; // push 127

// ─── Classifier ───────────────────────────────────────────────────────────────

pub struct ShellcodeClassifier;

impl ShellcodeClassifier {
    pub fn classify(data: &[u8]) -> ClassificationResult {
        let mut result = ClassificationResult::unknown(data.len());
        result.entropy = compute_entropy(data);

        result.framework  = Self::detect_framework(data, &mut result.evidence);
        result.encoding   = Self::detect_encoding(data, &mut result.evidence);
        result.platform   = Self::detect_platform(data, &mut result.evidence);
        result.shellcode_type = Self::detect_type(data, &result.framework, &result.platform, &mut result.evidence);
        result.confidence = Self::compute_confidence(&result);
        result
    }

    fn detect_framework(data: &[u8], evidence: &mut Vec<String>) -> FrameworkPattern {
        if scan(data, CS_BEACON).is_some() {
            evidence.push("cobalt_strike: beacon prologue matched".to_string());
            return FrameworkPattern::CobaltStrike;
        }
        if scan(data, MSF_REV_SHELL_X64).is_some() {
            evidence.push("metasploit: x64 stager prologue FC 48 83 E4 F0 E8".to_string());
            return FrameworkPattern::Metasploit;
        }
        if scan(data, MSF_X86_STAGER).is_some() {
            evidence.push("metasploit: x86 stager prologue FC E8 82 00 00 00".to_string());
            return FrameworkPattern::Metasploit;
        }
        if scan(data, SHIKATA_FPU).is_some() || scan(data, SHIKATA_ALT).is_some() {
            evidence.push("metasploit: shikata_ga_nai FPU stub detected".to_string());
            return FrameworkPattern::Metasploit;
        }
        // Sliver/Havoc: no reliable byte signature without full decryption
        FrameworkPattern::None
    }

    fn detect_encoding(data: &[u8], evidence: &mut Vec<String>) -> ShellcodeEncoding {
        // Shikata: FPU instruction present
        if scan(data, SHIKATA_FPU).is_some() || scan(data, SHIKATA_ALT).is_some() {
            evidence.push("shikata_ga_nai: fnstenv poly stub".to_string());
            return ShellcodeEncoding::ShikataGaNai;
        }
        // Alpha uppercase: ≥90% of bytes are A-Z, digits, or +%/-
        let alpha_count = data.iter().filter(|&&b| {
            b.is_ascii_uppercase() || b.is_ascii_digit() || matches!(b, b'+' | b'%' | b'/' | b'-')
        }).count();
        if data.len() > 16 && alpha_count as f32 / data.len() as f32 > 0.90 {
            evidence.push("alpha_upper: >90% bytes in printable upper-alpha range".to_string());
            return ShellcodeEncoding::AlphaUpper;
        }
        // Unicode: every other byte is 0x00
        if data.len() >= 8 {
            let null_odd = data.iter().enumerate()
                .filter(|&(i, &b)| i % 2 == 1 && b == 0).count();
            if null_odd as f32 / (data.len() / 2) as f32 > 0.80 {
                evidence.push("unicode: high null interleave (UTF-16LE pattern)".to_string());
                return ShellcodeEncoding::Unicode;
            }
        }
        // XOR: mid-range entropy with detectable key
        let ent = compute_entropy(data);
        if ent > 5.5 && ent < 7.6 {
            if let Some(key) = detect_xor_key(data) {
                evidence.push(format!("xor: likely single-byte key {:#04x}", key));
                return ShellcodeEncoding::Xor;
            }
        }
        // Raw: identifiable prologues or low entropy
        if ent < 5.5 || data.first() == Some(&0xFC) || data.first() == Some(&0x64) {
            return ShellcodeEncoding::Raw;
        }
        ShellcodeEncoding::Unknown
    }

    fn detect_platform(data: &[u8], evidence: &mut Vec<String>) -> ShellcodePlatform {
        // Windows x64: stack alignment prefix
        if data.len() >= 3 && data[0] == 0xFC && data[1] == 0x48 && data[2] == 0x83 {
            evidence.push("platform: windows_x64 (stack alignment prologue)".to_string());
            return ShellcodePlatform::Windows64;
        }
        // Windows x86: common stager start
        if data.len() >= 2 && data[0] == 0xFC && data[1] == 0xE8 {
            evidence.push("platform: windows_x86".to_string());
            return ShellcodePlatform::Windows32;
        }
        // Linux x64: syscall instruction
        if scan(data, X64_SYSCALL).is_some() && scan(data, BIN_SH).is_none() {
            evidence.push("platform: linux_x64 (syscall instruction)".to_string());
            return ShellcodePlatform::Linux64;
        }
        // Linux x86: int 0x80
        if scan(data, LINUX_INT80).is_some() {
            evidence.push("platform: linux_x86 (int 0x80)".to_string());
            return ShellcodePlatform::Linux32;
        }
        // macOS: BSD syscall base 0x2000000
        if scan(data, &[0x00, 0x00, 0x20, 0x00, 0x00]).is_some()
            && scan(data, X64_SYSCALL).is_some()
        {
            evidence.push("platform: macos_x64 (BSD syscall + 0x2000000 offset)".to_string());
            return ShellcodePlatform::MacOS64;
        }
        // Fallback: MZ header = Windows
        if scan(data, MZ_HEADER).is_some() {
            return ShellcodePlatform::Windows64;
        }
        ShellcodePlatform::Unknown
    }

    fn detect_type(data: &[u8], fw: &FrameworkPattern, _platform: &ShellcodePlatform,
                   evidence: &mut Vec<String>) -> ShellcodeType {
        // CobbaltStrike → loader
        if *fw == FrameworkPattern::CobaltStrike {
            evidence.push("type: loader (cobalt strike beacon)".to_string());
            return ShellcodeType::Loader;
        }

        // Reflective DLL: MZ header in payload
        if data.len() >= 2 && &data[..2] == MZ_HEADER {
            evidence.push("type: reflective_dll (MZ header)".to_string());
            return ShellcodeType::ReflectiveDll;
        }

        // Process injection markers
        if scan(data, VIRTUAL_ALLOC_EX).is_some()
            || scan(data, WRITE_PROC_MEM).is_some()
            || scan(data, CREATE_REMOTE_THR).is_some()
        {
            evidence.push("type: process_injection (VirtualAllocEx/WriteProcessMemory string found)".to_string());
            return ShellcodeType::ProcessInjection;
        }
        // push PAGE_EXECUTE_READWRITE (0x40) pattern often in inject stubs
        if scan(data, PUSH_PAGE_RWX).is_some() && !evidence.is_empty() {
            evidence.push("type: process_injection (PAGE_EXECUTE_READWRITE push)".to_string());
            return ShellcodeType::ProcessInjection;
        }

        // Download and execute
        if scan(data, URL_HTTP).is_some() || scan(data, URL_HTTPS).is_some() {
            if scan(data, BIN_SH).is_some() || scan(data, CMD_EXE).is_some() || scan(data, CMD_NUL).is_some() {
                evidence.push("type: download_and_exec (HTTP + shell/cmd)".to_string());
                return ShellcodeType::DownloadAndExec;
            }
            evidence.push("type: download_and_exec (HTTP URL present)".to_string());
            return ShellcodeType::DownloadAndExec;
        }

        // Bind shell
        let has_socket = scan(data, WINSOCK_INIT).is_some() || scan(data, LINUX_INT80).is_some()
            || scan(data, X64_SYSCALL).is_some();
        let has_bind   = scan(data, LISTEN_SOMAXCONN).is_some();
        let has_exec   = scan(data, BIN_SH).is_some() || scan(data, BIN_BASH).is_some()
            || scan(data, CMD_EXE).is_some();
        let has_connect = scan(data, PUSH_PORT_PATTERN).is_some();

        if has_bind && has_socket {
            evidence.push("type: bind_shell (listen + socket pattern)".to_string());
            return ShellcodeType::BindShell;
        }
        if has_connect && has_socket && has_exec {
            evidence.push("type: reverse_shell (connect + exec pattern)".to_string());
            return ShellcodeType::ReverseShell;
        }

        // API hashing
        if detect_api_hashing(data) {
            evidence.push("type: api_hashing (ROR13 loop detected)".to_string());
            return ShellcodeType::ApiHashing;
        }

        // PIC: starts with CALL/JMP to self (common PIC technique)
        if data.len() >= 5 && data[0] == 0xE8 && data[1] == 0x00 && data[2] == 0x00
            && data[3] == 0x00 && data[4] == 0x00
        {
            evidence.push("type: position_independent (CALL+0 PIC prologue)".to_string());
            return ShellcodeType::PositionIndependent;
        }

        ShellcodeType::Unknown
    }

    fn compute_confidence(r: &ClassificationResult) -> f32 {
        let base = match r.shellcode_type {
            ShellcodeType::Unknown => 0.1,
            _ => 0.5,
        };
        let enc_bonus = match r.encoding {
            ShellcodeEncoding::Unknown | ShellcodeEncoding::Raw => 0.0,
            _ => 0.15,
        };
        let fw_bonus = match r.framework {
            FrameworkPattern::None => 0.0,
            _ => 0.2,
        };
        let evidence_bonus = (r.evidence.len() as f32 * 0.05).min(0.15);
        (base + enc_bonus + fw_bonus + evidence_bonus).min(1.0)
    }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

pub fn compute_entropy(data: &[u8]) -> f64 {
    if data.is_empty() { return 0.0; }
    let mut freq = [0u64; 256];
    for &b in data { freq[b as usize] += 1; }
    let n = data.len() as f64;
    freq.iter().filter(|&&c| c > 0).fold(0.0, |acc, &c| {
        let p = c as f64 / n;
        acc - p * p.log2()
    })
}

pub fn scan(data: &[u8], pattern: &[u8]) -> Option<usize> {
    if pattern.is_empty() || data.len() < pattern.len() { return None; }
    data.windows(pattern.len()).position(|w| w == pattern)
}

pub fn detect_xor_key(data: &[u8]) -> Option<u8> {
    if data.len() < 8 { return None; }
    let mut freq = [0u32; 256];
    for &b in data { freq[b as usize] += 1; }
    let (max_byte, _) = freq.iter().enumerate()
        .max_by_key(|&(_, &c)| c)?;
    let key = max_byte as u8 ^ 0x00;
    if key == 0 { Some(max_byte as u8 ^ 0x90) } else { Some(key) }
}

pub fn detect_api_hashing(data: &[u8]) -> bool {
    if data.len() < 4 { return false; }
    // ROR edi, 13 (0xC1 0xCF 0x0D) or ROR eax, 13 (0xC1 0xC8 0x0D)
    scan(data, ROR13_LOOP).is_some()
        || scan(data, ROR13_EAX).is_some()
        || {
            // Also: D1 CF = ROR edi, 1 in a loop (ROR1 variant)
            data.windows(2).any(|w| w == [0xD1, 0xCF] || w == [0xD1, 0xC8])
        }
}

// ─── Byte statistics ──────────────────────────────────────────────────────────

#[derive(Debug)]
pub struct ByteStats {
    pub freq:  [u32; 256],
    pub total: usize,
}

impl ByteStats {
    pub fn new(data: &[u8]) -> Self {
        let mut freq = [0u32; 256];
        for &b in data { freq[b as usize] += 1; }
        Self { freq, total: data.len() }
    }

    pub fn most_common(&self) -> (u8, u32) {
        let (idx, &cnt) = self.freq.iter().enumerate()
            .max_by_key(|&(_, &c)| c).unwrap();
        (idx as u8, cnt)
    }

    pub fn null_ratio(&self) -> f32 {
        if self.total == 0 { return 0.0; }
        self.freq[0] as f32 / self.total as f32
    }

    pub fn printable_ratio(&self) -> f32 {
        if self.total == 0 { return 0.0; }
        let printable: u32 = self.freq[0x20..0x7F].iter().sum();
        printable as f32 / self.total as f32
    }

    pub fn unique_bytes(&self) -> usize {
        self.freq.iter().filter(|&&c| c > 0).count()
    }

    pub fn entropy(&self) -> f64 {
        let data: Vec<u8> = self.freq.iter().enumerate()
            .flat_map(|(b, &c)| std::iter::repeat(b as u8).take(c as usize))
            .collect();
        compute_entropy(&data)
    }
}

// ─── Multi-stage classifier ───────────────────────────────────────────────────

/// Classify an array of shellcode layers (e.g. after successive decoding).
pub fn classify_layers(layers: &[Vec<u8>]) -> Vec<ClassificationResult> {
    layers.iter().map(|layer| ShellcodeClassifier::classify(layer)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_classify_msf_x64() {
        let sc = &[0xFC_u8, 0x48, 0x83, 0xE4, 0xF0, 0xE8, 0x00, 0x00];
        let r = ShellcodeClassifier::classify(sc);
        assert_eq!(r.framework, FrameworkPattern::Metasploit);
        assert_eq!(r.platform, ShellcodePlatform::Windows64);
    }

    #[test]
    fn test_classify_shikata() {
        let mut sc = vec![0u8; 64];
        sc[0] = 0xD9; sc[1] = 0x74; sc[2] = 0x24; sc[3] = 0xF4;
        let r = ShellcodeClassifier::classify(&sc);
        assert_eq!(r.encoding, ShellcodeEncoding::ShikataGaNai);
        assert_eq!(r.framework, FrameworkPattern::Metasploit);
    }

    #[test]
    fn test_classify_linux_shell() {
        let sc = [0xCD_u8, 0x80, 0x2F, 0x62, 0x69, 0x6E, 0x2F, 0x73, 0x68, 0x00];
        let r = ShellcodeClassifier::classify(&sc);
        assert_eq!(r.platform, ShellcodePlatform::Linux32);
    }

    #[test]
    fn test_classify_reflective_dll() {
        let mut data = b"MZ\x90\x00".to_vec();
        data.extend_from_slice(&[0u8; 60]);
        let r = ShellcodeClassifier::classify(&data);
        assert_eq!(r.shellcode_type, ShellcodeType::ReflectiveDll);
    }

    #[test]
    fn test_classify_download_exec() {
        let mut sc = b"http://evil.com/payload.exe\0".to_vec();
        sc.extend_from_slice(b"cmd.exe");
        let r = ShellcodeClassifier::classify(&sc);
        assert_eq!(r.shellcode_type, ShellcodeType::DownloadAndExec);
    }

    #[test]
    fn test_entropy() {
        let zeros = vec![0u8; 256];
        assert_eq!(compute_entropy(&zeros), 0.0);
        let uniform: Vec<u8> = (0..=255u8).collect();
        assert!((compute_entropy(&uniform) - 8.0).abs() < 0.01);
    }

    #[test]
    fn test_byte_stats() {
        let data = vec![0xAAu8; 100];
        let s = ByteStats::new(&data);
        let (b, c) = s.most_common();
        assert_eq!(b, 0xAA);
        assert_eq!(c, 100);
        assert_eq!(s.unique_bytes(), 1);
    }

    #[test]
    fn test_detect_api_hashing() {
        let mut data = vec![0u8; 32];
        data[5] = 0xC1; data[6] = 0xCF; data[7] = 0x0D;
        assert!(detect_api_hashing(&data));
    }

    #[test]
    fn test_classification_summary() {
        let r = ClassificationResult::unknown(100);
        let s = r.summary();
        assert!(s.contains("unknown"));
    }

    #[test]
    fn test_is_likely_malicious() {
        let mut r = ClassificationResult::unknown(100);
        r.shellcode_type = ShellcodeType::ReverseShell;
        r.confidence = 0.8;
        assert!(r.is_likely_malicious());
    }

    #[test]
    fn test_classify_layers() {
        let layers = vec![
            vec![0xFC_u8, 0x48, 0x83, 0xE4, 0xF0, 0xE8, 0x00, 0x00],
            vec![0x00u8; 32],
        ];
        let results = classify_layers(&layers);
        assert_eq!(results.len(), 2);
    }
}
