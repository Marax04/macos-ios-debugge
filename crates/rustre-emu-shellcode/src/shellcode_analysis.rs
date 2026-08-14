//! Static shellcode profiling — architecture detection, technique identification,
//! XOR-loop decoding, and network indicator extraction.

// ── Architecture ──────────────────────────────────────────────────────────────

/// CPU architecture of a shellcode sample.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShellcodeArch {
    X86_32,
    X86_64,
    Arm32,
    Arm64,
    Unknown,
}

impl std::fmt::Display for ShellcodeArch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::X86_32 => write!(f, "x86-32"),
            Self::X86_64 => write!(f, "x86-64"),
            Self::Arm32 => write!(f, "ARM32"),
            Self::Arm64 => write!(f, "ARM64"),
            Self::Unknown => write!(f, "unknown"),
        }
    }
}

// ── Probable OS ───────────────────────────────────────────────────────────────

/// Probable operating-system target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbableOs {
    Windows,
    Linux,
    MacOs,
    Unknown,
}

impl std::fmt::Display for ProbableOs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Windows => write!(f, "Windows"),
            Self::Linux => write!(f, "Linux"),
            Self::MacOs => write!(f, "macOS"),
            Self::Unknown => write!(f, "unknown"),
        }
    }
}

// ── Shellcode type ────────────────────────────────────────────────────────────

/// High-level behavioural classification of a shellcode sample.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShellcodeType {
    Bind,
    Reverse,
    DownloadExecute,
    EggHunter,
    Stager,
    Loader,
    Injector,
    Unknown,
}

impl std::fmt::Display for ShellcodeType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Bind => write!(f, "bind-shell"),
            Self::Reverse => write!(f, "reverse-shell"),
            Self::DownloadExecute => write!(f, "download-and-execute"),
            Self::EggHunter => write!(f, "egg-hunter"),
            Self::Stager => write!(f, "stager"),
            Self::Loader => write!(f, "loader"),
            Self::Injector => write!(f, "injector"),
            Self::Unknown => write!(f, "unknown"),
        }
    }
}

// ── Technique ─────────────────────────────────────────────────────────────────

/// Low-level techniques detected in shellcode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShellcodeTechnique {
    GetPcThunk,
    PebWalk,
    HashApiResolution,
    XorDecoding,
    Base64,
    StackStrings,
    IndirectSyscall,
    CallbackExecution,
    Rop,
    Syswhispers,
}

impl std::fmt::Display for ShellcodeTechnique {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::GetPcThunk => write!(f, "GetPC-thunk"),
            Self::PebWalk => write!(f, "PEB-walk"),
            Self::HashApiResolution => write!(f, "hash-API-resolution"),
            Self::XorDecoding => write!(f, "XOR-decoding"),
            Self::Base64 => write!(f, "Base64"),
            Self::StackStrings => write!(f, "stack-strings"),
            Self::IndirectSyscall => write!(f, "indirect-syscall"),
            Self::CallbackExecution => write!(f, "callback-execution"),
            Self::Rop => write!(f, "ROP"),
            Self::Syswhispers => write!(f, "SysWhispers"),
        }
    }
}

// ── Decoded payload ───────────────────────────────────────────────────────────

/// A decoded embedded payload found in shellcode.
#[derive(Debug, Clone)]
pub struct DecodedPayload {
    pub offset: usize,
    pub size: usize,
    pub key: Vec<u8>,
    pub algorithm: String,
    pub data: Vec<u8>,
}

// ── Shellcode profile ─────────────────────────────────────────────────────────

/// Complete analysis profile for a shellcode sample.
#[derive(Debug, Clone)]
pub struct ShellcodeProfile {
    pub arch: ShellcodeArch,
    pub probable_os: ProbableOs,
    pub shellcode_type: ShellcodeType,
    pub techniques: Vec<ShellcodeTechnique>,
    pub decoded_payloads: Vec<DecodedPayload>,
    pub network_indicators: Vec<String>,
    pub file_indicators: Vec<String>,
    pub api_call_log: Vec<String>,
    pub size: usize,
}

// ── Analyser ──────────────────────────────────────────────────────────────────

/// Performs static analysis on raw shellcode bytes.
pub struct ShellcodeAnalyzer;

impl ShellcodeAnalyzer {
    #[must_use] 
    pub const fn new() -> Self {
        Self
    }

    /// Run a full analysis pass and return a [`ShellcodeProfile`].
    #[must_use] 
    pub fn analyze(&self, data: &[u8], _base: u64) -> ShellcodeProfile {
        let arch = self.detect_arch(data);
        let techniques = self.detect_techniques(data);
        let probable_os = self.detect_os(data, &techniques);
        let decoded_payloads = self.find_xor_loops(data);
        let network_indicators = self.extract_network_indicators(data);
        let file_indicators = self.extract_file_indicators(data);
        let shellcode_type = self.classify_type(data, &techniques, &network_indicators);

        ShellcodeProfile {
            arch,
            probable_os,
            shellcode_type,
            techniques,
            decoded_payloads,
            network_indicators,
            file_indicators,
            api_call_log: Vec::new(),
            size: data.len(),
        }
    }

    // ── Architecture detection ────────────────────────────────────────────────

    /// Detect the most likely CPU architecture by scanning heuristics.
    #[must_use] 
    pub fn detect_arch(&self, data: &[u8]) -> ShellcodeArch {
        if data.len() < 4 {
            return ShellcodeArch::Unknown;
        }

        // ARM64: common prologue `STP X29, X30, [SP, -N]!`
        // Encoded as 0xA9_BF_7B_FD in little-endian
        if data.len() >= 4 {
            for w in data.windows(4) {
                let v = u32::from_le_bytes([w[0], w[1], w[2], w[3]]);
                if v == 0xA9BF7BFD {
                    return ShellcodeArch::Arm64;
                }
            }
        }

        // ARM32: `PUSH {FP, LR}` = 0xE9 2D 48 00 in LE
        if data.len() >= 4 {
            for w in data.windows(4) {
                let v = u32::from_le_bytes([w[0], w[1], w[2], w[3]]);
                if v == 0xE92D4800 {
                    return ShellcodeArch::Arm32;
                }
            }
        }

        // x86-64: REX prefixes in first 32 bytes
        let scan_len = data.len().min(32);
        let rex_count = data[..scan_len]
            .iter()
            .filter(|&&b| (0x48..=0x4F).contains(&b))
            .count();
        if rex_count >= 2 {
            return ShellcodeArch::X86_64;
        }

        // x86-32: PUSH EBP; MOV EBP, ESP  (55 89 E5)
        if data.windows(3).any(|w| w == [0x55, 0x89, 0xE5]) {
            return ShellcodeArch::X86_32;
        }
        // MOV EDI, EDI prologue (8B FF)
        if data.windows(2).any(|w| w == [0x8B, 0xFF]) {
            return ShellcodeArch::X86_32;
        }

        ShellcodeArch::Unknown
    }

    // ── Technique detection ───────────────────────────────────────────────────

    /// Detect known shellcode techniques by pattern scanning.
    #[must_use] 
    pub fn detect_techniques(&self, data: &[u8]) -> Vec<ShellcodeTechnique> {
        let mut out = Vec::new();

        // GetPC thunk: E8 00 00 00 00 followed by 58–5F (POP reg)
        if data.windows(6).any(|w| {
            w[0] == 0xE8
                && w[1] == 0x00
                && w[2] == 0x00
                && w[3] == 0x00
                && w[4] == 0x00
                && (0x58..=0x5F).contains(&w[5])
        }) {
            out.push(ShellcodeTechnique::GetPcThunk);
        }

        // XOR decoding loop: look for XOR [ESI+ECX] or simple XOR patterns
        if (data.windows(3).any(|w| w == [0x30, 0x04, 0x0E])
            || data
                .windows(2)
                .any(|w| w[0] == 0x30 && (w[1] & 0xC7) == 0x04))
            && !out.contains(&ShellcodeTechnique::XorDecoding) {
                out.push(ShellcodeTechnique::XorDecoding);
            }
        // Also detect single-byte XOR key loops more broadly
        if self.has_xor_loop_heuristic(data) && !out.contains(&ShellcodeTechnique::XorDecoding) {
            out.push(ShellcodeTechnique::XorDecoding);
        }

        // PEB walk: MOV EAX, FS:[30h]  (64 A1 30 00 00 00)
        if data.windows(4).any(|w| w == [0x64, 0xA1, 0x30, 0x00]) {
            out.push(ShellcodeTechnique::PebWalk);
        }
        // GS:[60h] for x64 PEB: 65 48 8B ... 60
        if data
            .windows(3)
            .any(|w| w[0] == 0x65 && w[1] == 0x48 && w[2] == 0x8B)
            && !out.contains(&ShellcodeTechnique::PebWalk) {
                out.push(ShellcodeTechnique::PebWalk);
            }

        // Hash API resolution: ROR 13 — C1 C8 0D or C1 CF 0D
        if data
            .windows(3)
            .any(|w| w[0] == 0xC1 && (w[1] == 0xC8 || w[1] == 0xCF) && w[2] == 0x0D)
        {
            out.push(ShellcodeTechnique::HashApiResolution);
        }

        // Stack strings: 5+ consecutive PUSH imm32/imm8 instructions
        let push_count = data
            .windows(2)
            .filter(|w| w[0] == 0x6A || w[0] == 0x68)
            .count();
        if push_count >= 5 {
            out.push(ShellcodeTechnique::StackStrings);
        }

        // Indirect syscall / direct SYSCALL (0F 05)
        if data.windows(2).any(|w| w == [0x0F, 0x05]) {
            out.push(ShellcodeTechnique::IndirectSyscall);
        }

        // Base64 alphabet detection (large run of base64 chars)
        if self.has_base64_blob(data) {
            out.push(ShellcodeTechnique::Base64);
        }

        out
    }

    // ── XOR loop decoder ──────────────────────────────────────────────────────

    /// Scan for XOR decode loops and return decoded payloads.
    #[must_use] 
    pub fn find_xor_loops(&self, data: &[u8]) -> Vec<DecodedPayload> {
        let mut payloads = Vec::new();

        // Strategy: try all single-byte XOR keys on windows of data.
        // Heuristic: a decoded window is interesting if it contains
        // MZ header, ELF magic, or a high ratio of printable ASCII.
        for key in 0x01u8..=0xFE {
            // Scan for a long run that looks like code after XOR.
            let window_size = data.len().min(1024);
            if window_size < 16 {
                break;
            }

            let decoded: Vec<u8> = data[..window_size].iter().map(|&b| b ^ key).collect();

            // Check for MZ header
            if decoded.starts_with(b"MZ") || decoded.starts_with(b"\x7fELF") {
                payloads.push(DecodedPayload {
                    offset: 0,
                    size: window_size,
                    key: vec![key],
                    algorithm: "XOR".to_string(),
                    data: decoded,
                });
                break; // stop at first match
            }
        }

        payloads
    }

    // ── Network indicator extraction ──────────────────────────────────────────

    /// Extract IP:port patterns and URLs from data.
    #[must_use] 
    pub fn extract_network_indicators(&self, data: &[u8]) -> Vec<String> {
        let mut indicators = Vec::new();

        // Collect printable ASCII runs
        let text = self.extract_ascii(data, 6);

        for s in &text {
            // http:// or https://
            if s.starts_with("http://") || s.starts_with("https://") {
                indicators.push(s.clone());
                continue;
            }
            // Very basic IP:port pattern heuristic
            if self.looks_like_ip_port(s) {
                indicators.push(s.clone());
            }
        }

        indicators.sort();
        indicators.dedup();
        indicators
    }

    // ── OS detection ─────────────────────────────────────────────────────────

    /// Infer probable target OS from techniques and byte patterns.
    #[must_use] 
    pub fn detect_os(&self, data: &[u8], techniques: &[ShellcodeTechnique]) -> ProbableOs {
        if techniques.contains(&ShellcodeTechnique::PebWalk)
            || techniques.contains(&ShellcodeTechnique::HashApiResolution)
        {
            return ProbableOs::Windows;
        }

        // Linux syscall numbers common in shellcode: execve=59(0x3B), socket=41, connect=42
        let linux_syscalls: &[u8] = &[0x3B, 0x29, 0x2A, 0x2C];
        // Pattern: MOV EAX/RAX, syscall_num near SYSCALL (0F 05)
        if data.windows(2).any(|w| w == [0x0F, 0x05]) {
            for w in data.windows(7) {
                if w[0] == 0xB8 && linux_syscalls.contains(&w[1]) {
                    return ProbableOs::Linux;
                }
            }
        }

        // INT 0x80 — classic Linux 32-bit
        if data.windows(2).any(|w| w == [0xCD, 0x80]) {
            return ProbableOs::Linux;
        }

        ProbableOs::Unknown
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    fn classify_type(
        &self,
        _data: &[u8],
        techniques: &[ShellcodeTechnique],
        network_indicators: &[String],
    ) -> ShellcodeType {
        if !network_indicators.is_empty() {
            return ShellcodeType::Reverse;
        }
        if techniques.contains(&ShellcodeTechnique::XorDecoding) {
            return ShellcodeType::Loader;
        }
        ShellcodeType::Unknown
    }

    fn extract_file_indicators(&self, data: &[u8]) -> Vec<String> {
        let mut out = Vec::new();
        for s in self.extract_ascii(data, 6) {
            if std::path::Path::new(&s).extension().is_some_and(|e| e.eq_ignore_ascii_case("exe"))
                || std::path::Path::new(&s).extension().is_some_and(|e| e.eq_ignore_ascii_case("dll"))
                || std::path::Path::new(&s).extension().is_some_and(|e| e.eq_ignore_ascii_case("bat"))
                || std::path::Path::new(&s).extension().is_some_and(|e| e.eq_ignore_ascii_case("ps1"))
                || std::path::Path::new(&s).extension().is_some_and(|e| e.eq_ignore_ascii_case("vbs"))
            {
                out.push(s);
            }
        }
        out
    }

    fn extract_ascii(&self, data: &[u8], min_len: usize) -> Vec<String> {
        let mut out = Vec::new();
        let mut cur = Vec::<u8>::new();
        for &b in data {
            if (0x20..0x7F).contains(&b) {
                cur.push(b);
            } else {
                if cur.len() >= min_len
                    && let Ok(s) = std::str::from_utf8(&cur) {
                        out.push(s.to_string());
                    }
                cur.clear();
            }
        }
        if cur.len() >= min_len
            && let Ok(s) = std::str::from_utf8(&cur) {
                out.push(s.to_string());
            }
        out
    }

    fn looks_like_ip_port(&self, s: &str) -> bool {
        let parts: Vec<&str> = s.splitn(2, ':').collect();
        if parts.len() != 2 {
            return false;
        }
        let ip_parts: Vec<&str> = parts[0].split('.').collect();
        if ip_parts.len() != 4 {
            return false;
        }
        if ip_parts.iter().any(|p| p.parse::<u8>().is_err()) {
            return false;
        }
        parts[1].parse::<u16>().is_ok()
    }

    fn has_xor_loop_heuristic(&self, data: &[u8]) -> bool {
        // Look for: XOR byte at increasing address followed by INC/LOOP/JNZ
        // Simple heuristic: XOR r8, imm8 (80 Fx key) + LOOP or JNZ nearby
        let xor_count = data
            .windows(3)
            .filter(|w| w[0] == 0x80 && (w[1] & 0xF8) == 0x30)
            .count();
        xor_count >= 3
    }

    fn has_base64_blob(&self, data: &[u8]) -> bool {
        // Base64 chars: A-Z a-z 0-9 + / =
        let is_b64 = |b: u8| b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'=';
        let mut run = 0usize;
        for &b in data {
            if is_b64(b) {
                run += 1;
                if run >= 64 {
                    return true;
                }
            } else {
                run = 0;
            }
        }
        false
    }
}

impl Default for ShellcodeAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn analyzer() -> ShellcodeAnalyzer {
        ShellcodeAnalyzer::new()
    }

    // ── Display ───────────────────────────────────────────────────────────────

    #[test]
    fn test_arch_display() {
        assert_eq!(ShellcodeArch::X86_64.to_string(), "x86-64");
        assert_eq!(ShellcodeArch::Arm64.to_string(), "ARM64");
        assert_eq!(ShellcodeArch::Unknown.to_string(), "unknown");
    }

    #[test]
    fn test_os_display() {
        assert_eq!(ProbableOs::Windows.to_string(), "Windows");
        assert_eq!(ProbableOs::Linux.to_string(), "Linux");
    }

    #[test]
    fn test_shellcode_type_display() {
        assert_eq!(ShellcodeType::Bind.to_string(), "bind-shell");
        assert_eq!(
            ShellcodeType::DownloadExecute.to_string(),
            "download-and-execute"
        );
    }

    #[test]
    fn test_technique_display() {
        assert_eq!(ShellcodeTechnique::PebWalk.to_string(), "PEB-walk");
        assert_eq!(ShellcodeTechnique::XorDecoding.to_string(), "XOR-decoding");
    }

    // ── Architecture detection ────────────────────────────────────────────────

    #[test]
    fn test_detect_arch_x86_64() {
        // Two REX.W prefixes in first 32 bytes
        let data: Vec<u8> = std::iter::repeat_n(0x90u8, 4)
            .chain([0x48u8, 0x89, 0xC3, 0x48, 0x8B, 0x00])
            .collect();
        assert_eq!(analyzer().detect_arch(&data), ShellcodeArch::X86_64);
    }

    #[test]
    fn test_detect_arch_x86_32_prologue() {
        let data = [0x55u8, 0x89, 0xE5, 0x90];
        assert_eq!(analyzer().detect_arch(&data), ShellcodeArch::X86_32);
    }

    #[test]
    fn test_detect_arch_arm64() {
        // STP X29, X30, [SP, -N]! = 0xA9BF7BFD
        let v = 0xA9BF7BFD_u32.to_le_bytes();
        assert_eq!(analyzer().detect_arch(&v), ShellcodeArch::Arm64);
    }

    #[test]
    fn test_detect_arch_arm32() {
        let v = 0xE92D4800_u32.to_le_bytes();
        assert_eq!(analyzer().detect_arch(&v), ShellcodeArch::Arm32);
    }

    #[test]
    fn test_detect_arch_unknown_short() {
        assert_eq!(
            analyzer().detect_arch(&[0x00, 0x01]),
            ShellcodeArch::Unknown
        );
    }

    // ── Technique detection ───────────────────────────────────────────────────

    #[test]
    fn test_detect_getpc_thunk() {
        let data = [0xE8u8, 0x00, 0x00, 0x00, 0x00, 0x58]; // CALL $+5; POP EAX
        let techs = analyzer().detect_techniques(&data);
        assert!(techs.contains(&ShellcodeTechnique::GetPcThunk));
    }

    #[test]
    fn test_detect_peb_walk_fs() {
        let data = [0x64u8, 0xA1, 0x30, 0x00, 0x00, 0x00];
        let techs = analyzer().detect_techniques(&data);
        assert!(techs.contains(&ShellcodeTechnique::PebWalk));
    }

    #[test]
    fn test_detect_peb_walk_gs() {
        let data = [0x65u8, 0x48, 0x8B, 0x40, 0x60];
        let techs = analyzer().detect_techniques(&data);
        assert!(techs.contains(&ShellcodeTechnique::PebWalk));
    }

    #[test]
    fn test_detect_hash_api_ror13() {
        let data = [0xC1u8, 0xC8, 0x0D]; // ROR eax, 13
        let techs = analyzer().detect_techniques(&data);
        assert!(techs.contains(&ShellcodeTechnique::HashApiResolution));
    }

    #[test]
    fn test_detect_syscall() {
        let data = [0x0Fu8, 0x05]; // SYSCALL
        let techs = analyzer().detect_techniques(&data);
        assert!(techs.contains(&ShellcodeTechnique::IndirectSyscall));
    }

    #[test]
    fn test_detect_stack_strings() {
        // 6 consecutive PUSH imm8
        let data: Vec<u8> = (0..6).flat_map(|_| [0x6Au8, 0x41]).collect();
        let techs = analyzer().detect_techniques(&data);
        assert!(techs.contains(&ShellcodeTechnique::StackStrings));
    }

    // ── Network indicator extraction ──────────────────────────────────────────

    #[test]
    fn test_extract_network_http() {
        let data = b"\x00http://evil.example.com/payload\x00";
        let inds = analyzer().extract_network_indicators(data);
        assert!(inds.iter().any(|s| s.starts_with("http://")));
    }

    #[test]
    fn test_extract_network_ip_port() {
        let data = b"\x00192.168.1.1:4444\x00";
        let inds = analyzer().extract_network_indicators(data);
        assert!(inds.iter().any(|s| s.contains("192.168.1.1")));
    }

    #[test]
    fn test_extract_network_empty() {
        let data = [0x00u8, 0xFF, 0xAA];
        assert!(analyzer().extract_network_indicators(&data).is_empty());
    }

    // ── OS detection ─────────────────────────────────────────────────────────

    #[test]
    fn test_detect_os_windows_peb() {
        let techs = vec![ShellcodeTechnique::PebWalk];
        assert_eq!(analyzer().detect_os(&[], &techs), ProbableOs::Windows);
    }

    #[test]
    fn test_detect_os_windows_hash_api() {
        let techs = vec![ShellcodeTechnique::HashApiResolution];
        assert_eq!(analyzer().detect_os(&[], &techs), ProbableOs::Windows);
    }

    #[test]
    fn test_detect_os_linux_int80() {
        let data = [0xCDu8, 0x80];
        assert_eq!(analyzer().detect_os(&data, &[]), ProbableOs::Linux);
    }

    #[test]
    fn test_detect_os_unknown() {
        assert_eq!(analyzer().detect_os(&[0x90], &[]), ProbableOs::Unknown);
    }

    // ── XOR loop / decoded payloads ───────────────────────────────────────────

    #[test]
    fn test_find_xor_loops_mz_key() {
        // XOR 'MZ' with key 0x42: b'\x0F' b'\x18'
        let key = 0x42u8;
        let mut data = vec![0u8; 1024];
        // Embed XOR'd MZ header at offset 0
        data[0] = b'M' ^ key;
        data[1] = b'Z' ^ key;
        let payloads = analyzer().find_xor_loops(&data);
        assert!(!payloads.is_empty());
        assert_eq!(payloads[0].key, vec![key]);
        assert!(payloads[0].data.starts_with(b"MZ"));
    }

    #[test]
    fn test_find_xor_loops_no_match() {
        // Random data that doesn't decode to any known magic
        let data = vec![0xAAu8; 16];
        // Might or might not find something — just check it doesn't panic
        let _ = analyzer().find_xor_loops(&data);
    }

    // ── Full analyze() ────────────────────────────────────────────────────────

    #[test]
    fn test_analyze_populates_size() {
        let data = vec![0x90u8; 128];
        let profile = analyzer().analyze(&data, 0x1000);
        assert_eq!(profile.size, 128);
    }

    #[test]
    fn test_analyze_x64_shellcode() {
        // REX prefixes + syscall
        let data = [0x48u8, 0x31, 0xC0, 0x48, 0x89, 0xC7, 0x0F, 0x05];
        let profile = analyzer().analyze(&data, 0);
        assert_eq!(profile.arch, ShellcodeArch::X86_64);
        assert!(
            profile
                .techniques
                .contains(&ShellcodeTechnique::IndirectSyscall)
        );
    }

    #[test]
    fn test_analyze_returns_profile() {
        let profile = analyzer().analyze(&[0x90, 0x90, 0xF4], 0);
        // arch may be unknown for 3 bytes, but should not panic
        let _ = profile.arch;
        let _ = profile.size;
    }
}
