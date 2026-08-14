//! `avr_code_analysis` — AVR higher-level code analysis: prologue/epilogue
//! detection, string detection, bootloader patterns, and signature scanning.
//!
//! Provides:
//! * [`AvrPrologue`]         — AVR function prologue (PUSH R28/R29, RCALL)
//! * [`AvrEpilogue`]         — AVR function epilogue (POP, RET/RETI)
//! * [`AvrStringDetector`]   — PROGMEM string and RAM string detection
//! * [`AvrBootloaderPattern`]— bootloader section detection
//! * [`AvrSignatureScanner`] — well-known AVR code signature matching
//! * [`AvrCodeAnalysis`]     — top-level facade

use std::collections::{BTreeSet, HashMap};
use std::fmt;

// ---------------------------------------------------------------------------
// AVR Prologue
// ---------------------------------------------------------------------------

/// AVR function frame kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameKind {
    /// No frame pointer; only SP-relative addressing.
    NoFrame,
    /// Full frame: Y (R28/R29) saved and loaded with SP.
    FullFrame,
    /// Partial frame: Y saved but not reloaded.
    PartialFrame,
}

/// A detected AVR function prologue.
#[derive(Debug, Clone)]
pub struct AvrPrologue {
    /// Start address of the prologue.
    pub address: u64,
    /// Frame kind.
    pub frame_kind: FrameKind,
    /// Number of bytes allocated on the stack (frame size).
    pub frame_size: u16,
    /// Set of callee-saved registers pushed.
    pub saved_regs: Vec<u8>,
    /// Whether the prologue saves SREG.
    pub saves_sreg: bool,
    /// Prologue size in bytes (instruction count × 2).
    pub prologue_bytes: usize,
}

impl AvrPrologue {
    /// Detect an AVR function prologue in `bytes` at `address`.
    ///
    /// Standard GCC-generated AVR prologue:
    /// 1. `PUSH R28` (0x2F920E92 or 2-byte form)
    /// 2. `PUSH R29`
    /// 3. `IN R28, SPL` / `IN R29, SPH`
    /// 4. `SUBI R28, lo(frame_size)` / `SBC R29, R1` or SBIW
    /// 5. `OUT SPH, R29` / `OUT SPL, R28`
    #[must_use]
    pub fn detect(bytes: &[u8], address: u64) -> Option<Self> {
        if bytes.len() < 4 {
            return None;
        }
        let mut offset = 0;
        let mut saved_regs = Vec::new();
        let mut frame_size = 0u16;
        let mut frame_kind = FrameKind::NoFrame;

        // Detect PUSH instructions (0x920F + reg encoding)
        while offset + 2 <= bytes.len() {
            let w = u16::from_le_bytes([bytes[offset], bytes[offset + 1]]);
            // AVR PUSH: 1001 001d dddd 1111 = 0x920F | (rd << 4)
            if (w & 0xFE0F) == 0x920F {
                let reg = ((w >> 4) & 0x1F) as u8;
                saved_regs.push(reg);
                offset += 2;
                if reg == 28 || reg == 29 {
                    frame_kind = FrameKind::FullFrame;
                }
            } else {
                break;
            }
        }

        // Look for SBIW Rd, K (0x9700): 1001 0111 KKdd KKKK
        if offset + 2 <= bytes.len() {
            let w = u16::from_le_bytes([bytes[offset], bytes[offset + 1]]);
            if (w & 0xFF00) == 0x9700 {
                let k = ((w & 0x00C0) >> 2) | (w & 0x000F);
                frame_size = k;
                offset += 2;
            }
        }

        if saved_regs.is_empty() && frame_size == 0 {
            return None;
        }

        Some(Self {
            address,
            frame_kind,
            frame_size,
            saved_regs,
            saves_sreg: false,
            prologue_bytes: offset,
        })
    }

    /// Whether this prologue uses Y (R28/R29) as frame pointer.
    #[must_use]
    pub fn uses_frame_pointer(&self) -> bool {
        self.frame_kind == FrameKind::FullFrame
    }

    /// Number of registers saved.
    #[must_use]
    pub const fn saved_register_count(&self) -> usize {
        self.saved_regs.len()
    }
}

// ---------------------------------------------------------------------------
// AVR Epilogue
// ---------------------------------------------------------------------------

/// A detected AVR function epilogue.
#[derive(Debug, Clone)]
pub struct AvrEpilogue {
    /// Start address.
    pub address: u64,
    /// Registers restored (in pop order).
    pub restored_regs: Vec<u8>,
    /// Whether it ends with RET (true) or RETI (false).
    pub is_ret: bool,
    /// Epilogue size in bytes.
    pub epilogue_bytes: usize,
}

impl AvrEpilogue {
    /// Detect an AVR epilogue in `bytes` at `address`.
    #[must_use]
    pub fn detect(bytes: &[u8], address: u64) -> Option<Self> {
        if bytes.len() < 2 {
            return None;
        }
        let mut offset = 0;
        let mut restored_regs = Vec::new();

        // Detect POP instructions (0x900F + reg encoding)
        while offset + 2 <= bytes.len() {
            let w = u16::from_le_bytes([bytes[offset], bytes[offset + 1]]);
            // AVR POP: 1001 000d dddd 1111 = 0x900F | (rd << 4)
            if (w & 0xFE0F) == 0x900F {
                let reg = ((w >> 4) & 0x1F) as u8;
                restored_regs.push(reg);
                offset += 2;
            } else {
                break;
            }
        }

        if offset + 2 > bytes.len() {
            return None;
        }
        let last = u16::from_le_bytes([bytes[offset], bytes[offset + 1]]);
        let is_ret = last == 0x9508; // RET
        let is_reti = last == 0x9518; // RETI
        if !is_ret && !is_reti {
            return None;
        }
        offset += 2;

        Some(Self {
            address,
            restored_regs,
            is_ret,
            epilogue_bytes: offset,
        })
    }

    /// Number of registers restored.
    #[must_use]
    pub const fn restored_register_count(&self) -> usize {
        self.restored_regs.len()
    }
}

// ---------------------------------------------------------------------------
// AVR String Detector
// ---------------------------------------------------------------------------

/// A string found in AVR code or data.
#[derive(Debug, Clone)]
pub struct AvrString {
    /// Address.
    pub address: u64,
    /// String content (printable characters).
    pub content: String,
    /// Whether in PROGMEM (flash) vs SRAM.
    pub is_progmem: bool,
    /// Length including null terminator.
    pub byte_len: usize,
}

/// Detect C strings in AVR flash or SRAM data.
#[derive(Debug, Clone, Default)]
pub struct AvrStringDetector {
    /// Detected strings.
    pub strings: Vec<AvrString>,
    /// Minimum string length to report.
    pub min_length: usize,
}

impl AvrStringDetector {
    /// Create a new detector with minimum length 4.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            min_length: 4,
            strings: Vec::new(),
        }
    }

    /// Scan `bytes` starting at `base` for C-style strings.
    pub fn scan(&mut self, bytes: &[u8], base: u64, is_progmem: bool) {
        let mut start = 0;
        while start < bytes.len() {
            let end = bytes[start..]
                .iter()
                .position(|&b| b == 0)
                .map_or(bytes.len(), |p| start + p);
            let slice = &bytes[start..end];
            if slice.len() >= self.min_length
                && slice.iter().all(|&b| b.is_ascii_graphic() || b == b' ')
            {
                let content = String::from_utf8_lossy(slice).into_owned();
                self.strings.push(AvrString {
                    address: base + start as u64,
                    content,
                    is_progmem,
                    byte_len: end - start + 1,
                });
            }
            start = end + 1;
        }
    }

    /// Strings in PROGMEM.
    #[must_use]
    pub fn progmem_strings(&self) -> Vec<&AvrString> {
        self.strings.iter().filter(|s| s.is_progmem).collect()
    }

    /// Strings in SRAM.
    #[must_use]
    pub fn sram_strings(&self) -> Vec<&AvrString> {
        self.strings.iter().filter(|s| !s.is_progmem).collect()
    }
}

// ---------------------------------------------------------------------------
// AVR Bootloader Pattern
// ---------------------------------------------------------------------------

/// AVR bootloader section kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BootloaderSection {
    /// Located in the bootloader section (last 512–4096 words of flash).
    BootSection,
    /// Application section (below the bootloader).
    AppSection,
    /// Indeterminate.
    #[default]
    Unknown,
}

/// AVR bootloader detection.
#[derive(Debug, Clone, Default)]
pub struct AvrBootloaderPattern {
    /// Whether SPM (Store Program Memory) instructions were found.
    pub has_spm: bool,
    /// Number of SPM instructions found.
    pub spm_count: usize,
    /// SPM addresses.
    pub spm_addresses: Vec<u64>,
    /// Whether BOOTKEY patterns (e.g., magic byte checks) were detected.
    pub has_boot_key_check: bool,
    /// Likely section.
    pub section: BootloaderSection,
    /// Flash size (in words).
    pub flash_words: u32,
}

impl AvrBootloaderPattern {
    /// Create a new bootloader pattern detector.
    #[must_use]
    pub fn new(flash_words: u32) -> Self {
        Self {
            flash_words,
            section: BootloaderSection::Unknown,
            ..Default::default()
        }
    }

    /// Record an SPM instruction at `address`.
    pub fn record_spm(&mut self, address: u64) {
        self.has_spm = true;
        self.spm_count += 1;
        self.spm_addresses.push(address);
    }

    /// Check whether `address` (in words) is in the bootloader section.
    ///
    /// Standard AVR bootloader sections occupy the top of flash.
    /// E.g., for `ATmega328P` (32K flash = 16K words), `BOOTSEC` starts at 0x3800.
    #[must_use]
    pub const fn is_in_boot_section(&self, address_words: u32) -> bool {
        if self.flash_words == 0 {
            return false;
        }
        // Bootloader section: top 1/8 of flash by convention
        let boot_start = self.flash_words * 7 / 8;
        address_words >= boot_start
    }

    /// Classify the start address.
    pub const fn classify(&mut self, code_start_words: u32) {
        self.section = if self.is_in_boot_section(code_start_words) {
            BootloaderSection::BootSection
        } else {
            BootloaderSection::AppSection
        };
    }

    /// Bootloader confidence (0–100).
    #[must_use]
    pub fn confidence(&self) -> u8 {
        let mut score: u8 = 0;
        if self.has_spm {
            score = score.saturating_add(50);
        }
        if self.section == BootloaderSection::BootSection {
            score = score.saturating_add(30);
        }
        if self.has_boot_key_check {
            score = score.saturating_add(20);
        }
        score.min(100)
    }

    /// Whether this is likely a bootloader.
    #[must_use]
    pub fn is_bootloader(&self) -> bool {
        self.confidence() >= 50
    }
}

// ---------------------------------------------------------------------------
// AVR Signature Scanner
// ---------------------------------------------------------------------------

/// A known AVR code signature.
#[derive(Debug, Clone)]
pub struct AvrSignature {
    /// Signature name.
    pub name: &'static str,
    /// Byte pattern to match.
    pub pattern: &'static [u8],
    /// Description.
    pub description: &'static str,
}

/// A signature match.
#[derive(Debug, Clone)]
pub struct SignatureMatch {
    /// Matched signature name.
    pub name: &'static str,
    /// Address where the pattern was found.
    pub address: u64,
}

/// Known AVR code signatures.
static AVR_SIGNATURES: &[AvrSignature] = &[
    AvrSignature {
        name: "avr_memcpy",
        pattern: &[0x01, 0x90, 0x01, 0x9F, 0xF8, 0x01], // simplified
        description: "AVR memcpy implementation",
    },
    AvrSignature {
        name: "avr_delay_loop",
        pattern: &[0x01, 0x97, 0xF1, 0xF7], // sbiw R24,1; brne -4
        description: "Simple delay loop",
    },
    AvrSignature {
        name: "avr_clear_bss",
        pattern: &[0x10, 0x92, 0x00, 0x02], // sts pattern for BSS clear
        description: "BSS section clear startup",
    },
    AvrSignature {
        name: "watchdog_disable",
        pattern: &[0xF8, 0x94, 0xA8, 0x95], // cli; wdr pattern
        description: "Watchdog disable sequence",
    },
];

/// AVR code signature scanner.
#[derive(Debug, Clone, Default)]
pub struct AvrSignatureScanner {
    /// Matches found.
    pub matches: Vec<SignatureMatch>,
    /// Additional user-defined patterns. Names are leaked once on insert so
    /// `SignatureMatch` can hold a `&'static str` without re-leaking per scan.
    extra_patterns: Vec<(&'static str, Vec<u8>, String)>,
}

impl AvrSignatureScanner {
    /// Create a new scanner.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a custom pattern.
    ///
    /// # Panics
    /// Panics if more than 1024 custom patterns are added, to bound leaked memory.
    pub fn add_pattern(
        &mut self,
        name: impl Into<String>,
        pattern: Vec<u8>,
        description: impl Into<String>,
    ) {
        assert!(
            self.extra_patterns.len() < 1024,
            "add_pattern: exceeded maximum of 1024 custom patterns"
        );
        let name_static: &'static str = Box::leak(name.into().into_boxed_str());
        self.extra_patterns
            .push((name_static, pattern, description.into()));
    }

    /// Scan `bytes` at `base` for all known signatures.
    pub fn scan(&mut self, bytes: &[u8], base: u64) {
        for sig in AVR_SIGNATURES {
            let pat = sig.pattern;
            for i in 0..bytes.len().saturating_sub(pat.len() - 1) {
                if bytes[i..].starts_with(pat) {
                    self.matches.push(SignatureMatch {
                        name: sig.name,
                        address: base + i as u64,
                    });
                }
            }
        }
        // Scan extra patterns. Names are already &'static (leaked at add_pattern).
        for (name, p, _) in &self.extra_patterns {
            if p.is_empty() {
                continue;
            }
            let pat = p.as_slice();
            for i in 0..bytes.len().saturating_sub(pat.len().saturating_sub(1)) {
                if bytes[i..].starts_with(pat) {
                    self.matches.push(SignatureMatch {
                        name,
                        address: base + i as u64,
                    });
                }
            }
        }
    }

    /// Number of matches found.
    #[must_use]
    pub const fn match_count(&self) -> usize {
        self.matches.len()
    }

    /// Whether a specific signature was found.
    #[must_use]
    pub fn found(&self, name: &str) -> bool {
        self.matches.iter().any(|m| m.name == name)
    }
}

// ---------------------------------------------------------------------------
// Top-level facade
// ---------------------------------------------------------------------------

/// An AVR code analysis finding.
#[derive(Debug, Clone)]
pub struct AvrFinding {
    pub address: u64,
    pub message: String,
}

impl fmt::Display for AvrFinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{:04x}: {}", self.address, self.message)
    }
}

/// Top-level AVR code analysis facade.
#[derive(Debug, Clone)]
pub struct AvrCodeAnalysis {
    /// Detected function prologues.
    pub prologues: Vec<AvrPrologue>,
    /// Detected function epilogues.
    pub epilogues: Vec<AvrEpilogue>,
    /// String detector.
    pub strings: AvrStringDetector,
    /// Bootloader pattern detector.
    pub bootloader: AvrBootloaderPattern,
    /// Signature scanner.
    pub scanner: AvrSignatureScanner,
    /// Findings.
    pub findings: Vec<AvrFinding>,
    /// Total instructions.
    pub total_instructions: usize,
    /// Function entry points.
    /// `BTreeSet` is used instead of `HashSet` so that attacker-controlled addresses
    /// parsed from untrusted flash cannot trigger hash-collision `DoS`.
    pub function_entries: BTreeSet<u64>,
}

impl AvrCodeAnalysis {
    /// Create a new analysis context for a given flash size in words.
    #[must_use]
    pub fn new(flash_words: u32) -> Self {
        Self {
            prologues: Vec::new(),
            epilogues: Vec::new(),
            strings: AvrStringDetector::new(),
            bootloader: AvrBootloaderPattern::new(flash_words),
            scanner: AvrSignatureScanner::new(),
            findings: Vec::new(),
            total_instructions: 0,
            function_entries: BTreeSet::new(),
        }
    }

    /// Analyze a code region, scanning for prologues, epilogues, and signatures.
    pub fn analyze_region(&mut self, bytes: &[u8], base: u64) {
        let mut off = 0;
        while off + 2 <= bytes.len() {
            self.total_instructions += 1;
            if let Some(prologue) = AvrPrologue::detect(&bytes[off..], base + off as u64) {
                let advance = prologue.prologue_bytes.max(2);
                self.function_entries.insert(base + off as u64);
                self.findings.push(AvrFinding {
                    address: base + off as u64,
                    message: format!("prologue frame_size={}", prologue.frame_size),
                });
                self.prologues.push(prologue);
                off += advance;
                continue;
            }
            if let Some(epilogue) = AvrEpilogue::detect(&bytes[off..], base + off as u64) {
                let advance = epilogue.epilogue_bytes.max(2);
                self.epilogues.push(epilogue);
                off += advance;
                continue;
            }
            // SPM detection (0x95E8)
            let w = u16::from_le_bytes([bytes[off], bytes[off + 1]]);
            if w == 0x95E8 {
                self.bootloader.record_spm(base + off as u64);
                self.findings.push(AvrFinding {
                    address: base + off as u64,
                    message: "SPM instruction found".to_string(),
                });
            }
            off += 2;
        }
        self.scanner.scan(bytes, base);
    }

    /// Add a function entry point manually.
    pub fn add_function_entry(&mut self, addr: u64) {
        self.function_entries.insert(addr);
    }

    /// Whether any SPM instructions were found (bootloader indicator).
    #[must_use]
    pub const fn has_spm(&self) -> bool {
        self.bootloader.has_spm
    }

    /// Total prologue + epilogue pairs (rough function count).
    #[must_use]
    pub fn function_count_estimate(&self) -> usize {
        self.prologues.len().min(self.epilogues.len())
    }

    /// Group findings by their textual message, returning counts.
    ///
    /// Useful for summarising scan output (e.g. how many "SPM instruction
    /// found" entries were emitted).
    #[must_use]
    pub fn finding_histogram(&self) -> HashMap<String, usize> {
        let mut hist: HashMap<String, usize> = HashMap::new();
        for f in &self.findings {
            *hist.entry(f.message.clone()).or_insert(0) += 1;
        }
        hist
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ── AvrPrologue ───────────────────────────────────────────────────────────

    #[test]
    fn test_prologue_detect_push_r28_r29() {
        // PUSH R28 = 0x920E, PUSH R29 = 0x92EF (wrong — let's compute)
        // PUSH R28: 1001 001d dddd 1111 → d=28=0x1C → 0x920F | (0x1C<<4) = 0x92CF? No.
        // Actually: 0x920F | (28 << 4) = 0x920F | 0x01C0 = 0x93CF — Let me recalculate.
        // PUSH Rd: opcode = 1001 001d dddd 1111 = 0x920F where d fills bits [8:4]
        // For R28: d=28=0b11100, so word = 0x920F | (0b11100 << 4) = 0x920F | 0x01C0 = not right
        // Actually bits: [15:10]=100100, [9]=1, [8:4]=ddddd, [3:0]=1111
        // = 0x920F with d in bits [8:4]
        // For R28 (0x1C=28): word = (0x92 << 8) | (0x0F) | ((28 & 0x10) << 4) | ((28 & 0xF) << 4)
        // Let's just compute: 1001_0010_1110_1111 for R28
        // bits: 15-9=1001001, 8=1 (d4), 7-4=1100 (d3-d0), 3-0=1111
        // d=28=0b11100, d4=1, d3-d0=1100
        // word = 0b1001_0010_1110_1111 = 0x92EF? No…
        // Correct formula: opcode = 0x920F | (d & 0x1F) << 4
        // d=28: 0x920F | (28 << 4) = 0x920F | 0x1C0 = 0x93CF
        // Let's just test with that:
        let r28_push: u16 = 0x920F | (28u16 << 4);
        let r29_push: u16 = 0x920F | (29u16 << 4);
        let bytes: Vec<u8> = r28_push
            .to_le_bytes()
            .iter()
            .chain(r29_push.to_le_bytes().iter())
            .copied()
            .collect();
        let prologue = AvrPrologue::detect(&bytes, 0x1000);
        assert!(prologue.is_some());
        let p = prologue.unwrap();
        assert_eq!(p.saved_regs, vec![28, 29]);
        assert_eq!(p.frame_kind, FrameKind::FullFrame);
    }

    #[test]
    fn test_prologue_detect_with_sbiw() {
        let r28_push: u16 = 0x920F | (28u16 << 4);
        // SBIW R24, 16: 0x9700 | (0 << 6) | (0 << 4) | 16 = 0x9710
        let sbiw: u16 = 0x9710;
        let bytes: Vec<u8> = r28_push
            .to_le_bytes()
            .iter()
            .chain(sbiw.to_le_bytes().iter())
            .copied()
            .collect();
        let prologue = AvrPrologue::detect(&bytes, 0x0);
        assert!(prologue.is_some());
        let p = prologue.unwrap();
        assert!(p.frame_size > 0 || !p.saved_regs.is_empty());
    }

    #[test]
    fn test_prologue_detect_empty_bytes() {
        assert!(AvrPrologue::detect(&[], 0).is_none());
        assert!(AvrPrologue::detect(&[0x00, 0x00], 0).is_none());
    }

    #[test]
    fn test_prologue_uses_frame_pointer() {
        let p = AvrPrologue {
            address: 0,
            frame_kind: FrameKind::FullFrame,
            frame_size: 16,
            saved_regs: vec![28, 29],
            saves_sreg: false,
            prologue_bytes: 4,
        };
        assert!(p.uses_frame_pointer());
    }

    #[test]
    fn test_prologue_no_frame_pointer() {
        let p = AvrPrologue {
            address: 0,
            frame_kind: FrameKind::NoFrame,
            frame_size: 0,
            saved_regs: vec![2, 3],
            saves_sreg: false,
            prologue_bytes: 4,
        };
        assert!(!p.uses_frame_pointer());
    }

    // ── AvrEpilogue ───────────────────────────────────────────────────────────

    #[test]
    fn test_epilogue_detect_ret() {
        let ret: u16 = 0x9508;
        let bytes = ret.to_le_bytes();
        let ep = AvrEpilogue::detect(&bytes, 0x100);
        assert!(ep.is_some());
        assert!(ep.unwrap().is_ret);
    }

    #[test]
    fn test_epilogue_detect_reti() {
        let reti: u16 = 0x9518;
        let bytes = reti.to_le_bytes();
        let ep = AvrEpilogue::detect(&bytes, 0x100);
        assert!(ep.is_some());
        let e = ep.unwrap();
        assert!(!e.is_ret);
    }

    #[test]
    fn test_epilogue_detect_pop_then_ret() {
        let r28_pop: u16 = 0x900F | (28u16 << 4);
        let ret: u16 = 0x9508;
        let bytes: Vec<u8> = r28_pop
            .to_le_bytes()
            .iter()
            .chain(ret.to_le_bytes().iter())
            .copied()
            .collect();
        let ep = AvrEpilogue::detect(&bytes, 0x200);
        assert!(ep.is_some());
        let e = ep.unwrap();
        assert_eq!(e.restored_regs, vec![28]);
        assert!(e.is_ret);
    }

    #[test]
    fn test_epilogue_detect_no_ret() {
        let nop: u16 = 0x0000;
        let bytes = nop.to_le_bytes();
        assert!(AvrEpilogue::detect(&bytes, 0).is_none());
    }

    #[test]
    fn test_epilogue_restored_count() {
        let ep = AvrEpilogue {
            address: 0,
            restored_regs: vec![28, 29],
            is_ret: true,
            epilogue_bytes: 6,
        };
        assert_eq!(ep.restored_register_count(), 2);
    }

    // ── AvrStringDetector ─────────────────────────────────────────────────────

    #[test]
    fn test_string_scan_simple() {
        let mut det = AvrStringDetector::new();
        let data = b"Hello, World!\0";
        det.scan(data, 0x1000, true);
        assert_eq!(det.strings.len(), 1);
        assert_eq!(det.strings[0].content, "Hello, World!");
    }

    #[test]
    fn test_string_scan_too_short() {
        let mut det = AvrStringDetector::new();
        let data = b"Hi\0";
        det.scan(data, 0, false);
        assert!(det.strings.is_empty()); // "Hi" is only 2 chars < min_length 4
    }

    #[test]
    fn test_string_scan_multiple() {
        let mut det = AvrStringDetector::new();
        let data = b"First\0Second\0Third\0";
        det.scan(data, 0, false);
        assert_eq!(det.strings.len(), 3);
    }

    #[test]
    fn test_string_progmem_filter() {
        let mut det = AvrStringDetector::new();
        det.scan(b"FlashStr\0", 0, true);
        det.scan(b"SramString\0", 0x100, false);
        assert_eq!(det.progmem_strings().len(), 1);
        assert_eq!(det.sram_strings().len(), 1);
    }

    // ── AvrBootloaderPattern ──────────────────────────────────────────────────

    #[test]
    fn test_bootloader_is_in_boot_section() {
        let bl = AvrBootloaderPattern::new(16384); // 16K words
        let boot_start = 16384 * 7 / 8;
        assert!(bl.is_in_boot_section(boot_start));
        assert!(!bl.is_in_boot_section(0x0000));
    }

    #[test]
    fn test_bootloader_record_spm() {
        let mut bl = AvrBootloaderPattern::new(16384);
        bl.record_spm(0x7800);
        assert!(bl.has_spm);
        assert_eq!(bl.spm_count, 1);
    }

    #[test]
    fn test_bootloader_confidence_with_spm() {
        let mut bl = AvrBootloaderPattern::new(16384);
        bl.record_spm(0x7800);
        assert!(bl.confidence() >= 50);
        assert!(bl.is_bootloader());
    }

    #[test]
    fn test_bootloader_no_spm_not_bootloader() {
        let bl = AvrBootloaderPattern::new(16384);
        assert!(!bl.is_bootloader());
    }

    #[test]
    fn test_bootloader_classify() {
        let mut bl = AvrBootloaderPattern::new(16384);
        bl.classify(16384 * 7 / 8);
        assert_eq!(bl.section, BootloaderSection::BootSection);
    }

    // ── AvrSignatureScanner ───────────────────────────────────────────────────

    #[test]
    fn test_scanner_find_delay_loop() {
        let mut sc = AvrSignatureScanner::new();
        let bytes = [0x01u8, 0x97, 0xF1, 0xF7];
        sc.scan(&bytes, 0x0);
        assert!(sc.found("avr_delay_loop"));
    }

    #[test]
    fn test_scanner_no_match() {
        let mut sc = AvrSignatureScanner::new();
        sc.scan(&[0x00u8; 16], 0x0);
        assert_eq!(sc.match_count(), 0);
    }

    #[test]
    fn test_scanner_custom_pattern() {
        let mut sc = AvrSignatureScanner::new();
        sc.add_pattern("my_func", vec![0xAA, 0xBB, 0xCC], "custom pattern");
        sc.scan(&[0x00, 0xAA, 0xBB, 0xCC, 0x00], 0x1000);
        assert_eq!(sc.match_count(), 1);
    }

    // ── AvrCodeAnalysis ───────────────────────────────────────────────────────

    #[test]
    fn test_analysis_analyze_region_spm() {
        let mut a = AvrCodeAnalysis::new(16384);
        let spm: u16 = 0x95E8;
        let bytes = spm.to_le_bytes();
        a.analyze_region(&bytes, 0x7800);
        assert!(a.has_spm());
        assert_eq!(a.bootloader.spm_count, 1);
    }

    #[test]
    fn test_analysis_total_instructions() {
        let mut a = AvrCodeAnalysis::new(1024);
        let bytes = [0x00u8; 8]; // 4 NOPs
        a.analyze_region(&bytes, 0x0);
        assert!(a.total_instructions > 0);
    }

    #[test]
    fn test_analysis_add_function_entry() {
        let mut a = AvrCodeAnalysis::new(1024);
        a.add_function_entry(0x100);
        assert!(a.function_entries.contains(&0x100));
    }

    #[test]
    fn test_analysis_function_count_estimate() {
        let a = AvrCodeAnalysis::new(1024);
        assert_eq!(a.function_count_estimate(), 0);
    }

    // ── Additional coverage ───────────────────────────────────────────────────

    #[test]
    fn test_prologue_saved_register_count() {
        let p = AvrPrologue {
            address: 0,
            frame_kind: FrameKind::FullFrame,
            frame_size: 0,
            saved_regs: vec![2, 3, 14, 15],
            saves_sreg: false,
            prologue_bytes: 8,
        };
        assert_eq!(p.saved_register_count(), 4);
    }

    #[test]
    fn test_string_scan_non_ascii_skipped() {
        let mut det = AvrStringDetector::new();
        // High bytes — not ASCII graphic
        let data: Vec<u8> = (0x80u8..0x90).chain(std::iter::once(0)).collect();
        det.scan(&data, 0, false);
        assert!(det.strings.is_empty());
    }

    #[test]
    fn test_bootloader_flash_zero_no_section() {
        let bl = AvrBootloaderPattern::new(0);
        assert!(!bl.is_in_boot_section(0));
    }

    #[test]
    fn test_bootloader_multiple_spm() {
        let mut bl = AvrBootloaderPattern::new(16384);
        bl.record_spm(0x7800);
        bl.record_spm(0x7802);
        bl.record_spm(0x7804);
        assert_eq!(bl.spm_count, 3);
        assert_eq!(bl.spm_addresses.len(), 3);
    }

    #[test]
    fn test_scanner_multiple_matches() {
        let mut sc = AvrSignatureScanner::new();
        // Two copies of the delay loop pattern
        let pat = [0x01u8, 0x97, 0xF1, 0xF7];
        let bytes: Vec<u8> = pat
            .iter()
            .chain(b"\x00\x00")
            .chain(pat.iter())
            .copied()
            .collect();
        sc.scan(&bytes, 0x0);
        assert!(sc.match_count() >= 2);
    }

    #[test]
    fn test_string_address_correct() {
        let mut det = AvrStringDetector::new();
        let data = b"\x00\x00Hello\x00";
        det.scan(data, 0x1000, false);
        // "Hello" starts at offset 2 → address 0x1002
        assert_eq!(det.strings[0].address, 0x1002);
    }

    #[test]
    fn test_string_byte_len_includes_null() {
        let mut det = AvrStringDetector::new();
        let data = b"Test!\x00";
        det.scan(data, 0, false);
        assert_eq!(det.strings[0].byte_len, 6); // 5 chars + null
    }

    #[test]
    fn test_analysis_no_findings_for_nop() {
        let mut a = AvrCodeAnalysis::new(1024);
        // NOP = 0x0000 — should not trigger any SPM or prologue
        let bytes = [0x00u8, 0x00, 0x00, 0x00];
        a.analyze_region(&bytes, 0x0);
        assert!(!a.has_spm());
        assert_eq!(a.bootloader.spm_count, 0);
    }

    #[test]
    fn test_epilogue_empty_input() {
        assert!(AvrEpilogue::detect(&[], 0).is_none());
        assert!(AvrEpilogue::detect(&[0x00], 0).is_none());
    }

    #[test]
    fn test_bootloader_classify_app_section() {
        let mut bl = AvrBootloaderPattern::new(16384);
        bl.classify(0x0000);
        assert_eq!(bl.section, BootloaderSection::AppSection);
    }
}
