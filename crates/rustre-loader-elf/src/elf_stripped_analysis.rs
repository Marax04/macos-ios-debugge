//! Analysis of stripped ELF binaries.
//!
//! When an ELF binary is stripped (`strip --strip-all`), static symbols and
//! debug information are removed. This module provides heuristics to recover
//! useful information from the remaining binary structure:
//!
//! - [`PrologueFinder`]: Scan executable sections for common function prologue
//!   sequences to identify function starts.
//! - [`EpilogueDetector`]: Find function epilogue sequences (`ret`, `pop rbp;
//!   ret`, etc.) to estimate function boundaries.
//! - [`PltGotAnalysis`]: Analyse the PLT/GOT to identify imported functions
//!   even in stripped binaries.
//! - [`LibcDetector`]: Detect the libc variant (glibc, musl, uclibc) via
//!   string and import fingerprints.
//! - [`StrippedReport`]: Aggregate result combining all analyses.
//! - [`ElfStrippedAnalysis`]: Top-level facade.

use std::collections::HashMap;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// x86-64 function prologue patterns (variable-length; try longest first).
///
/// Each entry is (`pattern_bytes`, `expected_length`).
const X86_64_PROLOGUE_PATTERNS: &[&[u8]] = &[
    // push rbp; mov rbp, rsp
    &[0x55, 0x48, 0x89, 0xE5],
    // push rbp; mov rbp, rsp (with rex.w implied variant)
    &[0x55, 0x48, 0x8B, 0xEC],
    // endbr64; push rbp; mov rbp, rsp (CET-enabled)
    &[0xF3, 0x0F, 0x1E, 0xFA, 0x55, 0x48, 0x89, 0xE5],
    // endbr64 alone (start of CET function)
    &[0xF3, 0x0F, 0x1E, 0xFA],
    // sub rsp, N (leaf function, no frame pointer)
    &[0x48, 0x83, 0xEC],
    // push rbx; sub rsp, N (callee-saved register save)
    &[0x53, 0x48, 83],
    // push r15 (GCC leaf with saved regs)
    &[0x41, 0x57],
    // push r14
    &[0x41, 0x56],
    // push r13
    &[0x41, 0x55],
    // push r12
    &[0x41, 0x54],
];

/// x86-64 function epilogue patterns.
const X86_64_EPILOGUE_PATTERNS: &[&[u8]] = &[
    // leave; ret
    &[0xC9, 0xC3],
    // pop rbp; ret
    &[0x5D, 0xC3],
    // ret
    &[0xC3],
    // retn N (stdcall)
    &[0xC2],
    // rep ret (AMD branch prediction pad)
    &[0xF3, 0xC3],
    // add rsp, N; ret
    &[0x48, 0x83, 0xC4, 0x00, 0xC3],
];

/// ARM (32-bit) function prologue patterns.
const ARM32_PROLOGUE_PATTERNS: &[&[u8]] = &[
    // PUSH {r11, lr} (Thumb-2 or ARM)
    &[0x00, 0x48, 0x2D, 0xE9],
    // PUSH {r4, lr}
    &[0x10, 0x40, 0x2D, 0xE9],
    // Thumb PUSH {r7, lr}: 0x2D, 0xE9
    &[0x2D, 0xE9],
];

/// `AArch64` function prologue patterns.
const AARCH64_PROLOGUE_PATTERNS: &[&[u8]] = &[
    // stp x29, x30, [sp, #-N]!
    &[0xFD, 0x7B],
    // stp x19, x20, [sp, #-N]!
    &[0xF3, 0x53],
];

/// Minimum function size in bytes (to avoid noise).
const MIN_FUNCTION_SIZE: usize = 4;

/// Maximum reasonable distance between a prologue candidate and epilogue.
const MAX_FUNCTION_SIZE: usize = 0x10_0000; // 1 MiB

/// Alignment requirement for function start candidates.
const FUNCTION_ALIGN: u64 = 4;

// ---------------------------------------------------------------------------
// Architecture enum
// ---------------------------------------------------------------------------

/// Architecture of the binary being analysed.
#[derive(Debug, Clone, PartialEq, Eq)]
#[derive(Default)]
pub enum AnalysisArch {
    X86_64,
    X86,
    Arm32,
    Aarch64,
    Mips,
    #[default]
    Unknown,
}

// ---------------------------------------------------------------------------
// PrologueFinder
// ---------------------------------------------------------------------------

/// A detected function start candidate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrologueHit {
    /// Virtual address (absolute) of the candidate prologue.
    pub address: u64,
    /// Length of the matched prologue pattern in bytes.
    pub pattern_len: usize,
    /// Confidence score 0–100 (higher = more specific pattern).
    pub confidence: u8,
    /// Human-readable description of the matched pattern.
    pub description: String,
}

/// Scans executable sections for function prologue byte patterns to identify
/// function start addresses in stripped ELF binaries.
#[derive(Debug, Default)]
pub struct PrologueFinder {
    /// Architecture-specific prologue patterns to search.
    pub arch: AnalysisArch,
    /// Minimum confidence to include in results.
    pub min_confidence: u8,
}

impl PrologueFinder {
    /// Create a new prologue finder for the given architecture.
    #[must_use]
    pub const fn new(arch: AnalysisArch) -> Self {
        Self { arch, min_confidence: 50 }
    }

    /// Set the minimum confidence threshold.
    #[must_use]
    pub const fn with_min_confidence(mut self, min_confidence: u8) -> Self {
        self.min_confidence = min_confidence;
        self
    }

    /// Scan `data` (a raw section dump) mapped at `base_va` for prologue
    /// patterns and return a list of hits.
    #[must_use]
    pub fn scan(&self, data: &[u8], base_va: u64) -> Vec<PrologueHit> {
        let patterns = self.patterns_for_arch();
        let mut hits = Vec::new();

        for offset in 0..data.len() {
            // Only check aligned addresses.
            let va = base_va + offset as u64;
            if !va.is_multiple_of(FUNCTION_ALIGN) {
                continue;
            }

            for (pattern, description, confidence) in &patterns {
                if data[offset..].starts_with(pattern) {
                    if *confidence >= self.min_confidence {
                        hits.push(PrologueHit {
                            address: va,
                            pattern_len: pattern.len(),
                            confidence: *confidence,
                            description: description.to_string(),
                        });
                    }
                    // Don't match multiple patterns at the same offset.
                    break;
                }
            }
        }

        hits
    }

    /// Return the set of patterns and their metadata for the current arch.
    fn patterns_for_arch(&self) -> Vec<(&'static [u8], &'static str, u8)> {
        match &self.arch {
            AnalysisArch::X86_64 => vec![
                (X86_64_PROLOGUE_PATTERNS[2], "endbr64;push rbp;mov rbp,rsp", 95),
                (X86_64_PROLOGUE_PATTERNS[0], "push rbp;mov rbp,rsp", 90),
                (X86_64_PROLOGUE_PATTERNS[1], "push rbp;mov rbp,rsp(alt)", 90),
                (X86_64_PROLOGUE_PATTERNS[3], "endbr64", 60),
                (X86_64_PROLOGUE_PATTERNS[4], "sub rsp,N", 70),
                (X86_64_PROLOGUE_PATTERNS[6], "push r15", 55),
                (X86_64_PROLOGUE_PATTERNS[7], "push r14", 55),
                (X86_64_PROLOGUE_PATTERNS[8], "push r13", 55),
                (X86_64_PROLOGUE_PATTERNS[9], "push r12", 55),
            ],
            AnalysisArch::Arm32 => vec![
                (ARM32_PROLOGUE_PATTERNS[0], "PUSH {r11,lr}", 85),
                (ARM32_PROLOGUE_PATTERNS[1], "PUSH {r4,lr}", 80),
            ],
            AnalysisArch::Aarch64 => vec![
                (AARCH64_PROLOGUE_PATTERNS[0], "stp x29,x30,[sp]", 88),
                (AARCH64_PROLOGUE_PATTERNS[1], "stp x19,x20,[sp]", 75),
            ],
            _ => vec![],
        }
    }

    /// Return the number of distinct function candidates found.
    #[must_use]
    pub fn count_candidates(&self, hits: &[PrologueHit]) -> usize {
        hits.iter().map(|h| h.address).collect::<std::collections::HashSet<_>>().len()
    }
}

// ---------------------------------------------------------------------------
// EpilogueDetector
// ---------------------------------------------------------------------------

/// A detected function epilogue (end) candidate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EpilogueHit {
    /// Address of the epilogue instruction.
    pub address: u64,
    /// Length of matched epilogue pattern.
    pub pattern_len: usize,
    /// Confidence 0–100.
    pub confidence: u8,
    /// Description of the matched pattern.
    pub description: String,
}

/// Detects function epilogue sequences in executable sections.
#[derive(Debug, Default)]
pub struct EpilogueDetector {
    /// Architecture.
    pub arch: AnalysisArch,
}

impl EpilogueDetector {
    /// Create a new detector for the given architecture.
    #[must_use]
    pub const fn new(arch: AnalysisArch) -> Self {
        Self { arch }
    }

    /// Scan `data` mapped at `base_va` for epilogue patterns.
    #[must_use]
    pub fn scan(&self, data: &[u8], base_va: u64) -> Vec<EpilogueHit> {
        let patterns = self.patterns_for_arch();
        let mut hits = Vec::new();

        for offset in 0..data.len() {
            for (pattern, description, confidence) in &patterns {
                if data[offset..].starts_with(pattern) {
                    hits.push(EpilogueHit {
                        address: base_va + offset as u64,
                        pattern_len: pattern.len(),
                        confidence: *confidence,
                        description: description.to_string(),
                    });
                    break;
                }
            }
        }

        hits
    }

    fn patterns_for_arch(&self) -> Vec<(&'static [u8], &'static str, u8)> {
        match &self.arch {
            AnalysisArch::X86_64 | AnalysisArch::X86 => vec![
                (X86_64_EPILOGUE_PATTERNS[0], "leave;ret", 95),
                (X86_64_EPILOGUE_PATTERNS[1], "pop rbp;ret", 90),
                (X86_64_EPILOGUE_PATTERNS[4], "rep ret", 85),
                (X86_64_EPILOGUE_PATTERNS[5], "add rsp,N;ret", 80),
                (X86_64_EPILOGUE_PATTERNS[2], "ret", 70),
                (X86_64_EPILOGUE_PATTERNS[3], "retn N", 75),
            ],
            _ => vec![],
        }
    }

    /// Pair each epilogue hit with the nearest prologue hit that precedes it,
    /// returning estimated function boundaries `(start_va, end_va)`.
    #[must_use]
    pub fn pair_with_prologues(
        epilogues: &[EpilogueHit],
        prologues: &[PrologueHit],
    ) -> Vec<(u64, u64)> {
        let mut pairs = Vec::new();
        for epilogue in epilogues {
            // Find the last prologue before this epilogue within MAX_FUNCTION_SIZE.
            let best = prologues
                .iter()
                .filter(|p| {
                    p.address < epilogue.address
                        && (epilogue.address - p.address) >= MIN_FUNCTION_SIZE as u64
                        && (epilogue.address - p.address) <= MAX_FUNCTION_SIZE as u64
                })
                .max_by_key(|p| p.address);

            if let Some(prologue) = best {
                pairs.push((prologue.address, epilogue.address + epilogue.pattern_len as u64));
            }
        }
        pairs.sort_unstable();
        pairs.dedup();
        pairs
    }
}

// ---------------------------------------------------------------------------
// PltGotAnalysis
// ---------------------------------------------------------------------------

/// Resolved PLT entry with function name and addresses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedPltEntry {
    /// Function name (from dynamic symbol table or relocation).
    pub name: String,
    /// Virtual address of the PLT stub.
    pub plt_address: u64,
    /// Virtual address of the GOT slot.
    pub got_address: u64,
    /// Whether the GOT slot has been resolved (non-zero, non-PLT-resolver value).
    pub is_resolved: bool,
}

/// Configuration for PLT/GOT analysis.
#[derive(Debug, Clone)]
pub struct PltGotConfig {
    /// PLT entry size in bytes (default: 16 for x86-64).
    pub plt_entry_size: u64,
    /// Offset of the GOT reference within each PLT stub (default: 2 for x86-64 jmp [rip+N]).
    pub got_ref_offset: usize,
}

impl Default for PltGotConfig {
    fn default() -> Self {
        Self { plt_entry_size: 16, got_ref_offset: 2 }
    }
}

/// Analyses the PLT and GOT sections to identify imported function calls
/// in stripped ELF binaries.
#[derive(Debug, Default)]
pub struct PltGotAnalysis {
    /// Resolved PLT entries.
    pub entries: Vec<ResolvedPltEntry>,
    /// Address of the PLT section.
    pub plt_base: u64,
    /// Number of total PLT slots.
    pub plt_slot_count: usize,
    /// Number of resolved GOT entries.
    pub resolved_count: usize,
}

impl PltGotAnalysis {
    /// Build a PLT/GOT analysis from:
    /// - `plt_data`: raw bytes of the `.plt` section
    /// - `plt_base`: virtual address of `.plt`
    /// - `got_data`: raw bytes of the `.got.plt` section
    /// - `got_base`: virtual address of `.got.plt`
    /// - `names`: map from GOT slot address → function name (from relocations)
    #[must_use] 
    pub fn analyse(
        plt_data: &[u8],
        plt_base: u64,
        got_data: &[u8],
        got_base: u64,
        names: &HashMap<u64, String>,
        config: &PltGotConfig,
    ) -> Self {
        let plt_entry_sz = usize::try_from(config.plt_entry_size).unwrap_or(0);
        let slot_count = if plt_entry_sz > 0 {
            plt_data.len() / plt_entry_sz
        } else {
            0
        };

        // Skip the first PLT entry (PLT[0] is the resolver stub).
        let mut entries = Vec::new();
        for i in 1..slot_count {
            let stub_offset = i * plt_entry_sz;
            let stub_va = plt_base + stub_offset as u64;

            // Try to recover the GOT address from the RIP-relative jmp in the stub.
            // x86-64 format: FF 25 <rel32> → GOT = stub_va + 6 + rel32
            let got_addr = if stub_offset + 6 <= plt_data.len()
                && plt_data[stub_offset] == 0xFF
                && plt_data[stub_offset + 1] == 0x25
            {
                let rel32 = i32::from_le_bytes(
                    plt_data[stub_offset + 2..stub_offset + 6].try_into().unwrap_or([0; 4]),
                );
                (stub_va + 6).wrapping_add(i64::from(rel32).cast_unsigned())
            } else {
                // Fallback: assume linear GOT layout.
                got_base + (i as u64) * 8
            };

            // Check whether the GOT slot is resolved.
            let got_slot_offset = usize::try_from(got_addr.wrapping_sub(got_base)).unwrap_or(0);
            let is_resolved = if got_slot_offset + 8 <= got_data.len() {
                let got_val = u64::from_le_bytes(
                    got_data[got_slot_offset..got_slot_offset + 8].try_into().unwrap_or([0; 8]),
                );
                // Resolved if the GOT slot does not point back into PLT.
                got_val != 0 && (got_val < plt_base || got_val >= plt_base + plt_data.len() as u64)
            } else {
                false
            };

            let name = names.get(&got_addr).cloned().unwrap_or_else(|| format!("plt_{i}"));

            entries.push(ResolvedPltEntry {
                name,
                plt_address: stub_va,
                got_address: got_addr,
                is_resolved,
            });
        }

        let resolved_count = entries.iter().filter(|e| e.is_resolved).count();

        Self {
            entries,
            plt_base,
            plt_slot_count: slot_count,
            resolved_count,
        }
    }

    /// Look up a PLT entry by its stub address.
    #[must_use]
    pub fn by_plt_address(&self, addr: u64) -> Option<&ResolvedPltEntry> {
        self.entries.iter().find(|e| e.plt_address == addr)
    }

    /// Look up a PLT entry by function name.
    #[must_use]
    pub fn by_name(&self, name: &str) -> Option<&ResolvedPltEntry> {
        self.entries.iter().find(|e| e.name == name)
    }

    /// Return all names of resolved imports.
    #[must_use]
    pub fn resolved_names(&self) -> Vec<&str> {
        self.entries
            .iter()
            .filter(|e| e.is_resolved)
            .map(|e| e.name.as_str())
            .collect()
    }
}

// ---------------------------------------------------------------------------
// LibcDetector
// ---------------------------------------------------------------------------

/// Detected libc variant.
#[derive(Debug, Clone, PartialEq, Eq)]
#[derive(Default)]
pub enum LibcVariant {
    Glibc { version_hint: Option<String> },
    Musl,
    Uclibc,
    Bionic,
    Newlib,
    #[default]
    Unknown,
}

impl LibcVariant {
    /// Return a human-readable name.
    #[must_use]
    pub const fn name(&self) -> &str {
        match self {
            Self::Glibc { .. } => "glibc",
            Self::Musl          => "musl",
            Self::Uclibc        => "uClibc",
            Self::Bionic        => "Bionic (Android)",
            Self::Newlib        => "newlib",
            Self::Unknown       => "unknown",
        }
    }

    /// Return `true` if this is a glibc variant.
    #[must_use]
    pub const fn is_glibc(&self) -> bool {
        matches!(self, Self::Glibc { .. })
    }
}

/// Detects which libc implementation the binary was linked against.
#[derive(Debug, Default)]
pub struct LibcDetector;

impl LibcDetector {
    /// Detect the libc variant from:
    /// - `needed_libs`: `DT_NEEDED` library names from the dynamic section.
    /// - `strings`: printable strings found in the binary.
    #[must_use]
    pub fn detect(needed_libs: &[&str], strings: &[&str]) -> LibcVariant {
        // Check DT_NEEDED entries first.
        for lib in needed_libs {
            let lower = lib.to_lowercase();
            if lower.starts_with("libc.so") || lower.starts_with("libc-") {
                // Distinguish glibc from musl by checking for known strings.
                for s in strings {
                    if s.contains("musl") || s.contains("musl libc") {
                        return LibcVariant::Musl;
                    }
                    if s.contains("uClibc") || s.contains("uclibc") {
                        return LibcVariant::Uclibc;
                    }
                }
                // Check for version string.
                let version = strings.iter()
                    .find(|s| s.contains("GNU C Library") || s.contains("glibc"))
                    .and_then(|s| {
                        s.split_whitespace()
                            .find(|w| w.starts_with("2.") || w.starts_with("2,"))
                            .map(|v| v.trim_end_matches(',').to_string())
                    });
                return LibcVariant::Glibc { version_hint: version };
            }
            if lower.starts_with("libbsd") {
                return LibcVariant::Glibc { version_hint: None };
            }
        }

        // Check strings for identification markers.
        for s in strings {
            let sl = s.to_lowercase();
            if sl.contains("musl") && sl.contains("libc") {
                return LibcVariant::Musl;
            }
            if sl.contains("uclibc") {
                return LibcVariant::Uclibc;
            }
            if sl.contains("bionic") || sl.contains("android") {
                return LibcVariant::Bionic;
            }
            if sl.contains("newlib") {
                return LibcVariant::Newlib;
            }
            if sl.contains("gnu c library") {
                return LibcVariant::Glibc { version_hint: None };
            }
        }

        LibcVariant::Unknown
    }

    /// Detect libc from a raw binary scan (looks for embedded strings).
    #[must_use]
    pub fn detect_from_binary(data: &[u8]) -> LibcVariant {
        let text = String::from_utf8_lossy(data);
        // Quick scan for identifying strings.
        if text.contains("musl") && text.contains("libc") {
            return LibcVariant::Musl;
        }
        if text.contains("uClibc") {
            return LibcVariant::Uclibc;
        }
        if text.contains("GNU C Library") {
            let version = text
                .lines()
                .find(|l| l.contains("GNU C Library") && l.contains("version"))
                .and_then(|l| {
                    l.split_whitespace()
                        .find(|w| w.starts_with("2."))
                        .map(std::string::ToString::to_string)
                });
            return LibcVariant::Glibc { version_hint: version };
        }
        if text.contains("Android") && text.contains("bionic") {
            return LibcVariant::Bionic;
        }
        if text.contains("newlib") {
            return LibcVariant::Newlib;
        }
        LibcVariant::Unknown
    }
}

// ---------------------------------------------------------------------------
// StrippedReport
// ---------------------------------------------------------------------------

/// Aggregated report from stripped ELF analysis.
#[derive(Debug, Default)]
pub struct StrippedReport {
    /// Whether the binary is confirmed stripped.
    pub is_stripped: bool,
    /// Detected architecture.
    pub arch: Option<AnalysisArch>,
    /// Estimated number of functions based on prologue scan.
    pub estimated_function_count: usize,
    /// Recovered function boundaries `(start_va, end_va)`.
    pub function_boundaries: Vec<(u64, u64)>,
    /// Resolved PLT entries.
    pub plt_entries: Vec<ResolvedPltEntry>,
    /// Detected libc variant.
    pub libc: LibcVariant,
    /// List of import names identified from PLT/GOT.
    pub identified_imports: Vec<String>,
    /// Total bytes of executable code found.
    pub total_code_bytes: u64,
    /// Any warnings generated during analysis.
    pub warnings: Vec<String>,
    /// Confidence score for the analysis (0–100).
    pub confidence: u8,
}

impl StrippedReport {
    /// Return `true` if any function boundaries were recovered.
    #[must_use]
    pub const fn has_recovered_functions(&self) -> bool {
        !self.function_boundaries.is_empty()
    }

    /// Return the average function size in bytes.
    #[must_use]
    pub fn average_function_size(&self) -> f64 {
        if self.function_boundaries.is_empty() {
            return 0.0;
        }
        let total: u64 = self.function_boundaries.iter().map(|(s, e)| e - s).sum();
        let total_approx = u32::try_from(total.min(u64::from(u32::MAX))).unwrap_or(u32::MAX);
        let count_approx = u32::try_from(self.function_boundaries.len().min(u32::MAX as usize)).unwrap_or(1);
        f64::from(total_approx) / f64::from(count_approx)
    }

    /// Return a brief textual summary.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "stripped={} functions≈{} imports={} libc={} confidence={}",
            self.is_stripped,
            self.estimated_function_count,
            self.identified_imports.len(),
            self.libc.name(),
            self.confidence,
        )
    }
}

// ---------------------------------------------------------------------------
// ElfStrippedAnalysis — top-level facade
// ---------------------------------------------------------------------------

/// PLT/GOT input data for [`ElfStrippedAnalysis::analyse`].
pub struct PltGotInput<'a> {
    /// Raw bytes of the `.plt` section.
    pub plt_data: &'a [u8],
    /// Virtual address of the `.plt` section.
    pub plt_base: u64,
    /// Raw bytes of the `.got.plt` section.
    pub got_data: &'a [u8],
    /// Virtual address of the `.got.plt` section.
    pub got_base: u64,
    /// Map from GOT slot address to resolved symbol name.
    pub names: &'a HashMap<u64, String>,
}

/// Top-level facade for analysis of stripped ELF binaries.
///
/// Combines prologue scanning, epilogue detection, PLT/GOT analysis, and
/// libc detection into a single [`StrippedReport`].
#[derive(Debug, Default)]
pub struct ElfStrippedAnalysis;

impl ElfStrippedAnalysis {
    /// Run a full stripped-binary analysis.
    ///
    /// # Parameters
    /// - `code_sections`: `(data, base_va)` pairs of executable sections.
    /// - `plt_got`: PLT/GOT section data and address map.
    /// - `needed_libs`: `DT_NEEDED` entries.
    /// - `strings`: printable strings extracted from the binary.
    /// - `is_stripped`: whether the binary has no `.symtab`.
    /// - `arch`: detected architecture.
    #[must_use]
    pub fn analyse(
        code_sections: &[(&[u8], u64)],
        plt_got: &PltGotInput<'_>,
        needed_libs: &[&str],
        strings: &[&str],
        is_stripped: bool,
        arch: &AnalysisArch,
    ) -> StrippedReport {
        let PltGotInput { plt_data, plt_base, got_data, got_base, names } = plt_got;
        let mut report = StrippedReport {
            is_stripped,
            arch: Some(arch.clone()),
            libc: LibcDetector::detect(needed_libs, strings),
            ..Default::default()
        };

        // Prologue / epilogue scanning over all executable sections.
        let prologue_finder = PrologueFinder::new(arch.clone())
            .with_min_confidence(60);
        let epilogue_detector = EpilogueDetector::new(arch.clone());

        let mut all_prologues: Vec<PrologueHit> = Vec::new();
        let mut all_epilogues: Vec<EpilogueHit> = Vec::new();
        let mut total_code_bytes: u64 = 0;

        for (section_data, base_va) in code_sections {
            total_code_bytes += section_data.len() as u64;
            let mut prols = prologue_finder.scan(section_data, *base_va);
            let mut epils = epilogue_detector.scan(section_data, *base_va);
            all_prologues.append(&mut prols);
            all_epilogues.append(&mut epils);
        }

        report.estimated_function_count = prologue_finder.count_candidates(&all_prologues);
        report.total_code_bytes = total_code_bytes;

        // Pair prologues with epilogues.
        report.function_boundaries =
            EpilogueDetector::pair_with_prologues(&all_epilogues, &all_prologues);

        // PLT/GOT analysis.
        let plt_config = PltGotConfig::default();
        if !plt_data.is_empty() {
            let plt_analysis = PltGotAnalysis::analyse(
                plt_data, *plt_base,
                got_data, *got_base,
                names, &plt_config,
            );

            report.identified_imports = plt_analysis.entries.iter().map(|e| e.name.clone()).collect();
            report.plt_entries = plt_analysis.entries;
        }

        // Confidence heuristic.
        report.confidence = Self::compute_confidence(&report);

        report
    }

    fn compute_confidence(report: &StrippedReport) -> u8 {
        let mut score: u32 = 0;

        if report.estimated_function_count > 0 {
            score += 30;
        }
        if !report.function_boundaries.is_empty() {
            score += 20;
        }
        if !report.identified_imports.is_empty() {
            score += 20;
        }
        if !matches!(report.libc, LibcVariant::Unknown) {
            score += 15;
        }
        if report.is_stripped {
            score += 15;
        }

        score.min(100) as u8
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // PrologueFinder tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_prologue_finder_x86_64_push_rbp() {
        let finder = PrologueFinder::new(AnalysisArch::X86_64);
        // push rbp; mov rbp, rsp = 55 48 89 E5
        let data = [0x55u8, 0x48, 0x89, 0xE5, 0x90, 0x90, 0x90, 0x90];
        let hits = finder.scan(&data, 0x0040_1000);
        assert!(!hits.is_empty());
        assert_eq!(hits[0].address, 0x0040_1000);
        assert!(hits[0].confidence >= 60);
    }

    #[test]
    fn test_prologue_finder_no_match() {
        let finder = PrologueFinder::new(AnalysisArch::X86_64);
        let data = vec![0xCCu8; 64]; // INT3 padding, no prologues
        let hits = finder.scan(&data, 0x0040_1000);
        assert!(hits.is_empty());
    }

    #[test]
    fn test_prologue_finder_multiple_hits() {
        let finder = PrologueFinder::new(AnalysisArch::X86_64);
        // Two prologues 16 bytes apart (both 4-byte aligned).
        let mut data = vec![0x90u8; 32];
        data[0] = 0x55; data[1] = 0x48; data[2] = 0x89; data[3] = 0xE5;
        data[16] = 0x55; data[17] = 0x48; data[18] = 0x89; data[19] = 0xE5;
        let hits = finder.scan(&data, 0x0040_1000);
        assert_eq!(hits.len(), 2);
        assert_eq!(hits[0].address, 0x0040_1000);
        assert_eq!(hits[1].address, 0x0040_1010);
    }

    #[test]
    fn test_prologue_finder_count_candidates() {
        let finder = PrologueFinder::new(AnalysisArch::X86_64);
        let mut data = vec![0x90u8; 32];
        data[0] = 0x55; data[1] = 0x48; data[2] = 0x89; data[3] = 0xE5;
        data[16] = 0x55; data[17] = 0x48; data[18] = 0x89; data[19] = 0xE5;
        let hits = finder.scan(&data, 0x0040_1000);
        assert_eq!(finder.count_candidates(&hits), 2);
    }

    #[test]
    fn test_prologue_finder_endbr64() {
        let finder = PrologueFinder::new(AnalysisArch::X86_64);
        // endbr64 = F3 0F 1E FA
        let mut data = vec![0x00u8; 16];
        data[0] = 0xF3; data[1] = 0x0F; data[2] = 0x1E; data[3] = 0xFA;
        let hits = finder.scan(&data, 0x1000);
        // endbr64 alone has confidence 60, which meets default 60 threshold
        assert!(!hits.is_empty());
    }

    #[test]
    fn test_prologue_finder_min_confidence_filter() {
        let finder = PrologueFinder::new(AnalysisArch::X86_64)
            .with_min_confidence(95);
        // Only endbr64 + push rbp + mov rbp,rsp qualifies at 95
        let mut data = vec![0x90u8; 16];
        // push rbp alone (confidence 90) should be filtered out
        data[0] = 0x55; data[1] = 0x48; data[2] = 0x89; data[3] = 0xE5;
        let hits = finder.scan(&data, 0x1000);
        // push rbp;mov rbp,rsp is 90, so filtered at threshold 95
        assert!(hits.is_empty());
    }

    #[test]
    fn test_prologue_finder_arm32() {
        let finder = PrologueFinder::new(AnalysisArch::Arm32);
        // PUSH {r11, lr} little-endian
        let data = [0x00u8, 0x48, 0x2D, 0xE9, 0x00, 0x00, 0x00, 0x00];
        let hits = finder.scan(&data, 0x8000);
        assert!(!hits.is_empty());
    }

    // -----------------------------------------------------------------------
    // EpilogueDetector tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_epilogue_detector_ret() {
        let detector = EpilogueDetector::new(AnalysisArch::X86_64);
        let data = [0x90u8, 0xC3, 0x90]; // nop; ret; nop
        let hits = detector.scan(&data, 0x0040_1000);
        let ret_hit = hits.iter().find(|h| h.description == "ret");
        assert!(ret_hit.is_some());
        assert_eq!(ret_hit.unwrap().address, 0x0040_1001);
    }

    #[test]
    fn test_epilogue_detector_leave_ret() {
        let detector = EpilogueDetector::new(AnalysisArch::X86_64);
        // leave; ret = C9 C3
        let data = [0xC9u8, 0xC3];
        let hits = detector.scan(&data, 0x1000);
        assert!(!hits.is_empty());
        assert_eq!(hits[0].address, 0x1000);
        assert!(hits[0].confidence >= 90);
    }

    #[test]
    fn test_epilogue_detector_no_match() {
        let detector = EpilogueDetector::new(AnalysisArch::X86_64);
        let data = vec![0x90u8; 32]; // all NOPs
        let hits = detector.scan(&data, 0x1000);
        assert!(hits.is_empty());
    }

    #[test]
    fn test_epilogue_detector_pair_with_prologues() {
        let prologues = vec![
            PrologueHit {
                address: 0x1000,
                pattern_len: 4,
                confidence: 90,
                description: "push rbp;mov rbp,rsp".to_string(),
            },
        ];
        let epilogues = vec![
            EpilogueHit {
                address: 0x1020,
                pattern_len: 1,
                confidence: 70,
                description: "ret".to_string(),
            },
        ];
        let pairs = EpilogueDetector::pair_with_prologues(&epilogues, &prologues);
        assert_eq!(pairs.len(), 1);
        assert_eq!(pairs[0], (0x1000, 0x1021));
    }

    #[test]
    fn test_epilogue_detector_pair_no_match_too_large() {
        let prologues = vec![
            PrologueHit {
                address: 0x1000,
                pattern_len: 4,
                confidence: 90,
                description: "push rbp".to_string(),
            },
        ];
        let epilogues = vec![
            EpilogueHit {
                address: 0x1000 + MAX_FUNCTION_SIZE as u64 + 1,
                pattern_len: 1,
                confidence: 70,
                description: "ret".to_string(),
            },
        ];
        let pairs = EpilogueDetector::pair_with_prologues(&epilogues, &prologues);
        assert!(pairs.is_empty());
    }

    // -----------------------------------------------------------------------
    // PltGotAnalysis tests
    // -----------------------------------------------------------------------

    fn build_plt_stub(got_va: u64, stub_va: u64) -> [u8; 16] {
        // FF 25 <rel32>: JMP [RIP+rel32] where RIP = stub_va+6
        let rel32 = (got_va.cast_signed() - (stub_va.cast_signed() + 6)) as i32;
        let mut stub = [0u8; 16];
        stub[0] = 0xFF;
        stub[1] = 0x25;
        stub[2..6].copy_from_slice(&rel32.to_le_bytes());
        stub
    }

    #[test]
    fn test_plt_got_analysis_basic() {
        let plt_base = 0x0040_1020_u64;
        let got_base = 0x0060_1000_u64;

        // PLT[0] = resolver (16 bytes), PLT[1] = printf stub
        let mut plt_data = vec![0u8; 32];
        // PLT[0]: just padding
        // PLT[1] at offset 16 → stub_va = 0x401030
        let stub = build_plt_stub(got_base + 24, plt_base + 16);
        plt_data[16..32].copy_from_slice(&stub);

        // GOT: [0..24] = reserved slots, [24..32] = printf GOT entry
        let mut got_data = vec![0u8; 32];
        // Set GOT[24] to a resolved address outside PLT
        let resolved_va: u64 = 0x7FFF_1234_5678;
        got_data[24..32].copy_from_slice(&resolved_va.to_le_bytes());

        let mut names = HashMap::new();
        names.insert(got_base + 24, "printf".to_string());

        let config = PltGotConfig::default();
        let analysis = PltGotAnalysis::analyse(
            &plt_data, plt_base,
            &got_data, got_base,
            &names, &config,
        );

        assert_eq!(analysis.plt_slot_count, 2); // including resolver
        assert!(!analysis.entries.is_empty());

        let printf_entry = analysis.by_name("printf");
        assert!(printf_entry.is_some());
        let e = printf_entry.unwrap();
        assert_eq!(e.got_address, got_base + 24);
        assert!(e.is_resolved);
    }

    #[test]
    fn test_plt_got_analysis_empty_plt() {
        let analysis = PltGotAnalysis::analyse(
            &[], 0, &[], 0, &HashMap::new(), &PltGotConfig::default(),
        );
        assert_eq!(analysis.entries.len(), 0);
        assert_eq!(analysis.resolved_count, 0);
    }

    #[test]
    fn test_plt_got_analysis_by_plt_address() {
        let plt_base = 0x0040_1020_u64;
        let got_base = 0x0060_1000_u64;
        let mut plt_data = vec![0u8; 32];
        let stub = build_plt_stub(got_base + 16, plt_base + 16);
        plt_data[16..32].copy_from_slice(&stub);

        let analysis = PltGotAnalysis::analyse(
            &plt_data, plt_base, &[], got_base, &HashMap::new(), &PltGotConfig::default(),
        );

        let entry = analysis.by_plt_address(plt_base + 16);
        assert!(entry.is_some());
    }

    #[test]
    fn test_plt_got_resolved_names() {
        let plt_base = 0x1000u64;
        let got_base = 0x3000u64;
        let mut plt_data = vec![0u8; 48]; // 3 entries × 16
        let stub1 = build_plt_stub(got_base + 24, plt_base + 16);
        let stub2 = build_plt_stub(got_base + 32, plt_base + 32);
        plt_data[16..32].copy_from_slice(&stub1);
        plt_data[32..48].copy_from_slice(&stub2);

        let mut got_data = vec![0u8; 40];
        got_data[24..32].copy_from_slice(&0xABCD_EF00_u64.to_le_bytes());
        got_data[32..40].copy_from_slice(&0xABCD_EF10_u64.to_le_bytes());

        let mut names = HashMap::new();
        names.insert(got_base + 24, "malloc".to_string());
        names.insert(got_base + 32, "free".to_string());

        let analysis = PltGotAnalysis::analyse(
            &plt_data, plt_base, &got_data, got_base, &names, &PltGotConfig::default(),
        );

        let resolved = analysis.resolved_names();
        assert!(resolved.contains(&"malloc"));
        assert!(resolved.contains(&"free"));
    }

    // -----------------------------------------------------------------------
    // LibcDetector tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_libc_detector_glibc_from_needed() {
        let libc = LibcDetector::detect(&["libc.so.6"], &[]);
        assert!(libc.is_glibc());
    }

    #[test]
    fn test_libc_detector_musl_from_string() {
        let libc = LibcDetector::detect(&["libc.so"], &["musl libc", "MIT License"]);
        assert_eq!(libc, LibcVariant::Musl);
    }

    #[test]
    fn test_libc_detector_uclibc_from_string() {
        let libc = LibcDetector::detect(&[], &["uClibc-ng 1.0.40"]);
        assert_eq!(libc, LibcVariant::Uclibc);
    }

    #[test]
    fn test_libc_detector_bionic_from_string() {
        let libc = LibcDetector::detect(&[], &["Android bionic libc"]);
        assert_eq!(libc, LibcVariant::Bionic);
    }

    #[test]
    fn test_libc_detector_unknown_no_hints() {
        let libc = LibcDetector::detect(&[], &[]);
        assert_eq!(libc, LibcVariant::Unknown);
    }

    #[test]
    fn test_libc_detector_from_binary_musl() {
        let data = b"musl libc 1.2.3\0some other content\0";
        let libc = LibcDetector::detect_from_binary(data);
        assert_eq!(libc, LibcVariant::Musl);
    }

    #[test]
    fn test_libc_detector_from_binary_glibc() {
        let data = b"GNU C Library (EGLIBC) release version 2.30\0";
        let libc = LibcDetector::detect_from_binary(data);
        assert!(libc.is_glibc());
    }

    #[test]
    fn test_libc_variant_name() {
        assert_eq!(LibcVariant::Glibc { version_hint: None }.name(), "glibc");
        assert_eq!(LibcVariant::Musl.name(), "musl");
        assert_eq!(LibcVariant::Uclibc.name(), "uClibc");
        assert_eq!(LibcVariant::Bionic.name(), "Bionic (Android)");
        assert_eq!(LibcVariant::Newlib.name(), "newlib");
        assert_eq!(LibcVariant::Unknown.name(), "unknown");
    }

    // -----------------------------------------------------------------------
    // StrippedReport tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_stripped_report_default() {
        let r = StrippedReport::default();
        assert!(!r.has_recovered_functions());
        assert_eq!(r.average_function_size(), 0.0);
        assert_eq!(r.confidence, 0);
    }

    #[test]
    fn test_stripped_report_average_function_size() {
        let r = StrippedReport {
            function_boundaries: vec![(0x1000, 0x1040), (0x1050, 0x1090)],
            ..Default::default()
        };
        assert!((r.average_function_size() - 64.0).abs() < 1.0);
    }

    #[test]
    fn test_stripped_report_has_recovered_functions() {
        let r = StrippedReport {
            function_boundaries: vec![(0x1000, 0x1050)],
            ..Default::default()
        };
        assert!(r.has_recovered_functions());
    }

    #[test]
    fn test_stripped_report_summary() {
        let r = StrippedReport {
            is_stripped: true,
            estimated_function_count: 42,
            identified_imports: vec!["malloc".to_string()],
            libc: LibcVariant::Glibc { version_hint: None },
            confidence: 75,
            ..Default::default()
        };
        let s = r.summary();
        assert!(s.contains("stripped=true"));
        assert!(s.contains("functions≈42"));
        assert!(s.contains("imports=1"));
    }

    // -----------------------------------------------------------------------
    // ElfStrippedAnalysis integration tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_elf_stripped_analysis_empty_sections() {
        let names = HashMap::new();
        let report = ElfStrippedAnalysis::analyse(
            &[],
            &PltGotInput { plt_data: &[], plt_base: 0, got_data: &[], got_base: 0, names: &names },
            &[], &[], true, &AnalysisArch::X86_64,
        );
        assert!(report.is_stripped);
        assert_eq!(report.estimated_function_count, 0);
    }

    #[test]
    fn test_elf_stripped_analysis_detects_prologues() {
        // Build a small fake .text section with two function prologues.
        let mut text = vec![0x90u8; 64];
        // Prologue at offset 0 (address 0x401000)
        text[0] = 0x55; text[1] = 0x48; text[2] = 0x89; text[3] = 0xE5;
        // ret at offset 12
        text[12] = 0xC3;
        // Prologue at offset 16 (address 0x401010)
        text[16] = 0x55; text[17] = 0x48; text[18] = 0x89; text[19] = 0xE5;
        // ret at offset 28
        text[28] = 0xC3;

        let names = HashMap::new();
        let report = ElfStrippedAnalysis::analyse(
            &[(&text, 0x0040_1000)],
            &PltGotInput { plt_data: &[], plt_base: 0, got_data: &[], got_base: 0, names: &names },
            &[], &[], true, &AnalysisArch::X86_64,
        );
        assert!(report.estimated_function_count >= 1);
    }

    #[test]
    fn test_elf_stripped_analysis_libc_detected() {
        let names = HashMap::new();
        let report = ElfStrippedAnalysis::analyse(
            &[],
            &PltGotInput { plt_data: &[], plt_base: 0, got_data: &[], got_base: 0, names: &names },
            &["libc.so.6"], &["GNU C Library"], true, &AnalysisArch::X86_64,
        );
        assert!(report.libc.is_glibc());
    }

    #[test]
    fn test_elf_stripped_analysis_confidence_positive() {
        let text = vec![0x55u8, 0x48, 0x89, 0xE5, 0x90, 0x90, 0x90, 0x90,
                             0x90, 0x90, 0x90, 0x90, 0xC9, 0xC3, 0x90, 0x90];
        let names = HashMap::new();
        let report = ElfStrippedAnalysis::analyse(
            &[(&text, 0x0040_1000)],
            &PltGotInput { plt_data: &[], plt_base: 0, got_data: &[], got_base: 0, names: &names },
            &["libc.so.6"], &["GNU C Library"], true, &AnalysisArch::X86_64,
        );
        assert!(report.confidence > 0);
    }
}
