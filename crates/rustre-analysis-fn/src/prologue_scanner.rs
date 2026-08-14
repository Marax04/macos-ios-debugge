//! Function prologue scanner — multi-architecture prologue pattern matching.
//!
//! Combines the `PrologueDb` with a streaming scanner that identifies function
//! starts by detecting well-known byte patterns in a binary.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

// ── ProloguePattern ───────────────────────────────────────────────────────────

/// Target architecture for prologue patterns.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TargetArch {
    X86_32,
    X86_64,
    Arm32,
    Arm64,
    Mips,
    RiscV,
    Unknown,
}

impl std::fmt::Display for TargetArch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

/// A single function prologue pattern with metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProloguePattern {
    /// Target architecture.
    pub arch: TargetArch,
    /// Raw pattern bytes. Bytes matching `mask == 0x00` are wildcards.
    pub bytes: Vec<u8>,
    /// Per-byte mask: `0xff` = exact, `0x00` = wildcard.
    pub mask: Vec<u8>,
    /// Human-readable description of this prologue type.
    pub description: String,
    /// Confidence score (0.0–1.0) when this pattern matches.
    pub confidence: f32,
}

impl ProloguePattern {
    /// # Panics
    ///
    /// Panics if `bytes.len() != mask.len()`.
    pub fn new(
        arch: TargetArch,
        bytes: Vec<u8>,
        mask: Vec<u8>,
        description: impl Into<String>,
        confidence: f32,
    ) -> Self {
        assert_eq!(
            bytes.len(),
            mask.len(),
            "bytes and mask must have equal length"
        );
        Self {
            arch,
            bytes,
            mask,
            description: description.into(),
            confidence,
        }
    }

    /// Build a fully-exact pattern from a hex pattern string like `"55 8B EC"`.
    ///
    /// # Errors
    ///
    /// Returns an error if any token in `hex` is not valid hexadecimal.
    pub fn from_exact(
        arch: TargetArch,
        hex: &str,
        description: impl Into<String>,
        confidence: f32,
    ) -> Result<Self, String> {
        let bytes: Vec<u8> = hex
            .split_whitespace()
            .map(|t| u8::from_str_radix(t, 16).map_err(|e| format!("invalid hex token `{t}`: {e}")))
            .collect::<Result<_, _>>()?;
        let mask = vec![0xffu8; bytes.len()];
        Ok(Self::new(arch, bytes, mask, description, confidence))
    }

    /// Build a pattern with wildcards using `??` tokens.
    ///
    /// # Errors
    ///
    /// Returns an error if any non-wildcard token in `pattern` is not valid hexadecimal.
    pub fn from_pattern_str(
        arch: TargetArch,
        pattern: &str,
        description: impl Into<String>,
        confidence: f32,
    ) -> Result<Self, String> {
        let mut bytes = Vec::new();
        let mut mask = Vec::new();
        for token in pattern.split_whitespace() {
            if token == "??" || token == ".." {
                bytes.push(0x00);
                mask.push(0x00);
            } else {
                bytes.push(
                    u8::from_str_radix(token, 16)
                        .map_err(|e| format!("invalid hex token `{token}`: {e}"))?,
                );
                mask.push(0xff);
            }
        }
        Ok(Self::new(arch, bytes, mask, description, confidence))
    }

    /// Return `true` if this pattern matches at the beginning of `data`.
    #[must_use]
    pub fn matches(&self, data: &[u8]) -> bool {
        if data.len() < self.bytes.len() {
            return false;
        }
        self.bytes
            .iter()
            .zip(self.mask.iter())
            .zip(data.iter())
            .all(|((&b, &m), &d)| m == 0 || b == d)
    }

    /// Return the number of concrete (non-wildcard) bytes.
    #[must_use]
    pub fn concrete_bytes(&self) -> usize {
        self.mask.iter().filter(|&&m| m != 0).count()
    }
}

impl std::fmt::Display for ProloguePattern {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "[{}] {} (conf={:.2})",
            self.arch, self.description, self.confidence
        )
    }
}

// ── PrologueDb ────────────────────────────────────────────────────────────────

/// Database of known function prologue patterns for multiple architectures.
pub struct PrologueDb {
    patterns: Vec<ProloguePattern>,
}

impl PrologueDb {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            patterns: Vec::new(),
        }
    }

    pub fn add(&mut self, p: ProloguePattern) {
        self.patterns.push(p);
    }

    #[must_use]
    pub const fn len(&self) -> usize {
        self.patterns.len()
    }
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.patterns.is_empty()
    }

    /// Return all patterns for a specific architecture.
    #[must_use]
    pub fn for_arch(&self, arch: TargetArch) -> Vec<&ProloguePattern> {
        self.patterns.iter().filter(|p| p.arch == arch).collect()
    }

    /// Build the default database with 50+ patterns.
    #[must_use]
    pub fn with_defaults() -> Self {
        let mut db = Self::new();
        Self::add_x86_64_patterns(&mut db);
        Self::add_x86_32_patterns(&mut db);
        Self::add_arm64_patterns(&mut db);
        Self::add_arm32_patterns(&mut db);
        Self::add_mips_patterns(&mut db);
        Self::add_riscv_patterns(&mut db);
        db.patterns.sort_by(|a, b| {
            b.confidence
                .partial_cmp(&a.confidence)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        db
    }

    fn add_x86_64_patterns(db: &mut Self) {
        const PATTERNS: &[(&str, &str, f32)] = &[
            (
                "55 48 89 E5",
                "push rbp; mov rbp, rsp (classic x86-64 frame)",
                0.95,
            ),
            (
                "55 41 57 41 56",
                "push rbp; push r15; push r14 (callee-saved)",
                0.85,
            ),
            ("48 83 EC", "sub rsp, N (leaf/stack allocation)", 0.80),
            ("55 48 89 E5 48 83 EC ??", "frame setup + stack alloc", 0.92),
            (
                "41 57 41 56 41 55 41 54",
                "push r15-r12 (callee-saved block)",
                0.88,
            ),
            ("53 55 41 54", "push rbx, rbp, r12 (fastcall variant)", 0.82),
            (
                "55 48 89 E5 ?? ?? ?? 48 89 5D ??",
                "frame + spill rbx",
                0.87,
            ),
            ("C3", "single-byte ret (tiny leaf)", 0.30),
            ("F3 0F 1E FA 55 48 89 E5", "endbr64 + classic frame", 0.96),
            ("65 48 8B 04 25 28 00 00 00", "GS canary read", 0.93),
            (
                "55 48 89 E5 48 ?? ?? ?? ?? 64 48 8B",
                "frame + GS canary",
                0.94,
            ),
            ("E8 00 00 00 00 58", "call $+5; pop rax (PIC stub)", 0.78),
            (
                "55 48 89 E5 E8 ?? ?? ?? ??",
                "frame + immediate call (constructor chain)",
                0.83,
            ),
        ];
        for &(pattern, description, confidence) in PATTERNS {
            db.add(
                ProloguePattern::from_pattern_str(
                    TargetArch::X86_64,
                    pattern,
                    description,
                    confidence,
                )
                .expect("builtin pattern is valid"),
            );
        }
    }

    fn add_x86_32_patterns(db: &mut Self) {
        db.add(
            ProloguePattern::from_exact(
                TargetArch::X86_32,
                "55 8B EC",
                "push ebp; mov ebp, esp (classic)",
                0.95,
            )
            .expect("builtin pattern is valid"),
        );
        db.add(
            ProloguePattern::from_pattern_str(
                TargetArch::X86_32,
                "55 8B EC 83 EC ??",
                "classic frame + local alloc",
                0.93,
            )
            .expect("builtin pattern is valid"),
        );
        db.add(
            ProloguePattern::from_pattern_str(
                TargetArch::X86_32,
                "55 8B EC 51",
                "classic frame + push ecx (fastcall)",
                0.88,
            )
            .expect("builtin pattern is valid"),
        );
        db.add(
            ProloguePattern::from_exact(
                TargetArch::X86_32,
                "8B FF 55 8B EC",
                "mov edi, edi stub + classic (MSVC hotpatch)",
                0.97,
            )
            .expect("builtin pattern is valid"),
        );
        db.add(
            ProloguePattern::from_exact(
                TargetArch::X86_32,
                "55 8B EC 56 57",
                "classic + push esi + push edi",
                0.85,
            )
            .expect("builtin pattern is valid"),
        );
        db.add(
            ProloguePattern::from_exact(
                TargetArch::X86_32,
                "55 8B EC 53 56 57",
                "classic + push ebx, esi, edi",
                0.86,
            )
            .expect("builtin pattern is valid"),
        );
        db.add(
            ProloguePattern::from_pattern_str(
                TargetArch::X86_32,
                "55 8B EC ?? ?? 64 A1 00 00 00 00",
                "classic + SEH setup",
                0.92,
            )
            .expect("builtin pattern is valid"),
        );
        db.add(
            ProloguePattern::from_pattern_str(
                TargetArch::X86_32,
                "55 8B EC 83 EC ?? 8B 45 ??",
                "classic + alloc + first arg load",
                0.84,
            )
            .expect("builtin pattern is valid"),
        );
        db.add(
            ProloguePattern::from_exact(
                TargetArch::X86_32,
                "55 8B EC 83 7D 08 00",
                "classic + argc check (main-style)",
                0.80,
            )
            .expect("builtin pattern is valid"),
        );
        db.add(
            ProloguePattern::from_exact(
                TargetArch::X86_32,
                "55 8B EC E8 00 00 00 00 58",
                "classic + PIC thunk",
                0.78,
            )
            .expect("builtin pattern is valid"),
        );
        db.add(
            ProloguePattern::from_pattern_str(
                TargetArch::X86_32,
                "55 8B EC 83 EC ?? A1 ?? ?? ?? ??",
                "classic + alloca canary",
                0.90,
            )
            .expect("builtin pattern is valid"),
        );
    }

    fn add_arm64_patterns(db: &mut Self) {
        db.add(
            ProloguePattern::from_pattern_str(
                TargetArch::Arm64,
                "?? ?? BF A9 ?? ?? BE A9",
                "stp x29, x30, ... (AArch64 frame)",
                0.94,
            )
            .expect("builtin pattern is valid"),
        );
        db.add(
            ProloguePattern::from_exact(
                TargetArch::Arm64,
                "FD 7B BF A9 FD 03 00 91",
                "stp x29, x30, [sp, #-16]!; mov x29, sp",
                0.95,
            )
            .expect("builtin pattern is valid"),
        );
        db.add(
            ProloguePattern::from_pattern_str(
                TargetArch::Arm64,
                "?? ?? BE A9 FD 7B 01 A9",
                "callee-save pair + frame",
                0.88,
            )
            .expect("builtin pattern is valid"),
        );
        db.add(
            ProloguePattern::from_exact(
                TargetArch::Arm64,
                "FF 83 00 D1",
                "sub sp, sp, #32 (leaf)",
                0.80,
            )
            .expect("builtin pattern is valid"),
        );
        db.add(
            ProloguePattern::from_pattern_str(
                TargetArch::Arm64,
                "FD 7B BF A9 ?? ?? BF A9 FD 03 00 91",
                "large callee-save frame",
                0.92,
            )
            .expect("builtin pattern is valid"),
        );
        db.add(
            ProloguePattern::from_exact(
                TargetArch::Arm64,
                "C0 03 5F D6",
                "ret (tiny leaf / tail-call)",
                0.35,
            )
            .expect("builtin pattern is valid"),
        );
    }

    fn add_arm32_patterns(db: &mut Self) {
        db.add(
            ProloguePattern::from_exact(
                TargetArch::Arm32,
                "00 48 2D E9",
                "push {r11, lr} (ARM frame)",
                0.90,
            )
            .expect("builtin pattern is valid"),
        );
        db.add(
            ProloguePattern::from_exact(
                TargetArch::Arm32,
                "10 B5",
                "push {r4, lr} (Thumb-2 leaf)",
                0.85,
            )
            .expect("builtin pattern is valid"),
        );
        db.add(
            ProloguePattern::from_exact(
                TargetArch::Arm32,
                "F0 B5",
                "push {r4-r7, lr} (Thumb-2 frame)",
                0.88,
            )
            .expect("builtin pattern is valid"),
        );
        db.add(
            ProloguePattern::from_exact(
                TargetArch::Arm32,
                "30 B5",
                "push {r4, r5, lr} (Thumb-2)",
                0.83,
            )
            .expect("builtin pattern is valid"),
        );
        db.add(
            ProloguePattern::from_exact(
                TargetArch::Arm32,
                "70 B5",
                "push {r4, r5, r6, lr} (Thumb-2)",
                0.85,
            )
            .expect("builtin pattern is valid"),
        );
        db.add(
            ProloguePattern::from_pattern_str(
                TargetArch::Arm32,
                "00 48 2D E9 00 D8 4D E2",
                "ARM frame + sp alignment",
                0.87,
            )
            .expect("builtin pattern is valid"),
        );
        db.add(
            ProloguePattern::from_exact(
                TargetArch::Arm32,
                "80 B4 80 B4",
                "push {r7}; push {r7} (Thumb-16 large frame)",
                0.70,
            )
            .expect("builtin pattern is valid"),
        );
        db.add(
            ProloguePattern::from_exact(
                TargetArch::Arm32,
                "80 BD",
                "pop {r7, pc} (Thumb-16 return)",
                0.40,
            )
            .expect("builtin pattern is valid"),
        );
    }

    fn add_mips_patterns(db: &mut Self) {
        db.add(
            ProloguePattern::from_exact(
                TargetArch::Mips,
                "27 BD FF E0",
                "addiu sp, sp, -32 (classic MIPS frame)",
                0.90,
            )
            .expect("builtin pattern is valid"),
        );
        db.add(
            ProloguePattern::from_exact(TargetArch::Mips, "27 BD FF D0", "addiu sp, sp, -48", 0.88)
                .expect("builtin pattern is valid"),
        );
        db.add(
            ProloguePattern::from_pattern_str(
                TargetArch::Mips,
                "27 BD ?? ?? AF BF ??",
                "addiu sp + sw ra (MIPS frame)",
                0.92,
            )
            .expect("builtin pattern is valid"),
        );
        db.add(
            ProloguePattern::from_exact(
                TargetArch::Mips,
                "3C 1C 00 00 03 99 E0 21",
                "lui gp; addu gp, gp, t9 (PIC prolog)",
                0.85,
            )
            .expect("builtin pattern is valid"),
        );
        db.add(
            ProloguePattern::from_pattern_str(
                TargetArch::Mips,
                "27 BD ?? ?? AF B1 ??",
                "MIPS frame + save s1",
                0.88,
            )
            .expect("builtin pattern is valid"),
        );
        db.add(
            ProloguePattern::from_exact(
                TargetArch::Mips,
                "27 BD FF F8 AF BF 00 04",
                "tiny MIPS frame",
                0.86,
            )
            .expect("builtin pattern is valid"),
        );
    }

    fn add_riscv_patterns(db: &mut Self) {
        db.add(
            ProloguePattern::from_exact(
                TargetArch::RiscV,
                "13 01 01 FF",
                "addi sp, sp, -16 (RV32 tiny frame)",
                0.88,
            )
            .expect("builtin pattern is valid"),
        );
        db.add(
            ProloguePattern::from_pattern_str(
                TargetArch::RiscV,
                "?? 01 01 FF 23 ?? 11 00",
                "addi sp + sd ra (RV64 frame)",
                0.92,
            )
            .expect("builtin pattern is valid"),
        );
        db.add(
            ProloguePattern::from_exact(
                TargetArch::RiscV,
                "13 01 01 FE",
                "addi sp, sp, -32 (RV32 frame)",
                0.88,
            )
            .expect("builtin pattern is valid"),
        );
        db.add(
            ProloguePattern::from_pattern_str(
                TargetArch::RiscV,
                "?? 01 01 FE 23 ?? 81 02",
                "RV64 frame + sd s0",
                0.90,
            )
            .expect("builtin pattern is valid"),
        );
        db.add(
            ProloguePattern::from_exact(
                TargetArch::RiscV,
                "82 80",
                "ret (c.jr ra Thumb equivalent)",
                0.35,
            )
            .expect("builtin pattern is valid"),
        );
        db.add(
            ProloguePattern::from_pattern_str(
                TargetArch::RiscV,
                "13 01 ?? FD 23 3C 11 02",
                "RV64 large frame",
                0.87,
            )
            .expect("builtin pattern is valid"),
        );
    }

    /// Match all patterns against `data` at offset 0.
    #[must_use]
    pub fn match_at(&self, data: &[u8]) -> Vec<&ProloguePattern> {
        self.patterns.iter().filter(|p| p.matches(data)).collect()
    }

    /// Find the best (highest-confidence) matching pattern at the start of `data`.
    #[must_use]
    pub fn best_match(&self, data: &[u8]) -> Option<&ProloguePattern> {
        self.patterns
            .iter()
            .filter(|p| p.matches(data))
            .max_by(|a, b| {
                a.confidence
                    .partial_cmp(&b.confidence)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
    }
}

impl Default for PrologueDb {
    fn default() -> Self {
        Self::with_defaults()
    }
}

// ── ScanMatch ─────────────────────────────────────────────────────────────────

/// A prologue match found during a binary scan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanMatch {
    pub offset: u64,
    pub pattern_description: String,
    pub arch: TargetArch,
    pub confidence: f32,
    pub match_len: usize,
}

impl ScanMatch {
    #[must_use]
    pub fn new(offset: u64, pattern: &ProloguePattern) -> Self {
        Self {
            offset,
            pattern_description: pattern.description.clone(),
            arch: pattern.arch,
            confidence: pattern.confidence,
            match_len: pattern.bytes.len(),
        }
    }
}

impl std::fmt::Display for ScanMatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{:#x}: [{}] {} (conf={:.2})",
            self.offset, self.arch, self.pattern_description, self.confidence
        )
    }
}

// ── PrologueScanner ───────────────────────────────────────────────────────────

/// Scans a binary for function prologues using a [`PrologueDb`].
pub struct PrologueScanner {
    db: PrologueDb,
    /// Minimum confidence threshold for reporting a match.
    pub min_confidence: f32,
    /// Byte alignment for scan stride (1 = byte-by-byte, 4 = word-aligned).
    pub alignment: usize,
    /// Only scan for patterns from this architecture (None = all).
    pub arch_filter: Option<TargetArch>,
}

impl PrologueScanner {
    #[must_use]
    pub const fn new(db: PrologueDb) -> Self {
        Self {
            db,
            min_confidence: 0.5,
            alignment: 1,
            arch_filter: None,
        }
    }

    #[must_use]
    pub const fn for_arch(mut self, arch: TargetArch) -> Self {
        self.arch_filter = Some(arch);
        self
    }

    #[must_use]
    pub const fn with_min_confidence(mut self, conf: f32) -> Self {
        self.min_confidence = conf;
        self
    }

    #[must_use]
    pub fn with_alignment(mut self, align: usize) -> Self {
        self.alignment = align.max(1);
        self
    }

    /// Scan `binary` and return all prologue matches.
    #[must_use]
    pub fn scan(&self, binary: &[u8]) -> Vec<ScanMatch> {
        let mut results = Vec::new();
        let mut offset = 0usize;
        while offset < binary.len() {
            let slice = &binary[offset..];
            let candidates: Vec<&ProloguePattern> = self
                .db
                .patterns
                .iter()
                .filter(|p| {
                    if let Some(arch) = self.arch_filter
                        && p.arch != arch
                    {
                        return false;
                    }
                    p.confidence >= self.min_confidence && p.matches(slice)
                })
                .collect();

            if let Some(best) = candidates.iter().max_by(|a, b| {
                a.confidence
                    .partial_cmp(&b.confidence)
                    .unwrap_or(std::cmp::Ordering::Equal)
            }) {
                results.push(ScanMatch::new(offset as u64, best));
            }

            offset += self.alignment;
        }
        results
    }

    /// Scan and deduplicate: keep only the highest-confidence match per address.
    #[must_use]
    pub fn scan_deduplicated(&self, binary: &[u8]) -> Vec<ScanMatch> {
        let mut raw = self.scan(binary);
        raw.sort_by(|a, b| {
            b.confidence
                .partial_cmp(&a.confidence)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        let mut seen_offsets = std::collections::HashSet::new();
        raw.retain(|m| seen_offsets.insert(m.offset));
        raw.sort_by_key(|m| m.offset);
        raw
    }

    /// Count matches per architecture.
    #[must_use]
    pub fn arch_histogram(&self, binary: &[u8]) -> HashMap<String, usize> {
        let mut hist: HashMap<String, usize> = HashMap::new();
        for m in self.scan(binary) {
            *hist.entry(format!("{:?}", m.arch)).or_insert(0) += 1;
        }
        hist
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn x64_classic() -> Vec<u8> {
        vec![0x55, 0x48, 0x89, 0xE5, 0x48, 0x83, 0xEC, 0x20]
    }

    fn x86_classic() -> Vec<u8> {
        vec![0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x10, 0x00, 0x00]
    }

    fn arm64_frame() -> Vec<u8> {
        vec![0xFD, 0x7B, 0xBF, 0xA9, 0xFD, 0x03, 0x00, 0x91]
    }

    // ── ProloguePattern ───────────────────────────────────────────────────────

    #[test]
    fn test_pattern_from_exact_matches() {
        let p = ProloguePattern::from_exact(TargetArch::X86_64, "55 48 89 E5", "test", 0.9)
            .expect("valid pattern");
        assert!(p.matches(&x64_classic()));
    }

    #[test]
    fn test_pattern_exact_no_match() {
        let p = ProloguePattern::from_exact(TargetArch::X86_64, "55 48 89 E5", "test", 0.9)
            .expect("valid pattern");
        assert!(!p.matches(&[0x00, 0x00, 0x00, 0x00]));
    }

    #[test]
    fn test_pattern_wildcard_matches() {
        let p = ProloguePattern::from_pattern_str(TargetArch::X86_64, "55 ?? 89 E5", "test", 0.8)
            .expect("valid pattern");
        assert!(p.matches(&[0x55, 0xFF, 0x89, 0xE5, 0x00]));
    }

    #[test]
    fn test_pattern_too_short() {
        let p = ProloguePattern::from_exact(TargetArch::X86_32, "55 8B EC", "test", 0.9)
            .expect("valid pattern");
        assert!(!p.matches(&[0x55, 0x8B]));
    }

    #[test]
    fn test_pattern_concrete_bytes_exact() {
        let p = ProloguePattern::from_exact(TargetArch::X86_64, "55 48 89 E5", "test", 0.9)
            .expect("valid pattern");
        assert_eq!(p.concrete_bytes(), 4);
    }

    #[test]
    fn test_pattern_concrete_bytes_with_wildcard() {
        let p = ProloguePattern::from_pattern_str(TargetArch::X86_64, "55 ?? 89 E5", "test", 0.8)
            .expect("valid pattern");
        assert_eq!(p.concrete_bytes(), 3);
    }

    #[test]
    fn test_pattern_display() {
        let p = ProloguePattern::from_exact(TargetArch::X86_64, "55 48 89 E5", "classic", 0.95)
            .expect("valid pattern");
        let s = p.to_string();
        assert!(s.contains("X86_64"));
        assert!(s.contains("classic"));
    }

    // ── PrologueDb ────────────────────────────────────────────────────────────

    #[test]
    fn test_db_defaults_have_50_plus_patterns() {
        let db = PrologueDb::with_defaults();
        assert!(db.len() >= 50, "expected ≥50 patterns, got {}", db.len());
    }

    #[test]
    fn test_db_for_arch_x86_64() {
        let db = PrologueDb::with_defaults();
        let pats = db.for_arch(TargetArch::X86_64);
        assert!(!pats.is_empty());
    }

    #[test]
    fn test_db_for_arch_arm64() {
        let db = PrologueDb::with_defaults();
        let pats = db.for_arch(TargetArch::Arm64);
        assert!(!pats.is_empty());
    }

    #[test]
    fn test_db_for_arch_mips() {
        let db = PrologueDb::with_defaults();
        let pats = db.for_arch(TargetArch::Mips);
        assert!(!pats.is_empty());
    }

    #[test]
    fn test_db_for_arch_riscv() {
        let db = PrologueDb::with_defaults();
        let pats = db.for_arch(TargetArch::RiscV);
        assert!(!pats.is_empty());
    }

    #[test]
    fn test_db_match_at_x64() {
        let db = PrologueDb::with_defaults();
        let matches = db.match_at(&x64_classic());
        assert!(!matches.is_empty());
        assert!(matches.iter().any(|p| p.arch == TargetArch::X86_64));
    }

    #[test]
    fn test_db_match_at_x86() {
        let db = PrologueDb::with_defaults();
        let matches = db.match_at(&x86_classic());
        assert!(!matches.is_empty());
        assert!(matches.iter().any(|p| p.arch == TargetArch::X86_32));
    }

    #[test]
    fn test_db_match_at_arm64() {
        let db = PrologueDb::with_defaults();
        let matches = db.match_at(&arm64_frame());
        assert!(!matches.is_empty());
        assert!(matches.iter().any(|p| p.arch == TargetArch::Arm64));
    }

    #[test]
    fn test_db_best_match_x64() {
        let db = PrologueDb::with_defaults();
        let best = db.best_match(&x64_classic()).unwrap();
        assert_eq!(best.arch, TargetArch::X86_64);
        assert!(best.confidence >= 0.9);
    }

    #[test]
    fn test_db_no_match_zeros() {
        let db = PrologueDb::with_defaults();
        let matches = db.match_at(&[0x00u8; 16]);
        assert!(matches.is_empty());
    }

    // ── PrologueScanner ───────────────────────────────────────────────────────

    #[test]
    fn test_scanner_finds_x64_prologue() {
        let db = PrologueDb::with_defaults();
        let scanner = PrologueScanner::new(db)
            .for_arch(TargetArch::X86_64)
            .with_min_confidence(0.8);
        let binary: Vec<u8> = [0x00u8; 16]
            .iter()
            .chain(x64_classic().iter())
            .copied()
            .collect();
        let matches = scanner.scan(&binary);
        assert!(!matches.is_empty());
        let found = matches.iter().any(|m| m.offset == 16);
        assert!(found, "expected match at offset 16");
    }

    #[test]
    fn test_scanner_alignment_4() {
        let db = PrologueDb::with_defaults();
        let scanner = PrologueScanner::new(db)
            .for_arch(TargetArch::X86_64)
            .with_alignment(4)
            .with_min_confidence(0.9);
        let mut binary = vec![0x00u8; 4];
        binary.extend_from_slice(&x64_classic());
        let matches = scanner.scan(&binary);
        assert!(!matches.is_empty());
        assert_eq!(matches[0].offset, 4);
    }

    #[test]
    fn test_scanner_min_confidence_filters() {
        let db = PrologueDb::with_defaults();
        let scanner = PrologueScanner::new(db).with_min_confidence(0.99);
        // F3 0F 1E FA 55 48 89 E5 = endbr64 + classic = 0.96 confidence.
        let binary = vec![0xF3, 0x0F, 0x1E, 0xFA, 0x55, 0x48, 0x89, 0xE5];
        let matches = scanner.scan(&binary);
        // Should be empty since best confidence ≈ 0.96 < 0.99.
        assert!(matches.iter().all(|m| m.confidence >= 0.99));
    }

    #[test]
    fn test_scanner_deduplication() {
        let db = PrologueDb::with_defaults();
        let scanner = PrologueScanner::new(db).for_arch(TargetArch::X86_32);
        let binary = x86_classic();
        let dedup = scanner.scan_deduplicated(&binary);
        let raw = PrologueScanner::new(PrologueDb::with_defaults())
            .for_arch(TargetArch::X86_32)
            .scan(&binary);
        // Deduplication should not produce more results than the raw scan.
        assert!(dedup.len() <= raw.len());
    }

    #[test]
    fn test_scanner_arch_histogram() {
        let db = PrologueDb::with_defaults();
        let scanner = PrologueScanner::new(db);
        let mut binary = x64_classic();
        binary.extend_from_slice(&x86_classic());
        let hist = scanner.arch_histogram(&binary);
        assert!(!hist.is_empty());
    }

    #[test]
    fn test_scan_match_display() {
        let db = PrologueDb::with_defaults();
        let best = db.best_match(&x64_classic()).unwrap();
        let m = ScanMatch::new(0x1000, best);
        let s = m.to_string();
        assert!(s.contains("0x1000"));
    }

    #[test]
    fn test_target_arch_display() {
        assert_eq!(TargetArch::X86_64.to_string(), "X86_64");
        assert_eq!(TargetArch::Arm64.to_string(), "Arm64");
    }
}
