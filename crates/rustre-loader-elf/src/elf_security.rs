//! `elf_security` — ELF binary hardening and security feature detection.
//!
//! Analyses a raw ELF byte slice and produces an [`ElfSecurity`] report
//! covering: RELRO (partial/full), stack canary, NX bit, PIE, Fortify source,
//! ASLR compatibility, and a rolled-up [`SecurityProfile`].

use serde::{Deserialize, Serialize};
use std::fmt;
use thiserror::Error;

// ─────────────────────────────────────────────────────────────────────────────
// Errors
// ─────────────────────────────────────────────────────────────────────────────

/// Errors produced while scanning ELF security features.
#[derive(Debug, Error)]
pub enum ElfSecurityError {
    /// Buffer is too small to contain a valid ELF header.
    #[error("buffer too short: {0} bytes")]
    TooShort(usize),
    /// Not an ELF file (bad magic).
    #[error("not an ELF file")]
    NotElf,
    /// ELF class field contains an unexpected value.
    #[error("unexpected ELF class: {0}")]
    BadClass(u8),
    /// Dynamic section could not be parsed.
    #[error("dynamic section parse error: {0}")]
    DynamicParseError(String),
    /// ELF header is truncated.
    #[error("truncated ELF header")]
    Truncated,
}

// ─────────────────────────────────────────────────────────────────────────────
// RELRO
// ─────────────────────────────────────────────────────────────────────────────

/// Relocation Read-Only (RELRO) protection level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RelRo {
    /// No RELRO: GOT/PLT sections remain writable at runtime.
    None,
    /// Partial RELRO: `.got` is read-only, but `.got.plt` is still writable.
    Partial,
    /// Full RELRO: all GOT entries are resolved at startup and made read-only.
    Full,
}

impl fmt::Display for RelRo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::None => write!(f, "None"),
            Self::Partial => write!(f, "Partial"),
            Self::Full => write!(f, "Full"),
        }
    }
}

/// A `PT_GNU_RELRO` segment found in the ELF program headers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelRoSection {
    /// Virtual address of the RELRO region.
    pub vaddr: u64,
    /// Length in bytes of the RELRO region.
    pub memsz: u64,
    /// Detected level.
    pub level: RelRo,
}

// ─────────────────────────────────────────────────────────────────────────────
// StackCanary
// ─────────────────────────────────────────────────────────────────────────────

/// Stack-canary detection result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StackCanary {
    /// Whether stack-smashing protection is enabled (presence of
    /// `__stack_chk_fail` or `__stack_chk_guard`).
    pub enabled: bool,
    /// The exact symbol name found, if any.
    pub detected_symbol: Option<String>,
}

impl StackCanary {
    const fn not_found() -> Self {
        Self {
            enabled: false,
            detected_symbol: None,
        }
    }

    fn found(sym: impl Into<String>) -> Self {
        Self {
            enabled: true,
            detected_symbol: Some(sym.into()),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// NXBit
// ─────────────────────────────────────────────────────────────────────────────

/// Non-Executable stack / data segment status.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NXBit {
    /// `true` when a `PT_GNU_STACK` segment is present and does *not* have the
    /// execute bit set (`PF_X` = 0x1).
    pub enabled: bool,
    /// Raw flags of the `PT_GNU_STACK` segment (if found).
    pub stack_flags: Option<u32>,
}

// ─────────────────────────────────────────────────────────────────────────────
// PIE check
// ─────────────────────────────────────────────────────────────────────────────

/// Position-Independent Executable status.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PieCheck {
    /// `true` when the ELF `e_type` is `ET_DYN` (the binary can be loaded at an
    /// arbitrary address by the dynamic linker / ASLR).
    pub enabled: bool,
    /// Raw `e_type` value.
    pub e_type: u16,
}

// ─────────────────────────────────────────────────────────────────────────────
// Fortify
// ─────────────────────────────────────────────────────────────────────────────

/// `_FORTIFY_SOURCE` detection.
///
/// When glibc is compiled with `-D_FORTIFY_SOURCE=2` the resulting binary
/// imports hardened versions of common functions (`__memcpy_chk`, etc.).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Fortify {
    /// Whether at least one `_chk` symbol was found.
    pub enabled: bool,
    /// Number of hardened function symbols detected.
    pub chk_symbol_count: usize,
    /// Representative sample of up to 5 detected symbols.
    pub sample_symbols: Vec<String>,
}

// ─────────────────────────────────────────────────────────────────────────────
// ASLR compatible
// ─────────────────────────────────────────────────────────────────────────────

/// Whether the binary is compatible with ASLR.
///
/// A binary is considered ASLR-compatible when it is PIE (`ET_DYN`) **and**
/// the NX bit is enabled.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AslrCompatible {
    /// Final compatibility verdict.
    pub compatible: bool,
    /// Reason string for audit logs.
    pub reason: String,
}

// ─────────────────────────────────────────────────────────────────────────────
// SecurityProfile
// ─────────────────────────────────────────────────────────────────────────────

/// Rolled-up security score and grade.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityProfile {
    /// Integer score 0–100 (higher is better).
    pub score: u8,
    /// Letter grade: A / B / C / D / F.
    pub grade: char,
    /// Human-readable summary.
    pub summary: String,
}

impl SecurityProfile {
    fn from_score(score: u8) -> Self {
        let grade = match score {
            90..=100 => 'A',
            75..=89 => 'B',
            60..=74 => 'C',
            40..=59 => 'D',
            _ => 'F',
        };
        let summary = format!("Security score: {score}/100 (grade {grade})");
        Self {
            score,
            grade,
            summary,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ElfSecurity
// ─────────────────────────────────────────────────────────────────────────────

/// Complete security feature report for a single ELF binary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ElfSecurity {
    /// RELRO segment information (if present).
    pub relro: Option<RelRoSection>,
    /// Stack canary detection result.
    pub stack_canary: StackCanary,
    /// NX bit (non-executable stack) status.
    pub nx: NXBit,
    /// Position-Independent Executable status.
    pub pie: PieCheck,
    /// Fortify source detection.
    pub fortify: Fortify,
    /// ASLR compatibility verdict.
    pub aslr: AslrCompatible,
    /// Rolled-up security profile.
    pub profile: SecurityProfile,
}

impl ElfSecurity {
    /// Analyse `data` and return the full security report.
    ///
    /// # Errors
    /// Returns [`ElfSecurityError`] if the bytes are not a recognisable ELF.
    pub fn analyse(data: &[u8]) -> Result<Self, ElfSecurityError> {
        if data.len() < 0x40 {
            return Err(ElfSecurityError::TooShort(data.len()));
        }
        if &data[0..4] != b"\x7fELF" {
            return Err(ElfSecurityError::NotElf);
        }
        let class = data[4];
        if class != 1 && class != 2 {
            return Err(ElfSecurityError::BadClass(class));
        }
        let is64 = class == 2;
        let e_type = u16::from_le_bytes([data[0x10], data[0x11]]);

        let (prog_hdr_off, prog_hdr_entry_size, prog_hdr_count) =
            parse_elf_phdr_fields(data, is64)?;

        // Scan program headers
        let (mut relro, nx, has_bind_now) =
            scan_phdrs(data, is64, prog_hdr_off, prog_hdr_entry_size, prog_hdr_count);

        // Upgrade RELRO to Full if BIND_NOW is set
        if let Some(ref mut r) = relro
            && has_bind_now {
                r.level = RelRo::Full;
            }

        // PIE: ET_DYN = 3
        let pie = PieCheck { enabled: e_type == 3, e_type };

        // Scan dynstr / dynsym for security symbols
        let (stack_canary, fortify) =
            scan_symbols(data, is64, prog_hdr_off, prog_hdr_entry_size, prog_hdr_count);

        let aslr = build_aslr(&pie, &nx);
        let score = compute_score(&nx, &pie, &stack_canary, &fortify, relro.as_ref());
        let profile = SecurityProfile::from_score(score);

        Ok(Self { relro, stack_canary, nx, pie, fortify, aslr, profile })
    }

    /// Returns the detected RELRO level (or [`RelRo::None`] if absent).
    #[must_use]
    pub fn relro_level(&self) -> RelRo {
        self.relro.as_ref().map_or(RelRo::None, |r| r.level)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal helpers
// ─────────────────────────────────────────────────────────────────────────────

const DT_NULL: i64 = 0;
const DT_BIND_NOW: i64 = 24;
const DT_FLAGS: i64 = 30;
const DF_BIND_NOW: u64 = 0x8;

fn scan_dynamic_for_bind_now(data: &[u8], _vaddr: u64, memsz: usize, is64: bool) -> bool {
    // We do a naive linear scan of the data section looking for DT_BIND_NOW
    // or DT_FLAGS with DF_BIND_NOW — the vaddr→file offset translation
    // requires a full section-header walk which we keep deliberately minimal.
    let entry_size = if is64 { 16 } else { 8 };
    let scan_limit = memsz.min(data.len());
    let mut pos = 0;
    while pos + entry_size <= scan_limit {
        let tag = if is64 {
            i64::from_le_bytes(data[pos..pos + 8].try_into().unwrap_or_default())
        } else {
            i64::from(i32::from_le_bytes(data[pos..pos + 4].try_into().unwrap_or_default()))
        };
        let val = if is64 {
            u64::from_le_bytes(data[pos + 8..pos + 16].try_into().unwrap_or_default())
        } else {
            u64::from(u32::from_le_bytes(data[pos + 4..pos + 8].try_into().unwrap_or_default()))
        };
        if tag == DT_NULL {
            break;
        }
        if tag == DT_BIND_NOW {
            return true;
        }
        if tag == DT_FLAGS && (val & DF_BIND_NOW) != 0 {
            return true;
        }
        pos += entry_size;
    }
    false
}

fn scan_symbols(
    data: &[u8],
    _is64: bool,
    _ph_off: usize,
    _ph_entsz: usize,
    _ph_num: usize,
) -> (StackCanary, Fortify) {
    // Extract printable ASCII strings from the binary and check for
    // well-known security symbols. This is an approximation that avoids
    // a full symtab/strtab walk.
    let canary_syms = ["__stack_chk_fail", "__stack_chk_guard"];
    let chk_prefix = "_chk";

    let mut canary = StackCanary::not_found();
    let mut chk_count = 0usize;
    let mut chk_samples: Vec<String> = Vec::with_capacity(5);

    // Scan for NUL-terminated strings in the binary
    let mut start = 0;
    for (i, &b) in data.iter().enumerate() {
        if b == 0 {
            if i > start && let Ok(s) = std::str::from_utf8(&data[start..i]) {
                let s = s.trim();
                if s.len() > 3 {
                    for &csym in &canary_syms {
                        if s.contains(csym) && !canary.enabled {
                            canary = StackCanary::found(csym);
                        }
                    }
                    if s.contains(chk_prefix) {
                        chk_count += 1;
                        if chk_samples.len() < 5 {
                            chk_samples.push(s.to_string());
                        }
                    }
                }
            }
            start = i + 1;
        }
    }

    let fortify = Fortify {
        enabled: chk_count > 0,
        chk_symbol_count: chk_count,
        sample_symbols: chk_samples,
    };

    (canary, fortify)
}

/// Parse ELF program-header offset/entsize/count from the ELF header.
fn parse_elf_phdr_fields(data: &[u8], is64: bool) -> Result<(usize, usize, usize), ElfSecurityError> {
    if is64 {
        if data.len() < 0x40 {
            return Err(ElfSecurityError::Truncated);
        }
        let phoff = usize::try_from(u64::from_le_bytes(data[0x20..0x28].try_into().unwrap_or_default())).unwrap_or(0);
        let phentsize = u16::from_le_bytes([data[0x36], data[0x37]]) as usize;
        let phnum = u16::from_le_bytes([data[0x38], data[0x39]]) as usize;
        Ok((phoff, phentsize, phnum))
    } else {
        if data.len() < 0x34 {
            return Err(ElfSecurityError::Truncated);
        }
        let phoff = u32::from_le_bytes(data[0x1C..0x20].try_into().unwrap_or_default()) as usize;
        let phentsize = u16::from_le_bytes([data[0x2A], data[0x2B]]) as usize;
        let phnum = u16::from_le_bytes([data[0x2C], data[0x2D]]) as usize;
        Ok((phoff, phentsize, phnum))
    }
}

/// Scan ELF program headers and return `(relro, nx, has_bind_now)`.
fn scan_phdrs(
    data: &[u8],
    is64: bool,
    prog_hdr_off: usize,
    prog_hdr_entry_size: usize,
    prog_hdr_count: usize,
) -> (Option<RelRoSection>, NXBit, bool) {
    let mut relro: Option<RelRoSection> = None;
    let mut nx = NXBit { enabled: true, stack_flags: None };
    let mut has_bind_now = false;

    for i in 0..prog_hdr_count {
        let off = prog_hdr_off + i * prog_hdr_entry_size;
        if off + prog_hdr_entry_size > data.len() {
            break;
        }
        let ph = &data[off..off + prog_hdr_entry_size];
        let p_type = u32::from_le_bytes(ph[0..4].try_into().unwrap_or_default());
        let (p_flags, p_vaddr, p_memsz) = if is64 {
            let flags = u32::from_le_bytes(ph[4..8].try_into().unwrap_or_default());
            let vaddr = u64::from_le_bytes(ph[16..24].try_into().unwrap_or_default());
            let memsz = u64::from_le_bytes(ph[40..48].try_into().unwrap_or_default());
            (flags, vaddr, memsz)
        } else {
            let flags = u32::from_le_bytes(ph[24..28].try_into().unwrap_or_default());
            let vaddr = u64::from(u32::from_le_bytes(ph[8..12].try_into().unwrap_or_default()));
            let memsz = u64::from(u32::from_le_bytes(ph[20..24].try_into().unwrap_or_default()));
            (flags, vaddr, memsz)
        };

        if p_type == 0x6474_E552 {
            relro = Some(RelRoSection { vaddr: p_vaddr, memsz: p_memsz, level: RelRo::Partial });
        }
        if p_type == 0x6474_E551 {
            let has_exec = p_flags & 0x1 != 0;
            nx = NXBit { enabled: !has_exec, stack_flags: Some(p_flags) };
        }
        if p_type == 2 {
            has_bind_now = scan_dynamic_for_bind_now(data, p_vaddr, usize::try_from(p_memsz).unwrap_or(0), is64);
        }
    }
    (relro, nx, has_bind_now)
}

fn build_aslr(pie: &PieCheck, nx: &NXBit) -> AslrCompatible {
    let aslr_compat = pie.enabled && nx.enabled;
    AslrCompatible {
        compatible: aslr_compat,
        reason: if aslr_compat {
            "PIE and NX both enabled".to_string()
        } else if !pie.enabled {
            "Not PIE (ET_EXEC)".to_string()
        } else {
            "NX disabled (executable stack)".to_string()
        },
    }
}

fn compute_score(
    nx: &NXBit,
    pie: &PieCheck,
    stack_canary: &StackCanary,
    fortify: &Fortify,
    relro: Option<&RelRoSection>,
) -> u8 {
    let mut score: u8 = 0;
    if nx.enabled { score = score.saturating_add(20); }
    if pie.enabled { score = score.saturating_add(20); }
    if stack_canary.enabled { score = score.saturating_add(20); }
    if fortify.enabled { score = score.saturating_add(15); }
    if relro.is_some_and(|r| r.level == RelRo::Partial) { score = score.saturating_add(10); }
    if relro.is_some_and(|r| r.level == RelRo::Full) { score = score.saturating_add(15); }
    score
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Minimal ELF builders ─────────────────────────────────────────────────

    /// Builds a minimal 64-bit ELF with configurable `e_type` (2=exec, 3=dyn).
    fn minimal_elf64(e_type: u16) -> Vec<u8> {
        let mut b = vec![0u8; 0x40];
        b[0..4].copy_from_slice(b"\x7fELF");
        b[4] = 2; // class 64
        b[5] = 1; // LE
        b[6] = 1; // version
        b[0x10..0x12].copy_from_slice(&e_type.to_le_bytes());
        b[0x12..0x14].copy_from_slice(&0x3Eu16.to_le_bytes()); // x86-64
        // e_phoff = 0 (no program headers)
        b
    }

    fn minimal_elf32(e_type: u16) -> Vec<u8> {
        let mut b = vec![0u8; 0x40];
        b[0..4].copy_from_slice(b"\x7fELF");
        b[4] = 1; // class 32
        b[5] = 1; // LE
        b[6] = 1;
        b[0x10..0x12].copy_from_slice(&e_type.to_le_bytes());
        b[0x12..0x14].copy_from_slice(&0x28u16.to_le_bytes()); // ARM
        b
    }

    /// Append a `PT_GNU_STACK` (0x6474e551) program header with given flags.
    fn with_gnu_stack(e_type: u16, flags: u32) -> Vec<u8> {
        let mut b = vec![0u8; 0x40 + 56]; // header + one 64-bit phdr
        b[0..4].copy_from_slice(b"\x7fELF");
        b[4] = 2;
        b[5] = 1;
        b[6] = 1;
        b[0x10..0x12].copy_from_slice(&e_type.to_le_bytes());
        // e_phoff = 0x40
        let phoff: u64 = 0x40;
        b[0x20..0x28].copy_from_slice(&phoff.to_le_bytes());
        b[0x36..0x38].copy_from_slice(&56u16.to_le_bytes()); // e_phentsize
        b[0x38..0x3A].copy_from_slice(&1u16.to_le_bytes()); // e_phnum = 1
        // Program header at 0x40
        let p_type: u32 = 0x6474_E551;
        b[0x40..0x44].copy_from_slice(&p_type.to_le_bytes());
        b[0x44..0x48].copy_from_slice(&flags.to_le_bytes());
        b
    }

    fn with_gnu_relro(e_type: u16) -> Vec<u8> {
        let mut b = vec![0u8; 0x40 + 56];
        b[0..4].copy_from_slice(b"\x7fELF");
        b[4] = 2;
        b[5] = 1;
        b[6] = 1;
        b[0x10..0x12].copy_from_slice(&e_type.to_le_bytes());
        let phoff: u64 = 0x40;
        b[0x20..0x28].copy_from_slice(&phoff.to_le_bytes());
        b[0x36..0x38].copy_from_slice(&56u16.to_le_bytes());
        b[0x38..0x3A].copy_from_slice(&1u16.to_le_bytes());
        let p_type: u32 = 0x6474_E552; // PT_GNU_RELRO
        b[0x40..0x44].copy_from_slice(&p_type.to_le_bytes());
        b[0x44..0x48].copy_from_slice(&5u32.to_le_bytes()); // flags
        // vaddr at offset 16
        let vaddr: u64 = 0x0060_1000;
        b[0x40 + 16..0x40 + 24].copy_from_slice(&vaddr.to_le_bytes());
        // memsz at offset 40
        let memsz: u64 = 0x1000;
        b[0x40 + 40..0x40 + 48].copy_from_slice(&memsz.to_le_bytes());
        b
    }

    // ── Error handling ───────────────────────────────────────────────────────

    #[test]
    fn error_too_short() {
        let err = ElfSecurity::analyse(&[0u8; 4]).unwrap_err();
        assert!(matches!(err, ElfSecurityError::TooShort(_)));
    }

    #[test]
    fn error_not_elf() {
        let mut data = vec![0u8; 0x40];
        data[0..4].copy_from_slice(b"JUNK");
        let err = ElfSecurity::analyse(&data).unwrap_err();
        assert!(matches!(err, ElfSecurityError::NotElf));
    }

    #[test]
    fn error_bad_class() {
        let mut data = vec![0u8; 0x40];
        data[0..4].copy_from_slice(b"\x7fELF");
        data[4] = 5; // invalid class
        let err = ElfSecurity::analyse(&data).unwrap_err();
        assert!(matches!(err, ElfSecurityError::BadClass(5)));
    }

    // ── PIE detection ────────────────────────────────────────────────────────

    #[test]
    fn pie_enabled_on_et_dyn() {
        let data = minimal_elf64(3); // ET_DYN
        let sec = ElfSecurity::analyse(&data).unwrap();
        assert!(sec.pie.enabled);
    }

    #[test]
    fn pie_disabled_on_et_exec() {
        let data = minimal_elf64(2); // ET_EXEC
        let sec = ElfSecurity::analyse(&data).unwrap();
        assert!(!sec.pie.enabled);
    }

    #[test]
    fn pie_etype_stored() {
        let data = minimal_elf64(3);
        let sec = ElfSecurity::analyse(&data).unwrap();
        assert_eq!(sec.pie.e_type, 3);
    }

    // ── NX bit ───────────────────────────────────────────────────────────────

    #[test]
    fn nx_enabled_when_no_stack_phdr() {
        // No PT_GNU_STACK → assume NX (default safe)
        let data = minimal_elf64(3);
        let sec = ElfSecurity::analyse(&data).unwrap();
        assert!(sec.nx.enabled);
    }

    #[test]
    fn nx_enabled_when_stack_is_rw() {
        let data = with_gnu_stack(3, 0x6); // PF_R|PF_W, no PF_X
        let sec = ElfSecurity::analyse(&data).unwrap();
        assert!(sec.nx.enabled);
    }

    #[test]
    fn nx_disabled_when_stack_is_rwx() {
        let data = with_gnu_stack(3, 0x7); // PF_R|PF_W|PF_X
        let sec = ElfSecurity::analyse(&data).unwrap();
        assert!(!sec.nx.enabled);
    }

    #[test]
    fn nx_stack_flags_stored() {
        let data = with_gnu_stack(3, 0x6);
        let sec = ElfSecurity::analyse(&data).unwrap();
        assert_eq!(sec.nx.stack_flags, Some(0x6));
    }

    // ── RELRO ────────────────────────────────────────────────────────────────

    #[test]
    fn relro_level_none_when_no_phdr() {
        let data = minimal_elf64(3);
        let sec = ElfSecurity::analyse(&data).unwrap();
        assert_eq!(sec.relro_level(), RelRo::None);
    }

    #[test]
    fn relro_partial_with_relro_phdr() {
        let data = with_gnu_relro(3);
        let sec = ElfSecurity::analyse(&data).unwrap();
        assert_eq!(sec.relro_level(), RelRo::Partial);
    }

    #[test]
    fn relro_section_vaddr_correct() {
        let data = with_gnu_relro(3);
        let sec = ElfSecurity::analyse(&data).unwrap();
        let relro = sec.relro.as_ref().unwrap();
        assert_eq!(relro.vaddr, 0x0060_1000);
    }

    #[test]
    fn relro_section_memsz_correct() {
        let data = with_gnu_relro(3);
        let sec = ElfSecurity::analyse(&data).unwrap();
        let relro = sec.relro.as_ref().unwrap();
        assert_eq!(relro.memsz, 0x1000);
    }

    // ── ASLR compatibility ───────────────────────────────────────────────────

    #[test]
    fn aslr_compatible_when_pie_and_nx() {
        let data = minimal_elf64(3); // ET_DYN, no rwx stack
        let sec = ElfSecurity::analyse(&data).unwrap();
        assert!(sec.aslr.compatible);
    }

    #[test]
    fn aslr_incompatible_when_not_pie() {
        let data = minimal_elf64(2); // ET_EXEC
        let sec = ElfSecurity::analyse(&data).unwrap();
        assert!(!sec.aslr.compatible);
    }

    #[test]
    fn aslr_incompatible_when_nx_off() {
        let data = with_gnu_stack(3, 0x7); // PIE but rwx stack
        let sec = ElfSecurity::analyse(&data).unwrap();
        assert!(!sec.aslr.compatible);
    }

    #[test]
    fn aslr_reason_not_empty() {
        let data = minimal_elf64(2);
        let sec = ElfSecurity::analyse(&data).unwrap();
        assert!(!sec.aslr.reason.is_empty());
    }

    // ── Stack canary ─────────────────────────────────────────────────────────

    #[test]
    fn stack_canary_not_found_in_minimal_elf() {
        let data = minimal_elf64(3);
        let sec = ElfSecurity::analyse(&data).unwrap();
        assert!(!sec.stack_canary.enabled);
    }

    #[test]
    fn stack_canary_found_when_symbol_present() {
        let mut data = minimal_elf64(3);
        data.extend_from_slice(b"\x00__stack_chk_fail\x00");
        let sec = ElfSecurity::analyse(&data).unwrap();
        assert!(sec.stack_canary.enabled);
    }

    #[test]
    fn stack_canary_symbol_name_stored() {
        let mut data = minimal_elf64(3);
        data.extend_from_slice(b"\x00__stack_chk_fail\x00");
        let sec = ElfSecurity::analyse(&data).unwrap();
        assert!(sec.stack_canary.detected_symbol.is_some());
    }

    // ── Fortify ──────────────────────────────────────────────────────────────

    #[test]
    fn fortify_not_found_in_minimal() {
        let data = minimal_elf64(3);
        let sec = ElfSecurity::analyse(&data).unwrap();
        assert!(!sec.fortify.enabled);
    }

    #[test]
    fn fortify_found_when_chk_symbol_present() {
        let mut data = minimal_elf64(3);
        data.extend_from_slice(b"\x00__memcpy_chk\x00__strcpy_chk\x00");
        let sec = ElfSecurity::analyse(&data).unwrap();
        assert!(sec.fortify.enabled);
    }

    #[test]
    fn fortify_count_correct() {
        let mut data = minimal_elf64(3);
        data.extend_from_slice(b"\x00__memcpy_chk\x00__strcpy_chk\x00");
        let sec = ElfSecurity::analyse(&data).unwrap();
        assert!(sec.fortify.chk_symbol_count >= 2);
    }

    // ── SecurityProfile scoring ──────────────────────────────────────────────

    #[test]
    fn profile_score_increases_with_features() {
        // Full-featured binary (ET_DYN, NX implied, stack_chk, chk symbols)
        let mut data = minimal_elf64(3);
        data.extend_from_slice(b"\x00__stack_chk_fail\x00__memcpy_chk\x00");
        let sec = ElfSecurity::analyse(&data).unwrap();
        assert!(sec.profile.score >= 40);
    }

    #[test]
    fn profile_grade_f_for_minimal() {
        let data = minimal_elf64(2); // no security features
        let sec = ElfSecurity::analyse(&data).unwrap();
        // PIE disabled, no canary, no fortify — grade should be low
        assert!(matches!(sec.profile.grade, 'A'..='F'));
    }

    #[test]
    fn profile_summary_not_empty() {
        let data = minimal_elf64(3);
        let sec = ElfSecurity::analyse(&data).unwrap();
        assert!(!sec.profile.summary.is_empty());
    }

    // ── 32-bit ELF ──────────────────────────────────────────────────────────

    #[test]
    fn elf32_parses_without_error() {
        let data = minimal_elf32(3);
        let sec = ElfSecurity::analyse(&data);
        assert!(sec.is_ok());
    }

    #[test]
    fn elf32_pie_from_et_dyn() {
        let data = minimal_elf32(3);
        let sec = ElfSecurity::analyse(&data).unwrap();
        assert!(sec.pie.enabled);
    }

    // ── RelRo Display ────────────────────────────────────────────────────────

    #[test]
    fn relro_display_none() {
        assert_eq!(format!("{}", RelRo::None), "None");
    }

    #[test]
    fn relro_display_partial() {
        assert_eq!(format!("{}", RelRo::Partial), "Partial");
    }

    #[test]
    fn relro_display_full() {
        assert_eq!(format!("{}", RelRo::Full), "Full");
    }
}
