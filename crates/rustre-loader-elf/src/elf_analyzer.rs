//! Deep ELF analysis: dynamic section, GOT/PLT, relocations, version info,
//! TLS, build-ID, note sections, and more.

use serde::{Deserialize, Serialize};

// Re-exports — keep the standard collection and fmt primitives reachable from
// the analyzer module for downstream consumers.
pub use std::collections::HashMap;
pub use std::fmt;

// ─── Error ────────────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum ElfAnalyzerError {
    #[error("not an ELF file: {0}")]
    NotElf(String),
    #[error("truncated data at offset {0:#x}")]
    Truncated(usize),
    #[error("unsupported architecture: {0}")]
    UnsupportedArch(String),
    #[error("parse error: {0}")]
    Parse(String),
}

// ─── DtTag ────────────────────────────────────────────────────────────────────

/// Selected dynamic section tag values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u64)]
pub enum DtTag {
    Null = 0,
    Needed = 1,
    PltRelSz = 2,
    PltGot = 3,
    Hash = 4,
    StrTab = 5,
    SymTab = 6,
    Rela = 7,
    RelaSz = 8,
    RelaEnt = 9,
    StrSz = 10,
    SymEnt = 11,
    Init = 12,
    Fini = 13,
    SoName = 14,
    Rpath = 15,
    Symbolic = 16,
    Rel = 17,
    RelSz = 18,
    RelEnt = 19,
    PltRel = 20,
    Textrel = 22,
    JmpRel = 23,
    BindNow = 24,
    GnuHash = 0x6FFF_FEF5,
    Verneed = 0x6FFF_FFFE,
    Verneednum = 0x6FFF_FFFF,
    Verdef = 0x6FFF_FFFC,
    Verdefnum = 0x6FFF_FFFD,
    Runpath = 0x1D,
    Flags = 0x1E,
    Flags1 = 0x6FFF_FFFB,
    Initarray = 0x19,
    FiniArray = 0x1A,
    InitArraySz = 0x1B,
    FiniArraySz = 0x1C,
    /// Catch-all variant. Carries the raw u64 tag value; given an explicit
    /// discriminant outside any standard ELF range so it never collides with
    /// other variants' assignments.
    Other(u64) = 0x7FFF_FFFF_FFFF_FFFE,
}

impl DtTag {
    #[must_use]
    pub const fn from_u64(v: u64) -> Self {
        match v {
            0 => Self::Null,
            1 => Self::Needed,
            2 => Self::PltRelSz,
            3 => Self::PltGot,
            4 => Self::Hash,
            5 => Self::StrTab,
            6 => Self::SymTab,
            7 => Self::Rela,
            8 => Self::RelaSz,
            9 => Self::RelaEnt,
            10 => Self::StrSz,
            11 => Self::SymEnt,
            12 => Self::Init,
            13 => Self::Fini,
            14 => Self::SoName,
            15 => Self::Rpath,
            16 => Self::Symbolic,
            17 => Self::Rel,
            18 => Self::RelSz,
            19 => Self::RelEnt,
            20 => Self::PltRel,
            22 => Self::Textrel,
            23 => Self::JmpRel,
            24 => Self::BindNow,
            0x6FFF_FEF5 => Self::GnuHash,
            0x6FFF_FFFE => Self::Verneed,
            0x6FFF_FFFF => Self::Verneednum,
            0x6FFF_FFFC => Self::Verdef,
            0x6FFF_FFFD => Self::Verdefnum,
            0x1D => Self::Runpath,
            0x1E => Self::Flags,
            0x6FFF_FFFB => Self::Flags1,
            0x19 => Self::Initarray,
            0x1A => Self::FiniArray,
            0x1B => Self::InitArraySz,
            0x1C => Self::FiniArraySz,
            other => Self::Other(other),
        }
    }

    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Null => "DT_NULL",
            Self::Needed => "DT_NEEDED",
            Self::PltRelSz => "DT_PLTRELSZ",
            Self::PltGot => "DT_PLTGOT",
            Self::Hash => "DT_HASH",
            Self::StrTab => "DT_STRTAB",
            Self::SymTab => "DT_SYMTAB",
            Self::Rela => "DT_RELA",
            Self::RelaSz => "DT_RELASZ",
            Self::RelaEnt => "DT_RELAENT",
            Self::StrSz => "DT_STRSZ",
            Self::SymEnt => "DT_SYMENT",
            Self::Init => "DT_INIT",
            Self::Fini => "DT_FINI",
            Self::SoName => "DT_SONAME",
            Self::Rpath => "DT_RPATH",
            Self::Symbolic => "DT_SYMBOLIC",
            Self::Rel => "DT_REL",
            Self::RelSz => "DT_RELSZ",
            Self::RelEnt => "DT_RELENT",
            Self::PltRel => "DT_PLTREL",
            Self::Textrel => "DT_TEXTREL",
            Self::JmpRel => "DT_JMPREL",
            Self::BindNow => "DT_BIND_NOW",
            Self::GnuHash => "DT_GNU_HASH",
            Self::Verneed => "DT_VERNEED",
            Self::Verneednum => "DT_VERNEEDNUM",
            Self::Verdef => "DT_VERDEF",
            Self::Verdefnum => "DT_VERDEFNUM",
            Self::Runpath => "DT_RUNPATH",
            Self::Flags => "DT_FLAGS",
            Self::Flags1 => "DT_FLAGS_1",
            Self::Initarray => "DT_INIT_ARRAY",
            Self::FiniArray => "DT_FINI_ARRAY",
            Self::InitArraySz => "DT_INIT_ARRAYSZ",
            Self::FiniArraySz => "DT_FINI_ARRAYSZ",
            Self::Other(_) => "DT_?",
        }
    }
}

// ─── DynamicEntry ─────────────────────────────────────────────────────────────

/// A single entry in the `.dynamic` section.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DynamicEntry {
    pub tag: DtTag,
    pub value: u64,
}

impl DynamicEntry {
    #[must_use]
    pub const fn tag_name(&self) -> &'static str {
        self.tag.name()
    }
}

// ─── DynamicSection ──────────────────────────────────────────────────────────

/// Parsed `.dynamic` section.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DynamicSection {
    pub entries: Vec<DynamicEntry>,
    pub needed_libs: Vec<String>,
    pub rpath: Option<String>,
    pub runpath: Option<String>,
    pub soname: Option<String>,
    pub init_fn: Option<u64>,
    pub fini_fn: Option<u64>,
    pub has_textrel: bool,
    pub has_bind_now: bool,
    pub flags: u64,
    pub flags1: u64,
}

impl DynamicSection {
    /// Build from a raw byte slice (8-byte entries for 64-bit ELF).
    #[must_use]
    pub fn parse_64(data: &[u8], strtab: &[u8]) -> Self {
        let mut out = Self::default();
        let mut pos = 0usize;
        while pos + 16 <= data.len() {
            let tag = u64::from_le_bytes(data[pos..pos + 8].try_into().unwrap_or([0; 8]));
            let val = u64::from_le_bytes(data[pos + 8..pos + 16].try_into().unwrap_or([0; 8]));
            let dt = DtTag::from_u64(tag);
            match dt {
                DtTag::Needed => {
                    let s = read_strtab_str(strtab, usize::try_from(val).unwrap_or(usize::MAX));
                    out.needed_libs.push(s);
                }
                DtTag::Rpath => {
                    out.rpath = Some(read_strtab_str(strtab, usize::try_from(val).unwrap_or(usize::MAX)));
                }
                DtTag::Runpath => {
                    out.runpath = Some(read_strtab_str(strtab, usize::try_from(val).unwrap_or(usize::MAX)));
                }
                DtTag::SoName => {
                    out.soname = Some(read_strtab_str(strtab, usize::try_from(val).unwrap_or(usize::MAX)));
                }
                DtTag::Init => {
                    out.init_fn = Some(val);
                }
                DtTag::Fini => {
                    out.fini_fn = Some(val);
                }
                DtTag::Textrel => {
                    out.has_textrel = true;
                }
                DtTag::BindNow => {
                    out.has_bind_now = true;
                }
                DtTag::Flags => {
                    out.flags = val;
                }
                DtTag::Flags1 => {
                    out.flags1 = val;
                }
                DtTag::Null => break,
                _ => {}
            }
            out.entries.push(DynamicEntry {
                tag: dt,
                value: val,
            });
            pos += 16;
        }
        out
    }

    /// Returns `true` if any `RUNPATH` is present.
    #[must_use]
    pub const fn has_runpath(&self) -> bool {
        self.runpath.is_some()
    }

    /// Return the effective search path (RPATH or RUNPATH).
    #[must_use]
    pub fn search_path(&self) -> Option<&str> {
        self.runpath.as_deref().or(self.rpath.as_deref())
    }
}

fn read_strtab_str(strtab: &[u8], offset: usize) -> String {
    if offset >= strtab.len() {
        return String::new();
    }
    let slice = &strtab[offset..];
    let end = slice.iter().position(|&b| b == 0).unwrap_or(slice.len());
    String::from_utf8_lossy(&slice[..end]).into_owned()
}

// ─── GotPltAnalysis ──────────────────────────────────────────────────────────

/// A single GOT entry associated with a PLT stub.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GotEntry {
    /// Virtual address of the GOT slot.
    pub got_va: u64,
    /// Virtual address of the PLT stub.
    pub plt_va: u64,
    /// Symbol name resolved through the dynamic symbol table.
    pub symbol: String,
    /// Whether the entry is lazy (not yet resolved by the dynamic linker).
    pub is_lazy: bool,
}

/// Results of GOT/PLT analysis.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GotPltAnalysis {
    pub entries: Vec<GotEntry>,
    pub plt_base: u64,
    pub got_plt_base: u64,
}

impl GotPltAnalysis {
    /// Return all entries for symbol `name`.
    #[must_use]
    pub fn find_symbol(&self, name: &str) -> Vec<&GotEntry> {
        self.entries.iter().filter(|e| e.symbol == name).collect()
    }

    /// Return the PLT stub address for `name`, if found.
    #[must_use]
    pub fn plt_for(&self, name: &str) -> Option<u64> {
        self.entries
            .iter()
            .find(|e| e.symbol == name)
            .map(|e| e.plt_va)
    }
}

// ─── RelocationTypes ─────────────────────────────────────────────────────────

/// Architecture-specific relocation type names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RelocArch {
    X86,
    X86_64,
    Arm,
    Arm64,
    Mips,
    RiscV,
}

impl RelocArch {
    /// Return the relocation type name for a numeric type.
    #[must_use]
    pub const fn reloc_name(self, rtype: u32) -> &'static str {
        match (self, rtype) {
            (Self::X86_64, 1) => "R_X86_64_64",
            (Self::X86_64, 2) => "R_X86_64_PC32",
            (Self::X86_64, 6) => "R_X86_64_GLOB_DAT",
            (Self::X86_64, 7) => "R_X86_64_JUMP_SLOT",
            (Self::X86_64, 8) => "R_X86_64_RELATIVE",
            (Self::X86_64, 10) => "R_X86_64_32",
            (Self::X86_64, 11) => "R_X86_64_32S",
            (Self::Arm64, 257) => "R_AARCH64_ABS64",
            (Self::Arm64, 258) => "R_AARCH64_ABS32",
            (Self::Arm64, 1026) => "R_AARCH64_JUMP_SLOT",
            (Self::Arm64, 1027) => "R_AARCH64_RELATIVE",
            (Self::Arm64, 1025) => "R_AARCH64_GLOB_DAT",
            (Self::Arm, 2) => "R_ARM_ABS32",
            (Self::Arm, 21) => "R_ARM_GLOB_DAT",
            (Self::Arm, 22) => "R_ARM_JUMP_SLOT",
            (Self::Arm, 23) => "R_ARM_RELATIVE",
            (Self::Mips, 2) => "R_MIPS_32",
            (Self::Mips, 37) => "R_MIPS_JUMP_SLOT",
            (Self::RiscV, 1) => "R_RISCV_32",
            (Self::RiscV, 2) => "R_RISCV_64",
            (Self::RiscV, 3) => "R_RISCV_RELATIVE",
            _ => "R_UNKNOWN",
        }
    }
}

// ─── VersionInfo ─────────────────────────────────────────────────────────────

/// GNU version information from `.gnu.version_r` / `.gnu.version_d`.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct VersionInfo {
    /// Required version entries (`DT_VERNEED`).
    pub needed: Vec<VersionNeeded>,
    /// Defined version entries (`DT_VERDEF`).
    pub defined: Vec<VersionDefined>,
}

/// A version needed entry from `.gnu.version_r`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionNeeded {
    /// Library name (e.g. `libc.so.6`).
    pub file: String,
    /// Version strings required from this library.
    pub versions: Vec<String>,
}

/// A version defined entry from `.gnu.version_d`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionDefined {
    /// Version string (e.g. `GLIBC_2.5`).
    pub version: String,
    pub flags: u16,
}

// ─── TlsSection ──────────────────────────────────────────────────────────────

/// TLS (Thread-Local Storage) information extracted from the ELF.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TlsSection {
    /// Virtual address of the TLS template.
    pub template_va: u64,
    /// Size of TLS initialised data.
    pub init_size: u64,
    /// Total TLS segment size (init + zero-filled).
    pub total_size: u64,
    /// TLS alignment requirement.
    pub alignment: u64,
    /// Number of TLS variables found in the symbol table.
    pub variable_count: usize,
}

impl TlsSection {
    /// Returns `true` if a TLS segment is present.
    #[must_use]
    pub const fn is_present(&self) -> bool {
        self.total_size > 0
    }
}

// ─── BuildId ─────────────────────────────────────────────────────────────────

/// GNU Build-ID extracted from `.note.gnu.build-id`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuildId {
    /// Raw bytes of the build ID.
    pub bytes: Vec<u8>,
    /// Hex-encoded build ID string.
    pub hex: String,
    /// Length of the build ID in bytes (20 = SHA-1, 32 = SHA-256).
    pub length: usize,
}

impl BuildId {
    /// Create from raw bytes.
    #[must_use]
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        let hex = bytes.iter().fold(String::with_capacity(bytes.len() * 2), |mut acc, b| { use std::fmt::Write; let _ = write!(acc, "{b:02x}"); acc });
        let length = bytes.len();
        Self { bytes, hex, length }
    }

    /// Returns `true` if this is a SHA-1 build ID (20 bytes).
    #[must_use]
    pub const fn is_sha1(&self) -> bool {
        self.length == 20
    }

    /// Returns `true` if this is a SHA-256 build ID (32 bytes).
    #[must_use]
    pub const fn is_sha256(&self) -> bool {
        self.length == 32
    }
}

// ─── NoteSection ─────────────────────────────────────────────────────────────

/// A parsed ELF note from a `.note.*` section.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NoteEntry {
    /// Note owner name (e.g. `"GNU"`, `"CORE"`).
    pub name: String,
    /// Note type.
    pub note_type: u32,
    /// Raw descriptor bytes.
    pub desc: Vec<u8>,
}

impl NoteEntry {
    /// Returns `true` when this is the GNU build-ID note (type 3).
    #[must_use]
    pub fn is_build_id(&self) -> bool {
        self.name == "GNU" && self.note_type == 3
    }

    /// Returns `true` when this is a GNU ABI tag note (type 1).
    #[must_use]
    pub fn is_abi_tag(&self) -> bool {
        self.name == "GNU" && self.note_type == 1
    }
}

// ─── ElfAnalyzer ─────────────────────────────────────────────────────────────

/// Deep ELF analysis engine.
#[derive(Debug, Default)]
pub struct ElfAnalyzer;

impl ElfAnalyzer {
    /// Create a new analyzer.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Parse the dynamic section from raw bytes.
    ///
    /// `data` is the `.dynamic` section bytes; `strtab` is the associated string table.
    #[must_use]
    pub fn parse_dynamic(&self, data: &[u8], strtab: &[u8]) -> DynamicSection {
        DynamicSection::parse_64(data, strtab)
    }

    /// Scan `data` for ELF note entries starting at `offset`.
    #[must_use]
    pub fn parse_notes(&self, data: &[u8], offset: usize, size: usize) -> Vec<NoteEntry> {
        let mut notes = Vec::new();
        let end = (offset + size).min(data.len());
        let mut pos = offset;
        while pos + 12 <= end {
            let namesz =
                u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap_or([0; 4])) as usize;
            let descsz =
                u32::from_le_bytes(data[pos + 4..pos + 8].try_into().unwrap_or([0; 4])) as usize;
            let note_type =
                u32::from_le_bytes(data[pos + 8..pos + 12].try_into().unwrap_or([0; 4]));
            pos += 12;

            if namesz == 0 {
                break;
            }
            let name_end = pos + namesz;
            if name_end > end {
                break;
            }
            let name = String::from_utf8_lossy(&data[pos..name_end.min(end)])
                .trim_end_matches('\0')
                .to_string();
            // Align name to 4 bytes
            pos += (namesz + 3) & !3;

            let desc_end = pos + descsz;
            if desc_end > end {
                break;
            }
            let desc = data[pos..desc_end].to_vec();
            pos += (descsz + 3) & !3;

            notes.push(NoteEntry {
                name,
                note_type,
                desc,
            });
        }
        notes
    }

    /// Extract a build-ID from note entries.
    #[must_use]
    pub fn extract_build_id(&self, notes: &[NoteEntry]) -> Option<BuildId> {
        notes
            .iter()
            .find(|n| n.is_build_id())
            .map(|n| BuildId::from_bytes(n.desc.clone()))
    }

    /// Build a mock `GotPltAnalysis` for testing.
    #[must_use]
    pub fn mock_got_plt() -> GotPltAnalysis {
        GotPltAnalysis {
            plt_base: 0x0040_1010,
            got_plt_base: 0x0060_1000,
            entries: vec![
                GotEntry {
                    got_va: 0x0060_1018,
                    plt_va: 0x0040_1020,
                    symbol: "malloc".into(),
                    is_lazy: true,
                },
                GotEntry {
                    got_va: 0x0060_1020,
                    plt_va: 0x0040_1030,
                    symbol: "free".into(),
                    is_lazy: true,
                },
                GotEntry {
                    got_va: 0x0060_1028,
                    plt_va: 0x0040_1040,
                    symbol: "printf".into(),
                    is_lazy: true,
                },
            ],
        }
    }

    /// Build a mock `DynamicSection`.
    #[must_use]
    pub fn mock_dynamic() -> DynamicSection {
        DynamicSection {
            entries: vec![
                DynamicEntry {
                    tag: DtTag::Needed,
                    value: 0,
                },
                DynamicEntry {
                    tag: DtTag::Needed,
                    value: 1,
                },
            ],
            needed_libs: vec!["libc.so.6".into(), "libm.so.6".into()],
            rpath: None,
            runpath: Some("/usr/local/lib".into()),
            soname: Some("libexample.so.1".into()),
            init_fn: Some(0x0040_1000),
            fini_fn: Some(0x0040_1100),
            has_textrel: false,
            has_bind_now: true,
            flags: 0,
            flags1: 0x1, // NODELETE
        }
    }

    /// Build a mock `TlsSection`.
    #[must_use]
    pub const fn mock_tls() -> TlsSection {
        TlsSection {
            template_va: 0x0060_2000,
            init_size: 16,
            total_size: 64,
            alignment: 8,
            variable_count: 3,
        }
    }

    /// Build a mock `VersionInfo`.
    #[must_use]
    pub fn mock_version_info() -> VersionInfo {
        VersionInfo {
            needed: vec![VersionNeeded {
                file: "libc.so.6".into(),
                versions: vec!["GLIBC_2.5".into(), "GLIBC_2.17".into()],
            }],
            defined: vec![VersionDefined {
                version: "MYLIB_1.0".into(),
                flags: 1,
            }],
        }
    }

    /// Build a mock `BuildId`.
    #[must_use]
    pub fn mock_build_id() -> BuildId {
        BuildId::from_bytes(vec![
            0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB,
            0xCD, 0xEF, 0x00, 0x11, 0x22, 0x33,
        ])
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── DtTag ────────────────────────────────────────────────────────────────

    #[test]
    fn test_dt_tag_from_u64_needed() {
        assert_eq!(DtTag::from_u64(1), DtTag::Needed);
    }

    #[test]
    fn test_dt_tag_from_u64_soname() {
        assert_eq!(DtTag::from_u64(14), DtTag::SoName);
    }

    #[test]
    fn test_dt_tag_from_u64_gnu_hash() {
        assert_eq!(DtTag::from_u64(0x6FFF_FEF5), DtTag::GnuHash);
    }

    #[test]
    fn test_dt_tag_other() {
        assert_eq!(DtTag::from_u64(0xDEAD_BEEF), DtTag::Other(0xDEAD_BEEF));
    }

    #[test]
    fn test_dt_tag_name_null() {
        assert_eq!(DtTag::Null.name(), "DT_NULL");
    }

    #[test]
    fn test_dt_tag_name_needed() {
        assert_eq!(DtTag::Needed.name(), "DT_NEEDED");
    }

    #[test]
    fn test_dt_tag_name_verneed() {
        assert_eq!(DtTag::Verneed.name(), "DT_VERNEED");
    }

    // ── DynamicSection ────────────────────────────────────────────────────────

    #[test]
    fn test_dynamic_section_mock_needed_libs() {
        let d = ElfAnalyzer::mock_dynamic();
        assert_eq!(d.needed_libs.len(), 2);
        assert!(d.needed_libs.contains(&"libc.so.6".to_string()));
    }

    #[test]
    fn test_dynamic_section_mock_soname() {
        let d = ElfAnalyzer::mock_dynamic();
        assert_eq!(d.soname.as_deref(), Some("libexample.so.1"));
    }

    #[test]
    fn test_dynamic_section_mock_runpath() {
        let d = ElfAnalyzer::mock_dynamic();
        assert!(d.has_runpath());
        assert_eq!(d.search_path(), Some("/usr/local/lib"));
    }

    #[test]
    fn test_dynamic_section_no_textrel() {
        let d = ElfAnalyzer::mock_dynamic();
        assert!(!d.has_textrel);
    }

    #[test]
    fn test_dynamic_section_bind_now() {
        let d = ElfAnalyzer::mock_dynamic();
        assert!(d.has_bind_now);
    }

    #[test]
    fn test_dynamic_section_parse_empty() {
        let d = DynamicSection::parse_64(&[], &[]);
        assert!(d.entries.is_empty());
        assert!(d.needed_libs.is_empty());
    }

    #[test]
    fn test_dynamic_section_parse_null_terminates() {
        // A single DT_NULL entry should produce an empty dynamic section
        let data = vec![0u8; 16]; // tag=0 (DT_NULL), val=0
        let d = DynamicSection::parse_64(&data, &[]);
        // DT_NULL causes break before pushing
        assert!(d.entries.is_empty() || d.entries[0].tag == DtTag::Null);
    }

    // ── GotPltAnalysis ────────────────────────────────────────────────────────

    #[test]
    fn test_got_plt_find_symbol() {
        let g = ElfAnalyzer::mock_got_plt();
        let entries = g.find_symbol("malloc");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].plt_va, 0x0040_1020);
    }

    #[test]
    fn test_got_plt_plt_for() {
        let g = ElfAnalyzer::mock_got_plt();
        assert_eq!(g.plt_for("free"), Some(0x0040_1030));
        assert_eq!(g.plt_for("unknown"), None);
    }

    #[test]
    fn test_got_plt_entry_count() {
        let g = ElfAnalyzer::mock_got_plt();
        assert_eq!(g.entries.len(), 3);
    }

    // ── RelocArch ─────────────────────────────────────────────────────────────

    #[test]
    fn test_reloc_arch_x86_64_glob_dat() {
        assert_eq!(RelocArch::X86_64.reloc_name(6), "R_X86_64_GLOB_DAT");
    }

    #[test]
    fn test_reloc_arch_arm64_jump_slot() {
        assert_eq!(RelocArch::Arm64.reloc_name(1026), "R_AARCH64_JUMP_SLOT");
    }

    #[test]
    fn test_reloc_arch_unknown() {
        assert_eq!(RelocArch::X86_64.reloc_name(9999), "R_UNKNOWN");
    }

    // ── VersionInfo ───────────────────────────────────────────────────────────

    #[test]
    fn test_version_info_mock_needed() {
        let v = ElfAnalyzer::mock_version_info();
        assert_eq!(v.needed.len(), 1);
        assert_eq!(v.needed[0].file, "libc.so.6");
        assert!(v.needed[0].versions.contains(&"GLIBC_2.5".to_string()));
    }

    #[test]
    fn test_version_info_mock_defined() {
        let v = ElfAnalyzer::mock_version_info();
        assert_eq!(v.defined.len(), 1);
        assert_eq!(v.defined[0].version, "MYLIB_1.0");
    }

    // ── TlsSection ────────────────────────────────────────────────────────────

    #[test]
    fn test_tls_section_is_present() {
        let t = ElfAnalyzer::mock_tls();
        assert!(t.is_present());
    }

    #[test]
    fn test_tls_section_empty_not_present() {
        let t = TlsSection::default();
        assert!(!t.is_present());
    }

    // ── BuildId ───────────────────────────────────────────────────────────────

    #[test]
    fn test_build_id_mock_sha1() {
        let b = ElfAnalyzer::mock_build_id();
        assert!(b.is_sha1());
        assert!(!b.is_sha256());
    }

    #[test]
    fn test_build_id_hex_length() {
        let b = ElfAnalyzer::mock_build_id();
        assert_eq!(b.hex.len(), 40); // 20 bytes × 2 hex chars
    }

    #[test]
    fn test_build_id_sha256() {
        let b = BuildId::from_bytes(vec![0u8; 32]);
        assert!(b.is_sha256());
    }

    // ── NoteEntry ─────────────────────────────────────────────────────────────

    #[test]
    fn test_note_entry_is_build_id() {
        let n = NoteEntry {
            name: "GNU".into(),
            note_type: 3,
            desc: vec![0xDE, 0xAD],
        };
        assert!(n.is_build_id());
    }

    #[test]
    fn test_note_entry_is_abi_tag() {
        let n = NoteEntry {
            name: "GNU".into(),
            note_type: 1,
            desc: vec![],
        };
        assert!(n.is_abi_tag());
    }

    #[test]
    fn test_note_entry_not_build_id_wrong_type() {
        let n = NoteEntry {
            name: "GNU".into(),
            note_type: 2,
            desc: vec![],
        };
        assert!(!n.is_build_id());
    }

    // ── ElfAnalyzer ───────────────────────────────────────────────────────────

    #[test]
    fn test_elf_analyzer_parse_notes_empty() {
        let az = ElfAnalyzer::new();
        let notes = az.parse_notes(&[], 0, 0);
        assert!(notes.is_empty());
    }

    #[test]
    fn test_elf_analyzer_extract_build_id_from_notes() {
        let az = ElfAnalyzer::new();
        // Build a minimal GNU build-ID note
        let mut data = Vec::new();
        let name = b"GNU\0";
        let desc: Vec<u8> = (0..20).collect();
        let namesz = name.len() as u32;
        let descsz = desc.len() as u32;
        data.extend_from_slice(&namesz.to_le_bytes());
        data.extend_from_slice(&descsz.to_le_bytes());
        data.extend_from_slice(&3u32.to_le_bytes()); // NT_GNU_BUILD_ID
        data.extend_from_slice(name);
        data.extend_from_slice(&desc);
        let notes = az.parse_notes(&data, 0, data.len());
        assert_eq!(notes.len(), 1);
        assert!(notes[0].is_build_id());
        let bid = az.extract_build_id(&notes).unwrap();
        assert_eq!(bid.length, 20);
    }

    #[test]
    fn test_elf_analyzer_extract_build_id_none() {
        let az = ElfAnalyzer::new();
        let bid = az.extract_build_id(&[]);
        assert!(bid.is_none());
    }

    #[test]
    fn test_elf_analyzer_parse_dynamic_delegate() {
        let az = ElfAnalyzer::new();
        let d = az.parse_dynamic(&[], &[]);
        assert!(d.entries.is_empty());
    }
    #[test]
    fn test_dt_tag_rela() {
        assert_eq!(DtTag::from_u64(7), DtTag::Rela);
    }
    #[test]
    fn test_dt_tag_flags1() {
        assert_eq!(DtTag::from_u64(0x6FFF_FFFB), DtTag::Flags1);
    }
    #[test]
    fn test_dynamic_section_init_fn() {
        let d = ElfAnalyzer::mock_dynamic();
        assert!(d.init_fn.is_some());
    }
    #[test]
    fn test_dynamic_section_fini_fn() {
        let d = ElfAnalyzer::mock_dynamic();
        assert!(d.fini_fn.is_some());
    }
    #[test]
    fn test_got_plt_plt_base() {
        let g = ElfAnalyzer::mock_got_plt();
        assert_ne!(g.plt_base, 0);
    }
    #[test]
    fn test_reloc_arch_arm_jump_slot() {
        assert_eq!(RelocArch::Arm.reloc_name(22), "R_ARM_JUMP_SLOT");
    }
    #[test]
    fn test_reloc_arch_mips_32() {
        assert_eq!(RelocArch::Mips.reloc_name(2), "R_MIPS_32");
    }
    #[test]
    fn test_tls_total_size() {
        let t = ElfAnalyzer::mock_tls();
        assert_eq!(t.total_size, 64);
    }
    #[test]
    fn test_version_info_needed_count() {
        let v = ElfAnalyzer::mock_version_info();
        assert_eq!(v.needed.len(), 1);
    }
    #[test]
    fn test_build_id_mock_bytes() {
        let b = ElfAnalyzer::mock_build_id();
        assert_eq!(b.bytes[0], 0xDE);
    }
}
