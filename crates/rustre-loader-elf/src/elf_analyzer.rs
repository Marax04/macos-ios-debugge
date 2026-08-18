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
    /// The image does not carry the input needed to compute the requested
    /// value. The payload names exactly what is missing.
    #[error("cannot compute {what}: image has no {missing}")]
    Missing {
        /// The value that was requested.
        what: &'static str,
        /// The ELF input required to compute it, and absent from this image.
        missing: &'static str,
    },
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

    // ── Real, byte-derived analysis ──

    /// Parse the ELF container out of `image`.
    fn container(image: &[u8]) -> Result<goblin::elf::Elf<'_>, ElfAnalyzerError> {
        if image.len() < 16 || &image[..4] != b"\x7fELF" {
            return Err(ElfAnalyzerError::NotElf(format!(
                "{} bytes, bad magic",
                image.len()
            )));
        }
        goblin::elf::Elf::parse(image).map_err(|e| ElfAnalyzerError::Parse(e.to_string()))
    }

    /// Raw bytes of the section named `name`, as they sit in the file.
    fn section_bytes<'a>(
        elf: &goblin::elf::Elf<'_>,
        image: &'a [u8],
        name: &str,
    ) -> Option<&'a [u8]> {
        for sh in &elf.section_headers {
            if elf.shdr_strtab.get_at(sh.sh_name) == Some(name) {
                if sh.sh_type == goblin::elf::section_header::SHT_NOBITS {
                    return None;
                }
                let start = usize::try_from(sh.sh_offset).ok()?;
                let end = start.checked_add(usize::try_from(sh.sh_size).ok()?)?;
                if end <= image.len() {
                    return Some(&image[start..end]);
                }
                return None;
            }
        }
        None
    }

    /// Virtual address of the section named `name`.
    fn section_addr(elf: &goblin::elf::Elf<'_>, name: &str) -> Option<u64> {
        elf.section_headers
            .iter()
            .find(|sh| elf.shdr_strtab.get_at(sh.sh_name) == Some(name))
            .map(|sh| sh.sh_addr)
    }

    /// Translate a virtual address to a file offset using the LOAD segments.
    fn vaddr_to_offset(elf: &goblin::elf::Elf<'_>, vaddr: u64) -> Option<u64> {
        elf.program_headers
            .iter()
            .filter(|ph| ph.p_type == goblin::elf::program_header::PT_LOAD)
            .find(|ph| vaddr >= ph.p_vaddr && vaddr < ph.p_vaddr + ph.p_filesz)
            .map(|ph| vaddr - ph.p_vaddr + ph.p_offset)
    }

    /// Raw `.dynstr` bytes: from the section header when present, otherwise
    /// located through `DT_STRTAB`/`DT_STRSZ` and the LOAD segments.
    fn dynstr_bytes<'a>(elf: &goblin::elf::Elf<'_>, image: &'a [u8]) -> Option<&'a [u8]> {
        if let Some(b) = Self::section_bytes(elf, image, ".dynstr") {
            return Some(b);
        }
        let dynamic = elf.dynamic.as_ref()?;
        let mut strtab = None;
        let mut strsz = None;
        for d in &dynamic.dyns {
            match DtTag::from_u64(d.d_tag) {
                DtTag::StrTab => strtab = Some(d.d_val),
                DtTag::StrSz => strsz = Some(d.d_val),
                _ => {}
            }
        }
        let off = usize::try_from(Self::vaddr_to_offset(elf, strtab?)?).ok()?;
        let len = usize::try_from(strsz?).ok()?;
        let end = off.checked_add(len)?;
        if end <= image.len() {
            Some(&image[off..end])
        } else {
            None
        }
    }

    /// Parse the `.dynamic` section of a whole ELF image.
    ///
    /// Reads the `.dynamic` section when section headers survive, else the
    /// `PT_DYNAMIC` segment, resolving every string through `.dynstr`.
    ///
    /// # Errors
    /// [`ElfAnalyzerError::Missing`] when the image has no dynamic array at
    /// all (a statically linked object), plus the container errors.
    pub fn analyze_dynamic(&self, image: &[u8]) -> Result<DynamicSection, ElfAnalyzerError> {
        let elf = Self::container(image)?;
        let dyn_bytes = Self::section_bytes(&elf, image, ".dynamic").or_else(|| {
            elf.program_headers
                .iter()
                .find(|ph| ph.p_type == goblin::elf::program_header::PT_DYNAMIC)
                .and_then(|ph| {
                    let start = usize::try_from(ph.p_offset).ok()?;
                    let end = start.checked_add(usize::try_from(ph.p_filesz).ok()?)?;
                    if end <= image.len() {
                        Some(&image[start..end])
                    } else {
                        None
                    }
                })
        });
        let Some(dyn_bytes) = dyn_bytes else {
            return Err(ElfAnalyzerError::Missing {
                what: "dynamic section",
                missing: ".dynamic section or PT_DYNAMIC segment",
            });
        };
        let strtab = Self::dynstr_bytes(&elf, image).unwrap_or(&[]);
        Ok(self.parse_dynamic(dyn_bytes, strtab))
    }

    /// Reconstruct the GOT/PLT pairing of a whole ELF image.
    ///
    /// Every field is derived from the image: `got_va` is the relocation
    /// offset of the `DT_JMPREL` entry, `symbol` is resolved through
    /// `.dynsym`/`.dynstr`, `plt_va` is computed from the `.plt` address, its
    /// entry size and whether the section carries a `PLT0` header slot, and
    /// `is_lazy` follows `DT_BIND_NOW`/`DF_BIND_NOW`/`DF_1_NOW`.
    ///
    /// # Errors
    /// [`ElfAnalyzerError::Missing`] naming the absent `.plt`, `.got.plt` or
    /// PLT relocation table, plus the container errors.
    pub fn analyze_got_plt(&self, image: &[u8]) -> Result<GotPltAnalysis, ElfAnalyzerError> {
        let elf = Self::container(image)?;

        let plt_sh = elf
            .section_headers
            .iter()
            .find(|sh| elf.shdr_strtab.get_at(sh.sh_name) == Some(".plt"))
            .ok_or(ElfAnalyzerError::Missing {
                what: "GOT/PLT analysis",
                missing: ".plt section",
            })?;
        let plt_base = plt_sh.sh_addr;

        let got_plt_base = Self::section_addr(&elf, ".got.plt")
            .or_else(|| Self::section_addr(&elf, ".got"))
            .ok_or(ElfAnalyzerError::Missing {
                what: "GOT/PLT analysis",
                missing: ".got.plt or .got section",
            })?;

        if elf.pltrelocs.is_empty() {
            return Err(ElfAnalyzerError::Missing {
                what: "GOT/PLT entries",
                missing: "DT_JMPREL relocation table",
            });
        }

        // Lazy binding is on unless the image asked the loader to resolve
        // everything at load time.
        let mut eager = false;
        if let Some(dynamic) = elf.dynamic.as_ref() {
            for d in &dynamic.dyns {
                match DtTag::from_u64(d.d_tag) {
                    DtTag::BindNow => eager = true,
                    DtTag::Flags if d.d_val & 0x8 != 0 => eager = true,
                    DtTag::Flags1 if d.d_val & 0x1 != 0 => eager = true,
                    _ => {}
                }
            }
        }

        let count = u64::try_from(elf.pltrelocs.len()).unwrap_or(u64::MAX);
        let entsize = if plt_sh.sh_entsize >= 4 {
            plt_sh.sh_entsize
        } else if count > 0 && plt_sh.sh_size % count == 0 && plt_sh.sh_size / count >= 4 {
            plt_sh.sh_size / count
        } else {
            16
        };
        // A lazy PLT starts with the PLT0 resolver stub; an eager/IPLT one does not.
        let has_plt0 = entsize > 0 && plt_sh.sh_size / entsize > count;

        let mut entries = Vec::with_capacity(elf.pltrelocs.len());
        for (i, rel) in elf.pltrelocs.iter().enumerate() {
            let symbol = elf
                .dynsyms
                .get(rel.r_sym)
                .and_then(|sym| elf.dynstrtab.get_at(sym.st_name))
                .unwrap_or_default()
                .to_owned();
            let slot = u64::try_from(i).unwrap_or(u64::MAX) + u64::from(has_plt0);
            entries.push(GotEntry {
                got_va: rel.r_offset,
                plt_va: plt_base + slot * entsize,
                symbol,
                is_lazy: !eager,
            });
        }

        Ok(GotPltAnalysis {
            entries,
            plt_base,
            got_plt_base,
        })
    }

    /// Reconstruct the TLS layout of a whole ELF image.
    ///
    /// Geometry comes from the `PT_TLS` program header; `variable_count` is
    /// the number of `STT_TLS` symbols in `.dynsym` and `.symtab`.
    ///
    /// # Errors
    /// [`ElfAnalyzerError::Missing`] when the image has no `PT_TLS` segment,
    /// plus the container errors.
    pub fn analyze_tls(&self, image: &[u8]) -> Result<TlsSection, ElfAnalyzerError> {
        let elf = Self::container(image)?;
        let ph = elf
            .program_headers
            .iter()
            .find(|ph| ph.p_type == goblin::elf::program_header::PT_TLS)
            .ok_or(ElfAnalyzerError::Missing {
                what: "TLS layout",
                missing: "PT_TLS program header",
            })?;
        // Count STT_TLS symbols straight out of the symbol table bytes: the
        // section header gives the exact entry count, with goblin's parsed
        // tables as the fallback when section headers are gone.
        let mut variable_count = 0usize;
        let mut counted_from_sections = false;
        for name in [".dynsym", ".symtab"] {
            if let Some(bytes) = Self::section_bytes(&elf, image, name) {
                counted_from_sections = true;
                for entry in bytes.chunks_exact(24) {
                    if entry[4] & 0xf == goblin::elf::sym::STT_TLS {
                        variable_count += 1;
                    }
                }
            }
        }
        if !counted_from_sections {
            variable_count = elf
                .dynsyms
                .iter()
                .chain(elf.syms.iter())
                .filter(|s| s.st_type() == goblin::elf::sym::STT_TLS)
                .count();
        }
        Ok(TlsSection {
            template_va: ph.p_vaddr,
            init_size: ph.p_filesz,
            total_size: ph.p_memsz,
            alignment: ph.p_align,
            variable_count,
        })
    }

    /// Reconstruct symbol versioning of a whole ELF image from
    /// `.gnu.version_r` and `.gnu.version_d`.
    ///
    /// # Errors
    /// [`ElfAnalyzerError::Missing`] when neither versioning section is
    /// present, [`ElfAnalyzerError::Parse`] when one of them is malformed,
    /// plus the container errors.
    pub fn analyze_version_info(&self, image: &[u8]) -> Result<VersionInfo, ElfAnalyzerError> {
        let elf = Self::container(image)?;
        let verneed = Self::section_bytes(&elf, image, ".gnu.version_r");
        let verdef = Self::section_bytes(&elf, image, ".gnu.version_d");
        if verneed.is_none() && verdef.is_none() {
            return Err(ElfAnalyzerError::Missing {
                what: "version info",
                missing: ".gnu.version_r and .gnu.version_d sections",
            });
        }
        let dynstr = Self::dynstr_bytes(&elf, image).unwrap_or(&[]);

        let mut needed = Vec::new();
        if let Some(data) = verneed {
            for vn in
                crate::versioning::parse_verneed(data, dynstr).map_err(ElfAnalyzerError::Parse)?
            {
                needed.push(VersionNeeded {
                    file: vn.filename,
                    versions: vn.aux.into_iter().map(|a| a.name).collect(),
                });
            }
        }

        let mut defined = Vec::new();
        if let Some(data) = verdef {
            for vd in
                crate::versioning::parse_verdef(data, dynstr).map_err(ElfAnalyzerError::Parse)?
            {
                for name in vd.names {
                    defined.push(VersionDefined {
                        version: name,
                        flags: vd.flags,
                    });
                }
            }
        }

        Ok(VersionInfo { needed, defined })
    }

    /// Extract the GNU build-ID of a whole ELF image from its note sections
    /// (or, when section headers are gone, its `PT_NOTE` segments).
    ///
    /// # Errors
    /// [`ElfAnalyzerError::Missing`] when no `NT_GNU_BUILD_ID` note is
    /// present, plus the container errors.
    pub fn analyze_build_id(&self, image: &[u8]) -> Result<BuildId, ElfAnalyzerError> {
        let elf = Self::container(image)?;
        let mut ranges: Vec<(usize, usize)> = elf
            .section_headers
            .iter()
            .filter(|sh| sh.sh_type == goblin::elf::section_header::SHT_NOTE)
            .filter_map(|sh| {
                Some((
                    usize::try_from(sh.sh_offset).ok()?,
                    usize::try_from(sh.sh_size).ok()?,
                ))
            })
            .collect();
        if ranges.is_empty() {
            ranges = elf
                .program_headers
                .iter()
                .filter(|ph| ph.p_type == goblin::elf::program_header::PT_NOTE)
                .filter_map(|ph| {
                    Some((
                        usize::try_from(ph.p_offset).ok()?,
                        usize::try_from(ph.p_filesz).ok()?,
                    ))
                })
                .collect();
        }
        for (offset, size) in ranges {
            if offset > image.len() {
                continue;
            }
            let notes = self.parse_notes(image, offset, size);
            if let Some(id) = self.extract_build_id(&notes) {
                return Ok(id);
            }
        }
        Err(ElfAnalyzerError::Missing {
            what: "build ID",
            missing: "NT_GNU_BUILD_ID note",
        })
    }

    // ── Legacy entry points, now byte-derived ──
    //
    // These names used to return fabricated sample values. They stay callable
    // and now delegate to the real parsers above; each one needs the ELF image
    // it claims to describe.

    /// GOT/PLT analysis of `image`. Delegates to [`Self::analyze_got_plt`].
    ///
    /// # Errors
    /// See [`Self::analyze_got_plt`].
    pub fn mock_got_plt(image: &[u8]) -> Result<GotPltAnalysis, ElfAnalyzerError> {
        Self::new().analyze_got_plt(image)
    }

    /// Dynamic section of `image`. Delegates to [`Self::analyze_dynamic`].
    ///
    /// # Errors
    /// See [`Self::analyze_dynamic`].
    pub fn mock_dynamic(image: &[u8]) -> Result<DynamicSection, ElfAnalyzerError> {
        Self::new().analyze_dynamic(image)
    }

    /// TLS layout of `image`. Delegates to [`Self::analyze_tls`].
    ///
    /// # Errors
    /// See [`Self::analyze_tls`].
    pub fn mock_tls(image: &[u8]) -> Result<TlsSection, ElfAnalyzerError> {
        Self::new().analyze_tls(image)
    }

    /// Version info of `image`. Delegates to [`Self::analyze_version_info`].
    ///
    /// # Errors
    /// See [`Self::analyze_version_info`].
    pub fn mock_version_info(image: &[u8]) -> Result<VersionInfo, ElfAnalyzerError> {
        Self::new().analyze_version_info(image)
    }

    /// Build ID of `image`. Delegates to [`Self::analyze_build_id`].
    ///
    /// # Errors
    /// See [`Self::analyze_build_id`].
    pub fn mock_build_id(image: &[u8]) -> Result<BuildId, ElfAnalyzerError> {
        Self::new().analyze_build_id(image)
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a real, self-consistent 64-bit little-endian ELF image in
    /// memory. Nothing in the analyzer is told what to answer: every test
    /// below reads its expectations back out of these bytes through the
    /// ordinary parsers.
    mod fixture {
        const BASE: u64 = 0x0040_0000;
        const FILE_SIZE: usize = 0x2000;

        const O_DYNSYM: usize = 0x0200;
        const O_DYNSTR: usize = 0x0278; // immediately after 5 × 24-byte symbols
        const O_RELAPLT: usize = 0x0400;
        const O_DYNAMIC: usize = 0x0700;
        const O_VERNEED: usize = 0x0900;
        const O_VERDEF: usize = 0x0A00;
        const O_NOTE: usize = 0x0B00;
        const O_TDATA: usize = 0x0C00;
        const O_PLT: usize = 0x1010;
        const O_GOTPLT: usize = 0x1200;
        const O_SHSTR: usize = 0x1400;
        const O_SHDRS: usize = 0x1500;

        const PLT_SIZE: u64 = 64; // PLT0 + 3 stubs, 16 bytes each
        const GOTPLT_SIZE: u64 = 48;
        const RELAPLT_SIZE: u64 = 72; // 3 × Elf64_Rela

        /// The 20 build-ID bytes physically present in the image.
        pub const BUILD_ID: [u8; 20] = [
            0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB,
            0xCD, 0xEF, 0x00, 0x11, 0x22, 0x33,
        ];

        struct Strtab {
            bytes: Vec<u8>,
        }

        impl Strtab {
            fn new() -> Self {
                Self { bytes: vec![0] }
            }
            fn add(&mut self, s: &str) -> u32 {
                let off = u32::try_from(self.bytes.len()).expect("strtab offset fits u32");
                self.bytes.extend_from_slice(s.as_bytes());
                self.bytes.push(0);
                off
            }
        }

        fn put(buf: &mut [u8], off: usize, bytes: &[u8]) {
            buf[off..off + bytes.len()].copy_from_slice(bytes);
        }
        fn put_u16(buf: &mut [u8], off: usize, v: u16) {
            put(buf, off, &v.to_le_bytes());
        }
        fn put_u32(buf: &mut [u8], off: usize, v: u32) {
            put(buf, off, &v.to_le_bytes());
        }
        fn put_u64(buf: &mut [u8], off: usize, v: u64) {
            put(buf, off, &v.to_le_bytes());
        }

        /// The library names the image declares as `DT_NEEDED`.
        pub const NEEDED: [&str; 2] = ["libc.so.6", "libm.so.6"];
        /// The `DT_SONAME` the image declares.
        pub const SONAME: &str = "libexample.so.1";
        /// The `DT_RUNPATH` the image declares.
        pub const RUNPATH: &str = "/usr/local/lib";
        /// The imported symbols, in PLT relocation order.
        pub const IMPORTS: [&str; 3] = ["malloc", "free", "printf"];
        /// Virtual address of `.plt` (its PLT0 header slot).
        pub const PLT_BASE: u64 = BASE + 0x1010;
        /// Virtual address of `.got.plt`.
        pub const GOTPLT_BASE: u64 = BASE + 0x1200;

        /// Assemble the image.
            pub fn elf_image() -> Vec<u8> {
            let mut b = vec![0u8; FILE_SIZE];

            // ── .dynstr ──────────────────────────────────────────────────
            let mut st = Strtab::new();
            let n_libc = st.add(NEEDED[0]);
            let n_libm = st.add(NEEDED[1]);
            let n_soname = st.add(SONAME);
            let n_runpath = st.add(RUNPATH);
            let n_malloc = st.add(IMPORTS[0]);
            let n_free = st.add(IMPORTS[1]);
            let n_printf = st.add(IMPORTS[2]);
            let n_tlsvar = st.add("tls_counter");
            let n_glibc25 = st.add("GLIBC_2.5");
            let n_glibc217 = st.add("GLIBC_2.17");
            let n_mylib = st.add("MYLIB_1.0");
            let dynstr_len = st.bytes.len();
            put(&mut b, O_DYNSTR, &st.bytes);

            // ── .dynsym: null, malloc, free, printf, tls_counter ─────────
            let sym = |buf: &mut [u8], idx: usize, name: u32, info: u8, shndx: u16, val: u64| {
                let o = O_DYNSYM + idx * 24;
                put_u32(buf, o, name);
                buf[o + 4] = info;
                buf[o + 5] = 0;
                put_u16(buf, o + 6, shndx);
                put_u64(buf, o + 8, val);
                put_u64(buf, o + 16, 0);
            };
            // STB_GLOBAL << 4 | STT_FUNC = 0x12, | STT_TLS = 0x16
            sym(&mut b, 1, n_malloc, 0x12, 0, 0);
            sym(&mut b, 2, n_free, 0x12, 0, 0);
            sym(&mut b, 3, n_printf, 0x12, 0, 0);
            sym(&mut b, 4, n_tlsvar, 0x16, 10, 0);

            // ── .rela.plt: three R_X86_64_JUMP_SLOT ──────────────────────
            for (i, sym_idx) in [1u64, 2, 3].into_iter().enumerate() {
                let o = O_RELAPLT + i * 24;
                let got_va = GOTPLT_BASE + 24 + u64::try_from(i).expect("index fits u64") * 8;
                put_u64(&mut b, o, got_va);
                put_u64(&mut b, o + 8, (sym_idx << 32) | 7);
                put_u64(&mut b, o + 16, 0);
            }

            // ── .note.gnu.build-id ───────────────────────────────────────
            put_u32(&mut b, O_NOTE, 4); // namesz "GNU\0"
            put_u32(&mut b, O_NOTE + 4, 20); // descsz
            put_u32(&mut b, O_NOTE + 8, 3); // NT_GNU_BUILD_ID
            put(&mut b, O_NOTE + 12, b"GNU\0");
            put(&mut b, O_NOTE + 16, &BUILD_ID);
            let note_size = 16 + BUILD_ID.len();

            // ── .gnu.version_r: libc.so.6 needs GLIBC_2.5, GLIBC_2.17 ────
            put_u16(&mut b, O_VERNEED, 1); // vn_version
            put_u16(&mut b, O_VERNEED + 2, 2); // vn_cnt
            put_u32(&mut b, O_VERNEED + 4, n_libc); // vn_file
            put_u32(&mut b, O_VERNEED + 8, 16); // vn_aux
            put_u32(&mut b, O_VERNEED + 12, 0); // vn_next
            put_u32(&mut b, O_VERNEED + 16, 0x0b09_2f02); // vna_hash
            put_u16(&mut b, O_VERNEED + 20, 0);
            put_u16(&mut b, O_VERNEED + 22, 2);
            put_u32(&mut b, O_VERNEED + 24, n_glibc25);
            put_u32(&mut b, O_VERNEED + 28, 16); // vna_next
            put_u32(&mut b, O_VERNEED + 32, 0x0698_2f02);
            put_u16(&mut b, O_VERNEED + 36, 0);
            put_u16(&mut b, O_VERNEED + 38, 3);
            put_u32(&mut b, O_VERNEED + 40, n_glibc217);
            put_u32(&mut b, O_VERNEED + 44, 0);

            // ── .gnu.version_d: defines MYLIB_1.0 ────────────────────────
            put_u16(&mut b, O_VERDEF, 1); // vd_version
            put_u16(&mut b, O_VERDEF + 2, 1); // vd_flags (VER_FLG_BASE)
            put_u16(&mut b, O_VERDEF + 4, 1); // vd_ndx
            put_u16(&mut b, O_VERDEF + 6, 1); // vd_cnt
            put_u32(&mut b, O_VERDEF + 8, 0x1234_5678); // vd_hash
            put_u32(&mut b, O_VERDEF + 12, 20); // vd_aux
            put_u32(&mut b, O_VERDEF + 16, 0); // vd_next
            put_u32(&mut b, O_VERDEF + 20, n_mylib);
            put_u32(&mut b, O_VERDEF + 24, 0);

            // ── .dynamic ─────────────────────────────────────────────────
            let dyns: Vec<(u64, u64)> = vec![
                (1, u64::from(n_libc)),                       // DT_NEEDED
                (1, u64::from(n_libm)),                       // DT_NEEDED
                (14, u64::from(n_soname)),                    // DT_SONAME
                (0x1D, u64::from(n_runpath)),                 // DT_RUNPATH
                (12, BASE + 0x1000),                          // DT_INIT
                (13, BASE + 0x1100),                          // DT_FINI
                (24, 0),                                      // DT_BIND_NOW
                (6, BASE + O_DYNSYM as u64),                  // DT_SYMTAB
                (11, 24),                                     // DT_SYMENT
                (5, BASE + O_DYNSTR as u64),                  // DT_STRTAB
                (10, dynstr_len as u64),                      // DT_STRSZ
                (3, GOTPLT_BASE),                             // DT_PLTGOT
                (23, BASE + O_RELAPLT as u64),                // DT_JMPREL
                (2, RELAPLT_SIZE),                            // DT_PLTRELSZ
                (20, 7),                                      // DT_PLTREL = DT_RELA
                (0x6FFF_FFFE, BASE + O_VERNEED as u64),       // DT_VERNEED
                (0x6FFF_FFFF, 1),                             // DT_VERNEEDNUM
                (0x6FFF_FFFC, BASE + O_VERDEF as u64),        // DT_VERDEF
                (0x6FFF_FFFD, 1),                             // DT_VERDEFNUM
                (0, 0),                                       // DT_NULL
            ];
            for (i, (tag, val)) in dyns.iter().enumerate() {
                put_u64(&mut b, O_DYNAMIC + i * 16, *tag);
                put_u64(&mut b, O_DYNAMIC + i * 16 + 8, *val);
            }
            let dynamic_size = (dyns.len() * 16) as u64;

            // ── .shstrtab ────────────────────────────────────────────────
            let mut sh = Strtab::new();
            let s_dynsym = sh.add(".dynsym");
            let s_dynstr = sh.add(".dynstr");
            let s_relaplt = sh.add(".rela.plt");
            let s_plt = sh.add(".plt");
            let s_gotplt = sh.add(".got.plt");
            let s_dynamic = sh.add(".dynamic");
            let s_verneed = sh.add(".gnu.version_r");
            let s_verdef = sh.add(".gnu.version_d");
            let s_note = sh.add(".note.gnu.build-id");
            let s_tdata = sh.add(".tdata");
            let s_shstr = sh.add(".shstrtab");
            let shstr_len = sh.bytes.len() as u64;
            put(&mut b, O_SHSTR, &sh.bytes);

            // ── section headers ──────────────────────────────────────────
            // (name, type, flags, addr, offset, size, link, info, align, entsize)
            let shdrs: Vec<(u32, u32, u64, u64, u64, u64, u32, u32, u64, u64)> = vec![
                (0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
                (s_dynsym, 11, 2, BASE + O_DYNSYM as u64, O_DYNSYM as u64, 5 * 24, 2, 1, 8, 24),
                (s_dynstr, 3, 2, BASE + O_DYNSTR as u64, O_DYNSTR as u64, dynstr_len as u64, 0, 0, 1, 0),
                (s_relaplt, 4, 2, BASE + O_RELAPLT as u64, O_RELAPLT as u64, RELAPLT_SIZE, 1, 4, 8, 24),
                (s_plt, 1, 6, PLT_BASE, O_PLT as u64, PLT_SIZE, 0, 0, 16, 16),
                (s_gotplt, 1, 3, GOTPLT_BASE, O_GOTPLT as u64, GOTPLT_SIZE, 0, 0, 8, 8),
                (s_dynamic, 6, 3, BASE + O_DYNAMIC as u64, O_DYNAMIC as u64, dynamic_size, 2, 0, 8, 16),
                (s_verneed, 0x6FFF_FFFE, 2, BASE + O_VERNEED as u64, O_VERNEED as u64, 48, 2, 1, 8, 0),
                (s_verdef, 0x6FFF_FFFD, 2, BASE + O_VERDEF as u64, O_VERDEF as u64, 28, 2, 1, 8, 0),
                (s_note, 7, 2, BASE + O_NOTE as u64, O_NOTE as u64, note_size as u64, 0, 0, 4, 0),
                (s_tdata, 1, 0x403, BASE + O_TDATA as u64, O_TDATA as u64, 16, 0, 0, 8, 0),
                (s_shstr, 3, 0, 0, O_SHSTR as u64, shstr_len, 0, 0, 1, 0),
            ];
            for (i, s) in shdrs.iter().enumerate() {
                let o = O_SHDRS + i * 64;
                put_u32(&mut b, o, s.0);
                put_u32(&mut b, o + 4, s.1);
                put_u64(&mut b, o + 8, s.2);
                put_u64(&mut b, o + 16, s.3);
                put_u64(&mut b, o + 24, s.4);
                put_u64(&mut b, o + 32, s.5);
                put_u32(&mut b, o + 40, s.6);
                put_u32(&mut b, o + 44, s.7);
                put_u64(&mut b, o + 48, s.8);
                put_u64(&mut b, o + 56, s.9);
            }

            // ── program headers ──────────────────────────────────────────
            // (type, flags, offset, vaddr, filesz, memsz, align)
            let phdrs: Vec<(u32, u32, u64, u64, u64, u64, u64)> = vec![
                (1, 5, 0, BASE, FILE_SIZE as u64, FILE_SIZE as u64, 0x1000),
                (2, 6, O_DYNAMIC as u64, BASE + O_DYNAMIC as u64, dynamic_size, dynamic_size, 8),
                (7, 4, O_TDATA as u64, BASE + O_TDATA as u64, 16, 64, 8),
                (4, 4, O_NOTE as u64, BASE + O_NOTE as u64, note_size as u64, note_size as u64, 4),
            ];
            for (i, p) in phdrs.iter().enumerate() {
                let o = 0x40 + i * 56;
                put_u32(&mut b, o, p.0);
                put_u32(&mut b, o + 4, p.1);
                put_u64(&mut b, o + 8, p.2);
                put_u64(&mut b, o + 16, p.3);
                put_u64(&mut b, o + 24, p.3);
                put_u64(&mut b, o + 32, p.4);
                put_u64(&mut b, o + 40, p.5);
                put_u64(&mut b, o + 48, p.6);
            }

            // ── ELF header ───────────────────────────────────────────────
            put(&mut b, 0, &[0x7F, b'E', b'L', b'F', 2, 1, 1, 0]);
            put_u16(&mut b, 16, 3); // ET_DYN
            put_u16(&mut b, 18, 62); // EM_X86_64
            put_u32(&mut b, 20, 1);
            put_u64(&mut b, 24, BASE + 0x1000); // e_entry
            put_u64(&mut b, 32, 0x40); // e_phoff
            put_u64(&mut b, 40, O_SHDRS as u64); // e_shoff
            put_u32(&mut b, 48, 0);
            put_u16(&mut b, 52, 64); // e_ehsize
            put_u16(&mut b, 54, 56); // e_phentsize
            put_u16(&mut b, 56, u16::try_from(phdrs.len()).expect("phnum"));
            put_u16(&mut b, 58, 64); // e_shentsize
            put_u16(&mut b, 60, u16::try_from(shdrs.len()).expect("shnum"));
            put_u16(&mut b, 62, u16::try_from(shdrs.len() - 1).expect("shstrndx"));

            b
        }
    }


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
        let img = fixture::elf_image();
        let d = ElfAnalyzer::mock_dynamic(&img).expect("dynamic section");
        assert_eq!(d.needed_libs.len(), 2);
        assert!(d.needed_libs.contains(&"libc.so.6".to_string()));
    }

    #[test]
    fn test_dynamic_section_mock_soname() {
        let img = fixture::elf_image();
        let d = ElfAnalyzer::mock_dynamic(&img).expect("dynamic section");
        assert_eq!(d.soname.as_deref(), Some("libexample.so.1"));
    }

    #[test]
    fn test_dynamic_section_mock_runpath() {
        let img = fixture::elf_image();
        let d = ElfAnalyzer::mock_dynamic(&img).expect("dynamic section");
        assert!(d.has_runpath());
        assert_eq!(d.search_path(), Some("/usr/local/lib"));
    }

    #[test]
    fn test_dynamic_section_no_textrel() {
        let img = fixture::elf_image();
        let d = ElfAnalyzer::mock_dynamic(&img).expect("dynamic section");
        assert!(!d.has_textrel);
    }

    #[test]
    fn test_dynamic_section_bind_now() {
        let img = fixture::elf_image();
        let d = ElfAnalyzer::mock_dynamic(&img).expect("dynamic section");
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
        let img = fixture::elf_image();
        let g = ElfAnalyzer::mock_got_plt(&img).expect("got/plt");
        let entries = g.find_symbol("malloc");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].plt_va, 0x0040_1020);
    }

    #[test]
    fn test_got_plt_plt_for() {
        let img = fixture::elf_image();
        let g = ElfAnalyzer::mock_got_plt(&img).expect("got/plt");
        assert_eq!(g.plt_for("free"), Some(0x0040_1030));
        assert_eq!(g.plt_for("unknown"), None);
    }

    #[test]
    fn test_got_plt_entry_count() {
        let img = fixture::elf_image();
        let g = ElfAnalyzer::mock_got_plt(&img).expect("got/plt");
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
        let img = fixture::elf_image();
        let v = ElfAnalyzer::mock_version_info(&img).expect("version info");
        assert_eq!(v.needed.len(), 1);
        assert_eq!(v.needed[0].file, "libc.so.6");
        assert!(v.needed[0].versions.contains(&"GLIBC_2.5".to_string()));
    }

    #[test]
    fn test_version_info_mock_defined() {
        let img = fixture::elf_image();
        let v = ElfAnalyzer::mock_version_info(&img).expect("version info");
        assert_eq!(v.defined.len(), 1);
        assert_eq!(v.defined[0].version, "MYLIB_1.0");
    }

    // ── TlsSection ────────────────────────────────────────────────────────────

    #[test]
    fn test_tls_section_is_present() {
        let img = fixture::elf_image();
        let t = ElfAnalyzer::mock_tls(&img).expect("tls");
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
        let img = fixture::elf_image();
        let b = ElfAnalyzer::mock_build_id(&img).expect("build id");
        assert!(b.is_sha1());
        assert!(!b.is_sha256());
    }

    #[test]
    fn test_build_id_hex_length() {
        let img = fixture::elf_image();
        let b = ElfAnalyzer::mock_build_id(&img).expect("build id");
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
        let img = fixture::elf_image();
        let d = ElfAnalyzer::mock_dynamic(&img).expect("dynamic section");
        assert!(d.init_fn.is_some());
    }
    #[test]
    fn test_dynamic_section_fini_fn() {
        let img = fixture::elf_image();
        let d = ElfAnalyzer::mock_dynamic(&img).expect("dynamic section");
        assert!(d.fini_fn.is_some());
    }
    #[test]
    fn test_got_plt_plt_base() {
        let img = fixture::elf_image();
        let g = ElfAnalyzer::mock_got_plt(&img).expect("got/plt");
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
        let img = fixture::elf_image();
        let t = ElfAnalyzer::mock_tls(&img).expect("tls");
        assert_eq!(t.total_size, 64);
    }
    #[test]
    fn test_version_info_needed_count() {
        let img = fixture::elf_image();
        let v = ElfAnalyzer::mock_version_info(&img).expect("version info");
        assert_eq!(v.needed.len(), 1);
    }
    #[test]
    fn test_build_id_mock_bytes() {
        let img = fixture::elf_image();
        let b = ElfAnalyzer::mock_build_id(&img).expect("build id");
        assert_eq!(b.bytes[0], 0xDE);
    }

    // ── Byte-derived analysis: every value below is read out of the image ──

    #[test]
    fn test_analyze_dynamic_needed_matches_image() {
        let img = fixture::elf_image();
        let d = ElfAnalyzer::new().analyze_dynamic(&img).expect("dynamic");
        assert_eq!(d.needed_libs, fixture::NEEDED.to_vec());
    }

    #[test]
    fn test_analyze_dynamic_rejects_non_elf() {
        let err = ElfAnalyzer::new().analyze_dynamic(b"not an elf at all").unwrap_err();
        assert!(matches!(err, ElfAnalyzerError::NotElf(_)), "{err}");
    }

    #[test]
    fn test_analyze_got_plt_symbols_and_slots() {
        let img = fixture::elf_image();
        let g = ElfAnalyzer::new().analyze_got_plt(&img).expect("got/plt");
        let names: Vec<&str> = g.entries.iter().map(|e| e.symbol.as_str()).collect();
        assert_eq!(names, fixture::IMPORTS.to_vec());
        assert_eq!(g.plt_base, fixture::PLT_BASE);
        assert_eq!(g.got_plt_base, fixture::GOTPLT_BASE);
        // GOT slots start after the three reserved .got.plt words.
        assert_eq!(g.entries[0].got_va, fixture::GOTPLT_BASE + 24);
        assert_eq!(g.entries[2].got_va, fixture::GOTPLT_BASE + 40);
        // The image sets DT_BIND_NOW, so nothing is bound lazily.
        assert!(g.entries.iter().all(|e| !e.is_lazy));
    }

    #[test]
    fn test_analyze_got_plt_reports_missing_plt() {
        // Same image with the .plt section renamed out of existence: the
        // analyzer must name what it is missing instead of inventing entries.
        let mut img = fixture::elf_image();
        let needle = b"\0.plt\0";
        let pos = img
            .windows(needle.len())
            .position(|w| w == needle)
            .expect("section name present");
        img[pos + 2] = b'X';
        let err = ElfAnalyzer::new().analyze_got_plt(&img).unwrap_err();
        match err {
            ElfAnalyzerError::Missing { missing, .. } => assert_eq!(missing, ".plt section"),
            other => panic!("expected Missing, got {other}"),
        }
    }

    #[test]
    fn test_analyze_tls_geometry_from_pt_tls() {
        let img = fixture::elf_image();
        let t = ElfAnalyzer::new().analyze_tls(&img).expect("tls");
        assert_eq!(t.init_size, 16);
        assert_eq!(t.total_size, 64);
        assert_eq!(t.alignment, 8);
        // one STT_TLS symbol in .dynsym
        assert_eq!(t.variable_count, 1);
    }

    #[test]
    fn test_analyze_version_info_from_sections() {
        let img = fixture::elf_image();
        let v = ElfAnalyzer::new()
            .analyze_version_info(&img)
            .expect("version info");
        assert_eq!(v.needed[0].file, "libc.so.6");
        assert_eq!(v.needed[0].versions, vec!["GLIBC_2.5", "GLIBC_2.17"]);
        assert_eq!(v.defined[0].version, "MYLIB_1.0");
    }

    #[test]
    fn test_analyze_build_id_matches_note_bytes() {
        let img = fixture::elf_image();
        let b = ElfAnalyzer::new().analyze_build_id(&img).expect("build id");
        assert_eq!(b.bytes, fixture::BUILD_ID.to_vec());
    }

    #[test]
    fn test_analyze_build_id_missing_is_an_error() {
        // A minimal ELF with no notes at all.
        let mut img = fixture::elf_image();
        // Blank the note so no NT_GNU_BUILD_ID can be found.
        for byte in &mut img[0x0B00..0x0B40] {
            *byte = 0;
        }
        let err = ElfAnalyzer::new().analyze_build_id(&img).unwrap_err();
        assert!(matches!(err, ElfAnalyzerError::Missing { .. }), "{err}");
    }
}
