//! `rustre-loader-elf`
//!
//! Comprehensive ELF loader using the `goblin` crate.
//! Parses and exposes LOAD segments, sections, static and dynamic symbols,
//! needed libraries, build-ID, interpreter path, SONAME, RPATH, and PLT
//! entries with GOT slot addresses.

pub mod arm_exidx;
pub mod elf_stripped_analysis;
pub mod compression;
pub mod elf_dynamic_linker;
pub mod elf_version_script;
pub mod elf_dwarf_reader;
pub mod elf_got_plt_analyzer;
pub mod elf_version_info;
pub mod debug_sections;
pub mod dynamic;
pub mod elf_analyzer;
pub mod elf_dynamic_analysis;
pub mod elf_security;
pub mod gnu_hash;
pub mod headers;
pub mod notes;
pub mod program_headers;
pub mod relocations;
pub mod sections;
pub mod symbols;
pub mod versioning;

pub use elf_dynamic_analysis::{
    DynError, DynSymBinding, DynSymEntry, DynSymType, DynSymVisibility, DynamicEntry,
    DynamicSection, DynamicSymbolTable, DynlibDeps, ElfDynamicAnalysis, GotEntry, GotPltAnalysis,
    GotSlotState, PltEntry as DynPltEntry, RelocRecord, RelocationApplier,
};

pub use debug_sections::{
    AbbrevAttrSpec, AbbrevDecl, Cie, DebugInfoCuHeader, DwarfVersion, Fde, FrameSection,
    LineTableProlog, debug_str_get, parse_debug_abbrev, parse_debug_info_headers, parse_eh_frame,
    parse_line_table_prolog,
};
pub use gnu_hash::{GnuBloomFilter, GnuHashTable, gnu_hash, gnu_hash_str};
pub use notes::{
    ElfNote, ElfNoteSection, GnuBuildId, GnuNoteType, NoteType, Prpsinfo, Prstatus,
    parse_note_section,
};
pub use relocations::{
    Aarch64Reloc, ArmReloc, MipsReloc, Ppc64Reloc, PpcReloc, RelEntry, RelaEntry, RelocTable,
    RiscVReloc, SparcReloc, X86_64Reloc, X86Reloc,
};
pub use versioning::{
    VersionDef, VersionNeed, VersionNeedAux, VersionTable, parse_verdef, parse_verdef_endian,
    parse_verneed, parse_verneed_endian,
};

use std::sync::Arc;

use async_trait::async_trait;
use goblin::elf::Elf;
use goblin::elf::program_header::{PF_R, PF_W, PF_X, PT_INTERP, PT_LOAD};
use goblin::elf::section_header::{SHT_NOTE, SHT_NULL, SHT_SYMTAB};
use goblin::elf::sym::{
    STB_GLOBAL, STB_LOCAL, STB_WEAK, STT_COMMON, STT_FILE, STT_FUNC, STT_NOTYPE, STT_OBJECT,
    STT_SECTION, STT_TLS,
};
use rustre_core::address::{Address, AddressRange};
use rustre_core::binary_view::{BinaryView, Memory, Segment};
use rustre_core::endian::Endian;
use rustre_core::errors::CoreError;
use rustre_core::permissions::Permissions;
use rustre_core::loader::{Loader, LoaderInput, LoadResult, NestedBinary, next_view_id};

// ---------------------------------------------------------------------------
// ELF e_machine constants (subset)
// ---------------------------------------------------------------------------

const EM_386: u16 = 3;
const EM_MIPS: u16 = 8;
const EM_PPC: u16 = 20;
const EM_PPC64: u16 = 21;
const EM_ARM: u16 = 40;
const EM_X86_64: u16 = 62;
const EM_AARCH64: u16 = 183;
const EM_RISCV: u16 = 243;
const EM_S390: u16 = 22;
const EM_SPARC: u16 = 2;
const EM_SPARC32PLUS: u16 = 18;
const EM_SPARCV9: u16 = 43;

// ELF type constants
const ET_EXEC: u16 = 2;
const ET_DYN: u16 = 3;
const ET_REL: u16 = 1;
const ET_CORE: u16 = 4;

// Symbol visibility constants
pub const STV_DEFAULT: u8 = 0;
const STV_INTERNAL: u8 = 1;
const STV_HIDDEN: u8 = 2;
const STV_PROTECTED: u8 = 3;

// GNU note type for build-id
const NT_GNU_BUILD_ID: u32 = 3;

// ---------------------------------------------------------------------------
// Public data types
// ---------------------------------------------------------------------------

/// CPU architecture reported by the ELF file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ElfArch {
    X86,
    X86_64,
    Arm,
    Arm64,
    Mips,
    MipsLe,
    RiscV32,
    RiscV64,
    PowerPc,
    PowerPc64,
    Sparc,
    S390,
    Unknown(u16),
}

/// ELF object file type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ElfType {
    Executable,
    SharedObject,
    Relocatable,
    Core,
    Unknown(u16),
}

/// One loadable ELF segment (`PT_LOAD`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ElfSegment {
    pub segment_type: u32,
    pub offset: u64,
    pub virtual_addr: u64,
    pub physical_addr: u64,
    pub file_size: u64,
    pub mem_size: u64,
    pub flags: u32,
    pub align: u64,
    pub permissions: Permissions,
}

/// One ELF section header entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ElfSection {
    pub name: String,
    pub section_type: u32,
    pub flags: u64,
    pub addr: u64,
    pub offset: u64,
    pub size: u64,
    pub permissions: Permissions,
}

/// Type tag of an ELF symbol.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SymbolType {
    NoType,
    Object,
    Function,
    Section,
    File,
    Common,
    Tls,
    Unknown(u8),
}

/// Binding attribute of an ELF symbol.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SymbolBinding {
    Local,
    Global,
    Weak,
    Unknown(u8),
}

/// Visibility of an ELF symbol.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SymbolVisibility {
    Default,
    Internal,
    Hidden,
    Protected,
}

/// One ELF symbol table entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ElfSymbol {
    pub name: String,
    pub value: u64,
    pub size: u64,
    pub sym_type: SymbolType,
    pub binding: SymbolBinding,
    pub visibility: SymbolVisibility,
    pub section_index: u16,
}

/// A PLT stub and its associated GOT slot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PltEntry {
    pub name: String,
    pub address: u64,
    pub got_address: u64,
}

/// All metadata extracted from an ELF binary.
#[derive(Debug, Clone)]
pub struct ElfInfo {
    pub arch: ElfArch,
    pub bits: u32,
    pub endian: Endian,
    pub elf_type: ElfType,
    pub entry_point: u64,
    pub segments: Vec<ElfSegment>,
    pub sections: Vec<ElfSection>,
    pub symbols: Vec<ElfSymbol>,
    pub dynamic_symbols: Vec<ElfSymbol>,
    pub needed_libs: Vec<String>,
    pub rpath: Option<String>,
    pub soname: Option<String>,
    pub build_id: Option<Vec<u8>>,
    pub interpreter: Option<String>,
    pub plt_entries: Vec<PltEntry>,
    /// Name of the separate debug file from `.gnu_debuglink` (e.g. `"foo.debug"`).
    pub debug_link: Option<String>,
    /// Total number of relocations across all relocation sections.
    pub relocation_count: usize,
    /// `true` when no `.symtab` section is present (binary has been stripped).
    pub stripped: bool,
}

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

fn permissions_from_elf_flags(flags: u32) -> Permissions {
    let mut perms = Permissions::NONE;
    if flags & PF_R != 0 {
        perms |= Permissions::READ;
    }
    if flags & PF_W != 0 {
        perms |= Permissions::WRITE;
    }
    if flags & PF_X != 0 {
        perms |= Permissions::EXECUTE;
    }
    if perms == Permissions::NONE {
        perms = Permissions::READ;
    }
    perms
}

fn permissions_from_section_flags(flags: u64) -> Permissions {
    // SHF_WRITE = 1, SHF_ALLOC = 2, SHF_EXECINSTR = 4
    let mut perms = Permissions::NONE;
    // SHF_ALLOC sections are always readable when mapped
    if flags & 0x2 != 0 {
        perms |= Permissions::READ;
    }
    if flags & 0x1 != 0 {
        perms |= Permissions::WRITE;
    }
    if flags & 0x4 != 0 {
        perms |= Permissions::EXECUTE;
    }
    if perms == Permissions::NONE {
        perms = Permissions::READ;
    }
    perms
}

const fn elf_arch_from_machine(machine: u16, is_little_endian: bool) -> ElfArch {
    match machine {
        EM_386 => ElfArch::X86,
        EM_X86_64 => ElfArch::X86_64,
        EM_ARM => ElfArch::Arm,
        EM_AARCH64 => ElfArch::Arm64,
        EM_MIPS => {
            if is_little_endian {
                ElfArch::MipsLe
            } else {
                ElfArch::Mips
            }
        }
        EM_RISCV => ElfArch::RiscV64, // distinguish 32/64 via class elsewhere
        EM_PPC => ElfArch::PowerPc,
        EM_PPC64 => ElfArch::PowerPc64,
        EM_S390 => ElfArch::S390,
        EM_SPARC | EM_SPARC32PLUS | EM_SPARCV9 => ElfArch::Sparc,
        other => ElfArch::Unknown(other),
    }
}

const fn elf_type_from_u16(t: u16) -> ElfType {
    match t {
        ET_EXEC => ElfType::Executable,
        ET_DYN => ElfType::SharedObject,
        ET_REL => ElfType::Relocatable,
        ET_CORE => ElfType::Core,
        other => ElfType::Unknown(other),
    }
}

const fn sym_type_from_u8(t: u8) -> SymbolType {
    match t {
        STT_NOTYPE => SymbolType::NoType,
        STT_OBJECT => SymbolType::Object,
        STT_FUNC => SymbolType::Function,
        STT_SECTION => SymbolType::Section,
        STT_FILE => SymbolType::File,
        STT_COMMON => SymbolType::Common,
        STT_TLS => SymbolType::Tls,
        other => SymbolType::Unknown(other),
    }
}

const fn sym_binding_from_u8(b: u8) -> SymbolBinding {
    match b {
        STB_LOCAL => SymbolBinding::Local,
        STB_GLOBAL => SymbolBinding::Global,
        STB_WEAK => SymbolBinding::Weak,
        other => SymbolBinding::Unknown(other),
    }
}

const fn sym_visibility_from_u8(v: u8) -> SymbolVisibility {
    match v & 0x3 {
        STV_INTERNAL => SymbolVisibility::Internal,
        STV_HIDDEN => SymbolVisibility::Hidden,
        STV_PROTECTED => SymbolVisibility::Protected,
        _ => SymbolVisibility::Default,
    }
}

/// Convert a goblin `Sym` + strtab into our `ElfSymbol`.
fn goblin_sym_to_elf_symbol(sym: &goblin::elf::Sym, name: &str) -> ElfSymbol {
    ElfSymbol {
        name: name.to_string(),
        value: sym.st_value,
        size: sym.st_size,
        sym_type: sym_type_from_u8(sym.st_type()),
        binding: sym_binding_from_u8(sym.st_bind()),
        visibility: sym_visibility_from_u8(sym.st_other),
        section_index: u16::try_from(sym.st_shndx).unwrap_or(u16::MAX),
    }
}

/// Extract the GNU build-id from a `.note.gnu.build-id` section.
/// The section data is an ELF note: namesz (4), descsz (4), type (4), name, desc.
fn parse_build_id(section_data: &[u8], little_endian: bool) -> Option<Vec<u8>> {
    if section_data.len() < 12 {
        return None;
    }
    let read_u32 = |b: &[u8]| -> Option<u32> {
        let arr: [u8; 4] = b.try_into().ok()?;
        if little_endian { Some(u32::from_le_bytes(arr)) } else { Some(u32::from_be_bytes(arr)) }
    };
    let namesz = read_u32(&section_data[0..4])? as usize;
    let descsz = read_u32(&section_data[4..8])? as usize;
    let note_type = read_u32(&section_data[8..12])?;
    if note_type != NT_GNU_BUILD_ID {
        return None;
    }
    // Name is aligned to 4 bytes
    let name_aligned = namesz.checked_add(3).map(|v| v & !3)?;
    let desc_start = 12usize.checked_add(name_aligned)?;
    if desc_start.checked_add(descsz)? > section_data.len() {
        return None;
    }
    Some(section_data[desc_start..desc_start + descsz].to_vec())
}

// ---------------------------------------------------------------------------
// ElfInfo parse helpers
// ---------------------------------------------------------------------------

fn parse_elf_segments(
    elf: &Elf<'_>,
    data: &[u8],
) -> (Vec<ElfSegment>, Option<String>) {
    let mut segments = Vec::with_capacity(elf.program_headers.len());
    let mut interpreter: Option<String> = None;
    for ph in &elf.program_headers {
        let seg_type = ph.p_type;
        let perms = permissions_from_elf_flags(ph.p_flags);
        if seg_type == PT_INTERP {
            let off = usize::try_from(ph.p_offset).unwrap_or(usize::MAX);
            let fsz = usize::try_from(ph.p_filesz).unwrap_or(usize::MAX);
            if off + fsz <= data.len() && fsz > 0 {
                let slice = &data[off..off + fsz];
                let nul = slice.iter().position(|&b| b == 0).unwrap_or(fsz);
                interpreter = Some(String::from_utf8_lossy(&slice[..nul]).to_string());
            }
        }
        segments.push(ElfSegment {
            segment_type: seg_type,
            offset: ph.p_offset,
            virtual_addr: ph.p_vaddr,
            physical_addr: ph.p_paddr,
            file_size: ph.p_filesz,
            mem_size: ph.p_memsz,
            flags: ph.p_flags,
            align: ph.p_align,
            permissions: perms,
        });
    }
    (segments, interpreter)
}

/// Intermediate result of section parsing: sections, build-id, debug-link, gnu-hash bytes, stripped flag.
type SectionParseResult = (Vec<ElfSection>, Option<Vec<u8>>, Option<String>, Option<Vec<u8>>, bool);

fn parse_elf_sections(
    elf: &Elf<'_>,
    data: &[u8],
    is_little_endian: bool,
) -> SectionParseResult {
    let mut sections = Vec::with_capacity(elf.section_headers.len());
    let mut build_id: Option<Vec<u8>> = None;
    let mut debug_link: Option<String> = None;
    let mut gnu_hash_data: Option<Vec<u8>> = None;
    let mut has_symtab = false;

    for sh in &elf.section_headers {
        if sh.sh_type == SHT_NULL {
            continue;
        }
        let name = elf.shdr_strtab.get_at(sh.sh_name).unwrap_or("").to_string();
        let perms = permissions_from_section_flags(sh.sh_flags);
        if sh.sh_type == SHT_SYMTAB {
            has_symtab = true;
        }
        if sh.sh_type == SHT_NOTE
            && (name == ".note.gnu.build-id" || name.contains("build-id"))
            && build_id.is_none()
        {
            let off = usize::try_from(sh.sh_offset).unwrap_or(usize::MAX);
            let sz = usize::try_from(sh.sh_size).unwrap_or(usize::MAX);
            if off + sz <= data.len() {
                build_id = parse_build_id(&data[off..off + sz], is_little_endian);
            }
        }
        if name == ".gnu_debuglink" && debug_link.is_none() {
            let off = usize::try_from(sh.sh_offset).unwrap_or(usize::MAX);
            let sz = usize::try_from(sh.sh_size).unwrap_or(usize::MAX);
            if off + sz <= data.len() && sz > 4 {
                let slice = &data[off..off + sz];
                if let Some(nul) = slice.iter().position(|&b| b == 0)
                    && let Ok(s) = std::str::from_utf8(&slice[..nul])
                    && !s.is_empty()
                {
                    debug_link = Some(s.to_string());
                }
            }
        }
        if name == ".gnu.hash" && gnu_hash_data.is_none() {
            let off = usize::try_from(sh.sh_offset).unwrap_or(usize::MAX);
            let sz = usize::try_from(sh.sh_size).unwrap_or(usize::MAX);
            if off + sz <= data.len() {
                gnu_hash_data = Some(data[off..off + sz].to_vec());
            }
        }
        sections.push(ElfSection {
            name,
            section_type: sh.sh_type,
            flags: sh.sh_flags,
            addr: sh.sh_addr,
            offset: sh.sh_offset,
            size: sh.sh_size,
            permissions: perms,
        });
    }
    (sections, build_id, debug_link, gnu_hash_data, !has_symtab)
}

fn parse_elf_symbols(
    elf: &Elf<'_>,
    gnu_hash_data: Option<&[u8]>,
    is_little_endian: bool,
) -> (Vec<ElfSymbol>, Vec<ElfSymbol>) {
    let mut symbols = Vec::with_capacity(elf.syms.len());
    for sym in &elf.syms {
        let name = elf.strtab.get_at(sym.st_name).unwrap_or("").to_string();
        symbols.push(goblin_sym_to_elf_symbol(&sym, &name));
    }
    let mut dynamic_symbols = Vec::with_capacity(elf.dynsyms.len());
    for sym in &elf.dynsyms {
        let name = elf.dynstrtab.get_at(sym.st_name).unwrap_or("").to_string();
        dynamic_symbols.push(goblin_sym_to_elf_symbol(&sym, &name));
    }
    if let Some(gh_bytes) = gnu_hash_data
        && let Ok(gnu_ht) = crate::gnu_hash::GnuHashTable::parse64(gh_bytes, is_little_endian)
    {
        let existing_count = dynamic_symbols.len();
        for sym_idx in gnu_ht.scan_all_symbols() {
            let idx = sym_idx as usize;
            if idx >= existing_count
                && let Some(sym) = elf.dynsyms.get(idx)
            {
                let name = elf.dynstrtab.get_at(sym.st_name).unwrap_or("").to_string();
                dynamic_symbols.push(goblin_sym_to_elf_symbol(&sym, &name));
            }
        }
    }
    (symbols, dynamic_symbols)
}

// ---------------------------------------------------------------------------
// ElfInfo implementation
// ---------------------------------------------------------------------------

impl ElfInfo {
    /// Parse a raw ELF binary and extract all available metadata.
    ///
    /// # Errors
    /// Returns an error string if the ELF binary is malformed or cannot be parsed.
    pub fn parse(data: &[u8]) -> Result<Self, String> {
        let elf = Elf::parse(data).map_err(|e| e.to_string())?;

        let is_little_endian = elf.little_endian;
        let endian = if is_little_endian { Endian::Little } else { Endian::Big };
        let bits = if elf.is_64 { 64u32 } else { 32u32 };
        let arch = elf_arch_from_machine(elf.header.e_machine, is_little_endian);
        let arch = match arch {
            ElfArch::RiscV64 if bits == 32 => ElfArch::RiscV32,
            other => other,
        };
        let elf_type = elf_type_from_u16(elf.header.e_type);
        let entry_point = elf.header.e_entry;

        let (segments, interpreter) = parse_elf_segments(&elf, data);
        let (sections, build_id, debug_link, gnu_hash_data, stripped) =
            parse_elf_sections(&elf, data, is_little_endian);
        let (symbols, dynamic_symbols) =
            parse_elf_symbols(&elf, gnu_hash_data.as_deref(), is_little_endian);

        let needed_libs: Vec<String> =
            elf.libraries.iter().map(std::string::ToString::to_string).collect();
        let rpath = elf.rpaths.first().map(std::string::ToString::to_string);
        let soname = elf.soname.map(str::to_string);

        let relocation_count = elf.dynrelas.iter().count()
            + elf.dynrels.iter().count()
            + elf.pltrelocs.iter().count()
            + elf.shdr_relocs.iter().map(|(_, rs)| rs.iter().count()).sum::<usize>();

        let plt_entries = build_plt_entries(&elf, &sections);

        Ok(Self {
            arch, bits, endian, elf_type, entry_point,
            segments, sections, symbols, dynamic_symbols,
            needed_libs, rpath, soname, build_id,
            interpreter, plt_entries, debug_link,
            relocation_count, stripped,
        })
    }

    // -----------------------------------------------------------------------
    // Convenience accessors
    // -----------------------------------------------------------------------

    /// Returns the PLT entries for this binary.
    #[must_use]
    pub fn plt_entries(&self) -> &[PltEntry] {
        &self.plt_entries
    }

    /// Returns the GNU build-ID bytes, if present.
    #[must_use]
    pub fn build_id(&self) -> Option<&[u8]> {
        self.build_id.as_deref()
    }

    /// Returns the separate debug-file name from `.gnu_debuglink`, if present.
    #[must_use]
    pub fn debug_link(&self) -> Option<&str> {
        self.debug_link.as_deref()
    }

    /// Returns `true` if the binary has no `.symtab` section (has been stripped).
    #[must_use]
    pub const fn is_stripped(&self) -> bool {
        self.stripped
    }

    /// Total number of relocations (RELA + REL + PLT) across the whole binary.
    #[must_use]
    pub const fn relocation_count(&self) -> usize {
        self.relocation_count
    }
}

/// Build PLT entries by combining `.plt` section base address with
/// `.rela.plt` / `.rel.plt` relocation entries.
fn build_plt_entries(elf: &Elf<'_>, sections: &[ElfSection]) -> Vec<PltEntry> {
    let mut entries = Vec::new();

    // Find the PLT section base and entry size (typically 16 bytes for x86-64).
    let plt_section = sections.iter().find(|s| s.name == ".plt");
    let plt_base = plt_section.map_or(0, |s| s.addr);
    // PLT entry size is architecture-dependent; 16 bytes for x86-64/aarch64.
    let plt_entry_size: u64 = 16;

    // RELA relocations
    for (idx, rela) in elf.pltrelocs.iter().enumerate() {
        let sym_idx = rela.r_sym;
        let got_addr = rela.r_offset;
        let name = if sym_idx < elf.dynsyms.len() {
            elf.dynstrtab
                .get_at(elf.dynsyms.get(sym_idx).map_or(0, |s| s.st_name))
                .unwrap_or("")
                .to_string()
        } else {
            format!("plt_{idx}")
        };

        // PLT stub: skip the first (resolver) entry
        let plt_addr = if plt_base > 0 {
            plt_base + (idx as u64 + 1) * plt_entry_size
        } else {
            0
        };

        if !name.is_empty() || plt_addr > 0 {
            entries.push(PltEntry {
                name,
                address: plt_addr,
                got_address: got_addr,
            });
        }
    }

    entries
}

// ---------------------------------------------------------------------------
// Architecture stub for ELF files
// ---------------------------------------------------------------------------

/// Stub architecture used when creating a `BinaryView` for an ELF binary.
#[derive(Debug)]
struct ElfArchStub {
    arch_name: String,
    ptr_size: usize,
    endian: Endian,
}

impl rustre_core::arch::Architecture for ElfArchStub {
    fn name(&self) -> &str {
        &self.arch_name
    }

    fn pointer_size(&self) -> usize {
        self.ptr_size
    }

    fn endian(&self) -> Endian {
        self.endian
    }

    fn disassemble(
        &self,
        address: Address,
        _bytes: &[u8],
    ) -> Result<rustre_core::arch::Instruction, CoreError> {
        Ok(rustre_core::arch::Instruction::new(
            address,
            1,
            "nop",
            vec![0x00],
        ))
    }

    fn get_branches(
        &self,
        _instr: &rustre_core::arch::Instruction,
    ) -> Vec<rustre_core::arch::BranchInfo> {
        vec![]
    }

    fn registers(&self) -> Vec<rustre_core::arch::RegisterInfo> {
        vec![]
    }

    fn calling_conventions(&self) -> Vec<rustre_core::arch::CallingConvention> {
        vec![]
    }
}

fn make_arch_stub(info: &ElfInfo) -> Arc<dyn rustre_core::arch::Architecture> {
    let (name, ptr) = match &info.arch {
        crate::ElfArch::X86 => ("x86", 4usize),
        crate::ElfArch::X86_64 => ("x86_64", 8),
        crate::ElfArch::Arm => ("arm", 4),
        crate::ElfArch::Arm64 => ("aarch64", 8),
        crate::ElfArch::Mips => ("mips", 4),
        crate::ElfArch::MipsLe => ("mipsel", 4),
        crate::ElfArch::RiscV32 => ("riscv32", 4),
        crate::ElfArch::RiscV64 => ("riscv64", 8),
        crate::ElfArch::PowerPc => ("powerpc", 4),
        crate::ElfArch::PowerPc64 => ("powerpc64", 8),
        crate::ElfArch::Sparc => ("sparc", 4),
        crate::ElfArch::S390 => ("s390x", 8),
        crate::ElfArch::Unknown(_) => ("unknown", 8),
    };
    Arc::new(ElfArchStub {
        arch_name: name.to_string(),
        ptr_size: ptr,
        endian: info.endian,
    })
}

// ---------------------------------------------------------------------------
// ElfLoader — implements the Loader trait
// ---------------------------------------------------------------------------

/// Full ELF loader backed by `goblin`.
#[derive(Debug)]
pub struct ElfLoader;

#[async_trait]
impl Loader for ElfLoader {
    fn name(&self) -> &'static str {
        "elf"
    }

    fn can_load(&self, input: &LoaderInput) -> bool {
        input.data.starts_with(&[0x7f, b'E', b'L', b'F'])
    }

    async fn load(&self, input: LoaderInput) -> Result<LoadResult, CoreError> {
        if !self.can_load(&input) {
            return Err(CoreError::LoaderError {
                loader: "elf".into(),
                message: "Not a valid ELF binary".into(),
            });
        }

        let info = ElfInfo::parse(&input.data).map_err(|e| CoreError::LoaderError {
            loader: "elf".into(),
            message: format!("ELF parse error: {e}"),
        })?;

        let arch = make_arch_stub(&info);
        let mut mem = Memory::new();

        // Map all PT_LOAD segments into memory.
        for seg in &info.segments {
            if seg.segment_type != PT_LOAD || seg.mem_size == 0 {
                continue;
            }
            let vaddr = seg.virtual_addr;
            // Guard against mem_size values too large to allocate.
            let mem_size = match usize::try_from(seg.mem_size) {
                Ok(s) if s <= 0x4000_0000 => s, // 1 GiB cap per segment
                _ => {
                    // Segment claims an unreasonable size; skip it.
                    continue;
                }
            };

            // Build segment data: copy file bytes then zero-pad to mem_size.
            let mut seg_data = vec![0u8; mem_size];
            let Ok(file_off) = usize::try_from(seg.offset) else { continue };
            let file_size = match usize::try_from(seg.file_size) {
                Ok(fs) => fs.min(mem_size),
                Err(_) => continue,
            };
            if file_off.checked_add(file_size).is_some_and(|end| end <= input.data.len()) && file_size > 0 {
                seg_data[..file_size].copy_from_slice(&input.data[file_off..file_off + file_size]);
            }

            let seg_end_vaddr = vaddr.saturating_add(mem_size as u64);
            mem.add_segment(Segment {
                range: AddressRange::new(
                    Address::new(vaddr),
                    Address::new(seg_end_vaddr),
                ),
                permissions: seg.permissions,
                data: seg_data,
            });
        }

        // Fallback: if no LOAD segments present, map the whole file.
        if mem.segments.is_empty() {
            mem.add_segment(Segment {
                range: AddressRange::new(Address::new(0), Address::new(input.data.len() as u64)),
                permissions: Permissions::READ | Permissions::EXECUTE,
                data: input.data.clone(),
            });
        }

        // Entry point list.
        let entry_points = if info.entry_point != 0 {
            vec![Address::new(info.entry_point)]
        } else {
            // No entry point: use the start of the first executable segment.
            mem.segments
                .iter()
                .find(|s| s.permissions.is_executable()).map_or_else(|| vec![Address::new(0)], |s| vec![s.range.start])
        };

        let view = BinaryView::new(
            next_view_id(),
            input.uri,
            arch,
            info.endian,
            info.bits,
            entry_points,
            mem,
        );

        Ok(LoadResult::new(view))
    }

    async fn find_nested(&self, _input: &LoaderInput) -> Result<Vec<NestedBinary>, CoreError> {
        Ok(vec![])
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Minimal ELF builder helpers
    // -----------------------------------------------------------------------

    /// Emit a 4-byte little-endian integer into `buf` at `offset`.
    fn write_u32_le(buf: &mut [u8], offset: usize, val: u32) {
        buf[offset..offset + 4].copy_from_slice(&val.to_le_bytes());
    }

    /// Emit a 4-byte big-endian integer into `buf` at `offset`.
    fn write_u32_be(buf: &mut [u8], offset: usize, val: u32) {
        buf[offset..offset + 4].copy_from_slice(&val.to_be_bytes());
    }

    /// Emit an 8-byte little-endian integer into `buf` at `offset`.
    fn write_u64_le(buf: &mut [u8], offset: usize, val: u64) {
        buf[offset..offset + 8].copy_from_slice(&val.to_le_bytes());
    }

    /// Build a minimal valid 64-bit little-endian ELF executable for x86-64.
    ///
    /// Layout:
    ///   - ELF header (64 bytes)
    ///   - One `PT_LOAD` program header (56 bytes)
    ///   - Code section (.text): 16 NOPs mapped at 0x401000
    fn build_minimal_elf64_le() -> Vec<u8> {
        // We will have:
        //   ELF header: 64 bytes
        //   1 program header: 56 bytes    (total: 120 bytes of headers)
        //   1 section header: 64 bytes
        //   section name table: 8 bytes ("\0.text\0")
        // Code payload at offset 0x200 (512 bytes from start)
        let code_offset: usize = 0x200;
        let code_size: usize = 16;
        let total_size = code_offset + code_size;

        let mut buf = vec![0u8; total_size];

        // ELF ident
        buf[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
        buf[4] = 2; // EI_CLASS: ELFCLASS64
        buf[5] = 1; // EI_DATA: ELFDATA2LSB
        buf[6] = 1; // EI_VERSION: EV_CURRENT
        // EI_OSABI, EI_ABIVERSION, padding: remain 0

        // e_type = ET_EXEC (2)
        buf[16..18].copy_from_slice(&2u16.to_le_bytes());
        // e_machine = EM_X86_64 (62)
        buf[18..20].copy_from_slice(&62u16.to_le_bytes());
        // e_version = 1
        write_u32_le(&mut buf, 20, 1);
        // e_entry = 0x401000
        write_u64_le(&mut buf, 24, 0x40_1000);
        // e_phoff = 64 (right after ELF header)
        write_u64_le(&mut buf, 32, 64);
        // e_shoff = 120 (after ELF header + 1 PH)
        write_u64_le(&mut buf, 40, 120);
        // e_flags = 0
        write_u32_le(&mut buf, 48, 0);
        // e_ehsize = 64
        buf[52..54].copy_from_slice(&64u16.to_le_bytes());
        // e_phentsize = 56
        buf[54..56].copy_from_slice(&56u16.to_le_bytes());
        // e_phnum = 1
        buf[56..58].copy_from_slice(&1u16.to_le_bytes());
        // e_shentsize = 64
        buf[58..60].copy_from_slice(&64u16.to_le_bytes());
        // e_shnum = 0 (we keep it simple: no section headers)
        buf[60..62].copy_from_slice(&0u16.to_le_bytes());
        // e_shstrndx = 0
        buf[62..64].copy_from_slice(&0u16.to_le_bytes());

        // Program header at offset 64 (PT_LOAD)
        let ph = 64usize;
        // p_type = PT_LOAD (1)
        write_u32_le(&mut buf, ph, 1);
        // p_flags = PF_R | PF_X = 5
        write_u32_le(&mut buf, ph + 4, 5);
        // p_offset = code_offset
        write_u64_le(&mut buf, ph + 8, code_offset as u64);
        // p_vaddr = 0x401000
        write_u64_le(&mut buf, ph + 16, 0x40_1000);
        // p_paddr = 0x401000
        write_u64_le(&mut buf, ph + 24, 0x40_1000);
        // p_filesz = code_size
        write_u64_le(&mut buf, ph + 32, code_size as u64);
        // p_memsz = code_size
        write_u64_le(&mut buf, ph + 40, code_size as u64);
        // p_align = 0x1000
        write_u64_le(&mut buf, ph + 48, 0x1000);

        // Fill code with NOPs
        for byte in &mut buf[code_offset..code_offset + code_size] {
            *byte = 0x90;
        }

        buf
    }

    /// Build a minimal 32-bit big-endian ELF (MIPS) for endian detection testing.
    fn build_minimal_elf32_be_mips() -> Vec<u8> {
        let code_offset: usize = 0x200;
        let code_size: usize = 16;
        let total = code_offset + code_size;
        let mut buf = vec![0u8; total];

        buf[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
        buf[4] = 1; // ELFCLASS32
        buf[5] = 2; // ELFDATA2MSB (big-endian)
        buf[6] = 1; // EV_CURRENT

        // e_type = ET_EXEC (2) — big-endian
        buf[16..18].copy_from_slice(&2u16.to_be_bytes());
        // e_machine = EM_MIPS (8)
        buf[18..20].copy_from_slice(&8u16.to_be_bytes());
        // e_version
        write_u32_be(&mut buf, 20, 1);
        // e_entry = 0x10000 (32-bit entry in ELF32 is 4 bytes at offset 24)
        write_u32_be(&mut buf, 24, 0x0001_0000);
        // e_phoff = 52 (ELF32 header size)
        write_u32_be(&mut buf, 28, 52);
        // e_shoff = 0
        write_u32_be(&mut buf, 32, 0);
        // e_flags = 0
        write_u32_be(&mut buf, 36, 0);
        // e_ehsize = 52
        buf[40..42].copy_from_slice(&52u16.to_be_bytes());
        // e_phentsize = 32
        buf[42..44].copy_from_slice(&32u16.to_be_bytes());
        // e_phnum = 1
        buf[44..46].copy_from_slice(&1u16.to_be_bytes());
        // e_shentsize = 40
        buf[46..48].copy_from_slice(&40u16.to_be_bytes());
        // e_shnum = 0
        buf[48..50].copy_from_slice(&0u16.to_be_bytes());
        // e_shstrndx = 0
        buf[50..52].copy_from_slice(&0u16.to_be_bytes());

        // ELF32 program header (32 bytes) at offset 52
        let ph = 52usize;
        // p_type = PT_LOAD
        write_u32_be(&mut buf, ph, 1);
        // p_offset
        write_u32_be(&mut buf, ph + 4, code_offset as u32);
        // p_vaddr
        write_u32_be(&mut buf, ph + 8, 0x0001_0000);
        // p_paddr
        write_u32_be(&mut buf, ph + 12, 0x0001_0000);
        // p_filesz
        write_u32_be(&mut buf, ph + 16, code_size as u32);
        // p_memsz
        write_u32_be(&mut buf, ph + 20, code_size as u32);
        // p_flags = PF_R | PF_X = 5
        write_u32_be(&mut buf, ph + 24, 5);
        // p_align
        write_u32_be(&mut buf, ph + 28, 0x1000);

        buf
    }

    // -----------------------------------------------------------------------
    // can_load tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_can_load_rejects_empty() {
        let loader = ElfLoader;
        let input = LoaderInput::new(String::new(), vec![]);
        assert!(!loader.can_load(&input));
    }

    #[test]
    fn test_can_load_rejects_pe() {
        let loader = ElfLoader;
        let mut data = vec![0u8; 256];
        data[0..2].copy_from_slice(b"MZ");
        let input = LoaderInput::new(String::new(), data);
        assert!(!loader.can_load(&input));
    }

    #[test]
    fn test_can_load_rejects_random_data() {
        let loader = ElfLoader;
        let input = LoaderInput::new(String::new(), b"this is not an elf".to_vec());
        assert!(!loader.can_load(&input));
    }

    #[test]
    fn test_can_load_accepts_elf64_le() {
        let loader = ElfLoader;
        let data = build_minimal_elf64_le();
        let input = LoaderInput::new("test.elf", data);
        assert!(loader.can_load(&input));
    }

    #[test]
    fn test_can_load_accepts_elf32_be() {
        let loader = ElfLoader;
        let data = build_minimal_elf32_be_mips();
        let input = LoaderInput::new("test.mips", data);
        assert!(loader.can_load(&input));
    }

    // -----------------------------------------------------------------------
    // ElfInfo::parse tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_elf_info_parse_elf64_le() {
        let data = build_minimal_elf64_le();
        let info = ElfInfo::parse(&data).expect("parse should succeed");
        assert_eq!(info.bits, 64);
        assert_eq!(info.endian, Endian::Little);
        assert_eq!(info.arch, crate::ElfArch::X86_64);
        assert_eq!(info.elf_type, ElfType::Executable);
        assert_eq!(info.entry_point, 0x40_1000);
    }

    #[test]
    fn test_elf_info_parse_elf32_be_mips() {
        let data = build_minimal_elf32_be_mips();
        let info = ElfInfo::parse(&data).expect("parse should succeed");
        assert_eq!(info.bits, 32);
        assert_eq!(info.endian, Endian::Big);
        assert_eq!(info.arch, crate::ElfArch::Mips);
        assert_eq!(info.entry_point, 0x0001_0000);
    }

    #[test]
    fn test_elf_info_segments_elf64() {
        let data = build_minimal_elf64_le();
        let info = ElfInfo::parse(&data).expect("parse should succeed");
        assert!(!info.segments.is_empty());
        let load_segs: Vec<_> = info
            .segments
            .iter()
            .filter(|s| s.segment_type == PT_LOAD)
            .collect();
        assert_eq!(load_segs.len(), 1);
        let seg = &load_segs[0];
        assert_eq!(seg.virtual_addr, 0x40_1000);
        assert_eq!(seg.file_size, 16);
        assert!(seg.permissions.is_readable());
        assert!(seg.permissions.is_executable());
        assert!(!seg.permissions.is_writable());
    }

    #[test]
    fn test_elf_info_no_symbols_in_minimal() {
        let data = build_minimal_elf64_le();
        let info = ElfInfo::parse(&data).expect("parse should succeed");
        // Minimal ELF has no symbol tables
        assert!(info.symbols.is_empty());
        assert!(info.dynamic_symbols.is_empty());
    }

    #[test]
    fn test_elf_info_no_needed_libs_in_minimal() {
        let data = build_minimal_elf64_le();
        let info = ElfInfo::parse(&data).expect("parse should succeed");
        assert!(info.needed_libs.is_empty());
        assert!(info.rpath.is_none());
        assert!(info.soname.is_none());
        assert!(info.build_id.is_none());
        assert!(info.interpreter.is_none());
        assert!(info.plt_entries.is_empty());
    }

    // -----------------------------------------------------------------------
    // ElfType conversion tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_elf_type_from_u16() {
        assert_eq!(elf_type_from_u16(ET_EXEC), ElfType::Executable);
        assert_eq!(elf_type_from_u16(ET_DYN), ElfType::SharedObject);
        assert_eq!(elf_type_from_u16(ET_REL), ElfType::Relocatable);
        assert_eq!(elf_type_from_u16(ET_CORE), ElfType::Core);
        assert_eq!(elf_type_from_u16(0xFF), ElfType::Unknown(0xFF));
    }

    // -----------------------------------------------------------------------
    // ElfArch conversion tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_elf_arch_x86() {
        assert_eq!(elf_arch_from_machine(EM_386, true), crate::ElfArch::X86);
    }

    #[test]
    fn test_elf_arch_x86_64() {
        assert_eq!(
            elf_arch_from_machine(EM_X86_64, true),
            crate::ElfArch::X86_64
        );
    }

    #[test]
    fn test_elf_arch_arm() {
        assert_eq!(elf_arch_from_machine(EM_ARM, true), crate::ElfArch::Arm);
    }

    #[test]
    fn test_elf_arch_aarch64() {
        assert_eq!(
            elf_arch_from_machine(EM_AARCH64, true),
            crate::ElfArch::Arm64
        );
    }

    #[test]
    fn test_elf_arch_mips_be() {
        assert_eq!(elf_arch_from_machine(EM_MIPS, false), crate::ElfArch::Mips);
    }

    #[test]
    fn test_elf_arch_mips_le() {
        assert_eq!(elf_arch_from_machine(EM_MIPS, true), crate::ElfArch::MipsLe);
    }

    #[test]
    fn test_elf_arch_riscv64() {
        assert_eq!(
            elf_arch_from_machine(EM_RISCV, true),
            crate::ElfArch::RiscV64
        );
    }

    #[test]
    fn test_elf_arch_ppc() {
        assert_eq!(
            elf_arch_from_machine(EM_PPC, false),
            crate::ElfArch::PowerPc
        );
    }

    #[test]
    fn test_elf_arch_ppc64() {
        assert_eq!(
            elf_arch_from_machine(EM_PPC64, false),
            crate::ElfArch::PowerPc64
        );
    }

    #[test]
    fn test_elf_arch_s390() {
        assert_eq!(elf_arch_from_machine(EM_S390, false), crate::ElfArch::S390);
    }

    #[test]
    fn test_elf_arch_sparc() {
        assert_eq!(
            elf_arch_from_machine(EM_SPARC, false),
            crate::ElfArch::Sparc
        );
    }

    #[test]
    fn test_elf_arch_unknown() {
        assert_eq!(
            elf_arch_from_machine(0xBEEF, true),
            crate::ElfArch::Unknown(0xBEEF)
        );
    }

    // -----------------------------------------------------------------------
    // Symbol helpers tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_sym_type_from_u8() {
        assert_eq!(sym_type_from_u8(STT_NOTYPE), SymbolType::NoType);
        assert_eq!(sym_type_from_u8(STT_OBJECT), SymbolType::Object);
        assert_eq!(sym_type_from_u8(STT_FUNC), SymbolType::Function);
        assert_eq!(sym_type_from_u8(STT_SECTION), SymbolType::Section);
        assert_eq!(sym_type_from_u8(STT_FILE), SymbolType::File);
        assert_eq!(sym_type_from_u8(STT_COMMON), SymbolType::Common);
        assert_eq!(sym_type_from_u8(STT_TLS), SymbolType::Tls);
        assert_eq!(sym_type_from_u8(0xFF), SymbolType::Unknown(0xFF));
    }

    #[test]
    fn test_sym_binding_from_u8() {
        assert_eq!(sym_binding_from_u8(STB_LOCAL), SymbolBinding::Local);
        assert_eq!(sym_binding_from_u8(STB_GLOBAL), SymbolBinding::Global);
        assert_eq!(sym_binding_from_u8(STB_WEAK), SymbolBinding::Weak);
        assert_eq!(sym_binding_from_u8(0xF), SymbolBinding::Unknown(0xF));
    }

    #[test]
    fn test_sym_visibility_from_u8() {
        assert_eq!(
            sym_visibility_from_u8(STV_DEFAULT),
            SymbolVisibility::Default
        );
        assert_eq!(
            sym_visibility_from_u8(STV_INTERNAL),
            SymbolVisibility::Internal
        );
        assert_eq!(sym_visibility_from_u8(STV_HIDDEN), SymbolVisibility::Hidden);
        assert_eq!(
            sym_visibility_from_u8(STV_PROTECTED),
            SymbolVisibility::Protected
        );
    }

    // -----------------------------------------------------------------------
    // Permissions helpers tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_permissions_from_elf_flags_rx() {
        let perms = permissions_from_elf_flags(PF_R | PF_X);
        assert!(perms.is_readable());
        assert!(perms.is_executable());
        assert!(!perms.is_writable());
    }

    #[test]
    fn test_permissions_from_elf_flags_rw() {
        let perms = permissions_from_elf_flags(PF_R | PF_W);
        assert!(perms.is_readable());
        assert!(perms.is_writable());
        assert!(!perms.is_executable());
    }

    #[test]
    fn test_permissions_from_elf_flags_rwx() {
        let perms = permissions_from_elf_flags(PF_R | PF_W | PF_X);
        assert!(perms.is_readable());
        assert!(perms.is_writable());
        assert!(perms.is_executable());
    }

    #[test]
    fn test_permissions_from_elf_flags_none_defaults_read() {
        let perms = permissions_from_elf_flags(0);
        assert!(perms.is_readable());
    }

    #[test]
    fn test_permissions_from_section_flags_alloc_exec() {
        // SHF_ALLOC (2) | SHF_EXECINSTR (4)
        let perms = permissions_from_section_flags(0x6);
        assert!(perms.is_readable());
        assert!(perms.is_executable());
        assert!(!perms.is_writable());
    }

    #[test]
    fn test_permissions_from_section_flags_write() {
        // SHF_ALLOC (2) | SHF_WRITE (1)
        let perms = permissions_from_section_flags(0x3);
        assert!(perms.is_readable());
        assert!(perms.is_writable());
    }

    // -----------------------------------------------------------------------
    // build_id note parsing
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_build_id_empty_returns_none() {
        assert!(parse_build_id(&[], true).is_none());
    }

    #[test]
    fn test_parse_build_id_valid_gnu_note() {
        // Craft a GNU build-id note: namesz=4 ("GNU\0"), descsz=20, type=3
        let mut note = vec![0u8; 12 + 4 + 20]; // header + name (4-aligned to 4) + desc
        // namesz = 4
        note[0..4].copy_from_slice(&4u32.to_le_bytes());
        // descsz = 20
        note[4..8].copy_from_slice(&20u32.to_le_bytes());
        // type = NT_GNU_BUILD_ID = 3
        note[8..12].copy_from_slice(&3u32.to_le_bytes());
        // name = "GNU\0"
        note[12..16].copy_from_slice(b"GNU\0");
        // desc (build-id bytes) = 20 bytes of 0xAB
        for byte in &mut note[16..36] {
            *byte = 0xAB;
        }
        let result = parse_build_id(&note, true);
        assert!(result.is_some());
        let id = result.unwrap();
        assert_eq!(id.len(), 20);
        assert!(id.iter().all(|&b| b == 0xAB));
    }

    #[test]
    fn test_parse_build_id_wrong_type_returns_none() {
        // NT_GNU_BUILD_ID = 3; use type 1 (NT_GNU_ABI_TAG)
        let mut note = vec![0u8; 12 + 4 + 4];
        note[0..4].copy_from_slice(&4u32.to_le_bytes());
        note[4..8].copy_from_slice(&4u32.to_le_bytes());
        note[8..12].copy_from_slice(&1u32.to_le_bytes()); // type 1, not 3
        note[12..16].copy_from_slice(b"GNU\0");
        assert!(parse_build_id(&note, true).is_none());
    }

    // -----------------------------------------------------------------------
    // Full async load tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_load_elf64_le_basic() {
        let loader = ElfLoader;
        let data = build_minimal_elf64_le();
        let input = LoaderInput::new("file://test.elf", data);
        let result = loader.load(input).await.expect("load should succeed");
        let view = result.view;
        assert_eq!(view.bits, 64);
        assert!(!view.entry_points.is_empty());
        assert_eq!(view.entry_points[0].0, 0x40_1000);
    }

    #[tokio::test]
    async fn test_load_elf32_be_mips() {
        let loader = ElfLoader;
        let data = build_minimal_elf32_be_mips();
        let input = LoaderInput::new("file://test.mips", data);
        let result = loader.load(input).await.expect("load should succeed");
        let view = result.view;
        assert_eq!(view.bits, 32);
        assert_eq!(view.endian, Endian::Big);
        assert!(!view.entry_points.is_empty());
        assert_eq!(view.entry_points[0].0, 0x0001_0000);
    }

    #[tokio::test]
    async fn test_load_sections_mapped_correctly() {
        let loader = ElfLoader;
        let data = build_minimal_elf64_le();
        let input = LoaderInput::new("file://test.elf", data.clone());
        let result = loader.load(input).await.expect("load should succeed");
        let view = result.view;
        let mem = view.mem.read();
        assert!(!mem.segments.is_empty());
        // The PT_LOAD segment is mapped at 0x401000
        let seg = mem
            .segments
            .iter()
            .find(|s| s.range.start.0 == 0x40_1000)
            .expect("segment at 0x401000 should exist");
        assert_eq!(seg.range.end.0, 0x40_1000 + 16);
        // Should be filled with NOPs (0x90)
        assert!(seg.data.iter().all(|&b| b == 0x90));
    }

    #[tokio::test]
    async fn test_load_segment_permissions_rx() {
        let loader = ElfLoader;
        let data = build_minimal_elf64_le();
        let input = LoaderInput::new("file://test.elf", data);
        let result = loader.load(input).await.expect("load should succeed");
        let view = result.view;
        let mem = view.mem.read();
        let seg = mem.segments.first().expect("should have a segment");
        assert!(seg.permissions.is_readable());
        assert!(seg.permissions.is_executable());
        assert!(!seg.permissions.is_writable());
    }

    #[tokio::test]
    async fn test_load_invalid_data_returns_error() {
        let loader = ElfLoader;
        let input = LoaderInput::new("file://bad", b"not an elf".to_vec());
        let result = loader.load(input).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_find_nested_is_empty() {
        let loader = ElfLoader;
        let data = build_minimal_elf64_le();
        let input = LoaderInput::new("file://test.elf", data);
        let nested = loader.find_nested(&input).await.expect("should succeed");
        assert!(nested.is_empty());
    }

    #[test]
    fn test_loader_name() {
        let loader = ElfLoader;
        assert_eq!(loader.name(), "elf");
    }

    #[tokio::test]
    async fn test_load_arch_stub_name_x86_64() {
        let loader = ElfLoader;
        let data = build_minimal_elf64_le();
        let input = LoaderInput::new("file://test.elf", data);
        let result = loader.load(input).await.expect("load should succeed");
        let view = result.view;
        assert_eq!(view.arch.name(), "x86_64");
        assert_eq!(view.arch.pointer_size(), 8);
        assert_eq!(view.arch.endian(), Endian::Little);
    }

    #[tokio::test]
    async fn test_load_arch_stub_name_mips() {
        let loader = ElfLoader;
        let data = build_minimal_elf32_be_mips();
        let input = LoaderInput::new("file://test.mips", data);
        let result = loader.load(input).await.expect("load should succeed");
        let view = result.view;
        assert_eq!(view.arch.name(), "mips");
        assert_eq!(view.arch.pointer_size(), 4);
        assert_eq!(view.arch.endian(), Endian::Big);
    }

    #[test]
    fn test_plt_entry_fields() {
        let entry = PltEntry {
            name: "malloc".to_string(),
            address: 0x0040_10a0,
            got_address: 0x0060_1018,
        };
        assert_eq!(entry.name, "malloc");
        assert_eq!(entry.address, 0x0040_10a0);
        assert_eq!(entry.got_address, 0x0060_1018);
    }

    #[test]
    fn test_elf_symbol_fields() {
        let sym = ElfSymbol {
            name: "main".to_string(),
            value: 0x0040_1100,
            size: 42,
            sym_type: SymbolType::Function,
            binding: SymbolBinding::Global,
            visibility: SymbolVisibility::Default,
            section_index: 1,
        };
        assert_eq!(sym.name, "main");
        assert_eq!(sym.sym_type, SymbolType::Function);
        assert_eq!(sym.binding, SymbolBinding::Global);
    }

    #[test]
    fn test_elf_section_fields() {
        let sec = ElfSection {
            name: ".text".to_string(),
            section_type: 1, // SHT_PROGBITS
            flags: 6,        // SHF_ALLOC | SHF_EXECINSTR
            addr: 0x0040_1000,
            offset: 0x1000,
            size: 0x500,
            permissions: Permissions::READ | Permissions::EXECUTE,
        };
        assert_eq!(sec.name, ".text");
        assert!(sec.permissions.is_executable());
    }
}
