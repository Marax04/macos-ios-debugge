//! ELF dynamic-linking analysis.
//!
//! Provides deep inspection of the `.dynamic` section, GOT/PLT tables,
//! relocation application, and dynamic symbol tables.  Useful for
//! understanding runtime linking, hooking points, and lazy-binding chains.

use std::collections::HashMap;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DynError {
    TruncatedData {
        offset: usize,
        needed: usize,
        available: usize,
    },
    InvalidTag(u64),
    MissingSection(String),
    BadAlignment {
        addr: u64,
        align: u64,
    },
    StringTableOutOfBounds {
        idx: u32,
    },
    RelocOutOfBounds {
        offset: u64,
    },
    UnsupportedClass(u8),
    InvalidPltType(u32),
    OverlappingRegions,
    InvalidGotEntry(u64),
}

impl std::fmt::Display for DynError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TruncatedData {
                offset,
                needed,
                available,
            } => write!(
                f,
                "truncated data at offset {offset:#x}: need {needed}, have {available}"
            ),
            Self::InvalidTag(t) => write!(f, "unknown dynamic tag {t:#x}"),
            Self::MissingSection(s) => write!(f, "missing section: {s}"),
            Self::BadAlignment { addr, align } => {
                write!(f, "address {addr:#x} not aligned to {align}")
            }
            Self::StringTableOutOfBounds { idx } => write!(f, "dynstr index {idx} out of bounds"),
            Self::RelocOutOfBounds { offset } => {
                write!(f, "relocation target {offset:#x} out of bounds")
            }
            Self::UnsupportedClass(c) => write!(f, "unsupported ELF class {c}"),
            Self::InvalidPltType(t) => write!(f, "invalid PLT relocation type {t}"),
            Self::OverlappingRegions => write!(f, "GOT/PLT regions overlap"),
            Self::InvalidGotEntry(v) => write!(f, "invalid GOT entry value {v:#x}"),
        }
    }
}

impl std::error::Error for DynError {}

// ---------------------------------------------------------------------------
// Dynamic tag constants (DT_*)
// ---------------------------------------------------------------------------

pub const DT_NULL: u64 = 0;
pub const DT_NEEDED: u64 = 1;
pub const DT_PLTRELSZ: u64 = 2;
pub const DT_PLTGOT: u64 = 3;
pub const DT_HASH: u64 = 4;
pub const DT_STRTAB: u64 = 5;
pub const DT_SYMTAB: u64 = 6;
pub const DT_RELA: u64 = 7;
pub const DT_RELASZ: u64 = 8;
pub const DT_RELAENT: u64 = 9;
pub const DT_STRSZ: u64 = 10;
pub const DT_SYMENT: u64 = 11;
pub const DT_INIT: u64 = 12;
pub const DT_FINI: u64 = 13;
pub const DT_SONAME: u64 = 14;
pub const DT_RPATH: u64 = 15;
pub const DT_SYMBOLIC: u64 = 16;
pub const DT_REL: u64 = 17;
pub const DT_RELSZ: u64 = 18;
pub const DT_RELENT: u64 = 19;
pub const DT_PLTREL: u64 = 20;
pub const DT_DEBUG: u64 = 21;
pub const DT_TEXTREL: u64 = 22;
pub const DT_JMPREL: u64 = 23;
pub const DT_BIND_NOW: u64 = 24;
pub const DT_INIT_ARRAY: u64 = 25;
pub const DT_FINI_ARRAY: u64 = 26;
pub const DT_INIT_ARRAYSZ: u64 = 27;
pub const DT_FINI_ARRAYSZ: u64 = 28;
pub const DT_RUNPATH: u64 = 29;
pub const DT_FLAGS: u64 = 30;
pub const DT_GNU_HASH: u64 = 0x6fff_fef5;
pub const DT_VERSYM: u64 = 0x6fff_fff0;
pub const DT_RELACOUNT: u64 = 0x6fff_fff9;
pub const DT_RELCOUNT: u64 = 0x6fff_fffa;
pub const DT_FLAGS_1: u64 = 0x6fff_fffb;
pub const DT_VERDEF: u64 = 0x6fff_fffc;
pub const DT_VERNEED: u64 = 0x6fff_fffe;

// DF_1 flags
pub const DF_1_NOW: u64 = 0x0000_0001;
pub const DF_1_GLOBAL: u64 = 0x0000_0002;
pub const DF_1_PIE: u64 = 0x0800_0000;
pub const DF_1_NODELETE: u64 = 0x0000_0008;
pub const DF_1_NOOPEN: u64 = 0x0000_0040;

// ---------------------------------------------------------------------------
// DynamicEntry
// ---------------------------------------------------------------------------

/// One entry in the `.dynamic` section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DynamicEntry {
    pub tag: u64,
    pub value: u64,
}

impl DynamicEntry {
    /// Human-readable name for well-known tags.
    #[must_use] 
    pub const fn tag_name(&self) -> &'static str {
        match self.tag {
            DT_NULL => "DT_NULL",
            DT_NEEDED => "DT_NEEDED",
            DT_PLTRELSZ => "DT_PLTRELSZ",
            DT_PLTGOT => "DT_PLTGOT",
            DT_HASH => "DT_HASH",
            DT_STRTAB => "DT_STRTAB",
            DT_SYMTAB => "DT_SYMTAB",
            DT_RELA => "DT_RELA",
            DT_RELASZ => "DT_RELASZ",
            DT_RELAENT => "DT_RELAENT",
            DT_STRSZ => "DT_STRSZ",
            DT_SYMENT => "DT_SYMENT",
            DT_INIT => "DT_INIT",
            DT_FINI => "DT_FINI",
            DT_SONAME => "DT_SONAME",
            DT_RPATH => "DT_RPATH",
            DT_SYMBOLIC => "DT_SYMBOLIC",
            DT_REL => "DT_REL",
            DT_RELSZ => "DT_RELSZ",
            DT_RELENT => "DT_RELENT",
            DT_PLTREL => "DT_PLTREL",
            DT_DEBUG => "DT_DEBUG",
            DT_TEXTREL => "DT_TEXTREL",
            DT_JMPREL => "DT_JMPREL",
            DT_BIND_NOW => "DT_BIND_NOW",
            DT_INIT_ARRAY => "DT_INIT_ARRAY",
            DT_FINI_ARRAY => "DT_FINI_ARRAY",
            DT_INIT_ARRAYSZ => "DT_INIT_ARRAYSZ",
            DT_FINI_ARRAYSZ => "DT_FINI_ARRAYSZ",
            DT_RUNPATH => "DT_RUNPATH",
            DT_FLAGS => "DT_FLAGS",
            DT_GNU_HASH => "DT_GNU_HASH",
            DT_VERSYM => "DT_VERSYM",
            DT_RELACOUNT => "DT_RELACOUNT",
            DT_RELCOUNT => "DT_RELCOUNT",
            DT_FLAGS_1 => "DT_FLAGS_1",
            DT_VERDEF => "DT_VERDEF",
            DT_VERNEED => "DT_VERNEED",
            _ => "DT_UNKNOWN",
        }
    }

    /// `true` when this entry terminates the dynamic array.
    #[must_use] 
    pub const fn is_null(&self) -> bool {
        self.tag == DT_NULL
    }
}

// ---------------------------------------------------------------------------
// DynamicSection
// ---------------------------------------------------------------------------

/// Parsed `.dynamic` section providing quick lookup by tag.
#[derive(Debug, Clone, Default)]
pub struct DynamicSection {
    entries: Vec<DynamicEntry>,
    tag_index: HashMap<u64, Vec<usize>>,
}

impl DynamicSection {
    /// Parse a `.dynamic` section from raw bytes (little-endian, 64-bit).
    ///
    /// # Errors
    /// Returns an error if the section data is malformed.
    pub fn parse_le64(data: &[u8]) -> Result<Self, DynError> {
        Self::parse_inner(data, true, true)
    }

    /// Parse a `.dynamic` section from raw bytes (big-endian, 64-bit).
    ///
    /// # Errors
    /// Returns an error if the section data is malformed.
    pub fn parse_be64(data: &[u8]) -> Result<Self, DynError> {
        Self::parse_inner(data, false, true)
    }

    /// Parse a `.dynamic` section from raw bytes (little-endian, 32-bit).
    ///
    /// # Errors
    /// Returns an error if the section data is malformed.
    pub fn parse_le32(data: &[u8]) -> Result<Self, DynError> {
        Self::parse_inner(data, true, false)
    }

    /// Parse a `.dynamic` section from raw bytes (big-endian, 32-bit).
    ///
    /// # Errors
    /// Returns an error if the section data is malformed.
    pub fn parse_be32(data: &[u8]) -> Result<Self, DynError> {
        Self::parse_inner(data, false, false)
    }

    fn parse_inner(data: &[u8], little_endian: bool, is_64bit: bool) -> Result<Self, DynError> {
        let entry_size = if is_64bit { 16usize } else { 8usize };
        if !data.len().is_multiple_of(entry_size) {
            return Err(DynError::TruncatedData {
                offset: 0,
                needed: entry_size,
                available: data.len() % entry_size,
            });
        }

        let capacity = data.len() / entry_size;
        let mut entries = Vec::with_capacity(capacity);
        let mut tag_index: HashMap<u64, Vec<usize>> = HashMap::with_capacity(capacity);
        let mut offset = 0;

        loop {
            if offset + entry_size > data.len() {
                break;
            }
            let (tag, value) = if is_64bit {
                let t = read_u64(&data[offset..], little_endian);
                let v = read_u64(&data[offset + 8..], little_endian);
                (t, v)
            } else {
                let t = u64::from(read_u32(&data[offset..], little_endian));
                let v = u64::from(read_u32(&data[offset + 4..], little_endian));
                (t, v)
            };

            let idx = entries.len();
            entries.push(DynamicEntry { tag, value });
            tag_index.entry(tag).or_default().push(idx);

            if tag == DT_NULL {
                break;
            }
            offset += entry_size;
        }

        Ok(Self { entries, tag_index })
    }

    /// All entries in order.
    #[must_use] 
    pub fn entries(&self) -> &[DynamicEntry] {
        &self.entries
    }

    /// First entry with the given tag, if any.
    #[must_use] 
    pub fn find(&self, tag: u64) -> Option<&DynamicEntry> {
        self.tag_index.get(&tag)?.first().map(|&i| &self.entries[i])
    }

    /// All entries with the given tag.
    #[must_use] 
    pub fn find_all(&self, tag: u64) -> Vec<&DynamicEntry> {
        self.tag_index.get(&tag).map_or_else(std::vec::Vec::new, |idxs| idxs.iter().map(|&i| &self.entries[i]).collect())
    }

    /// Collect all `DT_NEEDED` string-table offsets.
    #[must_use] 
    pub fn needed_offsets(&self) -> Vec<u64> {
        self.find_all(DT_NEEDED)
            .into_iter()
            .map(|e| e.value)
            .collect()
    }

    /// `true` if `DT_BIND_NOW` or `DF_1_NOW` is present.
    #[must_use] 
    pub fn is_full_relro(&self) -> bool {
        if self.find(DT_BIND_NOW).is_some() {
            return true;
        }
        if let Some(f) = self.find(DT_FLAGS_1) {
            return f.value & DF_1_NOW != 0;
        }
        false
    }

    /// `true` if this is a PIE (position-independent executable).
    #[must_use] 
    pub fn is_pie(&self) -> bool {
        if let Some(f) = self.find(DT_FLAGS_1) {
            return f.value & DF_1_PIE != 0;
        }
        false
    }

    /// Number of non-null entries.
    #[must_use] 
    pub fn len(&self) -> usize {
        self.entries
            .iter()
            .take_while(|e| e.tag != DT_NULL)
            .count()
    }

    #[must_use] 
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

// ---------------------------------------------------------------------------
// GotPltAnalysis
// ---------------------------------------------------------------------------

/// Flags describing the state of a GOT/PLT slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GotSlotState {
    /// Slot contains the PLT stub address (not yet resolved by ld.so).
    Unresolved,
    /// Slot has been patched by the dynamic linker with the real address.
    Resolved(u64),
    /// Slot contains zero (null function pointer).
    Null,
    /// Slot contains a suspicious value (potential hook/trojan).
    Hooked(u64),
}

/// One entry in the Global Offset Table that corresponds to a PLT stub.
#[derive(Debug, Clone)]
pub struct GotEntry {
    /// Virtual address of this GOT slot.
    pub got_addr: u64,
    /// Current value stored in the slot (from raw binary data).
    pub raw_value: u64,
    /// Resolved symbol name (if available).
    pub symbol_name: Option<String>,
    /// Dynamic symbol index.
    pub sym_index: u32,
    /// Analysis result.
    pub state: GotSlotState,
}

/// Full GOT/PLT analysis result.
#[derive(Debug, Clone, Default)]
pub struct GotPltAnalysis {
    /// Virtual address of the start of the GOT.
    pub got_base: u64,
    /// Virtual address of the GOT[0] (dynamic linker data).
    pub got_dt_debug: u64,
    /// Virtual address of GOT[1] (`link_map` pointer).
    pub got_link_map: u64,
    /// Virtual address of GOT[2] (PLT resolver).
    pub got_resolver: u64,
    /// PLT-related GOT slots (GOT[3..]).
    pub plt_got_entries: Vec<GotEntry>,
    /// Suspicious entries that may indicate hooks.
    pub hooked_entries: Vec<GotEntry>,
}

impl GotPltAnalysis {
    /// Analyse GOT data given raw bytes, base virtual address, and PLT/GOT
    /// symbol information.
    ///
    /// # Errors
    /// Returns an error if the GOT data is malformed.
    pub fn analyze(
        got_data: &[u8],
        got_vaddr: u64,
        is_64bit: bool,
        little_endian: bool,
        plt_base: u64,
        plt_entry_size: u64,
        symbols: &[(u32, String)],
    ) -> Result<Self, DynError> {
        let ptr_size = if is_64bit { 8usize } else { 4usize };
        if got_data.len() < ptr_size * 3 {
            return Err(DynError::TruncatedData {
                offset: 0,
                needed: ptr_size * 3,
                available: got_data.len(),
            });
        }

        let read_ptr = |data: &[u8], offset: usize| -> u64 {
            if is_64bit {
                read_u64(&data[offset..], little_endian)
            } else {
                u64::from(read_u32(&data[offset..], little_endian))
            }
        };

        let dt_debug = read_ptr(got_data, 0);
        let link_map = read_ptr(got_data, ptr_size);
        let resolver = read_ptr(got_data, ptr_size * 2);

        let slot_count = got_data.len() / ptr_size;
        let plt_slots = slot_count.saturating_sub(3);
        let mut plt_got_entries = Vec::with_capacity(plt_slots);
        let mut hooked_entries = Vec::new();

        let sym_map: HashMap<u32, &str> = symbols.iter().map(|(i, n)| (*i, n.as_str())).collect();

        let mut slot_offset = ptr_size * 3;
        let mut sym_idx = 0u32;
        while slot_offset + ptr_size <= got_data.len() {
            let raw = read_ptr(got_data, slot_offset);
            let slot_addr = got_vaddr + slot_offset as u64;
            let name = sym_map.get(&sym_idx).map(std::string::ToString::to_string);

            // Classify the slot value
            let state = if raw == 0 {
                GotSlotState::Null
            } else {
                // Check if it points back into the PLT (unresolved lazy binding).
                // The PLT window is sized from the per-entry stride and the
                // number of slots we expect to walk so we don't hard-code 4 KiB
                // for binaries with very large or very small PLTs.
                let plt_slots = (got_data.len() / ptr_size).saturating_sub(3) as u64;
                let plt_window = plt_entry_size
                    .saturating_mul(plt_slots.saturating_add(1))
                    .max(plt_entry_size)
                    .max(4096);
                let in_plt = raw >= plt_base && raw < plt_base.saturating_add(plt_window);
                if in_plt {
                    GotSlotState::Unresolved
                } else {
                    GotSlotState::Resolved(raw)
                }
            };

            // Flag values that differ from expected range as potential hooks
            let hooked = matches!(state, GotSlotState::Resolved(v)
                if v < 0x1000 || (v > 0xffff_ffff_ffff_f000 && is_64bit));
            let effective_state = if hooked {
                GotSlotState::Hooked(raw)
            } else {
                state
            };

            let entry = GotEntry {
                got_addr: slot_addr,
                raw_value: raw,
                symbol_name: name,
                sym_index: sym_idx,
                state: effective_state,
            };

            if matches!(effective_state, GotSlotState::Hooked(_)) {
                hooked_entries.push(entry.clone());
            }
            plt_got_entries.push(entry);

            slot_offset += ptr_size;
            sym_idx += 1;
        }

        Ok(Self {
            got_base: got_vaddr,
            got_dt_debug: dt_debug,
            got_link_map: link_map,
            got_resolver: resolver,
            plt_got_entries,
            hooked_entries,
        })
    }

    /// `true` when any GOT slot appears to be hooked.
    #[must_use] 
    pub const fn has_hooks(&self) -> bool {
        !self.hooked_entries.is_empty()
    }
}

// ---------------------------------------------------------------------------
// PltEntry
// ---------------------------------------------------------------------------

/// One PLT stub together with its GOT slot and resolved symbol name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PltEntry {
    /// Virtual address of the PLT stub.
    pub plt_addr: u64,
    /// Virtual address of the corresponding GOT entry.
    pub got_addr: u64,
    /// Index into the dynamic symbol table.
    pub sym_index: u32,
    /// Symbol name (empty if symbol table is stripped).
    pub name: String,
    /// Relocation addend (0 for REL-style).
    pub addend: i64,
}

impl PltEntry {
    pub fn new(
        plt_addr: u64,
        got_addr: u64,
        sym_index: u32,
        name: impl Into<String>,
        addend: i64,
    ) -> Self {
        Self {
            plt_addr,
            got_addr,
            sym_index,
            name: name.into(),
            addend,
        }
    }

    /// `true` when this stub has a non-empty name.
    #[must_use] 
    pub const fn is_named(&self) -> bool {
        !self.name.is_empty()
    }
}

// ---------------------------------------------------------------------------
// DynlibDeps
// ---------------------------------------------------------------------------

/// Dependency graph extracted from `DT_NEEDED` entries.
#[derive(Debug, Clone, Default)]
pub struct DynlibDeps {
    pub libraries: Vec<String>,
    pub soname: Option<String>,
    pub rpath: Option<String>,
    pub runpath: Option<String>,
}

impl DynlibDeps {
    #[must_use] 
    pub fn from_dynamic(dynamic: &DynamicSection, dynstr: &[u8]) -> Self {
        let read_str = |off: u64| -> String {
            let off = usize::try_from(off).unwrap_or(usize::MAX);
            if off >= dynstr.len() {
                return String::new();
            }
            let end = dynstr[off..]
                .iter()
                .position(|&b| b == 0)
                .unwrap_or(dynstr.len() - off);
            String::from_utf8_lossy(&dynstr[off..off + end]).into_owned()
        };

        let libraries = dynamic
            .needed_offsets()
            .into_iter()
            .map(&read_str)
            .collect();

        let soname = dynamic.find(DT_SONAME).map(|e| read_str(e.value));
        let rpath = dynamic.find(DT_RPATH).map(|e| read_str(e.value));
        let runpath = dynamic.find(DT_RUNPATH).map(|e| read_str(e.value));

        Self {
            libraries,
            soname,
            rpath,
            runpath,
        }
    }

    /// `true` when any listed library matches `name` (case-insensitive).
    #[must_use] 
    pub fn depends_on(&self, name: &str) -> bool {
        let lower = name.to_lowercase();
        self.libraries
            .iter()
            .any(|lib| lib.to_lowercase().contains(&lower))
    }

    /// Effective search path: RPATH if present, otherwise RUNPATH.
    #[must_use] 
    pub fn search_path(&self) -> Option<&str> {
        self.rpath.as_deref().or(self.runpath.as_deref())
    }
}

// ---------------------------------------------------------------------------
// DynamicSymbolTable
// ---------------------------------------------------------------------------

/// Binding type of a dynamic symbol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DynSymBinding {
    Local,
    Global,
    Weak,
    Unknown(u8),
}

/// Type of a dynamic symbol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DynSymType {
    NoType,
    Object,
    Func,
    Section,
    File,
    Common,
    Tls,
    IfuncGnu,
    Unknown(u8),
}

/// Visibility of a dynamic symbol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DynSymVisibility {
    Default,
    Internal,
    Hidden,
    Protected,
}

/// One entry in the `.dynsym` table.
#[derive(Debug, Clone)]
pub struct DynSymEntry {
    pub index: u32,
    pub name: String,
    pub value: u64,
    pub size: u64,
    pub binding: DynSymBinding,
    pub sym_type: DynSymType,
    pub visibility: DynSymVisibility,
    pub section_index: u16,
}

impl DynSymEntry {
    /// `true` when this symbol is exported (global or weak, with non-zero value).
    #[must_use] 
    pub const fn is_exported(&self) -> bool {
        matches!(self.binding, DynSymBinding::Global | DynSymBinding::Weak) && self.value != 0
    }

    /// `true` when this is a function symbol.
    #[must_use] 
    pub const fn is_function(&self) -> bool {
        matches!(self.sym_type, DynSymType::Func | DynSymType::IfuncGnu)
    }
}

/// Parsed `.dynsym` + `.dynstr` table.
#[derive(Debug, Clone, Default)]
pub struct DynamicSymbolTable {
    pub symbols: Vec<DynSymEntry>,
    name_index: HashMap<String, Vec<u32>>,
}

impl DynamicSymbolTable {
    /// Parse from raw `.dynsym` bytes + corresponding `.dynstr` bytes.
    /// `is_64bit` selects between 24-byte (64-bit) and 16-byte (32-bit) entries.
    ///
    /// # Errors
    /// Returns an error if the symbol table data is malformed.
    pub fn parse(
        dynsym: &[u8],
        dynstr: &[u8],
        little_endian: bool,
        is_64bit: bool,
    ) -> Result<Self, DynError> {
        let entry_size = if is_64bit { 24usize } else { 16usize };
        if !dynsym.len().is_multiple_of(entry_size) {
            return Err(DynError::TruncatedData {
                offset: 0,
                needed: entry_size,
                available: dynsym.len() % entry_size,
            });
        }

        let mut symbols = Vec::new();
        let mut name_index: HashMap<String, Vec<u32>> = HashMap::new();

        for (i, chunk) in dynsym.chunks(entry_size).enumerate() {
            let name_off = read_u32(chunk, little_endian);
            let (value, size, info, other, shndx) = if is_64bit {
                let info = chunk[4];
                let other = chunk[5];
                let shndx = read_u16(&chunk[6..], little_endian);
                let value = read_u64(&chunk[8..], little_endian);
                let size = read_u64(&chunk[16..], little_endian);
                (value, size, info, other, shndx)
            } else {
                let value = u64::from(read_u32(&chunk[4..], little_endian));
                let size = u64::from(read_u32(&chunk[8..], little_endian));
                let info = chunk[12];
                let other = chunk[13];
                let shndx = read_u16(&chunk[14..], little_endian);
                (value, size, info, other, shndx)
            };

            let name = read_dynstr(dynstr, name_off)?;
            let binding = match info >> 4 {
                0 => DynSymBinding::Local,
                1 => DynSymBinding::Global,
                2 => DynSymBinding::Weak,
                b => DynSymBinding::Unknown(b),
            };
            let sym_type = match info & 0xf {
                0 => DynSymType::NoType,
                1 => DynSymType::Object,
                2 => DynSymType::Func,
                3 => DynSymType::Section,
                4 => DynSymType::File,
                5 => DynSymType::Common,
                6 => DynSymType::Tls,
                10 => DynSymType::IfuncGnu,
                t => DynSymType::Unknown(t),
            };
            let visibility = match other & 0x3 {
                1 => DynSymVisibility::Internal,
                2 => DynSymVisibility::Hidden,
                3 => DynSymVisibility::Protected,
                _ => DynSymVisibility::Default,
            };

            let idx = u32::try_from(i).unwrap_or(u32::MAX);
            name_index.entry(name.clone()).or_default().push(idx);
            symbols.push(DynSymEntry {
                index: idx,
                name,
                value,
                size,
                binding,
                sym_type,
                visibility,
                section_index: shndx,
            });
        }

        Ok(Self {
            symbols,
            name_index,
        })
    }

    /// Look up all symbols by exact name.
    #[must_use] 
    pub fn find_by_name(&self, name: &str) -> Vec<&DynSymEntry> {
        self.name_index.get(name).map_or_else(std::vec::Vec::new, |idxs| idxs.iter().map(|&i| &self.symbols[i as usize]).collect())
    }

    /// All exported function symbols.
    #[must_use] 
    pub fn exported_functions(&self) -> Vec<&DynSymEntry> {
        self.symbols
            .iter()
            .filter(|s| s.is_exported() && s.is_function())
            .collect()
    }

    /// Number of symbols.
    #[must_use] 
    pub const fn len(&self) -> usize {
        self.symbols.len()
    }
    #[must_use] 
    pub const fn is_empty(&self) -> bool {
        self.symbols.is_empty()
    }
}

// ---------------------------------------------------------------------------
// RelocationApplier
// ---------------------------------------------------------------------------

/// One relocation record (unified REL + RELA representation).
#[derive(Debug, Clone)]
pub struct RelocRecord {
    /// Offset in the binary (virtual address of the location to patch).
    pub offset: u64,
    /// Relocation type (architecture-specific).
    pub reloc_type: u32,
    /// Symbol index.
    pub sym_index: u32,
    /// Addend (0 for REL-style).
    pub addend: i64,
}

impl RelocRecord {
    #[must_use]
    pub fn new_rela(offset: u64, info: u64, addend: i64, is_64bit: bool) -> Self {
        let (sym_index, reloc_type) = if is_64bit {
            (u32::try_from(info >> 32).unwrap_or(u32::MAX), u32::try_from(info & 0xffff_ffff).unwrap_or(u32::MAX))
        } else {
            (u32::try_from(info >> 8).unwrap_or(u32::MAX), u32::try_from(info & 0xff).unwrap_or(u32::MAX))
        };
        Self {
            offset,
            reloc_type,
            sym_index,
            addend,
        }
    }

    #[must_use]
    pub fn new_rel(offset: u64, info: u64, is_64bit: bool) -> Self {
        Self::new_rela(offset, info, 0, is_64bit)
    }
}

/// Applies relocations to a mutable binary image buffer.
#[derive(Debug, Default)]
pub struct RelocationApplier {
    pub applied: Vec<RelocRecord>,
    pub skipped: Vec<RelocRecord>,
}

impl RelocationApplier {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    /// Parse RELA section and record all records.
    ///
    /// # Errors
    /// Returns an error if the RELA data is malformed.
    pub fn parse_rela(
        data: &[u8],
        little_endian: bool,
        is_64bit: bool,
    ) -> Result<Vec<RelocRecord>, DynError> {
        let entry_size = if is_64bit { 24usize } else { 12usize };
        if !data.len().is_multiple_of(entry_size) {
            return Err(DynError::TruncatedData {
                offset: 0,
                needed: entry_size,
                available: data.len() % entry_size,
            });
        }
        let mut records = Vec::new();
        for chunk in data.chunks(entry_size) {
            let (offset, info, addend) = if is_64bit {
                let o = read_u64(chunk, little_endian);
                let i = read_u64(&chunk[8..], little_endian);
                let a = read_i64(&chunk[16..], little_endian);
                (o, i, a)
            } else {
                let o = u64::from(read_u32(chunk, little_endian));
                let i = u64::from(read_u32(&chunk[4..], little_endian));
                let a = i64::from(read_i32(&chunk[8..], little_endian));
                (o, i, a)
            };
            records.push(RelocRecord::new_rela(offset, info, addend, is_64bit));
        }
        Ok(records)
    }

    /// Parse REL section and record all records.
    ///
    /// # Errors
    /// Returns an error if the REL data is malformed.
    pub fn parse_rel(
        data: &[u8],
        little_endian: bool,
        is_64bit: bool,
    ) -> Result<Vec<RelocRecord>, DynError> {
        let entry_size = if is_64bit { 16usize } else { 8usize };
        if !data.len().is_multiple_of(entry_size) {
            return Err(DynError::TruncatedData {
                offset: 0,
                needed: entry_size,
                available: data.len() % entry_size,
            });
        }
        let mut records = Vec::new();
        for chunk in data.chunks(entry_size) {
            let (offset, info) = if is_64bit {
                (
                    read_u64(chunk, little_endian),
                    read_u64(&chunk[8..], little_endian),
                )
            } else {
                (
                    u64::from(read_u32(chunk, little_endian)),
                    u64::from(read_u32(&chunk[4..], little_endian)),
                )
            };
            records.push(RelocRecord::new_rel(offset, info, is_64bit));
        }
        Ok(records)
    }

    /// Apply a single relative relocation (`R_X86_64_RELATIVE` / `R_AARCH64_RELATIVE`).
    ///
    /// # Errors
    /// Returns an error if the relocation offset is out of bounds.
    pub fn apply_relative(
        &mut self,
        image: &mut [u8],
        record: &RelocRecord,
        image_base: u64,
        load_bias: u64,
        is_64bit: bool,
        little_endian: bool,
    ) -> Result<(), DynError> {
        let target_va = (image_base.cast_signed() + record.addend).cast_unsigned().wrapping_add(load_bias);
        let offset = usize::try_from(record.offset).unwrap_or(usize::MAX);
        if is_64bit {
            if offset.checked_add(8).is_none_or(|end| end > image.len()) {
                return Err(DynError::RelocOutOfBounds {
                    offset: record.offset,
                });
            }
            write_u64(&mut image[offset..], target_va, little_endian);
        } else {
            if offset.checked_add(4).is_none_or(|end| end > image.len()) {
                return Err(DynError::RelocOutOfBounds {
                    offset: record.offset,
                });
            }
            write_u32(&mut image[offset..], u32::try_from(target_va & 0xFFFF_FFFF).unwrap_or(u32::MAX), little_endian);
        }
        self.applied.push(record.clone());
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// DynSymbolHashTable â€” SYSV and GNU hash table look-up
// ---------------------------------------------------------------------------

/// ELF SYSV hash table.
pub struct SysvHashTable<'a> {
    data: &'a [u8],
    little_endian: bool,
}

impl<'a> SysvHashTable<'a> {
    #[must_use] 
    pub const fn new(data: &'a [u8], little_endian: bool) -> Option<Self> {
        if data.len() < 8 {
            return None;
        }
        Some(Self {
            data,
            little_endian,
        })
    }

    fn nbucket(&self) -> u32 {
        read_u32(self.data, self.little_endian)
    }
    fn nchain(&self) -> u32 {
        read_u32(&self.data[4..], self.little_endian)
    }

    /// Compute the SYSV hash of `name`.
    #[must_use] 
    pub fn hash(name: &[u8]) -> u32 {
        let mut h: u32 = 0;
        for &c in name {
            h = (h << 4).wrapping_add(u32::from(c));
            let g = h & 0xf000_0000;
            if g != 0 {
                h ^= g >> 24;
            }
            h &= !g;
        }
        h
    }

    /// Look up a symbol index by name, returning `None` if not found.
    #[must_use] 
    pub fn lookup(&self, name: &[u8]) -> Option<u32> {
        let nbucket = self.nbucket() as usize;
        let nchain = self.nchain() as usize;
        if nbucket == 0 {
            return None; // avoid division by zero on a malformed table
        }
        let bucket_off = 8usize;
        let chain_off = bucket_off.checked_add(nbucket.checked_mul(4)?)?;
        if self.data.len() < chain_off.checked_add(nchain.checked_mul(4)?)? {
            return None;
        }

        let h = Self::hash(name) as usize;
        let mut idx = read_u32(
            &self.data[bucket_off + (h % nbucket) * 4..],
            self.little_endian,
        ) as usize;
        // Bound iterations by nchain so a cyclic chain (A -> B -> A) cannot spin forever.
        let mut steps = 0usize;
        while idx != 0 && steps <= nchain {
            if chain_off + idx * 4 + 4 > self.data.len() {
                break;
            }
            let next = read_u32(&self.data[chain_off + idx * 4..], self.little_endian) as usize;
            if next == idx {
                break;
            } // guard against cycles
            idx = next;
            steps += 1;
        }
        None // Full name comparison requires the dynsym table; this is the chain walk skeleton.
    }

    #[must_use] 
    pub fn nbucket_count(&self) -> u32 {
        self.nbucket()
    }
    #[must_use] 
    pub fn nchain_count(&self) -> u32 {
        self.nchain()
    }
}

// ---------------------------------------------------------------------------
// DynRelocStats â€” statistics over a relocation table
// ---------------------------------------------------------------------------

/// Statistics collected from parsing relocations.
#[derive(Debug, Clone, Default)]
pub struct DynRelocStats {
    pub total: usize,
    pub relative: usize,
    pub glob_dat: usize,
    pub jump_slot: usize,
    pub copy: usize,
    pub tls_dtpmod: usize,
    pub tls_tpoff: usize,
    pub other: usize,
}

impl DynRelocStats {
    /// Analyse a set of `RelocRecord`s against known `x86_64` relocation types.
    #[must_use] 
    pub fn from_records_x86_64(records: &[RelocRecord]) -> Self {
        let mut s = Self::default();
        for r in records {
            s.total += 1;
            match r.reloc_type {
                8 => s.relative += 1,  // R_X86_64_RELATIVE
                6 => s.glob_dat += 1,  // R_X86_64_GLOB_DAT
                7 => s.jump_slot += 1, // R_X86_64_JUMP_SLOT
                5 => s.copy += 1,      // R_X86_64_COPY
                19 => s.tls_dtpmod += 1,
                20 => s.tls_tpoff += 1,
                _ => s.other += 1,
            }
        }
        s
    }

    /// Percentage of relative relocations (0-100).
    #[must_use] 
    pub fn relative_pct(&self) -> f64 {
        if self.total == 0 {
            return 0.0;
        }
        f64::from(u32::try_from(self.relative).unwrap_or(u32::MAX))
            / f64::from(u32::try_from(self.total).unwrap_or(u32::MAX))
            * 100.0
    }

    /// `true` if the binary appears to be a PIE (high relative reloc ratio).
    #[must_use] 
    pub fn likely_pie(&self) -> bool {
        self.total >= 4 && self.relative_pct() >= 60.0
    }
}

// ---------------------------------------------------------------------------
// ElfLinkMap â€” simulated link_map for ASLR analysis
// ---------------------------------------------------------------------------

/// A minimal representation of an ELF `link_map` entry.
#[derive(Debug, Clone)]
pub struct LinkMapEntry {
    /// Preferred load address (from `PT_LOAD` / image base).
    pub preferred_base: u64,
    /// Actual runtime load address (known after ASLR).
    pub actual_base: u64,
    /// SONAME or file path.
    pub name: String,
    /// Load bias = `actual_base` - `preferred_base`.
    pub load_bias: i64,
}

impl LinkMapEntry {
    pub fn new(name: impl Into<String>, preferred: u64, actual: u64) -> Self {
        let load_bias = actual.cast_signed() - preferred.cast_signed();
        Self {
            preferred_base: preferred,
            actual_base: actual,
            name: name.into(),
            load_bias,
        }
    }

    #[must_use] 
    pub const fn resolve_va(&self, rva: u64) -> u64 {
        (rva.cast_signed() + self.load_bias).cast_unsigned()
    }

    #[must_use] 
    pub const fn is_aslr_randomised(&self) -> bool {
        self.actual_base != self.preferred_base
    }
}

/// A simulated link-map of loaded ELF images.
#[derive(Debug, Default)]
pub struct ElfLinkMap {
    pub entries: Vec<LinkMapEntry>,
}

impl ElfLinkMap {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(&mut self, entry: LinkMapEntry) {
        self.entries.push(entry);
    }

    #[must_use] 
    pub fn find(&self, name: &str) -> Option<&LinkMapEntry> {
        self.entries.iter().find(|e| e.name.contains(name))
    }

    /// All entries that have been ASLR-randomised.
    #[must_use] 
    pub fn randomised_entries(&self) -> Vec<&LinkMapEntry> {
        self.entries
            .iter()
            .filter(|e| e.is_aslr_randomised())
            .collect()
    }
}

// ---------------------------------------------------------------------------
// DynStringTable â€” helper for the `.dynstr` section
// ---------------------------------------------------------------------------

/// Wrapper around the raw `.dynstr` bytes.
pub struct DynStringTable<'a> {
    data: &'a [u8],
}

impl<'a> DynStringTable<'a> {
    #[must_use] 
    pub const fn new(data: &'a [u8]) -> Self {
        Self { data }
    }

    /// Get a null-terminated string at `offset`.
    #[must_use] 
    pub fn get(&self, offset: u32) -> Option<&'a str> {
        let start = offset as usize;
        if start >= self.data.len() {
            return None;
        }
        let end = self.data[start..]
            .iter()
            .position(|&b| b == 0)
            .map_or(self.data.len(), |p| start + p);
        std::str::from_utf8(&self.data[start..end]).ok()
    }

    #[must_use] 
    pub const fn size(&self) -> usize {
        self.data.len()
    }
}

// ---------------------------------------------------------------------------
// ElfDynamicAnalysis â€” top-level aggregator
// ---------------------------------------------------------------------------

/// Complete dynamic analysis of an ELF binary.
#[derive(Debug)]
pub struct ElfDynamicAnalysis {
    pub dynamic_section: DynamicSection,
    pub deps: DynlibDeps,
    pub symbol_table: DynamicSymbolTable,
    pub got_plt: GotPltAnalysis,
    pub plt_entries: Vec<PltEntry>,
    pub reloc_records: Vec<RelocRecord>,
    pub is_64bit: bool,
    pub little_endian: bool,
}

impl ElfDynamicAnalysis {
    /// Build analysis from pre-parsed component data.
    ///
    /// `format` encodes both the ELF class and endianness as `(is_64bit, little_endian)`.
    #[must_use]
    pub const fn new(
        dynamic_section: DynamicSection,
        deps: DynlibDeps,
        symbol_table: DynamicSymbolTable,
        got_plt: GotPltAnalysis,
        plt_entries: Vec<PltEntry>,
        reloc_records: Vec<RelocRecord>,
        format: (bool, bool),
    ) -> Self {
        let (is_64bit, little_endian) = format;
        Self {
            dynamic_section,
            deps,
            symbol_table,
            got_plt,
            plt_entries,
            reloc_records,
            is_64bit,
            little_endian,
        }
    }

    /// `true` when any GOT slot appears to have been hooked.
    #[must_use] 
    pub const fn has_hooks(&self) -> bool {
        self.got_plt.has_hooks()
    }

    /// All exported function symbols.
    #[must_use] 
    pub fn exported_functions(&self) -> Vec<&DynSymEntry> {
        self.symbol_table.exported_functions()
    }

    /// Look up a PLT stub by symbol name.
    #[must_use] 
    pub fn find_plt(&self, name: &str) -> Option<&PltEntry> {
        self.plt_entries.iter().find(|e| e.name == name)
    }

    /// Number of dynamic relocations.
    #[must_use] 
    pub const fn reloc_count(&self) -> usize {
        self.reloc_records.len()
    }

    /// All required shared libraries.
    #[must_use] 
    pub fn required_libs(&self) -> &[String] {
        &self.deps.libraries
    }
}

// ---------------------------------------------------------------------------
// Low-level byte helpers
// ---------------------------------------------------------------------------

fn read_u16(data: &[u8], little_endian: bool) -> u16 {
    if data.len() < 2 {
        return 0;
    }
    if little_endian {
        u16::from_le_bytes([data[0], data[1]])
    } else {
        u16::from_be_bytes([data[0], data[1]])
    }
}

fn read_u32(data: &[u8], little_endian: bool) -> u32 {
    if data.len() < 4 {
        return 0;
    }
    if little_endian {
        u32::from_le_bytes([data[0], data[1], data[2], data[3]])
    } else {
        u32::from_be_bytes([data[0], data[1], data[2], data[3]])
    }
}

fn read_u64(data: &[u8], little_endian: bool) -> u64 {
    if data.len() < 8 {
        return 0;
    }
    let b: [u8; 8] = data[..8].try_into().unwrap();
    if little_endian {
        u64::from_le_bytes(b)
    } else {
        u64::from_be_bytes(b)
    }
}

fn read_i32(data: &[u8], little_endian: bool) -> i32 {
    read_u32(data, little_endian).cast_signed()
}

fn read_i64(data: &[u8], little_endian: bool) -> i64 {
    read_u64(data, little_endian).cast_signed()
}

fn write_u32(data: &mut [u8], v: u32, little_endian: bool) {
    let b = if little_endian {
        v.to_le_bytes()
    } else {
        v.to_be_bytes()
    };
    data[..4].copy_from_slice(&b);
}

fn write_u64(data: &mut [u8], v: u64, little_endian: bool) {
    let b = if little_endian {
        v.to_le_bytes()
    } else {
        v.to_be_bytes()
    };
    data[..8].copy_from_slice(&b);
}

fn read_dynstr(dynstr: &[u8], off: u32) -> Result<String, DynError> {
    let off = off as usize;
    if off >= dynstr.len() {
        return Err(DynError::StringTableOutOfBounds { idx: u32::try_from(off).unwrap_or(u32::MAX) });
    }
    let end = dynstr[off..]
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(dynstr.len() - off);
    Ok(String::from_utf8_lossy(&dynstr[off..off + end]).into_owned())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ---- helpers ----

    fn make_dyn_le64(entries: &[(u64, u64)]) -> Vec<u8> {
        let mut buf = Vec::new();
        for &(tag, val) in entries {
            buf.extend_from_slice(&tag.to_le_bytes());
            buf.extend_from_slice(&val.to_le_bytes());
        }
        buf
    }

    fn make_dynstr(strings: &[&str]) -> Vec<u8> {
        let mut buf = vec![0u8]; // index 0 = empty
        for s in strings {
            buf.extend_from_slice(s.as_bytes());
            buf.push(0);
        }
        buf
    }

    fn make_dynsym_entry_64(
        name_off: u32,
        value: u64,
        size: u64,
        info: u8,
        other: u8,
        shndx: u16,
    ) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&name_off.to_le_bytes());
        buf.push(info);
        buf.push(other);
        buf.extend_from_slice(&shndx.to_le_bytes());
        buf.extend_from_slice(&value.to_le_bytes());
        buf.extend_from_slice(&size.to_le_bytes());
        buf
    }

    // ---- DynamicSection tests ----

    #[test]
    fn test_dynamic_section_parse_empty_null() {
        let data = make_dyn_le64(&[(DT_NULL, 0)]);
        let ds = DynamicSection::parse_le64(&data).unwrap();
        assert_eq!(ds.len(), 0);
    }

    #[test]
    fn test_dynamic_section_parse_needed() {
        let data = make_dyn_le64(&[(DT_NEEDED, 1), (DT_NEEDED, 8), (DT_NULL, 0)]);
        let ds = DynamicSection::parse_le64(&data).unwrap();
        assert_eq!(ds.needed_offsets(), vec![1, 8]);
    }

    #[test]
    fn test_dynamic_section_find() {
        let data = make_dyn_le64(&[(DT_STRTAB, 0x1000), (DT_STRSZ, 0x200), (DT_NULL, 0)]);
        let ds = DynamicSection::parse_le64(&data).unwrap();
        assert_eq!(ds.find(DT_STRTAB).unwrap().value, 0x1000);
        assert!(ds.find(DT_SYMTAB).is_none());
    }

    #[test]
    fn test_dynamic_section_len() {
        let data = make_dyn_le64(&[
            (DT_NEEDED, 1),
            (DT_INIT, 0x400),
            (DT_FINI, 0x500),
            (DT_NULL, 0),
        ]);
        let ds = DynamicSection::parse_le64(&data).unwrap();
        assert_eq!(ds.len(), 3);
    }

    #[test]
    fn test_dynamic_section_is_empty_true() {
        let data = make_dyn_le64(&[(DT_NULL, 0)]);
        let ds = DynamicSection::parse_le64(&data).unwrap();
        assert!(ds.is_empty());
    }

    #[test]
    fn test_dynamic_section_is_empty_false() {
        let data = make_dyn_le64(&[(DT_NEEDED, 1), (DT_NULL, 0)]);
        let ds = DynamicSection::parse_le64(&data).unwrap();
        assert!(!ds.is_empty());
    }

    #[test]
    fn test_dynamic_section_full_relro_bind_now() {
        let data = make_dyn_le64(&[(DT_BIND_NOW, 1), (DT_NULL, 0)]);
        let ds = DynamicSection::parse_le64(&data).unwrap();
        assert!(ds.is_full_relro());
    }

    #[test]
    fn test_dynamic_section_full_relro_flags1() {
        let data = make_dyn_le64(&[(DT_FLAGS_1, DF_1_NOW), (DT_NULL, 0)]);
        let ds = DynamicSection::parse_le64(&data).unwrap();
        assert!(ds.is_full_relro());
    }

    #[test]
    fn test_dynamic_section_not_full_relro() {
        let data = make_dyn_le64(&[(DT_FLAGS_1, DF_1_GLOBAL), (DT_NULL, 0)]);
        let ds = DynamicSection::parse_le64(&data).unwrap();
        assert!(!ds.is_full_relro());
    }

    #[test]
    fn test_dynamic_section_is_pie() {
        let data = make_dyn_le64(&[(DT_FLAGS_1, DF_1_PIE | DF_1_NOW), (DT_NULL, 0)]);
        let ds = DynamicSection::parse_le64(&data).unwrap();
        assert!(ds.is_pie());
    }

    #[test]
    fn test_dynamic_section_tag_name() {
        let e = DynamicEntry {
            tag: DT_NEEDED,
            value: 0,
        };
        assert_eq!(e.tag_name(), "DT_NEEDED");
        let e2 = DynamicEntry {
            tag: 0xdead_beef,
            value: 0,
        };
        assert_eq!(e2.tag_name(), "DT_UNKNOWN");
    }

    #[test]
    fn test_dynamic_section_truncated_error() {
        let data = vec![0u8; 7]; // not a multiple of 16
        assert!(matches!(
            DynamicSection::parse_le64(&data),
            Err(DynError::TruncatedData { .. })
        ));
    }

    #[test]
    fn test_dynamic_section_find_all() {
        let data = make_dyn_le64(&[
            (DT_NEEDED, 1),
            (DT_NEEDED, 5),
            (DT_NEEDED, 10),
            (DT_NULL, 0),
        ]);
        let ds = DynamicSection::parse_le64(&data).unwrap();
        let all = ds.find_all(DT_NEEDED);
        assert_eq!(all.len(), 3);
    }

    #[test]
    fn test_dynamic_section_is_null() {
        let e = DynamicEntry {
            tag: DT_NULL,
            value: 0,
        };
        assert!(e.is_null());
        let e2 = DynamicEntry {
            tag: DT_NEEDED,
            value: 0,
        };
        assert!(!e2.is_null());
    }

    #[test]
    fn test_dynamic_section_be64() {
        let mut data = Vec::new();
        data.extend_from_slice(&DT_STRTAB.to_be_bytes());
        data.extend_from_slice(&0x2000u64.to_be_bytes());
        data.extend_from_slice(&DT_NULL.to_be_bytes());
        data.extend_from_slice(&0u64.to_be_bytes());
        let ds = DynamicSection::parse_be64(&data).unwrap();
        assert_eq!(ds.find(DT_STRTAB).unwrap().value, 0x2000);
    }

    // ---- DynlibDeps tests ----

    #[test]
    fn test_dynlib_deps_no_needed() {
        let data = make_dyn_le64(&[(DT_NULL, 0)]);
        let ds = DynamicSection::parse_le64(&data).unwrap();
        let deps = DynlibDeps::from_dynamic(&ds, &[0]);
        assert!(deps.libraries.is_empty());
    }

    #[test]
    fn test_dynlib_deps_two_libs() {
        let dynstr = make_dynstr(&["libc.so.6", "libpthread.so.0"]);
        let libc_off = 1u64;
        let pthread_off = libc_off + "libc.so.6".len() as u64 + 1;
        let data = make_dyn_le64(&[
            (DT_NEEDED, libc_off),
            (DT_NEEDED, pthread_off),
            (DT_NULL, 0),
        ]);
        let ds = DynamicSection::parse_le64(&data).unwrap();
        let deps = DynlibDeps::from_dynamic(&ds, &dynstr);
        assert_eq!(deps.libraries.len(), 2);
        assert!(deps.depends_on("libc"));
        assert!(deps.depends_on("pthread"));
    }

    #[test]
    fn test_dynlib_deps_soname() {
        let dynstr = make_dynstr(&["libfoo.so.1"]);
        let data = make_dyn_le64(&[(DT_SONAME, 1), (DT_NULL, 0)]);
        let ds = DynamicSection::parse_le64(&data).unwrap();
        let deps = DynlibDeps::from_dynamic(&ds, &dynstr);
        assert_eq!(deps.soname.as_deref(), Some("libfoo.so.1"));
    }

    #[test]
    fn test_dynlib_deps_rpath() {
        let dynstr = make_dynstr(&["/opt/lib"]);
        let data = make_dyn_le64(&[(DT_RPATH, 1), (DT_NULL, 0)]);
        let ds = DynamicSection::parse_le64(&data).unwrap();
        let deps = DynlibDeps::from_dynamic(&ds, &dynstr);
        assert_eq!(deps.search_path(), Some("/opt/lib"));
    }

    #[test]
    fn test_dynlib_deps_runpath_fallback() {
        let dynstr = make_dynstr(&["/usr/local/lib"]);
        let data = make_dyn_le64(&[(DT_RUNPATH, 1), (DT_NULL, 0)]);
        let ds = DynamicSection::parse_le64(&data).unwrap();
        let deps = DynlibDeps::from_dynamic(&ds, &dynstr);
        assert_eq!(deps.search_path(), Some("/usr/local/lib"));
    }

    #[test]
    fn test_dynlib_deps_no_search_path() {
        let data = make_dyn_le64(&[(DT_NULL, 0)]);
        let ds = DynamicSection::parse_le64(&data).unwrap();
        let deps = DynlibDeps::from_dynamic(&ds, &[0]);
        assert!(deps.search_path().is_none());
    }

    // ---- DynamicSymbolTable tests ----

    #[test]
    fn test_dynsym_empty() {
        let dynstr = vec![0u8];
        let tbl = DynamicSymbolTable::parse(&[], &dynstr, true, true).unwrap();
        assert!(tbl.is_empty());
    }

    #[test]
    fn test_dynsym_single_func() {
        let dynstr = make_dynstr(&["malloc"]);
        let entry = make_dynsym_entry_64(1, 0x4000, 0x40, 0x12, 0, 1); // GLOBAL FUNC
        let tbl = DynamicSymbolTable::parse(&entry, &dynstr, true, true).unwrap();
        assert_eq!(tbl.len(), 1);
        let sym = &tbl.symbols[0];
        assert_eq!(sym.name, "malloc");
        assert!(matches!(sym.binding, DynSymBinding::Global));
        assert!(matches!(sym.sym_type, DynSymType::Func));
        assert!(sym.is_function());
        assert!(sym.is_exported());
    }

    #[test]
    fn test_dynsym_weak_binding() {
        let dynstr = make_dynstr(&["__libc_start_main"]);
        let entry = make_dynsym_entry_64(1, 0x5000, 0, 0x22, 0, 1); // WEAK FUNC
        let tbl = DynamicSymbolTable::parse(&entry, &dynstr, true, true).unwrap();
        let sym = &tbl.symbols[0];
        assert!(matches!(sym.binding, DynSymBinding::Weak));
    }

    #[test]
    fn test_dynsym_hidden_visibility() {
        let dynstr = make_dynstr(&["hidden_fn"]);
        let entry = make_dynsym_entry_64(1, 0x6000, 0, 0x12, 0x02, 1);
        let tbl = DynamicSymbolTable::parse(&entry, &dynstr, true, true).unwrap();
        assert!(matches!(
            tbl.symbols[0].visibility,
            DynSymVisibility::Hidden
        ));
    }

    #[test]
    fn test_dynsym_find_by_name() {
        let dynstr = make_dynstr(&["alpha", "beta"]);
        let e1 = make_dynsym_entry_64(1, 0x1000, 0, 0x12, 0, 1);
        let e2 = make_dynsym_entry_64(1 + "alpha".len() as u32 + 1, 0x2000, 0, 0x12, 0, 1);
        let mut data = e1;
        data.extend(e2);
        let tbl = DynamicSymbolTable::parse(&data, &dynstr, true, true).unwrap();
        assert!(!tbl.find_by_name("alpha").is_empty());
        assert!(tbl.find_by_name("gamma").is_empty());
    }

    #[test]
    fn test_dynsym_exported_functions() {
        let dynstr = make_dynstr(&["fn_a"]);
        let entry = make_dynsym_entry_64(1, 0x3000, 0x20, 0x12, 0, 1);
        let tbl = DynamicSymbolTable::parse(&entry, &dynstr, true, true).unwrap();
        let fns = tbl.exported_functions();
        assert_eq!(fns.len(), 1);
    }

    // ---- RelocationApplier tests ----

    #[test]
    fn test_parse_rela_empty() {
        let records = RelocationApplier::parse_rela(&[], true, true).unwrap();
        assert!(records.is_empty());
    }

    #[test]
    fn test_parse_rela_single() {
        let mut data = Vec::new();
        let offset: u64 = 0x1000;
        let info: u64 = (1u64 << 32) | 8; // sym=1, type=R_X86_64_RELATIVE(8)
        let addend: i64 = 0x0040_0000;
        data.extend_from_slice(&offset.to_le_bytes());
        data.extend_from_slice(&info.to_le_bytes());
        data.extend_from_slice(&addend.to_le_bytes());
        let records = RelocationApplier::parse_rela(&data, true, true).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].offset, 0x1000);
        assert_eq!(records[0].sym_index, 1);
        assert_eq!(records[0].addend, 0x0040_0000);
    }

    #[test]
    fn test_apply_relative_reloc() {
        let mut image = vec![0u8; 16];
        let record = RelocRecord {
            offset: 0,
            reloc_type: 8,
            sym_index: 0,
            addend: 0x100,
        };
        let mut applier = RelocationApplier::new();
        applier
            .apply_relative(&mut image, &record, 0x0040_0000, 0, true, true)
            .unwrap();
        let val = u64::from_le_bytes(image[0..8].try_into().unwrap());
        assert_eq!(val, 0x0040_0100);
    }

    #[test]
    fn test_apply_relative_out_of_bounds() {
        let mut image = vec![0u8; 4];
        let record = RelocRecord {
            offset: 0,
            reloc_type: 8,
            sym_index: 0,
            addend: 0,
        };
        let mut applier = RelocationApplier::new();
        let result = applier.apply_relative(&mut image, &record, 0, 0, true, true);
        assert!(matches!(result, Err(DynError::RelocOutOfBounds { .. })));
    }

    #[test]
    fn test_parse_rel_single() {
        let offset: u64 = 0x2000;
        let info: u64 = (2u64 << 32) | 1;
        let mut data = Vec::new();
        data.extend_from_slice(&offset.to_le_bytes());
        data.extend_from_slice(&info.to_le_bytes());
        let records = RelocationApplier::parse_rel(&data, true, true).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].addend, 0);
    }

    // ---- GotPltAnalysis tests ----

    #[test]
    fn test_got_too_small() {
        let result = GotPltAnalysis::analyze(&[0u8; 4], 0x3000, true, true, 0x1000, 16, &[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_got_basic_parse() {
        let mut got = vec![0u8; 8 * 4]; // 4 x 8-byte slots
        // GOT[0]=0, GOT[1]=linkmap, GOT[2]=resolver, GOT[3]=plt_stub
        let plt_base: u64 = 0x0040_1020;
        write_u64(&mut got[24..], plt_base + 6, true); // GOT[3] points into PLT = unresolved
        let analysis =
            GotPltAnalysis::analyze(&got, 0x0040_3000, true, true, plt_base, 16, &[]).unwrap();
        assert_eq!(analysis.plt_got_entries.len(), 1);
        assert!(matches!(
            analysis.plt_got_entries[0].state,
            GotSlotState::Unresolved
        ));
    }

    #[test]
    fn test_got_no_hooks() {
        let got = vec![0u8; 8 * 3];
        let analysis =
            GotPltAnalysis::analyze(&got, 0x0040_3000, true, true, 0x0040_1020, 16, &[]).unwrap();
        assert!(!analysis.has_hooks());
    }

    // ---- PltEntry tests ----

    #[test]
    fn test_plt_entry_is_named() {
        let e = PltEntry::new(0x0040_1020, 0x0040_3018, 0, "printf", 0);
        assert!(e.is_named());
        let e2 = PltEntry::new(0x0040_1030, 0x0040_3020, 1, "", 0);
        assert!(!e2.is_named());
    }

    // ---- ElfDynamicAnalysis tests ----

    #[test]
    fn test_elf_dynamic_analysis_no_hooks() {
        let ds = DynamicSection::default();
        let deps = DynlibDeps::default();
        let sym_tbl = DynamicSymbolTable::default();
        let got = GotPltAnalysis::default();
        let analysis = ElfDynamicAnalysis::new(ds, deps, sym_tbl, got, vec![], vec![], (true, true));
        assert!(!analysis.has_hooks());
        assert_eq!(analysis.reloc_count(), 0);
        assert!(analysis.required_libs().is_empty());
    }

    #[test]
    fn test_elf_dynamic_find_plt_present() {
        let ds = DynamicSection::default();
        let deps = DynlibDeps::default();
        let sym_tbl = DynamicSymbolTable::default();
        let got = GotPltAnalysis::default();
        let plt = vec![PltEntry::new(0x0040_1020, 0x0040_3018, 0, "exit", 0)];
        let analysis = ElfDynamicAnalysis::new(ds, deps, sym_tbl, got, plt, vec![], (true, true));
        assert!(analysis.find_plt("exit").is_some());
        assert!(analysis.find_plt("write").is_none());
    }

    #[test]
    fn test_elf_dynamic_find_plt_absent() {
        let ds = DynamicSection::default();
        let deps = DynlibDeps::default();
        let sym_tbl = DynamicSymbolTable::default();
        let got = GotPltAnalysis::default();
        let analysis = ElfDynamicAnalysis::new(ds, deps, sym_tbl, got, vec![], vec![], (true, true));
        assert!(analysis.find_plt("anything").is_none());
    }

    #[test]
    fn test_dyn_error_display() {
        let e = DynError::StringTableOutOfBounds { idx: 999 };
        assert!(e.to_string().contains("999"));
        let e2 = DynError::InvalidTag(0xdead_beef);
        assert!(e2.to_string().contains("deadbeef"));
    }

    #[test]
    fn test_read_dynstr_out_of_bounds() {
        let dynstr = vec![b'a', b'\0'];
        assert!(matches!(
            read_dynstr(&dynstr, 99),
            Err(DynError::StringTableOutOfBounds { .. })
        ));
    }

    #[test]
    fn test_read_dynstr_ok() {
        let mut dynstr = vec![0u8];
        dynstr.extend_from_slice(b"hello\0");
        let s = read_dynstr(&dynstr, 1).unwrap();
        assert_eq!(s, "hello");
    }

    #[test]
    fn test_got_slot_state_resolved() {
        let mut got = vec![0u8; 8 * 4];
        write_u64(&mut got[24..], 0x7fff_1234_5678, true);
        let analysis =
            GotPltAnalysis::analyze(&got, 0x0060_3000, true, true, 0x0040_1020, 16, &[]).unwrap();
        assert!(matches!(
            analysis.plt_got_entries[0].state,
            GotSlotState::Resolved(0x7fff_1234_5678)
        ));
    }

    #[test]
    fn test_dynlib_depends_case_insensitive() {
        let deps = DynlibDeps {
            libraries: vec!["LibC.so.6".to_string()],
            soname: None,
            rpath: None,
            runpath: None,
        };
        assert!(deps.depends_on("libc"));
    }

    #[test]
    fn test_dynamic_section_32bit() {
        let mut data = Vec::new();
        data.extend_from_slice(&(DT_STRTAB as u32).to_le_bytes());
        data.extend_from_slice(&0x1000u32.to_le_bytes());
        data.extend_from_slice(&(DT_NULL as u32).to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes());
        let ds = DynamicSection::parse_le32(&data).unwrap();
        assert_eq!(ds.find(DT_STRTAB).unwrap().value, 0x1000);
    }

    #[test]
    fn test_recod_new_rel_sym_decode() {
        // 64-bit: sym = info >> 32, type = info & 0xffff_ffff
        let info = (5u64 << 32) | 7;
        let r = RelocRecord::new_rel(0x1000, info, true);
        assert_eq!(r.sym_index, 5);
        assert_eq!(r.reloc_type, 7);
        assert_eq!(r.addend, 0);
    }
}
