//! ELF symbol table (Sym) parsing — `Elf32_Sym` / `Elf64_Sym`.
//!
//! Handles STB_* binding, STT_* type, STV_* visibility, and special section
//! indices. Exposes a function-symbol list for analysis.

// ---------------------------------------------------------------------------
// STB_* symbol binding constants
// ---------------------------------------------------------------------------

pub const STB_LOCAL: u8 = 0;
pub const STB_GLOBAL: u8 = 1;
pub const STB_WEAK: u8 = 2;
pub const STB_LOOS: u8 = 10;
pub const STB_HIOS: u8 = 12;
pub const STB_LOPROC: u8 = 13;
pub const STB_HIPROC: u8 = 15;
pub const STB_GNU_UNIQUE: u8 = 10; // GNU extension

/// Human-readable binding name.
#[must_use]
pub const fn binding_name(b: u8) -> &'static str {
    match b {
        STB_LOCAL => "LOCAL",
        STB_GLOBAL => "GLOBAL",
        STB_WEAK => "WEAK",
        STB_GNU_UNIQUE => "GNU_UNIQUE",
        _ if b >= STB_LOPROC => "PROC",
        _ => "Unknown",
    }
}

// ---------------------------------------------------------------------------
// STT_* symbol type constants
// ---------------------------------------------------------------------------

pub const STT_NOTYPE: u8 = 0;
pub const STT_OBJECT: u8 = 1;
pub const STT_FUNC: u8 = 2;
pub const STT_SECTION: u8 = 3;
pub const STT_FILE: u8 = 4;
pub const STT_COMMON: u8 = 5;
pub const STT_TLS: u8 = 6;
pub const STT_LOOS: u8 = 10;
pub const STT_HIOS: u8 = 12;
pub const STT_LOPROC: u8 = 13;
pub const STT_HIPROC: u8 = 15;
pub const STT_GNU_IFUNC: u8 = 10; // GNU indirect function

/// Human-readable symbol type name.
#[must_use]
pub const fn symbol_type_name(t: u8) -> &'static str {
    match t {
        STT_NOTYPE => "NOTYPE",
        STT_OBJECT => "OBJECT",
        STT_FUNC => "FUNC",
        STT_SECTION => "SECTION",
        STT_FILE => "FILE",
        STT_COMMON => "COMMON",
        STT_TLS => "TLS",
        STT_GNU_IFUNC => "GNU_IFUNC",
        _ if t >= STT_LOPROC => "PROC",
        _ => "Unknown",
    }
}

// ---------------------------------------------------------------------------
// STV_* symbol visibility constants
// ---------------------------------------------------------------------------

pub const STV_DEFAULT: u8 = 0;
pub const STV_INTERNAL: u8 = 1;
pub const STV_HIDDEN: u8 = 2;
pub const STV_PROTECTED: u8 = 3;

/// Human-readable visibility name.
#[must_use]
pub const fn visibility_name(v: u8) -> &'static str {
    match v {
        STV_DEFAULT => "DEFAULT",
        STV_INTERNAL => "INTERNAL",
        STV_HIDDEN => "HIDDEN",
        STV_PROTECTED => "PROTECTED",
        _ => "Unknown",
    }
}

// ---------------------------------------------------------------------------
// ELF info/other field helpers
// ---------------------------------------------------------------------------

/// Extract symbol binding from `st_info`.
#[inline]
#[must_use]
pub const fn st_bind(info: u8) -> u8 {
    info >> 4
}

/// Extract symbol type from `st_info`.
#[inline]
#[must_use]
pub const fn st_type(info: u8) -> u8 {
    info & 0x0F
}

/// Build `st_info` from binding and type.
#[inline]
#[must_use]
pub const fn st_info(bind: u8, stype: u8) -> u8 {
    (bind << 4) | (stype & 0x0F)
}

/// Extract visibility from `st_other`.
#[inline]
#[must_use]
pub const fn st_visibility(other: u8) -> u8 {
    other & 0x03
}

// ---------------------------------------------------------------------------
// Raw Elf32_Sym / Elf64_Sym
// ---------------------------------------------------------------------------

/// Raw 32-bit ELF symbol (`Elf32_Sym`), 16 bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sym32 {
    pub st_name: u32,
    pub st_value: u32,
    pub st_size: u32,
    pub st_info: u8,
    pub st_other: u8,
    pub st_shndx: u16,
}

impl Sym32 {
    pub const SIZE: usize = 16;

    /// # Errors
    /// Returns an error string if the data is too short at the given offset.
    pub fn parse(data: &[u8], offset: usize, le: bool) -> Result<Self, String> {
        if offset.checked_add(Self::SIZE).is_none_or(|end| end > data.len()) {
            return Err(format!("Sym32 truncated at {offset:#x}"));
        }
        let r16 = |off: usize| -> u16 {
            let b = [data[off], data[off + 1]];
            if le {
                u16::from_le_bytes(b)
            } else {
                u16::from_be_bytes(b)
            }
        };
        let r32 = |off: usize| -> u32 {
            let b: [u8; 4] = data[off..off + 4].try_into().unwrap_or([0; 4]);
            if le {
                u32::from_le_bytes(b)
            } else {
                u32::from_be_bytes(b)
            }
        };
        let b = offset;
        Ok(Self {
            st_name: r32(b),
            st_value: r32(b + 4),
            st_size: r32(b + 8),
            st_info: data[b + 12],
            st_other: data[b + 13],
            st_shndx: r16(b + 14),
        })
    }

    #[must_use] 
    pub fn parse_table(data: &[u8], offset: usize, count: usize, le: bool) -> Vec<Self> {
        // Cap count to what actually fits in the buffer (alloc-DoS hardening).
        let count = count.min(data.len().saturating_sub(offset) / Self::SIZE);
        let mut out = Vec::with_capacity(count);
        out.extend((0..count).filter_map(|i| Self::parse(data, offset + i * Self::SIZE, le).ok()));
        out
    }

    #[must_use]
    pub const fn binding(&self) -> u8 {
        st_bind(self.st_info)
    }
    #[must_use]
    pub const fn sym_type(&self) -> u8 {
        st_type(self.st_info)
    }
    #[must_use]
    pub const fn visibility(&self) -> u8 {
        st_visibility(self.st_other)
    }
    #[must_use]
    pub const fn is_function(&self) -> bool {
        self.sym_type() == STT_FUNC
    }
    #[must_use]
    pub const fn is_global(&self) -> bool {
        self.binding() == STB_GLOBAL
    }
}

/// Raw 64-bit ELF symbol (`Elf64_Sym`), 24 bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sym64 {
    pub st_name: u32,
    pub st_info: u8,
    pub st_other: u8,
    pub st_shndx: u16,
    pub st_value: u64,
    pub st_size: u64,
}

impl Sym64 {
    pub const SIZE: usize = 24;

    /// # Errors
    /// Returns an error string if the data is too short at the given offset.
    pub fn parse(data: &[u8], offset: usize, le: bool) -> Result<Self, String> {
        if offset.checked_add(Self::SIZE).is_none_or(|end| end > data.len()) {
            return Err(format!("Sym64 truncated at {offset:#x}"));
        }
        let r16 = |off: usize| -> u16 {
            let b = [data[off], data[off + 1]];
            if le {
                u16::from_le_bytes(b)
            } else {
                u16::from_be_bytes(b)
            }
        };
        let r32 = |off: usize| -> u32 {
            let b: [u8; 4] = data[off..off + 4].try_into().unwrap_or([0; 4]);
            if le {
                u32::from_le_bytes(b)
            } else {
                u32::from_be_bytes(b)
            }
        };
        let r64 = |off: usize| -> u64 {
            let b: [u8; 8] = data[off..off + 8].try_into().unwrap_or([0; 8]);
            if le {
                u64::from_le_bytes(b)
            } else {
                u64::from_be_bytes(b)
            }
        };
        let b = offset;
        Ok(Self {
            st_name: r32(b),
            st_info: data[b + 4],
            st_other: data[b + 5],
            st_shndx: r16(b + 6),
            st_value: r64(b + 8),
            st_size: r64(b + 16),
        })
    }

    #[must_use] 
    pub fn parse_table(data: &[u8], offset: usize, count: usize, le: bool) -> Vec<Self> {
        // Cap count to what actually fits in the buffer (alloc-DoS hardening).
        let count = count.min(data.len().saturating_sub(offset) / Self::SIZE);
        let mut out = Vec::with_capacity(count);
        out.extend((0..count).filter_map(|i| Self::parse(data, offset + i * Self::SIZE, le).ok()));
        out
    }

    #[must_use]
    pub const fn binding(&self) -> u8 {
        st_bind(self.st_info)
    }
    #[must_use]
    pub const fn sym_type(&self) -> u8 {
        st_type(self.st_info)
    }
    #[must_use]
    pub const fn visibility(&self) -> u8 {
        st_visibility(self.st_other)
    }
    #[must_use]
    pub const fn is_function(&self) -> bool {
        self.sym_type() == STT_FUNC
    }
    #[must_use]
    pub const fn is_global(&self) -> bool {
        self.binding() == STB_GLOBAL
    }
}

// ---------------------------------------------------------------------------
// High-level ElfSymbol
// ---------------------------------------------------------------------------

/// Normalized ELF symbol with resolved name.
#[derive(Debug, Clone)]
pub struct ElfSymbol {
    /// Symbol name (resolved from string table).
    pub name: String,
    /// Virtual address.
    pub value: u64,
    /// Symbol size in bytes.
    pub size: u64,
    /// Binding (STB_*).
    pub binding: u8,
    /// Type (STT_*).
    pub sym_type: u8,
    /// Visibility (STV_*).
    pub visibility: u8,
    /// Section index.
    pub shndx: u16,
    /// Is this a 64-bit symbol?
    pub is_64bit: bool,
}

impl ElfSymbol {
    #[must_use]
    pub fn from_sym32(sym: &Sym32, name: String) -> Self {
        Self {
            name,
            value: u64::from(sym.st_value),
            size: u64::from(sym.st_size),
            binding: sym.binding(),
            sym_type: sym.sym_type(),
            visibility: sym.visibility(),
            shndx: sym.st_shndx,
            is_64bit: false,
        }
    }

    #[must_use]
    pub const fn from_sym64(sym: &Sym64, name: String) -> Self {
        Self {
            name,
            value: sym.st_value,
            size: sym.st_size,
            binding: sym.binding(),
            sym_type: sym.sym_type(),
            visibility: sym.visibility(),
            shndx: sym.st_shndx,
            is_64bit: true,
        }
    }

    #[must_use]
    pub const fn is_function(&self) -> bool {
        self.sym_type == STT_FUNC
    }
    #[must_use]
    pub const fn is_object(&self) -> bool {
        self.sym_type == STT_OBJECT
    }
    #[must_use]
    pub const fn is_tls(&self) -> bool {
        self.sym_type == STT_TLS
    }
    #[must_use]
    pub const fn is_undefined(&self) -> bool {
        self.shndx == 0
    } // SHN_UNDEF
    #[must_use]
    pub const fn is_global(&self) -> bool {
        self.binding == STB_GLOBAL
    }
    #[must_use]
    pub const fn is_weak(&self) -> bool {
        self.binding == STB_WEAK
    }
    #[must_use]
    pub const fn is_local(&self) -> bool {
        self.binding == STB_LOCAL
    }
    #[must_use]
    pub const fn is_hidden(&self) -> bool {
        self.visibility == STV_HIDDEN
    }
    #[must_use]
    pub const fn is_ifunc(&self) -> bool {
        self.sym_type == STT_GNU_IFUNC
    }

    #[must_use]
    pub const fn binding_name(&self) -> &'static str {
        binding_name(self.binding)
    }
    #[must_use]
    pub const fn type_name(&self) -> &'static str {
        symbol_type_name(self.sym_type)
    }
    #[must_use]
    pub const fn visibility_name(&self) -> &'static str {
        visibility_name(self.visibility)
    }
}

// ---------------------------------------------------------------------------
// String table lookup
// ---------------------------------------------------------------------------

/// Read a null-terminated string from a byte slice.
#[must_use]
pub fn strtab_get(strtab: &[u8], offset: u32) -> String {
    let off = offset as usize;
    if off >= strtab.len() {
        return String::new();
    }
    let slice = &strtab[off..];
    let end = slice.iter().position(|&b| b == 0).unwrap_or(slice.len());
    String::from_utf8_lossy(&slice[..end]).into_owned()
}

/// Build a list of high-level symbols from 32-bit raw symbols and string table.
#[must_use] 
pub fn build_symbols32(syms: &[Sym32], strtab: &[u8]) -> Vec<ElfSymbol> {
    let mut out = Vec::with_capacity(syms.len());
    out.extend(syms.iter().map(|s| {
        let name = strtab_get(strtab, s.st_name);
        ElfSymbol::from_sym32(s, name)
    }));
    out
}

/// Build a list of high-level symbols from 64-bit raw symbols and string table.
#[must_use] 
pub fn build_symbols64(syms: &[Sym64], strtab: &[u8]) -> Vec<ElfSymbol> {
    let mut out = Vec::with_capacity(syms.len());
    out.extend(syms.iter().map(|s| {
        let name = strtab_get(strtab, s.st_name);
        ElfSymbol::from_sym64(s, name)
    }));
    out
}

/// Filter for function symbols only, sorted by address.
#[must_use] 
pub fn function_symbols(symbols: &[ElfSymbol]) -> Vec<&ElfSymbol> {
    let mut funcs: Vec<&ElfSymbol> = symbols
        .iter()
        .filter(|s| s.is_function() && !s.is_undefined() && s.value != 0)
        .collect();
    funcs.sort_by_key(|s| s.value);
    funcs
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_sym32(name: u32, value: u32, size: u32, bind: u8, stype: u8, shndx: u16) -> Vec<u8> {
        let mut b = vec![0u8; 16];
        b[0..4].copy_from_slice(&name.to_le_bytes());
        b[4..8].copy_from_slice(&value.to_le_bytes());
        b[8..12].copy_from_slice(&size.to_le_bytes());
        b[12] = st_info(bind, stype);
        b[13] = 0; // st_other
        b[14..16].copy_from_slice(&shndx.to_le_bytes());
        b
    }

    fn make_sym64(name: u32, value: u64, size: u64, bind: u8, stype: u8, shndx: u16) -> Vec<u8> {
        let mut b = vec![0u8; 24];
        b[0..4].copy_from_slice(&name.to_le_bytes());
        b[4] = st_info(bind, stype);
        b[5] = 0; // st_other
        b[6..8].copy_from_slice(&shndx.to_le_bytes());
        b[8..16].copy_from_slice(&value.to_le_bytes());
        b[16..24].copy_from_slice(&size.to_le_bytes());
        b
    }

    #[test]
    fn test_parse_sym32_func() {
        let b = make_sym32(5, 0x0804_8000, 0x100, STB_GLOBAL, STT_FUNC, 1);
        let sym = Sym32::parse(&b, 0, true).unwrap();
        assert_eq!(sym.st_value, 0x0804_8000);
        assert_eq!(sym.st_size, 0x100);
        assert!(sym.is_function());
        assert!(sym.is_global());
    }

    #[test]
    fn test_parse_sym64_object() {
        let b = make_sym64(3, 0x0060_1000, 8, STB_GLOBAL, STT_OBJECT, 2);
        let sym = Sym64::parse(&b, 0, true).unwrap();
        assert_eq!(sym.st_value, 0x0060_1000);
        assert!(!sym.is_function());
        assert_eq!(sym.sym_type(), STT_OBJECT);
    }

    #[test]
    fn test_sym32_truncated() {
        assert!(Sym32::parse(&[0u8; 8], 0, true).is_err());
    }

    #[test]
    fn test_sym64_truncated() {
        assert!(Sym64::parse(&[0u8; 8], 0, true).is_err());
    }

    #[test]
    fn test_st_info_roundtrip() {
        let info = st_info(STB_GLOBAL, STT_FUNC);
        assert_eq!(st_bind(info), STB_GLOBAL);
        assert_eq!(st_type(info), STT_FUNC);
    }

    #[test]
    fn test_st_visibility() {
        assert_eq!(st_visibility(STV_HIDDEN), STV_HIDDEN);
        assert_eq!(st_visibility(STV_DEFAULT), STV_DEFAULT);
    }

    #[test]
    fn test_build_symbols32() {
        let strtab = b"\0main\0foo\0";
        let b1 = make_sym32(1, 0x0040_1000, 0x40, STB_GLOBAL, STT_FUNC, 1);
        let b2 = make_sym32(6, 0x0040_1040, 0x20, STB_LOCAL, STT_FUNC, 1);
        let s1 = Sym32::parse(&b1, 0, true).unwrap();
        let s2 = Sym32::parse(&b2, 0, true).unwrap();
        let syms = build_symbols32(&[s1, s2], strtab);
        assert_eq!(syms[0].name, "main");
        assert_eq!(syms[1].name, "foo");
        assert!(syms[0].is_global());
        assert!(syms[1].is_local());
    }

    #[test]
    fn test_function_symbols_filter_and_sort() {
        let syms = vec![
            ElfSymbol {
                name: "b".into(),
                value: 0x0040_2000,
                size: 10,
                binding: STB_GLOBAL,
                sym_type: STT_FUNC,
                visibility: STV_DEFAULT,
                shndx: 1,
                is_64bit: true,
            },
            ElfSymbol {
                name: "data".into(),
                value: 0x0040_3000,
                size: 4,
                binding: STB_GLOBAL,
                sym_type: STT_OBJECT,
                visibility: STV_DEFAULT,
                shndx: 2,
                is_64bit: true,
            },
            ElfSymbol {
                name: "a".into(),
                value: 0x0040_1000,
                size: 20,
                binding: STB_GLOBAL,
                sym_type: STT_FUNC,
                visibility: STV_DEFAULT,
                shndx: 1,
                is_64bit: true,
            },
            ElfSymbol {
                name: "undef".into(),
                value: 0x0,
                size: 0,
                binding: STB_GLOBAL,
                sym_type: STT_FUNC,
                visibility: STV_DEFAULT,
                shndx: 0,
                is_64bit: true,
            },
        ];
        let funcs = function_symbols(&syms);
        assert_eq!(funcs.len(), 2);
        assert_eq!(funcs[0].name, "a"); // sorted by address
        assert_eq!(funcs[1].name, "b");
    }

    #[test]
    fn test_strtab_get_oob() {
        let strtab = b"\0hello\0";
        assert_eq!(strtab_get(strtab, 999), "");
    }

    #[test]
    fn test_binding_name_all() {
        assert_eq!(binding_name(STB_LOCAL), "LOCAL");
        assert_eq!(binding_name(STB_GLOBAL), "GLOBAL");
        assert_eq!(binding_name(STB_WEAK), "WEAK");
    }

    #[test]
    fn test_symbol_type_name_all() {
        assert_eq!(symbol_type_name(STT_FUNC), "FUNC");
        assert_eq!(symbol_type_name(STT_OBJECT), "OBJECT");
        assert_eq!(symbol_type_name(STT_TLS), "TLS");
        assert_eq!(symbol_type_name(STT_GNU_IFUNC), "GNU_IFUNC");
    }

    #[test]
    fn test_visibility_name_all() {
        assert_eq!(visibility_name(STV_DEFAULT), "DEFAULT");
        assert_eq!(visibility_name(STV_HIDDEN), "HIDDEN");
        assert_eq!(visibility_name(STV_PROTECTED), "PROTECTED");
    }

    #[test]
    fn test_elf_symbol_ifunc() {
        let sym = ElfSymbol {
            name: "malloc".into(),
            value: 0x0040_1000,
            size: 0,
            binding: STB_GLOBAL,
            sym_type: STT_GNU_IFUNC,
            visibility: STV_DEFAULT,
            shndx: 1,
            is_64bit: true,
        };
        assert!(sym.is_ifunc());
        assert!(sym.is_global());
    }
}
