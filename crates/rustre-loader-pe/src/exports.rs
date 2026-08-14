//! PE export table analysis: `IMAGE_EXPORT_DIRECTORY`, named/ordinal/forwarded exports.

use crate::imports::RvaSection;
use crate::imports::rva_to_file_offset;

// ---------------------------------------------------------------------------
// Data types
// ---------------------------------------------------------------------------

/// `IMAGE_EXPORT_DIRECTORY` — parsed export directory header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportDirectory {
    /// Flags (reserved, must be 0).
    pub characteristics: u32,
    /// Timestamp.
    pub time_date_stamp: u32,
    /// Major version.
    pub major_version: u16,
    /// Minor version.
    pub minor_version: u16,
    /// RVA of the module name string.
    pub name_rva: u32,
    /// Ordinal base (typically 1).
    pub base: u32,
    /// Total number of exported functions.
    pub number_of_functions: u32,
    /// Number of named exports.
    pub number_of_names: u32,
    /// RVA of the Export Address Table (EAT).
    pub address_of_functions: u32,
    /// RVA of the Name Pointer Table (NPT).
    pub address_of_names: u32,
    /// RVA of the Ordinal Table.
    pub address_of_name_ordinals: u32,
}

impl ExportDirectory {
    /// Parse a 40-byte `IMAGE_EXPORT_DIRECTORY` from `data` at `offset`.
    ///
    /// # Errors
    ///
    /// Returns `Err` if `offset + 40 > data.len()`.
    pub fn parse(data: &[u8], offset: usize) -> Result<Self, String> {
        if offset + 40 > data.len() {
            return Err(format!("Export directory truncated at offset {offset}"));
        }
        let r16 = |off: usize| -> u16 {
            u16::from_le_bytes(data[off..off + 2].try_into().unwrap_or([0; 2]))
        };
        let r32 = |off: usize| -> u32 {
            u32::from_le_bytes(data[off..off + 4].try_into().unwrap_or([0; 4]))
        };
        let b = offset;
        Ok(Self {
            characteristics: r32(b),
            time_date_stamp: r32(b + 4),
            major_version: r16(b + 8),
            minor_version: r16(b + 10),
            name_rva: r32(b + 12),
            base: r32(b + 16),
            number_of_functions: r32(b + 20),
            number_of_names: r32(b + 24),
            address_of_functions: r32(b + 28),
            address_of_names: r32(b + 32),
            address_of_name_ordinals: r32(b + 36),
        })
    }
}

/// One exported symbol.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportedSymbol {
    /// Symbol name (None for anonymous/ordinal-only exports).
    pub name: Option<String>,
    /// The export ordinal (= index in EAT + ordinal base).
    pub ordinal: u32,
    /// RVA of the exported function or data (if not forwarded).
    pub rva: u32,
    /// Absolute VA when image is loaded at `image_base`.
    pub virtual_address: u64,
    /// Forward target string (e.g. "NTDLL.RtlAllocateHeap") if this is a forwarded export.
    pub forward_name: Option<String>,
    /// `true` if this export is a forwarder.
    pub is_forward: bool,
}

// ---------------------------------------------------------------------------
// Helper: read NUL-terminated string
// ---------------------------------------------------------------------------

fn read_cstr(data: &[u8], offset: usize) -> String {
    if offset >= data.len() {
        return String::new();
    }
    let slice = &data[offset..];
    let end = slice.iter().position(|&b| b == 0).unwrap_or(slice.len());
    String::from_utf8_lossy(&slice[..end]).into_owned()
}

// ---------------------------------------------------------------------------
// Parse exports
// ---------------------------------------------------------------------------

/// Parse all exported symbols from the export directory.
///
/// `export_dir_rva` and `export_dir_size` come from data directory entry 0.
/// `image_base` is added to RVAs to compute virtual addresses.
#[must_use]
pub fn parse_export_table(
    data: &[u8],
    sections: &[RvaSection],
    export_dir_rva: u32,
    export_dir_size: u32,
    image_base: u64,
) -> Vec<ExportedSymbol> {
    let Some(dir_off) = rva_to_file_offset(export_dir_rva, sections) else {
        return Vec::new();
    };

    let Ok(dir) = ExportDirectory::parse(data, dir_off) else {
        return Vec::new();
    };

    // The counts are raw u32s from the file: cap pre-allocations by what the
    // file could actually hold (4-byte EAT / name-RVA entries, 2-byte ordinals).
    let num_funcs = (dir.number_of_functions as usize).min(data.len() / 4);
    let num_names = (dir.number_of_names as usize).min(data.len() / 4);
    let ordinal_base = dir.base;
    let mut symbols = Vec::with_capacity(num_funcs);

    // --- Read the Name Pointer Table (num_names x RVA) ---
    let Some(npt_off) = rva_to_file_offset(dir.address_of_names, sections) else {
        return symbols;
    };
    let mut name_rvas = Vec::with_capacity(num_names);
    for i in 0..num_names {
        let off = npt_off + i * 4;
        if off + 4 > data.len() {
            break;
        }
        let rva = u32::from_le_bytes(data[off..off + 4].try_into().unwrap_or([0; 4]));
        name_rvas.push(rva);
    }

    // --- Read the Ordinal Table (num_names x u16, relative to ordinal_base) ---
    let Some(ot_off) = rva_to_file_offset(dir.address_of_name_ordinals, sections) else {
        return symbols;
    };
    let mut name_ordinals = Vec::with_capacity(num_names);
    for i in 0..num_names {
        let off = ot_off + i * 2;
        if off + 2 > data.len() {
            break;
        }
        let ord = u16::from_le_bytes(data[off..off + 2].try_into().unwrap_or([0; 2]));
        name_ordinals.push(ord as usize);
    }

    // --- Build name → ordinal_index map ---
    // name_ordinals[i] is the index into the EAT for the i-th named export.
    // The actual ordinal = name_ordinals[i] + ordinal_base.
    let mut index_to_name: std::collections::HashMap<usize, String> =
        std::collections::HashMap::with_capacity(num_names);
    for i in 0..num_names.min(name_rvas.len()).min(name_ordinals.len()) {
        if let Some(name_file_off) = rva_to_file_offset(name_rvas[i], sections) {
            let name = read_cstr(data, name_file_off);
            index_to_name.insert(name_ordinals[i], name);
        }
    }

    // --- Read the Export Address Table (num_funcs x RVA) ---
    let Some(eat_off) = rva_to_file_offset(dir.address_of_functions, sections) else {
        return symbols;
    };

    let export_section_start = export_dir_rva;
    let export_section_end = export_dir_rva.saturating_add(export_dir_size);

    for i in 0..num_funcs {
        let off = eat_off + i * 4;
        if off + 4 > data.len() {
            break;
        }
        let func_rva = u32::from_le_bytes(data[off..off + 4].try_into().unwrap_or([0; 4]));
        if func_rva == 0 {
            continue; // gap in EAT
        }

        let ordinal = ordinal_base + u32::try_from(i).unwrap_or(u32::MAX);
        let name = index_to_name.get(&i).cloned();

        // A forwarded export has its RVA pointing inside the export directory itself.
        let (forward_name, is_forward) =
            if func_rva >= export_section_start && func_rva < export_section_end {
                let fwd_off = rva_to_file_offset(func_rva, sections);
                let fwd = fwd_off.map(|o| read_cstr(data, o)).unwrap_or_default();
                (Some(fwd), true)
            } else {
                (None, false)
            };

        symbols.push(ExportedSymbol {
            name,
            ordinal,
            rva: func_rva,
            virtual_address: image_base + u64::from(func_rva),
            forward_name,
            is_forward,
        });
    }

    symbols
}

// ---------------------------------------------------------------------------
// Export map
// ---------------------------------------------------------------------------

/// An indexed map of all exports for O(1) lookup.
#[derive(Debug, Clone, Default)]
pub struct ExportMap {
    /// Exports by ordinal.
    by_ordinal: std::collections::HashMap<u32, ExportedSymbol>,
    /// Exports by name (for named exports).
    by_name: std::collections::HashMap<String, u32>,
}

impl ExportMap {
    /// Build an export map from a list of exported symbols.
    #[must_use]
    pub fn build(symbols: Vec<ExportedSymbol>) -> Self {
        let mut by_ordinal = std::collections::HashMap::with_capacity(symbols.len());
        let mut by_name = std::collections::HashMap::with_capacity(symbols.len());
        for sym in symbols {
            if let Some(ref n) = sym.name {
                by_name.insert(n.clone(), sym.ordinal);
            }
            by_ordinal.insert(sym.ordinal, sym);
        }
        Self {
            by_ordinal,
            by_name,
        }
    }

    /// Look up an export by ordinal.
    #[must_use]
    pub fn by_ordinal(&self, ordinal: u32) -> Option<&ExportedSymbol> {
        self.by_ordinal.get(&ordinal)
    }

    /// Look up an export by name.
    #[must_use]
    pub fn by_name(&self, name: &str) -> Option<&ExportedSymbol> {
        let ord = self.by_name.get(name)?;
        self.by_ordinal.get(ord)
    }

    /// Return all exported symbols.
    #[must_use]
    pub fn all(&self) -> Vec<&ExportedSymbol> {
        let mut v: Vec<&ExportedSymbol> = self.by_ordinal.values().collect();
        v.sort_by_key(|s| s.ordinal);
        v
    }

    /// Total number of exports.
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_ordinal.len()
    }

    /// Return `true` if the map is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_ordinal.is_empty()
    }

    /// Count forwarded exports.
    #[must_use]
    pub fn forward_count(&self) -> usize {
        self.by_ordinal.values().filter(|s| s.is_forward).count()
    }

    /// Return all forwarded exports.
    #[must_use]
    pub fn forwards(&self) -> Vec<&ExportedSymbol> {
        let mut v: Vec<&ExportedSymbol> =
            self.by_ordinal.values().filter(|s| s.is_forward).collect();
        v.sort_by_key(|s| s.ordinal);
        v
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_export_directory_bytes() -> Vec<u8> {
        let mut buf = vec![0u8; 40];
        let r = |buf: &mut Vec<u8>, off: usize, val: u32| {
            buf[off..off + 4].copy_from_slice(&val.to_le_bytes());
        };
        r(&mut buf, 0, 0); // characteristics
        r(&mut buf, 4, 0); // timestamp
        // major/minor: 0
        r(&mut buf, 12, 0x1000); // name_rva
        r(&mut buf, 16, 1); // ordinal base
        r(&mut buf, 20, 2); // number_of_functions
        r(&mut buf, 24, 1); // number_of_names
        r(&mut buf, 28, 0x2000); // address_of_functions
        r(&mut buf, 32, 0x3000); // address_of_names
        r(&mut buf, 36, 0x4000); // address_of_name_ordinals
        buf
    }

    #[test]
    fn test_export_directory_parse() {
        let buf = make_export_directory_bytes();
        let dir = ExportDirectory::parse(&buf, 0).unwrap();
        assert_eq!(dir.base, 1);
        assert_eq!(dir.number_of_functions, 2);
        assert_eq!(dir.number_of_names, 1);
    }

    #[test]
    fn test_export_directory_too_short() {
        assert!(ExportDirectory::parse(&[0u8; 20], 0).is_err());
    }

    #[test]
    fn test_export_map_build_and_lookup() {
        let sym1 = ExportedSymbol {
            name: Some("Foo".into()),
            ordinal: 1,
            rva: 0x1000,
            virtual_address: 0x40_1000,
            forward_name: None,
            is_forward: false,
        };
        let sym2 = ExportedSymbol {
            name: None,
            ordinal: 2,
            rva: 0x2000,
            virtual_address: 0x40_2000,
            forward_name: None,
            is_forward: false,
        };
        let map = ExportMap::build(vec![sym1, sym2]);
        assert_eq!(map.len(), 2);
        assert!(!map.is_empty());
        assert_eq!(map.by_name("Foo").unwrap().rva, 0x1000);
        assert_eq!(map.by_ordinal(2).unwrap().rva, 0x2000);
        assert!(map.by_name("NonExistent").is_none());
    }

    #[test]
    fn test_export_map_forward_count() {
        let fwd = ExportedSymbol {
            name: Some("Bar".into()),
            ordinal: 3,
            rva: 0x500,
            virtual_address: 0x40_0500,
            forward_name: Some("NTDLL.Bar".into()),
            is_forward: true,
        };
        let map = ExportMap::build(vec![fwd]);
        assert_eq!(map.forward_count(), 1);
        assert_eq!(map.forwards().len(), 1);
    }

    #[test]
    fn test_export_map_all_sorted() {
        let syms: Vec<ExportedSymbol> = (1..=5u32)
            .map(|i| ExportedSymbol {
                name: Some(format!("Sym{i}")),
                ordinal: i,
                rva: i * 0x100,
                virtual_address: 0x40_0000 + u64::from(i) * 0x100,
                forward_name: None,
                is_forward: false,
            })
            .collect();
        let map = ExportMap::build(syms);
        let all = map.all();
        assert_eq!(all.len(), 5);
        assert!(all.windows(2).all(|w| w[0].ordinal < w[1].ordinal));
    }

    #[test]
    fn test_exported_symbol_fields() {
        let sym = ExportedSymbol {
            name: Some("TestFunc".into()),
            ordinal: 10,
            rva: 0x3000,
            virtual_address: 0x1_8000_3000,
            forward_name: None,
            is_forward: false,
        };
        assert_eq!(sym.ordinal, 10);
        assert!(!sym.is_forward);
    }

    #[test]
    fn test_read_cstr_empty() {
        assert_eq!(read_cstr(b"\x00", 0), "");
    }

    #[test]
    fn test_read_cstr_at_offset() {
        let s = b"abc\x00def\x00";
        assert_eq!(read_cstr(s, 4), "def");
    }
}
