//! PE import table analysis: `IMAGE_IMPORT_DESCRIPTOR`, IAT, ILT, delay imports.

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Ordinal import flag: high bit of the name RVA in the ILT/IAT.
pub const IMAGE_ORDINAL_FLAG32: u32 = 0x8000_0000;
pub const IMAGE_ORDINAL_FLAG64: u64 = 0x8000_0000_0000_0000;

// ---------------------------------------------------------------------------
// Data types
// ---------------------------------------------------------------------------

/// One parsed import (a function imported from a DLL).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportedFunction {
    /// Name of the owning DLL.
    pub dll: String,
    /// Function name, or `None` if imported by ordinal only.
    pub name: Option<String>,
    /// Ordinal (present for ordinal imports; hint for named imports).
    pub ordinal: u16,
    /// IAT virtual address (image-base–relative) where the resolved address will be stored.
    pub iat_rva: u64,
    /// `true` if this was imported by ordinal rather than name.
    pub by_ordinal: bool,
}

/// A DLL import descriptor entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportDescriptor {
    /// RVA of the Import Lookup Table (original thunk table).
    pub original_first_thunk: u32,
    /// Timestamp; 0 = not bound, -1 = bound all imports.
    pub time_date_stamp: u32,
    /// Index of the first forwarder reference.
    pub forwarder_chain: u32,
    /// RVA of the DLL name string.
    pub name_rva: u32,
    /// RVA of the Import Address Table (thunk table patched at load time).
    pub first_thunk: u32,
}

impl ImportDescriptor {
    /// Parse one 20-byte `IMAGE_IMPORT_DESCRIPTOR` from `data` at `offset`.
    ///
    /// # Errors
    ///
    /// Returns `Err` if `offset + 20 > data.len()`.
    pub fn parse(data: &[u8], offset: usize) -> Result<Self, String> {
        if offset + 20 > data.len() {
            return Err(format!("Import descriptor truncated at offset {offset}"));
        }
        let r32 = |off: usize| -> u32 {
            u32::from_le_bytes(data[off..off + 4].try_into().unwrap_or([0; 4]))
        };
        Ok(Self {
            original_first_thunk: r32(offset),
            time_date_stamp: r32(offset + 4),
            forwarder_chain: r32(offset + 8),
            name_rva: r32(offset + 12),
            first_thunk: r32(offset + 16),
        })
    }

    /// Return `true` if this is the null terminator entry.
    #[must_use]
    pub const fn is_null(&self) -> bool {
        self.original_first_thunk == 0
            && self.time_date_stamp == 0
            && self.forwarder_chain == 0
            && self.name_rva == 0
            && self.first_thunk == 0
    }

    /// Return `true` if this DLL's IAT is already bound.
    #[must_use]
    pub const fn is_bound(&self) -> bool {
        self.time_date_stamp == 0xFFFF_FFFF
    }
}

// ---------------------------------------------------------------------------
// Delay import descriptor (Microsoft-specific)
// ---------------------------------------------------------------------------

/// Parsed `IMAGE_DELAYLOAD_DESCRIPTOR`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DelayImportDescriptor {
    /// Attributes: bit 1 = use RVAs (v2 format).
    pub attributes: u32,
    /// RVA of the DLL name string.
    pub dll_name_rva: u32,
    /// RVA of the module handle slot.
    pub module_handle_rva: u32,
    /// RVA of the delay IAT.
    pub delay_iat_rva: u32,
    /// RVA of the delay ILT.
    pub delay_int_rva: u32,
    /// RVA of the bound delay IAT.
    pub bound_delay_iat_rva: u32,
    /// RVA of the unload delay IAT.
    pub unload_delay_iat_rva: u32,
    /// Timestamp.
    pub time_stamp: u32,
}

impl DelayImportDescriptor {
    /// Parse one 32-byte `IMAGE_DELAYLOAD_DESCRIPTOR` from `data` at `offset`.
    ///
    /// # Errors
    ///
    /// Returns `Err` if `offset + 32 > data.len()`.
    pub fn parse(data: &[u8], offset: usize) -> Result<Self, String> {
        if offset + 32 > data.len() {
            return Err(format!(
                "Delay import descriptor truncated at offset {offset}"
            ));
        }
        let r32 = |off: usize| -> u32 {
            u32::from_le_bytes(data[off..off + 4].try_into().unwrap_or([0; 4]))
        };
        Ok(Self {
            attributes: r32(offset),
            dll_name_rva: r32(offset + 4),
            module_handle_rva: r32(offset + 8),
            delay_iat_rva: r32(offset + 12),
            delay_int_rva: r32(offset + 16),
            bound_delay_iat_rva: r32(offset + 20),
            unload_delay_iat_rva: r32(offset + 24),
            time_stamp: r32(offset + 28),
        })
    }

    /// Return `true` if this is a null (terminator) entry.
    #[must_use]
    pub const fn is_null(&self) -> bool {
        self.dll_name_rva == 0 && self.delay_iat_rva == 0
    }

    /// Return `true` if this descriptor uses RVAs (v2 format).
    #[must_use]
    pub const fn uses_rvas(&self) -> bool {
        self.attributes & 1 != 0
    }
}

// ---------------------------------------------------------------------------
// Helper: read a NUL-terminated string from file data at a file offset
// ---------------------------------------------------------------------------

fn read_cstr(data: &[u8], file_offset: usize) -> String {
    if file_offset >= data.len() {
        return String::new();
    }
    let slice = &data[file_offset..];
    let end = slice.iter().position(|&b| b == 0).unwrap_or(slice.len());
    String::from_utf8_lossy(&slice[..end]).into_owned()
}

// ---------------------------------------------------------------------------
// RVA → file offset using the section table
// ---------------------------------------------------------------------------

/// A lightweight section record sufficient for RVA → file-offset translation.
#[derive(Debug, Clone)]
pub struct RvaSection {
    pub virtual_address: u32,
    pub virtual_size: u32,
    pub raw_size: u32,
    pub raw_offset: u32,
}

impl RvaSection {
    /// Translate `rva` to a file offset, if this section covers it.
    #[must_use]
    pub fn rva_to_offset(&self, rva: u32) -> Option<usize> {
        let end = self
            .virtual_address
            .saturating_add(self.virtual_size.max(self.raw_size));
        if rva < self.virtual_address || rva >= end {
            return None;
        }
        let off_in_sec = rva - self.virtual_address;
        // Only `raw_size` bytes of this section exist in the file. Where
        // `virtual_size` is larger — ordinary for `.bss`-style padding, and
        // trivially forged in a hostile binary — the tail has no file bytes
        // behind it, and translating it anyway yields an offset inside the
        // *next* section's data or past the end of the file. The parse then
        // continues on bytes that were never part of this section, silently.
        //
        // `PeHeaders::rva_to_file_offset` already refuses these; this is the
        // same rule, so the two translations cannot disagree about which RVAs
        // are addressable.
        if off_in_sec >= self.raw_size {
            return None;
        }
        (self.raw_offset as usize).checked_add(off_in_sec as usize)
    }
}

/// Translate an RVA to a file offset using a slice of section records.
#[must_use]
pub fn rva_to_file_offset(rva: u32, sections: &[RvaSection]) -> Option<usize> {
    for sec in sections {
        if let Some(off) = sec.rva_to_offset(rva) {
            return Some(off);
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Parse the full import table (32-bit)
// ---------------------------------------------------------------------------

/// Parse all imported functions from the PE import table (32-bit ILT).
///
/// `import_dir_rva` is the RVA of the first `IMAGE_IMPORT_DESCRIPTOR` entry,
/// `import_dir_size` is its size, `image_base` is used only to compute final
/// IAT VAs stored in `ImportedFunction.iat_rva`.
#[must_use]
pub fn parse_import_table_32(
    data: &[u8],
    sections: &[RvaSection],
    import_dir_rva: u32,
    _import_dir_size: u32,
    image_base: u64,
) -> Vec<ImportedFunction> {
    let mut functions = Vec::new();

    let Some(mut desc_off) = rva_to_file_offset(import_dir_rva, sections) else {
        return functions;
    };

    loop {
        let Ok(desc) = ImportDescriptor::parse(data, desc_off) else {
            break;
        };
        if desc.is_null() {
            break;
        }
        desc_off += 20;

        let dll_name = if desc.name_rva != 0 {
            rva_to_file_offset(desc.name_rva, sections)
                .map(|o| read_cstr(data, o))
                .unwrap_or_default()
        } else {
            String::new()
        };

        // Prefer the ILT (original thunks); fall back to IAT
        let thunk_rva = if desc.original_first_thunk != 0 {
            desc.original_first_thunk
        } else {
            desc.first_thunk
        };

        if thunk_rva == 0 {
            continue;
        }

        let Some(mut thunk_off) = rva_to_file_offset(thunk_rva, sections) else {
            continue;
        };
        let mut iat_rva = desc.first_thunk;

        loop {
            if thunk_off + 4 > data.len() {
                break;
            }
            let thunk_val =
                u32::from_le_bytes(data[thunk_off..thunk_off + 4].try_into().unwrap_or([0; 4]));
            if thunk_val == 0 {
                break;
            }

            let (name, ordinal, by_ordinal) = if thunk_val & IMAGE_ORDINAL_FLAG32 != 0 {
                // Ordinal import
                let ord = (thunk_val & 0xFFFF) as u16;
                (None, ord, true)
            } else {
                // Named import: thunk_val is RVA to IMAGE_IMPORT_BY_NAME (hint u16 + name)
                let hint_file_off = rva_to_file_offset(thunk_val & 0x7FFF_FFFF, sections);
                hint_file_off.map_or((None, 0, false), |hint_off| {
                    if hint_off + 2 <= data.len() {
                        let hint = u16::from_le_bytes(
                            data[hint_off..hint_off + 2].try_into().unwrap_or([0; 2]),
                        );
                        let func_name = read_cstr(data, hint_off + 2);
                        (Some(func_name), hint, false)
                    } else {
                        (None, 0, false)
                    }
                })
            };

            functions.push(ImportedFunction {
                dll: dll_name.clone(),
                name,
                ordinal,
                iat_rva: image_base + u64::from(iat_rva),
                by_ordinal,
            });

            thunk_off += 4;
            iat_rva += 4;
        }
    }

    functions
}

// ---------------------------------------------------------------------------
// Parse the full import table (64-bit)
// ---------------------------------------------------------------------------

/// Parse all imported functions from the PE import table (64-bit ILT).
#[must_use]
pub fn parse_import_table_64(
    data: &[u8],
    sections: &[RvaSection],
    import_dir_rva: u32,
    _import_dir_size: u32,
    image_base: u64,
) -> Vec<ImportedFunction> {
    let mut functions = Vec::new();

    let Some(mut desc_off) = rva_to_file_offset(import_dir_rva, sections) else {
        return functions;
    };

    loop {
        let Ok(desc) = ImportDescriptor::parse(data, desc_off) else {
            break;
        };
        if desc.is_null() {
            break;
        }
        desc_off += 20;

        let dll_name = if desc.name_rva != 0 {
            rva_to_file_offset(desc.name_rva, sections)
                .map(|o| read_cstr(data, o))
                .unwrap_or_default()
        } else {
            String::new()
        };

        let thunk_rva = if desc.original_first_thunk != 0 {
            desc.original_first_thunk
        } else {
            desc.first_thunk
        };

        if thunk_rva == 0 {
            continue;
        }

        let Some(mut thunk_off) = rva_to_file_offset(thunk_rva, sections) else {
            continue;
        };
        let mut iat_rva = u64::from(desc.first_thunk);

        loop {
            if thunk_off + 8 > data.len() {
                break;
            }
            let thunk_val =
                u64::from_le_bytes(data[thunk_off..thunk_off + 8].try_into().unwrap_or([0; 8]));
            if thunk_val == 0 {
                break;
            }

            let (name, ordinal, by_ordinal) = if thunk_val & IMAGE_ORDINAL_FLAG64 != 0 {
                let ord = (thunk_val & 0xFFFF) as u16;
                (None, ord, true)
            } else {
                let hint_rva = u32::try_from(thunk_val & 0x7FFF_FFFF_FFFF_FFFF).unwrap_or(u32::MAX);
                let hint_file_off = rva_to_file_offset(hint_rva, sections);
                hint_file_off.map_or((None, 0, false), |hint_off| {
                    if hint_off + 2 <= data.len() {
                        let hint = u16::from_le_bytes(
                            data[hint_off..hint_off + 2].try_into().unwrap_or([0; 2]),
                        );
                        let func_name = read_cstr(data, hint_off + 2);
                        (Some(func_name), hint, false)
                    } else {
                        (None, 0, false)
                    }
                })
            };

            functions.push(ImportedFunction {
                dll: dll_name.clone(),
                name,
                ordinal,
                iat_rva: image_base + iat_rva,
                by_ordinal,
            });

            thunk_off += 8;
            iat_rva += 8;
        }
    }

    functions
}

// ---------------------------------------------------------------------------
// Delay import parsing
// ---------------------------------------------------------------------------

/// Parse all delay-loaded DLL descriptors.
#[must_use]
pub fn parse_delay_imports(
    data: &[u8],
    sections: &[RvaSection],
    delay_dir_rva: u32,
) -> Vec<DelayImportDescriptor> {
    let mut descs = Vec::new();

    let Some(mut off) = rva_to_file_offset(delay_dir_rva, sections) else {
        return descs;
    };

    loop {
        let Ok(desc) = DelayImportDescriptor::parse(data, off) else {
            break;
        };
        if desc.is_null() {
            break;
        }
        descs.push(desc);
        off += 32;
    }

    descs
}

// ---------------------------------------------------------------------------
// Bound import table
// ---------------------------------------------------------------------------

/// One entry in the bound import table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundImportEntry {
    /// Timestamp of the bound DLL.
    pub time_date_stamp: u32,
    /// Offset (relative to the start of the bound import directory) to the
    /// module name.
    pub offset_module_name: u16,
    /// Number of module forwarder refs following this entry.
    pub number_of_module_forwarder_refs: u16,
    /// DLL name (resolved).
    pub name: String,
}

/// Parse the bound import directory.
#[must_use]
pub fn parse_bound_imports(data: &[u8], dir_file_offset: usize) -> Vec<BoundImportEntry> {
    let mut entries = Vec::new();
    let mut off = dir_file_offset;

    loop {
        if off + 8 > data.len() {
            break;
        }
        let ts = u32::from_le_bytes(data[off..off + 4].try_into().unwrap_or([0; 4]));
        let name_off = u16::from_le_bytes(data[off + 4..off + 6].try_into().unwrap_or([0; 2]));
        let fwd_refs = u16::from_le_bytes(data[off + 6..off + 8].try_into().unwrap_or([0; 2]));

        if ts == 0 && name_off == 0 {
            break;
        }

        let name_file_off = dir_file_offset + name_off as usize;
        let name = read_cstr(data, name_file_off);

        entries.push(BoundImportEntry {
            time_date_stamp: ts,
            offset_module_name: name_off,
            number_of_module_forwarder_refs: fwd_refs,
            name,
        });

        off += 8;
        // Skip forwarder refs (each is 8 bytes); use saturating to avoid
        // wrapping on a malformed fwd_refs value (max 65535 * 8 = 524280, safe
        // for usize but the explicit check keeps future readers honest).
        off = off.saturating_add((fwd_refs as usize).saturating_mul(8));
    }

    entries
}

// ---------------------------------------------------------------------------
// Forward export detection heuristic
// ---------------------------------------------------------------------------

/// Return `true` if `export_data` looks like a forward string (`DLL.FuncName`).
/// Forward exports have their RVA pointing inside the export section itself.
#[must_use]
pub fn looks_like_forward(export_data: &[u8]) -> bool {
    // A forward string contains a dot and consists of printable ASCII
    if export_data.is_empty() {
        return false;
    }
    let end = export_data
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(export_data.len());
    let s = &export_data[..end];
    if s.is_empty() {
        return false;
    }
    let has_dot = s.contains(&b'.');
    let all_printable = s.iter().all(|&b| b.is_ascii_graphic());
    has_dot && all_printable
}

// ---------------------------------------------------------------------------
// Import table summary
// ---------------------------------------------------------------------------

/// Summary of all imports grouped by DLL.
#[derive(Debug, Clone)]
pub struct ImportSummary {
    /// Map of DLL name → list of imported function names (or "#ordinal").
    pub by_dll: std::collections::HashMap<String, Vec<String>>,
}

impl ImportSummary {
    /// Build a summary from a flat list of `ImportedFunction`s.
    #[must_use]
    pub fn from_functions(funcs: &[ImportedFunction]) -> Self {
        let mut by_dll: std::collections::HashMap<String, Vec<String>> =
            std::collections::HashMap::with_capacity(funcs.len());
        for f in funcs {
            let label = f.name.as_ref().map_or_else(|| format!("#{}", f.ordinal), Clone::clone);
            by_dll.entry(f.dll.clone()).or_default().push(label);
        }
        Self { by_dll }
    }

    /// Return all DLL names.
    #[must_use]
    pub fn dlls(&self) -> Vec<&str> {
        let mut names: Vec<&str> = self.by_dll.keys().map(String::as_str).collect();
        names.sort_unstable();
        names
    }

    /// Return all imported symbols from a given DLL.
    #[must_use]
    pub fn from_dll<'a>(&'a self, dll: &str) -> &'a [String] {
        self.by_dll.get(dll).map_or(&[], Vec::as_slice)
    }

    /// Count total number of imports.
    #[must_use]
    pub fn total_count(&self) -> usize {
        self.by_dll.values().map(Vec::len).sum()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_import_descriptor_parse_null() {
        let data = vec![0u8; 20];
        let desc = ImportDescriptor::parse(&data, 0).unwrap();
        assert!(desc.is_null());
    }

    #[test]
    fn test_import_descriptor_bound() {
        let mut data = vec![0u8; 20];
        data[4..8].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // time_date_stamp
        let desc = ImportDescriptor::parse(&data, 0).unwrap();
        assert!(desc.is_bound());
    }

    #[test]
    fn test_import_descriptor_parse_short() {
        assert!(ImportDescriptor::parse(&[0u8; 10], 0).is_err());
    }

    #[test]
    fn test_delay_import_descriptor_null() {
        let data = vec![0u8; 32];
        let desc = DelayImportDescriptor::parse(&data, 0).unwrap();
        assert!(desc.is_null());
    }

    #[test]
    fn test_delay_import_uses_rvas() {
        let mut data = vec![0u8; 32];
        data[0..4].copy_from_slice(&1u32.to_le_bytes());
        let desc = DelayImportDescriptor::parse(&data, 0).unwrap();
        assert!(desc.uses_rvas());
    }

    #[test]
    fn test_rva_section_translation() {
        let sec = RvaSection {
            virtual_address: 0x1000,
            virtual_size: 0x500,
            raw_size: 0x600,
            raw_offset: 0x200,
        };
        assert_eq!(sec.rva_to_offset(0x1000), Some(0x200));
        assert_eq!(sec.rva_to_offset(0x1100), Some(0x300));
        assert!(sec.rva_to_offset(0x2000).is_none());
    }

    #[test]
    fn test_rva_to_file_offset_multiple_sections() {
        let sections = vec![
            RvaSection {
                virtual_address: 0x1000,
                virtual_size: 0x100,
                raw_size: 0x200,
                raw_offset: 0x400,
            },
            RvaSection {
                virtual_address: 0x2000,
                virtual_size: 0x100,
                raw_size: 0x200,
                raw_offset: 0x600,
            },
        ];
        assert_eq!(rva_to_file_offset(0x2000, &sections), Some(0x600));
        assert_eq!(rva_to_file_offset(0x2050, &sections), Some(0x650));
        assert!(rva_to_file_offset(0x5000, &sections).is_none());
    }

    #[test]
    fn test_looks_like_forward_yes() {
        assert!(looks_like_forward(b"NTDLL.HeapAlloc\0"));
    }

    #[test]
    fn test_looks_like_forward_no() {
        assert!(!looks_like_forward(b"\x00\x01\x02\x03"));
        assert!(!looks_like_forward(b"NoForward\0"));
    }

    #[test]
    fn test_import_summary_build() {
        let funcs = vec![
            ImportedFunction {
                dll: "KERNEL32.dll".into(),
                name: Some("VirtualAlloc".into()),
                ordinal: 0,
                iat_rva: 0x40_1000,
                by_ordinal: false,
            },
            ImportedFunction {
                dll: "KERNEL32.dll".into(),
                name: Some("VirtualFree".into()),
                ordinal: 0,
                iat_rva: 0x40_1008,
                by_ordinal: false,
            },
            ImportedFunction {
                dll: "NTDLL.dll".into(),
                name: None,
                ordinal: 42,
                iat_rva: 0x40_1010,
                by_ordinal: true,
            },
        ];
        let summary = ImportSummary::from_functions(&funcs);
        assert_eq!(summary.total_count(), 3);
        let dlls = summary.dlls();
        assert!(dlls.contains(&"KERNEL32.dll"));
        assert!(dlls.contains(&"NTDLL.dll"));
        assert_eq!(summary.from_dll("KERNEL32.dll").len(), 2);
        assert_eq!(summary.from_dll("NTDLL.dll")[0], "#42");
    }

    #[test]
    fn test_imported_function_fields() {
        let f = ImportedFunction {
            dll: "user32.dll".into(),
            name: Some("MessageBoxA".into()),
            ordinal: 7,
            iat_rva: 0x1_8000_1234,
            by_ordinal: false,
        };
        assert_eq!(f.dll, "user32.dll");
        assert_eq!(f.name.as_deref(), Some("MessageBoxA"));
        assert!(!f.by_ordinal);
    }

    #[test]
    fn test_ordinal_flag_constants() {
        assert_eq!(IMAGE_ORDINAL_FLAG32, 0x8000_0000);
        assert_eq!(IMAGE_ORDINAL_FLAG64, 0x8000_0000_0000_0000);
    }

    #[test]
    fn test_bound_import_parse_empty() {
        let data = vec![0u8; 16];
        let entries = parse_bound_imports(&data, 0);
        assert!(entries.is_empty());
    }

    #[test]
    fn test_read_cstr() {
        let data = b"hello\x00world";
        assert_eq!(read_cstr(data, 0), "hello");
        assert_eq!(read_cstr(data, 6), "world");
    }
}
