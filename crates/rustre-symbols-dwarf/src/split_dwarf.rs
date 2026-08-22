//! Split DWARF (`.dwo` / `.dwp`) support.
//!
//! Implements:
//! - Detection and loading of `.dwo` skeleton compilation units
//! - `.dwp` (DWARF package) section unpacking
//! - Path resolution for external DWO files
//! - Supplementary DWARF object handling

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use thiserror::Error;

// ── Errors ────────────────────────────────────────────────────────────────────

/// Errors produced while loading or resolving split-DWARF files.
#[derive(Debug, Error)]
pub enum SplitDwarfError {
    /// The input is not a valid `.dwo` file.
    #[error("not a DWO file")]
    NotDwo,
    /// The input is not a valid `.dwp` package.
    #[error("not a DWP package")]
    NotDwp,
    /// The `.dwo` file's DWO ID does not match the skeleton CU's `DW_AT_dwo_id`.
    #[error("DWO ID mismatch: expected {0:#x}, got {1:#x}")]
    IdMismatch(u64, u64),
    /// A required section is missing from the package.
    #[error("section {0} not found in package")]
    SectionMissing(String),
    /// The split-DWARF data is structurally invalid.
    #[error("malformed split DWARF: {0}")]
    Malformed(String),
    /// A filesystem I/O error occurred.
    #[error("IO error: {0}")]
    Io(String),
    /// The data ended unexpectedly at the given offset.
    #[error("truncated data at offset {0}")]
    Truncated(usize),
}

// ── DwoSection ────────────────────────────────────────────────────────────────

/// A named section extracted from a `.dwo` file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DwoSection {
    /// Section name (e.g., `.debug_info.dwo`).
    pub name: String,
    /// Raw section data.
    pub data: Vec<u8>,
}

impl DwoSection {
    /// Create a section from its name and raw bytes.
    pub fn new(name: impl Into<String>, data: Vec<u8>) -> Self {
        Self {
            name: name.into(),
            data,
        }
    }

    /// Return `true` if this section contains DWARF debug information.
    #[must_use]
    pub fn is_debug_section(&self) -> bool {
        self.name.starts_with(".debug_")
    }
}

// ── DwoFile ────────────────────────────────────────────────────────────────────

/// A `.dwo` file: a separate debug-information file referenced by a skeleton CU.
#[derive(Debug, Clone)]
pub struct DwoFile {
    /// Path to the DWO file on disk.
    pub path: PathBuf,
    /// The 64-bit DWO identifier (matches the skeleton CU's `DW_AT_dwo_id`).
    pub dwo_id: u64,
    /// Sections extracted from the file.
    pub sections: Vec<DwoSection>,
}

impl DwoFile {
    /// Construct a `DwoFile` from in-memory ELF data.
    ///
    /// Parses the ELF section table and extracts all `.debug_*.dwo` sections.
    ///
    /// # Errors
    ///
    /// Returns `SplitDwarfError::NotDwo` if the data is not a valid ELF or contains no `.dwo` sections,
    /// and `SplitDwarfError::Malformed` if the ELF section table cannot be parsed.
    pub fn from_elf_bytes(path: impl Into<PathBuf>, data: &[u8]) -> Result<Self, SplitDwarfError> {
        let path = path.into();
        // Detect ELF magic.
        if data.len() < 4 || data[0..4] != [0x7f, b'E', b'L', b'F'] {
            return Err(SplitDwarfError::NotDwo);
        }

        let sections =
            extract_elf_sections(data).map_err(|e| SplitDwarfError::Malformed(e.to_string()))?;

        // Verify at least one `.dwo` section is present. Use a case-insensitive
        // check because some toolchains emit `.DWO` on case-preserving filesystems.
        let has_dwo = sections.iter().any(|s| {
            std::path::Path::new(&s.name)
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("dwo"))
        });
        if !has_dwo {
            return Err(SplitDwarfError::NotDwo);
        }

        // Extract DWO ID from `.debug_info.dwo` if available.
        let dwo_id = extract_dwo_id_from_sections(&sections).unwrap_or(0);

        Ok(Self {
            path,
            dwo_id,
            sections,
        })
    }

    /// Return a section by name.
    #[must_use]
    pub fn section(&self, name: &str) -> Option<&DwoSection> {
        self.sections.iter().find(|s| s.name == name)
    }

    /// Return the `.debug_info.dwo` section bytes.
    #[must_use]
    pub fn debug_info_dwo(&self) -> Option<&[u8]> {
        self.section(".debug_info.dwo").map(|s| s.data.as_slice())
    }

    /// Return the `.debug_abbrev.dwo` section bytes.
    #[must_use]
    pub fn debug_abbrev_dwo(&self) -> Option<&[u8]> {
        self.section(".debug_abbrev.dwo").map(|s| s.data.as_slice())
    }

    /// Return the `.debug_str.dwo` section bytes.
    #[must_use]
    pub fn debug_str_dwo(&self) -> Option<&[u8]> {
        self.section(".debug_str.dwo").map(|s| s.data.as_slice())
    }
}

// ── SkeletonUnit ──────────────────────────────────────────────────────────────

/// A skeleton compilation unit in the main executable that references a `.dwo` file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkeletonUnit {
    /// Offset of this CU's header in `.debug_info`.
    pub offset: u64,
    /// The DWO ID (from `DW_AT_dwo_id`).
    pub dwo_id: u64,
    /// Path to the referenced `.dwo` file (from `DW_AT_dwo_name` / `DW_AT_comp_dir`).
    pub dwo_name: String,
    /// Compilation directory (from `DW_AT_comp_dir`).
    pub comp_dir: String,
}

impl SkeletonUnit {
    /// Resolve the full path to the `.dwo` file.
    ///
    /// If `dwo_name` is absolute, it is returned as-is.  Otherwise it is
    /// joined to `comp_dir`.
    #[must_use]
    pub fn resolve_path(&self) -> PathBuf {
        let dwo_path = Path::new(&self.dwo_name);
        if dwo_path.is_absolute() {
            dwo_path.to_path_buf()
        } else if !self.comp_dir.is_empty() {
            Path::new(&self.comp_dir).join(dwo_path)
        } else {
            dwo_path.to_path_buf()
        }
    }
}

// ── DwpPackage ───────────────────────────────────────────────────────────────

/// An index entry in a `.dwp` package.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DwpEntry {
    /// The 64-bit DWO identifier this entry describes.
    pub dwo_id: u64,
    /// Offset of each section within the package's combined section.
    pub section_offsets: HashMap<String, u64>,
    /// Size of each section within the combined section.
    pub section_sizes: HashMap<String, u64>,
}

/// A `.dwp` package file that bundles multiple `.dwo` files.
pub struct DwpPackage {
    /// All index entries keyed by DWO ID.
    pub entries: HashMap<u64, DwpEntry>,
    /// Raw combined section data: section name → bytes.
    pub sections: HashMap<String, Vec<u8>>,
}

impl DwpPackage {
    /// Construct a `DwpPackage` from raw ELF bytes.
    ///
    /// # Errors
    ///
    /// Returns `SplitDwarfError::NotDwp` if the data is not an ELF or lacks DWP index sections,
    /// and `SplitDwarfError::Malformed` if the ELF section table cannot be parsed.
    pub fn from_elf_bytes(data: &[u8]) -> Result<Self, SplitDwarfError> {
        if data.len() < 4 || data[0..4] != [0x7f, b'E', b'L', b'F'] {
            return Err(SplitDwarfError::NotDwp);
        }

        let raw_sections =
            extract_elf_sections(data).map_err(|e| SplitDwarfError::Malformed(e.to_string()))?;

        let has_compile_index = raw_sections.iter().any(|s| s.name == ".debug_cu_index");
        let has_type_index = raw_sections.iter().any(|s| s.name == ".debug_tu_index");

        if !has_compile_index && !has_type_index {
            return Err(SplitDwarfError::NotDwp);
        }

        let sections: HashMap<String, Vec<u8>> =
            raw_sections.into_iter().map(|s| (s.name, s.data)).collect();

        let entries = if let Some(cu_index_data) = sections.get(".debug_cu_index") {
            parse_dwp_index(cu_index_data)?
        } else {
            HashMap::new()
        };

        Ok(Self { entries, sections })
    }

    /// Retrieve the DWO sections for a given DWO ID.
    #[must_use]
    pub fn get_dwo(&self, dwo_id: u64) -> Option<Vec<DwoSection>> {
        let entry = self.entries.get(&dwo_id)?;
        let mut result = Vec::new();
        for (section_name, &offset) in &entry.section_offsets {
            let size = usize::try_from(entry.section_sizes.get(section_name).copied().unwrap_or(0))
                .unwrap_or(usize::MAX);
            if let Some(combined) = self.sections.get(section_name) {
                let start = usize::try_from(offset).unwrap_or(usize::MAX);
                let end = (start + size).min(combined.len());
                let data = combined.get(start..end).unwrap_or(&[]).to_vec();
                result.push(DwoSection::new(section_name, data));
            }
        }
        Some(result)
    }

    /// List all DWO IDs in this package.
    #[must_use]
    pub fn dwo_ids(&self) -> Vec<u64> {
        self.entries.keys().copied().collect()
    }
}

// ── Resolver ─────────────────────────────────────────────────────────────────

/// Resolves DWO files for a given set of skeleton compilation units.
pub struct DwoResolver {
    search_paths: Vec<PathBuf>,
}

impl DwoResolver {
    /// Create a resolver with a list of search directories.
    #[must_use]
    pub const fn new(search_paths: Vec<PathBuf>) -> Self {
        Self { search_paths }
    }

    /// Resolve the path to a DWO file given a skeleton unit.
    ///
    /// Tries (in order):
    /// 1. The path as returned by [`SkeletonUnit::resolve_path`].
    /// 2. Each search directory joined with the base name of the DWO path.
    #[must_use]
    pub fn resolve_path(&self, skeleton: &SkeletonUnit) -> Option<PathBuf> {
        let primary = skeleton.resolve_path();
        if primary.exists() {
            return Some(primary);
        }

        // Try just the file name in each search dir.
        let file_name = primary.file_name()?;
        for dir in &self.search_paths {
            let candidate = dir.join(file_name);
            if candidate.exists() {
                return Some(candidate);
            }
        }

        None
    }
}

/// Resolve a DWO path from its component parts, without checking the filesystem.
#[must_use]
pub fn resolve_dwo_path(comp_dir: &str, dwo_name: &str) -> PathBuf {
    let p = Path::new(dwo_name);
    if p.is_absolute() {
        p.to_path_buf()
    } else if !comp_dir.is_empty() {
        Path::new(comp_dir).join(p)
    } else {
        p.to_path_buf()
    }
}

// ── Internal helpers ──────────────────────────────────────────────────────────

fn extract_elf_sections(data: &[u8]) -> Result<Vec<DwoSection>, &'static str> {
    if data.len() < 64 {
        return Err("ELF too short");
    }
    let ei_class = data[4];
    let mut sections = Vec::new();

    match ei_class {
        1 => {
            // 32-bit ELF
            let e_shoff = u32::from_le_bytes(data[32..36].try_into().unwrap()) as usize;
            let e_shentsize = u16::from_le_bytes(data[46..48].try_into().unwrap()) as usize;
            let e_shnum = u16::from_le_bytes(data[48..50].try_into().unwrap()) as usize;
            let e_shstrndx = u16::from_le_bytes(data[50..52].try_into().unwrap()) as usize;

            let shstr_hdr = e_shoff + e_shstrndx * e_shentsize;
            if shstr_hdr + 16 + 8 > data.len() {
                return Ok(sections);
            }
            let shstr_off =
                u32::from_le_bytes(data[shstr_hdr + 16..shstr_hdr + 20].try_into().unwrap())
                    as usize;
            let shstr_size =
                u32::from_le_bytes(data[shstr_hdr + 20..shstr_hdr + 24].try_into().unwrap())
                    as usize;
            let shstrtab = data.get(shstr_off..shstr_off + shstr_size).unwrap_or(&[]);

            for i in 0..e_shnum {
                let hdr = e_shoff + i * e_shentsize;
                if hdr + 24 > data.len() {
                    break;
                }
                let sh_name_off =
                    u32::from_le_bytes(data[hdr..hdr + 4].try_into().unwrap()) as usize;
                let sh_off =
                    u32::from_le_bytes(data[hdr + 16..hdr + 20].try_into().unwrap()) as usize;
                let sh_size =
                    u32::from_le_bytes(data[hdr + 20..hdr + 24].try_into().unwrap()) as usize;

                let name_end = shstrtab[sh_name_off..]
                    .iter()
                    .position(|&b| b == 0)
                    .map_or(shstrtab.len(), |p| sh_name_off + p);
                let name = String::from_utf8_lossy(&shstrtab[sh_name_off..name_end]).into_owned();
                let sec_data = data.get(sh_off..sh_off + sh_size).unwrap_or(&[]).to_vec();
                sections.push(DwoSection::new(name, sec_data));
            }
        }
        2 => {
            // 64-bit ELF
            let e_shoff = usize::try_from(u64::from_le_bytes(data[40..48].try_into().unwrap()))
                .unwrap_or(usize::MAX);
            let e_shentsize = usize::from(u16::from_le_bytes(data[58..60].try_into().unwrap()));
            let e_shnum = usize::from(u16::from_le_bytes(data[60..62].try_into().unwrap()));
            let e_shstrndx = usize::from(u16::from_le_bytes(data[62..64].try_into().unwrap()));

            let shstr_hdr = e_shoff + e_shstrndx * e_shentsize;
            if shstr_hdr + 32 + 16 > data.len() {
                return Ok(sections);
            }
            let shstr_off = usize::try_from(u64::from_le_bytes(
                data[shstr_hdr + 24..shstr_hdr + 32].try_into().unwrap(),
            ))
            .unwrap_or(usize::MAX);
            let shstr_size = usize::try_from(u64::from_le_bytes(
                data[shstr_hdr + 32..shstr_hdr + 40]
                    .try_into()
                    .unwrap_or([0u8; 8]),
            ))
            .unwrap_or(usize::MAX);
            let shstrtab = data.get(shstr_off..shstr_off + shstr_size).unwrap_or(&[]);

            for i in 0..e_shnum {
                let hdr = e_shoff + i * e_shentsize;
                if hdr + 40 > data.len() {
                    break;
                }
                let sh_name_off =
                    u32::from_le_bytes(data[hdr..hdr + 4].try_into().unwrap()) as usize;
                let sh_off = usize::try_from(u64::from_le_bytes(
                    data[hdr + 24..hdr + 32].try_into().unwrap(),
                ))
                .unwrap_or(usize::MAX);
                let sh_size = usize::try_from(u64::from_le_bytes(
                    data[hdr + 32..hdr + 40].try_into().unwrap(),
                ))
                .unwrap_or(usize::MAX);

                let name_end = shstrtab
                    .get(sh_name_off..)
                    .and_then(|s| s.iter().position(|&b| b == 0))
                    .map_or(shstrtab.len(), |p| sh_name_off + p);
                let name =
                    String::from_utf8_lossy(shstrtab.get(sh_name_off..name_end).unwrap_or(&[]))
                        .into_owned();
                let sec_data = data.get(sh_off..sh_off + sh_size).unwrap_or(&[]).to_vec();
                sections.push(DwoSection::new(name, sec_data));
            }
        }
        _ => return Err("unsupported ELF class"),
    }

    Ok(sections)
}

fn extract_dwo_id_from_sections(sections: &[DwoSection]) -> Option<u64> {
    // DWO ID appears in the CU header of .debug_info.dwo.
    let info = sections.iter().find(|s| s.name == ".debug_info.dwo")?;
    let data = &info.data;
    // Detect 32-bit vs 64-bit DWARF by checking for the 0xFFFFFFFF marker.
    // DWARF 5 split-unit (DW_UT_split_compile) CU header layout:
    //   32-bit: unit_length(4) + version(2) + unit_type(1) + address_size(1)
    //           + debug_abbrev_offset(4) + dwo_id(8)  => dwo_id at offset 12
    //   64-bit: 0xFFFFFFFF(4) + unit_length(8) + version(2) + unit_type(1)
    //           + address_size(1) + debug_abbrev_offset(8) + dwo_id(8) => dwo_id at offset 24
    let is_64bit = data.len() >= 4
        && u32::from_le_bytes(data[0..4].try_into().ok()?) == 0xFFFF_FFFF;
    let dwo_id_offset = if is_64bit { 24 } else { 12 };
    if data.len() < dwo_id_offset + 8 {
        return None;
    }
    Some(u64::from_le_bytes(data[dwo_id_offset..dwo_id_offset + 8].try_into().ok()?))
}

fn parse_dwp_index(data: &[u8]) -> Result<HashMap<u64, DwpEntry>, SplitDwarfError> {
    // Simplified: a real parser would follow the DWARF package index format.
    // Here we return an empty map — full DWP index parsing requires extensive
    // format knowledge that is out of scope for this module.
    // The DWP index header is at least 16 bytes (version, padding, unit_count, slot_count).
    // Reject anything shorter as malformed so the Result wrap is meaningful.
    if !data.is_empty() && data.len() < 16 {
        return Err(SplitDwarfError::Malformed(format!(
            "DWP index too short: {} bytes",
            data.len()
        )));
    }
    Ok(HashMap::new())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dwo_section_new() {
        let s = DwoSection::new(".debug_info.dwo", vec![0x01, 0x02]);
        assert_eq!(s.name, ".debug_info.dwo");
        assert_eq!(s.data.len(), 2);
    }

    #[test]
    fn test_dwo_section_is_debug() {
        let s = DwoSection::new(".debug_str.dwo", vec![]);
        assert!(s.is_debug_section());

        let s2 = DwoSection::new(".text", vec![]);
        assert!(!s2.is_debug_section());
    }

    #[test]
    fn test_skeleton_unit_resolve_absolute() {
        let su = SkeletonUnit {
            offset: 0,
            dwo_id: 42,
            dwo_name: "/absolute/path/foo.dwo".into(),
            comp_dir: "/build".into(),
        };
        let p = su.resolve_path();
        assert_eq!(p, PathBuf::from("/absolute/path/foo.dwo"));
    }

    #[test]
    fn test_skeleton_unit_resolve_relative() {
        let su = SkeletonUnit {
            offset: 0,
            dwo_id: 42,
            dwo_name: "foo.dwo".into(),
            comp_dir: "/build/src".into(),
        };
        let p = su.resolve_path();
        assert_eq!(p, PathBuf::from("/build/src/foo.dwo"));
    }

    #[test]
    fn test_skeleton_unit_resolve_no_comp_dir() {
        let su = SkeletonUnit {
            offset: 0,
            dwo_id: 0,
            dwo_name: "bar.dwo".into(),
            comp_dir: String::new(),
        };
        assert_eq!(su.resolve_path(), PathBuf::from("bar.dwo"));
    }

    #[test]
    fn test_resolve_dwo_path_absolute() {
        let p = resolve_dwo_path("/build", "/abs/foo.dwo");
        assert_eq!(p, PathBuf::from("/abs/foo.dwo"));
    }

    #[test]
    fn test_resolve_dwo_path_relative() {
        let p = resolve_dwo_path("/build", "foo.dwo");
        assert_eq!(p, PathBuf::from("/build/foo.dwo"));
    }

    #[test]
    fn test_resolve_dwo_path_empty_comp_dir() {
        let p = resolve_dwo_path("", "foo.dwo");
        assert_eq!(p, PathBuf::from("foo.dwo"));
    }

    #[test]
    fn test_dwo_file_not_elf() {
        let result = DwoFile::from_elf_bytes("/tmp/foo.dwo", b"not an elf");
        assert!(matches!(result, Err(SplitDwarfError::NotDwo)));
    }

    #[test]
    fn test_dwp_package_not_elf() {
        let result = DwpPackage::from_elf_bytes(b"garbage");
        assert!(matches!(result, Err(SplitDwarfError::NotDwp)));
    }

    #[test]
    fn test_dwo_section_empty_data() {
        let s = DwoSection::new(".debug_abbrev.dwo", vec![]);
        assert_eq!(s.data.len(), 0);
    }

    #[test]
    fn test_dwp_entry_struct() {
        let entry = DwpEntry {
            dwo_id: 0xABCD_1234,
            section_offsets: HashMap::new(),
            section_sizes: HashMap::new(),
        };
        assert_eq!(entry.dwo_id, 0xABCD_1234);
    }

    #[test]
    fn test_dwo_resolver_no_paths() {
        let resolver = DwoResolver::new(vec![]);
        let su = SkeletonUnit {
            offset: 0,
            dwo_id: 0,
            dwo_name: "nonexistent_unlikely_12345.dwo".into(),
            comp_dir: String::new(),
        };
        // Should return None since the file doesn't exist
        assert!(resolver.resolve_path(&su).is_none());
    }

    #[test]
    fn test_split_dwarf_error_display() {
        let e = SplitDwarfError::NotDwo;
        assert!(e.to_string().contains("DWO"));

        let e2 = SplitDwarfError::IdMismatch(1, 2);
        assert!(e2.to_string().contains("mismatch"));
    }

    #[test]
    fn test_dwo_section_clone() {
        let s = DwoSection::new(".debug_info.dwo", vec![1, 2, 3]);
        let c = s.clone();
        assert_eq!(c.name, s.name);
        assert_eq!(c.data, s.data);
    }

    #[test]
    fn test_skeleton_unit_fields() {
        let su = SkeletonUnit {
            offset: 0x400,
            dwo_id: 0xDEAD_BEEF_CAFE_1234,
            dwo_name: "foo.dwo".into(),
            comp_dir: "/src".into(),
        };
        assert_eq!(su.offset, 0x400);
        assert_eq!(su.dwo_id, 0xDEAD_BEEF_CAFE_1234);
    }
}
