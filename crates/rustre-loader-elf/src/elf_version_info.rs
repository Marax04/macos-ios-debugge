//! ELF version information — mid-level aggregator.
//!
//! **Layer:** sits above [`crate::versioning`] (the raw byte-level parsers)
//! and below [`crate::elf_version_script`] (the high-level analysis
//! utilities).  This module owns the [`ElfVersionInfo`] aggregate that
//! combines all three GNU version sections into a single value with a
//! pre-built `index → name` map, and the [`parse_version_info`] entry
//! point that drives the three low-level parsers.
//!
//! The per-record types (`VerSym`, `VerNeed`, `VerDef`, `VersionNeed`) are
//! intentionally distinct from the identically-named types in
//! `crate::versioning`: they carry richer fields (e.g. the `hidden` bit in
//! `VerSym`, the `version` wire field in `VersionNeed`) and use a different
//! parsing strategy (count-driven rather than next-pointer-driven).
//!
//! References:
//!   - ELF-64 Object File Format, §4 — Symbol Versioning
//!   - GNU ELF extensions: `SHT_GNU_versym`, `SHT_GNU_verneed`, `SHT_GNU_verdef`

use std::collections::HashMap;

// ---------------------------------------------------------------------------
// Section type constants
// ---------------------------------------------------------------------------

/// Section type for `.gnu.version` (`Elfxx_Half` array of symbol version indices).
pub const SHT_GNU_VERSYM: u32 = 0x6FFF_FFFF;
/// Section type for `.gnu.version_r` (Version Needs).
pub const SHT_GNU_VERNEED: u32 = 0x6FFF_FFFE;
/// Section type for `.gnu.version_d` (Version Definitions).
pub const SHT_GNU_VERDEF: u32 = 0x6FFF_FFFD;

/// The special version index meaning "global" (`VER_NDX_GLOBAL`).
pub const VER_NDX_GLOBAL: u16 = 1;
/// The special version index meaning "local" (`VER_NDX_LOCAL`).
pub const VER_NDX_LOCAL: u16 = 0;
/// Bit mask applied to version symbol index to strip the hidden flag.
pub const VERSYM_HIDDEN_MASK: u16 = 0x8000;

// ---------------------------------------------------------------------------
// VerSym — one entry from .gnu.version
// ---------------------------------------------------------------------------

/// A single entry from the `.gnu.version` (`.gnu_version`) section.
///
/// Each `Elfxx_Half` in the section corresponds to the symbol at the same
/// index in the dynamic symbol table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerSym {
    /// Symbol table index this entry belongs to.
    pub sym_index: usize,
    /// Raw version index value (may have the hidden bit set in the high bit).
    pub version_index: u16,
    /// `true` when the hidden bit (bit 15) is set — symbol is not exported.
    pub hidden: bool,
    /// Effective version index (hidden bit masked out).
    pub effective_index: u16,
}

impl VerSym {
    /// Parse all version symbol entries from `.gnu.version` section bytes.
    #[must_use] 
    pub fn parse_all(data: &[u8]) -> Vec<Self> {
        Self::parse_all_endian(data, true)
    }

    /// Endianness-aware variant of [`VerSym::parse_all`]; pass `le = false` for
    /// big-endian ELF objects.
    #[must_use]
    pub fn parse_all_endian(data: &[u8], le: bool) -> Vec<Self> {
        let count = data.len() / 2;
        let mut out = Vec::with_capacity(count);
        for i in 0..count {
            let off = i * 2;
            let b = [data[off], data[off + 1]];
            let raw = if le {
                u16::from_le_bytes(b)
            } else {
                u16::from_be_bytes(b)
            };
            out.push(Self {
                sym_index: i,
                version_index: raw,
                hidden: (raw & VERSYM_HIDDEN_MASK) != 0,
                effective_index: raw & !VERSYM_HIDDEN_MASK,
            });
        }
        out
    }
}

// ---------------------------------------------------------------------------
// VerNeedAux — auxiliary record within a VersionNeed entry
// ---------------------------------------------------------------------------

/// One auxiliary record inside a `Verneed` entry; describes one required version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerNeed {
    /// Version hash (ELF hash of `name`).
    pub hash: u32,
    /// Flags (`VER_FLG_WEAK` etc.).
    pub flags: u16,
    /// Version index assigned to this requirement.
    pub other: u16,
    /// Version string (e.g. `"GLIBC_2.17"`).
    pub name: String,
}

impl VerNeed {
    /// Returns `true` if the `VER_FLG_WEAK` flag is set.
    #[must_use] 
    pub const fn is_weak(&self) -> bool {
        self.flags & 0x02 != 0
    }
}

// ---------------------------------------------------------------------------
// VersionNeed
// ---------------------------------------------------------------------------

/// One `Verneed` entry from `.gnu.version_r` listing requirements from a dylib.
#[derive(Debug, Clone)]
pub struct VersionNeed {
    /// ELF version of the Verneed structure (always 1).
    pub version: u16,
    /// Name of the dependency library providing these versions.
    pub file: String,
    /// Individual version requirements.
    pub auxiliaries: Vec<VerNeed>,
}

// ---------------------------------------------------------------------------
// VerDef — one version definition from .gnu.version_d
// ---------------------------------------------------------------------------

/// One auxiliary name record within a `VerDef` entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerDefAux {
    /// Version name (e.g. `"libfoo.so.1"` or `"FOO_1.0"`).
    pub name: String,
}

/// One version definition entry from `.gnu.version_d`.
#[derive(Debug, Clone)]
pub struct VerDef {
    /// ELF version of the Verdef structure (always 1).
    pub version: u16,
    /// Flags (`VER_FLG_BASE`, `VER_FLG_WEAK`).
    pub flags: u16,
    /// Version index (matches indices in `.gnu.version`).
    pub ndx: u16,
    /// ELF hash of the primary version name.
    pub hash: u32,
    /// Auxiliary name records (first is the version name, rest are dependencies).
    pub auxiliaries: Vec<VerDefAux>,
}

impl VerDef {
    /// Returns `true` if the `VER_FLG_BASE` flag is set (base definition).
    #[must_use] 
    pub const fn is_base(&self) -> bool {
        self.flags & 0x01 != 0
    }

    /// Returns the primary version name (first aux entry).
    #[must_use] 
    pub fn primary_name(&self) -> Option<&str> {
        self.auxiliaries.first().map(|a| a.name.as_str())
    }
}

// ---------------------------------------------------------------------------
// ElfVersionInfo
// ---------------------------------------------------------------------------

/// Parsed ELF version information from all three version sections.
#[derive(Debug, Clone, Default)]
pub struct ElfVersionInfo {
    /// Per-symbol version indices from `.gnu.version`.
    pub versyms: Vec<VerSym>,
    /// Version needs from `.gnu.version_r`.
    pub verneed: Vec<VersionNeed>,
    /// Version definitions from `.gnu.version_d`.
    pub verdef: Vec<VerDef>,
    /// Map from version index → name (built from verneed + verdef).
    pub index_to_name: HashMap<u16, String>,
}

impl ElfVersionInfo {
    /// Returns the version name for a symbol's version index, if known.
    pub fn version_name_for_sym(&self, sym_index: usize) -> Option<&str> {
        let vs = self.versyms.get(sym_index)?;
        if vs.effective_index <= VER_NDX_GLOBAL {
            return None; // global/local — no version string
        }
        self.index_to_name.get(&vs.effective_index).map(String::as_str)
    }

    /// Returns `true` if a given symbol index is versioned (not local/global).
    #[must_use] 
    pub fn is_versioned(&self, sym_index: usize) -> bool {
        self.versyms
            .get(sym_index)
            .is_some_and(|v| v.effective_index > VER_NDX_GLOBAL)
    }

    /// Returns all required version names gathered from `.gnu.version_r`.
    #[must_use] 
    pub fn required_versions(&self) -> Vec<&str> {
        let mut names = Vec::new();
        for vn in &self.verneed {
            for aux in &vn.auxiliaries {
                names.push(aux.name.as_str());
            }
        }
        names
    }

    /// Returns all defined version names from `.gnu.version_d`.
    #[must_use] 
    pub fn defined_versions(&self) -> Vec<&str> {
        self.verdef
            .iter()
            .filter_map(|vd| vd.primary_name())
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Low-level parser helpers
// ---------------------------------------------------------------------------

fn read_u16(data: &[u8], off: usize, le: bool) -> Option<u16> {
    let b: [u8; 2] = data.get(off..off + 2)?.try_into().ok()?;
    Some(if le {
        u16::from_le_bytes(b)
    } else {
        u16::from_be_bytes(b)
    })
}

fn read_u32(data: &[u8], off: usize, le: bool) -> Option<u32> {
    let b: [u8; 4] = data.get(off..off + 4)?.try_into().ok()?;
    Some(if le {
        u32::from_le_bytes(b)
    } else {
        u32::from_be_bytes(b)
    })
}

/// Read a NUL-terminated string from `data` starting at `off` (relative to section start).
fn read_cstr(data: &[u8], off: usize) -> String {
    if off >= data.len() {
        return String::new();
    }
    let slice = &data[off..];
    let end = slice.iter().position(|&b| b == 0).unwrap_or(slice.len());
    String::from_utf8_lossy(&slice[..end]).into_owned()
}

// ---------------------------------------------------------------------------
// Verneed parser
// ---------------------------------------------------------------------------

/// Parse `.gnu.version_r` section bytes into a list of [`VersionNeed`] entries.
///
/// * `data`    — raw bytes of the `.gnu.version_r` section
/// * `dynstr`  — raw bytes of `.dynstr` (for string resolution)
/// * `count`   — number of `Verneed` entries (from section `sh_info`)
#[must_use] 
pub fn parse_verneed(data: &[u8], dynstr: &[u8], count: usize) -> Vec<VersionNeed> {
    parse_verneed_endian(data, dynstr, count, true)
}

/// Endianness-aware variant of [`parse_verneed`]; pass `le = false` for
/// big-endian ELF objects.
#[must_use]
pub fn parse_verneed_endian(
    data: &[u8],
    dynstr: &[u8],
    count: usize,
    le: bool,
) -> Vec<VersionNeed> {
    let mut result = Vec::new();
    let mut offset = 0usize;

    for _ in 0..count {
        if offset + 16 > data.len() {
            break;
        }
        // Verneed structure (16 bytes):
        //   vn_version: u16
        //   vn_cnt:     u16
        //   vn_file:    u32  (index into dynstr)
        //   vn_aux:     u32  (byte offset from start of this record to first aux)
        //   vn_next:    u32  (byte offset to next Verneed, 0 = last)
        let vn_version = read_u16(data, offset, le).unwrap_or(0);
        let vn_cnt     = read_u16(data, offset + 2, le).unwrap_or(0);
        let vn_file    = read_u32(data, offset + 4, le).unwrap_or(0);
        let vn_aux     = read_u32(data, offset + 8, le).unwrap_or(0);
        let vn_next    = read_u32(data, offset + 12, le).unwrap_or(0);

        let file = read_cstr(dynstr, vn_file as usize);

        // Parse auxiliary entries (Vernaux, 16 bytes each)
        let mut auxiliaries = Vec::new();
        let mut aux_off = offset + vn_aux as usize;
        for _ in 0..vn_cnt {
            if aux_off + 16 > data.len() {
                break;
            }
            // Vernaux:
            //   vna_hash:  u32
            //   vna_flags: u16
            //   vna_other: u16
            //   vna_name:  u32 (index into dynstr)
            //   vna_next:  u32
            let hash  = read_u32(data, aux_off, le).unwrap_or(0);
            let flags = read_u16(data, aux_off + 4, le).unwrap_or(0);
            let other = read_u16(data, aux_off + 6, le).unwrap_or(0);
            let name_idx = read_u32(data, aux_off + 8, le).unwrap_or(0);
            let aux_next = read_u32(data, aux_off + 12, le).unwrap_or(0);
            let name = read_cstr(dynstr, name_idx as usize);
            auxiliaries.push(VerNeed { hash, flags, other, name });
            if aux_next == 0 {
                break;
            }
            aux_off += aux_next as usize;
        }

        result.push(VersionNeed {
            version: vn_version,
            file,
            auxiliaries,
        });

        if vn_next == 0 {
            break;
        }
        offset += vn_next as usize;
    }

    result
}

// ---------------------------------------------------------------------------
// Verdef parser
// ---------------------------------------------------------------------------

/// Parse `.gnu.version_d` section bytes into a list of [`VerDef`] entries.
///
/// * `data`    — raw bytes of the `.gnu.version_d` section
/// * `dynstr`  — raw bytes of `.dynstr` (for string resolution)
/// * `count`   — number of `Verdef` entries (from section `sh_info`)
#[must_use] 
pub fn parse_verdef(data: &[u8], dynstr: &[u8], count: usize) -> Vec<VerDef> {
    parse_verdef_endian(data, dynstr, count, true)
}

/// Endianness-aware variant of [`parse_verdef`]; pass `le = false` for
/// big-endian ELF objects.
#[must_use]
pub fn parse_verdef_endian(data: &[u8], dynstr: &[u8], count: usize, le: bool) -> Vec<VerDef> {
    let mut result = Vec::new();
    let mut offset = 0usize;

    for _ in 0..count {
        if offset + 20 > data.len() {
            break;
        }
        // Verdef structure (20 bytes):
        //   vd_version: u16
        //   vd_flags:   u16
        //   vd_ndx:     u16
        //   vd_cnt:     u16   (number of Verdaux entries)
        //   vd_hash:    u32
        //   vd_aux:     u32   (offset to first Verdaux)
        //   vd_next:    u32
        let vd_version = read_u16(data, offset, le).unwrap_or(0);
        let vd_flags   = read_u16(data, offset + 2, le).unwrap_or(0);
        let vd_ndx     = read_u16(data, offset + 4, le).unwrap_or(0);
        let vd_cnt     = read_u16(data, offset + 6, le).unwrap_or(0);
        let vd_hash    = read_u32(data, offset + 8, le).unwrap_or(0);
        let vd_aux     = read_u32(data, offset + 12, le).unwrap_or(0);
        let vd_next    = read_u32(data, offset + 16, le).unwrap_or(0);

        // Parse Verdaux entries (8 bytes each):
        //   vda_name: u32 (index into dynstr)
        //   vda_next: u32
        let mut auxiliaries = Vec::new();
        let mut aux_off = offset + vd_aux as usize;
        for _ in 0..vd_cnt {
            if aux_off + 8 > data.len() {
                break;
            }
            let name_idx = read_u32(data, aux_off, le).unwrap_or(0);
            let aux_next = read_u32(data, aux_off + 4, le).unwrap_or(0);
            auxiliaries.push(VerDefAux { name: read_cstr(dynstr, name_idx as usize) });
            if aux_next == 0 {
                break;
            }
            aux_off += aux_next as usize;
        }

        result.push(VerDef {
            version: vd_version,
            flags: vd_flags,
            ndx: vd_ndx,
            hash: vd_hash,
            auxiliaries,
        });

        if vd_next == 0 {
            break;
        }
        offset += vd_next as usize;
    }

    result
}

// ---------------------------------------------------------------------------
// Top-level parse function
// ---------------------------------------------------------------------------

/// Parse all ELF version information from raw section bytes.
///
/// Parameters:
/// * `versym_data`  — raw bytes of `.gnu.version` (may be empty)
/// * `verneed_data` — raw bytes of `.gnu.version_r` (may be empty)
/// * `verdef_data`  — raw bytes of `.gnu.version_d` (may be empty)
/// * `dynstr`       — raw bytes of `.dynstr`
/// * `verneed_count` — number of `Verneed` entries (from `sh_info` field)
/// * `verdef_count`  — number of `Verdef` entries (from `sh_info` field)
#[must_use] 
pub fn parse_version_info(
    versym_data:   &[u8],
    verneed_data:  &[u8],
    verdef_data:   &[u8],
    dynstr:        &[u8],
    verneed_count: usize,
    verdef_count:  usize,
) -> ElfVersionInfo {
    parse_version_info_endian(
        &VersionSections {
            versym_data,
            verneed_data,
            verdef_data,
            dynstr,
            verneed_count,
            verdef_count,
        },
        true,
    )
}

/// The four `.gnu.version*` sections a version-info parse reads, plus the entry
/// counts the dynamic table reports for two of them.
///
/// ⚠ Introduced because `parse_version_info_endian` took these six separately
/// and needed an `#[allow(clippy::too_many_arguments)]`. Four consecutive
/// `&[u8]` parameters is precisely the signature where swapping `verneed_data`
/// and `verdef_data` compiles and yields a plausible-looking wrong answer:
/// both are `Elf_Verdaux`-shaped records read against the same `dynstr`.
/// Named fields make the swap impossible to write.
#[derive(Debug, Clone, Copy)]
pub struct VersionSections<'a> {
    /// `.gnu.version` — one `Elf_Versym` per dynamic symbol.
    pub versym_data: &'a [u8],
    /// `.gnu.version_r` — version requirements.
    pub verneed_data: &'a [u8],
    /// `.gnu.version_d` — version definitions.
    pub verdef_data: &'a [u8],
    /// `.dynstr`, against which every name offset above is resolved.
    pub dynstr: &'a [u8],
    /// `DT_VERNEEDNUM`.
    pub verneed_count: usize,
    /// `DT_VERDEFNUM`.
    pub verdef_count: usize,
}

/// Endianness-aware variant of [`parse_version_info`]; pass `le = false` for
/// big-endian ELF objects (the `le` flag comes from `EI_DATA` in the header).
#[must_use]
pub fn parse_version_info_endian(secs: &VersionSections<'_>, le: bool) -> ElfVersionInfo {
    let VersionSections {
        versym_data,
        verneed_data,
        verdef_data,
        dynstr,
        verneed_count,
        verdef_count,
    } = *secs;
    let versyms = VerSym::parse_all_endian(versym_data, le);
    let verneed = parse_verneed_endian(verneed_data, dynstr, verneed_count, le);
    let verdef  = parse_verdef_endian(verdef_data, dynstr, verdef_count, le);

    // Build index → name map from version needs
    let mut index_to_name: HashMap<u16, String> = HashMap::new();
    for vn in &verneed {
        for aux in &vn.auxiliaries {
            if aux.other > VER_NDX_GLOBAL {
                index_to_name.insert(aux.other, aux.name.clone());
            }
        }
    }
    // Also insert from version definitions
    for vd in &verdef {
        if let Some(name) = vd.primary_name()
            && vd.ndx > VER_NDX_GLOBAL {
                index_to_name.entry(vd.ndx).or_insert_with(|| name.to_owned());
            }
    }

    ElfVersionInfo { versyms, verneed, verdef, index_to_name }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // Build a minimal dynstr containing NUL-separated strings.
    fn _make_dynstr(strings: &[&str]) -> Vec<u8> {
        let mut out = vec![0u8]; // index 0 = empty string
        for s in strings {
            out.extend_from_slice(s.as_bytes());
            out.push(0);
        }
        out
    }

    #[test]
    fn test_versym_parse_empty() {
        let v = VerSym::parse_all(&[]);
        assert!(v.is_empty());
    }

    #[test]
    fn test_versym_parse_single_global() {
        let data: Vec<u8> = 1u16.to_le_bytes().to_vec();
        let v = VerSym::parse_all(&data);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].effective_index, VER_NDX_GLOBAL);
        assert!(!v[0].hidden);
    }

    #[test]
    fn test_versym_parse_hidden() {
        let raw: u16 = 0x8003; // hidden bit set, effective = 3
        let data = raw.to_le_bytes().to_vec();
        let v = VerSym::parse_all(&data);
        assert!(v[0].hidden);
        assert_eq!(v[0].effective_index, 3);
    }

    #[test]
    fn test_versym_parse_multiple() {
        let mut data = Vec::new();
        for i in 0u16..4 {
            data.extend_from_slice(&i.to_le_bytes());
        }
        let v = VerSym::parse_all(&data);
        assert_eq!(v.len(), 4);
        for (i, vs) in v.iter().enumerate() {
            assert_eq!(vs.sym_index, i);
            assert_eq!(vs.effective_index, i as u16);
        }
    }

    #[test]
    fn test_parse_verneed_empty() {
        let v = parse_verneed(&[], &[], 0);
        assert!(v.is_empty());
    }

    #[test]
    fn test_parse_verneed_single() {
        // dynstr: "\0GLIBC_2.17\0libc.so.6\0"
        let mut dynstr = vec![0u8];
        let glibc_off = dynstr.len();
        dynstr.extend_from_slice(b"GLIBC_2.17\0");
        let libc_off = dynstr.len();
        dynstr.extend_from_slice(b"libc.so.6\0");

        // Build verneed record (16 bytes) + vernaux (16 bytes)
        let mut data = vec![0u8; 32];
        // Verneed
        data[0..2].copy_from_slice(&1u16.to_le_bytes());  // vn_version
        data[2..4].copy_from_slice(&1u16.to_le_bytes());  // vn_cnt
        data[4..8].copy_from_slice(&(libc_off as u32).to_le_bytes()); // vn_file
        data[8..12].copy_from_slice(&16u32.to_le_bytes()); // vn_aux = 16 (right after this record)
        data[12..16].copy_from_slice(&0u32.to_le_bytes()); // vn_next = 0 (last)
        // Vernaux at offset 16
        let aux = &mut data[16..32];
        aux[0..4].copy_from_slice(&0xDEAD_BEEFu32.to_le_bytes()); // vna_hash
        aux[4..6].copy_from_slice(&0u16.to_le_bytes());             // vna_flags
        aux[6..8].copy_from_slice(&2u16.to_le_bytes());             // vna_other (version index 2)
        aux[8..12].copy_from_slice(&(glibc_off as u32).to_le_bytes()); // vna_name
        aux[12..16].copy_from_slice(&0u32.to_le_bytes());           // vna_next

        let result = parse_verneed(&data, &dynstr, 1);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].file, "libc.so.6");
        assert_eq!(result[0].auxiliaries.len(), 1);
        assert_eq!(result[0].auxiliaries[0].name, "GLIBC_2.17");
        assert_eq!(result[0].auxiliaries[0].other, 2);
    }

    #[test]
    fn test_parse_verdef_empty() {
        let v = parse_verdef(&[], &[], 0);
        assert!(v.is_empty());
    }

    #[test]
    fn test_parse_verdef_single() {
        let mut dynstr = vec![0u8];
        let name_off = dynstr.len();
        dynstr.extend_from_slice(b"FOO_1.0\0");

        // Verdef (20 bytes) + Verdaux (8 bytes)
        let mut data = vec![0u8; 28];
        data[0..2].copy_from_slice(&1u16.to_le_bytes());  // vd_version
        data[2..4].copy_from_slice(&0u16.to_le_bytes());  // vd_flags
        data[4..6].copy_from_slice(&2u16.to_le_bytes());  // vd_ndx
        data[6..8].copy_from_slice(&1u16.to_le_bytes());  // vd_cnt
        data[8..12].copy_from_slice(&0xABCDu32.to_le_bytes()); // vd_hash
        data[12..16].copy_from_slice(&20u32.to_le_bytes()); // vd_aux = 20 bytes ahead
        data[16..20].copy_from_slice(&0u32.to_le_bytes()); // vd_next = 0
        // Verdaux at offset 20
        data[20..24].copy_from_slice(&(name_off as u32).to_le_bytes());
        data[24..28].copy_from_slice(&0u32.to_le_bytes()); // vda_next = 0

        let result = parse_verdef(&data, &dynstr, 1);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].ndx, 2);
        assert_eq!(result[0].primary_name(), Some("FOO_1.0"));
    }

    #[test]
    fn test_parse_version_info_index_map() {
        // Build minimal verneed with version index 3 = "GLIBC_2.5"
        let mut dynstr = vec![0u8];
        let glibc_off = dynstr.len();
        dynstr.extend_from_slice(b"GLIBC_2.5\0");
        let libc_off = dynstr.len();
        dynstr.extend_from_slice(b"libc.so.6\0");

        let mut data = vec![0u8; 32];
        data[0..2].copy_from_slice(&1u16.to_le_bytes());
        data[2..4].copy_from_slice(&1u16.to_le_bytes());
        data[4..8].copy_from_slice(&(libc_off as u32).to_le_bytes());
        data[8..12].copy_from_slice(&16u32.to_le_bytes());
        data[12..16].copy_from_slice(&0u32.to_le_bytes());
        let aux = &mut data[16..32];
        aux[6..8].copy_from_slice(&3u16.to_le_bytes()); // vna_other = 3
        aux[8..12].copy_from_slice(&(glibc_off as u32).to_le_bytes());

        let versym_data = {
            let mut d = Vec::new();
            d.extend_from_slice(&0u16.to_le_bytes()); // sym 0 = local
            d.extend_from_slice(&1u16.to_le_bytes()); // sym 1 = global
            d.extend_from_slice(&3u16.to_le_bytes()); // sym 2 = version 3
            d
        };

        let info = parse_version_info(&versym_data, &data, &[], &dynstr, 1, 0);
        assert_eq!(info.versyms.len(), 3);
        assert!(info.index_to_name.contains_key(&3));
        assert_eq!(info.index_to_name[&3], "GLIBC_2.5");
        assert_eq!(info.version_name_for_sym(2), Some("GLIBC_2.5"));
        assert!(info.is_versioned(2));
        assert!(!info.is_versioned(0));
    }

    #[test]
    fn test_required_versions() {
        let info = ElfVersionInfo {
            versyms: vec![],
            verneed: vec![VersionNeed {
                version: 1,
                file: "libc.so.6".into(),
                auxiliaries: vec![
                    VerNeed { hash: 0, flags: 0, other: 2, name: "GLIBC_2.5".into() },
                    VerNeed { hash: 0, flags: 0, other: 3, name: "GLIBC_2.17".into() },
                ],
            }],
            verdef: vec![],
            index_to_name: HashMap::new(),
        };
        let reqs = info.required_versions();
        assert_eq!(reqs.len(), 2);
        assert!(reqs.contains(&"GLIBC_2.5"));
        assert!(reqs.contains(&"GLIBC_2.17"));
    }

    #[test]
    fn test_verdef_is_base() {
        let vd = VerDef { version: 1, flags: 0x01, ndx: 1, hash: 0, auxiliaries: vec![] };
        assert!(vd.is_base());
        let vd2 = VerDef { version: 1, flags: 0x00, ndx: 2, hash: 0, auxiliaries: vec![VerDefAux { name: "FOO_1.0".into() }] };
        assert!(!vd2.is_base());
        assert_eq!(vd2.primary_name(), Some("FOO_1.0"));
    }

    #[test]
    fn test_versym_parse_all_big_endian() {
        // Two entries: 0x0002 and 0x8003 (hidden bit set), stored MSB-first.
        let data = vec![0x00, 0x02, 0x80, 0x03];
        let be = VerSym::parse_all_endian(&data, false);
        assert_eq!(be.len(), 2);
        assert_eq!(be[0].version_index, 2);
        assert!(!be[0].hidden);
        assert!(be[1].hidden);
        assert_eq!(be[1].effective_index, 3);
        // The LE default reads the same bytes byte-swapped.
        assert_eq!(VerSym::parse_all(&data)[0].version_index, 0x0200);
    }

    #[test]
    fn test_parse_verneed_big_endian() {
        let mut data = vec![0u8; 32];
        data[0..2].copy_from_slice(&1u16.to_be_bytes()); // vn_version
        data[2..4].copy_from_slice(&1u16.to_be_bytes()); // vn_cnt
        data[4..8].copy_from_slice(&0u32.to_be_bytes()); // vn_file → "libc.so.6"
        data[8..12].copy_from_slice(&16u32.to_be_bytes()); // vn_aux
        data[12..16].copy_from_slice(&0u32.to_be_bytes()); // vn_next
        data[16..20].copy_from_slice(&0xCAFEu32.to_be_bytes()); // vna_hash
        data[20..22].copy_from_slice(&0u16.to_be_bytes()); // vna_flags
        data[22..24].copy_from_slice(&3u16.to_be_bytes()); // vna_other
        data[24..28].copy_from_slice(&10u32.to_be_bytes()); // vna_name → "GLIBC_2.5"
        data[28..32].copy_from_slice(&0u32.to_be_bytes()); // vna_next
        let dynstr = b"libc.so.6\0GLIBC_2.5\0".to_vec();

        let needs = parse_verneed_endian(&data, &dynstr, 1, false);
        assert_eq!(needs.len(), 1);
        assert_eq!(needs[0].file, "libc.so.6");
        assert_eq!(needs[0].auxiliaries.len(), 1);
        assert_eq!(needs[0].auxiliaries[0].hash, 0xCAFE);
        assert_eq!(needs[0].auxiliaries[0].other, 3);
        assert_eq!(needs[0].auxiliaries[0].name, "GLIBC_2.5");
    }

    #[test]
    fn test_le_wrappers_delegate_unchanged() {
        // The historical LE entry points must stay equivalent to the endian-aware
        // ones invoked with le = true.
        let versym = vec![0x01, 0x00, 0x02, 0x00];
        assert_eq!(
            VerSym::parse_all(&versym).len(),
            VerSym::parse_all_endian(&versym, true).len()
        );
        assert_eq!(
            VerSym::parse_all(&versym)[1].version_index,
            VerSym::parse_all_endian(&versym, true)[1].version_index
        );
        let info_le = parse_version_info(&versym, &[], &[], &[], 0, 0);
        let info_eq = parse_version_info_endian(
            &VersionSections {
                versym_data: &versym,
                verneed_data: &[],
                verdef_data: &[],
                dynstr: &[],
                verneed_count: 0,
                verdef_count: 0,
            },
            true,
        );
        assert_eq!(info_le.versyms.len(), info_eq.versyms.len());
    }

    #[test]
    fn test_verneed_is_weak() {
        let vn = VerNeed { hash: 0, flags: 0x02, other: 2, name: "WEAK_VER".into() };
        assert!(vn.is_weak());
        let vn2 = VerNeed { hash: 0, flags: 0x00, other: 3, name: "STRONG_VER".into() };
        assert!(!vn2.is_weak());
    }
}
