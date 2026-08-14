//! ELF symbol versioning — high-level analysis layer.
//!
//! **Layer:** sits above [`crate::versioning`] (raw byte-level parsers)
//! and [`crate::elf_version_info`] (mid-level aggregator).  This module
//! provides:
//!
//! * Rich newtype wrappers (`Versym`, `VersionNeeds`, `VersionDefs`) with
//!   `HashMap`-backed fast lookup by version index.
//! * Cross-section utilities: `build_versioned_table`,
//!   `check_version_compatibility`, `version_report`.
//! * GNU-hash helpers: `version_hash`, `verify_vernaux_hash`.
//! * glibc-specific helpers (`glibc_versions`, `min_glibc`).
//!
//! Symbol versioning in ELF allows shared libraries to export multiple
//! versions of the same symbol, enabling ABI evolution without breaking
//! binary compatibility.  There are three related sections:
//!
//! * **`.gnu.version`** (`SHT_GNU_versym`): one 16-bit `Versym` per symbol
//!   in `.dynsym`, mapping each symbol to a version index.
//! * **`.gnu.version_r`** (`SHT_GNU_verneed`): for *users* of versioned
//!   symbols — lists needed version names from each dependency.
//! * **`.gnu.version_d`** (`SHT_GNU_verdef`): for *providers* — lists
//!   version definitions exported by this library.
//!
//! # Version index encoding
//!
//! | Value  | Meaning |
//! |--------|---------|
//! | `0`    | `VER_NDX_LOCAL` — symbol not exported |
//! | `1`    | `VER_NDX_GLOBAL` — unversioned global symbol |
//! | `≥ 2`  | Index into `.gnu.version_d` (if in a provider) or `.gnu.version_r` (if a user) |
//! | high bit (`0x8000`) set | "hidden" version — only matches exactly |

use std::collections::HashMap;
use std::fmt;

// ── Error type ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VersionError {
    TooShort { section: &'static str, needed: usize, got: usize },
    UnknownVersionIndex { sym: String, idx: u16 },
    BadOffset { section: &'static str, offset: usize },
    DuplicateVersion { version: String },
    IncompatibleVersionSet { sym: String, provided: String, needed: String },
}

impl fmt::Display for VersionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooShort { section, needed, got } =>
                write!(f, "{section}: too short (need {needed}, have {got})"),
            Self::UnknownVersionIndex { sym, idx } =>
                write!(f, "symbol '{sym}' has unknown version index {idx}"),
            Self::BadOffset { section, offset } =>
                write!(f, "{section}: bad offset {offset}"),
            Self::DuplicateVersion { version } =>
                write!(f, "duplicate version name '{version}'"),
            Self::IncompatibleVersionSet { sym, provided, needed } =>
                write!(f, "symbol '{sym}': version '{needed}' needed but only '{provided}' provided"),
        }
    }
}

// ── Versym values ─────────────────────────────────────────────────────────────

/// A `Versym` entry from `.gnu.version`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Versym(pub u16);

impl Versym {
    pub const LOCAL:  u16 = 0;
    pub const GLOBAL: u16 = 1;
    pub const HIDDEN_BIT: u16 = 0x8000;

    /// True if this symbol is local (not exported).
    #[must_use]
    pub const fn is_local(self) -> bool { self.0 == Self::LOCAL }

    /// True if this is an unversioned global.
    #[must_use]
    pub const fn is_global(self) -> bool { self.0 == Self::GLOBAL }

    /// True if the hidden bit is set.
    #[must_use]
    pub const fn is_hidden(self) -> bool { (self.0 & Self::HIDDEN_BIT) != 0 }

    /// Version index without the hidden bit.
    #[must_use]
    pub const fn index(self) -> u16 { self.0 & !Self::HIDDEN_BIT }
}

impl fmt::Display for Versym {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.index() {
            0 => f.write_str("LOCAL"),
            1 => f.write_str("GLOBAL"),
            n if self.is_hidden() => write!(f, "v{n} (hidden)"),
            n => write!(f, "v{n}"),
        }
    }
}

/// Parse `.gnu.version` section into a vector of `Versym`.
///
/// The section is simply `ndynsym × 2` bytes of little-endian `u16`.
///
/// # Errors
/// Returns an error if the data length is not a multiple of 2.
pub fn parse_versym(data: &[u8]) -> Result<Vec<Versym>, VersionError> {
    parse_versym_endian(data, true)
}

/// Read a `u16` at `off` with the given byte order.
///
/// The caller is responsible for the bounds check, exactly as the inline
/// indexing this replaces was.
fn rd16(data: &[u8], off: usize, le: bool) -> u16 {
    let b = [data[off], data[off + 1]];
    if le {
        u16::from_le_bytes(b)
    } else {
        u16::from_be_bytes(b)
    }
}

/// Read a `u32` at `off` with the given byte order.
fn rd32(data: &[u8], off: usize, le: bool) -> u32 {
    let b = [data[off], data[off + 1], data[off + 2], data[off + 3]];
    if le {
        u32::from_le_bytes(b)
    } else {
        u32::from_be_bytes(b)
    }
}

/// Endianness-aware variant of [`parse_versym`]; pass `le = false` for
/// big-endian ELF objects.
///
/// # Errors
/// Returns an error if the data length is not a multiple of 2.
pub fn parse_versym_endian(data: &[u8], le: bool) -> Result<Vec<Versym>, VersionError> {
    if !data.len().is_multiple_of(2) {
        return Err(VersionError::TooShort {
            section: ".gnu.version",
            needed: data.len() + 1,
            got: data.len(),
        });
    }
    Ok(data.chunks_exact(2)
        .map(|c| {
            let b = [c[0], c[1]];
            Versym(if le {
                u16::from_le_bytes(b)
            } else {
                u16::from_be_bytes(b)
            })
        })
        .collect())
}

// ── Verneed (.gnu.version_r) ───────────────────────────────────────────────────

/// A single `Vernaux` record — one required version from a library.
#[derive(Debug, Clone)]
pub struct Vernaux {
    /// CRC32 hash of the version string.
    pub hash: u32,
    /// Flags (0 = normal, 2 = WEAK).
    pub flags: u16,
    /// Version index (must match a `Versym` in this binary).
    pub other: u16,
    /// Version string (e.g., `"GLIBC_2.17"`).
    pub name: String,
}

impl Vernaux {
    #[must_use]
    pub const fn is_weak(&self) -> bool { (self.flags & 2) != 0 }
}

/// A `Verneed` record — one dependency's version requirements.
#[derive(Debug, Clone)]
pub struct Verneed {
    /// File (SONAME) the versions are needed from, e.g., `"libc.so.6"`.
    pub file: String,
    /// Individual version requirements from this file.
    pub aux: Vec<Vernaux>,
}

/// Parsed `.gnu.version_r` section.
#[derive(Debug, Clone, Default)]
pub struct VersionNeeds {
    pub entries: Vec<Verneed>,
    /// Quick lookup: version index → `(file, version_name)`.
    pub by_index: HashMap<u16, (String, String)>,
}

impl VersionNeeds {
    /// Parse from raw section data.
    ///
    /// `data` — the raw `.gnu.version_r` section bytes.
    /// `dynstr` — the `.dynstr` section (for resolving name offsets).
    ///
    /// # Errors
    /// Returns an error if the section data is malformed.
    pub fn parse(data: &[u8], dynstr: &[u8]) -> Result<Self, VersionError> {
        Self::parse_endian(data, dynstr, true)
    }

    /// Endianness-aware variant of [`VersionNeeds::parse`]; pass `le = false` for
    /// big-endian ELF objects.
    ///
    /// # Errors
    /// Returns an error if the section data is malformed.
    pub fn parse_endian(data: &[u8], dynstr: &[u8], le: bool) -> Result<Self, VersionError> {
        let mut entries = Vec::new();
        let mut by_index = HashMap::new();
        let mut offset = 0usize;

        while offset + 16 <= data.len() {
            let _version = rd16(data, offset, le);
            let cnt      = rd16(data, offset+2, le) as usize;
            let file_off = rd32(data, offset+4, le) as usize;
            let aux_off  = rd32(data, offset+8, le) as usize;
            let next_off = rd32(data, offset+12, le) as usize;

            let file = get_dynstr(dynstr, file_off)?;
            let mut aux_list = Vec::new();
            let mut aux_cursor = offset + aux_off;

            for _ in 0..cnt {
                if aux_cursor + 16 > data.len() {
                    return Err(VersionError::TooShort {
                        section: ".gnu.version_r aux",
                        needed: aux_cursor + 16,
                        got: data.len(),
                    });
                }
                let hash      = rd32(data, aux_cursor, le);
                let flags     = rd16(data, aux_cursor+4, le);
                let other     = rd16(data, aux_cursor+6, le);
                let name_off  = rd32(data, aux_cursor+8, le) as usize;
                let next_aux  = rd32(data, aux_cursor+12, le) as usize;

                let name = get_dynstr(dynstr, name_off)?;
                by_index.insert(other, (file.clone(), name.clone()));
                aux_list.push(Vernaux { hash, flags, other, name });

                if next_aux == 0 { break; }
                aux_cursor += next_aux;
            }

            entries.push(Verneed { file, aux: aux_list });
            if next_off == 0 { break; }
            offset += next_off;
        }

        Ok(Self { entries, by_index })
    }

    /// Look up the version string for a `Versym` index.
    #[must_use]
    pub fn version_for_index(&self, idx: u16) -> Option<&str> {
        self.by_index.get(&idx).map(|(_, name)| name.as_str())
    }

    /// Find the SONAME that provides a given version string.
    #[must_use]
    pub fn file_for_version(&self, version: &str) -> Option<&str> {
        for entry in &self.entries {
            if entry.aux.iter().any(|a| a.name == version) {
                return Some(&entry.file);
            }
        }
        None
    }

    /// Return all required GLIBC versions, sorted.
    #[must_use]
    pub fn glibc_versions(&self) -> Vec<String> {
        let mut v: Vec<_> = self.entries.iter()
            .flat_map(|e| e.aux.iter())
            .filter(|a| a.name.starts_with("GLIBC_"))
            .map(|a| a.name.clone())
            .collect();
        v.sort();
        v.dedup();
        v
    }

    /// The minimum glibc version required (e.g., `"GLIBC_2.5"`).
    #[must_use]
    pub fn min_glibc(&self) -> Option<String> {
        self.glibc_versions().into_iter().next()
    }
}

// ── Verdef (.gnu.version_d) ────────────────────────────────────────────────────

/// A single `Verdaux` record — one name within a version definition.
#[derive(Debug, Clone)]
pub struct Verdaux {
    /// Version name (e.g., `"MYLIB_1.0"`).
    pub name: String,
}

/// A `Verdef` record — one version provided by this library.
#[derive(Debug, Clone)]
pub struct Verdef {
    /// Version definition flags (`VER_FLG_BASE` = 0x1 for the base version).
    pub flags: u16,
    /// Version index (must be ≥ 2; matches Versym values in exporting binary).
    pub ndx: u16,
    /// Parent versions (for compatibility chains).
    pub parents: Vec<u16>,
    /// Version name(s).
    pub names: Vec<String>,
}

impl Verdef {
    /// True if this is the base version (`VER_FLG_BASE`).
    #[must_use]
    pub const fn is_base(&self) -> bool { (self.flags & 0x1) != 0 }

    /// True if this version is a compatibility alias (`VER_FLG_WEAK`).
    #[must_use]
    pub const fn is_weak(&self) -> bool { (self.flags & 0x2) != 0 }

    /// Primary name of this version.
    #[must_use]
    pub fn primary_name(&self) -> Option<&str> {
        self.names.first().map(String::as_str)
    }
}

/// Parsed `.gnu.version_d` section.
#[derive(Debug, Clone, Default)]
pub struct VersionDefs {
    pub entries: Vec<Verdef>,
    /// Quick lookup: version index → Verdef.
    pub by_index: HashMap<u16, usize>,
}

impl VersionDefs {
    /// Parse from raw section data and dynstr.
    ///
    /// # Errors
    /// Returns an error if the section data is malformed.
    pub fn parse(data: &[u8], dynstr: &[u8]) -> Result<Self, VersionError> {
        Self::parse_endian(data, dynstr, true)
    }

    /// Endianness-aware variant of [`VersionDefs::parse`]; pass `le = false` for
    /// big-endian ELF objects.
    ///
    /// # Errors
    /// Returns an error if the section data is malformed.
    pub fn parse_endian(data: &[u8], dynstr: &[u8], le: bool) -> Result<Self, VersionError> {
        let mut entries = Vec::new();
        let mut by_index = HashMap::new();
        let mut offset = 0usize;

        while offset + 20 <= data.len() {
            let _version = rd16(data, offset, le);
            let flags    = rd16(data, offset+2, le);
            let ndx      = rd16(data, offset+4, le);
            let cnt      = rd16(data, offset+6, le) as usize;
            let _hash    = rd32(data, offset+8, le);
            let aux_off  = rd32(data, offset+12, le) as usize;
            let next_off = rd32(data, offset+16, le) as usize;

            let mut names = Vec::new();
            let parents = Vec::new();
            let mut aux_cursor = offset + aux_off;

            for i in 0..cnt {
                if aux_cursor + 8 > data.len() {
                    return Err(VersionError::TooShort {
                        section: ".gnu.version_d aux",
                        needed: aux_cursor + 8,
                        got: data.len(),
                    });
                }
                let name_off = rd32(data, aux_cursor, le) as usize;
                let next_aux = rd32(data, aux_cursor+4, le) as usize;
                let name = get_dynstr(dynstr, name_off)?;
                // Both the first (version name) and subsequent (parent versions)
                // Verdaux entries are collected into `names`.
                names.push(name);
                let _ = i; // i used only for tracking position semantically
                if next_aux == 0 { break; }
                aux_cursor += next_aux;
            }

            let idx = entries.len();
            by_index.insert(ndx, idx);
            entries.push(Verdef { flags, ndx, parents, names });

            if next_off == 0 { break; }
            offset += next_off;
        }

        Ok(Self { entries, by_index })
    }

    /// Find a version definition by name.
    #[must_use]
    pub fn find_by_name(&self, name: &str) -> Option<&Verdef> {
        self.entries.iter().find(|v| v.names.iter().any(|n| n == name))
    }

    /// Find a version definition by index.
    #[must_use]
    pub fn find_by_index(&self, ndx: u16) -> Option<&Verdef> {
        let i = *self.by_index.get(&ndx)?;
        self.entries.get(i)
    }

    /// True if the library provides `version_name`.
    #[must_use]
    pub fn provides(&self, version_name: &str) -> bool {
        self.find_by_name(version_name).is_some()
    }

    /// Topological list of versions in dependency order (base first).
    #[must_use]
    pub fn ordered_versions(&self) -> Vec<&str> {
        let mut result = Vec::new();
        if let Some(base) = self.entries.iter().find(|v| v.is_base())
            && let Some(n) = base.primary_name() { result.push(n); }
        for v in &self.entries {
            if !v.is_base()
                && let Some(n) = v.primary_name()
                    && !result.contains(&n) {
                        result.push(n);
                    }
        }
        result
    }
}

// ── Symbol version table ───────────────────────────────────────────────────────

/// Annotated symbol: combines a dynsym entry with its version.
#[derive(Debug, Clone)]
pub struct VersionedSymbol {
    /// Symbol name (e.g., `"memcpy"`).
    pub name: String,
    /// Version string (e.g., `"GLIBC_2.14"`) or empty for unversioned.
    pub version: String,
    /// Versym index.
    pub versym: Versym,
    /// True if this is a definition (`STB_GLOBAL`, non-UND).
    pub is_defined: bool,
    /// Symbol value (virtual address or 0 for undefined).
    pub value: u64,
    /// True if the symbol is exported.
    pub is_exported: bool,
}

impl fmt::Display for VersionedSymbol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.version.is_empty() {
            write!(f, "{}", self.name)
        } else {
            write!(f, "{}@@{}", self.name, self.version)
        }
    }
}

/// Build a table of versioned symbols from `.dynsym`, `.gnu.version`, and
/// `.gnu.version_r` / `.gnu.version_d` data.
///
/// `dynsym_entries`: `(name, value, is_defined)` for each dynsym entry.
/// `versyms`: from `parse_versym`.
/// `needs`: optional parsed `.gnu.version_r`.
/// `defs`: optional parsed `.gnu.version_d`.
#[must_use]
pub fn build_versioned_table(
    dynsym_entries: &[(String, u64, bool)],
    versyms: &[Versym],
    needs: Option<&VersionNeeds>,
    defs: Option<&VersionDefs>,
) -> Vec<VersionedSymbol> {
    dynsym_entries.iter().enumerate().map(|(i, (name, value, is_defined))| {
        let vs = versyms.get(i).copied().unwrap_or(Versym(1));
        let version = if vs.is_local() || vs.is_global() {
            String::new()
        } else {
            let idx = vs.index();
            // Try version_r (import side) first, then version_d (export side).
            let v = needs.and_then(|n| n.version_for_index(idx))
                .or_else(|| defs.and_then(|d| d.find_by_index(idx)).and_then(|def| def.primary_name()));
            v.unwrap_or("").to_string()
        };
        let is_exported = *is_defined && !vs.is_local();
        VersionedSymbol {
            name: name.clone(),
            version,
            versym: vs,
            is_defined: *is_defined,
            value: *value,
            is_exported,
        }
    }).collect()
}

// ── Compatibility checker ─────────────────────────────────────────────────────

/// Check whether all symbols needed by a binary (from `.gnu.version_r`) are
/// actually provided by the corresponding libraries (from their `.gnu.version_d`).
///
/// `provider_defs`: map from SONAME to its parsed `VersionDefs`.
///
/// Returns a list of incompatibilities found.
#[must_use]
pub fn check_version_compatibility<S: ::std::hash::BuildHasher>(
    needs: &VersionNeeds,
    provider_defs: &HashMap<String, VersionDefs, S>,
) -> Vec<VersionError> {
    let mut errors = Vec::new();
    for verneed in &needs.entries {
        let file = &verneed.file;
        let Some(defs) = provider_defs.get(file.as_str()) else { continue };
        for aux in &verneed.aux {
            if !defs.provides(&aux.name) && !aux.is_weak() {
                errors.push(VersionError::IncompatibleVersionSet {
                    sym: format!("(any symbol from {file})"),
                    provided: defs.ordered_versions().first().copied().unwrap_or("none").to_string(),
                    needed: aux.name.clone(),
                });
            }
        }
    }
    errors
}

// ── GNU version hash ──────────────────────────────────────────────────────────

/// Compute the ELF hash used for version strings (same as `elf_hash`).
#[must_use]
pub fn version_hash(name: &str) -> u32 {
    let mut h: u32 = 0;
    for c in name.bytes() {
        h = h.wrapping_shl(4).wrapping_add(u32::from(c));
        let g = h & 0xF000_0000;
        if g != 0 {
            h ^= g >> 24;
        }
        h &= !g;
    }
    h
}

/// Verify that a `Vernaux` hash matches the version name.
#[must_use]
pub fn verify_vernaux_hash(aux: &Vernaux) -> bool {
    aux.hash == version_hash(&aux.name)
}

// ── Utilities ─────────────────────────────────────────────────────────────────

fn get_dynstr(dynstr: &[u8], off: usize) -> Result<String, VersionError> {
    if off >= dynstr.len() {
        return Err(VersionError::BadOffset { section: "dynstr", offset: off });
    }
    let end = dynstr[off..].iter().position(|&b| b == 0)
        .map_or(dynstr.len(), |i| off + i);
    Ok(String::from_utf8_lossy(&dynstr[off..end]).into_owned())
}

/// List all symbols that have a specific version (e.g., `"GLIBC_2.17"`).
#[must_use]
pub fn symbols_with_version<'a>(
    table: &'a [VersionedSymbol],
    version: &str,
) -> Vec<&'a VersionedSymbol> {
    table.iter().filter(|s| s.version == version).collect()
}

/// Return all unique version strings required by this binary.
#[must_use]
pub fn required_versions(table: &[VersionedSymbol]) -> Vec<String> {
    let mut v: Vec<_> = table.iter()
        .filter(|s| !s.is_defined && !s.version.is_empty())
        .map(|s| s.version.clone())
        .collect();
    v.sort();
    v.dedup();
    v
}

/// Produce a human-readable compatibility report.
#[must_use]
pub fn version_report(needs: &VersionNeeds) -> String {
    use std::fmt::Write as _;
    let mut out = String::from("Symbol Version Requirements:\n");
    for entry in &needs.entries {
        let _ = writeln!(out, "  From {}:", entry.file);
        for aux in &entry.aux {
            let weak = if aux.is_weak() { " (weak)" } else { "" };
            let _ = writeln!(out, "    [v{:2}] {}{}", aux.other, aux.name, weak);
        }
    }
    out
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versym_flags() {
        assert!(Versym(0).is_local());
        assert!(Versym(1).is_global());
        assert!(!Versym(2).is_local());
        assert!(!Versym(2).is_hidden());
        assert!(Versym(0x8002).is_hidden());
        assert_eq!(Versym(0x8005).index(), 5);
    }

    #[test]
    fn parse_versym_even() {
        // Two symbols: LOCAL, v2.
        let data: &[u8] = &[0x00, 0x00, 0x02, 0x00];
        let vs = parse_versym(data).unwrap();
        assert_eq!(vs.len(), 2);
        assert!(vs[0].is_local());
        assert_eq!(vs[1].index(), 2);
    }

    #[test]
    fn parse_versym_odd_fails() {
        let data: &[u8] = &[0x00, 0x00, 0x02];
        assert!(parse_versym(data).is_err());
    }

    #[test]
    fn version_hash_glibc() {
        // GNU ELF hash of "GLIBC_2.5".
        let h = version_hash("GLIBC_2.5");
        assert!(h > 0); // non-zero hash
    }

    #[test]
    fn build_versioned_table_empty() {
        let syms = vec![("_init".to_string(), 0x400u64, true)];
        let vs = vec![Versym(1)];
        let table = build_versioned_table(&syms, &vs, None, None);
        assert_eq!(table.len(), 1);
        assert!(table[0].version.is_empty());
    }

    #[test]
    fn required_versions_empty_for_defined() {
        let syms = vec![
            VersionedSymbol {
                name: "myfunc".to_string(),
                version: "MYLIB_1.0".to_string(),
                versym: Versym(2),
                is_defined: true,
                value: 0x1000,
                is_exported: true,
            }
        ];
        let req = required_versions(&syms);
        assert!(req.is_empty()); // defined symbols don't count as requirements
    }

    #[test]
    fn required_versions_finds_undefined() {
        let syms = vec![
            VersionedSymbol {
                name: "printf".to_string(),
                version: "GLIBC_2.2.5".to_string(),
                versym: Versym(3),
                is_defined: false,
                value: 0,
                is_exported: false,
            }
        ];
        let req = required_versions(&syms);
        assert_eq!(req, vec!["GLIBC_2.2.5"]);
    }

    #[test]
    fn compatibility_check_no_provider() {
        // No provider defs means no errors (can't check).
        let needs = VersionNeeds::default();
        let errors = check_version_compatibility(&needs, &HashMap::new());
        assert!(errors.is_empty());
    }

    #[test]
    fn version_report_format() {
        let needs = VersionNeeds {
            entries: vec![Verneed {
                file: "libc.so.6".to_string(),
                aux: vec![Vernaux { hash: 0, flags: 0, other: 2, name: "GLIBC_2.17".to_string() }],
            }],
            by_index: HashMap::new(),
        };
        let report = version_report(&needs);
        assert!(report.contains("libc.so.6"));
        assert!(report.contains("GLIBC_2.17"));
    }

    #[test]
    fn symbols_with_version_filter() {
        let syms = vec![
            VersionedSymbol { name: "a".into(), version: "V1".into(), versym: Versym(2), is_defined: true, value: 1, is_exported: true },
            VersionedSymbol { name: "b".into(), version: "V2".into(), versym: Versym(3), is_defined: true, value: 2, is_exported: true },
        ];
        let v1 = symbols_with_version(&syms, "V1");
        assert_eq!(v1.len(), 1);
        assert_eq!(v1[0].name, "a");
    }

    // ── Big-endian support ────────────────────────────────────────────────────

    #[test]
    fn parse_versym_big_endian() {
        // 0x0002 then 0x8003 (hidden), MSB-first.
        let data = [0x00, 0x02, 0x80, 0x03];
        let be = parse_versym_endian(&data, false).unwrap();
        assert_eq!(be.len(), 2);
        assert_eq!(be[0].index(), 2);
        assert!(!be[0].is_hidden());
        assert!(be[1].is_hidden());
        assert_eq!(be[1].index(), 3);
        // Default LE reading of the same bytes is byte-swapped.
        assert_eq!(parse_versym(&data).unwrap()[0].0, 0x0200);
    }

    #[test]
    fn parse_verneed_big_endian() {
        let mut data = vec![0u8; 32];
        data[0..2].copy_from_slice(&1u16.to_be_bytes()); // vn_version
        data[2..4].copy_from_slice(&1u16.to_be_bytes()); // vn_cnt
        data[4..8].copy_from_slice(&0u32.to_be_bytes()); // vn_file → "libc.so.6"
        data[8..12].copy_from_slice(&16u32.to_be_bytes()); // vn_aux
        data[12..16].copy_from_slice(&0u32.to_be_bytes()); // vn_next
        data[16..20].copy_from_slice(&0xCAFEu32.to_be_bytes()); // vna_hash
        data[20..22].copy_from_slice(&0u16.to_be_bytes()); // vna_flags
        data[22..24].copy_from_slice(&2u16.to_be_bytes()); // vna_other (index 2)
        data[24..28].copy_from_slice(&10u32.to_be_bytes()); // vna_name → "GLIBC_2.5"
        data[28..32].copy_from_slice(&0u32.to_be_bytes()); // vna_next
        let dynstr = b"libc.so.6\0GLIBC_2.5\0";

        let needs = VersionNeeds::parse_endian(&data, dynstr, false).unwrap();
        assert_eq!(needs.entries.len(), 1);
        assert_eq!(needs.entries[0].file, "libc.so.6");
        assert_eq!(needs.entries[0].aux.len(), 1);
        assert_eq!(needs.entries[0].aux[0].hash, 0xCAFE);
        assert_eq!(needs.entries[0].aux[0].name, "GLIBC_2.5");
        assert_eq!(
            needs.by_index.get(&2).map(|(f, v)| (f.as_str(), v.as_str())),
            Some(("libc.so.6", "GLIBC_2.5"))
        );
    }

    #[test]
    fn parse_verdef_big_endian() {
        let mut data = vec![0u8; 28];
        data[0..2].copy_from_slice(&1u16.to_be_bytes()); // vd_version
        data[2..4].copy_from_slice(&0u16.to_be_bytes()); // vd_flags
        data[4..6].copy_from_slice(&2u16.to_be_bytes()); // vd_ndx
        data[6..8].copy_from_slice(&1u16.to_be_bytes()); // vd_cnt
        data[8..12].copy_from_slice(&0u32.to_be_bytes()); // vd_hash
        data[12..16].copy_from_slice(&20u32.to_be_bytes()); // vd_aux
        data[16..20].copy_from_slice(&0u32.to_be_bytes()); // vd_next
        data[20..24].copy_from_slice(&0u32.to_be_bytes()); // vda_name
        data[24..28].copy_from_slice(&0u32.to_be_bytes()); // vda_next
        let dynstr = b"MYLIB_1.0\0";

        let defs = VersionDefs::parse_endian(&data, dynstr, false).unwrap();
        assert_eq!(defs.entries.len(), 1);
        assert_eq!(defs.entries[0].ndx, 2);
    }

    #[test]
    fn le_wrappers_delegate_unchanged() {
        // The historical LE entry points must stay equivalent to the endian-aware
        // ones invoked with le = true.
        let versym = [0x01, 0x00, 0x02, 0x00];
        assert_eq!(
            parse_versym(&versym).unwrap(),
            parse_versym_endian(&versym, true).unwrap()
        );
        assert_eq!(
            VersionNeeds::parse(&[], &[]).unwrap().entries.len(),
            VersionNeeds::parse_endian(&[], &[], true).unwrap().entries.len()
        );
        assert_eq!(
            VersionDefs::parse(&[], &[]).unwrap().entries.len(),
            VersionDefs::parse_endian(&[], &[], true).unwrap().entries.len()
        );
    }
}
