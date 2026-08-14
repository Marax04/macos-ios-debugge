//! `DynamoRIO` drcov coverage import.
//!
//! Supports both text (v2) and binary drcov formats.  Parses module tables,
//! basic-block tables, and produces coverage bitmaps ready for use with the
//! rest of `rustre-trace-coverage`.

use std::collections::HashMap;
use std::fmt;

use crate::CovError;

// ─── DrcovVersion ─────────────────────────────────────────────────────────────

/// Supported drcov file format versions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DrcovVersion {
    /// Version 2 — standard text-header format used by `DynamoRIO` 6+.
    V2,
    /// Version 3 — extended with per-BB thread ID column.
    V3,
}

impl fmt::Display for DrcovVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::V2 => write!(f, "drcov-v2"),
            Self::V3 => write!(f, "drcov-v3"),
        }
    }
}

impl DrcovVersion {
    /// Parse the version integer from a drcov header line.
    ///
    /// # Errors
    /// Returns `CovError::ParseError` if the line format is unexpected or the version is unknown.
    pub fn from_header(line: &str) -> Result<Self, CovError> {
        // "DRCOV VERSION: 2" or "DRCOV VERSION: 3"
        let num_str = line
            .split(':')
            .nth(1)
            .ok_or_else(|| CovError::ParseError(format!("bad version line: {line}")))?
            .trim();
        match num_str {
            "2" => Ok(Self::V2),
            "3" => Ok(Self::V3),
            other => Err(CovError::ParseError(format!(
                "unsupported drcov version: {other}"
            ))),
        }
    }
}

// ─── DrcovFlavor ──────────────────────────────────────────────────────────────

/// Instrumentation flavor recorded in the drcov header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DrcovFlavor {
    /// Standard `DynamoRIO` client.
    DynamoRio,
    /// `WinAFL` client flavor.
    WinAfl,
    /// Custom flavor string.
    Custom(String),
}

impl DrcovFlavor {
    /// Parse flavor from the "DRCOV FLAVOR: xxx" header line.
    #[must_use] 
    pub fn from_header(line: &str) -> Self {
        let val = line.split(':').nth(1).unwrap_or("").trim().to_lowercase();
        match val.as_str() {
            "dynamorio" | "drcov" => Self::DynamoRio,
            "winafl" => Self::WinAfl,
            other => Self::Custom(other.to_string()),
        }
    }
}

impl fmt::Display for DrcovFlavor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DynamoRio => write!(f, "dynamorio"),
            Self::WinAfl => write!(f, "winafl"),
            Self::Custom(s) => write!(f, "{s}"),
        }
    }
}

// ─── DrcovModule ──────────────────────────────────────────────────────────────

/// A module (executable or library) recorded in the drcov module table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DrcovModule {
    /// Zero-based module index used by BB records.
    pub id: u32,
    /// Load address (base) of the module.
    pub base: u64,
    /// One-past-end address of the module mapping.
    pub end: u64,
    /// Entry-point address (may be 0 if unknown).
    pub entry: u64,
    /// File-system path of the module image.
    pub path: String,
}

impl DrcovModule {
    /// Size of the module mapping in bytes.
    #[must_use]
    pub const fn size(&self) -> u64 {
        self.end.saturating_sub(self.base)
    }

    /// Return `true` if `addr` falls within `[base, end)`.
    #[must_use]
    pub const fn contains(&self, addr: u64) -> bool {
        addr >= self.base && addr < self.end
    }

    /// Convert an absolute address to a module-relative offset.
    #[must_use]
    pub const fn relative_offset(&self, addr: u64) -> Option<u64> {
        if self.contains(addr) {
            Some(addr - self.base)
        } else {
            None
        }
    }

    /// Short name: the file name component of `path`.
    #[must_use]
    pub fn name(&self) -> &str {
        self.path
            .rsplit(['/', '\\'])
            .next()
            .unwrap_or(&self.path)
    }

    /// Parse a single module-table text line (v2 format).
    ///
    /// Expected columns: `id, base, end, entry, path`
    #[must_use] 
    pub fn parse_text_line(line: &str) -> Option<Self> {
        let cols: Vec<&str> = line.splitn(5, ',').collect();
        if cols.len() < 5 {
            return None;
        }
        let id = cols[0].trim().parse::<u32>().ok()?;
        let base = parse_hex(cols[1].trim())?;
        let end = parse_hex(cols[2].trim())?;
        let entry = parse_hex(cols[3].trim())?;
        let path = cols[4].trim().to_string();
        Some(Self {
            id,
            base,
            end,
            entry,
            path,
        })
    }
}

impl fmt::Display for DrcovModule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Module[{}] {:#x}..{:#x} {}",
            self.id,
            self.base,
            self.end,
            self.name()
        )
    }
}

// ─── DrcovBB ──────────────────────────────────────────────────────────────────

/// A basic-block record from a drcov BB table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DrcovBB {
    /// Offset of the BB start from the start of its module.
    pub start_offset: u32,
    /// Size of the basic block in bytes.
    pub size: u16,
    /// Index into the module table that owns this BB.
    pub module_id: u16,
}

impl DrcovBB {
    /// Construct a new basic-block record.
    #[must_use]
    pub const fn new(start_offset: u32, size: u16, module_id: u16) -> Self {
        Self {
            start_offset,
            size,
            module_id,
        }
    }

    /// Absolute address of this BB given a slice of loaded modules.
    #[must_use]
    pub fn absolute_address(&self, modules: &[DrcovModule]) -> Option<u64> {
        modules
            .iter()
            .find(|m| m.id == u32::from(self.module_id))
            .map(|m| m.base + u64::from(self.start_offset))
    }

    /// Deserialise from 8 raw bytes (little-endian drcov binary format).
    #[must_use] 
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 8 {
            return None;
        }
        let start_offset = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let size = u16::from_le_bytes([bytes[4], bytes[5]]);
        let module_id = u16::from_le_bytes([bytes[6], bytes[7]]);
        Some(Self {
            start_offset,
            size,
            module_id,
        })
    }

    /// Serialise to 8 bytes (little-endian).
    #[must_use]
    pub fn to_bytes(&self) -> [u8; 8] {
        let mut out = [0u8; 8];
        out[0..4].copy_from_slice(&self.start_offset.to_le_bytes());
        out[4..6].copy_from_slice(&self.size.to_le_bytes());
        out[6..8].copy_from_slice(&self.module_id.to_le_bytes());
        out
    }
}

// ─── DrcovFile ────────────────────────────────────────────────────────────────

/// A parsed drcov coverage file.
#[derive(Debug, Clone)]
pub struct DrcovFile {
    /// File format version.
    pub version: DrcovVersion,
    /// Instrumentation flavor.
    pub flavor: DrcovFlavor,
    /// Module table.
    pub module_table: Vec<DrcovModule>,
    /// Basic-block hit table.
    pub bb_table: Vec<DrcovBB>,
}

impl DrcovFile {
    /// Total number of covered basic blocks.
    #[must_use]
    pub const fn bb_count(&self) -> usize {
        self.bb_table.len()
    }

    /// Number of modules recorded.
    #[must_use]
    pub const fn module_count(&self) -> usize {
        self.module_table.len()
    }

    /// Look up a module by its numeric ID.
    #[must_use]
    pub fn module_by_id(&self, id: u32) -> Option<&DrcovModule> {
        self.module_table.iter().find(|m| m.id == id)
    }

    /// Look up a module whose address range contains `addr`.
    #[must_use]
    pub fn module_containing(&self, addr: u64) -> Option<&DrcovModule> {
        self.module_table.iter().find(|m| m.contains(addr))
    }

    /// Return all BBs belonging to the module with `module_id`.
    #[must_use]
    pub fn bbs_for_module(&self, module_id: u16) -> Vec<&DrcovBB> {
        self.bb_table
            .iter()
            .filter(|bb| bb.module_id == module_id)
            .collect()
    }

    /// Resolve all BB records to absolute addresses using the module table.
    #[must_use]
    pub fn absolute_addresses(&self) -> Vec<u64> {
        self.bb_table
            .iter()
            .filter_map(|bb| bb.absolute_address(&self.module_table))
            .collect()
    }

    /// Build a coverage bitmap: `HashMap<addr, hit>` (hit count = 1 per BB
    /// record; duplicates accumulate).
    #[must_use]
    pub fn to_coverage_map(&self) -> HashMap<u64, u64> {
        let mut map = HashMap::new();
        for bb in &self.bb_table {
            if let Some(addr) = bb.absolute_address(&self.module_table) {
                *map.entry(addr).or_insert(0u64) += 1;
            }
        }
        map
    }
}

// ─── DrcovReader ──────────────────────────────────────────────────────────────

/// Reader that parses both text and binary drcov files.
pub struct DrcovReader;

impl DrcovReader {
    /// Parse a drcov file from a text string (v2/v3 text format).
    ///
    /// # Errors
    /// Returns [`CovError::ParseError`] for malformed input.
    pub fn parse_text(input: &str) -> Result<DrcovFile, CovError> {
        let mut lines = input.lines();

        // Header: version
        let version_line = lines
            .next()
            .ok_or_else(|| CovError::ParseError("empty file".to_string()))?;
        let version = DrcovVersion::from_header(version_line)?;

        // Header: flavor
        let flavor_line = lines.next().unwrap_or("DRCOV FLAVOR: dynamorio");
        let flavor = DrcovFlavor::from_header(flavor_line);

        // Module table header: "Module Table: version 3, count N"
        let mut module_table = Vec::new();
        let mut in_modules = false;
        let mut module_count = 0usize;
        let mut columns_line_seen = false;
        let mut bb_table = Vec::new();

        for line in lines {
            let trimmed = line.trim();

            // Detect module table header
            if trimmed.starts_with("Module Table:") {
                in_modules = true;
                // Extract count from "... count N"
                if let Some(pos) = trimmed.rfind("count ")
                    && let Ok(n) = trimmed[pos + 6..].trim().parse::<usize>() {
                        module_count = n;
                    }
                continue;
            }

            if in_modules {
                // Skip the column header line (starts with "id")
                if !columns_line_seen && trimmed.starts_with("id") {
                    columns_line_seen = true;
                    continue;
                }
                if let Some(m) = DrcovModule::parse_text_line(trimmed) {
                    module_table.push(m);
                    if module_table.len() >= module_count && module_count > 0 {
                        in_modules = false;
                    }
                }
                continue;
            }

            // BB table header: "BB Table: N bbs"
            if trimmed.starts_with("BB Table:") {
                // Parse text BB lines after this (for text-format v2)
                continue;
            }

            // Text-format BB: "offset_hex, size_dec, module_id_dec"
            if trimmed.contains(',') && !trimmed.starts_with("id") {
                let parts: Vec<&str> = trimmed.splitn(3, ',').collect();
                if parts.len() == 3
                    && let (Some(off), Some(sz), Some(mid)) = (
                        parse_hex(parts[0].trim()),
                        parts[1].trim().parse::<u16>().ok(),
                        parts[2].trim().parse::<u16>().ok(),
                    ) {
                        let off32 = u32::try_from(off).unwrap_or({
                            u32::MAX // clamp oversized offsets; the BB will be out-of-range at use
                        });
                        bb_table.push(DrcovBB::new(off32, sz, mid));
                    }
            }
        }

        Ok(DrcovFile {
            version,
            flavor,
            module_table,
            bb_table,
        })
    }

    /// Parse a drcov file from raw bytes (binary BB table format).
    ///
    /// Expects a text header followed by a binary blob after the `BB Table:`
    /// sentinel line.
    ///
    /// # Errors
    /// Returns [`CovError::ParseError`] on malformed data.
    pub fn parse_binary(data: &[u8]) -> Result<DrcovFile, CovError> {
        // Split at the first \r\n\r\n or \n\n boundary after the BB Table line.
        let text_end = find_binary_split(data)
            .ok_or_else(|| CovError::ParseError("could not locate binary BB data".to_string()))?;

        let header_text = std::str::from_utf8(&data[..text_end])
            .map_err(|e| CovError::ParseError(format!("utf8 header: {e}")))?;

        // Parse text portion for header + module table
        let mut file = Self::parse_text(header_text)?;

        // Parse binary BB records (8 bytes each)
        let bb_data = &data[text_end..];
        let count = bb_data.len() / 8;
        file.bb_table = (0..count)
            .filter_map(|i| DrcovBB::from_bytes(&bb_data[i * 8..]))
            .collect();

        Ok(file)
    }

    /// Auto-detect format and parse.
    ///
    /// # Errors
    /// Returns `CovError` if neither text nor binary parsing succeeds.
    pub fn parse(data: &[u8]) -> Result<DrcovFile, CovError> {
        // If the data is valid UTF-8 and does NOT have a binary BB blob,
        // treat as text; otherwise try binary.
        if let Ok(s) = std::str::from_utf8(data)
            && (!s.contains("BB Table:") || is_all_text(data)) {
                return Self::parse_text(s);
            }
        Self::parse_binary(data)
    }
}

// ─── ModuleBase ───────────────────────────────────────────────────────────────

/// Resolves module-relative offsets to absolute addresses given a runtime
/// load-address map.  Useful when re-basing a drcov file recorded with
/// different ASLR offsets.
#[derive(Debug, Clone, Default)]
pub struct ModuleBase {
    /// `module_name → runtime_base`.
    bases: HashMap<String, u64>,
}

impl ModuleBase {
    /// Create an empty resolver.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a runtime base address for `module_name`.
    pub fn set(&mut self, module_name: impl Into<String>, base: u64) {
        self.bases.insert(module_name.into(), base);
    }

    /// Look up the base for `name` (exact or suffix match).
    #[must_use]
    pub fn get(&self, name: &str) -> Option<u64> {
        if let Some(&b) = self.bases.get(name) {
            return Some(b);
        }
        // Suffix match: "libc.so.6" matches key "libc.so.6"
        self.bases
            .iter()
            .find(|(k, _)| name.ends_with(k.as_str()) || k.ends_with(name))
            .map(|(_, &v)| v)
    }

    /// Re-base a `DrcovFile` using the recorded runtime bases.
    /// Modules whose names are not found in this resolver are left unchanged.
    pub fn rebase(&self, file: &mut DrcovFile) {
        for module in &mut file.module_table {
            if let Some(new_base) = self.get(module.name()) {
                let size = module.size();
                module.base = new_base;
                module.end = new_base + size;
            }
        }
    }

    /// Number of registered base overrides.
    #[must_use]
    pub fn len(&self) -> usize {
        self.bases.len()
    }

    /// True when no overrides are registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bases.is_empty()
    }
}

// ─── CoverageBitmap ───────────────────────────────────────────────────────────

/// A flat coverage bitmap derived from a drcov BB table.
///
/// The bitmap stores one bit per 4-byte granule within a memory region.
/// Set bits mean "this granule was covered".
#[derive(Debug, Clone)]
pub struct CoverageBitmap {
    /// Base address of the region this bitmap covers.
    pub base: u64,
    /// Granule size in bytes (typically 1 or 4).
    pub granule: u64,
    /// Bit vector — one bit per granule.
    bits: Vec<u8>,
}

impl CoverageBitmap {
    /// Create a zeroed bitmap for the address range `[base, base + size)`.
    #[must_use]
    pub fn new(base: u64, size: u64, granule: u64) -> Self {
        // Guard against allocation overflow: cap at 256 MiB of bitmap bytes.
        const MAX_BITMAP_BYTES: u64 = 256 * 1024 * 1024;
        let granule = granule.max(1);
        let num_granules = size.div_ceil(granule);
        let byte_count = crate::u64_to_usize_sat(num_granules.div_ceil(8).min(MAX_BITMAP_BYTES));
        Self {
            base,
            granule,
            bits: vec![0u8; byte_count],
        }
    }

    /// Mark address `addr` as covered.
    pub fn mark(&mut self, addr: u64) {
        if addr < self.base {
            return;
        }
        let idx = crate::u64_to_usize_sat((addr - self.base) / self.granule);
        let byte = idx / 8;
        let bit = idx % 8;
        if byte < self.bits.len() {
            self.bits[byte] |= 1 << bit;
        }
    }

    /// Return `true` if `addr` is marked covered.
    #[must_use]
    pub fn is_covered(&self, addr: u64) -> bool {
        if addr < self.base {
            return false;
        }
        let idx = crate::u64_to_usize_sat((addr - self.base) / self.granule);
        let byte = idx / 8;
        let bit = idx % 8;
        byte < self.bits.len() && (self.bits[byte] & (1 << bit)) != 0
    }

    /// Total number of set bits (covered granules).
    #[must_use]
    pub fn covered_count(&self) -> usize {
        self.bits.iter().map(|b| b.count_ones() as usize).sum()
    }

    /// Total number of granules in the bitmap.
    #[must_use]
    pub const fn total_granules(&self) -> usize {
        self.bits.len() * 8
    }

    /// Coverage ratio `[0.0, 1.0]`.
    #[must_use]
    pub fn coverage_ratio(&self) -> f64 {
        let total = self.total_granules();
        if total == 0 {
            return 0.0;
        }
        crate::usize_to_f64(self.covered_count()) / crate::usize_to_f64(total)
    }

    /// Build a coverage bitmap from the BBs in `file` for a specific module.
    #[must_use] 
    pub fn from_drcov_file(file: &DrcovFile, module_id: u16) -> Option<Self> {
        let module = file
            .module_table
            .iter()
            .find(|m| m.id == u32::from(module_id))?;
        let size = module.size();
        if size == 0 {
            return None;
        }
        let mut bitmap = Self::new(module.base, size, 1);
        for bb in file.bbs_for_module(module_id) {
            let addr = module.base + u64::from(bb.start_offset);
            for offset in 0..u64::from(bb.size) {
                bitmap.mark(addr + offset);
            }
        }
        Some(bitmap)
    }

    /// Union two bitmaps of equal size/base/granule in place.
    ///
    /// # Errors
    /// Returns `CovError::SizeMismatch` if the bitmaps have different sizes.
    pub fn union_with(&mut self, other: &Self) -> Result<(), CovError> {
        if self.bits.len() != other.bits.len() {
            return Err(CovError::SizeMismatch {
                a: self.bits.len(),
                b: other.bits.len(),
            });
        }
        for (a, b) in self.bits.iter_mut().zip(&other.bits) {
            *a |= b;
        }
        Ok(())
    }

    /// Raw bitmap bytes (immutable view).
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bits
    }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

fn parse_hex(s: &str) -> Option<u64> {
    let s = s.trim_start_matches("0x").trim_start_matches("0X");
    u64::from_str_radix(s, 16).ok()
}

fn find_binary_split(data: &[u8]) -> Option<usize> {
    // Look for the "BB Table: N bbs" line followed immediately by binary data.
    // The binary data starts after the newline that ends the BB Table header.
    let needle = b"BB Table:";
    let pos = data.windows(needle.len()).position(|w| w == needle)?;
    // Advance to end of line
    let line_end = data[pos..].iter().position(|&b| b == b'\n')?;
    Some(pos + line_end + 1)
}

fn is_all_text(data: &[u8]) -> bool {
    // Heuristic: no bytes in 0x01..0x08 range (common in binary BB tables)
    !data.iter().any(|&b| b > 0 && b < 9)
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── DrcovVersion ─────────────────────────────────────────────────────────

    #[test]
    fn version_from_header_v2() {
        let v = DrcovVersion::from_header("DRCOV VERSION: 2").unwrap();
        assert_eq!(v, DrcovVersion::V2);
    }

    #[test]
    fn version_from_header_v3() {
        let v = DrcovVersion::from_header("DRCOV VERSION: 3").unwrap();
        assert_eq!(v, DrcovVersion::V3);
    }

    #[test]
    fn version_from_header_unknown_errors() {
        assert!(DrcovVersion::from_header("DRCOV VERSION: 5").is_err());
    }

    #[test]
    fn version_display() {
        assert_eq!(DrcovVersion::V2.to_string(), "drcov-v2");
        assert_eq!(DrcovVersion::V3.to_string(), "drcov-v3");
    }

    // ── DrcovFlavor ──────────────────────────────────────────────────────────

    #[test]
    fn flavor_dynamorio() {
        let f = DrcovFlavor::from_header("DRCOV FLAVOR: dynamorio");
        assert_eq!(f, DrcovFlavor::DynamoRio);
    }

    #[test]
    fn flavor_winafl() {
        let f = DrcovFlavor::from_header("DRCOV FLAVOR: winafl");
        assert_eq!(f, DrcovFlavor::WinAfl);
    }

    #[test]
    fn flavor_custom() {
        let f = DrcovFlavor::from_header("DRCOV FLAVOR: frida");
        assert_eq!(f, DrcovFlavor::Custom("frida".to_string()));
    }

    // ── DrcovModule ──────────────────────────────────────────────────────────

    #[test]
    fn module_parse_text_line() {
        let line = " 0, 0x400000, 0x410000, 0x401000, /bin/target";
        let m = DrcovModule::parse_text_line(line).unwrap();
        assert_eq!(m.id, 0);
        assert_eq!(m.base, 0x400000);
        assert_eq!(m.end, 0x410000);
        assert_eq!(m.entry, 0x401000);
        assert_eq!(m.path, "/bin/target");
    }

    #[test]
    fn module_contains() {
        let m = DrcovModule {
            id: 0,
            base: 0x1000,
            end: 0x2000,
            entry: 0x1000,
            path: "a.out".to_string(),
        };
        assert!(m.contains(0x1500));
        assert!(!m.contains(0x2000));
        assert!(!m.contains(0x0FFF));
    }

    #[test]
    fn module_relative_offset() {
        let m = DrcovModule {
            id: 0,
            base: 0x1000,
            end: 0x2000,
            entry: 0x1000,
            path: "a.out".to_string(),
        };
        assert_eq!(m.relative_offset(0x1100), Some(0x100));
        assert!(m.relative_offset(0x3000).is_none());
    }

    #[test]
    fn module_name_unix() {
        let m = DrcovModule {
            id: 0,
            base: 0,
            end: 1,
            entry: 0,
            path: "/usr/lib/libc.so.6".to_string(),
        };
        assert_eq!(m.name(), "libc.so.6");
    }

    #[test]
    fn module_size() {
        let m = DrcovModule {
            id: 0,
            base: 0x1000,
            end: 0x3000,
            entry: 0x1000,
            path: "x".to_string(),
        };
        assert_eq!(m.size(), 0x2000);
    }

    // ── DrcovBB ──────────────────────────────────────────────────────────────

    #[test]
    fn bb_from_to_bytes_roundtrip() {
        let bb = DrcovBB::new(0x0001_A2B3, 0x40, 0x02);
        let bytes = bb.to_bytes();
        let back = DrcovBB::from_bytes(&bytes).unwrap();
        assert_eq!(bb, back);
    }

    #[test]
    fn bb_absolute_address() {
        let modules = vec![DrcovModule {
            id: 0,
            base: 0x10_0000,
            end: 0x20_0000,
            entry: 0x10_0000,
            path: "mod.so".to_string(),
        }];
        let bb = DrcovBB::new(0x100, 0x20, 0);
        assert_eq!(bb.absolute_address(&modules), Some(0x10_0100));
    }

    #[test]
    fn bb_from_bytes_too_short() {
        assert!(DrcovBB::from_bytes(&[0u8; 4]).is_none());
    }

    // ── DrcovReader text format ───────────────────────────────────────────────

    fn sample_text_drcov() -> &'static str {
        "DRCOV VERSION: 2\nDRCOV FLAVOR: dynamorio\nModule Table: version 2, count 1\nid, base, end, entry, path\n 0, 0x400000, 0x410000, 0x401000, /bin/target\nBB Table: 2 bbs\n0x1000, 10, 0\n0x2000, 8, 0\n"
    }

    #[test]
    fn parse_text_basic() {
        let f = DrcovReader::parse_text(sample_text_drcov()).unwrap();
        assert_eq!(f.version, DrcovVersion::V2);
        assert_eq!(f.module_table.len(), 1);
        assert_eq!(f.bb_table.len(), 2);
    }

    #[test]
    fn parse_text_bb_fields() {
        let f = DrcovReader::parse_text(sample_text_drcov()).unwrap();
        let bb = &f.bb_table[0];
        assert_eq!(bb.start_offset, 0x1000);
        assert_eq!(bb.size, 10);
        assert_eq!(bb.module_id, 0);
    }

    #[test]
    fn drcov_file_bb_count() {
        let f = DrcovReader::parse_text(sample_text_drcov()).unwrap();
        assert_eq!(f.bb_count(), 2);
    }

    #[test]
    fn drcov_file_to_coverage_map() {
        let f = DrcovReader::parse_text(sample_text_drcov()).unwrap();
        let map = f.to_coverage_map();
        assert!(map.contains_key(&(0x400000 + 0x1000)));
        assert!(map.contains_key(&(0x400000 + 0x2000)));
    }

    // ── ModuleBase ───────────────────────────────────────────────────────────

    #[test]
    fn module_base_exact_lookup() {
        let mut mb = ModuleBase::new();
        mb.set("target", 0xDEAD_0000);
        assert_eq!(mb.get("target"), Some(0xDEAD_0000));
    }

    #[test]
    fn module_base_suffix_lookup() {
        let mut mb = ModuleBase::new();
        mb.set("libc.so.6", 0x7FFF_0000);
        assert_eq!(mb.get("/lib/libc.so.6"), Some(0x7FFF_0000));
    }

    #[test]
    fn module_base_miss() {
        let mb = ModuleBase::new();
        assert!(mb.get("nothing").is_none());
    }

    #[test]
    fn module_base_rebase() {
        let text = "DRCOV VERSION: 2\nDRCOV FLAVOR: dynamorio\nModule Table: version 2, count 1\nid, base, end, entry, path\n 0, 0x400000, 0x410000, 0x401000, /bin/target\nBB Table: 0 bbs\n";
        let mut f = DrcovReader::parse_text(text).unwrap();
        let mut mb = ModuleBase::new();
        mb.set("target", 0x5000_0000);
        mb.rebase(&mut f);
        assert_eq!(f.module_table[0].base, 0x5000_0000);
        assert_eq!(f.module_table[0].end, 0x5001_0000);
    }

    // ── CoverageBitmap ───────────────────────────────────────────────────────

    #[test]
    fn bitmap_mark_and_check() {
        let mut bm = CoverageBitmap::new(0x1000, 0x100, 1);
        bm.mark(0x1010);
        assert!(bm.is_covered(0x1010));
        assert!(!bm.is_covered(0x1011));
    }

    #[test]
    fn bitmap_covered_count() {
        let mut bm = CoverageBitmap::new(0x0, 0x100, 1);
        bm.mark(0x0);
        bm.mark(0x1);
        bm.mark(0x2);
        assert_eq!(bm.covered_count(), 3);
    }

    #[test]
    fn bitmap_coverage_ratio() {
        let mut bm = CoverageBitmap::new(0x0, 8, 1);
        for addr in 0..4u64 {
            bm.mark(addr);
        }
        let ratio = bm.coverage_ratio();
        assert!((ratio - 0.5).abs() < 0.15, "ratio={ratio}");
    }

    #[test]
    fn bitmap_union_with() {
        let mut a = CoverageBitmap::new(0x0, 0x10, 1);
        let mut b = CoverageBitmap::new(0x0, 0x10, 1);
        a.mark(0x0);
        b.mark(0x1);
        a.union_with(&b).unwrap();
        assert!(a.is_covered(0x0));
        assert!(a.is_covered(0x1));
    }

    #[test]
    fn bitmap_union_size_mismatch() {
        let mut a = CoverageBitmap::new(0x0, 0x10, 1);
        let b = CoverageBitmap::new(0x0, 0x20, 1);
        assert!(a.union_with(&b).is_err());
    }

    #[test]
    fn bitmap_out_of_range_mark_noop() {
        let mut bm = CoverageBitmap::new(0x1000, 0x10, 1);
        bm.mark(0x0); // before base — should not panic
        assert_eq!(bm.covered_count(), 0);
    }

    #[test]
    fn bitmap_from_drcov_file() {
        let text = "DRCOV VERSION: 2\nDRCOV FLAVOR: dynamorio\nModule Table: version 2, count 1\nid, base, end, entry, path\n 0, 0x400000, 0x410000, 0x401000, /bin/target\nBB Table: 1 bbs\n0x0, 4, 0\n";
        let f = DrcovReader::parse_text(text).unwrap();
        let bm = CoverageBitmap::from_drcov_file(&f, 0).unwrap();
        assert!(bm.is_covered(0x400000));
    }

    // ── DrcovFile helpers ────────────────────────────────────────────────────

    #[test]
    fn drcov_file_bbs_for_module() {
        let text = "DRCOV VERSION: 2\nDRCOV FLAVOR: dynamorio\nModule Table: version 2, count 2\nid, base, end, entry, path\n 0, 0x400000, 0x410000, 0x401000, /bin/a\n 1, 0x500000, 0x510000, 0x501000, /bin/b\nBB Table: 3 bbs\n0x100, 4, 0\n0x200, 4, 1\n0x300, 4, 0\n";
        let f = DrcovReader::parse_text(text).unwrap();
        assert_eq!(f.bbs_for_module(0).len(), 2);
        assert_eq!(f.bbs_for_module(1).len(), 1);
    }

    #[test]
    fn drcov_file_module_by_id() {
        let text = "DRCOV VERSION: 2\nDRCOV FLAVOR: dynamorio\nModule Table: version 2, count 1\nid, base, end, entry, path\n 0, 0x400000, 0x410000, 0x401000, /bin/target\nBB Table: 0 bbs\n";
        let f = DrcovReader::parse_text(text).unwrap();
        assert!(f.module_by_id(0).is_some());
        assert!(f.module_by_id(99).is_none());
    }

    #[test]
    fn drcov_file_module_containing() {
        let text = "DRCOV VERSION: 2\nDRCOV FLAVOR: dynamorio\nModule Table: version 2, count 1\nid, base, end, entry, path\n 0, 0x400000, 0x410000, 0x401000, /bin/target\nBB Table: 0 bbs\n";
        let f = DrcovReader::parse_text(text).unwrap();
        assert!(f.module_containing(0x405000).is_some());
        assert!(f.module_containing(0x1000).is_none());
    }

    #[test]
    fn parse_hex_with_prefix() {
        assert_eq!(parse_hex("0xFF"), Some(0xFF));
        assert_eq!(parse_hex("100"), Some(0x100));
    }

    #[test]
    fn module_base_len_is_empty() {
        let mut mb = ModuleBase::new();
        assert!(mb.is_empty());
        mb.set("x", 1);
        assert_eq!(mb.len(), 1);
        assert!(!mb.is_empty());
    }
}
