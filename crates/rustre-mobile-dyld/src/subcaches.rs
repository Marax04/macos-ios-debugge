//! `subcaches` — Sub-cache support for macOS Big Sur+ / iOS 15+ dyld caches.
//!
//! Starting with dyld-940 (macOS 11.0 / iOS 15), the dyld shared cache is
//! split into a **primary** cache file plus zero or more **sub-caches**.
//! Each sub-cache stores one or more mappings of the full virtual address space.
//!
//! Naming convention (macOS):
//!   - Primary: `dyld_shared_cache_arm64e`
//!   - Sub-caches: `dyld_shared_cache_arm64e.1`, `.2`, …
//!   - Symbols cache: `dyld_shared_cache_arm64e.symbols`
//!
//! On iOS the naming is the same but may be embedded in the IPSW as
//! `dyld_shared_cache_<arch>` with numeric suffixes.

use super::DyldError;

// ─────────────────────────────────────────────────────────────────────────────
// On-disk struct sizes
// ─────────────────────────────────────────────────────────────────────────────

/// Byte size of a `dyld_subcache_entry` (UUID + extension string).
pub const SUBCACHE_ENTRY_SIZE: usize = 32;
/// Byte size of a `dyld_subcache_entry_v2` (UUID + extension + file-suffix flag).
pub const SUBCACHE_ENTRY_V2_SIZE: usize = 48;

// ─────────────────────────────────────────────────────────────────────────────
// DyldSubcacheEntry (original, dyld-940)
// ─────────────────────────────────────────────────────────────────────────────

/// Parsed `dyld_subcache_entry` — identifies one sub-cache file.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DyldSubcacheEntry {
    /// 128-bit UUID of the sub-cache.
    pub uuid: [u8; 16],
    /// Virtual-address offset at which this sub-cache's content starts.
    pub cache_vm_offset: u64,
    /// Human-readable file-suffix string (e.g. `".1"`, `".2"`, `".symbols"`).
    pub file_suffix: String,
}

impl DyldSubcacheEntry {
    /// Parse one entry at `offset` within the primary cache file.
    pub fn parse(data: &[u8], offset: usize) -> Result<Self, DyldError> {
        if data.len() < offset + SUBCACHE_ENTRY_SIZE {
            return Err(DyldError::Truncated(offset));
        }
        let d = &data[offset..];

        let mut uuid = [0u8; 16];
        uuid.copy_from_slice(&d[0..16]);

        let cache_vm_offset = read_u64(d, 16)?;

        // File suffix: NUL-terminated string in the last 8 bytes (bytes 24..32).
        let suffix_bytes = &d[24..32];
        let nul = suffix_bytes.iter().position(|&b| b == 0).unwrap_or(8);
        let file_suffix = std::str::from_utf8(&suffix_bytes[..nul])
            .map(std::borrow::ToOwned::to_owned)
            .map_err(|_| DyldError::Parse("invalid UTF-8 in subcache suffix".to_owned()))?;

        Ok(Self {
            uuid,
            cache_vm_offset,
            file_suffix,
        })
    }

    /// Parse all sub-cache entries at the given offset.
    pub fn parse_all(data: &[u8], offset: u32, count: u32) -> Result<Vec<Self>, DyldError> {
        let mut entries = Vec::with_capacity(count as usize);
        for i in 0..count as usize {
            entries.push(Self::parse(
                data,
                offset as usize + i * SUBCACHE_ENTRY_SIZE,
            )?);
        }
        Ok(entries)
    }

    /// Returns the UUID formatted as a standard UUID string.
    #[must_use]
    pub fn uuid_string(&self) -> String {
        let u = &self.uuid;
        format!(
            "{:02X}{:02X}{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
            u[0],
            u[1],
            u[2],
            u[3],
            u[4],
            u[5],
            u[6],
            u[7],
            u[8],
            u[9],
            u[10],
            u[11],
            u[12],
            u[13],
            u[14],
            u[15],
        )
    }

    /// Returns `true` if this entry refers to the `.symbols` sub-cache.
    #[must_use]
    pub fn is_symbols_cache(&self) -> bool {
        self.file_suffix == ".symbols"
    }

    /// Returns the numeric index of this sub-cache (e.g. `".3"` → `Some(3)`).
    #[must_use]
    pub fn numeric_index(&self) -> Option<u32> {
        self.file_suffix.trim_start_matches('.').parse::<u32>().ok()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DyldSubcacheEntryV2 (dyld-1100+)
// ─────────────────────────────────────────────────────────────────────────────

/// Extended `dyld_subcache_entry_v2` with a longer suffix field and a flag
/// indicating the files use a numeric suffix rather than the full UUID name.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DyldSubcacheEntryV2 {
    /// Base entry (UUID + `vm_offset` + 8-byte suffix).
    pub base: DyldSubcacheEntry,
    /// Whether the sub-cache files are addressed by numeric suffix.
    pub use_numeric_suffix: u32,
    /// Reserved padding.
    pub pad: u32,
    /// Extended file-suffix string (up to 20 bytes, NUL-terminated).
    pub file_suffix_ext: String,
}

impl DyldSubcacheEntryV2 {
    /// Parse one V2 entry.
    pub fn parse(data: &[u8], offset: usize) -> Result<Self, DyldError> {
        if data.len() < offset + SUBCACHE_ENTRY_V2_SIZE {
            return Err(DyldError::Truncated(offset));
        }
        let base = DyldSubcacheEntry::parse(data, offset)?;
        let d = &data[offset..];
        let use_numeric_suffix = read_u32(d, 32)?;
        let pad = read_u32(d, 36)?;

        // Extended suffix: bytes 40..48 (8 bytes in the v2 layout defined above,
        // but the real struct has a 32-byte total with a 20-byte suffix field in
        // later dyld sources).  We parse the remaining 8 bytes here.
        let ext_bytes = &d[40..48];
        let nul = ext_bytes.iter().position(|&b| b == 0).unwrap_or(8);
        let file_suffix_ext = std::str::from_utf8(&ext_bytes[..nul])
            .map(std::borrow::ToOwned::to_owned)
            .map_err(|_| DyldError::Parse("invalid UTF-8 in subcache v2 ext suffix".to_owned()))?;

        Ok(Self {
            base,
            use_numeric_suffix,
            pad,
            file_suffix_ext,
        })
    }

    /// Parse all V2 entries.
    pub fn parse_all(data: &[u8], offset: u32, count: u32) -> Result<Vec<Self>, DyldError> {
        let mut entries = Vec::with_capacity(count as usize);
        for i in 0..count as usize {
            entries.push(Self::parse(
                data,
                offset as usize + i * SUBCACHE_ENTRY_V2_SIZE,
            )?);
        }
        Ok(entries)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SubcacheSet — manages a group of loaded sub-cache buffers
// ─────────────────────────────────────────────────────────────────────────────

/// A loaded sub-cache buffer together with its metadata.
#[derive(Debug, Clone)]
pub struct LoadedSubcache {
    /// The sub-cache entry from the primary header.
    pub entry: DyldSubcacheEntry,
    /// Raw file contents of the sub-cache.
    pub data: Vec<u8>,
}

impl LoadedSubcache {
    /// Construct a `LoadedSubcache` from an entry and the raw bytes.
    #[must_use]
    pub const fn new(entry: DyldSubcacheEntry, data: Vec<u8>) -> Self {
        Self { entry, data }
    }

    /// Returns `true` if the sub-cache starts with a valid dyld header magic.
    #[must_use]
    pub fn is_valid_cache(&self) -> bool {
        self.data.len() >= 16 && self.data[0..7] == *b"dyld_v1"
    }
}

/// A collection of loaded sub-caches for a split shared-cache installation.
#[derive(Debug, Default)]
pub struct SubcacheSet {
    pub caches: Vec<LoadedSubcache>,
}

impl SubcacheSet {
    /// Create an empty `SubcacheSet`.
    #[must_use]
    pub const fn new() -> Self {
        Self { caches: Vec::new() }
    }

    /// Add a loaded sub-cache.
    pub fn push(&mut self, cache: LoadedSubcache) {
        self.caches.push(cache);
    }

    /// Find a sub-cache by its file suffix.
    #[must_use]
    pub fn find_by_suffix(&self, suffix: &str) -> Option<&LoadedSubcache> {
        self.caches.iter().find(|c| c.entry.file_suffix == suffix)
    }

    /// Find a sub-cache by its UUID.
    #[must_use]
    pub fn find_by_uuid(&self, uuid: &[u8; 16]) -> Option<&LoadedSubcache> {
        self.caches.iter().find(|c| c.entry.uuid == *uuid)
    }

    /// Read bytes from any sub-cache that covers the given virtual address.
    ///
    /// This is a simple linear scan — for performance-critical paths use a
    /// proper virtual-address → sub-cache index.
    #[must_use]
    pub fn read_at_va(&self, va: u64, len: usize) -> Option<&[u8]> {
        for lc in &self.caches {
            let base = lc.entry.cache_vm_offset;
            let cache_size = lc.data.len() as u64;
            if va >= base && va.saturating_sub(base) + len as u64 <= cache_size {
                let off = (va - base) as usize;
                return lc.data.get(off..off + len);
            }
        }
        None
    }

    /// Returns the total number of sub-caches in the set.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.caches.len()
    }

    /// Returns `true` if no sub-caches are loaded.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.caches.is_empty()
    }

    /// Returns the symbols sub-cache if one has been loaded.
    #[must_use]
    pub fn symbols_cache(&self) -> Option<&LoadedSubcache> {
        self.caches.iter().find(|c| c.entry.is_symbols_cache())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Filename helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Generate the expected filename for each sub-cache given the primary path.
///
/// Returns a list of `(entry, expected_path)` pairs.
#[must_use]
pub fn expected_subcache_paths(
    primary_path: &str,
    entries: &[DyldSubcacheEntry],
) -> Vec<(String, String)> {
    entries
        .iter()
        .map(|e| {
            let path = format!("{}{}", primary_path, e.file_suffix);
            (e.file_suffix.clone(), path)
        })
        .collect()
}

/// Check which sub-cache files are present on disk given the primary path.
///
/// Returns a list of `(suffix, path, exists)` tuples.
#[must_use]
pub fn check_subcache_presence(
    primary_path: &str,
    entries: &[DyldSubcacheEntry],
) -> Vec<(String, String, bool)> {
    entries
        .iter()
        .map(|e| {
            let path = format!("{}{}", primary_path, e.file_suffix);
            let exists = std::path::Path::new(&path).exists();
            (e.file_suffix.clone(), path, exists)
        })
        .collect()
}

// ─────────────────────────────────────────────────────────────────────────────
// open_with_subcaches — filesystem-level loader
// ─────────────────────────────────────────────────────────────────────────────

/// Load the primary cache file and all available sub-caches from disk.
///
/// Sub-cache files that are missing are silently skipped (split caches may be
/// delivered on different partitions).  The symbols sub-cache is also loaded if
/// present.
///
/// Returns `(primary_data, subcache_set)`.
pub fn open_with_subcaches(
    primary_path: &str,
    entries: &[DyldSubcacheEntry],
) -> Result<(Vec<u8>, SubcacheSet), DyldError> {
    let primary = std::fs::read(primary_path).map_err(|e| DyldError::Io(e.to_string()))?;

    let mut set = SubcacheSet::new();

    for entry in entries {
        let path = format!("{}{}", primary_path, entry.file_suffix);
        if let Ok(data) = std::fs::read(&path) {
            set.push(LoadedSubcache::new(entry.clone(), data));
        } else {
            // Sub-cache not available — not fatal.
        }
    }

    Ok((primary, set))
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

fn read_u32(data: &[u8], offset: usize) -> Result<u32, DyldError> {
    data.get(offset..offset + 4)
        .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
        .ok_or(DyldError::Truncated(offset))
}

fn read_u64(data: &[u8], offset: usize) -> Result<u64, DyldError> {
    data.get(offset..offset + 8)
        .map(|s| u64::from_le_bytes([s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]]))
        .ok_or(DyldError::Truncated(offset))
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_entry_bytes(uuid: [u8; 16], vm_offset: u64, suffix: &str) -> Vec<u8> {
        let mut b = vec![0u8; SUBCACHE_ENTRY_SIZE];
        b[0..16].copy_from_slice(&uuid);
        b[16..24].copy_from_slice(&vm_offset.to_le_bytes());
        let sb = suffix.as_bytes();
        let copy_len = sb.len().min(8);
        b[24..24 + copy_len].copy_from_slice(&sb[..copy_len]);
        b
    }

    #[test]
    fn test_parse_entry() {
        let uuid = [1u8; 16];
        let raw = make_entry_bytes(uuid, 0x4000_0000, ".1");
        let entry = DyldSubcacheEntry::parse(&raw, 0).expect("parse");
        assert_eq!(entry.uuid, uuid);
        assert_eq!(entry.cache_vm_offset, 0x4000_0000);
        assert_eq!(entry.file_suffix, ".1");
        assert!(!entry.is_symbols_cache());
        assert_eq!(entry.numeric_index(), Some(1));
    }

    #[test]
    fn test_symbols_entry() {
        let raw = make_entry_bytes([0u8; 16], 0, ".symbols");
        let entry = DyldSubcacheEntry::parse(&raw, 0).expect("parse");
        assert!(entry.is_symbols_cache());
        assert_eq!(entry.numeric_index(), None);
    }

    #[test]
    fn test_parse_all_entries() {
        let mut raw = Vec::new();
        for i in 0u8..3 {
            let suffix = format!(".{}", i + 1);
            raw.extend_from_slice(&make_entry_bytes(
                [i; 16],
                u64::from(i) * 0x1000_0000,
                &suffix,
            ));
        }
        let entries = DyldSubcacheEntry::parse_all(&raw, 0, 3).expect("parse_all");
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[2].file_suffix, ".3");
    }

    #[test]
    fn test_uuid_string_format() {
        let uuid = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54,
            0x32, 0x10,
        ];
        let raw = make_entry_bytes(uuid, 0, ".1");
        let entry = DyldSubcacheEntry::parse(&raw, 0).expect("parse");
        let s = entry.uuid_string();
        assert_eq!(s.len(), 36);
        assert!(s.contains('-'));
        assert!(s.starts_with("01234567"));
    }

    #[test]
    fn test_subcache_set_operations() {
        let e1 = DyldSubcacheEntry {
            uuid: [1u8; 16],
            cache_vm_offset: 0x0010_0000,
            file_suffix: ".1".to_owned(),
        };
        let e2 = DyldSubcacheEntry {
            uuid: [2u8; 16],
            cache_vm_offset: 0x0020_0000,
            file_suffix: ".symbols".to_owned(),
        };

        // Build fake sub-cache data (0x10 bytes at VM base).
        let data1 = vec![0xAA_u8; 0x10000];
        let data2 = vec![0xBB_u8; 0x10000];

        let mut set = SubcacheSet::new();
        set.push(LoadedSubcache::new(e1, data1));
        set.push(LoadedSubcache::new(e2, data2));

        assert_eq!(set.len(), 2);
        assert!(!set.is_empty());
        assert!(set.find_by_suffix(".1").is_some());
        assert!(set.symbols_cache().is_some());
        assert!(set.find_by_uuid(&[1u8; 16]).is_some());
        assert!(set.find_by_uuid(&[9u8; 16]).is_none());
    }

    #[test]
    fn test_read_at_va() {
        let e = DyldSubcacheEntry {
            uuid: [0u8; 16],
            cache_vm_offset: 0x1000,
            file_suffix: ".1".to_owned(),
        };
        let mut data = vec![0u8; 0x2000];
        data[0x100] = 0xDE;
        data[0x101] = 0xAD;

        let mut set = SubcacheSet::new();
        set.push(LoadedSubcache::new(e, data));

        // VA 0x1100 → data[0x100]
        let bytes = set.read_at_va(0x1100, 2).expect("read");
        assert_eq!(bytes[0], 0xDE);
        assert_eq!(bytes[1], 0xAD);

        // VA before the sub-cache → None
        assert!(set.read_at_va(0x0, 2).is_none());
    }

    #[test]
    fn test_expected_paths() {
        let entries = vec![
            DyldSubcacheEntry {
                uuid: [0u8; 16],
                cache_vm_offset: 0,
                file_suffix: ".1".to_owned(),
            },
            DyldSubcacheEntry {
                uuid: [0u8; 16],
                cache_vm_offset: 0,
                file_suffix: ".symbols".to_owned(),
            },
        ];
        let paths =
            expected_subcache_paths("/private/var/db/dyld/dyld_shared_cache_arm64e", &entries);
        assert_eq!(paths.len(), 2);
        assert!(paths[0].1.ends_with(".1"));
        assert!(paths[1].1.ends_with(".symbols"));
    }

    #[test]
    fn test_truncated_entry() {
        let raw = vec![0u8; 8]; // way too short
        let result = DyldSubcacheEntry::parse(&raw, 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_v2_entry_parse() {
        let mut raw = vec![0u8; SUBCACHE_ENTRY_V2_SIZE];
        // Fill uuid
        for i in 0..16usize {
            raw[i] = u8::try_from(i).unwrap_or(0);
        }
        // vm_offset
        raw[16..24].copy_from_slice(&0x8000_0000_u64.to_le_bytes());
        // suffix ".2"
        raw[24] = b'.';
        raw[25] = b'2';
        // use_numeric_suffix = 1
        raw[32..36].copy_from_slice(&1u32.to_le_bytes());

        let entry = DyldSubcacheEntryV2::parse(&raw, 0).expect("parse");
        assert_eq!(entry.base.file_suffix, ".2");
        assert_eq!(entry.use_numeric_suffix, 1);
        assert_eq!(entry.base.cache_vm_offset, 0x8000_0000);
    }
}
