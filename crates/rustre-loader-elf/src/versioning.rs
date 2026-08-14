//! ELF symbol versioning: `VER_NEED` / `VER_DEF` table parsing.
//!
//! Symbol versioning allows shared libraries to export multiple versions of the
//! same symbol under different version names (e.g. `GLIBC_2.5`, `GLIBC_2.17`).

// ─────────────────────────────────────────────────────────────────────────────
// Data types
// ─────────────────────────────────────────────────────────────────────────────

/// One version dependency from `.gnu.version_r` (Verneed).
///
/// Each library that the binary links against has one `VersionNeed` entry,
/// which in turn has one or more `VersionNeedAux` entries listing the version
/// names required from that library.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionNeed {
    /// Name of the library that provides these versions (e.g. `"libc.so.6"`).
    pub filename: String,
    /// Version requirements from this library.
    pub aux: Vec<VersionNeedAux>,
}

/// One specific version required from a dependency.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionNeedAux {
    /// Version hash (used to match against the definition in the depended-on library).
    pub hash: u32,
    /// ELF version flags (1 = weak, 0 = normal).
    pub flags: u16,
    /// Version index assigned by the linker.
    pub other: u16,
    /// Version name (e.g. `"GLIBC_2.17"`).
    pub name: String,
}

/// One version definition from `.gnu.version_d` (Verdef).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionDef {
    /// Flags: 1 = `VER_FLG_BASE` (the base version).
    pub flags: u16,
    /// Version index.
    pub ndx: u16,
    /// Version hash.
    pub hash: u32,
    /// Version names (usually one base name plus any dependency names).
    pub names: Vec<String>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Parsing helpers
// ─────────────────────────────────────────────────────────────────────────────

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

fn read_cstr(strtab: &[u8], off: usize) -> String {
    if off >= strtab.len() {
        return String::new();
    }
    let end = strtab[off..]
        .iter()
        .position(|&b| b == 0)
        .map_or(strtab.len(), |n| off + n);
    String::from_utf8_lossy(&strtab[off..end]).to_string()
}

// ─────────────────────────────────────────────────────────────────────────────
// parse_verneed
// ─────────────────────────────────────────────────────────────────────────────

/// Parse the `.gnu.version_r` section into a list of [`VersionNeed`] entries.
///
/// # Errors
/// Returns `Err(String)` if the data is too short or the linked strtab is missing.
pub fn parse_verneed(data: &[u8], strtab: &[u8]) -> Result<Vec<VersionNeed>, String> {
    parse_verneed_endian(data, strtab, true)
}

/// Endianness-aware variant of [`parse_verneed`].
///
/// Pass `le = false` for big-endian ELF objects (e.g. `EM_SPARC`, big-endian
/// MIPS/PowerPC), where the `Elf*_Verneed` fields are stored most-significant
/// byte first.
///
/// # Errors
/// Returns `Err(String)` if the data is too short or the linked strtab is missing.
pub fn parse_verneed_endian(
    data: &[u8],
    strtab: &[u8],
    le: bool,
) -> Result<Vec<VersionNeed>, String> {
    if data.is_empty() {
        return Ok(Vec::new());
    }

    let mut needs = Vec::new();
    let mut off = 0usize;

    loop {
        // Verneed entry: vn_version(2), vn_cnt(2), vn_file(4), vn_aux(4), vn_next(4)
        let _version = read_u16(data, off, le).ok_or_else(|| format!("short verneed at {off}"))?;
        let cnt =
            read_u16(data, off + 2, le).ok_or_else(|| format!("short verneed.cnt at {off}"))?;
        let file_off = read_u32(data, off + 4, le)
            .ok_or_else(|| format!("short verneed.file at {off}"))? as usize;
        let aux_off = read_u32(data, off + 8, le)
            .ok_or_else(|| format!("short verneed.aux at {off}"))? as usize;
        let next_off = read_u32(data, off + 12, le)
            .ok_or_else(|| format!("short verneed.next at {off}"))? as usize;

        let filename = read_cstr(strtab, file_off);

        // Parse aux entries.
        let mut aux_list = Vec::with_capacity(cnt as usize);
        let mut aux_cursor = off + aux_off;
        for _ in 0..cnt {
            let hash = read_u32(data, aux_cursor, le)
                .ok_or_else(|| format!("short verneedaux.hash at {aux_cursor}"))?;
            let flags = read_u16(data, aux_cursor + 4, le)
                .ok_or_else(|| format!("short verneedaux.flags at {aux_cursor}"))?;
            let other = read_u16(data, aux_cursor + 6, le)
                .ok_or_else(|| format!("short verneedaux.other at {aux_cursor}"))?;
            let name_off = read_u32(data, aux_cursor + 8, le)
                .ok_or_else(|| format!("short verneedaux.name at {aux_cursor}"))?
                as usize;
            let next_aux = read_u32(data, aux_cursor + 12, le)
                .ok_or_else(|| format!("short verneedaux.next at {aux_cursor}"))?
                as usize;

            let name = read_cstr(strtab, name_off);
            aux_list.push(VersionNeedAux {
                hash,
                flags,
                other,
                name,
            });
            if next_aux == 0 {
                break;
            }
            aux_cursor += next_aux;
        }

        needs.push(VersionNeed {
            filename,
            aux: aux_list,
        });

        if next_off == 0 {
            break;
        }
        off += next_off;
    }

    Ok(needs)
}

// ─────────────────────────────────────────────────────────────────────────────
// parse_verdef
// ─────────────────────────────────────────────────────────────────────────────

/// Parse the `.gnu.version_d` section into a list of [`VersionDef`] entries.
///
/// # Errors
/// Returns `Err(String)` if the data is malformed.
pub fn parse_verdef(data: &[u8], strtab: &[u8]) -> Result<Vec<VersionDef>, String> {
    parse_verdef_endian(data, strtab, true)
}

/// Endianness-aware variant of [`parse_verdef`].
///
/// Pass `le = false` for big-endian ELF objects.
///
/// # Errors
/// Returns `Err(String)` if the data is malformed.
pub fn parse_verdef_endian(
    data: &[u8],
    strtab: &[u8],
    le: bool,
) -> Result<Vec<VersionDef>, String> {
    if data.is_empty() {
        return Ok(Vec::new());
    }

    let mut defs = Vec::new();
    let mut off = 0usize;

    loop {
        // Verdef entry: vd_version(2), vd_flags(2), vd_ndx(2), vd_cnt(2),
        //               vd_hash(4), vd_aux(4), vd_next(4)
        let _version = read_u16(data, off, le).ok_or_else(|| format!("short verdef at {off}"))?;
        let flags =
            read_u16(data, off + 2, le).ok_or_else(|| format!("short verdef.flags at {off}"))?;
        let ndx = read_u16(data, off + 4, le).ok_or_else(|| format!("short verdef.ndx at {off}"))?;
        let cnt = read_u16(data, off + 6, le).ok_or_else(|| format!("short verdef.cnt at {off}"))?;
        let hash =
            read_u32(data, off + 8, le).ok_or_else(|| format!("short verdef.hash at {off}"))?;
        let aux_off = read_u32(data, off + 12, le)
            .ok_or_else(|| format!("short verdef.aux at {off}"))? as usize;
        let next_off = read_u32(data, off + 16, le)
            .ok_or_else(|| format!("short verdef.next at {off}"))? as usize;

        // Parse verdaux: each is vda_name(4), vda_next(4)
        let mut names = Vec::with_capacity(cnt as usize);
        let mut aux_cursor = off + aux_off;
        for _ in 0..cnt {
            let name_off = read_u32(data, aux_cursor, le)
                .ok_or_else(|| format!("short verdaux.name at {aux_cursor}"))?
                as usize;
            let next_aux = read_u32(data, aux_cursor + 4, le)
                .ok_or_else(|| format!("short verdaux.next at {aux_cursor}"))?
                as usize;
            names.push(read_cstr(strtab, name_off));
            if next_aux == 0 {
                break;
            }
            aux_cursor += next_aux;
        }

        defs.push(VersionDef {
            flags,
            ndx,
            hash,
            names,
        });

        if next_off == 0 {
            break;
        }
        off += next_off;
    }

    Ok(defs)
}

// ─────────────────────────────────────────────────────────────────────────────
// VersionTable — per-symbol version index from `.gnu.version`
// ─────────────────────────────────────────────────────────────────────────────

/// The `.gnu.version` section: one `u16` per dynamic symbol giving its version
/// index.
#[derive(Debug, Clone)]
pub struct VersionTable {
    /// `versions[i]` is the version index of dynamic symbol `i`.
    pub versions: Vec<u16>,
}

impl VersionTable {
    /// Parse the `.gnu.version` section (an array of `u16`s).
    #[must_use]
    pub fn parse(data: &[u8]) -> Self {
        Self::parse_endian(data, true)
    }

    /// Endianness-aware variant of [`VersionTable::parse`].
    ///
    /// Pass `le = false` for big-endian ELF objects.
    #[must_use]
    pub fn parse_endian(data: &[u8], le: bool) -> Self {
        let mut versions = Vec::with_capacity(data.len() / 2);
        let mut off = 0;
        while off + 1 < data.len() {
            let b = [data[off], data[off + 1]];
            versions.push(if le {
                u16::from_le_bytes(b)
            } else {
                u16::from_be_bytes(b)
            });
            off += 2;
        }
        Self { versions }
    }

    /// Return the version index for symbol `sym_idx`, if available.
    #[must_use]
    pub fn get(&self, sym_idx: usize) -> Option<u16> {
        self.versions.get(sym_idx).copied()
    }

    /// Number of entries.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.versions.len()
    }

    /// Returns `true` if empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.versions.is_empty()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── GNU hash of version strings (sanity) ──────────────────────────────────

    #[test]
    fn test_version_table_parse_empty() {
        let vt = VersionTable::parse(&[]);
        assert!(vt.is_empty());
        assert!(vt.get(0).is_none());
    }

    #[test]
    fn test_version_table_parse_single() {
        let data: Vec<u8> = vec![0x01, 0x00]; // version index = 1
        let vt = VersionTable::parse(&data);
        assert_eq!(vt.len(), 1);
        assert_eq!(vt.get(0), Some(1));
    }

    #[test]
    fn test_version_table_parse_multiple() {
        let data: Vec<u8> = vec![
            0x01, 0x00, // sym 0: version 1
            0x02, 0x00, // sym 1: version 2
            0x00, 0x00, // sym 2: version 0 (local / undefined)
        ];
        let vt = VersionTable::parse(&data);
        assert_eq!(vt.len(), 3);
        assert_eq!(vt.get(1), Some(2));
        assert_eq!(vt.get(2), Some(0));
        assert!(vt.get(99).is_none());
    }

    // ── Verneed parsing ───────────────────────────────────────────────────────

    fn make_verneed_section() -> (Vec<u8>, Vec<u8>) {
        // Build a minimal .gnu.version_r with one entry and one aux.
        //
        // Verneed layout (LE, 64-bit same as 32-bit for version/cnt/file/aux/next):
        //   off 0:  vn_version=1 (2)
        //   off 2:  vn_cnt=1 (2)
        //   off 4:  vn_file → strtab off for "libc.so.6" (4)
        //   off 8:  vn_aux → relative offset to first aux = 16 (4)
        //   off 12: vn_next = 0 (4)  [only one entry]
        //   [aux at off 16]
        //   off 16: vna_hash (4)
        //   off 20: vna_flags=0 (2)
        //   off 22: vna_other=2 (2)
        //   off 24: vna_name → strtab off for "GLIBC_2.17" (4)
        //   off 28: vna_next=0 (4)
        let mut data = vec![0u8; 32];
        // vn_version = 1
        data[0..2].copy_from_slice(&1u16.to_le_bytes());
        // vn_cnt = 1
        data[2..4].copy_from_slice(&1u16.to_le_bytes());
        // vn_file = strtab offset 0  ("libc.so.6\0")
        data[4..8].copy_from_slice(&0u32.to_le_bytes());
        // vn_aux = 16 (offset from start of this entry)
        data[8..12].copy_from_slice(&16u32.to_le_bytes());
        // vn_next = 0
        data[12..16].copy_from_slice(&0u32.to_le_bytes());
        // aux: vna_hash = 0xDEAD
        data[16..20].copy_from_slice(&0xDEADu32.to_le_bytes());
        // vna_flags = 0
        data[20..22].copy_from_slice(&0u16.to_le_bytes());
        // vna_other = 2
        data[22..24].copy_from_slice(&2u16.to_le_bytes());
        // vna_name = strtab offset 10 ("GLIBC_2.17\0")
        data[24..28].copy_from_slice(&10u32.to_le_bytes());
        // vna_next = 0
        data[28..32].copy_from_slice(&0u32.to_le_bytes());

        // strtab: "libc.so.6\0GLIBC_2.17\0"
        let strtab = b"libc.so.6\0GLIBC_2.17\0".to_vec();
        (data, strtab)
    }

    #[test]
    fn test_parse_verneed_basic() {
        let (data, strtab) = make_verneed_section();
        let needs = parse_verneed(&data, &strtab).unwrap();
        assert_eq!(needs.len(), 1);
        assert_eq!(needs[0].filename, "libc.so.6");
        assert_eq!(needs[0].aux.len(), 1);
        assert_eq!(needs[0].aux[0].name, "GLIBC_2.17");
        assert_eq!(needs[0].aux[0].other, 2);
        assert_eq!(needs[0].aux[0].hash, 0xDEAD);
    }

    #[test]
    fn test_parse_verneed_empty() {
        let result = parse_verneed(&[], b"").unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn test_parse_verneed_short_data() {
        assert!(parse_verneed(&[0u8; 2], b"").is_err());
    }

    // ── Verdef parsing ────────────────────────────────────────────────────────

    fn make_verdef_section() -> (Vec<u8>, Vec<u8>) {
        // Verdef layout:
        //   off 0:  vd_version=1 (2)
        //   off 2:  vd_flags=1 (VER_FLG_BASE) (2)
        //   off 4:  vd_ndx=1 (2)
        //   off 6:  vd_cnt=1 (2)
        //   off 8:  vd_hash=0xABCD (4)
        //   off 12: vd_aux=20 (4) [offset from entry start to first verdaux]
        //   off 16: vd_next=0 (4)
        //   [padding to off 20]
        //   off 20: vda_name=0 (strtab offset for "MYLIB_1.0") (4)
        //   off 24: vda_next=0 (4)
        let mut data = vec![0u8; 28];
        data[0..2].copy_from_slice(&1u16.to_le_bytes()); // vd_version
        data[2..4].copy_from_slice(&1u16.to_le_bytes()); // vd_flags (VER_FLG_BASE)
        data[4..6].copy_from_slice(&1u16.to_le_bytes()); // vd_ndx
        data[6..8].copy_from_slice(&1u16.to_le_bytes()); // vd_cnt
        data[8..12].copy_from_slice(&0xABCDu32.to_le_bytes()); // vd_hash
        data[12..16].copy_from_slice(&20u32.to_le_bytes()); // vd_aux
        data[16..20].copy_from_slice(&0u32.to_le_bytes()); // vd_next
        // verdaux at off 20:
        data[20..24].copy_from_slice(&0u32.to_le_bytes()); // vda_name = 0 → "MYLIB_1.0"
        data[24..28].copy_from_slice(&0u32.to_le_bytes()); // vda_next = 0

        let strtab = b"MYLIB_1.0\0".to_vec();
        (data, strtab)
    }

    #[test]
    fn test_parse_verdef_basic() {
        let (data, strtab) = make_verdef_section();
        let defs = parse_verdef(&data, &strtab).unwrap();
        assert_eq!(defs.len(), 1);
        assert_eq!(defs[0].flags, 1);
        assert_eq!(defs[0].ndx, 1);
        assert_eq!(defs[0].hash, 0xABCD);
        assert_eq!(defs[0].names, vec!["MYLIB_1.0"]);
    }

    #[test]
    fn test_parse_verdef_empty() {
        let result = parse_verdef(&[], b"").unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn test_parse_verdef_short_data() {
        assert!(parse_verdef(&[0u8; 3], b"").is_err());
    }

    #[test]
    fn test_version_need_aux_fields() {
        let aux = VersionNeedAux {
            hash: 0xCAFE,
            flags: 0,
            other: 3,
            name: "GLIBC_2.5".into(),
        };
        assert_eq!(aux.name, "GLIBC_2.5");
        assert_eq!(aux.other, 3);
    }

    // ── Big-endian support ────────────────────────────────────────────────────

    #[test]
    fn test_version_table_parse_big_endian() {
        // 0x0001, 0x0002 stored MSB-first.
        let data: Vec<u8> = vec![0x00, 0x01, 0x00, 0x02];
        let be = VersionTable::parse_endian(&data, false);
        assert_eq!(be.get(0), Some(1));
        assert_eq!(be.get(1), Some(2));
        // The default (LE) reading of the same bytes is byte-swapped.
        let le = VersionTable::parse(&data);
        assert_eq!(le.get(0), Some(0x0100));
    }

    #[test]
    fn test_parse_verdef_big_endian() {
        let mut data = vec![0u8; 28];
        data[0..2].copy_from_slice(&1u16.to_be_bytes()); // vd_version
        data[2..4].copy_from_slice(&1u16.to_be_bytes()); // vd_flags
        data[4..6].copy_from_slice(&1u16.to_be_bytes()); // vd_ndx
        data[6..8].copy_from_slice(&1u16.to_be_bytes()); // vd_cnt
        data[8..12].copy_from_slice(&0xABCDu32.to_be_bytes()); // vd_hash
        data[12..16].copy_from_slice(&20u32.to_be_bytes()); // vd_aux
        data[16..20].copy_from_slice(&0u32.to_be_bytes()); // vd_next
        data[20..24].copy_from_slice(&0u32.to_be_bytes()); // vda_name
        data[24..28].copy_from_slice(&0u32.to_be_bytes()); // vda_next
        let strtab = b"MYLIB_1.0\0".to_vec();

        let defs = parse_verdef_endian(&data, &strtab, false).unwrap();
        assert_eq!(defs.len(), 1);
        assert_eq!(defs[0].ndx, 1);
        assert_eq!(defs[0].hash, 0xABCD);
        assert_eq!(defs[0].names, vec!["MYLIB_1.0"]);
    }

    #[test]
    fn test_parse_verneed_big_endian() {
        // vn_version(2), vn_cnt(2), vn_file(4), vn_aux(4), vn_next(4) = 16 bytes,
        // then one Vernaux at off 16: hash(4), flags(2), other(2), name(4), next(4).
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

        let strtab = b"libc.so.6\0GLIBC_2.5\0".to_vec();
        let needs = parse_verneed_endian(&data, &strtab, false).unwrap();
        assert_eq!(needs.len(), 1);
        assert_eq!(needs[0].filename, "libc.so.6");
        assert_eq!(needs[0].aux.len(), 1);
        assert_eq!(needs[0].aux[0].hash, 0xCAFE);
        assert_eq!(needs[0].aux[0].other, 3);
        assert_eq!(needs[0].aux[0].name, "GLIBC_2.5");
    }

    #[test]
    fn test_le_wrappers_match_endian_variants() {
        // The historical LE entry points must stay exactly equivalent to the new
        // endian-aware ones called with le = true.
        let (vd, vd_str) = make_verdef_section();
        assert_eq!(
            parse_verdef(&vd, &vd_str).unwrap().len(),
            parse_verdef_endian(&vd, &vd_str, true).unwrap().len()
        );
        let (vn, vn_str) = make_verneed_section();
        assert_eq!(
            parse_verneed(&vn, &vn_str).unwrap()[0].filename,
            parse_verneed_endian(&vn, &vn_str, true).unwrap()[0].filename
        );
    }

    #[test]
    fn test_version_def_clone() {
        let def = VersionDef {
            flags: 1,
            ndx: 2,
            hash: 0xBEEF,
            names: vec!["VER_1".into()],
        };
        let cloned = def.clone();
        assert_eq!(cloned.names, def.names);
    }
}
