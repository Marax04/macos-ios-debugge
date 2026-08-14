//! OLE2 File Allocation Table (FAT) and Mini-FAT parsing.
//!
//! Implements the sector-chain model for both the regular FAT (512-/4096-byte
//! sectors) and the Mini-FAT (64-byte sectors stored inside the mini-stream).

use super::{OleDirectoryEntry, OleError, OleHeader};

// ── Sector sentinel constants ─────────────────────────────────────────────────

/// Marks the last sector in a chain.
pub const ENDOFCHAIN: u32 = 0xFFFF_FFFE;
/// Marks a free (unused) sector.
pub const FREESECT: u32 = 0xFFFF_FFFF;
/// Marks a sector used for FAT data.
pub const FATSECT: u32 = 0xFFFF_FFFD;
/// Marks a sector used for the DIFAT chain.
pub const DIFSECT: u32 = 0xFFFF_FFFC;
/// Marks the absence of a child/sibling in the directory tree.
pub const NOSTREAM: u32 = 0xFFFF_FFFF;

// ── FatChain ──────────────────────────────────────────────────────────────────

/// An ordered list of sector indices forming a single chain.
#[derive(Debug, Clone, Default)]
pub struct FatChain {
    /// Sector numbers in chain order.
    pub sectors: Vec<u32>,
}

impl FatChain {
    /// Returns `true` if the chain contains no sectors.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.sectors.is_empty()
    }

    /// Returns the number of sectors in the chain.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.sectors.len()
    }

    /// Returns the total byte capacity of all sectors in this chain.
    #[must_use]
    pub const fn total_bytes(&self, sector_size: usize) -> usize {
        self.sectors.len() * sector_size
    }
}

// ── Fat ───────────────────────────────────────────────────────────────────────

/// The File Allocation Table for a Compound File Binary.
#[derive(Debug, Clone, Default)]
pub struct Fat {
    /// Raw FAT entries (sector → next sector or sentinel).
    pub entries: Vec<u32>,
}

impl Fat {
    /// Parse all FAT sectors described by the header's DIFAT array.
    ///
    /// # Errors
    /// Returns `OleError::ParseError` if FAT sector offsets are out of bounds.
    pub fn parse(data: &[u8], header: &OleHeader) -> Result<Self, OleError> {
        let sector_size = header.sector_size_bytes() as usize;
        let entries_per_sector = sector_size / 4;
        let mut fat_entries = Vec::new();

        // The first 109 DIFAT entries are at bytes 76..512 of the header.
        // Each is a u32 sector index (or FREESECT if unused).
        let difat_count = ((512usize.saturating_sub(76)) / 4).min(109);

        for difat_idx in 0..difat_count {
            let byte_pos = 76 + difat_idx * 4;
            if byte_pos + 4 > data.len() {
                break;
            }
            let sector_id =
                u32::from_le_bytes(data[byte_pos..byte_pos + 4].try_into().map_err(|_| {
                    OleError::ParseError(format!("DIFAT[{difat_idx}] out of bounds"))
                })?);

            if sector_id == FREESECT || sector_id == NOSTREAM || sector_id == FATSECT {
                continue;
            }

            // Sector offset in file: (sector_id + 1) * sector_size
            let sector_off = match (sector_id as usize)
                .checked_add(1)
                .and_then(|n| n.checked_mul(sector_size))
            {
                Some(v) => v,
                None => continue,
            };
            if sector_off.checked_add(sector_size).is_none_or(|end| end > data.len()) {
                // Sector is beyond the file — skip gracefully
                continue;
            }

            for entry_idx in 0..entries_per_sector {
                let ep = sector_off + entry_idx * 4;
                if ep + 4 > data.len() {
                    break;
                }
                let val = u32::from_le_bytes(
                    data[ep..ep + 4]
                        .try_into()
                        .map_err(|_| OleError::ParseError("FAT entry".into()))?,
                );
                fat_entries.push(val);
            }
        }

        Ok(Self {
            entries: fat_entries,
        })
    }

    /// Follow the FAT chain starting at `first_sector`.
    ///
    /// Returns the ordered list of sectors until `ENDOFCHAIN` or a sentinel.
    #[must_use]
    pub fn chain(&self, first_sector: u32) -> FatChain {
        if first_sector == ENDOFCHAIN || first_sector == FREESECT || first_sector == NOSTREAM {
            return FatChain::default();
        }
        let mut sectors = Vec::new();
        let mut current = first_sector;
        let mut visited = 0usize;
        let max_len = self.entries.len() + 1;
        loop {
            if current == ENDOFCHAIN
                || current == FREESECT
                || current == NOSTREAM
                || current == DIFSECT
                || current == FATSECT
            {
                break;
            }
            if current as usize >= self.entries.len() {
                break;
            }
            sectors.push(current);
            visited += 1;
            if visited >= max_len {
                // Cycle guard: stop after at most max_len sectors.
                break;
            }
            current = self.entries[current as usize];
        }
        FatChain { sectors }
    }

    /// Assemble the raw bytes for `chain` by reading sectors from `data`.
    ///
    /// Each sector is exactly `header.sector_size_bytes()` bytes at offset
    /// `(sector_id + 1) * sector_size`.
    #[must_use]
    pub fn read_stream(&self, data: &[u8], chain: &FatChain, header: &OleHeader) -> Vec<u8> {
        let sector_size = header.sector_size_bytes() as usize;
        let mut result = Vec::with_capacity(chain.total_bytes(sector_size));
        for &sector_id in &chain.sectors {
            let off = match (sector_id as usize)
                .checked_add(1)
                .and_then(|n| n.checked_mul(sector_size))
            {
                Some(v) => v,
                None => continue,
            };
            if off + sector_size <= data.len() {
                result.extend_from_slice(&data[off..off + sector_size]);
            }
        }
        result
    }
}

// ── MiniFat ───────────────────────────────────────────────────────────────────

/// Mini File Allocation Table for small streams (< 4096 bytes by default).
#[derive(Debug, Clone, Default)]
pub struct MiniFat {
    /// Mini-FAT entries (mini-sector → next mini-sector or sentinel).
    pub entries: Vec<u32>,
    /// The raw bytes of the mini-stream container (root entry's stream).
    pub mini_stream: Vec<u8>,
}

impl MiniFat {
    /// Parse the Mini-FAT and mini-stream from `data`.
    ///
    /// # Errors
    /// Propagates `OleError::ParseError` on structural issues.
    pub fn parse(
        data: &[u8],
        fat: &Fat,
        header: &OleHeader,
        root_dir_entry: &OleDirectoryEntry,
    ) -> Result<Self, OleError> {
        // Read mini FAT sectors
        let mini_fat_chain = fat.chain(header.first_mini_fat);
        let mini_fat_bytes = fat.read_stream(data, &mini_fat_chain, header);

        let mut entries = Vec::with_capacity(mini_fat_bytes.len() / 4);
        let mut idx = 0;
        while idx + 4 <= mini_fat_bytes.len() {
            let val = u32::from_le_bytes(
                mini_fat_bytes[idx..idx + 4]
                    .try_into()
                    .map_err(|_| OleError::ParseError("mini FAT entry".into()))?,
            );
            entries.push(val);
            idx += 4;
        }

        // Read the mini-stream container (root entry's data sectors)
        let mini_stream_chain = fat.chain(root_dir_entry.start_sector);
        let mini_stream = fat.read_stream(data, &mini_stream_chain, header);

        Ok(Self {
            entries,
            mini_stream,
        })
    }

    /// Follow the mini-FAT chain starting at `first_sector`.
    #[must_use]
    pub fn chain(&self, first_sector: u32) -> FatChain {
        if first_sector == ENDOFCHAIN || first_sector == FREESECT || first_sector == NOSTREAM {
            return FatChain::default();
        }
        let mut sectors = Vec::new();
        let mut current = first_sector;
        let mut visited = 0usize;
        let max_len = self.entries.len() + 1;
        loop {
            if current == ENDOFCHAIN || current == FREESECT || current == NOSTREAM {
                break;
            }
            if current as usize >= self.entries.len() {
                break;
            }
            sectors.push(current);
            visited += 1;
            if visited >= max_len {
                // Cycle guard.
                break;
            }
            current = self.entries[current as usize];
        }
        FatChain { sectors }
    }

    /// Read a mini-stream by following `chain` through 64-byte mini-sectors.
    #[must_use]
    pub fn read_stream(&self, chain: &FatChain) -> Vec<u8> {
        const MINI_SECTOR_SIZE: usize = 64;
        let mut result = Vec::with_capacity(chain.total_bytes(MINI_SECTOR_SIZE));
        for &sector_id in &chain.sectors {
            let off = sector_id as usize * MINI_SECTOR_SIZE;
            if off + MINI_SECTOR_SIZE <= self.mini_stream.len() {
                result.extend_from_slice(&self.mini_stream[off..off + MINI_SECTOR_SIZE]);
            }
        }
        result
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::OleHeader;

    const OLE_MAGIC: [u8; 8] = [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];

    fn make_header_bytes(
        sector_size_exp: u16,
        first_dir: u32,
        fat_count: u32,
        first_mini_fat: u32,
    ) -> Vec<u8> {
        let mut data = vec![0u8; 512];
        data[..8].copy_from_slice(&OLE_MAGIC);
        data[24..26].copy_from_slice(&0x003Eu16.to_le_bytes());
        data[26..28].copy_from_slice(&3u16.to_le_bytes());
        data[28..30].copy_from_slice(&0xFFFEu16.to_le_bytes());
        data[30..32].copy_from_slice(&sector_size_exp.to_le_bytes());
        data[32..34].copy_from_slice(&6u16.to_le_bytes());
        data[44..48].copy_from_slice(&fat_count.to_le_bytes());
        data[48..52].copy_from_slice(&first_dir.to_le_bytes());
        data[56..60].copy_from_slice(&4096u32.to_le_bytes());
        data[60..64].copy_from_slice(&first_mini_fat.to_le_bytes());
        data[64..68].copy_from_slice(&0u32.to_le_bytes());
        data
    }

    fn make_full_file(sector_size_exp: u16) -> (Vec<u8>, OleHeader) {
        let sector_size = 1usize << sector_size_exp;
        // We create: header + 1 FAT sector + 1 dir sector + 2 data sectors
        // Sector layout (0-indexed after header):
        //   0 = FAT sector
        //   1 = dir sector
        //   2 = data sector 0
        //   3 = data sector 1
        let first_dir: u32 = 1;
        let first_mini_fat: u32 = ENDOFCHAIN; // no mini FAT
        let fat_count: u32 = 1;
        let mut header_bytes =
            make_header_bytes(sector_size_exp, first_dir, fat_count, first_mini_fat);

        // DIFAT[0] points to sector 0 as FAT sector
        header_bytes[76..80].copy_from_slice(&0u32.to_le_bytes());

        // FAT sector (sector 0): 512 bytes = 128 u32 entries
        let entries_per_sector = sector_size / 4;
        let mut fat_data = vec![0u8; sector_size];
        // sector 0 = FATSECT (itself)
        fat_data[0..4].copy_from_slice(&FATSECT.to_le_bytes());
        // sector 1 = ENDOFCHAIN (dir sector)
        fat_data[4..8].copy_from_slice(&ENDOFCHAIN.to_le_bytes());
        // sector 2 → sector 3 (data chain)
        fat_data[8..12].copy_from_slice(&3u32.to_le_bytes());
        // sector 3 = ENDOFCHAIN
        fat_data[12..16].copy_from_slice(&ENDOFCHAIN.to_le_bytes());
        // Rest = FREESECT
        for i in 4..entries_per_sector {
            let off = i * 4;
            if off + 4 <= fat_data.len() {
                fat_data[off..off + 4].copy_from_slice(&FREESECT.to_le_bytes());
            }
        }
        // Dir sector (sector 1): one root entry at offset (1+1)*sector_size
        let mut dir_entry = vec![0u8; 128];
        // name = "Root Entry"
        let name_u16: Vec<u16> = "Root Entry".encode_utf16().collect();
        for (i, &c) in name_u16.iter().enumerate() {
            if i * 2 + 2 > 64 {
                break;
            }
            dir_entry[i * 2..i * 2 + 2].copy_from_slice(&c.to_le_bytes());
        }
        let name_len = ((name_u16.len() + 1) * 2).min(64) as u16;
        dir_entry[64..66].copy_from_slice(&name_len.to_le_bytes());
        dir_entry[66] = 5; // root
        dir_entry[68..72].copy_from_slice(&NOSTREAM.to_le_bytes());
        dir_entry[72..76].copy_from_slice(&NOSTREAM.to_le_bytes());
        dir_entry[76..80].copy_from_slice(&NOSTREAM.to_le_bytes());
        dir_entry[116..120].copy_from_slice(&2u32.to_le_bytes()); // start_sector = 2
        dir_entry[120..124].copy_from_slice(&(sector_size as u32 * 2).to_le_bytes());

        let mut data = header_bytes;
        // Sector 0: FAT
        data.extend_from_slice(&fat_data);
        // Sector 1: dir (pad to sector_size)
        let mut dir_padded = vec![0u8; sector_size];
        dir_padded[..128].copy_from_slice(&dir_entry);
        data.extend_from_slice(&dir_padded);
        // Sector 2: data "helloworld!!"
        let mut sector2 = vec![b'A'; sector_size];
        sector2[..12].copy_from_slice(b"helloworld!!");
        data.extend_from_slice(&sector2);
        // Sector 3: data
        let sector3 = vec![b'B'; sector_size];
        data.extend_from_slice(&sector3);

        let hdr = OleHeader::parse(&data).unwrap();
        (data, hdr)
    }

    // ── FatChain ──────────────────────────────────────────────────────────────

    #[test]
    fn test_fat_chain_is_empty() {
        assert!(FatChain::default().is_empty());
    }

    #[test]
    fn test_fat_chain_len() {
        let c = FatChain {
            sectors: vec![0, 1, 2],
        };
        assert_eq!(c.len(), 3);
    }

    #[test]
    fn test_fat_chain_total_bytes() {
        let c = FatChain {
            sectors: vec![0, 1, 2],
        };
        assert_eq!(c.total_bytes(512), 1536);
    }

    #[test]
    fn test_fat_chain_not_empty() {
        let c = FatChain { sectors: vec![5] };
        assert!(!c.is_empty());
    }

    // ── Constants ─────────────────────────────────────────────────────────────

    #[test]
    fn test_constants_endofchain() {
        assert_eq!(ENDOFCHAIN, 0xFFFF_FFFE);
    }

    #[test]
    fn test_constants_freesect() {
        assert_eq!(FREESECT, 0xFFFF_FFFF);
    }

    #[test]
    fn test_constants_nostream() {
        assert_eq!(NOSTREAM, 0xFFFF_FFFF);
    }

    #[test]
    fn test_constants_difsect() {
        assert_eq!(DIFSECT, 0xFFFF_FFFC);
    }

    // ── Fat::parse ────────────────────────────────────────────────────────────

    #[test]
    fn test_fat_parse_basic() {
        let (data, hdr) = make_full_file(9);
        let fat = Fat::parse(&data, &hdr).unwrap();
        assert!(!fat.entries.is_empty());
    }

    #[test]
    fn test_fat_parse_too_small() {
        let data = vec![0u8; 4];
        let hdr_bytes = make_header_bytes(9, 1, 1, ENDOFCHAIN);
        let hdr = OleHeader::parse(&hdr_bytes).unwrap();
        // Should not panic; may return empty or partial
        let fat = Fat::parse(&data, &hdr);
        assert!(fat.is_ok());
    }

    // ── Fat::chain ────────────────────────────────────────────────────────────

    #[test]
    fn test_fat_chain_follow() {
        let fat = Fat {
            entries: vec![1, 2, ENDOFCHAIN, FREESECT],
        };
        let chain = fat.chain(0);
        assert_eq!(chain.sectors, vec![0, 1, 2]);
    }

    #[test]
    fn test_fat_chain_endofchain_start() {
        let fat = Fat {
            entries: vec![ENDOFCHAIN],
        };
        let chain = fat.chain(ENDOFCHAIN);
        assert!(chain.is_empty());
    }

    #[test]
    fn test_fat_chain_single_sector() {
        let fat = Fat {
            entries: vec![ENDOFCHAIN],
        };
        let chain = fat.chain(0);
        assert_eq!(chain.sectors, vec![0]);
    }

    #[test]
    fn test_fat_chain_freesect_start() {
        let fat = Fat {
            entries: vec![ENDOFCHAIN],
        };
        let chain = fat.chain(FREESECT);
        assert!(chain.is_empty());
    }

    // ── Fat::read_stream ──────────────────────────────────────────────────────

    #[test]
    fn test_fat_read_stream_basic() {
        let (data, hdr) = make_full_file(9);
        let fat = Fat::parse(&data, &hdr).unwrap();
        let chain = fat.chain(2); // data starts at sector 2
        let bytes = fat.read_stream(&data, &chain, &hdr);
        assert!(!bytes.is_empty());
        // Sector 2 starts with "helloworld!!"
        assert_eq!(&bytes[..12], b"helloworld!!");
    }

    #[test]
    fn test_fat_read_stream_empty_chain() {
        let (data, hdr) = make_full_file(9);
        let fat = Fat::parse(&data, &hdr).unwrap();
        let chain = FatChain::default();
        let bytes = fat.read_stream(&data, &chain, &hdr);
        assert!(bytes.is_empty());
    }

    // ── MiniFat ───────────────────────────────────────────────────────────────

    #[test]
    fn test_mini_fat_chain_follow() {
        let mini = MiniFat {
            entries: vec![1, 2, ENDOFCHAIN],
            mini_stream: vec![b'X'; 192],
        };
        let chain = mini.chain(0);
        assert_eq!(chain.sectors, vec![0, 1, 2]);
    }

    #[test]
    fn test_mini_fat_chain_empty() {
        let mini = MiniFat::default();
        let chain = mini.chain(ENDOFCHAIN);
        assert!(chain.is_empty());
    }

    #[test]
    fn test_mini_fat_read_stream() {
        let mut mini_stream = vec![0u8; 192];
        mini_stream[..4].copy_from_slice(b"ABCD");
        mini_stream[64..68].copy_from_slice(b"EFGH");
        let mini = MiniFat {
            entries: vec![1, ENDOFCHAIN],
            mini_stream,
        };
        let chain = mini.chain(0);
        let bytes = mini.read_stream(&chain);
        assert_eq!(&bytes[..4], b"ABCD");
        assert_eq!(&bytes[64..68], b"EFGH");
    }

    #[test]
    fn test_mini_fat_read_stream_empty() {
        let mini = MiniFat::default();
        let chain = FatChain::default();
        let bytes = mini.read_stream(&chain);
        assert!(bytes.is_empty());
    }

    // ── Combined parse + chain + read ─────────────────────────────────────────

    #[test]
    fn test_fat_chain_cycle_guard() {
        // Create a cycling FAT: 0→1, 1→0 (infinite loop)
        let fat = Fat {
            entries: vec![1, 0],
        };
        // Should terminate via cycle guard, not loop forever
        let chain = fat.chain(0);
        assert!(chain.sectors.len() <= fat.entries.len() + 1);
    }

    #[test]
    fn test_mini_fat_chain_cycle_guard() {
        let mini = MiniFat {
            entries: vec![1, 0],
            mini_stream: vec![0u8; 128],
        };
        let chain = mini.chain(0);
        assert!(chain.sectors.len() <= mini.entries.len() + 1);
    }

    #[test]
    fn test_fat_chain_out_of_bounds_sector() {
        let fat = Fat { entries: vec![5] }; // sector 5 doesn't exist
        let chain = fat.chain(0);
        // Should produce [0] then stop (next sector 5 is out of bounds)
        assert_eq!(chain.sectors, vec![0]);
    }
}
