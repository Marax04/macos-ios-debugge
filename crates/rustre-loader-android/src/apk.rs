//! APK (ZIP) file parser with CRC32 verification and APK v2 signing block detection.

// ── Error ─────────────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ApkError {
    #[error("invalid ZIP magic")]
    InvalidMagic,
    #[error("truncated ZIP data")]
    Truncated,
    #[error("parse error: {0}")]
    ParseError(String),
    #[error("CRC32 mismatch")]
    CrcMismatch,
    #[error("unsupported compression method {0}")]
    UnsupportedCompression(u16),
    #[error("no central directory found")]
    NoCentralDirectory,
}

// ── ZIP structures ────────────────────────────────────────────────────────────

/// A single entry from the ZIP central directory.
#[derive(Debug, Clone)]
pub struct ZipEntry {
    pub name: String,
    pub compression: u16,
    pub crc32: u32,
    pub compressed_size: u32,
    pub uncompressed_size: u32,
    pub local_header_offset: u32,
    pub extra_field_len: u16,
    pub comment: String,
}

/// Parsed APK/ZIP file: central directory entries.
#[derive(Debug, Clone)]
pub struct ApkFile {
    pub entries: Vec<ZipEntry>,
}

// ── CRC32 ─────────────────────────────────────────────────────────────────────

/// Build CRC32 lookup table (polynomial 0xEDB88320).
#[must_use] 
pub fn crc32_table() -> [u32; 256] {
    let poly: u32 = 0xEDB8_8320;
    let mut table = [0u32; 256];
    for i in 0u32..256 {
        let mut crc = i;
        for _ in 0..8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ poly;
            } else {
                crc >>= 1;
            }
        }
        table[i as usize] = crc;
    }
    table
}

/// Compute CRC32 of `data`.
#[must_use] 
pub fn compute_crc32(data: &[u8]) -> u32 {
    let table = crc32_table();
    let mut crc: u32 = 0xFFFF_FFFF;
    for &b in data {
        let idx = ((crc ^ u32::from(b)) & 0xFF) as usize;
        crc = (crc >> 8) ^ table[idx];
    }
    crc ^ 0xFFFF_FFFF
}

// ── Parser ────────────────────────────────────────────────────────────────────

const EOCD_SIG: u32 = 0x0605_4B50;
const CD_SIG: u32 = 0x0201_4B50;
const LFH_SIG: u32 = 0x0403_4B50;

impl ApkFile {
    /// Parse an APK/ZIP file from raw bytes.
    pub fn parse(data: &[u8]) -> Result<Self, ApkError> {
        if data.len() < 4 {
            return Err(ApkError::Truncated);
        }
        // Check local file header magic as a minimum sanity check.
        if data[0] != 0x50 || data[1] != 0x4B {
            return Err(ApkError::InvalidMagic);
        }

        // Find End of Central Directory by scanning backward from the end.
        let eocd_off = find_eocd(data).ok_or(ApkError::NoCentralDirectory)?;
        let eocd = &data[eocd_off..];

        if eocd.len() < 22 {
            return Err(ApkError::Truncated);
        }

        // let disk_num      = le_u16(eocd, 4);
        // let start_disk    = le_u16(eocd, 6);
        let cd_count = le_u16(eocd, 10) as usize;
        let cd_offset = le_u32(eocd, 16) as usize;
        // let comment_len   = le_u16(eocd, 20);

        let mut entries = Vec::with_capacity(cd_count);
        let mut pos = cd_offset;

        for _ in 0..cd_count {
            if pos + 46 > data.len() {
                break;
            }
            if le_u32(data, pos) != CD_SIG {
                return Err(ApkError::ParseError(format!(
                    "bad central dir sig at {pos:#x}"
                )));
            }
            // let version_made   = le_u16(data, pos + 4);
            // let version_needed = le_u16(data, pos + 6);
            // let general_flags  = le_u16(data, pos + 8);
            let compression = le_u16(data, pos + 10);
            // let mod_time       = le_u16(data, pos + 12);
            // let mod_date       = le_u16(data, pos + 14);
            let crc32 = le_u32(data, pos + 16);
            let compressed_size = le_u32(data, pos + 20);
            let uncompressed_size = le_u32(data, pos + 24);
            let fname_len = le_u16(data, pos + 28) as usize;
            let extra_len = le_u16(data, pos + 30) as usize;
            let comment_len = le_u16(data, pos + 32) as usize;
            let extra_field_len = extra_len as u16;
            // let disk_start     = le_u16(data, pos + 34);
            // let int_attrs      = le_u16(data, pos + 36);
            // let ext_attrs      = le_u32(data, pos + 38);
            let local_header_offset = le_u32(data, pos + 42);

            pos += 46;
            if pos + fname_len > data.len() {
                break;
            }
            let name = String::from_utf8_lossy(&data[pos..pos + fname_len]).into_owned();
            pos += fname_len;
            pos += extra_len;
            let comment = if pos + comment_len <= data.len() {
                String::from_utf8_lossy(&data[pos..pos + comment_len]).into_owned()
            } else {
                String::new()
            };
            pos += comment_len;

            entries.push(ZipEntry {
                name,
                compression,
                crc32,
                compressed_size,
                uncompressed_size,
                local_header_offset,
                extra_field_len,
                comment,
            });
        }

        Ok(Self { entries })
    }

    /// Find an entry by name.
    #[must_use] 
    pub fn find(&self, name: &str) -> Option<&ZipEntry> {
        self.entries.iter().find(|e| e.name == name)
    }

    /// List all entry names.
    #[must_use] 
    pub fn names(&self) -> Vec<&str> {
        self.entries.iter().map(|e| e.name.as_str()).collect()
    }

    /// Extract a stored (uncompressed) entry from the raw APK bytes.
    pub fn read_entry_stored(data: &[u8], entry: &ZipEntry) -> Result<Vec<u8>, ApkError> {
        let lh_off = entry.local_header_offset as usize;
        if lh_off + 30 > data.len() {
            return Err(ApkError::Truncated);
        }
        if le_u32(data, lh_off) != LFH_SIG {
            return Err(ApkError::ParseError(
                "bad local file header signature".into(),
            ));
        }
        let fname_len = le_u16(data, lh_off + 26) as usize;
        let extra_len = le_u16(data, lh_off + 28) as usize;
        let data_off = lh_off + 30 + fname_len + extra_len;
        let data_end = data_off + entry.compressed_size as usize;
        if data_end > data.len() {
            return Err(ApkError::Truncated);
        }
        Ok(data[data_off..data_end].to_vec())
    }

    /// Extract a DEFLATE or stored entry. Only BTYPE=00 (stored blocks) supported.
    pub fn read_entry_deflate(data: &[u8], entry: &ZipEntry) -> Result<Vec<u8>, ApkError> {
        let compressed = Self::read_entry_stored(data, entry)?;
        if entry.compression == 0 {
            return Ok(compressed);
        }
        if entry.compression != 8 {
            return Err(ApkError::UnsupportedCompression(entry.compression));
        }
        // Minimal DEFLATE: support non-compressed blocks (BTYPE=00)
        inflate_deflate(&compressed, entry.uncompressed_size as usize)
    }
}

/// Detect whether `data` looks like an APK (ZIP with AndroidManifest.xml).
#[must_use] 
pub fn detect_apk(data: &[u8]) -> bool {
    if !data.starts_with(b"PK\x03\x04") {
        return false;
    }
    data.windows(19).any(|w| w == b"AndroidManifest.xml")
}

// ── APK Signature Block ───────────────────────────────────────────────────────

const APK_SIG_MAGIC: &[u8] = b"APK Sig Block 42";
const APK_SIG_V2_ID: u32 = 0x7109_871A;

/// A parsed signer block from an APK Signature Scheme v2 block.
#[derive(Debug, Clone)]
pub struct SignerBlock {
    pub digest_algo: u32,
    pub certificate: Vec<u8>,
}

/// Parsed APK Signature Block header.
#[derive(Debug, Clone)]
pub struct ApkSignatureBlock {
    pub scheme_version: u32,
    pub signer_blocks: Vec<SignerBlock>,
}

/// Try to find and parse the APK v2 signing block in `data`.
#[must_use] 
pub fn find_apk_v2_signing_block(data: &[u8]) -> Option<ApkSignatureBlock> {
    // The signing block sits just before the start of the central directory.
    // Its structure:
    //   [block_size_lo u64][...id-value pairs...][block_size_hi u64][magic 16 bytes]
    // Search for the magic near the end of the file.
    let magic_off = data
        .windows(APK_SIG_MAGIC.len())
        .rposition(|w| w == APK_SIG_MAGIC)?;

    if magic_off < 24 {
        return None;
    }

    // Read block size (8 bytes before magic)
    let block_size = le_u64(data, magic_off - 8) as usize;
    let block_start = magic_off.checked_sub(block_size + 8)?;

    // Skip the first 8 bytes (size field) of the block.
    let pairs_start = block_start + 8;
    let pairs_end = magic_off - 8;

    let mut pos = pairs_start;
    while pos + 12 <= pairs_end {
        let pair_size = le_u64(data, pos) as usize;
        let id = le_u32(data, pos + 8);
        let value_off = pos + 12;
        let value_end = pos + 8 + pair_size;
        if value_end > pairs_end {
            break;
        }

        if id == APK_SIG_V2_ID && value_off < value_end {
            // Very simple parse: return a block with a single signer placeholder.
            let cert_data = data[value_off..value_end.min(data.len())].to_vec();
            return Some(ApkSignatureBlock {
                scheme_version: 2,
                signer_blocks: vec![SignerBlock {
                    digest_algo: 0,
                    certificate: cert_data,
                }],
            });
        }

        pos += 8 + pair_size;
    }

    // No v2 block found but magic was present — return empty block.
    Some(ApkSignatureBlock {
        scheme_version: 2,
        signer_blocks: vec![],
    })
}

// ── Private helpers ───────────────────────────────────────────────────────────

fn le_u16(data: &[u8], off: usize) -> u16 {
    if off + 2 > data.len() {
        return 0;
    }
    u16::from_le_bytes(data[off..off + 2].try_into().unwrap_or([0; 2]))
}

fn le_u32(data: &[u8], off: usize) -> u32 {
    if off + 4 > data.len() {
        return 0;
    }
    u32::from_le_bytes(data[off..off + 4].try_into().unwrap_or([0; 4]))
}

fn le_u64(data: &[u8], off: usize) -> u64 {
    if off + 8 > data.len() {
        return 0;
    }
    u64::from_le_bytes(data[off..off + 8].try_into().unwrap_or([0; 8]))
}

fn find_eocd(data: &[u8]) -> Option<usize> {
    // EOCD is at most 22 + 65535 bytes from the end.
    let search_start = data.len().saturating_sub(65535 + 22);
    data[search_start..]
        .windows(4)
        .rposition(|w| le_u32(w, 0) == EOCD_SIG)
        .map(|p| p + search_start)
}

/// Minimal inflate for non-compressed (BTYPE=00) DEFLATE blocks.
fn inflate_deflate(compressed: &[u8], expected_size: usize) -> Result<Vec<u8>, ApkError> {
    // `expected_size` is the ZIP central-directory `uncompressed_size`, i.e. a
    // 32-bit attacker-controlled field: a few-byte entry can claim 4 GiB. This
    // implementation only copies stored (BTYPE=00) blocks verbatim, so the
    // output can never exceed the compressed input — cap the reservation by it.
    let mut out = Vec::with_capacity(expected_size.min(compressed.len()));
    let mut pos = 0usize;
    // bit-stream position (we ignore the 2-bit CMF/FLG header of zlib if present)
    // Detect zlib wrapper (CMF=0x78)
    if compressed.first() == Some(&0x78) {
        pos = 2; // skip zlib header
    }

    while pos < compressed.len() {
        if pos >= compressed.len() {
            break;
        }
        let bfinal_btype = compressed[pos];
        pos += 1;
        let btype = (bfinal_btype >> 1) & 0x3;
        match btype {
            0b00 => {
                // Stored block: skip remaining bits in byte, read LEN / NLEN
                if pos + 4 > compressed.len() {
                    return Err(ApkError::Truncated);
                }
                let len = le_u16(compressed, pos) as usize;
                let _nlen = le_u16(compressed, pos + 2);
                pos += 4;
                if pos + len > compressed.len() {
                    return Err(ApkError::Truncated);
                }
                out.extend_from_slice(&compressed[pos..pos + len]);
                pos += len;
            }
            _ => {
                // Compressed blocks not supported in this minimal implementation.
                return Err(ApkError::UnsupportedCompression(8));
            }
        }
        if bfinal_btype & 1 != 0 {
            break;
        } // BFINAL set
    }
    Ok(out)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_minimal_zip(entry_name: &str, content: &[u8]) -> Vec<u8> {
        // Build a minimal valid ZIP with one stored entry.
        let mut buf = Vec::new();

        // Local file header
        let lfh_offset = 0u32;
        let name_bytes = entry_name.as_bytes();
        let crc = compute_crc32(content);

        buf.extend_from_slice(&LFH_SIG.to_le_bytes());
        buf.extend_from_slice(&0x14_u16.to_le_bytes()); // version
        buf.extend_from_slice(&0u16.to_le_bytes()); // flags
        buf.extend_from_slice(&0u16.to_le_bytes()); // compression=stored
        buf.extend_from_slice(&0u16.to_le_bytes()); // mod time
        buf.extend_from_slice(&0u16.to_le_bytes()); // mod date
        buf.extend_from_slice(&crc.to_le_bytes());
        buf.extend_from_slice(&(content.len() as u32).to_le_bytes());
        buf.extend_from_slice(&(content.len() as u32).to_le_bytes());
        buf.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
        buf.extend_from_slice(&0u16.to_le_bytes()); // extra len
        buf.extend_from_slice(name_bytes);
        buf.extend_from_slice(content);

        let cd_offset = buf.len() as u32;

        // Central directory entry
        buf.extend_from_slice(&CD_SIG.to_le_bytes());
        buf.extend_from_slice(&0x14_u16.to_le_bytes()); // version made
        buf.extend_from_slice(&0x14_u16.to_le_bytes()); // version needed
        buf.extend_from_slice(&0u16.to_le_bytes()); // flags
        buf.extend_from_slice(&0u16.to_le_bytes()); // compression
        buf.extend_from_slice(&0u16.to_le_bytes()); // mod time
        buf.extend_from_slice(&0u16.to_le_bytes()); // mod date
        buf.extend_from_slice(&crc.to_le_bytes());
        buf.extend_from_slice(&(content.len() as u32).to_le_bytes());
        buf.extend_from_slice(&(content.len() as u32).to_le_bytes());
        buf.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
        buf.extend_from_slice(&0u16.to_le_bytes()); // extra len
        buf.extend_from_slice(&0u16.to_le_bytes()); // comment len
        buf.extend_from_slice(&0u16.to_le_bytes()); // disk start
        buf.extend_from_slice(&0u16.to_le_bytes()); // int attrs
        buf.extend_from_slice(&0u32.to_le_bytes()); // ext attrs
        buf.extend_from_slice(&lfh_offset.to_le_bytes());
        buf.extend_from_slice(name_bytes);

        let cd_size = buf.len() as u32 - cd_offset;

        // EOCD
        buf.extend_from_slice(&EOCD_SIG.to_le_bytes());
        buf.extend_from_slice(&0u16.to_le_bytes()); // disk num
        buf.extend_from_slice(&0u16.to_le_bytes()); // start disk
        buf.extend_from_slice(&1u16.to_le_bytes()); // entries on disk
        buf.extend_from_slice(&1u16.to_le_bytes()); // total entries
        buf.extend_from_slice(&cd_size.to_le_bytes());
        buf.extend_from_slice(&cd_offset.to_le_bytes());
        buf.extend_from_slice(&0u16.to_le_bytes()); // comment len

        buf
    }

    // ── CRC32 ─────────────────────────────────────────────────────────────────

    #[test]
    fn test_crc32_known_value() {
        // CRC32("123456789") = 0xCBF43926
        let crc = compute_crc32(b"123456789");
        assert_eq!(crc, 0xCBF4_3926);
    }

    #[test]
    fn test_crc32_empty() {
        assert_eq!(compute_crc32(b""), 0x0000_0000);
    }

    #[test]
    fn test_crc32_table_256_entries() {
        let t = crc32_table();
        assert_eq!(t.len(), 256);
        // First entry (byte 0x00) should be 0
        assert_eq!(t[0], 0);
    }

    // ── ApkFile::parse ────────────────────────────────────────────────────────

    #[test]
    fn test_parse_minimal_zip() {
        let zip = make_minimal_zip("test.txt", b"hello");
        let apk = ApkFile::parse(&zip).unwrap();
        assert_eq!(apk.entries.len(), 1);
        assert_eq!(apk.entries[0].name, "test.txt");
    }

    #[test]
    fn test_parse_invalid_magic() {
        assert!(matches!(
            ApkFile::parse(&[0xFF, 0xFE, 0x00, 0x00]),
            Err(ApkError::InvalidMagic)
        ));
    }

    #[test]
    fn test_parse_truncated() {
        assert!(matches!(ApkFile::parse(&[]), Err(ApkError::Truncated)));
    }

    #[test]
    fn test_find_entry() {
        let zip = make_minimal_zip("AndroidManifest.xml", b"<manifest/>");
        let apk = ApkFile::parse(&zip).unwrap();
        assert!(apk.find("AndroidManifest.xml").is_some());
        assert!(apk.find("missing.txt").is_none());
    }

    #[test]
    fn test_names() {
        let zip = make_minimal_zip("classes.dex", b"\x00");
        let apk = ApkFile::parse(&zip).unwrap();
        let names = apk.names();
        assert_eq!(names, vec!["classes.dex"]);
    }

    #[test]
    fn test_read_entry_stored() {
        let content = b"test content";
        let zip = make_minimal_zip("data.bin", content);
        let apk = ApkFile::parse(&zip).unwrap();
        let entry = apk.find("data.bin").unwrap();
        let data = ApkFile::read_entry_stored(&zip, entry).unwrap();
        assert_eq!(data, content);
    }

    #[test]
    fn test_read_entry_deflate_stored() {
        let content = b"plaintext";
        let zip = make_minimal_zip("plain.txt", content);
        let apk = ApkFile::parse(&zip).unwrap();
        let entry = apk.find("plain.txt").unwrap();
        let data = ApkFile::read_entry_deflate(&zip, entry).unwrap();
        assert_eq!(data, content);
    }

    // ── detect_apk ────────────────────────────────────────────────────────────

    #[test]
    fn test_detect_apk_true() {
        let mut data = b"PK\x03\x04".to_vec();
        data.extend_from_slice(&[0u8; 50]);
        data.extend_from_slice(b"AndroidManifest.xml");
        assert!(detect_apk(&data));
    }

    #[test]
    fn test_detect_apk_no_manifest() {
        let data = b"PK\x03\x04someother";
        assert!(!detect_apk(data));
    }

    #[test]
    fn test_detect_apk_not_zip() {
        assert!(!detect_apk(b"\x00\x01\x02\x03AndroidManifest.xml"));
    }

    // ── APK signature block ───────────────────────────────────────────────────

    #[test]
    fn test_find_sig_block_absent() {
        let data = make_minimal_zip("test.txt", b"data");
        // No signing block present — should return None or empty
        let result = find_apk_v2_signing_block(&data);
        // Not present → None
        assert!(result.is_none());
    }

    // ── ZipEntry fields ───────────────────────────────────────────────────────

    #[test]
    fn test_entry_compression_stored() {
        let zip = make_minimal_zip("a.txt", b"x");
        let apk = ApkFile::parse(&zip).unwrap();
        assert_eq!(apk.entries[0].compression, 0);
    }

    #[test]
    fn test_entry_uncompressed_size() {
        let content = b"hello world!";
        let zip = make_minimal_zip("b.txt", content);
        let apk = ApkFile::parse(&zip).unwrap();
        assert_eq!(apk.entries[0].uncompressed_size as usize, content.len());
    }

    #[test]
    fn test_read_entry_unsupported_compression() {
        let content = b"test";
        let mut zip = make_minimal_zip("c.txt", content);
        // Patch compression method to 8 (DEFLATE) in local header (offset 8)
        zip[8] = 8;
        // Also patch compression in central directory. Central directory starts
        // at offset 30 + fname_len + data_len = 30 + 5 + 4 = 39.
        // Within the CD entry, compression is at relative offset 10 → absolute 49.
        let cd_start = 30 + "c.txt".len() + content.len();
        let cd_compression_offset = cd_start + 10;
        zip[cd_compression_offset] = 8;
        let apk = ApkFile::parse(&zip).unwrap();
        let entry = apk.find("c.txt").unwrap();
        // compression=8, but data is not actually deflated — should error
        assert!(ApkFile::read_entry_deflate(&zip, entry).is_err());
    }
}
