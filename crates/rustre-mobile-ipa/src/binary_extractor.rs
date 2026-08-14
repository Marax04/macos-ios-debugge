//! Binary extraction from IPA archives.
//!
//! An IPA file is a ZIP archive. This module:
//! 1. Parses the ZIP central directory to enumerate entries.
//! 2. Extracts specific files (the Mach-O executable, `.dylib`s, etc.) by path.
//! 3. Handles fat (universal) Mach-O binaries — splits them into individual
//!    thin slices (`lipo`-equivalent).
//! 4. Verifies `CodeDirectory` SHA-256 / SHA-1 hashes from embedded code signatures.

// ─────────────────────────────────────────────────────────────────────────────
// ExtractError
// ─────────────────────────────────────────────────────────────────────────────

/// Errors from binary extraction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExtractError {
    NotZip,
    Truncated,
    InvalidEntry(String),
    NotFound(String),
    DecompressError(String),
    NotMachO,
    CodeSignatureError(String),
}

impl std::fmt::Display for ExtractError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotZip => write!(f, "not a valid ZIP/IPA"),
            Self::Truncated => write!(f, "ZIP data truncated"),
            Self::InvalidEntry(s) => write!(f, "invalid ZIP entry: {s}"),
            Self::NotFound(s) => write!(f, "file not found in IPA: {s}"),
            Self::DecompressError(s) => write!(f, "decompression error: {s}"),
            Self::NotMachO => write!(f, "data is not a Mach-O binary"),
            Self::CodeSignatureError(s) => write!(f, "code signature error: {s}"),
        }
    }
}

impl std::error::Error for ExtractError {}

// ─────────────────────────────────────────────────────────────────────────────
// ZIP parsing (central directory)
// ─────────────────────────────────────────────────────────────────────────────

/// A single ZIP central-directory entry (metadata only, data read on demand).
#[derive(Debug, Clone)]
pub struct ZipEntry {
    pub name: String,
    pub method: u16,
    pub compressed_size: u32,
    pub uncompressed_size: u32,
    pub local_header_offset: u32,
    pub crc32: u32,
}

/// Minimal ZIP central-directory parser.
#[derive(Debug)]
pub struct ZipReader<'a> {
    data: &'a [u8],
    entries: Vec<ZipEntry>,
}

impl<'a> ZipReader<'a> {
    const EOCD_SIG: u32 = 0x0605_4B50;
    const CENTRAL_SIG: u32 = 0x0201_4B50;
    const LOCAL_SIG: u32 = 0x0403_4B50;

    /// Parse the ZIP from `data`.
    ///
    /// # Errors
    /// Returns [`ExtractError::NotZip`] if `data` is not a valid ZIP file,
    /// or [`ExtractError::Truncated`] if the data is too short or malformed.
    ///
    /// # Panics
    /// Panics if internal slice arithmetic overflows (should not happen in practice).
    pub fn parse(data: &'a [u8]) -> Result<Self, ExtractError> {
        if data.len() < 22 {
            return Err(ExtractError::NotZip);
        }
        // Check local file header magic at start.
        if u32::from_le_bytes(data[..4].try_into().unwrap()) != Self::LOCAL_SIG {
            return Err(ExtractError::NotZip);
        }

        // Find EOCD record by scanning backwards.
        let eocd_off = Self::find_eocd(data).ok_or(ExtractError::Truncated)?;
        let eocd = &data[eocd_off..];
        if eocd.len() < 22 {
            return Err(ExtractError::Truncated);
        }

        let cd_offset = u32::from_le_bytes(eocd[16..20].try_into().unwrap()) as usize;
        let _cd_size = u32::from_le_bytes(eocd[12..16].try_into().unwrap()) as usize;
        let n_entries = u16::from_le_bytes([eocd[8], eocd[9]]) as usize;

        let mut entries = Vec::with_capacity(n_entries);
        let mut pos = cd_offset;

        while pos + 46 <= data.len() && entries.len() < n_entries {
            let sig = u32::from_le_bytes(data[pos..pos+4].try_into().unwrap());
            if sig != Self::CENTRAL_SIG {
                break;
            }
            let compression = u16::from_le_bytes([data[pos+10], data[pos+11]]);
            let crc32 = u32::from_le_bytes(data[pos+16..pos+20].try_into().unwrap());
            let compressed = u32::from_le_bytes(data[pos+20..pos+24].try_into().unwrap());
            let uncompressed = u32::from_le_bytes(data[pos+24..pos+28].try_into().unwrap());
            let name_len = u16::from_le_bytes([data[pos+28], data[pos+29]]) as usize;
            let extra_len = u16::from_le_bytes([data[pos+30], data[pos+31]]) as usize;
            let comment_len = u16::from_le_bytes([data[pos+32], data[pos+33]]) as usize;
            let local_offset = u32::from_le_bytes(data[pos+42..pos+46].try_into().unwrap());

            let name_start = pos + 46;
            let name_end = name_start + name_len;
            if name_end > data.len() {
                break;
            }
            let name = String::from_utf8_lossy(&data[name_start..name_end]).into_owned();

            entries.push(ZipEntry { name, method: compression, compressed_size: compressed,
                uncompressed_size: uncompressed, local_header_offset: local_offset, crc32 });

            pos += 46 + name_len + extra_len + comment_len;
        }

        Ok(Self { data, entries })
    }

    fn find_eocd(data: &[u8]) -> Option<usize> {
        // EOCD is at most 65535 + 22 bytes from the end.
        let search_start = data.len().saturating_sub(65536 + 22);
        for i in (search_start..data.len().saturating_sub(3)).rev() {
            if u32::from_le_bytes(data[i..i+4].try_into().ok()?) == Self::EOCD_SIG {
                return Some(i);
            }
        }
        None
    }

    /// List all entry names.
    #[must_use]
    pub fn entry_names(&self) -> Vec<&str> {
        self.entries.iter().map(|e| e.name.as_str()).collect()
    }

    /// Find an entry by exact name.
    #[must_use]
    pub fn find_entry(&self, name: &str) -> Option<&ZipEntry> {
        self.entries.iter().find(|e| e.name == name)
    }

    /// Find entries whose names contain a substring.
    #[must_use]
    pub fn find_entries_containing(&self, substr: &str) -> Vec<&ZipEntry> {
        self.entries.iter().filter(|e| e.name.contains(substr)).collect()
    }

    /// Extract raw (potentially compressed) data for an entry.
    ///
    /// # Errors
    /// Returns [`ExtractError::Truncated`] if the data is truncated,
    /// [`ExtractError::InvalidEntry`] if the local file header is missing,
    /// or [`ExtractError::DecompressError`] if decompression fails.
    ///
    /// # Panics
    /// Panics if slice arithmetic overflows.
    pub fn extract_entry(&self, entry: &ZipEntry) -> Result<Vec<u8>, ExtractError> {
        let off = entry.local_header_offset as usize;
        if off + 30 > self.data.len() {
            return Err(ExtractError::Truncated);
        }
        let local_sig = u32::from_le_bytes(self.data[off..off+4].try_into().unwrap());
        if local_sig != Self::LOCAL_SIG {
            return Err(ExtractError::InvalidEntry(entry.name.clone()));
        }
        let fname_len = u16::from_le_bytes([self.data[off+26], self.data[off+27]]) as usize;
        let extra_len = u16::from_le_bytes([self.data[off+28], self.data[off+29]]) as usize;
        let data_start = off
            .checked_add(30)
            .and_then(|x| x.checked_add(fname_len))
            .and_then(|x| x.checked_add(extra_len))
            .ok_or(ExtractError::Truncated)?;
        if data_start > self.data.len() {
            return Err(ExtractError::Truncated);
        }
        let data_end = data_start
            .checked_add(entry.compressed_size as usize)
            .ok_or(ExtractError::Truncated)?;
        if data_end > self.data.len() {
            return Err(ExtractError::Truncated);
        }
        let raw = &self.data[data_start..data_end];

        match entry.method {
            0 => Ok(raw.to_vec()), // stored
            8 => inflate_raw(raw).map_err(ExtractError::DecompressError),
            _ => Err(ExtractError::DecompressError(format!("unsupported compression method {}", entry.method))),
        }
    }

    /// Extract a file by path prefix (case-sensitive).
    ///
    /// # Errors
    /// Returns [`ExtractError::NotFound`] if no entry with that name exists,
    /// or propagates errors from [`Self::extract_entry`].
    pub fn extract_by_name(&self, name: &str) -> Result<Vec<u8>, ExtractError> {
        let entry = self.find_entry(name)
            .ok_or_else(|| ExtractError::NotFound(name.to_string()))?;
        self.extract_entry(entry)
    }
}

/// Decompress a raw DEFLATE stream (ZIP local file compression method 8).
///
/// Uses [`flate2`]'s `DeflateDecoder`, which expects a raw deflate bitstream
/// (no zlib header / Adler-32 trailer) — this matches the wire format used
/// inside ZIP entries.
fn inflate_raw(data: &[u8]) -> Result<Vec<u8>, String> {
    use flate2::read::DeflateDecoder;
    use std::io::Read;

    let mut decoder = DeflateDecoder::new(data);
    let mut out = Vec::with_capacity(data.len().saturating_mul(2));
    decoder
        .read_to_end(&mut out)
        .map_err(|e| format!("deflate decode failed: {e}"))?;
    Ok(out)
}

// ─────────────────────────────────────────────────────────────────────────────
// Mach-O structures
// ─────────────────────────────────────────────────────────────────────────────

/// Mach-O magic numbers.
pub const MH_MAGIC: u32 = 0xFEED_FACE;
pub const MH_CIGAM: u32 = 0xCEFA_EDFE;
pub const MH_MAGIC_64: u32 = 0xFEED_FACF;
pub const MH_CIGAM_64: u32 = 0xCFFA_EDFE;
pub const FAT_MAGIC: u32 = 0xCAFE_BABE;
pub const FAT_CIGAM: u32 = 0xBEBA_FECA;

/// Mach-O CPU type codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CpuType {
    X86,
    X86_64,
    Arm,
    Arm64,
    Arm64_32,
    Ppc,
    Ppc64,
    Unknown(i32),
}

impl CpuType {
    #[must_use]
    pub const fn from_i32(v: i32) -> Self {
        match v {
            7 => Self::X86,
            0x0100_0007 => Self::X86_64,
            12 => Self::Arm,
            0x0100_000C => Self::Arm64,
            0x0200_000C => Self::Arm64_32,
            18 => Self::Ppc,
            0x0100_0012 => Self::Ppc64,
            _ => Self::Unknown(v),
        }
    }

    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::X86 => "x86",
            Self::X86_64 => "x86_64",
            Self::Arm => "arm",
            Self::Arm64 => "arm64",
            Self::Arm64_32 => "arm64_32",
            Self::Ppc => "ppc",
            Self::Ppc64 => "ppc64",
            Self::Unknown(_) => "unknown",
        }
    }
}

/// A thin Mach-O slice extracted from a fat binary.
#[derive(Debug, Clone)]
pub struct ThinSlice {
    pub cpu_type: CpuType,
    pub cpu_subtype: u32,
    /// The raw bytes of this slice.
    pub data: Vec<u8>,
}

/// A fat / universal binary header entry.
#[derive(Debug, Clone)]
pub struct FatArch {
    pub cpu_type: CpuType,
    pub cpu_subtype: u32,
    pub offset: u32,
    pub size: u32,
    pub align: u32,
}

// ─────────────────────────────────────────────────────────────────────────────
// FatSplitter
// ─────────────────────────────────────────────────────────────────────────────

/// Splits a fat (universal) Mach-O binary into thin slices.
pub struct FatSplitter;

impl FatSplitter {
    /// Detect whether `data` is a fat binary.
    ///
    /// # Panics
    /// Panics if `data` has at least 4 bytes but the slice conversion fails.
    #[must_use]
    pub fn is_fat(data: &[u8]) -> bool {
        if data.len() < 4 { return false; }
        let magic = u32::from_be_bytes(data[..4].try_into().unwrap());
        magic == FAT_MAGIC || magic == FAT_CIGAM
    }

    /// Detect whether `data` is a thin Mach-O.
    ///
    /// # Panics
    /// Panics if `data` has at least 4 bytes but the slice conversion fails.
    #[must_use]
    pub fn is_thin_macho(data: &[u8]) -> bool {
        if data.len() < 4 { return false; }
        let magic = u32::from_le_bytes(data[..4].try_into().unwrap());
        matches!(magic, MH_MAGIC | MH_MAGIC_64 | MH_CIGAM | MH_CIGAM_64)
    }

    /// Parse fat archs from a fat binary.
    ///
    /// # Errors
    /// Returns [`ExtractError::NotMachO`] if the magic is wrong,
    /// or [`ExtractError::Truncated`] if the data is too short.
    ///
    /// # Panics
    /// Panics if internal slice conversions fail.
    pub fn parse_fat_archs(data: &[u8]) -> Result<Vec<FatArch>, ExtractError> {
        if data.len() < 8 { return Err(ExtractError::NotMachO); }
        let magic = u32::from_be_bytes(data[..4].try_into().unwrap());
        if magic != FAT_MAGIC && magic != FAT_CIGAM {
            return Err(ExtractError::NotMachO);
        }
        let n_archs = u32::from_be_bytes(data[4..8].try_into().unwrap()) as usize;
        // A fat binary cannot contain more slices than fit in the file header.
        let max_archs = (data.len().saturating_sub(8)) / 20;
        if n_archs > max_archs {
            return Err(ExtractError::Truncated);
        }
        let mut archs = Vec::with_capacity(n_archs.min(64));
        for i in 0..n_archs {
            let off = 8 + i * 20;
            if off + 20 > data.len() { return Err(ExtractError::Truncated); }
            let cpu_type = CpuType::from_i32(i32::from_be_bytes(data[off..off+4].try_into().unwrap()));
            let cpu_subtype = u32::from_be_bytes(data[off+4..off+8].try_into().unwrap());
            let offset = u32::from_be_bytes(data[off+8..off+12].try_into().unwrap());
            let size = u32::from_be_bytes(data[off+12..off+16].try_into().unwrap());
            let align = u32::from_be_bytes(data[off+16..off+20].try_into().unwrap());
            archs.push(FatArch { cpu_type, cpu_subtype, offset, size, align });
        }
        Ok(archs)
    }

    /// Extract all thin slices from `data`.
    ///
    /// # Errors
    /// Returns an error if parsing fat archs fails or the data is truncated.
    pub fn split(data: &[u8]) -> Result<Vec<ThinSlice>, ExtractError> {
        let archs = Self::parse_fat_archs(data)?;
        let mut out = Vec::new();
        for arch in archs {
            let start = arch.offset as usize;
            let end = start.checked_add(arch.size as usize).ok_or(ExtractError::Truncated)?;
            if end > data.len() { return Err(ExtractError::Truncated); }
            out.push(ThinSlice {
                cpu_type: arch.cpu_type,
                cpu_subtype: arch.cpu_subtype,
                data: data[start..end].to_vec(),
            });
        }
        Ok(out)
    }

    /// Extract the thin slice for a specific CPU type.
    ///
    /// # Errors
    /// Returns [`ExtractError::NotFound`] if the target arch is not present,
    /// or propagates errors from [`Self::split`].
    pub fn extract_arch(data: &[u8], target: CpuType) -> Result<Vec<u8>, ExtractError> {
        if Self::is_thin_macho(data) {
            return Ok(data.to_vec());
        }
        let slices = Self::split(data)?;
        slices.into_iter().find(|s| s.cpu_type == target)
            .map(|s| s.data)
            .ok_or_else(|| ExtractError::NotFound(format!("arch {target:?}")))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CodeDirectory
// ─────────────────────────────────────────────────────────────────────────────

/// Parsed Apple `CodeDirectory` from an embedded code signature.
#[derive(Debug, Clone)]
pub struct CodeDirectory {
    pub version: u32,
    pub flags: u32,
    pub hash_offset: u32,
    pub ident_offset: u32,
    pub n_special_slots: u32,
    pub n_code_slots: u32,
    pub code_limit: u32,
    pub hash_size: u8,
    pub hash_type: u8,
    pub page_size: u8,
    /// Bundle identifier.
    pub identifier: String,
    /// Hashes of each page (as raw bytes).
    pub hashes: Vec<Vec<u8>>,
}

impl CodeDirectory {
    const MAGIC: u32 = 0xFADE_0C02;

    /// Parse a [`CodeDirectory`] blob.
    ///
    /// # Errors
    /// Returns [`ExtractError::CodeSignatureError`] if the data is malformed.
    ///
    /// # Panics
    /// Panics if internal slice conversions fail.
    pub fn parse(data: &[u8]) -> Result<Self, ExtractError> {
        if data.len() < 44 {
            return Err(ExtractError::CodeSignatureError("too short".into()));
        }
        let magic = u32::from_be_bytes(data[..4].try_into().unwrap());
        if magic != Self::MAGIC {
            return Err(ExtractError::CodeSignatureError(format!("bad magic 0x{magic:08X}")));
        }
        let _length = u32::from_be_bytes(data[4..8].try_into().unwrap());
        let version = u32::from_be_bytes(data[8..12].try_into().unwrap());
        let flags = u32::from_be_bytes(data[12..16].try_into().unwrap());
        let hash_offset = u32::from_be_bytes(data[16..20].try_into().unwrap());
        let ident_offset = u32::from_be_bytes(data[20..24].try_into().unwrap());
        let n_special_slots = u32::from_be_bytes(data[24..28].try_into().unwrap());
        let n_code_slots = u32::from_be_bytes(data[28..32].try_into().unwrap());
        let code_limit = u32::from_be_bytes(data[32..36].try_into().unwrap());
        let hash_size = data[36];
        let hash_type = data[37];
        let page_size = data[39];

        // Read identifier string.
        let ident_start = ident_offset as usize;
        let identifier = if ident_start < data.len() {
            let end = data[ident_start..].iter().position(|&b| b == 0)
                .map_or(data.len(), |n| ident_start + n);
            String::from_utf8_lossy(&data[ident_start..end]).into_owned()
        } else {
            String::new()
        };

        // Read hashes.
        let total_slots = n_special_slots + n_code_slots;
        let hash_start = (hash_offset as usize).saturating_sub(n_special_slots as usize * hash_size as usize);
        let mut hashes = Vec::new();
        for i in 0..(total_slots as usize) {
            let slot_start = hash_start + i * hash_size as usize;
            let slot_end = slot_start + hash_size as usize;
            if slot_end <= data.len() {
                hashes.push(data[slot_start..slot_end].to_vec());
            }
        }

        Ok(Self { version, flags, hash_offset, ident_offset, n_special_slots, n_code_slots,
            code_limit, hash_size, hash_type, page_size: 1u8 << page_size, identifier, hashes })
    }

    /// Verify the first N code hashes against the actual binary pages.
    #[must_use]
    pub fn verify_pages(&self, binary: &[u8], n: usize) -> Vec<bool> {
        let page_sz = if self.page_size == 0 { 4096 } else { self.page_size as usize };
        let code_hashes = &self.hashes[self.n_special_slots as usize..];
        let mut results = Vec::new();
        for (i, code_hash) in code_hashes.iter().enumerate().take(n) {
            let start = i * page_sz;
            let end = (start + page_sz).min(binary.len());
            if start >= binary.len() { break; }
            let page = &binary[start..end];
            let hash = match self.hash_type {
                1 => sha1_simple(page),
                2 => sha256_simple(page),
                _ => Vec::new(),
            };
            results.push(hash == *code_hash);
        }
        results
    }
}

/// SHA-1 (FIPS 180-4) — pure-Rust single-shot implementation, no external deps.
/// Returns the 20-byte digest of `data`.
fn sha1_simple(data: &[u8]) -> Vec<u8> {
    let mut state: [u32; 5] = [
        0x6745_2301, 0xEFCD_AB89, 0x98BA_DCFE, 0x1032_5476, 0xC3D2_E1F0,
    ];

    // Build padded message: data || 0x80 || 0x00.. || 64-bit big-endian bit length.
    let bit_len = (data.len() as u64).wrapping_mul(8);
    let mut msg = Vec::with_capacity(data.len() + 72);
    msg.extend_from_slice(data);
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in msg.chunks_exact(64) {
        let mut words = [0u32; 80];
        for (idx, word) in chunk.chunks_exact(4).enumerate() {
            words[idx] = u32::from_be_bytes([word[0], word[1], word[2], word[3]]);
        }
        for idx in 16..80 {
            words[idx] = (words[idx - 3] ^ words[idx - 8] ^ words[idx - 14] ^ words[idx - 16]).rotate_left(1);
        }

        let [mut va, mut vb, mut vc, mut vd, mut ve] = state;
        for (ri, &wv) in words.iter().enumerate() {
            let (fv, k) = match ri {
                0..=19 => ((vb & vc) | ((!vb) & vd), 0x5A82_7999u32),
                20..=39 => (vb ^ vc ^ vd, 0x6ED9_EBA1),
                40..=59 => ((vb & vc) | (vb & vd) | (vc & vd), 0x8F1B_BCDC),
                _ => (vb ^ vc ^ vd, 0xCA62_C1D6),
            };
            let temp = va
                .rotate_left(5)
                .wrapping_add(fv)
                .wrapping_add(ve)
                .wrapping_add(k)
                .wrapping_add(wv);
            ve = vd;
            vd = vc;
            vc = vb.rotate_left(30);
            vb = va;
            va = temp;
        }
        state[0] = state[0].wrapping_add(va);
        state[1] = state[1].wrapping_add(vb);
        state[2] = state[2].wrapping_add(vc);
        state[3] = state[3].wrapping_add(vd);
        state[4] = state[4].wrapping_add(ve);
    }

    let mut out = Vec::with_capacity(20);
    for word in state {
        out.extend_from_slice(&word.to_be_bytes());
    }
    out
}

/// SHA-256 (FIPS 180-4) — pure-Rust single-shot implementation, no external deps.
/// Returns the 32-byte digest of `data`.
fn sha256_simple(data: &[u8]) -> Vec<u8> {
    const K: [u32; 64] = [
        0x428a_2f98, 0x7137_4491, 0xb5c0_fbcf, 0xe9b5_dba5, 0x3956_c25b, 0x59f1_11f1,
        0x923f_82a4, 0xab1c_5ed5, 0xd807_aa98, 0x1283_5b01, 0x2431_85be, 0x550c_7dc3,
        0x72be_5d74, 0x80de_b1fe, 0x9bdc_06a7, 0xc19b_f174, 0xe49b_69c1, 0xefbe_4786,
        0x0fc1_9dc6, 0x240c_a1cc, 0x2de9_2c6f, 0x4a74_84aa, 0x5cb0_a9dc, 0x76f9_88da,
        0x983e_5152, 0xa831_c66d, 0xb003_27c8, 0xbf59_7fc7, 0xc6e0_0bf3, 0xd5a7_9147,
        0x06ca_6351, 0x1429_2967, 0x27b7_0a85, 0x2e1b_2138, 0x4d2c_6dfc, 0x5338_0d13,
        0x650a_7354, 0x766a_0abb, 0x81c2_c92e, 0x9272_2c85, 0xa2bf_e8a1, 0xa81a_664b,
        0xc24b_8b70, 0xc76c_51a3, 0xd192_e819, 0xd699_0624, 0xf40e_3585, 0x106a_a070,
        0x19a4_c116, 0x1e37_6c08, 0x2748_774c, 0x34b0_bcb5, 0x391c_0cb3, 0x4ed8_aa4a,
        0x5b9c_ca4f, 0x682e_6ff3, 0x748f_82ee, 0x78a5_636f, 0x84c8_7814, 0x8cc7_0208,
        0x90be_fffa, 0xa450_6ceb, 0xbef9_a3f7, 0xc671_78f2,
    ];

    let mut state: [u32; 8] = [
        0x6a09_e667, 0xbb67_ae85, 0x3c6e_f372, 0xa54f_f53a, 0x510e_527f, 0x9b05_688c,
        0x1f83_d9ab, 0x5be0_cd19,
    ];

    let bit_len = (data.len() as u64).wrapping_mul(8);
    let mut msg = Vec::with_capacity(data.len() + 72);
    msg.extend_from_slice(data);
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in msg.chunks_exact(64) {
        let mut words = [0u32; 64];
        for (idx, word) in chunk.chunks_exact(4).enumerate() {
            words[idx] = u32::from_be_bytes([word[0], word[1], word[2], word[3]]);
        }
        for idx in 16..64 {
            let s0 = words[idx - 15].rotate_right(7) ^ words[idx - 15].rotate_right(18) ^ (words[idx - 15] >> 3);
            let s1 = words[idx - 2].rotate_right(17) ^ words[idx - 2].rotate_right(19) ^ (words[idx - 2] >> 10);
            words[idx] = words[idx - 16]
                .wrapping_add(s0)
                .wrapping_add(words[idx - 7])
                .wrapping_add(s1);
        }

        let [mut va, mut vb, mut vc, mut vd, mut ve, mut vf, mut vg, mut vh] = state;
        for idx in 0..64 {
            let s1 = ve.rotate_right(6) ^ ve.rotate_right(11) ^ ve.rotate_right(25);
            let ch = (ve & vf) ^ ((!ve) & vg);
            let temp1 = vh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[idx])
                .wrapping_add(words[idx]);
            let s0 = va.rotate_right(2) ^ va.rotate_right(13) ^ va.rotate_right(22);
            let maj = (va & vb) ^ (va & vc) ^ (vb & vc);
            let temp2 = s0.wrapping_add(maj);
            vh = vg;
            vg = vf;
            vf = ve;
            ve = vd.wrapping_add(temp1);
            vd = vc;
            vc = vb;
            vb = va;
            va = temp1.wrapping_add(temp2);
        }
        state[0] = state[0].wrapping_add(va);
        state[1] = state[1].wrapping_add(vb);
        state[2] = state[2].wrapping_add(vc);
        state[3] = state[3].wrapping_add(vd);
        state[4] = state[4].wrapping_add(ve);
        state[5] = state[5].wrapping_add(vf);
        state[6] = state[6].wrapping_add(vg);
        state[7] = state[7].wrapping_add(vh);
    }

    let mut out = Vec::with_capacity(32);
    for word in state {
        out.extend_from_slice(&word.to_be_bytes());
    }
    out
}

#[cfg(test)]
mod hash_tests {
    use super::{sha1_simple, sha256_simple};

    #[test]
    fn sha1_empty_known_vector() {
        // FIPS 180-4 test vector for the empty string.
        let got = sha1_simple(b"");
        let expected: [u8; 20] = [
            0xda, 0x39, 0xa3, 0xee, 0x5e, 0x6b, 0x4b, 0x0d, 0x32, 0x55, 0xbf, 0xef, 0x95, 0x60,
            0x18, 0x90, 0xaf, 0xd8, 0x07, 0x09,
        ];
        assert_eq!(got, expected.to_vec());
    }

    #[test]
    fn sha1_abc_known_vector() {
        let got = sha1_simple(b"abc");
        let expected: [u8; 20] = [
            0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a, 0xba, 0x3e, 0x25, 0x71, 0x78, 0x50,
            0xc2, 0x6c, 0x9c, 0xd0, 0xd8, 0x9d,
        ];
        assert_eq!(got, expected.to_vec());
    }

    #[test]
    fn sha256_empty_known_vector() {
        let got = sha256_simple(b"");
        let expected: [u8; 32] = [
            0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
            0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
            0x78, 0x52, 0xb8, 0x55,
        ];
        assert_eq!(got, expected.to_vec());
    }

    #[test]
    fn sha256_abc_known_vector() {
        let got = sha256_simple(b"abc");
        let expected: [u8; 32] = [
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
            0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
            0xf2, 0x00, 0x15, 0xad,
        ];
        assert_eq!(got, expected.to_vec());
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// IpaBinaryExtractor
// ─────────────────────────────────────────────────────────────────────────────

/// High-level extractor: finds the main executable inside an IPA.
pub struct IpaBinaryExtractor<'a> {
    reader: ZipReader<'a>,
}

impl<'a> IpaBinaryExtractor<'a> {
    /// Parse an IPA file.
    ///
    /// # Errors
    /// Returns an error if the data is not a valid ZIP/IPA file.
    pub fn open(data: &'a [u8]) -> Result<Self, ExtractError> {
        let reader = ZipReader::parse(data)?;
        Ok(Self { reader })
    }

    /// Return the `Payload/<App>.app` prefix.
    #[must_use]
    pub fn app_prefix(&self) -> Option<String> {
        for name in self.reader.entry_names() {
            if let Some(rest) = name.strip_prefix("Payload/")
                && let Some(app_end) = rest.find('/')
            {
                let app_dir = &rest[..app_end];
                if app_dir.to_ascii_lowercase().ends_with(".app") {
                    return Some(format!("Payload/{app_dir}/"));
                }
            }
        }
        None
    }

    /// Find the main executable name from `Info.plist`.
    #[must_use] 
    pub fn main_executable_name(&self) -> Option<String> {
        let prefix = self.app_prefix()?;
        let plist_path = format!("{prefix}Info.plist");
        let plist_data = self.reader.extract_by_name(&plist_path).ok()?;
        // Quick heuristic: look for CFBundleExecutable in the plist bytes.
        let s = std::str::from_utf8(&plist_data).ok()?;
        if let Some(pos) = s.find("CFBundleExecutable") {
            // XML plist: look for the next <string> tag.
            if let Some(str_start) = s[pos..].find("<string>") {
                let after = pos + str_start + 8;
                if let Some(str_end) = s[after..].find("</string>") {
                    return Some(s[after..after+str_end].to_string());
                }
            }
        }
        None
    }

    /// Extract the main binary as raw bytes.
    ///
    /// # Errors
    /// Returns [`ExtractError::NotFound`] if the app bundle or executable cannot be found,
    /// or propagates extraction errors.
    pub fn extract_main_binary(&self) -> Result<Vec<u8>, ExtractError> {
        let prefix = self.app_prefix().ok_or_else(|| ExtractError::NotFound("Payload/*.app/".into()))?;
        let exec_name = self.main_executable_name()
            .ok_or_else(|| ExtractError::NotFound("CFBundleExecutable".into()))?;
        let path = format!("{prefix}{exec_name}");
        self.reader.extract_by_name(&path)
    }

    /// List all `.dylib` files in the IPA.
    #[must_use]
    pub fn list_dylibs(&self) -> Vec<&str> {
        self.reader.entry_names().into_iter()
            .filter(|n| n.to_ascii_lowercase().ends_with(".dylib"))
            .collect()
    }

    /// List all Mach-O files (heuristic: check for `__TEXT` in path or `.dylib`/`.so`).
    #[must_use]
    pub fn list_binaries(&self) -> Vec<&str> {
        let prefix = self.app_prefix();
        self.reader.entry_names().into_iter().filter(|n| {
            let nl = n.to_ascii_lowercase();
            std::path::Path::new(&nl).extension().is_some_and(|e| e.eq_ignore_ascii_case("dylib"))
            || std::path::Path::new(&nl).extension().is_some_and(|e| e.eq_ignore_ascii_case("so"))
            || prefix.as_deref().is_some_and(|p| {
                n.starts_with(p) && !n.contains('.') && !n.ends_with('/')
            })
        }).collect()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fat_detection() {
        let fat_magic = FAT_MAGIC.to_be_bytes();
        assert!(FatSplitter::is_fat(&fat_magic));

        let thin_magic = MH_MAGIC_64.to_le_bytes();
        assert!(!FatSplitter::is_fat(&thin_magic));
        assert!(FatSplitter::is_thin_macho(&thin_magic));
    }

    #[test]
    fn test_cpu_type_from_i32() {
        assert_eq!(CpuType::from_i32(7), CpuType::X86);
        assert_eq!(CpuType::from_i32(0x0100_000C), CpuType::Arm64);
        assert_eq!(CpuType::from_i32(12), CpuType::Arm);
    }

    #[test]
    fn test_fat_parse_minimal() {
        let mut data = Vec::new();
        // FAT_MAGIC (BE) + n_archs = 1
        data.extend_from_slice(&FAT_MAGIC.to_be_bytes());
        data.extend_from_slice(&1u32.to_be_bytes());
        // One fat_arch: cpu_type=ARM64, subtype=0, offset=28, size=4, align=12
        data.extend_from_slice(&(0x0100_000Cu32).to_be_bytes()); // cpu_type
        data.extend_from_slice(&0u32.to_be_bytes());              // cpu_subtype
        data.extend_from_slice(&28u32.to_be_bytes());             // offset
        data.extend_from_slice(&4u32.to_be_bytes());              // size
        data.extend_from_slice(&12u32.to_be_bytes());             // align
        // Placeholder slice data
        data.extend_from_slice(&[0xCF, 0xFA, 0xED, 0xFE]); // MH_CIGAM_64

        let archs = FatSplitter::parse_fat_archs(&data).unwrap();
        assert_eq!(archs.len(), 1);
        assert_eq!(archs[0].cpu_type, CpuType::Arm64);

        let slices = FatSplitter::split(&data).unwrap();
        assert_eq!(slices.len(), 1);
        assert_eq!(slices[0].data, &[0xCF, 0xFA, 0xED, 0xFE]);
    }

    #[test]
    fn test_zip_bad_magic() {
        let data = b"NOTAZIP";
        assert_eq!(ZipReader::parse(data).unwrap_err(), ExtractError::NotZip);
    }

    #[test]
    fn test_code_directory_bad_magic() {
        let data = [0x00u8; 48];
        let result = CodeDirectory::parse(&data);
        assert!(matches!(result.unwrap_err(), ExtractError::CodeSignatureError(_)));
    }
}
