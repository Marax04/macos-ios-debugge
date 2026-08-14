//! `rustre-mobile-ipa::fairplay_detect`
//!
//! `FairPlay` DRM detection for Mach-O binaries.
//!
//! FairPlay-encrypted App Store binaries have their `__TEXT` segment encrypted
//! and carry one of two load commands that record the encrypted region:
//!
//! * `LC_ENCRYPTION_INFO`    (0x21) — used in 32-bit Mach-O.
//! * `LC_ENCRYPTION_INFO_64` (0x2C) — used in 64-bit Mach-O.
//!
//! When `cryptid` in this command is non-zero, the binary is FairPlay-encrypted.
//! `cryptid == 0` means the encryption has been removed (decrypted dump).

// ─────────────────────────────────────────────────────────────────────────────
// Mach-O constants
// ─────────────────────────────────────────────────────────────────────────────

const MH_MAGIC: u32 = 0xFEED_FACE;
const MH_CIGAM: u32 = 0xCEFA_EDFE;
const MH_MAGIC_64: u32 = 0xFEED_FACF;
const MH_CIGAM_64: u32 = 0xCFFA_EDFE;
const FAT_MAGIC: u32 = 0xCAFE_BABE;
const FAT_CIGAM: u32 = 0xBEBA_FECA;

const LC_ENCRYPTION_INFO: u32 = 0x21;
const LC_ENCRYPTION_INFO_64: u32 = 0x2C;

// ─────────────────────────────────────────────────────────────────────────────
// EncryptionInfo
// ─────────────────────────────────────────────────────────────────────────────

/// Parsed `encryption_info_command` / `encryption_info_command_64` data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptionInfo {
    /// Byte offset of encrypted range within the file.
    pub crypt_offset: u32,
    /// Byte size of the encrypted range.
    pub crypt_size: u32,
    /// `FairPlay` encryption ID.  `0` means not encrypted (stripped/decrypted).
    pub crypt_id: u32,
    /// Whether this came from an `LC_ENCRYPTION_INFO_64` load command.
    pub is_64bit: bool,
}

impl EncryptionInfo {
    /// Returns `true` when the binary region is FairPlay-encrypted.
    #[must_use]
    pub const fn is_encrypted(&self) -> bool {
        self.crypt_id != 0
    }

    /// Returns the encrypted byte range as `(offset, size)`.
    #[must_use]
    pub const fn range(&self) -> (u32, u32) {
        (self.crypt_offset, self.crypt_size)
    }
}

impl std::fmt::Display for EncryptionInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "EncryptionInfo {{ offset={:#x}, size={:#x}, id={}, 64bit={} }}",
            self.crypt_offset, self.crypt_size, self.crypt_id, self.is_64bit
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// FairPlaySignature
// ─────────────────────────────────────────────────────────────────────────────

/// A `FairPlay` code signature entry (placeholder — actual decryption not supported).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FairPlaySignature {
    /// Byte offset of the `__LINKEDIT` segment within the binary.
    pub linkedit_offset: usize,
    /// Raw DER bytes of the embedded signature blob (if found).
    pub signature_blob: Vec<u8>,
}

// ─────────────────────────────────────────────────────────────────────────────
// FairPlayDetector
// ─────────────────────────────────────────────────────────────────────────────

/// Scans a Mach-O binary for `FairPlay` DRM markers.
pub struct FairPlayDetector<'a> {
    data: &'a [u8],
}

impl<'a> FairPlayDetector<'a> {
    /// Create a new detector for `data`.
    #[must_use]
    pub const fn new(data: &'a [u8]) -> Self {
        Self { data }
    }

    /// Returns `true` when `data` starts with a Mach-O or FAT magic.
    #[must_use]
    pub fn is_macho(&self) -> bool {
        is_macho(self.data)
    }

    /// Scan the binary and return all `EncryptionInfo` entries found.
    ///
    /// Handles:
    /// * Thin 32-bit and 64-bit Mach-O.
    /// * FAT binaries (each arch slice is scanned).
    #[must_use]
    pub fn find_encryption_info(&self) -> Vec<EncryptionInfo> {
        let data = self.data;
        if data.len() < 4 {
            return vec![];
        }

        let magic = u32::from_le_bytes(data[0..4].try_into().unwrap_or([0; 4]));
        let magic_be = u32::from_be_bytes(data[0..4].try_into().unwrap_or([0; 4]));

        if magic == FAT_MAGIC
            || magic_be == FAT_MAGIC
            || magic == FAT_CIGAM
            || magic_be == FAT_CIGAM
        {
            return self.scan_fat();
        }
        Self::scan_thin(data)
    }

    /// Returns `true` when any slice of the binary is FairPlay-encrypted.
    #[must_use]
    pub fn is_fairplay_encrypted(&self) -> bool {
        self.find_encryption_info()
            .iter()
            .any(EncryptionInfo::is_encrypted)
    }

    /// Return all `EncryptionInfo` entries where `crypt_id != 0`.
    #[must_use]
    pub fn encrypted_regions(&self) -> Vec<EncryptionInfo> {
        self.find_encryption_info()
            .into_iter()
            .filter(EncryptionInfo::is_encrypted)
            .collect()
    }

    // ── Private helpers ────────────────────────────────────────────────────────

    fn scan_fat(&self) -> Vec<EncryptionInfo> {
        let data = self.data;
        if data.len() < 8 {
            return vec![];
        }
        // FAT header: magic(4) + nfat_arch(4)
        let be = u32::from_be_bytes(data[0..4].try_into().unwrap()) == FAT_MAGIC;
        let nfat = if be {
            u32::from_be_bytes(data[4..8].try_into().unwrap_or([0; 4]))
        } else {
            u32::from_le_bytes(data[4..8].try_into().unwrap_or([0; 4]))
        } as usize;

        let mut results = Vec::new();
        // Each fat_arch entry: cputype(4) + cpusubtype(4) + offset(4) + size(4) + align(4) = 20 bytes
        for i in 0..nfat {
            let entry_off = 8 + i * 20;
            if entry_off + 20 > data.len() {
                break;
            }
            let slice_off = if be {
                u32::from_be_bytes(data[entry_off + 8..entry_off + 12].try_into().unwrap()) as usize
            } else {
                u32::from_le_bytes(data[entry_off + 8..entry_off + 12].try_into().unwrap()) as usize
            };
            let slice_size = if be {
                u32::from_be_bytes(data[entry_off + 12..entry_off + 16].try_into().unwrap())
                    as usize
            } else {
                u32::from_le_bytes(data[entry_off + 12..entry_off + 16].try_into().unwrap())
                    as usize
            };
            if slice_off + slice_size > data.len() {
                continue;
            }
            let slice = &data[slice_off..slice_off + slice_size];
            results.extend(Self::scan_thin(slice));
        }
        results
    }

    fn scan_thin(data: &[u8]) -> Vec<EncryptionInfo> {
        if data.len() < 8 {
            return vec![];
        }
        let magic = u32::from_le_bytes(data[0..4].try_into().unwrap_or([0; 4]));
        let swap = magic == MH_CIGAM || magic == MH_CIGAM_64;
        let is64 = magic == MH_MAGIC_64 || magic == MH_CIGAM_64;

        let rd32 = |off: usize| -> u32 {
            if off + 4 > data.len() {
                return 0;
            }
            let b: [u8; 4] = data[off..off + 4].try_into().unwrap_or([0; 4]);
            if swap {
                u32::from_be_bytes(b)
            } else {
                u32::from_le_bytes(b)
            }
        };

        // Mach-O header size: 28 bytes (32-bit) or 32 bytes (64-bit)
        let hdr_size = if is64 { 32usize } else { 28usize };
        if data.len() < hdr_size {
            return vec![];
        }

        let ncmds = rd32(16) as usize;
        let sizeofcmds = rd32(20) as usize;
        let _ = sizeofcmds;

        let mut off = hdr_size;
        let mut results = Vec::new();

        for _ in 0..ncmds {
            if off + 8 > data.len() {
                break;
            }
            let cmd = rd32(off);
            let cmdsize = rd32(off + 4) as usize;
            if cmdsize < 8 {
                break;
            }

            if cmd == LC_ENCRYPTION_INFO {
                if off + 20 <= data.len() {
                    let crypt_offset = rd32(off + 8);
                    let crypt_size = rd32(off + 12);
                    let crypt_id = rd32(off + 16);
                    results.push(EncryptionInfo {
                        crypt_offset,
                        crypt_size,
                        crypt_id,
                        is_64bit: false,
                    });
                }
            } else if cmd == LC_ENCRYPTION_INFO_64 && off + 20 <= data.len() {
                let crypt_offset = rd32(off + 8);
                let crypt_size = rd32(off + 12);
                let crypt_id = rd32(off + 16);
                results.push(EncryptionInfo {
                    crypt_offset,
                    crypt_size,
                    crypt_id,
                    is_64bit: true,
                });
            }

            off += cmdsize;
        }

        results
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// is_fairplay_encrypted — standalone function
// ─────────────────────────────────────────────────────────────────────────────

/// Returns `true` when `macho_data` contains a FairPlay-encrypted segment.
#[must_use]
pub fn is_fairplay_encrypted(macho_data: &[u8]) -> bool {
    FairPlayDetector::new(macho_data).is_fairplay_encrypted()
}

/// Returns `true` when `data` starts with a recognised Mach-O magic.
#[must_use]
pub fn is_macho(data: &[u8]) -> bool {
    if data.len() < 4 {
        return false;
    }
    let le = u32::from_le_bytes(data[0..4].try_into().unwrap_or([0; 4]));
    let be = u32::from_be_bytes(data[0..4].try_into().unwrap_or([0; 4]));
    matches!(le, MH_MAGIC | MH_CIGAM | MH_MAGIC_64 | MH_CIGAM_64)
        || matches!(be, FAT_MAGIC | FAT_CIGAM)
}

/// Note for callers: `FairPlay` decryption requires running on a jailbroken device.
///
/// This function always returns an error to make the limitation explicit.
///
/// # Errors
///
/// Always returns `Err` — actual decryption is not implemented.
pub fn decrypt_stub(_macho_data: &[u8]) -> Result<Vec<u8>, String> {
    Err(
        "FairPlay decryption is not implemented: it requires running on-device \
         with the FairPlay kernel extension active. Use a jailbroken device tool \
         such as frida-ios-dump or clutch to extract the decrypted binary."
            .to_string(),
    )
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── is_macho ──────────────────────────────────────────────────────────────

    #[test]
    fn test_is_macho_little_endian_32() {
        let magic = MH_MAGIC.to_le_bytes();
        assert!(is_macho(&magic));
    }

    #[test]
    fn test_is_macho_little_endian_64() {
        let magic = MH_MAGIC_64.to_le_bytes();
        assert!(is_macho(&magic));
    }

    #[test]
    fn test_is_macho_fat() {
        let magic = FAT_MAGIC.to_be_bytes();
        assert!(is_macho(&magic));
    }

    #[test]
    fn test_is_macho_false_for_elf() {
        assert!(!is_macho(b"\x7FELF"));
    }

    #[test]
    fn test_is_macho_false_for_zip() {
        assert!(!is_macho(b"PK\x03\x04"));
    }

    #[test]
    fn test_is_macho_too_short() {
        assert!(!is_macho(&[0xCE, 0xFA]));
    }

    // ── EncryptionInfo ────────────────────────────────────────────────────────

    #[test]
    fn test_encryption_info_is_encrypted_true() {
        let ei = EncryptionInfo {
            crypt_offset: 0x1000,
            crypt_size: 0x8000,
            crypt_id: 1,
            is_64bit: true,
        };
        assert!(ei.is_encrypted());
    }

    #[test]
    fn test_encryption_info_is_encrypted_false() {
        let ei = EncryptionInfo {
            crypt_offset: 0x1000,
            crypt_size: 0x8000,
            crypt_id: 0,
            is_64bit: true,
        };
        assert!(!ei.is_encrypted());
    }

    #[test]
    fn test_encryption_info_range() {
        let ei = EncryptionInfo {
            crypt_offset: 0x100,
            crypt_size: 0x400,
            crypt_id: 1,
            is_64bit: false,
        };
        assert_eq!(ei.range(), (0x100, 0x400));
    }

    #[test]
    fn test_encryption_info_display() {
        let ei = EncryptionInfo {
            crypt_offset: 0x1000,
            crypt_size: 0x8000,
            crypt_id: 1,
            is_64bit: true,
        };
        let s = ei.to_string();
        assert!(s.contains("id=1"));
        assert!(s.contains("64bit=true"));
    }

    // ── FairPlayDetector ──────────────────────────────────────────────────────

    #[test]
    fn test_detector_not_macho() {
        let d = FairPlayDetector::new(b"not macho");
        assert!(!d.is_macho());
        assert!(!d.is_fairplay_encrypted());
    }

    #[test]
    fn test_detector_empty() {
        let d = FairPlayDetector::new(&[]);
        assert!(!d.is_macho());
        assert!(d.find_encryption_info().is_empty());
    }

    fn make_thin_64_with_enc_info(crypt_id: u32) -> Vec<u8> {
        // MH_MAGIC_64 LE header: magic(4) + cputype(4) + cpusubtype(4) + filetype(4)
        //                       + ncmds(4) + sizeofcmds(4) + flags(4) + reserved(4) = 32 bytes
        // Then LC_ENCRYPTION_INFO_64: cmd(4) + cmdsize(4) + cryptoff(4) + cryptsize(4) + cryptid(4) + pad(4) = 24 bytes
        let mut v: Vec<u8> = Vec::new();
        // magic
        v.extend_from_slice(&MH_MAGIC_64.to_le_bytes());
        // cputype (ARM64 = 0x0100_000C)
        v.extend_from_slice(&0x0100_000C_u32.to_le_bytes());
        // cpusubtype
        v.extend_from_slice(&0_u32.to_le_bytes());
        // filetype MH_EXECUTE = 2
        v.extend_from_slice(&2_u32.to_le_bytes());
        // ncmds = 1
        v.extend_from_slice(&1_u32.to_le_bytes());
        // sizeofcmds = 24
        v.extend_from_slice(&24_u32.to_le_bytes());
        // flags
        v.extend_from_slice(&0_u32.to_le_bytes());
        // reserved
        v.extend_from_slice(&0_u32.to_le_bytes());
        // LC_ENCRYPTION_INFO_64 = 0x2C
        v.extend_from_slice(&LC_ENCRYPTION_INFO_64.to_le_bytes());
        // cmdsize = 24
        v.extend_from_slice(&24_u32.to_le_bytes());
        // cryptoff
        v.extend_from_slice(&0x4000_u32.to_le_bytes());
        // cryptsize
        v.extend_from_slice(&0x8000_u32.to_le_bytes());
        // cryptid
        v.extend_from_slice(&crypt_id.to_le_bytes());
        // pad
        v.extend_from_slice(&0_u32.to_le_bytes());
        v
    }

    #[test]
    fn test_detector_encrypted_binary() {
        let data = make_thin_64_with_enc_info(1);
        let d = FairPlayDetector::new(&data);
        assert!(d.is_macho());
        assert!(d.is_fairplay_encrypted());
        let info = d.find_encryption_info();
        assert_eq!(info.len(), 1);
        assert!(info[0].is_encrypted());
        assert!(info[0].is_64bit);
    }

    #[test]
    fn test_detector_decrypted_binary() {
        let data = make_thin_64_with_enc_info(0);
        let d = FairPlayDetector::new(&data);
        assert!(!d.is_fairplay_encrypted());
    }

    #[test]
    fn test_detector_no_enc_cmd() {
        // Binary with no LC_ENCRYPTION_INFO_64
        let mut v: Vec<u8> = Vec::new();
        v.extend_from_slice(&MH_MAGIC_64.to_le_bytes());
        v.extend_from_slice(&[0u8; 28]); // rest of header with ncmds=0
        let d = FairPlayDetector::new(&v);
        assert!(d.is_macho());
        assert!(!d.is_fairplay_encrypted());
        assert!(d.find_encryption_info().is_empty());
    }

    #[test]
    fn test_encrypted_regions_filter() {
        let data = make_thin_64_with_enc_info(1);
        let d = FairPlayDetector::new(&data);
        let regions = d.encrypted_regions();
        assert_eq!(regions.len(), 1);
    }

    #[test]
    fn test_encrypted_regions_empty_when_decrypted() {
        let data = make_thin_64_with_enc_info(0);
        let d = FairPlayDetector::new(&data);
        assert!(d.encrypted_regions().is_empty());
    }

    // ── is_fairplay_encrypted (standalone) ────────────────────────────────────

    #[test]
    fn test_standalone_encrypted() {
        let data = make_thin_64_with_enc_info(1);
        assert!(is_fairplay_encrypted(&data));
    }

    #[test]
    fn test_standalone_not_encrypted() {
        let data = make_thin_64_with_enc_info(0);
        assert!(!is_fairplay_encrypted(&data));
    }

    // ── decrypt_stub ──────────────────────────────────────────────────────────

    #[test]
    fn test_decrypt_stub_always_errors() {
        assert!(decrypt_stub(&[]).is_err());
        assert!(decrypt_stub(&make_thin_64_with_enc_info(1)).is_err());
        let msg = decrypt_stub(&[]).unwrap_err();
        assert!(msg.contains("FairPlay decryption is not implemented"));
    }
}
