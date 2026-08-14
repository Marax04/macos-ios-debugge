//! `FairPlay` DRM encryption detection and decryption workflow.
//!
//! Apple's `FairPlay` encrypts a segment of the Mach-O binary (the `__TEXT`
//! segment) identified by the `LC_ENCRYPTION_INFO` / `LC_ENCRYPTION_INFO_64`
//! load commands.  The encryption can only be removed at runtime by the device
//! kernel; offline decryption requires a jailbroken device.
//!
//! This module provides:
//! 1. Detection of `FairPlay` encryption via Mach-O parsing.
//! 2. Documentation of the frida-ios-dump / bagbak workflow.
//! 3. A helper to patch a pre-dumped binary back into a re-packaged IPA.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use thiserror::Error;

// ─── Error ────────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum DecryptError {
    #[error("io error: {0}")]
    Io(String),
    #[error("invalid mach-o: {0}")]
    InvalidMachO(String),
    #[error("not encrypted (crypt_id=0)")]
    NotEncrypted,
    #[error("unsupported architecture: {0}")]
    UnsupportedArch(String),
    #[error("patch failed: {0}")]
    PatchFailed(String),
}

// ─── Mach-O constants ─────────────────────────────────────────────────────────

const MH_MAGIC: u32 = 0xFEED_FACE;
const MH_CIGAM: u32 = 0xCEFA_EDFE;
const MH_MAGIC_64: u32 = 0xFEED_FACF;
const MH_CIGAM_64: u32 = 0xCFFA_EDFE;
const FAT_MAGIC: u32 = 0xCAFE_BABE;
const FAT_MAGIC_64: u32 = 0xCAFE_BABF;

const LC_ENCRYPTION_INFO: u32 = 0x21;
const LC_ENCRYPTION_INFO_64: u32 = 0x2C;

// ─── EncryptionInfo ───────────────────────────────────────────────────────────

/// Raw parsed values from `LC_ENCRYPTION_INFO[_64]`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptionInfo {
    /// Load command type (`LC_ENCRYPTION_INFO` or `LC_ENCRYPTION_INFO_64`).
    pub cmd: u32,
    /// Byte offset of the encrypted region within the file.
    pub crypt_offset: u32,
    /// Size in bytes of the encrypted region.
    pub crypt_size: u32,
    /// Encryption system identifier. `0` = not encrypted; `1` = `FairPlay`.
    pub crypt_id: u32,
}

impl EncryptionInfo {
    /// Return `true` if the region is encrypted (`crypt_id` != 0).
    #[must_use]
    pub const fn is_encrypted(&self) -> bool {
        self.crypt_id != 0
    }

    /// Return a human-readable description of the encryption scheme.
    #[must_use]
    pub const fn scheme_name(&self) -> &'static str {
        match self.crypt_id {
            0 => "None",
            1 => "FairPlay",
            _ => "Unknown",
        }
    }
}

// ─── FairPlayInfo ─────────────────────────────────────────────────────────────

/// High-level `FairPlay` encryption status for an IPA/binary.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FairPlayInfo {
    /// `true` if any slice is FairPlay-encrypted.
    pub is_encrypted: bool,
    /// Encryption info per architecture slice (e.g. for fat binaries).
    pub slices: Vec<FairPlaySlice>,
}

/// `FairPlay` status for a single Mach-O slice.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FairPlaySlice {
    /// CPU type of this slice.
    pub arch: String,
    /// File offset where this Mach-O slice starts.
    pub file_offset: u32,
    pub encryption_info: Option<EncryptionInfo>,
}

impl FairPlaySlice {
    /// Return `true` if this slice is FairPlay-encrypted.
    #[must_use]
    pub fn is_encrypted(&self) -> bool {
        self.encryption_info
            .as_ref()
            .is_some_and(EncryptionInfo::is_encrypted)
    }
}

// ─── Mach-O helpers ───────────────────────────────────────────────────────────

fn read_u32_at(data: &[u8], offset: usize, swap: bool) -> Option<u32> {
    let b = data.get(offset..offset + 4)?;
    let v = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
    if swap { Some(v.swap_bytes()) } else { Some(v) }
}

fn parse_load_commands(data: &[u8], offset: usize, swap: bool) -> Option<EncryptionInfo> {
    // Determine if 64-bit.
    let magic = read_u32_at(data, offset, false)?;
    let is_64 = matches!(magic, MH_MAGIC_64 | MH_CIGAM_64);
    let header_size = if is_64 { 32usize } else { 28usize };

    let ncmds = read_u32_at(data, offset + 16, swap)? as usize;

    let mut pos = offset + header_size;
    for _ in 0..ncmds {
        if pos + 8 > data.len() {
            break;
        }
        let cmd = read_u32_at(data, pos, swap)?;
        let cmd_size = read_u32_at(data, pos + 4, swap)? as usize;
        if cmd_size < 8 {
            break;
        }

        if cmd == LC_ENCRYPTION_INFO || cmd == LC_ENCRYPTION_INFO_64 {
            // struct: cmd u32, cmdsize u32, cryptoff u32, cryptsize u32, cryptid u32
            if pos + 20 <= data.len() {
                let crypt_offset = read_u32_at(data, pos + 8, swap)?;
                let crypt_size = read_u32_at(data, pos + 12, swap)?;
                let crypt_id = read_u32_at(data, pos + 16, swap)?;
                return Some(EncryptionInfo {
                    cmd,
                    crypt_offset,
                    crypt_size,
                    crypt_id,
                });
            }
        }

        pos += cmd_size;
    }
    None
}

fn cpu_arch_name(cputype: u32) -> String {
    match cputype {
        0x0000_000C => "armv7".to_string(),
        0x0100_000C => "arm64".to_string(),
        0x0000_0007 => "i386".to_string(),
        0x0100_0007 => "x86_64".to_string(),
        _ => format!("cpu_{cputype:#010x}"),
    }
}

// ─── detect_fairplay ──────────────────────────────────────────────────────────

/// Detect `FairPlay` encryption in a raw Mach-O or fat binary.
///
/// Parses `LC_ENCRYPTION_INFO` / `LC_ENCRYPTION_INFO_64` load commands from
/// each architecture slice.
#[must_use]
pub fn detect_fairplay(data: &[u8]) -> FairPlayInfo {
    if data.len() < 8 {
        return FairPlayInfo::default();
    }

    let magic = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);

    match magic {
        FAT_MAGIC | FAT_MAGIC_64 => {
            // Fat binary: iterate slices.
            let nfat_arch = u32::from_be_bytes([data[4], data[5], data[6], data[7]]) as usize;
            let mut info = FairPlayInfo::default();

            for i in 0..nfat_arch.min(16) {
                let base = 8 + i * 20;
                if base + 20 > data.len() {
                    break;
                }
                let cputype = u32::from_be_bytes([
                    data[base],
                    data[base + 1],
                    data[base + 2],
                    data[base + 3],
                ]);
                let offset = u32::from_be_bytes([
                    data[base + 8],
                    data[base + 9],
                    data[base + 10],
                    data[base + 11],
                ]) as usize;

                let enc = parse_load_commands(data, offset, false);
                let is_enc = enc.as_ref().is_some_and(EncryptionInfo::is_encrypted);

                if is_enc {
                    info.is_encrypted = true;
                }

                info.slices.push(FairPlaySlice {
                    arch: cpu_arch_name(cputype),
                    file_offset: u32::try_from(offset).unwrap_or(u32::MAX),
                    encryption_info: enc,
                });
            }
            info
        }
        MH_MAGIC | MH_CIGAM | MH_MAGIC_64 | MH_CIGAM_64 => {
            let swap = matches!(magic, MH_CIGAM | MH_CIGAM_64);
            let enc = parse_load_commands(data, 0, swap);
            let is_enc = enc.as_ref().is_some_and(EncryptionInfo::is_encrypted);
            let cputype = read_u32_at(data, 4, swap).unwrap_or(0);
            let arch = cpu_arch_name(cputype);
            FairPlayInfo {
                is_encrypted: is_enc,
                slices: vec![FairPlaySlice {
                    arch,
                    file_offset: 0,
                    encryption_info: enc,
                }],
            }
        }
        _ => FairPlayInfo::default(),
    }
}

// ─── Decryption workflow documentation ───────────────────────────────────────

/// Instructions for decrypting a FairPlay-encrypted IPA on a jailbroken device.
///
/// Full offline decryption is impossible without a jailbroken device because
/// the `FairPlay` key is stored in the Secure Enclave and the decryption happens
/// inside the kernel.  The recommended workflow is:
///
/// 1. Install the app on a jailbroken device running `frida-server`.
/// 2. Run `frida-ios-dump` or `bagbak`:
///    ```text
///    frida-ios-dump -H 192.168.1.100 com.example.App
///    # or
///    bagbak --output ./decrypted com.example.App
///    ```
/// 3. The tool attaches to the running process, reads the decrypted __TEXT
///    segment from memory, and patches it back into the on-disk binary.
/// 4. Call [`apply_dump`] to re-integrate the decrypted binary into a new IPA.
#[must_use]
pub const fn decryption_workflow() -> &'static str {
    "Use frida-ios-dump or bagbak on a jailbroken device to extract the decrypted binary, \
     then call apply_dump() to patch it into the IPA."
}

// ─── apply_dump ───────────────────────────────────────────────────────────────

/// Patch a decrypted binary slice back into an IPA.
///
/// After obtaining a decrypted Mach-O from a jailbroken device, this function:
/// 1. Validates the decrypted binary (checks magic).
/// 2. Zeroes the `crypt_id` field in the embedded `LC_ENCRYPTION_INFO`.
/// 3. Writes the patched binary to `output_dir/<executable_name>`.
///
/// The caller is responsible for re-zipping the IPA afterwards.
///
/// # Errors
/// Returns [`DecryptError`] if the binary is invalid or the operation fails.
pub fn apply_dump(
    decrypted_binary: &[u8],
    executable_name: &str,
    output_dir: &Path,
) -> Result<PathBuf, DecryptError> {
    if decrypted_binary.len() < 4 {
        return Err(DecryptError::InvalidMachO("too short".into()));
    }

    let magic = u32::from_le_bytes([
        decrypted_binary[0],
        decrypted_binary[1],
        decrypted_binary[2],
        decrypted_binary[3],
    ]);

    if !matches!(
        magic,
        MH_MAGIC | MH_CIGAM | MH_MAGIC_64 | MH_CIGAM_64 | FAT_MAGIC | FAT_MAGIC_64
    ) {
        return Err(DecryptError::InvalidMachO(format!(
            "bad magic {magic:#010x}"
        )));
    }

    let mut patched = decrypted_binary.to_vec();

    // Zero out crypt_id in LC_ENCRYPTION_INFO to mark as decrypted.
    let swap = matches!(magic, MH_CIGAM | MH_CIGAM_64);
    zero_crypt_id(&mut patched, 0, swap);

    let out_path = output_dir.join(executable_name);
    std::fs::write(&out_path, &patched).map_err(|e| DecryptError::Io(e.to_string()))?;

    Ok(out_path)
}

fn zero_crypt_id(data: &mut [u8], offset: usize, swap: bool) {
    if data.len() < offset + 8 {
        return;
    }
    let magic = u32::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ]);
    let is_64 = matches!(magic, MH_MAGIC_64 | MH_CIGAM_64);
    let header_size = if is_64 { 32usize } else { 28usize };

    let ncmds_raw = u32::from_le_bytes([
        data[offset + 16],
        data[offset + 17],
        data[offset + 18],
        data[offset + 19],
    ]);
    let ncmds = if swap {
        ncmds_raw.swap_bytes()
    } else {
        ncmds_raw
    } as usize;

    let mut pos = offset + header_size;
    for _ in 0..ncmds {
        if pos + 8 > data.len() {
            break;
        }
        let cmd_raw = u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
        let cmd = if swap { cmd_raw.swap_bytes() } else { cmd_raw };
        let size_raw =
            u32::from_le_bytes([data[pos + 4], data[pos + 5], data[pos + 6], data[pos + 7]]);
        let cmd_size = (if swap {
            size_raw.swap_bytes()
        } else {
            size_raw
        }) as usize;

        if cmd == LC_ENCRYPTION_INFO || cmd == LC_ENCRYPTION_INFO_64 {
            if pos + 20 <= data.len() {
                // Zero crypt_id at pos + 16.
                data[pos + 16] = 0;
                data[pos + 17] = 0;
                data[pos + 18] = 0;
                data[pos + 19] = 0;
            }
            return;
        }

        if cmd_size < 8 {
            break;
        }
        pos += cmd_size;
    }
}

// ─── CryptInfo summary ────────────────────────────────────────────────────────

/// A summary of the encryption state of a binary for display.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptSummary {
    pub total_slices: usize,
    pub encrypted_slices: usize,
    pub has_fairplay: bool,
    pub arch_list: Vec<String>,
}

impl CryptSummary {
    /// Build from [`FairPlayInfo`].
    #[must_use]
    pub fn from_fairplay_info(info: &FairPlayInfo) -> Self {
        let encrypted_slices = info.slices.iter().filter(|s| s.is_encrypted()).count();
        let arch_list = info.slices.iter().map(|s| s.arch.clone()).collect();
        Self {
            total_slices: info.slices.len(),
            encrypted_slices,
            has_fairplay: info.is_encrypted,
            arch_list,
        }
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_thin_macho_with_encryption(crypt_id: u32) -> Vec<u8> {
        // Minimal arm64 Mach-O header with one LC_ENCRYPTION_INFO_64 load command.
        let mut data = Vec::new();

        // Mach-O header (arm64, LE):
        // magic, cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags
        data.extend_from_slice(&MH_MAGIC_64.to_le_bytes()); // magic
        data.extend_from_slice(&0x0100_000Cu32.to_le_bytes()); // cputype arm64
        data.extend_from_slice(&0u32.to_le_bytes()); // cpusubtype
        data.extend_from_slice(&2u32.to_le_bytes()); // filetype MH_EXECUTE
        data.extend_from_slice(&1u32.to_le_bytes()); // ncmds = 1
        data.extend_from_slice(&20u32.to_le_bytes()); // sizeofcmds = 20
        data.extend_from_slice(&0u32.to_le_bytes()); // flags
        data.extend_from_slice(&0u32.to_le_bytes()); // reserved (64-bit)

        // LC_ENCRYPTION_INFO_64: cmd, cmdsize, cryptoff, cryptsize, cryptid, pad
        data.extend_from_slice(&LC_ENCRYPTION_INFO_64.to_le_bytes()); // cmd
        data.extend_from_slice(&24u32.to_le_bytes()); // cmdsize = 24
        data.extend_from_slice(&0x4000u32.to_le_bytes()); // cryptoff
        data.extend_from_slice(&0x4000u32.to_le_bytes()); // cryptsize
        data.extend_from_slice(&crypt_id.to_le_bytes()); // cryptid
        data.extend_from_slice(&0u32.to_le_bytes()); // pad

        data
    }

    #[test]
    fn test_detect_fairplay_encrypted() {
        let data = make_thin_macho_with_encryption(1);
        let info = detect_fairplay(&data);
        assert!(info.is_encrypted);
        assert_eq!(info.slices.len(), 1);
        assert!(info.slices[0].is_encrypted());
    }

    #[test]
    fn test_detect_fairplay_not_encrypted() {
        let data = make_thin_macho_with_encryption(0);
        let info = detect_fairplay(&data);
        assert!(!info.is_encrypted);
    }

    #[test]
    fn test_detect_fairplay_empty() {
        let info = detect_fairplay(&[]);
        assert!(!info.is_encrypted);
    }

    #[test]
    fn test_detect_fairplay_random() {
        let info = detect_fairplay(&[0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00]);
        assert!(!info.is_encrypted);
    }

    #[test]
    fn test_encryption_info_scheme_name() {
        let ei = EncryptionInfo {
            cmd: LC_ENCRYPTION_INFO_64,
            crypt_offset: 0,
            crypt_size: 0,
            crypt_id: 1,
        };
        assert_eq!(ei.scheme_name(), "FairPlay");
        let ei2 = EncryptionInfo {
            cmd: LC_ENCRYPTION_INFO_64,
            crypt_offset: 0,
            crypt_size: 0,
            crypt_id: 0,
        };
        assert_eq!(ei2.scheme_name(), "None");
    }

    #[test]
    fn test_encryption_info_is_encrypted() {
        let ei = EncryptionInfo {
            cmd: LC_ENCRYPTION_INFO,
            crypt_offset: 0x4000,
            crypt_size: 0x4000,
            crypt_id: 1,
        };
        assert!(ei.is_encrypted());
    }

    #[test]
    fn test_apply_dump_invalid_magic() {
        let err = apply_dump(
            &[0xDE, 0xAD, 0xBE, 0xEF, 0, 0, 0, 0],
            "App",
            Path::new("/tmp"),
        )
        .unwrap_err();
        assert!(matches!(err, DecryptError::InvalidMachO(_)));
    }

    #[test]
    fn test_apply_dump_too_short() {
        let err = apply_dump(&[], "App", Path::new("/tmp")).unwrap_err();
        assert!(matches!(err, DecryptError::InvalidMachO(_)));
    }

    #[test]
    fn test_crypt_summary_from_fairplay() {
        let data = make_thin_macho_with_encryption(1);
        let info = detect_fairplay(&data);
        let summary = CryptSummary::from_fairplay_info(&info);
        assert_eq!(summary.total_slices, 1);
        assert_eq!(summary.encrypted_slices, 1);
        assert!(summary.has_fairplay);
    }

    #[test]
    fn test_crypt_summary_not_encrypted() {
        let data = make_thin_macho_with_encryption(0);
        let info = detect_fairplay(&data);
        let summary = CryptSummary::from_fairplay_info(&info);
        assert_eq!(summary.encrypted_slices, 0);
        assert!(!summary.has_fairplay);
    }

    #[test]
    fn test_decryption_workflow_not_empty() {
        assert!(!decryption_workflow().is_empty());
    }

    #[test]
    fn test_fairplay_info_default() {
        let info = FairPlayInfo::default();
        assert!(!info.is_encrypted);
        assert!(info.slices.is_empty());
    }

    #[test]
    fn test_decrypt_error_display() {
        assert!(
            DecryptError::NotEncrypted
                .to_string()
                .contains("not encrypted")
        );
        assert!(
            DecryptError::InvalidMachO("x".into())
                .to_string()
                .contains('x')
        );
        assert!(
            DecryptError::UnsupportedArch("x86".into())
                .to_string()
                .contains("x86")
        );
    }

    #[test]
    fn test_arch_name_called() {
        // Just verify cpu_arch_name doesn't panic for known types.
        let _ = cpu_arch_name(12);
        let _ = cpu_arch_name(0x0100_000C);
    }
}
