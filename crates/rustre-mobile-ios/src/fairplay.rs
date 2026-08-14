//! `FairPlay` DRM detection and analysis for iOS/macOS `Mach-O` binaries.
//!
//! Reads [`LC_ENCRYPTION_INFO`] / [`LC_ENCRYPTION_INFO_64`] load commands to
//! determine whether a binary is FairPlay-encrypted, and provides hooks for
//! decrypted-dump workflows via USB + Frida-based memory extraction. The main
//! entry points are [`detect_fairplay`], [`check_binary`], and [`DumpSession`].

use std::fmt;
use serde::{Deserialize, Serialize};
use thiserror::Error;

// ─── Error ────────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum FairPlayError {
    #[error("no encryption load command found")]
    NoEncryptionCommand,
    #[error("binary is encrypted — decryption required before disassembly")]
    EncryptedSegment { crypt_offset: u32, crypt_size: u32, crypt_id: u32 },
    #[error("device not found: {udid}")]
    DeviceNotFound { udid: String },
    #[error("failed to connect to usbmuxd: {0}")]
    UsbmuxdConnect(String),
    #[error("Frida injection failed: {0}")]
    FridaInject(String),
    #[error("memory dump failed: {0}")]
    DumpFailed(String),
    #[error("I/O error: {0}")]
    Io(String),
    #[error("parse error: {0}")]
    Parse(String),
}

pub type Result<T> = std::result::Result<T, FairPlayError>;

// ─── Mach-O constants ────────────────────────────────────────────────────────

/// `LC_ENCRYPTION_INFO` load command number (32-bit).
pub const LC_ENCRYPTION_INFO: u32 = 0x21;
/// `LC_ENCRYPTION_INFO_64` load command number (64-bit).
pub const LC_ENCRYPTION_INFO_64: u32 = 0x2C;

/// `cryptid` value indicating no encryption.
pub const CRYPT_ID_NONE: u32 = 0;
/// [`cryptid`](EncryptionInfoCmd::cryptid) value indicating `FairPlay` v1 encryption.
pub const CRYPT_ID_FAIRPLAY: u32 = 1;

// ─── Load command layout (little-endian) ─────────────────────────────────────

/// The `encryption_info_command` / `encryption_info_command_64` structure.
///
/// Layout:
///
/// ```text
/// +0x00  u32  cmd
/// +0x04  u32  cmdsize
/// +0x08  u32  cryptoff   — file offset of the encrypted range
/// +0x0C  u32  cryptsize  — size in bytes of the encrypted range
/// +0x10  u32  cryptid    — 0 = unencrypted, 1 = FairPlay
/// +0x14  u32  pad        — (64-bit variant only)
/// ```
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct EncryptionInfoCmd {
    pub cmd: u32,
    pub cmdsize: u32,
    pub cryptoff: u32,
    pub cryptsize: u32,
    pub cryptid: u32,
}

impl EncryptionInfoCmd {
    fn read(data: &[u8], off: usize) -> Option<Self> {
        if off + 20 > data.len() { return None; }
        let cmd      = u32_le(data, off);
        let cmdsize  = u32_le(data, off + 4);
        let cryptoff = u32_le(data, off + 8);
        let cryptsz  = u32_le(data, off + 12);
        let cryptid  = u32_le(data, off + 16);
        Some(Self { cmd, cmdsize, cryptoff, cryptsize: cryptsz, cryptid })
    }
}

fn u32_le(data: &[u8], off: usize) -> u32 {
    let Some(b) = data.get(off..off + 4) else { return 0 };
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}

fn u32_be(data: &[u8], off: usize) -> u32 {
    let Some(b) = data.get(off..off + 4) else { return 0 };
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}

// ─── FairPlayStatus ───────────────────────────────────────────────────────────

/// Encryption status of a binary image.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FairPlayStatus {
    /// No `LC_ENCRYPTION_INFO*` command found, or `cryptid == 0`.
    Unencrypted,
    /// Binary has `cryptid == 1` — the region is still FairPlay-encrypted.
    Encrypted {
        /// File offset of the encrypted region.
        crypt_offset: u32,
        /// Size of the encrypted region in bytes.
        crypt_size: u32,
        /// [`cryptid`](EncryptionInfoCmd::cryptid) value (typically 1 for `FairPlay` v1).
        crypt_id: u32,
    },
    /// Binary was previously decrypted by an external tool.
    Decrypted {
        /// Name of the tool that performed decryption (e.g. `"frida-ios-dump"`).
        tool_used: String,
    },
}

impl FairPlayStatus {
    /// Returns `true` if this binary has a live `FairPlay` `cryptid`.
    #[must_use]
    pub const fn is_encrypted(&self) -> bool { matches!(self, Self::Encrypted { .. }) }
    /// Returns `true` if no encryption command was found or `cryptid == 0`.
    #[must_use]
    pub const fn is_unencrypted(&self) -> bool { matches!(self, Self::Unencrypted) }
    /// Returns `true` if the binary was previously decrypted by an external tool.
    #[must_use]
    pub const fn is_decrypted(&self) -> bool { matches!(self, Self::Decrypted { .. }) }

    /// Return the encrypted region as `(offset, size)` if applicable.
    #[must_use]
    pub const fn encrypted_range(&self) -> Option<(u32, u32)> {
        if let Self::Encrypted { crypt_offset, crypt_size, .. } = self {
            Some((*crypt_offset, *crypt_size))
        } else {
            None
        }
    }
}

impl fmt::Display for FairPlayStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unencrypted => write!(f, "Unencrypted"),
            Self::Encrypted { crypt_offset, crypt_size, crypt_id } => {
                write!(f, "Encrypted (cryptid={crypt_id}, offset={crypt_offset:#x}, size={crypt_size:#x})")
            }
            Self::Decrypted { tool_used } => {
                write!(f, "Decrypted (via {tool_used})")
            }
        }
    }
}

// ─── Mach-O header parser (minimal) ──────────────────────────────────────────

/// Magic numbers for supported Mach-O formats.
pub const MH_MAGIC_32:    u32 = 0xFEED_FACE;
pub const MH_MAGIC_64:    u32 = 0xFEED_FACF;
pub const MH_CIGAM_32:    u32 = 0xCEFA_EDFE;
pub const MH_CIGAM_64:    u32 = 0xCFFA_EDFE;
pub const FAT_MAGIC:      u32 = 0xCAFE_BABE;
pub const FAT_MAGIC_64:   u32 = 0xCAFE_BABF;

const fn is_64bit_magic(magic: u32) -> bool {
    magic == MH_MAGIC_64 || magic == MH_CIGAM_64
}

const fn is_big_endian_magic(magic: u32) -> bool {
    magic == MH_CIGAM_32 || magic == MH_CIGAM_64
}

/// Minimal Mach-O header parsed from a raw byte slice.
#[derive(Debug, Clone)]
pub struct MachoHeader {
    pub magic: u32,
    pub cputype: u32,
    pub cpusubtype: u32,
    pub filetype: u32,
    pub ncmds: u32,
    pub sizeofcmds: u32,
    pub flags: u32,
    /// Byte offset of the first load command.
    pub lc_start: usize,
}

impl MachoHeader {
    fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 28 { return None; }
        let magic = u32_le(data, 0);

        let read32 = if is_big_endian_magic(magic) { u32_be as fn(&[u8], usize) -> u32 } else { u32_le };

        let is_64 = is_64bit_magic(magic);
        if is_64 && data.len() < 32 { return None; }
        let lc_start = if is_64 { 32usize } else { 28usize };

        let (ncmds, sizeofcmds) = match magic {
            MH_MAGIC_32 | MH_CIGAM_32 | MH_MAGIC_64 | MH_CIGAM_64 => {
                (read32(data, 16), read32(data, 20))
            }
            _ => return None,
        };

        Some(Self {
            magic,
            cputype:    read32(data, 4),
            cpusubtype: read32(data, 8),
            filetype:   read32(data, 12),
            ncmds,
            sizeofcmds,
            flags:      read32(data, 24),
            lc_start,
        })
    }
}

// ─── Core detection function ──────────────────────────────────────────────────

/// Detect `FairPlay` encryption status by scanning load commands in a `Mach-O` slice.
///
/// The `data` slice should start at the Mach-O magic (not a FAT header).
///
/// # Errors
/// Returns [`FairPlayError::Parse`] if the header is truncated or not a valid Mach-O.
pub fn detect_fairplay_in_slice(data: &[u8]) -> Result<FairPlayStatus> {
    let header = MachoHeader::parse(data)
        .ok_or_else(|| FairPlayError::Parse("not a valid Mach-O".into()))?;

    let mut off = header.lc_start;
    let lc_end  = header.lc_start.saturating_add(header.sizeofcmds as usize).min(data.len());

    for _ in 0..header.ncmds {
        if off + 8 > data.len() || off >= lc_end { break; }

        let cmd     = u32_le(data, off);
        let cmdsize = u32_le(data, off + 4) as usize;
        if cmdsize < 8 { break; }

        if cmd == LC_ENCRYPTION_INFO || cmd == LC_ENCRYPTION_INFO_64 {
            let enc = EncryptionInfoCmd::read(data, off)
                .ok_or_else(|| FairPlayError::Parse("truncated encryption_info_command".into()))?;

            return if enc.cryptid == CRYPT_ID_NONE {
                Ok(FairPlayStatus::Unencrypted)
            } else {
                Ok(FairPlayStatus::Encrypted {
                    crypt_offset: enc.cryptoff,
                    crypt_size:   enc.cryptsize,
                    crypt_id:     enc.cryptid,
                })
            };
        }

        off = match off.checked_add(cmdsize) {
            Some(next) if next <= data.len() => next,
            _ => break,
        };
    }

    // No encryption command found → binary is not wrapped.
    Ok(FairPlayStatus::Unencrypted)
}

/// Detect `FairPlay` status from raw binary bytes, handling `FAT` archives.
///
/// For FAT binaries the arm64 slice is preferred; falls back to the first slice.
///
/// # Errors
/// Returns [`FairPlayError::Parse`] if the data is too short or has an unknown magic.
pub fn detect_fairplay(data: &[u8]) -> Result<FairPlayStatus> {
    if data.len() < 4 {
        return Err(FairPlayError::Parse("binary too short".into()));
    }

    let magic = u32_le(data, 0);

    match magic {
        FAT_MAGIC | FAT_MAGIC_64 => {
            // FAT header: nfat_arch entries follow at offset 8.
            // Each arch entry: cputype(4) + cpusubtype(4) + offset(4) + size(4) + align(4).
            if data.len() < 8 { return Err(FairPlayError::Parse("FAT header truncated".into())); }
            // FAT headers are always big-endian per Apple spec.
            let nfat_arch = u32_be(data, 4) as usize;
            let arch_entry_size = 20usize;

            // Find an arm64 slice (cputype=0x0100000C).
            let mut first_status: Option<FairPlayStatus> = None;
            for i in 0..nfat_arch {
                let entry_off = 8 + i * arch_entry_size;
                if entry_off + 20 > data.len() { break; }
                let cputype  = u32_be(data, entry_off);
                let offset   = u32_be(data, entry_off + 8) as usize;
                let size     = u32_be(data, entry_off + 12) as usize;
                if offset + size > data.len() { continue; }

                let slice = &data[offset..offset + size];
                let status = detect_fairplay_in_slice(slice)?;

                if first_status.is_none() { first_status = Some(status.clone()); }
                // Prefer arm64 (0x0100000C) or arm64e (0x0200000C).
                if cputype == 0x0100_000C || cputype == 0x0200_000C {
                    return Ok(status);
                }
            }
            Ok(first_status.unwrap_or(FairPlayStatus::Unencrypted))
        }
        MH_MAGIC_32 | MH_CIGAM_32 | MH_MAGIC_64 | MH_CIGAM_64 => {
            detect_fairplay_in_slice(data)
        }
        _ => Err(FairPlayError::Parse(format!("unknown magic: {magic:#010x}"))),
    }
}

// ─── Loader integration ───────────────────────────────────────────────────────

/// Result returned to the loader after inspecting a binary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoaderDecision {
    pub status: FairPlayStatus,
    /// `true` when the loader should proceed with disassembly.
    pub can_disassemble: bool,
    /// Human-readable message shown in the UI.
    pub message: String,
}

impl LoaderDecision {
    /// Build a [`LoaderDecision`] from a detected status.
    #[must_use]
    pub fn from_status(status: FairPlayStatus) -> Self {
        match &status {
            FairPlayStatus::Unencrypted => Self {
                message: "Binary is not FairPlay-encrypted. Proceeding.".into(),
                can_disassemble: true,
                status,
            },
            FairPlayStatus::Encrypted { crypt_offset, crypt_size, crypt_id } => {
                Self {
                    message: format!(
                        "Binary is FairPlay-encrypted (cryptid={crypt_id}, range={crypt_offset:#x}..{:#x}). \
                         Disassembly of the encrypted segment is refused. \
                         Use `dump_decrypted_binary` to obtain a decrypted image first.",
                        crypt_offset + crypt_size,
                    ),
                    can_disassemble: false,
                    status,
                }
            }
            FairPlayStatus::Decrypted { tool_used } => Self {
                message: format!("Binary was decrypted by '{tool_used}'. Proceeding."),
                can_disassemble: true,
                status,
            },
        }
    }

    /// Raise an error if disassembly should not proceed.
    ///
    /// # Errors
    /// Returns [`FairPlayError::EncryptedSegment`] when the binary is still encrypted,
    /// or [`FairPlayError::DumpFailed`] for any other reason disassembly is blocked.
    pub fn assert_can_disassemble(&self) -> Result<()> {
        if self.can_disassemble {
            Ok(())
        } else if let FairPlayStatus::Encrypted { crypt_offset, crypt_size, crypt_id } = &self.status {
            Err(FairPlayError::EncryptedSegment {
                crypt_offset: *crypt_offset,
                crypt_size: *crypt_size,
                crypt_id: *crypt_id,
            })
        } else {
            Err(FairPlayError::DumpFailed("unknown reason".into()))
        }
    }
}

// ─── Dump session ─────────────────────────────────────────────────────────────

/// Transport used to communicate with the target device.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeviceTransport {
    /// USB via usbmuxd.
    #[default]
    Usb,
    /// Wi-Fi (network device visible via Frida).
    Network { host: String, port: u16 },
}

/// Configuration for a Frida-based memory-dump session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DumpConfig {
    /// UDID of the target device.
    pub device_udid: String,
    /// Bundle identifier of the target app (e.g. `"com.example.MyApp"`).
    pub bundle_id: String,
    pub transport: DeviceTransport,
    /// Maximum number of seconds to wait for the app to launch.
    pub launch_timeout_secs: u32,
    /// Additional Frida script fragments to inject alongside the dump script.
    pub extra_script: Option<String>,
}

impl DumpConfig {
    /// Create a new [`DumpConfig`] with USB transport and default timeout.
    #[must_use]
    pub fn new(device_udid: impl Into<String>, bundle_id: impl Into<String>) -> Self {
        Self {
            device_udid: device_udid.into(),
            bundle_id: bundle_id.into(),
            transport: DeviceTransport::Usb,
            launch_timeout_secs: 30,
            extra_script: None,
        }
    }
}

/// State of a running or completed dump session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DumpSessionState {
    Connecting,
    Spawning,
    Injecting,
    Dumping { bytes_read: u64, bytes_total: u64 },
    Reassembling,
    Done,
    Failed(String),
}

impl fmt::Display for DumpSessionState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Connecting        => write!(f, "Connecting to device"),
            Self::Spawning          => write!(f, "Spawning app"),
            Self::Injecting         => write!(f, "Injecting Frida script"),
            Self::Dumping { bytes_read, bytes_total } =>
                write!(f, "Dumping memory ({bytes_read}/{bytes_total} bytes)"),
            Self::Reassembling      => write!(f, "Reassembling decrypted binary"),
            Self::Done              => write!(f, "Done"),
            Self::Failed(msg)       => write!(f, "Failed: {msg}"),
        }
    }
}

/// A handle to a Frida-based dump session.
#[derive(Debug)]
pub struct DumpSession {
    pub config: DumpConfig,
    pub state: DumpSessionState,
    /// Collected memory pages from the running app.
    pages: Vec<MemoryPage>,
    /// The original (encrypted) binary bytes.
    original: Vec<u8>,
}

/// One contiguous page of memory read from the device.
#[derive(Debug, Clone)]
pub struct MemoryPage {
    pub vm_address: u64,
    pub data: Vec<u8>,
}

impl DumpSession {
    /// Create a new (not yet started) session.
    #[must_use]
    pub const fn new(config: DumpConfig, original_binary: Vec<u8>) -> Self {
        Self {
            config,
            state: DumpSessionState::Connecting,
            pages: Vec::new(),
            original: original_binary,
        }
    }

    /// Advance state machine (simulated; real implementation would call Frida over USB).
    pub fn advance(&mut self) {
        self.state = match &self.state {
            DumpSessionState::Connecting      => DumpSessionState::Spawning,
            DumpSessionState::Spawning        => DumpSessionState::Injecting,
            DumpSessionState::Injecting       => DumpSessionState::Dumping { bytes_read: 0, bytes_total: 0 },
            DumpSessionState::Dumping { .. }  => DumpSessionState::Reassembling,
            DumpSessionState::Reassembling    => DumpSessionState::Done,
            other                             => other.clone(),
        };
    }

    /// Add a memory page received from the device.
    pub fn add_page(&mut self, page: MemoryPage) {
        self.pages.push(page);
    }

    /// Reassemble the decrypted binary: patch the encrypted range in the original
    /// with data read from the running process, and clear `cryptid`.
    ///
    /// # Errors
    /// Returns [`FairPlayError::DumpFailed`] if the session is not yet in a
    /// reassembly-ready state, or propagates errors from [`detect_fairplay`].
    pub fn reassemble(&self) -> Result<Vec<u8>> {
        if !matches!(self.state, DumpSessionState::Reassembling | DumpSessionState::Done) {
            return Err(FairPlayError::DumpFailed("session not ready for reassembly".into()));
        }

        let mut output = self.original.clone();

        // Detect the encrypted range from the original binary's load commands.
        let status = detect_fairplay(&self.original)?;
        let (crypt_off, crypt_size) = match status {
            FairPlayStatus::Encrypted { crypt_offset, crypt_size, .. } =>
                (crypt_offset as usize, crypt_size as usize),
            _ => return Ok(output), // nothing to patch
        };

        // Patch with data from memory pages covering the encrypted range.
        for page in &self.pages {
            // Simplistic mapping: assume ASLR slide is zero for reconstruction.
            let page_start = usize::try_from(page.vm_address).unwrap_or(usize::MAX);
            let page_end   = page_start + page.data.len();
            let enc_end    = crypt_off + crypt_size;

            let overlap_start = page_start.max(crypt_off);
            let overlap_end   = page_end.min(enc_end);
            if overlap_start >= overlap_end { continue; }

            let src_start  = overlap_start - page_start;
            let dst_start  = overlap_start;
            let count      = overlap_end - overlap_start;

            if dst_start + count > output.len() { continue; }
            output[dst_start..dst_start + count]
                .copy_from_slice(&page.data[src_start..src_start + count]);
        }

        // Clear cryptid in the patched binary.
        patch_cryptid(&mut output, CRYPT_ID_NONE);

        Ok(output)
    }
}

/// Overwrite the `cryptid` field in the first `LC_ENCRYPTION_INFO*` command found.
pub fn patch_cryptid(data: &mut [u8], new_cryptid: u32) {
    let Some(header) = MachoHeader::parse(data) else { return };

    let mut off = header.lc_start;
    let lc_end  = header.lc_start.saturating_add(header.sizeofcmds as usize).min(data.len());

    while off + 8 <= data.len() && off < lc_end {
        let cmd     = u32_le(data, off);
        let cmdsize = u32_le(data, off + 4) as usize;
        if cmdsize < 8 { break; }

        if cmd == LC_ENCRYPTION_INFO || cmd == LC_ENCRYPTION_INFO_64 {
            if off + 20 <= data.len() {
                let new = new_cryptid.to_le_bytes();
                data[off + 16] = new[0];
                data[off + 17] = new[1];
                data[off + 18] = new[2];
                data[off + 19] = new[3];
            }
            return;
        }
        off = match off.checked_add(cmdsize) {
            Some(next) if next <= data.len() => next,
            _ => break,
        };
    }
}

// ─── High-level convenience API ───────────────────────────────────────────────

/// Convenience: detect `FairPlay` from bytes and return a loader decision.
#[must_use]
pub fn check_binary(data: &[u8]) -> LoaderDecision {
    match detect_fairplay(data) {
        Ok(status) => LoaderDecision::from_status(status),
        Err(e) => LoaderDecision {
            status: FairPlayStatus::Unencrypted,
            can_disassemble: false,
            message: format!("FairPlay check error: {e}"),
        },
    }
}

/// Synthesise a decrypted-binary marker when the caller already has the
/// bytes from another decryption tool (e.g. frida-ios-dump, bagbak).
pub fn mark_as_decrypted(data: &mut [u8], tool_name: &str) {
    // Clear cryptid so downstream parsers recognise the binary as decrypted.
    patch_cryptid(data, CRYPT_ID_NONE);
    let _ = tool_name; // carried in LoaderDecision / metadata, not in the bytes
}

// ─── Frida dump script template ───────────────────────────────────────────────

/// The minimal Frida JavaScript that performs an in-memory dump of decrypted TEXT.
///
/// The real implementation would be served via an embedded resource; this
/// constant contains the documented interface so callers can extend it.
pub const FRIDA_DUMP_SCRIPT: &str = r"
// rustre-fairplay: Frida dump script
// Invoked on the target process after all decryption has happened.
//
// Protocol:
//   1. Find all Mach-O images via Process.enumerateModules()
//   2. For each image that has a non-zero cryptid in its load commands,
//      read the decrypted memory region.
//   3. Send pages back to the host via send({ type: 'page', va, data })
//   4. Signal completion with send({ type: 'done' })

'use strict';

function u32le(buf, off) {
    return buf[off] | (buf[off+1]<<8) | (buf[off+2]<<16) | (buf[off+3]<<24);
}

function dumpModule(mod) {
    var base = mod.base;
    var magic = Memory.readU32(base);
    var LC_ENCRYPTION_INFO    = 0x21;
    var LC_ENCRYPTION_INFO_64 = 0x2C;
    var is64 = (magic === 0xFEEDFACF);
    var lc_off = is64 ? 32 : 28;
    var ncmds  = Memory.readU32(base.add(16));

    for (var i = 0; i < ncmds; i++) {
        var cmd     = Memory.readU32(base.add(lc_off));
        var cmdsize = Memory.readU32(base.add(lc_off + 4));
        if (cmd === LC_ENCRYPTION_INFO || cmd === LC_ENCRYPTION_INFO_64) {
            var cryptoff  = Memory.readU32(base.add(lc_off + 8));
            var cryptsize = Memory.readU32(base.add(lc_off + 12));
            var cryptid   = Memory.readU32(base.add(lc_off + 16));
            if (cryptid !== 0) {
                var region = base.add(cryptoff).readByteArray(cryptsize);
                send({ type: 'page', va: base.add(cryptoff).toString(), mod: mod.name }, region);
            }
            break;
        }
        lc_off += cmdsize;
    }
}

Process.enumerateModules().forEach(function(mod) {
    try { dumpModule(mod); } catch(e) {}
});
send({ type: 'done' });
";

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── FairPlayStatus ────────────────────────────────────────────────────────

    #[test]
    fn test_fairplay_status_predicates() {
        assert!(FairPlayStatus::Unencrypted.is_unencrypted());
        assert!(!FairPlayStatus::Unencrypted.is_encrypted());
        assert!(!FairPlayStatus::Unencrypted.is_decrypted());

        let enc = FairPlayStatus::Encrypted { crypt_offset: 0x4000, crypt_size: 0x1000, crypt_id: 1 };
        assert!(enc.is_encrypted());
        assert!(!enc.is_unencrypted());

        let dec = FairPlayStatus::Decrypted { tool_used: "bagbak".into() };
        assert!(dec.is_decrypted());
    }

    #[test]
    fn test_fairplay_status_encrypted_range() {
        let enc = FairPlayStatus::Encrypted { crypt_offset: 0x4000, crypt_size: 0x2000, crypt_id: 1 };
        assert_eq!(enc.encrypted_range(), Some((0x4000, 0x2000)));
        assert_eq!(FairPlayStatus::Unencrypted.encrypted_range(), None);
    }

    #[test]
    fn test_fairplay_status_display() {
        let s = FairPlayStatus::Unencrypted.to_string();
        assert_eq!(s, "Unencrypted");

        let enc = FairPlayStatus::Encrypted { crypt_offset: 0x4000, crypt_size: 0x1000, crypt_id: 1 };
        let s = enc.to_string();
        assert!(s.contains("cryptid=1"));
        assert!(s.contains("0x4000"));

        let dec = FairPlayStatus::Decrypted { tool_used: "frida-ios-dump".into() };
        let s = dec.to_string();
        assert!(s.contains("frida-ios-dump"));
    }

    // ── detect_fairplay with synthesised binaries ─────────────────────────────

    fn make_macho64_header(ncmds: u32, sizeofcmds: u32) -> Vec<u8> {
        let mut h = vec![0u8; 32];
        // magic
        h[0..4].copy_from_slice(&MH_MAGIC_64.to_le_bytes());
        // cputype = ARM64 = 0x0100000C
        h[4..8].copy_from_slice(&0x0100_000Cu32.to_le_bytes());
        // cpusubtype
        h[8..12].copy_from_slice(&0u32.to_le_bytes());
        // filetype = MH_EXECUTE = 2
        h[12..16].copy_from_slice(&2u32.to_le_bytes());
        // ncmds
        h[16..20].copy_from_slice(&ncmds.to_le_bytes());
        // sizeofcmds
        h[20..24].copy_from_slice(&sizeofcmds.to_le_bytes());
        // flags
        h[24..28].copy_from_slice(&0u32.to_le_bytes());
        // reserved (64-bit)
        h[28..32].copy_from_slice(&0u32.to_le_bytes());
        h
    }

    fn make_encryption_cmd(cryptoff: u32, cryptsize: u32, cryptid: u32) -> Vec<u8> {
        let mut cmd = vec![0u8; 24]; // LC_ENCRYPTION_INFO_64 with pad
        cmd[0..4].copy_from_slice(&LC_ENCRYPTION_INFO_64.to_le_bytes());
        cmd[4..8].copy_from_slice(&24u32.to_le_bytes()); // cmdsize
        cmd[8..12].copy_from_slice(&cryptoff.to_le_bytes());
        cmd[12..16].copy_from_slice(&cryptsize.to_le_bytes());
        cmd[16..20].copy_from_slice(&cryptid.to_le_bytes());
        // pad = 0
        cmd
    }

    #[test]
    fn test_detect_fairplay_unencrypted_binary() {
        let mut data = make_macho64_header(1, 24);
        data.extend_from_slice(&make_encryption_cmd(0x4000, 0x1000, CRYPT_ID_NONE));
        let status = detect_fairplay(&data).unwrap();
        assert_eq!(status, FairPlayStatus::Unencrypted);
    }

    #[test]
    fn test_detect_fairplay_encrypted_binary() {
        let mut data = make_macho64_header(1, 24);
        data.extend_from_slice(&make_encryption_cmd(0x4000, 0x8000, CRYPT_ID_FAIRPLAY));
        let status = detect_fairplay(&data).unwrap();
        assert!(matches!(status, FairPlayStatus::Encrypted {
            crypt_offset: 0x4000, crypt_size: 0x8000, crypt_id: 1
        }));
    }

    #[test]
    fn test_detect_fairplay_no_encryption_cmd() {
        // Mach-O with zero load commands.
        let data = make_macho64_header(0, 0);
        let status = detect_fairplay(&data).unwrap();
        assert_eq!(status, FairPlayStatus::Unencrypted);
    }

    #[test]
    fn test_detect_fairplay_too_short() {
        let data = [0u8; 2];
        assert!(detect_fairplay(&data).is_err());
    }

    #[test]
    fn test_detect_fairplay_bad_magic() {
        let data = [0xDEu8, 0xAD, 0xBE, 0xEF, 0, 0, 0, 0, 0, 0, 0, 0];
        assert!(detect_fairplay(&data).is_err());
    }

    // ── patch_cryptid ─────────────────────────────────────────────────────────

    #[test]
    fn test_patch_cryptid_clears_encryption() {
        let mut data = make_macho64_header(1, 24);
        data.extend_from_slice(&make_encryption_cmd(0x4000, 0x8000, 1));
        patch_cryptid(&mut data, 0);
        let status = detect_fairplay(&data).unwrap();
        assert_eq!(status, FairPlayStatus::Unencrypted);
    }

    #[test]
    fn test_patch_cryptid_no_op_on_invalid_binary() {
        let mut data = vec![0u8; 32];
        patch_cryptid(&mut data, 0); // should not panic
    }

    // ── LoaderDecision ────────────────────────────────────────────────────────

    #[test]
    fn test_loader_decision_unencrypted() {
        let d = LoaderDecision::from_status(FairPlayStatus::Unencrypted);
        assert!(d.can_disassemble);
        assert!(d.assert_can_disassemble().is_ok());
    }

    #[test]
    fn test_loader_decision_encrypted_refuses_disassembly() {
        let status = FairPlayStatus::Encrypted { crypt_offset: 0x4000, crypt_size: 0x1000, crypt_id: 1 };
        let d = LoaderDecision::from_status(status);
        assert!(!d.can_disassemble);
        assert!(d.assert_can_disassemble().is_err());
        assert!(d.message.contains("0x4000"));
    }

    #[test]
    fn test_loader_decision_decrypted() {
        let status = FairPlayStatus::Decrypted { tool_used: "bagbak".into() };
        let d = LoaderDecision::from_status(status);
        assert!(d.can_disassemble);
        assert!(d.message.contains("bagbak"));
    }

    // ── check_binary ──────────────────────────────────────────────────────────

    #[test]
    fn test_check_binary_encrypted() {
        let mut data = make_macho64_header(1, 24);
        data.extend_from_slice(&make_encryption_cmd(0x4000, 0x1000, 1));
        let d = check_binary(&data);
        assert!(!d.can_disassemble);
    }

    #[test]
    fn test_check_binary_bad_input() {
        let data = [0xFF, 0xFF, 0xFF, 0xFF];
        let d = check_binary(&data);
        // Should not panic, and should return a usable decision.
        assert!(!d.message.is_empty());
    }

    // ── DumpConfig ────────────────────────────────────────────────────────────

    #[test]
    fn test_dump_config_defaults() {
        let cfg = DumpConfig::new("00001234-0000ABCDEF012345", "com.example.app");
        assert_eq!(cfg.transport, DeviceTransport::Usb);
        assert_eq!(cfg.launch_timeout_secs, 30);
        assert!(cfg.extra_script.is_none());
    }

    // ── DumpSession state machine ─────────────────────────────────────────────

    #[test]
    fn test_dump_session_advance_states() {
        let cfg = DumpConfig::new("udid", "bundle");
        let original = make_macho64_header(0, 0);
        let mut session = DumpSession::new(cfg, original);

        assert_eq!(session.state, DumpSessionState::Connecting);
        session.advance();
        assert_eq!(session.state, DumpSessionState::Spawning);
        session.advance();
        assert_eq!(session.state, DumpSessionState::Injecting);
        session.advance();
        assert!(matches!(session.state, DumpSessionState::Dumping { .. }));
        session.advance();
        assert_eq!(session.state, DumpSessionState::Reassembling);
        session.advance();
        assert_eq!(session.state, DumpSessionState::Done);
    }

    #[test]
    fn test_dump_session_reassemble_unencrypted() {
        let cfg = DumpConfig::new("udid", "bundle");
        let mut original = make_macho64_header(0, 0);
        original.resize(0x10000, 0xCC); // fill with CC
        let mut session = DumpSession::new(cfg, original);
        // Advance to reassembling.
        for _ in 0..4 { session.advance(); }
        // Reassemble with no pages — should just return original.
        let out = session.reassemble().unwrap();
        assert!(!out.is_empty());
    }

    #[test]
    fn test_dump_session_add_page() {
        let cfg = DumpConfig::new("udid", "bundle");
        let original = make_macho64_header(0, 0);
        let mut session = DumpSession::new(cfg, original);
        session.add_page(MemoryPage { vm_address: 0x1000_4000, data: vec![0xAA; 0x1000] });
        assert_eq!(session.pages.len(), 1);
    }

    // ── DumpSessionState display ──────────────────────────────────────────────

    #[test]
    fn test_dump_session_state_display() {
        assert!(DumpSessionState::Connecting.to_string().contains("Connecting"));
        assert!(DumpSessionState::Done.to_string().contains("Done"));
        let s = DumpSessionState::Dumping { bytes_read: 100, bytes_total: 200 };
        assert!(s.to_string().contains("100"));
        let f = DumpSessionState::Failed("oops".into());
        assert!(f.to_string().contains("oops"));
    }

    // ── EncryptionInfoCmd parsing ─────────────────────────────────────────────

    #[test]
    fn test_encryption_info_cmd_read() {
        let mut buf = vec![0u8; 24];
        buf[0..4].copy_from_slice(&LC_ENCRYPTION_INFO_64.to_le_bytes());
        buf[4..8].copy_from_slice(&24u32.to_le_bytes());
        buf[8..12].copy_from_slice(&0x4000u32.to_le_bytes());
        buf[12..16].copy_from_slice(&0x2000u32.to_le_bytes());
        buf[16..20].copy_from_slice(&1u32.to_le_bytes());
        let cmd = EncryptionInfoCmd::read(&buf, 0).unwrap();
        assert_eq!(cmd.cryptoff, 0x4000);
        assert_eq!(cmd.cryptsize, 0x2000);
        assert_eq!(cmd.cryptid, 1);
    }

    #[test]
    fn test_encryption_info_cmd_read_truncated() {
        let buf = [0u8; 10]; // too short
        assert!(EncryptionInfoCmd::read(&buf, 0).is_none());
    }

    // ── DeviceTransport ───────────────────────────────────────────────────────

    #[test]
    fn test_device_transport_default() {
        assert_eq!(DeviceTransport::default(), DeviceTransport::Usb);
    }

    #[test]
    fn test_device_transport_network() {
        let t = DeviceTransport::Network { host: "192.168.1.2".into(), port: 27042 };
        assert!(matches!(t, DeviceTransport::Network { port: 27042, .. }));
    }

    // ── mark_as_decrypted ─────────────────────────────────────────────────────

    #[test]
    fn test_mark_as_decrypted_clears_cryptid() {
        let mut data = make_macho64_header(1, 24);
        data.extend_from_slice(&make_encryption_cmd(0x4000, 0x1000, 1));
        mark_as_decrypted(&mut data, "frida-ios-dump");
        let status = detect_fairplay(&data).unwrap();
        assert_eq!(status, FairPlayStatus::Unencrypted);
    }

    // ── FRIDA_DUMP_SCRIPT ─────────────────────────────────────────────────────

    #[test]
    fn test_frida_dump_script_not_empty() {
        assert!(!FRIDA_DUMP_SCRIPT.trim().is_empty());
        assert!(FRIDA_DUMP_SCRIPT.contains("enumerateModules"));
        assert!(FRIDA_DUMP_SCRIPT.contains("LC_ENCRYPTION_INFO"));
    }
}
