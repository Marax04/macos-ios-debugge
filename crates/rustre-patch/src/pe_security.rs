//! `pe_security` — Lightweight PE security-flag summary used by patching
//! workflows (and surfaced via the MCP `patch_pe_security_summary` tool).
//!
//! Parses only the DOS + PE optional header; no third-party PE crate. The
//! summary reports the common Windows hardening flags so a patcher can decide
//! whether a binary needs DEP/ASLR fix-ups before a patch is applied.
//!
//! Both an in-memory entry point ([`pe_security_summary`]) and a path-loading
//! entry point ([`pe_security_summary_from_path`]) are provided so MCP tool
//! wrappers can honour a `path` parameter even when no session buffer is set
//! — mirroring the convention used by the `loader_pe_*` tools.

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Errors produced while parsing a PE for its security summary.
#[derive(Debug, Error)]
pub enum SecurityError {
    /// The buffer is too small to contain a DOS + PE header.
    #[error("binary too small ({0} bytes)")]
    TooSmall(usize),
    /// The buffer does not have a `PE\0\0` signature where expected.
    #[error("not a PE binary")]
    NotPe,
    /// A header field points outside the buffer.
    #[error("malformed PE header: {0}")]
    Malformed(&'static str),
}

/// I/O wrapper around [`SecurityError`] for the path-loading entry point.
#[derive(Debug, Error)]
pub enum SecurityPathError {
    /// File could not be read.
    #[error("io error reading {path}: {source}")]
    Io {
        /// Path that failed to load.
        path: String,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },
    /// Underlying parse error.
    #[error(transparent)]
    Parse(#[from] SecurityError),
}

/// Bit flags surfaced via the PE optional header `DllCharacteristics` field.
const IMAGE_DLLCHAR_DYNAMIC_BASE: u16 = 0x0040; // ASLR
const IMAGE_DLLCHAR_FORCE_INTEGRITY: u16 = 0x0080;
const IMAGE_DLLCHAR_NX_COMPAT: u16 = 0x0100; // DEP
const IMAGE_DLLCHAR_NO_ISOLATION: u16 = 0x0200;
const IMAGE_DLLCHAR_NO_SEH: u16 = 0x0400;
const IMAGE_DLLCHAR_NO_BIND: u16 = 0x0800;
const IMAGE_DLLCHAR_GUARD_CF: u16 = 0x4000; // Control Flow Guard
const IMAGE_DLLCHAR_TERMINAL_SERVER_AWARE: u16 = 0x8000;

/// Parsed security flags from a PE binary's `DllCharacteristics` field.
///
/// Wraps the raw `u16` value and exposes each flag as a method so the
/// containing [`PeSecuritySummary`] struct does not exceed the three-bool
/// limit recommended by `clippy::struct_excessive_bools`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeFlags(pub u16);

impl PeFlags {
    /// `IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE` — ASLR enabled.
    #[must_use] pub const fn aslr(self) -> bool { self.0 & IMAGE_DLLCHAR_DYNAMIC_BASE != 0 }
    /// `IMAGE_DLLCHARACTERISTICS_NX_COMPAT` — DEP / NX enabled.
    #[must_use] pub const fn dep(self) -> bool { self.0 & IMAGE_DLLCHAR_NX_COMPAT != 0 }
    /// `IMAGE_DLLCHARACTERISTICS_GUARD_CF` — Control Flow Guard.
    #[must_use] pub const fn cfg(self) -> bool { self.0 & IMAGE_DLLCHAR_GUARD_CF != 0 }
    /// `IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY` — signed enforcement.
    #[must_use] pub const fn force_integrity(self) -> bool { self.0 & IMAGE_DLLCHAR_FORCE_INTEGRITY != 0 }
    /// `IMAGE_DLLCHARACTERISTICS_NO_SEH` — structured exception handling disabled.
    #[must_use] pub const fn no_seh(self) -> bool { self.0 & IMAGE_DLLCHAR_NO_SEH != 0 }
    /// `IMAGE_DLLCHARACTERISTICS_NO_ISOLATION`.
    #[must_use] pub const fn no_isolation(self) -> bool { self.0 & IMAGE_DLLCHAR_NO_ISOLATION != 0 }
    /// `IMAGE_DLLCHARACTERISTICS_NO_BIND`.
    #[must_use] pub const fn no_bind(self) -> bool { self.0 & IMAGE_DLLCHAR_NO_BIND != 0 }
    /// `IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE`.
    #[must_use] pub const fn terminal_server_aware(self) -> bool { self.0 & IMAGE_DLLCHAR_TERMINAL_SERVER_AWARE != 0 }
}

/// Summary of common Windows hardening flags on a PE binary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeSecuritySummary {
    /// All `DllCharacteristics`-derived security flags.
    pub flags: PeFlags,
    /// `true` for PE32+ (64-bit), `false` for PE32.
    pub is_64bit: bool,
    /// Raw `DllCharacteristics` value (kept so callers can inspect unmodeled bits).
    pub dll_characteristics: u16,
}

/// Parse `data` and return a [`PeSecuritySummary`].
///
/// # Errors
///
/// Returns [`SecurityError`] if the buffer is too small, is not a PE, or has a
/// malformed header.
pub fn pe_security_summary(data: &[u8]) -> Result<PeSecuritySummary, SecurityError> {
    if data.len() < 0x40 {
        return Err(SecurityError::TooSmall(data.len()));
    }
    if &data[0..2] != b"MZ" {
        return Err(SecurityError::NotPe);
    }
    let e_lfanew =
        u32::from_le_bytes([data[0x3c], data[0x3d], data[0x3e], data[0x3f]]) as usize;
    let pe_sig_end = e_lfanew
        .checked_add(24)
        .ok_or(SecurityError::Malformed("e_lfanew overflow"))?;
    if pe_sig_end > data.len() {
        return Err(SecurityError::Malformed("PE header out of bounds"));
    }
    if &data[e_lfanew..e_lfanew + 4] != b"PE\0\0" {
        return Err(SecurityError::NotPe);
    }
    let opt_magic_off = e_lfanew + 24;
    if opt_magic_off + 2 > data.len() {
        return Err(SecurityError::Malformed("optional header missing"));
    }
    let opt_magic = u16::from_le_bytes([data[opt_magic_off], data[opt_magic_off + 1]]);
    let (is_64bit, dllchar_off) = match opt_magic {
        0x10b => (false, opt_magic_off + 70),  // PE32
        0x20b => (true, opt_magic_off + 70),   // PE32+ (same offset for DllCharacteristics)
        _ => return Err(SecurityError::Malformed("unknown optional-header magic")),
    };
    if dllchar_off + 2 > data.len() {
        return Err(SecurityError::Malformed("DllCharacteristics out of bounds"));
    }
    let dll_characteristics =
        u16::from_le_bytes([data[dllchar_off], data[dllchar_off + 1]]);
    Ok(PeSecuritySummary {
        flags: PeFlags(dll_characteristics),
        is_64bit,
        dll_characteristics,
    })
}

/// Load a PE from `path` and produce a [`PeSecuritySummary`].
///
/// This is the path-accepting counterpart for MCP tool dispatchers that
/// receive a `path` parameter when no in-memory session buffer is loaded —
/// matching the `loader_pe_*` convention.
///
/// # Errors
///
/// Returns [`SecurityPathError::Io`] if the file cannot be read, or
/// [`SecurityPathError::Parse`] if the bytes fail to parse.
pub fn pe_security_summary_from_path<P: AsRef<std::path::Path>>(
    path: P,
) -> Result<PeSecuritySummary, SecurityPathError> {
    let p = path.as_ref();
    let data = std::fs::read(p).map_err(|e| SecurityPathError::Io {
        path: p.display().to_string(),
        source: e,
    })?;
    Ok(pe_security_summary(&data)?)
}

// ---------------------------------------------------------------------------
// Setter: toggle DllCharacteristics flags on disk + recompute PE checksum
// ---------------------------------------------------------------------------

/// Optional toggles applied by [`pe_security_set_from_path`]. `None` leaves
/// the bit unchanged; `Some(true)` sets it; `Some(false)` clears it.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct PeFlagToggle {
    /// Toggle `IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE` (ASLR).
    pub aslr: Option<bool>,
    /// Toggle `IMAGE_DLLCHARACTERISTICS_NX_COMPAT` (DEP / NX).
    pub dep: Option<bool>,
    /// Toggle `IMAGE_DLLCHARACTERISTICS_GUARD_CF` (Control Flow Guard).
    pub cfg: Option<bool>,
    /// Toggle `IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY`.
    pub force_integrity: Option<bool>,
}

/// Outcome of [`pe_security_set_from_path`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeSecuritySetOutcome {
    /// Pre-change `DllCharacteristics`.
    pub old_dll_characteristics: u16,
    /// Post-change `DllCharacteristics`.
    pub new_dll_characteristics: u16,
    /// Pre-change PE checksum (from optional header).
    pub old_checksum: u32,
    /// Post-change PE checksum.
    pub new_checksum: u32,
    /// `true` when `dry_run` was set — file is unchanged.
    pub dry_run: bool,
    /// Backup file path, if `backup` was requested.
    pub backup_path: Option<String>,
}

/// Compute the Microsoft PE image checksum for `image` assuming the 4-byte
/// `CheckSum` field at `checksum_offset` is zeroed.
///
/// Mirrors `CheckSumMappedFile` from `IMAGEHLP`: sum 16-bit words with carry
/// folding, then add the file length.
#[must_use]
pub fn compute_pe_checksum(image: &[u8], checksum_offset: usize) -> u32 {
    let mut sum: u64 = 0;
    let len = image.len();
    let mut i = 0usize;
    while i + 1 < len {
        // Skip the four checksum bytes — they must be zeroed in the sum
        if i == checksum_offset || i == checksum_offset + 2 {
            i += 2;
            continue;
        }
        let w = u64::from(u16::from_le_bytes([image[i], image[i + 1]]));
        sum = sum.wrapping_add(w);
        sum = (sum & 0xffff) + (sum >> 16);
        i += 2;
    }
    if i < len {
        // Trailing odd byte
        sum = sum.wrapping_add(u64::from(image[i]));
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum = (sum & 0xffff) + (sum >> 16);
    let folded = (sum & 0xffff) as u32;
    folded.wrapping_add(len as u32)
}

/// Toggle PE `DllCharacteristics` security bits and recompute the PE
/// optional-header checksum, writing back to disk (or simulating with
/// `dry_run`).
///
/// # Errors
///
/// Returns [`SecurityPathError`] for I/O or parse failures.
pub fn pe_security_set_from_path<P: AsRef<std::path::Path>>(
    path: P,
    toggles: PeFlagToggle,
    dry_run: bool,
    backup: bool,
) -> Result<PeSecuritySetOutcome, SecurityPathError> {
    let p = path.as_ref();
    let path_str = p.display().to_string();
    let original = std::fs::read(p).map_err(|e| SecurityPathError::Io {
        path: path_str.clone(),
        source: e,
    })?;
    let mut data = original.clone();
    // Re-parse to locate DllCharacteristics offset + checksum offset
    if data.len() < 0x40 {
        return Err(SecurityError::TooSmall(data.len()).into());
    }
    if &data[0..2] != b"MZ" {
        return Err(SecurityError::NotPe.into());
    }
    let e_lfanew =
        u32::from_le_bytes([data[0x3c], data[0x3d], data[0x3e], data[0x3f]]) as usize;
    if e_lfanew + 24 > data.len() || &data[e_lfanew..e_lfanew + 4] != b"PE\0\0" {
        return Err(SecurityError::NotPe.into());
    }
    let opt_magic_off = e_lfanew + 24;
    if opt_magic_off + 2 > data.len() {
        return Err(SecurityError::Malformed("optional header missing").into());
    }
    let opt_magic = u16::from_le_bytes([data[opt_magic_off], data[opt_magic_off + 1]]);
    let dllchar_off = match opt_magic {
        0x10b | 0x20b => opt_magic_off + 70,
        _ => return Err(SecurityError::Malformed("unknown optional-header magic").into()),
    };
    // PE optional header CheckSum field: at opt_magic_off + 64 for both PE32 and PE32+
    let checksum_off = opt_magic_off + 64;
    if dllchar_off + 2 > data.len() || checksum_off + 4 > data.len() {
        return Err(SecurityError::Malformed("optional header truncated").into());
    }
    let old_dll = u16::from_le_bytes([data[dllchar_off], data[dllchar_off + 1]]);
    let old_chk = u32::from_le_bytes([
        data[checksum_off],
        data[checksum_off + 1],
        data[checksum_off + 2],
        data[checksum_off + 3],
    ]);
    // Apply toggles
    let mut new_dll = old_dll;
    let apply = |bits: &mut u16, mask: u16, want: Option<bool>| match want {
        Some(true) => *bits |= mask,
        Some(false) => *bits &= !mask,
        None => {}
    };
    apply(&mut new_dll, IMAGE_DLLCHAR_DYNAMIC_BASE, toggles.aslr);
    apply(&mut new_dll, IMAGE_DLLCHAR_NX_COMPAT, toggles.dep);
    apply(&mut new_dll, IMAGE_DLLCHAR_GUARD_CF, toggles.cfg);
    apply(&mut new_dll, IMAGE_DLLCHAR_FORCE_INTEGRITY, toggles.force_integrity);
    data[dllchar_off..dllchar_off + 2].copy_from_slice(&new_dll.to_le_bytes());
    // Zero checksum, recompute, write
    data[checksum_off..checksum_off + 4].copy_from_slice(&0u32.to_le_bytes());
    let new_chk = compute_pe_checksum(&data, checksum_off);
    data[checksum_off..checksum_off + 4].copy_from_slice(&new_chk.to_le_bytes());

    let mut backup_path = None;
    if !dry_run {
        if backup {
            let bp = format!("{path_str}.rustre.bak");
            std::fs::write(&bp, &original).map_err(|e| SecurityPathError::Io {
                path: bp.clone(),
                source: e,
            })?;
            backup_path = Some(bp);
        }
        std::fs::write(p, &data).map_err(|e| SecurityPathError::Io {
            path: path_str.clone(),
            source: e,
        })?;
    }
    Ok(PeSecuritySetOutcome {
        old_dll_characteristics: old_dll,
        new_dll_characteristics: new_dll,
        old_checksum: old_chk,
        new_checksum: new_chk,
        dry_run,
        backup_path,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal PE32+ buffer with a chosen `DllCharacteristics` value.
    fn make_minimal_pe(dllchar: u16, is_64: bool) -> Vec<u8> {
        let mut buf = vec![0u8; 0x200];
        buf[0..2].copy_from_slice(b"MZ");
        let e_lfanew = 0x80u32;
        buf[0x3c..0x40].copy_from_slice(&e_lfanew.to_le_bytes());
        let pe = e_lfanew as usize;
        buf[pe..pe + 4].copy_from_slice(b"PE\0\0");
        // COFF: keep zeros (machine, num_sections, etc); set size_of_optional_header
        let size_opt: u16 = 240;
        buf[pe + 20..pe + 22].copy_from_slice(&size_opt.to_le_bytes());
        let opt = pe + 24;
        let magic: u16 = if is_64 { 0x20b } else { 0x10b };
        buf[opt..opt + 2].copy_from_slice(&magic.to_le_bytes());
        // DllCharacteristics at opt + 70
        buf[opt + 70..opt + 72].copy_from_slice(&dllchar.to_le_bytes());
        buf
    }

    #[test]
    fn parses_aslr_dep_cfg() {
        let dllchar = IMAGE_DLLCHAR_DYNAMIC_BASE | IMAGE_DLLCHAR_NX_COMPAT | IMAGE_DLLCHAR_GUARD_CF;
        let buf = make_minimal_pe(dllchar, true);
        let s = pe_security_summary(&buf).unwrap();
        assert!(s.flags.aslr());
        assert!(s.flags.dep());
        assert!(s.flags.cfg());
        assert!(s.is_64bit);
        assert!(!s.flags.force_integrity());
    }

    #[test]
    fn rejects_non_pe() {
        let buf = vec![0u8; 0x100];
        assert!(matches!(pe_security_summary(&buf), Err(SecurityError::NotPe)));
    }

    #[test]
    fn path_loader_reads_file() {
        let dllchar = IMAGE_DLLCHAR_NX_COMPAT;
        let buf = make_minimal_pe(dllchar, false);
        let dir = std::env::temp_dir();
        let path = dir.join("rustre_patch_pe_security_test.bin");
        std::fs::write(&path, &buf).unwrap();
        let s = pe_security_summary_from_path(&path).unwrap();
        assert!(s.flags.dep());
        assert!(!s.flags.aslr());
        assert!(!s.is_64bit);
        let _ = std::fs::remove_file(&path);
    }
}
