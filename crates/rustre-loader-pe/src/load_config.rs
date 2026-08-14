//! PE load configuration directory — CFG, `SafeSEH`, GS cookie, `CHPE`.

use crate::imports::{RvaSection, rva_to_file_offset};

// ---------------------------------------------------------------------------
// Guard flags
// ---------------------------------------------------------------------------

pub const IMAGE_GUARD_CF_INSTRUMENTED: u32 = 0x0000_0100;
pub const IMAGE_GUARD_CFW_INSTRUMENTED: u32 = 0x0000_0200;
pub const IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT: u32 = 0x0000_0400;
pub const IMAGE_GUARD_SECURITY_COOKIE_UNUSED: u32 = 0x0000_0800;
pub const IMAGE_GUARD_PROTECT_DELAYLOAD_IAT: u32 = 0x0000_1000;
pub const IMAGE_GUARD_DELAYLOAD_IAT_IN_ITS_OWN_SECTION: u32 = 0x0000_2000;
pub const IMAGE_GUARD_CF_EXPORT_SUPPRESSION_INFO_PRESENT: u32 = 0x0000_4000;
pub const IMAGE_GUARD_CF_ENABLE_EXPORT_SUPPRESSION: u32 = 0x0000_8000;
pub const IMAGE_GUARD_CF_LONGJUMP_TABLE_PRESENT: u32 = 0x0001_0000;
pub const IMAGE_GUARD_RF_INSTRUMENTED: u32 = 0x0002_0000;
pub const IMAGE_GUARD_RF_ENABLE: u32 = 0x0004_0000;
pub const IMAGE_GUARD_RF_STRICT: u32 = 0x0008_0000;
pub const IMAGE_GUARD_RETPOLINE_PRESENT: u32 = 0x0010_0000;
pub const IMAGE_GUARD_EH_CONTINUATION_TABLE_PRESENT: u32 = 0x0040_0000;

// DLL characteristics relevant to load config
pub const IMAGE_DLLCHARACTERISTICS_GUARD_CF: u16 = 0x4000;
pub const IMAGE_DLLCHARACTERISTICS_NX_COMPAT: u16 = 0x0100;
pub const IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE: u16 = 0x0040;
pub const IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA: u16 = 0x0020;

// ---------------------------------------------------------------------------
// IMAGE_LOAD_CONFIG_DIRECTORY32
// ---------------------------------------------------------------------------

/// Parsed 32-bit `IMAGE_LOAD_CONFIG_DIRECTORY`.
#[derive(Debug, Clone, Default)]
pub struct LoadConfigDirectory32 {
    pub size: u32,
    pub time_date_stamp: u32,
    pub major_version: u16,
    pub minor_version: u16,
    pub global_flags_clear: u32,
    pub global_flags_set: u32,
    pub critical_section_default_timeout: u32,
    pub de_commit_free_block_threshold: u32,
    pub de_commit_total_free_threshold: u32,
    pub lock_prefix_table: u32,
    pub maximum_allocation_size: u32,
    pub virtual_memory_threshold: u32,
    pub process_affinity_mask: u32,
    pub process_heap_flags: u32,
    pub csd_version: u16,
    pub dependent_load_flags: u16,
    pub edit_list: u32,
    /// VA of the security cookie (`/GS`).
    pub security_cookie: u32,
    /// VA of the SEH handler table (`SafeSEH`).
    pub se_handler_table: u32,
    /// Count of `SafeSEH` handlers.
    pub se_handler_count: u32,
    /// VA of the CFG check function pointer.
    pub guard_cf_check_function_pointer: u32,
    /// VA of the CFG dispatch function pointer.
    pub guard_cf_dispatch_function_pointer: u32,
    /// VA of the CFG function table.
    pub guard_cf_function_table: u32,
    /// Count of CFG function table entries.
    pub guard_cf_function_count: u32,
    /// CFG guard flags.
    pub guard_flags: u32,
    // (extended fields truncated at size boundary)
}

impl LoadConfigDirectory32 {
    /// Parse from `data` at file `offset`.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the data at `offset` is too short.
    pub fn parse(data: &[u8], offset: usize) -> Result<Self, String> {
        if offset + 4 > data.len() {
            return Err("Load config 32 too short".into());
        }
        let r16 = |off: usize| -> u16 {
            u16::from_le_bytes(
                data.get(off..off + 2)
                    .and_then(|b| b.try_into().ok())
                    .unwrap_or([0; 2]),
            )
        };
        let r32 = |off: usize| -> u32 {
            u32::from_le_bytes(
                data.get(off..off + 4)
                    .and_then(|b| b.try_into().ok())
                    .unwrap_or([0; 4]),
            )
        };
        let size = r32(offset);
        let b = offset;

        Ok(Self {
            size,
            time_date_stamp: r32(b + 4),
            major_version: r16(b + 8),
            minor_version: r16(b + 10),
            global_flags_clear: r32(b + 12),
            global_flags_set: r32(b + 16),
            critical_section_default_timeout: r32(b + 20),
            de_commit_free_block_threshold: r32(b + 24),
            de_commit_total_free_threshold: r32(b + 28),
            lock_prefix_table: r32(b + 32),
            maximum_allocation_size: r32(b + 36),
            virtual_memory_threshold: r32(b + 40),
            process_affinity_mask: r32(b + 44),
            process_heap_flags: r32(b + 48),
            csd_version: r16(b + 52),
            dependent_load_flags: r16(b + 54),
            edit_list: r32(b + 56),
            security_cookie: if size >= 64 { r32(b + 60) } else { 0 },
            se_handler_table: if size >= 68 { r32(b + 64) } else { 0 },
            se_handler_count: if size >= 72 { r32(b + 68) } else { 0 },
            guard_cf_check_function_pointer: if size >= 76 { r32(b + 72) } else { 0 },
            guard_cf_dispatch_function_pointer: if size >= 80 { r32(b + 76) } else { 0 },
            guard_cf_function_table: if size >= 84 { r32(b + 80) } else { 0 },
            guard_cf_function_count: if size >= 88 { r32(b + 84) } else { 0 },
            guard_flags: if size >= 92 { r32(b + 88) } else { 0 },
        })
    }

    /// Return `true` if Control Flow Guard is enabled.
    #[must_use]
    pub const fn has_cfg(&self) -> bool {
        self.guard_flags & IMAGE_GUARD_CF_INSTRUMENTED != 0
    }

    /// Return `true` if `/GS` security cookie is present.
    #[must_use]
    pub const fn has_gs_cookie(&self) -> bool {
        self.security_cookie != 0
    }

    /// Return `true` if `SafeSEH` is present.
    #[must_use]
    pub const fn has_safe_seh(&self) -> bool {
        self.se_handler_table != 0 && self.se_handler_count > 0
    }
}

// ---------------------------------------------------------------------------
// IMAGE_LOAD_CONFIG_DIRECTORY64
// ---------------------------------------------------------------------------

/// Parsed 64-bit `IMAGE_LOAD_CONFIG_DIRECTORY`.
#[derive(Debug, Clone, Default)]
pub struct LoadConfigDirectory64 {
    pub size: u32,
    pub time_date_stamp: u32,
    pub major_version: u16,
    pub minor_version: u16,
    pub global_flags_clear: u32,
    pub global_flags_set: u32,
    pub critical_section_default_timeout: u32,
    pub de_commit_free_block_threshold: u64,
    pub de_commit_total_free_threshold: u64,
    pub lock_prefix_table: u64,
    pub maximum_allocation_size: u64,
    pub virtual_memory_threshold: u64,
    pub process_affinity_mask: u64,
    pub process_heap_flags: u32,
    pub csd_version: u16,
    pub dependent_load_flags: u16,
    pub edit_list: u64,
    /// VA of the security cookie (`/GS`).
    pub security_cookie: u64,
    /// VA of the CFG check function pointer.
    pub guard_cf_check_function_pointer: u64,
    /// VA of the CFG dispatch function pointer.
    pub guard_cf_dispatch_function_pointer: u64,
    /// VA of the CFG function table.
    pub guard_cf_function_table: u64,
    /// Count of CFG function table entries.
    pub guard_cf_function_count: u64,
    /// CFG guard flags.
    pub guard_flags: u32,
    // (many more fields in newer SDK versions)
}

impl LoadConfigDirectory64 {
    /// Parse from `data` at file `offset`.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the data at `offset` is too short.
    pub fn parse(data: &[u8], offset: usize) -> Result<Self, String> {
        if offset + 4 > data.len() {
            return Err("Load config 64 too short".into());
        }
        let r16 = |off: usize| -> u16 {
            u16::from_le_bytes(
                data.get(off..off + 2)
                    .and_then(|b| b.try_into().ok())
                    .unwrap_or([0; 2]),
            )
        };
        let r32 = |off: usize| -> u32 {
            u32::from_le_bytes(
                data.get(off..off + 4)
                    .and_then(|b| b.try_into().ok())
                    .unwrap_or([0; 4]),
            )
        };
        let r64 = |off: usize| -> u64 {
            u64::from_le_bytes(
                data.get(off..off + 8)
                    .and_then(|b| b.try_into().ok())
                    .unwrap_or([0; 8]),
            )
        };
        let size = r32(offset);
        let b = offset;

        Ok(Self {
            size,
            time_date_stamp: r32(b + 4),
            major_version: r16(b + 8),
            minor_version: r16(b + 10),
            global_flags_clear: r32(b + 12),
            global_flags_set: r32(b + 16),
            critical_section_default_timeout: r32(b + 20),
            de_commit_free_block_threshold: r64(b + 24),
            de_commit_total_free_threshold: r64(b + 32),
            lock_prefix_table: r64(b + 40),
            maximum_allocation_size: r64(b + 48),
            virtual_memory_threshold: r64(b + 56),
            process_affinity_mask: r64(b + 64),
            process_heap_flags: r32(b + 72),
            csd_version: r16(b + 76),
            dependent_load_flags: r16(b + 78),
            edit_list: r64(b + 80),
            security_cookie: if size >= 96 { r64(b + 88) } else { 0 },
            guard_cf_check_function_pointer: if size >= 104 { r64(b + 96) } else { 0 },
            guard_cf_dispatch_function_pointer: if size >= 112 { r64(b + 104) } else { 0 },
            guard_cf_function_table: if size >= 120 { r64(b + 112) } else { 0 },
            guard_cf_function_count: if size >= 128 { r64(b + 120) } else { 0 },
            guard_flags: if size >= 132 { r32(b + 128) } else { 0 },
        })
    }

    /// Return `true` if Control Flow Guard is enabled.
    #[must_use]
    pub const fn has_cfg(&self) -> bool {
        self.guard_flags & IMAGE_GUARD_CF_INSTRUMENTED != 0
    }

    /// Return `true` if the retpoline mitigation bit is set.
    #[must_use]
    pub const fn has_retpoline(&self) -> bool {
        self.guard_flags & IMAGE_GUARD_RETPOLINE_PRESENT != 0
    }

    /// Return `true` if `/GS` security cookie is present.
    #[must_use]
    pub const fn has_gs_cookie(&self) -> bool {
        self.security_cookie != 0
    }
}

// ---------------------------------------------------------------------------
// CFG function table
// ---------------------------------------------------------------------------

/// One entry in the CFG function table (RVA + metadata).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CfgFunctionEntry {
    /// RVA of the protected function.
    pub rva: u32,
    /// Additional metadata (bits 0-3 = type flags for the CFG entry).
    pub flags: u8,
}

/// Parse the CFG function table entries.
#[must_use]
pub fn parse_cfg_function_table(
    data: &[u8],
    sections: &[RvaSection],
    table_rva: u32,
    count: u64,
    entry_stride: u32,
) -> Vec<CfgFunctionEntry> {
    let Some(table_off) = rva_to_file_offset(table_rva, sections) else {
        return Vec::new();
    };

    let stride = usize::try_from(entry_stride).unwrap_or(usize::MAX);
    // `count` and `entry_stride` are raw file fields: cap the entry count by the
    // bytes actually available in the buffer (each entry needs >= 4 bytes).
    let count_usize = usize::try_from(count)
        .unwrap_or(usize::MAX)
        .min(data.len().saturating_sub(table_off) / stride.max(4) + 1);
    let mut entries = Vec::with_capacity(count_usize);

    for i in 0..count_usize {
        // checked arithmetic: `i * stride` / `+ 4` would wrap in release builds
        let Some(off) = i.checked_mul(stride).and_then(|d| table_off.checked_add(d)) else {
            break;
        };
        if off.checked_add(4).is_none_or(|end| end > data.len()) {
            break;
        }
        let rva = u32::from_le_bytes(data[off..off + 4].try_into().unwrap_or([0; 4]));
        // Stride > 4 → the extra byte(s) encode CFG metadata flags
        let flags = if stride > 4 && off + 5 <= data.len() {
            data[off + 4]
        } else {
            0
        };
        entries.push(CfgFunctionEntry { rva, flags });
    }

    entries
}

// ---------------------------------------------------------------------------
// SafeSEH handler table
// ---------------------------------------------------------------------------

/// Extract `SafeSEH` handler RVAs.
#[must_use]
pub fn parse_safe_seh_handlers(
    data: &[u8],
    sections: &[RvaSection],
    handler_table_va: u32,
    handler_count: u32,
    image_base: u64,
) -> Vec<u32> {
    if handler_table_va == 0 || handler_count == 0 {
        return Vec::new();
    }
    let va = u64::from(handler_table_va);
    if va < image_base {
        return Vec::new();
    }
    let rva = u32::try_from(va - image_base).unwrap_or(u32::MAX);
    let Some(table_off) = rva_to_file_offset(rva, sections) else {
        return Vec::new();
    };

    // `handler_count` is a raw u32 from the file: cap by what the buffer holds.
    let hcount = usize::try_from(handler_count)
        .unwrap_or(usize::MAX)
        .min(data.len().saturating_sub(table_off) / 4);
    let mut handlers = Vec::with_capacity(hcount);
    for i in 0..hcount {
        let off = table_off + i * 4;
        if off + 4 > data.len() {
            break;
        }
        let handler_rva = u32::from_le_bytes(data[off..off + 4].try_into().unwrap_or([0; 4]));
        handlers.push(handler_rva);
    }
    handlers
}

// ---------------------------------------------------------------------------
// Security analysis summary
// ---------------------------------------------------------------------------

/// Bitflags for security mitigations detected in the load config.
#[derive(Debug, Clone, Copy, Default)]
pub struct MitigationFlags(pub u8);

impl MitigationFlags {
    pub const CFG: u8 = 0x01;
    pub const GS_COOKIE: u8 = 0x02;
    pub const SAFE_SEH: u8 = 0x04;
    pub const NX_COMPAT: u8 = 0x08;
    pub const ASLR: u8 = 0x10;
    pub const HIGH_ENTROPY_VA: u8 = 0x20;
    pub const RETPOLINE: u8 = 0x40;

    #[must_use]
    pub const fn get(self, bit: u8) -> bool { self.0 & bit != 0 }
    #[must_use]
    pub const fn has_cfg(self) -> bool { self.get(Self::CFG) }
    #[must_use]
    pub const fn has_gs_cookie(self) -> bool { self.get(Self::GS_COOKIE) }
    #[must_use]
    pub const fn has_safe_seh(self) -> bool { self.get(Self::SAFE_SEH) }
    #[must_use]
    pub const fn has_nx_compat(self) -> bool { self.get(Self::NX_COMPAT) }
    #[must_use]
    pub const fn has_aslr(self) -> bool { self.get(Self::ASLR) }
    #[must_use]
    pub const fn has_high_entropy_va(self) -> bool { self.get(Self::HIGH_ENTROPY_VA) }
    #[must_use]
    pub const fn has_retpoline(self) -> bool { self.get(Self::RETPOLINE) }

    #[must_use]
    pub const fn set_bit(self, bit: u8) -> Self { Self(self.0 | bit) }
    #[must_use]
    pub const fn clear_bit(self, bit: u8) -> Self { Self(self.0 & !bit) }
    pub const fn set(&mut self, bit: u8, value: bool) {
        if value { self.0 |= bit; } else { self.0 &= !bit; }
    }
}

/// Summary of security mitigations detected in the load config.
#[derive(Debug, Clone, Default)]
pub struct SecurityFeatures {
    pub mitigations: MitigationFlags,
    pub cfg_function_count: u64,
    pub seh_handler_count: u32,
}

impl SecurityFeatures {
    /// Score from 0 (no mitigations) to 7 (all present).
    #[must_use]
    pub const fn mitigation_score(&self) -> u32 {
        self.mitigations.0.count_ones()
    }

    /// Return a description of missing mitigations.
    #[must_use]
    pub fn missing_mitigations(&self) -> Vec<&'static str> {
        let mut missing = Vec::new();
        if !self.mitigations.has_cfg() {
            missing.push("CFG");
        }
        if !self.mitigations.has_gs_cookie() {
            missing.push("/GS");
        }
        if !self.mitigations.has_nx_compat() {
            missing.push("NX");
        }
        if !self.mitigations.has_aslr() {
            missing.push("ASLR");
        }
        missing
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_load_config32(size: u32) -> Vec<u8> {
        let mut buf = vec![0u8; (size as usize).max(92)];
        buf[0..4].copy_from_slice(&size.to_le_bytes());
        buf
    }

    #[test]
    fn test_load_config32_parse_minimal() {
        let buf = make_load_config32(64);
        let _ = &buf[..]; // no-op
        let lc = LoadConfigDirectory32::parse(&buf, 0).unwrap();
        assert_eq!(lc.size, 64);
        assert!(!lc.has_cfg());
        assert!(!lc.has_gs_cookie());
        assert!(!lc.has_safe_seh());
    }

    #[test]
    fn test_load_config32_with_gs_cookie() {
        let mut buf = make_load_config32(92);
        buf[0..4].copy_from_slice(&92u32.to_le_bytes()); // size
        buf[60..64].copy_from_slice(&0x1234_5678u32.to_le_bytes()); // security_cookie
        let lc = LoadConfigDirectory32::parse(&buf, 0).unwrap();
        assert!(lc.has_gs_cookie());
    }

    #[test]
    fn test_load_config32_with_cfg() {
        let mut buf = make_load_config32(92);
        buf[88..92].copy_from_slice(&IMAGE_GUARD_CF_INSTRUMENTED.to_le_bytes()); // guard_flags
        let lc = LoadConfigDirectory32::parse(&buf, 0).unwrap();
        assert!(lc.has_cfg());
    }

    #[test]
    fn test_load_config64_parse_minimal() {
        let mut buf = vec![0u8; 136];
        buf[0..4].copy_from_slice(&96u32.to_le_bytes()); // size
        let lc = LoadConfigDirectory64::parse(&buf, 0).unwrap();
        assert_eq!(lc.size, 96);
        assert!(!lc.has_cfg());
    }

    #[test]
    fn test_load_config64_with_retpoline() {
        let mut buf = vec![0u8; 136];
        buf[0..4].copy_from_slice(&136u32.to_le_bytes()); // size must cover guard_flags
        buf[128..132].copy_from_slice(&IMAGE_GUARD_RETPOLINE_PRESENT.to_le_bytes());
        let lc = LoadConfigDirectory64::parse(&buf, 0).unwrap();
        assert!(lc.has_retpoline());
    }

    #[test]
    fn test_security_features_score() {
        let mut m = MitigationFlags::default();
        m.set(MitigationFlags::CFG, true);
        m.set(MitigationFlags::GS_COOKIE, true);
        m.set(MitigationFlags::NX_COMPAT, true);
        m.set(MitigationFlags::ASLR, true);
        let sf = SecurityFeatures { mitigations: m, ..Default::default() };
        assert_eq!(sf.mitigation_score(), 4);
    }

    #[test]
    fn test_security_features_missing() {
        let sf = SecurityFeatures { mitigations: MitigationFlags::default(), ..Default::default() };
        let missing = sf.missing_mitigations();
        assert!(missing.contains(&"CFG"));
        assert!(missing.contains(&"NX"));
    }

    #[test]
    fn test_cfg_function_table_no_sections() {
        let entries = parse_cfg_function_table(&[], &[], 0x1000, 10, 4);
        assert!(entries.is_empty());
    }

    #[test]
    fn test_safe_seh_empty() {
        let handlers = parse_safe_seh_handlers(&[], &[], 0, 0, 0x40_0000);
        assert!(handlers.is_empty());
    }

    #[test]
    fn test_guard_flag_constants() {
        assert_ne!(IMAGE_GUARD_CF_INSTRUMENTED, 0);
        assert_ne!(IMAGE_GUARD_RETPOLINE_PRESENT, 0);
        assert_ne!(IMAGE_GUARD_RF_ENABLE, 0);
    }
}
