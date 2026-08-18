//! Windows x64 SEH table parsing: `.pdata` (`RUNTIME_FUNCTION` array) and
//! `.xdata` (`UNWIND_INFO`, C scope tables, MSVC C++ EH `FuncInfo`), exposed
//! as [`ExceptionRegion`] metadata attachable to an [`crate::exception_cfg::ExceptionCfg`].
//!
//! All RVAs are resolved against a caller-supplied *image* byte slice that is
//! addressed in RVA space (i.e. `image[rva]` is the byte at that RVA).  The
//! caller maps section file offsets to RVAs before calling in.

use crate::exception_cfg::{
    ExceptionHandler, ExceptionHandlingKind, ExceptionRegion, RuntimeFunction, UnwindInfo,
};
#[cfg(test)]
use crate::exception_cfg::HandlerKind;
use rustre_core::address::Address;

// ─────────────────────────────────────────────────────────────────────────────
// Little-endian helpers
// ─────────────────────────────────────────────────────────────────────────────

fn rd_u32(data: &[u8], off: usize) -> Option<u32> {
    let b = data.get(off..off + 4)?;
    Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

fn rd_i32(data: &[u8], off: usize) -> Option<i32> {
    rd_u32(data, off).map(|v| v as i32)
}

// ─────────────────────────────────────────────────────────────────────────────
// .pdata — RUNTIME_FUNCTION array
// ─────────────────────────────────────────────────────────────────────────────

/// Parse a raw `.pdata` section into `RUNTIME_FUNCTION` entries (12 bytes
/// each, little-endian).  Trailing zero entries (padding) are dropped.
#[must_use]
pub fn parse_pdata(pdata: &[u8]) -> Vec<RuntimeFunction> {
    let mut out = Vec::new();
    let mut off = 0usize;
    while off + 12 <= pdata.len() {
        let begin = rd_u32(pdata, off).unwrap_or(0);
        let end = rd_u32(pdata, off + 4).unwrap_or(0);
        let unwind = rd_u32(pdata, off + 8).unwrap_or(0);
        off += 12;
        if begin == 0 && end == 0 && unwind == 0 {
            continue; // zero padding
        }
        // Every RUNTIME_FUNCTION in a valid x64 table ends after it begins — a
        // function has non-zero length. A record that violates this did not
        // come from an x64 table: `.pdata` on ARM64 uses 8-byte records
        // (BeginAddress + UnwindData), so striding by 12 makes each "entry"
        // straddle two real ones. This parser only receives bytes and cannot
        // know the machine, so the invariant is the only signal available.
        // Dropping such records is not cosmetic: returning them hands the
        // caller functions that do not exist, indistinguishable from real ones.
        if end <= begin {
            continue;
        }
        out.push(RuntimeFunction {
            begin_address: begin,
            end_address: end,
            unwind_info_address: unwind,
        });
    }
    out
}

/// Find the `RUNTIME_FUNCTION` entry covering `rva` (binary search over a
/// sorted-by-begin table; falls back to linear scan when unsorted).
#[must_use]
pub fn find_runtime_function(table: &[RuntimeFunction], rva: u32) -> Option<&RuntimeFunction> {
    table
        .iter()
        .find(|rf| rva >= rf.begin_address && rva < rf.end_address)
}

// ─────────────────────────────────────────────────────────────────────────────
// .xdata — UNWIND_INFO
// ─────────────────────────────────────────────────────────────────────────────

/// Result of fully parsing an `UNWIND_INFO` record from `.xdata`.
#[derive(Debug, Clone)]
pub struct ParsedUnwindInfo {
    /// The decoded header/flags view.
    pub info: UnwindInfo,
    /// `UNWIND_INFO` version (low 3 bits of the first byte; 1 or 2).
    pub version: u8,
    /// Frame register number (0 = none).
    pub frame_register: u8,
    /// Scaled frame-register offset.
    pub frame_offset: u8,
    /// RVA (into the image) of the language-specific data that follows the
    /// handler RVA — a C scope table or MSVC `FuncInfo` pointer.
    pub language_data_rva: Option<u32>,
}

/// Parse an `UNWIND_INFO` structure located at `rva` in `image` (RVA-addressed).
#[must_use]
pub fn parse_unwind_info(image: &[u8], rva: u32) -> Option<ParsedUnwindInfo> {
    let base = rva as usize;
    let b0 = *image.get(base)?;
    let version = b0 & 0x07;
    let flags = b0 >> 3;
    let prolog_size = *image.get(base + 1)?;
    let count = *image.get(base + 2)?;
    let b3 = *image.get(base + 3)?;
    let frame_register = b3 & 0x0F;
    let frame_offset = b3 >> 4;

    let mut info = UnwindInfo::from_flags_byte(flags);
    info.prolog_size = prolog_size;
    info.unwind_code_count = count;

    // Unwind codes: `count` slots of 2 bytes, padded to an even slot count.
    let codes_len = ((count as usize) + 1) & !1;
    let after_codes = base + 4 + codes_len * 2;

    let mut language_data_rva = None;
    if info.is_chained {
        let cbegin = rd_u32(image, after_codes)?;
        let cend = rd_u32(image, after_codes + 4)?;
        let cunwind = rd_u32(image, after_codes + 8)?;
        info.chained_function = Some(RuntimeFunction {
            begin_address: cbegin,
            end_address: cend,
            unwind_info_address: cunwind,
        });
    } else if info.has_exception_handler || info.has_termination_handler {
        info.handler_rva = rd_u32(image, after_codes);
        // Language-specific data immediately follows the handler RVA.
        language_data_rva = Some((after_codes + 4) as u32);
    }

    Some(ParsedUnwindInfo {
        info,
        version,
        frame_register,
        frame_offset,
        language_data_rva,
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// C scope table (__C_specific_handler)
// ─────────────────────────────────────────────────────────────────────────────

/// One `SCOPE_TABLE` entry used by `__C_specific_handler` (__try/__except/
/// __finally in C).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CScopeEntry {
    /// RVA of the start of the guarded (__try) range.
    pub begin_rva: u32,
    /// RVA one past the end of the guarded range.
    pub end_rva: u32,
    /// RVA of the filter function, or `1` for `EXCEPTION_EXECUTE_HANDLER`;
    /// for a __finally scope this is the RVA of the finally funclet.
    pub handler_rva: u32,
    /// RVA of the __except block, or `0` for a __finally scope.
    pub jump_target_rva: u32,
}

impl CScopeEntry {
    /// A `JumpTarget` of 0 marks a termination (__finally) scope.
    #[must_use]
    pub const fn is_finally(&self) -> bool {
        self.jump_target_rva == 0
    }
}

/// Parse a `SCOPE_TABLE` (`Count` u32 followed by `Count` 16-byte entries) at
/// `rva` in the RVA-addressed `image`.  Returns `None` on truncation or an
/// implausible count.
#[must_use]
pub fn parse_c_scope_table(image: &[u8], rva: u32) -> Option<Vec<CScopeEntry>> {
    let base = rva as usize;
    let count = rd_u32(image, base)? as usize;
    // Sanity cap: a scope table larger than the remaining section is bogus.
    if count > (image.len().saturating_sub(base + 4)) / 16 {
        return None;
    }
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        let off = base + 4 + i * 16;
        out.push(CScopeEntry {
            begin_rva: rd_u32(image, off)?,
            end_rva: rd_u32(image, off + 4)?,
            handler_rva: rd_u32(image, off + 8)?,
            jump_target_rva: rd_u32(image, off + 12)?,
        });
    }
    Some(out)
}

/// Convert C scope-table entries into [`ExceptionRegion`] metadata (VAs are
/// `image_base + rva`).  Nesting depth is computed by containment.
#[must_use]
pub fn regions_from_c_scope_table(entries: &[CScopeEntry], image_base: u64) -> Vec<ExceptionRegion> {
    let va = |rva: u32| Address::new(image_base + u64::from(rva));
    let mut regions: Vec<ExceptionRegion> = entries
        .iter()
        .map(|e| {
            let handlers = if e.is_finally() {
                vec![ExceptionHandler::finally(va(e.handler_rva))]
            } else {
                let mut h = ExceptionHandler::catch(va(e.jump_target_rva));
                h.filter_expr = Some(if e.handler_rva == 1 {
                    "EXCEPTION_EXECUTE_HANDLER".to_owned()
                } else {
                    format!("filter_{:#x}", image_base + u64::from(e.handler_rva))
                });
                vec![h]
            };
            ExceptionRegion {
                try_start: va(e.begin_rva),
                try_end: va(e.end_rva),
                handlers,
                kind: ExceptionHandlingKind::WindowsSeh64,
                depth: 0,
            }
        })
        .collect();

    // Depth by strict containment.
    let ranges: Vec<(Address, Address)> =
        regions.iter().map(|r| (r.try_start, r.try_end)).collect();
    for (i, r) in regions.iter_mut().enumerate() {
        let (s, e) = ranges[i];
        r.depth = ranges
            .iter()
            .enumerate()
            .filter(|&(j, &(os, oe))| j != i && os <= s && e <= oe && (os, oe) != (s, e))
            .count() as u32;
    }
    regions
}

// ─────────────────────────────────────────────────────────────────────────────
// MSVC C++ EH — FuncInfo / TryBlockMap / IpToStateMap
// ─────────────────────────────────────────────────────────────────────────────

/// Parsed MSVC C++ EH `FuncInfo` header (magic `0x1993052x`).
#[derive(Debug, Clone, Copy)]
pub struct MsvcFuncInfo {
    pub magic: u32,
    pub max_state: u32,
    pub unwind_map_rva: u32,
    pub try_block_count: u32,
    pub try_block_map_rva: u32,
    pub ip_map_count: u32,
    pub ip_to_state_map_rva: u32,
}

/// One `TryBlockMapEntry`.
#[derive(Debug, Clone, Copy)]
pub struct MsvcTryBlock {
    pub try_low: i32,
    pub try_high: i32,
    pub catch_high: i32,
    pub catch_count: u32,
    pub handler_array_rva: u32,
}

/// One `HandlerType` (catch clause).
#[derive(Debug, Clone, Copy)]
pub struct MsvcCatchHandler {
    pub adjectives: u32,
    /// RVA of the `TypeDescriptor` for the caught type (0 = `catch(...)`).
    pub type_descriptor_rva: u32,
    pub catch_obj_offset: i32,
    /// RVA of the catch funclet.
    pub handler_rva: u32,
}

/// One `IpToStateMapEntry` (x64 layout: Ip RVA + state).
#[derive(Debug, Clone, Copy)]
pub struct IpToState {
    pub ip_rva: u32,
    pub state: i32,
}

/// Parse a `FuncInfo` structure at `rva` (x64 image layout, RVA fields).
#[must_use]
pub fn parse_msvc_funcinfo(image: &[u8], rva: u32) -> Option<MsvcFuncInfo> {
    let b = rva as usize;
    let magic = rd_u32(image, b)?;
    if magic & 0xFFFF_FF00 != 0x1993_0500 {
        return None;
    }
    Some(MsvcFuncInfo {
        magic,
        max_state: rd_u32(image, b + 4)?,
        unwind_map_rva: rd_u32(image, b + 8)?,
        try_block_count: rd_u32(image, b + 12)?,
        try_block_map_rva: rd_u32(image, b + 16)?,
        ip_map_count: rd_u32(image, b + 20)?,
        ip_to_state_map_rva: rd_u32(image, b + 24)?,
    })
}

/// Parse the `TryBlockMap` array (20-byte entries on x64).
#[must_use]
pub fn parse_try_block_map(image: &[u8], rva: u32, count: u32) -> Option<Vec<MsvcTryBlock>> {
    let b = rva as usize;
    if count as usize > image.len().saturating_sub(b) / 20 {
        return None;
    }
    let mut out = Vec::with_capacity(count as usize);
    for i in 0..count as usize {
        let off = b + i * 20;
        out.push(MsvcTryBlock {
            try_low: rd_i32(image, off)?,
            try_high: rd_i32(image, off + 4)?,
            catch_high: rd_i32(image, off + 8)?,
            catch_count: rd_u32(image, off + 12)?,
            handler_array_rva: rd_u32(image, off + 16)?,
        });
    }
    Some(out)
}

/// Parse a `HandlerType` array (20-byte entries on x64).
#[must_use]
pub fn parse_catch_handlers(image: &[u8], rva: u32, count: u32) -> Option<Vec<MsvcCatchHandler>> {
    let b = rva as usize;
    if count as usize > image.len().saturating_sub(b) / 20 {
        return None;
    }
    let mut out = Vec::with_capacity(count as usize);
    for i in 0..count as usize {
        let off = b + i * 20;
        out.push(MsvcCatchHandler {
            adjectives: rd_u32(image, off)?,
            type_descriptor_rva: rd_u32(image, off + 4)?,
            catch_obj_offset: rd_i32(image, off + 8)?,
            handler_rva: rd_u32(image, off + 12)?,
            // off+16 is the funclet frame displacement (x64); not needed here.
        });
    }
    Some(out)
}

/// Parse the `IpToStateMap` array (8-byte entries: Ip RVA, state).
#[must_use]
pub fn parse_ip_to_state_map(image: &[u8], rva: u32, count: u32) -> Option<Vec<IpToState>> {
    let b = rva as usize;
    if count as usize > image.len().saturating_sub(b) / 8 {
        return None;
    }
    let mut out = Vec::with_capacity(count as usize);
    for i in 0..count as usize {
        let off = b + i * 8;
        out.push(IpToState {
            ip_rva: rd_u32(image, off)?,
            state: rd_i32(image, off + 4)?,
        });
    }
    Some(out)
}

/// Build [`ExceptionRegion`]s from a parsed MSVC C++ EH `FuncInfo`.
///
/// Try ranges are recovered by projecting each try block's `[try_low,
/// try_high]` state interval through the IP-to-state map: the try body is the
/// union of IP ranges whose state falls inside the interval.  `func_end_rva`
/// bounds the last IP range.
#[must_use]
pub fn regions_from_msvc_funcinfo(
    image: &[u8],
    fi: &MsvcFuncInfo,
    image_base: u64,
    func_end_rva: u32,
) -> Vec<ExceptionRegion> {
    let Some(try_blocks) = parse_try_block_map(image, fi.try_block_map_rva, fi.try_block_count)
    else {
        return Vec::new();
    };
    let ip_map =
        parse_ip_to_state_map(image, fi.ip_to_state_map_rva, fi.ip_map_count).unwrap_or_default();
    let va = |rva: u32| Address::new(image_base + u64::from(rva));

    let mut regions = Vec::new();
    for tb in &try_blocks {
        // Project the state interval to an IP range.
        let mut start: Option<u32> = None;
        let mut end: u32 = func_end_rva;
        for (i, e) in ip_map.iter().enumerate() {
            let in_try = e.state >= tb.try_low && e.state <= tb.try_high;
            if in_try && start.is_none() {
                start = Some(e.ip_rva);
            }
            if !in_try && start.is_some() && end == func_end_rva {
                // First entry after the try range closes it.
                if ip_map[..i].iter().any(|p| p.ip_rva == start.unwrap_or(0)) || start.is_some() {
                    end = e.ip_rva;
                    break;
                }
            }
        }
        let Some(start) = start else { continue };

        let handlers: Vec<ExceptionHandler> =
            parse_catch_handlers(image, tb.handler_array_rva, tb.catch_count)
                .unwrap_or_default()
                .iter()
                .map(|h| {
                    let mut eh = ExceptionHandler::catch(va(h.handler_rva));
                    if h.type_descriptor_rva == 0 {
                        eh.type_name = Some("...".to_owned());
                    }
                    eh
                })
                .collect();

        regions.push(ExceptionRegion {
            try_start: va(start),
            try_end: va(end),
            handlers,
            kind: ExceptionHandlingKind::MsvcCppEh,
            depth: 0,
        });
    }

    // Nesting depth by containment.
    let ranges: Vec<(Address, Address)> =
        regions.iter().map(|r| (r.try_start, r.try_end)).collect();
    for (i, r) in regions.iter_mut().enumerate() {
        let (s, e) = ranges[i];
        r.depth = ranges
            .iter()
            .enumerate()
            .filter(|&(j, &(os, oe))| j != i && os <= s && e <= oe && (os, oe) != (s, e))
            .count() as u32;
    }
    regions
}

/// Which personality routine guards a function — decides how the language-
/// specific data after the handler RVA is interpreted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SehPersonality {
    /// `__C_specific_handler` — C scope table.
    CSpecific,
    /// `__CxxFrameHandler3/4` — pointer to MSVC `FuncInfo`.
    CxxFrame,
}

/// One-call convenience: given `.pdata`-derived `RuntimeFunction`, an
/// RVA-addressed image, and the personality kind, produce the exception
/// regions for that function.
#[must_use]
pub fn seh_regions_for_function(
    image: &[u8],
    rf: &RuntimeFunction,
    personality: SehPersonality,
    image_base: u64,
) -> Vec<ExceptionRegion> {
    let Some(parsed) = parse_unwind_info(image, rf.unwind_info_address) else {
        return Vec::new();
    };
    let Some(lang_rva) = parsed.language_data_rva else {
        return Vec::new();
    };
    match personality {
        SehPersonality::CSpecific => parse_c_scope_table(image, lang_rva)
            .map(|entries| regions_from_c_scope_table(&entries, image_base))
            .unwrap_or_default(),
        SehPersonality::CxxFrame => {
            // Language data is a 4-byte RVA to FuncInfo.
            let Some(fi_rva) = rd_u32(image, lang_rva as usize) else {
                return Vec::new();
            };
            parse_msvc_funcinfo(image, fi_rva)
                .map(|fi| regions_from_msvc_funcinfo(image, &fi, image_base, rf.end_address))
                .unwrap_or_default()
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn put_u32(buf: &mut Vec<u8>, v: u32) {
        buf.extend_from_slice(&v.to_le_bytes());
    }

    /// An arm64 `.pdata` must not be decoded into entries that do not exist.
    ///
    /// `.pdata` exists on ARM64 Windows too, but its `RUNTIME_FUNCTION` is
    /// **8 bytes** (BeginAddress + UnwindData), not the 12 of x64
    /// (Begin/End/UnwindInfoAddress). This parser strides by 12 unconditionally
    /// and cannot know the machine — it only receives bytes.
    ///
    /// Read that way, each "entry" straddles two real records: the second
    /// record's BeginAddress lands in the `end_address` slot and so on. The
    /// giveaway is that the invariant `begin < end` — which holds for every
    /// RUNTIME_FUNCTION in a valid x64 table, since a function has non-zero
    /// length — is violated. Silently returning those as functions is worse
    /// than returning none: callers cannot tell them from real ones.
    #[test]
    fn an_arm64_pdata_does_not_yield_impossible_entries() {
        // Four arm64 records, 8 bytes each: (BeginAddress, UnwindData).
        // Ascending function starts, packed unwind data (low bit set).
        let mut p = Vec::new();
        for (begin, unwind) in [
            (0x1000u32, 0x0000_0011u32),
            (0x1040, 0x0000_0021),
            (0x1080, 0x0000_0031),
            (0x10C0, 0x0000_0041),
        ] {
            put_u32(&mut p, begin);
            put_u32(&mut p, unwind);
        }

        for rf in parse_pdata(&p) {
            assert!(
                rf.begin_address < rf.end_address,
                "entry {rf:?} is impossible: a RUNTIME_FUNCTION always ends after it                  begins, so this came from decoding a non-x64 table with the x64 stride"
            );
        }
    }

    #[test]
    fn pdata_parses_entries_and_skips_padding() {
        let mut p = Vec::new();
        put_u32(&mut p, 0x1000);
        put_u32(&mut p, 0x1050);
        put_u32(&mut p, 0x3000);
        // zero padding entry
        put_u32(&mut p, 0);
        put_u32(&mut p, 0);
        put_u32(&mut p, 0);
        let rfs = parse_pdata(&p);
        assert_eq!(rfs.len(), 1);
        assert_eq!(rfs[0].begin_address, 0x1000);
        assert_eq!(rfs[0].end_address, 0x1050);
        assert_eq!(rfs[0].unwind_info_address, 0x3000);
    }

    #[test]
    fn find_runtime_function_covers_rva() {
        let t = vec![
            RuntimeFunction {
                begin_address: 0x1000,
                end_address: 0x1050,
                unwind_info_address: 0x3000,
            },
            RuntimeFunction {
                begin_address: 0x1050,
                end_address: 0x1100,
                unwind_info_address: 0x3010,
            },
        ];
        assert_eq!(find_runtime_function(&t, 0x104F).unwrap().begin_address, 0x1000);
        assert_eq!(find_runtime_function(&t, 0x1050).unwrap().begin_address, 0x1050);
        assert!(find_runtime_function(&t, 0x2000).is_none());
    }

    /// Build a minimal image with UNWIND_INFO at 0x3000 with EHANDLER flag,
    /// 2 unwind codes, handler RVA and a C scope table right after.
    fn image_with_c_scope() -> Vec<u8> {
        let mut img = vec![0u8; 0x4000];
        let b = 0x3000;
        img[b] = 0x09; // version 1, flags = UNW_FLAG_EHANDLER (1) << 3
        img[b + 1] = 8; // prolog size
        img[b + 2] = 2; // 2 unwind codes -> 2 slots (even), 4 bytes
        img[b + 3] = 0x05; // frame reg 5 (rbp), offset 0
        // codes at b+4..b+8 (leave zero)
        let after = b + 8;
        img[after..after + 4].copy_from_slice(&0x2000u32.to_le_bytes()); // handler RVA
        // scope table at after+4: count=2
        let st = after + 4;
        img[st..st + 4].copy_from_slice(&2u32.to_le_bytes());
        // entry 0: __except with EXCEPTION_EXECUTE_HANDLER
        let e0 = st + 4;
        img[e0..e0 + 4].copy_from_slice(&0x1000u32.to_le_bytes());
        img[e0 + 4..e0 + 8].copy_from_slice(&0x1020u32.to_le_bytes());
        img[e0 + 8..e0 + 12].copy_from_slice(&1u32.to_le_bytes());
        img[e0 + 12..e0 + 16].copy_from_slice(&0x1030u32.to_le_bytes());
        // entry 1: __finally (jump target 0), nested inside entry 0
        let e1 = e0 + 16;
        img[e1..e1 + 4].copy_from_slice(&0x1008u32.to_le_bytes());
        img[e1 + 4..e1 + 8].copy_from_slice(&0x1010u32.to_le_bytes());
        img[e1 + 8..e1 + 12].copy_from_slice(&0x1040u32.to_le_bytes());
        img[e1 + 12..e1 + 16].copy_from_slice(&0u32.to_le_bytes());
        img
    }

    #[test]
    fn unwind_info_parses_header_and_handler() {
        let img = image_with_c_scope();
        let p = parse_unwind_info(&img, 0x3000).unwrap();
        assert_eq!(p.version, 1);
        assert!(p.info.has_exception_handler);
        assert!(!p.info.is_chained);
        assert_eq!(p.info.prolog_size, 8);
        assert_eq!(p.info.unwind_code_count, 2);
        assert_eq!(p.frame_register, 5);
        assert_eq!(p.info.handler_rva, Some(0x2000));
        assert!(p.language_data_rva.is_some());
    }

    #[test]
    fn c_scope_table_to_regions() {
        let img = image_with_c_scope();
        let p = parse_unwind_info(&img, 0x3000).unwrap();
        let entries = parse_c_scope_table(&img, p.language_data_rva.unwrap()).unwrap();
        assert_eq!(entries.len(), 2);
        assert!(!entries[0].is_finally());
        assert!(entries[1].is_finally());

        let regions = regions_from_c_scope_table(&entries, 0x1400_0000);
        assert_eq!(regions.len(), 2);
        let r0 = &regions[0];
        assert_eq!(r0.try_start, Address::new(0x1400_1000));
        assert_eq!(r0.try_end, Address::new(0x1400_1020));
        assert_eq!(r0.kind, ExceptionHandlingKind::WindowsSeh64);
        assert_eq!(r0.handlers[0].kind, HandlerKind::Catch);
        assert_eq!(
            r0.handlers[0].filter_expr.as_deref(),
            Some("EXCEPTION_EXECUTE_HANDLER")
        );
        assert_eq!(r0.depth, 0);
        let r1 = &regions[1];
        assert_eq!(r1.handlers[0].kind, HandlerKind::Finally);
        assert_eq!(r1.handlers[0].handler_addr, Address::new(0x1400_1040));
        assert_eq!(r1.depth, 1); // nested inside r0
    }

    #[test]
    fn seh_regions_for_function_end_to_end_c() {
        let img = image_with_c_scope();
        let rf = RuntimeFunction {
            begin_address: 0x1000,
            end_address: 0x1050,
            unwind_info_address: 0x3000,
        };
        let regions = seh_regions_for_function(&img, &rf, SehPersonality::CSpecific, 0);
        assert_eq!(regions.len(), 2);
    }

    #[test]
    fn chained_unwind_info_parses_chain() {
        let mut img = vec![0u8; 0x100];
        img[0] = 0x21; // version 1, flags = CHAININFO(4) << 3
        img[1] = 0;
        img[2] = 0; // 0 codes -> 0 slots
        img[3] = 0;
        img[4..8].copy_from_slice(&0x1000u32.to_le_bytes());
        img[8..12].copy_from_slice(&0x1050u32.to_le_bytes());
        img[12..16].copy_from_slice(&0x80u32.to_le_bytes());
        let p = parse_unwind_info(&img, 0).unwrap();
        assert!(p.info.is_chained);
        let c = p.info.chained_function.unwrap();
        assert_eq!(c.begin_address, 0x1000);
        assert_eq!(c.unwind_info_address, 0x80);
        assert!(p.language_data_rva.is_none());
    }

    #[test]
    fn truncated_scope_table_rejected() {
        let img = vec![0xFFu8; 8]; // count = 0xFFFFFFFF, no room
        assert!(parse_c_scope_table(&img, 0).is_none());
    }

    /// Build an image containing a FuncInfo with one try block, one catch(...)
    /// handler, and an IP-to-state map.
    fn image_with_funcinfo() -> Vec<u8> {
        let mut img = vec![0u8; 0x1000];
        // FuncInfo at 0x100
        let fi = 0x100;
        img[fi..fi + 4].copy_from_slice(&0x1993_0522u32.to_le_bytes());
        img[fi + 4..fi + 8].copy_from_slice(&3u32.to_le_bytes()); // maxState
        img[fi + 8..fi + 12].copy_from_slice(&0u32.to_le_bytes()); // unwind map
        img[fi + 12..fi + 16].copy_from_slice(&1u32.to_le_bytes()); // 1 try block
        img[fi + 16..fi + 20].copy_from_slice(&0x200u32.to_le_bytes()); // try map
        img[fi + 20..fi + 24].copy_from_slice(&3u32.to_le_bytes()); // 3 ip entries
        img[fi + 24..fi + 28].copy_from_slice(&0x300u32.to_le_bytes()); // ip map
        // TryBlockMapEntry at 0x200: tryLow=1 tryHigh=1 catchHigh=2 n=1 arr=0x280
        let tb = 0x200;
        img[tb..tb + 4].copy_from_slice(&1u32.to_le_bytes());
        img[tb + 4..tb + 8].copy_from_slice(&1u32.to_le_bytes());
        img[tb + 8..tb + 12].copy_from_slice(&2u32.to_le_bytes());
        img[tb + 12..tb + 16].copy_from_slice(&1u32.to_le_bytes());
        img[tb + 16..tb + 20].copy_from_slice(&0x280u32.to_le_bytes());
        // HandlerType at 0x280: adjectives, type=0 (catch ...), disp, handler
        let h = 0x280;
        img[h..h + 4].copy_from_slice(&0x40u32.to_le_bytes());
        img[h + 4..h + 8].copy_from_slice(&0u32.to_le_bytes());
        img[h + 8..h + 12].copy_from_slice(&0u32.to_le_bytes());
        img[h + 12..h + 16].copy_from_slice(&0x1F00u32.to_le_bytes());
        // IpToStateMap at 0x300: (0x1000,-1) (0x1010,1) (0x1030,-1)
        let ip = 0x300;
        img[ip..ip + 4].copy_from_slice(&0x1000u32.to_le_bytes());
        img[ip + 4..ip + 8].copy_from_slice(&(-1i32).to_le_bytes());
        img[ip + 8..ip + 12].copy_from_slice(&0x1010u32.to_le_bytes());
        img[ip + 12..ip + 16].copy_from_slice(&1u32.to_le_bytes());
        img[ip + 16..ip + 20].copy_from_slice(&0x1030u32.to_le_bytes());
        img[ip + 20..ip + 24].copy_from_slice(&(-1i32).to_le_bytes());
        img
    }

    #[test]
    fn msvc_funcinfo_regions() {
        let img = image_with_funcinfo();
        let fi = parse_msvc_funcinfo(&img, 0x100).unwrap();
        assert_eq!(fi.try_block_count, 1);
        let regions = regions_from_msvc_funcinfo(&img, &fi, 0x1_0000, 0x1050);
        assert_eq!(regions.len(), 1);
        let r = &regions[0];
        assert_eq!(r.kind, ExceptionHandlingKind::MsvcCppEh);
        assert_eq!(r.try_start, Address::new(0x1_1010));
        assert_eq!(r.try_end, Address::new(0x1_1030));
        assert_eq!(r.handlers.len(), 1);
        assert_eq!(r.handlers[0].handler_addr, Address::new(0x1_1F00));
        assert_eq!(r.handlers[0].type_name.as_deref(), Some("..."));
    }

    #[test]
    fn msvc_funcinfo_bad_magic_rejected() {
        let mut img = vec![0u8; 0x40];
        img[0..4].copy_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
        assert!(parse_msvc_funcinfo(&img, 0).is_none());
    }
}
