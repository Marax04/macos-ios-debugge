//! PE exception directory (.pdata) parser — `RUNTIME_FUNCTION` + `UNWIND_INFO`.
//!
//! Supports x64 (AMD64), ARM, and ARM64 variants. The exception table is the
//! primary mechanism for function boundary detection in stripped 64-bit PEs.

use crate::imports::{RvaSection, rva_to_file_offset};

// ---------------------------------------------------------------------------
// RUNTIME_FUNCTION (x64)
// ---------------------------------------------------------------------------

/// `IMAGE_RUNTIME_FUNCTION_ENTRY` — one entry in the x64 `.pdata` section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeFunction {
    /// RVA of the function start.
    pub begin_address: u32,
    /// RVA of the first byte past the function end.
    pub end_address: u32,
    /// RVA of the `UNWIND_INFO` structure, or a chained `RUNTIME_FUNCTION` pointer
    /// (flag bit 0 indicates chaining).
    pub unwind_info_address: u32,
}

impl RuntimeFunction {
    /// Parse one 12-byte `IMAGE_RUNTIME_FUNCTION_ENTRY` from `data` at `offset`.
    ///
    /// # Errors
    ///
    /// Returns `Err` if `data` is too short.
    pub fn parse(data: &[u8], offset: usize) -> Result<Self, String> {
        if offset + 12 > data.len() {
            return Err(format!(
                "RuntimeFunction entry truncated at offset {offset}"
            ));
        }
        let r32 = |off: usize| -> u32 {
            u32::from_le_bytes(data[off..off + 4].try_into().unwrap_or([0; 4]))
        };
        Ok(Self {
            begin_address: r32(offset),
            end_address: r32(offset + 4),
            unwind_info_address: r32(offset + 8),
        })
    }

    /// Return `true` if this entry chains to another `RUNTIME_FUNCTION`.
    #[must_use]
    pub const fn is_chained(&self) -> bool {
        self.unwind_info_address & 0x4 != 0
    }

    /// Return the RVA of the `UNWIND_INFO` (clear the flag bits).
    #[must_use]
    pub const fn unwind_info_rva(&self) -> u32 {
        self.unwind_info_address & !0x3
    }

    /// Function size in bytes.
    #[must_use]
    pub const fn size(&self) -> u32 {
        self.end_address.saturating_sub(self.begin_address)
    }
}

// ---------------------------------------------------------------------------
// UNWIND_INFO
// ---------------------------------------------------------------------------

/// Unwind operation codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnwindCode {
    PushNonvol { reg: u8 },
    AllocLarge { size: u32 },
    AllocSmall { size: u8 },
    SetFpreg { reg: u8, offset: u16 },
    SaveNonvol { reg: u8, offset: u32 },
    SaveNonvolFar { reg: u8, offset: u32 },
    SaveXmm128 { reg: u8, offset: u32 },
    SaveXmm128Far { reg: u8, offset: u32 },
    PushMachframe { push_error: bool },
    Unknown(u8),
}

/// Register names for x64 unwind codes.
#[must_use]
pub const fn x64_reg_name(reg: u8) -> &'static str {
    match reg {
        0 => "RAX",
        1 => "RCX",
        2 => "RDX",
        3 => "RBX",
        4 => "RSP",
        5 => "RBP",
        6 => "RSI",
        7 => "RDI",
        8 => "R8",
        9 => "R9",
        10 => "R10",
        11 => "R11",
        12 => "R12",
        13 => "R13",
        14 => "R14",
        15 => "R15",
        _ => "?",
    }
}

/// Parsed `UNWIND_INFO` structure.
#[derive(Debug, Clone)]
pub struct UnwindInfo {
    /// Version (must be 1).
    pub version: u8,
    /// Unwind info flags (`UNW_FLAG_*`).
    pub flags: u8,
    /// Size of function prolog in bytes.
    pub size_of_prolog: u8,
    /// Count of unwind code slots.
    pub count_of_codes: u8,
    /// Frame register (0 = none, 1–15 = register).
    pub frame_register: u8,
    /// Frame register offset.
    pub frame_offset: u8,
    /// Parsed unwind codes.
    pub codes: Vec<UnwindCode>,
    /// If `UNW_FLAG_CHAININFO`: chained `RUNTIME_FUNCTION` RVA.
    pub chained_function: Option<RuntimeFunction>,
    /// If `UNW_FLAG_EHANDLER` or `UNW_FLAG_UHANDLER`: RVA of the handler.
    pub handler_rva: Option<u32>,
}

// UNWIND_INFO flags
pub const UNW_FLAG_NHANDLER: u8 = 0x00;
pub const UNW_FLAG_EHANDLER: u8 = 0x01;
pub const UNW_FLAG_UHANDLER: u8 = 0x02;
pub const UNW_FLAG_CHAININFO: u8 = 0x04;

/// Read a little-endian `u16` from `data` at `offset`, returning 0 on truncation.
fn le16(data: &[u8], offset: usize) -> u16 {
    if offset + 2 <= data.len() {
        u16::from_le_bytes([data[offset], data[offset + 1]])
    } else {
        0
    }
}

/// Decode a single unwind code entry, returning `(UnwindCode, slots_consumed)`.
fn decode_one_unwind_code(
    data: &[u8],
    codes_start: usize,
    ci: usize,
    count: usize,
    op_info: u8,
    unwind_op: u8,
    code_val: u8,
) -> (UnwindCode, usize) {
    match unwind_op {
        0 => (UnwindCode::PushNonvol { reg: op_info }, 1),
        1 => {
            if op_info == 0 {
                if ci + 1 < count {
                    let sz = u32::from(le16(data, codes_start + (ci + 1) * 2)) * 8;
                    (UnwindCode::AllocLarge { size: sz }, 2)
                } else {
                    (UnwindCode::AllocLarge { size: 0 }, 1)
                }
            } else if ci + 2 < count {
                let lo = u32::from(le16(data, codes_start + (ci + 1) * 2));
                let hi = u32::from(le16(data, codes_start + (ci + 2) * 2));
                (UnwindCode::AllocLarge { size: (hi << 16) | lo }, 3)
            } else {
                (UnwindCode::AllocLarge { size: 0 }, 1)
            }
        }
        2 => (UnwindCode::AllocSmall { size: op_info * 8 + 8 }, 1),
        3 => (UnwindCode::SetFpreg { reg: op_info, offset: u16::from(code_val) }, 1),
        4 => {
            if ci + 1 < count {
                let off = u32::from(le16(data, codes_start + (ci + 1) * 2)) * 8;
                (UnwindCode::SaveNonvol { reg: op_info, offset: off }, 2)
            } else {
                (UnwindCode::SaveNonvol { reg: op_info, offset: 0 }, 1)
            }
        }
        5 => {
            if ci + 2 < count {
                let lo = u32::from(le16(data, codes_start + (ci + 1) * 2));
                let hi = u32::from(le16(data, codes_start + (ci + 2) * 2));
                (UnwindCode::SaveNonvolFar { reg: op_info, offset: (hi << 16) | lo }, 3)
            } else {
                (UnwindCode::SaveNonvolFar { reg: op_info, offset: 0 }, 1)
            }
        }
        8 => {
            if ci + 1 < count {
                let off = u32::from(le16(data, codes_start + (ci + 1) * 2)) * 16;
                (UnwindCode::SaveXmm128 { reg: op_info, offset: off }, 2)
            } else {
                (UnwindCode::SaveXmm128 { reg: op_info, offset: 0 }, 1)
            }
        }
        9 => {
            if ci + 2 < count {
                let lo = u32::from(le16(data, codes_start + (ci + 1) * 2));
                let hi = u32::from(le16(data, codes_start + (ci + 2) * 2));
                (UnwindCode::SaveXmm128Far { reg: op_info, offset: (hi << 16) | lo }, 3)
            } else {
                (UnwindCode::SaveXmm128Far { reg: op_info, offset: 0 }, 1)
            }
        }
        10 => (UnwindCode::PushMachframe { push_error: op_info != 0 }, 1),
        other => (UnwindCode::Unknown(other), 1),
    }
}

/// Collect all unwind codes starting at `codes_start` for `count` slots.
fn parse_unwind_codes(data: &[u8], codes_start: usize, count: usize) -> Vec<UnwindCode> {
    let mut codes = Vec::with_capacity(count);
    let mut ci = 0usize;
    while ci < count {
        let code_off = codes_start + ci * 2;
        let byte1 = if code_off + 1 < data.len() { data[code_off + 1] } else { 0 };
        let unwind_op = byte1 & 0xF;
        let op_info = byte1 >> 4;
        let code_val = if code_off < data.len() { data[code_off] } else { 0 };
        let (decoded, slots) =
            decode_one_unwind_code(data, codes_start, ci, count, op_info, unwind_op, code_val);
        codes.push(decoded);
        ci += slots;
    }
    codes
}

/// Parse the optional tail of an `UNWIND_INFO` record (chained function or handler RVA).
fn parse_unwind_tail(
    data: &[u8],
    aligned_off: usize,
    flags: u8,
) -> (Option<RuntimeFunction>, Option<u32>) {
    if flags & UNW_FLAG_CHAININFO != 0 {
        (RuntimeFunction::parse(data, aligned_off).ok(), None)
    } else if flags & (UNW_FLAG_EHANDLER | UNW_FLAG_UHANDLER) != 0 {
        if aligned_off + 4 <= data.len() {
            let rva = u32::from_le_bytes(
                data[aligned_off..aligned_off + 4].try_into().unwrap_or([0; 4]),
            );
            (None, Some(rva))
        } else {
            (None, None)
        }
    } else {
        (None, None)
    }
}

impl UnwindInfo {
    /// Parse an `UNWIND_INFO` structure from `data` at file `offset`.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the data is malformed or truncated.
    pub fn parse(data: &[u8], offset: usize) -> Result<Self, String> {
        if offset + 4 > data.len() {
            return Err(format!("UNWIND_INFO truncated at offset {offset}"));
        }
        let b = offset;
        let byte0 = data[b];
        let version = byte0 & 0x7;
        let flags = byte0 >> 3;
        let size_of_prolog = data[b + 1];
        let count_of_codes = data[b + 2];
        let byte3 = data[b + 3];
        let frame_register = byte3 & 0xF;
        let frame_offset = byte3 >> 4;

        if version != 1 {
            return Err(format!("UNWIND_INFO: unexpected version {version}"));
        }

        // Each unwind code is 2 bytes; there may be padding to 4-byte alignment.
        let codes_start = b + 4;
        let codes_end = codes_start + count_of_codes as usize * 2;
        if codes_end > data.len() {
            return Err("UNWIND_INFO codes truncated".into());
        }

        let codes = parse_unwind_codes(data, codes_start, count_of_codes as usize);

        // Locate optional data after codes (4-byte aligned)
        let aligned_off = (codes_end + 3) & !3;
        let (chained_function, handler_rva) = parse_unwind_tail(data, aligned_off, flags);

        Ok(Self {
            version,
            flags,
            size_of_prolog,
            count_of_codes,
            frame_register,
            frame_offset,
            codes,
            chained_function,
            handler_rva,
        })
    }

    /// Return `true` if this function has an exception handler.
    #[must_use]
    pub const fn has_exception_handler(&self) -> bool {
        self.flags & UNW_FLAG_EHANDLER != 0
    }

    /// Return `true` if this function has a termination handler.
    #[must_use]
    pub const fn has_termination_handler(&self) -> bool {
        self.flags & UNW_FLAG_UHANDLER != 0
    }

    /// Return `true` if this `UNWIND_INFO` chains to another.
    #[must_use]
    pub const fn is_chained(&self) -> bool {
        self.flags & UNW_FLAG_CHAININFO != 0
    }
}

// ---------------------------------------------------------------------------
// ARM .pdata entry (compact form)
// ---------------------------------------------------------------------------

/// One ARM .pdata entry (8-byte variant with compact or extended unwind).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArmRuntimeFunction {
    /// RVA of the function start (bit 0 indicates Thumb mode).
    pub begin_address: u32,
    /// Encoded unwind data or RVA of full unwind info.
    pub unwind_data: u32,
}

impl ArmRuntimeFunction {
    /// Parse one 8-byte ARM .pdata entry.
    ///
    /// # Errors
    ///
    /// Returns `Err` if `data` is too short.
    pub fn parse(data: &[u8], offset: usize) -> Result<Self, String> {
        if offset + 8 > data.len() {
            return Err(format!("ARM RuntimeFunction truncated at offset {offset}"));
        }
        let r32 = |off: usize| -> u32 {
            u32::from_le_bytes(data[off..off + 4].try_into().unwrap_or([0; 4]))
        };
        Ok(Self {
            begin_address: r32(offset),
            unwind_data: r32(offset + 4),
        })
    }

    /// Return `true` if this uses compact (inline) unwind data.
    #[must_use]
    pub const fn is_compact(&self) -> bool {
        self.unwind_data & 0x8000_0000 != 0
    }

    /// Return `true` if this is a Thumb-mode function.
    #[must_use]
    pub const fn is_thumb(&self) -> bool {
        self.begin_address & 1 != 0
    }

    /// Return the RVA of the function start (clear Thumb bit).
    #[must_use]
    pub const fn function_rva(&self) -> u32 {
        self.begin_address & !1
    }
}

// ---------------------------------------------------------------------------
// Parse the full exception directory
// ---------------------------------------------------------------------------

/// Parsed exception directory for a PE binary.
#[derive(Debug, Clone)]
pub struct ExceptionDirectory {
    /// All `RUNTIME_FUNCTION` entries.
    pub functions: Vec<RuntimeFunction>,
    /// Parsed `UNWIND_INFO` structures keyed by `RUNTIME_FUNCTION` index.
    pub unwind_infos: Vec<Option<UnwindInfo>>,
}

impl ExceptionDirectory {
    /// Parse the exception directory from the PE .pdata section.
    #[must_use]
    pub fn parse_x64(
        data: &[u8],
        sections: &[RvaSection],
        pdata_rva: u32,
        pdata_size: u32,
    ) -> Self {
        let Some(pdata_off) = rva_to_file_offset(pdata_rva, sections) else {
            return Self {
                functions: Vec::new(),
                unwind_infos: Vec::new(),
            };
        };

        // `pdata_size` is a raw u32 from the data directory: cap the
        // pre-allocation by the entries the file could actually contain.
        let num_entries = (pdata_size as usize / 12).min(data.len() / 12);
        let mut functions = Vec::with_capacity(num_entries);
        let mut unwind_infos = Vec::with_capacity(num_entries);

        for i in 0..num_entries {
            let off = pdata_off + i * 12;
            if off + 12 > data.len() {
                break;
            }
            let Ok(rf) = RuntimeFunction::parse(data, off) else {
                break;
            };
            if rf.begin_address == 0 && rf.end_address == 0 {
                break;
            }

            // Resolve UNWIND_INFO
            let ui = if rf.is_chained() {
                None
            } else {
                let ui_rva = rf.unwind_info_rva();
                rva_to_file_offset(ui_rva, sections)
                    .and_then(|ui_off| UnwindInfo::parse(data, ui_off).ok())
            };

            unwind_infos.push(ui);
            functions.push(rf);
        }

        Self {
            functions,
            unwind_infos,
        }
    }

    /// Return all function RVA ranges as `(begin, end)` tuples.
    #[must_use]
    pub fn function_ranges(&self) -> Vec<(u32, u32)> {
        self.functions
            .iter()
            .map(|f| (f.begin_address, f.end_address))
            .collect()
    }

    /// Count functions that have exception handlers registered.
    #[must_use]
    pub fn exception_handler_count(&self) -> usize {
        self.unwind_infos
            .iter()
            .filter(|ui| {
                ui.as_ref()
                    .is_some_and(UnwindInfo::has_exception_handler)
            })
            .count()
    }

    /// Count chained `RUNTIME_FUNCTION` entries.
    #[must_use]
    pub fn chained_count(&self) -> usize {
        self.functions.iter().filter(|f| f.is_chained()).count()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_runtime_function_parse() {
        let mut buf = vec![0u8; 12];
        buf[0..4].copy_from_slice(&0x1000u32.to_le_bytes());
        buf[4..8].copy_from_slice(&0x1080u32.to_le_bytes());
        buf[8..12].copy_from_slice(&0x5000u32.to_le_bytes());
        let rf = RuntimeFunction::parse(&buf, 0).unwrap();
        assert_eq!(rf.begin_address, 0x1000);
        assert_eq!(rf.end_address, 0x1080);
        assert_eq!(rf.size(), 0x80);
        assert!(!rf.is_chained());
    }

    #[test]
    fn test_runtime_function_parse_too_short() {
        assert!(RuntimeFunction::parse(&[0u8; 8], 0).is_err());
    }

    #[test]
    fn test_runtime_function_chained() {
        let mut buf = vec![0u8; 12];
        buf[8..12].copy_from_slice(&0x5004u32.to_le_bytes()); // bit 2 set = chained
        let rf = RuntimeFunction::parse(&buf, 0).unwrap();
        assert!(rf.is_chained());
    }

    #[test]
    fn test_unwind_info_parse_minimal() {
        // Version 1, flags 0, prolog 6, 0 codes, no frame reg
        let buf = vec![0x01u8, 0x06, 0x00, 0x00];
        let ui = UnwindInfo::parse(&buf, 0).unwrap();
        assert_eq!(ui.version, 1);
        assert_eq!(ui.size_of_prolog, 6);
        assert_eq!(ui.count_of_codes, 0);
        assert!(ui.codes.is_empty());
    }

    #[test]
    fn test_unwind_info_push_nonvol() {
        // version=1, flags=0, prolog=1, count=1, frame=0
        // code slot: offset_in_prolog=1, then second byte packs
        // UnwindOp in the low nibble (0 = PUSH_NONVOL) and OpInfo in the high
        // nibble (5 = RBP), i.e. (5 << 4) | 0 = 0x50.
        let buf = vec![0x01u8, 0x01, 0x01, 0x00, 0x01, 0x50]; // + 1 code slot
        let ui = UnwindInfo::parse(&buf, 0).unwrap();
        assert_eq!(ui.codes.len(), 1);
        assert!(matches!(ui.codes[0], UnwindCode::PushNonvol { reg: 5 }));
    }

    #[test]
    fn test_unwind_info_bad_version() {
        let buf = vec![0x02u8, 0x00, 0x00, 0x00]; // version=2, invalid
        assert!(UnwindInfo::parse(&buf, 0).is_err());
    }

    #[test]
    fn test_x64_reg_name() {
        assert_eq!(x64_reg_name(0), "RAX");
        assert_eq!(x64_reg_name(5), "RBP");
        assert_eq!(x64_reg_name(15), "R15");
        assert_eq!(x64_reg_name(20), "?");
    }

    #[test]
    fn test_arm_runtime_function_parse() {
        let mut buf = vec![0u8; 8];
        buf[0..4].copy_from_slice(&0x1001u32.to_le_bytes()); // Thumb bit set
        buf[4..8].copy_from_slice(&0x8000_0001u32.to_le_bytes()); // compact
        let arf = ArmRuntimeFunction::parse(&buf, 0).unwrap();
        assert!(arf.is_thumb());
        assert!(arf.is_compact());
        assert_eq!(arf.function_rva(), 0x1000);
    }

    #[test]
    fn test_arm_runtime_function_too_short() {
        assert!(ArmRuntimeFunction::parse(&[0u8; 4], 0).is_err());
    }

    #[test]
    fn test_exception_directory_parse_x64_empty_sections() {
        let sections: Vec<RvaSection> = Vec::new();
        let ed = ExceptionDirectory::parse_x64(&[], &sections, 0x1000, 0x100);
        assert!(ed.functions.is_empty());
    }

    #[test]
    fn test_exception_directory_function_ranges() {
        let rf1 = RuntimeFunction {
            begin_address: 0x1000,
            end_address: 0x1080,
            unwind_info_address: 0,
        };
        let rf2 = RuntimeFunction {
            begin_address: 0x2000,
            end_address: 0x2040,
            unwind_info_address: 0,
        };
        let ed = ExceptionDirectory {
            functions: vec![rf1, rf2],
            unwind_infos: vec![None, None],
        };
        let ranges = ed.function_ranges();
        assert_eq!(ranges.len(), 2);
        assert_eq!(ranges[0], (0x1000, 0x1080));
    }

    #[test]
    fn test_exception_directory_exception_handler_count() {
        let ui = UnwindInfo {
            version: 1,
            flags: UNW_FLAG_EHANDLER,
            size_of_prolog: 0,
            count_of_codes: 0,
            frame_register: 0,
            frame_offset: 0,
            codes: Vec::new(),
            chained_function: None,
            handler_rva: Some(0x5000),
        };
        let ed = ExceptionDirectory {
            functions: vec![RuntimeFunction {
                begin_address: 0x1000,
                end_address: 0x1010,
                unwind_info_address: 0,
            }],
            unwind_infos: vec![Some(ui)],
        };
        assert_eq!(ed.exception_handler_count(), 1);
    }
}
