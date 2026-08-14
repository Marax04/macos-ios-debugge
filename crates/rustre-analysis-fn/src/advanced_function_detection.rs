//! Advanced function detection for `rustre-analysis-fn`.
//!
//! This module extends the basic prologue scanner with recognition of
//! non-standard function patterns that frequently appear in compiled binaries:
//!
//! * **PIC prologues** — position-independent code (`__x86.get_pc_thunk.*`, GOT-relative
//!   addressing set-up sequences).
//! * **GCC cold functions** — functions placed in `.text.unlikely` / `.text.cold` with
//!   attributes that cause GCC to emit a minimal prologue.
//! * **COMDAT linkage stubs** — identical-COMDAT folded functions in MSVC `/OPT:ICF` outputs.
//! * **Tail-call merging** — a pattern where the compiler replaces the last `CALL; RET`
//!   pair with a single `JMP` to eliminate stack frames.
//! * **Thunk detection** — very short functions (≤ 6 bytes on x86) whose only purpose
//!   is a single unconditional `JMP` to another target.
//! * **PLT stub recognition** — Linux PLT entries (`[addr]@plt`) that consist of
//!   `JMP [GOT_slot]; PUSH index; JMP plt0`.
//! * **Exception-handler table mining** — parsing `.pdata` (PE32+) or `__gcc_except_table`
//!   (ELF / LLVM) to discover functions referenced only via exception dispatch.
//! * **LSDA reference mining** — scanning Language-Specific Data Area references embedded in
//!   `.eh_frame` CFI records to discover C++ landing-pad addresses.
//! * **Symbol table reconciliation** — merging detector output with partial or full symbol
//!   tables, resolving address conflicts and assigning provenance scores.

use std::collections::{HashMap, HashSet};

use crate::{Confidence, DetectionSource, FunctionBoundary, MemorySlice};
use rustre_core::address::Address;

// ─────────────────────────────────────────────────────────────────────────────
// PIC prologue detection
// ─────────────────────────────────────────────────────────────────────────────

/// A set of byte patterns that indicate position-independent code prologues on
/// x86-32.  The classic pattern is `CALL $+5; POP reg` used to materialise the
/// GOT/IP base into a register.
pub struct PicPrologueDetector {
    /// Minimum number of PIC-style instructions required before accepting the
    /// address as a function entry.
    ///
    /// NOTE: currently dead — `scan` does not read this field, so changing it
    /// has no effect on detection behavior. Flagged rather than removed; wire
    /// it into `scan` (e.g. require `min_pic_insns` consecutive PIC-pattern
    /// hits before accepting) or drop it once confirmed unused by callers.
    pub min_pic_insns: usize,
}

impl PicPrologueDetector {
    /// Create a detector with sensible defaults.
    #[must_use]
    pub const fn new() -> Self {
        Self { min_pic_insns: 1 }
    }

    /// Scan `mem` for x86-32 PIC prologues.
    ///
    /// The canonical sequence is:
    /// ```text
    /// call  .+5          ; E8 00 00 00 00
    /// pop   <reg>        ; 58..5F
    /// ```
    /// Some compilers also use the `__x86.get_pc_thunk.*` variant:
    /// ```text
    /// mov   (<rsp>), <reg>   ; 8B 04 24 or 8B 0C 24 …
    /// ret                    ; C3
    /// ```
    #[must_use]
    pub fn scan(&self, mem: &MemorySlice<'_>) -> Vec<FunctionBoundary> {
        let mut results = Vec::new();
        let bytes = mem.bytes;
        let len = bytes.len();

        let mut i = 0usize;
        while i + 2 < len {
            // Pattern 1: CALL $+5 (E8 00 00 00 00) followed by POP reg (58..5F)
            if i + 5 < len
                && bytes[i] == 0xE8
                && bytes[i + 1] == 0x00
                && bytes[i + 2] == 0x00
                && bytes[i + 3] == 0x00
                && bytes[i + 4] == 0x00
                && (0x58..=0x5F).contains(&bytes[i + 5])
            {
                let addr = Address::new(mem.base.as_u64() + i as u64);
                results.push(
                    FunctionBoundary::new(addr, Confidence::High, DetectionSource::ProloguePattern)
                        .with_name("pic_thunk"),
                );
                i += 6;
                continue;
            }

            // Pattern 2: get_pc_thunk variant: MOV (ESP), reg; RET
            // 8B 04 24 C3  (mov eax, [esp]; ret)
            if i + 3 < len
                && bytes[i] == 0x8B
                && bytes[i + 2] == 0x24
                && bytes[i + 3] == 0xC3
                && matches!(bytes[i + 1], 0x04 | 0x0C | 0x14 | 0x1C | 0x34 | 0x3C)
            {
                let addr = Address::new(mem.base.as_u64() + i as u64);
                results.push(
                    FunctionBoundary::new(addr, Confidence::High, DetectionSource::ProloguePattern)
                        .with_name("get_pc_thunk"),
                );
                i += 4;
                continue;
            }

            i += 1;
        }

        results
    }
}

impl Default for PicPrologueDetector {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Thunk detector
// ─────────────────────────────────────────────────────────────────────────────

/// Classifies a short function as a thunk if it consists of exactly one
/// unconditional `JMP` instruction with no other meaningful instructions.
#[derive(Debug, Clone)]
pub struct ThunkInfo {
    /// Start address of the thunk.
    pub thunk_addr: Address,
    /// Where the thunk jumps.
    pub target_addr: Address,
    /// Whether the target is an indirect (memory-dereferenced) jump.
    pub is_indirect: bool,
    /// Optional resolved name of the target.
    pub target_name: Option<String>,
}

/// Detects thunk functions in a memory slice.
pub struct ThunkDetector {
    /// Maximum byte length of a function to be considered a thunk candidate.
    pub max_thunk_bytes: usize,
}

impl ThunkDetector {
    /// Create a detector with a 16-byte thunk limit.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            max_thunk_bytes: 16,
        }
    }

    /// Scan `mem` for x86-64 thunk patterns.
    ///
    /// Recognised patterns:
    /// * `JMP rel8` (`EB xx`) — 2 bytes
    /// * `JMP rel32` (`E9 xx xx xx xx`) — 5 bytes
    /// * `JMP [RIP+rel32]` (`FF 25 xx xx xx xx`) — 6 bytes (indirect, PLT/IAT)
    #[must_use]
    pub fn scan(&self, mem: &MemorySlice<'_>) -> Vec<ThunkInfo> {
        let mut results = Vec::new();
        let bytes = mem.bytes;
        let base = mem.base.as_u64();

        let mut i = 0usize;
        while i < bytes.len() {
            // JMP rel32 (E9)
            if i + 5 <= bytes.len() && bytes[i] == 0xE9 {
                let disp =
                    i32::from_le_bytes([bytes[i + 1], bytes[i + 2], bytes[i + 3], bytes[i + 4]]);
                let next_pc = base.wrapping_add(i as u64).wrapping_add(5);
                let target_raw = u64::from_ne_bytes(
                    (i64::from_ne_bytes(next_pc.to_ne_bytes()).wrapping_add(i64::from(disp)))
                        .to_ne_bytes(),
                );
                results.push(ThunkInfo {
                    thunk_addr: Address::new(base + i as u64),
                    target_addr: Address::new(target_raw),
                    is_indirect: false,
                    target_name: None,
                });
                i += 5;
                continue;
            }

            // JMP rel8 (EB)
            if i + 2 <= bytes.len() && bytes[i] == 0xEB {
                let disp = i8::from_le_bytes([bytes[i + 1]]);
                let next_pc = base.wrapping_add(i as u64).wrapping_add(2);
                let target_raw = next_pc.wrapping_add_signed(i64::from(disp));
                results.push(ThunkInfo {
                    thunk_addr: Address::new(base + i as u64),
                    target_addr: Address::new(target_raw),
                    is_indirect: false,
                    target_name: None,
                });
                i += 2;
                continue;
            }

            // JMP [RIP+rel32] (FF 25)
            if i + 6 <= bytes.len() && bytes[i] == 0xFF && bytes[i + 1] == 0x25 {
                let disp =
                    i32::from_le_bytes([bytes[i + 2], bytes[i + 3], bytes[i + 4], bytes[i + 5]]);
                let next_pc = base.wrapping_add(i as u64).wrapping_add(6);
                let got_slot = u64::from_ne_bytes(
                    (i64::from_ne_bytes(next_pc.to_ne_bytes()).wrapping_add(i64::from(disp)))
                        .to_ne_bytes(),
                );
                results.push(ThunkInfo {
                    thunk_addr: Address::new(base + i as u64),
                    target_addr: Address::new(got_slot),
                    is_indirect: true,
                    target_name: None,
                });
                i += 6;
                continue;
            }

            i += 1;
        }

        // Keep only those within the thunk-size budget (scan forward from the start
        // of each detected thunk to confirm there is no other code before the next
        // thunk or end of the window).
        results.retain(|t| {
            let start =
                usize::try_from(t.thunk_addr.as_u64().saturating_sub(base)).unwrap_or(usize::MAX);
            start < self.max_thunk_bytes || start == 0
        });

        results
    }

    /// Convert detected thunks to [`FunctionBoundary`] entries.
    #[must_use]
    pub fn to_boundaries(thunks: &[ThunkInfo]) -> Vec<FunctionBoundary> {
        thunks
            .iter()
            .map(|t| {
                let mut fb = FunctionBoundary::new(
                    t.thunk_addr,
                    Confidence::High,
                    DetectionSource::ProloguePattern,
                );
                if let Some(name) = &t.target_name {
                    fb = fb.with_name(format!("thunk_{name}"));
                } else {
                    fb = fb.with_name("thunk");
                }
                fb
            })
            .collect()
    }
}

impl Default for ThunkDetector {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PLT stub recognition
// ─────────────────────────────────────────────────────────────────────────────

/// One entry in the Procedure Linkage Table.
#[derive(Debug, Clone)]
pub struct PltEntry {
    /// Virtual address of this PLT stub.
    pub plt_addr: Address,
    /// Address of the corresponding GOT slot.
    pub got_slot: Address,
    /// Index pushed onto the stack (used to identify the relocation).
    pub reloc_index: Option<u32>,
    /// Symbol name resolved from the dynamic symbol table, if available.
    pub symbol_name: Option<String>,
}

/// Recognises Linux PLT stubs in an x86-64 binary.
///
/// A standard PLT entry (after the PLT-0 resolver) is 16 bytes:
/// ```text
/// JMP  [RIP + <GOT slot offset>]   ; FF 25 xx xx xx xx
/// PUSH <reloc_index>               ; 68 xx xx xx xx
/// JMP  <plt0>                      ; E9 xx xx xx xx
/// ```
pub struct PltScanner {
    /// Expected alignment of PLT entries in bytes (typically 16).
    pub entry_alignment: usize,
    /// Maximum number of entries to scan.
    pub max_entries: usize,
}

impl PltScanner {
    /// Create a scanner for standard 16-byte PLT entries.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            entry_alignment: 16,
            max_entries: 4096,
        }
    }

    /// Scan `mem` for PLT stubs. Returns one [`PltEntry`] per detected stub.
    #[must_use]
    pub fn scan(&self, mem: &MemorySlice<'_>) -> Vec<PltEntry> {
        let mut results = Vec::new();
        let bytes = mem.bytes;
        let base = mem.base.as_u64();
        let alignment = self.entry_alignment;

        // `entry_alignment` is a public, caller-settable field. A value of 0
        // would make `i % alignment` panic (division/modulo by zero) and
        // `i += alignment - (i % alignment)` would fail to advance `i`,
        // hanging the scan. Treat a malformed (zero) alignment as "no
        // alignment requirement" instead of panicking or looping forever.
        if alignment == 0 {
            return results;
        }

        let mut i = 0usize;
        while i + 16 <= bytes.len() && results.len() < self.max_entries {
            // Expect alignment.
            if !i.is_multiple_of(alignment) {
                i += alignment - (i % alignment);
                continue;
            }

            // JMP [RIP+rel32]
            if bytes[i] == 0xFF && bytes[i + 1] == 0x25 {
                let disp =
                    i32::from_le_bytes([bytes[i + 2], bytes[i + 3], bytes[i + 4], bytes[i + 5]]);
                let next_pc = base.wrapping_add(i as u64).wrapping_add(6);
                let got_slot = u64::from_ne_bytes(
                    (i64::from_ne_bytes(next_pc.to_ne_bytes()).wrapping_add(i64::from(disp)))
                        .to_ne_bytes(),
                );

                // PUSH imm32 at offset 6
                let reloc_index = if i + 11 <= bytes.len() && bytes[i + 6] == 0x68 {
                    Some(u32::from_le_bytes([
                        bytes[i + 7],
                        bytes[i + 8],
                        bytes[i + 9],
                        bytes[i + 10],
                    ]))
                } else {
                    None
                };

                results.push(PltEntry {
                    plt_addr: Address::new(base + i as u64),
                    got_slot: Address::new(got_slot),
                    reloc_index,
                    symbol_name: None,
                });
            }

            i += alignment;
        }

        results
    }

    /// Convert PLT entries into [`FunctionBoundary`] records.
    #[must_use]
    pub fn to_boundaries(entries: &[PltEntry]) -> Vec<FunctionBoundary> {
        entries
            .iter()
            .map(|e| {
                let name = e
                    .symbol_name
                    .as_deref()
                    .map_or_else(|| "plt_stub".into(), |s| format!("{s}@plt"));
                FunctionBoundary::new(
                    e.plt_addr,
                    Confidence::Certain,
                    DetectionSource::SymbolTable,
                )
                .with_name(name)
            })
            .collect()
    }
}

impl Default for PltScanner {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Exception-handler table mining (.pdata / LSDA)
// ─────────────────────────────────────────────────────────────────────────────

/// A function entry recovered from a PE `.pdata` `RUNTIME_FUNCTION` record or
/// ELF/LLVM `__gcc_except_table`.
#[derive(Debug, Clone)]
pub struct ExceptionHandlerEntry {
    /// Start address of the guarded function.
    pub function_start: Address,
    /// End address of the guarded function (exclusive).
    pub function_end: Address,
    /// Address of the unwind / LSDA data structure.
    pub handler_addr: Address,
}

/// Parses a flat byte array containing PE32+ `RUNTIME_FUNCTION` records.
///
/// Each record is 12 bytes:
/// ```text
/// u32  BeginAddress  (RVA)
/// u32  EndAddress    (RVA)
/// u32  UnwindInfoAddress (RVA)
/// ```
#[must_use]
pub fn parse_pdata_records(pdata_bytes: &[u8], image_base: u64) -> Vec<ExceptionHandlerEntry> {
    let mut entries = Vec::new();
    let mut i = 0usize;
    while i + 12 <= pdata_bytes.len() {
        let begin = u64::from(u32::from_le_bytes([
            pdata_bytes[i],
            pdata_bytes[i + 1],
            pdata_bytes[i + 2],
            pdata_bytes[i + 3],
        ]));
        let end = u64::from(u32::from_le_bytes([
            pdata_bytes[i + 4],
            pdata_bytes[i + 5],
            pdata_bytes[i + 6],
            pdata_bytes[i + 7],
        ]));
        let handler = u64::from(u32::from_le_bytes([
            pdata_bytes[i + 8],
            pdata_bytes[i + 9],
            pdata_bytes[i + 10],
            pdata_bytes[i + 11],
        ]));

        // Skip null records.
        if begin == 0 && end == 0 {
            i += 12;
            continue;
        }

        entries.push(ExceptionHandlerEntry {
            function_start: Address::new(image_base + begin),
            function_end: Address::new(image_base + end),
            handler_addr: Address::new(image_base + handler),
        });
        i += 12;
    }
    entries
}

/// Convert exception-handler entries to [`FunctionBoundary`] records.
#[must_use]
pub fn exception_entries_to_boundaries(entries: &[ExceptionHandlerEntry]) -> Vec<FunctionBoundary> {
    entries
        .iter()
        .map(|e| {
            FunctionBoundary::new(
                e.function_start,
                Confidence::Certain,
                DetectionSource::ExceptionHandler,
            )
            .with_end(e.function_end)
        })
        .collect()
}

// ─────────────────────────────────────────────────────────────────────────────
// LSDA reference mining
// ─────────────────────────────────────────────────────────────────────────────

/// An LSDA (Language-Specific Data Area) reference found in `.eh_frame` CFI records.
///
/// The `personality` address identifies the C++ personality routine,
/// while `lsda_addr` is the start of the type/action tables.
#[derive(Debug, Clone)]
pub struct LsdaReference {
    /// Address of the function whose FDE contains this LSDA reference.
    pub function_addr: Address,
    /// Address of the LSDA data for that function.
    pub lsda_addr: Address,
    /// Address of the personality routine (e.g. `__gxx_personality_v0`).
    pub personality_addr: Option<Address>,
}

/// `DW_EH_PE_omit`: no value encoded.
const DW_EH_PE_OMIT: u8 = 0xFF;

/// Parsed per-CIE info needed to decode the FDEs that reference it.
struct CieInfo {
    /// Encoding of FDE `pc_begin`/`pc_range` (`DW_EH_PE_*`), or absptr default.
    fde_encoding: u8,
    /// Encoding of the LSDA pointer in FDE augmentation data, if any.
    lsda_encoding: Option<u8>,
    /// Whether the CIE augmentation string starts with 'z'.
    has_aug_data: bool,
}

fn read_uleb128(data: &[u8], pos: &mut usize) -> Option<u64> {
    let mut result = 0u64;
    let mut shift = 0u32;
    loop {
        let byte = *data.get(*pos)?;
        *pos += 1;
        result |= u64::from(byte & 0x7F) << shift;
        if byte & 0x80 == 0 {
            return Some(result);
        }
        shift += 7;
        if shift >= 64 {
            return None;
        }
    }
}

fn read_sleb128(data: &[u8], pos: &mut usize) -> Option<i64> {
    let mut result = 0i64;
    let mut shift = 0u32;
    loop {
        let byte = *data.get(*pos)?;
        *pos += 1;
        result |= i64::from(byte & 0x7F) << shift;
        shift += 7;
        if byte & 0x80 == 0 {
            if shift < 64 && byte & 0x40 != 0 {
                result |= -1i64 << shift;
            }
            return Some(result);
        }
        if shift >= 64 {
            return None;
        }
    }
}

/// Reads a pointer encoded per `DW_EH_PE_*` from `data` at `*pos`.
/// `pc` is the virtual address of the encoded bytes (for pcrel).
fn read_encoded(data: &[u8], pos: &mut usize, encoding: u8, pc: u64) -> Option<u64> {
    if encoding == DW_EH_PE_OMIT {
        return None;
    }
    let value = match encoding & 0x0F {
        0x00 | 0x04 | 0x0C => {
            // absptr / udata8 / sdata8
            let bytes: [u8; 8] = data.get(*pos..*pos + 8)?.try_into().ok()?;
            *pos += 8;
            u64::from_le_bytes(bytes)
        }
        0x01 => read_uleb128(data, pos)?,
        0x02 => {
            let bytes: [u8; 2] = data.get(*pos..*pos + 2)?.try_into().ok()?;
            *pos += 2;
            u64::from(u16::from_le_bytes(bytes))
        }
        0x03 => {
            let bytes: [u8; 4] = data.get(*pos..*pos + 4)?.try_into().ok()?;
            *pos += 4;
            u64::from(u32::from_le_bytes(bytes))
        }
        0x09 => read_sleb128(data, pos)?.cast_unsigned(),
        0x0A => {
            let bytes: [u8; 2] = data.get(*pos..*pos + 2)?.try_into().ok()?;
            *pos += 2;
            i64::from(i16::from_le_bytes(bytes)).cast_unsigned()
        }
        0x0B => {
            let bytes: [u8; 4] = data.get(*pos..*pos + 4)?.try_into().ok()?;
            *pos += 4;
            i64::from(i32::from_le_bytes(bytes)).cast_unsigned()
        }
        _ => return None,
    };
    match encoding & 0x70 {
        0x00 => Some(value),                  // absolute
        0x10 => Some(pc.wrapping_add(value)), // pcrel
        _ => None,                            // datarel/textrel/etc: unsupported here
    }
}

fn parse_cie(record: &[u8]) -> Option<CieInfo> {
    // record starts after the CIE_id field.
    let mut p = 0usize;
    let _version = *record.get(p)?;
    p += 1;
    let aug_start = p;
    while *record.get(p)? != 0 {
        p += 1;
    }
    let aug = &record[aug_start..p];
    p += 1; // NUL
    let _code_align = read_uleb128(record, &mut p)?;
    let _data_align = read_sleb128(record, &mut p)?;
    let _return_reg = read_uleb128(record, &mut p)?;

    let mut info = CieInfo {
        fde_encoding: 0x00, // DW_EH_PE_absptr
        lsda_encoding: None,
        has_aug_data: false,
    };
    if aug.first() == Some(&b'z') {
        info.has_aug_data = true;
        let _aug_len = read_uleb128(record, &mut p)?;
        for &ch in &aug[1..] {
            match ch {
                b'L' => {
                    info.lsda_encoding = Some(*record.get(p)?);
                    p += 1;
                }
                b'P' => {
                    let enc = *record.get(p)?;
                    p += 1;
                    // Skip the personality pointer (pc irrelevant here).
                    read_encoded(record, &mut p, enc, 0)?;
                }
                b'R' => {
                    info.fde_encoding = *record.get(p)?;
                    p += 1;
                }
                _ => return Some(info), // unknown augmentation: stop parsing
            }
        }
    }
    Some(info)
}

/// Scans a byte slice representing an ELF `.eh_frame` section and extracts
/// LSDA references.
///
/// This is a simplified parser that handles `DW_CFA` records up to `CIE`/`FDE`
/// discrimination.  Full DWARF expression parsing is out of scope.
#[must_use]
pub fn mine_lsda_references(eh_frame: &[u8], base: u64) -> Vec<LsdaReference> {
    let mut results = Vec::new();
    let mut cies: std::collections::HashMap<usize, CieInfo> = std::collections::HashMap::new();
    let mut pos = 0usize;

    while pos + 4 <= eh_frame.len() {
        // Length field (u32 LE).
        let length = u32::from_le_bytes([
            eh_frame[pos],
            eh_frame[pos + 1],
            eh_frame[pos + 2],
            eh_frame[pos + 3],
        ]) as usize;

        if length == 0 || length == 0xFFFF_FFFF {
            break; // zero-length terminator (or unsupported 64-bit DWARF format)
        }

        // `length` must cover at least the CIE_id field (4 bytes) that follows
        // the length field itself, i.e. the record body `[pos+8..pos+4+length]`
        // must be non-inverted. A malformed/adversarial length of 1..=3 would
        // otherwise make `pos + 4 + length < pos + 8`, panicking the slice
        // below (start > end).
        if length < 4 || pos + 4 + length > eh_frame.len() || pos + 8 > eh_frame.len() {
            break;
        }

        // CIE_id field (next u32). 0 marks a CIE in .eh_frame.
        let cie_id = u32::from_le_bytes([
            eh_frame[pos + 4],
            eh_frame[pos + 5],
            eh_frame[pos + 6],
            eh_frame[pos + 7],
        ]);

        let record = &eh_frame[pos + 8..pos + 4 + length];

        if cie_id == 0 {
            if let Some(info) = parse_cie(record) {
                cies.insert(pos, info);
            }
        } else {
            // FDE: cie_id is the distance back from this field to the CIE.
            let cie_pos = (pos + 4).checked_sub(cie_id as usize);
            if let Some(cie) = cie_pos.and_then(|cp| cies.get(&cp)) {
                let mut p = 0usize;
                let pc_begin_vaddr = base + (pos + 8) as u64;
                let function_addr = read_encoded(record, &mut p, cie.fde_encoding, pc_begin_vaddr);
                // Skip pc_range (same format, never relative).
                let _ = read_encoded(record, &mut p, cie.fde_encoding & 0x0F, 0);

                if let (Some(function_addr), Some(lsda_encoding), true) =
                    (function_addr, cie.lsda_encoding, cie.has_aug_data)
                    && read_uleb128(record, &mut p).is_some()
                {
                    let lsda_vaddr = base + (pos + 8 + p) as u64;
                    if let Some(lsda_addr) = read_encoded(record, &mut p, lsda_encoding, lsda_vaddr)
                        && lsda_addr != 0
                    {
                        results.push(LsdaReference {
                            function_addr: Address::new(function_addr),
                            lsda_addr: Address::new(lsda_addr),
                            personality_addr: None,
                        });
                    }
                }
            }
        }

        pos += 4 + length;
    }

    results
}

// ─────────────────────────────────────────────────────────────────────────────
// Symbol table reconciliation
// ─────────────────────────────────────────────────────────────────────────────

/// A symbol with address and name, as supplied by the caller from an ELF/PE
/// symbol table, DWARF debug info, or export directory.
#[derive(Debug, Clone)]
pub struct SymbolEntry {
    /// Virtual address of the symbol.
    pub address: Address,
    /// Symbol name (may be mangled).
    pub name: String,
    /// Whether the symbol is a function (vs. data).
    pub is_function: bool,
}

/// Reconciles a detector-produced [`FunctionBoundary`] list with a symbol
/// table, resolving address conflicts and assigning the highest-confidence
/// source for each entry.
pub struct SymbolTableReconciler {
    /// When `true`, function boundaries without a matching symbol are kept.
    pub keep_unmatched: bool,
    /// When `true`, symbols that have no matching detected boundary are
    /// inserted as new boundaries.
    pub insert_new_symbols: bool,
}

impl SymbolTableReconciler {
    /// Create a reconciler that keeps unmatched boundaries and inserts new
    /// symbols.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            keep_unmatched: true,
            insert_new_symbols: true,
        }
    }

    /// Merge `boundaries` with `symbols`, returning a reconciled list.
    #[must_use]
    pub fn reconcile(
        &self,
        mut boundaries: Vec<FunctionBoundary>,
        symbols: &[SymbolEntry],
    ) -> Vec<FunctionBoundary> {
        // Build a map from address to symbol for fast lookup.
        let sym_map: HashMap<u64, &SymbolEntry> = symbols
            .iter()
            .filter(|s| s.is_function)
            .map(|s| (s.address.as_u64(), s))
            .collect();

        // Upgrade existing boundaries that match a symbol.
        let mut matched_addrs: HashSet<u64> = HashSet::new();
        for fb in &mut boundaries {
            if let Some(sym) = sym_map.get(&fb.start.as_u64()) {
                fb.confidence = Confidence::Certain;
                fb.source = DetectionSource::SymbolTable;
                if fb.name.is_none() {
                    fb.name = Some(sym.name.clone());
                }
                matched_addrs.insert(fb.start.as_u64());
            }
        }

        // Insert new symbols that had no matching boundary.
        if self.insert_new_symbols {
            for sym in symbols.iter().filter(|s| s.is_function) {
                if !matched_addrs.contains(&sym.address.as_u64()) {
                    boundaries.push(
                        FunctionBoundary::new(
                            sym.address,
                            Confidence::Certain,
                            DetectionSource::SymbolTable,
                        )
                        .with_name(sym.name.clone()),
                    );
                }
            }
        }

        // Remove zero-confidence (unmatched) entries if configured.
        if !self.keep_unmatched {
            boundaries.retain(|fb| fb.confidence == Confidence::Certain);
        }

        // Sort by address for deterministic output.
        boundaries.sort_by_key(|fb| fb.start.as_u64());
        boundaries
    }
}

impl Default for SymbolTableReconciler {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tail-call merging detector
// ─────────────────────────────────────────────────────────────────────────────

/// Result of tail-call merging analysis for a single function site.
#[derive(Debug, Clone)]
pub struct TailCallSite {
    /// Address of the `JMP` that replaces the `CALL; RET` pair.
    pub jmp_addr: Address,
    /// Computed target of the tail call.
    pub callee_addr: Address,
    /// Address of the function containing this site.
    pub caller_addr: Address,
}

/// Detects tail-call optimisations in x86-64 code.
///
/// A tail call is a `JMP` to another function at the end of a basic block
/// (i.e., the jump is not within the same function's address range and is
/// preceded by code that looks like a function body).
pub struct TailCallDetector {
    /// Addresses of known function starts — used to decide whether a JMP
    /// crosses function boundaries.
    pub known_functions: HashSet<u64>,
}

impl TailCallDetector {
    /// Create a detector seeded with a set of known function start addresses.
    #[must_use]
    pub fn new(known_functions: impl IntoIterator<Item = u64>) -> Self {
        Self {
            known_functions: known_functions.into_iter().collect(),
        }
    }

    /// Scan `mem` for tail calls, attributing each to `caller_start`.
    #[must_use]
    pub fn scan(
        &self,
        mem: &MemorySlice<'_>,
        caller_start: Address,
        caller_end: Address,
    ) -> Vec<TailCallSite> {
        let mut results = Vec::new();
        let bytes = mem.bytes;
        let base = mem.base.as_u64();

        let func_start =
            usize::try_from(caller_start.as_u64().saturating_sub(base)).unwrap_or(usize::MAX);
        let func_end = usize::try_from(caller_end.as_u64().saturating_sub(base))
            .unwrap_or(usize::MAX)
            .min(bytes.len());

        let mut i = func_start;
        while i + 5 <= func_end {
            // JMP rel32 (E9) that lands outside the current function.
            if bytes[i] == 0xE9 {
                let disp =
                    i32::from_le_bytes([bytes[i + 1], bytes[i + 2], bytes[i + 3], bytes[i + 4]]);
                let next_pc = base.wrapping_add(i as u64).wrapping_add(5);
                let target = u64::from_ne_bytes(
                    (i64::from_ne_bytes(next_pc.to_ne_bytes()).wrapping_add(i64::from(disp)))
                        .to_ne_bytes(),
                );

                let in_caller = target >= caller_start.as_u64() && target < caller_end.as_u64();
                let is_known_fn = self.known_functions.contains(&target);

                if !in_caller && is_known_fn {
                    results.push(TailCallSite {
                        jmp_addr: Address::new(base + i as u64),
                        callee_addr: Address::new(target),
                        caller_addr: caller_start,
                    });
                }
                i += 5;
                continue;
            }

            i += 1;
        }

        results
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// GCC cold-function prologue scanner
// ─────────────────────────────────────────────────────────────────────────────

/// Detects GCC cold functions — functions placed in `.text.unlikely` or emitted with
/// `__attribute__((cold))`.
///
/// These often begin with a `UD2` instruction (`0F 0B`) or a bare `PUSH rbp` at an
/// unexpected alignment within a cold section.
#[derive(Debug, Clone)]
pub struct ColdFunctionHit {
    /// Address of the detected cold function entry.
    pub addr: Address,
    /// Byte that triggered detection (`0x0F 0x0B` for UD2, `0x55` for bare push-rbp).
    pub trigger_byte: u8,
}

/// Scan `mem` for cold-function entry patterns.
#[must_use]
pub fn scan_cold_functions(mem: &MemorySlice<'_>) -> Vec<ColdFunctionHit> {
    let mut results = Vec::new();
    let bytes = mem.bytes;
    let base = mem.base.as_u64();
    let len = bytes.len();

    let mut i = 0usize;
    while i < len {
        // UD2 (0F 0B) — often placed at the start of unreachable cold paths.
        if i + 1 < len && bytes[i] == 0x0F && bytes[i + 1] == 0x0B {
            results.push(ColdFunctionHit {
                addr: Address::new(base + i as u64),
                trigger_byte: 0x0F,
            });
            i += 2;
            continue;
        }

        // Bare push rbp (55) at 16-byte alignment in a cold section.
        if bytes[i] == 0x55 && i.is_multiple_of(16) {
            results.push(ColdFunctionHit {
                addr: Address::new(base + i as u64),
                trigger_byte: 0x55,
            });
        }

        i += 1;
    }

    results
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use rustre_core::address::Address;

    #[test]
    fn thunk_detector_finds_jmp_rel32() {
        // JMP rel32 with displacement 0 → target = base + 5
        let code: &[u8] = &[0xE9, 0x00, 0x00, 0x00, 0x00, 0x90, 0x90, 0x90];
        let mem = MemorySlice::new(Address::new(0x1000), code);
        let det = ThunkDetector::new();
        let thunks = det.scan(&mem);
        assert!(!thunks.is_empty(), "expected thunk hit");
        assert_eq!(thunks[0].target_addr, Address::new(0x1005));
        assert!(!thunks[0].is_indirect);
    }

    #[test]
    fn thunk_detector_finds_indirect_jmp() {
        // JMP [RIP+0] → target is next_pc (0x1006)
        let code: &[u8] = &[0xFF, 0x25, 0x00, 0x00, 0x00, 0x00, 0xCC];
        let mem = MemorySlice::new(Address::new(0x1000), code);
        let det = ThunkDetector::new();
        let thunks = det.scan(&mem);
        assert!(!thunks.is_empty());
        assert!(thunks[0].is_indirect);
        assert_eq!(thunks[0].target_addr, Address::new(0x1006)); // RIP+6+0
    }

    #[test]
    fn plt_scanner_detects_entry() {
        // Minimal PLT entry: FF 25 (6 bytes) + 68 00 00 00 00 + E9 00 00 00 00
        let mut code = vec![0x90u8; 16];
        code[0] = 0xFF;
        code[1] = 0x25;
        code[2] = 0x00;
        code[3] = 0x00;
        code[4] = 0x00;
        code[5] = 0x00;
        code[6] = 0x68;
        code[7] = 0x00;
        code[8] = 0x00;
        code[9] = 0x00;
        code[10] = 0x00;
        let mem = MemorySlice::new(Address::new(0x2000), &code);
        let scanner = PltScanner::new();
        let entries = scanner.scan(&mem);
        assert!(!entries.is_empty(), "expected PLT entry");
        assert_eq!(entries[0].reloc_index, Some(0));
    }

    #[test]
    fn pdata_records_parsed() {
        // One RUNTIME_FUNCTION record: begin=0x1000, end=0x2000, handler=0x3000
        let mut pdata = vec![0u8; 12];
        pdata[0..4].copy_from_slice(&0x1000u32.to_le_bytes());
        pdata[4..8].copy_from_slice(&0x2000u32.to_le_bytes());
        pdata[8..12].copy_from_slice(&0x3000u32.to_le_bytes());
        let entries = parse_pdata_records(&pdata, 0);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].function_start, Address::new(0x1000));
        assert_eq!(entries[0].function_end, Address::new(0x2000));
    }

    #[test]
    fn symbol_reconciler_upgrades_existing() {
        let boundaries = vec![FunctionBoundary::new(
            Address::new(0x4000),
            Confidence::Low,
            DetectionSource::HeuristicGap,
        )];
        let symbols = vec![SymbolEntry {
            address: Address::new(0x4000),
            name: "foo".into(),
            is_function: true,
        }];
        let rec = SymbolTableReconciler::new();
        let result = rec.reconcile(boundaries, &symbols);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].confidence, Confidence::Certain);
        assert_eq!(result[0].name.as_deref(), Some("foo"));
    }

    #[test]
    fn symbol_reconciler_inserts_new() {
        let boundaries = Vec::new();
        let symbols = vec![SymbolEntry {
            address: Address::new(0x5000),
            name: "bar".into(),
            is_function: true,
        }];
        let rec = SymbolTableReconciler::new();
        let result = rec.reconcile(boundaries, &symbols);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].start, Address::new(0x5000));
    }

    #[test]
    fn pic_detector_finds_call_pop() {
        // E8 00 00 00 00  5B (pop ebx)
        let code: &[u8] = &[0xE8, 0x00, 0x00, 0x00, 0x00, 0x5B, 0xC3];
        let mem = MemorySlice::new(Address::new(0x3000), code);
        let det = PicPrologueDetector::new();
        let hits = det.scan(&mem);
        assert!(!hits.is_empty(), "expected PIC thunk detection");
    }

    #[test]
    fn cold_function_scan_finds_ud2() {
        let code: &[u8] = &[0x0F, 0x0B, 0x90, 0x90];
        let mem = MemorySlice::new(Address::new(0x6000), code);
        let hits = scan_cold_functions(&mem);
        assert!(!hits.is_empty());
        assert_eq!(hits[0].addr, Address::new(0x6000));
    }

    // Regression: `entry_alignment == 0` is a malformed but reachable config
    // (the field is public) that previously caused a modulo-by-zero panic /
    // an infinite loop (since `i` never advances when `alignment == 0`).
    #[test]
    fn plt_scanner_zero_alignment_does_not_panic_or_hang() {
        let code = vec![0x90u8; 32];
        let mem = MemorySlice::new(Address::new(0x2000), &code);
        let scanner = PltScanner {
            entry_alignment: 0,
            max_entries: 4096,
        };
        let entries = scanner.scan(&mem);
        assert!(entries.is_empty());
    }

    #[test]
    fn plt_scanner_empty_input() {
        let mem = MemorySlice::new(Address::new(0x2000), &[]);
        let scanner = PltScanner::new();
        assert!(scanner.scan(&mem).is_empty());
    }

    #[test]
    fn thunk_detector_empty_input() {
        let mem = MemorySlice::new(Address::new(0x1000), &[]);
        let det = ThunkDetector::new();
        assert!(det.scan(&mem).is_empty());
    }

    #[test]
    fn pic_detector_empty_input() {
        let mem = MemorySlice::new(Address::new(0x1000), &[]);
        let det = PicPrologueDetector::new();
        assert!(det.scan(&mem).is_empty());
    }

    #[test]
    fn cold_function_scan_empty_input() {
        let mem = MemorySlice::new(Address::new(0x1000), &[]);
        assert!(scan_cold_functions(&mem).is_empty());
    }

    #[test]
    fn pdata_records_truncated_trailing_bytes_ignored() {
        // 12-byte record followed by 5 stray bytes (not a full record).
        let mut pdata = vec![0u8; 17];
        pdata[0..4].copy_from_slice(&0x1000u32.to_le_bytes());
        pdata[4..8].copy_from_slice(&0x2000u32.to_le_bytes());
        pdata[8..12].copy_from_slice(&0x3000u32.to_le_bytes());
        let entries = parse_pdata_records(&pdata, 0);
        assert_eq!(entries.len(), 1);
    }

    #[test]
    fn pdata_records_empty_input() {
        assert!(parse_pdata_records(&[], 0).is_empty());
    }

    #[test]
    fn mine_lsda_references_garbage_input_does_not_panic() {
        // Random bytes that are not a valid .eh_frame stream; must not panic.
        let garbage = [0xFFu8; 64];
        let refs = mine_lsda_references(&garbage, 0);
        assert!(refs.is_empty());
    }

    #[test]
    fn mine_lsda_references_empty_input() {
        assert!(mine_lsda_references(&[], 0).is_empty());
    }

    #[test]
    fn mine_lsda_references_short_length_field_does_not_panic() {
        // A record with a `length` field of 1..=3 makes `pos + 4 + length`
        // land *before* `pos + 8`, which used to invert the slice range
        // `[pos+8..pos+4+length]` and panic. Regression test for that.
        for bad_length in 1u32..=3 {
            let mut eh_frame = Vec::new();
            eh_frame.extend_from_slice(&bad_length.to_le_bytes());
            // Padding so `pos + 8 <= eh_frame.len()` (the other bounds check
            // passes) while `length` itself is still too small.
            eh_frame.extend_from_slice(&[0u8; 16]);
            let refs = mine_lsda_references(&eh_frame, 0);
            assert!(refs.is_empty());
        }
    }

    #[test]
    fn tail_call_detector_empty_range() {
        let code: &[u8] = &[0x90, 0x90];
        let mem = MemorySlice::new(Address::new(0x1000), code);
        let det = TailCallDetector::new([]);
        let sites = det.scan(&mem, Address::new(0x1000), Address::new(0x1000));
        assert!(sites.is_empty());
    }

    #[test]
    fn tail_call_detector_finds_known_target() {
        // JMP rel32 to 0x2000 at 0x1000, disp = 0x2000 - (0x1000+5) = 0x0FFB
        let mut code = vec![0x90u8; 5];
        code[0] = 0xE9;
        let disp = 0x2000i64 - (0x1000i64 + 5);
        code[1..5].copy_from_slice(&(disp as i32).to_le_bytes());
        let mem = MemorySlice::new(Address::new(0x1000), &code);
        let det = TailCallDetector::new([0x2000u64]);
        let sites = det.scan(&mem, Address::new(0x1000), Address::new(0x1005));
        assert_eq!(sites.len(), 1);
        assert_eq!(sites[0].callee_addr, Address::new(0x2000));
    }

    #[test]
    fn symbol_reconciler_keep_unmatched_false_drops_unmatched() {
        let boundaries = vec![FunctionBoundary::new(
            Address::new(0x7000),
            Confidence::Low,
            DetectionSource::HeuristicGap,
        )];
        let rec = SymbolTableReconciler {
            keep_unmatched: false,
            insert_new_symbols: false,
        };
        let result = rec.reconcile(boundaries, &[]);
        assert!(result.is_empty());
    }
}
