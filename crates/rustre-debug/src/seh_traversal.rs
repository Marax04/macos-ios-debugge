//! `seh_traversal` — x64 Structured Exception Handling (SEH) / `.pdata` parser.
//!
//! Walks the PE `.pdata` section (array of `RUNTIME_FUNCTION` records) to
//! enumerate all exception handler registrations, decodes each `UNWIND_INFO`
//! block (prolog codes, chained unwind, and the optional exception handler /
//! filter function pointer), and builds a searchable `SehIndex`.
//!
//! ## vs WinDbg / IDA Pro
//! WinDbg exposes `.fnent <addr>` (one function at a time) and IDA shows the
//! parsed SEH handlers in a window, both requiring the binary to be opened.
//! This module extracts the full handler graph from raw PE bytes, offline,
//! and returns it as a queryable index for LLM tool-calls — enabling questions
//! like "which functions have `__except` filters near address X?" that neither
//! tool answers in batch form.

use std::collections::BTreeMap;
use thiserror::Error;

/// Errors produced by the SEH parser.
#[derive(Debug, Error)]
pub enum SehError {
    #[error("buffer too small: need at least {need} bytes at offset {offset:#x}")]
    TooSmall { offset: usize, need: usize },
    #[error("invalid UNWIND_INFO version {0} at offset {1:#x}")]
    BadVersion(u8, usize),
    #[error("chained unwind depth exceeded limit")]
    ChainTooDeep,
    #[error(".pdata section not found in PE image")]
    NoPdata,
    /// The image is not x64. `.pdata` exists on other architectures but with a
    /// different `RUNTIME_FUNCTION` layout (arm64 uses 8-byte records, not 12),
    /// so decoding it with these routines would fabricate entries rather than
    /// fail.
    #[error("unsupported machine {0:#06x}: this .pdata parser decodes the x64 layout only")]
    UnsupportedMachine(u16),
}

/// Which `RUNTIME_FUNCTION` layout a `.pdata` section uses.
///
/// `.pdata` is not x64-only, but its record layout is architecture-specific.
/// Decoding one architecture's table with the other's stride does not fail: it
/// silently fabricates entries (or, as measured, drops every real one), so the
/// stride is a parameter rather than a constant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PdataFormat {
    /// x86-64: 12-byte records — `BeginAddress`, `EndAddress`, `UnwindInfoAddress`.
    X64,
    /// AArch64: 8-byte records — `BeginAddress`, `UnwindData`.
    Arm64,
}

impl PdataFormat {
    /// Size in bytes of one `RUNTIME_FUNCTION` record in this format.
    #[must_use]
    pub const fn record_size(self) -> usize {
        match self {
            Self::X64 => 12,
            Self::Arm64 => 8,
        }
    }

    /// Map a PE COFF `Machine` value to the `.pdata` layout it implies.
    ///
    /// Returns `None` for every other machine (x86, ARM32, IA64, …) — those
    /// either have no `.pdata` or a layout this module does not decode.
    #[must_use]
    pub fn from_machine(machine: u16) -> Option<Self> {
        match machine {
            0x8664 => Some(Self::X64),
            0xAA64 => Some(Self::Arm64),
            _ => None,
        }
    }
}

/// Decoded ARM64 *packed* unwind data (the `UnwindData` DWORD of an ARM64
/// `RUNTIME_FUNCTION` when its low two bits are non-zero).
///
/// Field layout per the ARM64 exception-handling specification, section
/// "Packed unwind data": bits 0-1 `Flag`, 2-12 `FunctionLength` (in 4-byte
/// units), 13-15 `RegF`, 16-19 `RegI`, 20 `H`, 21-22 `CR`, 23-31 `FrameSize`
/// (in 16-byte units). Both scaled fields are converted to **bytes** here —
/// leaving them in their native units is the invisible unit bug this type
/// exists to prevent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Arm64PackedUnwind {
    /// `Flag`: 1 = packed, 2 = packed fragment.
    pub flag: u8,
    /// Function length in **bytes** (`FunctionLength` × 4).
    pub function_length: u32,
    /// Number of non-volatile FP registers saved (`RegF`).
    pub reg_f: u8,
    /// Number of non-volatile integer registers saved (`RegI`).
    pub reg_i: u8,
    /// `H`: the function homes its incoming register parameters.
    pub homes_params: bool,
    /// `CR`: chained-return/frame-chain flags (raw 2-bit field).
    pub cr: u8,
    /// Frame size in **bytes** (`FrameSize` × 16).
    pub frame_size: u32,
    /// The undecoded DWORD, kept so callers can re-check anything this
    /// struct does not model.
    pub raw: u32,
}

/// Decode an ARM64 `UnwindData` DWORD as packed unwind information.
///
/// Returns `None` when the low two bits are zero — that is not packed data at
/// all, it is an RVA pointing into `.xdata`.
#[must_use]
pub fn decode_arm64_packed(unwind_data: u32) -> Option<Arm64PackedUnwind> {
    let flag = (unwind_data & 0b11) as u8;
    if flag == 0 {
        return None;
    }
    Some(Arm64PackedUnwind {
        flag,
        function_length: ((unwind_data >> 2) & 0x7FF) * 4,
        reg_f: ((unwind_data >> 13) & 0x7) as u8,
        reg_i: ((unwind_data >> 16) & 0xF) as u8,
        homes_params: (unwind_data >> 20) & 1 != 0,
        cr: ((unwind_data >> 21) & 0x3) as u8,
        frame_size: ((unwind_data >> 23) & 0x1FF) * 16,
        raw: unwind_data,
    })
}

// ── UNWIND_INFO constants (from winnt.h) ─────────────────────────────────────

const UNW_FLAG_NHANDLER: u8 = 0x00;
const UNW_FLAG_EHANDLER: u8 = 0x01;
const UNW_FLAG_UHANDLER: u8 = 0x02;
const UNW_FLAG_FHANDLER: u8 = 0x03; // filter + handler (not in MSDN but used)
const UNW_FLAG_CHAININFO: u8 = 0x04;

// ── data model ───────────────────────────────────────────────────────────────

/// What kind of handler (if any) is declared by an `UNWIND_INFO`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum HandlerKind {
    /// No handler — purely used for unwinding.
    None,
    /// `__except` — exception handler (runs handler, does NOT re-execute
    /// the faulting instruction; it receives the full `EXCEPTION_POINTERS`).
    ExceptionHandler,
    /// `__finally` / termination handler.
    TerminationHandler,
    /// Both exception filter and handler (some compilers combine them).
    FilterAndHandler,
    /// Chained to another `RUNTIME_FUNCTION` — no handler here.
    Chained,
}

impl std::fmt::Display for HandlerKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::None => write!(f, "none"),
            Self::ExceptionHandler => write!(f, "__except"),
            Self::TerminationHandler => write!(f, "__finally"),
            Self::FilterAndHandler => write!(f, "__except+__finally"),
            Self::Chained => write!(f, "chained"),
        }
    }
}

/// A single prolog unwind operation decoded from the `UNWIND_CODE` array.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct UnwindCode {
    /// Byte offset in the function prolog where this operation occurs.
    pub prolog_offset: u8,
    /// Raw operation code (bits `[3:0]` of the second byte).
    pub op_code: u8,
    /// Raw info nibble (bits `[7:4]` of the second byte).
    pub op_info: u8,
}

/// Parsed `UNWIND_INFO` for one `RUNTIME_FUNCTION`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct UnwindInfo {
    /// File offset of the `UNWIND_INFO` structure.
    pub offset: u32,
    /// UNWIND_INFO version (must be 1).
    pub version: u8,
    /// Raw flags byte (bits `[7:3]`).
    pub flags: u8,
    /// Size of the function prolog in bytes.
    pub size_of_prolog: u8,
    /// Frame register (0 = RSP relative; non-zero = register number).
    pub frame_register: u8,
    /// Frame register offset (scaled by 16).
    pub frame_offset: u8,
    /// Decoded unwind codes (may be empty when flags = CHAININFO).
    pub codes: Vec<UnwindCode>,
    /// What kind of handler is registered.
    pub handler_kind: HandlerKind,
    /// RVA of the language-specific exception/termination handler, if any.
    pub handler_rva: Option<u32>,
    /// RVA of the chained `RUNTIME_FUNCTION`, if `handler_kind == Chained`.
    pub chained_function_rva: Option<u32>,
}

/// One function's complete SEH record.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SehEntry {
    /// RVA of the first byte of the function.
    pub begin_address: u32,
    /// RVA of the byte after the last byte of the function.
    pub end_address: u32,
    /// Decoded `UNWIND_INFO` (may be a chain of entries when chained).
    pub unwind_chain: Vec<UnwindInfo>,
    /// ARM64 only: RVA of this function's `.xdata` `UNWIND_INFO` record, when
    /// the record used the non-packed form. That structure (32-bit header,
    /// epilog scopes, variable-length unwind codes) is **not** decoded by this
    /// module, so the RVA is surfaced instead of being silently dropped —
    /// half-decoding it would be worse than not decoding it.
    #[serde(default)]
    pub xdata_rva: Option<u32>,
    /// ARM64 only: the decoded packed unwind data, when the record used the
    /// packed form.
    #[serde(default)]
    pub arm64_packed: Option<Arm64PackedUnwind>,
}

impl SehEntry {
    /// Return the effective exception-handler RVA if any entry in the chain
    /// has one.
    #[must_use]
    pub fn exception_handler_rva(&self) -> Option<u32> {
        self.unwind_chain
            .iter()
            .find(|u| {
                matches!(
                    u.handler_kind,
                    HandlerKind::ExceptionHandler | HandlerKind::FilterAndHandler
                )
            })
            .and_then(|u| u.handler_rva)
    }

    /// Returns `true` if this function registers any exception handler.
    #[must_use]
    pub fn has_exception_handler(&self) -> bool {
        self.exception_handler_rva().is_some()
    }

    /// Whether this entry's length is actually known.
    ///
    /// `false` for an ARM64 non-packed record, whose length lives in an
    /// `.xdata` structure this module does not decode.
    #[must_use]
    pub const fn extent_is_known(&self) -> bool {
        self.end_address > self.begin_address
    }
}

/// What a [`SehIndex`] knows about a given RVA.
#[derive(Debug, Clone, Copy)]
pub enum Coverage<'a> {
    /// An entry provably covers this address.
    Contains(&'a SehEntry),
    /// The nearest preceding entry may or may not cover this address: its
    /// length is recorded nowhere this module decodes (ARM64 `.xdata`). The
    /// entry is returned because it is still the caller's best lead — its
    /// `xdata_rva` is where the real length lives.
    ExtentUnknown(&'a SehEntry),
    /// No entry begins at or before this address.
    None,
}

/// Searchable index built from a PE's `.pdata` section.
#[derive(Debug, Default, Clone, serde::Serialize, serde::Deserialize)]
pub struct SehIndex {
    /// All entries sorted by `begin_address`.
    pub entries: Vec<SehEntry>,
    /// RVA → entry index for O(log n) lookup by function start.
    by_rva: BTreeMap<u32, usize>,
}

impl SehIndex {
    /// Look up the `SehEntry` for the function that starts at `rva`.
    #[must_use]
    pub fn by_begin_rva(&self, rva: u32) -> Option<&SehEntry> {
        self.by_rva.get(&rva).map(|&i| &self.entries[i])
    }

    /// Return the `SehEntry` that provably contains `rva`.
    ///
    /// `None` means "no entry is known to cover this address" — which on an
    /// ARM64 image is NOT the same as "there is no entry here". Use
    /// [`Self::coverage`] when that distinction matters.
    #[must_use]
    pub fn containing(&self, rva: u32) -> Option<&SehEntry> {
        match self.coverage(rva) {
            Coverage::Contains(e) => Some(e),
            Coverage::ExtentUnknown(_) | Coverage::None => None,
        }
    }

    /// Classify what this index knows about `rva`.
    ///
    /// The ARM64 non-packed path deliberately leaves `end_address ==
    /// begin_address`, because the real length lives in an `.xdata` record
    /// this module does not decode — "unknown, not guessed", and rightly so.
    /// But `containing()` then answered `None` for those functions, including
    /// for their own entry point, and `None` reads as "this address has no
    /// unwind information at all". On an ARM64 image the entry — and its
    /// `.xdata` RVA, the thing a caller needs next — was sitting right there.
    ///
    /// Unknown extent is now its own answer, and the exact begin address is
    /// always `Contains`: a function provably contains its own first byte.
    #[must_use]
    pub fn coverage(&self, rva: u32) -> Coverage<'_> {
        let Some((&begin, &idx)) = self.by_rva.range(..=rva).next_back() else {
            return Coverage::None;
        };
        let entry = &self.entries[idx];
        if entry.extent_is_known() {
            if rva < entry.end_address {
                Coverage::Contains(entry)
            } else {
                Coverage::None
            }
        } else if rva == begin {
            Coverage::Contains(entry)
        } else {
            Coverage::ExtentUnknown(entry)
        }
    }

    /// All entries that register an exception handler.
    #[must_use]
    pub fn entries_with_handler(&self) -> Vec<&SehEntry> {
        self.entries
            .iter()
            .filter(|e| e.has_exception_handler())
            .collect()
    }

    /// Number of functions in the index.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` if the index is empty (no `.pdata` entries).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

// ── parser ───────────────────────────────────────────────────────────────────

/// Read a `u32` little-endian from `data[offset..]`.
fn read_u32(data: &[u8], offset: usize) -> Result<u32, SehError> {
    let end = offset + 4;
    if end > data.len() {
        return Err(SehError::TooSmall { offset, need: 4 });
    }
    Ok(u32::from_le_bytes(data[offset..end].try_into().unwrap()))
}

/// Longest `UNW_FLAG_CHAININFO` chain followed before giving up. Real chains
/// are one or two links; anything longer is malformed or hostile input.
const MAX_CHAIN_DEPTH: usize = 8;

/// Find the `UnwindInfoAddress` of the RUNTIME_FUNCTION whose `BeginAddress`
/// is `target_rva`, scanning the `.pdata` table directly.
///
/// A linear scan on purpose: this runs only while resolving a chain (one or
/// two links, on the minority of functions that are split), and it avoids
/// having to build and thread an index through `parse_pdata`'s main loop while
/// that same index is still being populated.
fn find_runtime_function(
    image_bytes: &[u8],
    pdata_file_offset: usize,
    entry_count: usize,
    target_rva: u32,
    format: PdataFormat,
) -> Option<u32> {
    for i in 0..entry_count {
        let base = pdata_file_offset + i * format.record_size();
        if read_u32(image_bytes, base).ok()? == target_rva {
            return read_u32(image_bytes, base + 8).ok();
        }
    }
    None
}

/// Parse `UNWIND_INFO` at file offset `file_offset` within `image_bytes`.
///
/// `depth` tracks chained-unwind depth to guard against cycles.
fn parse_unwind_info(
    image_bytes: &[u8],
    file_offset: usize,
    depth: u8,
) -> Result<Vec<UnwindInfo>, SehError> {
    if depth > 8 {
        return Err(SehError::ChainTooDeep);
    }
    if file_offset + 4 > image_bytes.len() {
        return Err(SehError::TooSmall { offset: file_offset, need: 4 });
    }
    let byte0 = image_bytes[file_offset];
    let byte1 = image_bytes[file_offset + 1];
    let byte2 = image_bytes[file_offset + 2];
    let byte3 = image_bytes[file_offset + 3];

    let version = byte0 & 0x07;
    if version != 1 {
        return Err(SehError::BadVersion(version, file_offset));
    }
    let flags = (byte0 >> 3) & 0x1F;
    let size_of_prolog = byte1;
    let count_of_codes = byte2;
    let frame_register = byte3 & 0x0F;
    let frame_offset = (byte3 >> 4) & 0x0F;

    // UNWIND_CODE array: 2 bytes per slot, but some ops consume extra slots.
    let codes_start = file_offset + 4;
    let codes_end = codes_start + (count_of_codes as usize) * 2;
    if codes_end > image_bytes.len() {
        return Err(SehError::TooSmall { offset: codes_start, need: count_of_codes as usize * 2 });
    }

    let mut codes = Vec::with_capacity(count_of_codes as usize);
    let mut i = 0usize;
    while i < count_of_codes as usize {
        let code_off = codes_start + i * 2;
        let prolog_offset = image_bytes[code_off];
        let op_byte = image_bytes[code_off + 1];
        let op_code = op_byte & 0x0F;
        let op_info = (op_byte >> 4) & 0x0F;
        codes.push(UnwindCode { prolog_offset, op_code, op_info });
        // Some op codes consume additional slots (UWOP_ALLOC_LARGE, etc.)
        let extra_slots = match op_code {
            1 => { // UWOP_ALLOC_LARGE: 1 extra if op_info==0, 2 if op_info==1
                if op_info == 0 { 1 } else { 2 }
            }
            // UWOP_SAVE_NONVOL, UWOP_SAVE_XMM128: 1 extra slot
            4 | 8 => 1,
            // UWOP_SAVE_NONVOL_FAR, UWOP_SAVE_XMM128_FAR: 2 extra slots
            5 | 9 => 2,
            _ => 0,
        };
        i += 1 + extra_slots;
    }

    // The optional handler / chained info follows the codes array, aligned to
    // 4 bytes from the start of UNWIND_INFO.
    // Slot count is always rounded up to even, then the DWORD follows.
    let handler_slot_start = codes_start + (((count_of_codes as usize) + 1) & !1) * 2;

    let (handler_kind, handler_rva, chained_function_rva) = if flags == UNW_FLAG_CHAININFO {
        // Chained: the "handler" DWORD is actually the begin_address of the
        // parent RUNTIME_FUNCTION (but we store it as an RVA for callers).
        let chain_rf_rva = if handler_slot_start + 4 <= image_bytes.len() {
            Some(read_u32(image_bytes, handler_slot_start)?)
        } else {
            None
        };
        (HandlerKind::Chained, None, chain_rf_rva)
    } else if flags == UNW_FLAG_NHANDLER {
        (HandlerKind::None, None, None)
    } else {
        let h_rva = if handler_slot_start + 4 <= image_bytes.len() {
            Some(read_u32(image_bytes, handler_slot_start)?)
        } else {
            None
        };
        let kind = match flags {
            UNW_FLAG_EHANDLER => HandlerKind::ExceptionHandler,
            UNW_FLAG_UHANDLER => HandlerKind::TerminationHandler,
            UNW_FLAG_FHANDLER => HandlerKind::FilterAndHandler,
            _ => HandlerKind::ExceptionHandler, // treat unknown as __except
        };
        (kind, h_rva, None)
    };

    let mut result = vec![UnwindInfo {
        offset: file_offset as u32,
        version,
        flags,
        size_of_prolog,
        frame_register,
        frame_offset,
        codes,
        handler_kind,
        handler_rva,
        chained_function_rva,
    }];

    // Recurse into chained UNWIND_INFO (chained_function_rva is the
    // begin_address of the parent RF; we'd need the original pdata to look up
    // the RF and its UnwindInfoAddress — handled by the caller layer).
    // For now we don't recurse because we need the pdata table; chaining is
    // resolved in `parse_pdata` below.
    let _ = depth; // suppress unused warning
    Ok(result)
}

/// Parse the full `.pdata` section from a raw PE image loaded at its preferred
/// base (or a rebased buffer), building an [`SehIndex`].
///
/// `pdata_file_offset` and `pdata_size` describe the `.pdata` section's
/// position within `image_bytes` (file offsets, not virtual addresses).
/// `image_base` is the image base (for converting RVAs to file offsets —
/// simplified: assumes sections are not re-aligned for in-memory mapping,
/// i.e. file offset == RVA for flat in-file buffers loaded without VA bias).
///
/// For a real PE loaded via `ReadProcessMemory` where file offset == VA - image_base,
/// pass `rva_to_file_offset = |rva| rva as usize`.
///
/// `format` selects the `RUNTIME_FUNCTION` stride and field layout — see
/// [`PdataFormat`].
pub fn parse_pdata<F>(
    image_bytes: &[u8],
    pdata_file_offset: usize,
    pdata_size: usize,
    format: PdataFormat,
    rva_to_file_offset: F,
) -> Result<SehIndex, SehError>
where
    F: Fn(u32) -> usize,
{
    if pdata_file_offset + pdata_size > image_bytes.len() {
        return Err(SehError::TooSmall {
            offset: pdata_file_offset,
            need: pdata_size,
        });
    }

    let entry_count = pdata_size / format.record_size();
    let mut entries = Vec::with_capacity(entry_count);
    let mut by_rva: BTreeMap<u32, usize> = BTreeMap::new();

    if format == PdataFormat::Arm64 {
        for i in 0..entry_count {
            let base = pdata_file_offset + i * PdataFormat::Arm64.record_size();
            let begin_address = read_u32(image_bytes, base)?;
            let unwind_data = read_u32(image_bytes, base + 4)?;

            // The entry EXISTS either way; only the amount that can be said
            // about it differs. Recording nothing (what the x64 path did after
            // mis-striding) is what produced an empty index on real ARM64
            // images.
            let (end_address, xdata_rva, arm64_packed) = match decode_arm64_packed(unwind_data) {
                Some(p) => (begin_address.wrapping_add(p.function_length), None, Some(p)),
                // Non-packed: `unwind_data` is an RVA into `.xdata`. The real
                // function length lives in that record, which this module does
                // not decode, so the end address stays unknown rather than
                // guessed.
                None => (begin_address, Some(unwind_data), None),
            };

            let idx = entries.len();
            entries.push(SehEntry {
                begin_address,
                end_address,
                unwind_chain: Vec::new(),
                xdata_rva,
                arm64_packed,
            });
            by_rva.insert(begin_address, idx);
        }
        return Ok(SehIndex { entries, by_rva });
    }

    for i in 0..entry_count {
        let base = pdata_file_offset + i * format.record_size();
        let begin_address = read_u32(image_bytes, base)?;
        let end_address = read_u32(image_bytes, base + 4)?;
        let unwind_info_address = read_u32(image_bytes, base + 8)?;

        // Lowest bit set == this is a packed unwind description (leaf functions,
        // no frame pointer). Skip — no handler possible.
        if unwind_info_address & 1 != 0 {
            continue;
        }

        let ui_file_offset = rva_to_file_offset(unwind_info_address);
        let mut unwind_chain = match parse_unwind_info(image_bytes, ui_file_offset, 0) {
            Ok(chain) => chain,
            Err(_) => continue, // skip malformed entries gracefully
        };

        // Follow UNW_FLAG_CHAININFO: the entry's real unwind codes and handler
        // live in another RUNTIME_FUNCTION (how MSVC encodes hot/cold split
        // functions). `parse_unwind_info` cannot do this itself — it has no
        // access to the .pdata table needed to turn a BeginAddress into an
        // UnwindInfoAddress — so it records the parent's RVA and stops here.
        //
        // `seen` bounds the walk on genuinely malformed or hostile input: a
        // chain that loops would otherwise spin forever, and `depth` alone
        // would not catch a two-node cycle within the limit.
        let mut seen = vec![begin_address];
        while let Some(parent_rva) =
            unwind_chain.last().and_then(|u| u.chained_function_rva)
        {
            if seen.contains(&parent_rva) || seen.len() > MAX_CHAIN_DEPTH {
                break;
            }
            seen.push(parent_rva);
            let Some(parent) = find_runtime_function(image_bytes, pdata_file_offset, entry_count, parent_rva, format)
            else {
                break;
            };
            if parent & 1 != 0 {
                break; // packed unwind data: nothing further to parse
            }
            match parse_unwind_info(image_bytes, rva_to_file_offset(parent), 0) {
                Ok(next) => unwind_chain.extend(next),
                Err(_) => break,
            }
        }

        let idx = entries.len();
        entries.push(SehEntry {
            begin_address,
            end_address,
            unwind_chain,
            xdata_rva: None,
            arm64_packed: None,
        });
        by_rva.insert(begin_address, idx);
    }

    Ok(SehIndex { entries, by_rva })
}

/// Convenience: parse `.pdata` from a flat PE file buffer, automatically
/// locating the section via the PE header.
///
/// Returns `Err(SehError::NoPdata)` when the image has no `.pdata`.
///
/// # Errors
/// Returns [`SehError`] for any structural parsing failure.
pub fn parse_pe_file(data: &[u8]) -> Result<SehIndex, SehError> {
    // Minimal PE header walk: DOS header → NT headers → section table.
    if data.len() < 64 {
        return Err(SehError::TooSmall { offset: 0, need: 64 });
    }
    if &data[0..2] != b"MZ" {
        return Err(SehError::TooSmall { offset: 0, need: 2 }); // reuse error
    }
    let e_lfanew = u32::from_le_bytes(data[60..64].try_into().unwrap()) as usize;
    if e_lfanew + 4 > data.len() {
        return Err(SehError::TooSmall { offset: e_lfanew, need: 4 });
    }
    if &data[e_lfanew..e_lfanew + 4] != b"PE\0\0" {
        return Err(SehError::NoPdata); // not a valid PE
    }
    // COFF file header at e_lfanew + 4
    let coff = e_lfanew + 4;
    if coff + 20 > data.len() {
        return Err(SehError::TooSmall { offset: coff, need: 20 });
    }
    // `.pdata` is not x64-only, and neither is its record layout: x64 uses
    // 12-byte RUNTIME_FUNCTIONs (Begin/End/UnwindInfoAddress) while arm64 uses
    // 8-byte ones (BeginAddress/UnwindData). Decoding one with the other's
    // stride does not fail — it silently produces the wrong table — so the
    // machine picks the layout. Everything else (x86, ARM32, IA64) is still
    // refused rather than guessed.
    let machine = u16::from_le_bytes(data[coff..coff + 2].try_into().unwrap());
    let format = PdataFormat::from_machine(machine)
        .ok_or(SehError::UnsupportedMachine(machine))?;
    let num_sections = u16::from_le_bytes(data[coff + 2..coff + 4].try_into().unwrap()) as usize;
    let opt_header_size =
        u16::from_le_bytes(data[coff + 16..coff + 18].try_into().unwrap()) as usize;

    // Optional header starts at coff + 20
    let opt_start = coff + 20;
    let section_table_start = opt_start + opt_header_size;

    // Determine image base from optional header magic
    if opt_start + 4 > data.len() {
        return Err(SehError::TooSmall { offset: opt_start, need: 4 });
    }
    let magic = u16::from_le_bytes(data[opt_start..opt_start + 2].try_into().unwrap());
    let image_base: u64 = if magic == 0x020b {
        // PE32+
        if opt_start + 32 > data.len() {
            0
        } else {
            u64::from_le_bytes(data[opt_start + 24..opt_start + 32].try_into().unwrap())
        }
    } else {
        0
    };
    let _ = image_base; // not needed for file-offset calculation on a flat file

    // Section headers: 40 bytes each
    let mut pdata_file_offset: Option<usize> = None;
    let mut pdata_size: Option<usize> = None;
    for i in 0..num_sections {
        let sh = section_table_start + i * 40;
        if sh + 40 > data.len() {
            break;
        }
        let name = &data[sh..sh + 8];
        if name.starts_with(b".pdata") {
            let virtual_size =
                u32::from_le_bytes(data[sh + 16..sh + 20].try_into().unwrap()) as usize;
            let raw_offset =
                u32::from_le_bytes(data[sh + 20..sh + 24].try_into().unwrap()) as usize;
            let raw_size =
                u32::from_le_bytes(data[sh + 16..sh + 20].try_into().unwrap()) as usize;
            let virtual_address =
                u32::from_le_bytes(data[sh + 12..sh + 16].try_into().unwrap());
            pdata_file_offset = Some(raw_offset);
            pdata_size = Some(virtual_size.min(raw_size));
            // For a flat file: RVA → file offset = RVA - virtual_address + raw_offset
            let va_off = virtual_address as usize;
            let ro = raw_offset;
            return parse_pdata(data, raw_offset, pdata_size.unwrap(), format, move |rva| {
                let rva = rva as usize;
                if rva >= va_off {
                    ro + (rva - va_off)
                } else {
                    rva // fallback for already-flat images
                }
            });
        }
        let _ = (pdata_file_offset, pdata_size);
    }
    Err(SehError::NoPdata)
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Build minimal .pdata + UNWIND_INFO bytes for a function with no handler.
    fn make_nhandler_pdata() -> (Vec<u8>, usize, usize) {
        // image layout:
        //  offset 0x000: .pdata (12 bytes = 1 entry)
        //  offset 0x100: UNWIND_INFO (8 bytes, no codes, no handler)
        let mut buf = vec![0u8; 0x200];
        // RUNTIME_FUNCTION entry
        buf[0..4].copy_from_slice(&0x1000u32.to_le_bytes()); // BeginAddress
        buf[4..8].copy_from_slice(&0x1050u32.to_le_bytes()); // EndAddress
        buf[8..12].copy_from_slice(&0x0100u32.to_le_bytes()); // UnwindInfoAddress = 0x100 (RVA)

        // UNWIND_INFO at RVA 0x100 => file offset 0x100
        //  version=1, flags=0 (NHANDLER), size_of_prolog=8, count_of_codes=0, frame=0
        buf[0x100] = 0x01; // version=1, flags=0
        buf[0x101] = 0x08; // size_of_prolog
        buf[0x102] = 0x00; // count_of_codes
        buf[0x103] = 0x00; // frame_register=0, frame_offset=0

        (buf, 0, 12)
    }

    /// Build a .pdata with a CHAINED function whose parent carries the codes.
    ///
    /// Entry 0: the chained child at RVA 0x1000, UNWIND_INFO at 0x100 with
    ///          UNW_FLAG_CHAININFO, pointing back at the parent's BeginAddress.
    /// Entry 1: the parent at RVA 0x2000, UNWIND_INFO at 0x180 with one code
    ///          and an exception handler.
    fn make_chained_pdata() -> (Vec<u8>, usize, usize) {
        let mut buf = vec![0u8; 0x400];
        // RUNTIME_FUNCTION[0] — the chained child.
        buf[0..4].copy_from_slice(&0x1000u32.to_le_bytes());
        buf[4..8].copy_from_slice(&0x1050u32.to_le_bytes());
        buf[8..12].copy_from_slice(&0x0100u32.to_le_bytes());
        // RUNTIME_FUNCTION[1] — the parent.
        buf[12..16].copy_from_slice(&0x2000u32.to_le_bytes());
        buf[16..20].copy_from_slice(&0x2080u32.to_le_bytes());
        buf[20..24].copy_from_slice(&0x0180u32.to_le_bytes());

        // Child UNWIND_INFO at 0x100: version 1, flags = CHAININFO, no codes.
        buf[0x100] = 0x01 | (UNW_FLAG_CHAININFO << 3);
        buf[0x101] = 0x04; // size_of_prolog
        buf[0x102] = 0x00; // count_of_codes
        buf[0x103] = 0x00;
        // Chained DWORD: the parent's BeginAddress.
        buf[0x104..0x108].copy_from_slice(&0x2000u32.to_le_bytes());

        // Parent UNWIND_INFO at 0x180: version 1, flags = EHANDLER, one code.
        buf[0x180] = 0x01 | (UNW_FLAG_EHANDLER << 3);
        buf[0x181] = 0x0A;
        buf[0x182] = 0x01; // one unwind code
        buf[0x183] = 0x00;
        buf[0x184] = 0x04; // code: offset 4
        buf[0x185] = 0x02; // UWOP_ALLOC_SMALL, info 0
        // handler RVA follows the (even-rounded) code array
        buf[0x188..0x18C].copy_from_slice(&0x3000u32.to_le_bytes());

        (buf, 0, 24)
    }

    /// A chained function must resolve to its parent's unwind data.
    ///
    /// `UNW_FLAG_CHAININFO` means "my real unwind information lives in another
    /// RUNTIME_FUNCTION" — the shape MSVC emits for hot/cold split functions,
    /// which is ordinary in optimised builds. `parse_unwind_info` recorded the
    /// parent's RVA and stopped, and `parse_pdata` never followed it, so
    /// `unwind_chain` was ALWAYS one element long even though its doc says it
    /// "may be a chain of entries when chained". The consequence is not
    /// cosmetic: every chained function looked like it had no unwind codes and
    /// no exception handler, so `entries_with_handler` silently omitted them.
    #[test]
    fn a_chained_function_resolves_to_its_parents_unwind_info() {
        let (buf, off, size) = make_chained_pdata();
        let index = parse_pdata(&buf, off, size, PdataFormat::X64, |rva| rva as usize).unwrap();

        let child = index.by_begin_rva(0x1000).expect("the chained entry is indexed");
        assert_eq!(child.unwind_chain[0].handler_kind, HandlerKind::Chained);
        assert_eq!(child.unwind_chain[0].chained_function_rva, Some(0x2000));
        assert!(
            child.unwind_chain.len() >= 2,
            "the parent's UNWIND_INFO must be appended to the chain, otherwise the              function appears to have no unwind codes and no handler"
        );

        let parent = &child.unwind_chain[1];
        assert_eq!(parent.handler_kind, HandlerKind::ExceptionHandler);
        assert_eq!(parent.handler_rva, Some(0x3000));
        assert_eq!(parent.codes.len(), 1, "the parent's unwind codes come with it");

        // And the chained child must now be reported as having a handler.
        assert!(
            index.entries_with_handler().iter().any(|e| e.begin_address == 0x1000),
            "a chained function inherits its parent's handler"
        );
    }

    /// A chain that loops must terminate, not spin.
    ///
    /// `.pdata` comes from the binary under analysis, which may be corrupt or
    /// deliberately malformed. Two functions each naming the other as parent is
    /// the smallest cycle; without a visited-set the resolver would follow it
    /// forever and hang the debugger on load.
    #[test]
    fn a_cyclic_chain_terminates_instead_of_spinning() {
        let mut buf = vec![0u8; 0x400];
        // Two RUNTIME_FUNCTIONs pointing at each other's BeginAddress.
        buf[0..4].copy_from_slice(&0x1000u32.to_le_bytes());
        buf[4..8].copy_from_slice(&0x1050u32.to_le_bytes());
        buf[8..12].copy_from_slice(&0x0100u32.to_le_bytes());
        buf[12..16].copy_from_slice(&0x2000u32.to_le_bytes());
        buf[16..20].copy_from_slice(&0x2050u32.to_le_bytes());
        buf[20..24].copy_from_slice(&0x0180u32.to_le_bytes());

        buf[0x100] = 0x01 | (UNW_FLAG_CHAININFO << 3);
        buf[0x104..0x108].copy_from_slice(&0x2000u32.to_le_bytes()); // -> B
        buf[0x180] = 0x01 | (UNW_FLAG_CHAININFO << 3);
        buf[0x184..0x188].copy_from_slice(&0x1000u32.to_le_bytes()); // -> A

        let index = parse_pdata(&buf, 0, 24, PdataFormat::X64, |rva| rva as usize).unwrap();
        for e in &index.entries {
            assert!(
                e.unwind_chain.len() <= MAX_CHAIN_DEPTH + 1,
                "a cyclic chain was followed {} links deep",
                e.unwind_chain.len()
            );
        }
    }

    /// A minimal but genuinely well-formed PE32+ file carrying one `.pdata`
    /// section with a single RUNTIME_FUNCTION plus its UNWIND_INFO.
    /// `parse_pe_file` had NO test at all — a public parser over wholly
    /// untrusted PE bytes with zero coverage.
    fn make_minimal_pe() -> Vec<u8> {
        const E_LFANEW: usize = 0x80;
        const OPT_SIZE: usize = 240; // PE32+ optional header
        let coff = E_LFANEW + 4;
        let opt_start = coff + 20;
        let sec_table = opt_start + OPT_SIZE;
        // .pdata contents live at file offset 0x400, unwind info at 0x500.
        const PDATA_RAW: usize = 0x400;
        const PDATA_RVA: u32 = 0x1000;
        const UNWIND_RVA: u32 = 0x1100;

        let mut buf = vec![0u8; 0x600];
        buf[0..2].copy_from_slice(b"MZ");
        buf[60..64].copy_from_slice(&(E_LFANEW as u32).to_le_bytes());
        buf[E_LFANEW..E_LFANEW + 4].copy_from_slice(b"PE\0\0");
        // COFF: machine, NumberOfSections=1, ..., SizeOfOptionalHeader
        buf[coff..coff + 2].copy_from_slice(&0x8664u16.to_le_bytes());
        buf[coff + 2..coff + 4].copy_from_slice(&1u16.to_le_bytes());
        buf[coff + 16..coff + 18].copy_from_slice(&(OPT_SIZE as u16).to_le_bytes());
        // Optional header: PE32+ magic, ImageBase at +24
        buf[opt_start..opt_start + 2].copy_from_slice(&0x020bu16.to_le_bytes());
        buf[opt_start + 24..opt_start + 32].copy_from_slice(&0x1_4000_0000u64.to_le_bytes());
        // Section header: name, VirtualSize, VirtualAddress, SizeOfRawData, PointerToRawData
        buf[sec_table..sec_table + 6].copy_from_slice(b".pdata");
        buf[sec_table + 12..sec_table + 16].copy_from_slice(&PDATA_RVA.to_le_bytes());
        buf[sec_table + 16..sec_table + 20].copy_from_slice(&12u32.to_le_bytes());
        buf[sec_table + 20..sec_table + 24].copy_from_slice(&(PDATA_RAW as u32).to_le_bytes());
        // RUNTIME_FUNCTION at the .pdata raw offset
        buf[PDATA_RAW..PDATA_RAW + 4].copy_from_slice(&0x2000u32.to_le_bytes());
        buf[PDATA_RAW + 4..PDATA_RAW + 8].copy_from_slice(&0x2050u32.to_le_bytes());
        buf[PDATA_RAW + 8..PDATA_RAW + 12].copy_from_slice(&UNWIND_RVA.to_le_bytes());
        // UNWIND_INFO: RVA 0x1100 -> file offset 0x400 + (0x1100 - 0x1000) = 0x500
        buf[0x500] = 0x01; // version 1, no flags
        buf[0x501] = 0x08; // size_of_prolog
        buf
    }

    /// An arm64 PE must never be parsed as if it were x64.
    ///
    /// `.pdata` exists on ARM64 Windows too, but its `RUNTIME_FUNCTION` is
    /// **8 bytes** (BeginAddress + UnwindData), not the 12 of x64
    /// (Begin/End/UnwindInfoAddress). This parser divided the section by 12 and
    /// strode through it in steps of 12 without ever looking at the machine
    /// field, so on an arm64 image every record it produced straddled two real
    /// ones: `begin_address` values taken from the middle of a neighbour,
    /// `unwind_info_address` pointing at nothing in particular. Malformed
    /// UNWIND_INFO is skipped with `continue`, so the result was not an error —
    /// it was a confidently-populated `SehIndex` full of fabricated functions,
    /// which `containing()` and `entries_with_handler()` would then answer from.
    ///
    /// Superseded (this iteration): refusing is no longer the best that can be
    /// done correctly — the 8-byte layout is now decoded, so an ARM64 image
    /// PARSES. What must not change is the other half of iter 340's guarantee:
    /// the x64 stride is never applied to an ARM64 table, and every machine
    /// whose layout is genuinely unknown is still refused rather than guessed.
    #[test]
    fn an_arm64_pe_is_decoded_with_its_own_stride_and_others_are_still_refused() {
        const E_LFANEW: usize = 0x80;
        let coff = E_LFANEW + 4;

        // Flip only the machine field: everything else stays a valid PE32+.
        // The .pdata section is 12 bytes, which under the ARM64 stride is one
        // whole 8-byte record (the trailing 4 bytes are a partial record and
        // are correctly not counted) rather than the x64 file's single 12-byte
        // one -- proving the stride actually followed the machine field.
        let mut arm = make_minimal_pe();
        arm[coff..coff + 2].copy_from_slice(&0xAA64u16.to_le_bytes());
        let idx = parse_pe_file(&arm).expect("an arm64 image is now decoded, not refused");
        assert_eq!(idx.len(), 1, "12 bytes / 8-byte ARM64 records = 1 whole record");

        // A machine whose .pdata layout this module does not know stays refused
        // -- iter 340's core guarantee, unchanged.
        for (machine, what) in [(0x014cu16, "i386"), (0x01c4, "ARMNT"), (0x0200, "IA64")] {
            let mut other = make_minimal_pe();
            other[coff..coff + 2].copy_from_slice(&machine.to_le_bytes());
            match parse_pe_file(&other) {
                Err(SehError::UnsupportedMachine(m)) => assert_eq!(m, machine),
                res => panic!("{what} must be refused, not guessed at: {res:?}"),
            }
        }

        // The x64 image keeps parsing exactly as before.
        let idx = parse_pe_file(&make_minimal_pe()).expect("x64 still parses");
        assert_eq!(idx.len(), 1);
    }

    #[test]
    fn parse_pe_file_finds_the_pdata_section() {
        let pe = make_minimal_pe();
        let idx = parse_pe_file(&pe).expect("well-formed PE should parse");
        assert_eq!(idx.len(), 1);
        assert_eq!(idx.entries[0].begin_address, 0x2000);
        assert_eq!(idx.entries[0].end_address, 0x2050);
    }

    /// Truncation + mutation sweep: `parse_pe_file` takes a wholly untrusted
    /// PE, so every malformed variant must return `Err`, never panic.
    #[test]
    fn parse_pe_file_never_panics_on_truncated_or_mutated_input() {
        let good = make_minimal_pe();

        for len in 0..=good.len() {
            let _ = parse_pe_file(&good[..len]);
        }

        // Mutating all 0x600 bytes x 5 probes is needlessly slow and mostly
        // hits zero padding; sweep the header/section-table region densely,
        // which is where every length, count and offset field lives.
        for i in 0..0x500usize {
            for probe in [0x00u8, 0x01, 0x7F, 0x80, 0xFF] {
                let mut m = good.clone();
                m[i] = probe;
                let _ = parse_pe_file(&m);
            }
        }

        // Whole 4-byte fields blown out to u32::MAX — the classic
        // offset/size overflow trigger that single-byte mutation misses.
        for i in 0..0x500usize {
            let mut m = good.clone();
            m[i..i + 4].copy_from_slice(&u32::MAX.to_le_bytes());
            let _ = parse_pe_file(&m);
        }
    }

    #[test]
    fn parse_nhandler_pdata() {
        let (buf, off, size) = make_nhandler_pdata();
        let idx = parse_pdata(&buf, off, size, PdataFormat::X64, |rva| rva as usize).unwrap();
        assert_eq!(idx.len(), 1);
        let e = &idx.entries[0];
        assert_eq!(e.begin_address, 0x1000);
        assert_eq!(e.end_address, 0x1050);
        assert!(!e.has_exception_handler());
        assert_eq!(idx.containing(0x1010).map(|e| e.begin_address), Some(0x1000));
        assert!(idx.containing(0x2000).is_none());
    }

    /// Build .pdata + UNWIND_INFO with an __except handler.
    fn make_ehandler_pdata() -> (Vec<u8>, usize, usize) {
        let mut buf = vec![0u8; 0x400];
        buf[0..4].copy_from_slice(&0x2000u32.to_le_bytes()); // BeginAddress
        buf[4..8].copy_from_slice(&0x20A0u32.to_le_bytes()); // EndAddress
        buf[8..12].copy_from_slice(&0x0200u32.to_le_bytes()); // UnwindInfoAddress

        // UNWIND_INFO at file offset 0x200: version=1, flags=EHANDLER (1<<3=0x08)
        buf[0x200] = (UNW_FLAG_EHANDLER << 3) | 0x01; // flags<<3 | version
        buf[0x201] = 0x10; // size_of_prolog = 16
        buf[0x202] = 0x00; // count_of_codes = 0
        buf[0x203] = 0x00; // frame_register/offset = 0
        // handler DWORD immediately after (count_of_codes=0, so at +4)
        buf[0x204..0x208].copy_from_slice(&0x3000u32.to_le_bytes()); // handler RVA = 0x3000

        (buf, 0, 12)
    }

    #[test]
    fn parse_ehandler_pdata() {
        let (buf, off, size) = make_ehandler_pdata();
        let idx = parse_pdata(&buf, off, size, PdataFormat::X64, |rva| rva as usize).unwrap();
        assert_eq!(idx.len(), 1);
        let e = &idx.entries[0];
        assert!(e.has_exception_handler());
        assert_eq!(e.exception_handler_rva(), Some(0x3000));
        assert_eq!(idx.entries_with_handler().len(), 1);
    }

    /// Build a 3-record ARM64 `.pdata` table (8 bytes per record), all packed
    /// so no `.xdata` is needed.
    fn make_arm64_pdata() -> Vec<u8> {
        let mut buf = vec![0u8; 24];
        // Flag=1, FunctionLength=0x10 units -> 64 bytes.
        buf[0..4].copy_from_slice(&0x1000u32.to_le_bytes());
        buf[4..8].copy_from_slice(&0x0000_0041u32.to_le_bytes());
        // Flag=1, FL=0x20 (128 bytes), RegF=2, RegI=4, CR=3, FrameSize=3 (48 bytes).
        buf[8..12].copy_from_slice(&0x2000u32.to_le_bytes());
        buf[12..16].copy_from_slice(&0x01E4_4081u32.to_le_bytes());
        // Flag=1, FL=4 (16 bytes), H=1.
        buf[16..20].copy_from_slice(&0x3000u32.to_le_bytes());
        buf[20..24].copy_from_slice(&0x0010_0011u32.to_le_bytes());
        buf
    }

    /// The x64 stride applied to an ARM64 table does not merely lose precision:
    /// measured before the fix, `parse_pdata` returned **0** entries for these
    /// three real functions (each mis-strided record either pointed its
    /// `UnwindInfoAddress` outside the buffer or landed on an odd value and was
    /// skipped). Windows-on-ARM images produced a confidently empty index.
    #[test]
    fn parse_pdata_on_an_arm64_table_does_not_invent_entries() {
        let buf = make_arm64_pdata();
        let index = parse_pdata(&buf, 0, 24, PdataFormat::Arm64, |rva| rva as usize).unwrap();
        assert_eq!(
            index.entries.len(),
            3,
            "rvas: {:?}",
            index.entries.iter().map(|e| e.begin_address).collect::<Vec<_>>()
        );
        assert_eq!(
            index.entries.iter().map(|e| e.begin_address).collect::<Vec<_>>(),
            vec![0x1000, 0x2000, 0x3000]
        );
        // end_address derives from the packed FunctionLength, in bytes.
        assert_eq!(index.entries[0].end_address, 0x1000 + 64);
        assert_eq!(index.entries[1].end_address, 0x2000 + 128);
        assert_eq!(index.entries[2].end_address, 0x3000 + 16);
        // Packed records carry no UNWIND_INFO and no .xdata pointer.
        for e in &index.entries {
            assert!(e.unwind_chain.is_empty());
            assert_eq!(e.xdata_rva, None);
            assert!(e.arm64_packed.is_some());
        }
    }

    /// Negative control for the stride change: the x64 mapping is untouched and
    /// every other machine is still refused rather than guessed.
    #[test]
    fn the_x64_record_stride_is_unchanged() {
        assert_eq!(PdataFormat::X64.record_size(), 12);
        assert_eq!(PdataFormat::Arm64.record_size(), 8);
        assert_eq!(PdataFormat::from_machine(0x8664), Some(PdataFormat::X64));
        assert_eq!(PdataFormat::from_machine(0xAA64), Some(PdataFormat::Arm64));
        assert_eq!(PdataFormat::from_machine(0x014c), None); // i386
        assert_eq!(PdataFormat::from_machine(0x01c4), None); // ARMNT
        assert_eq!(PdataFormat::from_machine(0x0200), None); // IA64
    }

    /// Values computed by hand from the ARM64 exception-handling specification's
    /// "Packed unwind data" table, NOT from this implementation — the two scaled
    /// fields (`FunctionLength` x4, `FrameSize` x16) are exactly where a unit
    /// error would otherwise be invisible.
    #[test]
    fn decode_arm64_packed_matches_hand_computed_vectors() {
        // 0x41 = Flag 1, FunctionLength 0x10 -> 64 bytes, everything else zero.
        let minimal = decode_arm64_packed(0x0000_0041).expect("bit0 set => packed");
        assert_eq!(minimal.flag, 1);
        assert_eq!(minimal.function_length, 64);
        assert_eq!(minimal.reg_f, 0);
        assert_eq!(minimal.reg_i, 0);
        assert!(!minimal.homes_params);
        assert_eq!(minimal.cr, 0);
        assert_eq!(minimal.frame_size, 0);

        // 0x01E4_4081 = 1 | (32<<2) | (2<<13) | (4<<16) | (0<<20) | (3<<21) | (3<<23)
        let full = decode_arm64_packed(0x01E4_4081).expect("packed");
        assert_eq!(full.flag, 1);
        assert_eq!(full.function_length, 32 * 4, "FunctionLength is in 4-byte units");
        assert_eq!(full.reg_f, 2);
        assert_eq!(full.reg_i, 4);
        assert!(!full.homes_params);
        assert_eq!(full.cr, 3);
        assert_eq!(full.frame_size, 3 * 16, "FrameSize is in 16-byte units");

        // 0x0010_0011 = 1 | (4<<2) | (1<<20): the H bit alone.
        let homed = decode_arm64_packed(0x0010_0011).expect("packed");
        assert_eq!(homed.function_length, 16);
        assert!(homed.homes_params);

        // Negative control: low two bits clear => an .xdata RVA, not packed data.
        assert!(decode_arm64_packed(0x0000_2000).is_none());
        assert!(decode_arm64_packed(0).is_none());
        // Flag 2 (packed fragment) is still packed.
        assert_eq!(decode_arm64_packed(0x0000_0042).map(|p| p.flag), Some(2));
    }

    /// A mixed table: one packed record, one pointing into `.xdata`. The second
    /// must still appear — with its `.xdata` RVA surfaced and NO fabricated
    /// unwind information.
    #[test]
    fn an_arm64_xdata_record_is_recorded_without_inventing_unwind_info() {
        let mut buf = vec![0u8; 16];
        buf[0..4].copy_from_slice(&0x1000u32.to_le_bytes());
        buf[4..8].copy_from_slice(&0x0000_0041u32.to_le_bytes()); // packed, 64 bytes
        buf[8..12].copy_from_slice(&0x2000u32.to_le_bytes());
        buf[12..16].copy_from_slice(&0x0000_4000u32.to_le_bytes()); // .xdata RVA

        let index = parse_pdata(&buf, 0, 16, PdataFormat::Arm64, |rva| rva as usize).unwrap();
        assert_eq!(index.entries.len(), 2);
        assert_eq!(index.entries[0].end_address, 0x1000 + 64);
        assert_eq!(index.entries[0].xdata_rva, None);

        let x = &index.entries[1];
        assert_eq!(x.begin_address, 0x2000);
        assert_eq!(x.xdata_rva, Some(0x4000));
        assert_eq!(x.arm64_packed, None);
        assert!(
            x.unwind_chain.is_empty(),
            "the .xdata UNWIND_INFO is not decoded, so nothing may be claimed"
        );
        assert_eq!(x.end_address, 0x2000, "length is unknown, not guessed");
    }

    #[test]
    fn seh_index_by_begin_rva() {
        let (buf, off, size) = make_nhandler_pdata();
        let idx = parse_pdata(&buf, off, size, PdataFormat::X64, |rva| rva as usize).unwrap();
        assert!(idx.by_begin_rva(0x1000).is_some());
        assert!(idx.by_begin_rva(0x1001).is_none());
    }

    fn entry(begin: u32, end: u32, xdata: Option<u32>) -> SehEntry {
        SehEntry {
            begin_address: begin,
            end_address: end,
            unwind_chain: Vec::new(),
            xdata_rva: xdata,
            arm64_packed: None,
        }
    }

    fn index_of(entries: Vec<SehEntry>) -> SehIndex {
        let mut by_rva = BTreeMap::new();
        for (i, e) in entries.iter().enumerate() {
            by_rva.insert(e.begin_address, i);
        }
        SehIndex { entries, by_rva }
    }

    /// An ARM64 entry whose length lives in undecoded .xdata must not read as
    /// "this address has no unwind information".
    ///
    /// The non-packed path deliberately leaves end == begin ("unknown, not
    /// guessed"), and `containing()` then answered None for those functions -
    /// including for their own entry point. None reads as absence, so a caller
    /// asking which function covers a crash RVA concluded there was no SEH
    /// entry, while the entry and its xdata_rva were sitting right there.
    #[test]
    fn an_entry_of_unknown_length_is_not_reported_as_absent() {
        let idx = index_of(vec![entry(0x1000, 0x1000, Some(0x9000))]);

        // The function provably contains its own first byte.
        assert!(
            matches!(idx.coverage(0x1000), Coverage::Contains(_)),
            "a function contains its own entry point whatever its length"
        );
        assert!(idx.containing(0x1000).is_some());

        // Past it, the honest answer is "I do not know how far it reaches",
        // and the entry is still the caller lead - its xdata_rva is where the
        // real length lives.
        match idx.coverage(0x1040) {
            Coverage::ExtentUnknown(e) => assert_eq!(e.xdata_rva, Some(0x9000)),
            other => panic!("expected ExtentUnknown, got {other:?}"),
        }
        assert!(
            idx.containing(0x1040).is_none(),
            "containing() still means PROVABLY contains, so it must stay conservative"
        );

        // Before every entry there really is nothing.
        assert!(matches!(idx.coverage(0x0FFF), Coverage::None));
    }

    /// An entry with a known length keeps its exact bounds, and the flag that
    /// separates the two cases is not a constant.
    #[test]
    fn a_known_extent_is_still_bounded_exactly() {
        let idx = index_of(vec![entry(0x2000, 0x2050, None)]);
        assert!(idx.entries[0].extent_is_known());
        assert!(matches!(idx.coverage(0x2000), Coverage::Contains(_)));
        assert!(matches!(idx.coverage(0x204F), Coverage::Contains(_)));
        assert!(
            matches!(idx.coverage(0x2050), Coverage::None),
            "the end address is exclusive and the length is known, so this is a real absence"
        );
        assert!(!index_of(vec![entry(0x3000, 0x3000, None)]).entries[0].extent_is_known());
    }

}
