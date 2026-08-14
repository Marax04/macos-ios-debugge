//! The nine function-detection strategies and a confidence lattice that
//! merges and resolves conflicting detections.
//!
//! Each strategy contributes [`FunctionBoundary`] candidates from a different
//! evidence source.  Real binaries expose different subsets of these sources
//! (a stripped ELF has no symbols; a PE has an exception directory; a Mach-O
//! has a `LC_FUNCTION_STARTS` load command; etc.), so the
//! [`StrategyEngine`] runs every applicable strategy and fuses the results
//! through a [`ConfidenceLattice`].
//!
//! Strategies implemented (spec section 6, function detection):
//!  1. Exception directory (PE `.pdata` `RUNTIME_FUNCTION`).
//!  2. Mach-O `LC_FUNCTION_STARTS` (ULEB128 delta list).
//!  3. ARM `.ARM.exidx` exception index entries.
//!  4. DWARF `.eh_frame` FDE initial-location.
//!  5. Symbol table / exports.
//!  6. Direct call targets.
//!  7. Architecture-specific prologue signatures.
//!  8. Linear sweep.
//!  9. Recursive descent.

use crate::{
    Confidence, DetectedArch, DetectionSource, FunctionBoundary, FunctionDetector, GapAnalyzer,
    MemorySlice, x86_64_frame_patterns, x86_64_leaf_patterns,
};
use rustre_core::address::{Address, AddressRange};
use std::collections::{BTreeMap, HashSet, VecDeque};

// ─────────────────────────────────────────────────────────────────────────────
// Strategy identity
// ─────────────────────────────────────────────────────────────────────────────

/// Identifies one of the nine detection strategies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum StrategyKind {
    /// PE exception directory (`.pdata`).
    ExceptionDirectory,
    /// Mach-O function-starts table.
    MachOFunctionStarts,
    /// ARM `.ARM.exidx` index.
    ArmExidx,
    /// DWARF `.eh_frame` FDEs.
    DwarfEhFrame,
    /// Symbol table / exports.
    Symbols,
    /// Direct call targets.
    CallTargets,
    /// Architecture prologue signatures.
    PrologueSignature,
    /// Linear sweep.
    LinearSweep,
    /// Recursive descent.
    RecursiveDescent,
}

impl StrategyKind {
    /// Baseline confidence contributed by this strategy in isolation.
    #[must_use]
    pub const fn base_confidence(self) -> Confidence {
        match self {
            // Structured metadata is authoritative.
            Self::ExceptionDirectory
            | Self::MachOFunctionStarts
            | Self::ArmExidx
            | Self::DwarfEhFrame
            | Self::Symbols => Confidence::Certain,
            // Strong but inferred.
            Self::CallTargets | Self::PrologueSignature => Confidence::High,
            // Weak structural heuristics.
            Self::RecursiveDescent => Confidence::Medium,
            Self::LinearSweep => Confidence::Low,
        }
    }

    /// Map to the persisted [`DetectionSource`].
    #[must_use]
    pub const fn to_source(self) -> DetectionSource {
        match self {
            Self::ExceptionDirectory | Self::ArmExidx | Self::DwarfEhFrame => {
                DetectionSource::ExceptionHandler
            }
            Self::MachOFunctionStarts | Self::Symbols => DetectionSource::SymbolTable,
            Self::CallTargets => DetectionSource::CallTarget,
            Self::PrologueSignature => DetectionSource::ProloguePattern,
            Self::LinearSweep | Self::RecursiveDescent => DetectionSource::HeuristicGap,
        }
    }

    /// A short human-readable name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::ExceptionDirectory => "exception_directory",
            Self::MachOFunctionStarts => "macho_function_starts",
            Self::ArmExidx => "arm_exidx",
            Self::DwarfEhFrame => "dwarf_eh_frame",
            Self::Symbols => "symbols",
            Self::CallTargets => "call_targets",
            Self::PrologueSignature => "prologue_signature",
            Self::LinearSweep => "linear_sweep",
            Self::RecursiveDescent => "recursive_descent",
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Strategy 1: PE exception directory (.pdata)
// ─────────────────────────────────────────────────────────────────────────────

/// One `RUNTIME_FUNCTION` entry from a PE x64 `.pdata` section.
///
/// The on-disk layout is three little-endian u32 RVAs:
/// `begin`, `end`, `unwind_info`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuntimeFunction {
    /// RVA of the function start.
    pub begin_rva: u32,
    /// RVA one-past the function end.
    pub end_rva: u32,
    /// RVA of the associated `UNWIND_INFO`.
    pub unwind_rva: u32,
}

/// Maximum number of `RUNTIME_FUNCTION` entries accepted from untrusted `.pdata` input.
///
/// A legitimate PE rarely exceeds a few hundred thousand functions;
/// beyond this a crafted payload would exhaust heap (dos-memory-exhaustion).
pub const PDATA_MAX_ENTRIES: usize = 1_000_000;

/// Parse a PE `.pdata` section into [`RuntimeFunction`] entries.
///
/// `image_base` is the loaded base used to turn RVAs into virtual addresses.
#[must_use]
pub fn parse_pdata(pdata: &[u8]) -> Vec<RuntimeFunction> {
    // See the twin in `rustre-analysis-cfg::seh`: records violating
    // `begin < end` cannot come from a valid x64 `.pdata` and are dropped
    // rather than reported as functions (an ARM64 table read with the x64
    // 12-byte stride produces exactly those).
    let mut out = Vec::new();
    let mut off = 0;
    while off + 12 <= pdata.len() {
        let begin =
            u32::from_le_bytes([pdata[off], pdata[off + 1], pdata[off + 2], pdata[off + 3]]);
        let end = u32::from_le_bytes([
            pdata[off + 4],
            pdata[off + 5],
            pdata[off + 6],
            pdata[off + 7],
        ]);
        let unwind = u32::from_le_bytes([
            pdata[off + 8],
            pdata[off + 9],
            pdata[off + 10],
            pdata[off + 11],
        ]);
        // A zeroed terminating record marks end of table.
        if begin == 0 && end == 0 && unwind == 0 {
            break;
        }
        // Impossible record: skip it rather than report a function that does
        // not exist (see the comment on this function).
        if end <= begin {
            off += 12;
            continue;
        }
        out.push(RuntimeFunction {
            begin_rva: begin,
            end_rva: end,
            unwind_rva: unwind,
        });
        off += 12;
        // Guard against memory exhaustion from a crafted oversized .pdata blob.
        if out.len() >= PDATA_MAX_ENTRIES {
            break;
        }
    }
    out
}

/// Convert parsed `.pdata` entries to [`FunctionBoundary`] values.
#[must_use]
pub fn boundaries_from_pdata(
    image_base: Address,
    entries: &[RuntimeFunction],
) -> Vec<FunctionBoundary> {
    entries
        .iter()
        .filter(|e| e.end_rva > e.begin_rva)
        .map(|e| {
            let start = Address::new(image_base.as_u64() + u64::from(e.begin_rva));
            let end = Address::new(image_base.as_u64() + u64::from(e.end_rva));
            FunctionBoundary::new(
                start,
                Confidence::Certain,
                DetectionSource::ExceptionHandler,
            )
            .with_end(end)
        })
        .collect()
}

// ─── Gap F: extra .pdata function recovery ──────────────────────────────────

/// Minimum byte-distance considered a candidate gap (skip the 1-byte CC/90
/// alignment fillers between adjacent `RUNTIME_FUNCTION` ranges).
pub const EXTRA_PDATA_MIN_GAP_SIZE: usize = 16;

/// Smallest validated extra function body (filters out lone `0xC3` placeholders
/// that the linear terminator scan would otherwise accept as a 1-byte function).
pub const EXTRA_PDATA_MIN_BODY_BYTES: u64 = 5;

/// Statistics returned alongside the extra-function set.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ExtraPdataStats {
    /// Total candidate gaps inspected.
    pub gaps_scanned: usize,
    /// Gaps whose first non-padding bytes matched a known x86-64 prologue.
    pub prologue_matches: usize,
    /// Gaps that produced a validated extra function.
    pub candidates_validated: usize,
    /// Number of `RUNTIME_FUNCTION` entries seen on the input.
    pub pdata_count: usize,
}

/// Find functions that exist in `.text` but are absent from the PE `.pdata`
/// exception directory.
///
/// Algorithm (per scout plan):
///   1. Derive known starts via [`boundaries_from_pdata`] from `pdata_entries`.
///   2. Sweep `.text` for gaps with [`GapAnalyzer::find_gaps`].
///   3. For each gap: skip CC/90 padding, match an x86-64 frame/leaf prologue,
///      then validate that a RET / JMP terminator lives inside the gap via the
///      same path used by [`FunctionDetector::estimate_end`].
///
/// Returned boundaries are tagged [`DetectionSource::HeuristicGap`] with
/// [`Confidence::Medium`].
#[must_use]
pub fn find_extra_pdata_funcs(
    image_base: Address,
    text_range: AddressRange,
    text_bytes: &[u8],
    pdata_entries: &[RuntimeFunction],
) -> (Vec<FunctionBoundary>, ExtraPdataStats) {
    let mut stats = ExtraPdataStats {
        pdata_count: pdata_entries.len(),
        ..ExtraPdataStats::default()
    };

    let mem = MemorySlice::new(text_range.start, text_bytes);

    // Collect [begin, end) ranges from .pdata covering `text_range`, sorted by begin.
    let mut covered: Vec<(u64, u64)> = pdata_entries
        .iter()
        .filter(|e| e.end_rva > e.begin_rva)
        .map(|e| {
            (
                image_base.as_u64() + u64::from(e.begin_rva),
                image_base.as_u64() + u64::from(e.end_rva),
            )
        })
        .filter(|(b, _)| *b >= text_range.start.as_u64() && *b < text_range.end.as_u64())
        .collect();
    covered.sort_unstable_by_key(|(b, _)| *b);

    // Build gap ranges between covered regions. A "gap" is the address span
    // strictly between the end of one pdata function and the start of the next
    // (or between text_range start/end and the first/last covered range).
    let analyzer = GapAnalyzer {
        min_gap_size: EXTRA_PDATA_MIN_GAP_SIZE,
        ..GapAnalyzer::new()
    };
    let mut gaps: Vec<AddressRange> = Vec::new();
    let mut cursor = text_range.start.as_u64();
    for (begin, end) in &covered {
        if *begin > cursor {
            let len = usize::try_from(*begin - cursor).unwrap_or(usize::MAX);
            if len >= analyzer.min_gap_size {
                gaps.push(AddressRange::new(Address::new(cursor), Address::new(*begin)));
            }
        }
        cursor = cursor.max(*end);
    }
    if cursor < text_range.end.as_u64() {
        let len = usize::try_from(text_range.end.as_u64() - cursor).unwrap_or(usize::MAX);
        if len >= analyzer.min_gap_size {
            gaps.push(AddressRange::new(Address::new(cursor), text_range.end));
        }
    }
    stats.gaps_scanned = gaps.len();

    let frame = x86_64_frame_patterns();
    let leaf = x86_64_leaf_patterns();
    let detector = FunctionDetector::new(DetectedArch::X86_64);

    let mut out = Vec::new();
    for gap in gaps {
        let Some(candidate) = analyzer.first_code_byte(gap, &mem) else {
            continue;
        };
        let window_len = usize::try_from(gap.end.as_u64().saturating_sub(candidate.as_u64())).unwrap_or(usize::MAX);
        let Some(window) = mem.slice_at(candidate, window_len) else {
            continue;
        };

        // Try frame-based prologues first (highest confidence), then leaf forms.
        let matched = frame
            .iter()
            .chain(leaf.iter())
            .find(|p| window.len() >= p.min_len() && p.matches(window));
        let Some(pat) = matched else {
            continue;
        };
        stats.prologue_matches += 1;

        // Validate region end with RET / JMP terminator via the detector.
        let Some(end) = detector.estimate_end(candidate, &mem) else {
            continue;
        };
        if end.as_u64() > gap.end.as_u64() {
            continue;
        }
        let body_size = end.as_u64().saturating_sub(candidate.as_u64());
        if body_size < EXTRA_PDATA_MIN_BODY_BYTES {
            continue;
        }

        stats.candidates_validated += 1;
        out.push(
            FunctionBoundary::new(
                candidate,
                Confidence::Medium,
                DetectionSource::HeuristicGap,
            )
            .with_end(end)
            .with_name(format!("extra_pdata_{}", pat.name)),
        );
    }

    (out, stats)
}

// ─────────────────────────────────────────────────────────────────────────────
// Strategy 2: Mach-O LC_FUNCTION_STARTS
// ─────────────────────────────────────────────────────────────────────────────

/// Decode a single ULEB128 value from `data` at `*pos`, advancing `pos`.
fn read_uleb128(data: &[u8], pos: &mut usize) -> Option<u64> {
    let mut result: u64 = 0;
    let mut shift = 0u32;
    loop {
        let byte = *data.get(*pos)?;
        *pos += 1;
        result |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Some(result);
        }
        shift += 7;
        if shift >= 64 {
            return None;
        }
    }
}

/// Maximum function-start entries decoded from a `LC_FUNCTION_STARTS` payload.
/// A crafted payload with no zero terminator would otherwise fill memory
/// until the process is killed (dos-memory-exhaustion).
pub const MACHO_STARTS_MAX_ENTRIES: usize = 1_000_000;

/// Decode a Mach-O `LC_FUNCTION_STARTS` payload: a ULEB128 delta list where the
/// first delta is added to `text_base` and each subsequent delta to the running
/// address.  A zero delta terminates the list.
#[must_use]
pub fn parse_macho_function_starts(text_base: Address, payload: &[u8]) -> Vec<FunctionBoundary> {
    let mut out = Vec::new();
    let mut pos = 0usize;
    let mut addr = text_base.as_u64();
    while pos < payload.len() {
        let Some(delta) = read_uleb128(payload, &mut pos) else {
            break;
        };
        if delta == 0 {
            break;
        }
        // The first decoded address is text_base + first_delta; each subsequent
        // delta is added to the running address.  No special-casing is needed
        // because `addr` starts at `text_base.as_u64()` and the first delta is
        // added unconditionally below.
        addr = addr.wrapping_add(delta);
        out.push(FunctionBoundary::new(
            Address::new(addr),
            Confidence::Certain,
            DetectionSource::SymbolTable,
        ));
        // Guard against memory exhaustion from a crafted payload.
        if out.len() >= MACHO_STARTS_MAX_ENTRIES {
            break;
        }
    }
    out
}

// ─────────────────────────────────────────────────────────────────────────────
// Strategy 3: ARM .ARM.exidx
// ─────────────────────────────────────────────────────────────────────────────

/// Maximum entries decoded from `.ARM.exidx`.
///
/// Each entry is 8 bytes on disk; 1 M entries = 8 MiB input, which is already
/// unrealistic for a real binary.
/// Capping prevents a crafted section from exhausting heap (dos-memory-exhaustion).
pub const ARM_EXIDX_MAX_ENTRIES: usize = 1_000_000;

/// Parse an `.ARM.exidx` section.
///
/// Each entry is 8 bytes: a 31-bit
/// PC-relative *prel31* offset to the function start, followed by exception
/// data.  The high bit of word 0 is reserved (must be 0 for a valid offset).
#[must_use]
pub fn parse_arm_exidx(section_addr: Address, data: &[u8]) -> Vec<FunctionBoundary> {
    let mut out = Vec::new();
    let mut off = 0usize;
    while off + 8 <= data.len() {
        let word0 = u32::from_le_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]]);
        // The high bit of word0 must be clear for a valid prel31 entry; skip
        // invalid entries rather than emitting bogus boundaries.
        if word0 & 0x8000_0000 != 0 {
            off += 8;
            continue;
        }
        // prel31: sign-extend 31-bit value, relative to the entry's own address.
        let entry_addr = section_addr.as_u64() + off as u64;
        let raw = word0 & 0x7fff_ffff;
        // Sign-extend the 31-bit prel31 value (bit 30 is the sign bit).
        let disp: i64 = if raw & 0x4000_0000 != 0 {
            i64::from(raw) - 0x8000_0000
        } else {
            i64::from(raw)
        };
        let func = entry_addr.wrapping_add_signed(disp);
        out.push(FunctionBoundary::new(
            Address::new(func),
            Confidence::Certain,
            DetectionSource::ExceptionHandler,
        ));
        off += 8;
        // Guard against memory exhaustion from a crafted .ARM.exidx section.
        if out.len() >= ARM_EXIDX_MAX_ENTRIES {
            break;
        }
    }
    out
}

// ─────────────────────────────────────────────────────────────────────────────
// Strategy 4: DWARF .eh_frame FDE initial locations
// ─────────────────────────────────────────────────────────────────────────────

/// Maximum FDE entries decoded from `.eh_frame`.  Limits memory use when
/// parsing untrusted input with many crafted FDE records (dos-memory-exhaustion).
pub const EH_FRAME_MAX_FDES: usize = 1_000_000;

/// Read a ULEB128 value, returning (value, new offset), or `None` on overrun.
fn read_uleb128_with_off(data: &[u8], mut off: usize) -> Option<(u64, usize)> {
    let mut value = 0u64;
    let mut shift = 0u32;
    loop {
        let byte = *data.get(off)?;
        off += 1;
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Some((value, off));
        }
        shift += 7;
        if shift >= 64 {
            return None;
        }
    }
}

/// Parse a CIE body and return its FDE pointer encoding
/// (`DW_EH_PE_absptr` if the CIE carries no 'R' augmentation).
fn cie_fde_encoding(body: &[u8]) -> u8 {
    const ABSPTR: u8 = 0x00;
    let mut off = 0usize;
    if body.get(off).is_none() {
        return ABSPTR;
    }
    off += 1;
    let aug_start = off;
    while body.get(off).copied().unwrap_or(0) != 0 {
        off += 1;
    }
    let aug = &body[aug_start..off.min(body.len())];
    if body.get(off).is_none() {
        return ABSPTR;
    }
    off += 1; // NUL
    if aug.first() != Some(&b'z') {
        return ABSPTR;
    }
    for _ in 0..3 {
        let Some((_, next)) = read_uleb128_with_off(body, off) else {
            return ABSPTR;
        };
        off = next;
    }
    let Some((_, mut off)) = read_uleb128_with_off(body, off) else {
        return ABSPTR;
    };
    for &c in &aug[1..] {
        match c {
            b'R' => return body.get(off).copied().unwrap_or(ABSPTR),
            b'L' => off += 1,
            b'P' => {
                let Some(&enc) = body.get(off) else {
                    return ABSPTR;
                };
                off += 1;
                off += match enc & 0x0f {
                    0x02 | 0x0a => 2, // udata2/sdata2
                    0x03 | 0x0b => 4, // udata4/sdata4
                    _ => 8,           // udata8/sdata8, absptr & remaining: pointer-sized
                };
            }
            _ => return ABSPTR,
        }
    }
    ABSPTR
}

/// A simplified `.eh_frame` walker that extracts FDE initial-location PC values.
///
/// `.eh_frame` is a list of length-prefixed records.  A record with CIE id 0 is
/// a CIE; any other id is an FDE whose first field after the CIE pointer is the
/// `initial_location` (here treated as an absolute `u`-word, the common
/// `DW_EH_PE_absptr` case).  This is a heuristic decoder sufficient for tests
/// and for binaries that use absolute pointers.
#[must_use]
pub fn parse_eh_frame_fdes(data: &[u8], ptr_size: u8) -> Vec<FunctionBoundary> {
    const DW_EH_PE_ABSPTR: u8 = 0x00;
    let mut cie_encodings: std::collections::HashMap<usize, u8> =
        std::collections::HashMap::new();
    let mut out = Vec::new();
    let mut off = 0usize;
    while off + 4 <= data.len() {
        let len_u32 =
            u32::from_le_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]]);
        if len_u32 == 0 {
            break; // terminator
        }
        // Guard against u32→usize overflow on 16-bit/32-bit targets and against
        // record_start + len wrapping if len is huge.
        let Ok(len) = usize::try_from(len_u32) else { break };
        let record_start = off + 4;
        if record_start + len > data.len() || record_start + 4 > data.len() {
            break;
        }
        let cie_id = u32::from_le_bytes([
            data[record_start],
            data[record_start + 1],
            data[record_start + 2],
            data[record_start + 3],
        ]);
        if cie_id == 0 {
            // CIE: remember its FDE pointer encoding for later FDEs.
            let body_end = (record_start + len).min(data.len());
            let encoding = cie_fde_encoding(&data[record_start + 4..body_end]);
            cie_encodings.insert(off, encoding);
        } else {
            // FDE: initial_location follows the 4-byte CIE pointer, which is
            // the distance back from this field to the owning CIE.
            let cie_off = (record_start).checked_sub(cie_id as usize);
            let encoding = cie_off
                .and_then(|o| cie_encodings.get(&o).copied())
                .unwrap_or(DW_EH_PE_ABSPTR);
            if encoding != DW_EH_PE_ABSPTR {
                // Non-absolute encodings (e.g. pcrel+sdata4 used by GCC/Clang)
                // cannot be resolved without the section's load address; skip
                // rather than emitting garbage boundaries.
                off = record_start + len;
                continue;
            }
            let loc_off = record_start + 4;
            let pc = match ptr_size {
                8 if loc_off + 8 <= data.len() => Some(u64::from_le_bytes([
                    data[loc_off],
                    data[loc_off + 1],
                    data[loc_off + 2],
                    data[loc_off + 3],
                    data[loc_off + 4],
                    data[loc_off + 5],
                    data[loc_off + 6],
                    data[loc_off + 7],
                ])),
                4 if loc_off + 4 <= data.len() => Some(u64::from(u32::from_le_bytes([
                    data[loc_off],
                    data[loc_off + 1],
                    data[loc_off + 2],
                    data[loc_off + 3],
                ]))),
                _ => None,
            };
            if let Some(pc) = pc
                && pc != 0
            {
                out.push(FunctionBoundary::new(
                    Address::new(pc),
                    Confidence::Certain,
                    DetectionSource::ExceptionHandler,
                ));
                // Guard against memory exhaustion from crafted .eh_frame blobs.
                if out.len() >= EH_FRAME_MAX_FDES {
                    return out;
                }
            }
        }
        off = record_start + len;
    }
    out
}

// ─────────────────────────────────────────────────────────────────────────────
// Strategy 5: symbols
// ─────────────────────────────────────────────────────────────────────────────

/// A function symbol contributed by the symbol table / exports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FunctionSymbol {
    /// Address of the symbol.
    pub address: Address,
    /// Symbol name.
    pub name: String,
}

/// Turn function symbols into authoritative boundaries.
#[must_use]
pub fn boundaries_from_symbols(symbols: &[FunctionSymbol]) -> Vec<FunctionBoundary> {
    symbols
        .iter()
        .map(|s| {
            FunctionBoundary::new(s.address, Confidence::Certain, DetectionSource::SymbolTable)
                .with_name(s.name.clone())
        })
        .collect()
}

// ─────────────────────────────────────────────────────────────────────────────
// Strategy 8/9 helpers: linear sweep & recursive descent over x86 CALL
// ─────────────────────────────────────────────────────────────────────────────

/// Recursive descent following x86 `CALL rel32` (`E8`) edges from a set of
/// seed entry points, bounded by `max_funcs`.
#[must_use]
pub fn recursive_descent_x86(
    mem: &MemorySlice<'_>,
    seeds: &[Address],
    max_funcs: usize,
) -> Vec<FunctionBoundary> {
    let mut visited: HashSet<u64> = HashSet::new();
    let mut work: VecDeque<u64> = seeds.iter().map(|a| a.as_u64()).collect();
    let base = mem.base.as_u64();
    let end = base.saturating_add(mem.len() as u64);

    while let Some(addr) = work.pop_front() {
        if visited.len() >= max_funcs {
            break;
        }
        if addr < base || addr >= end || !visited.insert(addr) {
            continue;
        }
        // Scan forward up to a cap looking for CALL rel32 and a terminator.
        let mut off = usize::try_from(addr - base).unwrap_or(usize::MAX);
        let scan_cap = (off + 4096).min(mem.bytes.len());
        while off < scan_cap {
            let b = mem.bytes[off];
            if b == 0xE8 && off + 5 <= mem.bytes.len() {
                let rel = i32::from_le_bytes([
                    mem.bytes[off + 1],
                    mem.bytes[off + 2],
                    mem.bytes[off + 3],
                    mem.bytes[off + 4],
                ]);
                let next_ip = base + off as u64 + 5;
                let target = next_ip.wrapping_add_signed(i64::from(rel));
                if target >= base && target < end {
                    work.push_back(target);
                }
                off += 5;
                continue;
            }
            // 0xC3 = RET terminates the linear scan of this function.
            if b == 0xC3 {
                break;
            }
            off += 1;
        }
    }

    let mut starts: Vec<u64> = visited.into_iter().collect();
    starts.sort_unstable();
    starts
        .into_iter()
        .map(|a| {
            FunctionBoundary::new(
                Address::new(a),
                Confidence::Medium,
                DetectionSource::HeuristicGap,
            )
        })
        .collect()
}

// ─────────────────────────────────────────────────────────────────────────────
// Confidence lattice
// ─────────────────────────────────────────────────────────────────────────────

/// Evidence accumulated for a single candidate function address from one or
/// more strategies.
#[derive(Debug, Clone)]
pub struct CandidateEvidence {
    /// Candidate address.
    pub address: Address,
    /// Strategies that voted for this address.
    pub sources: Vec<StrategyKind>,
    /// Best end address proposed by any strategy.
    pub end: Option<Address>,
    /// Best name proposed by any strategy.
    pub name: Option<String>,
}

impl CandidateEvidence {
    /// The maximum single-strategy confidence among all voters.
    #[must_use]
    pub fn peak_confidence(&self) -> Confidence {
        self.sources
            .iter()
            .map(|s| s.base_confidence())
            .max()
            .unwrap_or(Confidence::Low)
    }

    /// Number of distinct strategies that agree on this address.
    #[must_use]
    pub fn agreement(&self) -> usize {
        let mut s: Vec<StrategyKind> = self.sources.clone();
        s.sort_unstable();
        s.dedup();
        s.len()
    }

    /// Fused confidence: the lattice *joins* evidence so that multiple
    /// independent weak signals can corroborate into a stronger one, while a
    /// single authoritative source already saturates the lattice.
    #[must_use]
    pub fn fused_confidence(&self) -> Confidence {
        let peak = self.peak_confidence();
        if peak == Confidence::Certain {
            return Confidence::Certain;
        }
        // Two or more agreeing strategies promote one level.
        if self.agreement() >= 2 {
            return match peak {
                Confidence::Low => Confidence::Medium,
                Confidence::Medium => Confidence::High,
                other => other,
            };
        }
        peak
    }
}

/// Fuses candidate boundaries from many strategies, resolving conflicts.
///
/// The lattice is keyed by address and uses [`CandidateEvidence::fused_confidence`]
/// to produce the final per-address verdict.  Overlapping candidates with
/// differing start addresses are *not* merged here (that is left to body
/// recovery); the lattice only deduplicates identical entry points.
#[derive(Debug, Default)]
pub struct ConfidenceLattice {
    evidence: BTreeMap<u64, CandidateEvidence>,
}

impl ConfidenceLattice {
    /// Create an empty lattice.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record one boundary that was produced by `strategy`.
    pub fn add(&mut self, strategy: StrategyKind, boundary: &FunctionBoundary) {
        let key = boundary.start.as_u64();
        let entry = self
            .evidence
            .entry(key)
            .or_insert_with(|| CandidateEvidence {
                address: boundary.start,
                sources: Vec::new(),
                end: None,
                name: None,
            });
        entry.sources.push(strategy);
        // Prefer the largest known end (the most complete body estimate).
        if let Some(end) = boundary.end {
            entry.end = Some(match entry.end {
                Some(prev) if prev.as_u64() >= end.as_u64() => prev,
                _ => end,
            });
        }
        if entry.name.is_none()
            && let Some(n) = &boundary.name
        {
            entry.name = Some(n.clone());
        }
    }

    /// Bulk-add all boundaries from a single strategy.
    pub fn add_all(&mut self, strategy: StrategyKind, boundaries: &[FunctionBoundary]) {
        for b in boundaries {
            self.add(strategy, b);
        }
    }

    /// Number of distinct candidate addresses.
    #[must_use]
    pub fn len(&self) -> usize {
        self.evidence.len()
    }

    /// Whether the lattice holds no candidates.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.evidence.is_empty()
    }

    /// Look up the accumulated evidence for an address.
    #[must_use]
    pub fn evidence_at(&self, addr: Address) -> Option<&CandidateEvidence> {
        self.evidence.get(&addr.as_u64())
    }

    /// Resolve the lattice into final boundaries, dropping any candidate whose
    /// fused confidence is below `min`.  Results are sorted by address and each
    /// carries the source of its highest-confidence voter.
    #[must_use]
    pub fn resolve(&self, min: Confidence) -> Vec<FunctionBoundary> {
        let mut out: Vec<FunctionBoundary> = Vec::new();
        for ev in self.evidence.values() {
            let conf = ev.fused_confidence();
            if conf < min {
                continue;
            }
            // The persisted source is that of the highest-confidence voter.
            let best = ev
                .sources
                .iter()
                .max_by_key(|s| s.base_confidence())
                .copied()
                .unwrap_or(StrategyKind::LinearSweep);
            let mut b = FunctionBoundary::new(ev.address, conf, best.to_source());
            if let Some(end) = ev.end {
                b = b.with_end(end);
            }
            if let Some(n) = &ev.name {
                b = b.with_name(n.clone());
            }
            out.push(b);
        }
        out.sort_by_key(|b| b.start.as_u64());
        out
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// StrategyEngine
// ─────────────────────────────────────────────────────────────────────────────

/// Inputs available to the [`StrategyEngine`].  Any field left empty disables
/// the corresponding strategy.
pub struct StrategyInputs<'a> {
    /// Raw PE `.pdata` bytes.
    pub pdata: Option<&'a [u8]>,
    /// PE image base for `.pdata` RVA resolution.
    pub image_base: Address,
    /// Mach-O `LC_FUNCTION_STARTS` payload + text base.
    pub macho_starts: Option<(&'a [u8], Address)>,
    /// ARM `.ARM.exidx` section bytes + section address.
    pub arm_exidx: Option<(&'a [u8], Address)>,
    /// DWARF `.eh_frame` bytes + pointer size.
    pub eh_frame: Option<(&'a [u8], u8)>,
    /// Function symbols.
    pub symbols: &'a [FunctionSymbol],
    /// Recursive-descent seed addresses.
    pub seeds: &'a [Address],
}

impl Default for StrategyInputs<'_> {
    fn default() -> Self {
        Self {
            pdata: None,
            image_base: Address::NULL,
            macho_starts: None,
            arm_exidx: None,
            eh_frame: None,
            symbols: &[],
            seeds: &[],
        }
    }
}

/// Drives all applicable strategies and fuses results through the lattice.
pub struct StrategyEngine {
    /// Target architecture.
    pub arch: DetectedArch,
    /// Maximum functions to discover via recursive descent.
    pub max_descent: usize,
}

impl StrategyEngine {
    /// Create an engine for `arch`.
    #[must_use]
    pub const fn new(arch: DetectedArch) -> Self {
        Self {
            arch,
            max_descent: 4096,
        }
    }

    /// Run every applicable strategy against `mem` + `inputs`, returning the
    /// populated [`ConfidenceLattice`].
    #[must_use]
    pub fn run(&self, mem: &MemorySlice<'_>, inputs: &StrategyInputs<'_>) -> ConfidenceLattice {
        let mut lattice = ConfidenceLattice::new();

        if let Some(pdata) = inputs.pdata {
            let entries = parse_pdata(pdata);
            let bounds = boundaries_from_pdata(inputs.image_base, &entries);
            lattice.add_all(StrategyKind::ExceptionDirectory, &bounds);

            // Gap F: recover functions present in .text but missing from .pdata.
            // Only meaningful on x86_64 where the prologue tables apply.
            if matches!(self.arch, DetectedArch::X86_64 | DetectedArch::Unknown) {
                let text_range = AddressRange::new(mem.base, mem.end());
                let (extras, _stats) = find_extra_pdata_funcs(
                    inputs.image_base,
                    text_range,
                    mem.bytes,
                    &entries,
                );
                lattice.add_all(StrategyKind::LinearSweep, &extras);
            }
        }
        if let Some((payload, base)) = inputs.macho_starts {
            let bounds = parse_macho_function_starts(base, payload);
            lattice.add_all(StrategyKind::MachOFunctionStarts, &bounds);
        }
        if let Some((data, addr)) = inputs.arm_exidx {
            let bounds = parse_arm_exidx(addr, data);
            lattice.add_all(StrategyKind::ArmExidx, &bounds);
        }
        if let Some((data, ptr)) = inputs.eh_frame {
            let bounds = parse_eh_frame_fdes(data, ptr);
            lattice.add_all(StrategyKind::DwarfEhFrame, &bounds);
        }
        if !inputs.symbols.is_empty() {
            let bounds = boundaries_from_symbols(inputs.symbols);
            lattice.add_all(StrategyKind::Symbols, &bounds);
        }

        // Prologue + call-target scans reuse the existing detector helpers.
        let detector = crate::FunctionDetector::new(self.arch);
        let prologues = detector.scan_prologues(mem);
        lattice.add_all(StrategyKind::PrologueSignature, &prologues);
        let calls = detector.collect_call_targets(mem);
        lattice.add_all(StrategyKind::CallTargets, &calls);

        // Recursive descent (also yields a linear-sweep-like superset).
        if !inputs.seeds.is_empty() && self.arch != DetectedArch::Arm64 {
            let rd = recursive_descent_x86(mem, inputs.seeds, self.max_descent);
            lattice.add_all(StrategyKind::RecursiveDescent, &rd);
        }

        lattice
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_pdata_three_entries() {
        let mut data = Vec::new();
        let recs: [(u32, u32, u32); 3] = [
            (0x1000, 0x1040, 0x9000),
            (0x1040, 0x1080, 0x9010),
            (0x1080, 0x10c0, 0x9020),
        ];
        for (b, e, u) in recs {
            data.extend_from_slice(&b.to_le_bytes());
            data.extend_from_slice(&e.to_le_bytes());
            data.extend_from_slice(&u.to_le_bytes());
        }
        let entries = parse_pdata(&data);
        assert_eq!(entries.len(), 3);
        let bounds = boundaries_from_pdata(Address::new(0x40_0000), &entries);
        assert_eq!(bounds[0].start, Address::new(0x40_1000));
        assert_eq!(bounds[0].end, Some(Address::new(0x40_1040)));
        assert_eq!(bounds[0].confidence, Confidence::Certain);
    }

    #[test]
    fn pdata_stops_at_zero_record() {
        let mut data = Vec::new();
        data.extend_from_slice(&0x1000u32.to_le_bytes());
        data.extend_from_slice(&0x1040u32.to_le_bytes());
        data.extend_from_slice(&0x9000u32.to_le_bytes());
        data.extend_from_slice(&[0u8; 12]); // terminator
        data.extend_from_slice(&0x2000u32.to_le_bytes()); // should be ignored
        let entries = parse_pdata(&data);
        assert_eq!(entries.len(), 1);
    }

    #[test]
    fn uleb128_decoding() {
        let data = [0xe5, 0x8e, 0x26]; // 624485
        let mut pos = 0;
        assert_eq!(read_uleb128(&data, &mut pos), Some(624_485));
        assert_eq!(pos, 3);
    }

    #[test]
    fn macho_function_starts_deltas() {
        // text base 0x4000; deltas 0x10, 0x20, 0x8; then 0 terminator.
        let payload = [0x10, 0x20, 0x08, 0x00];
        let bounds = parse_macho_function_starts(Address::new(0x4000), &payload);
        assert_eq!(bounds.len(), 3);
        assert_eq!(bounds[0].start, Address::new(0x4010));
        assert_eq!(bounds[1].start, Address::new(0x4030));
        assert_eq!(bounds[2].start, Address::new(0x4038));
    }

    #[test]
    fn arm_exidx_prel31_positive() {
        // Entry at section addr 0x8000, prel31 offset +0x100 -> func at 0x8100.
        let off: u32 = 0x100;
        let mut data = Vec::new();
        data.extend_from_slice(&off.to_le_bytes());
        data.extend_from_slice(&0x8000_0000u32.to_le_bytes()); // exception data
        let bounds = parse_arm_exidx(Address::new(0x8000), &data);
        assert_eq!(bounds.len(), 1);
        assert_eq!(bounds[0].start, Address::new(0x8100));
    }

    #[test]
    fn eh_frame_extracts_fde_pc() {
        // CIE: len=4, id=0, then 4 bytes padding-ish.
        let mut data = Vec::new();
        // CIE record: length 4, cie_id 0, body 4 bytes.
        data.extend_from_slice(&4u32.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes());
        // FDE record: length 12, cie_ptr nonzero, initial_location 8 bytes, pad.
        data.extend_from_slice(&12u32.to_le_bytes());
        data.extend_from_slice(&4u32.to_le_bytes()); // cie pointer (nonzero => FDE)
        data.extend_from_slice(&0x4010u64.to_le_bytes()); // initial location
        let bounds = parse_eh_frame_fdes(&data, 8);
        assert_eq!(bounds.len(), 1);
        assert_eq!(bounds[0].start, Address::new(0x4010));
    }

    #[test]
    fn lattice_promotes_corroborating_evidence() {
        let mut lat = ConfidenceLattice::new();
        let b = FunctionBoundary::new(
            Address::new(0x100),
            Confidence::Low,
            DetectionSource::HeuristicGap,
        );
        lat.add(StrategyKind::LinearSweep, &b);
        // Single weak signal stays Low.
        assert_eq!(
            lat.evidence_at(Address::new(0x100))
                .unwrap()
                .fused_confidence(),
            Confidence::Low
        );
        // Add a second independent weak source -> promoted to Medium.
        lat.add(StrategyKind::RecursiveDescent, &b);
        let ev = lat.evidence_at(Address::new(0x100)).unwrap();
        assert_eq!(ev.agreement(), 2);
        assert_eq!(ev.fused_confidence(), Confidence::High); // medium peak + agreement
    }

    #[test]
    fn lattice_certain_saturates() {
        let mut lat = ConfidenceLattice::new();
        let sym = FunctionBoundary::new(
            Address::new(0x200),
            Confidence::Certain,
            DetectionSource::SymbolTable,
        );
        lat.add(StrategyKind::Symbols, &sym);
        assert_eq!(
            lat.evidence_at(Address::new(0x200))
                .unwrap()
                .fused_confidence(),
            Confidence::Certain
        );
    }

    #[test]
    fn lattice_resolve_filters_and_sorts() {
        let mut lat = ConfidenceLattice::new();
        lat.add(
            StrategyKind::LinearSweep,
            &FunctionBoundary::new(
                Address::new(0x300),
                Confidence::Low,
                DetectionSource::HeuristicGap,
            ),
        );
        lat.add(
            StrategyKind::Symbols,
            &FunctionBoundary::new(
                Address::new(0x100),
                Confidence::Certain,
                DetectionSource::SymbolTable,
            ),
        );
        // Only the Certain entry survives a High threshold.
        let resolved = lat.resolve(Confidence::High);
        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved[0].start, Address::new(0x100));
    }

    #[test]
    fn lattice_keeps_largest_end_and_name() {
        let mut lat = ConfidenceLattice::new();
        let b1 = FunctionBoundary::new(
            Address::new(0x100),
            Confidence::Certain,
            DetectionSource::SymbolTable,
        )
        .with_end(Address::new(0x140))
        .with_name("foo");
        let b2 = FunctionBoundary::new(
            Address::new(0x100),
            Confidence::High,
            DetectionSource::CallTarget,
        )
        .with_end(Address::new(0x180));
        lat.add(StrategyKind::Symbols, &b1);
        lat.add(StrategyKind::CallTargets, &b2);
        let resolved = lat.resolve(Confidence::Low);
        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved[0].end, Some(Address::new(0x180)));
        assert_eq!(resolved[0].name.as_deref(), Some("foo"));
    }

    #[test]
    fn recursive_descent_follows_calls() {
        // E8 call at 0 -> target; RET at end.
        // base 0x1000. call rel32 at off 0: next_ip=0x1005, rel=0x10 -> 0x1015.
        let mut bytes = vec![0xE8, 0x10, 0x00, 0x00, 0x00];
        bytes.extend_from_slice(&[0x90; 0x10]); // padding up to 0x15
        bytes.push(0xC3); // ret in callee region
        let mem = MemorySlice::new(Address::new(0x1000), &bytes);
        let found = recursive_descent_x86(&mem, &[Address::new(0x1000)], 16);
        assert!(found.iter().any(|b| b.start == Address::new(0x1000)));
        assert!(found.iter().any(|b| b.start == Address::new(0x1015)));
    }

    #[test]
    fn strategy_kind_metadata() {
        assert_eq!(StrategyKind::Symbols.base_confidence(), Confidence::Certain);
        assert_eq!(StrategyKind::LinearSweep.base_confidence(), Confidence::Low);
        assert_eq!(
            StrategyKind::CallTargets.to_source(),
            DetectionSource::CallTarget
        );
        assert_eq!(
            StrategyKind::ExceptionDirectory.name(),
            "exception_directory"
        );
    }

    #[test]
    fn engine_runs_metadata_strategies() {
        let bytes = vec![0x90u8; 64];
        let mem = MemorySlice::new(Address::new(0x1000), &bytes);
        let starts: [u8; 2] = [0x10, 0x00];
        let syms = vec![FunctionSymbol {
            address: Address::new(0x1000),
            name: "main".into(),
        }];
        let inputs = StrategyInputs {
            macho_starts: Some((&starts, Address::new(0x2000))),
            symbols: &syms,
            ..Default::default()
        };
        let engine = StrategyEngine::new(DetectedArch::X86_64);
        let lattice = engine.run(&mem, &inputs);
        assert!(lattice.evidence_at(Address::new(0x1000)).is_some());
        assert!(lattice.evidence_at(Address::new(0x2010)).is_some());
        let resolved = lattice.resolve(Confidence::Certain);
        assert!(resolved.iter().any(|b| b.name.as_deref() == Some("main")));
    }
}
