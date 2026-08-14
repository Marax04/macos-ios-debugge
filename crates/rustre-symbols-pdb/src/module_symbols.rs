//! `module_symbols` — per-module (compiland) symbol stream parser.
//!
//! Each module (object file / import library entry) in a `PDB` has its own
//! symbol sub-stream that contains procedure symbols, local variables,
//! parameter descriptions, frame layout records and debug range annotations.
//!
//! This module parses the most important per-module symbol record types:
//!
//! | Record | Description |
//! |--------|-------------|
//! | `S_GPROC32` / `S_LPROC32` | Global / local procedure definition |
//! | `S_BLOCK32`  | Lexical block (sub-scope) |
//! | `S_END`      | End of scope (proc / block) |
//! | `S_LOCAL`    | Local variable (`CodeView` 4.x) |
//! | `S_REGREL32` | Variable at `[reg + offset]` |
//! | `S_FRAMEPROC`| Frame layout metadata |
//! | `S_DEFRANGE_REGISTER`      | Live range for register variable |
//! | `S_DEFRANGE_FRAMEPOINTER_REL` | Live range for frame-pointer-relative var |
//! | `S_DEFRANGE_REGISTER_REL`  | Live range for reg-relative variable |
//! | `S_CALLEES` / `S_CALLERS`  | Inlinee call-graph edges |
//! | `S_INLINESITE` / `S_INLINESITE_END` | Inline site markers |

use serde::{Deserialize, Serialize};

use crate::stream_reader::StreamReader;
use crate::{PdbError, Result};

// ── Symbol record type codes used in per-module streams ──────────────────────

const S_END: u16 = 0x0006;
const S_FRAMEPROC: u16 = 0x1012;
const S_BLOCK32: u16 = 0x1103;
// Single source of truth: `crate::sym_kinds` (cvinfo.h SYM_ENUM_e).
use crate::sym_kinds::{S_GPROC32, S_LPROC32, S_REGREL32};
const S_LOCAL: u16 = 0x113E;
const S_DEFRANGE_REGISTER: u16 = 0x1141;
const S_DEFRANGE_FRAMEPOINTER_REL: u16 = 0x1142;
const S_DEFRANGE_REGISTER_REL: u16 = 0x1145;
const S_CALLEES: u16 = 0x115A;
const S_CALLERS: u16 = 0x115B;
const S_INLINESITE: u16 = 0x114D;
const S_LPROC32_DPC: u16 = 0x1155;
const S_GPROC32_DPC: u16 = 0x1156;
const S_PROC_ID_END: u16 = 0x114F;

// ── Address range ─────────────────────────────────────────────────────────────

/// A half-open address range `[offset, offset + length)` within a PE section.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AddressRange {
    /// Byte offset within the section (or from a base register).
    pub offset: i32,
    /// Length in bytes.
    pub length: u16,
}

impl AddressRange {
    /// True when `addr` (an offset from the same base) is within the range.
    #[must_use]
    pub fn contains(&self, addr: i32) -> bool {
        addr >= self.offset && addr < self.offset + i32::from(self.length)
    }
}

// ── LiveRange ─────────────────────────────────────────────────────────────────

/// One contiguous live range for a variable, pairing an `AddressRange` with
/// optional gap bitfields that mark sub-ranges where the variable is dead.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LiveRange {
    /// The section-relative address range where the variable is live.
    pub range: AddressRange,
    /// Gap bytes — pairs of (`gap_start_offset`: u16, `gap_length`: u16) relative
    /// to `range.offset`.
    pub gaps: Vec<(u16, u16)>,
}

// ── Variable storage locations ────────────────────────────────────────────────

/// Where a local variable lives in memory or registers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum VariableStorage {
    /// Variable is held in a CPU register (CV register index).
    Register(u16),
    /// Variable is at `[frame_pointer + offset]`.
    FrameRelative(i32),
    /// Variable is at `[register + offset]` for an arbitrary base register.
    RegisterRelative {
        /// CV register index of the base register.
        register: u16,
        /// Signed byte offset from the base register.
        offset: i32,
    },
    /// No concrete storage information available.
    Unknown,
}

// ── LocalVar ──────────────────────────────────────────────────────────────────

/// A local variable or function parameter in a compiland symbol stream.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalVar {
    /// Variable name.
    pub name: String,
    /// `CodeView` type index.
    pub type_index: u32,
    /// How the variable is stored.
    pub storage: VariableStorage,
    /// True when this is a function parameter.
    pub is_parameter: bool,
    /// True when the variable has been optimised away (may have ranges).
    pub is_optimized_away: bool,
    /// True when the address of this variable has been taken.
    pub is_address_taken: bool,
    /// Live ranges describing where the value is valid.
    pub live_ranges: Vec<LiveRange>,
}

// ── FrameLayout ───────────────────────────────────────────────────────────────

/// Frame layout information from an `S_FRAMEPROC` record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FrameLayout {
    /// Total number of bytes in the local variable area of the frame.
    pub frame_size: u32,
    /// Padding bytes added to the frame by the compiler.
    pub pad_size: u32,
    /// Offset of the pad from the start of locals.
    pub pad_offset: u32,
    /// Number of bytes of callee-saved registers.
    pub saved_regs_size: u32,
    /// Register used as the exception handler data pointer.
    pub eh_reg: u16,
    /// Offset of the exception handler data pointer relative to EH register.
    pub eh_offset: u32,
    /// Raw frame-proc flags word.
    pub flags: u32,
}

impl FrameLayout {
    /// True when the function uses alloca or has a variable-size frame.
    #[must_use]
    pub const fn has_alloca(&self) -> bool {
        self.flags & 0x0002 != 0
    }

    /// True when structured exception handling (SEH) is used.
    #[must_use]
    pub const fn has_seh(&self) -> bool {
        self.flags & 0x0008 != 0
    }

    /// True when C++ EH (`__try` / `__except`) is in use.
    #[must_use]
    pub const fn has_cpp_eh(&self) -> bool {
        self.flags & 0x0010 != 0
    }

    /// True when the function has a security cookie (`/GS`).
    #[must_use]
    pub const fn has_security_cookie(&self) -> bool {
        self.flags & 0x0004 != 0
    }

    /// True when the frame pointer is omitted (FPO).
    #[must_use]
    pub const fn is_fpo(&self) -> bool {
        self.flags & 0x0100 != 0
    }
}

// ── LexicalBlock ──────────────────────────────────────────────────────────────

/// A lexical scope block (`S_BLOCK32`) nested inside a procedure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LexicalBlock {
    /// Code offset (from the procedure's start) where this block begins.
    pub code_offset: u32,
    /// PE section number.
    pub segment: u16,
    /// Byte length of the block.
    pub length: u32,
    /// Optional block name (usually empty).
    pub name: String,
    /// Variables declared in this block.
    pub locals: Vec<LocalVar>,
    /// Nested child blocks.
    pub children: Vec<Self>,
}

// ── InlineSite ────────────────────────────────────────────────────────────────

/// An inlined call-site record (`S_INLINESITE`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InlineSite {
    /// The inlinee type index (points to an `LF_FUNC_ID` in the `IPI` stream).
    pub inlinee: u32,
    /// Encoded binary annotations (pairs of annotated lines / code offsets).
    pub binary_annotations: Vec<u8>,
}

// ── ProcSymbol ────────────────────────────────────────────────────────────────

/// A procedure symbol (`S_GPROC32` / `S_LPROC32`) from a per-module stream.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcSymbol {
    /// Procedure name (may be mangled).
    pub name: String,
    /// Code offset within the PE section.
    pub code_offset: u32,
    /// PE section number (1-based).
    pub segment: u16,
    /// Total byte length of the procedure code.
    pub code_size: u32,
    /// Offset from `code_offset` where debuggable code begins.
    pub dbg_start: u32,
    /// Offset from `code_offset` where the epilogue begins.
    pub dbg_end: u32,
    /// `CodeView` type index for the procedure type.
    pub type_index: u32,
    /// `CV_PFLAG` byte: inlines, no-return, custom calling convention, etc.
    pub flags: u8,
    /// True when this is a global (externally visible) procedure.
    pub is_global: bool,
    /// Frame layout information (from the immediately following `S_FRAMEPROC`).
    pub frame_layout: Option<FrameLayout>,
    /// Local variables and parameters belonging to this procedure.
    pub locals: Vec<LocalVar>,
    /// Lexical blocks nested inside this procedure.
    pub blocks: Vec<LexicalBlock>,
    /// Inlined call sites inside this procedure.
    pub inline_sites: Vec<InlineSite>,
    /// Symbols (type indices) of functions this procedure calls (from `S_CALLEES`).
    pub callees: Vec<u32>,
    /// Symbols (type indices) of functions that call this one (from `S_CALLERS`).
    pub callers: Vec<u32>,
}

impl ProcSymbol {
    /// True when the procedure never returns (`CV_PFLAG_NOFPO` | noreturn bits).
    #[must_use]
    pub const fn is_noreturn(&self) -> bool {
        self.flags & 0x01 != 0
    }

    /// True when the frame pointer is omitted (FPO / leaf function).
    #[must_use]
    pub fn is_fpo(&self) -> bool {
        // CV_PFLAG_NOFPO = 0x04 means frame pointer IS present; absence → FPO.
        self.frame_layout.as_ref().is_some_and(FrameLayout::is_fpo)
    }

    /// Compute the `RVA` of this procedure given the section `RVA` base.
    ///
    /// The caller must supply a function that maps a 1-based section index to
    /// its image `RVA`.  Returns `None` if the section index is out of range.
    #[must_use]
    pub fn rva(&self, section_rva: impl Fn(u16) -> Option<u32>) -> Option<u64> {
        section_rva(self.segment).map(|base| u64::from(base) + u64::from(self.code_offset))
    }
}

// ── ModuleSymbols ─────────────────────────────────────────────────────────────

/// All parsed symbols for one compiland (object file / import library entry).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ModuleSymbols {
    /// All procedures found in this module's symbol stream.
    pub procedures: Vec<ProcSymbol>,
    /// Module-level locals that live outside any procedure (unusual but legal).
    pub globals: Vec<LocalVar>,
}

impl ModuleSymbols {
    /// Create an empty symbol set.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Find a procedure by name.
    #[must_use]
    pub fn find_proc(&self, name: &str) -> Option<&ProcSymbol> {
        self.procedures.iter().find(|p| p.name == name)
    }

    /// Total number of local variables across all procedures.
    #[must_use]
    pub fn total_locals(&self) -> usize {
        self.procedures
            .iter()
            .map(|p| p.locals.len())
            .sum::<usize>()
            + self.globals.len()
    }

    /// Total number of inlined sites across all procedures.
    #[must_use]
    pub fn total_inline_sites(&self) -> usize {
        self.procedures.iter().map(|p| p.inline_sites.len()).sum()
    }
}

// ── Parser ────────────────────────────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
fn dispatch_record(
    rdr: &mut StreamReader<'_>,
    rec_type: u16,
    payload_len: usize,
    rec_start: usize,
    payload_end: usize,
    result: &mut ModuleSymbols,
    proc_stack: &mut Vec<ProcSymbol>,
    block_stack: &mut Vec<LexicalBlock>,
) -> Result<()> {
    match rec_type {
        S_GPROC32 | S_LPROC32 | S_GPROC32_DPC | S_LPROC32_DPC => {
            let sym = parse_proc_record(rdr, rec_type, payload_len)?;
            proc_stack.push(sym);
        }
        S_FRAMEPROC => {
            let fl = parse_frameproc(rdr, payload_len)?;
            if let Some(top) = proc_stack.last_mut() {
                top.frame_layout = Some(fl);
            }
        }
        S_BLOCK32 => {
            let blk = parse_block32(rdr, payload_len)?;
            block_stack.push(blk);
        }
        S_LOCAL => {
            let lv = parse_local(rdr, payload_len)?;
            if let Some(blk) = block_stack.last_mut() {
                blk.locals.push(lv);
            } else if let Some(proc_sym) = proc_stack.last_mut() {
                proc_sym.locals.push(lv);
            } else {
                result.globals.push(lv);
            }
        }
        S_REGREL32 => {
            let lv = parse_regrel32(rdr, payload_len)?;
            if let Some(blk) = block_stack.last_mut() {
                blk.locals.push(lv);
            } else if let Some(proc_sym) = proc_stack.last_mut() {
                proc_sym.locals.push(lv);
            } else {
                result.globals.push(lv);
            }
        }
        S_DEFRANGE_REGISTER => {
            parse_defrange_register(rdr, payload_len)?;
        }
        S_DEFRANGE_FRAMEPOINTER_REL => {
            parse_defrange_fp_rel(rdr, payload_len)?;
        }
        S_DEFRANGE_REGISTER_REL => {
            parse_defrange_reg_rel(rdr, payload_len)?;
        }
        S_CALLEES => {
            let indices = parse_callee_caller_list(rdr, payload_len)?;
            if let Some(proc_sym) = proc_stack.last_mut() {
                proc_sym.callees.extend(indices);
            }
        }
        S_CALLERS => {
            let indices = parse_callee_caller_list(rdr, payload_len)?;
            if let Some(proc_sym) = proc_stack.last_mut() {
                proc_sym.callers.extend(indices);
            }
        }
        S_INLINESITE => {
            let site = parse_inline_site(rdr, rec_start, payload_end)?;
            if let Some(proc_sym) = proc_stack.last_mut() {
                proc_sym.inline_sites.push(site);
            }
        }
        S_END | S_PROC_ID_END => {
            if let Some(blk) = block_stack.pop() {
                if let Some(parent_blk) = block_stack.last_mut() {
                    parent_blk.children.push(blk);
                } else if let Some(proc_sym) = proc_stack.last_mut() {
                    proc_sym.blocks.push(blk);
                }
            } else if let Some(proc_sym) = proc_stack.pop() {
                result.procedures.push(proc_sym);
            }
        }
        _ => {}
    }
    Ok(())
}

/// Parse a raw per-module symbol stream into a `ModuleSymbols` record.
///
/// The stream starts at the first symbol record (the `DBI` module entry already
/// indicates the byte length of the symbol sub-stream).
///
/// # Errors
/// Returns an error if parsing/reading fails.
pub fn parse_module_symbols(data: &[u8]) -> Result<ModuleSymbols> {
    let mut rdr = StreamReader::new(data);
    let mut result = ModuleSymbols::new();
    let mut proc_stack: Vec<ProcSymbol> = Vec::new();
    let mut block_stack: Vec<LexicalBlock> = Vec::new();

    while rdr.remaining() >= 4 {
        let rec_start = rdr.pos();
        let length = rdr.read_u16()? as usize;
        if length < 2 {
            break;
        }
        let rec_type = rdr.read_u16()?;
        let payload_len = length.saturating_sub(2);
        let payload_end = rec_start + 2 + length;

        dispatch_record(
            &mut rdr,
            rec_type,
            payload_len,
            rec_start,
            payload_end,
            &mut result,
            &mut proc_stack,
            &mut block_stack,
        )?;

        // Advance to the next 4-byte aligned record boundary.
        let aligned = (2 + length + 3) & !3;
        let consumed = rdr.pos() - rec_start;
        if aligned > consumed {
            let _ = rdr.skip(aligned - consumed);
        } else if rdr.pos() < payload_end {
            rdr.seek(payload_end);
        }
    }

    // Drain any unclosed procedures (malformed stream resilience).
    for proc_sym in proc_stack {
        result.procedures.push(proc_sym);
    }

    Ok(result)
}

// ── Internal record parsers ───────────────────────────────────────────────────

fn parse_proc_record(
    rdr: &mut StreamReader<'_>,
    rec_type: u16,
    _payload_len: usize,
) -> Result<ProcSymbol> {
    // Layout:
    // parent(4) + end(4) + next(4) + len(4) + dbg_start(4) + dbg_end(4)
    // + typind(4) + offset(4) + segment(2) + flags(1) + name(nul)
    if rdr.remaining() < 36 {
        return Err(PdbError::StreamTooShort);
    }
    let _parent = rdr.read_u32()?;
    let _end = rdr.read_u32()?;
    let _next = rdr.read_u32()?;
    let code_size = rdr.read_u32()?;
    let dbg_start = rdr.read_u32()?;
    let dbg_end = rdr.read_u32()?;
    let type_index = rdr.read_u32()?;
    let code_offset = rdr.read_u32()?;
    let segment = rdr.read_u16()?;
    let flags = rdr.read_u8()?;
    let name = rdr.read_cstring().unwrap_or_default();

    let is_global = matches!(rec_type, S_GPROC32 | S_GPROC32_DPC);

    Ok(ProcSymbol {
        name,
        code_offset,
        segment,
        code_size,
        dbg_start,
        dbg_end,
        type_index,
        flags,
        is_global,
        frame_layout: None,
        locals: Vec::new(),
        blocks: Vec::new(),
        inline_sites: Vec::new(),
        callees: Vec::new(),
        callers: Vec::new(),
    })
}

fn parse_frameproc(rdr: &mut StreamReader<'_>, _payload_len: usize) -> Result<FrameLayout> {
    // Layout:
    // frame_size(4) + pad_size(4) + pad_offset(4) + saved_regs_size(4)
    // + eh_offset(4) + eh_reg(2) + flags(4)
    if rdr.remaining() < 26 {
        return Err(PdbError::StreamTooShort);
    }
    let frame_size = rdr.read_u32()?;
    let pad_size = rdr.read_u32()?;
    let pad_offset = rdr.read_u32()?;
    let saved_regs_size = rdr.read_u32()?;
    let eh_offset = rdr.read_u32()?;
    let eh_reg = rdr.read_u16()?;
    let flags = rdr.read_u32()?;

    Ok(FrameLayout {
        frame_size,
        pad_size,
        pad_offset,
        saved_regs_size,
        eh_reg,
        eh_offset,
        flags,
    })
}

fn parse_block32(rdr: &mut StreamReader<'_>, _payload_len: usize) -> Result<LexicalBlock> {
    // Layout: parent(4) + end(4) + len(4) + offset(4) + segment(2) + name(nul)
    if rdr.remaining() < 18 {
        return Err(PdbError::StreamTooShort);
    }
    let _parent = rdr.read_u32()?;
    let _end = rdr.read_u32()?;
    let length = rdr.read_u32()?;
    let code_offset = rdr.read_u32()?;
    let segment = rdr.read_u16()?;
    let name = rdr.read_cstring().unwrap_or_default();

    Ok(LexicalBlock {
        code_offset,
        segment,
        length,
        name,
        locals: Vec::new(),
        children: Vec::new(),
    })
}

fn parse_local(rdr: &mut StreamReader<'_>, _payload_len: usize) -> Result<LocalVar> {
    // S_LOCAL: typind(4) + flags(2) + name(nul)
    if rdr.remaining() < 6 {
        return Err(PdbError::StreamTooShort);
    }
    let type_index = rdr.read_u32()?;
    let flags = rdr.read_u16()?;
    let name = rdr.read_cstring().unwrap_or_default();

    // CV_LVARFLAGS bit meanings.
    let is_parameter = (flags & 0x0001) != 0;
    let is_address_taken = (flags & 0x0002) != 0;
    let is_optimized_away = (flags & 0x0004) != 0;

    Ok(LocalVar {
        name,
        type_index,
        storage: VariableStorage::Unknown,
        is_parameter,
        is_optimized_away,
        is_address_taken,
        live_ranges: Vec::new(),
    })
}

fn parse_regrel32(rdr: &mut StreamReader<'_>, _payload_len: usize) -> Result<LocalVar> {
    // S_REGREL32: offset(4) + typind(4) + register(2) + name(nul)
    if rdr.remaining() < 10 {
        return Err(PdbError::StreamTooShort);
    }
    let offset = rdr.read_i32()?;
    let type_index = rdr.read_u32()?;
    let register = rdr.read_u16()?;
    let name = rdr.read_cstring().unwrap_or_default();

    // Heuristic: register index 335 (x86-64 RSP) / 335 → frame-relative.
    // We record as RegisterRelative and let the caller interpret.
    let storage = VariableStorage::RegisterRelative { register, offset };

    // Parameters are typically at positive frame offsets; locals at negative.
    let is_parameter = offset > 0;

    Ok(LocalVar {
        name,
        type_index,
        storage,
        is_parameter,
        is_optimized_away: false,
        is_address_taken: false,
        live_ranges: Vec::new(),
    })
}

/// Parse an `S_DEFRANGE_REGISTER` record (register variable live range).
/// Returns the parsed live range for the caller to correlate with the
/// preceding `S_LOCAL`.
fn parse_defrange_register(
    rdr: &mut StreamReader<'_>,
    payload_len: usize,
) -> Result<Option<LiveRange>> {
    // register(2) + may_have_no_name(2) + range(AddressRange=8) + gaps…
    if rdr.remaining() < 12 {
        let _ = rdr.skip(payload_len.min(rdr.remaining()));
        return Ok(None);
    }
    let _register = rdr.read_u16()?;
    let _attrs = rdr.read_u16()?;
    let range_off = rdr.read_i32()?;
    let _isect = rdr.read_u16()?;
    let range_len = rdr.read_u16()?;
    let range = AddressRange {
        offset: range_off,
        length: range_len,
    };

    let bytes_read = 12usize;
    let gap_bytes = payload_len.saturating_sub(bytes_read);
    let num_gaps = gap_bytes / 4;
    let mut gaps = Vec::with_capacity(num_gaps);
    for _ in 0..num_gaps {
        if rdr.remaining() < 4 {
            break;
        }
        let gap_start = rdr.read_u16()?;
        let gap_len = rdr.read_u16()?;
        gaps.push((gap_start, gap_len));
    }
    Ok(Some(LiveRange { range, gaps }))
}

/// Parse an `S_DEFRANGE_FRAMEPOINTER_REL` record.
fn parse_defrange_fp_rel(
    rdr: &mut StreamReader<'_>,
    payload_len: usize,
) -> Result<Option<LiveRange>> {
    // fp_offset(4) + range(8) + gaps…
    if rdr.remaining() < 12 {
        let _ = rdr.skip(payload_len.min(rdr.remaining()));
        return Ok(None);
    }
    let _fp_offset = rdr.read_i32()?;
    let range_off = rdr.read_i32()?;
    let _isect = rdr.read_u16()?;
    let range_len = rdr.read_u16()?;
    let range = AddressRange {
        offset: range_off,
        length: range_len,
    };

    let bytes_read = 12usize;
    let gap_bytes = payload_len.saturating_sub(bytes_read);
    let num_gaps = gap_bytes / 4;
    let mut gaps = Vec::with_capacity(num_gaps);
    for _ in 0..num_gaps {
        if rdr.remaining() < 4 {
            break;
        }
        let gap_start = rdr.read_u16()?;
        let gap_len = rdr.read_u16()?;
        gaps.push((gap_start, gap_len));
    }
    Ok(Some(LiveRange { range, gaps }))
}

/// Parse an `S_DEFRANGE_REGISTER_REL` record.
fn parse_defrange_reg_rel(
    rdr: &mut StreamReader<'_>,
    payload_len: usize,
) -> Result<Option<LiveRange>> {
    // base_reg(2) + spilled_udt_member(2) + offset_parent(4) + range(8) + gaps…
    if rdr.remaining() < 16 {
        let _ = rdr.skip(payload_len.min(rdr.remaining()));
        return Ok(None);
    }
    let _base_reg = rdr.read_u16()?;
    let _flags = rdr.read_u16()?;
    let _offset_parent = rdr.read_i32()?;
    let range_off = rdr.read_i32()?;
    let _isect = rdr.read_u16()?;
    let range_len = rdr.read_u16()?;
    let range = AddressRange {
        offset: range_off,
        length: range_len,
    };

    let bytes_read = 16usize;
    let gap_bytes = payload_len.saturating_sub(bytes_read);
    let num_gaps = gap_bytes / 4;
    let mut gaps = Vec::with_capacity(num_gaps);
    for _ in 0..num_gaps {
        if rdr.remaining() < 4 {
            break;
        }
        let gap_start = rdr.read_u16()?;
        let gap_len = rdr.read_u16()?;
        gaps.push((gap_start, gap_len));
    }
    Ok(Some(LiveRange { range, gaps }))
}

fn parse_callee_caller_list(rdr: &mut StreamReader<'_>, payload_len: usize) -> Result<Vec<u32>> {
    // count(4) + id_0(4) ... id_n-1(4)
    if rdr.remaining() < 4 {
        let _ = rdr.skip(payload_len.min(rdr.remaining()));
        return Ok(Vec::new());
    }
    let count = rdr.read_u32()? as usize;
    let safe_count = count.min(rdr.remaining() / 4).min(payload_len / 4);
    let mut ids = Vec::with_capacity(safe_count);
    for _ in 0..safe_count {
        if rdr.remaining() < 4 {
            break;
        }
        ids.push(rdr.read_u32()?);
    }
    Ok(ids)
}

fn parse_inline_site(
    rdr: &mut StreamReader<'_>,
    rec_start: usize,
    payload_end: usize,
) -> Result<InlineSite> {
    // parent(4) + end(4) + inlinee(4) + binary_annotations(variable)
    if rdr.remaining() < 12 {
        return Ok(InlineSite {
            inlinee: 0,
            binary_annotations: Vec::new(),
        });
    }
    let _parent = rdr.read_u32()?;
    let _end = rdr.read_u32()?;
    let inlinee = rdr.read_u32()?;
    let header_consumed = rdr.pos() - rec_start - 4; // subtract the length/type u16s
    let ann_bytes = payload_end.saturating_sub(rdr.pos()).min(rdr.remaining());
    let binary_annotations = rdr.peek_bytes(ann_bytes).unwrap_or(&[]).to_vec();
    let _ = rdr.skip(ann_bytes);
    let _ = header_consumed; // silences unused-variable warning

    Ok(InlineSite {
        inlinee,
        binary_annotations,
    })
}

// ── Public utilities ──────────────────────────────────────────────────────────

/// Collect all unique source files referenced by local variables that have
/// register-relative storage with a known section (extracted from REGREL32).
///
/// Useful for quick module → source file mapping without full line-info parsing.
#[must_use]
pub fn collect_proc_names(syms: &ModuleSymbols) -> Vec<&str> {
    syms.procedures.iter().map(|p| p.name.as_str()).collect()
}

/// Return the procedure that contains the given code offset + segment, if any.
#[must_use]
pub fn find_proc_at(syms: &ModuleSymbols, segment: u16, offset: u32) -> Option<&ProcSymbol> {
    syms.procedures.iter().find(|p| {
        p.segment == segment && offset >= p.code_offset && offset < p.code_offset + p.code_size
    })
}

/// Estimate parameter count for a procedure by counting `S_REGREL32` or
/// `S_LOCAL` variables with the `is_parameter` flag set.
#[must_use]
pub fn param_count(proc: &ProcSymbol) -> usize {
    proc.locals.iter().filter(|v| v.is_parameter).count()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn frame_record(rec_type: u16, payload: &[u8]) -> Vec<u8> {
        let length = u16::try_from(2 + payload.len()).unwrap();
        let mut v = Vec::new();
        v.extend_from_slice(&length.to_le_bytes());
        v.extend_from_slice(&rec_type.to_le_bytes());
        v.extend_from_slice(payload);
        while v.len() % 4 != 0 {
            v.push(0);
        }
        v
    }

    /// Build a minimal `S_GPROC32` payload followed by `S_END`.
    fn make_proc_stream(name: &str, offset: u32, size: u32) -> Vec<u8> {
        let mut p = Vec::new();
        p.extend_from_slice(&0u32.to_le_bytes()); // parent
        p.extend_from_slice(&0u32.to_le_bytes()); // end
        p.extend_from_slice(&0u32.to_le_bytes()); // next
        p.extend_from_slice(&size.to_le_bytes()); // len
        p.extend_from_slice(&0u32.to_le_bytes()); // dbg_start
        p.extend_from_slice(&size.to_le_bytes()); // dbg_end
        p.extend_from_slice(&0u32.to_le_bytes()); // typind
        p.extend_from_slice(&offset.to_le_bytes()); // code_offset
        p.extend_from_slice(&1u16.to_le_bytes()); // segment
        p.push(0); // flags
        p.extend_from_slice(name.as_bytes());
        p.push(0); // NUL
        let mut stream = frame_record(S_GPROC32, &p);
        stream.extend(frame_record(S_END, &[]));
        stream
    }

    #[test]
    fn test_parse_empty_stream() {
        let m = parse_module_symbols(&[]).unwrap();
        assert!(m.procedures.is_empty());
    }

    #[test]
    fn test_parse_single_proc() {
        let stream = make_proc_stream("TestFunc", 0x1000, 0x100);
        let m = parse_module_symbols(&stream).unwrap();
        assert_eq!(m.procedures.len(), 1);
        assert_eq!(m.procedures[0].name, "TestFunc");
        assert_eq!(m.procedures[0].code_offset, 0x1000);
        assert_eq!(m.procedures[0].code_size, 0x100);
        assert!(m.procedures[0].is_global);
    }

    #[test]
    fn test_parse_multiple_procs() {
        let mut stream = make_proc_stream("Alpha", 0x1000, 0x80);
        stream.extend(make_proc_stream("Beta", 0x2000, 0x40));
        let m = parse_module_symbols(&stream).unwrap();
        assert_eq!(m.procedures.len(), 2);
        assert_eq!(m.procedures[0].name, "Alpha");
        assert_eq!(m.procedures[1].name, "Beta");
    }

    #[test]
    fn test_parse_local_in_proc() {
        let mut local_p = Vec::new();
        local_p.extend_from_slice(&7u32.to_le_bytes()); // type_index
        local_p.extend_from_slice(&0x0001u16.to_le_bytes()); // flags: is_parameter
        local_p.extend_from_slice(b"arg0\x00");

        let mut proc_p = Vec::new();
        for _ in 0..9 {
            proc_p.extend_from_slice(&0u32.to_le_bytes());
        }
        proc_p.extend_from_slice(&1u16.to_le_bytes()); // segment
        proc_p.push(0); // flags
        proc_p.extend_from_slice(b"MyFunc\x00");

        let mut stream = frame_record(S_GPROC32, &proc_p);
        stream.extend(frame_record(S_LOCAL, &local_p));
        stream.extend(frame_record(S_END, &[]));

        let m = parse_module_symbols(&stream).unwrap();
        assert_eq!(m.procedures.len(), 1);
        assert_eq!(m.procedures[0].locals.len(), 1);
        assert_eq!(m.procedures[0].locals[0].name, "arg0");
        assert!(m.procedures[0].locals[0].is_parameter);
    }

    #[test]
    fn test_find_proc_at() {
        let stream = make_proc_stream("Fn", 0x1000, 0x200);
        let m = parse_module_symbols(&stream).unwrap();
        assert!(find_proc_at(&m, 1, 0x1100).is_some());
        assert!(find_proc_at(&m, 1, 0x1200).is_none());
        assert!(find_proc_at(&m, 2, 0x1000).is_none());
    }

    #[test]
    fn test_collect_proc_names() {
        let mut stream = make_proc_stream("Foo", 0x100, 0x10);
        stream.extend(make_proc_stream("Bar", 0x200, 0x20));
        let m = parse_module_symbols(&stream).unwrap();
        let names = collect_proc_names(&m);
        assert!(names.contains(&"Foo"));
        assert!(names.contains(&"Bar"));
    }

    #[test]
    fn test_frame_layout_flags() {
        let mut fp_payload = vec![0u8; 26];
        // flags at offset 22 (after 4+4+4+4+4+2 = 22 bytes)
        let flags: u32 = 0x0008 | 0x0004; // SEH + security cookie
        fp_payload[22..26].copy_from_slice(&flags.to_le_bytes());
        let stream = {
            let mut proc_p = Vec::new();
            for _ in 0..9 {
                proc_p.extend_from_slice(&0u32.to_le_bytes());
            }
            proc_p.extend_from_slice(&1u16.to_le_bytes());
            proc_p.push(0);
            proc_p.extend_from_slice(b"F\x00");
            let mut s = frame_record(S_GPROC32, &proc_p);
            s.extend(frame_record(S_FRAMEPROC, &fp_payload));
            s.extend(frame_record(S_END, &[]));
            s
        };
        let m = parse_module_symbols(&stream).unwrap();
        let fl = m.procedures[0].frame_layout.as_ref().unwrap();
        assert!(fl.has_seh());
        assert!(fl.has_security_cookie());
        assert!(!fl.has_alloca());
    }

    #[test]
    fn test_address_range_contains() {
        let r = AddressRange {
            offset: 100,
            length: 50,
        };
        assert!(r.contains(100));
        assert!(r.contains(149));
        assert!(!r.contains(150));
        assert!(!r.contains(99));
    }

    #[test]
    fn test_module_symbols_total_locals() {
        let stream = make_proc_stream("X", 0, 0);
        let m = parse_module_symbols(&stream).unwrap();
        assert_eq!(m.total_locals(), 0);
    }

    #[test]
    fn test_regrel32_record() {
        let mut p = Vec::new();
        p.extend_from_slice(&(-8i32).to_le_bytes()); // fp-relative offset
        p.extend_from_slice(&3u32.to_le_bytes()); // type_index
        p.extend_from_slice(&335u16.to_le_bytes()); // RSP
        p.extend_from_slice(b"localVar\x00");

        let mut proc_p = Vec::new();
        for _ in 0..9 {
            proc_p.extend_from_slice(&0u32.to_le_bytes());
        }
        proc_p.extend_from_slice(&1u16.to_le_bytes());
        proc_p.push(0);
        proc_p.extend_from_slice(b"G\x00");

        let mut stream = frame_record(S_GPROC32, &proc_p);
        stream.extend(frame_record(S_REGREL32, &p));
        stream.extend(frame_record(S_END, &[]));

        let m = parse_module_symbols(&stream).unwrap();
        assert_eq!(m.procedures[0].locals.len(), 1);
        assert_eq!(m.procedures[0].locals[0].name, "localVar");
        assert!(matches!(
            m.procedures[0].locals[0].storage,
            VariableStorage::RegisterRelative {
                register: 335,
                offset: -8
            }
        ));
    }

    #[test]
    fn test_callees_record() {
        // S_CALLEES: count=2 then two u32 ids
        let mut p = Vec::new();
        p.extend_from_slice(&2u32.to_le_bytes());
        p.extend_from_slice(&10u32.to_le_bytes());
        p.extend_from_slice(&20u32.to_le_bytes());

        let mut proc_p = Vec::new();
        for _ in 0..9 {
            proc_p.extend_from_slice(&0u32.to_le_bytes());
        }
        proc_p.extend_from_slice(&1u16.to_le_bytes());
        proc_p.push(0);
        proc_p.extend_from_slice(b"H\x00");

        let mut stream = frame_record(S_GPROC32, &proc_p);
        stream.extend(frame_record(S_CALLEES, &p));
        stream.extend(frame_record(S_END, &[]));

        let m = parse_module_symbols(&stream).unwrap();
        assert_eq!(m.procedures[0].callees, vec![10, 20]);
    }
}
