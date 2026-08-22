//! DWARF 4/5 `.debug_line` line-number program interpreter.
//!
//! Parses the line-number program header, then executes special, standard, and
//! extended opcodes to produce a sequence of `LineRow` entries associating
//! machine addresses with (file, line, column, `is_stmt`) tuples.
//!
//! # Parallel implementations
//!
//! This crate ships more than one line-number program implementation: see also `line_program`.
//! None of them is wired into [`crate::DwarfReader`], which uses its own
//! inline copy, so each carries an independent bug set and a fix applied
//! here does not propagate. Pick one deliberately and stay on it.

use std::collections::HashMap;

// ─────────────────────────────────────────────────────────────────────────────
// Opcode constants
// ─────────────────────────────────────────────────────────────────────────────

/// Standard opcodes (DWARF 4 §6.2.5.2 / DWARF 5 §6.2.5.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum StandardOpcode {
    /// `DW_LNS_copy`: append a row to the matrix.
    Copy             = 0x01,
    /// `DW_LNS_advance_pc`: advance address by a ULEB128 operand.
    AdvancePc        = 0x02,
    /// `DW_LNS_advance_line`: advance line by a SLEB128 operand.
    AdvanceLine      = 0x03,
    /// `DW_LNS_set_file`: set the file register.
    SetFile          = 0x04,
    /// `DW_LNS_set_column`: set the column register.
    SetColumn        = 0x05,
    /// `DW_LNS_negate_stmt`: toggle the `is_stmt` register.
    NegateStmt       = 0x06,
    /// `DW_LNS_set_basic_block`: mark the start of a basic block.
    SetBasicBlock    = 0x07,
    /// `DW_LNS_const_add_pc`: advance address as special opcode 255 would.
    ConstAddPc       = 0x08,
    /// `DW_LNS_fixed_advance_pc`: advance address by an unencoded u16.
    FixedAdvancePc   = 0x09,
    /// `DW_LNS_set_prologue_end`: mark the end of the function prologue.
    SetPrologueEnd   = 0x0a,
    /// `DW_LNS_set_epilogue_begin`: mark the start of the function epilogue.
    SetEpilogueBegin = 0x0b,
    /// `DW_LNS_set_isa`: set the ISA register.
    SetIsa           = 0x0c,
}

impl StandardOpcode {
    /// Decode a standard opcode byte; `None` if it is not a known opcode.
    #[must_use]
    pub const fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x01 => Some(Self::Copy),
            0x02 => Some(Self::AdvancePc),
            0x03 => Some(Self::AdvanceLine),
            0x04 => Some(Self::SetFile),
            0x05 => Some(Self::SetColumn),
            0x06 => Some(Self::NegateStmt),
            0x07 => Some(Self::SetBasicBlock),
            0x08 => Some(Self::ConstAddPc),
            0x09 => Some(Self::FixedAdvancePc),
            0x0a => Some(Self::SetPrologueEnd),
            0x0b => Some(Self::SetEpilogueBegin),
            0x0c => Some(Self::SetIsa),
            _ => None,
        }
    }
}

/// Extended opcodes (opcode byte 0x00 followed by ULEB128 length then subcode).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ExtendedOpcode {
    /// `DW_LNE_end_sequence`: terminate the current row sequence.
    EndSequence      = 0x01,
    /// `DW_LNE_set_address`: set the address register to an absolute address.
    SetAddress       = 0x02,
    /// `DW_LNE_define_file`: define an additional source file (DWARF <= 4).
    DefineFile       = 0x03,
    /// `DW_LNE_set_discriminator`: set the discriminator register.
    SetDiscriminator = 0x04,
    /// `DW_LNE_lo_user`: start of the vendor-specific opcode range.
    LoUser           = 0x80,
    /// `DW_LNE_hi_user`: end of the vendor-specific opcode range.
    HiUser           = 0xff,
}

impl ExtendedOpcode {
    /// Decode an extended opcode subcode; `None` if it is not a known opcode.
    #[must_use]
    pub const fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x01 => Some(Self::EndSequence),
            0x02 => Some(Self::SetAddress),
            0x03 => Some(Self::DefineFile),
            0x04 => Some(Self::SetDiscriminator),
            _ => None,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// LineOp — decoded opcode ready for execution
// ─────────────────────────────────────────────────────────────────────────────

/// A decoded line-number program opcode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LineOp {
    /// Special opcode: simultaneously advance address and line.
    Special {
        /// Address increment in bytes (already scaled).
        addr_inc: u64,
        /// Signed line increment.
        line_inc: i64,
    },
    /// Append a row to the matrix.
    Copy,
    /// Advance the address register by the given byte count.
    AdvancePc(u64),
    /// Advance the line register by the given signed amount.
    AdvanceLine(i64),
    /// Set the file register.
    SetFile(u64),
    /// Set the column register.
    SetColumn(u64),
    /// Toggle the `is_stmt` register.
    NegateStmt,
    /// Mark the start of a basic block.
    SetBasicBlock,
    /// Advance the address register by the special-opcode-255 amount.
    ConstAddPc(u64),
    /// Advance the address register by an unencoded u16.
    FixedAdvancePc(u16),
    /// Mark the end of the function prologue.
    SetPrologueEnd,
    /// Mark the start of the function epilogue.
    SetEpilogueBegin,
    /// Set the ISA register.
    SetIsa(u64),
    // Extended
    /// Terminate the current sequence and reset the state machine.
    EndSequence,
    /// Set the address register to an absolute address.
    SetAddress(u64),
    /// Define an additional source file (DWARF <= 4).
    DefineFile {
        /// Source file name.
        name: String,
        /// Index into the include-directory table.
        dir_idx: u64,
        /// Last-modification time (0 if unknown).
        mtime: u64,
        /// File size in bytes (0 if unknown).
        file_size: u64,
    },
    /// Set the discriminator register.
    SetDiscriminator(u64),
    /// Unrecognized extended opcode, kept with its raw payload.
    UnknownExtended {
        /// Extended opcode subcode byte.
        subcode: u8,
        /// Raw operand bytes.
        data: Vec<u8>,
    },
}

// ─────────────────────────────────────────────────────────────────────────────
// File entry
// ─────────────────────────────────────────────────────────────────────────────

/// A file entry in the line-number program header.
#[derive(Debug, Clone)]
pub struct FileEntry {
    /// Source file name.
    pub name: String,
    /// Index into `include_directories`; 0 means compilation directory.
    pub dir_index: u64,
    /// Last-modification time (0 if unknown).
    pub last_modified: u64,
    /// File size in bytes (0 if unknown).
    pub file_size: u64,
}

// ─────────────────────────────────────────────────────────────────────────────
// LineRow — one row in the line-number matrix
// ─────────────────────────────────────────────────────────────────────────────

/// One row produced by the line-number state machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LineRow {
    /// Machine address of the instruction.
    pub address: u64,
    /// One-based file index.
    pub file: u64,
    /// One-based line number.
    pub line: u64,
    /// Zero-based column (0 = unknown).
    pub column: u64,
    /// This address is a recommended breakpoint location.
    pub is_stmt: bool,
    /// Marks the beginning of a basic block.
    pub basic_block: bool,
    /// End of a function prologue.
    pub prologue_end: bool,
    /// Beginning of a function epilogue.
    pub epilogue_begin: bool,
    /// ISA identifier.
    pub isa: u64,
    /// Discriminator (identifies multiple blocks sharing an address).
    pub discriminator: u64,
    /// This row ends a sequence.
    pub end_sequence: bool,
}

impl LineRow {
    const fn initial(default_is_stmt: bool) -> Self {
        Self {
            address: 0,
            file: 1,
            line: 1,
            column: 0,
            is_stmt: default_is_stmt,
            basic_block: false,
            prologue_end: false,
            epilogue_begin: false,
            isa: 0,
            discriminator: 0,
            end_sequence: false,
        }
    }

    /// Reset fields that are reset after each row is appended to the matrix.
    const fn reset_row_fields(&mut self, default_is_stmt: bool) {
        self.basic_block = false;
        self.prologue_end = false;
        self.epilogue_begin = false;
        self.discriminator = 0;
        self.is_stmt = default_is_stmt;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// LineMatrix
// ─────────────────────────────────────────────────────────────────────────────

/// The full set of rows produced for one compilation-unit line program.
#[derive(Debug, Default, Clone)]
pub struct LineMatrix {
    /// Rows in program-emission order.
    pub rows: Vec<LineRow>,
}

impl LineMatrix {
    /// Create an empty line matrix.
    #[must_use]
    pub const fn new() -> Self { Self { rows: Vec::new() } }

    /// Look up the source location for a given address (last row ≤ address).
    #[must_use] 
    pub fn lookup(&self, addr: u64) -> Option<&LineRow> {
        // Binary search for the last row whose address ≤ addr.
        let idx = self.rows.partition_point(|r| r.address <= addr);
        if idx == 0 { None } else { self.rows.get(idx - 1) }
    }

    /// Collect all stmt rows (good breakpoint candidates).
    pub fn stmt_rows(&self) -> impl Iterator<Item = &LineRow> {
        self.rows.iter().filter(|r| r.is_stmt && !r.end_sequence)
    }

    /// Number of rows.
    #[must_use] 
    pub const fn len(&self) -> usize { self.rows.len() }
    /// Whether the matrix has no rows.
    #[must_use]
    pub const fn is_empty(&self) -> bool { self.rows.is_empty() }
}

// ─────────────────────────────────────────────────────────────────────────────
// StateMachine
// ─────────────────────────────────────────────────────────────────────────────

/// Execution state of the line-number program state machine.
#[derive(Debug, Clone)]
pub struct StateMachine {
    /// Current values of the line-number state-machine registers.
    pub register: LineRow,
    default_is_stmt: bool,
    minimum_instruction_length: u8,
    maximum_ops_per_insn: u8,
    line_base: i8,
    line_range: u8,
    opcode_base: u8,
}

impl StateMachine {
    /// Create a state machine initialized from the line-program header fields.
    #[must_use]
    pub const fn new(
        default_is_stmt: bool,
        minimum_instruction_length: u8,
        maximum_ops_per_insn: u8,
        line_base: i8,
        line_range: u8,
        opcode_base: u8,
    ) -> Self {
        Self {
            register: LineRow::initial(default_is_stmt),
            default_is_stmt,
            minimum_instruction_length,
            maximum_ops_per_insn,
            line_base,
            line_range,
            opcode_base,
        }
    }

    /// Decode a special opcode into (`addr_advance`, `line_advance`).
    #[must_use] 
    pub fn decode_special(&self, opcode: u8) -> (u64, i64) {
        let adjusted = u64::from(opcode.wrapping_sub(self.opcode_base));
        // `.max(1)`: StateMachine::new is public, so a caller can supply 0 directly.
        let line_range = u64::from(self.line_range).max(1);
        let op_advance = adjusted / line_range;
        let line_inc = (adjusted % line_range) as i64 + i64::from(self.line_base);
        let mips = u64::from(self.maximum_ops_per_insn.max(1));
        let addr_inc = u64::from(self.minimum_instruction_length)
            * ((self.register.address /* op_index not tracked here */ + op_advance) / mips);
        // Simplified — op_index tracking omitted for single-op ISA.
        let addr_inc2 = u64::from(self.minimum_instruction_length) * op_advance;
        let _ = addr_inc;
        (addr_inc2, line_inc)
    }

    /// Execute a single `LineOp`, updating `register`. Returns a row if one
    /// should be appended to the matrix, and a bool indicating end-of-sequence.
    pub fn execute(&mut self, op: &LineOp) -> (Option<LineRow>, bool) {
        match op {
            LineOp::Special { addr_inc, line_inc } => {
                self.register.address = self.register.address.wrapping_add(*addr_inc);
                self.register.line = (self.register.line as i64 + line_inc) as u64;
                let row = self.register.clone();
                self.register.reset_row_fields(self.default_is_stmt);
                (Some(row), false)
            }
            LineOp::Copy => {
                let row = self.register.clone();
                self.register.reset_row_fields(self.default_is_stmt);
                (Some(row), false)
            }
            LineOp::AdvancePc(delta) => {
                self.register.address = self.register.address.wrapping_add(*delta);
                (None, false)
            }
            LineOp::AdvanceLine(delta) => {
                self.register.line = (self.register.line as i64 + delta) as u64;
                (None, false)
            }
            LineOp::SetFile(f) => { self.register.file = *f; (None, false) }
            LineOp::SetColumn(c) => { self.register.column = *c; (None, false) }
            LineOp::NegateStmt => { self.register.is_stmt = !self.register.is_stmt; (None, false) }
            LineOp::SetBasicBlock => { self.register.basic_block = true; (None, false) }
            LineOp::ConstAddPc(delta) => {
                self.register.address = self.register.address.wrapping_add(*delta);
                (None, false)
            }
            LineOp::FixedAdvancePc(delta) => {
                self.register.address = self.register.address.wrapping_add(u64::from(*delta));
                (None, false)
            }
            LineOp::SetPrologueEnd => { self.register.prologue_end = true; (None, false) }
            LineOp::SetEpilogueBegin => { self.register.epilogue_begin = true; (None, false) }
            LineOp::SetIsa(isa) => { self.register.isa = *isa; (None, false) }
            LineOp::EndSequence => {
                self.register.end_sequence = true;
                let row = self.register.clone();
                self.register = LineRow::initial(self.default_is_stmt);
                (Some(row), true)
            }
            LineOp::SetAddress(addr) => { self.register.address = *addr; (None, false) }
            LineOp::DefineFile { .. } => (None, false), // handled at program level
            LineOp::SetDiscriminator(d) => { self.register.discriminator = *d; (None, false) }
            LineOp::UnknownExtended { .. } => (None, false),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// LineProgram — header + bytecode + executor
// ─────────────────────────────────────────────────────────────────────────────

/// Parsed line-number program header and its bytecode.
#[derive(Debug, Clone)]
pub struct LineProgram {
    // Header fields
    /// DWARF line-number program version (2-5).
    pub version: u16,
    /// Target address size in bytes (DWARF 5 header field; 8 otherwise).
    pub address_size: u8,
    /// Size in bytes of the smallest target instruction.
    pub minimum_instruction_length: u8,
    /// Maximum operations per instruction (VLIW; 1 for most ISAs).
    pub maximum_ops_per_insn: u8,
    /// Initial value of the `is_stmt` register.
    pub default_is_stmt: bool,
    /// Smallest line increment a special opcode can encode.
    pub line_base: i8,
    /// Number of distinct line increments special opcodes encode.
    pub line_range: u8,
    /// First special opcode value; standard opcodes are below this.
    pub opcode_base: u8,
    /// Operand counts for each standard opcode (indices 1..`opcode_base`).
    pub standard_opcode_lengths: Vec<u8>,
    /// Include-directory table.
    pub include_directories: Vec<String>,
    /// File-name table.
    pub file_names: Vec<FileEntry>,
    /// Raw opcode stream (excludes header).
    pub opcodes: Vec<u8>,
}

/// Read a ULEB128 from `data` at `*pos`, advancing `*pos`.
fn read_uleb128(data: &[u8], pos: &mut usize) -> Option<u64> {
    let mut result: u64 = 0;
    let mut shift = 0u32;
    loop {
        if *pos >= data.len() { return None; }
        let byte = data[*pos];
        *pos += 1;
        result |= u64::from(byte & 0x7f) << shift;
        shift += 7;
        if byte & 0x80 == 0 { break; }
        if shift >= 64 { return None; }
    }
    Some(result)
}

/// Read a SLEB128 from `data` at `*pos`.
fn read_sleb128(data: &[u8], pos: &mut usize) -> Option<i64> {
    let mut result: i64 = 0;
    let mut shift = 0u32;
    loop {
        if *pos >= data.len() { return None; }
        let byte = data[*pos];
        *pos += 1;
        result |= i64::from(byte & 0x7f) << shift;
        shift += 7;
        if byte & 0x80 == 0 {
            if shift < 64 && (byte & 0x40) != 0 {
                result |= !0i64 << shift;
            }
            break;
        }
        if shift >= 64 { return None; }
    }
    Some(result)
}

// ─────────────────────────────────────────────────────────────────────────────
// DWARF 5 line-header entry formats (§6.2.4.1)
// ─────────────────────────────────────────────────────────────────────────────

/// `DW_LNCT_path`: entry content is a path string.
pub const DW_LNCT_PATH: u64 = 0x1;
/// `DW_LNCT_directory_index`: entry content is an include-directory index.
pub const DW_LNCT_DIRECTORY_INDEX: u64 = 0x2;
/// `DW_LNCT_timestamp`: entry content is a modification timestamp.
pub const DW_LNCT_TIMESTAMP: u64 = 0x3;
/// `DW_LNCT_size`: entry content is the file size in bytes.
pub const DW_LNCT_SIZE: u64 = 0x4;
/// `DW_LNCT_MD5`: entry content is a 16-byte MD5 digest.
pub const DW_LNCT_MD5: u64 = 0x5;

/// A value decoded from one `(content_type, form)` cell of a DWARF 5
/// directory or file-name entry.
enum FormValue {
    Str(String),
    Uint(u64),
    /// Value present but not needed (e.g. an MD5 block).
    Opaque,
}

/// Read a NUL-terminated string out of an auxiliary string section at `off`.
fn str_at(section: &[u8], off: usize) -> String {
    let Some(rest) = section.get(off..) else { return String::new() };
    let end = rest.iter().position(|&b| b == 0).unwrap_or(rest.len());
    String::from_utf8_lossy(&rest[..end]).into_owned()
}

/// Decode a single form-encoded value from the line-program header.
///
/// `offset_size` is 4 for 32-bit DWARF and 8 for 64-bit DWARF. Returns `None`
/// when the data is truncated or the form is not one representable here, in
/// which case the caller must abort — the stream position can no longer be
/// trusted.
fn read_form_value(
    data: &[u8],
    pos: &mut usize,
    form: u64,
    offset_size: usize,
    debug_line_str: &[u8],
    debug_str: &[u8],
) -> Option<FormValue> {
    // Read `n` little-endian bytes as a u64.
    fn uint(data: &[u8], pos: &mut usize, n: usize) -> Option<u64> {
        let slice = data.get(*pos..pos.checked_add(n)?)?;
        let mut buf = [0u8; 8];
        buf[..n].copy_from_slice(slice);
        *pos += n;
        Some(u64::from_le_bytes(buf))
    }

    match form {
        // DW_FORM_string — inline NUL-terminated.
        0x08 => read_null_terminated(data, pos).map(FormValue::Str),
        // DW_FORM_line_strp — offset into .debug_line_str.
        0x1f => {
            let off = uint(data, pos, offset_size)?;
            Some(FormValue::Str(str_at(debug_line_str, usize::try_from(off).ok()?)))
        }
        // DW_FORM_strp — offset into .debug_str.
        0x0e => {
            let off = uint(data, pos, offset_size)?;
            Some(FormValue::Str(str_at(debug_str, usize::try_from(off).ok()?)))
        }
        // DW_FORM_sec_offset / DW_FORM_strp_sup.
        0x17 | 0x1d => uint(data, pos, offset_size).map(FormValue::Uint),
        // DW_FORM_strx / DW_FORM_udata — index or plain unsigned.
        0x1a | 0x0f => read_uleb128(data, pos).map(FormValue::Uint),
        // DW_FORM_sdata.
        0x0d => read_sleb128(data, pos).map(|v| FormValue::Uint(v as u64)),
        // DW_FORM_strx1..4 and DW_FORM_data1/2/4/8.
        0x25 | 0x0b => uint(data, pos, 1).map(FormValue::Uint),
        0x26 | 0x05 => uint(data, pos, 2).map(FormValue::Uint),
        0x27 => uint(data, pos, 3).map(FormValue::Uint),
        0x28 | 0x06 => uint(data, pos, 4).map(FormValue::Uint),
        0x07 => uint(data, pos, 8).map(FormValue::Uint),
        // DW_FORM_data16 — the MD5 case.
        0x1e => {
            let end = pos.checked_add(16)?;
            if end > data.len() { return None; }
            *pos = end;
            Some(FormValue::Opaque)
        }
        // DW_FORM_block — ULEB length then that many bytes.
        0x09 => {
            let n = usize::try_from(read_uleb128(data, pos)?).ok()?;
            let end = pos.checked_add(n)?;
            if end > data.len() { return None; }
            *pos = end;
            Some(FormValue::Opaque)
        }
        _ => None,
    }
}

/// Parse one DWARF 5 entry-format descriptor table plus its entries.
///
/// Returns the decoded `(path, directory_index)` pair per entry. Both the
/// format count and the entry count are capped against the bytes actually
/// remaining so a corrupt header cannot drive a huge allocation.
fn parse_v5_entries(
    data: &[u8],
    pos: &mut usize,
    offset_size: usize,
    debug_line_str: &[u8],
    debug_str: &[u8],
) -> Result<Vec<(String, u64)>, &'static str> {
    let format_count = *data.get(*pos).ok_or("truncated entry_format_count")? as usize;
    *pos += 1;
    // Each descriptor is at least two bytes (two ULEBs).
    if format_count.saturating_mul(2) > data.len().saturating_sub(*pos) {
        return Err("entry_format_count exceeds remaining data");
    }
    let mut formats = Vec::with_capacity(format_count);
    for _ in 0..format_count {
        let content = read_uleb128(data, pos).ok_or("truncated content type")?;
        let form = read_uleb128(data, pos).ok_or("truncated form")?;
        formats.push((content, form));
    }

    let count = read_uleb128(data, pos).ok_or("truncated entries count")?;
    let count = usize::try_from(count).map_err(|_| "entries count too large")?;
    // A non-empty entry consumes at least one byte per described field.
    if format_count > 0 && count > data.len().saturating_sub(*pos) {
        return Err("entries count exceeds remaining data");
    }
    let mut out = Vec::with_capacity(count.min(1024));
    for _ in 0..count {
        let mut path = String::new();
        let mut dir_index = 0u64;
        for &(content, form) in &formats {
            let value = read_form_value(data, pos, form, offset_size, debug_line_str, debug_str)
                .ok_or("unsupported or truncated form in line header")?;
            match (content, value) {
                (DW_LNCT_PATH, FormValue::Str(s)) => path = s,
                (DW_LNCT_DIRECTORY_INDEX, FormValue::Uint(v)) => dir_index = v,
                _ => {}
            }
        }
        out.push((path, dir_index));
    }
    Ok(out)
}

fn read_null_terminated(data: &[u8], pos: &mut usize) -> Option<String> {
    let start = *pos;
    while *pos < data.len() && data[*pos] != 0 { *pos += 1; }
    if *pos >= data.len() { return None; }
    let s = String::from_utf8_lossy(&data[start..*pos]).into_owned();
    *pos += 1; // skip NUL
    Some(s)
}

impl LineProgram {
    /// Parse a line-number program from a `.debug_line` section slice starting
    /// at the given offset.  Returns the program and the offset after it.
    pub fn parse(data: &[u8], offset: usize) -> Result<(Self, usize), &'static str> {
        Self::parse_with_str_sections(data, offset, &[], &[])
    }

    /// Same as [`LineProgram::parse`], but with the auxiliary string sections
    /// needed to resolve DWARF 5 `DW_FORM_line_strp` / `DW_FORM_strp`
    /// directory and file names.
    ///
    /// [`LineProgram::parse`] delegates here with empty sections, in which case
    /// such names decode to the empty string rather than being mis-parsed.
    pub fn parse_with_str_sections(
        data: &[u8],
        offset: usize,
        debug_line_str: &[u8],
        debug_str: &[u8],
    ) -> Result<(Self, usize), &'static str> {
        let mut pos = offset;

        // Unit length (4-byte or 8-byte for 64-bit DWARF)
        if pos + 4 > data.len() { return Err("truncated unit_length"); }
        let (unit_length, is64, header_size) = {
            let first = u32::from_le_bytes(data[pos..pos+4].try_into().unwrap());
            if first == 0xffff_ffff {
                if pos + 12 > data.len() { return Err("truncated 64-bit unit_length"); }
                let len = u64::from_le_bytes(data[pos+4..pos+12].try_into().unwrap());
                (len as usize, true, 12usize)
            } else {
                (first as usize, false, 4usize)
            }
        };
        pos += header_size;
        let unit_end = pos
            .checked_add(unit_length)
            .ok_or("unit_length overflows the address space")?;

        // ⚠ This check was missing. `unit_length` is attacker-controlled data
        // read straight out of the section: a unit that claims more bytes than
        // the buffer holds was accepted, and `parse` returned `unit_end` as the
        // "next offset" — a value PAST the end of `data`. A caller looping over
        // units with that offset either indexes out of range or silently stops,
        // and neither is a parse error it can report.
        //
        // Found by `a_truncated_unit_is_rejected`, which only exists because
        // the hand-encoded fixture it feeds had been sitting uncalled behind an
        // `#[allow(dead_code)]`.
        if unit_end > data.len() {
            return Err("unit_length runs past the end of the section");
        }

        // version
        if pos + 2 > data.len() { return Err("truncated version"); }
        let version = u16::from_le_bytes(data[pos..pos+2].try_into().unwrap());
        pos += 2;

        let offset_size = if is64 { 8usize } else { 4usize };

        // address_size + segment_selector_size (DWARF 5 only, §6.2.4). These
        // sit between `version` and `header_length`; both bytes must be
        // consumed or every field after them is off by one.
        let address_size = if version >= 5 {
            if pos + 2 > data.len() { return Err("truncated address_size"); }
            let v = data[pos];
            pos += 2; // address_size, then segment_selector_size
            v
        } else { 8 };

        // header_length
        let header_length = if is64 {
            if pos + 8 > data.len() { return Err("truncated header_length"); }
            let v = u64::from_le_bytes(data[pos..pos+8].try_into().unwrap());
            pos += 8; v as usize
        } else {
            if pos + 4 > data.len() { return Err("truncated header_length"); }
            let v = u32::from_le_bytes(data[pos..pos+4].try_into().unwrap());
            pos += 4; v as usize
        };
        // `header_length` is an attacker-controlled file field. `pos +
        // header_length` WRAPS in release, and a wrapped `program_start`
        // slips past the `program_start < opcode_end` test below, so the
        // HEADER bytes get re-read as the opcode stream.
        let program_start = pos
            .checked_add(header_length)
            .ok_or("header_length overflows the address space")?;
        if program_start > data.len() {
            return Err("header_length runs past the end of the section");
        }

        let minimum_instruction_length = if pos < data.len() { let v = data[pos]; pos += 1; v } else { return Err("eof"); };
        let maximum_ops_per_insn = if version >= 4 {
            if pos < data.len() { let v = data[pos]; pos += 1; v } else { return Err("eof"); }
        } else { 1 };
        let default_is_stmt = if pos < data.len() { let v = data[pos] != 0; pos += 1; v } else { return Err("eof"); };
        let line_base = if pos < data.len() { let v = data[pos] as i8; pos += 1; v } else { return Err("eof"); };
        let line_range = if pos < data.len() { let v = data[pos]; pos += 1; v } else { return Err("eof"); };
        let opcode_base = if pos < data.len() { let v = data[pos]; pos += 1; v } else { return Err("eof"); };
        // `line_range` is a divisor in the special-opcode and DW_LNS_const_add_pc
        // paths; a zero here is malformed and would panic.
        if line_range == 0 { return Err("line_range must be non-zero"); }

        let mut standard_opcode_lengths = Vec::new();
        for _ in 0..(opcode_base as usize).saturating_sub(1) {
            if pos < data.len() { standard_opcode_lengths.push(data[pos]); pos += 1; }
        }

        let (include_directories, file_names) = if version >= 5 {
            // DWARF 5 §6.2.4.1: format-descriptor tables, 0-based indices.
            // No synthetic index-0 entry is prepended — entry 0 *is* the
            // compilation directory / primary source file.
            let dirs = parse_v5_entries(data, &mut pos, offset_size, debug_line_str, debug_str)?
                .into_iter()
                .map(|(path, _)| path)
                .collect::<Vec<_>>();
            let files = parse_v5_entries(data, &mut pos, offset_size, debug_line_str, debug_str)?
                .into_iter()
                .map(|(name, dir_index)| FileEntry {
                    name,
                    dir_index,
                    last_modified: 0,
                    file_size: 0,
                })
                .collect::<Vec<_>>();
            (dirs, files)
        } else {
            let mut include_directories = vec![String::new()]; // index 0 = comp dir
            loop {
                if pos >= data.len() { break; }
                if data[pos] == 0 { pos += 1; break; }
                let dir = read_null_terminated(data, &mut pos).unwrap_or_default();
                include_directories.push(dir);
            }

            let mut file_names = vec![FileEntry { name: String::new(), dir_index: 0, last_modified: 0, file_size: 0 }];
            loop {
                if pos >= data.len() { break; }
                if data[pos] == 0 { pos += 1; break; }
                let name = read_null_terminated(data, &mut pos).unwrap_or_default();
                let dir_index = read_uleb128(data, &mut pos).unwrap_or(0);
                let last_modified = read_uleb128(data, &mut pos).unwrap_or(0);
                let file_size = read_uleb128(data, &mut pos).unwrap_or(0);
                file_names.push(FileEntry { name, dir_index, last_modified, file_size });
            }
            (include_directories, file_names)
        };

        // Sanity check: the header consumer position should not have run
        // past `program_start` (which marks the first opcode).
        debug_assert!(pos <= program_start, "line-program header consumed past program_start");
        // opcodes start at program_start
        let opcode_end = unit_end.min(data.len());
        let opcodes = if program_start < opcode_end {
            data[program_start..opcode_end].to_vec()
        } else {
            Vec::new()
        };

        Ok((Self {
            version,
            address_size,
            minimum_instruction_length,
            maximum_ops_per_insn,
            default_is_stmt,
            line_base,
            line_range,
            opcode_base,
            standard_opcode_lengths,
            include_directories,
            file_names,
            opcodes,
        }, unit_end.min(data.len())))
    }

    /// Execute the program and return the complete `LineMatrix`.
    #[must_use] 
    pub fn execute(&self) -> LineMatrix {
        let mut matrix = LineMatrix::new();
        let mut sm = StateMachine::new(
            self.default_is_stmt,
            self.minimum_instruction_length,
            self.maximum_ops_per_insn,
            self.line_base,
            self.line_range,
            self.opcode_base,
        );

        let data = &self.opcodes;
        let mut pos = 0;

        while pos < data.len() {
            let byte = data[pos];
            pos += 1;

            let op = if byte == 0 {
                // Extended
                let length = usize::try_from(read_uleb128(data, &mut pos).unwrap_or(0))
                    .unwrap_or(usize::MAX);
                let end = pos.saturating_add(length);
                if pos >= data.len() { break; }
                let subcode = data[pos]; pos += 1;
                let ext_op = match ExtendedOpcode::from_u8(subcode) {
                    Some(ExtendedOpcode::EndSequence) => LineOp::EndSequence,
                    Some(ExtendedOpcode::SetAddress) => {
                        let addr = if self.address_size == 4 {
                            if pos + 4 > data.len() { break; }
                            let v = u64::from(u32::from_le_bytes(data[pos..pos+4].try_into().unwrap()));
                            pos += 4; v
                        } else {
                            if pos + 8 > data.len() { break; }
                            let v = u64::from_le_bytes(data[pos..pos+8].try_into().unwrap());
                            pos += 8; v
                        };
                        LineOp::SetAddress(addr)
                    }
                    Some(ExtendedOpcode::DefineFile) => {
                        let name = read_null_terminated(data, &mut pos).unwrap_or_default();
                        let dir_idx = read_uleb128(data, &mut pos).unwrap_or(0);
                        let mtime = read_uleb128(data, &mut pos).unwrap_or(0);
                        let file_size = read_uleb128(data, &mut pos).unwrap_or(0);
                        LineOp::DefineFile { name, dir_idx, mtime, file_size }
                    }
                    Some(ExtendedOpcode::SetDiscriminator) => {
                        let d = read_uleb128(data, &mut pos).unwrap_or(0);
                        LineOp::SetDiscriminator(d)
                    }
                    _ => {
                        let ext_data = data[pos..end.min(data.len())].to_vec();
                        pos = end.min(data.len());
                        LineOp::UnknownExtended { subcode, data: ext_data }
                    }
                };
                // DWARF requires an extended opcode to occupy exactly `length`
                // bytes after the length field. Snap forward so a padded or
                // over-declared opcode does not desynchronise the stream.
                pos = pos.max(end.min(data.len()));
                ext_op
            } else if byte < self.opcode_base {
                // Standard
                match StandardOpcode::from_u8(byte) {
                    Some(StandardOpcode::Copy) => LineOp::Copy,
                    Some(StandardOpcode::AdvancePc) => {
                        let v = read_uleb128(data, &mut pos).unwrap_or(0);
                        LineOp::AdvancePc(v * u64::from(self.minimum_instruction_length))
                    }
                    Some(StandardOpcode::AdvanceLine) => {
                        let v = read_sleb128(data, &mut pos).unwrap_or(0);
                        LineOp::AdvanceLine(v)
                    }
                    Some(StandardOpcode::SetFile) => {
                        LineOp::SetFile(read_uleb128(data, &mut pos).unwrap_or(0))
                    }
                    Some(StandardOpcode::SetColumn) => {
                        LineOp::SetColumn(read_uleb128(data, &mut pos).unwrap_or(0))
                    }
                    Some(StandardOpcode::NegateStmt) => LineOp::NegateStmt,
                    Some(StandardOpcode::SetBasicBlock) => LineOp::SetBasicBlock,
                    Some(StandardOpcode::ConstAddPc) => {
                        let adjusted = (255u64).wrapping_sub(u64::from(self.opcode_base));
                        let op_adv = adjusted / u64::from(self.line_range).max(1);
                        LineOp::ConstAddPc(op_adv * u64::from(self.minimum_instruction_length))
                    }
                    Some(StandardOpcode::FixedAdvancePc) => {
                        if pos + 2 > data.len() { break; }
                        let v = u16::from_le_bytes(data[pos..pos+2].try_into().unwrap());
                        pos += 2;
                        LineOp::FixedAdvancePc(v)
                    }
                    Some(StandardOpcode::SetPrologueEnd) => LineOp::SetPrologueEnd,
                    Some(StandardOpcode::SetEpilogueBegin) => LineOp::SetEpilogueBegin,
                    Some(StandardOpcode::SetIsa) => {
                        LineOp::SetIsa(read_uleb128(data, &mut pos).unwrap_or(0))
                    }
                    None => {
                        // Skip unknown standard opcode by consuming its arguments
                        let n_args = if byte > 0 && (byte as usize) < self.standard_opcode_lengths.len() + 1 {
                            self.standard_opcode_lengths[byte as usize - 1] as usize
                        } else { 0 };
                        for _ in 0..n_args { read_uleb128(data, &mut pos); }
                        continue;
                    }
                }
            } else {
                // Special
                let (addr_inc, line_inc) = sm.decode_special(byte);
                LineOp::Special { addr_inc, line_inc }
            };

            let (row, _end_seq) = sm.execute(&op);
            if let Some(r) = row {
                matrix.rows.push(r);
            }
        }

        matrix
    }

    /// Resolve file index to a path string using `include_directories`.
    ///
    /// Indices follow the unit's own convention: DWARF ≤ 4 file numbers are
    /// 1-based (a synthetic entry occupies slot 0), DWARF 5 file indices are
    /// 0-based with entry 0 being the primary source file. Both are stored so
    /// that a direct index is correct.
    #[must_use]
    pub fn resolve_file(&self, file_idx: u64) -> Option<String> {
        let entry = self.file_names.get(file_idx as usize)?;
        let dir = self.include_directories.get(entry.dir_index as usize)
            .map_or("", std::string::String::as_str);
        if dir.is_empty() {
            Some(entry.name.clone())
        } else {
            Some(format!("{}/{}", dir, entry.name))
        }
    }

    /// Parse all line programs from a full `.debug_line` section.
    #[must_use] 
    pub fn parse_all(data: &[u8]) -> Vec<Self> {
        let mut programs = Vec::new();
        let mut offset = 0;
        while offset < data.len() {
            match Self::parse(data, offset) {
                Ok((prog, next)) => {
                    programs.push(prog);
                    if next <= offset { break; }
                    offset = next;
                }
                Err(_) => break,
            }
        }
        programs
    }

    /// Build an address-to-source map (address → (`file_path`, line)).
    #[must_use] 
    pub fn address_map(&self) -> HashMap<u64, (String, u64)> {
        let matrix = self.execute();
        let mut map = HashMap::new();
        for row in &matrix.rows {
            if !row.end_sequence {
                let file = self.resolve_file(row.file).unwrap_or_default();
                map.insert(row.address, (file, row.line));
            }
        }
        map
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Build a DWARF 5 `.debug_line` unit whose directory and file tables use
    /// the §6.2.4.1 entry-format encoding.
    ///
    /// `debug_line_str` layout used by the file table below:
    ///   offset 0: "/src\0"   offset 5: "main.c\0"
    fn dwarf5_line_program_bytes() -> (Vec<u8>, Vec<u8>) {
        let line_str: Vec<u8> = b"/src\0main.c\0".to_vec();

        let mut header: Vec<u8> = Vec::new();
        header.extend_from_slice(&5u16.to_le_bytes()); // version = 5
        header.push(8); // address_size
        header.push(0); // segment_selector_size — the byte that was skipped
        header.extend_from_slice(&0u32.to_le_bytes()); // header_length, patched
        let header_length_at = header.len() - 4;

        header.push(1); // minimum_instruction_length
        header.push(1); // maximum_ops_per_insn
        header.push(1); // default_is_stmt
        header.push(0xfb); // line_base = -5
        header.push(14); // line_range
        header.push(13); // opcode_base
        header.extend_from_slice(&[0, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1]);

        // directory table: 1 format (DW_LNCT_path, DW_FORM_line_strp), 1 entry
        header.push(1);
        header.push(DW_LNCT_PATH as u8);
        header.push(0x1f); // DW_FORM_line_strp
        header.push(1); // directories_count
        header.extend_from_slice(&0u32.to_le_bytes()); // -> "/src"

        // file table: 2 formats (path=line_strp, directory_index=udata), 1 entry
        header.push(2);
        header.push(DW_LNCT_PATH as u8);
        header.push(0x1f);
        header.push(DW_LNCT_DIRECTORY_INDEX as u8);
        header.push(0x0f); // DW_FORM_udata
        header.push(1); // file_names_count
        header.extend_from_slice(&5u32.to_le_bytes()); // -> "main.c"
        header.push(0); // directory_index = 0

        // header_length counts from just after the header_length field itself.
        let hl = (header.len() - (header_length_at + 4)) as u32;
        header[header_length_at..header_length_at + 4].copy_from_slice(&hl.to_le_bytes());

        // Opcode stream: set_address(0x2000), set_file(0), copy, end_sequence.
        // `set_file(0)` is meaningful only under DWARF 5 numbering — under the
        // <= 4 rules index 0 is the synthetic blank entry.
        let mut ops: Vec<u8> = Vec::new();
        ops.extend_from_slice(&[0x00, 0x09, 0x02]);
        ops.extend_from_slice(&0x2000u64.to_le_bytes());
        ops.extend_from_slice(&[0x04, 0x00]); // DW_LNS_set_file, ULEB 0
        ops.push(0x01); // DW_LNS_copy
        ops.extend_from_slice(&[0x00, 0x01, 0x01]); // DW_LNE_end_sequence

        let mut unit: Vec<u8> = Vec::new();
        let body_len = (header.len() + ops.len()) as u32;
        unit.extend_from_slice(&body_len.to_le_bytes());
        unit.extend_from_slice(&header);
        unit.extend_from_slice(&ops);
        (unit, line_str)
    }

    #[test]
    fn dwarf5_header_reads_segment_selector_and_entry_format_tables() {
        let (unit, line_str) = dwarf5_line_program_bytes();
        let (prog, next) =
            LineProgram::parse_with_str_sections(&unit, 0, &line_str, &[]).expect("parse");

        assert_eq!(prog.version, 5);
        assert_eq!(prog.address_size, 8);
        // Before the fix these came from the segment_selector_size byte and the
        // format-table bytes, shifting every field by one.
        assert_eq!(prog.minimum_instruction_length, 1);
        assert_eq!(prog.maximum_ops_per_insn, 1);
        assert!(prog.default_is_stmt);
        assert_eq!(prog.line_base, -5);
        assert_eq!(prog.line_range, 14);
        assert_eq!(prog.opcode_base, 13);

        assert_eq!(prog.include_directories, vec!["/src".to_string()]);
        assert_eq!(prog.file_names.len(), 1);
        assert_eq!(prog.file_names[0].name, "main.c");
        assert_eq!(next, unit.len());
    }

    #[test]
    fn dwarf5_file_indices_are_zero_based() {
        let (unit, line_str) = dwarf5_line_program_bytes();
        let (prog, _) =
            LineProgram::parse_with_str_sections(&unit, 0, &line_str, &[]).expect("parse");
        // DWARF 5 index 0 is the primary source file, not a synthetic blank.
        assert_eq!(prog.resolve_file(0).as_deref(), Some("/src/main.c"));
        assert_eq!(prog.resolve_file(1), None);
    }

    #[test]
    fn dwarf5_opcodes_execute_against_correct_header() {
        let (unit, line_str) = dwarf5_line_program_bytes();
        let (prog, _) =
            LineProgram::parse_with_str_sections(&unit, 0, &line_str, &[]).expect("parse");
        let matrix = prog.execute();
        let row = matrix.rows.iter().find(|r| !r.end_sequence).expect("a row");
        assert_eq!(row.address, 0x2000);
        assert_eq!(prog.resolve_file(row.file).as_deref(), Some("/src/main.c"));
    }

    #[test]
    fn dwarf5_parse_without_str_sections_yields_empty_names_not_garbage() {
        // The convenience `parse` entry point has no .debug_line_str, so
        // line_strp names decode empty — but offsets are still consumed, so
        // the rest of the header stays aligned.
        let (unit, _) = dwarf5_line_program_bytes();
        let (prog, _) = LineProgram::parse(&unit, 0).expect("parse");
        assert_eq!(prog.line_range, 14);
        assert_eq!(prog.file_names.len(), 1);
        assert_eq!(prog.file_names[0].name, "");
    }

    #[test]
    fn dwarf5_bogus_entry_count_is_rejected_not_allocated() {
        let (mut unit, line_str) = dwarf5_line_program_bytes();
        // Overwrite the directories_count byte with a huge ULEB128 value.
        let idx = unit
            .windows(3)
            .position(|w| w == [1, DW_LNCT_PATH as u8, 0x1f])
            .expect("directory format descriptor")
            + 3;
        unit[idx] = 0xff; // start of an oversized ULEB128
        unit.insert(idx + 1, 0xff);
        unit.insert(idx + 2, 0x7f);
        let err = LineProgram::parse_with_str_sections(&unit, 0, &line_str, &[]).unwrap_err();
        assert!(
            err.contains("exceeds remaining data") || err.contains("truncated"),
            "unexpected error: {err}"
        );
    }

    pub(crate) fn minimal_line_program_bytes() -> Vec<u8> {
        // Minimal DWARF 4 .debug_line unit with a single sequence:
        //   SetAddress(0x1000), AdvanceLine(10-1=9), Copy, EndSequence
        let mut prog: Vec<u8> = Vec::new();
        // We build the header then the opcode stream and prepend unit_length.
        let header_fields: Vec<u8> = vec![
            0x04, 0x00, // version = 4
            // header_length (4 bytes) — will be patched
            0x00, 0x00, 0x00, 0x00,
            0x01, // minimum_instruction_length = 1
            0x01, // maximum_ops_per_insn = 1
            0x01, // default_is_stmt = 1
            0xfb, // line_base = -5 (signed)
            0x0e, // line_range = 14
            0x0d, // opcode_base = 13
            // standard_opcode_lengths[1..12]:
            0,1,1,1,1,0,0,0,1,0,0,
            // include_dirs: empty (single NUL)
            0x00,
            // file names: one entry "test.c" dir_idx=0 mtime=0 size=0
            b't', b'e', b's', b't', b'.', b'c', 0x00,
            0x00, // dir_idx uleb
            0x00, // mtime uleb
            0x00, // size uleb
            // end of file names
            0x00,
        ];
        // Opcodes
        let opcodes: Vec<u8> = vec![
            // Extended: SetAddress(0x1000)
            0x00, // extended marker
            0x09, // length=9 (1 subcode + 8 addr bytes)
            0x02, // DW_LNE_set_address
            0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x1000 LE64
            // DW_LNS_advance_line: line = 1 + 9 = 10
            0x03, 0x09, // advance_line SLEB128=9
            // DW_LNS_copy
            0x01,
            // Extended: EndSequence
            0x00, 0x01, 0x01,
        ];
        let header_len = header_fields.len() - 6 + opcodes.len(); // minus version(2)+hdrlen(4)
        // Actually header_length = bytes from end of header_length field to start of opcodes.
        let hdr_len_val = (header_fields.len() - 6) as u32; // version+hdrlen = 6 bytes
        let mut hf = header_fields;
        hf[2] = (hdr_len_val & 0xff) as u8;
        hf[3] = ((hdr_len_val >> 8) & 0xff) as u8;
        hf[4] = ((hdr_len_val >> 16) & 0xff) as u8;
        hf[5] = ((hdr_len_val >> 24) & 0xff) as u8;
        let content_len = hf.len() + opcodes.len();
        // unit_length (4 bytes) = everything after it
        prog.extend_from_slice(&(content_len as u32).to_le_bytes());
        prog.extend_from_slice(&hf);
        prog.extend_from_slice(&opcodes);
        let _ = header_len;
        prog
    }

    #[test]
    fn test_uleb128_simple() {
        let data = [0x80, 0x01]; // 128
        let mut pos = 0;
        assert_eq!(read_uleb128(&data, &mut pos), Some(128));
        assert_eq!(pos, 2);
    }

    #[test]
    fn test_sleb128_negative() {
        let data = [0x7c]; // -4
        let mut pos = 0;
        assert_eq!(read_sleb128(&data, &mut pos), Some(-4));
    }

    #[test]
    fn test_null_terminated() {
        let data = b"hello\x00world";
        let mut pos = 0;
        assert_eq!(read_null_terminated(data, &mut pos), Some("hello".to_string()));
        assert_eq!(pos, 6);
    }

    #[test]
    fn test_state_machine_initial() {
        let sm = StateMachine::new(true, 1, 1, -5, 14, 13);
        assert_eq!(sm.register.line, 1);
        assert_eq!(sm.register.file, 1);
        assert!(sm.register.is_stmt);
    }

    #[test]
    fn test_state_machine_set_address() {
        let mut sm = StateMachine::new(true, 1, 1, -5, 14, 13);
        let (row, end) = sm.execute(&LineOp::SetAddress(0xdeadbeef));
        assert!(row.is_none());
        assert!(!end);
        assert_eq!(sm.register.address, 0xdeadbeef);
    }

    #[test]
    fn test_state_machine_advance_line() {
        let mut sm = StateMachine::new(true, 1, 1, -5, 14, 13);
        sm.execute(&LineOp::AdvanceLine(9));
        assert_eq!(sm.register.line, 10);
    }

    #[test]
    fn test_state_machine_copy_emits_row() {
        let mut sm = StateMachine::new(true, 1, 1, -5, 14, 13);
        sm.execute(&LineOp::SetAddress(0x1000));
        let (row, _) = sm.execute(&LineOp::Copy);
        assert!(row.is_some());
        assert_eq!(row.unwrap().address, 0x1000);
    }

    #[test]
    fn test_state_machine_end_sequence() {
        let mut sm = StateMachine::new(true, 1, 1, -5, 14, 13);
        sm.execute(&LineOp::SetAddress(0x2000));
        let (row, end) = sm.execute(&LineOp::EndSequence);
        assert!(end);
        let r = row.unwrap();
        assert!(r.end_sequence);
        // After end_sequence, register resets
        assert_eq!(sm.register.address, 0);
    }

    #[test]
    fn test_line_matrix_lookup() {
        let mut m = LineMatrix::new();
        m.rows.push(LineRow { address: 0x1000, line: 10, file: 1, column: 0,
            is_stmt: true, basic_block: false, prologue_end: false,
            epilogue_begin: false, isa: 0, discriminator: 0, end_sequence: false });
        m.rows.push(LineRow { address: 0x1010, line: 11, file: 1, column: 0,
            is_stmt: true, basic_block: false, prologue_end: false,
            epilogue_begin: false, isa: 0, discriminator: 0, end_sequence: false });
        assert_eq!(m.lookup(0x1005).map(|r| r.line), Some(10));
        assert_eq!(m.lookup(0x1010).map(|r| r.line), Some(11));
        assert!(m.lookup(0x0fff).is_none());
    }

    #[test]
    fn test_line_matrix_stmt_rows() {
        let mut m = LineMatrix::new();
        for i in 0..5u64 {
            m.rows.push(LineRow { address: i * 4, line: i + 1, file: 1, column: 0,
                is_stmt: i % 2 == 0, basic_block: false, prologue_end: false,
                epilogue_begin: false, isa: 0, discriminator: 0, end_sequence: false });
        }
        let stmts: Vec<_> = m.stmt_rows().collect();
        assert_eq!(stmts.len(), 3);
    }

    #[test]
    fn test_standard_opcode_roundtrip() {
        for code in [0x01u8, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c] {
            assert!(StandardOpcode::from_u8(code).is_some(), "code 0x{code:02x} not recognised");
        }
        assert!(StandardOpcode::from_u8(0xff).is_none());
    }

    #[test]
    fn test_extended_opcode_roundtrip() {
        assert_eq!(ExtendedOpcode::from_u8(0x01), Some(ExtendedOpcode::EndSequence));
        assert_eq!(ExtendedOpcode::from_u8(0x02), Some(ExtendedOpcode::SetAddress));
        assert_eq!(ExtendedOpcode::from_u8(0x03), Some(ExtendedOpcode::DefineFile));
        assert_eq!(ExtendedOpcode::from_u8(0x04), Some(ExtendedOpcode::SetDiscriminator));
        assert!(ExtendedOpcode::from_u8(0x05).is_none());
    }

    #[test]
    fn test_resolve_file() {
        let mut prog = LineProgram {
            version: 4,
            address_size: 8,
            minimum_instruction_length: 1,
            maximum_ops_per_insn: 1,
            default_is_stmt: true,
            line_base: -5,
            line_range: 14,
            opcode_base: 13,
            standard_opcode_lengths: vec![0,1,1,1,1,0,0,0,1,0,0],
            include_directories: vec![String::new(), "/home/user/src".to_string()],
            file_names: vec![
                FileEntry { name: String::new(), dir_index: 0, last_modified: 0, file_size: 0 },
                FileEntry { name: "main.c".to_string(), dir_index: 1, last_modified: 0, file_size: 0 },
            ],
            opcodes: Vec::new(),
        };
        assert_eq!(prog.resolve_file(1), Some("/home/user/src/main.c".to_string()));
        prog.file_names.push(FileEntry { name: "util.c".to_string(), dir_index: 0, last_modified: 0, file_size: 0 });
        assert_eq!(prog.resolve_file(2), Some("util.c".to_string()));
    }

    #[test]
    fn test_parse_all_empty() {
        let programs = LineProgram::parse_all(&[]);
        assert!(programs.is_empty());
    }

    #[test]
    fn test_decode_special_zero_advance() {
        let sm = StateMachine::new(true, 1, 1, -5, 14, 13);
        // opcode_base = 13, so special opcode 13 → adjusted=0
        let (addr, line) = sm.decode_special(13);
        assert_eq!(addr, 0);
        assert_eq!(line, -5); // line_base
    }
}

#[cfg(test)]
mod line_program_end_to_end_tests {
    //! ⚠ `minimal_line_program_bytes` hand-encodes a complete DWARF 4
    //! `.debug_line` unit — header, `DW_LNE_set_address`, `DW_LNS_advance_line`,
    //! `DW_LNS_copy`, `DW_LNE_end_sequence` — and had **no caller**. The unit
    //! tests around it covered ULEB/SLEB decoding and opcode arithmetic in
    //! isolation, so nothing ever ran a real program through `parse` +
    //! `execute`. An `#[allow(dead_code)]` hid the unused fixture, and with it
    //! the fact that the parser had no end-to-end coverage at all.

    use super::tests::minimal_line_program_bytes;
    use super::*;

    /// The unit parses, and reports consuming the whole buffer.
    #[test]
    fn minimal_unit_parses() {
        let data = minimal_line_program_bytes();
        let (_prog, next) = LineProgram::parse(&data, 0).expect("hand-encoded unit must parse");
        assert_eq!(next, data.len(), "the unit must consume exactly its bytes");
    }

    /// Executing it yields a row at the address the program sets (0x1000) with
    /// the line the program advances to (1 + 9 = 10).
    #[test]
    fn minimal_unit_yields_the_encoded_row() {
        let data = minimal_line_program_bytes();
        let (prog, _) = LineProgram::parse(&data, 0).expect("parse");
        let matrix = prog.execute();

        let row = matrix
            .lookup(0x1000)
            .expect("a row must cover the address set by DW_LNE_set_address");
        assert_eq!(row.address, 0x1000, "address from DW_LNE_set_address");
        assert_eq!(row.line, 10, "line 1 advanced by 9");
    }

    /// An address below the sequence start is not covered by it.
    #[test]
    fn address_before_the_sequence_is_not_covered() {
        let data = minimal_line_program_bytes();
        let (prog, _) = LineProgram::parse(&data, 0).expect("parse");
        let matrix = prog.execute();
        assert!(matrix.lookup(0x0FFF).is_none());
    }

    /// `header_length` is attacker-controlled and was added to `pos`
    /// unchecked. An out-of-range value does not panic — it makes
    /// `program_start` overshoot, the `program_start < opcode_end` test then
    /// reads FALSE, and the unit parses "successfully" with an empty opcode
    /// stream: a corrupt line program silently reported as a valid one with no
    /// rows. It must be an error instead.
    #[test]
    fn an_out_of_range_header_length_is_rejected() {
        let mut data = minimal_line_program_bytes();
        // DWARF 4, 32-bit format: unit_length(4) + version(2), then header_length.
        data[6..10].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        assert!(
            LineProgram::parse(&data, 0).is_err(),
            "a header_length past the end of the section was accepted"
        );
    }

    /// Truncating the unit must produce an error, not a partial matrix that
    /// silently reports wrong lines.
    #[test]
    fn a_truncated_unit_is_rejected() {
        let data = minimal_line_program_bytes();
        let cut = &data[..data.len() / 2];
        assert!(LineProgram::parse(cut, 0).is_err());
    }
}
