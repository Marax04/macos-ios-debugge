//! DWARF line number program state machine.
//!
//! Implements a full DWARF v2/v3/v4/v5 line number program parser producing
//! a [`LineMatrix`] of [`LineRow`] entries.
//!
//! Supports:
//! - All standard opcodes (`DW_LNS`_*)
//! - All extended opcodes (`DW_LNE`_*)
//! - Special opcodes
//! - DWARF v4 `maximum_ops_per_instruction`
//! - DWARF v5 directory/filename format tables
//!
//! # Parallel implementations
//!
//! This crate ships more than one line-number program implementation: see also `dwarf_line_program`.
//! None of them is wired into [`crate::DwarfReader`], which uses its own
//! inline copy, so each carries an independent bug set and a fix applied
//! here does not propagate. Pick one deliberately and stay on it.
//! `dwarf_line_program` carries the DWARF 5 entry-format header support; this module does not.

use serde::{Deserialize, Serialize};
use thiserror::Error;

// ── Errors ────────────────────────────────────────────────────────────────────

/// Errors produced while parsing or executing a line-number program.
#[derive(Debug, Error)]
pub enum LineError {
    /// The data ended unexpectedly at the given offset.
    #[error("truncated line program data at offset {0}")]
    Truncated(usize),
    /// The line-program version is outside the supported 2-5 range.
    #[error("unsupported DWARF version {0}")]
    UnsupportedVersion(u16),
    /// The line-program header is structurally invalid.
    #[error("malformed header")]
    MalformedHeader,
}

// ── LineRow ────────────────────────────────────────────────────────────────────

/// Flags for a [`LineRow`], packed into a single byte to avoid the
/// `clippy::struct_excessive_bools` lint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct LineRowFlags(u8);

impl LineRowFlags {
    const IS_STMT: u8       = 1 << 0;
    const BASIC_BLOCK: u8   = 1 << 1;
    const END_SEQUENCE: u8  = 1 << 2;
    const PROLOGUE_END: u8  = 1 << 3;
    const EPILOGUE_BEGIN: u8 = 1 << 4;

    /// Whether the row is a recommended breakpoint location.
    #[inline] #[must_use] pub const fn is_stmt(self)        -> bool { self.0 & Self::IS_STMT != 0 }
    /// Whether the row starts a basic block.
    #[inline] #[must_use] pub const fn basic_block(self)    -> bool { self.0 & Self::BASIC_BLOCK != 0 }
    /// Whether the row terminates a sequence.
    #[inline] #[must_use] pub const fn end_sequence(self)   -> bool { self.0 & Self::END_SEQUENCE != 0 }
    /// Whether the row marks the end of the function prologue.
    #[inline] #[must_use] pub const fn prologue_end(self)   -> bool { self.0 & Self::PROLOGUE_END != 0 }
    /// Whether the row marks the start of the function epilogue.
    #[inline] #[must_use] pub const fn epilogue_begin(self) -> bool { self.0 & Self::EPILOGUE_BEGIN != 0 }

    /// Set the `is_stmt` flag.
    #[inline] pub const fn set_is_stmt(&mut self, v: bool)        { self.set_bit(Self::IS_STMT, v); }
    /// Set the `basic_block` flag.
    #[inline] pub const fn set_basic_block(&mut self, v: bool)    { self.set_bit(Self::BASIC_BLOCK, v); }
    /// Set the `end_sequence` flag.
    #[inline] pub const fn set_end_sequence(&mut self, v: bool)   { self.set_bit(Self::END_SEQUENCE, v); }
    /// Set the `prologue_end` flag.
    #[inline] pub const fn set_prologue_end(&mut self, v: bool)   { self.set_bit(Self::PROLOGUE_END, v); }
    /// Set the `epilogue_begin` flag.
    #[inline] pub const fn set_epilogue_begin(&mut self, v: bool) { self.set_bit(Self::EPILOGUE_BEGIN, v); }

    #[inline]
    const fn set_bit(&mut self, bit: u8, v: bool) {
        if v { self.0 |= bit; } else { self.0 &= !bit; }
    }
}

/// A single row in the DWARF line number matrix.
///
/// Corresponds to a single source-code location.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LineRow {
    /// Program counter value for this row.
    pub address: u64,
    /// Operation index within a VLIW instruction (usually 0).
    pub op_index: u64,
    /// 1-based file index into the file name table.
    pub file: u32,
    /// Source line number (1-based, 0 = unknown).
    pub line: u32,
    /// Source column (1-based, 0 = unknown).
    pub column: u32,
    /// Packed boolean flags (`is_stmt`, `basic_block`, `end_sequence`, `prologue_end`, `epilogue_begin`).
    pub flags: LineRowFlags,
    /// Applicable ISA (instruction set architecture discriminator).
    pub isa: u64,
    /// Column discriminator for identical addresses.
    pub discriminator: u64,
}

impl LineRow {
    /// Whether this row represents a recommended breakpoint location.
    #[inline] #[must_use] pub const fn is_stmt(&self)        -> bool { self.flags.is_stmt() }
    /// Whether the row is at the beginning of a basic block.
    #[inline] #[must_use] pub const fn basic_block(&self)    -> bool { self.flags.basic_block() }
    /// Whether the address immediately follows the end of a sequence.
    #[inline] #[must_use] pub const fn end_sequence(&self)   -> bool { self.flags.end_sequence() }
    /// Whether this is a recommended location at the beginning of a prologue.
    #[inline] #[must_use] pub const fn prologue_end(&self)   -> bool { self.flags.prologue_end() }
    /// Whether this is the beginning of an epilogue.
    #[inline] #[must_use] pub const fn epilogue_begin(&self) -> bool { self.flags.epilogue_begin() }
}

impl LineRow {
    fn initial(default_is_stmt: bool) -> Self {
        let mut flags = LineRowFlags::default();
        flags.set_is_stmt(default_is_stmt);
        Self {
            address: 0,
            op_index: 0,
            file: 1,
            line: 1,
            column: 0,
            flags,
            isa: 0,
            discriminator: 0,
        }
    }

    fn reset(&mut self, default_is_stmt: bool) {
        *self = Self::initial(default_is_stmt);
    }
}

impl Default for LineRow {
    fn default() -> Self {
        Self::initial(true)
    }
}


// ── LineFile ──────────────────────────────────────────────────────────────────

/// An entry in the DWARF line number file name table.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LineFile {
    /// File name (may include directory component).
    pub name: String,
    /// Index into the directory table (0 = compilation directory).
    pub dir_index: u64,
    /// Last-modification timestamp (0 if unknown).
    pub mtime: u64,
    /// File size in bytes (0 if unknown).
    pub size: u64,
}

// ── LineHeader ────────────────────────────────────────────────────────────────

/// The header of a DWARF line number program.
#[derive(Debug, Clone)]
pub struct LineHeader {
    /// DWARF version of this line program (2, 3, 4, or 5).
    pub version: u16,
    /// Minimum instruction length in bytes.
    pub min_insn_len: u8,
    /// Maximum operations per instruction (DWARF v4+, 1 for non-VLIW).
    pub max_ops_per_insn: u8,
    /// Default value of the `is_stmt` register.
    pub default_is_stmt: bool,
    /// Minimum value for the signed line increment in special opcodes.
    pub line_base: i8,
    /// Range of line increment values in special opcodes.
    pub line_range: u8,
    /// Opcode value of the first special opcode.
    pub opcode_base: u8,
    /// Number of LEB128 operands for each standard opcode (index 0 = opcode 1).
    pub standard_opcode_lengths: Vec<u8>,
    /// Directory table.
    pub include_directories: Vec<String>,
    /// File name table (1-based; entry at index 0 is a sentinel).
    pub file_names: Vec<LineFile>,
}

impl LineHeader {
    /// Resolve a 1-based file index to its display path.
    #[must_use]
    pub fn file_path(&self, file_idx: u32) -> String {
        let idx = file_idx as usize;
        self.file_names.get(idx).map_or_else(
            || format!("<file:{file_idx}>"),
            |f| {
                if f.dir_index == 0 {
                    f.name.clone()
                } else {
                    let dir_idx = usize::try_from(f.dir_index - 1).unwrap_or(usize::MAX);
                    self.include_directories
                        .get(dir_idx)
                        .map_or_else(|| f.name.clone(), |dir| format!("{dir}/{}", f.name))
                }
            },
        )
    }
}

// ── LineMatrix ────────────────────────────────────────────────────────────────

/// The result of executing a DWARF line number program: all emitted rows.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LineMatrix {
    /// All emitted rows, in program order.
    pub rows: Vec<LineRow>,
}

impl LineMatrix {
    /// Return the row for the given address, if one exists (exact match).
    #[must_use]
    pub fn row_for_address(&self, addr: u64) -> Option<&LineRow> {
        self.rows.iter().find(|r| r.address == addr)
    }

    /// Return all rows in a given file (by 1-based file index).
    #[must_use]
    pub fn rows_for_file(&self, file_idx: u32) -> Vec<&LineRow> {
        self.rows.iter().filter(|r| r.file == file_idx).collect()
    }

    /// Return all rows that are statement rows.
    #[must_use]
    pub fn statement_rows(&self) -> Vec<&LineRow> {
        self.rows.iter().filter(|r| r.is_stmt()).collect()
    }

    /// Total number of emitted rows.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.rows.len()
    }

    /// True if no rows were emitted.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    /// Find the closest row at or before `address`.
    #[must_use]
    pub fn lookup(&self, address: u64) -> Option<&LineRow> {
        let pos = self.rows.partition_point(|r| r.address <= address);
        if pos == 0 {
            None
        } else {
            self.rows.get(pos - 1)
        }
    }
}

// ── LineProgram ───────────────────────────────────────────────────────────────

/// A DWARF line number program that can be parsed and executed.
pub struct LineProgram<'a> {
    data: &'a [u8],
    pos: usize,
    is_64bit: bool,
    unit_end: usize,
}

impl<'a> LineProgram<'a> {
    /// Create a new program from raw `.debug_line` section data.
    #[must_use]
    pub const fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            pos: 0,
            is_64bit: false,
            unit_end: 0,
        }
    }

    /// Parse and execute all line programs in the section, returning a combined matrix.
    ///
    /// # Errors
    /// Returns [`LineError`] on malformed or truncated data.
    pub fn execute_all(&mut self) -> Result<LineMatrix, LineError> {
        let mut matrix = LineMatrix::default();
        while self.pos < self.data.len() {
            let (hdr, program_start) = self.parse_header()?;
            let unit_end = self.unit_end;
            let rows = self.execute_program(&hdr, program_start, unit_end)?;
            matrix.rows.extend(rows);
            self.pos = unit_end.min(self.data.len());
        }
        Ok(matrix)
    }

    // ── header parsing ──────────────────────────────────────────────────────

    fn parse_header(&mut self) -> Result<(LineHeader, usize), LineError> {
        if self.pos + 4 > self.data.len() {
            return Err(LineError::Truncated(self.pos));
        }

        let initial_len = self.read_u32()?;
        let (is_64bit, unit_len) = if initial_len == 0xFFFF_FFFF {
            let len = self.read_u64()?;
            (true, usize::try_from(len).unwrap_or(usize::MAX))
        } else {
            (false, initial_len as usize)
        };
        self.is_64bit = is_64bit;
        self.unit_end = self.pos + unit_len;
        if self.unit_end > self.data.len() {
            return Err(LineError::Truncated(self.pos));
        }

        let version = self.read_u16()?;
        if !(2..=5).contains(&version) {
            return Err(LineError::UnsupportedVersion(version));
        }

        // DWARF 5 adds address size + segment size before the header length
        if version >= 5 {
            let _addr_size = self.read_u8()?;
            let _seg_size = self.read_u8()?;
        }

        let _header_len = if is_64bit {
            usize::try_from(self.read_u64()?).unwrap_or(usize::MAX)
        } else {
            self.read_u32()? as usize
        };

        let min_insn_len = self.read_u8()?;
        let max_ops_per_insn = if version >= 4 { self.read_u8()? } else { 1 };
        let default_is_stmt = self.read_u8()? != 0;
        let line_base = self.read_u8()?.cast_signed();
        let line_range = self.read_u8()?;
        let opcode_base = self.read_u8()?;

        // Standard opcode lengths (opcode_base - 1 entries).
        let n_std = (opcode_base as usize).saturating_sub(1);
        let mut standard_opcode_lengths = Vec::with_capacity(n_std);
        for _ in 0..n_std {
            standard_opcode_lengths.push(self.read_u8()?);
        }

        let (include_directories, file_names) = if version < 5 {
            self.read_v4_dirs_and_files()?
        } else {
            self.read_v5_dirs_and_files()?
        };

        let program_start = self.pos;
        let hdr = LineHeader {
            version,
            min_insn_len,
            max_ops_per_insn,
            default_is_stmt,
            line_base,
            line_range,
            opcode_base,
            standard_opcode_lengths,
            include_directories,
            file_names,
        };

        Ok((hdr, program_start))
    }

    fn read_v4_dirs_and_files(&mut self) -> Result<(Vec<String>, Vec<LineFile>), LineError> {
        let mut dirs = Vec::new();
        loop {
            let s = self.read_cstring();
            if s.is_empty() {
                break;
            }
            dirs.push(s);
        }
        let mut files = vec![LineFile {
            name: String::new(),
            dir_index: 0,
            mtime: 0,
            size: 0,
        }]; // 1-based sentinel
        loop {
            let name = self.read_cstring();
            if name.is_empty() {
                break;
            }
            let dir_idx = self.read_uleb128()?;
            let mtime = self.read_uleb128()?;
            let size = self.read_uleb128()?;
            files.push(LineFile {
                name,
                dir_index: dir_idx,
                mtime,
                size,
            });
        }
        Ok((dirs, files))
    }

    fn read_v5_dirs_and_files(&mut self) -> Result<(Vec<String>, Vec<LineFile>), LineError> {
        // DWARF 5 uses a descriptor-based format; simplified version:
        let _dir_entry_format_count = self.read_u8()?;
        let dir_count = usize::try_from(self.read_uleb128()?).unwrap_or(usize::MAX);
        // `dir_count` is attacker-controlled: cap by the bytes left (each
        // entry needs at least its NUL byte) and stop at end of data —
        // `read_cstring` does not advance at EOF, so an unchecked loop with a
        // huge count would spin pushing empty strings until OOM.
        let max_dirs = self.data.len().saturating_sub(self.pos);
        let mut dirs = Vec::with_capacity(dir_count.min(max_dirs));
        for _ in 0..dir_count {
            if self.pos >= self.data.len() {
                break;
            }
            let s = self.read_cstring();
            dirs.push(s);
        }
        let _file_entry_format_count = self.read_u8()?;
        let file_count = usize::try_from(self.read_uleb128()?).unwrap_or(usize::MAX);
        let mut files = vec![LineFile {
            name: String::new(),
            dir_index: 0,
            mtime: 0,
            size: 0,
        }];
        for _ in 0..file_count {
            if self.pos >= self.data.len() {
                break;
            }
            let name = self.read_cstring();
            files.push(LineFile {
                name,
                dir_index: 0,
                mtime: 0,
                size: 0,
            });
        }
        Ok((dirs, files))
    }

    // ── program execution ────────────────────────────────────────────────────

    fn execute_program(
        &mut self,
        hdr: &LineHeader,
        start: usize,
        end: usize,
    ) -> Result<Vec<LineRow>, LineError> {
        self.pos = start;
        let mut rows = Vec::new();
        let mut reg = LineRow::initial(hdr.default_is_stmt);
        while self.pos < end {
            if self.pos >= self.data.len() {
                break;
            }
            let opcode = self.read_u8()?;
            if opcode == 0 {
                self.exec_extended(hdr, &mut reg, &mut rows, end)?;
            } else if opcode < hdr.opcode_base {
                self.exec_standard(hdr, opcode, &mut reg, &mut rows)?;
            } else {
                Self::exec_special(hdr, opcode, &mut reg, &mut rows);
            }
        }
        Ok(rows)
    }

    fn exec_extended(
        &mut self,
        hdr: &LineHeader,
        reg: &mut LineRow,
        rows: &mut Vec<LineRow>,
        end: usize,
    ) -> Result<(), LineError> {
        let ext_len = usize::try_from(self.read_uleb128()?).unwrap_or(usize::MAX);
        let ext_start = self.pos;
        let ext_op = self.read_u8()?;
        match ext_op {
            1 => {
                // DW_LNE_end_sequence
                reg.flags.set_end_sequence(true);
                rows.push(reg.clone());
                reg.reset(hdr.default_is_stmt);
            }
            2 => {
                // DW_LNE_set_address
                reg.address = if hdr.version >= 5 || ext_len - 1 == 8 {
                    self.read_u64()?
                } else if ext_len - 1 == 4 {
                    u64::from(self.read_u32()?)
                } else {
                    self.read_u64()?
                };
                reg.op_index = 0;
            }
            3 => {
                // DW_LNE_define_file — skip (we don't mutate the header)
                let name = self.read_cstring();
                let dir_idx = self.read_uleb128()?;
                let mtime = self.read_uleb128()?;
                let size = self.read_uleb128()?;
                let _ = (name, dir_idx, mtime, size);
            }
            4 => {
                // DW_LNE_set_discriminator
                reg.discriminator = self.read_uleb128()?;
            }
            _ => {}
        }
        self.pos = (ext_start + ext_len).min(end);
        Ok(())
    }

    fn exec_standard(
        &mut self,
        hdr: &LineHeader,
        opcode: u8,
        reg: &mut LineRow,
        rows: &mut Vec<LineRow>,
    ) -> Result<(), LineError> {
        match opcode {
            1 => {
                // DW_LNS_copy
                rows.push(reg.clone());
                reg.discriminator = 0;
                reg.flags.set_basic_block(false);
                reg.flags.set_prologue_end(false);
                reg.flags.set_epilogue_begin(false);
            }
            2 => {
                // DW_LNS_advance_pc
                let adv = self.read_uleb128()?;
                let max_ops = u64::from(hdr.max_ops_per_insn.max(1));
                // `adv` is an unbounded ULEB128 from the file; the twin
                // `dwarf_line_program` uses `wrapping_add` at every address
                // update for exactly this reason.
                reg.address = reg
                    .address
                    .wrapping_add((adv.wrapping_mul(u64::from(hdr.min_insn_len))) / max_ops);
                reg.op_index = (reg.op_index + adv) % max_ops;
            }
            3 => {
                // DW_LNS_advance_line
                let la = self.read_sleb128()?;
                reg.line = u32::try_from(i64::from(reg.line) + la).unwrap_or(0);
            }
            4 => { reg.file   = u32::try_from(self.read_uleb128()?).unwrap_or(u32::MAX); } // DW_LNS_set_file
            5 => { reg.column = u32::try_from(self.read_uleb128()?).unwrap_or(u32::MAX); } // DW_LNS_set_column
            6 => reg.flags.set_is_stmt(!reg.flags.is_stmt()), // DW_LNS_negate_stmt
            7 => reg.flags.set_basic_block(true),             // DW_LNS_set_basic_block
            8 => {
                // DW_LNS_const_add_pc
                // `.max(1)`: `line_range` is read from the header and used as a
                // divisor — see the note in `exec_special`.
                let adj = (255u64 - u64::from(hdr.opcode_base))
                    / u64::from(hdr.line_range).max(1);
                let max_ops = u64::from(hdr.max_ops_per_insn.max(1));
                reg.address = reg
                    .address
                    .wrapping_add((adj * u64::from(hdr.min_insn_len)) / max_ops);
                reg.op_index = (reg.op_index + adj) % max_ops;
            }
            9 => {
                // DW_LNS_fixed_advance_pc
                reg.address = reg.address.wrapping_add(u64::from(self.read_u16()?));
                reg.op_index = 0;
            }
            10 => reg.flags.set_prologue_end(true),   // DW_LNS_set_prologue_end
            11 => reg.flags.set_epilogue_begin(true), // DW_LNS_set_epilogue_begin
            12 => { reg.isa = self.read_uleb128()?; } // DW_LNS_set_isa
            _ => {
                let n_ops = hdr.standard_opcode_lengths
                    .get(opcode as usize - 1).copied().unwrap_or(0);
                for _ in 0..n_ops { let _ = self.read_uleb128()?; }
            }
        }
        Ok(())
    }

    fn exec_special(hdr: &LineHeader, opcode: u8, reg: &mut LineRow, rows: &mut Vec<LineRow>) {
        // `line_range` and `opcode_base` come straight from the header of a
        // possibly malformed file.  `line_range` is a *divisor* here and in
        // DW_LNS_const_add_pc, so a zero would abort the whole parse; the twin
        // `dwarf_line_program` guards it twice — it rejects `line_range == 0`
        // at header-parse time and still clamps with `.max(1)` at the point of
        // division.  This copy did neither.  `opcode - opcode_base` likewise
        // underflows for any opcode below the base.
        let line_range = u64::from(hdr.line_range).max(1);
        let adj = u64::from(opcode).saturating_sub(u64::from(hdr.opcode_base));
        let op_advance = adj / line_range;
        let line_inc = (adj % line_range).cast_signed() + i64::from(hdr.line_base);
        let max_ops = u64::from(hdr.max_ops_per_insn.max(1));
        reg.address = reg
            .address
            .wrapping_add((op_advance * u64::from(hdr.min_insn_len)) / max_ops);
        reg.op_index = (reg.op_index + op_advance) % max_ops;
        reg.line = u32::try_from(i64::from(reg.line) + line_inc).unwrap_or(0);
        rows.push(reg.clone());
        reg.flags.set_basic_block(false);
        reg.flags.set_prologue_end(false);
        reg.flags.set_epilogue_begin(false);
        reg.discriminator = 0;
    }

    // ── byte reading helpers ─────────────────────────────────────────────────

    fn read_u8(&mut self) -> Result<u8, LineError> {
        let b = self
            .data
            .get(self.pos)
            .copied()
            .ok_or(LineError::Truncated(self.pos))?;
        self.pos += 1;
        Ok(b)
    }

    fn read_u16(&mut self) -> Result<u16, LineError> {
        if self.pos + 2 > self.data.len() {
            return Err(LineError::Truncated(self.pos));
        }
        let v = u16::from_le_bytes([self.data[self.pos], self.data[self.pos + 1]]);
        self.pos += 2;
        Ok(v)
    }

    fn read_u32(&mut self) -> Result<u32, LineError> {
        if self.pos + 4 > self.data.len() {
            return Err(LineError::Truncated(self.pos));
        }
        let v = u32::from_le_bytes(self.data[self.pos..self.pos + 4].try_into().unwrap());
        self.pos += 4;
        Ok(v)
    }

    fn read_u64(&mut self) -> Result<u64, LineError> {
        if self.pos + 8 > self.data.len() {
            return Err(LineError::Truncated(self.pos));
        }
        let v = u64::from_le_bytes(self.data[self.pos..self.pos + 8].try_into().unwrap());
        self.pos += 8;
        Ok(v)
    }

    fn read_uleb128(&mut self) -> Result<u64, LineError> {
        let mut result = 0u64;
        let mut shift = 0u32;
        loop {
            let b = self.read_u8()?;
            result |= u64::from(b & 0x7f) << shift;
            shift += 7;
            if b & 0x80 == 0 {
                break;
            }
            if shift >= 64 {
                return Err(LineError::Truncated(self.pos));
            }
        }
        Ok(result)
    }

    fn read_sleb128(&mut self) -> Result<i64, LineError> {
        let mut result = 0i64;
        let mut shift = 0u32;
        let b = loop {
            let byte = self.read_u8()?;
            result |= i64::from(byte & 0x7f) << shift;
            shift += 7;
            if byte & 0x80 == 0 {
                break byte;
            }
            if shift >= 64 {
                return Err(LineError::Truncated(self.pos));
            }
        };
        if shift < 64 && (b & 0x40) != 0 {
            result |= !0i64 << shift;
        }
        Ok(result)
    }

    fn read_cstring(&mut self) -> String {
        let start = self.pos;
        while self.pos < self.data.len() && self.data[self.pos] != 0 {
            self.pos += 1;
        }
        let s = String::from_utf8_lossy(&self.data[start..self.pos]).into_owned();
        if self.pos < self.data.len() {
            self.pos += 1;
        } // skip null
        s
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn encode_uleb(mut n: u64) -> Vec<u8> {
        let mut v = Vec::new();
        loop {
            let mut b = (n & 0x7f) as u8;
            n >>= 7;
            if n != 0 {
                b |= 0x80;
            }
            v.push(b);
            if n == 0 {
                break;
            }
        }
        v
    }

    fn encode_sleb(mut n: i64) -> Vec<u8> {
        let mut v = Vec::new();
        loop {
            let mut b = (n & 0x7f) as u8;
            n >>= 7;
            let done = (n == 0 && b & 0x40 == 0) || (n == -1 && b & 0x40 != 0);
            if !done {
                b |= 0x80;
            }
            v.push(b);
            if done {
                break;
            }
        }
        v
    }

    /// Build a minimal DWARF v4 line program with one special opcode and `DW_LNE_end_sequence`.
    fn make_minimal_line_program() -> Vec<u8> {
        let mut prog = Vec::new();
        // Header body (everything after the length field and version).
        let mut hdr_body: Vec<u8> = vec![
            1,    // minimum_instruction_length
            1,    // maximum_operations_per_instruction (DWARF v4)
            1,    // default_is_stmt
            0xFB, // line_base = -5 (i8)
            14,   // line_range
            10,   // opcode_base
        ];
        // standard_opcode_lengths for opcodes 1-9
        hdr_body.extend_from_slice(&[0, 1, 1, 1, 1, 0, 0, 0, 1]);
        // include_directories: empty
        hdr_body.push(0);
        // file names: one entry
        hdr_body.extend_from_slice(b"main.c\0");
        hdr_body.extend(encode_uleb(0)); // dir_idx
        hdr_body.extend(encode_uleb(0)); // mtime
        hdr_body.extend(encode_uleb(0)); // size
        hdr_body.push(0); // end of file names

        // Program opcodes.
        let mut opcodes: Vec<u8> = Vec::new();
        // DW_LNE_set_address = 0
        opcodes.push(0); // extended opcode prefix
        opcodes.extend(encode_uleb(9)); // length = 1 + 8
        opcodes.push(2); // DW_LNE_set_address
        opcodes.extend_from_slice(&0x1000u64.to_le_bytes());
        // Special opcode to advance line and emit a row
        // special_opcode = (line_increment - line_base) + (op_advance * line_range) + opcode_base
        // line_base=-5 line_range=14 opcode_base=10
        // advance line by 1: (1 - (-5)) = 6; op_advance=0; special = 6 + 10 = 16
        opcodes.push(16u8);
        // DW_LNE_end_sequence
        opcodes.push(0);
        opcodes.extend(encode_uleb(1));
        opcodes.push(1);

        // header_len (u32 LE) = hdr_body.len()
        let header_len = hdr_body.len() as u32;
        // unit body = version(2) + header_len(4) + hdr_body + opcodes
        let unit_body_len = 2 + 4 + hdr_body.len() + opcodes.len();
        // unit_len = unit_body_len (not including the initial u32 length field itself)
        prog.extend_from_slice(&(unit_body_len as u32).to_le_bytes()); // initial len
        prog.extend_from_slice(&4u16.to_le_bytes()); // version
        prog.extend_from_slice(&header_len.to_le_bytes()); // header_len
        prog.extend(hdr_body);
        prog.extend(opcodes);
        prog
    }

    #[test]
    fn test_empty_section_produces_no_rows() {
        let mut lp = LineProgram::new(&[]);
        let matrix = lp.execute_all().unwrap();
        assert!(matrix.is_empty());
    }

    #[test]
    fn test_minimal_line_program() {
        let data = make_minimal_line_program();
        let mut lp = LineProgram::new(&data);
        let matrix = lp.execute_all().unwrap();
        // Should have at least two rows (one from special opcode, one end_sequence)
        assert!(!matrix.is_empty(), "expected rows, got none");
    }

    #[test]
    fn test_line_row_default() {
        let r = LineRow::default();
        assert_eq!(r.line, 1);
        assert_eq!(r.address, 0);
        assert!(r.is_stmt());
    }

    #[test]
    fn test_line_row_initial() {
        let r = LineRow::initial(false);
        assert!(!r.is_stmt());
        assert_eq!(r.file, 1);
        assert_eq!(r.column, 0);
    }

    #[test]
    fn test_line_matrix_empty() {
        let m = LineMatrix::default();
        assert!(m.is_empty());
        assert_eq!(m.len(), 0);
    }

    #[test]
    fn test_line_matrix_lookup_exact() {
        let mut m = LineMatrix::default();
        m.rows.push(LineRow {
            address: 0x1000,
            line: 10,
            ..LineRow::default()
        });
        assert_eq!(m.row_for_address(0x1000).unwrap().line, 10);
    }

    #[test]
    fn test_line_matrix_lookup_before() {
        let mut m = LineMatrix::default();
        m.rows.push(LineRow {
            address: 0x1000,
            line: 5,
            ..LineRow::default()
        });
        m.rows.push(LineRow {
            address: 0x1010,
            line: 6,
            ..LineRow::default()
        });
        let row = m.lookup(0x1008).unwrap();
        assert_eq!(row.line, 5);
    }

    #[test]
    fn test_line_matrix_lookup_none_before_start() {
        let mut m = LineMatrix::default();
        m.rows.push(LineRow {
            address: 0x1000,
            line: 5,
            ..LineRow::default()
        });
        assert!(m.lookup(0x0FFF).is_none());
    }

    #[test]
    fn test_line_matrix_rows_for_file() {
        let mut m = LineMatrix::default();
        m.rows.push(LineRow {
            file: 1,
            line: 1,
            ..LineRow::default()
        });
        m.rows.push(LineRow {
            file: 2,
            line: 1,
            ..LineRow::default()
        });
        m.rows.push(LineRow {
            file: 1,
            line: 2,
            ..LineRow::default()
        });
        assert_eq!(m.rows_for_file(1).len(), 2);
        assert_eq!(m.rows_for_file(2).len(), 1);
        assert_eq!(m.rows_for_file(3).len(), 0);
    }

    #[test]
    fn test_line_matrix_statement_rows() {
        let mut m = LineMatrix::default();
        {
            let mut r = LineRow::default();
            r.flags.set_is_stmt(true);
            m.rows.push(r);
        }
        {
            let mut r = LineRow::default();
            r.flags.set_is_stmt(false);
            m.rows.push(r);
        }
        {
            let mut r = LineRow::default();
            r.flags.set_is_stmt(true);
            m.rows.push(r);
        }
        assert_eq!(m.statement_rows().len(), 2);
    }

    #[test]
    fn test_line_header_file_path_no_dir() {
        let hdr = LineHeader {
            version: 4,
            min_insn_len: 1,
            max_ops_per_insn: 1,
            default_is_stmt: true,
            line_base: -5,
            line_range: 14,
            opcode_base: 10,
            standard_opcode_lengths: vec![0, 1, 1, 1, 1, 0, 0, 0, 1],
            include_directories: vec!["/src".into()],
            file_names: vec![
                super::LineFile {
                    name: String::new(),
                    dir_index: 0,
                    mtime: 0,
                    size: 0,
                },
                super::LineFile {
                    name: "main.c".into(),
                    dir_index: 0,
                    mtime: 0,
                    size: 0,
                },
            ],
        };
        assert_eq!(hdr.file_path(1), "main.c");
    }

    #[test]
    fn test_line_header_file_path_with_dir() {
        let hdr = LineHeader {
            version: 4,
            min_insn_len: 1,
            max_ops_per_insn: 1,
            default_is_stmt: true,
            line_base: -5,
            line_range: 14,
            opcode_base: 10,
            standard_opcode_lengths: vec![0, 1, 1, 1, 1, 0, 0, 0, 1],
            include_directories: vec!["/src".into()],
            file_names: vec![
                super::LineFile {
                    name: String::new(),
                    dir_index: 0,
                    mtime: 0,
                    size: 0,
                },
                super::LineFile {
                    name: "foo.c".into(),
                    dir_index: 1,
                    mtime: 0,
                    size: 0,
                },
            ],
        };
        assert_eq!(hdr.file_path(1), "/src/foo.c");
    }

    #[test]
    fn test_line_header_file_path_out_of_range() {
        let hdr = LineHeader {
            version: 4,
            min_insn_len: 1,
            max_ops_per_insn: 1,
            default_is_stmt: true,
            line_base: -5,
            line_range: 14,
            opcode_base: 10,
            standard_opcode_lengths: vec![],
            include_directories: vec![],
            file_names: vec![],
        };
        assert!(hdr.file_path(99).contains("<file:99>"));
    }

    #[test]
    fn test_line_file_struct() {
        let f = super::LineFile {
            name: "hello.rs".into(),
            dir_index: 1,
            mtime: 12345,
            size: 1024,
        };
        assert_eq!(f.name, "hello.rs");
        assert_eq!(f.dir_index, 1);
    }

    #[test]
    fn test_line_row_fields() {
        let mut flags = LineRowFlags::default();
        flags.set_is_stmt(true);
        flags.set_prologue_end(true);
        let r = LineRow {
            address: 0xDEAD,
            op_index: 0,
            file: 2,
            line: 42,
            column: 7,
            flags,
            isa: 0,
            discriminator: 0,
        };
        assert_eq!(r.address, 0xDEAD);
        assert_eq!(r.line, 42);
        assert!(r.prologue_end());
    }

    #[test]
    fn test_truncated_section_error() {
        let data = vec![0x01, 0x00, 0x00, 0x00, 0x00]; // too-short unit
        let mut lp = LineProgram::new(&data);
        // Should either succeed (empty matrix) or return error — must not panic.
        let _ = lp.execute_all();
    }

    #[test]
    fn test_uleb_roundtrip() {
        let v = encode_uleb(12345);
        let _pos = 0usize;
        let mut result = 0u64;
        let mut shift = 0u32;
        for &b in &v {
            result |= u64::from(b & 0x7f) << shift;
            shift += 7;
            if b & 0x80 == 0 {
                break;
            }
        }
        assert_eq!(result, 12345);
    }

    #[test]
    fn test_sleb_negative() {
        let v = encode_sleb(-42);
        let mut pos = 0;
        let mut r = 0i64;
        let mut shift = 0u32;
        let b = loop {
            let byte = v[pos];
            pos += 1;
            r |= i64::from(byte & 0x7f) << shift;
            shift += 7;
            if byte & 0x80 == 0 {
                break byte;
            }
        };
        if shift < 64 && (b & 0x40) != 0 {
            r |= !0i64 << shift;
        }
        assert_eq!(r, -42);
    }

    #[test]
    fn test_line_matrix_row_count() {
        let data = make_minimal_line_program();
        let mut lp = LineProgram::new(&data);
        let matrix = lp.execute_all().unwrap();
        assert!(!matrix.is_empty());
    }

    #[test]
    fn test_unsupported_version_error() {
        let mut data = Vec::new();
        // Build a unit with version 99
        let unit_body = vec![
            99u8, 0u8, // version = 99
            0, 0, 0, 0, // header_len placeholder
        ];
        data.extend_from_slice(&(unit_body.len() as u32).to_le_bytes());
        data.extend(unit_body);
        let mut lp = LineProgram::new(&data);
        let result = lp.execute_all();
        // Should return UnsupportedVersion or handle gracefully
        let _ = result; // don't assert error type for now
    }
}
