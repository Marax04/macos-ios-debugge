// source_map.rs — Source code mapping and line-level debugging
// Part of rustre-debug crate
//
// Provides:
//   - DWARF line table parsing (.debug_line state machine)
//   - Address ↔ source location bidirectional lookup
//   - Source file cache with content retrieval
//   - Source-root path remapping
//   - Breakpoint resolution by source file + line

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use parking_lot::RwLock;
use std::fmt;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub enum SourceMapError {
    NoLinetableForAddress(u64),
    SourceFileNotFound(PathBuf),
    LineOutOfRange { file: PathBuf, line: u32 },
    NoAddressForLine { file: String, line: u32 },
    Io(String),
    MalformedDwarf(String),
    AmbiguousLine { file: String, line: u32, candidates: Vec<u64> },
}

impl fmt::Display for SourceMapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoLinetableForAddress(a) =>
                write!(f, "no source mapping for address 0x{a:x}"),
            Self::SourceFileNotFound(p) =>
                write!(f, "source file not found: {}", p.display()),
            Self::LineOutOfRange { file, line } =>
                write!(f, "line {line} out of range in {}", file.display()),
            Self::NoAddressForLine { file, line } =>
                write!(f, "no address for {file}:{line}"),
            Self::Io(s) => write!(f, "I/O error: {s}"),
            Self::MalformedDwarf(s) => write!(f, "malformed DWARF: {s}"),
            Self::AmbiguousLine { file, line, candidates } =>
                write!(f, "ambiguous source line {file}:{line} ({} candidates)", candidates.len()),
        }
    }
}

pub type SourceResult<T> = Result<T, SourceMapError>;

// ---------------------------------------------------------------------------
// Source location
// ---------------------------------------------------------------------------

/// A precise source code location.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SourceLocation {
    pub file:     PathBuf,
    pub line:     u32,
    pub column:   u32,
    pub function: Option<String>,
}

impl SourceLocation {
    pub fn new(file: impl Into<PathBuf>, line: u32) -> Self {
        Self { file: file.into(), line, column: 0, function: None }
    }

    #[must_use]
    pub const fn with_column(mut self, col: u32) -> Self { self.column = col; self }
    #[must_use]
    pub fn with_function(mut self, func: impl Into<String>) -> Self {
        self.function = Some(func.into()); self
    }
}

impl fmt::Display for SourceLocation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.file.display(), self.line)?;
        if self.column > 0 { write!(f, ":{}", self.column)?; }
        if let Some(func) = &self.function { write!(f, " (in {func})")?; }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// DWARF line table structures
// ---------------------------------------------------------------------------

/// Row-level state flags for a DWARF line table entry packed into a byte.
///
/// Bit 0 = basic\_block, bit 1 = end\_sequence, bit 2 = prologue\_end,
/// bit 3 = epilogue\_begin.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LineRowFlags(pub u8);

impl LineRowFlags {
    /// Statement at a basic-block boundary.
    #[must_use] pub const fn basic_block(self) -> bool    { self.0 & 0x01 != 0 }
    /// Marks the end of a sequence of instructions.
    #[must_use] pub const fn end_sequence(self) -> bool   { self.0 & 0x02 != 0 }
    /// Marks the end of the function prologue.
    #[must_use] pub const fn prologue_end(self) -> bool   { self.0 & 0x04 != 0 }
    /// Marks the start of a function epilogue.
    #[must_use] pub const fn epilogue_begin(self) -> bool { self.0 & 0x08 != 0 }

    pub const fn set_basic_block(&mut self)    { self.0 |= 0x01; }
    pub const fn set_end_sequence(&mut self)   { self.0 |= 0x02; }
    pub const fn set_prologue_end(&mut self)   { self.0 |= 0x04; }
    pub const fn set_epilogue_begin(&mut self) { self.0 |= 0x08; }
    pub const fn clear_row_fields(&mut self)   { self.0 &= !0x0F; }
}

/// A single row of the DWARF line table (after state machine execution).
#[derive(Debug, Clone)]
pub struct LineTableRow {
    pub address:          u64,
    pub op_index:         u32,   // DWARF4+ op-index within a VLIW instruction word
    pub file_index:       u32,   // 1-based index into file_names
    pub line:             u32,
    pub column:           u32,
    pub is_stmt:          bool,  // recommended breakpoint position
    pub row_flags:        LineRowFlags,
    pub isa:              u32,
    pub discriminator:    u32,
}

impl LineTableRow {
    const fn initial_state() -> Self {
        Self {
            address:       0,
            op_index:      0,
            file_index:    1,
            line:          1,
            column:        0,
            is_stmt:       true,
            row_flags:     LineRowFlags(0),
            isa:           0,
            discriminator: 0,
        }
    }

    const fn reset_row_fields(&mut self) {
        self.row_flags.clear_row_fields();
        self.discriminator  = 0;
    }
}

/// Header for a DWARF `.debug_line` compilation unit.
#[derive(Debug, Clone)]
pub struct LineTableHeader {
    pub minimum_instruction_length:    u8,
    pub maximum_ops_per_instruction:   u8,
    pub default_is_stmt:               bool,
    pub line_base:                     i8,
    pub line_range:                    u8,
    pub opcode_base:                   u8,
    pub standard_opcode_lengths:       Vec<u8>,
    pub include_directories:           Vec<PathBuf>,
    pub file_names:                    Vec<FileEntry>,
    pub address_size:                  u8,   // 4 or 8
    pub is_64bit:                      bool, // DWARF-64 format
    pub version:                       u16,
}

#[derive(Debug, Clone)]
pub struct FileEntry {
    pub name:            PathBuf,
    pub dir_index:       u32,  // 0 = compilation directory, otherwise into include_directories
    pub modification:    u64,
    pub length:          u64,
}

impl FileEntry {
    #[must_use]
    pub fn resolve_path(&self, header: &LineTableHeader, comp_dir: &Path) -> PathBuf {
        let base = if self.dir_index == 0 {
            comp_dir.to_path_buf()
        } else {
            header.include_directories
                .get((self.dir_index as usize).saturating_sub(1))
                .cloned()
                .unwrap_or_else(|| comp_dir.to_path_buf())
        };
        base.join(&self.name)
    }
}

// ---------------------------------------------------------------------------
// DWARF line program opcodes
// ---------------------------------------------------------------------------

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StdOpcode {
    Copy              = 0x01,
    AdvancePc         = 0x02,
    AdvanceLine       = 0x03,
    SetFile           = 0x04,
    SetColumn         = 0x05,
    NegateStmt        = 0x06,
    SetBasicBlock     = 0x07,
    ConstAddPc        = 0x08,
    FixedAdvancePc    = 0x09,
    SetPrologueEnd    = 0x0A,
    SetEpilogueBegin  = 0x0B,
    SetIsa            = 0x0C,
}

impl StdOpcode {
    /// Convert a raw opcode byte into a [`StdOpcode`].
    #[must_use]
    pub const fn from_u8(b: u8) -> Option<Self> {
        Some(match b {
            0x01 => Self::Copy,
            0x02 => Self::AdvancePc,
            0x03 => Self::AdvanceLine,
            0x04 => Self::SetFile,
            0x05 => Self::SetColumn,
            0x06 => Self::NegateStmt,
            0x07 => Self::SetBasicBlock,
            0x08 => Self::ConstAddPc,
            0x09 => Self::FixedAdvancePc,
            0x0A => Self::SetPrologueEnd,
            0x0B => Self::SetEpilogueBegin,
            0x0C => Self::SetIsa,
            _    => return None,
        })
    }

    /// Numeric opcode value.
    #[must_use]
    pub const fn as_u8(self) -> u8 { self as u8 }
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExtOpcode {
    EndSequence    = 0x01,
    SetAddress     = 0x02,
    DefineFile     = 0x03,
    SetDiscrim     = 0x04,
    LoUser         = 0x80,
    HiUser         = 0xFF,
}

impl ExtOpcode {
    /// Convert a raw extended-opcode byte into an [`ExtOpcode`].
    #[must_use]
    pub const fn from_u8(b: u8) -> Option<Self> {
        Some(match b {
            0x01 => Self::EndSequence,
            0x02 => Self::SetAddress,
            0x03 => Self::DefineFile,
            0x04 => Self::SetDiscrim,
            0x80 => Self::LoUser,
            0xFF => Self::HiUser,
            _    => return None,
        })
    }

    /// Numeric opcode value.
    #[must_use]
    pub const fn as_u8(self) -> u8 { self as u8 }

    /// True if this is in the user-defined opcode range.
    #[must_use]
    pub const fn is_user(self) -> bool {
        matches!(self, Self::LoUser | Self::HiUser)
    }
}

// ---------------------------------------------------------------------------
// Line table state machine
// ---------------------------------------------------------------------------

pub struct LineTableStateMachine<'a> {
    header: &'a LineTableHeader,
    data:   &'a [u8],
    pos:    usize,
    state:  LineTableRow,
    rows:   Vec<LineTableRow>,
}

impl<'a> LineTableStateMachine<'a> {
    #[must_use]
    pub const fn new(header: &'a LineTableHeader, data: &'a [u8]) -> Self {
        let mut state = LineTableRow::initial_state();
        state.is_stmt = header.default_is_stmt;
        Self { header, data, pos: 0, state, rows: Vec::new() }
    }

    fn read_u8(&mut self) -> Option<u8> {
        let b = *self.data.get(self.pos)?;
        self.pos += 1;
        Some(b)
    }

    fn read_u16(&mut self) -> Option<u16> {
        let a = u16::from(self.read_u8()?);
        let b = u16::from(self.read_u8()?);
        Some(a | (b << 8))
    }

    fn read_u32(&mut self) -> Option<u32> {
        let a = u32::from(self.read_u16()?);
        let b = u32::from(self.read_u16()?);
        Some(a | (b << 16))
    }

    fn read_u64(&mut self) -> Option<u64> {
        let a = u64::from(self.read_u32()?);
        let b = u64::from(self.read_u32()?);
        Some(a | (b << 32))
    }

    fn read_address(&mut self) -> Option<u64> {
        if self.header.address_size == 8 { self.read_u64() } else { self.read_u32().map(u64::from) }
    }

    /// Read ULEB128-encoded unsigned integer.
    fn read_uleb128(&mut self) -> Option<u64> {
        let mut result = 0u64;
        let mut shift  = 0u32;
        loop {
            let byte = self.read_u8()?;
            result |= u64::from(byte & 0x7F) << shift;
            shift += 7;
            if byte & 0x80 == 0 { break; }
            if shift >= 64 { return None; }
        }
        Some(result)
    }

    /// Read SLEB128-encoded signed integer.
    fn read_sleb128(&mut self) -> Option<i64> {
        let mut result = 0i64;
        let mut shift  = 0u32;
        loop {
            let byte = self.read_u8()?;
            result |= i64::from(byte & 0x7F) << shift;
            shift += 7;
            if byte & 0x80 == 0 {
                // Sign extend if needed
                if shift < 64 && (byte & 0x40) != 0 {
                    result |= -(1i64 << shift);
                }
                break;
            }
            if shift >= 64 { return None; }
        }
        Some(result)
    }

    fn read_null_terminated(&mut self) -> Option<Vec<u8>> {
        let mut bytes = Vec::with_capacity(32);
        loop {
            let b = self.read_u8()?;
            if b == 0 { break; }
            bytes.push(b);
        }
        Some(bytes)
    }

    fn advance_pc(&mut self, op_advance: u64) {
        let min = u64::from(self.header.minimum_instruction_length);
        let max_ops = u64::from(self.header.maximum_ops_per_instruction);
        if max_ops <= 1 {
            // DWARF3 or single-op-per-instruction: simple multiply
            self.state.address = self.state.address.wrapping_add(op_advance.wrapping_mul(min));
            self.state.op_index = 0;
        } else {
            // DWARF4+ full formula (DWARF spec §6.2.5.1):
            //   address  += minimum_instruction_length
            //               * ((op_index + op_advance) / maximum_ops_per_instruction)
            //   op_index  = (op_index + op_advance) % maximum_ops_per_instruction
            let combined = u64::from(self.state.op_index).wrapping_add(op_advance);
            self.state.address = self.state.address.wrapping_add(min.wrapping_mul(combined / max_ops));
            self.state.op_index = u32::try_from(combined % max_ops).unwrap_or(u32::MAX);
        }
    }

    fn emit_row(&mut self) {
        self.rows.push(self.state.clone());
        self.state.reset_row_fields();
    }

    fn exec_extended(&mut self, ext: u8, remaining: usize) {
        match ext {
            0x01 /* EndSequence */ => {
                self.state.row_flags.set_end_sequence();
                self.emit_row();
                self.state = LineTableRow::initial_state();
                self.state.is_stmt = self.header.default_is_stmt;
            }
            0x02 /* SetAddress */ => {
                self.state.address = self.read_address().unwrap_or(0);
            }
            0x03 /* DefineFile */ => {
                let name_bytes = self.read_null_terminated().unwrap_or_default();
                let name = String::from_utf8_lossy(&name_bytes).into_owned();
                let dir_index = u32::try_from(self.read_uleb128().unwrap_or(0)).unwrap_or(u32::MAX);
                let mtime     = self.read_uleb128().unwrap_or(0);
                let file_len  = self.read_uleb128().unwrap_or(0);
                let _ = (name, dir_index, mtime, file_len);
            }
            0x04 /* SetDiscriminator */ => {
                self.state.discriminator = u32::try_from(self.read_uleb128().unwrap_or(0)).unwrap_or(u32::MAX);
            }
            _ => { for _ in 0..remaining { self.read_u8(); } }
        }
    }

    /// Execute the line program until exhausted. Returns all line table rows.
    ///
    /// # Errors
    ///
    /// Returns `SourceMapError` if the line program is malformed.
    pub fn execute(&mut self) -> Result<Vec<LineTableRow>, SourceMapError> {
        while self.pos < self.data.len() {
            let Some(opcode) = self.read_u8() else { break };

            if opcode == 0 {
                // Extended opcode — validate length against remaining buffer
                let Some(raw_len) = self.read_uleb128() else { break };
                let remaining_bytes = self.data.len().saturating_sub(self.pos);
                let len = match usize::try_from(raw_len) {
                    Ok(l) if l <= remaining_bytes => l,
                    _ => break,
                };
                let Some(ext) = self.read_u8() else { break };
                self.exec_extended(ext, len.saturating_sub(1));
            } else if opcode < self.header.opcode_base {
                // Standard opcode
                match opcode {
                    0x01 /* Copy */ => {
                        self.emit_row();
                    }
                    0x02 /* AdvancePC */ => {
                        let op_advance = self.read_uleb128().unwrap_or(0);
                        self.advance_pc(op_advance);
                    }
                    0x03 /* AdvanceLine */ => {
                        let delta = self.read_sleb128().unwrap_or(0);
                        self.state.line = u32::try_from((i64::from(self.state.line) + delta).max(1)).unwrap_or(u32::MAX);
                    }
                    0x04 /* SetFile */ => {
                        self.state.file_index = u32::try_from(self.read_uleb128().unwrap_or(1)).unwrap_or(u32::MAX);
                    }
                    0x05 /* SetColumn */ => {
                        self.state.column = u32::try_from(self.read_uleb128().unwrap_or(0)).unwrap_or(u32::MAX);
                    }
                    0x06 /* NegateStmt */ => {
                        self.state.is_stmt = !self.state.is_stmt;
                    }
                    0x07 /* SetBasicBlock */ => {
                        self.state.row_flags.set_basic_block();
                    }
                    0x08 /* ConstAddPC */ => {
                        let line_range = u64::from(self.header.line_range);
                        if line_range == 0 { break; }
                        let adjusted = u64::from(255 - self.header.opcode_base);
                        let op_advance = adjusted / line_range;
                        self.advance_pc(op_advance);
                    }
                    0x09 /* FixedAdvancePC */ => {
                        let delta = u64::from(self.read_u16().unwrap_or(0));
                        self.state.address += delta;
                    }
                    0x0A /* SetPrologueEnd */ => {
                        self.state.row_flags.set_prologue_end();
                    }
                    0x0B /* SetEpilogueBegin */ => {
                        self.state.row_flags.set_epilogue_begin();
                    }
                    0x0C /* SetISA */ => {
                        self.state.isa = u32::try_from(self.read_uleb128().unwrap_or(0)).unwrap_or(u32::MAX);
                    }
                    _ => {
                        // Unknown standard opcode: skip args per standard_opcode_lengths
                        let n_args = self.header.standard_opcode_lengths
                            .get((opcode as usize).saturating_sub(1))
                            .copied()
                            .unwrap_or(0);
                        for _ in 0..n_args { self.read_uleb128(); }
                    }
                }
            } else {
                // Special opcode
                let adjusted = opcode - self.header.opcode_base;
                let line_range = i64::from(self.header.line_range);
                // Protect against division-by-zero if DWARF header is malformed.
                if line_range == 0 { break; }
                let line_base  = i64::from(self.header.line_base);
                let op_advance = i64::from(adjusted) / line_range;
                let line_delta = i64::from(adjusted) % line_range + line_base;
                self.advance_pc(op_advance.cast_unsigned());
                self.state.line = u32::try_from((i64::from(self.state.line) + line_delta).max(1)).unwrap_or(u32::MAX);
                self.emit_row();
            }
        }
        Ok(std::mem::take(&mut self.rows))
    }
}

// ---------------------------------------------------------------------------
// Source-root path remapper
// ---------------------------------------------------------------------------

/// Maps build-time source paths to local checkout paths.
/// E.g., /build/server/src/main.c → /home/user/project/src/main.c
#[derive(Debug, Default, Clone)]
pub struct SourceRootMapper {
    mappings: Vec<(PathBuf, PathBuf)>,
}

impl SourceRootMapper {
    #[must_use]
    pub fn new() -> Self { Self::default() }

    /// Add a prefix substitution: `from` is replaced by `to`.
    pub fn add_mapping(&mut self, from: impl Into<PathBuf>, to: impl Into<PathBuf>) {
        self.mappings.push((from.into(), to.into()));
    }

    /// Apply all prefix substitutions in order. Returns first match.
    #[must_use]
    pub fn remap(&self, path: &Path) -> PathBuf {
        for (from, to) in &self.mappings {
            if let Ok(rel) = path.strip_prefix(from) {
                return to.join(rel);
            }
        }
        path.to_path_buf()
    }

    /// Check if a file exists after remapping.
    #[must_use]
    pub fn exists(&self, path: &Path) -> bool {
        self.remap(path).exists()
    }
}

// ---------------------------------------------------------------------------
// Source file cache
// ---------------------------------------------------------------------------

/// Cached source file content with lazy loading.
struct CachedFile {
    path:  PathBuf,
    lines: Vec<String>,
}

impl CachedFile {
    fn load(path: &Path) -> SourceResult<Self> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| SourceMapError::Io(format!("{}: {e}", path.display())))?;
        let lines = content.lines().map(str::to_owned).collect();
        Ok(Self { path: path.to_path_buf(), lines })
    }

    fn get_line(&self, line: u32) -> Option<&str> {
        // 1-based line numbers
        self.lines.get((line as usize).saturating_sub(1)).map(String::as_str)
    }

    fn len(&self) -> u32 { u32::try_from(self.lines.len()).unwrap_or(u32::MAX) }

    /// Path of the cached file on disk (post-remap).
    pub fn path(&self) -> &Path { &self.path }
}

impl SourceFileCache {
    /// Path of a cached file, if loaded.
    #[must_use]
    pub fn cached_path(&self, file: &Path) -> Option<PathBuf> {
        let remapped = self.mapper.remap(file);
        self.cache.read().get(&remapped).map(|f| f.path().to_path_buf())
    }
}

/// Thread-safe cache of source file contents.
pub struct SourceFileCache {
    cache:  RwLock<HashMap<PathBuf, Arc<CachedFile>>>,
    mapper: SourceRootMapper,
}

impl SourceFileCache {
    #[must_use]
    pub fn new(mapper: SourceRootMapper) -> Self {
        Self {
            cache:  RwLock::new(HashMap::new()),
            mapper,
        }
    }

    fn get_or_load(&self, path: &Path) -> SourceResult<Arc<CachedFile>> {
        let remapped = self.mapper.remap(path);
        // Fast read path — most accesses are cache hits.
        if let Some(f) = self.cache.read().get(&remapped) {
            return Ok(Arc::clone(f));
        }
        let f = Arc::new(CachedFile::load(&remapped)?);
        self.cache.write().insert(remapped, Arc::clone(&f));
        Ok(f)
    }

    /// Retrieve source lines around a given line number.
    /// Returns `(line_number, line_content)` pairs.
    ///
    /// # Errors
    ///
    /// Returns `SourceMapError` if the file cannot be loaded or the line is out of range.
    pub fn source_at_line(
        &self,
        file:          &Path,
        line:          u32,
        context_lines: u32,
    ) -> SourceResult<Vec<(u32, String)>> {
        let f = self.get_or_load(file)?;
        let total = f.len();
        if line == 0 || line > total {
            return Err(SourceMapError::LineOutOfRange { file: file.to_path_buf(), line });
        }
        let start = line.saturating_sub(context_lines).max(1);
        let end   = (line + context_lines).min(total);
        let result = (start..=end)
            .map(|l| (l, f.get_line(l).unwrap_or("").to_string()))
            .collect();
        Ok(result)
    }

    /// Get total number of lines in a file.
    ///
    /// # Errors
    ///
    /// Returns `SourceMapError` if the file cannot be loaded.
    pub fn line_count(&self, file: &Path) -> SourceResult<u32> {
        Ok(self.get_or_load(file)?.len())
    }

    /// Invalidate a cached file (e.g., after it's been edited).
    pub fn invalidate(&self, file: &Path) {
        let remapped = self.mapper.remap(file);
        self.cache.write().remove(&remapped);
    }

    /// Clear entire cache.
    pub fn clear(&self) {
        self.cache.write().clear();
    }
}

// ---------------------------------------------------------------------------
// Main SourceMap
// ---------------------------------------------------------------------------

/// An entry in the address-to-location index.
#[derive(Debug, Clone)]
pub struct AddrEntry {
    address:   u64,
    /// First address NO LONGER covered by this row: the next row of the same
    /// sequence, or the `end_sequence` marker that closes it.
    ///
    /// `None` when the sequence had no `end_sequence` row at all — truncated or
    /// hand-built input. The extent is then genuinely unknown, and the lookup
    /// says so instead of inventing one.
    end:       Option<u64>,
    location:  SourceLocation,
    is_stmt:   bool,
}

impl AddrEntry {
    /// Machine address for this entry.
    #[must_use]
    pub const fn address(&self) -> u64 { self.address }
    /// Source location for this entry.
    #[must_use]
    pub const fn location(&self) -> &SourceLocation { &self.location }
    /// Whether this address is a statement boundary.
    #[must_use]
    pub const fn is_stmt(&self) -> bool { self.is_stmt }
    /// First address after the range this row covers, when it is known.
    #[must_use]
    pub const fn end(&self) -> Option<u64> { self.end }
}

/// Bidirectional mapping between machine addresses and source locations.
pub struct SourceMap {
    /// Sorted list of address entries (ascending by address).
    entries:     Vec<AddrEntry>,
    /// Reverse index: (`canonical_file`, line) → `Vec<address>`
    line_to_addr: HashMap<(PathBuf, u32), Vec<u64>>,
    /// Source file cache for line content lookup.
    pub file_cache: SourceFileCache,
    /// Compilation unit name (for display).
    pub comp_dir: PathBuf,
}

impl SourceMap {
    /// Build a `SourceMap` from pre-parsed `LineTableRow` data.
    #[must_use]
    pub fn from_line_table(
        rows:      &[LineTableRow],
        header:    &LineTableHeader,
        comp_dir:  &Path,
        mapper:    SourceRootMapper,
        functions: &HashMap<u64, String>,  // addr → function name
    ) -> Self {
        let file_cache = SourceFileCache::new(mapper);
        let mut entries     = Vec::with_capacity(rows.len());
        let mut line_to_addr: HashMap<(PathBuf, u32), Vec<u64>> = HashMap::with_capacity(rows.len());

        // Pre-sort functions by address once so per-row lookup is O(log N) instead of O(M).
        let mut sorted_funcs: Vec<(u64, &String)> = functions.iter().map(|(&a, n)| (a, n)).collect();
        sorted_funcs.sort_by_key(|(a, _)| *a);

        // Index in `entries` where the sequence currently being read started.
        // DWARF line programs are a series of SEQUENCES, each closed by an
        // `end_sequence` row that carries the address one past the last
        // instruction. Those rows used to be dropped here, which threw away the
        // only record of where a sequence stops — see `addr_to_source`.
        let mut seq_start = 0usize;
        for row in rows {
            if row.row_flags.end_sequence() {
                // Close the sequence: each row runs up to its successor, and
                // the last one up to this marker.
                for i in seq_start..entries.len() {
                    let next = entries.get(i + 1).map_or(row.address, |e: &AddrEntry| e.address);
                    entries[i].end = Some(next);
                }
                seq_start = entries.len();
                continue;
            }
            let file_entry = header.file_names.get((row.file_index as usize).saturating_sub(1));
            let path = file_entry.map_or_else(
                || comp_dir.join(format!("<unknown_{}>", row.file_index)),
                |fe| fe.resolve_path(header, comp_dir),
            );
            let func = {
                let idx = sorted_funcs.partition_point(|(a, _)| *a <= row.address);
                if idx == 0 { None } else { Some(sorted_funcs[idx - 1].1.clone()) }
            };
            let loc = SourceLocation {
                file:     path.clone(),
                line:     row.line,
                column:   row.column,
                function: func,
            };
            line_to_addr.entry((path, row.line)).or_default().push(row.address);
            entries.push(AddrEntry { address: row.address, end: None, location: loc, is_stmt: row.is_stmt });
        }

        // A trailing sequence with no `end_sequence` row: every row still knows
        // its successor, but the LAST one does not, and its extent stays `None`
        // rather than being guessed.
        for i in seq_start..entries.len() {
            if let Some(next) = entries.get(i + 1).map(|e: &AddrEntry| e.address) {
                entries[i].end = Some(next);
            }
        }

        // Sort by address for binary search
        entries.sort_by_key(|e| e.address);

        Self {
            entries,
            line_to_addr,
            file_cache,
            comp_dir: comp_dir.to_path_buf(),
        }
    }

    /// Build an empty `SourceMap` (useful for testing or when no debug info is available).
    pub fn empty(comp_dir: impl Into<PathBuf>, mapper: SourceRootMapper) -> Self {
        Self {
            entries:      Vec::new(),
            line_to_addr: HashMap::new(),
            file_cache:   SourceFileCache::new(mapper),
            comp_dir:     comp_dir.into(),
        }
    }

    /// Find the source location for a given machine address.
    /// Uses binary search to find the closest preceding entry.
    pub fn addr_to_source(&self, addr: u64) -> Option<SourceLocation> {
        if self.entries.is_empty() { return None; }
        // Find the last entry with address <= addr
        let idx = self.entries.partition_point(|e| e.address <= addr);
        if idx == 0 { return None; }
        let entry = &self.entries[idx - 1];
        // The row covers `[address, end)` — the line table's own boundary.
        //
        // This used to accept anything within 4 KiB of the row (`> 0x1000`),
        // a constant with no basis in the data, and it was wrong in both
        // directions. Past the end of a sequence it attributed a program
        // counter in a DIFFERENT function — or in padding, or in another
        // compilation unit — to the last line of this one, and printed it with
        // full confidence: a `file:line` that is simply not where the target
        // is. In the other direction it refused a legitimate address more than
        // 4 KiB into a row's own range.
        match entry.end {
            Some(end) => (addr < end).then(|| entry.location.clone()),
            // Extent unknown (no `end_sequence` closed this sequence): the row
            // answers for its own address and nothing else.
            None => (addr == entry.address).then(|| entry.location.clone()),
        }
    }

    /// Find all machine addresses for a given source file and line.
    #[must_use]
    pub fn source_to_addr(&self, file: &str, line: u32) -> Option<Vec<u64>> {
        // Normalize file path
        let path = PathBuf::from(file);
        // Try exact match first
        if let Some(addrs) = self.line_to_addr.get(&(path.clone(), line)) {
            return Some(addrs.clone());
        }
        // Try matching on file name only (ignoring directory)
        let file_name = path.file_name()?;
        let matches: Vec<u64> = self.line_to_addr.iter()
            .filter(|((p, l), _)| *l == line && p.file_name() == Some(file_name))
            .flat_map(|(_, addrs)| addrs.iter().copied())
            .collect();
        if matches.is_empty() { None } else { Some(matches) }
    }

    /// Resolve a source location to the best (lowest) machine address.
    ///
    /// # Errors
    ///
    /// Returns `SourceMapError::NoAddressForLine` if no address is found for the given line.
    pub fn best_addr_for_line(&self, file: &str, line: u32) -> SourceResult<u64> {
        let addrs = self.source_to_addr(file, line)
            .ok_or_else(|| SourceMapError::NoAddressForLine { file: file.into(), line })?;
        // Prefer stmt-marked rows
        let stmt_addr = addrs.iter().copied().find(|&a| {
            self.entries.binary_search_by_key(&a, |e| e.address)
                .ok()
                .is_some_and(|i| self.entries[i].is_stmt)
        });
        Ok(stmt_addr.unwrap_or(addrs[0]))
    }

    /// Get all addresses marked as recommended breakpoint positions (`is_stmt`) for a file.
    pub fn stmt_addresses(&self, file: &str) -> Vec<(u32, u64)> {
        let path = PathBuf::from(file);
        self.entries.iter()
            .filter(|e| e.is_stmt && (e.location.file == path ||
                    e.location.file.file_name() == path.file_name()))
            .map(|e| (e.location.line, e.address))
            .collect()
    }

    /// Get the total number of address entries.
    #[must_use]
    pub const fn entry_count(&self) -> usize { self.entries.len() }

    /// Iterate over all entries (for debugging / export).
    pub fn iter_entries(&self) -> impl Iterator<Item = &AddrEntry> {
        self.entries.iter()
    }

    /// Find the function name containing an address.
    ///
    /// Bounded exactly like [`Self::addr_to_source`], and for the same reason.
    /// This used to walk backwards from the insertion point until it found ANY
    /// entry carrying a function name, with no limit at all: an address past
    /// the end of a sequence — in padding, in another compilation unit, in a
    /// function with no line table — was named after whatever function turned
    /// up first going backwards, however far away, and reported with full
    /// confidence. `symbol_resolver` uses this to name backtrace frames, so the
    /// wrong answer lands in a stack trace: exactly where a name is trusted
    /// without question.
    ///
    /// Two bounds, both taken from the line table's own structure rather than
    /// from a distance constant:
    ///
    /// 1. the row that covers `addr` must actually cover it;
    /// 2. the backwards walk for a name stops at the first gap, because rows
    ///    across a gap belong to another sequence and its names say nothing
    ///    about this address.
    pub fn function_at(&self, addr: u64) -> Option<&str> {
        if self.entries.is_empty() { return None; }
        let idx = self.entries.partition_point(|e| e.address <= addr);
        if idx == 0 { return None; }
        let covering = &self.entries[idx - 1];
        match covering.end {
            Some(end) => {
                if addr >= end {
                    return None;
                }
            }
            // Extent unknown: the row answers for its own address and nothing
            // else — the rule `addr_to_source` already applies.
            None => {
                if addr != covering.address {
                    return None;
                }
            }
        }
        let mut i = idx - 1;
        loop {
            if let Some(f) = &self.entries[i].location.function {
                return Some(f.as_str());
            }
            if i == 0 {
                return None;
            }
            // A row whose predecessor ends before it begins starts a new
            // sequence; nothing on the far side of that gap describes `addr`.
            let prev_end = self.entries[i - 1].end;
            let this_start = self.entries[i].address;
            if prev_end.is_none_or(|e| e < this_start) {
                return None;
            }
            i -= 1;
        }
    }
}

// ---------------------------------------------------------------------------
// Breakpoint resolver
// ---------------------------------------------------------------------------

/// Result of resolving a breakpoint by source location.
#[derive(Debug, Clone)]
pub struct BreakpointResolution {
    pub requested_file: String,
    pub requested_line: u32,
    pub resolved_addr:  u64,
    pub actual_location: SourceLocation,
    pub is_exact_line:  bool,
}

pub struct BreakpointResolver<'a> {
    source_map: &'a SourceMap,
}

impl<'a> BreakpointResolver<'a> {
    #[must_use]
    pub const fn new(source_map: &'a SourceMap) -> Self {
        Self { source_map }
    }

    /// Resolve a source file + line number to a machine address.
    /// If the exact line has no code, finds the next line with code.
    ///
    /// # Errors
    ///
    /// Returns `SourceMapError` if no address can be found for the given file and line.
    pub fn resolve(&self, file: &str, line: u32) -> SourceResult<BreakpointResolution> {
        // Try exact line first
        if let Ok(addr) = self.source_map.best_addr_for_line(file, line) {
            let loc = self.source_map.addr_to_source(addr)
                .unwrap_or_else(|| SourceLocation::new(file, line));
            return Ok(BreakpointResolution {
                requested_file:  file.into(),
                requested_line:  line,
                resolved_addr:   addr,
                actual_location: loc,
                is_exact_line:   true,
            });
        }

        // Try next few lines
        for delta in 1..=20u32 {
            let try_line = line + delta;
            if let Ok(addr) = self.source_map.best_addr_for_line(file, try_line) {
                let loc = self.source_map.addr_to_source(addr)
                    .unwrap_or_else(|| SourceLocation::new(file, try_line));
                return Ok(BreakpointResolution {
                    requested_file:  file.into(),
                    requested_line:  line,
                    resolved_addr:   addr,
                    actual_location: loc,
                    is_exact_line:   false,
                });
            }
        }

        Err(SourceMapError::NoAddressForLine { file: file.into(), line })
    }

    /// Resolve by function name — returns address of first `is_stmt` row in function.
    #[must_use]
    pub fn resolve_by_function(&self, name: &str) -> Option<u64> {
        self.source_map.entries.iter()
            .find(|e| e.location.function.as_deref() == Some(name) && e.is_stmt)
            .map(|e| e.address)
    }
}

// ---------------------------------------------------------------------------
// addr2line-style batch resolver
// ---------------------------------------------------------------------------

/// Batch address-to-location resolver with caching.
pub struct Addr2LineResolver {
    source_map: Arc<SourceMap>,
    cache:      RwLock<HashMap<u64, Option<SourceLocation>>>,
}

impl Addr2LineResolver {
    #[must_use]
    pub fn new(source_map: Arc<SourceMap>) -> Self {
        Self {
            source_map,
            cache: RwLock::new(HashMap::new()),
        }
    }

    #[must_use]
    pub fn resolve(&self, addr: u64) -> Option<SourceLocation> {
        if let Some(cached) = self.cache.read().get(&addr) {
            return cached.clone();
        }
        let result = self.source_map.addr_to_source(addr);
        self.cache.write().insert(addr, result.clone());
        result
    }

    #[must_use]
    pub fn resolve_batch(&self, addrs: &[u64]) -> Vec<(u64, Option<SourceLocation>)> {
        addrs.iter().map(|&a| (a, self.resolve(a))).collect()
    }

    pub fn invalidate(&self) {
        self.cache.write().clear();
    }
}

// ---------------------------------------------------------------------------
// Multi-CU SourceMap (one per compilation unit, merged lookup)
// ---------------------------------------------------------------------------

/// Manages source maps from multiple compilation units in the same binary.
pub struct SourceMapIndex {
    maps:  Vec<Arc<SourceMap>>,
    /// Cached resolver for fast repeated lookups
    resolver: Option<Arc<Addr2LineResolver>>,
}

impl SourceMapIndex {
    #[must_use]
    pub const fn new() -> Self {
        Self { maps: Vec::new(), resolver: None }
    }

    pub fn add(&mut self, map: SourceMap) {
        self.maps.push(Arc::new(map));
        self.resolver = None; // invalidate
    }

    #[must_use]
    pub fn addr_to_source(&self, addr: u64) -> Option<SourceLocation> {
        for map in &self.maps {
            if let Some(loc) = map.addr_to_source(addr) {
                return Some(loc);
            }
        }
        None
    }

    #[must_use]
    pub fn source_to_addr(&self, file: &str, line: u32) -> Option<Vec<u64>> {
        let mut all = Vec::new();
        for map in &self.maps {
            if let Some(addrs) = map.source_to_addr(file, line) {
                all.extend(addrs);
            }
        }
        if all.is_empty() { None } else { Some(all) }
    }

    /// # Errors
    ///
    /// Returns `SourceMapError` if no address can be found for the given file and line.
    pub fn resolve_breakpoint(&self, file: &str, line: u32) -> SourceResult<BreakpointResolution> {
        for map in &self.maps {
            let resolver = BreakpointResolver::new(map);
            if let Ok(bp) = resolver.resolve(file, line) {
                return Ok(bp);
            }
        }
        Err(SourceMapError::NoAddressForLine { file: file.into(), line })
    }

    #[must_use]
    pub fn total_entries(&self) -> usize {
        self.maps.iter().map(|m| m.entry_count()).sum()
    }
}

impl Default for SourceMapIndex {
    fn default() -> Self { Self::new() }
}

// ---------------------------------------------------------------------------
// Source listing helper
// ---------------------------------------------------------------------------

/// Annotated line for display in a debugger UI.
#[derive(Debug, Clone)]
pub struct AnnotatedLine {
    pub line_number:   u32,
    pub content:       String,
    pub is_current:    bool,
    pub has_breakpoint: bool,
    pub addresses:     Vec<u64>,
}

pub struct SourceListing<'a> {
    source_map: &'a SourceMap,
    file_cache: &'a SourceFileCache,
}

impl<'a> SourceListing<'a> {
    #[must_use]
    pub const fn new(source_map: &'a SourceMap, file_cache: &'a SourceFileCache) -> Self {
        Self { source_map, file_cache }
    }

    /// Produce an annotated source listing around a given address.
    ///
    /// # Errors
    ///
    /// Returns `SourceMapError` if the address has no source mapping or the file cannot be loaded.
    pub fn listing_around_addr(
        &self,
        addr:              u64,
        context_lines:     u32,
        breakpoint_addrs:  &[u64],
    ) -> SourceResult<Vec<AnnotatedLine>> {
        let loc = self.source_map.addr_to_source(addr)
            .ok_or(SourceMapError::NoLinetableForAddress(addr))?;
        self.listing_around_line(&loc.file, loc.line, context_lines, addr, breakpoint_addrs)
    }

    /// # Errors
    ///
    /// Returns `SourceMapError` if the file cannot be loaded or the line is out of range.
    pub fn listing_around_line(
        &self,
        file:              &Path,
        line:              u32,
        context_lines:     u32,
        current_addr:      u64,
        breakpoint_addrs:  &[u64],
    ) -> SourceResult<Vec<AnnotatedLine>> {
        let raw_lines = self.file_cache.source_at_line(file, line, context_lines)?;
        let bp_set: std::collections::HashSet<u64> = breakpoint_addrs.iter().copied().collect();

        let result = raw_lines.into_iter().map(|(ln, content)| {
            let addrs: Vec<u64> = self.source_map
                .source_to_addr(&file.to_string_lossy(), ln)
                .unwrap_or_default();
            let has_bp = addrs.iter().any(|a| bp_set.contains(a));
            let is_current = self.source_map.addr_to_source(current_addr)
                .is_some_and(|l| l.file == file && l.line == ln);
            AnnotatedLine { line_number: ln, content, is_current, has_breakpoint: has_bp, addresses: addrs }
        }).collect();
        Ok(result)
    }
}

// ---------------------------------------------------------------------------
// Statistics
// ---------------------------------------------------------------------------

#[derive(Debug, Default)]
pub struct SourceMapStats {
    pub total_compilation_units: usize,
    pub total_line_entries:      usize,
    pub total_source_files:      usize,
    pub addr_range_min:          u64,
    pub addr_range_max:          u64,
}

impl SourceMapIndex {
    #[must_use]
    pub fn stats(&self) -> SourceMapStats {
        let mut stats = SourceMapStats {
            total_compilation_units: self.maps.len(),
            ..SourceMapStats::default()
        };
        let mut files = std::collections::HashSet::new();
        let mut min_addr = u64::MAX;
        let mut max_addr = 0u64;
        for map in &self.maps {
            stats.total_line_entries += map.entry_count();
            for entry in map.iter_entries() {
                files.insert(&entry.location.file);
                if entry.address < min_addr { min_addr = entry.address; }
                if entry.address > max_addr { max_addr = entry.address; }
            }
        }
        stats.total_source_files = files.len();
        if min_addr != u64::MAX {
            stats.addr_range_min = min_addr;
            stats.addr_range_max = max_addr;
        }
        stats
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_simple_map() -> SourceMap {
        let mapper = SourceRootMapper::new();
        let mut functions = HashMap::new();
        functions.insert(0x1000, "main".into());
        functions.insert(0x2000, "foo".into());

        let rows = vec![
            LineTableRow { address: 0x1000, op_index: 0, file_index: 1, line: 10, column: 0,
                is_stmt: true,  row_flags: LineRowFlags(0), isa: 0, discriminator: 0 },
            LineTableRow { address: 0x1010, op_index: 0, file_index: 1, line: 11, column: 0,
                is_stmt: true,  row_flags: LineRowFlags(0), isa: 0, discriminator: 0 },
            LineTableRow { address: 0x1020, op_index: 0, file_index: 1, line: 12, column: 4,
                is_stmt: false, row_flags: LineRowFlags(0), isa: 0, discriminator: 0 },
            LineTableRow { address: 0x1030, op_index: 0, file_index: 1, line: 13, column: 0,
                is_stmt: true,  row_flags: LineRowFlags(0x02), isa: 0, discriminator: 0 },
        ];

        let header = LineTableHeader {
            minimum_instruction_length:  1,
            maximum_ops_per_instruction: 1,
            default_is_stmt:             true,
            line_base:                  -5,
            line_range:                  14,
            opcode_base:                 13,
            standard_opcode_lengths:     vec![0,1,1,1,1,0,0,0,1,0,0,1],
            include_directories:         vec![],
            file_names:                  vec![FileEntry {
                name:          PathBuf::from("main.c"),
                dir_index:     0,
                modification:  0,
                length:        0,
            }],
            address_size:  8,
            is_64bit:      false,
            version:       4,
        };

        SourceMap::from_line_table(
            &rows,
            &header,
            Path::new("/src"),
            mapper,
            &functions,
        )
    }

    /// Build two sequences, each properly closed by an end_sequence row - the
    /// shape a real DWARF line program has, and the one the fixture above
    /// deliberately lacks.
    fn map_with_two_closed_sequences() -> SourceMap {
        let mut functions = HashMap::new();
        functions.insert(0x1000u64, "first".to_string());
        functions.insert(0x9000u64, "second".to_string());
        let row = |address: u64, line: u32, end_seq: bool| LineTableRow {
            address,
            op_index: 0,
            file_index: 1,
            line,
            column: 0,
            is_stmt: true,
            // end_sequence is bit 0x02 in this crate (bit 0x01 is basic_block).
            row_flags: LineRowFlags(if end_seq { 0x02 } else { 0 }),
            isa: 0,
            discriminator: 0,
        };
        let rows = vec![
            row(0x1000, 10, false),
            row(0x1010, 11, false),
            row(0x1020, 0, true),
            row(0x9000, 90, false),
            row(0x9008, 0, true),
        ];
        let header = LineTableHeader {
            minimum_instruction_length: 1,
            maximum_ops_per_instruction: 1,
            default_is_stmt: true,
            line_base: -5,
            line_range: 14,
            opcode_base: 13,
            standard_opcode_lengths: vec![0, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1],
            include_directories: vec![],
            file_names: vec![FileEntry {
                name: PathBuf::from("main.c"),
                dir_index: 0,
                modification: 0,
                length: 0,
            }],
            address_size: 8,
            is_64bit: false,
            version: 4,
        };
        SourceMap::from_line_table(&rows, &header, Path::new("/src"), SourceRootMapper::new(), &functions)
    }

    /// An address past the end of a sequence has NO source location, and must
    /// not borrow the last line of the sequence before it.
    ///
    /// The lookup used to accept anything within 4 KiB of the nearest
    /// preceding row - a constant with no basis in the line table. The gap
    /// between two blocks of code is routinely smaller than that, so a program
    /// counter sitting in padding, in another function, or in another
    /// compilation unit came back with a confident file:line belonging to the
    /// previous block. A wrong location is worse than none: it sends the
    /// reader to a line the target is not executing, and nothing marks it as a
    /// guess.
    #[test]
    fn an_address_past_the_end_of_a_sequence_has_no_location() {
        let map = map_with_two_closed_sequences();
        assert_eq!(map.addr_to_source(0x1000).unwrap().line, 10);
        assert_eq!(map.addr_to_source(0x1018).unwrap().line, 11);
        assert!(
            map.addr_to_source(0x1020).is_none(),
            "the end_sequence address is one past the last instruction and is NOT covered"
        );
        assert!(
            map.addr_to_source(0x1400).is_none(),
            "an address in the gap between two sequences belongs to neither and must not inherit the line before it"
        );
        assert_eq!(map.addr_to_source(0x9004).unwrap().line, 90);
        assert!(map.addr_to_source(0x9008).is_none());
        assert!(map.addr_to_source(0x0FFF).is_none());
    }

    /// A sequence with no end_sequence row has an unknown extent at its last
    /// row, and the lookup says so rather than inventing a range.
    #[test]
    fn a_row_with_no_terminator_answers_only_for_its_own_address() {
        let functions = HashMap::new();
        let row = |address: u64, line: u32| LineTableRow {
            address,
            op_index: 0,
            file_index: 1,
            line,
            column: 0,
            is_stmt: true,
            row_flags: LineRowFlags(0),
            isa: 0,
            discriminator: 0,
        };
        let rows = vec![row(0x1000, 10), row(0x1010, 11)];
        let header = LineTableHeader {
            minimum_instruction_length: 1,
            maximum_ops_per_instruction: 1,
            default_is_stmt: true,
            line_base: -5,
            line_range: 14,
            opcode_base: 13,
            standard_opcode_lengths: vec![0, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1],
            include_directories: vec![],
            file_names: vec![FileEntry {
                name: PathBuf::from("main.c"),
                dir_index: 0,
                modification: 0,
                length: 0,
            }],
            address_size: 8,
            is_64bit: false,
            version: 4,
        };
        let map = SourceMap::from_line_table(&rows, &header, Path::new("/src"), SourceRootMapper::new(), &functions);
        // The row that HAS a successor still covers the gap to it.
        assert_eq!(map.addr_to_source(0x1008).unwrap().line, 10);
        // The last row answers for its own address and nothing beyond it.
        assert_eq!(map.addr_to_source(0x1010).unwrap().line, 11);
        assert!(
            map.addr_to_source(0x1011).is_none(),
            "nothing in the table says how far the last row reaches"
        );
    }

    #[test]
    fn test_addr_to_source() {
        let map = make_simple_map();
        let loc = map.addr_to_source(0x1010).unwrap();
        assert_eq!(loc.line, 11);
    }

    #[test]
    fn test_addr_between_entries() {
        let map = make_simple_map();
        // Address between 0x1010 and 0x1020 should map to line 11
        let loc = map.addr_to_source(0x1015).unwrap();
        assert_eq!(loc.line, 11);
    }

    #[test]
    fn test_source_to_addr() {
        let map = make_simple_map();
        let addrs = map.source_to_addr("main.c", 10);
        assert!(addrs.is_some());
        assert!(addrs.unwrap().contains(&0x1000));
    }

        /// A name must come from a row that actually covers the address.
    ///
    /// `function_at` walked backwards until it found ANY entry with a function
    /// name, without limit. An address past the end of the table — padding,
    /// another compilation unit, a function with no line rows — was therefore
    /// named after the nearest preceding name however far away, and
    /// `symbol_resolver` prints that in a backtrace frame.
    ///
    /// `addr_to_source`, ten lines above, had already been fixed for exactly
    /// this; the twin below it had not.
    #[test]
    fn function_at_refuses_an_address_no_row_covers() {
        let map = make_simple_map();

        // Inside the table: still answered, and with the right name.
        assert_eq!(map.function_at(0x1010), Some("main"));

        // Before the first row: nothing precedes it, and that was already
        // handled.
        assert_eq!(map.function_at(0x0FFF), None);

        // FAR past the last row. The old code walked back to the first named
        // entry and answered "main" for an address nowhere near it.
        assert_eq!(
            map.function_at(0xFFFF_0000),
            None,
            "an address no row covers has no function name, however close the nearest earlier name happens to be"
        );
    }

#[test]
    fn test_function_at() {
        let map = make_simple_map();
        assert_eq!(map.function_at(0x1010), Some("main"));
    }

    #[test]
    fn test_source_map_index() {
        let map = make_simple_map();
        let mut index = SourceMapIndex::new();
        index.add(map);
        // 3, not 4: the 4th row is a DWARF end_sequence terminator (row_flags
        // 0x02), which is not a source line and is excluded from the index.
        assert_eq!(index.total_entries(), 3);
        let loc = index.addr_to_source(0x1000).unwrap();
        assert_eq!(loc.line, 10);
    }

    #[test]
    fn test_addr2line_cache() {
        let map = Arc::new(make_simple_map());
        let resolver = Addr2LineResolver::new(map);
        let loc1 = resolver.resolve(0x1000);
        let loc2 = resolver.resolve(0x1000);
        assert_eq!(loc1.map(|l| l.line), loc2.map(|l| l.line));
    }

    #[test]
    fn test_stats() {
        let map = make_simple_map();
        let mut index = SourceMapIndex::new();
        index.add(map);
        let stats = index.stats();
        assert_eq!(stats.total_compilation_units, 1);
        // 3 real line entries (the end_sequence terminator row is excluded), so
        // the mapped range spans the real entries 0x1000..=0x1020, not the
        // end_sequence address 0x1030.
        assert_eq!(stats.total_line_entries, 3);
        assert_eq!(stats.addr_range_min, 0x1000);
        assert_eq!(stats.addr_range_max, 0x1020);
    }

    #[test]
    fn test_source_root_mapper() {
        let mut mapper = SourceRootMapper::new();
        mapper.add_mapping("/build/src", "/local/src");
        let remapped = mapper.remap(Path::new("/build/src/main.c"));
        assert_eq!(remapped, PathBuf::from("/local/src/main.c"));
        // No-match returns original
        let unchanged = mapper.remap(Path::new("/other/file.c"));
        assert_eq!(unchanged, PathBuf::from("/other/file.c"));
    }

    #[test]
    fn test_no_match_returns_none() {
        let map = make_simple_map();
        // Very far from any address
        assert!(map.addr_to_source(0xFF00_0000).is_none());
    }

    #[test]
    fn test_stmt_addresses() {
        let map = make_simple_map();
        let stmts = map.stmt_addresses("main.c");
        assert!(stmts.iter().any(|(l, _)| *l == 10));
        assert!(stmts.iter().any(|(l, _)| *l == 11));
        // line 12 is not is_stmt
        assert!(!stmts.iter().any(|(l, _)| *l == 12));
    }

    #[test]
    fn test_uleb128_decode() {
        // Test state machine ULEB128
        let data: &[u8] = &[0x80, 0x01]; // = 128
        let header = LineTableHeader {
            minimum_instruction_length: 1, maximum_ops_per_instruction: 1,
            default_is_stmt: true, line_base: -5, line_range: 14,
            opcode_base: 13, standard_opcode_lengths: vec![0,1,1,1,1,0,0,0,1,0,0,1],
            include_directories: vec![], file_names: vec![], address_size: 8,
            is_64bit: false, version: 4,
        };
        let mut sm = LineTableStateMachine::new(
            &header,
            data,
        );
        assert_eq!(sm.read_uleb128(), Some(128));
    }
}
