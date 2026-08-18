//! Map coverage data back to source lines via DWARF debug information.
//!
//! Provides line-level and function-level coverage attribution by parsing
//! DWARF `.debug_line` and `.debug_info` sections. When DWARF is unavailable,
//! falls back to address-only attribution.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::ops::Range;

// ─── Source location ──────────────────────────────────────────────────────────

/// A fully qualified source location.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SourceLocation {
    /// Absolute or relative path to the source file.
    pub file: String,
    /// 1-based line number.
    pub line: u32,
    /// 1-based column number (0 means unknown).
    pub column: u32,
}

impl SourceLocation {
    pub fn new(file: impl Into<String>, line: u32, column: u32) -> Self {
        Self {
            file: file.into(),
            line,
            column,
        }
    }

    pub fn file_line(file: impl Into<String>, line: u32) -> Self {
        Self::new(file, line, 0)
    }
}

impl std::fmt::Display for SourceLocation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.column > 0 {
            write!(f, "{}:{}:{}", self.file, self.line, self.column)
        } else {
            write!(f, "{}:{}", self.file, self.line)
        }
    }
}

// ─── DWARF line table entry ───────────────────────────────────────────────────

/// A single row from a DWARF `.debug_line` line number program.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LineEntry {
    /// Machine code address of this row.
    pub address: u64,
    /// File index into the file table.
    pub file_index: u32,
    /// 1-based line number.
    pub line: u32,
    /// 1-based column (0 = unknown).
    pub column: u32,
    /// True if this row marks the start of a statement.
    pub is_stmt: bool,
    /// True if this row marks the end of a sequence.
    pub end_sequence: bool,
    /// True if this is the prologue end (first real user code).
    pub prologue_end: bool,
}

impl LineEntry {
    #[must_use] 
    pub fn location(&self, file_table: &[String]) -> Option<SourceLocation> {
        let file = file_table.get(self.file_index as usize)?;
        Some(SourceLocation::new(file.clone(), self.line, self.column))
    }
}

// ─── DWARF source line table ──────────────────────────────────────────────────

/// A compilation unit's line number table parsed from DWARF `.debug_line`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LineTable {
    /// Compilation unit path (directory + name).
    pub comp_dir: String,
    /// File table (indexed by `file_index` in `LineEntry`).
    pub files: Vec<String>,
    /// Line table rows sorted by address.
    pub rows: Vec<LineEntry>,
}

impl LineTable {
    pub fn new(comp_dir: impl Into<String>) -> Self {
        Self {
            comp_dir: comp_dir.into(),
            files: vec![String::new()], // index 0 is unused in DWARF
            rows: vec![],
        }
    }

    /// Add a file to the file table and return its 1-based index.
    pub fn add_file(&mut self, path: impl Into<String>) -> u32 {
        self.files.push(path.into());
        crate::usize_to_u32_sat(self.files.len() - 1)
    }

    /// Sort rows by address for binary search.
    pub fn sort(&mut self) {
        self.rows.sort_by_key(|r| r.address);
    }

    /// Look up the source location for a given address.
    ///
    /// Returns the location from the row whose address is the largest that is
    /// still ≤ the given address (floor lookup).
    #[must_use] 
    pub fn lookup(&self, address: u64) -> Option<SourceLocation> {
        if self.rows.is_empty() {
            return None;
        }
        // Binary search for largest addr <= address
        let idx = match self
            .rows
            .binary_search_by_key(&address, |r| r.address)
        {
            Ok(i) => i,
            Err(0) => return None,
            Err(i) => i - 1,
        };
        let row = &self.rows[idx];
        if row.end_sequence {
            // end_sequence rows don't represent real code
            if idx == 0 {
                return None;
            }
            return self.rows.get(idx - 1)?.location(&self.files);
        }
        row.location(&self.files)
    }

    /// Returns all addresses in [start, end) and their source locations.
    #[must_use] 
    pub fn locations_in_range(&self, range: Range<u64>) -> Vec<(u64, SourceLocation)> {
        let mut result = Vec::new();
        for row in &self.rows {
            if row.address >= range.start && row.address < range.end && !row.end_sequence
                && let Some(loc) = row.location(&self.files) {
                    result.push((row.address, loc));
                }
        }
        result
    }
}

// ─── Function debug info ──────────────────────────────────────────────────────

/// Debug metadata for a single function from DWARF `.debug_info`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionDebugInfo {
    /// Demangled name.
    pub name: String,
    /// Mangled linkage name.
    pub linkage_name: Option<String>,
    /// Low PC (start address).
    pub low_pc: u64,
    /// High PC (exclusive end address).
    pub high_pc: u64,
    /// Source file declaration.
    pub decl_file: Option<String>,
    /// Source line declaration.
    pub decl_line: Option<u32>,
    /// Inline call site info (for inlined functions).
    pub is_inline: bool,
}

impl FunctionDebugInfo {
    #[must_use] 
    pub const fn contains(&self, address: u64) -> bool {
        address >= self.low_pc && address < self.high_pc
    }

    #[must_use] 
    pub const fn address_range(&self) -> Range<u64> {
        self.low_pc..self.high_pc
    }

    #[must_use] 
    pub const fn size(&self) -> u64 {
        self.high_pc.saturating_sub(self.low_pc)
    }
}

// ─── Source map database ──────────────────────────────────────────────────────

/// Aggregated DWARF debug information for a binary.
///
/// In a real implementation, this would be populated by parsing ELF/PE DWARF
/// sections via `gimli`. Here we provide the data model and lookup logic.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SourceMap {
    /// Per-CU line tables.
    pub line_tables: Vec<LineTable>,
    /// All functions sorted by `low_pc`.
    pub functions: Vec<FunctionDebugInfo>,
    /// Module base address (for ASLR adjustment).
    pub base_address: u64,
    /// Whether the binary had DWARF info.
    pub has_debug_info: bool,
}

impl SourceMap {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a line table (from one compilation unit).
    pub fn add_line_table(&mut self, mut table: LineTable) {
        table.sort();
        self.line_tables.push(table);
        self.has_debug_info = true;
    }

    /// Add a function entry.
    pub fn add_function(&mut self, func: FunctionDebugInfo) {
        self.functions.push(func);
        // Keep sorted by low_pc
        self.functions.sort_by_key(|f| f.low_pc);
        self.has_debug_info = true;
    }

    /// Adjust an address by subtracting the module base (for ASLR-slid addresses).
    #[must_use] 
    pub const fn adjust_address(&self, address: u64) -> u64 {
        address.saturating_sub(self.base_address)
    }

    /// Look up the source location for a given (possibly slid) address.
    #[must_use] 
    pub fn lookup_location(&self, address: u64) -> Option<SourceLocation> {
        let addr = self.adjust_address(address);
        for table in &self.line_tables {
            if let Some(loc) = table.lookup(addr) {
                return Some(loc);
            }
        }
        None
    }

    /// Look up the function that contains a given address.
    #[must_use] 
    pub fn lookup_function(&self, address: u64) -> Option<&FunctionDebugInfo> {
        let addr = self.adjust_address(address);
        // Binary search for candidate
        let pos = self
            .functions
            .partition_point(|f| f.low_pc <= addr);
        // pos is the first function whose low_pc > addr
        // Walk backwards to find containing function
        for i in (0..pos).rev() {
            if self.functions[i].contains(addr) {
                return Some(&self.functions[i]);
            }
        }
        None
    }

    /// Returns all functions that overlap the given address range.
    #[must_use] 
    pub fn functions_in_range(&self, range: Range<u64>) -> Vec<&FunctionDebugInfo> {
        self.functions
            .iter()
            .filter(|f| f.low_pc < range.end && f.high_pc > range.start)
            .collect()
    }
}

// ─── Coverage-to-source attribution ──────────────────────────────────────────

/// Per-source-file line coverage data.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FileCoverage {
    /// Source file path.
    pub file: String,
    /// Map from 1-based line number to (`hit_count`, `total_executions`).
    pub lines: BTreeMap<u32, LineHitData>,
}

/// Hit data for a single source line.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LineHitData {
    /// Total execution count for all addresses on this line.
    pub hit_count: u64,
    /// Number of distinct addresses on this line.
    pub address_count: u32,
    /// Whether any address on this line was executed.
    pub is_covered: bool,
}

impl FileCoverage {
    pub fn new(file: impl Into<String>) -> Self {
        Self {
            file: file.into(),
            lines: BTreeMap::new(),
        }
    }

    pub fn record_hit(&mut self, line: u32, count: u64) {
        let entry = self.lines.entry(line).or_default();
        entry.hit_count += count;
        entry.address_count += 1;
        if count > 0 {
            entry.is_covered = true;
        }
    }

    #[must_use] 
    pub fn covered_lines(&self) -> usize {
        self.lines.values().filter(|l| l.is_covered).count()
    }

    #[must_use] 
    pub fn total_lines(&self) -> usize {
        self.lines.len()
    }

    #[must_use] 
    pub fn line_coverage_pct(&self) -> f64 {
        let total = self.total_lines();
        if total == 0 {
            return 0.0;
        }
        crate::usize_to_f64(self.covered_lines()) / crate::usize_to_f64(total) * 100.0
    }

    #[must_use] 
    pub fn uncovered_lines(&self) -> Vec<u32> {
        self.lines
            .iter()
            .filter(|(_, l)| !l.is_covered)
            .map(|(&line, _)| line)
            .collect()
    }
}

/// Per-function source-level coverage.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionSourceCoverage {
    pub name: String,
    pub file: Option<String>,
    pub decl_line: Option<u32>,
    pub covered_lines: u32,
    pub total_lines: u32,
    pub call_count: u64,
    pub line_coverage_pct: f64,
}

// ─── Source coverage report ───────────────────────────────────────────────────

/// Full source-level coverage report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceCoverageReport {
    /// Module name.
    pub module: String,
    /// Per-file coverage.
    pub files: Vec<FileCoverage>,
    /// Per-function source coverage.
    pub functions: Vec<FunctionSourceCoverage>,
    /// Total covered source lines across all files.
    pub total_covered_lines: u32,
    /// Total instrumented source lines across all files.
    pub total_lines: u32,
    /// Whether DWARF debug info was available.
    pub has_debug_info: bool,
}

impl SourceCoverageReport {
    #[must_use] 
    pub fn line_coverage_pct(&self) -> f64 {
        if self.total_lines == 0 {
            return 0.0;
        }
        f64::from(self.total_covered_lines) / f64::from(self.total_lines) * 100.0
    }

    #[must_use] 
    pub fn find_file(&self, path: &str) -> Option<&FileCoverage> {
        self.files.iter().find(|f| f.file == path)
    }

    /// # Errors
    /// Returns a `serde_json::Error` if serialization fails.
    pub fn to_json(&self) -> serde_json::Result<String> {
        serde_json::to_string_pretty(self)
    }
}

// ─── Attribution engine ───────────────────────────────────────────────────────

/// Maps a set of (address, `hit_count`) pairs to source-level coverage via a
/// `SourceMap`.
pub struct SourceAttributor {
    source_map: SourceMap,
}

impl SourceAttributor {
    #[must_use] 
    pub const fn new(source_map: SourceMap) -> Self {
        Self { source_map }
    }

    /// Attribute a slice of (address, `hit_count`) pairs to source locations.
    ///
    /// Returns a `SourceCoverageReport` with per-file and per-function data.
    #[must_use] 
    pub fn attribute(
        &self,
        module: &str,
        hits: &[(u64, u32)],
    ) -> SourceCoverageReport {
        let mut file_cov: HashMap<String, FileCoverage> = HashMap::new();

        for &(addr, count) in hits {
            if let Some(loc) = self.source_map.lookup_location(addr) {
                let fc = file_cov
                    .entry(loc.file.clone())
                    .or_insert_with(|| FileCoverage::new(loc.file.clone()));
                fc.record_hit(loc.line, u64::from(count));
            }
        }

        // Per-function attribution
        let mut func_cov: Vec<FunctionSourceCoverage> = Vec::new();
        for func in &self.source_map.functions {
            // Collect all hits in this function's address range
            let mut covered_lines: HashSet<u32> = HashSet::new();
            let mut total_calls: u64 = 0;

            for &(addr, count) in hits {
                let adjusted = self.source_map.adjust_address(addr);
                if func.contains(adjusted)
                    && let Some(loc) = self.source_map.lookup_location(addr) {
                        if count > 0 {
                            covered_lines.insert(loc.line);
                        }
                        total_calls += u64::from(count);
                    }
            }

            // Collect total instrumented lines in range
            let total_lines: u32 = {
                let mut seen_lines: HashSet<u32> = HashSet::new();
                for table in &self.source_map.line_tables {
                    for (_, loc) in table.locations_in_range(func.address_range()) {
                        seen_lines.insert(loc.line);
                    }
                }
                crate::usize_to_u32_sat(seen_lines.len())
            };

            let covered = crate::usize_to_u32_sat(covered_lines.len());
            let pct = if total_lines > 0 {
                f64::from(covered) / f64::from(total_lines) * 100.0
            } else {
                0.0
            };

            func_cov.push(FunctionSourceCoverage {
                name: func.name.clone(),
                file: func.decl_file.clone(),
                decl_line: func.decl_line,
                covered_lines: covered,
                total_lines,
                call_count: total_calls,
                line_coverage_pct: pct,
            });
        }

        // Aggregate totals
        let mut total_covered = 0u32;
        let mut total_lines_all = 0u32;
        for fc in file_cov.values() {
            total_covered += crate::usize_to_u32_sat(fc.covered_lines());
            total_lines_all += crate::usize_to_u32_sat(fc.total_lines());
        }

        let mut files: Vec<FileCoverage> = file_cov.into_values().collect();
        files.sort_by(|a, b| a.file.cmp(&b.file));

        SourceCoverageReport {
            module: module.to_owned(),
            files,
            functions: func_cov,
            total_covered_lines: total_covered,
            total_lines: total_lines_all,
            has_debug_info: self.source_map.has_debug_info,
        }
    }
}

// ─── DWARF stub parser ────────────────────────────────────────────────────────

/// DWARF parser that builds a `SourceMap` out of raw section bytes.
///
/// The line-number program and the debug-information entries are decoded here
/// directly; see `parse_line_program` and `parse_debug_info` below.
pub struct DwarfParser;

impl DwarfParser {
    /// Parse DWARF info from raw section data.
    /// Returns `None` if no DWARF is present or parsing fails.
    ///
    /// Callers that need to know *why* a parse failed should use
    /// [`DwarfParser::parse_sections`], which returns a [`DwarfError`].
    #[must_use]
    pub fn parse(
        debug_line: &[u8],
        debug_info: &[u8],
        debug_abbrev: &[u8],
        debug_str: &[u8],
    ) -> Option<SourceMap> {
        Self::parse_sections(debug_line, debug_info, debug_abbrev, debug_str).ok()
    }

    /// Build a [`SourceMap`] from the four DWARF sections.
    ///
    /// Kept under its historical name — it used to return a hand-written
    /// sample map and now parses the bytes it is given.
    ///
    /// # Errors
    /// See [`DwarfParser::parse_sections`].
    pub fn mock_source_map(
        debug_line: &[u8],
        debug_info: &[u8],
        debug_abbrev: &[u8],
        debug_str: &[u8],
    ) -> Result<SourceMap, DwarfError> {
        Self::parse_sections(debug_line, debug_info, debug_abbrev, debug_str)
    }
}

// ─── Real DWARF parsing ───────────────────────────────────────────────────────

/// Everything that can stop a DWARF parse. No variant carries a guessed
/// value: when the input does not contain what is needed, the error names it.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum DwarfError {
    /// A required section was empty or absent.
    #[error("cannot build {what}: no {missing}")]
    Missing {
        /// The value that was requested.
        what: &'static str,
        /// The DWARF input required to compute it.
        missing: &'static str,
    },
    /// The bytes are present but do not form the structure they claim.
    #[error("malformed DWARF: {0}")]
    Malformed(String),
    /// A DWARF version this parser does not decode.
    #[error("unsupported DWARF version {0} in {1}")]
    UnsupportedVersion(u16, &'static str),
}

/// A cursor over a DWARF section with the primitive readers the format needs.
struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    const fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    const fn at(data: &'a [u8], pos: usize) -> Self {
        Self { data, pos }
    }

    const fn eof(&self) -> bool {
        self.pos >= self.data.len()
    }

    fn need(&self, n: usize) -> Result<(), DwarfError> {
        if self.pos + n > self.data.len() {
            Err(DwarfError::Malformed(format!(
                "want {n} bytes at {:#x}, only {} left",
                self.pos,
                self.data.len().saturating_sub(self.pos)
            )))
        } else {
            Ok(())
        }
    }

    fn u8(&mut self) -> Result<u8, DwarfError> {
        self.need(1)?;
        let v = self.data[self.pos];
        self.pos += 1;
        Ok(v)
    }

    fn i8(&mut self) -> Result<i8, DwarfError> {
        Ok(self.u8()? as i8)
    }

    fn u16(&mut self) -> Result<u16, DwarfError> {
        self.need(2)?;
        let v = u16::from_le_bytes([self.data[self.pos], self.data[self.pos + 1]]);
        self.pos += 2;
        Ok(v)
    }

    fn u32(&mut self) -> Result<u32, DwarfError> {
        self.need(4)?;
        let mut b = [0u8; 4];
        b.copy_from_slice(&self.data[self.pos..self.pos + 4]);
        self.pos += 4;
        Ok(u32::from_le_bytes(b))
    }

    fn u64(&mut self) -> Result<u64, DwarfError> {
        self.need(8)?;
        let mut b = [0u8; 8];
        b.copy_from_slice(&self.data[self.pos..self.pos + 8]);
        self.pos += 8;
        Ok(u64::from_le_bytes(b))
    }

    fn uleb(&mut self) -> Result<u64, DwarfError> {
        let mut result = 0u64;
        let mut shift = 0u32;
        loop {
            let byte = self.u8()?;
            if shift < 64 {
                result |= u64::from(byte & 0x7f) << shift;
            }
            shift += 7;
            if byte & 0x80 == 0 {
                return Ok(result);
            }
            if shift > 128 {
                return Err(DwarfError::Malformed("runaway ULEB128".to_owned()));
            }
        }
    }

    fn sleb(&mut self) -> Result<i64, DwarfError> {
        let mut result = 0i64;
        let mut shift = 0u32;
        loop {
            let byte = self.u8()?;
            if shift < 64 {
                result |= i64::from(byte & 0x7f) << shift;
            }
            shift += 7;
            if byte & 0x80 == 0 {
                if shift < 64 && byte & 0x40 != 0 {
                    result |= -1i64 << shift;
                }
                return Ok(result);
            }
            if shift > 128 {
                return Err(DwarfError::Malformed("runaway SLEB128".to_owned()));
            }
        }
    }

    fn cstr(&mut self) -> Result<String, DwarfError> {
        let start = self.pos;
        while self.pos < self.data.len() && self.data[self.pos] != 0 {
            self.pos += 1;
        }
        if self.pos >= self.data.len() {
            return Err(DwarfError::Malformed(format!(
                "unterminated string at {start:#x}"
            )));
        }
        let s = String::from_utf8_lossy(&self.data[start..self.pos]).into_owned();
        self.pos += 1;
        Ok(s)
    }

    fn skip(&mut self, n: usize) -> Result<(), DwarfError> {
        self.need(n)?;
        self.pos += n;
        Ok(())
    }
}

/// Read a NUL-terminated string out of `.debug_str` at `offset`.
fn str_at(section: &[u8], offset: usize) -> Option<String> {
    if offset >= section.len() {
        return None;
    }
    let rest = &section[offset..];
    let end = rest.iter().position(|&b| b == 0).unwrap_or(rest.len());
    Some(String::from_utf8_lossy(&rest[..end]).into_owned())
}

/// One decoded attribute value.
#[derive(Debug, Clone)]
enum AttrValue {
    Addr(u64),
    Uint(u64),
    Int(i64),
    Str(String),
    StrOffset(u64),
    Flag(bool),
    Skipped,
}

/// One abbreviation declaration from `.debug_abbrev`.
#[derive(Debug, Clone)]
struct Abbrev {
    tag: u64,
    has_children: bool,
    /// (attribute, form, implicit-const value)
    attrs: Vec<(u64, u64, i64)>,
}

/// Parse the abbreviation table that starts at `offset`.
fn parse_abbrev_table(
    data: &[u8],
    offset: usize,
) -> Result<std::collections::HashMap<u64, Abbrev>, DwarfError> {
    let mut table = std::collections::HashMap::new();
    if offset >= data.len() {
        return Ok(table);
    }
    let mut r = Reader::at(data, offset);
    loop {
        if r.eof() {
            break;
        }
        let code = r.uleb()?;
        if code == 0 {
            break;
        }
        let tag = r.uleb()?;
        let has_children = r.u8()? != 0;
        let mut attrs = Vec::new();
        loop {
            let at = r.uleb()?;
            let form = r.uleb()?;
            let implicit = if form == 0x21 { r.sleb()? } else { 0 };
            if at == 0 && form == 0 {
                break;
            }
            attrs.push((at, form, implicit));
        }
        table.insert(
            code,
            Abbrev {
                tag,
                has_children,
                attrs,
            },
        );
    }
    Ok(table)
}

/// Decode one attribute value of the given form.
fn read_form(
    r: &mut Reader<'_>,
    form: u64,
    implicit: i64,
    addr_size: u8,
    debug_str: &[u8],
) -> Result<AttrValue, DwarfError> {
    let v = match form {
        0x01 => AttrValue::Addr(match addr_size {
            8 => r.u64()?,
            4 => u64::from(r.u32()?),
            2 => u64::from(r.u16()?),
            other => {
                return Err(DwarfError::Malformed(format!(
                    "address size {other} unsupported"
                )));
            }
        }),
        0x03 => {
            let n = r.u16()? as usize;
            r.skip(n)?;
            AttrValue::Skipped
        }
        0x04 => {
            let n = r.u32()? as usize;
            r.skip(n)?;
            AttrValue::Skipped
        }
        0x05 => AttrValue::Uint(u64::from(r.u16()?)),
        0x06 | 0x17 | 0x22 | 0x23 => AttrValue::Uint(u64::from(r.u32()?)),
        0x07 => AttrValue::Uint(r.u64()?),
        0x08 => AttrValue::Str(r.cstr()?),
        0x09 | 0x18 => {
            let n = usize::try_from(r.uleb()?).unwrap_or(usize::MAX);
            r.skip(n)?;
            AttrValue::Skipped
        }
        0x0a => {
            let n = r.u8()? as usize;
            r.skip(n)?;
            AttrValue::Skipped
        }
        0x0b => AttrValue::Uint(u64::from(r.u8()?)),
        0x0c => AttrValue::Flag(r.u8()? != 0),
        0x0d => AttrValue::Int(r.sleb()?),
        0x0e | 0x1f => {
            let off = usize::try_from(r.u32()?).unwrap_or(usize::MAX);
            str_at(debug_str, off).map_or(AttrValue::StrOffset(off as u64), AttrValue::Str)
        }
        0x0f => AttrValue::Uint(r.uleb()?),
        0x10 => AttrValue::Uint(u64::from(r.u32()?)),
        0x11 => AttrValue::Uint(u64::from(r.u8()?)),
        0x12 => AttrValue::Uint(u64::from(r.u16()?)),
        0x13 => AttrValue::Uint(u64::from(r.u32()?)),
        0x14 | 0x20 => AttrValue::Uint(r.u64()?),
        0x15 => AttrValue::Uint(r.uleb()?),
        0x16 => {
            let inner = r.uleb()?;
            return read_form(r, inner, 0, addr_size, debug_str);
        }
        0x19 => AttrValue::Flag(true),
        0x1a | 0x1b => AttrValue::Uint(r.uleb()?),
        0x1c | 0x1d => AttrValue::Uint(u64::from(r.u32()?)),
        0x1e => {
            r.skip(16)?;
            AttrValue::Skipped
        }
        0x21 => AttrValue::Int(implicit),
        0x25 | 0x29 => AttrValue::Uint(u64::from(r.u8()?)),
        0x26 | 0x2a => AttrValue::Uint(u64::from(r.u16()?)),
        0x27 | 0x2b => {
            r.skip(3)?;
            AttrValue::Skipped
        }
        0x28 | 0x2c => AttrValue::Uint(u64::from(r.u32()?)),
        other => {
            return Err(DwarfError::Malformed(format!("unknown form {other:#x}")));
        }
    };
    Ok(v)
}

impl DwarfParser {
    /// Parse `.debug_line` into one [`LineTable`] per compilation unit.
    ///
    /// Implements the DWARF 2/3/4 line-number program: the file and directory
    /// tables come out of the unit header, and every row is produced by
    /// running the state machine, exactly as a debugger would.
    ///
    /// # Errors
    /// [`DwarfError::Missing`] on empty input, [`DwarfError::Malformed`] on a
    /// truncated or inconsistent program, [`DwarfError::UnsupportedVersion`]
    /// for DWARF 5 line headers (whose directory/file entry formats this
    /// parser does not decode).
    pub fn parse_line_program(debug_line: &[u8]) -> Result<Vec<LineTable>, DwarfError> {
        if debug_line.is_empty() {
            return Err(DwarfError::Missing {
                what: "line tables",
                missing: ".debug_line section",
            });
        }
        let mut tables = Vec::new();
        let mut unit_start = 0usize;
        while unit_start + 4 <= debug_line.len() {
            let mut r = Reader::at(debug_line, unit_start);
            let unit_length = r.u32()? as usize;
            if unit_length == 0 {
                break;
            }
            if unit_length == 0xFFFF_FFFF {
                return Err(DwarfError::Malformed(
                    "64-bit DWARF line units are not decoded".to_owned(),
                ));
            }
            let unit_end = r.pos + unit_length;
            if unit_end > debug_line.len() {
                return Err(DwarfError::Malformed(format!(
                    "line unit at {unit_start:#x} runs past the section"
                )));
            }
            let version = r.u16()?;
            if !(2..=4).contains(&version) {
                return Err(DwarfError::UnsupportedVersion(version, ".debug_line"));
            }
            let header_length = r.u32()? as usize;
            let program_start = r.pos + header_length;
            let min_inst_len = r.u8()?;
            if version >= 4 {
                let _max_ops = r.u8()?;
            }
            let default_is_stmt = r.u8()? != 0;
            let line_base = i64::from(r.i8()?);
            let line_range = u64::from(r.u8()?);
            let opcode_base = r.u8()?;
            let mut std_lengths = vec![0u8; opcode_base.saturating_sub(1) as usize];
            for slot in &mut std_lengths {
                *slot = r.u8()?;
            }

            // include_directories
            let mut dirs: Vec<String> = vec![String::new()];
            loop {
                let s = r.cstr()?;
                if s.is_empty() {
                    break;
                }
                dirs.push(s);
            }

            // file_names
            let mut table = LineTable::new(dirs.get(1).cloned().unwrap_or_default());
            loop {
                let name = r.cstr()?;
                if name.is_empty() {
                    break;
                }
                let dir_idx = usize::try_from(r.uleb()?).unwrap_or(0);
                let _mtime = r.uleb()?;
                let _length = r.uleb()?;
                let full = if name.starts_with('/') || dir_idx == 0 {
                    name
                } else {
                    dirs.get(dir_idx)
                        .map_or(name.clone(), |d| format!("{d}/{name}"))
                };
                table.add_file(full);
            }

            // ── the line-number program ──────────────────────────────────
            r.pos = program_start.max(r.pos);
            let mut address = 0u64;
            let mut file = 1u32;
            let mut line = 1i64;
            let mut column = 0u32;
            let mut is_stmt = default_is_stmt;
            let mut prologue_end = false;

            while r.pos < unit_end {
                let opcode = r.u8()?;
                if opcode >= opcode_base {
                    // special opcode
                    let adj = u64::from(opcode - opcode_base);
                    if line_range == 0 {
                        return Err(DwarfError::Malformed("line_range is zero".to_owned()));
                    }
                    address += (adj / line_range) * u64::from(min_inst_len);
                    line += line_base
                        + i64::try_from(adj % line_range).unwrap_or(0);
                    table.rows.push(LineEntry {
                        address,
                        file_index: file,
                        line: u32::try_from(line.max(0)).unwrap_or(u32::MAX),
                        column,
                        is_stmt,
                        end_sequence: false,
                        prologue_end,
                    });
                    prologue_end = false;
                } else if opcode == 0 {
                    // extended opcode
                    let len = usize::try_from(r.uleb()?).unwrap_or(0);
                    let next = r.pos + len;
                    if len == 0 {
                        continue;
                    }
                    let sub = r.u8()?;
                    match sub {
                        1 => {
                            table.rows.push(LineEntry {
                                address,
                                file_index: file,
                                line: 0,
                                column: 0,
                                is_stmt: false,
                                end_sequence: true,
                                prologue_end: false,
                            });
                            address = 0;
                            file = 1;
                            line = 1;
                            column = 0;
                            is_stmt = default_is_stmt;
                            prologue_end = false;
                        }
                        2 => {
                            address = match len - 1 {
                                8 => r.u64()?,
                                4 => u64::from(r.u32()?),
                                other => {
                                    return Err(DwarfError::Malformed(format!(
                                        "DW_LNE_set_address with {other}-byte address"
                                    )));
                                }
                            };
                        }
                        _ => {}
                    }
                    r.pos = next.min(unit_end);
                } else {
                    match opcode {
                        1 => {
                            table.rows.push(LineEntry {
                                address,
                                file_index: file,
                                line: u32::try_from(line.max(0)).unwrap_or(u32::MAX),
                                column,
                                is_stmt,
                                end_sequence: false,
                                prologue_end,
                            });
                            prologue_end = false;
                        }
                        2 => address += r.uleb()? * u64::from(min_inst_len),
                        3 => line += r.sleb()?,
                        4 => file = u32::try_from(r.uleb()?).unwrap_or(u32::MAX),
                        5 => column = u32::try_from(r.uleb()?).unwrap_or(u32::MAX),
                        6 => is_stmt = !is_stmt,
                        7 => {}
                        8 => {
                            if line_range == 0 {
                                return Err(DwarfError::Malformed(
                                    "line_range is zero".to_owned(),
                                ));
                            }
                            let adj = u64::from(255 - opcode_base);
                            address += (adj / line_range) * u64::from(min_inst_len);
                        }
                        9 => address += u64::from(r.u16()?),
                        10 => prologue_end = true,
                        11 | 12 => {
                            // epilogue_begin takes no operand, set_isa takes one ULEB
                            if opcode == 12 {
                                let _isa = r.uleb()?;
                            }
                        }
                        other => {
                            // Unknown standard opcode: skip its declared operands.
                            let n = std_lengths
                                .get(other as usize - 1)
                                .copied()
                                .unwrap_or(0);
                            for _ in 0..n {
                                let _ = r.uleb()?;
                            }
                        }
                    }
                }
            }

            table.sort();
            tables.push(table);
            unit_start = unit_end;
        }
        Ok(tables)
    }

    /// Parse `.debug_info`/`.debug_abbrev` into the function list.
    ///
    /// Walks every DIE of every compilation unit and keeps
    /// `DW_TAG_subprogram` / `DW_TAG_inlined_subroutine` entries that carry a
    /// name and a `DW_AT_low_pc`. `DW_AT_high_pc` is honoured in both its
    /// address form and its DWARF 4 offset form. `line_tables` supplies the
    /// file names that `DW_AT_decl_file` indexes into.
    ///
    /// # Errors
    /// [`DwarfError::Missing`] on empty input, [`DwarfError::Malformed`] on a
    /// truncated unit, [`DwarfError::UnsupportedVersion`] beyond DWARF 5.
    pub fn parse_debug_info(
        debug_info: &[u8],
        debug_abbrev: &[u8],
        debug_str: &[u8],
        line_tables: &[LineTable],
    ) -> Result<Vec<FunctionDebugInfo>, DwarfError> {
        if debug_info.is_empty() {
            return Err(DwarfError::Missing {
                what: "function debug info",
                missing: ".debug_info section",
            });
        }
        if debug_abbrev.is_empty() {
            return Err(DwarfError::Missing {
                what: "function debug info",
                missing: ".debug_abbrev section",
            });
        }

        let mut functions = Vec::new();
        let mut unit_start = 0usize;
        let mut cu_index = 0usize;
        while unit_start + 11 <= debug_info.len() {
            let mut r = Reader::at(debug_info, unit_start);
            let unit_length = r.u32()? as usize;
            if unit_length == 0 {
                break;
            }
            if unit_length == 0xFFFF_FFFF {
                return Err(DwarfError::Malformed(
                    "64-bit DWARF info units are not decoded".to_owned(),
                ));
            }
            let unit_end = r.pos + unit_length;
            if unit_end > debug_info.len() {
                return Err(DwarfError::Malformed(format!(
                    "info unit at {unit_start:#x} runs past the section"
                )));
            }
            let version = r.u16()?;
            if !(2..=5).contains(&version) {
                return Err(DwarfError::UnsupportedVersion(version, ".debug_info"));
            }
            let (abbrev_offset, addr_size) = if version >= 5 {
                let _unit_type = r.u8()?;
                let addr_size = r.u8()?;
                let off = r.u32()? as usize;
                (off, addr_size)
            } else {
                let off = r.u32()? as usize;
                let addr_size = r.u8()?;
                (off, addr_size)
            };
            let abbrevs = parse_abbrev_table(debug_abbrev, abbrev_offset)?;
            let files: &[String] = line_tables
                .get(cu_index)
                .map_or(&[], |t| t.files.as_slice());

            while r.pos < unit_end {
                let code = r.uleb()?;
                if code == 0 {
                    continue; // end of a sibling chain
                }
                let Some(abbrev) = abbrevs.get(&code).cloned() else {
                    return Err(DwarfError::Malformed(format!(
                        "abbrev code {code} not in table at offset {abbrev_offset:#x}"
                    )));
                };
                let _ = abbrev.has_children;

                let mut name = None;
                let mut linkage = None;
                let mut low_pc = None;
                let mut high_pc_raw = None;
                let mut high_pc_is_addr = false;
                let mut decl_file = None;
                let mut decl_line = None;

                for (at, form, implicit) in &abbrev.attrs {
                    let value = read_form(&mut r, *form, *implicit, addr_size, debug_str)?;
                    match (*at, &value) {
                        (0x03, AttrValue::Str(s)) => name = Some(s.clone()),
                        (0x6e | 0x2007, AttrValue::Str(s)) => linkage = Some(s.clone()),
                        (0x11, AttrValue::Addr(a) | AttrValue::Uint(a)) => low_pc = Some(*a),
                        (0x12, AttrValue::Addr(a)) => {
                            high_pc_raw = Some(*a);
                            high_pc_is_addr = true;
                        }
                        (0x12, AttrValue::Uint(a)) => high_pc_raw = Some(*a),
                        (0x3a, AttrValue::Uint(i)) => {
                            decl_file = usize::try_from(*i)
                                .ok()
                                .and_then(|i| files.get(i))
                                .cloned();
                        }
                        (0x3b, AttrValue::Uint(l)) => {
                            decl_line = u32::try_from(*l).ok();
                        }
                        _ => {}
                    }
                }

                let is_subprogram = abbrev.tag == 0x2e;
                let is_inlined = abbrev.tag == 0x1d;
                if (is_subprogram || is_inlined)
                    && let (Some(n), Some(lo)) = (name, low_pc)
                {
                    let hi = high_pc_raw.map_or(lo, |h| if high_pc_is_addr { h } else { lo + h });
                    functions.push(FunctionDebugInfo {
                        name: n,
                        linkage_name: linkage,
                        low_pc: lo,
                        high_pc: hi,
                        decl_file,
                        decl_line,
                        is_inline: is_inlined,
                    });
                }
            }

            cu_index += 1;
            unit_start = unit_end;
        }

        Ok(functions)
    }

    /// Build a [`SourceMap`] out of real DWARF section bytes.
    ///
    /// # Errors
    /// Propagates every [`DwarfError`] of the line and info parsers; a missing
    /// `.debug_info` is tolerated (the line table alone is still a valid map),
    /// a missing `.debug_line` is not.
    pub fn parse_sections(
        debug_line: &[u8],
        debug_info: &[u8],
        debug_abbrev: &[u8],
        debug_str: &[u8],
    ) -> Result<SourceMap, DwarfError> {
        let tables = Self::parse_line_program(debug_line)?;
        let mut sm = SourceMap::new();
        let functions = match Self::parse_debug_info(debug_info, debug_abbrev, debug_str, &tables) {
            Ok(f) => f,
            // Line info without DIEs is a legitimate, partial answer.
            Err(DwarfError::Missing { .. }) => Vec::new(),
            Err(e) => return Err(e),
        };
        for t in tables {
            sm.add_line_table(t);
        }
        for f in functions {
            sm.add_function(f);
        }
        Ok(sm)
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Real DWARF bytes, assembled here and decoded by the parser under test.
    /// Nothing below asserts a value that was not encoded into these sections.
    mod dwarf_fixture {
        fn uleb(out: &mut Vec<u8>, mut v: u64) {
            loop {
                let mut byte = u8::try_from(v & 0x7f).expect("7 bits");
                v >>= 7;
                if v != 0 {
                    byte |= 0x80;
                }
                out.push(byte);
                if v == 0 {
                    break;
                }
            }
        }

        fn sleb(out: &mut Vec<u8>, mut v: i64) {
            loop {
                let mut byte = u8::try_from(v as u64 & 0x7f).expect("7 bits");
                v >>= 7;
                let sign_bit = byte & 0x40 != 0;
                if (v == 0 && !sign_bit) || (v == -1 && sign_bit) {
                    out.push(byte);
                    return;
                }
                byte |= 0x80;
                out.push(byte);
            }
        }

        /// A DWARF 4 `.debug_line` unit for `/src/main.c` with rows at
        /// 0x1000/line 10, 0x1010/line 12, 0x1020/line 14 and an
        /// end-sequence at 0x1030.
        pub fn debug_line() -> Vec<u8> {
            let mut header = Vec::new();
            header.push(1u8); // minimum_instruction_length
            header.push(1u8); // maximum_operations_per_instruction (v4)
            header.push(1u8); // default_is_stmt
            header.push(0xFBu8); // line_base = -5
            header.push(14u8); // line_range
            header.push(13u8); // opcode_base
            header.extend_from_slice(&[0, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1]); // std lengths
            header.extend_from_slice(b"/src\0"); // include_directories[1]
            header.push(0); // end of directories
            header.extend_from_slice(b"main.c\0");
            uleb(&mut header, 1); // dir index
            uleb(&mut header, 0); // mtime
            uleb(&mut header, 0); // length
            header.push(0); // end of file names

            let mut prog = Vec::new();
            // DW_LNE_set_address 0x1000
            prog.extend_from_slice(&[0x00, 0x09, 0x02]);
            prog.extend_from_slice(&0x1000u64.to_le_bytes());
            prog.push(0x03); // DW_LNS_advance_line
            sleb(&mut prog, 9); // line 1 -> 10
            prog.push(0x0A); // DW_LNS_set_prologue_end
            prog.push(0x01); // DW_LNS_copy
            prog.push(0x02); // DW_LNS_advance_pc
            uleb(&mut prog, 0x10);
            prog.push(0x03);
            sleb(&mut prog, 2); // line 12
            prog.push(0x01);
            prog.push(0x02);
            uleb(&mut prog, 0x10);
            prog.push(0x03);
            sleb(&mut prog, 2); // line 14
            prog.push(0x01);
            prog.push(0x02);
            uleb(&mut prog, 0x10); // -> 0x1030
            prog.extend_from_slice(&[0x00, 0x01, 0x01]); // DW_LNE_end_sequence

            let mut unit = Vec::new();
            unit.extend_from_slice(&4u16.to_le_bytes()); // version
            unit.extend_from_slice(
                &u32::try_from(header.len()).expect("header length").to_le_bytes(),
            );
            unit.extend_from_slice(&header);
            unit.extend_from_slice(&prog);

            let mut out = Vec::new();
            out.extend_from_slice(&u32::try_from(unit.len()).expect("unit length").to_le_bytes());
            out.extend_from_slice(&unit);
            out
        }

        /// Abbreviations for the compile unit and the `main` subprogram.
        pub fn debug_abbrev() -> Vec<u8> {
            let mut a = Vec::new();
            // code 1: DW_TAG_compile_unit, has children, DW_AT_name(string)
            uleb(&mut a, 1);
            uleb(&mut a, 0x11);
            a.push(1);
            uleb(&mut a, 0x03);
            uleb(&mut a, 0x08);
            uleb(&mut a, 0);
            uleb(&mut a, 0);
            // code 2: DW_TAG_subprogram, no children
            uleb(&mut a, 2);
            uleb(&mut a, 0x2E);
            a.push(0);
            for (at, form) in [
                (0x03u64, 0x08u64), // name, string
                (0x6E, 0x08),       // linkage_name, string
                (0x11, 0x01),       // low_pc, addr
                (0x12, 0x06),       // high_pc, data4 (offset form)
                (0x3A, 0x0B),       // decl_file, data1
                (0x3B, 0x0B),       // decl_line, data1
            ] {
                uleb(&mut a, at);
                uleb(&mut a, form);
            }
            uleb(&mut a, 0);
            uleb(&mut a, 0);
            a.push(0); // end of table
            a
        }

        /// One compile unit declaring `main` at 0x1000..0x1030, line 9.
        pub fn debug_info() -> Vec<u8> {
            let mut unit = Vec::new();
            unit.extend_from_slice(&4u16.to_le_bytes()); // version
            unit.extend_from_slice(&0u32.to_le_bytes()); // abbrev offset
            unit.push(8); // address size
            uleb(&mut unit, 1); // DW_TAG_compile_unit
            unit.extend_from_slice(b"main.c\0");
            uleb(&mut unit, 2); // DW_TAG_subprogram
            unit.extend_from_slice(b"main\0");
            unit.extend_from_slice(b"_main\0");
            unit.extend_from_slice(&0x1000u64.to_le_bytes());
            unit.extend_from_slice(&0x30u32.to_le_bytes());
            unit.push(1); // decl_file -> file table index 1
            unit.push(9); // decl_line
            uleb(&mut unit, 0); // end of children

            let mut out = Vec::new();
            out.extend_from_slice(&u32::try_from(unit.len()).expect("unit length").to_le_bytes());
            out.extend_from_slice(&unit);
            out
        }

        /// The source map the four sections above describe.
        pub fn source_map() -> super::SourceMap {
            super::DwarfParser::mock_source_map(
                &debug_line(),
                &debug_info(),
                &debug_abbrev(),
                &[],
            )
            .expect("fixture DWARF parses")
        }
    }


    #[test]
    fn test_line_table_lookup() {
        let sm = dwarf_fixture::source_map();
        let loc = sm.lookup_location(0x1000).unwrap();
        assert_eq!(loc.line, 10);
        assert_eq!(loc.file, "/src/main.c");
    }

    #[test]
    fn test_line_table_floor_lookup() {
        let sm = dwarf_fixture::source_map();
        // Address between 0x1000 and 0x1010 should map to line 10
        let loc = sm.lookup_location(0x1008).unwrap();
        assert_eq!(loc.line, 10);
    }

    #[test]
    fn test_function_lookup() {
        let sm = dwarf_fixture::source_map();
        let func = sm.lookup_function(0x1015).unwrap();
        assert_eq!(func.name, "main");
    }

    #[test]
    fn test_function_lookup_out_of_range() {
        let sm = dwarf_fixture::source_map();
        let func = sm.lookup_function(0x9999);
        assert!(func.is_none());
    }

    #[test]
    fn test_source_attribution() {
        let sm = dwarf_fixture::source_map();
        let attributor = SourceAttributor::new(sm);
        let hits = vec![(0x1000u64, 5u32), (0x1010, 3), (0x1020, 0)];
        let report = attributor.attribute("test.exe", &hits);
        assert!(report.has_debug_info);
        assert_eq!(report.files.len(), 1);
        let fc = &report.files[0];
        assert_eq!(fc.file, "/src/main.c");
        assert_eq!(fc.covered_lines(), 2); // lines 10 and 12 have hits > 0
        assert_eq!(fc.total_lines(), 3);   // lines 10, 12, 14
    }

    #[test]
    fn test_file_coverage_pct() {
        let mut fc = FileCoverage::new("test.c");
        fc.record_hit(1, 5);
        fc.record_hit(2, 0);
        fc.record_hit(3, 3);
        assert_eq!(fc.covered_lines(), 2);
        assert_eq!(fc.total_lines(), 3);
        let pct = fc.line_coverage_pct();
        assert!((pct - 66.666).abs() < 0.01);
    }

    #[test]
    fn test_uncovered_lines() {
        let mut fc = FileCoverage::new("test.c");
        fc.record_hit(10, 1);
        fc.record_hit(11, 0);
        fc.record_hit(12, 0);
        let uncov = fc.uncovered_lines();
        assert_eq!(uncov, vec![11, 12]);
    }

    #[test]
    fn test_source_location_display() {
        let loc = SourceLocation::new("foo.c", 42, 7);
        assert_eq!(loc.to_string(), "foo.c:42:7");
        let loc2 = SourceLocation::file_line("bar.c", 10);
        assert_eq!(loc2.to_string(), "bar.c:10");
    }

    #[test]
    fn test_json_roundtrip() {
        let sm = dwarf_fixture::source_map();
        let attributor = SourceAttributor::new(sm);
        let hits = vec![(0x1000u64, 1u32)];
        let report = attributor.attribute("mod", &hits);
        let json = report.to_json().unwrap();
        assert!(json.contains("main.c"));
    }

    #[test]
    fn test_line_program_rows_are_decoded() {
        let tables =
            DwarfParser::parse_line_program(&dwarf_fixture::debug_line()).expect("line program");
        assert_eq!(tables.len(), 1);
        let rows = &tables[0].rows;
        assert_eq!(rows.len(), 4);
        assert_eq!((rows[0].address, rows[0].line), (0x1000, 10));
        assert_eq!((rows[1].address, rows[1].line), (0x1010, 12));
        assert_eq!((rows[2].address, rows[2].line), (0x1020, 14));
        assert!(rows[0].prologue_end);
        assert!(rows[3].end_sequence);
        assert_eq!(rows[3].address, 0x1030);
    }

    #[test]
    fn test_debug_info_functions_are_decoded() {
        let tables =
            DwarfParser::parse_line_program(&dwarf_fixture::debug_line()).expect("line program");
        let funcs = DwarfParser::parse_debug_info(
            &dwarf_fixture::debug_info(),
            &dwarf_fixture::debug_abbrev(),
            &[],
            &tables,
        )
        .expect("debug info");
        assert_eq!(funcs.len(), 1);
        assert_eq!(funcs[0].name, "main");
        assert_eq!(funcs[0].linkage_name.as_deref(), Some("_main"));
        assert_eq!(funcs[0].low_pc, 0x1000);
        // DW_AT_high_pc in offset form: 0x1000 + 0x30
        assert_eq!(funcs[0].high_pc, 0x1030);
        assert_eq!(funcs[0].decl_line, Some(9));
        assert_eq!(funcs[0].decl_file.as_deref(), Some("/src/main.c"));
    }

    #[test]
    fn test_missing_debug_line_is_an_error() {
        let err = DwarfParser::parse_line_program(&[]).unwrap_err();
        assert!(matches!(err, DwarfError::Missing { .. }), "{err}");
    }

    #[test]
    fn test_parse_returns_none_without_dwarf() {
        assert!(DwarfParser::parse(&[], &[], &[], &[]).is_none());
    }

    #[test]
    fn test_parse_sections_round_trip() {
        let sm = DwarfParser::parse_sections(
            &dwarf_fixture::debug_line(),
            &dwarf_fixture::debug_info(),
            &dwarf_fixture::debug_abbrev(),
            &[],
        )
        .expect("source map");
        assert!(sm.has_debug_info);
        assert_eq!(sm.lookup_location(0x1020).expect("row").line, 14);
        assert_eq!(sm.lookup_function(0x1005).expect("func").name, "main");
    }
}
