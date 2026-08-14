//! `CodeView` function-info decoder.
//!
//! Parses `S_GPROC32` / `S_LPROC32` symbol records, FRAMEPROC (`CvFrameInfo`),
//! `S_LOCAL` locals (`CvLocal`), and inlinee records, building a
//! per-function database (`CvFunctionDb`).

use std::collections::HashMap;
use std::fmt;

// ── Error ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CvFuncError {
    Truncated { offset: usize, needed: usize },
    UnknownRecord(u16),
    Other(String),
}

impl fmt::Display for CvFuncError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated { offset, needed } => {
                write!(f, "truncated at {offset}, needed {needed}")
            }
            Self::UnknownRecord(k) => write!(f, "unknown record {k:#06x}"),
            Self::Other(s) => write!(f, "{s}"),
        }
    }
}

// ── Symbol-record kind constants ──────────────────────────────────────────────

pub mod symkind {
    pub const S_GPROC32: u16 = 0x1110;
    pub const S_LPROC32: u16 = 0x110F;
    pub const S_GPROC32_ID: u16 = 0x1147;
    pub const S_LPROC32_ID: u16 = 0x1146;
    pub const S_END: u16 = 0x0006;
    pub const S_FRAMEPROC: u16 = 0x1012;
    pub const S_LOCAL: u16 = 0x113E;
    pub const S_REGREL32: u16 = 0x1111;
    pub const S_INLINESITE: u16 = 0x114D;
    pub const S_INLINESITE2: u16 = 0x115D;
    pub const S_INLINESITE_END: u16 = 0x114E;
    pub const S_CALLSITEINFO: u16 = 0x1139;
    pub const S_BUILDINFO: u16 = 0x114C;
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn read_u16(data: &[u8], pos: usize) -> Result<u16, CvFuncError> {
    if pos + 2 > data.len() {
        return Err(CvFuncError::Truncated {
            offset: pos,
            needed: 2,
        });
    }
    Ok(u16::from_le_bytes([data[pos], data[pos + 1]]))
}

fn read_u32(data: &[u8], pos: usize) -> Result<u32, CvFuncError> {
    if pos + 4 > data.len() {
        return Err(CvFuncError::Truncated {
            offset: pos,
            needed: 4,
        });
    }
    Ok(u32::from_le_bytes([
        data[pos],
        data[pos + 1],
        data[pos + 2],
        data[pos + 3],
    ]))
}

fn read_cstring(data: &[u8], pos: usize) -> (String, usize) {
    let end = data[pos..]
        .iter()
        .position(|&b| b == 0)
        .map_or(data.len(), |n| pos + n);
    let s = String::from_utf8_lossy(&data[pos..end]).to_string();
    (s, end - pos + 1)
}

// ── CvFunctionInfo (S_GPROC32 / S_LPROC32) ───────────────────────────────────

/// Parsed `S_GPROC32` or `S_LPROC32` symbol record.
#[derive(Debug, Clone)]
pub struct CvFunctionInfo {
    /// Function name.
    pub name: String,
    /// Whether this is a global (`S_GPROC32`) vs local (`S_LPROC32`) proc.
    pub is_global: bool,
    /// Offset of the function start within its segment.
    pub offset: u32,
    /// Segment index.
    pub segment: u16,
    /// Code length in bytes.
    pub code_length: u32,
    /// Debug-start offset (within function body).
    pub debug_start: u32,
    /// Debug-end offset (within function body).
    pub debug_end: u32,
    /// Type index of the function.
    pub type_index: u32,
    /// Flags byte.
    pub flags: u8,
    /// Relative virtual address (populated after section map is applied).
    pub rva: u64,
}

impl CvFunctionInfo {
    /// Parse from the *body* of a `S_GPROC32/S_LPROC32` record (after the 2-byte kind).
    ///
    /// `S_PROC32` body layout:
    /// ```text
    /// parent:        u32  (+0)
    /// end:           u32  (+4)
    /// next:          u32  (+8)
    /// code_length:   u32  (+12)
    /// debug_start:   u32  (+16)
    /// debug_end:     u32  (+20)
    /// type_index:    u32  (+24)
    /// offset:        u32  (+28)
    /// segment:       u16  (+32)
    /// flags:         u8   (+34)
    /// name:          [u8]  (+35, null-terminated)
    /// ```
    /// # Errors
    /// Returns [`CvFuncError::Truncated`] if `body` is shorter than 35 bytes.
    pub fn parse(body: &[u8], is_global: bool) -> Result<Self, CvFuncError> {
        if body.len() < 35 {
            return Err(CvFuncError::Truncated {
                offset: 0,
                needed: 35,
            });
        }
        let _parent = read_u32(body, 0)?;
        let _end = read_u32(body, 4)?;
        let _next = read_u32(body, 8)?;
        let code_length = read_u32(body, 12)?;
        let debug_start = read_u32(body, 16)?;
        let debug_end = read_u32(body, 20)?;
        let type_index = read_u32(body, 24)?;
        let offset = read_u32(body, 28)?;
        let segment = read_u16(body, 32)?;
        let flags = body[34];
        let (name, _) = read_cstring(body, 35);

        Ok(Self {
            name,
            is_global,
            offset,
            segment,
            code_length,
            debug_start,
            debug_end,
            type_index,
            flags,
            rva: 0,
        })
    }

    /// Whether the function has been inlined (per flags).
    #[must_use]
    pub const fn is_inlined(&self) -> bool {
        self.flags & 0x01 != 0
    }

    /// Whether the function has no return (noreturn attribute).
    #[must_use]
    pub const fn is_noreturn(&self) -> bool {
        self.flags & 0x02 != 0
    }

    /// Compute the end RVA of the function.
    #[must_use]
    pub const fn end_rva(&self) -> u64 {
        self.rva + self.code_length as u64
    }
}

impl fmt::Display for CvFunctionInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let scope = if self.is_global { "global" } else { "local" };
        write!(
            f,
            "{} {} offset={:#x} seg={} len={}",
            scope, self.name, self.offset, self.segment, self.code_length
        )
    }
}

// ── CvFrameInfo (S_FRAMEPROC) ────────────────────────────────────────────────

/// Parsed FRAMEPROC symbol record.
#[derive(Debug, Clone)]
pub struct CvFrameInfo {
    /// Total frame size (bytes allocated on stack).
    pub frame_size: u32,
    /// Size of padding area between locals and save area.
    pub pad_size: u32,
    /// Offset of padding within the frame.
    pub pad_offset: u32,
    /// Size of callee-save register save area.
    pub save_size: u32,
    /// Exception handler offset.
    pub eh_offset: u32,
    /// Exception handler segment.
    pub eh_section: u16,
    /// FRAMEPROC flags.
    pub flags: u32,
}

impl CvFrameInfo {
    /// Parse from the body of a `S_FRAMEPROC` record.
    ///
    /// Layout:
    /// ```text
    /// frame_size:   u32  (+0)
    /// pad_size:     u32  (+4)
    /// pad_offset:   u32  (+8)
    /// save_size:    u32  (+12)
    /// eh_offset:    u32  (+16)
    /// eh_section:   u16  (+20)
    /// flags:        u32  (+22)
    /// ```
    /// # Errors
    /// Returns [`CvFuncError::Truncated`] if `body` is shorter than 26 bytes.
    pub fn parse(body: &[u8]) -> Result<Self, CvFuncError> {
        if body.len() < 26 {
            return Err(CvFuncError::Truncated {
                offset: 0,
                needed: 26,
            });
        }
        let frame_size = read_u32(body, 0)?;
        let pad_size = read_u32(body, 4)?;
        let pad_offset = read_u32(body, 8)?;
        let save_size = read_u32(body, 12)?;
        let eh_offset = read_u32(body, 16)?;
        let eh_section = read_u16(body, 20)?;
        let flags = read_u32(body, 22)?;
        Ok(Self {
            frame_size,
            pad_size,
            pad_offset,
            save_size,
            eh_offset,
            eh_section,
            flags,
        })
    }

    /// Whether the function uses SEH.
    #[must_use]
    pub const fn has_seh(&self) -> bool {
        self.flags & 0x0001 != 0
    }

    /// Whether the function uses EH (C++ exception handling).
    #[must_use]
    pub const fn has_eh(&self) -> bool {
        self.flags & 0x0002 != 0
    }

    /// Whether the function uses alloca.
    #[must_use]
    pub const fn has_alloca(&self) -> bool {
        self.flags & 0x0004 != 0
    }

    /// Whether the function uses inline assembly.
    #[must_use]
    pub const fn has_inline_asm(&self) -> bool {
        self.flags & 0x0008 != 0
    }

    /// Whether the function has stack security checks (/GS).
    #[must_use]
    pub const fn has_security_checks(&self) -> bool {
        self.flags & 0x0010 != 0
    }

    /// Whether the frame pointer has been omitted.
    #[must_use]
    pub const fn frame_pointer_omitted(&self) -> bool {
        self.flags & 0x0100 != 0
    }
}

// ── CvLocal (S_LOCAL) ─────────────────────────────────────────────────────────

/// Parsed `S_LOCAL` symbol record.
#[derive(Debug, Clone)]
pub struct CvLocal {
    /// Type index of the local variable.
    pub type_index: u32,
    /// Local-variable flags.
    pub flags: u16,
    /// Variable name.
    pub name: String,
}

impl CvLocal {
    /// Parse from the body of an `S_LOCAL` record.
    ///
    /// Layout:
    /// ```text
    /// type_index:  u32  (+0)
    /// flags:       u16  (+4)
    /// name:        [u8] (+6, null-terminated)
    /// ```
    /// # Errors
    /// Returns [`CvFuncError::Truncated`] if `body` is shorter than 6 bytes.
    pub fn parse(body: &[u8]) -> Result<Self, CvFuncError> {
        if body.len() < 6 {
            return Err(CvFuncError::Truncated {
                offset: 0,
                needed: 6,
            });
        }
        let type_index = read_u32(body, 0)?;
        let flags = read_u16(body, 4)?;
        let (name, _) = read_cstring(body, 6);
        Ok(Self {
            type_index,
            flags,
            name,
        })
    }

    /// Whether this local is a parameter.
    #[must_use]
    pub const fn is_param(&self) -> bool {
        self.flags & 0x0001 != 0
    }

    /// Whether this local is an address-taken variable.
    #[must_use]
    pub const fn is_address_taken(&self) -> bool {
        self.flags & 0x0002 != 0
    }

    /// Whether this local is a compiler-generated variable (e.g. `this` ptr).
    #[must_use]
    pub const fn is_compiler_generated(&self) -> bool {
        self.flags & 0x0004 != 0
    }

    /// Whether this is a register variable (live in a register at all times).
    #[must_use]
    pub const fn is_enreg(&self) -> bool {
        self.flags & 0x0010 != 0
    }
}

impl fmt::Display for CvLocal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind = if self.is_param() { "param" } else { "local" };
        write!(f, "{kind} {} type={:#x}", self.name, self.type_index)
    }
}

// ── CvInlinees / InlineTree ───────────────────────────────────────────────────

/// A single entry in the inline site record.
#[derive(Debug, Clone)]
pub struct CvInlinee {
    /// Inlinee function type index.
    pub inlinee: u32,
    /// File checksum offset (index into checksum table).
    pub file_id: u32,
    /// Source line where inlining occurred.
    pub source_line: u32,
}

impl CvInlinee {
    /// Parse from a binary slice.
    ///
    /// # Errors
    /// Returns [`CvFuncError::Truncated`] if `data` is shorter than 12 bytes.
    pub fn parse(data: &[u8]) -> Result<Self, CvFuncError> {
        if data.len() < 12 {
            return Err(CvFuncError::Truncated {
                offset: 0,
                needed: 12,
            });
        }
        let inlinee = read_u32(data, 0)?;
        let file_id = read_u32(data, 4)?;
        let source_line = read_u32(data, 8)?;
        Ok(Self {
            inlinee,
            file_id,
            source_line,
        })
    }
}

/// The full inline call tree for a function.
#[derive(Debug, Clone, Default)]
pub struct InlineTree {
    pub sites: Vec<InlineSite>,
}

/// One inline call site.
#[derive(Debug, Clone)]
pub struct InlineSite {
    pub inlinee_id: u32,
    pub invocation_count: u32,
    pub binary_annotations: Vec<u8>,
}

impl InlineTree {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_site(&mut self, site: InlineSite) {
        self.sites.push(site);
    }

    #[must_use]
    pub const fn depth(&self) -> usize {
        self.sites.len()
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.sites.is_empty()
    }

    /// All unique inlinee IDs in the tree.
    #[must_use]
    pub fn unique_inlinees(&self) -> Vec<u32> {
        let mut ids: Vec<u32> = self.sites.iter().map(|s| s.inlinee_id).collect();
        ids.sort_unstable();
        ids.dedup();
        ids
    }
}

// ── CvFunctionDb ──────────────────────────────────────────────────────────────

/// Database of `CodeView` function records for one module/object file.
#[derive(Debug, Default)]
pub struct CvFunctionDb {
    /// All function records, keyed by symbol offset.
    pub functions: HashMap<u32, CvFunctionRecord>,
}

/// All debug information associated with one function.
#[derive(Debug, Clone, Default)]
pub struct CvFunctionRecord {
    pub proc: Option<CvFunctionInfo>,
    pub frame: Option<CvFrameInfo>,
    pub locals: Vec<CvLocal>,
    pub inline_tree: InlineTree,
}

impl CvFunctionRecord {
    /// Whether this record has full frame information.
    #[must_use]
    pub const fn has_frame_info(&self) -> bool {
        self.frame.is_some()
    }

    /// List of parameter locals.
    #[must_use]
    pub fn params(&self) -> Vec<&CvLocal> {
        self.locals.iter().filter(|l| l.is_param()).collect()
    }

    /// List of non-parameter locals.
    #[must_use]
    pub fn variables(&self) -> Vec<&CvLocal> {
        self.locals.iter().filter(|l| !l.is_param()).collect()
    }
}

impl CvFunctionDb {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert or update a function record.
    pub fn insert_proc(&mut self, offset: u32, proc: CvFunctionInfo) {
        self.functions.entry(offset).or_default().proc = Some(proc);
    }

    /// Attach frame info to an existing function.
    pub fn attach_frame(&mut self, offset: u32, frame: CvFrameInfo) {
        self.functions.entry(offset).or_default().frame = Some(frame);
    }

    /// Attach a local variable to a function.
    pub fn attach_local(&mut self, offset: u32, local: CvLocal) {
        self.functions.entry(offset).or_default().locals.push(local);
    }

    /// Look up a function by symbol offset.
    #[must_use]
    pub fn get(&self, offset: u32) -> Option<&CvFunctionRecord> {
        self.functions.get(&offset)
    }

    /// Count of functions in the database.
    #[must_use]
    pub fn count(&self) -> usize {
        self.functions.len()
    }

    /// Parse a symbol stream and populate the database.
    ///
    /// `data` is the raw contents of a symbol stream (sequence of
    /// `length: u16, kind: u16, body: [u8; length-2]` records).
    /// # Errors
    /// Returns [`CvFuncError`] if a record is malformed or truncated.
    pub fn parse_symbol_stream(&mut self, data: &[u8]) -> Result<(), CvFuncError> {
        let mut pos = 0;
        let mut current_func_offset: Option<u32> = None;

        while pos + 4 <= data.len() {
            let record_len = read_u16(data, pos)? as usize;
            if record_len < 2 {
                // Malformed: a record length below 2 cannot describe even the
                // kind field, and advancing by it would desynchronize (or, at
                // record_len == 0, loop forever). Stop.
                break;
            }
            let kind = read_u16(data, pos + 2)?;
            let body_start = pos + 4;
            let body_end = pos + 2 + record_len;
            if body_end > data.len() {
                break;
            }
            let body = &data[body_start..body_end];

            match kind {
                symkind::S_GPROC32
                | symkind::S_LPROC32
                | symkind::S_GPROC32_ID
                | symkind::S_LPROC32_ID => {
                    let is_global = kind == symkind::S_GPROC32 || kind == symkind::S_GPROC32_ID;
                    if let Ok(proc) = CvFunctionInfo::parse(body, is_global) {
                        let func_offset: u32 = body_start.try_into().unwrap_or(u32::MAX);
                        self.insert_proc(func_offset, proc);
                        current_func_offset = Some(func_offset);
                    }
                }
                symkind::S_FRAMEPROC => {
                    if let (Ok(frame), Some(off)) = (CvFrameInfo::parse(body), current_func_offset)
                    {
                        self.attach_frame(off, frame);
                    }
                }
                symkind::S_LOCAL => {
                    if let (Ok(local), Some(off)) = (CvLocal::parse(body), current_func_offset) {
                        self.attach_local(off, local);
                    }
                }
                symkind::S_END => {
                    current_func_offset = None;
                }
                _ => {}
            }

            // CodeView records carry their own alignment padding inside
            // record_len, so 2 + record_len is already 4-aligned. Adding a
            // further realignment here would skip 2 bytes per record.
            pos += 2 + record_len;
        }
        Ok(())
    }
}

// ── CvFunctionCallSite ────────────────────────────────────────────────────────

/// A single call site within a function (`S_CALLSITEINFO`).
#[derive(Debug, Clone)]
pub struct CvFunctionCallSite {
    /// Offset of the call instruction.
    pub offset: u32,
    /// Segment.
    pub segment: u16,
    /// Type index of the called function.
    pub type_index: u32,
}

impl CvFunctionCallSite {
    /// Parse from a `S_CALLSITEINFO` body.
    ///
    /// # Errors
    /// Returns [`CvFuncError::Truncated`] if `body` is shorter than 10 bytes.
    pub fn parse(body: &[u8]) -> Result<Self, CvFuncError> {
        if body.len() < 10 {
            return Err(CvFuncError::Truncated {
                offset: 0,
                needed: 10,
            });
        }
        let offset = read_u32(body, 0)?;
        let segment = read_u16(body, 4)?;
        let _pad = read_u16(body, 6)?;
        let type_index = read_u32(body, 8)?;
        Ok(Self {
            offset,
            segment,
            type_index,
        })
    }
}

// ── CvBuildInfo ───────────────────────────────────────────────────────────────

/// Parsed `S_BUILDINFO` symbol record.
#[derive(Debug, Clone)]
pub struct CvBuildInfo {
    /// Build info type index.
    pub id: u32,
}

impl CvBuildInfo {
    /// # Errors
    /// Returns [`CvFuncError::Truncated`] if `body` is shorter than 4 bytes.
    pub fn parse(body: &[u8]) -> Result<Self, CvFuncError> {
        if body.len() < 4 {
            return Err(CvFuncError::Truncated {
                offset: 0,
                needed: 4,
            });
        }
        let id = read_u32(body, 0)?;
        Ok(Self { id })
    }
}

// ── CvScopeBlock ─────────────────────────────────────────────────────────────

/// Represents a lexical scope block within a function.
#[derive(Debug, Clone)]
pub struct CvScopeBlock {
    pub parent: u32,
    pub end: u32,
    pub code_length: u32,
    pub offset: u32,
    pub segment: u16,
    pub name: String,
}

impl CvScopeBlock {
    /// # Errors
    /// Returns [`CvFuncError::Truncated`] if `body` is shorter than 18 bytes.
    pub fn parse(body: &[u8]) -> Result<Self, CvFuncError> {
        if body.len() < 18 {
            return Err(CvFuncError::Truncated {
                offset: 0,
                needed: 18,
            });
        }
        let parent = read_u32(body, 0)?;
        let end = read_u32(body, 4)?;
        let code_length = read_u32(body, 8)?;
        let offset = read_u32(body, 12)?;
        let segment = read_u16(body, 16)?;
        let (name, _) = if body.len() > 18 {
            read_cstring(body, 18)
        } else {
            (String::new(), 0)
        };
        Ok(Self {
            parent,
            end,
            code_length,
            offset,
            segment,
            name,
        })
    }
}

// ── CvFunctionCallGraph ───────────────────────────────────────────────────────

/// Call graph derived from `CodeView` call-site records.
#[derive(Debug, Default)]
pub struct CvFunctionCallGraph {
    /// `caller_offset` → list of callee `type_indices`
    pub edges: std::collections::HashMap<u32, Vec<u32>>,
}

impl CvFunctionCallGraph {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a call edge.
    pub fn add_call(&mut self, caller_offset: u32, callee_type_index: u32) {
        self.edges
            .entry(caller_offset)
            .or_default()
            .push(callee_type_index);
    }

    /// Out-degree of a function (number of call sites).
    #[must_use]
    pub fn out_degree(&self, caller_offset: u32) -> usize {
        self.edges.get(&caller_offset).map_or(0, Vec::len)
    }

    /// Whether a function is a leaf.
    #[must_use]
    pub fn is_leaf(&self, caller_offset: u32) -> bool {
        self.out_degree(caller_offset) == 0
    }

    /// Number of functions in the call graph.
    #[must_use]
    pub fn node_count(&self) -> usize {
        self.edges.len()
    }
}

// ── FunctionCoverage ──────────────────────────────────────────────────────────

/// Tracks which functions have been visited during analysis.
#[derive(Debug, Default)]
pub struct FunctionCoverage {
    visited: std::collections::HashSet<u32>,
    total: usize,
}

impl FunctionCoverage {
    #[must_use]
    pub fn new(total: usize) -> Self {
        Self {
            visited: std::collections::HashSet::default(),
            total,
        }
    }

    /// Mark a function (by symbol offset) as visited.
    pub fn visit(&mut self, offset: u32) {
        self.visited.insert(offset);
    }

    /// Whether a function has been visited.
    #[must_use]
    pub fn is_visited(&self, offset: u32) -> bool {
        self.visited.contains(&offset)
    }

    /// Coverage percentage.
    #[must_use]
    pub fn percent(&self) -> f64 {
        if self.total == 0 {
            return 100.0;
        }
        let visited: u32 = self.visited.len().try_into().unwrap_or(u32::MAX);
        let total: u32 = self.total.try_into().unwrap_or(u32::MAX);
        f64::from(visited) / f64::from(total) * 100.0
    }

    /// Number of visited functions.
    #[must_use]
    pub fn visited_count(&self) -> usize {
        self.visited.len()
    }

    /// Total function count.
    #[must_use]
    pub const fn total_count(&self) -> usize {
        self.total
    }
}

// ── CvFunctionStats ───────────────────────────────────────────────────────────

/// Statistics gathered from a `CvFunctionDb`.
#[derive(Debug, Clone, Default)]
pub struct CvFunctionStats {
    pub total_functions: usize,
    pub functions_with_frame: usize,
    pub total_locals: usize,
    pub total_params: usize,
    pub functions_with_inlines: usize,
    pub global_functions: usize,
    pub local_functions: usize,
}

impl CvFunctionStats {
    /// Compute from a function database.
    #[must_use]
    pub fn compute(db: &CvFunctionDb) -> Self {
        let mut s = Self {
            total_functions: db.count(),
            ..Self::default()
        };
        for rec in db.functions.values() {
            if rec.has_frame_info() {
                s.functions_with_frame += 1;
            }
            s.total_locals += rec.variables().len();
            s.total_params += rec.params().len();
            if !rec.inline_tree.is_empty() {
                s.functions_with_inlines += 1;
            }
            if let Some(proc) = &rec.proc {
                if proc.is_global {
                    s.global_functions += 1;
                } else {
                    s.local_functions += 1;
                }
            }
        }
        s
    }

    /// Mean number of locals per function.
    #[must_use]
    pub fn mean_locals(&self) -> f64 {
        if self.total_functions == 0 {
            return 0.0;
        }
        let locals: u32 = self.total_locals.try_into().unwrap_or(u32::MAX);
        let funcs: u32 = self.total_functions.try_into().unwrap_or(u32::MAX);
        f64::from(locals) / f64::from(funcs)
    }
}

impl std::fmt::Display for CvFunctionStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "CvFunctionStats: {} funcs, {} with frame, {} locals, {} params",
            self.total_functions, self.functions_with_frame, self.total_locals, self.total_params
        )
    }
}

// ── SymbolStreamBuilder ───────────────────────────────────────────────────────

/// Builds a synthetic `CodeView` symbol stream for testing.
pub struct SymbolStreamBuilder {
    records: Vec<(u16, Vec<u8>)>,
}

impl SymbolStreamBuilder {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            records: Vec::new(),
        }
    }

    /// Add a raw record.
    pub fn add(&mut self, kind: u16, body: Vec<u8>) -> &mut Self {
        self.records.push((kind, body));
        self
    }

    /// Serialize to a byte vector.
    #[must_use]
    pub fn build(&self) -> Vec<u8> {
        let mut out = vec![];
        for (kind, body) in &self.records {
            // A conformant CodeView record is 4-aligned including its 2-byte
            // length prefix, and the padding is counted inside record_len.
            let pad = (4 - (4 + body.len()) % 4) % 4;
            let body_len: u16 = (body.len() + pad).try_into().unwrap_or(u16::MAX);
            let record_len = 2u16 + body_len;
            out.extend_from_slice(&record_len.to_le_bytes());
            out.extend_from_slice(&kind.to_le_bytes());
            out.extend_from_slice(body);
            out.extend(vec![0u8; pad]);
        }
        out
    }
}

impl Default for SymbolStreamBuilder {
    fn default() -> Self {
        Self::new()
    }
}

// ── CvInlineReport ────────────────────────────────────────────────────────────

/// Report of inlining across a module's functions.
#[derive(Debug, Clone, Default)]
pub struct CvInlineReport {
    pub total_functions: usize,
    pub functions_with_inlines: usize,
    pub total_inline_sites: usize,
    pub unique_inlinees: Vec<u32>,
    pub max_inline_depth: usize,
}

impl CvInlineReport {
    /// Compute from a function database.
    #[must_use]
    pub fn compute(db: &CvFunctionDb) -> Self {
        let mut rpt = Self {
            total_functions: db.count(),
            ..Self::default()
        };
        let mut all_inlinees: std::collections::HashSet<u32> = std::collections::HashSet::default();
        for rec in db.functions.values() {
            if !rec.inline_tree.is_empty() {
                rpt.functions_with_inlines += 1;
                rpt.total_inline_sites += rec.inline_tree.depth();
                rpt.max_inline_depth = rpt.max_inline_depth.max(rec.inline_tree.depth());
                for &id in &rec.inline_tree.unique_inlinees() {
                    all_inlinees.insert(id);
                }
            }
        }
        rpt.unique_inlinees = all_inlinees.into_iter().collect();
        rpt.unique_inlinees.sort_unstable();
        rpt
    }

    /// Percentage of functions that contain any inlined calls.
    #[must_use]
    pub fn inline_rate(&self) -> f64 {
        if self.total_functions == 0 {
            return 0.0;
        }
        let with_inlines: u32 = self.functions_with_inlines.try_into().unwrap_or(u32::MAX);
        let total: u32 = self.total_functions.try_into().unwrap_or(u32::MAX);
        f64::from(with_inlines) / f64::from(total) * 100.0
    }
}

impl fmt::Display for CvInlineReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "InlineReport: {}/{} fns ({:.1}%) have inlines, {} unique inlinees",
            self.functions_with_inlines,
            self.total_functions,
            self.inline_rate(),
            self.unique_inlinees.len()
        )
    }
}

// ── CvAddressMap ─────────────────────────────────────────────────────────────

/// Maps symbol offsets to RVAs given a section-offset table.
pub struct CvAddressMap {
    /// Section base RVAs indexed by 1-based segment number.
    section_bases: Vec<u64>,
}

impl CvAddressMap {
    /// Create with a list of section base RVAs (index 0 = section 1).
    #[must_use]
    pub const fn new(section_bases: Vec<u64>) -> Self {
        Self { section_bases }
    }

    /// Compute the RVA for a (segment, offset) pair.
    #[must_use]
    pub fn rva(&self, segment: u16, offset: u32) -> Option<u64> {
        let idx = usize::from(segment).checked_sub(1)?;
        let base = *self.section_bases.get(idx)?;
        Some(base + u64::from(offset))
    }

    /// Apply this map to all functions in a database, filling in their `rva` fields.
    pub fn apply_to_db(&self, db: &mut CvFunctionDb) {
        for rec in db.functions.values_mut() {
            if let Some(proc) = &mut rec.proc && let Some(rva) = self.rva(proc.segment, proc.offset) {
                proc.rva = rva;
            }
        }
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // --- Helpers to build binary records ---

    struct ProcBodyArgs<'a> {
        name: &'a str,
        offset: u32,
        seg: u16,
        len: u32,
        debug_start: u32,
        debug_end: u32,
        ti: u32,
        flags: u8,
    }

    fn make_proc_body(args: &ProcBodyArgs<'_>) -> Vec<u8> {
        let mut b = vec![];
        b.extend_from_slice(&0u32.to_le_bytes()); // parent
        b.extend_from_slice(&0u32.to_le_bytes()); // end
        b.extend_from_slice(&0u32.to_le_bytes()); // next
        b.extend_from_slice(&args.len.to_le_bytes());
        b.extend_from_slice(&args.debug_start.to_le_bytes());
        b.extend_from_slice(&args.debug_end.to_le_bytes());
        b.extend_from_slice(&args.ti.to_le_bytes());
        b.extend_from_slice(&args.offset.to_le_bytes());
        b.extend_from_slice(&args.seg.to_le_bytes());
        b.push(args.flags);
        b.extend_from_slice(args.name.as_bytes());
        b.push(0);
        b
    }

    fn make_proc(name: &str, offset: u32, seg: u16, len: u32, ti: u32, flags: u8) -> Vec<u8> {
        make_proc_body(&ProcBodyArgs { name, offset, seg, len, debug_start: 0, debug_end: len, ti, flags })
    }

    fn make_frame_body(frame_size: u32, flags: u32) -> Vec<u8> {
        let mut b = vec![];
        b.extend_from_slice(&frame_size.to_le_bytes()); // frame_size
        b.extend_from_slice(&0u32.to_le_bytes()); // pad_size
        b.extend_from_slice(&0u32.to_le_bytes()); // pad_offset
        b.extend_from_slice(&16u32.to_le_bytes()); // save_size
        b.extend_from_slice(&0u32.to_le_bytes()); // eh_offset
        b.extend_from_slice(&0u16.to_le_bytes()); // eh_section
        b.extend_from_slice(&flags.to_le_bytes()); // flags
        b
    }

    fn make_local_body(name: &str, ti: u32, flags: u16) -> Vec<u8> {
        let mut b = vec![];
        b.extend_from_slice(&ti.to_le_bytes());
        b.extend_from_slice(&flags.to_le_bytes());
        b.extend_from_slice(name.as_bytes());
        b.push(0);
        b
    }

    // --- CvFunctionInfo ---

    #[test]
    fn test_proc_parse_global() {
        let body = make_proc("main", 0x1000, 1, 128, 0x1050, 0);
        let proc = CvFunctionInfo::parse(&body, true).unwrap();
        assert_eq!(proc.name, "main");
        assert!(proc.is_global);
        assert_eq!(proc.offset, 0x1000);
        assert_eq!(proc.code_length, 128);
        assert_eq!(proc.segment, 1);
        assert_eq!(proc.type_index, 0x1050);
    }

    #[test]
    fn test_proc_parse_local() {
        let body = make_proc("helper", 0x2000, 1, 64, 0x2000, 0);
        let proc = CvFunctionInfo::parse(&body, false).unwrap();
        assert!(!proc.is_global);
        assert_eq!(proc.name, "helper");
    }

    #[test]
    fn test_proc_flags_noreturn() {
        let body = make_proc("abort", 0, 1, 4, 0, 0x02);
        let proc = CvFunctionInfo::parse(&body, true).unwrap();
        assert!(proc.is_noreturn());
    }

    #[test]
    fn test_proc_end_rva() {
        let body = make_proc("f", 0, 1, 256, 0, 0);
        let mut proc = CvFunctionInfo::parse(&body, true).unwrap();
        proc.rva = 0x1000;
        assert_eq!(proc.end_rva(), 0x1100);
    }

    #[test]
    fn test_proc_truncated() {
        assert!(CvFunctionInfo::parse(&[0u8; 10], true).is_err());
    }

    #[test]
    fn test_proc_display() {
        let body = make_proc("foo", 0x1000, 2, 50, 0, 0);
        let proc = CvFunctionInfo::parse(&body, true).unwrap();
        let s = proc.to_string();
        assert!(s.contains("foo"));
        assert!(s.contains("global"));
    }

    // --- CvFrameInfo ---

    #[test]
    fn test_frame_parse_basic() {
        let body = make_frame_body(64, 0);
        let fi = CvFrameInfo::parse(&body).unwrap();
        assert_eq!(fi.frame_size, 64);
        assert!(!fi.has_seh());
        assert!(!fi.has_eh());
    }

    #[test]
    fn test_frame_flags_seh() {
        let body = make_frame_body(64, 0x0001);
        let fi = CvFrameInfo::parse(&body).unwrap();
        assert!(fi.has_seh());
    }

    #[test]
    fn test_frame_flags_alloca() {
        let body = make_frame_body(128, 0x0004);
        let fi = CvFrameInfo::parse(&body).unwrap();
        assert!(fi.has_alloca());
    }

    #[test]
    fn test_frame_flags_security_check() {
        let body = make_frame_body(128, 0x0010);
        let fi = CvFrameInfo::parse(&body).unwrap();
        assert!(fi.has_security_checks());
    }

    #[test]
    fn test_frame_fpo() {
        let body = make_frame_body(0, 0x0100);
        let fi = CvFrameInfo::parse(&body).unwrap();
        assert!(fi.frame_pointer_omitted());
    }

    #[test]
    fn test_frame_truncated() {
        assert!(CvFrameInfo::parse(&[0u8; 10]).is_err());
    }

    // --- CvLocal ---

    #[test]
    fn test_local_parse_variable() {
        let body = make_local_body("count", 0x1050, 0x0000);
        let loc = CvLocal::parse(&body).unwrap();
        assert_eq!(loc.name, "count");
        assert!(!loc.is_param());
        assert_eq!(loc.type_index, 0x1050);
    }

    #[test]
    fn test_local_parse_param() {
        let body = make_local_body("argc", 0x0074, 0x0001);
        let loc = CvLocal::parse(&body).unwrap();
        assert!(loc.is_param());
        assert_eq!(loc.name, "argc");
    }

    #[test]
    fn test_local_address_taken() {
        let body = make_local_body("ptr", 0x74, 0x0002);
        let loc = CvLocal::parse(&body).unwrap();
        assert!(loc.is_address_taken());
    }

    #[test]
    fn test_local_compiler_generated() {
        let body = make_local_body("$T0", 0x74, 0x0004);
        let loc = CvLocal::parse(&body).unwrap();
        assert!(loc.is_compiler_generated());
    }

    #[test]
    fn test_local_truncated() {
        assert!(CvLocal::parse(&[0u8; 4]).is_err());
    }

    #[test]
    fn test_local_display() {
        let body = make_local_body("x", 0x74, 0);
        let loc = CvLocal::parse(&body).unwrap();
        let s = loc.to_string();
        assert!(s.contains('x'));
        assert!(s.contains("local"));
    }

    // --- CvInlinee ---

    #[test]
    fn test_inlinee_parse() {
        let mut data = vec![];
        data.extend_from_slice(&0x2000u32.to_le_bytes()); // inlinee
        data.extend_from_slice(&5u32.to_le_bytes()); // file_id
        data.extend_from_slice(&42u32.to_le_bytes()); // source_line
        let ci = CvInlinee::parse(&data).unwrap();
        assert_eq!(ci.inlinee, 0x2000);
        assert_eq!(ci.source_line, 42);
    }

    #[test]
    fn test_inlinee_truncated() {
        assert!(CvInlinee::parse(&[0u8; 8]).is_err());
    }

    // --- InlineTree ---

    #[test]
    fn test_inline_tree_empty() {
        let t = InlineTree::new();
        assert!(t.is_empty());
        assert_eq!(t.depth(), 0);
    }

    #[test]
    fn test_inline_tree_add_site() {
        let mut t = InlineTree::new();
        t.add_site(InlineSite {
            inlinee_id: 100,
            invocation_count: 1,
            binary_annotations: vec![],
        });
        assert_eq!(t.depth(), 1);
    }

    #[test]
    fn test_inline_tree_unique_inlinees() {
        let mut t = InlineTree::new();
        t.add_site(InlineSite {
            inlinee_id: 10,
            invocation_count: 2,
            binary_annotations: vec![],
        });
        t.add_site(InlineSite {
            inlinee_id: 10,
            invocation_count: 1,
            binary_annotations: vec![],
        });
        t.add_site(InlineSite {
            inlinee_id: 20,
            invocation_count: 1,
            binary_annotations: vec![],
        });
        let ids = t.unique_inlinees();
        assert_eq!(ids, vec![10, 20]);
    }

    // --- CvFunctionDb ---

    #[test]
    fn test_db_insert_and_get() {
        let mut db = CvFunctionDb::new();
        let body = make_proc("main", 0, 1, 100, 0, 0);
        let proc = CvFunctionInfo::parse(&body, true).unwrap();
        db.insert_proc(0x100, proc);
        assert_eq!(db.count(), 1);
        assert!(db.get(0x100).is_some());
    }

    #[test]
    fn test_db_attach_frame() {
        let mut db = CvFunctionDb::new();
        let body = make_proc("f", 0, 1, 10, 0, 0);
        let proc = CvFunctionInfo::parse(&body, true).unwrap();
        db.insert_proc(1, proc);
        let fb = make_frame_body(32, 0);
        let frame = CvFrameInfo::parse(&fb).unwrap();
        db.attach_frame(1, frame);
        let rec = db.get(1).unwrap();
        assert!(rec.has_frame_info());
        assert_eq!(rec.frame.as_ref().unwrap().frame_size, 32);
    }

    #[test]
    fn test_db_attach_locals() {
        let mut db = CvFunctionDb::new();
        db.insert_proc(
            10,
            CvFunctionInfo {
                name: "test".to_string(),
                is_global: true,
                offset: 0,
                segment: 1,
                code_length: 4,
                debug_start: 0,
                debug_end: 4,
                type_index: 0,
                flags: 0,
                rva: 0,
            },
        );
        let lb = make_local_body("a", 0x74, 0x01); // param
        db.attach_local(10, CvLocal::parse(&lb).unwrap());
        let lb2 = make_local_body("b", 0x74, 0x00); // local
        db.attach_local(10, CvLocal::parse(&lb2).unwrap());
        let rec = db.get(10).unwrap();
        assert_eq!(rec.locals.len(), 2);
        assert_eq!(rec.params().len(), 1);
        assert_eq!(rec.variables().len(), 1);
    }

    // --- CvFunctionRecord ---

    #[test]
    fn test_record_no_frame_info() {
        let rec = CvFunctionRecord::default();
        assert!(!rec.has_frame_info());
    }

    // --- CvFuncError ---

    #[test]
    fn test_error_display_truncated() {
        let e = CvFuncError::Truncated {
            offset: 5,
            needed: 10,
        };
        assert!(e.to_string().contains("truncated"));
    }

    #[test]
    fn test_error_display_unknown() {
        let e = CvFuncError::UnknownRecord(0x1234);
        assert!(e.to_string().contains("0x1234"));
    }

    // --- Additional CvFunctionInfo tests ---

    #[test]
    fn test_proc_not_inlined_by_default() {
        let body = make_proc("foo", 0, 1, 10, 0, 0);
        let proc = CvFunctionInfo::parse(&body, true).unwrap();
        assert!(!proc.is_inlined());
    }

    #[test]
    fn test_proc_rva_zero_default() {
        let body = make_proc("f", 0, 1, 10, 0, 0);
        let proc = CvFunctionInfo::parse(&body, true).unwrap();
        assert_eq!(proc.rva, 0);
    }

    #[test]
    fn test_proc_local_no_inlined_flag() {
        let body = make_proc("local_fn", 0, 1, 10, 0, 0);
        let proc = CvFunctionInfo::parse(&body, false).unwrap();
        assert!(!proc.is_noreturn());
        assert!(!proc.is_inlined());
    }

    // --- Additional CvFrameInfo tests ---

    #[test]
    fn test_frame_has_eh() {
        let body = make_frame_body(32, 0x0002);
        let fi = CvFrameInfo::parse(&body).unwrap();
        assert!(fi.has_eh());
    }

    #[test]
    fn test_frame_inline_asm() {
        let body = make_frame_body(0, 0x0008);
        let fi = CvFrameInfo::parse(&body).unwrap();
        assert!(fi.has_inline_asm());
    }

    #[test]
    fn test_frame_no_flags() {
        let body = make_frame_body(128, 0);
        let fi = CvFrameInfo::parse(&body).unwrap();
        assert!(!fi.has_seh());
        assert!(!fi.has_eh());
        assert!(!fi.has_alloca());
        assert!(!fi.frame_pointer_omitted());
    }

    // --- Additional CvLocal tests ---

    #[test]
    fn test_local_not_enreg() {
        let body = make_local_body("x", 0x74, 0);
        let loc = CvLocal::parse(&body).unwrap();
        assert!(!loc.is_enreg());
    }

    #[test]
    fn test_local_enreg_flag() {
        let body = make_local_body("r", 0x74, 0x0010);
        let loc = CvLocal::parse(&body).unwrap();
        assert!(loc.is_enreg());
    }

    // --- InlineTree additional tests ---

    #[test]
    fn test_inline_tree_multiple_sites() {
        let mut t = InlineTree::new();
        for id in [10u32, 20, 30, 10, 20] {
            t.add_site(InlineSite {
                inlinee_id: id,
                invocation_count: 1,
                binary_annotations: vec![],
            });
        }
        assert_eq!(t.depth(), 5);
        let uniq = t.unique_inlinees();
        assert_eq!(uniq, vec![10, 20, 30]);
    }

    // --- CvFunctionDb::parse_symbol_stream ---

    fn make_symbol_stream(records: &[(u16, Vec<u8>)]) -> Vec<u8> {
        let mut out = vec![];
        for (kind, body) in records {
            // A conformant record is 4-aligned including its 2-byte length
            // prefix, and counts its padding inside record_len.
            let pad = (4 - (4 + body.len()) % 4) % 4;
            let body_u16: u16 = (body.len() + pad).try_into().unwrap_or(u16::MAX);
            let record_len = 2u16 + body_u16;
            out.extend_from_slice(&record_len.to_le_bytes());
            out.extend_from_slice(&kind.to_le_bytes());
            out.extend_from_slice(body);
            out.extend(vec![0u8; pad]);
        }
        out
    }

    #[test]
    fn test_parse_symbol_stream_empty() {
        let mut db = CvFunctionDb::new();
        db.parse_symbol_stream(&[]).unwrap();
        assert_eq!(db.count(), 0);
    }

    #[test]
    fn test_parse_symbol_stream_gproc32() {
        let body = make_proc_body(&ProcBodyArgs { name: "exported_fn", offset: 0x1000, seg: 1, len: 200, debug_start: 4, debug_end: 196, ti: 0x1080, flags: 0 });
        let stream = make_symbol_stream(&[(symkind::S_GPROC32, body)]);
        let mut db = CvFunctionDb::new();
        db.parse_symbol_stream(&stream).unwrap();
        assert_eq!(db.count(), 1);
    }

    #[test]
    fn test_parse_symbol_stream_with_frameproc() {
        let pb = make_proc("f", 0, 1, 100, 0, 0);
        let fb = make_frame_body(64, 0);
        let stream = make_symbol_stream(&[(symkind::S_GPROC32, pb), (symkind::S_FRAMEPROC, fb)]);
        let mut db = CvFunctionDb::new();
        db.parse_symbol_stream(&stream).unwrap();
        // There should be one function with frame info
        let values: Vec<_> = db.functions.values().collect();
        assert_eq!(values.len(), 1);
        assert!(values[0].has_frame_info());
    }

    // --- CvFunctionCallSite tests ---

    #[test]
    fn test_callsite_parse() {
        let mut b = vec![];
        b.extend_from_slice(&0x100u32.to_le_bytes()); // offset
        b.extend_from_slice(&1u16.to_le_bytes()); // segment
        b.extend_from_slice(&0u16.to_le_bytes()); // pad
        b.extend_from_slice(&0x1080u32.to_le_bytes()); // type_index
        let cs = CvFunctionCallSite::parse(&b).unwrap();
        assert_eq!(cs.offset, 0x100);
        assert_eq!(cs.segment, 1);
        assert_eq!(cs.type_index, 0x1080);
    }

    #[test]
    fn test_callsite_truncated() {
        assert!(CvFunctionCallSite::parse(&[0u8; 4]).is_err());
    }

    // --- CvScopeBlock tests ---

    #[test]
    fn test_scope_block_parse() {
        let mut b = vec![];
        b.extend_from_slice(&0u32.to_le_bytes()); // parent
        b.extend_from_slice(&0u32.to_le_bytes()); // end
        b.extend_from_slice(&64u32.to_le_bytes()); // code_length
        b.extend_from_slice(&0x1000u32.to_le_bytes()); // offset
        b.extend_from_slice(&1u16.to_le_bytes()); // segment
        b.extend_from_slice(b"block1\0");
        let sb = CvScopeBlock::parse(&b).unwrap();
        assert_eq!(sb.code_length, 64);
        assert_eq!(sb.name, "block1");
    }

    // --- CvFunctionCallGraph tests ---

    #[test]
    fn test_callgraph_new_empty() {
        let cg = CvFunctionCallGraph::new();
        assert_eq!(cg.node_count(), 0);
    }

    #[test]
    fn test_callgraph_add_and_degree() {
        let mut cg = CvFunctionCallGraph::new();
        cg.add_call(0x100, 0x1080);
        cg.add_call(0x100, 0x2000);
        assert_eq!(cg.out_degree(0x100), 2);
        assert!(!cg.is_leaf(0x100));
    }

    #[test]
    fn test_callgraph_leaf() {
        let cg = CvFunctionCallGraph::new();
        assert!(cg.is_leaf(0x999));
    }

    // --- CvAddressMap tests ---

    #[test]
    fn test_address_map_rva() {
        let map = CvAddressMap::new(vec![0x1000, 0x5000]);
        assert_eq!(map.rva(1, 0x10), Some(0x1010));
        assert_eq!(map.rva(2, 0x20), Some(0x5020));
    }

    #[test]
    fn test_address_map_invalid_segment() {
        let map = CvAddressMap::new(vec![0x1000]);
        assert_eq!(map.rva(0, 0), None); // segment 0 is invalid
        assert_eq!(map.rva(99, 0), None);
    }

    #[test]
    fn test_address_map_apply_to_db() {
        let pb = make_proc("f", 0x10, 1, 100, 0, 0);
        let mut db = CvFunctionDb::new();
        let proc = CvFunctionInfo::parse(&pb, true).unwrap();
        db.insert_proc(1, proc);
        let map = CvAddressMap::new(vec![0x2000]);
        map.apply_to_db(&mut db);
        let rec = db.get(1).unwrap();
        assert_eq!(rec.proc.as_ref().unwrap().rva, 0x2010);
    }

    // --- CvInlineReport tests ---

    #[test]
    fn test_inline_report_empty_db() {
        let db = CvFunctionDb::new();
        let r = CvInlineReport::compute(&db);
        assert_eq!(r.total_functions, 0);
        assert!(r.inline_rate().abs() < f64::EPSILON);
    }

    #[test]
    fn test_inline_report_display() {
        let db = CvFunctionDb::new();
        let r = CvInlineReport::compute(&db);
        let s = r.to_string();
        assert!(s.contains("0/0"));
    }

    // --- CvFunctionStats tests ---

    #[test]
    fn test_stats_empty_db() {
        let db = CvFunctionDb::new();
        let s = CvFunctionStats::compute(&db);
        assert_eq!(s.total_functions, 0);
        assert!(s.mean_locals().abs() < f64::EPSILON);
    }

    #[test]
    fn test_stats_display() {
        let db = CvFunctionDb::new();
        let s = CvFunctionStats::compute(&db);
        let ds = s.to_string();
        assert!(ds.contains("CvFunctionStats"));
    }

    // --- FunctionCoverage tests ---

    #[test]
    fn test_coverage_basic() {
        let mut cov = FunctionCoverage::new(10);
        cov.visit(1);
        cov.visit(2);
        assert_eq!(cov.visited_count(), 2);
        assert_eq!(cov.total_count(), 10);
        assert!((cov.percent() - 20.0).abs() < 0.1);
    }

    #[test]
    fn test_coverage_visited() {
        let mut cov = FunctionCoverage::new(5);
        cov.visit(3);
        assert!(cov.is_visited(3));
        assert!(!cov.is_visited(4));
    }

    #[test]
    fn test_coverage_zero_total() {
        let cov = FunctionCoverage::new(0);
        assert!((cov.percent() - 100.0).abs() < f64::EPSILON);
    }
}
