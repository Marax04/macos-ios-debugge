//! Hex-editor-integrated disassembler view.
//!
//! Provides [`HexDisassembler`] which pairs raw hex bytes with human-readable
//! disassembly, [`DisasmView`] for the combined rendering model,
//! [`OffsetFormatter`] for various offset display styles, [`RelativeOffset`]
//! for branch-target annotations, [`JumpArrow`] for visualising control flow
//! inside the listing, [`DisasmAnnotation`] for free-text notes, and
//! [`SyncScroll`] for keeping the hex and disasm panels in lock-step.

use std::collections::HashMap;
use std::fmt;
use std::ops::Range;

use serde::{Deserialize, Serialize};
use thiserror::Error;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors produced by the hex-disassembler module.
#[derive(Debug, Error)]
pub enum DisasmError {
    #[error("offset 0x{0:x} is out of range (buffer length 0x{1:x})")]
    OutOfRange(u64, u64),
    #[error("invalid instruction at offset 0x{0:x}")]
    InvalidInstruction(u64),
    #[error("overlapping region: 0x{0:x}..0x{1:x} conflicts with 0x{2:x}..0x{3:x}")]
    OverlappingRegion(u64, u64, u64, u64),
    #[error("annotation id {0} not found")]
    AnnotationNotFound(u64),
    #[error("jump arrow id {0} not found")]
    ArrowNotFound(u64),
    #[error("sync scroll: column mismatch – hex has {0} bytes per row, disasm has {1}")]
    ColumnMismatch(usize, usize),
    #[error("formatter error: {0}")]
    Formatter(String),
}

pub type DisasmResult<T> = Result<T, DisasmError>;

// ---------------------------------------------------------------------------
// OffsetStyle / OffsetFormatter
// ---------------------------------------------------------------------------

/// How raw byte offsets are presented in the listing gutter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[derive(Default)]
pub enum OffsetStyle {
    /// Plain hexadecimal: `0x00401000`
    #[default]
    Hex,
    /// Decimal integer: `4198400`
    Decimal,
    /// Segment:Offset pair (16-bit style): `0040:1000`
    SegmentOffset,
    /// Relative to a chosen base address: `+0x1000`
    RelativeToBase,
    /// Symbol + displacement: `main+0x10`
    SymbolPlusDisp,
}


/// Formats a file/virtual address according to a chosen [`OffsetStyle`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OffsetFormatter {
    style: OffsetStyle,
    /// Base address subtracted when `style == RelativeToBase`.
    base: u64,
    /// Width (number of hex digits) for zero-padded hex output.
    hex_width: usize,
    /// Symbol table: address → name (used for `SymbolPlusDisp`).
    symbols: HashMap<u64, String>,
}

impl OffsetFormatter {
    /// Create a new formatter with sensible defaults.
    #[must_use]
    pub fn new(style: OffsetStyle) -> Self {
        Self {
            style,
            base: 0,
            hex_width: 8,
            symbols: HashMap::new(),
        }
    }

    /// Set the base address for relative formatting.
    #[must_use] 
    pub const fn with_base(mut self, base: u64) -> Self {
        self.base = base;
        self
    }

    /// Set the zero-padding width for hexadecimal output.
    #[must_use] 
    pub const fn with_hex_width(mut self, width: usize) -> Self {
        self.hex_width = width;
        self
    }

    /// Register a symbol so `SymbolPlusDisp` can resolve it.
    pub fn add_symbol(&mut self, addr: u64, name: impl Into<String>) {
        self.symbols.insert(addr, name.into());
    }

    /// Format `addr` according to the current style.
    #[must_use] 
    pub fn format(&self, addr: u64) -> String {
        match self.style {
            OffsetStyle::Hex => {
                format!("0x{:0>width$X}", addr, width = self.hex_width)
            }
            OffsetStyle::Decimal => format!("{addr}"),
            OffsetStyle::SegmentOffset => {
                let seg = (addr >> 16) & 0xFFFF;
                let off = addr & 0xFFFF;
                format!("{seg:04X}:{off:04X}")
            }
            OffsetStyle::RelativeToBase => {
                let rel = addr.wrapping_sub(self.base);
                format!("+0x{rel:X}")
            }
            OffsetStyle::SymbolPlusDisp => {
                // Find the nearest symbol ≤ addr.
                let mut best: Option<(u64, &str)> = None;
                for (&sym_addr, name) in &self.symbols {
                    if sym_addr <= addr
                        && best.is_none_or(|(ba, _)| sym_addr > ba) {
                            best = Some((sym_addr, name.as_str()));
                        }
                }
                match best {
                    Some((sym_addr, name)) if sym_addr == addr => name.to_string(),
                    Some((sym_addr, name)) => {
                        format!("{}+0x{:X}", name, addr - sym_addr)
                    }
                    None => format!("0x{addr:X}"),
                }
            }
        }
    }
}

impl Default for OffsetFormatter {
    fn default() -> Self {
        Self::new(OffsetStyle::Hex)
    }
}

// ---------------------------------------------------------------------------
// RelativeOffset
// ---------------------------------------------------------------------------

/// Represents the target of a branch instruction relative to the current PC.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelativeOffset {
    /// Absolute address of the branch instruction (source).
    pub source: u64,
    /// Absolute address of the branch target.
    pub target: u64,
    /// True if this is an unconditional jump.
    pub unconditional: bool,
}

impl RelativeOffset {
    /// Compute the signed displacement (target − (source + `insn_size`)).
    #[must_use]
    pub const fn signed_displacement(&self, insn_size: u64) -> i64 {
        self.target.wrapping_sub(self.source + insn_size).cast_signed()
    }

    /// True when the branch goes backwards (loop / tail-call pattern).
    #[must_use]
    pub const fn is_backward(&self) -> bool {
        self.target < self.source
    }

    /// True when the branch goes forward.
    #[must_use]
    pub const fn is_forward(&self) -> bool {
        self.target > self.source
    }
}

// ---------------------------------------------------------------------------
// JumpArrow
// ---------------------------------------------------------------------------

/// Visual arrow connecting a branch source to its target in the listing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JumpArrow {
    /// Unique identifier (row index in the listing).
    pub id: u64,
    pub source: u64,
    pub target: u64,
    /// Nesting depth (for non-overlapping arrow columns).
    pub depth: u8,
    /// Whether this is a conditional branch.
    pub conditional: bool,
    /// Optional colour hint (RGBA).
    pub color: Option<[u8; 4]>,
}

impl JumpArrow {
    /// Create a new jump arrow.
    #[must_use]
    pub const fn new(id: u64, source: u64, target: u64) -> Self {
        Self {
            id,
            source,
            target,
            depth: 0,
            conditional: false,
            color: None,
        }
    }

    /// Mark this arrow as conditional.
    #[must_use] 
    pub const fn conditional(mut self) -> Self {
        self.conditional = true;
        self
    }

    /// Assign a nesting depth.
    #[must_use] 
    pub const fn at_depth(mut self, depth: u8) -> Self {
        self.depth = depth;
        self
    }

    /// Assign an RGBA colour.
    #[must_use] 
    pub const fn with_color(mut self, rgba: [u8; 4]) -> Self {
        self.color = Some(rgba);
        self
    }

    /// Return the vertical span (in listing rows) of this arrow.
    #[must_use] 
    pub fn row_span(&self, row_height: u64) -> u64 {
        let lo = self.source.min(self.target);
        let hi = self.source.max(self.target);
        (hi - lo).saturating_div(row_height).max(1)
    }
}

// ---------------------------------------------------------------------------
// DisasmAnnotation
// ---------------------------------------------------------------------------

/// A free-text note attached to a specific offset in the listing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisasmAnnotation {
    /// Unique annotation id.
    pub id: u64,
    /// The byte offset (file or virtual) this annotation is attached to.
    pub offset: u64,
    /// Short label shown inline.
    pub label: String,
    /// Longer description shown in a tooltip / side-panel.
    pub description: String,
    /// Optional tag for categorisation (e.g. "vuln", "crypto", "api").
    pub tag: Option<String>,
    /// Timestamp (Unix seconds) when this annotation was created.
    pub created_at: u64,
}

impl DisasmAnnotation {
    /// Create a minimal annotation.
    #[must_use]
    pub fn new(id: u64, offset: u64, label: impl Into<String>) -> Self {
        Self {
            id,
            offset,
            label: label.into(),
            description: String::new(),
            tag: None,
            created_at: 0,
        }
    }

    /// Attach a description.
    #[must_use]
    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = desc.into();
        self
    }

    /// Attach a tag.
    #[must_use]
    pub fn with_tag(mut self, tag: impl Into<String>) -> Self {
        self.tag = Some(tag.into());
        self
    }
}

// ---------------------------------------------------------------------------
// Instruction / DisasmLine
// ---------------------------------------------------------------------------

/// A single disassembled instruction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Instruction {
    /// Virtual / file offset of the first byte.
    pub offset: u64,
    /// Raw bytes.
    pub bytes: Vec<u8>,
    /// Mnemonic string (e.g. `"MOV"`).
    pub mnemonic: String,
    /// Operand string (e.g. `"RAX, [RBX+8]"`).
    pub operands: String,
    /// Optional comment appended after a `;`.
    pub comment: Option<String>,
    /// If this instruction is a branch, the resolved target.
    pub branch_target: Option<u64>,
}

impl Instruction {
    /// Full size of this instruction in bytes.
    #[must_use]
    pub const fn size(&self) -> usize {
        self.bytes.len()
    }

    /// Full disassembly string: `mnemonic  operands`.
    #[must_use] 
    pub fn display(&self) -> String {
        if self.operands.is_empty() {
            self.mnemonic.clone()
        } else {
            format!("{:<8} {}", self.mnemonic, self.operands)
        }
    }
}

/// One row in the combined hex+disassembly listing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisasmLine {
    /// The instruction for this row.
    pub instruction: Instruction,
    /// Hex bytes formatted as a space-separated string (e.g. `"48 89 C0"`).
    pub hex_bytes: String,
    /// Annotations attached to this offset.
    pub annotations: Vec<DisasmAnnotation>,
    /// Jump arrows that start or end at this row.
    pub arrows: Vec<u64>,
}

impl DisasmLine {
    /// Build a `DisasmLine` from an `Instruction`.
    #[must_use]
    pub fn from_instruction(insn: Instruction) -> Self {
        let hex_bytes = insn
            .bytes
            .iter()
            .map(|b| format!("{b:02X}"))
            .collect::<Vec<_>>()
            .join(" ");
        Self {
            instruction: insn,
            hex_bytes,
            annotations: Vec::new(),
            arrows: Vec::new(),
        }
    }

    /// Add an annotation to this line.
    pub fn push_annotation(&mut self, ann: DisasmAnnotation) {
        self.annotations.push(ann);
    }
}

// ---------------------------------------------------------------------------
// DisasmView
// ---------------------------------------------------------------------------

/// The combined hex + disassembly view model.
///
/// `DisasmView` holds an ordered list of [`DisasmLine`]s and the metadata
/// (formatter, arrows, annotations) needed to render them.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisasmView {
    /// Ordered listing rows.
    lines: Vec<DisasmLine>,
    /// Offset → line index for O(1) lookup.
    offset_index: HashMap<u64, usize>,
    /// Jump arrows keyed by their id.
    arrows: HashMap<u64, JumpArrow>,
    /// Global annotations keyed by id.
    annotations: HashMap<u64, DisasmAnnotation>,
    /// The formatter used to render offset gutters.
    pub formatter: OffsetFormatter,
    /// Bytes per row when showing hex alongside disassembly.
    pub bytes_per_row: usize,
}

impl DisasmView {
    /// Create an empty view.
    #[must_use]
    pub fn new(formatter: OffsetFormatter) -> Self {
        Self {
            lines: Vec::new(),
            offset_index: HashMap::new(),
            arrows: HashMap::new(),
            annotations: HashMap::new(),
            formatter,
            bytes_per_row: 16,
        }
    }

    /// Append a pre-built [`DisasmLine`].
    pub fn push_line(&mut self, line: DisasmLine) {
        let idx = self.lines.len();
        self.offset_index.insert(line.instruction.offset, idx);
        self.lines.push(line);
    }

    /// Return an immutable slice of all lines.
    #[must_use]
    pub fn lines(&self) -> &[DisasmLine] {
        &self.lines
    }

    /// Look up a line by offset.
    #[must_use]
    pub fn line_at(&self, offset: u64) -> Option<&DisasmLine> {
        self.offset_index.get(&offset).map(|&i| &self.lines[i])
    }

    /// Add a jump arrow to the view, updating the source/target line references.
    ///
    /// # Errors
    ///
    /// Currently infallible; reserved for future validation.
    pub fn add_arrow(&mut self, arrow: JumpArrow) -> DisasmResult<()> {
        let id = arrow.id;
        let src = arrow.source;
        let tgt = arrow.target;
        self.arrows.insert(id, arrow);
        if let Some(&si) = self.offset_index.get(&src) {
            self.lines[si].arrows.push(id);
        }
        if let Some(&ti) = self.offset_index.get(&tgt)
            && ti != *self.offset_index.get(&src).unwrap_or(&usize::MAX) {
                self.lines[ti].arrows.push(id);
            }
        Ok(())
    }

    /// Remove a jump arrow by id.
    ///
    /// # Errors
    ///
    /// Returns [`DisasmError::ArrowNotFound`] if no arrow with the given `id` exists.
    pub fn remove_arrow(&mut self, id: u64) -> DisasmResult<JumpArrow> {
        let arrow = self.arrows.remove(&id).ok_or(DisasmError::ArrowNotFound(id))?;
        for line in &mut self.lines {
            line.arrows.retain(|&a| a != id);
        }
        Ok(arrow)
    }

    /// Add an annotation, attaching it to the appropriate line.
    ///
    /// # Errors
    ///
    /// Currently infallible; reserved for future validation.
    pub fn add_annotation(&mut self, ann: DisasmAnnotation) -> DisasmResult<()> {
        let offset = ann.offset;
        let id = ann.id;
        self.annotations.insert(id, ann.clone());
        if let Some(&li) = self.offset_index.get(&offset) {
            self.lines[li].push_annotation(ann);
        }
        Ok(())
    }

    /// Remove an annotation by id.
    ///
    /// # Errors
    ///
    /// Returns [`DisasmError::AnnotationNotFound`] if no annotation with the given `id` exists.
    pub fn remove_annotation(&mut self, id: u64) -> DisasmResult<DisasmAnnotation> {
        let ann = self
            .annotations
            .remove(&id)
            .ok_or(DisasmError::AnnotationNotFound(id))?;
        for line in &mut self.lines {
            line.annotations.retain(|a| a.id != id);
        }
        Ok(ann)
    }

    /// Return all lines in the given virtual-address range.
    #[must_use] 
    pub fn lines_in_range(&self, range: Range<u64>) -> Vec<&DisasmLine> {
        self.lines
            .iter()
            .filter(|l| range.contains(&l.instruction.offset))
            .collect()
    }

    /// Total bytes covered by all instructions in the view.
    #[must_use]
    pub fn total_bytes(&self) -> usize {
        self.lines.iter().map(|l| l.instruction.size()).sum()
    }

    /// Number of lines in the view.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.lines.len()
    }

    /// True when there are no lines.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.lines.is_empty()
    }
}

// ---------------------------------------------------------------------------
// SyncScroll
// ---------------------------------------------------------------------------

/// Keeps a hex panel and a disasm panel scrolled to the same byte offset.
///
/// The hex panel shows `bytes_per_row` bytes per row; the disasm panel shows
/// one instruction per row (variable byte count). `SyncScroll` translates
/// between row indices in each panel so that both panels display the same
/// approximate position.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncScroll {
    /// How many bytes are shown per row in the hex panel.
    pub bytes_per_row: usize,
    /// Cumulative byte offsets per disasm row (one entry per instruction).
    disasm_row_offsets: Vec<u64>,
    /// Current scroll position expressed as a byte offset.
    current_offset: u64,
}

impl SyncScroll {
    /// Create a new `SyncScroll` with the given hex row width and a flat list
    /// of instruction offsets from the disasm view.
    ///
    /// # Errors
    ///
    /// Returns [`DisasmError::ColumnMismatch`] if `bytes_per_row` is zero.
    pub fn new(bytes_per_row: usize, disasm_offsets: Vec<u64>) -> DisasmResult<Self> {
        if bytes_per_row == 0 {
            return Err(DisasmError::ColumnMismatch(0, disasm_offsets.len()));
        }
        Ok(Self {
            bytes_per_row,
            disasm_row_offsets: disasm_offsets,
            current_offset: 0,
        })
    }

    /// Scroll so that `offset` is at the top of both panels.
    pub const fn scroll_to_offset(&mut self, offset: u64) {
        self.current_offset = offset;
    }

    /// Return the current byte offset (shared scroll position).
    #[must_use]
    pub const fn current_offset(&self) -> u64 {
        self.current_offset
    }

    /// Translate the byte offset to a hex panel row index.
    #[must_use]
    pub fn hex_row(&self) -> usize {
        usize::try_from(self.current_offset).unwrap_or(usize::MAX) / self.bytes_per_row
    }

    /// Translate the byte offset to a disasm panel row index.
    /// Returns the index of the first instruction whose offset ≥ `current_offset`.
    #[must_use]
    pub fn disasm_row(&self) -> usize {
        match self
            .disasm_row_offsets
            .binary_search(&self.current_offset)
        {
            Ok(i) => i,
            Err(i) => i.saturating_sub(1),
        }
    }

    /// Step forward by `n` hex rows.
    pub fn scroll_hex_rows(&mut self, n: i64) {
        let bytes = n * i64::try_from(self.bytes_per_row).unwrap_or(i64::MAX);
        self.current_offset = self.current_offset.saturating_add_signed(bytes);
    }

    /// Step forward by `n` disasm rows.
    pub fn scroll_disasm_rows(&mut self, n: i64) {
        let row = i64::try_from(self.disasm_row()).unwrap_or(i64::MAX).saturating_add(n);
        let row = usize::try_from(row.max(0)).unwrap_or(0);
        if let Some(&off) = self.disasm_row_offsets.get(row) {
            self.current_offset = off;
        }
    }

    /// Return a `(hex_row, disasm_row)` pair for the current position.
    #[must_use]
    pub fn rows(&self) -> (usize, usize) {
        (self.hex_row(), self.disasm_row())
    }
}

// ---------------------------------------------------------------------------
// HexDisassembler
// ---------------------------------------------------------------------------

/// High-level disassembler that operates on a raw byte slice and produces a
/// [`DisasmView`].
///
/// In production this would delegate to a real disassembly engine (e.g. a
/// Capstone wrapper). Here we provide the full structural scaffolding with a
/// simple stub decoder so all the surrounding machinery is fully exercisable.
#[derive(Debug, Clone)]
pub struct HexDisassembler {
    /// Virtual base address of the first byte in the buffer.
    pub base_address: u64,
    /// Maximum number of bytes to disassemble in one call (0 = unlimited).
    pub max_bytes: usize,
    /// Offset formatter used when building the view.
    pub formatter: OffsetFormatter,
    /// Next arrow/annotation id (auto-incremented).
    next_id: u64,
}

impl HexDisassembler {
    /// Create a new disassembler with a given base address.
    #[must_use]
    pub fn new(base_address: u64) -> Self {
        Self {
            base_address,
            max_bytes: 0,
            formatter: OffsetFormatter::new(OffsetStyle::Hex),
            next_id: 1,
        }
    }

    /// Set the maximum bytes to decode per call.
    #[must_use] 
    pub const fn with_max_bytes(mut self, n: usize) -> Self {
        self.max_bytes = n;
        self
    }

    /// Disassemble `bytes` starting at `self.base_address` and return a
    /// fully populated [`DisasmView`].
    ///
    /// This stub treats every byte as a 1-byte NOP so that the surrounding
    /// infrastructure (arrows, annotations, sync-scroll) can be tested without
    /// a real ISA decoder.
    ///
    /// # Errors
    ///
    /// Currently infallible; reserved for future ISA-decoder errors.
    pub fn disassemble(&mut self, bytes: &[u8]) -> DisasmResult<DisasmView> {
        let limit = if self.max_bytes == 0 {
            bytes.len()
        } else {
            bytes.len().min(self.max_bytes)
        };
        let mut view = DisasmView::new(self.formatter.clone());
        view.lines.reserve(limit);
        view.offset_index.reserve(limit);
        let mut pos = 0usize;
        while pos < limit {
            let offset = self.base_address + u64::try_from(pos).unwrap_or(u64::MAX);
            let byte = bytes[pos];
            let insn = Self::stub_decode(offset, byte);
            let line = DisasmLine::from_instruction(insn);
            view.push_line(line);
            pos += 1;
        }
        Ok(view)
    }

    /// Disassemble a range of bytes within a larger buffer.
    ///
    /// # Errors
    ///
    /// Returns [`DisasmError::OutOfRange`] if `range` is out of bounds or inverted.
    pub fn disassemble_range(
        &mut self,
        bytes: &[u8],
        range: Range<usize>,
    ) -> DisasmResult<DisasmView> {
        let len = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        if range.start > range.end || range.end > bytes.len() {
            return Err(DisasmError::OutOfRange(
                u64::try_from(range.end).unwrap_or(u64::MAX),
                len,
            ));
        }
        let saved_base = self.base_address;
        self.base_address += u64::try_from(range.start).unwrap_or(u64::MAX);
        let result = self.disassemble(&bytes[range]);
        self.base_address = saved_base;
        result
    }

    /// Add a jump arrow to a view, auto-assigning an id.
    ///
    /// # Errors
    ///
    /// Propagates errors from [`DisasmView::add_arrow`].
    pub fn add_jump_arrow(
        &mut self,
        view: &mut DisasmView,
        source: u64,
        target: u64,
        conditional: bool,
    ) -> DisasmResult<u64> {
        let id = self.next_id;
        self.next_id += 1;
        let depth = Self::compute_arrow_depth(view, source, target);
        let mut arrow = JumpArrow::new(id, source, target).at_depth(depth);
        if conditional {
            arrow = arrow.conditional();
        }
        view.add_arrow(arrow)?;
        Ok(id)
    }

    /// Add a free-text annotation, auto-assigning an id.
    ///
    /// # Errors
    ///
    /// Propagates errors from [`DisasmView::add_annotation`].
    pub fn annotate(
        &mut self,
        view: &mut DisasmView,
        offset: u64,
        label: impl Into<String>,
        description: impl Into<String>,
    ) -> DisasmResult<u64> {
        let id = self.next_id;
        self.next_id += 1;
        let ann = DisasmAnnotation::new(id, offset, label)
            .with_description(description);
        view.add_annotation(ann)?;
        Ok(id)
    }

    /// Build a [`SyncScroll`] from a completed `DisasmView`.
    ///
    /// # Errors
    ///
    /// Returns [`DisasmError::ColumnMismatch`] if `bytes_per_row` is zero.
    pub fn build_sync_scroll(
        &self,
        view: &DisasmView,
        bytes_per_row: usize,
    ) -> DisasmResult<SyncScroll> {
        let offsets: Vec<u64> = view
            .lines()
            .iter()
            .map(|l| l.instruction.offset)
            .collect();
        SyncScroll::new(bytes_per_row, offsets)
    }

    // -----------------------------------------------------------------------
    // Private helpers
    // -----------------------------------------------------------------------

    fn stub_decode(offset: u64, byte: u8) -> Instruction {
        let (mnemonic, operands, branch_target) = match byte {
            0x00 | 0x90 => ("NOP", String::new(), None),
            0xCC => ("INT3", String::new(), None),
            0xEB => {
                // Short unconditional jump (displacement follows, but we only
                // have one byte here — produce a stub).
                let target = offset.wrapping_add(2);
                ("JMP", format!("0x{target:X}"), Some(target))
            }
            0x74 => {
                let target = offset.wrapping_add(2);
                ("JZ", format!("0x{target:X}"), Some(target))
            }
            0x75 => {
                let target = offset.wrapping_add(2);
                ("JNZ", format!("0x{target:X}"), Some(target))
            }
            0xC3 => ("RET", String::new(), None),
            b => ("DB", format!("0x{b:02X}"), None),
        };
        Instruction {
            offset,
            bytes: vec![byte],
            mnemonic: mnemonic.to_string(),
            operands,
            comment: None,
            branch_target,
        }
    }

    fn compute_arrow_depth(view: &DisasmView, src: u64, tgt: u64) -> u8 {
        let lo = src.min(tgt);
        let hi = src.max(tgt);
        let mut max_depth: u8 = 0;
        for arrow in view.arrows.values() {
            let alo = arrow.source.min(arrow.target);
            let ahi = arrow.source.max(arrow.target);
            // Ranges overlap?
            if alo < hi && ahi > lo {
                max_depth = max_depth.max(arrow.depth + 1);
            }
        }
        max_depth
    }
}

impl fmt::Display for DisasmView {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for line in &self.lines {
            let offset_str = self.formatter.format(line.instruction.offset);
            write!(f, "{:<18} {:24} {}", offset_str, line.hex_bytes, line.instruction.display())?;
            if let Some(ref cmt) = line.instruction.comment {
                write!(f, "  ; {cmt}")?;
            }
            writeln!(f)?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_disasm() -> HexDisassembler {
        HexDisassembler::new(0x1000)
    }

    // --- OffsetFormatter ---

    #[test]
    fn test_formatter_hex() {
        let f = OffsetFormatter::new(OffsetStyle::Hex).with_hex_width(8);
        assert_eq!(f.format(0x401000), "0x00401000");
    }

    #[test]
    fn test_formatter_decimal() {
        let f = OffsetFormatter::new(OffsetStyle::Decimal);
        assert_eq!(f.format(4096), "4096");
    }

    #[test]
    fn test_formatter_segment_offset() {
        let f = OffsetFormatter::new(OffsetStyle::SegmentOffset);
        assert_eq!(f.format(0x00401000), "0040:1000");
    }

    #[test]
    fn test_formatter_relative_to_base() {
        let f = OffsetFormatter::new(OffsetStyle::RelativeToBase).with_base(0x1000);
        assert_eq!(f.format(0x1100), "+0x100");
    }

    #[test]
    fn test_formatter_symbol_plus_disp_exact() {
        let mut f = OffsetFormatter::new(OffsetStyle::SymbolPlusDisp);
        f.add_symbol(0x1000, "main");
        assert_eq!(f.format(0x1000), "main");
    }

    #[test]
    fn test_formatter_symbol_plus_disp_offset() {
        let mut f = OffsetFormatter::new(OffsetStyle::SymbolPlusDisp);
        f.add_symbol(0x1000, "main");
        assert_eq!(f.format(0x1010), "main+0x10");
    }

    #[test]
    fn test_formatter_symbol_no_match() {
        let f = OffsetFormatter::new(OffsetStyle::SymbolPlusDisp);
        assert_eq!(f.format(0xDEAD), "0xDEAD");
    }

    // --- RelativeOffset ---

    #[test]
    fn test_relative_offset_forward() {
        let r = RelativeOffset { source: 0x100, target: 0x200, unconditional: true };
        assert!(r.is_forward());
        assert!(!r.is_backward());
    }

    #[test]
    fn test_relative_offset_backward() {
        let r = RelativeOffset { source: 0x200, target: 0x100, unconditional: false };
        assert!(r.is_backward());
        assert!(!r.is_forward());
    }

    #[test]
    fn test_relative_offset_displacement() {
        // JMP target = source + 2 + disp  ⟹  disp = target - (source + 2)
        let r = RelativeOffset { source: 0x100, target: 0x110, unconditional: true };
        assert_eq!(r.signed_displacement(2), 0xE);
    }

    #[test]
    fn test_relative_offset_negative_displacement() {
        let r = RelativeOffset { source: 0x110, target: 0x100, unconditional: false };
        assert_eq!(r.signed_displacement(2), -18i64);
    }

    // --- JumpArrow ---

    #[test]
    fn test_jump_arrow_defaults() {
        let a = JumpArrow::new(1, 0x100, 0x200);
        assert!(!a.conditional);
        assert_eq!(a.depth, 0);
        assert!(a.color.is_none());
    }

    #[test]
    fn test_jump_arrow_conditional() {
        let a = JumpArrow::new(1, 0x100, 0x200).conditional();
        assert!(a.conditional);
    }

    #[test]
    fn test_jump_arrow_depth() {
        let a = JumpArrow::new(1, 0x100, 0x200).at_depth(3);
        assert_eq!(a.depth, 3);
    }

    #[test]
    fn test_jump_arrow_row_span() {
        let a = JumpArrow::new(1, 0x1000, 0x1010);
        assert_eq!(a.row_span(1), 0x10);
    }

    // --- DisasmAnnotation ---

    #[test]
    fn test_annotation_creation() {
        let a = DisasmAnnotation::new(1, 0x1000, "entry");
        assert_eq!(a.label, "entry");
        assert_eq!(a.offset, 0x1000);
        assert!(a.tag.is_none());
    }

    #[test]
    fn test_annotation_with_tag() {
        let a = DisasmAnnotation::new(1, 0, "x").with_tag("crypto");
        assert_eq!(a.tag.as_deref(), Some("crypto"));
    }

    // --- DisasmView ---

    #[test]
    fn test_disasm_view_empty() {
        let v = DisasmView::new(OffsetFormatter::default());
        assert!(v.is_empty());
        assert_eq!(v.len(), 0);
        assert_eq!(v.total_bytes(), 0);
    }

    #[test]
    fn test_disasm_view_push_line() {
        let mut v = DisasmView::new(OffsetFormatter::default());
        let insn = Instruction {
            offset: 0x1000,
            bytes: vec![0x90],
            mnemonic: "NOP".into(),
            operands: String::new(),
            comment: None,
            branch_target: None,
        };
        v.push_line(DisasmLine::from_instruction(insn));
        assert_eq!(v.len(), 1);
        assert_eq!(v.total_bytes(), 1);
    }

    #[test]
    fn test_disasm_view_line_at_hit() {
        let mut v = DisasmView::new(OffsetFormatter::default());
        let insn = Instruction {
            offset: 0x400,
            bytes: vec![0xC3],
            mnemonic: "RET".into(),
            operands: String::new(),
            comment: None,
            branch_target: None,
        };
        v.push_line(DisasmLine::from_instruction(insn));
        assert!(v.line_at(0x400).is_some());
    }

    #[test]
    fn test_disasm_view_line_at_miss() {
        let v = DisasmView::new(OffsetFormatter::default());
        assert!(v.line_at(0x9999).is_none());
    }

    #[test]
    fn test_disasm_view_lines_in_range() {
        let mut v = DisasmView::new(OffsetFormatter::default());
        for off in [0x100u64, 0x101, 0x102, 0x200] {
            let insn = Instruction {
                offset: off,
                bytes: vec![0x90],
                mnemonic: "NOP".into(),
                operands: String::new(),
                comment: None,
                branch_target: None,
            };
            v.push_line(DisasmLine::from_instruction(insn));
        }
        let in_range = v.lines_in_range(0x100..0x103);
        assert_eq!(in_range.len(), 3);
    }

    #[test]
    fn test_disasm_view_add_remove_annotation() {
        let mut v = DisasmView::new(OffsetFormatter::default());
        let insn = Instruction {
            offset: 0x1000,
            bytes: vec![0x90],
            mnemonic: "NOP".into(),
            operands: String::new(),
            comment: None,
            branch_target: None,
        };
        v.push_line(DisasmLine::from_instruction(insn));
        let ann = DisasmAnnotation::new(42, 0x1000, "test");
        v.add_annotation(ann).unwrap();
        assert!(v.line_at(0x1000).unwrap().annotations.len() == 1);
        let removed = v.remove_annotation(42).unwrap();
        assert_eq!(removed.id, 42);
    }

    #[test]
    fn test_disasm_view_remove_annotation_missing() {
        let mut v = DisasmView::new(OffsetFormatter::default());
        assert!(matches!(
            v.remove_annotation(99),
            Err(DisasmError::AnnotationNotFound(99))
        ));
    }

    #[test]
    fn test_disasm_view_add_remove_arrow() {
        let mut v = DisasmView::new(OffsetFormatter::default());
        for off in [0x1000u64, 0x1010] {
            let insn = Instruction {
                offset: off,
                bytes: vec![0x90],
                mnemonic: "NOP".into(),
                operands: String::new(),
                comment: None,
                branch_target: None,
            };
            v.push_line(DisasmLine::from_instruction(insn));
        }
        let arrow = JumpArrow::new(7, 0x1000, 0x1010);
        v.add_arrow(arrow).unwrap();
        assert!(v.line_at(0x1000).unwrap().arrows.contains(&7));
        v.remove_arrow(7).unwrap();
        assert!(v.line_at(0x1000).unwrap().arrows.is_empty());
    }

    // --- HexDisassembler ---

    #[test]
    fn test_disassemble_basic() {
        let mut d = make_disasm();
        let bytes = [0x90u8, 0xC3, 0xCC];
        let view = d.disassemble(&bytes).unwrap();
        assert_eq!(view.len(), 3);
    }

    #[test]
    fn test_disassemble_nop_mnemonic() {
        let mut d = make_disasm();
        let view = d.disassemble(&[0x90]).unwrap();
        assert_eq!(view.lines()[0].instruction.mnemonic, "NOP");
    }

    #[test]
    fn test_disassemble_ret_mnemonic() {
        let mut d = make_disasm();
        let view = d.disassemble(&[0xC3]).unwrap();
        assert_eq!(view.lines()[0].instruction.mnemonic, "RET");
    }

    #[test]
    fn test_disassemble_hex_bytes_format() {
        let mut d = make_disasm();
        let view = d.disassemble(&[0xAB]).unwrap();
        assert_eq!(view.lines()[0].hex_bytes, "AB");
    }

    #[test]
    fn test_disassemble_max_bytes() {
        let mut d = make_disasm().with_max_bytes(2);
        let view = d.disassemble(&[0x90; 10]).unwrap();
        assert_eq!(view.len(), 2);
    }

    #[test]
    fn test_disassemble_range() {
        let mut d = make_disasm();
        let bytes = [0x00u8; 20];
        let view = d.disassemble_range(&bytes, 5..10).unwrap();
        assert_eq!(view.len(), 5);
        assert_eq!(view.lines()[0].instruction.offset, 0x1000 + 5);
    }

    #[test]
    fn test_disassemble_range_out_of_bounds() {
        let mut d = make_disasm();
        assert!(d.disassemble_range(&[0u8; 10], 0..20).is_err());
    }

    #[test]
    fn test_add_jump_arrow() {
        let mut d = make_disasm();
        let mut view = d.disassemble(&[0xEB, 0x90]).unwrap();
        let id = d.add_jump_arrow(&mut view, 0x1000, 0x1001, false).unwrap();
        assert!(id > 0);
    }

    #[test]
    fn test_annotate() {
        let mut d = make_disasm();
        let mut view = d.disassemble(&[0x90]).unwrap();
        let id = d.annotate(&mut view, 0x1000, "entry", "function entry point").unwrap();
        assert!(id > 0);
        assert_eq!(view.line_at(0x1000).unwrap().annotations[0].label, "entry");
    }

    #[test]
    fn test_sync_scroll_build() {
        let mut d = make_disasm();
        let view = d.disassemble(&[0x90; 32]).unwrap();
        let ss = d.build_sync_scroll(&view, 16).unwrap();
        assert_eq!(ss.bytes_per_row, 16);
    }

    // --- SyncScroll ---

    #[test]
    fn test_sync_scroll_zero_bytes_per_row_error() {
        assert!(SyncScroll::new(0, vec![0, 1, 2]).is_err());
    }

    #[test]
    fn test_sync_scroll_hex_row() {
        let ss = SyncScroll::new(16, vec![0, 1, 2, 3]).unwrap();
        // at offset 32, hex row = 32/16 = 2
        let mut ss = ss;
        ss.scroll_to_offset(32);
        assert_eq!(ss.hex_row(), 2);
    }

    #[test]
    fn test_sync_scroll_disasm_row() {
        let offsets = vec![0u64, 4, 8, 12];
        let mut ss = SyncScroll::new(4, offsets).unwrap();
        ss.scroll_to_offset(8);
        assert_eq!(ss.disasm_row(), 2);
    }

    #[test]
    fn test_sync_scroll_scroll_hex_rows() {
        let mut ss = SyncScroll::new(4, vec![0, 4, 8]).unwrap();
        ss.scroll_hex_rows(2);
        assert_eq!(ss.current_offset(), 8);
    }

    #[test]
    fn test_sync_scroll_scroll_disasm_rows() {
        let mut ss = SyncScroll::new(4, vec![0u64, 4, 8, 16]).unwrap();
        ss.scroll_disasm_rows(2);
        assert_eq!(ss.current_offset(), 8);
    }

    #[test]
    fn test_sync_scroll_rows_tuple() {
        let mut ss = SyncScroll::new(4, vec![0u64, 4, 8]).unwrap();
        ss.scroll_to_offset(4);
        let (h, d) = ss.rows();
        assert_eq!(h, 1);
        assert_eq!(d, 1);
    }

    #[test]
    fn test_display_trait() {
        let mut d = make_disasm();
        let view = d.disassemble(&[0x90, 0xC3]).unwrap();
        let s = format!("{}", view);
        assert!(s.contains("NOP"));
        assert!(s.contains("RET"));
    }

    #[test]
    fn test_instruction_display_no_operands() {
        let insn = Instruction {
            offset: 0,
            bytes: vec![0x90],
            mnemonic: "NOP".into(),
            operands: String::new(),
            comment: None,
            branch_target: None,
        };
        assert_eq!(insn.display(), "NOP");
    }

    #[test]
    fn test_instruction_display_with_operands() {
        let insn = Instruction {
            offset: 0,
            bytes: vec![0x48, 0x89, 0xC0],
            mnemonic: "MOV".into(),
            operands: "RAX, RAX".into(),
            comment: None,
            branch_target: None,
        };
        let d = insn.display();
        assert!(d.contains("MOV"));
        assert!(d.contains("RAX, RAX"));
    }

    #[test]
    fn test_arrow_depth_increases_on_overlap() {
        let mut disasm = make_disasm();
        let mut view = disasm.disassemble(&[0x90; 20]).unwrap();
        // First arrow: 0x1000 → 0x100A
        let _id1 = disasm.add_jump_arrow(&mut view, 0x1000, 0x100A, false).unwrap();
        // Second overlapping arrow: 0x1002 → 0x1008
        let _id2 = disasm.add_jump_arrow(&mut view, 0x1002, 0x1008, true).unwrap();
        // The second arrow must have depth ≥ 1
        let arrow2 = view.arrows.get(&_id2).unwrap();
        assert!(arrow2.depth >= 1);
    }
}
