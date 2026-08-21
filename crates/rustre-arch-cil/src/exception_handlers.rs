//! CIL exception handler decoding and control-flow analysis.
//!
//! Implements parsing of CIL `.try` / `catch` / `finally` / `fault` / `filter`
//! handler tables (ECMA-335 §II.25.4.6), plus a flow analyzer that adds
//! exception edges to a basic-block CFG.

// ---------------------------------------------------------------------------
// Handler type
// ---------------------------------------------------------------------------

/// The kind of a CIL exception handler clause.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HandlerKind {
    /// `catch <TypeToken>` — handles a specific exception type.
    Catch,
    /// `finally` — always executed on block exit.
    Finally,
    /// `fault` — like finally but only on exception.
    Fault,
    /// `filter` — user-defined filter expression precedes the handler.
    Filter,
}

impl HandlerKind {
    /// True if the handler requires a catch-type token.
    #[must_use]
    pub fn uses_catch_type(self) -> bool {
        self.is_catch()
    }

    /// True if this is a Catch clause.
    #[must_use]
    pub fn is_catch(self) -> bool {
        self == Self::Catch
    }

    /// True if this is a Finally clause.
    #[must_use]
    pub fn is_finally(self) -> bool {
        self == Self::Finally
    }

    /// True if this is a Filter clause.
    #[must_use]
    pub fn is_filter(self) -> bool {
        self == Self::Filter
    }
}

// ---------------------------------------------------------------------------
// HandlerBlock
// ---------------------------------------------------------------------------

/// Byte-level ranges describing one CIL exception handler clause.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandlerBlock {
    /// Byte offset of the first instruction in the guarded (try) region.
    pub try_offset: u32,
    /// Byte length of the guarded (try) region.
    pub try_length: u32,
    /// Byte offset of the first instruction of the handler.
    pub handler_offset: u32,
    /// Byte length of the handler region.
    pub handler_length: u32,
    /// For `Filter` handlers: byte offset of the filter code block.
    /// For `Catch` handlers: the metadata token of the catch type.
    /// For `Finally`/`Fault`: 0.
    pub class_token_or_filter: u32,
}

impl HandlerBlock {
    /// Byte offset one past the end of the try region.
    #[must_use]
    pub const fn try_end(&self) -> u32 {
        self.try_offset.saturating_add(self.try_length)
    }

    /// Byte offset one past the end of the handler region.
    #[must_use]
    pub const fn handler_end(&self) -> u32 {
        self.handler_offset.saturating_add(self.handler_length)
    }

    /// True if the given byte offset falls within the try region.
    #[must_use]
    pub const fn contains_try_offset(&self, offset: u32) -> bool {
        offset >= self.try_offset && offset < self.try_end()
    }

    /// True if the given byte offset falls within the handler region.
    #[must_use]
    pub const fn contains_handler_offset(&self, offset: u32) -> bool {
        offset >= self.handler_offset && offset < self.handler_end()
    }
}

// ---------------------------------------------------------------------------
// ExceptionHandler
// ---------------------------------------------------------------------------

/// A fully decoded CIL exception handler clause.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExceptionHandler {
    /// Clause type.
    pub kind: HandlerKind,
    /// Protected-region and handler-region ranges.
    pub block: HandlerBlock,
    /// For `Catch`: the metadata token of the exception type.
    /// For `Filter`: the byte offset of the filter block.
    /// For `Finally`/`Fault`: `None`.
    pub catch_type: Option<u32>,
    /// Index within its enclosing [`MethodExceptionTable`].
    pub index: usize,
}

impl ExceptionHandler {
    /// Return the filter-block offset for `Filter` handlers.
    #[must_use]
    pub fn filter_offset(&self) -> Option<u32> {
        if self.kind == HandlerKind::Filter {
            Some(self.block.class_token_or_filter)
        } else {
            None
        }
    }
}

// ---------------------------------------------------------------------------
// Decode errors
// ---------------------------------------------------------------------------

/// Errors produced by exception table parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EhDecodeError {
    /// The byte slice was too short.
    Truncated,
    /// An unrecognised handler kind flag was encountered.
    UnknownHandlerKind(u32),
    /// The method header flags indicate no exception handlers.
    NoHandlers,
}

impl std::fmt::Display for EhDecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Truncated => write!(f, "exception table truncated"),
            Self::UnknownHandlerKind(k) => write!(f, "unknown handler kind 0x{k:04X}"),
            Self::NoHandlers => write!(f, "method has no exception handlers"),
        }
    }
}

impl std::error::Error for EhDecodeError {}

// ---------------------------------------------------------------------------
// MethodExceptionTable
// ---------------------------------------------------------------------------

/// The complete exception handler table for one CIL method.
#[derive(Debug, Clone, Default)]
pub struct MethodExceptionTable {
    /// All decoded exception handlers.
    pub handlers: Vec<ExceptionHandler>,
    /// Whether the table uses the fat (32-bit field) format.
    pub fat_format: bool,
}

impl MethodExceptionTable {
    /// Create an empty exception table.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Return all handlers covering the given byte offset in the try region.
    #[must_use]
    pub fn handlers_for_try_offset(&self, offset: u32) -> Vec<&ExceptionHandler> {
        self.handlers
            .iter()
            .filter(|h| h.block.contains_try_offset(offset))
            .collect()
    }

    /// Return the catch handler for a specific exception-type token, if any.
    #[must_use]
    pub fn catch_handler_for_type(&self, type_token: u32) -> Option<&ExceptionHandler> {
        self.handlers
            .iter()
            .find(|h| h.kind == HandlerKind::Catch && h.catch_type == Some(type_token))
    }

    /// Return the finally handler covering a given offset, if any.
    #[must_use]
    pub fn finally_handler_for_offset(&self, offset: u32) -> Option<&ExceptionHandler> {
        self.handlers
            .iter()
            .find(|h| h.kind == HandlerKind::Finally && h.block.contains_try_offset(offset))
    }

    /// Parse a CIL method exception section (small or fat) from raw bytes.
    ///
    /// `bytes` should point at the start of the section header, i.e.
    /// the byte just after the last instruction in the method body.
    ///
    /// # Errors
    /// Returns [`EhDecodeError`] on malformed input.
    pub fn parse(bytes: &[u8]) -> Result<Self, EhDecodeError> {
        if bytes.is_empty() {
            return Err(EhDecodeError::Truncated);
        }

        let flags = bytes[0];
        let kind_flags = flags & 0x3f;
        let fat_format = flags & 0x40 != 0;
        // Section kind 1 = exception handlers
        if kind_flags != 1 {
            return Err(EhDecodeError::NoHandlers);
        }

        let mut table = Self {
            fat_format,
            ..Default::default()
        };

        if fat_format {
            // Fat: 4-byte section header (flags u8, datasize u24), each clause = 24 bytes
            if bytes.len() < 4 {
                return Err(EhDecodeError::Truncated);
            }
            let data_size = u32::from_le_bytes([bytes[1], bytes[2], bytes[3], 0]);
            let clause_count = (data_size.saturating_sub(4)) / 24;
            let mut off = 4usize;
            for idx in 0..clause_count as usize {
                if bytes.len() < off + 24 {
                    return Err(EhDecodeError::Truncated);
                }
                let h = parse_fat_clause(bytes, off, idx)?;
                table.handlers.push(h);
                off += 24;
            }
        } else {
            // Small: 4-byte header (flags u8, datasize u8, reserved u16), each clause = 12 bytes
            if bytes.len() < 4 {
                return Err(EhDecodeError::Truncated);
            }
            let data_size = bytes[1] as usize;
            if data_size < 4 {
                return Err(EhDecodeError::Truncated);
            }
            let clause_count = (data_size - 4) / 12;
            let mut off = 4usize;
            for idx in 0..clause_count {
                if bytes.len() < off + 12 {
                    return Err(EhDecodeError::Truncated);
                }
                let h = parse_small_clause(bytes, off, idx)?;
                table.handlers.push(h);
                off += 12;
            }
        }

        Ok(table)
    }

    /// Build a table directly from a list of pre-decoded handlers.
    #[must_use]
    pub const fn from_handlers(handlers: Vec<ExceptionHandler>) -> Self {
        Self {
            handlers,
            fat_format: true,
        }
    }
}

// ---------------------------------------------------------------------------
// Per-clause parsers
// ---------------------------------------------------------------------------

const fn parse_handler_kind(raw: u32) -> Result<HandlerKind, EhDecodeError> {
    match raw {
        0x0000 => Ok(HandlerKind::Catch),
        0x0001 => Ok(HandlerKind::Filter),
        0x0002 => Ok(HandlerKind::Finally),
        0x0004 => Ok(HandlerKind::Fault),
        other => Err(EhDecodeError::UnknownHandlerKind(other)),
    }
}

fn parse_fat_clause(
    bytes: &[u8],
    off: usize,
    idx: usize,
) -> Result<ExceptionHandler, EhDecodeError> {
    let clause_kind =
        u32::from_le_bytes([bytes[off], bytes[off + 1], bytes[off + 2], bytes[off + 3]]);
    let try_offset = u32::from_le_bytes([
        bytes[off + 4],
        bytes[off + 5],
        bytes[off + 6],
        bytes[off + 7],
    ]);
    let try_length = u32::from_le_bytes([
        bytes[off + 8],
        bytes[off + 9],
        bytes[off + 10],
        bytes[off + 11],
    ]);
    let handler_offset = u32::from_le_bytes([
        bytes[off + 12],
        bytes[off + 13],
        bytes[off + 14],
        bytes[off + 15],
    ]);
    let handler_length = u32::from_le_bytes([
        bytes[off + 16],
        bytes[off + 17],
        bytes[off + 18],
        bytes[off + 19],
    ]);
    let cktf = u32::from_le_bytes([
        bytes[off + 20],
        bytes[off + 21],
        bytes[off + 22],
        bytes[off + 23],
    ]);

    let kind = parse_handler_kind(clause_kind)?;
    let catch_type = if kind == HandlerKind::Catch {
        Some(cktf)
    } else {
        None
    };

    Ok(ExceptionHandler {
        kind,
        block: HandlerBlock {
            try_offset,
            try_length,
            handler_offset,
            handler_length,
            class_token_or_filter: cktf,
        },
        catch_type,
        index: idx,
    })
}

fn parse_small_clause(
    bytes: &[u8],
    off: usize,
    idx: usize,
) -> Result<ExceptionHandler, EhDecodeError> {
    let clause_kind = u16::from_le_bytes([bytes[off], bytes[off + 1]]);
    let try_offset = u16::from_le_bytes([bytes[off + 2], bytes[off + 3]]);
    let try_length = u16::from(bytes[off + 4]);
    let handler_offset = u16::from_le_bytes([bytes[off + 5], bytes[off + 6]]);
    let handler_length = u16::from(bytes[off + 7]);
    let cktf = u32::from_le_bytes([
        bytes[off + 8],
        bytes[off + 9],
        bytes[off + 10],
        bytes[off + 11],
    ]);

    let kind = parse_handler_kind(u32::from(clause_kind))?;
    let catch_type = if kind == HandlerKind::Catch {
        Some(cktf)
    } else {
        None
    };

    Ok(ExceptionHandler {
        kind,
        block: HandlerBlock {
            try_offset: u32::from(try_offset),
            try_length: u32::from(try_length),
            handler_offset: u32::from(handler_offset),
            handler_length: u32::from(handler_length),
            class_token_or_filter: cktf,
        },
        catch_type,
        index: idx,
    })
}

// ---------------------------------------------------------------------------
// ExceptionFlowAnalyzer
// ---------------------------------------------------------------------------

/// A simple CFG edge introduced by an exception handler.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EhEdge {
    /// Byte offset of the source block start (any instruction in the try region).
    pub from_offset: u32,
    /// Byte offset of the handler entry point.
    pub to_offset: u32,
    /// Type of the handler.
    pub kind: HandlerKind,
}

/// Analyzes a [`MethodExceptionTable`] and produces exception-flow CFG edges.
pub struct ExceptionFlowAnalyzer<'a> {
    table: &'a MethodExceptionTable,
}

impl<'a> ExceptionFlowAnalyzer<'a> {
    /// Create a new analyzer over the given exception table.
    #[must_use]
    pub const fn new(table: &'a MethodExceptionTable) -> Self {
        Self { table }
    }

    /// Generate one [`EhEdge`] per handler, from the first byte of its try region
    /// to the first byte of its handler region.
    ///
    /// In a real compiler this would be one edge per basic block that overlaps
    /// the try region, but this simplified version uses the try-region start as
    /// the representative source node.
    #[must_use]
    pub fn edges(&self) -> Vec<EhEdge> {
        self.table
            .handlers
            .iter()
            .map(|h| EhEdge {
                from_offset: h.block.try_offset,
                to_offset: h.block.handler_offset,
                kind: h.kind,
            })
            .collect()
    }

    /// Generate exception edges for all basic-block leaders that lie within a try region.
    ///
    /// `block_starts` is a sorted slice of byte offsets for all basic-block leaders.
    #[must_use]
    pub fn edges_for_blocks(&self, block_starts: &[u32]) -> Vec<EhEdge> {
        let mut out = Vec::with_capacity(self.table.handlers.len());
        for handler in &self.table.handlers {
            for &start in block_starts {
                if handler.block.contains_try_offset(start) {
                    out.push(EhEdge {
                        from_offset: start,
                        to_offset: handler.block.handler_offset,
                        kind: handler.kind,
                    });
                }
            }
        }
        out
    }

    /// Return `true` if the given byte offset is guarded by at least one handler.
    #[must_use]
    pub fn is_guarded(&self, offset: u32) -> bool {
        self.table
            .handlers
            .iter()
            .any(|h| h.block.contains_try_offset(offset))
    }

    /// Return all `finally` edges (used for dominance-frontier analysis).
    #[must_use]
    pub fn finally_edges(&self) -> Vec<EhEdge> {
        self.table
            .handlers
            .iter()
            .filter(|h| h.kind == HandlerKind::Finally)
            .map(|h| EhEdge {
                from_offset: h.block.try_offset,
                to_offset: h.block.handler_offset,
                kind: h.kind,
            })
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_fat_handler(
        kind: u32,
        try_off: u32,
        try_len: u32,
        hnd_off: u32,
        hnd_len: u32,
        cktf: u32,
    ) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&kind.to_le_bytes());
        v.extend_from_slice(&try_off.to_le_bytes());
        v.extend_from_slice(&try_len.to_le_bytes());
        v.extend_from_slice(&hnd_off.to_le_bytes());
        v.extend_from_slice(&hnd_len.to_le_bytes());
        v.extend_from_slice(&cktf.to_le_bytes());
        v
    }

    fn make_fat_section(clauses: &[Vec<u8>]) -> Vec<u8> {
        // flags: 0x41 = fat(0x40) | kind(0x01)
        // data_size: u24 = 4 (header) + clauses.len() * 24
        let data_size: u32 = 4 + u32::try_from(clauses.len()).expect("test fixture is small") * 24;
        let ds_bytes = data_size.to_le_bytes();
        let mut v = vec![0x41_u8, ds_bytes[0], ds_bytes[1], ds_bytes[2]];
        for c in clauses {
            v.extend_from_slice(c);
        }
        v
    }

    #[test]
    fn test_handler_kind_display() {
        let e = ExceptionHandler {
            kind: HandlerKind::Catch,
            block: HandlerBlock {
                try_offset: 0,
                try_length: 10,
                handler_offset: 10,
                handler_length: 5,
                class_token_or_filter: 0x0200_0001,
            },
            catch_type: Some(0x0200_0001),
            index: 0,
        };
        assert!(e.kind.is_catch());
        assert!(!e.kind.is_finally());
        assert_eq!(e.block.try_end(), 10);
        assert_eq!(e.block.handler_end(), 15);
    }

    #[test]
    fn test_parse_fat_catch() {
        let clause = make_fat_handler(0x0000, 0, 10, 10, 5, 0x0200_0001);
        let section = make_fat_section(&[clause]);
        let table = MethodExceptionTable::parse(&section).unwrap();
        assert_eq!(table.handlers.len(), 1);
        let h = &table.handlers[0];
        assert_eq!(h.kind, HandlerKind::Catch);
        assert_eq!(h.block.try_offset, 0);
        assert_eq!(h.block.try_length, 10);
        assert_eq!(h.block.handler_offset, 10);
        assert_eq!(h.catch_type, Some(0x0200_0001));
    }

    #[test]
    fn test_parse_fat_finally() {
        let clause = make_fat_handler(0x0002, 0, 20, 20, 8, 0);
        let section = make_fat_section(&[clause]);
        let table = MethodExceptionTable::parse(&section).unwrap();
        let h = &table.handlers[0];
        assert_eq!(h.kind, HandlerKind::Finally);
        assert!(h.catch_type.is_none());
    }

    #[test]
    fn test_parse_fat_fault() {
        let clause = make_fat_handler(0x0004, 5, 10, 15, 4, 0);
        let section = make_fat_section(&[clause]);
        let table = MethodExceptionTable::parse(&section).unwrap();
        assert_eq!(table.handlers[0].kind, HandlerKind::Fault);
    }

    #[test]
    fn test_parse_fat_filter() {
        let clause = make_fat_handler(0x0001, 0, 10, 20, 6, 15); // filter at offset 15
        let section = make_fat_section(&[clause]);
        let table = MethodExceptionTable::parse(&section).unwrap();
        let h = &table.handlers[0];
        assert_eq!(h.kind, HandlerKind::Filter);
        assert_eq!(h.filter_offset(), Some(15));
    }

    #[test]
    fn test_parse_multiple_handlers() {
        let c1 = make_fat_handler(0x0000, 0, 10, 10, 5, 0x0200_0001);
        let c2 = make_fat_handler(0x0002, 0, 10, 15, 4, 0);
        let section = make_fat_section(&[c1, c2]);
        let table = MethodExceptionTable::parse(&section).unwrap();
        assert_eq!(table.handlers.len(), 2);
        assert_eq!(table.handlers[0].kind, HandlerKind::Catch);
        assert_eq!(table.handlers[1].kind, HandlerKind::Finally);
    }

    #[test]
    fn test_truncated_error() {
        assert!(matches!(
            MethodExceptionTable::parse(&[]),
            Err(EhDecodeError::Truncated)
        ));
    }

    #[test]
    fn test_no_handlers_error() {
        // flags byte 0x00 → not exception section
        assert!(matches!(
            MethodExceptionTable::parse(&[0x00, 0, 0, 0]),
            Err(EhDecodeError::NoHandlers)
        ));
    }

    #[test]
    fn test_unknown_handler_kind() {
        let clause = make_fat_handler(0xDEAD, 0, 5, 5, 5, 0);
        let section = make_fat_section(&[clause]);
        let result = MethodExceptionTable::parse(&section);
        assert!(matches!(result, Err(EhDecodeError::UnknownHandlerKind(_))));
    }

    #[test]
    fn test_contains_try_offset() {
        let block = HandlerBlock {
            try_offset: 10,
            try_length: 20,
            handler_offset: 30,
            handler_length: 5,
            class_token_or_filter: 0,
        };
        assert!(block.contains_try_offset(10));
        assert!(block.contains_try_offset(15));
        assert!(block.contains_try_offset(29));
        assert!(!block.contains_try_offset(9));
        assert!(!block.contains_try_offset(30));
    }

    #[test]
    fn test_handlers_for_try_offset() {
        let h = ExceptionHandler {
            kind: HandlerKind::Finally,
            block: HandlerBlock {
                try_offset: 0,
                try_length: 30,
                handler_offset: 30,
                handler_length: 5,
                class_token_or_filter: 0,
            },
            catch_type: None,
            index: 0,
        };
        let table = MethodExceptionTable::from_handlers(vec![h]);
        assert_eq!(table.handlers_for_try_offset(10).len(), 1);
        assert_eq!(table.handlers_for_try_offset(40).len(), 0);
    }

    #[test]
    fn test_catch_handler_for_type() {
        let h = ExceptionHandler {
            kind: HandlerKind::Catch,
            block: HandlerBlock {
                try_offset: 0,
                try_length: 10,
                handler_offset: 10,
                handler_length: 5,
                class_token_or_filter: 0x0200_0001,
            },
            catch_type: Some(0x0200_0001),
            index: 0,
        };
        let table = MethodExceptionTable::from_handlers(vec![h]);
        assert!(table.catch_handler_for_type(0x0200_0001).is_some());
        assert!(table.catch_handler_for_type(0x0200_0002).is_none());
    }

    #[test]
    fn test_flow_analyzer_edges() {
        let h = ExceptionHandler {
            kind: HandlerKind::Catch,
            block: HandlerBlock {
                try_offset: 0,
                try_length: 20,
                handler_offset: 20,
                handler_length: 10,
                class_token_or_filter: 0,
            },
            catch_type: Some(0),
            index: 0,
        };
        let table = MethodExceptionTable::from_handlers(vec![h]);
        let analyzer = ExceptionFlowAnalyzer::new(&table);
        let edges = analyzer.edges();
        assert_eq!(edges.len(), 1);
        assert_eq!(edges[0].from_offset, 0);
        assert_eq!(edges[0].to_offset, 20);
    }

    #[test]
    fn test_flow_analyzer_edges_for_blocks() {
        let h = ExceptionHandler {
            kind: HandlerKind::Finally,
            block: HandlerBlock {
                try_offset: 0,
                try_length: 30,
                handler_offset: 30,
                handler_length: 5,
                class_token_or_filter: 0,
            },
            catch_type: None,
            index: 0,
        };
        let table = MethodExceptionTable::from_handlers(vec![h]);
        let analyzer = ExceptionFlowAnalyzer::new(&table);
        let blocks = [0u32, 10, 20, 30, 40];
        let edges = analyzer.edges_for_blocks(&blocks);
        // Offsets 0, 10, 20 are in the try region (0..30)
        assert_eq!(edges.len(), 3);
        for e in &edges {
            assert_eq!(e.to_offset, 30);
            assert_eq!(e.kind, HandlerKind::Finally);
        }
    }

    #[test]
    fn test_is_guarded() {
        let h = ExceptionHandler {
            kind: HandlerKind::Catch,
            block: HandlerBlock {
                try_offset: 10,
                try_length: 20,
                handler_offset: 30,
                handler_length: 5,
                class_token_or_filter: 0,
            },
            catch_type: Some(0),
            index: 0,
        };
        let table = MethodExceptionTable::from_handlers(vec![h]);
        let analyzer = ExceptionFlowAnalyzer::new(&table);
        assert!(analyzer.is_guarded(10));
        assert!(analyzer.is_guarded(25));
        assert!(!analyzer.is_guarded(30));
        assert!(!analyzer.is_guarded(9));
    }

    #[test]
    fn test_finally_edges() {
        let hc = ExceptionHandler {
            kind: HandlerKind::Catch,
            index: 0,
            block: HandlerBlock {
                try_offset: 0,
                try_length: 10,
                handler_offset: 10,
                handler_length: 5,
                class_token_or_filter: 0,
            },
            catch_type: Some(0),
        };
        let hf = ExceptionHandler {
            kind: HandlerKind::Finally,
            index: 1,
            block: HandlerBlock {
                try_offset: 0,
                try_length: 10,
                handler_offset: 15,
                handler_length: 5,
                class_token_or_filter: 0,
            },
            catch_type: None,
        };
        let table = MethodExceptionTable::from_handlers(vec![hc, hf]);
        let analyzer = ExceptionFlowAnalyzer::new(&table);
        let fedges = analyzer.finally_edges();
        assert_eq!(fedges.len(), 1);
        assert_eq!(fedges[0].to_offset, 15);
    }
}
