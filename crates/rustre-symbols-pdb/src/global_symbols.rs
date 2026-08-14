//! `global_symbols` — `GlobalSymbols` stream parser.
//!
//! The `GlobalSymbols` stream contains public and global symbols for the entire
//! binary. Each record is a `CodeView` symbol record beginning with a 4-byte
//! header (length + type code).

use serde::{Deserialize, Serialize};

use crate::Result;
use crate::stream_reader::StreamReader;

// ── Symbol record type codes ──────────────────────────────────────────────────

// Single source of truth: `crate::sym_kinds` (cvinfo.h SYM_ENUM_e).
use crate::sym_kinds::{
    S_GDATA32, S_GPROC32, S_LABEL32, S_LDATA32, S_LPROC32, S_PUB32, S_THUNK32,
};
/// `S_CONSTANT` as defined in cvinfo.h: 0x1107.
use crate::sym_kinds::S_CONSTANT as S_CONSTANT_CV;
/// `S_GTHREAD32` (0x1113) — global thread-local storage data.
use crate::sym_kinds::S_GTHREAD32 as S_TLSDATA32;

// ── GlobalSymKind ─────────────────────────────────────────────────────────────

/// The kind of a global-scope symbol record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum GlobalSymKind {
    /// A public or global procedure (`S_PUB32` / `S_GPROC32` / `S_LPROC32`).
    Procedure {
        /// TPI type index of the function's type.
        type_index: u32,
        /// Offset of the function within its segment.
        code_offset: u32,
        /// Length of the function body in bytes.
        code_size: u32,
        /// Segment (section) index.
        segment: u16,
    },
    /// A global or local data symbol (`S_GDATA32` / `S_LDATA32`).
    Data {
        /// TPI type index of the variable's type.
        type_index: u32,
        /// Offset of the data within its segment.
        offset: u32,
        /// Segment (section) index.
        segment: u16,
    },
    /// A named constant (`S_CONSTANT`).
    Constant {
        /// TPI type index of the constant's type.
        type_index: u32,
        /// Constant value.
        value: i64,
    },
    /// A thread-local storage variable (`S_TLSDATA32`).
    ThreadLocal {
        /// TPI type index of the variable's type.
        type_index: u32,
        /// Offset of the variable within the TLS segment.
        offset: u32,
        /// Segment (section) index.
        segment: u16,
    },
    /// A code label (`S_LABEL32`).
    Label {
        /// Offset of the label within its segment.
        offset: u32,
        /// Segment (section) index.
        segment: u16,
    },
    /// An import thunk (`S_THUNK32`).
    Thunk {
        /// Offset of the thunk within its segment.
        offset: u32,
        /// Segment (section) index.
        segment: u16,
        /// Length of the thunk in bytes.
        length: u16,
    },
    /// An unrecognised record type.
    Unknown(u16),
}

// ── GlobalSymbol ──────────────────────────────────────────────────────────────

/// One fully-parsed global symbol.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlobalSymbol {
    /// Undecoded symbol name (may be mangled).
    pub name: String,
    /// Demangled name if available (currently same as `name` — a full demangler
    /// would be invoked here in production).
    pub demangled: Option<String>,
    /// `RVA` (segment:offset resolved by the caller, or just the raw offset).
    pub address: Option<u64>,
    /// Decoded record kind and its payload.
    pub kind: GlobalSymKind,
}

impl GlobalSymbol {
    /// True when this symbol represents an executable function.
    #[must_use]
    pub const fn is_function(&self) -> bool {
        matches!(
            &self.kind,
            GlobalSymKind::Procedure { .. } | GlobalSymKind::Thunk { .. }
        )
    }

    /// Return the type index carried by this symbol, if any.
    #[must_use]
    pub const fn type_index(&self) -> Option<u32> {
        match &self.kind {
            GlobalSymKind::Procedure { type_index, .. }
            | GlobalSymKind::Data { type_index, .. }
            | GlobalSymKind::Constant { type_index, .. }
            | GlobalSymKind::ThreadLocal { type_index, .. } => Some(*type_index),
            _ => None,
        }
    }
}

// ── Parsing ───────────────────────────────────────────────────────────────────

/// Parse all global symbol records from a raw stream byte slice.
///
/// # Errors
/// Returns an error if parsing/reading fails.
pub fn parse_global_symbols(data: &[u8]) -> Result<Vec<GlobalSymbol>> {
    let mut rdr = StreamReader::new(data);
    let mut symbols = Vec::new();

    while rdr.remaining() >= 4 {
        let start = rdr.pos();
        let length = rdr.read_u16()? as usize;
        if length < 2 {
            break;
        }
        let rec_type = rdr.read_u16()?;
        // Payload starts at current position; total record = length - 2 bytes of payload.
        let payload_len = length.saturating_sub(2);
        if rdr.remaining() < payload_len {
            break;
        }

        let sym = parse_symbol_record(rec_type, &mut rdr, payload_len)?;
        if let Some(s) = sym {
            let size_for_filter = match &s.kind {
                GlobalSymKind::Procedure { code_size, .. } => *code_size,
                GlobalSymKind::Thunk { length, .. } => u32::from(*length),
                _ => 0,
            };
            if crate::pdb_symbol_is_sane(&s.name, size_for_filter) {
                symbols.push(s);
            }
        }

        // Advance to next 4-byte aligned record boundary.
        let consumed = rdr.pos() - start;
        let aligned = (2 + length + 3) & !3;
        if aligned > consumed {
            let _ = rdr.skip(aligned - consumed);
        }
    }

    Ok(symbols)
}

fn parse_symbol_record(
    rec_type: u16,
    rdr: &mut StreamReader<'_>,
    _payload_len: usize,
) -> Result<Option<GlobalSymbol>> {
    match rec_type {
        S_PUB32 => parse_pub32(rdr),
        S_GPROC32 | S_LPROC32 => parse_gproc32(rdr),
        S_GDATA32 | S_LDATA32 => parse_gdata32(rdr),
        S_TLSDATA32 => parse_tlsdata32(rdr),
        S_LABEL32 => parse_label32(rdr),
        S_THUNK32 => parse_thunk32(rdr),
        S_CONSTANT_CV => parse_constant_cv(rdr),
        _ => Ok(None),
    }
}

fn parse_pub32(rdr: &mut StreamReader<'_>) -> Result<Option<GlobalSymbol>> {
    // flags(4) + offset(4) + segment(2) + name(nul)
    if rdr.remaining() < 10 {
        return Ok(None);
    }
    let flags = rdr.read_u32()?;
    let offset = rdr.read_u32()?;
    let segment_val = rdr.read_u16()?;
    let name = rdr.read_cstring()?;
    let is_code = (flags & 0x2) != 0;
    let kind = if is_code {
        GlobalSymKind::Procedure {
            type_index: 0,
            code_offset: offset,
            code_size: 0,
            segment: segment_val,
        }
    } else {
        GlobalSymKind::Data {
            type_index: 0,
            offset,
            segment: segment_val,
        }
    };
    Ok(Some(GlobalSymbol {
        demangled: simple_demangle(&name),
        name,
        address: Some(u64::from(offset)),
        kind,
    }))
}

fn parse_gproc32(rdr: &mut StreamReader<'_>) -> Result<Option<GlobalSymbol>> {
    // parent(4)+end(4)+next(4)+len(4)+dbg_start(4)+dbg_end(4)+typind(4)+offset(4)+seg(2)+flags(1)+name
    if rdr.remaining() < 36 {
        return Ok(None);
    }
    let _ = rdr.read_u32()?; // parent
    let _ = rdr.read_u32()?; // end
    let _ = rdr.read_u32()?; // next
    let code_size = rdr.read_u32()?;
    let _ = rdr.read_u32()?; // dbg_start
    let _ = rdr.read_u32()?; // dbg_end
    let type_index = rdr.read_u32()?;
    let code_offset = rdr.read_u32()?;
    let segment = rdr.read_u16()?;
    let _ = rdr.read_u8()?; // flags
    let name = rdr.read_cstring()?;
    Ok(Some(GlobalSymbol {
        demangled: simple_demangle(&name),
        name,
        address: Some(u64::from(code_offset)),
        kind: GlobalSymKind::Procedure {
            type_index,
            code_offset,
            code_size,
            segment,
        },
    }))
}

fn parse_gdata32(rdr: &mut StreamReader<'_>) -> Result<Option<GlobalSymbol>> {
    // typind(4) + offset(4) + segment(2) + name(nul)
    if rdr.remaining() < 10 {
        return Ok(None);
    }
    let type_index = rdr.read_u32()?;
    let offset = rdr.read_u32()?;
    let segment = rdr.read_u16()?;
    let name = rdr.read_cstring()?;
    Ok(Some(GlobalSymbol {
        demangled: simple_demangle(&name),
        name,
        address: Some(u64::from(offset)),
        kind: GlobalSymKind::Data {
            type_index,
            offset,
            segment,
        },
    }))
}

fn parse_tlsdata32(rdr: &mut StreamReader<'_>) -> Result<Option<GlobalSymbol>> {
    if rdr.remaining() < 10 {
        return Ok(None);
    }
    let type_index = rdr.read_u32()?;
    let offset = rdr.read_u32()?;
    let segment = rdr.read_u16()?;
    let name = rdr.read_cstring()?;
    Ok(Some(GlobalSymbol {
        demangled: simple_demangle(&name),
        name,
        address: Some(u64::from(offset)),
        kind: GlobalSymKind::ThreadLocal {
            type_index,
            offset,
            segment,
        },
    }))
}

fn parse_label32(rdr: &mut StreamReader<'_>) -> Result<Option<GlobalSymbol>> {
    // offset(4) + segment(2) + flags(1) + name
    if rdr.remaining() < 7 {
        return Ok(None);
    }
    let offset = rdr.read_u32()?;
    let segment = rdr.read_u16()?;
    let _ = rdr.read_u8()?; // flags
    let name = rdr.read_cstring()?;
    Ok(Some(GlobalSymbol {
        demangled: None,
        name,
        address: Some(u64::from(offset)),
        kind: GlobalSymKind::Label { offset, segment },
    }))
}

fn parse_thunk32(rdr: &mut StreamReader<'_>) -> Result<Option<GlobalSymbol>> {
    // parent(4)+end(4)+next(4)+offset(4)+segment(2)+len(2)+ord(1)+name
    if rdr.remaining() < 19 {
        return Ok(None);
    }
    let _ = rdr.read_u32()?; // parent
    let _ = rdr.read_u32()?; // end
    let _ = rdr.read_u32()?; // next
    let offset = rdr.read_u32()?;
    let segment = rdr.read_u16()?;
    let length = rdr.read_u16()?;
    let _ = rdr.read_u8()?; // ord
    let name = rdr.read_cstring()?;
    Ok(Some(GlobalSymbol {
        demangled: simple_demangle(&name),
        name,
        address: Some(u64::from(offset)),
        kind: GlobalSymKind::Thunk {
            offset,
            segment,
            length,
        },
    }))
}

fn parse_constant_cv(rdr: &mut StreamReader<'_>) -> Result<Option<GlobalSymbol>> {
    if rdr.remaining() < 4 {
        return Ok(None);
    }
    let type_index = rdr.read_u32()?;
    let value = rdr.read_numeric_leaf()?;
    let name = rdr.read_cstring()?;
    Ok(Some(GlobalSymbol {
        demangled: None,
        name,
        address: None,
        kind: GlobalSymKind::Constant { type_index, value },
    }))
}

/// Very minimal MSVC demangler: strips the leading `?` from a mangled name.
fn simple_demangle(name: &str) -> Option<String> {
    if name.starts_with('?') {
        // Return the raw name without the leading `?` as a best-effort.
        Some(name.trim_start_matches('?').to_string())
    } else {
        None
    }
}

/// Symbol flags for `S_PUB32`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SymFlags(pub u32);

impl SymFlags {
    /// Symbol lives in a code section.
    pub const CODE: u32 = 0x0001;
    /// Symbol is a function.
    pub const FUNCTION: u32 = 0x0002;
    /// Symbol is managed code.
    pub const MANAGED: u32 = 0x0004;
    /// Symbol is MSIL code.
    pub const MSIL: u32 = 0x0008;

    /// True if the function flag is set.
    #[must_use]
    pub const fn is_function(self) -> bool {
        self.0 & Self::FUNCTION != 0
    }

    /// True if the code flag is set.
    #[must_use]
    pub const fn is_code(self) -> bool {
        self.0 & Self::CODE != 0
    }
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

    fn pub32_payload(name: &str, offset: u32, is_fn: bool) -> Vec<u8> {
        let mut p = Vec::new();
        let flags: u32 = if is_fn { 0x2 } else { 0 };
        p.extend_from_slice(&flags.to_le_bytes());
        p.extend_from_slice(&offset.to_le_bytes());
        p.extend_from_slice(&1u16.to_le_bytes()); // segment
        p.extend_from_slice(name.as_bytes());
        p.push(0);
        p
    }

    #[test]
    fn test_parse_pub32_function() {
        let stream = frame_record(S_PUB32, &pub32_payload("MyFunc", 0x1000, true));
        let syms = parse_global_symbols(&stream).unwrap();
        assert_eq!(syms.len(), 1);
        assert_eq!(syms[0].name, "MyFunc");
        assert!(syms[0].is_function());
    }

    #[test]
    fn test_parse_pub32_data() {
        let stream = frame_record(S_PUB32, &pub32_payload("gVar", 0x2000, false));
        let syms = parse_global_symbols(&stream).unwrap();
        assert_eq!(syms.len(), 1);
        assert!(matches!(syms[0].kind, GlobalSymKind::Data { .. }));
    }

    #[test]
    fn test_parse_label32() {
        let mut p = Vec::new();
        p.extend_from_slice(&0x3000u32.to_le_bytes()); // offset
        p.extend_from_slice(&1u16.to_le_bytes()); // segment
        p.push(0); // flags
        p.extend_from_slice(b"label_x\x00");
        let stream = frame_record(S_LABEL32, &p);
        let syms = parse_global_symbols(&stream).unwrap();
        assert_eq!(syms.len(), 1);
        assert!(matches!(syms[0].kind, GlobalSymKind::Label { .. }));
        assert_eq!(syms[0].name, "label_x");
    }

    #[test]
    fn test_parse_gdata32() {
        let mut p = Vec::new();
        p.extend_from_slice(&5u32.to_le_bytes()); // type_index
        p.extend_from_slice(&0x4000u32.to_le_bytes()); // offset
        p.extend_from_slice(&2u16.to_le_bytes()); // segment
        p.extend_from_slice(b"gData\x00");
        let stream = frame_record(S_GDATA32, &p);
        let syms = parse_global_symbols(&stream).unwrap();
        assert_eq!(syms[0].name, "gData");
        assert_eq!(syms[0].type_index(), Some(5));
    }

    #[test]
    fn test_empty_stream() {
        let syms = parse_global_symbols(&[]).unwrap();
        assert!(syms.is_empty());
    }

    #[test]
    fn test_multiple_symbols() {
        let mut stream = Vec::new();
        stream.extend(frame_record(S_PUB32, &pub32_payload("A", 0x100, true)));
        stream.extend(frame_record(S_PUB32, &pub32_payload("B", 0x200, false)));
        let syms = parse_global_symbols(&stream).unwrap();
        assert_eq!(syms.len(), 2);
    }

    #[test]
    fn test_simple_demangle() {
        assert_eq!(simple_demangle("?foo@@YAXI@Z"), Some("foo@@YAXI@Z".into()));
        assert_eq!(simple_demangle("normal_func"), None);
    }

    #[test]
    fn test_sym_flags_is_function() {
        let f = SymFlags(0x2);
        assert!(f.is_function());
        let d = SymFlags(0x0);
        assert!(!d.is_function());
    }

    #[test]
    fn test_global_symbol_type_index_data() {
        let sym = GlobalSymbol {
            name: "x".into(),
            demangled: None,
            address: None,
            kind: GlobalSymKind::Data {
                type_index: 42,
                offset: 0,
                segment: 1,
            },
        };
        assert_eq!(sym.type_index(), Some(42));
    }
}
