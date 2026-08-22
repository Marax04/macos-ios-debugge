//! Complete STABS record parser.
//!
//! Handles all `N_*` record types and produces a structured parse tree.
//! Type descriptor strings are parsed recursively into [`StabsTypeExpr`] values.
//!
//! Supported `N_*` codes:
//! `N_GSYM`, `N_FNAME`, `N_FUN`, `N_STSYM`, `N_LCSYM`, `N_MAIN`, `N_RSYM`,
//! `N_SLINE`, `N_DSLINE`, `N_BSLINE`, `N_SSYM`, `N_SO`, `N_LSYM`, `N_BINCL`,
//! `N_SOL`, `N_PSYM`, `N_EINCL`, `N_ENTRY`, `N_LBRAC`, `N_EXCL`, `N_RBRAC`,
//! `N_BCOMM`, `N_ECOMM`, `N_ECOML`, `N_LENG`.

use std::collections::HashMap;

// ─────────────────────────────────────────────────────────────────────────────
// StabsRecord (raw input)
// ─────────────────────────────────────────────────────────────────────────────

/// A raw STAB record as stored in the `.stab` section.
#[derive(Debug, Clone)]
pub struct StabsRecord {
    /// Index into `.stabstr` for the string field.
    pub n_strx: u32,
    /// Record type (one of the `N_*` constants).
    pub n_type: u8,
    /// Other / auxiliary field.
    pub n_other: u8,
    /// Description field (line number, register number, type number, etc.).
    pub n_desc: u16,
    /// Value field (address, offset, or misc).
    pub n_value: u32,
}

/// Parse a flat byte slice into STAB records (little-endian, 12 bytes each).
///
/// # Panics
/// Panics if the byte slice has incomplete 12-byte records at the end (should
/// not happen in practice since the loop checks `i + 12 <= data.len()`).
#[must_use]
pub fn parse_stab_section(data: &[u8]) -> Vec<StabsRecord> {
    let mut records = Vec::new();
    let mut i = 0usize;
    while i + 12 <= data.len() {
        records.push(StabsRecord {
            n_strx:  u32::from_le_bytes(data[i..i+4].try_into().unwrap()),
            n_type:  data[i+4],
            n_other: data[i+5],
            n_desc:  u16::from_le_bytes(data[i+6..i+8].try_into().unwrap()),
            n_value: u32::from_le_bytes(data[i+8..i+12].try_into().unwrap()),
        });
        i += 12;
    }
    records
}

// ─────────────────────────────────────────────────────────────────────────────
// N_* constants
// ─────────────────────────────────────────────────────────────────────────────

/// `N_GSYM` stab type: Global symbol.
pub const N_GSYM:  u8 = 0x20;
/// `N_FNAME` stab type: Function name (Pascal/Fortran).
pub const N_FNAME: u8 = 0x22;
/// `N_FUN` stab type: Function or text-segment variable.
pub const N_FUN:   u8 = 0x24;
/// `N_STSYM` stab type: Static symbol in the data segment.
pub const N_STSYM: u8 = 0x26;
/// `N_LCSYM` stab type: Static symbol in the BSS segment.
pub const N_LCSYM: u8 = 0x28;
/// `N_MAIN` stab type: Name of the main routine.
pub const N_MAIN:  u8 = 0x2A;
/// `N_ROSYM` stab type: Read-only data symbol.
pub const N_ROSYM: u8 = 0x2C;
/// `N_RSYM` stab type: Register variable.
pub const N_RSYM:  u8 = 0x40;
/// `N_SLINE` stab type: Source line in the text segment.
pub const N_SLINE: u8 = 0x44;
/// `N_DSLINE` stab type: Source line in the data segment.
pub const N_DSLINE:u8 = 0x46;
/// `N_BSLINE` stab type: Source line in the BSS segment.
pub const N_BSLINE:u8 = 0x48;
/// `N_SSYM` stab type: Structure/union element.
pub const N_SSYM:  u8 = 0x60;
/// `N_SO` stab type: Main source file (compilation unit).
pub const N_SO:    u8 = 0x64;
/// `N_LSYM` stab type: Local symbol (stack variable or type definition).
pub const N_LSYM:  u8 = 0x80;
/// `N_BINCL` stab type: Begin include file.
pub const N_BINCL: u8 = 0x82;
/// `N_SOL` stab type: Included (`#include`d) source file.
pub const N_SOL:   u8 = 0x84;
/// `N_PSYM` stab type: Function parameter.
pub const N_PSYM:  u8 = 0xA0;
/// `N_EINCL` stab type: End include file.
pub const N_EINCL: u8 = 0xA2;
/// `N_ENTRY` stab type: Alternate function entry point.
pub const N_ENTRY: u8 = 0xA4;
/// `N_LBRAC` stab type: Begin lexical block.
pub const N_LBRAC: u8 = 0xC0;
/// `N_EXCL` stab type: Excluded include file (deduplicated).
pub const N_EXCL:  u8 = 0xC2;
/// `N_RBRAC` stab type: End lexical block.
pub const N_RBRAC: u8 = 0xE0;
/// `N_BCOMM` stab type: Begin common block.
pub const N_BCOMM: u8 = 0xE2;
/// `N_ECOMM` stab type: End common block.
pub const N_ECOMM: u8 = 0xE4;
/// `N_ECOML` stab type: End common block (local name).
pub const N_ECOML: u8 = 0xE8;
/// `N_LENG` stab type: Length of the preceding entry.
pub const N_LENG:  u8 = 0xFE;

// ─────────────────────────────────────────────────────────────────────────────
// StabsTypeExpr — parsed type descriptor
// ─────────────────────────────────────────────────────────────────────────────

/// A parsed STABS type descriptor.
#[derive(Debug, Clone, PartialEq)]
pub enum StabsTypeExpr {
    /// A reference to a numbered type `(file, num)` or just `num`.
    TypeRef {
        /// File index (0 = current file).
        file: u16,
        /// Type number within the file.
        num: u32,
    },
    /// Pointer to another type.
    Pointer(Box<Self>),
    /// Reference (C++ `&`).
    Reference(Box<Self>),
    /// Array: index type, element type, lower bound, upper bound.
    Array {
        /// Index type (usually a range of int).
        index_type: Box<Self>,
        /// Element type.
        elem_type: Box<Self>,
        /// Lower bound.
        lo: i64,
        /// Upper bound.
        hi: i64,
    },
    /// Struct.
    Struct {
        /// Struct tag name, if any.
        name: Option<String>,
        /// Size in bytes.
        size: u32,
        /// Member fields.
        fields: Vec<StabsField>,
    },
    /// Union.
    Union {
        /// Union tag name, if any.
        name: Option<String>,
        /// Size in bytes.
        size: u32,
        /// Member fields.
        fields: Vec<StabsField>,
    },
    /// Enum.
    Enum {
        /// Enum tag name, if any.
        name: Option<String>,
        /// `(name, value)` enumerator pairs.
        values: Vec<(String, i64)>,
    },
    /// Function type.
    Function {
        /// Return type.
        return_type: Box<Self>,
    },
    /// Range (sub-range of another type).
    Range {
        /// Base type the range restricts.
        base: Box<Self>,
        /// Lower bound.
        lo: i64,
        /// Upper bound.
        hi: i64,
    },
    /// C++ member pointer.
    MemberPtr {
        /// Class containing the member.
        class_type: Box<Self>,
        /// Type of the pointed-to member.
        member_type: Box<Self>,
    },
    /// `volatile` qualifier.
    Volatile(Box<Self>),
    /// `const` qualifier.
    Const(Box<Self>),
    /// Typedef alias with a name.
    Typedef {
        /// Typedef name.
        name: String,
        /// Aliased type.
        inner: Box<Self>,
    },
    /// Void / unresolved.
    Void,
    /// Unknown / unparseable.
    Unknown(String),
}

/// A struct/union field in a STABS type descriptor.
#[derive(Debug, Clone, PartialEq)]
pub struct StabsField {
    /// Field name.
    pub name: String,
    /// Field type expression.
    pub type_expr: StabsTypeExpr,
    /// Bit offset within the struct.
    pub bit_offset: u32,
    /// Bit size (0 = natural alignment of type).
    pub bit_size: u32,
}

// ─────────────────────────────────────────────────────────────────────────────
// TypeDescriptorParser
// ─────────────────────────────────────────────────────────────────────────────

/// Recursive descent parser for STABS type descriptor strings.
pub struct TypeDescriptorParser<'a> {
    input: &'a [u8],
    pos: usize,
    /// Recursive-descent nesting depth, bounded by [`MAX_PARSE_DEPTH`].
    depth: u32,
}

/// Maximum nesting depth accepted by [`TypeDescriptorParser::parse_type`].
/// A hostile `.stabstr` descriptor of `200_000` consecutive `*` would otherwise
/// overflow the stack; real compilers never nest more than a handful of levels.
const MAX_PARSE_DEPTH: u32 = 100;

impl<'a> TypeDescriptorParser<'a> {
    /// Create a parser over a byte slice.
    #[must_use]
    pub const fn new(input: &'a [u8]) -> Self {
        Self { input, pos: 0, depth: 0 }
    }

    #[must_use]
    const fn peek(&self) -> Option<u8> {
        if self.pos < self.input.len() {
            Some(self.input[self.pos])
        } else {
            None
        }
    }

}

/// Byte-by-byte iterator over the descriptor input.
///
/// Returns `None` at end of input. Implementing [`Iterator`] allows external
/// state machines to drive the cursor in lock-step with their own decoding.
impl Iterator for TypeDescriptorParser<'_> {
    type Item = u8;
    fn next(&mut self) -> Option<u8> {
        let b = self.input.get(self.pos).copied();
        if b.is_some() { self.pos += 1; }
        b
    }
}

impl<'a> TypeDescriptorParser<'a> {
    fn expect(&mut self, ch: u8) -> bool {
        if self.peek() == Some(ch) {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    fn read_until(&mut self, ch: u8) -> &'a [u8] {
        let start = self.pos;
        while self.pos < self.input.len() && self.input[self.pos] != ch {
            self.pos += 1;
        }
        &self.input[start..self.pos]
    }

    fn read_int(&mut self) -> i64 {
        let neg = self.peek() == Some(b'-');
        if neg { self.pos += 1; }
        let start = self.pos;
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.pos += 1;
        }
        let s = std::str::from_utf8(&self.input[start..self.pos]).unwrap_or("0");
        let v = s.parse::<i64>().unwrap_or(0);
        if neg { -v } else { v }
    }

    fn read_type_num(&mut self) -> (u16, u32) {
        if self.peek() == Some(b'(') {
            self.pos += 1;
            let file = u16::try_from(self.read_int()).unwrap_or(u16::MAX);
            self.expect(b',');
            let num = u32::try_from(self.read_int()).unwrap_or(u32::MAX);
            self.expect(b')');
            (file, num)
        } else {
            let num = u32::try_from(self.read_int()).unwrap_or(u32::MAX);
            (0, num)
        }
    }

    fn read_name(&mut self, end: u8) -> String {
        let bytes = self.read_until(end);
        String::from_utf8_lossy(bytes).into_owned()
    }

    /// Parse a full type expression starting at current position.
    pub fn parse_type(&mut self) -> StabsTypeExpr {
        if self.depth >= MAX_PARSE_DEPTH {
            return StabsTypeExpr::Unknown(String::from("depth limit"));
        }
        self.depth += 1;
        let out = self.parse_type_checked();
        self.depth -= 1;
        out
    }

    fn parse_type_checked(&mut self) -> StabsTypeExpr {
        // If the input starts with a type-number form ('(' or a digit / '-'),
        // it's either a reference or an assignment "(...)=body".  Otherwise
        // we have a bare type body (e.g. "*(0,1)" or "r(0,1);0;127;").
        match self.peek() {
            Some(b'(' | b'0'..=b'9' | b'-') => {
                let save = self.pos;
                let (_file, _num) = self.read_type_num();
                if self.peek() == Some(b'=') {
                    self.pos += 1;
                    return self.parse_type_body();
                }
                let (file, num) = { self.pos = save; self.read_type_num() };
                StabsTypeExpr::TypeRef { file, num }
            }
            _ => self.parse_type_body(),
        }
    }

    fn parse_type_body(&mut self) -> StabsTypeExpr {
        match self.peek() {
            Some(b'*') => {
                self.pos += 1;
                StabsTypeExpr::Pointer(Box::new(self.parse_type()))
            }
            Some(b'&') => {
                self.pos += 1;
                StabsTypeExpr::Reference(Box::new(self.parse_type()))
            }
            Some(b'f' | b'F') => {
                self.pos += 1;
                let ret = self.parse_type();
                StabsTypeExpr::Function { return_type: Box::new(ret) }
            }
            Some(b'a') => {
                // Array: a<index_type>;<element_type>
                self.pos += 1;
                let index_type = self.parse_type();
                self.expect(b';');
                let elem_type = self.parse_type();
                StabsTypeExpr::Array {
                    index_type: Box::new(index_type),
                    elem_type: Box::new(elem_type),
                    lo: 0, hi: 0,
                }
            }
            Some(b'r') => {
                // Range: r<base>;<lo>;<hi>
                self.pos += 1;
                let base = self.parse_type();
                self.expect(b';');
                let lo = self.read_int();
                self.expect(b';');
                let hi = self.read_int();
                self.expect(b';');
                StabsTypeExpr::Range { base: Box::new(base), lo, hi }
            }
            Some(b's' | b'S') => {
                // Struct: s<size><field1><field2>...;
                self.pos += 1;
                let size = u32::try_from(self.read_int()).unwrap_or(u32::MAX);
                let fields = self.parse_fields();
                StabsTypeExpr::Struct { name: None, size, fields }
            }
            Some(b'u' | b'U') => {
                // Union: u<size><fields>...;
                self.pos += 1;
                let size = u32::try_from(self.read_int()).unwrap_or(u32::MAX);
                let fields = self.parse_fields();
                StabsTypeExpr::Union { name: None, size, fields }
            }
            Some(b'e' | b'E') => {
                // Enum: e<name>:<val>,...;
                self.pos += 1;
                let values = self.parse_enum_values();
                StabsTypeExpr::Enum { name: None, values }
            }
            Some(b'k') => {
                // const qualifier
                self.pos += 1;
                StabsTypeExpr::Const(Box::new(self.parse_type()))
            }
            Some(b'B') => {
                // volatile qualifier
                self.pos += 1;
                StabsTypeExpr::Volatile(Box::new(self.parse_type()))
            }
            Some(b'v') => {
                // void
                self.pos += 1;
                StabsTypeExpr::Void
            }
            _ => {
                let remaining = std::str::from_utf8(&self.input[self.pos..]).unwrap_or("").to_string();
                StabsTypeExpr::Unknown(remaining)
            }
        }
    }

    fn parse_fields(&mut self) -> Vec<StabsField> {
        let mut fields = Vec::new();
        loop {
            if matches!(self.peek(), None | Some(b';')) {
                break;
            }
            // field: <name>:<type>;<bit_offset>;<bit_size>;
            let name = self.read_name(b':');
            if name.is_empty() { break; }
            self.expect(b':');
            if self.peek() == Some(b';') { break; }
            let type_expr = self.parse_type();
            self.expect(b',');
            let bit_offset = u32::try_from(self.read_int()).unwrap_or(u32::MAX);
            self.expect(b',');
            let bit_size = u32::try_from(self.read_int()).unwrap_or(u32::MAX);
            self.expect(b';');
            fields.push(StabsField { name, type_expr, bit_offset, bit_size });
        }
        fields
    }

    fn parse_enum_values(&mut self) -> Vec<(String, i64)> {
        let mut vals = Vec::new();
        loop {
            if matches!(self.peek(), None | Some(b';')) {
                self.expect(b';');
                break;
            }
            let name_bytes = self.read_until(b':');
            let name = String::from_utf8_lossy(name_bytes).into_owned();
            self.expect(b':');
            let val = self.read_int();
            self.expect(b',');
            if name.is_empty() { break; }
            vals.push((name, val));
        }
        vals
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ParsedStab — structured record
// ─────────────────────────────────────────────────────────────────────────────

/// A fully parsed STABS record.
#[derive(Debug, Clone)]
pub enum ParsedStab {
    /// `N_SO` — source file name and compilation unit.
    SourceFile {
        /// Source file path (or an `<end:ADDR>` marker for the closing record).
        path: String,
        /// Compilation directory, when known.
        comp_dir: Option<String>,
        /// True for the empty end-of-CU record.
        is_end: bool,
    },
    /// `N_SOL` — `#include`d source file change.
    IncludedFile {
        /// Included file path.
        path: String,
    },
    /// `N_FUN` — function definition or end-of-function.
    Function {
        /// Function name (empty for end records).
        name: String,
        /// Parsed return-type descriptor, if present.
        type_expr: Option<StabsTypeExpr>,
        /// Function start address.
        address: u32,
        /// True for the empty end-of-function record.
        is_end: bool,
    },
    /// `N_GSYM` — global variable symbol.
    GlobalSym {
        /// Variable name.
        name: String,
        /// Variable type.
        type_expr: StabsTypeExpr,
        /// Address (often 0; resolved via the linker symbol).
        address: u32,
    },
    /// `N_STSYM` — static variable in data segment.
    StaticDataSym {
        /// Variable name.
        name: String,
        /// Variable type.
        type_expr: StabsTypeExpr,
        /// Address in the data segment.
        address: u32,
    },
    /// `N_LCSYM` — static variable in BSS.
    StaticBssSym {
        /// Variable name.
        name: String,
        /// Variable type.
        type_expr: StabsTypeExpr,
        /// Address in the BSS segment.
        address: u32,
    },
    /// `N_LSYM` — local symbol (stack variable or type).
    LocalSym {
        /// Symbol name.
        name: String,
        /// Symbol type.
        type_expr: StabsTypeExpr,
        /// Frame offset of the stack slot.
        offset: i32,
    },
    /// `N_PSYM` — function parameter symbol.
    Param {
        /// Parameter name.
        name: String,
        /// Parameter type.
        type_expr: StabsTypeExpr,
        /// Frame offset of the parameter.
        offset: i32,
    },
    /// `N_RSYM` — register variable.
    Register {
        /// Variable name.
        name: String,
        /// Variable type.
        type_expr: StabsTypeExpr,
        /// Register number.
        reg: u8,
    },
    /// `N_SLINE` — source line in .text.
    SourceLine {
        /// Line number.
        line: u16,
        /// Code address.
        address: u32,
    },
    /// `N_DSLINE` / `N_BSLINE` — source line in .data / .bss.
    DataLine {
        /// Line number.
        line: u16,
        /// Data address.
        address: u32,
        /// True for `N_BSLINE` (.bss), false for `N_DSLINE` (.data).
        in_bss: bool,
    },
    /// `N_LBRAC` / `N_RBRAC` — lexical block begin/end.
    Block {
        /// True for `N_LBRAC` (begin), false for `N_RBRAC` (end).
        is_begin: bool,
        /// Block boundary address.
        address: u32,
    },
    /// `N_BINCL` — begin include file.
    BeginInclude {
        /// Include file name.
        filename: String,
        /// Header checksum used for deduplication.
        sum: u32,
    },
    /// `N_EINCL` — end include file.
    EndInclude,
    /// `N_EXCL` — excluded include file (already seen).
    ExcludeInclude {
        /// Include file name.
        filename: String,
        /// Header checksum matching the original `N_BINCL`.
        sum: u32,
    },
    /// `N_BCOMM` / `N_ECOMM` — common block.
    CommonBlock {
        /// Common block name.
        name: String,
        /// True for `N_BCOMM` (begin), false for `N_ECOMM` (end).
        is_begin: bool,
    },
    /// `N_ECOML` — end common block (local).
    EndCommonLocal {
        /// Address of the common block end.
        address: u32,
    },
    /// `N_ENTRY` — alternate function entry.
    Entry {
        /// Entry point name.
        name: String,
        /// Entry point address.
        address: u32,
    },
    /// `N_FNAME` — function name (Pascal/Fortran).
    FunctionName(String),
    /// `N_MAIN` — main function name.
    MainName(String),
    /// `N_SSYM` — structure element/slot.
    StructSym {
        /// Element name.
        name: String,
        /// Offset within the structure.
        offset: i32,
    },
    /// `N_ROSYM` — Read-only data sym.
    RoSym {
        /// Symbol name.
        name: String,
        /// Address in the read-only data segment.
        address: u32,
    },
    /// `N_LENG` — length of preceding entry.
    Length(u32),
    /// Any other / unrecognised record.
    Unknown {
        /// Raw `n_type` code.
        n_type: u8,
        /// Raw `.stabstr` string index.
        n_strx: u32,
        /// Raw description field.
        n_desc: u16,
        /// Raw value field.
        n_value: u32,
    },
}

// ─────────────────────────────────────────────────────────────────────────────
// FullStabsParser
// ─────────────────────────────────────────────────────────────────────────────

/// Top-level STABS parser that combines raw records with string table lookup.
pub struct FullStabsParser {
    /// String table (`.stabstr`).
    pub stabstr: Vec<u8>,
}

impl FullStabsParser {
    /// Create a parser with the given string table.
    #[must_use]
    pub const fn new(stabstr: Vec<u8>) -> Self {
        Self { stabstr }
    }

    /// Look up a NUL-terminated string at an *absolute* `.stabstr` offset.
    #[must_use]
    pub fn lookup_str(&self, offset: u32) -> &str {
        crate::cu_strings::read_cstr(&self.stabstr, offset as usize)
    }

    /// Look up a record's string at the running CU-relative base, advancing
    /// the base past an `N_UNDF` compilation-unit header.
    #[must_use]
    pub fn lookup_str_based(
        &self,
        base: &mut crate::cu_strings::CuStringBase,
        r: &StabsRecord,
    ) -> &str {
        base.resolve(&self.stabstr, r.n_type, r.n_strx, r.n_value)
    }

    /// Parse all records in the given raw stab section.
    ///
    /// Maintains the running `N_UNDF` string-table base across the record
    /// sequence, so multi-CU (linker-merged) sections resolve correct names
    /// for every CU rather than only the first.
    #[must_use]
    pub fn parse_all(&self, records: &[StabsRecord]) -> Vec<ParsedStab> {
        let mut base = crate::cu_strings::CuStringBase::new();
        records
            .iter()
            .map(|r| {
                let s = self.lookup_str_based(&mut base, r);
                Self::parse_record(s, r)
            })
            .collect()
    }

    /// Build a `n_type → count` histogram across a raw record slice.
    ///
    /// Useful for surveying which STABS record kinds appear in a binary
    /// before deciding which subset to fully decode.
    #[must_use]
    pub fn record_type_histogram(records: &[StabsRecord]) -> HashMap<u8, usize> {
        let mut out: HashMap<u8, usize> = HashMap::new();
        for r in records {
            *out.entry(r.n_type).or_insert(0) += 1;
        }
        out
    }

    /// Parse a single STABS record, resolving its string as an absolute
    /// `.stabstr` offset.
    ///
    /// Prefer [`Self::parse_all`] for a whole section: it maintains the
    /// `N_UNDF` CU-relative string base, which a single-record call cannot.
    #[must_use]
    pub fn parse_one(&self, r: &StabsRecord) -> ParsedStab {
        Self::parse_record(self.lookup_str(r.n_strx), r)
    }

    /// Parse one record given its already-resolved string.
    fn parse_record(s: &str, r: &StabsRecord) -> ParsedStab {
        match r.n_type {
            N_SO => Self::parse_so(s, r),
            N_SOL => ParsedStab::IncludedFile { path: s.to_string() },
            N_FUN => Self::parse_fun(s, r),
            N_GSYM => Self::parse_typed_sym(s, r, |n, t, v| ParsedStab::GlobalSym { name: n, type_expr: t, address: v }),
            N_STSYM => Self::parse_typed_sym(s, r, |n, t, v| ParsedStab::StaticDataSym { name: n, type_expr: t, address: v }),
            N_LCSYM => Self::parse_typed_sym(s, r, |n, t, v| ParsedStab::StaticBssSym { name: n, type_expr: t, address: v }),
            N_LSYM => {
                let (name, ty) = split_name_type(s);
                let type_expr = parse_type_descriptor(ty);
                ParsedStab::LocalSym { name, type_expr, offset: r.n_value.cast_signed() }
            }
            N_PSYM => {
                let (name, ty) = split_name_type(s);
                let type_expr = parse_type_descriptor(ty);
                ParsedStab::Param { name, type_expr, offset: r.n_value.cast_signed() }
            }
            N_RSYM => {
                let (name, ty) = split_name_type(s);
                let type_expr = parse_type_descriptor(ty);
                ParsedStab::Register { name, type_expr, reg: u8::try_from(r.n_value).unwrap_or(u8::MAX) }
            }
            N_SLINE => ParsedStab::SourceLine { line: r.n_desc, address: r.n_value },
            N_DSLINE => ParsedStab::DataLine { line: r.n_desc, address: r.n_value, in_bss: false },
            N_BSLINE => ParsedStab::DataLine { line: r.n_desc, address: r.n_value, in_bss: true },
            N_LBRAC => ParsedStab::Block { is_begin: true, address: r.n_value },
            N_RBRAC => ParsedStab::Block { is_begin: false, address: r.n_value },
            N_BINCL => ParsedStab::BeginInclude { filename: s.to_string(), sum: r.n_value },
            N_EINCL => ParsedStab::EndInclude,
            N_EXCL => ParsedStab::ExcludeInclude { filename: s.to_string(), sum: r.n_value },
            N_BCOMM => ParsedStab::CommonBlock { name: s.to_string(), is_begin: true },
            N_ECOMM => ParsedStab::CommonBlock { name: s.to_string(), is_begin: false },
            N_ECOML => ParsedStab::EndCommonLocal { address: r.n_value },
            N_ENTRY => ParsedStab::Entry { name: s.to_string(), address: r.n_value },
            N_FNAME => ParsedStab::FunctionName(s.to_string()),
            N_MAIN => ParsedStab::MainName(s.to_string()),
            N_SSYM => ParsedStab::StructSym { name: s.to_string(), offset: r.n_value.cast_signed() },
            N_ROSYM => ParsedStab::RoSym { name: s.to_string(), address: r.n_value },
            N_LENG => ParsedStab::Length(r.n_value),
            _ => ParsedStab::Unknown { n_type: r.n_type, n_strx: r.n_strx, n_desc: r.n_desc, n_value: r.n_value },
        }
    }

    fn parse_so(s: &str, r: &StabsRecord) -> ParsedStab {
        if s.is_empty() {
            // GCC closes a translation unit with an empty N_SO whose
            // n_value carries the end address of the CU's text region.
            // Tag it as an end marker so downstream layers know it's the
            // closing entry rather than a fresh CU opener.
            return ParsedStab::SourceFile {
                path: format!("<end:{:#x}>", r.n_value),
                comp_dir: None,
                is_end: true,
            };
        }
        // GCC emits two SO records: first the directory, then the filename.
        // We return them individually; the reconstructor combines them.
        ParsedStab::SourceFile { path: s.to_string(), comp_dir: None, is_end: false }
    }

    fn parse_fun(s: &str, r: &StabsRecord) -> ParsedStab {
        if s.is_empty() {
            return ParsedStab::Function { name: String::new(), type_expr: None, address: r.n_value, is_end: true };
        }
        let (name, ty) = split_name_type(s);
        let type_expr = if ty.is_empty() { None } else { Some(parse_type_descriptor(ty)) };
        ParsedStab::Function { name, type_expr, address: r.n_value, is_end: false }
    }

    fn parse_typed_sym<F>(s: &str, r: &StabsRecord, ctor: F) -> ParsedStab
    where F: Fn(String, StabsTypeExpr, u32) -> ParsedStab
    {
        let (name, ty) = split_name_type(s);
        let type_expr = parse_type_descriptor(ty);
        ctor(name, type_expr, r.n_value)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Split `"name:type_descriptor"` into `(name, type_descriptor)`.
#[must_use]
pub fn split_name_type(s: &str) -> (String, &str) {
    // `::`-aware: see `crate::split_stab_name`.
    let (name, desc) = crate::split_stab_name(s);
    (name.to_string(), desc)
}

/// Parse a type descriptor string into a [`StabsTypeExpr`].
#[must_use]
pub fn parse_type_descriptor(s: &str) -> StabsTypeExpr {
    if s.is_empty() {
        return StabsTypeExpr::Void;
    }
    let mut parser = TypeDescriptorParser::new(s.as_bytes());
    parser.parse_type()
}

// ─────────────────────────────────────────────────────────────────────────────
// ParseStats
// ─────────────────────────────────────────────────────────────────────────────

/// Summary of a parse run.
#[derive(Debug, Clone, Default)]
pub struct ParseStats {
    /// Total records parsed.
    pub total_records: usize,
    /// `N_SO` source-file records.
    pub source_files: usize,
    /// `N_FUN` function records.
    pub functions: usize,
    /// `N_LSYM` local symbols.
    pub local_syms: usize,
    /// `N_PSYM` parameters.
    pub params: usize,
    /// `N_RSYM` register variables.
    pub registers: usize,
    /// `N_SLINE`/`N_DSLINE`/`N_BSLINE` line records.
    pub line_records: usize,
    /// Unrecognised records.
    pub unknown_records: usize,
}

impl ParseStats {
    /// Compute from parsed records.
    #[must_use]
    pub fn compute(parsed: &[ParsedStab]) -> Self {
        let mut s = Self { total_records: parsed.len(), ..Self::default() };
        for p in parsed {
            match p {
                ParsedStab::SourceFile { .. } => s.source_files += 1,
                ParsedStab::Function { .. } => s.functions += 1,
                ParsedStab::LocalSym { .. } => s.local_syms += 1,
                ParsedStab::Param { .. } => s.params += 1,
                ParsedStab::Register { .. } => s.registers += 1,
                ParsedStab::SourceLine { .. } | ParsedStab::DataLine { .. } => s.line_records += 1,
                ParsedStab::Unknown { .. } => s.unknown_records += 1,
                _ => {}
            }
        }
        s
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_stabstr(strings: &[&str]) -> Vec<u8> {
        let mut out = Vec::new();
        for s in strings {
            out.extend_from_slice(s.as_bytes());
            out.push(0);
        }
        out
    }

    fn make_record(n_strx: u32, n_type: u8, n_desc: u16, n_value: u32) -> StabsRecord {
        StabsRecord { n_strx, n_type, n_other: 0, n_desc, n_value }
    }

    #[test]
    fn test_lookup_str() {
        let stabstr = make_stabstr(&["hello", "world"]);
        let parser = FullStabsParser::new(stabstr);
        assert_eq!(parser.lookup_str(0), "hello");
        assert_eq!(parser.lookup_str(6), "world");
    }

    #[test]
    fn test_parse_so() {
        let stabstr = make_stabstr(&["main.c"]);
        let parser = FullStabsParser::new(stabstr);
        let r = make_record(0, N_SO, 0, 0x4000);
        if let ParsedStab::SourceFile { path, is_end, .. } = parser.parse_one(&r) {
            assert_eq!(path, "main.c");
            assert!(!is_end);
        } else {
            panic!("expected SourceFile");
        }
    }

    #[test]
    fn test_parse_fun() {
        let stabstr = make_stabstr(&["my_func:f(0,1)"]);
        let parser = FullStabsParser::new(stabstr);
        let r = make_record(0, N_FUN, 0, 0x1000);
        if let ParsedStab::Function { name, address, is_end, .. } = parser.parse_one(&r) {
            assert_eq!(name, "my_func");
            assert_eq!(address, 0x1000);
            assert!(!is_end);
        } else {
            panic!("expected Function");
        }
    }

    #[test]
    fn test_parse_lsym() {
        let stabstr = make_stabstr(&["local_var:(0,1)"]);
        let parser = FullStabsParser::new(stabstr);
        let r = make_record(0, N_LSYM, 0, 0xFFFF_FFF0u32); // negative offset
        if let ParsedStab::LocalSym { name, offset, .. } = parser.parse_one(&r) {
            assert_eq!(name, "local_var");
            assert_eq!(offset, -16);
        } else {
            panic!("expected LocalSym");
        }
    }

    #[test]
    fn test_type_descriptor_pointer() {
        let t = parse_type_descriptor("*(0,1)");
        if let StabsTypeExpr::Pointer(inner) = t {
            assert!(matches!(*inner, StabsTypeExpr::TypeRef { .. }));
        } else {
            panic!("expected pointer, got {t:?}");
        }
    }

    #[test]
    fn test_type_descriptor_range() {
        let t = parse_type_descriptor("r(0,1);0;127;");
        if let StabsTypeExpr::Range { lo, hi, .. } = t {
            assert_eq!(lo, 0);
            assert_eq!(hi, 127);
        } else {
            panic!("expected range, got {t:?}");
        }
    }

    #[test]
    fn test_parse_section() {
        // Build a 12-byte stab record.
        let mut data = Vec::new();
        data.extend_from_slice(&0u32.to_le_bytes()); // n_strx
        data.push(N_SO);    // n_type
        data.push(0);       // n_other
        data.extend_from_slice(&0u16.to_le_bytes()); // n_desc
        data.extend_from_slice(&0x4000u32.to_le_bytes()); // n_value
        let records = parse_stab_section(&data);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].n_type, N_SO);
    }

    #[test]
    fn test_parse_stats() {
        let stabstr = make_stabstr(&["file.c", "func:f(0,1)", "param:p(0,1)"]);
        let parser = FullStabsParser::new(stabstr);
        let records = vec![
            make_record(0, N_SO, 0, 0),
            make_record(6, N_FUN, 0, 0x1000),
            make_record(19, N_PSYM, 0, 8),
        ];
        let parsed = parser.parse_all(&records);
        let stats = ParseStats::compute(&parsed);
        assert_eq!(stats.source_files, 1);
        assert_eq!(stats.functions, 1);
        assert_eq!(stats.params, 1);
    }
}
