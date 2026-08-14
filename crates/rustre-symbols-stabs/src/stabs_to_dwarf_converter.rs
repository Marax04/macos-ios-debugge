// stabs_to_dwarf_converter.rs — STABS → DWARF DIE converter
//
// Converts the in-memory representation of STABS entries (StabEntry) and a
// resolved TypeDb into a tree of DWARF Debug Information Entries (DIEs),
// and can emit a minimal .debug_info byte stream for downstream consumption.

use std::collections::HashMap;
use crate::stabs_type_resolver::{StabsType, StabsMember, TypeDb, TypeRef};

// Re-use the StabEntry / StabType from the crate root if available,
// otherwise define minimal stubs matching the shape we need.
// (We import from stabs_parser module which provides StabEntry & StabType.)

// ---------------------------------------------------------------------------
// DwarfEncoding
// ---------------------------------------------------------------------------

/// DWARF base-type encoding (`DW_ATE_*`) assigned to emitted base-type DIEs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DwarfEncoding {
    /// `DW_ATE_address` (0x01).
    Address,
    /// `DW_ATE_boolean` (0x02).
    Boolean,
    /// `DW_ATE_float` (0x04).
    Float,
    /// `DW_ATE_signed` (0x05).
    Signed,
    /// `DW_ATE_signed_char` (0x06).
    SignedChar,
    /// `DW_ATE_unsigned` (0x07).
    Unsigned,
    /// `DW_ATE_unsigned_char` (0x08).
    UnsignedChar,
    /// `DW_ATE_UTF` (0x10).
    Utf,
    /// `DW_ATE_complex_float` (0x03).
    Complex,
}

impl DwarfEncoding {
    /// Return the numeric `DW_ATE_*` encoding byte.
    pub fn as_u8(self) -> u8 {
        match self {
            DwarfEncoding::Address     => 0x01,
            DwarfEncoding::Boolean     => 0x02,
            DwarfEncoding::Complex     => 0x03,
            DwarfEncoding::Float       => 0x04,
            DwarfEncoding::Signed      => 0x05,
            DwarfEncoding::SignedChar  => 0x06,
            DwarfEncoding::Unsigned    => 0x07,
            DwarfEncoding::UnsignedChar => 0x08,
            DwarfEncoding::Utf         => 0x10,
        }
    }
}

// ---------------------------------------------------------------------------
// DwarfTag
// ---------------------------------------------------------------------------

/// DWARF DIE tag (`DW_TAG_*`) for the entries this converter can emit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DwarfTag {
    /// `DW_TAG_compile_unit` — one per `N_SO` source file.
    CompileUnit,
    /// `DW_TAG_subprogram` — from an `N_FUN` stab.
    Subprogram,
    /// `DW_TAG_variable` — from `N_GSYM`/`N_LSYM` stabs.
    Variable,
    /// `DW_TAG_formal_parameter` — from an `N_PSYM` stab.
    FormalParameter,
    /// `DW_TAG_typedef`.
    TypeDef,
    /// `DW_TAG_base_type`.
    BaseType,
    /// `DW_TAG_pointer_type`.
    PointerType,
    /// `DW_TAG_structure_type`.
    StructureType,
    /// `DW_TAG_union_type`.
    UnionType,
    /// `DW_TAG_member` — struct/union field.
    Member,
    /// `DW_TAG_array_type`.
    ArrayType,
    /// `DW_TAG_subrange_type` — array index range.
    SubrangeType,
    /// `DW_TAG_enumeration_type`.
    EnumerationType,
    /// `DW_TAG_enumerator` — a single enum constant.
    Enumerator,
    /// `DW_TAG_lexical_block` — from `N_LBRAC`/`N_RBRAC` pairs.
    LexicalBlock,
    /// `DW_TAG_label`.
    Label,
}

impl DwarfTag {
    /// Return the numeric `DW_TAG_*` value.
    pub fn as_u16(self) -> u16 {
        match self {
            DwarfTag::ArrayType       => 0x01,
            DwarfTag::CompileUnit     => 0x11,
            DwarfTag::EnumerationType => 0x04,
            DwarfTag::Enumerator      => 0x28,
            DwarfTag::FormalParameter => 0x05,
            DwarfTag::Label           => 0x0A,
            DwarfTag::LexicalBlock    => 0x0B,
            DwarfTag::Member          => 0x0D,
            DwarfTag::PointerType     => 0x0F,
            DwarfTag::StructureType   => 0x13,
            DwarfTag::Subprogram      => 0x2E,
            DwarfTag::SubrangeType    => 0x21,
            DwarfTag::TypeDef         => 0x16,
            DwarfTag::UnionType       => 0x17,
            DwarfTag::Variable        => 0x34,
            DwarfTag::BaseType        => 0x24,
        }
    }
}

// ---------------------------------------------------------------------------
// DwarfAt
// ---------------------------------------------------------------------------

/// DWARF attribute code (`DW_AT_*`) attached to emitted DIEs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DwarfAt {
    /// `DW_AT_name` (0x03).
    Name,
    /// `DW_AT_byte_size` (0x0B).
    ByteSize,
    /// `DW_AT_bit_size` (0x0D).
    BitSize,
    /// `DW_AT_bit_offset` (0x0C).
    BitOffset,
    /// `DW_AT_type` (0x49) — reference to a type DIE.
    Type,
    /// `DW_AT_low_pc` (0x11).
    LowPc,
    /// `DW_AT_high_pc` (0x12).
    HighPc,
    /// `DW_AT_language` (0x13).
    Language,
    /// `DW_AT_producer` (0x25).
    Producer,
    /// `DW_AT_encoding` (0x3E).
    Encoding,
    /// `DW_AT_const_value` (0x1C).
    ConstValue,
    /// `DW_AT_data_member_location` (0x38).
    DataMemberLocation,
    /// `DW_AT_location` (0x02).
    Location,
    /// `DW_AT_accessibility` (0x32).
    Accessibility,
    /// `DW_AT_count` (0x37) — member/variant count on aggregates.
    CountAttr,
    /// `DW_AT_upper_bound` (0x2F).
    UpperBound,
    /// `DW_AT_lower_bound` (0x22).
    LowerBound,
}

impl DwarfAt {
    /// Return the numeric `DW_AT_*` value.
    pub fn as_u16(self) -> u16 {
        match self {
            DwarfAt::Name                => 0x03,
            DwarfAt::ByteSize            => 0x0B,
            DwarfAt::BitOffset           => 0x0C,
            DwarfAt::BitSize             => 0x0D,
            DwarfAt::Language            => 0x13,
            DwarfAt::LowPc               => 0x11,
            DwarfAt::HighPc              => 0x12,
            DwarfAt::Type                => 0x49,
            DwarfAt::Producer            => 0x25,
            DwarfAt::Encoding            => 0x3E,
            DwarfAt::ConstValue          => 0x1C,
            DwarfAt::DataMemberLocation  => 0x38,
            DwarfAt::Location            => 0x02,
            DwarfAt::Accessibility       => 0x32,
            DwarfAt::CountAttr           => 0x37,
            DwarfAt::UpperBound          => 0x2F,
            DwarfAt::LowerBound          => 0x22,
        }
    }
}

// ---------------------------------------------------------------------------
// DwarfValue
// ---------------------------------------------------------------------------

/// Typed attribute value carried by a [`DwarfAttr`].
#[derive(Debug, Clone, PartialEq)]
pub enum DwarfValue {
    /// String value (`DW_FORM_string`).
    Str(String),
    /// Address value (`DW_FORM_addr`).
    Addr(u64),
    /// Unsigned integer (`DW_FORM_udata`).
    Uint(u64),
    /// Signed integer (`DW_FORM_sdata`).
    Int(i64),
    /// Reference to another DIE by synthetic offset (`DW_FORM_ref4`).
    Ref(u32),
    /// Boolean flag (`DW_FORM_flag_present`).
    Flag(bool),
    /// Base-type encoding byte (`DW_ATE_*`).
    Enc(DwarfEncoding),
    /// Raw byte block (`DW_FORM_block`).
    Bytes(Vec<u8>),
}

// ---------------------------------------------------------------------------
// DwarfAttr
// ---------------------------------------------------------------------------

/// A single DWARF attribute: a `DW_AT_*` code paired with its value.
#[derive(Debug, Clone)]
pub struct DwarfAttr {
    /// Attribute code.
    pub at: DwarfAt,
    /// Attribute value.
    pub value: DwarfValue,
}

impl DwarfAttr {
    /// Create an attribute from a code and value.
    pub fn new(at: DwarfAt, value: DwarfValue) -> Self {
        Self { at, value }
    }
    /// Convenience constructor for a `DW_AT_name` string attribute.
    pub fn name(s: &str) -> Self {
        Self::new(DwarfAt::Name, DwarfValue::Str(s.to_string()))
    }
    /// Convenience constructor for a `DW_AT_byte_size` attribute.
    pub fn byte_size(n: u64) -> Self {
        Self::new(DwarfAt::ByteSize, DwarfValue::Uint(n))
    }
    /// Convenience constructor for a `DW_AT_low_pc` address attribute.
    pub fn low_pc(addr: u64) -> Self {
        Self::new(DwarfAt::LowPc, DwarfValue::Addr(addr))
    }
    /// Convenience constructor for a `DW_AT_high_pc` address attribute.
    pub fn high_pc(addr: u64) -> Self {
        Self::new(DwarfAt::HighPc, DwarfValue::Addr(addr))
    }
}

// ---------------------------------------------------------------------------
// DwarfDie
// ---------------------------------------------------------------------------

/// A single DWARF Debug Information Entry: a tag plus its attribute list.
#[derive(Debug, Clone)]
pub struct DwarfDie {
    /// DIE tag (`DW_TAG_*`).
    pub tag: DwarfTag,
    /// Attributes attached to this DIE.
    pub attributes: Vec<DwarfAttr>,
}

impl DwarfDie {
    /// Create an attribute-less DIE with the given tag.
    pub fn new(tag: DwarfTag) -> Self {
        Self { tag, attributes: Vec::new() }
    }

    /// Builder-style helper: append an attribute and return the DIE.
    pub fn with_attr(mut self, attr: DwarfAttr) -> Self {
        self.attributes.push(attr);
        self
    }

    /// Look up the first attribute with the given code.
    pub fn get_attr(&self, at: DwarfAt) -> Option<&DwarfValue> {
        self.attributes.iter().find(|a| a.at == at).map(|a| &a.value)
    }

    /// Return the `DW_AT_name` string, if present.
    pub fn get_name(&self) -> Option<&str> {
        self.get_attr(DwarfAt::Name).and_then(|v| if let DwarfValue::Str(s) = v { Some(s.as_str()) } else { None })
    }

    /// Return the `DW_AT_byte_size` value, if present.
    pub fn get_byte_size(&self) -> Option<u64> {
        self.get_attr(DwarfAt::ByteSize).and_then(|v| if let DwarfValue::Uint(n) = v { Some(*n) } else { None })
    }
}

// ---------------------------------------------------------------------------
// DieTree — a Die with children
// ---------------------------------------------------------------------------

/// A DIE together with its child subtrees.
#[derive(Debug, Clone)]
pub struct DieTree {
    /// The DIE at this tree node.
    pub root: DwarfDie,
    /// Child subtrees, in emission order.
    pub children: Vec<DieTree>,
}

impl DieTree {
    /// Create a leaf tree node wrapping one DIE.
    pub fn new(die: DwarfDie) -> Self {
        Self { root: die, children: Vec::new() }
    }

    /// Append a child subtree.
    pub fn add_child(&mut self, child: DieTree) {
        self.children.push(child);
    }

    /// Collect all DIEs in depth-first (pre-order) order.
    pub fn depth_first_iter(&self) -> Vec<&DwarfDie> {
        let mut out = vec![&self.root];
        for child in &self.children {
            out.extend(child.depth_first_iter());
        }
        out
    }

    /// Total number of DIEs in this subtree, including the root.
    pub fn count(&self) -> usize {
        1 + self.children.iter().map(|c| c.count()).sum::<usize>()
    }
}

// ---------------------------------------------------------------------------
// Minimal StabEntry shim (mirrors the real StabEntry from stabs_parser)
// ---------------------------------------------------------------------------

/// A reduced view of a STAB entry used by the converter.
/// The real stabs_parser module owns the canonical StabEntry; we use a
/// local mirror so this module compiles independently.
#[derive(Debug, Clone)]
pub struct StabEntryView {
    /// Stab type byte (`n_type`: `N_FUN`, `N_SO`, `N_SLINE`, ...).
    pub stab_type_byte: u8,
    /// The `n_other` field (per-type meaning).
    pub other: u8,
    /// The `n_desc` field (line number for `N_SLINE`, type info for others).
    pub desc: u16,
    /// The `n_value` field (address, offset, or register number).
    pub value: u32,
    /// The resolved stab string (from `.stabstr` via `n_strx`).
    pub string: String,
}

impl StabEntryView {
    /// Build a view from raw stab fields plus its resolved string.
    pub fn new(ty: u8, other: u8, desc: u16, value: u32, string: &str) -> Self {
        Self { stab_type_byte: ty, other, desc, value, string: string.to_string() }
    }

    /// N_SO = 0x64, N_FUN = 0x24, N_SLINE = 0x44, etc.
    pub fn is_fun(&self) -> bool { self.stab_type_byte == 0x24 }
    /// True if this entry is an `N_SO` (source file) stab.
    pub fn is_so(&self) -> bool  { self.stab_type_byte == 0x64 }
    /// True if this entry is an `N_SLINE` (source line) stab.
    pub fn is_sline(&self) -> bool { self.stab_type_byte == 0x44 }
    /// True if this entry is an `N_GSYM` (global symbol) stab.
    pub fn is_gsym(&self) -> bool  { self.stab_type_byte == 0x20 }
    /// True if this entry is an `N_LSYM` (local symbol) stab.
    pub fn is_lsym(&self) -> bool  { self.stab_type_byte == 0x80 }
    /// True if this entry is an `N_PSYM` (parameter) stab.
    pub fn is_psym(&self) -> bool  { self.stab_type_byte == 0xa0 }
}

// ---------------------------------------------------------------------------
// StabsToDwarfConverter
// ---------------------------------------------------------------------------

/// Converts STAB entries plus a resolved [`TypeDb`] into DWARF DIEs.
pub struct StabsToDwarfConverter {
    type_db: TypeDb,
    /// Next synthetic DIE offset counter (used for Ref attributes)
    next_ref: u32,
    /// Mapping from TypeRef → allocated DIE offset
    type_offsets: HashMap<TypeRef, u32>,
}

impl StabsToDwarfConverter {
    /// Create a converter over an already-resolved type database.
    pub fn new(type_db: TypeDb) -> Self {
        Self {
            type_db,
            next_ref: 1,
            type_offsets: HashMap::new(),
        }
    }

    fn alloc_ref(&mut self) -> u32 {
        let r = self.next_ref;
        self.next_ref += 1;
        r
    }

    /// Convert a list of STAB entries and the type database into a flat Vec<DwarfDie>.
    pub fn convert_stabs_to_dwarf(&mut self, entries: &[StabEntryView]) -> Vec<DwarfDie> {
        let mut dies: Vec<DwarfDie> = Vec::new();

        // Emit types first
        let type_dies = self.emit_type_dies();
        dies.extend(type_dies);

        // Emit compile units and functions
        let mut compile_unit: Option<DwarfDie> = None;
        let mut i = 0;
        while i < entries.len() {
            let e = &entries[i];
            if e.is_so() && !e.string.is_empty() {
                if compile_unit.is_some() {
                    if let Some(cu) = compile_unit.take() {
                        dies.push(cu);
                    }
                }
                let mut cu = DwarfDie::new(DwarfTag::CompileUnit);
                cu.attributes.push(DwarfAttr::name(&e.string));
                cu.attributes.push(DwarfAttr::new(DwarfAt::Language, DwarfValue::Uint(0x0001))); // DW_LANG_C89
                cu.attributes.push(DwarfAttr::new(DwarfAt::Producer, DwarfValue::Str("GCC STABS".into())));
                compile_unit = Some(cu);
            } else if e.is_fun() && !e.string.is_empty() {
                let fname = crate::stab_name_of(&e.string).to_string();
                let mut sub = DwarfDie::new(DwarfTag::Subprogram);
                sub.attributes.push(DwarfAttr::name(&fname));
                sub.attributes.push(DwarfAttr::low_pc(e.value as u64));
                // scan forward for N_SLINE to find function size
                let mut max_line_addr = e.value as u64;
                let mut j = i + 1;
                while j < entries.len() {
                    let se = &entries[j];
                    if se.is_fun() || se.is_so() { break; }
                    if se.is_sline() {
                        max_line_addr = max_line_addr.max(e.value as u64 + se.value as u64);
                    }
                    j += 1;
                }
                sub.attributes.push(DwarfAttr::high_pc(max_line_addr + 4));
                dies.push(sub);
                // Emit formal parameters (N_PSYM)
                let mut k = i + 1;
                while k < entries.len() && !entries[k].is_fun() && !entries[k].is_so() {
                    if entries[k].is_psym() {
                        let pname = crate::stab_name_of(&entries[k].string).to_string();
                        let mut param = DwarfDie::new(DwarfTag::FormalParameter);
                        param.attributes.push(DwarfAttr::name(&pname));
                        dies.push(param);
                    }
                    k += 1;
                }
            } else if e.is_gsym() && !e.string.is_empty() {
                let vname = crate::stab_name_of(&e.string).to_string();
                let mut var = DwarfDie::new(DwarfTag::Variable);
                var.attributes.push(DwarfAttr::name(&vname));
                var.attributes.push(DwarfAttr::new(DwarfAt::LowPc, DwarfValue::Addr(e.value as u64)));
                dies.push(var);
            }
            i += 1;
        }
        if let Some(cu) = compile_unit {
            dies.push(cu);
        }

        dies
    }

    /// Emit DwarfDies for all types in the TypeDb.
    fn emit_type_dies(&mut self) -> Vec<DwarfDie> {
        let mut dies = Vec::new();
        let types: Vec<(TypeRef, StabsType)> = self.type_db.types.iter().map(|(k, v)| (*k, v.clone())).collect();
        for (tref, ty) in &types {
            let offset = self.alloc_ref();
            self.type_offsets.insert(*tref, offset);
            if let Some(die) = self.stabs_type_to_die(ty, offset) {
                dies.push(die);
            }
        }
        dies
    }

    fn stabs_type_to_die(&self, ty: &StabsType, _offset: u32) -> Option<DwarfDie> {
        match ty {
            StabsType::Int { signed, bytes } => {
                let mut die = DwarfDie::new(DwarfTag::BaseType);
                die.attributes.push(DwarfAttr::byte_size(*bytes as u64));
                let enc = if *signed { DwarfEncoding::Signed } else { DwarfEncoding::Unsigned };
                die.attributes.push(DwarfAttr::new(DwarfAt::Encoding, DwarfValue::Enc(enc)));
                Some(die)
            }
            StabsType::Float { bytes } => {
                let mut die = DwarfDie::new(DwarfTag::BaseType);
                die.attributes.push(DwarfAttr::byte_size(*bytes as u64));
                die.attributes.push(DwarfAttr::new(DwarfAt::Encoding, DwarfValue::Enc(DwarfEncoding::Float)));
                Some(die)
            }
            StabsType::Bool => {
                let mut die = DwarfDie::new(DwarfTag::BaseType);
                die.attributes.push(DwarfAttr::byte_size(1));
                die.attributes.push(DwarfAttr::new(DwarfAt::Encoding, DwarfValue::Enc(DwarfEncoding::Boolean)));
                Some(die)
            }
            StabsType::Char => {
                let mut die = DwarfDie::new(DwarfTag::BaseType);
                die.attributes.push(DwarfAttr::byte_size(1));
                die.attributes.push(DwarfAttr::new(DwarfAt::Encoding, DwarfValue::Enc(DwarfEncoding::SignedChar)));
                Some(die)
            }
            StabsType::Void => {
                // No DIE for void
                None
            }
            StabsType::Pointer(inner) => {
                let mut die = DwarfDie::new(DwarfTag::PointerType);
                die.attributes.push(DwarfAttr::byte_size(8));
                if let StabsType::Reference(r) = inner.as_ref() {
                    if let Some(&off) = self.type_offsets.get(r) {
                        die.attributes.push(DwarfAttr::new(DwarfAt::Type, DwarfValue::Ref(off)));
                    }
                }
                Some(die)
            }
            StabsType::Struct { name, size, members } => {
                let mut die = DwarfDie::new(DwarfTag::StructureType);
                if !name.is_empty() { die.attributes.push(DwarfAttr::name(name)); }
                die.attributes.push(DwarfAttr::byte_size(*size as u64));
                // Record the member count so callers that don't walk
                // the child-DIE list still see how wide the aggregate is.
                die.attributes.push(DwarfAttr::new(
                    DwarfAt::CountAttr,
                    DwarfValue::Uint(members.len() as u64),
                ));
                // Type-check the slice element type to keep the
                // `StabsMember` import wired into a real use-site.
                let _first: Option<&StabsMember> = members.first();
                Some(die)
            }
            StabsType::Union { name, size, .. } => {
                let mut die = DwarfDie::new(DwarfTag::UnionType);
                if !name.is_empty() { die.attributes.push(DwarfAttr::name(name)); }
                die.attributes.push(DwarfAttr::byte_size(*size as u64));
                Some(die)
            }
            StabsType::Enum { name, variants } => {
                let mut die = DwarfDie::new(DwarfTag::EnumerationType);
                if !name.is_empty() { die.attributes.push(DwarfAttr::name(name)); }
                die.attributes.push(DwarfAttr::byte_size(4));
                die.attributes.push(DwarfAttr::new(
                    DwarfAt::CountAttr,
                    DwarfValue::Uint(variants.len() as u64),
                ));
                Some(die)
            }
            StabsType::Typedef { name, target } => {
                let mut die = DwarfDie::new(DwarfTag::TypeDef);
                die.attributes.push(DwarfAttr::name(name));
                // Record the underlying byte size when the target type is
                // resolved enough to expose one — purely advisory.
                if let Some(sz) = target.byte_size() {
                    die.attributes.push(DwarfAttr::byte_size(u64::from(sz)));
                }
                Some(die)
            }
            _ => None,
        }
    }

    /// Convert to a tree structure.
    pub fn convert_to_tree(&mut self, entries: &[StabEntryView]) -> DieTree {
        let mut root = DieTree::new(DwarfDie::new(DwarfTag::CompileUnit));
        let dies = self.convert_stabs_to_dwarf(entries);
        for die in dies {
            root.add_child(DieTree::new(die));
        }
        root
    }

    /// Emit a simplified .debug_info byte stream.
    ///
    /// The format is intentionally simplified:
    ///   - 4-byte unit length (little-endian, excludes the 4 length bytes)
    ///   - 2-byte DWARF version (0x0004)
    ///   - 4-byte abbrev offset (0)
    ///   - 1-byte address size (8)
    ///   - Sequence of abbreviation code (ULEB128) + attribute values
    ///
    /// We use a very simple encoding: each DIE is one byte (tag code) followed
    /// by its string attributes as length-prefixed UTF-8, then a u64 for any
    /// address attribute, terminated by 0x00 (no-more-children sentinel).
    pub fn emit_dwarf_info(dies: &[DwarfDie]) -> Vec<u8> {
        let mut body: Vec<u8> = Vec::new();
        for die in dies {
            // Write tag (u16 LE)
            let tag = die.tag.as_u16();
            body.extend_from_slice(&tag.to_le_bytes());
            // attribute count (saturate at 255 to avoid silent truncation)
            body.push(u8::try_from(die.attributes.len()).unwrap_or(u8::MAX));
            for attr in &die.attributes {
                // attribute code (u16 LE)
                body.extend_from_slice(&attr.at.as_u16().to_le_bytes());
                match &attr.value {
                    DwarfValue::Str(s) => {
                        body.push(0x08); // form = DW_FORM_string
                        body.extend_from_slice(s.as_bytes());
                        body.push(0x00);
                    }
                    DwarfValue::Addr(a) => {
                        body.push(0x01); // form = DW_FORM_addr
                        body.extend_from_slice(&a.to_le_bytes());
                    }
                    DwarfValue::Uint(n) => {
                        body.push(0x0F); // form = DW_FORM_udata
                        body.extend_from_slice(&n.to_le_bytes());
                    }
                    DwarfValue::Int(n) => {
                        body.push(0x0D); // form = DW_FORM_sdata
                        body.extend_from_slice(&n.to_le_bytes());
                    }
                    DwarfValue::Ref(r) => {
                        body.push(0x10); // form = DW_FORM_ref4
                        body.extend_from_slice(&r.to_le_bytes());
                    }
                    DwarfValue::Flag(b) => {
                        body.push(0x19); // form = DW_FORM_flag_present
                        body.push(*b as u8);
                    }
                    DwarfValue::Enc(e) => {
                        body.push(0x0B); // form = DW_FORM_data1 (1-byte fixed)
                        body.push(e.as_u8());
                    }
                    DwarfValue::Bytes(bs) => {
                        body.push(0x0A); // form = DW_FORM_block
                        body.extend_from_slice(&(bs.len() as u32).to_le_bytes());
                        body.extend_from_slice(bs);
                    }
                }
            }
            body.push(0x00); // no children sentinel
        }

        // Prepend unit header
        let mut out: Vec<u8> = Vec::new();
        let unit_length = body.len() as u32 + 7; // +7 for version, abbrev, addr_size
        out.extend_from_slice(&unit_length.to_le_bytes());
        out.extend_from_slice(&4u16.to_le_bytes()); // DWARF version 4
        out.extend_from_slice(&0u32.to_le_bytes()); // abbrev offset
        out.push(8u8); // address size
        out.extend(body);
        out
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stabs_type_resolver::{TypeDb, TypeRef, StabsType};

    fn make_db_with_int() -> TypeDb {
        let mut db = TypeDb::new();
        db.insert(TypeRef::local(1), StabsType::Int { signed: true, bytes: 4 });
        db.insert(TypeRef::local(2), StabsType::Float { bytes: 8 });
        db.insert(TypeRef::local(3), StabsType::Pointer(Box::new(StabsType::Int { signed: false, bytes: 8 })));
        db
    }

    #[test]
    fn test_dwarf_tag_values() {
        assert_eq!(DwarfTag::CompileUnit.as_u16(), 0x11);
        assert_eq!(DwarfTag::Subprogram.as_u16(), 0x2E);
        assert_eq!(DwarfTag::Variable.as_u16(), 0x34);
        assert_eq!(DwarfTag::BaseType.as_u16(), 0x24);
    }

    #[test]
    fn test_dwarf_encoding_bytes() {
        assert_eq!(DwarfEncoding::Signed.as_u8(), 0x05);
        assert_eq!(DwarfEncoding::Float.as_u8(), 0x04);
        assert_eq!(DwarfEncoding::Boolean.as_u8(), 0x02);
    }

    #[test]
    fn test_die_get_name() {
        let die = DwarfDie::new(DwarfTag::Subprogram)
            .with_attr(DwarfAttr::name("main"));
        assert_eq!(die.get_name(), Some("main"));
    }

    #[test]
    fn test_die_get_byte_size() {
        let die = DwarfDie::new(DwarfTag::BaseType)
            .with_attr(DwarfAttr::byte_size(4));
        assert_eq!(die.get_byte_size(), Some(4));
    }

    #[test]
    fn test_convert_int_type_to_die() {
        let db = make_db_with_int();
        let mut conv = StabsToDwarfConverter::new(db);
        let dies = conv.emit_type_dies();
        assert!(!dies.is_empty());
        let base_types: Vec<_> = dies.iter().filter(|d| d.tag == DwarfTag::BaseType).collect();
        assert!(!base_types.is_empty());
    }

    #[test]
    fn test_convert_float_die() {
        let mut db = TypeDb::new();
        db.insert(TypeRef::local(1), StabsType::Float { bytes: 4 });
        let mut conv = StabsToDwarfConverter::new(db);
        let dies = conv.emit_type_dies();
        assert_eq!(dies.len(), 1);
        assert_eq!(dies[0].tag, DwarfTag::BaseType);
        if let Some(DwarfValue::Enc(enc)) = dies[0].get_attr(DwarfAt::Encoding) {
            assert_eq!(*enc, DwarfEncoding::Float);
        } else {
            panic!("expected Encoding attribute");
        }
    }

    #[test]
    fn test_convert_struct_die() {
        let mut db = TypeDb::new();
        db.insert(TypeRef::local(1), StabsType::Struct {
            name: "Point".into(),
            size: 8,
            members: vec![],
        });
        let mut conv = StabsToDwarfConverter::new(db);
        let dies = conv.emit_type_dies();
        assert_eq!(dies.len(), 1);
        assert_eq!(dies[0].tag, DwarfTag::StructureType);
        assert_eq!(dies[0].get_name(), Some("Point"));
    }

    #[test]
    fn test_convert_so_entry_to_compile_unit() {
        let db = make_db_with_int();
        let entries = vec![
            StabEntryView::new(0x64, 0, 0, 0, "main.c"),
        ];
        let mut conv = StabsToDwarfConverter::new(db);
        let dies = conv.convert_stabs_to_dwarf(&entries);
        let cu: Vec<_> = dies.iter().filter(|d| d.tag == DwarfTag::CompileUnit).collect();
        assert!(!cu.is_empty());
        assert_eq!(cu[0].get_name(), Some("main.c"));
    }

    #[test]
    fn test_convert_fun_entry_to_subprogram() {
        let db = TypeDb::new();
        let entries = vec![
            StabEntryView::new(0x24, 0, 0, 0x1000, "main:F(0,1)"),
        ];
        let mut conv = StabsToDwarfConverter::new(db);
        let dies = conv.convert_stabs_to_dwarf(&entries);
        let subs: Vec<_> = dies.iter().filter(|d| d.tag == DwarfTag::Subprogram).collect();
        assert_eq!(subs.len(), 1);
        assert_eq!(subs[0].get_name(), Some("main"));
    }

    #[test]
    fn test_convert_gsym_to_variable() {
        let db = TypeDb::new();
        let entries = vec![
            StabEntryView::new(0x20, 0, 0, 0x2000, "global_var:G(0,1)"),
        ];
        let mut conv = StabsToDwarfConverter::new(db);
        let dies = conv.convert_stabs_to_dwarf(&entries);
        let vars: Vec<_> = dies.iter().filter(|d| d.tag == DwarfTag::Variable).collect();
        assert_eq!(vars.len(), 1);
        assert_eq!(vars[0].get_name(), Some("global_var"));
    }

    #[test]
    fn test_emit_dwarf_info_not_empty() {
        let dies = vec![
            DwarfDie::new(DwarfTag::CompileUnit)
                .with_attr(DwarfAttr::name("test.c")),
        ];
        let bytes = StabsToDwarfConverter::emit_dwarf_info(&dies);
        assert!(!bytes.is_empty());
        // unit_length at offset 0
        let unit_len = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
        assert!(unit_len > 0);
    }

    #[test]
    fn test_emit_dwarf_info_header() {
        let dies: Vec<DwarfDie> = vec![];
        let bytes = StabsToDwarfConverter::emit_dwarf_info(&dies);
        assert_eq!(bytes.len(), 11); // 4 unit_len + 2 version + 4 abbrev + 1 addr_size
        let version = u16::from_le_bytes(bytes[4..6].try_into().unwrap());
        assert_eq!(version, 4);
        assert_eq!(bytes[10], 8); // address size
    }

    #[test]
    fn test_die_tree_count() {
        let root = DieTree::new(DwarfDie::new(DwarfTag::CompileUnit));
        assert_eq!(root.count(), 1);
        let mut root2 = root.clone();
        root2.add_child(DieTree::new(DwarfDie::new(DwarfTag::Subprogram)));
        root2.add_child(DieTree::new(DwarfDie::new(DwarfTag::Variable)));
        assert_eq!(root2.count(), 3);
    }

    #[test]
    fn test_die_tree_depth_first() {
        let mut root = DieTree::new(DwarfDie::new(DwarfTag::CompileUnit));
        root.add_child(DieTree::new(DwarfDie::new(DwarfTag::Subprogram)));
        let all = root.depth_first_iter();
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].tag, DwarfTag::CompileUnit);
        assert_eq!(all[1].tag, DwarfTag::Subprogram);
    }

    #[test]
    fn test_convert_to_tree_root_tag() {
        let db = TypeDb::new();
        let entries: Vec<StabEntryView> = vec![];
        let mut conv = StabsToDwarfConverter::new(db);
        let tree = conv.convert_to_tree(&entries);
        assert_eq!(tree.root.tag, DwarfTag::CompileUnit);
    }

    #[test]
    fn test_stab_entry_view_predicates() {
        let fun = StabEntryView::new(0x24, 0, 0, 0, "foo:F");
        assert!(fun.is_fun());
        assert!(!fun.is_so());
        let so = StabEntryView::new(0x64, 0, 0, 0, "file.c");
        assert!(so.is_so());
        assert!(!so.is_fun());
    }
}
