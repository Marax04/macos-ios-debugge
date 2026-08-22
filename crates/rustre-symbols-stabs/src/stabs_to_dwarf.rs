// stabs_to_dwarf.rs — Convert STABS debug information into a DWARF-like internal representation
//
// This module bridges the gap between the STABS-parsed CompilationUnit/ParsedFunction
// structures from stabs_parser.rs and a normalized set of DIEs (Debug Info Entries)
// that match the DWARF data model closely enough for consumers to work with both.
//
// Supported conversions:
//   STABS CompilationUnit    → DW_TAG_compile_unit
//   STABS ParsedFunction     → DW_TAG_subprogram
//   STABS Parameter          → DW_TAG_formal_parameter
//   STABS LocalVar           → DW_TAG_variable
//   STABS RegisterVar        → DW_TAG_variable (with DW_AT_location = register)
//   STABS GlobalSymbol       → DW_TAG_variable (external)
//   STABS StabType::Struct   → DW_TAG_structure_type / DW_TAG_union_type
//   STABS StabType::Enum     → DW_TAG_enumeration_type
//   STABS StructField        → DW_TAG_member
//   STABS EnumVariant        → DW_TAG_enumerator
//   STABS line entries       → DW_TAG_line_info (synthetic)

use std::collections::HashMap;
use crate::stabs_parser::{CompilationUnit, ParsedFunction, GlobalSymbol, LocalVar, Parameter, RegisterVar};
use crate::stabs_type_decoder::{StabType, StructField, EnumVariant, TypeDatabase, decode_type};

// ── DWARF tag constants (subset used here) ────────────────────────────────────

/// DWARF DIE tag constants (`DW_TAG_*`) used by the converter.
pub mod dw_tag {
    /// `DW_TAG_compile_unit`.
    pub const COMPILE_UNIT: u16 = 0x0011;
    /// `DW_TAG_subprogram`.
    pub const SUBPROGRAM: u16 = 0x002E;
    /// `DW_TAG_formal_parameter`.
    pub const FORMAL_PARAMETER: u16 = 0x0005;
    /// `DW_TAG_variable`.
    pub const VARIABLE: u16 = 0x0034;
    /// `DW_TAG_base_type`.
    pub const BASE_TYPE: u16 = 0x0024;
    /// `DW_TAG_pointer_type`.
    pub const POINTER_TYPE: u16 = 0x000F;
    /// `DW_TAG_reference_type`.
    pub const REFERENCE_TYPE: u16 = 0x0010;
    /// `DW_TAG_array_type`.
    pub const ARRAY_TYPE: u16 = 0x0001;
    /// `DW_TAG_structure_type`.
    pub const STRUCTURE_TYPE: u16 = 0x0013;
    /// `DW_TAG_union_type`.
    pub const UNION_TYPE: u16 = 0x0017;
    /// `DW_TAG_enumeration_type`.
    pub const ENUMERATION_TYPE: u16 = 0x0004;
    /// `DW_TAG_member`.
    pub const MEMBER: u16 = 0x000D;
    /// `DW_TAG_enumerator`.
    pub const ENUMERATOR: u16 = 0x0028;
    /// `DW_TAG_typedef`.
    pub const TYPEDEF: u16 = 0x0016;
    /// `DW_TAG_const_type`.
    pub const CONST_TYPE: u16 = 0x0026;
    /// `DW_TAG_volatile_type`.
    pub const VOLATILE_TYPE: u16 = 0x0035;
    /// `DW_TAG_subrange_type`.
    pub const SUBRANGE_TYPE: u16 = 0x0021;
    /// `DW_TAG_inlined_subroutine`.
    pub const INLINED_SUBROUTINE: u16 = 0x001D;
    /// `DW_TAG_lexical_block`.
    pub const LEXICAL_BLOCK: u16 = 0x000B;
}

/// DWARF attribute constants (`DW_AT_*`) used by the converter.
pub mod dw_at {
    /// `DW_AT_name`.
    pub const NAME: u16 = 0x03;
    /// `DW_AT_byte_size`.
    pub const BYTE_SIZE: u16 = 0x0B;
    /// `DW_AT_bit_offset`.
    pub const BIT_OFFSET: u16 = 0x0C;
    /// `DW_AT_bit_size`.
    pub const BIT_SIZE: u16 = 0x0D;
    /// `DW_AT_comp_dir`.
    pub const COMP_DIR: u16 = 0x1B;
    /// `DW_AT_const_value`.
    pub const CONST_VALUE: u16 = 0x1C;
    /// `DW_AT_external`.
    pub const EXTERNAL: u16 = 0x3F;
    /// `DW_AT_low_pc`.
    pub const LOW_PC: u16 = 0x11;
    /// `DW_AT_high_pc`.
    pub const HIGH_PC: u16 = 0x12;
    /// `DW_AT_language`.
    pub const LANGUAGE: u16 = 0x13;
    /// `DW_AT_producer`.
    pub const PRODUCER: u16 = 0x25;
    /// `DW_AT_type`.
    pub const TYPE: u16 = 0x49;
    /// `DW_AT_location`.
    pub const LOCATION: u16 = 0x02;
    /// `DW_AT_data_member_location`.
    pub const DATA_MEMBER_LOCATION: u16 = 0x38;
    /// `DW_AT_prototyped`.
    pub const PROTOTYPED: u16 = 0x27;
    /// `DW_AT_decl_file`.
    pub const DECL_FILE: u16 = 0x3A;
    /// `DW_AT_decl_line`.
    pub const DECL_LINE: u16 = 0x3B;
    /// `DW_AT_encoding`.
    pub const ENCODING: u16 = 0x3E;
}

/// DWARF base-type encoding constants (`DW_ATE_*`).
pub mod dw_ate {
    /// No encoding (void placeholder).
    pub const VOID: u8 = 0x00;
    /// `DW_ATE_address`.
    pub const ADDRESS: u8 = 0x01;
    /// `DW_ATE_boolean`.
    pub const BOOLEAN: u8 = 0x02;
    /// `DW_ATE_complex_float`.
    pub const COMPLEX_FLOAT: u8 = 0x03;
    /// `DW_ATE_float`.
    pub const FLOAT: u8 = 0x04;
    /// `DW_ATE_signed`.
    pub const SIGNED: u8 = 0x05;
    /// `DW_ATE_signed_char`.
    pub const SIGNED_CHAR: u8 = 0x06;
    /// `DW_ATE_unsigned`.
    pub const UNSIGNED: u8 = 0x07;
    /// `DW_ATE_unsigned_char`.
    pub const UNSIGNED_CHAR: u8 = 0x08;
}

/// DWARF source-language constants (`DW_LANG_*`).
pub mod dw_lang {
    /// `DW_LANG_C`.
    pub const C: u16 = 0x0001;
    /// `DW_LANG_C89` (same code as `C`).
    pub const C89: u16 = 0x0001;
    /// `DW_LANG_C99`.
    pub const C99: u16 = 0x000C;
    /// `DW_LANG_C_plus_plus`.
    pub const CPP: u16 = 0x0004;
    /// `DW_LANG_Fortran77`.
    pub const FORTRAN77: u16 = 0x0007;
    /// `DW_LANG_Rust`.
    pub const RUST: u16 = 0x001C;
}

// ── Attribute value ───────────────────────────────────────────────────────────

/// Value of a DIE attribute.
#[derive(Debug, Clone, PartialEq)]
pub enum AttrValue {
    /// String value (names, producer, paths).
    String(String),
    /// Unsigned integer value (sizes, addresses, encodings).
    Unsigned(u64),
    /// Signed integer value (enum constants, bounds).
    Signed(i64),
    /// Boolean flag (e.g. `DW_AT_external`).
    Bool(bool),
    /// Raw byte block (DWARF location expressions).
    Bytes(Vec<u8>),
    /// Reference to another DIE.
    Ref(DieId),
}

// ── DIE ───────────────────────────────────────────────────────────────────────

/// A unique identifier for a Debug Info Entry
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DieId(pub u32);

/// A single Debug Info Entry in the synthetic DWARF-like tree
#[derive(Debug, Clone)]
pub struct Die {
    /// Unique id of this DIE within its [`DieTree`].
    pub id: DieId,
    /// DIE tag (`DW_TAG_*` from [`dw_tag`]).
    pub tag: u16,
    /// Attribute list as `(DW_AT_* code, value)` pairs.
    pub attrs: Vec<(u16, AttrValue)>,
    /// Ids of child DIEs, in insertion order.
    pub children: Vec<DieId>,
    /// Id of the parent DIE, if any.
    pub parent: Option<DieId>,
}

impl Die {
    /// Create an attribute-less DIE with the given id and tag.
    #[must_use]
    pub const fn new(id: DieId, tag: u16) -> Self {
        Self { id, tag, attrs: Vec::new(), children: Vec::new(), parent: None }
    }

    /// Look up an attribute value by its `DW_AT_*` code.
    #[must_use]
    pub fn attr(&self, attr_code: u16) -> Option<&AttrValue> {
        self.attrs.iter().find(|(a, _)| *a == attr_code).map(|(_, v)| v)
    }

    /// Return the `DW_AT_name` string, if present.
    #[must_use]
    pub fn name(&self) -> Option<&str> {
        if let Some(AttrValue::String(s)) = self.attr(dw_at::NAME) { Some(s) } else { None }
    }

    /// Return the `DW_AT_low_pc` address, if present.
    #[must_use]
    pub fn low_pc(&self) -> Option<u64> {
        if let Some(AttrValue::Unsigned(v)) = self.attr(dw_at::LOW_PC) { Some(*v) } else { None }
    }

    /// Return the `DW_AT_high_pc` address, if present.
    #[must_use]
    pub fn high_pc(&self) -> Option<u64> {
        if let Some(AttrValue::Unsigned(v)) = self.attr(dw_at::HIGH_PC) { Some(*v) } else { None }
    }

    /// Return the `DW_AT_byte_size` value, if present.
    #[must_use]
    pub fn byte_size(&self) -> Option<u64> {
        if let Some(AttrValue::Unsigned(v)) = self.attr(dw_at::BYTE_SIZE) { Some(*v) } else { None }
    }

    /// True if the DIE carries `DW_AT_external = true`.
    #[must_use]
    pub fn is_external(&self) -> bool {
        self.attr(dw_at::EXTERNAL) == Some(&AttrValue::Bool(true))
    }

    fn set_attr(&mut self, attr: u16, val: AttrValue) {
        if let Some(entry) = self.attrs.iter_mut().find(|(a, _)| *a == attr) {
            entry.1 = val;
        } else {
            self.attrs.push((attr, val));
        }
    }
}

// ── DIE tree ──────────────────────────────────────────────────────────────────

/// A tree of DIEs representing one or more compilation units
#[derive(Debug, Default)]
pub struct DieTree {
    dies: Vec<Die>,
    next_id: u32,
    root_ids: Vec<DieId>,
}

impl DieTree {
    /// Create an empty DIE tree.
    #[must_use]
    pub fn new() -> Self { Self::default() }

    fn alloc(&mut self, tag: u16) -> DieId {
        let id = DieId(self.next_id);
        self.next_id += 1;
        self.dies.push(Die::new(id, tag));
        id
    }

    // `alloc` assigns DieId(next_id) and pushes in the same order, so the
    // index into `dies` *is* the id. Direct indexing turns tree construction
    // from O(n^2) into O(n); the id equality check keeps the invariant
    // enforced rather than merely assumed.
    fn get_mut(&mut self, id: DieId) -> Option<&mut Die> {
        self.dies
            .get_mut(usize::try_from(id.0).ok()?)
            .filter(|d| d.id == id)
    }

    /// Look up a DIE by id.
    #[must_use]
    pub fn get(&self, id: DieId) -> Option<&Die> {
        self.dies.get(usize::try_from(id.0).ok()?).filter(|d| d.id == id)
    }

    fn set_attr(&mut self, id: DieId, attr: u16, val: AttrValue) {
        if let Some(die) = self.get_mut(id) {
            die.set_attr(attr, val);
        }
    }

    fn add_child(&mut self, parent_id: DieId, child_id: DieId) {
        if let Some(parent) = self.get_mut(parent_id) {
            parent.children.push(child_id);
        }
        if let Some(child) = self.get_mut(child_id) {
            child.parent = Some(parent_id);
        }
    }

    fn add_root(&mut self, id: DieId) {
        self.root_ids.push(id);
    }

    /// Ids of the root DIEs (one per compilation unit).
    #[must_use]
    pub fn roots(&self) -> &[DieId] { &self.root_ids }
    /// All DIEs in allocation order.
    #[must_use]
    pub fn all_dies(&self) -> &[Die] { &self.dies }

    /// Find every DIE whose `DW_AT_name` equals `name`.
    #[must_use]
    pub fn find_by_name(&self, name: &str) -> Vec<&Die> {
        self.dies.iter().filter(|d| d.name() == Some(name)).collect()
    }

    /// Iterate over all `DW_TAG_subprogram` DIEs.
    pub fn subprograms(&self) -> impl Iterator<Item = &Die> {
        self.dies.iter().filter(|d| d.tag == dw_tag::SUBPROGRAM)
    }

    /// Iterate over all `DW_TAG_compile_unit` DIEs.
    pub fn compile_units(&self) -> impl Iterator<Item = &Die> {
        self.dies.iter().filter(|d| d.tag == dw_tag::COMPILE_UNIT)
    }
}

// ── Converter ─────────────────────────────────────────────────────────────────

/// Converts STABS parsed data into a `DieTree`
pub struct StabsToDwarf {
    /// The DIE tree built so far.
    pub tree: DieTree,
    type_die_map: HashMap<String, DieId>,
    type_db: TypeDatabase,
}

impl StabsToDwarf {
    /// Create a converter with an empty DIE tree and type cache.
    #[must_use]
    pub fn new() -> Self {
        Self {
            tree: DieTree::new(),
            type_die_map: HashMap::new(),
            type_db: TypeDatabase::new(),
        }
    }

    /// Convert a list of parsed compilation units into DIEs
    pub fn convert_units(&mut self, units: &[CompilationUnit]) {
        for cu in units {
            self.convert_cu(cu);
        }
    }

    fn convert_cu(&mut self, cu: &CompilationUnit) {
        let cu_id = self.tree.alloc(dw_tag::COMPILE_UNIT);
        self.tree.add_root(cu_id);

        // Per DWARF: DW_AT_name on a compile unit is the source file name
        // (basename), while DW_AT_comp_dir carries the directory.
        self.tree.set_attr(cu_id, dw_at::NAME, AttrValue::String(cu.filename.clone()));
        if !cu.directory.is_empty() {
            self.tree.set_attr(cu_id, dw_at::COMP_DIR, AttrValue::String(cu.directory.clone()));
        }
        self.tree.set_attr(cu_id, dw_at::LANGUAGE, AttrValue::Unsigned(u64::from(dw_lang::C)));
        self.tree.set_attr(cu_id, dw_at::PRODUCER, AttrValue::String("GCC (STABS)".to_string()));

        for func in &cu.functions {
            let func_id = self.convert_function(func, cu_id);
            self.tree.add_child(cu_id, func_id);
        }

        for gs in &cu.globals {
            let var_id = self.convert_global(gs);
            self.tree.add_child(cu_id, var_id);
        }
    }

    fn convert_function(&mut self, func: &ParsedFunction, _parent: DieId) -> DieId {
        let sp_id = self.tree.alloc(dw_tag::SUBPROGRAM);
        self.tree.set_attr(sp_id, dw_at::NAME, AttrValue::String(func.name.clone()));
        self.tree.set_attr(sp_id, dw_at::LOW_PC, AttrValue::Unsigned(func.start_addr));
        if func.end_addr > func.start_addr {
            self.tree.set_attr(sp_id, dw_at::HIGH_PC, AttrValue::Unsigned(func.end_addr));
        }
        if !func.type_str.is_empty() {
            // Emit a synthetic return type attribute
            let ret_type = self.ensure_type_die(&func.type_str);
            self.tree.set_attr(sp_id, dw_at::TYPE, AttrValue::Ref(ret_type));
        }

        for param in &func.params {
            let p_id = self.convert_param(param);
            self.tree.add_child(sp_id, p_id);
        }

        for local in &func.locals {
            let v_id = self.convert_local(local);
            self.tree.add_child(sp_id, v_id);
        }

        for rv in &func.reg_vars {
            let v_id = self.convert_reg_var(rv);
            self.tree.add_child(sp_id, v_id);
        }

        // Emit lexical blocks from bracket pairs
        let mut brace_stack: Vec<DieId> = Vec::new();
        for bracket in &func.brackets {
            use crate::stabs_parser::BracketKind;
            match bracket.kind {
                BracketKind::Open => {
                    let lb_id = self.tree.alloc(dw_tag::LEXICAL_BLOCK);
                    self.tree.set_attr(lb_id, dw_at::LOW_PC,
                        AttrValue::Unsigned(func.start_addr.saturating_add(u64::from(bracket.offset))));
                    let parent = brace_stack.last().copied().unwrap_or(sp_id);
                    self.tree.add_child(parent, lb_id);
                    brace_stack.push(lb_id);
                }
                BracketKind::Close => {
                    if let Some(lb_id) = brace_stack.pop() {
                        self.tree.set_attr(lb_id, dw_at::HIGH_PC,
                            AttrValue::Unsigned(func.start_addr.saturating_add(u64::from(bracket.offset))));
                    }
                }
            }
        }

        sp_id
    }

    fn convert_param(&mut self, param: &Parameter) -> DieId {
        let p_id = self.tree.alloc(dw_tag::FORMAL_PARAMETER);
        self.tree.set_attr(p_id, dw_at::NAME, AttrValue::String(param.name.clone()));
        // Encode location as DW_OP_fbreg offset
        let loc = encode_fbreg_location(param.frame_offset);
        self.tree.set_attr(p_id, dw_at::LOCATION, AttrValue::Bytes(loc));
        if !param.type_str.is_empty() {
            let ty_id = self.ensure_type_die(&param.type_str);
            self.tree.set_attr(p_id, dw_at::TYPE, AttrValue::Ref(ty_id));
        }
        p_id
    }

    fn convert_local(&mut self, local: &LocalVar) -> DieId {
        let v_id = self.tree.alloc(dw_tag::VARIABLE);
        self.tree.set_attr(v_id, dw_at::NAME, AttrValue::String(local.name.clone()));
        let loc = encode_fbreg_location(local.frame_offset);
        self.tree.set_attr(v_id, dw_at::LOCATION, AttrValue::Bytes(loc));
        if !local.type_str.is_empty() {
            let ty_id = self.ensure_type_die(&local.type_str);
            self.tree.set_attr(v_id, dw_at::TYPE, AttrValue::Ref(ty_id));
        }
        v_id
    }

    fn convert_reg_var(&mut self, rv: &RegisterVar) -> DieId {
        let v_id = self.tree.alloc(dw_tag::VARIABLE);
        self.tree.set_attr(v_id, dw_at::NAME, AttrValue::String(rv.name.clone()));
        let loc = encode_reg_location(rv.reg);
        self.tree.set_attr(v_id, dw_at::LOCATION, AttrValue::Bytes(loc));
        if !rv.type_str.is_empty() {
            let ty_id = self.ensure_type_die(&rv.type_str);
            self.tree.set_attr(v_id, dw_at::TYPE, AttrValue::Ref(ty_id));
        }
        v_id
    }

    fn convert_global(&mut self, gs: &GlobalSymbol) -> DieId {
        let v_id = self.tree.alloc(dw_tag::VARIABLE);
        self.tree.set_attr(v_id, dw_at::NAME, AttrValue::String(gs.name.clone()));
        self.tree.set_attr(v_id, dw_at::EXTERNAL, AttrValue::Bool(true));
        if gs.address != 0 {
            let loc = encode_addr_location(gs.address);
            self.tree.set_attr(v_id, dw_at::LOCATION, AttrValue::Bytes(loc));
        }
        if !gs.type_str.is_empty() {
            let ty_id = self.ensure_type_die(&gs.type_str);
            self.tree.set_attr(v_id, dw_at::TYPE, AttrValue::Ref(ty_id));
        }
        v_id
    }

    /// Ensure a type DIE exists for the given STABS type string; return its ID
    fn ensure_type_die(&mut self, type_str: &str) -> DieId {
        if let Some(&existing) = self.type_die_map.get(type_str) {
            return existing;
        }
        let stab_type = decode_type(type_str);
        // Cache the decoded type in the shared TypeDatabase keyed by its
        // synthetic per-converter index so later lookups can resolve named
        // references without re-decoding the same descriptor.
        let next_idx = self.type_db.len() as i32;
        self.type_db.insert(
            crate::stabs_type_decoder::TypeId::simple(next_idx),
            stab_type.clone(),
        );
        let die_id = self.emit_type_die(&stab_type, type_str);
        self.type_die_map.insert(type_str.to_string(), die_id);
        die_id
    }

    /// Return the number of distinct STABS types cached by this converter.
    #[must_use]
    pub fn cached_type_count(&self) -> usize {
        self.type_db.len()
    }

    fn emit_type_die(&mut self, ty: &StabType, key: &str) -> DieId {
        match ty {
            StabType::Void => self.emit_base_type("void", 0, dw_ate::VOID),
            StabType::Bool => self.emit_base_type("bool", 1, dw_ate::BOOLEAN),
            StabType::Char => self.emit_base_type("char", 1, dw_ate::SIGNED_CHAR),
            StabType::SignedChar => self.emit_base_type("signed char", 1, dw_ate::SIGNED_CHAR),
            StabType::UnsignedChar => self.emit_base_type("unsigned char", 1, dw_ate::UNSIGNED_CHAR),
            StabType::Short => self.emit_base_type("short", 2, dw_ate::SIGNED),
            StabType::UnsignedShort => self.emit_base_type("unsigned short", 2, dw_ate::UNSIGNED),
            StabType::Int => self.emit_base_type("int", 4, dw_ate::SIGNED),
            StabType::UnsignedInt => self.emit_base_type("unsigned int", 4, dw_ate::UNSIGNED),
            StabType::Long => self.emit_base_type("long", 8, dw_ate::SIGNED),
            StabType::UnsignedLong => self.emit_base_type("unsigned long", 8, dw_ate::UNSIGNED),
            StabType::LongLong => self.emit_base_type("long long", 8, dw_ate::SIGNED),
            StabType::UnsignedLongLong => self.emit_base_type("unsigned long long", 8, dw_ate::UNSIGNED),
            StabType::Float => self.emit_base_type("float", 4, dw_ate::FLOAT),
            StabType::Double => self.emit_base_type("double", 8, dw_ate::FLOAT),
            StabType::LongDouble => self.emit_base_type("long double", 16, dw_ate::FLOAT),

            StabType::Pointer(inner) => {
                let inner_id = self.emit_type_die(inner, "");
                let p_id = self.tree.alloc(dw_tag::POINTER_TYPE);
                self.tree.set_attr(p_id, dw_at::BYTE_SIZE, AttrValue::Unsigned(8));
                self.tree.set_attr(p_id, dw_at::TYPE, AttrValue::Ref(inner_id));
                p_id
            }
            StabType::Reference(inner) => {
                let inner_id = self.emit_type_die(inner, "");
                let r_id = self.tree.alloc(dw_tag::REFERENCE_TYPE);
                self.tree.set_attr(r_id, dw_at::BYTE_SIZE, AttrValue::Unsigned(8));
                self.tree.set_attr(r_id, dw_at::TYPE, AttrValue::Ref(inner_id));
                r_id
            }

            StabType::Struct { name, is_union, byte_size, fields } => {
                let tag = if *is_union { dw_tag::UNION_TYPE } else { dw_tag::STRUCTURE_TYPE };
                let st_id = self.tree.alloc(tag);
                self.tree.set_attr(st_id, dw_at::NAME, AttrValue::String(name.clone()));
                self.tree.set_attr(st_id, dw_at::BYTE_SIZE, AttrValue::Unsigned(u64::from(*byte_size)));
                for field in fields {
                    let m_id = self.emit_member_die(field);
                    self.tree.add_child(st_id, m_id);
                }
                st_id
            }

            StabType::Enum { name, variants } => {
                let en_id = self.tree.alloc(dw_tag::ENUMERATION_TYPE);
                self.tree.set_attr(en_id, dw_at::NAME, AttrValue::String(name.clone()));
                for variant in variants {
                    let variant: &EnumVariant = variant;
                    let v_id = self.tree.alloc(dw_tag::ENUMERATOR);
                    self.tree.set_attr(v_id, dw_at::NAME, AttrValue::String(variant.name.clone()));
                    self.tree.set_attr(v_id, dw_at::CONST_VALUE, AttrValue::Signed(variant.value));
                    self.tree.add_child(en_id, v_id);
                }
                en_id
            }

            StabType::Typedef { name, inner } => {
                let inner_id = self.emit_type_die(inner, "");
                let td_id = self.tree.alloc(dw_tag::TYPEDEF);
                self.tree.set_attr(td_id, dw_at::NAME, AttrValue::String(name.clone()));
                self.tree.set_attr(td_id, dw_at::TYPE, AttrValue::Ref(inner_id));
                td_id
            }

            StabType::Const(inner) => {
                let inner_id = self.emit_type_die(inner, "");
                let c_id = self.tree.alloc(dw_tag::CONST_TYPE);
                self.tree.set_attr(c_id, dw_at::TYPE, AttrValue::Ref(inner_id));
                c_id
            }

            StabType::Volatile(inner) => {
                let inner_id = self.emit_type_die(inner, "");
                let v_id = self.tree.alloc(dw_tag::VOLATILE_TYPE);
                self.tree.set_attr(v_id, dw_at::TYPE, AttrValue::Ref(inner_id));
                v_id
            }

            StabType::Array { low, high, elem_type } => {
                let elem_id = self.emit_type_die(elem_type, "");
                let arr_id = self.tree.alloc(dw_tag::ARRAY_TYPE);
                self.tree.set_attr(arr_id, dw_at::TYPE, AttrValue::Ref(elem_id));
                // Sub-range child
                let sr_id = self.tree.alloc(dw_tag::SUBRANGE_TYPE);
                if *low != 0 {
                    self.tree.set_attr(sr_id, 0x22 /*DW_AT_lower_bound*/, AttrValue::Signed(*low));
                }
                if *high >= 0 {
                    self.tree.set_attr(sr_id, 0x2F /*DW_AT_upper_bound*/, AttrValue::Signed(*high));
                }
                self.tree.add_child(arr_id, sr_id);
                arr_id
            }

            StabType::XRef { kind, name } => {
                // Forward declaration
                let tag = match kind {
                    crate::stabs_type_decoder::XRefKind::Struct => dw_tag::STRUCTURE_TYPE,
                    crate::stabs_type_decoder::XRefKind::Union => dw_tag::UNION_TYPE,
                    crate::stabs_type_decoder::XRefKind::Enum => dw_tag::ENUMERATION_TYPE,
                };
                let d_id = self.tree.alloc(tag);
                self.tree.set_attr(d_id, dw_at::NAME, AttrValue::String(name.clone()));
                // Mark as declaration
                self.tree.set_attr(d_id, 0x3C /*DW_AT_declaration*/, AttrValue::Bool(true));
                d_id
            }

            StabType::TypeRef { module, index } => {
                // Emit a placeholder; real consumers would resolve this
                let p_id = self.tree.alloc(dw_tag::BASE_TYPE);
                self.tree.set_attr(p_id, dw_at::NAME,
                    AttrValue::String(format!("typeref({module},{index})")));
                p_id
            }

            _ => {
                let uk_id = self.tree.alloc(dw_tag::BASE_TYPE);
                self.tree.set_attr(uk_id, dw_at::NAME, AttrValue::String(format!("unknown({key})")));
                uk_id
            }
        }
    }

    fn emit_base_type(&mut self, name: &str, byte_size: u64, encoding: u8) -> DieId {
        // Deduplicate base types
        let key = format!("base:{name}:{encoding}");
        if let Some(&id) = self.type_die_map.get(&key) { return id; }
        let bt_id = self.tree.alloc(dw_tag::BASE_TYPE);
        self.tree.set_attr(bt_id, dw_at::NAME, AttrValue::String(name.to_string()));
        self.tree.set_attr(bt_id, dw_at::BYTE_SIZE, AttrValue::Unsigned(byte_size));
        self.tree.set_attr(bt_id, dw_at::ENCODING, AttrValue::Unsigned(u64::from(encoding)));
        self.type_die_map.insert(key, bt_id);
        bt_id
    }

    fn emit_member_die(&mut self, field: &StructField) -> DieId {
        let m_id = self.tree.alloc(dw_tag::MEMBER);
        self.tree.set_attr(m_id, dw_at::NAME, AttrValue::String(field.name.clone()));
        // DW_AT_data_member_location = byte offset
        let byte_off = field.bit_offset / 8;
        self.tree.set_attr(m_id, dw_at::DATA_MEMBER_LOCATION, AttrValue::Unsigned(u64::from(byte_off)));
        if field.is_bitfield() {
            self.tree.set_attr(m_id, dw_at::BIT_SIZE, AttrValue::Unsigned(u64::from(field.bit_size)));
            self.tree.set_attr(m_id, dw_at::BIT_OFFSET, AttrValue::Unsigned(u64::from(field.bit_offset)));
        }
        let ft_id = self.emit_type_die(&field.field_type, "");
        self.tree.set_attr(m_id, dw_at::TYPE, AttrValue::Ref(ft_id));
        m_id
    }

    /// Summary statistics about the generated tree
    #[must_use]
    pub fn stats(&self) -> ConversionStats {
        let mut stats = ConversionStats::default();
        for die in self.tree.all_dies() {
            match die.tag {
                dw_tag::COMPILE_UNIT => stats.compile_units += 1,
                dw_tag::SUBPROGRAM => stats.subprograms += 1,
                dw_tag::FORMAL_PARAMETER => stats.parameters += 1,
                dw_tag::VARIABLE => stats.variables += 1,
                dw_tag::BASE_TYPE => stats.base_types += 1,
                dw_tag::STRUCTURE_TYPE | dw_tag::UNION_TYPE => stats.struct_types += 1,
                dw_tag::ENUMERATION_TYPE => stats.enum_types += 1,
                _ => stats.other += 1,
            }
        }
        stats
    }
}

impl Default for StabsToDwarf {
    fn default() -> Self { Self::new() }
}

/// Per-tag DIE counts produced by [`StabsToDwarf::stats`].
#[derive(Debug, Default)]
pub struct ConversionStats {
    /// Number of `DW_TAG_compile_unit` DIEs.
    pub compile_units: usize,
    /// Number of `DW_TAG_subprogram` DIEs.
    pub subprograms: usize,
    /// Number of `DW_TAG_formal_parameter` DIEs.
    pub parameters: usize,
    /// Number of `DW_TAG_variable` DIEs.
    pub variables: usize,
    /// Number of `DW_TAG_base_type` DIEs.
    pub base_types: usize,
    /// Number of `DW_TAG_structure_type` / `DW_TAG_union_type` DIEs.
    pub struct_types: usize,
    /// Number of `DW_TAG_enumeration_type` DIEs.
    pub enum_types: usize,
    /// Number of DIEs with any other tag.
    pub other: usize,
}

impl ConversionStats {
    /// Total DIE count across all categories.
    #[must_use]
    pub const fn total_dies(&self) -> usize {
        self.compile_units + self.subprograms + self.parameters + self.variables
            + self.base_types + self.struct_types + self.enum_types + self.other
    }
}

// ── DWARF expression helpers ──────────────────────────────────────────────────

/// Encode a `DW_OP_fbreg(offset)` location expression
fn encode_fbreg_location(offset: i32) -> Vec<u8> {
    // DW_OP_fbreg = 0x91, followed by SLEB128 offset
    let mut v = vec![0x91u8];
    encode_sleb128(i64::from(offset), &mut v);
    v
}

/// Encode a `DW_OP_reg(n)` for n < 32, or `DW_OP_regx` for larger register numbers
fn encode_reg_location(reg: u32) -> Vec<u8> {
    if reg < 32 {
        vec![0x50 + reg as u8] // DW_OP_reg0..DW_OP_reg31
    } else {
        let mut v = vec![0x90u8]; // DW_OP_regx
        encode_uleb128(u64::from(reg), &mut v);
        v
    }
}

/// Encode a `DW_OP_addr(addr)` location expression (8-byte address)
fn encode_addr_location(addr: u64) -> Vec<u8> {
    let mut v = vec![0x03u8]; // DW_OP_addr
    v.extend_from_slice(&addr.to_le_bytes());
    v
}

fn encode_sleb128(mut val: i64, out: &mut Vec<u8>) {
    loop {
        let mut byte = (val & 0x7F) as u8;
        val >>= 7;
        let done = (val == 0 && (byte & 0x40) == 0) || (val == -1 && (byte & 0x40) != 0);
        if !done { byte |= 0x80; }
        out.push(byte);
        if done { break; }
    }
}

fn encode_uleb128(mut val: u64, out: &mut Vec<u8>) {
    loop {
        let mut byte = (val & 0x7F) as u8;
        val >>= 7;
        if val != 0 { byte |= 0x80; }
        out.push(byte);
        if val == 0 { break; }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stabs_parser::{CompilationUnit, ParsedFunction, LineEntry};

    fn make_simple_cu() -> CompilationUnit {
        CompilationUnit {
            directory: "/src".to_string(),
            filename: "main.c".to_string(),
            included_files: vec![],
            functions: vec![
                ParsedFunction {
                    name: "main".to_string(),
                    type_str: "F(0,1)".to_string(),
                    start_addr: 0x1000,
                    end_addr: 0x1100,
                    source_file: "/src/main.c".to_string(),
                    lines: vec![
                        LineEntry { address: 0x1000, line: 5, file_idx: 0 },
                    ],
                    params: vec![],
                    locals: vec![],
                    reg_vars: vec![],
                    brackets: vec![],
                }
            ],
            globals: vec![],
            statics: vec![],
        }
    }

    #[test]
    fn test_convert_single_cu() {
        let cu = make_simple_cu();
        let mut conv = StabsToDwarf::new();
        conv.convert_units(&[cu]);
        let stats = conv.stats();
        assert_eq!(stats.compile_units, 1);
        assert_eq!(stats.subprograms, 1);
    }

    #[test]
    fn test_subprogram_attrs() {
        let cu = make_simple_cu();
        let mut conv = StabsToDwarf::new();
        conv.convert_units(&[cu]);
        let sp = conv.tree.subprograms().next().unwrap();
        assert_eq!(sp.name(), Some("main"));
        assert_eq!(sp.low_pc(), Some(0x1000));
        assert_eq!(sp.high_pc(), Some(0x1100));
    }

    #[test]
    fn test_compile_unit_attrs() {
        let cu = make_simple_cu();
        let mut conv = StabsToDwarf::new();
        conv.convert_units(&[cu]);
        let die_cu = conv.tree.compile_units().next().unwrap();
        assert_eq!(die_cu.name(), Some("main.c"));
    }

    #[test]
    fn test_encode_fbreg_location() {
        let loc = encode_fbreg_location(-8);
        assert_eq!(loc[0], 0x91); // DW_OP_fbreg
        // SLEB128 of -8: 0x78 (single byte, -8 = 0x78 in LEB128)
        assert_eq!(loc[1], 0x78);
    }

    #[test]
    fn test_encode_reg_location_small() {
        let loc = encode_reg_location(0);
        assert_eq!(loc, vec![0x50]); // DW_OP_reg0
        let loc2 = encode_reg_location(5);
        assert_eq!(loc2, vec![0x55]); // DW_OP_reg5
    }

    #[test]
    fn test_encode_addr_location() {
        let loc = encode_addr_location(0x400000);
        assert_eq!(loc[0], 0x03); // DW_OP_addr
        assert_eq!(loc.len(), 9); // 1 + 8 bytes
    }

    #[test]
    fn test_sleb128_positive() {
        let mut v = Vec::new();
        encode_sleb128(0, &mut v);
        assert_eq!(v, vec![0x00]);
        v.clear();
        encode_sleb128(127, &mut v);
        // Correct SLEB128 of +127 is two bytes [0x7F, 0x00]: a single 0x7F
        // would be interpreted as -1 because bit 6 (sign) is set.
        assert_eq!(v, vec![0xFF, 0x00]);
    }

    #[test]
    fn test_sleb128_negative() {
        let mut v = Vec::new();
        encode_sleb128(-1, &mut v);
        assert_eq!(v, vec![0x7F]);
    }

    #[test]
    fn test_uleb128() {
        let mut v = Vec::new();
        encode_uleb128(300, &mut v);
        assert_eq!(v, vec![0xAC, 0x02]);
    }
}
