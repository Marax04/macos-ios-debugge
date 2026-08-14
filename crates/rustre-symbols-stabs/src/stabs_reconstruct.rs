//! Type reconstruction: rebuild C struct/union/enum definitions from STABS.
//!
//! [`StabsReconstructor`] takes a [`StabsTypeDb`] and produces C-like type
//! definitions suitable for output in a decompiler.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fmt;

use crate::stabs_types::{
    StabsCompositeType, StabsEnumVariant, StabsStructField, StabsType, StabsTypeDb, TypeRef,
};

// Re-export the underlying STABS type-record building blocks so consumers of
// `stabs_reconstruct` can refer to them through this module without pulling in
// `stabs_types` separately.
pub use crate::stabs_types::{StabsArrayType, StabsBaseType, StabsFunctionType, StabsPointerType};

// ─────────────────────────────────────────────────────────────────────────────
// CTypeDecl — a C type declaration string
// ─────────────────────────────────────────────────────────────────────────────

/// A rendered C type declaration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CTypeDecl {
    /// Declared name, if any.
    pub name: Option<String>,
    /// The C declaration text.
    pub decl: String,
    /// Whether this is only a forward declaration.
    pub forward_ref: bool,
    /// Whether this declaration is a `typedef`.
    pub is_typedef: bool,
}

impl CTypeDecl {
    /// Build an unnamed declaration from its text.
    pub fn simple(decl: impl Into<String>) -> Self {
        Self {
            name: None,
            decl: decl.into(),
            forward_ref: false,
            is_typedef: false,
        }
    }

    /// Build a named declaration.
    pub fn named(name: impl Into<String>, decl: impl Into<String>) -> Self {
        Self {
            name: Some(name.into()),
            decl: decl.into(),
            forward_ref: false,
            is_typedef: false,
        }
    }
}

impl fmt::Display for CTypeDecl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_typedef {
            write!(f, "typedef {}", self.decl)?;
            if let Some(n) = &self.name {
                write!(f, " {n}")?;
            }
            write!(f, ";")
        } else {
            f.write_str(&self.decl)
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// StabsReconstructor
// ─────────────────────────────────────────────────────────────────────────────

/// Renders [`StabsTypeDb`] entries as C-like type declarations.
pub struct StabsReconstructor<'a> {
    db: &'a StabsTypeDb,
    /// Cycle guard. Keyed by the *whole* `TypeRef`: type numbers are namespaced
    /// per file, so (0,5) and (1,5) are different types and keying on `num`
    /// alone made an ordinary cross-file field render as "(recursive)".
    seen: HashSet<TypeRef>,
    /// Depth guard. `seen` bounds cycles but not depth: a chain of 100_000
    /// distinct pointer types would still overflow the stack.
    depth: u32,
    indent: usize,
}

/// Maximum type-rendering nesting depth.
const MAX_RENDER_DEPTH: u32 = 128;

impl<'a> StabsReconstructor<'a> {
    /// Create a reconstructor over the given type database.
    #[must_use] 
    pub fn new(db: &'a StabsTypeDb) -> Self {
        Self {
            db,
            seen: HashSet::new(),
            depth: 0,
            indent: 0,
        }
    }

    /// Convert a `TypeRef` to its C string representation.
    pub fn type_str(&mut self, r: TypeRef) -> String {
        if self.seen.contains(&r) {
            return "(recursive)".to_string();
        }
        if self.depth >= MAX_RENDER_DEPTH {
            return "/* depth limit */".to_string();
        }
        self.seen.insert(r);
        self.depth += 1;
        let result = self.db.get(&r).map_or_else(
            || format!("/* unknown T#{} */", r.num),
            |ty| self.render_type(ty, r),
        );
        self.depth -= 1;
        self.seen.remove(&r);
        result
    }

    fn render_type(&mut self, ty: &StabsType, r: TypeRef) -> String {
        match ty {
            StabsType::Base(b) => b.c_name(),
            StabsType::Alias(inner) => self.type_str(*inner),
            StabsType::Pointer(p) => format!("{}*", self.type_str(p.pointee)),
            StabsType::Reference(r2) => format!("{}&", self.type_str(r2.pointee)),
            StabsType::Qualified(q) => {
                let qual = match q.qualifier {
                    crate::stabs_types::TypeQualifier::Const => "const",
                    crate::stabs_types::TypeQualifier::Volatile => "volatile",
                    crate::stabs_types::TypeQualifier::Restrict => "restrict",
                };
                format!("{} {}", qual, self.type_str(q.inner))
            }
            StabsType::Array(a) => {
                let elem = self.type_str(a.element_type);
                format!("{}[{}]", elem, a.count())
            }
            StabsType::Function(f) => {
                let ret = self.type_str(f.return_type);
                let params: Vec<String> = f.param_types.iter().map(|p| self.type_str(*p)).collect();
                format!("{} (*)({})", ret, params.join(", "))
            }
            StabsType::Typedef { name, inner } => {
                if name.is_empty() {
                    format!("/* typedef T#{} */ {}", r.num, self.type_str(*inner))
                } else {
                    name.clone()
                }
            }
            StabsType::Forward { name } => format!("struct {name}"),
            StabsType::Composite(c) => self.render_composite(c),
        }
    }

    fn render_composite(&mut self, c: &StabsCompositeType) -> String {
        match c {
            StabsCompositeType::Struct {
                name,
                byte_size,
                fields,
            } => self.render_struct("struct", name, *byte_size, fields),
            StabsCompositeType::Union {
                name,
                byte_size,
                fields,
            } => self.render_struct("union", name, *byte_size, fields),
            StabsCompositeType::Enum { name, variants } => Self::render_enum(name, variants),
        }
    }

    fn render_struct(
        &mut self,
        kw: &str,
        name: &str,
        byte_size: u32,
        fields: &[StabsStructField],
    ) -> String {
        use std::fmt::Write as _;
        let pad = " ".repeat(self.indent * 4);
        let mut out = format!("{kw} {name} {{  /* {byte_size} bytes */\n");
        self.indent += 1;
        for f in fields {
            let ty = self.type_str(f.type_ref);
            let field_pad = " ".repeat(self.indent * 4);
            let _ = writeln!(out, "{}{}  {}  {}; /* bit offset {} */", pad, field_pad, ty, &f.name, f.bit_offset);
        }
        self.indent -= 1;
        let _ = write!(out, "{pad}}}");
        out
    }

    fn render_enum(name: &str, variants: &[StabsEnumVariant]) -> String {
        use std::fmt::Write as _;
        let mut out = format!("enum {name} {{\n");
        for v in variants {
            let _ = writeln!(out, "    {} = {},", v.name, v.value);
        }
        out.push('}');
        out
    }

    /// Reconstruct all named types from the database.
    pub fn reconstruct_all(&mut self) -> Vec<CTypeDecl> {
        let refs: Vec<TypeRef> = self.db.refs().copied().collect();
        let mut decls = Vec::new();
        for r in &refs {
            if let Some(ty) = self.db.get(r) {
                match ty {
                    StabsType::Composite(c) => {
                        let name = c.name().to_string();
                        let decl_str = self.render_composite(c);
                        decls.push(CTypeDecl::named(name, decl_str));
                    }
                    StabsType::Typedef { name, .. } if !name.is_empty() => {
                        let decl_str = self.type_str(*r);
                        let mut d = CTypeDecl::named(name, decl_str);
                        d.is_typedef = true;
                        decls.push(d);
                    }
                    _ => {}
                }
            }
        }
        decls
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TypeOrderer — topological sort for type declarations
// ─────────────────────────────────────────────────────────────────────────────

/// Topologically sorts type declarations so dependencies come first.
pub struct TypeOrderer {
    deps: HashMap<TypeRef, Vec<TypeRef>>,
    order: Vec<TypeRef>,
    visited: HashSet<TypeRef>,
}

impl Default for TypeOrderer {
    fn default() -> Self {
        Self::new()
    }
}

impl TypeOrderer {
    /// Create an empty orderer.
    #[must_use] 
    pub fn new() -> Self {
        Self {
            deps: HashMap::new(),
            order: Vec::new(),
            visited: HashSet::new(),
        }
    }

    /// Record that `ty` depends on `dep` (so `dep` must be declared first).
    pub fn add_dep(&mut self, ty: TypeRef, dep: TypeRef) {
        self.deps.entry(ty).or_default().push(dep);
    }

    /// Depth-first sort from `roots`; dependencies precede their dependents.
    pub fn sort(&mut self, roots: &[TypeRef]) -> Vec<TypeRef> {
        self.order.clear();
        self.visited.clear();
        for r in roots {
            self.visit(*r);
        }
        self.order.clone()
    }

    fn visit(&mut self, r: TypeRef) {
        if self.visited.contains(&r) {
            return;
        }
        self.visited.insert(r);
        let deps: Vec<TypeRef> = self.deps.get(&r).cloned().unwrap_or_default();
        for dep in deps {
            self.visit(dep);
        }
        self.order.push(r);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// StructLayout — precise field layout analysis
// ─────────────────────────────────────────────────────────────────────────────

/// Analysis of a struct's field layout.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StructLayout {
    /// Struct name.
    pub name: String,
    /// Total struct size in bytes.
    pub total_bytes: u32,
    /// Field layouts including synthesized padding entries.
    pub fields: Vec<FieldLayout>,
    /// Total padding in bytes.
    pub padding_bytes: u32,
    /// Whether any field is a bitfield.
    pub has_bitfields: bool,
}

/// Layout of a single struct field (or padding hole).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldLayout {
    /// Field name (synthetic `_pad_N` for padding).
    pub name: String,
    /// Bit offset from the start of the struct.
    pub bit_offset: u32,
    /// Bit size of the field.
    pub bit_size: u32,
    /// Rendered type string.
    pub type_str: String,
    /// True for synthesized padding entries.
    pub is_padding: bool,
}

impl FieldLayout {
    /// Byte offset of the field.
    #[must_use] 
    pub const fn byte_offset(&self) -> u32 {
        self.bit_offset / 8
    }
    /// Size in bytes (rounded up).
    #[must_use] 
    pub const fn byte_size(&self) -> u32 {
        self.bit_size.div_ceil(8)
    }
    /// Returns `true` if the field is a bitfield (size not byte-aligned).
    #[must_use] 
    pub const fn is_bitfield(&self) -> bool {
        !self.bit_size.is_multiple_of(8)
    }
}

impl StructLayout {
    /// Analyze a field list, synthesizing padding entries and totals.
    #[must_use] 
    pub fn analyze(name: &str, fields: &[StabsStructField], total_bytes: u32) -> Self {
        let mut layouts = Vec::new();
        // Bit arithmetic is done in u64: `bit_offset`, `bit_size` and
        // `total_bytes` all come straight out of a parsed `s<size>` descriptor,
        // so a hostile value such as 0x2000_0000 would overflow `u32 * 8`
        // (panicking in debug, wrapping to nonsense padding figures in release).
        let mut prev_end: u64 = 0;
        let mut padding: u64 = 0;
        let mut has_bitfields = false;

        for f in fields {
            let f_off = u64::from(f.bit_offset);
            // Check for padding before this field
            if f_off > prev_end {
                let pad = f_off - prev_end;
                layouts.push(FieldLayout {
                    name: format!("_pad_{prev_end}"),
                    bit_offset: u32::try_from(prev_end).unwrap_or(u32::MAX),
                    bit_size: u32::try_from(pad).unwrap_or(u32::MAX),
                    type_str: format!("uint8_t[{}]", pad / 8),
                    is_padding: true,
                });
                padding += pad / 8;
            }
            let bit_size = if f.bit_size > 0 {
                f.bit_size
            } else {
                // Assume 32-bit field if not specified
                32
            };
            if bit_size % 8 != 0 {
                has_bitfields = true;
            }
            layouts.push(FieldLayout {
                name: f.name.clone(),
                bit_offset: f.bit_offset,
                bit_size,
                type_str: format!("T#{}", f.type_ref.num),
                is_padding: false,
            });
            prev_end = f_off + u64::from(bit_size);
        }

        // Trailing padding
        let total_bits = u64::from(total_bytes) * 8;
        if total_bits > prev_end {
            let trail = total_bits - prev_end;
            padding += trail / 8;
        }

        Self {
            name: name.to_string(),
            total_bytes,
            fields: layouts,
            padding_bytes: u32::try_from(padding).unwrap_or(u32::MAX),
            has_bitfields,
        }
    }

    /// Fraction of the struct that is non-padding (0.0 to 1.0).
    #[must_use] 
    pub fn efficiency(&self) -> f64 {
        if self.total_bytes == 0 {
            return 1.0;
        }
        // Clamp: malformed input can declare more padding than total size,
        // which would otherwise yield a negative "efficiency".
        (1.0 - (f64::from(self.padding_bytes) / f64::from(self.total_bytes))).clamp(0.0, 1.0)
    }

    /// All fields excluding synthesized padding.
    #[must_use] 
    pub fn non_padding_fields(&self) -> Vec<&FieldLayout> {
        self.fields.iter().filter(|f| !f.is_padding).collect()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stabs_types::{StabsBaseType, StabsType, StabsTypeDb, TypeRef};

    fn make_db() -> StabsTypeDb {
        let mut db = StabsTypeDb::new();
        db.insert(
            TypeRef::local(1),
            StabsType::Base(StabsBaseType::Int {
                bits: 32,
                signed: true,
            }),
        );
        db.insert(TypeRef::local(2), StabsType::Base(StabsBaseType::Char));
        db
    }

    // --- CTypeDecl ---

    #[test]
    fn c_type_decl_simple_display() {
        let d = CTypeDecl::simple("int");
        assert_eq!(format!("{d}"), "int");
    }

    #[test]
    fn c_type_decl_typedef_display() {
        let mut d = CTypeDecl::named("my_int", "int");
        d.is_typedef = true;
        let s = format!("{d}");
        assert!(s.contains("typedef"));
        assert!(s.contains("my_int"));
    }

    // --- StabsReconstructor ---

    #[test]
    fn reconstruct_base_int() {
        let db = make_db();
        let mut rec = StabsReconstructor::new(&db);
        let s = rec.type_str(TypeRef::local(1));
        assert_eq!(s, "int");
    }

    #[test]
    fn reconstruct_base_char() {
        let db = make_db();
        let mut rec = StabsReconstructor::new(&db);
        assert_eq!(rec.type_str(TypeRef::local(2)), "char");
    }

    #[test]
    fn reconstruct_unknown_type() {
        let db = StabsTypeDb::new();
        let mut rec = StabsReconstructor::new(&db);
        let s = rec.type_str(TypeRef::local(99));
        assert!(s.contains("unknown"));
    }

    #[test]
    fn reconstruct_pointer() {
        let mut db = make_db();
        db.insert(
            TypeRef::local(3),
            StabsType::Pointer(crate::stabs_types::StabsPointerType {
                pointee: TypeRef::local(1),
            }),
        );
        let mut rec = StabsReconstructor::new(&db);
        let s = rec.type_str(TypeRef::local(3));
        assert!(s.contains("int"));
        assert!(s.contains('*'));
    }

    #[test]
    fn reconstruct_array() {
        let mut db = make_db();
        db.insert(
            TypeRef::local(4),
            StabsType::Array(StabsArrayType {
                index_type: TypeRef::local(1),
                lower: 0,
                upper: 9,
                element_type: TypeRef::local(1),
            }),
        );
        let mut rec = StabsReconstructor::new(&db);
        let s = rec.type_str(TypeRef::local(4));
        assert!(s.contains("10")); // count = 10
    }

    #[test]
    fn reconstruct_forward() {
        let mut db = StabsTypeDb::new();
        db.insert(
            TypeRef::local(1),
            StabsType::Forward {
                name: "Node".into(),
            },
        );
        let mut rec = StabsReconstructor::new(&db);
        let s = rec.type_str(TypeRef::local(1));
        assert!(s.contains("Node"));
    }

    #[test]
    fn reconstruct_all_returns_something() {
        let mut db = make_db();
        db.insert(
            TypeRef::local(5),
            StabsType::Composite(crate::stabs_types::StabsCompositeType::Struct {
                name: "Point".into(),
                byte_size: 8,
                fields: vec![],
            }),
        );
        let mut rec = StabsReconstructor::new(&db);
        let decls = rec.reconstruct_all();
        assert!(!decls.is_empty());
    }

    // --- TypeOrderer ---

    #[test]
    fn orderer_simple_chain() {
        let mut o = TypeOrderer::new();
        let a = TypeRef::local(1);
        let b = TypeRef::local(2);
        let c = TypeRef::local(3);
        o.add_dep(b, a);
        o.add_dep(c, b);
        let order = o.sort(&[c]);
        assert_eq!(order[0], a);
        assert_eq!(order[2], c);
    }

    #[test]
    fn orderer_no_deps() {
        let mut o = TypeOrderer::new();
        let a = TypeRef::local(1);
        let order = o.sort(&[a]);
        assert_eq!(order, vec![a]);
    }

    // --- StructLayout ---

    #[test]
    fn struct_layout_no_padding() {
        let fields = vec![
            StabsStructField {
                name: "x".into(),
                type_ref: TypeRef::local(1),
                bit_offset: 0,
                bit_size: 32,
            },
            StabsStructField {
                name: "y".into(),
                type_ref: TypeRef::local(1),
                bit_offset: 32,
                bit_size: 32,
            },
        ];
        let layout = StructLayout::analyze("Point", &fields, 8);
        assert_eq!(layout.padding_bytes, 0);
        assert!((layout.efficiency() - 1.0).abs() < 1e-10);
    }

    #[test]
    fn struct_layout_with_padding() {
        let fields = vec![
            StabsStructField {
                name: "a".into(),
                type_ref: TypeRef::local(1),
                bit_offset: 0,
                bit_size: 8,
            },
            StabsStructField {
                name: "b".into(),
                type_ref: TypeRef::local(1),
                bit_offset: 32,
                bit_size: 32,
            },
        ];
        let layout = StructLayout::analyze("Padded", &fields, 8);
        assert!(layout.padding_bytes > 0);
        assert!(layout.efficiency() < 1.0);
    }

    #[test]
    fn struct_layout_non_padding_count() {
        let fields = vec![StabsStructField {
            name: "x".into(),
            type_ref: TypeRef::local(1),
            bit_offset: 0,
            bit_size: 32,
        }];
        let layout = StructLayout::analyze("S", &fields, 4);
        assert_eq!(layout.non_padding_fields().len(), 1);
    }

    #[test]
    fn field_layout_byte_offset() {
        let f = FieldLayout {
            name: "x".into(),
            bit_offset: 32,
            bit_size: 32,
            type_str: "int".into(),
            is_padding: false,
        };
        assert_eq!(f.byte_offset(), 4);
    }

    #[test]
    fn field_layout_is_bitfield() {
        let bf = FieldLayout {
            name: "f".into(),
            bit_offset: 0,
            bit_size: 3,
            type_str: "int".into(),
            is_padding: false,
        };
        assert!(bf.is_bitfield());
        let regular = FieldLayout {
            name: "g".into(),
            bit_offset: 0,
            bit_size: 32,
            type_str: "int".into(),
            is_padding: false,
        };
        assert!(!regular.is_bitfield());
    }
}
