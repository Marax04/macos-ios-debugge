//! Advanced C type printer.
//!
//! Emits human-readable C type declarations with:
//! - Typedef collapsing (emit `size_t` instead of `unsigned long long`).
//! - Anonymous struct/union nesting.
//! - Function pointer syntax.
//! - Array decay rules.
//! - `const` / `volatile` qualifiers.
//! - GCC/MSVC `__attribute__`/`__declspec` annotations.

use std::collections::HashMap;
use std::fmt::Write as _;

use crate::{
    DecompType, FunctionType, QualifiedType, StructType, TypeDatabase, UnionType,
};
use rustre_decompiler_expr::IntWidth;

// ─────────────────────────────────────────────────────────────────────────────
// Typedef registry
// ─────────────────────────────────────────────────────────────────────────────

/// Maps canonical C type strings to their preferred typedef aliases.
///
/// When the printer encounters a type that has a registered alias, it emits the
/// alias instead of the expanded form.  For example `uint64_t` instead of
/// `unsigned long long`.
#[derive(Debug, Default, Clone)]
pub struct TypedefRegistry {
    /// `(canonical_c_name → alias)`.
    aliases: HashMap<String, String>,
    /// Whether to prefer aliases over expanded types.
    pub prefer_aliases: bool,
}

impl TypedefRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self {
            aliases: HashMap::new(),
            prefer_aliases: true,
        }
    }

    /// Register a typedef alias.
    pub fn register(&mut self, canonical: impl Into<String>, alias: impl Into<String>) {
        self.aliases.insert(canonical.into(), alias.into());
    }

    /// Look up an alias for a canonical type string.
    #[must_use]
    pub fn alias_for(&self, canonical: &str) -> Option<&str> {
        if self.prefer_aliases {
            self.aliases.get(canonical).map(String::as_str)
        } else {
            None
        }
    }

    /// Populate with the standard C99/POSIX typedefs.
    pub fn load_standard(&mut self) {
        self.register("int8_t",   "int8_t");
        self.register("int16_t",  "int16_t");
        self.register("int32_t",  "int32_t");
        self.register("int64_t",  "int64_t");
        self.register("uint8_t",  "uint8_t");
        self.register("uint16_t", "uint16_t");
        self.register("uint32_t", "uint32_t");
        self.register("uint64_t", "uint64_t");
        self.register("char *",   "char *");
        self.register("void *",   "void *");
    }

    /// Populate with common Windows typedefs.
    pub fn load_windows(&mut self) {
        self.register("uint32_t", "DWORD");
        self.register("uint16_t", "WORD");
        self.register("uint8_t",  "BYTE");
        self.register("int32_t",  "BOOL");
        self.register("void *",   "HANDLE");
        self.register("uint64_t", "ULONGLONG");
        self.register("int64_t",  "LONGLONG");
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Printer configuration
// ─────────────────────────────────────────────────────────────────────────────

/// Attribute-emission options for the advanced type printer.
#[derive(Debug, Clone)]
pub struct PrintAttrs {
    /// Emit `__attribute__((packed))` for structs without padding.
    pub packed: bool,
    /// Emit `__declspec(align(N))` / `__attribute__((aligned(N)))`.
    pub aligned: bool,
    /// Emit `__cdecl` / `__stdcall` annotations on function types.
    pub calling_convention: bool,
}

impl Default for PrintAttrs {
    fn default() -> Self {
        Self { packed: false, aligned: true, calling_convention: true }
    }
}

/// Configuration flags for the advanced type printer.
#[derive(Debug, Clone)]
pub struct PrintConfig {
    /// Attribute emission options.
    pub attrs: PrintAttrs,
    /// Expand anonymous struct/union inline rather than emitting a forward
    /// declaration.
    pub expand_anonymous: bool,
    /// Collapse `typedef`-able types.
    pub collapse_typedefs: bool,
    /// Target ABI: `"msvc"` or `"gcc"`.
    pub target_abi: String,
    /// Indentation string.
    pub indent: String,
}

impl Default for PrintConfig {
    fn default() -> Self {
        Self {
            attrs: PrintAttrs::default(),
            expand_anonymous: true,
            collapse_typedefs: true,
            target_abi: "gcc".to_string(),
            indent: "    ".to_string(),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// AdvancedTypePrinter
// ─────────────────────────────────────────────────────────────────────────────

/// Prints `DecompType` values as idiomatic C declarations.
pub struct AdvancedTypePrinter {
    pub config: PrintConfig,
    pub typedefs: TypedefRegistry,
}

impl Default for AdvancedTypePrinter {
    fn default() -> Self {
        let mut typedefs = TypedefRegistry::new();
        typedefs.load_standard();
        Self {
            config: PrintConfig::default(),
            typedefs,
        }
    }
}

impl AdvancedTypePrinter {
    /// Create a printer with default settings.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a printer with Windows-type aliases enabled.
    #[must_use]
    pub fn for_windows() -> Self {
        let mut p = Self::new();
        p.typedefs.load_windows();
        p.config.attrs.calling_convention = true;
        p.config.target_abi = "msvc".to_string();
        p
    }

    // ── Main entry points ────────────────────────────────────────────────────

    /// Emit the C name for a type (no declarator, no variable name).
    #[must_use]
    pub fn print_type(&self, ty: &DecompType) -> String {
        self.print_type_inner(ty, false)
    }

    /// Emit a full variable declaration: `TYPE varname;`.
    #[must_use]
    pub fn print_decl(&self, ty: &DecompType, var_name: &str) -> String {
        self.print_declarator(ty, var_name)
    }

    /// Emit a `typedef TYPE alias;` declaration.
    #[must_use]
    pub fn print_typedef(&self, alias: &str, ty: &DecompType) -> String {
        format!("typedef {};", self.print_declarator(ty, alias))
    }

    /// Emit a qualified type (with `const` / `volatile` prefix).
    #[must_use]
    pub fn print_qualified(&self, qt: &QualifiedType) -> String {
        let q = qt.qualifiers.qualifier_string();
        let t = self.print_type(&qt.ty);
        if q.is_empty() { t } else { format!("{q} {t}") }
    }

    /// Emit a struct declaration with field comments.
    #[must_use]
    pub fn print_struct(&self, st: &StructType, indent_level: usize) -> String {
        let pad = self.config.indent.repeat(indent_level);
        let inner_pad = self.config.indent.repeat(indent_level + 1);
        let mut out = format!("{pad}struct {} {{\n", st.name);
        for field in &st.fields {
            let decl = self.print_declarator(&field.ty, &field.name);
            writeln!(out, "{inner_pad}{decl}; /* offset 0x{:x} */", field.offset).unwrap();
        }
        // Emit attribute annotations.
        if self.config.attrs.packed && !self.config.target_abi.contains("msvc") {
            writeln!(out, "{pad}}} __attribute__((packed)); /* size = 0x{:x} */", st.total_size).unwrap();
        } else {
            writeln!(out, "{pad}}}; /* size = 0x{:x} */", st.total_size).unwrap();
        }
        out
    }

    /// Emit a union declaration.
    #[must_use]
    pub fn print_union(&self, u: &UnionType, indent_level: usize) -> String {
        let pad = self.config.indent.repeat(indent_level);
        let inner_pad = self.config.indent.repeat(indent_level + 1);
        let mut out = format!("{pad}union {} {{\n", u.name);
        for member in &u.members {
            let decl = self.print_declarator(&member.ty, &member.name);
            writeln!(out, "{inner_pad}{decl};").unwrap();
        }
        writeln!(out, "{pad}}}; /* size = 0x{:x} */", u.total_size).unwrap();
        out
    }

    /// Emit a function prototype.
    #[must_use]
    pub fn print_function(&self, f: &FunctionType) -> String {
        let ret = self.print_type(&f.return_type);
        let cc = if self.config.attrs.calling_convention {
            format!(" {} ", f.calling_convention.as_str())
        } else {
            " ".to_string()
        };
        let params: Vec<String> = f
            .parameters
            .iter()
            .map(|(name, ty)| format!("{} {name}", self.print_type(ty)))
            .collect();
        let variadic = if f.is_variadic { ", ..." } else { "" };
        format!(
            "{ret}{cc}{}({}{})",
            f.name,
            params.join(", "),
            variadic
        )
    }

    /// Emit all types in a database as C declarations.
    #[must_use]
    pub fn print_database(&self, db: &TypeDatabase) -> String {
        let mut out = String::new();
        for name in db.structs.keys() {
            if let Some(st) = db.get_struct(name) {
                out.push_str(&self.print_struct(st, 0));
                out.push('\n');
            }
        }
        for (alias, ty) in &db.typedefs {
            writeln!(out, "typedef {} {};", self.print_type(ty), alias).unwrap();
        }
        for f in db.functions.values() {
            writeln!(out, "{};", self.print_function(f)).unwrap();
        }
        out
    }

    // ── Internal helpers ─────────────────────────────────────────────────────

    fn print_type_inner(&self, ty: &DecompType, in_ptr_context: bool) -> String {
        match ty {
            DecompType::Void => "void".to_string(),
            DecompType::Bool => "bool".to_string(),
            DecompType::Int(w) => {
                let canonical = int_width_cname(*w);
                // Try typedef alias.
                if self.config.collapse_typedefs
                    && let Some(alias) = self.typedefs.alias_for(canonical) {
                        return alias.to_string();
                    }
                canonical.to_string()
            }
            DecompType::Float32 => "float".to_string(),
            DecompType::Float64 => "double".to_string(),
            DecompType::Ptr(inner) => {
                format!("{} *", self.print_type_inner(inner, true))
            }
            DecompType::Array(elem, n) => {
                // In a pointer context, decay to pointer.
                if in_ptr_context && *n == 0 {
                    format!("{} *", self.print_type_inner(elem, true))
                } else {
                    self.print_type_inner(elem, false)
                }
            }
            DecompType::Struct(st) => {
                if self.config.expand_anonymous && st.name.starts_with("anon_") {
                    // Inline anonymous struct.
                    let mut out = "struct {\n".to_string();
                    for f in &st.fields {
                        let decl = self.print_declarator(&f.ty, &f.name);
                        writeln!(out, "    {decl};").unwrap();
                    }
                    out.push('}');
                    out
                } else {
                    format!("struct {}", st.name)
                }
            }
            DecompType::FnPtr { ret, params } => {
                let ret_s = self.print_type_inner(ret, false);
                let params_s: Vec<String> = params
                    .iter()
                    .map(|p| self.print_type_inner(p, false))
                    .collect();
                format!("{ret_s} (*)({})", params_s.join(", "))
            }
            DecompType::CStr => {
                self.typedefs.alias_for("char *").map_or_else(|| "char *".to_string(), str::to_string)
            }
            DecompType::Enum { name, .. } => format!("enum {name}"),
            DecompType::Unknown => "void *".to_string(),
        }
    }

    /// Build a C declarator for `ty varname`.
    ///
    /// Handles array, function-pointer, and plain types correctly.
    fn print_declarator(&self, ty: &DecompType, varname: &str) -> String {
        match ty {
            DecompType::Array(elem, n) => {
                let elem_s = self.print_type_inner(elem, false);
                if *n == 0 {
                    format!("{elem_s} {varname}[]")
                } else {
                    format!("{elem_s} {varname}[{n}]")
                }
            }
            DecompType::FnPtr { ret, params } => {
                let ret_s = self.print_type_inner(ret, false);
                let params_s: Vec<String> = params
                    .iter()
                    .map(|p| self.print_type_inner(p, false))
                    .collect();
                format!("{ret_s} (*{varname})({})", params_s.join(", "))
            }
            _ => {
                let type_s = self.print_type_inner(ty, false);
                format!("{type_s} {varname}")
            }
        }
    }

    // ── Qualified type helpers ────────────────────────────────────────────────

    /// Emit a type with `const` qualifier in the correct C position.
    ///
    /// C rules:
    /// * `const int` — the integer is const.
    /// * `int * const` — the pointer is const.
    /// * `const int *` — the pointed-to int is const.
    #[must_use]
    pub fn print_const_type(&self, ty: &DecompType, const_ptr: bool) -> String {
        match ty {
            DecompType::Ptr(inner) => {
                let inner_s = self.print_type_inner(inner, true);
                if const_ptr {
                    format!("{inner_s} * const")
                } else {
                    format!("const {inner_s} *")
                }
            }
            _ => format!("const {}", self.print_type_inner(ty, false)),
        }
    }

    /// Emit a `volatile`-qualified type.
    #[must_use]
    pub fn print_volatile_type(&self, ty: &DecompType) -> String {
        format!("volatile {}", self.print_type_inner(ty, false))
    }

    /// Emit an `__attribute__((aligned(N)))` annotation string (GCC style).
    #[must_use]
    pub fn alignment_attribute(align: u64) -> String {
        format!("__attribute__((aligned({align})))")
    }

    /// Emit a `__declspec(align(N))` annotation string (MSVC style).
    #[must_use]
    pub fn declspec_align(align: u64) -> String {
        format!("__declspec(align({align}))")
    }

    // ── Enum emitter ──────────────────────────────────────────────────────────

    /// Emit a full `enum` declaration.
    #[must_use]
    pub fn print_enum(&self, name: &str, variants: &[(String, i64)], indent_level: usize) -> String {
        let pad = self.config.indent.repeat(indent_level);
        let inner = self.config.indent.repeat(indent_level + 1);
        let mut out = format!("{pad}enum {name} {{\n");
        for (vname, value) in variants {
            writeln!(out, "{inner}{vname} = {value},").unwrap();
        }
        writeln!(out, "{pad}}};").unwrap();
        out
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

const fn int_width_cname(w: IntWidth) -> &'static str {
    match w {
        IntWidth::I8 => "int8_t",
        IntWidth::I16 => "int16_t",
        IntWidth::I32 => "int32_t",
        IntWidth::I64 => "int64_t",
        IntWidth::U8 => "uint8_t",
        IntWidth::U16 => "uint16_t",
        IntWidth::U32 => "uint32_t",
        IntWidth::U64 => "uint64_t",
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{FunctionType, StructField, StructType, TypeQualifier};

    fn i32() -> DecompType { DecompType::Int(IntWidth::I32) }
    fn i64() -> DecompType { DecompType::Int(IntWidth::I64) }
    fn ptr_void() -> DecompType { DecompType::Ptr(Box::new(DecompType::Void)) }
    fn ptr_i32() -> DecompType { DecompType::Ptr(Box::new(i32())) }

    fn printer() -> AdvancedTypePrinter { AdvancedTypePrinter::new() }

    // ── print_type ────────────────────────────────────────────────────────────

    #[test]
    fn test_print_void() { assert_eq!(printer().print_type(&DecompType::Void), "void"); }
    #[test]
    fn test_print_bool() { assert_eq!(printer().print_type(&DecompType::Bool), "bool"); }
    #[test]
    fn test_print_i32() { assert_eq!(printer().print_type(&i32()), "int32_t"); }
    #[test]
    fn test_print_ptr_void() { assert_eq!(printer().print_type(&ptr_void()), "void *"); }
    #[test]
    fn test_print_cstr() { assert_eq!(printer().print_type(&DecompType::CStr), "char *"); }
    #[test]
    fn test_print_float32() { assert_eq!(printer().print_type(&DecompType::Float32), "float"); }
    #[test]
    fn test_print_float64() { assert_eq!(printer().print_type(&DecompType::Float64), "double"); }

    // ── print_decl ────────────────────────────────────────────────────────────

    #[test]
    fn test_decl_array() {
        let arr = DecompType::Array(Box::new(i32()), 10);
        assert_eq!(printer().print_decl(&arr, "buf"), "int32_t buf[10]");
    }

    #[test]
    fn test_decl_ptr() {
        assert_eq!(printer().print_decl(&ptr_i32(), "p"), "int32_t * p");
    }

    // ── function pointer ──────────────────────────────────────────────────────

    #[test]
    fn test_fnptr() {
        let fp = DecompType::FnPtr {
            ret: Box::new(i32()),
            params: vec![i32(), i64()],
        };
        let s = printer().print_decl(&fp, "callback");
        assert!(s.contains("callback"));
        assert!(s.contains("int32_t"));
    }

    // ── typedef ───────────────────────────────────────────────────────────────

    #[test]
    fn test_typedef_emit() {
        let s = printer().print_typedef("MyInt", &i32());
        assert!(s.starts_with("typedef"));
        assert!(s.contains("MyInt"));
    }

    // ── struct ────────────────────────────────────────────────────────────────

    #[test]
    fn test_struct_has_fields() {
        let st = StructType {
            name: "Point".to_string(),
            fields: vec![
                StructField { offset: 0, name: "x".to_string(), ty: i32() },
                StructField { offset: 4, name: "y".to_string(), ty: i32() },
            ],
            total_size: 8,
        };
        let s = printer().print_struct(&st, 0);
        assert!(s.contains("x"));
        assert!(s.contains("y"));
        assert!(s.contains("Point"));
    }

    // ── anonymous struct expansion ────────────────────────────────────────────

    #[test]
    fn test_anonymous_struct_inline() {
        let st = StructType {
            name: "anon_0".to_string(),
            fields: vec![
                StructField { offset: 0, name: "a".to_string(), ty: i32() },
            ],
            total_size: 4,
        };
        let ty = DecompType::Struct(Box::new(st));
        let s = printer().print_type(&ty);
        assert!(s.contains("struct {"));
    }

    // ── const / volatile ──────────────────────────────────────────────────────

    #[test]
    fn test_const_ptr_to_int() {
        let s = printer().print_const_type(&ptr_i32(), false);
        assert!(s.contains("const"));
        assert!(s.contains("int32_t"));
    }

    #[test]
    fn test_const_ptr_itself() {
        let s = printer().print_const_type(&ptr_i32(), true);
        assert!(s.contains("* const"));
    }

    #[test]
    fn test_volatile_type() {
        let s = printer().print_volatile_type(&i32());
        assert!(s.starts_with("volatile"));
    }

    // ── attribute helpers ─────────────────────────────────────────────────────

    #[test]
    fn test_alignment_attribute() {
        let s = AdvancedTypePrinter::alignment_attribute(16);
        assert_eq!(s, "__attribute__((aligned(16)))");
    }

    #[test]
    fn test_declspec_align() {
        let s = AdvancedTypePrinter::declspec_align(8);
        assert_eq!(s, "__declspec(align(8))");
    }

    // ── enum ──────────────────────────────────────────────────────────────────

    #[test]
    fn test_enum_emit() {
        let variants = vec![
            ("A".to_string(), 0i64),
            ("B".to_string(), 1),
            ("C".to_string(), 2),
        ];
        let s = printer().print_enum("Color", &variants, 0);
        assert!(s.contains("Color"));
        assert!(s.contains("A = 0"));
        assert!(s.contains("B = 1"));
    }

    // ── Windows printer ───────────────────────────────────────────────────────

    #[test]
    fn test_windows_printer_dword() {
        let p = AdvancedTypePrinter::for_windows();
        // DWORD is an alias for uint32_t.
        let s = p.print_type(&DecompType::Int(IntWidth::U32));
        assert_eq!(s, "DWORD");
    }

    // ── function printer ──────────────────────────────────────────────────────

    #[test]
    fn test_print_function_prototype() {
        let mut f = FunctionType::new("add", i32());
        f.add_param("a", i32());
        f.add_param("b", i32());
        let s = printer().print_function(&f);
        assert!(s.contains("add"));
        assert!(s.contains("int32_t"));
    }

    // ── qualified type ────────────────────────────────────────────────────────

    #[test]
    fn test_qualified_const() {
        let qt = QualifiedType::new(i32()).with_qualifiers(TypeQualifier::CONST);
        let s = printer().print_qualified(&qt);
        assert!(s.contains("const"));
    }
}
