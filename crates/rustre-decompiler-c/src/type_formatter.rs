//! C type formatter.
//!
//! Converts internal type representations to valid C declaration syntax,
//! following the "inside-out" rule (declarations read from the name outward
//! through postfix operators then prefix operators).
//!
//! Examples:
//! - `int` → `"int"`
//! - `char *` → `"char *name"` / `"char *"`
//! - `int (*)(void)` → `"int (*fp)(void)"`
//! - `int [4]` → `"int name[4]"`
//! - `const unsigned long long` → `"const unsigned long long"`

// ── Base types ────────────────────────────────────────────────────────────────

/// Qualifiers that can be applied to a base type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Qualifier {
    Const,
    Volatile,
    Restrict,
}

impl std::fmt::Display for Qualifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Const => write!(f, "const"),
            Self::Volatile => write!(f, "volatile"),
            Self::Restrict => write!(f, "restrict"),
        }
    }
}

/// The set of signed/unsigned integer widths.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IntWidth {
    Char,
    Short,
    Int,
    Long,
    LongLong,
}

impl std::fmt::Display for IntWidth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Char => write!(f, "char"),
            Self::Short => write!(f, "short"),
            Self::Int => write!(f, "int"),
            Self::Long => write!(f, "long"),
            Self::LongLong => write!(f, "long long"),
        }
    }
}

/// A C type description.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CType {
    /// `void`
    Void,
    /// `_Bool`
    Bool,
    /// Signed integer.
    Int { width: IntWidth, signed: bool },
    /// `float`
    Float,
    /// `double`
    Double,
    /// `long double`
    LongDouble,
    /// A named struct/union/enum/typedef.
    Named(String),
    /// Qualified type.
    Qualified {
        qualifiers: Vec<Qualifier>,
        inner: Box<Self>,
    },
    /// Pointer to `inner`.
    Pointer(Box<Self>),
    /// Const pointer: `inner * const`.
    ConstPointer(Box<Self>),
    /// Array of `len` elements (None = unsized `[]`).
    Array {
        inner: Box<Self>,
        len: Option<usize>,
    },
    /// Function pointer / function type.
    Function {
        return_type: Box<Self>,
        params: Vec<Self>,
        variadic: bool,
    },
}

impl CType {
    // ── Convenience constructors ──────────────────────────────────────────────

    #[must_use]
    pub const fn int() -> Self {
        Self::Int {
            width: IntWidth::Int,
            signed: true,
        }
    }
    #[must_use]
    pub const fn uint() -> Self {
        Self::Int {
            width: IntWidth::Int,
            signed: false,
        }
    }
    #[must_use]
    pub const fn char() -> Self {
        Self::Int {
            width: IntWidth::Char,
            signed: true,
        }
    }
    #[must_use]
    pub const fn uchar() -> Self {
        Self::Int {
            width: IntWidth::Char,
            signed: false,
        }
    }
    #[must_use]
    pub const fn short() -> Self {
        Self::Int {
            width: IntWidth::Short,
            signed: true,
        }
    }
    #[must_use]
    pub const fn ushort() -> Self {
        Self::Int {
            width: IntWidth::Short,
            signed: false,
        }
    }
    #[must_use]
    pub const fn long() -> Self {
        Self::Int {
            width: IntWidth::Long,
            signed: true,
        }
    }
    #[must_use]
    pub const fn ulong() -> Self {
        Self::Int {
            width: IntWidth::Long,
            signed: false,
        }
    }
    #[must_use]
    pub const fn longlong() -> Self {
        Self::Int {
            width: IntWidth::LongLong,
            signed: true,
        }
    }
    #[must_use]
    pub const fn ulonglong() -> Self {
        Self::Int {
            width: IntWidth::LongLong,
            signed: false,
        }
    }
    #[must_use]
    pub fn ptr(inner: Self) -> Self {
        Self::Pointer(Box::new(inner))
    }
    #[must_use]
    pub fn array(inner: Self, len: usize) -> Self {
        Self::Array {
            inner: Box::new(inner),
            len: Some(len),
        }
    }
    #[must_use]
    pub fn func(ret: Self, params: Vec<Self>, variadic: bool) -> Self {
        Self::Function {
            return_type: Box::new(ret),
            params,
            variadic,
        }
    }
    #[must_use]
    pub fn named(name: impl Into<String>) -> Self {
        Self::Named(name.into())
    }
    #[must_use]
    pub fn const_qual(inner: Self) -> Self {
        Self::Qualified {
            qualifiers: vec![Qualifier::Const],
            inner: Box::new(inner),
        }
    }
}

// ── Type canonicalizer ────────────────────────────────────────────────────────

/// Normalises a `CType` by flattening redundant qualifiers.
#[derive(Debug, Default)]
pub struct TypeCanonicalizer;

impl TypeCanonicalizer {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Deduplicate and sort qualifiers.
    #[must_use]
    pub fn canonicalize(ty: CType) -> CType {
        match ty {
            CType::Qualified {
                mut qualifiers,
                inner,
            } => {
                qualifiers.sort_by_key(|q| *q as u8);
                qualifiers.dedup();
                let inner = Self::canonicalize(*inner);
                if qualifiers.is_empty() {
                    inner
                } else {
                    CType::Qualified {
                        qualifiers,
                        inner: Box::new(inner),
                    }
                }
            }
            CType::Pointer(inner) => CType::Pointer(Box::new(Self::canonicalize(*inner))),
            CType::ConstPointer(inner) => CType::ConstPointer(Box::new(Self::canonicalize(*inner))),
            CType::Array { inner, len } => CType::Array {
                inner: Box::new(Self::canonicalize(*inner)),
                len,
            },
            CType::Function {
                return_type,
                params,
                variadic,
            } => CType::Function {
                return_type: Box::new(Self::canonicalize(*return_type)),
                params: params.into_iter().map(Self::canonicalize).collect(),
                variadic,
            },
            other => other,
        }
    }
}

// ── Type formatter ────────────────────────────────────────────────────────────

/// Formats `CType` values as C declaration strings.
///
/// Implements the "inside-out" (cdecl) rule so that complex types like
/// `int (*fp)(int, char *)` are rendered correctly.
#[derive(Debug, Default)]
pub struct TypeFormatter {
    /// When true, `unsigned char` is spelled `uint8_t` etc. (stdint style).
    pub use_stdint: bool,
}

impl TypeFormatter {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub const fn with_stdint(use_stdint: bool) -> Self {
        Self { use_stdint }
    }

    // ── Public API ────────────────────────────────────────────────────────────

    /// Format a type without a declarator name — e.g. `"int *"`.
    #[must_use]
    pub fn format_type(&self, ty: &CType) -> String {
        self.format_decl(ty, "")
    }

    /// Format a full declaration — e.g. `"int *foo"` or `"int (*fp)(void)"`.
    ///
    /// If `name` is empty the result is an abstract declarator.
    #[must_use]
    pub fn format_decl(&self, ty: &CType, name: &str) -> String {
        let (prefix, suffix) = self.split(ty);
        let mid = name.trim();
        if suffix.is_empty() {
            if mid.is_empty() {
                prefix.trim_end().to_string()
            } else {
                format!("{prefix}{mid}").trim_end().to_string()
            }
        } else if mid.is_empty() {
            format!("{prefix}{suffix}").trim_end().to_string()
        } else {
            format!("{prefix}{mid}{suffix}").trim_end().to_string()
        }
    }

    /// Format a struct field declaration `type name;`.
    #[must_use]
    pub fn format_field(&self, ty: &CType, name: &str) -> String {
        format!("{};", self.format_decl(ty, name))
    }

    /// Format a parameter list for a function type.
    #[must_use]
    pub fn format_params(&self, params: &[CType], variadic: bool) -> String {
        if params.is_empty() && !variadic {
            return "void".to_string();
        }
        let mut parts: Vec<String> = params.iter().map(|p| self.format_type(p)).collect();
        if variadic {
            parts.push("...".to_string());
        }
        parts.join(", ")
    }

    // ── Core splitting logic ──────────────────────────────────────────────────

    /// Return `(prefix, suffix)` for the inside-out rule.
    ///
    /// `prefix` is everything to the left of the name (including a trailing
    /// space), `suffix` is everything to the right (array/function postfix
    /// operators). For pointer types `prefix` ends with `*` and no trailing
    /// space (the space is provided by the caller).
    fn split(&self, ty: &CType) -> (String, String) {
        match ty {
            CType::Void => ("void ".to_string(), String::new()),
            CType::Bool => ("_Bool ".to_string(), String::new()),
            CType::Float => ("float ".to_string(), String::new()),
            CType::Double => ("double ".to_string(), String::new()),
            CType::LongDouble => ("long double ".to_string(), String::new()),
            CType::Named(n) => (format!("{n} "), String::new()),

            CType::Int { width, signed } => {
                let s = self.format_int(*width, *signed);
                (format!("{s} "), String::new())
            }

            CType::Qualified { qualifiers, inner } => {
                let qual_str: String = qualifiers
                    .iter()
                    .map(std::string::ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(" ");
                let (inner_pre, inner_suf) = self.split(inner);
                (format!("{qual_str} {inner_pre}"), inner_suf)
            }

            CType::Pointer(inner) => {
                match inner.as_ref() {
                    // Array or function pointer — we need parentheses around `*name`.
                    CType::Array { .. } | CType::Function { .. } => {
                        let (inner_pre, inner_suf) = self.split(inner);
                        // Caller will wrap `*name` in parens.
                        (format!("{inner_pre}(*"), format!("){inner_suf}"))
                    }
                    _ => {
                        let (inner_pre, _) = self.split(inner);
                        (format!("{inner_pre}*"), String::new())
                    }
                }
            }

            CType::ConstPointer(inner) => {
                let (inner_pre, inner_suf) = self.split(inner);
                match inner.as_ref() {
                    CType::Array { .. } | CType::Function { .. } => {
                        (format!("{inner_pre}(* const"), format!("){inner_suf}"))
                    }
                    _ => (format!("{inner_pre}* const "), inner_suf),
                }
            }

            CType::Array { inner, len } => {
                let (inner_pre, inner_suf) = self.split(inner);
                let bracket = len.as_ref().map_or_else(|| "[]".to_string(), |n| format!("[{n}]"));
                (inner_pre, format!("{bracket}{inner_suf}"))
            }

            CType::Function {
                return_type,
                params,
                variadic,
            } => {
                let (ret_pre, _) = self.split(return_type);
                let params_str = self.format_params(params, *variadic);
                // For a plain function type (not a pointer-to-function) the
                // result is `ret name(params)`.
                (ret_pre, format!("({params_str})"))
            }
        }
    }

    fn format_int(&self, width: IntWidth, signed: bool) -> String {
        if self.use_stdint {
            return match (width, signed) {
                (IntWidth::Char, true) => "int8_t".into(),
                (IntWidth::Char, false) => "uint8_t".into(),
                (IntWidth::Short, true) => "int16_t".into(),
                (IntWidth::Short, false) => "uint16_t".into(),
                (IntWidth::Int | IntWidth::Long, true) => "int32_t".into(),
                (IntWidth::Int | IntWidth::Long, false) => "uint32_t".into(),
                (IntWidth::LongLong, true) => "int64_t".into(),
                (IntWidth::LongLong, false) => "uint64_t".into(),
            };
        }
        let sign = if signed { "" } else { "unsigned " };
        format!("{sign}{width}")
    }
}

// ── Typedef emitter ───────────────────────────────────────────────────────────

/// Emit a `typedef old new;` string.
#[must_use]
pub fn format_typedef(formatter: &TypeFormatter, ty: &CType, alias: &str) -> String {
    format!("typedef {};", formatter.format_decl(ty, alias))
}

/// Emit a `struct name { field; ... }` stub.
#[must_use]
pub fn format_struct_stub(
    name: &str,
    fields: &[(&CType, &str)],
    formatter: &TypeFormatter,
) -> String {
    use std::fmt::Write as _;
    let mut out = format!("struct {name} {{\n");
    for (ty, field_name) in fields {
        writeln!(out, "    {}", formatter.format_field(ty, field_name)).unwrap();
    }
    out.push_str("};");
    out
}

// ─────────────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;

    fn fmt() -> TypeFormatter {
        TypeFormatter::new()
    }

    // ── Simple base types ─────────────────────────────────────────────────────

    #[test]
    fn test_void() {
        assert_eq!(fmt().format_type(&CType::Void), "void");
    }

    #[test]
    fn test_int() {
        assert_eq!(fmt().format_type(&CType::int()), "int");
    }

    #[test]
    fn test_char() {
        assert_eq!(fmt().format_type(&CType::char()), "char");
    }

    #[test]
    fn test_unsigned_int() {
        assert_eq!(fmt().format_type(&CType::uint()), "unsigned int");
    }

    #[test]
    fn test_unsigned_char() {
        assert_eq!(fmt().format_type(&CType::uchar()), "unsigned char");
    }

    #[test]
    fn test_long_long() {
        assert_eq!(fmt().format_type(&CType::longlong()), "long long");
    }

    #[test]
    fn test_unsigned_long_long() {
        assert_eq!(fmt().format_type(&CType::ulonglong()), "unsigned long long");
    }

    #[test]
    fn test_float() {
        assert_eq!(fmt().format_type(&CType::Float), "float");
    }

    #[test]
    fn test_double() {
        assert_eq!(fmt().format_type(&CType::Double), "double");
    }

    #[test]
    fn test_named_struct() {
        assert_eq!(fmt().format_type(&CType::named("struct Foo")), "struct Foo");
    }

    // ── Pointer types ─────────────────────────────────────────────────────────

    #[test]
    fn test_pointer_to_int() {
        assert_eq!(fmt().format_decl(&CType::ptr(CType::int()), "p"), "int *p");
    }

    #[test]
    fn test_pointer_to_char_abstract() {
        assert_eq!(fmt().format_type(&CType::ptr(CType::char())), "char *");
    }

    #[test]
    fn test_pointer_to_void() {
        assert_eq!(
            fmt().format_decl(&CType::ptr(CType::Void), "vp"),
            "void *vp"
        );
    }

    #[test]
    fn test_const_int() {
        assert_eq!(
            fmt().format_type(&CType::const_qual(CType::int())),
            "const int"
        );
    }

    #[test]
    fn test_pointer_to_const_char() {
        let ty = CType::ptr(CType::const_qual(CType::char()));
        assert_eq!(fmt().format_decl(&ty, "s"), "const char *s");
    }

    #[test]
    fn test_const_pointer_to_int() {
        let ty = CType::ConstPointer(Box::new(CType::int()));
        assert_eq!(fmt().format_decl(&ty, "cp"), "int * const cp");
    }

    // ── Array types ───────────────────────────────────────────────────────────

    #[test]
    fn test_array_of_int() {
        let ty = CType::array(CType::int(), 4);
        assert_eq!(fmt().format_decl(&ty, "arr"), "int arr[4]");
    }

    #[test]
    fn test_unsized_array() {
        let ty = CType::Array {
            inner: Box::new(CType::char()),
            len: None,
        };
        assert_eq!(fmt().format_decl(&ty, "buf"), "char buf[]");
    }

    #[test]
    fn test_array_of_pointers() {
        let ty = CType::array(CType::ptr(CType::int()), 8);
        assert_eq!(fmt().format_decl(&ty, "pp"), "int *pp[8]");
    }

    // ── Function types ────────────────────────────────────────────────────────

    #[test]
    fn test_function_no_params() {
        let ty = CType::func(CType::Void, vec![], false);
        assert_eq!(fmt().format_decl(&ty, "f"), "void f(void)");
    }

    #[test]
    fn test_function_with_params() {
        let ty = CType::func(
            CType::int(),
            vec![CType::int(), CType::ptr(CType::char())],
            false,
        );
        assert_eq!(fmt().format_decl(&ty, "f"), "int f(int, char *)");
    }

    #[test]
    fn test_variadic_function() {
        let ty = CType::func(CType::int(), vec![CType::ptr(CType::char())], true);
        assert_eq!(fmt().format_decl(&ty, "printf"), "int printf(char *, ...)");
    }

    #[test]
    fn test_pointer_to_function() {
        let fn_ty = CType::func(CType::int(), vec![CType::Void], false);
        let ty = CType::ptr(fn_ty);
        assert_eq!(fmt().format_decl(&ty, "fp"), "int (*fp)(void)");
    }

    #[test]
    fn test_pointer_to_function_no_name() {
        let fn_ty = CType::func(CType::Void, vec![], false);
        let ty = CType::ptr(fn_ty);
        // Test expectation had a typo (missing ')'); correct C abstract declarator is `void (*)(void)`.
        assert_eq!(fmt().format_type(&ty), "void (*)(void)");
    }

    #[test]
    fn test_pointer_to_array() {
        let arr_ty = CType::array(CType::int(), 3);
        let ty = CType::ptr(arr_ty);
        assert_eq!(fmt().format_decl(&ty, "pa"), "int (*pa)[3]");
    }

    // ── stdint mode ───────────────────────────────────────────────────────────

    #[test]
    fn test_stdint_uint8() {
        let f = TypeFormatter::with_stdint(true);
        assert_eq!(f.format_type(&CType::uchar()), "uint8_t");
    }

    #[test]
    fn test_stdint_int32() {
        let f = TypeFormatter::with_stdint(true);
        assert_eq!(f.format_type(&CType::int()), "int32_t");
    }

    #[test]
    fn test_stdint_uint64() {
        let f = TypeFormatter::with_stdint(true);
        assert_eq!(f.format_type(&CType::ulonglong()), "uint64_t");
    }

    // ── Canonicalizer ─────────────────────────────────────────────────────────

    #[test]
    fn test_canonicalizer_deduplicates_qualifiers() {
        let _c = TypeCanonicalizer::new();
        let ty = CType::Qualified {
            qualifiers: vec![Qualifier::Const, Qualifier::Const, Qualifier::Volatile],
            inner: Box::new(CType::int()),
        };
        let canon = TypeCanonicalizer::canonicalize(ty);
        if let CType::Qualified { qualifiers, .. } = canon {
            assert_eq!(qualifiers.len(), 2);
        } else {
            panic!("expected Qualified");
        }
    }

    #[test]
    fn test_canonicalizer_strips_empty_qualifiers() {
        let _c = TypeCanonicalizer::new();
        let ty = CType::Qualified {
            qualifiers: vec![],
            inner: Box::new(CType::int()),
        };
        assert_eq!(TypeCanonicalizer::canonicalize(ty), CType::int());
    }

    // ── Typedef / struct helpers ──────────────────────────────────────────────

    #[test]
    fn test_format_typedef() {
        let ty = CType::ptr(CType::Void);
        assert_eq!(format_typedef(&fmt(), &ty, "PVOID"), "typedef void *PVOID;");
    }

    #[test]
    fn test_format_struct_stub() {
        let ty_i = CType::int();
        let ty_p = CType::ptr(CType::char());
        let fields: Vec<(&CType, &str)> = vec![(&ty_i, "count"), (&ty_p, "data")];
        let s = format_struct_stub("MyStruct", &fields, &fmt());
        assert!(s.contains("struct MyStruct"));
        assert!(s.contains("int count;"));
        assert!(s.contains("char *data;"));
    }

    #[test]
    fn test_format_field() {
        let ty = CType::array(CType::uchar(), 16);
        assert_eq!(fmt().format_field(&ty, "hash"), "unsigned char hash[16];");
    }

    // ── Nested complex types ──────────────────────────────────────────────────

    #[test]
    fn test_const_char_ptr_decl() {
        let ty = CType::ptr(CType::const_qual(CType::char()));
        assert_eq!(fmt().format_decl(&ty, "str"), "const char *str");
    }

    #[test]
    fn test_function_returning_pointer() {
        let ret = CType::ptr(CType::int());
        let ty = CType::func(ret, vec![CType::uint()], false);
        assert_eq!(fmt().format_decl(&ty, "alloc"), "int *alloc(unsigned int)");
    }
}
