//! `python_type_stubs` — .pyi type stub generator for the `RustRE` Python API.
//!
//! Provides [`PythonTypeStubs`], a registry of type stub definitions, and
//! [`StubGenerator`] which renders them to `.pyi` format understood by mypy,
//! pyright, and similar type-checkers.

use std::fmt;

use serde::{Deserialize, Serialize};

// ── TypeAnnotation ────────────────────────────────────────────────────────────

/// A Python type annotation.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TypeAnnotation {
    /// `None` (Python None type).
    None_,
    /// `bool`
    Bool,
    /// `int`
    Int,
    /// `float`
    Float,
    /// `str`
    Str,
    /// `bytes`
    Bytes,
    /// `list[T]`
    List(Box<Self>),
    /// `dict[K, V]`
    Dict(Box<Self>, Box<Self>),
    /// `tuple[T, ...]`
    Tuple(Vec<Self>),
    /// `Optional[T]` — shorthand for `Union[T, None]`.
    Optional(Box<Self>),
    /// `Union[A, B, ...]`
    Union(Vec<Self>),
    /// An arbitrary named type (e.g. `BinaryView`, `Function`, `Address`).
    Named(String),
    /// `Any`
    Any,
    /// `...` (ellipsis, used in stub bodies).
    Ellipsis,
}

impl fmt::Display for TypeAnnotation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::None_ => write!(f, "None"),
            Self::Bool => write!(f, "bool"),
            Self::Int => write!(f, "int"),
            Self::Float => write!(f, "float"),
            Self::Str => write!(f, "str"),
            Self::Bytes => write!(f, "bytes"),
            Self::List(t) => write!(f, "list[{t}]"),
            Self::Dict(k, v) => write!(f, "dict[{k}, {v}]"),
            Self::Tuple(ts) => {
                write!(f, "tuple[")?;
                for (i, t) in ts.iter().enumerate() {
                    if i > 0 { write!(f, ", ")?; }
                    write!(f, "{t}")?;
                }
                write!(f, "]")
            }
            Self::Optional(t) => write!(f, "Optional[{t}]"),
            Self::Union(ts) => {
                write!(f, "Union[")?;
                for (i, t) in ts.iter().enumerate() {
                    if i > 0 { write!(f, ", ")?; }
                    write!(f, "{t}")?;
                }
                write!(f, "]")
            }
            Self::Named(n) => write!(f, "{n}"),
            Self::Any => write!(f, "Any"),
            Self::Ellipsis => write!(f, "..."),
        }
    }
}

impl TypeAnnotation {
    /// Convenience constructor for a named type.
    #[must_use]
    pub fn named(name: impl Into<String>) -> Self {
        Self::Named(name.into())
    }

    /// Convenience constructor for `list[T]`.
    #[must_use]
    pub fn list_of(item: Self) -> Self {
        Self::List(Box::new(item))
    }

    /// Convenience constructor for `dict[str, V]`.
    #[must_use]
    pub fn str_dict(value: Self) -> Self {
        Self::Dict(Box::new(Self::Str), Box::new(value))
    }

    /// Convenience constructor for `Optional[T]`.
    #[must_use]
    pub fn opt(inner: Self) -> Self {
        Self::Optional(Box::new(inner))
    }

    /// Return `true` if this annotation is `None_` or `Optional`.
    #[must_use]
    pub const fn is_nullable(&self) -> bool {
        matches!(self, Self::None_ | Self::Optional(_))
    }

    /// Return a human-readable summary without generics.
    #[must_use]
    pub const fn base_name(&self) -> &str {
        match self {
            Self::None_ => "None",
            Self::Bool => "bool",
            Self::Int => "int",
            Self::Float => "float",
            Self::Str => "str",
            Self::Bytes => "bytes",
            Self::List(_) => "list",
            Self::Dict(_, _) => "dict",
            Self::Tuple(_) => "tuple",
            Self::Optional(_) => "Optional",
            Self::Union(_) => "Union",
            Self::Named(n) => n.as_str(),
            Self::Any => "Any",
            Self::Ellipsis => "...",
        }
    }
}

// ── FunctionSignature ─────────────────────────────────────────────────────────

/// A typed parameter in a function signature.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TypedParam {
    /// Parameter name.
    pub name: String,
    /// Python type annotation.
    pub annotation: TypeAnnotation,
    /// Whether the parameter has a default value.
    pub has_default: bool,
    /// Default value expression (Python literal string).
    pub default_expr: Option<String>,
    /// Whether this is a `*args` parameter.
    pub variadic: bool,
    /// Whether this is a `**kwargs` parameter.
    pub keyword_variadic: bool,
}

impl TypedParam {
    /// Create a simple required parameter.
    #[must_use]
    pub fn new(name: impl Into<String>, annotation: TypeAnnotation) -> Self {
        Self {
            name: name.into(),
            annotation,
            has_default: false,
            default_expr: None,
            variadic: false,
            keyword_variadic: false,
        }
    }

    /// Add a default value.
    #[must_use]
    pub fn with_default(mut self, expr: impl Into<String>) -> Self {
        self.has_default = true;
        self.default_expr = Some(expr.into());
        self
    }

    /// Mark as `*args`.
    #[must_use]
    pub const fn variadic(mut self) -> Self {
        self.variadic = true;
        self
    }

    /// Mark as `**kwargs`.
    #[must_use]
    pub const fn keyword_variadic(mut self) -> Self {
        self.keyword_variadic = true;
        self
    }

    /// Render this parameter as it appears in a `.pyi` signature.
    #[must_use]
    pub fn render(&self) -> String {
        let prefix = if self.keyword_variadic { "**" } else if self.variadic { "*" } else { "" };
        let base = format!("{prefix}{}: {}", self.name, self.annotation);
        if let Some(def) = &self.default_expr {
            format!("{base} = {def}")
        } else {
            base
        }
    }
}

/// Describes the calling convention / decorator of a Python function.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub enum MethodKind {
    /// An ordinary function or instance method.
    #[default]
    Regular,
    /// Decorated with `@classmethod`.
    ClassMethod,
    /// Decorated with `@staticmethod`.
    StaticMethod,
    /// Decorated with `@property`.
    Property,
}

/// Flags that describe how a Python function/method is decorated.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FunctionFlags {
    /// Whether this is an `async def`.
    pub is_async: bool,
    /// Calling convention / decorator kind.
    pub kind: MethodKind,
}

impl FunctionFlags {
    /// Return `true` if the function is a `@classmethod`.
    #[must_use]
    pub fn is_classmethod(&self) -> bool { self.kind == MethodKind::ClassMethod }
    /// Return `true` if the function is a `@staticmethod`.
    #[must_use]
    pub fn is_staticmethod(&self) -> bool { self.kind == MethodKind::StaticMethod }
    /// Return `true` if the function is a `@property`.
    #[must_use]
    pub fn is_property(&self) -> bool { self.kind == MethodKind::Property }
}

/// A complete function or method signature.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionSignature {
    /// Function name.
    pub name: String,
    /// Parameters (excluding `self` for methods — add it explicitly).
    pub params: Vec<TypedParam>,
    /// Return type annotation.
    pub return_type: TypeAnnotation,
    /// Docstring for the stub.
    pub docstring: Option<String>,
    /// Decoration flags (`async`, `classmethod`, `staticmethod`, `property`).
    pub flags: FunctionFlags,
    /// Decorators to emit (without the `@`).
    pub decorators: Vec<String>,
}

impl FunctionSignature {
    /// Create a basic function signature.
    #[must_use]
    pub fn new(name: impl Into<String>, return_type: TypeAnnotation) -> Self {
        Self {
            name: name.into(),
            params: Vec::new(),
            return_type,
            docstring: None,
            flags: FunctionFlags::default(),
            decorators: Vec::new(),
        }
    }

    /// Add a parameter.
    #[must_use]
    pub fn param(mut self, p: TypedParam) -> Self {
        self.params.push(p);
        self
    }

    /// Set docstring.
    #[must_use]
    pub fn doc(mut self, s: impl Into<String>) -> Self {
        self.docstring = Some(s.into());
        self
    }

    /// Mark as async.
    #[must_use]
    pub fn async_def(mut self) -> Self {
        self.flags.is_async = true;
        self
    }

    /// Render to `.pyi` format with `indent` leading spaces.
    #[must_use]
    pub fn render_pyi(&self, indent: usize) -> String {
        use std::fmt::Write as _;
        let pad = " ".repeat(indent);
        let mut out = String::new();

        for dec in &self.decorators {
            let _ = writeln!(out, "{pad}@{dec}");
        }
        if self.flags.is_classmethod() { let _ = writeln!(out, "{pad}@classmethod"); }
        if self.flags.is_staticmethod() { let _ = writeln!(out, "{pad}@staticmethod"); }
        if self.flags.is_property() { let _ = writeln!(out, "{pad}@property"); }

        let async_kw = if self.flags.is_async { "async " } else { "" };
        let param_str = self.params.iter().map(TypedParam::render).collect::<Vec<_>>().join(", ");
        let _ = writeln!(out, "{pad}{async_kw}def {}({param_str}) -> {}: ...", self.name, self.return_type);

        out
    }

    /// Number of required (non-default) parameters.
    #[must_use]
    pub fn required_param_count(&self) -> usize {
        self.params.iter().filter(|p| !p.has_default && !p.variadic && !p.keyword_variadic).count()
    }
}

// ── PropertySignature ─────────────────────────────────────────────────────────

/// A Python property stub.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PropertySignature {
    /// Property name.
    pub name: String,
    /// Property type.
    pub ty: TypeAnnotation,
    /// Whether the property is read-only (no setter).
    pub read_only: bool,
    /// Short description.
    pub description: String,
}

impl PropertySignature {
    #[must_use]
    pub fn new(name: impl Into<String>, ty: TypeAnnotation) -> Self {
        Self {
            name: name.into(),
            ty,
            read_only: true,
            description: String::new(),
        }
    }

    #[must_use]
    pub const fn writable(mut self) -> Self {
        self.read_only = false;
        self
    }

    #[must_use]
    pub fn desc(mut self, s: impl Into<String>) -> Self {
        self.description = s.into();
        self
    }

    /// Render to `.pyi` format.
    #[must_use]
    pub fn render_pyi(&self, indent: usize) -> String {
        use std::fmt::Write as _;
        let pad = " ".repeat(indent);
        let mut out = String::new();
        let _ = writeln!(out, "{pad}@property");
        let _ = writeln!(out, "{pad}def {}(self) -> {}: ...", self.name, self.ty);
        if !self.read_only {
            let _ = writeln!(out, "{pad}@{}.setter", self.name);
            let _ = writeln!(out, "{pad}def {}(self, value: {}) -> None: ...", self.name, self.ty);
        }
        out
    }
}

// ── ClassSignature ────────────────────────────────────────────────────────────

/// A Python class stub definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClassSignature {
    /// Class name.
    pub name: String,
    /// Base classes.
    pub bases: Vec<String>,
    /// Methods.
    pub methods: Vec<FunctionSignature>,
    /// Properties.
    pub properties: Vec<PropertySignature>,
    /// Class-level attributes (name → type).
    pub class_attrs: Vec<(String, TypeAnnotation)>,
    /// Short description.
    pub docstring: Option<String>,
}

impl ClassSignature {
    /// Create a class stub.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            bases: Vec::new(),
            methods: Vec::new(),
            properties: Vec::new(),
            class_attrs: Vec::new(),
            docstring: None,
        }
    }

    #[must_use]
    pub fn base(mut self, base: impl Into<String>) -> Self {
        self.bases.push(base.into());
        self
    }

    #[must_use]
    pub fn method(mut self, m: FunctionSignature) -> Self {
        self.methods.push(m);
        self
    }

    #[must_use]
    pub fn property(mut self, p: PropertySignature) -> Self {
        self.properties.push(p);
        self
    }

    #[must_use]
    pub fn attr(mut self, name: impl Into<String>, ty: TypeAnnotation) -> Self {
        self.class_attrs.push((name.into(), ty));
        self
    }

    #[must_use]
    pub fn doc(mut self, s: impl Into<String>) -> Self {
        self.docstring = Some(s.into());
        self
    }

    /// Render to `.pyi` format.
    #[must_use]
    pub fn render_pyi(&self) -> String {
        use std::fmt::Write as _;
        let base_str = if self.bases.is_empty() {
            String::new()
        } else {
            format!("({})", self.bases.join(", "))
        };
        let mut out = format!("class {}{}:\n", self.name, base_str);

        if let Some(ds) = &self.docstring {
            let _ = writeln!(out, "    \"\"\"{ds}\"\"\"");
        }

        for (attr, ty) in &self.class_attrs {
            let _ = writeln!(out, "    {attr}: {ty}");
        }

        for prop in &self.properties {
            out.push_str(&prop.render_pyi(4));
        }

        for method in &self.methods {
            out.push_str(&method.render_pyi(4));
        }

        if self.class_attrs.is_empty() && self.methods.is_empty() && self.properties.is_empty() {
            out.push_str("    ...\n");
        }

        out
    }
}

// ── TypeStub ─────────────────────────────────────────────────────────────────

/// A single `.pyi` type stub — either a function or a class.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TypeStub {
    /// A top-level function stub.
    Function(FunctionSignature),
    /// A class stub with methods and properties.
    Class(ClassSignature),
    /// A type alias: `Name = TypeAnnotation`.
    TypeAlias { name: String, ty: TypeAnnotation },
    /// A module-level constant: `NAME: Type`.
    Constant { name: String, ty: TypeAnnotation },
}

impl TypeStub {
    /// Return the primary name of this stub.
    #[must_use]
    pub fn name(&self) -> &str {
        match self {
            Self::Function(f) => &f.name,
            Self::Class(c) => &c.name,
            Self::TypeAlias { name, .. } | Self::Constant { name, .. } => name,
        }
    }

    /// Render to `.pyi` format.
    #[must_use]
    pub fn render_pyi(&self) -> String {
        match self {
            Self::Function(f) => f.render_pyi(0),
            Self::Class(c) => c.render_pyi(),
            Self::TypeAlias { name, ty } => format!("{name} = {ty}\n"),
            Self::Constant { name, ty } => format!("{name}: {ty}\n"),
        }
    }
}

// ── PythonTypeStubs ───────────────────────────────────────────────────────────

/// Registry of all Python type stubs for the `RustRE` API.
#[derive(Debug, Default)]
pub struct PythonTypeStubs {
    stubs: Vec<TypeStub>,
    /// Module-level imports to include in the generated stub.
    imports: Vec<String>,
}

impl PythonTypeStubs {
    /// Create an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a registry pre-populated with the standard `RustRE` Python API stubs.
    #[must_use]
    pub fn standard() -> Self {
        let mut s = Self::new();
        s.add_import("from __future__ import annotations");
        s.add_import("from typing import Any, Optional, Union, List, Dict, Tuple, Callable");

        // BinaryView class
        s.register(TypeStub::Class(
            ClassSignature::new("BinaryView")
                .doc("Represents a loaded binary in RustRE.")
                .attr("name", TypeAnnotation::Str)
                .attr("path", TypeAnnotation::Str)
                .attr("length", TypeAnnotation::Int)
                .method(FunctionSignature::new(
                    "functions",
                    TypeAnnotation::list_of(TypeAnnotation::named("Function")),
                ))
                .method(FunctionSignature::new(
                    "strings",
                    TypeAnnotation::list_of(TypeAnnotation::named("StringRef")),
                ))
                .method(
                    FunctionSignature::new("read", TypeAnnotation::Bytes)
                        .param(TypedParam::new("self", TypeAnnotation::named("BinaryView")))
                        .param(TypedParam::new("addr", TypeAnnotation::Int))
                        .param(TypedParam::new("length", TypeAnnotation::Int)),
                ),
        ));

        // Function class
        s.register(TypeStub::Class(
            ClassSignature::new("Function")
                .doc("Represents a function in a binary.")
                .attr("start", TypeAnnotation::Int)
                .attr("name", TypeAnnotation::Str)
                .method(
                    FunctionSignature::new("basic_blocks", TypeAnnotation::list_of(TypeAnnotation::named("BasicBlock")))
                        .param(TypedParam::new("self", TypeAnnotation::named("Function"))),
                )
                .method(
                    FunctionSignature::new("callers", TypeAnnotation::list_of(TypeAnnotation::named("ReferenceSource")))
                        .param(TypedParam::new("self", TypeAnnotation::named("Function"))),
                ),
        ));

        // Top-level helpers
        s.register(TypeStub::Function(
            FunctionSignature::new("load_binary", TypeAnnotation::named("BinaryView"))
                .param(TypedParam::new("path", TypeAnnotation::Str))
                .doc("Load a binary file and return a BinaryView."),
        ));

        s.register(TypeStub::Function(
            FunctionSignature::new("get_function_at", TypeAnnotation::opt(TypeAnnotation::named("Function")))
                .param(TypedParam::new("bv", TypeAnnotation::named("BinaryView")))
                .param(TypedParam::new("addr", TypeAnnotation::Int))
                .doc("Return the Function at addr, or None."),
        ));

        s.register(TypeStub::Function(
            FunctionSignature::new("compute_entropy", TypeAnnotation::Float)
                .param(TypedParam::new("data", TypeAnnotation::Bytes))
                .doc("Compute Shannon entropy of data in bits per byte."),
        ));

        s.register(TypeStub::Constant {
            name: "RUSTRE_VERSION".to_string(),
            ty: TypeAnnotation::Str,
        });

        s.register(TypeStub::TypeAlias {
            name: "Address".to_string(),
            ty: TypeAnnotation::Int,
        });

        s
    }

    /// Register a type stub.
    pub fn register(&mut self, stub: TypeStub) {
        self.stubs.push(stub);
    }

    /// Add a module-level import line.
    pub fn add_import(&mut self, import: impl Into<String>) {
        self.imports.push(import.into());
    }

    /// Find a stub by name.
    #[must_use]
    pub fn find(&self, name: &str) -> Option<&TypeStub> {
        self.stubs.iter().find(|s| s.name() == name)
    }

    /// Return all stubs.
    #[must_use]
    pub fn all(&self) -> &[TypeStub] {
        &self.stubs
    }

    /// Number of stubs.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.stubs.len()
    }

    /// Returns `true` if no stubs are registered.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.stubs.is_empty()
    }

    /// Return names of all registered stubs.
    #[must_use]
    pub fn stub_names(&self) -> Vec<&str> {
        self.stubs.iter().map(TypeStub::name).collect()
    }
}

// ── StubGenerator ─────────────────────────────────────────────────────────────

/// Renders a [`PythonTypeStubs`] registry to a `.pyi` file.
pub struct StubGenerator<'a> {
    stubs: &'a PythonTypeStubs,
    /// Module name for the generated stub (used in the header comment).
    module_name: String,
}

impl<'a> StubGenerator<'a> {
    /// Create a generator backed by `stubs`.
    #[must_use]
    pub fn new(stubs: &'a PythonTypeStubs, module_name: impl Into<String>) -> Self {
        Self { stubs, module_name: module_name.into() }
    }

    /// Render the full `.pyi` stub file.
    #[must_use]
    pub fn generate(&self) -> String {
        let mut out = format!(
            "# Auto-generated type stubs for module '{}'\n# Do not edit manually.\n\n",
            self.module_name
        );

        for import in &self.stubs.imports {
            out.push_str(import);
            out.push('\n');
        }
        if !self.stubs.imports.is_empty() {
            out.push('\n');
        }

        for stub in self.stubs.all() {
            out.push_str(&stub.render_pyi());
            out.push('\n');
        }

        out
    }

    /// Render only the function stubs.
    #[must_use]
    pub fn generate_functions_only(&self) -> String {
        let mut out = String::new();
        for stub in self.stubs.all() {
            if let TypeStub::Function(f) = stub {
                out.push_str(&f.render_pyi(0));
            }
        }
        out
    }

    /// Render only the class stubs.
    #[must_use]
    pub fn generate_classes_only(&self) -> String {
        let mut out = String::new();
        for stub in self.stubs.all() {
            if let TypeStub::Class(c) = stub {
                out.push_str(&c.render_pyi());
                out.push('\n');
            }
        }
        out
    }

    /// Return a list of all type names defined in the stubs.
    #[must_use]
    pub fn defined_types(&self) -> Vec<&str> {
        self.stubs
            .all()
            .iter()
            .filter(|s| matches!(s, TypeStub::Class(_) | TypeStub::TypeAlias { .. }))
            .map(TypeStub::name)
            .collect()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── TypeAnnotation ───────────────────────────────────────────────────────

    #[test]
    fn test_type_annotation_display_primitives() {
        assert_eq!(TypeAnnotation::Int.to_string(), "int");
        assert_eq!(TypeAnnotation::Str.to_string(), "str");
        assert_eq!(TypeAnnotation::Bool.to_string(), "bool");
        assert_eq!(TypeAnnotation::Float.to_string(), "float");
        assert_eq!(TypeAnnotation::Bytes.to_string(), "bytes");
        assert_eq!(TypeAnnotation::None_.to_string(), "None");
        assert_eq!(TypeAnnotation::Any.to_string(), "Any");
    }

    #[test]
    fn test_type_annotation_display_list() {
        let t = TypeAnnotation::list_of(TypeAnnotation::Str);
        assert_eq!(t.to_string(), "list[str]");
    }

    #[test]
    fn test_type_annotation_display_dict() {
        let t = TypeAnnotation::str_dict(TypeAnnotation::Int);
        assert_eq!(t.to_string(), "dict[str, int]");
    }

    #[test]
    fn test_type_annotation_display_optional() {
        let t = TypeAnnotation::opt(TypeAnnotation::Str);
        assert_eq!(t.to_string(), "Optional[str]");
    }

    #[test]
    fn test_type_annotation_display_union() {
        let t = TypeAnnotation::Union(vec![TypeAnnotation::Int, TypeAnnotation::Str]);
        assert_eq!(t.to_string(), "Union[int, str]");
    }

    #[test]
    fn test_type_annotation_named() {
        let t = TypeAnnotation::named("BinaryView");
        assert_eq!(t.to_string(), "BinaryView");
    }

    #[test]
    fn test_type_annotation_tuple() {
        let t = TypeAnnotation::Tuple(vec![TypeAnnotation::Int, TypeAnnotation::Str]);
        assert_eq!(t.to_string(), "tuple[int, str]");
    }

    #[test]
    fn test_type_annotation_is_nullable() {
        assert!(TypeAnnotation::None_.is_nullable());
        assert!(TypeAnnotation::opt(TypeAnnotation::Int).is_nullable());
        assert!(!TypeAnnotation::Int.is_nullable());
    }

    #[test]
    fn test_type_annotation_base_name() {
        assert_eq!(TypeAnnotation::Int.base_name(), "int");
        assert_eq!(TypeAnnotation::named("Foo").base_name(), "Foo");
        assert_eq!(TypeAnnotation::list_of(TypeAnnotation::Int).base_name(), "list");
    }

    // ── TypedParam ───────────────────────────────────────────────────────────

    #[test]
    fn test_typed_param_render_simple() {
        let p = TypedParam::new("x", TypeAnnotation::Int);
        assert_eq!(p.render(), "x: int");
    }

    #[test]
    fn test_typed_param_render_with_default() {
        let p = TypedParam::new("n", TypeAnnotation::Int).with_default("0");
        assert_eq!(p.render(), "n: int = 0");
    }

    #[test]
    fn test_typed_param_render_variadic() {
        let p = TypedParam::new("args", TypeAnnotation::Any).variadic();
        assert_eq!(p.render(), "*args: Any");
    }

    #[test]
    fn test_typed_param_render_keyword_variadic() {
        let p = TypedParam::new("kwargs", TypeAnnotation::Any).keyword_variadic();
        assert_eq!(p.render(), "**kwargs: Any");
    }

    // ── FunctionSignature ────────────────────────────────────────────────────

    #[test]
    fn test_function_signature_render_pyi_basic() {
        let sig = FunctionSignature::new("foo", TypeAnnotation::Int)
            .param(TypedParam::new("x", TypeAnnotation::Str));
        let out = sig.render_pyi(0);
        assert!(out.contains("def foo(x: str) -> int: ..."));
    }

    #[test]
    fn test_function_signature_render_pyi_async() {
        let sig = FunctionSignature::new("bar", TypeAnnotation::None_).async_def();
        let out = sig.render_pyi(0);
        assert!(out.contains("async def bar"));
    }

    #[test]
    fn test_function_signature_render_pyi_indented() {
        let sig = FunctionSignature::new("method", TypeAnnotation::None_)
            .param(TypedParam::new("self", TypeAnnotation::named("Self")));
        let out = sig.render_pyi(4);
        assert!(out.starts_with("    def method("));
    }

    #[test]
    fn test_function_signature_required_params() {
        let sig = FunctionSignature::new("f", TypeAnnotation::None_)
            .param(TypedParam::new("a", TypeAnnotation::Int))
            .param(TypedParam::new("b", TypeAnnotation::Str).with_default("\"\""));
        assert_eq!(sig.required_param_count(), 1);
    }

    // ── PropertySignature ────────────────────────────────────────────────────

    #[test]
    fn test_property_signature_render_readonly() {
        let p = PropertySignature::new("name", TypeAnnotation::Str);
        let out = p.render_pyi(4);
        assert!(out.contains("@property"));
        assert!(out.contains("def name(self) -> str: ..."));
        assert!(!out.contains("setter"));
    }

    #[test]
    fn test_property_signature_render_writable() {
        let p = PropertySignature::new("addr", TypeAnnotation::Int).writable();
        let out = p.render_pyi(0);
        assert!(out.contains("setter"));
    }

    // ── ClassSignature ───────────────────────────────────────────────────────

    #[test]
    fn test_class_signature_render_pyi_empty() {
        let c = ClassSignature::new("Empty");
        let out = c.render_pyi();
        assert!(out.contains("class Empty:"));
        assert!(out.contains("..."));
    }

    #[test]
    fn test_class_signature_render_pyi_with_base() {
        let c = ClassSignature::new("Child").base("Parent");
        let out = c.render_pyi();
        assert!(out.contains("class Child(Parent):"));
    }

    #[test]
    fn test_class_signature_render_pyi_with_attrs() {
        let c = ClassSignature::new("Foo").attr("count", TypeAnnotation::Int);
        let out = c.render_pyi();
        assert!(out.contains("count: int"));
    }

    #[test]
    fn test_class_signature_render_pyi_with_method() {
        let c = ClassSignature::new("Bar").method(
            FunctionSignature::new("greet", TypeAnnotation::Str)
                .param(TypedParam::new("self", TypeAnnotation::named("Bar"))),
        );
        let out = c.render_pyi();
        assert!(out.contains("def greet"));
    }

    // ── TypeStub ─────────────────────────────────────────────────────────────

    #[test]
    fn test_type_stub_name_function() {
        let stub = TypeStub::Function(FunctionSignature::new("my_fn", TypeAnnotation::None_));
        assert_eq!(stub.name(), "my_fn");
    }

    #[test]
    fn test_type_stub_name_class() {
        let stub = TypeStub::Class(ClassSignature::new("MyClass"));
        assert_eq!(stub.name(), "MyClass");
    }

    #[test]
    fn test_type_stub_type_alias_render() {
        let stub = TypeStub::TypeAlias { name: "Addr".to_string(), ty: TypeAnnotation::Int };
        assert_eq!(stub.render_pyi(), "Addr = int\n");
    }

    #[test]
    fn test_type_stub_constant_render() {
        let stub = TypeStub::Constant { name: "VERSION".to_string(), ty: TypeAnnotation::Str };
        assert_eq!(stub.render_pyi(), "VERSION: str\n");
    }

    // ── PythonTypeStubs ──────────────────────────────────────────────────────

    #[test]
    fn test_python_type_stubs_register_and_find() {
        let mut stubs = PythonTypeStubs::new();
        stubs.register(TypeStub::Function(FunctionSignature::new("fn_a", TypeAnnotation::Int)));
        assert!(stubs.find("fn_a").is_some());
        assert!(stubs.find("missing").is_none());
    }

    #[test]
    fn test_python_type_stubs_standard_populated() {
        let stubs = PythonTypeStubs::standard();
        assert!(!stubs.is_empty());
        assert!(stubs.find("BinaryView").is_some());
        assert!(stubs.find("load_binary").is_some());
    }

    #[test]
    fn test_python_type_stubs_len() {
        let s = PythonTypeStubs::new();
        assert!(s.is_empty());
        let s2 = PythonTypeStubs::standard();
        assert!(!s2.is_empty());
    }

    #[test]
    fn test_python_type_stubs_stub_names() {
        let stubs = PythonTypeStubs::standard();
        let names = stubs.stub_names();
        assert!(names.contains(&"BinaryView"));
    }

    // ── StubGenerator ────────────────────────────────────────────────────────

    #[test]
    fn test_stub_generator_generate_contains_imports() {
        let stubs = PythonTypeStubs::standard();
        let generator = StubGenerator::new(&stubs, "rustre");
        let out = generator.generate();
        assert!(out.contains("from typing import"));
    }

    #[test]
    fn test_stub_generator_generate_contains_class() {
        let stubs = PythonTypeStubs::standard();
        let generator = StubGenerator::new(&stubs, "rustre");
        let out = generator.generate();
        assert!(out.contains("class BinaryView:"));
    }

    #[test]
    fn test_stub_generator_functions_only() {
        let stubs = PythonTypeStubs::standard();
        let generator = StubGenerator::new(&stubs, "rustre");
        let out = generator.generate_functions_only();
        assert!(out.contains("def load_binary"));
        assert!(!out.contains("class BinaryView"));
    }

    #[test]
    fn test_stub_generator_classes_only() {
        let stubs = PythonTypeStubs::standard();
        let generator = StubGenerator::new(&stubs, "rustre");
        let out = generator.generate_classes_only();
        assert!(out.contains("class BinaryView"));
        assert!(!out.contains("def load_binary"));
    }

    #[test]
    fn test_stub_generator_defined_types() {
        let stubs = PythonTypeStubs::standard();
        let generator = StubGenerator::new(&stubs, "rustre");
        let types = generator.defined_types();
        assert!(types.contains(&"BinaryView"));
    }

    #[test]
    fn test_stub_generator_header_contains_module_name() {
        let stubs = PythonTypeStubs::standard();
        let generator = StubGenerator::new(&stubs, "rustre_analysis");
        let out = generator.generate();
        assert!(out.contains("rustre_analysis"));
    }
}
