//! `c_output_full` — Complete C compilation-unit output with headers, types,
//! globals, and multiple functions.
//!
//! Provides [`COutputFull`] as the top-level driver that collects all
//! declarations and emits a single, self-contained C source file or
//! header/source pair.

/// Re-export of [`std::collections::HashMap`] for consumers building auxiliary
/// per-output lookup tables alongside this driver.
pub use std::collections::HashMap;
use std::fmt::Write as FmtWrite;

use serde::{Deserialize, Serialize};

// ─────────────────────────────────────────────────────────────────────────────
// Type declarations
// ─────────────────────────────────────────────────────────────────────────────

/// A single C type declaration (struct / enum / typedef / union).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TypeDeclaration {
    pub kind: TypeDeclKind,
    pub name: String,
    pub body: String,
    pub comment: Option<String>,
}

/// The variety of a type declaration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TypeDeclKind {
    Struct,
    Enum,
    Union,
    Typedef,
    Forward,
}

impl TypeDeclaration {
    /// Create a struct declaration.
    #[must_use]
    pub fn struct_decl(name: impl Into<String>, body: impl Into<String>) -> Self {
        Self {
            kind: TypeDeclKind::Struct,
            name: name.into(),
            body: body.into(),
            comment: None,
        }
    }

    /// Create an enum declaration.
    #[must_use]
    pub fn enum_decl(name: impl Into<String>, body: impl Into<String>) -> Self {
        Self {
            kind: TypeDeclKind::Enum,
            name: name.into(),
            body: body.into(),
            comment: None,
        }
    }

    /// Create a typedef declaration.
    #[must_use]
    pub fn typedef_decl(alias: impl Into<String>, target: impl Into<String>) -> Self {
        Self {
            kind: TypeDeclKind::Typedef,
            name: alias.into(),
            body: target.into(),
            comment: None,
        }
    }

    /// Create a forward declaration.
    #[must_use]
    pub fn forward_decl(name: impl Into<String>, kind: &TypeDeclKind) -> Self {
        let name: String = name.into();
        let body = match &kind {
            TypeDeclKind::Struct => format!("struct {name};"),
            TypeDeclKind::Enum => format!("enum {name};"),
            TypeDeclKind::Union => format!("union {name};"),
            _ => format!("/* forward: {name} */"),
        };
        Self {
            kind: TypeDeclKind::Forward,
            name,
            body,
            comment: None,
        }
    }

    /// Attach a comment.
    #[must_use]
    pub fn with_comment(mut self, comment: impl Into<String>) -> Self {
        self.comment = Some(comment.into());
        self
    }

    /// Emit the declaration to a string.
    #[must_use]
    pub fn emit(&self) -> String {
        let mut out = String::new();
        if let Some(c) = &self.comment {
            let _ = writeln!(out, "/* {c} */");
        }
        match self.kind {
            TypeDeclKind::Struct => {
                let _ = write!(out, "struct {} {{\n{}\n}};", self.name, self.body);
            }
            TypeDeclKind::Enum => {
                let _ = write!(out, "enum {} {{\n{}\n}};", self.name, self.body);
            }
            TypeDeclKind::Union => {
                let _ = write!(out, "union {} {{\n{}\n}};", self.name, self.body);
            }
            TypeDeclKind::Typedef => {
                let _ = write!(out, "typedef {} {};", self.body, self.name);
            }
            TypeDeclKind::Forward => {
                let _ = write!(out, "{}", self.body);
            }
        }
        out
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Struct declaration (rich)
// ─────────────────────────────────────────────────────────────────────────────

/// A rich struct declaration with named, typed fields.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StructDeclaration {
    pub name: String,
    pub fields: Vec<StructField>,
    pub packed: bool,
    pub comment: Option<String>,
}

/// One field in a struct declaration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StructField {
    pub ty: String,
    pub name: String,
    pub offset_comment: Option<u64>,
    pub bit_width: Option<u8>,
}

impl StructDeclaration {
    /// Create a new struct declaration.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            fields: Vec::new(),
            packed: false,
            comment: None,
        }
    }

    /// Add a field.
    pub fn add_field(&mut self, ty: impl Into<String>, name: impl Into<String>) {
        self.fields.push(StructField {
            ty: ty.into(),
            name: name.into(),
            offset_comment: None,
            bit_width: None,
        });
    }

    /// Add a field with an offset hint.
    pub fn add_field_at(&mut self, offset: u64, ty: impl Into<String>, name: impl Into<String>) {
        self.fields.push(StructField {
            ty: ty.into(),
            name: name.into(),
            offset_comment: Some(offset),
            bit_width: None,
        });
    }

    /// Add a bitfield.
    pub fn add_bitfield(&mut self, ty: impl Into<String>, name: impl Into<String>, bits: u8) {
        self.fields.push(StructField {
            ty: ty.into(),
            name: name.into(),
            offset_comment: None,
            bit_width: Some(bits),
        });
    }

    /// Emit to a C string.
    #[must_use]
    pub fn emit(&self) -> String {
        let mut out = String::new();
        if let Some(c) = &self.comment {
            let _ = writeln!(out, "/* {c} */");
        }
        if self.packed {
            let _ = writeln!(out, "#pragma pack(push, 1)");
        }
        let _ = writeln!(out, "struct {} {{", self.name);
        for f in &self.fields {
            let bitfield = f.bit_width.map(|b| format!(" : {b}")).unwrap_or_default();
            let offset_cmt = f
                .offset_comment
                .map(|o| format!(" /* 0x{o:x} */"))
                .unwrap_or_default();
            let _ = writeln!(out, "    {} {}{}{};", f.ty, f.name, bitfield, offset_cmt);
        }
        let _ = write!(out, "}};");
        if self.packed {
            let _ = write!(out, "\n#pragma pack(pop)");
        }
        out
    }

    /// Return the field count.
    #[must_use]
    pub const fn field_count(&self) -> usize {
        self.fields.len()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Enum declaration (rich)
// ─────────────────────────────────────────────────────────────────────────────

/// A rich enum declaration with named variants.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnumDeclaration {
    pub name: String,
    pub variants: Vec<EnumVariant>,
    pub comment: Option<String>,
}

/// One variant in an enum.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnumVariant {
    pub name: String,
    pub value: Option<i64>,
    pub comment: Option<String>,
}

impl EnumDeclaration {
    /// Create a new enum declaration.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            variants: Vec::new(),
            comment: None,
        }
    }

    /// Add a variant with an explicit value.
    pub fn add_variant(&mut self, name: impl Into<String>, value: i64) {
        self.variants.push(EnumVariant {
            name: name.into(),
            value: Some(value),
            comment: None,
        });
    }

    /// Add a variant with an implicit (auto-increment) value.
    pub fn add_auto_variant(&mut self, name: impl Into<String>) {
        self.variants.push(EnumVariant {
            name: name.into(),
            value: None,
            comment: None,
        });
    }

    /// Emit to a C string.
    #[must_use]
    pub fn emit(&self) -> String {
        let mut out = String::new();
        if let Some(c) = &self.comment {
            let _ = writeln!(out, "/* {c} */");
        }
        let _ = writeln!(out, "enum {} {{", self.name);
        for v in &self.variants {
            let val_s = v.value.map(|x| format!(" = {x}")).unwrap_or_default();
            let cmt = v
                .comment
                .as_deref()
                .map(|c| format!("  /* {c} */"))
                .unwrap_or_default();
            let _ = writeln!(out, "    {}{},{}", v.name, val_s, cmt);
        }
        let _ = write!(out, "}};");
        out
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Function declaration
// ─────────────────────────────────────────────────────────────────────────────

/// A C function declaration (prototype or full body).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionDeclaration {
    pub return_type: String,
    pub name: String,
    pub params: Vec<FunctionParam>,
    pub body: Option<String>,
    pub is_static: bool,
    pub is_inline: bool,
    pub calling_convention: Option<String>,
    pub comment: Option<String>,
    pub attributes: Vec<String>,
}

/// One parameter of a function declaration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionParam {
    pub ty: String,
    pub name: String,
}

impl FunctionDeclaration {
    /// Create a new function declaration.
    #[must_use]
    pub fn new(return_type: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            return_type: return_type.into(),
            name: name.into(),
            params: Vec::new(),
            body: None,
            is_static: false,
            is_inline: false,
            calling_convention: None,
            comment: None,
            attributes: Vec::new(),
        }
    }

    /// Add a parameter.
    pub fn add_param(&mut self, ty: impl Into<String>, name: impl Into<String>) {
        self.params.push(FunctionParam {
            ty: ty.into(),
            name: name.into(),
        });
    }

    /// Set the body.
    pub fn set_body(&mut self, body: impl Into<String>) {
        self.body = Some(body.into());
    }

    /// Build the prototype string.
    #[must_use]
    pub fn prototype(&self) -> String {
        let params: Vec<String> = self
            .params
            .iter()
            .map(|p| format!("{} {}", p.ty, p.name))
            .collect();
        let cc = self
            .calling_convention
            .as_deref()
            .map(|c| format!("{c} "))
            .unwrap_or_default();
        let static_s = if self.is_static { "static " } else { "" };
        let inline_s = if self.is_inline { "inline " } else { "" };
        format!(
            "{}{}{} {}{}({})",
            static_s,
            inline_s,
            self.return_type,
            cc,
            self.name,
            params.join(", ")
        )
    }

    /// Emit the full declaration or definition.
    #[must_use]
    pub fn emit(&self) -> String {
        let mut out = String::new();
        if let Some(c) = &self.comment {
            let _ = writeln!(out, "/* {c} */");
        }
        for attr in &self.attributes {
            let _ = writeln!(out, "__attribute__(({attr}))");
        }
        match &self.body {
            None => {
                let _ = write!(out, "{};", self.prototype());
            }
            Some(body) => {
                let _ = writeln!(out, "{} {{", self.prototype());
                let _ = writeln!(out, "{body}");
                let _ = write!(out, "}}");
            }
        }
        out
    }

    /// Return the number of parameters.
    #[must_use]
    pub const fn param_count(&self) -> usize {
        self.params.len()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Global variable declaration
// ─────────────────────────────────────────────────────────────────────────────

/// A global variable declaration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlobalVarDecl {
    pub ty: String,
    pub name: String,
    pub initializer: Option<String>,
    pub is_static: bool,
    pub is_const: bool,
    pub is_extern: bool,
    pub address_comment: Option<u64>,
    pub comment: Option<String>,
}

impl GlobalVarDecl {
    /// Create a new global variable declaration.
    #[must_use]
    pub fn new(ty: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            ty: ty.into(),
            name: name.into(),
            initializer: None,
            is_static: false,
            is_const: false,
            is_extern: false,
            address_comment: None,
            comment: None,
        }
    }

    /// Set an initializer.
    #[must_use]
    pub fn with_init(mut self, init: impl Into<String>) -> Self {
        self.initializer = Some(init.into());
        self
    }

    /// Mark as extern.
    #[must_use]
    pub const fn extern_(mut self) -> Self {
        self.is_extern = true;
        self
    }

    /// Mark as const.
    #[must_use]
    pub const fn const_(mut self) -> Self {
        self.is_const = true;
        self
    }

    /// Emit to a C string.
    #[must_use]
    pub fn emit(&self) -> String {
        let mut out = String::new();
        if let Some(c) = &self.comment {
            let _ = writeln!(out, "/* {c} */");
        }
        let addr_cmt = self
            .address_comment
            .map(|a| format!(" /* @ 0x{a:x} */"))
            .unwrap_or_default();
        let extern_s = if self.is_extern { "extern " } else { "" };
        let static_s = if self.is_static { "static " } else { "" };
        let const_s = if self.is_const { "const " } else { "" };
        match &self.initializer {
            Some(init) => {
                let _ = write!(
                    out,
                    "{}{}{}{} {} = {}{};",
                    extern_s, static_s, const_s, self.ty, self.name, init, addr_cmt
                );
            }
            None => {
                let _ = write!(
                    out,
                    "{}{}{}{} {}{};",
                    extern_s, static_s, const_s, self.ty, self.name, addr_cmt
                );
            }
        }
        out
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Header generator
// ─────────────────────────────────────────────────────────────────────────────

/// Generates a C header file with include guards, includes, and declarations.
#[derive(Debug, Default)]
pub struct HeaderGenerator {
    pub guard_name: String,
    pub file_name: String,
    pub includes: Vec<String>,
    pub forward_decls: Vec<String>,
    pub type_decls: Vec<TypeDeclaration>,
    pub struct_decls: Vec<StructDeclaration>,
    pub enum_decls: Vec<EnumDeclaration>,
    pub function_protos: Vec<FunctionDeclaration>,
    pub global_decls: Vec<GlobalVarDecl>,
    pub macro_defines: Vec<(String, String)>,
}

impl HeaderGenerator {
    /// Create a new header generator.
    #[must_use]
    pub fn new(file_name: impl Into<String>) -> Self {
        let name: String = file_name.into();
        let guard = name
            .to_uppercase()
            .replace(['.', '/', '-'], "_");
        Self {
            guard_name: guard,
            file_name: name,
            ..Default::default()
        }
    }

    /// Add a system include.
    pub fn add_include(&mut self, header: impl Into<String>) {
        self.includes.push(header.into());
    }

    /// Add a `#define`.
    pub fn add_define(&mut self, name: impl Into<String>, value: impl Into<String>) {
        self.macro_defines.push((name.into(), value.into()));
    }

    /// Emit the complete header.
    #[must_use]
    pub fn emit(&self) -> String {
        let mut out = String::new();
        let _ = writeln!(out, "#ifndef {}", self.guard_name);
        let _ = writeln!(out, "#define {}", self.guard_name);
        let _ = writeln!(out);
        for inc in &self.includes {
            let _ = writeln!(out, "#include <{inc}>");
        }
        if !self.includes.is_empty() {
            let _ = writeln!(out);
        }
        for (name, val) in &self.macro_defines {
            let _ = writeln!(out, "#define {name} {val}");
        }
        if !self.macro_defines.is_empty() {
            let _ = writeln!(out);
        }
        for fwd in &self.forward_decls {
            let _ = writeln!(out, "{fwd}");
        }
        if !self.forward_decls.is_empty() {
            let _ = writeln!(out);
        }
        for td in &self.type_decls {
            let _ = writeln!(out, "{}", td.emit());
            let _ = writeln!(out);
        }
        for sd in &self.struct_decls {
            let _ = writeln!(out, "{}", sd.emit());
            let _ = writeln!(out);
        }
        for ed in &self.enum_decls {
            let _ = writeln!(out, "{}", ed.emit());
            let _ = writeln!(out);
        }
        for gv in &self.global_decls {
            let _ = writeln!(out, "{}", gv.emit());
        }
        if !self.global_decls.is_empty() {
            let _ = writeln!(out);
        }
        for fp in &self.function_protos {
            let _ = writeln!(out, "{}", fp.emit());
        }
        let _ = writeln!(out);
        let _ = writeln!(out, "#endif /* {} */", self.guard_name);
        out
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Compilation unit
// ─────────────────────────────────────────────────────────────────────────────

/// A complete C compilation unit (source file).
#[derive(Debug, Default)]
pub struct CompilationUnit {
    pub file_name: String,
    pub includes: Vec<String>,
    pub local_includes: Vec<String>,
    pub macro_defines: Vec<(String, String)>,
    pub type_decls: Vec<TypeDeclaration>,
    pub struct_decls: Vec<StructDeclaration>,
    pub enum_decls: Vec<EnumDeclaration>,
    pub global_vars: Vec<GlobalVarDecl>,
    pub functions: Vec<FunctionDeclaration>,
    pub file_comment: Option<String>,
}

impl CompilationUnit {
    /// Create a new compilation unit.
    #[must_use]
    pub fn new(file_name: impl Into<String>) -> Self {
        Self {
            file_name: file_name.into(),
            ..Default::default()
        }
    }

    /// Add a system include.
    pub fn add_include(&mut self, header: impl Into<String>) {
        self.includes.push(header.into());
    }

    /// Add a local include.
    pub fn add_local_include(&mut self, header: impl Into<String>) {
        self.local_includes.push(header.into());
    }

    /// Add a `#define`.
    pub fn define(&mut self, name: impl Into<String>, value: impl Into<String>) {
        self.macro_defines.push((name.into(), value.into()));
    }

    /// Add a global variable.
    pub fn add_global(&mut self, g: GlobalVarDecl) {
        self.global_vars.push(g);
    }

    /// Add a function.
    pub fn add_function(&mut self, f: FunctionDeclaration) {
        self.functions.push(f);
    }

    /// Add a struct.
    pub fn add_struct(&mut self, s: StructDeclaration) {
        self.struct_decls.push(s);
    }

    /// Add an enum.
    pub fn add_enum(&mut self, e: EnumDeclaration) {
        self.enum_decls.push(e);
    }

    /// Emit the complete C source file.
    #[must_use]
    pub fn emit(&self) -> String {
        let mut out = String::new();
        if let Some(c) = &self.file_comment {
            let _ = writeln!(out, "/*");
            let _ = writeln!(out, " * {c}");
            let _ = writeln!(out, " */");
            let _ = writeln!(out);
        }
        for inc in &self.includes {
            let _ = writeln!(out, "#include <{inc}>");
        }
        for inc in &self.local_includes {
            let _ = writeln!(out, "#include \"{inc}\"");
        }
        if !self.includes.is_empty() || !self.local_includes.is_empty() {
            let _ = writeln!(out);
        }
        for (name, val) in &self.macro_defines {
            let _ = writeln!(out, "#define {name} {val}");
        }
        if !self.macro_defines.is_empty() {
            let _ = writeln!(out);
        }
        for sd in &self.struct_decls {
            let _ = writeln!(out, "{}", sd.emit());
            let _ = writeln!(out);
        }
        for ed in &self.enum_decls {
            let _ = writeln!(out, "{}", ed.emit());
            let _ = writeln!(out);
        }
        for td in &self.type_decls {
            let _ = writeln!(out, "{}", td.emit());
        }
        if !self.type_decls.is_empty() {
            let _ = writeln!(out);
        }
        for g in &self.global_vars {
            let _ = writeln!(out, "{}", g.emit());
        }
        if !self.global_vars.is_empty() {
            let _ = writeln!(out);
        }
        for f in &self.functions {
            let _ = writeln!(out, "{}", f.emit());
            let _ = writeln!(out);
        }
        out
    }

    /// Return the total number of functions.
    #[must_use]
    pub const fn function_count(&self) -> usize {
        self.functions.len()
    }

    /// Return total line count of emitted code.
    #[must_use]
    pub fn line_count(&self) -> usize {
        self.emit().lines().count()
    }

    /// Find a function by name.
    #[must_use]
    pub fn find_function(&self, name: &str) -> Option<&FunctionDeclaration> {
        self.functions.iter().find(|f| f.name == name)
    }

    /// Find a struct by name.
    #[must_use]
    pub fn find_struct(&self, name: &str) -> Option<&StructDeclaration> {
        self.struct_decls.iter().find(|s| s.name == name)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// COutputFull — top-level driver
// ─────────────────────────────────────────────────────────────────────────────

/// Top-level C code output manager that produces a header + source pair.
#[derive(Debug, Default)]
pub struct COutputFull {
    pub header: HeaderGenerator,
    pub source: CompilationUnit,
    pub source_name: String,
    pub header_name: String,
    pub stats: OutputStats,
}

/// Statistics collected during output generation.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct OutputStats {
    pub function_count: usize,
    pub struct_count: usize,
    pub enum_count: usize,
    pub global_count: usize,
    pub type_decl_count: usize,
    pub total_source_lines: usize,
    pub total_header_lines: usize,
}

impl COutputFull {
    /// Create a new output full with the given base name (e.g. "output").
    #[must_use]
    pub fn new(base_name: impl Into<String>) -> Self {
        let base: String = base_name.into();
        let header_name = format!("{base}.h");
        let source_name = format!("{base}.c");
        let mut header = HeaderGenerator::new(header_name.clone());
        header.add_include("stdint.h");
        header.add_include("stdbool.h");
        let mut source = CompilationUnit::new(source_name.clone());
        source.add_local_include(header_name.clone());
        Self {
            header,
            source,
            source_name,
            header_name,
            stats: OutputStats::default(),
        }
    }

    /// Add a function — prototype goes to header, definition to source.
    pub fn add_function(&mut self, f: FunctionDeclaration) {
        let mut proto = f.clone();
        proto.body = None;
        self.header.function_protos.push(proto);
        self.source.add_function(f);
        self.stats.function_count += 1;
    }

    /// Add a struct declaration to header.
    pub fn add_struct(&mut self, s: StructDeclaration) {
        self.stats.struct_count += 1;
        self.source.add_struct(s.clone());
        self.header.struct_decls.push(s);
    }

    /// Add an enum declaration to header.
    pub fn add_enum(&mut self, e: EnumDeclaration) {
        self.stats.enum_count += 1;
        self.source.add_enum(e.clone());
        self.header.enum_decls.push(e);
    }

    /// Add a global variable.
    pub fn add_global(&mut self, g: GlobalVarDecl) {
        self.stats.global_count += 1;
        let extern_proto = GlobalVarDecl {
            is_extern: true,
            initializer: None,
            ..g.clone()
        };
        self.header.global_decls.push(extern_proto);
        self.source.add_global(g);
    }

    /// Finalize and compute stats.
    pub fn finalize(&mut self) {
        let src = self.source.emit();
        let hdr = self.header.emit();
        self.stats.total_source_lines = src.lines().count();
        self.stats.total_header_lines = hdr.lines().count();
    }

    /// Emit the header source.
    #[must_use]
    pub fn emit_header(&self) -> String {
        self.header.emit()
    }

    /// Emit the source file.
    #[must_use]
    pub fn emit_source(&self) -> String {
        self.source.emit()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// MacroDefinition
// ─────────────────────────────────────────────────────────────────────────────

/// A parameterized macro definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MacroDefinition {
    pub name: String,
    pub params: Vec<String>,
    pub body: String,
    /// True for function-like macros (always emit parens, even when empty).
    pub function_like: bool,
}

impl MacroDefinition {
    /// Object-like macro.
    #[must_use]
    pub fn object(name: impl Into<String>, body: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            params: Vec::new(),
            body: body.into(),
            function_like: false,
        }
    }

    /// Function-like macro.
    #[must_use]
    pub fn function_like(
        name: impl Into<String>,
        params: Vec<String>,
        body: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            params,
            body: body.into(),
            function_like: true,
        }
    }

    /// Emit the `#define` line.
    #[must_use]
    pub fn emit(&self) -> String {
        if self.function_like {
            format!(
                "#define {}({}) {}",
                self.name,
                self.params.join(", "),
                self.body
            )
        } else {
            format!("#define {} {}", self.name, self.body)
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── TypeDeclaration ───────────────────────────────────────────────────────

    #[test]
    fn test_type_decl_typedef() {
        let td = TypeDeclaration::typedef_decl("DWORD", "unsigned long");
        let s = td.emit();
        assert!(s.contains("typedef"), "expected 'typedef' in '{s}'");
        assert!(s.contains("DWORD"));
        assert!(s.contains("unsigned long"));
    }

    #[test]
    fn test_type_decl_struct_kind() {
        let td = TypeDeclaration::struct_decl("Foo", "    int x;");
        assert_eq!(td.kind, TypeDeclKind::Struct);
        let s = td.emit();
        assert!(s.contains("struct Foo"));
    }

    #[test]
    fn test_type_decl_enum() {
        let td = TypeDeclaration::enum_decl("Color", "    RED,\n    GREEN,\n    BLUE");
        let s = td.emit();
        assert!(s.contains("enum Color"));
        assert!(s.contains("RED"));
    }

    #[test]
    fn test_type_decl_forward_struct() {
        let td = TypeDeclaration::forward_decl("Node", &TypeDeclKind::Struct);
        let s = td.emit();
        assert!(s.contains("struct Node"));
    }

    #[test]
    fn test_type_decl_with_comment() {
        let td =
            TypeDeclaration::typedef_decl("HANDLE", "void *").with_comment("Windows handle type");
        let s = td.emit();
        assert!(s.contains("Windows handle type"));
    }

    // ── StructDeclaration ──────────────────────────────────────────────────────

    #[test]
    fn test_struct_decl_fields() {
        let mut sd = StructDeclaration::new("Point");
        sd.add_field("int", "x");
        sd.add_field("int", "y");
        assert_eq!(sd.field_count(), 2);
        let s = sd.emit();
        assert!(s.contains("struct Point"));
        assert!(s.contains("int x"));
        assert!(s.contains("int y"));
    }

    #[test]
    fn test_struct_decl_with_offset() {
        let mut sd = StructDeclaration::new("Header");
        sd.add_field_at(0, "uint32_t", "magic");
        sd.add_field_at(4, "uint32_t", "size");
        let s = sd.emit();
        assert!(s.contains("0x0"));
        assert!(s.contains("0x4"));
    }

    #[test]
    fn test_struct_decl_packed() {
        let mut sd = StructDeclaration::new("PackedHeader");
        sd.packed = true;
        sd.add_field("uint8_t", "a");
        let s = sd.emit();
        assert!(s.contains("#pragma pack"));
    }

    #[test]
    fn test_struct_decl_bitfield() {
        let mut sd = StructDeclaration::new("Flags");
        sd.add_bitfield("uint32_t", "active", 1);
        sd.add_bitfield("uint32_t", "visible", 1);
        let s = sd.emit();
        assert!(s.contains(": 1"));
    }

    // ── EnumDeclaration ────────────────────────────────────────────────────────

    #[test]
    fn test_enum_decl_variants() {
        let mut ed = EnumDeclaration::new("Status");
        ed.add_variant("OK", 0);
        ed.add_variant("ERROR", -1);
        let s = ed.emit();
        assert!(s.contains("enum Status"));
        assert!(s.contains("OK = 0"));
        assert!(s.contains("ERROR = -1"));
    }

    #[test]
    fn test_enum_decl_auto_variants() {
        let mut ed = EnumDeclaration::new("Color");
        ed.add_auto_variant("RED");
        ed.add_auto_variant("GREEN");
        let s = ed.emit();
        assert!(s.contains("RED"));
        assert!(s.contains("GREEN"));
    }

    // ── FunctionDeclaration ────────────────────────────────────────────────────

    #[test]
    fn test_func_decl_prototype() {
        let mut f = FunctionDeclaration::new("int", "add");
        f.add_param("int", "a");
        f.add_param("int", "b");
        let proto = f.prototype();
        assert!(proto.contains("int add"));
        assert!(proto.contains("int a"));
        assert!(proto.contains("int b"));
    }

    #[test]
    fn test_func_decl_emit_no_body() {
        let f = FunctionDeclaration::new("void", "init");
        let s = f.emit();
        assert!(s.ends_with(';'));
    }

    #[test]
    fn test_func_decl_emit_with_body() {
        let mut f = FunctionDeclaration::new("int", "double_it");
        f.add_param("int", "x");
        f.set_body("    return x * 2;");
        let s = f.emit();
        assert!(s.contains('{'));
        assert!(s.contains('}'));
        assert!(s.contains("return x * 2;"));
    }

    #[test]
    fn test_func_decl_static() {
        let mut f = FunctionDeclaration::new("void", "helper");
        f.is_static = true;
        let proto = f.prototype();
        assert!(proto.starts_with("static "));
    }

    #[test]
    fn test_func_decl_inline() {
        let mut f = FunctionDeclaration::new("int", "clamp");
        f.is_inline = true;
        let proto = f.prototype();
        assert!(proto.contains("inline"));
    }

    #[test]
    fn test_func_decl_param_count() {
        let mut f = FunctionDeclaration::new("void", "foo");
        f.add_param("int", "a");
        f.add_param("int", "b");
        f.add_param("int", "c");
        assert_eq!(f.param_count(), 3);
    }

    #[test]
    fn test_func_decl_calling_convention() {
        let mut f = FunctionDeclaration::new("void", "fn");
        f.calling_convention = Some("__stdcall".to_string());
        let p = f.prototype();
        assert!(p.contains("__stdcall"));
    }

    // ── GlobalVarDecl ──────────────────────────────────────────────────────────

    #[test]
    fn test_global_var_simple() {
        let g = GlobalVarDecl::new("int", "counter");
        let s = g.emit();
        assert!(s.contains("int counter;"));
    }

    #[test]
    fn test_global_var_with_init() {
        let g = GlobalVarDecl::new("int", "max_size").with_init("1024");
        let s = g.emit();
        assert!(s.contains("= 1024"));
    }

    #[test]
    fn test_global_var_extern() {
        let g = GlobalVarDecl::new("int", "g_count").extern_();
        let s = g.emit();
        assert!(s.starts_with("extern"));
    }

    #[test]
    fn test_global_var_const() {
        let g = GlobalVarDecl::new("char*", "NAME")
            .const_()
            .with_init("\"rustre\"");
        let s = g.emit();
        assert!(s.contains("const"));
    }

    #[test]
    fn test_global_var_address_comment() {
        let mut g = GlobalVarDecl::new("uint64_t", "base_addr");
        g.address_comment = Some(0x0001_4000_1000);
        let s = g.emit();
        assert!(s.contains("0x140001000"));
    }

    // ── HeaderGenerator ────────────────────────────────────────────────────────

    #[test]
    fn test_header_generator_guard() {
        let hg = HeaderGenerator::new("my_header.h");
        let s = hg.emit();
        assert!(s.contains("#ifndef MY_HEADER_H"));
        assert!(s.contains("#define MY_HEADER_H"));
        assert!(s.contains("#endif"));
    }

    #[test]
    fn test_header_generator_includes() {
        let mut hg = HeaderGenerator::new("api.h");
        hg.add_include("stdint.h");
        let s = hg.emit();
        assert!(s.contains("#include <stdint.h>"));
    }

    #[test]
    fn test_header_generator_define() {
        let mut hg = HeaderGenerator::new("defs.h");
        hg.add_define("MAX_SIZE", "1024");
        let s = hg.emit();
        assert!(s.contains("#define MAX_SIZE 1024"));
    }

    // ── CompilationUnit ────────────────────────────────────────────────────────

    #[test]
    fn test_compilation_unit_emit() {
        let mut cu = CompilationUnit::new("test.c");
        cu.add_include("stdio.h");
        let mut f = FunctionDeclaration::new("int", "main");
        f.set_body("    return 0;");
        cu.add_function(f);
        let s = cu.emit();
        assert!(s.contains("#include <stdio.h>"));
        assert!(s.contains("int main()"));
    }

    #[test]
    fn test_compilation_unit_find_function() {
        let mut cu = CompilationUnit::new("test.c");
        let f = FunctionDeclaration::new("void", "init");
        cu.add_function(f);
        assert!(cu.find_function("init").is_some());
        assert!(cu.find_function("missing").is_none());
    }

    #[test]
    fn test_compilation_unit_find_struct() {
        let mut cu = CompilationUnit::new("test.c");
        let s = StructDeclaration::new("MyStruct");
        cu.add_struct(s);
        assert!(cu.find_struct("MyStruct").is_some());
    }

    #[test]
    fn test_compilation_unit_function_count() {
        let mut cu = CompilationUnit::new("test.c");
        cu.add_function(FunctionDeclaration::new("void", "a"));
        cu.add_function(FunctionDeclaration::new("void", "b"));
        assert_eq!(cu.function_count(), 2);
    }

    // ── COutputFull ────────────────────────────────────────────────────────────

    #[test]
    fn test_c_output_full_basic() {
        let mut out = COutputFull::new("module");
        assert_eq!(out.source_name, "module.c");
        assert_eq!(out.header_name, "module.h");
        let f = FunctionDeclaration::new("int", "compute");
        out.add_function(f);
        assert_eq!(out.stats.function_count, 1);
    }

    #[test]
    fn test_c_output_full_emit_header() {
        let out = COutputFull::new("module");
        let hdr = out.emit_header();
        assert!(hdr.contains("#ifndef"));
    }

    #[test]
    fn test_c_output_full_emit_source() {
        let out = COutputFull::new("module");
        let src = out.emit_source();
        assert!(src.contains("#include \"module.h\""));
    }

    #[test]
    fn test_c_output_full_add_struct() {
        let mut out = COutputFull::new("types");
        let mut s = StructDeclaration::new("Vec3");
        s.add_field("float", "x");
        s.add_field("float", "y");
        s.add_field("float", "z");
        out.add_struct(s);
        assert_eq!(out.stats.struct_count, 1);
        let hdr = out.emit_header();
        assert!(hdr.contains("struct Vec3"));
    }

    #[test]
    fn test_c_output_full_add_enum() {
        let mut out = COutputFull::new("enums");
        let mut e = EnumDeclaration::new("Direction");
        e.add_variant("NORTH", 0);
        e.add_variant("SOUTH", 1);
        out.add_enum(e);
        assert_eq!(out.stats.enum_count, 1);
    }

    #[test]
    fn test_c_output_full_add_global() {
        let mut out = COutputFull::new("globals");
        let g = GlobalVarDecl::new("int", "g_count").with_init("0");
        out.add_global(g);
        assert_eq!(out.stats.global_count, 1);
        let hdr = out.emit_header();
        assert!(hdr.contains("extern int g_count"));
    }

    #[test]
    fn test_c_output_full_finalize() {
        let mut out = COutputFull::new("final");
        let mut f = FunctionDeclaration::new("void", "run");
        f.set_body("    /* nothing */");
        out.add_function(f);
        out.finalize();
        assert!(out.stats.total_source_lines > 0);
        assert!(out.stats.total_header_lines > 0);
    }

    // ── MacroDefinition ────────────────────────────────────────────────────────

    #[test]
    fn test_macro_object() {
        let m = MacroDefinition::object("PI", "3.14159265f");
        assert_eq!(m.emit(), "#define PI 3.14159265f");
    }

    #[test]
    fn test_macro_function_like() {
        let m = MacroDefinition::function_like(
            "MAX",
            vec!["a".to_string(), "b".to_string()],
            "((a) > (b) ? (a) : (b))",
        );
        let s = m.emit();
        assert!(s.contains("MAX(a, b)"));
        assert!(s.contains("(a) > (b)"));
    }

    #[test]
    fn test_macro_no_params() {
        let m = MacroDefinition::function_like("EMPTY", vec![], "do {} while(0)");
        let s = m.emit();
        assert!(s.contains("EMPTY()"));
    }

    // ── Integration ────────────────────────────────────────────────────────────

    #[test]
    fn test_full_pipeline() {
        let mut out = COutputFull::new("full");

        let mut point = StructDeclaration::new("Point");
        point.add_field("float", "x");
        point.add_field("float", "y");
        out.add_struct(point);

        let mut dist = FunctionDeclaration::new("float", "distance");
        dist.add_param("const struct Point *", "a");
        dist.add_param("const struct Point *", "b");
        dist.set_body(
            "    float dx = a->x - b->x;\n    float dy = a->y - b->y;\n    return dx*dx + dy*dy;",
        );
        out.add_function(dist);

        let g = GlobalVarDecl::new("int", "call_count").with_init("0");
        out.add_global(g);

        out.finalize();

        let src = out.emit_source();
        let hdr = out.emit_header();

        assert!(src.contains("distance"));
        assert!(src.contains("a->x"));
        assert!(hdr.contains("struct Point"));
        assert!(hdr.contains("extern int call_count"));
        assert_eq!(out.stats.function_count, 1);
        assert_eq!(out.stats.struct_count, 1);
        assert_eq!(out.stats.global_count, 1);
    }

    #[test]
    fn test_struct_comment_in_output() {
        let mut sd = StructDeclaration::new("Metadata");
        sd.comment = Some("Binary metadata header".to_string());
        sd.add_field("uint32_t", "version");
        let s = sd.emit();
        assert!(s.contains("Binary metadata header"));
    }

    #[test]
    fn test_enum_comment_in_output() {
        let mut ed = EnumDeclaration::new("Protocol");
        ed.comment = Some("Supported network protocols".to_string());
        ed.add_variant("TCP", 6);
        let s = ed.emit();
        assert!(s.contains("Supported network protocols"));
    }
}
