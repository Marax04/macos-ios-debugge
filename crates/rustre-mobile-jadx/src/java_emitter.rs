//! `java_emitter` — AST → Java source code emitter.
//!
//! Converts a `CompilationUnit` (or individual `AstClass` / `AstMethod`) to
//! human-readable Java source text.  The output aims to match JADX's default
//! formatting closely.

use std::fmt::Write as FmtWrite;

use super::java_ast::{
    AstClass, AstField, AstMethod, CatchClause, ClassKind, CompilationUnit, Expr, JavaType,
    LambdaBody, Statement, SwitchCase,
};

// ─────────────────────────────────────────────────────────────────────────────
// EmitOptions
// ─────────────────────────────────────────────────────────────────────────────

/// Options controlling the Java source output.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EmitOptions {
    /// Indentation string (default: 4 spaces).
    pub indent: String,
    /// Emit import statements.
    pub emit_imports: bool,
    /// Emit package declaration.
    pub emit_package: bool,
    /// Emit blank line between class members.
    pub blank_between_members: bool,
    /// Maximum line length before wrapping (0 = no limit).
    pub max_line_len: usize,
}

impl Default for EmitOptions {
    fn default() -> Self {
        Self {
            indent: "    ".to_owned(),
            emit_imports: true,
            emit_package: true,
            blank_between_members: true,
            max_line_len: 120,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Public API
// ─────────────────────────────────────────────────────────────────────────────

/// Emit a full `CompilationUnit` to Java source.
#[must_use]
pub fn emit_compilation_unit(cu: &CompilationUnit) -> String {
    emit_compilation_unit_opts(cu, &EmitOptions::default())
}

/// Emit a `CompilationUnit` with custom options.
#[must_use]
pub fn emit_compilation_unit_opts(cu: &CompilationUnit, opts: &EmitOptions) -> String {
    let mut out = String::new();
    let emitter = Emitter::new(opts);

    if opts.emit_package && !cu.package.is_empty() {
        let _ = writeln!(out, "package {};", cu.package);
        out.push('\n');
    }

    if opts.emit_imports {
        let mut imports = cu.imports.clone();
        imports.sort();
        imports.dedup();
        for imp in &imports {
            let _ = writeln!(out, "import {imp};");
        }
        if !imports.is_empty() {
            out.push('\n');
        }
    }

    for (i, cls) in cu.classes.iter().enumerate() {
        if i > 0 {
            out.push('\n');
        }
        out.push_str(&emitter.emit_class(cls, 0));
    }

    out
}

/// Emit a single `AstClass` to Java source.
#[must_use]
pub fn emit_class(cls: &AstClass) -> String {
    let opts = EmitOptions::default();
    let emitter = Emitter::new(&opts);
    emitter.emit_class(cls, 0)
}

/// Emit a single `AstMethod` to Java source.
#[must_use]
pub fn emit_method(method: &AstMethod) -> String {
    let opts = EmitOptions::default();
    let emitter = Emitter::new(&opts);
    emitter.emit_method(method, 1)
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal emitter
// ─────────────────────────────────────────────────────────────────────────────

struct Emitter<'a> {
    opts: &'a EmitOptions,
}

impl<'a> Emitter<'a> {
    const fn new(opts: &'a EmitOptions) -> Self {
        Emitter { opts }
    }

    fn indent(&self, depth: usize) -> String {
        self.opts.indent.repeat(depth)
    }

    // ─── class ───────────────────────────────────────────────────────────────

    fn emit_class(&self, cls: &AstClass, depth: usize) -> String {
        let mut out = String::new();
        let ind = self.indent(depth);

        // Annotations
        for ann in &cls.annotations {
            let _ = writeln!(out, "{ind}@{ann}");
        }

        // Class header
        let mods = cls.modifiers.to_string();
        let kind = cls.kind.to_string();
        let extends = cls
            .super_class
            .as_deref()
            .map(|s| format!(" extends {s}"))
            .unwrap_or_default();
        let implements = if cls.interfaces.is_empty() {
            String::new()
        } else {
            let kw = if cls.kind == ClassKind::Interface {
                " extends "
            } else {
                " implements "
            };
            format!("{}{}", kw, cls.interfaces.join(", "))
        };

        if mods.is_empty() {
            let _ = writeln!(
                out,
                "{}{} {}{}{} {{",
                ind,
                kind,
                cls.simple_name(),
                extends,
                implements
            );
        } else {
            let _ = writeln!(
                out,
                "{}{} {} {}{}{} {{",
                ind,
                mods,
                kind,
                cls.simple_name(),
                extends,
                implements
            );
        }

        // Fields
        if !cls.fields.is_empty() {
            for field in &cls.fields {
                out.push_str(&self.emit_field(field, depth + 1));
                out.push('\n');
            }
            if self.opts.blank_between_members {
                out.push('\n');
            }
        }

        // Methods
        for (i, method) in cls.methods.iter().enumerate() {
            if i > 0 && self.opts.blank_between_members {
                out.push('\n');
            }
            out.push_str(&self.emit_method(method, depth + 1));
            out.push('\n');
        }

        // Inner classes
        for inner in &cls.inner_classes {
            out.push('\n');
            out.push_str(&self.emit_class(inner, depth + 1));
        }

        let _ = writeln!(out, "{ind}}}");
        out
    }

    // ─── field ───────────────────────────────────────────────────────────────

    fn emit_field(&self, field: &AstField, depth: usize) -> String {
        let ind = self.indent(depth);
        let mods = field.modifiers.to_string();
        let ty = emit_type(&field.ty);
        let name = &field.name;

        for ann in &field.annotations {
            let _ = writeln!(
                // We can't push_str here so we build separately.
                &mut String::new(),
                "{ind}@{ann}"
            );
        }

        field.init.as_ref().map_or_else(
            || {
                if mods.is_empty() {
                    format!("{ind}{ty} {name};")
                } else {
                    format!("{ind}{mods} {ty} {name};")
                }
            },
            |init| {
                let init_str = self.emit_expr(init, 0);
                if mods.is_empty() {
                    format!("{ind}{ty} {name} = {init_str};")
                } else {
                    format!("{ind}{mods} {ty} {name} = {init_str};")
                }
            },
        )
    }

    // ─── method ──────────────────────────────────────────────────────────────

    fn emit_method(&self, method: &AstMethod, depth: usize) -> String {
        let mut out = String::new();
        let ind = self.indent(depth);

        // Annotations
        for ann in &method.annotations {
            let _ = writeln!(out, "{ind}@{ann}");
        }

        let mods = method.modifiers.to_string();
        let ret = emit_type(&method.return_type);
        let name = &method.name;

        // Parameters
        let params_str: String = method
            .params
            .iter()
            .map(|(n, ty)| format!("{} {}", emit_type(ty), n))
            .collect::<Vec<_>>()
            .join(", ");

        // Throws clause
        let throws_str = if method.throws.is_empty() {
            String::new()
        } else {
            format!(" throws {}", method.throws.join(", "))
        };

        match &method.body {
            None => {
                // abstract or native
                if mods.is_empty() {
                    let _ = writeln!(out, "{ind}{ret} {name}({params_str}){throws_str};");
                } else {
                    let _ = writeln!(out, "{ind}{mods} {ret} {name}({params_str}){throws_str};");
                }
            }
            Some(body) => {
                if mods.is_empty() {
                    let _ = writeln!(out, "{ind}{ret} {name}({params_str}){throws_str} {{");
                } else {
                    let _ = writeln!(out, "{ind}{mods} {ret} {name}({params_str}){throws_str} {{");
                }
                for stmt in body {
                    out.push_str(&self.emit_stmt(stmt, depth + 1));
                }
                let _ = writeln!(out, "{ind}}}");
            }
        }

        out
    }

    // ─── statement ───────────────────────────────────────────────────────────

    fn emit_stmt(&self, stmt: &Statement, depth: usize) -> String {
        let ind = self.indent(depth);
        match stmt {
            Statement::Empty => String::new(),

            Statement::LocalDecl {
                ty,
                name,
                init: None,
            } => {
                format!("{}{} {};\n", ind, emit_type(ty), name)
            }
            Statement::LocalDecl {
                ty,
                name,
                init: Some(e),
            } => {
                format!(
                    "{}{} {} = {};\n",
                    ind,
                    emit_type(ty),
                    name,
                    self.emit_expr(e, 0)
                )
            }

            Statement::Assign { target, value } => {
                format!(
                    "{}{} = {};\n",
                    ind,
                    self.emit_expr(target, 0),
                    self.emit_expr(value, 0)
                )
            }

            Statement::Expr(e) => {
                format!("{}{};\n", ind, self.emit_expr(e, 0))
            }

            Statement::Return(None) => format!("{ind}return;\n"),

            Statement::Return(Some(e)) => {
                format!("{}return {};\n", ind, self.emit_expr(e, 0))
            }

            Statement::Throw(e) => {
                format!("{}throw {};\n", ind, self.emit_expr(e, 0))
            }

            Statement::Break(None) => format!("{ind}break;\n"),
            Statement::Break(Some(lbl)) => format!("{ind}break {lbl};\n"),
            Statement::Continue(None) => format!("{ind}continue;\n"),
            Statement::Continue(Some(lbl)) => format!("{ind}continue {lbl};\n"),

            Statement::Block(stmts) => {
                let mut s = format!("{ind}{{\n");
                for stmt in stmts {
                    s.push_str(&self.emit_stmt(stmt, depth + 1));
                }
                let _ = writeln!(s, "{ind}}}");
                s
            }

            Statement::If {
                cond,
                then,
                else_: None,
            } => {
                let mut s = format!("{}if ({}) {{\n", ind, self.emit_expr(cond, 0));
                s.push_str(&self.emit_stmt(then, depth + 1));
                let _ = writeln!(s, "{ind}}}");
                s
            }
            Statement::If {
                cond,
                then,
                else_: Some(else_stmt),
            } => {
                let mut s = format!("{}if ({}) {{\n", ind, self.emit_expr(cond, 0));
                s.push_str(&self.emit_stmt(then, depth + 1));
                let _ = writeln!(s, "{ind}}} else {{");
                s.push_str(&self.emit_stmt(else_stmt, depth + 1));
                let _ = writeln!(s, "{ind}}}");
                s
            }

            Statement::While { cond, body } => {
                let mut s = format!("{}while ({}) {{\n", ind, self.emit_expr(cond, 0));
                s.push_str(&self.emit_stmt(body, depth + 1));
                let _ = writeln!(s, "{ind}}}");
                s
            }

            Statement::DoWhile { body, cond } => {
                let mut s = format!("{ind}do {{\n");
                s.push_str(&self.emit_stmt(body, depth + 1));
                let _ = writeln!(s, "{}}} while ({});", ind, self.emit_expr(cond, 0));
                s
            }

            Statement::For {
                init,
                cond,
                update,
                body,
            } => {
                let init_str = init
                    .as_ref()
                    .map(|s| {
                        self.emit_stmt(s, 0)
                            .trim_end_matches('\n')
                            .trim_end_matches(';')
                            .to_owned()
                    })
                    .unwrap_or_default();
                let cond_str = cond
                    .as_ref()
                    .map(|e| self.emit_expr(e, 0))
                    .unwrap_or_default();
                let update_str = update
                    .as_ref()
                    .map(|e| self.emit_expr(e, 0))
                    .unwrap_or_default();
                let mut s = format!("{ind}for ({init_str}; {cond_str}; {update_str}) {{\n");
                s.push_str(&self.emit_stmt(body, depth + 1));
                let _ = writeln!(s, "{ind}}}");
                s
            }

            Statement::ForEach {
                elem_type,
                var,
                iter,
                body,
            } => {
                let mut s = format!(
                    "{}for ({} {} : {}) {{\n",
                    ind,
                    emit_type(elem_type),
                    var,
                    self.emit_expr(iter, 0)
                );
                s.push_str(&self.emit_stmt(body, depth + 1));
                let _ = writeln!(s, "{ind}}}");
                s
            }

            Statement::Switch { expr, cases } => self.emit_switch(&ind, expr, cases, depth),

            Statement::TryCatch {
                body,
                catches,
                finally,
            } => self.emit_try_catch(&ind, body, catches, finally.as_deref(), depth),

            Statement::Synchronized { lock, body } => {
                let mut s = format!("{}synchronized ({}) {{\n", ind, self.emit_expr(lock, 0));
                s.push_str(&self.emit_stmt(body, depth + 1));
                let _ = writeln!(s, "{ind}}}");
                s
            }

            Statement::Labeled(lbl, stmt) => {
                let mut s = format!("{ind}{lbl}:\n");
                s.push_str(&self.emit_stmt(stmt, depth));
                s
            }

            Statement::Unknown(s) => format!("{ind}{s}\n"),
        }
    }

    fn emit_switch(&self, ind: &str, expr: &Expr, cases: &[SwitchCase], depth: usize) -> String {
        let mut s = format!("{}switch ({}) {{\n", ind, self.emit_expr(expr, 0));
        for case in cases {
            if let Some(lbl) = &case.label {
                let _ = writeln!(s, "{}case {}:", ind, self.emit_expr(lbl, 0));
            } else {
                let _ = writeln!(s, "{ind}default:");
            }
            for stmt in &case.body {
                s.push_str(&self.emit_stmt(stmt, depth + 2));
            }
        }
        let _ = writeln!(s, "{ind}}}");
        s
    }

    fn emit_try_catch(
        &self,
        ind: &str,
        body: &Statement,
        catches: &[CatchClause],
        finally: Option<&Statement>,
        depth: usize,
    ) -> String {
        let mut s = format!("{ind}try {{\n");
        s.push_str(&self.emit_stmt(body, depth + 1));
        for catch in catches {
            let types = catch.exception_types.join(" | ");
            let _ = writeln!(s, "{}}} catch ({} {}) {{", ind, types, catch.var);
            for stmt in &catch.body {
                s.push_str(&self.emit_stmt(stmt, depth + 1));
            }
        }
        if let Some(fin) = finally {
            let _ = writeln!(s, "{ind}}} finally {{");
            s.push_str(&self.emit_stmt(fin, depth + 1));
        }
        let _ = writeln!(s, "{ind}}}");
        s
    }

    // ─── expression ──────────────────────────────────────────────────────────

    fn emit_expr(&self, expr: &Expr, _depth: usize) -> String {
        match expr {
            Expr::IntLit(n) => format!("{n}"),
            Expr::LongLit(n) => format!("{n}L"),
            Expr::FloatLit(f) => format!("{f}f"),
            Expr::DoubleLit(d) => format!("{d}"),
            Expr::BoolLit(b) => b.to_string(),
            Expr::StringLit(s) => format!("\"{}\"", escape_java_string(s)),
            Expr::NullLit => "null".to_owned(),
            Expr::Var(v) => v.clone(),
            Expr::This => "this".to_owned(),
            Expr::Super => "super".to_owned(),

            Expr::FieldGet { object, field, .. } => {
                format!("{}.{}", self.emit_expr(object, 0), field)
            }
            Expr::StaticFieldGet { class, field, .. } => {
                format!("{}.{}", simple_class_name(class), field)
            }

            Expr::InvokeVirtual {
                object,
                method,
                args,
                ..
            }
            | Expr::InvokeInterface {
                object,
                method,
                args,
                ..
            } => {
                let obj = self.emit_expr(object, 0);
                let args_str = self.emit_args(args);
                format!("{obj}.{method}({args_str})")
            }

            Expr::InvokeStatic {
                class,
                method,
                args,
                ..
            } => {
                let cls = simple_class_name(class);
                let args_str = self.emit_args(args);
                format!("{cls}.{method}({args_str})")
            }

            Expr::InvokeDirect {
                object,
                method,
                args,
                ..
            } => {
                let obj = self.emit_expr(object, 0);
                let args_str = self.emit_args(args);
                if method == "<init>" {
                    format!("new {obj}({args_str})")
                } else {
                    format!("{obj}.{method}({args_str})")
                }
            }

            Expr::InvokeSuper { method, args, .. } => {
                let args_str = self.emit_args(args);
                format!("super.{method}({args_str})")
            }

            Expr::ArrayGet { array, index, .. } => {
                format!("{}[{}]", self.emit_expr(array, 0), self.emit_expr(index, 0))
            }

            Expr::ArrayLen(arr) => {
                format!("{}.length", self.emit_expr(arr, 0))
            }

            Expr::NewArray { elem_type, size } => {
                format!("new {}[{}]", emit_type(elem_type), self.emit_expr(size, 0))
            }

            Expr::NewObject { class, args } => {
                let cls = simple_class_name(class);
                let args_str = self.emit_args(args);
                format!("new {cls}({args_str})")
            }

            Expr::Cast { expr, target } => {
                format!("({}){}", emit_type(target), self.emit_expr(expr, 0))
            }

            Expr::InstanceOf { expr, class } => {
                format!(
                    "{} instanceof {}",
                    self.emit_expr(expr, 0),
                    simple_class_name(class)
                )
            }

            Expr::BinOp { op, lhs, rhs } => {
                format!(
                    "({} {} {})",
                    self.emit_expr(lhs, 0),
                    op,
                    self.emit_expr(rhs, 0)
                )
            }

            Expr::UnaryOp { op, expr } => {
                format!("{}({})", op, self.emit_expr(expr, 0))
            }

            Expr::Ternary { cond, then, else_ } => {
                format!(
                    "({} ? {} : {})",
                    self.emit_expr(cond, 0),
                    self.emit_expr(then, 0),
                    self.emit_expr(else_, 0)
                )
            }

            Expr::Lambda(lambda) => {
                // If this lambda was detected as a method reference, emit `ClassName::method`.
                if let Some(ref syntax) = lambda.method_ref_syntax {
                    return syntax.clone();
                }
                let params: String = lambda
                    .params
                    .iter()
                    .map(|(n, _)| n.as_str())
                    .collect::<Vec<_>>()
                    .join(", ");
                match &lambda.body {
                    LambdaBody::Expr(e) => format!("({}) -> {}", params, self.emit_expr(e, 0)),
                    LambdaBody::Block(stmts) => {
                        let mut s = format!("({params}) -> {{\n");
                        for stmt in stmts {
                            s.push_str(&self.emit_stmt(stmt, 1));
                        }
                        s.push('}');
                        s
                    }
                }
            }

            Expr::Unknown(s) => format!("/* {s} */"),
        }
    }

    fn emit_args(&self, args: &[Expr]) -> String {
        args.iter()
            .map(|a| self.emit_expr(a, 0))
            .collect::<Vec<_>>()
            .join(", ")
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

fn emit_type(ty: &JavaType) -> String {
    ty.to_string()
}

fn simple_class_name(fqn: &str) -> &str {
    // The 'L' marker must come off BEFORE the split and exactly once. Stripping
    // it afterwards ate the first letter of every class whose simple name starts
    // with 'L': `Ljava/lang/Long;` became "ong" and `LinkedList` became
    // "inkedList".
    let s = fqn.strip_prefix('L').unwrap_or(fqn);
    let s = s.strip_suffix(';').unwrap_or(s);
    s.rsplit(['.', '/']).next().unwrap_or(s)
}

fn escape_java_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 4);
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            other => out.push(other),
        }
    }
    out
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::super::java_ast::{AstClass, BinOp, ClassKind, Primitive};
    use super::*;

    #[test]
    fn test_emit_class_has_class_keyword() {
        let cls = AstClass::mock("Foo", "com.example");
        let src = emit_class(&cls);
        assert!(src.contains("class Foo"), "src: {src}");
    }

    #[test]
    fn test_emit_class_has_braces() {
        let cls = AstClass::mock("Foo", "com.example");
        let src = emit_class(&cls);
        assert!(src.contains('{'));
        assert!(src.contains('}'));
    }

    #[test]
    fn test_emit_method_return_void() {
        let cls = AstClass::mock("Foo", "com.example");
        let m = cls.find_method("<init>").expect("<init>");
        let src = emit_method(m);
        assert!(src.contains("return;"), "src: {src}");
    }

    #[test]
    fn test_emit_method_has_name() {
        let cls = AstClass::mock("Foo", "com.example");
        let m = cls.find_method("getInstance").expect("getInstance");
        let src = emit_method(m);
        assert!(src.contains("getInstance"), "src: {src}");
    }

    #[test]
    fn test_emit_compilation_unit_package() {
        let cls = AstClass::mock("Foo", "com.example");
        let mut cu = CompilationUnit::new("com.example");
        cu.add_class(cls);
        let src = emit_compilation_unit(&cu);
        assert!(src.contains("package com.example;"), "src: {src}");
    }

    #[test]
    fn test_emit_expr_int_lit() {
        let opts = EmitOptions::default();
        let emitter = Emitter::new(&opts);
        assert_eq!(emitter.emit_expr(&Expr::IntLit(42), 0), "42");
    }

    #[test]
    fn test_emit_expr_string_lit() {
        let opts = EmitOptions::default();
        let emitter = Emitter::new(&opts);
        assert_eq!(
            emitter.emit_expr(&Expr::StringLit("hello".to_owned()), 0),
            "\"hello\""
        );
    }

    #[test]
    fn test_emit_expr_null() {
        let opts = EmitOptions::default();
        let emitter = Emitter::new(&opts);
        assert_eq!(emitter.emit_expr(&Expr::NullLit, 0), "null");
    }

    #[test]
    fn test_emit_expr_this() {
        let opts = EmitOptions::default();
        let emitter = Emitter::new(&opts);
        assert_eq!(emitter.emit_expr(&Expr::This, 0), "this");
    }

    #[test]
    fn test_emit_expr_binop() {
        let opts = EmitOptions::default();
        let emitter = Emitter::new(&opts);
        let e = Expr::BinOp {
            op: BinOp::Add,
            lhs: Box::new(Expr::Var("x".to_owned())),
            rhs: Box::new(Expr::IntLit(1)),
        };
        assert_eq!(emitter.emit_expr(&e, 0), "(x + 1)");
    }

    #[test]
    fn test_emit_stmt_local_decl() {
        let opts = EmitOptions::default();
        let emitter = Emitter::new(&opts);
        let s = Statement::LocalDecl {
            ty: JavaType::Primitive(Primitive::Int),
            name: "x".to_owned(),
            init: Some(Expr::IntLit(5)),
        };
        let out = emitter.emit_stmt(&s, 0);
        assert!(out.contains("int x = 5;"), "out: {out}");
    }

    #[test]
    fn test_emit_stmt_return() {
        let opts = EmitOptions::default();
        let emitter = Emitter::new(&opts);
        let s = Statement::Return(Some(Expr::Var("result".to_owned())));
        let out = emitter.emit_stmt(&s, 0);
        assert!(out.contains("return result;"), "out: {out}");
    }

    #[test]
    fn test_emit_stmt_if() {
        let opts = EmitOptions::default();
        let emitter = Emitter::new(&opts);
        let s = Statement::If {
            cond: Expr::BoolLit(true),
            then: Box::new(Statement::Return(None)),
            else_: None,
        };
        let out = emitter.emit_stmt(&s, 0);
        assert!(out.contains("if (true)"), "out: {out}");
        assert!(out.contains("return;"), "out: {out}");
    }

    #[test]
    fn test_emit_stmt_while() {
        let opts = EmitOptions::default();
        let emitter = Emitter::new(&opts);
        let s = Statement::While {
            cond: Expr::BoolLit(false),
            body: Box::new(Statement::Empty),
        };
        let out = emitter.emit_stmt(&s, 0);
        assert!(out.contains("while (false)"), "out: {out}");
    }

    #[test]
    fn test_emit_field_private() {
        let cls = AstClass::mock("Foo", "com.example");
        let src = emit_class(&cls);
        assert!(src.contains("private"), "src: {src}");
    }

    #[test]
    fn test_simple_class_name_keeps_leading_l() {
        // The 'L' marker is stripped once, before the split. Classes whose own
        // name starts with 'L' are extremely common in Android (Long, List,
        // LinkedList, Looper), and stripping repeatedly turned `Long` into "ong".
        assert_eq!(simple_class_name("Ljava/lang/Long;"), "Long");
        assert_eq!(simple_class_name("Ljava/util/LinkedList;"), "LinkedList");
        assert_eq!(simple_class_name("Ljava/util/List;"), "List");
        assert_eq!(simple_class_name("LL;"), "L");
        assert_eq!(simple_class_name("Ljava/lang/String;"), "String");
        // Already-simple and dotted forms must still work.
        assert_eq!(simple_class_name("com.example.Foo"), "Foo");
    }

    #[test]
    fn test_escape_java_string() {
        assert_eq!(escape_java_string("say \"hi\""), "say \\\"hi\\\"");
        assert_eq!(escape_java_string("line\nnewline"), "line\\nnewline");
    }

    #[test]
    fn test_simple_class_name() {
        assert_eq!(simple_class_name("java.lang.String"), "String");
        assert_eq!(simple_class_name("Ljava/lang/Object;"), "Object");
    }

    #[test]
    fn test_emit_options_no_imports() {
        let cls = AstClass::mock("Foo", "com.example");
        let mut cu = CompilationUnit::new("com.example");
        cu.add_import("java.util.List");
        cu.add_class(cls);
        let opts = EmitOptions {
            emit_imports: false,
            ..Default::default()
        };
        let src = emit_compilation_unit_opts(&cu, &opts);
        assert!(!src.contains("import"), "src: {src}");
    }

    #[test]
    fn test_emit_interface() {
        let mut cls = AstClass::new("Runnable", "java.lang");
        cls.kind = ClassKind::Interface;
        let src = emit_class(&cls);
        assert!(src.contains("interface Runnable"), "src: {src}");
    }
}
