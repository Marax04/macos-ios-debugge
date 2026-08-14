//! `printer` — Pretty-printer for Smali classes, methods, and instructions.
//!
//! Converts the in-memory `SmaliClass` / `SmaliMethod` / `SmaliField` /
//! `SmaliInstr` types back into a canonical Smali source text suitable for
//! writing to `.smali` files or displaying in a UI.

use std::fmt::Write as FmtWrite;

use super::{SmaliAccess, SmaliClass, SmaliField, SmaliInstr, SmaliMethod, SmaliOperand, SmaliReg};

// ─────────────────────────────────────────────────────────────────────────────
// PrintOptions
// ─────────────────────────────────────────────────────────────────────────────

/// Options controlling the output of the printer.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PrintOptions {
    /// Indent each method body line with this string (default: `"    "`).
    pub indent: String,
    /// Emit blank lines between methods.
    pub blank_between_methods: bool,
    /// Emit a `# <index> <mnemonic>` comment on each instruction.
    pub emit_index_comments: bool,
    /// Emit `.line N` annotations (if line info is available).
    pub emit_line_numbers: bool,
    /// Width for padding the hex address column (0 = don't emit).
    pub address_column_width: usize,
}

impl Default for PrintOptions {
    fn default() -> Self {
        Self {
            indent: "    ".to_owned(),
            blank_between_methods: true,
            emit_index_comments: false,
            emit_line_numbers: false,
            address_column_width: 0,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Public API
// ─────────────────────────────────────────────────────────────────────────────

/// Print a complete `SmaliClass` to a `String`.
#[must_use]
pub fn print_class(class: &SmaliClass) -> String {
    print_class_opts(class, &PrintOptions::default())
}

/// Print a complete `SmaliClass` with custom `PrintOptions`.
#[must_use]
pub fn print_class_opts(class: &SmaliClass, opts: &PrintOptions) -> String {
    let mut out = String::new();

    // .class header
    let _ = writeln!(out, ".class {} {}", access_string(class.access), class.name);
    let _ = writeln!(out, ".super {}", class.super_class);

    for iface in &class.interfaces {
        let _ = writeln!(out, ".implements {iface}");
    }

    // Fields
    if !class.fields.is_empty() {
        out.push('\n');
        for field in &class.fields {
            out.push_str(&print_field(field));
            out.push('\n');
        }
    }

    // Methods
    for (i, method) in class.methods.iter().enumerate() {
        if i > 0 && opts.blank_between_methods {
            out.push('\n');
        }
        out.push_str(&print_method_opts(method, opts));
        out.push('\n');
    }

    out
}

/// Print a single `SmaliField` definition line.
#[must_use]
pub fn print_field(field: &SmaliField) -> String {
    let mut s = format!(
        ".field {} {}:{}",
        access_string(field.access),
        field.name,
        field.type_desc
    );
    if let Some(init) = field.initial {
        let _ = write!(s, " = {init:#x}");
    }
    s
}

/// Print a complete `SmaliMethod` body.
#[must_use]
pub fn print_method(method: &SmaliMethod) -> String {
    print_method_opts(method, &PrintOptions::default())
}

/// Print a `SmaliMethod` with custom options.
#[must_use]
pub fn print_method_opts(method: &SmaliMethod, opts: &PrintOptions) -> String {
    let mut out = String::new();
    let indent = &opts.indent;

    // .method header
    let _ = writeln!(
        out,
        ".method {} {}{}",
        access_string(method.access),
        method.name,
        method.signature
    );

    if method.registers > 0 {
        let _ = writeln!(out, "{}.registers {}", indent, method.registers);
    }

    for (idx, instr) in method.instructions.iter().enumerate() {
        if let Some(label) = &instr.label {
            let _ = writeln!(out, "{indent}{label}");
        }
        let line = print_instr(instr);
        if opts.emit_index_comments {
            let _ = writeln!(out, "{indent}{line}  # {idx}");
        } else {
            let _ = writeln!(out, "{indent}{line}");
        }
    }

    let _ = write!(out, ".end method");
    out
}

/// Print a single `SmaliInstr` as a text line (without label).
#[must_use]
pub fn print_instr(instr: &SmaliInstr) -> String {
    let mut s = instr.op.to_string();
    write_instr_operands(&mut s, instr);
    s
}

/// Append the operand list of an instruction to an existing buffer.
fn write_instr_operands(s: &mut String, instr: &SmaliInstr) {
    for (i, op) in instr.operands.iter().enumerate() {
        if i == 0 {
            s.push(' ');
        } else {
            s.push_str(", ");
        }
        write_operand(s, op);
    }
}

/// Print a `SmaliOperand` as text.
#[must_use]
pub fn print_operand(op: &SmaliOperand) -> String {
    let mut s = String::new();
    write_operand(&mut s, op);
    s
}

/// Append a `SmaliOperand` to an existing buffer (avoids intermediate String).
fn write_operand(out: &mut String, op: &SmaliOperand) {
    match op {
        SmaliOperand::Reg(r) => write_reg(out, r),
        SmaliOperand::Literal(n) => {
            if *n < 0 {
                let _ = write!(out, "-{:#x}", i128::from(*n).unsigned_abs());
            } else {
                let _ = write!(out, "{n:#x}");
            }
        }
        SmaliOperand::Str(s) => {
            out.push('"');
            write_escaped_string(out, s);
            out.push('"');
        }
        SmaliOperand::TypeRef(t) | SmaliOperand::FieldRef(t) | SmaliOperand::MethodRef(t) => {
            out.push_str(t);
        }
    }
}

/// Print a `SmaliReg` as text.
#[must_use]
pub fn print_reg(r: &SmaliReg) -> String {
    let mut s = String::with_capacity(4);
    write_reg(&mut s, r);
    s
}

fn write_reg(out: &mut String, r: &SmaliReg) {
    if r.num < 64 {
        let _ = write!(out, "v{}", r.num);
    } else {
        let _ = write!(out, "p{}", r.num - 64);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Access flag string
// ─────────────────────────────────────────────────────────────────────────────

/// Convert `SmaliAccess` bits to a space-separated keyword string.
#[must_use]
pub fn access_string(flags: SmaliAccess) -> String {
    // Build directly into a String to avoid the intermediate Vec + join allocation.
    let mut out = String::with_capacity(32);
    let mut push = |s: &str| {
        if !out.is_empty() {
            out.push(' ');
        }
        out.push_str(s);
    };
    if flags.contains(SmaliAccess::PUBLIC) {
        push("public");
    }
    if flags.contains(SmaliAccess::PRIVATE) {
        push("private");
    }
    if flags.contains(SmaliAccess::PROTECTED) {
        push("protected");
    }
    if flags.contains(SmaliAccess::STATIC) {
        push("static");
    }
    if flags.contains(SmaliAccess::FINAL) {
        push("final");
    }
    if flags.contains(SmaliAccess::ABSTRACT) {
        push("abstract");
    }
    if flags.contains(SmaliAccess::NATIVE) {
        push("native");
    }
    if flags.contains(SmaliAccess::CONSTRUCTOR) {
        push("constructor");
    }
    out
}

// ─────────────────────────────────────────────────────────────────────────────
// String escaping
// ─────────────────────────────────────────────────────────────────────────────

/// Escape special characters in a string literal.
#[must_use]
pub fn escape_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 4);
    write_escaped_string(&mut out, s);
    out
}

/// Append the escaped form of `s` to `out` (avoids intermediate allocation
/// when escaping into an already-existing buffer).
fn write_escaped_string(out: &mut String, s: &str) {
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\0' => out.push_str("\\0"),
            other if (other as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04X}", other as u32);
            }
            other => out.push(other),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Diff helper
// ─────────────────────────────────────────────────────────────────────────────

/// A structural diff between two `SmaliClass` values.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ClassDiff {
    pub added_methods: Vec<String>,
    pub removed_methods: Vec<String>,
    pub added_fields: Vec<String>,
    pub removed_fields: Vec<String>,
    pub changed_methods: Vec<String>,
}

/// Compute a structural diff between two parsed Smali classes.
///
/// # Panics
///
/// Panics if a method name appears in the intersection of the two name sets
/// but cannot be located back in either input's `methods` vector — this can
/// only happen if the inputs are mutated concurrently with this call.
#[must_use]
pub fn diff_classes(old: &SmaliClass, new: &SmaliClass) -> ClassDiff {
    let old_methods: std::collections::HashSet<&str> =
        old.methods.iter().map(|m| m.name.as_str()).collect();
    let new_methods: std::collections::HashSet<&str> =
        new.methods.iter().map(|m| m.name.as_str()).collect();

    let added_methods = new_methods
        .difference(&old_methods)
        .map(std::string::ToString::to_string)
        .collect();
    let removed_methods = old_methods
        .difference(&new_methods)
        .map(std::string::ToString::to_string)
        .collect();

    let old_fields: std::collections::HashSet<&str> =
        old.fields.iter().map(|f| f.name.as_str()).collect();
    let new_fields: std::collections::HashSet<&str> =
        new.fields.iter().map(|f| f.name.as_str()).collect();

    let added_fields = new_fields
        .difference(&old_fields)
        .map(std::string::ToString::to_string)
        .collect();
    let removed_fields = old_fields
        .difference(&new_fields)
        .map(std::string::ToString::to_string)
        .collect();

    // Methods that exist in both but have a different instruction count.
    // Build name -> method maps once to avoid an O(n*m) double linear scan
    // inside the intersection loop.
    let intersection_size = old_methods.intersection(&new_methods).count();
    let mut changed_methods = Vec::with_capacity(intersection_size);
    let old_by_name: std::collections::HashMap<&str, &SmaliMethod> =
        old.methods.iter().map(|m| (m.name.as_str(), m)).collect();
    let new_by_name: std::collections::HashMap<&str, &SmaliMethod> =
        new.methods.iter().map(|m| (m.name.as_str(), m)).collect();
    for method_name in old_methods.intersection(&new_methods) {
        let old_m = old_by_name[*method_name];
        let new_m = new_by_name[*method_name];
        if old_m.instr_count() != new_m.instr_count() || old_m.signature != new_m.signature {
            changed_methods.push((*method_name).to_string());
        }
    }

    ClassDiff {
        added_methods,
        removed_methods,
        added_fields,
        removed_fields,
        changed_methods,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::super::{SmaliClass, SmaliOp};
    use super::*;

    #[test]
    fn test_print_class_contains_class_name() {
        let c = SmaliClass::mock("Lcom/example/Foo;");
        let text = print_class(&c);
        assert!(text.contains("Lcom/example/Foo;"), "text: {text}");
    }

    #[test]
    fn test_print_class_contains_method() {
        let c = SmaliClass::mock("Lfoo;");
        let text = print_class(&c);
        assert!(text.contains(".method"), "text: {text}");
        assert!(text.contains(".end method"), "text: {text}");
    }

    #[test]
    fn test_print_class_contains_field() {
        let c = SmaliClass::mock("Lfoo;");
        let text = print_class(&c);
        assert!(text.contains(".field"), "text: {text}");
    }

    #[test]
    fn test_print_method_registers() {
        let c = SmaliClass::mock("Lfoo;");
        let m = &c.methods[0];
        let text = print_method(m);
        assert!(text.contains(".registers"), "text: {text}");
    }

    #[test]
    fn test_print_method_return_void() {
        let c = SmaliClass::mock("Lfoo;");
        let m = c.methods.iter().find(|m| m.name == "<init>").expect("init");
        let text = print_method(m);
        assert!(text.contains("return-void"), "text: {text}");
    }

    #[test]
    fn test_print_field() {
        let c = SmaliClass::mock("Lfoo;");
        let f = &c.fields[0];
        let text = print_field(f);
        assert!(text.contains(".field"), "text: {text}");
        assert!(text.contains("count"), "text: {text}");
    }

    #[test]
    fn test_access_string_public_static() {
        let flags = SmaliAccess::PUBLIC | SmaliAccess::STATIC;
        let s = access_string(flags);
        assert!(s.contains("public"), "s: {s}");
        assert!(s.contains("static"), "s: {s}");
    }

    #[test]
    fn test_access_string_constructor() {
        let flags = SmaliAccess::PUBLIC | SmaliAccess::CONSTRUCTOR;
        let s = access_string(flags);
        assert!(s.contains("constructor"), "s: {s}");
    }

    #[test]
    fn test_escape_string_newline() {
        assert_eq!(escape_string("hello\nworld"), "hello\\nworld");
    }

    #[test]
    fn test_escape_string_quote() {
        assert_eq!(escape_string("say \"hi\""), "say \\\"hi\\\"");
    }

    #[test]
    fn test_escape_string_tab() {
        assert_eq!(escape_string("a\tb"), "a\\tb");
    }

    #[test]
    fn test_print_instr_no_operands() {
        let i = SmaliInstr {
            op: SmaliOp::ReturnVoid,
            operands: vec![],
            label: None,
        };
        assert_eq!(print_instr(&i), "return-void");
    }

    #[test]
    fn test_print_instr_with_operands() {
        let i = SmaliInstr {
            op: SmaliOp::Move,
            operands: vec![
                SmaliOperand::Reg(SmaliReg { num: 0 }),
                SmaliOperand::Reg(SmaliReg { num: 1 }),
            ],
            label: None,
        };
        assert_eq!(print_instr(&i), "move v0, v1");
    }

    #[test]
    fn test_print_instr_const_string() {
        let i = SmaliInstr {
            op: SmaliOp::ConstString,
            operands: vec![
                SmaliOperand::Reg(SmaliReg { num: 0 }),
                SmaliOperand::Str("hello".to_owned()),
            ],
            label: None,
        };
        assert_eq!(print_instr(&i), r#"const-string v0, "hello""#);
    }

    #[test]
    fn test_print_instr_with_label() {
        let i = SmaliInstr {
            op: SmaliOp::Nop,
            operands: vec![],
            label: Some(":cond_0".to_owned()),
        };
        let method = super::super::SmaliMethod {
            name: "test".to_owned(),
            class: "L;".to_owned(),
            signature: "()V".to_owned(),
            access: SmaliAccess::PUBLIC,
            registers: 1,
            instructions: vec![i],
        };
        let text = print_method(&method);
        assert!(text.contains(":cond_0"), "text: {text}");
    }

    #[test]
    fn test_diff_classes_added_method() {
        let old = SmaliClass::mock("Lfoo;");
        let mut new_class = old.clone();
        new_class.methods.push(super::super::SmaliMethod {
            name: "newMethod".to_owned(),
            class: "Lfoo;".to_owned(),
            signature: "()V".to_owned(),
            access: SmaliAccess::PUBLIC,
            registers: 1,
            instructions: vec![],
        });
        let diff = diff_classes(&old, &new_class);
        assert!(diff.added_methods.contains(&"newMethod".to_owned()));
        assert!(diff.removed_methods.is_empty());
    }

    #[test]
    fn test_diff_classes_removed_field() {
        let old = SmaliClass::mock("Lfoo;");
        let mut new_class = old.clone();
        new_class.fields.clear();
        let diff = diff_classes(&old, &new_class);
        assert!(!diff.removed_fields.is_empty());
    }

    #[test]
    fn test_print_options_with_index_comments() {
        let c = SmaliClass::mock("Lfoo;");
        let m = c.methods.iter().find(|m| m.name == "<init>").expect("init");
        let opts = PrintOptions {
            emit_index_comments: true,
            ..Default::default()
        };
        let text = print_method_opts(m, &opts);
        assert!(text.contains("# 0"), "text: {text}");
    }

    #[test]
    fn test_print_super() {
        let c = SmaliClass::mock("Lfoo;");
        let text = print_class(&c);
        assert!(text.contains(".super Ljava/lang/Object;"), "text: {text}");
    }
}
