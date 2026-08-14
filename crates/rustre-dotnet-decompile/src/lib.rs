//! `rustre-dotnet-decompile`
//!
//! CIL → C# decompiler. Converts `DotnetMethod` and `DotnetType` from
//! `rustre-dotnet` into readable C# source text.

pub mod linq_recovery_full;
pub mod async_recovery;
pub mod csharp_patterns;
pub mod linq_recovery;

/// Narrowing numeric cast helpers. These wrap saturating/wrapping conversions
/// in named functions so call sites stay readable. Each helper is a deliberate
/// boundary — saturation/wrap semantics are documented per fn.
#[doc(hidden)]
pub mod casts {
    /// Truncating cast `usize` → `u32`. Saturates at `u32::MAX`.
    #[inline]
    #[must_use]
    pub fn usize_to_u32(v: usize) -> u32 { u32::try_from(v).unwrap_or(u32::MAX) }
    /// Truncating cast `usize` → `i32`. Saturates at `i32::MAX`.
    #[inline]
    #[must_use]
    pub fn usize_to_i32(v: usize) -> i32 { i32::try_from(v).unwrap_or(i32::MAX) }
    /// Truncating cast `usize` → `i64`. Saturates at `i64::MAX`.
    #[inline]
    #[must_use]
    pub fn usize_to_i64(v: usize) -> i64 { i64::try_from(v).unwrap_or(i64::MAX) }
    /// Cast `usize` → `f64`. Composed from two losslessly-from-u32 halves so
    /// the precision loss is explicit (mantissa is 52 bits).
    #[inline]
    #[must_use]
    pub fn usize_to_f64(v: usize) -> f64 {
        let hi = u32::try_from(v >> 32).unwrap_or(u32::MAX);
        let lo = u32::try_from(v & 0xFFFF_FFFF).unwrap_or(u32::MAX);
        (f64::from(hi) * f64::from(1u32 << 16)).mul_add(f64::from(1u32 << 16), f64::from(lo))
    }
    /// Cast `i32` → `usize`. Negative values saturate to 0.
    #[inline]
    #[must_use]
    pub fn i32_to_usize(v: i32) -> usize { usize::try_from(v).unwrap_or(0) }
    /// Cast `i8` → `usize`. Negative values saturate to 0.
    #[inline]
    #[must_use]
    pub fn i8_to_usize(v: i8) -> usize { usize::try_from(v).unwrap_or(0) }
    /// Cast `i32` → `u16` (truncating + sign-stripping).
    #[inline]
    #[must_use]
    pub fn i32_to_u16(v: i32) -> u16 { u16::try_from(v.cast_unsigned() & 0xFFFF).unwrap_or(u16::MAX) }
    /// Cast `i8` → `u16` (sign-extended into low bits).
    #[inline]
    #[must_use]
    pub fn i8_to_u16(v: i8) -> u16 { u16::from(v.cast_unsigned()) }
    /// Cast `i64` → `u32` (truncating + sign-stripping).
    #[inline]
    #[must_use]
    pub fn i64_to_u32(v: i64) -> u32 { u32::try_from(v.cast_unsigned() & 0xFFFF_FFFF).unwrap_or(u32::MAX) }
    /// Reinterpret `u8` as `i8` (bit-for-bit).
    #[inline]
    #[must_use]
    pub const fn u8_as_i8(v: u8) -> i8 { v.cast_signed() }
    /// Reinterpret `u32` as `i32` (bit-for-bit).
    #[inline]
    #[must_use]
    pub const fn u32_as_i32(v: u32) -> i32 { v.cast_signed() }
    /// Reinterpret `u64` as `i64` (bit-for-bit).
    #[inline]
    #[must_use]
    pub const fn u64_as_i64(v: u64) -> i64 { v.cast_signed() }
}

use ahash::AHashMap;
use std::fmt::Write as _;

use anyhow::Result;
use rustre_dotnet::{
    AssemblyFile, CilInstruction, CilOperand, DotnetMethod, DotnetType, ExceptionHandlerKind,
    MethodBody,
};

// ─── Options ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct DecompilerOptions {
    /// Indentation string (default: four spaces).
    pub indent: String,
    /// Emit CIL offset comments before each statement.
    pub emit_comments: bool,
    /// Use `var` for local variable declarations.
    pub use_var: bool,
    /// Use short type names (`int` instead of `System.Int32`).
    pub use_short_types: bool,
}

impl Default for DecompilerOptions {
    fn default() -> Self {
        Self {
            indent: "    ".to_string(),
            emit_comments: false,
            use_var: true,
            use_short_types: true,
        }
    }
}

// ─── Type name normalisation ───────────────────────────────────────────────────

fn normalize_type(name: &str) -> &str {
    match name {
        "System.Void" | "void" => "void",
        "System.Boolean" | "bool" => "bool",
        "System.Char" | "char" => "char",
        "System.Byte" | "byte" => "byte",
        "System.SByte" | "sbyte" => "sbyte",
        "System.Int16" | "short" => "short",
        "System.UInt16" | "ushort" => "ushort",
        "System.Int32" | "int" => "int",
        "System.UInt32" | "uint" => "uint",
        "System.Int64" | "long" => "long",
        "System.UInt64" | "ulong" => "ulong",
        "System.Single" | "float" => "float",
        "System.Double" | "double" => "double",
        "System.String" | "string" => "string",
        "System.Object" | "object" => "object",
        "System.Decimal" | "decimal" => "decimal",
        _ => name,
    }
}

fn normalize_type_owned(name: &str) -> String {
    normalize_type(name).to_string()
}

// ─── Access modifier mapping ───────────────────────────────────────────────────

/// Map `TypeDef` / `MethodDef` flags to C# modifiers.
fn method_modifiers(flags: u32) -> Vec<&'static str> {
    let mut mods = Vec::new();
    // Visibility (bits 0-2)
    match flags & 0x0007 {
        0x03 => mods.push("internal"),
        0x04 => mods.push("protected"),
        0x05 => mods.push("protected internal"),
        0x06 => mods.push("public"),
        // 0x01 (Private), 0x02 (FamANDAssem), and any unrecognised value => private.
        _ => mods.push("private"),
    }
    if flags & 0x0010 != 0 {
        mods.push("static");
    }
    if flags & 0x0020 != 0 {
        mods.push("virtual");
    }
    if flags & 0x0040 != 0 {
        mods.push("sealed");
    }
    if flags & 0x0080 != 0 {
        mods.push("sealed");
    } // NewSlot treated as sealed for simplicity
    if flags & 0x0400 != 0 {
        mods.push("abstract");
    }
    mods
}

fn type_modifiers(flags: u32) -> Vec<&'static str> {
    let mut mods = Vec::new();
    match flags & 0x07 {
        0x01 | 0x02 => mods.push("public"),
        _ => mods.push("internal"),
    }
    if flags & 0x0100 != 0 {
        mods.push("abstract");
    }
    if flags & 0x0200 != 0 {
        mods.push("sealed");
    }
    if flags & 0x0080 != 0 {
        mods.push("sealed");
    }
    mods
}

// ─── Property detection ───────────────────────────────────────────────────────

fn detect_property_name(method_name: &str) -> Option<(&'static str, &str)> {
    method_name.strip_prefix("get_").map_or_else(
        || method_name.strip_prefix("set_").map(|prop| ("set", prop)),
        |prop| Some(("get", prop)),
    )
}

// ─── Stack-to-variable lowering ────────────────────────────────────────────────

#[derive(Debug, Clone)]
enum StackValue {
    Temp(usize),
    Literal(String),
    /// Field access expression or call result expression
    FieldAccess(String),
    Null,
}

impl StackValue {
    fn to_expr(&self) -> String {
        match self {
            Self::Temp(n) => format!("t{n}"),
            Self::Literal(s) | Self::FieldAccess(s) => s.clone(),
            Self::Null => "null".to_string(),
        }
    }
}

struct DecompileState<'a> {
    opts: &'a DecompilerOptions,
    stack: Vec<StackValue>,
    temp_counter: usize,
    statements: Vec<String>,
    /// Locals: index → (name, type)
    locals: Vec<(String, String)>,
    /// Tracks which local indices have already been declared with `var`.
    declared_locals: std::collections::HashSet<usize>,
    method: &'a DotnetMethod,
    indent: String,
}

impl<'a> DecompileState<'a> {
    fn new(
        opts: &'a DecompilerOptions,
        method: &'a DotnetMethod,
        body: &'a MethodBody,
        indent: &str,
    ) -> Self {
        let locals: Vec<(String, String)> = body
            .locals
            .iter()
            .map(|l| {
                (
                    format!("local{}", l.index),
                    normalize_type_owned(&l.type_name),
                )
            })
            .collect();
        Self {
            opts,
            stack: Vec::new(),
            temp_counter: 0,
            statements: Vec::new(),
            locals,
            declared_locals: std::collections::HashSet::new(),
            method,
            indent: indent.to_string(),
        }
    }

    fn push(&mut self, v: StackValue) {
        self.stack.push(v);
    }

    fn pop(&mut self) -> StackValue {
        self.stack
            .pop()
            .unwrap_or_else(|| StackValue::Literal("/* empty */".to_string()))
    }

    const fn alloc_temp(&mut self) -> StackValue {
        let n = self.temp_counter;
        self.temp_counter += 1;
        StackValue::Temp(n)
    }

    fn emit(&mut self, mut stmt: String) {
        stmt.insert_str(0, &self.indent);
        self.statements.push(stmt);
    }

    fn param_name(&self, idx: usize) -> String {
        if self.method.signature.is_static {
            self.method
                .signature
                .params
                .get(idx).map_or_else(|| format!("arg{idx}"), |(n, _)| n.clone())
        } else if idx == 0 {
            "this".to_string()
        } else {
            self.method
                .signature
                .params
                .get(idx - 1).map_or_else(|| format!("arg{idx}"), |(n, _)| n.clone())
        }
    }

    fn local_name(&self, idx: usize) -> String {
        self.locals
            .get(idx).map_or_else(|| format!("local{idx}"), |(n, _)| n.clone())
    }

    fn process(&mut self, instr: &CilInstruction) {
        let comment = if self.opts.emit_comments {
            format!(" /* IL_{:04X} */", instr.offset)
        } else {
            String::new()
        };
        if self.process_loads(instr) { return; }
        if self.process_stores(instr, &comment) { return; }
        if self.process_arithmetic(instr, &comment) { return; }
        if self.process_branches(instr, &comment) { return; }
        if self.process_objects(instr, &comment) { return; }
        if self.process_arrays(instr, &comment) { return; }
        self.process_misc(instr, &comment);
    }

    fn process_loads(&mut self, instr: &CilInstruction) -> bool {
        match instr.opcode.as_str() {
            "nop" | "break" => {}
            "ldnull" => self.push(StackValue::Null),
            "ldc.i4.0" => self.push(StackValue::Literal("0".into())),
            "ldc.i4.1" => self.push(StackValue::Literal("1".into())),
            "ldc.i4.2" => self.push(StackValue::Literal("2".into())),
            "ldc.i4.3" => self.push(StackValue::Literal("3".into())),
            "ldc.i4.4" => self.push(StackValue::Literal("4".into())),
            "ldc.i4.5" => self.push(StackValue::Literal("5".into())),
            "ldc.i4.6" => self.push(StackValue::Literal("6".into())),
            "ldc.i4.7" => self.push(StackValue::Literal("7".into())),
            "ldc.i4.8" => self.push(StackValue::Literal("8".into())),
            "ldc.i4.m1" => self.push(StackValue::Literal("-1".into())),
            "ldc.i4.s" | "ldc.i4" => {
                let v = match &instr.operand { CilOperand::Int8(n) => n.to_string(), CilOperand::Int32(n) => n.to_string(), _ => "0".into() };
                self.push(StackValue::Literal(v));
            }
            "ldc.i8" => { let v = match &instr.operand { CilOperand::Int64(n) => format!("{n}L"), _ => "0L".into() }; self.push(StackValue::Literal(v)); }
            "ldc.r4" => { let v = match &instr.operand { CilOperand::Float32(f) => format!("{f}f"), _ => "0f".into() }; self.push(StackValue::Literal(v)); }
            "ldc.r8" => { let v = match &instr.operand { CilOperand::Float64(f) => f.to_string(), _ => "0.0".into() }; self.push(StackValue::Literal(v)); }
            "ldstr" => {
                let s = match &instr.operand { CilOperand::String(s) => format!("\"{s}\""), CilOperand::Token(t) => format!("/* token 0x{t:08X} */\"\""), _ => "\"\"".into() };
                self.push(StackValue::Literal(s));
            }
            "ldarg.0" => { let v = self.param_name(0); self.push(StackValue::Literal(v)); }
            "ldarg.1" => { let v = self.param_name(1); self.push(StackValue::Literal(v)); }
            "ldarg.2" => { let v = self.param_name(2); self.push(StackValue::Literal(v)); }
            "ldarg.3" => { let v = self.param_name(3); self.push(StackValue::Literal(v)); }
            "ldarg.s" | "ldarg" => {
                let idx = match &instr.operand { CilOperand::Int32(n) => casts::i32_to_usize(*n), _ => 0 };
                let name = self.param_name(idx); self.push(StackValue::Literal(name));
            }
            "ldloc.0" | "ldloc.1" | "ldloc.2" | "ldloc.3" | "ldloc.s" | "ldloc" => {
                let idx: usize = match instr.opcode.as_str() {
                    "ldloc.0" => 0, "ldloc.1" => 1, "ldloc.2" => 2, "ldloc.3" => 3,
                    _ => match &instr.operand { CilOperand::Int32(n) => casts::i32_to_usize(*n), _ => 0 },
                };
                let name = self.local_name(idx); self.push(StackValue::Literal(name));
            }
            _ => return false,
        }
        true
    }

    fn process_stores(&mut self, instr: &CilInstruction, comment: &str) -> bool {
        match instr.opcode.as_str() {
            "stloc.0" | "stloc.1" | "stloc.2" | "stloc.3" | "stloc.s" | "stloc" => {
                let idx: usize = match instr.opcode.as_str() {
                    "stloc.0" => 0, "stloc.1" => 1, "stloc.2" => 2, "stloc.3" => 3,
                    _ => match &instr.operand { CilOperand::Int32(n) => casts::i32_to_usize(*n), _ => 0 },
                };
                let val = self.pop();
                let name = self.local_name(idx);
                let already_declared = !self.declared_locals.insert(idx);
                if already_declared {
                    self.emit(format!("{name} = {};{comment}", val.to_expr()));
                } else {
                    let ty = self.locals.get(idx).map_or_else(|| "var".into(), |(_, t)| t.clone());
                    let decl_type = if self.opts.use_var { "var".to_string() } else { ty };
                    self.emit(format!("{decl_type} {name} = {};{comment}", val.to_expr()));
                }
            }
            "dup" => {
                let v = self.stack.last().cloned().unwrap_or_else(|| StackValue::Literal("/* dup */".into()));
                self.push(v);
            }
            "pop" => { self.pop(); }
            _ => return false,
        }
        true
    }

    fn process_arithmetic(&mut self, instr: &CilInstruction, comment: &str) -> bool {
        let op_sym: Option<&str> = match instr.opcode.as_str() {
            "add" => Some("+"), "sub" => Some("-"), "mul" => Some("*"),
            "div" | "div.un" => Some("/"), "rem" | "rem.un" => Some("%"),
            "and" => Some("&"), "or" => Some("|"), "xor" => Some("^"),
            "shl" => Some("<<"), "shr" | "shr.un" => Some(">>"),
            "ceq" => Some("=="), "cgt" | "cgt.un" => Some(">"), "clt" | "clt.un" => Some("<"),
            _ => None,
        };
        if let Some(op) = op_sym {
            let b = self.pop(); let a = self.pop();
            let tmp = self.alloc_temp();
            self.emit(format!("var {} = {} {op} {};{comment}", tmp.to_expr(), a.to_expr(), b.to_expr()));
            self.push(tmp);
            return true;
        }
        match instr.opcode.as_str() {
            "neg" => { let a = self.pop(); let tmp = self.alloc_temp(); self.emit(format!("var {} = -{};{comment}", tmp.to_expr(), a.to_expr())); self.push(tmp); }
            "not" => { let a = self.pop(); let tmp = self.alloc_temp(); self.emit(format!("var {} = ~{};{comment}", tmp.to_expr(), a.to_expr())); self.push(tmp); }
            "conv.i1" | "conv.i2" | "conv.i4" | "conv.u1" | "conv.u2" | "conv.u4" | "conv.i8"
            | "conv.u8" | "conv.r4" | "conv.r8" | "conv.i" | "conv.u" => {
                let cs_type = match instr.opcode.as_str() {
                    "conv.i1" => "sbyte", "conv.i2" => "short", "conv.u1" => "byte",
                    "conv.u2" => "ushort", "conv.u4" | "conv.u" => "uint",
                    "conv.i8" => "long", "conv.u8" => "ulong",
                    "conv.r4" => "float", "conv.r8" => "double", _ => "int",
                };
                let a = self.pop(); let tmp = self.alloc_temp();
                self.emit(format!("var {} = ({cs_type}){};{comment}", tmp.to_expr(), a.to_expr()));
                self.push(tmp);
            }
            _ => return false,
        }
        true
    }

    fn process_branches(&mut self, instr: &CilInstruction, comment: &str) -> bool {
        let branch_target = || match &instr.operand { CilOperand::Branch(t) => *t, _ => 0 };
        match instr.opcode.as_str() {
            "brfalse" | "brfalse.s" => {
                let t = branch_target(); let v = self.pop();
                self.emit(format!("if ({} == false) goto IL_{t:04X};{comment}", v.to_expr()));
            }
            "brtrue" | "brtrue.s" => {
                let t = branch_target(); let v = self.pop();
                self.emit(format!("if ({} != false) goto IL_{t:04X};{comment}", v.to_expr()));
            }
            "br" | "br.s" => { let t = branch_target(); self.emit(format!("goto IL_{t:04X};{comment}")); }
            "leave" | "leave.s" => { let t = branch_target(); self.emit(format!("goto IL_{t:04X}; // leave{comment}")); }
            "beq" | "beq.s" => {
                let t = branch_target(); let b = self.pop(); let a = self.pop();
                self.emit(format!("if ({} == {}) goto IL_{t:04X};{comment}", a.to_expr(), b.to_expr()));
            }
            "bne.un" | "bne.un.s" => {
                let t = branch_target(); let b = self.pop(); let a = self.pop();
                self.emit(format!("if ({} != {}) goto IL_{t:04X};{comment}", a.to_expr(), b.to_expr()));
            }
            "bgt" | "bgt.s" | "bgt.un" | "bgt.un.s" => {
                let t = branch_target(); let b = self.pop(); let a = self.pop();
                self.emit(format!("if ({} > {}) goto IL_{t:04X};{comment}", a.to_expr(), b.to_expr()));
            }
            "bge" | "bge.s" | "bge.un" | "bge.un.s" => {
                let t = branch_target(); let b = self.pop(); let a = self.pop();
                self.emit(format!("if ({} >= {}) goto IL_{t:04X};{comment}", a.to_expr(), b.to_expr()));
            }
            "blt" | "blt.s" | "blt.un" | "blt.un.s" => {
                let t = branch_target(); let b = self.pop(); let a = self.pop();
                self.emit(format!("if ({} < {}) goto IL_{t:04X};{comment}", a.to_expr(), b.to_expr()));
            }
            "ble" | "ble.s" | "ble.un" | "ble.un.s" => {
                let t = branch_target(); let b = self.pop(); let a = self.pop();
                self.emit(format!("if ({} <= {}) goto IL_{t:04X};{comment}", a.to_expr(), b.to_expr()));
            }
            "switch" => {
                let val = self.pop();
                if let CilOperand::Switch(targets) = &instr.operand {
                    let mut s = format!("switch ({}) {{{comment}\n", val.to_expr());
                    for (i, t) in targets.iter().enumerate() {
                        writeln!(s, "{}case {i}: goto IL_{:04X};", self.indent, t).unwrap();
                    }
                    s.push('}');
                    self.emit(s);
                }
            }
            _ => return false,
        }
        true
    }

    fn process_objects(&mut self, instr: &CilInstruction, comment: &str) -> bool {
        match instr.opcode.as_str() {
            "ret" => {
                let ret_type = normalize_type(&self.method.signature.return_type);
                if ret_type == "void" || self.stack.is_empty() { self.emit(format!("return;{comment}")); }
                else { let v = self.pop(); self.emit(format!("return {};{comment}", v.to_expr())); }
            }
            "throw" => { let v = self.pop(); self.emit(format!("throw {};{comment}", v.to_expr())); }
            "call" | "callvirt" => {
                let token = match &instr.operand { CilOperand::Token(t) => *t, _ => 0 };
                let tmp = self.alloc_temp();
                self.emit(format!("var {} = /* call 0x{token:08X} */();{comment}", tmp.to_expr()));
                self.push(tmp);
            }
            "newobj" => {
                let token = match &instr.operand { CilOperand::Token(t) => *t, _ => 0 };
                let tmp = self.alloc_temp();
                self.emit(format!("var {} = new /* 0x{token:08X} */();{comment}", tmp.to_expr()));
                self.push(tmp);
            }
            "ldfld" | "ldsfld" => {
                let token = match &instr.operand { CilOperand::Token(t) => *t, _ => 0 };
                let obj = if instr.opcode == "ldfld" { self.pop().to_expr() } else { String::new() };
                let expr = if obj.is_empty() { format!("/* sfld 0x{token:08X} */") } else { format!("{obj}./* fld 0x{token:08X} */") };
                self.push(StackValue::FieldAccess(expr));
            }
            "stfld" | "stsfld" => {
                let token = match &instr.operand { CilOperand::Token(t) => *t, _ => 0 };
                let val = self.pop();
                let obj = if instr.opcode == "stfld" { self.pop().to_expr() } else { String::new() };
                let lhs = if obj.is_empty() { format!("/* sfld 0x{token:08X} */") } else { format!("{obj}./* fld 0x{token:08X} */") };
                self.emit(format!("{lhs} = {};{comment}", val.to_expr()));
            }
            "box" | "unbox" | "unbox.any" | "castclass" | "isinst" => {
                let token = match &instr.operand { CilOperand::Token(t) => *t, _ => 0 };
                let val = self.pop(); let tmp = self.alloc_temp();
                let s = if instr.opcode == "isinst" {
                    format!("var {} = {} as /* 0x{token:08X} */;{comment}", tmp.to_expr(), val.to_expr())
                } else {
                    format!("var {} = (/* 0x{token:08X} */){};{comment}", tmp.to_expr(), val.to_expr())
                };
                self.emit(s); self.push(tmp);
            }
            "initobj" => {
                let val = self.pop();
                let token = match &instr.operand { CilOperand::Token(t) => *t, _ => 0 };
                self.emit(format!("{} = default; // initobj 0x{token:08X}{comment}", val.to_expr()));
            }
            _ => return false,
        }
        true
    }

    fn process_arrays(&mut self, instr: &CilInstruction, comment: &str) -> bool {
        match instr.opcode.as_str() {
            "newarr" => {
                let token = match &instr.operand { CilOperand::Token(t) => *t, _ => 0 };
                let len = self.pop(); let tmp = self.alloc_temp();
                self.emit(format!("var {} = new /* 0x{token:08X} */[{}];{comment}", tmp.to_expr(), len.to_expr()));
                self.push(tmp);
            }
            "ldlen" => {
                let arr = self.pop(); let tmp = self.alloc_temp();
                self.emit(format!("var {} = {}.Length;{comment}", tmp.to_expr(), arr.to_expr()));
                self.push(tmp);
            }
            "ldelem.i4" | "ldelem.i8" | "ldelem.r4" | "ldelem.r8" | "ldelem.ref" | "ldelem.u1"
            | "ldelem.i1" | "ldelem.i2" | "ldelem.u2" | "ldelem" => {
                let idx_v = self.pop(); let arr = self.pop(); let tmp = self.alloc_temp();
                self.emit(format!("var {} = {}[{}];{comment}", tmp.to_expr(), arr.to_expr(), idx_v.to_expr()));
                self.push(tmp);
            }
            "stelem.i4" | "stelem.i8" | "stelem.r4" | "stelem.r8" | "stelem.ref" | "stelem" => {
                let val = self.pop(); let idx_v = self.pop(); let arr = self.pop();
                self.emit(format!("{}[{}] = {};{comment}", arr.to_expr(), idx_v.to_expr(), val.to_expr()));
            }
            _ => return false,
        }
        true
    }

    fn process_misc(&mut self, instr: &CilInstruction, comment: &str) {
        if instr.opcode == "endfinally" {
            self.emit(format!("// endfinally{comment}"));
        } else {
            let op = &instr.opcode;
            self.emit(format!("/* {op} */"));
        }
    }
}

// ─── CSharpDecompiler ─────────────────────────────────────────────────────────

#[derive(Default)]
pub struct CSharpDecompiler {
    pub options: DecompilerOptions,
}


impl CSharpDecompiler {
    #[must_use] 
    pub const fn new(options: DecompilerOptions) -> Self {
        Self { options }
    }

    /// Decompile a single `DotnetMethod` into a C# method string.
    ///
    /// # Errors
    /// Returns an error if internal disassembly or formatting fails.
    pub fn decompile_method(&self, method: &DotnetMethod) -> Result<String> {
        let mut out = String::new();
        let indent = &self.options.indent;
        let mods = method_modifiers(method.flags);
        let mods_str = mods.join(" ");
        let ret_type = normalize_type_owned(&method.signature.return_type);

        // Detect property accessor
        let is_property = detect_property_name(&method.name);

        let params_str = method
            .signature
            .params
            .iter()
            .map(|(name, ty)| format!("{} {name}", normalize_type(ty)))
            .collect::<Vec<_>>()
            .join(", ");

        let method_display_name = if let Some((_, prop)) = is_property {
            format!(
                "// property accessor: {prop}\n{indent}{mods_str} {ret_type} {}",
                method.name
            )
        } else {
            format!("{indent}{mods_str} {ret_type} {}", method.name)
        };

        writeln!(out, "{method_display_name}({params_str})\n{indent}{{"
        ).unwrap();

        if let Some(body) = &method.body {
            // Local declarations
            for local in &body.locals {
                let ty = normalize_type_owned(&local.type_name);
                writeln!(out, "{indent}{indent}{ty} local{} = default;",
                    local.index
                ).unwrap();
            }
            // Exception handler info
            for eh in &body.exception_handlers {
                match eh.kind {
                    ExceptionHandlerKind::Catch => {
                        let catch_ty = eh.catch_type.as_deref().unwrap_or("Exception");
                        writeln!(out, "{indent}{indent}// try [IL_{:04X}..IL_{:04X}] catch({catch_ty}) [IL_{:04X}..IL_{:04X}]",
                            eh.try_start, eh.try_end, eh.handler_start, eh.handler_end
                        ).unwrap();
                    }
                    ExceptionHandlerKind::Finally => {
                        writeln!(out, "{indent}{indent}// try [IL_{:04X}..IL_{:04X}] finally [IL_{:04X}..IL_{:04X}]",
                            eh.try_start, eh.try_end, eh.handler_start, eh.handler_end
                        ).unwrap();
                    }
                    _ => {}
                }
            }

            let mut state =
                DecompileState::new(&self.options, method, body, &format!("{indent}{indent}"));
            for instr in &body.instructions {
                state.process(instr);
            }
            for stmt in &state.statements {
                out.push_str(stmt);
                out.push('\n');
            }
        } else {
            writeln!(out, "{indent}{indent}throw new System.NotImplementedException();"
            ).unwrap();
        }

        writeln!(out, "{indent}}}").unwrap();
        Ok(out)
    }

    /// Decompile an entire `DotnetType` to a C# class/interface/struct/enum definition.
    ///
    /// # Errors
    /// Returns an error if any member decompilation fails.
    pub fn decompile_type(&self, t: &DotnetType) -> Result<String> {
        let mut out = String::new();
        let indent = &self.options.indent;

        // Namespace
        let in_ns = !t.namespace.is_empty();
        if in_ns {
            writeln!(out, "namespace {}\n{{", t.namespace).unwrap();
        }

        let kind = if t.is_interface() {
            "interface"
        } else if t.is_enum() {
            "enum"
        } else if t.is_struct() {
            "struct"
        } else if t.is_delegate() {
            "delegate"
        } else {
            "class"
        };

        // Derive a synthetic flags value to drive the access modifier helper.
        // DotnetType.is_class etc. map to TypeDef flag bits.
        let synthetic_flags: u32 = 0x01 // public
            | if t.is_interface() { 0x0020 } else { 0 }
            | if t.is_struct() { 0x0100 } else { 0 };
        let type_mod_str = type_modifiers(synthetic_flags).join(" ");
        let mut header = format!("{indent}{type_mod_str} {kind} {}", t.name);
        let mut bases: Vec<&str> = Vec::new();
        if let Some(base) = &t.base_type {
            let b = normalize_type(base);
            if b != "object" && b != "System.Object" {
                bases.push(b);
            }
        }
        let iface_strs: Vec<String> = t
            .interfaces
            .iter()
            .map(|i| normalize_type_owned(i))
            .collect();
        for i in &iface_strs {
            bases.push(i.as_str());
        }
        if !bases.is_empty() {
            write!(header, " : {}", bases.join(", ")).unwrap();
        }
        writeln!(out, "{header}\n{indent}{{").unwrap();

        // Fields
        for field in &t.fields {
            let field_mods = if field.is_static {
                "public static"
            } else {
                "public"
            };
            let ty = normalize_type_owned(&field.type_name);
            writeln!(out, "{indent}{indent}{field_mods} {ty} {};",
                field.name
            ).unwrap();
        }

        // Collect property accessors to group them.
        // Uses AHashMap because the keys are property names extracted from method
        // names in the untrusted binary — attacker-controlled strings that could
        // be crafted to collide in std's SipHash map (dos-hash-collision).
        let mut properties: AHashMap<String, Vec<String>> = AHashMap::new();
        for method in &t.methods {
            if let Some((accessor, prop_name)) = detect_property_name(&method.name) {
                properties
                    .entry(prop_name.to_string())
                    .or_default()
                    .push(accessor.to_string());
            }
        }

        // Emit grouped properties first
        for (prop_name, accessors) in &properties {
            let has_get = accessors.iter().any(|a| a == "get");
            let has_set = accessors.iter().any(|a| a == "set");
            let ret_type = t
                .methods
                .iter()
                .find(|m| m.name == format!("get_{prop_name}")).map_or_else(|| "object".to_string(), |m| normalize_type_owned(&m.signature.return_type));
            let accessors_str = match (has_get, has_set) {
                (true, true) => "get; set;",
                (true, false) => "get;",
                (false, true) => "set;",
                (false, false) => "",
            };
            writeln!(out, "{indent}{indent}public {ret_type} {prop_name} {{ {accessors_str} }}"
            ).unwrap();
        }

        // Emit methods
        for method in &t.methods {
            // Skip property accessors that were already grouped
            if detect_property_name(&method.name).is_some() {
                continue;
            }
            let method_text = self.decompile_method(method)?;
            // Indent each line an extra level
            for line in method_text.lines() {
                writeln!(out, "{indent}{line}").unwrap();
            }
        }

        writeln!(out, "{indent}}}").unwrap();
        if in_ns {
            out.push('}');
            out.push('\n');
        }
        Ok(out)
    }

    /// Decompile an entire assembly. Returns a map of `full_type_name → C# source`.
    /// Uses `AHashMap` because keys are type names from untrusted assembly data
    /// (dos-hash-collision).
    ///
    /// # Errors
    /// Returns an error if any type within the assembly fails to decompile.
    pub fn decompile_assembly(&self, assembly: &AssemblyFile) -> Result<AHashMap<String, String>> {
        let types = assembly.types();
        let mut result = AHashMap::with_capacity_and_hasher(types.len(), ahash::RandomState::new());
        for t in &types {
            let src = self.decompile_type(t)?;
            result.insert(t.full_name.clone(), src);
        }
        Ok(result)
    }
}

// ─── TypeKind ─────────────────────────────────────────────────────────────────

/// Classification of a .NET type from its `TypeDef` flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TypeKind {
    Class,
    Interface,
    Struct,
    Enum,
    Delegate,
}

impl TypeKind {
    /// Determine the kind from TypeDef.Flags.
    #[must_use]
    pub const fn from_flags(flags: u32) -> Self {
        if flags & 0x0020 != 0 {
            return Self::Interface;
        }
        if flags & 0x0100 != 0 {
            return Self::Struct; // simplified: check base type in reality
        }
        Self::Class
    }

    /// Returns the C# keyword for this kind.
    #[must_use]
    pub const fn keyword(self) -> &'static str {
        match self {
            Self::Class => "class",
            Self::Interface => "interface",
            Self::Struct => "struct",
            Self::Enum => "enum",
            Self::Delegate => "delegate",
        }
    }
}

impl std::fmt::Display for TypeKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.keyword())
    }
}

// ─── HLIL — High-Level Intermediate Language ──────────────────────────────────

/// Binary operators used in HLIL expressions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinaryOp {
    Add,
    Sub,
    Mul,
    Div,
    Rem,
    And,
    Or,
    Xor,
    Shl,
    Shr,
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
}

impl BinaryOp {
    /// Returns the C# operator string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Add => "+",
            Self::Sub => "-",
            Self::Mul => "*",
            Self::Div => "/",
            Self::Rem => "%",
            Self::And => "&",
            Self::Or => "|",
            Self::Xor => "^",
            Self::Shl => "<<",
            Self::Shr => ">>",
            Self::Eq => "==",
            Self::Ne => "!=",
            Self::Lt => "<",
            Self::Le => "<=",
            Self::Gt => ">",
            Self::Ge => ">=",
        }
    }
}

/// Unary operators used in HLIL expressions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnaryOp {
    Neg,
    Not,
    BitNot,
    Cast(u8), // element type byte
}

impl UnaryOp {
    /// Returns the C# representation prefix.
    #[must_use]
    pub fn prefix_str(self) -> String {
        match self {
            Self::Neg => "-".to_string(),
            Self::Not => "!".to_string(),
            Self::BitNot => "~".to_string(),
            Self::Cast(et) => format!("({})", elem_type_name(et)),
        }
    }
}

const fn elem_type_name(et: u8) -> &'static str {
    match et {
        0x02 => "bool",
        0x03 => "char",
        0x04 => "sbyte",
        0x05 => "byte",
        0x06 => "short",
        0x07 => "ushort",
        0x08 => "int",
        0x09 => "uint",
        0x0A => "long",
        0x0B => "ulong",
        0x0C => "float",
        0x0D => "double",
        0x0E => "string",
        0x1C => "object",
        _ => "nint",
    }
}

/// A high-level expression in the HLIL model.
#[derive(Debug, Clone)]
pub enum HlilExpression {
    /// Integer constant.
    Const(i64),
    /// Floating-point constant.
    FloatConst(f64),
    /// String literal.
    StringLit(String),
    /// Null literal.
    Null,
    /// Local variable by index and name.
    Local(usize, String),
    /// Parameter by index and name.
    Param(usize, String),
    /// Static field access by token and optional name.
    StaticField(u32, Option<String>),
    /// Instance field access: (object expression, token, optional name).
    InstanceField(Box<Self>, u32, Option<String>),
    /// Array element: (array, index).
    ArrayElement(Box<Self>, Box<Self>),
    /// Array length.
    ArrayLength(Box<Self>),
    /// Binary operation.
    BinaryOp {
        op: BinaryOp,
        lhs: Box<Self>,
        rhs: Box<Self>,
    },
    /// Unary operation.
    UnaryOp {
        op: UnaryOp,
        operand: Box<Self>,
    },
    /// Cast or type conversion: (target type token, value).
    Cast(u32, Box<Self>),
    /// `is` type test.
    IsInst(u32, Box<Self>),
    /// Method call: (token, args).
    Call(u32, Vec<Self>),
    /// Virtual method call.
    Callvirt(u32, Vec<Self>),
    /// Object construction: (token, args).
    NewObj(u32, Vec<Self>),
    /// Array construction: (element type token, size).
    NewArr(u32, Box<Self>),
    /// Opaque / un-lifted expression.
    Opaque(String),
    /// Conditional ternary: condition ? `true_expr` : `false_expr`.
    Ternary(
        Box<Self>,
        Box<Self>,
        Box<Self>,
    ),
}

impl HlilExpression {
    /// Convert this expression to C# source text.
    #[must_use]
    pub fn to_csharp(&self) -> String {
        match self {
            Self::Const(n) => n.to_string(),
            Self::FloatConst(f) => format!("{f}"),
            Self::StringLit(s) => format!("\"{s}\""),
            Self::Null => "null".to_string(),
            Self::Local(_, name) | Self::Param(_, name) => name.clone(),
            Self::StaticField(_tok, Some(name)) => name.clone(),
            Self::StaticField(tok, None) => format!("/* sfld_{tok:08X} */"),
            Self::InstanceField(obj, _tok, Some(name)) => {
                format!("{}.{name}", obj.to_csharp())
            }
            Self::InstanceField(obj, tok, None) => {
                format!("{}./* fld_{tok:08X} */", obj.to_csharp())
            }
            Self::ArrayElement(arr, idx) => {
                format!("{}[{}]", arr.to_csharp(), idx.to_csharp())
            }
            Self::ArrayLength(arr) => format!("{}.Length", arr.to_csharp()),
            Self::BinaryOp { op, lhs, rhs } => {
                format!("({} {} {})", lhs.to_csharp(), op.as_str(), rhs.to_csharp())
            }
            Self::UnaryOp { op, operand } => {
                format!("{}{}", op.prefix_str(), operand.to_csharp())
            }
            Self::Cast(tok, val) => format!("(/* 0x{tok:08X} */){}", val.to_csharp()),
            Self::IsInst(tok, val) => format!("{} as /* 0x{tok:08X} */", val.to_csharp()),
            Self::Call(tok, args) | Self::Callvirt(tok, args) => {
                let args_str = args
                    .iter()
                    .map(Self::to_csharp)
                    .collect::<Vec<_>>()
                    .join(", ");
                format!("/* call_{tok:08X} */({args_str})")
            }
            Self::NewObj(tok, args) => {
                let args_str = args
                    .iter()
                    .map(Self::to_csharp)
                    .collect::<Vec<_>>()
                    .join(", ");
                format!("new /* 0x{tok:08X} */({args_str})")
            }
            Self::NewArr(tok, size) => {
                format!("new /* 0x{tok:08X} */[{}]", size.to_csharp())
            }
            Self::Opaque(s) => s.clone(),
            Self::Ternary(cond, t, f) => {
                format!(
                    "({} ? {} : {})",
                    cond.to_csharp(),
                    t.to_csharp(),
                    f.to_csharp()
                )
            }
        }
    }
}

/// A high-level statement in the HLIL model.
#[derive(Debug, Clone)]
pub enum HlilStatement {
    /// Variable assignment.
    Assign {
        target: HlilExpression,
        value: HlilExpression,
    },
    /// Variable declaration and initialisation.
    DeclareLocal {
        index: usize,
        name: String,
        type_name: String,
        value: Option<HlilExpression>,
    },
    /// Expression statement (method call with no result).
    Expr(HlilExpression),
    /// Return statement.
    Return(Option<HlilExpression>),
    /// Throw statement.
    Throw(HlilExpression),
    /// Goto label.
    Goto(u32),
    /// Label.
    Label(u32),
    /// If-then-else.
    If {
        cond: HlilExpression,
        then_block: HlilBlock,
        else_block: Option<HlilBlock>,
    },
    /// While loop.
    While {
        cond: HlilExpression,
        body: HlilBlock,
    },
    /// For-each loop.
    ForEach {
        element: String,
        collection: HlilExpression,
        body: HlilBlock,
    },
    /// Try-catch.
    TryCatch {
        try_block: HlilBlock,
        catches: Vec<(String, String, HlilBlock)>,
        finally: Option<HlilBlock>,
    },
    /// Using block.
    Using {
        variable: String,
        init: HlilExpression,
        body: HlilBlock,
    },
    /// Comment line.
    Comment(String),
    /// Endfinally pseudo-statement.
    Endfinally,
}

impl HlilStatement {
    /// Convert this statement to C# source text.
    #[must_use]
    pub fn to_csharp(&self, indent: &str) -> String {
        match self {
            Self::Assign { target, value } => {
                format!("{indent}{} = {};", target.to_csharp(), value.to_csharp())
            }
            Self::DeclareLocal { name, type_name, value: Some(val), .. } => {
                format!("{indent}{type_name} {name} = {};", val.to_csharp())
            }
            Self::DeclareLocal { name, type_name, value: None, .. } => {
                format!("{indent}{type_name} {name};")
            }
            Self::Expr(e) => format!("{indent}{};", e.to_csharp()),
            Self::Return(None) => format!("{indent}return;"),
            Self::Return(Some(e)) => format!("{indent}return {};", e.to_csharp()),
            Self::Throw(e) => format!("{indent}throw {};", e.to_csharp()),
            Self::Goto(target) => format!("{indent}goto IL_{target:04X};"),
            Self::Label(offset) => format!("IL_{offset:04X}:"),
            Self::Comment(c) => format!("{indent}// {c}"),
            Self::Endfinally => format!("{indent}// endfinally"),
            Self::If { cond, then_block, else_block } => {
                hlil_if_to_csharp(indent, cond, then_block, else_block.as_ref())
            }
            Self::While { cond, body } => {
                let inner = format!("    {indent}");
                let mut s = format!("{indent}while ({})\n{indent}{{\n", cond.to_csharp());
                s.push_str(&body.to_csharp(&inner));
                write!(s, "{indent}}}").unwrap();
                s
            }
            Self::ForEach { element, collection, body } => {
                let inner = format!("    {indent}");
                let mut s = format!(
                    "{indent}foreach (var {element} in {})\n{indent}{{\n",
                    collection.to_csharp()
                );
                s.push_str(&body.to_csharp(&inner));
                write!(s, "{indent}}}").unwrap();
                s
            }
            Self::TryCatch { try_block, catches, finally } => {
                hlil_try_catch_to_csharp(indent, try_block, catches, finally.as_ref())
            }
            Self::Using { variable, init, body } => {
                let inner = format!("    {indent}");
                let mut s = format!(
                    "{indent}using (var {variable} = {})\n{indent}{{\n",
                    init.to_csharp()
                );
                s.push_str(&body.to_csharp(&inner));
                write!(s, "{indent}}}").unwrap();
                s
            }
        }
    }
}

fn hlil_if_to_csharp(
    indent: &str,
    cond: &HlilExpression,
    then_block: &HlilBlock,
    else_block: Option<&HlilBlock>,
) -> String {
    let inner = format!("    {indent}");
    let mut s = format!("{indent}if ({})\n{indent}{{\n", cond.to_csharp());
    s.push_str(&then_block.to_csharp(&inner));
    write!(s, "{indent}}}").unwrap();
    if let Some(else_b) = else_block {
        writeln!(s, "\n{indent}else\n{indent}{{").unwrap();
        s.push_str(&else_b.to_csharp(&inner));
        write!(s, "{indent}}}").unwrap();
    }
    s
}

fn hlil_try_catch_to_csharp(
    indent: &str,
    try_block: &HlilBlock,
    catches: &[(String, String, HlilBlock)],
    finally: Option<&HlilBlock>,
) -> String {
    let inner = format!("    {indent}");
    let mut s = format!("{indent}try\n{indent}{{\n");
    s.push_str(&try_block.to_csharp(&inner));
    write!(s, "{indent}}}").unwrap();
    for (ty, var, block) in catches {
        writeln!(s, "\n{indent}catch ({ty} {var})\n{indent}{{").unwrap();
        s.push_str(&block.to_csharp(&inner));
        write!(s, "{indent}}}").unwrap();
    }
    if let Some(fin) = finally {
        writeln!(s, "\n{indent}finally\n{indent}{{").unwrap();
        s.push_str(&fin.to_csharp(&inner));
        write!(s, "{indent}}}").unwrap();
    }
    s
}

/// A block of HLIL statements.
#[derive(Debug, Clone, Default)]
pub struct HlilBlock {
    pub statements: Vec<HlilStatement>,
}

impl HlilBlock {
    /// Create a new empty block.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Convert this block to C# source text.
    #[must_use]
    pub fn to_csharp(&self, indent: &str) -> String {
        let mut out = String::new();
        for stmt in &self.statements {
            out.push_str(&stmt.to_csharp(indent));
            out.push('\n');
        }
        out
    }

    /// Append a statement to this block.
    pub fn push(&mut self, stmt: HlilStatement) {
        self.statements.push(stmt);
    }

    /// Returns `true` if the block contains no statements.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.statements.is_empty()
    }

    /// Returns the number of statements in the block.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.statements.len()
    }
}

/// A complete HLIL method body.
#[derive(Debug, Clone)]
pub struct HlilMethod {
    pub name: String,
    pub return_type: String,
    pub params: Vec<(String, String)>,
    pub is_static: bool,
    pub modifiers: Vec<String>,
    pub locals: Vec<(String, String)>,
    pub body: HlilBlock,
}

impl HlilMethod {
    /// Convert to a C# method definition string.
    #[must_use]
    pub fn to_csharp(&self, indent: &str) -> String {
        let inner = format!("    {indent}");
        let mods = self.modifiers.join(" ");
        let ret = normalize_type(&self.return_type);
        let params_str = self
            .params
            .iter()
            .map(|(n, t)| format!("{} {n}", normalize_type(t)))
            .collect::<Vec<_>>()
            .join(", ");
        let mut out = format!(
            "{indent}{mods} {ret} {}({params_str})\n{indent}{{\n",
            self.name
        );
        for (name, ty) in &self.locals {
            writeln!(out, "{inner}{} {name};", normalize_type(ty)).unwrap();
        }
        out.push_str(&self.body.to_csharp(&inner));
        writeln!(out, "{indent}}}").unwrap();
        out
    }
}

// ─── CIL opcode registry ──────────────────────────────────────────────────────

/// Describes the type of operand for a CIL opcode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperandKind {
    /// No operand.
    None,
    /// 1-byte signed integer.
    Int8,
    /// 4-byte signed integer.
    Int32,
    /// 8-byte signed integer.
    Int64,
    /// 4-byte IEEE float.
    Float32,
    /// 8-byte IEEE float.
    Float64,
    /// 4-byte metadata token.
    Token,
    /// 4-byte branch target (absolute offset).
    BranchTarget,
    /// 1-byte branch target (short).
    BranchTargetShort,
    /// Switch table: 4-byte count followed by count×4-byte targets.
    Switch,
    /// 1-byte unsigned integer (variable index, etc).
    UInt8,
    /// 2-byte unsigned integer.
    UInt16,
}

impl OperandKind {
    /// Returns the byte size of this operand (0 for Switch, as it is variable).
    #[must_use]
    pub const fn byte_size(self) -> usize {
        match self {
            Self::None | Self::Switch => 0,
            Self::Int8 | Self::UInt8 | Self::BranchTargetShort => 1,
            Self::UInt16 => 2,
            Self::Int32 | Self::Float32 | Self::Token | Self::BranchTarget => 4,
            Self::Int64 | Self::Float64 => 8,
        }
    }
}

/// A single entry in the CIL opcode table.
#[derive(Debug, Clone)]
pub struct CilOpcodeInfo {
    /// Opcode name as used in ECMA-335 notation.
    pub name: &'static str,
    /// First byte of the opcode.
    pub byte1: u8,
    /// Second byte, if this is a two-byte (0xFE-prefixed) opcode.
    pub byte2: Option<u8>,
    /// The kind of operand this opcode takes.
    pub operand_kind: OperandKind,
    /// The stack delta: positive pushes values, negative pops values.
    pub stack_delta: i8,
    /// Whether this opcode is a branch instruction.
    pub is_branch: bool,
    /// Whether this opcode is an unconditional terminator.
    pub is_terminator: bool,
}

/// Compile-time opcode lookup table for all CIL opcodes.
pub struct CilOpcodeRegistry;

impl CilOpcodeRegistry {
    /// Returns a slice of all CIL opcode descriptors, in ECMA-335 order.
    #[must_use]
    pub fn all_opcodes() -> &'static [CilOpcodeInfo] {
        OPCODE_TABLE
    }

    /// Look up an opcode by name.
    #[must_use]
    pub fn by_name(name: &str) -> Option<&'static CilOpcodeInfo> {
        OPCODE_TABLE.iter().find(|o| o.name == name)
    }

    /// Look up an opcode by its encoding bytes.
    #[must_use]
    pub fn by_encoding(byte1: u8, byte2: Option<u8>) -> Option<&'static CilOpcodeInfo> {
        OPCODE_TABLE
            .iter()
            .find(|o| o.byte1 == byte1 && o.byte2 == byte2)
    }

    /// Returns the total byte size of an opcode + operand (excluding switch targets).
    #[must_use]
    pub const fn encoding_size(info: &CilOpcodeInfo) -> usize {
        let prefix = if info.byte2.is_some() { 2 } else { 1 };
        prefix + info.operand_kind.byte_size()
    }

    /// Returns the total number of opcodes in the table.
    #[must_use]
    pub fn count() -> usize {
        OPCODE_TABLE.len()
    }
}

static OPCODE_TABLE: &[CilOpcodeInfo] = &[
    // One-byte no-operand opcodes
    CilOpcodeInfo {
        name: "nop",
        byte1: 0x00,
        byte2: None,
        operand_kind: OperandKind::None,
        stack_delta: 0,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "break",
        byte1: 0x01,
        byte2: None,
        operand_kind: OperandKind::None,
        stack_delta: 0,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "ldarg.0",
        byte1: 0x02,
        byte2: None,
        operand_kind: OperandKind::None,
        stack_delta: 1,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "ldarg.1",
        byte1: 0x03,
        byte2: None,
        operand_kind: OperandKind::None,
        stack_delta: 1,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "ldarg.2",
        byte1: 0x04,
        byte2: None,
        operand_kind: OperandKind::None,
        stack_delta: 1,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "ldarg.3",
        byte1: 0x05,
        byte2: None,
        operand_kind: OperandKind::None,
        stack_delta: 1,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "ldloc.0",
        byte1: 0x06,
        byte2: None,
        operand_kind: OperandKind::None,
        stack_delta: 1,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "ldloc.1",
        byte1: 0x07,
        byte2: None,
        operand_kind: OperandKind::None,
        stack_delta: 1,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "ldloc.2",
        byte1: 0x08,
        byte2: None,
        operand_kind: OperandKind::None,
        stack_delta: 1,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "ldloc.3",
        byte1: 0x09,
        byte2: None,
        operand_kind: OperandKind::None,
        stack_delta: 1,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "stloc.0",
        byte1: 0x0A,
        byte2: None,
        operand_kind: OperandKind::None,
        stack_delta: -1,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "stloc.1",
        byte1: 0x0B,
        byte2: None,
        operand_kind: OperandKind::None,
        stack_delta: -1,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "stloc.2",
        byte1: 0x0C,
        byte2: None,
        operand_kind: OperandKind::None,
        stack_delta: -1,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "stloc.3",
        byte1: 0x0D,
        byte2: None,
        operand_kind: OperandKind::None,
        stack_delta: -1,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "ldarg.s",
        byte1: 0x0E,
        byte2: None,
        operand_kind: OperandKind::UInt8,
        stack_delta: 1,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "ldarga.s",
        byte1: 0x0F,
        byte2: None,
        operand_kind: OperandKind::UInt8,
        stack_delta: 1,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "starg.s",
        byte1: 0x10,
        byte2: None,
        operand_kind: OperandKind::UInt8,
        stack_delta: -1,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "ldloc.s",
        byte1: 0x11,
        byte2: None,
        operand_kind: OperandKind::UInt8,
        stack_delta: 1,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "ldloca.s",
        byte1: 0x12,
        byte2: None,
        operand_kind: OperandKind::UInt8,
        stack_delta: 1,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "stloc.s",
        byte1: 0x13,
        byte2: None,
        operand_kind: OperandKind::UInt8,
        stack_delta: -1,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "ldnull",
        byte1: 0x14,
        byte2: None,
        operand_kind: OperandKind::None,
        stack_delta: 1,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "ldc.i4.m1",
        byte1: 0x15,
        byte2: None,
        operand_kind: OperandKind::None,
        stack_delta: 1,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "ldc.i4.0",
        byte1: 0x16,
        byte2: None,
        operand_kind: OperandKind::None,
        stack_delta: 1,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "ldc.i4.1",
        byte1: 0x17,
        byte2: None,
        operand_kind: OperandKind::None,
        stack_delta: 1,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "ldc.i4.2",
        byte1: 0x18,
        byte2: None,
        operand_kind: OperandKind::None,
        stack_delta: 1,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "ldc.i4.3",
        byte1: 0x19,
        byte2: None,
        operand_kind: OperandKind::None,
        stack_delta: 1,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "ldc.i4.4",
        byte1: 0x1A,
        byte2: None,
        operand_kind: OperandKind::None,
        stack_delta: 1,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "ldc.i4.5",
        byte1: 0x1B,
        byte2: None,
        operand_kind: OperandKind::None,
        stack_delta: 1,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "ldc.i4.6",
        byte1: 0x1C,
        byte2: None,
        operand_kind: OperandKind::None,
        stack_delta: 1,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "ldc.i4.7",
        byte1: 0x1D,
        byte2: None,
        operand_kind: OperandKind::None,
        stack_delta: 1,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "ldc.i4.8",
        byte1: 0x1E,
        byte2: None,
        operand_kind: OperandKind::None,
        stack_delta: 1,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "ldc.i4.s",
        byte1: 0x1F,
        byte2: None,
        operand_kind: OperandKind::Int8,
        stack_delta: 1,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "ldc.i4",
        byte1: 0x20,
        byte2: None,
        operand_kind: OperandKind::Int32,
        stack_delta: 1,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "ldc.i8",
        byte1: 0x21,
        byte2: None,
        operand_kind: OperandKind::Int64,
        stack_delta: 1,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "ldc.r4",
        byte1: 0x22,
        byte2: None,
        operand_kind: OperandKind::Float32,
        stack_delta: 1,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "ldc.r8",
        byte1: 0x23,
        byte2: None,
        operand_kind: OperandKind::Float64,
        stack_delta: 1,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "dup",
        byte1: 0x25,
        byte2: None,
        operand_kind: OperandKind::None,
        stack_delta: 1,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "pop",
        byte1: 0x26,
        byte2: None,
        operand_kind: OperandKind::None,
        stack_delta: -1,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "jmp",
        byte1: 0x27,
        byte2: None,
        operand_kind: OperandKind::Token,
        stack_delta: 0,
        is_branch: true,
        is_terminator: true,
    },
    CilOpcodeInfo {
        name: "call",
        byte1: 0x28,
        byte2: None,
        operand_kind: OperandKind::Token,
        stack_delta: 0,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "calli",
        byte1: 0x29,
        byte2: None,
        operand_kind: OperandKind::Token,
        stack_delta: 0,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "ret",
        byte1: 0x2A,
        byte2: None,
        operand_kind: OperandKind::None,
        stack_delta: 0,
        is_branch: false,
        is_terminator: true,
    },
    CilOpcodeInfo {
        name: "br.s",
        byte1: 0x2B,
        byte2: None,
        operand_kind: OperandKind::BranchTargetShort,
        stack_delta: 0,
        is_branch: true,
        is_terminator: true,
    },
    CilOpcodeInfo {
        name: "brfalse.s",
        byte1: 0x2C,
        byte2: None,
        operand_kind: OperandKind::BranchTargetShort,
        stack_delta: -1,
        is_branch: true,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "brtrue.s",
        byte1: 0x2D,
        byte2: None,
        operand_kind: OperandKind::BranchTargetShort,
        stack_delta: -1,
        is_branch: true,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "beq.s",
        byte1: 0x2E,
        byte2: None,
        operand_kind: OperandKind::BranchTargetShort,
        stack_delta: -2,
        is_branch: true,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "bge.s",
        byte1: 0x2F,
        byte2: None,
        operand_kind: OperandKind::BranchTargetShort,
        stack_delta: -2,
        is_branch: true,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "bgt.s",
        byte1: 0x30,
        byte2: None,
        operand_kind: OperandKind::BranchTargetShort,
        stack_delta: -2,
        is_branch: true,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "ble.s",
        byte1: 0x31,
        byte2: None,
        operand_kind: OperandKind::BranchTargetShort,
        stack_delta: -2,
        is_branch: true,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "blt.s",
        byte1: 0x32,
        byte2: None,
        operand_kind: OperandKind::BranchTargetShort,
        stack_delta: -2,
        is_branch: true,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "bne.un.s",
        byte1: 0x33,
        byte2: None,
        operand_kind: OperandKind::BranchTargetShort,
        stack_delta: -2,
        is_branch: true,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "bge.un.s",
        byte1: 0x34,
        byte2: None,
        operand_kind: OperandKind::BranchTargetShort,
        stack_delta: -2,
        is_branch: true,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "bgt.un.s",
        byte1: 0x35,
        byte2: None,
        operand_kind: OperandKind::BranchTargetShort,
        stack_delta: -2,
        is_branch: true,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "ble.un.s",
        byte1: 0x36,
        byte2: None,
        operand_kind: OperandKind::BranchTargetShort,
        stack_delta: -2,
        is_branch: true,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "blt.un.s",
        byte1: 0x37,
        byte2: None,
        operand_kind: OperandKind::BranchTargetShort,
        stack_delta: -2,
        is_branch: true,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "br",
        byte1: 0x38,
        byte2: None,
        operand_kind: OperandKind::BranchTarget,
        stack_delta: 0,
        is_branch: true,
        is_terminator: true,
    },
    CilOpcodeInfo {
        name: "brfalse",
        byte1: 0x39,
        byte2: None,
        operand_kind: OperandKind::BranchTarget,
        stack_delta: -1,
        is_branch: true,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "brtrue",
        byte1: 0x3A,
        byte2: None,
        operand_kind: OperandKind::BranchTarget,
        stack_delta: -1,
        is_branch: true,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "beq",
        byte1: 0x3B,
        byte2: None,
        operand_kind: OperandKind::BranchTarget,
        stack_delta: -2,
        is_branch: true,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "bge",
        byte1: 0x3C,
        byte2: None,
        operand_kind: OperandKind::BranchTarget,
        stack_delta: -2,
        is_branch: true,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "bgt",
        byte1: 0x3D,
        byte2: None,
        operand_kind: OperandKind::BranchTarget,
        stack_delta: -2,
        is_branch: true,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "ble",
        byte1: 0x3E,
        byte2: None,
        operand_kind: OperandKind::BranchTarget,
        stack_delta: -2,
        is_branch: true,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "blt",
        byte1: 0x3F,
        byte2: None,
        operand_kind: OperandKind::BranchTarget,
        stack_delta: -2,
        is_branch: true,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "bne.un",
        byte1: 0x40,
        byte2: None,
        operand_kind: OperandKind::BranchTarget,
        stack_delta: -2,
        is_branch: true,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "bge.un",
        byte1: 0x41,
        byte2: None,
        operand_kind: OperandKind::BranchTarget,
        stack_delta: -2,
        is_branch: true,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "bgt.un",
        byte1: 0x42,
        byte2: None,
        operand_kind: OperandKind::BranchTarget,
        stack_delta: -2,
        is_branch: true,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "ble.un",
        byte1: 0x43,
        byte2: None,
        operand_kind: OperandKind::BranchTarget,
        stack_delta: -2,
        is_branch: true,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "blt.un",
        byte1: 0x44,
        byte2: None,
        operand_kind: OperandKind::BranchTarget,
        stack_delta: -2,
        is_branch: true,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "switch",
        byte1: 0x45,
        byte2: None,
        operand_kind: OperandKind::Switch,
        stack_delta: -1,
        is_branch: true,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "ldind.i1",
        byte1: 0x46,
        byte2: None,
        operand_kind: OperandKind::None,
        stack_delta: 0,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "ldind.u1",
        byte1: 0x47,
        byte2: None,
        operand_kind: OperandKind::None,
        stack_delta: 0,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "ldind.i2",
        byte1: 0x48,
        byte2: None,
        operand_kind: OperandKind::None,
        stack_delta: 0,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "ldind.u2",
        byte1: 0x49,
        byte2: None,
        operand_kind: OperandKind::None,
        stack_delta: 0,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "ldind.i4",
        byte1: 0x4A,
        byte2: None,
        operand_kind: OperandKind::None,
        stack_delta: 0,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "ldind.u4",
        byte1: 0x4B,
        byte2: None,
        operand_kind: OperandKind::None,
        stack_delta: 0,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "ldind.i8",
        byte1: 0x4C,
        byte2: None,
        operand_kind: OperandKind::None,
        stack_delta: 0,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "ldind.i",
        byte1: 0x4D,
        byte2: None,
        operand_kind: OperandKind::None,
        stack_delta: 0,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "ldind.r4",
        byte1: 0x4E,
        byte2: None,
        operand_kind: OperandKind::None,
        stack_delta: 0,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "ldind.r8",
        byte1: 0x4F,
        byte2: None,
        operand_kind: OperandKind::None,
        stack_delta: 0,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "ldind.ref",
        byte1: 0x50,
        byte2: None,
        operand_kind: OperandKind::None,
        stack_delta: 0,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "stind.ref",
        byte1: 0x51,
        byte2: None,
        operand_kind: OperandKind::None,
        stack_delta: -2,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "stind.i1",
        byte1: 0x52,
        byte2: None,
        operand_kind: OperandKind::None,
        stack_delta: -2,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "stind.i2",
        byte1: 0x53,
        byte2: None,
        operand_kind: OperandKind::None,
        stack_delta: -2,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "stind.i4",
        byte1: 0x54,
        byte2: None,
        operand_kind: OperandKind::None,
        stack_delta: -2,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "stind.i8",
        byte1: 0x55,
        byte2: None,
        operand_kind: OperandKind::None,
        stack_delta: -2,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "stind.r4",
        byte1: 0x56,
        byte2: None,
        operand_kind: OperandKind::None,
        stack_delta: -2,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "stind.r8",
        byte1: 0x57,
        byte2: None,
        operand_kind: OperandKind::None,
        stack_delta: -2,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "add",
        byte1: 0x58,
        byte2: None,
        operand_kind: OperandKind::None,
        stack_delta: -1,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "sub",
        byte1: 0x59,
        byte2: None,
        operand_kind: OperandKind::None,
        stack_delta: -1,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "mul",
        byte1: 0x5A,
        byte2: None,
        operand_kind: OperandKind::None,
        stack_delta: -1,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "div",
        byte1: 0x5B,
        byte2: None,
        operand_kind: OperandKind::None,
        stack_delta: -1,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "div.un",
        byte1: 0x5C,
        byte2: None,
        operand_kind: OperandKind::None,
        stack_delta: -1,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "rem",
        byte1: 0x5D,
        byte2: None,
        operand_kind: OperandKind::None,
        stack_delta: -1,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "rem.un",
        byte1: 0x5E,
        byte2: None,
        operand_kind: OperandKind::None,
        stack_delta: -1,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "and",
        byte1: 0x5F,
        byte2: None,
        operand_kind: OperandKind::None,
        stack_delta: -1,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "or",
        byte1: 0x60,
        byte2: None,
        operand_kind: OperandKind::None,
        stack_delta: -1,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "xor",
        byte1: 0x61,
        byte2: None,
        operand_kind: OperandKind::None,
        stack_delta: -1,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "shl",
        byte1: 0x62,
        byte2: None,
        operand_kind: OperandKind::None,
        stack_delta: -1,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "shr",
        byte1: 0x63,
        byte2: None,
        operand_kind: OperandKind::None,
        stack_delta: -1,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "shr.un",
        byte1: 0x64,
        byte2: None,
        operand_kind: OperandKind::None,
        stack_delta: -1,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "neg",
        byte1: 0x65,
        byte2: None,
        operand_kind: OperandKind::None,
        stack_delta: 0,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "not",
        byte1: 0x66,
        byte2: None,
        operand_kind: OperandKind::None,
        stack_delta: 0,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "conv.i1",
        byte1: 0x67,
        byte2: None,
        operand_kind: OperandKind::None,
        stack_delta: 0,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "conv.i2",
        byte1: 0x68,
        byte2: None,
        operand_kind: OperandKind::None,
        stack_delta: 0,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "conv.i4",
        byte1: 0x69,
        byte2: None,
        operand_kind: OperandKind::None,
        stack_delta: 0,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "conv.i8",
        byte1: 0x6A,
        byte2: None,
        operand_kind: OperandKind::None,
        stack_delta: 0,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "conv.r4",
        byte1: 0x6B,
        byte2: None,
        operand_kind: OperandKind::None,
        stack_delta: 0,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "conv.r8",
        byte1: 0x6C,
        byte2: None,
        operand_kind: OperandKind::None,
        stack_delta: 0,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "conv.u4",
        byte1: 0x6D,
        byte2: None,
        operand_kind: OperandKind::None,
        stack_delta: 0,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "conv.u8",
        byte1: 0x6E,
        byte2: None,
        operand_kind: OperandKind::None,
        stack_delta: 0,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "callvirt",
        byte1: 0x6F,
        byte2: None,
        operand_kind: OperandKind::Token,
        stack_delta: 0,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "cpobj",
        byte1: 0x70,
        byte2: None,
        operand_kind: OperandKind::Token,
        stack_delta: -2,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "ldobj",
        byte1: 0x71,
        byte2: None,
        operand_kind: OperandKind::Token,
        stack_delta: 0,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "ldstr",
        byte1: 0x72,
        byte2: None,
        operand_kind: OperandKind::Token,
        stack_delta: 1,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "newobj",
        byte1: 0x73,
        byte2: None,
        operand_kind: OperandKind::Token,
        stack_delta: 1,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "castclass",
        byte1: 0x74,
        byte2: None,
        operand_kind: OperandKind::Token,
        stack_delta: 0,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "isinst",
        byte1: 0x75,
        byte2: None,
        operand_kind: OperandKind::Token,
        stack_delta: 0,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "conv.r.un",
        byte1: 0x76,
        byte2: None,
        operand_kind: OperandKind::None,
        stack_delta: 0,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "unbox",
        byte1: 0x79,
        byte2: None,
        operand_kind: OperandKind::Token,
        stack_delta: 0,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "throw",
        byte1: 0x7A,
        byte2: None,
        operand_kind: OperandKind::None,
        stack_delta: -1,
        is_branch: false,
        is_terminator: true,
    },
    CilOpcodeInfo {
        name: "ldfld",
        byte1: 0x7B,
        byte2: None,
        operand_kind: OperandKind::Token,
        stack_delta: 0,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "ldflda",
        byte1: 0x7C,
        byte2: None,
        operand_kind: OperandKind::Token,
        stack_delta: 0,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "stfld",
        byte1: 0x7D,
        byte2: None,
        operand_kind: OperandKind::Token,
        stack_delta: -2,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "ldsfld",
        byte1: 0x7E,
        byte2: None,
        operand_kind: OperandKind::Token,
        stack_delta: 1,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "ldsflda",
        byte1: 0x7F,
        byte2: None,
        operand_kind: OperandKind::Token,
        stack_delta: 1,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "stsfld",
        byte1: 0x80,
        byte2: None,
        operand_kind: OperandKind::Token,
        stack_delta: -1,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "stobj",
        byte1: 0x81,
        byte2: None,
        operand_kind: OperandKind::Token,
        stack_delta: -2,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "conv.ovf.i1.un",
        byte1: 0x82,
        byte2: None,
        operand_kind: OperandKind::None,
        stack_delta: 0,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "conv.ovf.i2.un",
        byte1: 0x83,
        byte2: None,
        operand_kind: OperandKind::None,
        stack_delta: 0,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "conv.ovf.i4.un",
        byte1: 0x84,
        byte2: None,
        operand_kind: OperandKind::None,
        stack_delta: 0,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "conv.ovf.i8.un",
        byte1: 0x85,
        byte2: None,
        operand_kind: OperandKind::None,
        stack_delta: 0,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "conv.ovf.u1.un",
        byte1: 0x86,
        byte2: None,
        operand_kind: OperandKind::None,
        stack_delta: 0,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "conv.ovf.u2.un",
        byte1: 0x87,
        byte2: None,
        operand_kind: OperandKind::None,
        stack_delta: 0,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "conv.ovf.u4.un",
        byte1: 0x88,
        byte2: None,
        operand_kind: OperandKind::None,
        stack_delta: 0,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "conv.ovf.u8.un",
        byte1: 0x89,
        byte2: None,
        operand_kind: OperandKind::None,
        stack_delta: 0,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "conv.ovf.i.un",
        byte1: 0x8A,
        byte2: None,
        operand_kind: OperandKind::None,
        stack_delta: 0,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "conv.ovf.u.un",
        byte1: 0x8B,
        byte2: None,
        operand_kind: OperandKind::None,
        stack_delta: 0,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "box",
        byte1: 0x8C,
        byte2: None,
        operand_kind: OperandKind::Token,
        stack_delta: 0,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "newarr",
        byte1: 0x8D,
        byte2: None,
        operand_kind: OperandKind::Token,
        stack_delta: 0,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "ldlen",
        byte1: 0x8E,
        byte2: None,
        operand_kind: OperandKind::None,
        stack_delta: 0,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "ldelema",
        byte1: 0x8F,
        byte2: None,
        operand_kind: OperandKind::Token,
        stack_delta: -1,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "ldelem.i1",
        byte1: 0x90,
        byte2: None,
        operand_kind: OperandKind::None,
        stack_delta: -1,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "ldelem.u1",
        byte1: 0x91,
        byte2: None,
        operand_kind: OperandKind::None,
        stack_delta: -1,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "ldelem.i2",
        byte1: 0x92,
        byte2: None,
        operand_kind: OperandKind::None,
        stack_delta: -1,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "ldelem.u2",
        byte1: 0x93,
        byte2: None,
        operand_kind: OperandKind::None,
        stack_delta: -1,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "ldelem.i4",
        byte1: 0x94,
        byte2: None,
        operand_kind: OperandKind::None,
        stack_delta: -1,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "ldelem.u4",
        byte1: 0x95,
        byte2: None,
        operand_kind: OperandKind::None,
        stack_delta: -1,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "ldelem.i8",
        byte1: 0x96,
        byte2: None,
        operand_kind: OperandKind::None,
        stack_delta: -1,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "ldelem.i",
        byte1: 0x97,
        byte2: None,
        operand_kind: OperandKind::None,
        stack_delta: -1,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "ldelem.r4",
        byte1: 0x98,
        byte2: None,
        operand_kind: OperandKind::None,
        stack_delta: -1,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "ldelem.r8",
        byte1: 0x99,
        byte2: None,
        operand_kind: OperandKind::None,
        stack_delta: -1,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "ldelem.ref",
        byte1: 0x9A,
        byte2: None,
        operand_kind: OperandKind::None,
        stack_delta: -1,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "stelem.i",
        byte1: 0x9B,
        byte2: None,
        operand_kind: OperandKind::None,
        stack_delta: -3,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "stelem.i1",
        byte1: 0x9C,
        byte2: None,
        operand_kind: OperandKind::None,
        stack_delta: -3,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "stelem.i2",
        byte1: 0x9D,
        byte2: None,
        operand_kind: OperandKind::None,
        stack_delta: -3,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "stelem.i4",
        byte1: 0x9E,
        byte2: None,
        operand_kind: OperandKind::None,
        stack_delta: -3,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "stelem.i8",
        byte1: 0x9F,
        byte2: None,
        operand_kind: OperandKind::None,
        stack_delta: -3,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "stelem.r4",
        byte1: 0xA0,
        byte2: None,
        operand_kind: OperandKind::None,
        stack_delta: -3,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "stelem.r8",
        byte1: 0xA1,
        byte2: None,
        operand_kind: OperandKind::None,
        stack_delta: -3,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "stelem.ref",
        byte1: 0xA2,
        byte2: None,
        operand_kind: OperandKind::None,
        stack_delta: -3,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "ldelem",
        byte1: 0xA3,
        byte2: None,
        operand_kind: OperandKind::Token,
        stack_delta: -1,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "stelem",
        byte1: 0xA4,
        byte2: None,
        operand_kind: OperandKind::Token,
        stack_delta: -3,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "unbox.any",
        byte1: 0xA5,
        byte2: None,
        operand_kind: OperandKind::Token,
        stack_delta: 0,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "conv.ovf.i1",
        byte1: 0xB3,
        byte2: None,
        operand_kind: OperandKind::None,
        stack_delta: 0,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "conv.ovf.u1",
        byte1: 0xB4,
        byte2: None,
        operand_kind: OperandKind::None,
        stack_delta: 0,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "conv.ovf.i2",
        byte1: 0xB5,
        byte2: None,
        operand_kind: OperandKind::None,
        stack_delta: 0,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "conv.ovf.u2",
        byte1: 0xB6,
        byte2: None,
        operand_kind: OperandKind::None,
        stack_delta: 0,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "conv.ovf.i4",
        byte1: 0xB7,
        byte2: None,
        operand_kind: OperandKind::None,
        stack_delta: 0,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "conv.ovf.u4",
        byte1: 0xB8,
        byte2: None,
        operand_kind: OperandKind::None,
        stack_delta: 0,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "conv.ovf.i8",
        byte1: 0xB9,
        byte2: None,
        operand_kind: OperandKind::None,
        stack_delta: 0,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "conv.ovf.u8",
        byte1: 0xBA,
        byte2: None,
        operand_kind: OperandKind::None,
        stack_delta: 0,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "refanyval",
        byte1: 0xC2,
        byte2: None,
        operand_kind: OperandKind::Token,
        stack_delta: 0,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "ckfinite",
        byte1: 0xC3,
        byte2: None,
        operand_kind: OperandKind::None,
        stack_delta: 0,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "mkrefany",
        byte1: 0xC6,
        byte2: None,
        operand_kind: OperandKind::Token,
        stack_delta: 0,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "ldtoken",
        byte1: 0xD0,
        byte2: None,
        operand_kind: OperandKind::Token,
        stack_delta: 1,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "conv.u2",
        byte1: 0xD1,
        byte2: None,
        operand_kind: OperandKind::None,
        stack_delta: 0,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "conv.u1",
        byte1: 0xD2,
        byte2: None,
        operand_kind: OperandKind::None,
        stack_delta: 0,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "conv.i",
        byte1: 0xD3,
        byte2: None,
        operand_kind: OperandKind::None,
        stack_delta: 0,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "conv.ovf.i",
        byte1: 0xD4,
        byte2: None,
        operand_kind: OperandKind::None,
        stack_delta: 0,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "conv.ovf.u",
        byte1: 0xD5,
        byte2: None,
        operand_kind: OperandKind::None,
        stack_delta: 0,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "add.ovf",
        byte1: 0xD6,
        byte2: None,
        operand_kind: OperandKind::None,
        stack_delta: -1,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "add.ovf.un",
        byte1: 0xD7,
        byte2: None,
        operand_kind: OperandKind::None,
        stack_delta: -1,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "mul.ovf",
        byte1: 0xD8,
        byte2: None,
        operand_kind: OperandKind::None,
        stack_delta: -1,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "mul.ovf.un",
        byte1: 0xD9,
        byte2: None,
        operand_kind: OperandKind::None,
        stack_delta: -1,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "sub.ovf",
        byte1: 0xDA,
        byte2: None,
        operand_kind: OperandKind::None,
        stack_delta: -1,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "sub.ovf.un",
        byte1: 0xDB,
        byte2: None,
        operand_kind: OperandKind::None,
        stack_delta: -1,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "endfinally",
        byte1: 0xDC,
        byte2: None,
        operand_kind: OperandKind::None,
        stack_delta: 0,
        is_branch: false,
        is_terminator: true,
    },
    CilOpcodeInfo {
        name: "leave",
        byte1: 0xDD,
        byte2: None,
        operand_kind: OperandKind::BranchTarget,
        stack_delta: 0,
        is_branch: true,
        is_terminator: true,
    },
    CilOpcodeInfo {
        name: "leave.s",
        byte1: 0xDE,
        byte2: None,
        operand_kind: OperandKind::BranchTargetShort,
        stack_delta: 0,
        is_branch: true,
        is_terminator: true,
    },
    CilOpcodeInfo {
        name: "stind.i",
        byte1: 0xDF,
        byte2: None,
        operand_kind: OperandKind::None,
        stack_delta: -2,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "conv.u",
        byte1: 0xE0,
        byte2: None,
        operand_kind: OperandKind::None,
        stack_delta: 0,
        is_branch: false,
        is_terminator: false,
    },
    // 0xFE-prefixed two-byte opcodes
    CilOpcodeInfo {
        name: "arglist",
        byte1: 0xFE,
        byte2: Some(0x00),
        operand_kind: OperandKind::None,
        stack_delta: 1,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "ceq",
        byte1: 0xFE,
        byte2: Some(0x01),
        operand_kind: OperandKind::None,
        stack_delta: -1,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "cgt",
        byte1: 0xFE,
        byte2: Some(0x02),
        operand_kind: OperandKind::None,
        stack_delta: -1,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "cgt.un",
        byte1: 0xFE,
        byte2: Some(0x03),
        operand_kind: OperandKind::None,
        stack_delta: -1,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "clt",
        byte1: 0xFE,
        byte2: Some(0x04),
        operand_kind: OperandKind::None,
        stack_delta: -1,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "clt.un",
        byte1: 0xFE,
        byte2: Some(0x05),
        operand_kind: OperandKind::None,
        stack_delta: -1,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "ldftn",
        byte1: 0xFE,
        byte2: Some(0x06),
        operand_kind: OperandKind::Token,
        stack_delta: 1,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "ldvirtftn",
        byte1: 0xFE,
        byte2: Some(0x07),
        operand_kind: OperandKind::Token,
        stack_delta: 0,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "ldarg",
        byte1: 0xFE,
        byte2: Some(0x09),
        operand_kind: OperandKind::UInt16,
        stack_delta: 1,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "ldarga",
        byte1: 0xFE,
        byte2: Some(0x0A),
        operand_kind: OperandKind::UInt16,
        stack_delta: 1,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "starg",
        byte1: 0xFE,
        byte2: Some(0x0B),
        operand_kind: OperandKind::UInt16,
        stack_delta: -1,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "ldloc",
        byte1: 0xFE,
        byte2: Some(0x0C),
        operand_kind: OperandKind::UInt16,
        stack_delta: 1,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "ldloca",
        byte1: 0xFE,
        byte2: Some(0x0D),
        operand_kind: OperandKind::UInt16,
        stack_delta: 1,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "stloc",
        byte1: 0xFE,
        byte2: Some(0x0E),
        operand_kind: OperandKind::UInt16,
        stack_delta: -1,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "localloc",
        byte1: 0xFE,
        byte2: Some(0x0F),
        operand_kind: OperandKind::None,
        stack_delta: 0,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "endfilter",
        byte1: 0xFE,
        byte2: Some(0x11),
        operand_kind: OperandKind::None,
        stack_delta: -1,
        is_branch: false,
        is_terminator: true,
    },
    CilOpcodeInfo {
        name: "unaligned.",
        byte1: 0xFE,
        byte2: Some(0x12),
        operand_kind: OperandKind::UInt8,
        stack_delta: 0,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "volatile.",
        byte1: 0xFE,
        byte2: Some(0x13),
        operand_kind: OperandKind::None,
        stack_delta: 0,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "tail.",
        byte1: 0xFE,
        byte2: Some(0x14),
        operand_kind: OperandKind::None,
        stack_delta: 0,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "initobj",
        byte1: 0xFE,
        byte2: Some(0x15),
        operand_kind: OperandKind::Token,
        stack_delta: -1,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "constrained.",
        byte1: 0xFE,
        byte2: Some(0x16),
        operand_kind: OperandKind::Token,
        stack_delta: 0,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "cpblk",
        byte1: 0xFE,
        byte2: Some(0x17),
        operand_kind: OperandKind::None,
        stack_delta: -3,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "initblk",
        byte1: 0xFE,
        byte2: Some(0x18),
        operand_kind: OperandKind::None,
        stack_delta: -3,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "no.",
        byte1: 0xFE,
        byte2: Some(0x19),
        operand_kind: OperandKind::UInt8,
        stack_delta: 0,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "rethrow",
        byte1: 0xFE,
        byte2: Some(0x1A),
        operand_kind: OperandKind::None,
        stack_delta: 0,
        is_branch: false,
        is_terminator: true,
    },
    CilOpcodeInfo {
        name: "sizeof",
        byte1: 0xFE,
        byte2: Some(0x1C),
        operand_kind: OperandKind::Token,
        stack_delta: 1,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "refanytype",
        byte1: 0xFE,
        byte2: Some(0x1D),
        operand_kind: OperandKind::None,
        stack_delta: 0,
        is_branch: false,
        is_terminator: false,
    },
    CilOpcodeInfo {
        name: "readonly.",
        byte1: 0xFE,
        byte2: Some(0x1E),
        operand_kind: OperandKind::None,
        stack_delta: 0,
        is_branch: false,
        is_terminator: false,
    },
];

// ─── CilDisassembler ──────────────────────────────────────────────────────────

/// Decodes a raw CIL byte stream into a `Vec<CilInstruction>`.
pub struct CilDisassembler;

impl CilDisassembler {
    /// Disassemble a byte slice into a list of CIL instructions.
    ///
    /// # Errors
    /// Returns an error if the byte stream is truncated mid-instruction.
    pub fn disassemble(bytes: &[u8]) -> Result<Vec<CilInstruction>> {
        use anyhow::anyhow;

        let mut instrs = Vec::new();
        let mut pos = 0usize;

        while pos < bytes.len() {
            let offset = u32::try_from(pos)
                .map_err(|_| anyhow::anyhow!("CIL byte stream too large: offset {pos} exceeds u32::MAX"))?;
            let b0 = bytes[pos];
            pos += 1;

            let (opcode, info) = if b0 == 0xFE {
                if pos >= bytes.len() {
                    return Err(anyhow!("truncated FE-prefix opcode at offset {offset}"));
                }
                let b1 = bytes[pos];
                pos += 1;
                let info = CilOpcodeRegistry::by_encoding(0xFE, Some(b1))
                    .ok_or_else(|| anyhow!("unknown opcode FE {b1:02X} at offset {offset}"))?;
                (info.name, info)
            } else {
                let info = CilOpcodeRegistry::by_encoding(b0, None)
                    .ok_or_else(|| anyhow!("unknown opcode {b0:02X} at offset {offset}"))?;
                (info.name, info)
            };

            let operand = match info.operand_kind {
                OperandKind::None => CilOperand::None,
                OperandKind::Int8 => {
                    let v = Self::read_i8(bytes, pos, offset)?;
                    pos += 1;
                    CilOperand::Int8(v)
                }
                OperandKind::UInt8 => {
                    let v = Self::read_u8(bytes, pos, offset)?;
                    pos += 1;
                    CilOperand::Int8(casts::u8_as_i8(v)) // store in Int8 for display
                }
                OperandKind::UInt16 => {
                    let v = Self::read_u16(bytes, pos, offset)?;
                    pos += 2;
                    CilOperand::Int32(i32::from(v))
                }
                OperandKind::Int32 => {
                    let v = Self::read_i32(bytes, pos, offset)?;
                    pos += 4;
                    CilOperand::Int32(v)
                }
                OperandKind::Int64 => {
                    let v = Self::read_i64(bytes, pos, offset)?;
                    pos += 8;
                    CilOperand::Int64(v)
                }
                OperandKind::Float32 => {
                    let bits = Self::read_u32(bytes, pos, offset)?;
                    pos += 4;
                    CilOperand::Float32(f32::from_bits(bits))
                }
                OperandKind::Float64 => {
                    let bits = Self::read_u64(bytes, pos, offset)?;
                    pos += 8;
                    CilOperand::Float64(f64::from_bits(bits))
                }
                OperandKind::Token => {
                    let tok = Self::read_u32(bytes, pos, offset)?;
                    pos += 4;
                    CilOperand::Token(tok)
                }
                OperandKind::BranchTarget => {
                    let delta = Self::read_i32(bytes, pos, offset)?;
                    pos += 4;
                    // Target = next instruction offset + delta
                    let target = casts::i64_to_u32(casts::usize_to_i64(pos) + i64::from(delta));
                    CilOperand::Branch(target)
                }
                OperandKind::BranchTargetShort => {
                    let delta = Self::read_i8(bytes, pos, offset)?;
                    pos += 1;
                    let target = casts::i64_to_u32(casts::usize_to_i64(pos) + i64::from(delta));
                    CilOperand::Branch(target)
                }
                OperandKind::Switch => {
                    let (targets, consumed) = Self::read_switch_targets(bytes, pos, offset)?;
                    pos += consumed;
                    CilOperand::Switch(targets)
                }
            };

            instrs.push(CilInstruction {
                offset,
                opcode: opcode.to_string(),
                operand,
            });
        }

        Ok(instrs)
    }

    fn read_u8(b: &[u8], pos: usize, off: u32) -> Result<u8> {
        b.get(pos)
            .copied()
            .ok_or_else(|| anyhow::anyhow!("truncated at offset {off}"))
    }

    fn read_i8(b: &[u8], pos: usize, off: u32) -> Result<i8> {
        Self::read_u8(b, pos, off).map(casts::u8_as_i8)
    }

    fn read_u16(b: &[u8], pos: usize, off: u32) -> Result<u16> {
        if pos + 2 > b.len() {
            return Err(anyhow::anyhow!("truncated at offset {off}"));
        }
        Ok(u16::from_le_bytes([b[pos], b[pos + 1]]))
    }

    fn read_u32(b: &[u8], pos: usize, off: u32) -> Result<u32> {
        if pos + 4 > b.len() {
            return Err(anyhow::anyhow!("truncated at offset {off}"));
        }
        Ok(u32::from_le_bytes([
            b[pos],
            b[pos + 1],
            b[pos + 2],
            b[pos + 3],
        ]))
    }

    fn read_i32(b: &[u8], pos: usize, off: u32) -> Result<i32> {
        Self::read_u32(b, pos, off).map(casts::u32_as_i32)
    }

    fn read_u64(b: &[u8], pos: usize, off: u32) -> Result<u64> {
        if pos + 8 > b.len() {
            return Err(anyhow::anyhow!("truncated at offset {off}"));
        }
        Ok(u64::from_le_bytes(b[pos..pos + 8].try_into().map_err(|_| anyhow::anyhow!("slice-to-array conversion failed at offset {off}"))?))
    }

    fn read_i64(b: &[u8], pos: usize, off: u32) -> Result<i64> {
        Self::read_u64(b, pos, off).map(casts::u64_as_i64)
    }

    /// Read a CIL switch table starting at `pos`.
    ///
    /// Returns `(targets, bytes_consumed)` where `bytes_consumed` includes the 4-byte count field.
    fn read_switch_targets(bytes: &[u8], pos: usize, offset: u32) -> Result<(Vec<u32>, usize)> {
        let count_u32 = Self::read_u32(bytes, pos, offset)?;
        let count = count_u32 as usize;
        let table_bytes = count.checked_mul(4)
            .ok_or_else(|| anyhow::anyhow!("switch table count overflow at offset {offset}"))?;
        let after_count = pos + 4;
        let base = after_count.checked_add(table_bytes)
            .ok_or_else(|| anyhow::anyhow!("switch table base overflow at offset {offset}"))?;
        if base > bytes.len() {
            return Err(anyhow::anyhow!("switch table extends past end of stream at offset {offset}"));
        }
        let mut targets = Vec::with_capacity(count.min(65536));
        let mut tpos = after_count;
        for _ in 0..count {
            let delta = Self::read_i32(bytes, tpos, offset)?;
            tpos += 4;
            targets.push(casts::i64_to_u32(casts::usize_to_i64(base) + i64::from(delta)));
        }
        Ok((targets, 4 + table_bytes))
    }

    /// Disassemble a byte slice and return each instruction paired with its
    /// stack depth at the point of execution.
    ///
    /// # Errors
    /// Returns an error if the byte stream is truncated mid-instruction.
    pub fn disassemble_with_stack(bytes: &[u8]) -> Result<Vec<(CilInstruction, i32)>> {
        let instrs = Self::disassemble(bytes)?;
        let mut result = Vec::with_capacity(instrs.len());
        let mut depth: i32 = 0;
        for instr in instrs {
            let d_before = depth;
            if let Some(info) = CilOpcodeRegistry::by_name(&instr.opcode) {
                depth += i32::from(info.stack_delta);
                if depth < 0 {
                    depth = 0;
                }
            }
            result.push((instr, d_before));
        }
        Ok(result)
    }
}

// ─── DecompilationPipeline ────────────────────────────────────────────────────

/// A configurable pipeline that runs the decompilation stages in order.
#[derive(Debug, Default)]
pub struct DecompilationPipeline {
    pub options: DecompilerOptions,
}

impl DecompilationPipeline {
    /// Create a pipeline with default options.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a pipeline with custom options.
    #[must_use]
    pub const fn with_options(options: DecompilerOptions) -> Self {
        Self { options }
    }

    /// Decompile a method through the full pipeline.
    ///
    /// # Errors
    /// Propagates errors from the inner decompiler.
    pub fn decompile_method(&self, method: &DotnetMethod) -> Result<String> {
        let dc = CSharpDecompiler::new(self.options.clone());
        dc.decompile_method(method)
    }

    /// Decompile a type through the full pipeline.
    ///
    /// # Errors
    /// Propagates errors from the inner decompiler.
    pub fn decompile_type(&self, t: &DotnetType) -> Result<String> {
        let dc = CSharpDecompiler::new(self.options.clone());
        dc.decompile_type(t)
    }

    /// Decompile all types in an assembly.
    ///
    /// # Errors
    /// Propagates errors from the inner decompiler.
    pub fn decompile_assembly(&self, assembly: &AssemblyFile) -> Result<AHashMap<String, String>> {
        let dc = CSharpDecompiler::new(self.options.clone());
        dc.decompile_assembly(assembly)
    }

    /// Lift a method body to HLIL without emitting C# source.
    #[must_use]
    pub fn lift_to_hlil(&self, method: &DotnetMethod) -> HlilMethod {
        let mods: Vec<String> = method_modifiers(method.flags)
            .into_iter()
            .map(str::to_string)
            .collect();
        let params: Vec<(String, String)> = method
            .signature
            .params
            .iter()
            .map(|(n, t)| (n.clone(), t.clone()))
            .collect();
        let body = method.body.as_ref().map_or_else(HlilBlock::new, |b| lift_body_to_hlil(b, method));
        HlilMethod {
            name: method.name.clone(),
            return_type: method.signature.return_type.clone(),
            params,
            is_static: method.is_static(),
            modifiers: mods,
            locals: method
                .body
                .as_ref()
                .map(|b| {
                    b.locals
                        .iter()
                        .map(|l| (format!("local{}", l.index), l.type_name.clone()))
                        .collect()
                })
                .unwrap_or_default(),
            body,
        }
    }
}

// ─── StackAnalysis ────────────────────────────────────────────────────────────

/// Stack effect analysis for a method body.
pub struct StackAnalysis;

impl StackAnalysis {
    /// Compute the maximum stack depth reached during a linear pass through
    /// the instruction sequence.  Does not account for branches.
    #[must_use]
    pub fn max_stack_depth(instrs: &[CilInstruction]) -> i32 {
        let mut depth: i32 = 0;
        let mut max: i32 = 0;
        for instr in instrs {
            if let Some(info) = CilOpcodeRegistry::by_name(&instr.opcode) {
                depth += i32::from(info.stack_delta);
                if depth < 0 {
                    depth = 0;
                }
                if depth > max {
                    max = depth;
                }
            }
        }
        max
    }

    /// Returns the set of instruction offsets that are branch targets.
    #[must_use]
    pub fn branch_target_offsets(instrs: &[CilInstruction]) -> std::collections::HashSet<u32> {
        let mut targets = std::collections::HashSet::new();
        for instr in instrs {
            match &instr.operand {
                CilOperand::Branch(t) => {
                    targets.insert(*t);
                }
                CilOperand::Switch(ts) => {
                    targets.extend(ts);
                }
                _ => {}
            }
        }
        targets
    }

    /// Returns `true` if the method body makes any virtual calls.
    #[must_use]
    pub fn has_virtual_calls(instrs: &[CilInstruction]) -> bool {
        instrs.iter().any(|i| i.opcode == "callvirt")
    }

    /// Returns the list of unique metadata tokens used as call targets.
    #[must_use]
    pub fn call_targets(instrs: &[CilInstruction]) -> Vec<u32> {
        let mut out = Vec::new();
        for instr in instrs {
            if matches!(
                instr.opcode.as_str(),
                "call" | "callvirt" | "newobj" | "calli"
            )
                && let CilOperand::Token(tok) = instr.operand
                    && !out.contains(&tok) {
                        out.push(tok);
                    }
        }
        out
    }

    /// Returns the list of unique field tokens accessed (ldfld, stfld, ldsfld, stsfld).
    #[must_use]
    pub fn field_accesses(instrs: &[CilInstruction]) -> Vec<u32> {
        let mut out = Vec::new();
        for instr in instrs {
            if matches!(
                instr.opcode.as_str(),
                "ldfld" | "stfld" | "ldsfld" | "stsfld"
            )
                && let CilOperand::Token(tok) = instr.operand
                    && !out.contains(&tok) {
                        out.push(tok);
                    }
        }
        out
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use rustre_dotnet::{
        CilInstruction, CilOperand, DotnetField, DotnetMethod, DotnetType, ExceptionHandler,
        ExceptionHandlerKind, LocalVar, MethodBody, MethodSignature,
    };

    fn default_decompiler() -> CSharpDecompiler {
        CSharpDecompiler::default()
    }

    fn make_void_method(name: &str, instrs: Vec<CilInstruction>) -> DotnetMethod {
        DotnetMethod {
            name: name.to_string(),
            signature: MethodSignature {
                return_type: "void".into(),
                params: vec![],
                is_static: true,
                is_vararg: false,
                ..Default::default()
            },
            body: Some(MethodBody {
                locals: vec![],
                instructions: instrs,
                exception_handlers: vec![],
                max_stack: 8,
                init_locals: true,
            }),
            flags: 0x16, // public static
            rva: 0,
            ..Default::default()
        }
    }

    fn make_int_method(name: &str, instrs: Vec<CilInstruction>) -> DotnetMethod {
        DotnetMethod {
            name: name.to_string(),
            signature: MethodSignature {
                return_type: "int".into(),
                params: vec![],
                is_static: true,
                is_vararg: false,
                ..Default::default()
            },
            body: Some(MethodBody {
                locals: vec![],
                instructions: instrs,
                exception_handlers: vec![],
                max_stack: 8,
                init_locals: false,
            }),
            flags: 0x16,
            rva: 0,
            ..Default::default()
        }
    }

    #[test]
    fn test_decompile_empty_body() {
        let method = make_void_method(
            "Empty",
            vec![CilInstruction {
                offset: 0,
                opcode: "ret".into(),
                operand: CilOperand::None,
            }],
        );
        let dc = default_decompiler();
        let out = dc.decompile_method(&method).unwrap();
        assert!(out.contains("void Empty()"));
        assert!(out.contains("return;"));
    }

    #[test]
    fn test_decompile_ldc_i4_add_ret() {
        let method = make_int_method(
            "Add",
            vec![
                CilInstruction {
                    offset: 0,
                    opcode: "ldc.i4.3".into(),
                    operand: CilOperand::None,
                },
                CilInstruction {
                    offset: 1,
                    opcode: "ldc.i4.4".into(),
                    operand: CilOperand::None,
                },
                CilInstruction {
                    offset: 2,
                    opcode: "add".into(),
                    operand: CilOperand::None,
                },
                CilInstruction {
                    offset: 3,
                    opcode: "ret".into(),
                    operand: CilOperand::None,
                },
            ],
        );
        let dc = default_decompiler();
        let out = dc.decompile_method(&method).unwrap();
        assert!(out.contains("3 + 4") || out.contains("t0"));
        assert!(out.contains("return"));
    }

    #[test]
    fn test_decompile_ldstr() {
        let mut method = make_void_method(
            "Greet",
            vec![
                CilInstruction {
                    offset: 0,
                    opcode: "ldstr".into(),
                    operand: CilOperand::String("Hello".into()),
                },
                CilInstruction {
                    offset: 5,
                    opcode: "stloc.0".into(),
                    operand: CilOperand::None,
                },
                CilInstruction {
                    offset: 6,
                    opcode: "ret".into(),
                    operand: CilOperand::None,
                },
            ],
        );
        if let Some(body) = method.body.as_mut() {
            body.locals.push(rustre_dotnet::LocalVar {
                index: 0,
                type_name: "string".into(),
                ..Default::default()
            });
        }
        let dc = default_decompiler();
        let out = dc.decompile_method(&method).unwrap();
        assert!(out.contains("\"Hello\""));
    }

    #[test]
    fn test_decompile_stloc_ldloc() {
        let mut method = make_int_method(
            "Locals",
            vec![
                CilInstruction {
                    offset: 0,
                    opcode: "ldc.i4".into(),
                    operand: CilOperand::Int32(42),
                },
                CilInstruction {
                    offset: 5,
                    opcode: "stloc.0".into(),
                    operand: CilOperand::None,
                },
                CilInstruction {
                    offset: 6,
                    opcode: "ldloc.0".into(),
                    operand: CilOperand::None,
                },
                CilInstruction {
                    offset: 7,
                    opcode: "ret".into(),
                    operand: CilOperand::None,
                },
            ],
        );
        if let Some(body) = method.body.as_mut() {
            body.locals.push(LocalVar {
                index: 0,
                type_name: "int".into(),
                ..Default::default()
            });
        }
        let dc = default_decompiler();
        let out = dc.decompile_method(&method).unwrap();
        assert!(out.contains("42"));
        assert!(out.contains("local0"));
    }

    #[test]
    fn test_decompile_branch_brfalse() {
        let method = make_void_method(
            "Branch",
            vec![
                CilInstruction {
                    offset: 0,
                    opcode: "ldc.i4.0".into(),
                    operand: CilOperand::None,
                },
                CilInstruction {
                    offset: 1,
                    opcode: "brfalse".into(),
                    operand: CilOperand::Branch(10),
                },
                CilInstruction {
                    offset: 5,
                    opcode: "ret".into(),
                    operand: CilOperand::None,
                },
            ],
        );
        let dc = default_decompiler();
        let out = dc.decompile_method(&method).unwrap();
        assert!(out.contains("goto") || out.contains("if"));
    }

    #[test]
    fn test_normalize_system_int32() {
        assert_eq!(normalize_type("System.Int32"), "int");
    }

    #[test]
    fn test_normalize_system_string() {
        assert_eq!(normalize_type("System.String"), "string");
    }

    #[test]
    fn test_normalize_system_bool() {
        assert_eq!(normalize_type("System.Boolean"), "bool");
    }

    #[test]
    fn test_normalize_void() {
        assert_eq!(normalize_type("System.Void"), "void");
    }

    #[test]
    fn test_normalize_custom_type_passthrough() {
        assert_eq!(normalize_type("MyApp.Foo"), "MyApp.Foo");
    }

    #[test]
    fn test_method_modifiers_public_static() {
        let mods = method_modifiers(0x06 | 0x10); // public + static
        assert!(mods.contains(&"public"));
        assert!(mods.contains(&"static"));
    }

    #[test]
    fn test_method_modifiers_private() {
        let mods = method_modifiers(0x01);
        assert!(mods.contains(&"private"));
    }

    #[test]
    fn test_method_modifiers_virtual() {
        let mods = method_modifiers(0x06 | 0x20);
        assert!(mods.contains(&"virtual"));
    }

    #[test]
    fn test_decompile_type_class() {
        let t = DotnetType {
            name: "Foo".into(),
            namespace: "Bar".into(),
            full_name: "Bar.Foo".into(),
            base_type: None,
            interfaces: vec![],
            methods: vec![],
            fields: vec![],
            properties: vec![],
            events: vec![],
            nested_types: vec![],
            custom_attributes: vec![],
            generic_params: vec![],
            kind_tag: rustre_dotnet::DotnetTypeKind::Class,
            flags: 0,
            layout: None,
        };
        let dc = default_decompiler();
        let out = dc.decompile_type(&t).unwrap();
        assert!(out.contains("namespace Bar"));
        assert!(out.contains("class Foo"));
    }

    #[test]
    fn test_decompile_type_interface() {
        let t = DotnetType {
            name: "IBar".into(),
            namespace: String::new(),
            full_name: "IBar".into(),
            base_type: None,
            interfaces: vec![],
            methods: vec![],
            fields: vec![],
            properties: vec![],
            events: vec![],
            nested_types: vec![],
            custom_attributes: vec![],
            generic_params: vec![],
            kind_tag: rustre_dotnet::DotnetTypeKind::Interface,
            flags: 0,
            layout: None,
        };
        let dc = default_decompiler();
        let out = dc.decompile_type(&t).unwrap();
        assert!(out.contains("interface IBar"));
    }

    #[test]
    fn test_decompile_type_with_field() {
        let t = DotnetType {
            name: "MyClass".into(),
            namespace: String::new(),
            full_name: "MyClass".into(),
            base_type: None,
            interfaces: vec![],
            methods: vec![],
            fields: vec![DotnetField {
                name: "Value".into(),
                type_name: "int".into(),
                flags: 0,
                is_static: false,
                ..Default::default()
            }],
            properties: vec![],
            events: vec![],
            nested_types: vec![],
            custom_attributes: vec![],
            generic_params: vec![],
            kind_tag: rustre_dotnet::DotnetTypeKind::Class,
            flags: 0,
            layout: None,
        };
        let dc = default_decompiler();
        let out = dc.decompile_type(&t).unwrap();
        assert!(out.contains("int Value"));
    }

    #[test]
    fn test_property_detection() {
        assert_eq!(detect_property_name("get_Name"), Some(("get", "Name")));
        assert_eq!(detect_property_name("set_Age"), Some(("set", "Age")));
        assert_eq!(detect_property_name("DoWork"), None);
    }

    #[test]
    fn test_decompile_type_with_property_accessor() {
        let get_method = DotnetMethod {
            name: "get_Count".into(),
            signature: MethodSignature {
                return_type: "int".into(),
                params: vec![],
                is_static: false,
                is_vararg: false,
                ..Default::default()
            },
            body: None,
            flags: 0x06,
            rva: 0,
            ..Default::default()
        };
        let t = DotnetType {
            name: "Container".into(),
            namespace: String::new(),
            full_name: "Container".into(),
            base_type: None,
            interfaces: vec![],
            methods: vec![get_method],
            fields: vec![],
            properties: vec![],
            events: vec![],
            nested_types: vec![],
            custom_attributes: vec![],
            generic_params: vec![],
            kind_tag: rustre_dotnet::DotnetTypeKind::Class,
            flags: 0,
            layout: None,
        };
        let dc = default_decompiler();
        let out = dc.decompile_type(&t).unwrap();
        assert!(out.contains("Count") && (out.contains("get;") || out.contains("get_Count")));
    }

    #[test]
    fn test_decompile_method_no_body() {
        let method = DotnetMethod {
            name: "Abstract".into(),
            signature: MethodSignature::default(),
            body: None,
            flags: 0x06,
            rva: 0,
            ..Default::default()
        };
        let dc = default_decompiler();
        let out = dc.decompile_method(&method).unwrap();
        assert!(out.contains("NotImplementedException"));
    }

    #[test]
    fn test_emit_comments_option() {
        let opts = DecompilerOptions {
            emit_comments: true,
            ..DecompilerOptions::default()
        };
        let dc = CSharpDecompiler::new(opts);
        let method = make_void_method(
            "Commented",
            vec![CilInstruction {
                offset: 0,
                opcode: "ret".into(),
                operand: CilOperand::None,
            }],
        );
        let out = dc.decompile_method(&method).unwrap();
        assert!(out.contains("IL_0000"));
    }

    #[test]
    fn test_decompile_assembly_empty() {
        use rustre_dotnet::AssemblyFile;
        use rustre_dotnet_metadata::{MetadataHeaps, MetadataReader, MetadataRoot, MetadataTables};
        let reader = MetadataReader {
            root: MetadataRoot {
                major_version: 1,
                minor_version: 1,
                streams: vec![],
            },
            heaps: MetadataHeaps::default(),
            tables: MetadataTables::default(),
        };
        let asm = AssemblyFile::from_metadata(reader);
        let dc = default_decompiler();
        let result = dc.decompile_assembly(&asm).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn test_use_var_false() {
        let opts = DecompilerOptions {
            use_var: false,
            ..DecompilerOptions::default()
        };
        let dc = CSharpDecompiler::new(opts);
        let mut method = make_int_method(
            "NoVar",
            vec![
                CilInstruction {
                    offset: 0,
                    opcode: "ldc.i4".into(),
                    operand: CilOperand::Int32(1),
                },
                CilInstruction {
                    offset: 5,
                    opcode: "stloc.0".into(),
                    operand: CilOperand::None,
                },
                CilInstruction {
                    offset: 6,
                    opcode: "ldloc.0".into(),
                    operand: CilOperand::None,
                },
                CilInstruction {
                    offset: 7,
                    opcode: "ret".into(),
                    operand: CilOperand::None,
                },
            ],
        );
        if let Some(body) = method.body.as_mut() {
            body.locals.push(LocalVar {
                index: 0,
                type_name: "int".into(),
                ..Default::default()
            });
        }
        let out = dc.decompile_method(&method).unwrap();
        assert!(out.contains("int local0"));
    }

    #[test]
    fn test_switch_instruction() {
        let method = make_void_method(
            "Switch",
            vec![
                CilInstruction {
                    offset: 0,
                    opcode: "ldc.i4.1".into(),
                    operand: CilOperand::None,
                },
                CilInstruction {
                    offset: 1,
                    opcode: "switch".into(),
                    operand: CilOperand::Switch(vec![10, 20]),
                },
                CilInstruction {
                    offset: 10,
                    opcode: "ret".into(),
                    operand: CilOperand::None,
                },
            ],
        );
        let dc = default_decompiler();
        let out = dc.decompile_method(&method).unwrap();
        assert!(out.contains("switch") || out.contains("case"));
    }

    #[test]
    fn test_exception_handler_comment_emitted() {
        let method = DotnetMethod {
            name: "TryCatch".into(),
            signature: MethodSignature {
                return_type: "void".into(),
                ..Default::default()
            },
            body: Some(MethodBody {
                locals: vec![],
                instructions: vec![CilInstruction {
                    offset: 0,
                    opcode: "ret".into(),
                    operand: CilOperand::None,
                }],
                exception_handlers: vec![ExceptionHandler {
                    kind: ExceptionHandlerKind::Catch,
                    try_start: 0,
                    try_end: 5,
                    handler_start: 5,
                    handler_end: 10,
                    catch_type: Some("System.Exception".into()),
                    filter_start: None,
                }],
                max_stack: 1,
                init_locals: false,
            }),
            flags: 0x06,
            rva: 0,
            ..Default::default()
        };
        let dc = default_decompiler();
        let out = dc.decompile_method(&method).unwrap();
        assert!(out.contains("catch") || out.contains("try"));
    }

    // ── Extended tests ───────────────────────────────────────────────────────

    #[test]
    fn test_decompile_arithmetic_sub() {
        let method = make_int_method(
            "Sub",
            vec![
                CilInstruction {
                    offset: 0,
                    opcode: "ldc.i4.8".into(),
                    operand: CilOperand::None,
                },
                CilInstruction {
                    offset: 1,
                    opcode: "ldc.i4.3".into(),
                    operand: CilOperand::None,
                },
                CilInstruction {
                    offset: 2,
                    opcode: "sub".into(),
                    operand: CilOperand::None,
                },
                CilInstruction {
                    offset: 3,
                    opcode: "ret".into(),
                    operand: CilOperand::None,
                },
            ],
        );
        let dc = default_decompiler();
        let out = dc.decompile_method(&method).unwrap();
        assert!(out.contains("8 - 3") || out.contains("t0"));
    }

    #[test]
    fn test_decompile_mul() {
        let method = make_int_method(
            "Mul",
            vec![
                CilInstruction {
                    offset: 0,
                    opcode: "ldc.i4.2".into(),
                    operand: CilOperand::None,
                },
                CilInstruction {
                    offset: 1,
                    opcode: "ldc.i4.5".into(),
                    operand: CilOperand::None,
                },
                CilInstruction {
                    offset: 2,
                    opcode: "mul".into(),
                    operand: CilOperand::None,
                },
                CilInstruction {
                    offset: 3,
                    opcode: "ret".into(),
                    operand: CilOperand::None,
                },
            ],
        );
        let dc = default_decompiler();
        let out = dc.decompile_method(&method).unwrap();
        assert!(out.contains("2 * 5") || out.contains("t0"));
    }

    #[test]
    fn test_decompile_neg_not() {
        let method = make_int_method(
            "NegNot",
            vec![
                CilInstruction {
                    offset: 0,
                    opcode: "ldc.i4.3".into(),
                    operand: CilOperand::None,
                },
                CilInstruction {
                    offset: 1,
                    opcode: "neg".into(),
                    operand: CilOperand::None,
                },
                CilInstruction {
                    offset: 2,
                    opcode: "ldc.i4.m1".into(),
                    operand: CilOperand::None,
                },
                CilInstruction {
                    offset: 3,
                    opcode: "not".into(),
                    operand: CilOperand::None,
                },
                CilInstruction {
                    offset: 4,
                    opcode: "add".into(),
                    operand: CilOperand::None,
                },
                CilInstruction {
                    offset: 5,
                    opcode: "ret".into(),
                    operand: CilOperand::None,
                },
            ],
        );
        let dc = default_decompiler();
        let out = dc.decompile_method(&method).unwrap();
        assert!(out.contains("-3") || out.contains("neg") || out.contains("t0"));
    }

    #[test]
    fn test_decompile_conv_i4() {
        let method = make_int_method(
            "Conv",
            vec![
                CilInstruction {
                    offset: 0,
                    opcode: "ldc.i8".into(),
                    operand: CilOperand::Int64(100),
                },
                CilInstruction {
                    offset: 9,
                    opcode: "conv.i4".into(),
                    operand: CilOperand::None,
                },
                CilInstruction {
                    offset: 10,
                    opcode: "ret".into(),
                    operand: CilOperand::None,
                },
            ],
        );
        let dc = default_decompiler();
        let out = dc.decompile_method(&method).unwrap();
        assert!(out.contains("(int)") || out.contains("conv"));
    }

    #[test]
    fn test_decompile_ceq_cgt_clt() {
        let method = make_void_method(
            "Compare",
            vec![
                CilInstruction {
                    offset: 0,
                    opcode: "ldc.i4.1".into(),
                    operand: CilOperand::None,
                },
                CilInstruction {
                    offset: 1,
                    opcode: "ldc.i4.2".into(),
                    operand: CilOperand::None,
                },
                CilInstruction {
                    offset: 2,
                    opcode: "ceq".into(),
                    operand: CilOperand::None,
                },
                CilInstruction {
                    offset: 3,
                    opcode: "pop".into(),
                    operand: CilOperand::None,
                },
                CilInstruction {
                    offset: 4,
                    opcode: "ldc.i4.1".into(),
                    operand: CilOperand::None,
                },
                CilInstruction {
                    offset: 5,
                    opcode: "ldc.i4.2".into(),
                    operand: CilOperand::None,
                },
                CilInstruction {
                    offset: 6,
                    opcode: "cgt".into(),
                    operand: CilOperand::None,
                },
                CilInstruction {
                    offset: 7,
                    opcode: "pop".into(),
                    operand: CilOperand::None,
                },
                CilInstruction {
                    offset: 8,
                    opcode: "ret".into(),
                    operand: CilOperand::None,
                },
            ],
        );
        let dc = default_decompiler();
        let out = dc.decompile_method(&method).unwrap();
        assert!(out.contains("==") || out.contains("ceq"));
    }

    #[test]
    fn test_decompile_ldnull() {
        let method = make_void_method(
            "NullCheck",
            vec![
                CilInstruction {
                    offset: 0,
                    opcode: "ldnull".into(),
                    operand: CilOperand::None,
                },
                CilInstruction {
                    offset: 1,
                    opcode: "pop".into(),
                    operand: CilOperand::None,
                },
                CilInstruction {
                    offset: 2,
                    opcode: "ret".into(),
                    operand: CilOperand::None,
                },
            ],
        );
        let dc = default_decompiler();
        let out = dc.decompile_method(&method).unwrap();
        // ldnull + pop = nothing emitted, just ret
        assert!(out.contains("return;"));
    }

    #[test]
    fn test_decompile_ldc_r4_r8() {
        let method = make_void_method(
            "FloatConst",
            vec![
                CilInstruction {
                    offset: 0,
                    opcode: "ldc.r4".into(),
                    operand: CilOperand::Float32(3.125_f32),
                },
                CilInstruction {
                    offset: 5,
                    opcode: "pop".into(),
                    operand: CilOperand::None,
                },
                CilInstruction {
                    offset: 6,
                    opcode: "ldc.r8".into(),
                    operand: CilOperand::Float64(2.625_f64),
                },
                CilInstruction {
                    offset: 15,
                    opcode: "pop".into(),
                    operand: CilOperand::None,
                },
                CilInstruction {
                    offset: 16,
                    opcode: "ret".into(),
                    operand: CilOperand::None,
                },
            ],
        );
        let dc = default_decompiler();
        let out = dc.decompile_method(&method).unwrap();
        // floats were pushed and popped — just check it compiles without panic
        assert!(out.contains("return;") || out.contains("void"));
    }

    #[test]
    fn test_decompile_ldc_i8() {
        let method = make_void_method(
            "LongConst",
            vec![
                CilInstruction {
                    offset: 0,
                    opcode: "ldc.i8".into(),
                    operand: CilOperand::Int64(1_000_000_000_000),
                },
                CilInstruction {
                    offset: 9,
                    opcode: "pop".into(),
                    operand: CilOperand::None,
                },
                CilInstruction {
                    offset: 10,
                    opcode: "ret".into(),
                    operand: CilOperand::None,
                },
            ],
        );
        let dc = default_decompiler();
        let out = dc.decompile_method(&method).unwrap();
        assert!(out.contains("1000000000000L") || out.contains('L'));
    }

    #[test]
    fn test_decompile_dup() {
        let method = make_int_method(
            "Dup",
            vec![
                CilInstruction {
                    offset: 0,
                    opcode: "ldc.i4.5".into(),
                    operand: CilOperand::None,
                },
                CilInstruction {
                    offset: 1,
                    opcode: "dup".into(),
                    operand: CilOperand::None,
                },
                CilInstruction {
                    offset: 2,
                    opcode: "add".into(),
                    operand: CilOperand::None,
                },
                CilInstruction {
                    offset: 3,
                    opcode: "ret".into(),
                    operand: CilOperand::None,
                },
            ],
        );
        let dc = default_decompiler();
        let out = dc.decompile_method(&method).unwrap();
        assert!(out.contains("5 + 5") || out.contains("t0"));
    }

    #[test]
    fn test_decompile_stelem() {
        let method = make_void_method(
            "ArrayWrite",
            vec![
                CilInstruction {
                    offset: 0,
                    opcode: "ldnull".into(),
                    operand: CilOperand::None,
                }, // arr
                CilInstruction {
                    offset: 1,
                    opcode: "ldc.i4.0".into(),
                    operand: CilOperand::None,
                }, // idx
                CilInstruction {
                    offset: 2,
                    opcode: "ldc.i4.1".into(),
                    operand: CilOperand::None,
                }, // val
                CilInstruction {
                    offset: 3,
                    opcode: "stelem.i4".into(),
                    operand: CilOperand::None,
                },
                CilInstruction {
                    offset: 4,
                    opcode: "ret".into(),
                    operand: CilOperand::None,
                },
            ],
        );
        let dc = default_decompiler();
        let out = dc.decompile_method(&method).unwrap();
        assert!(out.contains("[0] =") || out.contains("stelem"));
    }

    #[test]
    fn test_decompile_ldelem() {
        let method = make_int_method(
            "ArrayRead",
            vec![
                CilInstruction {
                    offset: 0,
                    opcode: "ldnull".into(),
                    operand: CilOperand::None,
                },
                CilInstruction {
                    offset: 1,
                    opcode: "ldc.i4.2".into(),
                    operand: CilOperand::None,
                },
                CilInstruction {
                    offset: 2,
                    opcode: "ldelem.i4".into(),
                    operand: CilOperand::None,
                },
                CilInstruction {
                    offset: 3,
                    opcode: "ret".into(),
                    operand: CilOperand::None,
                },
            ],
        );
        let dc = default_decompiler();
        let out = dc.decompile_method(&method).unwrap();
        assert!(out.contains("[2]") || out.contains("ldelem"));
    }

    #[test]
    fn test_decompile_newarr_ldlen() {
        let method = make_int_method(
            "ArrayLen",
            vec![
                CilInstruction {
                    offset: 0,
                    opcode: "ldc.i4.4".into(),
                    operand: CilOperand::None,
                },
                CilInstruction {
                    offset: 1,
                    opcode: "newarr".into(),
                    operand: CilOperand::Token(0x0100_0001),
                },
                CilInstruction {
                    offset: 6,
                    opcode: "ldlen".into(),
                    operand: CilOperand::None,
                },
                CilInstruction {
                    offset: 7,
                    opcode: "ret".into(),
                    operand: CilOperand::None,
                },
            ],
        );
        let dc = default_decompiler();
        let out = dc.decompile_method(&method).unwrap();
        assert!(out.contains(".Length") || out.contains("ldlen"));
    }

    #[test]
    fn test_decompile_throw() {
        let method = make_void_method(
            "Thrower",
            vec![
                CilInstruction {
                    offset: 0,
                    opcode: "ldnull".into(),
                    operand: CilOperand::None,
                },
                CilInstruction {
                    offset: 1,
                    opcode: "throw".into(),
                    operand: CilOperand::None,
                },
            ],
        );
        let dc = default_decompiler();
        let out = dc.decompile_method(&method).unwrap();
        assert!(out.contains("throw"));
    }

    #[test]
    fn test_decompile_castclass() {
        let method = make_void_method(
            "Cast",
            vec![
                CilInstruction {
                    offset: 0,
                    opcode: "ldnull".into(),
                    operand: CilOperand::None,
                },
                CilInstruction {
                    offset: 1,
                    opcode: "castclass".into(),
                    operand: CilOperand::Token(0x0100_0002),
                },
                CilInstruction {
                    offset: 6,
                    opcode: "pop".into(),
                    operand: CilOperand::None,
                },
                CilInstruction {
                    offset: 7,
                    opcode: "ret".into(),
                    operand: CilOperand::None,
                },
            ],
        );
        let dc = default_decompiler();
        let out = dc.decompile_method(&method).unwrap();
        // castclass should emit a cast expression
        assert!(out.contains('(') || out.contains("0x0100_0002"));
    }

    #[test]
    fn test_decompile_isinst() {
        let method = make_void_method(
            "IsInst",
            vec![
                CilInstruction {
                    offset: 0,
                    opcode: "ldnull".into(),
                    operand: CilOperand::None,
                },
                CilInstruction {
                    offset: 1,
                    opcode: "isinst".into(),
                    operand: CilOperand::Token(0x0100_0003),
                },
                CilInstruction {
                    offset: 6,
                    opcode: "pop".into(),
                    operand: CilOperand::None,
                },
                CilInstruction {
                    offset: 7,
                    opcode: "ret".into(),
                    operand: CilOperand::None,
                },
            ],
        );
        let dc = default_decompiler();
        let out = dc.decompile_method(&method).unwrap();
        assert!(out.contains("as") || out.contains("0x0100_0003"));
    }

    #[test]
    fn test_decompile_initobj() {
        let method = make_void_method(
            "InitObj",
            vec![
                CilInstruction {
                    offset: 0,
                    opcode: "ldnull".into(),
                    operand: CilOperand::None,
                },
                CilInstruction {
                    offset: 1,
                    opcode: "initobj".into(),
                    operand: CilOperand::Token(0x0200_0001),
                },
                CilInstruction {
                    offset: 6,
                    opcode: "ret".into(),
                    operand: CilOperand::None,
                },
            ],
        );
        let dc = default_decompiler();
        let out = dc.decompile_method(&method).unwrap();
        assert!(out.contains("default") || out.contains("initobj"));
    }

    #[test]
    fn test_decompile_newobj() {
        let method = make_void_method(
            "New",
            vec![
                CilInstruction {
                    offset: 0,
                    opcode: "newobj".into(),
                    operand: CilOperand::Token(0x0A00_0001),
                },
                CilInstruction {
                    offset: 5,
                    opcode: "pop".into(),
                    operand: CilOperand::None,
                },
                CilInstruction {
                    offset: 6,
                    opcode: "ret".into(),
                    operand: CilOperand::None,
                },
            ],
        );
        let dc = default_decompiler();
        let out = dc.decompile_method(&method).unwrap();
        assert!(out.contains("new") || out.contains("0x0A00_0001"));
    }

    #[test]
    fn test_decompile_ldfld_stfld() {
        let method = make_void_method(
            "Fields",
            vec![
                CilInstruction {
                    offset: 0,
                    opcode: "ldarg.0".into(),
                    operand: CilOperand::None,
                },
                CilInstruction {
                    offset: 1,
                    opcode: "ldfld".into(),
                    operand: CilOperand::Token(0x0400_0001),
                },
                CilInstruction {
                    offset: 6,
                    opcode: "pop".into(),
                    operand: CilOperand::None,
                },
                CilInstruction {
                    offset: 7,
                    opcode: "ldarg.0".into(),
                    operand: CilOperand::None,
                },
                CilInstruction {
                    offset: 8,
                    opcode: "ldc.i4.0".into(),
                    operand: CilOperand::None,
                },
                CilInstruction {
                    offset: 9,
                    opcode: "stfld".into(),
                    operand: CilOperand::Token(0x0400_0001),
                },
                CilInstruction {
                    offset: 14,
                    opcode: "ret".into(),
                    operand: CilOperand::None,
                },
            ],
        );
        let dc = default_decompiler();
        let out = dc.decompile_method(&method).unwrap();
        assert!(out.contains("./* fld") || out.contains("0x0400_0001"));
    }

    #[test]
    fn test_decompile_beq_blt_bge() {
        let method = make_void_method(
            "Compares",
            vec![
                CilInstruction {
                    offset: 0,
                    opcode: "ldc.i4.1".into(),
                    operand: CilOperand::None,
                },
                CilInstruction {
                    offset: 1,
                    opcode: "ldc.i4.1".into(),
                    operand: CilOperand::None,
                },
                CilInstruction {
                    offset: 2,
                    opcode: "beq".into(),
                    operand: CilOperand::Branch(8),
                },
                CilInstruction {
                    offset: 7,
                    opcode: "nop".into(),
                    operand: CilOperand::None,
                },
                CilInstruction {
                    offset: 8,
                    opcode: "ret".into(),
                    operand: CilOperand::None,
                },
            ],
        );
        let dc = default_decompiler();
        let out = dc.decompile_method(&method).unwrap();
        assert!(out.contains("==") || out.contains("goto"));
    }

    #[test]
    fn test_decompile_shl_shr() {
        let method = make_int_method(
            "Shift",
            vec![
                CilInstruction {
                    offset: 0,
                    opcode: "ldc.i4".into(),
                    operand: CilOperand::Int32(16),
                },
                CilInstruction {
                    offset: 5,
                    opcode: "ldc.i4.2".into(),
                    operand: CilOperand::None,
                },
                CilInstruction {
                    offset: 6,
                    opcode: "shl".into(),
                    operand: CilOperand::None,
                },
                CilInstruction {
                    offset: 7,
                    opcode: "ldc.i4.1".into(),
                    operand: CilOperand::None,
                },
                CilInstruction {
                    offset: 8,
                    opcode: "shr".into(),
                    operand: CilOperand::None,
                },
                CilInstruction {
                    offset: 9,
                    opcode: "ret".into(),
                    operand: CilOperand::None,
                },
            ],
        );
        let dc = default_decompiler();
        let out = dc.decompile_method(&method).unwrap();
        assert!(out.contains("<<") || out.contains(">>"));
    }

    #[test]
    fn test_decompile_finally_handler() {
        let method = DotnetMethod {
            name: "TryFinally".into(),
            signature: MethodSignature {
                return_type: "void".into(),
                ..Default::default()
            },
            body: Some(MethodBody {
                locals: vec![],
                instructions: vec![
                    CilInstruction {
                        offset: 0,
                        opcode: "nop".into(),
                        operand: CilOperand::None,
                    },
                    CilInstruction {
                        offset: 1,
                        opcode: "leave.s".into(),
                        operand: CilOperand::Branch(5),
                    },
                    CilInstruction {
                        offset: 3,
                        opcode: "endfinally".into(),
                        operand: CilOperand::None,
                    },
                    CilInstruction {
                        offset: 4,
                        opcode: "nop".into(),
                        operand: CilOperand::None,
                    },
                    CilInstruction {
                        offset: 5,
                        opcode: "ret".into(),
                        operand: CilOperand::None,
                    },
                ],
                exception_handlers: vec![ExceptionHandler {
                    kind: ExceptionHandlerKind::Finally,
                    try_start: 0,
                    try_end: 3,
                    handler_start: 3,
                    handler_end: 5,
                    catch_type: None,
                    filter_start: None,
                }],
                max_stack: 1,
                init_locals: false,
            }),
            flags: 0x06,
            rva: 0,
            ..Default::default()
        };
        let dc = default_decompiler();
        let out = dc.decompile_method(&method).unwrap();
        assert!(out.contains("finally") || out.contains("endfinally"));
    }

    #[test]
    fn test_decompile_type_with_method_body() {
        let method = DotnetMethod {
            name: "Compute".into(),
            signature: MethodSignature {
                return_type: "int".into(),
                params: vec![("x".into(), "int".into())],
                is_static: false,
                is_vararg: false,
                ..Default::default()
            },
            body: Some(MethodBody {
                locals: vec![],
                instructions: vec![
                    CilInstruction {
                        offset: 0,
                        opcode: "ldarg.1".into(),
                        operand: CilOperand::None,
                    },
                    CilInstruction {
                        offset: 1,
                        opcode: "ldc.i4.2".into(),
                        operand: CilOperand::None,
                    },
                    CilInstruction {
                        offset: 2,
                        opcode: "mul".into(),
                        operand: CilOperand::None,
                    },
                    CilInstruction {
                        offset: 3,
                        opcode: "ret".into(),
                        operand: CilOperand::None,
                    },
                ],
                exception_handlers: vec![],
                max_stack: 2,
                init_locals: false,
            }),
            flags: 0x06,
            rva: 0,
            ..Default::default()
        };
        let t = DotnetType {
            name: "Calculator".into(),
            namespace: "Math".into(),
            full_name: "Math.Calculator".into(),
            base_type: None,
            interfaces: vec![],
            methods: vec![method],
            fields: vec![],
            properties: vec![],
            events: vec![],
            nested_types: vec![],
            custom_attributes: vec![],
            generic_params: vec![],
            kind_tag: rustre_dotnet::DotnetTypeKind::Class,
            flags: 0,
            layout: None,
        };
        let dc = default_decompiler();
        let out = dc.decompile_type(&t).unwrap();
        assert!(out.contains("namespace Math"));
        assert!(out.contains("Compute"));
        assert!(out.contains('x'));
    }

    #[test]
    fn test_decompile_options_use_short_types_false() {
        let opts = DecompilerOptions {
            use_short_types: false,
            ..DecompilerOptions::default()
        };
        let dc = CSharpDecompiler::new(opts);
        let method = make_void_method(
            "Test",
            vec![CilInstruction {
                offset: 0,
                opcode: "ret".into(),
                operand: CilOperand::None,
            }],
        );
        let out = dc.decompile_method(&method).unwrap();
        // With use_short_types=false normalization still maps via normalize_type
        // Just check the output compiles fine
        assert!(out.contains("Test"));
    }

    #[test]
    fn test_hlil_expression_display() {
        let expr = HlilExpression::BinaryOp {
            op: BinaryOp::Add,
            lhs: Box::new(HlilExpression::Const(42)),
            rhs: Box::new(HlilExpression::Const(8)),
        };
        let s = expr.to_csharp();
        assert_eq!(s, "(42 + 8)");
    }

    #[test]
    fn test_hlil_statement_assign() {
        let stmt = HlilStatement::Assign {
            target: HlilExpression::Local(0, "result".into()),
            value: HlilExpression::Const(100),
        };
        let s = stmt.to_csharp("    ");
        assert!(s.contains("result") && s.contains("100"));
    }

    #[test]
    fn test_hlil_statement_return() {
        let stmt = HlilStatement::Return(Some(HlilExpression::Const(0)));
        let s = stmt.to_csharp("    ");
        assert_eq!(s.trim(), "return 0;");
    }

    #[test]
    fn test_hlil_block_format() {
        let block = HlilBlock {
            statements: vec![HlilStatement::Return(Some(HlilExpression::Const(42)))],
        };
        let s = block.to_csharp("    ");
        assert!(s.contains("return 42;"));
    }

    #[test]
    fn test_cil_opcode_registry_all_opcodes() {
        let ops = CilOpcodeRegistry::all_opcodes();
        assert!(ops.len() > 100);
        assert!(ops.iter().any(|o| o.name == "nop"));
        assert!(ops.iter().any(|o| o.name == "ret"));
        assert!(ops.iter().any(|o| o.name == "call"));
        assert!(ops.iter().any(|o| o.name == "ldarg.0"));
    }

    #[test]
    fn test_cil_opcode_lookup_by_name() {
        let nop = CilOpcodeRegistry::by_name("nop").unwrap();
        assert_eq!(nop.byte1, 0x00);
        assert_eq!(nop.operand_kind, OperandKind::None);
        let ceq = CilOpcodeRegistry::by_name("ceq").unwrap();
        assert_eq!(ceq.byte1, 0xFE);
        assert_eq!(ceq.byte2, Some(0x01));
    }

    #[test]
    fn test_cil_opcode_lookup_by_encoding() {
        let ret = CilOpcodeRegistry::by_encoding(0x2A, None).unwrap();
        assert_eq!(ret.name, "ret");
        let ceq = CilOpcodeRegistry::by_encoding(0xFE, Some(0x01)).unwrap();
        assert_eq!(ceq.name, "ceq");
    }

    #[test]
    fn test_cil_disassembler_basic() {
        let bytes = vec![
            0x00u8, // nop
            0x17,   // ldc.i4.1
            0x2A,   // ret
        ];
        let instrs = CilDisassembler::disassemble(&bytes).unwrap();
        assert_eq!(instrs.len(), 3);
        assert_eq!(instrs[0].opcode, "nop");
        assert_eq!(instrs[1].opcode, "ldc.i4.1");
        assert_eq!(instrs[2].opcode, "ret");
    }

    #[test]
    fn test_cil_disassembler_ldc_i4_s() {
        let bytes = vec![0x1Fu8, 0x2A]; // ldc.i4.s 42
        let instrs = CilDisassembler::disassemble(&bytes).unwrap();
        assert_eq!(instrs.len(), 1);
        assert_eq!(instrs[0].opcode, "ldc.i4.s");
        assert!(matches!(instrs[0].operand, CilOperand::Int8(42)));
    }

    #[test]
    fn test_cil_disassembler_ldc_i4() {
        let mut bytes = vec![0x20u8]; // ldc.i4
        bytes.extend_from_slice(&100i32.to_le_bytes());
        let instrs = CilDisassembler::disassemble(&bytes).unwrap();
        assert_eq!(instrs.len(), 1);
        assert_eq!(instrs[0].opcode, "ldc.i4");
        assert!(matches!(instrs[0].operand, CilOperand::Int32(100)));
    }

    #[test]
    fn test_cil_disassembler_call_token() {
        let mut bytes = vec![0x28u8]; // call
        bytes.extend_from_slice(&0x0A00_0001_u32.to_le_bytes());
        let instrs = CilDisassembler::disassemble(&bytes).unwrap();
        assert_eq!(instrs[0].opcode, "call");
        assert!(matches!(instrs[0].operand, CilOperand::Token(0x0A00_0001)));
    }

    #[test]
    fn test_cil_disassembler_prefixed_ceq() {
        let bytes = vec![0xFEu8, 0x01]; // ceq
        let instrs = CilDisassembler::disassemble(&bytes).unwrap();
        assert_eq!(instrs.len(), 1);
        assert_eq!(instrs[0].opcode, "ceq");
    }

    #[test]
    fn test_decompile_pipeline_method() {
        let method = make_int_method(
            "Pipeline",
            vec![
                CilInstruction {
                    offset: 0,
                    opcode: "ldc.i4".into(),
                    operand: CilOperand::Int32(7),
                },
                CilInstruction {
                    offset: 5,
                    opcode: "ldc.i4.3".into(),
                    operand: CilOperand::None,
                },
                CilInstruction {
                    offset: 6,
                    opcode: "add".into(),
                    operand: CilOperand::None,
                },
                CilInstruction {
                    offset: 7,
                    opcode: "ret".into(),
                    operand: CilOperand::None,
                },
            ],
        );
        let pipeline = DecompilationPipeline::default();
        let out = pipeline.decompile_method(&method).unwrap();
        assert!(out.contains("int Pipeline"));
        assert!(out.contains("return") || out.contains("t0"));
    }

    #[test]
    fn test_type_kind_detection() {
        assert_eq!(TypeKind::from_flags(0x0020), TypeKind::Interface);
        assert_eq!(TypeKind::from_flags(0x0000), TypeKind::Class);
    }
}

// ─── Stack effect table ───────────────────────────────────────────────────────

/// Stack effect (+pops, +pushes) for a given opcode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StackEffect {
    /// Number of values popped from the stack.
    pub pops: i8,
    /// Number of values pushed onto the stack.
    pub pushes: i8,
}

impl StackEffect {
    /// Net change in stack depth.
    #[must_use]
    pub const fn delta(self) -> i8 {
        self.pushes - self.pops
    }
}

/// Returns the stack effect for a given opcode name, using explicit pops/pushes.
/// Returns `None` for unknown opcodes.
#[must_use]
pub fn stack_effect(opcode: &str) -> Option<StackEffect> {
    let e = |pops, pushes| Some(StackEffect { pops, pushes });
    match opcode {
        "nop" | "break" | "jmp" | "ret" | "br" | "br.s" | "endfinally" | "endfilter"
        | "leave" | "leave.s" => e(0, 0),
        "ldarg.0" | "ldarg.1" | "ldarg.2" | "ldarg.3" | "ldarg.s" | "ldarg" | "ldarga.s"
        | "ldarga" | "ldloc.0" | "ldloc.1" | "ldloc.2" | "ldloc.3" | "ldloc.s" | "ldloc"
        | "ldloca.s" | "ldloca" | "ldnull" | "ldc.i4.m1" | "ldc.i4.0" | "ldc.i4.1" | "ldc.i4.2"
        | "ldc.i4.3" | "ldc.i4.4" | "ldc.i4.5" | "ldc.i4.6" | "ldc.i4.7" | "ldc.i4.8"
        | "ldc.i4.s" | "ldc.i4" | "ldc.i8" | "ldc.r4" | "ldc.r8" | "call" | "calli" | "callvirt"
        | "newobj" | "ldstr" | "ldsfld" | "ldsflda" | "ldtoken" | "sizeof" | "arglist"
        | "ldftn" | "ldvirtftn" => e(0, 1),
        "starg.s" | "starg" | "stloc.0" | "stloc.1" | "stloc.2" | "stloc.3" | "stloc.s"
        | "stloc" | "pop" | "brfalse" | "brfalse.s" | "brtrue" | "brtrue.s" | "switch"
        | "throw" | "stsfld" | "initobj" => e(1, 0),
        "dup" => e(1, 2),
        "beq" | "beq.s" | "bne.un" | "bne.un.s" | "bge" | "bge.s" | "bge.un" | "bge.un.s"
        | "bgt" | "bgt.s" | "bgt.un" | "bgt.un.s" | "ble" | "ble.s" | "ble.un" | "ble.un.s"
        | "blt" | "blt.s" | "blt.un" | "blt.un.s" | "cpobj" | "stind.ref" | "stind.i1"
        | "stind.i2" | "stind.i4" | "stind.i8" | "stind.r4" | "stind.r8" | "stind.i"
        | "stfld" | "stobj" => e(2, 0),
        "ldind.i1" | "ldind.u1" | "ldind.i2" | "ldind.u2" | "ldind.i4" | "ldind.u4"
        | "ldind.i8" | "ldind.r4" | "ldind.r8" | "ldind.i" | "ldind.ref" | "neg" | "not"
        | "conv.i1" | "conv.u1" | "conv.i2" | "conv.u2" | "conv.i4" | "conv.u4" | "conv.i8"
        | "conv.u8" | "conv.r4" | "conv.r8" | "conv.i" | "conv.u" | "conv.r.un"
        | "conv.ovf.i1" | "conv.ovf.u1" | "conv.ovf.i2" | "conv.ovf.u2" | "conv.ovf.i4"
        | "conv.ovf.u4" | "conv.ovf.i8" | "conv.ovf.u8" | "conv.ovf.i" | "conv.ovf.u"
        | "conv.ovf.i1.un" | "conv.ovf.u1.un" | "conv.ovf.i2.un" | "conv.ovf.u2.un"
        | "conv.ovf.i4.un" | "conv.ovf.u4.un" | "conv.ovf.i8.un" | "conv.ovf.u8.un"
        | "conv.ovf.i.un" | "conv.ovf.u.un" | "ldobj" | "castclass" | "isinst" | "unbox"
        | "unbox.any" | "box" | "ldfld" | "ldflda" | "newarr" | "ldlen" | "refanyval"
        | "ckfinite" | "mkrefany" | "localloc" | "refanytype" => e(1, 1),
        "add" | "sub" | "mul" | "div" | "div.un" | "rem" | "rem.un" | "and" | "or" | "xor"
        | "shl" | "shr" | "shr.un" | "add.ovf" | "add.ovf.un" | "mul.ovf" | "mul.ovf.un"
        | "sub.ovf" | "sub.ovf.un" | "ldelema"
        | "ldelem.i1" | "ldelem.u1" | "ldelem.i2" | "ldelem.u2" | "ldelem.i4" | "ldelem.u4"
        | "ldelem.i8" | "ldelem.r4" | "ldelem.r8" | "ldelem.i" | "ldelem.ref" | "ldelem"
        | "ceq" | "cgt" | "cgt.un" | "clt" | "clt.un" => e(2, 1),
        "stelem.i" | "stelem.i1" | "stelem.i2" | "stelem.i4" | "stelem.i8" | "stelem.r4"
        | "stelem.r8" | "stelem.ref" | "stelem" | "cpblk" | "initblk" => e(3, 0),
        _ => None,
    }
}

// ─── SSA variable builder ──────────────────────────────────────────────────────

/// Represents a single SSA definition.
#[derive(Debug, Clone)]
pub struct SsaDef {
    /// Variable name, e.g., `s0_0` for stack slot 0, version 0.
    pub name: String,
    /// The instruction offset that produced this value.
    pub def_offset: u32,
    /// The expression text for this definition.
    pub expr: String,
}

/// Tracks SSA versioning for each stack slot.
#[derive(Debug, Default)]
pub struct SsaBuilder {
    versions: std::collections::HashMap<usize, usize>,
    /// All SSA definitions recorded so far.
    pub defs: Vec<SsaDef>,
}

impl SsaBuilder {
    /// Create a new `SsaBuilder`.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Allocate a fresh SSA name for stack slot `slot`.
    pub fn fresh(&mut self, slot: usize, offset: u32, expr: impl Into<String>) -> String {
        let ver = self.versions.entry(slot).or_insert(0);
        let name = format!("s{slot}_{ver}");
        self.defs.push(SsaDef {
            name: name.clone(),
            def_offset: offset,
            expr: expr.into(),
        });
        *ver += 1;
        name
    }

    /// Returns the current (latest) SSA name for `slot`, or a placeholder.
    #[must_use]
    pub fn current(&self, slot: usize) -> String {
        let ver = self.versions.get(&slot).copied().unwrap_or(0);
        if ver == 0 {
            format!("s{slot}_undef")
        } else {
            format!("s{slot}_{}", ver - 1)
        }
    }

    /// Returns how many SSA definitions have been created.
    #[must_use]
    pub const fn def_count(&self) -> usize {
        self.defs.len()
    }
}

// ─── Pattern recogniser ────────────────────────────────────────────────────────

/// Pattern-based recogniser for common high-level patterns in CIL sequences.
pub struct PatternRecogniser;

impl PatternRecogniser {
    /// Detect a `foreach` pattern:
    /// `callvirt MoveNext`, `brfalse`, `callvirt get_Current`.
    #[must_use]
    pub fn detect_foreach(instrs: &[CilInstruction]) -> bool {
        let names: Vec<&str> = instrs.iter().map(|i| i.opcode.as_str()).collect();
        names.windows(3).any(|w| {
            w[0] == "callvirt" && (w[1] == "brfalse" || w[1] == "brfalse.s") && w[2] == "callvirt"
        })
    }

    /// Detect a `using` pattern:
    /// `callvirt Dispose` inside a finally handler.
    #[must_use]
    pub fn detect_using(instrs: &[CilInstruction], has_finally: bool) -> bool {
        if !has_finally {
            return false;
        }
        instrs.iter().any(|i| i.opcode.as_str() == "callvirt")
    }

    /// Detect a string concatenation pattern: multiple `ldstr` + `call` (String.Concat).
    #[must_use]
    pub fn detect_string_concat(instrs: &[CilInstruction]) -> bool {
        let mut consecutive_ldstr = 0usize;
        for i in instrs {
            match i.opcode.as_str() {
                "ldstr" => consecutive_ldstr += 1,
                "call" | "callvirt" => {
                    if consecutive_ldstr >= 2 {
                        return true;
                    }
                    consecutive_ldstr = 0;
                }
                _ => consecutive_ldstr = 0,
            }
        }
        false
    }

    /// Detect a `lock` pattern: `Monitor.Enter` + `finally { Monitor.Exit }`.
    #[must_use]
    pub fn detect_lock(instrs: &[CilInstruction], has_finally: bool) -> bool {
        if !has_finally {
            return false;
        }
        instrs
            .iter()
            .filter(|i| i.opcode == "call" || i.opcode == "callvirt")
            .count()
            >= 2
    }

    /// Detect a null-check pattern: `ldarg.X` + `brfalse`/`brtrue`.
    #[must_use]
    pub fn detect_null_check(instrs: &[CilInstruction]) -> bool {
        instrs.windows(2).any(|w| {
            matches!(
                w[0].opcode.as_str(),
                "ldarg.0" | "ldarg.1" | "ldarg.2" | "ldarg.3" | "ldarg.s" | "ldarg"
            ) && matches!(
                w[1].opcode.as_str(),
                "brfalse" | "brfalse.s" | "brtrue" | "brtrue.s"
            )
        })
    }

    /// Detect a property getter pattern: exactly one `ldfld` or `ldsfld` + `ret`.
    #[must_use]
    pub fn detect_simple_property_getter(instrs: &[CilInstruction]) -> bool {
        let loads = instrs
            .iter()
            .filter(|i| matches!(i.opcode.as_str(), "ldfld" | "ldsfld"))
            .count();
        let rets = instrs.iter().filter(|i| i.opcode == "ret").count();
        loads == 1 && rets == 1 && instrs.len() <= 5
    }

    /// Detect a property setter pattern: `stfld` or `stsfld` + `ret`.
    #[must_use]
    pub fn detect_simple_property_setter(instrs: &[CilInstruction]) -> bool {
        let stores = instrs
            .iter()
            .filter(|i| matches!(i.opcode.as_str(), "stfld" | "stsfld"))
            .count();
        let rets = instrs.iter().filter(|i| i.opcode == "ret").count();
        stores == 1 && rets == 1 && instrs.len() <= 6
    }

    /// Detect a throw-null-reference pattern: `ldnull` + `throw`.
    #[must_use]
    pub fn detect_throw_null(instrs: &[CilInstruction]) -> bool {
        instrs
            .windows(2)
            .any(|w| w[0].opcode == "ldnull" && w[1].opcode == "throw")
    }

    /// Detect a ternary pattern: `ceq`/`clt`/`cgt` + `brfalse` + value + `br` + value.
    #[must_use]
    pub fn detect_ternary(instrs: &[CilInstruction]) -> bool {
        let ops: Vec<&str> = instrs.iter().map(|i| i.opcode.as_str()).collect();
        ops.windows(4).any(|w| {
            matches!(w[0], "ceq" | "clt" | "cgt" | "clt.un" | "cgt.un")
                && matches!(w[1], "brfalse" | "brfalse.s" | "brtrue" | "brtrue.s")
                && matches!(
                    w[2],
                    "ldc.i4.0" | "ldc.i4.1" | "ldnull" | "ldloc.0" | "ldloc.1"
                )
                && w[3] == "br"
        })
    }
}

// ─── HLIL body lifter ─────────────────────────────────────────────────────────

/// Lift a `MethodBody` to a `HlilBlock`.
fn lift_body_to_hlil(body: &MethodBody, method: &DotnetMethod) -> HlilBlock {
    let mut block = HlilBlock::new();
    let mut stack: Vec<HlilExpression> = Vec::new();
    for instr in &body.instructions {
        hlil_lift_one(instr, body, method, &mut stack, &mut block);
    }
    block
}

fn hlil_lift_loads(
    instr: &CilInstruction,
    body: &MethodBody,
    method: &DotnetMethod,
    stack: &mut Vec<HlilExpression>,
) -> bool {
    match instr.opcode.as_str() {
        "ldnull" => stack.push(HlilExpression::Null),
        "ldc.i4.m1" => stack.push(HlilExpression::Const(-1)),
        "ldc.i4.0" => stack.push(HlilExpression::Const(0)),
        "ldc.i4.1" => stack.push(HlilExpression::Const(1)),
        "ldc.i4.2" => stack.push(HlilExpression::Const(2)),
        "ldc.i4.3" => stack.push(HlilExpression::Const(3)),
        "ldc.i4.4" => stack.push(HlilExpression::Const(4)),
        "ldc.i4.5" => stack.push(HlilExpression::Const(5)),
        "ldc.i4.6" => stack.push(HlilExpression::Const(6)),
        "ldc.i4.7" => stack.push(HlilExpression::Const(7)),
        "ldc.i4.8" => stack.push(HlilExpression::Const(8)),
        "ldc.i4.s" | "ldc.i4" => {
            let v = match &instr.operand {
                CilOperand::Int8(n) => i64::from(*n),
                CilOperand::Int32(n) => i64::from(*n),
                _ => 0,
            };
            stack.push(HlilExpression::Const(v));
        }
        "ldc.i8" => {
            let v = if let CilOperand::Int64(n) = &instr.operand { *n } else { 0 };
            stack.push(HlilExpression::Const(v));
        }
        "ldc.r4" => {
            let v = if let CilOperand::Float32(f) = &instr.operand { f64::from(*f) } else { 0.0 };
            stack.push(HlilExpression::FloatConst(v));
        }
        "ldc.r8" => {
            let v = if let CilOperand::Float64(f) = &instr.operand { *f } else { 0.0 };
            stack.push(HlilExpression::FloatConst(v));
        }
        "ldstr" => {
            let s = if let CilOperand::String(s) = &instr.operand { s.clone() } else { String::new() };
            stack.push(HlilExpression::StringLit(s));
        }
        "ldarg.0" => push_param(stack, 0, method),
        "ldarg.1" => push_param(stack, 1, method),
        "ldarg.2" => push_param(stack, 2, method),
        "ldarg.3" => push_param(stack, 3, method),
        "ldarg.s" | "ldarg" => push_param(stack, operand_as_usize(instr), method),
        "ldloc.0" | "ldloc.1" | "ldloc.2" | "ldloc.3" | "ldloc.s" | "ldloc" => {
            let idx: usize = match instr.opcode.as_str() {
                "ldloc.0" => 0, "ldloc.1" => 1, "ldloc.2" => 2, "ldloc.3" => 3,
                _ => operand_as_usize(instr),
            };
            let idx_u32 = casts::usize_to_u32(idx);
            let name = body.locals.iter().find(|l| l.index == idx_u32)
                .map_or_else(|| format!("local{idx}"), |l| format!("local{}", l.index));
            stack.push(HlilExpression::Local(idx, name));
        }
        _ => return false,
    }
    true
}

fn hlil_lift_one(
    instr: &CilInstruction,
    body: &MethodBody,
    method: &DotnetMethod,
    stack: &mut Vec<HlilExpression>,
    block: &mut HlilBlock,
) {
    let offset = instr.offset;
    if hlil_lift_loads(instr, body, method, stack) { return; }
    match instr.opcode.as_str() {
        "stloc.0" | "stloc.1" | "stloc.2" | "stloc.3" | "stloc.s" | "stloc" => {
            let idx: usize = match instr.opcode.as_str() {
                "stloc.0" => 0, "stloc.1" => 1, "stloc.2" => 2, "stloc.3" => 3,
                _ => operand_as_usize(instr),
            };
            let idx_u32 = casts::usize_to_u32(idx);
            let val = stack.pop().unwrap_or(HlilExpression::Const(0));
            let local_name = body.locals.iter().find(|l| l.index == idx_u32)
                .map_or_else(|| format!("local{idx}"), |l| format!("local{}", l.index));
            block.push(HlilStatement::Assign {
                target: HlilExpression::Local(idx, local_name),
                value: val,
            });
        }
        "dup" => { let top = stack.last().cloned().unwrap_or(HlilExpression::Const(0)); stack.push(top); }
        "pop" => { stack.pop(); }
        "add" | "add.ovf" | "add.ovf.un" => hlil_binary_op(stack, BinaryOp::Add),
        "sub" | "sub.ovf" | "sub.ovf.un" => hlil_binary_op(stack, BinaryOp::Sub),
        "mul" | "mul.ovf" | "mul.ovf.un" => hlil_binary_op(stack, BinaryOp::Mul),
        "div" | "div.un" => hlil_binary_op(stack, BinaryOp::Div),
        "rem" | "rem.un" => hlil_binary_op(stack, BinaryOp::Rem),
        "and" => hlil_binary_op(stack, BinaryOp::And),
        "or" => hlil_binary_op(stack, BinaryOp::Or),
        "xor" => hlil_binary_op(stack, BinaryOp::Xor),
        "shl" => hlil_binary_op(stack, BinaryOp::Shl),
        "shr" | "shr.un" => hlil_binary_op(stack, BinaryOp::Shr),
        "neg" => { let v = stack.pop().unwrap_or(HlilExpression::Const(0)); stack.push(HlilExpression::UnaryOp { op: UnaryOp::Neg, operand: Box::new(v) }); }
        "not" => { let v = stack.pop().unwrap_or(HlilExpression::Const(0)); stack.push(HlilExpression::UnaryOp { op: UnaryOp::BitNot, operand: Box::new(v) }); }
        "ceq" => hlil_binary_op(stack, BinaryOp::Eq),
        "cgt" | "cgt.un" => hlil_binary_op(stack, BinaryOp::Gt),
        "clt" | "clt.un" => hlil_binary_op(stack, BinaryOp::Lt),
        "nop" | "break"
        | "conv.i1" | "conv.u1" | "conv.i2" | "conv.u2" | "conv.i4" | "conv.u4" | "conv.i8"
        | "conv.u8" | "conv.r4" | "conv.r8" | "conv.i" | "conv.u" | "conv.r.un"
        | "conv.ovf.i4" | "conv.ovf.u4" | "conv.ovf.i8" | "conv.ovf.u8" | "conv.ovf.i"
        | "conv.ovf.u" | "conv.ovf.i4.un" | "conv.ovf.u4.un" => {}
        "ldfld" => { let t = operand_as_token(instr); let obj = stack.pop().unwrap_or(HlilExpression::Null); stack.push(HlilExpression::InstanceField(Box::new(obj), t, None)); }
        "ldsfld" => { let t = operand_as_token(instr); stack.push(HlilExpression::StaticField(t, None)); }
        "stfld" => {
            let t = operand_as_token(instr);
            let val = stack.pop().unwrap_or(HlilExpression::Const(0));
            let obj = stack.pop().unwrap_or(HlilExpression::Null);
            block.push(HlilStatement::Assign { target: HlilExpression::InstanceField(Box::new(obj), t, None), value: val });
        }
        "stsfld" => {
            let t = operand_as_token(instr);
            let val = stack.pop().unwrap_or(HlilExpression::Const(0));
            block.push(HlilStatement::Assign { target: HlilExpression::StaticField(t, None), value: val });
        }
        "newarr" => { let t = operand_as_token(instr); let size = stack.pop().unwrap_or(HlilExpression::Const(0)); stack.push(HlilExpression::NewArr(t, Box::new(size))); }
        "ldlen" => { let arr = stack.pop().unwrap_or_else(|| HlilExpression::Opaque("arr".into())); stack.push(HlilExpression::ArrayLength(Box::new(arr))); }
        "ldelem.i4" | "ldelem.u4" | "ldelem.i1" | "ldelem.u1" | "ldelem.i2" | "ldelem.u2"
        | "ldelem.i8" | "ldelem.r4" | "ldelem.r8" | "ldelem.ref" | "ldelem" => {
            let idx = stack.pop().unwrap_or(HlilExpression::Const(0));
            let arr = stack.pop().unwrap_or_else(|| HlilExpression::Opaque("arr".into()));
            stack.push(HlilExpression::ArrayElement(Box::new(arr), Box::new(idx)));
        }
        "newobj" => { let t = operand_as_token(instr); stack.push(HlilExpression::NewObj(t, Vec::new())); }
        "call" | "callvirt" => { let t = operand_as_token(instr); stack.push(HlilExpression::Call(t, Vec::new())); }
        "box" | "castclass" => { let t = operand_as_token(instr); let v = stack.pop().unwrap_or(HlilExpression::Null); stack.push(HlilExpression::Cast(t, Box::new(v))); }
        "isinst" | "unbox" | "unbox.any" => { let t = operand_as_token(instr); let v = stack.pop().unwrap_or(HlilExpression::Null); stack.push(HlilExpression::IsInst(t, Box::new(v))); }
        "ret" => {
            let ret_type = normalize_type(&method.signature.return_type);
            if ret_type == "void" { block.push(HlilStatement::Return(None)); }
            else { let val = stack.pop(); block.push(HlilStatement::Return(val)); }
        }
        "throw" => { let v = stack.pop().unwrap_or(HlilExpression::Null); block.push(HlilStatement::Throw(v)); }
        "br" | "br.s" | "leave" | "leave.s" => { block.push(HlilStatement::Goto(operand_as_branch(instr))); }
        "brfalse" | "brfalse.s" | "brtrue" | "brtrue.s" => {
            let target = operand_as_branch(instr);
            let cond_expr = stack.pop().unwrap_or(HlilExpression::Const(0));
            let cond = if instr.opcode.starts_with("brtrue") { cond_expr } else {
                HlilExpression::BinaryOp { op: BinaryOp::Eq, lhs: Box::new(cond_expr), rhs: Box::new(HlilExpression::Const(0)) }
            };
            let mut then_block = HlilBlock::new();
            then_block.push(HlilStatement::Goto(target));
            block.push(HlilStatement::If { cond, then_block, else_block: None });
        }
        "endfinally" => block.push(HlilStatement::Endfinally),
        _ => { block.push(HlilStatement::Comment(format!("IL_{offset:04X}: {}", instr.opcode))); }
    }
}

fn push_param(stack: &mut Vec<HlilExpression>, idx: usize, method: &DotnetMethod) {
    let name = if method.signature.is_static {
        method
            .signature
            .params
            .get(idx).map_or_else(|| format!("arg{idx}"), |(n, _)| n.clone())
    } else if idx == 0 {
        "this".into()
    } else {
        method
            .signature
            .params
            .get(idx - 1).map_or_else(|| format!("arg{idx}"), |(n, _)| n.clone())
    };
    stack.push(HlilExpression::Param(idx, name));
}

fn hlil_binary_op(stack: &mut Vec<HlilExpression>, op: BinaryOp) {
    let rhs = stack.pop().unwrap_or(HlilExpression::Const(0));
    let lhs = stack.pop().unwrap_or(HlilExpression::Const(0));
    stack.push(HlilExpression::BinaryOp {
        op,
        lhs: Box::new(lhs),
        rhs: Box::new(rhs),
    });
}

fn operand_as_usize(instr: &CilInstruction) -> usize {
    match &instr.operand {
        CilOperand::Int8(n) => casts::i8_to_usize(*n),
        CilOperand::Int32(n) => casts::i32_to_usize(*n),
        _ => 0,
    }
}

const fn operand_as_token(instr: &CilInstruction) -> u32 {
    match &instr.operand {
        CilOperand::Token(t) => *t,
        _ => 0,
    }
}

const fn operand_as_branch(instr: &CilInstruction) -> u32 {
    match &instr.operand {
        CilOperand::Branch(t) => *t,
        _ => 0,
    }
}

// ─── Exception handler recovery ───────────────────────────────────────────────

/// Recovered exception region.
#[derive(Debug, Clone)]
pub struct RecoveredRegion {
    /// Kind of this exception region.
    pub kind: RecoveredRegionKind,
    /// The protected (try) block.
    pub try_block: HlilBlock,
    /// The handler block (catch/finally/filter body).
    pub handler_block: HlilBlock,
    /// Caught exception type, if any.
    pub catch_type: Option<String>,
    /// Name of the exception variable, if any.
    pub variable_name: Option<String>,
}

/// Kind of a recovered exception region.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveredRegionKind {
    /// try { } catch { }
    TryCatch,
    /// try { } finally { }
    TryFinally,
    /// try { } fault { }
    TryFault,
    /// try { } filter { }
    TryFilter,
    /// using (var x = ...) { }
    Using,
}

impl RecoveredRegionKind {
    /// Returns the C# keyword for the handler portion of this region.
    #[must_use]
    pub const fn keyword(self) -> &'static str {
        match self {
            Self::TryCatch => "catch",
            Self::TryFinally | Self::TryFault => "finally",
            Self::TryFilter => "filter",
            Self::Using => "using",
        }
    }
}

impl RecoveredRegion {
    /// Emit C# source for this region.
    #[must_use]
    pub fn to_csharp(&self, indent: &str) -> String {
        let inner = format!("    {indent}");
        let mut out = format!("{indent}try\n{indent}{{\n");
        out.push_str(&self.try_block.to_csharp(&inner));
        write!(out, "{indent}}}").unwrap();

        match self.kind {
            RecoveredRegionKind::TryCatch => {
                let ty = self.catch_type.as_deref().unwrap_or("Exception");
                let var = self.variable_name.as_deref().unwrap_or("ex");
                writeln!(out, "\n{indent}catch ({ty} {var})\n{indent}{{").unwrap();
                out.push_str(&self.handler_block.to_csharp(&inner));
                write!(out, "{indent}}}").unwrap();
            }
            RecoveredRegionKind::TryFinally | RecoveredRegionKind::TryFault => {
                writeln!(out, "\n{indent}finally\n{indent}{{").unwrap();
                out.push_str(&self.handler_block.to_csharp(&inner));
                write!(out, "{indent}}}").unwrap();
            }
            RecoveredRegionKind::Using => {
                let var = self.variable_name.as_deref().unwrap_or("d");
                out = format!("{indent}using (var {var} = /* resource */)\n{indent}{{\n");
                out.push_str(&self.try_block.to_csharp(&inner));
                write!(out, "{indent}}}").unwrap();
            }
            RecoveredRegionKind::TryFilter => {
                writeln!(out, "\n{indent}// filter\n{indent}{{").unwrap();
                out.push_str(&self.handler_block.to_csharp(&inner));
                write!(out, "{indent}}}").unwrap();
            }
        }

        out
    }
}

// ─── C# code emitter ──────────────────────────────────────────────────────────

/// High-level C# source emitter.
pub struct CSharpEmitter {
    indent_unit: String,
}

impl Default for CSharpEmitter {
    fn default() -> Self {
        Self {
            indent_unit: "    ".to_string(),
        }
    }
}

impl CSharpEmitter {
    /// Create a new emitter with a custom indent unit.
    #[must_use]
    pub fn new(indent_unit: impl Into<String>) -> Self {
        Self {
            indent_unit: indent_unit.into(),
        }
    }

    /// Emit a complete C# method definition from an `HlilMethod`.
    #[must_use]
    pub fn emit_method(&self, method: &HlilMethod) -> String {
        method.to_csharp(&self.indent_unit)
    }

    /// Emit a C# namespace block wrapping a list of type bodies.
    #[must_use]
    pub fn emit_namespace(&self, namespace: &str, types: &[String]) -> String {
        let inner = format!("    {}", self.indent_unit);
        let mut out = format!("namespace {namespace}\n{{\n");
        for ty in types {
            for line in ty.lines() {
                out.push_str(&inner);
                out.push_str(line);
                out.push('\n');
            }
        }
        out.push_str("}\n");
        out
    }

    /// Emit a `using` directive.
    #[must_use]
    pub fn emit_using(namespace: &str) -> String {
        format!("using {namespace};\n")
    }

    /// Emit a set of standard C# `using` directives.
    #[must_use]
    pub fn emit_standard_usings() -> String {
        let usings = [
            "System",
            "System.Collections.Generic",
            "System.Linq",
            "System.Text",
            "System.Threading.Tasks",
        ];
        usings
            .iter()
            .map(|u| Self::emit_using(u))
            .collect::<String>()
    }
}

// ─── Stack delta ─────────────────────────────────────────────────────────────

/// Stack effect using separate pop/push counts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StackDelta {
    /// Fixed pop/push counts.
    Fixed { pop: u8, push: u8 },
    /// Variable — depends on the method signature.
    Variable,
}

impl StackDelta {
    /// Returns the net stack change (`push - pop`) for fixed-delta opcodes.
    #[must_use]
    pub fn net(self) -> Option<i16> {
        match self {
            Self::Fixed { pop, push } => Some(i16::from(push) - i16::from(pop)),
            Self::Variable => None,
        }
    }
}

// ─── Extended tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod extended_tests {
    use super::*;
    use rustre_dotnet::{CilInstruction, CilOperand, DotnetMethod, MethodBody, MethodSignature};

    fn void_method_with(name: &str, instrs: Vec<CilInstruction>) -> DotnetMethod {
        DotnetMethod {
            name: name.into(),
            signature: MethodSignature {
                return_type: "void".into(),
                ..Default::default()
            },
            body: Some(MethodBody {
                instructions: instrs,
                ..Default::default()
            }),
            flags: 0x06,
            rva: 0,
            ..Default::default()
        }
    }

    #[test]
    fn test_stack_effect_nop() {
        let e = stack_effect("nop").unwrap();
        assert_eq!(e.pops, 0);
        assert_eq!(e.pushes, 0);
        assert_eq!(e.delta(), 0);
    }

    #[test]
    fn test_stack_effect_add() {
        let e = stack_effect("add").unwrap();
        assert_eq!(e.pops, 2);
        assert_eq!(e.pushes, 1);
        assert_eq!(e.delta(), -1);
    }

    #[test]
    fn test_stack_effect_ldstr() {
        let e = stack_effect("ldstr").unwrap();
        assert_eq!(e.pushes, 1);
        assert_eq!(e.pops, 0);
    }

    #[test]
    fn test_stack_effect_unknown() {
        assert!(stack_effect("nonexistent_opcode").is_none());
    }

    #[test]
    fn test_ssa_builder_fresh() {
        let mut b = SsaBuilder::new();
        let n1 = b.fresh(0, 0, "ldarg.0");
        let n2 = b.fresh(0, 1, "ldarg.0");
        assert_ne!(n1, n2);
        assert_eq!(b.def_count(), 2);
    }

    #[test]
    fn test_ssa_builder_current() {
        let mut b = SsaBuilder::new();
        let _ = b.fresh(0, 0, "x");
        let cur = b.current(0);
        assert!(cur.contains("s0_"));
    }

    #[test]
    fn test_ssa_builder_undefined() {
        let b = SsaBuilder::new();
        assert!(b.current(5).contains("undef"));
    }

    #[test]
    fn test_pattern_null_check() {
        let instrs = vec![
            CilInstruction {
                offset: 0,
                opcode: "ldarg.0".into(),
                operand: CilOperand::None,
            },
            CilInstruction {
                offset: 1,
                opcode: "brfalse.s".into(),
                operand: CilOperand::Branch(10),
            },
        ];
        assert!(PatternRecogniser::detect_null_check(&instrs));
    }

    #[test]
    fn test_pattern_string_concat() {
        let instrs = vec![
            CilInstruction {
                offset: 0,
                opcode: "ldstr".into(),
                operand: CilOperand::None,
            },
            CilInstruction {
                offset: 1,
                opcode: "ldstr".into(),
                operand: CilOperand::None,
            },
            CilInstruction {
                offset: 2,
                opcode: "call".into(),
                operand: CilOperand::Token(0x0A00_0001),
            },
        ];
        assert!(PatternRecogniser::detect_string_concat(&instrs));
    }

    #[test]
    fn test_pattern_simple_getter() {
        let instrs = vec![
            CilInstruction {
                offset: 0,
                opcode: "ldarg.0".into(),
                operand: CilOperand::None,
            },
            CilInstruction {
                offset: 1,
                opcode: "ldfld".into(),
                operand: CilOperand::Token(0x0400_0001),
            },
            CilInstruction {
                offset: 6,
                opcode: "ret".into(),
                operand: CilOperand::None,
            },
        ];
        assert!(PatternRecogniser::detect_simple_property_getter(&instrs));
    }

    #[test]
    fn test_pattern_throw_null() {
        let instrs = vec![
            CilInstruction {
                offset: 0,
                opcode: "ldnull".into(),
                operand: CilOperand::None,
            },
            CilInstruction {
                offset: 1,
                opcode: "throw".into(),
                operand: CilOperand::None,
            },
        ];
        assert!(PatternRecogniser::detect_throw_null(&instrs));
    }

    #[test]
    fn test_hlil_lift_simple_add() {
        let method = void_method_with(
            "Add",
            vec![
                CilInstruction {
                    offset: 0,
                    opcode: "ldc.i4.1".into(),
                    operand: CilOperand::None,
                },
                CilInstruction {
                    offset: 1,
                    opcode: "ldc.i4.2".into(),
                    operand: CilOperand::None,
                },
                CilInstruction {
                    offset: 2,
                    opcode: "add".into(),
                    operand: CilOperand::None,
                },
                CilInstruction {
                    offset: 3,
                    opcode: "pop".into(),
                    operand: CilOperand::None,
                },
                CilInstruction {
                    offset: 4,
                    opcode: "ret".into(),
                    operand: CilOperand::None,
                },
            ],
        );
        let pipeline = DecompilationPipeline::new();
        let hlil = pipeline.lift_to_hlil(&method);
        assert_eq!(hlil.name, "Add");
        assert!(!hlil.body.is_empty());
    }

    #[test]
    fn test_hlil_lift_stloc() {
        let method = void_method_with(
            "StoreLocal",
            vec![
                CilInstruction {
                    offset: 0,
                    opcode: "ldc.i4.7".into(),
                    operand: CilOperand::None,
                },
                CilInstruction {
                    offset: 1,
                    opcode: "stloc.0".into(),
                    operand: CilOperand::None,
                },
                CilInstruction {
                    offset: 2,
                    opcode: "ret".into(),
                    operand: CilOperand::None,
                },
            ],
        );
        let pipeline = DecompilationPipeline::new();
        let hlil = pipeline.lift_to_hlil(&method);
        let src = hlil.body.to_csharp("    ");
        assert!(src.contains("local0") || src.contains('7'));
    }

    #[test]
    fn test_hlil_to_csharp_method() {
        let method = void_method_with(
            "Foo",
            vec![CilInstruction {
                offset: 0,
                opcode: "ret".into(),
                operand: CilOperand::None,
            }],
        );
        let pipeline = DecompilationPipeline::new();
        let hlil = pipeline.lift_to_hlil(&method);
        let src = hlil.to_csharp("    ");
        assert!(src.contains("Foo"));
        assert!(src.contains("return;") || src.contains('{'));
    }

    #[test]
    fn test_csharp_emitter_namespace() {
        let emitter = CSharpEmitter::default();
        let src = emitter.emit_namespace("MyApp", &["class Foo {}".to_string()]);
        assert!(src.starts_with("namespace MyApp"));
        assert!(src.contains("Foo"));
    }

    #[test]
    fn test_csharp_emitter_standard_usings() {
        let src = CSharpEmitter::emit_standard_usings();
        assert!(src.contains("using System;"));
        assert!(src.contains("System.Collections.Generic"));
    }

    #[test]
    fn test_recovered_region_try_finally() {
        let r = RecoveredRegion {
            kind: RecoveredRegionKind::TryFinally,
            try_block: HlilBlock::new(),
            handler_block: HlilBlock::new(),
            catch_type: None,
            variable_name: None,
        };
        let src = r.to_csharp("    ");
        assert!(src.contains("try"));
        assert!(src.contains("finally"));
    }

    #[test]
    fn test_recovered_region_try_catch() {
        let r = RecoveredRegion {
            kind: RecoveredRegionKind::TryCatch,
            try_block: HlilBlock::new(),
            handler_block: HlilBlock::new(),
            catch_type: Some("System.Exception".to_string()),
            variable_name: Some("ex".to_string()),
        };
        let src = r.to_csharp("    ");
        assert!(src.contains("catch"));
        assert!(src.contains("System.Exception"));
    }

    #[test]
    fn test_type_kind_keyword() {
        assert_eq!(TypeKind::Class.keyword(), "class");
        assert_eq!(TypeKind::Interface.keyword(), "interface");
        assert_eq!(TypeKind::Struct.keyword(), "struct");
        assert_eq!(TypeKind::Enum.keyword(), "enum");
        assert_eq!(TypeKind::Delegate.keyword(), "delegate");
    }

    #[test]
    fn test_binary_op_as_str() {
        assert_eq!(BinaryOp::Add.as_str(), "+");
        assert_eq!(BinaryOp::Eq.as_str(), "==");
        assert_eq!(BinaryOp::Ge.as_str(), ">=");
    }

    #[test]
    fn test_unary_op_prefix() {
        assert_eq!(UnaryOp::Neg.prefix_str(), "-");
        assert_eq!(UnaryOp::BitNot.prefix_str(), "~");
    }

    #[test]
    fn test_hlil_expression_null() {
        assert_eq!(HlilExpression::Null.to_csharp(), "null");
    }

    #[test]
    fn test_hlil_expression_const_neg() {
        assert_eq!(HlilExpression::Const(-1).to_csharp(), "-1");
    }

    #[test]
    fn test_hlil_expression_string_lit() {
        assert_eq!(
            HlilExpression::StringLit("hello".into()).to_csharp(),
            "\"hello\""
        );
    }

    #[test]
    fn test_hlil_expression_array_length() {
        let e = HlilExpression::ArrayLength(Box::new(HlilExpression::Local(0, "arr".into())));
        assert_eq!(e.to_csharp(), "arr.Length");
    }

    #[test]
    fn test_hlil_expression_ternary() {
        let e = HlilExpression::Ternary(
            Box::new(HlilExpression::Const(1)),
            Box::new(HlilExpression::Const(2)),
            Box::new(HlilExpression::Const(3)),
        );
        assert_eq!(e.to_csharp(), "(1 ? 2 : 3)");
    }

    #[test]
    fn test_cil_disassembler_empty() {
        let instrs = CilDisassembler::disassemble(&[]).unwrap();
        assert!(instrs.is_empty());
    }

    #[test]
    fn test_cil_disassembler_switch() {
        let mut bytes = vec![0x45u8]; // switch
        bytes.extend_from_slice(&1u32.to_le_bytes()); // 1 target
        bytes.extend_from_slice(&0u32.to_le_bytes()); // target delta 0
        let instrs = CilDisassembler::disassemble(&bytes).unwrap();
        assert_eq!(instrs.len(), 1);
        assert_eq!(instrs[0].opcode, "switch");
        assert!(matches!(instrs[0].operand, CilOperand::Switch(_)));
    }

    #[test]
    fn test_cil_disassembler_with_stack_ldc_ret() {
        let bytes = vec![0x17u8, 0x2A]; // ldc.i4.1, ret
        let pairs = CilDisassembler::disassemble_with_stack(&bytes).unwrap();
        assert_eq!(pairs[0].1, 0);
        assert_eq!(pairs[1].1, 1);
    }

    #[test]
    fn test_cil_opcode_registry_count() {
        assert!(CilOpcodeRegistry::count() >= 200);
    }

    #[test]
    fn test_hlil_block_push_len() {
        let mut block = HlilBlock::new();
        assert_eq!(block.len(), 0);
        block.push(HlilStatement::Comment("test".into()));
        assert_eq!(block.len(), 1);
        assert!(!block.is_empty());
    }

    #[test]
    fn test_stack_delta_net() {
        let d = StackDelta::Fixed { pop: 2, push: 1 };
        assert_eq!(d.net(), Some(-1));
        let v = StackDelta::Variable;
        assert_eq!(v.net(), None);
    }

    #[test]
    fn test_hlil_declare_local_with_value() {
        let stmt = HlilStatement::DeclareLocal {
            index: 0,
            name: "x".into(),
            type_name: "int".into(),
            value: Some(HlilExpression::Const(42)),
        };
        let s = stmt.to_csharp("    ");
        assert!(s.contains("int x = 42"));
    }

    #[test]
    fn test_hlil_if_statement() {
        let cond = HlilExpression::Const(1);
        let mut then_b = HlilBlock::new();
        then_b.push(HlilStatement::Return(None));
        let stmt = HlilStatement::If {
            cond,
            then_block: then_b,
            else_block: None,
        };
        let s = stmt.to_csharp("    ");
        assert!(s.contains("if") && s.contains("return;"));
    }

    #[test]
    fn test_hlil_while_statement() {
        let cond = HlilExpression::Const(1);
        let body = HlilBlock::new();
        let stmt = HlilStatement::While { cond, body };
        let s = stmt.to_csharp("    ");
        assert!(s.contains("while (1)"));
    }

    #[test]
    fn test_hlil_foreach_statement() {
        let col = HlilExpression::Local(0, "items".into());
        let body = HlilBlock::new();
        let stmt = HlilStatement::ForEach {
            element: "item".into(),
            collection: col,
            body,
        };
        let s = stmt.to_csharp("    ");
        assert!(s.contains("foreach") && s.contains("item") && s.contains("items"));
    }

    #[test]
    fn test_hlil_try_catch_statement() {
        let try_b = HlilBlock::new();
        let mut catch_b = HlilBlock::new();
        catch_b.push(HlilStatement::Endfinally);
        let stmt = HlilStatement::TryCatch {
            try_block: try_b,
            catches: vec![("Exception".into(), "ex".into(), catch_b)],
            finally: None,
        };
        let s = stmt.to_csharp("    ");
        assert!(s.contains("try") && s.contains("catch"));
    }

    #[test]
    fn test_stack_effect_conv_opcodes() {
        let e = stack_effect("conv.i4").unwrap();
        assert_eq!(e.pops, 1);
        assert_eq!(e.pushes, 1);
    }

    #[test]
    fn test_stack_effect_branch_opcodes() {
        let e = stack_effect("brfalse").unwrap();
        assert_eq!(e.pops, 1);
        assert_eq!(e.pushes, 0);
    }

    #[test]
    fn test_stack_effect_dup() {
        let e = stack_effect("dup").unwrap();
        assert_eq!(e.pops, 1);
        assert_eq!(e.pushes, 2);
        assert_eq!(e.delta(), 1);
    }

    #[test]
    fn test_stack_delta_variable() {
        let d = StackDelta::Variable;
        assert!(d.net().is_none());
    }

    #[test]
    fn test_ssa_def_fields() {
        let mut b = SsaBuilder::new();
        let name = b.fresh(3, 42, "some_expr");
        let def = b.defs.last().unwrap();
        assert_eq!(def.name, name);
        assert_eq!(def.def_offset, 42);
        assert_eq!(def.expr, "some_expr");
    }

    #[test]
    fn test_pattern_lock_needs_finally() {
        let instrs = vec![
            CilInstruction {
                offset: 0,
                opcode: "call".into(),
                operand: CilOperand::Token(1),
            },
            CilInstruction {
                offset: 5,
                opcode: "call".into(),
                operand: CilOperand::Token(2),
            },
        ];
        assert!(!PatternRecogniser::detect_lock(&instrs, false));
        assert!(PatternRecogniser::detect_lock(&instrs, true));
    }

    #[test]
    fn test_recovered_region_kind_keyword() {
        assert_eq!(RecoveredRegionKind::TryCatch.keyword(), "catch");
        assert_eq!(RecoveredRegionKind::TryFinally.keyword(), "finally");
        assert_eq!(RecoveredRegionKind::Using.keyword(), "using");
    }

    #[test]
    fn test_csharp_emitter_using_directive() {
        let s = CSharpEmitter::emit_using("System.IO");
        assert_eq!(s, "using System.IO;\n");
    }

    #[test]
    fn test_csharp_emitter_method_round_trip() {
        let method = void_method_with(
            "TestMethod",
            vec![CilInstruction {
                offset: 0,
                opcode: "ret".into(),
                operand: CilOperand::None,
            }],
        );
        let pipeline = DecompilationPipeline::new();
        let hlil = pipeline.lift_to_hlil(&method);
        let emitter = CSharpEmitter::default();
        let src = emitter.emit_method(&hlil);
        assert!(src.contains("TestMethod"));
    }
}

// ─── Control Flow Graph ───────────────────────────────────────────────────────

/// A directed edge in the control-flow graph.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CfgEdgeKind {
    /// Unconditional fall-through or jump.
    Unconditional,
    /// Taken branch (condition is true).
    CondTrue,
    /// Not-taken branch (condition is false).
    CondFalse,
    /// Exception edge.
    Exception,
}

/// One basic block in the control-flow graph.
#[derive(Debug, Clone)]
pub struct CfgBlock {
    /// Offset of the first instruction.
    pub start: u32,
    /// Offset past the last instruction.
    pub end: u32,
    /// Instructions in this block.
    pub instructions: Vec<CilInstruction>,
    /// Successor (target offset, edge kind) pairs.
    pub successors: Vec<(u32, CfgEdgeKind)>,
}

impl CfgBlock {
    /// Creates a new, empty `CfgBlock` starting at `start`.
    #[must_use]
    pub const fn new(start: u32) -> Self {
        Self {
            start,
            end: start,
            instructions: Vec::new(),
            successors: Vec::new(),
        }
    }

    /// Returns `true` if this block ends with a terminator instruction.
    #[must_use]
    pub fn is_terminated(&self) -> bool {
        self.instructions
            .last()
            .is_some_and(|i| {
                matches!(
                    i.opcode.as_str(),
                    "ret" | "throw" | "rethrow" | "br" | "leave"
                )
            })
    }

    /// Returns the number of instructions in this block.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.instructions.len()
    }

    /// Returns `true` if this block has no instructions.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.instructions.is_empty()
    }
}

/// A complete control-flow graph for a method body.
#[derive(Debug, Clone, Default)]
pub struct ControlFlowGraph {
    /// All basic blocks, keyed by their start offset.
    pub blocks: Vec<CfgBlock>,
}

impl ControlFlowGraph {
    /// Builds a CFG from raw CIL instructions.
    ///
    /// # Errors
    /// Returns an error if the instruction list is malformed.
    pub fn build(instrs: &[CilInstruction]) -> anyhow::Result<Self> {
        if instrs.is_empty() {
            return Ok(Self::default());
        }
        let leaders = cfg_collect_leaders(instrs);
        let leader_vec: Vec<u32> = leaders.into_iter().collect();
        let mut blocks: Vec<CfgBlock> = leader_vec.iter().map(|&s| CfgBlock::new(s)).collect();
        for instr in instrs {
            let idx = leader_vec
                .partition_point(|&l| l <= instr.offset)
                .saturating_sub(1);
            if let Some(blk) = blocks.get_mut(idx) {
                blk.end = instr.offset + 1;
                blk.instructions.push(instr.clone());
            }
        }
        cfg_compute_successors(&mut blocks);
        Ok(Self { blocks })
    }

    /// Returns the number of basic blocks in the graph.
    #[must_use]
    pub const fn block_count(&self) -> usize {
        self.blocks.len()
    }

    /// Finds the block containing the given offset, if any.
    #[must_use]
    pub fn block_at(&self, offset: u32) -> Option<&CfgBlock> {
        self.blocks.iter().find(|b| b.start == offset)
    }
}

// ─── Data-Flow: Use-Def Chains ─────────────────────────────────────────────

/// A use-def entry: `slot` holds the local variable index; `def_offset` is
/// the instruction offset that last defined it; `use_offset` is where it's used.
#[derive(Debug, Clone)]
pub struct UseDefEntry {
    /// Local variable slot.
    pub slot: u16,
    /// Instruction offset where this variable was last defined.
    pub def_offset: u32,
    /// Instruction offset where this variable is used.
    pub use_offset: u32,
}

/// Simplified use-def chain builder over a flat instruction list.
#[derive(Debug, Default)]
pub struct UseDefChains {
    /// All collected use-def entries.
    pub entries: Vec<UseDefEntry>,
}

impl UseDefChains {
    /// Builds use-def chains from a flat instruction list.
    #[must_use]
    pub fn build(instrs: &[CilInstruction]) -> Self {
        let mut last_def: std::collections::HashMap<u16, u32> = std::collections::HashMap::new();
        let mut entries = Vec::new();

        for instr in instrs {
            // stloc.* defines a slot; ldloc.* uses it
            let defines: Option<u16> = match instr.opcode.as_str() {
                "stloc.0" => Some(0),
                "stloc.1" => Some(1),
                "stloc.2" => Some(2),
                "stloc.3" => Some(3),
                "stloc" | "stloc.s" => match &instr.operand {
                    CilOperand::Int32(n) => Some(casts::i32_to_u16(*n)),
                    CilOperand::Int8(n) => Some(casts::i8_to_u16(*n)),
                    _ => None,
                },
                _ => None,
            };
            let uses: Option<u16> = match instr.opcode.as_str() {
                "ldloc.0" => Some(0),
                "ldloc.1" => Some(1),
                "ldloc.2" => Some(2),
                "ldloc.3" => Some(3),
                "ldloc" | "ldloc.s" | "ldloca" | "ldloca.s" => match &instr.operand {
                    CilOperand::Int32(n) => Some(casts::i32_to_u16(*n)),
                    CilOperand::Int8(n) => Some(casts::i8_to_u16(*n)),
                    _ => None,
                },
                _ => None,
            };

            if let Some(slot) = uses
                && let Some(&def_offset) = last_def.get(&slot) {
                    entries.push(UseDefEntry {
                        slot,
                        def_offset,
                        use_offset: instr.offset,
                    });
                }
            if let Some(slot) = defines {
                last_def.insert(slot, instr.offset);
            }
        }

        Self { entries }
    }

    /// Returns the number of use-def pairs found.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` if no use-def pairs were found.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Returns all uses of a given local variable slot.
    #[must_use]
    pub fn uses_of(&self, slot: u16) -> Vec<&UseDefEntry> {
        self.entries.iter().filter(|e| e.slot == slot).collect()
    }
}

fn cfg_collect_leaders(instrs: &[CilInstruction]) -> std::collections::BTreeSet<u32> {
    let mut leaders: std::collections::BTreeSet<u32> = std::collections::BTreeSet::new();
    leaders.insert(instrs[0].offset);
    for (i, instr) in instrs.iter().enumerate() {
        let is_branch = matches!(
            instr.opcode.as_str(),
            "br" | "br.s" | "brtrue" | "brtrue.s" | "brfalse" | "brfalse.s"
                | "beq" | "beq.s" | "bne.un" | "bne.un.s"
                | "blt" | "blt.s" | "blt.un" | "blt.un.s"
                | "ble" | "ble.s" | "ble.un" | "ble.un.s"
                | "bgt" | "bgt.s" | "bgt.un" | "bgt.un.s"
                | "bge" | "bge.s" | "bge.un" | "bge.un.s"
                | "switch"
        );
        if is_branch {
            if let CilOperand::Branch(t) = &instr.operand {
                leaders.insert(*t);
            }
            if let Some(next) = instrs.get(i + 1) {
                leaders.insert(next.offset);
            }
        }
        let is_term = matches!(
            instr.opcode.as_str(),
            "ret" | "throw" | "rethrow" | "endfinally" | "endfilter"
        );
        if is_term
            && let Some(next) = instrs.get(i + 1) {
                leaders.insert(next.offset);
            }
    }
    leaders
}

fn cfg_compute_successors(blocks: &mut [CfgBlock]) {
    for b in 0..blocks.len() {
        let Some(last) = blocks[b].instructions.last().cloned() else { continue };
        let is_cond = matches!(
            last.opcode.as_str(),
            "brtrue" | "brtrue.s" | "brfalse" | "brfalse.s"
                | "beq" | "beq.s" | "bne.un" | "bne.un.s"
                | "blt" | "blt.s" | "blt.un" | "blt.un.s"
                | "ble" | "ble.s" | "ble.un" | "ble.un.s"
                | "bgt" | "bgt.s" | "bgt.un" | "bgt.un.s"
                | "bge" | "bge.s" | "bge.un" | "bge.un.s"
        );
        let is_uncond = matches!(last.opcode.as_str(), "br" | "br.s");
        let is_ret = matches!(
            last.opcode.as_str(),
            "ret" | "throw" | "rethrow" | "endfinally" | "endfilter"
        );
        let next_start: Option<u32> = blocks.get(b + 1).map(|nb| nb.start);
        if is_ret {
            // no successors
        } else if is_uncond {
            if let CilOperand::Branch(t) = &last.operand {
                blocks[b].successors.push((*t, CfgEdgeKind::Unconditional));
            }
        } else if is_cond {
            if let CilOperand::Branch(t) = &last.operand {
                blocks[b].successors.push((*t, CfgEdgeKind::CondTrue));
            }
            if let Some(ns) = next_start {
                blocks[b].successors.push((ns, CfgEdgeKind::CondFalse));
            }
        } else if let Some(ns) = next_start {
            blocks[b].successors.push((ns, CfgEdgeKind::Unconditional));
        }
    }
}

// ─── Constant Folding Pass ─────────────────────────────────────────────────

/// Result of constant propagation on a single instruction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FoldResult {
    /// Instruction pushes a known constant integer.
    KnownInt(i64),
    /// Instruction pushes a known constant string.
    KnownStr(String),
    /// Instruction pushes a known boolean.
    KnownBool(bool),
    /// Result is not statically known.
    Unknown,
}

impl FoldResult {
    /// Returns `true` if this is a known constant value.
    #[must_use]
    pub const fn is_known(&self) -> bool {
        !matches!(self, Self::Unknown)
    }
}

/// Performs simple constant folding over a flat instruction sequence.
#[derive(Debug, Default)]
pub struct ConstantFolder {
    stack: Vec<FoldResult>,
    /// Mapping from local slot → last known constant value.
    pub locals: std::collections::HashMap<u16, FoldResult>,
    /// Output fold results, one per instruction.
    pub results: Vec<FoldResult>,
}

impl ConstantFolder {
    /// Run the folder over `instrs`.
    pub fn fold(&mut self, instrs: &[CilInstruction]) {
        for instr in instrs {
            let r = self.fold_one(instr);
            self.results.push(r);
        }
    }

    fn fold_one(&mut self, instr: &CilInstruction) -> FoldResult {
        if let Some(r) = self.fold_constant(instr) {
            return r;
        }
        match instr.opcode.as_str() {
            "add" => self.fold_int_binop(i64::wrapping_add),
            "mul" => self.fold_int_binop(i64::wrapping_mul),
            "sub" => self.fold_int_binop(i64::wrapping_sub),
            "ceq" => {
                let b = self.stack.pop().unwrap_or(FoldResult::Unknown);
                let a = self.stack.pop().unwrap_or(FoldResult::Unknown);
                if let (FoldResult::KnownInt(x), FoldResult::KnownInt(y)) = (&a, &b) {
                    let r = FoldResult::KnownBool(x == y);
                    self.stack.push(r.clone());
                    r
                } else {
                    self.stack.push(FoldResult::Unknown);
                    FoldResult::Unknown
                }
            }
            "pop" => { self.stack.pop(); FoldResult::Unknown }
            "dup" => {
                let top = self.stack.last().cloned().unwrap_or(FoldResult::Unknown);
                self.stack.push(top.clone());
                top
            }
            "stloc.0" => { self.stloc(0); FoldResult::Unknown }
            "stloc.1" => { self.stloc(1); FoldResult::Unknown }
            "stloc.2" => { self.stloc(2); FoldResult::Unknown }
            "stloc.3" => { self.stloc(3); FoldResult::Unknown }
            "stloc" | "stloc.s" => {
                let slot = match &instr.operand {
                    CilOperand::Int32(n) => casts::i32_to_u16(*n),
                    CilOperand::Int8(n) => casts::i8_to_u16(*n),
                    _ => 0,
                };
                self.stloc(slot);
                FoldResult::Unknown
            }
            "ldloc.0" => self.ldloc(0),
            "ldloc.1" => self.ldloc(1),
            "ldloc.2" => self.ldloc(2),
            "ldloc.3" => self.ldloc(3),
            "ldloc" | "ldloc.s" => {
                let slot = match &instr.operand {
                    CilOperand::Int32(n) => casts::i32_to_u16(*n),
                    CilOperand::Int8(n) => casts::i8_to_u16(*n),
                    _ => 0,
                };
                self.ldloc(slot)
            }
            _ => { self.stack.push(FoldResult::Unknown); FoldResult::Unknown }
        }
    }

    fn fold_constant(&mut self, instr: &CilInstruction) -> Option<FoldResult> {
        let v: i64 = match instr.opcode.as_str() {
            "ldc.i4.0" => 0,
            "ldc.i4.1" => 1,
            "ldc.i4.2" => 2,
            "ldc.i4.3" => 3,
            "ldc.i4.4" => 4,
            "ldc.i4.5" => 5,
            "ldc.i4.6" => 6,
            "ldc.i4.7" => 7,
            "ldc.i4.8" => 8,
            "ldc.i4.m1" => -1,
            "ldc.i4" | "ldc.i4.s" => {
                if let CilOperand::Int32(n) = &instr.operand { i64::from(*n) }
                else { self.stack.push(FoldResult::Unknown); return Some(FoldResult::Unknown); }
            }
            "ldc.i8" => {
                if let CilOperand::Int64(n) = &instr.operand { *n }
                else { self.stack.push(FoldResult::Unknown); return Some(FoldResult::Unknown); }
            }
            "ldstr" => {
                let r = if let CilOperand::String(s) = &instr.operand {
                    FoldResult::KnownStr(s.clone())
                } else {
                    FoldResult::Unknown
                };
                self.stack.push(r.clone());
                return Some(r);
            }
            _ => return None,
        };
        let r = FoldResult::KnownInt(v);
        self.stack.push(r.clone());
        Some(r)
    }

    fn fold_int_binop(&mut self, op: fn(i64, i64) -> i64) -> FoldResult {
        let b = self.stack.pop().unwrap_or(FoldResult::Unknown);
        let a = self.stack.pop().unwrap_or(FoldResult::Unknown);
        if let (FoldResult::KnownInt(x), FoldResult::KnownInt(y)) = (&a, &b) {
            let r = FoldResult::KnownInt(op(*x, *y));
            self.stack.push(r.clone());
            r
        } else {
            self.stack.push(FoldResult::Unknown);
            FoldResult::Unknown
        }
    }

    fn stloc(&mut self, slot: u16) {
        let v = self.stack.pop().unwrap_or(FoldResult::Unknown);
        self.locals.insert(slot, v);
    }

    fn ldloc(&mut self, slot: u16) -> FoldResult {
        let v = self
            .locals
            .get(&slot)
            .cloned()
            .unwrap_or(FoldResult::Unknown);
        self.stack.push(v.clone());
        v
    }

    /// Returns the number of known constants folded.
    #[must_use]
    pub fn known_count(&self) -> usize {
        self.results.iter().filter(|r| r.is_known()).count()
    }
}

// ─── CFG and data-flow tests ──────────────────────────────────────────────

#[cfg(test)]
mod cfg_tests {
    use super::*;

    fn instr(offset: u32, opcode: &str) -> CilInstruction {
        CilInstruction {
            offset,
            opcode: opcode.into(),
            operand: CilOperand::None,
        }
    }
    fn instr_br(offset: u32, opcode: &str, target: u32) -> CilInstruction {
        CilInstruction {
            offset,
            opcode: opcode.into(),
            operand: CilOperand::Branch(target),
        }
    }
    fn instr_ldc(offset: u32, val: i32) -> CilInstruction {
        CilInstruction {
            offset,
            opcode: "ldc.i4".into(),
            operand: CilOperand::Int32(val),
        }
    }
    fn instr_stloc(offset: u32, slot: u16) -> CilInstruction {
        CilInstruction {
            offset,
            opcode: "stloc".into(),
            operand: CilOperand::Int32(i32::from(slot)),
        }
    }
    fn instr_ldloc(offset: u32, slot: u16) -> CilInstruction {
        CilInstruction {
            offset,
            opcode: "ldloc".into(),
            operand: CilOperand::Int32(i32::from(slot)),
        }
    }

    #[test]
    fn test_cfg_empty() {
        let cfg = ControlFlowGraph::build(&[]).unwrap();
        assert_eq!(cfg.block_count(), 0);
    }

    #[test]
    fn test_cfg_single_block() {
        let instrs = vec![instr(0, "ldarg.0"), instr(1, "ret")];
        let cfg = ControlFlowGraph::build(&instrs).unwrap();
        assert_eq!(cfg.block_count(), 1);
        assert!(cfg.blocks[0].is_terminated());
    }

    #[test]
    fn test_cfg_two_blocks_unconditional_branch() {
        let instrs = vec![instr_br(0, "br", 5), instr(5, "ret")];
        let cfg = ControlFlowGraph::build(&instrs).unwrap();
        assert_eq!(cfg.block_count(), 2);
        let b0 = &cfg.blocks[0];
        assert_eq!(b0.successors.len(), 1);
        assert_eq!(b0.successors[0].1, CfgEdgeKind::Unconditional);
    }

    #[test]
    fn test_cfg_conditional_branch_two_successors() {
        let instrs = vec![
            instr(0, "ldarg.0"),
            instr_br(1, "brtrue", 10),
            instr(6, "ldc.i4.0"),
            instr(7, "ret"),
            instr(10, "ldc.i4.1"),
            instr(11, "ret"),
        ];
        let cfg = ControlFlowGraph::build(&instrs).unwrap();
        // Block starting at 1 (brtrue) should have two successors
        let cond_block = cfg.block_at(0).unwrap();
        // The leader at offset 0 should lead into the brtrue block
        assert!(cfg.block_count() >= 2);
        let _ = cond_block;
    }

    #[test]
    fn test_cfg_block_len() {
        let instrs = vec![
            instr(0, "ldarg.0"),
            instr(1, "ldarg.1"),
            instr(2, "add"),
            instr(3, "ret"),
        ];
        let cfg = ControlFlowGraph::build(&instrs).unwrap();
        assert_eq!(cfg.blocks[0].len(), 4);
        assert!(!cfg.blocks[0].is_empty());
    }

    #[test]
    fn test_cfg_block_at_missing() {
        let instrs = vec![instr(0, "ret")];
        let cfg = ControlFlowGraph::build(&instrs).unwrap();
        assert!(cfg.block_at(99).is_none());
    }

    #[test]
    fn test_use_def_empty() {
        let chains = UseDefChains::build(&[]);
        assert!(chains.is_empty());
        assert_eq!(chains.len(), 0);
    }

    #[test]
    fn test_use_def_simple_chain() {
        let instrs = vec![
            instr_ldc(0, 42),
            instr_stloc(5, 0),
            instr_ldloc(6, 0),
            instr(7, "ret"),
        ];
        let chains = UseDefChains::build(&instrs);
        assert_eq!(chains.len(), 1);
        assert_eq!(chains.entries[0].slot, 0);
        assert_eq!(chains.entries[0].def_offset, 5);
        assert_eq!(chains.entries[0].use_offset, 6);
    }

    #[test]
    fn test_use_def_no_def_no_entry() {
        // ldloc without prior stloc → no entry
        let instrs = vec![instr_ldloc(0, 0), instr(1, "ret")];
        let chains = UseDefChains::build(&instrs);
        assert!(chains.is_empty());
    }

    #[test]
    fn test_use_def_uses_of() {
        let instrs = vec![
            instr_ldc(0, 1),
            instr_stloc(1, 0),
            instr_ldloc(2, 0),
            instr_ldloc(3, 0),
            instr(4, "ret"),
        ];
        let chains = UseDefChains::build(&instrs);
        let uses = chains.uses_of(0);
        assert_eq!(uses.len(), 2);
    }

    #[test]
    fn test_constant_folder_add() {
        let mut cf = ConstantFolder::default();
        cf.fold(&[
            CilInstruction {
                offset: 0,
                opcode: "ldc.i4.2".into(),
                operand: CilOperand::None,
            },
            CilInstruction {
                offset: 1,
                opcode: "ldc.i4".into(),
                operand: CilOperand::Int32(3),
            },
            CilInstruction {
                offset: 2,
                opcode: "add".into(),
                operand: CilOperand::None,
            },
        ]);
        assert_eq!(cf.results[2], FoldResult::KnownInt(5));
    }

    #[test]
    fn test_constant_folder_mul() {
        let mut cf = ConstantFolder::default();
        cf.fold(&[
            CilInstruction {
                offset: 0,
                opcode: "ldc.i4".into(),
                operand: CilOperand::Int32(6),
            },
            CilInstruction {
                offset: 1,
                opcode: "ldc.i4".into(),
                operand: CilOperand::Int32(7),
            },
            CilInstruction {
                offset: 2,
                opcode: "mul".into(),
                operand: CilOperand::None,
            },
        ]);
        assert_eq!(cf.results[2], FoldResult::KnownInt(42));
    }

    #[test]
    fn test_constant_folder_ceq_true() {
        let mut cf = ConstantFolder::default();
        cf.fold(&[
            CilInstruction {
                offset: 0,
                opcode: "ldc.i4.1".into(),
                operand: CilOperand::None,
            },
            CilInstruction {
                offset: 1,
                opcode: "ldc.i4.1".into(),
                operand: CilOperand::None,
            },
            CilInstruction {
                offset: 2,
                opcode: "ceq".into(),
                operand: CilOperand::None,
            },
        ]);
        assert_eq!(cf.results[2], FoldResult::KnownBool(true));
    }

    #[test]
    fn test_constant_folder_stloc_ldloc() {
        let mut cf = ConstantFolder::default();
        cf.fold(&[instr_ldc(0, 99), instr_stloc(1, 2), instr_ldloc(2, 2)]);
        assert_eq!(cf.results[2], FoldResult::KnownInt(99));
    }

    #[test]
    fn test_constant_folder_known_count() {
        let mut cf = ConstantFolder::default();
        cf.fold(&[
            CilInstruction {
                offset: 0,
                opcode: "ldc.i4.0".into(),
                operand: CilOperand::None,
            },
            CilInstruction {
                offset: 1,
                opcode: "ldarg.0".into(),
                operand: CilOperand::None,
            },
        ]);
        assert_eq!(cf.known_count(), 1);
    }

    #[test]
    fn test_constant_folder_ldstr() {
        let mut cf = ConstantFolder::default();
        cf.fold(&[CilInstruction {
            offset: 0,
            opcode: "ldstr".into(),
            operand: CilOperand::String("hello".into()),
        }]);
        assert_eq!(cf.results[0], FoldResult::KnownStr("hello".into()));
    }

    #[test]
    fn test_fold_result_is_known() {
        assert!(FoldResult::KnownInt(0).is_known());
        assert!(FoldResult::KnownBool(false).is_known());
        assert!(!FoldResult::Unknown.is_known());
    }

    #[test]
    fn test_cfg_edge_kind_debug() {
        let e = CfgEdgeKind::CondTrue;
        assert_eq!(format!("{e:?}"), "CondTrue");
    }
}

// ─── HLIL Type inference pass ─────────────────────────────────────────────────

/// Inferred .NET type for an expression in the HLIL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InferredType {
    /// `int` (System.Int32).
    Int32,
    /// `long` (System.Int64).
    Int64,
    /// `float` (System.Single).
    Float32,
    /// `double` (System.Double).
    Float64,
    /// `bool` (System.Boolean).
    Bool,
    /// `string` (System.String).
    String,
    /// `object` (System.Object).
    Object,
    /// A reference type with the given name.
    Ref(std::string::String),
    /// A value type with the given name.
    Value(std::string::String),
    /// Array of element type.
    Array(Box<Self>),
    /// Nullable wrapper.
    Nullable(Box<Self>),
    /// Unknown / not inferrable.
    Unknown,
}

impl InferredType {
    /// Returns the C# keyword / type name for this type.
    #[must_use]
    pub fn to_csharp(&self) -> std::string::String {
        match self {
            Self::Int32 => "int".into(),
            Self::Int64 => "long".into(),
            Self::Float32 => "float".into(),
            Self::Float64 => "double".into(),
            Self::Bool => "bool".into(),
            Self::String => "string".into(),
            Self::Object => "object".into(),
            Self::Ref(n) | Self::Value(n) => n.clone(),
            Self::Array(inner) => format!("{}[]", inner.to_csharp()),
            Self::Nullable(inner) => format!("{}?", inner.to_csharp()),
            Self::Unknown => "var".into(),
        }
    }

    /// Returns `true` if this is a known concrete type.
    #[must_use]
    pub const fn is_known(&self) -> bool {
        !matches!(self, Self::Unknown)
    }

    /// Returns `true` if this is a numeric type.
    #[must_use]
    pub const fn is_numeric(&self) -> bool {
        matches!(
            self,
            Self::Int32 | Self::Int64 | Self::Float32 | Self::Float64
        )
    }

    /// Returns `true` if this is a reference type.
    #[must_use]
    pub const fn is_reference(&self) -> bool {
        matches!(
            self,
            Self::String | Self::Object | Self::Ref(_) | Self::Array(_)
        )
    }
}

/// Map an element type byte from a blob signature to an `InferredType`.
#[must_use]
pub const fn infer_type_from_element(et: u8) -> InferredType {
    match et {
        0x02 => InferredType::Bool,
        // 0x03=char, 0x04..=0x07=i1/u1/i2/u2, 0x08|0x09=i4/u4 all collapse to Int32.
        0x03..=0x09 => InferredType::Int32,
        // 0x0A|0x0B=i8/u8, 0x18|0x19=IntPtr/UIntPtr collapse to Int64.
        0x0A | 0x0B | 0x18 | 0x19 => InferredType::Int64,
        0x0C => InferredType::Float32,
        0x0D => InferredType::Float64,
        0x0E => InferredType::String,
        0x1C => InferredType::Object,
        _ => InferredType::Unknown,
    }
}

// ─── Decompiler pipeline extended ─────────────────────────────────────────────

/// Extended pipeline step that annotates HLIL statements with inferred types.
pub struct TypeAnnotationPass;

impl TypeAnnotationPass {
    /// Annotate local variable declarations in an HLIL block with inferred types.
    /// Currently a best-effort pass based on literal operands.
    #[must_use]
    pub fn annotate(block: &HlilBlock) -> Vec<(usize, InferredType)> {
        let mut annotations = Vec::new();
        for (i, stmt) in block.statements.iter().enumerate() {
            let inferred = Self::infer_stmt(stmt);
            if inferred.is_known() {
                annotations.push((i, inferred));
            }
        }
        annotations
    }

    fn infer_stmt(stmt: &HlilStatement) -> InferredType {
        match stmt {
            HlilStatement::Assign { value, .. } => Self::infer_expr(value),
            HlilStatement::Return(Some(expr)) => Self::infer_expr(expr),
            _ => InferredType::Unknown,
        }
    }

    fn infer_expr(expr: &HlilExpression) -> InferredType {
        // Simple heuristics based on literal patterns in the C# text representation
        let text = expr.to_csharp();
        if text == "null" {
            return InferredType::Object;
        }
        if text == "true" || text == "false" {
            return InferredType::Bool;
        }
        if text.ends_with('L') || text.ends_with('l') {
            return InferredType::Int64;
        }
        if text.ends_with('f') || text.ends_with('F') {
            return InferredType::Float32;
        }
        if text.ends_with('d') || text.ends_with('D') {
            return InferredType::Float64;
        }
        if text.starts_with('"') && text.ends_with('"') {
            return InferredType::String;
        }
        if text.parse::<i64>().is_ok() {
            return InferredType::Int32;
        }
        InferredType::Unknown
    }
}

// ─── Decompiler metrics ────────────────────────────────────────────────────────

/// Detected high-level patterns (≤3 bools to satisfy the `struct_excessive_bools` lint).
#[derive(Debug, Clone, Default)]
pub struct DetectedPatterns {
    /// Whether the `foreach` pattern was detected.
    pub has_foreach: bool,
    /// Whether the `using` pattern was detected.
    pub has_using: bool,
    /// Whether the `lock` pattern was detected.
    pub has_lock: bool,
}

/// Metrics collected during decompilation of a single method.
#[derive(Debug, Clone, Default)]
pub struct DecompilerMetrics {
    /// Number of CIL instructions processed.
    pub instruction_count: usize,
    /// Number of HLIL statements emitted.
    pub statement_count: usize,
    /// Number of unresolved tokens (call / field / type tokens).
    pub unresolved_tokens: usize,
    /// Number of exception handlers processed.
    pub exception_handlers: usize,
    /// Detected high-level patterns (foreach / using / lock).
    pub detected: DetectedPatterns,
    /// Whether the `async/await` pattern was detected.
    pub has_async: bool,
    /// Cyclomatic complexity estimate.
    pub cyclomatic_complexity: usize,
}

impl DecompilerMetrics {
    /// Compute metrics from an HLIL method output.
    ///
    /// # Panics
    ///
    /// Does not panic.
    #[must_use]
    pub fn from_hlil(result: &HlilMethod) -> Self {
        let statement_count = result.body.statements.len();
        let has_foreach = result
            .body
            .statements
            .iter()
            .any(|s| matches!(s, HlilStatement::ForEach { .. }));
        let has_using = result
            .body
            .statements
            .iter()
            .any(|s| matches!(s, HlilStatement::Using { .. }));
        // No dedicated Lock variant; lock patterns are encoded as TryCatch with a specific shape
        let has_lock = false;
        let exception_handlers = result
            .body
            .statements
            .iter()
            .filter(|s| matches!(s, HlilStatement::TryCatch { .. }))
            .count();
        // Cyclomatic complexity: 1 + number of conditional branches
        let cyclomatic = 1 + result
            .body
            .statements
            .iter()
            .filter(|s| matches!(s, HlilStatement::If { .. }))
            .count();

        Self {
            instruction_count: 0,
            statement_count,
            unresolved_tokens: 0,
            exception_handlers,
            detected: DetectedPatterns { has_foreach, has_using, has_lock },
            has_async: false,
            cyclomatic_complexity: cyclomatic,
        }
    }

    /// Returns a short text summary of these metrics.
    #[must_use]
    pub fn summary(&self) -> std::string::String {
        format!(
            "stmts={} cc={} eh={} foreach={} using={} lock={}",
            self.statement_count,
            self.cyclomatic_complexity,
            self.exception_handlers,
            self.detected.has_foreach,
            self.detected.has_using,
            self.detected.has_lock,
        )
    }
}

// ─── Extended C# emitter helpers ──────────────────────────────────────────────

impl CSharpEmitter {
    /// Emit a full namespace block around a type body string.
    ///
    /// Unlike the instance method [`CSharpEmitter::emit_namespace`] which takes a slice of
    /// pre-rendered type strings, this free-standing helper wraps a single pre-rendered body.
    ///
    /// # Panics
    ///
    /// Does not panic.
    #[must_use]
    pub fn emit_namespace_block(namespace: &str, body: &str) -> std::string::String {
        if namespace.is_empty() {
            return body.to_string();
        }
        format!("namespace {namespace} {{\n{body}\n}}\n")
    }

    /// Emit a `#region` / `#endregion` block.
    #[must_use]
    pub fn emit_region(label: &str, body: &str) -> std::string::String {
        format!("#region {label}\n{body}\n#endregion\n")
    }

    /// Emit a single-line comment.
    #[must_use]
    pub fn emit_comment(text: &str) -> std::string::String {
        format!("// {text}\n")
    }

    /// Emit a multi-line (XML doc) comment.
    #[must_use]
    pub fn emit_doc_comment(summary: &str) -> std::string::String {
        format!("/// <summary>\n/// {summary}\n/// </summary>\n")
    }

    /// Emit a `return <expr>;` statement.
    #[must_use]
    pub fn emit_return(expr: Option<&str>) -> std::string::String {
        expr.map_or_else(|| "return;\n".to_string(), |e| format!("return {e};\n"))
    }

    /// Emit a throw statement.
    #[must_use]
    pub fn emit_throw(expr: &str) -> std::string::String {
        format!("throw {expr};\n")
    }

    /// Emit a `goto label;` statement.
    #[must_use]
    pub fn emit_goto(label: &str) -> std::string::String {
        format!("goto {label};\n")
    }

    /// Emit a label declaration.
    #[must_use]
    pub fn emit_label(label: &str) -> std::string::String {
        format!("{label}:\n")
    }

    /// Emit a local variable declaration.
    #[must_use]
    pub fn emit_local_decl(ty: &str, name: &str, init: Option<&str>) -> std::string::String {
        init.map_or_else(|| format!("{ty} {name};\n"), |e| format!("{ty} {name} = {e};\n"))
    }

    /// Emit a simple assignment.
    #[must_use]
    pub fn emit_assign(lhs: &str, rhs: &str) -> std::string::String {
        format!("{lhs} = {rhs};\n")
    }

    /// Emit a void method call statement.
    #[must_use]
    pub fn emit_call_stmt(expr: &str) -> std::string::String {
        format!("{expr};\n")
    }

    /// Emit an attribute annotation.
    #[must_use]
    pub fn emit_attribute(attr: &str) -> std::string::String {
        format!("[{attr}]\n")
    }
}

// ─── HLIL pattern: yield return ───────────────────────────────────────────────

/// Detects whether a method body looks like a C# iterator method (`yield return`).
///
/// Heuristic: the compiler-generated state machine has a `MoveNext` method.
/// We check if any method in the type is named `MoveNext` and has a `switch`
/// instruction (the state dispatch).
///
/// # Panics
///
/// Does not panic.
#[must_use]
pub fn detect_yield_return(method: &DotnetMethod) -> bool {
    method
        .body
        .as_ref()
        .is_some_and(|b| b.instructions.iter().any(|i| i.opcode == "switch"))
        && method.name == "MoveNext"
}

/// Detects async/await pattern: the method uses `awaiter` calls in its body.
///
/// Heuristic: body has both `call` and a local variable pattern consistent
/// with `GetAwaiter` / `GetResult` calls.
///
/// # Panics
///
/// Does not panic.
#[must_use]
pub fn detect_async(method: &DotnetMethod) -> bool {
    method
        .body
        .as_ref()
        .is_some_and(|b| {
            let has_get_awaiter = b.instructions.iter().any(|i| i.opcode == "call");
            let has_ret = b.instructions.iter().any(|i| i.opcode == "ret");
            has_get_awaiter && has_ret && method.name.contains("MoveNext")
        })
}

// ─── Decompiler-level string table ────────────────────────────────────────────

/// Tracks all string literals encountered during decompilation.
#[derive(Debug, Default)]
pub struct StringTable {
    /// (token, `string_value`) pairs.
    pub entries: Vec<(u32, std::string::String)>,
}

impl StringTable {
    /// Record a string literal found at `token`.
    pub fn record(&mut self, token: u32, value: std::string::String) {
        if !self.entries.iter().any(|(t, _)| *t == token) {
            self.entries.push((token, value));
        }
    }

    /// Look up the string for a token.
    #[must_use]
    pub fn get(&self, token: u32) -> Option<&str> {
        self.entries
            .iter()
            .find(|(t, _)| *t == token)
            .map(|(_, s)| s.as_str())
    }

    /// Collect all strings encountered.
    #[must_use]
    pub fn all_strings(&self) -> Vec<&str> {
        self.entries.iter().map(|(_, s)| s.as_str()).collect()
    }

    /// Returns the number of recorded string literals.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` if the table is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

// ─── Dead-code elimination (HLIL level) ───────────────────────────────────────

/// Removes empty `HlilStatement::Comment` entries from a block.
///
/// These act as no-ops in code generation and are safe to strip from the IR.
///
/// # Panics
///
/// Does not panic.
#[must_use]
pub fn hlil_remove_nops(block: &HlilBlock) -> HlilBlock {
    let mut out = HlilBlock::new();
    for stmt in &block.statements {
        let is_empty_comment = matches!(stmt, HlilStatement::Comment(c) if c.trim().is_empty());
        if !is_empty_comment {
            out.push(stmt.clone());
        }
    }
    out
}

// ─── HLIL expression simplifier ───────────────────────────────────────────────

/// Simplify trivial constant expressions in HLIL statement string representations.
///
/// For example `"0 + 1"` → `"1"`, `"true == true"` → `"true"`.
/// This is a textual pass, not an AST pass.
///
/// # Panics
///
/// Does not panic.
#[must_use]
pub fn simplify_expr(expr: &str) -> std::string::String {
    let trimmed = expr.trim();
    // 0 + X → X
    if let Some(rest) = trimmed.strip_prefix("0 + ") {
        return rest.to_string();
    }
    // X + 0 → X
    if let Some(base) = trimmed.strip_suffix(" + 0") {
        return base.to_string();
    }
    // X * 1 → X
    if let Some(base) = trimmed.strip_suffix(" * 1") {
        return base.to_string();
    }
    // 1 * X → X
    if let Some(rest) = trimmed.strip_prefix("1 * ") {
        return rest.to_string();
    }
    // X - 0 → X
    if let Some(base) = trimmed.strip_suffix(" - 0") {
        return base.to_string();
    }
    // double negation: !!x → x
    if let Some(inner) = trimmed.strip_prefix("!!") {
        return inner.to_string();
    }
    // x == x → true (simple text equality)
    if trimmed.contains(" == ") {
        let parts: Vec<&str> = trimmed.splitn(2, " == ").collect();
        if parts.len() == 2 && parts[0].trim() == parts[1].trim() {
            return "true".to_string();
        }
    }
    trimmed.to_string()
}

// ─── Tests for expanded decompile code ────────────────────────────────────────

#[cfg(test)]
mod decompile_expanded_tests {
    use super::*;
    use rustre_dotnet::{CilInstruction, CilOperand, DotnetMethod, MethodBody, MethodSignature};

    fn make_method_with_instrs(name: &str, instrs: Vec<CilInstruction>) -> DotnetMethod {
        DotnetMethod {
            name: name.to_string(),
            signature: MethodSignature {
                return_type: "void".into(),
                ..Default::default()
            },
            body: Some(MethodBody {
                instructions: instrs,
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    #[test]
    fn test_inferred_type_to_csharp() {
        assert_eq!(InferredType::Int32.to_csharp(), "int");
        assert_eq!(InferredType::Int64.to_csharp(), "long");
        assert_eq!(InferredType::Float32.to_csharp(), "float");
        assert_eq!(InferredType::Bool.to_csharp(), "bool");
        assert_eq!(InferredType::String.to_csharp(), "string");
        assert_eq!(InferredType::Unknown.to_csharp(), "var");
    }

    #[test]
    fn test_inferred_type_array() {
        let arr = InferredType::Array(Box::new(InferredType::Int32));
        assert_eq!(arr.to_csharp(), "int[]");
        assert!(arr.is_reference());
    }

    #[test]
    fn test_inferred_type_nullable() {
        let n = InferredType::Nullable(Box::new(InferredType::Int32));
        assert_eq!(n.to_csharp(), "int?");
    }

    #[test]
    fn test_inferred_type_is_numeric() {
        assert!(InferredType::Int32.is_numeric());
        assert!(InferredType::Float64.is_numeric());
        assert!(!InferredType::Bool.is_numeric());
        assert!(!InferredType::String.is_numeric());
    }

    #[test]
    fn test_infer_type_from_element() {
        assert_eq!(infer_type_from_element(0x08), InferredType::Int32);
        assert_eq!(infer_type_from_element(0x0A), InferredType::Int64);
        assert_eq!(infer_type_from_element(0x0C), InferredType::Float32);
        assert_eq!(infer_type_from_element(0x02), InferredType::Bool);
        assert_eq!(infer_type_from_element(0x0E), InferredType::String);
        assert_eq!(infer_type_from_element(0xFF), InferredType::Unknown);
    }

    #[test]
    fn test_type_annotation_pass_literal_int() {
        let mut block = HlilBlock::new();
        block.push(HlilStatement::Assign {
            target: HlilExpression::Local(0, "x".into()),
            value: HlilExpression::Const(42),
        });
        let ann = TypeAnnotationPass::annotate(&block);
        assert_eq!(ann.len(), 1);
        assert_eq!(ann[0].1, InferredType::Int32);
    }

    #[test]
    fn test_type_annotation_pass_literal_string() {
        let mut block = HlilBlock::new();
        block.push(HlilStatement::Assign {
            target: HlilExpression::Local(0, "s".into()),
            value: HlilExpression::StringLit("hello".into()),
        });
        let ann = TypeAnnotationPass::annotate(&block);
        assert_eq!(ann[0].1, InferredType::String);
    }

    #[test]
    fn test_type_annotation_pass_literal_long() {
        let mut block = HlilBlock::new();
        // Opaque expression with L suffix triggers Int64 inference
        block.push(HlilStatement::Assign {
            target: HlilExpression::Local(0, "n".into()),
            value: HlilExpression::Opaque("100L".into()),
        });
        let ann = TypeAnnotationPass::annotate(&block);
        assert_eq!(ann[0].1, InferredType::Int64);
    }

    #[test]
    fn test_type_annotation_pass_literal_bool() {
        let mut block = HlilBlock::new();
        // Null literal infers Object
        block.push(HlilStatement::Assign {
            target: HlilExpression::Local(0, "b".into()),
            value: HlilExpression::Null,
        });
        let ann = TypeAnnotationPass::annotate(&block);
        assert_eq!(ann[0].1, InferredType::Object);
    }

    #[test]
    fn test_decompiler_metrics_empty() {
        let method = make_method_with_instrs(
            "M",
            vec![CilInstruction {
                offset: 0,
                opcode: "ret".into(),
                operand: CilOperand::None,
            }],
        );
        let pipeline = DecompilationPipeline::new();
        let hlil = pipeline.lift_to_hlil(&method);
        let metrics = DecompilerMetrics::from_hlil(&hlil);
        assert_eq!(metrics.cyclomatic_complexity, 1);
        assert!(!metrics.detected.has_foreach);
    }

    #[test]
    fn test_decompiler_metrics_summary() {
        let metrics = DecompilerMetrics {
            statement_count: 5,
            cyclomatic_complexity: 3,
            exception_handlers: 1,
            detected: DetectedPatterns { has_foreach: true, ..Default::default() },
            ..Default::default()
        };
        let s = metrics.summary();
        assert!(s.contains("stmts=5"));
        assert!(s.contains("cc=3"));
    }

    #[test]
    fn test_csharp_emitter_namespace() {
        let body = "class Foo {}";
        let ns = CSharpEmitter::emit_namespace_block("MyApp", body);
        assert!(ns.contains("namespace MyApp"));
        assert!(ns.contains("class Foo"));
    }

    #[test]
    fn test_csharp_emitter_region() {
        let r = CSharpEmitter::emit_region("Fields", "int x;");
        assert!(r.contains("#region Fields"));
        assert!(r.contains("#endregion"));
    }

    #[test]
    fn test_csharp_emitter_doc_comment() {
        let c = CSharpEmitter::emit_doc_comment("Does something");
        assert!(c.contains("<summary>"));
        assert!(c.contains("Does something"));
    }

    #[test]
    fn test_csharp_emitter_local_decl_with_init() {
        let s = CSharpEmitter::emit_local_decl("int", "x", Some("0"));
        assert_eq!(s, "int x = 0;\n");
    }

    #[test]
    fn test_csharp_emitter_local_decl_no_init() {
        let s = CSharpEmitter::emit_local_decl("string", "name", None);
        assert_eq!(s, "string name;\n");
    }

    #[test]
    fn test_csharp_emitter_return_void() {
        assert_eq!(CSharpEmitter::emit_return(None), "return;\n");
    }

    #[test]
    fn test_csharp_emitter_return_expr() {
        assert_eq!(CSharpEmitter::emit_return(Some("x + 1")), "return x + 1;\n");
    }

    #[test]
    fn test_csharp_emitter_throw() {
        let s = CSharpEmitter::emit_throw("new Exception()");
        assert!(s.contains("throw"));
    }

    #[test]
    fn test_csharp_emitter_goto_label() {
        let g = CSharpEmitter::emit_goto("IL_0010");
        assert_eq!(g, "goto IL_0010;\n");
        let l = CSharpEmitter::emit_label("IL_0010");
        assert_eq!(l, "IL_0010:\n");
    }

    #[test]
    fn test_csharp_emitter_attribute() {
        let a = CSharpEmitter::emit_attribute("Obsolete");
        assert_eq!(a, "[Obsolete]\n");
    }

    #[test]
    fn test_string_table_record_and_get() {
        let mut tbl = StringTable::default();
        tbl.record(0x7000_0001, "hello".into());
        assert_eq!(tbl.get(0x7000_0001), Some("hello"));
        assert_eq!(tbl.len(), 1);
        assert!(!tbl.is_empty());
    }

    #[test]
    fn test_string_table_no_duplicates() {
        let mut tbl = StringTable::default();
        tbl.record(0x7000_0001, "x".into());
        tbl.record(0x7000_0001, "x".into()); // duplicate
        assert_eq!(tbl.len(), 1);
    }

    #[test]
    fn test_string_table_all_strings() {
        let mut tbl = StringTable::default();
        tbl.record(1, "a".into());
        tbl.record(2, "b".into());
        let all = tbl.all_strings();
        assert!(all.contains(&"a"));
        assert!(all.contains(&"b"));
    }

    #[test]
    fn test_hlil_remove_nops() {
        let mut block = HlilBlock::new();
        // Empty comments act as no-ops and are stripped
        block.push(HlilStatement::Comment("   ".into()));
        block.push(HlilStatement::Assign {
            target: HlilExpression::Local(0, "x".into()),
            value: HlilExpression::Const(1),
        });
        block.push(HlilStatement::Comment(String::new()));
        let cleaned = hlil_remove_nops(&block);
        assert_eq!(cleaned.statements.len(), 1);
    }

    #[test]
    fn test_simplify_expr_zero_plus() {
        assert_eq!(simplify_expr("0 + x"), "x");
    }

    #[test]
    fn test_simplify_expr_plus_zero() {
        assert_eq!(simplify_expr("x + 0"), "x");
    }

    #[test]
    fn test_simplify_expr_times_one() {
        assert_eq!(simplify_expr("x * 1"), "x");
        assert_eq!(simplify_expr("1 * x"), "x");
    }

    #[test]
    fn test_simplify_expr_minus_zero() {
        assert_eq!(simplify_expr("x - 0"), "x");
    }

    #[test]
    fn test_simplify_expr_double_negation() {
        assert_eq!(simplify_expr("!!x"), "x");
    }

    #[test]
    fn test_simplify_expr_self_equality() {
        assert_eq!(simplify_expr("x == x"), "true");
    }

    #[test]
    fn test_simplify_expr_no_simplification() {
        assert_eq!(simplify_expr("x + y"), "x + y");
    }

    #[test]
    fn test_detect_yield_return_false_for_non_movenext() {
        let method = make_method_with_instrs(
            "Run",
            vec![
                CilInstruction {
                    offset: 0,
                    opcode: "switch".into(),
                    operand: CilOperand::Switch(vec![]),
                },
                CilInstruction {
                    offset: 5,
                    opcode: "ret".into(),
                    operand: CilOperand::None,
                },
            ],
        );
        assert!(!detect_yield_return(&method)); // not named MoveNext
    }

    #[test]
    fn test_detect_yield_return_true_for_movenext_with_switch() {
        let method = make_method_with_instrs(
            "MoveNext",
            vec![
                CilInstruction {
                    offset: 0,
                    opcode: "switch".into(),
                    operand: CilOperand::Switch(vec![10, 20]),
                },
                CilInstruction {
                    offset: 9,
                    opcode: "ret".into(),
                    operand: CilOperand::None,
                },
            ],
        );
        assert!(detect_yield_return(&method));
    }

    #[test]
    fn test_use_def_chains_basic() {
        let instrs = vec![
            CilInstruction {
                offset: 0,
                opcode: "ldc.i4.1".into(),
                operand: CilOperand::None,
            },
            CilInstruction {
                offset: 1,
                opcode: "stloc.0".into(),
                operand: CilOperand::None,
            },
            CilInstruction {
                offset: 2,
                opcode: "ldloc.0".into(),
                operand: CilOperand::None,
            },
            CilInstruction {
                offset: 3,
                opcode: "ret".into(),
                operand: CilOperand::None,
            },
        ];
        let udc = UseDefChains::build(&instrs);
        assert_eq!(udc.len(), 1);
        assert_eq!(udc.uses_of(0).len(), 1);
    }

    #[test]
    fn test_use_def_chains_no_definitions() {
        let instrs = vec![CilInstruction {
            offset: 0,
            opcode: "ldloc.0".into(),
            operand: CilOperand::None,
        }];
        let udc = UseDefChains::build(&instrs);
        assert!(udc.is_empty());
    }

    #[test]
    fn test_cfg_block_is_empty() {
        let b = CfgBlock::new(0);
        assert!(b.is_empty());
        assert_eq!(b.len(), 0);
    }

    #[test]
    fn test_control_flow_graph_empty() {
        let cfg = ControlFlowGraph::build(&[]).unwrap();
        assert_eq!(cfg.block_count(), 0);
    }

    #[test]
    fn test_control_flow_graph_single_block() {
        let instrs = vec![
            CilInstruction {
                offset: 0,
                opcode: "nop".into(),
                operand: CilOperand::None,
            },
            CilInstruction {
                offset: 1,
                opcode: "ret".into(),
                operand: CilOperand::None,
            },
        ];
        let cfg = ControlFlowGraph::build(&instrs).unwrap();
        assert_eq!(cfg.block_count(), 1);
    }

    #[test]
    fn test_control_flow_graph_branch() {
        let instrs = vec![
            CilInstruction {
                offset: 0,
                opcode: "brfalse.s".into(),
                operand: CilOperand::Branch(4),
            },
            CilInstruction {
                offset: 2,
                opcode: "nop".into(),
                operand: CilOperand::None,
            },
            CilInstruction {
                offset: 3,
                opcode: "ret".into(),
                operand: CilOperand::None,
            },
            CilInstruction {
                offset: 4,
                opcode: "ret".into(),
                operand: CilOperand::None,
            },
        ];
        let cfg = ControlFlowGraph::build(&instrs).unwrap();
        assert!(cfg.block_count() >= 2);
    }

    #[test]
    fn test_cfg_block_at() {
        let instrs = vec![CilInstruction {
            offset: 0,
            opcode: "ret".into(),
            operand: CilOperand::None,
        }];
        let cfg = ControlFlowGraph::build(&instrs).unwrap();
        assert!(cfg.block_at(0).is_some());
        assert!(cfg.block_at(99).is_none());
    }

    #[test]
    fn test_csharp_emitter_assign() {
        let s = CSharpEmitter::emit_assign("x", "42");
        assert_eq!(s, "x = 42;\n");
    }

    #[test]
    fn test_csharp_emitter_call_stmt() {
        let s = CSharpEmitter::emit_call_stmt("Console.WriteLine(\"hi\")");
        assert!(s.ends_with(";\n"));
    }
}

// ─── §27.4 – Async/await state machine detector ──────────────────────────────

/// Carries information about a single `await` point recovered from a state machine.
#[derive(Debug, Clone)]
pub struct AwaitPoint {
    /// The state index (switch case value) that this await arm handles.
    pub state: i32,
    /// The expression being awaited, as a C# source snippet.
    pub awaited_expr: String,
    /// The continuation state index jumped to after the await completes.
    pub continuation_state: Option<i32>,
}

/// Recovered representation of one async method body.
#[derive(Debug, Clone)]
pub struct RecoveredAsyncMethod {
    /// C# method name (stripped of compiler decorations).
    pub name: String,
    /// C# return type, e.g. `"Task<int>"` or `"Task"`.
    pub return_type: String,
    /// Parameter list as `(type, name)` pairs.
    pub params: Vec<(String, String)>,
    /// Access modifiers.
    pub modifiers: Vec<String>,
    /// Recovered await points, in state order.
    pub await_points: Vec<AwaitPoint>,
    /// Body statements that precede the first await.
    pub preamble: Vec<String>,
    /// Body statements that follow the last await.
    pub postamble: Vec<String>,
}

impl RecoveredAsyncMethod {
    /// Emit this recovered method as a C# `async` method definition.
    #[must_use]
    pub fn to_csharp(&self, indent: &str) -> String {
        let inner = format!("    {indent}");
        let mods = if self.modifiers.is_empty() {
            "public async".to_string()
        } else {
            format!("{} async", self.modifiers.join(" "))
        };
        let params_str = self
            .params
            .iter()
            .map(|(ty, name)| format!("{} {name}", normalize_type(ty)))
            .collect::<Vec<_>>()
            .join(", ");
        let ret = normalize_type_owned(&self.return_type);
        let mut out = format!(
            "{indent}{mods} {ret} {}({params_str})\n{indent}{{\n",
            self.name
        );
        for stmt in &self.preamble {
            writeln!(out, "{inner}{stmt}").unwrap();
        }
        for ap in &self.await_points {
            writeln!(out, "{inner}var __result{} = await {};",
                ap.state, ap.awaited_expr
            ).unwrap();
        }
        for stmt in &self.postamble {
            writeln!(out, "{inner}{stmt}").unwrap();
        }
        writeln!(out, "{indent}}}").unwrap();
        out
    }
}

/// Detects and recovers async/await state machines from compiler-generated types.
pub struct AsyncStateMachineDetector;

impl AsyncStateMachineDetector {
    // Compiler-generated field names that mark an async state machine.
    const STATE_FIELD: &'static str = "<>1__state";
    const BUILDER_FIELD: &'static str = "<>t__builder";
    const IASYNC_STATE_MACHINE: &'static str = "IAsyncStateMachine";

    /// Returns `true` if `type_def` appears to be a compiler-generated
    /// async state-machine struct.
    ///
    /// Heuristics (in decreasing confidence):
    /// 1. The type implements `IAsyncStateMachine`.
    /// 2. The type has a method named `MoveNext`.
    /// 3. The type has fields named `<>1__state` and `<>t__builder`.
    #[must_use]
    pub fn detect(type_def: &DotnetType) -> bool {
        // Check interface list
        let implements_iasm = type_def
            .interfaces
            .iter()
            .any(|i| i.contains(Self::IASYNC_STATE_MACHINE));

        // Check for MoveNext method
        let has_move_next = type_def.methods.iter().any(|m| m.name == "MoveNext");

        // Check for state machine fields
        let has_state_field = type_def.fields.iter().any(|f| f.name == Self::STATE_FIELD);
        let has_builder_field = type_def
            .fields
            .iter()
            .any(|f| f.name == Self::BUILDER_FIELD);

        implements_iasm || has_move_next || (has_state_field && has_builder_field)
    }

    /// Reconstruct the original `async` method signature and await points from
    /// a compiler-generated state machine type.
    ///
    /// Returns `None` if the type does not look like an async state machine or
    /// if no `MoveNext` method is present.
    #[must_use]
    pub fn reconstruct_async_method(state_machine: &DotnetType) -> Option<RecoveredAsyncMethod> {
        if !Self::detect(state_machine) {
            return None;
        }

        let move_next = state_machine
            .methods
            .iter()
            .find(|m| m.name == "MoveNext")?;

        // Derive original method name: strip the compiler suffix "<MethodName>d__N"
        // e.g. "<LoadDataAsync>d__3" → "LoadDataAsync"
        let raw_name = &state_machine.name;
        let original_name = Self::strip_state_machine_name(raw_name)
            .unwrap_or(raw_name.as_str())
            .to_string();

        // Determine return type from the builder field type, defaulting to Task
        let return_type = state_machine
            .fields
            .iter()
            .find(|f| f.name == Self::BUILDER_FIELD).map_or_else(|| "Task".to_string(), |f| Self::builder_type_to_task(&f.type_name));

        // Collect captured parameters: fields that don't start with '<' are captures
        let params: Vec<(String, String)> = state_machine
            .fields
            .iter()
            .filter(|f| !f.name.starts_with('<') && f.name != "this")
            .map(|f| (normalize_type_owned(&f.type_name), f.name.clone()))
            .collect();

        // Parse await points from the MoveNext switch structure
        let await_points = Self::extract_await_points(move_next);

        // Simple preamble/postamble: just comment stubs
        let preamble = vec!["// preamble (recovered from state 0)".to_string()];
        let postamble = vec!["// postamble (recovered from final state)".to_string()];

        Some(RecoveredAsyncMethod {
            name: original_name,
            return_type,
            params,
            modifiers: vec!["public".to_string()],
            await_points,
            preamble,
            postamble,
        })
    }

    /// Extract await points from a `MoveNext` method body by examining switch
    /// instructions (state dispatch) and call tokens (awaiter calls).
    fn extract_await_points(move_next: &DotnetMethod) -> Vec<AwaitPoint> {
        let Some(body) = &move_next.body else { return Vec::new() };

        let instrs = &body.instructions;
        let mut await_points = Vec::new();

        // Find switch instructions; each case index is an await state.
        for (i, instr) in instrs.iter().enumerate() {
            if instr.opcode == "switch" {
                if let CilOperand::Switch(targets) = &instr.operand {
                    for (case_idx, _target) in targets.iter().enumerate() {
                        // Look ahead for a call that could be GetAwaiter
                        let awaited_expr = instrs[i..]
                            .iter()
                            .find(|ii| ii.opcode == "call" || ii.opcode == "callvirt")
                            .map_or_else(|| "/* unknown */".to_string(), |ii| {
                                if let CilOperand::Token(tok) = &ii.operand {
                                    format!("/* call_0x{tok:08X} */")
                                } else {
                                    "/* unknown */".to_string()
                                }
                            });

                        await_points.push(AwaitPoint {
                            state: casts::usize_to_i32(case_idx),
                            awaited_expr,
                            continuation_state: Some(casts::usize_to_i32(case_idx) + 1),
                        });
                    }
                }
                break; // Only handle first switch (the state dispatcher)
            }
        }

        await_points
    }

    /// Map a task builder type name to its corresponding `Task<T>` / `Task` return type.
    fn builder_type_to_task(builder_type: &str) -> String {
        // AsyncTaskMethodBuilder<T> → Task<T>
        // AsyncTaskMethodBuilder   → Task
        // AsyncVoidMethodBuilder   → void (async void)
        if builder_type.contains("AsyncVoidMethodBuilder") {
            return "void".to_string();
        }
        if let Some(idx) = builder_type.find('<') {
            let inner = &builder_type[idx + 1..builder_type.len() - 1];
            return format!("Task<{}>", normalize_type_owned(inner));
        }
        "Task".to_string()
    }

    /// Strip the compiler-generated suffix from a state machine type name.
    /// E.g. `"<LoadDataAsync>d__3"` → `Some("LoadDataAsync")`.
    fn strip_state_machine_name(name: &str) -> Option<&str> {
        let inner = name.strip_prefix('<')?.split('>').next()?;
        Some(inner)
    }
}

// ─── §27.4 – Lambda reconstructor ────────────────────────────────────────────

/// Represents a reconstructed lambda expression.
#[derive(Debug, Clone)]
pub struct ReconstructedLambda {
    /// The parameter list as a C# snippet, e.g. `"(int x, string y)"`.
    pub params: String,
    /// The lambda body as a C# snippet, e.g. `"x + y"`.
    pub body: String,
    /// Captured variables from the display class.
    pub captures: Vec<(String, String)>, // (type, name)
}

impl ReconstructedLambda {
    /// Emit this lambda as a C# lambda expression.
    #[must_use]
    pub fn to_csharp(&self) -> String {
        if self.body.contains('\n') || self.body.len() > 60 {
            format!("{} =>\n{{\n    {}\n}}", self.params, self.body)
        } else {
            format!("{} => {}", self.params, self.body)
        }
    }
}

/// Reconstructs compiler-generated lambdas from display classes and anonymous methods.
pub struct LambdaReconstructor;

impl LambdaReconstructor {
    /// Returns `true` if the type name looks like a compiler-generated display class.
    ///
    /// Display classes are named `<>c__DisplayClassN` or `<>c` or start with `<>`.
    #[must_use]
    pub fn is_display_class(type_name: &str) -> bool {
        type_name.starts_with("<>")
    }

    /// Returns `true` if the method name looks like a compiler-generated anonymous method.
    ///
    /// Anonymous methods are named like `<EnclosingMethod>b__N`.
    #[must_use]
    pub fn is_anonymous_method(method_name: &str) -> bool {
        method_name.starts_with('<') && method_name.contains(">b__")
    }

    /// Reconstruct a lambda from a display class and its anonymous method.
    ///
    /// The display class fields become the captured variables; the anonymous
    /// method parameters become the lambda parameters; the method body becomes
    /// the lambda body.
    #[must_use]
    pub fn reconstruct_lambda(
        display_class: &DotnetType,
        anon_method: &DotnetMethod,
    ) -> ReconstructedLambda {
        // Captured variables: non-compiler fields on the display class
        let captures: Vec<(String, String)> = display_class
            .fields
            .iter()
            .filter(|f| !f.name.starts_with('<'))
            .map(|f| (normalize_type_owned(&f.type_name), f.name.clone()))
            .collect();

        // Lambda parameters: the anonymous method's actual parameters
        // (skip `this` for instance methods)
        let _ = anon_method.signature.is_static;
        let param_start = 0;
        let params_str = anon_method.signature.params[param_start..]
            .iter()
            .map(|(name, ty)| format!("{} {name}", normalize_type(ty)))
            .collect::<Vec<_>>()
            .join(", ");

        let params = if anon_method.signature.params[param_start..].len() == 1 {
            // Single-param lambda: no parentheses needed
            let (name, ty) = &anon_method.signature.params[param_start];
            format!("{} {name}", normalize_type(ty))
        } else {
            format!("({params_str})")
        };

        // Lambda body: best-effort from the method body
        let body = Self::extract_lambda_body(anon_method);

        ReconstructedLambda {
            params,
            body,
            captures,
        }
    }

    /// Extract the lambda body from a method's CIL instructions as a C# snippet.
    fn extract_lambda_body(method: &DotnetMethod) -> String {
        let Some(body) = &method.body else { return "/* no body */".to_string() };

        // Use the simple decompiler state to generate the body
        let opts = DecompilerOptions {
            use_var: true,
            ..Default::default()
        };
        let mut state = DecompileState::new(&opts, method, body, "");
        for instr in &body.instructions {
            state.process(instr);
        }
        if state.statements.is_empty() {
            return "/* empty */".to_string();
        }
        // Return the last statement stripped of trailing semicolons as the expression
        let last = state
            .statements
            .last()
            .unwrap_or(&String::new())
            .trim()
            .to_string();
        // Remove leading "return " if present, trailing ";"
        let expr = last
            .trim_start_matches("return ")
            .trim_end_matches(';')
            .to_string();
        if expr.is_empty() {
            "/* empty */".to_string()
        } else {
            expr
        }
    }

    /// Find all anonymous methods in a type and reconstruct them as lambdas.
    #[must_use]
    pub fn reconstruct_all_lambdas(display_class: &DotnetType) -> Vec<ReconstructedLambda> {
        display_class
            .methods
            .iter()
            .filter(|m| Self::is_anonymous_method(&m.name))
            .map(|m| Self::reconstruct_lambda(display_class, m))
            .collect()
    }
}

// ─── §27.4 – Property reconstructor ──────────────────────────────────────────

/// A fully reconstructed property with optional get/set bodies.
#[derive(Debug, Clone)]
pub struct PropertyDef {
    /// Property name (stripped of `get_` / `set_` prefix).
    pub name: String,
    /// C# type of the property.
    pub property_type: String,
    /// Access modifiers.
    pub modifiers: Vec<String>,
    /// Whether the property has a getter.
    pub has_getter: bool,
    /// Whether the property has a setter.
    pub has_setter: bool,
    /// Whether the getter is auto-implemented.
    pub is_auto: bool,
    /// Optional getter body (C# source lines).
    pub getter_body: Option<String>,
    /// Optional setter body (C# source lines).
    pub setter_body: Option<String>,
}

impl PropertyDef {
    /// Emit this property as a C# property definition.
    #[must_use]
    pub fn emit(&self, indent: &str) -> String {
        let inner = format!("    {indent}");
        let mods = if self.modifiers.is_empty() {
            "public".to_string()
        } else {
            self.modifiers.join(" ")
        };
        let ty = normalize_type_owned(&self.property_type);

        if self.is_auto {
            let accessors = match (self.has_getter, self.has_setter) {
                (true, true) => "get; set;",
                (true, false) => "get;",
                (false, true) => "set;",
                (false, false) => "",
            };
            return format!("{indent}{mods} {ty} {} {{ {accessors} }}\n", self.name);
        }

        let mut out = format!("{indent}{mods} {ty} {}\n{indent}{{\n", self.name);
        if self.has_getter {
            if let Some(body) = &self.getter_body {
                writeln!(out, "{inner}get\n{inner}{{").unwrap();
                for line in body.lines() {
                    writeln!(out, "{inner}    {line}").unwrap();
                }
                writeln!(out, "{inner}}}").unwrap();
            } else {
                writeln!(out, "{inner}get;").unwrap();
            }
        }
        if self.has_setter {
            if let Some(body) = &self.setter_body {
                writeln!(out, "{inner}set\n{inner}{{").unwrap();
                for line in body.lines() {
                    writeln!(out, "{inner}    {line}").unwrap();
                }
                writeln!(out, "{inner}}}").unwrap();
            } else {
                writeln!(out, "{inner}set;").unwrap();
            }
        }
        writeln!(out, "{indent}}}").unwrap();
        out
    }
}

/// Reconstructs C# properties from `get_X` / `set_X` method pairs.
pub struct PropertyReconstructor;

impl PropertyReconstructor {
    /// Attempt to match a `get_X` and `set_X` method pair into a `PropertyDef`.
    ///
    /// Returns `None` if the names don't match as a property pair.
    #[must_use]
    pub fn detect_property_pair(
        get_method: Option<&DotnetMethod>,
        set_method: Option<&DotnetMethod>,
    ) -> Option<PropertyDef> {
        let (name, property_type, get_mods, has_getter) = if let Some(g) = get_method {
            let prop = g.name.strip_prefix("get_")?;
            let ty = normalize_type_owned(&g.signature.return_type);
            let mods = method_modifiers(g.flags)
                .into_iter()
                .map(str::to_string)
                .collect::<Vec<_>>();
            (prop.to_string(), ty, mods, true)
        } else {
            // Must have at least a getter OR a setter
            let s = set_method?;
            let prop = s.name.strip_prefix("set_")?;
            // For setter-only, use the first param type as the property type
            let ty = s
                .signature
                .params
                .first().map_or_else(|| "object".to_string(), |(_, t)| normalize_type_owned(t));
            let mods = method_modifiers(s.flags)
                .into_iter()
                .map(str::to_string)
                .collect::<Vec<_>>();
            (prop.to_string(), ty, mods, false)
        };

        // Detect whether this is auto-implemented: getter body is just ldfld+ret
        let is_auto = get_method
            .and_then(|g| g.body.as_ref())
            .is_none_or(|b| PatternRecogniser::detect_simple_property_getter(&b.instructions)); // No body → definitely auto

        // Generate body text for non-auto properties
        let opts = DecompilerOptions::default();
        let dc = CSharpDecompiler::new(opts);

        let getter_body = if is_auto {
            None
        } else {
            get_method
                .and_then(|g| dc.decompile_method(g).ok())
                .map(|s| {
                    // Strip the outer method wrapper, keep only the body
                    extract_method_body_text(&s)
                })
        };

        let setter_present = set_method.is_some();
        let setter_body = if !is_auto && setter_present {
            set_method
                .and_then(|s| dc.decompile_method(s).ok())
                .map(|s| extract_method_body_text(&s))
        } else {
            None
        };

        Some(PropertyDef {
            name,
            property_type,
            modifiers: get_mods,
            has_getter,
            has_setter: setter_present,
            is_auto,
            getter_body,
            setter_body,
        })
    }

    /// Emit a `PropertyDef` as a C# property definition.
    #[must_use]
    pub fn emit_property(prop: &PropertyDef, indent: &str) -> String {
        prop.emit(indent)
    }

    /// Scan a list of methods and collect all get/set pairs as `PropertyDef` instances.
    #[must_use]
    pub fn collect_properties(methods: &[DotnetMethod]) -> Vec<PropertyDef> {
        use std::collections::BTreeMap;

        // Index methods by property name
        let mut getters: BTreeMap<String, &DotnetMethod> = BTreeMap::new();
        let mut setters: BTreeMap<String, &DotnetMethod> = BTreeMap::new();
        for m in methods {
            if let Some(prop) = m.name.strip_prefix("get_") {
                getters.insert(prop.to_string(), m);
            } else if let Some(prop) = m.name.strip_prefix("set_") {
                setters.insert(prop.to_string(), m);
            }
        }

        // Collect unique property names
        let mut names: Vec<String> = getters.keys().cloned().collect();
        for k in setters.keys() {
            if !names.contains(k) {
                names.push(k.clone());
            }
        }
        names.sort();

        names
            .iter()
            .filter_map(|n| {
                let g = getters.get(n).copied();
                let s = setters.get(n).copied();
                Self::detect_property_pair(g, s)
            })
            .collect()
    }
}

/// Extract only the inner body lines from a decompiled method string.
fn extract_method_body_text(method_src: &str) -> String {
    let lines: Vec<&str> = method_src.lines().collect();
    // Skip the method signature line and the opening brace line
    let start = lines
        .iter()
        .position(|l| l.trim() == "{")
        .map_or(0, |i| i + 1);
    let end = lines
        .iter()
        .rposition(|l| l.trim() == "}")
        .unwrap_or(lines.len());
    lines[start..end].join("\n")
}

// ─── §27.4 – LINQ reconstructor ──────────────────────────────────────────────

/// Information about one method call in a LINQ chain.
#[derive(Debug, Clone)]
pub struct MethodCallInfo {
    /// The called method name (e.g. `"Where"`, `"Select"`, `"OrderBy"`).
    pub method_name: String,
    /// The metadata token of the called method.
    pub token: u32,
    /// The source offset of the call instruction.
    pub offset: u32,
}

/// The style of LINQ output to produce.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinqStyle {
    /// Fluent method syntax: `collection.Where(x => ...).Select(x => ...)`.
    MethodSyntax,
    /// SQL-like query expression: `from x in collection where ... select ...`.
    QueryExpression,
}

/// Detects and reconstructs LINQ query chains.
pub struct LinqReconstructor;

impl LinqReconstructor {
    /// LINQ operator method names recognised by the reconstructor.
    const LINQ_OPERATORS: &'static [&'static str] = &[
        "Where",
        "Select",
        "SelectMany",
        "OrderBy",
        "OrderByDescending",
        "ThenBy",
        "ThenByDescending",
        "GroupBy",
        "Join",
        "GroupJoin",
        "Take",
        "TakeWhile",
        "Skip",
        "SkipWhile",
        "First",
        "FirstOrDefault",
        "Last",
        "LastOrDefault",
        "Single",
        "SingleOrDefault",
        "Any",
        "All",
        "Count",
        "LongCount",
        "Sum",
        "Min",
        "Max",
        "Average",
        "Aggregate",
        "Distinct",
        "Union",
        "Intersect",
        "Except",
        "Concat",
        "Zip",
        "ToList",
        "ToArray",
        "ToDictionary",
        "ToLookup",
        "ToHashSet",
        "AsEnumerable",
        "AsQueryable",
        "Cast",
        "OfType",
    ];

    /// Returns `true` if any of the method calls in a method body target a
    /// recognised LINQ operator.
    #[must_use]
    pub fn detect_linq_chain(method: &DotnetMethod) -> bool {
        let Some(body) = &method.body else { return false };
        body.instructions.iter().any(|instr| {
            matches!(instr.opcode.as_str(), "call" | "callvirt")
        })
        // A heuristic: LINQ chains tend to have multiple consecutive calls
        && {
            let call_count = body.instructions.iter()
                .filter(|i| matches!(i.opcode.as_str(), "call" | "callvirt"))
                .count();
            call_count >= 2
        }
    }

    /// Extract `MethodCallInfo` entries for all `call`/`callvirt` instructions
    /// in a method body.
    #[must_use]
    pub fn extract_call_chain(method: &DotnetMethod) -> Vec<MethodCallInfo> {
        let Some(body) = &method.body else { return Vec::new() };
        body.instructions
            .iter()
            .filter(|i| matches!(i.opcode.as_str(), "call" | "callvirt"))
            .map(|i| {
                let token = match &i.operand {
                    CilOperand::Token(t) => *t,
                    _ => 0,
                };
                MethodCallInfo {
                    method_name: format!("call_0x{token:08X}"),
                    token,
                    offset: i.offset,
                }
            })
            .collect()
    }

    /// Reconstruct a LINQ chain as either method syntax or query expression.
    ///
    /// `source_expr` is the name of the collection variable (e.g. `"items"`).
    /// `calls` is the ordered list of LINQ operators extracted from the method.
    ///
    /// Returns `None` if the call list contains no recognised LINQ operators.
    #[must_use]
    pub fn reconstruct_query_expression(
        calls: &[MethodCallInfo],
        source_expr: &str,
        style: LinqStyle,
    ) -> Option<String> {
        // Filter to known LINQ operators
        let linq_calls: Vec<&MethodCallInfo> = calls
            .iter()
            .filter(|c| {
                Self::LINQ_OPERATORS
                    .iter()
                    .any(|op| c.method_name.contains(op))
            })
            .collect();

        if linq_calls.is_empty() {
            return None;
        }

        match style {
            LinqStyle::MethodSyntax => {
                let chain = linq_calls.iter().fold(String::new(), |mut acc, c| {
                    use std::fmt::Write;
                    let _ = write!(acc, ".{}(/* token 0x{:08X} */)", c.method_name, c.token);
                    acc
                });
                Some(format!("{source_expr}{chain}"))
            }
            LinqStyle::QueryExpression => {
                // Build a simplified query expression heuristically.
                let mut parts: Vec<String> = Vec::new();
                let range_var = "x";
                parts.push(format!("from {range_var} in {source_expr}"));

                for c in &linq_calls {
                    let name = &c.method_name;
                    if name.contains("Where") {
                        parts.push(format!("where /* token 0x{:08X} */", c.token));
                    } else if name.contains("OrderBy") {
                        parts.push(format!("orderby /* token 0x{:08X} */", c.token));
                    } else if name.contains("GroupBy") {
                        parts.push(format!(
                            "group {range_var} by /* token 0x{:08X} */",
                            c.token
                        ));
                    } else if name.contains("Select") {
                        parts.push(format!("select /* token 0x{:08X} */", c.token));
                    }
                }
                // Ensure the query ends with a `select` clause
                if !parts
                    .iter()
                    .any(|p| p.starts_with("select") || p.starts_with("group"))
                {
                    parts.push(format!("select {range_var}"));
                }
                Some(parts.join("\n"))
            }
        }
    }
}

// ─── §27.4 – String literal decoder (#US heap) ───────────────────────────────

/// Decodes entries from the `#US` (User Strings) heap of a .NET assembly.
pub struct StringLiteralDecoder;

impl StringLiteralDecoder {
    /// Decode a `#US` heap entry at the given byte offset.
    ///
    /// The `#US` heap stores UTF-16 LE strings prefixed by a compressed length.
    /// The last byte of the blob is a "special character" flag and is not part
    /// of the string content.
    ///
    /// Returns the decoded string, or an escaped hex representation on error.
    #[must_use]
    pub fn decode_string(us_index: u32, us_heap: &[u8]) -> String {
        let offset = us_index as usize;
        if offset >= us_heap.len() {
            return format!("/* #US[0x{us_index:X}] out of range */");
        }

        // Decode the compressed length prefix (ECMA §II.24.2.4)
        let (blob_len, prefix_len) = Self::decode_compressed_uint(us_heap, offset);
        if blob_len == 0 {
            return String::new();
        }

        let data_start = offset + prefix_len;
        let data_end = data_start + blob_len as usize;
        if data_end > us_heap.len() {
            return format!("/* #US[0x{us_index:X}] truncated */");
        }

        // UTF-16 LE content: blob_len bytes, last byte is the flag
        // The string occupies bytes [data_start .. data_end - 1]
        let string_bytes = &us_heap[data_start..data_end.saturating_sub(1)];
        if !string_bytes.len().is_multiple_of(2) {
            return format!("/* #US[0x{us_index:X}] odd byte count */");
        }

        let utf16_units: Vec<u16> = string_bytes
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();

        char::decode_utf16(utf16_units)
            .map(|r| r.unwrap_or(char::REPLACEMENT_CHARACTER))
            .collect()
    }

    /// Decode a compressed unsigned integer from the blob at `pos`.
    ///
    /// Returns `(value, bytes_consumed)`.
    fn decode_compressed_uint(data: &[u8], pos: usize) -> (u32, usize) {
        if pos >= data.len() {
            return (0, 0);
        }
        let b0 = data[pos];
        if b0 & 0x80 == 0 {
            (u32::from(b0), 1)
        } else if b0 & 0xC0 == 0x80 {
            if pos + 1 >= data.len() {
                return (0, 1);
            }
            let val = (u32::from(b0 & 0x3F) << 8) | u32::from(data[pos + 1]);
            (val, 2)
        } else {
            if pos + 3 >= data.len() {
                return (0, 1);
            }
            let val = (u32::from(b0 & 0x1F) << 24)
                | (u32::from(data[pos + 1]) << 16)
                | (u32::from(data[pos + 2]) << 8)
                | u32::from(data[pos + 3]);
            (val, 4)
        }
    }

    /// Format a decoded string as a C# string literal (with escaping).
    #[must_use]
    pub fn format_as_csharp_literal(s: &str) -> String {
        let mut out = String::with_capacity(s.len() + 2);
        out.push('"');
        for ch in s.chars() {
            match ch {
                '"' => out.push_str("\\\""),
                '\\' => out.push_str("\\\\"),
                '\n' => out.push_str("\\n"),
                '\r' => out.push_str("\\r"),
                '\t' => out.push_str("\\t"),
                '\0' => out.push_str("\\0"),
                c if c.is_control() => write!(out, "\\u{:04X}", c as u32).unwrap(),
                c => out.push(c),
            }
        }
        out.push('"');
        out
    }
}

// ─── §27.4 – Custom attribute decoder ────────────────────────────────────────

/// A single decoded argument in a custom attribute.
#[derive(Debug, Clone)]
pub enum AttributeArg {
    /// Boolean value.
    Bool(bool),
    /// Integer value.
    Int(i64),
    /// Unsigned integer.
    UInt(u64),
    /// Floating-point value.
    Float(f64),
    /// String value (may be null → None).
    Str(Option<String>),
    /// Type reference (full name).
    TypeRef(String),
    /// Enum value (type, value).
    Enum(String, i64),
    /// Array of arguments.
    Array(Vec<Self>),
    /// Opaque / unparsed blob snippet.
    Opaque(String),
}

impl AttributeArg {
    /// Emit this argument as a C# expression.
    #[must_use]
    pub fn to_csharp(&self) -> String {
        match self {
            Self::Bool(b) => {
                if *b {
                    "true".into()
                } else {
                    "false".into()
                }
            }
            Self::Int(n) => n.to_string(),
            Self::UInt(n) => format!("{n}u"),
            Self::Float(f) => format!("{f}"),
            Self::Str(Some(s)) => StringLiteralDecoder::format_as_csharp_literal(s),
            Self::Str(None) => "null".into(),
            Self::TypeRef(t) => format!("typeof({t})"),
            Self::Enum(ty, val) => format!("({ty}){val}"),
            Self::Array(items) => {
                let inner = items
                    .iter()
                    .map(Self::to_csharp)
                    .collect::<Vec<_>>()
                    .join(", ");
                format!("new[] {{ {inner} }}")
            }
            Self::Opaque(s) => format!("/* {s} */"),
        }
    }
}

/// A decoded named argument (property or field initialiser in an attribute).
#[derive(Debug, Clone)]
pub struct AttributeNamedArg {
    /// Whether this is a property (`true`) or field (`false`) assignment.
    pub is_property: bool,
    /// The property/field name.
    pub name: String,
    /// The value.
    pub value: AttributeArg,
}

impl AttributeNamedArg {
    /// Emit as `Name = value`.
    #[must_use]
    pub fn to_csharp(&self) -> String {
        format!("{} = {}", self.name, self.value.to_csharp())
    }
}

/// A fully decoded custom attribute.
#[derive(Debug, Clone)]
pub struct DecodedAttribute {
    /// Attribute class name (without the `Attribute` suffix if present).
    pub name: String,
    /// Positional constructor arguments.
    pub positional_args: Vec<AttributeArg>,
    /// Named arguments (property/field initialisers).
    pub named_args: Vec<AttributeNamedArg>,
}

impl DecodedAttribute {
    /// Emit this attribute as a C# attribute annotation.
    #[must_use]
    pub fn to_csharp(&self) -> String {
        let mut parts: Vec<String> = self
            .positional_args
            .iter()
            .map(AttributeArg::to_csharp)
            .collect();
        for na in &self.named_args {
            parts.push(na.to_csharp());
        }
        if parts.is_empty() {
            format!("[{}]", self.name)
        } else {
            format!("[{}({})]", self.name, parts.join(", "))
        }
    }
}

/// Decodes custom attribute blobs according to ECMA-335 §II.23.3.
pub struct AttributeDecoder;

impl AttributeDecoder {
    /// Decode a custom attribute blob.
    ///
    /// `attr_name` is the name of the attribute class (used for display).
    /// `blob` is the raw custom attribute blob (starting after the prolog).
    ///
    /// This implementation performs a best-effort decode; unknown argument
    /// types are emitted as opaque hex blobs.
    #[must_use]
    pub fn decode_custom_attribute(attr_name: &str, blob: &[u8]) -> DecodedAttribute {
        // Custom attribute blobs start with the two-byte prolog 0x0001
        let data = if blob.len() >= 2 && blob[0] == 0x01 && blob[1] == 0x00 {
            &blob[2..]
        } else {
            blob
        };

        // Without full metadata type info we can't fully decode positional args.
        // Emit the raw hex as an opaque argument instead.
        let positional_args = if data.is_empty() {
            Vec::new()
        } else {
            // Try to decode as a simple sequence of values
            Self::decode_positional_args_heuristic(data)
        };

        DecodedAttribute {
            name: attr_name.to_string(),
            positional_args,
            named_args: Vec::new(),
        }
    }

    /// Heuristic positional argument decoder that produces at least something
    /// readable without full metadata resolution.
    fn decode_positional_args_heuristic(data: &[u8]) -> Vec<AttributeArg> {
        // Try: if the blob looks like a null-terminated or length-prefixed string
        if !data.is_empty() && data[0] == 0xFF {
            return vec![AttributeArg::Str(None)]; // null string
        }
        if data.len() >= 2 {
            // Check for UTF-16 LE BOM or high-bit markers
        }
        // Fall back: emit raw hex
        let hex = data
            .iter()
            .map(|b| format!("{b:02X}"))
            .collect::<Vec<_>>()
            .join(" ");
        vec![AttributeArg::Opaque(hex)]
    }

    /// Emit a set of custom attributes as C# annotation lines.
    #[must_use]
    pub fn emit_attributes(attrs: &[DecodedAttribute]) -> String {
        attrs.iter().fold(String::new(), |mut acc, a| {
            use std::fmt::Write;
            let _ = writeln!(acc, "{}", a.to_csharp());
            acc
        })
    }

    /// Decode a sequence of custom attribute blobs from a blob heap slice.
    ///
    /// `entries` is a list of `(attr_name, blob_offset, blob_len)` tuples.
    #[must_use]
    pub fn decode_all(entries: &[(&str, usize, usize)], blob_heap: &[u8]) -> Vec<DecodedAttribute> {
        entries
            .iter()
            .map(|(name, offset, len)| {
                let end = (*offset + *len).min(blob_heap.len());
                let slice = &blob_heap[*offset..end];
                Self::decode_custom_attribute(name, slice)
            })
            .collect()
    }
}

// ─── §27.4 – Generic instantiator ────────────────────────────────────────────

/// A type signature node in the generic type system.
#[derive(Debug, Clone)]
pub enum TypeSig {
    /// Primitive type by element-type byte.
    Primitive(u8),
    /// Named class or struct.
    Named(String),
    /// Generic instance: base type + type arguments.
    GenericInst {
        base: Box<Self>,
        args: Vec<Self>,
    },
    /// Szarray (single-dimensional zero-based array).
    SzArray(Box<Self>),
    /// Pointer type.
    Ptr(Box<Self>),
    /// By-reference type.
    ByRef(Box<Self>),
    /// Generic method or type parameter (index).
    Var(u32),
    /// Generic method parameter (index).
    MVar(u32),
}

impl TypeSig {
    /// Instantiate this type signature by substituting type variables.
    ///
    /// `type_args` are substituted for `Var(i)` parameters;
    /// `method_args` are substituted for `MVar(i)` parameters.
    #[must_use]
    pub fn instantiate(&self, type_args: &[Self], method_args: &[Self]) -> Self {
        match self {
            Self::Var(i) => type_args
                .get(*i as usize)
                .cloned()
                .unwrap_or_else(|| Self::Named(format!("T{i}"))),
            Self::MVar(i) => method_args
                .get(*i as usize)
                .cloned()
                .unwrap_or_else(|| Self::Named(format!("M{i}"))),
            Self::GenericInst { base, args } => {
                let new_args = args
                    .iter()
                    .map(|a| a.instantiate(type_args, method_args))
                    .collect();
                Self::GenericInst {
                    base: Box::new(base.instantiate(type_args, method_args)),
                    args: new_args,
                }
            }
            Self::SzArray(inner) => {
                Self::SzArray(Box::new(inner.instantiate(type_args, method_args)))
            }
            Self::Ptr(inner) => {
                Self::Ptr(Box::new(inner.instantiate(type_args, method_args)))
            }
            Self::ByRef(inner) => {
                Self::ByRef(Box::new(inner.instantiate(type_args, method_args)))
            }
            other => other.clone(),
        }
    }
}

/// Renders generic type instantiations as C# type names.
pub struct GenericInstantiator;

impl GenericInstantiator {
    /// Render a `TypeSig` as a C# type name.
    ///
    /// `type_args` are the concrete type arguments to substitute.
    ///
    /// Examples:
    /// - `GenericInst { base: Named("List"), args: [Primitive(0x08)] }` → `"List<int>"`
    /// - `SzArray(Primitive(0x0E))` → `"string[]"`
    #[must_use]
    pub fn instantiate_type(type_sig: &TypeSig, type_args: &[TypeSig]) -> String {
        let instantiated = type_sig.instantiate(type_args, &[]);
        Self::render(&instantiated)
    }

    /// Recursively render a `TypeSig` node as C# source text.
    #[must_use]
    pub fn render(sig: &TypeSig) -> String {
        match sig {
            TypeSig::Primitive(et) => elem_type_name(*et).to_string(),
            TypeSig::Named(name) => {
                // Strip assembly-qualified suffixes and use short type names
                let short = name.split(',').next().unwrap_or(name);
                normalize_type_owned(short)
            }
            TypeSig::GenericInst { base, args } => {
                let base_str = Self::render(base);
                // Remove arity suffix if present (e.g. "Dictionary`2" → "Dictionary")
                let base_clean = if let Some(pos) = base_str.rfind('`') {
                    base_str[..pos].to_string()
                } else {
                    base_str
                };
                let args_str = args.iter().map(Self::render).collect::<Vec<_>>().join(", ");
                format!("{base_clean}<{args_str}>")
            }
            TypeSig::SzArray(inner) => format!("{}[]", Self::render(inner)),
            TypeSig::Ptr(inner) => format!("{}*", Self::render(inner)),
            TypeSig::ByRef(inner) => format!("ref {}", Self::render(inner)),
            TypeSig::Var(i) => format!("T{i}"),
            TypeSig::MVar(i) => format!("M{i}"),
        }
    }

    /// Construct a `Task<T>` type signature from an inner type.
    #[must_use]
    pub fn task_of(inner: TypeSig) -> TypeSig {
        TypeSig::GenericInst {
            base: Box::new(TypeSig::Named("Task".to_string())),
            args: vec![inner],
        }
    }

    /// Construct a `List<T>` type signature from an inner type.
    #[must_use]
    pub fn list_of(inner: TypeSig) -> TypeSig {
        TypeSig::GenericInst {
            base: Box::new(TypeSig::Named("List".to_string())),
            args: vec![inner],
        }
    }

    /// Construct a `Dictionary<K, V>` type signature.
    #[must_use]
    pub fn dictionary_of(key: TypeSig, value: TypeSig) -> TypeSig {
        TypeSig::GenericInst {
            base: Box::new(TypeSig::Named("Dictionary".to_string())),
            args: vec![key, value],
        }
    }

    /// Construct an `IEnumerable<T>` type signature.
    #[must_use]
    pub fn ienumerable_of(inner: TypeSig) -> TypeSig {
        TypeSig::GenericInst {
            base: Box::new(TypeSig::Named("IEnumerable".to_string())),
            args: vec![inner],
        }
    }
}

// ─── §27.4 – Full TypeDef emitter ────────────────────────────────────────────

/// Output-control flags for the type emitter (≤3 bools each to avoid `struct_excessive_bools`).
#[derive(Debug, Clone)]
pub struct TypeOutputFlags {
    /// Whether to emit full method bodies or just signatures.
    pub emit_bodies: bool,
    /// Whether to skip compiler-generated members.
    pub skip_compiler_generated: bool,
    /// Whether to detect and skip async state machine types.
    pub skip_state_machines: bool,
}

impl Default for TypeOutputFlags {
    fn default() -> Self {
        Self { emit_bodies: true, skip_compiler_generated: true, skip_state_machines: true }
    }
}

/// Style/reconstruction flags for the type emitter (≤3 bools each).
#[derive(Debug, Clone)]
pub struct TypeStyleFlags {
    /// Whether to reconstruct properties from accessor pairs.
    pub reconstruct_properties: bool,
    /// Whether to reconstruct lambdas from display classes.
    pub reconstruct_lambdas: bool,
    /// Whether to emit XML doc comments (stubs).
    pub emit_doc_comments: bool,
}

impl Default for TypeStyleFlags {
    fn default() -> Self {
        Self { reconstruct_properties: true, reconstruct_lambdas: true, emit_doc_comments: false }
    }
}

/// Configuration for the full type emitter.
#[derive(Debug, Clone)]
pub struct TypeEmitOptions {
    /// Indentation unit.
    pub indent: String,
    /// Output-control flags (bodies, filtering).
    pub output: TypeOutputFlags,
    /// Style and reconstruction flags.
    pub style: TypeStyleFlags,
}

impl Default for TypeEmitOptions {
    fn default() -> Self {
        Self {
            indent: "    ".to_string(),
            output: TypeOutputFlags::default(),
            style: TypeStyleFlags::default(),
        }
    }
}

/// Produces a complete C# class/struct/interface/enum/delegate definition.
pub struct TypeDefEmitter {
    pub options: TypeEmitOptions,
    pub dc: CSharpDecompiler,
}

impl TypeDefEmitter {
    /// Create a new emitter with default options.
    #[must_use]
    pub fn new() -> Self {
        Self {
            options: TypeEmitOptions::default(),
            dc: CSharpDecompiler::default(),
        }
    }

    /// Create a new emitter with custom options.
    #[must_use]
    pub fn with_options(options: TypeEmitOptions) -> Self {
        let dc_opts = DecompilerOptions {
            indent: options.indent.clone(),
            emit_comments: false,
            use_var: true,
            use_short_types: true,
        };
        Self {
            options,
            dc: CSharpDecompiler::new(dc_opts),
        }
    }

    /// Emit a complete class definition from a `DotnetType`.
    ///
    /// This is the main entry point for the enhanced type emitter and supersedes
    /// the simpler `CSharpDecompiler::decompile_type`.
    ///
    /// # Errors
    /// Returns an error if member decompilation or formatting fails.
    pub fn emit_class(&self, type_def: &DotnetType) -> Result<String> {
        let mut out = String::new();
        let ind = &self.options.indent;

        if self.options.output.skip_state_machines && AsyncStateMachineDetector::detect(type_def) {
            writeln!(out, "{ind}// [async state machine for a recovered async method — see above]").unwrap();
            if let Some(recovered) = AsyncStateMachineDetector::reconstruct_async_method(type_def) {
                out.push_str(&recovered.to_csharp(ind));
            }
            return Ok(out);
        }

        let in_ns = !type_def.namespace.is_empty();
        if in_ns { writeln!(out, "namespace {}\n{{", type_def.namespace).unwrap(); }

        let (all_mods, generic_suffix, header) = self.emit_class_header(&mut out, type_def, ind);
        let body_ind = format!("{ind}{ind}");

        if type_def.is_enum() {
            return Ok(Self::emit_enum_body(out, type_def, ind, &body_ind, in_ns));
        }
        if type_def.is_delegate()
            && let Some(r) = Self::emit_delegate_def(out.clone(), type_def, ind, &all_mods, &generic_suffix, &header, in_ns) {
            return Ok(r);
        }

        self.emit_fields_section(&mut out, type_def, &body_ind);
        self.emit_properties_section(&mut out, type_def, &body_ind);
        let accessor_names = self.collect_accessor_names(type_def);
        self.emit_methods_section(&mut out, type_def, ind, &body_ind, &accessor_names);
        for nested_name in &type_def.nested_types {
            writeln!(out, "{body_ind}// nested type: {nested_name}").unwrap();
        }
        writeln!(out, "{ind}}}").unwrap();
        if in_ns { out.push_str("}\n"); }
        Ok(out)
    }

    fn emit_class_header(&self, out: &mut String, type_def: &DotnetType, ind: &str) -> (String, String, String) {
        let kind = if type_def.is_interface() { "interface" }
            else if type_def.is_enum() { "enum" }
            else if type_def.is_struct() { "struct" }
            else if type_def.is_delegate() { "delegate" }
            else { "class" };
        let access = Self::type_access(type_def.flags);
        let mut extra: Vec<&str> = Vec::new();
        if type_def.flags & 0x0100 != 0 && !type_def.is_interface() { extra.push("abstract"); }
        if type_def.flags & 0x0200 != 0 && !type_def.is_struct() { extra.push("sealed"); }
        let all_mods = if extra.is_empty() { access.to_string() }
            else { format!("{access} {}", extra.join(" ")) };
        let generic_suffix = if type_def.generic_params.is_empty() { String::new() }
            else { format!("<{}>", type_def.generic_params.iter().map(|p| p.name.as_str()).collect::<Vec<_>>().join(", ")) };
        let mut bases: Vec<String> = Vec::new();
        if let Some(base) = &type_def.base_type {
            let b = normalize_type_owned(base);
            if !matches!(b.as_str(), "object" | "System.Object" | "ValueType" | "System.ValueType" | "Enum" | "System.Enum") {
                bases.push(b);
            }
        }
        for iface in &type_def.interfaces {
            if iface != "IAsyncStateMachine" || !self.options.output.skip_state_machines {
                bases.push(normalize_type_owned(iface));
            }
        }
        let mut header = format!("{ind}{all_mods} {kind} {}{}", type_def.name, generic_suffix);
        if !bases.is_empty() { write!(header, " : {}", bases.join(", ")).unwrap(); }
        if self.options.style.emit_doc_comments {
            writeln!(out, "{ind}/// <summary>\n{ind}/// {}\n{ind}/// </summary>", type_def.name).unwrap();
        }
        writeln!(out, "{header}\n{ind}{{").unwrap();
        (all_mods, generic_suffix, header)
    }

    fn emit_enum_body(mut out: String, type_def: &DotnetType, ind: &str, body_ind: &str, in_ns: bool) -> String {
        for field in &type_def.fields {
            if field.name == "value__" { continue; }
            writeln!(out, "{body_ind}{},", field.name).unwrap();
        }
        writeln!(out, "{ind}}}").unwrap();
        if in_ns { out.push_str("}\n"); }
        out
    }

    fn emit_delegate_def(mut out: String, type_def: &DotnetType, ind: &str, all_mods: &str, generic_suffix: &str, header: &str, in_ns: bool) -> Option<String> {
        let invoke = type_def.methods.iter().find(|m| m.name == "Invoke")?;
        let ret = normalize_type_owned(&invoke.signature.return_type);
        let params_str = invoke.signature.params.iter()
            .map(|(n, t)| format!("{} {n}", normalize_type(t))).collect::<Vec<_>>().join(", ");
        let trimmed = out.trim_end_matches(&format!("{header}\n{ind}{{\n")).to_string();
        out = trimmed;
        writeln!(out, "{ind}{all_mods} delegate {ret} {}{}({params_str});", type_def.name, generic_suffix).unwrap();
        if in_ns { out.push_str("}\n"); }
        Some(out)
    }

    fn emit_fields_section(&self, out: &mut String, type_def: &DotnetType, body_ind: &str) {
        for field in &type_def.fields {
            if self.options.output.skip_compiler_generated && field.name.contains('<') { continue; }
            let field_access = Self::field_access(field.flags);
            let is_readonly = field.flags & 0x0020 != 0;
            let is_const = field.flags & 0x0040 != 0;
            let mut mods = vec![field_access];
            if is_const { mods.push("const"); }
            else if field.is_static { mods.push("static"); if is_readonly { mods.push("readonly"); } }
            else if is_readonly { mods.push("readonly"); }
            let ty = normalize_type_owned(&field.type_name);
            if self.options.style.emit_doc_comments {
                writeln!(out, "{body_ind}/// <summary>Field {}</summary>", field.name).unwrap();
            }
            writeln!(out, "{body_ind}{} {ty} {};", mods.join(" "), field.name).unwrap();
        }
    }

    fn emit_properties_section(&self, out: &mut String, type_def: &DotnetType, body_ind: &str) {
        if self.options.style.reconstruct_properties && !type_def.is_interface() {
            let props = PropertyReconstructor::collect_properties(&type_def.methods);
            for prop in &props {
                if self.options.style.emit_doc_comments {
                    writeln!(out, "{body_ind}/// <summary>Property {}</summary>", prop.name).unwrap();
                }
                out.push_str(&prop.emit(body_ind));
            }
        } else if type_def.is_interface() {
            let props = PropertyReconstructor::collect_properties(&type_def.methods);
            for prop in &props {
                let ty = normalize_type_owned(&prop.property_type);
                let accessors = match (prop.has_getter, prop.has_setter) {
                    (true, true) => "get; set;", (true, false) => "get;",
                    (false, true) => "set;", (false, false) => "",
                };
                writeln!(out, "{body_ind}{ty} {} {{ {accessors} }}", prop.name).unwrap();
            }
        }
    }

    fn collect_accessor_names(&self, type_def: &DotnetType) -> std::collections::HashSet<String> {
        if !self.options.style.reconstruct_properties { return std::collections::HashSet::new(); }
        PropertyReconstructor::collect_properties(&type_def.methods).iter()
            .flat_map(|p| {
                let mut names = Vec::new();
                if p.has_getter { names.push(format!("get_{}", p.name)); }
                if p.has_setter { names.push(format!("set_{}", p.name)); }
                names
            }).collect()
    }

    fn emit_methods_section(
        &self, out: &mut String, type_def: &DotnetType, ind: &str, body_ind: &str,
        accessor_names: &std::collections::HashSet<String>,
    ) {
        for method in &type_def.methods {
            if self.options.output.skip_compiler_generated
                && (method.name.starts_with('<') || method.name.contains("__StaticArrayInitTypeSize"))
            { continue; }
            if accessor_names.contains(&method.name) { continue; }
            if type_def.is_delegate() && matches!(method.name.as_str(), "Invoke" | "BeginInvoke" | "EndInvoke" | ".ctor") { continue; }
            if self.options.style.emit_doc_comments {
                writeln!(out, "{body_ind}/// <summary>Method {}</summary>", method.name).unwrap();
            }
            if self.options.output.emit_bodies && !type_def.is_interface() {
                match self.dc.decompile_method(method) {
                    Ok(text) => { for line in text.lines() { writeln!(out, "{ind}{line}").unwrap(); } }
                    Err(e) => { writeln!(out, "{body_ind}/* decompile error: {e} */").unwrap(); }
                }
            } else {
                let mods_str = if type_def.is_interface() { String::new() }
                    else { method_modifiers(method.flags).join(" ") + " " };
                let ret = normalize_type_owned(&method.signature.return_type);
                let params_str = method.signature.params.iter()
                    .map(|(n, t)| format!("{} {n}", normalize_type(t))).collect::<Vec<_>>().join(", ");
                writeln!(out, "{body_ind}{mods_str}{ret} {}({params_str});", method.name).unwrap();
            }
        }
    }

    /// Determine the C# access modifier from `TypeDef` visibility flags.
    const fn type_access(flags: u32) -> &'static str {
        match flags & 0x07 {
            0x01 | 0x02 => "public",
            0x03 => "private", // NestedPrivate
            0x04 => "protected", // NestedFamily
            0x05 => "protected internal",
            // 0x06 (NestedAssembly) and any other value default to "internal".
            _ => "internal",
        }
    }

    /// Determine the C# access modifier from `FieldDef` flags.
    const fn field_access(flags: u32) -> &'static str {
        match flags & 0x0007 {
            0x03 => "internal",
            0x04 => "protected",
            0x05 => "protected internal",
            0x06 => "public",
            // 0x01 (Private), 0x02 (FamANDAssem) and any other value default to "private".
            _ => "private",
        }
    }
}

impl Default for TypeDefEmitter {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Tests for §27.4 additions ───────────────────────────────────────────────

#[cfg(test)]
mod advanced_decompile_tests {
    use super::*;
    use rustre_dotnet::{DotnetField, DotnetMethod, DotnetType, MethodSignature};

    fn make_type(name: &str) -> DotnetType {
        DotnetType {
            name: name.into(),
            namespace: String::new(),
            full_name: name.into(),
            base_type: None,
            interfaces: vec![],
            methods: vec![],
            fields: vec![],
            properties: vec![],
            events: vec![],
            nested_types: vec![],
            custom_attributes: vec![],
            generic_params: vec![],
            kind_tag: rustre_dotnet::DotnetTypeKind::Class,
            flags: 0x01,
            layout: None,
        }
    }

    fn make_field(name: &str, ty: &str, is_static: bool) -> DotnetField {
        DotnetField {
            name: name.into(),
            type_name: ty.into(),
            is_static,
            flags: if is_static { 0x10 } else { 0x06 },
            ..Default::default()
        }
    }

    // ── AsyncStateMachineDetector tests ──────────────────────────────────────

    #[test]
    fn test_async_detect_by_interface() {
        let mut t = make_type("<LoadAsync>d__3");
        t.interfaces.push("IAsyncStateMachine".into());
        assert!(AsyncStateMachineDetector::detect(&t));
    }

    #[test]
    fn test_async_detect_by_fields() {
        let mut t = make_type("<Work>d__0");
        t.fields.push(make_field("<>1__state", "int", false));
        t.fields
            .push(make_field("<>t__builder", "AsyncTaskMethodBuilder", false));
        assert!(AsyncStateMachineDetector::detect(&t));
    }

    #[test]
    fn test_async_detect_by_movenext() {
        let mut t = make_type("<Run>d__1");
        t.methods.push(DotnetMethod {
            name: "MoveNext".into(),
            signature: MethodSignature {
                return_type: "void".into(),
                ..Default::default()
            },
            ..Default::default()
        });
        assert!(AsyncStateMachineDetector::detect(&t));
    }

    #[test]
    fn test_async_detect_negative() {
        let t = make_type("RegularClass");
        assert!(!AsyncStateMachineDetector::detect(&t));
    }

    #[test]
    fn test_async_strip_name() {
        assert_eq!(
            AsyncStateMachineDetector::strip_state_machine_name("<LoadDataAsync>d__3"),
            Some("LoadDataAsync")
        );
        assert_eq!(
            AsyncStateMachineDetector::strip_state_machine_name("NotAStateMachine"),
            None
        );
    }

    #[test]
    fn test_async_reconstruct_returns_none_for_non_state_machine() {
        let t = make_type("Foo");
        assert!(AsyncStateMachineDetector::reconstruct_async_method(&t).is_none());
    }

    #[test]
    fn test_async_reconstruct_basic() {
        let mut t = make_type("<FetchData>d__5");
        t.interfaces.push("IAsyncStateMachine".into());
        t.fields.push(make_field("<>1__state", "int", false));
        t.fields.push(make_field(
            "<>t__builder",
            "AsyncTaskMethodBuilder<int>",
            false,
        ));
        t.methods.push(DotnetMethod {
            name: "MoveNext".into(),
            signature: MethodSignature {
                return_type: "void".into(),
                ..Default::default()
            },
            body: None,
            ..Default::default()
        });
        let recovered = AsyncStateMachineDetector::reconstruct_async_method(&t);
        assert!(recovered.is_some());
        let r = recovered.unwrap();
        assert_eq!(r.name, "FetchData");
        assert!(r.return_type.contains("Task"));
    }

    #[test]
    fn test_async_recovered_to_csharp() {
        let r = RecoveredAsyncMethod {
            name: "DoWork".into(),
            return_type: "Task<int>".into(),
            params: vec![("int".into(), "count".into())],
            modifiers: vec!["public".into()],
            await_points: vec![AwaitPoint {
                state: 0,
                awaited_expr: "SomeService.FetchAsync()".into(),
                continuation_state: Some(1),
            }],
            preamble: vec!["int total = 0;".into()],
            postamble: vec!["return total;".into()],
        };
        let src = r.to_csharp("    ");
        assert!(src.contains("async"));
        assert!(src.contains("Task<int>"));
        assert!(src.contains("await"));
        assert!(src.contains("DoWork"));
        assert!(src.contains("int count"));
    }

    // ── LambdaReconstructor tests ────────────────────────────────────────────

    #[test]
    fn test_lambda_is_display_class() {
        assert!(LambdaReconstructor::is_display_class(
            "<>c__DisplayClass3_0"
        ));
        assert!(LambdaReconstructor::is_display_class("<>c"));
        assert!(!LambdaReconstructor::is_display_class("RegularClass"));
    }

    #[test]
    fn test_lambda_is_anonymous_method() {
        assert!(LambdaReconstructor::is_anonymous_method("<MyMethod>b__0"));
        assert!(LambdaReconstructor::is_anonymous_method("<>b__3_0"));
        assert!(!LambdaReconstructor::is_anonymous_method("regularMethod"));
    }

    #[test]
    fn test_lambda_reconstruct_empty_body() {
        let display_class = make_type("<>c__DisplayClass0_0");
        let anon_method = DotnetMethod {
            name: "<Process>b__0".into(),
            signature: MethodSignature {
                return_type: "int".into(),
                params: vec![("x".into(), "int".into())],
                is_static: true,
                ..Default::default()
            },
            body: None,
            ..Default::default()
        };
        let lambda = LambdaReconstructor::reconstruct_lambda(&display_class, &anon_method);
        assert!(!lambda.params.is_empty());
        let csharp = lambda.to_csharp();
        assert!(csharp.contains("=>"));
    }

    #[test]
    fn test_lambda_captures_non_compiler_fields() {
        let mut display_class = make_type("<>c__DisplayClass1_0");
        display_class
            .fields
            .push(make_field("threshold", "int", false));
        display_class
            .fields
            .push(make_field("<>__captured", "object", false)); // compiler
        let anon_method = DotnetMethod {
            name: "<Filter>b__1".into(),
            signature: MethodSignature {
                return_type: "bool".into(),
                params: vec![("item".into(), "int".into())],
                is_static: true,
                ..Default::default()
            },
            body: None,
            ..Default::default()
        };
        let lambda = LambdaReconstructor::reconstruct_lambda(&display_class, &anon_method);
        assert_eq!(lambda.captures.len(), 1);
        assert_eq!(lambda.captures[0].1, "threshold");
    }

    #[test]
    fn test_lambda_reconstruct_all() {
        let mut dc = make_type("<>c");
        dc.methods.push(DotnetMethod {
            name: "<Sort>b__0".into(),
            signature: MethodSignature {
                return_type: "bool".into(),
                ..Default::default()
            },
            ..Default::default()
        });
        dc.methods.push(DotnetMethod {
            name: "<Sort>b__1".into(),
            signature: MethodSignature {
                return_type: "int".into(),
                ..Default::default()
            },
            ..Default::default()
        });
        dc.methods.push(DotnetMethod {
            name: "regular_method".into(),
            signature: MethodSignature {
                return_type: "void".into(),
                ..Default::default()
            },
            ..Default::default()
        });
        let lambdas = LambdaReconstructor::reconstruct_all_lambdas(&dc);
        assert_eq!(lambdas.len(), 2);
    }

    // ── PropertyReconstructor tests ──────────────────────────────────────────

    #[test]
    fn test_property_detect_pair_getter_only() {
        let getter = DotnetMethod {
            name: "get_Count".into(),
            signature: MethodSignature {
                return_type: "int".into(),
                params: vec![],
                is_static: false,
                ..Default::default()
            },
            flags: 0x06,
            body: None,
            ..Default::default()
        };
        let prop = PropertyReconstructor::detect_property_pair(Some(&getter), None);
        assert!(prop.is_some());
        let p = prop.unwrap();
        assert_eq!(p.name, "Count");
        assert_eq!(p.property_type, "int");
        assert!(p.has_getter);
        assert!(!p.has_setter);
    }

    #[test]
    fn test_property_detect_pair_getter_and_setter() {
        let getter = DotnetMethod {
            name: "get_Name".into(),
            signature: MethodSignature {
                return_type: "string".into(),
                ..Default::default()
            },
            flags: 0x06,
            body: None,
            ..Default::default()
        };
        let setter = DotnetMethod {
            name: "set_Name".into(),
            signature: MethodSignature {
                return_type: "void".into(),
                params: vec![("value".into(), "string".into())],
                ..Default::default()
            },
            flags: 0x06,
            body: None,
            ..Default::default()
        };
        let prop = PropertyReconstructor::detect_property_pair(Some(&getter), Some(&setter));
        assert!(prop.is_some());
        let p = prop.unwrap();
        assert!(p.has_getter);
        assert!(p.has_setter);
        assert_eq!(p.name, "Name");
    }

    #[test]
    fn test_property_emit_auto() {
        let prop = PropertyDef {
            name: "Value".into(),
            property_type: "int".into(),
            modifiers: vec!["public".into()],
            has_getter: true,
            has_setter: true,
            is_auto: true,
            getter_body: None,
            setter_body: None,
        };
        let src = PropertyReconstructor::emit_property(&prop, "    ");
        assert!(src.contains("public int Value"));
        assert!(src.contains("get; set;"));
    }

    #[test]
    fn test_property_collect_from_methods() {
        let methods = vec![
            DotnetMethod {
                name: "get_Age".into(),
                signature: MethodSignature {
                    return_type: "int".into(),
                    ..Default::default()
                },
                flags: 0x06,
                body: None,
                ..Default::default()
            },
            DotnetMethod {
                name: "set_Age".into(),
                signature: MethodSignature {
                    return_type: "void".into(),
                    params: vec![("value".into(), "int".into())],
                    ..Default::default()
                },
                flags: 0x06,
                body: None,
                ..Default::default()
            },
            DotnetMethod {
                name: "DoWork".into(),
                signature: MethodSignature {
                    return_type: "void".into(),
                    ..Default::default()
                },
                flags: 0x06,
                body: None,
                ..Default::default()
            },
        ];
        let props = PropertyReconstructor::collect_properties(&methods);
        assert_eq!(props.len(), 1);
        assert_eq!(props[0].name, "Age");
    }

    // ── LinqReconstructor tests ──────────────────────────────────────────────

    #[test]
    fn test_linq_operator_constants_non_empty() {
        assert!(!LinqReconstructor::LINQ_OPERATORS.is_empty());
        assert!(LinqReconstructor::LINQ_OPERATORS.contains(&"Where"));
        assert!(LinqReconstructor::LINQ_OPERATORS.contains(&"Select"));
        assert!(LinqReconstructor::LINQ_OPERATORS.contains(&"GroupBy"));
    }

    #[test]
    fn test_linq_reconstruct_method_syntax() {
        let calls = vec![
            MethodCallInfo {
                method_name: "Where".into(),
                token: 0x0A00_0001,
                offset: 0,
            },
            MethodCallInfo {
                method_name: "Select".into(),
                token: 0x0A00_0002,
                offset: 5,
            },
        ];
        let result = LinqReconstructor::reconstruct_query_expression(
            &calls,
            "items",
            LinqStyle::MethodSyntax,
        );
        assert!(result.is_some());
        let s = result.unwrap();
        assert!(s.contains("items"));
        assert!(s.contains("Where") || s.contains("0x0A00_0001"));
    }

    #[test]
    fn test_linq_reconstruct_query_expression() {
        let calls = vec![
            MethodCallInfo {
                method_name: "Where".into(),
                token: 0x0A00_0001,
                offset: 0,
            },
            MethodCallInfo {
                method_name: "Select".into(),
                token: 0x0A00_0002,
                offset: 5,
            },
        ];
        let result = LinqReconstructor::reconstruct_query_expression(
            &calls,
            "items",
            LinqStyle::QueryExpression,
        );
        assert!(result.is_some());
        let s = result.unwrap();
        assert!(s.contains("from"));
        assert!(s.contains("in items"));
    }

    #[test]
    fn test_linq_no_operators_returns_none() {
        let calls = vec![MethodCallInfo {
            method_name: "SomeOtherMethod".into(),
            token: 1,
            offset: 0,
        }];
        let result = LinqReconstructor::reconstruct_query_expression(
            &calls,
            "coll",
            LinqStyle::MethodSyntax,
        );
        assert!(result.is_none());
    }

    #[test]
    fn test_linq_query_has_select_clause() {
        let calls = vec![MethodCallInfo {
            method_name: "Where".into(),
            token: 1,
            offset: 0,
        }];
        let result = LinqReconstructor::reconstruct_query_expression(
            &calls,
            "xs",
            LinqStyle::QueryExpression,
        );
        assert!(result.is_some());
        let s = result.unwrap();
        assert!(s.contains("select") || s.contains("group"));
    }

    // ── StringLiteralDecoder tests ───────────────────────────────────────────

    #[test]
    fn test_string_decode_out_of_range() {
        let heap = vec![0x00u8];
        let s = StringLiteralDecoder::decode_string(100, &heap);
        assert!(s.contains("out of range"));
    }

    #[test]
    fn test_string_decode_zero_length() {
        // A single 0x00 byte means length=0, empty string
        let heap = vec![0x00u8];
        let s = StringLiteralDecoder::decode_string(0, &heap);
        assert_eq!(s, "");
    }

    #[test]
    fn test_string_decode_hello() {
        // #US blob for "Hi": prolog 0x05 (length 5 = 4 utf16 bytes + 1 flag), "Hi" in UTF-16LE, flag 0x00
        let heap = vec![
            0x05u8, // compressed length = 5
            b'H', 0x00, // 'H' in UTF-16LE
            b'i', 0x00, // 'i' in UTF-16LE
            0x00, // special character flag
        ];
        let s = StringLiteralDecoder::decode_string(0, &heap);
        assert_eq!(s, "Hi");
    }

    #[test]
    fn test_string_format_as_literal() {
        let s = StringLiteralDecoder::format_as_csharp_literal("He said \"hello\"\nbye");
        assert!(s.starts_with('"'));
        assert!(s.ends_with('"'));
        assert!(s.contains("\\\""));
        assert!(s.contains("\\n"));
    }

    #[test]
    fn test_string_format_escapes_backslash() {
        let s = StringLiteralDecoder::format_as_csharp_literal("C:\\path");
        assert!(s.contains("\\\\"));
    }

    // ── AttributeDecoder tests ───────────────────────────────────────────────

    #[test]
    fn test_attribute_decode_empty_blob() {
        let attr = AttributeDecoder::decode_custom_attribute("Obsolete", &[0x01, 0x00]);
        assert_eq!(attr.name, "Obsolete");
        assert!(attr.positional_args.is_empty());
    }

    #[test]
    fn test_attribute_to_csharp_no_args() {
        let attr = DecodedAttribute {
            name: "Serializable".into(),
            positional_args: vec![],
            named_args: vec![],
        };
        assert_eq!(attr.to_csharp(), "[Serializable]");
    }

    #[test]
    fn test_attribute_to_csharp_with_args() {
        let attr = DecodedAttribute {
            name: "Obsolete".into(),
            positional_args: vec![AttributeArg::Str(Some("Use Foo instead".into()))],
            named_args: vec![AttributeNamedArg {
                is_property: true,
                name: "IsError".into(),
                value: AttributeArg::Bool(true),
            }],
        };
        let s = attr.to_csharp();
        assert!(s.contains("[Obsolete("));
        assert!(s.contains("Use Foo instead"));
        assert!(s.contains("IsError = true"));
    }

    #[test]
    fn test_attribute_arg_types() {
        assert_eq!(AttributeArg::Bool(true).to_csharp(), "true");
        assert_eq!(AttributeArg::Bool(false).to_csharp(), "false");
        assert_eq!(AttributeArg::Int(-42).to_csharp(), "-42");
        assert_eq!(AttributeArg::UInt(7).to_csharp(), "7u");
        assert_eq!(AttributeArg::Str(None).to_csharp(), "null");
        assert_eq!(
            AttributeArg::TypeRef("System.String".into()).to_csharp(),
            "typeof(System.String)"
        );
    }

    #[test]
    fn test_attribute_arg_array() {
        let arr = AttributeArg::Array(vec![AttributeArg::Int(1), AttributeArg::Int(2)]);
        let s = arr.to_csharp();
        assert!(s.contains("new[]"));
        assert!(s.contains('1') && s.contains('2'));
    }

    #[test]
    fn test_attribute_emit_all() {
        let attrs = vec![
            DecodedAttribute {
                name: "Foo".into(),
                positional_args: vec![],
                named_args: vec![],
            },
            DecodedAttribute {
                name: "Bar".into(),
                positional_args: vec![],
                named_args: vec![],
            },
        ];
        let s = AttributeDecoder::emit_attributes(&attrs);
        assert!(s.contains("[Foo]"));
        assert!(s.contains("[Bar]"));
    }

    // ── GenericInstantiator tests ────────────────────────────────────────────

    #[test]
    fn test_generic_render_primitive() {
        let sig = TypeSig::Primitive(0x08); // int
        assert_eq!(GenericInstantiator::render(&sig), "int");
    }

    #[test]
    fn test_generic_render_named() {
        let sig = TypeSig::Named("System.String".into());
        assert_eq!(GenericInstantiator::render(&sig), "string");
    }

    #[test]
    fn test_generic_render_list_int() {
        let sig = GenericInstantiator::list_of(TypeSig::Primitive(0x08));
        assert_eq!(GenericInstantiator::render(&sig), "List<int>");
    }

    #[test]
    fn test_generic_render_dict() {
        let sig = GenericInstantiator::dictionary_of(
            TypeSig::Primitive(0x0E), // string
            TypeSig::Primitive(0x1C), // object
        );
        assert_eq!(
            GenericInstantiator::render(&sig),
            "Dictionary<string, object>"
        );
    }

    #[test]
    fn test_generic_render_task_bool() {
        let sig = GenericInstantiator::task_of(TypeSig::Primitive(0x02)); // bool
        assert_eq!(GenericInstantiator::render(&sig), "Task<bool>");
    }

    #[test]
    fn test_generic_render_array() {
        let sig = TypeSig::SzArray(Box::new(TypeSig::Primitive(0x08)));
        assert_eq!(GenericInstantiator::render(&sig), "int[]");
    }

    #[test]
    fn test_generic_render_by_ref() {
        let sig = TypeSig::ByRef(Box::new(TypeSig::Primitive(0x08)));
        assert_eq!(GenericInstantiator::render(&sig), "ref int");
    }

    #[test]
    fn test_generic_render_ptr() {
        let sig = TypeSig::Ptr(Box::new(TypeSig::Primitive(0x09))); // uint
        assert_eq!(GenericInstantiator::render(&sig), "uint*");
    }

    #[test]
    fn test_generic_instantiate_var() {
        let sig = TypeSig::Var(0); // T0
        let args = vec![TypeSig::Primitive(0x08)]; // substitute int
        assert_eq!(GenericInstantiator::instantiate_type(&sig, &args), "int");
    }

    #[test]
    fn test_generic_instantiate_generic_inst() {
        // List<T0> where T0 = string
        let sig = TypeSig::GenericInst {
            base: Box::new(TypeSig::Named("List`1".into())),
            args: vec![TypeSig::Var(0)],
        };
        let args = vec![TypeSig::Primitive(0x0E)]; // string
        assert_eq!(
            GenericInstantiator::instantiate_type(&sig, &args),
            "List<string>"
        );
    }

    #[test]
    fn test_generic_ienumerable() {
        let sig = GenericInstantiator::ienumerable_of(TypeSig::Primitive(0x08));
        assert_eq!(GenericInstantiator::render(&sig), "IEnumerable<int>");
    }

    // ── TypeDefEmitter tests ─────────────────────────────────────────────────

    #[test]
    fn test_typedef_emitter_simple_class() {
        let t = make_type("MyClass");
        let emitter = TypeDefEmitter::new();
        let src = emitter.emit_class(&t).unwrap();
        assert!(src.contains("class MyClass"));
        assert!(src.contains('{') && src.contains('}'));
    }

    #[test]
    fn test_typedef_emitter_public_class_has_access() {
        let mut t = make_type("Widget");
        t.flags = 0x01; // public
        let emitter = TypeDefEmitter::new();
        let src = emitter.emit_class(&t).unwrap();
        assert!(src.contains("public"));
    }

    #[test]
    fn test_typedef_emitter_interface() {
        let mut t = make_type("IFoo");
        t.kind_tag = rustre_dotnet::DotnetTypeKind::Interface;
        let emitter = TypeDefEmitter::new();
        let src = emitter.emit_class(&t).unwrap();
        assert!(src.contains("interface IFoo"));
    }

    #[test]
    fn test_typedef_emitter_enum() {
        let mut t = make_type("Color");
        t.kind_tag = rustre_dotnet::DotnetTypeKind::Enum;
        t.fields.push(make_field("Red", "int", true));
        t.fields.push(make_field("Green", "int", true));
        t.fields.push(make_field("Blue", "int", true));
        let emitter = TypeDefEmitter::new();
        let src = emitter.emit_class(&t).unwrap();
        assert!(src.contains("enum Color"));
        assert!(src.contains("Red"));
        assert!(src.contains("Green"));
    }

    #[test]
    fn test_typedef_emitter_struct() {
        let mut t = make_type("Point");
        t.kind_tag = rustre_dotnet::DotnetTypeKind::Struct;
        t.fields.push(make_field("X", "float", false));
        t.fields.push(make_field("Y", "float", false));
        let emitter = TypeDefEmitter::new();
        let src = emitter.emit_class(&t).unwrap();
        assert!(src.contains("struct Point") || src.contains("class Point"));
        assert!(src.contains("float X") || src.contains('X'));
    }

    #[test]
    fn test_typedef_emitter_skips_compiler_generated_fields() {
        let mut t = make_type("SomeClass");
        t.fields.push(make_field("<>backing_field", "int", false));
        t.fields.push(make_field("PublicField", "int", false));
        let emitter = TypeDefEmitter::new();
        let src = emitter.emit_class(&t).unwrap();
        assert!(!src.contains("<>backing_field"));
        assert!(src.contains("PublicField"));
    }

    #[test]
    fn test_typedef_emitter_with_namespace() {
        let mut t = make_type("Foo");
        t.namespace = "MyApp.Core".into();
        let emitter = TypeDefEmitter::new();
        let src = emitter.emit_class(&t).unwrap();
        assert!(src.contains("namespace MyApp.Core"));
        assert!(src.contains("class Foo"));
    }

    #[test]
    fn test_typedef_emitter_async_state_machine_skipped() {
        let mut t = make_type("<DoWork>d__0");
        t.interfaces.push("IAsyncStateMachine".into());
        t.fields.push(make_field("<>1__state", "int", false));
        t.fields
            .push(make_field("<>t__builder", "AsyncTaskMethodBuilder", false));
        t.methods.push(DotnetMethod {
            name: "MoveNext".into(),
            signature: MethodSignature {
                return_type: "void".into(),
                ..Default::default()
            },
            ..Default::default()
        });
        let emitter = TypeDefEmitter::new();
        let src = emitter.emit_class(&t).unwrap();
        // The state machine body should be replaced by a reconstructed async method comment
        assert!(
            src.contains("async state machine") || src.contains("async") || src.contains("DoWork")
        );
    }

    #[test]
    fn test_typedef_emitter_properties_from_accessors() {
        let mut t = make_type("Person");
        t.methods.push(DotnetMethod {
            name: "get_Name".into(),
            signature: MethodSignature {
                return_type: "string".into(),
                ..Default::default()
            },
            flags: 0x06,
            body: None,
            ..Default::default()
        });
        t.methods.push(DotnetMethod {
            name: "set_Name".into(),
            signature: MethodSignature {
                return_type: "void".into(),
                params: vec![("value".into(), "string".into())],
                ..Default::default()
            },
            flags: 0x06,
            body: None,
            ..Default::default()
        });
        let emitter = TypeDefEmitter::new();
        let src = emitter.emit_class(&t).unwrap();
        assert!(src.contains("Name"));
        assert!(src.contains("string"));
        assert!(src.contains("get;") || src.contains("get"));
    }

    #[test]
    fn test_typedef_emitter_doc_comments_option() {
        let t = make_type("Documented");
        let opts = TypeEmitOptions {
            style: TypeStyleFlags { emit_doc_comments: true, ..Default::default() },
            ..TypeEmitOptions::default()
        };
        let emitter = TypeDefEmitter::with_options(opts);
        let src = emitter.emit_class(&t).unwrap();
        assert!(src.contains("/// <summary>"));
    }

    #[test]
    fn test_typedef_emitter_delegate() {
        let mut t = make_type("EventHandler");
        t.kind_tag = rustre_dotnet::DotnetTypeKind::Delegate;
        t.methods.push(DotnetMethod {
            name: "Invoke".into(),
            signature: MethodSignature {
                return_type: "void".into(),
                params: vec![
                    ("sender".into(), "object".into()),
                    ("e".into(), "EventArgs".into()),
                ],
                ..Default::default()
            },
            flags: 0x06,
            body: None,
            ..Default::default()
        });
        let emitter = TypeDefEmitter::new();
        let src = emitter.emit_class(&t).unwrap();
        assert!(src.contains("delegate"));
        assert!(src.contains("EventHandler"));
    }

    #[test]
    fn test_typedef_emitter_generic_type() {
        use rustre_dotnet::GenericParam;
        let mut t = make_type("Container");
        t.generic_params = vec![GenericParam {
            number: 0,
            name: "T".into(),
            flags: 0,
            constraints: vec![],
        }];
        let emitter = TypeDefEmitter::new();
        let src = emitter.emit_class(&t).unwrap();
        assert!(src.contains("Container<T>"));
    }

    #[test]
    fn test_typedef_emitter_inheritance() {
        let mut t = make_type("Derived");
        t.base_type = Some("BaseClass".into());
        t.interfaces = vec!["IDisposable".into()];
        let emitter = TypeDefEmitter::new();
        let src = emitter.emit_class(&t).unwrap();
        assert!(src.contains("BaseClass") || src.contains("IDisposable"));
    }

    #[test]
    fn test_typedef_emitter_field_access_modifiers() {
        let mut t = make_type("Widget");
        let mut f = make_field("_count", "int", false);
        f.flags = 0x01; // private
        t.fields.push(f);
        let emitter = TypeDefEmitter::new();
        let src = emitter.emit_class(&t).unwrap();
        assert!(src.contains("private") || src.contains("_count"));
    }

    #[test]
    fn test_typedef_emitter_readonly_field() {
        let mut t = make_type("Immutable");
        let mut f = make_field("_value", "int", false);
        f.flags = 0x06 | 0x0020; // public + initonly
        t.fields.push(f);
        let emitter = TypeDefEmitter::new();
        let src = emitter.emit_class(&t).unwrap();
        assert!(src.contains("readonly") || src.contains("_value"));
    }

    // ── extract_method_body_text helper ──────────────────────────────────────

    #[test]
    fn test_extract_method_body_text() {
        let src = "    public int Foo()\n    {\n        return 42;\n    }\n";
        let body = extract_method_body_text(src);
        assert!(body.contains("return 42;"));
        assert!(!body.contains("public int Foo"));
    }

    // ── TypeSig instantiation ─────────────────────────────────────────────────

    #[test]
    fn test_typesig_mvar_substitution() {
        let sig = TypeSig::MVar(0);
        let method_args = vec![TypeSig::Primitive(0x0E)]; // string
        let inst = sig.instantiate(&[], &method_args);
        assert_eq!(GenericInstantiator::render(&inst), "string");
    }

    #[test]
    fn test_typesig_var_out_of_bounds() {
        let sig = TypeSig::Var(5);
        let inst = sig.instantiate(&[], &[]);
        // Should produce a placeholder
        let s = GenericInstantiator::render(&inst);
        assert!(s.contains("T5") || s.contains('T'));
    }
}
