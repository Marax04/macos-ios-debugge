//! `smali_generator` — Smali text generation from DEX bytecode.
//!
//! Generates human-readable Smali assembly from decoded DEX structures.
//! Covers register naming, label generation, instruction formatting,
//! class/method header generation, and basic register allocation.

use std::collections::HashMap;
use std::fmt::{self, Write as FmtWrite};

// ---------------------------------------------------------------------------
// Smali class
// ---------------------------------------------------------------------------

/// Smali access flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct AccessFlags(pub u32);

impl AccessFlags {
    pub const PUBLIC: u32 = 0x0001;
    pub const PRIVATE: u32 = 0x0002;
    pub const PROTECTED: u32 = 0x0004;
    pub const STATIC: u32 = 0x0008;
    pub const FINAL: u32 = 0x0010;
    pub const SYNCHRONIZED: u32 = 0x0020;
    pub const BRIDGE: u32 = 0x0040;
    pub const VARARGS: u32 = 0x0080;
    pub const NATIVE: u32 = 0x0100;
    pub const INTERFACE: u32 = 0x0200;
    pub const ABSTRACT: u32 = 0x0400;
    pub const STRICT: u32 = 0x0800;
    pub const SYNTHETIC: u32 = 0x1000;
    pub const ANNOTATION: u32 = 0x2000;
    pub const ENUM: u32 = 0x4000;
    pub const CONSTRUCTOR: u32 = 0x10000;

    #[must_use] 
    pub const fn new(flags: u32) -> Self {
        Self(flags)
    }
    #[must_use] 
    pub const fn has(self, flag: u32) -> bool {
        self.0 & flag != 0
    }

    #[must_use] 
    pub fn to_smali_class(self) -> String {
        let mut parts: Vec<&'static str> = Vec::with_capacity(7);
        if self.has(Self::PUBLIC) {
            parts.push("public");
        }
        if self.has(Self::PRIVATE) {
            parts.push("private");
        }
        if self.has(Self::PROTECTED) {
            parts.push("protected");
        }
        if self.has(Self::FINAL) {
            parts.push("final");
        }
        if self.has(Self::ABSTRACT) {
            parts.push("abstract");
        }
        if self.has(Self::INTERFACE) {
            parts.push("interface");
        }
        if self.has(Self::ENUM) {
            parts.push("enum");
        }
        parts.join(" ")
    }

    #[must_use] 
    pub fn to_smali_method(self) -> String {
        let mut parts: Vec<&'static str> = Vec::with_capacity(9);
        if self.has(Self::PUBLIC) {
            parts.push("public");
        }
        if self.has(Self::PRIVATE) {
            parts.push("private");
        }
        if self.has(Self::PROTECTED) {
            parts.push("protected");
        }
        if self.has(Self::STATIC) {
            parts.push("static");
        }
        if self.has(Self::FINAL) {
            parts.push("final");
        }
        if self.has(Self::SYNCHRONIZED) {
            parts.push("synchronized");
        }
        if self.has(Self::NATIVE) {
            parts.push("native");
        }
        if self.has(Self::ABSTRACT) {
            parts.push("abstract");
        }
        if self.has(Self::CONSTRUCTOR) {
            parts.push("constructor");
        }
        parts.join(" ")
    }
}

// ---------------------------------------------------------------------------
// Register allocation
// ---------------------------------------------------------------------------

/// Simple register allocator that maps virtual registers to Smali `v`/`p` names.
#[derive(Debug, Clone)]
pub struct RegisterAllocation {
    pub register_count: u16,
    pub param_count: u16,
}

impl RegisterAllocation {
    /// Create an allocation with `regs` total registers and `params` parameter registers.
    #[must_use] 
    pub const fn new(register_count: u16, param_count: u16) -> Self {
        Self {
            register_count,
            param_count,
        }
    }

    /// Number of local (v) registers.
    #[must_use] 
    pub const fn local_count(&self) -> u16 {
        self.register_count.saturating_sub(self.param_count)
    }

    /// Get the Smali name of register `n`.
    /// Parameter registers start at `register_count - param_count`.
    #[must_use] 
    pub fn name(&self, reg: u16) -> String {
        let param_start = self.register_count.saturating_sub(self.param_count);
        if reg >= param_start && self.param_count > 0 {
            format!("p{}", reg - param_start)
        } else {
            format!("v{reg}")
        }
    }

    /// Generate `.registers N` directive.
    #[must_use] 
    pub fn registers_directive(&self) -> String {
        format!(".registers {}", self.register_count)
    }
}

// ---------------------------------------------------------------------------
// Label generator
// ---------------------------------------------------------------------------

/// Generates unique Smali labels for jump targets.
#[derive(Debug, Default)]
pub struct LabelGenerator {
    labels: HashMap<u32, String>,
    counter: u32,
}

impl LabelGenerator {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    /// Get or create a label for the given bytecode offset.
    pub fn label_for(&mut self, offset: u32) -> String {
        if let Some(l) = self.labels.get(&offset) {
            return l.clone();
        }
        let label = format!(":goto_{:04x}", self.counter);
        self.counter += 1;
        self.labels.insert(offset, label.clone());
        label
    }

    /// Return all labels sorted by offset.
    #[must_use] 
    pub fn sorted_labels(&self) -> Vec<(u32, &str)> {
        let mut v: Vec<(u32, &str)> = self.labels.iter().map(|(&o, l)| (o, l.as_str())).collect();
        v.sort_by_key(|(o, _)| *o);
        v
    }

    #[must_use] 
    pub fn count(&self) -> usize {
        self.labels.len()
    }
}

// ---------------------------------------------------------------------------
// Smali instruction
// ---------------------------------------------------------------------------

/// A single Smali instruction with optional label and comment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SmaliInstruction {
    pub label: Option<String>,
    pub mnemonic: String,
    pub operands: Vec<String>,
    pub comment: Option<String>,
}

impl SmaliInstruction {
    pub fn new(mnemonic: impl Into<String>, operands: Vec<String>) -> Self {
        Self {
            label: None,
            mnemonic: mnemonic.into(),
            operands,
            comment: None,
        }
    }

    #[must_use]
    pub fn with_label(mut self, label: impl Into<String>) -> Self {
        self.label = Some(label.into());
        self
    }

    #[must_use]
    pub fn with_comment(mut self, comment: impl Into<String>) -> Self {
        self.comment = Some(comment.into());
        self
    }

    /// Format as a Smali text line.
    #[must_use] 
    pub fn format(&self) -> String {
        let mut out = String::new();
        if let Some(ref lbl) = self.label {
            out.push_str(lbl);
            out.push('\n');
        }
        out.push_str("    ");
        out.push_str(&self.mnemonic);
        if !self.operands.is_empty() {
            out.push(' ');
            out.push_str(&self.operands.join(", "));
        }
        if let Some(ref cmt) = self.comment {
            out.push_str("  # ");
            out.push_str(cmt);
        }
        out
    }
}

impl fmt::Display for SmaliInstruction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.format())
    }
}

// ---------------------------------------------------------------------------
// SmaliMethod
// ---------------------------------------------------------------------------

/// A Smali method with header and body.
#[derive(Debug, Clone)]
pub struct SmaliMethod {
    pub name: String,
    pub access_flags: AccessFlags,
    pub params: Vec<String>,
    pub return_type: String,
    pub registers: RegisterAllocation,
    pub instructions: Vec<SmaliInstruction>,
}

impl SmaliMethod {
    pub fn new(
        name: impl Into<String>,
        flags: AccessFlags,
        params: Vec<String>,
        return_type: impl Into<String>,
        registers: RegisterAllocation,
    ) -> Self {
        Self {
            name: name.into(),
            access_flags: flags,
            params,
            return_type: return_type.into(),
            registers,
            instructions: Vec::new(),
        }
    }

    pub fn add_instruction(&mut self, insn: SmaliInstruction) {
        self.instructions.push(insn);
    }

    /// Generate the Smali text for this method.
    #[must_use] 
    pub fn to_smali(&self) -> String {
        let mut out = String::new();
        let flags_str = self.access_flags.to_smali_method();
        let param_str = self.params.join("");
        let _ = writeln!(
            out,
            ".method {flags_str} {name}({param_str}){ret}",
            name = self.name,
            param_str = param_str,
            ret = self.return_type,
        );
        let _ = writeln!(out, "    {}", self.registers.registers_directive());
        for insn in &self.instructions {
            out.push_str(&insn.format());
            out.push('\n');
        }
        out.push_str(".end method\n");
        out
    }
}

// ---------------------------------------------------------------------------
// SmaliField
// ---------------------------------------------------------------------------

/// A Smali field declaration.
#[derive(Debug, Clone)]
pub struct SmaliField {
    pub name: String,
    pub access_flags: AccessFlags,
    pub field_type: String,
    pub initial_value: Option<String>,
}

impl SmaliField {
    #[must_use] 
    pub fn to_smali(&self) -> String {
        let flags = self.access_flags.to_smali_class();
        let mut s = format!(".field {flags} {}:{}", self.name, self.field_type);
        if let Some(ref v) = self.initial_value {
            s.push_str(" = ");
            s.push_str(v);
        }
        s.push('\n');
        s
    }
}

// ---------------------------------------------------------------------------
// SmaliClass
// ---------------------------------------------------------------------------

/// A complete Smali class.
#[derive(Debug, Clone)]
pub struct SmaliClass {
    pub class_name: String,
    pub superclass: String,
    pub interfaces: Vec<String>,
    pub access_flags: AccessFlags,
    pub source_file: Option<String>,
    pub fields: Vec<SmaliField>,
    pub methods: Vec<SmaliMethod>,
}

impl SmaliClass {
    pub fn new(
        class_name: impl Into<String>,
        superclass: impl Into<String>,
        flags: AccessFlags,
    ) -> Self {
        Self {
            class_name: class_name.into(),
            superclass: superclass.into(),
            interfaces: Vec::new(),
            access_flags: flags,
            source_file: None,
            fields: Vec::new(),
            methods: Vec::new(),
        }
    }

    pub fn add_interface(&mut self, iface: impl Into<String>) {
        self.interfaces.push(iface.into());
    }

    pub fn add_field(&mut self, field: SmaliField) {
        self.fields.push(field);
    }
    pub fn add_method(&mut self, method: SmaliMethod) {
        self.methods.push(method);
    }

    /// Generate the full Smali text for this class.
    #[must_use] 
    pub fn to_smali(&self) -> String {
        let mut out = String::new();
        let flags_str = self.access_flags.to_smali_class();
        let _ = writeln!(out, ".class {flags_str} {}", self.class_name);
        let _ = writeln!(out, ".super {}", self.superclass);
        if let Some(ref src) = self.source_file {
            let _ = writeln!(out, ".source \"{src}\"");
        }
        for iface in &self.interfaces {
            let _ = writeln!(out, ".implements {iface}");
        }
        for field in &self.fields {
            out.push_str(&field.to_smali());
        }
        for method in &self.methods {
            out.push_str(&method.to_smali());
        }
        out
    }
}

// ---------------------------------------------------------------------------
// SmaliVerifier
// ---------------------------------------------------------------------------

/// Errors detected by [`SmaliVerifier`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SmaliVerifierErrorMarker;

// ---------------------------------------------------------------------------
// Smali type system helpers
// ---------------------------------------------------------------------------

/// Converts a Java type name to a Smali descriptor.
#[must_use] 
pub fn java_to_descriptor(java_type: &str) -> String {
    match java_type {
        "void" => "V".into(),
        "boolean" => "Z".into(),
        "byte" => "B".into(),
        "char" => "C".into(),
        "short" => "S".into(),
        "int" => "I".into(),
        "long" => "J".into(),
        "float" => "F".into(),
        "double" => "D".into(),
        t if t.ends_with("[]") => format!("[{}", java_to_descriptor(&t[..t.len() - 2])),
        t => format!("L{};", t.replace('.', "/")),
    }
}

/// Converts a Smali descriptor back to a Java type name.
#[must_use] 
pub fn descriptor_to_java(desc: &str) -> String {
    match desc {
        "V" => "void".into(),
        "Z" => "boolean".into(),
        "B" => "byte".into(),
        "C" => "char".into(),
        "S" => "short".into(),
        "I" => "int".into(),
        "J" => "long".into(),
        "F" => "float".into(),
        "D" => "double".into(),
        d if d.starts_with('[') => format!("{}[]", descriptor_to_java(&d[1..])),
        d if d.starts_with('L') && d.ends_with(';') => d[1..d.len() - 1].replace('/', "."),
        d => d.into(),
    }
}

/// Builds a Smali method signature string.
#[must_use] 
pub fn build_method_signature(name: &str, params: &[&str], return_type: &str) -> String {
    let param_desc: String = params.iter().map(|p| java_to_descriptor(p)).collect();
    let ret_desc = java_to_descriptor(return_type);
    format!("{name}({param_desc}){ret_desc}")
}

// ---------------------------------------------------------------------------
// Smali annotation
// ---------------------------------------------------------------------------

/// A Smali annotation.
#[derive(Debug, Clone)]
pub struct SmaliAnnotation {
    pub visibility: AnnotationVisibility,
    pub annotation_type: String,
    pub elements: Vec<(String, String)>,
}

/// Annotation visibility in Smali.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnnotationVisibility {
    Build,
    Runtime,
    System,
}

impl fmt::Display for AnnotationVisibility {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Build => write!(f, "build"),
            Self::Runtime => write!(f, "runtime"),
            Self::System => write!(f, "system"),
        }
    }
}

impl SmaliAnnotation {
    #[must_use] 
    pub fn to_smali(&self) -> String {
        let mut out = format!(".annotation {} {}\n", self.visibility, self.annotation_type);
        for (k, v) in &self.elements {
            use std::fmt::Write as _;
            let _ = writeln!(out, "    {k} = {v}");
        }
        out.push_str(".end annotation\n");
        out
    }
}

// ---------------------------------------------------------------------------
// Smali instruction builders
// ---------------------------------------------------------------------------

/// Helper functions for building common Smali instructions.
pub mod insn {
    use super::SmaliInstruction;

    #[must_use] 
    pub fn return_void() -> SmaliInstruction {
        SmaliInstruction::new("return-void", vec![])
    }

    #[must_use] 
    pub fn return_object(reg: &str) -> SmaliInstruction {
        SmaliInstruction::new("return-object", vec![reg.into()])
    }

    #[must_use] 
    pub fn return_wide(reg: &str) -> SmaliInstruction {
        SmaliInstruction::new("return-wide", vec![reg.into()])
    }

    #[must_use] 
    pub fn const_string(dst: &str, s: &str) -> SmaliInstruction {
        SmaliInstruction::new("const-string", vec![dst.into(), format!("\"{s}\"")])
    }

    #[must_use] 
    pub fn const_4(dst: &str, val: i8) -> SmaliInstruction {
        SmaliInstruction::new("const/4", vec![dst.into(), format!("{val:#x}")])
    }

    #[must_use] 
    pub fn const_16(dst: &str, val: i16) -> SmaliInstruction {
        SmaliInstruction::new("const/16", vec![dst.into(), format!("{val:#x}")])
    }

    #[must_use] 
    pub fn move_(dst: &str, src: &str) -> SmaliInstruction {
        SmaliInstruction::new("move", vec![dst.into(), src.into()])
    }

    #[must_use] 
    pub fn invoke_virtual(regs: &[&str], method: &str) -> SmaliInstruction {
        let reg_str = format!("{{{}}}", regs.join(", "));
        SmaliInstruction::new("invoke-virtual", vec![reg_str, method.into()])
    }

    #[must_use] 
    pub fn invoke_static(regs: &[&str], method: &str) -> SmaliInstruction {
        let reg_str = format!("{{{}}}", regs.join(", "));
        SmaliInstruction::new("invoke-static", vec![reg_str, method.into()])
    }

    #[must_use] 
    pub fn invoke_special(regs: &[&str], method: &str) -> SmaliInstruction {
        let reg_str = format!("{{{}}}", regs.join(", "));
        SmaliInstruction::new("invoke-special", vec![reg_str, method.into()])
    }

    #[must_use] 
    pub fn iget(dst: &str, obj: &str, field: &str) -> SmaliInstruction {
        SmaliInstruction::new("iget", vec![dst.into(), obj.into(), field.into()])
    }

    #[must_use] 
    pub fn iput(src: &str, obj: &str, field: &str) -> SmaliInstruction {
        SmaliInstruction::new("iput", vec![src.into(), obj.into(), field.into()])
    }

    #[must_use] 
    pub fn sget(dst: &str, field: &str) -> SmaliInstruction {
        SmaliInstruction::new("sget", vec![dst.into(), field.into()])
    }

    #[must_use] 
    pub fn new_instance(dst: &str, class: &str) -> SmaliInstruction {
        SmaliInstruction::new("new-instance", vec![dst.into(), class.into()])
    }

    #[must_use] 
    pub fn if_eqz(reg: &str, label: &str) -> SmaliInstruction {
        SmaliInstruction::new("if-eqz", vec![reg.into(), label.into()])
    }

    #[must_use] 
    pub fn if_nez(reg: &str, label: &str) -> SmaliInstruction {
        SmaliInstruction::new("if-nez", vec![reg.into(), label.into()])
    }

    #[must_use] 
    pub fn nop() -> SmaliInstruction {
        SmaliInstruction::new("nop", vec![])
    }
}

pub enum SmaliVerifyError {
    /// A register index exceeds the declared register count.
    RegisterOutOfRange { reg: u16, max: u16, method: String },
    /// A method has no `.registers` equivalent (register count = 0).
    ZeroRegisters { method: String },
    /// A label is referenced but never defined.
    UndefinedLabel { label: String, method: String },
}

impl fmt::Display for SmaliVerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RegisterOutOfRange { reg, max, method } => write!(
                f,
                "method {method}: register v{reg} out of range (max v{max})"
            ),
            Self::ZeroRegisters { method } => write!(f, "method {method}: zero registers declared"),
            Self::UndefinedLabel { label, method } => {
                write!(f, "method {method}: undefined label '{label}'")
            }
        }
    }
}

/// Basic structural verifier for Smali output.
#[derive(Debug, Default)]
pub struct SmaliVerifier;

impl SmaliVerifier {
    #[must_use] 
    pub const fn new() -> Self {
        Self
    }

    /// Verify a [`SmaliClass`] and return any errors found.
    #[must_use] 
    pub fn verify(&self, class: &SmaliClass) -> Vec<SmaliVerifyError> {
        let mut errors = Vec::new();
        for method in &class.methods {
            if method.registers.register_count == 0 {
                errors.push(SmaliVerifyError::ZeroRegisters {
                    method: method.name.clone(),
                });
            }
        }
        errors
    }
}

// ---------------------------------------------------------------------------
// SmaliFormatter
// ---------------------------------------------------------------------------

/// Formats Smali output with configurable indentation and comment style.
#[derive(Debug)]
pub struct SmaliFormatter {
    pub indent: String,
    pub show_offsets: bool,
}

impl Default for SmaliFormatter {
    fn default() -> Self {
        Self {
            indent: "    ".into(),
            show_offsets: false,
        }
    }
}

impl SmaliFormatter {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn with_indent(mut self, indent: impl Into<String>) -> Self {
        self.indent = indent.into();
        self
    }

    #[must_use] 
    pub const fn with_offsets(mut self) -> Self {
        self.show_offsets = true;
        self
    }

    /// Format a [`SmaliClass`] to a string.
    #[must_use] 
    pub fn format_class(&self, class: &SmaliClass) -> String {
        class.to_smali()
    }

    /// Format a single instruction with this formatter's indentation.
    #[must_use] 
    pub fn format_instruction(&self, insn: &SmaliInstruction) -> String {
        let base = insn.format();
        // Replace leading 4 spaces with configured indent
        base.strip_prefix("    ")
            .map_or_else(|| base.clone(), |rest| format!("{}{}", self.indent, rest))
    }
}

// ---------------------------------------------------------------------------
// SmaliGenerator — top-level
// ---------------------------------------------------------------------------

/// Generates Smali text from a collection of classes.
#[derive(Debug, Default)]
pub struct SmaliGenerator {
    classes: Vec<SmaliClass>,
}

impl SmaliGenerator {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_class(&mut self, class: SmaliClass) {
        self.classes.push(class);
    }

    /// Generate all classes as a map from class name to Smali text.
    #[must_use] 
    pub fn generate_all(&self) -> HashMap<String, String> {
        self.classes
            .iter()
            .map(|c| (c.class_name.clone(), c.to_smali()))
            .collect()
    }

    /// Generate Smali for a single class by name.
    #[must_use] 
    pub fn generate(&self, class_name: &str) -> Option<String> {
        self.classes
            .iter()
            .find(|c| c.class_name == class_name)
            .map(SmaliClass::to_smali)
    }

    #[must_use] 
    pub const fn class_count(&self) -> usize {
        self.classes.len()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // --- AccessFlags -------------------------------------------------------

    #[test]
    fn test_access_flags_has_public() {
        let f = AccessFlags::new(AccessFlags::PUBLIC);
        assert!(f.has(AccessFlags::PUBLIC));
        assert!(!f.has(AccessFlags::STATIC));
    }

    #[test]
    fn test_access_flags_class_string() {
        let f = AccessFlags::new(AccessFlags::PUBLIC | AccessFlags::FINAL);
        let s = f.to_smali_class();
        assert!(s.contains("public"));
        assert!(s.contains("final"));
    }

    #[test]
    fn test_access_flags_method_string() {
        let f = AccessFlags::new(AccessFlags::PUBLIC | AccessFlags::STATIC);
        let s = f.to_smali_method();
        assert!(s.contains("static"));
    }

    #[test]
    fn test_access_flags_constructor() {
        let f = AccessFlags::new(AccessFlags::PUBLIC | AccessFlags::CONSTRUCTOR);
        assert!(f.to_smali_method().contains("constructor"));
    }

    // --- RegisterAllocation ------------------------------------------------

    #[test]
    fn test_register_alloc_local() {
        let alloc = RegisterAllocation::new(5, 2);
        assert_eq!(alloc.local_count(), 3);
        assert_eq!(alloc.name(0), "v0");
        assert_eq!(alloc.name(3), "p0");
        assert_eq!(alloc.name(4), "p1");
    }

    #[test]
    fn test_register_alloc_directive() {
        let alloc = RegisterAllocation::new(4, 1);
        assert_eq!(alloc.registers_directive(), ".registers 4");
    }

    #[test]
    fn test_register_alloc_all_local() {
        let alloc = RegisterAllocation::new(3, 0);
        assert_eq!(alloc.name(0), "v0");
        assert_eq!(alloc.name(2), "v2");
        assert_eq!(alloc.local_count(), 3);
    }

    // --- LabelGenerator ----------------------------------------------------

    #[test]
    fn test_label_generator_creates_labels() {
        let mut lg = LabelGenerator::new();
        let l1 = lg.label_for(0x10);
        let l2 = lg.label_for(0x20);
        assert_ne!(l1, l2);
        assert_eq!(lg.count(), 2);
    }

    #[test]
    fn test_label_generator_idempotent() {
        let mut lg = LabelGenerator::new();
        let l1 = lg.label_for(0x10);
        let l2 = lg.label_for(0x10);
        assert_eq!(l1, l2);
        assert_eq!(lg.count(), 1);
    }

    #[test]
    fn test_label_generator_sorted() {
        let mut lg = LabelGenerator::new();
        lg.label_for(0x30);
        lg.label_for(0x10);
        lg.label_for(0x20);
        let sorted = lg.sorted_labels();
        assert_eq!(sorted[0].0, 0x10);
        assert_eq!(sorted[2].0, 0x30);
    }

    // --- SmaliInstruction --------------------------------------------------

    #[test]
    fn test_smali_instruction_format_simple() {
        let insn = SmaliInstruction::new("return-void", vec![]);
        let s = insn.format();
        assert!(s.contains("return-void"));
    }

    #[test]
    fn test_smali_instruction_with_operands() {
        let insn = SmaliInstruction::new("move", vec!["v0".into(), "v1".into()]);
        let s = insn.format();
        assert!(s.contains("v0"));
        assert!(s.contains("v1"));
    }

    #[test]
    fn test_smali_instruction_with_label() {
        let insn = SmaliInstruction::new("nop", vec![]).with_label(":goto_0000");
        let s = insn.format();
        assert!(s.contains(":goto_0000"));
    }

    #[test]
    fn test_smali_instruction_with_comment() {
        let insn = SmaliInstruction::new("nop", vec![]).with_comment("dead code");
        let s = insn.format();
        assert!(s.contains("dead code"));
    }

    #[test]
    fn test_smali_instruction_display() {
        let insn = SmaliInstruction::new("return-void", vec![]);
        assert!(insn.to_string().contains("return-void"));
    }

    // --- SmaliMethod -------------------------------------------------------

    #[test]
    fn test_smali_method_to_smali() {
        let mut m = SmaliMethod::new(
            "toString",
            AccessFlags::new(AccessFlags::PUBLIC),
            vec![],
            "Ljava/lang/String;",
            RegisterAllocation::new(2, 1),
        );
        m.add_instruction(SmaliInstruction::new("return-object", vec!["p0".into()]));
        let s = m.to_smali();
        assert!(s.contains(".method"));
        assert!(s.contains("toString"));
        assert!(s.contains(".end method"));
        assert!(s.contains("return-object"));
    }

    #[test]
    fn test_smali_method_registers_directive() {
        let m = SmaliMethod::new(
            "init",
            AccessFlags::new(AccessFlags::PUBLIC | AccessFlags::CONSTRUCTOR),
            vec![],
            "V",
            RegisterAllocation::new(3, 1),
        );
        let s = m.to_smali();
        assert!(s.contains(".registers 3"));
    }

    // --- SmaliClass --------------------------------------------------------

    #[test]
    fn test_smali_class_to_smali() {
        let class = SmaliClass::new(
            "Lcom/example/Foo;",
            "Ljava/lang/Object;",
            AccessFlags::new(AccessFlags::PUBLIC),
        );
        let s = class.to_smali();
        assert!(s.contains(".class"));
        assert!(s.contains("Lcom/example/Foo;"));
        assert!(s.contains(".super"));
    }

    #[test]
    fn test_smali_class_with_interface() {
        let mut class = SmaliClass::new(
            "Lcom/example/Bar;",
            "Ljava/lang/Object;",
            AccessFlags::new(AccessFlags::PUBLIC),
        );
        class.add_interface("Ljava/io/Serializable;");
        let s = class.to_smali();
        assert!(s.contains(".implements Ljava/io/Serializable;"));
    }

    #[test]
    fn test_smali_class_with_source() {
        let mut class = SmaliClass::new("LA;", "LB;", AccessFlags::new(0));
        class.source_file = Some("A.java".into());
        let s = class.to_smali();
        assert!(s.contains(".source \"A.java\""));
    }

    #[test]
    fn test_smali_class_with_field() {
        let mut class = SmaliClass::new("LA;", "LB;", AccessFlags::new(AccessFlags::PUBLIC));
        class.add_field(SmaliField {
            name: "count".into(),
            access_flags: AccessFlags::new(AccessFlags::PRIVATE),
            field_type: "I".into(),
            initial_value: None,
        });
        let s = class.to_smali();
        assert!(s.contains(".field"));
        assert!(s.contains("count:I"));
    }

    // --- SmaliVerifier -----------------------------------------------------

    #[test]
    fn test_verifier_no_errors_valid_class() {
        let mut class = SmaliClass::new("LA;", "LB;", AccessFlags::new(AccessFlags::PUBLIC));
        class.add_method(SmaliMethod::new(
            "foo",
            AccessFlags::new(AccessFlags::PUBLIC),
            vec![],
            "V",
            RegisterAllocation::new(2, 1),
        ));
        let v = SmaliVerifier::new();
        assert!(v.verify(&class).is_empty());
    }

    #[test]
    fn test_verifier_zero_registers_error() {
        let mut class = SmaliClass::new("LA;", "LB;", AccessFlags::new(AccessFlags::PUBLIC));
        class.add_method(SmaliMethod::new(
            "foo",
            AccessFlags::new(AccessFlags::PUBLIC),
            vec![],
            "V",
            RegisterAllocation::new(0, 0),
        ));
        let v = SmaliVerifier::new();
        let errors = v.verify(&class);
        assert!(!errors.is_empty());
        assert!(matches!(errors[0], SmaliVerifyError::ZeroRegisters { .. }));
    }

    #[test]
    fn test_verifier_error_display() {
        let e = SmaliVerifyError::ZeroRegisters {
            method: "foo".into(),
        };
        assert!(e.to_string().contains("foo"));
    }

    // --- SmaliFormatter ----------------------------------------------------

    #[test]
    fn test_formatter_default_indent() {
        let fmt = SmaliFormatter::new();
        let insn = SmaliInstruction::new("nop", vec![]);
        let s = fmt.format_instruction(&insn);
        assert!(s.contains("nop"));
    }

    #[test]
    fn test_formatter_custom_indent() {
        let fmt = SmaliFormatter::new().with_indent("  ");
        let insn = SmaliInstruction::new("nop", vec![]);
        let s = fmt.format_instruction(&insn);
        assert!(s.starts_with("  nop"));
    }

    // --- SmaliGenerator ----------------------------------------------------

    #[test]
    fn test_generator_empty() {
        let g = SmaliGenerator::new();
        assert_eq!(g.class_count(), 0);
        assert!(g.generate_all().is_empty());
    }

    #[test]
    fn test_generator_add_and_generate() {
        let mut g = SmaliGenerator::new();
        g.add_class(SmaliClass::new(
            "LA;",
            "LB;",
            AccessFlags::new(AccessFlags::PUBLIC),
        ));
        assert_eq!(g.class_count(), 1);
        let all = g.generate_all();
        assert!(all.contains_key("LA;"));
    }

    #[test]
    fn test_generator_generate_by_name() {
        let mut g = SmaliGenerator::new();
        g.add_class(SmaliClass::new(
            "LA;",
            "LB;",
            AccessFlags::new(AccessFlags::PUBLIC),
        ));
        assert!(g.generate("LA;").is_some());
        assert!(g.generate("LX;").is_none());
    }

    #[test]
    fn test_smali_field_to_smali_with_value() {
        let f = SmaliField {
            name: "TAG".into(),
            access_flags: AccessFlags::new(
                AccessFlags::PUBLIC | AccessFlags::STATIC | AccessFlags::FINAL,
            ),
            field_type: "Ljava/lang/String;".into(),
            initial_value: Some("\"MyTag\"".into()),
        };
        let s = f.to_smali();
        assert!(s.contains("TAG:Ljava/lang/String;"));
        assert!(s.contains("= \"MyTag\""));
    }

    // --- Additional AccessFlags tests ---

    #[test]
    fn test_access_flags_interface() {
        let f =
            AccessFlags::new(AccessFlags::PUBLIC | AccessFlags::INTERFACE | AccessFlags::ABSTRACT);
        let s = f.to_smali_class();
        assert!(s.contains("interface"));
        assert!(s.contains("abstract"));
    }

    #[test]
    fn test_access_flags_enum() {
        let f = AccessFlags::new(AccessFlags::PUBLIC | AccessFlags::ENUM);
        assert!(f.to_smali_class().contains("enum"));
    }

    #[test]
    fn test_access_flags_synthetic() {
        let f = AccessFlags::new(AccessFlags::SYNTHETIC);
        assert!(f.has(AccessFlags::SYNTHETIC));
    }

    #[test]
    fn test_access_flags_native_method() {
        let f = AccessFlags::new(AccessFlags::PUBLIC | AccessFlags::NATIVE);
        assert!(f.to_smali_method().contains("native"));
    }

    #[test]
    fn test_access_flags_synchronized() {
        let f = AccessFlags::new(AccessFlags::PUBLIC | AccessFlags::SYNCHRONIZED);
        assert!(f.to_smali_method().contains("synchronized"));
    }

    // --- Additional RegisterAllocation tests ---

    #[test]
    fn test_register_alloc_p_names() {
        let alloc = RegisterAllocation::new(3, 3);
        assert_eq!(alloc.name(0), "p0");
        assert_eq!(alloc.name(2), "p2");
    }

    #[test]
    fn test_register_alloc_zero_params() {
        let alloc = RegisterAllocation::new(2, 0);
        assert_eq!(alloc.local_count(), 2);
        assert_eq!(alloc.name(0), "v0");
        assert_eq!(alloc.name(1), "v1");
    }

    // --- Additional SmaliMethod tests ---

    #[test]
    fn test_smali_method_multiple_params() {
        let m = SmaliMethod::new(
            "concat",
            AccessFlags::new(AccessFlags::PUBLIC | AccessFlags::STATIC),
            vec!["Ljava/lang/String;".into(), "Ljava/lang/String;".into()],
            "Ljava/lang/String;",
            RegisterAllocation::new(4, 2),
        );
        let s = m.to_smali();
        assert!(s.contains("concat"));
        assert!(s.contains("public"));
        assert!(s.contains("static"));
    }

    #[test]
    fn test_smali_method_abstract() {
        let m = SmaliMethod::new(
            "doSomething",
            AccessFlags::new(AccessFlags::PUBLIC | AccessFlags::ABSTRACT),
            vec![],
            "V",
            RegisterAllocation::new(1, 1),
        );
        let s = m.to_smali();
        assert!(s.contains("abstract"));
    }

    // --- Additional SmaliInstruction tests ---

    #[test]
    fn test_smali_instruction_invoke_virtual() {
        let insn = SmaliInstruction::new(
            "invoke-virtual",
            vec![
                "{v0, v1}".into(),
                "Ljava/io/PrintStream;->println(Ljava/lang/String;)V".into(),
            ],
        );
        let s = insn.format();
        assert!(s.contains("invoke-virtual"));
        assert!(s.contains("println"));
    }

    #[test]
    fn test_smali_instruction_iget() {
        let insn = SmaliInstruction::new(
            "iget",
            vec!["v0".into(), "p0".into(), "LFoo;->count:I".into()],
        );
        assert!(insn.format().contains("iget"));
    }

    // --- Additional SmaliClass tests ---

    #[test]
    fn test_smali_class_multiple_methods() {
        let mut class = SmaliClass::new("LA;", "LB;", AccessFlags::new(AccessFlags::PUBLIC));
        for i in 0..3 {
            class.add_method(SmaliMethod::new(
                format!("method{i}"),
                AccessFlags::new(AccessFlags::PUBLIC),
                vec![],
                "V",
                RegisterAllocation::new(1, 1),
            ));
        }
        let s = class.to_smali();
        assert!(s.contains("method0"));
        assert!(s.contains("method2"));
    }

    // --- Additional SmaliVerifier tests ---

    #[test]
    fn test_verifier_multiple_methods_one_error() {
        let mut class = SmaliClass::new("LA;", "LB;", AccessFlags::new(AccessFlags::PUBLIC));
        class.add_method(SmaliMethod::new(
            "good",
            AccessFlags::new(AccessFlags::PUBLIC),
            vec![],
            "V",
            RegisterAllocation::new(2, 1),
        ));
        class.add_method(SmaliMethod::new(
            "bad",
            AccessFlags::new(AccessFlags::PUBLIC),
            vec![],
            "V",
            RegisterAllocation::new(0, 0),
        ));
        let errors = SmaliVerifier::new().verify(&class);
        assert_eq!(errors.len(), 1);
    }

    // --- Additional SmaliGenerator tests ---

    #[test]
    fn test_generator_multiple_classes() {
        let mut g = SmaliGenerator::new();
        g.add_class(SmaliClass::new(
            "LA;",
            "LB;",
            AccessFlags::new(AccessFlags::PUBLIC),
        ));
        g.add_class(SmaliClass::new(
            "LC;",
            "LD;",
            AccessFlags::new(AccessFlags::PUBLIC),
        ));
        assert_eq!(g.class_count(), 2);
        assert_eq!(g.generate_all().len(), 2);
    }

    #[test]
    fn test_label_generator_prefix() {
        let mut lg = LabelGenerator::new();
        let l = lg.label_for(0);
        assert!(l.starts_with(':'));
    }

    #[test]
    fn test_smali_formatter_format_class() {
        let fmt = SmaliFormatter::new();
        let class = SmaliClass::new("LA;", "LB;", AccessFlags::new(AccessFlags::PUBLIC));
        let s = fmt.format_class(&class);
        assert!(s.contains(".class"));
    }

    // --- java_to_descriptor / descriptor_to_java ---

    #[test]
    fn test_java_to_descriptor_int() {
        assert_eq!(java_to_descriptor("int"), "I");
    }

    #[test]
    fn test_java_to_descriptor_void() {
        assert_eq!(java_to_descriptor("void"), "V");
    }

    #[test]
    fn test_java_to_descriptor_long() {
        assert_eq!(java_to_descriptor("long"), "J");
    }

    #[test]
    fn test_java_to_descriptor_object() {
        assert_eq!(java_to_descriptor("java.lang.String"), "Ljava/lang/String;");
    }

    #[test]
    fn test_java_to_descriptor_array_int() {
        assert_eq!(java_to_descriptor("int[]"), "[I");
    }

    #[test]
    fn test_descriptor_to_java_int() {
        assert_eq!(descriptor_to_java("I"), "int");
    }

    #[test]
    fn test_descriptor_to_java_object() {
        assert_eq!(descriptor_to_java("Ljava/lang/String;"), "java.lang.String");
    }

    #[test]
    fn test_descriptor_to_java_array() {
        assert_eq!(descriptor_to_java("[I"), "int[]");
    }

    #[test]
    fn test_build_method_signature() {
        let sig = build_method_signature("greet", &["java.lang.String"], "void");
        assert!(sig.contains("greet"));
        assert!(sig.contains("Ljava/lang/String;"));
        assert!(sig.ends_with(")V"));
    }

    // --- insn builder helpers ---

    #[test]
    fn test_insn_return_void() {
        let i = insn::return_void();
        assert_eq!(i.mnemonic, "return-void");
    }

    #[test]
    fn test_insn_const_string() {
        let i = insn::const_string("v0", "hello");
        assert!(i.format().contains("const-string"));
        assert!(i.format().contains("hello"));
    }

    #[test]
    fn test_insn_invoke_virtual() {
        let i = insn::invoke_virtual(&["v0", "v1"], "LFoo;->bar()V");
        assert!(i.format().contains("invoke-virtual"));
    }

    #[test]
    fn test_insn_iget() {
        let i = insn::iget("v0", "p0", "LFoo;->x:I");
        assert!(i.format().contains("iget"));
    }

    #[test]
    fn test_insn_if_eqz() {
        let i = insn::if_eqz("v0", ":end");
        assert!(i.format().contains("if-eqz"));
        assert!(i.format().contains(":end"));
    }

    #[test]
    fn test_insn_new_instance() {
        let i = insn::new_instance("v0", "Ljava/lang/StringBuilder;");
        assert!(i.format().contains("new-instance"));
    }

    // --- SmaliAnnotation ---

    #[test]
    fn test_annotation_to_smali() {
        let ann = SmaliAnnotation {
            visibility: AnnotationVisibility::Runtime,
            annotation_type: "Ljava/lang/Deprecated;".into(),
            elements: vec![],
        };
        let s = ann.to_smali();
        assert!(s.contains(".annotation runtime"));
        assert!(s.contains(".end annotation"));
    }

    #[test]
    fn test_annotation_visibility_display() {
        assert_eq!(AnnotationVisibility::Build.to_string(), "build");
        assert_eq!(AnnotationVisibility::System.to_string(), "system");
    }
}
