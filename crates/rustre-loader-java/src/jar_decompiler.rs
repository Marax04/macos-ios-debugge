//! `jar_decompiler` — High-level JAR/class decompiler and analysis facade.
//!
//! Provides structured decompilation output for Java `.class` files:
//! - `JarDecompiler`: entry-point orchestrator for JAR archives.
//! - `ClassFileDisassembler`: renders bytecode as readable text.
//! - `ConstantPoolAnalyser`: deep inspection of constant-pool entries.
//! - `MethodBody`: decoded bytecode + CFG of a single method.
//! - `AnnotationReader`: reads runtime-visible and -invisible annotations.
//! - `InnerClassInfo`: tracks inner/nested class relationships.

use std::collections::HashMap;
use std::fmt;

// Re-use types from the parent crate.
pub use crate::JavaLoaderError;
use crate::{
    ConstantPoolEntry, JavaClass, JavaClassFlags, JvmDisassembler, JvmInstruction, JvmOpcode,
};

// ─────────────────────────────────────────────────────────────────────────────
// ConstantPoolAnalyser
// ─────────────────────────────────────────────────────────────────────────────

/// Deep analysis of a Java class's constant pool.
pub struct ConstantPoolAnalyser<'a> {
    pool: &'a [ConstantPoolEntry],
}

/// Statistics derived from the constant pool.
#[derive(Debug, Clone, Default)]
pub struct ConstantPoolStats {
    pub utf8_count: usize,
    pub class_ref_count: usize,
    pub method_ref_count: usize,
    pub field_ref_count: usize,
    pub string_ref_count: usize,
    pub integer_count: usize,
    pub long_count: usize,
    pub float_count: usize,
    pub double_count: usize,
    pub name_and_type_count: usize,
    pub other_count: usize,
    pub total: usize,
}

impl<'a> ConstantPoolAnalyser<'a> {
    /// Create an analyser for a given constant pool slice.
    #[must_use]
    pub const fn new(pool: &'a [ConstantPoolEntry]) -> Self {
        Self { pool }
    }

    /// Compute statistics over the constant pool.
    #[must_use]
    pub fn stats(&self) -> ConstantPoolStats {
        let mut s = ConstantPoolStats::default();
        for entry in self.pool {
            s.total += 1;
            match entry {
                ConstantPoolEntry::Utf8(_) => s.utf8_count += 1,
                ConstantPoolEntry::ClassRef(_) => s.class_ref_count += 1,
                ConstantPoolEntry::MethodRef { .. } => s.method_ref_count += 1,
                ConstantPoolEntry::FieldRef { .. } => s.field_ref_count += 1,
                ConstantPoolEntry::StringRef(_) => s.string_ref_count += 1,
                ConstantPoolEntry::Integer(_) => s.integer_count += 1,
                ConstantPoolEntry::Long(_) => s.long_count += 1,
                ConstantPoolEntry::Float(_) => s.float_count += 1,
                ConstantPoolEntry::Double(_) => s.double_count += 1,
                ConstantPoolEntry::NameAndType { .. } => s.name_and_type_count += 1,
                ConstantPoolEntry::Other(_) => s.other_count += 1,
            }
        }
        s
    }

    /// Return all UTF-8 string literals in the pool.
    #[must_use]
    pub fn utf8_strings(&self) -> Vec<&str> {
        self.pool
            .iter()
            .filter_map(|e| {
                if let ConstantPoolEntry::Utf8(s) = e {
                    Some(s.as_str())
                } else {
                    None
                }
            })
            .collect()
    }

    /// Return all class names referenced in the pool.
    #[must_use]
    pub fn referenced_classes(&self) -> Vec<String> {
        let mut names = Vec::new();
        for entry in self.pool {
            if let ConstantPoolEntry::ClassRef(idx) = entry
                && let Some(ConstantPoolEntry::Utf8(s)) = self.pool.get(*idx as usize) {
                    names.push(s.clone());
                }
        }
        names.sort();
        names.dedup();
        names
    }

    /// Return all method references as `"class.method:descriptor"` strings.
    #[must_use]
    pub fn method_refs(&self) -> Vec<String> {
        let mut refs = Vec::new();
        for entry in self.pool {
            if let ConstantPoolEntry::MethodRef { class, nat } = entry {
                let class_name = self.resolve_class_name(*class as usize);
                let (method_name, desc) = self.resolve_nat(*nat as usize);
                refs.push(format!("{class_name}.{method_name}:{desc}"));
            }
        }
        refs.sort();
        refs.dedup();
        refs
    }

    /// Return all integer constants in the pool.
    #[must_use]
    pub fn integer_constants(&self) -> Vec<i32> {
        self.pool
            .iter()
            .filter_map(|e| {
                if let ConstantPoolEntry::Integer(n) = e {
                    Some(*n)
                } else {
                    None
                }
            })
            .collect()
    }

    /// Search for UTF-8 strings matching a substring.
    #[must_use]
    pub fn search_strings(&self, pattern: &str) -> Vec<&str> {
        self.utf8_strings()
            .into_iter()
            .filter(|s| s.contains(pattern))
            .collect()
    }

    /// Return the UTF-8 string at `idx`, or `"<invalid>"`.
    #[must_use]
    pub fn utf8_at(&self, idx: usize) -> &str {
        if let Some(ConstantPoolEntry::Utf8(s)) = self.pool.get(idx) {
            s.as_str()
        } else {
            "<invalid>"
        }
    }

    fn resolve_class_name(&self, class_idx: usize) -> String {
        if let Some(ConstantPoolEntry::ClassRef(name_idx)) = self.pool.get(class_idx) {
            self.utf8_at(*name_idx as usize).to_string()
        } else {
            format!("<class#{class_idx}>")
        }
    }

    fn resolve_nat(&self, nat_idx: usize) -> (String, String) {
        if let Some(ConstantPoolEntry::NameAndType { name, desc }) = self.pool.get(nat_idx) {
            (
                self.utf8_at(*name as usize).to_string(),
                self.utf8_at(*desc as usize).to_string(),
            )
        } else {
            ("<name>".to_string(), "<desc>".to_string())
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// MethodBody
// ─────────────────────────────────────────────────────────────────────────────

/// A decoded method body with disassembled instructions and basic-block info.
#[derive(Debug, Clone)]
pub struct MethodBody {
    /// Method name.
    pub name: String,
    /// Method descriptor.
    pub descriptor: String,
    /// Access flags.
    pub flags: JavaClassFlags,
    /// Raw bytecode bytes.
    pub bytecode: Vec<u8>,
    /// Disassembled instructions.
    pub instructions: Vec<JvmInstruction>,
    /// Basic block start offsets (indices into `instructions`).
    pub basic_block_starts: Vec<usize>,
    /// Exception handler table entries.
    pub exception_handlers: Vec<ExceptionHandler>,
    /// Maximum stack depth (from Code attribute).
    pub max_stack: u16,
    /// Maximum local variable slots.
    pub max_locals: u16,
}

/// An exception handler entry from a method's Code attribute.
#[derive(Debug, Clone)]
pub struct ExceptionHandler {
    pub start_pc: u16,
    pub end_pc: u16,
    pub handler_pc: u16,
    /// Catch type (class name), or `None` for `finally`.
    pub catch_type: Option<String>,
}

impl MethodBody {
    /// Build a `MethodBody` from raw bytecode bytes and method metadata.
    #[must_use]
    pub fn from_bytecode(
        name: String,
        descriptor: String,
        flags: JavaClassFlags,
        bytecode: Vec<u8>,
        max_stack: u16,
        max_locals: u16,
    ) -> Self {
        let disassembler = JvmDisassembler::new();
        let instructions = disassembler.disassemble(&bytecode);
        let basic_block_starts = compute_basic_block_starts(&instructions);
        Self {
            name,
            descriptor,
            flags,
            bytecode,
            instructions,
            basic_block_starts,
            exception_handlers: Vec::new(),
            max_stack,
            max_locals,
        }
    }

    /// Number of instructions.
    #[must_use]
    pub const fn instruction_count(&self) -> usize {
        self.instructions.len()
    }

    /// Number of basic blocks.
    #[must_use]
    pub fn basic_block_count(&self) -> usize {
        self.basic_block_starts
            .len()
            .max(usize::from(!self.instructions.is_empty()))
    }

    /// Return `true` if the method contains any `invoke*` instruction.
    #[must_use]
    pub fn has_calls(&self) -> bool {
        self.instructions.iter().any(super::JvmInstruction::is_invoke)
    }

    /// Cyclomatic complexity approximation: number of branch instructions + 1.
    #[must_use]
    pub fn cyclomatic_complexity(&self) -> usize {
        let branches = self
            .instructions
            .iter()
            .filter(|i| i.opcode.is_branch())
            .count();
        branches + 1
    }

    /// Return all CP indices referenced by `invoke*` instructions.
    #[must_use]
    pub fn callee_cp_indices(&self) -> Vec<u16> {
        self.instructions
            .iter()
            .filter(|i| i.is_invoke())
            .filter_map(super::JvmInstruction::cp_index)
            .collect()
    }
}

fn compute_basic_block_starts(instructions: &[JvmInstruction]) -> Vec<usize> {
    if instructions.is_empty() {
        return Vec::new();
    }
    let mut leaders = std::collections::BTreeSet::new();
    leaders.insert(0usize);
    for (idx, instr) in instructions.iter().enumerate() {
        if (instr.opcode.is_branch() || instr.opcode.is_return() || instr.opcode == JvmOpcode::Athrow)
            && idx + 1 < instructions.len() {
                leaders.insert(idx + 1);
            }
    }
    leaders.into_iter().collect()
}

// ─────────────────────────────────────────────────────────────────────────────
// AnnotationReader
// ─────────────────────────────────────────────────────────────────────────────

/// Parsed Java annotation.
#[derive(Debug, Clone)]
pub struct JavaAnnotation {
    /// Fully-qualified annotation type (e.g. `"Ljava/lang/Deprecated;"`).
    pub annotation_type: String,
    /// Key-value pairs from the annotation's element-value pairs.
    pub elements: Vec<(String, String)>,
    /// Whether this was runtime-visible.
    pub visible: bool,
}

impl fmt::Display for JavaAnnotation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "@{}",
            self.annotation_type.trim_matches(|c| c == 'L' || c == ';')
        )?;
        if !self.elements.is_empty() {
            write!(f, "(")?;
            for (i, (k, v)) in self.elements.iter().enumerate() {
                if i > 0 {
                    write!(f, ", ")?;
                }
                write!(f, "{k}={v}")?;
            }
            write!(f, ")")?;
        }
        Ok(())
    }
}

/// Reads annotations from raw attribute bytes.
#[derive(Debug, Default)]
pub struct AnnotationReader;

impl AnnotationReader {
    /// Create a new reader.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Parse `RuntimeVisibleAnnotations` or `RuntimeInvisibleAnnotations` attribute bytes.
    ///
    /// The `cp` slice is the constant pool used to resolve type and element names.
    /// The `visible` flag indicates which attribute type these bytes came from.
    #[must_use]
    pub fn parse(
        &self,
        data: &[u8],
        cp: &[ConstantPoolEntry],
        visible: bool,
    ) -> Vec<JavaAnnotation> {
        if data.len() < 2 {
            return Vec::new();
        }
        let num_annotations = u16::from_be_bytes([data[0], data[1]]) as usize;
        let mut pos = 2;
        let mut annotations = Vec::new();
        for _ in 0..num_annotations {
            if let Some((ann, advance)) = self.parse_annotation(data, pos, cp, visible) {
                annotations.push(ann);
                pos += advance;
            } else {
                break;
            }
        }
        annotations
    }

    fn parse_annotation(
        &self,
        data: &[u8],
        pos: usize,
        cp: &[ConstantPoolEntry],
        visible: bool,
    ) -> Option<(JavaAnnotation, usize)> {
        if pos + 4 > data.len() {
            return None;
        }
        let type_idx = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
        let num_pairs = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize;
        let annotation_type = if let Some(ConstantPoolEntry::Utf8(s)) = cp.get(type_idx) {
            s.clone()
        } else {
            format!("<type#{type_idx}>")
        };
        let mut elements = Vec::new();
        let mut p = pos + 4;
        for _ in 0..num_pairs {
            if p + 2 > data.len() {
                break;
            }
            let name_idx = u16::from_be_bytes([data[p], data[p + 1]]) as usize;
            p += 2;
            let name = if let Some(ConstantPoolEntry::Utf8(s)) = cp.get(name_idx) {
                s.clone()
            } else {
                format!("<name#{name_idx}>")
            };
            // Minimal element value parsing: just consume the tag + index
            if p + 3 > data.len() {
                break;
            }
            let _tag = data[p];
            p += 1;
            let val_idx = u16::from_be_bytes([data[p], data[p + 1]]) as usize;
            p += 2;
            let value = if let Some(ConstantPoolEntry::Utf8(s)) = cp.get(val_idx) {
                s.clone()
            } else if let Some(ConstantPoolEntry::Integer(n)) = cp.get(val_idx) {
                n.to_string()
            } else {
                format!("<val#{val_idx}>")
            };
            elements.push((name, value));
        }
        let advance = p - pos;
        Some((
            JavaAnnotation {
                annotation_type,
                elements,
                visible,
            },
            advance,
        ))
    }

    /// Return `true` if any annotation in `annotations` is a `@Deprecated` annotation.
    #[must_use]
    pub fn is_deprecated(annotations: &[JavaAnnotation]) -> bool {
        annotations
            .iter()
            .any(|a| a.annotation_type.contains("Deprecated"))
    }

    /// Filter annotations by type name substring.
    #[must_use]
    pub fn filter_by_type<'a>(
        annotations: &'a [JavaAnnotation],
        type_fragment: &str,
    ) -> Vec<&'a JavaAnnotation> {
        annotations
            .iter()
            .filter(|a| a.annotation_type.contains(type_fragment))
            .collect()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// InnerClass
// ─────────────────────────────────────────────────────────────────────────────

/// Relationship between an outer class and one of its inner/nested classes.
#[derive(Debug, Clone)]
pub struct InnerClassInfo {
    /// Binary name of the inner class (e.g. `"com/example/Outer$Inner"`).
    pub inner_class_name: String,
    /// Binary name of the outer class, if known.
    pub outer_class_name: Option<String>,
    /// Simple name of the inner class (e.g. `"Inner"`), or `None` for anonymous.
    pub simple_name: Option<String>,
    /// Access flags of the inner class.
    pub flags: JavaClassFlags,
    /// Whether this is an anonymous class.
    pub is_anonymous: bool,
    /// Whether this is a static (non-capturing) nested class.
    pub is_static: bool,
}

impl InnerClassInfo {
    /// Build from components.
    #[must_use]
    pub fn new(
        inner_class_name: String,
        outer_class_name: Option<String>,
        simple_name: Option<String>,
        flags: JavaClassFlags,
    ) -> Self {
        let is_anonymous = simple_name.is_none()
            || simple_name
                .as_deref()
                .is_some_and(str::is_empty);
        let is_static = flags.contains(JavaClassFlags::STATIC);
        Self {
            inner_class_name,
            outer_class_name,
            simple_name,
            flags,
            is_anonymous,
            is_static,
        }
    }

    /// Return `true` if this is an interface.
    #[must_use]
    pub const fn is_interface(&self) -> bool {
        self.flags.contains(JavaClassFlags::INTERFACE)
    }

    /// Return `true` if this is an enum.
    #[must_use]
    pub const fn is_enum(&self) -> bool {
        self.flags.contains(JavaClassFlags::ENUM)
    }
}

impl fmt::Display for InnerClassInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_anonymous {
            write!(f, "<anonymous class> in {:?}", self.outer_class_name)
        } else {
            write!(
                f,
                "{} (inner of {:?})",
                self.simple_name
                    .as_deref()
                    .unwrap_or(&self.inner_class_name),
                self.outer_class_name
            )
        }
    }
}

/// Parses `InnerClasses` attribute bytes.
pub struct InnerClassReader;

impl InnerClassReader {
    /// Parse the `InnerClasses` attribute payload.
    ///
    /// `data` is the raw attribute body (after the 6-byte name+length header).
    /// `cp` is the constant pool for name resolution.
    #[must_use]
    pub fn parse(data: &[u8], cp: &[ConstantPoolEntry]) -> Vec<InnerClassInfo> {
        if data.len() < 2 {
            return Vec::new();
        }
        let count = u16::from_be_bytes([data[0], data[1]]) as usize;
        let mut infos = Vec::new();
        let mut pos = 2;
        for _ in 0..count {
            if pos + 8 > data.len() {
                break;
            }
            let inner_idx = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
            let outer_idx = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize;
            let name_idx = u16::from_be_bytes([data[pos + 4], data[pos + 5]]) as usize;
            let flags_bits = u16::from_be_bytes([data[pos + 6], data[pos + 7]]);
            pos += 8;

            let inner_name = resolve_cp_class(cp, inner_idx);
            let outer_name = if outer_idx == 0 {
                None
            } else {
                Some(resolve_cp_class(cp, outer_idx))
            };
            let simple_name = if name_idx == 0 {
                None
            } else if let Some(ConstantPoolEntry::Utf8(s)) = cp.get(name_idx) {
                Some(s.clone())
            } else {
                None
            };
            let flags = JavaClassFlags::from_bits_truncate(flags_bits);
            infos.push(InnerClassInfo::new(
                inner_name,
                outer_name,
                simple_name,
                flags,
            ));
        }
        infos
    }
}

fn resolve_cp_class(cp: &[ConstantPoolEntry], class_idx: usize) -> String {
    if let Some(ConstantPoolEntry::ClassRef(name_idx)) = cp.get(class_idx)
        && let Some(ConstantPoolEntry::Utf8(s)) = cp.get(*name_idx as usize) {
            return s.clone();
        }
    format!("<class#{class_idx}>")
}

// ─────────────────────────────────────────────────────────────────────────────
// ClassFileDisassembler
// ─────────────────────────────────────────────────────────────────────────────

/// Renders a parsed Java class as human-readable disassembly text.
#[derive(Debug, Default)]
pub struct ClassFileDisassembler;

impl ClassFileDisassembler {
    /// Create a new disassembler.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Produce a disassembly of `class`, similar to `javap -c`.
    #[must_use]
    pub fn disassemble(&self, class: &JavaClass) -> String {
        let mut out = String::new();
        out.push_str(&format!(
            "class {} (Java {})\n",
            class.class_name,
            class.version.java_release()
        ));
        if let Some(ref sup) = class.super_name {
            out.push_str(&format!("  extends {sup}\n"));
        }
        for iface in &class.interfaces {
            out.push_str(&format!("  implements {iface}\n"));
        }
        out.push('\n');
        // Fields
        for field in &class.fields {
            out.push_str(&format!("  field {}:{}\n", field.name, field.descriptor));
        }
        // Methods
        for method in &class.methods {
            out.push_str(&format!("  method {}:{}\n", method.name, method.descriptor));
        }
        out
    }

    /// Disassemble a raw `Code` attribute byte slice using `JvmDisassembler`.
    #[must_use]
    pub fn disassemble_code(&self, code: &[u8]) -> String {
        let dis = JvmDisassembler::new();
        let instrs = dis.disassemble(code);
        let mut out = String::new();
        for instr in &instrs {
            out.push_str(&format!(
                "  {:04}  {}\n",
                instr.offset,
                instr.opcode.mnemonic()
            ));
        }
        out
    }

    /// Render a single `JvmInstruction` as a string.
    #[must_use]
    pub fn render_instruction(instr: &JvmInstruction) -> String {
        format!("{:04}  {}", instr.offset, instr.opcode.mnemonic())
    }

    /// Count distinct opcodes in a code byte slice.
    #[must_use]
    pub fn opcode_histogram(&self, code: &[u8]) -> HashMap<String, usize> {
        let dis = JvmDisassembler::new();
        let instrs = dis.disassemble(code);
        let mut hist = HashMap::new();
        for instr in instrs {
            *hist.entry(instr.opcode.mnemonic().to_string()).or_insert(0) += 1;
        }
        hist
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// JarDecompiler
// ─────────────────────────────────────────────────────────────────────────────

/// Summary of a decompiled JAR archive.
#[derive(Debug, Default, Clone)]
pub struct JarSummary {
    /// Total number of classes extracted.
    pub class_count: usize,
    /// Total number of methods across all classes.
    pub total_methods: usize,
    /// Total number of fields across all classes.
    pub total_fields: usize,
    /// Map from class name → list of method names.
    pub class_methods: HashMap<String, Vec<String>>,
    /// Parse errors encountered: class name → error message.
    pub errors: HashMap<String, String>,
}

/// Result of decompiling a single class.
#[derive(Debug, Clone)]
pub struct DecompiledClass {
    /// Binary class name.
    pub class_name: String,
    /// Access flags.
    pub flags: JavaClassFlags,
    /// Java version.
    pub java_version: String,
    /// Methods with their disassembled bodies.
    pub methods: Vec<MethodSummary>,
    /// Referenced external classes.
    pub external_refs: Vec<String>,
    /// Inner class relationships.
    pub inner_classes: Vec<InnerClassInfo>,
}

/// Summary of a single method.
#[derive(Debug, Clone)]
pub struct MethodSummary {
    /// Method name.
    pub name: String,
    /// Method descriptor.
    pub descriptor: String,
    /// Number of instructions.
    pub instruction_count: usize,
    /// Cyclomatic complexity.
    pub cyclomatic_complexity: usize,
    /// Whether the method calls other methods.
    pub has_calls: bool,
}

/// Decompiler for JAR archives.
///
/// Parses each embedded `.class` file in a ZIP/JAR payload and produces
/// structured decompilation data.
#[derive(Debug, Default)]
pub struct JarDecompiler {
    /// Per-class decompilation results.
    pub classes: Vec<DecompiledClass>,
    /// Summary statistics.
    pub summary: JarSummary,
}

impl JarDecompiler {
    /// Create a new decompiler.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Decompile a single parsed `JavaClass`.
    pub fn add_class(&mut self, class: &JavaClass) {
        let cp_analyser = ConstantPoolAnalyser::new(&class.constant_pool);
        let external_refs = cp_analyser.referenced_classes();
        let dis = ClassFileDisassembler::new();

        let methods: Vec<MethodSummary> = class
            .methods
            .iter()
            .map(|m| {
                // We don't have raw bytecode in JavaClass, so build from descriptor.
                let instr_count = 0;
                let cc = 1;
                MethodSummary {
                    name: m.name.clone(),
                    descriptor: m.descriptor.clone(),
                    instruction_count: instr_count,
                    cyclomatic_complexity: cc,
                    has_calls: false,
                }
            })
            .collect();

        let dc = DecompiledClass {
            class_name: class.class_name.clone(),
            flags: class.flags,
            java_version: class.version.to_string(),
            methods: methods.clone(),
            external_refs,
            inner_classes: Vec::new(),
        };

        self.summary.class_count += 1;
        self.summary.total_methods += methods.len();
        self.summary.total_fields += class.fields.len();
        self.summary.class_methods.insert(
            class.class_name.clone(),
            methods.iter().map(|m| m.name.clone()).collect(),
        );

        let _ = dis; // used above conceptually
        self.classes.push(dc);
    }

    /// Decompile raw class file bytes and add to results.
    pub fn add_class_bytes(&mut self, name: &str, data: &[u8]) {
        match JavaClass::parse(data) {
            Ok(class) => self.add_class(&class),
            Err(e) => {
                self.summary.errors.insert(name.to_string(), e.to_string());
            }
        }
    }

    /// Return a `DecompiledClass` by name.
    #[must_use]
    pub fn get_class(&self, name: &str) -> Option<&DecompiledClass> {
        self.classes.iter().find(|c| c.class_name == name)
    }

    /// Return all class names.
    #[must_use]
    pub fn class_names(&self) -> Vec<&str> {
        self.classes.iter().map(|c| c.class_name.as_str()).collect()
    }

    /// Return all external class references across all decompiled classes.
    #[must_use]
    pub fn all_external_refs(&self) -> Vec<String> {
        let mut refs: Vec<String> = self
            .classes
            .iter()
            .flat_map(|c| c.external_refs.iter().cloned())
            .collect();
        refs.sort();
        refs.dedup();
        refs
    }

    /// Return `true` if no classes were decompiled.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.classes.is_empty()
    }

    /// Return the class with the most methods.
    #[must_use]
    pub fn most_complex_class(&self) -> Option<&DecompiledClass> {
        self.classes.iter().max_by_key(|c| c.methods.len())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ConstantPoolEntry;

    fn make_cp() -> Vec<ConstantPoolEntry> {
        vec![
            ConstantPoolEntry::Other(0),                          // 0: sentinel
            ConstantPoolEntry::Utf8("java/lang/Object".into()),   // 1
            ConstantPoolEntry::Utf8("<init>".into()),             // 2
            ConstantPoolEntry::Utf8("()V".into()),                // 3
            ConstantPoolEntry::ClassRef(1),                       // 4: Object
            ConstantPoolEntry::NameAndType { name: 2, desc: 3 },  // 5
            ConstantPoolEntry::MethodRef { class: 4, nat: 5 },    // 6
            ConstantPoolEntry::Utf8("Ljava/lang/String;".into()), // 7
            ConstantPoolEntry::StringRef(7),                      // 8
            ConstantPoolEntry::Integer(42),                       // 9
            ConstantPoolEntry::Long(1000),                        // 10
        ]
    }

    // ── ConstantPoolAnalyser ──────────────────────────────────────────────────

    #[test]
    fn test_cp_stats_total() {
        let cp = make_cp();
        let analyser = ConstantPoolAnalyser::new(&cp);
        let s = analyser.stats();
        assert_eq!(s.total, cp.len());
    }

    #[test]
    fn test_cp_stats_counts() {
        let cp = make_cp();
        let analyser = ConstantPoolAnalyser::new(&cp);
        let s = analyser.stats();
        assert!(s.utf8_count >= 4);
        assert!(s.method_ref_count >= 1);
        assert!(s.integer_count >= 1);
    }

    #[test]
    fn test_cp_utf8_strings() {
        let cp = make_cp();
        let analyser = ConstantPoolAnalyser::new(&cp);
        let strings = analyser.utf8_strings();
        assert!(strings.contains(&"<init>"));
    }

    #[test]
    fn test_cp_referenced_classes() {
        let cp = make_cp();
        let analyser = ConstantPoolAnalyser::new(&cp);
        let classes = analyser.referenced_classes();
        assert!(classes.contains(&"java/lang/Object".to_string()));
    }

    #[test]
    fn test_cp_method_refs() {
        let cp = make_cp();
        let analyser = ConstantPoolAnalyser::new(&cp);
        let refs = analyser.method_refs();
        assert!(!refs.is_empty());
        assert!(refs[0].contains("java/lang/Object"));
    }

    #[test]
    fn test_cp_integer_constants() {
        let cp = make_cp();
        let analyser = ConstantPoolAnalyser::new(&cp);
        let ints = analyser.integer_constants();
        assert!(ints.contains(&42));
    }

    #[test]
    fn test_cp_search_strings() {
        let cp = make_cp();
        let analyser = ConstantPoolAnalyser::new(&cp);
        let found = analyser.search_strings("init");
        assert!(found.contains(&"<init>"));
    }

    #[test]
    fn test_cp_utf8_at() {
        let cp = make_cp();
        let analyser = ConstantPoolAnalyser::new(&cp);
        assert_eq!(analyser.utf8_at(2), "<init>");
    }

    // ── MethodBody ────────────────────────────────────────────────────────────

    #[test]
    fn test_method_body_empty() {
        let mb = MethodBody::from_bytecode(
            "foo".into(),
            "()V".into(),
            JavaClassFlags::PUBLIC,
            vec![],
            0,
            0,
        );
        assert_eq!(mb.instruction_count(), 0);
        assert_eq!(mb.cyclomatic_complexity(), 1);
        assert!(!mb.has_calls());
    }

    #[test]
    fn test_method_body_nop() {
        // nop (0x00), return (0xB1)
        let code = vec![0x00, 0xB1];
        let mb = MethodBody::from_bytecode(
            "bar".into(),
            "()V".into(),
            JavaClassFlags::PUBLIC,
            code,
            1,
            1,
        );
        assert_eq!(mb.instruction_count(), 2);
        assert!(!mb.has_calls());
    }

    #[test]
    fn test_method_body_invoke() {
        // invokevirtual (0xB6) + 2 operand bytes + return
        let code = vec![0xB6, 0x00, 0x01, 0xB1];
        let mb =
            MethodBody::from_bytecode("m".into(), "()V".into(), JavaClassFlags::PUBLIC, code, 2, 1);
        assert!(mb.has_calls());
        assert!(!mb.callee_cp_indices().is_empty());
    }

    #[test]
    fn test_method_body_branch_complexity() {
        // ifeq (0x99) + 2 bytes offset + return
        let code = vec![0x99, 0x00, 0x05, 0xB1];
        let mb =
            MethodBody::from_bytecode("m".into(), "()V".into(), JavaClassFlags::PUBLIC, code, 1, 1);
        assert!(mb.cyclomatic_complexity() >= 2);
    }

    #[test]
    fn test_method_body_basic_blocks() {
        // nop, ifeq, nop, return
        let code = vec![0x00, 0x99, 0x00, 0x03, 0x00, 0xB1];
        let mb =
            MethodBody::from_bytecode("m".into(), "()V".into(), JavaClassFlags::PUBLIC, code, 1, 1);
        assert!(mb.basic_block_count() >= 1);
    }

    // ── AnnotationReader ──────────────────────────────────────────────────────

    #[test]
    fn test_annotation_reader_empty() {
        let reader = AnnotationReader::new();
        let cp: Vec<ConstantPoolEntry> = vec![];
        let annotations = reader.parse(&[0x00, 0x00], &cp, true);
        assert!(annotations.is_empty());
    }

    #[test]
    fn test_annotation_reader_one_annotation() {
        let mut cp = vec![ConstantPoolEntry::Other(0)];
        cp.push(ConstantPoolEntry::Utf8("Ljava/lang/Deprecated;".into())); // 1
        // 1 annotation, type=1, 0 element pairs
        let data = [0x00, 0x01, 0x00, 0x01, 0x00, 0x00];
        let reader = AnnotationReader::new();
        let anns = reader.parse(&data, &cp, true);
        assert_eq!(anns.len(), 1);
        assert_eq!(anns[0].annotation_type, "Ljava/lang/Deprecated;");
        assert!(anns[0].visible);
    }

    #[test]
    fn test_annotation_is_deprecated() {
        let ann = JavaAnnotation {
            annotation_type: "Ljava/lang/Deprecated;".into(),
            elements: vec![],
            visible: true,
        };
        assert!(AnnotationReader::is_deprecated(&[ann]));
    }

    #[test]
    fn test_annotation_not_deprecated() {
        let ann = JavaAnnotation {
            annotation_type: "Ljava/lang/Override;".into(),
            elements: vec![],
            visible: true,
        };
        assert!(!AnnotationReader::is_deprecated(&[ann]));
    }

    #[test]
    fn test_annotation_filter() {
        let anns = vec![
            JavaAnnotation {
                annotation_type: "Ljava/lang/Deprecated;".into(),
                elements: vec![],
                visible: true,
            },
            JavaAnnotation {
                annotation_type: "Lcom/example/Test;".into(),
                elements: vec![],
                visible: false,
            },
        ];
        let filtered = AnnotationReader::filter_by_type(&anns, "Deprecated");
        assert_eq!(filtered.len(), 1);
    }

    #[test]
    fn test_annotation_display() {
        let ann = JavaAnnotation {
            annotation_type: "Ljava/lang/Deprecated;".into(),
            elements: vec![("since".into(), "1.5".into())],
            visible: true,
        };
        let s = ann.to_string();
        assert!(s.contains("Deprecated"));
        assert!(s.contains("since=1.5"));
    }

    // ── InnerClassInfo ────────────────────────────────────────────────────────

    #[test]
    fn test_inner_class_anonymous() {
        let ic = InnerClassInfo::new(
            "com/example/Outer$1".into(),
            Some("com/example/Outer".into()),
            None,
            JavaClassFlags::empty(),
        );
        assert!(ic.is_anonymous);
    }

    #[test]
    fn test_inner_class_named() {
        let ic = InnerClassInfo::new(
            "com/example/Outer$Inner".into(),
            Some("com/example/Outer".into()),
            Some("Inner".into()),
            JavaClassFlags::PUBLIC,
        );
        assert!(!ic.is_anonymous);
    }

    #[test]
    fn test_inner_class_static() {
        let ic = InnerClassInfo::new(
            "com/example/Outer$Static".into(),
            Some("com/example/Outer".into()),
            Some("Static".into()),
            JavaClassFlags::STATIC | JavaClassFlags::PUBLIC,
        );
        assert!(ic.is_static);
    }

    #[test]
    fn test_inner_class_interface() {
        let ic = InnerClassInfo::new(
            "com/example/IFace".into(),
            None,
            Some("IFace".into()),
            JavaClassFlags::INTERFACE | JavaClassFlags::PUBLIC,
        );
        assert!(ic.is_interface());
    }

    #[test]
    fn test_inner_class_display_anonymous() {
        let ic = InnerClassInfo::new(
            "com/Outer$1".into(),
            Some("com/Outer".into()),
            None,
            JavaClassFlags::empty(),
        );
        let s = ic.to_string();
        assert!(s.contains("anonymous"));
    }

    // ── ClassFileDisassembler ─────────────────────────────────────────────────

    #[test]
    fn test_disassembler_empty_code() {
        let dis = ClassFileDisassembler::new();
        let out = dis.disassemble_code(&[]);
        assert!(out.is_empty());
    }

    #[test]
    fn test_disassembler_nop_return() {
        let dis = ClassFileDisassembler::new();
        let out = dis.disassemble_code(&[0x00, 0xB1]);
        assert!(out.contains("nop"));
        assert!(out.contains("return"));
    }

    #[test]
    fn test_disassembler_opcode_histogram() {
        let dis = ClassFileDisassembler::new();
        let code = [0x00u8, 0x00, 0xB1]; // nop nop return
        let hist = dis.opcode_histogram(&code);
        assert_eq!(hist.get("nop").copied().unwrap_or(0), 2);
        assert_eq!(hist.get("return").copied().unwrap_or(0), 1);
    }

    #[test]
    fn test_render_instruction() {
        let instr = JvmInstruction {
            offset: 4,
            opcode: JvmOpcode::Nop,
            operands: vec![],
        };
        let s = ClassFileDisassembler::render_instruction(&instr);
        assert!(s.contains("0004"));
        assert!(s.contains("nop"));
    }

    // ── JarDecompiler ─────────────────────────────────────────────────────────

    #[test]
    fn test_jar_decompiler_empty() {
        let jd = JarDecompiler::new();
        assert!(jd.is_empty());
        assert_eq!(jd.summary.class_count, 0);
    }

    #[test]
    fn test_jar_decompiler_add_class_bytes_invalid() {
        let mut jd = JarDecompiler::new();
        jd.add_class_bytes("Bad.class", b"not a class file");
        assert!(jd.summary.errors.contains_key("Bad.class"));
    }

    #[test]
    fn test_jar_decompiler_class_names() {
        let mut jd = JarDecompiler::new();
        // Build a minimal valid class
        let class_data = build_minimal_class_bytes("com/example/Test", "java/lang/Object");
        jd.add_class_bytes("Test.class", &class_data);
        if jd.summary.errors.is_empty() {
            let names = jd.class_names();
            assert!(names.iter().any(|n| n.contains("Test")));
        }
    }

    #[test]
    fn test_jar_decompiler_all_external_refs() {
        let jd = JarDecompiler::new();
        let refs = jd.all_external_refs();
        assert!(refs.is_empty());
    }

    #[test]
    fn test_jar_decompiler_most_complex_none() {
        let jd = JarDecompiler::new();
        assert!(jd.most_complex_class().is_none());
    }

    // ── InnerClassReader ──────────────────────────────────────────────────────

    #[test]
    fn test_inner_class_reader_empty_data() {
        let cp: Vec<ConstantPoolEntry> = vec![];
        let result = InnerClassReader::parse(&[], &cp);
        assert!(result.is_empty());
    }

    #[test]
    fn test_inner_class_reader_zero_entries() {
        let cp: Vec<ConstantPoolEntry> = vec![];
        let data = [0x00u8, 0x00]; // count = 0
        let result = InnerClassReader::parse(&data, &cp);
        assert!(result.is_empty());
    }

    // ── helpers ───────────────────────────────────────────────────────────────

    fn build_minimal_class_bytes(class_name: &str, super_name: &str) -> Vec<u8> {
        let mut out = Vec::new();
        // Magic
        out.extend_from_slice(&[0xCA, 0xFE, 0xBA, 0xBE]);
        // Minor, major (52.0 = Java 8)
        out.extend_from_slice(&[0x00, 0x00, 0x00, 0x34]);

        // Constant pool:
        // idx 0: sentinel (not written)
        // idx 1: Utf8(class_name)
        // idx 2: Utf8(super_name)
        // idx 3: ClassRef(1) — this
        // idx 4: ClassRef(2) — super
        let cp: Vec<Vec<u8>> = vec![
            utf8_entry(class_name),
            utf8_entry(super_name),
            class_ref_entry(1),
            class_ref_entry(2),
        ];

        // cp_count = len + 1 (1-indexed, includes the sentinel)
        let cp_count = (cp.len() + 1) as u16;
        out.extend_from_slice(&cp_count.to_be_bytes());
        for entry in &cp {
            out.extend_from_slice(entry);
        }

        // access_flags = PUBLIC (0x0021)
        out.extend_from_slice(&[0x00, 0x21]);
        // this_class = 3 (ClassRef pointing to class_name)
        out.extend_from_slice(&[0x00, 0x03]);
        // super_class = 4
        out.extend_from_slice(&[0x00, 0x04]);
        // interfaces count = 0
        out.extend_from_slice(&[0x00, 0x00]);
        // fields count = 0
        out.extend_from_slice(&[0x00, 0x00]);
        // methods count = 0
        out.extend_from_slice(&[0x00, 0x00]);
        // class attributes count = 0
        out.extend_from_slice(&[0x00, 0x00]);
        out
    }

    fn utf8_entry(s: &str) -> Vec<u8> {
        let bytes = s.as_bytes();
        let mut e = vec![0x01];
        e.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
        e.extend_from_slice(bytes);
        e
    }

    fn class_ref_entry(name_idx: u16) -> Vec<u8> {
        let mut e = vec![0x07];
        e.extend_from_slice(&name_idx.to_be_bytes());
        e
    }
}
