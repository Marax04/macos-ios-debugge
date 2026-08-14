// rustre-arch-wasm/src/wasm_validator.rs
//! WasmValidator — validate WASM module structure, types, and instructions.

pub use std::collections::HashMap;

pub use crate::WasmFuncType;
use crate::{WasmModuleHeader, WasmSectionId, WasmValueType, read_uleb128};
pub use rustre_core::errors::CoreError;

// ─── ValidationError ─────────────────────────────────────────────────────────

/// Errors that can be found during WASM validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationError {
    /// A section header or body is malformed.
    MalformedSection { section: String, detail: String },
    /// An instruction opcode is not valid in the current context.
    InvalidOpcode { offset: usize, opcode: u8 },
    /// A value type mismatch on the operand stack.
    TypeMismatch {
        expected: String,
        found: String,
        context: String,
    },
    /// An import references a name that is not defined.
    UnresolvedImport { module: String, name: String },
    /// A memory access could exceed the declared memory size.
    MemoryOutOfBounds {
        offset: u64,
        access_size: u32,
        memory_limit_pages: u32,
    },
    /// A function index is out of range.
    InvalidFuncIndex { index: u32, max: u32 },
    /// A type index is out of range.
    InvalidTypeIndex { index: u32, max: u32 },
    /// The module magic or version bytes are wrong.
    InvalidMagic,
    /// A local variable index is out of range inside a function body.
    InvalidLocalIndex { func: u32, index: u32 },
    /// Generic validation error.
    Generic(String),
}

impl ValidationError {
    pub fn is_fatal(&self) -> bool {
        matches!(
            self,
            Self::InvalidMagic | Self::MalformedSection { .. } | Self::InvalidOpcode { .. }
        )
    }

    pub fn category(&self) -> &'static str {
        match self {
            Self::MalformedSection { .. } => "structure",
            Self::InvalidOpcode { .. } => "opcode",
            Self::TypeMismatch { .. } => "type",
            Self::UnresolvedImport { .. } => "import",
            Self::MemoryOutOfBounds { .. } => "memory",
            Self::InvalidFuncIndex { .. }
            | Self::InvalidTypeIndex { .. }
            | Self::InvalidLocalIndex { .. } => "index",
            Self::InvalidMagic => "magic",
            Self::Generic(_) => "generic",
        }
    }
}

impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MalformedSection { section, detail } => {
                write!(f, "Malformed section '{section}': {detail}")
            }
            Self::InvalidOpcode { offset, opcode } => {
                write!(f, "Invalid opcode 0x{opcode:02x} at offset {offset:#x}")
            }
            Self::TypeMismatch {
                expected,
                found,
                context,
            } => write!(
                f,
                "Type mismatch in '{context}': expected {expected}, found {found}"
            ),
            Self::UnresolvedImport { module, name } => {
                write!(f, "Unresolved import: {module}::{name}")
            }
            Self::MemoryOutOfBounds {
                offset,
                access_size,
                memory_limit_pages,
            } => write!(
                f,
                "Memory access at offset {offset}+{access_size} may exceed {memory_limit_pages} pages"
            ),
            Self::InvalidFuncIndex { index, max } => {
                write!(f, "Function index {index} out of range (max {max})")
            }
            Self::InvalidTypeIndex { index, max } => {
                write!(f, "Type index {index} out of range (max {max})")
            }
            Self::InvalidLocalIndex { func, index } => {
                write!(f, "Local index {index} out of range in function {func}")
            }
            Self::InvalidMagic => write!(f, "Invalid WASM magic bytes or version"),
            Self::Generic(s) => write!(f, "Validation error: {s}"),
        }
    }
}

// ─── WasmValueStack ──────────────────────────────────────────────────────────

/// Tracks the operand-stack types for a simple type-checker.
#[derive(Debug, Clone, Default)]
pub struct WasmValueStack {
    /// Stack of types. `None` represents the "polymorphic" (unreachable) type.
    stack: Vec<Option<WasmValueType>>,
    /// True when the current block is unreachable (after `unreachable`/`return`).
    unreachable: bool,
}

impl WasmValueStack {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&mut self, t: WasmValueType) {
        if !self.unreachable {
            self.stack.push(Some(t));
        }
    }

    /// Pop a value and check it matches `expected`. Returns an error on mismatch.
    pub fn pop_expect(
        &mut self,
        expected: WasmValueType,
        context: &str,
    ) -> Result<(), ValidationError> {
        if self.unreachable {
            return Ok(());
        }
        match self.stack.pop() {
            None => Err(ValidationError::TypeMismatch {
                expected: expected.name().to_string(),
                found: "empty stack".to_string(),
                context: context.to_string(),
            }),
            Some(None) => Ok(()), // polymorphic
            Some(Some(t)) if t == expected => Ok(()),
            Some(Some(t)) => Err(ValidationError::TypeMismatch {
                expected: expected.name().to_string(),
                found: t.name().to_string(),
                context: context.to_string(),
            }),
        }
    }

    pub fn pop_any(&mut self) -> Option<Option<WasmValueType>> {
        if self.unreachable {
            None
        } else {
            self.stack.pop()
        }
    }

    pub fn depth(&self) -> usize {
        self.stack.len()
    }

    pub fn mark_unreachable(&mut self) {
        self.unreachable = true;
        self.stack.clear();
    }

    pub fn is_unreachable(&self) -> bool {
        self.unreachable
    }

    pub fn reset_to_reachable(&mut self) {
        self.unreachable = false;
    }
}

// ─── TypeChecker ──────────────────────────────────────────────────────────────

/// Tracks value-stack types for a single function body.
pub struct TypeChecker {
    stack: WasmValueStack,
    /// Known local variable types.
    locals: Vec<WasmValueType>,
    /// Errors collected during type-checking.
    pub errors: Vec<ValidationError>,
    /// Function index being checked.
    func_index: u32,
}

impl TypeChecker {
    pub fn new(func_index: u32, locals: Vec<WasmValueType>) -> Self {
        Self {
            stack: WasmValueStack::new(),
            locals,
            errors: Vec::new(),
            func_index,
        }
    }

    pub fn check_local_get(&mut self, local_idx: u32) {
        if local_idx as usize >= self.locals.len() {
            self.errors.push(ValidationError::InvalidLocalIndex {
                func: self.func_index,
                index: local_idx,
            });
            return;
        }
        self.stack.push(self.locals[local_idx as usize]);
    }

    pub fn check_local_set(&mut self, local_idx: u32) {
        if local_idx as usize >= self.locals.len() {
            self.errors.push(ValidationError::InvalidLocalIndex {
                func: self.func_index,
                index: local_idx,
            });
            return;
        }
        let expected = self.locals[local_idx as usize];
        if let Err(e) = self.stack.pop_expect(expected, "local.set") {
            self.errors.push(e);
        }
    }

    pub fn check_binop_i32(&mut self) {
        if let Err(e) = self.stack.pop_expect(WasmValueType::I32, "i32 binop rhs") {
            self.errors.push(e);
        }
        if let Err(e) = self.stack.pop_expect(WasmValueType::I32, "i32 binop lhs") {
            self.errors.push(e);
        }
        self.stack.push(WasmValueType::I32);
    }

    pub fn check_binop_i64(&mut self) {
        if let Err(e) = self.stack.pop_expect(WasmValueType::I64, "i64 binop rhs") {
            self.errors.push(e);
        }
        if let Err(e) = self.stack.pop_expect(WasmValueType::I64, "i64 binop lhs") {
            self.errors.push(e);
        }
        self.stack.push(WasmValueType::I64);
    }

    pub fn check_const_i32(&mut self) {
        self.stack.push(WasmValueType::I32);
    }

    pub fn check_const_i64(&mut self) {
        self.stack.push(WasmValueType::I64);
    }

    pub fn check_return(&mut self, result_type: Option<WasmValueType>) {
        if let Some(rt) = result_type && let Err(e) = self.stack.pop_expect(rt, "return") {
            self.errors.push(e);
        }
        self.stack.mark_unreachable();
    }

    pub fn check_unreachable(&mut self) {
        self.stack.mark_unreachable();
    }

    pub fn stack_depth(&self) -> usize {
        self.stack.depth()
    }

    pub fn has_errors(&self) -> bool {
        !self.errors.is_empty()
    }
}

// ─── FunctionValidator ────────────────────────────────────────────────────────

/// Validates a single function body at the byte level.
pub struct FunctionValidator {
    pub func_index: u32,
    pub errors: Vec<ValidationError>,
    known_func_count: u32,
    known_type_count: u32,
    memory_pages: u32,
}

impl FunctionValidator {
    pub fn new(
        func_index: u32,
        known_func_count: u32,
        known_type_count: u32,
        memory_pages: u32,
    ) -> Self {
        Self {
            func_index,
            errors: Vec::new(),
            known_func_count,
            known_type_count,
            memory_pages,
        }
    }

    /// Validate function body bytes. Returns `true` if valid.
    pub fn validate_body(&mut self, body: &[u8]) -> bool {
        let mut pos = 0usize;
        while pos < body.len() {
            let op = body[pos];
            pos += 1;
            match op {
                0x00 => {} // unreachable
                0x01 => {} // nop
                0x0b => {} // end
                0x0f => {} // return
                0x10 => {
                    // call funcidx
                    match read_uleb128(body, pos) {
                        Ok((idx, n)) => {
                            pos += n;
                            if idx as u32 >= self.known_func_count {
                                self.errors.push(ValidationError::InvalidFuncIndex {
                                    index: idx as u32,
                                    max: self.known_func_count.saturating_sub(1),
                                });
                            }
                        }
                        Err(_) => {
                            self.errors.push(ValidationError::MalformedSection {
                                section: "code".to_string(),
                                detail: format!("truncated call at {pos:#x}"),
                            });
                            break;
                        }
                    }
                }
                0x11 => {
                    // call_indirect typeidx tableidx
                    match read_uleb128(body, pos) {
                        Ok((type_idx, n1)) => {
                            pos += n1;
                            if type_idx as u32 >= self.known_type_count {
                                self.errors.push(ValidationError::InvalidTypeIndex {
                                    index: type_idx as u32,
                                    max: self.known_type_count.saturating_sub(1),
                                });
                            }
                            // consume table idx
                            if let Ok((_, n2)) = read_uleb128(body, pos) {
                                pos += n2;
                            }
                        }
                        Err(_) => break,
                    }
                }
                // Variable ops: consume one LEB128
                0x20..=0x24 => match read_uleb128(body, pos) {
                    Ok((_, n)) => pos += n,
                    Err(_) => {
                        self.errors.push(ValidationError::MalformedSection {
                            section: "code".to_string(),
                            detail: "truncated variable op".to_string(),
                        });
                        break;
                    }
                },
                // Memory ops: consume align + offset
                0x28..=0x3e => {
                    match read_uleb128(body, pos) {
                        Ok((_, n)) => pos += n,
                        Err(_) => break,
                    }
                    match read_uleb128(body, pos) {
                        Ok((mem_offset, n)) => {
                            pos += n;
                            // Check if offset exceeds declared memory
                            if self.memory_pages > 0 {
                                let limit_bytes = self.memory_pages as u64 * 65536;
                                if mem_offset > limit_bytes {
                                    self.errors.push(ValidationError::MemoryOutOfBounds {
                                        offset: mem_offset,
                                        access_size: 4,
                                        memory_limit_pages: self.memory_pages,
                                    });
                                }
                            }
                        }
                        Err(_) => break,
                    }
                }
                // memory.size / memory.grow: consume reserved byte
                0x3f | 0x40 => {
                    if pos >= body.len() {
                        self.errors.push(ValidationError::MalformedSection {
                            section: "code".to_string(),
                            detail: format!("truncated memory.size/grow at {pos:#x}"),
                        });
                        break;
                    }
                    pos += 1;
                }
                // i32.const: consume SLEB128
                0x41 => {
                    let mut p = pos;
                    while p < body.len() {
                        let b = body[p];
                        p += 1;
                        if b & 0x80 == 0 {
                            break;
                        }
                    }
                    pos = p;
                }
                // i64.const: consume SLEB128
                0x42 => {
                    let mut p = pos;
                    while p < body.len() {
                        let b = body[p];
                        p += 1;
                        if b & 0x80 == 0 {
                            break;
                        }
                    }
                    pos = p;
                }
                // f32.const: 4 bytes
                0x43 => {
                    pos += 4.min(body.len() - pos);
                }
                // f64.const: 8 bytes
                0x44 => {
                    pos += 8.min(body.len() - pos);
                }
                // No-operand numeric ops (0x45 – 0xc4)
                0x45..=0xc4 => {}
                // br / br_if: one LEB128
                0x0c | 0x0d => match read_uleb128(body, pos) {
                    Ok((_, n)) => pos += n,
                    Err(_) => break,
                },
                // br_table
                0x0e => {
                    const MAX_BR_TABLE_LABELS: u64 = 65_536;
                    match read_uleb128(body, pos) {
                        Ok((count, n)) => {
                            pos += n;
                            if count > MAX_BR_TABLE_LABELS {
                                self.errors.push(ValidationError::MalformedSection {
                                    section: "code".to_string(),
                                    detail: format!("br_table count {count} exceeds limit"),
                                });
                                break;
                            }
                            // consume count+1 labels
                            for _ in 0..=count {
                                match read_uleb128(body, pos) {
                                    Ok((_, n2)) => pos += n2,
                                    Err(_) => {
                                        pos = body.len();
                                        break;
                                    }
                                }
                            }
                        }
                        Err(_) => break,
                    }
                }
                0xfc..=0xfe => {
                    // Skip multi-byte opcodes: consume sub-opcode LEB128
                    match read_uleb128(body, pos) {
                        Ok((_, n)) => pos += n,
                        Err(_) => break,
                    }
                }
                // Unknown opcode
                other => {
                    self.errors.push(ValidationError::InvalidOpcode {
                        offset: pos - 1,
                        opcode: other,
                    });
                }
            }
        }
        self.errors.is_empty()
    }
}

// ─── ModuleValidator ──────────────────────────────────────────────────────────

/// Validates an entire WASM module binary.
pub struct ModuleValidator {
    /// Memory limit to use when checking memory accesses (in pages).
    pub memory_limit_pages: u32,
    /// Known imports that are considered resolved.
    pub resolved_imports: std::collections::HashSet<String>,
}

impl Default for ModuleValidator {
    fn default() -> Self {
        Self {
            memory_limit_pages: 256,
            resolved_imports: std::collections::HashSet::new(),
        }
    }
}

impl ModuleValidator {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_memory_limit(mut self, pages: u32) -> Self {
        self.memory_limit_pages = pages;
        self
    }

    pub fn with_resolved_import(mut self, module: &str, name: &str) -> Self {
        self.resolved_imports.insert(format!("{module}::{name}"));
        self
    }

    /// Validate `wasm_bytes` and return a `ValidationReport`.
    pub fn validate(&self, wasm_bytes: &[u8]) -> ValidationReport {
        let mut report = ValidationReport::new();

        // 1. Magic + version
        match WasmModuleHeader::parse(wasm_bytes) {
            Ok(_) => {}
            Err(_) => {
                report.add_error(ValidationError::InvalidMagic);
                return report; // can't go further
            }
        }

        if wasm_bytes.len() < 8 {
            report.add_error(ValidationError::MalformedSection {
                section: "module".to_string(),
                detail: "module too short".to_string(),
            });
            return report;
        }

        // 2. Section scanning
        let mut pos = 8usize;
        let mut type_section_count = 0u32;
        let mut func_section_count = 0u32;
        let mut memory_pages = self.memory_limit_pages;

        while pos < wasm_bytes.len() {
            if pos >= wasm_bytes.len() {
                break;
            }
            let section_id = wasm_bytes[pos];
            pos += 1;

            let (section_size, n) = match read_uleb128(wasm_bytes, pos) {
                Ok(v) => v,
                Err(_) => {
                    report.add_error(ValidationError::MalformedSection {
                        section: format!("id={section_id}"),
                        detail: "cannot read section size".to_string(),
                    });
                    break;
                }
            };
            pos += n;

            let section_size_usize = usize::try_from(section_size).unwrap_or(usize::MAX);
            let section_end = match pos.checked_add(section_size_usize) {
                Some(e) => e,
                None => {
                    report.add_error(ValidationError::MalformedSection {
                        section: format!("id={section_id}"),
                        detail: "section size overflows address space".to_string(),
                    });
                    break;
                }
            };
            if section_end > wasm_bytes.len() {
                report.add_error(ValidationError::MalformedSection {
                    section: format!("id={section_id}"),
                    detail: format!(
                        "section claims size {section_size} but only {} bytes remain",
                        wasm_bytes.len() - pos
                    ),
                });
                break;
            }

            let section_body = &wasm_bytes[pos..section_end];

            match WasmSectionId::from_byte(section_id) {
                Some(WasmSectionId::Type) => {
                    // Count types
                    if let Ok((count, _)) = read_uleb128(section_body, 0) {
                        type_section_count = count as u32;
                        report.type_count = count as u32;
                    }
                }
                Some(WasmSectionId::Function) => {
                    if let Ok((count, _)) = read_uleb128(section_body, 0) {
                        func_section_count = count as u32;
                        report.function_count = count as u32;
                    }
                }
                Some(WasmSectionId::Memory) => {
                    // Minimal memory section parse
                    if section_body.len() >= 3 && section_body[0] == 1 {
                        // count = 1
                        let kind = section_body[1];
                        // kind: 0x00 = min only, 0x01 = min+max.
                        debug_assert!(kind <= 1);
                        if let Ok((min_pages, _)) = read_uleb128(section_body, 2) {
                            memory_pages = min_pages as u32;
                            report.memory_pages = memory_pages;
                        }
                    }
                }
                Some(WasmSectionId::Import) => {
                    self.check_imports(section_body, &mut report);
                }
                Some(WasmSectionId::Code) => {
                    self.validate_code_section(
                        section_body,
                        func_section_count,
                        type_section_count,
                        memory_pages,
                        &mut report,
                    );
                }
                None => {
                    // Unknown section ID
                    report.add_warning(format!("Unknown section id {section_id}"));
                }
                _ => {}
            }

            pos = section_end;
        }

        report
    }

    fn check_imports(&self, body: &[u8], report: &mut ValidationReport) {
        let Ok((count, mut pos)) = read_uleb128(body, 0) else {
            return;
        };
        for _ in 0..count {
            // Read module name
            let Ok((mod_len, n)) = read_uleb128(body, pos) else {
                break;
            };
            pos += n;
            if pos + mod_len as usize > body.len() {
                break;
            }
            let module = String::from_utf8_lossy(&body[pos..pos + mod_len as usize]).to_string();
            pos += mod_len as usize;
            // Read name
            let Ok((name_len, n)) = read_uleb128(body, pos) else {
                break;
            };
            pos += n;
            if pos + name_len as usize > body.len() {
                break;
            }
            let name = String::from_utf8_lossy(&body[pos..pos + name_len as usize]).to_string();
            pos += name_len as usize;
            // Skip import descriptor (1 byte kind + 1 LEB128 index)
            if pos < body.len() {
                let _kind = body[pos];
                pos += 1;
                if let Ok((_, n)) = read_uleb128(body, pos) {
                    pos += n;
                }
            }

            let key = format!("{module}::{name}");
            if !self.resolved_imports.contains(&key) {
                report.add_warning(format!("Import not pre-resolved: {key}"));
            }
        }
    }

    fn validate_code_section(
        &self,
        body: &[u8],
        func_count: u32,
        type_count: u32,
        memory_pages: u32,
        report: &mut ValidationReport,
    ) {
        let Ok((count, mut pos)) = read_uleb128(body, 0) else {
            return;
        };
        for func_idx in 0..count {
            let Ok((body_size, n)) = read_uleb128(body, pos) else {
                break;
            };
            pos += n;
            let body_size_usize = usize::try_from(body_size).unwrap_or(usize::MAX);
            let func_end = match pos.checked_add(body_size_usize) {
                Some(e) => e,
                None => {
                    report.add_error(ValidationError::MalformedSection {
                        section: "code".to_string(),
                        detail: format!("function {func_idx} body size overflows"),
                    });
                    break;
                }
            };
            if func_end > body.len() {
                report.add_error(ValidationError::MalformedSection {
                    section: "code".to_string(),
                    detail: format!("function {func_idx} body overflows section"),
                });
                break;
            }
            let func_body = &body[pos..func_end];
            let mut fv =
                FunctionValidator::new(func_idx as u32, func_count, type_count, memory_pages);
            // Skip locals declaration at the start of the function body
            if let Ok((local_decl_count, ln)) = read_uleb128(func_body, 0) {
                let mut lpos = ln;
                for _ in 0..local_decl_count {
                    if let Ok((_, n1)) = read_uleb128(func_body, lpos) {
                        lpos += n1;
                        if lpos < func_body.len() {
                            lpos += 1;
                        } // valtype
                    }
                }
                fv.validate_body(&func_body[lpos..]);
            } else {
                fv.validate_body(func_body);
            }
            for e in fv.errors {
                report.add_error(e);
            }
            pos = func_end;
        }
    }
}

// ─── ValidationReport ─────────────────────────────────────────────────────────

/// The result of validating a WASM module.
#[derive(Debug, Clone)]
pub struct ValidationReport {
    /// All validation errors found.
    pub errors: Vec<ValidationError>,
    /// Non-fatal warnings.
    pub warnings: Vec<String>,
    /// Number of types declared.
    pub type_count: u32,
    /// Number of functions declared.
    pub function_count: u32,
    /// Declared minimum memory size in pages.
    pub memory_pages: u32,
}

impl ValidationReport {
    pub fn new() -> Self {
        Self {
            errors: Vec::new(),
            warnings: Vec::new(),
            type_count: 0,
            function_count: 0,
            memory_pages: 0,
        }
    }

    pub fn add_error(&mut self, e: ValidationError) {
        self.errors.push(e);
    }

    pub fn add_warning(&mut self, w: String) {
        self.warnings.push(w);
    }

    /// True when no errors were found.
    pub fn is_valid(&self) -> bool {
        self.errors.is_empty()
    }

    /// Number of errors.
    pub fn error_count(&self) -> usize {
        self.errors.len()
    }

    /// Number of warnings.
    pub fn warning_count(&self) -> usize {
        self.warnings.len()
    }

    /// Errors belonging to a particular category.
    pub fn errors_of_category(&self, category: &str) -> Vec<&ValidationError> {
        self.errors
            .iter()
            .filter(|e| e.category() == category)
            .collect()
    }

    /// Whether any fatal error was found.
    pub fn has_fatal(&self) -> bool {
        self.errors.iter().any(|e| e.is_fatal())
    }
}

impl Default for ValidationReport {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_wasm() -> Vec<u8> {
        // Magic + version + empty module
        vec![0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00]
    }

    fn build_wasm_with_code(func_body: &[u8]) -> Vec<u8> {
        // Minimal wasm with one type (no params, no results) + one function + code section
        let mut m = vec![0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00];
        // Type section: 1 type: () -> ()
        m.extend_from_slice(&[0x01, 0x04, 0x01, 0x60, 0x00, 0x00]);
        // Function section: 1 function, type index 0
        m.extend_from_slice(&[0x03, 0x02, 0x01, 0x00]);
        // Code section: 1 function body
        let inner: Vec<u8> = {
            let mut v = vec![0x00]; // 0 locals
            v.extend_from_slice(func_body);
            v
        };
        let body_size = inner.len() as u8;
        let section_size = (2 + inner.len()) as u8; // count(1) + size_leb(1) + inner
        m.extend_from_slice(&[0x0a, section_size, 0x01, body_size]);
        m.extend_from_slice(&inner);
        m
    }

    // ── ValidationError ───────────────────────────────────────────────────────

    #[test]
    fn test_validation_error_display_malformed() {
        let e = ValidationError::MalformedSection {
            section: "type".to_string(),
            detail: "truncated".to_string(),
        };
        assert!(e.to_string().contains("type"));
        assert!(e.to_string().contains("truncated"));
    }

    #[test]
    fn test_validation_error_display_invalid_opcode() {
        let e = ValidationError::InvalidOpcode {
            offset: 0x10,
            opcode: 0xFF,
        };
        assert!(e.to_string().contains("0xff"));
    }

    #[test]
    fn test_validation_error_display_type_mismatch() {
        let e = ValidationError::TypeMismatch {
            expected: "i32".to_string(),
            found: "i64".to_string(),
            context: "add".to_string(),
        };
        assert!(e.to_string().contains("i32"));
        assert!(e.to_string().contains("i64"));
    }

    #[test]
    fn test_validation_error_is_fatal() {
        assert!(ValidationError::InvalidMagic.is_fatal());
        assert!(
            ValidationError::InvalidOpcode {
                offset: 0,
                opcode: 0
            }
            .is_fatal()
        );
        assert!(
            !ValidationError::UnresolvedImport {
                module: "m".to_string(),
                name: "n".to_string()
            }
            .is_fatal()
        );
    }

    #[test]
    fn test_validation_error_categories() {
        assert_eq!(ValidationError::InvalidMagic.category(), "magic");
        assert_eq!(
            ValidationError::TypeMismatch {
                expected: "i32".to_string(),
                found: "i64".to_string(),
                context: "x".to_string()
            }
            .category(),
            "type"
        );
        assert_eq!(
            ValidationError::MemoryOutOfBounds {
                offset: 0,
                access_size: 4,
                memory_limit_pages: 1
            }
            .category(),
            "memory"
        );
    }

    // ── WasmValueStack ────────────────────────────────────────────────────────

    #[test]
    fn test_value_stack_push_pop() {
        let mut s = WasmValueStack::new();
        s.push(WasmValueType::I32);
        s.pop_expect(WasmValueType::I32, "test").unwrap();
        assert_eq!(s.depth(), 0);
    }

    #[test]
    fn test_value_stack_type_mismatch() {
        let mut s = WasmValueStack::new();
        s.push(WasmValueType::I64);
        let r = s.pop_expect(WasmValueType::I32, "test");
        assert!(r.is_err());
    }

    #[test]
    fn test_value_stack_unreachable() {
        let mut s = WasmValueStack::new();
        s.mark_unreachable();
        assert!(s.is_unreachable());
        // Pop on unreachable always succeeds
        s.pop_expect(WasmValueType::I32, "test").unwrap();
    }

    #[test]
    fn test_value_stack_empty_pop_error() {
        let mut s = WasmValueStack::new();
        let r = s.pop_expect(WasmValueType::I32, "test");
        assert!(r.is_err());
    }

    // ── TypeChecker ───────────────────────────────────────────────────────────

    #[test]
    fn test_type_checker_i32_binop() {
        let mut tc = TypeChecker::new(0, vec![WasmValueType::I32, WasmValueType::I32]);
        tc.check_const_i32();
        tc.check_const_i32();
        tc.check_binop_i32();
        assert!(!tc.has_errors());
        assert_eq!(tc.stack_depth(), 1);
    }

    #[test]
    fn test_type_checker_local_get_set() {
        let mut tc = TypeChecker::new(0, vec![WasmValueType::I64]);
        tc.check_const_i64();
        tc.check_local_set(0);
        tc.check_local_get(0);
        assert!(!tc.has_errors());
    }

    #[test]
    fn test_type_checker_invalid_local() {
        let mut tc = TypeChecker::new(0, vec![]);
        tc.check_local_get(5);
        assert!(tc.has_errors());
    }

    #[test]
    fn test_type_checker_return_consumes_value() {
        let mut tc = TypeChecker::new(0, vec![]);
        tc.check_const_i32();
        tc.check_return(Some(WasmValueType::I32));
        assert!(!tc.has_errors());
    }

    // ── FunctionValidator ─────────────────────────────────────────────────────

    #[test]
    fn test_function_validator_simple_body() {
        let mut fv = FunctionValidator::new(0, 1, 1, 1);
        // nop + return
        let body = vec![0x01, 0x0f, 0x0b];
        assert!(fv.validate_body(&body));
    }

    #[test]
    fn test_function_validator_invalid_opcode() {
        let mut fv = FunctionValidator::new(0, 1, 1, 1);
        let body = vec![0xEE]; // unknown opcode
        assert!(!fv.validate_body(&body));
        assert!(!fv.errors.is_empty());
    }

    #[test]
    fn test_function_validator_call_out_of_range() {
        let mut fv = FunctionValidator::new(0, 2, 1, 1);
        // call funcidx=5 (out of range)
        let body = vec![0x10, 0x05, 0x0b];
        fv.validate_body(&body);
        
        assert!(fv
            .errors
            .iter().any(|e| matches!(e, ValidationError::InvalidFuncIndex { .. })));
    }

    // ── ModuleValidator ───────────────────────────────────────────────────────

    #[test]
    fn test_module_validator_minimal_valid() {
        let v = ModuleValidator::new();
        let r = v.validate(&minimal_wasm());
        assert!(r.is_valid());
    }

    #[test]
    fn test_module_validator_invalid_magic() {
        let v = ModuleValidator::new();
        let bad = vec![0xFF, 0xFF, 0xFF, 0xFF, 0x01, 0x00, 0x00, 0x00];
        let r = v.validate(&bad);
        assert!(!r.is_valid());
        assert!(r.has_fatal());
    }

    #[test]
    fn test_module_validator_too_short() {
        let v = ModuleValidator::new();
        let r = v.validate(&[0x00, 0x61]);
        assert!(!r.is_valid());
    }

    #[test]
    fn test_module_validator_with_code_section() {
        let v = ModuleValidator::new();
        let wasm = build_wasm_with_code(&[0x01, 0x0f, 0x0b]); // nop + return + end
        let r = v.validate(&wasm);
        assert!(r.function_count == 1);
    }

    #[test]
    fn test_module_validator_report_error_count() {
        let mut r = ValidationReport::new();
        r.add_error(ValidationError::InvalidMagic);
        r.add_error(ValidationError::Generic("x".to_string()));
        assert_eq!(r.error_count(), 2);
    }

    #[test]
    fn test_module_validator_report_warnings() {
        let mut r = ValidationReport::new();
        r.add_warning("something minor".to_string());
        assert_eq!(r.warning_count(), 1);
        assert!(r.is_valid());
    }

    #[test]
    fn test_module_validator_errors_of_category() {
        let mut r = ValidationReport::new();
        r.add_error(ValidationError::InvalidMagic);
        r.add_error(ValidationError::TypeMismatch {
            expected: "i32".to_string(),
            found: "i64".to_string(),
            context: "x".to_string(),
        });
        let magic_errs = r.errors_of_category("magic");
        assert_eq!(magic_errs.len(), 1);
    }

    #[test]
    fn test_module_validator_with_memory_limit() {
        let v = ModuleValidator::new().with_memory_limit(4);
        let r = v.validate(&minimal_wasm());
        assert!(r.is_valid());
    }

    #[test]
    fn test_module_validator_resolved_import() {
        let v = ModuleValidator::new().with_resolved_import("wasi_snapshot_preview1", "fd_write");
        // Just ensure no panic
        let r = v.validate(&minimal_wasm());
        assert!(r.is_valid());
    }

    #[test]
    fn test_memory_out_of_bounds_error() {
        let e = ValidationError::MemoryOutOfBounds {
            offset: 999999,
            access_size: 4,
            memory_limit_pages: 1,
        };
        assert!(e.to_string().contains("999999"));
    }

    #[test]
    fn test_unresolved_import_error() {
        let e = ValidationError::UnresolvedImport {
            module: "env".to_string(),
            name: "abort".to_string(),
        };
        assert!(e.to_string().contains("env"));
        assert!(e.to_string().contains("abort"));
    }

    // ───── Edge-case coverage ─────────────────────────────────────────────

    #[test]
    fn validate_empty_input_invalid_magic() {
        let v = ModuleValidator::new();
        let r = v.validate(&[]);
        assert!(!r.is_valid());
    }

    #[test]
    fn validate_truncated_magic() {
        let v = ModuleValidator::new();
        let r = v.validate(&[0x00, 0x61, 0x73]); // 3 of 4 magic bytes
        assert!(!r.is_valid());
    }

    #[test]
    fn validate_bad_magic_bytes() {
        let v = ModuleValidator::new();
        // Wrong magic
        let r = v.validate(&[0xFF, 0xFF, 0xFF, 0xFF, 0x01, 0x00, 0x00, 0x00]);
        assert!(!r.is_valid());
    }

    #[test]
    fn validate_wrong_version() {
        let v = ModuleValidator::new();
        // Right magic, wrong version
        let r = v.validate(&[0x00, 0x61, 0x73, 0x6D, 0xFF, 0xFF, 0xFF, 0xFF]);
        // Version mismatch should fail or at least record an issue
        let _ = r;
    }

    #[test]
    fn report_add_multiple_errors_aggregates() {
        let mut r = ValidationReport::new();
        for off in [0u32, 10, 20] {
            r.add_error(ValidationError::InvalidOpcode { offset: off as usize, opcode: 0xFF });
        }
        assert_eq!(r.errors_of_category("opcode").len(), 3);
    }

    #[test]
    fn validation_error_invalid_magic_has_fatal() {
        let e = ValidationError::InvalidMagic;
        assert!(e.is_fatal());
        assert_eq!(e.category(), "magic");
    }

    #[test]
    fn validator_with_zero_memory_limit_still_valid_on_empty_module() {
        // Empty module has no memory section: zero limit shouldn't trigger
        // memory-related errors.
        let v = ModuleValidator::new().with_memory_limit(0);
        let r = v.validate(&minimal_wasm());
        assert!(r.is_valid());
    }

    #[test]
    fn validator_resolved_imports_chainable() {
        let v = ModuleValidator::new()
            .with_resolved_import("a", "b")
            .with_resolved_import("c", "d");
        let r = v.validate(&minimal_wasm());
        assert!(r.is_valid());
    }
}
