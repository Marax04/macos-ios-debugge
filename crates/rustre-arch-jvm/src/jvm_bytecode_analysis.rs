//! `jvm_bytecode_analysis` — JVM bytecode analysis: stack frame simulation,
//! exception handlers, invokedynamic resolution, generics, and inner classes.

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

// ─── Error ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JvmAnalysisError {
    StackUnderflow {
        pc: usize,
    },
    TypeMismatch {
        pc: usize,
        expected: String,
        found: String,
    },
    UnknownOpcode(u8),
    MalformedClass(String),
    InvokeDynamicNotResolved(u16),
}

impl fmt::Display for JvmAnalysisError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::StackUnderflow { pc } => write!(f, "stack underflow at pc={pc}"),
            Self::TypeMismatch {
                pc,
                expected,
                found,
            } => {
                write!(
                    f,
                    "type mismatch at pc={pc}: expected {expected} found {found}"
                )
            }
            Self::UnknownOpcode(op) => write!(f, "unknown opcode: 0x{op:02X}"),
            Self::MalformedClass(msg) => write!(f, "malformed class: {msg}"),
            Self::InvokeDynamicNotResolved(idx) => {
                write!(f, "invokedynamic #{idx} not resolved")
            }
        }
    }
}

impl std::error::Error for JvmAnalysisError {}

// ─── JvmValue ────────────────────────────────────────────────────────────────

/// An abstract JVM value type on the operand stack.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum JvmValue {
    Int,
    Long,
    Float,
    Double,
    Reference(String), // class name
    Null,
    ReturnAddress(usize), // for jsr/ret
    Top,                  // second slot of long/double
    Unknown,
}

impl JvmValue {
    #[must_use] 
    pub const fn category(&self) -> u8 {
        match self {
            Self::Long | Self::Double => 2,
            _ => 1,
        }
    }

    #[must_use] 
    pub const fn is_reference(&self) -> bool {
        matches!(self, Self::Reference(_) | Self::Null)
    }
}

impl fmt::Display for JvmValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Int => write!(f, "int"),
            Self::Long => write!(f, "long"),
            Self::Float => write!(f, "float"),
            Self::Double => write!(f, "double"),
            Self::Reference(cls) => write!(f, "ref({cls})"),
            Self::Null => write!(f, "null"),
            Self::ReturnAddress(pc) => write!(f, "ret_addr({pc})"),
            Self::Top => write!(f, "top"),
            Self::Unknown => write!(f, "unknown"),
        }
    }
}

// ─── StackFrame ──────────────────────────────────────────────────────────────

/// A JVM stack frame at a specific program point.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StackFrame {
    pub operand_stack: Vec<JvmValue>,
    pub locals: Vec<JvmValue>,
    pub max_stack: usize,
    pub max_locals: usize,
}

impl StackFrame {
    #[must_use] 
    pub fn new(max_stack: usize, max_locals: usize) -> Self {
        Self {
            operand_stack: Vec::with_capacity(max_stack),
            locals: vec![JvmValue::Unknown; max_locals],
            max_stack,
            max_locals,
        }
    }

    pub fn push(&mut self, v: JvmValue) -> Result<(), JvmAnalysisError> {
        if v.category() == 2 {
            self.operand_stack.push(v);
            self.operand_stack.push(JvmValue::Top);
        } else {
            self.operand_stack.push(v);
        }
        Ok(())
    }

    pub fn pop(&mut self, pc: usize) -> Result<JvmValue, JvmAnalysisError> {
        self.operand_stack
            .pop()
            .ok_or(JvmAnalysisError::StackUnderflow { pc })
    }

    #[must_use] 
    pub fn peek(&self) -> Option<&JvmValue> {
        self.operand_stack.last()
    }

    pub fn set_local(&mut self, index: usize, val: JvmValue) {
        if index < self.locals.len() {
            self.locals[index] = val;
        }
    }

    #[must_use] 
    pub fn get_local(&self, index: usize) -> JvmValue {
        self.locals.get(index).cloned().unwrap_or(JvmValue::Unknown)
    }

    #[must_use] 
    pub const fn stack_depth(&self) -> usize {
        self.operand_stack.len()
    }
}

// ─── StackFrameSimulator ─────────────────────────────────────────────────────

/// Simulates JVM operand stack state through bytecode.
pub struct StackFrameSimulator {
    pub frames: HashMap<usize, StackFrame>,
    pub errors: Vec<JvmAnalysisError>,
}

impl StackFrameSimulator {
    #[must_use] 
    pub fn new() -> Self {
        Self {
            frames: HashMap::new(),
            errors: Vec::new(),
        }
    }

    /// Simulate a sequence of opcodes, tracking stack state.
    /// `opcodes`: list of (pc, opcode, operands).
    pub fn simulate(&mut self, opcodes: &[(usize, u8, Vec<u16>)], entry_frame: StackFrame) {
        let mut frame = entry_frame;

        for (pc, opcode, operands) in opcodes {
            self.frames.insert(*pc, frame.clone());
            if let Err(e) = self.simulate_one(&mut frame, *pc, *opcode, operands) {
                self.errors.push(e);
            }
        }
    }

    fn simulate_one(
        &self,
        frame: &mut StackFrame,
        pc: usize,
        opcode: u8,
        operands: &[u16],
    ) -> Result<(), JvmAnalysisError> {
        match opcode {
            0x00 => {} // nop
            0x01 => {
                frame.push(JvmValue::Null)?;
            } // aconst_null
            0x02..=0x08 => {
                frame.push(JvmValue::Int)?;
            } // iconst_*
            0x09..=0x0A => {
                frame.push(JvmValue::Long)?;
            } // lconst_*
            0x0B..=0x0D => {
                frame.push(JvmValue::Float)?;
            } // fconst_*
            0x0E..=0x0F => {
                frame.push(JvmValue::Double)?;
            } // dconst_*
            0x10 | 0x11 => {
                frame.push(JvmValue::Int)?;
            } // bipush, sipush
            0x12..=0x14 => {
                frame.push(JvmValue::Unknown)?;
            } // ldc, ldc_w, ldc2_w
            0x15 => {
                // iload
                let idx = operands.first().copied().unwrap_or(0) as usize;
                frame.push(frame.get_local(idx))?;
            }
            0x16 => {
                frame.push(JvmValue::Long)?;
            } // lload
            0x17 => {
                frame.push(JvmValue::Float)?;
            } // fload
            0x18 => {
                frame.push(JvmValue::Double)?;
            } // dload
            0x19 => {
                // aload
                let idx = operands.first().copied().unwrap_or(0) as usize;
                frame.push(frame.get_local(idx))?;
            }
            0x1A..=0x1D => {
                frame.push(JvmValue::Int)?;
            } // iload_0..3
            0x1E..=0x21 => {
                frame.push(JvmValue::Long)?;
            } // lload_0..3
            0x22..=0x25 => {
                frame.push(JvmValue::Float)?;
            } // fload_0..3
            0x26..=0x29 => {
                frame.push(JvmValue::Double)?;
            } // dload_0..3
            0x2A..=0x2D => {
                frame.push(JvmValue::Reference(String::new()))?;
            } // aload_0..3
            // Array loads
            0x2E => {
                frame.pop(pc)?;
                frame.pop(pc)?;
                frame.push(JvmValue::Int)?;
            } // iaload
            0x2F => {
                frame.pop(pc)?;
                frame.pop(pc)?;
                frame.push(JvmValue::Long)?;
            } // laload
            0x30 => {
                frame.pop(pc)?;
                frame.pop(pc)?;
                frame.push(JvmValue::Float)?;
            } // faload
            0x31 => {
                frame.pop(pc)?;
                frame.pop(pc)?;
                frame.push(JvmValue::Double)?;
            } // daload
            0x32 => {
                frame.pop(pc)?;
                frame.pop(pc)?;
                frame.push(JvmValue::Reference(String::new()))?;
            }
            // Stores
            0x36 => {
                // istore
                let val = frame.pop(pc)?;
                let idx = operands.first().copied().unwrap_or(0) as usize;
                frame.set_local(idx, val);
            }
            0x3B..=0x3E => {
                frame.pop(pc)?;
            } // istore_0..3
            0x4B..=0x4E => {
                frame.pop(pc)?;
            } // astore_0..3
            // Stack manipulation
            0x57 => {
                frame.pop(pc)?;
            } // pop
            0x58 => {
                frame.pop(pc)?;
                frame.pop(pc)?;
            } // pop2
            0x59 => {
                // dup
                let v = frame.peek().cloned().unwrap_or(JvmValue::Unknown);
                frame.push(v)?;
            }
            // Arithmetic
            0x60 => {
                frame.pop(pc)?;
                frame.pop(pc)?;
                frame.push(JvmValue::Int)?;
            } // iadd
            0x61 => {
                frame.pop(pc)?;
                frame.pop(pc)?;
                frame.push(JvmValue::Long)?;
            } // ladd
            0x62 => {
                frame.pop(pc)?;
                frame.pop(pc)?;
                frame.push(JvmValue::Float)?;
            } // fadd
            0x63 => {
                frame.pop(pc)?;
                frame.pop(pc)?;
                frame.push(JvmValue::Double)?;
            } // dadd
            // Comparisons / branches: don't change stack in our simple model
            0x99..=0xA6 => {
                frame.pop(pc)?;
            } // if*
            0xA7 => {} // goto
            // Return
            0xAC => {
                frame.pop(pc)?;
            } // ireturn
            0xAD => {
                frame.pop(pc)?;
            } // lreturn
            0xAE => {
                frame.pop(pc)?;
            } // freturn
            0xAF => {
                frame.pop(pc)?;
            } // dreturn
            0xB0 => {
                frame.pop(pc)?;
            } // areturn
            0xB1 => {} // return (void)
            // Field access
            0xB2 => {
                frame.push(JvmValue::Unknown)?;
            } // getstatic
            0xB3 => {
                frame.pop(pc)?;
            } // putstatic
            0xB4 => {
                frame.pop(pc)?;
                frame.push(JvmValue::Unknown)?;
            } // getfield
            0xB5 => {
                frame.pop(pc)?;
                frame.pop(pc)?;
            } // putfield
            // Method invocation
            0xB6..=0xB9 => {
                // invokevirtual, invokespecial, invokestatic, invokeinterface
                frame.push(JvmValue::Unknown)?;
            }
            0xBA => {
                // invokedynamic
                frame.push(JvmValue::Unknown)?;
            }
            // Object creation
            0xBB => {
                frame.push(JvmValue::Reference(String::new()))?;
            } // new
            0xBC => {
                frame.pop(pc)?;
                frame.push(JvmValue::Reference(String::new()))?;
            } // newarray
            0xC0 => {
                frame.pop(pc)?;
                frame.push(JvmValue::Reference(String::new()))?;
            } // checkcast
            0xC1 => {
                frame.pop(pc)?;
                frame.push(JvmValue::Int)?;
            } // instanceof
            _ => {} // Treat unknown as no-op for simulation.
        }
        Ok(())
    }

    #[must_use] 
    pub fn frame_at(&self, pc: usize) -> Option<&StackFrame> {
        self.frames.get(&pc)
    }

    #[must_use] 
    pub const fn has_errors(&self) -> bool {
        !self.errors.is_empty()
    }
}

impl Default for StackFrameSimulator {
    fn default() -> Self {
        Self::new()
    }
}

// ─── ExceptionHandlerMapper ──────────────────────────────────────────────────

/// An exception handler entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExceptionHandler {
    pub start_pc: usize,
    pub end_pc: usize,
    pub handler_pc: usize,
    pub catch_type: Option<String>, // None = catch all (finally).
}

impl ExceptionHandler {
    #[must_use] 
    pub const fn covers(&self, pc: usize) -> bool {
        pc >= self.start_pc && pc < self.end_pc
    }

    #[must_use] 
    pub const fn is_finally(&self) -> bool {
        self.catch_type.is_none()
    }
}

/// Maps program points to applicable exception handlers.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct ExceptionHandlerMapper {
    pub handlers: Vec<ExceptionHandler>,
}

impl ExceptionHandlerMapper {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_handler(&mut self, handler: ExceptionHandler) {
        self.handlers.push(handler);
    }

    /// Find all handlers that cover `pc`.
    #[must_use] 
    pub fn handlers_for(&self, pc: usize) -> Vec<&ExceptionHandler> {
        self.handlers.iter().filter(|h| h.covers(pc)).collect()
    }

    /// Find handlers for a specific exception type.
    #[must_use] 
    pub fn handlers_for_type(&self, pc: usize, exc_type: &str) -> Vec<&ExceptionHandler> {
        self.handlers_for(pc)
            .into_iter()
            .filter(|h| h.catch_type.as_deref() == Some(exc_type) || h.is_finally())
            .collect()
    }

    /// All unique handler PC targets.
    #[must_use] 
    pub fn handler_targets(&self) -> Vec<usize> {
        let mut targets: Vec<usize> = self.handlers.iter().map(|h| h.handler_pc).collect();
        targets.sort_unstable();
        targets.dedup();
        targets
    }
}

// ─── BootstrapMethodTable ─────────────────────────────────────────────────────

/// A bootstrap method entry (for invokedynamic).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BootstrapMethod {
    pub index: u16,
    pub method_ref: String,
    pub arguments: Vec<String>,
}

/// The bootstrap method table from a class file.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct BootstrapMethodTable {
    pub methods: Vec<BootstrapMethod>,
}

impl BootstrapMethodTable {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(&mut self, method: BootstrapMethod) {
        self.methods.push(method);
    }

    #[must_use] 
    pub fn get(&self, index: u16) -> Option<&BootstrapMethod> {
        self.methods.iter().find(|m| m.index == index)
    }
}

// ─── LambdaTarget ────────────────────────────────────────────────────────────

/// A resolved lambda target from an invokedynamic instruction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LambdaTarget {
    pub invoke_dynamic_pc: usize,
    pub bootstrap_index: u16,
    pub functional_interface: String,
    pub target_method: String,
    pub target_class: String,
    pub capture_count: usize,
}

// ─── InvokeDynamicResolver ────────────────────────────────────────────────────

/// Resolves invokedynamic instructions to their lambda targets.
pub struct InvokeDynamicResolver {
    pub bootstrap_table: BootstrapMethodTable,
    pub resolved: Vec<LambdaTarget>,
}

impl InvokeDynamicResolver {
    #[must_use] 
    pub const fn new(bootstrap_table: BootstrapMethodTable) -> Self {
        Self {
            bootstrap_table,
            resolved: Vec::new(),
        }
    }

    /// Attempt to resolve an invokedynamic at `pc` using bootstrap index `bsm_index`.
    pub fn resolve(
        &mut self,
        pc: usize,
        bsm_index: u16,
        name_and_type: &str,
    ) -> Result<&LambdaTarget, JvmAnalysisError> {
        let bsm = self
            .bootstrap_table
            .get(bsm_index)
            .ok_or(JvmAnalysisError::InvokeDynamicNotResolved(bsm_index))?;

        // Check for LambdaMetafactory.
        let is_lambda_meta = bsm.method_ref.contains("LambdaMetafactory");
        // Prefer the explicit NameAndType from the invokedynamic instruction when present;
        // fall back to the first bootstrap argument when the caller passes an empty string.
        let target_method = if name_and_type.is_empty() {
            bsm.arguments.first().cloned().unwrap_or_default()
        } else {
            name_and_type.to_string()
        };
        let functional_interface = bsm.arguments.get(1).cloned().unwrap_or_default();

        let target = LambdaTarget {
            invoke_dynamic_pc: pc,
            bootstrap_index: bsm_index,
            functional_interface,
            target_method,
            target_class: if is_lambda_meta {
                "lambda".into()
            } else {
                "unknown".into()
            },
            capture_count: bsm.arguments.len().saturating_sub(2),
        };
        self.resolved.push(target);
        Ok(self.resolved.last().unwrap())
    }

    #[must_use] 
    pub const fn resolution_count(&self) -> usize {
        self.resolved.len()
    }
}

// ─── GenericsErasureAnalyzer ─────────────────────────────────────────────────

/// Tracks generic type erasure patterns.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErasedType {
    pub raw_type: String,
    pub generic_signature: Option<String>,
    pub checkcast_target: Option<String>,
}

/// Detects and records type erasure patterns from checkcast and signatures.
#[derive(Debug, Default)]
pub struct GenericsErasureAnalyzer {
    pub erased_types: Vec<ErasedType>,
}

impl GenericsErasureAnalyzer {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a checkcast instruction (indicates generic type erasure boundary).
    pub fn record_checkcast(
        &mut self,
        raw_type: impl Into<String>,
        checkcast_target: impl Into<String>,
    ) {
        self.erased_types.push(ErasedType {
            raw_type: raw_type.into(),
            generic_signature: None,
            checkcast_target: Some(checkcast_target.into()),
        });
    }

    /// Record a generic signature string.
    pub fn record_signature(&mut self, raw_type: impl Into<String>, signature: impl Into<String>) {
        self.erased_types.push(ErasedType {
            raw_type: raw_type.into(),
            generic_signature: Some(signature.into()),
            checkcast_target: None,
        });
    }

    #[must_use] 
    pub const fn count(&self) -> usize {
        self.erased_types.len()
    }
}

// ─── InnerClassAnalyzer ──────────────────────────────────────────────────────

/// Information about an inner class relationship.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InnerClassInfo {
    pub inner_class: String,
    pub outer_class: Option<String>,
    pub inner_name: Option<String>,
    pub access_flags: u16,
    pub is_anonymous: bool,
    pub is_local: bool,
    pub is_static: bool,
}

impl InnerClassInfo {
    #[must_use] 
    pub const fn is_synthetic(&self) -> bool {
        self.access_flags & 0x1000 != 0
    }
}

/// Analyses inner class relationships in a class file.
#[derive(Debug, Default)]
pub struct InnerClassAnalyzer {
    pub inner_classes: Vec<InnerClassInfo>,
}

impl InnerClassAnalyzer {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(&mut self, info: InnerClassInfo) {
        self.inner_classes.push(info);
    }

    #[must_use] 
    pub fn anonymous_classes(&self) -> Vec<&InnerClassInfo> {
        self.inner_classes
            .iter()
            .filter(|i| i.is_anonymous)
            .collect()
    }

    #[must_use] 
    pub fn static_nested_classes(&self) -> Vec<&InnerClassInfo> {
        self.inner_classes
            .iter()
            .filter(|i| i.is_static && !i.is_anonymous)
            .collect()
    }

    #[must_use] 
    pub const fn count(&self) -> usize {
        self.inner_classes.len()
    }
}

// ─── BytecodeAnalyzer ─────────────────────────────────────────────────────────

/// Top-level JVM bytecode analyser.
pub struct BytecodeAnalyzer {
    pub stack_simulator: StackFrameSimulator,
    pub exception_mapper: ExceptionHandlerMapper,
    pub invokedynamic_resolver: InvokeDynamicResolver,
    pub generics_analyzer: GenericsErasureAnalyzer,
    pub inner_class_analyzer: InnerClassAnalyzer,
}

impl BytecodeAnalyzer {
    #[must_use] 
    pub fn new() -> Self {
        Self {
            stack_simulator: StackFrameSimulator::new(),
            exception_mapper: ExceptionHandlerMapper::new(),
            invokedynamic_resolver: InvokeDynamicResolver::new(BootstrapMethodTable::new()),
            generics_analyzer: GenericsErasureAnalyzer::new(),
            inner_class_analyzer: InnerClassAnalyzer::new(),
        }
    }

    /// Run stack frame simulation.
    pub fn simulate_frames(
        &mut self,
        opcodes: &[(usize, u8, Vec<u16>)],
        max_stack: usize,
        max_locals: usize,
    ) {
        let entry = StackFrame::new(max_stack, max_locals);
        self.stack_simulator.simulate(opcodes, entry);
    }

    /// Get analysis summary.
    #[must_use] 
    pub fn summary(&self) -> String {
        format!(
            "frames={} handlers={} lambdas={} erased={} inner={}",
            self.stack_simulator.frames.len(),
            self.exception_mapper.handlers.len(),
            self.invokedynamic_resolver.resolution_count(),
            self.generics_analyzer.count(),
            self.inner_class_analyzer.count(),
        )
    }
}

impl Default for BytecodeAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jvm_value_category() {
        assert_eq!(JvmValue::Long.category(), 2);
        assert_eq!(JvmValue::Int.category(), 1);
    }

    #[test]
    fn jvm_value_is_reference() {
        assert!(JvmValue::Reference("foo".into()).is_reference());
        assert!(JvmValue::Null.is_reference());
        assert!(!JvmValue::Int.is_reference());
    }

    #[test]
    fn stack_frame_push_pop() {
        let mut frame = StackFrame::new(10, 5);
        frame.push(JvmValue::Int).unwrap();
        frame.push(JvmValue::Float).unwrap();
        assert_eq!(frame.stack_depth(), 2);
        let v = frame.pop(0).unwrap();
        assert_eq!(v, JvmValue::Float);
    }

    #[test]
    fn stack_frame_push_wide() {
        let mut frame = StackFrame::new(10, 5);
        frame.push(JvmValue::Long).unwrap();
        // Long pushes itself + Top.
        assert_eq!(frame.stack_depth(), 2);
    }

    #[test]
    fn stack_frame_underflow() {
        let mut frame = StackFrame::new(10, 5);
        let result = frame.pop(42);
        assert!(matches!(
            result,
            Err(JvmAnalysisError::StackUnderflow { pc: 42 })
        ));
    }

    #[test]
    fn stack_frame_locals() {
        let mut frame = StackFrame::new(10, 5);
        frame.set_local(0, JvmValue::Int);
        assert_eq!(frame.get_local(0), JvmValue::Int);
        assert_eq!(frame.get_local(4), JvmValue::Unknown);
    }

    #[test]
    fn stack_frame_peek() {
        let mut frame = StackFrame::new(10, 5);
        frame.push(JvmValue::Int).unwrap();
        assert_eq!(frame.peek(), Some(&JvmValue::Int));
    }

    #[test]
    fn simulator_nop() {
        let mut sim = StackFrameSimulator::new();
        let ops = vec![(0, 0x00u8, vec![])]; // nop
        let frame = StackFrame::new(10, 5);
        sim.simulate(&ops, frame);
        assert!(!sim.has_errors());
    }

    #[test]
    fn simulator_iconst_ireturn() {
        let mut sim = StackFrameSimulator::new();
        let ops = vec![
            (0, 0x05, vec![]), // iconst_2
            (1, 0xAC, vec![]), // ireturn
        ];
        let frame = StackFrame::new(10, 5);
        sim.simulate(&ops, frame);
        assert!(!sim.has_errors());
    }

    #[test]
    fn simulator_records_frames() {
        let mut sim = StackFrameSimulator::new();
        let ops = vec![(0, 0x00, vec![]), (1, 0x00, vec![])];
        let frame = StackFrame::new(10, 5);
        sim.simulate(&ops, frame);
        assert!(sim.frame_at(0).is_some());
        assert!(sim.frame_at(1).is_some());
    }

    #[test]
    fn exception_handler_covers() {
        let handler = ExceptionHandler {
            start_pc: 10,
            end_pc: 20,
            handler_pc: 50,
            catch_type: Some("java/lang/Exception".into()),
        };
        assert!(handler.covers(15));
        assert!(!handler.covers(5));
        assert!(!handler.covers(20));
    }

    #[test]
    fn exception_handler_finally() {
        let handler = ExceptionHandler {
            start_pc: 0,
            end_pc: 10,
            handler_pc: 20,
            catch_type: None,
        };
        assert!(handler.is_finally());
    }

    #[test]
    fn exception_mapper_handlers_for() {
        let mut mapper = ExceptionHandlerMapper::new();
        mapper.add_handler(ExceptionHandler {
            start_pc: 0,
            end_pc: 100,
            handler_pc: 200,
            catch_type: Some("java/lang/Exception".into()),
        });
        let handlers = mapper.handlers_for(50);
        assert_eq!(handlers.len(), 1);
    }

    #[test]
    fn exception_mapper_handler_targets() {
        let mut mapper = ExceptionHandlerMapper::new();
        mapper.add_handler(ExceptionHandler {
            start_pc: 0,
            end_pc: 10,
            handler_pc: 50,
            catch_type: None,
        });
        mapper.add_handler(ExceptionHandler {
            start_pc: 10,
            end_pc: 20,
            handler_pc: 50,
            catch_type: None,
        });
        let targets = mapper.handler_targets();
        assert_eq!(targets, vec![50]);
    }

    #[test]
    fn bootstrap_method_table_add_get() {
        let mut table = BootstrapMethodTable::new();
        table.add(BootstrapMethod {
            index: 0,
            method_ref: "java/lang/invoke/LambdaMetafactory.metafactory".into(),
            arguments: vec!["(I)V".into(), "apply".into()],
        });
        assert!(table.get(0).is_some());
        assert!(table.get(1).is_none());
    }

    #[test]
    fn invokedynamic_resolver_resolve() {
        let mut table = BootstrapMethodTable::new();
        table.add(BootstrapMethod {
            index: 0,
            method_ref: "LambdaMetafactory.metafactory".into(),
            arguments: vec!["method_ref".into(), "Runnable".into()],
        });
        let mut resolver = InvokeDynamicResolver::new(table);
        let result = resolver.resolve(42, 0, "run:()V");
        assert!(result.is_ok());
        assert_eq!(resolver.resolution_count(), 1);
    }

    #[test]
    fn invokedynamic_resolver_not_found() {
        let table = BootstrapMethodTable::new();
        let mut resolver = InvokeDynamicResolver::new(table);
        let result = resolver.resolve(0, 99, "");
        assert!(matches!(
            result,
            Err(JvmAnalysisError::InvokeDynamicNotResolved(99))
        ));
    }

    #[test]
    fn generics_erasure_record() {
        let mut ga = GenericsErasureAnalyzer::new();
        ga.record_checkcast("Object", "String");
        ga.record_signature("List", "<E>");
        assert_eq!(ga.count(), 2);
    }

    #[test]
    fn inner_class_anonymous() {
        let mut analyzer = InnerClassAnalyzer::new();
        analyzer.add(InnerClassInfo {
            inner_class: "Foo$1".into(),
            outer_class: Some("Foo".into()),
            inner_name: None,
            access_flags: 0,
            is_anonymous: true,
            is_local: false,
            is_static: false,
        });
        assert_eq!(analyzer.anonymous_classes().len(), 1);
    }

    #[test]
    fn inner_class_static_nested() {
        let mut analyzer = InnerClassAnalyzer::new();
        analyzer.add(InnerClassInfo {
            inner_class: "Foo$Bar".into(),
            outer_class: Some("Foo".into()),
            inner_name: Some("Bar".into()),
            access_flags: 0,
            is_anonymous: false,
            is_local: false,
            is_static: true,
        });
        assert_eq!(analyzer.static_nested_classes().len(), 1);
    }

    #[test]
    fn bytecode_analyzer_summary() {
        let analyzer = BytecodeAnalyzer::new();
        let summary = analyzer.summary();
        assert!(summary.contains("frames="));
    }

    #[test]
    fn jvm_error_display() {
        let e = JvmAnalysisError::StackUnderflow { pc: 42 };
        assert!(e.to_string().contains("42"));
    }
}
