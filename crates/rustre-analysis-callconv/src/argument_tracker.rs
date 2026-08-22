//! Track function arguments: forward data-flow from call site, identify
//! argument count, types (int/ptr/float), and passing mechanism (reg/stack).

use rustc_hash::FxHashMap;
use std::collections::{HashSet, VecDeque};
use serde::{Deserialize, Serialize};

use crate::CallingConventionPattern;

// ─── Argument type ────────────────────────────────────────────────────────────

/// Inferred type of a function argument.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ArgType {
    /// 8-bit integer.
    Int8,
    /// 16-bit integer.
    Int16,
    /// 32-bit integer.
    Int32,
    /// 64-bit integer.
    Int64,
    /// Pointer (address-sized integer).
    Pointer,
    /// Single-precision float.
    Float32,
    /// Double-precision float.
    Float64,
    /// 128-bit SIMD vector.
    Vector128,
    /// 256-bit SIMD vector.
    Vector256,
    /// Boolean.
    Bool,
    /// Unknown type.
    Unknown,
}

impl std::fmt::Display for ArgType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Int8 => write!(f, "i8"),
            Self::Int16 => write!(f, "i16"),
            Self::Int32 => write!(f, "i32"),
            Self::Int64 => write!(f, "i64"),
            Self::Pointer => write!(f, "ptr"),
            Self::Float32 => write!(f, "f32"),
            Self::Float64 => write!(f, "f64"),
            Self::Vector128 => write!(f, "v128"),
            Self::Vector256 => write!(f, "v256"),
            Self::Bool => write!(f, "bool"),
            Self::Unknown => write!(f, "unknown"),
        }
    }
}

impl ArgType {
    /// Size in bytes.
    #[must_use]
    pub const fn size_bytes(&self) -> usize {
        match self {
            Self::Int8 | Self::Bool => 1,
            Self::Int16 => 2,
            Self::Int32 | Self::Float32 => 4,
            Self::Int64 | Self::Float64 | Self::Pointer => 8,
            Self::Vector128 => 16,
            Self::Vector256 => 32,
            Self::Unknown => 0,
        }
    }

    /// Whether this is a floating-point type.
    #[must_use]
    pub const fn is_float(&self) -> bool {
        matches!(self, Self::Float32 | Self::Float64 | Self::Vector128 | Self::Vector256)
    }

    /// Whether this type is passed in an integer register.
    #[must_use]
    pub const fn uses_int_reg(&self) -> bool {
        matches!(self, Self::Int8 | Self::Int16 | Self::Int32 | Self::Int64 | Self::Pointer | Self::Bool)
    }
}

// ─── Argument passing mechanism ───────────────────────────────────────────────

/// How an argument is passed to the function.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PassingMechanism {
    /// Passed in an integer/pointer register.
    Register { name: String },
    /// Passed in a floating-point/SIMD register.
    FpRegister { name: String },
    /// Passed on the stack at a given offset from SP.
    Stack { offset: i32 },
    /// Returned via hidden pointer (large struct).
    HiddenPointer { register: String },
}

impl std::fmt::Display for PassingMechanism {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Register { name } => write!(f, "reg:{name}"),
            Self::FpRegister { name } => write!(f, "fpreg:{name}"),
            Self::Stack { offset } => write!(f, "stack+{offset}"),
            Self::HiddenPointer { register } => write!(f, "hidden_ptr:{register}"),
        }
    }
}

// ─── Argument description ─────────────────────────────────────────────────────

/// A single inferred argument at a call site.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Argument {
    /// Parameter index (0-based).
    pub index: usize,
    /// Inferred type.
    pub arg_type: ArgType,
    /// How the argument is passed.
    pub mechanism: PassingMechanism,
    /// Whether this argument was definitely observed being set.
    pub definitely_used: bool,
    /// The symbolic value (e.g., register name or immediate) when known.
    pub value_hint: Option<String>,
    /// Confidence in the inferred type (0..1).
    pub type_confidence: f32,
}

impl Argument {
    /// Create a new argument with unknown type.
    #[must_use]
    pub const fn new(index: usize, mechanism: PassingMechanism) -> Self {
        Self {
            index,
            arg_type: ArgType::Unknown,
            mechanism,
            definitely_used: false,
            value_hint: None,
            type_confidence: 0.5,
        }
    }

    /// Builder: set type.
    #[must_use]
    pub const fn with_type(mut self, ty: ArgType, confidence: f32) -> Self {
        self.arg_type = ty;
        self.type_confidence = confidence;
        self
    }

    /// Builder: set definite use.
    #[must_use]
    pub const fn definitely_used(mut self) -> Self {
        self.definitely_used = true;
        self
    }

    /// Builder: set value hint.
    #[must_use]
    pub fn with_hint(mut self, hint: impl Into<String>) -> Self {
        self.value_hint = Some(hint.into());
        self
    }
}

// ─── Data-flow value ──────────────────────────────────────────────────────────

/// A simplified data-flow value for argument tracking.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DataFlowValue {
    /// Concrete constant.
    Constant(i64),
    /// Register value at function entry (argument).
    EntryReg(String),
    /// Stack slot value.
    StackSlot(i32),
    /// Result of a call.
    CallResult(u64),
    /// Known pointer.
    Pointer(u64),
    /// Unknown / joined value.
    Top,
    /// Bottom (undefined).
    Bottom,
}

impl DataFlowValue {
    /// Returns `true` if this value could be a pointer.
    #[must_use]
    pub const fn may_be_pointer(&self) -> bool {
        matches!(self, Self::Pointer(_) | Self::EntryReg(_) | Self::Top)
    }

    /// Returns `true` if this value is definitely a constant.
    #[must_use]
    pub const fn is_constant(&self) -> bool {
        matches!(self, Self::Constant(_))
    }
}

// ─── Data-flow state ──────────────────────────────────────────────────────────

/// Register/memory state for one point in a data-flow analysis.
#[derive(Debug, Clone, Default)]
pub struct DataFlowState {
    pub regs: FxHashMap<String, DataFlowValue>,
    pub stack: FxHashMap<i32, DataFlowValue>,
    pub defined_regs: HashSet<String>,
}

impl DataFlowState {
    /// Create an initial state where all entry registers are argument candidates.
    #[must_use]
    pub fn entry(arg_regs: &[&str]) -> Self {
        let mut regs = FxHashMap::default();
        for &r in arg_regs {
            regs.insert(r.to_string(), DataFlowValue::EntryReg(r.to_string()));
        }
        Self {
            regs,
            stack: FxHashMap::default(),
            defined_regs: HashSet::new(),
        }
    }

    /// Get the value of a register.
    #[must_use]
    pub fn get_reg(&self, name: &str) -> &DataFlowValue {
        self.regs.get(name).unwrap_or(&DataFlowValue::Bottom)
    }

    /// Set the value of a register.
    pub fn set_reg(&mut self, name: impl Into<String>, val: DataFlowValue) {
        let n = name.into();
        self.defined_regs.insert(n.clone());
        self.regs.insert(n, val);
    }

    /// Read from a stack slot.
    #[must_use]
    pub fn get_stack(&self, offset: i32) -> &DataFlowValue {
        self.stack.get(&offset).unwrap_or(&DataFlowValue::Bottom)
    }

    /// Write to a stack slot.
    pub fn set_stack(&mut self, offset: i32, val: DataFlowValue) {
        self.stack.insert(offset, val);
    }

    /// Whether `reg` has been explicitly defined (written to after entry).
    #[must_use]
    pub fn is_defined(&self, reg: &str) -> bool {
        self.defined_regs.contains(reg)
    }
}

// ─── Call-site instruction model ─────────────────────────────────────────────

/// A simplified instruction for call-site analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallSiteInstrExt {
    pub address: u64,
    pub kind: CsInstrKind,
}

/// Kind of call-site instruction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CsInstrKind {
    /// MOV reg, value
    MovRegImm { dst: String, imm: i64 },
    /// MOV reg, reg
    MovRegReg { dst: String, src: String },
    /// MOV [rsp+off], reg (stack store)
    MovStackReg { offset: i32, src: String },
    /// MOV reg, [rsp+off] (stack load)
    MovRegStack { dst: String, offset: i32 },
    /// LEA reg, [rip+off] (pointer load)
    Lea { dst: String, offset: i64 },
    /// PUSH reg
    Push { reg: String },
    /// A CALL instruction
    Call { target: Option<u64> },
    /// XOR reg, reg (zeroing)
    Xor { dst: String, src: String },
    /// Any other write to register
    RegWrite { reg: String },
    /// Any other instruction
    Other,
}

// ─── ArgumentTracker ──────────────────────────────────────────────────────────

/// Tracks arguments being set up at a call site using forward data-flow.
pub struct ArgumentTracker {
    pub cc: CallingConventionPattern,
    pub arch_bits: u32,
}

impl ArgumentTracker {
    /// Create a tracker for a given calling convention.
    #[must_use]
    pub const fn new(cc: CallingConventionPattern, arch_bits: u32) -> Self {
        Self { cc, arch_bits }
    }

    /// Analyze a window of instructions before a CALL and return the inferred argument list.
    #[must_use]
    pub fn analyze_call_site(&self, pre_call_instrs: &[CallSiteInstrExt]) -> CallSiteArguments {
        let arg_regs: Vec<&str> = self.cc.arg_registers.iter().map(String::as_str).collect();
        let fp_regs: Vec<&str> = self.cc.fp_arg_registers.iter().map(String::as_str).collect();
        let mut state = DataFlowState::entry(&arg_regs);
        let mut stack_args: FxHashMap<i32, DataFlowValue> = FxHashMap::default();
        let mut set_regs: Vec<String> = Vec::new();
        let mut set_fp_regs: Vec<String> = Vec::new();

        for instr in pre_call_instrs {
            match &instr.kind {
                CsInstrKind::MovRegImm { dst, imm } => {
                    state.set_reg(dst.clone(), DataFlowValue::Constant(*imm));
                    if arg_regs.contains(&dst.as_str()) && !set_regs.contains(dst) {
                        set_regs.push(dst.clone());
                    }
                    if fp_regs.contains(&dst.as_str()) && !set_fp_regs.contains(dst) {
                        set_fp_regs.push(dst.clone());
                    }
                }
                CsInstrKind::MovRegReg { dst, src } => {
                    let val = state.get_reg(src).clone();
                    state.set_reg(dst.clone(), val);
                    if arg_regs.contains(&dst.as_str()) && !set_regs.contains(dst) {
                        set_regs.push(dst.clone());
                    }
                }
                CsInstrKind::Lea { dst, offset } => {
                    state.set_reg(dst.clone(), DataFlowValue::Pointer(*offset as u64));
                    if arg_regs.contains(&dst.as_str()) && !set_regs.contains(dst) {
                        set_regs.push(dst.clone());
                    }
                }
                CsInstrKind::MovStackReg { offset, src } => {
                    let val = state.get_reg(src).clone();
                    stack_args.insert(*offset, val);
                }
                CsInstrKind::MovRegStack { dst, offset } => {
                    let val = state.get_stack(*offset).clone();
                    state.set_reg(dst.clone(), val);
                }
                CsInstrKind::Push { reg } => {
                    // For cdecl/stdcall, pushes are stack arguments in reverse.
                    // `stack_args.len()` is adversarially controlled (an
                    // arbitrarily long pre-call instruction window can push
                    // an unbounded number of slots): converting it to `i32`
                    // and then negating/multiplying with plain arithmetic can
                    // overflow (e.g. `i32::MIN` has no positive negation) and
                    // panic in debug builds / silently wrap in release. Use
                    // saturating arithmetic throughout so a malformed/huge
                    // instruction stream degrades to a clamped offset instead
                    // of panicking or wrapping to a bogus (possibly positive)
                    // slot.
                    let val = state.get_reg(reg).clone();
                    let sp_offset = push_slot_offset(stack_args.len(), self.arch_bits);
                    stack_args.insert(sp_offset, val);
                }
                CsInstrKind::Xor { dst, src } if dst == src => {
                    state.set_reg(dst.clone(), DataFlowValue::Constant(0));
                    if arg_regs.contains(&dst.as_str()) && !set_regs.contains(dst) {
                        set_regs.push(dst.clone());
                    }
                }
                CsInstrKind::RegWrite { reg } => {
                    state.set_reg(reg.clone(), DataFlowValue::Top);
                    if arg_regs.contains(&reg.as_str()) && !set_regs.contains(reg) {
                        set_regs.push(reg.clone());
                    }
                }
                CsInstrKind::Call { .. } => break,
                CsInstrKind::Xor { .. } | CsInstrKind::Other => {}
            }
        }

        self.build_argument_list(&set_regs, &set_fp_regs, &stack_args, &state)
    }

    fn build_argument_list(
        &self,
        set_regs: &[String],
        set_fp_regs: &[String],
        stack_args: &FxHashMap<i32, DataFlowValue>,
        state: &DataFlowState,
    ) -> CallSiteArguments {
        let mut args: Vec<Argument> = Vec::new();
        let mut idx = 0usize;

        // Register arguments. `idx` is the register's position in the
        // calling convention's argument-register order (not a counter over
        // only the registers actually observed as set) so that a gap — e.g.
        // an unused leading register in optimized code — does not shift
        // later parameters' reported positions.
        for (pos, reg) in self.cc.arg_registers.iter().enumerate() {
            if set_regs.contains(reg) {
                let val = state.get_reg(reg);
                let (ty, conf) = self.infer_type_from_value(val, false);
                args.push(
                    Argument::new(pos, PassingMechanism::Register { name: reg.clone() })
                        .with_type(ty, conf)
                        .definitely_used()
                        .with_hint(format_value(val)),
                );
                idx = idx.max(pos + 1);
            }
        }

        // FP register arguments
        for (pos, reg) in self.cc.fp_arg_registers.iter().enumerate() {
            if set_fp_regs.contains(reg) {
                args.push(
                    Argument::new(pos, PassingMechanism::FpRegister { name: reg.clone() })
                        .with_type(ArgType::Float64, 0.7)
                        .definitely_used(),
                );
                idx = idx.max(pos + 1);
            }
        }

        // Stack arguments (sorted by offset)
        let mut stack_sorted: Vec<(i32, &DataFlowValue)> = stack_args.iter().map(|(k, v)| (*k, v)).collect();
        stack_sorted.sort_by_key(|(off, _)| *off);
        for (off, val) in &stack_sorted {
            let (ty, conf) = self.infer_type_from_value(val, false);
            args.push(
                Argument::new(idx, PassingMechanism::Stack { offset: *off })
                    .with_type(ty, conf)
                    .definitely_used()
                    .with_hint(format_value(val)),
            );
            idx += 1;
        }

        CallSiteArguments {
            arguments: args,
            total_count: idx,
            register_count: set_regs.len() + set_fp_regs.len(),
            stack_count: stack_sorted.len(),
            has_variadic_hint: false,
        }
    }

    const fn infer_type_from_value(&self, val: &DataFlowValue, is_fp: bool) -> (ArgType, f32) {
        if is_fp {
            return (ArgType::Float64, 0.7);
        }
        match val {
            DataFlowValue::Constant(c) => {
                if *c == 0 || *c == 1 {
                    (ArgType::Bool, 0.6)
                } else if *c >= i32::MIN as i64 && *c <= i32::MAX as i64 {
                    (ArgType::Int32, 0.7)
                } else {
                    (ArgType::Int64, 0.7)
                }
            }
            DataFlowValue::Pointer(_) => (ArgType::Pointer, 0.9),
            DataFlowValue::EntryReg(_) => (ArgType::Unknown, 0.3),
            DataFlowValue::CallResult(_) => (ArgType::Int64, 0.5),
            DataFlowValue::Top | DataFlowValue::Bottom => (ArgType::Unknown, 0.3),
            DataFlowValue::StackSlot(_) => (ArgType::Pointer, 0.6),
        }
    }
}

/// Compute the (negative) stack-pointer offset for the `slot_index`-th
/// (0-based) `Push` seen before a call, for an architecture with the given
/// pointer width in bits.
///
/// `slot_index` (`stack_args.len()` at the time of the push) is
/// adversarially controlled — an arbitrarily long pre-call instruction
/// window can push an unbounded number of slots — so this uses saturating
/// arithmetic throughout. Plain `i32` arithmetic (`-(len as i32 + 1) *
/// stride`) can overflow once `slot_index` approaches `i32::MAX` (`i32::MIN`
/// has no positive negation), panicking in debug builds and silently
/// wrapping to a bogus, possibly non-negative, offset in release.
const fn push_slot_offset(slot_index: usize, arch_bits: u32) -> i32 {
    let stride = arch_bits as i32 / 8;
    let slot = if slot_index > i32::MAX as usize { i32::MAX } else { slot_index as i32 };
    slot.saturating_add(1).saturating_mul(stride).saturating_neg()
}

fn format_value(val: &DataFlowValue) -> String {
    match val {
        DataFlowValue::Constant(c) => format!("0x{c:x}"),
        DataFlowValue::Pointer(p) => format!("ptr:0x{p:x}"),
        DataFlowValue::EntryReg(r) => format!("arg:{r}"),
        DataFlowValue::CallResult(a) => format!("ret@0x{a:x}"),
        DataFlowValue::StackSlot(o) => format!("stack+{o}"),
        DataFlowValue::Top => "?".into(),
        DataFlowValue::Bottom => "undef".into(),
    }
}

/// Arguments inferred at a call site.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallSiteArguments {
    pub arguments: Vec<Argument>,
    pub total_count: usize,
    pub register_count: usize,
    pub stack_count: usize,
    pub has_variadic_hint: bool,
}

impl CallSiteArguments {
    /// All arguments passed in registers.
    #[must_use]
    pub fn register_args(&self) -> Vec<&Argument> {
        self.arguments
            .iter()
            .filter(|a| matches!(a.mechanism, PassingMechanism::Register { .. } | PassingMechanism::FpRegister { .. }))
            .collect()
    }

    /// All arguments passed on the stack.
    #[must_use]
    pub fn stack_args(&self) -> Vec<&Argument> {
        self.arguments
            .iter()
            .filter(|a| matches!(a.mechanism, PassingMechanism::Stack { .. }))
            .collect()
    }

    /// Return the C-like signature string.
    #[must_use]
    pub fn signature_str(&self) -> String {
        let params: Vec<String> = self.arguments
            .iter()
            .map(|a| format!("{}: {}", a.mechanism, a.arg_type))
            .collect();
        format!("fn({})", params.join(", "))
    }
}

// ─── BulkArgumentTracker ──────────────────────────────────────────────────────

/// Tracks arguments for multiple call sites in a function.
pub struct BulkArgumentTracker {
    pub tracker: ArgumentTracker,
}

impl BulkArgumentTracker {
    /// Create with the given calling convention.
    #[must_use]
    pub const fn new(cc: CallingConventionPattern, arch_bits: u32) -> Self {
        Self {
            tracker: ArgumentTracker::new(cc, arch_bits),
        }
    }

    /// Analyze all call sites in a function body.
    ///
    /// `call_sites` is a list of `(call_address, pre_call_instructions)`.
    #[must_use]
    pub fn analyze_all(
        &self,
        call_sites: &[(u64, Vec<CallSiteInstrExt>)],
    ) -> Vec<(u64, CallSiteArguments)> {
        call_sites
            .iter()
            .map(|(addr, instrs)| (*addr, self.tracker.analyze_call_site(instrs)))
            .collect()
    }

    /// Infer the maximum arity across all call sites.
    #[must_use]
    pub fn max_arity(results: &[(u64, CallSiteArguments)]) -> usize {
        results.iter().map(|(_, a)| a.total_count).max().unwrap_or(0)
    }

    /// Aggregate argument types across all call sites (majority vote per position).
    #[must_use]
    pub fn aggregate_types(results: &[(u64, CallSiteArguments)]) -> Vec<ArgType> {
        let max = Self::max_arity(results);
        let mut type_votes: Vec<FxHashMap<String, usize>> = vec![FxHashMap::default(); max];
        for (_, args) in results {
            for (i, arg) in args.arguments.iter().enumerate() {
                if i < max {
                    *type_votes[i].entry(arg.arg_type.to_string()).or_insert(0) += 1;
                }
            }
        }
        type_votes
            .into_iter()
            .map(|votes| {
                // `votes` is a HashMap; break count ties by string key so the
                // winner is reproducible across runs regardless of hash order.
                let best = votes
                    .into_iter()
                    .max_by(|(ta, ca), (tb, cb)| ca.cmp(cb).then_with(|| tb.cmp(ta)))
                    .map(|(t, _)| t);
                match best.as_deref() {
                    Some("i32") => ArgType::Int32,
                    Some("i64") => ArgType::Int64,
                    Some("ptr") => ArgType::Pointer,
                    Some("f32") => ArgType::Float32,
                    Some("f64") => ArgType::Float64,
                    Some("bool") => ArgType::Bool,
                    _ => ArgType::Unknown,
                }
            })
            .collect()
    }
}

// ─── Type inference from register usage ──────────────────────────────────────

/// Infer argument types from instruction patterns within a function.
pub struct RegUsageTypeInferrer {
    pub arch_bits: u32,
}

impl RegUsageTypeInferrer {
    /// Create a new inferrer.
    #[must_use]
    pub const fn new(arch_bits: u32) -> Self {
        Self { arch_bits }
    }

    /// Infer the type of value in `reg` based on how it is used within `instrs`.
    #[must_use]
    pub fn infer_type(&self, reg: &str, instrs: &[CallSiteInstrExt]) -> ArgType {
        let mut votes: FxHashMap<ArgType, usize> = FxHashMap::default();
        for instr in instrs {
            match &instr.kind {
                // If the register is used in an XOR with itself → likely zeroed int
                CsInstrKind::Xor { dst, src } if dst == reg && src == reg => {
                    *votes.entry(ArgType::Bool).or_insert(0) += 1;
                }
                // If stored to a FP reg, it may be a float parameter
                CsInstrKind::MovRegReg { dst, src } if src == reg => {
                    if dst.starts_with("xmm") || dst.starts_with("ymm") {
                        *votes.entry(ArgType::Float64).or_insert(0) += 2;
                    }
                }
                // If loaded from memory into this reg, likely a pointer load result
                CsInstrKind::MovRegStack { dst, .. } if dst == reg => {
                    *votes.entry(ArgType::Pointer).or_insert(0) += 1;
                }
                // If LEA sets this reg, it's a pointer
                CsInstrKind::Lea { dst, .. } if dst == reg => {
                    *votes.entry(ArgType::Pointer).or_insert(0) += 3;
                }
                CsInstrKind::MovRegImm { .. }
                | CsInstrKind::MovRegReg { .. }
                | CsInstrKind::MovStackReg { .. }
                | CsInstrKind::MovRegStack { .. }
                | CsInstrKind::Lea { .. }
                | CsInstrKind::Push { .. }
                | CsInstrKind::Call { .. }
                | CsInstrKind::Xor { .. }
                | CsInstrKind::RegWrite { .. }
                | CsInstrKind::Other => {}
            }
        }
        // `votes` is a HashMap; break count ties by `ArgType`'s (derived) Ord so
        // the winner is reproducible across runs regardless of hash order.
        votes
            .into_iter()
            .max_by(|(ta, ca), (tb, cb)| ca.cmp(cb).then_with(|| tb.cmp(ta)))
            .map_or(if self.arch_bits == 64 { ArgType::Int64 } else { ArgType::Int32 }, |(t, _)| t)
    }
}

// ─── Forward data-flow engine ─────────────────────────────────────────────────

/// A simple forward data-flow engine that propagates values across a basic block.
pub struct ForwardDataFlow {
    pub state: DataFlowState,
}

impl ForwardDataFlow {
    /// Create a new engine with the given initial state.
    #[must_use]
    pub const fn new(initial: DataFlowState) -> Self {
        Self { state: initial }
    }

    /// Process one instruction and update state.
    pub fn process(&mut self, instr: &CallSiteInstrExt) {
        match &instr.kind {
            CsInstrKind::MovRegImm { dst, imm } => {
                self.state.set_reg(dst.clone(), DataFlowValue::Constant(*imm));
            }
            CsInstrKind::MovRegReg { dst, src } => {
                let val = self.state.get_reg(src).clone();
                self.state.set_reg(dst.clone(), val);
            }
            CsInstrKind::Lea { dst, offset } => {
                self.state.set_reg(dst.clone(), DataFlowValue::Pointer(*offset as u64));
            }
            CsInstrKind::MovStackReg { offset, src } => {
                let val = self.state.get_reg(src).clone();
                self.state.set_stack(*offset, val);
            }
            CsInstrKind::MovRegStack { dst, offset } => {
                let val = self.state.get_stack(*offset).clone();
                self.state.set_reg(dst.clone(), val);
            }
            CsInstrKind::Xor { dst, src } if dst == src => {
                self.state.set_reg(dst.clone(), DataFlowValue::Constant(0));
            }
            CsInstrKind::RegWrite { reg } => {
                self.state.set_reg(reg.clone(), DataFlowValue::Top);
            }
            CsInstrKind::Push { reg } => {
                let val = self.state.get_reg(reg).clone();
                self.state.set_stack(-8, val); // approximate
            }
            CsInstrKind::Xor { .. }
            | CsInstrKind::Call { .. }
            | CsInstrKind::Other => {}
        }
    }

    /// Process a sequence of instructions.
    pub fn process_block(&mut self, instrs: &[CallSiteInstrExt]) {
        let mut queue: VecDeque<&CallSiteInstrExt> = instrs.iter().collect();
        while let Some(instr) = queue.pop_front() {
            if matches!(instr.kind, CsInstrKind::Call { .. }) {
                break;
            }
            self.process(instr);
        }
    }

    /// Return all argument registers that have been set.
    #[must_use]
    pub fn active_arg_regs(&self, cc: &CallingConventionPattern) -> Vec<(String, DataFlowValue)> {
        cc.arg_registers
            .iter()
            .filter_map(|r| {
                let val = self.state.get_reg(r);
                if val == &DataFlowValue::Bottom {
                    None
                } else {
                    Some((r.clone(), val.clone()))
                }
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sysv_x64;

    fn make_sysv_cc() -> CallingConventionPattern {
        sysv_x64()
    }

    #[test]
    fn test_arg_tracker_basic() {
        let cc = make_sysv_cc();
        let tracker = ArgumentTracker::new(cc, 64);
        let instrs = vec![
            CallSiteInstrExt { address: 0x1000, kind: CsInstrKind::MovRegImm { dst: "rdi".into(), imm: 0x42 } },
            CallSiteInstrExt { address: 0x1007, kind: CsInstrKind::MovRegImm { dst: "rsi".into(), imm: 0x100 } },
            CallSiteInstrExt { address: 0x100e, kind: CsInstrKind::Call { target: Some(0x2000) } },
        ];
        let result = tracker.analyze_call_site(&instrs);
        assert_eq!(result.register_count, 2);
        assert_eq!(result.total_count, 2);
    }

    #[test]
    fn test_arg_tracker_register_gap_preserves_position() {
        // Only rsi (the SysV position-1 arg register) is set; rdi (position 0)
        // is never written. The reported `param_index` for rsi must still be
        // 1, not 0 — otherwise callers would mislabel it as the first
        // parameter.
        let cc = make_sysv_cc();
        let tracker = ArgumentTracker::new(cc, 64);
        let instrs = vec![
            CallSiteInstrExt { address: 0x1000, kind: CsInstrKind::MovRegImm { dst: "rsi".into(), imm: 0x100 } },
            CallSiteInstrExt { address: 0x1007, kind: CsInstrKind::Call { target: Some(0x2000) } },
        ];
        let result = tracker.analyze_call_site(&instrs);
        assert_eq!(result.arguments.len(), 1);
        assert_eq!(result.arguments[0].index, 1);
        match &result.arguments[0].mechanism {
            PassingMechanism::Register { name } => assert_eq!(name, "rsi"),
            other => panic!("expected register mechanism, got {other:?}"),
        }
    }

    #[test]
    fn test_arg_tracker_stack() {
        let cc = crate::cdecl_x86();
        let tracker = ArgumentTracker::new(cc, 32);
        let instrs = vec![
            CallSiteInstrExt { address: 0x1000, kind: CsInstrKind::Push { reg: "eax".into() } },
            CallSiteInstrExt { address: 0x1001, kind: CsInstrKind::Call { target: Some(0x2000) } },
        ];
        let result = tracker.analyze_call_site(&instrs);
        assert!(result.total_count >= 1);
    }

    /// Regression test: `push_slot_offset` used to compute the stack slot
    /// offset with plain `i32` arithmetic (`-(len as i32 + 1) * stride`),
    /// which overflows once `slot_index` approaches (or exceeds) `i32::MAX`
    /// — panicking in debug builds (`i32::MIN` has no positive negation,
    /// and the multiply/add/negate can overflow) and silently wrapping to a
    /// bogus, possibly non-negative, offset in release. With adversarially
    /// large slot indices this must not panic and must stay non-positive.
    #[test]
    fn test_push_slot_offset_saturates_instead_of_overflowing() {
        // Values around and beyond i32::MAX that a plain `as i32 + 1` /
        // multiply would previously wrap or overflow on.
        for slot_index in [
            0usize,
            1,
            i32::MAX as usize - 1,
            i32::MAX as usize,
            i32::MAX as usize + 1,
            usize::MAX,
        ] {
            let off32 = push_slot_offset(slot_index, 32);
            let off64 = push_slot_offset(slot_index, 64);
            assert!(off32 <= 0, "32-bit offset must stay non-positive, got {off32}");
            assert!(off64 <= 0, "64-bit offset must stay non-positive, got {off64}");
        }
    }

    #[test]
    fn test_push_slot_offset_normal_case() {
        // Ordinary small cases should still compute the exact expected
        // offset (first push at index 0 -> one slot below SP).
        assert_eq!(push_slot_offset(0, 32), -4);
        assert_eq!(push_slot_offset(1, 32), -8);
        assert_eq!(push_slot_offset(0, 64), -8);
    }

    #[test]
    fn test_dataflow_constant() {
        let state = DataFlowState::default();
        let mut flow = ForwardDataFlow::new(state);
        let instrs = vec![
            CallSiteInstrExt { address: 0, kind: CsInstrKind::MovRegImm { dst: "rdi".into(), imm: 42 } },
        ];
        flow.process_block(&instrs);
        assert_eq!(flow.state.get_reg("rdi"), &DataFlowValue::Constant(42));
    }

    #[test]
    fn test_dataflow_propagation() {
        let state = DataFlowState::default();
        let mut flow = ForwardDataFlow::new(state);
        let instrs = vec![
            CallSiteInstrExt { address: 0, kind: CsInstrKind::MovRegImm { dst: "rdi".into(), imm: 99 } },
            CallSiteInstrExt { address: 4, kind: CsInstrKind::MovRegReg { dst: "rsi".into(), src: "rdi".into() } },
        ];
        flow.process_block(&instrs);
        assert_eq!(flow.state.get_reg("rsi"), &DataFlowValue::Constant(99));
    }

    #[test]
    fn test_signature_str() {
        let args = CallSiteArguments {
            arguments: vec![
                Argument::new(0, PassingMechanism::Register { name: "rdi".into() })
                    .with_type(ArgType::Int64, 0.8),
                Argument::new(1, PassingMechanism::Register { name: "rsi".into() })
                    .with_type(ArgType::Pointer, 0.9),
            ],
            total_count: 2,
            register_count: 2,
            stack_count: 0,
            has_variadic_hint: false,
        };
        let sig = args.signature_str();
        assert!(sig.contains("i64"));
        assert!(sig.contains("ptr"));
    }

    /// Regression test: `aggregate_types`' majority vote used to resolve a
    /// tied vote count via `HashMap`/`FxHashMap` iteration order, which is
    /// nondeterministic across runs. With an exact tie between two type
    /// strings at one argument position, the outcome must be stable.
    #[test]
    fn aggregate_types_is_deterministic_on_tie() {
        let make = |ty: ArgType| CallSiteArguments {
            arguments: vec![Argument::new(0, PassingMechanism::Register { name: "rdi".into() })
                .with_type(ty, 0.5)],
            total_count: 1,
            register_count: 1,
            stack_count: 0,
            has_variadic_hint: false,
        };
        // Exactly one vote each for i32 and ptr at position 0: a genuine tie.
        let results: Vec<(u64, CallSiteArguments)> =
            vec![(0, make(ArgType::Int32)), (1, make(ArgType::Pointer))];
        let first = BulkArgumentTracker::aggregate_types(&results);
        for _ in 0..20 {
            assert_eq!(BulkArgumentTracker::aggregate_types(&results), first);
        }
    }

    /// Regression test: `RegUsageTypeInferrer::infer_type`'s vote tally has
    /// the same tie-break hazard as `aggregate_types`.
    #[test]
    fn infer_type_is_deterministic_on_tie() {
        // One vote for Bool (xor self,self) and one vote for Pointer
        // (mov reg, [stack]) — an exact tie in vote weight.
        let instrs = vec![
            CallSiteInstrExt {
                address: 0,
                kind: CsInstrKind::Xor { dst: "rax".into(), src: "rax".into() },
            },
            CallSiteInstrExt {
                address: 4,
                kind: CsInstrKind::MovRegStack { dst: "rax".into(), offset: -8 },
            },
        ];
        let inferrer = RegUsageTypeInferrer::new(64);
        let first = inferrer.infer_type("rax", &instrs);
        for _ in 0..20 {
            assert_eq!(inferrer.infer_type("rax", &instrs), first);
        }
    }

    // ─── Property-based / randomized regression tests ─────────────────────────
    //
    // No proptest dependency is pulled in by this crate, so these use a small
    // deterministic xorshift PRNG (seeded, reproducible on failure) to explore
    // many pseudo-random instruction streams per invariant.

    use crate::test_prng::Xorshift64;

    /// Property: for any call site the tracker analyzes, the `index` values of
    /// arguments passed via *integer* registers must be injective (no two
    /// distinct register arguments claim the same parameter slot) — a
    /// collision would mean two real parameters get silently merged into one
    /// slot in the recovered signature. Explored over many randomly generated
    /// subsets/orders of `MovRegImm` writes to the `SysV` integer-arg registers.
    #[test]
    fn prop_register_arg_indices_are_injective() {
        let arg_regs = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"];
        let mut rng = Xorshift64::new(0xC0FFEE);

        for trial in 0..200u64 {
            let cc = sysv_x64();
            let tracker = ArgumentTracker::new(cc, 64);

            // Pick a random non-empty subset of the arg registers and a
            // random order to write them in.
            let mut chosen: Vec<&str> = arg_regs
                .iter()
                .copied()
                .filter(|_| rng.next_range(2) == 0)
                .collect();
            if chosen.is_empty() {
                chosen.push(arg_regs[rng.next_range(arg_regs.len())]);
            }
            // Fisher-Yates shuffle using the deterministic RNG.
            for i in (1..chosen.len()).rev() {
                let j = rng.next_range(i + 1);
                chosen.swap(i, j);
            }

            let mut instrs: Vec<CallSiteInstrExt> = chosen
                .iter()
                .enumerate()
                .map(|(n, reg)| CallSiteInstrExt {
                    address: n as u64 * 4,
                    kind: CsInstrKind::MovRegImm { dst: (*reg).into(), imm: n as i64 + 1 },
                })
                .collect();
            instrs.push(CallSiteInstrExt {
                address: instrs.len() as u64 * 4,
                kind: CsInstrKind::Call { target: Some(0x1000) },
            });

            let result = tracker.analyze_call_site(&instrs);
            let reg_indices: Vec<usize> = result
                .arguments
                .iter()
                .filter(|a| matches!(a.mechanism, PassingMechanism::Register { .. }))
                .map(|a| a.index)
                .collect();

            let mut seen = std::collections::HashSet::new();
            for idx in &reg_indices {
                assert!(
                    seen.insert(*idx),
                    "trial {trial}: duplicate argument index {idx} for chosen regs {chosen:?} (indices: {reg_indices:?})"
                );
            }
        }
    }

    /// Property: the *set* of recovered register arguments (register name ->
    /// param index) for a call site is invariant under permutation of the
    /// order in which the (non-overwriting) `MovRegImm` writes appear in the
    /// pre-call instruction window. Argument-slot assignment is driven by the
    /// calling convention's fixed register ordering, not by program order, so
    /// shuffling independent register writes must not change the outcome.
    #[test]
    fn prop_register_classification_stable_under_permutation() {
        let arg_regs = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"];
        let mut rng = Xorshift64::new(0x5EED_1234);

        for trial in 0..200u64 {
            let mut chosen: Vec<&str> = arg_regs
                .iter()
                .copied()
                .filter(|_| rng.next_range(2) == 0)
                .collect();
            if chosen.is_empty() {
                chosen.push(arg_regs[rng.next_range(arg_regs.len())]);
            }

            let base_result = {
                let cc = sysv_x64();
                let tracker = ArgumentTracker::new(cc, 64);
                let mut instrs: Vec<CallSiteInstrExt> = chosen
                    .iter()
                    .enumerate()
                    .map(|(n, reg)| CallSiteInstrExt {
                        address: n as u64 * 4,
                        kind: CsInstrKind::MovRegImm { dst: (*reg).into(), imm: n as i64 + 1 },
                    })
                    .collect();
                instrs.push(CallSiteInstrExt {
                    address: instrs.len() as u64 * 4,
                    kind: CsInstrKind::Call { target: Some(0x2000) },
                });
                tracker.analyze_call_site(&instrs)
            };
            let mut base_pairs: Vec<(String, usize)> = base_result
                .arguments
                .iter()
                .filter_map(|a| match &a.mechanism {
                    PassingMechanism::Register { name } => Some((name.clone(), a.index)),
                    _ => None,
                })
                .collect();
            base_pairs.sort();

            // Shuffle the write order and re-run; each register is written
            // exactly once so permuting is order-only, not value-changing.
            let mut shuffled = chosen.clone();
            for i in (1..shuffled.len()).rev() {
                let j = rng.next_range(i + 1);
                shuffled.swap(i, j);
            }

            let permuted_result = {
                let cc = sysv_x64();
                let tracker = ArgumentTracker::new(cc, 64);
                let mut instrs: Vec<CallSiteInstrExt> = shuffled
                    .iter()
                    .enumerate()
                    .map(|(n, reg)| CallSiteInstrExt {
                        address: n as u64 * 4,
                        kind: CsInstrKind::MovRegImm { dst: (*reg).into(), imm: n as i64 + 1 },
                    })
                    .collect();
                instrs.push(CallSiteInstrExt {
                    address: instrs.len() as u64 * 4,
                    kind: CsInstrKind::Call { target: Some(0x2000) },
                });
                tracker.analyze_call_site(&instrs)
            };
            let mut permuted_pairs: Vec<(String, usize)> = permuted_result
                .arguments
                .iter()
                .filter_map(|a| match &a.mechanism {
                    PassingMechanism::Register { name } => Some((name.clone(), a.index)),
                    _ => None,
                })
                .collect();
            permuted_pairs.sort();

            assert_eq!(
                base_pairs, permuted_pairs,
                "trial {trial}: register->index assignment changed under permutation; chosen={chosen:?} shuffled={shuffled:?}"
            );
            assert_eq!(base_result.register_count, permuted_result.register_count);
            assert_eq!(base_result.total_count, permuted_result.total_count);
        }
    }

    /// Property: `push_slot_offset` is strictly monotonically decreasing
    /// (non-increasing under saturation) as `slot_index` grows, for a fixed
    /// architecture width — later pushes must never be assigned a stack
    /// offset that is `>=` an earlier push's offset, which would alias two
    /// distinct stack arguments onto (or reorder them past) the same slot.
    /// Explored over many random `(slot_index, arch_bits)` pairs including
    /// adversarially large indices.
    #[test]
    fn prop_push_slot_offset_monotonic() {
        let mut rng = Xorshift64::new(0xABCD_EF01);

        for trial in 0..200u64 {
            let arch_bits = if rng.next_range(2) == 0 { 32 } else { 64 };
            let base = rng.next_range(1_000_000);
            let a = base;
            let b = base + 1 + rng.next_range(1_000_000);
            debug_assert!(a < b);

            let off_a = push_slot_offset(a, arch_bits);
            let off_b = push_slot_offset(b, arch_bits);
            assert!(
                off_b <= off_a,
                "trial {trial}: push_slot_offset not monotonic for arch_bits={arch_bits}: index {a} -> {off_a}, index {b} -> {off_b}"
            );
        }
    }
}
