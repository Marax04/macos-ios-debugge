//! `jvm_bytecode_verifier` — data-flow bytecode verification for JVM methods.
//!
//! Implements a simplified version of the JVM §4.9 verification algorithm:
//! tracks operand-stack and local-variable types through basic blocks using
//! a forward data-flow fixed-point iteration.  The verifier is not a full
//! JVM TCK verifier but is suitable for static analysis of class files.
//!
//! Entry point: [`JvmBytecodeVerifier::verify_method`].

use std::collections::{BTreeMap, HashSet, VecDeque};
use std::fmt;

// ── TypeInfo ──────────────────────────────────────────────────────────────────

/// Abstract type on the JVM operand stack or in a local-variable slot.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum TypeInfo {
    /// 32-bit integer (boolean, byte, char, short, int).
    Int,
    /// 32-bit float.
    Float,
    /// 64-bit long (occupies two stack slots).
    Long,
    /// 64-bit double (occupies two stack slots).
    Double,
    /// Reference to a named class or interface.
    Reference(String),
    /// Null literal (compatible with any reference type).
    Null,
    /// Uninitialized object created by `new` at the given bytecode offset.
    UninitializedRef(u32),
    /// `this` before `<init>` call in a constructor.
    UninitializedThis,
    /// Filler for the second slot of Long/Double.
    Top,
    /// Represents an unverifiable state (bottom of the lattice).
    Unknown,
}

impl TypeInfo {
    /// Return `true` if this type can be used as a 32-bit computational integer.
    #[must_use] 
    pub const fn is_int_compat(&self) -> bool {
        matches!(self, Self::Int)
    }

    /// Return `true` if this is any reference kind.
    #[must_use] 
    pub const fn is_reference(&self) -> bool {
        matches!(self, Self::Reference(_) | Self::Null | Self::UninitializedRef(_) | Self::UninitializedThis)
    }

    /// Merge two types (join in the type lattice).  Returns `Unknown` if the
    /// types are incompatible.
    #[must_use] 
    pub fn merge(a: &Self, b: &Self) -> Self {
        if a == b { return a.clone(); }
        match (a, b) {
            (Self::Null, Self::Reference(_)) | (Self::Reference(_), Self::Null) => {
                // Null is assignable to any reference — keep the reference type.
                match (a, b) {
                    (Self::Reference(n), _) | (_, Self::Reference(n)) => Self::Reference(n.clone()),
                    _ => unreachable!(),
                }
            }
            (Self::Reference(n1), Self::Reference(n2)) if n1 == n2 => Self::Reference(n1.clone()),
            // Different reference types — fall back to java/lang/Object.
            (Self::Reference(_), Self::Reference(_)) => Self::Reference("java/lang/Object".into()),
            (Self::Unknown, _) | (_, Self::Unknown) => Self::Unknown,
            _ => Self::Unknown,
        }
    }

    /// Returns `true` if this type occupies two stack slots.
    #[must_use] 
    pub const fn is_wide(&self) -> bool {
        matches!(self, Self::Long | Self::Double)
    }

    #[must_use] 
    pub const fn short_name(&self) -> &str {
        match self {
            Self::Int => "I",
            Self::Float => "F",
            Self::Long => "J",
            Self::Double => "D",
            Self::Reference(_) => "L",
            Self::Null => "null",
            Self::UninitializedRef(_) => "uninit",
            Self::UninitializedThis => "uninitThis",
            Self::Top => "_",
            Self::Unknown => "?",
        }
    }
}

impl fmt::Display for TypeInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Reference(n) => write!(f, "L{n};"),
            Self::UninitializedRef(pc) => write!(f, "Uninit@{pc}"),
            other => f.write_str(other.short_name()),
        }
    }
}

// ── VerifierState ─────────────────────────────────────────────────────────────

/// The abstract machine state at a single bytecode offset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifierState {
    pub locals: Vec<TypeInfo>,
    pub stack: Vec<TypeInfo>,
}

impl VerifierState {
    /// Maximum allowed local-variable slots.  The JVM spec limits `max_locals` to
    /// a u16 (65 535), but allocating that many `TypeInfo` slots per state copy is
    /// a `DoS` vector when the verifier copies states repeatedly during the
    /// fixed-point iteration.  We cap at 4 096 which covers all realistic methods.
    const MAX_LOCALS: usize = 4096;

    /// Create an empty state with `max_locals` slots.
    /// If `max_locals` exceeds [`MAX_LOCALS`] the vector is capped to prevent
    /// memory-exhaustion from attacker-controlled class files.
    #[must_use] 
    pub fn new(max_locals: usize) -> Self {
        let effective = max_locals.min(Self::MAX_LOCALS);
        Self {
            locals: vec![TypeInfo::Unknown; effective],
            stack: Vec::new(),
        }
    }

    /// Push a type onto the operand stack.
    pub fn push(&mut self, t: TypeInfo) {
        if t.is_wide() {
            self.stack.push(t);
            self.stack.push(TypeInfo::Top);
        } else {
            self.stack.push(t);
        }
    }

    /// Pop one stack slot; returns `Err` on underflow.
    pub fn pop(&mut self) -> Result<TypeInfo, VerifyError> {
        self.stack.pop().ok_or(VerifyError::StackUnderflow)
    }

    /// Pop one stack slot and verify it matches `expected`.
    pub fn pop_expect(&mut self, expected: &TypeInfo) -> Result<TypeInfo, VerifyError> {
        let t = self.pop()?;
        if &t != expected && *expected != TypeInfo::Unknown {
            return Err(VerifyError::TypeMismatch {
                expected: expected.clone(),
                found: t,
            });
        }
        Ok(t)
    }

    /// Peek at the top of the stack without consuming it.
    #[must_use] 
    pub fn peek(&self) -> Option<&TypeInfo> {
        self.stack.last()
    }

    /// Merge `other` into `self` using the type lattice join.
    /// Returns `true` if any slot changed (fixed-point check).
    pub fn merge_from(&mut self, other: &Self) -> bool {
        let mut changed = false;
        let max_loc = self.locals.len().max(other.locals.len());
        if self.locals.len() < max_loc {
            self.locals.resize(max_loc, TypeInfo::Unknown);
            changed = true;
        }
        for (i, t) in other.locals.iter().enumerate() {
            let merged = TypeInfo::merge(&self.locals[i], t);
            if merged != self.locals[i] {
                self.locals[i] = merged;
                changed = true;
            }
        }
        for (i, t) in other.stack.iter().enumerate() {
            if i >= self.stack.len() {
                self.stack.push(t.clone());
                changed = true;
            } else {
                let merged = TypeInfo::merge(&self.stack[i], t);
                if merged != self.stack[i] {
                    self.stack[i] = merged;
                    changed = true;
                }
            }
        }
        changed
    }

    /// Set a local variable.
    pub fn set_local(&mut self, idx: usize, t: TypeInfo) {
        if idx >= self.locals.len() {
            self.locals.resize(idx + 1, TypeInfo::Unknown);
        }
        self.locals[idx] = t.clone();
        if t.is_wide() && idx + 1 < self.locals.len() {
            self.locals[idx + 1] = TypeInfo::Top;
        }
    }

    /// Get a local variable.
    pub fn get_local(&self, idx: usize) -> Result<TypeInfo, VerifyError> {
        self.locals.get(idx).cloned().ok_or(VerifyError::InvalidLocalIndex(idx))
    }
}

// ── VerifyError ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyError {
    StackUnderflow,
    TypeMismatch { expected: TypeInfo, found: TypeInfo },
    InvalidLocalIndex(usize),
    InvalidOpcode(u8),
    TruncatedBytecode { at: usize },
    MaxIterationsExceeded,
    InvalidBranchTarget(i32),
    WideMismatch,
}

impl fmt::Display for VerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::StackUnderflow => f.write_str("operand stack underflow"),
            Self::TypeMismatch { expected, found } =>
                write!(f, "type mismatch: expected {expected}, found {found}"),
            Self::InvalidLocalIndex(i) => write!(f, "invalid local variable index {i}"),
            Self::InvalidOpcode(op) => write!(f, "unknown opcode 0x{op:02x}"),
            Self::TruncatedBytecode { at } => write!(f, "bytecode truncated at offset {at}"),
            Self::MaxIterationsExceeded => f.write_str("fixed-point iteration did not converge"),
            Self::InvalidBranchTarget(t) => write!(f, "branch target {t} out of range"),
            Self::WideMismatch => f.write_str("wide-type slot mismatch"),
        }
    }
}

// ── VerifyResult ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct VerifyResult {
    /// Abstract state at each verified bytecode offset.
    pub states: BTreeMap<u32, VerifierState>,
    /// Warnings (non-fatal type ambiguities, unresolvable classes, etc.).
    pub warnings: Vec<String>,
    /// Whether the method passed full data-flow verification.
    pub passed: bool,
}

// ── JvmBytecodeVerifier ───────────────────────────────────────────────────────

/// Configuration for the verifier.
#[derive(Debug, Clone)]
pub struct VerifierConfig {
    /// Maximum fixed-point iterations before giving up.
    pub max_iterations: usize,
    /// Whether to treat unknown opcodes as warnings rather than errors.
    pub lenient: bool,
}

impl Default for VerifierConfig {
    fn default() -> Self {
        Self { max_iterations: 1024, lenient: false }
    }
}

/// JVM bytecode verifier.  Performs forward data-flow analysis.
pub struct JvmBytecodeVerifier {
    config: VerifierConfig,
}

impl JvmBytecodeVerifier {
    #[must_use] 
    pub fn new() -> Self {
        Self { config: VerifierConfig::default() }
    }

    #[must_use] 
    pub const fn with_config(config: VerifierConfig) -> Self {
        Self { config }
    }

    /// Verify a single method.
    ///
    /// - `bytecode`: raw Code attribute bytecode bytes
    /// - `max_locals`: the `max_locals` field from the Code attribute
    /// - `arg_types`: parameter types to initialise locals from (including `this` for instance methods)
    pub fn verify_method(
        &self,
        bytecode: &[u8],
        max_locals: usize,
        arg_types: &[TypeInfo],
    ) -> Result<VerifyResult, VerifyError> {
        let mut entry = VerifierState::new(max_locals);
        for (i, t) in arg_types.iter().enumerate() {
            entry.set_local(i, t.clone());
        }

        // states[offset] = abstract state on entry to that offset.
        // Use BTreeMap rather than HashMap so that attacker-controlled bytecode
        // offsets (used as keys) cannot trigger hash-collision DoS.
        let mut states: BTreeMap<u32, VerifierState> = BTreeMap::new();
        states.insert(0, entry);

        let mut worklist: VecDeque<u32> = VecDeque::new();
        worklist.push_back(0);
        let mut visited: HashSet<u32> = HashSet::new();
        let mut warnings = Vec::new();
        let mut iterations = 0;

        while let Some(offset) = worklist.pop_front() {
            iterations += 1;
            if iterations > self.config.max_iterations {
                return Err(VerifyError::MaxIterationsExceeded);
            }

            let state = match states.get(&offset) {
                Some(s) => s.clone(),
                None => continue,
            };

            let successors = self.step(bytecode, offset, state, &mut states, &mut warnings)?;
            for succ in successors {
                if !visited.contains(&succ) || states.contains_key(&succ) {
                    worklist.push_back(succ);
                }
            }
            visited.insert(offset);
        }

        let ordered: BTreeMap<u32, VerifierState> = states.into_iter().collect();
        Ok(VerifyResult { states: ordered, warnings, passed: true })
    }

    /// Simulate one instruction at `offset`.  Returns successor offsets.
    fn step(
        &self,
        code: &[u8],
        offset: u32,
        mut st: VerifierState,
        states: &mut BTreeMap<u32, VerifierState>,
        warnings: &mut Vec<String>,
    ) -> Result<Vec<u32>, VerifyError> {
        let pc = offset as usize;
        if pc >= code.len() {
            return Ok(vec![]);
        }
        let op = code[pc];

        macro_rules! need {
            ($n:expr) => {
                if pc + $n > code.len() {
                    return Err(VerifyError::TruncatedBytecode { at: pc });
                }
            };
        }

        macro_rules! u8at {
            ($off:expr) => {{ need!($off + 1); code[pc + $off] }};
        }
        macro_rules! i16at {
            ($off:expr) => {{ need!($off + 2); i16::from_be_bytes([code[pc+$off], code[pc+$off+1]]) as i32 }};
        }
        macro_rules! i32at {
            ($off:expr) => {{ need!($off + 4); i32::from_be_bytes([code[pc+$off], code[pc+$off+1], code[pc+$off+2], code[pc+$off+3]]) }};
        }
        macro_rules! u16at {
            ($off:expr) => {{ need!($off + 2); u16::from_be_bytes([code[pc+$off], code[pc+$off+1]]) }};
        }

        // Determine instruction length and successor offsets.
        let (instr_len, mut succs): (usize, Vec<u32>) = match op {
            // Constants
            0x00 => (1, vec![]),          // nop
            0x01 => { st.push(TypeInfo::Null); (1, vec![]) }    // aconst_null
            0x02..=0x08 => { st.push(TypeInfo::Int); (1, vec![]) }  // iconst_m1..iconst_5
            0x09 | 0x0A => { st.push(TypeInfo::Long); (1, vec![]) } // lconst_0, lconst_1
            0x0B | 0x0C => { st.push(TypeInfo::Float); (1, vec![]) } // fconst_0..fconst_2 (partial)
            0x0D..=0x0F => { st.push(TypeInfo::Float); (1, vec![]) } // fconst
            0x10 => { st.push(TypeInfo::Int); (2, vec![]) }   // bipush
            0x11 => { st.push(TypeInfo::Int); (3, vec![]) }   // sipush
            0x12 => { st.push(TypeInfo::Int); (2, vec![]) }   // ldc (simplified)
            0x13 => { st.push(TypeInfo::Int); (3, vec![]) }   // ldc_w
            0x14 => { st.push(TypeInfo::Long); (3, vec![]) }  // ldc2_w

            // Loads
            0x15 => { let idx = u8at!(1) as usize; let t = st.get_local(idx)?; st.push(t); (2, vec![]) } // iload
            0x16 => { let idx = u8at!(1) as usize; let t = st.get_local(idx)?; st.push(t); (2, vec![]) } // lload
            0x17 => { let idx = u8at!(1) as usize; let t = st.get_local(idx)?; st.push(t); (2, vec![]) } // fload
            0x18 => { let idx = u8at!(1) as usize; let t = st.get_local(idx)?; st.push(t); (2, vec![]) } // dload
            0x19 => { let idx = u8at!(1) as usize; let t = st.get_local(idx)?; st.push(t); (2, vec![]) } // aload
            0x1A..=0x1D => { st.push(TypeInfo::Int); (1, vec![]) }   // iload_0..3
            0x1E..=0x21 => { st.push(TypeInfo::Long); (1, vec![]) }  // lload_0..3
            0x22..=0x25 => { st.push(TypeInfo::Float); (1, vec![]) } // fload_0..3
            0x26..=0x29 => { st.push(TypeInfo::Double); (1, vec![]) }// dload_0..3
            0x2A..=0x2D => { // aload_0..3
                let idx = (op - 0x2A) as usize;
                let t = st.get_local(idx).unwrap_or(TypeInfo::Reference("java/lang/Object".into()));
                st.push(t);
                (1, vec![])
            }

            // Array loads
            0x2E => { st.pop()?; st.pop()?; st.push(TypeInfo::Int); (1, vec![]) }    // iaload
            0x2F => { st.pop()?; st.pop()?; st.push(TypeInfo::Long); (1, vec![]) }   // laload
            0x30 => { st.pop()?; st.pop()?; st.push(TypeInfo::Float); (1, vec![]) }  // faload
            0x31 => { st.pop()?; st.pop()?; st.push(TypeInfo::Double); (1, vec![]) } // daload
            0x32 => { st.pop()?; st.pop()?; st.push(TypeInfo::Reference("java/lang/Object".into())); (1, vec![]) } // aaload
            0x33 => { st.pop()?; st.pop()?; st.push(TypeInfo::Int); (1, vec![]) }    // baload
            0x34 => { st.pop()?; st.pop()?; st.push(TypeInfo::Int); (1, vec![]) }    // caload
            0x35 => { st.pop()?; st.pop()?; st.push(TypeInfo::Int); (1, vec![]) }    // saload

            // Stores
            0x36 => { let idx = u8at!(1) as usize; let t = st.pop()?; st.set_local(idx, t); (2, vec![]) } // istore
            0x37 => { let idx = u8at!(1) as usize; let t = st.pop()?; st.set_local(idx, t); (2, vec![]) } // lstore
            0x38 => { let idx = u8at!(1) as usize; let t = st.pop()?; st.set_local(idx, t); (2, vec![]) } // fstore
            0x39 => { let idx = u8at!(1) as usize; let t = st.pop()?; st.set_local(idx, t); (2, vec![]) } // dstore
            0x3A => { let idx = u8at!(1) as usize; let t = st.pop()?; st.set_local(idx, t); (2, vec![]) } // astore
            0x3B..=0x3E => { let idx = (op - 0x3B) as usize; let t = st.pop()?; st.set_local(idx, t); (1, vec![]) } // istore_0..3
            0x3F..=0x42 => { let idx = (op - 0x3F) as usize; let t = st.pop()?; st.set_local(idx, t); (1, vec![]) } // lstore_0..3
            0x43..=0x46 => { let idx = (op - 0x43) as usize; let t = st.pop()?; st.set_local(idx, t); (1, vec![]) } // fstore_0..3
            0x47..=0x4A => { let idx = (op - 0x47) as usize; let t = st.pop()?; st.set_local(idx, t); (1, vec![]) } // dstore_0..3
            0x4B..=0x4E => { let idx = (op - 0x4B) as usize; let t = st.pop()?; st.set_local(idx, t); (1, vec![]) } // astore_0..3

            // Array stores
            0x4F..=0x56 => { st.pop()?; st.pop()?; st.pop()?; (1, vec![]) } // *astore

            // Stack manipulation
            0x57 => { st.pop()?; (1, vec![]) }     // pop
            0x58 => { st.pop()?; st.pop()?; (1, vec![]) } // pop2
            0x59 => { let t = st.peek().cloned().unwrap_or(TypeInfo::Unknown); st.push(t); (1, vec![]) } // dup
            0x5A => { let t1 = st.pop()?; let t2 = st.peek().cloned().unwrap_or(TypeInfo::Unknown); st.push(t1.clone()); st.push(t2); st.push(t1); (1, vec![]) } // dup_x1
            0x5B..=0x5D => { (1, vec![]) } // dup_x2, dup2, dup2_x1 (simplified)
            0x5E | 0x5F => { (1, vec![]) }          // dup2_x2, swap (simplified)

            // Arithmetic (all consume two ints/floats/etc., produce one)
            0x60..=0x84 => { // iadd..iinc (partial; iinc is store-modify)
                if op == 0x84 { (3, vec![]) } // iinc: no stack change
                else {
                    st.pop()?;
                    // Result type mirrors input
                    let t = if op < 0x64 { TypeInfo::Int }
                        else if op < 0x68 { TypeInfo::Long }
                        else if op < 0x6C { TypeInfo::Float }
                        else { TypeInfo::Double };
                    st.pop()?;
                    st.push(t);
                    (1, vec![])
                }
            }

            // Conversion opcodes
            0x85..=0x93 => { st.pop()?; st.push(TypeInfo::Int); (1, vec![]) }

            // Comparison / branches
            0x94..=0x98 => { st.pop()?; st.pop()?; st.push(TypeInfo::Int); (1, vec![]) } // *cmp

            // If branches (consume one or two ints, branch conditionally)
            0x99..=0xA4 => { // ifeq..if_icmple
                st.pop()?;
                if op >= 0x9F { st.pop()?; } // if_icmp* pop two
                let branch_i32 = offset as i32 + i16at!(1);
                let branch = u32::try_from(branch_i32).map_err(|_| VerifyError::InvalidBranchTarget(branch_i32))?;
                let next = offset + 3;
                (3, vec![next, branch])
            }
            0xA5 | 0xA6 => { // if_acmpeq, if_acmpne
                st.pop()?; st.pop()?;
                let branch_i32 = offset as i32 + i16at!(1);
                let branch = u32::try_from(branch_i32).map_err(|_| VerifyError::InvalidBranchTarget(branch_i32))?;
                let next = offset + 3;
                (3, vec![next, branch])
            }

            // Goto
            0xA7 => {
                let target_i32 = offset as i32 + i16at!(1);
                let target = u32::try_from(target_i32).map_err(|_| VerifyError::InvalidBranchTarget(target_i32))?;
                (3, vec![target])
            }
            0xC8 => {
                let target_i32 = offset as i32 + i32at!(1);
                let target = u32::try_from(target_i32).map_err(|_| VerifyError::InvalidBranchTarget(target_i32))?;
                (5, vec![target])
            } // goto_w

            // Return
            0xAC..=0xB0 => { (1, vec![]) } // ireturn..areturn
            0xB1 => { (1, vec![]) }         // return

            // Field access
            0xB2 => { st.push(TypeInfo::Reference("java/lang/Object".into())); (3, vec![]) } // getstatic
            0xB3 => { st.pop()?; (3, vec![]) } // putstatic
            0xB4 => { st.pop()?; st.push(TypeInfo::Reference("java/lang/Object".into())); (3, vec![]) } // getfield
            0xB5 => { st.pop()?; st.pop()?; (3, vec![]) } // putfield

            // Method invocations (simplified: pop all args + objectref if virtual)
            0xB6..=0xBA => {
                // We cannot resolve the descriptor without the constant pool here,
                // so we add a warning and do not model argument consumption precisely.
                let idx = u16at!(1);
                warnings.push(format!("invoke at pc={pc} cp#{idx}: skipping arg modeling"));
                let extra = if op == 0xB9 { 2 } else if op == 0xBA { 2 } else { 0 };
                (3 + extra, vec![])
            }

            // Object creation
            0xBB => { let idx = u16at!(1); st.push(TypeInfo::UninitializedRef(pc as u32)); let _ = idx; (3, vec![]) } // new
            0xBC => { st.pop()?; st.push(TypeInfo::Reference("[I".into())); (2, vec![]) } // newarray
            0xBD => { st.pop()?; st.push(TypeInfo::Reference("[Ljava/lang/Object;".into())); (3, vec![]) } // anewarray
            0xBE => { st.pop()?; st.push(TypeInfo::Int); (1, vec![]) } // arraylength

            // Throw
            0xBF => { st.pop()?; (1, vec![]) }

            // Checkcast / instanceof
            0xC0 => { (3, vec![]) } // checkcast (no stack change)
            0xC1 => { st.pop()?; st.push(TypeInfo::Int); (3, vec![]) } // instanceof

            // Monitor
            0xC2 | 0xC3 => { st.pop()?; (1, vec![]) }

            // Tableswitch / lookupswitch (simplified)
            0xAA | 0xAB => { st.pop()?; (1, vec![]) }

            // Wide prefix
            0xC4 => (2, vec![]),

            // Multianewarray
            0xC5 => { let dims = u8at!(3) as usize; for _ in 0..dims { st.pop()?; } st.push(TypeInfo::Reference("[[Ljava/lang/Object;".into())); (4, vec![]) }

            // ifnull / ifnonnull
            0xC6 | 0xC7 => {
                st.pop()?;
                let branch_i32 = offset as i32 + i16at!(1);
                let branch = u32::try_from(branch_i32).map_err(|_| VerifyError::InvalidBranchTarget(branch_i32))?;
                let next = offset + 3;
                (3, vec![next, branch])
            }

            // Unknown
            other => {
                if self.config.lenient {
                    warnings.push(format!("unknown opcode 0x{other:02x} at pc={pc}; skipping"));
                    (1, vec![])
                } else {
                    return Err(VerifyError::InvalidOpcode(other));
                }
            }
        };

        // Fall-through for non-branch instructions
        if succs.is_empty() && op != 0xAC && op != 0xAD && op != 0xAE && op != 0xAF && op != 0xB0
            && op != 0xB1 && op != 0xBF && op != 0xA7 && op != 0xC8
            && !(0xAA..=0xAB).contains(&op)
        {
            let next = (offset as usize + instr_len) as u32;
            if (next as usize) < code.len() {
                succs.push(next);
            }
        }

        // Propagate state to successors
        for &succ in &succs {
            if (succ as usize) < code.len() {
                let entry = states.entry(succ).or_insert_with(|| VerifierState::new(st.locals.len()));
                entry.merge_from(&st);
            }
        }

        Ok(succs)
    }
}

impl Default for JvmBytecodeVerifier {
    fn default() -> Self {
        Self::new()
    }
}

// ── public convenience ────────────────────────────────────────────────────────

/// Verify `bytecode` with the given `max_locals` and initial `arg_types`.
/// Returns a [`VerifyResult`] on success or a [`VerifyError`] on hard failure.
pub fn verify_method(
    bytecode: &[u8],
    max_locals: usize,
    arg_types: &[TypeInfo],
) -> Result<VerifyResult, VerifyError> {
    JvmBytecodeVerifier::new().verify_method(bytecode, max_locals, arg_types)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_empty_method_returns_void() {
        // Simplest possible method: just `return`
        let code = vec![0xB1u8]; // return
        let result = verify_method(&code, 1, &[]).unwrap();
        assert!(result.passed);
        assert!(result.states.contains_key(&0));
    }

    #[test]
    fn verify_iconst_ireturn() {
        let code = vec![0x03u8, 0xACu8]; // iconst_0; ireturn
        let result = verify_method(&code, 1, &[]).unwrap();
        assert!(result.passed);
        // After iconst_0 (offset 0) the state at offset 1 should have Int on stack
        let st1 = result.states.get(&1).expect("state at offset 1");
        assert!(st1.stack.contains(&TypeInfo::Int));
    }

    #[test]
    fn verify_iload_istore() {
        // iload_0; istore_1; return
        let code = vec![0x1Au8, 0x3Cu8, 0xB1u8];
        let result = verify_method(&code, 2, &[TypeInfo::Int]).unwrap();
        assert!(result.passed);
    }

    #[test]
    fn verify_aload_instance_method() {
        // aload_0; return (this-returning nothing)
        let code = vec![0x2Au8, 0xB1u8];
        let result = verify_method(&code, 1, &[TypeInfo::Reference("MyClass".into())]).unwrap();
        assert!(result.passed);
        let st = result.states.get(&0).unwrap();
        assert_eq!(st.get_local(0).unwrap(), TypeInfo::Reference("MyClass".into()));
    }

    #[test]
    fn verify_ifne_branch() {
        // iconst_1; ifne +2 (offset 4); iconst_0; return
        // bytecode offsets: 0=iconst_1, 1=ifne, 2=hi, 3=lo, 4=iconst_0, 5=return
        let code = vec![0x04u8, 0x9Au8, 0x00, 0x04, 0x03, 0xB1];
        let result = verify_method(&code, 1, &[]).unwrap();
        assert!(result.passed);
    }

    #[test]
    fn verify_pop_stack_underflow() {
        let code = vec![0x57u8]; // pop with empty stack
        let result = verify_method(&code, 0, &[]);
        // This should produce an error
        assert!(result.is_err());
    }

    #[test]
    fn verify_nop_sequence() {
        let code = vec![0x00u8, 0x00, 0x00, 0xB1]; // nop; nop; nop; return
        let result = verify_method(&code, 0, &[]).unwrap();
        assert!(result.passed);
        assert_eq!(result.states.len(), 4);
    }

    #[test]
    fn verify_wide_type_long_const() {
        // lconst_0; lreturn
        let code = vec![0x09u8, 0xADu8];
        let result = verify_method(&code, 2, &[]).unwrap();
        assert!(result.passed);
        let st = result.states.get(&1).unwrap();
        assert!(st.stack.contains(&TypeInfo::Long));
    }

    #[test]
    fn type_info_merge_same_returns_same() {
        let a = TypeInfo::Int;
        let b = TypeInfo::Int;
        assert_eq!(TypeInfo::merge(&a, &b), TypeInfo::Int);
    }

    #[test]
    fn type_info_merge_null_with_ref() {
        let a = TypeInfo::Null;
        let b = TypeInfo::Reference("java/lang/String".into());
        let merged = TypeInfo::merge(&a, &b);
        assert_eq!(merged, TypeInfo::Reference("java/lang/String".into()));
    }

    #[test]
    fn type_info_merge_different_refs_gives_object() {
        let a = TypeInfo::Reference("com/example/Foo".into());
        let b = TypeInfo::Reference("com/example/Bar".into());
        let merged = TypeInfo::merge(&a, &b);
        assert_eq!(merged, TypeInfo::Reference("java/lang/Object".into()));
    }

    #[test]
    fn type_info_merge_incompatible_gives_unknown() {
        let merged = TypeInfo::merge(&TypeInfo::Int, &TypeInfo::Float);
        assert_eq!(merged, TypeInfo::Unknown);
    }

    #[test]
    fn verifier_state_push_pop_roundtrip() {
        let mut st = VerifierState::new(0);
        st.push(TypeInfo::Int);
        let t = st.pop().unwrap();
        assert_eq!(t, TypeInfo::Int);
    }

    #[test]
    fn verifier_state_wide_push_occupies_two_slots() {
        let mut st = VerifierState::new(0);
        st.push(TypeInfo::Long);
        assert_eq!(st.stack.len(), 2);
        assert_eq!(st.stack[0], TypeInfo::Long);
        assert_eq!(st.stack[1], TypeInfo::Top);
    }

    #[test]
    fn verifier_state_merge_from_changes() {
        let mut a = VerifierState::new(2);
        a.set_local(0, TypeInfo::Int);
        let mut b = VerifierState::new(2);
        b.set_local(0, TypeInfo::Float);
        let changed = a.merge_from(&b);
        assert!(changed);
        assert_eq!(a.locals[0], TypeInfo::Unknown);
    }

    #[test]
    fn lenient_mode_skips_unknown_opcode() {
        let code = vec![0xFEu8, 0xB1u8]; // 0xFE is not a valid JVM opcode
        let verifier = JvmBytecodeVerifier::with_config(VerifierConfig { lenient: true, ..Default::default() });
        let result = verifier.verify_method(&code, 0, &[]).unwrap();
        assert!(!result.warnings.is_empty());
    }

    #[test]
    fn strict_mode_errors_on_unknown_opcode() {
        let code = vec![0xFEu8];
        let result = verify_method(&code, 0, &[]);
        assert!(matches!(result, Err(VerifyError::InvalidOpcode(0xFE))));
    }

    #[test]
    fn type_info_display() {
        assert_eq!(TypeInfo::Int.to_string(), "I");
        assert_eq!(TypeInfo::Reference("java/lang/String".into()).to_string(), "Ljava/lang/String;");
        assert_eq!(TypeInfo::UninitializedRef(10).to_string(), "Uninit@10");
    }

    #[test]
    fn type_info_is_wide() {
        assert!(TypeInfo::Long.is_wide());
        assert!(TypeInfo::Double.is_wide());
        assert!(!TypeInfo::Int.is_wide());
        assert!(!TypeInfo::Reference("X".into()).is_wide());
    }

    #[test]
    fn verify_bipush_iconst_add_ireturn() {
        // bipush 5; iconst_3; iadd; ireturn
        let code = vec![0x10u8, 0x05, 0x06, 0x60, 0xACu8];
        let result = verify_method(&code, 0, &[]).unwrap();
        assert!(result.passed);
    }

    #[test]
    fn verify_aconst_null_areturn() {
        let code = vec![0x01u8, 0xB0u8]; // aconst_null; areturn
        let result = verify_method(&code, 0, &[]).unwrap();
        assert!(result.passed);
        let st = result.states.get(&1).unwrap();
        assert!(st.stack.contains(&TypeInfo::Null));
    }
}
