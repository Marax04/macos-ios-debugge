//! CIL abstract execution / symbolic evaluation engine.
//!
//! Implements a stack-based interpreter for ECMA-335 CIL bytecode.
//! Handles all common opcodes: arithmetic, bitwise, comparison, branching,
//! locals, arguments, and conversions.  Designed for taint tracking and
//! abstract value analysis rather than true managed runtime execution.

use std::collections::HashSet;

// ── Value types ───────────────────────────────────────────────────────────────

/// Abstract value on the CIL evaluation stack.
#[derive(Debug, Clone, PartialEq)]
pub enum CilValue {
    /// 32-bit signed integer (covers I1/U1/I2/U2/I4/U4 after stack normalization).
    I32(i32),
    /// 64-bit signed integer (I8/U8).
    I64(i64),
    /// 64-bit float (R4 and R8 both widen to F64 on stack).
    F64(f64),
    /// Native integer (platform pointer-sized).
    NativeInt(i64),
    /// Unmanaged pointer (raw address).
    Ptr(u64),
    /// Managed object reference (GC address).
    Obj(u64),
    /// Null reference.
    Null,
    /// Value whose precise representation is unknown (e.g., from external call).
    Unknown,
}

impl CilValue {
    #[must_use]
    pub fn is_zero(&self) -> bool {
        match self {
            Self::I32(v)       => *v == 0,
            Self::I64(v) | Self::NativeInt(v)       => *v == 0,
            Self::F64(v)       => *v == 0.0,
            Self::Ptr(v)       => *v == 0,
            Self::Null         => true,
            _ => false,
        }
    }

    /// Coerce to i64 for comparison / branch operations.
    #[must_use]
    pub const fn to_i64(&self) -> Option<i64> {
        match self {
            Self::I32(v)       => Some(*v as i64),
            Self::I64(v) | Self::NativeInt(v)       => Some(*v),
            Self::Ptr(v)       => Some(v.cast_signed()),
            Self::Null         => Some(0),
            _ => None,
        }
    }

    /// Coerce to f64 for floating-point operations.
    #[must_use]
    pub const fn to_f64(&self) -> Option<f64> {
        match self {
            Self::F64(v)  => Some(*v),
            Self::I32(v)  => Some(*v as f64),
            Self::I64(v)  => Some(*v as f64),
            _ => None,
        }
    }

    /// True if this is an Unknown or indeterminate value.
    #[must_use]
    pub const fn is_unknown(&self) -> bool {
        matches!(self, Self::Unknown)
    }
}

// ── Evaluation stack ──────────────────────────────────────────────────────────

/// The CIL evaluation stack.
pub struct EvalStack {
    stack: Vec<CilValue>,
}

impl EvalStack {
    #[must_use]
    pub fn new() -> Self {
        Self { stack: Vec::with_capacity(32) }
    }

    pub fn push(&mut self, v: CilValue) {
        self.stack.push(v);
    }

    pub fn pop(&mut self) -> CilValue {
        self.stack.pop().unwrap_or(CilValue::Unknown)
    }

    #[must_use]
    pub fn peek(&self) -> Option<&CilValue> {
        self.stack.last()
    }

    #[must_use]
    pub const fn depth(&self) -> usize {
        self.stack.len()
    }

    pub fn dup(&mut self) {
        if let Some(top) = self.stack.last().cloned() {
            self.stack.push(top);
        }
    }

    pub fn clear(&mut self) {
        self.stack.clear();
    }
}

impl Default for EvalStack {
    fn default() -> Self { Self::new() }
}

// ── Local variables ───────────────────────────────────────────────────────────

/// Local variable storage for one method invocation.
pub struct LocalVars {
    pub vars: Vec<CilValue>,
}

impl LocalVars {
    #[must_use]
    pub fn new(count: usize) -> Self {
        Self { vars: vec![CilValue::I32(0); count] }
    }

    #[must_use]
    pub fn load(&self, idx: usize) -> CilValue {
        self.vars.get(idx).cloned().unwrap_or(CilValue::Unknown)
    }

    pub fn store(&mut self, idx: usize, val: CilValue) {
        if idx < self.vars.len() {
            self.vars[idx] = val;
        } else {
            while self.vars.len() <= idx {
                self.vars.push(CilValue::Unknown);
            }
            self.vars[idx] = val;
        }
    }
}

// ── Arguments ─────────────────────────────────────────────────────────────────

/// Method argument storage.
pub struct Arguments {
    pub args: Vec<CilValue>,
}

impl Arguments {
    #[must_use]
    pub const fn new(args: Vec<CilValue>) -> Self {
        Self { args }
    }

    #[must_use]
    pub fn load(&self, idx: usize) -> CilValue {
        self.args.get(idx).cloned().unwrap_or(CilValue::Unknown)
    }

    pub fn store(&mut self, idx: usize, val: CilValue) {
        if idx < self.args.len() {
            self.args[idx] = val;
        } else {
            while self.args.len() <= idx {
                self.args.push(CilValue::Unknown);
            }
            self.args[idx] = val;
        }
    }
}

// ── Method call result ────────────────────────────────────────────────────────

/// Result of abstractly executing a method.
#[derive(Debug)]
pub struct MethodCallResult {
    pub returned_value: Option<CilValue>,
    pub exception_possible: bool,
    pub tainted_addresses: Vec<u64>,
}

// ── Execution engine ──────────────────────────────────────────────────────────

/// Abstract CIL execution engine.
pub struct CilExecutionEngine {
    /// Maximum instructions to execute before giving up (prevents infinite loops).
    pub max_steps: usize,
}

impl CilExecutionEngine {
    #[must_use]
    pub const fn new() -> Self {
        Self { max_steps: 100_000 }
    }

    #[must_use]
    pub const fn with_max_steps(max_steps: usize) -> Self {
        Self { max_steps }
    }

    /// Execute a method body abstractly.
    ///
    /// `opcodes` is the raw CIL method body (header stripped).
    /// Returns the top-of-stack value when RET is reached, or None on error.
    pub fn execute_method_abstract(
        &self,
        opcodes: &[u8],
        locals: &mut LocalVars,
        args: &Arguments,
    ) -> Option<CilValue> {
        let mut stack = EvalStack::new();
        let mut pc: usize = 0;
        let mut steps = 0usize;

        while pc < opcodes.len() && steps < self.max_steps {
            steps += 1;
            let op = opcodes[pc];

            match op {
                // ── NOP / BRK ────────────────────────────────────────────
                // nop
                // break (debug breakpoint)

                // ── ldarg short forms ────────────────────────────────────
                0x02 => { stack.push(args.load(0)); pc += 1; }
                0x03 => { stack.push(args.load(1)); pc += 1; }
                0x04 => { stack.push(args.load(2)); pc += 1; }
                0x05 => { stack.push(args.load(3)); pc += 1; }
                0x0E => { // ldarg.s <uint8>
                    let idx = *opcodes.get(pc + 1)? as usize;
                    stack.push(args.load(idx));
                    pc += 2;
                }

                // ── ldloc short forms ────────────────────────────────────
                0x06 => { stack.push(locals.load(0)); pc += 1; }
                0x07 => { stack.push(locals.load(1)); pc += 1; }
                0x08 => { stack.push(locals.load(2)); pc += 1; }
                0x09 => { stack.push(locals.load(3)); pc += 1; }
                0x11 => { // ldloc.s <uint8>
                    let idx = *opcodes.get(pc + 1)? as usize;
                    stack.push(locals.load(idx));
                    pc += 2;
                }

                // ── stloc short forms ────────────────────────────────────
                0x0A => { let v = stack.pop(); locals.store(0, v); pc += 1; }
                0x0B => { let v = stack.pop(); locals.store(1, v); pc += 1; }
                0x0C => { let v = stack.pop(); locals.store(2, v); pc += 1; }
                0x0D => { let v = stack.pop(); locals.store(3, v); pc += 1; }
                0x13 => { // stloc.s <uint8>
                    let idx = *opcodes.get(pc + 1)? as usize;
                    let v = stack.pop();
                    locals.store(idx, v);
                    pc += 2;
                }

                // ── starg.s ──────────────────────────────────────────────
                0x10 => {
                    let _idx = *opcodes.get(pc + 1)? as usize;
                    let _ = stack.pop(); // starg — drop; args are immutable in abstract exec
                    pc += 2;
                }

                // ── ldnull ───────────────────────────────────────────────
                0x14 => { stack.push(CilValue::Null); pc += 1; }

                // ── ldc.i4 short forms ───────────────────────────────────
                0x15 => { stack.push(CilValue::I32(-1)); pc += 1; }
                0x16 => { stack.push(CilValue::I32(0));  pc += 1; }
                0x17 => { stack.push(CilValue::I32(1));  pc += 1; }
                0x18 => { stack.push(CilValue::I32(2));  pc += 1; }
                0x19 => { stack.push(CilValue::I32(3));  pc += 1; }
                0x1A => { stack.push(CilValue::I32(4));  pc += 1; }
                0x1B => { stack.push(CilValue::I32(5));  pc += 1; }
                0x1C => { stack.push(CilValue::I32(6));  pc += 1; }
                0x1D => { stack.push(CilValue::I32(7));  pc += 1; }
                0x1E => { stack.push(CilValue::I32(8));  pc += 1; }

                // ldc.i4.s <int8>
                0x1F => {
                    let v = i32::from((*opcodes.get(pc + 1)?).cast_signed());
                    stack.push(CilValue::I32(v));
                    pc += 2;
                }

                // ldc.i4 <int32>
                0x20 => {
                    if pc + 4 >= opcodes.len() { break; }
                    let bytes = [opcodes[pc+1], opcodes[pc+2], opcodes[pc+3], opcodes[pc+4]];
                    stack.push(CilValue::I32(i32::from_le_bytes(bytes)));
                    pc += 5;
                }

                // ldc.i8 <int64>
                0x21 => {
                    if pc + 8 >= opcodes.len() { break; }
                    let bytes = [
                        opcodes[pc+1], opcodes[pc+2], opcodes[pc+3], opcodes[pc+4],
                        opcodes[pc+5], opcodes[pc+6], opcodes[pc+7], opcodes[pc+8],
                    ];
                    stack.push(CilValue::I64(i64::from_le_bytes(bytes)));
                    pc += 9;
                }

                // ldc.r4 <float32>
                0x22 => {
                    if pc + 4 >= opcodes.len() { break; }
                    let bytes = [opcodes[pc+1], opcodes[pc+2], opcodes[pc+3], opcodes[pc+4]];
                    let f = f64::from(f32::from_le_bytes(bytes));
                    stack.push(CilValue::F64(f));
                    pc += 5;
                }

                // ldc.r8 <float64>
                0x23 => {
                    if pc + 8 >= opcodes.len() { break; }
                    let bytes = [
                        opcodes[pc+1], opcodes[pc+2], opcodes[pc+3], opcodes[pc+4],
                        opcodes[pc+5], opcodes[pc+6], opcodes[pc+7], opcodes[pc+8],
                    ];
                    stack.push(CilValue::F64(f64::from_le_bytes(bytes)));
                    pc += 9;
                }

                // ── dup / pop ────────────────────────────────────────────
                0x25 => { stack.dup(); pc += 1; }
                0x26 => { let _ = stack.pop(); pc += 1; }

                // ── ret ──────────────────────────────────────────────────
                0x2A => {
                    if stack.depth() > 0 {
                        return Some(stack.pop());
                    }
                    return None;
                }

                // ── br (unconditional branch) ────────────────────────────
                0x38 => {
                    if pc + 4 >= opcodes.len() { break; }
                    let off = i32::from_le_bytes([
                        opcodes[pc+1], opcodes[pc+2], opcodes[pc+3], opcodes[pc+4]
                    ]);
                    let next = pc_as_i64(pc + 5) + i64::from(off);
                    let Ok(next) = usize::try_from(next) else { break };
                    if next >= opcodes.len() { break; }
                    pc = next;
                }

                // br.s (short branch)
                0x2B => {
                    let off = i64::from((*opcodes.get(pc + 1)?).cast_signed());
                    let next = pc_as_i64(pc + 2) + off;
                    let Ok(next) = usize::try_from(next) else { break };
                    if next >= opcodes.len() { break; }
                    pc = next;
                }

                // ── conditional branches (short) ──────────────────────────
                0x2C..=0x37 => {
                    let off = i64::from((*opcodes.get(pc + 1)?).cast_signed());
                    let taken_pc = pc_as_i64(pc + 2) + off;
                    let fallthrough = pc + 2;
                    let taken = in_range_pc(taken_pc, opcodes.len());
                    let cond = Self::eval_branch_short(op, &mut stack);
                    pc = if cond == Some(true) {
                        taken.unwrap_or(fallthrough)
                    } else {
                        fallthrough
                    };
                }

                // ── switch (0x45): count + n*4 byte table, pops 1 value ──
                0x45 => {
                    if pc + 4 >= opcodes.len() { break; }
                    let n = u32::from_le_bytes([
                        opcodes[pc+1], opcodes[pc+2], opcodes[pc+3], opcodes[pc+4]
                    ]) as usize;
                    stack.pop();
                    // skip opcode byte + 4-byte count + n*4 offset entries
                    // Use checked arithmetic to prevent integer overflow on large n.
                    let Some(next_pc) = n.checked_mul(4).and_then(|v| v.checked_add(pc + 5))
                    else {
                        break;
                    };
                    if next_pc >= opcodes.len() { break; }
                    pc = next_pc;
                }

                // ── conditional branches (long) ───────────────────────────
                0x39..=0x44 | 0x46 => {
                    if pc + 4 >= opcodes.len() { break; }
                    let off = i64::from(i32::from_le_bytes([
                        opcodes[pc+1], opcodes[pc+2], opcodes[pc+3], opcodes[pc+4]
                    ]));
                    let taken_pc = pc_as_i64(pc + 5) + off;
                    let fallthrough = pc + 5;
                    let taken = in_range_pc(taken_pc, opcodes.len());
                    let cond = self.eval_branch_long(op, &mut stack);
                    pc = if cond == Some(true) {
                        taken.unwrap_or(fallthrough)
                    } else {
                        fallthrough
                    };
                }

                // ── arithmetic ───────────────────────────────────────────
                0x58 => { Self::bin_op_i32(&mut stack, i32::wrapping_add); pc += 1; } // add
                0x59 => { Self::bin_op_i32(&mut stack, i32::wrapping_sub); pc += 1; } // sub
                0x5A => { Self::bin_op_i32(&mut stack, i32::wrapping_mul); pc += 1; } // mul
                0x5B => { // div
                    let b = stack.pop();
                    let a = stack.pop();
                    match (a.to_i64(), b.to_i64()) {
                        (Some(av), Some(bv)) if bv != 0 => stack.push(CilValue::I64(av / bv)),
                        _ => stack.push(CilValue::Unknown),
                    }
                    pc += 1;
                }
                0x5C => { // div.un
                    let b = stack.pop();
                    let a = stack.pop();
                    match (a.to_i64(), b.to_i64()) {
                        (Some(av), Some(bv)) if bv != 0 => {
                            stack.push(CilValue::I64((av.cast_unsigned() / bv.cast_unsigned()).cast_signed()));
                        }
                        _ => stack.push(CilValue::Unknown),
                    }
                    pc += 1;
                }
                0x5D => { // rem
                    let b = stack.pop();
                    let a = stack.pop();
                    match (a.to_i64(), b.to_i64()) {
                        (Some(av), Some(bv)) if bv != 0 => stack.push(CilValue::I64(av % bv)),
                        _ => stack.push(CilValue::Unknown),
                    }
                    pc += 1;
                }
                0x5F => { Self::bin_op_i64(&mut stack, |a, b| a & b); pc += 1; } // and
                0x60 => { Self::bin_op_i64(&mut stack, |a, b| a | b); pc += 1; } // or
                0x61 => { Self::bin_op_i64(&mut stack, |a, b| a ^ b); pc += 1; } // xor
                0x62 => { // shl
                    let b = stack.pop();
                    let a = stack.pop();
                    match (a.to_i64(), b.to_i64()) {
                        (Some(av), Some(bv)) => stack.push(CilValue::I64(av << (bv & 63))),
                        _ => stack.push(CilValue::Unknown),
                    }
                    pc += 1;
                }
                0x63 => { // shr
                    let b = stack.pop();
                    let a = stack.pop();
                    match (a.to_i64(), b.to_i64()) {
                        (Some(av), Some(bv)) => stack.push(CilValue::I64(av >> (bv & 63))),
                        _ => stack.push(CilValue::Unknown),
                    }
                    pc += 1;
                }
                0x65 => { // neg
                    let a = stack.pop();
                    match a.to_i64() {
                        Some(v) => stack.push(CilValue::I64(-v)),
                        None    => stack.push(CilValue::Unknown),
                    }
                    pc += 1;
                }
                0x66 => { // not (bitwise)
                    let a = stack.pop();
                    match a.to_i64() {
                        Some(v) => stack.push(CilValue::I64(!v)),
                        None    => stack.push(CilValue::Unknown),
                    }
                    pc += 1;
                }

                // ── conv variants ─────────────────────────────────────────
                0x67 => { Self::conv_i(&mut stack, |v| i64::from(low_i8(v))); pc += 1; }  // conv.i1
                0x68 => { Self::conv_i(&mut stack, |v| i64::from(low_i16(v))); pc += 1; } // conv.i2
                0x69 => { Self::conv_i(&mut stack, |v| i64::from(low_i32(v))); pc += 1; } // conv.i4
                // conv.i8 (already i64 in abstract)
                0x6B => { // conv.r4
                    let a = stack.pop();
                    let v = f64::from(a.to_f64().unwrap_or(0.0) as f32);
                    stack.push(CilValue::F64(v));
                    pc += 1;
                }
                0x6C => { // conv.r8
                    let a = stack.pop();
                    let v = a.to_f64().unwrap_or(0.0);
                    stack.push(CilValue::F64(v));
                    pc += 1;
                }
                0x6D => { Self::conv_i(&mut stack, |v| i64::from(low_u32(v))); pc += 1; } // conv.u4
                0x6E => { Self::conv_i(&mut stack, |v| v.cast_unsigned().cast_signed()); pc += 1; } // conv.u8

                // ── two-byte prefix opcodes (0xFE) ────────────────────────
                0xFE => {
                    let sub = *opcodes.get(pc + 1)?;
                    match sub {
                        0x01 => { // ceq
                            let b = stack.pop();
                            let a = stack.pop();
                            let eq = match (a.to_i64(), b.to_i64()) {
                                (Some(av), Some(bv)) => av == bv,
                                _ => false,
                            };
                            stack.push(CilValue::I32(i32::from(eq)));
                        }
                        0x02 => { // cgt
                            let b = stack.pop();
                            let a = stack.pop();
                            let r = match (a.to_i64(), b.to_i64()) {
                                (Some(av), Some(bv)) => av > bv,
                                _ => false,
                            };
                            stack.push(CilValue::I32(i32::from(r)));
                        }
                        0x04 => { // clt
                            let b = stack.pop();
                            let a = stack.pop();
                            let r = match (a.to_i64(), b.to_i64()) {
                                (Some(av), Some(bv)) => av < bv,
                                _ => false,
                            };
                            stack.push(CilValue::I32(i32::from(r)));
                        }
                        _ => {
                            // Unknown prefix opcode — push Unknown, skip 2 bytes.
                            stack.push(CilValue::Unknown);
                        }
                    }
                    pc += 2;
                }

                // ── call / callvirt (skip 4-byte token, push Unknown) ─────
                0x28 | 0x6F | 0x73 | 0x72 => {
                    pc += 5;
                    stack.push(CilValue::Unknown);
                }

                // ── newobj (skip 4-byte token, push Unknown) ──────────────
                // ── ldstr (skip 4-byte token, push Unknown) ───────────────
                // ── anything else: advance 1 byte ─────────────────────────
                _ => {
                    pc += 1;
                }
            }
        }

        // Implicit return.
        if stack.depth() > 0 { Some(stack.pop()) } else { None }
    }

    // ── Taint tracking ─────────────────────────────────────────────────────

    /// Execute the method with the specified argument indices marked as tainted.
    /// Returns addresses (Ptr/Obj values) that are reachable from tainted data.
    #[must_use]
    pub fn track_taint(
        &self,
        opcodes: &[u8],
        tainted_args: Vec<usize>,
        arg_count: usize,
    ) -> Vec<u64> {
        let tainted_set: HashSet<usize> = tainted_args.into_iter().collect();
        let args_vec: Vec<CilValue> = (0..arg_count)
            .map(|i| {
                if tainted_set.contains(&i) {
                    CilValue::Ptr(0xDEAD_0000 + i as u64)
                } else {
                    CilValue::I32(0)
                }
            })
            .collect();
        let mut locals = LocalVars::new(16);
        let args = Arguments::new(args_vec);
        let result = self.execute_method_abstract(opcodes, &mut locals, &args);
        let mut addresses = Vec::new();
        if let Some(CilValue::Ptr(addr)) = result
            && addr >= 0xDEAD_0000 {
                addresses.push(addr);
            }
        addresses
    }

    // ── Internal helpers ───────────────────────────────────────────────────

    fn bin_op_i32<F>(stack: &mut EvalStack, f: F)
    where
        F: Fn(i32, i32) -> i32,
    {
        let b = stack.pop();
        let a = stack.pop();
        match (a.to_i64(), b.to_i64()) {
            (Some(av), Some(bv)) => stack.push(CilValue::I32(f(low_i32(av), low_i32(bv)))),
            _ => stack.push(CilValue::Unknown),
        }
    }

    fn bin_op_i64<F>(stack: &mut EvalStack, f: F)
    where
        F: Fn(i64, i64) -> i64,
    {
        let b = stack.pop();
        let a = stack.pop();
        match (a.to_i64(), b.to_i64()) {
            (Some(av), Some(bv)) => stack.push(CilValue::I64(f(av, bv))),
            _ => stack.push(CilValue::Unknown),
        }
    }

    fn conv_i<F>(stack: &mut EvalStack, f: F)
    where
        F: Fn(i64) -> i64,
    {
        let a = stack.pop();
        match a.to_i64() {
            Some(v) => stack.push(CilValue::I64(f(v))),
            None    => stack.push(CilValue::Unknown),
        }
    }

    /// Returns Some(true) if the short branch should be taken, None for unknown.
    fn eval_branch_short(op: u8, stack: &mut EvalStack) -> Option<bool> {
        match op {
            0x2C => { // brfalse.s
                let a = stack.pop();
                Some(a.is_zero())
            }
            0x2D => { // brtrue.s
                let a = stack.pop();
                Some(!a.is_zero())
            }
            0x2E => { // beq.s
                let b = stack.pop(); let a = stack.pop();
                Some(a.to_i64()? == b.to_i64()?)
            }
            0x2F => { // bge.s
                let b = stack.pop(); let a = stack.pop();
                Some(a.to_i64()? >= b.to_i64()?)
            }
            0x30 => { // bgt.s
                let b = stack.pop(); let a = stack.pop();
                Some(a.to_i64()? > b.to_i64()?)
            }
            0x31 => { // ble.s
                let b = stack.pop(); let a = stack.pop();
                Some(a.to_i64()? <= b.to_i64()?)
            }
            0x32 => { // blt.s
                let b = stack.pop(); let a = stack.pop();
                Some(a.to_i64()? < b.to_i64()?)
            }
            0x33 => { // bne.un.s
                let b = stack.pop(); let a = stack.pop();
                Some(a.to_i64()? != b.to_i64()?)
            }
            _ => { stack.pop(); None }
        }
    }

    /// Returns Some(true) if the long branch should be taken.
    fn eval_branch_long(&self, op: u8, stack: &mut EvalStack) -> Option<bool> {
        // Long forms 0x39–0x46 mirror 0x2C–0x37
        let short_op = op - 0x39 + 0x2C;
        Self::eval_branch_short(short_op, stack)
    }
}

impl Default for CilExecutionEngine {
    fn default() -> Self { Self::new() }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

// Width / sign helpers
//
// The CIL `conv.*` opcodes are *defined* to keep the low N bits of the operand
// and reinterpret them at the requested width. Going through `to_le_bytes`
// states that truncation explicitly, so it can never be confused with an
// accidental narrowing introduced by a plain `as`.

/// CIL `conv.i1`: low 8 bits of `v`, reinterpreted as signed.
const fn low_i8(v: i64) -> i8 {
    v.to_le_bytes()[0].cast_signed()
}

/// CIL `conv.i2`: low 16 bits of `v`, reinterpreted as signed.
const fn low_i16(v: i64) -> i16 {
    let b = v.to_le_bytes();
    i16::from_le_bytes([b[0], b[1]])
}

/// CIL `conv.i4`: low 32 bits of `v`, reinterpreted as signed.
const fn low_i32(v: i64) -> i32 {
    let b = v.to_le_bytes();
    i32::from_le_bytes([b[0], b[1], b[2], b[3]])
}

/// CIL `conv.u4`: low 32 bits of `v`, reinterpreted as unsigned.
const fn low_u32(v: i64) -> u32 {
    let b = v.to_le_bytes();
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}

/// A program counter widened to `i64` so a signed branch displacement can be
/// added to it. `pc` indexes a byte slice, so it is at most `isize::MAX` and
/// the conversion cannot fail on any supported target; the saturating fallback
/// exists only so untrusted input can never panic here.
fn pc_as_i64(pc: usize) -> i64 {
    i64::try_from(pc).unwrap_or(i64::MAX)
}

/// A computed branch target, accepted only if it lands inside `len`.
/// Negative and out-of-range targets yield `None` instead of wrapping.
fn in_range_pc(target: i64, len: usize) -> Option<usize> {
    usize::try_from(target).ok().filter(|&t| t < len)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn engine() -> CilExecutionEngine { CilExecutionEngine::new() }
    fn no_args() -> Arguments { Arguments::new(vec![]) }
    fn no_locals() -> LocalVars { LocalVars::new(0) }

    #[test]
    fn ldc_i4_0_ret() {
        // ldc.i4.0 (0x16), ret (0x2A)
        let code = [0x16, 0x2A];
        let result = engine().execute_method_abstract(&code, &mut no_locals(), &no_args());
        assert_eq!(result, Some(CilValue::I32(0)));
    }

    #[test]
    fn ldc_i4_s_ret() {
        // ldc.i4.s 42, ret
        let code = [0x1F, 42u8, 0x2A];
        let result = engine().execute_method_abstract(&code, &mut no_locals(), &no_args());
        assert_eq!(result, Some(CilValue::I32(42)));
    }

    #[test]
    fn ldc_i4_full_ret() {
        // Bytes were 0x01,0x00,0x00,0x80 which decodes to 0x80000001 (-2147483647), not i32::MIN; corrected to little-endian i32::MIN.
        let code = [0x20, 0x00, 0x00, 0x00, 0x80u8, 0x2A]; // i32::MIN
        let result = engine().execute_method_abstract(&code, &mut no_locals(), &no_args());
        assert_eq!(result, Some(CilValue::I32(i32::MIN)));
    }

    #[test]
    fn add_two_constants() {
        // ldc.i4.3, ldc.i4.5, add, ret
        let code = [0x19, 0x1B, 0x58, 0x2A];
        let result = engine().execute_method_abstract(&code, &mut no_locals(), &no_args());
        assert_eq!(result, Some(CilValue::I32(8)));
    }

    #[test]
    fn sub_constants() {
        let code = [0x1B, 0x17, 0x59, 0x2A]; // 5 - 1 = 4
        let result = engine().execute_method_abstract(&code, &mut no_locals(), &no_args());
        assert_eq!(result, Some(CilValue::I32(4)));
    }

    #[test]
    fn mul_constants() {
        let code = [0x18, 0x19, 0x5A, 0x2A]; // 2 * 3 = 6
        let result = engine().execute_method_abstract(&code, &mut no_locals(), &no_args());
        assert_eq!(result, Some(CilValue::I32(6)));
    }

    #[test]
    fn and_constants() {
        let code = [0x1C, 0x1E, 0x5F, 0x2A]; // 6 & 8 = 0
        let result = engine().execute_method_abstract(&code, &mut no_locals(), &no_args());
        assert_eq!(result, Some(CilValue::I64(0)));
    }

    #[test]
    fn or_constants() {
        let code = [0x1C, 0x1E, 0x60, 0x2A]; // 6 | 8 = 14
        let result = engine().execute_method_abstract(&code, &mut no_locals(), &no_args());
        assert_eq!(result, Some(CilValue::I64(14)));
    }

    #[test]
    fn xor_constants() {
        let code = [0x1D, 0x1D, 0x61, 0x2A]; // 7 ^ 7 = 0
        let result = engine().execute_method_abstract(&code, &mut no_locals(), &no_args());
        assert_eq!(result, Some(CilValue::I64(0)));
    }

    #[test]
    fn dup() {
        // ldc.i4.5, dup, add, ret => 10
        let code = [0x1B, 0x25, 0x58, 0x2A];
        let result = engine().execute_method_abstract(&code, &mut no_locals(), &no_args());
        assert_eq!(result, Some(CilValue::I32(10)));
    }

    #[test]
    fn ldloc_stloc_roundtrip() {
        // ldc.i4.7, stloc.0, ldloc.0, ret
        let code = [0x1D, 0x0A, 0x06, 0x2A];
        let mut locals = LocalVars::new(1);
        let result = engine().execute_method_abstract(&code, &mut locals, &no_args());
        assert_eq!(result, Some(CilValue::I32(7)));
    }

    #[test]
    fn ldarg_0() {
        // ldarg.0, ret
        let code = [0x02, 0x2A];
        let args = Arguments::new(vec![CilValue::I32(99)]);
        let result = engine().execute_method_abstract(&code, &mut no_locals(), &args);
        assert_eq!(result, Some(CilValue::I32(99)));
    }

    #[test]
    fn not_op() {
        // ldc.i4.0, not, ret => -1
        let code = [0x16, 0x66, 0x2A];
        let result = engine().execute_method_abstract(&code, &mut no_locals(), &no_args());
        assert_eq!(result, Some(CilValue::I64(-1)));
    }

    #[test]
    fn neg_op() {
        let code = [0x17, 0x65, 0x2A]; // neg(1) = -1
        let result = engine().execute_method_abstract(&code, &mut no_locals(), &no_args());
        assert_eq!(result, Some(CilValue::I64(-1)));
    }

    #[test]
    fn ceq_equal() {
        // ldc.i4.3, ldc.i4.3, ceq, ret
        let code = [0x19, 0x19, 0xFE, 0x01, 0x2A];
        let result = engine().execute_method_abstract(&code, &mut no_locals(), &no_args());
        assert_eq!(result, Some(CilValue::I32(1)));
    }

    #[test]
    fn ceq_not_equal() {
        let code = [0x19, 0x17, 0xFE, 0x01, 0x2A]; // 3 == 1 => 0
        let result = engine().execute_method_abstract(&code, &mut no_locals(), &no_args());
        assert_eq!(result, Some(CilValue::I32(0)));
    }

    #[test]
    fn branch_short_brfalse() {
        // ldc.i4.0, brfalse.s +1, ldc.i4.1, [target:] ldc.i4.5, ret
        // brfalse skips ldc.i4.1 and lands on ldc.i4.5
        let code = [0x16, 0x2C, 0x01, 0x17, 0x1B, 0x2A];
        let result = engine().execute_method_abstract(&code, &mut no_locals(), &no_args());
        // After brfalse (taken), pc jumps to ldc.i4.5 (0x1B), ret => 5
        assert_eq!(result, Some(CilValue::I32(5)));
    }

    #[test]
    fn nop_does_not_crash() {
        let code = [0x00, 0x00, 0x16, 0x2A];
        let result = engine().execute_method_abstract(&code, &mut no_locals(), &no_args());
        assert_eq!(result, Some(CilValue::I32(0)));
    }
}
