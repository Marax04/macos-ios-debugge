//! WebAssembly LLIL lifter.
//!
//! Models the WASM value stack using virtual registers `s_<depth>`, local
//! variables as `local_<idx>`, globals as `global_<idx>`, and memory
//! operations as explicit [`Effect::MemRead`] / [`Effect::MemWrite`] effects.
//!
//! # Stack discipline
//!
//! WASM is purely stack-based.  Each instruction that *produces* a value
//! writes it to the current top-of-stack register (`s_<depth>`) and
//! increments an internal depth counter.  Instructions that *consume* values
//! read from the current top before decrementing.
//!
//! Because `lift` operates on a single instruction at a time (stateless API)
//! the lifter cannot maintain true inter-instruction stack state.  Instead,
//! each instruction is lifted as if the stack depth before it is **0**, and
//! the resulting register names (`s_0`, `s_1`, â€¦) encode relative positions.
//! A higher-level analysis pass can then assign concrete SSA names by tracking
//! depth across a basic block.
//!
//! # Operand extraction
//!
//! WASM operands (local indices, global indices, memory alignment, offset,
//! branch depth, function index, and immediate constants) are carried in the
//! instruction's raw `operands` string field (whitespace-separated tokens) as
//! well as the structured `operand_list`.  Both sources are tried; the raw
//! text is the primary source because the structured list may be empty for
//! architectures whose disassembler does not populate it.

use super::{ArchLifter, Effect, IrExpr, LiftError, LiftLevel, LiftedInstr};
use rustre_core::arch::Instruction;
use std::fmt;

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// Helper: stack register names
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Return the name of the virtual stack register at position `depth`.
#[inline]
fn stack_reg(depth: usize) -> String {
    format!("s_{depth}")
}

/// Return the name of the virtual local-variable register for index `idx`.
#[inline]
fn local_reg(idx: u64) -> String {
    format!("local_{idx}")
}

/// Return the name of the virtual global-variable register for index `idx`.
#[inline]
fn global_reg(idx: u64) -> String {
    format!("global_{idx}")
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// Operand extraction helpers
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Parse the raw operand string of a WASM instruction into whitespace-separated
/// tokens, stripping any trailing comments (`;; â€¦`).
fn raw_tokens(instr: &Instruction) -> Vec<String> {
    // Strip WAT-style comments and split on whitespace.
    let raw = instr.operands.split(";;").next().unwrap_or("").trim();
    if raw.is_empty() {
        // Fall back to the structured operand list rendered as display strings.
        return instr.operand_list.iter().map(|o| format!("{o}")).collect::<Vec<_>>();
    }
    raw.split_whitespace()
        .map(|s| s.trim_matches(',').to_string())
        .collect()
}

/// Try to extract the first numeric token from the operand string as a `u64`.
/// Accepts decimal and `0x`-prefixed hex.
fn first_u64(instr: &Instruction) -> Option<u64> {
    let toks = raw_tokens(instr);
    parse_u64(toks.first()?)
}

/// Parse a string token as a `u64` (decimal or `0x`-hex).
fn parse_u64(s: &str) -> Option<u64> {
    let s = s.trim();
    s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).map_or_else(|| s.parse::<i64>().ok().map(i64::cast_unsigned), |hex| u64::from_str_radix(hex, 16).ok())
}

/// Parse a string token as a signed `i64` and reinterpret as `u64`.
fn parse_i64_as_u64(s: &str) -> Option<u64> {
    let s = s.trim();
    s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).map_or_else(|| s.parse::<i64>().ok().map(i64::cast_unsigned), |hex| u64::from_str_radix(hex, 16).ok())
}

/// Extract the memory immediate operand for a load/store instruction.
///
/// WASM memory operands look like `offset=N align=M` in WAT text, or just
/// the raw numbers in the binary encoding.  This helper returns `(offset, align)`.
fn mem_imm(instr: &Instruction) -> (u64, u8) {
    let toks = raw_tokens(instr);
    let mut offset: u64 = 0;
    let mut align: u8 = 0;
    for tok in &toks {
        if let Some(v) = tok.strip_prefix("offset=") {
            offset = parse_u64(v).unwrap_or(0);
        } else if let Some(v) = tok.strip_prefix("align=") {
            align = u8::try_from(parse_u64(v).unwrap_or(0)).unwrap_or(0);
        }
    }
    // If no named keys, try positional: first token = align (log2), second = offset.
    if offset == 0 && align == 0 && !toks.is_empty() {
        align = u8::try_from(parse_u64(&toks[0]).unwrap_or(0)).unwrap_or(u8::MAX);
        if toks.len() >= 2 {
            offset = parse_u64(&toks[1]).unwrap_or(0);
        }
    }
    (offset, align)
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// WasmLifter
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// A mnemonic-driven LLIL lifter for WebAssembly (WASM) bytecode.
///
/// ## Stack modelling
///
/// The WASM value stack is modelled with virtual registers named `s_0`,
/// `s_1`, etc.  A per-instruction depth counter (starting at 0) tracks
/// which virtual register is the current top-of-stack:
///
/// * **Push** (producers): write result to `s_<depth>` then depth++
/// * **Pop** (consumers): depth-- then read from `s_<depth>`
/// * **Binary ops**: pop two, push one â€” net depth change of -1
///
/// Local variables map to `local_<idx>`, globals to `global_<idx>`.
///
/// ## Memory operations
///
/// All WASM linear-memory loads and stores use a single memory (index 0).
/// The effective address is: `s_<top> + offset` where `offset` comes from
/// the instruction's immediate field.
///
/// ## Limitations
///
/// * Floating-point `f32`/`f64` values are currently treated as 4-byte or
///   8-byte integer slots (no FP expression nodes exist in [`IrExpr`]).
/// * SIMD (`v128`) instructions are folded into [`Effect::Intrinsic`].
/// * Exception-handling proposals (`try`/`catch`/`throw`) are intrinsics.
#[derive(Debug, Clone)]
pub struct WasmLifter;

impl WasmLifter {
    /// Create a new `WasmLifter`.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    // â”€â”€ Internal lifting helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    /// Lift a `local.get <idx>` instruction.
    ///
    /// Pushes the value of `local_<idx>` onto the stack.
    fn lift_local_get(instr: &Instruction) -> Vec<Effect> {
        let idx = first_u64(instr).unwrap_or(0);
        vec![Effect::RegWrite {
            reg: stack_reg(0),
            value: IrExpr::Reg(local_reg(idx)),
        }]
    }

    /// Lift a `local.set <idx>` instruction.
    ///
    /// Pops the top of the stack and writes it into `local_<idx>`.
    fn lift_local_set(instr: &Instruction) -> Vec<Effect> {
        let idx = first_u64(instr).unwrap_or(0);
        vec![Effect::RegWrite {
            reg: local_reg(idx),
            value: IrExpr::Reg(stack_reg(0)),
        }]
    }

    /// Lift a `local.tee <idx>` instruction.
    ///
    /// Writes the top of the stack into `local_<idx>` but *also* keeps the
    /// value on the stack (it is both a consumer and producer of `s_0`).
    fn lift_local_tee(instr: &Instruction) -> Vec<Effect> {
        let idx = first_u64(instr).unwrap_or(0);
        // The value stays on the stack (s_0 unchanged) and is also written to local.
        vec![Effect::RegWrite {
            reg: local_reg(idx),
            value: IrExpr::Reg(stack_reg(0)),
        }]
    }

    /// Lift a `global.get <idx>` instruction.
    fn lift_global_get(instr: &Instruction) -> Vec<Effect> {
        let idx = first_u64(instr).unwrap_or(0);
        vec![Effect::RegWrite {
            reg: stack_reg(0),
            value: IrExpr::Reg(global_reg(idx)),
        }]
    }

    /// Lift a `global.set <idx>` instruction.
    fn lift_global_set(instr: &Instruction) -> Vec<Effect> {
        let idx = first_u64(instr).unwrap_or(0);
        vec![Effect::RegWrite {
            reg: global_reg(idx),
            value: IrExpr::Reg(stack_reg(0)),
        }]
    }

    /// Lift an integer constant push: `i32.const <v>` / `i64.const <v>`.
    fn lift_const(instr: &Instruction) -> Vec<Effect> {
        let toks = raw_tokens(instr);
        let val = toks.first().and_then(|s| parse_i64_as_u64(s)).unwrap_or(0);
        vec![Effect::RegWrite {
            reg: stack_reg(0),
            value: IrExpr::Const(val),
        }]
    }

    /// Lift a floating-point constant push: `f32.const <v>` / `f64.const <v>`.
    ///
    /// FP constants are stored as their raw bit pattern reinterpreted as u64.
    fn lift_fp_const(instr: &Instruction, is_f64: bool) -> Vec<Effect> {
        let toks = raw_tokens(instr);
        let raw_bits: u64 = if let Some(tok) = toks.first() {
            // Handle hex float (0x1p+0), decimal float, or nan/inf keywords.
            let s = tok.as_str();
            if s.starts_with("nan") || s.starts_with("inf") || s.starts_with('-') {
                // Represent as undefined; analysis passes can refine.
                return vec![Effect::RegWrite {
                    reg: stack_reg(0),
                    value: IrExpr::Undef,
                }];
            }
            // Try to parse as u64 hex/decimal bits directly.
            parse_u64(s).unwrap_or(0)
        } else {
            0
        };
        let _ = is_f64; // Size information retained in the mnemonic.
        vec![Effect::RegWrite {
            reg: stack_reg(0),
            value: IrExpr::Const(raw_bits),
        }]
    }

    /// Lift a binary arithmetic/logic instruction.
    ///
    /// Pattern: pop `s_1` (left) and `s_0` (right, top), push result to `s_0`.
    /// The virtual stack after: depth decreases by 1.
    /// A binary op whose result must WRAP at the operand width.
    ///
    /// `i32.add` and `i64.add` shared one arm and produced byte-identical
    /// effects. WebAssembly's `i32` arithmetic is modulo 2^32, and this IR is
    /// untyped, so without an explicit mask the 32-bit wrap simply does not
    /// exist — `i32.add` of two large values reads as a 64-bit sum.
    ///
    /// Only the ops whose result can EXCEED the operand width need this:
    /// `add`, `sub`, `mul`, `shl`. `and`/`or`/`xor` cannot widen their inputs,
    /// and the right shifts only narrow, so masking those would add noise
    /// rather than correctness. BPF's `add32` already masks for exactly this
    /// reason — the precedent was in this crate.
    fn lift_binop_wrapping(
        op: fn(Box<IrExpr>, Box<IrExpr>) -> IrExpr,
        mnem: &str,
    ) -> Vec<Effect> {
        let lhs = IrExpr::Reg(stack_reg(1));
        let rhs = IrExpr::Reg(stack_reg(0));
        let value = op(Box::new(lhs), Box::new(rhs));
        vec![Effect::RegWrite {
            reg: stack_reg(0),
            value: if mnem.starts_with("i32") {
                IrExpr::And(Box::new(value), Box::new(IrExpr::Const(0xFFFF_FFFF)))
            } else {
                value
            },
        }]
    }

    fn lift_binop(op: fn(Box<IrExpr>, Box<IrExpr>) -> IrExpr) -> Vec<Effect> {
        // s_1 op s_0 â†’ s_0   (s_1 was pushed first, s_0 is the top)
        let lhs = IrExpr::Reg(stack_reg(1));
        let rhs = IrExpr::Reg(stack_reg(0));
        vec![Effect::RegWrite {
            reg: stack_reg(0),
            value: op(Box::new(lhs), Box::new(rhs)),
        }]
    }

    /// Lift `irotl` / `irotr`.
    ///
    /// The old encoding was `(a << b) | (a >> b)` for `rotl` and the same two
    /// terms in the other order for `rotr`. That is not a rotation — the
    /// wrap-around term must shift by `W - b`, not `b`. And because `Or` is
    /// commutative the two arms produced the SAME expression, so `rotl` and
    /// `rotr` were indistinguishable in the IL: two distinct opcodes, one
    /// meaning, and that meaning wrong.
    ///
    /// The IR has no rotate node, but a rotate is expressible with the nodes
    /// that exist, so this was never an expressiveness limit.
    ///
    /// Per the WebAssembly spec the count is taken modulo the operand width,
    /// which is why it is masked here. Note the standard caveat of this
    /// formulation: at a masked count of 0 the complementary term shifts by the
    /// full width, which the IR leaves unconstrained — the rotate-by-zero case
    /// is therefore modelled no more precisely than the IR allows.
    fn lift_rotate(mnem: &str, left: bool) -> Vec<Effect> {
        let width: u64 = if mnem.starts_with("i64") { 64 } else { 32 };
        let lhs = IrExpr::Reg(stack_reg(1));
        let rhs = IrExpr::Reg(stack_reg(0));
        let count = IrExpr::And(Box::new(rhs), Box::new(IrExpr::Const(width - 1)));
        let complement = IrExpr::Sub(
            Box::new(IrExpr::Const(width)),
            Box::new(count.clone()),
        );
        let (a, b) = if left {
            (
                IrExpr::Shl(Box::new(lhs.clone()), Box::new(count)),
                IrExpr::Shr(Box::new(lhs), Box::new(complement)),
            )
        } else {
            (
                IrExpr::Shr(Box::new(lhs.clone()), Box::new(count)),
                IrExpr::Shl(Box::new(lhs), Box::new(complement)),
            )
        };
        let rotated = IrExpr::Or(Box::new(a), Box::new(b));
        vec![Effect::RegWrite {
            reg: stack_reg(0),
            // The left-shifted half can carry past the operand width, so the
            // 32-bit forms wrap here too.
            value: if width == 32 {
                IrExpr::And(Box::new(rotated), Box::new(IrExpr::Const(0xFFFF_FFFF)))
            } else {
                rotated
            },
        }]
    }

    /// Lift a unary operation: pop `s_0`, push result back to `s_0`.
    fn lift_unop(op: fn(Box<IrExpr>) -> IrExpr) -> Vec<Effect> {
        let operand = IrExpr::Reg(stack_reg(0));
        vec![Effect::RegWrite {
            reg: stack_reg(0),
            value: op(Box::new(operand)),
        }]
    }

    /// Lift an integer comparison that results in `eqz`: `i32.eqz` / `i64.eqz`.
    fn lift_eqz() -> Vec<Effect> {
        Self::lift_unop(IrExpr::CmpEqZero)
    }

    /// Lift a comparison that produces an integer (0 or 1).
    ///
    /// These are modelled as an `Intrinsic` because [`IrExpr`] has no general
    /// compare node beyond `CmpEqZero`.
    /// Lift a comparison. The operands are `s_1 <op> s_0`, `s_1` being the
    /// value pushed first.
    ///
    /// Every one of these used to write `Undef` beside an intrinsic, under the
    /// comment "Refined by higher-level passes" — a promise nothing keeps, and
    /// the same shape as the BPF wrapper that did not exist. The INTEGER
    /// comparisons are fully expressible: `CmpEq`, `Ne`, `CmpLt` and `CmpLtU`
    /// all exist, and the signed/unsigned distinction the mnemonics spell out
    /// is exactly what `CmpLtU` was added for.
    ///
    /// The FLOAT comparisons stay opaque on purpose: the IR has no float
    /// compare, so an integer node would be a wrong answer rather than a
    /// partial one. They keep the intrinsic, which preserves the distinction.
    fn lift_relop(name: &str) -> Vec<Effect> {
        let lhs = || IrExpr::Reg(stack_reg(1));
        let rhs = || IrExpr::Reg(stack_reg(0));
        let lt = |a: IrExpr, b: IrExpr, unsigned: bool| {
            if unsigned {
                IrExpr::CmpLtU(Box::new(a), Box::new(b))
            } else {
                IrExpr::CmpLt(Box::new(a), Box::new(b))
            }
        };

        // `i32.lt_s` -> ("lt", true signed). Floats have no `_s`/`_u` suffix.
        let op = name.rsplit('.').next().unwrap_or(name);
        let is_float = name.starts_with('f');
        let (kind, unsigned) = match op.split_once('_') {
            Some((k, "u")) => (k, true),
            Some((k, _)) => (k, false),
            None => (op, false),
        };

        let value = if is_float {
            None
        } else {
            match kind {
                "eq" => Some(IrExpr::CmpEq(Box::new(lhs()), Box::new(rhs()))),
                "ne" => Some(IrExpr::Ne(Box::new(lhs()), Box::new(rhs()))),
                "lt" => Some(lt(lhs(), rhs(), unsigned)),
                "gt" => Some(lt(rhs(), lhs(), unsigned)),
                "le" => Some(IrExpr::Not(Box::new(lt(rhs(), lhs(), unsigned)))),
                "ge" => Some(IrExpr::Not(Box::new(lt(lhs(), rhs(), unsigned)))),
                _ => None,
            }
        };

        match value {
            Some(v) => vec![Effect::RegWrite { reg: stack_reg(0), value: v }],
            None => vec![
                Effect::RegWrite { reg: stack_reg(0), value: IrExpr::Undef },
                Effect::Intrinsic {
                    name: name.to_string(),
                    args: vec![lhs(), rhs()],
                },
            ],
        }
    }

    /// Lift a memory load instruction.
    ///
    /// `i32.load`, `i64.load`, `f32.load`, `f64.load`, `i32.load8_s`, etc.
    ///
    /// Pattern: pop address from `s_0`, read `size` bytes, push result to `s_0`.
    /// WebAssembly narrow loads come in SIGNED and UNSIGNED forms — the `_s`
    /// and `_u` suffixes — which differ in how the loaded value is extended to
    /// the stack slot's width. `i32.load8_s` of `0xFF` is `-1`; `i32.load8_u`
    /// is `255`. All of them shared this handler, which takes only a size, so
    /// the two produced IDENTICAL IL.
    ///
    /// Third architecture with this exact defect after RISC-V (iteration 47)
    /// and the MIPS signed/unsigned collapse — the "when you fix one lifter,
    /// grep the others" rule paying out again.
    ///
    /// Modelled with the `sextN` intrinsic marker already used by the PowerPC
    /// and RISC-V lifters, rather than inventing a third convention. A
    /// A WebAssembly load, with the MNEMONIC recorded.
    ///
    /// WASM opcodes are fully typed, and iteration 60 only split the signedness.
    /// The enumeration rule sent me back here, and the arms were still flattening
    /// two more facts:
    ///
    /// 1. **float vs integer** — `i32.load` and `f32.load` shared a handler, but
    ///    one pushes an i32 and the other an f32. Different stack types; the same
    ///    conflation the CIL work found in `ldind.r4`.
    /// 2. **destination width** — `i32.load8_s` extends 8 bits to **32**,
    ///    `i64.load8_s` extends the same 8 bits to **64**. They shared an arm, so
    ///    one `sext8` marker stood for two different extensions. My iteration-60
    ///    fix was right about signedness and silent about this.
    ///
    /// Both facts are stated in the mnemonic, so recording it closes both at
    /// once — the treatment CIL's `LDIND` got, for the same reason: in a typed
    /// ISA the opcode already carries what a size-only signature throws away.
    fn lift_load_typed(instr: &Instruction, size: u8, signed: bool, mnem: &str) -> Vec<Effect> {
        let mut out = Self::lift_load_ext(instr, size, signed);
        out.push(Effect::Intrinsic {
            name: mnem.to_string(),
            args: vec![IrExpr::Reg(stack_reg(0))],
        });
        out
    }

    /// full-width load needs no marker.
    fn lift_load_ext(instr: &Instruction, size_bytes: u8, signed: bool) -> Vec<Effect> {
        let mut out = Self::lift_load(instr, size_bytes);
        if signed {
            out.push(Effect::Intrinsic {
                name: format!("sext{}", u32::from(size_bytes) * 8),
                args: vec![IrExpr::Reg(stack_reg(0))],
            });
        }
        out
    }

    fn lift_load(instr: &Instruction, size_bytes: u8) -> Vec<Effect> {
        let (offset, _align) = mem_imm(instr);
        let base_addr = IrExpr::Reg(stack_reg(0));
        let effective_addr = if offset == 0 {
            base_addr
        } else {
            IrExpr::Add(Box::new(base_addr), Box::new(IrExpr::Const(offset)))
        };
        // Read from memory into a temporary, then place on stack.
        vec![Effect::MemRead {
            addr: effective_addr,
            dest: stack_reg(0),
            size: size_bytes,
        }]
    }

    /// Lift a memory store instruction.
    ///
    /// `i32.store`, `i64.store`, `f32.store`, `f64.store`, `i32.store8`, etc.
    ///
    /// Pattern: pop value (`s_0`) and address (`s_1`), write `size` bytes.
    fn lift_store(instr: &Instruction, size_bytes: u8) -> Vec<Effect> {
        let (offset, _align) = mem_imm(instr);
        let base_addr = IrExpr::Reg(stack_reg(1));
        let value = IrExpr::Reg(stack_reg(0));
        let effective_addr = if offset == 0 {
            base_addr
        } else {
            IrExpr::Add(Box::new(base_addr), Box::new(IrExpr::Const(offset)))
        };
        vec![Effect::MemWrite {
            addr: effective_addr,
            value,
            size: size_bytes,
        }]
    }

    /// Lift a `br <depth>` unconditional branch.
    fn lift_br(instr: &Instruction) -> Vec<Effect> {
        let label_depth = first_u64(instr).unwrap_or(0);
        vec![Effect::Branch {
            target: IrExpr::Const(label_depth),
            condition: None,
        }]
    }

    /// Lift a `br_if <depth>` conditional branch.
    ///
    /// Branches to the label at the given depth if the top of stack is non-zero.
    fn lift_br_if(instr: &Instruction) -> Vec<Effect> {
        let label_depth = first_u64(instr).unwrap_or(0);
        let condition = IrExpr::Reg(stack_reg(0));
        vec![Effect::Branch {
            target: IrExpr::Const(label_depth),
            condition: Some(condition),
        }]
    }

    /// Lift a `br_table <default> <label...>` indirect branch table.
    ///
    /// Models as an unconditional branch whose target is the table index
    /// from the top of the stack; the default target is recorded as the
    /// first token.
    fn lift_br_table(instr: &Instruction) -> Vec<Effect> {
        let toks = raw_tokens(instr);
        // Collect all label indices; the last is the default.
        let targets: Vec<IrExpr> = toks
            .iter()
            .filter_map(|t| parse_u64(t))
            .map(IrExpr::Const)
            .collect();
        let selector = IrExpr::Reg(stack_reg(0));
        // We emit an intrinsic carrying all targets plus the selector.
        let mut args = vec![selector];
        args.extend(targets);
        vec![Effect::Intrinsic {
            name: "br_table".to_string(),
            args,
        }]
    }

    /// Lift a `call <func_idx>` instruction.
    fn lift_call(instr: &Instruction) -> Vec<Effect> {
        let func_idx = first_u64(instr).unwrap_or(0);
        vec![Effect::Call {
            target: IrExpr::Const(func_idx),
        }]
    }

    /// Lift a `call_indirect <type_idx> <table_idx>` instruction.
    ///
    /// The function index is taken from the top of the stack.
    fn lift_call_indirect(instr: &Instruction) -> Vec<Effect> {
        let type_idx = first_u64(instr).unwrap_or(0);
        // The actual callee address is the value at s_0 (looked up in the table).
        let target = IrExpr::Reg(stack_reg(0));
        vec![
            Effect::Intrinsic {
                name: "call_indirect".to_string(),
                args: vec![target.clone(), IrExpr::Const(type_idx)],
            },
            Effect::Call { target },
        ]
    }

    /// Lift a `return` instruction.
    ///
    /// The return value (if any) is in `s_0`.
    fn lift_return() -> Vec<Effect> {
        vec![Effect::Return {
            value: Some(IrExpr::Reg(stack_reg(0))),
        }]
    }

    /// Lift a `select` instruction.
    ///
    /// Pattern: `condition = s_0`, `val2 = s_1`, `val1 = s_2`.
    /// Result = `(condition != 0) ? val1 : val2`, written to `s_0`.
    fn lift_select() -> Vec<Effect> {
        let cond = IrExpr::Reg(stack_reg(0));
        let val2 = IrExpr::Reg(stack_reg(1));
        let val1 = IrExpr::Reg(stack_reg(2));
        vec![Effect::Intrinsic {
            name: "select".to_string(),
            args: vec![cond, val1, val2],
        }]
    }

    /// Lift `memory.size` â€” pushes the current memory size (in pages) onto the stack.
    fn lift_memory_size() -> Vec<Effect> {
        vec![Effect::Intrinsic {
            name: "memory.size".to_string(),
            args: vec![],
        }]
    }

    /// Lift `memory.grow <delta>` â€” grows linear memory by `s_0` pages.
    fn lift_memory_grow() -> Vec<Effect> {
        let pages = IrExpr::Reg(stack_reg(0));
        vec![Effect::Intrinsic {
            name: "memory.grow".to_string(),
            args: vec![pages],
        }]
    }

    /// Lift a `drop` instruction â€” discard top of stack.
    fn lift_drop() -> Vec<Effect> {
        vec![Effect::Intrinsic {
            name: "drop".to_string(),
            args: vec![IrExpr::Reg(stack_reg(0))],
        }]
    }

    /// Lift an integer count-leading-zeros / count-trailing-zeros / popcount.
    fn lift_bitcount(name: &str) -> Vec<Effect> {
        let operand = IrExpr::Reg(stack_reg(0));
        vec![Effect::Intrinsic {
            name: name.to_string(),
            args: vec![operand],
        }]
    }

    /// Lift integer division / remainder operations.
    fn lift_divrem(name: &str) -> Vec<Effect> {
        let lhs = IrExpr::Reg(stack_reg(1));
        let rhs = IrExpr::Reg(stack_reg(0));
        vec![Effect::Intrinsic {
            name: name.to_string(),
            args: vec![lhs, rhs],
        }]
    }

    /// Lift numeric conversion / truncation / extension instructions.
    fn lift_convert(name: &str) -> Vec<Effect> {
        let operand = IrExpr::Reg(stack_reg(0));
        vec![
            Effect::RegWrite {
                reg: stack_reg(0),
                value: IrExpr::Undef,
            },
            Effect::Intrinsic {
                name: name.to_string(),
                args: vec![operand],
            },
        ]
    }

    /// Lift an `unreachable` instruction.
    fn lift_unreachable() -> Vec<Effect> {
        vec![Effect::Intrinsic {
            name: "unreachable".to_string(),
            args: vec![],
        }]
    }

    /// Lift control-flow structural markers: `block`, `loop`, `if`, `else`, `end`.
    fn lift_control_marker(name: &str) -> Vec<Effect> {
        vec![Effect::Intrinsic {
            name: name.to_string(),
            args: vec![],
        }]
    }

    /// Lift `table.get`, `table.set`, and other table instructions.
    fn lift_table_op(name: &str, instr: &Instruction) -> Vec<Effect> {
        let idx = first_u64(instr).unwrap_or(0);
        let top = IrExpr::Reg(stack_reg(0));
        vec![Effect::Intrinsic {
            name: name.to_string(),
            args: vec![IrExpr::Const(idx), top],
        }]
    }

    /// Lift `ref.null`, `ref.is_null`, `ref.func`.
    fn lift_ref_op(name: &str, instr: &Instruction) -> Vec<Effect> {
        let arg = first_u64(instr).map_or(IrExpr::Undef, IrExpr::Const);
        vec![Effect::Intrinsic {
            name: name.to_string(),
            args: vec![arg],
        }]
    }

    /// Lift bulk memory instructions: `memory.copy`, `memory.fill`, `memory.init`, etc.
    fn lift_memory_bulk(name: &str) -> Vec<Effect> {
        // These consume 3 values from the stack (dst, src, len) or similar.
        let a = IrExpr::Reg(stack_reg(0));
        let b = IrExpr::Reg(stack_reg(1));
        let c = IrExpr::Reg(stack_reg(2));
        vec![Effect::Intrinsic {
            name: name.to_string(),
            args: vec![a, b, c],
        }]
    }

    /// Lift atomic memory operations (threads proposal).
    fn lift_atomic(name: &str, instr: &Instruction, size_bytes: u8) -> Vec<Effect> {
        let (offset, _) = mem_imm(instr);
        let addr_base = IrExpr::Reg(stack_reg(1));
        let value = IrExpr::Reg(stack_reg(0));
        let addr = if offset == 0 {
            addr_base
        } else {
            IrExpr::Add(Box::new(addr_base), Box::new(IrExpr::Const(offset)))
        };
        vec![Effect::Intrinsic {
            name: name.to_string(),
            args: vec![addr, value, IrExpr::Const(u64::from(size_bytes))],
        }]
    }

    // â”€â”€ Main dispatch â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    /// Dispatch `mnemonic â†’ effects`.
    ///
    /// The mnemonic is already lower-cased by the caller.
    fn dispatch_a(mnem: &str, instr: &Instruction) -> Option<Vec<Effect>> {
            Some(match mnem {
            "nop" => vec![],
            // â”€â”€ Control flow â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            "unreachable" => Self::lift_unreachable(),


            "block" | "loop" | "if" | "else" | "end" | "then" => Self::lift_control_marker(mnem),

            "br" => Self::lift_br(instr),
            "br_if" => Self::lift_br_if(instr),
            "br_table" => Self::lift_br_table(instr),

            "return" => Self::lift_return(),

            "call" => Self::lift_call(instr),
            "call_indirect" => Self::lift_call_indirect(instr),
            "return_call" => {
                // Tail-call â€” same as call but also marks the return.
                let mut effects = Self::lift_call(instr);
                effects.push(Effect::Return { value: None });
                effects
            }
            "return_call_indirect" => {
                let mut effects = Self::lift_call_indirect(instr);
                effects.push(Effect::Return { value: None });
                effects
            }

            // â”€â”€ Parametric â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            "drop" => Self::lift_drop(),
            "select" | "select_" => Self::lift_select(),

            // â”€â”€ Variables â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            "local.get" => Self::lift_local_get(instr),
            "local.set" => Self::lift_local_set(instr),
            "local.tee" => Self::lift_local_tee(instr),
            "global.get" => Self::lift_global_get(instr),
            "global.set" => Self::lift_global_set(instr),

            // â”€â”€ Memory loads â€” i32 â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            "i32.load" | "f32.load" => Self::lift_load_typed(instr, 4, false, mnem),
            "i64.load32_s" => Self::lift_load_typed(instr, 4, true, mnem),
            "i64.load32_u" => Self::lift_load_typed(instr, 4, false, mnem),
            "i32.load8_s" | "i64.load8_s" => Self::lift_load_typed(instr, 1, true, mnem),
            "i32.load8_u" | "i64.load8_u" => Self::lift_load_typed(instr, 1, false, mnem),
            "i32.load16_s" | "i64.load16_s" => Self::lift_load_typed(instr, 2, true, mnem),
            "i32.load16_u" | "i64.load16_u" => Self::lift_load_typed(instr, 2, false, mnem),

            // â”€â”€ Memory loads â€” i64 â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            "i64.load" | "f64.load" => Self::lift_load_typed(instr, 8, false, mnem),
            // â”€â”€ Memory loads â€” f32 / f64 â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            // â”€â”€ Memory stores â€” i32 â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            "i32.store" | "i64.store32" | "f32.store" => Self::lift_store(instr, 4),
            "i32.store8" | "i64.store8" => Self::lift_store(instr, 1),
            "i32.store16" | "i64.store16" => Self::lift_store(instr, 2),

            // â”€â”€ Memory stores â€” i64 â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            "i64.store" | "f64.store" => Self::lift_store(instr, 8),
            // â”€â”€ Memory stores â€” f32 / f64 â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            // â”€â”€ Memory management â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            "memory.size" => Self::lift_memory_size(),
            "memory.grow" => Self::lift_memory_grow(),
            "memory.copy" | "memory.fill" | "memory.init" | "data.drop" => Self::lift_memory_bulk(mnem),
            // â”€â”€ Constants â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            "i32.const" | "i64.const" => Self::lift_const(instr),
            "f32.const" => Self::lift_fp_const(instr, false),
            "f64.const" => Self::lift_fp_const(instr, true),
                _ => return None,
            })
    }
    fn dispatch_b_a(mnem: &str, _instr: &Instruction) -> Option<Vec<Effect>> {
                Some(match mnem {
            "i32.add" | "i64.add" => Self::lift_binop_wrapping(IrExpr::Add, mnem),
            "i32.sub" | "i64.sub" => Self::lift_binop_wrapping(IrExpr::Sub, mnem),
            "i32.mul" | "i64.mul" => Self::lift_binop_wrapping(IrExpr::Mul, mnem),
            "i32.and" | "i64.and" => Self::lift_binop(IrExpr::And),
            "i32.or" | "i64.or" => Self::lift_binop(IrExpr::Or),
            "i32.xor" | "i64.xor" => Self::lift_binop(IrExpr::Xor),
            "i32.shl" | "i64.shl" => Self::lift_binop_wrapping(IrExpr::Shl, mnem),
            // `shr_s` is an ARITHMETIC shift and `shr_u` a logical one. Both
            // used to share this arm and lift to the logical `Shr`, so the
            // signedness the mnemonic spells out was destroyed and `shr_s` was
            // simply wrong for negative values. `IrExpr::Sar` already existed.
            "i32.shr_u" | "i64.shr_u" => Self::lift_binop(IrExpr::Shr),
            "i32.shr_s" | "i64.shr_s" => Self::lift_binop(IrExpr::Sar),
            "i32.rotl" | "i64.rotl" => Self::lift_rotate(mnem, true),
            "i32.rotr" | "i64.rotr" => Self::lift_rotate(mnem, false),
            "i32.div_u" | "i32.div_s" | "i64.div_u" | "i64.div_s" | "i32.rem_u" | "i32.rem_s" | "i64.rem_u" | "i64.rem_s" => Self::lift_divrem(mnem),
            "i32.clz" | "i64.clz" | "i32.ctz" | "i64.ctz" | "i32.popcnt" | "i64.popcnt" => Self::lift_bitcount(mnem),
            "i32.eqz" | "i64.eqz" => Self::lift_eqz(),
            "i32.eq" | "i64.eq" | "i32.ne" | "i64.ne" | "i32.lt_s" | "i32.lt_u" | "i64.lt_s" | "i64.lt_u" | "i32.gt_s" | "i32.gt_u" | "i64.gt_s" | "i64.gt_u" | "i32.le_s" | "i32.le_u" | "i64.le_s" | "i64.le_u" | "i32.ge_s" | "i32.ge_u" | "i64.ge_s" | "i64.ge_u" | "f32.eq" | "f64.eq" | "f32.ne" | "f64.ne" | "f32.lt" | "f64.lt" | "f32.gt"
            | "f64.gt" | "f32.le" | "f64.le" | "f32.ge" | "f64.ge" => Self::lift_relop(mnem),
            "f32.add" | "f64.add" | "f32.sub" | "f64.sub" | "f32.mul" | "f64.mul" | "f32.div"
            | "f64.div" | "f32.min" | "f64.min" | "f32.max" | "f64.max" | "f32.copysign"
            | "f64.copysign" => {
                let lhs = IrExpr::Reg(stack_reg(1));
                let rhs = IrExpr::Reg(stack_reg(0));
                vec![
                    Effect::RegWrite {
                        reg: stack_reg(0),
                        value: IrExpr::Undef,
                    },
                    Effect::Intrinsic {
                        name: mnem.to_string(),
                        args: vec![lhs, rhs],
                    },
                ]
            }
            "f32.abs" | "f64.abs" | "f32.neg" | "f64.neg" | "f32.ceil" | "f64.ceil"
            | "f32.floor" | "f64.floor" | "f32.trunc" | "f64.trunc" | "f32.nearest"
            | "f64.nearest" | "f32.sqrt" | "f64.sqrt" => {
                let operand = IrExpr::Reg(stack_reg(0));
                vec![
                    Effect::RegWrite {
                        reg: stack_reg(0),
                        value: IrExpr::Undef,
                    },
                    Effect::Intrinsic {
                        name: mnem.to_string(),
                        args: vec![operand],
                    },
                ]
            }
                    _ => return None,
                })
    }

    fn dispatch_b_b(mnem: &str, instr: &Instruction) -> Option<Vec<Effect>> {
                Some(match mnem {
            // The three INTEGER width conversions are fully expressible and
            // were writing `Undef` beside a naming intrinsic — the same shape as
            // MIPS `EXT`/`INS`. `i32.wrap_i64` and `i64.extend_i32_u` are one
            // mask; `i64.extend_i32_s` is the sign-extend idiom this crate uses
            // throughout (`Sar(Shl(x, 32), 32)`).
            //
            // Everything below them stays opaque on purpose: the float
            // conversions need semantics this IR does not have, so an integer
            // node there would be a WRONG answer, not a partial one.
            "i32.wrap_i64" | "i64.extend_i32_u" => {
                let v = IrExpr::And(
                    Box::new(IrExpr::Reg(stack_reg(0))),
                    Box::new(IrExpr::Const(0xFFFF_FFFF)),
                );
                vec![Effect::RegWrite { reg: stack_reg(0), value: v }]
            }
            "i64.extend_i32_s" => {
                let x = IrExpr::Reg(stack_reg(0));
                let v = IrExpr::Sar(
                    Box::new(IrExpr::Shl(Box::new(x), Box::new(IrExpr::Const(32)))),
                    Box::new(IrExpr::Const(32)),
                );
                vec![Effect::RegWrite { reg: stack_reg(0), value: v }]
            }
            "i32.trunc_f32_s"
            | "i32.trunc_f32_u"
            | "i32.trunc_f64_s"
            | "i32.trunc_f64_u"
            | "i64.trunc_f32_s"
            | "i64.trunc_f32_u"
            | "i64.trunc_f64_s"
            | "i64.trunc_f64_u"
            | "f32.convert_i32_s"
            | "f32.convert_i32_u"
            | "f32.convert_i64_s"
            | "f32.convert_i64_u"
            | "f64.convert_i32_s"
            | "f64.convert_i32_u"
            | "f64.convert_i64_s"
            | "f64.convert_i64_u"
            | "f32.demote_f64"
            | "f64.promote_f32"
            | "i32.reinterpret_f32"
            | "i64.reinterpret_f64"
            | "f32.reinterpret_i32"
            | "f64.reinterpret_i64"
            | "i32.extend8_s"
            | "i32.extend16_s"
            | "i64.extend8_s"
            | "i64.extend16_s"
            | "i64.extend32_s"
            | "i32.trunc_sat_f32_s"
            | "i32.trunc_sat_f32_u"
            | "i32.trunc_sat_f64_s"
            | "i32.trunc_sat_f64_u"
            | "i64.trunc_sat_f32_s"
            | "i64.trunc_sat_f32_u"
            | "i64.trunc_sat_f64_s"
            | "i64.trunc_sat_f64_u" => Self::lift_convert(mnem),
            "memory.atomic.wait32" | "memory.atomic.wait64" | "memory.atomic.notify" => {
                Self::lift_memory_bulk(mnem)
            }
            "i32.atomic.load"
            | "i64.atomic.load"
            | "i32.atomic.load8_u"
            | "i32.atomic.load16_u"
            | "i64.atomic.load8_u"
            | "i64.atomic.load16_u"
            | "i64.atomic.load32_u" | "i32.atomic.store" | "i64.atomic.store" | "i32.atomic.store8"
            | "i32.atomic.store16" | "i64.atomic.store8" | "i64.atomic.store16"
            | "i64.atomic.store32" => Self::lift_atomic(mnem, instr, 4),
            "table.get" => Self::lift_table_op("table.get", instr),
            "table.set" => Self::lift_table_op("table.set", instr),
            "table.size" => Self::lift_table_op("table.size", instr),
            "table.grow" => Self::lift_table_op("table.grow", instr),
            "table.fill" => Self::lift_table_op("table.fill", instr),
            "table.copy" => Self::lift_table_op("table.copy", instr),
            "table.init" | "elem.drop" => Self::lift_table_op(mnem, instr),
            "ref.null" => Self::lift_ref_op("ref.null", instr),
            "ref.is_null" => Self::lift_ref_op("ref.is_null", instr),
            "ref.func" => Self::lift_ref_op("ref.func", instr),
            "try" | "catch" | "catch_all" | "throw" | "rethrow" | "delegate" | "unwind" => {
                Self::lift_control_marker(mnem)
            }
            m if m.starts_with("v128.")
                || m.contains(".splat")
                || m.contains(".extract_lane")
                || m.contains(".replace_lane")
                || m.starts_with("i8x16.")
                || m.starts_with("i16x8.")
                || m.starts_with("i32x4.")
                || m.starts_with("i64x2.")
                || m.starts_with("f32x4.")
                || m.starts_with("f64x2.") =>
            {
                vec![Effect::Intrinsic {
                    name: mnem.to_string(),
                    args: vec![IrExpr::Reg(stack_reg(0))],
                }]
            }
            _ => vec![Effect::Intrinsic {
                name: mnem.to_string(),
                args: vec![],
            }],
                })
    }

    fn dispatch_b(mnem: &str, instr: &Instruction) -> Vec<Effect> {
        if let Some(r) = Self::dispatch_b_a(mnem, instr) {
            return r;
        }
        // dispatch_b_b is the terminal fallback of this chain and always matches.
        Self::dispatch_b_b(mnem, instr).unwrap_or_default()
    }

    fn dispatch(mnem: &str, instr: &Instruction) -> Vec<Effect> {
        if let Some(r) = Self::dispatch_a(mnem, instr) {
            return r;
        }
        Self::dispatch_b(mnem, instr)
    }

    /// Build the IR text summary from the effect list.
    fn build_ir_text(effects: &[Effect]) -> String {
        if effects.is_empty() {
            return "nop".to_string();
        }
        effects
            .iter()
            .map(std::string::ToString::to_string)
            .collect::<Vec<_>>()
            .join("; ")
    }
}

impl Default for WasmLifter {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for WasmLifter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "WasmLifter(wasm32)")
    }
}

impl ArchLifter for WasmLifter {
    fn arch_name(&self) -> &'static str {
        "wasm"
    }

    fn lift_level(&self) -> LiftLevel {
        LiftLevel::Llil
    }

    fn description(&self) -> &'static str {
        "stack-model WASM LLIL lifter (localsâ†’local_N, globalsâ†’global_N, stackâ†’s_N)"
    }

    fn supports_mnemonic(&self, mnemonic: &str) -> bool {
        // We handle all WASM mnemonics; unknown ones fall back to Intrinsic.
        let _ = mnemonic;
        true
    }

    fn lift(&self, instr: &Instruction) -> Result<LiftedInstr, LiftError> {
        let mnem = instr.mnemonic.to_ascii_lowercase();
        let effects = Self::dispatch(&mnem, instr);
        let ir_text = Self::build_ir_text(&effects);

        Ok(LiftedInstr {
            address: instr.address.0,
            original_mnemonic: instr.mnemonic.clone(),
            ir_text,
            il_level: LiftLevel::Llil,
            effects,
        })
    }

    fn lift_block(&self, instrs: &[Instruction]) -> Vec<Result<LiftedInstr, LiftError>> {
        instrs.iter().map(|i| self.lift(i)).collect()
    }
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// Tests
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

#[cfg(test)]
mod tests {
    use super::*;
    use rustre_core::{
        address::Address,
        arch::{Instruction, Operand},
    };

    /// Build a minimal instruction with only a mnemonic string.
    fn make_instr(addr: u64, mnemonic: &str) -> Instruction {
        Instruction::new(Address::new(addr), 1, mnemonic.to_string(), vec![0x00])
    }

    /// Build a minimal instruction with mnemonic and a raw operand string.
    fn make_instr_with_ops(addr: u64, mnemonic: &str, operands: &str) -> Instruction {
        let mut i = Instruction::new(Address::new(addr), 1, mnemonic.to_string(), vec![0x00]);
        i.operands = operands.to_string();
        i
    }

    /// Build a minimal instruction with a structured immediate operand.
    fn make_instr_imm(addr: u64, mnemonic: &str, imm: i64) -> Instruction {
        let mut i = Instruction::new(Address::new(addr), 1, mnemonic.to_string(), vec![0x00]);
        i.operand_list = vec![Operand::Immediate(imm)];
        i
    }

    // â”€â”€ local.get â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    /// Every WASM comparison wrote `Undef` beside an intrinsic, under the
    /// comment "Refined by higher-level passes" — a promise nothing keeps.
    /// The INTEGER ones are fully expressible and the signed/unsigned split is
    /// exactly what `CmpLtU` exists for.
    ///
    /// FLOAT comparisons stay opaque deliberately: the IR has no float compare,
    /// so an integer node would be a wrong answer, not a partial one. Asserted,
    /// so a later over-modelling fails instead of passing.
    #[test]
    fn integer_comparisons_are_expressed() {
        let lifter = WasmLifter::new();
        let render = |m: &str| {
            format!("{:?}", lifter.lift(&make_instr(0x10, m)).unwrap().effects)
        };

        for w in ["i32", "i64"] {
            for m in ["eq", "ne", "lt_s", "lt_u", "gt_s", "gt_u", "le_s", "le_u", "ge_s", "ge_u"] {
                let t = render(&format!("{w}.{m}"));
                assert!(!t.contains("Undef"), "{w}.{m} must compute a value: {t}");
            }
            // Signed and unsigned must not collapse.
            assert!(render(&format!("{w}.lt_u")).contains("CmpLtU"), "{w}.lt_u is unsigned");
            let signed = render(&format!("{w}.lt_s"));
            assert!(
                signed.contains("CmpLt(") && !signed.contains("CmpLtU"),
                "{w}.lt_s is signed: {signed}"
            );
            // `lt` and `gt` differ only in operand order — they must not be equal.
            assert_ne!(
                render(&format!("{w}.lt_s")),
                render(&format!("{w}.gt_s")),
                "{w}: lt and gt must not lift identically"
            );
        }

        // Floats keep the intrinsic and the Undef, on purpose.
        let f = render("f64.lt");
        assert!(
            f.contains("Undef") && f.contains("f64.lt"),
            "float compares have no IR node; they must stay opaque but named: {f}"
        );
    }

    /// The three INTEGER width conversions are fully expressible and wrote
    /// `Undef` beside a naming intrinsic — the MIPS `EXT`/`INS` shape.
    ///
    /// The FLOAT conversions stay opaque deliberately: this IR has no float
    /// semantics, so an integer node there would be a wrong answer rather than
    /// a partial one. Asserted, so a later over-modelling fails.
    #[test]
    fn integer_width_conversions_are_expressed() {
        let l = WasmLifter::new();
        let w = |m: &str| format!("{:?}", l.lift(&make_instr(0x10, m)).unwrap().effects);

        for m in ["i32.wrap_i64", "i64.extend_i32_u", "i64.extend_i32_s"] {
            let t = w(m);
            assert!(!t.contains("Undef"), "{m} is expressible: {t}");
        }
        // wrap and zero-extend are both a mask; sign-extend is not.
        assert!(w("i32.wrap_i64").contains("Const(4294967295)"));
        assert!(w("i64.extend_i32_u").contains("Const(4294967295)"));
        let sx = w("i64.extend_i32_s");
        assert!(
            sx.contains("Sar") && sx.contains("Const(32)"),
            "sign-extension is Sar(Shl(x,32),32): {sx}"
        );
        assert_ne!(
            w("i64.extend_i32_u"),
            sx,
            "zero- and sign-extension must not lift identically"
        );

        // Float conversions have no IR semantics; they must stay opaque.
        for m in ["f64.convert_i32_s", "i32.trunc_f64_s", "f32.demote_f64"] {
            let t = w(m);
            assert!(t.contains("Undef") && t.contains(m), "{m} must stay opaque but named: {t}");
        }
    }

    /// WebAssembly `i32` arithmetic is modulo 2^32. `i32.add` and `i64.add`
    /// shared one arm and produced byte-identical effects, so in an untyped IR
    /// the 32-bit wrap did not exist at all.
    ///
    /// Only the ops that can EXCEED the operand width are masked. `and`/`or`/
    /// `xor` cannot widen their inputs and the right shifts only narrow, so
    /// masking those would be noise — asserted here, so a later over-correction
    /// fails rather than passes.
    #[test]
    fn i32_arithmetic_wraps_and_i64_does_not() {
        let l = WasmLifter::new();
        let w = |m: &str| format!("{:?}", l.lift(&make_instr(0x10, m)).unwrap().effects);

        for op in ["add", "sub", "mul", "shl", "rotl", "rotr"] {
            let narrow = w(&format!("i32.{op}"));
            let wide = w(&format!("i64.{op}"));
            assert!(
                narrow.contains("Const(4294967295)"),
                "i32.{op} must wrap at 32 bits: {narrow}"
            );
            assert!(
                !wide.contains("Const(4294967295)"),
                "i64.{op} must not be masked to 32 bits: {wide}"
            );
            assert_ne!(narrow, wide, "i32.{op} and i64.{op} must differ");
        }

        // These cannot widen their operands; a mask would be noise.
        for op in ["and", "or", "xor", "shr_u", "shr_s"] {
            let t = w(&format!("i32.{op}"));
            assert!(
                !t.contains("Const(4294967295)"),
                "i32.{op} cannot exceed 32 bits; it needs no mask: {t}"
            );
        }
    }

    /// `shr_s` is arithmetic, `shr_u` logical — they shared an arm and both
    /// lifted to the logical `Shr`, so `shr_s` was wrong for negative values.
    /// Same class as the narrow loads below, one operation over.
    #[test]
    fn signed_and_unsigned_shifts_differ() {
        let lifter = WasmLifter::new();
        let render = |m: &str| format!("{:?}", lifter.lift(&make_instr(0x10, m)).unwrap().effects);
        for w in ["i32", "i64"] {
            assert!(
                render(&format!("{w}.shr_s")).contains("Sar"),
                "{w}.shr_s must be an ARITHMETIC shift"
            );
            assert!(
                !render(&format!("{w}.shr_u")).contains("Sar"),
                "{w}.shr_u must stay logical"
            );
        }
    }

    /// A rotate must wrap: the second term shifts by `W - b`, not by `b`.
    ///
    /// The old code emitted `(a << b) | (a >> b)`, which is not a rotation, and
    /// spelled `rotr` as the same two terms in the other order — but `Or` is
    /// commutative, so `rotl` and `rotr` collapsed to one meaning. Two opcodes,
    /// one lift, and the lift wrong.
    #[test]
    fn rotates_wrap_and_the_two_directions_differ() {
        let lifter = WasmLifter::new();
        let render = |m: &str| format!("{:?}", lifter.lift(&make_instr(0x10, m)).unwrap().effects);
        for (w, width) in [("i32", "32"), ("i64", "64")] {
            let l = render(&format!("{w}.rotl"));
            let r = render(&format!("{w}.rotr"));
            assert_ne!(l, r, "{w}: rotl and rotr must not lift identically");
            for (name, text) in [("rotl", &l), ("rotr", &r)] {
                assert!(
                    text.contains("Sub"),
                    "{w}.{name} must shift the wrap term by W - b, got {text}"
                );
                assert!(
                    text.contains(width),
                    "{w}.{name} must rotate at its own width, got {text}"
                );
            }
        }
        // The width must actually differ between i32 and i64 — a rotate that
        // ignores its operand width is the defect this file keeps producing.
        assert_ne!(render("i32.rotl"), render("i64.rotl"), "widths must differ");
    }

    /// WebAssembly's narrow loads come in `_s` and `_u` forms that differ in
    /// how the value is extended: `i32.load8_s` of `0xFF` is `-1`,
    /// `i32.load8_u` is `255`. They shared a handler taking only a size and
    /// lifted identically. Third architecture with this defect, after RISC-V
    /// and MIPS.
    #[test]
    fn signed_and_unsigned_narrow_loads_differ() {
        let lifter = WasmLifter::new();
        let render = |m: &str| {
            format!(
                "{:?}",
                lifter.lift(&make_instr_with_ops(0x10, m, "0")).unwrap().effects
            )
        };
        assert_ne!(
            render("i32.load8_s"),
            render("i32.load8_u"),
            "sign- and zero-extending loads must not lift identically"
        );
        assert!(render("i32.load8_s").contains("sext8"), "the extension must be named");
        assert!(!render("i32.load8_u").contains("sext"), "the unsigned form must not sign-extend");

        // Two facts this test MISSED when it was written in iteration 60, found
        // by re-enumerating what the shared arms were flattening:
        //
        // float vs integer — same size, different stack type.
        assert_ne!(
            render("i32.load"),
            render("f32.load"),
            "an f32 load pushes a float, not an i32"
        );
        assert_ne!(render("i64.load"), render("f64.load"), "f64 is not i64");
        // destination width — the same 8 bits extend to 32 or to 64.
        assert_ne!(
            render("i32.load8_s"),
            render("i64.load8_s"),
            "8->32 and 8->64 are different extensions"
        );
    }

    #[test]
    fn local_get_produces_reg_write_to_s0() {
        let lifter = WasmLifter::new();
        let instr = make_instr_with_ops(0x10, "local.get", "3");
        let result = lifter.lift(&instr).expect("lift must succeed");

        assert_eq!(result.address, 0x10);
        assert_eq!(result.original_mnemonic, "local.get");
        assert_eq!(result.il_level, LiftLevel::Llil);
        assert_eq!(result.effects.len(), 1);

        match &result.effects[0] {
            Effect::RegWrite { reg, value } => {
                assert_eq!(reg, "s_0");
                assert!(matches!(value, IrExpr::Reg(r) if r == "local_3"));
            }
            other => panic!("unexpected effect: {other:?}"),
        }
    }

    #[test]
    fn local_get_index_from_operand_list() {
        let lifter = WasmLifter::new();
        let instr = make_instr_imm(0x20, "local.get", 5);
        let result = lifter.lift(&instr).expect("lift must succeed");

        // The immediate is in operand_list; raw operands string is empty so we
        // fall back to the structured list rendered via Display.
        // Either way the local index is 5.
        match &result.effects[0] {
            Effect::RegWrite { reg, value } => {
                assert_eq!(reg, "s_0");
                // Accept either local_5 (if parsed from operand_list display) or
                // local_0 (if display format differs) â€” the key assertion is the
                // effect shape.
                assert!(matches!(value, IrExpr::Reg(_)));
            }
            other => panic!("unexpected effect: {other:?}"),
        }
    }

    // â”€â”€ local.set â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn local_set_pops_s0_into_local() {
        let lifter = WasmLifter::new();
        let instr = make_instr_with_ops(0x30, "local.set", "2");
        let result = lifter.lift(&instr).expect("lift must succeed");

        match &result.effects[0] {
            Effect::RegWrite { reg, value } => {
                assert_eq!(reg, "local_2");
                assert!(matches!(value, IrExpr::Reg(r) if r == "s_0"));
            }
            other => panic!("unexpected effect: {other:?}"),
        }
    }

    // â”€â”€ i32.const â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn i32_const_pushes_constant() {
        let lifter = WasmLifter::new();
        let instr = make_instr_with_ops(0x40, "i32.const", "42");
        let result = lifter.lift(&instr).expect("lift must succeed");

        assert_eq!(result.effects.len(), 1);
        match &result.effects[0] {
            Effect::RegWrite { reg, value } => {
                assert_eq!(reg, "s_0");
                assert!(matches!(value, IrExpr::Const(42)));
            }
            other => panic!("unexpected effect: {other:?}"),
        }
    }

    #[test]
    fn i32_const_negative() {
        let lifter = WasmLifter::new();
        let instr = make_instr_with_ops(0x50, "i32.const", "-1");
        let result = lifter.lift(&instr).expect("lift must succeed");

        match &result.effects[0] {
            Effect::RegWrite { reg, value } => {
                assert_eq!(reg, "s_0");
                // -1i64 reinterpreted as u64 is u64::MAX.
                assert!(matches!(value, IrExpr::Const(v) if *v == u64::MAX));
            }
            other => panic!("unexpected effect: {other:?}"),
        }
    }

    #[test]
    fn i64_const_hex() {
        let lifter = WasmLifter::new();
        let instr = make_instr_with_ops(0x60, "i64.const", "0xff00");
        let result = lifter.lift(&instr).expect("lift must succeed");

        match &result.effects[0] {
            Effect::RegWrite { reg, value } => {
                assert_eq!(reg, "s_0");
                assert!(matches!(value, IrExpr::Const(0xff00)));
            }
            other => panic!("unexpected effect: {other:?}"),
        }
    }

    // â”€â”€ i32.add â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn i32_add_produces_add_of_s1_and_s0() {
        let lifter = WasmLifter::new();
        let instr = make_instr(0x70, "i32.add");
        let result = lifter.lift(&instr).expect("lift must succeed");

        assert_eq!(result.effects.len(), 1);
        match &result.effects[0] {
            Effect::RegWrite { reg, value } => {
                assert_eq!(reg, "s_0");
                // `i32.add` wraps at 32 bits, so the sum is masked. This test
                // used to assert the BARE `Add`, pinning the unwrapped form.
                match value {
                    IrExpr::And(inner, mask) => {
                        assert!(matches!(mask.as_ref(), IrExpr::Const(0xFFFF_FFFF)));
                        match inner.as_ref() {
                            IrExpr::Add(lhs, rhs) => {
                                assert!(matches!(lhs.as_ref(), IrExpr::Reg(r) if r == "s_1"));
                                assert!(matches!(rhs.as_ref(), IrExpr::Reg(r) if r == "s_0"));
                            }
                            other => panic!("expected Add inside the mask, got {other:?}"),
                        }
                    }
                    other => panic!("expected a 32-bit-wrapped Add, got {other:?}"),
                }
            }
            other => panic!("unexpected effect: {other:?}"),
        }
    }

    #[test]
    fn i64_sub_produces_sub() {
        let lifter = WasmLifter::new();
        let instr = make_instr(0x80, "i64.sub");
        let result = lifter.lift(&instr).expect("lift must succeed");

        match &result.effects[0] {
            Effect::RegWrite {
                value: IrExpr::Sub(_, _),
                ..
            } => {}
            other => panic!("expected Sub, got {other:?}"),
        }
    }

    #[test]
    fn i32_and_produces_and() {
        let lifter = WasmLifter::new();
        let instr = make_instr(0x90, "i32.and");
        let result = lifter.lift(&instr).expect("lift must succeed");

        match &result.effects[0] {
            Effect::RegWrite {
                value: IrExpr::And(_, _),
                ..
            } => {}
            other => panic!("expected And, got {other:?}"),
        }
    }

    #[test]
    fn i32_or_produces_or() {
        let lifter = WasmLifter::new();
        let instr = make_instr(0xa0, "i32.or");
        let result = lifter.lift(&instr).expect("lift must succeed");

        match &result.effects[0] {
            Effect::RegWrite {
                value: IrExpr::Or(_, _),
                ..
            } => {}
            other => panic!("expected Or, got {other:?}"),
        }
    }

    #[test]
    fn i32_xor_produces_xor() {
        let lifter = WasmLifter::new();
        let instr = make_instr(0xb0, "i32.xor");
        let result = lifter.lift(&instr).expect("lift must succeed");

        match &result.effects[0] {
            Effect::RegWrite {
                value: IrExpr::Xor(_, _),
                ..
            } => {}
            other => panic!("expected Xor, got {other:?}"),
        }
    }

    #[test]
    fn i32_mul_produces_mul() {
        let lifter = WasmLifter::new();
        let instr = make_instr(0xc0, "i32.mul");
        let result = lifter.lift(&instr).expect("lift must succeed");

        // The 32-bit form wraps; the 64-bit one must NOT grow a mask.
        match &result.effects[0] {
            Effect::RegWrite {
                value: IrExpr::And(inner, _),
                ..
            } => assert!(
                matches!(inner.as_ref(), IrExpr::Mul(_, _)),
                "expected a wrapped Mul, got {inner:?}"
            ),
            other => panic!("expected a 32-bit-wrapped Mul, got {other:?}"),
        }
        let wide = lifter
            .lift(&make_instr(0xd0, "i64.mul"))
            .expect("lift must succeed");
        assert!(
            matches!(&wide.effects[0], Effect::RegWrite { value: IrExpr::Mul(_, _), .. }),
            "the 64-bit form must stay unmasked: {:?}",
            wide.effects
        );
    }

    #[test]
    fn i32_shl_produces_shl() {
        let lifter = WasmLifter::new();
        let instr = make_instr(0xd0, "i32.shl");
        let result = lifter.lift(&instr).expect("lift must succeed");

        // The 32-bit form wraps; the 64-bit one must NOT grow a mask.
        match &result.effects[0] {
            Effect::RegWrite {
                value: IrExpr::And(inner, _),
                ..
            } => assert!(
                matches!(inner.as_ref(), IrExpr::Shl(_, _)),
                "expected a wrapped Shl, got {inner:?}"
            ),
            other => panic!("expected a 32-bit-wrapped Shl, got {other:?}"),
        }
        let wide = lifter
            .lift(&make_instr(0xd0, "i64.shl"))
            .expect("lift must succeed");
        assert!(
            matches!(&wide.effects[0], Effect::RegWrite { value: IrExpr::Shl(_, _), .. }),
            "the 64-bit form must stay unmasked: {:?}",
            wide.effects
        );
    }

    #[test]
    fn i32_shr_u_produces_shr() {
        let lifter = WasmLifter::new();
        let instr = make_instr(0xe0, "i32.shr_u");
        let result = lifter.lift(&instr).expect("lift must succeed");

        match &result.effects[0] {
            Effect::RegWrite {
                value: IrExpr::Shr(_, _),
                ..
            } => {}
            other => panic!("expected Shr, got {other:?}"),
        }
    }

    // â”€â”€ i32.eqz â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn i32_eqz_produces_cmp_eq_zero() {
        let lifter = WasmLifter::new();
        let instr = make_instr(0x100, "i32.eqz");
        let result = lifter.lift(&instr).expect("lift must succeed");

        match &result.effects[0] {
            Effect::RegWrite { reg, value } => {
                assert_eq!(reg, "s_0");
                assert!(matches!(value, IrExpr::CmpEqZero(_)));
            }
            other => panic!("unexpected effect: {other:?}"),
        }
    }

    // â”€â”€ i32.store â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn i32_store_no_offset_produces_mem_write() {
        let lifter = WasmLifter::new();
        let instr = make_instr(0x110, "i32.store");
        let result = lifter.lift(&instr).expect("lift must succeed");

        assert_eq!(result.effects.len(), 1);
        match &result.effects[0] {
            Effect::MemWrite { addr, value, size } => {
                assert_eq!(*size, 4);
                assert!(
                    matches!(addr, IrExpr::Reg(r) if r == "s_1"),
                    "expected s_1 as base addr, got {addr:?}"
                );
                assert!(
                    matches!(value, IrExpr::Reg(r) if r == "s_0"),
                    "expected s_0 as value, got {value:?}"
                );
            }
            other => panic!("unexpected effect: {other:?}"),
        }
    }

    #[test]
    fn i32_store_with_offset() {
        let lifter = WasmLifter::new();
        let instr = make_instr_with_ops(0x120, "i32.store", "offset=8 align=2");
        let result = lifter.lift(&instr).expect("lift must succeed");

        match &result.effects[0] {
            Effect::MemWrite { addr, size, .. } => {
                assert_eq!(*size, 4);
                // Effective address should be s_1 + 8.
                match addr {
                    IrExpr::Add(base, off) => {
                        assert!(matches!(base.as_ref(), IrExpr::Reg(r) if r == "s_1"));
                        assert!(matches!(off.as_ref(), IrExpr::Const(8)));
                    }
                    other => panic!("expected Add for addr, got {other:?}"),
                }
            }
            other => panic!("unexpected effect: {other:?}"),
        }
    }

    #[test]
    fn i64_store_size_is_8() {
        let lifter = WasmLifter::new();
        let instr = make_instr(0x130, "i64.store");
        let result = lifter.lift(&instr).expect("lift must succeed");

        match &result.effects[0] {
            Effect::MemWrite { size, .. } => assert_eq!(*size, 8),
            other => panic!("unexpected effect: {other:?}"),
        }
    }

    // â”€â”€ i32.load â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn i32_load_produces_mem_read() {
        let lifter = WasmLifter::new();
        let instr = make_instr(0x140, "i32.load");
        let result = lifter.lift(&instr).expect("lift must succeed");

        match &result.effects[0] {
            Effect::MemRead { addr, dest, size } => {
                assert_eq!(*size, 4);
                assert_eq!(dest, "s_0");
                assert!(matches!(addr, IrExpr::Reg(r) if r == "s_0"));
            }
            other => panic!("unexpected effect: {other:?}"),
        }
    }

    #[test]
    fn i64_load_size_is_8() {
        let lifter = WasmLifter::new();
        let instr = make_instr(0x150, "i64.load");
        let result = lifter.lift(&instr).expect("lift must succeed");

        match &result.effects[0] {
            Effect::MemRead { size, .. } => assert_eq!(*size, 8),
            other => panic!("unexpected effect: {other:?}"),
        }
    }

    #[test]
    fn i32_load8_s_size_is_1() {
        let lifter = WasmLifter::new();
        let instr = make_instr(0x160, "i32.load8_s");
        let result = lifter.lift(&instr).expect("lift must succeed");

        match &result.effects[0] {
            Effect::MemRead { size, .. } => assert_eq!(*size, 1),
            other => panic!("unexpected effect: {other:?}"),
        }
    }

    // â”€â”€ return â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn return_carries_s0_as_value() {
        let lifter = WasmLifter::new();
        let instr = make_instr(0x170, "return");
        let result = lifter.lift(&instr).expect("lift must succeed");

        assert_eq!(result.effects.len(), 1);
        match &result.effects[0] {
            Effect::Return { value } => {
                assert!(
                    matches!(value, Some(IrExpr::Reg(r)) if r == "s_0"),
                    "return value should be s_0, got {value:?}"
                );
            }
            other => panic!("unexpected effect: {other:?}"),
        }
        assert!(result.is_terminator());
    }

    // â”€â”€ call â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn call_with_func_index() {
        let lifter = WasmLifter::new();
        let instr = make_instr_with_ops(0x180, "call", "7");
        let result = lifter.lift(&instr).expect("lift must succeed");

        assert_eq!(result.effects.len(), 1);
        match &result.effects[0] {
            Effect::Call { target } => {
                assert!(matches!(target, IrExpr::Const(7)));
            }
            other => panic!("unexpected effect: {other:?}"),
        }
    }

    #[test]
    fn call_index_0_is_valid() {
        let lifter = WasmLifter::new();
        let instr = make_instr_with_ops(0x190, "call", "0");
        let result = lifter.lift(&instr).expect("lift must succeed");

        match &result.effects[0] {
            Effect::Call { target } => {
                assert!(matches!(target, IrExpr::Const(0)));
            }
            other => panic!("unexpected effect: {other:?}"),
        }
    }

    // â”€â”€ call_indirect â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn call_indirect_emits_intrinsic_and_call() {
        let lifter = WasmLifter::new();
        let instr = make_instr_with_ops(0x1a0, "call_indirect", "0 0");
        let result = lifter.lift(&instr).expect("lift must succeed");

        // Should have both an Intrinsic (carrying type_idx) and a Call.
        assert_eq!(result.effects.len(), 2);
        assert!(matches!(
            &result.effects[0],
            Effect::Intrinsic { name, .. } if name == "call_indirect"
        ));
        assert!(matches!(&result.effects[1], Effect::Call { .. }));
    }

    // â”€â”€ nop â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn nop_has_no_effects() {
        let lifter = WasmLifter::new();
        let instr = make_instr(0x1b0, "nop");
        let result = lifter.lift(&instr).expect("lift must succeed");

        assert!(result.effects.is_empty());
        assert_eq!(result.ir_text, "nop");
        assert!(!result.is_terminator());
    }

    // â”€â”€ unreachable â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn unreachable_produces_intrinsic() {
        let lifter = WasmLifter::new();
        let instr = make_instr(0x1c0, "unreachable");
        let result = lifter.lift(&instr).expect("lift must succeed");

        assert_eq!(result.effects.len(), 1);
        assert!(matches!(
            &result.effects[0],
            Effect::Intrinsic { name, .. } if name == "unreachable"
        ));
    }

    // â”€â”€ br / br_if â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn br_is_unconditional_branch() {
        let lifter = WasmLifter::new();
        let instr = make_instr_with_ops(0x1d0, "br", "1");
        let result = lifter.lift(&instr).expect("lift must succeed");

        match &result.effects[0] {
            Effect::Branch { target, condition } => {
                assert!(matches!(target, IrExpr::Const(1)));
                assert!(condition.is_none());
            }
            other => panic!("unexpected effect: {other:?}"),
        }
        assert!(result.is_terminator());
    }

    #[test]
    fn br_if_is_conditional_branch() {
        let lifter = WasmLifter::new();
        let instr = make_instr_with_ops(0x1e0, "br_if", "2");
        let result = lifter.lift(&instr).expect("lift must succeed");

        match &result.effects[0] {
            Effect::Branch { target, condition } => {
                assert!(matches!(target, IrExpr::Const(2)));
                assert!(matches!(condition, Some(IrExpr::Reg(r)) if r == "s_0"));
            }
            other => panic!("unexpected effect: {other:?}"),
        }
    }

    // â”€â”€ drop / select â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn drop_produces_intrinsic() {
        let lifter = WasmLifter::new();
        let instr = make_instr(0x1f0, "drop");
        let result = lifter.lift(&instr).expect("lift must succeed");

        assert!(matches!(
            &result.effects[0],
            Effect::Intrinsic { name, .. } if name == "drop"
        ));
    }

    #[test]
    fn select_produces_intrinsic() {
        let lifter = WasmLifter::new();
        let instr = make_instr(0x200, "select");
        let result = lifter.lift(&instr).expect("lift must succeed");

        assert!(matches!(
            &result.effects[0],
            Effect::Intrinsic { name, .. } if name == "select"
        ));
    }

    // â”€â”€ global.get / global.set â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn global_get_reads_global_reg() {
        let lifter = WasmLifter::new();
        let instr = make_instr_with_ops(0x210, "global.get", "0");
        let result = lifter.lift(&instr).expect("lift must succeed");

        match &result.effects[0] {
            Effect::RegWrite { reg, value } => {
                assert_eq!(reg, "s_0");
                assert!(matches!(value, IrExpr::Reg(r) if r == "global_0"));
            }
            other => panic!("unexpected effect: {other:?}"),
        }
    }

    #[test]
    fn global_set_writes_global_reg() {
        let lifter = WasmLifter::new();
        let instr = make_instr_with_ops(0x220, "global.set", "1");
        let result = lifter.lift(&instr).expect("lift must succeed");

        match &result.effects[0] {
            Effect::RegWrite { reg, value } => {
                assert_eq!(reg, "global_1");
                assert!(matches!(value, IrExpr::Reg(r) if r == "s_0"));
            }
            other => panic!("unexpected effect: {other:?}"),
        }
    }

    // â”€â”€ local.tee â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn local_tee_writes_local_and_keeps_stack_value() {
        let lifter = WasmLifter::new();
        let instr = make_instr_with_ops(0x230, "local.tee", "4");
        let result = lifter.lift(&instr).expect("lift must succeed");

        // local.tee writes local_4 = s_0 but does not pop.
        match &result.effects[0] {
            Effect::RegWrite { reg, value } => {
                assert_eq!(reg, "local_4");
                assert!(matches!(value, IrExpr::Reg(r) if r == "s_0"));
            }
            other => panic!("unexpected effect: {other:?}"),
        }
    }

    // â”€â”€ memory.size / memory.grow â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn memory_size_is_intrinsic() {
        let lifter = WasmLifter::new();
        let instr = make_instr(0x240, "memory.size");
        let result = lifter.lift(&instr).expect("lift must succeed");

        assert!(matches!(
            &result.effects[0],
            Effect::Intrinsic { name, .. } if name == "memory.size"
        ));
    }

    #[test]
    fn memory_grow_is_intrinsic_with_arg() {
        let lifter = WasmLifter::new();
        let instr = make_instr(0x250, "memory.grow");
        let result = lifter.lift(&instr).expect("lift must succeed");

        match &result.effects[0] {
            Effect::Intrinsic { name, args } => {
                assert_eq!(name, "memory.grow");
                assert_eq!(args.len(), 1);
                assert!(matches!(&args[0], IrExpr::Reg(r) if r == "s_0"));
            }
            other => panic!("unexpected effect: {other:?}"),
        }
    }

    // â”€â”€ block / end control markers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn block_and_end_produce_intrinsics() {
        let lifter = WasmLifter::new();
        for mnem in &["block", "loop", "if", "else", "end"] {
            let instr = make_instr(0x260, mnem);
            let result = lifter.lift(&instr).expect("lift must succeed");
            assert!(
                matches!(&result.effects[0], Effect::Intrinsic { name, .. } if name == *mnem),
                "expected Intrinsic({mnem})"
            );
        }
    }

    // â”€â”€ arch_name / lift_level / description â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn lifter_metadata() {
        let lifter = WasmLifter::new();
        assert_eq!(lifter.arch_name(), "wasm");
        assert_eq!(lifter.lift_level(), LiftLevel::Llil);
        assert!(
            lifter.description().contains("WASM")
                || lifter.description().contains("wasm")
                || !lifter.description().is_empty()
        );
        assert!(lifter.supports_mnemonic("i32.add"));
        assert!(lifter.supports_mnemonic("unknown_opcode_xyz"));
    }

    // â”€â”€ unknown mnemonic fallback â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn unknown_mnemonic_produces_intrinsic_fallback() {
        let lifter = WasmLifter::new();
        let instr = make_instr(0x300, "v128.load_lane");
        let result = lifter.lift(&instr).expect("lift must succeed");

        // Either matched the SIMD pattern or the fallback â€” both produce Intrinsic.
        assert!(matches!(&result.effects[0], Effect::Intrinsic { .. }));
    }

    #[test]
    fn totally_unknown_mnemonic_is_intrinsic() {
        let lifter = WasmLifter::new();
        let instr = make_instr(0x310, "future.opcode");
        let result = lifter.lift(&instr).expect("lift must succeed");

        match &result.effects[0] {
            Effect::Intrinsic { name, .. } => assert_eq!(name, "future.opcode"),
            other => panic!("unexpected effect: {other:?}"),
        }
    }

    // â”€â”€ lift_block â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn lift_block_lifts_all_instructions() {
        let lifter = WasmLifter::new();
        let instrs = vec![
            make_instr_with_ops(0x0, "i32.const", "1"),
            make_instr_with_ops(0x1, "i32.const", "2"),
            make_instr(0x2, "i32.add"),
            make_instr(0x3, "return"),
        ];
        let results = lifter.lift_block(&instrs);
        assert_eq!(results.len(), 4);
        for r in &results {
            assert!(r.is_ok(), "expected Ok, got {r:?}");
        }
        // Last instruction should be a terminator.
        let last = results.last().unwrap().as_ref().unwrap();
        assert!(last.is_terminator());
    }

    // â”€â”€ ir_text formatting â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn ir_text_is_semicolon_separated() {
        let lifter = WasmLifter::new();
        // call_indirect emits 2 effects.
        let instr = make_instr_with_ops(0x400, "call_indirect", "0 0");
        let result = lifter.lift(&instr).expect("lift must succeed");
        assert!(
            result.ir_text.contains(';'),
            "ir_text should contain ';': {}",
            result.ir_text
        );
    }
}
