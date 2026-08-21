//! Semantics-validation harness for the x86-64 LLIL lifter.
//!
//! Mode: NATIVE-EXECUTION ORACLE (Remill/Rizin style). Each covered
//! instruction encoding is executed twice per input state:
//!
//!   1. through a tiny LLIL interpreter over the IL produced by
//!      `rustre_arch_x86::lift_to_llil_with_bits(.., 64)`, and
//!   2. natively on the host CPU via a hand-assembled JIT stub placed in
//!      `VirtualAlloc(PAGE_EXECUTE_READWRITE)` memory (no extra crate deps;
//!      `kernel32` is always linked on windows-msvc).
//!
//! Final GPRs (all except RSP) and the per-instruction DEFINED flags are
//! compared over randomized + edge-value input states. Flags that the Intel
//! SDM leaves undefined for an instruction (e.g. AF after logic ops, OF after
//! multi-bit shifts) are excluded via a per-case defined-flags list, as are
//! flags the lifter deliberately models as opaque intrinsics (see
//! LIMITATIONS below).
//!
//! The native path is gated on `cfg(all(windows, target_arch = "x86_64"))`;
//! on any other host the differential test is skipped (the interpreter
//! self-tests still run). This crate is developed on Windows x86-64, so the
//! native mode is the one that actually executes here.
//!
//! ─────────────────────────────────────────────────────────────────────────
//! FIXED: ADC/SBB carry-in flags (crates/rustre-arch-x86/src/lift.rs,
//! `X86Lifter::lift_add_sub`). The incoming CF used to be folded into the
//! second operand (`b' = b + CF`) before the CF/OF/AF flag predicates were
//! built, which lost information at the `b == MAX && CF == 1` corner. CF/AF
//! are now computed via full-adder/full-subtractor identities over the
//! original `a`, `b`, and carry-in, and OF uses the original `b`. All flags
//! are compared for ADC/SBB regardless of the input CF
//! (`adc_carry_in_corner_is_fixed` pins the fixed CF value).
//!
//! LIMITATIONS OF THE IL (documented, not bugs — modeled as intrinsics):
//!   - Shift CF is `Intrinsic("shift_carry")` (src/lift.rs:1646): the last
//!     bit shifted out is not expressible without the count, so CF is not
//!     compared for SHL/SHR/SAR. OF after shifts is undefined for counts > 1
//!     per the SDM and the lifter never writes it, so it is excluded too.
//!   - IMUL CF/OF are `Intrinsic("imul_overflow")` (src/lift.rs:1401), so
//!     no flags are compared for IMUL (SF/ZF/AF/PF are SDM-undefined anyway).

#![cfg(test)]

use std::collections::{HashMap, HashSet};

use iced_x86::{Decoder, DecoderOptions, Instruction as IcedInstruction};
use rustre_arch_x86::lift_to_llil_with_bits;
use rustre_il_llil::{LlilAnnotatedInstr, LlilExpr, LlilInstruction, LlilRegister, Size};

// ───────────────────────────────────────────────────────────────────────────
// Small deterministic PRNG (SplitMix64) — no external deps.
// ───────────────────────────────────────────────────────────────────────────

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
}

// ───────────────────────────────────────────────────────────────────────────
// LLIL interpreter
// ───────────────────────────────────────────────────────────────────────────

const FLAG_NAMES: [&str; 6] = ["cf", "pf", "af", "zf", "sf", "of"];

/// Interpreter CPU state. Registers are stored as full 64-bit values keyed by
/// their canonical 64-bit name; sub-register reads/writes go through
/// `reg_info` (with the x86-64 rule that 32-bit writes zero the upper half).
#[derive(Clone)]
struct IState {
    regs: HashMap<String, u64>,
    temps: HashMap<u32, u64>,
    flags: HashMap<String, u8>,
    /// Snapshot of `flags` taken at the start of the current machine
    /// instruction. `Flag(..)` reads resolve here so that all SetFlag sources
    /// within one instruction see the pre-instruction flag state (x86 flag
    /// updates are parallel, not sequential). This matters for ADC/SBB, whose
    /// OF/AF expressions reference the carry-IN `Flag("cf")` even though the
    /// lifter emits the CF update earlier in the same instruction's IL.
    flags_in: HashMap<String, u8>,
    /// Flags written from an opaque intrinsic — value unknown to the IL.
    unknown_flags: HashSet<String>,
    mem: HashMap<u64, u8>,
}

#[derive(Debug)]
#[allow(dead_code)] // String payload is read via the Debug impl in assert msgs.
struct Unsupported(String);

type EvalResult = Result<u64, Unsupported>;

fn mask(size: Size) -> u64 {
    match size.bits() {
        64 => u64::MAX,
        b => (1u64 << b) - 1,
    }
}

fn sext(v: u64, size: Size) -> i64 {
    let b = size.bits() as u32;
    if b >= 64 {
        v as i64
    } else {
        ((v << (64 - b)) as i64) >> (64 - b)
    }
}

/// Sub-register layout: canonical 64-bit parent, bit shift, width in bits.
fn reg_info(name: &str) -> Option<(String, u32, u32)> {
    const LEGACY: [&str; 8] = ["ax", "bx", "cx", "dx", "si", "di", "bp", "sp"];
    let full = |s: &str| (format!("r{s}"), 0, 64);
    // r8..r15 family
    if let Some(num) = name
        .strip_prefix('r')
        .and_then(|r| r.trim_end_matches(['d', 'w', 'l', 'b']).parse::<u8>().ok())
        && (8..=15).contains(&num) {
            let base = format!("r{num}");
            let bits = match name.chars().last().unwrap() {
                'd' => 32,
                'w' => 16,
                'l' | 'b' => 8,
                _ => 64,
            };
            return Some((base, 0, bits));
        }
    if let Some(rest) = name.strip_prefix('r')
        && LEGACY.contains(&rest) {
            return Some(full(rest));
        }
    if let Some(rest) = name.strip_prefix('e')
        && LEGACY.contains(&rest) {
            return Some((format!("r{rest}"), 0, 32));
        }
    if LEGACY.contains(&name) {
        return Some((format!("r{name}"), 0, 16));
    }
    match name {
        "al" => Some(("rax".into(), 0, 8)),
        "bl" => Some(("rbx".into(), 0, 8)),
        "cl" => Some(("rcx".into(), 0, 8)),
        "dl" => Some(("rdx".into(), 0, 8)),
        "spl" => Some(("rsp".into(), 0, 8)),
        "bpl" => Some(("rbp".into(), 0, 8)),
        "sil" => Some(("rsi".into(), 0, 8)),
        "dil" => Some(("rdi".into(), 0, 8)),
        "ah" => Some(("rax".into(), 8, 8)),
        "bh" => Some(("rbx".into(), 8, 8)),
        "ch" => Some(("rcx".into(), 8, 8)),
        "dh" => Some(("rdx".into(), 8, 8)),
        _ => None,
    }
}

impl IState {
    fn new() -> Self {
        let mut flags = HashMap::new();
        for f in FLAG_NAMES {
            flags.insert(f.to_string(), 0);
        }
        flags.insert("df".to_string(), 0);
        Self {
            regs: HashMap::new(),
            temps: HashMap::new(),
            flags_in: flags.clone(),
            flags,
            unknown_flags: HashSet::new(),
            mem: HashMap::new(),
        }
    }

    fn read_named(&self, name: &str) -> Result<u64, Unsupported> {
        let (base, shift, bits) = reg_info(name)
            .ok_or_else(|| Unsupported(format!("register read: {name}")))?;
        let full = self.regs.get(&base).copied().unwrap_or(0);
        let m = if bits == 64 { u64::MAX } else { (1u64 << bits) - 1 };
        Ok((full >> shift) & m)
    }

    fn write_named(&mut self, name: &str, bits_hint: u32, value: u64) -> Result<(), Unsupported> {
        let (base, shift, bits) = reg_info(name)
            .ok_or_else(|| Unsupported(format!("register write: {name}")))?;
        let bits = bits.min(bits_hint.max(1));
        let old = self.regs.get(&base).copied().unwrap_or(0);
        let new = match bits {
            64 => value,
            // x86-64 rule: writing a 32-bit sub-register zeroes bits 63:32.
            32 => value & 0xFFFF_FFFF,
            b => {
                let m = ((1u64 << b) - 1) << shift;
                (old & !m) | ((value << shift) & m)
            }
        };
        self.regs.insert(base, new);
        Ok(())
    }

    fn read_reg(&self, reg: &LlilRegister, size: Size) -> EvalResult {
        match reg {
            LlilRegister::Temporary(id) => {
                Ok(self.temps.get(id).copied().unwrap_or(0) & mask(size))
            }
            LlilRegister::Concrete(name) => Ok(self.read_named(name)? & mask(size)),
        }
    }

    fn write_reg(&mut self, reg: &LlilRegister, size: Size, value: u64) -> Result<(), Unsupported> {
        match reg {
            LlilRegister::Temporary(id) => {
                self.temps.insert(*id, value & mask(size));
                Ok(())
            }
            LlilRegister::Concrete(name) => {
                self.write_named(name, size.bits() as u32, value & mask(size))
            }
        }
    }

    fn read_mem(&self, addr: u64, size: Size) -> u64 {
        let mut v = 0u64;
        for i in 0..size.bytes().min(8) {
            let b = self.mem.get(&addr.wrapping_add(i as u64)).copied().unwrap_or(0);
            v |= u64::from(b) << (8 * i);
        }
        v
    }

    fn write_mem(&mut self, addr: u64, size: Size, value: u64) {
        for i in 0..size.bytes().min(8) {
            self.mem
                .insert(addr.wrapping_add(i as u64), (value >> (8 * i)) as u8);
        }
    }

    fn eval(&self, e: &LlilExpr) -> EvalResult {
        use LlilExpr as E;
        let bin = |l: &LlilExpr, r: &LlilExpr| -> Result<(u64, u64), Unsupported> {
            Ok((self.eval(l)?, self.eval(r)?))
        };
        match e {
            E::Const { value, size } => Ok(*value & mask(*size)),
            E::RegisterRef { reg, size } => self.read_reg(reg, *size),
            E::Flag(name) => Ok(u64::from(
                self.flags_in.get(name.as_str()).copied().unwrap_or(0),
            )),
            E::Load { addr, size } => {
                let a = self.eval(addr)?;
                Ok(self.read_mem(a, *size))
            }
            E::AddT(l, r, s) | E::Add { left: l, right: r, size: s } => {
                let (a, b) = bin(l, r)?;
                Ok(a.wrapping_add(b) & mask(*s))
            }
            E::SubT(l, r, s) | E::Sub { left: l, right: r, size: s } => {
                let (a, b) = bin(l, r)?;
                Ok(a.wrapping_sub(b) & mask(*s))
            }
            E::MulT(l, r, s) | E::Mul { left: l, right: r, size: s } => {
                let (a, b) = bin(l, r)?;
                Ok(a.wrapping_mul(b) & mask(*s))
            }
            E::DivU(l, r, s) => {
                let (a, b) = bin(l, r)?;
                if b == 0 {
                    return Err(Unsupported("div by zero".into()));
                }
                Ok((a / b) & mask(*s))
            }
            E::DivS(l, r, s) => {
                let (a, b) = bin(l, r)?;
                let (a, b) = (sext(a, *s), sext(b, *s));
                if b == 0 {
                    return Err(Unsupported("div by zero".into()));
                }
                Ok((a.wrapping_div(b) as u64) & mask(*s))
            }
            E::ModU(l, r, s) => {
                let (a, b) = bin(l, r)?;
                if b == 0 {
                    return Err(Unsupported("mod by zero".into()));
                }
                Ok((a % b) & mask(*s))
            }
            E::ModS(l, r, s) => {
                let (a, b) = bin(l, r)?;
                let (a, b) = (sext(a, *s), sext(b, *s));
                if b == 0 {
                    return Err(Unsupported("mod by zero".into()));
                }
                Ok((a.wrapping_rem(b) as u64) & mask(*s))
            }
            E::Neg(v, s) => Ok(self.eval(v)?.wrapping_neg() & mask(*s)),
            E::Not(v, s) => Ok(!self.eval(v)? & mask(*s)),
            E::And(l, r, s) => {
                let (a, b) = bin(l, r)?;
                Ok((a & b) & mask(*s))
            }
            E::Or(l, r, s) => {
                let (a, b) = bin(l, r)?;
                Ok((a | b) & mask(*s))
            }
            E::Xor(l, r, s) => {
                let (a, b) = bin(l, r)?;
                Ok((a ^ b) & mask(*s))
            }
            E::ShlT(l, r, s) | E::Shl { value: l, shift: r, size: s } => {
                let (a, b) = bin(l, r)?;
                let bits = s.bits() as u64;
                Ok(if b >= bits { 0 } else { (a << b) & mask(*s) })
            }
            E::Shr(l, r, s) => {
                let (a, b) = bin(l, r)?;
                let bits = s.bits() as u64;
                Ok(if b >= bits { 0 } else { (a & mask(*s)) >> b })
            }
            E::Sar(l, r, s) => {
                let (a, b) = bin(l, r)?;
                let bits = s.bits() as u64;
                let av = sext(a, *s);
                let sh = b.min(bits - 1);
                Ok(((av >> sh) as u64) & mask(*s))
            }
            E::Rol(l, r, s) => {
                let (a, b) = bin(l, r)?;
                let bits = s.bits() as u32;
                let c = (b as u32) % bits;
                let a = a & mask(*s);
                if c == 0 {
                    Ok(a)
                } else {
                    Ok(((a << c) | (a >> (bits - c))) & mask(*s))
                }
            }
            E::Ror(l, r, s) => {
                let (a, b) = bin(l, r)?;
                let bits = s.bits() as u32;
                let c = (b as u32) % bits;
                let a = a & mask(*s);
                if c == 0 {
                    Ok(a)
                } else {
                    Ok(((a >> c) | (a << (bits - c))) & mask(*s))
                }
            }
            E::CmpEq(l, r) => cmp_common(self, l, r, |a, b, _, _| a == b),
            E::CmpNe(l, r) => cmp_common(self, l, r, |a, b, _, _| a != b),
            E::CmpUlt(l, r) => cmp_common(self, l, r, |a, b, _, _| a < b),
            E::CmpUle(l, r) => cmp_common(self, l, r, |a, b, _, _| a <= b),
            E::CmpUgt(l, r) => cmp_common(self, l, r, |a, b, _, _| a > b),
            E::CmpUge(l, r) => cmp_common(self, l, r, |a, b, _, _| a >= b),
            E::CmpSlt(l, r) => cmp_common(self, l, r, |_, _, a, b| a < b),
            E::CmpSle(l, r) => cmp_common(self, l, r, |_, _, a, b| a <= b),
            E::CmpSgt(l, r) => cmp_common(self, l, r, |_, _, a, b| a > b),
            E::CmpSge(l, r) => cmp_common(self, l, r, |_, _, a, b| a >= b),
            E::ZeroExtend { expr, from, to } => Ok(self.eval(expr)? & mask(*from) & mask(*to)),
            E::SignExtend { expr, from, to } => {
                Ok((sext(self.eval(expr)? & mask(*from), *from) as u64) & mask(*to))
            }
            E::LowPart { expr, to } => Ok(self.eval(expr)? & mask(*to)),
            E::CondExpr { cond, true_val, false_val, size } => {
                let c = self.eval(cond)?;
                let v = if c != 0 {
                    self.eval(true_val)?
                } else {
                    self.eval(false_val)?
                };
                Ok(v & mask(*size))
            }
            E::Intrinsic { name, args, .. } if name == "parity" => {
                // x86 PF: set if the LOW BYTE of the result has even parity.
                let v = self.eval(&args[0])?;
                Ok(u64::from((v as u8).count_ones().is_multiple_of(2)))
            }
            // ── Bit-scan / bit-count intrinsics ──────────────────────────
            //
            // Added 2026-07-23. Before this the interpreter modelled exactly ONE
            // intrinsic (`parity`), and any other made the whole case
            // `Unsupported` — which is the STRUCTURAL reason this oracle covered
            // ~34 of the ~1839 mnemonics `lift.rs` handles. "Lift to an opaque
            // intrinsic" was, in effect, the decision to opt out of hardware
            // validation, and that is where earlier sessions found real defects
            // (the inverted BLSR carry, the mul/imul high half).
            //
            // Each of these has an exact, checkable definition, so modelling
            // them costs nothing in fidelity and buys the whole bit-scan family
            // a differential test against the real CPU.
            E::Intrinsic { name, args, result_size } if name == "bsf" || name == "bsr" => {
                // BSF/BSR: index of the lowest/highest set bit. UNDEFINED when
                // the source is zero — the caller (`interp_supports`/the
                // differential) must not compare that case, so refuse it rather
                // than invent a value.
                let v = self.eval(&args[0])? & mask(*result_size);
                if v == 0 {
                    return Err(Unsupported(format!("{name} of zero is architecturally undefined")));
                }
                Ok(u64::from(if name == "bsf" { v.trailing_zeros() } else { 63 - v.leading_zeros() }))
            }
            E::Intrinsic { name, args, result_size } if name == "popcnt" => {
                Ok(u64::from((self.eval(&args[0])? & mask(*result_size)).count_ones()))
            }
            E::Intrinsic { name, args, result_size } if name == "tzcnt" || name == "lzcnt" => {
                // Unlike BSF/BSR these are DEFINED for a zero source: both
                // return the operand width (SDM/APM), which is exactly why they
                // exist as separate instructions.
                let width = u32::try_from(result_size.bits()).unwrap_or(64);
                let m = mask(*result_size);
                let v = self.eval(&args[0])? & m;
                if v == 0 {
                    return Ok(u64::from(width));
                }
                Ok(u64::from(if name == "tzcnt" {
                    v.trailing_zeros()
                } else {
                    // Count leading zeros WITHIN the operand width, not within u64.
                    v.leading_zeros() - (64 - width)
                }))
            }
            // ── Double-precision shift (SHLD / SHRD) ─────────────────────
            //
            // `lift_double_shift` (lift.rs:4535) emits
            // `Intrinsic { name: "shld"|"shrd", args: [dst, src, count] }`.
            // Both have an exact definition, so modelling them is lossless:
            //   SHLD dst,src,c -> (dst << c) | (src >> (width - c))
            //   SHRD dst,src,c -> (dst >> c) | (src << (width - c))
            // The count is already masked to 5/6 bits by `mask_shift_count`
            // before it reaches here (that masking is itself pinned by
            // `shift_counts_are_masked_per_apm`).
            //
            // A count of 0 leaves the destination UNCHANGED and, per the SDM,
            // touches no flags — importantly it must NOT be treated as a
            // width-sized shift, which is where a naive `width - c` would
            // shift by the full width and produce garbage.
            E::Intrinsic { name, args, result_size } if name == "shld" || name == "shrd" => {
                let width = u32::try_from(result_size.bits()).unwrap_or(64);
                let m = mask(*result_size);
                let dst = self.eval(&args[0])? & m;
                let src = self.eval(&args[1])? & m;
                let c = u32::try_from(self.eval(&args[2])? & u64::from(width - 1)).unwrap_or(0);
                if c == 0 {
                    return Ok(dst);
                }
                let v = if name == "shld" {
                    (dst << c) | (src >> (width - c))
                } else {
                    (dst >> c) | (src << (width - c))
                };
                Ok(v & m)
            }
            E::Intrinsic { name, .. } => Err(Unsupported(format!("intrinsic {name}"))),
            other => Err(Unsupported(format!("expr {other}"))),
        }
    }

    /// Execute one lifted machine instruction (its whole LLIL sequence).
    fn run(&mut self, llil: &[LlilAnnotatedInstr]) -> Result<(), Unsupported> {
        use LlilInstruction as I;
        // Parallel flag semantics: freeze the carry-in / flag-in snapshot.
        self.flags_in = self.flags.clone();
        for ai in llil {
            match &ai.instr {
                I::Nop => {}
                I::SetReg { dest, size, value } => {
                    let v = self.eval(value)?;
                    self.write_reg(dest, *size, v)?;
                }
                I::SetRegSplit { high, low, src } => {
                    // The source is the DOUBLE-WIDTH result (`double_size(size)`
                    // in `lift_mul`/`lift_div`), split across two half-width
                    // registers: edx:eax, dx:ax, rdx:rax.
                    //
                    // This used to refuse EVERY SetRegSplit on the grounds that
                    // a double-width product "is not representable in a single
                    // u64". That is true only for the 64-bit forms, whose
                    // product is 128 bits. For 8/16/32-bit operands the doubled
                    // result is 16/32/64 bits and fits a u64 exactly — so the
                    // blanket refusal excluded `mul ebx`, `imul ebx`, `div ebx`
                    // and friends for no reason, leaving the widening-multiply
                    // family (where earlier sessions found real high-half
                    // defects) with no hardware validation at all.
                    let v = self.eval(src)?;
                    let s = src.result_size();
                    if s.bits() > 64 {
                        return Err(Unsupported(
                            "SetRegSplit wider than 64 bits (128-bit product)".into(),
                        ));
                    }
                    let half_bytes = s.bytes() / 2;
                    let Ok(half) = Size::try_from(half_bytes) else {
                        return Err(Unsupported(format!("SetRegSplit half-size of {s:?}")));
                    };
                    let half_bits = u32::try_from(half_bytes * 8).unwrap_or(32);
                    let lo_mask = if half_bits >= 64 { u64::MAX } else { (1u64 << half_bits) - 1 };
                    self.write_reg(low, half, v & lo_mask)?;
                    self.write_reg(high, half, v >> half_bits)?;
                }
                I::SetFlag { name, src } => if let Ok(v) = self.eval(src) {
                    self.flags.insert(name.clone(), u8::from(v != 0));
                    self.unknown_flags.remove(name);
                } else {
                    // Opaque intrinsic (shift_carry, imul_overflow, ...):
                    // the IL declares the flag written but not its value.
                    self.flags.remove(name);
                    self.unknown_flags.insert(name.clone());
                },
                I::Store { addr, size, value } => {
                    let a = self.eval(addr)?;
                    let v = self.eval(value)?;
                    self.write_mem(a, *size, v);
                }
                I::Load { dest, size, addr } => {
                    let a = self.eval(addr)?;
                    let v = self.read_mem(a, *size);
                    self.write_reg(dest, *size, v)?;
                }
                I::Push { size, src } => {
                    let v = self.eval(src)?;
                    let sp = self.read_named("rsp")?.wrapping_sub(size.bytes() as u64);
                    self.write_named("rsp", 64, sp)?;
                    self.write_mem(sp, *size, v);
                }
                I::Pop { dest, size } => {
                    let sp = self.read_named("rsp")?;
                    let v = self.read_mem(sp, *size);
                    self.write_reg(dest, *size, v)?;
                    self.write_named("rsp", 64, sp.wrapping_add(size.bytes() as u64))?;
                }
                other => return Err(Unsupported(format!("instruction {other:?}"))),
            }
        }
        Ok(())
    }
}

fn cmp_common(
    st: &IState,
    l: &LlilExpr,
    r: &LlilExpr,
    f: impl Fn(u64, u64, i64, i64) -> bool,
) -> EvalResult {
    let size = l.result_size();
    let a = st.eval(l)? & mask(size);
    let b = st.eval(r)? & mask(size);
    Ok(u64::from(f(a, b, sext(a, size), sext(b, size))))
}

// ───────────────────────────────────────────────────────────────────────────
// Native oracle (Windows x86-64 JIT)
// ───────────────────────────────────────────────────────────────────────────

#[cfg(all(windows, target_arch = "x86_64"))]
mod native {
    /// Context layout: index = machine register number (rax=0, rcx=1, rdx=2,
    /// rbx=3, rbp=5, rsi=6, rdi=7, r8..r15 = 8..15). Slot 4 (rsp's number)
    /// holds RFLAGS instead — RSP is never loaded or stored by the stub.
    #[repr(C, align(16))]
    pub struct Ctx(pub [u64; 16]);

    pub const FLAGS_SLOT: usize = 4;
    /// CF | PF | AF | ZF | SF | OF
    pub const FLAG_MASK: u64 = 0x1 | 0x4 | 0x10 | 0x40 | 0x80 | 0x800;
    /// Reserved bit 1 always set; IF set (user mode).
    pub const RFLAGS_BASE: u64 = 0x202;

    unsafe extern "system" {
        fn VirtualAlloc(addr: *mut u8, size: usize, ty: u32, prot: u32) -> *mut u8;
        fn VirtualFree(addr: *mut u8, size: usize, ty: u32) -> i32;
    }
    const MEM_COMMIT_RESERVE: u32 = 0x3000;
    const MEM_RELEASE: u32 = 0x8000;
    const PAGE_EXECUTE_READWRITE: u32 = 0x40;

    fn mov_load(buf: &mut Vec<u8>, reg: u8) {
        // mov r64, [rcx + 8*reg]
        let rex = 0x48 | u8::from(reg >= 8) << 2;
        buf.extend([rex, 0x8B, 0x40 | ((reg & 7) << 3) | 0x01, 8 * reg]);
    }

    fn mov_store(buf: &mut Vec<u8>, reg: u8) {
        // mov [rax + 8*reg], r64
        let rex = 0x48 | u8::from(reg >= 8) << 2;
        buf.extend([rex, 0x89, 0x40 | ((reg & 7) << 3), 8 * reg]);
    }

    /// Build the trampoline: save nonvolatiles, load flags + GPRs from the
    /// context (pointer arrives in RCX per Windows x64 ABI), run the target
    /// instruction, store GPRs + flags back, restore, ret.
    fn build_stub(instr: &[u8]) -> Vec<u8> {
        let mut b: Vec<u8> = Vec::with_capacity(160 + instr.len());
        // push rbx/rbp/rsi/rdi/r12-r15 ; push rcx (ctx)
        b.extend([0x53, 0x55, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x51]);
        // mov rax, [rcx+32] ; push rax ; popfq   (load input RFLAGS)
        b.extend([0x48, 0x8B, 0x41, 0x20, 0x50, 0x9D]);
        // load GPRs (rcx last, since it is the context base)
        for r in [0u8, 2, 3, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15] {
            mov_load(&mut b, r);
        }
        mov_load(&mut b, 1);
        // the instruction under test
        b.extend_from_slice(instr);
        // pushfq ; push rax ; mov rax, [rsp+16]  (rax := ctx)
        b.extend([0x9C, 0x50, 0x48, 0x8B, 0x44, 0x24, 0x10]);
        for r in [1u8, 2, 3, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15] {
            mov_store(&mut b, r);
        }
        // mov rbx, [rsp] ; mov [rax+0], rbx      (result RAX)
        b.extend([0x48, 0x8B, 0x1C, 0x24, 0x48, 0x89, 0x58, 0x00]);
        // mov rbx, [rsp+8] ; mov [rax+32], rbx   (result RFLAGS)
        b.extend([0x48, 0x8B, 0x5C, 0x24, 0x08, 0x48, 0x89, 0x58, 0x20]);
        // add rsp, 24 ; pop r15..r12, rdi, rsi, rbp, rbx ; ret
        b.extend([0x48, 0x83, 0xC4, 0x18]);
        b.extend([0x41, 0x5F, 0x41, 0x5E, 0x41, 0x5D, 0x41, 0x5C, 0x5F, 0x5E, 0x5D, 0x5B, 0xC3]);
        b
    }

    pub struct Jit {
        code: *mut u8,
        len: usize,
    }

    impl Jit {
        pub fn new(instr: &[u8]) -> Self {
            let stub = build_stub(instr);
            unsafe {
                let p = VirtualAlloc(
                    std::ptr::null_mut(),
                    stub.len(),
                    MEM_COMMIT_RESERVE,
                    PAGE_EXECUTE_READWRITE,
                );
                assert!(!p.is_null(), "VirtualAlloc failed");
                std::ptr::copy_nonoverlapping(stub.as_ptr(), p, stub.len());
                Self { code: p, len: stub.len() }
            }
        }

        /// Execute the instruction over the given context in place.
        pub fn run(&self, ctx: &mut Ctx) {
            let _ = self.len;
            unsafe {
                let f: unsafe extern "C" fn(*mut Ctx) = std::mem::transmute(self.code);
                f(ctx);
            }
        }
    }

    impl Drop for Jit {
        fn drop(&mut self) {
            unsafe {
                VirtualFree(self.code, 0, MEM_RELEASE);
            }
        }
    }
}

// ───────────────────────────────────────────────────────────────────────────
// Test-case table
// ───────────────────────────────────────────────────────────────────────────

/// GPRs compared between the two oracles (everything except RSP/RIP).
const CMP_REGS: [&str; 15] = [
    "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "r8", "r9", "r10", "r11", "r12", "r13",
    "r14", "r15",
];

/// Machine-encoding register numbers matching `CMP_REGS` (for the JIT ctx).
const CMP_REG_NUMS: [usize; 15] = [0, 3, 1, 2, 6, 7, 5, 8, 9, 10, 11, 12, 13, 14, 15];

struct Case {
    name: &'static str,
    bytes: &'static [u8],
    /// Flags with SDM-defined values after this instruction, restricted to
    /// those the lifter models concretely (see LIMITATIONS at the top).
    defined_flags: &'static [&'static str],
    /// Optional per-case repair of an input state that would FAULT on real
    /// silicon.
    ///
    /// The input grid is shared by every case, which is what kept DIV/IDIV out
    /// of this harness: a zero divisor, or a quotient too large for the
    /// destination, raises #DE, and #DE inside the JIT stub takes the whole
    /// test process down — so the strongest oracle in the repo had no coverage
    /// of an instruction family the lifter does implement.
    ///
    /// A guard nudges the state into the legal domain rather than skipping it,
    /// so the case still runs across the full grid. It must only ever WIDEN
    /// legality: a guard that pins inputs to one value would turn the case into
    /// a single-point check wearing a grid's clothing.
    guard: Option<fn(&mut InputState)>,
}

const ALL: &[&str] = &["cf", "pf", "af", "zf", "sf", "of"];
const LOGIC: &[&str] = &["cf", "pf", "zf", "sf", "of"]; // AF undefined (SDM)
const INCDEC: &[&str] = &["pf", "af", "zf", "sf", "of"]; // CF untouched
const SHIFT: &[&str] = &["pf", "zf", "sf"]; // CF: IL intrinsic; OF undef (cnt>1); AF undef
const NONE: &[&str] = &[];
/// BT/BTS/BTR/BTC define CF only; OF/SF/ZF/AF/PF are undefined (SDM vol.2).
const CF_ONLY: &[&str] = &["cf"];

fn cases() -> Vec<Case> {
    let c = |name, bytes, defined_flags| Case { name, bytes, defined_flags, guard: None };
    let cg = |name, bytes, defined_flags, guard| Case {
        name,
        bytes,
        defined_flags,
        guard: Some(guard),
    };
    vec![
        // Arithmetic
        c("add rax, rbx", &[0x48, 0x01, 0xD8], ALL),
        c("add eax, ebx", &[0x01, 0xD8], ALL),
        c("add al, bl", &[0x00, 0xD8], ALL),
        c("add rax, 0x7f", &[0x48, 0x83, 0xC0, 0x7F], ALL),
        c("sub rax, rbx", &[0x48, 0x29, 0xD8], ALL),
        c("sub ecx, edx", &[0x29, 0xD1], ALL),
        c("adc rax, rbx", &[0x48, 0x11, 0xD8], ALL),
        c("sbb rax, rbx", &[0x48, 0x19, 0xD8], ALL),
        c("inc rax", &[0x48, 0xFF, 0xC0], INCDEC),
        c("dec rax", &[0x48, 0xFF, 0xC8], INCDEC),
        c("inc ebx", &[0xFF, 0xC3], INCDEC),
        c("neg rax", &[0x48, 0xF7, 0xD8], ALL),
        c("neg ecx", &[0xF7, 0xD9], ALL),
        c("cmp rax, rbx", &[0x48, 0x39, 0xD8], ALL),
        c("cmp al, bl", &[0x38, 0xD8], ALL),
        // ── 16-BIT DESTINATIONS ───────────────────────────────────────
        // A 16-bit write PRESERVES bits 16..63 — the exact opposite of a 32-bit
        // write, which zero-extends. Two defects this session came from getting
        // the 32-bit rule wrong, and the 16-bit rule was covered by only four
        // cases out of a hundred, so the opposite mistake had almost nowhere to
        // show up. These make the preserving case as well covered as the
        // zero-extending one.
        c("add cx, dx", &[0x66, 0x01, 0xD1], ALL),
        c("sub cx, dx", &[0x66, 0x29, 0xD1], ALL),
        c("adc cx, dx", &[0x66, 0x11, 0xD1], ALL),
        c("sbb cx, dx", &[0x66, 0x19, 0xD1], ALL),
        c("and cx, dx", &[0x66, 0x21, 0xD1], LOGIC),
        c("or cx, dx", &[0x66, 0x09, 0xD1], LOGIC),
        c("xor cx, dx", &[0x66, 0x31, 0xD1], LOGIC),
        c("neg cx", &[0x66, 0xF7, 0xD9], ALL),
        c("not cx", &[0x66, 0xF7, 0xD1], NONE),
        c("inc cx", &[0x66, 0xFF, 0xC1], INCDEC),
        c("dec cx", &[0x66, 0xFF, 0xC9], INCDEC),
        c("cmp cx, dx", &[0x66, 0x39, 0xD1], ALL),
        c("test cx, dx", &[0x66, 0x85, 0xD1], LOGIC),
        c("shl cx, 3", &[0x66, 0xC1, 0xE1, 0x03], SHIFT),
        c("shr cx, cl", &[0x66, 0xD3, 0xE9], SHIFT),
        c("movzx ecx, dl", &[0x0F, 0xB6, 0xCA], NONE),
        c("xadd cx, dx", &[0x66, 0x0F, 0xC1, 0xD1], ALL),
        // 16-bit CMOV: unlike the 32-bit form (which always writes and so
        // always zero-extends), this one must leave bits 16..63 alone in BOTH
        // branches. Same instruction, opposite obligation — the reason this
        // class admits no blanket rule.
        c("cmovne cx, dx", &[0x66, 0x0F, 0x45, 0xCA], NONE),
        c("cmpxchg cx, bx", &[0x66, 0x0F, 0xB1, 0xD9], ALL),

        // ── 32-BIT FORMS of instructions covered only at 64/8 bits ────────
        // Every one of these zero-extends into the 64-bit register; the two
        // bugs found this session were exactly that rule applied wrongly.
        c("adc ecx, edx", &[0x11, 0xD1], ALL),
        c("sbb ecx, edx", &[0x19, 0xD1], ALL),
        c("and ecx, edx", &[0x21, 0xD1], LOGIC),
        c("or ecx, edx", &[0x09, 0xD1], LOGIC),
        c("xor ecx, edx", &[0x31, 0xD1], LOGIC),
        c("not ecx", &[0xF7, 0xD1], NONE),
        c("dec ecx", &[0xFF, 0xC9], INCDEC),
        c("cmp ecx, edx", &[0x39, 0xD1], ALL),
        c("test ecx, edx", &[0x85, 0xD1], LOGIC),
        c("neg bl", &[0xF6, 0xDB], ALL),

        // Logic
        c("and rax, rbx", &[0x48, 0x21, 0xD8], LOGIC),
        c("or rax, rbx", &[0x48, 0x09, 0xD8], LOGIC),
        c("xor rax, rbx", &[0x48, 0x31, 0xD8], LOGIC),
        c("xor rax, rax (zero idiom)", &[0x48, 0x31, 0xC0], LOGIC),
        c("not rax", &[0x48, 0xF7, 0xD0], NONE),
        c("test rax, rbx", &[0x48, 0x85, 0xD8], LOGIC),
        c("test bl, 0x0f", &[0xF6, 0xC3, 0x0F], LOGIC),
        // Shifts (immediate counts, in range; see LIMITATIONS for CF/OF)
        c("shl rax, 4", &[0x48, 0xC1, 0xE0, 0x04], SHIFT),
        c("shr rax, 4", &[0x48, 0xC1, 0xE8, 0x04], SHIFT),
        c("sar rax, 4", &[0x48, 0xC1, 0xF8, 0x04], SHIFT),
        c("shl ebx, 7", &[0xC1, 0xE3, 0x07], SHIFT),
        c("shr bl, 3", &[0xC0, 0xEB, 0x03], SHIFT),
        c("sar rdx, 63", &[0x48, 0xC1, 0xFA, 0x3F], SHIFT),
        // NOW COVERABLE (2026-07-23): the oracle interpreter learned these
        // intrinsics, so the bit-scan/bit-count family gained hardware
        // validation for the first time. BSF/BSR leave the destination
        // UNDEFINED for a zero source, which the interpreter reports as
        // Unsupported rather than inventing a value — those input states are
        // skipped, the rest are compared.
        // BSF/BSR: now coverable. Their destination is architecturally
        // UNDEFINED when the source is zero; the interpreter refuses exactly
        // those states and the differential skips them (per-state refusal, with
        // a guard that a case cannot be refused on ALL states). Every non-zero
        // source is compared against the real CPU.
        c("bsf eax, ebx", &[0x0F, 0xBC, 0xC3], NONE),
        c("bsr eax, ebx", &[0x0F, 0xBD, 0xC3], NONE),
        c("bsf rax, rbx", &[0x48, 0x0F, 0xBC, 0xC3], NONE),
        c("bsr rax, rbx", &[0x48, 0x0F, 0xBD, 0xC3], NONE),
        //
        // POPCNT/TZCNT/LZCNT have no undefined input — that is precisely why
        // they exist alongside BSF/BSR — so they are compared for every state.
        c("popcnt eax, ebx", &[0xF3, 0x0F, 0xB8, 0xC3], NONE),
        c("popcnt rax, rbx", &[0xF3, 0x48, 0x0F, 0xB8, 0xC3], NONE),
        c("tzcnt eax, ebx", &[0xF3, 0x0F, 0xBC, 0xC3], NONE),
        c("lzcnt eax, ebx", &[0xF3, 0x0F, 0xBD, 0xC3], NONE),
        // Double-precision shifts, now modelled by the interpreter.
        c("shld eax, ebx, cl", &[0x0F, 0xA5, 0xD8], NONE),
        c("shrd eax, ebx, cl", &[0x0F, 0xAD, 0xD8], NONE),
        c("shld eax, ebx, 5", &[0x0F, 0xA4, 0xD8, 0x05], NONE),
        // Widening multiply, ONE-operand form (edx:eax = eax * r/m32). Now
        // reachable because the interpreter handles `SetRegSplit` for widths
        // whose doubled result fits a u64. This is the high-half path where
        // earlier sessions found real defects, previously with no hardware case.
        // OF/CF are the `mul_overflow` intrinsic, so only registers compare.
        c("mul ebx", &[0xF7, 0xE3], NONE),
        // ── DIV / IDIV (32-bit forms only) ────────────────────────────
        // The 64-bit forms are deliberately absent: their dividend is the
        // 128-bit RDX:RAX pair, and this oracle interpreter is u64-based, so it
        // cannot represent the input — the same structural limit that keeps
        // 128-bit products out (see the SetRegSplit refusal). The 32-bit forms
        // have a 64-bit EDX:EAX dividend and a 32-bit quotient, which fit
        // exactly, so they ARE validated against hardware.
        // Absent until 2026-07-28 purely because the shared input grid can
        // produce a faulting state; guarded, they run over the whole grid.
        // Worth covering: the dividend is the RDX:RAX PAIR, which is exactly
        // the kind of implicit-operand wiring that unit tests can agree with
        // themselves about while disagreeing with the CPU.
        //
        // Unsigned: force the high half to 0 so the quotient always fits in
        // the destination, and make the divisor non-zero. Both are the minimum
        // needed for legality — rax and the divisor's low bits still vary
        // across the whole grid.
        // 8-bit forms: dividend is AX, results are AL (quotient) and AH
        // (remainder) — the two halves of the very register being divided, so
        // this is the sharpest instance of the read-after-write hazard class.
        // It was fixed at the same time as the general case and had NO hardware
        // case until now; a fix without a case is a claim, not a result.
        //
        // Legality: the quotient must fit in AL, so keep the dividend below
        // 256 (unsigned) and make the divisor non-zero.
        cg("div bl", &[0xF6, 0xF3], NONE, |st| {
            st.regs[0] &= 0xFF; // rax -> ax < 256, so ax/bl always fits al
            if st.regs[1] as u8 == 0 {
                st.regs[1] = 1; // bl
            }
        }),
        // Signed: AX must be the sign extension of AL for the quotient to fit,
        // and AL = -128 with BL = -1 is the unrepresentable case (#DE).
        cg("idiv bl", &[0xF6, 0xFB], NONE, |st| {
            let al = st.regs[0] as u8;
            st.regs[0] = i64::from(al as i8) as u64 & 0xFFFF;
            let bl = st.regs[1] as u8;
            if bl == 0 || (al == 0x80 && bl == 0xFF) {
                st.regs[1] = 1;
            }
        }),
        // MUL at the narrow widths: 8-bit writes AX alone (no pair), 16-bit
        // writes the DX:AX PAIR and so belongs to the same class as div.
        c("mul bl", &[0xF6, 0xE3], NONE),
        c("mul bx", &[0x66, 0xF7, 0xE3], NONE),
        // XCHG on sub-registers: two writes whose values each read the other
        // operand — the class, with no arithmetic to hide behind.
        c("xchg al, bl", &[0x86, 0xD8], NONE),
        c("xchg ax, bx", &[0x66, 0x93], NONE),
        // XADD / CMPXCHG at narrower widths than the covered 64-bit forms.
        c("xadd ecx, edx", &[0x0F, 0xC1, 0xD1], ALL),
        c("xadd bl, cl", &[0x0F, 0xC0, 0xCB], ALL),
        // 32-bit CMPXCHG: the case that exposed the conditional-write hazard.
        // Both writes are conditional, and at 32 bits writing the old value
        // back is NOT a no-op (x86-64 zero-extends), so the untaken branch used
        // to destroy the upper half of the destination. Now written at the
        // 64-bit parent. Kept permanently: it is the only width that can catch
        // a regression of this class.
        c("cmpxchg ecx, ebx", &[0x0F, 0xB1, 0xD9], ALL),
        c("cmpxchg cl, bl", &[0x0F, 0xB0, 0xD9], ALL),
        cg("div ebx", &[0xF7, 0xF3], NONE, |st| {
            st.regs[3] = 0;
            if st.regs[1] as u32 == 0 {
                st.regs[1] = 1;
            }
        }),
        // Signed: the high half must be the SIGN EXTENSION of the low half
        // (what CQO produces), or the 128-bit dividend is not the sign-extended
        // 64-bit value and the quotient overflows. The one remaining faulting
        // case is INT64_MIN / -1, whose quotient is unrepresentable — the SDM
        // says #DE, so it is steered away rather than "handled".
        cg("idiv ecx", &[0xF7, 0xF9], NONE, |st| {
            let lo = st.regs[0] as u32;
            st.regs[3] = if (lo as i32) < 0 { u64::MAX } else { 0 };
            let d = st.regs[2] as u32;
            if d == 0 || (lo == 1 << 31 && d == u32::MAX) {
                st.regs[2] = 1;
            }
        }),
        c("imul ebx", &[0xF7, 0xEB], NONE),
        // BMI1 bit-manipulation. These turned out NOT to use intrinsics at all —
        // the lifter builds them from pure And/Xor/Sub (lift.rs:6740, 6823,
        // 6841) — so they were always interpretable; the earlier attempt to add
        // them merely aborted on an unrelated `bsf` case before reaching them.
        // Worth having: `blsr` carried a real INVERTED-CARRY defect fixed in an
        // earlier session with no hardware case pinning it. CF is an intrinsic
        // here, so only the register result is compared.
        c("blsr eax, ebx", &[0xC4, 0xE2, 0x78, 0xF3, 0xCB], NONE),
        c("blsi eax, ebx", &[0xC4, 0xE2, 0x78, 0xF3, 0xDB], NONE),
        c("blsmsk eax, ebx", &[0xC4, 0xE2, 0x78, 0xF3, 0xD3], NONE),
        // Still NOT coverable, and the reason is structural — worth recording rather
        // than leaving as an unexplained gap. This oracle's mini-interpreter
        // evaluates exactly ONE intrinsic, `parity` (see the `E::Intrinsic`
        // arms in `interp_expr`); every other intrinsic makes the whole case
        // `Unsupported`. So any instruction whose RESULT is lifted to an opaque
        // intrinsic can never be hardware-validated here:
        //   bsf/bsr        -> lift_bit_scan            (lift.rs:648)
        //   popcnt         -> lift_unary_intrinsic_with_zf (lift.rs:651)
        //   lzcnt/tzcnt    -> lift.rs:652
        //   blsr/blsi/blsmsk -> lift_bmi_* (lift.rs:2631 …)
        //   shld/shrd      -> double-shift intrinsic
        // That is the real explanation for the oracle covering ~34 of the
        // ~1839 mnemonics lift.rs handles: it is not neglect, it is that
        // "lift to an opaque intrinsic" IS the decision to opt out of hardware
        // validation. Widening the oracle means teaching `interp_expr` these
        // intrinsics — the single highest-leverage improvement available to the
        // x86 verification story, and a prerequisite for ever calling the
        // flag-semantics classes closed with evidence.
        //
        // Measured, not assumed: the ONE-OPERAND widening forms `mul ebx` /
        // `imul ebx` are also `Unsupported` — writing the edx:eax pair pulls in
        // constructs `interp_expr` does not model — even though the TWO-operand
        // `imul rax, rbx` above is covered. So the high-half multiply path,
        // where earlier sessions found real defects, still has no hardware
        // validation and cannot get any without extending the interpreter.
        // Rotates and double-shifts with a VARIABLE (cl) count.
        //
        // Added 2026-07-23 by diffing the mnemonics `lift.rs` handles against
        // the mnemonics this oracle covers: rol/ror/rcl/rcr/shld/shrd had ZERO
        // hardware validation, despite being part of the same count-masking
        // class that an unmasked `bt` had just been found surviving in. The
        // random input states put a full 64-bit value in rcx, so `cl` is
        // out-of-range on most iterations — which is the case that matters.
        //
        // CF/OF are opaque `rol_cf`/`rol_of` intrinsics in the lifter, so they
        // stay out of `defined_flags`; the REGISTER RESULT is what the count
        // masking determines and what is compared here.
        c("rol eax, cl", &[0xD3, 0xC0], NONE),
        c("ror eax, cl", &[0xD3, 0xC8], NONE),
        c("rol rax, cl", &[0x48, 0xD3, 0xC0], NONE),
        c("ror rax, cl", &[0x48, 0xD3, 0xC8], NONE),
        // 8- and 16-bit rotates: the width where "mask to 5 bits" and
        // "reduce mod width" diverge, and where a naive `bits - amt` underflows.
        c("rol bl, cl", &[0xD2, 0xC3], NONE),
        c("ror bl, cl", &[0xD2, 0xCB], NONE),
        c("rol ax, cl", &[0x66, 0xD3, 0xC0], NONE),
        c("rol eax, 12", &[0xC1, 0xC0, 0x0C], NONE),
        c("rol bl, 12", &[0xC0, 0xC3, 0x0C], NONE),
        // NOT coverable here: SHLD/SHRD lift to an OPAQUE INTRINSIC, which this
        // oracle's mini-interpreter cannot evaluate ("interpreter does not
        // support case `shld eax, ebx, cl`"). This is the structural reason the
        // oracle covers only ~34 of the ~1839 mnemonics lift.rs handles:
        // anything reduced to an opaque intrinsic is, by construction, outside
        // hardware validation. Covering SHLD/SHRD requires teaching the
        // interpreter the intrinsic first — tracked, not silently dropped.
        // Bit test / set / reset / complement, REGISTER bit-base.
        //
        // The bit offset is taken MODULO the operand size (SDM vol.2 BT: "the
        // instruction takes the modulo 16, 32, or 64 of the bit offset
        // operand"), which is NOT the shift rule above — shifts use a fixed
        // 5-bit mask at every sub-64-bit width, bit-test is genuinely
        // mod-width, so they disagree at 16 bits.
        //
        // These are the cases the oracle was MISSING: the shift family had
        // native validation and the bit-test family did not, which is exactly
        // how an unmasked `bt` offset survived a sweep that declared the
        // count-masking class closed everywhere. `input_states` supplies full
        // random 64-bit registers, so out-of-range offsets are exercised here
        // by construction rather than by a hand-picked constant.
        //
        // Only CF is architecturally defined; OF/SF/ZF/AF/PF are undefined
        // after BT* (SDM), so they stay out of `defined_flags`.
        c("bt eax, ecx", &[0x0F, 0xA3, 0xC8], CF_ONLY),
        c("bt rax, rcx", &[0x48, 0x0F, 0xA3, 0xC8], CF_ONLY),
        c("bt ax, cx", &[0x66, 0x0F, 0xA3, 0xC8], CF_ONLY),
        c("bt eax, 0x21", &[0x0F, 0xBA, 0xE0, 0x21], CF_ONLY),
        c("bts eax, ecx", &[0x0F, 0xAB, 0xC8], CF_ONLY),
        c("bts rax, rcx", &[0x48, 0x0F, 0xAB, 0xC8], CF_ONLY),
        c("btr eax, ecx", &[0x0F, 0xB3, 0xC8], CF_ONLY),
        c("btc eax, ecx", &[0x0F, 0xBB, 0xC8], CF_ONLY),
        // Moves / extensions
        c("mov rax, rbx", &[0x48, 0x89, 0xD8], NONE),
        c("mov eax, ebx (zext to 64)", &[0x89, 0xD8], NONE),
        c("mov al, bl", &[0x88, 0xD8], NONE),
        c("movabs rax, imm64", &[0x48, 0xB8, 0xF0, 0xDE, 0xBC, 0x9A, 0x78, 0x56, 0x34, 0x12], NONE),
        c("movzx rax, bl", &[0x48, 0x0F, 0xB6, 0xC3], NONE),
        c("movzx eax, bx", &[0x0F, 0xB7, 0xC3], NONE),
        c("movsx rax, bl", &[0x48, 0x0F, 0xBE, 0xC3], NONE),
        c("movsx ecx, dl", &[0x0F, 0xBE, 0xCA], NONE),
        c("movsxd rax, ebx", &[0x48, 0x63, 0xC3], NONE),
        // IMUL two-operand (flags all excluded: CF/OF opaque, rest undefined)
        c("imul rax, rbx", &[0x48, 0x0F, 0xAF, 0xC3], NONE),
        c("imul ecx, edx", &[0x0F, 0xAF, 0xCA], NONE),
        c("imul rax, rbx, 0x11", &[0x48, 0x6B, 0xC3, 0x11], NONE),
        // LEA
        c("lea rax, [rbx+rcx*4+0x10]", &[0x48, 0x8D, 0x44, 0x8B, 0x10], NONE),
        c("lea eax, [rbx+rbx*2]", &[0x8D, 0x04, 0x5B], NONE),
        c("lea rax, [rbx-8]", &[0x48, 0x8D, 0x43, 0xF8], NONE),
        // BSWAP
        c("bswap rax", &[0x48, 0x0F, 0xC8], NONE),
        c("bswap ecx", &[0x0F, 0xC9], NONE),
        // Sign-extension into the high register
        c("cdq", &[0x99], NONE),
        c("cqo", &[0x48, 0x99], NONE),
        // CMOVcc (reads flags, conditional register write)
        c("cmove rax, rbx", &[0x48, 0x0F, 0x44, 0xC3], NONE),
        c("cmovb ecx, edx", &[0x0F, 0x42, 0xCA], NONE),
        c("cmovg rax, rbx", &[0x48, 0x0F, 0x4F, 0xC3], NONE),
        // SETcc
        c("sete al", &[0x0F, 0x94, 0xC0], NONE),
        c("setb cl", &[0x0F, 0x92, 0xC1], NONE),
        c("setle dl", &[0x0F, 0x9E, 0xC2], NONE),
        // XCHG / XADD / CMPXCHG (register forms)
        c("xchg rax, rbx", &[0x48, 0x87, 0xD8], NONE),
        c("xchg ecx, edx", &[0x87, 0xD1], NONE),
        c("xadd rax, rbx", &[0x48, 0x0F, 0xC1, 0xD8], ALL),
        c("cmpxchg rcx, rbx", &[0x48, 0x0F, 0xB1, 0xD9], ALL),
        // Variable (CL-count) shifts. Per the AMD APM vol.3 (pub 24594 rev
        // 3.34, Oct 2022), SAL/SHL p.314 (and identically SHR/SAR): "The
        // processor masks the upper three bits of the count operand, thus
        // restricting the count to a number between 0 and 31. When the
        // destination is 64 bits wide, the processor masks the upper two bits
        // of the count, providing a count in the range of 0 to 63."
        // Flags are excluded (NONE): the APM also says "If the shift count is
        // 0, no flags are modified", and the lifter writes SF/ZF/PF
        // unconditionally — a separate, documented gap (same one already noted
        // for rotates in src/lift.rs). Values are what is compared here.
        c("shl rax, cl", &[0x48, 0xD3, 0xE0], NONE),
        c("shl eax, cl", &[0xD3, 0xE0], NONE),
        c("shr rax, cl", &[0x48, 0xD3, 0xE8], NONE),
        c("shr eax, cl", &[0xD3, 0xE8], NONE),
        c("sar rax, cl", &[0x48, 0xD3, 0xF8], NONE),
        c("sar edx, cl", &[0xD3, 0xFA], NONE),
        // Sub-32-bit widths: the count is still masked to 5 bits (NOT to the
        // operand width), so `shl bl, cl` with cl=0x21 really shifts by 1
        // while cl=12 shifts everything out.
        c("shl bl, cl", &[0xD2, 0xE3], NONE),
        c("shr bl, cl", &[0xD2, 0xEB], NONE),
        c("sar bl, cl", &[0xD2, 0xFB], NONE),
        // BMI2 SHLX/SHRX/SARX: same masking rule ("When the operand size is
        // 32, bits [31:5] of shft_cnt are ignored; when the operand size is
        // 64, bits [63:6] of shft_cnt are ignored" — APM vol.3 SHLX). These
        // never touch flags, so NONE is exact.
        c("shlx rax, rbx, rcx", &[0xC4, 0xE2, 0xF1, 0xF7, 0xC3], NONE),
        c("shlx eax, ebx, ecx", &[0xC4, 0xE2, 0x71, 0xF7, 0xC3], NONE),
        c("shrx rax, rbx, rcx", &[0xC4, 0xE2, 0xF3, 0xF7, 0xC3], NONE),
        c("sarx eax, ebx, ecx", &[0xC4, 0xE2, 0x72, 0xF7, 0xC3], NONE),
        // High-byte partial registers (AH/BH/CH/DH, no REX)
        c("add ah, bh", &[0x00, 0xFC], ALL),
        c("mov ah, bh", &[0x88, 0xFC], NONE),
        c("test ah, ah", &[0x84, 0xE4], LOGIC),
    ]
}

// ───────────────────────────────────────────────────────────────────────────
// Harness plumbing
// ───────────────────────────────────────────────────────────────────────────

fn decode64(bytes: &[u8]) -> IcedInstruction {
    let mut dec = Decoder::with_ip(64, bytes, 0x1000, DecoderOptions::NONE);
    let instr = dec.decode();
    assert!(!instr.is_invalid(), "failed to decode {bytes:02x?}");
    assert_eq!(instr.len(), bytes.len(), "trailing bytes in {bytes:02x?}");
    instr
}

const EDGES: [u64; 13] = [
    0,
    1,
    2,
    0x7F,
    0x80,
    0xFF,
    0x7FFF_FFFF,
    0x8000_0000,
    0xFFFF_FFFF,
    u64::MAX,
    i64::MIN as u64,
    i64::MAX as u64,
    0x1234_5678_9ABC_DEF0,
];

#[derive(Clone)]
struct InputState {
    regs: [u64; 15], // parallel to CMP_REGS
    flags: [u8; 6],  // parallel to FLAG_NAMES
}

fn input_states(rng: &mut Rng) -> Vec<InputState> {
    let mut out = Vec::new();
    // Edge grid over (rax, rbx) with CF in {0, 1}, other regs randomized.
    for &a in &EDGES {
        for &b in &EDGES {
            for cf in [0u8, 1] {
                let mut regs = [0u64; 15];
                for r in regs.iter_mut() {
                    *r = rng.next();
                }
                regs[0] = a; // rax
                regs[1] = b; // rbx
                regs[2] = b; // rcx mirrors rbx so 2-reg cases with rcx/rdx hit edges too
                regs[3] = a; // rdx
                let mut flags = [0u8; 6];
                for f in flags.iter_mut() {
                    *f = (rng.next() & 1) as u8;
                }
                flags[0] = cf;
                out.push(InputState { regs, flags });
            }
        }
    }
    // Fully random states.
    for _ in 0..64 {
        let mut regs = [0u64; 15];
        for r in regs.iter_mut() {
            *r = rng.next();
        }
        let mut flags = [0u8; 6];
        for f in flags.iter_mut() {
            *f = (rng.next() & 1) as u8;
        }
        out.push(InputState { regs, flags });
    }
    out
}

fn interp_final(case: &Case, input: &InputState) -> (IState, bool) {
    let instr = decode64(case.bytes);
    let llil = lift_to_llil_with_bits(&instr, 64);
    let mut st = IState::new();
    for (i, name) in CMP_REGS.iter().enumerate() {
        st.regs.insert((*name).to_string(), input.regs[i]);
    }
    st.regs.insert("rsp".to_string(), 0x7FFF_0000);
    for (i, f) in FLAG_NAMES.iter().enumerate() {
        st.flags.insert((*f).to_string(), input.flags[i]);
    }
    let supported = st.run(&llil).is_ok();
    (st, supported)
}

// ───────────────────────────────────────────────────────────────────────────
// Interpreter self-tests (run on every host)
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn interpreter_supports_all_cases() {
    let base = InputState { regs: [3; 15], flags: [0; 6] };
    for case in cases() {
        // Guarded cases declare that some states fault on real silicon; this
        // self-test must ask them about a LEGAL state, or it reports
        // "unsupported" for an input the case never claimed to accept.
        let mut input = base.clone();
        if let Some(g) = case.guard {
            g(&mut input);
        }
        let (_, ok) = interp_final(&case, &input);
        assert!(ok, "interpreter does not support case `{}`", case.name);
    }
}

#[test]
fn interpreter_basic_semantics() {
    // add rax, rbx with rax=1, rbx=u64::MAX -> rax=0, CF=1, ZF=1
    let mut input = InputState { regs: [0; 15], flags: [0; 6] };
    input.regs[0] = 1;
    input.regs[1] = u64::MAX;
    let case = Case {
        name: "add rax, rbx",
        bytes: &[0x48, 0x01, 0xD8],
        defined_flags: ALL,
        guard: None,
    };
    let (st, ok) = interp_final(&case, &input);
    assert!(ok);
    assert_eq!(st.regs["rax"], 0);
    assert_eq!(st.flags["cf"], 1);
    assert_eq!(st.flags["zf"], 1);
    assert_eq!(st.flags["of"], 0);

    // mov eax, ebx zero-extends into rax.
    let mut input = InputState { regs: [0; 15], flags: [0; 6] };
    input.regs[0] = u64::MAX;
    input.regs[1] = 0x8000_0001_DEAD_BEEF;
    let case = Case { name: "mov eax, ebx", bytes: &[0x89, 0xD8], defined_flags: NONE, guard: None };
    let (st, ok) = interp_final(&case, &input);
    assert!(ok);
    assert_eq!(st.regs["rax"], 0xDEAD_BEEF);
}

/// Shift counts must be masked per the AMD APM vol.3 (pub 24594 rev 3.34),
/// SAL/SHL p.314 (SHR/SAR identical): "The processor masks the upper three
/// bits of the count operand, thus restricting the count to a number between
/// 0 and 31. When the destination is 64 bits wide, the processor masks the
/// upper two bits of the count, providing a count in the range of 0 to 63."
/// The lifter used to emit the RAW count, so `shl eax, cl` with cl=0x80
/// (hardware: count 0x80 & 0x1F == 0, eax unchanged) evaluated as a shift by
/// 128 and zeroed the register.
#[test]
fn shift_counts_are_masked_per_apm() {
    // shl eax, cl with cl = 0x80 -> masked count 0 -> eax unchanged.
    let mut input = InputState { regs: [0; 15], flags: [0; 6] };
    input.regs[0] = 0xDEAD_BEEF; // rax
    input.regs[2] = 0x80; // rcx (cl)
    let case = Case { name: "shl eax, cl", bytes: &[0xD3, 0xE0], defined_flags: NONE, guard: None };
    let (st, ok) = interp_final(&case, &input);
    assert!(ok);
    assert_eq!(
        st.regs["rax"], 0xDEAD_BEEF,
        "cl=0x80 masks to count 0: eax must be unchanged"
    );

    // shl bl, cl with cl = 0x21 (33) -> masked count 1 (5-bit mask, NOT
    // mod-width) -> bl = 0x41 << 1 = 0x82.
    let mut input = InputState { regs: [0; 15], flags: [0; 6] };
    input.regs[1] = 0x41; // rbx (bl)
    input.regs[2] = 0x21; // rcx (cl)
    let case = Case { name: "shl bl, cl", bytes: &[0xD2, 0xE3], defined_flags: NONE, guard: None };
    let (st, ok) = interp_final(&case, &input);
    assert!(ok);
    assert_eq!(st.regs["rbx"], 0x82, "cl=33 masks to count 1 on an 8-bit shl");

    // shlx eax, ebx, ecx with ecx = 0x40 -> bits [31:5] of the count ignored
    // -> count 0 -> eax = ebx.
    let mut input = InputState { regs: [0; 15], flags: [0; 6] };
    input.regs[1] = 0x1234_5678; // rbx
    input.regs[2] = 0x40; // rcx
    let case = Case {
        name: "shlx eax, ebx, ecx",
        bytes: &[0xC4, 0xE2, 0x71, 0xF7, 0xC3],
        defined_flags: NONE,
        guard: None,
    };
    let (st, ok) = interp_final(&case, &input);
    assert!(ok);
    assert_eq!(st.regs["rax"], 0x1234_5678, "shlx count 0x40 masks to 0");
}

/// Regression check for the former ADC carry-in bug (see the removed KNOWN
/// LIFTER BUG block; fixed in `X86Lifter::lift_add_sub`,
/// src/lift.rs). `adc rax, rbx` with rax=5, rbx=u64::MAX, CF=1 must now
/// report the real hardware CF=1 (not the old buggy CF=0).
#[test]
fn adc_carry_in_corner_is_fixed() {
    let mut input = InputState { regs: [0; 15], flags: [0; 6] };
    input.regs[0] = 5;
    input.regs[1] = u64::MAX;
    input.flags[0] = 1; // CF in
    let case = Case {
        name: "adc rax, rbx",
        bytes: &[0x48, 0x11, 0xD8],
        defined_flags: ALL,
        guard: None,
    };
    let (st, ok) = interp_final(&case, &input);
    assert!(ok);
    assert_eq!(st.regs["rax"], 5, "result itself is correct (wraps to rax)");
    assert_eq!(st.flags["cf"], 1, "real hardware sets CF=1 here");
}

// ───────────────────────────────────────────────────────────────────────────
// The differential test proper (native oracle, Windows x86-64 only)
// ───────────────────────────────────────────────────────────────────────────

#[cfg(all(windows, target_arch = "x86_64"))]
mod differential {
    use super::*;
    use native::{Ctx, Jit, FLAGS_SLOT, FLAG_MASK, RFLAGS_BASE};

    const FLAG_BITS: [(usize, u64); 6] =
        [(0, 0x1), (1, 0x4), (2, 0x10), (3, 0x40), (4, 0x80), (5, 0x800)];

    /// Sanity check: the JIT trampoline itself is transparent — a NOP must
    /// pass every register and every arithmetic flag through unchanged.
    #[test]
    fn jit_stub_roundtrip() {
        let jit = Jit::new(&[0x90]);
        let mut rng = Rng(0xC0FF_EE00);
        for _ in 0..200 {
            let mut ctx = Ctx([0; 16]);
            for (i, slot) in ctx.0.iter_mut().enumerate() {
                if i != FLAGS_SLOT {
                    *slot = rng.next();
                }
            }
            let in_flags = rng.next() & FLAG_MASK;
            ctx.0[FLAGS_SLOT] = RFLAGS_BASE | in_flags;
            let expect = ctx.0;
            jit.run(&mut ctx);
            for (i, (&got, &want)) in ctx.0.iter().zip(expect.iter()).enumerate() {
                if i == FLAGS_SLOT {
                    assert_eq!(got & FLAG_MASK, in_flags, "flag roundtrip");
                } else {
                    assert_eq!(got, want, "gpr {i} roundtrip");
                }
            }
        }
    }

    #[test]
    fn lifter_matches_native_cpu() {
        let mut rng = Rng(0xDEAD_BEEF_1234_5678);
        let states = input_states(&mut rng);
        let mut failures = Vec::new();

        for case in cases() {
            let jit = Jit::new(case.bytes);
            // Some instructions are architecturally UNDEFINED for particular
            // inputs — BSF/BSR leave the destination undefined when the source
            // is zero — and the interpreter correctly refuses those states
            // rather than inventing a value. Refusing the STATE must not
            // disqualify the whole INSTRUCTION, which is what the old
            // `assert!(ok, "unsupported")` did: it excluded every such family
            // from hardware validation entirely.
            let mut compared_states = 0usize;
            let mut refused_states = 0usize;
            for (si, input) in states.iter().enumerate() {
                // Repair states this instruction would fault on (see
                // `Case::guard`). Done per case, on a COPY, so one guarded case
                // cannot alter the grid every other case sees.
                let mut input = input.clone();
                if let Some(g) = case.guard {
                    g(&mut input);
                }
                let input = &input;

                // Native run.
                let mut ctx = Ctx([0; 16]);
                for (i, &n) in CMP_REG_NUMS.iter().enumerate() {
                    ctx.0[n] = input.regs[i];
                }
                let mut rf = RFLAGS_BASE;
                for (i, (_, bit)) in FLAG_BITS.iter().enumerate() {
                    if input.flags[i] != 0 {
                        rf |= bit;
                    }
                }
                ctx.0[FLAGS_SLOT] = rf;
                jit.run(&mut ctx);

                // IL interpreter run.
                let (st, ok) = interp_final(&case, input);
                if !ok {
                    refused_states += 1;
                    continue;
                }
                compared_states += 1;

                // Compare GPRs.
                for (i, name) in CMP_REGS.iter().enumerate() {
                    let native = ctx.0[CMP_REG_NUMS[i]];
                    let il = st.regs.get(*name).copied().unwrap_or(0);
                    if native != il {
                        failures.push(format!(
                            "[{}] state {si}: {name}: native={native:#x} il={il:#x} \
                             (in: rax={:#x} rbx={:#x} cf={})",
                            case.name, input.regs[0], input.regs[1], input.flags[0]
                        ));
                    }
                }

                // Compare defined flags.
                {
                    let out_rf = ctx.0[FLAGS_SLOT];
                    for &fname in case.defined_flags {
                        let fi = FLAG_NAMES.iter().position(|f| *f == fname).unwrap();
                        let native = u8::from(out_rf & FLAG_BITS[fi].1 != 0);
                        match st.flags.get(fname) {
                            Some(&il) => {
                                if il != native {
                                    failures.push(format!(
                                        "[{}] state {si}: flag {fname}: native={native} il={il} \
                                         (in: rax={:#x} rbx={:#x} cf={})",
                                        case.name, input.regs[0], input.regs[1], input.flags[0]
                                    ));
                                }
                            }
                            None => failures.push(format!(
                                "[{}] state {si}: flag {fname} is declared defined but the IL \
                                 left it opaque/unknown",
                                case.name
                            )),
                        }
                    }
                }
            }

            // Anti-degeneracy, per instruction: a case whose every state is
            // refused proves nothing, and would sit in `cases()` looking like
            // coverage. Fail loudly instead of passing silently.
            assert!(
                compared_states > 0,
                "case `{}` was refused by the interpreter on ALL {refused_states} input                  states — it is listed as covered but validates nothing",
                case.name
            );
        }

        assert!(
            failures.is_empty(),
            "{} semantic mismatches between lifter IL and native CPU:\n{}",
            failures.len(),
            failures[..failures.len().min(40)].join("\n")
        );
    }
}
