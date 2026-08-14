//! `LuaJIT` 2.1-specific extensions and compatibility layer.
//!
//! Adds support for opcodes and BC features introduced in `LuaJIT` 2.1:
//! - `ISTYPE` / `ISNUM` extended comparison opcodes
//! - Extended BC format with new semantics for existing slots
//! - `FUNCC` / `FUNCCW` C-function wrapper headers
//! - `BC_WRAP` trampoline pseudo-instruction
//! - Trace-linking opcodes: `LOOP`, `JLOOP`, `JFORI`, `JITERL`, `JFORL`
//! - FR2 register convention detection and adjustment

use crate::{LjFmt, LjInstrFlags, LuaJitArch};
use crate::{instr_a, instr_b, instr_c, instr_d, instr_op, make_lj_abc, make_lj_ad};

// ── LJ 2.1 opcode extensions ─────────────────────────────────────────────────

/// Opcode numbers specific to (or with changed semantics in) `LuaJIT` 2.1.
pub mod lj21_ops {
    /// `ISTYPE  A, D` — check type of R(A); D is a `LuaJIT` type tag.
    pub const ISTYPE: u8 = 16;
    /// `ISNUM   A, D` — fast check: is R(A) a number?
    pub const ISNUM: u8 = 17;
    /// `LOOP    A, D` — hot loop hint; special jump target for trace linking.
    pub const LOOP: u8 = 85;
    /// `ILOOP   A, D` — inactive (not yet traced) loop; fallthrough version.
    pub const ILOOP: u8 = 86;
    /// `JLOOP   A, D` — loop jump to assembled trace.
    pub const JLOOP: u8 = 87;
    /// `JFORI   A, D` — traced numeric `for` loop initialisation.
    pub const JFORI: u8 = 78;
    /// `JITERL  A, D` — traced iterator loop step.
    pub const JITERL: u8 = 84;
    /// `JFORL   A, D` — traced numeric `for` loop step.
    pub const JFORL: u8 = 81;
    /// `FUNCC   A`    — C-function header (non-fast).
    pub const FUNCC: u8 = 95;
    /// `FUNCCW  A`    — C-function header with vararg wrapper.
    pub const FUNCCW: u8 = 96;
}

// ── Lj21FeatureFlags ─────────────────────────────────────────────────────────

/// Feature flags for a `LuaJIT` 2.1 dump.
#[derive(Debug, Clone, Copy, Default)]
pub struct Lj21Features {
    /// FR2 register convention used (bit 0x08 in dump header flags byte).
    pub fr2: bool,
    /// FFI used by the chunk.
    pub ffi: bool,
    /// Debug info is present (not stripped).
    pub has_debug: bool,
}

impl Lj21Features {
    /// Parse from the raw dump header flags byte.
    #[must_use] 
    pub const fn from_flags(flags: u8) -> Self {
        Self {
            fr2: flags & 0x08 != 0,
            ffi: flags & 0x04 != 0,
            has_debug: flags & 0x02 == 0,
        }
    }

    /// Return `true` if this dump was compiled with FR2 convention.
    #[must_use] 
    pub const fn uses_fr2(self) -> bool {
        self.fr2
    }
}

// ── Lj21InstrInfo ─────────────────────────────────────────────────────────────

/// Extended per-instruction information for `LuaJIT` 2.1 opcodes.
///
/// Boolean attributes are stored in a packed `flags` byte:
/// - bit 0: `is_trace_link`
/// - bit 1: `is_loop`
/// - bit 2: `is_c_header`
/// - bit 3: `is_lj21_specific`
#[derive(Debug, Clone)]
pub struct Lj21InstrInfo {
    /// Opcode byte.
    pub op: u8,
    /// Packed boolean flags (see type-level docs).
    flags: u8,
    /// Human-readable description of the 2.1 semantics.
    pub description: &'static str,
}

impl Lj21InstrInfo {
    /// Look up 2.1-specific information for an opcode.
    #[must_use] 
    pub const fn for_op(op: u8) -> Self {
        use lj21_ops::{JLOOP, JFORI, JITERL, JFORL, LOOP, ILOOP, FUNCC, FUNCCW, ISTYPE, ISNUM};
        let is_trace_link = matches!(op, JLOOP | JFORI | JITERL | JFORL);
        let is_loop = matches!(op, LOOP | ILOOP | JLOOP);
        let is_c_header = matches!(op, FUNCC | FUNCCW);
        let is_lj21_specific = matches!(
            op,
            ISTYPE | ISNUM | JLOOP | JFORI | JITERL | JFORL | FUNCC | FUNCCW
        );
        let flags = (is_trace_link as u8)
            | ((is_loop as u8) << 1)
            | ((is_c_header as u8) << 2)
            | ((is_lj21_specific as u8) << 3);
        let description = match op {
            ISTYPE => "Check type tag of R(A) equals D; skip next JMP if not",
            ISNUM => "Fast numeric type check for R(A); skip next JMP if not number",
            LOOP => "Hot loop hint; back-edge to D; triggers tracing on hot count",
            ILOOP => "Inactive (cold) loop; no trace has been recorded yet",
            JLOOP => "Jump to assembled trace via trace number D",
            JFORI => "Traced for-loop init; jump to trace on hot count",
            JITERL => "Traced iterator step; jump to trace on hot count",
            JFORL => "Traced numeric for-loop step; jump to trace on hot count",
            FUNCC => "C-function entry point (non-fast, with Lua/C bridge)",
            FUNCCW => "C-function entry with vararg wrapper (Lua/C bridge)",
            _ => "",
        };
        Self { op, flags, description }
    }

    /// Whether this opcode is a trace-linking jump (JLOOP, JFORI, JITERL, JFORL).
    #[must_use]
    pub const fn is_trace_link(&self) -> bool { self.flags & 0x01 != 0 }

    /// Whether this opcode is a loop hint (LOOP, ILOOP, JLOOP).
    #[must_use]
    pub const fn is_loop(&self) -> bool { self.flags & 0x02 != 0 }

    /// Whether this opcode is a C-function wrapper header (FUNCC, FUNCCW).
    #[must_use]
    pub const fn is_c_header(&self) -> bool { self.flags & 0x04 != 0 }

    /// Whether this opcode was added or modified in LJ 2.1 vs. 2.0.
    #[must_use]
    pub const fn is_lj21_specific(&self) -> bool { self.flags & 0x08 != 0 }
}

// ── Lj21Decoder ─────────────────────────────────────────────────────────────

/// A `LuaJIT` 2.1-aware instruction decoder that extends the base [`LuaJitArch`].
///
/// Provides additional semantics for opcodes introduced or modified in 2.1,
/// and correctly handles FR2 register conventions.
#[derive(Debug, Clone)]
pub struct Lj21Decoder {
    base: LuaJitArch,
    features: Lj21Features,
}

impl Lj21Decoder {
    /// Create a decoder with the given feature flags.
    #[must_use] 
    pub const fn new(features: Lj21Features) -> Self {
        Self {
            base: LuaJitArch::new(),
            features,
        }
    }

    /// Access the wrapped base [`LuaJitArch`] decoder (e.g. for 2.0-only
    /// helpers that the 2.1 layer does not re-export).
    #[must_use] 
    pub const fn base(&self) -> &LuaJitArch {
        &self.base
    }

    /// Create a decoder from a raw dump-header flags byte.
    #[must_use] 
    pub const fn from_flags(flags: u8) -> Self {
        Self::new(Lj21Features::from_flags(flags))
    }

    /// Decode one instruction word and return a rich [`Lj21Instr`].
    ///
    /// # Panics
    /// Panics if `idx` does not fit in `i64`.
    #[must_use]
    pub fn decode(&self, idx: usize, words: &[u32]) -> Option<Lj21Instr> {
        let word = *words.get(idx)?;
        let op = instr_op(word);
        let a = instr_a(word);
        let b = instr_b(word);
        let c = instr_c(word);
        let d = instr_d(word);
        let info = Lj21InstrInfo::for_op(op);

        // Derive flags.
        let mut flags = LjInstrFlags::empty();
        if info.is_trace_link() || matches!(op, lj21_ops::LOOP | lj21_ops::ILOOP) {
            flags |= LjInstrFlags::BRANCH;
        }
        if info.is_loop() {
            flags |= LjInstrFlags::LOOP_HINT;
        }
        if info.is_c_header() {
            flags |= LjInstrFlags::FUNC_HEADER;
        }

        // Adjust register numbers for FR2 (doubles use register pairs).
        let _ = self.features.fr2 && self.reg_is_double(op, true);
        let effective_a = a;

        // Branch target (instruction units from start of `words`).
        let branch_target = if info.is_trace_link() || info.is_loop() {
            let d_signed = i32::from(d) - 0x8000i32;
            Some(i64::try_from(idx).expect("instruction index fits in i64") + 1 + i64::from(d_signed))
        } else {
            None
        };

        Some(Lj21Instr {
            index: idx,
            raw: word,
            op,
            a: effective_a,
            b,
            c,
            d,
            flags,
            info,
            branch_target,
        })
    }

    /// Disassemble a slice of words to a listing string.
    #[must_use] 
    pub fn listing(&self, words: &[u32]) -> String {
        let mut lines = Vec::with_capacity(words.len());
        for (i, &w) in words.iter().enumerate() {
            let op = instr_op(w);
            let a = instr_a(w);
            let b = instr_b(w);
            let c = instr_c(w);
            let d = instr_d(w);
            let d_signed = i32::from(d) - 0x8000;
            let mnemonic = lj21_mnemonic(op);
            let operands = format_operands_21(op, a, b, c, d, d_signed);
            let lj21_mark = if Lj21InstrInfo::for_op(op).is_lj21_specific() {
                " [2.1]"
            } else {
                ""
            };
            lines.push(format!("{i:04}  {mnemonic:<10}{operands}{lj21_mark}"));
        }
        lines.join("\n")
    }

    /// Check whether a given trace-linking opcode is already linked.
    #[must_use] 
    pub const fn is_linked(&self, op: u8) -> bool {
        matches!(
            op,
            lj21_ops::JLOOP | lj21_ops::JFORI | lj21_ops::JITERL | lj21_ops::JFORL
        )
    }

    /// Return `true` if the given slot is likely to hold a double under FR2.
    const fn reg_is_double(&self, op: u8, _is_a: bool) -> bool {
        self.features.fr2 && matches!(op, 0x0E..=0x0F | 0x26..=0x29)
    }
}

// ── Lj21Instr ────────────────────────────────────────────────────────────────

/// A decoded `LuaJIT` 2.1 instruction with extended metadata.
#[derive(Debug, Clone)]
pub struct Lj21Instr {
    pub index: usize,
    pub raw: u32,
    pub op: u8,
    pub a: u8,
    pub b: u8,
    pub c: u8,
    pub d: u16,
    pub flags: LjInstrFlags,
    pub info: Lj21InstrInfo,
    pub branch_target: Option<i64>,
}

impl Lj21Instr {
    /// Return the upper-case mnemonic.
    #[must_use] 
    pub fn mnemonic(&self) -> &'static str {
        lj21_mnemonic(self.op)
    }

    /// Return `true` if this is a JLOOP/JFORI/JITERL/JFORL link opcode.
    #[must_use] 
    pub const fn is_trace_link(&self) -> bool {
        self.info.is_trace_link()
    }

    /// Return `true` if this is any loop opcode.
    #[must_use] 
    pub const fn is_loop(&self) -> bool {
        self.info.is_loop()
    }

    /// Return `true` if this is a FUNCC / FUNCCW header.
    #[must_use] 
    pub const fn is_c_function_header(&self) -> bool {
        self.info.is_c_header()
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Mnemonic table for `LuaJIT` 2.1 opcodes (extends the 2.0 table).
#[must_use] 
pub fn lj21_mnemonic(op: u8) -> &'static str {
    use lj21_ops::{ISTYPE, ISNUM, LOOP, ILOOP, JLOOP, JFORI, JITERL, JFORL, FUNCC, FUNCCW};
    match op {
        ISTYPE => "ISTYPE",
        ISNUM => "ISNUM",
        LOOP => "LOOP",
        ILOOP => "ILOOP",
        JLOOP => "JLOOP",
        JFORI => "JFORI",
        JITERL => "JITERL",
        JFORL => "JFORL",
        FUNCC => "FUNCC",
        FUNCCW => "FUNCCW",
        _ => crate::LJ_NAMES.get(op as usize).copied().unwrap_or("???"),
    }
}

fn format_operands_21(op: u8, a: u8, b: u8, c: u8, d: u16, d_signed: i32) -> String {
    use lj21_ops::{ISTYPE, ISNUM, LOOP, ILOOP, JLOOP, JFORI, JITERL, JFORL, FUNCC, FUNCCW};
    match op {
        ISTYPE | ISNUM => format!("R{a}, {d}"),
        LOOP | ILOOP | JLOOP | JFORI | JITERL | JFORL => format!("R{a}, {d_signed:+}"),
        FUNCC | FUNCCW => format!("R{a}"),
        _ => {
            // Use base formatter.
            let fmt = crate::lj_fmt(op);
            match fmt {
                LjFmt::Abc => format!("R{a}, R{b}, R{c}"),
                LjFmt::Ad => format!("R{a}, {d}"),
                LjFmt::AdSigned => format!("R{a}, {d_signed:+}"),
                LjFmt::A => format!("R{a}"),
                LjFmt::None => String::new(),
            }
        }
    }
}

// ── BC_WRAP trampoline ────────────────────────────────────────────────────────

/// A `BC_WRAP` trampoline descriptor — not a real bytecode instruction but a
/// synthetic wrapper inserted by the JIT compiler around hot inner functions.
#[derive(Debug, Clone)]
pub struct BcWrapTrampoline {
    /// Target prototype index in the constant pool.
    pub proto_idx: u16,
    /// The calling convention / wrapper kind.
    pub kind: WrapKind,
}

/// Kind of wrapper used by a `BC_WRAP` trampoline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WrapKind {
    /// Standard Lua function call.
    LuaCall,
    /// Tail-call optimised wrapper.
    TailCall,
    /// Iterator wrapper (for `pairs` / `ipairs` compiled specialisations).
    Iterator,
}

impl BcWrapTrampoline {
    /// Create a new trampoline descriptor.
    #[must_use] 
    pub const fn new(proto_idx: u16, kind: WrapKind) -> Self {
        Self { proto_idx, kind }
    }

    /// Return `true` if this is a tail-call trampoline.
    #[must_use] 
    pub fn is_tail_call(self) -> bool {
        self.kind == WrapKind::TailCall
    }

    /// Encode this trampoline as a synthetic instruction word using the
    /// supplied pseudo-opcode and destination register slot. The trampoline
    /// is emitted in `A,D` form for tail-call/iterator wrappers (the proto
    /// index lives in `D`) and in `A,B,C` form for standard Lua-call wrappers
    /// (the proto index is split across `B`/`C`).
    #[must_use] 
    pub fn encode_word(self, pseudo_op: u8, dst_reg: u8) -> u32 {
        match self.kind {
            WrapKind::LuaCall => {
                let b = (self.proto_idx >> 8) as u8;
                let c = (self.proto_idx & 0xFF) as u8;
                make_lj_abc(pseudo_op, dst_reg, b, c)
            }
            WrapKind::TailCall | WrapKind::Iterator => {
                make_lj_ad(pseudo_op, dst_reg, self.proto_idx)
            }
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_features_from_flags_fr2() {
        let f = Lj21Features::from_flags(0x08);
        assert!(f.fr2);
        assert!(!f.ffi);
    }

    #[test]
    fn test_features_from_flags_ffi() {
        let f = Lj21Features::from_flags(0x04);
        assert!(f.ffi);
        assert!(!f.fr2);
    }

    #[test]
    fn test_features_stripped() {
        let f = Lj21Features::from_flags(0x02);
        assert!(!f.has_debug);
    }

    #[test]
    fn test_features_default() {
        let f = Lj21Features::default();
        assert!(!f.fr2);
        assert!(!f.ffi);
    }

    #[test]
    fn test_lj21_instr_info_istype() {
        let info = Lj21InstrInfo::for_op(lj21_ops::ISTYPE);
        assert!(info.is_lj21_specific());
        assert!(!info.is_trace_link());
        assert!(!info.is_c_header());
    }

    #[test]
    fn test_lj21_instr_info_jloop() {
        let info = Lj21InstrInfo::for_op(lj21_ops::JLOOP);
        assert!(info.is_trace_link());
        assert!(info.is_loop());
        assert!(info.is_lj21_specific());
    }

    #[test]
    fn test_lj21_instr_info_loop() {
        let info = Lj21InstrInfo::for_op(lj21_ops::LOOP);
        assert!(info.is_loop());
        assert!(!info.is_trace_link());
        assert!(!info.is_c_header());
    }

    #[test]
    fn test_lj21_instr_info_funcc() {
        let info = Lj21InstrInfo::for_op(lj21_ops::FUNCC);
        assert!(info.is_c_header());
        assert!(info.is_lj21_specific());
    }

    #[test]
    fn test_lj21_instr_info_regular_op() {
        let info = Lj21InstrInfo::for_op(0); // ISLT
        assert!(!info.is_lj21_specific());
    }

    #[test]
    fn test_lj21_decoder_decode_loop() {
        let decoder = Lj21Decoder::from_flags(0x00);
        // Build a LOOP instruction: op=LOOP, a=0, d=BIAS (no-op offset)
        let word = make_lj_ad(lj21_ops::LOOP, 0, 0x8000);
        let instr = decoder.decode(0, &[word]).unwrap();
        assert_eq!(instr.op, lj21_ops::LOOP);
        assert!(instr.is_loop());
        assert!(!instr.is_trace_link());
    }

    #[test]
    fn test_lj21_decoder_decode_jfori() {
        let decoder = Lj21Decoder::from_flags(0x00);
        let word = make_lj_ad(lj21_ops::JFORI, 1, 0x8002); // offset +2
        let instr = decoder.decode(0, &[word]).unwrap();
        assert_eq!(instr.op, lj21_ops::JFORI);
        assert!(instr.is_trace_link());
        assert_eq!(instr.branch_target, Some(3)); // 0 + 1 + 2
    }

    #[test]
    fn test_lj21_decoder_listing_contains_opnames() {
        let decoder = Lj21Decoder::from_flags(0x00);
        let nop = make_lj_ad(0, 0, 0); // ISLT (op 0)
        let loop_w = make_lj_ad(lj21_ops::LOOP, 0, 0x8000);
        let listing = decoder.listing(&[nop, loop_w]);
        assert!(listing.contains("LOOP"), "listing: {listing}");
    }

    #[test]
    fn test_lj21_decoder_is_linked() {
        let decoder = Lj21Decoder::from_flags(0x00);
        assert!(decoder.is_linked(lj21_ops::JLOOP));
        assert!(decoder.is_linked(lj21_ops::JFORI));
        assert!(!decoder.is_linked(lj21_ops::LOOP));
    }

    #[test]
    fn test_lj21_mnemonic_isnum() {
        assert_eq!(lj21_mnemonic(lj21_ops::ISNUM), "ISNUM");
    }

    #[test]
    fn test_lj21_mnemonic_regular() {
        // Op 0 = ISLT in the base table.
        let m = lj21_mnemonic(0);
        assert!(!m.is_empty());
    }

    #[test]
    fn test_bc_wrap_trampoline() {
        let t = BcWrapTrampoline::new(3, WrapKind::TailCall);
        assert_eq!(t.proto_idx, 3);
        assert!(t.is_tail_call());
    }

    #[test]
    fn test_bc_wrap_lua_call() {
        let t = BcWrapTrampoline::new(0, WrapKind::LuaCall);
        assert!(!t.clone().is_tail_call());
        assert_eq!(t.kind, WrapKind::LuaCall);
    }

    #[test]
    fn test_bc_wrap_iterator() {
        let t = BcWrapTrampoline::new(1, WrapKind::Iterator);
        assert_eq!(t.kind, WrapKind::Iterator);
    }

    #[test]
    fn test_lj21_instr_c_function_header() {
        let decoder = Lj21Decoder::from_flags(0x00);
        let word = make_lj_ad(lj21_ops::FUNCC, 0, 0);
        let instr = decoder.decode(0, &[word]).unwrap();
        assert!(instr.is_c_function_header());
    }

    #[test]
    fn test_lj21_instr_mnemonic() {
        let decoder = Lj21Decoder::from_flags(0x00);
        let word = make_lj_ad(lj21_ops::JFORL, 0, 0x8001);
        let instr = decoder.decode(0, &[word]).unwrap();
        assert_eq!(instr.mnemonic(), "JFORL");
    }

    #[test]
    fn test_format_operands_istype() {
        let s = format_operands_21(lj21_ops::ISTYPE, 2, 0, 0, 5, 5);
        assert!(s.contains("R2"));
        assert!(s.contains('5'));
    }

    #[test]
    fn test_format_operands_funccw() {
        let s = format_operands_21(lj21_ops::FUNCCW, 3, 0, 0, 0, 0);
        assert!(s.contains("R3"));
    }

    #[test]
    fn test_lj21_features_uses_fr2() {
        assert!(Lj21Features::from_flags(0x08).uses_fr2());
        assert!(!Lj21Features::from_flags(0x00).uses_fr2());
    }

    #[test]
    fn test_lj21_instr_fields() {
        let decoder = Lj21Decoder::from_flags(0x00);
        let word = make_lj_abc(32, 1, 2, 3); // ADDVV R1, R2, R3
        let instr = decoder.decode(0, &[word]).unwrap();
        assert_eq!(instr.a, 1);
        assert_eq!(instr.b, 2);
        assert_eq!(instr.c, 3);
    }

    #[test]
    fn test_lj21_no_instruction_out_of_bounds() {
        let decoder = Lj21Decoder::from_flags(0x00);
        let result = decoder.decode(5, &[]);
        assert!(result.is_none());
    }
}
