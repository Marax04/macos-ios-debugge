//! `X86LifterV2` — the new modular x86/x64 lifter.
//!
//! CALL-GRAPH STATUS (investigated 2026-07-12): this module is UNREFERENCED
//! outside this crate. `X86LifterV2` (and the `x86_handlers` module it wraps)
//! is exported from `lib.rs` but no other workspace crate
//! (`rustre-arch-x86`, `rustre-il-llil`, `rustre-il-mlil`,
//! `rustre-mcp-tools`) calls it; the only reference is this crate's own
//! tests. The x86 module actually used by the real decompiler pipeline
//! (`rustre-decompiler`) is the separate, unrelated
//! `rustre-arch-x86/src/lift.rs`. Do not confuse the two, and do not assume
//! this module is dead code to delete — see repo convention of documenting
//! rather than removing such modules.
//!
//! This is the production-facing struct that:
//!
//!   1. accepts raw bytes + a base address,
//!   2. decodes them with `iced-x86`,
//!   3. routes every decoded instruction through `x86_handlers::lift_instruction`,
//!   4. wraps the resulting `X86LiftCtx` output into the crate's `LiftedInstr`,
//!   5. participates in the `ArchLifter` trait so it can be registered in the
//!      `LifterRegistry`.
//!
//! `X86LifterV2` coexists with the original `X86Lifter` in `lib.rs`; it is
//! not a drop-in replacement but an additive improvement. The original lifter
//! handles a subset of opcodes through its own pattern; V2 handles the full
//! ISA through the modular handler table.

use crate::{
    ArchLifter, Effect, IrExpr, LiftError, LiftLevel, LiftedInstr,
    x86_context::{ModeHint, X86LiftCtx},
    x86_handlers::lift_instruction,
};
use iced_x86::{Decoder, DecoderOptions, Instruction as IcedInstr};
use rustre_core::arch::Instruction;
use std::fmt;

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// X86LifterV2
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// The second-generation x86/x64 LLIL lifter.
///
/// # Fields
///
/// * `bits` â€” machine mode: 16, 32, or 64. Must be one of these three values.
/// * `error_recovery` â€” if `true`, instructions that the handler table cannot
///   fully translate are emitted as `Effect::Intrinsic` stubs rather than
///   producing a `LiftError`. This matches production usage where completeness
///   is more valuable than strict correctness for rare opcodes.
#[derive(Debug, Clone)]
pub struct X86LifterV2 {
    /// Machine mode: 16, 32, or 64.
    pub bits: u8,
    /// Fall back to an opaque intrinsic for unsupported mnemonics rather than
    /// returning `LiftError::LiftFailed`.
    pub error_recovery: bool,
}

impl X86LifterV2 {
    /// Create a 64-bit lifter with error recovery enabled (recommended default).
    #[must_use]
    pub const fn new_64() -> Self {
        Self {
            bits: 64,
            error_recovery: true,
        }
    }

    /// Create a 32-bit lifter with error recovery enabled.
    #[must_use]
    pub const fn new_32() -> Self {
        Self {
            bits: 32,
            error_recovery: true,
        }
    }

    /// Create a 16-bit lifter (legacy x86 / real-mode DOS analysis).
    #[must_use]
    pub const fn new_16() -> Self {
        Self {
            bits: 16,
            error_recovery: true,
        }
    }

    /// Create a lifter with explicit settings.
    #[must_use]
    /// Lifts this instruction into the IL.
    ///
    /// # Panics
    ///
    /// Panics if internal state is inconsistent.
    pub fn new(bits: u8, error_recovery: bool) -> Self {
        assert!(matches!(bits, 16 | 32 | 64), "bits must be 16, 32, or 64");
        Self {
            bits,
            error_recovery,
        }
    }

    /// Convert a `rustre_core::arch::Instruction` to an `iced_x86::Instruction`
    /// by re-decoding the raw bytes. This bridges the two type systems without
    /// requiring a direct dependency on iced-x86 in `rustre-core`.
    fn decode_instr(&self, instr: &Instruction) -> Result<IcedInstr, LiftError> {
        let bytes = &instr.bytes;
        let addr = instr.address.0;
        let bitness = u32::from(self.bits);
        let mut decoder = Decoder::with_ip(bitness, bytes, addr, DecoderOptions::NONE);
        let iced = decoder.decode();
        if iced.is_invalid() {
            Err(LiftError::DisasmFailed(
                addr,
                "iced-x86 reports invalid".into(),
            ))
        } else {
            Ok(iced)
        }
    }

    /// Lift a single already-decoded `iced_x86::Instruction`.
    ///
    /// # Errors
    ///
    /// Returns an error if the IL lifting operation fails.
    pub fn lift_iced(&self, iced: &IcedInstr, addr: u64) -> Result<LiftedInstr, LiftError> {
        let mode = ModeHint::from_instr(iced);
        let mut ctx = X86LiftCtx::new(addr, self.bits, mode);

        let lift_result = lift_instruction(iced, &mut ctx);

        if let Err(e) = lift_result {
            if self.error_recovery {
                // Emit a stub intrinsic so the CFG remains connected.
                ctx.emit(Effect::Intrinsic {
                    name: format!("x86.unlifted.{:?}", iced.mnemonic()),
                    args: vec![IrExpr::Const(addr)],
                });
            } else {
                return Err(e);
            }
        }

        let mut mnemonic = format!("{:?}", iced.mnemonic());
        mnemonic.make_ascii_lowercase();
        Ok(LiftedInstr {
            address: addr,
            original_mnemonic: mnemonic,
            ir_text: if ctx.ir_text.is_empty() {
                "nop".into()
            } else {
                ctx.ir_text
            },
            il_level: LiftLevel::Llil,
            effects: ctx.effects,
        })
    }

    /// Lift a contiguous block of bytes starting at `base_addr`.
    ///
    /// Decodes and lifts instructions sequentially until all `bytes` are
    /// consumed or an `INVALID` opcode is encountered. Returns the
    /// successfully lifted instructions and any per-instruction errors.
    #[must_use] 
    pub fn lift_bytes(
        &self,
        bytes: &[u8],
        base_addr: u64,
    ) -> (Vec<LiftedInstr>, Vec<(u64, LiftError)>) {
        let bitness = u32::from(self.bits);
        let mut decoder = Decoder::with_ip(bitness, bytes, base_addr, DecoderOptions::NONE);
        // Average x86 instruction is ~3-4 bytes; preallocate to avoid repeated regrowth.
        let mut lifted = Vec::with_capacity(bytes.len() / 3);
        let mut errors = Vec::new();

        while decoder.can_decode() {
            let iced = decoder.decode();
            let addr = iced.ip();
            if iced.is_invalid() {
                errors.push((
                    addr,
                    LiftError::DisasmFailed(addr, "invalid encoding".into()),
                ));
                break;
            }
            match self.lift_iced(&iced, addr) {
                Ok(li) => lifted.push(li),
                Err(e) => errors.push((addr, e)),
            }
        }

        (lifted, errors)
    }
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// ArchLifter implementation
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

impl ArchLifter for X86LifterV2 {
    fn arch_name(&self) -> &'static str {
        match self.bits {
            64 => "x86_64_v2",
            32 => "x86_32_v2",
            _ => "x86_16_v2",
        }
    }

    fn lift_level(&self) -> LiftLevel {
        LiftLevel::Llil
    }

    fn lift(&self, instr: &Instruction) -> Result<LiftedInstr, LiftError> {
        let iced = self.decode_instr(instr)?;
        self.lift_iced(&iced, instr.address.0)
    }

    fn lift_block(&self, instrs: &[Instruction]) -> Vec<Result<LiftedInstr, LiftError>> {
        instrs.iter().map(|i| self.lift(i)).collect()
    }

    fn description(&self) -> &'static str {
        "x86/x64 LLIL lifter v2 (full ISA coverage via handler table)"
    }

    fn supports_mnemonic(&self, _mnemonic: &str) -> bool {
        // V2 claims support for all mnemonics; unsupported ones fall through to
        // the error-recovery stub path rather than returning false here.
        true
    }
}

impl fmt::Display for X86LifterV2 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "X86LifterV2(bits={}, recovery={})",
            self.bits, self.error_recovery
        )
    }
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// Convenience builders
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Build a V2 lifter and register it in the provided registry under the
/// given architecture string.
pub fn register_v2_lifter(registry: &mut crate::LifterRegistry, bits: u8, error_recovery: bool) {
    let lifter = X86LifterV2::new(bits, error_recovery);
    registry.register(lifter);
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// Tests
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

#[cfg(test)]
mod tests {
    use super::*;
    use crate::LiftLevel;

    fn lifter() -> X86LifterV2 {
        X86LifterV2::new_64()
    }

    /// Encode a single instruction via iced-x86's `CodeAssembler` is not
    /// available here; instead we provide known-good byte sequences.

    // NOP (0x90)
    #[test]
    fn lift_nop_bytes() {
        let (lifted, errors) = lifter().lift_bytes(&[0x90], 0x1000);
        assert!(errors.is_empty(), "errors: {errors:?}");
        assert_eq!(lifted.len(), 1);
        assert_eq!(lifted[0].il_level, LiftLevel::Llil);
    }

    // RET (0xC3)
    #[test]
    fn lift_ret_bytes() {
        let (lifted, errors) = lifter().lift_bytes(&[0xc3], 0x2000);
        assert!(errors.is_empty(), "errors: {errors:?}");
        assert_eq!(lifted.len(), 1);
        // RET should produce a Return effect.
        let has_return = lifted[0]
            .effects
            .iter()
            .any(|e| matches!(e, Effect::Return { .. }));
        assert!(has_return, "expected Return effect in RET");
    }

    // MOV rax, 0x42  (48 B8 42 00 00 00 00 00 00 00)
    #[test]
    fn lift_mov_imm64() {
        let bytes = [0x48, 0xb8, 0x42, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let (lifted, errors) = lifter().lift_bytes(&bytes, 0x3000);
        assert!(errors.is_empty(), "errors: {errors:?}");
        assert_eq!(lifted.len(), 1);
        let has_reg_write = lifted[0]
            .effects
            .iter()
            .any(|e| matches!(e, Effect::RegWrite { reg, .. } if reg == "rax"));
        assert!(has_reg_write, "expected RegWrite to rax");
    }

    // PUSH rbp (0x55) + MOV rbp, rsp (48 89 E5) â€” typical function prologue
    #[test]
    fn lift_function_prologue() {
        let bytes = [0x55u8, 0x48, 0x89, 0xe5];
        let (lifted, errors) = lifter().lift_bytes(&bytes, 0x4000);
        assert!(errors.is_empty(), "errors: {errors:?}");
        assert_eq!(lifted.len(), 2);
        // PUSH should write to memory.
        assert!(
            lifted[0]
                .effects
                .iter()
                .any(|e| matches!(e, Effect::MemWrite { .. }))
        );
    }

    // JE rel8 (74 XX) â€” conditional jump.
    #[test]
    fn lift_je_rel8() {
        let bytes = [0x74u8, 0x10]; // JE +0x10
        let (lifted, errors) = lifter().lift_bytes(&bytes, 0x5000);
        assert!(errors.is_empty(), "errors: {errors:?}");
        assert_eq!(lifted.len(), 1);
        let has_branch = lifted[0].effects.iter().any(|e| {
            matches!(
                e,
                Effect::Branch {
                    condition: Some(_),
                    ..
                }
            )
        });
        assert!(has_branch, "expected conditional Branch effect");
    }

    // CALL rel32 (E8 XX XX XX XX)
    #[test]
    fn lift_call_rel32() {
        let bytes = [0xe8u8, 0x00, 0x00, 0x00, 0x00]; // CALL +0
        let (lifted, errors) = lifter().lift_bytes(&bytes, 0x6000);
        assert!(errors.is_empty(), "errors: {errors:?}");
        // CALL emits SP decrement + store + Call effect.
        let has_call = lifted[0]
            .effects
            .iter()
            .any(|e| matches!(e, Effect::Call { .. }));
        assert!(has_call, "expected Call effect");
    }

    // XOR eax, eax (31 C0) â€” common register-zeroing idiom
    #[test]
    fn lift_xor_self_zeroing() {
        let bytes = [0x31u8, 0xc0];
        let (lifted, errors) = lifter().lift_bytes(&bytes, 0x7000);
        assert!(errors.is_empty(), "errors: {errors:?}");
        assert_eq!(lifted.len(), 1);
        // Should write zf, cf, of, sf, pf.
        let reg_writes: Vec<_> = lifted[0]
            .effects
            .iter()
            .filter_map(|e| {
                if let Effect::RegWrite { reg, .. } = e {
                    Some(reg.as_str())
                } else {
                    None
                }
            })
            .collect();
        assert!(reg_writes.contains(&"zf"), "missing zf");
        assert!(reg_writes.contains(&"cf"), "missing cf");
    }

    // Error recovery: invalid opcode 0xFF 0xFF should not panic.
    #[test]
    fn invalid_opcode_does_not_panic() {
        // An all-0xFF sequence will be decoded as something iced handles,
        // so use a sequence that is architecturally invalid.
        let bytes = [0x0fu8, 0x0b]; // UD2
        let (lifted, _errors) = lifter().lift_bytes(&bytes, 0x8000);
        // UD2 should produce an intrinsic + Return (we handle it in system.rs).
        assert_eq!(lifted.len(), 1);
    }

    // lift_bytes decodes multiple instructions.
    #[test]
    fn lift_bytes_multiple_instrs() {
        // NOP NOP NOP RET
        let bytes = [0x90u8, 0x90, 0x90, 0xc3];
        let (lifted, errors) = lifter().lift_bytes(&bytes, 0x9000);
        assert!(errors.is_empty());
        assert_eq!(lifted.len(), 4);
    }

    // Addresses are correctly assigned.
    #[test]
    fn lift_bytes_addresses() {
        // NOP (1 byte at 0x1000) + RET (1 byte at 0x1001)
        let bytes = [0x90u8, 0xc3];
        let (lifted, _) = lifter().lift_bytes(&bytes, 0x1000);
        assert_eq!(lifted[0].address, 0x1000);
        assert_eq!(lifted[1].address, 0x1001);
    }

    // arch_name
    #[test]
    fn arch_name_64() {
        assert_eq!(lifter().arch_name(), "x86_64_v2");
    }

    #[test]
    fn arch_name_32() {
        assert_eq!(X86LifterV2::new_32().arch_name(), "x86_32_v2");
    }

    // supports_mnemonic always true.
    #[test]
    fn supports_any_mnemonic() {
        assert!(lifter().supports_mnemonic("mov"));
        assert!(lifter().supports_mnemonic("vaddps"));
        assert!(lifter().supports_mnemonic("nonexistent"));
    }

    // Error recovery OFF â€” unsupported opcode returns LiftError.
    // We can't easily trigger this with valid bytes since every valid mnemonic
    // has a handler, so we test the struct configuration instead.
    #[test]
    fn error_recovery_flag() {
        let strict = X86LifterV2::new(64, false);
        assert!(!strict.error_recovery);
        let lenient = X86LifterV2::new(64, true);
        assert!(lenient.error_recovery);
    }
}
