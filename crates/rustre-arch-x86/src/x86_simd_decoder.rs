//! SIMD / AVX instruction decoder for x86.
//!
//! Provides [`X86SimdDecoder`], [`SimdInsn`], [`SimdGroup`], and
//! [`decode_simd()`] for classifying SSE/AVX/AVX-512 instructions and
//! extracting their operand and vector-width information from raw byte
//! sequences via `iced-x86`.
//!
//! # Layer distinction
//!
//! This module is the **runtime SIMD decoder**: it drives `iced-x86` to fully
//! decode instructions, classifies them into [`SimdGroup`] subgroups (SSE,
//! SSE2, SSSE3, AVX, AVX-512, AES-NI, SHA, …), and extracts vector widths
//! and AVX-512 masking information.
//!
//! For **static descriptor tables** — compile-time `const` [`crate::sse::SseInstr`]
//! entries that annotate already-decoded instructions with category and
//! description strings — see [`crate::sse`].
//!
//! # Dispatch status (NOT wired — 2026-07-23)
//!
//! This module does not run. `crate::sse` is the one on the real path (used
//! ~10× from `lift.rs`); the only references to `X86SimdDecoder` / `decode_simd`
//! in the workspace are the `pub mod` line in lib.rs and `tests/blitz.rs`.
//!
//! This replaces the previous "the two modules are complementary" claim, which
//! implied both execute. They do not: the leaner descriptor table runs and the
//! richer decoder here — SSE/SSSE3/AVX/AVX-512/AES-NI/SHA subgroup
//! classification, vector-width and AVX-512 masking extraction — is inert. The
//! project does not have that classification available to analysis today.
//!
//! Keep, delete, or wire — but do not assume it is live.

use std::collections::HashMap;
use std::fmt;

use iced_x86::{
    Decoder, DecoderOptions, Instruction, Mnemonic, OpKind, Register,
};

// ─────────────────────────────────────────────────────────────────────────────
// SimdGroup
// ─────────────────────────────────────────────────────────────────────────────

/// Top-level classification of a SIMD instruction family.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SimdGroup {
    /// Scalar or packed SSE (XMM, 128-bit).
    Sse,
    /// SSE2 (integer ops, double-precision, extended moves).
    Sse2,
    /// SSE3 (horizontal ops, MONITOR/MWAIT).
    Sse3,
    /// SSSE3 (supplemental — pshufb, phadd, etc.).
    Ssse3,
    /// SSE4.1 (blending, round, mpsadbw, etc.).
    Sse41,
    /// SSE4.2 (string ops, CRC32).
    Sse42,
    /// AVX / VEX-encoded 256-bit operations.
    Avx,
    /// AVX2 integer 256-bit operations.
    Avx2,
    /// AVX-512 Foundation (EVEX, 512-bit).
    Avx512F,
    /// AVX-512 Byte/Word.
    Avx512Bw,
    /// AVX-512 Doubleword/Quadword.
    Avx512Dq,
    /// AVX-512 Vector Length extensions.
    Avx512Vl,
    /// AES-NI instructions.
    Aes,
    /// PCLMULQDQ (carry-less multiplication).
    Pclmul,
    /// SHA extensions.
    Sha,
    /// AMX (Advanced Matrix Extensions).
    Amx,
    /// Generic/unknown SIMD.
    Unknown,
}

impl fmt::Display for SimdGroup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Sse => "SSE",
            Self::Sse2 => "SSE2",
            Self::Sse3 => "SSE3",
            Self::Ssse3 => "SSSE3",
            Self::Sse41 => "SSE4.1",
            Self::Sse42 => "SSE4.2",
            Self::Avx => "AVX",
            Self::Avx2 => "AVX2",
            Self::Avx512F => "AVX-512F",
            Self::Avx512Bw => "AVX-512BW",
            Self::Avx512Dq => "AVX-512DQ",
            Self::Avx512Vl => "AVX-512VL",
            Self::Aes => "AES-NI",
            Self::Pclmul => "PCLMUL",
            Self::Sha => "SHA",
            Self::Amx => "AMX",
            Self::Unknown => "UNKNOWN",
        };
        write!(f, "{s}")
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// VectorWidth
// ─────────────────────────────────────────────────────────────────────────────

/// Effective vector register width in bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum VectorWidth {
    Xmm = 128,
    Ymm = 256,
    Zmm = 512,
    Tmm = 8192, // AMX tile (arbitrary large value)
    Scalar,
}

impl fmt::Display for VectorWidth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Xmm => write!(f, "128b"),
            Self::Ymm => write!(f, "256b"),
            Self::Zmm => write!(f, "512b"),
            Self::Tmm => write!(f, "tile"),
            Self::Scalar => write!(f, "scalar"),
        }
    }
}

/// Derive vector width from an iced-x86 [`Register`].
const fn vector_width_from_reg(reg: Register) -> VectorWidth {
    use iced_x86::Register as R;
    let r = reg as u32;
    if r >= R::XMM0 as u32 && r <= R::XMM31 as u32 {
        VectorWidth::Xmm
    } else if r >= R::YMM0 as u32 && r <= R::YMM31 as u32 {
        VectorWidth::Ymm
    } else if r >= R::ZMM0 as u32 && r <= R::ZMM31 as u32 {
        VectorWidth::Zmm
    } else if r >= R::TMM0 as u32 && r <= R::TMM7 as u32 {
        VectorWidth::Tmm
    } else {
        VectorWidth::Scalar
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SimdInsn
// ─────────────────────────────────────────────────────────────────────────────

/// A fully decoded SIMD instruction record.
#[derive(Debug, Clone)]
pub struct SimdInsn {
    /// Virtual address of the instruction.
    pub address: u64,
    /// Mnemonic text (lower-case).
    pub mnemonic: String,
    /// Raw bytes of this instruction.
    pub bytes: Vec<u8>,
    /// SIMD family group.
    pub group: SimdGroup,
    /// Effective vector register width.
    pub vector_width: VectorWidth,
    /// Number of operands.
    pub operand_count: u32,
    /// Whether this instruction uses masking (k1..k7).
    pub uses_mask: bool,
    /// Whether the mask is zero-masking (vs. merge-masking).
    pub zero_masking: bool,
    /// Whether this is a memory-to-register load operation.
    pub is_load: bool,
    /// Whether this is a register-to-memory store operation.
    pub is_store: bool,
    /// Whether EVEX broadcast (`{1to4}`, `{1to8}`, etc.) is active.
    pub broadcast: bool,
    /// Optional element type hint (e.g. "f32", "i64", "f64").
    pub element_type: Option<String>,
    /// Human-readable one-line description, when the mnemonic has a matching
    /// entry in the [`crate::sse`] static descriptor tables (legacy
    /// SSE/SSE2/SSSE3/SSE4 family only — AVX/AVX-512 `V`-prefixed mnemonics
    /// have no entry there and this is `None` for them).
    pub description: Option<&'static str>,
}

impl SimdInsn {
    /// Format a one-line summary.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "{:#010x}  {:20}  [{} / {}]{}{}{}",
            self.address,
            self.mnemonic,
            self.group,
            self.vector_width,
            if self.uses_mask { " mask" } else { "" },
            if self.broadcast { " bcast" } else { "" },
            if self.is_load {
                " ld"
            } else if self.is_store {
                " st"
            } else {
                ""
            },
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SimdDecoderOptions
// ─────────────────────────────────────────────────────────────────────────────

/// Configuration for the SIMD decoder.
#[derive(Debug, Clone)]
pub struct SimdDecoderOptions {
    /// Machine bitness (16, 32, or 64).
    pub bitness: u32,
    /// Whether to decode non-SIMD instructions as well (they are filtered out).
    pub strict_simd_only: bool,
}

impl Default for SimdDecoderOptions {
    fn default() -> Self {
        Self {
            bitness: 64,
            strict_simd_only: true,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// X86SimdDecoder
// ─────────────────────────────────────────────────────────────────────────────

/// Decodes SIMD/AVX instructions from raw byte sequences.
///
/// Internally wraps `iced-x86` to decode instructions and then classifies
/// each one into a [`SimdGroup`] and extracts [`SimdInsn`] metadata.
#[derive(Debug)]
pub struct X86SimdDecoder {
    options: SimdDecoderOptions,
    /// Mnemonic-name to `SimdGroup` override table.
    group_overrides: HashMap<String, SimdGroup>,
}

impl X86SimdDecoder {
    /// Create a new decoder with default options (64-bit, SIMD-only).
    #[must_use]
    pub fn new_64bit() -> Self {
        Self {
            options: SimdDecoderOptions::default(),
            group_overrides: HashMap::new(),
        }
    }

    /// Create a new decoder with the given options.
    #[must_use]
    pub fn with_options(options: SimdDecoderOptions) -> Self {
        Self {
            options,
            group_overrides: HashMap::new(),
        }
    }

    /// Register a custom [`SimdGroup`] for a specific mnemonic (lower-case).
    pub fn add_group_override(&mut self, mnemonic: impl Into<String>, group: SimdGroup) {
        self.group_overrides.insert(mnemonic.into(), group);
    }

    /// Decode `bytes` starting at `base_address` and return all SIMD
    /// instructions found.  Non-SIMD instructions are silently skipped.
    #[must_use]
    pub fn decode_bytes(&self, base_address: u64, bytes: &[u8]) -> Vec<SimdInsn> {
        let mut decoder = Decoder::with_ip(
            self.options.bitness,
            bytes,
            base_address,
            DecoderOptions::NONE,
        );
        let mut out = Vec::new();
        while decoder.can_decode() {
            let start_pos = decoder.position();
            let instr = decoder.decode();
            let end_pos = decoder.position();

            // Only clone the raw bytes once we know the instruction will
            // actually be kept — avoids an allocation per discarded
            // (non-SIMD, when `strict_simd_only` is set) instruction.
            if let Some(si) = self.classify(
                &instr,
                base_address.wrapping_add(start_pos as u64),
                || bytes[start_pos..end_pos].to_vec(),
            ) {
                out.push(si);
            }
        }
        out
    }

    /// Decode a single instruction from `bytes` at `address`.
    #[must_use]
    pub fn decode_one(&self, address: u64, bytes: &[u8]) -> Option<SimdInsn> {
        let mut decoder = Decoder::with_ip(
            self.options.bitness,
            bytes,
            address,
            DecoderOptions::NONE,
        );
        if !decoder.can_decode() {
            return None;
        }
        let instr = decoder.decode();
        let len = instr.len();
        self.classify(&instr, address, || bytes[..len].to_vec())
    }

    // ------------------------------------------------------------------
    // Internal: classify an iced instruction as SIMD or not.
    // ------------------------------------------------------------------

    fn classify(
        &self,
        instr: &Instruction,
        address: u64,
        raw: impl FnOnce() -> Vec<u8>,
    ) -> Option<SimdInsn> {
        use iced_x86::Code;

        // Track the raw opcode `Code` so callers needing the iced taxonomy can
        // cross-reference it in debug builds (and so the strict-mode filter
        // below can fast-reject INVALID without going through the formatter).
        let code: Code = instr.code();
        if code == Code::INVALID {
            return None;
        }
        let m: Mnemonic = instr.mnemonic();
        let mnemonic = format!("{m:?}").to_ascii_lowercase();

        let group = if let Some(g) = self.group_overrides.get(&mnemonic) {
            g.clone()
        } else {
            Self::classify_group(instr.code())
        };

        if self.options.strict_simd_only && group == SimdGroup::Unknown {
            return None;
        }

        // Determine vector width from destination register.
        let mut vector_width = VectorWidth::Scalar;
        // AVX-512 masking lives in the EVEX opmask FIELD, not in the operand
        // list. Verified against the decoder rather than assumed:
        // `vandps zmm0{k1}{z},zmm1,zmm2` reports `op_count() == 3` with
        // operands ZMM0/ZMM1/ZMM2 and `op_mask() == K1` — K1 is not an operand
        // at all.
        //
        // This field was previously set by scanning the operands for K1..K7,
        // so it could NEVER be true for a masked EVEX instruction: masking
        // detection, the capability this module exists to provide, was dead.
        // Nothing asserted it, which is why it survived.
        //
        // The operand scan is not merely insufficient, it asked the wrong
        // question: an instruction that WRITES a mask register
        // (`vpcmpeqd k1, zmm0, zmm1`) is producing a mask, not applying one.
        let uses_mask = instr.op_mask() != Register::None;
        // Seed with the iced flag; AVX-512 EVEX `{z}` is the canonical source.
        let mut zero_masking = instr.zeroing_masking();
        let mut is_load = false;
        let mut is_store = false;

        for i in 0..instr.op_count() {
            match instr.op_kind(i) {
                OpKind::Register => {
                    let reg = instr.op_register(i);
                    let w = vector_width_from_reg(reg);
                    // VectorWidth derives Ord from declaration order, which puts
                    // Scalar last (greatest). Treat Scalar as the lowest priority
                    // so any vector register width replaces it.
                    if w != VectorWidth::Scalar
                        && (vector_width == VectorWidth::Scalar || w > vector_width)
                    {
                        vector_width = w;
                    }
                    // NOTE: a k-register appearing as an OPERAND is deliberately
                    // NOT treated as masking here — see `uses_mask` above.
                }
                OpKind::Memory => {
                    if i == 0 {
                        is_store = true;
                    } else {
                        is_load = true;
                    }
                }
                _ => {}
            }
        }

        // Re-check after operand scan in case any operand toggled the flag
        // (defensive: iced returns the EVEX z-bit unconditionally).
        zero_masking |= instr.zeroing_masking();
        let broadcast = instr.is_broadcast();

        let element_type = Self::infer_element_type(&mnemonic);
        let description = crate::sse::lookup_by_mnemonic(&mnemonic).map(|e| e.description);

        Some(SimdInsn {
            address,
            mnemonic,
            bytes: raw(),
            group,
            vector_width,
            operand_count: instr.op_count(),
            uses_mask,
            zero_masking,
            is_load,
            is_store,
            broadcast,
            element_type,
            description,
        })
    }

    fn classify_group(code: iced_x86::Code) -> SimdGroup {
        use iced_x86::Code as C;
        // Fast path: non-SIMD/INVALID codes never need the string scan below.
        if matches!(code, C::INVALID) {
            return SimdGroup::Unknown;
        }
        let s = format!("{code:?}").to_ascii_lowercase();
        // Order matters: check more specific prefixes first.
        if s.contains("aes") {
            SimdGroup::Aes
        } else if s.contains("pclmul") {
            SimdGroup::Pclmul
        } else if s.contains("sha") {
            SimdGroup::Sha
        } else if s.contains("amx") || s.contains("tmm") || s.contains("tileload") || s.contains("tilestore") {
            SimdGroup::Amx
        } else if s.starts_with("evex") || s.contains("_zmm") || s.contains("zmm") {
            SimdGroup::Avx512F
        } else if s.contains("avx2") {
            SimdGroup::Avx2
        } else if s.contains("_ymm") || s.contains("ymm") || s.starts_with("vex") {
            SimdGroup::Avx
        } else if s.contains("sse42") || s.contains("crc32") || s.contains("pcmpestri") || s.contains("pcmpestrm") {
            SimdGroup::Sse42
        } else if s.contains("sse41") || s.contains("blend") || s.contains("round") || s.contains("mpsadbw") {
            SimdGroup::Sse41
        } else if s.contains("ssse3") || s.contains("pshufb") || s.contains("phadd") {
            SimdGroup::Ssse3
        } else if s.contains("sse3") || s.contains("haddps") || s.contains("movddup") {
            SimdGroup::Sse3
        } else if s.contains("sse2") || s.contains("_pd") || s.contains("movdqa") || s.contains("movdqu") {
            SimdGroup::Sse2
        } else if s.contains("sse") || s.contains("_ps") || s.contains("movaps") || s.contains("movups") || s.contains("xmm") || s.contains("mmx") || s.contains("_mm_") {
            SimdGroup::Sse // treat MMX as legacy SSE
        } else {
            SimdGroup::Unknown
        }
    }

    fn infer_element_type(mnemonic: &str) -> Option<String> {
        if mnemonic.ends_with("pd") || mnemonic.contains("pd_") {
            Some("f64".into())
        } else if mnemonic.ends_with("ps") || mnemonic.contains("ps_") {
            Some("f32".into())
        } else if mnemonic.ends_with("sd") {
            Some("f64_scalar".into())
        } else if mnemonic.ends_with("ss") {
            Some("f32_scalar".into())
        } else if mnemonic.contains("epi64") || mnemonic.contains("epu64") {
            Some("i64".into())
        } else if mnemonic.contains("epi32") || mnemonic.contains("epu32") {
            Some("i32".into())
        } else if mnemonic.contains("epi16") || mnemonic.contains("epu16") {
            Some("i16".into())
        } else if mnemonic.contains("epi8") || mnemonic.contains("epu8") {
            Some("i8".into())
        } else {
            None
        }
    }

    /// Statistics: count instructions per [`SimdGroup`].
    #[must_use]
    pub fn group_histogram(&self, insns: &[SimdInsn]) -> HashMap<String, usize> {
        let mut map: HashMap<String, usize> = HashMap::new();
        for insn in insns {
            *map.entry(insn.group.to_string()).or_default() += 1;
        }
        map
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// decode_simd
// ─────────────────────────────────────────────────────────────────────────────

/// Decode all SIMD instructions from `bytes` starting at `base_address`.
///
/// This is the primary free-function entry point.
#[must_use]
pub fn decode_simd(base_address: u64, bytes: &[u8], bitness: u32) -> Vec<SimdInsn> {
    let decoder = X86SimdDecoder::with_options(SimdDecoderOptions {
        bitness,
        strict_simd_only: true,
    });
    decoder.decode_bytes(base_address, bytes)
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// SSE2: MOVAPS xmm0, xmm1
    const MOVAPS: &[u8] = &[0x0F, 0x28, 0xC1];
    /// AVX: VMOVAPS ymm0, ymm1
    const VMOVAPS_YMM: &[u8] = &[0xC5, 0xFC, 0x28, 0xC1];
    /// AVX-512: VMOVAPS zmm0 {k1}{z}, zmm1
    const _VMOVAPS_ZMM: &[u8] = &[0x62, 0xF1, 0x7C, 0xC9, 0x28, 0xC1];
    /// NOP — should be filtered out by strict mode.
    const NOP: &[u8] = &[0x90];

    #[test]
    fn decode_movaps_is_sse() {
        let d = X86SimdDecoder::new_64bit();
        let insns = d.decode_bytes(0x1000, MOVAPS);
        assert_eq!(insns.len(), 1);
        assert_eq!(insns[0].group, SimdGroup::Sse);
        assert_eq!(insns[0].vector_width, VectorWidth::Xmm);
    }

    #[test]
    fn decode_vmovaps_ymm_is_avx() {
        let d = X86SimdDecoder::new_64bit();
        let insns = d.decode_bytes(0x1000, VMOVAPS_YMM);
        assert_eq!(insns.len(), 1);
        assert_eq!(insns[0].group, SimdGroup::Avx);
        assert_eq!(insns[0].vector_width, VectorWidth::Ymm);
    }

    #[test]
    fn decode_simd_free_function() {
        let insns = decode_simd(0x1000, MOVAPS, 64);
        assert_eq!(insns.len(), 1);
    }

    #[test]
    fn nop_filtered_in_strict_mode() {
        let d = X86SimdDecoder::new_64bit();
        let insns = d.decode_bytes(0x1000, NOP);
        assert!(insns.is_empty());
    }

    #[test]
    fn nop_included_in_non_strict_mode() {
        let d = X86SimdDecoder::with_options(SimdDecoderOptions {
            bitness: 64,
            strict_simd_only: false,
        });
        let insns = d.decode_bytes(0x1000, NOP);
        assert!(!insns.is_empty());
    }

    #[test]
    fn decode_one_returns_single_insn() {
        let d = X86SimdDecoder::new_64bit();
        let result = d.decode_one(0x1000, MOVAPS);
        assert!(result.is_some());
    }

    #[test]
    fn group_override_takes_precedence() {
        let mut d = X86SimdDecoder::new_64bit();
        d.add_group_override("movaps", SimdGroup::Aes);
        let insns = d.decode_bytes(0x1000, MOVAPS);
        assert_eq!(insns[0].group, SimdGroup::Aes);
    }

    #[test]
    fn summary_contains_mnemonic() {
        let d = X86SimdDecoder::new_64bit();
        let insns = d.decode_bytes(0x1000, MOVAPS);
        let s = insns[0].summary();
        assert!(s.contains("movaps") || s.contains("MOVAPS"));
    }

    #[test]
    fn group_histogram_counts() {
        let d = X86SimdDecoder::new_64bit();
        let mut buf = Vec::new();
        buf.extend_from_slice(MOVAPS);
        buf.extend_from_slice(VMOVAPS_YMM);
        let insns = d.decode_bytes(0x1000, &buf);
        let hist = d.group_histogram(&insns);
        assert!(hist.values().sum::<usize>() >= 2);
    }

    /// REGRESSION: AVX-512 masking must be read from the EVEX opmask FIELD.
    ///
    /// `uses_mask` was derived by scanning the operand list for K1..K7, but a
    /// masked EVEX instruction does not carry its mask as an operand:
    /// `vandps zmm0{k1}{z},zmm1,zmm2` decodes to three operands
    /// (ZMM0/ZMM1/ZMM2) with the mask in `op_mask()`. So the flag could never
    /// be true for the case it exists to describe, and nothing asserted it.
    #[test]
    fn evex_masking_is_detected() {
        use iced_x86::{Code, Encoder, Instruction, Register};

        let build = |mask: Register, zeroing: bool| {
            let mut i = Instruction::with3(
                Code::EVEX_Vandps_zmm_k1z_zmm_zmmm512b32,
                Register::ZMM0,
                Register::ZMM1,
                Register::ZMM2,
            )
            .unwrap();
            if mask != Register::None {
                i.set_op_mask(mask);
            }
            i.set_zeroing_masking(zeroing);
            let mut enc = Encoder::new(64);
            enc.encode(&i, 0x1000).unwrap();
            enc.take_buffer()
        };

        let dec = X86SimdDecoder::new_64bit();

        let masked = dec.decode_one(0x1000, &build(Register::K1, false)).unwrap();
        assert!(masked.uses_mask, "{}", masked.summary());
        assert!(!masked.zero_masking);
        assert_eq!(masked.vector_width, VectorWidth::Zmm);

        let zeroed = dec.decode_one(0x1000, &build(Register::K2, true)).unwrap();
        assert!(zeroed.uses_mask);
        assert!(zeroed.zero_masking);

        // Unmasked must stay false — a flag that is always true is no better
        // than one that is always false.
        let plain = dec.decode_one(0x1000, &build(Register::None, false)).unwrap();
        assert!(!plain.uses_mask, "{}", plain.summary());
    }

    #[test]
    fn vector_width_ordering() {
        assert!(VectorWidth::Zmm > VectorWidth::Ymm);
        assert!(VectorWidth::Ymm > VectorWidth::Xmm);
    }

    #[test]
    fn simd_group_display() {
        assert_eq!(SimdGroup::Avx512F.to_string(), "AVX-512F");
        assert_eq!(SimdGroup::Sse42.to_string(), "SSE4.2");
    }
}
