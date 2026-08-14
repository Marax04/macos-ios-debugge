//! Return-type recovery for `rustre-analysis-callconv`.
//!
//! Infers the return type of a function by analysing how the caller uses the
//! value in the return register (`RAX` / `EAX` on x86-64/32, `X0` on ARM64,
//! `A0` on RISC-V) immediately after the `CALL` instruction returns.
//!
//! Techniques used:
//!
//! 1. **Compare with zero/null/negative** — `TEST EAX, EAX; JZ` suggests BOOL
//!    or pointer; `CMP EAX, 0; JL` suggests a signed integer error code.
//! 2. **HANDLE vs BOOL vs pointer** — `CMP EAX, -1` (`INVALID_HANDLE_VALUE`),
//!    `AND EAX, EAX; JZ` (null pointer check).
//! 3. **Integer narrowing** — `MOVSX`/`MOVZX` applied to `AL`/`AX` suggests
//!    the return is a byte or word.
//! 4. **Void detection** — the return register is never read after the CALL.
//! 5. **Float detection** — `MOVQ [mem], XMM0` or `CVTSD2SI` immediately after
//!    a CALL suggests float return.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

// ─────────────────────────────────────────────────────────────────────────────
// Inferred return type
// ─────────────────────────────────────────────────────────────────────────────

/// The inferred return type of a function.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum InferredReturnType {
    /// No return value (void / noreturn).
    Void,
    /// 1-byte boolean (0 = false, non-zero = true).
    Bool,
    /// 1-byte signed integer.
    I8,
    /// 1-byte unsigned integer.
    U8,
    /// 16-bit signed integer.
    I16,
    /// 16-bit unsigned integer.
    U16,
    /// 32-bit signed integer (typical NTSTATUS, errno return).
    I32,
    /// 32-bit unsigned integer.
    U32,
    /// 64-bit signed integer.
    I64,
    /// 64-bit unsigned integer.
    U64,
    /// Pointer (width depends on architecture).
    Pointer,
    /// Windows HANDLE (pointer-sized, checked with != `INVALID_HANDLE_VALUE`).
    Handle,
    /// 32-bit or 64-bit float.
    Float,
    /// 64-bit double.
    Double,
    /// Return type could not be determined.
    Unknown,
}

impl InferredReturnType {
    /// Human-readable C-style label.
    #[must_use]
    pub const fn c_label(self) -> &'static str {
        match self {
            Self::Void => "void",
            Self::Bool => "BOOL",
            Self::I8 => "int8_t",
            Self::U8 => "uint8_t",
            Self::I16 => "int16_t",
            Self::U16 => "uint16_t",
            Self::I32 => "int32_t",
            Self::U32 => "uint32_t",
            Self::I64 => "int64_t",
            Self::U64 => "uint64_t",
            Self::Pointer => "void*",
            Self::Handle => "HANDLE",
            Self::Float => "float",
            Self::Double => "double",
            Self::Unknown => "?",
        }
    }

    /// Whether this type is an integer (including bool).
    #[must_use]
    pub const fn is_integer(self) -> bool {
        matches!(
            self,
            Self::Bool
                | Self::I8
                | Self::U8
                | Self::I16
                | Self::U16
                | Self::I32
                | Self::U32
                | Self::I64
                | Self::U64
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Post-call usage observation
// ─────────────────────────────────────────────────────────────────────────────

/// An observation about how the return value is used after a CALL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PostCallUsage {
    /// The return register is never read (void or ignored).
    NotRead,
    /// `TEST EAX, EAX` / `TEST RAX, RAX`.
    TestWithSelf,
    /// `CMP EAX, 0` / `CMP RAX, 0`.
    CmpWithZero,
    /// `CMP EAX, -1` (`INVALID_HANDLE_VALUE` check).
    CmpWithMinusOne,
    /// `CMP EAX, 0xFFFFFFFF`.
    CmpWithMaxU32,
    /// `CMP EAX, <small positive>` — success/error code comparison.
    CmpWithSmallPositive(u32),
    /// `JS` / `JL` / `JLE` — signed comparison with zero (error-code pattern).
    SignedBranchOnReturn,
    /// `JE` / `JNE` / `JZ` / `JNZ` — zero check.
    ZeroBranch,
    /// `MOVSX reg, AL` — sign-extend byte.
    MovsxByte,
    /// `MOVZX reg, AL` — zero-extend byte.
    MovzxByte,
    /// `MOVSX reg, AX` — sign-extend word.
    MovsxWord,
    /// `MOVZX reg, AX` — zero-extend word.
    MovzxWord,
    /// `MOVQ [mem], XMM0` or `MOVSD [mem], XMM0` — float return consumed.
    FloatStore,
    /// `CVTSD2SI` / `CVTSS2SI` — float converted to int.
    FloatToInt,
    /// Return value is passed directly to another CALL as an argument.
    PassedToCall,
    /// Return value is stored to memory without narrowing.
    StoredFull,
    /// Some other usage.
    Other,
}

impl PostCallUsage {
    /// Infer the return type implied by this usage.
    #[must_use]
    pub const fn implied_type(&self) -> Option<InferredReturnType> {
        match self {
            Self::NotRead => Some(InferredReturnType::Void),
            Self::TestWithSelf | Self::ZeroBranch | Self::CmpWithZero => {
                Some(InferredReturnType::Bool) // or pointer, refined later
            }
            Self::CmpWithMinusOne | Self::CmpWithMaxU32 => Some(InferredReturnType::Handle),
            Self::CmpWithSmallPositive(_) | Self::SignedBranchOnReturn => {
                Some(InferredReturnType::I32)
            }
            Self::MovsxByte => Some(InferredReturnType::I8),
            Self::MovzxByte => Some(InferredReturnType::U8),
            Self::MovsxWord => Some(InferredReturnType::I16),
            Self::MovzxWord => Some(InferredReturnType::U16),
            Self::FloatStore | Self::FloatToInt => Some(InferredReturnType::Double),
            Self::PassedToCall | Self::StoredFull | Self::Other => None,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Post-call sequence scanner (x86-64)
// ─────────────────────────────────────────────────────────────────────────────

/// Scan the `look_ahead` bytes immediately after `call_offset` for patterns
/// that indicate how the return value in EAX/RAX is used.
///
/// Returns a list of observations (multiple may be present, e.g. TEST + JZ).
#[must_use]
pub fn scan_post_call_usage_x86_64(
    code: &[u8],
    call_offset: usize,
    call_len: usize,
    look_ahead: usize,
) -> Vec<PostCallUsage> {
    let mut observations = Vec::new();
    // Use saturating arithmetic: `call_offset`/`call_len`/`look_ahead` may be
    // attacker- or fuzzer-controlled (e.g. derived from corrupt disassembly
    // metadata); a plain `+` would panic on debug builds and silently wrap on
    // release for near-`usize::MAX` inputs instead of degrading gracefully.
    let start = call_offset.saturating_add(call_len);
    let end = start.saturating_add(look_ahead).min(code.len());

    if start >= code.len() {
        return vec![PostCallUsage::NotRead];
    }

    let window = &code[start..end];
    let mut i = 0usize;
    let mut eax_read = false;

    while i < window.len() {
        let b = window[i];

        // TEST EAX, EAX (85 C0) or TEST RAX, RAX (48 85 C0)
        if b == 0x85 && i + 1 < window.len() && window[i + 1] == 0xC0 {
            observations.push(PostCallUsage::TestWithSelf);
            eax_read = true;
            i += 2;
            continue;
        }
        if b == 0x48 && i + 2 < window.len() && window[i + 1] == 0x85 && window[i + 2] == 0xC0 {
            observations.push(PostCallUsage::TestWithSelf);
            eax_read = true;
            i += 3;
            continue;
        }

        // CMP EAX, imm32 (3D xx xx xx xx)
        if b == 0x3D && i + 4 < window.len() {
            let imm = u32::from_le_bytes([window[i + 1], window[i + 2], window[i + 3], window[i + 4]]);
            let obs = match imm {
                0 => PostCallUsage::CmpWithZero,
                0xFFFF_FFFF => PostCallUsage::CmpWithMinusOne,
                1..=0xFF => PostCallUsage::CmpWithSmallPositive(imm),
                _ => PostCallUsage::Other,
            };
            observations.push(obs);
            eax_read = true;
            i += 5;
            continue;
        }

        // CMP EAX, imm8 (83 F8 xx). Per x86 semantics the imm8 operand of the
        // `83 /7 ib` encoding is *sign-extended* to 32 bits, not zero-extended
        // — so `83 F8 FF` is `CMP EAX, -1`, the extremely common
        // `INVALID_HANDLE_VALUE`/handle-check idiom (the same comparison the
        // `3D imm32` branch above already recognizes as `CmpWithMinusOne`).
        // Reading the byte as a plain zero-extended `u32` misclassified it as
        // `CmpWithSmallPositive(255)`, silently losing the HANDLE inference
        // for one of its two possible encodings.
        if b == 0x83 && i + 2 < window.len() && window[i + 1] == 0xF8 {
            let imm_sext = i32::from(window[i + 2] as i8) as u32;
            let obs = match imm_sext {
                0 => PostCallUsage::CmpWithZero,
                0xFFFF_FFFF => PostCallUsage::CmpWithMinusOne,
                1..=0xFF => PostCallUsage::CmpWithSmallPositive(imm_sext),
                _ => PostCallUsage::Other,
            };
            observations.push(obs);
            eax_read = true;
            i += 3;
            continue;
        }

        // JE/JNE/JZ/JNZ rel8 (74/75 xx)
        if matches!(b, 0x74 | 0x75) {
            observations.push(PostCallUsage::ZeroBranch);
            i += 2;
            continue;
        }

        // JS rel8 (78 xx) / JL rel8 (7C xx) / JLE rel8 (7E xx)
        if matches!(b, 0x78 | 0x7C | 0x7E) {
            observations.push(PostCallUsage::SignedBranchOnReturn);
            i += 2;
            continue;
        }

        // MOVSX reg32, AL (0F BE xx)
        if b == 0x0F && i + 2 < window.len() && window[i + 1] == 0xBE {
            let modrm = window[i + 2];
            if (modrm & 0x07) == 0 {
                observations.push(PostCallUsage::MovsxByte);
                eax_read = true;
            }
            i += 3;
            continue;
        }

        // MOVZX reg32, AL (0F B6 xx)
        if b == 0x0F && i + 2 < window.len() && window[i + 1] == 0xB6 {
            let modrm = window[i + 2];
            if (modrm & 0x07) == 0 {
                observations.push(PostCallUsage::MovzxByte);
                eax_read = true;
            }
            i += 3;
            continue;
        }

        // MOVSX reg32, AX (0F BF xx)
        if b == 0x0F && i + 2 < window.len() && window[i + 1] == 0xBF {
            observations.push(PostCallUsage::MovsxWord);
            eax_read = true;
            i += 3;
            continue;
        }

        // MOVZX reg32, AX (0F B7 xx)
        if b == 0x0F && i + 2 < window.len() && window[i + 1] == 0xB7 {
            observations.push(PostCallUsage::MovzxWord);
            eax_read = true;
            i += 3;
            continue;
        }

        // MOVSD [mem], XMM0 (F2 0F 11 xx) — float return store
        if b == 0xF2 && i + 3 < window.len() && window[i + 1] == 0x0F && window[i + 2] == 0x11 {
            observations.push(PostCallUsage::FloatStore);
            i += 4;
            continue;
        }

        // MOVSS [mem], XMM0 (F3 0F 11 xx)
        if b == 0xF3 && i + 3 < window.len() && window[i + 1] == 0x0F && window[i + 2] == 0x11 {
            observations.push(PostCallUsage::FloatStore);
            i += 4;
            continue;
        }

        // CVTSD2SI (F2 0F 2D) or CVTSS2SI (F3 0F 2D)
        if (b == 0xF2 || b == 0xF3) && i + 3 < window.len() && window[i + 1] == 0x0F && window[i + 2] == 0x2D {
            observations.push(PostCallUsage::FloatToInt);
            i += 4;
            continue;
        }

        // MOV [mem], EAX (89 05 ...) — stored full
        if b == 0x89 && i + 1 < window.len() {
            observations.push(PostCallUsage::StoredFull);
            eax_read = true;
            i += 2;
            continue;
        }

        // RET — eax not read before we returned
        if b == 0xC3 || b == 0xC2 {
            break;
        }

        i += 1;
    }

    if observations.is_empty() && !eax_read {
        observations.push(PostCallUsage::NotRead);
    }

    observations
}

// ─────────────────────────────────────────────────────────────────────────────
// Return-type inference engine
// ─────────────────────────────────────────────────────────────────────────────

/// Voted inference: collect observations across multiple call sites and vote
/// for the most likely return type.
#[derive(Debug, Default)]
pub struct ReturnTypeVoter {
    /// Votes per inferred type.
    votes: HashMap<String, usize>,
    /// Total number of call sites analysed.
    pub site_count: usize,
}

impl ReturnTypeVoter {
    /// Create a new voter.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record observations from one call site.
    pub fn observe(&mut self, usages: &[PostCallUsage]) {
        self.site_count += 1;
        // Collect implied types, preferring more specific ones.
        for obs in usages {
            if let Some(ty) = obs.implied_type() {
                *self.votes.entry(format!("{ty:?}")).or_insert(0) += 1;
            }
        }
    }

    /// Return the inferred return type with the most votes.
    #[must_use]
    pub fn verdict(&self) -> InferredReturnType {
        if self.votes.is_empty() {
            return InferredReturnType::Unknown;
        }

        // Priority ordering: more specific types beat generic ones.
        let priority = |s: &str| -> u32 {
            match s {
                "I8" | "U8" | "I16" | "U16" => 10,
                "Handle" => 9,
                "Float" | "Double" => 8,
                "Bool" => 7,
                "I32" | "U32" | "I64" | "U64" => 6,
                "Pointer" => 5,
                "Void" => 4,
                _ => 1,
            }
        };

        // `self.votes` is a HashMap; on a full tie (same priority and same vote
        // count) break by key name so the winner is reproducible across runs
        // regardless of hash iteration order.
        let best = self.votes.iter().max_by(|(ka, va), (kb, vb)| {
            let pa = priority(ka);
            let pb = priority(kb);
            pa.cmp(&pb).then_with(|| va.cmp(vb)).then_with(|| kb.cmp(ka))
        });

        match best.map(|(k, _)| k.as_str()) {
            Some("Void") => InferredReturnType::Void,
            Some("Bool") => InferredReturnType::Bool,
            Some("I8") => InferredReturnType::I8,
            Some("U8") => InferredReturnType::U8,
            Some("I16") => InferredReturnType::I16,
            Some("U16") => InferredReturnType::U16,
            Some("I32") => InferredReturnType::I32,
            Some("U32") => InferredReturnType::U32,
            Some("I64") => InferredReturnType::I64,
            Some("U64") => InferredReturnType::U64,
            Some("Pointer") => InferredReturnType::Pointer,
            Some("Handle") => InferredReturnType::Handle,
            Some("Float") => InferredReturnType::Float,
            Some("Double") => InferredReturnType::Double,
            _ => InferredReturnType::Unknown,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// High-level API
// ─────────────────────────────────────────────────────────────────────────────

/// Result of return-type recovery for a single function.
#[derive(Debug, Clone)]
pub struct ReturnTypeResult {
    /// Address of the function.
    pub function_addr: u64,
    /// Inferred return type.
    pub return_type: InferredReturnType,
    /// Number of call sites analysed.
    pub call_site_count: usize,
    /// Confidence score in [0.0, 1.0].
    pub confidence: f64,
}

/// One call-site descriptor for bulk analysis.
#[derive(Debug, Clone)]
pub struct CallSiteDescriptor {
    /// Code bytes of the caller function.
    pub code: Vec<u8>,
    /// Byte offset of the CALL instruction within `code`.
    pub call_offset: usize,
    /// Length of the CALL instruction (typically 5 for rel32).
    pub call_len: usize,
}

/// Analyse multiple call sites and return a consolidated return-type result.
#[must_use]
pub fn recover_return_type(
    function_addr: u64,
    call_sites: &[CallSiteDescriptor],
) -> ReturnTypeResult {
    let mut voter = ReturnTypeVoter::new();

    for site in call_sites {
        let usages = scan_post_call_usage_x86_64(
            &site.code,
            site.call_offset,
            site.call_len,
            32, // look ahead 32 bytes
        );
        voter.observe(&usages);
    }

    let return_type = voter.verdict();

    // Confidence: higher with more sites and unanimous votes.
    let confidence = if voter.site_count == 0 {
        0.0
    } else {
        let max_votes = voter.votes.values().copied().max().unwrap_or(0);
        let total_votes: usize = voter.votes.values().sum();
        if total_votes == 0 {
            0.0
        } else {
            (max_votes as f64 / total_votes as f64).min(1.0)
        }
    };

    ReturnTypeResult {
        function_addr,
        return_type,
        call_site_count: voter.site_count,
        confidence,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scan_test_eax_eax() {
        // After CALL (5 bytes at offset 0), at offset 5: TEST EAX, EAX (85 C0)
        let mut code = vec![0x90u8; 5]; // placeholder CALL
        code.extend_from_slice(&[0x85, 0xC0]); // TEST EAX, EAX
        let obs = scan_post_call_usage_x86_64(&code, 0, 5, 16);
        assert!(obs.iter().any(|o| *o == PostCallUsage::TestWithSelf));
    }

    #[test]
    fn scan_cmp_eax_minus_one() {
        // 3D FF FF FF FF — CMP EAX, -1
        let mut code = vec![0x90u8; 5];
        code.extend_from_slice(&[0x3D, 0xFF, 0xFF, 0xFF, 0xFF]);
        let obs = scan_post_call_usage_x86_64(&code, 0, 5, 16);
        assert!(obs.iter().any(|o| *o == PostCallUsage::CmpWithMinusOne));
    }

    #[test]
    fn scan_movzx_byte() {
        // 0F B6 C0 — MOVZX EAX, AL
        let mut code = vec![0x90u8; 5];
        code.extend_from_slice(&[0x0F, 0xB6, 0xC0]);
        let obs = scan_post_call_usage_x86_64(&code, 0, 5, 16);
        assert!(obs.iter().any(|o| *o == PostCallUsage::MovzxByte));
    }

    #[test]
    fn scan_float_store() {
        // F2 0F 11 05 xx xx xx xx — MOVSD [RIP+xx], XMM0
        let mut code = vec![0x90u8; 5];
        code.extend_from_slice(&[0xF2, 0x0F, 0x11, 0x05, 0x00, 0x00, 0x00, 0x00]);
        let obs = scan_post_call_usage_x86_64(&code, 0, 5, 16);
        assert!(obs.iter().any(|o| *o == PostCallUsage::FloatStore));
    }

    #[test]
    fn scan_not_read_after_ret() {
        // Immediately RET after CALL → return value not read.
        let mut code = vec![0x90u8; 5];
        code.push(0xC3); // RET
        let obs = scan_post_call_usage_x86_64(&code, 0, 5, 16);
        assert!(obs.iter().any(|o| *o == PostCallUsage::NotRead));
    }

    #[test]
    fn return_type_voter_bool() {
        let mut voter = ReturnTypeVoter::new();
        voter.observe(&[PostCallUsage::TestWithSelf, PostCallUsage::ZeroBranch]);
        voter.observe(&[PostCallUsage::TestWithSelf]);
        let ty = voter.verdict();
        assert_eq!(ty, InferredReturnType::Bool);
    }

    #[test]
    fn return_type_voter_handle() {
        let mut voter = ReturnTypeVoter::new();
        voter.observe(&[PostCallUsage::CmpWithMinusOne]);
        voter.observe(&[PostCallUsage::CmpWithMinusOne]);
        let ty = voter.verdict();
        assert_eq!(ty, InferredReturnType::Handle);
    }

    #[test]
    fn return_type_voter_void() {
        let mut voter = ReturnTypeVoter::new();
        voter.observe(&[PostCallUsage::NotRead]);
        voter.observe(&[PostCallUsage::NotRead]);
        let ty = voter.verdict();
        assert_eq!(ty, InferredReturnType::Void);
    }

    #[test]
    fn recover_return_type_bulk() {
        // Two call sites both show TEST EAX after call.
        let site = CallSiteDescriptor {
            code: {
                let mut v = vec![0x90u8; 5];
                v.extend_from_slice(&[0x85, 0xC0, 0x74, 0x05]); // TEST EAX,EAX; JZ
                v
            },
            call_offset: 0,
            call_len: 5,
        };
        let result = recover_return_type(0x1000, &[site.clone(), site]);
        assert_eq!(result.return_type, InferredReturnType::Bool);
        assert_eq!(result.call_site_count, 2);
        assert!(result.confidence > 0.0);
    }

    /// Regression test: malformed/huge `call_offset`+`call_len` (e.g. from
    /// corrupt disassembly metadata) must not panic via integer overflow.
    #[test]
    fn scan_does_not_panic_on_overflowing_offsets() {
        let code = vec![0x90u8; 8];
        let obs1 = scan_post_call_usage_x86_64(&code, usize::MAX - 2, 5, 16);
        assert_eq!(obs1, vec![PostCallUsage::NotRead]);
        let obs2 = scan_post_call_usage_x86_64(&code, 4, usize::MAX - 2, usize::MAX);
        assert_eq!(obs2, vec![PostCallUsage::NotRead]);
    }

    /// Regression test: `83 F8 FF` (`CMP EAX, -1` via the short imm8
    /// encoding) must be recognized the same way as the `3D FF FF FF FF`
    /// (imm32) encoding — as `CmpWithMinusOne` — because the x86 `83 /7 ib`
    /// form sign-extends its immediate byte to 32 bits. Before the fix this
    /// was misread as a plain zero-extended byte, i.e. `CmpWithSmallPositive
    /// (255)`, silently dropping the `HANDLE` inference for one of the two
    /// ways compilers emit this extremely common
    /// `!= INVALID_HANDLE_VALUE`-style check.
    #[test]
    fn scan_cmp_eax_minus_one_imm8_form() {
        // 83 F8 FF — CMP EAX, -1 (imm8, sign-extended)
        let mut code = vec![0x90u8; 5];
        code.extend_from_slice(&[0x83, 0xF8, 0xFF]);
        let obs = scan_post_call_usage_x86_64(&code, 0, 5, 16);
        assert!(
            obs.iter().any(|o| *o == PostCallUsage::CmpWithMinusOne),
            "expected CmpWithMinusOne, got {obs:?}"
        );
        assert!(!obs.iter().any(|o| matches!(o, PostCallUsage::CmpWithSmallPositive(_))));

        // End-to-end: voter should now infer HANDLE from this idiom alone,
        // matching the imm32 encoding's behavior.
        let mut voter = ReturnTypeVoter::new();
        voter.observe(&obs);
        assert_eq!(voter.verdict(), InferredReturnType::Handle);
    }

    /// A small positive imm8 comparison (`CMP EAX, 5`) must still be read as
    /// a small positive value, not affected by the sign-extension fix.
    #[test]
    fn scan_cmp_eax_small_positive_imm8_unaffected() {
        let mut code = vec![0x90u8; 5];
        code.extend_from_slice(&[0x83, 0xF8, 0x05]); // CMP EAX, 5
        let obs = scan_post_call_usage_x86_64(&code, 0, 5, 16);
        assert!(obs.iter().any(|o| *o == PostCallUsage::CmpWithSmallPositive(5)));
    }

    #[test]
    fn inferred_type_labels() {
        assert_eq!(InferredReturnType::Void.c_label(), "void");
        assert_eq!(InferredReturnType::Handle.c_label(), "HANDLE");
        assert_eq!(InferredReturnType::I32.c_label(), "int32_t");
        assert!(InferredReturnType::Bool.is_integer());
        assert!(!InferredReturnType::Pointer.is_integer());
    }

    /// Regression test: `ReturnTypeVoter::verdict` used to break a full tie
    /// (same priority AND same vote count) via `HashMap` iteration order,
    /// which is nondeterministic across runs. Verify a genuine tie between
    /// two same-priority types ("I32" vs "U32") resolves the same way every
    /// time regardless of insertion order.
    #[test]
    fn verdict_is_deterministic_on_full_tie() {
        let mut voter_a = ReturnTypeVoter::new();
        voter_a.votes.insert("I32".to_string(), 2);
        voter_a.votes.insert("U32".to_string(), 2);
        let first = voter_a.verdict();
        for _ in 0..20 {
            assert_eq!(voter_a.verdict(), first);
        }

        // Same data, different insertion order -> must agree with `first`.
        let mut voter_b = ReturnTypeVoter::new();
        voter_b.votes.insert("U32".to_string(), 2);
        voter_b.votes.insert("I32".to_string(), 2);
        assert_eq!(voter_b.verdict(), first);
    }

    use crate::test_prng::Xorshift64;

    /// DETERMINISM PROPERTY (return-type voting, requirement #3): over many
    /// random sequences of post-call observations, `verdict()` must be stable
    /// across repeated invocations and independent of the order in which the
    /// same observations were recorded — the vote/tie-break logic must never
    /// depend on hash iteration order.
    #[test]
    fn prop_voter_verdict_is_deterministic_and_order_independent() {
        let palette = [
            PostCallUsage::NotRead,
            PostCallUsage::TestWithSelf,
            PostCallUsage::CmpWithZero,
            PostCallUsage::CmpWithMinusOne,
            PostCallUsage::CmpWithSmallPositive(5),
            PostCallUsage::SignedBranchOnReturn,
            PostCallUsage::ZeroBranch,
            PostCallUsage::MovsxByte,
            PostCallUsage::MovzxByte,
            PostCallUsage::MovsxWord,
            PostCallUsage::MovzxWord,
            PostCallUsage::FloatStore,
            PostCallUsage::FloatToInt,
        ];
        let mut rng = Xorshift64::new(0x5EED_600D);

        for trial in 0..300u64 {
            let site_count = 1 + rng.next_range(8);
            // Build a random multiset of observations per site.
            let sites: Vec<Vec<PostCallUsage>> = (0..site_count)
                .map(|_| {
                    let k = 1 + rng.next_range(4);
                    (0..k).map(|_| palette[rng.next_range(palette.len())].clone()).collect()
                })
                .collect();

            let verdict_of = |order: &[usize]| -> InferredReturnType {
                let mut voter = ReturnTypeVoter::new();
                for &i in order {
                    voter.observe(&sites[i]);
                }
                voter.verdict()
            };

            let forward: Vec<usize> = (0..site_count).collect();
            let base = verdict_of(&forward);

            // Repeated runs must agree.
            for _ in 0..5 {
                assert_eq!(verdict_of(&forward), base, "trial {trial}: verdict unstable");
            }
            // Reversed observation order must agree (voting is order-free).
            let reversed: Vec<usize> = (0..site_count).rev().collect();
            assert_eq!(
                verdict_of(&reversed),
                base,
                "trial {trial}: verdict depends on observation order"
            );
        }
    }
}
