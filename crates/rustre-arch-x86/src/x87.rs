//! x87 FPU instruction decoder.
//!
//! The x87 FPU occupies the D8–DF opcode space.  Each escape byte selects a
//! group; the `ModRM` byte and mod/reg/rm fields further refine the instruction.
//!
//! # Layer distinction
//!
//! This module is the **x87 decoder**: it maps raw (escape byte, `ModRM`) pairs
//! to mnemonic strings and operand text via [`decode_x87`], and provides
//! helper constants such as [`FPU_REGS`] and [`fpu_reg`].  It is purely
//! textual and carries no IL dependency.
//!
//! For **IL lifting** — translating x87 instructions into [`rustre_il_lift::Effect`]
//! sequences that model the 8-deep FPU stack, condition-code registers
//! (`fpu_c0`–`fpu_c3`), and status-word updates — see [`crate::fpu_lifter`].
//! The two modules are complementary: the decoder classifies; the lifter
//! produces the intermediate representation.
//!
//! This module provides:
//! - Full decode of the 8 escape groups (D8–DF) into mnemonic + operand text.
//! - x87 register names (ST(0)–ST(7)).
//! - FPU control-word field descriptions.
//! - A top-level [`decode_x87`] function.
//!
//! # Dispatch status (NOT wired into `src/lift.rs`)
//!
//! This module is **not** part of the active lifting path. `src/lift.rs`
//! dispatches every mnemonic directly via its own native match arms (added
//! across several hardening passes), and does not call into this module.
//! It is intentionally retained -- not dead code pending removal -- per
//! explicit user instruction, as a possible future cross-validation /
//! second-opinion decode path independent of `lift.rs`.

// ---------------------------------------------------------------------------
// FPU register names
// ---------------------------------------------------------------------------

/// Names for the eight x87 FPU stack registers.
pub const FPU_REGS: [&str; 8] = [
    "st(0)", "st(1)", "st(2)", "st(3)", "st(4)", "st(5)", "st(6)", "st(7)",
];

/// Return the FPU stack register name for slot `n` (0–7).
#[must_use]
pub const fn fpu_reg(n: u8) -> &'static str {
    FPU_REGS[(n & 0x7) as usize]
}

// ---------------------------------------------------------------------------
// x87 instruction category
// ---------------------------------------------------------------------------

/// Semantic category of an x87 FPU instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub enum X87Category {
    /// Load from memory or stack.
    Load,
    /// Store to memory or pop from stack.
    Store,
    /// Basic arithmetic (FADD, FSUB, FMUL, FDIV, …).
    Arithmetic,
    /// Comparison (FCOM, FTST, FUCOM, …).
    Compare,
    /// Transcendental (FSIN, FCOS, FPTAN, FATAN, FYL2X, …).
    Transcendental,
    /// Stack / control operations (FLDZ, FLD1, FLDPI, FXCH, FFREE, …).
    Control,
    /// Integer conversion (FILD, FIST, FISTP, FBLD, FBSTP, …).
    Integer,
    /// Miscellaneous (FNOP, FWAIT, FINIT, FCLEX, FSTENV, FLDENV, …).
    Misc,
}

// ---------------------------------------------------------------------------
// Decoded x87 instruction
// ---------------------------------------------------------------------------

/// A decoded x87 instruction.
#[derive(Debug, Clone)]
#[must_use]
pub struct X87Instr {
    /// Mnemonic, e.g. `"fadd"`.
    pub mnemonic: String,
    /// Operand text, e.g. `"st(1)"` or `"dword ptr [eax]"`.
    pub operands: String,
    /// Semantic category.
    pub category: X87Category,
}

// ---------------------------------------------------------------------------
// Top-level decoder
// ---------------------------------------------------------------------------

/// Decode a single x87 FPU instruction from `escape` (D8–DF) and `modrm`.
///
/// For memory-form encodings (mod ≠ 3) a simplified operand string is
/// produced (size-qualifier only; no full effective-address expansion).
///
/// Returns `None` when the combination is reserved or cannot be decoded.
#[must_use]
pub fn decode_x87(escape: u8, modrm: u8) -> Option<X87Instr> {
    let mode = (modrm >> 6) & 0x3;
    let reg = (modrm >> 3) & 0x7;
    let rm = modrm & 0x7;
    let is_reg = mode == 3;

    match escape {
        0xD8 => decode_d8(reg, rm, is_reg),
        0xD9 => decode_d9(reg, rm, is_reg),
        0xDA => decode_da(reg, rm, is_reg),
        0xDB => decode_db(reg, rm, is_reg),
        0xDC => decode_dc(reg, rm, is_reg),
        0xDD => decode_dd(reg, rm, is_reg),
        0xDE => decode_de(reg, rm, is_reg),
        0xDF => decode_df(reg, rm, is_reg),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// D8 — single-precision real operations
// ---------------------------------------------------------------------------

fn decode_d8(reg: u8, rm: u8, is_reg: bool) -> Option<X87Instr> {
    if is_reg {
        let (mn, cat) = match reg {
            0 => ("fadd", X87Category::Arithmetic),
            1 => ("fmul", X87Category::Arithmetic),
            2 => ("fcom", X87Category::Compare),
            3 => ("fcomp", X87Category::Compare),
            4 => ("fsub", X87Category::Arithmetic),
            5 => ("fsubr", X87Category::Arithmetic),
            6 => ("fdiv", X87Category::Arithmetic),
            7 => ("fdivr", X87Category::Arithmetic),
            _ => return None,
        };
        Some(X87Instr {
            mnemonic: mn.into(),
            operands: format!("st(0), {}", fpu_reg(rm)),
            category: cat,
        })
    } else {
        let (mn, cat) = match reg {
            0 => ("fadd", X87Category::Arithmetic),
            1 => ("fmul", X87Category::Arithmetic),
            2 => ("fcom", X87Category::Compare),
            3 => ("fcomp", X87Category::Compare),
            4 => ("fsub", X87Category::Arithmetic),
            5 => ("fsubr", X87Category::Arithmetic),
            6 => ("fdiv", X87Category::Arithmetic),
            7 => ("fdivr", X87Category::Arithmetic),
            _ => return None,
        };
        Some(X87Instr {
            mnemonic: mn.into(),
            operands: "dword ptr [mem]".into(),
            category: cat,
        })
    }
}

// ---------------------------------------------------------------------------
// D9 — single-precision real / control
// ---------------------------------------------------------------------------

fn decode_d9(reg: u8, rm: u8, is_reg: bool) -> Option<X87Instr> {
    if is_reg {
        // Full modrm byte when mod=3: op = reg<<3 | rm
        let full = (reg << 3) | rm;
        let (mn, ops, cat) = match full {
            0x00..=0x07 => ("fld", fpu_reg(rm).to_string(), X87Category::Load),
            0x08..=0x0F => ("fxch", fpu_reg(rm).to_string(), X87Category::Control),
            0x10 => ("fnop", String::new(), X87Category::Misc),
            0x20 => ("fchs", String::new(), X87Category::Arithmetic),
            0x21 => ("fabs", String::new(), X87Category::Arithmetic),
            0x24 => ("ftst", String::new(), X87Category::Compare),
            0x25 => ("fxam", String::new(), X87Category::Compare),
            0x28 => ("fld1", String::new(), X87Category::Load),
            0x29 => ("fldl2t", String::new(), X87Category::Load),
            0x2A => ("fldl2e", String::new(), X87Category::Load),
            0x2B => ("fldpi", String::new(), X87Category::Load),
            0x2C => ("fldlg2", String::new(), X87Category::Load),
            0x2D => ("fldln2", String::new(), X87Category::Load),
            0x2E => ("fldz", String::new(), X87Category::Load),
            0x30 => ("f2xm1", String::new(), X87Category::Transcendental),
            0x31 => ("fyl2x", String::new(), X87Category::Transcendental),
            0x32 => ("fptan", String::new(), X87Category::Transcendental),
            0x33 => ("fpatan", String::new(), X87Category::Transcendental),
            0x34 => ("fxtract", String::new(), X87Category::Transcendental),
            0x35 => ("fprem1", String::new(), X87Category::Arithmetic),
            0x36 => ("fdecstp", String::new(), X87Category::Control),
            0x37 => ("fincstp", String::new(), X87Category::Control),
            0x38 => ("fprem", String::new(), X87Category::Arithmetic),
            0x39 => ("fyl2xp1", String::new(), X87Category::Transcendental),
            0x3A => ("fsqrt", String::new(), X87Category::Arithmetic),
            0x3B => ("fsincos", String::new(), X87Category::Transcendental),
            0x3C => ("frndint", String::new(), X87Category::Arithmetic),
            0x3D => ("fscale", String::new(), X87Category::Arithmetic),
            0x3E => ("fsin", String::new(), X87Category::Transcendental),
            0x3F => ("fcos", String::new(), X87Category::Transcendental),
            _ => return None,
        };
        Some(X87Instr {
            mnemonic: mn.into(),
            operands: ops,
            category: cat,
        })
    } else {
        let (mn, sz, cat) = match reg {
            0 => ("fld", "dword", X87Category::Load),
            2 => ("fst", "dword", X87Category::Store),
            3 => ("fstp", "dword", X87Category::Store),
            4 => ("fldenv", "", X87Category::Misc),
            5 => ("fldcw", "word", X87Category::Control),
            6 => ("fstenv", "", X87Category::Misc),
            7 => ("fstcw", "word", X87Category::Control),
            _ => return None,
        };
        let ops = if sz.is_empty() {
            "[mem]".into()
        } else {
            format!("{sz} ptr [mem]")
        };
        Some(X87Instr {
            mnemonic: mn.into(),
            operands: ops,
            category: cat,
        })
    }
}

// ---------------------------------------------------------------------------
// DA — integer 32-bit / conditional moves
// ---------------------------------------------------------------------------

fn decode_da(reg: u8, rm: u8, is_reg: bool) -> Option<X87Instr> {
    if is_reg {
        let full = (reg << 3) | rm;
        let (mn, ops, cat) = match full {
            0x00..=0x07 => (
                "fcmovb",
                format!("st(0), {}", fpu_reg(rm)),
                X87Category::Control,
            ),
            0x08..=0x0F => (
                "fcmove",
                format!("st(0), {}", fpu_reg(rm)),
                X87Category::Control,
            ),
            0x10..=0x17 => (
                "fcmovbe",
                format!("st(0), {}", fpu_reg(rm)),
                X87Category::Control,
            ),
            0x18..=0x1F => (
                "fcmovu",
                format!("st(0), {}", fpu_reg(rm)),
                X87Category::Control,
            ),
            0x29 => ("fucompp", String::new(), X87Category::Compare),
            _ => return None,
        };
        Some(X87Instr {
            mnemonic: mn.into(),
            operands: ops,
            category: cat,
        })
    } else {
        let (mn, cat) = match reg {
            0 => ("fiadd", X87Category::Arithmetic),
            1 => ("fimul", X87Category::Arithmetic),
            2 => ("ficom", X87Category::Compare),
            3 => ("ficomp", X87Category::Compare),
            4 => ("fisub", X87Category::Arithmetic),
            5 => ("fisubr", X87Category::Arithmetic),
            6 => ("fidiv", X87Category::Arithmetic),
            7 => ("fidivr", X87Category::Arithmetic),
            _ => return None,
        };
        Some(X87Instr {
            mnemonic: mn.into(),
            operands: "dword ptr [mem]".into(),
            category: cat,
        })
    }
}

// ---------------------------------------------------------------------------
// DB — integer 32-bit / conditional moves / extended
// ---------------------------------------------------------------------------

fn decode_db(reg: u8, rm: u8, is_reg: bool) -> Option<X87Instr> {
    if is_reg {
        let full = (reg << 3) | rm;
        let (mn, ops, cat) = match full {
            0x00..=0x07 => (
                "fcmovnb",
                format!("st(0), {}", fpu_reg(rm)),
                X87Category::Control,
            ),
            0x08..=0x0F => (
                "fcmovne",
                format!("st(0), {}", fpu_reg(rm)),
                X87Category::Control,
            ),
            0x10..=0x17 => (
                "fcmovnbe",
                format!("st(0), {}", fpu_reg(rm)),
                X87Category::Control,
            ),
            0x18..=0x1F => (
                "fcmovnu",
                format!("st(0), {}", fpu_reg(rm)),
                X87Category::Control,
            ),
            0x22 => ("fnclex", String::new(), X87Category::Misc),
            0x23 => ("fninit", String::new(), X87Category::Misc),
            0x28..=0x2F => (
                "fucomi",
                format!("st(0), {}", fpu_reg(rm)),
                X87Category::Compare,
            ),
            0x30..=0x37 => (
                "fcomi",
                format!("st(0), {}", fpu_reg(rm)),
                X87Category::Compare,
            ),
            _ => return None,
        };
        Some(X87Instr {
            mnemonic: mn.into(),
            operands: ops,
            category: cat,
        })
    } else {
        let (mn, sz, cat) = match reg {
            0 => ("fild", "dword", X87Category::Integer),
            1 => ("fisttp", "dword", X87Category::Integer),
            2 => ("fist", "dword", X87Category::Integer),
            3 => ("fistp", "dword", X87Category::Integer),
            5 => ("fld", "tbyte", X87Category::Load),
            7 => ("fstp", "tbyte", X87Category::Store),
            _ => return None,
        };
        Some(X87Instr {
            mnemonic: mn.into(),
            operands: format!("{sz} ptr [mem]"),
            category: cat,
        })
    }
}

// ---------------------------------------------------------------------------
// DC — double-precision arithmetic
// ---------------------------------------------------------------------------

fn decode_dc(reg: u8, rm: u8, is_reg: bool) -> Option<X87Instr> {
    if is_reg {
        let (mn, cat) = match reg {
            0 => ("fadd", X87Category::Arithmetic),
            1 => ("fmul", X87Category::Arithmetic),
            4 => ("fsubr", X87Category::Arithmetic),
            5 => ("fsub", X87Category::Arithmetic),
            6 => ("fdivr", X87Category::Arithmetic),
            7 => ("fdiv", X87Category::Arithmetic),
            _ => return None,
        };
        Some(X87Instr {
            mnemonic: mn.into(),
            operands: format!("{}, st(0)", fpu_reg(rm)),
            category: cat,
        })
    } else {
        let (mn, cat) = match reg {
            0 => ("fadd", X87Category::Arithmetic),
            1 => ("fmul", X87Category::Arithmetic),
            2 => ("fcom", X87Category::Compare),
            3 => ("fcomp", X87Category::Compare),
            4 => ("fsub", X87Category::Arithmetic),
            5 => ("fsubr", X87Category::Arithmetic),
            6 => ("fdiv", X87Category::Arithmetic),
            7 => ("fdivr", X87Category::Arithmetic),
            _ => return None,
        };
        Some(X87Instr {
            mnemonic: mn.into(),
            operands: "qword ptr [mem]".into(),
            category: cat,
        })
    }
}

// ---------------------------------------------------------------------------
// DD — double-precision load/store
// ---------------------------------------------------------------------------

fn decode_dd(reg: u8, rm: u8, is_reg: bool) -> Option<X87Instr> {
    if is_reg {
        let (mn, ops, cat) = match reg {
            0 => ("ffree", fpu_reg(rm).to_string(), X87Category::Control),
            2 => ("fst", fpu_reg(rm).to_string(), X87Category::Store),
            3 => ("fstp", fpu_reg(rm).to_string(), X87Category::Store),
            4 => ("fucom", fpu_reg(rm).to_string(), X87Category::Compare),
            5 => ("fucomp", fpu_reg(rm).to_string(), X87Category::Compare),
            _ => return None,
        };
        Some(X87Instr {
            mnemonic: mn.into(),
            operands: ops,
            category: cat,
        })
    } else {
        let (mn, sz, cat) = match reg {
            0 => ("fld", "qword", X87Category::Load),
            1 => ("fisttp", "qword", X87Category::Integer),
            2 => ("fst", "qword", X87Category::Store),
            3 => ("fstp", "qword", X87Category::Store),
            4 => ("frstor", "", X87Category::Misc),
            6 => ("fsave", "", X87Category::Misc),
            7 => ("fstsw", "word", X87Category::Control),
            _ => return None,
        };
        let ops = if sz.is_empty() {
            "[mem]".into()
        } else {
            format!("{sz} ptr [mem]")
        };
        Some(X87Instr {
            mnemonic: mn.into(),
            operands: ops,
            category: cat,
        })
    }
}

// ---------------------------------------------------------------------------
// DE — integer 16-bit arithmetic / pop forms
// ---------------------------------------------------------------------------

fn decode_de(reg: u8, rm: u8, is_reg: bool) -> Option<X87Instr> {
    if is_reg {
        let full = (reg << 3) | rm;
        let (mn, ops, cat) = match full {
            0x00..=0x07 => (
                "faddp",
                format!("{}, st(0)", fpu_reg(rm)),
                X87Category::Arithmetic,
            ),
            0x08..=0x0F => (
                "fmulp",
                format!("{}, st(0)", fpu_reg(rm)),
                X87Category::Arithmetic,
            ),
            0x19 => ("fcompp", String::new(), X87Category::Compare),
            0x20..=0x27 => (
                "fsubrp",
                format!("{}, st(0)", fpu_reg(rm)),
                X87Category::Arithmetic,
            ),
            0x28..=0x2F => (
                "fsubp",
                format!("{}, st(0)", fpu_reg(rm)),
                X87Category::Arithmetic,
            ),
            0x30..=0x37 => (
                "fdivrp",
                format!("{}, st(0)", fpu_reg(rm)),
                X87Category::Arithmetic,
            ),
            0x38..=0x3F => (
                "fdivp",
                format!("{}, st(0)", fpu_reg(rm)),
                X87Category::Arithmetic,
            ),
            _ => return None,
        };
        Some(X87Instr {
            mnemonic: mn.into(),
            operands: ops,
            category: cat,
        })
    } else {
        let (mn, cat) = match reg {
            0 => ("fiadd", X87Category::Arithmetic),
            1 => ("fimul", X87Category::Arithmetic),
            2 => ("ficom", X87Category::Compare),
            3 => ("ficomp", X87Category::Compare),
            4 => ("fisub", X87Category::Arithmetic),
            5 => ("fisubr", X87Category::Arithmetic),
            6 => ("fidiv", X87Category::Arithmetic),
            7 => ("fidivr", X87Category::Arithmetic),
            _ => return None,
        };
        Some(X87Instr {
            mnemonic: mn.into(),
            operands: "word ptr [mem]".into(),
            category: cat,
        })
    }
}

// ---------------------------------------------------------------------------
// DF — integer 16-bit load/store / FBLD / FBSTP
// ---------------------------------------------------------------------------

fn decode_df(reg: u8, rm: u8, is_reg: bool) -> Option<X87Instr> {
    if is_reg {
        let full = (reg << 3) | rm;
        let (mn, ops, cat) = match full {
            0x28..=0x2F => (
                "fucomip",
                format!("st(0), {}", fpu_reg(rm)),
                X87Category::Compare,
            ),
            0x30..=0x37 => (
                "fcomip",
                format!("st(0), {}", fpu_reg(rm)),
                X87Category::Compare,
            ),
            0x20 => ("fstsw", "ax".into(), X87Category::Control),
            _ => return None,
        };
        Some(X87Instr {
            mnemonic: mn.into(),
            operands: ops,
            category: cat,
        })
    } else {
        let (mn, sz, cat) = match reg {
            0 => ("fild", "word", X87Category::Integer),
            1 => ("fisttp", "word", X87Category::Integer),
            2 => ("fist", "word", X87Category::Integer),
            3 => ("fistp", "word", X87Category::Integer),
            4 => ("fbld", "tbyte", X87Category::Integer),
            5 => ("fild", "qword", X87Category::Integer),
            6 => ("fbstp", "tbyte", X87Category::Integer),
            7 => ("fistp", "qword", X87Category::Integer),
            _ => return None,
        };
        Some(X87Instr {
            mnemonic: mn.into(),
            operands: format!("{sz} ptr [mem]"),
            category: cat,
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fpu_reg_names() {
        assert_eq!(fpu_reg(0), "st(0)");
        assert_eq!(fpu_reg(7), "st(7)");
        // wraps at 8
        assert_eq!(fpu_reg(8), "st(0)");
    }

    #[test]
    fn test_decode_d8_reg_fadd() {
        // D8 /0 reg-form: reg=0, rm=1 → fadd st(0), st(1)
        let i = decode_x87(0xD8, 0b11_000_001).unwrap(); // mod=3, reg=0, rm=1
        assert_eq!(i.mnemonic, "fadd");
        assert!(i.operands.contains("st(1)"));
    }

    #[test]
    fn test_decode_d8_mem_fmul() {
        // D8 /1 mem-form: reg=1 → fmul dword ptr
        let i = decode_x87(0xD8, 0b00_001_000).unwrap(); // mod=0, reg=1, rm=0
        assert_eq!(i.mnemonic, "fmul");
        assert!(i.operands.contains("dword"));
    }

    #[test]
    fn test_decode_d9_fld1() {
        // D9 E8 — FLD1
        let i = decode_x87(0xD9, 0xE8).unwrap();
        assert_eq!(i.mnemonic, "fld1");
        assert_eq!(i.category as u8, X87Category::Load as u8);
    }

    #[test]
    fn test_decode_d9_fsin() {
        // D9 FE — FSIN
        let i = decode_x87(0xD9, 0xFE).unwrap();
        assert_eq!(i.mnemonic, "fsin");
        assert_eq!(i.category as u8, X87Category::Transcendental as u8);
    }

    #[test]
    fn test_decode_d9_fcos() {
        // D9 FF — FCOS
        let i = decode_x87(0xD9, 0xFF).unwrap();
        assert_eq!(i.mnemonic, "fcos");
    }

    #[test]
    fn test_decode_d9_fldz() {
        // D9 EE — FLDZ
        let i = decode_x87(0xD9, 0xEE).unwrap();
        assert_eq!(i.mnemonic, "fldz");
    }

    #[test]
    fn test_decode_d9_fstcw_mem() {
        // D9 /7 mem → FSTCW
        let i = decode_x87(0xD9, 0b00_111_000).unwrap();
        assert_eq!(i.mnemonic, "fstcw");
        assert!(i.operands.contains("word"));
    }

    #[test]
    fn test_decode_da_fcmovb() {
        // DA /0 reg-form: mod=3, reg=0, rm=2 → fcmovb st(0), st(2)
        let i = decode_x87(0xDA, 0b11_000_010).unwrap();
        assert_eq!(i.mnemonic, "fcmovb");
    }

    #[test]
    fn test_decode_db_fnclex() {
        // DB E2 — FNCLEX
        let i = decode_x87(0xDB, 0xE2).unwrap();
        assert_eq!(i.mnemonic, "fnclex");
    }

    #[test]
    fn test_decode_dc_fadd_st1() {
        // DC /0 reg-form: mod=3, reg=0, rm=1 → fadd st(1), st(0)
        let i = decode_x87(0xDC, 0b11_000_001).unwrap();
        assert_eq!(i.mnemonic, "fadd");
        assert!(i.operands.contains("st(1)"));
    }

    #[test]
    fn test_decode_dd_ffree() {
        // DD /0 reg-form: mod=3, reg=0, rm=3 → ffree st(3)
        let i = decode_x87(0xDD, 0b11_000_011).unwrap();
        assert_eq!(i.mnemonic, "ffree");
    }

    #[test]
    fn test_decode_dd_fld_mem() {
        // DD /0 mem → fld qword
        let i = decode_x87(0xDD, 0b00_000_001).unwrap();
        assert_eq!(i.mnemonic, "fld");
        assert!(i.operands.contains("qword"));
    }

    #[test]
    fn test_decode_de_faddp() {
        // DE C1 — FADDP st(1), st(0)   (mod=3, reg=0, rm=1)
        let i = decode_x87(0xDE, 0b11_000_001).unwrap();
        assert_eq!(i.mnemonic, "faddp");
    }

    #[test]
    fn test_decode_de_fcompp() {
        // DE D9 — FCOMPP
        let i = decode_x87(0xDE, 0xD9).unwrap();
        assert_eq!(i.mnemonic, "fcompp");
    }

    #[test]
    fn test_decode_df_fstsw_ax() {
        // DF E0 — FSTSW AX
        let i = decode_x87(0xDF, 0xE0).unwrap();
        assert_eq!(i.mnemonic, "fstsw");
        assert!(i.operands.contains("ax"));
    }

    #[test]
    fn test_decode_df_fild_word() {
        // DF /0 mem → fild word
        let i = decode_x87(0xDF, 0b00_000_000).unwrap();
        assert_eq!(i.mnemonic, "fild");
        assert!(i.operands.contains("word"));
    }

    #[test]
    fn test_decode_invalid_returns_none() {
        // DA with reg=6 in reg-form — reserved
        assert!(decode_x87(0xDA, 0b11_110_000).is_none());
    }

    #[test]
    fn test_decode_d9_fnop() {
        // D9 D0 — FNOP
        let i = decode_x87(0xD9, 0xD0).unwrap();
        assert_eq!(i.mnemonic, "fnop");
    }

    #[test]
    fn test_decode_d9_fptan() {
        // D9 F2 — FPTAN
        let i = decode_x87(0xD9, 0xF2).unwrap();
        assert_eq!(i.mnemonic, "fptan");
        assert_eq!(i.category as u8, X87Category::Transcendental as u8);
    }

    #[test]
    fn test_decode_db_fcomi() {
        // DB F0 — FCOMI st(0), st(0)
        let i = decode_x87(0xDB, 0xF0).unwrap();
        assert_eq!(i.mnemonic, "fcomi");
    }
}
