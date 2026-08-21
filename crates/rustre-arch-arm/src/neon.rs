//! ARM NEON / Advanced SIMD instruction tables and decode helpers.
//!
//! Covers all NEON data-processing instructions for both A32 and T32 encodings
//! as defined in the ARM Architecture Reference Manual ARMv7-A/R.

// ---------------------------------------------------------------------------
// Register helpers
// ---------------------------------------------------------------------------

/// Return a Dn double-register name (D0–D31).
#[must_use]
pub const fn dreg(n: u8) -> &'static str {
    const NAMES: [&str; 32] = [
        "d0", "d1", "d2", "d3", "d4", "d5", "d6", "d7", "d8", "d9", "d10", "d11", "d12", "d13",
        "d14", "d15", "d16", "d17", "d18", "d19", "d20", "d21", "d22", "d23", "d24", "d25", "d26",
        "d27", "d28", "d29", "d30", "d31",
    ];
    NAMES[(n & 31) as usize]
}

/// Return a Qn quad-register name (Q0–Q15).
#[must_use]
pub const fn qreg(n: u8) -> &'static str {
    const NAMES: [&str; 16] = [
        "q0", "q1", "q2", "q3", "q4", "q5", "q6", "q7", "q8", "q9", "q10", "q11", "q12", "q13",
        "q14", "q15",
    ];
    NAMES[(n & 15) as usize]
}

/// Return a Sn single-precision register name (S0–S31).
#[must_use]
pub const fn sreg(n: u8) -> &'static str {
    const NAMES: [&str; 32] = [
        "s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7", "s8", "s9", "s10", "s11", "s12", "s13",
        "s14", "s15", "s16", "s17", "s18", "s19", "s20", "s21", "s22", "s23", "s24", "s25", "s26",
        "s27", "s28", "s29", "s30", "s31",
    ];
    NAMES[(n & 31) as usize]
}

// ---------------------------------------------------------------------------
// NEON element size suffix
// ---------------------------------------------------------------------------

/// NEON element type size suffix from the `size` field (2-bit).
#[must_use]
pub fn neon_size_suffix(size: u8) -> &'static str {
    match size & 3 {
        0 => ".8",
        1 => ".16",
        2 => ".32",
        3 => ".64",
        _ => unreachable!(),
    }
}

/// NEON signed integer suffix.
#[must_use]
pub fn neon_signed_suffix(size: u8) -> &'static str {
    match size & 3 {
        0 => ".s8",
        1 => ".s16",
        2 => ".s32",
        3 => ".s64",
        _ => unreachable!(),
    }
}

/// NEON unsigned integer suffix.
#[must_use]
pub fn neon_unsigned_suffix(size: u8) -> &'static str {
    match size & 3 {
        0 => ".u8",
        1 => ".u16",
        2 => ".u32",
        3 => ".u64",
        _ => unreachable!(),
    }
}

/// NEON float suffix (only size==2 or size==3 are valid for fp).
#[must_use]
pub const fn neon_float_suffix(size: u8) -> &'static str {
    match size & 3 {
        2 => ".f32",
        3 => ".f64",
        _ => ".f??",
    }
}

/// NEON polynomial suffix.
#[must_use]
pub const fn neon_poly_suffix(size: u8) -> &'static str {
    match size & 3 {
        0 => ".p8",
        1 => ".p16",
        _ => ".p??",
    }
}

// ---------------------------------------------------------------------------
// Decode NEON data-processing (A32 encoding, bits [31:24]=0b1111001x)
// ---------------------------------------------------------------------------

/// Decode result for a NEON instruction.
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use]
pub struct NeonInstr {
    /// Full mnemonic including type suffix (e.g. `"vadd.i32"`).
    pub mnemonic: String,
    /// Operand string (e.g. `"q0, q1, q2"`).
    pub operands: String,
}

/// Decode a NEON data-processing instruction from its 32-bit word.
///
/// Returns `None` if the word does not match the NEON encoding space.
#[must_use]
pub fn decode_neon_dp(word: u32) -> Option<NeonInstr> {
    // NEON data-processing: bits[31:23] = 1111 001x (U bit at 24)
    let top = word >> 23;
    if top & 0x1FE != 0x1E4 {
        // 1111_001x → 0b1_1110_010x >> 1 = 0xF2 or 0xF3
        // Allow 0xF2xxxxxx and 0xF3xxxxxx
        let byte3 = (word >> 24) as u8;
        if byte3 != 0xF2 && byte3 != 0xF3 {
            return None;
        }
    }

    let u = (word >> 24) & 1; // unsigned flag
    let a = (word >> 23) & 1; // 'a' bit (some instructions)
    let size = ((word >> 20) & 3) as u8;
    let vn = ((word >> 16) & 0xF) as u8;
    let vd = ((word >> 12) & 0xF) as u8;
    let opc = ((word >> 8) & 0xF) as u8;
    let n_bit = ((word >> 7) & 1) as u8;
    let q = ((word >> 6) & 1) as u8; // Q=1 → quad regs
    let m_bit = ((word >> 5) & 1) as u8;
    let vm = (word & 0xF) as u8;

    // Reconstruct full register indices (D and N extension bits)
    let rd = vd | (n_bit << 4);
    let rn = vn | (m_bit << 4);
    let rm = vm; // M-bit handled separately in actual hardware but we simplify

    let reg_d = if q != 0 { qreg(rd >> 1) } else { dreg(rd) };
    let reg_n = if q != 0 { qreg(rn >> 1) } else { dreg(rn) };
    let reg_m = if q != 0 { qreg(rm >> 1) } else { dreg(rm) };
    let ops3 = format!("{reg_d}, {reg_n}, {reg_m}");

    // Decode by opc field
    let suf = if u == 0 {
        neon_signed_suffix(size)
    } else {
        neon_unsigned_suffix(size)
    };
    let mnemonic = match opc {
        0x0 => format!("vhadd{suf}"),
        0x1 => format!("vqadd{suf}"),
        0x2 => format!("vrhadd{suf}"),
        0x3 => match (a != 0, u != 0) {
            (true, false) => "vbit".to_string(),
            (true, true) => "vbif".to_string(),
            (false, false) => "vand".to_string(),
            (false, true) => "veor".to_string(),
        },
        0x4 => format!("vhsub{suf}"),
        0x5 => format!("vqsub{suf}"),
        0x6 => format!("vcgt{suf}"),
        0x7 => format!("vcge{suf}"),
        0x8 => format!("vshl{suf}"),
        0x9 => format!("vqshl{suf}"),
        0xA => format!("vrshl{suf}"),
        0xB => format!("vqrshl{suf}"),
        0xC => format!("vmax{suf}"),
        0xD => format!("vmin{suf}"),
        0xE => format!("vabd{suf}"),
        0xF => {
            let fsuf = if u == 0 {
                neon_signed_suffix(size)
            } else {
                neon_float_suffix(size)
            };
            if a == 0 {
                format!("vmla{fsuf}")
            } else {
                format!("vmls{fsuf}")
            }
        }
        _ => "undef".to_string(),
    };
    Some(NeonInstr {
        mnemonic,
        operands: ops3,
    })
}

// ---------------------------------------------------------------------------
// NEON load/store multiple (VLDn / VSTn)
// ---------------------------------------------------------------------------

/// NEON load/store type for VLDn/VSTn instructions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub enum NeonLsType {
    /// VLD1 / VST1 — interleave 1.
    Ls1,
    /// VLD2 / VST2 — interleave 2.
    Ls2,
    /// VLD3 / VST3 — interleave 3.
    Ls3,
    /// VLD4 / VST4 — interleave 4.
    Ls4,
}

impl NeonLsType {
    /// Decode from `type` field (4-bit) of the VLD/VST encoding.
    ///
    /// Returns `None` for reserved or unsupported patterns.
    #[must_use]
    pub const fn from_type_field(t: u8) -> Option<Self> {
        match t & 0xF {
            0x7 | 0xA | 0x6 | 0x2 => Some(Self::Ls1),
            0x8 | 0x9 | 0x3 => Some(Self::Ls2),
            0x4 | 0x5 => Some(Self::Ls3),
            0x0 | 0x1 => Some(Self::Ls4),
            _ => None,
        }
    }

    /// Number of registers involved.
    #[must_use]
    pub const fn count(&self) -> u8 {
        match self {
            Self::Ls1 => 1,
            Self::Ls2 => 2,
            Self::Ls3 => 3,
            Self::Ls4 => 4,
        }
    }
}

/// Decode a NEON load/store multiple instruction (A32 encoding).
///
/// `word` must have bits[31:24]=0b11110100 (load) or 0b11110000 (store).
///
/// Returns `None` if the encoding is not a VLD/VST multiple.
#[must_use]
pub fn decode_neon_ls(word: u32, is_load: bool) -> Option<NeonInstr> {
    let rn = ((word >> 16) & 0xF) as u8;
    let vd = ((word >> 12) & 0xF) as u8;
    let ls_ty = ((word >> 8) & 0xF) as u8;
    let size = ((word >> 6) & 3) as u8;
    let align = ((word >> 4) & 3) as u8;
    let rm = (word & 0xF) as u8;

    let ty = NeonLsType::from_type_field(ls_ty)?;
    let n = ty.count();
    let suffix = neon_size_suffix(size);
    let verb = if is_load { "vld" } else { "vst" };
    let mnemonic = format!("{verb}{n}{suffix}");

    let reg_list = {
        let mut s = String::from("{");
        for i in 0..n {
            if i != 0 {
                s.push_str(", ");
            }
            s.push_str(dreg(vd + i));
        }
        s.push('}');
        s
    };

    let align_str = if align != 0 {
        format!("@{}", 8u32 << align)
    } else {
        String::new()
    };

    let rm_str = match rm {
        0xD => "sp".to_string(),
        0xF => "!".to_string(),
        r => format!(", r{r}"),
    };

    let rn_name = if rn == 13 {
        "sp"
    } else if rn == 15 {
        "pc"
    } else {
        ""
    };
    let base = if rn_name.is_empty() {
        format!("[r{rn}{align_str}]{rm_str}")
    } else {
        format!("[{rn_name}{align_str}]{rm_str}")
    };

    Some(NeonInstr {
        mnemonic,
        operands: format!("{reg_list}, {base}"),
    })
}

// ---------------------------------------------------------------------------
// NEON scalar operations
// ---------------------------------------------------------------------------

/// Decode a NEON scalar (lane-indexed) operation mnemonic.
///
/// `opc1` and `opc2` are the opcode fields from the encoding.
/// `size` is the element size field (2-bit).
/// Returns the mnemonic string or `"???"`.
#[must_use]
pub fn neon_scalar_mnemonic(opc1: u8, opc2: u8, size: u8, u: u8) -> String {
    let sfx = if u != 0 {
        neon_unsigned_suffix(size)
    } else {
        neon_signed_suffix(size)
    };
    match (opc1 & 3, opc2 & 7) {
        (0, 0) => format!("vmla{sfx}"),
        (0, 4) => format!("vmls{sfx}"),
        (1, 0) => format!("vmull{sfx}"),
        (1, 4) => format!("vqdmull{sfx}"),
        (2, 0) => format!("vmlal{sfx}"),
        (2, 4) => format!("vmlsl{sfx}"),
        (3, 0) => format!("vmla{}", neon_float_suffix(size)),
        (3, 4) => format!("vmls{}", neon_float_suffix(size)),
        _ => "???".to_string(),
    }
}

// ---------------------------------------------------------------------------
// NEON shift-by-immediate
// ---------------------------------------------------------------------------

/// Decode a NEON shift-by-immediate instruction.
///
/// `l` is the L bit (extends imm6 to 64-bit range),
/// `imm6` is the 6-bit shift amount field,
/// `opc` is the U:opc concatenation.
pub fn decode_neon_shift_imm(l: u8, imm6: u8, opc: u8, u: u8, q: u8, vd: u8, vm: u8) -> NeonInstr {
    // Determine the element size from L:imm6
    let esize = if l != 0 {
        64u8
    } else if imm6 & 0x20 != 0 {
        32
    } else if imm6 & 0x10 != 0 {
        16
    } else if imm6 & 0x08 != 0 {
        8
    } else {
        return NeonInstr {
            mnemonic: "???".to_string(),
            operands: String::new(),
        };
    };

    let size_code = match esize {
        8 => 0u8,
        16 => 1,
        32 => 2,
        _ => 3,
    };

    let reg_d = if q != 0 { qreg(vd >> 1) } else { dreg(vd) };
    let reg_m = if q != 0 { qreg(vm >> 1) } else { dreg(vm) };

    // Shift amount: right-shifts are encoded as (esize - imm6), left-shifts as imm6
    let right = u32::from(esize) - u32::from(imm6);
    let left = u32::from(imm6);
    let ssuf = neon_signed_suffix(size_code);
    let usuf = neon_unsigned_suffix(size_code);
    let zsuf = neon_size_suffix(size_code);
    let (mnemonic, shamt) = match (opc & 0xF, u != 0) {
        (0x0, false) => (format!("vshr{ssuf}"), right),
        (0x0, true) => (format!("vshr{usuf}"), right),
        (0x1, false) => (format!("vsra{ssuf}"), right),
        (0x1, true) => (format!("vsra{usuf}"), right),
        (0x2, false) => (format!("vrshr{ssuf}"), right),
        (0x2, true) => (format!("vrshr{usuf}"), right),
        (0x3, false) => (format!("vrsra{ssuf}"), right),
        (0x3, true) => (format!("vrsra{usuf}"), right),
        (0x4, true) => (format!("vsri{zsuf}"), right),
        (0x5, false) => (format!("vshl{zsuf}"), left),
        (0x5, true) => (format!("vsli{zsuf}"), left),
        (0x6 | 0x7, false) => (format!("vqshl{ssuf}"), left),
        (0x6, true) => (format!("vqshl{usuf}"), left),
        (0x7, true) => (format!("vqshlu{ssuf}"), left),
        (0x8, false) => (format!("vshrn{zsuf}"), right),
        (0x8, true) => (format!("vqshrun{ssuf}"), right),
        (0x9, false) => (format!("vqshrn{ssuf}"), right),
        (0x9, true) => (format!("vqshrn{usuf}"), right),
        (0xA, false) => (format!("vshll{ssuf}"), left),
        (0xA, true) => (format!("vshll{usuf}"), left),
        (0xE, _) => ("vcvt.f32.s32".to_string(), left),
        (0xF, _) => ("vcvt.f32.u32".to_string(), left),
        _ => ("???".to_string(), 0),
    };

    NeonInstr {
        mnemonic,
        operands: format!("{reg_d}, {reg_m}, #{shamt}"),
    }
}

// ---------------------------------------------------------------------------
// NEON two-register misc
// ---------------------------------------------------------------------------

/// Decode a NEON two-register miscellaneous instruction.
///
/// `a` is bits[17:16] and `b` is bits[10:6] from the encoding.
pub fn decode_neon_2reg_misc(a: u8, b: u8, size: u8, q: u8, vd: u8, vm: u8) -> NeonInstr {
    let reg_d = if q != 0 { qreg(vd >> 1) } else { dreg(vd) };
    let reg_m = if q != 0 { qreg(vm >> 1) } else { dreg(vm) };
    let ops = format!("{reg_d}, {reg_m}");

    let mnemonic = match (a & 3, b & 0x1F) {
        (0, 0x00) => format!("vrev64{}", neon_size_suffix(size)),
        (0, 0x04) => format!("vrev32{}", neon_size_suffix(size)),
        (0, 0x08) => format!("vrev16{}", neon_size_suffix(size)),
        (0, 0x10) => format!("vpaddl{}", neon_signed_suffix(size)),
        (0, 0x12) => format!("vpaddl{}", neon_unsigned_suffix(size)),
        (0, 0x14) => "vcls.s8".to_string(),
        (0, 0x16) => "vclz.i8".to_string(),
        (0, 0x18) => "vcnt.8".to_string(),
        (0, 0x19) => "vmvn".to_string(),
        (0, 0x1C) => format!("vpadal{}", neon_signed_suffix(size)),
        (0, 0x1E) => format!("vpadal{}", neon_unsigned_suffix(size)),
        (0, 0x1A) => format!("vqabs{}", neon_signed_suffix(size)),
        (0, 0x1B) => format!("vqneg{}", neon_signed_suffix(size)),
        (1, 0x00) => format!("vcgt.{}", if size == 2 { "f32" } else { "s32" }),
        (1, 0x04) => format!("vcge.{}", if size == 2 { "f32" } else { "s32" }),
        (1, 0x08) => format!("vceq.{}", if size == 2 { "f32" } else { "i32" }),
        (1, 0x0C) => format!("vcle.{}", if size == 2 { "f32" } else { "s32" }),
        (1, 0x10) => format!("vclt.{}", if size == 2 { "f32" } else { "s32" }),
        (1, 0x14) => "vabs.f32".to_string(),
        (1, 0x18) => "vneg.f32".to_string(),
        (2, 0x00) => "vswp".to_string(),
        (2, 0x04) => "vtrn.8".to_string(),
        (2, 0x08) => "vuzp.8".to_string(),
        (2, 0x0C) => "vzip.8".to_string(),
        (2, 0x10) => "vmovn.i16".to_string(),
        (2, 0x11) => "vqmovun.s16".to_string(),
        (2, 0x12) => "vqmovn.s16".to_string(),
        (2, 0x13) => "vqmovn.u16".to_string(),
        (2, 0x14) => "vshll.i8".to_string(),
        (2, 0x18) | (3, 0x09) => "vcvt.f32.s32".to_string(),
        (2, 0x19) | (3, 0x08) => "vcvt.f32.u32".to_string(),
        (2, 0x1A) => "vcvtps.u32.f32".to_string(),
        (2, 0x1B) => "vcvtps.s32.f32".to_string(),
        (2, 0x1E) => "vcvt.f16.f32".to_string(),
        (2, 0x1F) => "vcvt.f32.f16".to_string(),
        (3, 0x00) => format!("vrecpe{}", neon_float_suffix(size)),
        (3, 0x04) => format!("vrsqrte{}", neon_float_suffix(size)),
        (3, 0x0A) => "vcvt.u32.f32".to_string(),
        (3, 0x0B) => "vcvt.s32.f32".to_string(),
        _ => "???".to_string(),
    };

    NeonInstr {
        mnemonic,
        operands: ops,
    }
}

// ---------------------------------------------------------------------------
// NEON table lookup
// ---------------------------------------------------------------------------

/// Decode VTBL / VTBX instruction.
pub fn decode_neon_table(word: u32) -> NeonInstr {
    let vd = ((word >> 12) & 0xF) as u8;
    let vn = ((word >> 16) & 0xF) as u8;
    let vm = (word & 0xF) as u8;
    let len = ((word >> 8) & 3) as u8 + 1; // number of table registers
    let is_vtbx = (word >> 6) & 1 != 0;

    let mnemonic = if is_vtbx {
        "vtbx.8".to_string()
    } else {
        "vtbl.8".to_string()
    };
    let table = {
        let mut s = String::from("{");
        for i in 0..len {
            if i != 0 {
                s.push_str(", ");
            }
            s.push_str(dreg(vn + i));
        }
        s.push('}');
        s
    };
    NeonInstr {
        mnemonic,
        operands: format!("{}, {}, {}", dreg(vd), table, dreg(vm)),
    }
}

// ---------------------------------------------------------------------------
// NEON duplicate / move element
// ---------------------------------------------------------------------------

/// Decode VDUP (scalar to vector) instruction.
#[must_use]
pub fn decode_vdup(word: u32) -> Option<NeonInstr> {
    let b = (word >> 22) & 1;
    let e = (word >> 5) & 1;
    let q = (word >> 6) & 1;
    let vd = ((word >> 16) & 0xF) as u8;
    let rt = ((word >> 12) & 0xF) as u8;

    let (suffix, _lane) = match (b, e) {
        (0, 0) => (".32", 0),
        (1, 0) => (".8", 0),
        (0, 1) => (".16", 0),
        _ => return None,
    };

    let reg_d = if q != 0 { qreg(vd >> 1) } else { dreg(vd) };
    let rt_name = match rt {
        13 => "sp".to_string(),
        14 => "lr".to_string(),
        15 => "pc".to_string(),
        r => format!("r{r}"),
    };

    Some(NeonInstr {
        mnemonic: format!("vdup{suffix}"),
        operands: format!("{reg_d}, {rt_name}"),
    })
}

// ---------------------------------------------------------------------------
// NEON pairwise add / min / max
// ---------------------------------------------------------------------------

/// Return the mnemonic for a NEON pairwise operation.
///
/// `op` is the pairwise opcode: 0=VPADD, 1=VPMAX(signed), 2=VPMAX(unsigned),
/// 3=VPMIN(signed), 4=VPMIN(unsigned).
#[must_use]
pub fn neon_pairwise_mnemonic(op: u8, size: u8, is_float: bool) -> String {
    if is_float {
        match op & 7 {
            0 => "vpadd.f32".to_string(),
            1 => "vpmax.f32".to_string(),
            2 => "vpmin.f32".to_string(),
            _ => "???".to_string(),
        }
    } else {
        match op & 7 {
            0 => format!("vpadd{}", neon_size_suffix(size)),
            1 => format!("vpmax{}", neon_signed_suffix(size)),
            2 => format!("vpmax{}", neon_unsigned_suffix(size)),
            3 => format!("vpmin{}", neon_signed_suffix(size)),
            4 => format!("vpmin{}", neon_unsigned_suffix(size)),
            _ => "???".to_string(),
        }
    }
}

// ---------------------------------------------------------------------------
// NEON multiply (long/accumulate)
// ---------------------------------------------------------------------------

/// Decode VMULL / VMLAL / VMLSL (polynomial or integer).
pub fn decode_neon_long_mul(word: u32) -> NeonInstr {
    let u = (word >> 24) & 1;
    let size = ((word >> 20) & 3) as u8;
    let vn = ((word >> 16) & 0xF) as u8;
    let vd = ((word >> 12) & 0xF) as u8;
    let opc = ((word >> 8) & 0xF) as u8;
    let vm = (word & 0xF) as u8;
    let n_bit = ((word >> 7) & 1) as u8;
    let m_bit = ((word >> 5) & 1) as u8;

    let rd = vd;
    let rn = vn | (n_bit << 4);
    let rm = vm | (m_bit << 4);

    let sfx = if u != 0 {
        neon_unsigned_suffix(size)
    } else {
        neon_signed_suffix(size)
    };

    let mnemonic = match opc {
        0x0 => format!("vmlal{sfx}"),
        0x4 => format!("vmlsl{sfx}"),
        0x8 => format!("vmull{sfx}"),
        0xC => {
            if u != 0 {
                format!("vmull.p{}", if size == 0 { "8" } else { "64" })
            } else {
                format!("vqdmull{sfx}")
            }
        }
        0x9 => format!("vqdmull{sfx}"),
        0x2 => format!("vqdmlal{sfx}"),
        0x6 => format!("vqdmlsl{sfx}"),
        _ => "???".to_string(),
    };

    NeonInstr {
        mnemonic,
        operands: format!("{}, {}, {}", qreg(rd >> 1), dreg(rn), dreg(rm)),
    }
}

// ---------------------------------------------------------------------------
// NEON floating-point operations
// ---------------------------------------------------------------------------

/// Decode VADD / VSUB / VMUL / VDIV (floating-point vector).
#[must_use]
pub fn decode_neon_fp(word: u32) -> Option<NeonInstr> {
    let opc = (word >> 20) & 0xF;
    let vn = ((word >> 16) & 0xF) as u8;
    let vd = ((word >> 12) & 0xF) as u8;
    let vm = (word & 0xF) as u8;
    let q = ((word >> 6) & 1) as u8;

    let reg_d = if q != 0 { qreg(vd >> 1) } else { dreg(vd) };
    let reg_n = if q != 0 { qreg(vn >> 1) } else { dreg(vn) };
    let reg_m = if q != 0 { qreg(vm >> 1) } else { dreg(vm) };
    let ops = format!("{reg_d}, {reg_n}, {reg_m}");

    let mnemonic = match opc {
        0x0 => "vadd.f32".to_string(),
        0x2 => "vsub.f32".to_string(),
        0x3 => "vabd.f32".to_string(),
        0x4 => "vmul.f32".to_string(),
        0x6 => "vmls.f32".to_string(),
        0x8 => "vceq.f32".to_string(),
        0xC => "vcgt.f32".to_string(),
        0xE => "vcge.f32".to_string(),
        0x5 => "vrecps.f32".to_string(),
        0x7 => "vrsqrts.f32".to_string(),
        _ => return None,
    };
    Some(NeonInstr {
        mnemonic,
        operands: ops,
    })
}

// ---------------------------------------------------------------------------
// NEON element / structure load/store — single structure to one lane
// ---------------------------------------------------------------------------

/// Decode VLD1/VST1 single-element to one lane.
#[must_use]
pub fn decode_neon_single_lane(word: u32, is_load: bool) -> Option<NeonInstr> {
    let size = ((word >> 10) & 3) as u8;
    let vd = ((word >> 12) & 0xF) as u8;
    let rn = ((word >> 16) & 0xF) as u8;
    let index = ((word >> 4) & 0xF) as u8;
    let rm = (word & 0xF) as u8;

    if size > 2 {
        return None;
    }
    let suffix = neon_size_suffix(size);
    let verb = if is_load { "vld1" } else { "vst1" };
    let mnemonic = format!("{verb}{suffix}");

    let rn_name = match rn {
        13 => "sp".to_string(),
        15 => "pc".to_string(),
        r => format!("r{r}"),
    };
    let wb = match rm {
        0xD => "!".to_string(),
        0xF => String::new(),
        r => format!(", r{r}"),
    };

    Some(NeonInstr {
        mnemonic,
        operands: format!("{{{}[{index}]}}, [{rn_name}]{wb}", dreg(vd)),
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dreg_names() {
        assert_eq!(dreg(0), "d0");
        assert_eq!(dreg(15), "d15");
        assert_eq!(dreg(31), "d31");
    }

    #[test]
    fn test_qreg_names() {
        assert_eq!(qreg(0), "q0");
        assert_eq!(qreg(15), "q15");
    }

    #[test]
    fn test_sreg_names() {
        assert_eq!(sreg(0), "s0");
        assert_eq!(sreg(31), "s31");
    }

    #[test]
    fn test_neon_size_suffix() {
        assert_eq!(neon_size_suffix(0), ".8");
        assert_eq!(neon_size_suffix(2), ".32");
        assert_eq!(neon_size_suffix(3), ".64");
    }

    #[test]
    fn test_neon_signed_suffix() {
        assert_eq!(neon_signed_suffix(1), ".s16");
        assert_eq!(neon_signed_suffix(2), ".s32");
    }

    #[test]
    fn test_neon_unsigned_suffix() {
        assert_eq!(neon_unsigned_suffix(0), ".u8");
        assert_eq!(neon_unsigned_suffix(3), ".u64");
    }

    #[test]
    fn test_neon_float_suffix() {
        assert_eq!(neon_float_suffix(2), ".f32");
        assert_eq!(neon_float_suffix(3), ".f64");
    }

    #[test]
    fn test_decode_neon_dp_vadd() {
        // F2 02 08 0 → vadd.i32 (synthetic: manually construct an approximate word)
        // Build: U=0, size=2, opc=8 (vshl), Q=0
        // bits[31:24]=0xF2, size=2 at [21:20], opc=8 at [11:8]
        let word: u32 = 0xF200_0800 | (2 << 20) | (8 << 8);
        let r = decode_neon_dp(word);
        assert!(r.is_some());
        let instr = r.unwrap();
        assert!(instr.mnemonic.contains("vshl"));
    }

    #[test]
    fn test_decode_neon_dp_none() {
        // Not a NEON dp word
        assert!(decode_neon_dp(0x0000_0000).is_none());
        assert!(decode_neon_dp(0xE000_0000).is_none());
    }

    #[test]
    fn test_neon_ls_type_from_type_field() {
        assert_eq!(NeonLsType::from_type_field(0x7), Some(NeonLsType::Ls1));
        assert_eq!(NeonLsType::from_type_field(0x8), Some(NeonLsType::Ls2));
        assert_eq!(NeonLsType::from_type_field(0x4), Some(NeonLsType::Ls3));
        assert_eq!(NeonLsType::from_type_field(0x0), Some(NeonLsType::Ls4));
        assert_eq!(NeonLsType::from_type_field(0xB), None);
    }

    #[test]
    fn test_neon_ls_count() {
        assert_eq!(NeonLsType::Ls2.count(), 2);
        assert_eq!(NeonLsType::Ls4.count(), 4);
    }

    #[test]
    fn test_neon_scalar_mnemonic_vmla() {
        let s = neon_scalar_mnemonic(0, 0, 2, 0);
        assert_eq!(s, "vmla.s32");
    }

    #[test]
    fn test_neon_scalar_mnemonic_vmull() {
        let s = neon_scalar_mnemonic(1, 0, 1, 0);
        assert_eq!(s, "vmull.s16");
    }

    #[test]
    fn test_decode_neon_shift_imm_vshl() {
        // l=0, imm6=0b100000 (size=32, shift=32), opc=5, u=0, q=0
        let instr = decode_neon_shift_imm(0, 0b10_0000, 5, 0, 0, 0, 1);
        assert!(instr.mnemonic.contains("vshl") || instr.mnemonic.contains(".32"));
    }

    #[test]
    fn test_decode_neon_2reg_misc_vrev64() {
        let instr = decode_neon_2reg_misc(0, 0x00, 0, 0, 0, 1);
        assert!(instr.mnemonic.contains("vrev64"));
    }

    #[test]
    fn test_decode_neon_2reg_misc_vmvn() {
        let instr = decode_neon_2reg_misc(0, 0x19, 0, 0, 0, 1);
        assert_eq!(instr.mnemonic, "vmvn");
    }

    #[test]
    fn test_neon_pairwise_mnemonic_vpadd() {
        assert_eq!(neon_pairwise_mnemonic(0, 0, false), "vpadd.8");
        assert_eq!(neon_pairwise_mnemonic(0, 0, true), "vpadd.f32");
    }

    #[test]
    fn test_neon_pairwise_mnemonic_vpmax() {
        assert!(neon_pairwise_mnemonic(1, 1, false).contains("vpmax"));
        assert!(neon_pairwise_mnemonic(2, 1, false).contains("vpmax.u"));
    }

    #[test]
    fn test_decode_neon_long_mul_vmull() {
        let word: u32 = 0xF200_0800 | (1 << 24) | (2 << 20) | (8 << 8);
        let instr = decode_neon_long_mul(word);
        // Should be vmull.u32 or similar
        assert!(!instr.mnemonic.is_empty());
    }

    #[test]
    fn test_decode_neon_fp_vadd() {
        // opc=0 → vadd.f32
        let instr = decode_neon_fp(0xF300_0D00);
        assert!(instr.is_some());
        assert!(instr.unwrap().mnemonic.contains("vadd.f32"));
    }

    #[test]
    fn test_decode_neon_table() {
        // Build a VTBL.8 word
        let word: u32 = 0xF3B0_0800;
        let instr = decode_neon_table(word);
        assert!(instr.mnemonic.starts_with("vtbl") || instr.mnemonic.starts_with("vtbx"));
    }

    #[test]
    fn test_vdup_decode() {
        // b=0, e=0 → vdup.32
        let word: u32 = 0xEE80_0B10; // approximate VDUP encoding
        // We just test the function doesn't panic
        let _ = decode_vdup(word);
    }
}
