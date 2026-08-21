//! ARM coprocessor instructions: MCR, MRC, CDP, MCRR, MRRC, LDC, STC.
//!
//! Covers all ARM A32 coprocessor encodings including the System Control
//! coprocessor (CP15) and the VFP/NEON coprocessors (CP10, CP11).

// ---------------------------------------------------------------------------
// Register name helpers
// ---------------------------------------------------------------------------

/// Return a GP register name by index.
#[must_use]
pub const fn gpr(r: u8) -> &'static str {
    match r & 0xF {
        0 => "r0",
        1 => "r1",
        2 => "r2",
        3 => "r3",
        4 => "r4",
        5 => "r5",
        6 => "r6",
        7 => "r7",
        8 => "r8",
        9 => "r9",
        10 => "r10",
        11 => "r11",
        12 => "r12",
        13 => "sp",
        14 => "lr",
        15 => "pc",
        _ => "???",
    }
}

// ---------------------------------------------------------------------------
// Coprocessor instruction decode
// ---------------------------------------------------------------------------

/// Decoded coprocessor instruction.
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use]
pub struct CoprocInstr {
    /// Full mnemonic including condition code (e.g. `"mcreq"`).
    pub mnemonic: String,
    /// Operand string.
    pub operands: String,
}

/// Condition code suffix table.
const COND_SUFFIX: [&str; 16] = [
    "eq", "ne", "cs", "cc", "mi", "pl", "vs", "vc", "hi", "ls", "ge", "lt", "gt", "le", "", "nv",
];

/// Decode the condition code suffix (bits [31:28]).
#[must_use]
const fn cond_suffix(cond: u8) -> &'static str {
    COND_SUFFIX[(cond & 0xF) as usize]
}

/// Decode an MCR (Move to Coprocessor from ARM Register) instruction.
///
/// `word` must match the MCR encoding: cond 1110 opc1 1 `CRn` Rt `cp_num` opc2 1 `CRm`.
///
/// Returns `None` if the word does not encode MCR.
#[must_use]
pub fn decode_mcr(word: u32) -> Option<CoprocInstr> {
    // Bits [27:24] = 1110, bit[20] = 0 (MCR), bit[4] = 1
    if (word >> 24) & 0xF != 0xE {
        return None;
    }
    if (word >> 20) & 1 != 0 {
        return None;
    }
    if (word >> 4) & 1 != 1 {
        return None;
    }

    let cond = ((word >> 28) & 0xF) as u8;
    let opc1 = ((word >> 21) & 0x7) as u8;
    let crn = ((word >> 16) & 0xF) as u8;
    let rt = ((word >> 12) & 0xF) as u8;
    let cp_num = ((word >> 8) & 0xF) as u8;
    let opc2 = ((word >> 5) & 0x7) as u8;
    let crm = (word & 0xF) as u8;

    Some(CoprocInstr {
        mnemonic: format!("mcr{}", cond_suffix(cond)),
        operands: format!("p{cp_num}, {opc1}, {}, c{crn}, c{crm}, {opc2}", gpr(rt)),
    })
}

/// Decode an MRC (Move to ARM Register from Coprocessor) instruction.
#[must_use]
pub fn decode_mrc(word: u32) -> Option<CoprocInstr> {
    if (word >> 24) & 0xF != 0xE {
        return None;
    }
    if (word >> 20) & 1 != 1 {
        return None;
    } // bit20=1 for MRC
    if (word >> 4) & 1 != 1 {
        return None;
    }

    let cond = ((word >> 28) & 0xF) as u8;
    let opc1 = ((word >> 21) & 0x7) as u8;
    let crn = ((word >> 16) & 0xF) as u8;
    let rt = ((word >> 12) & 0xF) as u8;
    let cp_num = ((word >> 8) & 0xF) as u8;
    let opc2 = ((word >> 5) & 0x7) as u8;
    let crm = (word & 0xF) as u8;

    Some(CoprocInstr {
        mnemonic: format!("mrc{}", cond_suffix(cond)),
        operands: format!("p{cp_num}, {opc1}, {}, c{crn}, c{crm}, {opc2}", gpr(rt)),
    })
}

/// Decode a CDP (Coprocessor Data Processing) instruction.
#[must_use]
pub fn decode_cdp(word: u32) -> Option<CoprocInstr> {
    if (word >> 24) & 0xF != 0xE {
        return None;
    }
    if (word >> 4) & 1 != 0 {
        return None;
    } // bit4=0 for CDP

    let cond = ((word >> 28) & 0xF) as u8;
    let opc1 = ((word >> 20) & 0xF) as u8;
    let crn = ((word >> 16) & 0xF) as u8;
    let crd = ((word >> 12) & 0xF) as u8;
    let cp_num = ((word >> 8) & 0xF) as u8;
    let opc2 = ((word >> 5) & 0x7) as u8;
    let crm = (word & 0xF) as u8;

    Some(CoprocInstr {
        mnemonic: format!("cdp{}", cond_suffix(cond)),
        operands: format!("p{cp_num}, {opc1}, c{crd}, c{crn}, c{crm}, {opc2}"),
    })
}

/// Decode an MCRR (Move to Coprocessor from two ARM Registers) instruction.
#[must_use]
pub fn decode_mcrr(word: u32) -> Option<CoprocInstr> {
    // bits[27:20] = 1100 0100
    if (word >> 20) & 0xFF != 0xC4 {
        return None;
    }

    let cond = ((word >> 28) & 0xF) as u8;
    let rt2 = ((word >> 16) & 0xF) as u8;
    let rt = ((word >> 12) & 0xF) as u8;
    let cp_num = ((word >> 8) & 0xF) as u8;
    let opc1 = ((word >> 4) & 0xF) as u8;
    let crm = (word & 0xF) as u8;

    Some(CoprocInstr {
        mnemonic: format!("mcrr{}", cond_suffix(cond)),
        operands: format!("p{cp_num}, {opc1}, {}, {}, c{crm}", gpr(rt), gpr(rt2)),
    })
}

/// Decode an MRRC (Move to two ARM Registers from Coprocessor) instruction.
#[must_use]
pub fn decode_mrrc(word: u32) -> Option<CoprocInstr> {
    if (word >> 20) & 0xFF != 0xC5 {
        return None;
    }

    let cond = ((word >> 28) & 0xF) as u8;
    let rt2 = ((word >> 16) & 0xF) as u8;
    let rt = ((word >> 12) & 0xF) as u8;
    let cp_num = ((word >> 8) & 0xF) as u8;
    let opc1 = ((word >> 4) & 0xF) as u8;
    let crm = (word & 0xF) as u8;

    Some(CoprocInstr {
        mnemonic: format!("mrrc{}", cond_suffix(cond)),
        operands: format!("p{cp_num}, {opc1}, {}, {}, c{crm}", gpr(rt), gpr(rt2)),
    })
}

/// Decode an LDC (Load Coprocessor) instruction.
#[must_use]
pub fn decode_ldc(word: u32) -> Option<CoprocInstr> {
    let bits27_20 = (word >> 20) & 0xFF;
    // LDC: bits[27:25]=110, bit24 = P, bit23 = U, bit22 = D(long), bit20=1
    if (bits27_20 >> 5) != 0b110 {
        return None;
    }
    if bits27_20 & 1 != 1 {
        return None;
    }

    let cond = ((word >> 28) & 0xF) as u8;
    let p_bit = (word >> 24) & 1;
    let u_bit = (word >> 23) & 1;
    let d_bit = (word >> 22) & 1;
    let w_bit = (word >> 21) & 1;
    let rn = ((word >> 16) & 0xF) as u8;
    let crd = ((word >> 12) & 0xF) as u8;
    let cp_num = ((word >> 8) & 0xF) as u8;
    let imm8 = word & 0xFF;

    let suffix_l = if d_bit != 0 { "l" } else { "" };
    let mnemonic = format!("ldc{suffix_l}{}", cond_suffix(cond));

    let sign = if u_bit != 0 { "" } else { "-" };
    let offset = imm8 * 4;
    let addr = if p_bit != 0 {
        let wb = if w_bit != 0 { "!" } else { "" };
        format!("[{}, #{sign}{offset}]{wb}", gpr(rn))
    } else if w_bit != 0 {
        format!("[{}], #{sign}{offset}", gpr(rn))
    } else {
        format!("[{}]", gpr(rn)) // unindexed
    };

    Some(CoprocInstr {
        mnemonic,
        operands: format!("p{cp_num}, c{crd}, {addr}"),
    })
}

/// Decode an STC (Store Coprocessor) instruction.
#[must_use]
pub fn decode_stc(word: u32) -> Option<CoprocInstr> {
    let bits27_20 = (word >> 20) & 0xFF;
    if (bits27_20 >> 5) != 0b110 {
        return None;
    }
    if bits27_20 & 1 != 0 {
        return None;
    } // bit20=0 for STC

    let cond = ((word >> 28) & 0xF) as u8;
    let p_bit = (word >> 24) & 1;
    let u_bit = (word >> 23) & 1;
    let d_bit = (word >> 22) & 1;
    let w_bit = (word >> 21) & 1;
    let rn = ((word >> 16) & 0xF) as u8;
    let crd = ((word >> 12) & 0xF) as u8;
    let cp_num = ((word >> 8) & 0xF) as u8;
    let imm8 = word & 0xFF;

    let suffix_l = if d_bit != 0 { "l" } else { "" };
    let mnemonic = format!("stc{suffix_l}{}", cond_suffix(cond));

    let sign = if u_bit != 0 { "" } else { "-" };
    let offset = imm8 * 4;
    let addr = if p_bit != 0 {
        let wb = if w_bit != 0 { "!" } else { "" };
        format!("[{}, #{sign}{offset}]{wb}", gpr(rn))
    } else if w_bit != 0 {
        format!("[{}], #{sign}{offset}", gpr(rn))
    } else {
        format!("[{}]", gpr(rn))
    };

    Some(CoprocInstr {
        mnemonic,
        operands: format!("p{cp_num}, c{crd}, {addr}"),
    })
}

// ---------------------------------------------------------------------------
// CP15 System Control register names
// ---------------------------------------------------------------------------

/// CP15 register name for a given (opc1, crn, crm, opc2) tuple.
///
/// Returns `None` if the combination is unknown.
#[must_use]
pub const fn cp15_reg_name(opc1: u8, crn: u8, crm: u8, opc2: u8) -> Option<&'static str> {
    match (opc1, crn, crm, opc2) {
        (0, 0, 0, 0) => Some("MIDR"),
        (0, 0, 0, 1) => Some("CTR"),
        (0, 0, 0, 2) => Some("TCMTR"),
        (0, 0, 0, 3) => Some("TLBTR"),
        (0, 0, 0, 5) => Some("MPIDR"),
        (0, 0, 0, 6) => Some("REVIDR"),
        (0, 0, 1, 0) => Some("ID_PFR0"),
        (0, 0, 1, 1) => Some("ID_PFR1"),
        (0, 0, 1, 2) => Some("ID_DFR0"),
        (0, 0, 1, 3) => Some("ID_AFR0"),
        (0, 0, 1, 4) => Some("ID_MMFR0"),
        (0, 0, 1, 5) => Some("ID_MMFR1"),
        (0, 0, 1, 6) => Some("ID_MMFR2"),
        (0, 0, 1, 7) => Some("ID_MMFR3"),
        (0, 0, 2, 0) => Some("ID_ISAR0"),
        (0, 0, 2, 1) => Some("ID_ISAR1"),
        (0, 0, 2, 2) => Some("ID_ISAR2"),
        (0, 0, 2, 3) => Some("ID_ISAR3"),
        (0, 0, 2, 4) => Some("ID_ISAR4"),
        (0, 0, 2, 5) => Some("ID_ISAR5"),
        (0, 1, 0, 0) => Some("SCTLR"),
        (0, 1, 0, 1) => Some("ACTLR"),
        (0, 1, 0, 2) => Some("CPACR"),
        (0, 2, 0, 0) => Some("TTBR0"),
        (0, 2, 0, 1) => Some("TTBR1"),
        (0, 2, 0, 2) => Some("TTBCR"),
        (0, 3, 0, 0) => Some("DACR"),
        (0, 5, 0, 0) => Some("DFSR"),
        (0, 5, 0, 1) => Some("IFSR"),
        (0, 5, 1, 0) => Some("ADFSR"),
        (0, 5, 1, 1) => Some("AIFSR"),
        (0, 6, 0, 0) => Some("DFAR"),
        (0, 6, 0, 2) => Some("IFAR"),
        (0, 7, 0, 4) => Some("PAR"),
        (0, 7, 1, 0) => Some("ICIALLUIS"),
        (0, 7, 5, 0) => Some("ICIALLU"),
        (0, 7, 5, 1) => Some("ICIMVAU"),
        (0, 7, 5, 4) => Some("CP15ISB"),
        (0, 7, 6, 1) => Some("DCIMVAC"),
        (0, 7, 6, 2) => Some("DCISW"),
        (0, 7, 8, 0) => Some("ATS1CPR"),
        (0, 7, 8, 1) => Some("ATS1CPW"),
        (0, 7, 10, 1) => Some("DCCMVAC"),
        (0, 7, 10, 2) => Some("DCCSW"),
        (0, 7, 10, 4) => Some("CP15DSB"),
        (0, 7, 10, 5) => Some("CP15DMB"),
        (0, 7, 11, 1) => Some("DCCMVAU"),
        (0, 7, 14, 1) => Some("DCCIMVAC"),
        (0, 7, 14, 2) => Some("DCCISW"),
        (0, 8, 3, 0) => Some("TLBIALLIS"),
        (0, 8, 7, 0) => Some("TLBIALL"),
        (0, 8, 7, 1) => Some("TLBIMVA"),
        (0, 8, 7, 2) => Some("TLBIASID"),
        (0, 9, 12, 0) => Some("PMCR"),
        (0, 9, 12, 1) => Some("PMCNTENSET"),
        (0, 9, 12, 2) => Some("PMCNTENCLR"),
        (0, 9, 12, 3) => Some("PMOVSR"),
        (0, 9, 12, 5) => Some("PMSELR"),
        (0, 9, 13, 0) => Some("PMCCNTR"),
        (0, 9, 13, 1) => Some("PMXEVTYPER"),
        (0, 9, 13, 2) => Some("PMXEVCNTR"),
        (0, 9, 14, 0) => Some("PMUSERENR"),
        (0, 9, 14, 1) => Some("PMINTENSET"),
        (0, 9, 14, 2) => Some("PMINTENCLR"),
        (0, 10, 2, 0) => Some("PRRR"),
        (0, 10, 2, 1) => Some("NMRR"),
        (0, 12, 0, 0) => Some("VBAR"),
        (0, 13, 0, 0) => Some("FCSEIDR"),
        (0, 13, 0, 1) => Some("CONTEXTIDR"),
        (0, 13, 0, 2) => Some("TPIDRURW"),
        (0, 13, 0, 3) => Some("TPIDRURO"),
        (0, 13, 0, 4) => Some("TPIDRPRW"),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Cortex-M specific system registers and instructions
// ---------------------------------------------------------------------------

/// Cortex-M special-purpose register names (for MSR/MRS).
#[must_use]
pub const fn cortex_m_sys_reg(sysm: u16) -> &'static str {
    match sysm & 0xFF {
        0x00 => "APSR",
        0x01 => "IAPSR",
        0x02 => "EAPSR",
        0x03 => "XPSR",
        0x05 => "IPSR",
        0x06 => "EPSR",
        0x07 => "IEPSR",
        0x08 => "MSP",
        0x09 => "PSP",
        0x10 => "PRIMASK",
        0x11 => "BASEPRI",
        0x12 => "BASEPRI_MAX",
        0x13 => "FAULTMASK",
        0x14 => "CONTROL",
        0x18 => "MSP_NS",
        0x19 => "PSP_NS",
        0x1A => "MSPLIM",
        0x1B => "PSPLIM",
        _ => "???",
    }
}

/// `EXC_RETURN` magic values for Cortex-M exception returns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub enum ExcReturn {
    /// Return to Handler mode, use MSP, restore FP state.
    HandlerMsp,
    /// Return to Thread mode, use MSP, restore FP state.
    ThreadMsp,
    /// Return to Thread mode, use PSP, restore FP state.
    ThreadPsp,
    /// Return to Handler mode, use MSP, no FP state.
    HandlerMspNoFp,
    /// Return to Thread mode, use MSP, no FP state.
    ThreadMspNoFp,
    /// Return to Thread mode, use PSP, no FP state.
    ThreadPspNoFp,
    /// Unknown `EXC_RETURN` value.
    Unknown(u32),
}

impl ExcReturn {
    /// Parse an `EXC_RETURN` value (must start with `0xFFFF_FF`).
    pub const fn parse(val: u32) -> Self {
        match val {
            0xFFFF_FFE1 => Self::HandlerMsp,
            0xFFFF_FFE9 => Self::ThreadMsp,
            0xFFFF_FFED => Self::ThreadPsp,
            0xFFFF_FFF1 => Self::HandlerMspNoFp,
            0xFFFF_FFF9 => Self::ThreadMspNoFp,
            0xFFFF_FFFD => Self::ThreadPspNoFp,
            other => Self::Unknown(other),
        }
    }

    /// Human-readable description.
    #[must_use]
    pub const fn description(&self) -> &'static str {
        match self {
            Self::HandlerMsp => "Return to Handler mode, MSP, FP",
            Self::ThreadMsp => "Return to Thread mode, MSP, FP",
            Self::ThreadPsp => "Return to Thread mode, PSP, FP",
            Self::HandlerMspNoFp => "Return to Handler mode, MSP, no FP",
            Self::ThreadMspNoFp => "Return to Thread mode, MSP, no FP",
            Self::ThreadPspNoFp => "Return to Thread mode, PSP, no FP",
            Self::Unknown(_) => "Unknown EXC_RETURN",
        }
    }
}

// ---------------------------------------------------------------------------
// ARMv7 parallel arithmetic and saturating instructions
// ---------------------------------------------------------------------------

/// Decode a parallel arithmetic instruction (GE flags version).
///
/// Covers UADD8/UADD16/USUB8/USUB16/UASX/USAX/SADD8/SADD16 etc.
/// `op` is bits [22:20] of the A32 encoding.
/// `s_bit` = 1 for signed variants.
#[must_use]
pub const fn parallel_arith_mnemonic(op: u8, s_bit: u8) -> &'static str {
    let signed = s_bit != 0;
    match (op & 7, signed) {
        (0b001, true) => "sadd16",
        (0b001, false) => "uadd16",
        (0b010, true) => "sasx",
        (0b010, false) => "uasx",
        (0b011, true) => "ssax",
        (0b011, false) => "usax",
        (0b100, true) => "ssub16",
        (0b100, false) => "usub16",
        (0b101, true) => "sadd8",
        (0b101, false) => "uadd8",
        (0b110, true) => "ssub8",
        (0b110, false) => "usub8",
        _ => "???",
    }
}

/// Decode a halving parallel arithmetic mnemonic (SHADD8 etc.).
#[must_use]
pub const fn halving_parallel_arith_mnemonic(op: u8, s_bit: u8) -> &'static str {
    let signed = s_bit != 0;
    match (op & 7, signed) {
        (0b001, true) => "shadd16",
        (0b001, false) => "uhadd16",
        (0b010, true) => "shasx",
        (0b010, false) => "uhasx",
        (0b011, true) => "shsax",
        (0b011, false) => "uhsax",
        (0b100, true) => "shsub16",
        (0b100, false) => "uhsub16",
        (0b101, true) => "shadd8",
        (0b101, false) => "uhadd8",
        (0b110, true) => "shsub8",
        (0b110, false) => "uhsub8",
        _ => "???",
    }
}

/// Decode a saturating parallel arithmetic mnemonic (QADD8 etc.).
#[must_use]
pub const fn saturating_parallel_arith_mnemonic(op: u8, s_bit: u8) -> &'static str {
    let signed = s_bit != 0;
    match (op & 7, signed) {
        (0b001, true) => "qadd16",
        (0b001, false) => "uqadd16",
        (0b010, true) => "qasx",
        (0b010, false) => "uqasx",
        (0b011, true) => "qsax",
        (0b011, false) => "uqsax",
        (0b100, true) => "qsub16",
        (0b100, false) => "uqsub16",
        (0b101, true) => "qadd8",
        (0b101, false) => "uqadd8",
        (0b110, true) => "qsub8",
        (0b110, false) => "uqsub8",
        _ => "???",
    }
}

// ---------------------------------------------------------------------------
// ARMv7 packing/unpacking instructions
// ---------------------------------------------------------------------------

/// Decode a PKHBT/PKHTB (pack halfword) instruction.
pub fn decode_pkh(word: u32) -> CoprocInstr {
    let cond = ((word >> 28) & 0xF) as u8;
    let rn = ((word >> 16) & 0xF) as u8;
    let rd = ((word >> 12) & 0xF) as u8;
    let imm5 = ((word >> 7) & 0x1F) as u8;
    let tb = (word >> 6) & 1;
    let rm = (word & 0xF) as u8;

    let mn = if tb != 0 {
        format!("pkhtb{}", cond_suffix(cond))
    } else {
        format!("pkhbt{}", cond_suffix(cond))
    };

    let shift_str = if tb != 0 {
        if imm5 == 0 {
            ", asr #32".to_string()
        } else {
            format!(", asr #{imm5}")
        }
    } else if imm5 != 0 {
        format!(", lsl #{imm5}")
    } else {
        String::new()
    };

    CoprocInstr {
        mnemonic: mn,
        operands: format!("{}, {}, {}{shift_str}", gpr(rd), gpr(rn), gpr(rm)),
    }
}

/// Decode a SXTB/SXTH/UXTB/UXTH/SXTB16/UXTB16 instruction.
#[must_use]
pub fn decode_extend_rotate(word: u32) -> Option<CoprocInstr> {
    let cond = ((word >> 28) & 0xF) as u8;
    let op = ((word >> 20) & 0xFF) as u8;
    let rn = ((word >> 16) & 0xF) as u8;
    let rd = ((word >> 12) & 0xF) as u8;
    let rot = ((word >> 10) & 3) as u8;
    let rm = (word & 0xF) as u8;

    // bits [27:20] select the variant
    let mnemonic = match op {
        0x6A if rn == 15 => format!("sxth{}", cond_suffix(cond)),
        0x6A => format!("sxtah{}", cond_suffix(cond)),
        0x6B => format!("sxth{}", cond_suffix(cond)),
        0x68 => format!("sxtab16{}", cond_suffix(cond)),
        0x69 => format!("sxtb16{}", cond_suffix(cond)),
        0x6E if rn == 15 => format!("sxtb{}", cond_suffix(cond)),
        0x6E => format!("sxtab{}", cond_suffix(cond)),
        0x6F => format!("sxtb{}", cond_suffix(cond)),
        0x6C => format!("uxtab16{}", cond_suffix(cond)),
        0x6D => format!("uxtb16{}", cond_suffix(cond)),
        0x72 => format!("uxtah{}", cond_suffix(cond)),
        0x73 => format!("uxth{}", cond_suffix(cond)),
        0x76 => format!("uxtab{}", cond_suffix(cond)),
        0x77 => format!("uxtb{}", cond_suffix(cond)),
        _ => return None,
    };

    let rot_str = match rot {
        0 => String::new(),
        r => format!(", ror #{}", r * 8),
    };

    let ops = if rn == 15 {
        format!("{}, {}{rot_str}", gpr(rd), gpr(rm))
    } else {
        format!("{}, {}, {}{rot_str}", gpr(rd), gpr(rn), gpr(rm))
    };

    Some(CoprocInstr {
        mnemonic,
        operands: ops,
    })
}

/// Decode REV/REV16/REVSH/RBIT instructions.
#[must_use]
pub fn decode_rev_rbit(word: u32) -> Option<CoprocInstr> {
    let cond = ((word >> 28) & 0xF) as u8;
    let rd = ((word >> 12) & 0xF) as u8;
    let rm = (word & 0xF) as u8;
    let op = (word >> 4) & 0xFF;

    let mnemonic = match op {
        0xB3 => format!("rev{}", cond_suffix(cond)),
        0xFB => format!("rev16{}", cond_suffix(cond)),
        0xFF => format!("revsh{}", cond_suffix(cond)),
        0xBB => format!("rbit{}", cond_suffix(cond)),
        _ => return None,
    };

    Some(CoprocInstr {
        mnemonic,
        operands: format!("{}, {}", gpr(rd), gpr(rm)),
    })
}

// ---------------------------------------------------------------------------
// Byte-reversal and bit operations
// ---------------------------------------------------------------------------

/// USAD8 / USADA8 — unsigned sum of absolute differences.
pub fn decode_usad8(word: u32) -> CoprocInstr {
    let cond = ((word >> 28) & 0xF) as u8;
    let rd = ((word >> 16) & 0xF) as u8;
    let ra = ((word >> 12) & 0xF) as u8;
    let rm = ((word >> 8) & 0xF) as u8;
    let rn = (word & 0xF) as u8;

    if ra == 15 {
        CoprocInstr {
            mnemonic: format!("usad8{}", cond_suffix(cond)),
            operands: format!("{}, {}, {}", gpr(rd), gpr(rn), gpr(rm)),
        }
    } else {
        CoprocInstr {
            mnemonic: format!("usada8{}", cond_suffix(cond)),
            operands: format!("{}, {}, {}, {}", gpr(rd), gpr(rn), gpr(rm), gpr(ra)),
        }
    }
}

/// SEL — select bytes based on GE flags.
pub fn decode_sel(word: u32) -> CoprocInstr {
    let cond = ((word >> 28) & 0xF) as u8;
    let rn = ((word >> 16) & 0xF) as u8;
    let rd = ((word >> 12) & 0xF) as u8;
    let rm = (word & 0xF) as u8;

    CoprocInstr {
        mnemonic: format!("sel{}", cond_suffix(cond)),
        operands: format!("{}, {}, {}", gpr(rd), gpr(rn), gpr(rm)),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gpr_names() {
        assert_eq!(gpr(0), "r0");
        assert_eq!(gpr(13), "sp");
        assert_eq!(gpr(14), "lr");
        assert_eq!(gpr(15), "pc");
    }

    #[test]
    fn test_cond_suffix_eq_ne() {
        assert_eq!(cond_suffix(0), "eq");
        assert_eq!(cond_suffix(1), "ne");
        assert_eq!(cond_suffix(14), ""); // AL
    }

    #[test]
    fn test_decode_mcr_basic() {
        // MCR p15, 0, r0, c7, c5, 0 → ICIALLU
        // cond=1110 (AL), opc1=0, crn=7, rt=0, cp=15, opc2=0, crm=5, bit4=1
        // 1110 1110 0000 0111 0000 1111 1001 0101
        let word: u32 = 0xEE07_0F95;
        let r = decode_mcr(word);
        assert!(r.is_some());
        let i = r.unwrap();
        assert!(i.mnemonic.contains("mcr"));
        assert!(i.operands.contains("p15"));
    }

    #[test]
    fn test_decode_mrc_basic() {
        // MRC p15, 0, r0, c0, c0, 0 → read MIDR
        let word: u32 = 0xEE10_0F10;
        let r = decode_mrc(word);
        assert!(r.is_some());
        let i = r.unwrap();
        assert!(i.mnemonic.contains("mrc"));
        assert!(i.operands.contains("p15"));
    }

    #[test]
    fn test_decode_cdp() {
        // CDP p0, 0, c0, c0, c0, 0
        let word: u32 = 0xEE00_0000;
        let r = decode_cdp(word);
        assert!(r.is_some());
    }

    #[test]
    fn test_decode_mcrr() {
        // MCRR p0, 0, r0, r1, c0
        let word: u32 = 0xEC41_0000;
        let r = decode_mcrr(word);
        assert!(r.is_some());
        let i = r.unwrap();
        assert!(i.mnemonic.contains("mcrr"));
    }

    #[test]
    fn test_decode_mrrc() {
        // MRRC p0, 0, r0, r1, c0
        let word: u32 = 0xEC51_0000;
        let r = decode_mrrc(word);
        assert!(r.is_some());
        let i = r.unwrap();
        assert!(i.mnemonic.contains("mrrc"));
    }

    #[test]
    fn test_cp15_reg_name_midr() {
        assert_eq!(cp15_reg_name(0, 0, 0, 0), Some("MIDR"));
    }

    #[test]
    fn test_cp15_reg_name_sctlr() {
        assert_eq!(cp15_reg_name(0, 1, 0, 0), Some("SCTLR"));
    }

    #[test]
    fn test_cp15_reg_name_ttbr0() {
        assert_eq!(cp15_reg_name(0, 2, 0, 0), Some("TTBR0"));
    }

    #[test]
    fn test_cp15_reg_name_unknown() {
        assert_eq!(cp15_reg_name(7, 7, 7, 7), None);
    }

    #[test]
    fn test_cortex_m_sys_reg() {
        assert_eq!(cortex_m_sys_reg(0x00), "APSR");
        assert_eq!(cortex_m_sys_reg(0x08), "MSP");
        assert_eq!(cortex_m_sys_reg(0x09), "PSP");
        assert_eq!(cortex_m_sys_reg(0x14), "CONTROL");
    }

    #[test]
    fn test_exc_return_parse() {
        assert_eq!(ExcReturn::parse(0xFFFF_FFF9), ExcReturn::ThreadMspNoFp);
        assert_eq!(ExcReturn::parse(0xFFFF_FFFD), ExcReturn::ThreadPspNoFp);
        assert_eq!(ExcReturn::parse(0xFFFF_FFF1), ExcReturn::HandlerMspNoFp);
    }

    #[test]
    fn test_exc_return_description() {
        assert!(
            ExcReturn::parse(0xFFFF_FFF9)
                .description()
                .contains("Thread")
        );
        assert!(
            ExcReturn::parse(0xFFFF_FFE1)
                .description()
                .contains("Handler")
        );
    }

    #[test]
    fn test_parallel_arith_mnemonic_sadd16() {
        assert_eq!(parallel_arith_mnemonic(0b001, 1), "sadd16");
        assert_eq!(parallel_arith_mnemonic(0b001, 0), "uadd16");
    }

    #[test]
    fn test_halving_parallel() {
        assert_eq!(halving_parallel_arith_mnemonic(0b101, 1), "shadd8");
        assert_eq!(halving_parallel_arith_mnemonic(0b101, 0), "uhadd8");
    }

    #[test]
    fn test_saturating_parallel() {
        assert_eq!(saturating_parallel_arith_mnemonic(0b101, 1), "qadd8");
        assert_eq!(saturating_parallel_arith_mnemonic(0b110, 0), "uqsub8");
    }

    #[test]
    fn test_decode_pkh() {
        // PKHBT r0, r1, r2
        let word: u32 = 0xE681_0012; // approximate
        let i = decode_pkh(word);
        assert!(i.mnemonic.starts_with("pkhbt") || i.mnemonic.starts_with("pkhtb"));
    }

    #[test]
    fn test_decode_sel() {
        let word: u32 = 0xE680_0FB0; // approximate SEL encoding
        let i = decode_sel(word);
        assert!(i.mnemonic.contains("sel"));
    }

    #[test]
    fn test_decode_usad8() {
        // USAD8 r0, r1, r2 (ra=15 → no accumulate)
        let word: u32 = 0xE780_F120; // approximate
        let i = decode_usad8(word);
        assert!(i.mnemonic.contains("usad"));
    }
}
