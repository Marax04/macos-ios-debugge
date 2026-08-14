//! PowerPC disassembler — full primary-opcode dispatch with major instruction
//! categories: load/store, arithmetic, logical, compare, branch, float.

use std::fmt;

// ─────────────────────────────────────────────────────────────────────────────
// Operand types
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PpcOperand {
    Reg(u8),
    FpReg(u8),
    VecReg(u8),
    CrField(u8),
    Imm(i32),
    UImm(u32),
    BranchTarget(i64),
    MemRef { base: u8, offset: i16 },
    Spr(u16),
}

impl fmt::Display for PpcOperand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Reg(r)            => write!(f, "r{r}"),
            Self::FpReg(r)          => write!(f, "f{r}"),
            Self::VecReg(r)         => write!(f, "v{r}"),
            Self::CrField(cr)       => write!(f, "cr{cr}"),
            Self::Imm(i)            => write!(f, "{i}"),
            Self::UImm(u)           => write!(f, "{u:#x}"),
            Self::BranchTarget(t)   => write!(f, "{t:#x}"),
            Self::MemRef { base, offset } => write!(f, "{offset}(r{base})"),
            Self::Spr(s)            => write!(f, "spr({s})"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Instruction
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct PpcInsn {
    pub addr: u64,
    pub raw: u32,
    pub mnemonic: String,
    pub operands: Vec<PpcOperand>,
}

impl PpcInsn {
    fn new(addr: u64, raw: u32, mnemonic: impl Into<String>, ops: Vec<PpcOperand>) -> Self {
        Self {
            addr,
            raw,
            mnemonic: mnemonic.into(),
            operands: ops,
        }
    }

    #[must_use]
    pub fn format_insn(&self) -> String {
        if self.operands.is_empty() {
            return self.mnemonic.clone();
        }
        let ops: Vec<String> = self.operands.iter().map(ToString::to_string).collect();
        format!("{:<10} {}", self.mnemonic, ops.join(", "))
    }
}

impl fmt::Display for PpcInsn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:#010x}  {:08x}  {}", self.addr, self.raw, self.format_insn())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Bit-field helpers
// ─────────────────────────────────────────────────────────────────────────────

#[inline]
const fn bits(raw: u32, hi: u32, lo: u32) -> u32 {
    let width = hi - lo + 1;
    let mask = if width >= 32 { u32::MAX } else { (1u32 << width) - 1 };
    (raw >> lo) & mask
}

#[inline]
fn ra(raw: u32) -> u8 { u8::try_from(bits(raw, 20, 16)).unwrap_or(u8::MAX) }
#[inline]
fn rb(raw: u32) -> u8 { u8::try_from(bits(raw, 15, 11)).unwrap_or(u8::MAX) }
#[inline]
fn rs(raw: u32) -> u8 { u8::try_from(bits(raw, 25, 21)).unwrap_or(u8::MAX) }  // source / rS
#[inline]
fn rt(raw: u32) -> u8 { u8::try_from(bits(raw, 25, 21)).unwrap_or(u8::MAX) }  // target / rT

#[inline]
fn simm(raw: u32) -> i32 {
    let v = (raw & 0xFFFF) as u16;
    i32::from(i16::from_ne_bytes(v.to_ne_bytes()))
}

#[inline]
const fn uimm(raw: u32) -> u32 {
    raw & 0xFFFF
}

#[inline]
fn fa(raw: u32) -> u8 { u8::try_from(bits(raw, 20, 16)).unwrap_or(u8::MAX) }
#[inline]
fn fb(raw: u32) -> u8 { u8::try_from(bits(raw, 15, 11)).unwrap_or(u8::MAX) }
#[inline]
fn fc(raw: u32) -> u8 { u8::try_from(bits(raw, 10, 6)).unwrap_or(u8::MAX) }
#[inline]
fn frt(raw: u32) -> u8 { u8::try_from(bits(raw, 25, 21)).unwrap_or(u8::MAX) }

// ─────────────────────────────────────────────────────────────────────────────
// Disassembler
// ─────────────────────────────────────────────────────────────────────────────

pub struct PpcDisassembler {
    pub big_endian: bool,
}

impl PpcDisassembler {
    #[must_use]
    pub const fn new() -> Self {
        Self { big_endian: true }
    }

    #[must_use]
    pub const fn new_little_endian() -> Self {
        Self { big_endian: false }
    }

    /// Disassemble a byte slice starting at `addr`.
    ///
    /// # Panics
    ///
    /// Panics if any 4-byte slice within `data` cannot be converted to `[u8; 4]`
    /// (this cannot happen given the loop bounds, but `try_into().unwrap()` is used).
    #[must_use]
    pub fn disassemble(&self, data: &[u8], addr: u64) -> Vec<PpcInsn> {
        let mut result = Vec::new();
        let mut i = 0usize;
        while i + 4 <= data.len() {
            let bytes = &data[i..i + 4];
            let raw = if self.big_endian {
                u32::from_be_bytes(bytes.try_into().unwrap())
            } else {
                u32::from_le_bytes(bytes.try_into().unwrap())
            };
            result.push(Self::decode_insn(raw, addr.wrapping_add(i as u64)));
            i += 4;
        }
        result
    }

    #[must_use]
    pub fn decode_insn(raw: u32, addr: u64) -> PpcInsn {
        let opcode = bits(raw, 31, 26);
        match opcode {
            // ── Integer Load ──────────────────────────────────────────
            32 => Self::decode_load(raw, addr, "lwz",  false),
            33 => Self::decode_load(raw, addr, "lwzu", false),
            34 => Self::decode_load(raw, addr, "lbz",  false),
            35 => Self::decode_load(raw, addr, "lbzu", false),
            40 => Self::decode_load(raw, addr, "lhz",  false),
            41 => Self::decode_load(raw, addr, "lhzu", false),
            42 => Self::decode_load(raw, addr, "lha",  false),
            43 => Self::decode_load(raw, addr, "lhau", false),
            58 => Self::decode_ds_load(raw, addr),

            // ── Integer Store ─────────────────────────────────────────
            36 => Self::decode_store(raw, addr, "stw"),
            37 => Self::decode_store(raw, addr, "stwu"),
            38 => Self::decode_store(raw, addr, "stb"),
            39 => Self::decode_store(raw, addr, "stbu"),
            44 => Self::decode_store(raw, addr, "sth"),
            45 => Self::decode_store(raw, addr, "sthu"),
            62 => Self::decode_ds_store(raw, addr),

            // ── Arithmetic immediate ──────────────────────────────────
            14 => PpcInsn::new(addr, raw, "addi",
                vec![PpcOperand::Reg(rt(raw)), PpcOperand::Reg(ra(raw)), PpcOperand::Imm(simm(raw))]),
            15 => PpcInsn::new(addr, raw, "addis",
                vec![PpcOperand::Reg(rt(raw)), PpcOperand::Reg(ra(raw)), PpcOperand::Imm(simm(raw))]),
            8  => PpcInsn::new(addr, raw, "subfic",
                vec![PpcOperand::Reg(rt(raw)), PpcOperand::Reg(ra(raw)), PpcOperand::Imm(simm(raw))]),
            12 => PpcInsn::new(addr, raw, "addic",
                vec![PpcOperand::Reg(rt(raw)), PpcOperand::Reg(ra(raw)), PpcOperand::Imm(simm(raw))]),
            13 => PpcInsn::new(addr, raw, "addic.",
                vec![PpcOperand::Reg(rt(raw)), PpcOperand::Reg(ra(raw)), PpcOperand::Imm(simm(raw))]),
            7  => PpcInsn::new(addr, raw, "mulli",
                vec![PpcOperand::Reg(rt(raw)), PpcOperand::Reg(ra(raw)), PpcOperand::Imm(simm(raw))]),

            // ── Logical immediate ─────────────────────────────────────
            28 => PpcInsn::new(addr, raw, "andi.",
                vec![PpcOperand::Reg(ra(raw)), PpcOperand::Reg(rs(raw)), PpcOperand::UImm(uimm(raw))]),
            29 => PpcInsn::new(addr, raw, "andis.",
                vec![PpcOperand::Reg(ra(raw)), PpcOperand::Reg(rs(raw)), PpcOperand::UImm(uimm(raw))]),
            24 => PpcInsn::new(addr, raw, "ori",
                vec![PpcOperand::Reg(ra(raw)), PpcOperand::Reg(rs(raw)), PpcOperand::UImm(uimm(raw))]),
            25 => PpcInsn::new(addr, raw, "oris",
                vec![PpcOperand::Reg(ra(raw)), PpcOperand::Reg(rs(raw)), PpcOperand::UImm(uimm(raw))]),
            26 => PpcInsn::new(addr, raw, "xori",
                vec![PpcOperand::Reg(ra(raw)), PpcOperand::Reg(rs(raw)), PpcOperand::UImm(uimm(raw))]),
            27 => PpcInsn::new(addr, raw, "xoris",
                vec![PpcOperand::Reg(ra(raw)), PpcOperand::Reg(rs(raw)), PpcOperand::UImm(uimm(raw))]),

            // ── Compare immediate ─────────────────────────────────────
            11 => PpcInsn::new(addr, raw, "cmpi",
                vec![PpcOperand::CrField(u8::try_from(bits(raw, 25, 23)).unwrap_or(u8::MAX)), PpcOperand::Reg(ra(raw)), PpcOperand::Imm(simm(raw))]),
            10 => PpcInsn::new(addr, raw, "cmpli",
                vec![PpcOperand::CrField(u8::try_from(bits(raw, 25, 23)).unwrap_or(u8::MAX)), PpcOperand::Reg(ra(raw)), PpcOperand::UImm(uimm(raw))]),

            // ── Branch ───────────────────────────────────────────────
            18 => Self::decode_b(raw, addr),
            16 => Self::decode_bc(raw, addr),
            19 => Self::decode_op19(raw, addr),

            // ── Float loads / stores ──────────────────────────────────
            48 => Self::decode_float_ls(raw, addr, "lfs"),
            49 => Self::decode_float_ls(raw, addr, "lfsu"),
            50 => Self::decode_float_ls(raw, addr, "lfd"),
            51 => Self::decode_float_ls(raw, addr, "lfdu"),
            52 => Self::decode_float_ss(raw, addr, "stfs"),
            53 => Self::decode_float_ss(raw, addr, "stfsu"),
            54 => Self::decode_float_ss(raw, addr, "stfd"),
            55 => Self::decode_float_ss(raw, addr, "stfdu"),

            // ── Float arithmetic (opcode 63) ──────────────────────────
            59 => Self::decode_fp59(raw, addr),
            63 => Self::decode_fp63(raw, addr),

            // ── Extended opcode 31 ────────────────────────────────────
            31 => Self::decode_op31(raw, addr),

            // ── Rotate/shift immediate (opcode 20-23) ─────────────────
            20 => Self::decode_rlwimi(raw, addr),
            21 => Self::decode_rlwinm(raw, addr),
            23 => Self::decode_rlwnm(raw, addr),

            _ => PpcInsn::new(addr, raw, "unknown", vec![PpcOperand::UImm(raw)]),
        }
    }

    // ── Load / store helpers ───────────────────────────────────────────────

    fn decode_load(raw: u32, addr: u64, mnem: &str, _update: bool) -> PpcInsn {
        PpcInsn::new(
            addr, raw, mnem,
            vec![
                PpcOperand::Reg(rt(raw)),
                PpcOperand::MemRef { base: ra(raw), offset: i16::try_from(simm(raw)).unwrap_or(i16::MAX) },
            ],
        )
    }

    fn decode_store(raw: u32, addr: u64, mnem: &str) -> PpcInsn {
        PpcInsn::new(
            addr, raw, mnem,
            vec![
                PpcOperand::Reg(rs(raw)),
                PpcOperand::MemRef { base: ra(raw), offset: i16::try_from(simm(raw)).unwrap_or(i16::MAX) },
            ],
        )
    }

    fn decode_ds_load(raw: u32, addr: u64) -> PpcInsn {
        let ds_type = raw & 0x3;
        let mnem = match ds_type { 0 => "ld", 1 => "ldu", 2 => "lwa", _ => "ld?" };
        // DS-form: bits[15:2] are the signed displacement, scaled by 4 (bits[1:0] are the type).
        // Extract sign-extended 14-bit field and multiply by 4.
        let ds_field = raw.cast_signed() << 16 >> 18; // sign-extended 14-bit value
        let offset = i16::try_from(ds_field * 4).unwrap_or(i16::MAX);
        PpcInsn::new(addr, raw, mnem, vec![
            PpcOperand::Reg(rt(raw)),
            PpcOperand::MemRef { base: ra(raw), offset },
        ])
    }

    fn decode_ds_store(raw: u32, addr: u64) -> PpcInsn {
        let ds_type = raw & 0x3;
        let mnem = match ds_type { 0 => "std", 1 => "stdu", _ => "std?" };
        // DS-form: bits[15:2] are the signed displacement, scaled by 4.
        let ds_field = raw.cast_signed() << 16 >> 18;
        let offset = i16::try_from(ds_field * 4).unwrap_or(i16::MAX);
        PpcInsn::new(addr, raw, mnem, vec![
            PpcOperand::Reg(rs(raw)),
            PpcOperand::MemRef { base: ra(raw), offset },
        ])
    }

    // ── Branch helpers ─────────────────────────────────────────────────────

    fn decode_b(raw: u32, addr: u64) -> PpcInsn {
        let li = (raw << 6).cast_signed() >> 6; // sign-extend bits 25:2
        let li_shifted = i64::from((li >> 2) << 2); // clear lower 2 bits
        let aa = (raw & 2) != 0;
        let lk = (raw & 1) != 0;
        let mnem = match (aa, lk) {
            (false, false) => "b",
            (false, true)  => "bl",
            (true, false)  => "ba",
            (true, true)   => "bla",
        };
        let target = if aa {
            li_shifted
        } else {
            addr.wrapping_add_signed(li_shifted).cast_signed()
        };
        PpcInsn::new(addr, raw, mnem, vec![PpcOperand::BranchTarget(target)])
    }

    fn decode_bc(raw: u32, addr: u64) -> PpcInsn {
        let bo = u8::try_from(bits(raw, 25, 21)).unwrap_or(u8::MAX);
        let bi = u8::try_from(bits(raw, 20, 16)).unwrap_or(u8::MAX);
        let bd = i64::from((raw & 0xFFFC).cast_signed() << 16 >> 16);
        let aa = (raw & 2) != 0;
        let lk = (raw & 1) != 0;
        let mnem = match (aa, lk) {
            (false, false) => "bc",
            (false, true)  => "bcl",
            (true, false)  => "bca",
            (true, true)   => "bcla",
        };
        let target = if aa { bd } else { addr.wrapping_add_signed(bd).cast_signed() };
        PpcInsn::new(addr, raw, mnem, vec![
            PpcOperand::UImm(u32::from(bo)),
            PpcOperand::UImm(u32::from(bi)),
            PpcOperand::BranchTarget(target),
        ])
    }

    fn decode_op19(raw: u32, addr: u64) -> PpcInsn {
        let xo = bits(raw, 10, 1);
        let lk = (raw & 1) != 0;
        let bo = u8::try_from(bits(raw, 25, 21)).unwrap_or(u8::MAX);
        let bi = u8::try_from(bits(raw, 20, 16)).unwrap_or(u8::MAX);
        match xo {
            16 => PpcInsn::new(addr, raw, if lk { "bclrl" } else { "bclr" }, vec![
                PpcOperand::UImm(u32::from(bo)), PpcOperand::UImm(u32::from(bi))]),
            528 => PpcInsn::new(addr, raw, if lk { "bcctrl" } else { "bcctr" }, vec![
                PpcOperand::UImm(u32::from(bo)), PpcOperand::UImm(u32::from(bi))]),
            _ => PpcInsn::new(addr, raw, "op19_unk", vec![PpcOperand::UImm(xo)]),
        }
    }

    // ── Extended opcode 31 ─────────────────────────────────────────────────

    fn decode_op31(raw: u32, addr: u64) -> PpcInsn {
        let xo = bits(raw, 10, 1);
        let rc = (raw & 1) != 0;
        let oe = bits(raw, 10, 10) != 0;
        match xo {
            // Compare
            0   => PpcInsn::new(addr, raw, "cmp", vec![
                PpcOperand::CrField(u8::try_from(bits(raw, 25, 23)).unwrap_or(u8::MAX)), PpcOperand::Reg(ra(raw)), PpcOperand::Reg(rb(raw))]),
            32  => PpcInsn::new(addr, raw, "cmpl", vec![
                PpcOperand::CrField(u8::try_from(bits(raw, 25, 23)).unwrap_or(u8::MAX)), PpcOperand::Reg(ra(raw)), PpcOperand::Reg(rb(raw))]),
            // Arithmetic
            266 => Self::rr_insn(addr, raw, if oe { "addo" } else { "add" }, rc),
            40  => Self::rr_insn(addr, raw, if oe { "subfo" } else { "subf" }, rc),
            235 => Self::rr_insn(addr, raw, if oe { "mullwo" } else { "mullw" }, rc),
            75  => Self::rr_insn(addr, raw, "mulhw",  rc),
            459 => Self::rr_insn(addr, raw, if oe { "divwo" }  else { "divw" },  rc),
            491 => Self::rr_insn(addr, raw, if oe { "divwuo" } else { "divwu" }, rc),
            104 => PpcInsn::new(addr, raw, if rc { "nego." } else { "neg" }, vec![
                PpcOperand::Reg(rt(raw)), PpcOperand::Reg(ra(raw))]),
            // Logical
            28  => Self::ra_rs_rb_insn(addr, raw, if rc { "and." }  else { "and" }),
            444 => Self::ra_rs_rb_insn(addr, raw, if rc { "or." }   else { "or" }),
            316 => Self::ra_rs_rb_insn(addr, raw, if rc { "xor." }  else { "xor" }),
            476 => Self::ra_rs_rb_insn(addr, raw, if rc { "nand." } else { "nand" }),
            124 => Self::ra_rs_rb_insn(addr, raw, if rc { "nor." }  else { "nor" }),
            // Shift
            24  => Self::ra_rs_rb_insn(addr, raw, if rc { "slw." }  else { "slw" }),
            536 => Self::ra_rs_rb_insn(addr, raw, if rc { "srw." }  else { "srw" }),
            792 => Self::ra_rs_rb_insn(addr, raw, if rc { "sraw." } else { "sraw" }),
            // Load/store indexed
            23  => PpcInsn::new(addr, raw, "lwzx", vec![
                PpcOperand::Reg(rt(raw)), PpcOperand::Reg(ra(raw)), PpcOperand::Reg(rb(raw))]),
            87  => PpcInsn::new(addr, raw, "lbzx", vec![
                PpcOperand::Reg(rt(raw)), PpcOperand::Reg(ra(raw)), PpcOperand::Reg(rb(raw))]),
            279 => PpcInsn::new(addr, raw, "lhzx", vec![
                PpcOperand::Reg(rt(raw)), PpcOperand::Reg(ra(raw)), PpcOperand::Reg(rb(raw))]),
            151 => PpcInsn::new(addr, raw, "stwx", vec![
                PpcOperand::Reg(rs(raw)), PpcOperand::Reg(ra(raw)), PpcOperand::Reg(rb(raw))]),
            215 => PpcInsn::new(addr, raw, "stbx", vec![
                PpcOperand::Reg(rs(raw)), PpcOperand::Reg(ra(raw)), PpcOperand::Reg(rb(raw))]),
            // SPR
            339 => PpcInsn::new(addr, raw, "mfspr", vec![
                PpcOperand::Reg(rt(raw)), PpcOperand::Spr(decode_spr(raw))]),
            467 => PpcInsn::new(addr, raw, "mtspr", vec![
                PpcOperand::Spr(decode_spr(raw)), PpcOperand::Reg(rs(raw))]),
            // Sync / misc
            598 => PpcInsn::new(addr, raw, "sync",  vec![]),
            854 => PpcInsn::new(addr, raw, "eieio", vec![]),
            _   => PpcInsn::new(addr, raw, "op31_unk", vec![PpcOperand::UImm(xo)]),
        }
    }

    fn rr_insn(addr: u64, raw: u32, mnem: &str, rc: bool) -> PpcInsn {
        let m = if rc { format!("{mnem}.") } else { mnem.to_string() };
        PpcInsn::new(addr, raw, m, vec![
            PpcOperand::Reg(rt(raw)), PpcOperand::Reg(ra(raw)), PpcOperand::Reg(rb(raw)),
        ])
    }

    fn ra_rs_rb_insn(addr: u64, raw: u32, mnem: &str) -> PpcInsn {
        PpcInsn::new(addr, raw, mnem, vec![
            PpcOperand::Reg(ra(raw)), PpcOperand::Reg(rs(raw)), PpcOperand::Reg(rb(raw)),
        ])
    }

    // ── Float helpers ──────────────────────────────────────────────────────

    fn decode_float_ls(raw: u32, addr: u64, mnem: &str) -> PpcInsn {
        PpcInsn::new(addr, raw, mnem, vec![
            PpcOperand::FpReg(frt(raw)),
            PpcOperand::MemRef { base: ra(raw), offset: i16::try_from(simm(raw)).unwrap_or(i16::MAX) },
        ])
    }

    fn decode_float_ss(raw: u32, addr: u64, mnem: &str) -> PpcInsn {
        PpcInsn::new(addr, raw, mnem, vec![
            PpcOperand::FpReg(frt(raw)),
            PpcOperand::MemRef { base: ra(raw), offset: i16::try_from(simm(raw)).unwrap_or(i16::MAX) },
        ])
    }

    fn decode_fp59(raw: u32, addr: u64) -> PpcInsn {
        let xo = bits(raw, 5, 1);
        let rc = (raw & 1) != 0;
        match xo {
            21 => Self::fp_rr(addr, raw, if rc { "fadds." } else { "fadds" }),
            20 => Self::fp_rr(addr, raw, if rc { "fsubs." } else { "fsubs" }),
            25 => Self::fp_rr(addr, raw, if rc { "fmuls." } else { "fmuls" }),
            18 => Self::fp_rr(addr, raw, if rc { "fdivs." } else { "fdivs" }),
            _  => PpcInsn::new(addr, raw, "fp59_unk", vec![PpcOperand::UImm(xo)]),
        }
    }

    fn decode_fp63(raw: u32, addr: u64) -> PpcInsn {
        let xo = bits(raw, 5, 1);
        let rc = (raw & 1) != 0;
        match xo {
            21 => Self::fp_rr(addr, raw, if rc { "fadd." }  else { "fadd" }),
            20 => Self::fp_rr(addr, raw, if rc { "fsub." }  else { "fsub" }),
            25 => Self::fp_rr(addr, raw, if rc { "fmul." }  else { "fmul" }),
            18 => Self::fp_rr(addr, raw, if rc { "fdiv." }  else { "fdiv" }),
            72 => PpcInsn::new(addr, raw, if rc { "fmr." } else { "fmr" }, vec![
                PpcOperand::FpReg(frt(raw)), PpcOperand::FpReg(fb(raw))]),
            12 => PpcInsn::new(addr, raw, if rc { "frsp." } else { "frsp" }, vec![
                PpcOperand::FpReg(frt(raw)), PpcOperand::FpReg(fb(raw))]),
            14 => PpcInsn::new(addr, raw, if rc { "fctiw." }  else { "fctiw" },  vec![
                PpcOperand::FpReg(frt(raw)), PpcOperand::FpReg(fb(raw))]),
            15 => PpcInsn::new(addr, raw, if rc { "fctiwz." } else { "fctiwz" }, vec![
                PpcOperand::FpReg(frt(raw)), PpcOperand::FpReg(fb(raw))]),
            // Fused multiply-add family — A-form, uses the FRC field.
            29 => Self::fp_rrr(addr, raw, if rc { "fmadd." }  else { "fmadd" }),
            28 => Self::fp_rrr(addr, raw, if rc { "fmsub." }  else { "fmsub" }),
            31 => Self::fp_rrr(addr, raw, if rc { "fnmadd." } else { "fnmadd" }),
            30 => Self::fp_rrr(addr, raw, if rc { "fnmsub." } else { "fnmsub" }),
            _  => PpcInsn::new(addr, raw, "fp63_unk", vec![PpcOperand::UImm(xo)]),
        }
    }

    fn fp_rr(addr: u64, raw: u32, mnem: &str) -> PpcInsn {
        PpcInsn::new(addr, raw, mnem, vec![
            PpcOperand::FpReg(frt(raw)), PpcOperand::FpReg(fa(raw)), PpcOperand::FpReg(fb(raw)),
        ])
    }

    /// A-form FP triple-operand: FRT, FRA, FRC, FRB (e.g. `fmadd`).
    fn fp_rrr(addr: u64, raw: u32, mnem: &str) -> PpcInsn {
        PpcInsn::new(addr, raw, mnem, vec![
            PpcOperand::FpReg(frt(raw)),
            PpcOperand::FpReg(fa(raw)),
            PpcOperand::FpReg(fc(raw)),
            PpcOperand::FpReg(fb(raw)),
        ])
    }

    // ── Rotate ────────────────────────────────────────────────────────────

    fn decode_rlwimi(raw: u32, addr: u64) -> PpcInsn {
        let sh = u8::try_from(bits(raw, 15, 11)).unwrap_or(u8::MAX);
        let mb = u8::try_from(bits(raw, 10, 6)).unwrap_or(u8::MAX);
        let me = u8::try_from(bits(raw, 5, 1)).unwrap_or(u8::MAX);
        let rc = (raw & 1) != 0;
        PpcInsn::new(addr, raw, if rc { "rlwimi." } else { "rlwimi" }, vec![
            PpcOperand::Reg(ra(raw)), PpcOperand::Reg(rs(raw)),
            PpcOperand::UImm(u32::from(sh)), PpcOperand::UImm(u32::from(mb)), PpcOperand::UImm(u32::from(me)),
        ])
    }

    fn decode_rlwinm(raw: u32, addr: u64) -> PpcInsn {
        let sh = u8::try_from(bits(raw, 15, 11)).unwrap_or(u8::MAX);
        let mb = u8::try_from(bits(raw, 10, 6)).unwrap_or(u8::MAX);
        let me = u8::try_from(bits(raw, 5, 1)).unwrap_or(u8::MAX);
        let rc = (raw & 1) != 0;
        PpcInsn::new(addr, raw, if rc { "rlwinm." } else { "rlwinm" }, vec![
            PpcOperand::Reg(ra(raw)), PpcOperand::Reg(rs(raw)),
            PpcOperand::UImm(u32::from(sh)), PpcOperand::UImm(u32::from(mb)), PpcOperand::UImm(u32::from(me)),
        ])
    }

    fn decode_rlwnm(raw: u32, addr: u64) -> PpcInsn {
        let mb = u8::try_from(bits(raw, 10, 6)).unwrap_or(u8::MAX);
        let me = u8::try_from(bits(raw, 5, 1)).unwrap_or(u8::MAX);
        let rc = (raw & 1) != 0;
        PpcInsn::new(addr, raw, if rc { "rlwnm." } else { "rlwnm" }, vec![
            PpcOperand::Reg(ra(raw)), PpcOperand::Reg(rs(raw)), PpcOperand::Reg(rb(raw)),
            PpcOperand::UImm(u32::from(mb)), PpcOperand::UImm(u32::from(me)),
        ])
    }
}

fn decode_spr(raw: u32) -> u16 {
    let spr5_10 = bits(raw, 20, 16);
    let spr0_4  = bits(raw, 15, 11);
    u16::try_from((spr5_10 << 5) | spr0_4).unwrap_or(u16::MAX)
}

impl Default for PpcDisassembler {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn dis() -> PpcDisassembler { PpcDisassembler::new() }

    fn enc_be(raw: u32) -> [u8; 4] { raw.to_be_bytes() }

    #[test]
    fn test_decode_addi() {
        // addi r3, r1, 16  → opcode=14, rt=3, ra=1, simm=16
        let raw: u32 = (14 << 26) | (3 << 21) | (1 << 16) | 16;
        let insn = PpcDisassembler::decode_insn(raw, 0x1000);
        assert_eq!(insn.mnemonic, "addi");
        assert_eq!(insn.operands[0], PpcOperand::Reg(3));
        assert_eq!(insn.operands[1], PpcOperand::Reg(1));
        assert_eq!(insn.operands[2], PpcOperand::Imm(16));
    }

    #[test]
    fn test_decode_lwz() {
        // lwz r4, 8(r1)  → opcode=32, rt=4, ra=1, d=8
        let raw: u32 = (32 << 26) | (4 << 21) | (1 << 16) | 8;
        let insn = PpcDisassembler::decode_insn(raw, 0);
        assert_eq!(insn.mnemonic, "lwz");
        assert_eq!(insn.operands[0], PpcOperand::Reg(4));
        assert_eq!(insn.operands[1], PpcOperand::MemRef { base: 1, offset: 8 });
    }

    #[test]
    fn test_decode_stw() {
        let raw: u32 = (36 << 26) | (3 << 21) | (1 << 16) | 0xFFFC; // offset -4 (FFFC signed)
        let insn = PpcDisassembler::decode_insn(raw, 0);
        assert_eq!(insn.mnemonic, "stw");
        assert!(matches!(insn.operands[1], PpcOperand::MemRef { base: 1, .. }));
    }

    #[test]
    fn test_decode_ori_nop() {
        // ori 0,0,0 is the canonical NOP
        let raw: u32 = 24 << 26;
        let insn = PpcDisassembler::decode_insn(raw, 0);
        assert_eq!(insn.mnemonic, "ori");
    }

    #[test]
    fn test_decode_b() {
        // b 0x100 (from addr 0): LI = 0x40 (in bits 25:2) → raw = opcode18 | (0x40 << 2)
        let raw: u32 = (18 << 26) | (0x100 & !3);
        let insn = PpcDisassembler::decode_insn(raw, 0);
        assert_eq!(insn.mnemonic, "b");
        assert!(matches!(insn.operands[0], PpcOperand::BranchTarget(0x100)));
    }

    #[test]
    fn test_decode_bl() {
        // bl (LK=1)
        let raw: u32 = (18 << 26) | (0x100 & !3) | 1;
        let insn = PpcDisassembler::decode_insn(raw, 0);
        assert_eq!(insn.mnemonic, "bl");
    }

    #[test]
    fn test_decode_bc() {
        let raw: u32 = (16 << 26) | (20 << 21) | 8; // always-true bc +8
        let insn = PpcDisassembler::decode_insn(raw, 0x100);
        assert_eq!(insn.mnemonic, "bc");
        assert!(matches!(insn.operands[2], PpcOperand::BranchTarget(0x108)));
    }

    #[test]
    fn test_decode_add() {
        // add r5, r3, r4  (xo=266, no Rc, no OE)
        let xo: u32 = 266 << 1;
        let raw: u32 = (31 << 26) | (5 << 21) | (3 << 16) | (4 << 11) | xo;
        let insn = PpcDisassembler::decode_insn(raw, 0);
        assert_eq!(insn.mnemonic, "add");
    }

    #[test]
    fn test_decode_and_rc() {
        let xo: u32 = (28 << 1) | 1; // xo=28, Rc=1
        let raw: u32 = (31 << 26) | (3 << 21) | (4 << 16) | (5 << 11) | xo;
        let insn = PpcDisassembler::decode_insn(raw, 0);
        assert_eq!(insn.mnemonic, "and.");
    }

    #[test]
    fn test_decode_cmp() {
        // cmp cr0, r3, r4 → opcode=31 xo=0
        let raw: u32 = (31 << 26) | (3 << 16) | (4 << 11); // xo=0
        let insn = PpcDisassembler::decode_insn(raw, 0);
        assert_eq!(insn.mnemonic, "cmp");
    }

    #[test]
    fn test_decode_mfspr_lr() {
        // mfspr r0, LR (SPR=8 → spr5_10=0 spr0_4=8)
        let spr_field: u32 = 8 << 11; // spr5_10=0, spr0_4=8
        let xo: u32 = 339 << 1;
        let raw: u32 = (31 << 26) | spr_field | xo;
        let insn = PpcDisassembler::decode_insn(raw, 0);
        assert_eq!(insn.mnemonic, "mfspr");
    }

    #[test]
    fn test_decode_rlwinm() {
        // rlwinm r3, r4, 2, 0, 29  → opcode=21
        let raw: u32 = (21 << 26) | (4 << 21) | (3 << 16) | (2 << 11) | (29 << 1);
        let insn = PpcDisassembler::decode_insn(raw, 0);
        assert_eq!(insn.mnemonic, "rlwinm");
    }

    #[test]
    fn test_decode_fadd() {
        // fadd f1, f2, f3  (opcode=63, xo=21, no Rc)
        let xo: u32 = 21 << 1;
        let raw: u32 = (63 << 26) | (1 << 21) | (2 << 16) | (3 << 11) | xo;
        let insn = PpcDisassembler::decode_insn(raw, 0);
        assert_eq!(insn.mnemonic, "fadd");
    }

    #[test]
    fn test_decode_lfd() {
        // lfd f1, 0(r1)  opcode=50
        let raw: u32 = (50 << 26) | (1 << 21) | (1 << 16);
        let insn = PpcDisassembler::decode_insn(raw, 0);
        assert_eq!(insn.mnemonic, "lfd");
        assert_eq!(insn.operands[0], PpcOperand::FpReg(1));
    }

    #[test]
    fn test_disassemble_slice() {
        let addis: u32 = (15 << 26) | (3 << 21) | 0x1234;
        let addi: u32  = (14 << 26) | (3 << 21) | (3 << 16) | 0x5678;
        let mut data = Vec::new();
        data.extend_from_slice(&enc_be(addis));
        data.extend_from_slice(&enc_be(addi));
        let insns = dis().disassemble(&data, 0x4000);
        assert_eq!(insns.len(), 2);
        assert_eq!(insns[0].mnemonic, "addis");
        assert_eq!(insns[1].mnemonic, "addi");
        assert_eq!(insns[0].addr, 0x4000);
        assert_eq!(insns[1].addr, 0x4004);
    }

    #[test]
    fn test_format_insn() {
        let raw: u32 = (14 << 26) | (3 << 21) | (1 << 16) | 8;
        let insn = PpcDisassembler::decode_insn(raw, 0);
        let s = insn.format_insn();
        assert!(s.contains("addi"));
        assert!(s.contains("r3"));
    }
}
