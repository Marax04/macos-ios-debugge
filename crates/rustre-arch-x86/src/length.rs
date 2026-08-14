//! Fast x86 instruction length decoder.
//!
//! Given a byte slice, determines the byte length of the first instruction
//! without full semantic decode. Useful for streaming over code pages.

use crate::modrm::ModRm;

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// The maximum plausible x86 instruction length (Intel SDM limit is 15 bytes).
pub const MAX_INSTR_LEN: usize = 15;

/// Error returned when an instruction length cannot be determined.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub enum LengthError {
    /// Byte slice is empty or too short.
    TruncatedStream,
    /// Opcode is not known / invalid.
    UnknownOpcode,
}

impl core::fmt::Display for LengthError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::TruncatedStream => write!(f, "truncated instruction stream"),
            Self::UnknownOpcode => write!(f, "unknown or invalid opcode"),
        }
    }
}

/// Compute the byte length of the first x86 instruction starting at `bytes`.
///
/// `bits` must be 16, 32, or 64.
///
/// # Errors
///
/// Returns [`LengthError::TruncatedStream`] if `bytes` is too short to contain
/// a complete instruction, or [`LengthError::UnknownOpcode`] for unrecognised
/// opcodes.
pub fn instr_length(bytes: &[u8], bits: u32) -> Result<usize, LengthError> {
    if bytes.is_empty() {
        return Err(LengthError::TruncatedStream);
    }
    let is_64 = bits == 64;

    // --- consume legacy prefixes + REX (prefix-aware: operand/address size and
    //     REX.W change immediate and offset widths) ---
    let ps = crate::prefix::PrefixSet::consume(bytes, is_64);
    let mut pos = ps.count;
    if pos >= bytes.len() {
        return Err(LengthError::TruncatedStream);
    }

    // Effective operand size flips to 16-bit either in 16-bit mode or under a
    // 0x66 override (but not both). REX.W forces 64-bit operand size and takes
    // precedence over 0x66, so it never yields a 16-bit immediate.
    let opsize16 = !ps.rex.w && ((bits == 16) ^ ps.op_size);
    let ctx = LenCtx {
        // "z" immediate: imm16 vs imm32 (never imm64).
        immz: if opsize16 { 2 } else { 4 },
        // "o" immediate (MOV reg,imm): full operand size; REX.W promotes to 8.
        io: if is_64 && ps.rex.w {
            8
        } else if opsize16 {
            2
        } else {
            4
        },
        // moffs offset width = address size.
        moffs: if is_64 {
            if ps.addr_size { 4 } else { 8 }
        } else if bits == 32 {
            if ps.addr_size { 2 } else { 4 }
        } else if ps.addr_size {
            4
        } else {
            2
        },
        // Near relative branch: 64-bit forces rel32; otherwise operand-size.
        rel: if is_64 {
            4
        } else if opsize16 {
            2
        } else {
            4
        },
    };

    let lead = bytes[pos];

    // --- VEX / EVEX ---
    // In 16/32-bit mode C4/C5/62 are LES/LDS/BOUND unless the next byte's top
    // two bits are 11 (an invalid ModRM for those forms), which re-purposes the
    // byte as a VEX/EVEX prefix.
    let vex_ok = |bytes: &[u8], pos: usize| {
        is_64 || bytes.get(pos + 1).is_some_and(|b| b & 0xC0 == 0xC0)
    };
    if lead == 0xC5 && vex_ok(bytes, pos) {
        // 2-byte VEX: C5 P0 OPCODE — opcode map is the implied 0F map.
        let opcode = *bytes.get(pos + 2).ok_or(LengthError::TruncatedStream)?;
        return modrm_and_imm(bytes, pos + 3, 0, vex_imm_bytes(1, opcode));
    }
    if lead == 0xC4 && vex_ok(bytes, pos) {
        // 3-byte VEX: C4 P0 P1 OPCODE — opcode map in P0[4:0].
        let map = bytes.get(pos + 1).ok_or(LengthError::TruncatedStream)? & 0x1F;
        let opcode = *bytes.get(pos + 3).ok_or(LengthError::TruncatedStream)?;
        return modrm_and_imm(bytes, pos + 4, 0, vex_imm_bytes(map, opcode));
    }
    if lead == 0x62 && vex_ok(bytes, pos) {
        // EVEX: 62 P0 P1 P2 OPCODE — opcode map in P0[2:0].
        let map = bytes.get(pos + 1).ok_or(LengthError::TruncatedStream)? & 0x07;
        let opcode = *bytes.get(pos + 4).ok_or(LengthError::TruncatedStream)?;
        return modrm_and_imm(bytes, pos + 5, 0, vex_imm_bytes(map, opcode));
    }

    // --- 2-byte escape 0F ---
    if lead == 0x0F {
        pos += 1; // consume 0F
        if pos >= bytes.len() {
            return Err(LengthError::TruncatedStream);
        }
        let op2 = bytes[pos];
        pos += 1; // consume opcode

        // 3-byte escapes
        if op2 == 0x38 || op2 == 0x3A {
            if pos >= bytes.len() {
                return Err(LengthError::TruncatedStream);
            }
            let _op3 = bytes[pos];
            pos += 1;
            // 0F 3A always has an imm8; 0F 38 generally does not
            let has_imm = op2 == 0x3A;
            return modrm_and_imm(bytes, pos, 0, usize::from(has_imm));
        }

        return length_2byte(bytes, pos, op2, &ctx);
    }

    // --- 1-byte opcode ---
    pos += 1; // consume opcode
    length_1byte(bytes, pos, lead, &ctx)
}

/// Prefix-derived operand/offset widths threaded into the opcode length tables.
#[derive(Debug, Clone, Copy)]
struct LenCtx {
    /// `z`-sized immediate (imm16 vs imm32).
    immz: usize,
    /// `o`-sized immediate for `MOV reg, imm` (operand size; REX.W ⇒ 8).
    io: usize,
    /// `moffs` offset width (address size).
    moffs: usize,
    /// Near relative-branch displacement width.
    rel: usize,
}

/// For the `F6`/`F7` group, the immediate exists only for the `/0` and `/1`
/// (`TEST`) encodings — the `ModRM` reg field selects the operation.
fn f6f7_has_imm(bytes: &[u8], pos: usize) -> bool {
    bytes.get(pos).is_some_and(|b| {
        let reg = (b >> 3) & 7;
        reg == 0 || reg == 1
    })
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Immediate byte count for a VEX/EVEX-encoded opcode, keyed by opcode map.
fn vex_imm_bytes(map: u8, opcode: u8) -> usize {
    match map {
        // 0F map: shift-by-imm group (70-73), CMPccPS/PD/SS/SD (C2),
        // PINSRW/PEXTRW (C4/C5), SHUFPS/PD (C6).
        1 => usize::from(matches!(opcode, 0x70..=0x73 | 0xC2 | 0xC4..=0xC6)),
        // 0F 3A map: every instruction carries an imm8.
        3 => 1,
        // 0F 38 map (and others): no immediate.
        _ => 0,
    }
}

/// Advance `pos` past the `ModRM` + SIB + displacement bytes, then add `imm_bytes`.
fn modrm_and_imm(bytes: &[u8], pos: usize, _op: u8, imm: usize) -> Result<usize, LengthError> {
    if pos >= bytes.len() {
        return Err(LengthError::TruncatedStream);
    }
    let modrm = ModRm::decode(bytes[pos]);
    let mut p = pos + 1;

    if !modrm.is_reg() {
        if modrm.has_sib() {
            if p >= bytes.len() {
                return Err(LengthError::TruncatedStream);
            }
            let sib_byte = bytes[p];
            p += 1;
            let sib = crate::modrm::Sib::decode(sib_byte);
            if sib.base_is_disp_only(modrm.mode) {
                p += 4; // disp32
            } else {
                p += modrm.disp_size();
            }
        } else {
            p += modrm.disp_size();
        }
    }
    p += imm;
    if p > bytes.len() {
        return Err(LengthError::TruncatedStream);
    }
    Ok(p)
}

/// Determine length contribution for a 1-byte opcode (opcode already consumed,
/// `pos` points past it). `ctx` carries the prefix-derived operand widths.
fn length_1byte(bytes: &[u8], pos: usize, op: u8, ctx: &LenCtx) -> Result<usize, LengthError> {
    // Categorise by opcode
    let len = match op {
        // ZO (no operands)
        0x90 | 0x98 | 0x99 | 0x9B..=0x9F | 0xC3 | 0xCB | 0xCC | 0xCF
        | 0xD7 | 0xF1 | 0xF4 | 0xF5 | 0xF8..=0xFD
        // Push/pop segment — ZO
        | 0x06 | 0x07 | 0x0E | 0x16 | 0x17 | 0x1E | 0x1F
        // Push/pop r16/r32/r64
        | 0x50..=0x5F
        // XCHG rAX,r
        | 0x91..=0x97
        // PUSHA/POPA
        | 0x60 | 0x61
        // String ops
        | 0xA4..=0xA7 | 0xAA..=0xAF
        // IN/OUT DX / lock/rep standalone
        | 0xEC..=0xEF | 0xF0 | 0xF2 | 0xF3 => pos,
        // imm8 only
        0x04 | 0x0C | 0x14 | 0x1C | 0x24 | 0x2C | 0x34 | 0x3C
        | 0x6A | 0xA8 | 0xCD | 0xD4 | 0xD5 | 0xE0..=0xE3 | 0xE4..=0xE7
        | 0xEB => {
            pos + 1
        }
        // imm16 (RET imm16)
        0xC2 | 0xCA => pos + 2,
        // operand-size immediate ("z": imm16/imm32) — ALU eAX,imm / PUSH imm / TEST eAX,imm
        0x05 | 0x0D | 0x15 | 0x1D | 0x25 | 0x2D | 0x35 | 0x3D
        | 0x68 | 0xA9 => pos + ctx.immz,
        // near relative CALL/JMP (rel16/rel32, 64-bit forces rel32)
        0xE8 | 0xE9 => pos + ctx.rel,
        // imm8 rel (Jcc rel8)
        0x70..=0x7F => pos + 1,
        // Far pointer ptr16:16 / ptr16:32 (offset is operand-size + 2-byte selector)
        0xEA | 0x9A => pos + ctx.immz + 2,
        // MOV reg,imm8 (B0–B7)
        0xB0..=0xB7 => pos + 1,
        // MOV reg,imm (B8–BF): operand-size immediate; REX.W ⇒ imm64
        0xB8..=0xBF => pos + ctx.io,
        // ENTER iw, ib
        0xC8 => pos + 3,
        // MOV AL/eAX,moffs and back — offset is address-size wide
        0xA0..=0xA3 => pos + ctx.moffs,
        // Grp1 rm, imm8 (80/82/83 sign-extend an imm8)
        0x80 | 0x82 | 0x83 => modrm_and_imm(bytes, pos, op, 1)?,
        // Grp1 rm, imm-z
        0x81 => modrm_and_imm(bytes, pos, op, ctx.immz)?,
        // Grp2 rm, 1 or CL (no immediate)
        0xD0..=0xD3 => modrm_and_imm(bytes, pos, op, 0)?,
        // Grp2 rm, imm8
        0xC0 | 0xC1 => modrm_and_imm(bytes, pos, op, 1)?,
        // MOV rm, imm8
        0xC6 => modrm_and_imm(bytes, pos, op, 1)?,
        // MOV rm, imm-z
        0xC7 => modrm_and_imm(bytes, pos, op, ctx.immz)?,
        // Grp3: immediate only for /0,/1 (TEST) — imm8 for F6, imm-z for F7
        0xF6 => modrm_and_imm(bytes, pos, op, usize::from(f6f7_has_imm(bytes, pos)))?,
        0xF7 => {
            let imm = if f6f7_has_imm(bytes, pos) { ctx.immz } else { 0 };
            modrm_and_imm(bytes, pos, op, imm)?
        }
        // Grp4 / Grp5 (no immediate)
        0xFE | 0xFF => modrm_and_imm(bytes, pos, op, 0)?,
        // IMUL r, rm, imm-z (69) and IMUL r, rm, imm8 (6B)
        0x69 => modrm_and_imm(bytes, pos, op, ctx.immz)?,
        0x6B => modrm_and_imm(bytes, pos, op, 1)?,
        // 0x8F is the AMD XOP prefix (not POP r/m) when the following byte's
        // 5-bit map field is ≥ 8. XOP length decoding is out of scope; report it
        // as unknown rather than mis-measuring it as a POP.
        0x8F if bytes.get(pos).is_some_and(|b| (b & 0x1f) >= 8) => {
            return Err(LengthError::UnknownOpcode);
        }
        // x87 FPU escapes (D8–DF): ModRM operand, no immediate
        0xD8..=0xDF => modrm_and_imm(bytes, pos, op, 0)?,
        // Most ModRM instructions with no immediate
        0x00..=0x03 | 0x08..=0x0B | 0x10..=0x13 | 0x18..=0x1B
        | 0x20..=0x23 | 0x28..=0x2B | 0x30..=0x33 | 0x38..=0x3B
        | 0x84..=0x8F => modrm_and_imm(bytes, pos, op, 0)?,
        _ => return Err(LengthError::UnknownOpcode),
    };
    if len > bytes.len() {
        return Err(LengthError::TruncatedStream);
    }
    Ok(len)
}

/// Determine length for a 2-byte opcode (0F xx), where `op2` is the second
/// byte and `pos` points past it.
fn length_2byte(bytes: &[u8], pos: usize, op2: u8, ctx: &LenCtx) -> Result<usize, LengthError> {
    let len = match op2 {
        // ZO system instructions
        0x05 | 0x06 | 0x07 | 0x08 | 0x09 | 0x0B | 0x0E | 0x0F | 0x30 | 0x31 | 0x32 | 0x33
        | 0x34 | 0x35 | 0x37 | 0x77 | 0xAA => pos,
        // NOP r/m (ModRM, no imm)
        0x0D | 0x18..=0x1F => modrm_and_imm(bytes, pos, op2, 0)?,
        // MOV to/from CR/DR (0F 20–23): the ModRM mod field is ignored — the
        // operand is always a register, so there is never a displacement/SIB.
        0x20..=0x23 => {
            if pos >= bytes.len() {
                return Err(LengthError::TruncatedStream);
            }
            pos + 1
        }
        // SSE moves, no imm
        0x10..=0x17
        | 0x28..=0x2D
        | 0x51..=0x5F
        | 0x60..=0x6F
        | 0x74..=0x76
        | 0x7C
        | 0x7D
        | 0x7E
        | 0x7F
        | 0xD0..=0xEF
        | 0xF0..=0xFE => modrm_and_imm(bytes, pos, op2, 0)?,
        // UCOMISS / COMISS
        0x2E | 0x2F => modrm_and_imm(bytes, pos, op2, 0)?,
        // CMOVcc / SETcc
        0x40..=0x4F => modrm_and_imm(bytes, pos, op2, 0)?,
        0x90..=0x9F => modrm_and_imm(bytes, pos, op2, 0)?,
        // Jcc rel16/rel32 (64-bit forces rel32)
        0x80..=0x8F => pos + ctx.rel,
        // Grp ops with imm8
        0x70..=0x73 => modrm_and_imm(bytes, pos, op2, 1)?,
        // SHLD/SHRD imm8
        0xA4 | 0xAC => modrm_and_imm(bytes, pos, op2, 1)?,
        // SHLD/SHRD CL (no imm)
        0xA5 | 0xAD => modrm_and_imm(bytes, pos, op2, 0)?,
        // BT/BTS/BTR/BTC
        0xA3 | 0xAB | 0xB3 | 0xBB => modrm_and_imm(bytes, pos, op2, 0)?,
        0xBA => modrm_and_imm(bytes, pos, op2, 1)?,
        // CMPXCHG / XADD / LSS / LFS / LGS / MOVZX / MOVSX / IMUL
        0xB0 | 0xB1 | 0xB2 | 0xB4 | 0xB5 | 0xB6 | 0xB7 | 0xBE | 0xBF | 0xAF | 0xC0 | 0xC1 => {
            modrm_and_imm(bytes, pos, op2, 0)?
        }
        // CMPPS / CMPSS etc (imm8)
        0xC2 => modrm_and_imm(bytes, pos, op2, 1)?,
        // PINSRW (imm8)
        0xC4 => modrm_and_imm(bytes, pos, op2, 1)?,
        // PEXTRW (imm8)
        0xC5 => modrm_and_imm(bytes, pos, op2, 1)?,
        // SHUFPS (imm8)
        0xC6 => modrm_and_imm(bytes, pos, op2, 1)?,
        // Grp9 / Grp15
        0xAE | 0xC7 => modrm_and_imm(bytes, pos, op2, 0)?,
        // BSWAP (opcode in low 3 bits — no ModRM)
        0xC8..=0xCF => pos,
        // VMREAD/VMWRITE
        0x78 | 0x79 => modrm_and_imm(bytes, pos, op2, 0)?,
        // LAR / LSL
        0x02 | 0x03 => modrm_and_imm(bytes, pos, op2, 0)?,
        // POPCNT / BSF / BSR
        0xB8 | 0xBC | 0xBD => modrm_and_imm(bytes, pos, op2, 0)?,
        // MOVNTI
        0xC3 => modrm_and_imm(bytes, pos, op2, 0)?,
        // CPUID
        0xA2 => pos,
        _ => return Err(LengthError::UnknownOpcode),
    };
    if len > bytes.len() {
        return Err(LengthError::TruncatedStream);
    }
    Ok(len)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_length_nop() {
        assert_eq!(instr_length(&[0x90], 64).unwrap(), 1);
    }

    #[test]
    fn test_length_ret() {
        assert_eq!(instr_length(&[0xC3], 64).unwrap(), 1);
    }

    #[test]
    fn test_length_push_imm8() {
        assert_eq!(instr_length(&[0x6A, 0x04], 64).unwrap(), 2);
    }

    #[test]
    fn test_length_jmp_rel8() {
        assert_eq!(instr_length(&[0xEB, 0x10], 64).unwrap(), 2);
    }

    #[test]
    fn test_length_jmp_rel32() {
        assert_eq!(
            instr_length(&[0xE9, 0x00, 0x10, 0x00, 0x00], 64).unwrap(),
            5
        );
    }

    #[test]
    fn test_length_call_rel32() {
        assert_eq!(
            instr_length(&[0xE8, 0x00, 0x00, 0x00, 0x00], 64).unwrap(),
            5
        );
    }

    #[test]
    fn test_length_mov_reg_imm32() {
        // mov eax, 1
        assert_eq!(
            instr_length(&[0xB8, 0x01, 0x00, 0x00, 0x00], 64).unwrap(),
            5
        );
    }

    #[test]
    fn test_length_rex_prefix() {
        // REX.W (48) + mov rax, rbx (89 D8)
        assert_eq!(instr_length(&[0x48, 0x89, 0xD8], 64).unwrap(), 3);
    }

    #[test]
    fn test_length_movrm_reg() {
        // 89 C0  mov eax, eax  (mod=3 reg=0 rm=0)
        assert_eq!(instr_length(&[0x89, 0xC0], 32).unwrap(), 2);
    }

    #[test]
    fn test_length_truncated() {
        assert_eq!(instr_length(&[], 64), Err(LengthError::TruncatedStream));
    }

    #[test]
    fn test_length_jcc_rel8() {
        // jz +5
        assert_eq!(instr_length(&[0x74, 0x05], 64).unwrap(), 2);
    }

    #[test]
    fn test_length_jcc_rel32() {
        // 0F 84 ... (jz rel32)
        assert_eq!(
            instr_length(&[0x0F, 0x84, 0x00, 0x10, 0x00, 0x00], 64).unwrap(),
            6
        );
    }

    #[test]
    fn test_length_syscall() {
        assert_eq!(instr_length(&[0x0F, 0x05], 64).unwrap(), 2);
    }

    #[test]
    fn test_length_cmov() {
        // 0F 44 C0 — cmovz eax, eax
        assert_eq!(instr_length(&[0x0F, 0x44, 0xC0], 64).unwrap(), 3);
    }

    #[test]
    fn test_length_movaps() {
        // 0F 28 C1 — movaps xmm0, xmm1
        assert_eq!(instr_length(&[0x0F, 0x28, 0xC1], 64).unwrap(), 3);
    }

    #[test]
    fn test_length_with_lock_prefix() {
        // F0 0F B1 07 — lock cmpxchg [rdi], eax
        assert_eq!(instr_length(&[0xF0, 0x0F, 0xB1, 0x07], 64).unwrap(), 4);
    }

    #[test]
    fn test_length_push_pop_r64() {
        assert_eq!(instr_length(&[0x50], 64).unwrap(), 1); // push rax
        assert_eq!(instr_length(&[0x58], 64).unwrap(), 1); // pop rax
    }

    // ── Prefix-aware length: regression tests for the fixed bugs ──────────────

    #[test]
    fn length_mov_r64_imm64_rexw() {
        // 48 B8 + imm64 → movabs rax, imm64 = 10 bytes (REX.W promotes imm to 8).
        let b = [0x48, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(instr_length(&b, 64).unwrap(), 10);
    }

    #[test]
    fn length_mov_ax_imm16_opsize() {
        // 66 B8 + imm16 → mov ax, imm16 = 4 bytes (0x66 shrinks the immediate).
        let b = [0x66, 0xB8, 0x34, 0x12];
        assert_eq!(instr_length(&b, 64).unwrap(), 4);
    }

    #[test]
    fn length_add_ax_imm16_opsize() {
        // 66 05 + imm16 → add ax, imm16 = 4 bytes.
        let b = [0x66, 0x05, 0x34, 0x12];
        assert_eq!(instr_length(&b, 64).unwrap(), 4);
    }

    #[test]
    fn length_f7_neg_has_no_immediate() {
        // 48 F7 D8 → neg rax (/3) — no immediate, length 3.
        assert_eq!(instr_length(&[0x48, 0xF7, 0xD8], 64).unwrap(), 3);
        // 48 F7 C0 + imm32 → test rax, imm32 (/0) — imm32, length 7.
        let b = [0x48, 0xF7, 0xC0, 0, 0, 0, 0];
        assert_eq!(instr_length(&b, 64).unwrap(), 7);
    }

    #[test]
    fn length_imul_imm_69_vs_6b() {
        // 69 /r id → imul r32, rm32, imm32 ; 6B /r ib → imm8.
        let b69 = [0x69, 0xC0, 0, 0, 0, 0]; // imul eax, eax, imm32
        assert_eq!(instr_length(&b69, 64).unwrap(), 6);
        let b6b = [0x6B, 0xC0, 0x02]; // imul eax, eax, 2
        assert_eq!(instr_length(&b6b, 64).unwrap(), 3);
    }

    // ── Differential validation against iced-x86 (the authoritative oracle) ───
    //
    // For a *streaming* length decoder, a wrong length silently desynchronises
    // the entire downstream disassembly. We therefore cross-check `instr_length`
    // against iced-x86's decoded length over a large, deterministic corpus: for
    // every input where iced decodes a (non-VEX/EVEX) instruction *and* our
    // scanner returns a length, the two MUST agree.

    struct Lcg(u64);
    impl Lcg {
        fn next(&mut self) -> u64 {
            self.0 = self
                .0
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            self.0
        }
    }

    /// Returns true if, after legacy/REX prefixes, the opcode stream begins with
    /// a VEX/EVEX lead byte (whose tail length our scanner only approximates) or
    /// a 16-bit-addressing situation we intentionally exclude.
    fn excluded(bytes: &[u8], bits: u32) -> bool {
        let ps = crate::prefix::PrefixSet::consume(bytes, bits == 64);
        match bytes.get(ps.count) {
            Some(0xC4) | Some(0xC5) | Some(0x62) => true, // VEX/EVEX
            None => true,
            _ => bits != 64 && ps.addr_size, // 16-bit addressing form
        }
    }

    fn diff_corpus(bits: u32, seed: u64, iters: usize) {
        use iced_x86::{Decoder, DecoderOptions};
        let mut rng = Lcg(seed);
        let mut checked = 0usize;
        for _ in 0..iters {
            // 1..=12 bytes, biased toward realistic prefixes/opcodes.
            let len = 1 + (rng.next() % 12) as usize;
            let mut bytes = Vec::with_capacity(len);
            for _ in 0..len {
                bytes.push((rng.next() >> 32) as u8);
            }
            if excluded(&bytes, bits) {
                continue;
            }
            let mut dec = Decoder::with_ip(bits, &bytes, 0x1000, DecoderOptions::NONE);
            let iced = dec.decode();
            if iced.is_invalid() {
                continue;
            }
            let iced_len = iced.len();
            // Only assert when iced consumed bytes wholly inside our buffer.
            if iced_len == 0 || iced_len > bytes.len() {
                continue;
            }
            if let Ok(our_len) = instr_length(&bytes, bits) {
                assert_eq!(
                    our_len,
                    iced_len,
                    "length mismatch (bits={bits}): bytes={:02x?} ours={our_len} iced={iced_len} ({})",
                    &bytes[..iced_len],
                    iced
                );
                checked += 1;
            }
        }
        assert!(
            checked > 100,
            "corpus exercised too few instructions: {checked}"
        );
    }

    #[test]
    fn diff_length_vs_iced_64bit() {
        diff_corpus(64, 0x1357_9bdf_2468_ace0, 60_000);
    }

    #[test]
    fn diff_length_vs_iced_32bit() {
        diff_corpus(32, 0x0f0f_f0f0_a5a5_5a5a, 60_000);
    }

    /// Structured differential: every legacy 1-byte opcode, with and without a
    /// REX.W / 0x66 prefix and a register-direct ModRM, cross-checked vs iced.
    #[test]
    fn diff_length_structured_opcodes_64bit() {
        use iced_x86::{Decoder, DecoderOptions};
        let prefixes: [&[u8]; 4] = [&[], &[0x48], &[0x66], &[0xf3]];
        let mut mism = Vec::new();
        for pfx in prefixes {
            for op in 0u16..=0xFF {
                for &modrm in &[0xC0u8, 0x00, 0x40, 0x80, 0x04, 0x05] {
                    let mut bytes = Vec::new();
                    bytes.extend_from_slice(pfx);
                    bytes.push(op as u8);
                    bytes.push(modrm);
                    bytes.extend_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]);
                    if excluded(&bytes, 64) {
                        continue;
                    }
                    let mut dec = Decoder::with_ip(64, &bytes, 0x1000, DecoderOptions::NONE);
                    let iced = dec.decode();
                    if iced.is_invalid() {
                        continue;
                    }
                    let il = iced.len();
                    if il == 0 || il > bytes.len() {
                        continue;
                    }
                    if let Ok(our) = instr_length(&bytes, 64)
                        && our != il {
                            mism.push(format!(
                                "pfx={:02x?} op={op:02x} modrm={modrm:02x}: ours={our} iced={il} ({iced})",
                                pfx
                            ));
                        }
                }
            }
        }
        assert!(
            mism.is_empty(),
            "structured length mismatches ({}):\n  {}",
            mism.len(),
            mism.join("\n  ")
        );
    }
}
