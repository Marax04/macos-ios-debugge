//! Heuristic `AArch64` jump-table recognizer.
//!
//! Detects the canonical compiler-emitted indirect-branch idioms used to
//! implement dense `switch` constructs:
//!
//! Pattern A (PIC, byte-offset table):
//! ```text
//! adrp  xN, .Ltable_page
//! add   xN, xN, :lo12:.Ltable
//! ldrb  wM, [xN, xIDX]
//! ldr   xT, [xN, wM, sxtw #2]
//! br    xT
//! ```
//!
//! Pattern B (absolute, 8-byte entries):
//! ```text
//! adr   xN, .Ltable
//! ldr   xT, [xN, xIDX, lsl #3]
//! br    xT
//! ```

use serde::{Deserialize, Serialize};

use crate::yaxpeax_decode;
use yaxpeax_arm::armv8::a64::Opcode;

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub enum JumpTableKind {
    PcRelative32,
    Absolute64,
    ByteOffsetTable,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct JumpTableInfo {
    pub branch_addr: u64,
    pub table_addr: u64,
    pub entry_count: usize,
    pub entry_size: u8,
    pub kind: JumpTableKind,
}

#[derive(Debug, Clone)]
struct Decoded {
    addr: u64,
    mnemonic: &'static str,
    text: String,
    opcode: Opcode,
}

const fn classify(opcode: Opcode) -> &'static str {
    match opcode {
        Opcode::ADRP => "adrp",
        Opcode::ADR => "adr",
        Opcode::ADD => "add",
        Opcode::LDR => "ldr",
        Opcode::LDRB => "ldrb",
        Opcode::BR => "br",
        _ => "",
    }
}

fn decode_all(instrs: &[(u64, &[u8])]) -> Vec<Decoded> {
    let mut out = Vec::with_capacity(instrs.len());
    for (addr, bytes) in instrs {
        let Ok(d) = yaxpeax_decode(bytes) else { continue };
        let text = d.to_string();
        let mn = classify(d.opcode);
        out.push(Decoded {
            addr: *addr,
            mnemonic: mn,
            text,
            opcode: d.opcode,
        });
    }
    out
}

fn extract_adrp_target(text: &str, instr_addr: u64) -> Option<u64> {
    let comma = text.rfind(',')?;
    let imm = text[comma + 1..].trim();
    parse_signed_imm(imm).map(|off| (instr_addr & !0xfff).wrapping_add(off.cast_unsigned()))
}

fn extract_adr_target(text: &str, instr_addr: u64) -> Option<u64> {
    let comma = text.rfind(',')?;
    let imm = text[comma + 1..].trim();
    parse_signed_imm(imm).map(|off| instr_addr.wrapping_add(off.cast_unsigned()))
}

fn parse_signed_imm(s: &str) -> Option<i64> {
    let s = s.trim().trim_start_matches('#').trim_start_matches('$');
    let (neg, rest) = if let Some(r) = s.strip_prefix('-') {
        (true, r)
    } else if let Some(r) = s.strip_prefix('+') {
        (false, r)
    } else {
        (false, s)
    };
    let v: i64 = if let Some(h) = rest.strip_prefix("0x").or_else(|| rest.strip_prefix("0X")) {
        i64::from_str_radix(h, 16).ok()?
    } else {
        rest.parse::<i64>().ok()?
    };
    Some(if neg { -v } else { v })
}

fn parse_add_lo12_imm(text: &str) -> Option<u64> {
    if let Some(p) = text.find(":lo12:") {
        let after = &text[p + 6..];
        let end = after
            .find(|c: char| c == ',' || c.is_ascii_whitespace())
            .unwrap_or(after.len());
        return parse_signed_imm(&after[..end]).map(i64::cast_unsigned);
    }
    let last = text.rsplit(',').next()?.trim();
    parse_signed_imm(last).map(i64::cast_unsigned)
}

fn op_text_contains(text: &str, needle: &str) -> bool {
    text.to_ascii_lowercase().contains(needle)
}

/// Heuristic detector for `AArch64` switch-style jump tables.
#[must_use]
pub fn detect_jump_tables(instrs: &[(u64, &[u8])]) -> Vec<JumpTableInfo> {
    let decoded = decode_all(instrs);
    let mut out = Vec::new();

    for i in 0..decoded.len() {
        if decoded[i].mnemonic != "br" {
            continue;
        }
        if try_pattern_a(&decoded, i, &mut out) {
            continue;
        }
        try_pattern_b(&decoded, i, &mut out);
    }

    out
}

fn try_pattern_a(decoded: &[Decoded], br_idx: usize, out: &mut Vec<JumpTableInfo>) -> bool {
    if br_idx < 4 {
        return false;
    }
    let adrp = &decoded[br_idx - 4];
    let add = &decoded[br_idx - 3];
    let ldrb = &decoded[br_idx - 2];
    let ldr = &decoded[br_idx - 1];
    let br = &decoded[br_idx];

    if adrp.mnemonic != "adrp"
        || add.mnemonic != "add"
        || ldrb.mnemonic != "ldrb"
        || ldr.mnemonic != "ldr"
        || br.mnemonic != "br"
    {
        return false;
    }
    if !matches!(adrp.opcode, Opcode::ADRP)
        || !matches!(add.opcode, Opcode::ADD)
        || !matches!(ldrb.opcode, Opcode::LDRB)
        || !matches!(ldr.opcode, Opcode::LDR)
        || !matches!(br.opcode, Opcode::BR)
    {
        return false;
    }
    if !op_text_contains(&ldr.text, "sxtw") {
        return false;
    }

    let Some(page) = extract_adrp_target(&adrp.text, adrp.addr) else { return false };
    let lo12 = parse_add_lo12_imm(&add.text).unwrap_or(0);
    let table_addr = page.wrapping_add(lo12);

    out.push(JumpTableInfo {
        branch_addr: br.addr,
        table_addr,
        entry_count: 0,
        entry_size: 1,
        kind: JumpTableKind::ByteOffsetTable,
    });
    true
}

fn try_pattern_b(decoded: &[Decoded], br_idx: usize, out: &mut Vec<JumpTableInfo>) -> bool {
    if br_idx < 2 {
        return false;
    }
    let adr = &decoded[br_idx - 2];
    let ldr = &decoded[br_idx - 1];
    let br = &decoded[br_idx];

    if adr.mnemonic != "adr" || ldr.mnemonic != "ldr" || br.mnemonic != "br" {
        return false;
    }
    if !matches!(adr.opcode, Opcode::ADR)
        || !matches!(ldr.opcode, Opcode::LDR)
        || !matches!(br.opcode, Opcode::BR)
    {
        return false;
    }

    let lower = ldr.text.to_ascii_lowercase();
    let (entry_size, kind) = if lower.contains("lsl #3") || lower.contains("lsl 3") {
        (8u8, JumpTableKind::Absolute64)
    } else if lower.contains("lsl #2") || lower.contains("lsl 2") {
        (4u8, JumpTableKind::PcRelative32)
    } else {
        return false;
    };

    let Some(table_addr) = extract_adr_target(&adr.text, adr.addr) else { return false };

    out.push(JumpTableInfo {
        branch_addr: br.addr,
        table_addr,
        entry_count: 0,
        entry_size,
        kind,
    });
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_pattern_b_absolute64() {
        let adr: [u8; 4] = [0x60, 0x00, 0x00, 0x10];
        let ldr: [u8; 4] = [0x01, 0x78, 0x61, 0xf8];
        let br: [u8; 4] = [0x20, 0x00, 0x1f, 0xd6];

        let instrs: Vec<(u64, &[u8])> = vec![
            (0x1000, &adr),
            (0x1004, &ldr),
            (0x1008, &br),
        ];
        let v = detect_jump_tables(&instrs);
        assert_eq!(v.len(), 1, "should detect one jump table");
        assert_eq!(v[0].branch_addr, 0x1008);
        assert_eq!(v[0].kind, JumpTableKind::Absolute64);
        assert_eq!(v[0].entry_size, 8);
        assert_eq!(v[0].table_addr, 0x100c);
    }

    #[test]
    fn detects_pattern_a_byte_offset_table() {
        let adrp: [u8; 4] = [0x09, 0x00, 0x00, 0xb0];
        let add: [u8; 4] = [0x29, 0x41, 0x10, 0x91];
        let ldrb: [u8; 4] = [0x2a, 0x69, 0x62, 0x38];
        let ldr: [u8; 4] = [0x2b, 0xc9, 0x6a, 0xf8];
        let br: [u8; 4] = [0x60, 0x01, 0x1f, 0xd6];

        let instrs: Vec<(u64, &[u8])> = vec![
            (0x2000, &adrp),
            (0x2004, &add),
            (0x2008, &ldrb),
            (0x200c, &ldr),
            (0x2010, &br),
        ];
        let v = detect_jump_tables(&instrs);
        assert_eq!(v.len(), 1, "should detect one byte-offset jump table");
        assert_eq!(v[0].branch_addr, 0x2010);
        assert_eq!(v[0].kind, JumpTableKind::ByteOffsetTable);
        assert_eq!(v[0].entry_size, 1);
    }

    #[test]
    fn ignores_unrelated_sequence() {
        let nop: [u8; 4] = [0x1f, 0x20, 0x03, 0xd5];
        let ret: [u8; 4] = [0xc0, 0x03, 0x5f, 0xd6];
        let instrs: Vec<(u64, &[u8])> = vec![
            (0x3000, &nop),
            (0x3004, &nop),
            (0x3008, &ret),
        ];
        let v = detect_jump_tables(&instrs);
        assert!(v.is_empty(), "no BR in stream means no jump tables");
    }
}
