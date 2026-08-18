//! Detection of stack-string construction from raw assembly instruction streams.
//!
//! Targets the obfuscation pattern where ASCII characters are written one byte
//! at a time onto a stack frame (`mov byte ptr [rsp+N], 'A'` /
//! `mov byte ptr [rbp-N], 'A'`) or via push of immediate dwords/qwords, rather
//! than referencing a `.rdata` literal.

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct StackStringHit {
    pub start_addr: u64,
    pub end_addr: u64,
    pub stack_offset: i64,
    pub bytes: Vec<u8>,
    pub decoded_utf8: Option<String>,
    pub decoded_utf8_lossy: Option<String>,
    pub confidence: u8,
}

#[derive(Debug, Clone, Copy)]
struct ByteStore {
    addr: u64,
    offset: i64,
    value: u8,
}

#[must_use]
pub fn detect_stack_strings(instrs: &[(u64, String, String)]) -> Vec<StackStringHit> {
    let mut stores: Vec<ByteStore> = Vec::new();
    for (addr, mnem, operands) in instrs {
        let m = mnem.trim().to_ascii_lowercase();
        if m == "mov" {
            if let Some((off, val)) = parse_mov_byte(operands) {
                stores.push(ByteStore { addr: *addr, offset: off, value: val });
            }
        } else if m == "push" {
            if let Some(imm) = parse_push_imm(operands) {
                let base = next_push_offset(&stores);
                for (i, b) in imm.iter().enumerate() {
                    stores.push(ByteStore {
                        addr: *addr,
                        offset: base + i as i64,
                        value: *b,
                    });
                }
            }
        }
    }

    group_runs(&stores)
}

fn next_push_offset(stores: &[ByteStore]) -> i64 {
    stores
        .iter()
        .map(|s| s.offset)
        .max()
        .map_or(0, |m| m + 1)
}

fn parse_mov_byte(operands: &str) -> Option<(i64, u8)> {
    let parts: Vec<&str> = operands.splitn(2, ',').collect();
    if parts.len() != 2 {
        return None;
    }
    let dest = parts[0].trim();
    let src = parts[1].trim();
    let off = parse_stack_mem(dest)?;
    let val = parse_imm(src)?;
    if val > 0xFF {
        return None;
    }
    Some((off, val as u8))
}

fn parse_stack_mem(s: &str) -> Option<i64> {
    let s = s.trim();
    let s = s
        .trim_start_matches("byte ptr")
        .trim_start_matches("BYTE PTR")
        .trim()
        .trim_start_matches('[')
        .trim_end_matches(']')
        .trim();

    let lower = s.to_ascii_lowercase();
    let (reg_end, reg) = if lower.starts_with("rsp") {
        (3, "rsp")
    } else if lower.starts_with("rbp") {
        (3, "rbp")
    } else if lower.starts_with("esp") {
        (3, "esp")
    } else if lower.starts_with("ebp") {
        (3, "ebp")
    } else {
        return None;
    };

    let rest = s[reg_end..].trim();
    if rest.is_empty() {
        return Some(0);
    }
    let (sign, num) = if let Some(r) = rest.strip_prefix('+') {
        (1i64, r.trim())
    } else if let Some(r) = rest.strip_prefix('-') {
        (-1i64, r.trim())
    } else {
        return None;
    };
    let n = parse_imm(num)? as i64;
    let off = sign * n;
    if reg == "rbp" || reg == "ebp" {
        Some(off)
    } else {
        Some(off)
    }
}

fn parse_imm(s: &str) -> Option<u64> {
    let s = s.trim().trim_end_matches('h');
    let s = s.trim();
    if let Some(h) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        return u64::from_str_radix(h, 16).ok();
    }
    if let Ok(n) = s.parse::<u64>() {
        return Some(n);
    }
    if s.chars().all(|c| c.is_ascii_hexdigit()) && s.chars().any(|c| c.is_ascii_alphabetic()) {
        return u64::from_str_radix(s, 16).ok();
    }
    if let Ok(n) = s.parse::<i64>() {
        return Some(n as u64);
    }
    None
}

fn parse_push_imm(operands: &str) -> Option<Vec<u8>> {
    let v = parse_imm(operands.trim())?;
    let bytes = v.to_le_bytes();
    let mut out: Vec<u8> = bytes.iter().copied().collect();
    while out.len() > 4 && *out.last().unwrap() == 0 {
        out.pop();
    }
    if out.len() < 4 {
        out.resize(4, 0);
    }
    Some(out)
}

fn group_runs(stores: &[ByteStore]) -> Vec<StackStringHit> {
    if stores.is_empty() {
        return Vec::new();
    }
    let mut sorted: Vec<ByteStore> = stores.to_vec();
    sorted.sort_by_key(|s| s.offset);

    let mut hits = Vec::new();
    let mut i = 0;
    while i < sorted.len() {
        let mut j = i;
        let mut bytes = vec![sorted[i].value];
        let mut start_addr = sorted[i].addr;
        let mut end_addr = sorted[i].addr;
        let base_off = sorted[i].offset;

        while j + 1 < sorted.len() && sorted[j + 1].offset == sorted[j].offset + 1 {
            j += 1;
            bytes.push(sorted[j].value);
            start_addr = start_addr.min(sorted[j].addr);
            end_addr = end_addr.max(sorted[j].addr);
        }

        if bytes.len() >= 4 {
            let printable = bytes
                .iter()
                .filter(|&&b| (0x20..=0x7E).contains(&b) || b == 0)
                .count();
            let ratio = printable as f64 / bytes.len() as f64;
            if ratio >= 0.70 {
                let mut conf = (ratio * 100.0) as u32;
                let ends_null = bytes.last().copied() == Some(0);
                if ends_null {
                    conf = conf.saturating_add(20);
                }
                let confidence = conf.min(100) as u8;

                let trimmed: Vec<u8> = if ends_null {
                    bytes[..bytes.len() - 1].to_vec()
                } else {
                    bytes.clone()
                };
                let decoded_utf8 = std::str::from_utf8(&trimmed).ok().map(str::to_owned);
                let decoded_utf8_lossy = if decoded_utf8.is_none() {
                    Some(String::from_utf8_lossy(&trimmed).into_owned())
                } else {
                    None
                };

                hits.push(StackStringHit {
                    start_addr,
                    end_addr,
                    stack_offset: base_off,
                    bytes,
                    decoded_utf8,
                    decoded_utf8_lossy,
                    confidence,
                });
            }
        }
        i = j + 1;
    }
    hits
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ins(addr: u64, m: &str, ops: &str) -> (u64, String, String) {
        (addr, m.to_string(), ops.to_string())
    }

    #[test]
    fn detects_rsp_mov_byte_run_hello() {
        let stream = vec![
            ins(0x1000, "mov", "byte ptr [rsp+0x10], 0x48"),
            ins(0x1004, "mov", "byte ptr [rsp+0x11], 0x65"),
            ins(0x1008, "mov", "byte ptr [rsp+0x12], 0x6C"),
            ins(0x100C, "mov", "byte ptr [rsp+0x13], 0x6C"),
            ins(0x1010, "mov", "byte ptr [rsp+0x14], 0x6F"),
            ins(0x1014, "mov", "byte ptr [rsp+0x15], 0x00"),
        ];
        let hits = detect_stack_strings(&stream);
        assert_eq!(hits.len(), 1);
        let h = &hits[0];
        assert_eq!(h.bytes, b"Hello\0");
        assert_eq!(h.decoded_utf8.as_deref(), Some("Hello"));
        assert_eq!(h.stack_offset, 0x10);
        assert!(h.confidence >= 100 || h.confidence > 80);
        assert_eq!(h.confidence, 100);
    }

    #[test]
    fn rbp_negative_offsets_admin() {
        let stream = vec![
            ins(0x2000, "mov", "[rbp-0x14], 0x61"),
            ins(0x2004, "mov", "[rbp-0x13], 0x64"),
            ins(0x2008, "mov", "[rbp-0x12], 0x6D"),
            ins(0x200C, "mov", "[rbp-0x11], 0x69"),
            ins(0x2010, "mov", "[rbp-0x10], 0x6E"),
        ];
        let hits = detect_stack_strings(&stream);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].decoded_utf8.as_deref(), Some("admin"));
        assert_eq!(hits[0].stack_offset, -0x14);
        assert!(hits[0].confidence >= 90);
    }

    #[test]
    fn ignores_short_or_nonprintable_runs() {
        let stream = vec![
            ins(0x3000, "mov", "byte ptr [rsp+0x0], 0x01"),
            ins(0x3004, "mov", "byte ptr [rsp+0x1], 0x02"),
            ins(0x3008, "mov", "byte ptr [rsp+0x2], 0x03"),
            ins(0x300C, "mov", "byte ptr [rsp+0x10], 0x41"),
            ins(0x3010, "mov", "byte ptr [rsp+0x11], 0x42"),
        ];
        let hits = detect_stack_strings(&stream);
        assert!(hits.is_empty());
    }

    #[test]
    fn push_immediate_builds_string() {
        let stream = vec![
            ins(0x4000, "push", "0x6F6C6C65"),
            ins(0x4005, "push", "0x21646C72"),
            ins(0x400A, "push", "0x6F77202C"),
        ];
        let hits = detect_stack_strings(&stream);
        assert_eq!(hits.len(), 1);
        let decoded = hits[0].decoded_utf8.as_deref().unwrap();
        assert_eq!(decoded.len(), hits[0].bytes.len());
        assert!(decoded.contains("ello"));
        assert!(hits[0].confidence >= 70);
    }
}
