//! Memory-operand parser used by struct-field recovery.
//!
//! Decodes Intel-syntax operands such as `qword ptr [rsp + 0x10]` into a
//! `(BaseKind, displacement, size_bytes)` triple so downstream passes can group
//! accesses that share the same base register.

use serde::{Deserialize, Serialize};

/// The base of a `[reg ± disp]` memory reference.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum BaseKind {
    /// Frame pointer (rbp / ebp).
    Rbp,
    /// Stack pointer (rsp / esp).
    Rsp,
    /// Any other GPR; the raw lowercase register name is preserved.
    Reg(String),
}

impl BaseKind {
    /// A short token usable as a C identifier prefix.
    #[must_use]
    pub fn ident_prefix(&self) -> String {
        match self {
            Self::Rbp => "frame".to_string(),
            Self::Rsp => "stack".to_string(),
            Self::Reg(r) => format!("heap_{r}"),
        }
    }
}

/// A parsed Intel-syntax memory reference: `<size> ptr [base ± disp]`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MemOperand {
    pub base: BaseKind,
    /// Signed displacement; positive if `+`, negative if `-`.
    pub displacement: i64,
    /// Access size in bytes (1 / 2 / 4 / 8 / 16 …). 0 if the operand had no
    /// `qword ptr` / `dword ptr` … prefix.
    pub size_bytes: u8,
}

/// Parse every `[...]` memory reference inside an operands string.
///
/// Returns one entry per `[…]` group whose base register is recognised.
#[must_use]
pub fn parse_mem_operands(operands: &str) -> Vec<MemOperand> {
    let mut out = Vec::new();
    let mut rest = operands;
    while let Some(start) = rest.find('[') {
        let prefix = &rest[..start];
        let after = &rest[start + 1..];
        let Some(end) = after.find(']') else { break };
        let inside = &after[..end];
        if let Some(parsed) = parse_one(prefix, inside) {
            out.push(parsed);
        }
        rest = &after[end + 1..];
    }
    out
}

fn parse_one(prefix: &str, inside: &str) -> Option<MemOperand> {
    let size = size_from_prefix(prefix);
    let inside_clean = inside.trim().to_lowercase();
    // Strip any leading segment override like "fs:" or "gs:".
    let inside_no_seg: &str = inside_clean
        .split_once(':')
        .map_or(inside_clean.as_str(), |(_seg, rest)| rest.trim());

    let (base, disp) = split_base_disp(inside_no_seg)?;
    let base_kind = classify_base(&base)?;
    Some(MemOperand {
        base: base_kind,
        displacement: disp,
        size_bytes: size,
    })
}

fn size_from_prefix(prefix: &str) -> u8 {
    let p = prefix.to_lowercase();
    if p.contains("byte ptr") {
        1
    } else if p.contains("word ptr") && !p.contains("dword") && !p.contains("qword") {
        2
    } else if p.contains("dword ptr") {
        4
    } else if p.contains("qword ptr") {
        8
    } else if p.contains("xmmword") || p.contains("oword") {
        16
    } else if p.contains("ymmword") {
        32
    } else if p.contains("zmmword") {
        64
    } else {
        // Default to pointer width when no prefix is present.  Most opcodes
        // that omit a size already encode register-width; assume 8 (x86_64).
        8
    }
}

/// Decompose `"<base> ± <disp>"` into a base register name and a signed
/// displacement.  Returns `None` if the input contains an index ×scale term
/// (which struct recovery cannot meaningfully attribute to a base).
fn split_base_disp(inner: &str) -> Option<(String, i64)> {
    // Reject SIB forms `[base + index*scale + disp]`.
    if inner.contains('*') {
        return None;
    }
    // Split into tokens by + / -, preserving the sign of each numeric term.
    let mut base: Option<String> = None;
    let mut disp: i64 = 0;
    let mut sign: i64 = 1;
    let mut tok = String::new();
    let push = |tok: &mut String, base: &mut Option<String>, disp: &mut i64, sign: i64| {
        let t = tok.trim();
        if t.is_empty() {
            return;
        }
        if let Some(v) = parse_num(t) {
            *disp = disp.saturating_add(sign.saturating_mul(v));
        } else if base.is_none() {
            *base = Some(t.to_string());
        } else {
            // Second register implies index — skip silently (returned None
            // earlier for `*` SIB; here treat as if absent).
            *base = base.clone();
        }
        tok.clear();
    };

    for ch in inner.chars() {
        match ch {
            '+' => {
                push(&mut tok, &mut base, &mut disp, sign);
                sign = 1;
            }
            '-' => {
                push(&mut tok, &mut base, &mut disp, sign);
                sign = -1;
            }
            _ => tok.push(ch),
        }
    }
    push(&mut tok, &mut base, &mut disp, sign);

    let base = base?;
    Some((base, disp))
}

fn parse_num(s: &str) -> Option<i64> {
    let s = s.trim();
    s.strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .map_or_else(
            || s.strip_suffix('h')
                .or_else(|| s.strip_suffix('H'))
                .map_or_else(|| s.parse::<i64>().ok(), |h| i64::from_str_radix(h, 16).ok()),
            |h| i64::from_str_radix(h, 16).ok(),
        )
}

fn classify_base(name: &str) -> Option<BaseKind> {
    let n = name.trim().to_lowercase();
    match n.as_str() {
        "rbp" | "ebp" | "bp" => Some(BaseKind::Rbp),
        "rsp" | "esp" | "sp" => Some(BaseKind::Rsp),
        "rax" | "rbx" | "rcx" | "rdx" | "rsi" | "rdi" | "r8" | "r9" | "r10" | "r11" | "r12"
        | "r13" | "r14" | "r15" | "eax" | "ebx" | "ecx" | "edx" | "esi" | "edi" => {
            Some(BaseKind::Reg(n))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_qword_rsp() {
        let m = parse_mem_operands("rax, qword ptr [rsp + 0x10]");
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].base, BaseKind::Rsp);
        assert_eq!(m[0].displacement, 0x10);
        assert_eq!(m[0].size_bytes, 8);
    }

    #[test]
    fn parses_negative_rbp() {
        let m = parse_mem_operands("dword ptr [rbp - 0x8], eax");
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].base, BaseKind::Rbp);
        assert_eq!(m[0].displacement, -8);
        assert_eq!(m[0].size_bytes, 4);
    }

    #[test]
    fn parses_byte_reg_base() {
        let m = parse_mem_operands("byte ptr [rax + 12]");
        assert_eq!(m[0].base, BaseKind::Reg("rax".to_string()));
        assert_eq!(m[0].displacement, 12);
        assert_eq!(m[0].size_bytes, 1);
    }

    #[test]
    fn rejects_sib() {
        let m = parse_mem_operands("[rax + rcx*4 + 8]");
        assert!(m.is_empty());
    }

    #[test]
    fn default_size_when_no_prefix() {
        let m = parse_mem_operands("[rsp]");
        assert_eq!(m[0].displacement, 0);
        assert_eq!(m[0].size_bytes, 8);
    }
}
