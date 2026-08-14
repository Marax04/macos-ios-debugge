//! `x86_register_width` — Sub-register width and canonicalization tables.
//!
//! Used by [`crate::VariableCollectionPass`] to assign correctly-sized C types
//! (uint8_t / uint16_t / uint32_t / uint64_t) to recovered variables instead of
//! the previous blanket `uint64_t`.  Also exposes a helper that maps an Intel
//! mnemonic suffix (`movb`/`movw`/`movl`/`movq`) and an operand-size hint
//! (`byte ptr`, `word ptr`, `dword ptr`, `qword ptr`) to a byte width.

/// Return the width, in bytes, of an x86/x86-64 general-purpose sub-register.
/// Returns `None` for non-registers, XMM/YMM/ZMM, or anything unrecognised.
#[must_use]
pub fn register_width_bytes(reg: &str) -> Option<u8> {
    match reg.to_lowercase().as_str() {
        // 64-bit
        "rax" | "rbx" | "rcx" | "rdx" | "rsi" | "rdi" | "rbp" | "rsp" | "rip"
        | "r8"  | "r9"  | "r10" | "r11" | "r12" | "r13" | "r14" | "r15" => Some(8),
        // 32-bit
        "eax" | "ebx" | "ecx" | "edx" | "esi" | "edi" | "ebp" | "esp"
        | "r8d" | "r9d" | "r10d" | "r11d" | "r12d" | "r13d" | "r14d" | "r15d" => Some(4),
        // 16-bit
        "ax" | "bx" | "cx" | "dx" | "si" | "di" | "bp" | "sp"
        | "r8w" | "r9w" | "r10w" | "r11w" | "r12w" | "r13w" | "r14w" | "r15w" => Some(2),
        // 8-bit (low)
        "al" | "bl" | "cl" | "dl" | "ah" | "bh" | "ch" | "dh"
        | "sil" | "dil" | "bpl" | "spl"
        | "r8b" | "r9b" | "r10b" | "r11b" | "r12b" | "r13b" | "r14b" | "r15b" => Some(1),
        _ => None,
    }
}

/// Map any sub-register name to its 64-bit canonical full register name
/// (e.g. `eax → rax`, `r10d → r10`, `al → rax`).  Returns the input lowercased
/// for unrecognised names.
#[must_use]
pub fn register_canonical(reg: &str) -> String {
    let lower = reg.to_lowercase();
    match lower.as_str() {
        "rax" | "eax" | "ax" | "ah" | "al" => "rax".to_string(),
        "rbx" | "ebx" | "bx" | "bh" | "bl" => "rbx".to_string(),
        "rcx" | "ecx" | "cx" | "ch" | "cl" => "rcx".to_string(),
        "rdx" | "edx" | "dx" | "dh" | "dl" => "rdx".to_string(),
        "rsi" | "esi" | "si" | "sil" => "rsi".to_string(),
        "rdi" | "edi" | "di" | "dil" => "rdi".to_string(),
        "rbp" | "ebp" | "bp" | "bpl" => "rbp".to_string(),
        "rsp" | "esp" | "sp" | "spl" => "rsp".to_string(),
        "r8"  | "r8d"  | "r8w"  | "r8b"  => "r8".to_string(),
        "r9"  | "r9d"  | "r9w"  | "r9b"  => "r9".to_string(),
        "r10" | "r10d" | "r10w" | "r10b" => "r10".to_string(),
        "r11" | "r11d" | "r11w" | "r11b" => "r11".to_string(),
        "r12" | "r12d" | "r12w" | "r12b" => "r12".to_string(),
        "r13" | "r13d" | "r13w" | "r13b" => "r13".to_string(),
        "r14" | "r14d" | "r14w" | "r14b" => "r14".to_string(),
        "r15" | "r15d" | "r15w" | "r15b" => "r15".to_string(),
        _ => lower,
    }
}

/// Pull a byte-width hint from an x86 instruction's mnemonic suffix or its
/// operand text.  Recognises:
///
/// * Mnemonic suffixes: `movb`/`movw`/`movl`/`movq` and the same suffixes on
///   `add`/`sub`/`and`/`or`/`xor`.
/// * Intel size hints in the operands: `byte ptr`, `word ptr`, `dword ptr`,
///   `qword ptr`.
///
/// Returns `None` if no hint is present.
#[must_use]
pub fn width_hint_from_instr(mnemonic: &str, operands: &str) -> Option<u8> {
    let m = mnemonic.to_lowercase();
    if m.ends_with('b') && m.len() > 1
        && is_size_suffix_root(strip_known_prefix(&m, 'b')) {
                return Some(1);
            }
    if m.ends_with('w') && m.len() > 1
        && is_size_suffix_root(strip_known_prefix(&m, 'w')) {
                return Some(2);
            }
    if m.ends_with('l') && m.len() > 1
        && is_size_suffix_root(strip_known_prefix(&m, 'l')) {
                return Some(4);
            }
    if m.ends_with('q') && m.len() > 1
        && is_size_suffix_root(strip_known_prefix(&m, 'q')) {
                return Some(8);
            }

    let ops = operands.to_lowercase();
    if ops.contains("byte ptr")  { return Some(1); }
    if ops.contains("word ptr") && !ops.contains("dword ptr") && !ops.contains("qword ptr") {
        return Some(2);
    }
    if ops.contains("dword ptr") { return Some(4); }
    if ops.contains("qword ptr") { return Some(8); }
    None
}

fn strip_known_prefix(mnemonic: &str, last: char) -> &str {
    let cut = mnemonic.len() - last.len_utf8();
    &mnemonic[..cut]
}

fn is_size_suffix_root(root: &str) -> bool {
    matches!(root, "mov" | "add" | "sub" | "and" | "or" | "xor" | "cmp" | "test")
}

/// Return the canonical C type name for a width and a sign hint.
/// `None` width or `None` sign falls back to `uint64_t`.
#[must_use]
pub const fn c_type_for(width: Option<u8>, signed: Option<bool>) -> &'static str {
    match (width, signed) {
        (Some(1), Some(true))  => "int8_t",
        (Some(2), Some(true))  => "int16_t",
        (Some(4), Some(true))  => "int32_t",
        (_, Some(true))        => "int64_t",
        (Some(1), _)           => "uint8_t",
        (Some(2), _)           => "uint16_t",
        (Some(4), _)           => "uint32_t",
        _                      => "uint64_t",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn width_64() {
        assert_eq!(register_width_bytes("rax"), Some(8));
        assert_eq!(register_width_bytes("r10"), Some(8));
        assert_eq!(register_width_bytes("R15"), Some(8));
    }

    #[test]
    fn width_32() {
        assert_eq!(register_width_bytes("eax"), Some(4));
        assert_eq!(register_width_bytes("r10d"), Some(4));
    }

    #[test]
    fn width_16() {
        assert_eq!(register_width_bytes("ax"), Some(2));
        assert_eq!(register_width_bytes("r10w"), Some(2));
    }

    #[test]
    fn width_8() {
        assert_eq!(register_width_bytes("al"), Some(1));
        assert_eq!(register_width_bytes("r10b"), Some(1));
        assert_eq!(register_width_bytes("dil"), Some(1));
    }

    #[test]
    fn width_unknown() {
        assert_eq!(register_width_bytes("xmm0"), None);
        assert_eq!(register_width_bytes("notareg"), None);
    }

    #[test]
    fn canonical_collapses_subregs() {
        assert_eq!(register_canonical("eax"), "rax");
        assert_eq!(register_canonical("al"),  "rax");
        assert_eq!(register_canonical("r10d"), "r10");
        assert_eq!(register_canonical("r10b"), "r10");
    }

    #[test]
    fn width_hint_from_mnemonic_suffix() {
        assert_eq!(width_hint_from_instr("movb", ""), Some(1));
        assert_eq!(width_hint_from_instr("movw", ""), Some(2));
        assert_eq!(width_hint_from_instr("movl", ""), Some(4));
        assert_eq!(width_hint_from_instr("movq", ""), Some(8));
    }

    #[test]
    fn width_hint_from_operand() {
        assert_eq!(width_hint_from_instr("mov", "rax, qword ptr [rbp - 8]"), Some(8));
        assert_eq!(width_hint_from_instr("mov", "eax, dword ptr [rbp - 4]"), Some(4));
        assert_eq!(width_hint_from_instr("mov", "ax, word ptr [rbp - 2]"),   Some(2));
        assert_eq!(width_hint_from_instr("mov", "al, byte ptr [rbp - 1]"),   Some(1));
    }

    #[test]
    fn width_hint_none() {
        assert_eq!(width_hint_from_instr("mov", "rax, rbx"), None);
        assert_eq!(width_hint_from_instr("ret", ""), None);
    }

    #[test]
    fn c_type_for_signed_unsigned() {
        assert_eq!(c_type_for(Some(4), Some(true)),  "int32_t");
        assert_eq!(c_type_for(Some(4), Some(false)), "uint32_t");
        assert_eq!(c_type_for(Some(4), None),        "uint32_t");
        assert_eq!(c_type_for(Some(1), Some(true)),  "int8_t");
        assert_eq!(c_type_for(None,    None),        "uint64_t");
    }
}
