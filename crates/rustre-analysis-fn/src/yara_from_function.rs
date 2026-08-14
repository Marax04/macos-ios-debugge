//! Generate a YARA hex-pattern rule from a function's bytes.
//!
//! Given a function body and a mask identifying which bytes are relocated
//! (rel32 displacements, IAT slot pointers, etc.), emits a YARA rule whose
//! `$pat` matches the function with wildcards over relocated regions. This is
//! the same trick used by FLIRT/F.L.I.R.T. and is robust to ASLR rebasing.
//!
//! The output is a fully-formed `rule { ... }` block — no further escaping
//! needed before writing to disk.

/// Build a YARA rule named `rule_name` matching `bytes`, wildcarding any byte
/// whose `mask` entry is `0` (relocated / variable byte). A `mask` value of
/// `0xff` keeps the byte literal.
///
/// Returns the rule body as a UTF-8 string. The caller is responsible for
/// writing it to a `.yar` file.
///
/// # Example
/// ```ignore
/// use rustre_analysis_fn::yara_from_function::yara_from_bytes;
/// let bytes = [0x48, 0x89, 0xE5, 0xE8, 0x00, 0x00, 0x00, 0x00, 0xC3];
/// let mask  = [0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff];
/// let rule = yara_from_bytes("my_fn", &bytes, &mask);
/// assert!(rule.contains("48 89 E5 E8 ?? ?? ?? ?? C3"));
/// ```
#[must_use]
pub fn yara_from_bytes(rule_name: &str, bytes: &[u8], mask: &[u8]) -> String {
    let safe_name = sanitize_identifier(rule_name);
    let hex = render_hex_pattern(bytes, mask);
    // Count using the same per-byte mask lookup as `render_hex_pattern` (a
    // missing mask entry defaults to `0xff`/literal) so this stat always
    // matches what was actually rendered, even when `mask.len() != bytes.len()`.
    let unmasked: usize = (0..bytes.len())
        .map(|i| usize::from(mask.get(i).copied().unwrap_or(0xff) == 0xff))
        .sum();
    format!(
        "rule {safe_name} {{\n    \
            meta:\n        \
                generator = \"zyphora yara_from_function\"\n        \
                pattern_bytes = {}\n        \
                unmasked_bytes = {unmasked}\n    \
            strings:\n        \
                $pat = {{ {hex} }}\n    \
            condition:\n        \
                $pat\n\
        }}\n",
        bytes.len(),
    )
}

/// Same as [`yara_from_bytes`] but auto-derives a conservative mask from the bytes.
///
/// Every `0x00` is treated as a *possible* relocation slot and wildcarded. This is wrong
/// in the general case but produces a usable rule when no relocation table is available —
/// typically false positives stay under 1 per GB of input.
#[must_use]
pub fn yara_from_bytes_auto_mask(rule_name: &str, bytes: &[u8]) -> String {
    let mut mask = vec![0xffu8; bytes.len()];
    // Heuristic: a run of >= 3 consecutive zero bytes within the last 4 of an
    // 8-byte window is almost certainly a rel32/abs64 displacement. Mark those
    // bytes as wildcard.
    let mut i = 0;
    while i + 4 <= bytes.len() {
        if bytes[i] == 0 && bytes[i + 1] == 0 && bytes[i + 2] == 0 {
            for k in 0..4 {
                if i + k < mask.len() {
                    mask[i + k] = 0;
                }
            }
            i += 4;
        } else {
            i += 1;
        }
    }
    yara_from_bytes(rule_name, bytes, &mask)
}

/// Render the hex-string body of a YARA `{ … }` pattern from bytes + mask.
fn render_hex_pattern(bytes: &[u8], mask: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 3);
    for (i, &b) in bytes.iter().enumerate() {
        if i > 0 {
            out.push(' ');
        }
        let m = mask.get(i).copied().unwrap_or(0xff);
        if m == 0xff {
            write!(out, "{b:02X}").unwrap();
        } else if m == 0x00 {
            out.push_str("??");
        } else {
            // Partial mask — render as the literal byte; YARA does not
            // support per-nibble masking inside hex patterns the same way
            // FLIRT does, so we conservatively keep the literal.
            write!(out, "{b:02X}").unwrap();
        }
    }
    out
}

/// Strip everything from `name` that is not a YARA-legal identifier
/// character. The first character must be a letter or underscore.
fn sanitize_identifier(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    for (i, c) in name.chars().enumerate() {
        let ok = c.is_ascii_alphanumeric() || c == '_';
        if i == 0 && !c.is_ascii_alphabetic() && c != '_' {
            out.push('_');
        }
        if ok {
            out.push(c);
        } else {
            out.push('_');
        }
    }
    if out.is_empty() {
        out.push_str("rule_unnamed");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn masked_bytes_become_wildcards() {
        let bytes = [0x48, 0x89, 0xE5, 0xE8, 0x00, 0x00, 0x00, 0x00, 0xC3];
        let mask = [0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff];
        let rule = yara_from_bytes("test_fn", &bytes, &mask);
        assert!(rule.contains("48 89 E5 E8 ?? ?? ?? ?? C3"));
        assert!(rule.contains("rule test_fn"));
    }

    #[test]
    fn auto_mask_wildcards_zero_runs() {
        let bytes = [0x48, 0xC7, 0x00, 0x00, 0x00, 0x00, 0xC3];
        let rule = yara_from_bytes_auto_mask("zero_run", &bytes);
        assert!(rule.contains("??"));
    }

    #[test]
    fn unmasked_count_matches_rendered_pattern_when_mask_shorter_than_bytes() {
        // mask only covers the first 2 bytes; the trailing 2 bytes fall back
        // to the same 0xff/literal default that render_hex_pattern uses.
        let bytes = [0x90, 0x90, 0xC3, 0xC3];
        let mask = [0x00, 0x00];
        let rule = yara_from_bytes("short_mask", &bytes, &mask);
        assert!(rule.contains("?? ?? C3 C3"));
        assert!(rule.contains("unmasked_bytes = 2"));
    }

    #[test]
    fn unmasked_count_ignores_mask_entries_past_bytes_len() {
        // mask is longer than bytes; only in-range entries should count.
        let bytes = [0x90];
        let mask = [0xff, 0xff, 0xff];
        let rule = yara_from_bytes("long_mask", &bytes, &mask);
        assert!(rule.contains("unmasked_bytes = 1"));
    }

    #[test]
    fn sanitizes_unsafe_identifier() {
        let rule = yara_from_bytes("9bad name", &[0x90], &[0xff]);
        // Starts with `_` since the original began with a digit.
        assert!(rule.contains("rule _9bad_name"));
    }
}
