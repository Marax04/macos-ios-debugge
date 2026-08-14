//! YARA string modifier processing engine.
//!
//! Implements the full set of YARA string modifiers:
//! - `nocase`   — case-insensitive comparison (lowercase normalisation)
//! - `wide`     — UTF-16LE interleaving
//! - `fullword` — word-boundary enforcement
//! - `xor`      — XOR scan with all 255 non-zero keys (plus key-range variant)
//! - `base64`   — standard and URL-safe base64 alphabet variants

use serde::{Deserialize, Serialize};

// ── ModifierFlags ─────────────────────────────────────────────────────────────

bitflags::bitflags! {
    /// Modifier flags exactly mirroring YARA string modifiers.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
    pub struct ModifierFlags: u32 {
        const NOCASE   = 0x0001;
        const WIDE     = 0x0002;
        const ASCII    = 0x0004;
        const FULLWORD = 0x0008;
        const PRIVATE  = 0x0010;
        const BASE64   = 0x0020;
        const BASE64WIDE = 0x0040;
        const XOR      = 0x0080;
        /// Applied when `xor` is given with a range, e.g. `xor(0x01-0xff)`.
        const XOR_RANGE = 0x0100;
    }
}

fn deserialize_alphabet<'de, D>(deserializer: D) -> Result<Option<[u8; 64]>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct OptAlphabetVisitor;
    impl<'de> serde::de::Visitor<'de> for OptAlphabetVisitor {
        type Value = Option<[u8; 64]>;
        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("option of 64-byte array")
        }
        fn visit_none<E>(self) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            Ok(None)
        }
        fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            let v: Vec<u8> = serde::Deserialize::deserialize(deserializer)?;
            if v.len() == 64 {
                let mut arr = [0u8; 64];
                arr.copy_from_slice(&v);
                Ok(Some(arr))
            } else {
                Err(serde::de::Error::custom(format!("expected 64 bytes, got {}", v.len())))
            }
        }
    }
    deserializer.deserialize_option(OptAlphabetVisitor)
}

// ── ModifierContext ───────────────────────────────────────────────────────────

/// Describes the modifier configuration for a single YARA string definition.
#[derive(Debug, Clone)]
pub struct ModifierContext {
    pub flags: ModifierFlags,
    /// XOR key range — defaults to `[1, 255]` when `XOR` is set.
    pub xor_min: u8,
    pub xor_max: u8,
    /// Base64 alphabet (length 64). Uses the standard alphabet when `None`.
    pub base64_alphabet: Option<[u8; 64]>,
}

impl serde::Serialize for ModifierContext {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut s = serializer.serialize_struct("ModifierContext", 4)?;
        s.serialize_field("flags", &self.flags)?;
        s.serialize_field("xor_min", &self.xor_min)?;
        s.serialize_field("xor_max", &self.xor_max)?;
        if let Some(arr) = self.base64_alphabet.as_ref() {
            s.serialize_field("base64_alphabet", arr.as_slice())?;
        } else {
            s.serialize_field("base64_alphabet", &Option::<Vec<u8>>::None)?;
        }
        s.end()
    }
}

impl<'de> serde::Deserialize<'de> for ModifierContext {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct Helper {
            flags: ModifierFlags,
            xor_min: u8,
            xor_max: u8,
            #[serde(deserialize_with = "deserialize_alphabet")]
            base64_alphabet: Option<[u8; 64]>,
        }
        let h = Helper::deserialize(deserializer)?;
        Ok(Self { flags: h.flags, xor_min: h.xor_min, xor_max: h.xor_max, base64_alphabet: h.base64_alphabet })
    }
}

impl Default for ModifierContext {
    fn default() -> Self {
        Self {
            flags: ModifierFlags::empty(),
            xor_min: 1,
            xor_max: 255,
            base64_alphabet: None,
        }
    }
}

impl ModifierContext {
    /// Create a context with only `NOCASE`.
    #[must_use]
    pub fn nocase() -> Self {
        Self { flags: ModifierFlags::NOCASE, ..Self::default() }
    }

    /// Create a context with only `WIDE`.
    #[must_use]
    pub fn wide() -> Self {
        Self { flags: ModifierFlags::WIDE, ..Self::default() }
    }

    /// Create a context with `ASCII | WIDE`.
    #[must_use]
    pub fn wide_ascii() -> Self {
        Self {
            flags: ModifierFlags::ASCII | ModifierFlags::WIDE,
            ..Self::default()
        }
    }

    /// Create a context with `FULLWORD`.
    #[must_use]
    pub fn fullword() -> Self {
        Self { flags: ModifierFlags::FULLWORD, ..Self::default() }
    }

    /// Create a context with `XOR` across all non-zero keys.
    #[must_use]
    pub fn xor_all() -> Self {
        Self {
            flags: ModifierFlags::XOR,
            xor_min: 1,
            xor_max: 255,
            ..Self::default()
        }
    }

    /// Create a context with `XOR` limited to a key range.
    #[must_use]
    pub fn xor_range(min: u8, max: u8) -> Self {
        Self {
            flags: ModifierFlags::XOR | ModifierFlags::XOR_RANGE,
            xor_min: min,
            xor_max: max,
            ..Self::default()
        }
    }

    /// Create a context with `BASE64`.
    #[must_use]
    pub fn base64() -> Self {
        Self { flags: ModifierFlags::BASE64, ..Self::default() }
    }
}

// ── MatchResult ───────────────────────────────────────────────────────────────

/// A single raw-bytes match candidate produced by the modifier engine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MatchCandidate {
    /// The transformed pattern bytes to search for.
    pub pattern: Vec<u8>,
    /// The XOR key used (0 means no XOR applied).
    pub xor_key: u8,
    /// Whether this pattern was produced for a wide (UTF-16LE) variant.
    pub is_wide: bool,
    /// The base64 alphabet variant used (0 = standard, 1 = url-safe, 2 = custom).
    pub base64_variant: u8,
}

// ── StringModifierEngine ──────────────────────────────────────────────────────

/// Transforms a raw YARA string pattern into all search candidates
/// according to its modifier set.
pub struct StringModifierEngine;

impl StringModifierEngine {
    /// Generate all pattern variants for the given `raw_bytes` and `ctx`.
    ///
    /// Returns a `Vec<MatchCandidate>` — one entry per transformation. The
    /// caller then searches the data buffer for each candidate independently.
    #[must_use]
    pub fn generate_candidates(raw_bytes: &[u8], ctx: &ModifierContext) -> Vec<MatchCandidate> {
        let mut candidates = Vec::new();

        let do_ascii = ctx.flags.contains(ModifierFlags::ASCII)
            || (!ctx.flags.contains(ModifierFlags::WIDE)
                && !ctx.flags.contains(ModifierFlags::BASE64));
        let do_wide = ctx.flags.contains(ModifierFlags::WIDE);
        let do_base64 = ctx.flags.contains(ModifierFlags::BASE64);
        let do_base64wide = ctx.flags.contains(ModifierFlags::BASE64WIDE);
        let do_xor = ctx.flags.contains(ModifierFlags::XOR);
        let do_nocase = ctx.flags.contains(ModifierFlags::NOCASE);

        // ── ASCII variants ────────────────────────────────────────────────────
        if do_ascii {
            let ascii_bytes = if do_nocase {
                Self::nocase_transform(raw_bytes)
            } else {
                raw_bytes.to_vec()
            };

            if do_xor {
                for key in ctx.xor_min..=ctx.xor_max {
                    let xored = Self::xor_bytes(&ascii_bytes, key);
                    candidates.push(MatchCandidate {
                        pattern: xored,
                        xor_key: key,
                        is_wide: false,
                        base64_variant: 0,
                    });
                }
            } else {
                candidates.push(MatchCandidate {
                    pattern: ascii_bytes,
                    xor_key: 0,
                    is_wide: false,
                    base64_variant: 0,
                });
            }
        }

        // ── Wide (UTF-16LE) variants ───────────────────────────────────────────
        if do_wide {
            let wide_bytes = Self::to_wide(raw_bytes);
            let wide_bytes = if do_nocase {
                Self::nocase_wide_transform(&wide_bytes)
            } else {
                wide_bytes
            };

            if do_xor {
                for key in ctx.xor_min..=ctx.xor_max {
                    let xored = Self::xor_bytes(&wide_bytes, key);
                    candidates.push(MatchCandidate {
                        pattern: xored,
                        xor_key: key,
                        is_wide: true,
                        base64_variant: 0,
                    });
                }
            } else {
                candidates.push(MatchCandidate {
                    pattern: wide_bytes,
                    xor_key: 0,
                    is_wide: true,
                    base64_variant: 0,
                });
            }
        }

        // ── Base64 variants ───────────────────────────────────────────────────
        if do_base64 {
            let alphabet = ctx.base64_alphabet.as_ref();
            for variant in 0u8..3 {
                let encoded = Self::base64_encode(raw_bytes, variant, alphabet);
                candidates.push(MatchCandidate {
                    pattern: encoded,
                    xor_key: 0,
                    is_wide: false,
                    base64_variant: variant,
                });
            }
        }
        if do_base64wide {
            let alphabet = ctx.base64_alphabet.as_ref();
            for variant in 0u8..3 {
                let encoded = Self::base64_encode(raw_bytes, variant, alphabet);
                let wide = Self::to_wide(&encoded);
                candidates.push(MatchCandidate {
                    pattern: wide,
                    xor_key: 0,
                    is_wide: true,
                    base64_variant: variant,
                });
            }
        }

        candidates
    }

    // ── Fullword filter ────────────────────────────────────────────────────────

    /// Filter match offsets to those that satisfy the `fullword` boundary rule.
    ///
    /// A `fullword` match requires that the byte immediately before the match
    /// (if any) and the byte immediately after (if any) are not alphanumeric
    /// and not `_`. For wide strings the step between boundary bytes is 2.
    #[must_use]
    pub fn filter_fullword(
        offsets: &[usize],
        pattern_len: usize,
        data: &[u8],
        is_wide: bool,
    ) -> Vec<usize> {
        let step = if is_wide { 2 } else { 1 };
        offsets
            .iter()
            .copied()
            .filter(|&off| {
                let before_ok = if off == 0 {
                    true
                } else {
                    let b = data[off - step];
                    !b.is_ascii_alphanumeric() && b != b'_'
                };
                let after = off + pattern_len;
                let after_ok = if after >= data.len() {
                    true
                } else {
                    let b = data[after];
                    !b.is_ascii_alphanumeric() && b != b'_'
                };
                before_ok && after_ok
            })
            .collect()
    }

    // ── NOCASE ─────────────────────────────────────────────────────────────────

    /// Normalise bytes to lowercase ASCII for case-insensitive comparison.
    ///
    /// Only ASCII letters are lowercased; all other bytes pass through unchanged.
    #[must_use]
    pub fn nocase_transform(bytes: &[u8]) -> Vec<u8> {
        bytes.iter().map(u8::to_ascii_lowercase).collect()
    }

    /// Apply nocase normalisation to a UTF-16LE buffer (only the low byte of
    /// each code unit is ASCII-lowercased; the high byte is always 0 in BMP).
    #[must_use]
    pub fn nocase_wide_transform(wide: &[u8]) -> Vec<u8> {
        let mut result = wide.to_vec();
        let mut i = 0;
        while i + 1 < result.len() {
            result[i] = result[i].to_ascii_lowercase();
            i += 2;
        }
        result
    }

    // ── WIDE ──────────────────────────────────────────────────────────────────

    /// Interleave ASCII bytes with zero bytes to produce a UTF-16LE buffer.
    #[must_use]
    pub fn to_wide(ascii: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(ascii.len() * 2);
        for &b in ascii {
            out.push(b);
            out.push(0);
        }
        out
    }

    /// Convert a UTF-16LE buffer back to its ASCII representation (lossy).
    #[must_use]
    pub fn from_wide(wide: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(wide.len() / 2);
        let mut i = 0;
        while i + 1 < wide.len() {
            let lo = wide[i];
            let hi = wide[i + 1];
            if hi == 0 {
                out.push(lo);
            } else {
                // Non-BMP code unit: emit replacement '?'
                out.push(b'?');
            }
            i += 2;
        }
        out
    }

    // ── XOR ───────────────────────────────────────────────────────────────────

    /// XOR every byte of `input` with `key`.
    #[must_use]
    pub fn xor_bytes(input: &[u8], key: u8) -> Vec<u8> {
        input.iter().map(|&b| b ^ key).collect()
    }

    /// Generate all 255 XOR variants (keys 1–255) of `input`.
    #[must_use]
    pub fn all_xor_variants(input: &[u8]) -> Vec<(u8, Vec<u8>)> {
        (1u8..=255)
            .map(|key| (key, Self::xor_bytes(input, key)))
            .collect()
    }

    /// Generate XOR variants for a key range `[min, max]` (inclusive).
    #[must_use]
    pub fn xor_range_variants(input: &[u8], min: u8, max: u8) -> Vec<(u8, Vec<u8>)> {
        let lo = min.min(max);
        let hi = min.max(max);
        (lo..=hi).map(|key| (key, Self::xor_bytes(input, key))).collect()
    }

    /// Detect the most likely XOR key by counting matches in `data` against
    /// `plaintext` XOR'd with each key.  Returns the (key, `match_count`) pair
    /// with the highest match count.
    #[must_use]
    pub fn detect_xor_key(plaintext: &[u8], data: &[u8]) -> (u8, usize) {
        let mut best = (0u8, 0usize);
        for key in 1u8..=255 {
            let variant = Self::xor_bytes(plaintext, key);
            let count = Self::count_occurrences(&variant, data);
            if count > best.1 {
                best = (key, count);
            }
        }
        best
    }

    fn count_occurrences(needle: &[u8], haystack: &[u8]) -> usize {
        if needle.is_empty() || needle.len() > haystack.len() {
            return 0;
        }
        haystack.windows(needle.len()).filter(|w| *w == needle).count()
    }

    // ── BASE64 ────────────────────────────────────────────────────────────────

    const BASE64_STANDARD: &'static [u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    const BASE64_URLSAFE: &'static [u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    const BASE64_IMAP: &'static [u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+,";

    /// Encode `input` using the specified base64 variant.
    ///
    /// - `variant = 0` → standard (+/)
    /// - `variant = 1` → URL-safe (-_)
    /// - `variant = 2` → custom or IMAP (+,)
    #[must_use]
    pub fn base64_encode(input: &[u8], variant: u8, custom: Option<&[u8; 64]>) -> Vec<u8> {
        let alpha: &[u8; 64] = match variant {
            0 => Self::BASE64_STANDARD,
            1 => Self::BASE64_URLSAFE,
            _ => custom.unwrap_or(Self::BASE64_IMAP),
        };
        let mut out = Vec::with_capacity(input.len().div_ceil(3) * 4);
        let mut i = 0;
        while i + 2 < input.len() {
            let b0 = input[i] as usize;
            let b1 = input[i + 1] as usize;
            let b2 = input[i + 2] as usize;
            out.push(alpha[b0 >> 2]);
            out.push(alpha[((b0 & 0x03) << 4) | (b1 >> 4)]);
            out.push(alpha[((b1 & 0x0F) << 2) | (b2 >> 6)]);
            out.push(alpha[b2 & 0x3F]);
            i += 3;
        }
        let rem = input.len() - i;
        if rem == 1 {
            let b0 = input[i] as usize;
            out.push(alpha[b0 >> 2]);
            out.push(alpha[(b0 & 0x03) << 4]);
            out.push(b'=');
            out.push(b'=');
        } else if rem == 2 {
            let b0 = input[i] as usize;
            let b1 = input[i + 1] as usize;
            out.push(alpha[b0 >> 2]);
            out.push(alpha[((b0 & 0x03) << 4) | (b1 >> 4)]);
            out.push(alpha[(b1 & 0x0F) << 2]);
            out.push(b'=');
        }
        out
    }

    /// Decode a standard base64 string. Returns `None` for invalid input.
    #[must_use]
    pub fn base64_decode_standard(input: &[u8]) -> Option<Vec<u8>> {
        Self::base64_decode(input, Self::BASE64_STANDARD)
    }

    /// Decode using a custom 64-character alphabet. Returns `None` on error.
    #[must_use]
    pub fn base64_decode(input: &[u8], alpha: &[u8; 64]) -> Option<Vec<u8>> {
        // Build reverse table
        let mut table = [0xFFu8; 256];
        for (i, &c) in alpha.iter().enumerate() {
            table[c as usize] = u8::try_from(i).unwrap_or(0xFF);
        }

        let mut out = Vec::with_capacity(input.len() * 3 / 4);
        let mut idx = 0;
        let stripped: Vec<u8> = input.iter().copied().filter(|&byte| byte != b'=').collect();
        while idx + 3 < stripped.len() {
            let b0 = table[stripped[idx] as usize];
            let b1 = table[stripped[idx + 1] as usize];
            let b2 = table[stripped[idx + 2] as usize];
            let b3 = table[stripped[idx + 3] as usize];
            if b0 == 0xFF || b1 == 0xFF || b2 == 0xFF || b3 == 0xFF {
                return None;
            }
            out.push((b0 << 2) | (b1 >> 4));
            out.push(((b1 & 0x0F) << 4) | (b2 >> 2));
            out.push(((b2 & 0x03) << 6) | b3);
            idx += 4;
        }
        let rem = stripped.len() - idx;
        if rem == 2 {
            let b0 = table[stripped[idx] as usize];
            let b1 = table[stripped[idx + 1] as usize];
            if b0 == 0xFF || b1 == 0xFF { return None; }
            out.push((b0 << 2) | (b1 >> 4));
        } else if rem == 3 {
            let b0 = table[stripped[idx] as usize];
            let b1 = table[stripped[idx + 1] as usize];
            let b2 = table[stripped[idx + 2] as usize];
            if b0 == 0xFF || b1 == 0xFF || b2 == 0xFF { return None; }
            out.push((b0 << 2) | (b1 >> 4));
            out.push(((b1 & 0x0F) << 4) | (b2 >> 2));
        }
        Some(out)
    }

    // ── High-level scan ───────────────────────────────────────────────────────

    /// Scan `data` for all occurrences of `pattern`.
    ///
    /// When `nocase` is set both `data` window and `pattern` are lowercased
    /// before comparison. Returns a sorted list of byte offsets.
    #[must_use]
    pub fn scan(data: &[u8], pattern: &[u8], nocase: bool) -> Vec<usize> {
        if pattern.is_empty() {
            return vec![];
        }
        if nocase {
            let pat_lower: Vec<u8> = pattern.iter().map(u8::to_ascii_lowercase).collect();
            data.windows(pat_lower.len())
                .enumerate()
                .filter_map(|(i, w)| {
                    let win_lower: Vec<u8> = w.iter().map(u8::to_ascii_lowercase).collect();
                    if win_lower == pat_lower { Some(i) } else { None }
                })
                .collect()
        } else {
            data.windows(pattern.len())
                .enumerate()
                .filter_map(|(i, w)| if w == pattern { Some(i) } else { None })
                .collect()
        }
    }
}

// ── ModifierPipeline ──────────────────────────────────────────────────────────

/// A pipeline that applies a sequence of modifiers and searches for all
/// resulting candidates in a data buffer.
pub struct ModifierPipeline {
    pub context: ModifierContext,
}

/// A single scan hit with associated metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanHit {
    pub offset: usize,
    pub length: usize,
    pub xor_key: u8,
    pub is_wide: bool,
    pub base64_variant: u8,
}

impl ModifierPipeline {
    /// Create a new pipeline with the given modifier context.
    #[must_use]
    pub const fn new(ctx: ModifierContext) -> Self {
        Self { context: ctx }
    }

    /// Scan `data` for all occurrences of `pattern` under the configured
    /// modifiers. Returns a list of [`ScanHit`] records.
    #[must_use]
    pub fn scan_all(&self, pattern: &[u8], data: &[u8]) -> Vec<ScanHit> {
        let candidates = StringModifierEngine::generate_candidates(pattern, &self.context);
        let fullword = self.context.flags.contains(ModifierFlags::FULLWORD);
        let nocase = self.context.flags.contains(ModifierFlags::NOCASE);
        let mut hits = Vec::new();

        for candidate in &candidates {
            let offsets = StringModifierEngine::scan(data, &candidate.pattern, nocase);
            let offsets = if fullword {
                StringModifierEngine::filter_fullword(
                    &offsets,
                    candidate.pattern.len(),
                    data,
                    candidate.is_wide,
                )
            } else {
                offsets
            };
            for off in offsets {
                hits.push(ScanHit {
                    offset: off,
                    length: candidate.pattern.len(),
                    xor_key: candidate.xor_key,
                    is_wide: candidate.is_wide,
                    base64_variant: candidate.base64_variant,
                });
            }
        }

        hits.sort_by_key(|h| h.offset);
        hits
    }

    /// Return the number of distinct XOR keys that would be tested.
    #[must_use]
    pub fn xor_key_count(&self) -> usize {
        if self.context.flags.contains(ModifierFlags::XOR) {
            let lo = self.context.xor_min;
            let hi = self.context.xor_max;
            usize::from(hi.saturating_sub(lo)) + 1
        } else {
            0
        }
    }
}

// ── EncodingStats ─────────────────────────────────────────────────────────────

/// Aggregate statistics about the modifier candidates for a pattern.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct EncodingStats {
    pub ascii_variants: usize,
    pub wide_variants: usize,
    pub base64_variants: usize,
    pub xor_variants: usize,
    pub total_candidates: usize,
}

impl EncodingStats {
    /// Compute stats for a pattern with the given modifier context.
    #[must_use]
    pub fn compute(pattern: &[u8], ctx: &ModifierContext) -> Self {
        let candidates = StringModifierEngine::generate_candidates(pattern, ctx);
        let mut stats = Self::default();
        for c in &candidates {
            stats.total_candidates += 1;
            if c.xor_key != 0 {
                stats.xor_variants += 1;
            }
            if c.is_wide {
                stats.wide_variants += 1;
            } else if c.base64_variant > 0 || (!c.is_wide && c.xor_key == 0) {
                stats.ascii_variants += 1;
            }
            if c.base64_variant > 0 {
                stats.base64_variants += 1;
            }
        }
        stats
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nocase_transform_lowercase() {
        let result = StringModifierEngine::nocase_transform(b"Hello World");
        assert_eq!(result, b"hello world");
    }

    #[test]
    fn test_nocase_transform_non_ascii_unchanged() {
        let input = &[0xDE, 0xAD, b'A'];
        let result = StringModifierEngine::nocase_transform(input);
        assert_eq!(result[0], 0xDE);
        assert_eq!(result[2], b'a');
    }

    #[test]
    fn test_wide_interleave() {
        let result = StringModifierEngine::to_wide(b"AB");
        assert_eq!(result, &[b'A', 0, b'B', 0]);
    }

    #[test]
    fn test_from_wide_roundtrip() {
        let wide = StringModifierEngine::to_wide(b"Hello");
        let back = StringModifierEngine::from_wide(&wide);
        assert_eq!(back, b"Hello");
    }

    #[test]
    fn test_xor_bytes_key_1() {
        let result = StringModifierEngine::xor_bytes(b"ABC", 1);
        assert_eq!(result, &[b'A' ^ 1, b'B' ^ 1, b'C' ^ 1]);
    }

    #[test]
    fn test_xor_roundtrip() {
        let original = b"secret";
        let xored = StringModifierEngine::xor_bytes(original, 0x42);
        let back = StringModifierEngine::xor_bytes(&xored, 0x42);
        assert_eq!(&back, original);
    }

    #[test]
    fn test_all_xor_variants_count() {
        let variants = StringModifierEngine::all_xor_variants(b"X");
        assert_eq!(variants.len(), 255);
        assert!(variants.iter().all(|(key, _)| *key >= 1));
    }

    #[test]
    fn test_xor_range_variants() {
        let variants = StringModifierEngine::xor_range_variants(b"Y", 10, 20);
        assert_eq!(variants.len(), 11);
        assert_eq!(variants[0].0, 10);
        assert_eq!(variants[10].0, 20);
    }

    #[test]
    fn test_base64_encode_standard() {
        let encoded = StringModifierEngine::base64_encode(b"Man", 0, None);
        assert_eq!(encoded, b"TWFu");
    }

    #[test]
    fn test_base64_encode_padding_one_byte() {
        let encoded = StringModifierEngine::base64_encode(b"M", 0, None);
        assert_eq!(encoded, b"TQ==");
    }

    #[test]
    fn test_base64_encode_padding_two_bytes() {
        let encoded = StringModifierEngine::base64_encode(b"Ma", 0, None);
        assert_eq!(encoded, b"TWE=");
    }

    #[test]
    fn test_base64_decode_roundtrip() {
        let original = b"Hello, YARA!";
        let encoded = StringModifierEngine::base64_encode(original, 0, None);
        let decoded = StringModifierEngine::base64_decode_standard(&encoded).unwrap();
        assert_eq!(&decoded, original);
    }

    #[test]
    fn test_base64_urlsafe_differs_from_standard() {
        let data = &[0b1111_1011, 0b1110_1111];
        let std = StringModifierEngine::base64_encode(data, 0, None);
        let url = StringModifierEngine::base64_encode(data, 1, None);
        // Standard uses '+' and '/' while URL-safe uses '-' and '_'
        assert_ne!(std, url);
    }

    #[test]
    fn test_scan_basic() {
        let offsets = StringModifierEngine::scan(b"hello world hello", b"hello", false);
        assert_eq!(offsets, vec![0, 12]);
    }

    #[test]
    fn test_scan_nocase() {
        let offsets = StringModifierEngine::scan(b"Hello World HELLO", b"hello", true);
        assert_eq!(offsets, vec![0, 12]);
    }

    #[test]
    fn test_fullword_filter_basic() {
        let data = b"foo hello world";
        let offsets = StringModifierEngine::filter_fullword(&[4], 5, data, false);
        assert_eq!(offsets, vec![4]);
    }

    #[test]
    fn test_fullword_filter_rejects_nonword() {
        let data = b"foohelloworld";
        let offsets = StringModifierEngine::filter_fullword(&[3], 5, data, false);
        assert!(offsets.is_empty());
    }

    #[test]
    fn test_generate_candidates_ascii_only() {
        let ctx = ModifierContext::default();
        let mut ctx2 = ctx;
        ctx2.flags = ModifierFlags::ASCII;
        let cands = StringModifierEngine::generate_candidates(b"test", &ctx2);
        assert_eq!(cands.len(), 1);
        assert!(!cands[0].is_wide);
    }

    #[test]
    fn test_generate_candidates_wide_adds_wide() {
        let ctx = ModifierContext::wide();
        let cands = StringModifierEngine::generate_candidates(b"test", &ctx);
        assert!(cands.iter().any(|c| c.is_wide));
    }

    #[test]
    fn test_generate_candidates_xor_count() {
        let ctx = ModifierContext::xor_all();
        let cands = StringModifierEngine::generate_candidates(b"hi", &ctx);
        assert_eq!(cands.len(), 255);
        assert!(cands.iter().all(|c| c.xor_key != 0));
    }

    #[test]
    fn test_generate_candidates_xor_range() {
        let ctx = ModifierContext::xor_range(5, 10);
        let cands = StringModifierEngine::generate_candidates(b"hi", &ctx);
        assert_eq!(cands.len(), 6);
    }

    #[test]
    fn test_generate_candidates_base64_three_variants() {
        let ctx = ModifierContext::base64();
        let cands = StringModifierEngine::generate_candidates(b"password", &ctx);
        assert_eq!(cands.len(), 3);
        assert!(cands.iter().all(|c| !c.is_wide));
    }

    #[test]
    fn test_pipeline_scan_hit_found() {
        let ctx = ModifierContext::default();
        let mut ctx2 = ctx;
        ctx2.flags = ModifierFlags::ASCII;
        let pipeline = ModifierPipeline::new(ctx2);
        let hits = pipeline.scan_all(b"hello", b"say hello world");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].offset, 4);
    }

    #[test]
    fn test_pipeline_nocase_hit() {
        let ctx = ModifierContext::nocase();
        let pipeline = ModifierPipeline::new(ctx);
        let hits = pipeline.scan_all(b"HELLO", b"say hello world");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].offset, 4);
    }

    #[test]
    fn test_pipeline_xor_hit() {
        let key = 0x42u8;
        let plain = b"secret";
        let mut data = b"padding".to_vec();
        data.extend(plain.iter().map(|&b| b ^ key));
        data.extend(b"padding");

        let ctx = ModifierContext::xor_range(key, key);
        let pipeline = ModifierPipeline::new(ctx);
        let hits = pipeline.scan_all(plain, &data);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].xor_key, key);
    }

    #[test]
    fn test_pipeline_xor_key_count() {
        let ctx = ModifierContext::xor_all();
        let pipeline = ModifierPipeline::new(ctx);
        assert_eq!(pipeline.xor_key_count(), 255);
    }

    #[test]
    fn test_encoding_stats() {
        let ctx = ModifierContext { flags: ModifierFlags::ASCII | ModifierFlags::XOR, xor_min: 1, xor_max: 10, base64_alphabet: None };
        let stats = EncodingStats::compute(b"test", &ctx);
        assert_eq!(stats.total_candidates, 10);
        assert_eq!(stats.xor_variants, 10);
    }

    #[test]
    fn test_detect_xor_key() {
        let key = 0x37u8;
        let plain = b"malware_signature";
        let xored = StringModifierEngine::xor_bytes(plain, key);
        let mut data = vec![0u8; 50];
        data[10..10 + xored.len()].copy_from_slice(&xored);
        let (detected_key, count) = StringModifierEngine::detect_xor_key(plain, &data);
        assert_eq!(detected_key, key);
        assert_eq!(count, 1);
    }
}
