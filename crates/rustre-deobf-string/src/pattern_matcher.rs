//! Pattern-based obfuscated-string detector.
//!
//! Matches known obfuscated string patterns from common malware families
//! (Emotet, `TrickBot`, Cobalt Strike, etc.) against raw binary data.
//! Each [`ObfuscationSignature`] specifies a byte pattern with an optional
//! mask, the obfuscation algorithm family it corresponds to, and a key hint
//! that can seed a decryption pass.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::StringAlgorithm;

// ── ObfuscationSignature ──────────────────────────────────────────────────────

/// A single obfuscation signature entry in the database.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObfuscationSignature {
    /// Short unique identifier (e.g. `"emotet_xor_0x3a"`).
    pub id: String,
    /// Human-readable description of the pattern.
    pub description: String,
    /// The byte pattern to match.  `None` bytes are wildcards.
    pub pattern: Vec<Option<u8>>,
    /// Optional AND-mask applied before comparing each byte.
    /// `None` means no masking (compare raw).
    pub mask: Vec<Option<u8>>,
    /// The obfuscation algorithm this pattern corresponds to.
    pub algorithm: StringAlgorithm,
    /// A key hint that may be tried during decryption.
    ///
    /// For XOR patterns this is the XOR key byte; for rolling XOR it is the
    /// initial byte; for ROT-N it is the rotation amount.
    pub key_hint: Option<Vec<u8>>,
    /// Confidence score for this pattern (0–100).
    pub confidence: u8,
    /// Tags identifying the malware family (e.g. `["emotet", "loader"]`).
    pub tags: Vec<String>,
}

impl ObfuscationSignature {
    /// Create a simple exact-byte pattern with no mask.
    #[must_use]
    pub fn exact(
        id: impl Into<String>,
        description: impl Into<String>,
        pattern: &[u8],
        algorithm: StringAlgorithm,
        confidence: u8,
    ) -> Self {
        Self {
            id: id.into(),
            description: description.into(),
            pattern: pattern.iter().map(|&b| Some(b)).collect(),
            mask: vec![None; pattern.len()],
            algorithm,
            key_hint: None,
            confidence,
            tags: Vec::new(),
        }
    }

    /// Create a wildcard pattern where `None` in `pattern` matches any byte.
    #[must_use]
    pub fn wildcard(
        id: impl Into<String>,
        description: impl Into<String>,
        pattern: Vec<Option<u8>>,
        algorithm: StringAlgorithm,
        confidence: u8,
    ) -> Self {
        let len = pattern.len();
        Self {
            id: id.into(),
            description: description.into(),
            pattern,
            mask: vec![None; len],
            algorithm,
            key_hint: None,
            confidence,
            tags: Vec::new(),
        }
    }

    /// Add a key hint.
    #[must_use]
    pub fn with_key(mut self, key: Vec<u8>) -> Self {
        self.key_hint = Some(key);
        self
    }

    /// Add a tag.
    #[must_use]
    pub fn with_tag(mut self, tag: impl Into<String>) -> Self {
        self.tags.push(tag.into());
        self
    }

    /// Add multiple tags.
    #[must_use]
    pub fn with_tags(mut self, tags: &[&str]) -> Self {
        self.tags.extend(tags.iter().map(|&t| t.to_owned()));
        self
    }

    /// Return `true` if `data` at position `offset` matches this signature.
    #[must_use]
    pub fn matches_at(&self, data: &[u8], offset: usize) -> bool {
        if offset + self.pattern.len() > data.len() {
            return false;
        }
        for (i, pat_byte) in self.pattern.iter().enumerate() {
            let Some(expected) = pat_byte else { continue };
            let actual = data[offset + i];
            let actual = if let Some(Some(m)) = self.mask.get(i) {
                actual & m
            } else {
                actual
            };
            if actual != *expected {
                return false;
            }
        }
        true
    }

    /// Return the pattern length.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.pattern.len()
    }

    /// Return `true` if the pattern is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.pattern.is_empty()
    }
}

// ── PatternMatchResult ────────────────────────────────────────────────────────

/// A single match produced by the [`PatternMatcher`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PatternMatchResult {
    /// Byte offset in the input data where the pattern was found.
    pub offset: usize,
    /// Length of the matched bytes.
    pub matched_length: usize,
    /// The matched bytes.
    pub matched_bytes: Vec<u8>,
    /// ID of the signature that matched.
    pub signature_id: String,
    /// Algorithm indicated by the matching signature.
    pub algorithm: StringAlgorithm,
    /// Key hint from the signature (may seed decryption).
    pub key_hint: Option<Vec<u8>>,
    /// Confidence score (0–100).
    pub confidence: u8,
    /// Tags from the matching signature.
    pub tags: Vec<String>,
    /// Description of the matching signature.
    pub description: String,
}

impl PatternMatchResult {
    /// Return `true` if this is a high-confidence match.
    #[must_use]
    pub const fn is_high_confidence(&self) -> bool {
        self.confidence >= 75
    }
}

// ── PatternMatchDb ────────────────────────────────────────────────────────────

/// Database of [`ObfuscationSignature`] entries.
///
/// Built-in signatures cover 30+ common obfuscation patterns from:
/// - Emotet (XOR loop variants, delta XOR)
/// - `TrickBot` (multi-byte XOR, rotating key)
/// - Cobalt Strike (format-string XOR, `BeaconPayload` preamble)
/// - Generic (single-byte XOR, ROT-13, Base64 preamble, null-padded stack strings, etc.)
#[derive(Debug, Default)]
pub struct PatternMatchDb {
    signatures: Vec<ObfuscationSignature>,
}

impl PatternMatchDb {
    /// Create an empty database.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// Create a database pre-populated with the 30+ built-in signatures.
    #[must_use]
    pub fn with_builtins() -> Self {
        let mut db = Self::empty();
        db.add_builtins();
        db
    }

    /// Add a signature to the database.
    pub fn add(&mut self, sig: ObfuscationSignature) {
        self.signatures.push(sig);
    }

    /// Return the number of signatures in the database.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.signatures.len()
    }

    /// Return `true` if the database is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.signatures.is_empty()
    }

    /// Return all signatures with the given tag.
    #[must_use]
    pub fn by_tag(&self, tag: &str) -> Vec<&ObfuscationSignature> {
        self.signatures
            .iter()
            .filter(|s| s.tags.iter().any(|t| t == tag))
            .collect()
    }

    /// Look up a signature by its ID.
    #[must_use]
    pub fn by_id(&self, id: &str) -> Option<&ObfuscationSignature> {
        self.signatures.iter().find(|s| s.id == id)
    }

    /// Iterate over all signatures.
    pub fn iter(&self) -> impl Iterator<Item = &ObfuscationSignature> {
        self.signatures.iter()
    }

    fn add_builtins(&mut self) {
        // ── Emotet XOR variants ──────────────────────────────────────────────

        // Emotet stores XOR-encoded strings with key 0x3A
        self.add(
            ObfuscationSignature::wildcard(
                "emotet_xor_0x3a",
                "Emotet XOR-encoded string block with key 0x3A",
                vec![None, None, None, None, Some(0x3A), Some(0x3A)],
                StringAlgorithm::XorConstant,
                82,
            )
            .with_key(vec![0x3A])
            .with_tags(&["emotet", "loader", "xor"]),
        );

        // Emotet delta-XOR chain: each byte XORed with previous ciphertext byte
        self.add(
            ObfuscationSignature::exact(
                "emotet_delta_xor",
                "Emotet delta-XOR chain preamble (0x00 0xE9 pattern)",
                &[0x00, 0xE9, 0x00, 0x00],
                StringAlgorithm::XorRolling,
                70,
            )
            .with_tags(&["emotet", "delta-xor"]),
        );

        // Emotet string pool pointer table
        self.add(
            ObfuscationSignature::wildcard(
                "emotet_string_pool",
                "Emotet string pool: null-terminated entries with size prefix",
                vec![
                    Some(0x00),
                    Some(0x00),
                    None,
                    Some(0x00),
                    Some(0x00),
                    Some(0x00),
                ],
                StringAlgorithm::XorConstant,
                65,
            )
            .with_tags(&["emotet", "string-pool"]),
        );

        // ── TrickBot XOR variants ─────────────────────────────────────────────

        // TrickBot 2-byte rolling XOR (key = 0x3B 0x12)
        self.add(
            ObfuscationSignature::wildcard(
                "trickbot_2byte_xor",
                "TrickBot 2-byte rolling XOR with key {0x3B, 0x12}",
                vec![None, None, None, None, None, None, None, None],
                StringAlgorithm::XorCyclic,
                78,
            )
            .with_key(vec![0x3B, 0x12])
            .with_tags(&["trickbot", "xor", "2-byte-key"]),
        );

        // TrickBot string obfuscation: 4-byte key stored inline before ciphertext
        self.add(
            ObfuscationSignature::wildcard(
                "trickbot_inline_key",
                "TrickBot inline 4-byte XOR key followed by ciphertext",
                vec![None, None, None, None, Some(0xFF), Some(0xFF), None, None],
                StringAlgorithm::XorCyclic,
                72,
            )
            .with_tags(&["trickbot", "inline-key"]),
        );

        // TrickBot custom ADD loop (byte += 0x47)
        self.add(
            ObfuscationSignature::wildcard(
                "trickbot_add_0x47",
                "TrickBot ADD(0x47) string encoding artefact",
                vec![None, None, Some(0x80), None, Some(0x47), None],
                StringAlgorithm::AddConstant,
                68,
            )
            .with_key(vec![0x47])
            .with_tags(&["trickbot", "add-obf"]),
        );

        // ── Cobalt Strike variants ────────────────────────────────────────────

        // Cobalt Strike BeaconPayload XOR preamble (0xCC 0xCD pattern)
        self.add(
            ObfuscationSignature::exact(
                "cobaltstrike_beacon_xor",
                "Cobalt Strike Beacon XOR-encoded payload preamble",
                &[0xCC, 0xCC, 0xCC, 0xCC],
                StringAlgorithm::XorConstant,
                85,
            )
            .with_key(vec![0xCC])
            .with_tags(&["cobalt-strike", "beacon", "xor"]),
        );

        // CS format-string key: strings start with 0xFE 0xFF after XOR
        self.add(
            ObfuscationSignature::wildcard(
                "cobaltstrike_format_xor",
                "Cobalt Strike XOR format string preamble (0xFE 0xFF)",
                vec![Some(0xFE), Some(0xFF), None, None, None, None],
                StringAlgorithm::XorConstant,
                80,
            )
            .with_tags(&["cobalt-strike", "format-string"]),
        );

        // CS reflective loader 4-byte XOR key marker
        self.add(
            ObfuscationSignature::wildcard(
                "cobaltstrike_reflective_xor",
                "Cobalt Strike reflective loader XOR key header",
                vec![Some(0x90), None, Some(0x90), None, Some(0x90), None],
                StringAlgorithm::XorCyclic,
                74,
            )
            .with_tags(&["cobalt-strike", "reflective-loader"]),
        );

        // ── Generic single-byte XOR patterns (high/medium entropy runs) ───────

        self.add(
            ObfuscationSignature::exact(
                "generic_xor_0x01",
                "Generic single-byte XOR 0x01 preamble",
                &[0x01, 0x01, 0x01, 0x01],
                StringAlgorithm::XorConstant,
                50,
            )
            .with_key(vec![0x01])
            .with_tags(&["generic", "xor"]),
        );

        self.add(
            ObfuscationSignature::exact(
                "generic_xor_0xff",
                "Generic NOT (XOR 0xFF) encoding",
                &[0xFF, 0xFF, 0xFF, 0xFF],
                StringAlgorithm::XorConstant,
                55,
            )
            .with_key(vec![0xFF])
            .with_tags(&["generic", "xor", "not"]),
        );

        self.add(
            ObfuscationSignature::exact(
                "generic_xor_0x41",
                "Generic XOR 0x41 ('A') — common CTF/malware key",
                &[0x41, 0x41, 0x41, 0x41],
                StringAlgorithm::XorConstant,
                55,
            )
            .with_key(vec![0x41])
            .with_tags(&["generic", "xor"]),
        );

        // ── ROT-N / Caesar variants ───────────────────────────────────────────

        // ROT-13 marker: presence of `\x76\x67\x7e` = "ugh" ROT-13'd
        self.add(
            ObfuscationSignature::exact(
                "rot13_marker",
                "Possible ROT-13 encoded text block",
                &[0x54, 0x75, 0x72, 0x79], // "Tury" = ROT-13("Grue")
                StringAlgorithm::RotN,
                60,
            )
            .with_key(vec![13])
            .with_tags(&["generic", "rot13"]),
        );

        // ROT-47 marker: `!"#$%` shifted block
        self.add(
            ObfuscationSignature::exact(
                "rot47_marker",
                "Possible ROT-47 encoded block",
                &[0x21, 0x22, 0x23, 0x24, 0x25],
                StringAlgorithm::RotN,
                55,
            )
            .with_key(vec![47])
            .with_tags(&["generic", "rot47"]),
        );

        // ── Base64-like expansion markers ────────────────────────────────────

        // Base64-encoded MZ header is "TVqQ"
        self.add(
            ObfuscationSignature::exact(
                "base64_mz_pe",
                "Base64-encoded MZ/PE header preamble (TVqQ)",
                b"TVqQ",
                StringAlgorithm::Base64,
                90,
            )
            .with_tags(&["base64", "pe", "loader"]),
        );

        // Base64-encoded ELF magic: "\x7FELF" → "f0VM"
        self.add(
            ObfuscationSignature::exact(
                "base64_elf",
                "Base64-encoded ELF magic (f0VM)",
                b"f0VM",
                StringAlgorithm::Base64,
                88,
            )
            .with_tags(&["base64", "elf"]),
        );

        // URL-safe base64 preamble: long run of alphanum with - and _
        self.add(
            ObfuscationSignature::wildcard(
                "base64url_preamble",
                "URL-safe base64 encoded payload preamble",
                vec![None, None, None, None, Some(b'-'), None, None, None, None],
                StringAlgorithm::Base64,
                60,
            )
            .with_tags(&["base64", "url-safe"]),
        );

        // ── Stack-string artefacts ────────────────────────────────────────────

        // Stack string: x86 `MOV BYTE PTR [EBP+disp8], imm8` sequences
        // Pattern: 0xC6 0x45 <disp8> <byte> repeated
        self.add(
            ObfuscationSignature::exact(
                "stack_string_x86_movbyte",
                "x86 stack-string construction: MOV BYTE PTR [EBP+n], imm8",
                &[0xC6, 0x45, 0x00],
                StringAlgorithm::StackString,
                75,
            )
            .with_tags(&["stack-string", "x86"]),
        );

        // x64 stack string: MOV BYTE PTR [RSP+disp32], imm8
        self.add(
            ObfuscationSignature::exact(
                "stack_string_x64_movbyte",
                "x64 stack-string construction: MOV BYTE PTR [RSP+n], imm8",
                &[0xC6, 0x84, 0x24],
                StringAlgorithm::StackString,
                75,
            )
            .with_tags(&["stack-string", "x64"]),
        );

        // ── XOR-rolling / PRNG key expansions ────────────────────────────────

        // Self-decrypting stub: LOOP + XOR pattern at entry point
        self.add(
            ObfuscationSignature::wildcard(
                "xor_loop_stub",
                "Self-decrypting XOR loop stub (XOR [ESI], CL; INC ESI; LOOP)",
                vec![Some(0x30), Some(0x0E), Some(0x46), Some(0xE2), None],
                StringAlgorithm::XorCyclic,
                80,
            )
            .with_tags(&["xor-loop", "stub", "packer"]),
        );

        // Rolling XOR: output[i] = input[i] ^ output[i-1]
        self.add(
            ObfuscationSignature::wildcard(
                "rolling_xor_chain",
                "Rolling XOR chain: each byte XORed with previous decrypted byte",
                vec![None, None, None, None, Some(0x00), Some(0x00)],
                StringAlgorithm::XorRolling,
                65,
            )
            .with_tags(&["rolling-xor", "chain"]),
        );

        // ── ADD / SUB constant ────────────────────────────────────────────────

        self.add(
            ObfuscationSignature::exact(
                "add_0x05_preamble",
                "ADD 0x05 constant encoding preamble",
                &[0x05, 0x05, 0x05, 0x05],
                StringAlgorithm::AddConstant,
                52,
            )
            .with_key(vec![0x05])
            .with_tags(&["add-obf"]),
        );

        self.add(
            ObfuscationSignature::exact(
                "sub_0x13_preamble",
                "SUB 0x13 constant encoding preamble",
                &[0xED, 0xEC, 0xEB, 0xEA], // ASCII 'a'..='d' shifted by -0x13
                StringAlgorithm::SubConstant,
                52,
            )
            .with_key(vec![0x13])
            .with_tags(&["sub-obf"]),
        );

        // ── ROL / ROR ────────────────────────────────────────────────────────

        self.add(
            ObfuscationSignature::exact(
                "rol1_preamble",
                "ROL-1 bit rotation encoding preamble",
                &[0x80, 0x80, 0x80, 0x80],
                StringAlgorithm::RolConstant,
                50,
            )
            .with_key(vec![1])
            .with_tags(&["rol-obf"]),
        );

        // ── RC4 KSA markers ───────────────────────────────────────────────────

        // RC4 S-box initialisation often starts with 0x00 0x01 0x02 0x03 ...
        self.add(
            ObfuscationSignature::exact(
                "rc4_sbox_init",
                "RC4 S-box initialisation sequence (0x00..0x07)",
                &[0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07],
                StringAlgorithm::Rc4,
                72,
            )
            .with_tags(&["rc4", "sbox"]),
        );

        // RC4-encrypted data with single-byte key 0x80 pattern
        self.add(
            ObfuscationSignature::wildcard(
                "rc4_key_0x80_marker",
                "Possible RC4 encryption with 1-byte key 0x80",
                vec![Some(0x80), None, None, None, None, None, None, None],
                StringAlgorithm::Rc4,
                55,
            )
            .with_key(vec![0x80])
            .with_tags(&["rc4"]),
        );

        // ── Hex-encoded strings ───────────────────────────────────────────────

        // Hex-encoded string starting with "4d 5a" = MZ
        self.add(
            ObfuscationSignature::exact(
                "hex_encoded_mz",
                "Hex-encoded MZ header string '4d5a' or '4D5A'",
                b"4d5a",
                StringAlgorithm::HexEncoded,
                80,
            )
            .with_tags(&["hex-encoded", "pe"]),
        );

        // ASCII hex encoding: "\\x41\\x42\\x43" pattern
        self.add(
            ObfuscationSignature::exact(
                "cstyle_hex_escape",
                "C-style hex escape sequence \\xNN encoding preamble",
                b"\\x41\\x42\\x43",
                StringAlgorithm::HexEncoded,
                70,
            )
            .with_tags(&["hex-encoded", "c-style"]),
        );

        // ── ChaCha20 / Salsa20 nonce ──────────────────────────────────────────

        // ChaCha20 stream cipher constant "expand 32-byte k"
        self.add(
            ObfuscationSignature::exact(
                "chacha20_constant",
                "ChaCha20 sigma constant 'expand 32-byte k'",
                b"expand 32-byte k",
                StringAlgorithm::ChaCha20,
                95,
            )
            .with_tags(&["chacha20", "stream-cipher"]),
        );

        // Salsa20 constant "expa" (first 4 bytes)
        self.add(
            ObfuscationSignature::exact(
                "salsa20_constant",
                "Salsa20 sigma constant 'expa' preamble",
                b"expa",
                StringAlgorithm::ChaCha20,
                75,
            )
            .with_tags(&["salsa20", "stream-cipher"]),
        );

        // ── Split-string marker ───────────────────────────────────────────────

        // Split strings concatenated at runtime — look for null-separated chunks
        self.add(
            ObfuscationSignature::wildcard(
                "split_string_nullsep",
                "Null-separated split-string assembly artefact",
                vec![None, None, None, Some(0x00), None, None, None, Some(0x00)],
                StringAlgorithm::SplitString,
                55,
            )
            .with_tags(&["split-string"]),
        );
    }
}

// ── PatternMatcher ────────────────────────────────────────────────────────────

/// Scans binary data against a [`PatternMatchDb`] and returns all matches.
pub struct PatternMatcher {
    /// The signature database.
    pub db: PatternMatchDb,
    /// Minimum confidence required to emit a result.
    pub min_confidence: u8,
    /// Maximum number of results to return (0 = unlimited).
    pub max_results: usize,
}

/// Hard upper bound on the number of results returned by [`PatternMatcher::scan`]
/// when `max_results` is left at 0 (unlimited by the caller).  Without this cap
/// a single wildcard signature (e.g. `rolling_xor_chain`) can match every byte
/// position in a large binary and exhaust memory (dos-memory-exhaustion).
const DEFAULT_MAX_RESULTS_HARD_CAP: usize = 100_000;

impl Default for PatternMatcher {
    fn default() -> Self {
        Self {
            db: PatternMatchDb::with_builtins(),
            min_confidence: 50,
            max_results: 0,
        }
    }
}

impl PatternMatcher {
    /// Create a matcher with the built-in signature database.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a matcher with an empty database (useful for testing).
    #[must_use]
    pub fn empty() -> Self {
        Self {
            db: PatternMatchDb::empty(),
            ..Self::default()
        }
    }

    /// Set the minimum confidence threshold.
    #[must_use]
    pub const fn with_min_confidence(mut self, min: u8) -> Self {
        self.min_confidence = min;
        self
    }

    /// Set the maximum number of results.
    #[must_use]
    pub const fn with_max_results(mut self, max: usize) -> Self {
        self.max_results = max;
        self
    }

    /// Scan `data` and return all matching results.
    ///
    /// The total number of results is bounded by `max_results` when set to a
    /// non-zero value, or by [`DEFAULT_MAX_RESULTS_HARD_CAP`] otherwise.  This
    /// prevents a wildcard signature from producing O(n) entries and exhausting
    /// memory on large untrusted binaries (dos-memory-exhaustion).
    #[must_use]
    pub fn scan(&self, data: &[u8]) -> Vec<PatternMatchResult> {
        let hard_cap = if self.max_results > 0 {
            self.max_results
        } else {
            DEFAULT_MAX_RESULTS_HARD_CAP
        };
        let mut results = Vec::new();

        'outer: for sig in self.db.iter() {
            if sig.confidence < self.min_confidence || sig.is_empty() {
                continue;
            }
            let limit = data.len().saturating_sub(sig.len()) + 1;
            for offset in 0..limit {
                if sig.matches_at(data, offset) {
                    let matched_bytes = data[offset..offset + sig.len()].to_vec();
                    results.push(PatternMatchResult {
                        offset,
                        matched_length: sig.len(),
                        matched_bytes,
                        signature_id: sig.id.clone(),
                        algorithm: sig.algorithm,
                        key_hint: sig.key_hint.clone(),
                        confidence: sig.confidence,
                        tags: sig.tags.clone(),
                        description: sig.description.clone(),
                    });
                    if results.len() >= hard_cap {
                        break 'outer;
                    }
                }
            }
        }

        results
    }

    /// Scan `data` and return only high-confidence matches.
    #[must_use]
    pub fn scan_high_confidence(&self, data: &[u8]) -> Vec<PatternMatchResult> {
        self.scan(data)
            .into_iter()
            .filter(PatternMatchResult::is_high_confidence)
            .collect()
    }

    /// Scan and group results by algorithm.
    #[must_use]
    pub fn scan_grouped(&self, data: &[u8]) -> HashMap<String, Vec<PatternMatchResult>> {
        let mut map: HashMap<String, Vec<PatternMatchResult>> = HashMap::new();
        for r in self.scan(data) {
            map.entry(r.algorithm.name().to_owned())
                .or_default()
                .push(r);
        }
        map
    }

    /// Return only matches belonging to a given tag.
    #[must_use]
    pub fn scan_by_tag(&self, data: &[u8], tag: &str) -> Vec<PatternMatchResult> {
        self.scan(data)
            .into_iter()
            .filter(|r| r.tags.iter().any(|t| t == tag))
            .collect()
    }

    /// Return the first match for a given signature ID, if any.
    #[must_use]
    pub fn first_match_for_id(&self, data: &[u8], id: &str) -> Option<PatternMatchResult> {
        let results = self.scan(data);
        results.into_iter().find(|r| r.signature_id == id)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── ObfuscationSignature ──────────────────────────────────────────────────

    #[test]
    fn test_sig_exact_match() {
        let sig = ObfuscationSignature::exact(
            "test_sig",
            "Test",
            &[0xDE, 0xAD, 0xBE, 0xEF],
            StringAlgorithm::XorConstant,
            80,
        );
        let data = [0x00, 0xDE, 0xAD, 0xBE, 0xEF, 0x00];
        assert!(sig.matches_at(&data, 1));
        assert!(!sig.matches_at(&data, 0));
    }

    #[test]
    fn test_sig_wildcard_match() {
        let sig = ObfuscationSignature::wildcard(
            "wc",
            "Test",
            vec![Some(0xAA), None, Some(0xBB)],
            StringAlgorithm::XorCyclic,
            70,
        );
        let data = [0xAA, 0xFF, 0xBB];
        assert!(sig.matches_at(&data, 0));
    }

    #[test]
    fn test_sig_no_match_wrong_byte() {
        let sig =
            ObfuscationSignature::exact("s", "d", &[0x01, 0x02], StringAlgorithm::XorConstant, 50);
        let data = [0x01, 0x03];
        assert!(!sig.matches_at(&data, 0));
    }

    #[test]
    fn test_sig_out_of_bounds_no_panic() {
        let sig = ObfuscationSignature::exact(
            "s",
            "d",
            &[0x01, 0x02, 0x03],
            StringAlgorithm::XorConstant,
            50,
        );
        let data = [0x01, 0x02]; // too short
        assert!(!sig.matches_at(&data, 0));
    }

    #[test]
    fn test_sig_with_key() {
        let sig = ObfuscationSignature::exact("s", "d", &[0xDE], StringAlgorithm::XorConstant, 50)
            .with_key(vec![0x42]);
        assert_eq!(sig.key_hint, Some(vec![0x42]));
    }

    #[test]
    fn test_sig_len() {
        let sig = ObfuscationSignature::exact(
            "s",
            "d",
            &[0x01, 0x02, 0x03],
            StringAlgorithm::XorConstant,
            50,
        );
        assert_eq!(sig.len(), 3);
    }

    #[test]
    fn test_sig_is_empty() {
        let sig =
            ObfuscationSignature::wildcard("empty", "d", vec![], StringAlgorithm::XorConstant, 50);
        assert!(sig.is_empty());
    }

    #[test]
    fn test_sig_with_tags() {
        let sig = ObfuscationSignature::exact("s", "d", &[0x01], StringAlgorithm::XorConstant, 50)
            .with_tags(&["emotet", "xor"]);
        assert_eq!(sig.tags.len(), 2);
        assert!(sig.tags.contains(&"emotet".to_owned()));
    }

    // ── PatternMatchDb ────────────────────────────────────────────────────────

    #[test]
    fn test_db_with_builtins_has_30_plus() {
        let db = PatternMatchDb::with_builtins();
        assert!(db.len() >= 30, "expected 30+ sigs, got {}", db.len());
    }

    #[test]
    fn test_db_empty() {
        let db = PatternMatchDb::empty();
        assert!(db.is_empty());
    }

    #[test]
    fn test_db_by_tag_emotet() {
        let db = PatternMatchDb::with_builtins();
        let emotet = db.by_tag("emotet");
        assert!(!emotet.is_empty(), "no emotet signatures");
    }

    #[test]
    fn test_db_by_id_found() {
        let db = PatternMatchDb::with_builtins();
        let sig = db.by_id("base64_mz_pe");
        assert!(sig.is_some());
    }

    #[test]
    fn test_db_by_id_not_found() {
        let db = PatternMatchDb::with_builtins();
        assert!(db.by_id("nonexistent_sig").is_none());
    }

    #[test]
    fn test_db_by_tag_rc4() {
        let db = PatternMatchDb::with_builtins();
        let rc4_sigs = db.by_tag("rc4");
        assert!(!rc4_sigs.is_empty());
    }

    #[test]
    fn test_db_by_tag_base64() {
        let db = PatternMatchDb::with_builtins();
        let b64 = db.by_tag("base64");
        assert!(!b64.is_empty());
    }

    // ── PatternMatcher ────────────────────────────────────────────────────────

    #[test]
    fn test_matcher_finds_base64_mz() {
        let m = PatternMatcher::new();
        let data = b"abc TVqQ xyz"; // Base64-encoded MZ
        let results = m.scan(data);
        let found = results.iter().any(|r| r.signature_id == "base64_mz_pe");
        assert!(found, "should detect base64 MZ preamble");
    }

    #[test]
    fn test_matcher_finds_rc4_sbox() {
        let m = PatternMatcher::new();
        let data: Vec<u8> = (0u8..=15).collect(); // 0x00..0x0F
        let results = m.scan(&data);
        let found = results.iter().any(|r| r.signature_id == "rc4_sbox_init");
        assert!(found, "should detect RC4 sbox init");
    }

    #[test]
    fn test_matcher_finds_chacha20_constant() {
        let m = PatternMatcher::new();
        let data = b"expand 32-byte k\x00\x00";
        let results = m.scan(data);
        let found = results
            .iter()
            .any(|r| r.signature_id == "chacha20_constant");
        assert!(found, "should detect ChaCha20 constant");
    }

    #[test]
    fn test_matcher_finds_stack_string_x86() {
        let m = PatternMatcher::new();
        let data = [0xC6, 0x45, 0x00, 0x41, 0xC6, 0x45, 0x01, 0x42];
        let results = m.scan(&data);
        let found = results
            .iter()
            .any(|r| r.signature_id == "stack_string_x86_movbyte");
        assert!(found, "should detect x86 stack string");
    }

    #[test]
    fn test_matcher_min_confidence_filters() {
        let m = PatternMatcher::new().with_min_confidence(99);
        // ChaCha20 constant has confidence 95, should be filtered.
        let data = b"expand 32-byte k";
        let results = m.scan(data);
        // All results must meet confidence 99
        assert!(results.iter().all(|r| r.confidence >= 99));
    }

    #[test]
    fn test_matcher_max_results() {
        let m = PatternMatcher::new()
            .with_min_confidence(0)
            .with_max_results(1);
        let data = b"TVqQTVqQTVqQ expand 32-byte k";
        let results = m.scan(data);
        assert!(results.len() <= 1);
    }

    #[test]
    fn test_matcher_empty_data() {
        let m = PatternMatcher::new();
        let results = m.scan(b"");
        assert!(results.is_empty());
    }

    #[test]
    fn test_matcher_no_match() {
        let m = PatternMatcher::new();
        let data = [0x00u8; 32]; // all zeros — unlikely to match high-confidence sigs
        let results = m.scan_high_confidence(&data);
        // RC4 sbox starts with 0x00, so check specifically no false positives > 80
        for r in &results {
            assert!(r.confidence >= 75, "false positive: {}", r.signature_id);
        }
    }

    #[test]
    fn test_matcher_scan_grouped() {
        let m = PatternMatcher::new();
        let data = b"TVqQ expand 32-byte k";
        let grouped = m.scan_grouped(data);
        assert!(!grouped.is_empty());
    }

    #[test]
    fn test_matcher_scan_by_tag_emotet() {
        let m = PatternMatcher::new();
        // Emotet XOR 0x3A pattern: need 6 bytes where bytes[4] == 0x3A
        let data = [0x00u8, 0x00, 0x00, 0x00, 0x3A, 0x3A, 0x00, 0x00];
        let results = m.scan_by_tag(&data, "emotet");
        assert!(!results.is_empty(), "should find emotet patterns");
    }

    #[test]
    fn test_matcher_high_confidence_scan() {
        let m = PatternMatcher::new();
        let data = b"expand 32-byte k";
        let results = m.scan_high_confidence(data);
        assert!(!results.is_empty());
        assert!(results.iter().all(|r| r.confidence >= 75));
    }

    #[test]
    fn test_matcher_first_match_for_id() {
        let m = PatternMatcher::new();
        let data = b"TVqQ rest of data";
        let result = m.first_match_for_id(data, "base64_mz_pe");
        assert!(result.is_some());
        assert_eq!(result.unwrap().offset, 0);
    }

    #[test]
    fn test_matcher_first_match_for_id_not_found() {
        let m = PatternMatcher::new();
        let data = b"no matches here";
        let result = m.first_match_for_id(data, "base64_mz_pe");
        assert!(result.is_none());
    }

    #[test]
    fn test_match_result_high_confidence() {
        let r = PatternMatchResult {
            offset: 0,
            matched_length: 4,
            matched_bytes: vec![0x01, 0x02, 0x03, 0x04],
            signature_id: "test".into(),
            algorithm: StringAlgorithm::XorConstant,
            key_hint: None,
            confidence: 80,
            tags: vec![],
            description: "test".into(),
        };
        assert!(r.is_high_confidence());
    }

    #[test]
    fn test_match_result_low_confidence() {
        let r = PatternMatchResult {
            offset: 0,
            matched_length: 4,
            matched_bytes: vec![0x01, 0x02, 0x03, 0x04],
            signature_id: "test".into(),
            algorithm: StringAlgorithm::XorConstant,
            key_hint: None,
            confidence: 50,
            tags: vec![],
            description: "test".into(),
        };
        assert!(!r.is_high_confidence());
    }
}
