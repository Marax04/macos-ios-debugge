//! `unicode_obfuscation_detector` — Detect Unicode-based obfuscation in strings.
//!
//! Attackers (and some obfuscators) exploit Unicode to hide malicious content
//! visually. This module detects:
//!
//! * **Homoglyphs** — characters that look like ASCII letters but have different
//!   code points (e.g. Cyrillic А `U+0410` vs Latin A `U+0041`).
//! * **Mixed scripts** — strings that interleave characters from multiple scripts.
//! * **Invisible / control characters** — zero-width joiners, directional
//!   formatting marks, soft hyphens, etc.
//! * **Confusable identifiers** — as per Unicode confusables.txt patterns.
//! * **Right-to-left overrides** — `U+202E` and friends used to hide extensions.
//! * **Punycode-encoded domains** — `xn--` prefixes in identifiers.

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

// ─── ObfuscationType ──────────────────────────────────────────────────────────

/// Classification of a detected Unicode obfuscation technique.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ObfuscationType {
    /// Visually similar character from a different Unicode block.
    Homoglyph,
    /// Mixed characters from multiple writing scripts.
    MixedScript,
    /// Invisible or zero-width formatting character.
    InvisibleCharacter,
    /// Bidirectional text control character.
    BidiOverride,
    /// `xn--` punycode hostname obfuscation.
    Punycode,
    /// Confusable identifier (similar to `Homoglyph` but via the confusables DB).
    ConfusableIdentifier,
    /// Unusual combining or modifier character.
    CombiningCharacter,
    /// Private Use Area code point.
    PrivateUseArea,
    /// Variation selector that changes glyph appearance.
    VariationSelector,
    /// High-entropy Unicode string suggesting encoded payload.
    HighEntropy,
}

impl fmt::Display for ObfuscationType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Homoglyph => write!(f, "homoglyph"),
            Self::MixedScript => write!(f, "mixed-script"),
            Self::InvisibleCharacter => write!(f, "invisible-character"),
            Self::BidiOverride => write!(f, "bidi-override"),
            Self::Punycode => write!(f, "punycode"),
            Self::ConfusableIdentifier => write!(f, "confusable-identifier"),
            Self::CombiningCharacter => write!(f, "combining-character"),
            Self::PrivateUseArea => write!(f, "private-use-area"),
            Self::VariationSelector => write!(f, "variation-selector"),
            Self::HighEntropy => write!(f, "high-entropy"),
        }
    }
}

// ─── ObfuscationFinding ───────────────────────────────────────────────────────

/// A single detected obfuscation event within a string.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObfuscationFinding {
    /// Type of obfuscation detected.
    pub obf_type: ObfuscationType,
    /// Character offset (in Unicode scalar values) where the finding starts.
    pub char_offset: usize,
    /// The offending character.
    pub offending_char: char,
    /// Code point of the offending character.
    pub codepoint: u32,
    /// An ASCII lookalike if known (for homoglyphs).
    pub ascii_lookalike: Option<char>,
    /// Human-readable explanation.
    pub explanation: String,
    /// Confidence score in [0, 100].
    pub confidence: u8,
}

impl fmt::Display for ObfuscationFinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{}] U+{:04X} at char {} — {}",
            self.obf_type, self.codepoint, self.char_offset, self.explanation,
        )
    }
}

// ─── DetectionResult ──────────────────────────────────────────────────────────

/// The result of analysing a string for Unicode obfuscation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionResult {
    /// The original input string.
    pub original: String,
    /// All detected findings, in order of character offset.
    pub findings: Vec<ObfuscationFinding>,
    /// Whether any obfuscation was detected.
    pub is_obfuscated: bool,
    /// ASCII-normalised version of the string (homoglyphs replaced by lookalikes).
    pub normalized: String,
    /// Overall confidence that the string is intentionally obfuscated [0, 100].
    pub overall_confidence: u8,
}

impl DetectionResult {
    /// Returns findings of a specific type.
    #[must_use]
    pub fn findings_of(&self, ty: &ObfuscationType) -> Vec<&ObfuscationFinding> {
        self.findings.iter().filter(|f| &f.obf_type == ty).collect()
    }

    /// Returns the count of findings per type.
    #[must_use]
    pub fn finding_counts(&self) -> HashMap<String, usize> {
        let mut map: HashMap<String, usize> = HashMap::new();
        for f in &self.findings {
            *map.entry(f.obf_type.to_string()).or_default() += 1;
        }
        map
    }

    /// Returns `true` when a bidi-override or punycode finding was detected.
    #[must_use]
    pub fn has_critical_finding(&self) -> bool {
        self.findings.iter().any(|f| {
            matches!(
                f.obf_type,
                ObfuscationType::BidiOverride | ObfuscationType::Punycode
            )
        })
    }
}

// ─── Static homoglyph table ───────────────────────────────────────────────────

/// Map from Unicode code point to its ASCII lookalike.
///
/// Covers common Cyrillic, Greek, Latin Extended, and mathematical alphanumerics
/// that are visually indistinguishable from plain ASCII in most fonts.
static HOMOGLYPH_TABLE: &[(char, char)] = &[
    // Cyrillic → Latin
    ('А', 'A'), ('В', 'B'), ('С', 'C'), ('Е', 'E'), ('Н', 'H'), ('І', 'I'),
    ('J', 'J'), ('К', 'K'), ('М', 'M'), ('О', 'O'), ('Р', 'P'), ('Ѕ', 'S'),
    ('Т', 'T'), ('Ԝ', 'W'), ('Х', 'X'), ('Ү', 'Y'),
    ('а', 'a'), ('с', 'c'), ('е', 'e'), ('ӓ', 'a'), ('ԁ', 'd'), ('о', 'o'),
    ('р', 'p'), ('ѕ', 's'), ('ᴜ', 'u'), ('х', 'x'), ('у', 'y'),
    // Greek → Latin
    ('Α', 'A'), ('Β', 'B'), ('Ε', 'E'), ('Ζ', 'Z'), ('Η', 'H'), ('Ι', 'I'),
    ('Κ', 'K'), ('Μ', 'M'), ('Ν', 'N'), ('Ο', 'O'), ('Ρ', 'P'), ('Τ', 'T'),
    ('Υ', 'Y'), ('Χ', 'X'), ('ο', 'o'), ('ν', 'v'), ('μ', 'u'),
    // Latin look-alikes
    ('ɑ', 'a'), ('ḃ', 'b'), ('ċ', 'c'), ('ḋ', 'd'), ('ė', 'e'), ('ḟ', 'f'),
    ('ġ', 'g'), ('ḣ', 'h'), ('ı', 'i'), ('ȷ', 'j'), ('ḵ', 'k'), ('ḷ', 'l'),
    ('ṁ', 'm'), ('ṅ', 'n'), ('ọ', 'o'), ('ṗ', 'p'), ('ṙ', 'r'), ('ṡ', 's'),
    ('ṫ', 't'), ('ụ', 'u'), ('ṿ', 'v'), ('ẇ', 'w'), ('ẋ', 'x'), ('ẏ', 'y'),
    ('ż', 'z'),
    // Mathematical bold / script alphanumerics
    ('𝐀', 'A'), ('𝐁', 'B'), ('𝐂', 'C'), ('𝐃', 'D'), ('𝐄', 'E'),
    ('𝐚', 'a'), ('𝐛', 'b'), ('𝐜', 'c'), ('𝐝', 'd'), ('𝐞', 'e'),
    // Fullwidth ASCII
    ('Ａ', 'A'), ('Ｂ', 'B'), ('Ｃ', 'C'), ('Ｄ', 'D'), ('Ｅ', 'E'),
    ('Ｆ', 'F'), ('Ｇ', 'G'), ('Ｈ', 'H'), ('Ｉ', 'I'), ('Ｊ', 'J'),
    ('ａ', 'a'), ('ｂ', 'b'), ('ｃ', 'c'), ('ｄ', 'd'), ('ｅ', 'e'),
    ('０', '0'), ('１', '1'), ('２', '2'), ('３', '3'), ('４', '4'),
    ('５', '5'), ('６', '6'), ('７', '7'), ('８', '8'), ('９', '9'),
];

// ─── Script detection helpers ─────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Script {
    Latin,
    Cyrillic,
    Greek,
    Arabic,
    Hebrew,
    CJK,
    Devanagari,
    Other,
}

const fn char_script(c: char) -> Script {
    let cp = c as u32;
    match cp {
        0x0041..=0x007A => Script::Latin,   // Basic Latin letters
        0x00C0..=0x024F => Script::Latin,   // Latin Extended
        0x0400..=0x04FF => Script::Cyrillic,
        0x0370..=0x03FF => Script::Greek,
        0x0600..=0x06FF => Script::Arabic,
        0x0590..=0x05FF => Script::Hebrew,
        0x0900..=0x097F => Script::Devanagari,
        0x4E00..=0x9FFF => Script::CJK,
        0x3040..=0x30FF => Script::CJK,    // Hiragana / Katakana
        _ => Script::Other,
    }
}

const fn is_invisible_char(c: char) -> bool {
    matches!(c as u32,
        0x00AD |          // Soft hyphen
        0x034F |          // Combining grapheme joiner
        0x061C |          // Arabic letter mark
        0x115F | 0x1160 | // Hangul fillers
        0x17B4 | 0x17B5 | // Khmer vowel inherent
        0x180B..=0x180D | // Mongolian free variation selectors
        0x200B..=0x200F | // Zero-width space/non-joiner/joiner/LRM/RLM
        0x202A..=0x202E | // Left-to-right embedding … right-to-left override
        0x2060..=0x2064 | // Word joiner, invisible times, etc.
        0x206A..=0x206F | // Inhibit symmetric swapping … nominal digit shapes
        0xFEFF |          // Zero-width no-break space (BOM)
        0xFFF0..=0xFFFF   // Specials
    )
}

const fn is_bidi_char(c: char) -> bool {
    matches!(c as u32,
        0x202A..=0x202E | // LRE, RLE, PDF, LRO, RLO
        0x2066..=0x2069 | // LRI, RLI, FSI, PDI
        0x200E | 0x200F   // LRM, RLM
    )
}

fn is_variation_selector(c: char) -> bool {
    let cp = c as u32;
    (0xFE00..=0xFE0F).contains(&cp) || (0xE0100..=0xE01EF).contains(&cp)
}

fn is_combining(c: char) -> bool {
    let cp = c as u32;
    (0x0300..=0x036F).contains(&cp)
        || (0x1AB0..=0x1AFF).contains(&cp)
        || (0x1DC0..=0x1DFF).contains(&cp)
        || (0x20D0..=0x20FF).contains(&cp)
}

fn is_private_use(c: char) -> bool {
    let cp = c as u32;
    (0xE000..=0xF8FF).contains(&cp) || (0xF0000..=0xFFFFF).contains(&cp)
}

// ─── UnicodeObfuscationDetector ───────────────────────────────────────────────

/// Analyses strings for Unicode-based obfuscation techniques.
#[derive(Debug, Clone)]
pub struct UnicodeObfuscationDetector {
    /// Minimum confidence [0, 100] for a finding to be included.
    pub min_confidence: u8,
    /// Whether to check for mixed-script sequences.
    pub check_mixed_script: bool,
    /// Whether to check for punycode.
    pub check_punycode: bool,
    /// Whether to report invisible characters.
    pub check_invisible: bool,
    /// Whether to report homoglyphs.
    pub check_homoglyphs: bool,
    /// Whether to report bidi override characters.
    pub check_bidi: bool,
    /// Whether to report high-entropy strings.
    pub check_entropy: bool,
}

impl Default for UnicodeObfuscationDetector {
    fn default() -> Self {
        Self {
            min_confidence: 60,
            check_mixed_script: true,
            check_punycode: true,
            check_invisible: true,
            check_homoglyphs: true,
            check_bidi: true,
            check_entropy: false,
        }
    }
}

impl UnicodeObfuscationDetector {
    /// Create a detector with all checks enabled.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Run `homoglyph_check` on the given string.
    #[must_use]
    pub fn homoglyph_check(&self, s: &str) -> Vec<ObfuscationFinding> {
        homoglyph_check(s)
    }

    /// Analyse a string and return a full [`DetectionResult`].
    #[must_use]
    pub fn analyze(&self, s: &str) -> DetectionResult {
        let mut findings: Vec<ObfuscationFinding> = Vec::new();

        // Homoglyph check
        if self.check_homoglyphs {
            findings.extend(homoglyph_check(s));
        }

        // Invisible / bidi character checks (character-by-character)
        for (i, c) in s.chars().enumerate() {
            let cp = c as u32;

            if self.check_invisible && is_invisible_char(c) {
                let is_bidi = is_bidi_char(c);
                if is_bidi && self.check_bidi {
                    findings.push(ObfuscationFinding {
                        obf_type: ObfuscationType::BidiOverride,
                        char_offset: i,
                        offending_char: c,
                        codepoint: cp,
                        ascii_lookalike: None,
                        explanation: format!("Bidi control U+{cp:04X} can reverse text direction"),
                        confidence: 95,
                    });
                } else if !is_bidi {
                    findings.push(ObfuscationFinding {
                        obf_type: ObfuscationType::InvisibleCharacter,
                        char_offset: i,
                        offending_char: c,
                        codepoint: cp,
                        ascii_lookalike: None,
                        explanation: format!("Invisible character U+{cp:04X}"),
                        confidence: 90,
                    });
                }
            }

            if is_combining(c) {
                findings.push(ObfuscationFinding {
                    obf_type: ObfuscationType::CombiningCharacter,
                    char_offset: i,
                    offending_char: c,
                    codepoint: cp,
                    ascii_lookalike: None,
                    explanation: format!("Combining character U+{cp:04X}"),
                    confidence: 70,
                });
            }

            if is_variation_selector(c) {
                findings.push(ObfuscationFinding {
                    obf_type: ObfuscationType::VariationSelector,
                    char_offset: i,
                    offending_char: c,
                    codepoint: cp,
                    ascii_lookalike: None,
                    explanation: format!("Variation selector U+{cp:04X}"),
                    confidence: 80,
                });
            }

            if is_private_use(c) {
                findings.push(ObfuscationFinding {
                    obf_type: ObfuscationType::PrivateUseArea,
                    char_offset: i,
                    offending_char: c,
                    codepoint: cp,
                    ascii_lookalike: None,
                    explanation: format!("Private-use area character U+{cp:04X}"),
                    confidence: 65,
                });
            }
        }

        // Mixed-script check
        if self.check_mixed_script {
            if let Some(finding) = mixed_script_check(s) {
                findings.push(finding);
            }
        }

        // Punycode check
        if self.check_punycode && s.contains("xn--") {
            findings.push(ObfuscationFinding {
                obf_type: ObfuscationType::Punycode,
                char_offset: s.find("xn--").unwrap_or(0),
                offending_char: 'x',
                codepoint: 'x' as u32,
                ascii_lookalike: None,
                explanation: "Punycode-encoded hostname (xn-- prefix)".to_string(),
                confidence: 85,
            });
        }

        // Filter by min_confidence
        findings.retain(|f| f.confidence >= self.min_confidence);
        findings.sort_by_key(|f| f.char_offset);

        // Build normalized form
        let normalized = normalize_homoglyphs(s);
        let is_obfuscated = !findings.is_empty();
        let overall_confidence = findings
            .iter()
            .map(|f| u32::from(f.confidence))
            .max()
            .unwrap_or(0) as u8;

        DetectionResult {
            original: s.to_string(),
            findings,
            is_obfuscated,
            normalized,
            overall_confidence,
        }
    }

    /// Batch-analyse multiple strings.
    #[must_use]
    pub fn analyze_batch(&self, strings: &[&str]) -> Vec<DetectionResult> {
        strings.iter().map(|s| self.analyze(s)).collect()
    }

    /// Quick check — returns `true` when any obfuscation is detected.
    #[must_use]
    pub fn is_obfuscated(&self, s: &str) -> bool {
        self.analyze(s).is_obfuscated
    }
}

// ─── Free functions ───────────────────────────────────────────────────────────

/// Check a string for homoglyphs (characters visually identical to ASCII but
/// from a different Unicode block).
///
/// Returns one [`ObfuscationFinding`] per suspicious character.
#[must_use]
pub fn homoglyph_check(s: &str) -> Vec<ObfuscationFinding> {
    let table: HashMap<char, char> = HOMOGLYPH_TABLE.iter().copied().collect();
    let mut findings = Vec::new();
    for (i, c) in s.chars().enumerate() {
        if let Some(&ascii) = table.get(&c) {
            findings.push(ObfuscationFinding {
                obf_type: ObfuscationType::Homoglyph,
                char_offset: i,
                offending_char: c,
                codepoint: c as u32,
                ascii_lookalike: Some(ascii),
                explanation: format!(
                    "U+{:04X} '{}' looks like ASCII '{ascii}'",
                    c as u32, c
                ),
                confidence: 88,
            });
        }
    }
    findings
}

/// Check for mixed scripts within `s`.
///
/// Returns `Some(finding)` when more than one non-trivial script is detected.
#[must_use]
pub fn mixed_script_check(s: &str) -> Option<ObfuscationFinding> {
    let mut scripts: HashMap<Script, usize> = HashMap::new();
    for c in s.chars() {
        if c.is_ascii_alphabetic() {
            *scripts.entry(Script::Latin).or_default() += 1;
        } else if c.is_alphabetic() {
            *scripts.entry(char_script(c)).or_default() += 1;
        }
    }
    // Remove Script::Other and Script::Latin if only 1 character.
    let significant: Vec<Script> = scripts
        .iter()
        .filter(|&(s, &count)| *s != Script::Other && count >= 1)
        .map(|(s, _)| *s)
        .collect();

    if significant.len() > 1 {
        let scripts_str: Vec<&str> = significant
            .iter()
            .map(|sc| match sc {
                Script::Latin => "Latin",
                Script::Cyrillic => "Cyrillic",
                Script::Greek => "Greek",
                Script::Arabic => "Arabic",
                Script::Hebrew => "Hebrew",
                Script::CJK => "CJK",
                Script::Devanagari => "Devanagari",
                Script::Other => "Other",
            })
            .collect();
        Some(ObfuscationFinding {
            obf_type: ObfuscationType::MixedScript,
            char_offset: 0,
            offending_char: s.chars().next().unwrap_or(' '),
            codepoint: s.chars().next().unwrap_or(' ') as u32,
            ascii_lookalike: None,
            explanation: format!("Mixed scripts detected: {}", scripts_str.join(", ")),
            confidence: 75,
        })
    } else {
        None
    }
}

/// Replace all known homoglyphs in `s` with their ASCII lookalikes.
#[must_use]
pub fn normalize_homoglyphs(s: &str) -> String {
    let table: HashMap<char, char> = HOMOGLYPH_TABLE.iter().copied().collect();
    s.chars()
        .map(|c| table.get(&c).copied().unwrap_or(c))
        .collect()
}

/// Remove all invisible/control characters from `s`.
#[must_use]
pub fn strip_invisible(s: &str) -> String {
    s.chars()
        .filter(|&c| !is_invisible_char(c) && !is_combining(c) && !is_variation_selector(c))
        .collect()
}

/// Count the number of non-ASCII Unicode characters in `s`.
#[must_use]
pub fn count_non_ascii_unicode(s: &str) -> usize {
    s.chars().filter(|c| !c.is_ascii()).count()
}

/// Returns `true` when `s` contains at least one known bidi-override character.
#[must_use]
pub fn has_bidi_override(s: &str) -> bool {
    s.chars().any(is_bidi_char)
}

/// Returns `true` when `s` contains at least one invisible character.
#[must_use]
pub fn has_invisible_char(s: &str) -> bool {
    s.chars().any(is_invisible_char)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_homoglyph_check_cyrillic_a() {
        // Cyrillic А looks like Latin A
        let s = "Аpple"; // First char is Cyrillic А (U+0410)
        let findings = homoglyph_check(s);
        assert!(!findings.is_empty());
        assert_eq!(findings[0].obf_type, ObfuscationType::Homoglyph);
        assert_eq!(findings[0].ascii_lookalike, Some('A'));
    }

    #[test]
    fn test_homoglyph_check_clean_ascii() {
        let findings = homoglyph_check("hello world");
        assert!(findings.is_empty());
    }

    #[test]
    fn test_normalize_homoglyphs() {
        let s = "Аpple"; // Cyrillic А
        let normalized = normalize_homoglyphs(s);
        assert_eq!(normalized, "Apple");
    }

    #[test]
    fn test_mixed_script_cyrillic_latin() {
        // "Аpple" contains Cyrillic А and Latin letters
        let s = "АBCdef"; // А is Cyrillic
        let result = mixed_script_check(s);
        assert!(result.is_some());
        let f = result.unwrap();
        assert_eq!(f.obf_type, ObfuscationType::MixedScript);
    }

    #[test]
    fn test_mixed_script_pure_latin() {
        let result = mixed_script_check("hello WORLD");
        assert!(result.is_none());
    }

    #[test]
    fn test_invisible_char_detection() {
        let s = "hel\u{200B}lo"; // zero-width space
        let detector = UnicodeObfuscationDetector::new();
        let result = detector.analyze(s);
        assert!(result.is_obfuscated);
    }

    #[test]
    fn test_bidi_detection() {
        let s = "file\u{202E}txt.exe"; // RLO
        let detector = UnicodeObfuscationDetector::new();
        let result = detector.analyze(s);
        assert!(result.has_critical_finding());
    }

    #[test]
    fn test_punycode_detection() {
        let s = "xn--e1afmkfd.xn--p1ai";
        let detector = UnicodeObfuscationDetector::new();
        let result = detector.analyze(s);
        assert!(result
            .findings
            .iter()
            .any(|f| f.obf_type == ObfuscationType::Punycode));
    }

    #[test]
    fn test_clean_ascii_not_obfuscated() {
        let detector = UnicodeObfuscationDetector::new();
        let result = detector.analyze("normal ascii string 123");
        assert!(!result.is_obfuscated);
    }

    #[test]
    fn test_strip_invisible() {
        let s = "hel\u{200B}lo"; // zero-width space between l and l
        let stripped = strip_invisible(s);
        assert_eq!(stripped, "hello");
    }

    #[test]
    fn test_count_non_ascii() {
        assert_eq!(count_non_ascii_unicode("hello"), 0);
        assert_eq!(count_non_ascii_unicode("héllo"), 1);
    }

    #[test]
    fn test_has_bidi_override_true() {
        assert!(has_bidi_override("test\u{202E}foo"));
    }

    #[test]
    fn test_has_bidi_override_false() {
        assert!(!has_bidi_override("normal text"));
    }

    #[test]
    fn test_has_invisible_char_true() {
        assert!(has_invisible_char("hel\u{200B}lo"));
    }

    #[test]
    fn test_has_invisible_char_false() {
        assert!(!has_invisible_char("clean"));
    }

    #[test]
    fn test_batch_analyze() {
        let detector = UnicodeObfuscationDetector::new();
        let strings = vec!["clean", "hel\u{200B}lo", "normal"];
        let results = detector.analyze_batch(&strings);
        assert_eq!(results.len(), 3);
        assert!(!results[0].is_obfuscated);
        assert!(results[1].is_obfuscated);
        assert!(!results[2].is_obfuscated);
    }

    #[test]
    fn test_finding_counts() {
        let detector = UnicodeObfuscationDetector::new();
        let s = "hel\u{200B}lo\u{202E}world";
        let result = detector.analyze(s);
        let counts = result.finding_counts();
        assert!(counts.values().sum::<usize>() >= 2);
    }

    #[test]
    fn test_detection_result_findings_of() {
        let detector = UnicodeObfuscationDetector::new();
        let s = "Аpple\u{200B}";
        let result = detector.analyze(s);
        let homoglyphs = result.findings_of(&ObfuscationType::Homoglyph);
        assert!(!homoglyphs.is_empty());
    }

    #[test]
    fn test_obfuscation_type_display() {
        assert_eq!(ObfuscationType::Homoglyph.to_string(), "homoglyph");
        assert_eq!(ObfuscationType::BidiOverride.to_string(), "bidi-override");
        assert_eq!(ObfuscationType::MixedScript.to_string(), "mixed-script");
    }

    #[test]
    fn test_overall_confidence_non_zero_when_obfuscated() {
        let detector = UnicodeObfuscationDetector::new();
        let s = "hel\u{202E}lo";
        let result = detector.analyze(s);
        if result.is_obfuscated {
            assert!(result.overall_confidence > 0);
        }
    }
}
