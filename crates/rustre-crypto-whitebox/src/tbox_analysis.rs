//! T-Box analysis for whitebox AES implementations.
//!
//! A T-Box (lookup table) variant of AES precomputes the combination of
//! `SubBytes` + `MixColumns` into 256-entry tables, one per input byte position.
//! Whitebox AES implementations obfuscate these tables with input and output
//! encodings (bijective functions) to hide the embedded key.
//!
//! This module detects T-box structures, measures their non-linearity, extracts
//! affine equivalences, and attempts to recover the round key bytes.

use crate::{AES_SBOX, CryptoError, LookupTable, TablePurpose};

// ── TBox ─────────────────────────────────────────────────────────────────────

/// A single T-Box entry: a 256-byte lookup table.
#[derive(Debug, Clone)]
pub struct TBox {
    /// The 256 output bytes produced for inputs 0..255.
    pub data: [u8; 256],
    /// Byte position (0..16) this T-box corresponds to, if known.
    pub byte_pos: Option<u8>,
    /// Round index (0..10), if known.
    pub round: Option<u8>,
    /// Confidence that this is a genuine T-box (0.0..1.0).
    pub confidence: f32,
}

impl TBox {
    /// Build a T-box from a slice. Returns `None` if `data.len() < 256`.
    #[must_use]
    pub fn from_slice(data: &[u8], byte_pos: Option<u8>, round: Option<u8>) -> Option<Self> {
        if data.len() < 256 {
            return None;
        }
        let mut arr = [0u8; 256];
        arr.copy_from_slice(&data[..256]);
        Some(Self {
            data: arr,
            byte_pos,
            round,
            confidence: 0.0,
        })
    }

    /// Return `true` if this table is a permutation (bijective function).
    #[must_use]
    pub fn is_bijective(&self) -> bool {
        let mut seen = [false; 256];
        for &b in &self.data {
            if seen[b as usize] {
                return false;
            }
            seen[b as usize] = true;
        }
        true
    }

    /// Compute the non-linearity of this S-box: minimum Hamming distance to all
    /// affine functions. Higher non-linearity implies stronger cryptographic
    /// resistance.
    #[must_use]
    pub fn non_linearity(&self) -> u32 {
        // Compute non-linearity via Walsh-Hadamard transform of each component function.
        // NL = min over non-zero output masks b of (128 - max_a |W_b(a)| / 2)
        let mut global_min_nl = u32::MAX;
        for b in 1u8..=255u8 {
            let mut max_abs = 0i32;
            for a in 0u8..=255u8 {
                let mut walsh: i32 = 0;
                for x in 0u8..=255u8 {
                    let fx_bit = (u32::from(b) & u32::from(self.data[x as usize])).count_ones() & 1;
                    let lin_bit = (u32::from(a) & u32::from(x)).count_ones() & 1;
                    walsh += if fx_bit == lin_bit { 1 } else { -1 };
                }
                if walsh.abs() > max_abs {
                    max_abs = walsh.abs();
                }
            }
            let nl = 128u32 - u32::try_from(max_abs / 2).unwrap_or(128);
            if nl < global_min_nl {
                global_min_nl = nl;
            }
        }
        global_min_nl
    }

    /// Check whether this table is affinely equivalent to the AES S-box.
    #[must_use]
    pub fn is_affinely_equivalent_to_sbox(&self) -> bool {
        for xor_in in 0u8..=255 {
            let first_out = self.data[xor_in as usize] ^ AES_SBOX[0];
            let all_match = (0usize..256).all(|i| {
                let idx = u8::try_from(i).unwrap_or(u8::MAX) ^ xor_in;
                self.data[idx as usize] ^ AES_SBOX[i] == first_out
            });
            if all_match {
                return true;
            }
        }
        false
    }

    /// Find the XOR constant that maps this table to `AES_SBOX` (if one exists).
    #[must_use]
    pub fn find_xor_equivalence(&self) -> Option<(u8, u8)> {
        for xor_in in 0u8..=255 {
            let xor_out = self.data[xor_in as usize] ^ AES_SBOX[0];
            let all_match = (0usize..256).all(|i| {
                let idx = u8::try_from(i).unwrap_or(u8::MAX) ^ xor_in;
                self.data[idx as usize] ^ AES_SBOX[i] == xor_out
            });
            if all_match {
                return Some((xor_in, xor_out));
            }
        }
        None
    }

    /// Convert this T-box to a `LookupTable` for storage.
    #[must_use]
    pub fn to_lookup_table(&self, offset: u64) -> LookupTable {
        LookupTable {
            offset,
            size: 256,
            data: self.data.to_vec(),
            purpose: TablePurpose::SubstitutionBox,
        }
    }
}

impl std::fmt::Display for TBox {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "TBox(pos={:?}, round={:?}, bijective={}, conf={:.2})",
            self.byte_pos,
            self.round,
            self.is_bijective(),
            self.confidence
        )
    }
}

// ── TBoxSet ───────────────────────────────────────────────────────────────────

/// A complete set of 16 T-boxes for one AES round.
#[derive(Debug, Clone, Default)]
pub struct TBoxSet {
    pub boxes: Vec<TBox>,
    pub round: Option<u8>,
}

impl TBoxSet {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            boxes: Vec::new(),
            round: None,
        }
    }

    /// Return `true` if all 16 T-boxes are present.
    #[must_use]
    pub const fn is_complete(&self) -> bool {
        self.boxes.len() == 16
    }

    /// Mean non-linearity across all boxes.
    #[must_use]
    pub fn mean_non_linearity(&self) -> f64 {
        if self.boxes.is_empty() {
            return 0.0;
        }
        let sum: u32 = self.boxes.iter().map(TBox::non_linearity).sum();
        f64::from(sum) / f64::from(u32::try_from(self.boxes.len()).unwrap_or(u32::MAX))
    }

    /// Return `true` if any box is bijective.
    #[must_use]
    pub fn any_bijective(&self) -> bool {
        self.boxes.iter().any(TBox::is_bijective)
    }

    /// Count boxes that are affinely equivalent to the AES S-box.
    #[must_use]
    pub fn count_sbox_equivalent(&self) -> usize {
        self.boxes
            .iter()
            .filter(|t| t.is_affinely_equivalent_to_sbox())
            .count()
    }
}

// ── AffineEquivalence ─────────────────────────────────────────────────────────

/// Describes an affine equivalence relationship between two lookup tables.
#[derive(Debug, Clone)]
pub struct AffineEquivalence {
    /// Input XOR constant.
    pub xor_in: u8,
    /// Output XOR constant.
    pub xor_out: u8,
    /// Index of the first table.
    pub table_a: usize,
    /// Index of the second table.
    pub table_b: usize,
}

// ── TBoxAnalyzer ──────────────────────────────────────────────────────────────

/// Detects and analyzes T-box structures in binary data.
pub struct TBoxAnalyzer {
    /// Minimum non-linearity threshold to consider a table cryptographically
    /// significant.
    pub min_nonlinearity: u32,
    /// Require T-boxes to be bijective.
    pub require_bijective: bool,
}

impl Default for TBoxAnalyzer {
    fn default() -> Self {
        Self {
            min_nonlinearity: 50,
            require_bijective: true,
        }
    }
}

impl TBoxAnalyzer {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Scan `binary` for 256-byte tables that look like T-boxes.
    #[must_use]
    pub fn scan(&self, binary: &[u8]) -> Vec<(u64, TBox)> {
        if binary.len() < 256 {
            return Vec::new();
        }
        // T-boxes are 256-byte aligned blocks; at most binary.len()/256 hits,
        // but typically very few. Start small to avoid over-allocating.
        let mut results = Vec::with_capacity(16);

        let mut offset = 0usize;
        while offset + 256 <= binary.len() {
            if let Some(mut tbox) = TBox::from_slice(&binary[offset..], None, None) {
                let nl = tbox.non_linearity();
                let bij = tbox.is_bijective();
                if nl >= self.min_nonlinearity && (!self.require_bijective || bij) {
                    let conf = self.score_tbox(&tbox);
                    tbox.confidence = conf;
                    if conf > 0.1 {
                        results.push((offset as u64, tbox));
                    }
                }
            }
            offset += 256;
        }
        results
    }

    /// Detect a T-box structure in a set of 256-byte tables.
    #[must_use]
    pub fn detect_structure(&self, tables: &[TBox]) -> bool {
        // A valid T-box structure for one AES round has 16 bijective tables.
        if tables.len() < 4 {
            return false;
        }
        let bij_count = tables.iter().filter(|t| t.is_bijective()).count();
        bij_count >= tables.len() / 2
    }

    /// Compute a confidence score for a single T-box.
    #[must_use]
    pub fn score_tbox(&self, tbox: &TBox) -> f32 {
        let mut score = 0.0f32;
        if tbox.is_bijective() {
            score += 0.4;
        }
        let nl = tbox.non_linearity();
        // AES S-box non-linearity ≈ 112; typical T-boxes should be close.
        let nl_score = (f32::from(u16::try_from(nl.min(128)).unwrap_or(128_u16)) / 128.0) * 0.3;
        score += nl_score;
        if tbox.is_affinely_equivalent_to_sbox() {
            score += 0.3;
        }
        score.min(1.0)
    }

    /// Find affine equivalences among a set of T-boxes.
    #[must_use]
    pub fn find_affine_equivalences(&self, tables: &[TBox]) -> Vec<AffineEquivalence> {
        let mut equivs = Vec::new();
        for (i, ta) in tables.iter().enumerate() {
            for (j, tb) in tables.iter().enumerate() {
                if i >= j {
                    continue;
                }
                if let Some((xor_in, xor_out)) = ta.find_xor_equivalence() {
                    // Check if applying (xor_in, xor_out) maps ta → tb.
                    let match_count = ta
                        .data
                        .iter()
                        .enumerate()
                        .filter(|&(k, &v)| {
                            tb.data[usize::from(u8::try_from(k).unwrap_or(u8::MAX) ^ xor_in)] ^ xor_out ^ v == 0
                        })
                        .count();
                    if match_count > 200 {
                        equivs.push(AffineEquivalence {
                            xor_in,
                            xor_out,
                            table_a: i,
                            table_b: j,
                        });
                    }
                }
            }
        }
        equivs
    }

    /// Given two T-boxes from the same round, estimate which byte positions
    /// they encode.
    #[must_use]
    pub fn estimate_byte_positions(&self, tables: &[TBox]) -> Vec<Option<u8>> {
        tables
            .iter()
            .enumerate()
            .map(|(i, _)| {
                // In Chow's construction tables are ordered by (round * 16 + byte_pos).
                Some(u8::try_from(i % 16).unwrap_or(u8::MAX))
            })
            .collect()
    }
}

// ── TBoxDecomposer ────────────────────────────────────────────────────────────

/// Strips outer encodings from T-boxes to recover the underlying AES operation.
pub struct TBoxDecomposer;

impl TBoxDecomposer {
    /// Attempt to decompose a T-box by removing outer affine encodings.
    ///
    /// Returns `Ok(TBox)` with the stripped table on success, or `Err` if
    /// no known affine encoding can be removed.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::Analysis`] if no affine encoding can be removed.
    pub fn strip_encoding(tbox: &TBox) -> Result<TBox, CryptoError> {
        // Try XOR stripping first.
        for xor_const in 0u8..=255 {
            let stripped: Vec<u8> = tbox.data.iter().map(|&b| b ^ xor_const).collect();
            let mut arr = [0u8; 256];
            arr.copy_from_slice(&stripped);
            let candidate = TBox {
                data: arr,
                byte_pos: tbox.byte_pos,
                round: tbox.round,
                confidence: 0.0,
            };
            if candidate.is_affinely_equivalent_to_sbox() {
                let mut out = candidate;
                out.confidence = 0.8;
                return Ok(out);
            }
        }
        Err(CryptoError::Analysis(
            "could not strip T-box encoding".into(),
        ))
    }

    /// Decompose a set of T-boxes, returning as many stripped tables as possible.
    #[must_use]
    pub fn decompose_set(tboxes: &[TBox]) -> Vec<Result<TBox, CryptoError>> {
        tboxes.iter().map(Self::strip_encoding).collect()
    }

    /// Estimate the linear (XOR) encoding applied to a T-box output.
    #[must_use]
    pub const fn estimate_output_encoding(tbox: &TBox) -> Option<u8> {
        // Find the XOR constant that makes the first output byte match AES_SBOX[0].
        let expected = AES_SBOX[0];
        let actual = tbox.data[0];
        Some(actual ^ expected)
    }

    /// Estimate the linear (XOR) encoding applied to T-box inputs.
    #[must_use]
    pub fn estimate_input_encoding(tbox: &TBox) -> Option<u8> {
        // Find xor_in such that tbox.data[xor_in ^ 0] == something consistent.
        (0u8..=255).find(|&xor_in| tbox.data[xor_in as usize] == AES_SBOX[0])
    }
}

// ── RoundKeyExtractor ─────────────────────────────────────────────────────────

/// Extracts AES round key bytes from stripped T-boxes.
pub struct RoundKeyExtractor;

impl RoundKeyExtractor {
    /// Extract a round key byte from a single stripped T-box.
    ///
    /// After stripping outer encodings, the remaining offset between the T-box
    /// and the canonical AES S-box encodes a key byte XOR.
    #[must_use]
    pub fn extract_key_byte(stripped: &TBox) -> Option<u8> {
        // Find best-matching XOR offset against AES_SBOX.
        let mut best_k = 0u8;
        let mut best_score = 0usize;
        for k in 0u8..=255 {
            let score = stripped
                .data
                .iter()
                .enumerate()
                .filter(|&(i, &v)| v == AES_SBOX[usize::from(u8::try_from(i).unwrap_or(u8::MAX) ^ k)])
                .count();
            if score > best_score {
                best_score = score;
                best_k = k;
            }
        }
        if best_score > 128 { Some(best_k) } else { None }
    }

    /// Extract up to 16 round-key bytes from a set of stripped T-boxes.
    #[must_use]
    pub fn extract_round_key(stripped_boxes: &[TBox]) -> Vec<Option<u8>> {
        stripped_boxes
            .iter()
            .map(Self::extract_key_byte)
            .collect()
    }

    /// Verify a candidate round key against a set of T-boxes.
    ///
    /// Returns the fraction of T-boxes that are consistent with `key`.
    #[must_use]
    pub fn verify_key(key: &[u8], stripped_boxes: &[TBox]) -> f32 {
        if stripped_boxes.is_empty() {
            return 0.0;
        }
        let consistent = stripped_boxes
            .iter()
            .enumerate()
            .filter(|(i, t)| {
                let kb = key.get(*i).copied().unwrap_or(0);
                t.data
                    .iter()
                    .enumerate()
                    .filter(|&(j, &v)| v == AES_SBOX[usize::from(u8::try_from(j).unwrap_or(u8::MAX) ^ kb)])
                    .count()
                    > 128
            })
            .count();
        let consistent_f = f32::from(u16::try_from(consistent).unwrap_or(u16::MAX));
        let total_f = f32::from(u16::try_from(stripped_boxes.len()).unwrap_or(u16::MAX));
        consistent_f / total_f
    }

    /// Given a full set of 16 T-boxes (one per AES input byte), attempt to
    /// recover the round key as a 16-byte vector.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::KeyExtraction`] if fewer than 16 T-boxes are provided.
    pub fn recover_key_from_tbox_set(tboxes: &[TBox]) -> Result<Vec<u8>, CryptoError> {
        if tboxes.len() < 16 {
            return Err(CryptoError::KeyExtraction(
                "need 16 T-boxes for key recovery".into(),
            ));
        }
        let key: Vec<u8> = tboxes[..16]
            .iter()
            .map(|t| Self::extract_key_byte(t).unwrap_or(0))
            .collect();
        Ok(key)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn sbox_tbox() -> TBox {
        TBox {
            data: AES_SBOX,
            byte_pos: Some(0),
            round: Some(1),
            confidence: 1.0,
        }
    }

    fn all_zero_tbox() -> TBox {
        TBox {
            data: [0u8; 256],
            byte_pos: None,
            round: None,
            confidence: 0.0,
        }
    }

    fn identity_tbox() -> TBox {
        let mut data = [0u8; 256];
        for (i, entry) in data.iter_mut().enumerate() {
            *entry = u8::try_from(i).unwrap_or(u8::MAX);
        }
        TBox {
            data,
            byte_pos: None,
            round: None,
            confidence: 0.0,
        }
    }

    #[test]
    fn test_tbox_from_slice_ok() {
        let data = vec![0u8; 256];
        let tb = TBox::from_slice(&data, Some(0), Some(1));
        assert!(tb.is_some());
        let tb = tb.unwrap();
        assert_eq!(tb.byte_pos, Some(0));
        assert_eq!(tb.round, Some(1));
    }

    #[test]
    fn test_tbox_from_slice_too_short() {
        let data = vec![0u8; 128];
        assert!(TBox::from_slice(&data, None, None).is_none());
    }

    #[test]
    fn test_tbox_bijective_identity() {
        let tb = identity_tbox();
        assert!(tb.is_bijective());
    }

    #[test]
    fn test_tbox_bijective_all_zero() {
        let tb = all_zero_tbox();
        assert!(!tb.is_bijective());
    }

    #[test]
    fn test_tbox_bijective_sbox() {
        let tb = sbox_tbox();
        assert!(tb.is_bijective());
    }

    #[test]
    fn test_tbox_non_linearity_sbox() {
        let tb = sbox_tbox();
        let nl = tb.non_linearity();
        // AES S-box is highly non-linear; NL should be > 50.
        assert!(nl > 50, "AES S-box NL={nl}");
    }

    #[test]
    fn test_tbox_non_linearity_identity() {
        let tb = identity_tbox();
        let nl = tb.non_linearity();
        // Identity is linear; NL = 0.
        assert_eq!(nl, 0);
    }

    #[test]
    fn test_tbox_affinely_equivalent_sbox() {
        let tb = sbox_tbox();
        assert!(tb.is_affinely_equivalent_to_sbox());
    }

    #[test]
    fn test_tbox_affinely_equivalent_xor_shifted() {
        // XOR every output by 0x42 — should still be affinely equivalent.
        let mut data = AES_SBOX;
        for b in &mut data {
            *b ^= 0x42;
        }
        let tb = TBox {
            data,
            byte_pos: None,
            round: None,
            confidence: 0.0,
        };
        assert!(tb.is_affinely_equivalent_to_sbox());
    }

    #[test]
    fn test_tbox_find_xor_equivalence_sbox() {
        let tb = sbox_tbox();
        let eq = tb.find_xor_equivalence();
        assert!(eq.is_some());
        let (xor_in, xor_out) = eq.unwrap();
        assert_eq!(xor_in, 0);
        assert_eq!(xor_out, 0);
    }

    #[test]
    fn test_tbox_to_lookup_table() {
        let tb = sbox_tbox();
        let lt = tb.to_lookup_table(0x1000);
        assert_eq!(lt.offset, 0x1000);
        assert_eq!(lt.size, 256);
        assert_eq!(lt.data.len(), 256);
        assert!(matches!(lt.purpose, TablePurpose::SubstitutionBox));
    }

    #[test]
    fn test_tbox_display() {
        let tb = sbox_tbox();
        let s = tb.to_string();
        assert!(s.contains("TBox"));
    }

    #[test]
    fn test_tboxset_complete() {
        let mut set = TBoxSet::new();
        for _ in 0..16 {
            set.boxes.push(sbox_tbox());
        }
        assert!(set.is_complete());
    }

    #[test]
    fn test_tboxset_incomplete() {
        let mut set = TBoxSet::new();
        set.boxes.push(sbox_tbox());
        assert!(!set.is_complete());
    }

    #[test]
    fn test_tboxset_mean_nonlinearity() {
        let mut set = TBoxSet::new();
        for _ in 0..4 {
            set.boxes.push(sbox_tbox());
        }
        let nl = set.mean_non_linearity();
        assert!(nl > 0.0);
    }

    #[test]
    fn test_tboxset_count_sbox_equivalent() {
        let mut set = TBoxSet::new();
        for _ in 0..8 {
            set.boxes.push(sbox_tbox());
        }
        set.boxes.push(identity_tbox());
        let cnt = set.count_sbox_equivalent();
        assert_eq!(cnt, 8);
    }

    #[test]
    fn test_analyzer_scan_finds_sbox() {
        let analyzer = TBoxAnalyzer {
            min_nonlinearity: 0,
            require_bijective: true,
        };
        let data: Vec<u8> = AES_SBOX.to_vec();
        let results = analyzer.scan(&data);
        assert!(!results.is_empty());
    }

    #[test]
    fn test_analyzer_detect_structure_true() {
        let analyzer = TBoxAnalyzer::new();
        let tables: Vec<TBox> = (0..8).map(|_| sbox_tbox()).collect();
        assert!(analyzer.detect_structure(&tables));
    }

    #[test]
    fn test_analyzer_detect_structure_false_empty() {
        let analyzer = TBoxAnalyzer::new();
        assert!(!analyzer.detect_structure(&[]));
    }

    #[test]
    fn test_analyzer_score_sbox() {
        let analyzer = TBoxAnalyzer::new();
        let tb = sbox_tbox();
        let score = analyzer.score_tbox(&tb);
        assert!(score > 0.5, "score={score}");
    }

    #[test]
    fn test_analyzer_estimate_byte_positions() {
        let analyzer = TBoxAnalyzer::new();
        let tables: Vec<TBox> = (0..16).map(|_| sbox_tbox()).collect();
        let positions = analyzer.estimate_byte_positions(&tables);
        assert_eq!(positions.len(), 16);
        assert_eq!(positions[0], Some(0));
        assert_eq!(positions[15], Some(15));
    }

    #[test]
    fn test_decomposer_strip_encoding_sbox() {
        let tb = sbox_tbox();
        let stripped = TBoxDecomposer::strip_encoding(&tb).unwrap();
        assert!(stripped.confidence > 0.0);
    }

    #[test]
    fn test_decomposer_strip_encoding_xor_shifted() {
        let mut data = AES_SBOX;
        for b in &mut data {
            *b ^= 0x37;
        }
        let tb = TBox {
            data,
            byte_pos: None,
            round: None,
            confidence: 0.0,
        };
        let result = TBoxDecomposer::strip_encoding(&tb);
        assert!(result.is_ok());
    }

    #[test]
    fn test_decomposer_estimate_output_encoding() {
        let tb = sbox_tbox();
        let enc = TBoxDecomposer::estimate_output_encoding(&tb);
        // sbox[0] = 0x63; AES_SBOX[0] = 0x63; xor = 0.
        assert_eq!(enc, Some(0));
    }

    #[test]
    fn test_decomposer_estimate_input_encoding() {
        let tb = sbox_tbox();
        let enc = TBoxDecomposer::estimate_input_encoding(&tb);
        // sbox[0] = 0x63 = AES_SBOX[0], so xor_in = 0.
        assert_eq!(enc, Some(0));
    }

    #[test]
    fn test_round_key_extractor_extract_key_byte_sbox() {
        let tb = sbox_tbox();
        let kb = RoundKeyExtractor::extract_key_byte(&tb);
        assert_eq!(kb, Some(0));
    }

    #[test]
    fn test_round_key_extractor_extract_key_byte_xor() {
        let k: u8 = 0x2b;
        let mut data = [0u8; 256];
        for (i, entry) in data.iter_mut().enumerate() {
            *entry = AES_SBOX[usize::from(u8::try_from(i).unwrap_or(u8::MAX) ^ k)];
        }
        let tb = TBox {
            data,
            byte_pos: None,
            round: None,
            confidence: 0.0,
        };
        let kb = RoundKeyExtractor::extract_key_byte(&tb);
        assert_eq!(kb, Some(k));
    }

    #[test]
    fn test_round_key_extractor_recover_key_from_set() {
        let k: [u8; 16] = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
            0x4f, 0x3c,
        ];
        let boxes: Vec<TBox> = k
            .iter()
            .map(|&kb| {
                let mut data = [0u8; 256];
                for (i, entry) in data.iter_mut().enumerate() {
                    *entry = AES_SBOX[usize::from(u8::try_from(i).unwrap_or(u8::MAX) ^ kb)];
                }
                TBox {
                    data,
                    byte_pos: None,
                    round: None,
                    confidence: 0.0,
                }
            })
            .collect();
        let key = RoundKeyExtractor::recover_key_from_tbox_set(&boxes).unwrap();
        assert_eq!(key, k.to_vec());
    }

    #[test]
    fn test_round_key_extractor_insufficient_boxes() {
        let boxes: Vec<TBox> = vec![sbox_tbox(); 4];
        assert!(RoundKeyExtractor::recover_key_from_tbox_set(&boxes).is_err());
    }

    #[test]
    fn test_round_key_extractor_verify_key() {
        let k: u8 = 0xab;
        let mut data = [0u8; 256];
        for (i, entry) in data.iter_mut().enumerate() {
            *entry = AES_SBOX[usize::from(u8::try_from(i).unwrap_or(u8::MAX) ^ k)];
        }
        let tb = TBox {
            data,
            byte_pos: None,
            round: None,
            confidence: 0.0,
        };
        let score =
            RoundKeyExtractor::verify_key(&[k, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], &[tb]);
        assert!(score > 0.5);
    }
}
