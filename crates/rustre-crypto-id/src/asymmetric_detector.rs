//! `asymmetric_detector` — Detect asymmetric-cryptography implementations in binary data.
//!
//! Identifies RSA (modular exponentiation, CRT helper constants), Diffie-Hellman,
//! DSA/ECDSA, ECC field arithmetic (Weierstrass / Montgomery / Edwards curves),
//! and post-quantum lattice signatures through constant and structural patterns.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

// ── AsymmetricFamily ──────────────────────────────────────────────────────────

/// Top-level asymmetric algorithm family.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AsymmetricFamily {
    Rsa,
    DiffieHellman,
    Dsa,
    EcdsaWeierstrass,
    EcdhMontgomery,
    EcEdwards,
    ElGamal,
    Paillier,
    Dilithium,   // post-quantum
    Kyber,       // post-quantum
    Unknown,
}

impl std::fmt::Display for AsymmetricFamily {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl AsymmetricFamily {
    /// Returns `true` for elliptic-curve based families.
    #[must_use]
    pub const fn is_ecc(self) -> bool {
        matches!(self, Self::EcdsaWeierstrass | Self::EcdhMontgomery | Self::EcEdwards)
    }

    /// Returns `true` for post-quantum families.
    #[must_use]
    pub const fn is_post_quantum(self) -> bool {
        matches!(self, Self::Dilithium | Self::Kyber)
    }

    /// Typical public key size in bits (most common variant), or `None`.
    #[must_use]
    pub const fn typical_key_bits(self) -> Option<u32> {
        match self {
            Self::Rsa | Self::DiffieHellman | Self::Dsa => Some(2048),
            Self::EcdsaWeierstrass => Some(256),
            Self::EcdhMontgomery | Self::EcEdwards => Some(255),
            Self::Dilithium => Some(1952),
            Self::Kyber => Some(1184),
            _ => None,
        }
    }
}

// ── ModExpPattern ─────────────────────────────────────────────────────────────

/// A detected modular-exponentiation pattern characteristic of RSA or DH.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModExpPattern {
    /// Byte offset of the pattern.
    pub offset: usize,
    /// Number of bytes the pattern spans.
    pub span: usize,
    /// Confidence [0.0, 1.0].
    pub confidence: f32,
    /// Description of the specific sub-pattern.
    pub description: String,
}

// ── EcPattern ─────────────────────────────────────────────────────────────────

/// A detected elliptic-curve arithmetic pattern.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EcPattern {
    /// Byte offset.
    pub offset: usize,
    /// Span in bytes.
    pub span: usize,
    /// Confidence [0.0, 1.0].
    pub confidence: f32,
    /// Description.
    pub description: String,
    /// Which curve family this matches.
    pub family: AsymmetricFamily,
}

// ── AsymmetricDetection ───────────────────────────────────────────────────────

/// A single detection event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AsymmetricDetection {
    /// Algorithm family.
    pub family: AsymmetricFamily,
    /// Byte offset.
    pub offset: usize,
    /// Confidence [0.0, 1.0].
    pub confidence: f32,
    /// Evidence description.
    pub evidence: String,
    /// Whether the detection came from a constant value.
    pub from_constant: bool,
}

impl AsymmetricDetection {
    #[must_use]
    fn new(
        family: AsymmetricFamily,
        offset: usize,
        confidence: f32,
        evidence: impl Into<String>,
        from_constant: bool,
    ) -> Self {
        Self { family, offset, confidence: confidence.clamp(0.0, 1.0), evidence: evidence.into(), from_constant }
    }

    /// Returns `true` if confidence ≥ 0.80.
    #[must_use]
    pub fn is_high_confidence(&self) -> bool {
        self.confidence >= 0.80
    }
}

// ── AsymmetricReport ──────────────────────────────────────────────────────────

/// Aggregated report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AsymmetricReport {
    /// All detections sorted by offset.
    pub detections: Vec<AsymmetricDetection>,
    /// Ranked identifications.
    pub ranked: Vec<(AsymmetricFamily, f32)>,
    /// Extracted `ModExp` patterns.
    pub mod_exp_patterns: Vec<ModExpPattern>,
    /// Extracted EC patterns.
    pub ec_patterns: Vec<EcPattern>,
}

impl AsymmetricReport {
    /// Top-ranked family.
    #[must_use]
    pub fn top_family(&self) -> Option<AsymmetricFamily> {
        self.ranked.first().map(|(f, _)| *f)
    }

    /// Family detection histogram.
    #[must_use]
    pub fn family_histogram(&self) -> HashMap<AsymmetricFamily, usize> {
        let mut m: HashMap<AsymmetricFamily, usize> = HashMap::new();
        for d in &self.detections {
            *m.entry(d.family).or_insert(0) += 1;
        }
        m
    }

    /// Returns `true` if any ECC pattern was found.
    #[must_use]
    pub fn has_ecc(&self) -> bool {
        self.detections.iter().any(|d| d.family.is_ecc())
    }

    /// Returns `true` if RSA-related constants were found.
    #[must_use]
    pub fn has_rsa(&self) -> bool {
        self.detections.iter().any(|d| d.family == AsymmetricFamily::Rsa)
    }
}

// ── pattern registry ──────────────────────────────────────────────────────────

struct PatternEntry {
    description: &'static str,
    family: AsymmetricFamily,
    bytes: Vec<u8>,
    mask: Vec<u8>,
    weight: f32,
    is_constant: bool,
}

fn builtin_entries() -> Vec<PatternEntry> {
    let mut v = builtin_rsa_ec_entries();
    v.extend(builtin_dh_pq_entries());
    v
}

fn builtin_rsa_ec_entries() -> Vec<PatternEntry> {
    let mut v = builtin_rsa_entries();
    v.extend(builtin_ec_entries());
    v
}

fn builtin_rsa_entries() -> Vec<PatternEntry> {
    vec![
        // ── RSA: Montgomery reduction constant 0xFF + 0 sentinel at start ────
        PatternEntry {
            description: "RSA-montgomery-sentinel",
            family: AsymmetricFamily::Rsa,
            bytes: vec![0x00, 0x00, 0x00, 0x00, 0x01], // typical big-int "1" prefix
            mask: vec![0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
            weight: 0.55,
            is_constant: false,
        },
        // RSA: common public exponent e=65537 = 0x0001_0001
        PatternEntry {
            description: "RSA-e-65537-BE",
            family: AsymmetricFamily::Rsa,
            bytes: vec![0x00, 0x01, 0x00, 0x01],
            mask: vec![0xFF, 0xFF, 0xFF, 0xFF],
            weight: 0.72,
            is_constant: true,
        },
        // RSA: common public exponent e=65537 LE
        PatternEntry {
            description: "RSA-e-65537-LE",
            family: AsymmetricFamily::Rsa,
            bytes: vec![0x01, 0x00, 0x01, 0x00],
            mask: vec![0xFF, 0xFF, 0xFF, 0xFF],
            weight: 0.68,
            is_constant: true,
        },
        // RSA: PKCS#1 DER OID prefix 0x30 0x82 (SEQUENCE tag + 2-byte length)
        PatternEntry {
            description: "RSA-PKCS1-SEQUENCE-tag",
            family: AsymmetricFamily::Rsa,
            bytes: vec![0x30, 0x82],
            mask: vec![0xFF, 0xFF],
            weight: 0.55,
            is_constant: false,
        },
        // RSA OAEP OID hex: 06 09 2A 86 48 86 F7 0D 01 01 07
        PatternEntry {
            description: "RSA-OAEP-OID",
            family: AsymmetricFamily::Rsa,
            bytes: vec![0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x07],
            mask: vec![0xFF; 11],
            weight: 0.92,
            is_constant: true,
        },
        // RSA PKCS v1.5 OID: ...01 01 01
        PatternEntry {
            description: "RSA-PKCS15-OID-tail",
            family: AsymmetricFamily::Rsa,
            bytes: vec![0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01],
            mask: vec![0xFF; 9],
            weight: 0.90,
            is_constant: true,
        },

    ]
}

fn builtin_ec_entries() -> Vec<PatternEntry> {
    vec![
        // ── ECDSA P-256 (secp256r1) prime p constant (first 4 bytes) ─────────
        // p = FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
        PatternEntry {
            description: "P256-prime-prefix",
            family: AsymmetricFamily::EcdsaWeierstrass,
            bytes: vec![0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01],
            mask: vec![0xFF; 8],
            weight: 0.88,
            is_constant: true,
        },
        // P-256 curve order n prefix: FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84
        PatternEntry {
            description: "P256-order-prefix",
            family: AsymmetricFamily::EcdsaWeierstrass,
            bytes: vec![0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF],
            mask: vec![0xFF; 12],
            weight: 0.90,
            is_constant: true,
        },
        // P-384 prime prefix: FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
        PatternEntry {
            description: "P384-prime-prefix",
            family: AsymmetricFamily::EcdsaWeierstrass,
            bytes: vec![0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
            mask: vec![0xFF; 12],
            weight: 0.72,
            is_constant: true,
        },

        // ── Curve25519 (ECDH Montgomery) prime p = 2^255 - 19 ─────────────────
        // p last 4 bytes LE: EC FF FF 7F
        PatternEntry {
            description: "Curve25519-prime-LE-suffix",
            family: AsymmetricFamily::EcdhMontgomery,
            bytes: vec![0xED, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F],
            mask: vec![0xFF; 32],
            weight: 0.96,
            is_constant: true,
        },
        // Curve25519 constant a24 = 121_665 = 0x0001_DB41
        PatternEntry {
            description: "Curve25519-a24-LE",
            family: AsymmetricFamily::EcdhMontgomery,
            bytes: vec![0x41, 0xDB, 0x01, 0x00],
            mask: vec![0xFF; 4],
            weight: 0.82,
            is_constant: true,
        },

        // ── Ed25519 base point y coordinate constant (last 4 bytes LE) ───────
        // y = 4/5 mod p, first 4 bytes LE: 58 66 66 66
        PatternEntry {
            description: "Ed25519-base-y-prefix-LE",
            family: AsymmetricFamily::EcEdwards,
            bytes: vec![0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66],
            mask: vec![0xFF; 8],
            weight: 0.92,
            is_constant: true,
        },
        // Ed25519 -d constant (first 4 bytes LE): 52 03 6C EE
        PatternEntry {
            description: "Ed25519-d-LE",
            family: AsymmetricFamily::EcEdwards,
            bytes: vec![0x52, 0x03, 0x6C, 0xEE],
            mask: vec![0xFF; 4],
            weight: 0.90,
            is_constant: true,
        },

    ]
}

fn builtin_dh_pq_entries() -> Vec<PatternEntry> {
    vec![
        // ── DH/DSA: IANA group-14 prime first 4 bytes BE ─────────────────────
        PatternEntry {
            description: "DH-group14-prime-BE",
            family: AsymmetricFamily::DiffieHellman,
            bytes: vec![0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                        0xC9, 0x0F, 0xDA, 0xA2],
            mask: vec![0xFF; 12],
            weight: 0.88,
            is_constant: true,
        },
        // DH: generator 2 push (PUSH 2)
        PatternEntry {
            description: "DH-generator-push-2",
            family: AsymmetricFamily::DiffieHellman,
            bytes: vec![0x6A, 0x02], // PUSH 2
            mask: vec![0xFF, 0xFF],
            weight: 0.52,
            is_constant: false,
        },

        // ── Dilithium: modulus q = 8_380_417 = 0x7F_E001 LE ─────────────────────
        PatternEntry {
            description: "Dilithium-q-LE",
            family: AsymmetricFamily::Dilithium,
            bytes: vec![0x01, 0xE0, 0x7F, 0x00],
            mask: vec![0xFF; 4],
            weight: 0.88,
            is_constant: true,
        },

        // ── Kyber: modulus q = 3329 = 0x0D01 LE ─────────────────────────────
        PatternEntry {
            description: "Kyber-q-LE",
            family: AsymmetricFamily::Kyber,
            bytes: vec![0x01, 0x0D, 0x00, 0x00],
            mask: vec![0xFF; 4],
            weight: 0.80,
            is_constant: true,
        },
        // Kyber NTT constant zeta_0 = 17 = 0x11
        PatternEntry {
            description: "Kyber-zeta0",
            family: AsymmetricFamily::Kyber,
            bytes: vec![0x11, 0x00, 0x00, 0x00],
            mask: vec![0xFF, 0xFF, 0xFF, 0xFF],
            weight: 0.60,
            is_constant: true,
        },

        // ── ElGamal: generic large-prime exponentiation (detect by MULX pattern)
        PatternEntry {
            description: "ElGamal-MULX-hint",
            family: AsymmetricFamily::ElGamal,
            bytes: vec![0xC4, 0xE2, 0xFB, 0xF6], // MULX edx:eax, ebx, esi (VEX)
            mask: vec![0xFF, 0xFF, 0xFF, 0xFF],
            weight: 0.55,
            is_constant: false,
        },
    ]
}

// ── AsymmetricDetector ────────────────────────────────────────────────────────

/// Scans binary data for asymmetric cryptography implementations.
pub struct AsymmetricDetector {
    /// Minimum confidence for reporting.
    pub min_confidence: f32,
    entries: Vec<PatternEntry>,
}

impl Default for AsymmetricDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl AsymmetricDetector {
    /// Create with default settings.
    #[must_use]
    pub fn new() -> Self {
        Self { min_confidence: 0.55, entries: builtin_entries() }
    }

    /// Override minimum confidence threshold.
    #[must_use]
    pub const fn with_min_confidence(mut self, min: f32) -> Self {
        self.min_confidence = min;
        self
    }

    /// Scan `binary` for asymmetric crypto patterns.
    #[must_use]
    pub fn scan(&self, binary: &[u8]) -> Vec<AsymmetricDetection> {
        let mut out: Vec<AsymmetricDetection> = Vec::new();
        for entry in &self.entries {
            if entry.weight < self.min_confidence {
                continue;
            }
            for offset in masked_scan(binary, &entry.bytes, &entry.mask) {
                out.push(AsymmetricDetection::new(
                    entry.family,
                    offset,
                    entry.weight,
                    format!("'{}' at 0x{:X}", entry.description, offset),
                    entry.is_constant,
                ));
            }
        }
        out.sort_by_key(|d| d.offset);
        out
    }

    /// Identify likely asymmetric families; returns ranked pairs.
    #[must_use]
    pub fn identify(&self, binary: &[u8]) -> Vec<(AsymmetricFamily, f32)> {
        let dets = self.scan(binary);
        let mut buckets: HashMap<AsymmetricFamily, Vec<f32>> = HashMap::new();
        for d in &dets {
            buckets.entry(d.family).or_default().push(d.confidence);
        }
        let mut ranked: Vec<(AsymmetricFamily, f32)> = buckets
            .into_iter()
            .map(|(f, v)| (f, combined_confidence(v.iter().copied())))
            .filter(|(_, c)| *c >= self.min_confidence)
            .collect();
        ranked.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        ranked
    }

    /// Extract structural modular-exponentiation patterns.
    #[must_use]
    pub fn extract_mod_exp_patterns(&self, binary: &[u8]) -> Vec<ModExpPattern> {
        // Heuristic: look for sequences that suggest repeated squaring:
        // IMUL + MOV + IMUL clusters within 64 bytes.
        let mut found = Vec::new();
        if binary.len() < 6 {
            return found;
        }
        for i in 0..binary.len() - 5 {
            let w = &binary[i..i + 6];
            // IMUL reg, reg/mem: 0F AF
            if w[0] == 0x0F && w[1] == 0xAF {
                // Look for another IMUL within 24 bytes
                if i + 30 <= binary.len() {
                    let window = &binary[i + 2..i + 26];
                    if window.windows(2).any(|b| b[0] == 0x0F && b[1] == 0xAF) {
                        found.push(ModExpPattern {
                            offset: i,
                            span: 26,
                            confidence: 0.60,
                            description: "consecutive IMUL cluster (repeated squaring hint)".into(),
                        });
                    }
                }
            }
        }
        found
    }

    /// Extract EC point arithmetic patterns.
    #[must_use]
    pub fn extract_ec_patterns(&self, binary: &[u8]) -> Vec<EcPattern> {
        let mut found = Vec::new();
        // P-256 prime prefix check
        let p256_prefix = [0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01];
        for offset in masked_scan(binary, &p256_prefix, &[0xFF; 8]) {
            found.push(EcPattern {
                offset,
                span: 8,
                confidence: 0.88,
                description: "P-256 prime prefix".into(),
                family: AsymmetricFamily::EcdsaWeierstrass,
            });
        }
        // Ed25519 -d constant
        let ed25519_d = [0x52, 0x03, 0x6C, 0xEE];
        for offset in masked_scan(binary, &ed25519_d, &[0xFF; 4]) {
            found.push(EcPattern {
                offset,
                span: 4,
                confidence: 0.90,
                description: "Ed25519 -d constant".into(),
                family: AsymmetricFamily::EcEdwards,
            });
        }
        found
    }

    /// Produce full report.
    #[must_use]
    pub fn full_report(&self, binary: &[u8]) -> AsymmetricReport {
        let detections = self.scan(binary);
        let ranked = self.identify(binary);
        let mod_exp_patterns = self.extract_mod_exp_patterns(binary);
        let ec_patterns = self.extract_ec_patterns(binary);
        AsymmetricReport { detections, ranked, mod_exp_patterns, ec_patterns }
    }
}

// ── helpers ───────────────────────────────────────────────────────────────────

fn masked_scan(data: &[u8], pattern: &[u8], mask: &[u8]) -> Vec<usize> {
    let plen = pattern.len();
    if plen == 0 || plen > data.len() {
        return Vec::new();
    }
    let mut out = Vec::new();
    for pos in 0..=(data.len() - plen) {
        let hit = pattern
            .iter()
            .enumerate()
            .all(|(i, &p)| mask[i] == 0x00 || (data[pos + i] & mask[i]) == (p & mask[i]));
        if hit {
            out.push(pos);
        }
    }
    out
}

fn combined_confidence(scores: impl Iterator<Item = f32>) -> f32 {
    let miss = scores.fold(1.0f32, |acc, s| acc * (1.0 - s.clamp(0.0, 1.0)));
    (1.0 - miss).clamp(0.0, 0.99)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scan_rsa_e_65537_be() {
        let b = [0x00, 0x01, 0x00, 0x01];
        let d = AsymmetricDetector::new();
        let dets = d.scan(&b);
        assert!(dets.iter().any(|x| x.family == AsymmetricFamily::Rsa));
    }

    #[test]
    fn test_scan_rsa_oaep_oid() {
        let b = [0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x07];
        let d = AsymmetricDetector::new();
        let dets = d.scan(&b);
        assert!(dets.iter().any(|x| x.family == AsymmetricFamily::Rsa && x.confidence >= 0.90));
    }

    #[test]
    fn test_scan_p256_prime_prefix() {
        let b = [0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01];
        let d = AsymmetricDetector::new();
        let dets = d.scan(&b);
        assert!(dets.iter().any(|x| x.family == AsymmetricFamily::EcdsaWeierstrass));
    }

    #[test]
    fn test_scan_curve25519_a24() {
        let b = 0x0001_DB41u32.to_le_bytes();
        let d = AsymmetricDetector::new();
        let dets = d.scan(&b);
        assert!(dets.iter().any(|x| x.family == AsymmetricFamily::EcdhMontgomery));
    }

    #[test]
    fn test_scan_ed25519_d() {
        let b = [0x52, 0x03, 0x6C, 0xEE];
        let d = AsymmetricDetector::new();
        let dets = d.scan(&b);
        assert!(dets.iter().any(|x| x.family == AsymmetricFamily::EcEdwards));
    }

    #[test]
    fn test_scan_dilithium_q() {
        let b = [0x01, 0xE0, 0x7F, 0x00];
        let d = AsymmetricDetector::new();
        let dets = d.scan(&b);
        assert!(dets.iter().any(|x| x.family == AsymmetricFamily::Dilithium));
    }

    #[test]
    fn test_scan_kyber_q() {
        let b = [0x01, 0x0D, 0x00, 0x00];
        let d = AsymmetricDetector::new();
        let dets = d.scan(&b);
        assert!(dets.iter().any(|x| x.family == AsymmetricFamily::Kyber));
    }

    #[test]
    fn test_identify_rsa_ranked() {
        let mut data = Vec::new();
        data.extend_from_slice(&[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01]);
        data.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
        let d = AsymmetricDetector::new();
        let ranked = d.identify(&data);
        assert!(!ranked.is_empty());
        assert_eq!(ranked[0].0, AsymmetricFamily::Rsa);
    }

    #[test]
    fn test_full_report_has_rsa() {
        let b = [0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x07];
        let d = AsymmetricDetector::new();
        let report = d.full_report(&b);
        assert!(report.has_rsa());
    }

    #[test]
    fn test_full_report_has_ecc() {
        let b = [0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01];
        let d = AsymmetricDetector::new();
        let report = d.full_report(&b);
        assert!(report.has_ecc());
    }

    #[test]
    fn test_family_histogram() {
        let mut data = Vec::new();
        data.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // rsa e
        data.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01]); // p256
        let d = AsymmetricDetector::new();
        let report = d.full_report(&data);
        let hist = report.family_histogram();
        assert!(hist.contains_key(&AsymmetricFamily::Rsa));
        assert!(hist.contains_key(&AsymmetricFamily::EcdsaWeierstrass));
    }

    #[test]
    fn test_extract_ec_patterns_p256() {
        let b = [0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01];
        let d = AsymmetricDetector::new();
        let pats = d.extract_ec_patterns(&b);
        assert!(!pats.is_empty());
        assert!(pats.iter().any(|p| p.family == AsymmetricFamily::EcdsaWeierstrass));
    }

    #[test]
    fn test_family_predicates() {
        assert!(AsymmetricFamily::EcdsaWeierstrass.is_ecc());
        assert!(!AsymmetricFamily::Rsa.is_ecc());
        assert!(AsymmetricFamily::Kyber.is_post_quantum());
        assert!(!AsymmetricFamily::Rsa.is_post_quantum());
    }

    #[test]
    fn test_typical_key_bits() {
        assert_eq!(AsymmetricFamily::Rsa.typical_key_bits(), Some(2048));
        assert_eq!(AsymmetricFamily::EcdsaWeierstrass.typical_key_bits(), Some(256));
        assert_eq!(AsymmetricFamily::Unknown.typical_key_bits(), None);
    }

    #[test]
    fn test_min_confidence_filter() {
        let b = [0x6A, 0x02]; // DH generator, weight 0.52
        let d = AsymmetricDetector::new().with_min_confidence(0.70);
        let dets = d.scan(&b);
        // weight 0.52 < 0.70 → filtered
        assert!(dets.iter().all(|det| det.confidence >= 0.70));
    }
}
