//! `rustre-crypto-id`
//!
//! Cryptographic algorithm identification in binary data.
//! Scans for known constants, S-boxes, and algorithmic patterns.

pub mod protocol_analysis;
pub mod algorithm_db;
pub mod cipher_detection;
pub mod constant_scanner;
pub mod hash_identifier;
pub mod impl_detector;
pub mod protocol_crypto;
pub mod constant_db;
pub mod active_prober;
pub mod side_channel_hints;
pub mod hash_function_detector;
pub mod stream_cipher_detector;
pub mod asymmetric_detector;

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use thiserror::Error;

// ── Error ────────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum CryptoIdError {
    #[error("binary too short for scanning")]
    TooShort,
    #[error("signature database error: {0}")]
    Database(String),
}

// ── CryptoAlgorithm ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CryptoAlgorithm {
    Md5,
    Sha1,
    Sha256,
    Sha512,
    Sha3_256,
    Blake2b,
    Aes128,
    Aes256,
    Des,
    TripleDes,
    Rc4,
    ChaCha20,
    Salsa20,
    Rsa,
    Ecdsa,
    Ed25519,
    X25519,
    Crc32,
    Adler32,
    Sm3,
    Sm4,
    Whirlpool,
    Tiger,
    Ripemd160,
}

impl std::fmt::Display for CryptoAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Md5 => "MD5",
            Self::Sha1 => "SHA-1",
            Self::Sha256 => "SHA-256",
            Self::Sha512 => "SHA-512",
            Self::Sha3_256 => "SHA3-256",
            Self::Blake2b => "BLAKE2b",
            Self::Aes128 => "AES-128",
            Self::Aes256 => "AES-256",
            Self::Des => "DES",
            Self::TripleDes => "3DES",
            Self::Rc4 => "RC4",
            Self::ChaCha20 => "ChaCha20",
            Self::Salsa20 => "Salsa20",
            Self::Rsa => "RSA",
            Self::Ecdsa => "ECDSA",
            Self::Ed25519 => "Ed25519",
            Self::X25519 => "X25519",
            Self::Crc32 => "CRC32",
            Self::Adler32 => "Adler32",
            Self::Sm3 => "SM3",
            Self::Sm4 => "SM4",
            Self::Whirlpool => "Whirlpool",
            Self::Tiger => "Tiger",
            Self::Ripemd160 => "RIPEMD-160",
        };
        write!(f, "{s}")
    }
}

// ── CryptoConstant ────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct CryptoConstant {
    pub name: String,
    pub algorithm: CryptoAlgorithm,
    pub value: Vec<u8>,
    pub size: usize,
}

// ── CryptoHit ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoHit {
    pub offset: usize,
    pub algorithm: CryptoAlgorithm,
    pub constant: String,
    pub confidence: f64,
}

// ── KeyCandidate ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyCandidate {
    pub offset: usize,
    pub length: usize,
    pub entropy: f64,
    pub description: String,
}

// ── CryptoReport ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoReport {
    pub algorithms_found: Vec<CryptoHit>,
    pub possible_keys: Vec<KeyCandidate>,
    pub recommendations: Vec<String>,
}

/// Coarse confidence band for an algorithm assessment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConfidenceLevel {
    Low,
    Medium,
    High,
}

impl ConfidenceLevel {
    fn from_score(score: f64) -> Self {
        if score >= 0.80 {
            Self::High
        } else if score >= 0.50 {
            Self::Medium
        } else {
            Self::Low
        }
    }
}

/// Type of evidence that contributed to a crypto identification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EvidenceKind {
    Constant,
    FunctionPattern,
    KeyMaterial,
}

/// Normalized evidence item used by deterministic identification APIs.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IdentificationEvidence {
    pub kind: EvidenceKind,
    pub algorithm: Option<CryptoAlgorithm>,
    pub offset: Option<usize>,
    pub label: String,
    pub confidence: f64,
}

/// Ranked assessment for a candidate crypto algorithm.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AlgorithmAssessment {
    pub algorithm: CryptoAlgorithm,
    pub evidence_count: usize,
    pub confidence: f64,
    pub level: ConfidenceLevel,
    pub evidence: Vec<IdentificationEvidence>,
}

/// Active probe categories that downstream tooling can execute.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ActiveProbeKind {
    BlockSizeSweep,
    EcbRepetition,
    PaddingMutation,
    KnownPlaintextAvalanche,
}

/// Concrete active probe payload with deterministic bytes and intent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActiveProbe {
    pub id: String,
    pub algorithm: Option<CryptoAlgorithm>,
    pub kind: ActiveProbeKind,
    pub payload: Vec<u8>,
    pub expected_observation: String,
}

/// Output of the active identification planning API.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ActiveIdentificationPlan {
    pub assessments: Vec<AlgorithmAssessment>,
    pub probes: Vec<ActiveProbe>,
}

/// Configuration for deterministic identification and probe planning.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct IdentificationConfig {
    pub min_confidence: f64,
    pub max_probes_per_algorithm: usize,
    pub include_key_candidates: bool,
}

impl Default for IdentificationConfig {
    fn default() -> Self {
        Self {
            min_confidence: 0.50,
            max_probes_per_algorithm: 2,
            include_key_candidates: true,
        }
    }
}

// ── Known constants ───────────────────────────────────────────────────────────

/// MD5 initial hash values (little-endian in memory).
pub const MD5_H: [u32; 4] = [0x6745_2301, 0xEFCD_AB89, 0x98BA_DCFE, 0x1032_5476];

/// SHA-1 initial hash values.
pub const SHA1_H: [u32; 5] = [
    0x6745_2301,
    0xEFCD_AB89,
    0x98BA_DCFE,
    0x1032_5476,
    0xC3D2_E1F0,
];

/// SHA-256 initial hash values.
pub const SHA256_H: [u32; 8] = [
    0x6a09_e667,
    0xbb67_ae85,
    0x3c6e_f372,
    0xa54f_f53a,
    0x510e_527f,
    0x9b05_688c,
    0x1f83_d9ab,
    0x5be0_cd19,
];

/// SHA-256 K constants (first 16).
pub const SHA256_K: [u32; 16] = [
    0x428a_2f98,
    0x7137_4491,
    0xb5c0_fbcf,
    0xe9b5_dba5,
    0x3956_c25b,
    0x59f1_11f1,
    0x923f_82a4,
    0xab1c_5ed5,
    0xd807_aa98,
    0x1283_5b01,
    0x2431_85be,
    0x550c_7dc3,
    0x72be_5d74,
    0x80de_b1fe,
    0x9bdc_06a7,
    0xc19b_f174,
];

/// AES S-box (256 bytes).
pub const AES_SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

/// AES inverse S-box.
pub const AES_INV_SBOX: [u8; 256] = [
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
];

/// AES Rcon table.
pub const AES_RCON: [u8; 11] = [
    0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36,
];

/// CRC32 polynomial table (first 8 entries for detection — full table is 1 KiB).
pub const CRC32_POLY: u32 = 0xEDB8_8320; // Reversed polynomial.

/// SM4 S-box (256 bytes).
pub const SM4_SBOX: [u8; 256] = [
    0xD6, 0x90, 0xE9, 0xFE, 0xCC, 0xE1, 0x3D, 0xB7, 0x16, 0xB6, 0x14, 0xC2, 0x28, 0xFB, 0x2C, 0x05,
    0x2B, 0x67, 0x9A, 0x76, 0x2A, 0xBE, 0x04, 0xC3, 0xAA, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
    0x9C, 0x42, 0x50, 0xF4, 0x91, 0xEF, 0x98, 0x7A, 0x33, 0x54, 0x0B, 0x43, 0xED, 0xCF, 0xAC, 0x62,
    0xE4, 0xB3, 0x1C, 0xA9, 0xC9, 0x08, 0xE8, 0x95, 0x80, 0xDF, 0x94, 0xFA, 0x75, 0x8F, 0x3F, 0xA6,
    0x47, 0x07, 0xA7, 0xFC, 0xF3, 0x73, 0x17, 0xBA, 0x83, 0x59, 0x3C, 0x19, 0xE6, 0x85, 0x4F, 0xA8,
    0x68, 0x6B, 0x81, 0xB2, 0x71, 0x64, 0xDA, 0x8B, 0xF8, 0xEB, 0x0F, 0x4B, 0x70, 0x56, 0x9D, 0x35,
    0x1E, 0x24, 0x0E, 0x5E, 0x63, 0x58, 0xD1, 0xA2, 0x25, 0x22, 0x7C, 0x3B, 0x01, 0x21, 0x78, 0x87,
    0xD4, 0x00, 0x46, 0x57, 0x9F, 0xD3, 0x27, 0x52, 0x4C, 0x36, 0x02, 0xE7, 0xA0, 0xC4, 0xC8, 0x9E,
    0xEA, 0xBF, 0x8A, 0xD2, 0x40, 0xC7, 0x38, 0xB5, 0xA3, 0xF7, 0xF2, 0xCE, 0xF9, 0x61, 0x15, 0xA1,
    0xE0, 0xAE, 0x5D, 0xA4, 0x9B, 0x34, 0x1A, 0x55, 0xAD, 0x93, 0x32, 0x30, 0xF5, 0x8C, 0xB1, 0xE3,
    0x1D, 0xF6, 0xE2, 0x2E, 0x82, 0x66, 0xCA, 0x60, 0xC0, 0x29, 0x23, 0xAB, 0x0D, 0x53, 0x4E, 0x6F,
    0xD5, 0xDB, 0x37, 0x45, 0xDE, 0xFD, 0x8E, 0x2F, 0x03, 0xFF, 0x6A, 0x72, 0x6D, 0x6C, 0x5B, 0x51,
    0x8D, 0x1B, 0xAF, 0x92, 0xBB, 0xDD, 0xBC, 0x7F, 0x11, 0xD9, 0x5C, 0x41, 0x1F, 0x10, 0x5A, 0xD8,
    0x0A, 0xC1, 0x31, 0x88, 0xA5, 0xCD, 0x7B, 0xBD, 0x2D, 0x74, 0xD0, 0x12, 0xB8, 0xE5, 0xB4, 0xB0,
    0x89, 0x69, 0x97, 0x4A, 0x0C, 0x96, 0x77, 0x7E, 0x65, 0xB9, 0xF1, 0x09, 0xC5, 0x6E, 0xC6, 0x84,
    0x18, 0xF0, 0x7D, 0xEC, 0x3A, 0xDC, 0x4D, 0x20, 0x79, 0xEE, 0x5F, 0x3E, 0xD7, 0xCB, 0x39, 0x48,
];

// ── SignatureDatabase ─────────────────────────────────────────────────────────

/// Built-in database of crypto signatures.
pub struct SignatureDatabase {
    constants: Arc<RwLock<Vec<CryptoConstant>>>,
}

impl Default for SignatureDatabase {
    fn default() -> Self {
        Self::new()
    }
}

impl SignatureDatabase {
    #[must_use]
    pub fn new() -> Self {
        let db = Self {
            constants: Arc::new(RwLock::new(Vec::new())),
        };
        db.load_builtins();
        db
    }

    fn load_builtins(&self) {
        let mut constants = self.constants.write();

        // MD5 initial values (16 bytes little-endian).
        let md5_bytes: Vec<u8> = MD5_H.iter().flat_map(|&h| h.to_le_bytes()).collect();
        constants.push(CryptoConstant {
            name: "MD5-H0".into(),
            algorithm: CryptoAlgorithm::Md5,
            size: md5_bytes.len(),
            value: md5_bytes,
        });

        // SHA-1 initial values.
        let sha1_bytes: Vec<u8> = SHA1_H.iter().flat_map(|&h| h.to_le_bytes()).collect();
        constants.push(CryptoConstant {
            name: "SHA1-H0".into(),
            algorithm: CryptoAlgorithm::Sha1,
            size: sha1_bytes.len(),
            value: sha1_bytes,
        });

        // SHA-256 initial values.
        let sha256_h: Vec<u8> = SHA256_H.iter().flat_map(|&h| h.to_be_bytes()).collect();
        constants.push(CryptoConstant {
            name: "SHA256-H0".into(),
            algorithm: CryptoAlgorithm::Sha256,
            size: sha256_h.len(),
            value: sha256_h,
        });

        // SHA-256 K constants (64 bytes = 16 words).
        let sha256_k: Vec<u8> = SHA256_K.iter().flat_map(|&k| k.to_be_bytes()).collect();
        constants.push(CryptoConstant {
            name: "SHA256-K0".into(),
            algorithm: CryptoAlgorithm::Sha256,
            size: sha256_k.len(),
            value: sha256_k,
        });

        // AES S-box.
        constants.push(CryptoConstant {
            name: "AES-SBOX".into(),
            algorithm: CryptoAlgorithm::Aes128,
            size: 256,
            value: AES_SBOX.to_vec(),
        });

        // AES inverse S-box.
        constants.push(CryptoConstant {
            name: "AES-INV-SBOX".into(),
            algorithm: CryptoAlgorithm::Aes128,
            size: 256,
            value: AES_INV_SBOX.to_vec(),
        });

        // SM4 S-box.
        constants.push(CryptoConstant {
            name: "SM4-SBOX".into(),
            algorithm: CryptoAlgorithm::Sm4,
            size: 256,
            value: SM4_SBOX.to_vec(),
        });

        // CRC32 table signature: first entry after 0 is always the polynomial value.
        let crc32_table = build_crc32_table();
        let crc32_bytes: Vec<u8> = crc32_table.iter().flat_map(|&w| w.to_le_bytes()).collect();
        constants.push(CryptoConstant {
            name: "CRC32-TABLE".into(),
            algorithm: CryptoAlgorithm::Crc32,
            size: 1024,
            value: crc32_bytes,
        });

        // SHA-512 initial values.
        let sha512_h: [u64; 8] = [
            0x6a09_e667_f3bc_c908,
            0xbb67_ae85_84ca_a73b,
            0x3c6e_f372_fe94_f82b,
            0xa54f_f53a_5f1d_36f1,
            0x510e_527f_ade6_82d1,
            0x9b05_688c_2b3e_6c1f,
            0x1f83_d9ab_fb41_bd6b,
            0x5be0_cd19_137e_2179,
        ];
        let sha512_bytes: Vec<u8> = sha512_h.iter().flat_map(|&h| h.to_be_bytes()).collect();
        constants.push(CryptoConstant {
            name: "SHA512-H0".into(),
            algorithm: CryptoAlgorithm::Sha512,
            size: sha512_bytes.len(),
            value: sha512_bytes,
        });

        // RIPEMD-160 corroborating signature.
        // The H0 vector shares its first 4 words with MD5/SHA-1, so using it
        // alone produces false positives.  Instead we anchor on the 5th init
        // word (0xC3D2_E1F0) immediately followed by the left-rotation round
        // constant 0x50A2_8BE6, which is unique to RIPEMD-160 and never appears
        // in MD5 or SHA-1 implementations.
        let rmd160_anchor: [u32; 2] = [0xc3d2_e1f0, 0x50a2_8be6];
        let rmd160_bytes: Vec<u8> = rmd160_anchor.iter().flat_map(|&h| h.to_le_bytes()).collect();
        constants.push(CryptoConstant {
            name: "RIPEMD160-ANCHOR".into(),
            algorithm: CryptoAlgorithm::Ripemd160,
            size: rmd160_bytes.len(),
            value: rmd160_bytes,
        });
    }

    #[must_use]
    pub fn constants(&self) -> Vec<CryptoConstant> {
        self.constants.read().clone()
    }

    pub fn add(&self, constant: CryptoConstant) {
        self.constants.write().push(constant);
    }
}

fn build_crc32_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    for i in 0u32..256 {
        let mut crc = i;
        for _ in 0..8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ CRC32_POLY;
            } else {
                crc >>= 1;
            }
        }
        table[i as usize] = crc;
    }
    table
}

// ── BinaryScanner ─────────────────────────────────────────────────────────────

/// Scans raw binary data for crypto constant signatures.
pub struct BinaryScanner {
    db: SignatureDatabase,
}

impl Default for BinaryScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl BinaryScanner {
    #[must_use]
    pub fn new() -> Self {
        Self {
            db: SignatureDatabase::new(),
        }
    }

    #[must_use]
    pub const fn with_database(db: SignatureDatabase) -> Self {
        Self { db }
    }

    /// Scan binary for all known crypto constants.
    #[must_use]
    pub fn scan(&self, data: &[u8]) -> Vec<CryptoHit> {
        let mut hits = Vec::new();
        // Collect under lock then release before sorting.
        let snapshot: Vec<_> = self.db.constants.read().iter().cloned().collect();

        for constant in &snapshot {
            if constant.value.is_empty() || constant.value.len() > data.len() {
                continue;
            }
            let limit = data.len() - constant.value.len();
            let needle = &constant.value;
            for offset in 0..=limit {
                if data[offset..offset + needle.len()] == needle[..] {
                    hits.push(CryptoHit {
                        offset,
                        algorithm: constant.algorithm,
                        constant: constant.name.clone(),
                        confidence: Self::confidence_for(&constant.name, constant.size),
                    });
                }
            }
        }

        hits.sort_by_key(|h| h.offset);
        hits
    }

    fn confidence_for(name: &str, size: usize) -> f64 {
        if size >= 256 {
            0.95 // Large tables → very high confidence.
        } else if size >= 32 {
            0.80
        } else if name.contains("H0") {
            0.70 // Init vectors are common, slightly lower.
        } else {
            0.60
        }
    }
}

// ── FunctionScanner ───────────────────────────────────────────────────────────

/// Analyses function byte sequences for algorithmic patterns.
pub struct FunctionScanner;

/// Description of a detected algorithmic pattern.
#[derive(Debug, Clone)]
pub struct PatternHit {
    pub algorithm: CryptoAlgorithm,
    pub description: String,
    pub confidence: f32,
}

impl FunctionScanner {
    /// Analyse a raw byte slice (function body) for crypto patterns.
    #[must_use]
    pub fn analyze(code: &[u8]) -> Vec<PatternHit> {
        let mut hits = Vec::new();

        // Heuristic: many byte-rotation and XOR instructions are characteristic of ChaCha20/Salsa20.
        let xor_count = code
            .windows(2)
            .filter(|w| w[0] == 0x31 || w[0] == 0x33)
            .count(); // XOR r,r / XOR r,m (x86)
        let rol_count = code
            .windows(2)
            .filter(|w| w[0] == 0xc1 && (w[1] & 0xF8 == 0xC0))
            .count();
        if xor_count > 30 && rol_count > 8 {
            hits.push(PatternHit {
                algorithm: CryptoAlgorithm::ChaCha20,
                description: format!("High XOR density ({xor_count}) + rotates ({rol_count})"),
                confidence: 0.65,
            });
        }

        // Heuristic: RC4 KSA — swap loop with index manipulation.
        // Look for repeated INC + MOV + XCHG sequences.
        let xchg_count = code
            .windows(1)
            .filter(|w| w[0] == 0x87 || w[0] == 0x86)
            .count();
        if xchg_count > 10 {
            hits.push(PatternHit {
                algorithm: CryptoAlgorithm::Rc4,
                description: format!("High XCHG density ({xchg_count}) — RC4 KSA"),
                confidence: 0.55,
            });
        }

        // Heuristic: RSA / modular exponentiation — lots of MUL instructions.
        let mul_count = code
            .windows(2)
            .filter(|w| w[0] == 0xF7 && (w[1] & 0xF8 == 0xE0))
            .count();
        if mul_count > 20 {
            hits.push(PatternHit {
                algorithm: CryptoAlgorithm::Rsa,
                description: format!("High MUL density ({mul_count}) — possible modexp"),
                confidence: 0.50,
            });
        }

        hits
    }
}

impl CryptoReport {
    /// Convert report fields into normalized evidence records.
    #[must_use]
    pub fn evidence(&self, config: IdentificationConfig) -> Vec<IdentificationEvidence> {
        let mut evidence: Vec<IdentificationEvidence> = self
            .algorithms_found
            .iter()
            .map(|hit| IdentificationEvidence {
                kind: EvidenceKind::Constant,
                algorithm: Some(hit.algorithm),
                offset: Some(hit.offset),
                label: hit.constant.clone(),
                confidence: hit.confidence,
            })
            .collect();

        if config.include_key_candidates {
            evidence.extend(self.possible_keys.iter().map(|key| IdentificationEvidence {
                kind: EvidenceKind::KeyMaterial,
                algorithm: None,
                offset: Some(key.offset),
                label: key.description.clone(),
                confidence: key.entropy,
            }));
        }

        evidence.sort_by(|left, right| evidence_sort_key(left).cmp(&evidence_sort_key(right)));
        evidence
    }

    /// Build deterministic algorithm assessments from report evidence.
    #[must_use]
    pub fn assessments(&self, config: IdentificationConfig) -> Vec<AlgorithmAssessment> {
        let mut grouped: Vec<(CryptoAlgorithm, Vec<IdentificationEvidence>)> = Vec::new();

        for evidence in self.evidence(config) {
            let Some(algorithm) = evidence.algorithm else {
                continue;
            };
            if let Some((_, items)) = grouped
                .iter_mut()
                .find(|(candidate, _)| *candidate == algorithm)
            {
                items.push(evidence);
            } else {
                grouped.push((algorithm, vec![evidence]));
            }
        }

        let mut assessments: Vec<AlgorithmAssessment> = grouped
            .into_iter()
            .filter_map(|(algorithm, evidence)| {
                let confidence = combined_confidence(evidence.iter().map(|item| item.confidence));
                if confidence < config.min_confidence {
                    return None;
                }
                Some(AlgorithmAssessment {
                    algorithm,
                    evidence_count: evidence.len(),
                    confidence,
                    level: ConfidenceLevel::from_score(confidence),
                    evidence,
                })
            })
            .collect();

        assessments.sort_by(|left, right| {
            right
                .confidence
                .partial_cmp(&left.confidence)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| algorithm_rank(left.algorithm).cmp(&algorithm_rank(right.algorithm)))
        });
        assessments
    }

    /// Build an active probe plan from the ranked assessments.
    #[must_use]
    pub fn active_identification_plan(
        &self,
        config: IdentificationConfig,
    ) -> ActiveIdentificationPlan {
        let assessments = self.assessments(config);
        let probes = build_active_probes(&assessments, config.max_probes_per_algorithm);
        ActiveIdentificationPlan {
            assessments,
            probes,
        }
    }
}

fn combined_confidence(scores: impl Iterator<Item = f64>) -> f64 {
    let miss_probability = scores.fold(1.0f64, |acc, score| acc * (1.0 - score.clamp(0.0, 1.0)));
    (1.0 - miss_probability).clamp(0.0, 0.99)
}

fn evidence_sort_key(evidence: &IdentificationEvidence) -> (usize, usize, usize, &str) {
    (
        evidence.algorithm.map_or(usize::MAX, algorithm_rank),
        evidence.offset.unwrap_or(usize::MAX),
        evidence_kind_rank(evidence.kind),
        evidence.label.as_str(),
    )
}

const fn evidence_kind_rank(kind: EvidenceKind) -> usize {
    match kind {
        EvidenceKind::Constant => 0,
        EvidenceKind::FunctionPattern => 1,
        EvidenceKind::KeyMaterial => 2,
    }
}

const fn algorithm_rank(algorithm: CryptoAlgorithm) -> usize {
    match algorithm {
        CryptoAlgorithm::Md5 => 0,
        CryptoAlgorithm::Sha1 => 1,
        CryptoAlgorithm::Sha256 => 2,
        CryptoAlgorithm::Sha512 => 3,
        CryptoAlgorithm::Sha3_256 => 4,
        CryptoAlgorithm::Blake2b => 5,
        CryptoAlgorithm::Aes128 => 6,
        CryptoAlgorithm::Aes256 => 7,
        CryptoAlgorithm::Des => 8,
        CryptoAlgorithm::TripleDes => 9,
        CryptoAlgorithm::Rc4 => 10,
        CryptoAlgorithm::ChaCha20 => 11,
        CryptoAlgorithm::Salsa20 => 12,
        CryptoAlgorithm::Rsa => 13,
        CryptoAlgorithm::Ecdsa => 14,
        CryptoAlgorithm::Ed25519 => 15,
        CryptoAlgorithm::X25519 => 16,
        CryptoAlgorithm::Crc32 => 17,
        CryptoAlgorithm::Adler32 => 18,
        CryptoAlgorithm::Sm3 => 19,
        CryptoAlgorithm::Sm4 => 20,
        CryptoAlgorithm::Whirlpool => 21,
        CryptoAlgorithm::Tiger => 22,
        CryptoAlgorithm::Ripemd160 => 23,
    }
}

fn build_active_probes(
    assessments: &[AlgorithmAssessment],
    max_per_algorithm: usize,
) -> Vec<ActiveProbe> {
    let mut probes = Vec::new();
    for assessment in assessments {
        for probe in probes_for_algorithm(assessment.algorithm)
            .into_iter()
            .take(max_per_algorithm)
        {
            probes.push(probe);
        }
    }
    probes
}

fn probes_for_algorithm(algorithm: CryptoAlgorithm) -> Vec<ActiveProbe> {
    match algorithm {
        CryptoAlgorithm::Aes128 | CryptoAlgorithm::Aes256 | CryptoAlgorithm::Sm4 => vec![
            ActiveProbe {
                id: format!("{}-ecb-repeat-16", probe_slug(algorithm)),
                algorithm: Some(algorithm),
                kind: ActiveProbeKind::EcbRepetition,
                payload: vec![0x41; 64],
                expected_observation: "Identical 16-byte ciphertext blocks suggest ECB mode".into(),
            },
            ActiveProbe {
                id: format!("{}-padding-flip", probe_slug(algorithm)),
                algorithm: Some(algorithm),
                kind: ActiveProbeKind::PaddingMutation,
                payload: padding_probe_payload(16),
                expected_observation: "Different validity for the final-byte mutation suggests CBC padding oracle behavior".into(),
            },
        ],
        CryptoAlgorithm::Des | CryptoAlgorithm::TripleDes => vec![ActiveProbe {
            id: format!("{}-block-size-8", probe_slug(algorithm)),
            algorithm: Some(algorithm),
            kind: ActiveProbeKind::BlockSizeSweep,
            payload: (0u8..40).collect(),
            expected_observation: "Length changes every 8 bytes suggest a 64-bit block cipher".into(),
        }],
        CryptoAlgorithm::Rc4 | CryptoAlgorithm::ChaCha20 | CryptoAlgorithm::Salsa20 => {
            vec![ActiveProbe {
                id: format!("{}-avalanche", probe_slug(algorithm)),
                algorithm: Some(algorithm),
                kind: ActiveProbeKind::KnownPlaintextAvalanche,
                payload: stream_probe_payload(),
                expected_observation: "Single-bit plaintext deltas should map to single-bit ciphertext deltas for stream ciphers".into(),
            }]
        }
        _ => vec![ActiveProbe {
            id: format!("{}-length-sweep", probe_slug(algorithm)),
            algorithm: Some(algorithm),
            kind: ActiveProbeKind::BlockSizeSweep,
            payload: (0u8..32).collect(),
            expected_observation: "Stable response classes across deterministic length sweep refine the algorithm candidate".into(),
        }],
    }
}

const fn probe_slug(algorithm: CryptoAlgorithm) -> &'static str {
    match algorithm {
        CryptoAlgorithm::Md5 => "md5",
        CryptoAlgorithm::Sha1 => "sha1",
        CryptoAlgorithm::Sha256 => "sha256",
        CryptoAlgorithm::Sha512 => "sha512",
        CryptoAlgorithm::Sha3_256 => "sha3-256",
        CryptoAlgorithm::Blake2b => "blake2b",
        CryptoAlgorithm::Aes128 => "aes-128",
        CryptoAlgorithm::Aes256 => "aes-256",
        CryptoAlgorithm::Des => "des",
        CryptoAlgorithm::TripleDes => "3des",
        CryptoAlgorithm::Rc4 => "rc4",
        CryptoAlgorithm::ChaCha20 => "chacha20",
        CryptoAlgorithm::Salsa20 => "salsa20",
        CryptoAlgorithm::Rsa => "rsa",
        CryptoAlgorithm::Ecdsa => "ecdsa",
        CryptoAlgorithm::Ed25519 => "ed25519",
        CryptoAlgorithm::X25519 => "x25519",
        CryptoAlgorithm::Crc32 => "crc32",
        CryptoAlgorithm::Adler32 => "adler32",
        CryptoAlgorithm::Sm3 => "sm3",
        CryptoAlgorithm::Sm4 => "sm4",
        CryptoAlgorithm::Whirlpool => "whirlpool",
        CryptoAlgorithm::Tiger => "tiger",
        CryptoAlgorithm::Ripemd160 => "ripemd160",
    }
}

fn padding_probe_payload(block_size: usize) -> Vec<u8> {
    let total = block_size.saturating_mul(2);
    let mut payload: Vec<u8> = (0..total).map(|i| u8::try_from(i).unwrap_or(255)).collect();
    if let Some(last) = payload.last_mut() {
        *last ^= 0x01;
    }
    payload
}

fn stream_probe_payload() -> Vec<u8> {
    let mut payload = vec![0u8; 32];
    payload.extend(vec![0u8; 31]);
    payload.push(1);
    payload
}

// ── CryptoScanner (high-level) ────────────────────────────────────────────────

/// High-level scanner: runs `BinaryScanner` + key candidate detection + report.
pub struct CryptoScanner {
    binary_scanner: BinaryScanner,
}

impl Default for CryptoScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl CryptoScanner {
    #[must_use]
    pub fn new() -> Self {
        Self {
            binary_scanner: BinaryScanner::new(),
        }
    }

    /// Full analysis pipeline: constant scan + key candidates + report generation.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoIdError::TooShort`] if `data` is fewer than 4 bytes.
    pub fn full_scan(&self, data: &[u8]) -> Result<CryptoReport, CryptoIdError> {
        if data.len() < 4 {
            return Err(CryptoIdError::TooShort);
        }

        let algorithms_found = self.binary_scanner.scan(data);
        let possible_keys = Self::find_key_candidates(data);
        let recommendations = Self::build_recommendations(&algorithms_found, &possible_keys);

        Ok(CryptoReport {
            algorithms_found,
            possible_keys,
            recommendations,
        })
    }

    /// Run the scanner and return deterministic ranked assessments plus active probes.
    ///
    /// # Errors
    ///
    /// Returns an error if [`Self::full_scan`] fails.
    pub fn identify_active(
        &self,
        data: &[u8],
        config: IdentificationConfig,
    ) -> Result<ActiveIdentificationPlan, CryptoIdError> {
        let report = self.full_scan(data)?;
        Ok(report.active_identification_plan(config))
    }

    fn find_key_candidates(data: &[u8]) -> Vec<KeyCandidate> {
        let mut candidates = Vec::new();
        // Look for high-entropy 16/24/32-byte windows (potential keys).
        for key_len in [16usize, 24, 32] {
            if data.len() < key_len {
                continue;
            }
            for offset in (0..data.len() - key_len).step_by(4) {
                let window = &data[offset..offset + key_len];
                let entropy = Self::byte_entropy(window);
                if entropy > 0.9 {
                    candidates.push(KeyCandidate {
                        offset,
                        length: key_len,
                        entropy,
                        description: format!("{key_len}-byte high-entropy region"),
                    });
                    // Skip forward to avoid overlapping candidates.
                    break;
                }
            }
        }
        candidates
    }

    /// Shannon entropy normalised to [0.0, 1.0].
    fn byte_entropy(data: &[u8]) -> f64 {
        if data.is_empty() {
            return 0.0;
        }
        let mut freq = [0u32; 256];
        for &b in data {
            freq[b as usize] += 1;
        }
        let n = f64::from(u32::try_from(data.len()).unwrap_or(u32::MAX));
        let entropy = freq
            .iter()
            .filter(|&&c| c > 0)
            .map(|&c| {
                let p = f64::from(c) / n;
                -p * p.log2()
            })
            .sum::<f64>();
        entropy / 8.0
    }

    fn build_recommendations(hits: &[CryptoHit], keys: &[KeyCandidate]) -> Vec<String> {
        let mut recs = Vec::with_capacity(8);
        let algos: std::collections::HashSet<_> = hits.iter().map(|h| h.algorithm).collect();

        if algos.contains(&CryptoAlgorithm::Md5) {
            recs.push("MD5 detected — consider collision resistance implications".into());
        }
        if algos.contains(&CryptoAlgorithm::Sha1) {
            recs.push("SHA-1 detected — deprecated for security purposes".into());
        }
        if algos.contains(&CryptoAlgorithm::Rc4) {
            recs.push("RC4 detected — insecure stream cipher, likely a vulnerability".into());
        }
        if algos.contains(&CryptoAlgorithm::Des) {
            recs.push("DES detected — broken, effective key size only 56 bits".into());
        }
        if algos.contains(&CryptoAlgorithm::Aes128) || algos.contains(&CryptoAlgorithm::Aes256) {
            recs.push("AES detected — verify key management and mode of operation".into());
        }
        if !keys.is_empty() {
            recs.push(format!(
                "Found {} potential key region(s) — inspect manually",
                keys.len()
            ));
        }
        if hits.is_empty() {
            recs.push("No known crypto constants found — algorithm may be obfuscated".into());
        }
        recs
    }
}

// ── AlgorithmId ───────────────────────────────────────────────────────────────

/// Fine-grained algorithm identifier, richer than `CryptoAlgorithm`.
/// Covers authenticated modes, custom algorithms, and variant key sizes.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AlgorithmId {
    Aes128,
    Aes192,
    Aes256,
    AesGcm,
    ChaCha20,
    ChaCha20Poly1305,
    Sha1,
    Sha256,
    Sha512,
    Blake2b,
    Md5,
    Crc32,
    Rc4,
    Des,
    TripleDes,
    Rsa,
    Ed25519,
    Custom(String),
}

impl std::fmt::Display for AlgorithmId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Aes128 => write!(f, "AES-128"),
            Self::Aes192 => write!(f, "AES-192"),
            Self::Aes256 => write!(f, "AES-256"),
            Self::AesGcm => write!(f, "AES-GCM"),
            Self::ChaCha20 => write!(f, "ChaCha20"),
            Self::ChaCha20Poly1305 => write!(f, "ChaCha20-Poly1305"),
            Self::Sha1 => write!(f, "SHA-1"),
            Self::Sha256 => write!(f, "SHA-256"),
            Self::Sha512 => write!(f, "SHA-512"),
            Self::Blake2b => write!(f, "BLAKE2b"),
            Self::Md5 => write!(f, "MD5"),
            Self::Crc32 => write!(f, "CRC32"),
            Self::Rc4 => write!(f, "RC4"),
            Self::Des => write!(f, "DES"),
            Self::TripleDes => write!(f, "3DES"),
            Self::Rsa => write!(f, "RSA"),
            Self::Ed25519 => write!(f, "Ed25519"),
            Self::Custom(s) => write!(f, "Custom({s})"),
        }
    }
}

// ── TestVector ────────────────────────────────────────────────────────────────

/// A known-answer test vector for an algorithm.
#[derive(Debug, Clone)]
pub struct TestVector {
    pub algorithm: AlgorithmId,
    pub description: &'static str,
    /// Key bytes, if applicable. `None` for hash algorithms.
    pub key: Option<&'static [u8]>,
    /// Nonce / IV bytes, if applicable.
    pub nonce: Option<&'static [u8]>,
    /// Plaintext / input bytes.
    pub plaintext: &'static [u8],
    /// Expected ciphertext / digest bytes.
    pub ciphertext: &'static [u8],
}

/// At least 5 built-in test vectors with real, verifiable values.
pub static BUILTIN_TEST_VECTORS: &[TestVector] = &[
    // ── AES-128-ECB NIST FIPS 197 Appendix B ──────────────────────────────────
    TestVector {
        algorithm: AlgorithmId::Aes128,
        description: "AES-128-ECB NIST FIPS-197 Appendix B test vector",
        key: Some(&[
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
            0x4f, 0x3c,
        ]),
        nonce: None,
        plaintext: &[
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93,
            0x17, 0x2a,
        ],
        ciphertext: &[
            0x3a, 0xd7, 0x7b, 0xb4, 0x0d, 0x7a, 0x36, 0x60, 0xa8, 0x9e, 0xca, 0xf3, 0x24, 0x66,
            0xef, 0x97,
        ],
    },
    // ── SHA-256 of empty string ────────────────────────────────────────────────
    TestVector {
        algorithm: AlgorithmId::Sha256,
        description: "SHA-256 of empty input (RFC 6234 example)",
        key: None,
        nonce: None,
        plaintext: &[],
        ciphertext: &[
            0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
            0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
            0x78, 0x52, 0xb8, 0x55,
        ],
    },
    // ── MD5 of empty string ────────────────────────────────────────────────────
    TestVector {
        algorithm: AlgorithmId::Md5,
        description: "MD5 of empty input (RFC 1321 test vector)",
        key: None,
        nonce: None,
        plaintext: &[],
        ciphertext: &[
            0xd4, 0x1d, 0x8c, 0xd9, 0x8f, 0x00, 0xb2, 0x04, 0xe9, 0x80, 0x09, 0x98, 0xec, 0xf8,
            0x42, 0x7e,
        ],
    },
    // ── CRC32 of b"hello world" ────────────────────────────────────────────────
    // Verified: CRC32/ISO-HDLC of b"hello world" = 0x0D4A_1185 (zlib / Python).
    // Little-endian bytes: [0x85, 0x11, 0x4a, 0x0d].
    TestVector {
        algorithm: AlgorithmId::Crc32,
        description: "CRC32/ISO-HDLC of b\"hello world\" = 0x0D4A_1185",
        key: None,
        nonce: None,
        plaintext: b"hello world",
        // stored little-endian so byte-comparison is well-defined
        ciphertext: &[0x85, 0x11, 0x4a, 0x0d],
    },
    // ── ChaCha20 RFC 8439 §2.4.2 test vector ──────────────────────────────────
    // Key: 32 bytes of 0x00..0x1f, nonce: 12 bytes with counter=1.
    // First 64 bytes of keystream XORed against a known plaintext.
    TestVector {
        algorithm: AlgorithmId::ChaCha20,
        description: "ChaCha20 RFC 8439 §2.4.2 — first block of keystream (counter=1)",
        key: Some(&[
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ]),
        nonce: Some(&[
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00,
        ]),
        // "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."
        // First 64 bytes of that string.
        plaintext: &[
            0x4c, 0x61, 0x64, 0x69, 0x65, 0x73, 0x20, 0x61, 0x6e, 0x64, 0x20, 0x47, 0x65, 0x6e,
            0x74, 0x6c, 0x65, 0x6d, 0x65, 0x6e, 0x20, 0x6f, 0x66, 0x20, 0x74, 0x68, 0x65, 0x20,
            0x63, 0x6c, 0x61, 0x73, 0x73, 0x20, 0x6f, 0x66, 0x20, 0x27, 0x39, 0x39, 0x3a, 0x20,
            0x49, 0x66, 0x20, 0x49, 0x20, 0x63, 0x6f, 0x75, 0x6c, 0x64, 0x20, 0x6f, 0x66, 0x66,
            0x65, 0x72, 0x20, 0x79, 0x6f, 0x75, 0x20, 0x6f,
        ],
        ciphertext: &[
            0x6e, 0x2e, 0x35, 0x9a, 0x25, 0x68, 0xf9, 0x80, 0x41, 0xba, 0x07, 0x28, 0xdd, 0x0d,
            0x69, 0x81, 0xe9, 0x7e, 0x7a, 0xec, 0x1d, 0x43, 0x60, 0xc2, 0x0a, 0x27, 0xaf, 0xcc,
            0xfd, 0x9f, 0xae, 0x0b, 0xf9, 0x1b, 0x65, 0xc5, 0x52, 0x47, 0x33, 0xab, 0x8f, 0x59,
            0x3d, 0xab, 0xcd, 0x62, 0xb3, 0x57, 0x16, 0x39, 0xd6, 0x24, 0xe6, 0x51, 0x52, 0xab,
            0x8f, 0x53, 0x0c, 0x35, 0x9f, 0x08, 0x61, 0xd8,
        ],
    },
    // ── SHA-256 of b"abc" ─────────────────────────────────────────────────────
    TestVector {
        algorithm: AlgorithmId::Sha256,
        description: "SHA-256 of b\"abc\" (FIPS 180-4 example)",
        key: None,
        nonce: None,
        plaintext: b"abc",
        ciphertext: &[
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
            0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
            0xf2, 0x00, 0x15, 0xad,
        ],
    },
];

// ── CryptoConstantFound ────────────────────────────────────────────────────────

/// A crypto constant detected at a specific byte offset in binary data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoConstantFound {
    /// Byte offset within the scanned buffer.
    pub offset: usize,
    /// The algorithm this constant belongs to.
    pub algorithm: AlgorithmId,
    /// Human-readable name of the constant (e.g. "AES-SBOX[0..4]").
    pub constant_name: String,
    /// Confidence in [0.0, 1.0].
    pub confidence: f32,
}

// ── CryptoFinding ─────────────────────────────────────────────────────────────

/// A single finding produced by `identify_in_binary`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoFinding {
    /// Byte offset within the scanned buffer.
    pub offset: usize,
    /// The algorithm identified.
    pub algorithm: AlgorithmId,
    /// Description of what triggered the finding.
    pub evidence: String,
    /// Confidence in [0.0, 1.0].
    pub confidence: f32,
}

// ── ConstantScanner ───────────────────────────────────────────────────────────

/// Scans a byte slice for known cryptographic constants.
/// Returns one `CryptoConstantFound` per distinct occurrence found.
///
/// # ⚠ There are TWO `ConstantScanner` types in this crate
///
/// This one is the **hand-written** scanner: a unit struct whose `scan_bytes`
/// calls a fixed list of `scan_*_constants` helpers. The other is
/// [`crate::constant_scanner::ConstantScanner`], a **table-driven** scanner
/// carrying a `Vec<CryptoConstant>`, section-aware virtual addresses and a
/// confidence threshold. **The MCP tools and the binary survey use the
/// table-driven one**, not this one.
///
/// The split has already cost a real defect: `test_constant_scanner_no_findings_on_zeros`
/// below exercises THIS scanner and passes, while the table-driven scanner was
/// simultaneously reporting **8176 "RIPEMD-160" hits** on 8 KiB of zeroes,
/// because its table contained the 4-byte pattern `00 00 00 00`. A test named
/// after a property tested the wrong implementation of it. When adding a
/// constant or a guard, decide which scanner you mean — and test that one.
pub struct ConstantScanner;

impl ConstantScanner {
    /// Scan `data` for known crypto constants and return all matches.
    #[must_use]
    pub fn scan_bytes(data: &[u8]) -> Vec<CryptoConstantFound> {
        let mut findings: Vec<CryptoConstantFound> = Vec::new();
        Self::scan_aes_constants(data, &mut findings);
        Self::scan_hash_crc_chacha_constants(data, &mut findings);
        findings.sort_by(|a, b| {
            a.offset.cmp(&b.offset).then_with(|| {
                b.confidence
                    .partial_cmp(&a.confidence)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
        });
        findings
    }

    fn scan_aes_constants(data: &[u8], findings: &mut Vec<CryptoConstantFound>) {
        // ── AES S-box prefix ──────────────────────────────────────────────────
        let aes_sbox_prefix: &[u8] = &[0x63, 0x7c, 0x77, 0x7b];
        for offset in find_all(data, aes_sbox_prefix) {
            let confidence =
                if offset + 256 <= data.len() && &data[offset..offset + 256] == AES_SBOX.as_ref() {
                    0.97
                } else {
                    0.72
                };
            findings.push(CryptoConstantFound {
                offset,
                algorithm: AlgorithmId::Aes128,
                constant_name: "AES-SBOX[0..4]".into(),
                confidence,
            });
        }
        // ── AES Rcon prefix [0x8d, 0x01, 0x02, 0x04, …] ─────────────────────
        let rcon_prefix: &[u8] = &[0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40];
        for offset in find_all(data, rcon_prefix) {
            findings.push(CryptoConstantFound {
                offset,
                algorithm: AlgorithmId::Aes128,
                constant_name: "AES-RCON-PREFIX".into(),
                confidence: 0.88,
            });
        }
        // ── AES inverse S-box prefix ──────────────────────────────────────────
        let aes_inv_prefix: &[u8] = &[0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36];
        for offset in find_all(data, aes_inv_prefix) {
            let confidence = if offset + 256 <= data.len()
                && &data[offset..offset + 256] == AES_INV_SBOX.as_ref()
            {
                0.97
            } else {
                0.70
            };
            findings.push(CryptoConstantFound {
                offset,
                algorithm: AlgorithmId::Aes128,
                constant_name: "AES-INV-SBOX-PREFIX".into(),
                confidence,
            });
        }
    }

    fn scan_hash_crc_chacha_constants(data: &[u8], findings: &mut Vec<CryptoConstantFound>) {
        // ── SHA-256 H0 initializer ────────────────────────────────────────────
        for offset in find_all(data, &0x6a09_e667u32.to_be_bytes()) {
            findings.push(CryptoConstantFound { offset, algorithm: AlgorithmId::Sha256, constant_name: "SHA256-H0[0]-BE".into(), confidence: 0.80 });
        }
        for offset in find_all(data, &0x6a09_e667u32.to_le_bytes()) {
            findings.push(CryptoConstantFound { offset, algorithm: AlgorithmId::Sha256, constant_name: "SHA256-H0[0]-LE".into(), confidence: 0.75 });
        }
        // ── SHA-256 K[0] ─────────────────────────────────────────────────────
        for offset in find_all(data, &0x428a_2f98u32.to_be_bytes()) {
            findings.push(CryptoConstantFound { offset, algorithm: AlgorithmId::Sha256, constant_name: "SHA256-K[0]-BE".into(), confidence: 0.78 });
        }
        // ── SHA-512 H0[0] ────────────────────────────────────────────────────
        for offset in find_all(data, &0x6a09_e667_f3bc_c908u64.to_be_bytes()) {
            findings.push(CryptoConstantFound { offset, algorithm: AlgorithmId::Sha512, constant_name: "SHA512-H0[0]-BE".into(), confidence: 0.90 });
        }
        // ── MD5 K[0] ─────────────────────────────────────────────────────────
        for offset in find_all(data, &0xd76a_a478u32.to_le_bytes()) {
            findings.push(CryptoConstantFound { offset, algorithm: AlgorithmId::Md5, constant_name: "MD5-K[0]-LE".into(), confidence: 0.82 });
        }
        for offset in find_all(data, &0xd76a_a478u32.to_be_bytes()) {
            findings.push(CryptoConstantFound { offset, algorithm: AlgorithmId::Md5, constant_name: "MD5-K[0]-BE".into(), confidence: 0.78 });
        }
        // ── MD5 initial H ─────────────────────────────────────────────────────
        for offset in find_all(data, &0x6745_2301u32.to_le_bytes()) {
            findings.push(CryptoConstantFound { offset, algorithm: AlgorithmId::Md5, constant_name: "MD5-H0[0]-LE".into(), confidence: 0.65 });
        }
        // ── CRC32 reversed polynomial ─────────────────────────────────────────
        for offset in find_all(data, &0xedb8_8320u32.to_le_bytes()) {
            findings.push(CryptoConstantFound { offset, algorithm: AlgorithmId::Crc32, constant_name: "CRC32-POLY-LE".into(), confidence: 0.90 });
        }
        for offset in find_all(data, &0xedb8_8320u32.to_be_bytes()) {
            findings.push(CryptoConstantFound { offset, algorithm: AlgorithmId::Crc32, constant_name: "CRC32-POLY-BE".into(), confidence: 0.85 });
        }
        // ── ChaCha20 "expand 32-byte k" sigma constant ────────────────────────
        for offset in find_all(data, b"expand 32-byte k") {
            findings.push(CryptoConstantFound { offset, algorithm: AlgorithmId::ChaCha20, constant_name: "CHACHA20-SIGMA".into(), confidence: 0.99 });
        }
    }
}

/// Return all byte offsets at which `needle` occurs within `haystack`.
fn find_all(haystack: &[u8], needle: &[u8]) -> Vec<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return Vec::new();
    }
    let limit = haystack.len() - needle.len();
    (0..=limit)
        .filter(|&i| haystack[i..i + needle.len()] == *needle)
        .collect()
}

// ── Shannon entropy ───────────────────────────────────────────────────────────

/// Compute the Shannon entropy of `data` in bits per byte (range: [0.0, 8.0]).
///
/// Returns 0.0 for empty input. Useful for distinguishing encrypted / compressed
/// regions (entropy near 8.0) from code / structured data (entropy typically < 6.0).
#[must_use]
pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut freq = [0u64; 256];
    for &b in data {
        freq[b as usize] += 1;
    }
    let n = f64::from(u32::try_from(data.len()).unwrap_or(u32::MAX));
    freq.iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = f64::from(u32::try_from(c).unwrap_or(u32::MAX)) / n;
            -p * p.log2()
        })
        .sum()
}

// ── AvalancheAnalyzer ─────────────────────────────────────────────────────────

/// Measures the avalanche effect of a byte-oriented function.
///
/// An ideal cipher or hash function exhibits a perfect avalanche: flipping any
/// single input bit flips each output bit with probability 0.5, yielding an
/// average avalanche score of 0.5.
pub struct AvalancheAnalyzer;

impl AvalancheAnalyzer {
    /// Run `f` over all single-bit perturbations of a zero input of `input_size`
    /// bytes and return the average fraction of output bits that changed.
    ///
    /// # Arguments
    /// * `f` - The function under test: takes a byte slice, returns a byte vec.
    /// * `input_size` - Number of input bytes (must be > 0).
    ///
    /// # Returns
    /// Average avalanche score in [0.0, 1.0]. A value near 0.5 indicates ideal
    /// diffusion; values close to 0.0 or 1.0 indicate weak diffusion.
    ///
    /// Returns 0.0 if `input_size` is zero or the function returns empty output.
    pub fn analyze(f: impl Fn(&[u8]) -> Vec<u8>, input_size: usize) -> f64 {
        if input_size == 0 {
            return 0.0;
        }

        // Baseline output: all-zero input.
        let baseline_input = vec![0u8; input_size];
        let baseline_output = f(&baseline_input);

        if baseline_output.is_empty() {
            return 0.0;
        }

        let output_bits = baseline_output.len().saturating_mul(8);
        if output_bits == 0 {
            return 0.0;
        }
        let total_bits_changed: u64 = (0..input_size.saturating_mul(8))
            .map(|bit_pos| {
                // Flip bit `bit_pos` in the input.
                let mut perturbed = baseline_input.clone();
                perturbed[bit_pos / 8] ^= 1 << (bit_pos % 8);

                let perturbed_output = f(&perturbed);

                // Count differing bits between baseline and perturbed output.
                baseline_output
                    .iter()
                    .zip(perturbed_output.iter())
                    .map(|(a, b)| u64::from((a ^ b).count_ones()))
                    .sum::<u64>()
            })
            .sum();

        let num_trials = f64::from(u32::try_from(input_size.saturating_mul(8)).unwrap_or(u32::MAX));
        if num_trials == 0.0 {
            return 0.0;
        }
        let avg_bits_changed = f64::from(u32::try_from(total_bits_changed).unwrap_or(u32::MAX)) / num_trials;
        avg_bits_changed / f64::from(u32::try_from(output_bits).unwrap_or(u32::MAX))
    }
}

// ── identify_in_binary ────────────────────────────────────────────────────────

/// High-level binary identification: runs `ConstantScanner`, converts findings
/// to `CryptoFinding` records, deduplicates by algorithm, and sorts by
/// descending confidence.
///
/// This is the primary entry point for callers that want a ranked list of
/// algorithms detected in an arbitrary byte buffer.
#[must_use]
pub fn identify_in_binary(data: &[u8]) -> Vec<CryptoFinding> {
    let raw = ConstantScanner::scan_bytes(data);

    let mut findings: Vec<CryptoFinding> = raw
        .into_iter()
        .map(|found| CryptoFinding {
            offset: found.offset,
            algorithm: found.algorithm,
            evidence: found.constant_name,
            confidence: found.confidence,
        })
        .collect();

    // ── Unification: merge results from the rich populated ConstantScanner
    //    (LE + BE + BigNum constant table) so crypto.identify reports the
    //    same hit population as analysis_crypto_scan_path. Map the string
    //    algorithm names to AlgorithmId variants where possible; fall back
    //    to AlgorithmId::Custom for table entries that have no enum slot
    //    (Curve25519, NIST primes, SM4, …).
    let rich = constant_scanner::ConstantScanner::new();
    let extra = rich.scan(data);
    for m in extra {
        let primary = m.algorithms.first().cloned().unwrap_or_default();
        let algorithm = match primary.to_ascii_uppercase().as_str() {
            "AES" | "AES-128" | "AES128" => AlgorithmId::Aes128,
            "AES-192" | "AES192" => AlgorithmId::Aes192,
            "AES-256" | "AES256" => AlgorithmId::Aes256,
            "AES-GCM" | "GCM" => AlgorithmId::AesGcm,
            "CHACHA20" | "CHACHA" => AlgorithmId::ChaCha20,
            "CHACHA20-POLY1305" | "CHACHA20POLY1305" => AlgorithmId::ChaCha20Poly1305,
            "SHA-1" | "SHA1" => AlgorithmId::Sha1,
            "SHA-256" | "SHA256" => AlgorithmId::Sha256,
            "SHA-512" | "SHA512" => AlgorithmId::Sha512,
            "BLAKE2B" | "BLAKE2" => AlgorithmId::Blake2b,
            "MD5" => AlgorithmId::Md5,
            "CRC32" => AlgorithmId::Crc32,
            "RC4" => AlgorithmId::Rc4,
            "DES" => AlgorithmId::Des,
            "3DES" | "TRIPLEDES" | "TRIPLE-DES" => AlgorithmId::TripleDes,
            "RSA" => AlgorithmId::Rsa,
            "ED25519" => AlgorithmId::Ed25519,
            _ => AlgorithmId::Custom(primary),
        };
        let endian = match m.endian {
            constant_scanner::MatchEndian::LittleEndian => "LE",
            constant_scanner::MatchEndian::BigEndian => "BE",
            constant_scanner::MatchEndian::Neutral => "N",
        };
        findings.push(CryptoFinding {
            offset: m.file_offset,
            algorithm,
            evidence: format!("{}[{}]", m.constant_name, endian),
            confidence: f32::from(m.confidence) / 100.0,
        });
    }

    // Deduplicate by (offset, evidence) preserving the higher confidence.
    findings.sort_by(|a, b| {
        a.offset
            .cmp(&b.offset)
            .then_with(|| a.evidence.cmp(&b.evidence))
            .then_with(|| {
                b.confidence
                    .partial_cmp(&a.confidence)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
    });
    findings.dedup_by(|a, b| a.offset == b.offset && a.evidence == b.evidence);

    // Sort by descending confidence, then offset for stability.
    findings.sort_by(|a, b| {
        b.confidence
            .partial_cmp(&a.confidence)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.offset.cmp(&b.offset))
    });

    findings
}

// ── TestVector helpers ────────────────────────────────────────────────────────

impl TestVector {
    /// Return a brief summary string for display / logging.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "[{}] {} — {} byte(s) in, {} byte(s) out",
            self.algorithm,
            self.description,
            self.plaintext.len(),
            self.ciphertext.len()
        )
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_binary_with(constant: &[u8], prefix_len: usize, total_len: usize) -> Vec<u8> {
        let mut data = vec![0u8; total_len];
        let end = (prefix_len + constant.len()).min(total_len);
        data[prefix_len..end].copy_from_slice(&constant[..end - prefix_len]);
        data
    }

    #[test]
    fn test_aes_sbox_constant_length() {
        assert_eq!(AES_SBOX.len(), 256);
    }

    #[test]
    fn test_sm4_sbox_length() {
        assert_eq!(SM4_SBOX.len(), 256);
    }

    #[test]
    fn test_crc32_table_first_entry() {
        let table = build_crc32_table();
        assert_eq!(table[0], 0);
        // Standard CRC32 table[1] = 0x7707_3096 (from IEEE polynomial).
        assert_eq!(table[1], 0x7707_3096);
    }

    #[test]
    fn test_signature_database_loads_builtins() {
        let db = SignatureDatabase::new();
        let constants = db.constants();
        assert!(!constants.is_empty());
        let names: Vec<&str> = constants.iter().map(|c| c.name.as_str()).collect();
        assert!(names.contains(&"AES-SBOX"));
        assert!(names.contains(&"SHA256-H0"));
        assert!(names.contains(&"MD5-H0"));
    }

    #[test]
    fn test_scan_finds_aes_sbox() {
        let scanner = BinaryScanner::new();
        let offset = 64usize;
        let data = make_binary_with(&AES_SBOX, offset, offset + 512);
        let hits = scanner.scan(&data);
        let aes_hits: Vec<_> = hits
            .iter()
            .filter(|h| h.algorithm == CryptoAlgorithm::Aes128 && h.constant == "AES-SBOX")
            .collect();
        assert!(!aes_hits.is_empty());
        assert_eq!(aes_hits[0].offset, offset);
    }

    #[test]
    fn test_scan_finds_md5_constants() {
        let scanner = BinaryScanner::new();
        let md5_bytes: Vec<u8> = MD5_H.iter().flat_map(|&h| h.to_le_bytes()).collect();
        let offset = 32usize;
        let data = make_binary_with(&md5_bytes, offset, 512);
        let hits = scanner.scan(&data);
        
        assert!(hits
            .iter().any(|h| h.algorithm == CryptoAlgorithm::Md5));
    }

    #[test]
    fn test_scan_finds_sha256_k() {
        let scanner = BinaryScanner::new();
        let k_bytes: Vec<u8> = SHA256_K.iter().flat_map(|&k| k.to_be_bytes()).collect();
        let offset = 128usize;
        let data = make_binary_with(&k_bytes, offset, 512);
        let hits = scanner.scan(&data);
        
        assert!(hits
            .iter().any(|h| h.algorithm == CryptoAlgorithm::Sha256));
    }

    #[test]
    fn test_scan_finds_sm4_sbox() {
        let scanner = BinaryScanner::new();
        let offset = 16usize;
        let data = make_binary_with(&SM4_SBOX, offset, offset + 512);
        let hits = scanner.scan(&data);
        
        assert!(hits
            .iter().any(|h| h.algorithm == CryptoAlgorithm::Sm4));
    }

    #[test]
    fn test_scan_no_false_positives_on_zeros() {
        let scanner = BinaryScanner::new();
        let data = vec![0u8; 2048];
        let hits = scanner.scan(&data);
        assert!(hits.is_empty());
    }

    #[test]
    fn test_full_scan_report() {
        let scanner = CryptoScanner::new();
        let offset = 0usize;
        let mut data = vec![0u8; 1024];
        data[offset..offset + 256].copy_from_slice(&AES_SBOX);
        let report = scanner.full_scan(&data).unwrap();
        assert!(!report.algorithms_found.is_empty());
        assert!(!report.recommendations.is_empty());
    }

    #[test]
    fn test_full_scan_too_short() {
        let scanner = CryptoScanner::new();
        assert!(matches!(
            scanner.full_scan(&[0u8; 2]),
            Err(CryptoIdError::TooShort)
        ));
    }

    #[test]
    fn test_algorithm_display() {
        assert_eq!(CryptoAlgorithm::Md5.to_string(), "MD5");
        assert_eq!(CryptoAlgorithm::ChaCha20.to_string(), "ChaCha20");
        assert_eq!(CryptoAlgorithm::Ed25519.to_string(), "Ed25519");
    }

    #[test]
    fn test_function_scanner_chacha_pattern() {
        // Synthetic code with many XOR/ROL bytes.
        let mut code = vec![0u8; 512];
        for i in (0..400usize).step_by(4) {
            code[i] = 0x31; // XOR
            code[i + 1] = 0xC0;
            code[i + 2] = 0xC1; // ROL
            code[i + 3] = 0xC0;
        }
        let hits = FunctionScanner::analyze(&code);
        let chacha = hits
            .iter()
            .any(|h| h.algorithm == CryptoAlgorithm::ChaCha20);
        assert!(chacha);
    }

    #[test]
    fn test_function_scanner_rc4_pattern() {
        let mut code = vec![0u8; 256];
        for i in (0..200usize).step_by(4) {
            code[i] = 0x87; // XCHG
            code[i + 1] = 0xC0;
        }
        let hits = FunctionScanner::analyze(&code);
        let rc4 = hits.iter().any(|h| h.algorithm == CryptoAlgorithm::Rc4);
        assert!(rc4);
    }

    #[test]
    fn test_key_candidate_high_entropy() {
        let scanner = CryptoScanner::new();
        // Pseudo-random 16 bytes (high entropy).
        let key_bytes = [
            0x9f, 0x3b, 0x7c, 0x4a, 0x1e, 0xd8, 0x52, 0xa6, 0x3f, 0x70, 0xbc, 0x19, 0xee, 0x45,
            0x28, 0x6d,
        ];
        let mut data = vec![0u8; 512];
        data[0..16].copy_from_slice(&key_bytes);
        let report = scanner.full_scan(&data).unwrap();
        // May or may not be high enough entropy — just ensure it doesn't panic.
        let _ = report.possible_keys;
    }

    #[test]
    fn test_database_custom_constant() {
        let db = SignatureDatabase::new();
        db.add(CryptoConstant {
            name: "MY-CONST".into(),
            algorithm: CryptoAlgorithm::Tiger,
            value: vec![0xDE, 0xAD, 0xBE, 0xEF],
            size: 4,
        });
        let constants = db.constants();
        assert!(constants.iter().any(|c| c.name == "MY-CONST"));
    }

    #[test]
    fn test_scan_finds_crc32_table() {
        let scanner = BinaryScanner::new();
        let table = build_crc32_table();
        let table_bytes: Vec<u8> = table.iter().flat_map(|&w| w.to_le_bytes()).collect();
        let offset = 64usize;
        let mut data = vec![0u8; offset + 1024 + 64];
        data[offset..offset + 1024].copy_from_slice(&table_bytes);
        let hits = scanner.scan(&data);
        let crc_hits: Vec<_> = hits
            .iter()
            .filter(|h| h.algorithm == CryptoAlgorithm::Crc32)
            .collect();
        assert!(!crc_hits.is_empty());
        assert_eq!(crc_hits[0].offset, offset);
    }

    #[test]
    fn test_crypto_hit_serialization() {
        let hit = CryptoHit {
            offset: 0x1234,
            algorithm: CryptoAlgorithm::Aes256,
            constant: "AES-SBOX".into(),
            confidence: 0.95,
        };
        let json = serde_json::to_string(&hit).unwrap();
        let parsed: CryptoHit = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.offset, hit.offset);
    }

    #[test]
    fn test_scan_multiple_constants_in_one_binary() {
        let scanner = BinaryScanner::new();
        let md5_bytes: Vec<u8> = MD5_H.iter().flat_map(|&h| h.to_le_bytes()).collect();
        let mut data = vec![0u8; 1024];
        data[0..256].copy_from_slice(&AES_SBOX);
        data[300..300 + md5_bytes.len()].copy_from_slice(&md5_bytes);
        let hits = scanner.scan(&data);
        let algos: std::collections::HashSet<_> = hits.iter().map(|h| h.algorithm).collect();
        assert!(algos.contains(&CryptoAlgorithm::Aes128));
        assert!(algos.contains(&CryptoAlgorithm::Md5));
    }

    #[test]
    fn test_sha1_constants_present() {
        let db = SignatureDatabase::new();
        let constants = db.constants();
        assert!(
            constants
                .iter()
                .any(|c| c.algorithm == CryptoAlgorithm::Sha1)
        );
    }

    #[test]
    fn test_sha512_constants_present() {
        let db = SignatureDatabase::new();
        let constants = db.constants();
        assert!(
            constants
                .iter()
                .any(|c| c.algorithm == CryptoAlgorithm::Sha512)
        );
    }

    #[test]
    fn test_report_builds_ranked_assessments() {
        let report = CryptoReport {
            algorithms_found: vec![
                CryptoHit {
                    offset: 16,
                    algorithm: CryptoAlgorithm::Md5,
                    constant: "MD5-H0".into(),
                    confidence: 0.70,
                },
                CryptoHit {
                    offset: 32,
                    algorithm: CryptoAlgorithm::Aes128,
                    constant: "AES-SBOX".into(),
                    confidence: 0.95,
                },
            ],
            possible_keys: vec![],
            recommendations: vec![],
        };

        let assessments = report.assessments(IdentificationConfig::default());
        assert_eq!(assessments[0].algorithm, CryptoAlgorithm::Aes128);
        assert_eq!(assessments[0].level, ConfidenceLevel::High);
        assert_eq!(assessments[1].algorithm, CryptoAlgorithm::Md5);
    }

    #[test]
    fn test_active_identification_plan_is_deterministic() {
        let scanner = CryptoScanner::new();
        let mut data = vec![0u8; 512];
        data[64..64 + AES_SBOX.len()].copy_from_slice(&AES_SBOX);

        let config = IdentificationConfig {
            min_confidence: 0.5,
            max_probes_per_algorithm: 1,
            include_key_candidates: false,
        };
        let first = scanner.identify_active(&data, config).unwrap();
        let second = scanner.identify_active(&data, config).unwrap();

        assert_eq!(first, second);
        assert_eq!(first.assessments[0].algorithm, CryptoAlgorithm::Aes128);
        assert_eq!(first.probes.len(), 1);
        assert_eq!(first.probes[0].kind, ActiveProbeKind::EcbRepetition);
    }

    // ── AlgorithmId tests ─────────────────────────────────────────────────────

    #[test]
    fn test_algorithm_id_display() {
        assert_eq!(AlgorithmId::Aes128.to_string(), "AES-128");
        assert_eq!(AlgorithmId::Aes192.to_string(), "AES-192");
        assert_eq!(AlgorithmId::Aes256.to_string(), "AES-256");
        assert_eq!(AlgorithmId::AesGcm.to_string(), "AES-GCM");
        assert_eq!(AlgorithmId::ChaCha20.to_string(), "ChaCha20");
        assert_eq!(
            AlgorithmId::ChaCha20Poly1305.to_string(),
            "ChaCha20-Poly1305"
        );
        assert_eq!(AlgorithmId::Sha1.to_string(), "SHA-1");
        assert_eq!(AlgorithmId::Sha256.to_string(), "SHA-256");
        assert_eq!(AlgorithmId::Sha512.to_string(), "SHA-512");
        assert_eq!(AlgorithmId::Blake2b.to_string(), "BLAKE2b");
        assert_eq!(AlgorithmId::Md5.to_string(), "MD5");
        assert_eq!(AlgorithmId::Crc32.to_string(), "CRC32");
        assert_eq!(AlgorithmId::Rc4.to_string(), "RC4");
        assert_eq!(AlgorithmId::Des.to_string(), "DES");
        assert_eq!(AlgorithmId::TripleDes.to_string(), "3DES");
        assert_eq!(AlgorithmId::Rsa.to_string(), "RSA");
        assert_eq!(AlgorithmId::Ed25519.to_string(), "Ed25519");
        assert_eq!(
            AlgorithmId::Custom("XXTEA".into()).to_string(),
            "Custom(XXTEA)"
        );
    }

    #[test]
    fn test_algorithm_id_equality_and_clone() {
        let a = AlgorithmId::Custom("FOO".into());
        let b = a.clone();
        assert_eq!(a, b);
        assert_ne!(AlgorithmId::Aes128, AlgorithmId::Aes256);
    }

    // ── BUILTIN_TEST_VECTORS tests ────────────────────────────────────────────

    #[test]
    fn test_builtin_test_vectors_count() {
        assert!(
            BUILTIN_TEST_VECTORS.len() >= 5,
            "Need at least 5 test vectors"
        );
    }

    #[test]
    fn test_aes128_ecb_test_vector_fields() {
        let tv = &BUILTIN_TEST_VECTORS[0];
        assert_eq!(tv.algorithm, AlgorithmId::Aes128);
        let key = tv.key.expect("AES-128 vector must have key");
        assert_eq!(key.len(), 16);
        assert_eq!(tv.plaintext.len(), 16);
        assert_eq!(tv.ciphertext.len(), 16);
        // Spot-check key bytes.
        assert_eq!(key[0], 0x2b);
        assert_eq!(key[15], 0x3c);
        // Spot-check ciphertext.
        assert_eq!(tv.ciphertext[0], 0x3a);
        assert_eq!(tv.ciphertext[15], 0x97);
    }

    #[test]
    fn test_sha256_empty_test_vector() {
        let tv = &BUILTIN_TEST_VECTORS[1];
        assert_eq!(tv.algorithm, AlgorithmId::Sha256);
        assert!(tv.plaintext.is_empty());
        assert_eq!(tv.ciphertext.len(), 32);
        // Known first bytes of SHA-256("").
        assert_eq!(tv.ciphertext[0], 0xe3);
        assert_eq!(tv.ciphertext[1], 0xb0);
    }

    #[test]
    fn test_md5_empty_test_vector() {
        let tv = &BUILTIN_TEST_VECTORS[2];
        assert_eq!(tv.algorithm, AlgorithmId::Md5);
        assert!(tv.plaintext.is_empty());
        assert_eq!(tv.ciphertext.len(), 16);
        // Known first bytes of MD5("").
        assert_eq!(tv.ciphertext[0], 0xd4);
        assert_eq!(tv.ciphertext[1], 0x1d);
    }

    #[test]
    fn test_crc32_hello_world_test_vector() {
        let tv = &BUILTIN_TEST_VECTORS[3];
        assert_eq!(tv.algorithm, AlgorithmId::Crc32);
        assert_eq!(tv.plaintext, b"hello world");
        // Expected LE bytes for 0x0D4A_1185.
        assert_eq!(tv.ciphertext, &[0x85, 0x11, 0x4a, 0x0d]);

        // Also verify by computing CRC32 here.
        let crc = crc32_compute(tv.plaintext);
        assert_eq!(
            crc, 0x0D4A_1185,
            "CRC32(b\"hello world\") must equal 0x0D4A_1185"
        );
    }

    #[test]
    fn test_chacha20_rfc8439_test_vector() {
        let tv = &BUILTIN_TEST_VECTORS[4];
        assert_eq!(tv.algorithm, AlgorithmId::ChaCha20);
        let key = tv.key.expect("ChaCha20 vector must have key");
        assert_eq!(key.len(), 32);
        let nonce = tv.nonce.expect("ChaCha20 vector must have nonce");
        assert_eq!(nonce.len(), 12);
        assert_eq!(tv.plaintext.len(), 64);
        assert_eq!(tv.ciphertext.len(), 64);
    }

    #[test]
    fn test_test_vector_summary_not_empty() {
        for tv in BUILTIN_TEST_VECTORS {
            let s = tv.summary();
            assert!(!s.is_empty());
        }
    }

    // ── ConstantScanner tests ─────────────────────────────────────────────────

    #[test]
    fn test_constant_scanner_finds_aes_sbox_prefix() {
        let mut data = vec![0u8; 512];
        data[100..104].copy_from_slice(&[0x63, 0x7c, 0x77, 0x7b]);
        let findings = ConstantScanner::scan_bytes(&data);
        let found = findings
            .iter()
            .any(|f| f.offset == 100 && f.algorithm == AlgorithmId::Aes128);
        assert!(found, "Should detect AES S-box prefix at offset 100");
    }

    #[test]
    fn test_constant_scanner_finds_full_aes_sbox_high_confidence() {
        let mut data = vec![0u8; 600];
        data[50..50 + 256].copy_from_slice(&AES_SBOX);
        let findings = ConstantScanner::scan_bytes(&data);
        let hit = findings
            .iter()
            .find(|f| f.offset == 50 && f.algorithm == AlgorithmId::Aes128)
            .expect("Must find AES S-box");
        assert!(
            hit.confidence >= 0.95,
            "Full S-box match should have confidence >= 0.95, got {}",
            hit.confidence
        );
    }

    #[test]
    fn test_constant_scanner_finds_sha256_h0_be() {
        let be_bytes = 0x6a09_e667u32.to_be_bytes();
        let mut data = vec![0u8; 64];
        data[10..14].copy_from_slice(&be_bytes);
        let findings = ConstantScanner::scan_bytes(&data);
        let found = findings
            .iter()
            .any(|f| f.offset == 10 && f.algorithm == AlgorithmId::Sha256);
        assert!(found, "Should detect SHA-256 H0 in big-endian");
    }

    #[test]
    fn test_constant_scanner_finds_sha256_h0_le() {
        let le_bytes = 0x6a09_e667u32.to_le_bytes();
        let mut data = vec![0u8; 64];
        data[20..24].copy_from_slice(&le_bytes);
        let findings = ConstantScanner::scan_bytes(&data);
        let found = findings
            .iter()
            .any(|f| f.offset == 20 && f.algorithm == AlgorithmId::Sha256);
        assert!(found, "Should detect SHA-256 H0 in little-endian");
    }

    #[test]
    fn test_constant_scanner_finds_md5_k0() {
        let le_bytes = 0xd76a_a478u32.to_le_bytes();
        let mut data = vec![0u8; 64];
        data[4..8].copy_from_slice(&le_bytes);
        let findings = ConstantScanner::scan_bytes(&data);
        let found = findings
            .iter()
            .any(|f| f.offset == 4 && f.algorithm == AlgorithmId::Md5);
        assert!(found, "Should detect MD5 K[0]");
    }

    #[test]
    fn test_constant_scanner_finds_crc32_poly() {
        let le_bytes = 0xedb8_8320u32.to_le_bytes();
        let mut data = vec![0u8; 64];
        data[8..12].copy_from_slice(&le_bytes);
        let findings = ConstantScanner::scan_bytes(&data);
        let found = findings
            .iter()
            .any(|f| f.offset == 8 && f.algorithm == AlgorithmId::Crc32);
        assert!(found, "Should detect CRC32 polynomial");
    }

    #[test]
    fn test_constant_scanner_finds_chacha20_sigma() {
        let sigma = b"expand 32-byte k";
        let mut data = vec![0u8; 128];
        data[32..48].copy_from_slice(sigma);
        let findings = ConstantScanner::scan_bytes(&data);
        let hit = findings
            .iter()
            .find(|f| f.offset == 32 && f.algorithm == AlgorithmId::ChaCha20)
            .expect("Must detect ChaCha20 sigma");
        assert!(
            hit.confidence >= 0.99,
            "Sigma detection confidence must be >= 0.99"
        );
    }

    #[test]
    fn test_constant_scanner_no_findings_on_zeros() {
        let data = vec![0u8; 4096];
        let findings = ConstantScanner::scan_bytes(&data);
        assert!(findings.is_empty(), "No findings expected in all-zero data");
    }

    #[test]
    fn test_constant_scanner_sorted_by_offset() {
        let mut data = vec![0u8; 512];
        // Place CRC32 poly at offset 400.
        data[400..404].copy_from_slice(&0xedb8_8320u32.to_le_bytes());
        // Place SHA-256 H0 at offset 10.
        data[10..14].copy_from_slice(&0x6a09_e667u32.to_be_bytes());
        let findings = ConstantScanner::scan_bytes(&data);
        let offsets: Vec<usize> = findings.iter().map(|f| f.offset).collect();
        let mut sorted = offsets.clone();
        sorted.sort_unstable();
        assert_eq!(offsets, sorted, "Findings must be sorted by offset");
    }

    #[test]
    fn test_crypto_finding_struct_fields() {
        let f = CryptoFinding {
            offset: 0x100,
            algorithm: AlgorithmId::Sha256,
            evidence: "SHA256-H0[0]-BE".into(),
            confidence: 0.80,
        };
        assert_eq!(f.offset, 0x100);
        assert_eq!(f.algorithm, AlgorithmId::Sha256);
        assert!((f.confidence - 0.80).abs() < f32::EPSILON);
    }

    // ── shannon_entropy tests ─────────────────────────────────────────────────

    #[test]
    fn test_shannon_entropy_empty() {
        assert_eq!(shannon_entropy(&[]), 0.0);
    }

    #[test]
    fn test_shannon_entropy_single_byte_class() {
        // All bytes the same → entropy = 0.
        let data = vec![0xAAu8; 256];
        assert_eq!(shannon_entropy(&data), 0.0);
    }

    #[test]
    fn test_shannon_entropy_uniform_256() {
        // One of each byte value → maximum entropy = 8.0 bits.
        let data: Vec<u8> = (0u8..=255).collect();
        let h = shannon_entropy(&data);
        assert!(
            (h - 8.0f64).abs() < 1e-4,
            "Uniform distribution entropy must be ~8.0, got {h}"
        );
    }

    #[test]
    fn test_shannon_entropy_two_symbols() {
        // Half 0x00, half 0xFF → entropy = 1.0 bits (probability 0.5 each).
        let data: Vec<u8> = (0..256)
            .map(|i| if i < 128 { 0u8 } else { 0xFFu8 })
            .collect();
        let h = shannon_entropy(&data);
        assert!(
            (h - 1.0f64).abs() < 1e-4,
            "Two-symbol entropy must be ~1.0, got {h}"
        );
    }

    #[test]
    fn test_shannon_entropy_high_for_random_like_data() {
        // AES S-box is a permutation → uniform → entropy close to 8.0.
        let h = shannon_entropy(&AES_SBOX);
        assert!(h > 7.9, "AES S-box entropy must be > 7.9, got {h}");
    }

    #[test]
    fn test_shannon_entropy_low_for_structured_data() {
        // Runs of few distinct values → low entropy.
        let data: Vec<u8> = (0..256).map(|i| (i % 4) as u8).collect();
        let h = shannon_entropy(&data);
        // 4 equally likely values → entropy = 2.0 bits.
        assert!(
            (h - 2.0f64).abs() < 0.01,
            "4-symbol uniform entropy must be ~2.0, got {h}"
        );
    }

    // ── AvalancheAnalyzer tests ───────────────────────────────────────────────

    #[test]
    fn test_avalanche_identity_function_zero() {
        // f(x) = x — no avalanche at all: flip one bit → exactly one output bit changes.
        // For N-byte input/output, each bit-flip changes 1/N bits → score = 1/(N*8).
        let score = AvalancheAnalyzer::analyze(<[u8]>::to_vec, 4);
        // 4-byte I/O: 1 bit changed out of 32 → 1/32 = 0.03125 per trial.
        assert!(
            score < 0.1,
            "Identity function avalanche should be very low, got {score}"
        );
    }

    #[test]
    fn test_avalanche_constant_function_zero() {
        // f(x) = [0xAB; 4] — constant output, avalanche = 0.
        let score = AvalancheAnalyzer::analyze(|_| vec![0xABu8; 4], 4);
        assert_eq!(score, 0.0, "Constant function must have zero avalanche");
    }

    #[test]
    fn test_avalanche_bit_reversal_reasonable() {
        // f(x) = bit-reverse every byte — still relatively structured diffusion.
        let score =
            AvalancheAnalyzer::analyze(|data| data.iter().map(|&b| b.reverse_bits()).collect(), 8);
        // Reversing bits: flipping bit i in input flips bit (7-i) in same byte of output.
        // Each trial changes exactly 1 bit out of 64 → score = 1/64 ≈ 0.015625.
        assert!(
            score < 0.1,
            "Bit-reversal avalanche should be low (structured), got {score}"
        );
    }

    #[test]
    fn test_avalanche_empty_input_returns_zero() {
        let score = AvalancheAnalyzer::analyze(<[u8]>::to_vec, 0);
        assert_eq!(score, 0.0);
    }

    #[test]
    fn test_avalanche_empty_output_returns_zero() {
        let score = AvalancheAnalyzer::analyze(|_| vec![], 4);
        assert_eq!(score, 0.0);
    }

    // ── identify_in_binary tests ──────────────────────────────────────────────

    #[test]
    fn test_identify_in_binary_empty_data() {
        let findings = identify_in_binary(&[]);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_identify_in_binary_finds_chacha20_sigma() {
        let sigma = b"expand 32-byte k";
        let mut data = vec![0u8; 200];
        data[64..80].copy_from_slice(sigma);
        let findings = identify_in_binary(&data);
        assert!(!findings.is_empty(), "Must detect ChaCha20 sigma in binary");
        assert_eq!(findings[0].algorithm, AlgorithmId::ChaCha20);
        assert!(findings[0].confidence >= 0.99);
    }

    #[test]
    fn test_identify_in_binary_sorted_by_confidence_desc() {
        // Place both AES S-box (confidence 0.97) and SHA-256 H0 (0.80) in the binary.
        let mut data = vec![0u8; 600];
        data[300..300 + 256].copy_from_slice(&AES_SBOX);
        data[10..14].copy_from_slice(&0x6a09_e667u32.to_be_bytes());
        let findings = identify_in_binary(&data);
        assert!(!findings.is_empty());
        // First finding should have highest or equal confidence.
        for pair in findings.windows(2) {
            assert!(
                pair[0].confidence >= pair[1].confidence,
                "Findings must be sorted by descending confidence"
            );
        }
    }

    #[test]
    fn test_identify_in_binary_finds_crc32_poly() {
        let mut data = vec![0u8; 64];
        data[0..4].copy_from_slice(&0xedb8_8320u32.to_le_bytes());
        let findings = identify_in_binary(&data);
        let crc = findings.iter().any(|f| f.algorithm == AlgorithmId::Crc32);
        assert!(crc, "Must detect CRC32 polynomial");
    }

    #[test]
    fn test_identify_in_binary_finds_md5_k0() {
        let mut data = vec![0u8; 64];
        data[0..4].copy_from_slice(&0xd76a_a478u32.to_le_bytes());
        let findings = identify_in_binary(&data);
        let md5 = findings.iter().any(|f| f.algorithm == AlgorithmId::Md5);
        assert!(md5, "Must detect MD5 K[0]");
    }

    #[test]
    fn test_identify_in_binary_crypto_finding_is_serializable() {
        let f = CryptoFinding {
            offset: 42,
            algorithm: AlgorithmId::Aes128,
            evidence: "AES-SBOX[0..4]".into(),
            confidence: 0.95,
        };
        let json = serde_json::to_string(&f).unwrap();
        let back: CryptoFinding = serde_json::from_str(&json).unwrap();
        assert_eq!(back.offset, f.offset);
        assert_eq!(back.algorithm, f.algorithm);
        assert!((back.confidence - f.confidence).abs() < f32::EPSILON);
    }

    // ── find_all helper tests ─────────────────────────────────────────────────

    #[test]
    fn test_find_all_empty_needle() {
        let result = find_all(b"hello", &[]);
        assert!(result.is_empty());
    }

    #[test]
    fn test_find_all_needle_longer_than_haystack() {
        let result = find_all(b"hi", b"hello");
        assert!(result.is_empty());
    }

    #[test]
    fn test_find_all_multiple_occurrences() {
        let haystack = b"abababab";
        let needle = b"ab";
        let offsets = find_all(haystack, needle);
        assert_eq!(offsets, vec![0, 2, 4, 6]);
    }

    #[test]
    fn test_find_all_no_match() {
        let offsets = find_all(b"hello world", b"xyz");
        assert!(offsets.is_empty());
    }
}

// ── CRC32 computation (used by tests) ────────────────────────────────────────

/// Compute standard CRC32/ISO-HDLC (Ethernet / zlib polynomial `0xEDB8_8320`)
/// for the given byte slice. Used internally to verify test vectors.
#[cfg(test)]
fn crc32_compute(data: &[u8]) -> u32 {
    let table = build_crc32_table();
    let mut crc: u32 = 0xFFFF_FFFF;
    for &b in data {
        let idx = ((crc ^ u32::from(b)) & 0xFF) as usize;
        crc = (crc >> 8) ^ table[idx];
    }
    crc ^ 0xFFFF_FFFF
}

// ── ChaCha20Identifier ────────────────────────────────────────────────────────

/// Detects the `ChaCha20` stream cipher constant "expand 32-byte k" in binary data.
///
/// The constant is split into four 32-bit little-endian words:
///  - "expa" = `0x6578_7061`
///  - "nd 3" = `0x6e64_2033`
///  - "2-by" = `0x322d_6279`
///  - "te k" = `0x7465_206b`
pub struct ChaCha20Identifier;

impl ChaCha20Identifier {
    /// Search `data` for the complete `ChaCha20` sigma constant "expand 32-byte k"
    /// as a contiguous 16-byte ASCII sequence.
    ///
    /// Returns the byte offsets of every occurrence found.
    #[must_use]
    pub fn detect_chacha20_const(data: &[u8]) -> Vec<usize> {
        const SIGMA: &[u8] = b"expand 32-byte k";
        if data.len() < SIGMA.len() {
            return Vec::new();
        }
        let limit = data.len() - SIGMA.len();
        (0..=limit)
            .filter(|&i| &data[i..i + SIGMA.len()] == SIGMA)
            .collect()
    }

    /// Search `data` for any individual 32-bit word of the sigma constant.
    ///
    /// Returns a `Vec` of `(offset, word_index)` tuples where `word_index` is
    /// 0 = "expa", 1 = "nd 3", 2 = "2-by", 3 = "te k".
    ///
    /// The words are stored as literal ASCII, so we search for the raw bytes:
    ///  - "expa" = [0x65, 0x78, 0x70, 0x61]
    ///  - "nd 3" = [0x6e, 0x64, 0x20, 0x33]
    ///  - "2-by" = [0x32, 0x2d, 0x62, 0x79]
    ///  - "te k" = [0x74, 0x65, 0x20, 0x6b]
    #[must_use]
    pub fn detect_chacha20_words(data: &[u8]) -> Vec<(usize, usize)> {
        // Byte patterns for each 4-byte word as they appear in memory (ASCII).
        const WORDS: [&[u8; 4]; 4] = [b"expa", b"nd 3", b"2-by", b"te k"];
        let mut hits = Vec::new();
        if data.len() < 4 {
            return hits;
        }
        let limit = data.len() - 4;
        for (wi, &needle) in WORDS.iter().enumerate() {
            for offset in 0..=limit {
                if &data[offset..offset + 4] == needle {
                    hits.push((offset, wi));
                }
            }
        }
        hits.sort_unstable_by_key(|&(off, wi)| (off, wi));
        hits
    }
}

// ── RsaDetector ───────────────────────────────────────────────────────────────

/// A hint about a potential RSA key found in binary data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RsaKeyHint {
    /// Byte offset within the scanned buffer.
    pub offset: usize,
    /// Human-readable description of what was found ("DER-RSA", "PEM-RSA", "large-prime-candidate").
    pub kind: String,
    /// Rough estimate of the key size in bits (0 if unknown).
    pub estimated_bits: u32,
}

/// Hard cap on RSA key hints to prevent memory exhaustion on attacker-controlled input.
const MAX_RSA_HINTS: usize = 1024;

/// Hard cap on `ChaCha20` sigma word hits (each word is only 4 bytes → high false-positive rate).
const MAX_CHACHA_WORD_HITS: usize = 256;

/// Detects RSA keys in binary data using structural heuristics.
pub struct RsaDetector;

impl RsaDetector {
    /// Scan `data` for RSA key material using three heuristics:
    ///
    /// 1. DER-encoded RSA key: starts with `0x30 0x82` (SEQUENCE, length ≥ 256).
    /// 2. PEM header "BEGIN RSA" (ASCII).
    /// 3. Large prime-looking byte sequences: contiguous high-entropy regions
    ///    whose length is consistent with a prime factor (64, 128, 256, 512 bytes).
    #[must_use]
    pub fn detect_rsa_keys(data: &[u8]) -> Vec<RsaKeyHint> {
        let mut hints = Vec::new();

        // Heuristic 1: DER SEQUENCE header 0x30 0x82 <len_hi> <len_lo>.
        if data.len() >= 4 {
            let limit = data.len() - 4;
            for offset in 0..=limit {
                if hints.len() >= MAX_RSA_HINTS {
                    break;
                }
                if data[offset] == 0x30 && data[offset + 1] == 0x82 {
                    let declared_len =
                        (u32::from(data[offset + 2]) << 8) | u32::from(data[offset + 3]);
                    if declared_len >= 64 {
                        // Estimate key bits from the DER blob length.
                        let estimated_bits = Self::estimate_bits_from_der_len(declared_len);
                        hints.push(RsaKeyHint {
                            offset,
                            kind: "DER-RSA".to_string(),
                            estimated_bits,
                        });
                    }
                }
            }
        }

        // Heuristic 2: PEM "BEGIN RSA" marker.
        let pem_marker = b"BEGIN RSA";
        if data.len() >= pem_marker.len() {
            let limit = data.len() - pem_marker.len();
            for offset in 0..=limit {
                if hints.len() >= MAX_RSA_HINTS {
                    break;
                }
                if &data[offset..offset + pem_marker.len()] == pem_marker {
                    hints.push(RsaKeyHint {
                        offset,
                        kind: "PEM-RSA".to_string(),
                        estimated_bits: 0, // Cannot determine without parsing the full PEM.
                    });
                }
            }
        }

        // Heuristic 3: Large prime-looking sequences.
        // A 1024-bit prime factor is 128 bytes; 2048-bit factor is 256 bytes.
        // Primes have the high bit set and bytes that are roughly uniform.
        for &key_half_bytes in &[64usize, 128, 256, 512] {
            if data.len() < key_half_bytes {
                continue;
            }
            let limit = data.len() - key_half_bytes;
            let mut offset = 0;
            while offset <= limit {
                let window = &data[offset..offset + key_half_bytes];
                // High bit must be set on the first byte (prime > 2^(n*8-1)).
                if window[0] & 0x80 != 0 {
                    // Check approximate uniformity via entropy.
                    let entropy = Self::byte_entropy(window);
                    if entropy > 6.5 {
                        hints.push(RsaKeyHint {
                            offset,
                            kind: "large-prime-candidate".to_string(),
                            estimated_bits: u32::try_from(key_half_bytes.saturating_mul(16)).unwrap_or(u32::MAX),
                        });
                        // Advance past this candidate to avoid overlapping hits.
                        offset += key_half_bytes;
                        continue;
                    }
                }
                offset += 1;
            }
        }

        hints.sort_by_key(|h| h.offset);
        hints
    }

    const fn estimate_bits_from_der_len(der_len: u32) -> u32 {
        // DER RSA private key payload sizes (approximate):
        //   512-bit key  : ~300  bytes
        //   1024-bit key : ~600  bytes
        //   2048-bit key : ~1190 bytes
        //   4096-bit key : ~2350 bytes
        match der_len {
            0..=400 => 512,
            401..=700 => 1024,
            701..=1400 => 2048,
            1401..=2800 => 4096,
            _ => 8192,
        }
    }

    fn byte_entropy(data: &[u8]) -> f64 {
        if data.is_empty() {
            return 0.0;
        }
        let mut freq = [0u32; 256];
        for &b in data {
            freq[b as usize] += 1;
        }
        let n = f64::from(u32::try_from(data.len()).unwrap_or(u32::MAX));
        freq.iter()
            .filter(|&&c| c > 0)
            .map(|&c| {
                let p = f64::from(c) / n;
                -p * p.log2()
            })
            .sum()
    }
}

// ── Extended CryptoFingerprint scan ──────────────────────────────────────────

impl ConstantScanner {
    /// Comprehensive scan covering all algorithms in the fingerprint database.
    ///
    /// In addition to the constants already detected by [`ConstantScanner::scan_bytes`],
    /// this method adds:
    /// - AES S-box first 8 bytes (lower confidence prefix match)
    /// - SHA-256 H0–H7 in big-endian as a 32-byte sequence
    /// - MD5 A–D init in little-endian (standard [01 23 45 67])
    /// - `ChaCha20` per-word detection (beyond the full-sigma search)
    /// - CRC32 reversed polynomial `0xEDB8_8320` (LE and BE — already present)
    /// - Poly1305 field prime component 2^130-5 marker bytes
    /// - Curve25519 field prime bytes
    /// - GHASH reduction polynomial bytes
    #[must_use]
    pub fn scan_for_all_constants(data: &[u8]) -> Vec<CryptoConstantFound> {
        let mut findings = Self::scan_bytes(data);
        Self::scan_extended_aes_sha_constants(data, &mut findings);
        Self::scan_prime_and_gcm_constants(data, &mut findings);
        findings.sort_by(|a, b| {
            a.offset.cmp(&b.offset).then_with(|| {
                b.confidence
                    .partial_cmp(&a.confidence)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
        });
        findings
    }

    fn scan_extended_aes_sha_constants(data: &[u8], findings: &mut Vec<CryptoConstantFound>) {
        // ── AES S-box 8-byte prefix ───────────────────────────────────────────
        let aes8: &[u8] = &[0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5];
        for offset in find_all(data, aes8) {
            if !findings.iter().any(|f| f.offset == offset && f.algorithm == AlgorithmId::Aes128) {
                findings.push(CryptoConstantFound { offset, algorithm: AlgorithmId::Aes128, constant_name: "AES-SBOX[0..8]".into(), confidence: 0.82 });
            }
        }
        // ── SHA-256 H0–H7 as contiguous 32-byte big-endian sequence ─────────
        let sha256_h_be: Vec<u8> = [
            0x6a09_e667u32, 0xbb67_ae85, 0x3c6e_f372, 0xa54f_f53a,
            0x510e_527f, 0x9b05_688c, 0x1f83_d9ab, 0x5be0_cd19,
        ].iter().flat_map(|&w| w.to_be_bytes()).collect();
        for offset in find_all(data, &sha256_h_be) {
            findings.push(CryptoConstantFound { offset, algorithm: AlgorithmId::Sha256, constant_name: "SHA256-H0-H7-BE".into(), confidence: 0.97 });
        }
        // ── MD5 A/B/C/D init values ───────────────────────────────────────────
        let md5_init: &[u8] = &[0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
        for offset in find_all(data, md5_init) {
            findings.push(CryptoConstantFound { offset, algorithm: AlgorithmId::Md5, constant_name: "MD5-ABCD-INIT-LE".into(), confidence: 0.80 });
        }
        // ── ChaCha20 individual sigma words ──────────────────────────────────
        let chacha_words = ChaCha20Identifier::detect_chacha20_words(data);
        for (offset, word_idx) in chacha_words.into_iter().take(MAX_CHACHA_WORD_HITS) {
            let name = match word_idx {
                0 => "CHACHA20-SIGMA-WORD0",
                1 => "CHACHA20-SIGMA-WORD1",
                2 => "CHACHA20-SIGMA-WORD2",
                _ => "CHACHA20-SIGMA-WORD3",
            };
            findings.push(CryptoConstantFound { offset, algorithm: AlgorithmId::ChaCha20, constant_name: name.into(), confidence: 0.65 });
        }
    }

    fn scan_prime_and_gcm_constants(data: &[u8], findings: &mut Vec<CryptoConstantFound>) {
        // ── Poly1305 field prime 2^130-5 ─────────────────────────────────────
        let poly1305_prime_le: &[u8] = &[
            0xfb, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0x03,
        ];
        for offset in find_all(data, poly1305_prime_le) {
            findings.push(CryptoConstantFound { offset, algorithm: AlgorithmId::ChaCha20, constant_name: "POLY1305-PRIME-LE".into(), confidence: 0.88 });
        }
        // ── Curve25519 field prime 2^255-19 ──────────────────────────────────
        let curve25519_prime_le: &[u8] = &[
            0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0x7f,
        ];
        for offset in find_all(data, curve25519_prime_le) {
            findings.push(CryptoConstantFound { offset, algorithm: AlgorithmId::Aes256, constant_name: "CURVE25519-PRIME-LE".into(), confidence: 0.94 });
        }
        // ── GHASH reduction polynomial for AES-GCM ───────────────────────────
        let ghash_poly_be: &[u8] = &[
            0xe1, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ];
        for offset in find_all(data, ghash_poly_be) {
            findings.push(CryptoConstantFound { offset, algorithm: AlgorithmId::AesGcm, constant_name: "GHASH-REDUCTION-POLY-BE".into(), confidence: 0.92 });
        }
    }
}

// ── AlgorithmConfidence ───────────────────────────────────────────────────────

/// Combines static constant evidence with optional behavioural (avalanche) data
/// to produce a single weighted confidence score.
pub struct AlgorithmConfidence;

impl AlgorithmConfidence {
    /// Combine static match evidence with an optional behavioural avalanche score.
    ///
    /// Weights:
    /// - Static constant matches: 0.7
    /// - Behavioural avalanche score (proximity to ideal 0.5): 0.3
    ///
    /// The static weight is the union-probability of all `static_matches` scores.
    /// The behavioural weight is `1 - |avalanche - 0.5| * 2` (1.0 at perfect 0.5,
    /// 0.0 at 0.0 or 1.0).
    ///
    /// Returns a combined confidence in [0.0, 1.0].
    #[must_use]
    pub fn combine_evidence(
        static_matches: &[CryptoConstantFound],
        behavioral: Option<f64>,
    ) -> f64 {
        const STATIC_WEIGHT: f64 = 0.7;
        const BEHAVIORAL_WEIGHT: f64 = 0.3;

        // Static score: union probability P(at least one match is correct).
        let static_score = if static_matches.is_empty() {
            0.0f64
        } else {
            let miss = static_matches
                .iter()
                .fold(1.0f64, |acc, m| acc * (1.0 - f64::from(m.confidence).clamp(0.0, 1.0)));
            1.0 - miss
        };

        // Behavioural score: 0.0 when avalanche = 0.0 or 1.0; 1.0 when avalanche = 0.5.
        let behavioral_score = behavioral.map_or(0.0, |av| {
            let proximity = (av - 0.5).abs().mul_add(-2.0, 1.0);
            proximity.clamp(0.0, 1.0)
        });

        if behavioral.is_none() {
            // No behavioural data: normalise to full static weight.
            static_score.clamp(0.0, 1.0)
        } else {
            (static_score * STATIC_WEIGHT + behavioral_score * BEHAVIORAL_WEIGHT).clamp(0.0, 1.0)
        }
    }

    /// Classify a combined score into a [`ConfidenceLevel`].
    #[must_use]
    pub fn level(score: f64) -> ConfidenceLevel {
        ConfidenceLevel::from_score(score)
    }
}

// ── Tests for new crypto-id additions ────────────────────────────────────────

#[cfg(test)]
mod extended_id_tests {
    use super::*;

    // ── ChaCha20Identifier ────────────────────────────────────────────────────

    #[test]
    fn test_chacha20_detect_const_present() {
        let sigma = b"expand 32-byte k";
        let mut data = vec![0u8; 200];
        data[50..66].copy_from_slice(sigma);
        let offsets = ChaCha20Identifier::detect_chacha20_const(&data);
        assert_eq!(offsets, vec![50]);
    }

    #[test]
    fn test_chacha20_detect_const_absent() {
        let data = vec![0u8; 100];
        let offsets = ChaCha20Identifier::detect_chacha20_const(&data);
        assert!(offsets.is_empty());
    }

    #[test]
    fn test_chacha20_detect_const_multiple() {
        let sigma = b"expand 32-byte k";
        let mut data = vec![0u8; 300];
        data[10..26].copy_from_slice(sigma);
        data[100..116].copy_from_slice(sigma);
        let offsets = ChaCha20Identifier::detect_chacha20_const(&data);
        assert_eq!(offsets, vec![10, 100]);
    }

    #[test]
    fn test_chacha20_detect_const_short_data() {
        // Data shorter than sigma → no matches, no panic.
        let data = b"expand".to_vec();
        let offsets = ChaCha20Identifier::detect_chacha20_const(&data);
        assert!(offsets.is_empty());
    }

    #[test]
    fn test_chacha20_detect_words_finds_word0() {
        // Word 0 of the sigma is the ASCII bytes of "expa": [0x65, 0x78, 0x70, 0x61].
        let needle: &[u8] = b"expa";
        let mut data = vec![0u8; 64];
        data[8..12].copy_from_slice(needle);
        let hits = ChaCha20Identifier::detect_chacha20_words(&data);
        assert!(hits.iter().any(|&(off, wi)| off == 8 && wi == 0));
    }

    #[test]
    fn test_chacha20_detect_words_finds_all_four() {
        // Embed the full sigma so all four words appear.
        let sigma = b"expand 32-byte k";
        let mut data = vec![0u8; 64];
        data[0..16].copy_from_slice(sigma);
        let hits = ChaCha20Identifier::detect_chacha20_words(&data);
        // Should find word indices 0,1,2,3 at offsets 0,4,8,12.
        let word_indices: Vec<usize> = hits.iter().map(|&(_, wi)| wi).collect();
        for wi in 0..4 {
            assert!(word_indices.contains(&wi), "Missing word index {wi}");
        }
    }

    // ── RsaDetector ──────────────────────────────────────────────────────────

    #[test]
    fn test_rsa_detector_der_header() {
        let mut data = vec![0u8; 300];
        // Inject a 0x30 0x82 header with declared length 0x04 0xA3 = 1187 (2048-bit key).
        data[10] = 0x30;
        data[11] = 0x82;
        data[12] = 0x04;
        data[13] = 0xa3;
        let hints = RsaDetector::detect_rsa_keys(&data);
        let der_hint = hints.iter().find(|h| h.kind == "DER-RSA");
        assert!(der_hint.is_some(), "Expected DER-RSA hint");
        let h = der_hint.unwrap();
        assert_eq!(h.offset, 10);
        assert_eq!(h.estimated_bits, 2048);
    }

    #[test]
    fn test_rsa_detector_pem_marker() {
        let mut data = b"-----BEGIN RSA PRIVATE KEY-----\n".to_vec();
        data.extend_from_slice(&[0u8; 100]);
        let hints = RsaDetector::detect_rsa_keys(&data);
        let pem = hints.iter().find(|h| h.kind == "PEM-RSA");
        assert!(pem.is_some(), "Expected PEM-RSA hint");
        // "-----BEGIN RSA..." — "BEGIN RSA" starts at index 5 (after five dashes).
        assert_eq!(pem.unwrap().offset, 5);
    }

    #[test]
    fn test_rsa_detector_no_false_positives_zeros() {
        let data = vec![0u8; 512];
        let hints = RsaDetector::detect_rsa_keys(&data);
        // All-zero has low entropy and no 0x30 0x82 header → no DER/PEM hits.
        
        assert!(!hints
            .iter().any(|h| h.kind == "DER-RSA" || h.kind == "PEM-RSA"));
    }

    #[test]
    fn test_rsa_detector_sorted_by_offset() {
        // Inject PEM at offset 200 and DER at offset 0.
        let mut data = vec![0u8; 400];
        data[0] = 0x30;
        data[1] = 0x82;
        data[2] = 0x02;
        data[3] = 0x00; // declared_len = 512 → 2048 bits
        let pem_marker = b"BEGIN RSA";
        data[200..209].copy_from_slice(pem_marker);
        let hints = RsaDetector::detect_rsa_keys(&data);
        for pair in hints.windows(2) {
            assert!(
                pair[0].offset <= pair[1].offset,
                "Hints must be sorted by offset"
            );
        }
    }

    #[test]
    fn test_rsa_detector_der_bit_estimate() {
        // Smoke-test the estimate function via the detector.
        let mut data = vec![0u8; 10];
        data[0] = 0x30;
        data[1] = 0x82;
        data[2] = 0x00;
        data[3] = 0x50; // declared_len = 80 → 512 bits
        let hints = RsaDetector::detect_rsa_keys(&data);
        let der = hints.iter().find(|h| h.kind == "DER-RSA").unwrap();
        assert_eq!(der.estimated_bits, 512);
    }

    // ── scan_for_all_constants ────────────────────────────────────────────────

    #[test]
    fn test_scan_all_finds_aes8_prefix() {
        let prefix: &[u8] = &[0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5];
        let mut data = vec![0u8; 100];
        data[20..28].copy_from_slice(prefix);
        let findings = ConstantScanner::scan_for_all_constants(&data);
        let hit = findings
            .iter()
            .any(|f| f.offset == 20 && f.constant_name.contains("AES-SBOX[0.."));
        assert!(hit, "Should detect AES S-box 8-byte prefix");
    }

    #[test]
    fn test_scan_all_finds_sha256_h_sequence() {
        let sha256_h_be: Vec<u8> = [
            0x6a09_e667u32,
            0xbb67_ae85,
            0x3c6e_f372,
            0xa54f_f53a,
            0x510e_527f,
            0x9b05_688c,
            0x1f83_d9ab,
            0x5be0_cd19,
        ]
        .iter()
        .flat_map(|&w| w.to_be_bytes())
        .collect();
        let mut data = vec![0u8; 200];
        data[60..60 + sha256_h_be.len()].copy_from_slice(&sha256_h_be);
        let findings = ConstantScanner::scan_for_all_constants(&data);
        let hit = findings
            .iter()
            .any(|f| f.offset == 60 && f.constant_name == "SHA256-H0-H7-BE");
        assert!(hit, "Should detect full SHA-256 H0-H7 sequence");
    }

    #[test]
    fn test_scan_all_finds_md5_init() {
        let init: &[u8] = &[0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
        let mut data = vec![0u8; 64];
        data[4..12].copy_from_slice(init);
        let findings = ConstantScanner::scan_for_all_constants(&data);
        let hit = findings
            .iter()
            .any(|f| f.offset == 4 && f.constant_name == "MD5-ABCD-INIT-LE");
        assert!(hit, "Should detect MD5 ABCD init");
    }

    #[test]
    fn test_scan_all_finds_chacha20_words() {
        // Embed only word 0 of the sigma constant: ASCII "expa".
        let mut data = vec![0u8; 64];
        data[16..20].copy_from_slice(b"expa");
        let findings = ConstantScanner::scan_for_all_constants(&data);
        let hit = findings
            .iter()
            .any(|f| f.constant_name.contains("CHACHA20-SIGMA-WORD0"));
        assert!(hit, "Should detect ChaCha20 sigma word 0");
    }

    #[test]
    fn test_scan_all_finds_ghash_poly() {
        let poly: &[u8] = &[
            0xe1, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ];
        let mut data = vec![0u8; 64];
        data[10..26].copy_from_slice(poly);
        let findings = ConstantScanner::scan_for_all_constants(&data);
        let hit = findings
            .iter()
            .any(|f| f.constant_name == "GHASH-REDUCTION-POLY-BE");
        assert!(hit, "Should detect GHASH reduction polynomial");
    }

    #[test]
    fn test_scan_all_sorted_by_offset() {
        // Multiple constants at different offsets.
        let mut data = vec![0u8; 512];
        // SHA-256 H0 at offset 10.
        data[10..14].copy_from_slice(&0x6a09_e667u32.to_be_bytes());
        // CRC32 poly at offset 200.
        data[200..204].copy_from_slice(&0xedb8_8320u32.to_le_bytes());
        let findings = ConstantScanner::scan_for_all_constants(&data);
        let offsets: Vec<usize> = findings.iter().map(|f| f.offset).collect();
        let mut sorted = offsets.clone();
        sorted.sort_unstable();
        assert_eq!(
            offsets, sorted,
            "All findings must be sorted by ascending offset"
        );
    }

    // ── AlgorithmConfidence ───────────────────────────────────────────────────

    #[test]
    fn test_algo_confidence_no_matches_no_behavioral() {
        let score = AlgorithmConfidence::combine_evidence(&[], None);
        assert_eq!(score, 0.0);
    }

    #[test]
    fn test_algo_confidence_single_static_no_behavioral() {
        let m = CryptoConstantFound {
            offset: 0,
            algorithm: AlgorithmId::Aes128,
            constant_name: "AES-SBOX".into(),
            confidence: 0.97,
        };
        let score = AlgorithmConfidence::combine_evidence(&[m], None);
        // Without behavioural data, result should equal the static score (0.97).
        assert!((score - 0.97).abs() < 1e-4, "Score mismatch: {score}");
    }

    #[test]
    fn test_algo_confidence_perfect_avalanche() {
        let m = CryptoConstantFound {
            offset: 0,
            algorithm: AlgorithmId::ChaCha20,
            constant_name: "CHACHA20-SIGMA".into(),
            confidence: 0.99,
        };
        // Perfect avalanche score = 0.5 → behavioral_score = 1.0.
        let score = AlgorithmConfidence::combine_evidence(&[m], Some(0.5));
        // score = 0.99*0.7 + 1.0*0.3 = 0.693 + 0.3 = 0.993
        assert!(score > 0.98, "Expected high combined score, got {score}");
    }

    #[test]
    fn test_algo_confidence_zero_avalanche() {
        let m = CryptoConstantFound {
            offset: 0,
            algorithm: AlgorithmId::Aes128,
            constant_name: "AES-SBOX".into(),
            confidence: 0.80,
        };
        // Avalanche = 0.0 → behavioral_score = 0.0.
        let score = AlgorithmConfidence::combine_evidence(&[m], Some(0.0));
        // score = 0.80*0.7 + 0.0*0.3 = 0.56
        assert!((score - 0.56).abs() < 1e-3, "Unexpected score {score}");
    }

    #[test]
    fn test_algo_confidence_multiple_static_matches() {
        let matches = vec![
            CryptoConstantFound {
                offset: 0,
                algorithm: AlgorithmId::Aes128,
                constant_name: "AES-SBOX".into(),
                confidence: 0.80,
            },
            CryptoConstantFound {
                offset: 256,
                algorithm: AlgorithmId::Aes128,
                constant_name: "AES-RCON-PREFIX".into(),
                confidence: 0.88,
            },
        ];
        let score = AlgorithmConfidence::combine_evidence(&matches, None);
        // Union: 1 - (1-0.80)*(1-0.88) = 1 - 0.20*0.12 = 1 - 0.024 = 0.976
        assert!((score - 0.976).abs() < 1e-3, "Unexpected score {score}");
    }

    #[test]
    fn test_algo_confidence_level_classification() {
        assert_eq!(AlgorithmConfidence::level(0.85), ConfidenceLevel::High);
        assert_eq!(AlgorithmConfidence::level(0.65), ConfidenceLevel::Medium);
        assert_eq!(AlgorithmConfidence::level(0.30), ConfidenceLevel::Low);
    }

    #[test]
    fn test_algo_confidence_score_clamped_to_one() {
        // All very high static scores should not exceed 1.0.
        let matches: Vec<CryptoConstantFound> = (0..10)
            .map(|i| CryptoConstantFound {
                offset: i * 4,
                algorithm: AlgorithmId::Sha256,
                constant_name: format!("SHA256-HIT-{i}"),
                confidence: 0.99,
            })
            .collect();
        let score = AlgorithmConfidence::combine_evidence(&matches, Some(0.5));
        assert!(score <= 1.0, "Score must not exceed 1.0, got {score}");
    }
}

// =============================================================================
// Binary crypto-constant scanner
// =============================================================================

// ── AES S-box ─────────────────────────────────────────────────────────────────

/// The standard AES forward S-box (256 bytes).
pub const AES_SBOX_V2: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

/// The AES inverse S-box (256 bytes).
pub const AES_INV_SBOX_V2: [u8; 256] = [
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
];

// ── SHA-256 round constants ───────────────────────────────────────────────────

/// SHA-256 round constants K[0..64] as little-endian u32 words.
pub const SHA256_K_V2: [u32; 64] = [
    0x428a_2f98, 0x7137_4491, 0xb5c0_fbcf, 0xe9b5_dba5, 0x3956_c25b, 0x59f1_11f1, 0x923f_82a4, 0xab1c_5ed5,
    0xd807_aa98, 0x1283_5b01, 0x2431_85be, 0x550c_7dc3, 0x72be_5d74, 0x80de_b1fe, 0x9bdc_06a7, 0xc19b_f174,
    0xe49b_69c1, 0xefbe_4786, 0x0fc1_9dc6, 0x240c_a1cc, 0x2de9_2c6f, 0x4a74_84aa, 0x5cb0_a9dc, 0x76f9_88da,
    0x983e_5152, 0xa831_c66d, 0xb003_27c8, 0xbf59_7fc7, 0xc6e0_0bf3, 0xd5a7_9147, 0x06ca_6351, 0x1429_2967,
    0x27b7_0a85, 0x2e1b_2138, 0x4d2c_6dfc, 0x5338_0d13, 0x650a_7354, 0x766a_0abb, 0x81c2_c92e, 0x9272_2c85,
    0xa2bf_e8a1, 0xa81a_664b, 0xc24b_8b70, 0xc76c_51a3, 0xd192_e819, 0xd699_0624, 0xf40e_3585, 0x106a_a070,
    0x19a4_c116, 0x1e37_6c08, 0x2748_774c, 0x34b0_bcb5, 0x391c_0cb3, 0x4ed8_aa4a, 0x5b9c_ca4f, 0x682e_6ff3,
    0x748f_82ee, 0x78a5_636f, 0x84c8_7814, 0x8cc7_0208, 0x90be_fffa, 0xa450_6ceb, 0xbef9_a3f7, 0xc671_78f2,
];

// ── MD5 sine-derived constants ────────────────────────────────────────────────

/// MD5 T-table (64 sine-derived 32-bit constants, stored big-endian).
pub const MD5_T: [u32; 64] = [
    0xd76a_a478, 0xe8c7_b756, 0x2420_70db, 0xc1bd_ceee, 0xf57c_0faf, 0x4787_c62a, 0xa830_4613, 0xfd46_9501,
    0x6980_98d8, 0x8b44_f7af, 0xffff_5bb1, 0x895c_d7be, 0x6b90_1122, 0xfd98_7193, 0xa679_438e, 0x49b4_0821,
    0xf61e_2562, 0xc040_b340, 0x265e_5a51, 0xe9b6_c7aa, 0xd62f_105d, 0x0244_1453, 0xd8a1_e681, 0xe7d3_fbc8,
    0x21e1_cde6, 0xc337_07d6, 0xf4d5_0d87, 0x455a_14ed, 0xa9e3_e905, 0xfcef_a3f8, 0x676f_02d9, 0x8d2a_4c8a,
    0xfffa_3942, 0x8771_f681, 0x6d9d_6122, 0xfde5_380c, 0xa4be_ea44, 0x4bde_cfa9, 0xf6bb_4b60, 0xbebf_bc70,
    0x289b_7ec6, 0xeaa1_27fa, 0xd4ef_3085, 0x0488_1d05, 0xd9d4_d039, 0xe6db_99e5, 0x1fa2_7cf8, 0xc4ac_5665,
    0xf429_2244, 0x432a_ff97, 0xab94_23a7, 0xfc93_a039, 0x655b_59c3, 0x8f0c_cc92, 0xffef_f47d, 0x8584_5dd1,
    0x6fa8_7e4f, 0xfe2c_e6e0, 0xa301_4314, 0x4e08_11a1, 0xf753_7e82, 0xbd3a_f235, 0x2ad7_d2bb, 0xeb86_d391,
];

// ── ChaCha20 magic constant ───────────────────────────────────────────────────

/// `ChaCha20` / Salsa20 "expand 32-byte k" magic constant (as bytes).
pub const CHACHA20_MAGIC: [u8; 16] = *b"expand 32-byte k";

/// `ChaCha20` "expand 16-byte k" magic constant (as bytes).
pub const CHACHA20_MAGIC_16: [u8; 16] = *b"expand 16-byte k";

// ── CRC-32 (IEEE) polynomial table (first 16 entries for signature) ───────────

/// The CRC-32 lookup table (IEEE/PKZIP polynomial `0xEDB8_8320`), all 256 entries.
pub const CRC32_TABLE: [u32; 256] = {
    // Rust does not yet support loops in const context without nightly features,
    // so we list the table explicitly.
    [
        0x0000_0000, 0x7707_3096, 0xee0e_612c, 0x9909_51ba, 0x076d_c419, 0x706a_f48f, 0xe963_a535,
        0x9e64_95a3, 0x0edb_8832, 0x79dc_b8a4, 0xe0d5_e91e, 0x97d2_d988, 0x09b6_4c2b, 0x7eb1_7cbd,
        0xe7b8_2d07, 0x90bf_1d91, 0x1db7_1064, 0x6ab0_20f2, 0xf3b9_7148, 0x84be_41de, 0x1ada_d47d,
        0x6ddd_e4eb, 0xf4d4_b551, 0x83d3_85c7, 0x136c_9856, 0x646b_a8c0, 0xfd62_f97a, 0x8a65_c9ec,
        0x1401_5c4f, 0x6306_6cd9, 0xfa0f_3d63, 0x8d08_0df5, 0x3b6e_20c8, 0x4c69_105e, 0xd560_41e4,
        0xa267_7172, 0x3c03_e4d1, 0x4b04_d447, 0xd20d_85fd, 0xa50a_b56b, 0x35b5_a8fa, 0x42b2_986c,
        0xdbbb_c9d6, 0xacbc_f940, 0x32d8_6ce3, 0x45df_5c75, 0xdcd6_0dcf, 0xabd1_3d59, 0x26d9_30ac,
        0x51de_003a, 0xc8d7_5180, 0xbfd0_6116, 0x21b4_f4b5, 0x56b3_c423, 0xcfba_9599, 0xb8bd_a50f,
        0x2802_b89e, 0x5f05_8808, 0xc60c_d9b2, 0xb10b_e924, 0x2f6f_7c87, 0x5868_4c11, 0xc161_1dab,
        0xb666_2d3d, 0x76dc_4190, 0x01db_7106, 0x98d2_20bc, 0xefd5_102a, 0x71b1_8589, 0x06b6_b51f,
        0x9fbf_e4a5, 0xe8b8_d433, 0x7807_c9a2, 0x0f00_f934, 0x9609_a88e, 0xe10e_9818, 0x7f6a_0dbb,
        0x086d_3d2d, 0x9164_6c97, 0xe663_5c01, 0x6b6b_51f4, 0x1c6c_6162, 0x8565_30d8, 0xf262_004e,
        0x6c06_95ed, 0x1b01_a57b, 0x8208_f4c1, 0xf50f_c457, 0x65b0_d9c6, 0x12b7_e950, 0x8bbe_b8ea,
        0xfcb9_887c, 0x62dd_1ddf, 0x15da_2d49, 0x8cd3_7cf3, 0xfbd4_4c65, 0x4db2_6158, 0x3ab5_51ce,
        0xa3bc_0074, 0xd4bb_30e2, 0x4adf_a541, 0x3dd8_95d7, 0xa4d1_c46d, 0xd3d6_f4fb, 0x4369_e96a,
        0x346e_d9fc, 0xad67_8846, 0xda60_b8d0, 0x4404_2d73, 0x3303_1de5, 0xaa0a_4c5f, 0xdd0d_7cc9,
        0x5005_713c, 0x2702_41aa, 0xbe0b_1010, 0xc90c_2086, 0x5768_b525, 0x206f_85b3, 0xb966_d409,
        0xce61_e49f, 0x5ede_f90e, 0x29d9_c998, 0xb0d0_9822, 0xc7d7_a8b4, 0x59b3_3d17, 0x2eb4_0d81,
        0xb7bd_5c3b, 0xc0ba_6cad, 0xedb8_8320, 0x9abf_b3b6, 0x03b6_e20c, 0x74b1_d29a, 0xead5_4739,
        0x9dd2_77af, 0x04db_2615, 0x73dc_1683, 0xe363_0b12, 0x9464_3b84, 0x0d6d_6a3e, 0x7a6a_5aa8,
        0xe40e_cf0b, 0x9309_ff9d, 0x0a00_ae27, 0x7d07_9eb1, 0xf00f_9344, 0x8708_a3d2, 0x1e01_f268,
        0x6906_c2fe, 0xf762_575d, 0x8065_67cb, 0x196c_3671, 0x6e6b_06e7, 0xfed4_1b76, 0x89d3_2be0,
        0x10da_7a5a, 0x67dd_4acc, 0xf9b9_df6f, 0x8ebe_eff9, 0x17b7_be43, 0x60b0_8ed5, 0xd6d6_a3e8,
        0xa1d1_937e, 0x38d8_c2c4, 0x4fdf_f252, 0xd1bb_67f1, 0xa6bc_5767, 0x3fb5_06dd, 0x48b2_364b,
        0xd80d_2bda, 0xaf0a_1b4c, 0x3603_4af6, 0x4104_7a60, 0xdf60_efc3, 0xa867_df55, 0x316e_8eef,
        0x4669_be79, 0xcb61_b38c, 0xbc66_831a, 0x256f_d2a0, 0x5268_e236, 0xcc0c_7795, 0xbb0b_4703,
        0x2202_16b9, 0x5505_262f, 0xc5ba_3bbe, 0xb2bd_0b28, 0x2bb4_5a92, 0x5cb3_6a04, 0xc2d7_ffa7,
        0xb5d0_cf31, 0x2cd9_9e8b, 0x5bde_ae1d, 0x9b64_c2b0, 0xec63_f226, 0x756a_a39c, 0x026d_930a,
        0x9c09_06a9, 0xeb0e_363f, 0x7207_6785, 0x0500_5713, 0x95bf_4a82, 0xe2b8_7a14, 0x7bb1_2bae,
        0x0cb6_1b38, 0x92d2_8e9b, 0xe5d5_be0d, 0x7cdc_efb7, 0x0bdb_df21, 0x86d3_d2d4, 0xf1d4_e242,
        0x68dd_b3f8, 0x1fda_836e, 0x81be_16cd, 0xf6b9_265b, 0x6fb0_77e1, 0x18b7_4777, 0x8808_5ae6,
        0xff0f_6a70, 0x6606_3bca, 0x1101_0b5c, 0x8f65_9eff, 0xf862_ae69, 0x616b_ffd3, 0x166c_cf45,
        0xa00a_e278, 0xd70d_d2ee, 0x4e04_8354, 0x3903_b3c2, 0xa767_2661, 0xd060_16f7, 0x4969_474d,
        0x3e6e_77db, 0xaed1_6a4a, 0xd9d6_5adc, 0x40df_0b66, 0x37d8_3bf0, 0xa9bc_ae53, 0xdebb_9ec5,
        0x47b2_cf7f, 0x30b5_ffe9, 0xbdbd_f21c, 0xcaba_c28a, 0x53b3_9330, 0x24b4_a3a6, 0xbad0_3605,
        0xcdd7_0693, 0x54de_5729, 0x23d9_67bf, 0xb366_7a2e, 0xc461_4ab8, 0x5d68_1b02, 0x2a6f_2b94,
        0xb40b_be37, 0xc30c_8ea1, 0x5a05_df1b, 0x2d02_ef8d,
    ]
};

// ── Scan result ───────────────────────────────────────────────────────────────

/// A single cryptographic constant match found inside a binary blob.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BinaryCryptoHit {
    /// Common algorithm name (e.g. `"AES"`, `"SHA-256"`).
    pub algorithm: String,
    /// The specific constant that was matched (e.g. `"AES_SBOX"`).
    pub constant_name: String,
    /// Byte offset into the input slice where the match starts.
    pub offset: u64,
    /// Confidence score in `[0.0, 1.0]`.
    pub confidence: f64,
    /// Number of matching bytes found (for partial matches).
    pub match_length: usize,
}

impl BinaryCryptoHit {
    #[must_use]
    pub fn new(
        algorithm: impl Into<String>,
        constant_name: impl Into<String>,
        offset: u64,
        confidence: f64,
        match_length: usize,
    ) -> Self {
        Self {
            algorithm: algorithm.into(),
            constant_name: constant_name.into(),
            offset,
            confidence,
            match_length,
        }
    }
}

// ── Generic Boyer-Moore-Horspool substring search ─────────────────────────────

/// Fast exact byte-pattern search using the simplified Horspool algorithm.
/// Returns all starting offsets (in bytes) where `pattern` occurs in `haystack`.
fn find_pattern(haystack: &[u8], pattern: &[u8]) -> Vec<usize> {
    let mut hits = Vec::new();
    let hay_len = haystack.len();
    let pat_len = pattern.len();
    if pat_len == 0 || pat_len > hay_len {
        return hits;
    }
    // Build bad-character skip table.
    let mut skip = [pat_len; 256];
    for (idx, &byte) in pattern[..pat_len - 1].iter().enumerate() {
        skip[byte as usize] = pat_len - 1 - idx;
    }
    let mut hay_idx = pat_len - 1;
    while hay_idx < hay_len {
        let mut pat_idx = pat_len - 1;
        let mut cursor = hay_idx;
        while {
            let in_range = pat_idx < pat_len;
            in_range && haystack[cursor] == pattern[pat_idx]
        } {
            if pat_idx == 0 {
                break;
            }
            pat_idx -= 1;
            cursor -= 1;
        }
        if haystack[cursor] == pattern[pat_idx] && pat_idx == 0 {
            hits.push(cursor);
        }
        hay_idx += skip[haystack[hay_idx] as usize];
    }
    hits
}

// ── AES S-box scanner ─────────────────────────────────────────────────────────

/// Search `binary` for the AES forward S-box.
#[must_use]
pub fn scan_for_aes_sbox(binary: &[u8]) -> Vec<BinaryCryptoHit> {
    // First 16 bytes are used as a distinctive prefix for partial matching.
    let signature = &AES_SBOX[..16];
    let mut hits = Vec::new();
    for offset in find_pattern(binary, signature) {
        // Verify the next bytes continue the S-box.
        let remaining = &binary[offset..];
        let match_len = AES_SBOX
            .iter()
            .zip(remaining.iter())
            .take_while(|(a, b)| a == b)
            .count();
        let confidence = f64::from(u32::try_from(match_len).unwrap_or(u32::MAX)) / f64::from(u32::try_from(AES_SBOX.len()).unwrap_or(u32::MAX));
        hits.push(BinaryCryptoHit::new(
            "AES",
            "AES_SBOX",
            offset as u64,
            confidence,
            match_len,
        ));
    }
    // Also look for the inverse S-box.
    let inv_sig = &AES_INV_SBOX[..16];
    for offset in find_pattern(binary, inv_sig) {
        let remaining = &binary[offset..];
        let match_len = AES_INV_SBOX
            .iter()
            .zip(remaining.iter())
            .take_while(|(a, b)| a == b)
            .count();
        let confidence = f64::from(u32::try_from(match_len).unwrap_or(u32::MAX)) / f64::from(u32::try_from(AES_INV_SBOX.len()).unwrap_or(u32::MAX));
        hits.push(BinaryCryptoHit::new(
            "AES",
            "AES_INV_SBOX",
            offset as u64,
            confidence,
            match_len,
        ));
    }
    hits
}

// ── SHA-256 constant scanner ──────────────────────────────────────────────────

/// Search `binary` for SHA-256 round constants (both LE and BE byte orders).
///
/// # Panics
///
/// Panics if a 4-byte slice cannot be converted to `[u8; 4]` (impossible in practice).
#[must_use]
pub fn scan_for_sha256_constants(binary: &[u8]) -> Vec<BinaryCryptoHit> {
    let mut hits = Vec::new();

    // Build LE and BE byte sequences for the first few constants as signature.
    let sig_len = 8; // first 8 u32s → 32 bytes as signature
    let mut le_sig = Vec::with_capacity(sig_len * 4);
    let mut be_sig = Vec::with_capacity(sig_len * 4);
    for &k in &SHA256_K[..sig_len] {
        le_sig.extend_from_slice(&k.to_le_bytes());
        be_sig.extend_from_slice(&k.to_be_bytes());
    }

    for (sig, name, endian) in [
        (le_sig.as_slice(), "SHA256_K_LE", "little-endian"),
        (be_sig.as_slice(), "SHA256_K_BE", "big-endian"),
    ] {
        for offset in find_pattern(binary, sig) {
            // Count how many of the full 64 constants match.
            let mut matched = 0usize;
            for (i, &k) in SHA256_K.iter().enumerate() {
                let byte_off = offset + i * 4;
                if byte_off + 4 > binary.len() {
                    break;
                }
                let word = if endian == "little-endian" {
                    u32::from_le_bytes(binary[byte_off..byte_off + 4].try_into().unwrap())
                } else {
                    u32::from_be_bytes(binary[byte_off..byte_off + 4].try_into().unwrap())
                };
                if word == k {
                    matched += 1;
                } else {
                    break;
                }
            }
            let confidence = f64::from(u32::try_from(matched).unwrap_or(u32::MAX)) / f64::from(u32::try_from(SHA256_K.len()).unwrap_or(u32::MAX));
            hits.push(BinaryCryptoHit::new(
                "SHA-256",
                name,
                offset as u64,
                confidence,
                matched * 4,
            ));
        }
    }
    hits
}

// ── CRC-32 table scanner ──────────────────────────────────────────────────────

/// Search `binary` for the CRC-32 IEEE lookup table (both byte orders).
///
/// # Panics
///
/// Panics if a 4-byte slice cannot be converted to `[u8; 4]` (impossible in practice).
#[must_use]
pub fn scan_for_crc32_table(binary: &[u8]) -> Vec<BinaryCryptoHit> {
    let mut hits = Vec::new();

    // First 4 entries (16 bytes) are used as a distinctive signature.
    let sig_entries = 4;
    let mut le_sig = Vec::with_capacity(sig_entries * 4);
    let mut be_sig = Vec::with_capacity(sig_entries * 4);
    for &entry in &CRC32_TABLE[..sig_entries] {
        le_sig.extend_from_slice(&entry.to_le_bytes());
        be_sig.extend_from_slice(&entry.to_be_bytes());
    }
    // CRC32 table starts with 0x0000_0000 which is non-distinctive — skip it
    // and use entries 1..5 instead.
    let mut le_sig2 = Vec::with_capacity(sig_entries * 4);
    for &entry in &CRC32_TABLE[1..=sig_entries] {
        le_sig2.extend_from_slice(&entry.to_le_bytes());
    }

    for (sig, name, start_entry) in [
        (le_sig.as_slice(), "CRC32_TABLE_LE", 0usize),
        (be_sig.as_slice(), "CRC32_TABLE_BE", 0usize),
        (le_sig2.as_slice(), "CRC32_TABLE_LE_alt", 1usize),
    ] {
        for raw_offset in find_pattern(binary, sig) {
            // Adjust for the start entry offset.
            let offset = if raw_offset >= start_entry * 4 {
                raw_offset - start_entry * 4
            } else {
                continue;
            };
            let is_le = name.contains("LE");
            let mut matched = 0usize;
            for (i, &entry) in CRC32_TABLE.iter().enumerate() {
                let byte_off = offset + i * 4;
                if byte_off + 4 > binary.len() {
                    break;
                }
                let word = if is_le {
                    u32::from_le_bytes(binary[byte_off..byte_off + 4].try_into().unwrap())
                } else {
                    u32::from_be_bytes(binary[byte_off..byte_off + 4].try_into().unwrap())
                };
                if word == entry {
                    matched += 1;
                } else {
                    break;
                }
            }
            let confidence = f64::from(u32::try_from(matched).unwrap_or(u32::MAX)) / f64::from(u32::try_from(CRC32_TABLE.len()).unwrap_or(u32::MAX));
            hits.push(BinaryCryptoHit::new(
                "CRC-32",
                name,
                offset as u64,
                confidence,
                matched * 4,
            ));
        }
    }
    hits
}

// ── ChaCha20 magic scanner ────────────────────────────────────────────────────

/// Search `binary` for the `ChaCha20` / Salsa20 "expand N-byte k" magic strings.
#[must_use]
pub fn scan_for_chacha_magic(binary: &[u8]) -> Vec<BinaryCryptoHit> {
    let mut hits = Vec::new();
    for offset in find_pattern(binary, &CHACHA20_MAGIC) {
        hits.push(BinaryCryptoHit::new(
            "ChaCha20/Salsa20",
            "CHACHA20_MAGIC_32",
            offset as u64,
            1.0,
            CHACHA20_MAGIC.len(),
        ));
    }
    for offset in find_pattern(binary, &CHACHA20_MAGIC_16) {
        hits.push(BinaryCryptoHit::new(
            "ChaCha20/Salsa20",
            "CHACHA20_MAGIC_16",
            offset as u64,
            1.0,
            CHACHA20_MAGIC_16.len(),
        ));
    }
    hits
}

// ── MD5 constant scanner ──────────────────────────────────────────────────────

/// Search `binary` for MD5 T-table constants (both LE and BE byte orders).
///
/// # Panics
///
/// Panics if a 4-byte slice cannot be converted to `[u8; 4]` (impossible in practice).
#[must_use]
pub fn scan_for_md5_constants(binary: &[u8]) -> Vec<BinaryCryptoHit> {
    let mut hits = Vec::new();
    let sig_count = 4;
    let mut le_sig = Vec::with_capacity(sig_count * 4);
    let mut be_sig = Vec::with_capacity(sig_count * 4);
    for &t in &MD5_T[..sig_count] {
        le_sig.extend_from_slice(&t.to_le_bytes());
        be_sig.extend_from_slice(&t.to_be_bytes());
    }
    for (sig, name, endian_le) in [
        (le_sig.as_slice(), "MD5_T_LE", true),
        (be_sig.as_slice(), "MD5_T_BE", false),
    ] {
        for offset in find_pattern(binary, sig) {
            let mut matched = 0usize;
            for (i, &t) in MD5_T.iter().enumerate() {
                let byte_off = offset + i * 4;
                if byte_off + 4 > binary.len() {
                    break;
                }
                let word = if endian_le {
                    u32::from_le_bytes(binary[byte_off..byte_off + 4].try_into().unwrap())
                } else {
                    u32::from_be_bytes(binary[byte_off..byte_off + 4].try_into().unwrap())
                };
                if word == t {
                    matched += 1;
                } else {
                    break;
                }
            }
            let confidence = f64::from(u32::try_from(matched).unwrap_or(u32::MAX)) / f64::from(u32::try_from(MD5_T.len()).unwrap_or(u32::MAX));
            hits.push(BinaryCryptoHit::new(
                "MD5",
                name,
                offset as u64,
                confidence,
                matched * 4,
            ));
        }
    }
    hits
}

// ── SHA-256 init value scanner ────────────────────────────────────────────────

/// Search `binary` for the SHA-256 initial hash values H0..H7
/// (`0x6a09e667 ... 0x5be0cd19`) in both LE and BE byte orders.
///
/// IDA Pro's findcrypt matches these as a standalone signature distinct
/// from the K round-constant table; without this scanner those hits are
/// missed entirely.
#[must_use]
pub fn scan_for_sha256_init(binary: &[u8]) -> Vec<BinaryCryptoHit> {
    let mut hits = Vec::new();
    let mut le_sig = Vec::with_capacity(SHA256_H.len() * 4);
    let mut be_sig = Vec::with_capacity(SHA256_H.len() * 4);
    for &h in &SHA256_H {
        le_sig.extend_from_slice(&h.to_le_bytes());
        be_sig.extend_from_slice(&h.to_be_bytes());
    }
    for (sig, name) in [
        (le_sig.as_slice(), "SHA256_H_LE"),
        (be_sig.as_slice(), "SHA256_H_BE"),
    ] {
        for offset in find_pattern(binary, sig) {
            hits.push(BinaryCryptoHit::new(
                "SHA-256",
                name,
                offset as u64,
                1.0,
                sig.len(),
            ));
        }
    }
    hits
}

// ── TEA / XTEA / XXTEA delta scanner ──────────────────────────────────────────

/// TEA / XTEA / XXTEA round delta constant (`(sqrt(5) - 1) * 2^31`).
pub const TEA_DELTA: u32 = 0x9E37_79B9;

/// Search `binary` for the TEA family delta constant `0x9E3779B9` in both byte orders.
///
/// The constant is only 4 bytes and may produce false positives, so callers should
/// corroborate hits with surrounding code patterns. Confidence is left at 0.6 to reflect this.
#[must_use]
pub fn scan_for_tea_delta(binary: &[u8]) -> Vec<BinaryCryptoHit> {
    let mut hits = Vec::new();
    let le = TEA_DELTA.to_le_bytes();
    let be = TEA_DELTA.to_be_bytes();
    for offset in find_pattern(binary, &le) {
        hits.push(BinaryCryptoHit::new(
            "TEA/XTEA/XXTEA",
            "TEA_DELTA_LE",
            offset as u64,
            0.6,
            4,
        ));
    }
    for offset in find_pattern(binary, &be) {
        hits.push(BinaryCryptoHit::new(
            "TEA/XTEA/XXTEA",
            "TEA_DELTA_BE",
            offset as u64,
            0.6,
            4,
        ));
    }
    hits
}

// ── SHA-512 init value scanner ────────────────────────────────────────────────

/// SHA-512 initial hash values H0..H7.
pub const SHA512_H: [u64; 8] = [
    0x6a09_e667_f3bc_c908,
    0xbb67_ae85_84ca_a73b,
    0x3c6e_f372_fe94_f82b,
    0xa54f_f53a_5f1d_36f1,
    0x510e_527f_ade6_82d1,
    0x9b05_688c_2b3e_6c1f,
    0x1f83_d9ab_fb41_bd6b,
    0x5be0_cd19_137e_2179,
];

/// Search `binary` for the SHA-512 initial hash values H0..H7 in both LE and BE byte orders.
#[must_use]
pub fn scan_for_sha512_init(binary: &[u8]) -> Vec<BinaryCryptoHit> {
    let mut hits = Vec::new();
    let mut le_sig = Vec::with_capacity(SHA512_H.len() * 8);
    let mut be_sig = Vec::with_capacity(SHA512_H.len() * 8);
    for &h in &SHA512_H {
        le_sig.extend_from_slice(&h.to_le_bytes());
        be_sig.extend_from_slice(&h.to_be_bytes());
    }
    for (sig, name) in [
        (le_sig.as_slice(), "SHA512_H_LE"),
        (be_sig.as_slice(), "SHA512_H_BE"),
    ] {
        for offset in find_pattern(binary, sig) {
            hits.push(BinaryCryptoHit::new(
                "SHA-512",
                name,
                offset as u64,
                1.0,
                sig.len(),
            ));
        }
    }
    hits
}

// ── SHA-1 init value scanner ──────────────────────────────────────────────────

/// Search `binary` for the SHA-1 / RIPEMD-160 initial hash values H0..H4 in both byte orders.
///
/// The values `0x67452301 ... 0xC3D2E1F0` are shared between SHA-1 and RIPEMD-160, so
/// both algorithm labels are emitted for each hit.
#[must_use]
pub fn scan_for_sha1_init(binary: &[u8]) -> Vec<BinaryCryptoHit> {
    let mut hits = Vec::new();
    let mut le_sig = Vec::with_capacity(SHA1_H.len() * 4);
    let mut be_sig = Vec::with_capacity(SHA1_H.len() * 4);
    for &h in &SHA1_H {
        le_sig.extend_from_slice(&h.to_le_bytes());
        be_sig.extend_from_slice(&h.to_be_bytes());
    }
    for (sig, sha1_name, rmd_name) in [
        (le_sig.as_slice(), "SHA1_H_LE", "RIPEMD160_H_LE"),
        (be_sig.as_slice(), "SHA1_H_BE", "RIPEMD160_H_BE"),
    ] {
        for offset in find_pattern(binary, sig) {
            hits.push(BinaryCryptoHit::new(
                "SHA-1",
                sha1_name,
                offset as u64,
                0.9,
                sig.len(),
            ));
            hits.push(BinaryCryptoHit::new(
                "RIPEMD-160",
                rmd_name,
                offset as u64,
                0.9,
                sig.len(),
            ));
        }
    }
    hits
}

// ── MD5 / MD4 init value scanner ─────────────────────────────────────────────

/// Search `binary` for the MD5 / MD4 initial hash values H0..H3 in both LE and BE byte orders.
///
/// The values `0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476` are shared between MD5 and
/// MD4, so both labels are emitted at each hit.
#[must_use]
pub fn scan_for_md5_init(binary: &[u8]) -> Vec<BinaryCryptoHit> {
    let mut hits = Vec::new();
    let mut le_sig = Vec::with_capacity(MD5_H.len() * 4);
    let mut be_sig = Vec::with_capacity(MD5_H.len() * 4);
    for &h in &MD5_H {
        le_sig.extend_from_slice(&h.to_le_bytes());
        be_sig.extend_from_slice(&h.to_be_bytes());
    }
    for (sig, endian_label) in [
        (le_sig.as_slice(), "LE"),
        (be_sig.as_slice(), "BE"),
    ] {
        for offset in find_pattern(binary, sig) {
            for algo in ["MD5", "MD4"] {
                hits.push(BinaryCryptoHit::new(
                    algo,
                    format!("{algo}_H_{endian_label}"),
                    offset as u64,
                    0.6,
                    sig.len(),
                ));
            }
        }
    }
    hits
}

// ── Blowfish P-array scanner ──────────────────────────────────────────────────

/// First 4 values of the Blowfish P-array (`pi` expansion).
pub const BLOWFISH_P_HEAD: [u32; 4] = [0x243F_6A88, 0x85A3_08D3, 0x1319_8A2E, 0x0370_7344];

/// Search `binary` for the first 4 Blowfish P-array values in both LE and BE byte orders.
#[must_use]
pub fn scan_for_blowfish_p(binary: &[u8]) -> Vec<BinaryCryptoHit> {
    let mut hits = Vec::new();
    let mut le_sig = Vec::with_capacity(BLOWFISH_P_HEAD.len() * 4);
    let mut be_sig = Vec::with_capacity(BLOWFISH_P_HEAD.len() * 4);
    for &p in &BLOWFISH_P_HEAD {
        le_sig.extend_from_slice(&p.to_le_bytes());
        be_sig.extend_from_slice(&p.to_be_bytes());
    }
    for (sig, name) in [
        (le_sig.as_slice(), "BLOWFISH_P_LE"),
        (be_sig.as_slice(), "BLOWFISH_P_BE"),
    ] {
        for offset in find_pattern(binary, sig) {
            hits.push(BinaryCryptoHit::new(
                "Blowfish",
                name,
                offset as u64,
                0.9,
                sig.len(),
            ));
        }
    }
    hits
}

// ── bcrypt magic scanner ──────────────────────────────────────────────────────

/// bcrypt magic string embedded in the `OrpheanBeholderScryDoubt` ciphertext.
pub const BCRYPT_MAGIC: &[u8] = b"OrpheanBeholderScryDoubt";

/// Search `binary` for the bcrypt magic string `OrpheanBeholderScryDoubt`.
#[must_use]
pub fn scan_for_bcrypt_magic(binary: &[u8]) -> Vec<BinaryCryptoHit> {
    let mut hits = Vec::new();
    for offset in find_pattern(binary, BCRYPT_MAGIC) {
        hits.push(BinaryCryptoHit::new(
            "bcrypt",
            "BCRYPT_MAGIC",
            offset as u64,
            1.0,
            BCRYPT_MAGIC.len(),
        ));
    }
    hits
}

// ── Camellia sigma scanner ────────────────────────────────────────────────────

/// Camellia key schedule sigma constants (6 u64 values).
pub const CAMELLIA_SIGMA_H: [u64; 6] = [
    0xa09e_667f_3bcc_908b,
    0xb67a_e858_4caa_73b2,
    0xc6ef_372f_e94f_82be,
    0x54ff_53a5_f1d3_6f1c,
    0x10e5_27fa_de68_2d1d,
    0xb056_88c2_b3e6_c1fd,
];

/// Search `binary` for Camellia sigma constants in both LE and BE byte orders.
#[must_use]
pub fn scan_for_camellia_sigma(binary: &[u8]) -> Vec<BinaryCryptoHit> {
    let mut hits = Vec::new();
    // Use first 4 values (32 bytes) as signature — distinctive enough.
    let sig_count = 4;
    let mut le_sig = Vec::with_capacity(sig_count * 8);
    let mut be_sig = Vec::with_capacity(sig_count * 8);
    for &s in &CAMELLIA_SIGMA_H[..sig_count] {
        le_sig.extend_from_slice(&s.to_le_bytes());
        be_sig.extend_from_slice(&s.to_be_bytes());
    }
    for (sig, name) in [
        (le_sig.as_slice(), "CAMELLIA_SIGMA_LE"),
        (be_sig.as_slice(), "CAMELLIA_SIGMA_BE"),
    ] {
        for offset in find_pattern(binary, sig) {
            hits.push(BinaryCryptoHit::new(
                "Camellia",
                name,
                offset as u64,
                0.9,
                sig.len(),
            ));
        }
    }
    hits
}

// ── DES S-box scanner ─────────────────────────────────────────────────────────

/// First 8 bytes of DES S-box 1 (used as a distinctive signature).
/// DES S1 starts with 14,4,13,1,2,15,11,8 which is non-zero and distinctive.
pub const DES_SBOX_S1_HEAD: [u8; 8] = [14, 4, 13, 1, 2, 15, 11, 8];

/// Search `binary` for the DES S-box S1 signature bytes.
#[must_use]
pub fn scan_for_des_sbox(binary: &[u8]) -> Vec<BinaryCryptoHit> {
    let mut hits = Vec::new();
    for offset in find_pattern(binary, &DES_SBOX_S1_HEAD) {
        hits.push(BinaryCryptoHit::new(
            "DES",
            "DES_SBOX_S1",
            offset as u64,
            0.6,
            DES_SBOX_S1_HEAD.len(),
        ));
    }
    hits
}

// ── Extra IDA-parity scanners ─────────────────────────────────────────────────

/// SHA-1 round constants K1-K4 (both big-endian and little-endian layouts).
/// K1=0x5A827999  K2=0x6ED9EBA1  K3=0x8F1BBCDC  K4=0xCA62C1D6
#[must_use]
pub fn scan_for_sha1_k_constants(binary: &[u8]) -> Vec<BinaryCryptoHit> {
    let mut hits = Vec::new();
    let sigs: &[(&str, [u8; 4])] = &[
        ("SHA1_K1_BE", [0x5A, 0x82, 0x79, 0x99]),
        ("SHA1_K2_BE", [0x6E, 0xD9, 0xEB, 0xA1]),
        ("SHA1_K3_BE", [0x8F, 0x1B, 0xBC, 0xDC]),
        ("SHA1_K4_BE", [0xCA, 0x62, 0xC1, 0xD6]),
        ("SHA1_K1_LE", [0x99, 0x79, 0x82, 0x5A]),
        ("SHA1_K2_LE", [0xA1, 0xEB, 0xD9, 0x6E]),
        ("SHA1_K3_LE", [0xDC, 0xBC, 0x1B, 0x8F]),
        ("SHA1_K4_LE", [0xD6, 0xC1, 0x62, 0xCA]),
    ];
    for (label, pattern) in sigs {
        for off in find_pattern(binary, pattern) {
            hits.push(BinaryCryptoHit::new("SHA-1", *label, off as u64, 0.8, 4));
        }
    }
    hits
}

/// Rijndael key-schedule Rcon table (first 11 bytes).
/// 0x8D 0x01 0x02 0x04 0x08 0x10 0x20 0x40 0x80 0x1B 0x36
pub const RIJNDAEL_RCON: [u8; 11] = [
    0x8D, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36,
];

#[must_use]
pub fn scan_for_rijndael_rcon(binary: &[u8]) -> Vec<BinaryCryptoHit> {
    let mut hits = Vec::new();
    for off in find_pattern(binary, &RIJNDAEL_RCON) {
        hits.push(BinaryCryptoHit::new("AES/Rijndael", "RCON_TABLE", off as u64, 0.9, RIJNDAEL_RCON.len()));
    }
    hits
}

/// Blowfish S-box 0 first 8 bytes (well-known initialisation from pi digits).
pub const BLOWFISH_S0_HEAD: [u8; 8] = [0xD1, 0x31, 0x0B, 0xA6, 0x98, 0xDF, 0xB5, 0xAC];

#[must_use]
pub fn scan_for_blowfish_sboxes(binary: &[u8]) -> Vec<BinaryCryptoHit> {
    let mut hits = Vec::new();
    for off in find_pattern(binary, &BLOWFISH_S0_HEAD) {
        hits.push(BinaryCryptoHit::new("Blowfish", "SBOX_S0", off as u64, 0.9, BLOWFISH_S0_HEAD.len()));
    }
    // S-box 1 head
    let s1_head: [u8; 8] = [0x2A, 0x4E, 0xB5, 0x7C, 0x34, 0x39, 0x73, 0x7A];
    for off in find_pattern(binary, &s1_head) {
        hits.push(BinaryCryptoHit::new("Blowfish", "SBOX_S1", off as u64, 0.85, 8));
    }
    // S-box 2 head
    let s2_head: [u8; 8] = [0xB3, 0xAA, 0x9B, 0x16, 0xA8, 0x93, 0x9C, 0xBF];
    for off in find_pattern(binary, &s2_head) {
        hits.push(BinaryCryptoHit::new("Blowfish", "SBOX_S2", off as u64, 0.85, 8));
    }
    // S-box 3 head
    let s3_head: [u8; 8] = [0xE6, 0xDB, 0x14, 0x8A, 0x4E, 0x54, 0x62, 0xBE];
    for off in find_pattern(binary, &s3_head) {
        hits.push(BinaryCryptoHit::new("Blowfish", "SBOX_S3", off as u64, 0.85, 8));
    }
    hits
}

/// GOST 28147-89 default S-box (CryptoPro variant) — first 8 nibble pairs.
/// Row 0: 4,10,9,2,13,8,0,14,6,11,1,12,7,15,5,3
/// Packed as bytes (each row stored as nibble pairs): first 4 bytes of row 0.
pub const GOST_SBOX_HEAD: [u8; 8] = [0xA4, 0x92, 0xD8, 0xE6, 0xCB, 0x21, 0xF7, 0x35];

#[must_use]
pub fn scan_for_gost_sbox(binary: &[u8]) -> Vec<BinaryCryptoHit> {
    let mut hits = Vec::new();
    for off in find_pattern(binary, &GOST_SBOX_HEAD) {
        hits.push(BinaryCryptoHit::new("GOST", "SBOX_CRYPTOPRO", off as u64, 0.75, GOST_SBOX_HEAD.len()));
    }
    // Id-Gost-R3411-94-CryptoProParamSet S-box alternative layout
    let alt_head: [u8; 8] = [0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88];
    for off in find_pattern(binary, &alt_head) {
        hits.push(BinaryCryptoHit::new("GOST", "SBOX_ALT", off as u64, 0.6, 8));
    }
    hits
}

/// secp256r1 (NIST P-256) curve parameter b (little-endian).
/// b = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
const SECP256R1_B_LE: [u8; 16] = [
    0x4b, 0x60, 0xd2, 0x27, 0x3e, 0x3c, 0xce, 0x3b,
    0xf6, 0xb0, 0x53, 0xcc, 0xb0, 0x06, 0x1d, 0x65,
];

#[must_use]
pub fn scan_for_ecc_params(binary: &[u8]) -> Vec<BinaryCryptoHit> {
    let mut hits = Vec::new();
    for off in find_pattern(binary, &SECP256R1_B_LE) {
        hits.push(BinaryCryptoHit::new("ECC/secp256r1", "CURVE_B_LE", off as u64, 0.9, SECP256R1_B_LE.len()));
    }
    // secp256r1 Gx (big-endian first 8 bytes)
    let gx_be_head: [u8; 8] = [0x6B, 0x17, 0xD1, 0xF2, 0xE1, 0x2C, 0x42, 0x47];
    for off in find_pattern(binary, &gx_be_head) {
        hits.push(BinaryCryptoHit::new("ECC/secp256r1", "BASE_POINT_GX", off as u64, 0.9, 8));
    }
    hits
}

/// Scan `binary` for all known cryptographic constants.
///
/// Returns a `Vec<BinaryCryptoHit>` sorted by offset, deduplicated at the
/// same offset when the same algorithm is found.
#[must_use]
pub fn scan_binary_for_crypto_constants(binary: &[u8]) -> Vec<BinaryCryptoHit> {
    let mut all: Vec<BinaryCryptoHit> = Vec::new();
    all.extend(scan_for_aes_sbox(binary));
    all.extend(scan_for_sha256_init(binary));
    all.extend(scan_for_sha256_constants(binary));
    all.extend(scan_for_crc32_table(binary));
    all.extend(scan_for_chacha_magic(binary));
    all.extend(scan_for_md5_constants(binary));
    all.extend(scan_for_tea_delta(binary));
    all.extend(scan_for_sha512_init(binary));
    all.extend(scan_for_sha1_init(binary));
    all.extend(scan_for_md5_init(binary));
    all.extend(scan_for_blowfish_p(binary));
    all.extend(scan_for_bcrypt_magic(binary));
    all.extend(scan_for_camellia_sigma(binary));
    all.extend(scan_for_des_sbox(binary));
    all.extend(scan_for_extended_constants(binary));
    all.extend(scan_for_sha1_k_constants(binary));
    all.extend(scan_for_rijndael_rcon(binary));
    all.extend(scan_for_blowfish_sboxes(binary));
    all.extend(scan_for_gost_sbox(binary));
    all.extend(scan_for_ecc_params(binary));
    // Sort by offset, then by descending confidence for deduplication.
    all.sort_by(|a, b| {
        a.offset.cmp(&b.offset).then(
            b.confidence
                .partial_cmp(&a.confidence)
                .unwrap_or(std::cmp::Ordering::Equal),
        )
    });
    all
}

/// Scan for the extended IDA-parity constant set: PEM/DER markers,
/// OpenSSL/libsodium string constants, TLS handshake markers, FNV/xxHash
/// primes, curve primes, hash init constants, Poly1305 clamp, GHASH R, etc.
#[must_use]
pub fn scan_for_extended_constants(binary: &[u8]) -> Vec<BinaryCryptoHit> {
    let mut hits = Vec::new();

    // Byte-string signatures scanned with a lightweight substring search.
    let string_sigs: &[(&str, &str, &[u8], f64)] = &[
        ("PEM",             "BEGIN_MARKER",     b"-----BEGIN",                        0.9),
        ("X.509",           "PEM_CERTIFICATE",  b"BEGIN CERTIFICATE",                 0.95),
        ("RSA",             "PEM_PRIVATE_KEY",  b"BEGIN RSA PRIVATE KEY",             0.95),
        ("OpenSSH",         "RSA_KEY_TYPE",     b"ssh-rsa",                           0.85),
        ("OpenSSH",         "ED25519_KEY_TYPE", b"ssh-ed25519",                       0.85),
        ("OpenSSL",         "LIBRARY_NAME",     b"OpenSSL",                           0.7),
        ("libsodium",       "LIBRARY_NAME",     b"libsodium",                         0.85),
        ("Win-CNG",         "BCryptGenRandom",  b"BCryptGenRandom",                   0.9),
        ("Win-CryptoAPI",   "CryptAcquireCtx",  b"CryptAcquireContext",               0.9),
        ("TLS",             "SSLKEYLOGFILE",    b"CLIENT_RANDOM ",                    0.9),
        ("PBKDF2",          "IDENTIFIER",       b"PBKDF2",                            0.85),
        ("Noise",           "PROTOCOL_STRING",  b"Noise_",                            0.7),
        ("bcrypt",          "$2a$_MAGIC",       b"$2a$",                              0.9),
        ("bcrypt",          "$2b$_MAGIC",       b"$2b$",                              0.9),
        ("bcrypt",          "$2y$_MAGIC",       b"$2y$",                              0.9),
        ("Argon2",          "IDENTIFIER",       b"argon2",                            0.85),
        ("Salsa20/ChaCha20","SIGMA_STR",        b"expand 32-byte k",                  0.98),
        ("Salsa20/ChaCha20","TAU_STR",          b"expand 16-byte k",                  0.98),
    ];
    for (algo, label, needle, conf) in string_sigs {
        for off in find_pattern(binary, needle) {
            hits.push(BinaryCryptoHit::new(*algo, *label, off as u64, *conf, needle.len()));
        }
    }

    // Numeric little-endian signatures.
    let le_sigs: &[(&str, &str, &[u8], f64)] = &[
        ("FNV",             "OFFSET_32",        &[0xC5, 0x9D, 0x1C, 0x81],            0.7),
        ("FNV",             "PRIME_32",         &[0x93, 0x01, 0x00, 0x01],            0.65),
        // FNV-1a 64-bit offset basis = 0xCBF29CE484222325 (LE)
        ("FNV",             "OFFSET_64",        &[0x25,0x23,0x22,0x84,0xE4,0x9C,0xF2,0xCB], 0.85),
        // FNV-1 64-bit prime = 0x00000100000001B3 (LE)
        ("FNV",             "PRIME_64",         &[0xB3,0x01,0x00,0x00,0x00,0x01,0x00,0x00], 0.75),
        ("xxHash32",        "PRIME1",           &[0xB1, 0x79, 0x82, 0x9E],            0.7),
        ("xxHash32",        "PRIME2",           &[0x77, 0xCA, 0x4A, 0x85],            0.7),
        ("MurmurHash3",     "C1",               &[0x51, 0x2D, 0x9E, 0xCC],            0.7),
        ("MurmurHash3",     "C2",               &[0x93, 0x35, 0x87, 0x1B],            0.7),
        // CityHash64 K0 = 0xC3A5C85C97CB3127 (LE)
        ("CityHash",        "K0",               &[0x27,0x31,0xCB,0x97,0x5C,0xC8,0xA5,0xC3], 0.8),
        // Adler-32 MOD (2-byte) and IDEA MOD 65537 (4-byte) removed:
        // too common in random binary data to be useful without context.
        ("RC5/RC6",         "P32_MAGIC",        &[0x63, 0x51, 0xE1, 0xB7],            0.85),
        ("Mersenne-Twister","INIT_MULT",        &[0x65, 0x89, 0x07, 0x6C],            0.75),
        ("GCM/GHASH",       "R_POLY",           &[0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xE1], 0.6),
        ("CRC32C",          "CASTAGNOLI_POLY",  &[0x78, 0x3B, 0xF6, 0x82],            0.85),
    ];
    for (algo, label, needle, conf) in le_sigs {
        for off in find_pattern(binary, needle) {
            hits.push(BinaryCryptoHit::new(*algo, *label, off as u64, *conf, needle.len()));
        }
    }

    // Poly1305 clamp mask (16 bytes).
    const POLY1305_CLAMP: [u8; 16] = [
        0xff,0xff,0xff,0x0f,0xfc,0xff,0xff,0x0f,0xfc,0xff,0xff,0x0f,0xfc,0xff,0xff,0x0f,
    ];
    for off in find_pattern(binary, &POLY1305_CLAMP) {
        hits.push(BinaryCryptoHit::new("Poly1305", "CLAMP_MASK", off as u64, 0.95, 16));
    }

    // MD4 init value.
    const MD4_INIT: [u8; 16] = [
        0x01,0x23,0x45,0x67, 0x89,0xab,0xcd,0xef, 0xfe,0xdc,0xba,0x98, 0x76,0x54,0x32,0x10,
    ];
    for off in find_pattern(binary, &MD4_INIT) {
        hits.push(BinaryCryptoHit::new("MD4", "INIT", off as u64, 0.9, 16));
    }

    hits
}

/// Aggregate summary of a binary crypto scan grouped by algorithm.
#[derive(Debug, Clone)]
pub struct CryptoScanSummary {
    pub total_hits: usize,
    pub per_algorithm: std::collections::BTreeMap<String, usize>,
    pub hits: Vec<BinaryCryptoHit>,
}

/// One-shot scan returning both the full hit list and a per-algorithm
/// summary suitable for triage pipelines that just want a count.
#[must_use]
pub fn scan_and_summarize(binary: &[u8]) -> CryptoScanSummary {
    let hits = scan_binary_for_crypto_constants(binary);
    let mut per_algorithm = std::collections::BTreeMap::new();
    for h in &hits {
        *per_algorithm.entry(h.algorithm.clone()).or_insert(0) += 1;
    }
    CryptoScanSummary {
        total_hits: hits.len(),
        per_algorithm,
        hits,
    }
}

// =============================================================================
// Unit tests — binary crypto-constant scanner
// =============================================================================

#[cfg(test)]
mod binary_crypto_scan_tests {
    use super::*;

    #[test]
    fn detect_aes_sbox_embedded() {
        let mut data = vec![0u8; 64];
        data.extend_from_slice(&AES_SBOX);
        data.extend_from_slice(&[0u8; 32]);
        let hits = scan_for_aes_sbox(&data);
        assert!(!hits.is_empty(), "should detect AES_SBOX");
        let h = &hits[0];
        assert_eq!(h.algorithm, "AES");
        assert_eq!(h.offset, 64);
        assert!(
            (h.confidence - 1.0).abs() < 0.01,
            "full confidence expected"
        );
    }

    #[test]
    fn detect_aes_inv_sbox_embedded() {
        let mut data = vec![0u8; 32];
        data.extend_from_slice(&AES_INV_SBOX);
        let hits = scan_for_aes_sbox(&data);
        let inv_hit = hits.iter().find(|h| h.constant_name == "AES_INV_SBOX");
        assert!(inv_hit.is_some(), "should detect AES_INV_SBOX");
    }

    #[test]
    fn detect_sha256_k_le() {
        let mut data = vec![0xffu8; 16];
        for &k in &SHA256_K {
            data.extend_from_slice(&k.to_le_bytes());
        }
        let hits = scan_for_sha256_constants(&data);
        assert!(!hits.is_empty());
        let h = hits
            .iter()
            .find(|h| h.constant_name == "SHA256_K_LE")
            .unwrap();
        assert!((h.confidence - 1.0).abs() < 0.01);
    }

    #[test]
    fn detect_sha256_k_be() {
        let mut data = vec![0u8; 8];
        for &k in &SHA256_K {
            data.extend_from_slice(&k.to_be_bytes());
        }
        let hits = scan_for_sha256_constants(&data);
        let h = hits.iter().find(|h| h.constant_name == "SHA256_K_BE");
        assert!(h.is_some(), "should detect SHA256_K_BE");
    }

    #[test]
    fn detect_crc32_table() {
        // Embed the distinctive portion (entries 1-5) in a larger buffer.
        let mut data = vec![0u8; 20];
        // Write entry 0 first.
        data.extend_from_slice(&CRC32_TABLE[0].to_le_bytes());
        for &e in &CRC32_TABLE[1..32] {
            data.extend_from_slice(&e.to_le_bytes());
        }
        let hits = scan_for_crc32_table(&data);
        assert!(!hits.is_empty(), "should detect CRC32_TABLE");
    }

    #[test]
    fn detect_chacha20_magic() {
        let mut data = b"some garbage here ".to_vec();
        data.extend_from_slice(&CHACHA20_MAGIC);
        data.extend_from_slice(b" more stuff");
        let hits = scan_for_chacha_magic(&data);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].offset, 18);
        assert!((hits[0].confidence - 1.0).abs() < 0.001);
    }

    #[test]
    fn detect_md5_constants_le() {
        let mut data = vec![0u8; 12];
        for &t in &MD5_T {
            data.extend_from_slice(&t.to_le_bytes());
        }
        let hits = scan_for_md5_constants(&data);
        assert!(!hits.is_empty());
        let h = hits.iter().find(|h| h.constant_name == "MD5_T_LE").unwrap();
        assert!((h.confidence - 1.0).abs() < 0.01);
    }

    #[test]
    fn scan_all_returns_sorted() {
        let mut data = vec![0u8; 32];
        data.extend_from_slice(&AES_SBOX);
        let hits = scan_binary_for_crypto_constants(&data);
        for w in hits.windows(2) {
            assert!(
                w[0].offset <= w[1].offset,
                "results should be sorted by offset"
            );
        }
    }

    #[test]
    fn no_false_positive_on_zeros() {
        let data = vec![0u8; 512];
        let hits = scan_binary_for_crypto_constants(&data);
        assert!(hits.is_empty(), "should not trigger on all-zero data");
    }

    #[test]
    fn hit_confidence_clamped() {
        let mut data = vec![0u8; 8];
        data.extend_from_slice(&AES_SBOX);
        let hits = scan_for_aes_sbox(&data);
        for h in &hits {
            assert!(h.confidence >= 0.0 && h.confidence <= 1.0);
        }
    }

    #[test]
    fn find_pattern_empty_needle() {
        let result = find_pattern(b"hello world", b"");
        assert!(result.is_empty());
    }

    #[test]
    fn find_pattern_multiple_occurrences() {
        let hay = b"abcabcabc";
        let needle = b"abc";
        let offsets = find_pattern(hay, needle);
        assert_eq!(offsets.len(), 3);
        assert_eq!(offsets, vec![0, 3, 6]);
    }

    #[test]
    fn detect_sha512_init_le() {
        let mut data = vec![0xffu8; 16];
        for &h in &SHA512_H {
            data.extend_from_slice(&h.to_le_bytes());
        }
        let hits = scan_for_sha512_init(&data);
        assert!(hits.iter().any(|h| h.constant_name == "SHA512_H_LE"), "should detect SHA512_H_LE");
    }

    #[test]
    fn detect_sha512_init_be() {
        let mut data = vec![0u8; 8];
        for &h in &SHA512_H {
            data.extend_from_slice(&h.to_be_bytes());
        }
        let hits = scan_for_sha512_init(&data);
        assert!(hits.iter().any(|h| h.constant_name == "SHA512_H_BE"), "should detect SHA512_H_BE");
    }

    #[test]
    fn detect_sha1_init_le() {
        let mut data = vec![0xffu8; 8];
        for &h in &SHA1_H {
            data.extend_from_slice(&h.to_le_bytes());
        }
        let hits = scan_for_sha1_init(&data);
        assert!(hits.iter().any(|h| h.algorithm == "SHA-1"), "should detect SHA-1 init");
        assert!(hits.iter().any(|h| h.algorithm == "RIPEMD-160"), "should also label RIPEMD-160");
    }

    #[test]
    fn detect_md5_init_le() {
        let mut data = vec![0xffu8; 8];
        for &h in &MD5_H {
            data.extend_from_slice(&h.to_le_bytes());
        }
        let hits = scan_for_md5_init(&data);
        assert!(hits.iter().any(|h| h.algorithm == "MD5"), "should detect MD5 init");
        assert!(hits.iter().any(|h| h.algorithm == "MD4"), "should also label MD4");
    }

    #[test]
    fn detect_blowfish_p_be() {
        let mut data = vec![0u8; 8];
        for &p in &BLOWFISH_P_HEAD {
            data.extend_from_slice(&p.to_be_bytes());
        }
        let hits = scan_for_blowfish_p(&data);
        assert!(hits.iter().any(|h| h.algorithm == "Blowfish"), "should detect Blowfish P-array");
    }

    #[test]
    fn detect_bcrypt_magic() {
        let mut data = b"garbage_prefix_".to_vec();
        data.extend_from_slice(BCRYPT_MAGIC);
        data.extend_from_slice(b"_suffix");
        let hits = scan_for_bcrypt_magic(&data);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].algorithm, "bcrypt");
    }

    #[test]
    fn detect_camellia_sigma_be() {
        let mut data = vec![0u8; 8];
        for &s in &CAMELLIA_SIGMA_H[..4] {
            data.extend_from_slice(&s.to_be_bytes());
        }
        let hits = scan_for_camellia_sigma(&data);
        assert!(hits.iter().any(|h| h.algorithm == "Camellia"), "should detect Camellia sigma");
    }

    #[test]
    fn detect_des_sbox_s1() {
        let mut data = vec![0xffu8; 4];
        data.extend_from_slice(&DES_SBOX_S1_HEAD);
        data.extend_from_slice(&[0u8; 4]);
        let hits = scan_for_des_sbox(&data);
        assert!(hits.iter().any(|h| h.algorithm == "DES"), "should detect DES S-box");
    }
}
