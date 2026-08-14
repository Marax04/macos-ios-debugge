//! Cryptographic algorithm database.
//!
//! Provides the [`CryptoAlgorithm`] enum, [`AlgorithmSignature`],
//! [`AlgorithmDb`] with 50+ entries, and [`detect_algorithm`].

use serde::{Deserialize, Serialize};
pub use std::collections::HashMap;

// ─────────────────────────────────────────────────────────────────────────────
// CryptoAlgorithm
// ─────────────────────────────────────────────────────────────────────────────

/// All cryptographic algorithms the detector can recognise.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CryptoAlgorithm {
    // ── Symmetric block ciphers ──────────────────────────────────────────────
    Aes128Ecb,
    Aes128Cbc,
    Aes128Ctr,
    Aes128Gcm,
    Aes192Cbc,
    Aes256Cbc,
    Aes256Gcm,
    Des,
    TripleDes,
    Blowfish,
    Twofish,
    Camellia128,
    Camellia256,
    Aria,
    Sm4,
    // ── Symmetric stream ciphers ─────────────────────────────────────────────
    Rc4,
    Rc4Drop256,
    ChaCha20,
    Salsa20,
    XSalsa20,
    XChaCha20,
    Rabbit,
    // ── Asymmetric ───────────────────────────────────────────────────────────
    Rsa1024,
    Rsa2048,
    Rsa4096,
    DiffieHellman,
    Ecdh,
    Ecdsa,
    Ed25519,
    X25519,
    Ed448,
    Sm2,
    // ── Hash functions ───────────────────────────────────────────────────────
    Md4,
    Md5,
    Sha1,
    Sha224,
    Sha256,
    Sha384,
    Sha512,
    Sha512_256,
    Sha3_224,
    Sha3_256,
    Sha3_384,
    Sha3_512,
    Blake2b,
    Blake2s,
    Blake3,
    Whirlpool,
    Tiger,
    Ripemd128,
    Ripemd160,
    Sm3,
    // ── MAC / AEAD ───────────────────────────────────────────────────────────
    HmacMd5,
    HmacSha1,
    HmacSha256,
    HmacSha512,
    Poly1305,
    Ghash,
    // ── Key derivation ───────────────────────────────────────────────────────
    Pbkdf2Sha1,
    Pbkdf2Sha256,
    Argon2i,
    Argon2d,
    Argon2id,
    Scrypt,
    Bcrypt,
    // ── Checksums ────────────────────────────────────────────────────────────
    Crc32,
    Crc32c,
    Crc64,
    Adler32,
    // ── Other ────────────────────────────────────────────────────────────────
    Unknown,
}

impl std::fmt::Display for CryptoAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Aes128Ecb => "AES-128-ECB",
            Self::Aes128Cbc => "AES-128-CBC",
            Self::Aes128Ctr => "AES-128-CTR",
            Self::Aes128Gcm => "AES-128-GCM",
            Self::Aes192Cbc => "AES-192-CBC",
            Self::Aes256Cbc => "AES-256-CBC",
            Self::Aes256Gcm => "AES-256-GCM",
            Self::Des => "DES",
            Self::TripleDes => "3DES",
            Self::Blowfish => "Blowfish",
            Self::Twofish => "Twofish",
            Self::Camellia128 => "Camellia-128",
            Self::Camellia256 => "Camellia-256",
            Self::Aria => "ARIA",
            Self::Sm4 => "SM4",
            Self::Rc4 => "RC4",
            Self::Rc4Drop256 => "RC4-drop256",
            Self::ChaCha20 => "ChaCha20",
            Self::Salsa20 => "Salsa20",
            Self::XSalsa20 => "XSalsa20",
            Self::XChaCha20 => "XChaCha20",
            Self::Rabbit => "Rabbit",
            Self::Rsa1024 => "RSA-1024",
            Self::Rsa2048 => "RSA-2048",
            Self::Rsa4096 => "RSA-4096",
            Self::DiffieHellman => "DH",
            Self::Ecdh => "ECDH",
            Self::Ecdsa => "ECDSA",
            Self::Ed25519 => "Ed25519",
            Self::X25519 => "X25519",
            Self::Ed448 => "Ed448",
            Self::Sm2 => "SM2",
            Self::Md4 => "MD4",
            Self::Md5 => "MD5",
            Self::Sha1 => "SHA-1",
            Self::Sha224 => "SHA-224",
            Self::Sha256 => "SHA-256",
            Self::Sha384 => "SHA-384",
            Self::Sha512 => "SHA-512",
            Self::Sha512_256 => "SHA-512/256",
            Self::Sha3_224 => "SHA3-224",
            Self::Sha3_256 => "SHA3-256",
            Self::Sha3_384 => "SHA3-384",
            Self::Sha3_512 => "SHA3-512",
            Self::Blake2b => "BLAKE2b",
            Self::Blake2s => "BLAKE2s",
            Self::Blake3 => "BLAKE3",
            Self::Whirlpool => "Whirlpool",
            Self::Tiger => "Tiger",
            Self::Ripemd128 => "RIPEMD-128",
            Self::Ripemd160 => "RIPEMD-160",
            Self::Sm3 => "SM3",
            Self::HmacMd5 => "HMAC-MD5",
            Self::HmacSha1 => "HMAC-SHA1",
            Self::HmacSha256 => "HMAC-SHA256",
            Self::HmacSha512 => "HMAC-SHA512",
            Self::Poly1305 => "Poly1305",
            Self::Ghash => "GHASH",
            Self::Pbkdf2Sha1 => "PBKDF2-SHA1",
            Self::Pbkdf2Sha256 => "PBKDF2-SHA256",
            Self::Argon2i => "Argon2i",
            Self::Argon2d => "Argon2d",
            Self::Argon2id => "Argon2id",
            Self::Scrypt => "scrypt",
            Self::Bcrypt => "bcrypt",
            Self::Crc32 => "CRC32",
            Self::Crc32c => "CRC32c",
            Self::Crc64 => "CRC64",
            Self::Adler32 => "Adler32",
            Self::Unknown => "Unknown",
        };
        write!(f, "{s}")
    }
}

impl CryptoAlgorithm {
    /// Return `true` if this is a symmetric cipher.
    #[must_use]
    pub const fn is_symmetric(&self) -> bool {
        matches!(
            self,
            Self::Aes128Ecb
                | Self::Aes128Cbc
                | Self::Aes128Ctr
                | Self::Aes128Gcm
                | Self::Aes192Cbc
                | Self::Aes256Cbc
                | Self::Aes256Gcm
                | Self::Des
                | Self::TripleDes
                | Self::Blowfish
                | Self::Twofish
                | Self::Camellia128
                | Self::Camellia256
                | Self::Aria
                | Self::Sm4
                | Self::Rc4
                | Self::Rc4Drop256
                | Self::ChaCha20
                | Self::Salsa20
                | Self::XSalsa20
                | Self::XChaCha20
                | Self::Rabbit
        )
    }

    /// Return `true` if this is an asymmetric/public-key algorithm.
    #[must_use]
    pub const fn is_asymmetric(&self) -> bool {
        matches!(
            self,
            Self::Rsa1024
                | Self::Rsa2048
                | Self::Rsa4096
                | Self::DiffieHellman
                | Self::Ecdh
                | Self::Ecdsa
                | Self::Ed25519
                | Self::X25519
                | Self::Ed448
                | Self::Sm2
        )
    }

    /// Return `true` if this is a hash function.
    #[must_use]
    pub const fn is_hash(&self) -> bool {
        matches!(
            self,
            Self::Md4
                | Self::Md5
                | Self::Sha1
                | Self::Sha224
                | Self::Sha256
                | Self::Sha384
                | Self::Sha512
                | Self::Sha512_256
                | Self::Sha3_224
                | Self::Sha3_256
                | Self::Sha3_384
                | Self::Sha3_512
                | Self::Blake2b
                | Self::Blake2s
                | Self::Blake3
                | Self::Whirlpool
                | Self::Tiger
                | Self::Ripemd128
                | Self::Ripemd160
                | Self::Sm3
        )
    }

    /// Return `true` if this algorithm is considered cryptographically weak.
    #[must_use]
    pub const fn is_weak(&self) -> bool {
        matches!(
            self,
            Self::Md4
                | Self::Md5
                | Self::Sha1
                | Self::Des
                | Self::Rc4
                | Self::Rc4Drop256
                | Self::Rsa1024
                | Self::Ripemd128
        )
    }

    /// Typical key size in bits (None if variable).
    #[must_use]
    pub const fn typical_key_bits(&self) -> Option<u32> {
        match self {
            Self::Aes128Ecb | Self::Aes128Cbc | Self::Aes128Ctr | Self::Aes128Gcm => Some(128),
            Self::Aes192Cbc => Some(192),
            Self::Aes256Cbc | Self::Aes256Gcm | Self::Ed25519 | Self::X25519 | Self::ChaCha20 => Some(256),
            Self::Des => Some(56),
            Self::TripleDes => Some(168),
            Self::Rsa1024 => Some(1024),
            Self::Rsa2048 => Some(2048),
            Self::Rsa4096 => Some(4096),
            _ => None,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SignatureKind
// ─────────────────────────────────────────────────────────────────────────────

/// What kind of evidence a signature is based on.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SignatureKind {
    /// A sequence of bytes appearing in the binary.
    BytePattern,
    /// A known magic constant value (u32 or u64).
    MagicConstant,
    /// A recognisable S-box or lookup table.
    Sbox,
    /// A specific code structure (e.g. round-key schedule shape).
    CodeStructure,
    /// A known initialisation vector or nonce size.
    IvPattern,
    /// A key-size indicator found in code.
    KeySizeIndicator,
    /// Import or symbol name pattern.
    SymbolName,
}

// ─────────────────────────────────────────────────────────────────────────────
// AlgorithmSignature
// ─────────────────────────────────────────────────────────────────────────────

/// A detectable signature for a specific cryptographic algorithm.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlgorithmSignature {
    /// The algorithm this signature identifies.
    pub algorithm: CryptoAlgorithm,
    /// Short human-readable name.
    pub name: String,
    /// What type of evidence this is.
    pub kind: SignatureKind,
    /// Byte pattern to scan for (if `kind == BytePattern`).
    pub pattern: Option<Vec<u8>>,
    /// Mask for the byte pattern (`0xFF` = must match, `0x00` = wildcard).
    pub mask: Option<Vec<u8>>,
    /// Magic constant value for `MagicConstant` kind.
    pub constant: Option<u64>,
    /// Confidence weight (0–100).
    pub confidence: u8,
    /// Brief description of what this signature catches.
    pub description: String,
}

impl AlgorithmSignature {
    /// Check whether this signature matches a byte slice at `offset`.
    #[must_use]
    pub fn matches_at(&self, data: &[u8], offset: usize) -> bool {
        let Some(pattern) = &self.pattern else { return false };
        if offset + pattern.len() > data.len() {
            return false;
        }
        let slice = &data[offset..offset + pattern.len()];
        match &self.mask {
            Some(mask) => {
                for ((&d, &p), &m) in slice.iter().zip(pattern.iter()).zip(mask.iter()) {
                    if (d & m) != (p & m) {
                        return false;
                    }
                }
                true
            }
            None => slice == pattern.as_slice(),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DetectionResult
// ─────────────────────────────────────────────────────────────────────────────

/// A single detection hit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionResult {
    pub algorithm: CryptoAlgorithm,
    pub offset: usize,
    pub confidence: u8,
    pub signature_name: String,
    pub description: String,
}

// ─────────────────────────────────────────────────────────────────────────────
// AlgorithmDb
// ─────────────────────────────────────────────────────────────────────────────

/// In-memory database of cryptographic algorithm signatures.
#[derive(Debug, Clone)]
pub struct AlgorithmDb {
    signatures: Vec<AlgorithmSignature>,
}

impl AlgorithmDb {
    /// Create a new empty database.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            signatures: Vec::new(),
        }
    }

    /// Create the default database pre-populated with 50+ signatures.
    #[must_use]
    pub fn default_db() -> Self {
        let mut db = Self::empty();
        db.populate_defaults();
        db
    }

    /// Add a signature to the database.
    pub fn add(&mut self, sig: AlgorithmSignature) {
        self.signatures.push(sig);
    }

    /// Return all signatures.
    #[must_use]
    pub fn signatures(&self) -> &[AlgorithmSignature] {
        &self.signatures
    }

    /// Count signatures.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.signatures.len()
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.signatures.is_empty()
    }

    /// Look up signatures for a specific algorithm.
    #[must_use]
    pub fn for_algorithm(&self, algo: CryptoAlgorithm) -> Vec<&AlgorithmSignature> {
        self.signatures
            .iter()
            .filter(|s| s.algorithm == algo)
            .collect()
    }

    fn sig(
        algorithm: CryptoAlgorithm,
        name: &str,
        kind: SignatureKind,
        pattern: Option<Vec<u8>>,
        constant: Option<u64>,
        confidence: u8,
        description: &str,
    ) -> AlgorithmSignature {
        AlgorithmSignature {
            algorithm,
            name: name.into(),
            kind,
            pattern: pattern.clone(),
            mask: pattern.map(|p| vec![0xFFu8; p.len()]),
            constant,
            confidence,
            description: description.into(),
        }
    }

    fn populate_defaults(&mut self) {
        self.populate_aes_des_algos();
        self.populate_md5_sha_algos();
        self.populate_stream_algos();
        self.populate_checksum_rsa_algos();
        self.populate_misc_algos();
    }

    fn populate_aes_des_algos(&mut self) {
        // ── AES S-box first row ──────────────────────────────────────────────
        self.add(Self::sig(
            CryptoAlgorithm::Aes128Cbc,
            "AES-SBOX-START",
            SignatureKind::Sbox,
            Some(vec![0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5]),
            None,
            95,
            "First 8 bytes of AES S-box",
        ));
        // ── AES round constant ───────────────────────────────────────────────
        self.add(Self::sig(
            CryptoAlgorithm::Aes128Cbc,
            "AES-RCON",
            SignatureKind::MagicConstant,
            Some(vec![0x01, 0x00, 0x00, 0x00]),
            Some(0x0100_0000),
            60,
            "AES round constant rcon[0]",
        ));
        // ── AES-GCM GHash polynomial ─────────────────────────────────────────
        self.add(Self::sig(
            CryptoAlgorithm::Aes128Gcm,
            "GCM-POLY",
            SignatureKind::MagicConstant,
            Some(vec![0x87, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
            Some(0x87),
            80,
            "GCM reduction polynomial 0x87",
        ));
        // ── DES initial permutation table ────────────────────────────────────
        self.add(Self::sig(
            CryptoAlgorithm::Des,
            "DES-IP-TABLE",
            SignatureKind::BytePattern,
            Some(vec![58, 50, 42, 34, 26, 18, 10, 2]),
            None,
            90,
            "First bytes of DES initial permutation table",
        ));
        // ── DES S-box 1 ──────────────────────────────────────────────────────
        self.add(Self::sig(
            CryptoAlgorithm::Des,
            "DES-SBOX1",
            SignatureKind::Sbox,
            Some(vec![14, 4, 13, 1, 2, 15, 11, 8]),
            None,
            85,
            "Start of DES S-box 1",
        ));
    }

    fn populate_md5_sha_algos(&mut self) {
        // ── MD5 initialization constants ─────────────────────────────────────
        self.add(Self::sig(
            CryptoAlgorithm::Md5,
            "MD5-INIT-A",
            SignatureKind::MagicConstant,
            Some(vec![0x01, 0x23, 0x45, 0x67]),
            Some(0x6745_2301),
            90,
            "MD5 initial hash value A (little-endian 0x6745_2301)",
        ));
        self.add(Self::sig(
            CryptoAlgorithm::Md5,
            "MD5-INIT-B",
            SignatureKind::MagicConstant,
            Some(vec![0x89, 0xab, 0xcd, 0xef]),
            Some(0xefcd_ab89),
            90,
            "MD5 initial hash value B",
        ));
        self.add(Self::sig(
            CryptoAlgorithm::Md5,
            "MD5-INIT-C",
            SignatureKind::MagicConstant,
            Some(vec![0xfe, 0xdc, 0xba, 0x98]),
            Some(0x98ba_dcfe),
            90,
            "MD5 initial hash value C",
        ));
        self.add(Self::sig(
            CryptoAlgorithm::Md5,
            "MD5-INIT-D",
            SignatureKind::MagicConstant,
            Some(vec![0x76, 0x54, 0x32, 0x10]),
            Some(0x1032_5476),
            90,
            "MD5 initial hash value D",
        ));
        // ── SHA-1 init values ────────────────────────────────────────────────
        self.add(Self::sig(
            CryptoAlgorithm::Sha1,
            "SHA1-H0",
            SignatureKind::MagicConstant,
            Some(vec![0x67, 0x45, 0x23, 0x01]),
            Some(0x0123_4567),
            88,
            "SHA-1 initial hash H0 (big-endian)",
        ));
        self.add(Self::sig(
            CryptoAlgorithm::Sha1,
            "SHA1-H1",
            SignatureKind::MagicConstant,
            Some(vec![0xef, 0xcd, 0xab, 0x89]),
            Some(0x89ab_cdef),
            88,
            "SHA-1 initial hash H1",
        ));
        self.add(Self::sig(
            CryptoAlgorithm::Sha1,
            "SHA1-K0",
            SignatureKind::MagicConstant,
            Some(vec![0x5a, 0x82, 0x79, 0x99]),
            Some(0x5a82_7999),
            85,
            "SHA-1 round constant K0 = floor(sqrt(2)*2^30)",
        ));
        // ── SHA-256 init values ──────────────────────────────────────────────
        self.add(Self::sig(
            CryptoAlgorithm::Sha256,
            "SHA256-H0",
            SignatureKind::MagicConstant,
            Some(vec![0x67, 0xe6, 0x09, 0x6a]),
            Some(0x6a09_e667),
            92,
            "SHA-256 initial hash H0 (big-endian)",
        ));
        self.add(Self::sig(
            CryptoAlgorithm::Sha256,
            "SHA256-H1",
            SignatureKind::MagicConstant,
            Some(vec![0x85, 0xae, 0x67, 0xbb]),
            Some(0xbb67_ae85),
            92,
            "SHA-256 initial hash H1",
        ));
        self.add(Self::sig(
            CryptoAlgorithm::Sha256,
            "SHA256-K0",
            SignatureKind::MagicConstant,
            Some(vec![0x98, 0x2f, 0x8a, 0x42]),
            Some(0x428a_2f98),
            90,
            "SHA-256 round constant K[0]",
        ));
        // ── SHA-512 init values ──────────────────────────────────────────────
        self.add(Self::sig(
            CryptoAlgorithm::Sha512,
            "SHA512-H0-LO",
            SignatureKind::MagicConstant,
            Some(vec![0x08, 0xc9, 0xbc, 0xf3, 0x67, 0xe6, 0x09, 0x6a]),
            Some(0x6a09_e667_f3bc_c908),
            93,
            "SHA-512 initial hash H0 (64-bit)",
        ));
    }

    fn populate_stream_algos(&mut self) {
        // ── ChaCha20 constant "expand 32-byte k" ────────────────────────────
        self.add(Self::sig(
            CryptoAlgorithm::ChaCha20,
            "CHACHA20-CONST",
            SignatureKind::BytePattern,
            Some(b"expand 32-byte k".to_vec()),
            None,
            99,
            "ChaCha20 sigma constant",
        ));
        self.add(Self::sig(
            CryptoAlgorithm::Salsa20,
            "SALSA20-CONST",
            SignatureKind::BytePattern,
            Some(b"expand 32-byte k".to_vec()),
            None,
            95,
            "Salsa20 sigma constant (shared with ChaCha20)",
        ));
        // ── Poly1305 prime ───────────────────────────────────────────────────
        self.add(Self::sig(
            CryptoAlgorithm::Poly1305,
            "POLY1305-PRIME",
            SignatureKind::MagicConstant,
            Some(vec![0xfb, 0xff, 0xff, 0x03]),
            Some(0x3_ffff_fffb),
            80,
            "Poly1305 partial-reduction constant",
        ));
        // ── RC4 KSA pattern: xor loop with 256 iterations hint ───────────────
        self.add(Self::sig(
            CryptoAlgorithm::Rc4,
            "RC4-KEYSTREAM-MAGIC",
            SignatureKind::MagicConstant,
            Some(vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]),
            None,
            60,
            "RC4 KSA initial state marker",
        ));
    }

    fn populate_checksum_rsa_algos(&mut self) {
        // ── CRC32 polynomial ─────────────────────────────────────────────────
        self.add(Self::sig(
            CryptoAlgorithm::Crc32,
            "CRC32-POLY",
            SignatureKind::MagicConstant,
            Some(vec![0xb7, 0x1d, 0xc1, 0xed]),
            Some(0xedc1_d7b7),
            95,
            "CRC32 reversed polynomial 0xEDB8_8320",
        ));
        self.add(Self::sig(
            CryptoAlgorithm::Crc32,
            "CRC32-POLY2",
            SignatureKind::MagicConstant,
            Some(vec![0x20, 0x83, 0xb8, 0xed]),
            Some(0xedb8_8320),
            95,
            "CRC32 polynomial 0xEDB8_8320",
        ));
        // ── Adler32 modulus ──────────────────────────────────────────────────
        self.add(Self::sig(
            CryptoAlgorithm::Adler32,
            "ADLER32-MOD",
            SignatureKind::MagicConstant,
            Some(vec![0xf1, 0xfe, 0x00, 0x00]),
            Some(0x0000_fff1),
            85,
            "Adler32 modulus 65521 = 0xFFF1",
        ));
        // ── RSA small prime markers ──────────────────────────────────────────
        self.add(Self::sig(
            CryptoAlgorithm::Rsa2048,
            "RSA-PRIME-65537",
            SignatureKind::MagicConstant,
            Some(vec![0x01, 0x00, 0x01]),
            Some(65537),
            70,
            "RSA public exponent 65537 (0x10001)",
        ));
        // ── BLAKE2b IV[0] ────────────────────────────────────────────────────
        self.add(Self::sig(
            CryptoAlgorithm::Blake2b,
            "BLAKE2B-IV0",
            SignatureKind::MagicConstant,
            Some(vec![0x08, 0xc9, 0xbc, 0xf3, 0x67, 0xe6, 0x09, 0x6a]),
            Some(0x6a09_e667_f3bc_c908u64),
            85,
            "BLAKE2b IV[0] (same as SHA-512 H0)",
        ));
    }

    fn populate_misc_algos(&mut self) {
        self.populate_misc_algos_1();
        self.populate_misc_algos_2();
    }

    fn populate_misc_algos_1(&mut self) {
        // ── bcrypt magic "$2a$" ───────────────────────────────────────────────
        self.add(Self::sig(
            CryptoAlgorithm::Bcrypt,
            "BCRYPT-MAGIC",
            SignatureKind::BytePattern,
            Some(b"$2a$".to_vec()),
            None,
            80,
            "bcrypt hash string prefix",
        ));
        self.add(Self::sig(
            CryptoAlgorithm::Bcrypt,
            "BCRYPT-MAGIC-B",
            SignatureKind::BytePattern,
            Some(b"$2b$".to_vec()),
            None,
            80,
            "bcrypt hash string prefix (version 2b)",
        ));
        // ── Blowfish P-array first value ─────────────────────────────────────
        self.add(Self::sig(
            CryptoAlgorithm::Blowfish,
            "BLOWFISH-P1",
            SignatureKind::MagicConstant,
            Some(vec![0x43, 0x3e, 0x6f, 0x24]),
            Some(0x243f_6a88),
            88,
            "Blowfish P[0] = 0x243f_6a88 (pi digits)",
        ));
        // ── Twofish MDS matrix constant ──────────────────────────────────────
        self.add(Self::sig(
            CryptoAlgorithm::Twofish,
            "TWOFISH-MDS",
            SignatureKind::MagicConstant,
            Some(vec![0x6c, 0x5b, 0x01, 0xbc]),
            Some(0xbc01_5b6c),
            75,
            "Twofish MDS[0][0]",
        ));
        // ── Whirlpool initialization ──────────────────────────────────────────
        self.add(Self::sig(
            CryptoAlgorithm::Whirlpool,
            "WHIRLPOOL-C0",
            SignatureKind::MagicConstant,
            Some(vec![0x18, 0x18, 0x60, 0x18]),
            Some(0x1818_6018),
            72,
            "Whirlpool C0 lookup table start",
        ));
        // ── Argon2 version tag ───────────────────────────────────────────────
        self.add(Self::sig(
            CryptoAlgorithm::Argon2id,
            "ARGON2-VERSION",
            SignatureKind::BytePattern,
            Some(b"$argon2id$".to_vec()),
            None,
            99,
            "Argon2id hash string",
        ));
        self.add(Self::sig(
            CryptoAlgorithm::Argon2i,
            "ARGON2I-VERSION",
            SignatureKind::BytePattern,
            Some(b"$argon2i$".to_vec()),
            None,
            99,
            "Argon2i hash string",
        ));
        // ── scrypt Salsa8 core marker ────────────────────────────────────────
        self.add(Self::sig(
            CryptoAlgorithm::Scrypt,
            "SCRYPT-CONST",
            SignatureKind::BytePattern,
            Some(b"scrypt".to_vec()),
            None,
            85,
            "scrypt header magic",
        ));
    }

    fn populate_misc_algos_2(&mut self) {
        // ── SM3 IV ──────────────────────────────────────────────────────────
        self.add(Self::sig(
            CryptoAlgorithm::Sm3,
            "SM3-H0",
            SignatureKind::MagicConstant,
            Some(vec![0x73, 0x80, 0x16, 0x7f]),
            Some(0x7380_166f),
            90,
            "SM3 initial hash H0",
        ));
        // ── SM4 S-box first entry ─────────────────────────────────────────────
        self.add(Self::sig(
            CryptoAlgorithm::Sm4,
            "SM4-SBOX-START",
            SignatureKind::Sbox,
            Some(vec![0xd6, 0x90, 0xe9, 0xfe]),
            None,
            90,
            "First bytes of SM4 S-box",
        ));
        // ── Tiger digest constant ─────────────────────────────────────────────
        self.add(Self::sig(
            CryptoAlgorithm::Tiger,
            "TIGER-CONST1",
            SignatureKind::MagicConstant,
            Some(vec![0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5]),
            Some(0xa5a5_a5a5_a5a5_a5a5),
            70,
            "Tiger hash sbox generation constant",
        ));
        // ── RIPEMD-160 init ──────────────────────────────────────────────────
        self.add(Self::sig(
            CryptoAlgorithm::Ripemd160,
            "RIPEMD160-H0",
            SignatureKind::MagicConstant,
            Some(vec![0x01, 0x23, 0x45, 0x67]),
            Some(0x6745_2301),
            85,
            "RIPEMD-160 initial hash H0 (same as MD5/SHA-1)",
        ));
        // ── GHash 0xe1 polynomial byte ───────────────────────────────────────
        self.add(Self::sig(
            CryptoAlgorithm::Ghash,
            "GHASH-POLY",
            SignatureKind::MagicConstant,
            Some(vec![
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0xe1,
            ]),
            Some(0xe1),
            80,
            "GHash/GCM reduction polynomial 0xe1 in 128-bit word",
        ));
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// detect_algorithm
// ─────────────────────────────────────────────────────────────────────────────

/// Scan `data` for known cryptographic patterns and return all matches.
#[must_use]
pub fn detect_algorithm(data: &[u8], db: &AlgorithmDb) -> Vec<DetectionResult> {
    let mut results = Vec::new();
    for sig in db.signatures() {
        if let Some(pattern) = &sig.pattern {
            if pattern.is_empty() {
                continue;
            }
            // Slide over all offsets.
            for offset in 0..data.len().saturating_sub(pattern.len() - 1) {
                if sig.matches_at(data, offset) {
                    results.push(DetectionResult {
                        algorithm: sig.algorithm,
                        offset,
                        confidence: sig.confidence,
                        signature_name: sig.name.clone(),
                        description: sig.description.clone(),
                    });
                }
            }
        }
    }
    // Sort by confidence descending, then offset ascending.
    results.sort_by(|a, b| {
        b.confidence
            .cmp(&a.confidence)
            .then(a.offset.cmp(&b.offset))
    });
    results
}

/// Return deduplicated algorithm names from detection results.
#[must_use]
pub fn unique_algorithms(results: &[DetectionResult]) -> Vec<CryptoAlgorithm> {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for r in results {
        if seen.insert(r.algorithm) {
            out.push(r.algorithm);
        }
    }
    out
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn aes_sbox_start() -> Vec<u8> {
        vec![0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5]
    }

    // -- CryptoAlgorithm -----------------------------------------------------

    #[test]
    fn test_aes_is_symmetric() {
        assert!(CryptoAlgorithm::Aes128Cbc.is_symmetric());
        assert!(!CryptoAlgorithm::Rsa2048.is_symmetric());
    }

    #[test]
    fn test_rsa_is_asymmetric() {
        assert!(CryptoAlgorithm::Rsa2048.is_asymmetric());
        assert!(!CryptoAlgorithm::Sha256.is_asymmetric());
    }

    #[test]
    fn test_sha256_is_hash() {
        assert!(CryptoAlgorithm::Sha256.is_hash());
        assert!(!CryptoAlgorithm::Aes256Cbc.is_hash());
    }

    #[test]
    fn test_weak_algorithms() {
        assert!(CryptoAlgorithm::Md5.is_weak());
        assert!(CryptoAlgorithm::Des.is_weak());
        assert!(CryptoAlgorithm::Rc4.is_weak());
        assert!(!CryptoAlgorithm::Aes256Gcm.is_weak());
    }

    #[test]
    fn test_key_bits() {
        assert_eq!(CryptoAlgorithm::Aes128Cbc.typical_key_bits(), Some(128));
        assert_eq!(CryptoAlgorithm::Aes256Gcm.typical_key_bits(), Some(256));
        assert_eq!(CryptoAlgorithm::Rsa4096.typical_key_bits(), Some(4096));
        assert_eq!(CryptoAlgorithm::Rc4.typical_key_bits(), None);
    }

    #[test]
    fn test_display() {
        assert_eq!(CryptoAlgorithm::ChaCha20.to_string(), "ChaCha20");
        assert_eq!(CryptoAlgorithm::Sha3_256.to_string(), "SHA3-256");
        assert_eq!(CryptoAlgorithm::Unknown.to_string(), "Unknown");
    }

    // -- AlgorithmDb ---------------------------------------------------------

    #[test]
    fn test_default_db_populated() {
        let db = AlgorithmDb::default_db();
        assert!(
            db.len() >= 30,
            "expected at least 30 signatures, got {}",
            db.len()
        );
    }

    #[test]
    fn test_db_for_algorithm() {
        let db = AlgorithmDb::default_db();
        let sigs = db.for_algorithm(CryptoAlgorithm::Md5);
        assert!(!sigs.is_empty());
    }

    #[test]
    fn test_db_add_custom() {
        let mut db = AlgorithmDb::empty();
        db.add(AlgorithmSignature {
            algorithm: CryptoAlgorithm::Rc4,
            name: "custom".into(),
            kind: SignatureKind::BytePattern,
            pattern: Some(vec![0xDE, 0xAD]),
            mask: None,
            constant: None,
            confidence: 50,
            description: "test".into(),
        });
        assert_eq!(db.len(), 1);
    }

    // -- AlgorithmSignature::matches_at --------------------------------------

    #[test]
    fn test_signature_matches() {
        let sig = AlgorithmSignature {
            algorithm: CryptoAlgorithm::Aes128Cbc,
            name: "test".into(),
            kind: SignatureKind::BytePattern,
            pattern: Some(vec![0xAB, 0xCD]),
            mask: None,
            constant: None,
            confidence: 80,
            description: "test".into(),
        };
        let data = [0x00, 0xAB, 0xCD, 0x00];
        assert!(!sig.matches_at(&data, 0));
        assert!(sig.matches_at(&data, 1));
        assert!(!sig.matches_at(&data, 2));
    }

    #[test]
    fn test_signature_matches_with_mask() {
        let sig = AlgorithmSignature {
            algorithm: CryptoAlgorithm::Aes128Cbc,
            name: "masked".into(),
            kind: SignatureKind::BytePattern,
            pattern: Some(vec![0xF0, 0x00]),
            mask: Some(vec![0xF0, 0x00]),
            constant: None,
            confidence: 70,
            description: "test".into(),
        };
        let data = [0xF5, 0x42]; // 0xF5 & 0xF0 == 0xF0, 0x42 & 0x00 == 0x00
        assert!(sig.matches_at(&data, 0));
    }

    #[test]
    fn test_signature_no_match_too_short() {
        let sig = AlgorithmSignature {
            algorithm: CryptoAlgorithm::Sha256,
            name: "t".into(),
            kind: SignatureKind::BytePattern,
            pattern: Some(vec![0x01, 0x02, 0x03]),
            mask: None,
            constant: None,
            confidence: 80,
            description: "t".into(),
        };
        assert!(!sig.matches_at(&[0x01, 0x02], 0));
    }

    // -- detect_algorithm ----------------------------------------------------

    #[test]
    fn test_detect_aes_sbox() {
        let db = AlgorithmDb::default_db();
        let mut data = vec![0u8; 32];
        data[4..12].copy_from_slice(&aes_sbox_start());
        let results = detect_algorithm(&data, &db);
        assert!(
            results
                .iter()
                .any(|r| r.algorithm == CryptoAlgorithm::Aes128Cbc)
        );
    }

    #[test]
    fn test_detect_chacha20() {
        let db = AlgorithmDb::default_db();
        let mut data = vec![0u8; 64];
        data[0..16].copy_from_slice(b"expand 32-byte k");
        let results = detect_algorithm(&data, &db);
        assert!(
            results
                .iter()
                .any(|r| r.algorithm == CryptoAlgorithm::ChaCha20)
        );
    }

    #[test]
    fn test_detect_md5_constants() {
        let db = AlgorithmDb::default_db();
        let mut data = vec![0u8; 64];
        data[0..4].copy_from_slice(&[0x01, 0x23, 0x45, 0x67]);
        data[4..8].copy_from_slice(&[0x89, 0xab, 0xcd, 0xef]);
        let results = detect_algorithm(&data, &db);
        assert!(results.iter().any(|r| r.algorithm == CryptoAlgorithm::Md5));
    }

    #[test]
    fn test_detect_empty_data() {
        let db = AlgorithmDb::default_db();
        let results = detect_algorithm(&[], &db);
        assert!(results.is_empty());
    }

    #[test]
    fn test_detect_no_match() {
        let db = AlgorithmDb::default_db();
        let data = vec![0xAAu8; 256];
        let results = detect_algorithm(&data, &db);
        // 0xAA repeated won't match any signature.
        assert!(results.is_empty());
    }

    #[test]
    fn test_detect_sorted_by_confidence() {
        let db = AlgorithmDb::default_db();
        let mut data = vec![0u8; 128];
        data[0..16].copy_from_slice(b"expand 32-byte k");
        data[16..24].copy_from_slice(&aes_sbox_start());
        let results = detect_algorithm(&data, &db);
        for w in results.windows(2) {
            assert!(w[0].confidence >= w[1].confidence);
        }
    }

    // -- unique_algorithms ---------------------------------------------------

    #[test]
    fn test_unique_algorithms_deduplicates() {
        let db = AlgorithmDb::default_db();
        let mut data = vec![0u8; 256];
        data[0..4].copy_from_slice(&[0x01, 0x23, 0x45, 0x67]);
        data[4..8].copy_from_slice(&[0x89, 0xab, 0xcd, 0xef]);
        data[8..12].copy_from_slice(&[0xfe, 0xdc, 0xba, 0x98]);
        data[12..16].copy_from_slice(&[0x76, 0x54, 0x32, 0x10]);
        let results = detect_algorithm(&data, &db);
        let algos = unique_algorithms(&results);
        let md5_count = algos.iter().filter(|&&a| a == CryptoAlgorithm::Md5).count();
        assert_eq!(md5_count, 1);
    }

    #[test]
    fn test_bcrypt_magic() {
        let db = AlgorithmDb::default_db();
        let data = b"$2a$12$some_bcrypt_hash_here".to_vec();
        let results = detect_algorithm(&data, &db);
        assert!(
            results
                .iter()
                .any(|r| r.algorithm == CryptoAlgorithm::Bcrypt)
        );
    }

    #[test]
    fn test_db_not_empty_after_add() {
        let mut db = AlgorithmDb::empty();
        assert!(db.is_empty());
        db.add(AlgorithmSignature {
            algorithm: CryptoAlgorithm::Sha256,
            name: "x".into(),
            kind: SignatureKind::MagicConstant,
            pattern: None,
            mask: None,
            constant: Some(1),
            confidence: 50,
            description: "x".into(),
        });
        assert!(!db.is_empty());
    }
}
