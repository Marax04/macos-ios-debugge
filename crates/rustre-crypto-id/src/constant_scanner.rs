//! Cryptographic constant scanner.
//!
//! Scans a binary for known crypto constants (AES S-box / round constants,
//! DES S-boxes, SHA round constants, RSA small primes, ECC field params, CRC
//! polynomials, etc.) and reports every match with its virtual address,
//! algorithm, and type.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ─────────────────────────────────────────────────────────────────────────────
// ConstantType — what the constant represents
// ─────────────────────────────────────────────────────────────────────────────

/// The semantic role of a cryptographic constant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ConstantType {
    /// S-box or substitution table entry.
    Sbox,
    /// Inverse S-box.
    InvSbox,
    /// Round constant (e.g. AES rcon, SHA K[i]).
    RoundConstant,
    /// Permutation table.
    PermutationTable,
    /// Initialization vector or initial hash value.
    Iv,
    /// Reduction polynomial (e.g. GCM, CRC).
    ReductionPolynomial,
    /// Field prime or characteristic.
    FieldPrime,
    /// Small exponent / public exponent.
    PublicExponent,
    /// Salt or nonce.
    SaltOrNonce,
    /// General magic constant.
    Magic,
}

impl std::fmt::Display for ConstantType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Sbox => "S-box",
            Self::InvSbox => "Inv-S-box",
            Self::RoundConstant => "RoundConst",
            Self::PermutationTable => "Permutation",
            Self::Iv => "IV",
            Self::ReductionPolynomial => "RedPoly",
            Self::FieldPrime => "FieldPrime",
            Self::PublicExponent => "PubExp",
            Self::SaltOrNonce => "Salt/Nonce",
            Self::Magic => "Magic",
        };
        write!(f, "{s}")
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CryptoConstant descriptor
// ─────────────────────────────────────────────────────────────────────────────

/// A known cryptographic constant with its byte representation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoConstant {
    /// Identifying name.
    pub name: String,
    /// Algorithm(s) this constant is associated with.
    pub algorithms: Vec<String>,
    /// Semantic type.
    pub constant_type: ConstantType,
    /// Byte pattern (little-endian representation where applicable).
    pub bytes: Vec<u8>,
    /// Optional big-endian alternative representation.
    pub bytes_be: Option<Vec<u8>>,
    /// Confidence weight 0–100.
    pub confidence: u8,
    /// Human-readable description.
    pub description: String,
}

impl CryptoConstant {
    fn new(
        name: &str,
        algorithms: &[&str],
        constant_type: ConstantType,
        bytes: &[u8],
        confidence: u8,
        description: &str,
    ) -> Self {
        Self {
            name: name.into(),
            algorithms: algorithms.iter().map(std::string::ToString::to_string).collect(),
            constant_type,
            bytes: bytes.to_owned(),
            bytes_be: None,
            confidence,
            description: description.into(),
        }
    }

    fn with_be(mut self, be: Vec<u8>) -> Self {
        self.bytes_be = Some(be);
        self
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ConstantMatch — a hit found in a binary
// ─────────────────────────────────────────────────────────────────────────────

/// A cryptographic constant matched at a specific location in a binary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConstantMatch {
    /// Virtual address of the match (`base_address` + `file_offset`).
    pub address: u64,
    /// File offset of the match.
    pub file_offset: usize,
    /// Length of the matched bytes.
    pub length: usize,
    /// Associated algorithms.
    pub algorithms: Vec<String>,
    /// Constant type.
    pub constant_type: ConstantType,
    /// Human-readable constant name.
    pub constant_name: String,
    /// Confidence.
    pub confidence: u8,
    /// Whether match was found in little-endian or big-endian form.
    pub endian: MatchEndian,
    /// Virtual address resolved through a section table, if available.
    /// `None` when no section information was provided to the scanner.
    pub va: Option<u64>,
}

/// Description of one PE/ELF section used to map file offsets to virtual addresses.
#[derive(Debug, Clone, Copy)]
pub struct ConstSectionInfo {
    /// Raw (file) offset of the section.
    pub file_offset: u64,
    /// Raw size in bytes.
    pub file_size: u64,
    /// Virtual address (image-relative or absolute) of the section start.
    pub virtual_address: u64,
}

impl ConstSectionInfo {
    /// Resolve a file offset to a virtual address using this section.
    /// Returns `None` if `offset` is outside the section.
    #[must_use]
    pub const fn va_for_offset(&self, offset: u64) -> Option<u64> {
        if offset >= self.file_offset && offset < self.file_offset.saturating_add(self.file_size) {
            Some(self.virtual_address + (offset - self.file_offset))
        } else {
            None
        }
    }
}

/// Endianness of the match.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MatchEndian {
    LittleEndian,
    BigEndian,
    Neutral,
}

// ─────────────────────────────────────────────────────────────────────────────
// ConstantScanner
// ─────────────────────────────────────────────────────────────────────────────

/// Scans binary data for known cryptographic constants.
///
/// # ⚠ There are TWO `ConstantScanner` types in this crate
///
/// This is the **table-driven** one — a `Vec<CryptoConstant>` plus
/// section-aware virtual addresses and a confidence threshold — and it is the
/// one the MCP tools and the binary survey use. The other,
/// [`crate::ConstantScanner`], is a unit struct with hand-written per-family
/// helpers. See its documentation for the defect this ambiguity caused.
pub struct ConstantScanner {
    constants: Vec<CryptoConstant>,
    /// Base address for reported virtual addresses.
    base_address: u64,
    /// Minimum confidence threshold.
    min_confidence: u8,
}

/// `true` when `pattern` cannot discriminate one buffer from another, so
/// searching for it alone produces noise rather than evidence.
///
/// Two shapes qualify, both found by running a scan over a file of zeroes:
///
/// * **every byte identical** (including empty) — `RIPEMD160_K0` is
///   `00 00 00 00`, RIPEMD-160's genuine round constant for rounds 0-15. As a
///   signature it matched at every offset of every zero-padded region: 8 KiB
///   of zeroes produced **8176 "RIPEMD-160" hits**.
/// * **a short word with at most one non-zero byte** — `AES_RCON_1` is
///   `01 00 00 00`, i.e. the little-endian integer 1. That appears in version
///   fields, counters and flags in essentially every binary; it matched the
///   `EV_CURRENT` byte of a bare ELF header and was reported as AES at
///   confidence 95.
///
/// The constants stay in the table: the values are correct and remain useful
/// as corroboration once several constants of one algorithm are found
/// together. What is refused is treating them as evidence **on their own**.
/// Longer patterns (S-boxes, magic strings) are unaffected.
#[must_use]
pub fn is_uninformative_pattern(pattern: &[u8]) -> bool {
    let Some(first) = pattern.first() else {
        return true;
    };
    if pattern.iter().all(|b| b == first) {
        return true;
    }
    // Small integers encoded in a 2/4/8-byte word.
    pattern.len() <= 8 && pattern.iter().filter(|&&b| b != 0).count() <= 1
}

impl ConstantScanner {
    /// Create a scanner with the default set of constants.
    #[must_use]
    pub fn new() -> Self {
        let mut s = Self {
            constants: Vec::new(),
            base_address: 0,
            min_confidence: 0,
        };
        s.populate();
        s
    }

    /// Set the base address added to every file offset for virtual addresses.
    pub const fn set_base_address(&mut self, addr: u64) {
        self.base_address = addr;
    }

    /// Set minimum confidence (matches below are suppressed).
    pub const fn set_min_confidence(&mut self, c: u8) {
        self.min_confidence = c;
    }

    /// Add a custom constant.
    pub fn add_constant(&mut self, c: CryptoConstant) {
        self.constants.push(c);
    }

    /// Return all registered constants.
    #[must_use]
    pub fn constants(&self) -> &[CryptoConstant] {
        &self.constants
    }

    /// Scan `data` for all registered constants and return every match.
    #[must_use]
    pub fn scan(&self, data: &[u8]) -> Vec<ConstantMatch> {
        let mut matches = Vec::new();

        for constant in &self.constants {
            if constant.confidence < self.min_confidence {
                continue;
            }
            // A pattern made of one repeated byte carries no information and
            // cannot identify anything on its own.
            //
            // `RIPEMD160_K0` is the honest example: RIPEMD-160's round
            // constant for rounds 0-15 really is zero, so the table entry is
            // `00 00 00 00`. As a SIGNATURE it matches at every offset of
            // every zero-padded region — a scan of 8 KiB of zeroes returned
            // **8176 "RIPEMD-160" hits**, swamping `by_algorithm` and every
            // total built from it. Same defect class as a magic-less LZMA
            // header being "detected" from its properties byte alone.
            //
            // The constant stays in the table (the value is correct and is
            // still useful as corroboration once a caller matches on several
            // constants at once); it just may not be searched for by itself.
            if is_uninformative_pattern(&constant.bytes) {
                continue;
            }
            // Scan for little-endian (primary) pattern.
            if !constant.bytes.is_empty() {
                let pat = &constant.bytes;
                for offset in 0..data.len().saturating_sub(pat.len() - 1) {
                    if data[offset..offset + pat.len()] == *pat.as_slice() {
                        matches.push(ConstantMatch {
                            address: self.base_address + offset as u64,
                            file_offset: offset,
                            length: pat.len(),
                            algorithms: constant.algorithms.clone(),
                            constant_type: constant.constant_type,
                            constant_name: constant.name.clone(),
                            confidence: constant.confidence,
                            endian: MatchEndian::LittleEndian,
                            va: None,
                        });
                    }
                }
            }
            // Also scan for big-endian alternative if provided.
            if let Some(be) = &constant.bytes_be
                && !be.is_empty() && be != &constant.bytes {
                    for offset in 0..data.len().saturating_sub(be.len() - 1) {
                        if data[offset..offset + be.len()] == *be.as_slice() {
                            matches.push(ConstantMatch {
                                address: self.base_address + offset as u64,
                                file_offset: offset,
                                length: be.len(),
                                algorithms: constant.algorithms.clone(),
                                constant_type: constant.constant_type,
                                constant_name: format!("{}-BE", constant.name),
                                confidence: constant.confidence,
                                endian: MatchEndian::BigEndian,
                                va: None,
                            });
                        }
                    }
                }
        }

        // Remove overlapping duplicates at the same address.
        matches.sort_by(|a, b| {
            a.file_offset
                .cmp(&b.file_offset)
                .then(b.confidence.cmp(&a.confidence))
        });
        matches
    }

    /// Scan `data` and resolve each match's virtual address via `sections`.
    ///
    /// Every returned [`ConstantMatch`] carries both `file_offset` and a
    /// section-resolved `va` (when the offset falls inside a section). Matches
    /// outside all sections keep `va: None`.
    #[must_use]
    pub fn scan_with_sections(
        &self,
        data: &[u8],
        sections: &[ConstSectionInfo],
    ) -> Vec<ConstantMatch> {
        let mut hits = self.scan(data);
        for hit in &mut hits {
            let off = hit.file_offset as u64;
            for sec in sections {
                if let Some(va) = sec.va_for_offset(off) {
                    hit.va = Some(va);
                    break;
                }
            }
        }
        hits
    }

    /// Scan and return grouped results keyed by algorithm name.
    #[must_use]
    pub fn scan_grouped(&self, data: &[u8]) -> HashMap<String, Vec<ConstantMatch>> {
        let all = self.scan(data);
        let mut map: HashMap<String, Vec<ConstantMatch>> = HashMap::new();
        for m in all {
            for algo in &m.algorithms {
                map.entry(algo.clone()).or_default().push(m.clone());
            }
        }
        map
    }

    // ── Built-in constant population ──────────────────────────────────────

    fn populate(&mut self) {
        self.populate_aes_des();
        self.populate_sha();
        self.populate_md5_rsa_ecc();
        self.populate_stream_crc();
        self.populate_blowfish_sm();
        self.populate_blake2_keccak();
        self.populate_md4_md5t();
        self.populate_crc_hmac_oids();
        self.populate_cipher_tables();
    }

    fn populate_aes_des(&mut self) {
        // ── AES S-box ──────────────────────────────────────────────────────
        self.constants.push(CryptoConstant::new(
            "AES_SBOX_ROW0",
            &["AES-128", "AES-192", "AES-256"],
            ConstantType::Sbox,
            &[
                0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7,
                0xab, 0x76,
            ],
            95,
            "First 16 bytes of AES forward S-box",
        ));
        // ── AES Inv S-box ──────────────────────────────────────────────────
        self.constants.push(CryptoConstant::new(
            "AES_INVSBOX_ROW0",
            &["AES-128", "AES-192", "AES-256"],
            ConstantType::InvSbox,
            &[
                0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3,
                0xd7, 0xfb,
            ],
            95,
            "First 16 bytes of AES inverse S-box",
        ));
        // ── AES round constants ────────────────────────────────────────────
        self.constants.push(CryptoConstant::new(
            "AES_RCON_1",
            &["AES-128", "AES-192", "AES-256"],
            ConstantType::RoundConstant,
            &[0x01, 0x00, 0x00, 0x00],
            80,
            "AES rcon[0] = 0x0100_0000",
        ));
        self.constants.push(CryptoConstant::new(
            "AES_RCON_2",
            &["AES-128", "AES-192", "AES-256"],
            ConstantType::RoundConstant,
            &[0x02, 0x00, 0x00, 0x00],
            75,
            "AES rcon[1] = 0x0200_0000",
        ));
        self.constants.push(CryptoConstant::new(
            "AES_RCON_SEQUENCE",
            &["AES-128", "AES-192", "AES-256"],
            ConstantType::RoundConstant,
            &[0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36],
            90,
            "AES round constant sequence rcon[0..9]",
        ));
        // ── DES S-boxes ────────────────────────────────────────────────────
        self.constants.push(CryptoConstant::new(
            "DES_SBOX1_START",
            &["DES", "3DES"],
            ConstantType::Sbox,
            &[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
            90,
            "DES S-box 1 first row",
        ));
        self.constants.push(CryptoConstant::new(
            "DES_IP_TABLE",
            &["DES", "3DES"],
            ConstantType::PermutationTable,
            &[58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4],
            90,
            "DES initial permutation table start",
        ));
    }

    fn populate_sha(&mut self) {
        // ── SHA-1 ──────────────────────────────────────────────────────────
        self.constants.push(
            CryptoConstant::new(
                "SHA1_H0",
                &["SHA-1"],
                ConstantType::Iv,
                &[0x01, 0x23, 0x45, 0x67], // LE
                88,
                "SHA-1 initial hash H0 = 0x6745_2301 (LE)",
            )
            .with_be(vec![0x67, 0x45, 0x23, 0x01]),
        );
        self.constants.push(
            CryptoConstant::new(
                "SHA1_K0",
                &["SHA-1"],
                ConstantType::RoundConstant,
                &[0x99, 0x79, 0x82, 0x5a], // LE of 0x5a82_7999
                85,
                "SHA-1 K0 constant (LE)",
            )
            .with_be(vec![0x5a, 0x82, 0x79, 0x99]),
        );
        self.constants.push(
            CryptoConstant::new(
                "SHA1_K1",
                &["SHA-1"],
                ConstantType::RoundConstant,
                &[0x99, 0x5e, 0xd1, 0x6e], // LE of 0x6ed9_eba1
                85,
                "SHA-1 K1 constant (LE)",
            )
            .with_be(vec![0x6e, 0xd9, 0xeb, 0xa1]),
        );
        // ── SHA-256 ────────────────────────────────────────────────────────
        self.constants.push(
            CryptoConstant::new(
                "SHA256_H0",
                &["SHA-256"],
                ConstantType::Iv,
                &[0x67, 0xe6, 0x09, 0x6a], // LE of 0x6a09_e667
                92,
                "SHA-256 initial H0 (LE)",
            )
            .with_be(vec![0x6a, 0x09, 0xe6, 0x67]),
        );
        self.constants.push(
            CryptoConstant::new(
                "SHA256_K0",
                &["SHA-256"],
                ConstantType::RoundConstant,
                &[0x98, 0x2f, 0x8a, 0x42], // LE of 0x428a_2f98
                90,
                "SHA-256 K[0] (LE)",
            )
            .with_be(vec![0x42, 0x8a, 0x2f, 0x98]),
        );
        self.constants.push(
            CryptoConstant::new(
                "SHA256_K1",
                &["SHA-256"],
                ConstantType::RoundConstant,
                &[0x91, 0x44, 0x37, 0x71], // LE of 0x7137_4491
                90,
                "SHA-256 K[1] (LE)",
            )
            .with_be(vec![0x71, 0x37, 0x44, 0x91]),
        );
        // ── SHA-256 H1..H7 (rest of the initial hash vector) ─────────────
        // Each entry registers both LE and BE byte patterns so we match
        // hand-rolled implementations regardless of host endianness.
        const SHA256_H_REST: [(u32, &str); 7] = [
            (0xbb67_ae85, "SHA-256 H1"),
            (0x3c6e_f372, "SHA-256 H2"),
            (0xa54f_f53a, "SHA-256 H3"),
            (0x510e_527f, "SHA-256 H4"),
            (0x9b05_688c, "SHA-256 H5"),
            (0x1f83_d9ab, "SHA-256 H6"),
            (0x5be0_cd19, "SHA-256 H7"),
        ];
        for (i, (word, desc)) in SHA256_H_REST.iter().enumerate() {
            let le = word.to_le_bytes();
            let be = word.to_be_bytes();
            let name = format!("SHA256_H{}", i + 1);
            self.constants.push(
                CryptoConstant::new(
                    &name,
                    &["SHA-256"],
                    ConstantType::Iv,
                    &le,
                    92,
                    desc,
                )
                .with_be(be.to_vec()),
            );
        }
        // ── SHA-256 K[2..16] (high-confidence round constants) ───────────
        const SHA256_K_TAIL: [u32; 14] = [
            0xb5c0_fbcf, 0xe9b5_dba5, 0x3956_c25b, 0x59f1_11f1,
            0x923f_82a4, 0xab1c_5ed5, 0xd807_aa98, 0x1283_5b01,
            0x2431_85be, 0x550c_7dc3, 0x72be_5d74, 0x80de_b1fe,
            0x9bdc_06a7, 0xc19b_f174,
        ];
        for (i, word) in SHA256_K_TAIL.iter().enumerate() {
            let idx = i + 2;
            let le = word.to_le_bytes();
            let be = word.to_be_bytes();
            let name = format!("SHA256_K{idx}");
            let desc = format!("SHA-256 K[{idx}] (LE)");
            self.constants.push(
                CryptoConstant::new(
                    &name,
                    &["SHA-256"],
                    ConstantType::RoundConstant,
                    &le,
                    88,
                    &desc,
                )
                .with_be(be.to_vec()),
            );
        }
        // ── SHA-512 ────────────────────────────────────────────────────────
        self.constants.push(
            CryptoConstant::new(
                "SHA512_H0",
                &["SHA-512"],
                ConstantType::Iv,
                &[0x08, 0xc9, 0xbc, 0xf3, 0x67, 0xe6, 0x09, 0x6a],
                93,
                "SHA-512 initial H0 (LE 64-bit)",
            )
            .with_be(vec![0x6a, 0x09, 0xe6, 0x67, 0xf3, 0xbc, 0xc9, 0x08]),
        );
    }

    fn populate_md5_rsa_ecc(&mut self) {
        // ── MD5 ───────────────────────────────────────────────────────────
        self.constants.push(CryptoConstant::new(
            "MD5_H0",
            &["MD5"],
            ConstantType::Iv,
            &[0x01, 0x23, 0x45, 0x67],
            90,
            "MD5 initial A = 0x6745_2301 (LE)",
        ));
        self.constants.push(CryptoConstant::new(
            "MD5_H1",
            &["MD5"],
            ConstantType::Iv,
            &[0x89, 0xab, 0xcd, 0xef],
            90,
            "MD5 initial B = 0xefcd_ab89 (LE)",
        ));
        self.constants.push(CryptoConstant::new(
            "MD5_H2",
            &["MD5"],
            ConstantType::Iv,
            &[0xfe, 0xdc, 0xba, 0x98],
            90,
            "MD5 initial C = 0x98ba_dcfe (LE)",
        ));
        self.constants.push(CryptoConstant::new(
            "MD5_H3",
            &["MD5"],
            ConstantType::Iv,
            &[0x76, 0x54, 0x32, 0x10],
            90,
            "MD5 initial D = 0x1032_5476 (LE)",
        ));
        // ── RSA ───────────────────────────────────────────────────────────
        self.constants.push(CryptoConstant::new(
            "RSA_E_65537_3B",
            &["RSA"],
            ConstantType::PublicExponent,
            &[0x01, 0x00, 0x01],
            70,
            "RSA public exponent 65537 = 0x01_0001 (3-byte DER form)",
        ));
        self.constants.push(CryptoConstant::new(
            "RSA_E_65537_4B_LE",
            &["RSA"],
            ConstantType::PublicExponent,
            &[0x01, 0x00, 0x01, 0x00],
            68,
            "RSA public exponent 65537 as 4-byte LE",
        ));
        // ── ECC Curve25519 field prime ─────────────────────────────────────
        self.constants.push(CryptoConstant::new(
            "CURVE25519_PRIME_PARTIAL",
            &["Ed25519", "X25519", "Curve25519"],
            ConstantType::FieldPrime,
            &[0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
            88,
            "Partial bytes of 2^255-19 (Curve25519 prime) in LE",
        ));
        // ── NIST P-256 prime partial ───────────────────────────────────────
        self.constants.push(CryptoConstant::new(
            "P256_PRIME_PARTIAL",
            &["ECDSA", "ECDH", "P-256"],
            ConstantType::FieldPrime,
            &[0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01],
            82,
            "Last 8 bytes of NIST P-256 prime (BE)",
        ));
    }

    fn populate_stream_crc(&mut self) {
        // ── ChaCha20 / Salsa20 ────────────────────────────────────────────
        self.constants.push(CryptoConstant::new(
            "CHACHA20_CONST",
            &["ChaCha20"],
            ConstantType::Magic,
            b"expand 32-byte k",
            99,
            "ChaCha20 sigma constant",
        ));
        self.constants.push(CryptoConstant::new(
            "SALSA20_CONST_16",
            &["Salsa20"],
            ConstantType::Magic,
            b"expand 16-byte k",
            98,
            "Salsa20 tau constant (128-bit key)",
        ));
        // ── CRC32 ────────────────────────────────────────────────────────
        self.constants.push(
            CryptoConstant::new(
                "CRC32_POLY_LE",
                &["CRC32"],
                ConstantType::ReductionPolynomial,
                &[0x20, 0x83, 0xb8, 0xed], // 0xedb8_8320 LE
                95,
                "CRC32 reflected polynomial 0xEDB8_8320 (LE)",
            )
            .with_be(vec![0xed, 0xb8, 0x83, 0x20]),
        );
        self.constants.push(CryptoConstant::new(
            "CRC32C_POLY_LE",
            &["CRC32c"],
            ConstantType::ReductionPolynomial,
            &[0xf2, 0x26, 0x23, 0x82], // 0x82f6_3b78 LE
            92,
            "CRC32c (Castagnoli) polynomial 0x82F6_3B78 (LE)",
        ));
        // ── Adler32 ──────────────────────────────────────────────────────
        self.constants.push(CryptoConstant::new(
            "ADLER32_MOD",
            &["Adler32"],
            ConstantType::Magic,
            &[0xf1, 0xff, 0x00, 0x00], // 65521 = 0xfff1 LE
            85,
            "Adler32 modulus 65521 (LE 4-byte)",
        ));
    }

    fn populate_blowfish_sm(&mut self) {
        // ── Blowfish ─────────────────────────────────────────────────────
        self.constants.push(
            CryptoConstant::new(
                "BLOWFISH_P0_LE",
                &["Blowfish"],
                ConstantType::Iv,
                &[0x88, 0x6a, 0x3f, 0x24], // 0x243f_6a88 LE
                88,
                "Blowfish P-array entry 0 in LE",
            )
            .with_be(vec![0x24, 0x3f, 0x6a, 0x88]),
        );
        // ── GCM reduction polynomial ──────────────────────────────────────
        self.constants.push(CryptoConstant::new(
            "GCM_POLY_0XE1",
            &["AES-GCM", "GHASH"],
            ConstantType::ReductionPolynomial,
            &[
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0xe1,
            ],
            82,
            "GCM 128-bit reduction polynomial ending in 0xe1",
        ));
        // ── SM3 ──────────────────────────────────────────────────────────
        self.constants.push(
            CryptoConstant::new(
                "SM3_H0",
                &["SM3"],
                ConstantType::Iv,
                &[0x6f, 0x16, 0x80, 0x73], // 0x7380_166f LE
                90,
                "SM3 initial hash H0 (LE)",
            )
            .with_be(vec![0x73, 0x80, 0x16, 0x6f]),
        );
        // ── SM4 S-box ─────────────────────────────────────────────────────
        self.constants.push(CryptoConstant::new(
            "SM4_SBOX_START",
            &["SM4"],
            ConstantType::Sbox,
            &[0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7],
            90,
            "First 8 bytes of SM4 S-box",
        ));
        // ── Poly1305 ─────────────────────────────────────────────────────
        self.constants.push(CryptoConstant::new(
            "POLY1305_CLAMP",
            &["Poly1305"],
            ConstantType::ReductionPolynomial,
            &[
                0x0f, 0xfc, 0xff, 0xff, 0x0f, 0xfc, 0xff, 0xff, 0x0f, 0xfc, 0xff, 0xff, 0x0f, 0x00,
                0x00, 0x00,
            ],
            80,
            "Poly1305 r-value clamp mask",
        ));
        // ── RIPEMD-160 ───────────────────────────────────────────────────
        self.constants.push(CryptoConstant::new(
            "RIPEMD160_K0",
            &["RIPEMD-160"],
            ConstantType::RoundConstant,
            &[0x00, 0x00, 0x00, 0x00],
            70,
            "RIPEMD-160 round constant K0=0 (LE)",
        ));
        // ── bcrypt ───────────────────────────────────────────────────────
        self.constants.push(CryptoConstant::new(
            "BCRYPT_MAGIC",
            &["bcrypt"],
            ConstantType::Magic,
            b"OrpheanBeholderScryDoubt",
            95,
            "bcrypt internal magic string",
        ));
        // ── PBKDF2 / HMAC shared constant (PKCS#5 ASCII) ─────────────────
        self.constants.push(CryptoConstant::new(
            "PBKDF2_HEADER",
            &["PBKDF2"],
            ConstantType::Magic,
            b"pbkdf2",
            72,
            "PBKDF2 identifier string",
        ));
        // ── Blake2b IV ───────────────────────────────────────────────────
        self.constants.push(CryptoConstant::new(
            "BLAKE2B_IV0_LE",
            &["BLAKE2b"],
            ConstantType::Iv,
            &[0x08, 0xc9, 0xbc, 0xf3, 0x67, 0xe6, 0x09, 0x6a],
            85,
            "BLAKE2b IV[0] in LE (same as SHA-512 H0)",
        ));
    }

    fn populate_blake2_keccak(&mut self) {
        // ── BLAKE2s IV ─────────────────────────────────────────────────────
        self.constants.push(
            CryptoConstant::new(
                "BLAKE2S_IV0_LE",
                &["BLAKE2s"],
                ConstantType::Iv,
                &[0x67, 0xe6, 0x09, 0x6a], // 0x6a09e667 LE
                85,
                "BLAKE2s IV[0] in LE",
            )
            .with_be(vec![0x6a, 0x09, 0xe6, 0x67]),
        );

        // ── SHA-256 K[0..7] first 8 round constants packed BE ──────────────
        // K[0..7] = 428a2f98 71374491 b5c0fbcf e9b5dba5 3956c25b 59f111f1 923f82a4 ab1c5ed5
        self.constants.push(CryptoConstant::new(
            "SHA256_K0_TO_K7_BE",
            &["SHA-256"],
            ConstantType::RoundConstant,
            &[
                0x42, 0x8a, 0x2f, 0x98, 0x71, 0x37, 0x44, 0x91,
                0xb5, 0xc0, 0xfb, 0xcf, 0xe9, 0xb5, 0xdb, 0xa5,
                0x39, 0x56, 0xc2, 0x5b, 0x59, 0xf1, 0x11, 0xf1,
                0x92, 0x3f, 0x82, 0xa4, 0xab, 0x1c, 0x5e, 0xd5,
            ],
            98,
            "SHA-256 K[0..7] big-endian packed",
        ));

        // ── SHA-512 first two K values (64-bit, BE) ────────────────────────
        // K[0] = 0x428a2f98d728ae22, K[1] = 0x7137449123ef65cd
        self.constants.push(CryptoConstant::new(
            "SHA512_K0_BE",
            &["SHA-512"],
            ConstantType::RoundConstant,
            &[0x42, 0x8a, 0x2f, 0x98, 0xd7, 0x28, 0xae, 0x22],
            95,
            "SHA-512 K[0] = 0x428a2f98d728ae22 (BE)",
        ));
        self.constants.push(CryptoConstant::new(
            "SHA512_K1_BE",
            &["SHA-512"],
            ConstantType::RoundConstant,
            &[0x71, 0x37, 0x44, 0x91, 0x23, 0xef, 0x65, 0xcd],
            95,
            "SHA-512 K[1] = 0x7137449123ef65cd (BE)",
        ));

        // ── SHA-3 / Keccak round constants (24 × u64, LE-packed) ───────────
        // RC[0..23] in little-endian byte order.
        self.constants.push(CryptoConstant::new(
            "KECCAK_RC_LE",
            &["SHA-3", "Keccak"],
            ConstantType::RoundConstant,
            &[
                0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x82, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x8a, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80,
                0x00, 0x80, 0x00, 0x80, 0x00, 0x00, 0x00, 0x80,
                0x8b, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x01, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00,
            ],
            96,
            "Keccak/SHA-3 first 6 round constants (LE)",
        ));

        // ── AES T-tables spot-check (Te0[0]..Te0[3] BE) ────────────────────
        // Te0[0..3] = c66363a5 f87c7c84 ee777799 f67b7b8d
        self.constants.push(CryptoConstant::new(
            "AES_TE0_HEAD_BE",
            &["AES-128", "AES-192", "AES-256"],
            ConstantType::Sbox,
            &[
                0xc6, 0x63, 0x63, 0xa5, 0xf8, 0x7c, 0x7c, 0x84,
                0xee, 0x77, 0x77, 0x99, 0xf6, 0x7b, 0x7b, 0x8d,
            ],
            92,
            "AES Te0 table first 4 entries (BE) — T-table indicator",
        ));
    }

    fn populate_md4_md5t(&mut self) {
        // ── MD4 round constants ────────────────────────────────────────────
        // MD4 uses sqrt(2) ≈ 0x5A827999, sqrt(3) ≈ 0x6ED9EBA1
        self.constants.push(
            CryptoConstant::new(
                "MD4_K1_LE",
                &["MD4"],
                ConstantType::RoundConstant,
                &[0x99, 0x79, 0x82, 0x5a],
                80,
                "MD4 K1 = 0x5A827999 (LE)",
            )
            .with_be(vec![0x5a, 0x82, 0x79, 0x99]),
        );
        self.constants.push(
            CryptoConstant::new(
                "MD4_K2_LE",
                &["MD4"],
                ConstantType::RoundConstant,
                &[0xa1, 0xeb, 0xd9, 0x6e],
                80,
                "MD4 K2 = 0x6ED9EBA1 (LE)",
            )
            .with_be(vec![0x6e, 0xd9, 0xeb, 0xa1]),
        );

        // ── MD5 round table T[0..3] (LE) ──────────────────────────────────
        // T[0] = 0xd76aa478, T[1] = 0xe8c7b756
        self.constants.push(CryptoConstant::new(
            "MD5_T0_LE",
            &["MD5"],
            ConstantType::RoundConstant,
            &[0x78, 0xa4, 0x6a, 0xd7],
            85,
            "MD5 T[0] = 0xd76aa478 (LE)",
        ));
        self.constants.push(CryptoConstant::new(
            "MD5_T1_LE",
            &["MD5"],
            ConstantType::RoundConstant,
            &[0x56, 0xb7, 0xc7, 0xe8],
            85,
            "MD5 T[1] = 0xe8c7b756 (LE)",
        ));
    }

    fn populate_crc_hmac_oids(&mut self) {
        // ── Zlib CRC-32 polynomial (already present); add forward poly ─────
        self.constants.push(
            CryptoConstant::new(
                "CRC32_POLY_FORWARD_LE",
                &["CRC32"],
                ConstantType::ReductionPolynomial,
                &[0xb7, 0x1d, 0xc1, 0x04], // 0x04C11DB7 LE
                90,
                "CRC32 forward polynomial 0x04C11DB7 (LE)",
            )
            .with_be(vec![0x04, 0xc1, 0x1d, 0xb7]),
        );

        // ── Castagnoli CRC-32C polynomial canonical form ──────────────────
        self.constants.push(
            CryptoConstant::new(
                "CRC32C_CASTAGNOLI_REFL_LE",
                &["CRC32c", "Castagnoli"],
                ConstantType::ReductionPolynomial,
                &[0x78, 0x3b, 0xf6, 0x82], // 0x82F63B78 LE (reflected form)
                93,
                "CRC32c Castagnoli reflected polynomial 0x82F63B78 (LE)",
            )
            .with_be(vec![0x82, 0xf6, 0x3b, 0x78]),
        );

        // ── HMAC inner / outer pads ───────────────────────────────────────
        // ipad = 0x36 repeated, opad = 0x5C repeated (in HMAC key XOR).
        self.constants.push(CryptoConstant::new(
            "HMAC_IPAD",
            &["HMAC"],
            ConstantType::Magic,
            &[0x36u8; 16],
            72,
            "HMAC inner pad: 16 bytes of 0x36",
        ));
        self.constants.push(CryptoConstant::new(
            "HMAC_OPAD",
            &["HMAC"],
            ConstantType::Magic,
            &[0x5cu8; 16],
            72,
            "HMAC outer pad: 16 bytes of 0x5C",
        ));

        // ── RSA OID strings (DER) ─────────────────────────────────────────
        // 1.2.840.113549.1.1.1 = rsaEncryption (OID encoded)
        self.constants.push(CryptoConstant::new(
            "RSA_OID_RSAENCRYPTION",
            &["RSA"],
            ConstantType::Magic,
            &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01],
            95,
            "RSA OID rsaEncryption 1.2.840.113549.1.1.1 (DER)",
        ));
        // 1.2.840.113549.1.1.11 = sha256WithRSAEncryption
        self.constants.push(CryptoConstant::new(
            "RSA_OID_SHA256_RSA",
            &["RSA"],
            ConstantType::Magic,
            &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b],
            93,
            "RSA OID sha256WithRSAEncryption (DER)",
        ));
    }

    fn populate_cipher_tables(&mut self) {
        // ── DES PC1 table (key permutation) ───────────────────────────────
        self.constants.push(CryptoConstant::new(
            "DES_PC1_TABLE",
            &["DES", "3DES"],
            ConstantType::PermutationTable,
            &[57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2],
            88,
            "DES PC-1 permuted choice 1 (first row)",
        ));

        // ── Twofish RS matrix / MDS hint ──────────────────────────────────
        // Twofish uses 0x169 as the GF(2^8) reduction polynomial; q0 S-box
        // starts with 0xA9, 0x67, 0xB3, 0xE8.
        self.constants.push(CryptoConstant::new(
            "TWOFISH_Q0_START",
            &["Twofish"],
            ConstantType::Sbox,
            &[0xa9, 0x67, 0xb3, 0xe8, 0x04, 0xfd, 0xa3, 0x76],
            90,
            "Twofish q0 S-box first 8 bytes",
        ));

        // ── Serpent S-box S0 first row ────────────────────────────────────
        self.constants.push(CryptoConstant::new(
            "SERPENT_S0_HEAD",
            &["Serpent"],
            ConstantType::Sbox,
            &[3, 8, 15, 1, 10, 6, 5, 11, 14, 13, 4, 2, 7, 0, 9, 12],
            88,
            "Serpent S-box S0 (first row)",
        ));

        // ── Camellia S-box SBOX1 first 8 bytes ────────────────────────────
        self.constants.push(CryptoConstant::new(
            "CAMELLIA_SBOX1_HEAD",
            &["Camellia"],
            ConstantType::Sbox,
            &[0x70, 0x82, 0x2c, 0xec, 0xb3, 0x27, 0xc0, 0xe5],
            88,
            "Camellia SBOX1 first 8 bytes",
        ));

        // ── Adler-32 modulus 65521 explicit BE form ───────────────────────
        self.constants.push(CryptoConstant::new(
            "ADLER32_MOD_BE",
            &["Adler32"],
            ConstantType::Magic,
            &[0x00, 0x00, 0xff, 0xf1],
            82,
            "Adler-32 modulus 65521 (BE 4-byte)",
        ));

        // ── SHA-256 H0..H7 packed LE (32 bytes) ────────────────────────────
        // Single-pattern anchor used by Rust-style sha2 crate: emits the IV
        // as a contiguous 32-byte LE block. IDA's FindCrypt reports each
        // such occurrence as one SHA-256 IV hit.
        self.constants.push(
            CryptoConstant::new(
                "SHA256_H0_TO_H7_LE",
                &["SHA-256"],
                ConstantType::Iv,
                &[
                    0x67, 0xe6, 0x09, 0x6a, 0x85, 0xae, 0x67, 0xbb,
                    0x72, 0xf3, 0x6e, 0x3c, 0x3a, 0xf5, 0x4f, 0xa5,
                    0x7f, 0x52, 0x0e, 0x51, 0x8c, 0x68, 0x05, 0x9b,
                    0xab, 0xd9, 0x83, 0x1f, 0x19, 0xcd, 0xe0, 0x5b,
                ],
                99,
                "SHA-256 H0..H7 initial hash vector packed (LE)",
            )
            .with_be(vec![
                0x6a, 0x09, 0xe6, 0x67, 0xbb, 0x67, 0xae, 0x85,
                0x3c, 0x6e, 0xf3, 0x72, 0xa5, 0x4f, 0xf5, 0x3a,
                0x51, 0x0e, 0x52, 0x7f, 0x9b, 0x05, 0x68, 0x8c,
                0x1f, 0x83, 0xd9, 0xab, 0x5b, 0xe0, 0xcd, 0x19,
            ]),
        );

        // ── TEA / XTEA delta 0x9E3779B9 (golden ratio) ────────────────────
        self.constants.push(
            CryptoConstant::new(
                "TEA_DELTA_LE",
                &["TEA", "XTEA", "XXTEA"],
                ConstantType::Magic,
                &[0xb9, 0x79, 0x37, 0x9e],
                85,
                "TEA/XTEA delta 0x9E3779B9 (golden ratio, LE)",
            )
            .with_be(vec![0x9e, 0x37, 0x79, 0xb9]),
        );

        // ── SHA-1 IV packed (5 words, LE+BE) ──────────────────────────────
        self.constants.push(
            CryptoConstant::new(
                "SHA1_IV_PACKED_LE",
                &["SHA-1"],
                ConstantType::Iv,
                &[
                    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                    0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
                    0xf0, 0xe1, 0xd2, 0xc3,
                ],
                97,
                "SHA-1 IV H0..H4 packed (LE)",
            )
            .with_be(vec![
                0x67, 0x45, 0x23, 0x01, 0xef, 0xcd, 0xab, 0x89,
                0x98, 0xba, 0xdc, 0xfe, 0x10, 0x32, 0x54, 0x76,
                0xc3, 0xd2, 0xe1, 0xf0,
            ]),
        );

        // ── MD5 IV packed (4 words, LE) ───────────────────────────────────
        self.constants.push(
            CryptoConstant::new(
                "MD5_IV_PACKED_LE",
                &["MD5"],
                ConstantType::Iv,
                &[
                    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                    0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
                ],
                96,
                "MD5 IV A..D packed (LE)",
            )
            .with_be(vec![
                0x67, 0x45, 0x23, 0x01, 0xef, 0xcd, 0xab, 0x89,
                0x98, 0xba, 0xdc, 0xfe, 0x10, 0x32, 0x54, 0x76,
            ]),
        );
    }
}

impl Default for ConstantScanner {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ScanReport
// ─────────────────────────────────────────────────────────────────────────────

/// Full scan report produced by [`ConstantScanner::full_report`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanReport {
    pub matches: Vec<ConstantMatch>,
    pub total_matches: usize,
    pub unique_algorithms: Vec<String>,
    pub binary_size: usize,
    pub base_address: u64,
}

impl ConstantScanner {
    /// Perform a full scan and return a comprehensive report.
    #[must_use]
    pub fn full_report(&self, data: &[u8]) -> ScanReport {
        let matches = self.scan(data);
        let mut algos: Vec<String> = matches
            .iter()
            .flat_map(|m| m.algorithms.iter().cloned())
            .collect();
        algos.sort();
        algos.dedup();

        let total_matches = matches.len();
        ScanReport {
            matches,
            total_matches,
            unique_algorithms: algos,
            binary_size: data.len(),
            base_address: self.base_address,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn scanner() -> ConstantScanner {
        ConstantScanner::new()
    }

    // -- ConstantType display ------------------------------------------------

    #[test]
    fn test_constant_type_display() {
        assert_eq!(ConstantType::Sbox.to_string(), "S-box");
        assert_eq!(ConstantType::RoundConstant.to_string(), "RoundConst");
        assert_eq!(ConstantType::FieldPrime.to_string(), "FieldPrime");
    }

    // -- ConstantScanner construction ----------------------------------------

    #[test]
    fn test_scanner_has_constants() {
        let s = scanner();
        assert!(
            s.constants().len() >= 20,
            "expected at least 20 built-in constants"
        );
    }

    #[test]
    fn test_scanner_add_custom() {
        let mut s = scanner();
        let before = s.constants().len();
        s.add_constant(CryptoConstant::new(
            "MY_CONST",
            &["Custom"],
            ConstantType::Magic,
            &[0xDE, 0xAD, 0xBE, 0xEF],
            99,
            "custom test",
        ));
        assert_eq!(s.constants().len(), before + 1);
    }

    // -- scan ----------------------------------------------------------------

    #[test]
    fn test_scan_aes_sbox() {
        let s = scanner();
        let mut data = vec![0u8; 256];
        // Embed AES S-box row 0 at offset 32.
        let sbox = &[
            0x63u8, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7,
            0xab, 0x76,
        ];
        data[32..48].copy_from_slice(sbox);
        let matches = s.scan(&data);
        assert!(matches.iter().any(|m| m.constant_name.contains("AES_SBOX")));
    }

    #[test]
    fn test_scan_chacha20_constant() {
        let s = scanner();
        let data = b"AAAAexpand 32-byte kBBBB".to_vec();
        let matches = s.scan(&data);
        assert!(matches.iter().any(|m| m.constant_name == "CHACHA20_CONST"));
    }

    #[test]
    fn test_scan_crc32_polynomial() {
        let s = scanner();
        let mut data = vec![0u8; 16];
        data[0..4].copy_from_slice(&[0x20, 0x83, 0xb8, 0xed]);
        let matches = s.scan(&data);
        assert!(matches.iter().any(|m| m.constant_name.contains("CRC32")));
    }

    #[test]
    fn test_scan_md5_init() {
        let s = scanner();
        let mut data = vec![0u8; 32];
        data[0..4].copy_from_slice(&[0x01, 0x23, 0x45, 0x67]);
        let matches = s.scan(&data);
        assert!(
            matches
                .iter()
                .any(|m| m.algorithms.contains(&"MD5".to_owned()))
        );
    }

    #[test]
    fn test_scan_empty_data() {
        let s = scanner();
        let matches = s.scan(&[]);
        assert!(matches.is_empty());
    }

    #[test]
    fn test_scan_no_match() {
        let s = scanner();
        let data = vec![0xAAu8; 512];
        // 0xAA repeated unlikely to match any constant.
        let matches = s.scan(&data);
        assert!(matches.is_empty());
    }

    #[test]
    fn test_scan_address_offset_applied() {
        let mut s = scanner();
        s.set_base_address(0x40_0000);
        let data = b"0000expand 32-byte k".to_vec();
        let matches = s.scan(&data);
        let m = matches
            .iter()
            .find(|m| m.constant_name == "CHACHA20_CONST")
            .unwrap();
        assert_eq!(m.address, 0x40_0004); // offset 4 + base 0x40_0000
    }

    #[test]
    fn test_scan_big_endian_alternative() {
        let s = scanner();
        // SHA-256 H0 in BE: 0x6a, 0x09, 0xe6, 0x67
        let data = vec![0x6a, 0x09, 0xe6, 0x67, 0x00, 0x00, 0x00, 0x00];
        let matches = s.scan(&data);
        assert!(
            matches
                .iter()
                .any(|m| m.algorithms.contains(&"SHA-256".to_owned()))
        );
    }

    #[test]
    fn test_scan_min_confidence_filter() {
        let mut s = ConstantScanner::new();
        s.set_min_confidence(99);
        let data = b"expand 32-byte k".to_vec();
        let matches = s.scan(&data);
        // Only constants with confidence >= 99.
        for m in &matches {
            assert!(m.confidence >= 99);
        }
    }

    // -- scan_grouped --------------------------------------------------------

    #[test]
    fn test_scan_grouped() {
        let s = scanner();
        let data = b"expand 32-byte k".to_vec();
        let grouped = s.scan_grouped(&data);
        assert!(grouped.contains_key("ChaCha20"));
    }

    // -- full_report ---------------------------------------------------------

    #[test]
    fn test_full_report() {
        let s = scanner();
        let data = b"expand 32-byte k".to_vec();
        let rpt = s.full_report(&data);
        assert!(rpt.total_matches >= 1);
        assert!(!rpt.unique_algorithms.is_empty());
        assert_eq!(rpt.binary_size, data.len());
    }

    #[test]
    fn test_full_report_empty() {
        let s = scanner();
        let rpt = s.full_report(&[]);
        assert_eq!(rpt.total_matches, 0);
        assert!(rpt.unique_algorithms.is_empty());
    }

    // -- MatchEndian ---------------------------------------------------------

    #[test]
    fn test_match_endian_eq() {
        assert_eq!(MatchEndian::LittleEndian, MatchEndian::LittleEndian);
        assert_ne!(MatchEndian::LittleEndian, MatchEndian::BigEndian);
    }

    // -- sorted order --------------------------------------------------------

    #[test]
    fn test_scan_sorted_by_offset() {
        let s = scanner();
        let mut data = vec![0u8; 256];
        data[0..16].copy_from_slice(b"expand 32-byte k");
        data[64..68].copy_from_slice(&[0x01, 0x23, 0x45, 0x67]);
        let matches = s.scan(&data);
        let offsets: Vec<usize> = matches.iter().map(|m| m.file_offset).collect();
        let mut sorted = offsets.clone();
        sorted.sort_unstable();
        assert_eq!(offsets, sorted);
    }

    // -- bcrypt magic --------------------------------------------------------

    #[test]
    fn test_bcrypt_magic() {
        let s = scanner();
        let data = b"OrpheanBeholderScryDoubt".to_vec();
        let matches = s.scan(&data);
        assert!(
            matches
                .iter()
                .any(|m| m.algorithms.contains(&"bcrypt".to_owned()))
        );
    }

    // -- New canonical patterns ----------------------------------------------

    #[test]
    fn test_scan_sha256_k_block() {
        let s = scanner();
        let block: &[u8] = &[
            0x42, 0x8a, 0x2f, 0x98, 0x71, 0x37, 0x44, 0x91,
            0xb5, 0xc0, 0xfb, 0xcf, 0xe9, 0xb5, 0xdb, 0xa5,
            0x39, 0x56, 0xc2, 0x5b, 0x59, 0xf1, 0x11, 0xf1,
            0x92, 0x3f, 0x82, 0xa4, 0xab, 0x1c, 0x5e, 0xd5,
        ];
        let matches = s.scan(block);
        assert!(
            matches.iter().any(|m| m.constant_name == "SHA256_K0_TO_K7_BE"),
            "expected SHA256_K0_TO_K7_BE match"
        );
    }

    #[test]
    fn test_scan_sha512_k0_be() {
        let s = scanner();
        let data: &[u8] = &[0x42, 0x8a, 0x2f, 0x98, 0xd7, 0x28, 0xae, 0x22];
        let matches = s.scan(data);
        assert!(matches.iter().any(|m| m.constant_name == "SHA512_K0_BE"));
    }

    #[test]
    fn test_scan_with_sections_populates_va() {
        let s = scanner();
        let mut data = vec![0u8; 0x200];
        data[0x100..0x100 + 16].copy_from_slice(b"expand 32-byte k");
        let sections = [ConstSectionInfo {
            file_offset: 0x80,
            file_size: 0x180,
            virtual_address: 0x0040_1000,
        }];
        let matches = s.scan_with_sections(&data, &sections);
        let m = matches
            .iter()
            .find(|m| m.constant_name == "CHACHA20_CONST")
            .expect("chacha20 expected");
        // 0x100 - 0x80 = 0x80; 0x401000 + 0x80 = 0x401080
        assert_eq!(m.va, Some(0x0040_1080));
    }

    #[test]
    fn test_scan_rsa_oid() {
        let s = scanner();
        let data: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
        let matches = s.scan(data);
        assert!(
            matches.iter().any(|m| m.constant_name == "RSA_OID_RSAENCRYPTION"),
            "expected RSA OID match"
        );
    }

    // -- DES permutation table -----------------------------------------------

    #[test]
    fn test_des_ip_table() {
        let s = scanner();
        let ip: Vec<u8> = vec![58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4];
        let matches = s.scan(&ip);
        assert!(
            matches
                .iter()
                .any(|m| m.algorithms.iter().any(|a| a == "DES"))
        );
    }

    /// No constant in the built-in table may fire on featureless input.
    ///
    /// This pins the CLASS, not the two instances that prompted it: a future
    /// constant that happens to be all-zeroes, all-0xFF, or a small
    /// little-endian integer will fail here rather than quietly flooding every
    /// scan. Two such entries were shipped —
    ///   * `RIPEMD160_K0` = `00 00 00 00` (a real round constant), which
    ///     produced **8176 "RIPEMD-160" hits** on 8 KiB of zeroes;
    ///   * `AES_RCON_1` = `01 00 00 00`, the integer 1, at confidence 95.
    /// Both remain in the table as corroborating evidence; `scan` simply
    /// refuses to search for patterns that cannot discriminate.
    #[test]
    fn no_constant_fires_on_featureless_buffers() {
        let scanner = ConstantScanner::new();
        for (label, buf) in [
            ("zeroes", vec![0x00u8; 64 * 1024]),
            ("ones", vec![0xFFu8; 64 * 1024]),
            ("0xAA padding", vec![0xAAu8; 64 * 1024]),
        ] {
            let hits = scanner.scan(&buf);
            assert!(
                hits.is_empty(),
                "{} of {label} produced {} constant hits, e.g. {:?}",
                buf.len(),
                hits.len(),
                hits.first().map(|h| (&h.constant_name, &h.algorithms, h.confidence))
            );
        }
    }

    /// The guard must not have silenced the table: real constants still match.
    ///
    /// Positive control for the test above — without it, deleting every
    /// constant would also make `no_constant_fires_on_featureless_buffers`
    /// pass.
    #[test]
    fn real_constants_still_match_after_the_guard() {
        let scanner = ConstantScanner::new();
        // First 16 bytes of the AES forward S-box, embedded in noise.
        let sbox = [
            0x63u8, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7,
            0xab, 0x76,
        ];
        let mut buf = vec![0xAAu8; 512];
        buf[128..128 + sbox.len()].copy_from_slice(&sbox);
        let hits = scanner.scan(&buf);
        assert!(
            hits.iter().any(|h| h.algorithms.iter().any(|a| a.starts_with("AES"))),
            "the AES S-box must still be detected, got {:?}",
            hits.iter().map(|h| &h.constant_name).collect::<Vec<_>>()
        );
    }

    #[test]
    fn uninformative_pattern_classifies_the_two_shipped_offenders() {
        assert!(is_uninformative_pattern(&[]), "empty");
        assert!(is_uninformative_pattern(&[0x00, 0x00, 0x00, 0x00]), "RIPEMD160_K0");
        assert!(is_uninformative_pattern(&[0x01, 0x00, 0x00, 0x00]), "AES_RCON_1");
        assert!(is_uninformative_pattern(&[0xFF; 8]), "all-ones word");
        // Genuine signatures must NOT be classified as uninformative.
        assert!(!is_uninformative_pattern(&[0x63, 0x7c, 0x77, 0x7b]), "AES S-box head");
        assert!(!is_uninformative_pattern(b"OrpheanBeholderScryDoubt"), "bcrypt magic");
        // A long run with a single non-zero byte is still discriminating
        // enough to keep (the rule is deliberately limited to short words).
        let mut long = vec![0u8; 32];
        long[31] = 1;
        assert!(!is_uninformative_pattern(&long), "32-byte pattern");
    }
}
