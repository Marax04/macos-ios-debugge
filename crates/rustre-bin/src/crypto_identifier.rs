//! Cryptographic algorithm identifier — scans binary data for known constants.

use std::fmt;

// ─────────────────────────────────────────────────────────────────────────────
// Algorithm enum
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CryptoAlgorithm {
    AesSBox,
    AesInvSBox,
    AesRcon,
    Sha1K,
    Sha256K,
    Sha512K,
    DesPc1,
    DesPc2,
    DesIp,
    DesSboxes,
    Rc4Ksa,
    Md5K,
    Md5S,
    Crc32Table,
    Base64Table,
    BlowfishSBox,
    Camellia,
    Chacha20,
    Serpent,
    Twofish,
    ElGamal,
    Rsa,
    EcConstants,
}

impl CryptoAlgorithm {
    pub fn display_name(self) -> &'static str {
        match self {
            Self::AesSBox       => "AES S-Box",
            Self::AesInvSBox    => "AES Inverse S-Box",
            Self::AesRcon       => "AES Rcon",
            Self::Sha1K         => "SHA-1 K constants",
            Self::Sha256K       => "SHA-256 K constants",
            Self::Sha512K       => "SHA-512 K constants",
            Self::DesPc1        => "DES PC1 permutation",
            Self::DesPc2        => "DES PC2 permutation",
            Self::DesIp         => "DES IP permutation",
            Self::DesSboxes     => "DES S-boxes",
            Self::Rc4Ksa        => "RC4 KSA",
            Self::Md5K          => "MD5 K constants",
            Self::Md5S          => "MD5 S constants",
            Self::Crc32Table    => "CRC-32 table",
            Self::Base64Table   => "Base64 alphabet",
            Self::BlowfishSBox  => "Blowfish S-box",
            Self::Camellia      => "Camellia constants",
            Self::Chacha20      => "ChaCha20 sigma constant",
            Self::Serpent       => "Serpent S-box",
            Self::Twofish       => "Twofish MDS matrix",
            Self::ElGamal       => "El-Gamal parameters",
            Self::Rsa           => "RSA modulus/exponent marker",
            Self::EcConstants   => "Elliptic curve constants",
        }
    }
}

impl fmt::Display for CryptoAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.display_name())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Match record
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ConstantMatch {
    pub algorithm: CryptoAlgorithm,
    pub offset: u64,
    pub confidence: f64,
    pub description: String,
}

// ─────────────────────────────────────────────────────────────────────────────
// Report
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default)]
pub struct CryptoReport {
    pub matches: Vec<ConstantMatch>,
    pub unique_algorithms: Vec<CryptoAlgorithm>,
}

impl CryptoReport {
    fn build(matches: Vec<ConstantMatch>) -> Self {
        let mut unique: Vec<CryptoAlgorithm> = Vec::new();
        for m in &matches {
            if !unique.contains(&m.algorithm) {
                unique.push(m.algorithm);
            }
        }
        Self {
            matches,
            unique_algorithms: unique,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// AES S-box fingerprints
// ─────────────────────────────────────────────────────────────────────────────

/// First 16 bytes of the AES forward S-box.
const AES_SBOX_PREFIX: &[u8] = &[
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
    0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
];

/// First 16 bytes of the AES inverse S-box.
const AES_INV_SBOX_PREFIX: &[u8] = &[
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38,
    0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
];

/// First 10 bytes of the AES Rcon table.
const AES_RCON: &[u8] = &[
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36,
];

// ─────────────────────────────────────────────────────────────────────────────
// SHA constants
// ─────────────────────────────────────────────────────────────────────────────

/// SHA-1 K constants as little-endian bytes (first two values).
const SHA1_K_LE: &[u8] = &[
    0x67, 0x45, 0x23, 0x01, // H0 initial
    0xbb, 0x66, 0xa0, 0x5a, // K[0] = 0x5A827999 LE
];

/// SHA-256 first two K constants (big-endian uint32).
const SHA256_K_BE_PREFIX: &[u8] = &[
    0x42, 0x8a, 0x2f, 0x98, // K[0] = 0x428a2f98
    0x71, 0x37, 0x44, 0x91, // K[1] = 0x71374491
    0xb5, 0xc0, 0xfb, 0xcf, // K[2]
    0xe9, 0xb5, 0xdb, 0xa5, // K[3]
];

/// SHA-512 first two K constants (big-endian uint64, truncated to 8 bytes).
const SHA512_K_PREFIX: &[u8] = &[
    0x42, 0x8a, 0x2f, 0x98, 0xd7, 0x28, 0xae, 0x22,
];

// ─────────────────────────────────────────────────────────────────────────────
// MD5 constants
// ─────────────────────────────────────────────────────────────────────────────

/// MD5 T[1] constant = 0xd76aa478 in little-endian.
const MD5_K_LE_PREFIX: &[u8] = &[
    0x78, 0xa4, 0x6a, 0xd7, // T[1]
    0x56, 0xb3, 0xc1, 0xe8, // T[2]
    0xdb, 0x70, 0x2c, 0x24, // T[3]
];

/// MD5 S constants (per-round shift amounts, first 16).
const MD5_S: &[u8] = &[7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22];

// ─────────────────────────────────────────────────────────────────────────────
// CRC-32
// ─────────────────────────────────────────────────────────────────────────────

/// CRC-32 table entry [1] = 0x77073096 in little-endian.
const CRC32_ENTRY1_LE: &[u8] = &[0x96, 0x30, 0x07, 0x77];
/// CRC-32 table entry [2] = 0xEE0E612C in little-endian.
const CRC32_ENTRY2_LE: &[u8] = &[0x2c, 0x61, 0x0e, 0xee];

// ─────────────────────────────────────────────────────────────────────────────
// Base64
// ─────────────────────────────────────────────────────────────────────────────

const BASE64_TABLE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

// ─────────────────────────────────────────────────────────────────────────────
// ChaCha20
// ─────────────────────────────────────────────────────────────────────────────

/// "expand 32-byte k" ASCII sigma constant.
const CHACHA20_SIGMA: &[u8] = b"expand 32-byte k";

// ─────────────────────────────────────────────────────────────────────────────
// Blowfish
// ─────────────────────────────────────────────────────────────────────────────

/// First 8 bytes of Blowfish P-array (derived from π).
const BLOWFISH_P_PREFIX: &[u8] = &[
    0x24, 0x3f, 0x6a, 0x88, 0x85, 0xa3, 0x08, 0xd3,
];

// ─────────────────────────────────────────────────────────────────────────────
// DES constants
// ─────────────────────────────────────────────────────────────────────────────

/// DES PC-1 permutation table (first 8 values).
const DES_PC1_PREFIX: &[u8] = &[57, 49, 41, 33, 25, 17, 9, 1];

/// DES S-box 1 first row (first 8 values).
const DES_SBOX1_PREFIX: &[u8] = &[14, 4, 13, 1, 2, 15, 11, 8];

// ─────────────────────────────────────────────────────────────────────────────
// RC4
// ─────────────────────────────────────────────────────────────────────────────

/// RC4 KSA initialisation: bytes 0..7 of identity-permutation 0x00,0x01,...
const RC4_IDENTITY_PREFIX: &[u8] = &[0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];

// ─────────────────────────────────────────────────────────────────────────────
// Serpent
// ─────────────────────────────────────────────────────────────────────────────

/// Serpent PHI constant used in key schedule: 0x9E3779B9 LE.
const SERPENT_PHI: &[u8] = &[0xB9, 0x79, 0x37, 0x9E];

// ─────────────────────────────────────────────────────────────────────────────
// Twofish
// ─────────────────────────────────────────────────────────────────────────────

/// Twofish MDS matrix first row constants.
const TWOFISH_MDS: &[u8] = &[0x01, 0xEF, 0x5B, 0x5B];

// ─────────────────────────────────────────────────────────────────────────────
// Camellia
// ─────────────────────────────────────────────────────────────────────────────

/// Camellia SIGMA1 constant: 0xA09E667F3BCC908B (first 4 bytes BE).
const CAMELLIA_SIGMA1: &[u8] = &[0xA0, 0x9E, 0x66, 0x7F];

// ─────────────────────────────────────────────────────────────────────────────
// EC / RSA markers
// ─────────────────────────────────────────────────────────────────────────────

/// P-256 prime p first 4 bytes (big-endian): 0xFFFFFFFF.
const P256_PRIME_PREFIX: &[u8] = &[0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01];

/// RSA PKCS#1 DER header for 2048-bit key.
const RSA_DER_HEADER: &[u8] = &[0x30, 0x82];

// ─────────────────────────────────────────────────────────────────────────────
// Core scan helpers
// ─────────────────────────────────────────────────────────────────────────────

fn find_all(haystack: &[u8], needle: &[u8]) -> Vec<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return Vec::new();
    }
    let mut positions = Vec::new();
    let mut i = 0usize;
    while i + needle.len() <= haystack.len() {
        if haystack[i..i + needle.len()] == *needle {
            positions.push(i);
            i += needle.len(); // skip to avoid overlapping matches
        } else {
            i += 1;
        }
    }
    positions
}

/// Count how many bytes of a 256-byte S-box run are in the plausible 0x00–0xFF
/// range with no repeated values — an approximation of a bijective S-box.
fn looks_like_sbox_256(data: &[u8], offset: usize) -> bool {
    if offset + 256 > data.len() {
        return false;
    }
    let slice = &data[offset..offset + 256];
    let mut seen = [false; 256];
    for &b in slice {
        if seen[b as usize] {
            return false;
        }
        seen[b as usize] = true;
    }
    true
}

/// Detect a run of 256 little-endian u32 values that look like a CRC table:
/// all entries are unique and have only reasonable Hamming weight.
fn looks_like_crc32_table(data: &[u8], offset: usize) -> bool {
    if offset + 256 * 4 > data.len() {
        return false;
    }
    // First entry must be 0x00000000 or 0x77073096.
    let e0 = u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap_or([0; 4]));
    let e1 = u32::from_le_bytes(data[offset + 4..offset + 8].try_into().unwrap_or([0; 4]));
    (e0 == 0x00000000 && e1 == 0x77073096) || (e0 == 0x77073096)
}

// ─────────────────────────────────────────────────────────────────────────────
// CryptoIdentifier
// ─────────────────────────────────────────────────────────────────────────────

pub struct CryptoIdentifier<'a> {
    data: &'a [u8],
}

impl<'a> CryptoIdentifier<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data }
    }

    // ── Individual scanners ────────────────────────────────────────────────

    pub fn scan_for_aes(&self) -> Vec<ConstantMatch> {
        let mut out = Vec::new();
        for pos in find_all(self.data, AES_SBOX_PREFIX) {
            if looks_like_sbox_256(self.data, pos) {
                out.push(ConstantMatch {
                    algorithm: CryptoAlgorithm::AesSBox,
                    offset: pos as u64,
                    confidence: 0.97,
                    description: "AES forward S-box (256-byte bijection)".into(),
                });
            } else {
                out.push(ConstantMatch {
                    algorithm: CryptoAlgorithm::AesSBox,
                    offset: pos as u64,
                    confidence: 0.75,
                    description: "AES S-box prefix match".into(),
                });
            }
        }
        for pos in find_all(self.data, AES_INV_SBOX_PREFIX) {
            out.push(ConstantMatch {
                algorithm: CryptoAlgorithm::AesInvSBox,
                offset: pos as u64,
                confidence: 0.95,
                description: "AES inverse S-box prefix".into(),
            });
        }
        for pos in find_all(self.data, AES_RCON) {
            out.push(ConstantMatch {
                algorithm: CryptoAlgorithm::AesRcon,
                offset: pos as u64,
                confidence: 0.85,
                description: "AES Rcon table".into(),
            });
        }
        out
    }

    pub fn scan_for_sha256_k(&self) -> Vec<ConstantMatch> {
        let mut out = Vec::new();
        for pos in find_all(self.data, SHA256_K_BE_PREFIX) {
            out.push(ConstantMatch {
                algorithm: CryptoAlgorithm::Sha256K,
                offset: pos as u64,
                confidence: 0.96,
                description: "SHA-256 K constants (big-endian)".into(),
            });
        }
        for pos in find_all(self.data, SHA512_K_PREFIX) {
            out.push(ConstantMatch {
                algorithm: CryptoAlgorithm::Sha512K,
                offset: pos as u64,
                confidence: 0.90,
                description: "SHA-512 K constants prefix".into(),
            });
        }
        for pos in find_all(self.data, SHA1_K_LE) {
            out.push(ConstantMatch {
                algorithm: CryptoAlgorithm::Sha1K,
                offset: pos as u64,
                confidence: 0.70,
                description: "SHA-1 initial hash values (little-endian)".into(),
            });
        }
        out
    }

    pub fn scan_for_crc32(&self) -> Vec<ConstantMatch> {
        let mut out = Vec::new();
        for pos in find_all(self.data, CRC32_ENTRY1_LE) {
            // Verify the next entry too.
            if self.data.get(pos + 4..pos + 8) == Some(CRC32_ENTRY2_LE) {
                let conf = if looks_like_crc32_table(self.data, pos.saturating_sub(4)) {
                    0.98
                } else {
                    0.80
                };
                out.push(ConstantMatch {
                    algorithm: CryptoAlgorithm::Crc32Table,
                    offset: pos as u64,
                    confidence: conf,
                    description: "CRC-32 lookup table".into(),
                });
            }
        }
        out
    }

    pub fn scan_for_md5_k(&self) -> Vec<ConstantMatch> {
        let mut out = Vec::new();
        for pos in find_all(self.data, MD5_K_LE_PREFIX) {
            out.push(ConstantMatch {
                algorithm: CryptoAlgorithm::Md5K,
                offset: pos as u64,
                confidence: 0.88,
                description: "MD5 T-constant array (little-endian)".into(),
            });
        }
        for pos in find_all(self.data, MD5_S) {
            out.push(ConstantMatch {
                algorithm: CryptoAlgorithm::Md5S,
                offset: pos as u64,
                confidence: 0.60,
                description: "MD5 per-round shift amounts".into(),
            });
        }
        out
    }

    pub fn scan_for_base64(&self) -> Vec<ConstantMatch> {
        let mut out = Vec::new();
        // Search for the standard 64-char table prefix.
        for pos in find_all(self.data, &BASE64_TABLE[..16]) {
            // Verify 64-byte extent.
            let end = pos + 64;
            if end <= self.data.len() && &self.data[pos..end] == BASE64_TABLE {
                out.push(ConstantMatch {
                    algorithm: CryptoAlgorithm::Base64Table,
                    offset: pos as u64,
                    confidence: 0.99,
                    description: "Base64 standard alphabet".into(),
                });
            } else {
                out.push(ConstantMatch {
                    algorithm: CryptoAlgorithm::Base64Table,
                    offset: pos as u64,
                    confidence: 0.65,
                    description: "Base64-like alphabet prefix".into(),
                });
            }
        }
        out
    }

    pub fn scan_for_chacha20(&self) -> Vec<ConstantMatch> {
        find_all(self.data, CHACHA20_SIGMA)
            .into_iter()
            .map(|pos| ConstantMatch {
                algorithm: CryptoAlgorithm::Chacha20,
                offset: pos as u64,
                confidence: 0.99,
                description: "ChaCha20 sigma constant \"expand 32-byte k\"".into(),
            })
            .collect()
    }

    pub fn scan_for_blowfish(&self) -> Vec<ConstantMatch> {
        find_all(self.data, BLOWFISH_P_PREFIX)
            .into_iter()
            .map(|pos| ConstantMatch {
                algorithm: CryptoAlgorithm::BlowfishSBox,
                offset: pos as u64,
                confidence: 0.88,
                description: "Blowfish P-array (π-derived)".into(),
            })
            .collect()
    }

    pub fn scan_for_des(&self) -> Vec<ConstantMatch> {
        let mut out = Vec::new();
        for pos in find_all(self.data, DES_PC1_PREFIX) {
            out.push(ConstantMatch {
                algorithm: CryptoAlgorithm::DesPc1,
                offset: pos as u64,
                confidence: 0.82,
                description: "DES PC-1 permutation table".into(),
            });
        }
        for pos in find_all(self.data, DES_SBOX1_PREFIX) {
            out.push(ConstantMatch {
                algorithm: CryptoAlgorithm::DesSboxes,
                offset: pos as u64,
                confidence: 0.70,
                description: "DES S-box 1 row 0".into(),
            });
        }
        out
    }

    pub fn scan_for_rc4(&self) -> Vec<ConstantMatch> {
        // RC4 identity permutation is very common but 8-byte prefix is
        // also common in other contexts; require at least 32 sequential bytes.
        let mut out = Vec::new();
        for pos in find_all(self.data, RC4_IDENTITY_PREFIX) {
            let end = pos + 256;
            if end <= self.data.len() {
                let identity_ok = self.data[pos..end]
                    .iter()
                    .enumerate()
                    .all(|(i, &b)| b == i as u8);
                let conf = if identity_ok { 0.72 } else { 0.30 };
                out.push(ConstantMatch {
                    algorithm: CryptoAlgorithm::Rc4Ksa,
                    offset: pos as u64,
                    confidence: conf,
                    description: "RC4 identity permutation (pre-KSA)".into(),
                });
            }
        }
        out
    }

    pub fn scan_for_serpent(&self) -> Vec<ConstantMatch> {
        find_all(self.data, SERPENT_PHI)
            .into_iter()
            .map(|pos| ConstantMatch {
                algorithm: CryptoAlgorithm::Serpent,
                offset: pos as u64,
                confidence: 0.80,
                description: "Serpent key schedule PHI constant".into(),
            })
            .collect()
    }

    pub fn scan_for_twofish(&self) -> Vec<ConstantMatch> {
        find_all(self.data, TWOFISH_MDS)
            .into_iter()
            .map(|pos| ConstantMatch {
                algorithm: CryptoAlgorithm::Twofish,
                offset: pos as u64,
                confidence: 0.75,
                description: "Twofish MDS matrix entry".into(),
            })
            .collect()
    }

    pub fn scan_for_camellia(&self) -> Vec<ConstantMatch> {
        find_all(self.data, CAMELLIA_SIGMA1)
            .into_iter()
            .map(|pos| ConstantMatch {
                algorithm: CryptoAlgorithm::Camellia,
                offset: pos as u64,
                confidence: 0.85,
                description: "Camellia SIGMA1 constant".into(),
            })
            .collect()
    }

    pub fn scan_for_ec(&self) -> Vec<ConstantMatch> {
        find_all(self.data, P256_PRIME_PREFIX)
            .into_iter()
            .map(|pos| ConstantMatch {
                algorithm: CryptoAlgorithm::EcConstants,
                offset: pos as u64,
                confidence: 0.92,
                description: "NIST P-256 prime".into(),
            })
            .collect()
    }

    pub fn scan_for_rsa(&self) -> Vec<ConstantMatch> {
        find_all(self.data, RSA_DER_HEADER)
            .into_iter()
            .map(|pos| ConstantMatch {
                algorithm: CryptoAlgorithm::Rsa,
                offset: pos as u64,
                confidence: 0.50,
                description: "RSA/DER SEQUENCE header".into(),
            })
            .collect()
    }

    // ── Master scan ───────────────────────────────────────────────────────

    /// Run all scanners and return merged, sorted matches.
    pub fn scan_all(&self) -> Vec<ConstantMatch> {
        let mut all: Vec<ConstantMatch> = Vec::new();
        all.extend(self.scan_for_aes());
        all.extend(self.scan_for_sha256_k());
        all.extend(self.scan_for_crc32());
        all.extend(self.scan_for_md5_k());
        all.extend(self.scan_for_base64());
        all.extend(self.scan_for_chacha20());
        all.extend(self.scan_for_blowfish());
        all.extend(self.scan_for_des());
        all.extend(self.scan_for_rc4());
        all.extend(self.scan_for_serpent());
        all.extend(self.scan_for_twofish());
        all.extend(self.scan_for_camellia());
        all.extend(self.scan_for_ec());
        all.extend(self.scan_for_rsa());
        all.sort_by(|a, b| {
            b.confidence
                .partial_cmp(&a.confidence)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| a.offset.cmp(&b.offset))
        });
        all
    }

    pub fn report(&self) -> CryptoReport {
        CryptoReport::build(self.scan_all())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_data_with(prefix: &[u8], extra: usize) -> Vec<u8> {
        let mut v = vec![0u8; 16];
        v.extend_from_slice(prefix);
        v.extend(vec![0u8; extra]);
        v
    }

    #[test]
    fn test_aes_sbox_prefix() {
        let data = make_data_with(AES_SBOX_PREFIX, 240);
        let id = CryptoIdentifier::new(&data);
        let matches = id.scan_for_aes();
        assert!(!matches.is_empty());
        assert_eq!(matches[0].algorithm, CryptoAlgorithm::AesSBox);
    }

    #[test]
    fn test_aes_inv_sbox_prefix() {
        let data = make_data_with(AES_INV_SBOX_PREFIX, 240);
        let id = CryptoIdentifier::new(&data);
        let matches = id.scan_for_aes();
        assert!(matches.iter().any(|m| m.algorithm == CryptoAlgorithm::AesInvSBox));
    }

    #[test]
    fn test_aes_rcon() {
        let data = make_data_with(AES_RCON, 10);
        let id = CryptoIdentifier::new(&data);
        let matches = id.scan_for_aes();
        assert!(matches.iter().any(|m| m.algorithm == CryptoAlgorithm::AesRcon));
    }

    #[test]
    fn test_sha256_k() {
        let data = make_data_with(SHA256_K_BE_PREFIX, 0);
        let id = CryptoIdentifier::new(&data);
        let matches = id.scan_for_sha256_k();
        assert!(!matches.is_empty());
        assert_eq!(matches[0].algorithm, CryptoAlgorithm::Sha256K);
    }

    #[test]
    fn test_crc32_detection() {
        let mut data = vec![0u8; 8];
        // CRC32 table[1]=0x77073096 then table[2]=0xEE0E612C LE
        data.extend_from_slice(CRC32_ENTRY1_LE);
        data.extend_from_slice(CRC32_ENTRY2_LE);
        let id = CryptoIdentifier::new(&data);
        let matches = id.scan_for_crc32();
        assert!(!matches.is_empty());
    }

    #[test]
    fn test_md5_k() {
        let data = make_data_with(MD5_K_LE_PREFIX, 0);
        let id = CryptoIdentifier::new(&data);
        let matches = id.scan_for_md5_k();
        assert!(!matches.is_empty());
    }

    #[test]
    fn test_base64_full_table() {
        let mut data = vec![0u8; 4];
        data.extend_from_slice(BASE64_TABLE);
        let id = CryptoIdentifier::new(&data);
        let matches = id.scan_for_base64();
        assert!(!matches.is_empty());
        assert!(matches[0].confidence > 0.9);
    }

    #[test]
    fn test_chacha20_sigma() {
        let data = make_data_with(CHACHA20_SIGMA, 0);
        let id = CryptoIdentifier::new(&data);
        let matches = id.scan_for_chacha20();
        assert_eq!(matches.len(), 1);
        assert!((matches[0].confidence - 0.99).abs() < 0.01);
    }

    #[test]
    fn test_blowfish() {
        let data = make_data_with(BLOWFISH_P_PREFIX, 0);
        let id = CryptoIdentifier::new(&data);
        let matches = id.scan_for_blowfish();
        assert!(!matches.is_empty());
    }

    #[test]
    fn test_des_pc1() {
        let data = make_data_with(DES_PC1_PREFIX, 0);
        let id = CryptoIdentifier::new(&data);
        let matches = id.scan_for_des();
        assert!(!matches.is_empty());
    }

    #[test]
    fn test_rc4_identity() {
        let identity: Vec<u8> = (0u8..=255).collect();
        let id = CryptoIdentifier::new(&identity);
        let matches = id.scan_for_rc4();
        assert!(!matches.is_empty());
        // Full 256-byte identity → higher confidence
        assert!(matches[0].confidence > 0.5);
    }

    #[test]
    fn test_serpent_phi() {
        let data = make_data_with(SERPENT_PHI, 0);
        let id = CryptoIdentifier::new(&data);
        let matches = id.scan_for_serpent();
        assert!(!matches.is_empty());
    }

    #[test]
    fn test_ec_p256() {
        let data = make_data_with(P256_PRIME_PREFIX, 0);
        let id = CryptoIdentifier::new(&data);
        let matches = id.scan_for_ec();
        assert!(!matches.is_empty());
        assert_eq!(matches[0].algorithm, CryptoAlgorithm::EcConstants);
    }

    #[test]
    fn test_scan_all_sorted_by_confidence() {
        let mut data = Vec::new();
        data.extend_from_slice(CHACHA20_SIGMA);
        data.extend_from_slice(SHA256_K_BE_PREFIX);
        let id = CryptoIdentifier::new(&data);
        let all = id.scan_all();
        // Verify descending confidence order.
        for w in all.windows(2) {
            assert!(w[0].confidence >= w[1].confidence);
        }
    }

    #[test]
    fn test_report_unique_algorithms() {
        let mut data = vec![0u8; 16];
        data.extend_from_slice(CHACHA20_SIGMA);
        data.extend_from_slice(CHACHA20_SIGMA); // duplicate
        let id = CryptoIdentifier::new(&data);
        let report = id.report();
        let chacha_count = report
            .unique_algorithms
            .iter()
            .filter(|&&a| a == CryptoAlgorithm::Chacha20)
            .count();
        assert_eq!(chacha_count, 1);
    }

    #[test]
    fn test_empty_data() {
        let id = CryptoIdentifier::new(&[]);
        let all = id.scan_all();
        assert!(all.is_empty());
    }

    #[test]
    fn test_find_all_no_match() {
        let found = find_all(&[0x00, 0x01, 0x02], &[0xFF]);
        assert!(found.is_empty());
    }
}
