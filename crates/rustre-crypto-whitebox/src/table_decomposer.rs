// rustre-crypto-whitebox/src/table_decomposer.rs
// Decomposes lookup tables found in whitebox implementations into their underlying operations.

use std::collections::HashMap;

/// Classification of what a lookup table represents.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TableKind {
    /// AES `SubBytes` (S-box or composition with key XOR).
    AesSBox,
    /// AES `InvSubBytes`.
    AesInvSBox,
    /// XOR with a fixed key byte: `f(x) = x XOR k`.
    KeyXor(u8),
    /// `MixColumns` coefficient: `f(x) = c * x` in `GF(2^8)`.
    MixColumnsMul(u8),
    /// AES T-box: `T[i](x) = MixColumns(SubBytes(x XOR k[i]))`.
    AesTBox { round: Option<usize>, key_byte: u8 },
    /// Identity permutation.
    Identity,
    /// XOR of two operations.
    Xor(Box<Self>, Box<Self>),
    /// Affine map over GF(2^8): f(x) = A*x XOR b.
    Affine { scale: u8, bias: u8 },
    /// Unknown / unclassified.
    Unknown,
}

impl TableKind {
    #[must_use]
    pub const fn is_aes_related(&self) -> bool {
        matches!(self, Self::AesSBox | Self::AesInvSBox | Self::AesTBox { .. })
    }
}

/// Decomposition result for a single 256-byte table.
#[derive(Debug, Clone)]
pub struct TableDecomposition {
    pub kind: TableKind,
    pub confidence: f64,
    pub description: String,
    pub extra: HashMap<String, String>,
}

impl TableDecomposition {
    #[must_use]
    fn new(kind: TableKind, confidence: f64, description: impl Into<String>) -> Self {
        Self {
            kind,
            confidence,
            description: description.into(),
            extra: HashMap::new(),
        }
    }
}

const SBOX: [u8; 256] = [
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
];

const INV_SBOX: [u8; 256] = [
    0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
    0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
    0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
    0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
    0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
    0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
    0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
    0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
    0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
    0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
    0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
    0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
    0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
    0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
    0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
    0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d,
];

fn gf_mul(mut a: u8, mut b: u8) -> u8 {
    let mut p = 0u8;
    for _ in 0..8 {
        if b & 1 != 0 { p ^= a; }
        let carry = a & 0x80;
        a <<= 1;
        if carry != 0 { a ^= 0x1b; }
        b >>= 1;
    }
    p
}

/// Main table decomposer.
pub struct TableDecomposer {
    pub check_tbox: bool,
    pub check_affine: bool,
}

impl Default for TableDecomposer {
    fn default() -> Self {
        Self { check_tbox: true, check_affine: true }
    }
}

impl TableDecomposer {
    #[must_use]
    pub fn new() -> Self { Self::default() }

    /// Decompose a 256-byte lookup table.
    #[must_use]
    pub fn decompose(&self, table: &[u8; 256]) -> TableDecomposition {
        // 1. Identity check.
        if let Some(d) = Self::check_identity(table) { return d; }
        // 2. AES SBox check.
        if let Some(d) = Self::check_aes_sbox(table) { return d; }
        // 3. AES InvSBox check.
        if let Some(d) = Self::check_aes_inv_sbox(table) { return d; }
        // 4. Shifted SBox (SBox XOR key byte).
        if let Some(d) = Self::check_shifted_sbox(table) { return d; }
        // 5. XOR with constant (key addition).
        if let Some(d) = Self::check_xor_const(table) { return d; }
        // 6. GF multiplication.
        if let Some(d) = Self::check_gf_mul(table) { return d; }
        // 7. T-box.
        if self.check_tbox && let Some(d) = Self::check_aes_tbox(table) { return d; }
        // 8. Affine map.
        if self.check_affine && let Some(d) = Self::check_affine_map(table) { return d; }
        // 9. Unknown.
        TableDecomposition::new(TableKind::Unknown, 0.0, "Unrecognised 256-byte table")
    }

    fn check_identity(t: &[u8; 256]) -> Option<TableDecomposition> {
        if (0..256).all(|i| t[i] == u8::try_from(i).unwrap_or(u8::MAX)) {
            Some(TableDecomposition::new(TableKind::Identity, 1.0, "Identity permutation f(x) = x"))
        } else { None }
    }

    fn check_aes_sbox(t: &[u8; 256]) -> Option<TableDecomposition> {
        if t == &SBOX {
            Some(TableDecomposition::new(TableKind::AesSBox, 1.0, "AES SubBytes S-box"))
        } else { None }
    }

    fn check_aes_inv_sbox(t: &[u8; 256]) -> Option<TableDecomposition> {
        if t == &INV_SBOX {
            Some(TableDecomposition::new(TableKind::AesInvSBox, 1.0, "AES InvSubBytes S-box"))
        } else { None }
    }

    fn check_shifted_sbox(t: &[u8; 256]) -> Option<TableDecomposition> {
        // Check if t[x] = SBOX[x XOR k] for some fixed k.
        for k in 0u8..=255 {
            if (0..256usize).all(|i| t[i] == SBOX[usize::from(u8::try_from(i).unwrap_or(u8::MAX) ^ k)]) {
                let desc = format!("AES SBox with key XOR 0x{k:02x}: f(x) = SBOX[x XOR 0x{k:02x}]");
                return Some(TableDecomposition::new(TableKind::AesTBox { round: None, key_byte: k }, 1.0, desc));
            }
        }
        // Check if t[x] = SBOX[x] XOR k (post-add key).
        for k in 1u8..=255 {
            if (0..256usize).all(|i| t[i] == SBOX[i] ^ k) {
                let desc = format!("AES SBox with output XOR 0x{k:02x}: f(x) = SBOX[x] XOR 0x{k:02x}");
                return Some(TableDecomposition::new(TableKind::AesTBox { round: None, key_byte: k }, 0.95, desc));
            }
        }
        None
    }

    fn check_xor_const(t: &[u8; 256]) -> Option<TableDecomposition> {
        // f(x) = x XOR k for some k.
        let k = t[0]; // If f(0) = k, then k = t[0] XOR 0 = t[0].
        if k != 0 && (0..256usize).all(|i| t[i] == u8::try_from(i).unwrap_or(u8::MAX) ^ k) {
            Some(TableDecomposition::new(
                TableKind::KeyXor(k),
                1.0,
                format!("Key addition: f(x) = x XOR 0x{k:02x}"),
            ))
        } else { None }
    }

    fn check_gf_mul(t: &[u8; 256]) -> Option<TableDecomposition> {
        // f(x) = c * x in GF(2^8) for c in {2,3,9,11,13,14} (AES MixColumns coefficients).
        for &coeff in &[2u8, 3, 9, 11, 13, 14] {
            if (0..256usize).all(|i| t[i] == gf_mul(coeff, u8::try_from(i).unwrap_or(u8::MAX))) {
                return Some(TableDecomposition::new(
                    TableKind::MixColumnsMul(coeff),
                    1.0,
                    format!("GF(2^8) multiplication by 0x{coeff:02x} (AES MixColumns coefficient)"),
                ));
            }
        }
        None
    }

    fn check_aes_tbox(t: &[u8; 256]) -> Option<TableDecomposition> {
        // T-box row 0: T[k](x) = [2*SBOX[x XOR k], 3*SBOX[x XOR k], SBOX[x XOR k], SBOX[x XOR k]].
        // We check only the first output byte (the 2* component).
        for k in 0u8..=255 {
            if (0..256usize).all(|i| t[i] == gf_mul(2, SBOX[usize::from(u8::try_from(i).unwrap_or(u8::MAX) ^ k)])) {
                return Some(TableDecomposition::new(
                    TableKind::AesTBox { round: None, key_byte: k },
                    0.95,
                    format!("AES T-box (MixCols row 0, key byte 0x{k:02x}): f(x) = 2*SBOX[x XOR 0x{k:02x}]"),
                ));
            }
            // Row 1: 3*SBOX[x XOR k].
            if (0..256usize).all(|i| t[i] == gf_mul(3, SBOX[usize::from(u8::try_from(i).unwrap_or(u8::MAX) ^ k)])) {
                return Some(TableDecomposition::new(
                    TableKind::AesTBox { round: None, key_byte: k },
                    0.95,
                    format!("AES T-box (MixCols row 1, key byte 0x{k:02x}): f(x) = 3*SBOX[x XOR 0x{k:02x}]"),
                ));
            }
        }
        None
    }

    fn check_affine_map(t: &[u8; 256]) -> Option<TableDecomposition> {
        // f(x) = scale * x XOR bias for some scale, bias.
        let bias = t[0]; // f(0) = scale*0 XOR bias = bias.
        for scale in 1u8..=255 {
            if (0..256usize).all(|i| t[i] == gf_mul(scale, u8::try_from(i).unwrap_or(u8::MAX)) ^ bias) {
                return Some(TableDecomposition::new(
                    TableKind::Affine { scale, bias },
                    0.90,
                    format!("Affine map: f(x) = 0x{scale:02x}*x XOR 0x{bias:02x} over GF(2^8)"),
                ));
            }
        }
        None
    }

    /// Decompose a sequence of 256-byte tables and summarise findings.
    #[must_use]
    pub fn decompose_all(&self, tables: &[[u8; 256]]) -> Vec<TableDecomposition> {
        tables.iter().map(|t| self.decompose(t)).collect()
    }

    /// Identify the AES round number from a series of T-boxes by checking which round
    /// key byte is embedded in each table.
    #[must_use]
    pub fn identify_round_from_tboxes(&self, tables: &[[u8; 256]]) -> Option<usize> {
        let decomposed = self.decompose_all(tables);
        let tbox_keys: Vec<u8> = decomposed.iter().filter_map(|d| {
            if let TableKind::AesTBox { key_byte, .. } = d.kind {
                Some(key_byte)
            } else { None }
        }).collect();

        if tbox_keys.len() < 4 { return None; }

        // Round 1: key bytes come from subkey 1 (bytes 16..32 of expanded key).
        // Without the full key schedule, we heuristically check if all key bytes are non-zero.
        let all_nonzero = tbox_keys.iter().all(|&k| k != 0);
        let all_zero = tbox_keys.iter().all(|&k| k == 0);
        if all_zero { Some(0) }          // Round 0 key addition (initial).
        else if all_nonzero { Some(1) }  // Likely round 1 or later.
        else { None }
    }
}

/// Check if a u32 table (1024 bytes) looks like an AES T-table (all four rows).
#[must_use]
pub fn is_aes_t_table(table: &[u32; 256]) -> bool {
    // T0[0] should be [2, 1, 1, 3] * SBOX[0] = [2, 1, 1, 3] * 0x63.
    let s = SBOX[0]; // 0x63
    let expected = (u32::from(gf_mul(2, s)) << 24)
        | (u32::from(s) << 16)
        | (u32::from(s) << 8)
        | u32::from(gf_mul(3, s));
    // Note: byte order depends on endianness; we check the most common form.
    table[0] == expected || table[0] == expected.swap_bytes()
}

/// Extract the T-box key byte embedded in a 256-byte table (if it is a T-box).
#[must_use]
pub fn extract_tbox_key(table: &[u8; 256]) -> Option<u8> {
    let decomp = TableDecomposer::default().decompose(table);
    if let TableKind::AesTBox { key_byte, .. } = decomp.kind {
        Some(key_byte)
    } else { None }
}

/// Score how "AES-like" a set of tables is (0.0 = not AES, 1.0 = definitely AES).
#[must_use]
pub fn aes_likeness_score(tables: &[[u8; 256]]) -> f64 {
    if tables.is_empty() { return 0.0; }
    let decomposer = TableDecomposer::default();
    let aes_count = tables.iter()
        .filter(|t| decomposer.decompose(t).kind.is_aes_related())
        .count();
    f64::from(u32::try_from(aes_count).unwrap_or(u32::MAX)) / f64::from(u32::try_from(tables.len()).unwrap_or(u32::MAX))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decomposes_identity() {
        let id: [u8; 256] = std::array::from_fn(|i| u8::try_from(i).unwrap_or(u8::MAX));
        let d = TableDecomposer::default().decompose(&id);
        assert_eq!(d.kind, TableKind::Identity);
        assert!((d.confidence - 1.0).abs() < 1e-9);
    }

    #[test]
    fn decomposes_aes_sbox() {
        let d = TableDecomposer::default().decompose(&SBOX);
        assert_eq!(d.kind, TableKind::AesSBox);
    }

    #[test]
    fn decomposes_key_xor() {
        let k = 0xab_u8;
        let t: [u8; 256] = std::array::from_fn(|i| u8::try_from(i).unwrap_or(u8::MAX) ^ k);
        let d = TableDecomposer::default().decompose(&t);
        assert_eq!(d.kind, TableKind::KeyXor(k));
    }

    #[test]
    fn decomposes_gf_mul2() {
        let t: [u8; 256] = std::array::from_fn(|i| gf_mul(2, u8::try_from(i).unwrap_or(u8::MAX)));
        let d = TableDecomposer::default().decompose(&t);
        assert_eq!(d.kind, TableKind::MixColumnsMul(2));
    }

    #[test]
    fn decomposes_shifted_sbox() {
        let k = 0x42_u8;
        let t: [u8; 256] = std::array::from_fn(|i| SBOX[usize::from(u8::try_from(i).unwrap_or(u8::MAX) ^ k)]);
        let d = TableDecomposer::default().decompose(&t);
        assert!(matches!(d.kind, TableKind::AesTBox { key_byte, .. } if key_byte == k));
    }

    #[test]
    fn aes_likeness_full_sbox_set() {
        let tables: Vec<[u8; 256]> = vec![SBOX; 16];
        let score = aes_likeness_score(&tables);
        assert!((score - 1.0).abs() < 1e-9);
    }

    #[test]
    fn aes_likeness_zero_for_unknown() {
        let tables: Vec<[u8; 256]> = vec![[0xaa; 256]; 4];
        let score = aes_likeness_score(&tables);
        assert!(score < 0.1);
    }
}
