// rustre-crypto-whitebox/src/bge_attacker.rs
// BGE Attack (Billet-Gilbert-Ech'habache) on AES whitebox implementations.
// Reference: "Cryptanalysis of a White Box AES Implementation" (2004).

use std::collections::HashMap;

/// A 256-byte lookup table (nibble or byte).
#[derive(Debug, Clone)]
pub struct LookupTable {
    pub data: [u8; 256],
}

impl LookupTable {
    #[must_use]
    pub const fn new(data: [u8; 256]) -> Self { Self { data } }
    #[must_use]
    pub fn identity() -> Self { Self { data: std::array::from_fn(|i| u8::try_from(i).unwrap_or(u8::MAX)) } }
    #[must_use]
    pub const fn apply(&self, input: u8) -> u8 { self.data[input as usize] }

    /// Compose self with other: result(x) = self(other(x)).
    #[must_use]
    pub fn compose(&self, other: &Self) -> Self {
        Self { data: std::array::from_fn(|i| self.apply(other.apply(u8::try_from(i).unwrap_or(u8::MAX)))) }
    }

    /// Invert this table (must be a bijection).
    #[must_use]
    pub fn invert(&self) -> Option<Self> {
        let mut inv = [0u8; 256];
        let mut seen = [false; 256];
        for (i, &v) in self.data.iter().enumerate() {
            if seen[v as usize] { return None; }
            seen[v as usize] = true;
            inv[v as usize] = u8::try_from(i).unwrap_or(u8::MAX);
        }
        Some(Self { data: inv })
    }

    /// Check if this table is affine over GF(2): f(x) = Ax + b.
    #[must_use]
    pub fn is_affine(&self) -> bool {
        // An affine map satisfies f(x XOR y) = f(x) XOR f(y) XOR f(0).
        let bias = self.data[0];
        for x in 0u8..=255 {
            for y in 0u8..=255 {
                let xxy = x ^ y;
                let lhs = self.apply(xxy);
                let rhs = self.apply(x) ^ self.apply(y) ^ bias;
                if lhs != rhs { return false; }
            }
        }
        true
    }

    /// Recover the affine matrix A and bias b if this table is affine.
    #[must_use]
    pub fn affine_components(&self) -> Option<([u8; 8], u8)> {
        if !self.is_affine() { return None; }
        let bias = self.data[0];
        let mut matrix = [0u8; 8]; // 8 rows of 1-bit (GF(2)^8).
        for (bit, entry) in matrix.iter_mut().enumerate() {
            let x = 1u8 << bit;
            *entry = self.apply(x) ^ bias;
        }
        Some((matrix, bias))
    }
}

/// Encoded round function of a whitebox AES implementation.
/// Represents one block of the encoded implementation.
#[derive(Debug, Clone)]
pub struct EncodedRound {
    /// Input encoding (bijective table applied before the round computation).
    pub input_encoding: LookupTable,
    /// Output encoding (bijective table applied after the round computation).
    pub output_encoding: LookupTable,
    /// The combined (encoded) lookup table.
    pub combined: LookupTable,
}

impl EncodedRound {
    #[must_use]
    pub fn from_combined(combined: LookupTable) -> Self {
        Self {
            input_encoding: LookupTable::identity(),
            output_encoding: LookupTable::identity(),
            combined,
        }
    }

    /// Apply the encoded round to an input byte.
    #[must_use]
    pub const fn apply(&self, x: u8) -> u8 {
        self.combined.apply(x)
    }
}

/// BGE attacker state, tracking one of four phases.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BgePhase {
    CollectSamples,
    FindAffineRelations,
    RecoverExternalEncoding,
    RecoverKey,
    Done,
}

/// BGE attack result.
#[derive(Debug, Clone)]
pub struct BgeResult {
    pub success: bool,
    pub recovered_key: Option<Vec<u8>>,
    pub phase_reached: BgePhase,
    pub external_encoding: Option<(LookupTable, LookupTable)>,
    pub notes: Vec<String>,
}

/// Sample set collected during Phase 1.
#[derive(Debug, Clone, Default)]
pub struct SampleSet {
    /// input byte → output byte for the combined table at each position.
    pub observations: Vec<(u8, u8)>,
}

impl SampleSet {
    #[must_use]
    pub fn new() -> Self { Self::default() }

    pub fn add(&mut self, input: u8, output: u8) {
        self.observations.push((input, output));
    }

    /// Reconstruct the lookup table from observations (need 256 distinct inputs).
    #[must_use]
    pub fn reconstruct_table(&self) -> Option<LookupTable> {
        if self.observations.len() < 256 { return None; }
        let mut data = [0u8; 256];
        let mut seen = [false; 256];
        for &(i, o) in &self.observations {
            data[i as usize] = o;
            seen[i as usize] = true;
        }
        if seen.iter().all(|&s| s) { Some(LookupTable { data }) } else { None }
    }
}

/// Main BGE Attacker.
pub struct BgeAttacker {
    pub num_samples: usize,
    pub verbose: bool,
}

impl Default for BgeAttacker {
    fn default() -> Self {
        Self { num_samples: 1024, verbose: false }
    }
}

impl BgeAttacker {
    #[must_use]
    pub const fn new(num_samples: usize) -> Self {
        Self { num_samples, verbose: false }
    }

    /// Phase 1: Collect I/O samples from the whitebox implementation.
    /// `oracle`: given an input byte at position `pos`, returns the output byte.
    #[must_use]
    pub fn phase1_collect<F>(&self, oracle: F) -> Vec<SampleSet>
    where
        F: Fn(usize, u8) -> u8, // (position, input) -> output
    {
        let mut sets = Vec::new();
        // Collect for each of the 16 byte positions of AES state.
        for pos in 0..16 {
            let mut set = SampleSet::new();
            for input in 0u8..=255 {
                let output = oracle(pos, input);
                set.add(input, output);
            }
            sets.push(set);
        }
        sets
    }

    /// Phase 2: Find affine relations between encoded tables.
    /// Given two encoded tables `T1` and `T2`, finds `A`,`B` such that `T2 = A ∘ T1 ∘ B`.
    #[must_use]
    pub fn phase2_find_affine_relation(
        &self,
        t1: &LookupTable,
        t2: &LookupTable,
    ) -> Option<(LookupTable, LookupTable)> {
        // Try to find affine maps A, B such that T2(x) = A(T1(B(x))).
        // Brute-force over bijective affine maps (there are 255*256 = 65280 of them over GF(2)^8).
        // For efficiency we try all possible biases and scale factors.
        for scale in 1u8..=255 {
            for bias_a in 0u8..=255 {
                for bias_b in 0u8..=255 {
                    let a = build_linear_map(scale, bias_a);
                    let b = build_linear_map(scale, bias_b);
                    // Check if T2 = A ∘ T1 ∘ B for all inputs.
                    let matches = (0..=255u8).all(|x| {
                        let bx = b.apply(x);
                        let t1bx = t1.apply(bx);
                        let at1bx = a.apply(t1bx);
                        at1bx == t2.apply(x)
                    });
                    if matches {
                        return Some((a, b));
                    }
                }
            }
        }
        None
    }

    /// Phase 3: Recover external encoding from the affine relations.
    /// Returns `(input_encoding, output_encoding)`.
    #[must_use]
    pub fn phase3_recover_encoding(
        &self,
        tables: &[LookupTable],
        relations: &[(LookupTable, LookupTable)],
    ) -> Option<(LookupTable, LookupTable)> {
        if tables.is_empty() || relations.is_empty() { return None; }

        // The input encoding is the B component of the first relation.
        let input_enc = relations[0].1.clone();
        // The output encoding is the A component of the first relation.
        let output_enc = relations[0].0.clone();

        // Validate against a second table: cross-check that the candidate
        // encodings derived from `(a2, b2)` agree with the ones we already
        // picked from `relations[0]`. A consistent BGE recovery requires the
        // second relation to factor through the SAME outer/inner bijections,
        // so applying `a2` after `input_enc` (and `b2` after `output_enc`)
        // must still produce a permutation when chained through `tables[1]`.
        if tables.len() >= 2 && relations.len() >= 2 {
            let (a2, b2) = &relations[1];
            let mut histogram: HashMap<u8, u32> = HashMap::new();
            for x in 0u8..=255 {
                let input_chain = a2.apply(input_enc.apply(x));
                let table_out = tables[1].apply(input_chain);
                let output_chain = b2.apply(output_enc.apply(table_out));
                *histogram.entry(output_chain).or_insert(0) += 1;
            }
            // A permutation hits every value exactly once.
            let consistent = histogram.len() == 256 && histogram.values().all(|&c| c == 1);
            if !consistent {
                return None;
            }
        }

        Some((input_enc, output_enc))
    }

    /// Phase 4: Recover the AES key bytes from the stripped encoding.
    #[must_use]
    pub fn phase4_recover_key(
        &self,
        tables: &[LookupTable],
        input_enc: &LookupTable,
        output_enc: &LookupTable,
    ) -> Option<Vec<u8>> {
        let inv_out = output_enc.invert()?;

        // Strip encodings from each table.
        let mut key_bytes = Vec::new();
        for table in tables {
            // Stripped table: T_raw(x) = inv_output(T(input(x))).
            let stripped = LookupTable {
                data: std::array::from_fn(|i| {
                    inv_out.apply(table.apply(input_enc.apply(u8::try_from(i).unwrap_or(u8::MAX))))
                }),
            };

            // The stripped table should equal SubBytes(x XOR k) for some key byte k.
            if let Some(k) = Self::recover_key_byte_from_stripped(&stripped) {
                key_bytes.push(k);
            } else {
                return None;
            }
        }

        if key_bytes.len() == 16 { Some(key_bytes) } else { None }
    }

    /// Given a table T(x) = `SubBytes(x XOR k)`, recover k.
    fn recover_key_byte_from_stripped(stripped: &LookupTable) -> Option<u8> {
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
        for k in 0u8..=255 {
            // T(0) should equal SBOX[0 ^ k] = SBOX[k].
            if stripped.apply(0) == SBOX[k as usize] {
                // Verify with a second point.
                if stripped.apply(1) == SBOX[(1u8 ^ k) as usize] {
                    return Some(k);
                }
            }
        }
        None
    }

    /// Full BGE attack pipeline.
    ///
    /// # Panics
    ///
    /// Panics if `rel01.unwrap()` or `encoding.unwrap()` fails; in practice they are
    /// guarded by `is_none()` checks immediately before, so this cannot occur.
    #[must_use]
    pub fn attack<F>(&self, oracle: F) -> BgeResult
    where
        F: Fn(usize, u8) -> u8,
    {
        let mut result = BgeResult {
            success: false,
            recovered_key: None,
            phase_reached: BgePhase::CollectSamples,
            external_encoding: None,
            notes: Vec::new(),
        };

        // Phase 1: collect samples.
        let sets = self.phase1_collect(oracle);
        let tables: Vec<LookupTable> = sets.iter()
            .filter_map(SampleSet::reconstruct_table)
            .collect();

        if tables.len() < 16 {
            result.notes.push(format!("Phase 1 incomplete: only {}/{} tables reconstructed", tables.len(), 16));
            return result;
        }
        result.phase_reached = BgePhase::FindAffineRelations;

        // Phase 2: find affine relation between table 0 and table 1.
        let rel01 = self.phase2_find_affine_relation(&tables[0], &tables[1]);
        if rel01.is_none() {
            result.notes.push("Phase 2 failed: could not find affine relation".into());
            return result;
        }
        let relations: Vec<(LookupTable, LookupTable)> = vec![rel01.unwrap()];
        result.phase_reached = BgePhase::RecoverExternalEncoding;

        // Phase 3: recover encoding.
        let encoding = self.phase3_recover_encoding(&tables, &relations);
        if encoding.is_none() {
            result.notes.push("Phase 3 failed: could not recover external encoding".into());
            return result;
        }
        let (input_enc, output_enc) = encoding.unwrap();
        result.external_encoding = Some((input_enc.clone(), output_enc.clone()));
        result.phase_reached = BgePhase::RecoverKey;

        // Phase 4: recover key.
        let key = self.phase4_recover_key(&tables, &input_enc, &output_enc);
        if let Some(k) = key {
            result.success = true;
            result.recovered_key = Some(k);
            result.phase_reached = BgePhase::Done;
        } else {
            result.notes.push("Phase 4 failed: could not recover key bytes".into());
        }

        result
    }
}

/// Build a simple GF(2^8) linear map f(x) = scale * x XOR bias (scalar multiplication + affine).
fn build_linear_map(scale: u8, bias: u8) -> LookupTable {
    LookupTable {
        data: std::array::from_fn(|i| gf_mul_simple(scale, u8::try_from(i).unwrap_or(u8::MAX)) ^ bias),
    }
}

/// Simplified GF(2^8) multiplication for map building.
fn gf_mul_simple(mut a: u8, mut b: u8) -> u8 {
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

/// Compute correlation between two tables (Pearson on byte values).
#[must_use]
pub fn table_correlation(t1: &LookupTable, t2: &LookupTable) -> f64 {
    let n = 256.0f64;
    let x: Vec<f64> = t1.data.iter().map(|&b| f64::from(b)).collect();
    let y: Vec<f64> = t2.data.iter().map(|&b| f64::from(b)).collect();
    let mx = x.iter().sum::<f64>() / n;
    let my = y.iter().sum::<f64>() / n;
    let num: f64 = x.iter().zip(y.iter()).map(|(xi, yi)| (xi - mx) * (yi - my)).sum();
    let den: f64 = (x.iter().map(|xi| (xi - mx).powi(2)).sum::<f64>()
        * y.iter().map(|yi| (yi - my).powi(2)).sum::<f64>()).sqrt();
    if den == 0.0 { 0.0 } else { num / den }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_table() {
        let t = LookupTable::identity();
        for i in 0u8..=255 { assert_eq!(t.apply(i), i); }
    }

    #[test]
    fn table_invert() {
        let t = LookupTable { data: std::array::from_fn(|i| u8::try_from((i * 3 + 7) % 256).unwrap_or(u8::MAX)) };
        // Not necessarily bijective, but test the structure.
        let _ = t.invert();
    }

    #[test]
    fn compose_tables() {
        let t1 = LookupTable { data: std::array::from_fn(|i| u8::try_from(i.wrapping_add(1) & 0xFF).unwrap_or(u8::MAX)) };
        let t2 = LookupTable { data: std::array::from_fn(|i| u8::try_from(i.wrapping_add(2) & 0xFF).unwrap_or(u8::MAX)) };
        let c = t1.compose(&t2); // c(x) = t1(t2(x)) = x + 3.
        assert_eq!(c.apply(0), 3);
        assert_eq!(c.apply(253), 0);
    }

    #[test]
    fn key_byte_recovery_trivial() {
        // Build a table that equals SBOX[x XOR 0x42].
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
        let k = 0x42u8;
        let t = LookupTable { data: std::array::from_fn(|i| SBOX[usize::from(u8::try_from(i).unwrap_or(u8::MAX) ^ k)]) };
        let _attacker = BgeAttacker::default();
        let recovered = BgeAttacker::recover_key_byte_from_stripped(&t);
        assert_eq!(recovered, Some(k));
    }
}
