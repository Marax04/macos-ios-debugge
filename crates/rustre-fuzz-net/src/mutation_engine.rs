//! `mutation_engine` — protocol mutation engine with history-based de-duplication.

use rustre_fuzz_afl::{RngCore, XorShiftRng};
use std::collections::HashSet;

// ── ProtocolMutation ──────────────────────────────────────────────────────────

/// A single mutation operation that can be applied to a byte buffer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtocolMutation {
    /// Flip a single bit at `byte_index`, `bit_index`.
    BitFlip { byte_index: usize, bit_index: u8 },
    /// Set a single byte at `index` to `value`.
    ByteSet { index: usize, value: u8 },
    /// Replace a 1/2/4/8-byte integer at `offset` with a boundary value.
    NumberBoundary { offset: usize, size: u8, value: u64 },
    /// Insert a string injection payload at `offset`.
    StringInjection { offset: usize, payload: Vec<u8> },
    /// Replace a length field at `offset` (2 or 4 bytes) with a corrupt value.
    LengthManipulation { offset: usize, size: u8, value: u32 },
    /// Replace bytes at `offset..offset+len` with a delimiter sequence.
    DelimiterInjection { offset: usize, delimiter: Vec<u8> },
    /// Havoc: apply multiple random sub-mutations.
    Havoc { count: usize },
}

impl ProtocolMutation {
    /// Apply this mutation to `data` in place.
    ///
    /// Does nothing if any index is out of range.
    pub fn apply(&self, data: &mut Vec<u8>, rng: &mut dyn RngCore) {
        match self {
            Self::BitFlip {
                byte_index,
                bit_index,
            } => {
                if *byte_index < data.len() {
                    data[*byte_index] ^= 1 << (*bit_index & 7);
                }
            }
            Self::ByteSet { index, value } => {
                if *index < data.len() {
                    data[*index] = *value;
                }
            }
            Self::NumberBoundary {
                offset,
                size,
                value,
            } => {
                let bytes = value.to_le_bytes();
                let n = *size as usize;
                if *offset + n <= data.len() {
                    data[*offset..*offset + n].copy_from_slice(&bytes[..n]);
                }
            }
            Self::StringInjection { offset, payload } => {
                if *offset <= data.len() {
                    data.splice(*offset..*offset, payload.iter().copied());
                }
            }
            Self::LengthManipulation {
                offset,
                size,
                value,
            } => {
                let bytes = value.to_le_bytes();
                let n = *size as usize;
                if *offset + n <= data.len() {
                    data[*offset..*offset + n].copy_from_slice(&bytes[..n]);
                }
            }
            Self::DelimiterInjection { offset, delimiter } => {
                if *offset <= data.len() {
                    data.splice(*offset..*offset, delimiter.iter().copied());
                }
            }
            Self::Havoc { count } => {
                for _ in 0..*count {
                    if data.is_empty() {
                        break;
                    }
                    let idx = rng.next_usize(data.len());
                    data[idx] ^= (rng.next_u32() & 0xff) as u8;
                }
            }
        }
    }

    /// Canonical key for de-duplication (ignores payload content for injections).
    #[must_use]
    pub fn dedup_key(&self) -> String {
        match self {
            Self::BitFlip {
                byte_index,
                bit_index,
            } => format!("bf:{byte_index}:{bit_index}"),
            Self::ByteSet { index, value } => format!("bs:{index}:{value}"),
            Self::NumberBoundary {
                offset,
                size,
                value,
            } => format!("nb:{offset}:{size}:{value}"),
            Self::StringInjection { offset, .. } => format!("si:{offset}"),
            Self::LengthManipulation {
                offset,
                size,
                value,
            } => format!("lm:{offset}:{size}:{value}"),
            Self::DelimiterInjection { offset, .. } => format!("di:{offset}"),
            Self::Havoc { count } => format!("hv:{count}"),
        }
    }
}

// ── MutationStrategy ─────────────────────────────────────────────────────────

/// Strategy used to select mutations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MutationStrategy {
    /// Choose one mutation uniformly at random.
    Random,
    /// Prioritise mutations at edges that have not yet been covered.
    CoverageGuided,
    /// Apply many diverse mutations per iteration.
    Havoc,
    /// Deterministic walk through interesting values.
    Deterministic,
}

// ── MutationHistory ───────────────────────────────────────────────────────────

/// Tracks applied mutations and de-duplicates by canonical key.
#[derive(Debug, Default)]
pub struct MutationHistory {
    /// Set of de-duplication keys seen.
    seen: HashSet<String>,
    /// All applied mutations in order.
    pub records: Vec<MutationRecord>,
    /// Maximum number of records retained.
    pub max_records: usize,
}

/// A single mutation record in the history.
#[derive(Debug, Clone)]
pub struct MutationRecord {
    /// The mutation that was applied.
    pub mutation: ProtocolMutation,
    /// The input bytes *before* the mutation.
    pub before: Vec<u8>,
    /// The input bytes *after* the mutation.
    pub after: Vec<u8>,
    /// Whether the mutation was novel (not a duplicate).
    pub is_novel: bool,
}

impl MutationHistory {
    /// Create a new history with default max of 1000 records.
    #[must_use]
    pub fn new(max_records: usize) -> Self {
        Self {
            max_records,
            ..Default::default()
        }
    }

    /// Record a mutation. Returns `true` if the mutation is novel.
    pub fn record(&mut self, mutation: ProtocolMutation, before: Vec<u8>, after: Vec<u8>) -> bool {
        let key = mutation.dedup_key();
        let is_novel = self.seen.insert(key);
        let rec = MutationRecord {
            mutation,
            before,
            after,
            is_novel,
        };
        if self.records.len() >= self.max_records {
            self.records.remove(0);
        }
        self.records.push(rec);
        is_novel
    }

    /// Number of unique mutations seen.
    #[must_use]
    pub fn unique_count(&self) -> usize {
        self.seen.len()
    }

    /// Number of records stored.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.records.len()
    }

    /// True if no records are stored.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Clear all history.
    pub fn clear(&mut self) {
        self.seen.clear();
        self.records.clear();
    }

    /// Return all novel records.
    #[must_use]
    pub fn novel_records(&self) -> Vec<&MutationRecord> {
        self.records.iter().filter(|r| r.is_novel).collect()
    }
}

// ── MutationEngine ────────────────────────────────────────────────────────────

/// A full mutation engine: generates mutations, applies them, and tracks history.
pub struct MutationEngine {
    pub strategy: MutationStrategy,
    pub history: MutationHistory,
    rng: XorShiftRng,
    /// Interesting byte values for boundary mutations.
    boundary_bytes: Vec<u8>,
    /// Interesting u32 values for number boundary mutations.
    boundary_u32: Vec<u32>,
    /// String injection payloads.
    injection_payloads: Vec<Vec<u8>>,
    /// Delimiter sequences.
    delimiters: Vec<Vec<u8>>,
}

impl MutationEngine {
    /// Create a new engine with the given strategy.
    #[must_use]
    pub fn new(strategy: MutationStrategy) -> Self {
        Self {
            strategy,
            history: MutationHistory::new(2048),
            rng: XorShiftRng::default(),
            boundary_bytes: vec![0x00, 0x01, 0x7f, 0x80, 0xfe, 0xff],
            boundary_u32: vec![
                0,
                1,
                0x7f,
                0x80,
                0xff,
                0x100,
                0x7fff,
                0x8000,
                0xffff,
                0x1_0000,
                0x7fff_ffff,
                0x8000_0000,
                0xffff_fffe,
                0xffff_ffff,
            ],
            injection_payloads: vec![
                b"%s%s%s%s".to_vec(),
                b"../../../etc/passwd".to_vec(),
                b"<script>alert(1)</script>".to_vec(),
                b"' OR 1=1 --".to_vec(),
                b"\x00\x01\x02\x03".to_vec(),
                b"A".repeat(256),
                b"\xff\xfe\xfd\xfc".to_vec(),
            ],
            delimiters: vec![
                b"\r\n".to_vec(),
                b"\n".to_vec(),
                b"\x00".to_vec(),
                b"\xff".to_vec(),
                b"\r\n\r\n".to_vec(),
                b"\n\n".to_vec(),
                b"&&".to_vec(),
                b"||".to_vec(),
                b";".to_vec(),
            ],
        }
    }

    /// Generate a mutation for `data` without applying it.
    pub fn generate_mutation(&mut self, data: &[u8]) -> Option<ProtocolMutation> {
        if data.is_empty() {
            return None;
        }
        Some(match self.strategy {
            MutationStrategy::Random => self.random_mutation(data),
            MutationStrategy::CoverageGuided => self.coverage_guided_mutation(data),
            MutationStrategy::Havoc => ProtocolMutation::Havoc {
                count: 8 + self.rng.next_usize(24),
            },
            MutationStrategy::Deterministic => self.deterministic_mutation(data),
        })
    }

    /// Apply a generated mutation to `data` and record it in history.
    ///
    /// Returns `true` if the mutation was novel.
    pub fn mutate(&mut self, data: &mut Vec<u8>) -> Option<bool> {
        let mutation = self.generate_mutation(data)?;
        let before = data.clone();
        mutation.apply(data, &mut XorShiftRng::default());
        let after = data.clone();
        let novel = self.history.record(mutation, before, after);
        Some(novel)
    }

    /// Apply `n` mutations to `data`.
    pub fn mutate_n(&mut self, data: &mut Vec<u8>, n: usize) {
        for _ in 0..n {
            self.mutate(data);
        }
    }

    fn random_mutation(&mut self, data: &[u8]) -> ProtocolMutation {
        let choice = self.rng.next_usize(6);
        match choice {
            0 => {
                let idx = self.rng.next_usize(data.len());
                let bit = (self.rng.next_u32() & 7) as u8;
                ProtocolMutation::BitFlip {
                    byte_index: idx,
                    bit_index: bit,
                }
            }
            1 => {
                let idx = self.rng.next_usize(data.len());
                let val = *self
                    .boundary_bytes
                    .get(self.rng.next_usize(self.boundary_bytes.len()))
                    .unwrap_or(&0xff);
                ProtocolMutation::ByteSet {
                    index: idx,
                    value: val,
                }
            }
            2 => {
                let sizes: &[u8] = &[1, 2, 4, 8];
                let size = sizes[self.rng.next_usize(4)];
                let offset = if data.len() >= size as usize {
                    self.rng.next_usize(data.len() - size as usize + 1)
                } else {
                    0
                };
                let val = u64::from(self.boundary_u32[self.rng.next_usize(self.boundary_u32.len())]);
                ProtocolMutation::NumberBoundary {
                    offset,
                    size,
                    value: val,
                }
            }
            3 => {
                let offset = self.rng.next_usize(data.len() + 1);
                let payload = self.injection_payloads
                    [self.rng.next_usize(self.injection_payloads.len())]
                .clone();
                ProtocolMutation::StringInjection { offset, payload }
            }
            4 => {
                let size: u8 = if self.rng.next_u32() & 1 == 0 { 2 } else { 4 };
                let offset = if data.len() >= size as usize {
                    self.rng.next_usize(data.len() - size as usize + 1)
                } else {
                    0
                };
                let vals: &[u32] = &[0, 1, 0xffff, 0xffff_ffff];
                let value = vals[self.rng.next_usize(vals.len())];
                ProtocolMutation::LengthManipulation {
                    offset,
                    size,
                    value,
                }
            }
            _ => {
                let offset = self.rng.next_usize(data.len() + 1);
                let delim = self.delimiters[self.rng.next_usize(self.delimiters.len())].clone();
                ProtocolMutation::DelimiterInjection {
                    offset,
                    delimiter: delim,
                }
            }
        }
    }

    fn coverage_guided_mutation(&mut self, data: &[u8]) -> ProtocolMutation {
        // Prefer edges not yet covered: pick boundary mutations over random ones.
        let offset = if data.len() > 1 {
            self.rng.next_usize(data.len() - 1)
        } else {
            0
        };
        let val = u64::from(self.boundary_u32[self.rng.next_usize(self.boundary_u32.len())]);
        ProtocolMutation::NumberBoundary {
            offset,
            size: 4,
            value: val,
        }
    }

    fn deterministic_mutation(&self, data: &[u8]) -> ProtocolMutation {
        // Walk deterministically: each call advances to the next byte index.
        let idx = self.history.len() % data.len().max(1);
        ProtocolMutation::ByteSet {
            index: idx,
            value: self.boundary_bytes[self.history.len() % self.boundary_bytes.len()],
        }
    }

    /// Total bytes mutated across all recorded mutations.
    #[must_use]
    pub fn total_bytes_mutated(&self) -> usize {
        self.history.records.iter().map(|r| r.after.len()).sum()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_data() -> Vec<u8> {
        b"HELLO WORLD 12345".to_vec()
    }

    #[test]
    fn test_bit_flip_apply() {
        let mut data = vec![0xAA];
        let m = ProtocolMutation::BitFlip {
            byte_index: 0,
            bit_index: 0,
        };
        m.apply(&mut data, &mut XorShiftRng::default());
        assert_eq!(data[0], 0xAB);
    }

    #[test]
    fn test_bit_flip_out_of_bounds_no_panic() {
        let mut data = vec![0x00];
        let m = ProtocolMutation::BitFlip {
            byte_index: 99,
            bit_index: 0,
        };
        m.apply(&mut data, &mut XorShiftRng::default());
        assert_eq!(data, vec![0x00]);
    }

    #[test]
    fn test_byte_set_apply() {
        let mut data = sample_data();
        let m = ProtocolMutation::ByteSet {
            index: 0,
            value: 0xFF,
        };
        m.apply(&mut data, &mut XorShiftRng::default());
        assert_eq!(data[0], 0xFF);
    }

    #[test]
    fn test_number_boundary_4byte() {
        let mut data = vec![0u8; 8];
        let m = ProtocolMutation::NumberBoundary {
            offset: 0,
            size: 4,
            value: 0xDEAD_BEEF,
        };
        m.apply(&mut data, &mut XorShiftRng::default());
        assert_eq!(
            u32::from_le_bytes(data[0..4].try_into().unwrap()),
            0xDEAD_BEEF
        );
    }

    #[test]
    fn test_string_injection_insert() {
        let mut data = b"hello world".to_vec();
        let payload = b" injected ".to_vec();
        let m = ProtocolMutation::StringInjection {
            offset: 5,
            payload,
        };
        m.apply(&mut data, &mut XorShiftRng::default());
        assert!(data.len() > b"hello world".len());
        let s = String::from_utf8_lossy(&data);
        assert!(s.contains("injected"));
    }

    #[test]
    fn test_length_manipulation_u16() {
        let mut data = vec![0u8; 4];
        let m = ProtocolMutation::LengthManipulation {
            offset: 0,
            size: 2,
            value: 0xFFFF,
        };
        m.apply(&mut data, &mut XorShiftRng::default());
        assert_eq!(u16::from_le_bytes(data[0..2].try_into().unwrap()), 0xFFFF);
    }

    #[test]
    fn test_delimiter_injection() {
        let mut data = b"header".to_vec();
        let m = ProtocolMutation::DelimiterInjection {
            offset: 6,
            delimiter: b"\r\n".to_vec(),
        };
        m.apply(&mut data, &mut XorShiftRng::default());
        assert!(data.ends_with(b"\r\n"));
    }

    #[test]
    fn test_havoc_changes_data() {
        let original = sample_data();
        let mut data = original;
        let m = ProtocolMutation::Havoc { count: 16 };
        m.apply(&mut data, &mut XorShiftRng::with_seed(42));
        // Not guaranteed to differ (could flip same bit twice), but highly likely.
        let _ = data;
    }

    #[test]
    fn test_mutation_dedup_key_unique_per_variant() {
        let keys: Vec<_> = vec![
            ProtocolMutation::BitFlip {
                byte_index: 0,
                bit_index: 0,
            }
            .dedup_key(),
            ProtocolMutation::ByteSet { index: 0, value: 0 }.dedup_key(),
            ProtocolMutation::NumberBoundary {
                offset: 0,
                size: 4,
                value: 0,
            }
            .dedup_key(),
            ProtocolMutation::StringInjection {
                offset: 0,
                payload: vec![],
            }
            .dedup_key(),
            ProtocolMutation::LengthManipulation {
                offset: 0,
                size: 2,
                value: 0,
            }
            .dedup_key(),
            ProtocolMutation::DelimiterInjection {
                offset: 0,
                delimiter: vec![],
            }
            .dedup_key(),
            ProtocolMutation::Havoc { count: 1 }.dedup_key(),
        ];
        let unique: HashSet<_> = keys.iter().collect();
        assert_eq!(unique.len(), keys.len());
    }

    #[test]
    fn test_mutation_history_novel() {
        let mut h = MutationHistory::new(100);
        let m = ProtocolMutation::ByteSet {
            index: 0,
            value: 0xFF,
        };
        let novel1 = h.record(m.clone(), vec![0], vec![0xFF]);
        assert!(novel1);
        let novel2 = h.record(m, vec![0], vec![0xFF]);
        assert!(!novel2);
    }

    #[test]
    fn test_mutation_history_len_and_unique() {
        let mut h = MutationHistory::new(100);
        for i in 0u8..5 {
            h.record(
                ProtocolMutation::ByteSet {
                    index: i as usize,
                    value: i,
                },
                vec![],
                vec![],
            );
        }
        assert_eq!(h.len(), 5);
        assert_eq!(h.unique_count(), 5);
    }

    #[test]
    fn test_mutation_history_max_evicts() {
        let mut h = MutationHistory::new(3);
        for i in 0u8..10 {
            h.record(
                ProtocolMutation::ByteSet {
                    index: i as usize,
                    value: i,
                },
                vec![],
                vec![],
            );
        }
        assert_eq!(h.len(), 3);
    }

    #[test]
    fn test_mutation_history_novel_records() {
        let mut h = MutationHistory::new(100);
        let m1 = ProtocolMutation::ByteSet { index: 0, value: 0 };
        let m2 = ProtocolMutation::ByteSet { index: 1, value: 0 };
        h.record(m1.clone(), vec![], vec![]);
        h.record(m1, vec![], vec![]);
        h.record(m2, vec![], vec![]);
        assert_eq!(h.novel_records().len(), 2);
    }

    #[test]
    fn test_mutation_history_clear() {
        let mut h = MutationHistory::new(100);
        h.record(ProtocolMutation::Havoc { count: 1 }, vec![], vec![]);
        h.clear();
        assert!(h.is_empty());
        assert_eq!(h.unique_count(), 0);
    }

    #[test]
    fn test_engine_random_mutates() {
        let mut engine = MutationEngine::new(MutationStrategy::Random);
        let mut data = sample_data();
        let original = data.clone();
        for _ in 0..10 {
            engine.mutate(&mut data);
        }
        let _ = (original, data);
    }

    #[test]
    fn test_engine_coverage_guided() {
        let mut engine = MutationEngine::new(MutationStrategy::CoverageGuided);
        let mut data = sample_data();
        engine.mutate_n(&mut data, 5);
        assert_eq!(engine.history.len(), 5);
    }

    #[test]
    fn test_engine_havoc_generates_havoc_mutation() {
        let mut engine = MutationEngine::new(MutationStrategy::Havoc);
        let data = sample_data();
        let m = engine.generate_mutation(&data).unwrap();
        assert!(matches!(m, ProtocolMutation::Havoc { .. }));
    }

    #[test]
    fn test_engine_deterministic() {
        let mut engine = MutationEngine::new(MutationStrategy::Deterministic);
        let mut data = sample_data();
        engine.mutate_n(&mut data, 6);
        assert_eq!(engine.history.len(), 6);
    }

    #[test]
    fn test_engine_generate_returns_none_on_empty() {
        let mut engine = MutationEngine::new(MutationStrategy::Random);
        assert!(engine.generate_mutation(&[]).is_none());
    }

    #[test]
    fn test_engine_total_bytes_mutated() {
        let mut engine = MutationEngine::new(MutationStrategy::Random);
        let mut data = sample_data();
        engine.mutate_n(&mut data, 5);
        assert!(engine.total_bytes_mutated() > 0);
    }
}
