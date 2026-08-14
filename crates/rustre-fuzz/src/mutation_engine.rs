// mutation_engine.rs — Universal mutation engine for RustRE

// ─── Constants ────────────────────────────────────────────────────────────────

pub const INTERESTING_U8: &[u8] = &[0, 1, 16, 32, 64, 127, 128, 255];
pub const INTERESTING_U16: &[u16] = &[0, 1, 128, 255, 256, 512, 1024, 32767, 32768, 65535];
pub const INTERESTING_U32: &[u32] = &[
    0, 1, 128, 255, 256, 65535, 65536, 0x7fff_ffff, 0x8000_0000, 0xffff_ffff,
];

// ─── xorshift64 ───────────────────────────────────────────────────────────────

pub fn xorshift64(state: &mut u64) -> u64 {
    let mut x = *state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    *state = x;
    x
}

// ─── MutationType ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MutationType {
    BitFlip,
    ByteFlip,
    ByteInsert,
    ByteDelete,
    ByteRepeat,
    BlockSwap,
    Arithmetic { delta: i8 },
    InterestingByte,
    InterestingWord,
    InterestingDword,
    XorByte { key: u8 },
    ShuffleBlock,
    Crossover(Vec<u8>),
    DictionaryInsert(Vec<u8>),
    TruncateEnd,
    ExtendWithRandom,
}

impl MutationType {
    pub fn name(&self) -> &'static str {
        match self {
            Self::BitFlip => "bit_flip",
            Self::ByteFlip => "byte_flip",
            Self::ByteInsert => "byte_insert",
            Self::ByteDelete => "byte_delete",
            Self::ByteRepeat => "byte_repeat",
            Self::BlockSwap => "block_swap",
            Self::Arithmetic { .. } => "arithmetic",
            Self::InterestingByte => "interesting_byte",
            Self::InterestingWord => "interesting_word",
            Self::InterestingDword => "interesting_dword",
            Self::XorByte { .. } => "xor_byte",
            Self::ShuffleBlock => "shuffle_block",
            Self::Crossover(_) => "crossover",
            Self::DictionaryInsert(_) => "dict_insert",
            Self::TruncateEnd => "truncate_end",
            Self::ExtendWithRandom => "extend_random",
        }
    }
}

// ─── MutationConfig ───────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct MutationConfig {
    pub max_mutations_per_round: u32,
    pub dictionary: Vec<Vec<u8>>,
    pub max_output_size: usize,
    pub seed: u64,
}

impl Default for MutationConfig {
    fn default() -> Self {
        Self {
            max_mutations_per_round: 8,
            dictionary: Vec::new(),
            max_output_size: 65536,
            seed: 0xcafebabe_deadbeef,
        }
    }
}

// ─── MutationHistory ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default)]
pub struct MutationHistory {
    pub mutations_applied: Vec<MutationType>,
    pub original_hash: u64,
}

impl MutationHistory {
    pub fn new(original_data: &[u8]) -> Self {
        Self {
            mutations_applied: Vec::new(),
            original_hash: fnv64(original_data),
        }
    }

    pub fn record(&mut self, m: MutationType) {
        self.mutations_applied.push(m);
    }

    pub fn len(&self) -> usize {
        self.mutations_applied.len()
    }

    pub fn is_empty(&self) -> bool {
        self.mutations_applied.is_empty()
    }
}

fn fnv64(data: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf29ce484222325;
    for &b in data {
        hash ^= b as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

// ─── apply_mutation ───────────────────────────────────────────────────────────

/// Apply a single mutation to `data` and return the mutated output.
pub fn apply_mutation(data: &[u8], mutation: MutationType, rng: &mut u64, max_size: usize) -> Vec<u8> {
    let mut out = data.to_vec();
    if out.is_empty() && !matches!(mutation, MutationType::ExtendWithRandom) {
        return out;
    }

    match mutation {
        MutationType::BitFlip => {
            let idx = (xorshift64(rng) % out.len().max(1) as u64) as usize;
            let bit = (xorshift64(rng) % 8) as u8;
            if idx < out.len() {
                out[idx] ^= 1 << bit;
            }
        }

        MutationType::ByteFlip => {
            let idx = (xorshift64(rng) % out.len().max(1) as u64) as usize;
            if idx < out.len() {
                out[idx] = (xorshift64(rng) & 0xff) as u8;
            }
        }

        MutationType::ByteInsert => {
            if out.len() < max_size {
                let pos = (xorshift64(rng) % (out.len() + 1) as u64) as usize;
                let b = (xorshift64(rng) & 0xff) as u8;
                out.insert(pos, b);
            }
        }

        MutationType::ByteDelete => {
            if !out.is_empty() {
                let pos = (xorshift64(rng) % out.len() as u64) as usize;
                out.remove(pos);
            }
        }

        MutationType::ByteRepeat => {
            if !out.is_empty() && out.len() < max_size {
                let idx = (xorshift64(rng) % out.len() as u64) as usize;
                let b = out[idx];
                let count = 1 + (xorshift64(rng) % 16) as usize;
                let actual = count.min(max_size - out.len());
                let tail: Vec<u8> = out[idx..].to_vec();
                out.truncate(idx);
                for _ in 0..actual {
                    out.push(b);
                }
                out.extend_from_slice(&tail);
            }
        }

        MutationType::BlockSwap => {
            if out.len() >= 4 {
                let half = out.len() / 2;
                let a_start = (xorshift64(rng) % half as u64) as usize;
                let b_start = half + (xorshift64(rng) % half as u64) as usize;
                let swap_len = 1 + (xorshift64(rng) % (half.min(out.len() - b_start)) as u64) as usize;
                let b_end = (b_start + swap_len).min(out.len());
                let a_end = (a_start + swap_len).min(half);
                let block_a: Vec<u8> = out[a_start..a_end].to_vec();
                let block_b: Vec<u8> = out[b_start..b_end].to_vec();
                let a_len = a_end - a_start;
                let b_len = b_end - b_start;
                if a_len == b_len {
                    out[a_start..a_end].copy_from_slice(&block_b);
                    out[b_start..b_end].copy_from_slice(&block_a);
                }
            }
        }

        MutationType::Arithmetic { delta } => {
            let idx = (xorshift64(rng) % out.len().max(1) as u64) as usize;
            if idx < out.len() {
                out[idx] = (out[idx] as i16).wrapping_add(delta as i16) as u8;
            }
        }

        MutationType::InterestingByte => {
            let idx = (xorshift64(rng) % out.len().max(1) as u64) as usize;
            let vi = (xorshift64(rng) % INTERESTING_U8.len() as u64) as usize;
            if idx < out.len() {
                out[idx] = INTERESTING_U8[vi];
            }
        }

        MutationType::InterestingWord => {
            if out.len() >= 2 {
                let idx = (xorshift64(rng) % (out.len() - 1) as u64) as usize;
                let vi = (xorshift64(rng) % INTERESTING_U16.len() as u64) as usize;
                let val = INTERESTING_U16[vi];
                out[idx] = (val & 0xff) as u8;
                out[idx + 1] = (val >> 8) as u8;
            }
        }

        MutationType::InterestingDword => {
            if out.len() >= 4 {
                let idx = (xorshift64(rng) % (out.len() - 3) as u64) as usize;
                let vi = (xorshift64(rng) % INTERESTING_U32.len() as u64) as usize;
                let val = INTERESTING_U32[vi];
                out[idx] = (val & 0xff) as u8;
                out[idx + 1] = ((val >> 8) & 0xff) as u8;
                out[idx + 2] = ((val >> 16) & 0xff) as u8;
                out[idx + 3] = ((val >> 24) & 0xff) as u8;
            }
        }

        MutationType::XorByte { key } => {
            let idx = (xorshift64(rng) % out.len().max(1) as u64) as usize;
            if idx < out.len() {
                out[idx] ^= key;
            }
        }

        MutationType::ShuffleBlock => {
            if out.len() >= 2 {
                let start = (xorshift64(rng) % (out.len() - 1) as u64) as usize;
                let len = 2 + (xorshift64(rng) % (out.len() - start).min(16) as u64) as usize;
                let end = (start + len).min(out.len());
                // Fisher-Yates shuffle of the block
                for i in (start + 1..end).rev() {
                    let j = start + (xorshift64(rng) % (i - start + 1) as u64) as usize;
                    out.swap(i, j);
                }
            }
        }

        MutationType::Crossover(other) => {
            if !other.is_empty() && out.len() < max_size {
                let src_start = (xorshift64(rng) % other.len() as u64) as usize;
                let chunk_len = 1 + (xorshift64(rng) % (other.len() - src_start).min(32) as u64) as usize;
                let chunk = &other[src_start..src_start + chunk_len];
                if out.len() + chunk.len() <= max_size {
                    let pos = (xorshift64(rng) % (out.len() + 1) as u64) as usize;
                    let tail: Vec<u8> = out[pos..].to_vec();
                    out.truncate(pos);
                    out.extend_from_slice(chunk);
                    out.extend_from_slice(&tail);
                }
            }
        }

        MutationType::DictionaryInsert(entry) => {
            if !entry.is_empty() && out.len() + entry.len() <= max_size {
                let pos = (xorshift64(rng) % (out.len() + 1) as u64) as usize;
                let tail: Vec<u8> = out[pos..].to_vec();
                out.truncate(pos);
                out.extend_from_slice(&entry);
                out.extend_from_slice(&tail);
            }
        }

        MutationType::TruncateEnd => {
            if out.len() > 1 {
                let keep = 1 + (xorshift64(rng) % (out.len() - 1) as u64) as usize;
                out.truncate(keep);
            }
        }

        MutationType::ExtendWithRandom => {
            let extra = 1 + (xorshift64(rng) % 32) as usize;
            let actual = extra.min(max_size.saturating_sub(out.len()));
            for _ in 0..actual {
                out.push((xorshift64(rng) & 0xff) as u8);
            }
        }
    }

    out
}

// ─── weighted_choice ─────────────────────────────────────────────────────────

/// Select a mutation type by weighted random choice.
pub fn weighted_choice(weights: &[(MutationType, u32)], rng: &mut u64) -> MutationType {
    let total: u32 = weights.iter().map(|(_, w)| w).sum();
    if total == 0 {
        return MutationType::BitFlip;
    }
    let r = (xorshift64(rng) % total as u64) as u32;
    let mut acc = 0u32;
    for (mutation, weight) in weights {
        acc += weight;
        if r < acc {
            return mutation.clone();
        }
    }
    weights.last().map(|(m, _)| m.clone()).unwrap_or(MutationType::BitFlip)
}

// ─── MutationEngine ───────────────────────────────────────────────────────────

pub struct MutationEngine {
    pub config: MutationConfig,
    rng: u64,
}

impl MutationEngine {
    pub fn new(config: MutationConfig) -> Self {
        let seed = config.seed;
        Self {
            config,
            rng: if seed == 0 { 0xdeadbeef12345678 } else { seed },
        }
    }

    pub fn rand_below(&mut self, n: u64) -> u64 {
        if n == 0 { return 0; }
        xorshift64(&mut self.rng) % n
    }

    /// Generate a random delta for arithmetic mutations.
    fn random_delta(&mut self) -> i8 {
        let v = self.rand_below(35) as i8;
        v - 17
    }

    /// Build a default weight table covering all mutation types.
    pub fn default_weights(&self) -> Vec<(MutationType, u32)> {
        vec![
            (MutationType::BitFlip, 10),
            (MutationType::ByteFlip, 10),
            (MutationType::ByteInsert, 8),
            (MutationType::ByteDelete, 8),
            (MutationType::ByteRepeat, 5),
            (MutationType::BlockSwap, 4),
            (MutationType::Arithmetic { delta: 1 }, 8),
            (MutationType::InterestingByte, 9),
            (MutationType::InterestingWord, 7),
            (MutationType::InterestingDword, 6),
            (MutationType::XorByte { key: 0xff }, 5),
            (MutationType::ShuffleBlock, 4),
            (MutationType::TruncateEnd, 5),
            (MutationType::ExtendWithRandom, 5),
        ]
    }

    /// Pick a random mutation type from the default weights.
    pub fn pick_mutation(&mut self) -> MutationType {
        let weights = self.default_weights();
        // Inline weighted selection to avoid borrow issues
        let total: u32 = weights.iter().map(|(_, w)| w).sum();
        let r = (xorshift64(&mut self.rng) % total as u64) as u32;
        let mut acc = 0u32;
        for (mutation, weight) in &weights {
            acc += weight;
            if r < acc {
                // Specialize parameterized mutations
                return match mutation {
                    MutationType::Arithmetic { .. } => MutationType::Arithmetic { delta: self.random_delta() },
                    MutationType::XorByte { .. } => MutationType::XorByte { key: (xorshift64(&mut self.rng) & 0xff) as u8 },
                    other => other.clone(),
                };
            }
        }
        MutationType::BitFlip
    }

    /// Apply a single randomly-chosen mutation.
    pub fn mutate_once(&mut self, data: &[u8]) -> (Vec<u8>, MutationType) {
        let mutation = self.pick_mutation();
        let dict_entry = if !self.config.dictionary.is_empty() {
            let i = (xorshift64(&mut self.rng) % self.config.dictionary.len() as u64) as usize;
            self.config.dictionary[i].clone()
        } else {
            vec![0xde, 0xad]
        };
        let effective_mutation = match &mutation {
            MutationType::DictionaryInsert(_) => MutationType::DictionaryInsert(dict_entry),
            other => other.clone(),
        };
        let max = self.config.max_output_size;
        let result = apply_mutation(data, effective_mutation.clone(), &mut self.rng, max);
        (result, effective_mutation)
    }

    /// Apply `n` mutations in sequence, tracking history.
    pub fn mutate_with_history(&mut self, data: &[u8], n: u32) -> (Vec<u8>, MutationHistory) {
        let mut history = MutationHistory::new(data);
        let mut current = data.to_vec();
        for _ in 0..n {
            let (mutated, mutation) = self.mutate_once(&current);
            history.record(mutation);
            current = mutated;
        }
        (current, history)
    }

    /// Apply mutations from explicit list for deterministic replay.
    pub fn replay(&mut self, data: &[u8], mutations: &[MutationType]) -> Vec<u8> {
        let mut current = data.to_vec();
        for m in mutations {
            let max = self.config.max_output_size;
            current = apply_mutation(&current, m.clone(), &mut self.rng, max);
        }
        current
    }

    /// Run a full mutation round: pick 1..=max_mutations_per_round mutations.
    pub fn run_round(&mut self, data: &[u8]) -> Vec<u8> {
        let n = 1 + self.rand_below(self.config.max_mutations_per_round as u64) as u32;
        let (result, _) = self.mutate_with_history(data, n);
        result
    }

    /// Generate `count` mutated variants of `data`.
    pub fn generate_variants(&mut self, data: &[u8], count: usize) -> Vec<Vec<u8>> {
        (0..count).map(|_| self.run_round(data)).collect()
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_engine() -> MutationEngine {
        MutationEngine::new(MutationConfig { seed: 42, ..Default::default() })
    }

    fn rng() -> u64 { 0x123456789abcdefu64 }

    #[test]
    fn test_bit_flip_changes_one_bit() {
        let data = vec![0u8; 8];
        let mut r = rng();
        let out = apply_mutation(&data, MutationType::BitFlip, &mut r, 1024);
        let diffs: usize = data.iter().zip(out.iter()).map(|(a, b)| (a ^ b).count_ones() as usize).sum();
        assert_eq!(diffs, 1);
    }

    #[test]
    fn test_byte_delete_reduces_length() {
        let data = vec![1, 2, 3, 4, 5];
        let mut r = rng();
        let out = apply_mutation(&data, MutationType::ByteDelete, &mut r, 1024);
        assert_eq!(out.len(), 4);
    }

    #[test]
    fn test_byte_insert_increases_length() {
        let data = vec![1, 2, 3];
        let mut r = rng();
        let out = apply_mutation(&data, MutationType::ByteInsert, &mut r, 1024);
        assert_eq!(out.len(), 4);
    }

    #[test]
    fn test_truncate_end_shorter() {
        let data = vec![1, 2, 3, 4, 5, 6];
        let mut r = rng();
        let out = apply_mutation(&data, MutationType::TruncateEnd, &mut r, 1024);
        assert!(out.len() < data.len());
    }

    #[test]
    fn test_extend_with_random_longer() {
        let data = vec![1, 2, 3];
        let mut r = rng();
        let out = apply_mutation(&data, MutationType::ExtendWithRandom, &mut r, 1024);
        assert!(out.len() > data.len());
    }

    #[test]
    fn test_interesting_byte_in_list() {
        let data = vec![0xAAu8; 16];
        let mut r = rng();
        let out = apply_mutation(&data, MutationType::InterestingByte, &mut r, 1024);
        let changed_bytes: Vec<u8> = out.iter().copied().filter(|&b| b != 0xAA).collect();
        for b in &changed_bytes {
            assert!(INTERESTING_U8.contains(b));
        }
    }

    #[test]
    fn test_xor_byte_flips_bits() {
        let data = vec![0xFFu8; 4];
        let mut r = rng();
        let out = apply_mutation(&data, MutationType::XorByte { key: 0x0F }, &mut r, 1024);
        let changed = out.iter().zip(data.iter()).filter(|(a, b)| a != b).count();
        assert_eq!(changed, 1);
    }

    #[test]
    fn test_crossover_merges_data() {
        let data = vec![0u8; 8];
        let other = vec![0xFFu8; 8];
        let mut r = rng();
        let out = apply_mutation(&data, MutationType::Crossover(other), &mut r, 1024);
        assert!(out.iter().any(|&b| b == 0xFF));
    }

    #[test]
    fn test_arithmetic_within_byte_range() {
        let data = vec![100u8; 4];
        let mut r = rng();
        let out = apply_mutation(&data, MutationType::Arithmetic { delta: 5 }, &mut r, 1024);
        // at least one byte changed
        assert_ne!(out, data);
    }

    #[test]
    fn test_interesting_dword_sets_known_value() {
        let data = vec![0u8; 8];
        let mut r = 1u64;
        let out = apply_mutation(&data, MutationType::InterestingDword, &mut r, 1024);
        // The interesting value is written at some `idx` in [0, len-3].
        // Verify that at least one 4-byte window decodes to a known value.
        let found = (0..=out.len() - 4).any(|i| {
            let val = u32::from_le_bytes([out[i], out[i + 1], out[i + 2], out[i + 3]]);
            INTERESTING_U32.contains(&val)
        });
        assert!(found);
    }

    #[test]
    fn test_dictionary_insert() {
        let data = vec![0u8; 4];
        let entry = vec![0xDE, 0xAD];
        let mut r = rng();
        let out = apply_mutation(&data, MutationType::DictionaryInsert(entry.clone()), &mut r, 1024);
        assert!(out.len() >= data.len() + entry.len());
        assert!(out.windows(entry.len()).any(|w| w == entry.as_slice()));
    }

    #[test]
    fn test_mutation_engine_run_round_nonempty() {
        let mut eng = make_engine();
        let data = vec![1, 2, 3, 4, 5];
        let out = eng.run_round(&data);
        assert!(!out.is_empty());
    }

    #[test]
    fn test_mutation_history_tracks_mutations() {
        let mut eng = make_engine();
        let data = vec![0u8; 32];
        let (_, hist) = eng.mutate_with_history(&data, 5);
        assert_eq!(hist.len(), 5);
    }

    #[test]
    fn test_generate_variants_count() {
        let mut eng = make_engine();
        let data = vec![0xABu8; 16];
        let variants = eng.generate_variants(&data, 10);
        assert_eq!(variants.len(), 10);
    }

    #[test]
    fn test_weighted_choice_respects_zero_weight() {
        let weights = vec![
            (MutationType::BitFlip, 0u32),
            (MutationType::ByteFlip, 10u32),
        ];
        let mut r = rng();
        let chosen = weighted_choice(&weights, &mut r);
        assert_eq!(chosen, MutationType::ByteFlip);
    }

    #[test]
    fn test_fnv64_stable() {
        let data = b"hello world";
        let h1 = super::fnv64(data);
        let h2 = super::fnv64(data);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_shuffle_block_same_bytes_different_order() {
        let data: Vec<u8> = (0..32).collect();
        let mut r = 777u64;
        let out = apply_mutation(&data, MutationType::ShuffleBlock, &mut r, 1024);
        assert_eq!(out.len(), data.len());
        // Same multiset
        let mut a = data.clone();
        let mut b = out.clone();
        a.sort();
        b.sort();
        assert_eq!(a, b);
    }
}
