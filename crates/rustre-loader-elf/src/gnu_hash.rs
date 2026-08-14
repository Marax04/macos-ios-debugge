//! GNU hash table (`.gnu.hash` section) parser.
//!
//! The GNU hash format supersedes the old `SysV` hash table.  It uses a DJB2
//! hash combined with a Bloom filter for accelerated negative-lookup rejection.

// ─────────────────────────────────────────────────────────────────────────────
// GNU hash algorithm
// ─────────────────────────────────────────────────────────────────────────────

/// Compute the GNU ELF hash (DJB2 variant) of `name`.
///
/// This is the hash function used in `.gnu.hash` sections.
#[must_use]
pub fn gnu_hash(name: &[u8]) -> u32 {
    let mut h: u32 = 5381;
    for &b in name {
        h = h.wrapping_mul(33).wrapping_add(u32::from(b));
    }
    h
}

/// Compute the GNU ELF hash of a NUL-terminated C string.
#[must_use]
pub fn gnu_hash_str(name: &str) -> u32 {
    gnu_hash(name.as_bytes())
}

// ─────────────────────────────────────────────────────────────────────────────
// GnuBloomFilter
// ─────────────────────────────────────────────────────────────────────────────

/// Bloom filter from a `.gnu.hash` section.
///
/// The Bloom filter allows quick rejection: if a symbol's hash is NOT in the
/// filter, the symbol is definitely absent from the hash table.
#[derive(Debug, Clone)]
pub struct GnuBloomFilter {
    /// Bloom words (each is `bloom_shift`-wide; width is 32 or 64 depending on ELF class).
    words: Vec<u64>,
    /// Shift value from the header.
    shift2: u32,
    /// Word width in bits (32 for ELF32, 64 for ELF64).
    word_bits: u32,
}

impl GnuBloomFilter {
    /// Create a Bloom filter from raw `words`, `shift2`, and `word_bits`.
    #[must_use]
    pub const fn new(words: Vec<u64>, shift2: u32, word_bits: u32) -> Self {
        Self {
            words,
            shift2,
            word_bits,
        }
    }

    /// Returns `false` if `hash` is **definitely not** in the symbol table,
    /// or `true` if it **may** be present (false positives are possible).
    #[must_use]
    pub fn might_contain(&self, hash: u32) -> bool {
        if self.words.is_empty() || self.word_bits == 0 {
            return true; // no filter — assume present
        }
        let n = u32::try_from(self.words.len()).unwrap_or(u32::MAX);
        let bit_mask = self.word_bits - 1;
        let word_idx = ((hash / self.word_bits) % n) as usize;
        let bit1 = hash & bit_mask;
        let bit2 = (hash >> self.shift2) & bit_mask;
        let word = self.words[word_idx];
        (word >> bit1) & 1 == 1 && (word >> bit2) & 1 == 1
    }

    /// Compute Bloom filter false-positive rate (approximate).
    ///
    /// Based on the formula: `(1 - e^(-k*n/m))^k` where k=2 bits per element.
    #[must_use]
    pub fn false_positive_rate(&self, num_symbols: usize) -> f64 {
        if self.words.is_empty() || num_symbols == 0 {
            return 0.0;
        }
        let m = f64::from(u32::try_from(self.words.len() * (self.word_bits as usize)).unwrap_or(u32::MAX));
        let k = 2.0f64; // always 2 bits per element in GNU hash
        let n = f64::from(u32::try_from(num_symbols).unwrap_or(u32::MAX));
        (1.0 - (-k * n / m).exp()).powf(k)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// GnuHashTable
// ─────────────────────────────────────────────────────────────────────────────

/// Parsed `.gnu.hash` section.
#[derive(Debug, Clone)]
pub struct GnuHashTable {
    /// Number of hash buckets.
    pub nbuckets: u32,
    /// Index of the first symbol in the hash table (symbols before this are
    /// local and not hashed).
    pub symoffset: u32,
    /// Bloom filter.
    pub bloom: GnuBloomFilter,
    /// Hash buckets: each entry is the index of the first symbol with that
    /// hash, or 0 if the bucket is empty.
    pub buckets: Vec<u32>,
    /// Hash chain: parallel to the dynamic symbol table (starting at
    /// `symoffset`).  The low bit is the "end of chain" marker.
    pub chain: Vec<u32>,
}

impl GnuHashTable {
    /// Parse a `.gnu.hash` section for a 64-bit ELF.
    ///
    /// # Errors
    /// Returns `Err(String)` if the data is too short or malformed.
    pub fn parse64(data: &[u8], le: bool) -> Result<Self, String> {
        if data.len() < 16 {
            return Err("gnu.hash section too short".into());
        }
        let read_u32 = |off: usize| -> Result<u32, String> {
            let arr: [u8; 4] = data.get(off..off + 4)
                .and_then(|b| b.try_into().ok())
                .ok_or_else(|| format!("read_u32 out of bounds at {off}"))?;
            Ok(if le { u32::from_le_bytes(arr) } else { u32::from_be_bytes(arr) })
        };
        let read_u64 = |off: usize| -> Result<u64, String> {
            let arr: [u8; 8] = data.get(off..off + 8)
                .and_then(|b| b.try_into().ok())
                .ok_or_else(|| format!("read_u64 out of bounds at {off}"))?;
            Ok(if le { u64::from_le_bytes(arr) } else { u64::from_be_bytes(arr) })
        };

        let nbuckets = read_u32(0)?;
        let symoffset = read_u32(4)?;
        let bloom_size_raw = read_u32(8)?;
        let bloom_size = bloom_size_raw as usize; // in 64-bit words
        let bloom_shift = read_u32(12)?;

        let bloom_off = 16usize;
        let bloom_bytes = bloom_size
            .checked_mul(8)
            .ok_or_else(|| format!("gnu.hash: bloom_size {bloom_size} overflows"))?;
        // Cap capacity to what actually fits in the buffer (alloc-DoS hardening);
        // the reads below still error out on truncated data.
        let mut bloom_words =
            Vec::with_capacity(bloom_size.min(data.len().saturating_sub(bloom_off) / 8));
        for i in 0..bloom_size {
            bloom_words.push(read_u64(bloom_off + i * 8)?);
        }

        let buckets_off = bloom_off
            .checked_add(bloom_bytes)
            .ok_or_else(|| "gnu.hash: buckets_off overflows".to_string())?;
        let nbuckets_usize = nbuckets as usize;
        let buckets_bytes = nbuckets_usize
            .checked_mul(4)
            .ok_or_else(|| format!("gnu.hash: nbuckets {nbuckets} overflows"))?;
        let mut buckets =
            Vec::with_capacity(nbuckets_usize.min(data.len().saturating_sub(buckets_off) / 4));
        for i in 0..nbuckets_usize {
            buckets.push(read_u32(buckets_off + i * 4)?);
        }

        let chain_off = buckets_off
            .checked_add(buckets_bytes)
            .ok_or_else(|| "gnu.hash: chain_off overflows".to_string())?;
        let chain_len = data.len().saturating_sub(chain_off) / 4;
        let mut chain = Vec::with_capacity(chain_len);
        for i in 0..chain_len {
            chain.push(read_u32(chain_off + i * 4)?);
        }

        Ok(Self {
            nbuckets,
            symoffset,
            bloom: GnuBloomFilter::new(bloom_words, bloom_shift, 64),
            buckets,
            chain,
        })
    }

    /// Look up a symbol name and return the **symbol table index** if found.
    /// Returns `None` if definitely absent (Bloom filter rejection or hash mismatch).
    #[must_use]
    pub fn lookup(&self, name: &str) -> Option<u32> {
        let hash = gnu_hash_str(name);
        if !self.bloom.might_contain(hash) {
            return None;
        }
        if self.nbuckets == 0 {
            return None;
        }
        let bucket_idx = (hash % self.nbuckets) as usize;
        let sym_idx = *self.buckets.get(bucket_idx)?;
        if sym_idx == 0 {
            return None; // empty bucket
        }
        let chain_start = sym_idx.saturating_sub(self.symoffset) as usize;
        for (i, &chain_val) in self.chain.iter().enumerate().skip(chain_start) {
            // Low bit is the chain terminator; mask it for the hash comparison.
            let chain_hash = chain_val & !1;
            if chain_hash == hash & !1 {
                // Candidate — the caller must verify the name via the dynsym strtab.
                return Some(sym_idx + u32::try_from(i).unwrap_or(u32::MAX) - u32::try_from(chain_start).unwrap_or(u32::MAX));
            }
            if chain_val & 1 != 0 {
                break; // end of chain
            }
        }
        None
    }

    /// Number of hashed symbols (conservative estimate from chain length).
    #[must_use]
    pub const fn symbol_count(&self) -> usize {
        self.chain.len()
    }

    /// Enumerate every symbol index stored in this hash table.
    ///
    /// Iterates all non-empty buckets and walks their chains, collecting the
    /// symbol-table indices of every hashed symbol.  The returned indices start
    /// at `symoffset` (the first global/weak symbol) and are de-duplicated.
    ///
    /// Use this to achieve completeness when goblin's `dynsyms` iterator misses
    /// symbols that are only reachable via the GNU hash table.
    #[must_use]
    pub fn scan_all_symbols(&self) -> Vec<u32> {
        let mut indices = Vec::new();
        for &bucket_start in &self.buckets {
            if bucket_start == 0 {
                continue;
            }
            // Walk the chain starting at bucket_start.
            let chain_idx = bucket_start.saturating_sub(self.symoffset) as usize;
            let mut sym_idx = bucket_start;
            for offset in 0..self.chain.len() {
                let ci = chain_idx + offset;
                if ci >= self.chain.len() {
                    break;
                }
                indices.push(sym_idx);
                if self.chain[ci] & 1 != 0 {
                    break; // end-of-chain marker
                }
                sym_idx += 1;
            }
        }
        // De-duplicate while preserving order (buckets can theoretically
        // overlap when the table is malformed).
        indices.sort_unstable();
        indices.dedup();
        indices
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gnu_hash_known_values() {
        // GNU hash values computed with the DJB2 variant (h=5381, h = h*33 + c).
        assert_eq!(gnu_hash_str("printf"), 0x156b_2bb8);
        assert_eq!(gnu_hash_str("exit"), 0x7c96_7e3f);
        assert_eq!(gnu_hash_str(""), 0x1505); // hash of empty string
    }

    #[test]
    fn test_gnu_hash_deterministic() {
        let h1 = gnu_hash_str("malloc");
        let h2 = gnu_hash_str("malloc");
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_gnu_hash_different_strings() {
        assert_ne!(gnu_hash_str("foo"), gnu_hash_str("bar"));
    }

    #[test]
    fn test_bloom_filter_empty_returns_true() {
        let f = GnuBloomFilter::new(vec![], 6, 64);
        assert!(f.might_contain(0xDEAD_BEEF));
    }

    #[test]
    fn test_bloom_filter_positive() {
        // Manually set bits for hash 42 with shift2=6, word_bits=64.
        let hash: u32 = 42;
        let shift2: u32 = 6;
        let word_bits: u32 = 64;
        let bit1 = hash & (word_bits - 1);
        let bit2 = (hash >> shift2) & (word_bits - 1);
        let word = (1u64 << bit1) | (1u64 << bit2);
        let f = GnuBloomFilter::new(vec![word], shift2, word_bits);
        assert!(f.might_contain(hash));
    }

    #[test]
    fn test_bloom_filter_negative() {
        // A Bloom filter with all zeros should reject everything.
        let f = GnuBloomFilter::new(vec![0u64], 6, 64);
        assert!(!f.might_contain(42));
    }

    #[test]
    fn test_bloom_fpr_empty_symbols() {
        let f = GnuBloomFilter::new(vec![0u64; 4], 6, 64);
        assert_eq!(f.false_positive_rate(0), 0.0);
    }

    #[test]
    fn test_bloom_fpr_reasonable_range() {
        // 4 words × 64 bits = 256 bits, 100 symbols → FPR < 50%
        let f = GnuBloomFilter::new(vec![u64::MAX; 4], 6, 64);
        let rate = f.false_positive_rate(100);
        assert!((0.0..=1.0).contains(&rate));
    }

    #[test]
    fn test_gnu_hash_table_parse64_too_short() {
        assert!(GnuHashTable::parse64(&[0u8; 4], true).is_err());
    }

    #[test]
    fn test_gnu_hash_table_parse64_minimal() {
        // Build a minimal GNU hash section: 1 bucket, symoffset=1, bloom_size=1
        let mut data = vec![0u8; 16 + 8 + 4]; // header + 1 bloom word + 1 bucket
        // nbuckets = 1
        data[0..4].copy_from_slice(&1u32.to_le_bytes());
        // symoffset = 1
        data[4..8].copy_from_slice(&1u32.to_le_bytes());
        // bloom_size = 1 (1 64-bit word)
        data[8..12].copy_from_slice(&1u32.to_le_bytes());
        // bloom_shift = 6
        data[12..16].copy_from_slice(&6u32.to_le_bytes());
        // bloom word = 0
        data[16..24].copy_from_slice(&0u64.to_le_bytes());
        // bucket[0] = 0 (empty)
        data[24..28].copy_from_slice(&0u32.to_le_bytes());

        let table = GnuHashTable::parse64(&data, true).unwrap();
        assert_eq!(table.nbuckets, 1);
        assert_eq!(table.symoffset, 1);
    }

    #[test]
    fn test_gnu_hash_lookup_empty_bucket() {
        // Build a table where bucket[0] = 0 (empty).
        let mut data = vec![0u8; 16 + 8 + 4];
        data[0..4].copy_from_slice(&1u32.to_le_bytes()); // nbuckets
        data[4..8].copy_from_slice(&1u32.to_le_bytes()); // symoffset
        data[8..12].copy_from_slice(&1u32.to_le_bytes()); // bloom_size
        data[12..16].copy_from_slice(&6u32.to_le_bytes()); // shift2
        data[16..24].copy_from_slice(&0u64.to_le_bytes()); // bloom
        data[24..28].copy_from_slice(&0u32.to_le_bytes()); // bucket = 0

        let table = GnuHashTable::parse64(&data, true).unwrap();
        // Bloom filter has word=0, so might_contain will return false for any hash.
        assert!(table.lookup("anything").is_none());
    }

    #[test]
    fn test_gnu_hash_byte_slice() {
        let h1 = gnu_hash(b"hello");
        let h2 = gnu_hash_str("hello");
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_gnu_hash_single_char() {
        // Single character hash should still be deterministic.
        let h = gnu_hash(b"a");
        assert_ne!(h, 0);
    }

    #[test]
    fn test_gnu_hash_table_symbol_count() {
        // Verify symbol_count reflects chain length.
        let mut data = vec![0u8; 16 + 8 + 4 + 8]; // header + bloom + bucket + 2 chain entries
        data[0..4].copy_from_slice(&1u32.to_le_bytes()); // nbuckets = 1
        data[4..8].copy_from_slice(&1u32.to_le_bytes()); // symoffset = 1
        data[8..12].copy_from_slice(&1u32.to_le_bytes()); // bloom_size = 1
        data[12..16].copy_from_slice(&6u32.to_le_bytes()); // shift2 = 6
        data[16..24].copy_from_slice(&0u64.to_le_bytes()); // bloom word
        data[24..28].copy_from_slice(&0u32.to_le_bytes()); // bucket = 0
        // chain: 2 entries = 8 bytes
        data[28..32].copy_from_slice(&0u32.to_le_bytes());
        data[32..36].copy_from_slice(&1u32.to_le_bytes()); // end-of-chain marker

        let table = GnuHashTable::parse64(&data, true).unwrap();
        assert_eq!(table.symbol_count(), 2);
    }

    // ── Extra edge-case coverage ────────────────────────────────────────────

    #[test]
    fn test_gnu_hash_empty_bytes() {
        assert_eq!(gnu_hash(b""), 5381);
    }

    #[test]
    fn test_gnu_hash_high_bit_bytes() {
        // Bytes >= 0x80 are valid input; ensure hash is computed without panic.
        let h = gnu_hash(&[0xFFu8; 16]);
        assert_ne!(h, 0);
        // Determinism
        assert_eq!(h, gnu_hash(&[0xFFu8; 16]));
    }

    #[test]
    fn test_gnu_hash_long_string_no_panic() {
        // Multiplication is wrapping; ensure no panic on long inputs.
        let big = vec![b'x'; 100_000];
        let _ = gnu_hash(&big);
    }

    #[test]
    fn test_bloom_filter_zero_word_bits_assumes_present() {
        // Defensive: word_bits=0 short-circuits to "may be present".
        let f = GnuBloomFilter::new(vec![0u64; 2], 6, 0);
        assert!(f.might_contain(1));
        assert!(f.might_contain(u32::MAX));
    }

    #[test]
    fn test_bloom_filter_fpr_zero_when_empty_words() {
        let f = GnuBloomFilter::new(vec![], 6, 64);
        assert_eq!(f.false_positive_rate(100), 0.0);
    }

    #[test]
    fn test_gnu_hash_table_parse64_empty_returns_err() {
        assert!(GnuHashTable::parse64(&[], true).is_err());
    }

    #[test]
    fn test_gnu_hash_table_parse64_truncated_bloom() {
        // Header says bloom_size=4 but data is too short to hold them.
        let mut data = vec![0u8; 16 + 8]; // only 1 bloom word worth of space
        data[0..4].copy_from_slice(&1u32.to_le_bytes());
        data[4..8].copy_from_slice(&0u32.to_le_bytes());
        data[8..12].copy_from_slice(&4u32.to_le_bytes()); // claims 4 words
        data[12..16].copy_from_slice(&6u32.to_le_bytes());
        assert!(GnuHashTable::parse64(&data, true).is_err());
    }

    #[test]
    fn test_gnu_hash_table_be_parse() {
        // Big-endian header parse path.
        let mut data = vec![0u8; 16 + 8 + 4];
        data[0..4].copy_from_slice(&1u32.to_be_bytes());
        data[4..8].copy_from_slice(&0u32.to_be_bytes());
        data[8..12].copy_from_slice(&1u32.to_be_bytes());
        data[12..16].copy_from_slice(&6u32.to_be_bytes());
        let t = GnuHashTable::parse64(&data, false).unwrap();
        assert_eq!(t.nbuckets, 1);
    }
}
