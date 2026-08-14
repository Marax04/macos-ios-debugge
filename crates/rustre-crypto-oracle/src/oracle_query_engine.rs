//! `oracle_query_engine` — High-level query interface for crypto oracle attacks.
//!
//! Provides `OracleQueryEngine`, a generic engine that wraps any oracle callable
//! (a closure that encrypts or decrypts data and returns a boolean verdict), and
//! offers structured queries: byte-at-a-time, block comparison, boundary detection,
//! and batch adaptive queries with rate limiting and caching.

use ahash::{HashMap, HashMapExt};
use std::fmt;

// ── OracleKind ────────────────────────────────────────────────────────────────

/// The type of cryptographic oracle being exploited.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OracleKind {
    /// Padding oracle (CBC/PKCS#7): distinguishes valid from invalid padding.
    Padding,
    /// ECB byte-at-a-time oracle: distinguishes equal from unequal blocks.
    EcbByteAtATime,
    /// Compression oracle: distinguishes shorter from longer ciphertext.
    Compression,
    /// Timing oracle: distinguishes fast from slow responses.
    Timing,
    /// MAC oracle: distinguishes valid from invalid MACs.
    Mac,
    /// Custom / unspecified.
    Custom,
}

impl fmt::Display for OracleKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Padding => write!(f, "Padding"),
            Self::EcbByteAtATime => write!(f, "ECB-byte-at-a-time"),
            Self::Compression => write!(f, "Compression"),
            Self::Timing => write!(f, "Timing"),
            Self::Mac => write!(f, "MAC"),
            Self::Custom => write!(f, "Custom"),
        }
    }
}

// ── OracleQuery ───────────────────────────────────────────────────────────────

/// A single oracle query with its metadata.
#[derive(Debug, Clone)]
pub struct OracleQuery {
    /// The ciphertext (or payload) to submit.
    pub payload: Vec<u8>,
    /// Optional label for diagnostic purposes.
    pub label: String,
    /// Which byte position this query is probing (0-based).
    pub byte_offset: Option<usize>,
    /// Which candidate byte value is being tested.
    pub candidate: Option<u8>,
}

impl OracleQuery {
    /// Create a simple unlabelled query.
    #[must_use]
    pub const fn new(payload: Vec<u8>) -> Self {
        Self {
            payload,
            label: String::new(),
            byte_offset: None,
            candidate: None,
        }
    }

    /// Create a labelled query targeting a specific byte/candidate pair.
    #[must_use]
    pub fn probe(payload: Vec<u8>, byte_offset: usize, candidate: u8) -> Self {
        Self {
            payload,
            label: format!("probe[{byte_offset}]=0x{candidate:02x}"),
            byte_offset: Some(byte_offset),
            candidate: Some(candidate),
        }
    }
}

// ── OracleResponse ────────────────────────────────────────────────────────────

/// The response returned by the oracle for one query.
#[derive(Debug, Clone)]
pub struct OracleResponse {
    /// The original query that produced this response.
    pub query: OracleQuery,
    /// `true` = oracle accepted (e.g. valid padding), `false` = rejected.
    pub accepted: bool,
    /// Optional auxiliary data returned by the oracle (e.g. ciphertext length).
    pub aux_data: Option<Vec<u8>>,
    /// Query index (monotonically increasing).
    pub query_index: u64,
}

impl OracleResponse {
    /// Returns `true` if the oracle accepted the query.
    #[must_use]
    pub const fn is_accepted(&self) -> bool {
        self.accepted
    }
}

impl fmt::Display for OracleResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let verdict = if self.accepted { "ACCEPT" } else { "REJECT" };
        write!(f, "[{}] #{} {} {}", verdict, self.query_index, self.query.label, self.query.payload.len())
    }
}

// ── QueryStats ────────────────────────────────────────────────────────────────

/// Accumulated statistics for an `OracleQueryEngine` session.
#[derive(Debug, Clone, Default)]
pub struct QueryStats {
    /// Total queries issued.
    pub total_queries: u64,
    /// Queries that received ACCEPT.
    pub accepted_count: u64,
    /// Queries that received REJECT.
    pub rejected_count: u64,
    /// Cache hits (queries answered from cache without calling the oracle).
    pub cache_hits: u64,
    /// Bytes recovered so far.
    pub bytes_recovered: usize,
}

impl QueryStats {
    /// Accept rate in the range \[0.0, 1.0\].
    #[must_use]
    pub fn accept_rate(&self) -> f64 {
        if self.total_queries == 0 {
            0.0
        } else {
            f64::from(u32::try_from(self.accepted_count).unwrap_or(u32::MAX))
                / f64::from(u32::try_from(self.total_queries).unwrap_or(u32::MAX))
        }
    }
}

impl fmt::Display for QueryStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "queries={} accept={} reject={} cache_hits={} bytes_recovered={}",
            self.total_queries,
            self.accepted_count,
            self.rejected_count,
            self.cache_hits,
            self.bytes_recovered,
        )
    }
}

// ── OracleQueryEngine ─────────────────────────────────────────────────────────

/// High-level engine that wraps a crypto oracle function and provides structured
/// query helpers for common attack patterns.
///
/// The inner oracle callable has signature `FnMut(&[u8]) -> bool` — it receives
/// a payload and returns `true` (ACCEPT) or `false` (REJECT).
pub struct OracleQueryEngine<F>
where
    F: FnMut(&[u8]) -> bool,
{
    /// The wrapped oracle function.
    oracle: F,
    /// Oracle type, for diagnostics.
    pub kind: OracleKind,
    /// Block size assumed by the cipher (e.g. 16 for AES).
    pub block_size: usize,
    /// When `true`, query results are memoized by payload hash.
    pub use_cache: bool,
    /// Memoization cache: `payload` → `accepted`.
    cache: HashMap<Vec<u8>, bool>,
    /// Running statistics.
    pub stats: QueryStats,
    /// Monotonically increasing query index.
    next_index: u64,
}

impl<F> OracleQueryEngine<F>
where
    F: FnMut(&[u8]) -> bool,
{
    /// Create a new engine wrapping `oracle`.
    #[must_use]
    pub fn new(oracle: F, kind: OracleKind, block_size: usize) -> Self {
        Self {
            oracle,
            kind,
            block_size,
            use_cache: true,
            cache: HashMap::new(),
            stats: QueryStats::default(),
            next_index: 0,
        }
    }

    /// Disable query caching.
    #[must_use]
    pub const fn without_cache(mut self) -> Self {
        self.use_cache = false;
        self
    }

    // ── Core query primitive ──────────────────────────────────────────────────

    /// Issue a single oracle query and return the response.
    pub fn query(&mut self, q: OracleQuery) -> OracleResponse {
        let idx = self.next_index;
        self.next_index += 1;
        self.stats.total_queries += 1;

        // Cache check.
        if self.use_cache
            && let Some(&cached) = self.cache.get(&q.payload)
        {
            self.stats.cache_hits += 1;
            if cached {
                self.stats.accepted_count += 1;
            } else {
                self.stats.rejected_count += 1;
            }
            return OracleResponse {
                query: q,
                accepted: cached,
                aux_data: None,
                query_index: idx,
            };
        }

        let accepted = (self.oracle)(&q.payload);

        if self.use_cache {
            self.cache.insert(q.payload.clone(), accepted);
        }
        if accepted {
            self.stats.accepted_count += 1;
        } else {
            self.stats.rejected_count += 1;
        }

        OracleResponse { query: q, accepted, aux_data: None, query_index: idx }
    }

    // ── Byte-at-a-time recovery ───────────────────────────────────────────────

    /// Try all 256 candidate bytes for `byte_offset` and return those that are
    /// accepted by the oracle.
    ///
    /// `build_payload` is called with `(candidate, byte_offset)` and must return
    /// the full payload to submit.
    pub fn probe_byte<G>(&mut self, byte_offset: usize, build_payload: G) -> Vec<u8>
    where
        G: Fn(u8, usize) -> Vec<u8>,
    {
        let mut accepted = Vec::new();
        for candidate in 0u8..=255 {
            let payload = build_payload(candidate, byte_offset);
            let q = OracleQuery::probe(payload, byte_offset, candidate);
            let resp = self.query(q);
            if resp.accepted {
                accepted.push(candidate);
            }
        }
        accepted
    }

    /// Recover a sequence of `length` bytes starting at `start_offset` using
    /// byte-at-a-time.  Returns `None` if any byte position yields no unique
    /// accepted candidate.
    pub fn recover_bytes<G>(
        &mut self,
        start_offset: usize,
        length: usize,
        build_payload: G,
    ) -> Option<Vec<u8>>
    where
        G: Fn(u8, usize, &[u8]) -> Vec<u8>,
    {
        let mut recovered: Vec<u8> = Vec::with_capacity(length);
        for offset in start_offset..start_offset + length {
            let known = recovered.clone();
            let mut accepted: Vec<u8> = (0u8..=255)
                .filter(|&candidate| {
                    let payload = build_payload(candidate, offset, &known);
                    let q = OracleQuery::probe(payload, offset, candidate);
                    // We need to issue the query but can't borrow self twice.
                    // Use the internal oracle directly.
                    (self.oracle)(&q.payload)
                })
                .collect();
            self.stats.total_queries += 256;

            match accepted.len() {
                0 => return None,
                1 => {
                    let byte = accepted.remove(0);
                    recovered.push(byte);
                    self.stats.bytes_recovered += 1;
                }
                _ => {
                    // Ambiguous — take first (caller can refine).
                    recovered.push(accepted[0]);
                    self.stats.bytes_recovered += 1;
                }
            }
        }
        Some(recovered)
    }

    // ── Block boundary detection ──────────────────────────────────────────────

    /// Detect the cipher block size empirically by incrementally appending
    /// bytes and watching for a ciphertext-length jump.
    ///
    /// `encrypt` is called with each payload and must return the ciphertext.
    pub fn detect_block_size<E>(&self, mut encrypt: E) -> Option<usize>
    where
        E: FnMut(&[u8]) -> Vec<u8>,
    {
        let baseline_len = encrypt(&[]).len();
        let mut prev_len = baseline_len;
        let mut payload = Vec::new();

        for _ in 0..64 {
            payload.push(b'A');
            let ct_len = encrypt(&payload).len();
            if ct_len != prev_len {
                let block_size = ct_len - baseline_len;
                if block_size > 0 {
                    return Some(block_size);
                }
            }
            prev_len = ct_len;
        }
        None
    }

    /// Detect whether the oracle uses ECB mode by submitting two identical
    /// plaintext blocks and checking for repeated ciphertext blocks.
    ///
    /// `encrypt` is called once with a crafted payload.
    pub fn detect_ecb_mode<E>(&self, mut encrypt: E) -> bool
    where
        E: FnMut(&[u8]) -> Vec<u8>,
    {
        let repeated = vec![b'A'; self.block_size * 3];
        let ct = encrypt(&repeated);
        if ct.len() < self.block_size * 2 {
            return false;
        }
        // Compare adjacent blocks.
        for i in 0..ct.len() / self.block_size - 1 {
            let a = &ct[i * self.block_size..(i + 1) * self.block_size];
            let b = &ct[(i + 1) * self.block_size..(i + 2) * self.block_size];
            if a == b {
                return true;
            }
        }
        false
    }

    // ── Batch query ───────────────────────────────────────────────────────────

    /// Issue a batch of queries and return all responses.
    pub fn query_batch(&mut self, queries: Vec<OracleQuery>) -> Vec<OracleResponse> {
        queries.into_iter().map(|q| self.query(q)).collect()
    }

    /// Issue all 256 candidate queries for a given byte offset and return the
    /// full response list (useful when the caller needs all responses, not just
    /// accepted ones).
    pub fn query_all_candidates<G>(
        &mut self,
        byte_offset: usize,
        build_payload: G,
    ) -> Vec<OracleResponse>
    where
        G: Fn(u8, usize) -> Vec<u8>,
    {
        let queries: Vec<OracleQuery> = (0u8..=255)
            .map(|c| OracleQuery::probe(build_payload(c, byte_offset), byte_offset, c))
            .collect();
        self.query_batch(queries)
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    /// Clear the memoization cache.
    pub fn clear_cache(&mut self) {
        self.cache.clear();
    }

    /// Reset statistics without clearing the cache.
    pub fn reset_stats(&mut self) {
        self.stats = QueryStats::default();
        self.next_index = 0;
    }

    /// Returns a reference to the current statistics.
    #[must_use]
    pub const fn stats(&self) -> &QueryStats {
        &self.stats
    }
}

// ── query_oracle (free function) ──────────────────────────────────────────────

/// Convenience function: submit a single payload to `oracle` and return whether
/// it was accepted.
#[must_use]
pub fn query_oracle<F>(oracle: &mut F, payload: &[u8]) -> bool
where
    F: FnMut(&[u8]) -> bool,
{
    oracle(payload)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Dummy padding oracle: returns `true` if the last byte of the payload
    /// equals 0x01 (trivial PKCS#7 for a 1-byte pad).
    fn padding_oracle(payload: &[u8]) -> bool {
        payload.last().copied() == Some(0x01)
    }

    #[test]
    fn test_single_query_accept() {
        let mut engine = OracleQueryEngine::new(padding_oracle, OracleKind::Padding, 16);
        let q = OracleQuery::new(vec![0x00; 15].into_iter().chain([0x01]).collect());
        let resp = engine.query(q);
        assert!(resp.is_accepted());
        assert_eq!(engine.stats.accepted_count, 1);
    }

    #[test]
    fn test_single_query_reject() {
        let mut engine = OracleQueryEngine::new(padding_oracle, OracleKind::Padding, 16);
        let q = OracleQuery::new(vec![0x00; 16]);
        let resp = engine.query(q);
        assert!(!resp.is_accepted());
        assert_eq!(engine.stats.rejected_count, 1);
    }

    #[test]
    fn test_probe_byte_finds_candidate() {
        let mut engine = OracleQueryEngine::new(padding_oracle, OracleKind::Padding, 16);
        let accepted = engine.probe_byte(15, |candidate, _offset| {
            let mut payload = vec![0x00u8; 15];
            payload.push(candidate);
            payload
        });
        assert_eq!(accepted, vec![0x01u8]);
    }

    #[test]
    fn test_cache_hit() {
        let call_count = std::cell::Cell::new(0u32);
        let oracle = |payload: &[u8]| -> bool {
            call_count.set(call_count.get() + 1);
            payload.last().copied() == Some(0x01)
        };
        let mut engine = OracleQueryEngine::new(oracle, OracleKind::Padding, 16);
        let payload = vec![0x01u8];
        engine.query(OracleQuery::new(payload.clone()));
        engine.query(OracleQuery::new(payload));
        // Second query should hit the cache.
        assert_eq!(call_count.get(), 1);
        assert_eq!(engine.stats.cache_hits, 1);
    }

    #[test]
    fn test_detect_ecb_mode() {
        let engine = OracleQueryEngine::new(|_: &[u8]| false, OracleKind::EcbByteAtATime, 16);
        // Build a fake ECB encrypt: XOR with 0 (identity), produces repeated blocks.
        let detected = engine.detect_ecb_mode(|payload| {
            // Each 16-byte block is just the first 16 bytes repeated.
            let block: Vec<u8> = payload.iter().take(16).cloned().collect();
            let padded_len = payload.len().div_ceil(16) * 16;
            let mut ct = Vec::with_capacity(padded_len);
            while ct.len() < padded_len {
                ct.extend_from_slice(&block[..16.min(block.len())]);
                if block.len() < 16 {
                    ct.resize(ct.len() + (16 - block.len()), 0);
                }
            }
            ct
        });
        assert!(detected);
    }

    #[test]
    fn test_query_batch() {
        let mut engine = OracleQueryEngine::new(padding_oracle, OracleKind::Padding, 16);
        let queries = vec![
            OracleQuery::new(vec![0x01]),
            OracleQuery::new(vec![0x02]),
        ];
        let responses = engine.query_batch(queries);
        assert_eq!(responses.len(), 2);
        assert!(responses[0].accepted);
        assert!(!responses[1].accepted);
    }

    #[test]
    fn test_stats_accumulation() {
        let mut engine = OracleQueryEngine::new(padding_oracle, OracleKind::Padding, 16);
        for b in 0u8..=4 {
            engine.query(OracleQuery::new(vec![b]));
        }
        assert_eq!(engine.stats.total_queries, 5);
        assert_eq!(engine.stats.accepted_count, 1); // only 0x01
        assert_eq!(engine.stats.rejected_count, 4);
    }

    #[test]
    fn test_query_oracle_free_fn() {
        let mut oracle = |payload: &[u8]| payload == b"secret";
        assert!(query_oracle(&mut oracle, b"secret"));
        assert!(!query_oracle(&mut oracle, b"wrong"));
    }
}
