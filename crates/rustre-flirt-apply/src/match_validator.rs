//! FLIRT match validator — CRC16 re-verification, name disambiguation, and
//! collision resolution when multiple signatures match the same address.

use std::collections::HashSet;
// AHashMap (randomised) prevents hash-collision DoS from attacker-controlled
// function addresses from untrusted binary input.
use ahash::AHashMap as HashMap;

use serde::{Deserialize, Serialize};

use crate::flirt_applicator::{Confidence, FuncAddr, FuncName, ResolvedMatch};

// ---------------------------------------------------------------------------
// CRC-16 (FLIRT variant — CRC-16/MCRF4XX with poly 0x1021, init 0xFFFF)
// ---------------------------------------------------------------------------

/// Compute CRC-16/MCRF4XX over a byte slice.
#[must_use] 
pub fn crc16_mcrf4xx(data: &[u8]) -> u16 {
    rustre_flirt::crc::flirt_tail(data)
}

/// Compute CRC-16 using FLIRT's specific algorithm (CRC-16/MCRF4XX, but applied
/// to the 32 bytes following the 32-byte prefix, skipping call-target bytes).
///
/// `body` — the raw function bytes starting at offset `prefix_len`.
/// `crc_len` — how many bytes contribute to the CRC (from the .sig header).
/// `wildcard_offsets` — byte offsets (relative to start of `body`) to zero out
///   before computing the CRC, because they encode call displacement that varies.
#[must_use] 
pub fn compute_flirt_crc(body: &[u8], crc_len: usize, wildcard_offsets: &[usize]) -> u16 {
    if body.len() < crc_len {
        return 0;
    }
    let mut buf = body[..crc_len].to_vec();
    for &off in wildcard_offsets {
        if off < buf.len() {
            buf[off] = 0x00;
        }
    }
    crc16_mcrf4xx(&buf)
}

// ---------------------------------------------------------------------------
// Candidate match (pre-validation)
// ---------------------------------------------------------------------------

/// A candidate FLIRT match before full validation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CandidateMatch {
    /// Address of the function being matched.
    pub address: FuncAddr,
    /// Candidate primary name from the signature.
    pub primary_name: FuncName,
    /// Alternative names from the same signature module.
    pub alt_names: Vec<FuncName>,
    /// Library this signature belongs to.
    pub library: String,
    /// Confidence from the initial scan (before CRC check).
    pub pre_confidence: u8,
    /// CRC16 from the .sig file header.
    pub expected_crc: u16,
    /// Length of bytes used for CRC computation.
    pub crc_len: u8,
    /// Wildcard offsets to zero during CRC computation.
    pub wildcard_offsets: Vec<usize>,
    /// Tail names and offsets.
    pub tail_names: Vec<(u16, FuncName)>,
    /// Referenced function names at offsets.
    pub ref_names: Vec<(u16, FuncName)>,
    /// Module offset in the .sig file (for deduplication).
    pub module_offset: u32,
}

// ---------------------------------------------------------------------------
// Validation result
// ---------------------------------------------------------------------------

/// Result of validating a single `CandidateMatch`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ValidationResult {
    /// Match is valid; contains the finalized `ResolvedMatch`.
    Valid(ResolvedMatch),
    /// CRC mismatch — the bytes at the address don't match the signature.
    CrcMismatch {
        address: FuncAddr,
        name: FuncName,
        expected: u16,
        actual: u16,
    },
    /// Name is ambiguous — multiple candidates have the same confidence and CRC.
    Ambiguous {
        address: FuncAddr,
        candidates: Vec<FuncName>,
    },
    /// The candidate was suppressed by a higher-priority collision winner.
    CollisionLost {
        address: FuncAddr,
        winner: FuncName,
        loser: FuncName,
    },
    /// Insufficient bytes at `address` to compute the CRC.
    InsufficientBytes {
        address: FuncAddr,
        needed: usize,
        available: usize,
    },
}

impl ValidationResult {
    #[must_use] 
    pub const fn is_valid(&self) -> bool { matches!(self, Self::Valid(_)) }

    #[must_use] 
    pub const fn address(&self) -> FuncAddr {
        match self {
            Self::Valid(m) => m.address,
            Self::CrcMismatch { address, .. }
            | Self::Ambiguous { address, .. }
            | Self::CollisionLost { address, .. }
            | Self::InsufficientBytes { address, .. } => *address,
        }
    }

    #[must_use] 
    pub fn into_resolved(self) -> Option<ResolvedMatch> {
        match self {
            Self::Valid(m) => Some(m),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Name disambiguation
// ---------------------------------------------------------------------------

/// Disambiguation policy for selecting among equally-confident candidates.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[derive(Default)]
pub enum DisambigPolicy {
    /// Prefer candidates whose name appears in a provided name allowlist.
    PreferAllowlisted,
    /// Prefer shorter names (often C stdlib names over mangled C++ names).
    #[default]
    PreferShorter,
    /// Prefer longer names (more specific).
    PreferLonger,
    /// Alphabetically first (deterministic, not semantically meaningful).
    Alphabetical,
    /// Mark all equally-good candidates as conflicting.
    MarkConflict,
}


/// Name allowlist for disambiguation.
#[derive(Debug, Default, Clone)]
pub struct NameAllowlist {
    names: HashSet<String>,
}

impl NameAllowlist {
    #[must_use] 
    pub fn new() -> Self { Self::default() }

    pub fn insert(&mut self, name: impl Into<String>) {
        self.names.insert(name.into());
    }

    #[must_use] 
    pub fn contains(&self, name: &str) -> bool {
        self.names.contains(name)
    }

    pub fn from_names<I: IntoIterator<Item = S>, S: Into<String>>(iter: I) -> Self {
        let mut al = Self::new();
        for name in iter { al.insert(name); }
        al
    }
}

/// Disambiguate a list of equally-confident candidate names for the same address,
/// returning the chosen winner and the losers.
///
/// # Panics
///
/// Panics if `candidates` contains elements but `.min()` or `.max()` returns `None`
/// (cannot occur given the non-empty guard at the top of the function).
#[must_use]
pub fn disambiguate(
    candidates: &[FuncName],
    policy: DisambigPolicy,
    allowlist: &NameAllowlist,
) -> (Option<FuncName>, Vec<FuncName>) {
    if candidates.is_empty() { return (None, vec![]); }
    if candidates.len() == 1 { return (Some(candidates[0].clone()), vec![]); }

    match policy {
        DisambigPolicy::MarkConflict => (None, candidates.to_vec()),
        DisambigPolicy::PreferAllowlisted => {
            let listed: Vec<_> = candidates.iter().filter(|n| allowlist.contains(n.as_str())).cloned().collect();
            if listed.len() == 1 {
                let winner = listed[0].clone();
                let losers = candidates.iter().filter(|n| **n != winner).cloned().collect();
                (Some(winner), losers)
            } else if listed.is_empty() {
                // Fall back to alphabetical.
                let mut sorted = candidates.to_vec();
                sorted.sort();
                let winner = sorted.remove(0);
                (Some(winner), sorted)
            } else {
                (None, candidates.to_vec())
            }
        }
        DisambigPolicy::PreferShorter => {
            let min_len = candidates.iter().map(std::string::String::len).min().unwrap();
            let shortest: Vec<_> = candidates.iter().filter(|n| n.len() == min_len).cloned().collect();
            if shortest.len() == 1 {
                let winner = shortest[0].clone();
                let losers = candidates.iter().filter(|n| **n != winner).cloned().collect();
                (Some(winner), losers)
            } else {
                (None, candidates.to_vec())
            }
        }
        DisambigPolicy::PreferLonger => {
            let max_len = candidates.iter().map(std::string::String::len).max().unwrap();
            let longest: Vec<_> = candidates.iter().filter(|n| n.len() == max_len).cloned().collect();
            if longest.len() == 1 {
                let winner = longest[0].clone();
                let losers = candidates.iter().filter(|n| **n != winner).cloned().collect();
                (Some(winner), losers)
            } else {
                (None, candidates.to_vec())
            }
        }
        DisambigPolicy::Alphabetical => {
            let mut sorted = candidates.to_vec();
            sorted.sort();
            let winner = sorted.remove(0);
            (Some(winner), sorted)
        }
    }
}

// ---------------------------------------------------------------------------
// Collision resolver
// ---------------------------------------------------------------------------

/// Priority scores assigned to library categories for collision resolution.
fn library_priority(library: &str) -> i32 {
    let lib_lower = library.to_lowercase();
    if lib_lower.contains("msvc") || lib_lower.contains("crt") { return 100; }
    if lib_lower.contains("libc") || lib_lower.contains("glibc") { return 95; }
    if lib_lower.contains("openssl") || lib_lower.contains("crypto") { return 80; }
    if lib_lower.contains("zlib") || lib_lower.contains("compress") { return 75; }
    if lib_lower.contains("boost") { return 60; }
    if lib_lower.contains("qt") { return 55; }
    50
}

/// Resolve collisions among multiple candidates at the same address.
///
/// Returns: (winner, losers) where winner is the best candidate (if unambiguous).
///
/// # Panics
///
/// Panics if `candidates` is non-empty but `.max()` returns `None` (cannot occur
/// given the non-empty guard at the top of the function).
#[must_use]
pub fn resolve_collision(
    candidates: &[CandidateMatch],
    policy: DisambigPolicy,
    allowlist: &NameAllowlist,
) -> (Option<CandidateMatch>, Vec<CandidateMatch>) {
    if candidates.is_empty() { return (None, vec![]); }
    if candidates.len() == 1 { return (Some(candidates[0].clone()), vec![]); }

    // Step 1: keep only highest-confidence candidates.
    let max_conf = candidates.iter().map(|c| c.pre_confidence).max().unwrap();
    let top: Vec<CandidateMatch> = candidates.iter().filter(|c| c.pre_confidence == max_conf).cloned().collect();

    if top.len() == 1 {
        let winner = top.into_iter().next().unwrap();
        let losers = candidates.iter().filter(|c| c.address != winner.address || c.primary_name != winner.primary_name).cloned().collect();
        return (Some(winner), losers);
    }

    // Step 2: prefer higher library priority.
    let max_prio = top.iter().map(|c| library_priority(&c.library)).max().unwrap();
    let top_prio: Vec<CandidateMatch> = top.into_iter().filter(|c| library_priority(&c.library) == max_prio).collect();

    if top_prio.len() == 1 {
        let winner = top_prio.into_iter().next().unwrap();
        let losers = candidates.iter().filter(|c| c.primary_name != winner.primary_name).cloned().collect();
        return (Some(winner), losers);
    }

    // Step 3: name disambiguation.
    let names: Vec<FuncName> = top_prio.iter().map(|c| c.primary_name.clone()).collect();
    let (chosen_name, _) = disambiguate(&names, policy, allowlist);

    if let Some(name) = chosen_name
        && let Some(winner) = top_prio.iter().find(|c| c.primary_name == name) {
            let winner = winner.clone();
            let losers = candidates.iter().filter(|c| c.primary_name != winner.primary_name).cloned().collect();
            return (Some(winner), losers);
        }

    // No clear winner.
    (None, candidates.to_vec())
}

// ---------------------------------------------------------------------------
// Validator
// ---------------------------------------------------------------------------

/// Configuration for the match validator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorConfig {
    /// Whether to verify CRC16 of the bytes after the prefix.
    pub verify_crc: bool,
    /// Collision resolution policy.
    pub collision_policy: DisambigPolicy,
    /// Name disambiguation policy.
    pub disambig_policy: DisambigPolicy,
    /// Minimum confidence to accept a match (before CRC boost).
    pub min_confidence: u8,
    /// Confidence boost granted when CRC passes.
    pub crc_pass_boost: u8,
    /// Penalty applied when CRC is not verifiable (insufficient bytes).
    pub crc_unverifiable_penalty: u8,
}

impl Default for ValidatorConfig {
    fn default() -> Self {
        Self {
            verify_crc: true,
            collision_policy: DisambigPolicy::PreferShorter,
            disambig_policy: DisambigPolicy::PreferShorter,
            min_confidence: 40,
            crc_pass_boost: 15,
            crc_unverifiable_penalty: 5,
        }
    }
}

/// Statistics from a validation run.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct ValidationStats {
    pub total: usize,
    pub valid: usize,
    pub crc_mismatch: usize,
    pub crc_passed: usize,
    pub ambiguous: usize,
    pub collision_lost: usize,
    pub insufficient_bytes: usize,
    pub below_min_confidence: usize,
}

/// The FLIRT match validator.
pub struct MatchValidator {
    config: ValidatorConfig,
    allowlist: NameAllowlist,
}

impl MatchValidator {
    #[must_use] 
    pub fn new(config: ValidatorConfig) -> Self {
        Self { config, allowlist: NameAllowlist::new() }
    }

    #[must_use] 
    pub fn with_defaults() -> Self {
        Self::new(ValidatorConfig::default())
    }

    pub fn set_allowlist(&mut self, al: NameAllowlist) { self.allowlist = al; }

    /// Validate a single candidate using the raw binary bytes at its address.
    ///
    /// `func_bytes` must be the bytes of the function starting from address 0
    /// (i.e. sliced from the full binary at `candidate.address`).
    pub fn validate_one(
        &self,
        candidate: &CandidateMatch,
        func_bytes: &[u8],
        stats: &mut ValidationStats,
    ) -> ValidationResult {
        stats.total += 1;

        if candidate.pre_confidence < self.config.min_confidence {
            stats.below_min_confidence += 1;
            return ValidationResult::CollisionLost {
                address: candidate.address,
                winner: "<min_confidence>".into(),
                loser: candidate.primary_name.clone(),
            };
        }

        // CRC verification.
        let crc_verified;
        let mut confidence = candidate.pre_confidence;

        if self.config.verify_crc && candidate.crc_len > 0 {
            let crc_len = candidate.crc_len as usize;
            if func_bytes.len() < crc_len {
                stats.insufficient_bytes += 1;
                confidence = confidence.saturating_sub(self.config.crc_unverifiable_penalty);
                crc_verified = false;
                if confidence < self.config.min_confidence {
                    return ValidationResult::InsufficientBytes {
                        address: candidate.address,
                        needed: crc_len,
                        available: func_bytes.len(),
                    };
                }
            } else {
                let actual_crc = compute_flirt_crc(func_bytes, crc_len, &candidate.wildcard_offsets);
                if actual_crc != candidate.expected_crc {
                    stats.crc_mismatch += 1;
                    return ValidationResult::CrcMismatch {
                        address: candidate.address,
                        name: candidate.primary_name.clone(),
                        expected: candidate.expected_crc,
                        actual: actual_crc,
                    };
                }
                stats.crc_passed += 1;
                confidence = confidence.saturating_add(self.config.crc_pass_boost).min(100);
                crc_verified = true;
            }
        } else {
            crc_verified = false;
        }

        let resolved = ResolvedMatch {
            address: candidate.address,
            primary_name: candidate.primary_name.clone(),
            alt_names: candidate.alt_names.clone(),
            library: candidate.library.clone(),
            confidence: Confidence::new(confidence),
            module_offset: candidate.module_offset,
            crc16: candidate.expected_crc,
            crc_verified,
            tail_names: candidate.tail_names.clone(),
            ref_names: candidate.ref_names.clone(),
        };

        stats.valid += 1;
        ValidationResult::Valid(resolved)
    }

    /// Validate a group of candidates for the same address (collision group).
    ///
    /// `func_bytes_by_addr` maps address → function bytes slice.
    pub fn validate_collision_group(
        &self,
        candidates: &[CandidateMatch],
        func_bytes_by_addr: &HashMap<FuncAddr, &[u8]>,
        stats: &mut ValidationStats,
    ) -> Vec<ValidationResult> {
        if candidates.is_empty() { return vec![]; }

        // Validate each candidate individually first.
        let mut individually_valid: Vec<(CandidateMatch, ResolvedMatch)> = vec![];
        let mut results: Vec<ValidationResult> = vec![];

        for candidate in candidates {
            let bytes = func_bytes_by_addr.get(&candidate.address).copied().unwrap_or(&[]);
            let mut temp_stats = ValidationStats::default();
            let result = self.validate_one(candidate, bytes, &mut temp_stats);
            // Accumulate into main stats.
            stats.total += temp_stats.total;
            stats.crc_mismatch += temp_stats.crc_mismatch;
            stats.crc_passed += temp_stats.crc_passed;
            stats.insufficient_bytes += temp_stats.insufficient_bytes;
            stats.below_min_confidence += temp_stats.below_min_confidence;

            match result {
                ValidationResult::Valid(ref r) => {
                    individually_valid.push((candidate.clone(), r.clone()));
                }
                other => results.push(other),
            }
        }

        if individually_valid.is_empty() {
            return results;
        }

        if individually_valid.len() == 1 {
            let (_, resolved) = individually_valid.remove(0);
            stats.valid += 1;
            results.push(ValidationResult::Valid(resolved));
            return results;
        }

        // Multiple valid candidates: collision resolution.
        let cands: Vec<CandidateMatch> = individually_valid.iter().map(|(c, _)| c.clone()).collect();
        let (winner_opt, losers) = resolve_collision(&cands, self.config.collision_policy, &self.allowlist);

        if let Some(winner) = winner_opt {
            // Mark losers.
            for loser in &losers {
                stats.collision_lost += 1;
                results.push(ValidationResult::CollisionLost {
                    address: winner.address,
                    winner: winner.primary_name.clone(),
                    loser: loser.primary_name.clone(),
                });
            }
            // Emit the winner.
            if let Some((_, resolved)) = individually_valid.into_iter().find(|(c, _)| c.primary_name == winner.primary_name) {
                stats.valid += 1;
                results.push(ValidationResult::Valid(resolved));
            }
        } else {
            // No clear winner — mark as ambiguous.
            let names: Vec<FuncName> = individually_valid.iter().map(|(c, _)| c.primary_name.clone()).collect();
            let address = individually_valid[0].1.address;
            stats.ambiguous += 1;
            results.push(ValidationResult::Ambiguous { address, candidates: names });
        }

        results
    }

    /// Validate a full flat list of candidates.
    /// Groups by address, then runs collision resolution per group.
    #[must_use] 
    pub fn validate_all(
        &self,
        candidates: &[CandidateMatch],
        func_bytes_by_addr: &HashMap<FuncAddr, &[u8]>,
    ) -> (Vec<ValidationResult>, ValidationStats) {
        let mut stats = ValidationStats::default();

        // Group by address.
        let mut groups: HashMap<FuncAddr, Vec<CandidateMatch>> = HashMap::new();
        for c in candidates {
            groups.entry(c.address).or_default().push(c.clone());
        }

        let mut results = Vec::with_capacity(candidates.len());
        for (_, group) in &groups {
            let mut group_results = self.validate_collision_group(group, func_bytes_by_addr, &mut stats);
            results.append(&mut group_results);
        }

        (results, stats)
    }

    /// Convenience: validate and return only valid resolved matches.
    #[must_use] 
    pub fn validated_matches(
        &self,
        candidates: &[CandidateMatch],
        func_bytes_by_addr: &HashMap<FuncAddr, &[u8]>,
    ) -> (Vec<ResolvedMatch>, ValidationStats) {
        let (results, stats) = self.validate_all(candidates, func_bytes_by_addr);
        let resolved: Vec<ResolvedMatch> = results.into_iter().filter_map(ValidationResult::into_resolved).collect();
        (resolved, stats)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crc16_known() {
        // CRC-16/MCRF4XX of b"123456789" = 0x6F91
        let crc = crc16_mcrf4xx(b"123456789");
        assert_eq!(crc, 0x6F91, "CRC16 mismatch: got {crc:#06x}");
    }

    #[test]
    fn test_validate_crc_pass() {
        let validator = MatchValidator::with_defaults();
        // Build 32 bytes of data and compute the expected CRC.
        let body = vec![0xAA_u8; 32];
        let expected_crc = crc16_mcrf4xx(&body);
        let candidate = CandidateMatch {
            address: 0x1000,
            primary_name: "test_fn".into(),
            alt_names: vec![],
            library: "libc".into(),
            pre_confidence: 80,
            expected_crc,
            crc_len: 32,
            wildcard_offsets: vec![],
            tail_names: vec![],
            ref_names: vec![],
            module_offset: 0,
        };
        let mut stats = ValidationStats::default();
        let result = validator.validate_one(&candidate, &body, &mut stats);
        assert!(result.is_valid(), "expected valid, got {result:?}");
        assert_eq!(stats.crc_passed, 1);
    }

    #[test]
    fn test_validate_crc_fail() {
        let validator = MatchValidator::with_defaults();
        let body = vec![0xBB_u8; 32];
        let candidate = CandidateMatch {
            address: 0x2000,
            primary_name: "wrong_fn".into(),
            alt_names: vec![],
            library: "libc".into(),
            pre_confidence: 80,
            expected_crc: 0xDEAD,
            crc_len: 32,
            wildcard_offsets: vec![],
            tail_names: vec![],
            ref_names: vec![],
            module_offset: 0,
        };
        let mut stats = ValidationStats::default();
        let result = validator.validate_one(&candidate, &body, &mut stats);
        assert!(matches!(result, ValidationResult::CrcMismatch { .. }));
        assert_eq!(stats.crc_mismatch, 1);
    }

    #[test]
    fn test_disambiguate_prefer_shorter() {
        let (winner, losers) = disambiguate(
            &["__cxa_throw_bad_alloc".into(), "malloc".into(), "operator_new".into()],
            DisambigPolicy::PreferShorter,
            &NameAllowlist::new(),
        );
        assert_eq!(winner.as_deref(), Some("malloc"));
        assert_eq!(losers.len(), 2);
    }

    #[test]
    fn test_library_priority_ordering() {
        assert!(library_priority("msvcrt") > library_priority("zlib"));
        assert!(library_priority("libc") > library_priority("boost"));
    }
}
