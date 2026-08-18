//! Instruction-level diff: edit scripts, similarity metrics, prime-hash
//! (Jakstab-style), instruction normalisation, wildcard matching, and
//! diff alignment.

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

// ── Basic instruction representation ─────────────────────────────────────────

/// Minimal instruction as seen by the differ.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Insn {
    pub address: u64,
    pub mnemonic: String,
    pub operands: Vec<Operand>,
    pub size: u8,
}

impl Insn {
    pub fn new(address: u64, mnemonic: impl Into<String>) -> Self {
        Self {
            address,
            mnemonic: mnemonic.into(),
            operands: Vec::new(),
            size: 0,
        }
    }

    #[must_use]
    pub fn with_operands(mut self, ops: Vec<Operand>) -> Self {
        self.operands = ops;
        self
    }

    #[must_use]
    pub const fn with_size(mut self, size: u8) -> Self {
        self.size = size;
        self
    }
}

impl fmt::Display for Insn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.operands.is_empty() {
            write!(f, "{}", self.mnemonic)
        } else {
            let ops: Vec<String> = self.operands.iter().map(std::string::ToString::to_string).collect();
            write!(f, "{} {}", self.mnemonic, ops.join(", "))
        }
    }
}

/// An instruction operand.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Operand {
    Register(String),
    Immediate(i64),
    Memory {
        base: Option<String>,
        index: Option<String>,
        scale: i32,
        disp: i64,
    },
    Label(String),
    Wildcard,
}

impl fmt::Display for Operand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Register(r) => f.write_str(r),
            Self::Immediate(v) => write!(f, "0x{v:x}"),
            Self::Memory {
                base,
                index,
                scale,
                disp,
            } => {
                write!(f, "[{base:?}+{index:?}*{disp}+{scale}]")
            }
            Self::Label(l) => f.write_str(l),
            Self::Wildcard => f.write_str("_"),
        }
    }
}

// ── InstructionNormalizer ─────────────────────────────────────────────────────

/// Normalises instructions for comparison by abstracting away address-specific
/// details (immediate absolute addresses, register assignments via α-rename, etc.)
pub struct InstructionNormalizer {
    /// Whether to normalise immediate values to canonical form.
    pub abstract_immediates: bool,
    /// Whether to rename registers so allocation differences are ignored.
    pub alpha_rename_registers: bool,
    /// Map used for register renaming.
    register_map: HashMap<String, String>,
    next_reg_id: u32,
}

impl InstructionNormalizer {
    #[must_use]
    pub fn new() -> Self {
        Self {
            abstract_immediates: true,
            alpha_rename_registers: false,
            register_map: HashMap::new(),
            next_reg_id: 0,
        }
    }

    /// Reset the normalizer state for a new function.
    pub fn reset(&mut self) {
        self.register_map.clear();
        self.next_reg_id = 0;
    }

    /// Normalise an instruction.
    pub fn normalize(&mut self, insn: &Insn) -> Insn {
        let ops: Vec<Operand> = insn
            .operands
            .iter()
            .map(|op| self.normalize_operand(op))
            .collect();
        Insn {
            address: 0, // strip address
            mnemonic: insn.mnemonic.to_lowercase(),
            operands: ops,
            size: insn.size,
        }
    }

    fn normalize_operand(&mut self, op: &Operand) -> Operand {
        match op {
            Operand::Register(r) => {
                if self.alpha_rename_registers {
                    let id = self.next_reg_id;
                    let renamed = self
                        .register_map
                        .entry(r.clone())
                        .or_insert_with(|| {
                            let name = format!("r{id}");
                            name
                        })
                        .clone();
                    // If we just inserted, increment
                    if !self
                        .register_map
                        .values()
                        .any(|v| *v == format!("r{}", id.saturating_sub(1)))
                    {
                        self.next_reg_id += 1;
                    }
                    Operand::Register(renamed)
                } else {
                    Operand::Register(r.to_lowercase())
                }
            }
            Operand::Immediate(v) => {
                if self.abstract_immediates {
                    // Keep relative offsets (small values), zero out large absolute addresses
                    if v.abs() > 0x10000 {
                        Operand::Immediate(0)
                    } else {
                        Operand::Immediate(*v)
                    }
                } else {
                    Operand::Immediate(*v)
                }
            }
            Operand::Memory {
                base,
                index,
                scale,
                disp,
            } => {
                let base2 = base.as_deref().map(str::to_lowercase);
                let index2 = index.as_deref().map(str::to_lowercase);
                let disp2 = if self.abstract_immediates && disp.abs() > 0x10000 {
                    0
                } else {
                    *disp
                };
                Operand::Memory {
                    base: base2,
                    index: index2,
                    scale: *scale,
                    disp: disp2,
                }
            }
            other => other.clone(),
        }
    }
}

impl Default for InstructionNormalizer {
    fn default() -> Self {
        Self::new()
    }
}

// ── PrimeHashInsn ─────────────────────────────────────────────────────────────

/// Jakstab-style prime hash: assigns a prime to each (mnemonic, operand-shape)
/// and computes the product as the basic-block hash.
pub struct PrimeHashInsn {
    mnemonic_primes: HashMap<String, u64>,
    next_prime_idx: usize,
}

const PRIMES: &[u64] = &[
    2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97,
    101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193,
    197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281,
];

impl PrimeHashInsn {
    #[must_use]
    pub fn new() -> Self {
        Self {
            mnemonic_primes: HashMap::new(),
            next_prime_idx: 0,
        }
    }

    fn prime_for_mnemonic(&mut self, mnemonic: &str) -> u64 {
        if let Some(&p) = self.mnemonic_primes.get(mnemonic) {
            return p;
        }
        // Deterministic prime selection based on mnemonic content (FNV-1a),
        // so two independent hashers assign the same prime to the same mnemonic
        // and *different* mnemonics get (with very high probability) different primes.
        let mut h: u64 = 14695981039346656037;
        for b in mnemonic.bytes() {
            h ^= u64::from(b);
            h = h.wrapping_mul(1099511628211);
        }
        let p = PRIMES[(h as usize) % PRIMES.len()];
        self.next_prime_idx += 1;
        self.mnemonic_primes.insert(mnemonic.to_owned(), p);
        p
    }

    /// Compute the product-of-primes hash for a block of instructions.
    pub fn hash_block(&mut self, insns: &[Insn]) -> u64 {
        let mut product: u64 = 1;
        for insn in insns {
            let p = self.prime_for_mnemonic(&insn.mnemonic.to_lowercase());
            product = product.wrapping_mul(p);
        }
        product
    }

    /// Compute a normalised hash (stable across address changes).
    pub fn hash_normalised_block(&mut self, insns: &[Insn]) -> u64 {
        let mut norm = InstructionNormalizer::new();
        let normalised: Vec<Insn> = insns.iter().map(|i| norm.normalize(i)).collect();
        self.hash_block(&normalised)
    }
}

impl Default for PrimeHashInsn {
    fn default() -> Self {
        Self::new()
    }
}

// ── WildcardMatcher ───────────────────────────────────────────────────────────

/// Matches instruction sequences with wildcards (`_` in mnemonic or operands).
pub struct WildcardMatcher;

impl WildcardMatcher {
    /// Match a pattern instruction against a concrete instruction.
    #[must_use]
    pub fn match_insn(pattern: &Insn, concrete: &Insn) -> bool {
        // Mnemonic match: "_" is a wildcard that matches any mnemonic
        let mnem_ok =
            pattern.mnemonic == "_" || pattern.mnemonic.eq_ignore_ascii_case(&concrete.mnemonic);
        if !mnem_ok {
            return false;
        }

        if pattern.operands.is_empty() {
            return true; // pattern doesn't constrain operands
        }
        if pattern.operands.len() != concrete.operands.len() {
            return false;
        }
        pattern
            .operands
            .iter()
            .zip(&concrete.operands)
            .all(|(p, c)| Self::match_operand(p, c))
    }

    fn match_operand(pattern: &Operand, concrete: &Operand) -> bool {
        match pattern {
            Operand::Wildcard => true,
            Operand::Register(r) => {
                matches!(concrete, Operand::Register(cr) if r.eq_ignore_ascii_case(cr))
            }
            Operand::Immediate(v) => {
                matches!(concrete, Operand::Immediate(cv) if cv == v)
            }
            Operand::Label(l) => {
                matches!(concrete, Operand::Label(cl) if cl == l)
            }
            Operand::Memory {
                base: pb,
                index: pi,
                scale: ps,
                disp: pd,
            } => {
                if let Operand::Memory {
                    base: cb,
                    index: ci,
                    scale: cs,
                    disp: cd,
                } = concrete
                {
                    pb == cb && pi == ci && ps == cs && pd == cd
                } else {
                    false
                }
            }
        }
    }

    /// Match a sequence of pattern instructions against a window of concrete instructions.
    #[must_use]
    pub fn match_sequence(pattern: &[Insn], concrete: &[Insn]) -> Option<usize> {
        if pattern.len() > concrete.len() {
            return None;
        }
        (0..=concrete.len() - pattern.len()).find(|&start| {
            pattern
                .iter()
                .zip(&concrete[start..])
                .all(|(p, c)| Self::match_insn(p, c))
        })
    }
}

// ── InsnEdit ─────────────────────────────────────────────────────────────────

/// A single edit operation in an instruction-level edit script.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum InsnEdit {
    Insert {
        position: usize,
        insn: Insn,
    },
    Delete {
        position: usize,
        insn: Insn,
    },
    Replace {
        position: usize,
        old: Insn,
        new: Insn,
    },
    Move {
        from: usize,
        to: usize,
        insn: Insn,
    },
}

impl InsnEdit {
    #[must_use]
    pub fn cost(&self) -> u32 {
        match self {
            Self::Insert { .. } => 1,
            Self::Delete { .. } => 1,
            Self::Replace { old, new, .. } => {
                if old.mnemonic == new.mnemonic {
                    1
                } else {
                    2
                }
            }
            Self::Move { .. } => 1,
        }
    }

    #[must_use]
    pub const fn is_insert(&self) -> bool {
        matches!(self, Self::Insert { .. })
    }
    #[must_use]
    pub const fn is_delete(&self) -> bool {
        matches!(self, Self::Delete { .. })
    }
    #[must_use]
    pub const fn is_replace(&self) -> bool {
        matches!(self, Self::Replace { .. })
    }
    #[must_use]
    pub const fn is_move(&self) -> bool {
        matches!(self, Self::Move { .. })
    }
}

// ── InsnSimilarity ────────────────────────────────────────────────────────────

/// Instruction-level similarity metrics.
pub struct InsnSimilarity;

impl InsnSimilarity {
    /// Mnemonic-only similarity (1.0 if identical, 0.0 if entirely different).
    #[must_use]
    pub fn mnemonic_similarity(a: &Insn, b: &Insn) -> f64 {
        if a.mnemonic.eq_ignore_ascii_case(&b.mnemonic) {
            1.0
        } else {
            0.0
        }
    }

    /// Full structural similarity including operands (0.0–1.0).
    #[must_use]
    pub fn structural_similarity(a: &Insn, b: &Insn) -> f64 {
        let mnem = if a.mnemonic.eq_ignore_ascii_case(&b.mnemonic) {
            1.0
        } else {
            0.0
        };
        if a.operands.is_empty() && b.operands.is_empty() {
            return mnem;
        }
        let total_ops = a.operands.len().max(b.operands.len());
        let matching_ops = a
            .operands
            .iter()
            .zip(&b.operands)
            .filter(|(pa, pb)| pa == pb)
            .count();
        let op_sim = if total_ops == 0 {
            1.0
        } else {
            matching_ops as f64 / total_ops as f64
        };
        0.5 * mnem + 0.5 * op_sim
    }

    /// Levenshtein edit distance between two instruction sequences.
    #[must_use]
    pub fn edit_distance(a: &[Insn], b: &[Insn]) -> usize {
        let m = a.len();
        let n = b.len();
        let mut dp = vec![vec![0usize; n + 1]; m + 1];
        for i in 0..=m {
            dp[i][0] = i;
        }
        for j in 0..=n {
            dp[0][j] = j;
        }
        for i in 1..=m {
            for j in 1..=n {
                let cost = if a[i - 1].mnemonic.eq_ignore_ascii_case(&b[j - 1].mnemonic) {
                    0
                } else {
                    1
                };
                dp[i][j] = (dp[i - 1][j] + 1)
                    .min(dp[i][j - 1] + 1)
                    .min(dp[i - 1][j - 1] + cost);
            }
        }
        dp[m][n]
    }

    /// Sequence similarity as 1 - (`edit_distance` / `max_len`).
    #[must_use]
    pub fn sequence_similarity(a: &[Insn], b: &[Insn]) -> f64 {
        let max_len = a.len().max(b.len());
        if max_len == 0 {
            return 1.0;
        }
        let dist = Self::edit_distance(a, b);
        1.0 - (dist as f64 / max_len as f64)
    }
}

// ── DiffAlignment ─────────────────────────────────────────────────────────────

/// Aligned instruction diff result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffAlignment {
    pub aligned_pairs: Vec<AlignedPair>,
    pub edit_distance: usize,
    pub similarity: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlignedPair {
    pub old_idx: Option<usize>,
    pub new_idx: Option<usize>,
    pub old_insn: Option<Insn>,
    pub new_insn: Option<Insn>,
    pub is_match: bool,
}

impl DiffAlignment {
    /// Compute instruction-level alignment between two sequences.
    #[must_use]
    pub fn compute(old: &[Insn], new: &[Insn]) -> Self {
        let ed = InsnSimilarity::edit_distance(old, new);
        let sim = InsnSimilarity::sequence_similarity(old, new);

        let m = old.len();
        let n = new.len();
        // Build DP table
        let mut dp = vec![vec![0usize; n + 1]; m + 1];
        for i in 0..=m {
            dp[i][0] = i;
        }
        for j in 0..=n {
            dp[0][j] = j;
        }
        for i in 1..=m {
            for j in 1..=n {
                let cost = if old[i - 1]
                    .mnemonic
                    .eq_ignore_ascii_case(&new[j - 1].mnemonic)
                {
                    0
                } else {
                    1
                };
                dp[i][j] = (dp[i - 1][j] + 1)
                    .min(dp[i][j - 1] + 1)
                    .min(dp[i - 1][j - 1] + cost);
            }
        }
        // Back-track
        let mut pairs = Vec::new();
        let (mut i, mut j) = (m, n);
        while i > 0 || j > 0 {
            if i > 0 && j > 0 {
                let cost = if old[i - 1]
                    .mnemonic
                    .eq_ignore_ascii_case(&new[j - 1].mnemonic)
                {
                    0
                } else {
                    1
                };
                if dp[i][j] == dp[i - 1][j - 1] + cost {
                    pairs.push(AlignedPair {
                        old_idx: Some(i - 1),
                        new_idx: Some(j - 1),
                        old_insn: Some(old[i - 1].clone()),
                        new_insn: Some(new[j - 1].clone()),
                        is_match: cost == 0,
                    });
                    i -= 1;
                    j -= 1;
                    continue;
                }
            }
            if i > 0 && (j == 0 || dp[i][j] == dp[i - 1][j] + 1) {
                pairs.push(AlignedPair {
                    old_idx: Some(i - 1),
                    new_idx: None,
                    old_insn: Some(old[i - 1].clone()),
                    new_insn: None,
                    is_match: false,
                });
                i -= 1;
            } else {
                pairs.push(AlignedPair {
                    old_idx: None,
                    new_idx: Some(j - 1),
                    old_insn: None,
                    new_insn: Some(new[j - 1].clone()),
                    is_match: false,
                });
                j -= 1;
            }
        }
        pairs.reverse();
        Self {
            aligned_pairs: pairs,
            edit_distance: ed,
            similarity: sim,
        }
    }

    #[must_use]
    pub fn changed_count(&self) -> usize {
        self.aligned_pairs.iter().filter(|p| !p.is_match).count()
    }

    #[must_use]
    pub fn matched_count(&self) -> usize {
        self.aligned_pairs.iter().filter(|p| p.is_match).count()
    }

    /// Generate simple edit script from alignment.
    #[must_use]
    pub fn to_edit_script(&self) -> Vec<InsnEdit> {
        let mut edits = Vec::new();
        for pair in &self.aligned_pairs {
            match (&pair.old_insn, &pair.new_insn) {
                (Some(old), Some(new)) if !pair.is_match => {
                    edits.push(InsnEdit::Replace {
                        position: pair.new_idx.unwrap_or(0),
                        old: old.clone(),
                        new: new.clone(),
                    });
                }
                (Some(old), None) => {
                    edits.push(InsnEdit::Delete {
                        position: pair.old_idx.unwrap_or(0),
                        insn: old.clone(),
                    });
                }
                (None, Some(new)) => {
                    edits.push(InsnEdit::Insert {
                        position: pair.new_idx.unwrap_or(0),
                        insn: new.clone(),
                    });
                }
                _ => {}
            }
        }
        edits
    }
}

// ── InstructionDiff ───────────────────────────────────────────────────────────

/// Top-level instruction diff between two function bodies.
#[derive(Debug, Serialize, Deserialize)]
pub struct InstructionDiff {
    pub function_a: String,
    pub function_b: String,
    pub alignment: DiffAlignment,
    pub prime_hash_a: u64,
    pub prime_hash_b: u64,
    pub hash_match: bool,
}

impl InstructionDiff {
    /// Compute the full diff between two instruction sequences.
    pub fn compute(
        function_a: impl Into<String>,
        insns_a: &[Insn],
        function_b: impl Into<String>,
        insns_b: &[Insn],
    ) -> Self {
        let mut hasher = PrimeHashInsn::new();
        let hash_a = hasher.hash_normalised_block(insns_a);
        let hash_b = hasher.hash_normalised_block(insns_b);
        let alignment = DiffAlignment::compute(insns_a, insns_b);
        Self {
            function_a: function_a.into(),
            function_b: function_b.into(),
            alignment,
            prime_hash_a: hash_a,
            prime_hash_b: hash_b,
            hash_match: hash_a == hash_b,
        }
    }

    #[must_use]
    pub const fn similarity(&self) -> f64 {
        self.alignment.similarity
    }

    #[must_use]
    pub const fn is_identical(&self) -> bool {
        self.hash_match
    }

    #[must_use]
    pub fn edit_script(&self) -> Vec<InsnEdit> {
        self.alignment.to_edit_script()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn insn(addr: u64, mnem: &str) -> Insn {
        Insn::new(addr, mnem)
    }

    fn insn_reg(addr: u64, mnem: &str, reg: &str) -> Insn {
        Insn::new(addr, mnem).with_operands(vec![Operand::Register(reg.into())])
    }

    fn insn_imm(addr: u64, mnem: &str, imm: i64) -> Insn {
        Insn::new(addr, mnem).with_operands(vec![Operand::Immediate(imm)])
    }

    // ── Insn tests ────────────────────────────────────────────────────────────

    #[test]
    fn test_insn_display_no_operands() {
        let i = insn(0x1000, "ret");
        assert_eq!(i.to_string(), "ret");
    }

    #[test]
    fn test_insn_display_with_operand() {
        let i = insn_reg(0x1000, "push", "rax");
        assert_eq!(i.to_string(), "push rax");
    }

    // ── InstructionNormalizer tests ───────────────────────────────────────────

    #[test]
    fn test_normalizer_strips_address() {
        let mut n = InstructionNormalizer::new();
        let i = insn(0xDEAD_BEEF, "nop");
        let ni = n.normalize(&i);
        assert_eq!(ni.address, 0);
    }

    #[test]
    fn test_normalizer_lowercases_mnemonic() {
        let mut n = InstructionNormalizer::new();
        let i = insn(0, "MOV");
        let ni = n.normalize(&i);
        assert_eq!(ni.mnemonic, "mov");
    }

    #[test]
    fn test_normalizer_abstracts_large_immediate() {
        let mut n = InstructionNormalizer::new();
        let i = insn_imm(0, "push", 0xDEAD_BEEF);
        let ni = n.normalize(&i);
        assert_eq!(ni.operands[0], Operand::Immediate(0));
    }

    #[test]
    fn test_normalizer_keeps_small_immediate() {
        let mut n = InstructionNormalizer::new();
        let i = insn_imm(0, "add", 42);
        let ni = n.normalize(&i);
        assert_eq!(ni.operands[0], Operand::Immediate(42));
    }

    #[test]
    fn test_normalizer_lowercases_register() {
        let mut n = InstructionNormalizer::new();
        let i = insn_reg(0, "mov", "RAX");
        let ni = n.normalize(&i);
        assert_eq!(ni.operands[0], Operand::Register("rax".into()));
    }

    // ── PrimeHashInsn tests ───────────────────────────────────────────────────

    #[test]
    fn test_prime_hash_same_block_equal() {
        let mut h = PrimeHashInsn::new();
        let block = vec![insn(0, "push"), insn(1, "mov"), insn(2, "ret")];
        let h1 = h.hash_block(&block);
        let mut h2 = PrimeHashInsn::new();
        let h2v = h2.hash_block(&block);
        assert_eq!(h1, h2v);
    }

    #[test]
    fn test_prime_hash_different_blocks_differ() {
        let mut h = PrimeHashInsn::new();
        let b1 = vec![insn(0, "push"), insn(1, "ret")];
        let b2 = vec![insn(0, "nop"), insn(1, "ret")];
        let h1 = h.hash_block(&b1);
        let mut h2 = PrimeHashInsn::new();
        let h2v = h2.hash_block(&b2);
        assert_ne!(h1, h2v);
    }

    #[test]
    fn test_prime_hash_normalised_ignores_address() {
        let b1 = vec![insn(0x1000, "push"), insn(0x1001, "ret")];
        let b2 = vec![insn(0x2000, "push"), insn(0x2001, "ret")];
        let mut h = PrimeHashInsn::new();
        let h1 = h.hash_normalised_block(&b1);
        let mut h2 = PrimeHashInsn::new();
        let h2v = h2.hash_normalised_block(&b2);
        assert_eq!(h1, h2v);
    }

    #[test]
    fn test_prime_hash_empty_block() {
        let mut h = PrimeHashInsn::new();
        let v = h.hash_block(&[]);
        assert_eq!(v, 1); // identity for product
    }

    // ── WildcardMatcher tests ─────────────────────────────────────────────────

    #[test]
    fn test_wildcard_match_exact() {
        let pat = insn(0, "push");
        let con = insn(0x1000, "push");
        assert!(WildcardMatcher::match_insn(&pat, &con));
    }

    #[test]
    fn test_wildcard_match_mnemonic_wildcard() {
        let pat = insn(0, "_");
        let con = insn(0, "nop");
        assert!(WildcardMatcher::match_insn(&pat, &con));
    }

    #[test]
    fn test_wildcard_match_case_insensitive_mnemonic() {
        let pat = insn(0, "MOV");
        let con = insn(0, "mov");
        assert!(WildcardMatcher::match_insn(&pat, &con));
    }

    #[test]
    fn test_wildcard_match_operand_wildcard() {
        let pat = Insn::new(0, "mov").with_operands(vec![Operand::Wildcard]);
        let con = insn_reg(0, "mov", "rax");
        assert!(WildcardMatcher::match_insn(&pat, &con));
    }

    #[test]
    fn test_wildcard_match_sequence_found() {
        let pattern = vec![insn(0, "push"), insn(0, "ret")];
        let concrete = vec![insn(0, "nop"), insn(1, "push"), insn(2, "ret")];
        assert_eq!(
            WildcardMatcher::match_sequence(&pattern, &concrete),
            Some(1)
        );
    }

    #[test]
    fn test_wildcard_match_sequence_not_found() {
        let pattern = vec![insn(0, "push"), insn(0, "jmp")];
        let concrete = vec![insn(0, "nop"), insn(1, "push"), insn(2, "ret")];
        assert_eq!(WildcardMatcher::match_sequence(&pattern, &concrete), None);
    }

    #[test]
    fn test_wildcard_no_match_different_mnemonic() {
        let pat = insn(0, "push");
        let con = insn(0, "pop");
        assert!(!WildcardMatcher::match_insn(&pat, &con));
    }

    // ── InsnEdit tests ────────────────────────────────────────────────────────

    #[test]
    fn test_edit_cost_insert() {
        let e = InsnEdit::Insert {
            position: 0,
            insn: insn(0, "nop"),
        };
        assert_eq!(e.cost(), 1);
        assert!(e.is_insert());
    }

    #[test]
    fn test_edit_cost_delete() {
        let e = InsnEdit::Delete {
            position: 0,
            insn: insn(0, "ret"),
        };
        assert_eq!(e.cost(), 1);
        assert!(e.is_delete());
    }

    #[test]
    fn test_edit_cost_replace_same_mnemonic() {
        let e = InsnEdit::Replace {
            position: 0,
            old: insn_reg(0, "mov", "rax"),
            new: insn_reg(0, "mov", "rbx"),
        };
        assert_eq!(e.cost(), 1);
        assert!(e.is_replace());
    }

    #[test]
    fn test_edit_cost_replace_different_mnemonic() {
        let e = InsnEdit::Replace {
            position: 0,
            old: insn(0, "push"),
            new: insn(0, "pop"),
        };
        assert_eq!(e.cost(), 2);
    }

    #[test]
    fn test_edit_move() {
        let e = InsnEdit::Move {
            from: 0,
            to: 5,
            insn: insn(0, "nop"),
        };
        assert_eq!(e.cost(), 1);
        assert!(e.is_move());
    }

    // ── InsnSimilarity tests ──────────────────────────────────────────────────

    #[test]
    fn test_mnemonic_similarity_equal() {
        assert_eq!(
            InsnSimilarity::mnemonic_similarity(&insn(0, "nop"), &insn(1, "nop")),
            1.0
        );
    }

    #[test]
    fn test_mnemonic_similarity_different() {
        assert_eq!(
            InsnSimilarity::mnemonic_similarity(&insn(0, "nop"), &insn(1, "ret")),
            0.0
        );
    }

    #[test]
    fn test_structural_similarity_identical() {
        let a = insn_reg(0, "mov", "rax");
        let b = insn_reg(0, "mov", "rax");
        assert_eq!(InsnSimilarity::structural_similarity(&a, &b), 1.0);
    }

    #[test]
    fn test_edit_distance_identical() {
        let seq = vec![insn(0, "push"), insn(1, "ret")];
        assert_eq!(InsnSimilarity::edit_distance(&seq, &seq), 0);
    }

    #[test]
    fn test_edit_distance_one_insert() {
        let a = vec![insn(0, "push"), insn(1, "ret")];
        let b = vec![insn(0, "push"), insn(1, "nop"), insn(2, "ret")];
        assert_eq!(InsnSimilarity::edit_distance(&a, &b), 1);
    }

    #[test]
    fn test_sequence_similarity_identical() {
        let seq = vec![insn(0, "push"), insn(1, "ret")];
        assert_eq!(InsnSimilarity::sequence_similarity(&seq, &seq), 1.0);
    }

    #[test]
    fn test_sequence_similarity_empty() {
        assert_eq!(InsnSimilarity::sequence_similarity(&[], &[]), 1.0);
    }

    #[test]
    fn test_sequence_similarity_partial() {
        let a = vec![insn(0, "push"), insn(1, "ret")];
        let b = vec![insn(0, "nop"), insn(1, "ret")];
        let sim = InsnSimilarity::sequence_similarity(&a, &b);
        assert!(sim > 0.0 && sim < 1.0);
    }

    // ── DiffAlignment tests ───────────────────────────────────────────────────

    #[test]
    fn test_alignment_identical_sequences() {
        let seq = vec![insn(0, "push"), insn(1, "ret")];
        let aln = DiffAlignment::compute(&seq, &seq);
        assert_eq!(aln.edit_distance, 0);
        assert_eq!(aln.similarity, 1.0);
        assert_eq!(aln.changed_count(), 0);
        assert_eq!(aln.matched_count(), 2);
    }

    #[test]
    fn test_alignment_one_changed_instruction() {
        let a = vec![insn(0, "nop"), insn(1, "ret")];
        let b = vec![insn(0, "push"), insn(1, "ret")];
        let aln = DiffAlignment::compute(&a, &b);
        assert_eq!(aln.edit_distance, 1);
        assert!(aln.similarity < 1.0);
    }

    #[test]
    fn test_alignment_edit_script_has_replace() {
        let a = vec![insn(0, "nop"), insn(1, "ret")];
        let b = vec![insn(0, "push"), insn(1, "ret")];
        let aln = DiffAlignment::compute(&a, &b);
        let edits = aln.to_edit_script();
        assert!(edits.iter().any(|e| e.is_replace()));
    }

    // ── InstructionDiff tests ─────────────────────────────────────────────────

    #[test]
    fn test_instruction_diff_identical() {
        let seq = vec![insn(0, "push"), insn(1, "ret")];
        let d = InstructionDiff::compute("fn_a", &seq, "fn_b", &seq);
        assert!(d.is_identical());
        assert_eq!(d.similarity(), 1.0);
    }

    #[test]
    fn test_instruction_diff_not_identical() {
        let a = vec![insn(0, "nop"), insn(1, "ret")];
        let b = vec![insn(0, "push"), insn(1, "ret")];
        let d = InstructionDiff::compute("fn_a", &a, "fn_b", &b);
        assert!(!d.is_identical());
        assert!(d.similarity() < 1.0);
    }

    #[test]
    fn test_instruction_diff_edit_script() {
        let a = vec![insn(0, "nop")];
        let b = vec![insn(0, "push")];
        let d = InstructionDiff::compute("fa", &a, "fb", &b);
        let script = d.edit_script();
        assert!(!script.is_empty());
    }
}
