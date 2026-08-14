//! Prime-product hash — BinDiff-style function hashing.
//!
//! Each mnemonic is assigned a prime number. A basic block's hash is the
//! product of the primes of its mnemonics (mod a large prime).  A function
//! hash combines its block hashes.
//!
//! Provides:
//! - `PrimeTable`  — 200+ mnemonic → prime mappings
//! - `BlockHash`   — prime-product hash of one basic block
//! - `FunctionHash`— combination of block hashes
//! - `PrimeProductHash` — top-level entry point
//! - `HashIndex`   — index for fast lookup
//! - `FuzzyHash`   — LSH-based fuzzy matching

use std::collections::HashMap;
use std::fmt;

// ── Prime table ────────────────────────────────────────────────────────────────

/// A table mapping mnemonic strings to prime numbers.
///
/// Primes are deterministically assigned to mnemonics so that the product of
/// primes in a basic block is a unique fingerprint of the opcode multiset.
#[derive(Debug, Clone)]
pub struct PrimeTable {
    table: HashMap<String, u64>,
    default_prime: u64,
}

impl PrimeTable {
    /// Build the default prime table with 200+ x86/x64 mnemonics.
    #[must_use]
    pub fn default_x86() -> Self {
        let entries: &[(&str, u64)] = &[
            // Data movement
            ("mov", 2),
            ("movsx", 3),
            ("movzx", 5),
            ("movsxd", 7),
            ("movss", 11),
            ("movsd", 13),
            ("movaps", 17),
            ("movups", 19),
            ("movdqu", 23),
            ("movdqa", 29),
            ("movq", 31),
            ("movd", 37),
            ("xchg", 41),
            ("push", 43),
            ("pop", 47),
            ("pusha", 53),
            ("popa", 59),
            ("pushf", 61),
            ("popf", 67),
            // Arithmetic
            ("add", 71),
            ("adc", 73),
            ("sub", 79),
            ("sbb", 83),
            ("mul", 89),
            ("imul", 97),
            ("div", 101),
            ("idiv", 103),
            ("inc", 107),
            ("dec", 109),
            ("neg", 113),
            // Logic
            ("and", 127),
            ("or", 131),
            ("xor", 137),
            ("not", 139),
            ("test", 149),
            ("cmp", 151),
            // Shift / rotate
            ("shl", 157),
            ("shr", 163),
            ("sal", 167),
            ("sar", 173),
            ("rol", 179),
            ("ror", 181),
            ("rcl", 191),
            ("rcr", 193),
            // Control flow
            ("jmp", 197),
            ("je", 199),
            ("jne", 211),
            ("jz", 211),
            ("jnz", 211),
            ("jl", 223),
            ("jle", 227),
            ("jg", 229),
            ("jge", 233),
            ("ja", 239),
            ("jae", 241),
            ("jb", 251),
            ("jbe", 257),
            ("jc", 263),
            ("jnc", 269),
            ("js", 271),
            ("jns", 277),
            ("jo", 281),
            ("jno", 283),
            ("jp", 293),
            ("jpo", 307),
            ("loop", 311),
            ("loope", 313),
            ("loopne", 317),
            // Calls / rets
            ("call", 331),
            ("ret", 337),
            ("retn", 337),
            ("retf", 347),
            ("int", 349),
            ("into", 353),
            ("iret", 359),
            // String
            ("movs", 367),
            ("cmps", 373),
            ("scas", 379),
            ("lods", 383),
            ("stos", 389),
            ("rep", 397),
            ("repe", 401),
            ("repne", 409),
            // Misc
            ("nop", 419),
            ("hlt", 421),
            ("wait", 431),
            ("lock", 433),
            ("lea", 439),
            ("xlatb", 443),
            ("in", 449),
            ("out", 457),
            ("ins", 461),
            ("outs", 463),
            ("cpuid", 467),
            ("rdtsc", 479),
            ("rdmsr", 487),
            ("wrmsr", 491),
            ("clc", 499),
            ("stc", 503),
            ("cmc", 509),
            ("cli", 521),
            ("sti", 523),
            ("cld", 541),
            ("std", 547),
            ("lahf", 557),
            ("sahf", 563),
            ("cbw", 569),
            ("cwde", 571),
            ("cdqe", 577),
            ("cwd", 587),
            ("cdq", 593),
            ("cqo", 599),
            ("bswap", 601),
            ("bt", 607),
            ("bts", 613),
            ("btr", 617),
            ("btc", 619),
            ("bsf", 631),
            ("bsr", 641),
            ("popcnt", 643),
            ("lzcnt", 647),
            ("tzcnt", 653),
            // SSE / AVX
            ("addss", 659),
            ("addsd", 661),
            ("subss", 673),
            ("subsd", 677),
            ("mulss", 683),
            ("mulsd", 691),
            ("divss", 701),
            ("divsd", 709),
            ("sqrtss", 719),
            ("sqrtsd", 727),
            ("maxss", 733),
            ("maxsd", 739),
            ("minss", 743),
            ("minsd", 751),
            ("andps", 757),
            ("andpd", 761),
            ("orps", 769),
            ("orpd", 773),
            ("xorps", 787),
            ("xorpd", 797),
            ("cmpss", 809),
            ("cmpsd", 811),
            ("comiss", 821),
            ("comisd", 823),
            ("cvtss2sd", 827),
            ("cvtsd2ss", 829),
            ("cvtsi2ss", 839),
            ("cvtsi2sd", 853),
            ("cvtss2si", 857),
            ("cvtsd2si", 859),
            // x64-specific
            ("syscall", 863),
            ("sysret", 877),
            ("swapgs", 881),
            // SIMD integer
            ("paddb", 883),
            ("paddw", 887),
            ("paddd", 907),
            ("paddq", 911),
            ("psubb", 919),
            ("psubw", 929),
            ("psubd", 937),
            ("psubq", 941),
            ("pmullw", 947),
            ("pmulhw", 953),
            ("pand", 967),
            ("por", 971),
            ("pxor", 977),
            ("pcmpeqb", 983),
            ("pcmpeqw", 991),
            ("pcmpeqd", 997),
            ("punpcklbw", 1009),
            ("punpckhbw", 1013),
            // Stack frame
            ("enter", 1019),
            ("leave", 1021),
            // Additional SSE / AVX
            ("rcpss", 1031),
            ("rcpps", 1033),
            ("rsqrtss", 1039),
            ("rsqrtps", 1049),
            ("addps", 1051),
            ("addpd", 1061),
            ("subps", 1063),
            ("subpd", 1069),
            ("mulps", 1087),
            ("mulpd", 1091),
            ("divps", 1093),
            ("divpd", 1097),
            ("shufps", 1103),
            ("shufpd", 1109),
            ("unpckhps", 1117),
            ("unpcklps", 1123),
            // Additional control flow / setcc
            ("sete", 1129),
            ("setne", 1151),
            ("setl", 1153),
            ("setle", 1163),
            ("setg", 1171),
            ("setge", 1181),
            ("seta", 1187),
            ("setae", 1193),
            ("setb", 1201),
            ("setbe", 1213),
            ("setc", 1217),
            ("setnc", 1223),
            ("sets", 1229),
            ("setns", 1231),
            ("seto", 1237),
            ("setno", 1249),
            ("setp", 1259),
            ("setnp", 1277),
            ("setz", 1279),
            ("setnz", 1283),
            // Additional conditional moves
            ("cmove", 1289),
            ("cmovne", 1291),
            ("cmovl", 1297),
            ("cmovle", 1301),
            ("cmovg", 1303),
            ("cmovge", 1307),
            ("cmova", 1319),
            ("cmovae", 1321),
            ("cmovb", 1327),
            ("cmovbe", 1361),
            ("cmovs", 1367),
            ("cmovns", 1373),
            ("cmovz", 1381),
            ("cmovnz", 1399),
        ];
        let table: HashMap<String, u64> =
            entries.iter().map(|&(mn, p)| (mn.to_string(), p)).collect();
        Self {
            table,
            default_prime: 1031,
        }
    }

    /// Return the prime for a mnemonic (default prime for unknown).
    #[must_use]
    pub fn prime(&self, mnemonic: &str) -> u64 {
        *self.table.get(mnemonic).unwrap_or(&self.default_prime)
    }

    /// Number of entries in the table.
    #[must_use]
    pub fn len(&self) -> usize {
        self.table.len()
    }

    /// Whether the table is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.table.is_empty()
    }

    /// Whether a mnemonic is in the table.
    #[must_use]
    pub fn contains(&self, mnemonic: &str) -> bool {
        self.table.contains_key(mnemonic)
    }
}

impl Default for PrimeTable {
    fn default() -> Self {
        Self::default_x86()
    }
}

// ── Modular prime-product helpers ─────────────────────────────────────────────

/// The modulus used for all prime-product hashes.
/// First prime larger than 2^32.
const MOD: u64 = 4_294_967_311;

fn mul_mod(a: u64, b: u64) -> u64 {
    // Use 128-bit multiplication to avoid overflow
    let result = (a as u128) * (b as u128) % (MOD as u128);
    result as u64
}

// ── BlockHash ─────────────────────────────────────────────────────────────────

/// Prime-product hash for one basic block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockHash {
    /// The prime product (mod MOD).
    pub value: u64,
    /// Number of instructions.
    pub instr_count: u32,
    /// Whether the block ends with a conditional branch.
    pub is_conditional: bool,
}

impl BlockHash {
    /// Compute a block hash from a list of mnemonics.
    #[must_use]
    pub fn compute(mnemonics: &[&str], table: &PrimeTable, is_conditional: bool) -> Self {
        let mut product = 1u64;
        for &mn in mnemonics {
            let p = table.prime(mn);
            product = mul_mod(product, p);
        }
        Self {
            value: product,
            instr_count: mnemonics.len() as u32,
            is_conditional,
        }
    }

    /// Compute from owned strings.
    #[must_use]
    pub fn compute_owned(mnemonics: &[String], table: &PrimeTable, is_conditional: bool) -> Self {
        let refs: Vec<&str> = mnemonics.iter().map(|s| s.as_str()).collect();
        Self::compute(&refs, table, is_conditional)
    }

    /// Whether this block is empty (product = 1 means no mnemonics).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.instr_count == 0
    }
}

// ── FunctionHash ──────────────────────────────────────────────────────────────

/// Prime-product hash for an entire function.
///
/// Combines all block hashes using a FNV-1a fold over the sorted block values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FunctionHash {
    /// The final function hash value.
    pub value: u64,
    /// Number of basic blocks.
    pub block_count: u32,
    /// Total instruction count.
    pub total_instrs: u32,
    /// Source address of the function.
    pub address: u64,
}

impl FunctionHash {
    /// Build a function hash from a list of block hashes.
    ///
    /// Blocks are sorted by value before combining so that the hash is
    /// independent of block enumeration order.
    #[must_use]
    pub fn from_blocks(address: u64, blocks: &[BlockHash]) -> Self {
        let mut values: Vec<u64> = blocks.iter().map(|b| b.value).collect();
        values.sort_unstable();
        let mut h: u64 = 0xcbf2_9ce4_8422_2325;
        for &v in &values {
            h ^= v;
            h = h.wrapping_mul(0x0000_0100_0000_01b3);
        }
        let total_instrs: u32 = blocks
            .iter()
            .map(|b| b.instr_count)
            .fold(0u32, |acc, c| acc.saturating_add(c));
        Self {
            value: h,
            block_count: blocks.len() as u32,
            total_instrs,
            address,
        }
    }

    /// Whether two functions are likely identical (same hash).
    #[must_use]
    pub fn likely_identical(&self, other: &Self) -> bool {
        self.value == other.value
    }

    /// Structural similarity heuristic based on block count and instruction count.
    #[must_use]
    pub fn structural_similarity(&self, other: &Self) -> f64 {
        let bc = ratio(self.block_count as f64, other.block_count as f64);
        let ic = ratio(self.total_instrs as f64, other.total_instrs as f64);
        0.5 * bc + 0.5 * ic
    }
}

fn ratio(a: f64, b: f64) -> f64 {
    if a == 0.0 && b == 0.0 {
        return 1.0;
    }
    if a == 0.0 || b == 0.0 {
        return 0.0;
    }
    a.min(b) / a.max(b)
}

// ── PrimeProductHash — top-level entry ────────────────────────────────────────

/// Top-level prime-product hash computer.
///
/// Holds a [`PrimeTable`] and provides convenience methods for hashing
/// blocks and functions.
#[derive(Debug, Clone)]
pub struct PrimeProductHash {
    pub table: PrimeTable,
}

impl PrimeProductHash {
    /// Create with the default x86 table.
    #[must_use]
    pub fn new() -> Self {
        Self {
            table: PrimeTable::default_x86(),
        }
    }

    /// Hash a single basic block.
    #[must_use]
    pub fn hash_block(&self, mnemonics: &[&str], is_conditional: bool) -> BlockHash {
        BlockHash::compute(mnemonics, &self.table, is_conditional)
    }

    /// Hash an entire function given its blocks (each block is a list of mnemonics).
    #[must_use]
    pub fn hash_function(
        &self,
        address: u64,
        blocks: &[Vec<&str>],
        is_conditional_block: &[bool],
    ) -> FunctionHash {
        let block_hashes: Vec<BlockHash> = blocks
            .iter()
            .zip(is_conditional_block.iter().chain(std::iter::repeat(&false)))
            .map(|(mns, &cond)| self.hash_block(mns, cond))
            .collect();
        FunctionHash::from_blocks(address, &block_hashes)
    }
}

impl Default for PrimeProductHash {
    fn default() -> Self {
        Self::new()
    }
}

// ── HashIndex ─────────────────────────────────────────────────────────────────

/// Index mapping function hash values to addresses for fast lookup.
#[derive(Debug, Default)]
pub struct HashIndex {
    map: HashMap<u64, Vec<u64>>,
}

impl HashIndex {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a function hash.
    pub fn insert(&mut self, hash: &FunctionHash) {
        self.map.entry(hash.value).or_default().push(hash.address);
    }

    /// Bulk-insert a slice of hashes.
    pub fn insert_all(&mut self, hashes: &[FunctionHash]) {
        for h in hashes {
            self.insert(h);
        }
    }

    /// Look up all addresses matching a hash value.
    #[must_use]
    pub fn lookup(&self, value: u64) -> &[u64] {
        self.map.get(&value).map(|v| v.as_slice()).unwrap_or(&[])
    }

    /// Number of unique hash values.
    #[must_use]
    pub fn unique_count(&self) -> usize {
        self.map.len()
    }

    /// Number of functions indexed.
    #[must_use]
    pub fn function_count(&self) -> usize {
        self.map.values().map(|v| v.len()).sum()
    }
}

// ── FuzzyHash ─────────────────────────────────────────────────────────────────

/// Fuzzy function hash that allows approximate matching.
///
/// Uses a sliding window of block hashes and LSH-style band decomposition
/// so that functions with similar (but not identical) block sequences can
/// still be matched.
#[derive(Debug, Clone)]
pub struct FuzzyHash {
    /// Block hash values in order.
    pub block_values: Vec<u64>,
    /// Band hashes: each band covers `band_size` consecutive blocks.
    pub bands: Vec<u64>,
    pub address: u64,
    pub band_size: usize,
}

impl FuzzyHash {
    /// Compute a fuzzy hash for a function.
    ///
    /// `band_size` controls the trade-off between sensitivity and specificity.
    #[must_use]
    pub fn compute(address: u64, blocks: &[BlockHash], band_size: usize) -> Self {
        let block_values: Vec<u64> = blocks.iter().map(|b| b.value).collect();
        let band_size = band_size.max(1);
        let bands: Vec<u64> = block_values
            .windows(band_size)
            .map(|window| {
                let mut h: u64 = 0xcbf2_9ce4_8422_2325;
                for &v in window {
                    h ^= v;
                    h = h.wrapping_mul(0x0000_0100_0000_01b3);
                }
                h
            })
            .collect();
        Self {
            block_values,
            bands,
            address,
            band_size,
        }
    }

    /// Approximate Jaccard similarity between two fuzzy hashes.
    #[must_use]
    pub fn similarity(&self, other: &Self) -> f64 {
        if self.bands.is_empty() && other.bands.is_empty() {
            return 1.0;
        }
        let a: std::collections::HashSet<u64> = self.bands.iter().copied().collect();
        let b: std::collections::HashSet<u64> = other.bands.iter().copied().collect();
        let inter = a.intersection(&b).count();
        let union = a.len() + b.len() - inter;
        if union == 0 {
            1.0
        } else {
            inter as f64 / union as f64
        }
    }

    /// Whether the two fuzzy hashes are structurally identical.
    #[must_use]
    pub fn is_identical(&self, other: &Self) -> bool {
        self.block_values == other.block_values
    }
}

// ── FuzzyHashIndex ────────────────────────────────────────────────────────────

/// Index for fast fuzzy matching using band decomposition.
#[derive(Debug, Default)]
pub struct FuzzyHashIndex {
    /// band_hash → list of (address, fuzzy_hash_index)
    bands: HashMap<u64, Vec<u64>>,
    pub hashes: Vec<FuzzyHash>,
}

impl FuzzyHashIndex {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a fuzzy hash into the index.
    pub fn insert(&mut self, fh: FuzzyHash) {
        let idx = self.hashes.len();
        for &band in &fh.bands {
            self.bands.entry(band).or_default().push(idx as u64);
        }
        self.hashes.push(fh);
    }

    /// Query for candidate fuzzy matches of `query`.
    ///
    /// Returns deduplicated list of (address, similarity) pairs above `threshold`.
    #[must_use]
    pub fn query(&self, query: &FuzzyHash, threshold: f64) -> Vec<(u64, f64)> {
        let mut candidates: std::collections::HashSet<usize> = Default::default();
        for &band in &query.bands {
            if let Some(idxs) = self.bands.get(&band) {
                for &i in idxs {
                    candidates.insert(i as usize);
                }
            }
        }
        let mut results: Vec<(u64, f64)> = candidates
            .into_iter()
            .filter_map(|i| {
                let fh = &self.hashes[i];
                let sim = query.similarity(fh);
                if sim >= threshold {
                    Some((fh.address, sim))
                } else {
                    None
                }
            })
            .collect();
        results.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        results
    }

    /// Number of indexed hashes.
    #[must_use]
    pub fn count(&self) -> usize {
        self.hashes.len()
    }
}

// ── MnemonicCategories ────────────────────────────────────────────────────────

/// Categorises mnemonics for higher-level analysis.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MnemonicCategory {
    Move,
    Arithmetic,
    Logic,
    Control,
    Memory,
    System,
    Float,
    Simd,
    Other,
}

impl MnemonicCategory {
    /// Classify a mnemonic into a category.
    #[must_use]
    pub fn classify(mnemonic: &str) -> Self {
        match mnemonic {
            "mov" | "movsx" | "movzx" | "movsxd" | "push" | "pop" | "xchg" => Self::Move,
            "add" | "adc" | "sub" | "sbb" | "mul" | "imul" | "div" | "idiv"
            | "inc" | "dec" | "neg" | "shl" | "shr" | "sal" | "sar"
            | "rol" | "ror" | "rcl" | "rcr" => Self::Arithmetic,
            "and" | "or" | "xor" | "not" | "test" | "cmp" => Self::Logic,
            "jmp" | "je" | "jne" | "jl" | "jle" | "jg" | "jge" | "ja" | "jae" | "jb" | "jbe"
            | "call" | "ret" | "retn" | "retf" | "loop" | "int" => Self::Control,
            "movq" | "movd" /* MMX/SSE moves not in the main list */ => Self::Move,
            "nop" | "hlt" | "cpuid" | "rdtsc" | "syscall" | "sysret" | "clc" | "stc"
            | "cli" | "sti" | "cld" | "std" | "enter" | "leave" => Self::System,
            mn if mn.starts_with('f') && !mn.starts_with("fb") => Self::Float,
            mn if mn.starts_with("mm") || mn.starts_with("xmm") || mn.starts_with("ymm")
                || mn.starts_with("zmm") => Self::Simd,
            mn if mn.starts_with("movs") || mn.starts_with("stosd") || mn.starts_with("lods")
                || mn.starts_with("scas") => Self::Memory,
            _ => Self::Other,
        }
    }
}

// ── PrimeProductReport ────────────────────────────────────────────────────────

/// Report of prime-product diffing between two binaries.
#[derive(Debug, Clone)]
pub struct PrimeProductReport {
    pub identical_count: usize,
    pub matched_count: usize,
    pub added_count: usize,
    pub removed_count: usize,
    pub mean_similarity: f64,
}

impl PrimeProductReport {
    /// Build from a `BinDiffMatcher` result.
    #[must_use]
    pub fn from_matcher_result(
        matches: &[BinDiffMatch],
        unmatched_a: &[FunctionHash],
        unmatched_b: &[FunctionHash],
    ) -> Self {
        let identical = matches.iter().filter(|m| m.exact).count();
        let mean_sim = if !matches.is_empty() {
            matches.iter().map(|m| m.similarity).sum::<f64>() / matches.len() as f64
        } else {
            0.0
        };
        Self {
            identical_count: identical,
            matched_count: matches.len() - identical,
            added_count: unmatched_b.len(),
            removed_count: unmatched_a.len(),
            mean_similarity: mean_sim,
        }
    }

    /// Overall binary similarity.
    #[must_use]
    pub fn binary_similarity(&self) -> f64 {
        let total =
            self.identical_count + self.matched_count + self.added_count + self.removed_count;
        if total == 0 {
            return 1.0;
        }
        (self.identical_count as f64 + self.matched_count as f64 * self.mean_similarity)
            / total as f64
    }
}

// ── MnemonicFrequencyTable ────────────────────────────────────────────────────

/// Frequency table of mnemonics across all functions in a binary.
#[derive(Debug, Clone, Default)]
pub struct MnemonicFrequencyTable {
    counts: std::collections::HashMap<String, u64>,
    total_instructions: u64,
}

impl MnemonicFrequencyTable {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record one occurrence of a mnemonic.
    pub fn record(&mut self, mnemonic: &str) {
        *self.counts.entry(mnemonic.to_string()).or_insert(0) += 1;
        self.total_instructions += 1;
    }

    /// Relative frequency of a mnemonic.
    #[must_use]
    pub fn frequency(&self, mnemonic: &str) -> f64 {
        if self.total_instructions == 0 {
            return 0.0;
        }
        let count = self.counts.get(mnemonic).copied().unwrap_or(0);
        count as f64 / self.total_instructions as f64
    }

    /// Top-N most common mnemonics.
    #[must_use]
    pub fn top_n(&self, n: usize) -> Vec<(&str, u64)> {
        let mut pairs: Vec<(&str, u64)> =
            self.counts.iter().map(|(k, &v)| (k.as_str(), v)).collect();
        pairs.sort_by(|a, b| b.1.cmp(&a.1));
        pairs.into_iter().take(n).collect()
    }

    /// Total instruction count.
    #[must_use]
    pub fn total(&self) -> u64 {
        self.total_instructions
    }
}

// ── BinDiffMatcher ────────────────────────────────────────────────────────────

/// Greedy function matcher using prime-product hashes.
///
/// Matches functions first by exact function hash, then by block-count/
/// instruction-count structural similarity.
pub struct BinDiffMatcher {
    pub threshold: f64,
}

/// A matched or unmatched function pair.
#[derive(Debug, Clone)]
pub struct BinDiffMatch {
    pub hash_a: FunctionHash,
    pub hash_b: FunctionHash,
    pub exact: bool,
    pub similarity: f64,
}

impl BinDiffMatcher {
    #[must_use]
    pub fn new(threshold: f64) -> Self {
        Self { threshold }
    }

    /// Match two sets of function hashes.
    ///
    /// Returns `(matches, unmatched_a, unmatched_b)`.
    #[must_use]
    pub fn match_functions(
        &self,
        funcs_a: &[FunctionHash],
        funcs_b: &[FunctionHash],
    ) -> (Vec<BinDiffMatch>, Vec<FunctionHash>, Vec<FunctionHash>) {
        let mut matched_b = vec![false; funcs_b.len()];
        let mut matches = Vec::new();
        let mut unmatched_a = Vec::new();

        // Pass 1: exact hash
        for fa in funcs_a {
            let found = funcs_b
                .iter()
                .enumerate()
                .find(|(i, fb)| !matched_b[*i] && fa.likely_identical(fb));
            if let Some((i, fb)) = found {
                matched_b[i] = true;
                matches.push(BinDiffMatch {
                    hash_a: fa.clone(),
                    hash_b: fb.clone(),
                    exact: true,
                    similarity: 1.0,
                });
            } else {
                unmatched_a.push(fa.clone());
            }
        }

        // Pass 2: structural similarity
        let mut remaining_a = Vec::new();
        for fa in &unmatched_a {
            let best = funcs_b
                .iter()
                .enumerate()
                .filter(|(i, _)| !matched_b[*i])
                .map(|(i, fb)| (i, fb, fa.structural_similarity(fb)))
                .filter(|(_, _, s)| *s >= self.threshold)
                .max_by(|a, b| a.2.partial_cmp(&b.2).unwrap_or(std::cmp::Ordering::Equal));
            if let Some((i, fb, sim)) = best {
                matched_b[i] = true;
                matches.push(BinDiffMatch {
                    hash_a: fa.clone(),
                    hash_b: fb.clone(),
                    exact: false,
                    similarity: sim,
                });
            } else {
                remaining_a.push(fa.clone());
            }
        }

        let unmatched_b: Vec<_> = funcs_b
            .iter()
            .enumerate()
            .filter(|(i, _)| !matched_b[*i])
            .map(|(_, f)| f.clone())
            .collect();

        (matches, remaining_a, unmatched_b)
    }
}

impl Default for BinDiffMatcher {
    fn default() -> Self {
        Self::new(0.5)
    }
}

// ── PrimeHistogram ────────────────────────────────────────────────────────────

/// Counts how many times each mnemonic's prime appears in a function.
#[derive(Debug, Clone, Default)]
pub struct PrimeHistogram {
    counts: std::collections::HashMap<u64, u32>,
}

impl PrimeHistogram {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record one occurrence of a prime.
    pub fn record(&mut self, prime: u64) {
        *self.counts.entry(prime).or_insert(0) += 1;
    }

    /// Jaccard similarity between two histograms (set of primes).
    #[must_use]
    pub fn jaccard(&self, other: &Self) -> f64 {
        let a: std::collections::HashSet<u64> = self.counts.keys().copied().collect();
        let b: std::collections::HashSet<u64> = other.counts.keys().copied().collect();
        let inter = a.intersection(&b).count();
        let union = a.len() + b.len() - inter;
        if union == 0 {
            1.0
        } else {
            inter as f64 / union as f64
        }
    }

    /// Most common prime.
    #[must_use]
    pub fn most_common(&self) -> Option<(u64, u32)> {
        self.counts
            .iter()
            .max_by_key(|&(_, &c)| c)
            .map(|(&p, &c)| (p, c))
    }

    /// Total prime occurrences.
    #[must_use]
    pub fn total(&self) -> u32 {
        self.counts.values().sum()
    }
}

// ── PrimeFunctionDatabase ─────────────────────────────────────────────────────

/// Database of prime-product function hashes for a binary.
#[derive(Debug, Default)]
pub struct PrimeFunctionDatabase {
    hashes: HashMap<u64, FunctionHash>,
    index: HashIndex,
}

impl PrimeFunctionDatabase {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a function hash.
    pub fn insert(&mut self, addr: u64, hash: FunctionHash) {
        self.index.insert(&hash);
        self.hashes.insert(addr, hash);
    }

    /// Look up by address.
    #[must_use]
    pub fn get(&self, addr: u64) -> Option<&FunctionHash> {
        self.hashes.get(&addr)
    }

    /// Find functions with the same hash (exact structural matches).
    #[must_use]
    pub fn find_matches(&self, hash: &FunctionHash) -> Vec<u64> {
        self.index.lookup(hash.value).to_vec()
    }

    /// Count of functions indexed.
    #[must_use]
    pub fn count(&self) -> usize {
        self.hashes.len()
    }

    /// Compute statistics across all indexed functions.
    #[must_use]
    pub fn stats(&self) -> DatabaseStats {
        let total = self.hashes.len();
        let unique_hashes = self.index.unique_count();
        let collision_rate = if unique_hashes > 0 {
            1.0 - (unique_hashes as f64 / total as f64)
        } else {
            0.0
        };
        let mean_blocks = if total > 0 {
            self.hashes
                .values()
                .map(|h| h.block_count as f64)
                .sum::<f64>()
                / total as f64
        } else {
            0.0
        };
        DatabaseStats {
            total,
            unique_hashes,
            collision_rate,
            mean_blocks,
        }
    }
}

/// Statistics for a prime function database.
#[derive(Debug, Clone)]
pub struct DatabaseStats {
    pub total: usize,
    pub unique_hashes: usize,
    pub collision_rate: f64,
    pub mean_blocks: f64,
}

impl fmt::Display for DatabaseStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "total={} unique={} collision_rate={:.2} mean_blocks={:.1}",
            self.total, self.unique_hashes, self.collision_rate, self.mean_blocks
        )
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn table() -> PrimeTable {
        PrimeTable::default_x86()
    }

    fn pp() -> PrimeProductHash {
        PrimeProductHash::new()
    }

    // --- PrimeTable ---

    #[test]
    fn test_table_has_200_entries() {
        let t = table();
        assert!(t.len() >= 200, "expected >= 200 entries, got {}", t.len());
    }

    #[test]
    fn test_table_mov_prime() {
        assert_eq!(table().prime("mov"), 2);
    }

    #[test]
    fn test_table_nop_prime() {
        assert_eq!(table().prime("nop"), 419);
    }

    #[test]
    fn test_table_call_prime() {
        assert_eq!(table().prime("call"), 331);
    }

    #[test]
    fn test_table_unknown_mnemonic() {
        assert_eq!(table().prime("xyz_unknown"), 1031); // default prime
    }

    #[test]
    fn test_table_contains_ret() {
        assert!(table().contains("ret"));
    }

    #[test]
    fn test_table_not_empty() {
        assert!(!table().is_empty());
    }

    // --- BlockHash ---

    #[test]
    fn test_block_hash_deterministic() {
        let t = table();
        let a = BlockHash::compute(&["add", "sub", "ret"], &t, false);
        let b = BlockHash::compute(&["add", "sub", "ret"], &t, false);
        assert_eq!(a.value, b.value);
    }

    #[test]
    fn test_block_hash_different_mnemonics() {
        let t = table();
        let a = BlockHash::compute(&["add"], &t, false);
        let b = BlockHash::compute(&["sub"], &t, false);
        assert_ne!(a.value, b.value);
    }

    #[test]
    fn test_block_hash_instr_count() {
        let t = table();
        let h = BlockHash::compute(&["nop", "nop", "ret"], &t, false);
        assert_eq!(h.instr_count, 3);
    }

    #[test]
    fn test_block_hash_empty() {
        let t = table();
        let h = BlockHash::compute(&[], &t, false);
        assert!(h.is_empty());
    }

    #[test]
    fn test_block_hash_is_conditional() {
        let t = table();
        let h = BlockHash::compute(&["cmp", "je"], &t, true);
        assert!(h.is_conditional);
    }

    // --- FunctionHash ---

    #[test]
    fn test_function_hash_deterministic() {
        let t = table();
        let b1 = BlockHash::compute(&["push", "mov"], &t, false);
        let b2 = BlockHash::compute(&["add", "ret"], &t, false);
        let h1 = FunctionHash::from_blocks(0x1000, &[b1.clone(), b2.clone()]);
        let h2 = FunctionHash::from_blocks(0x1000, &[b1, b2]);
        assert_eq!(h1.value, h2.value);
    }

    #[test]
    fn test_function_hash_block_order_invariant() {
        let t = table();
        let b1 = BlockHash::compute(&["add"], &t, false);
        let b2 = BlockHash::compute(&["sub"], &t, false);
        let h1 = FunctionHash::from_blocks(0, &[b1.clone(), b2.clone()]);
        let h2 = FunctionHash::from_blocks(0, &[b2, b1]);
        assert_eq!(h1.value, h2.value);
    }

    #[test]
    fn test_function_hash_likely_identical() {
        let t = table();
        let b = BlockHash::compute(&["nop"], &t, false);
        let h1 = FunctionHash::from_blocks(0x1000, std::slice::from_ref(&b));
        let h2 = FunctionHash::from_blocks(0x2000, &[b]);
        assert!(h1.likely_identical(&h2));
    }

    #[test]
    fn test_function_hash_structural_similarity() {
        let t = table();
        let b = BlockHash::compute(&["nop", "ret"], &t, false);
        let h1 = FunctionHash::from_blocks(0, &[b.clone(), b.clone()]);
        let h2 = FunctionHash::from_blocks(0, &[b.clone(), b.clone(), b.clone()]);
        let sim = h1.structural_similarity(&h2);
        assert!((0.0..=1.0).contains(&sim));
    }

    #[test]
    fn test_function_hash_total_instrs() {
        let t = table();
        let b1 = BlockHash::compute(&["mov", "add", "sub"], &t, false);
        let b2 = BlockHash::compute(&["ret"], &t, false);
        let h = FunctionHash::from_blocks(0, &[b1, b2]);
        assert_eq!(h.total_instrs, 4);
    }

    // --- PrimeProductHash ---

    #[test]
    fn test_pp_hash_block() {
        let p = pp();
        let bh = p.hash_block(&["mov", "add", "ret"], false);
        assert!(bh.instr_count == 3);
    }

    #[test]
    fn test_pp_hash_function() {
        let p = pp();
        let fh = p.hash_function(
            0x1000,
            &[vec!["push", "mov"], vec!["add", "ret"]],
            &[false, false],
        );
        assert_eq!(fh.block_count, 2);
        assert_eq!(fh.total_instrs, 4);
    }

    // --- HashIndex ---

    #[test]
    fn test_hash_index_insert_lookup() {
        let t = table();
        let b = BlockHash::compute(&["nop"], &t, false);
        let h = FunctionHash::from_blocks(0x1000, &[b]);
        let mut idx = HashIndex::new();
        idx.insert(&h);
        let r = idx.lookup(h.value);
        assert_eq!(r, &[0x1000]);
    }

    #[test]
    fn test_hash_index_collision() {
        let t = table();
        let b = BlockHash::compute(&["nop"], &t, false);
        let h1 = FunctionHash::from_blocks(0x1000, std::slice::from_ref(&b));
        let h2 = FunctionHash::from_blocks(0x2000, &[b]);
        let mut idx = HashIndex::new();
        idx.insert(&h1);
        idx.insert(&h2);
        let r = idx.lookup(h1.value);
        assert_eq!(r.len(), 2);
    }

    #[test]
    fn test_hash_index_unique_count() {
        let t = table();
        let b1 = BlockHash::compute(&["add"], &t, false);
        let b2 = BlockHash::compute(&["sub"], &t, false);
        let h1 = FunctionHash::from_blocks(0x1000, &[b1]);
        let h2 = FunctionHash::from_blocks(0x2000, &[b2]);
        let mut idx = HashIndex::new();
        idx.insert_all(&[h1, h2]);
        assert_eq!(idx.unique_count(), 2);
        assert_eq!(idx.function_count(), 2);
    }

    // --- FuzzyHash ---

    #[test]
    fn test_fuzzy_hash_identical_blocks() {
        let t = table();
        let blocks: Vec<BlockHash> = vec![
            BlockHash::compute(&["add", "sub"], &t, false),
            BlockHash::compute(&["mul", "ret"], &t, false),
        ];
        let fh1 = FuzzyHash::compute(0x1000, &blocks, 1);
        let fh2 = FuzzyHash::compute(0x2000, &blocks, 1);
        assert!(fh1.is_identical(&fh2));
        assert_eq!(fh1.similarity(&fh2), 1.0);
    }

    #[test]
    fn test_fuzzy_hash_different_blocks() {
        let t = table();
        let b1 = BlockHash::compute(&["add"], &t, false);
        let b2 = BlockHash::compute(&["xor"], &t, false);
        let fh1 = FuzzyHash::compute(0x1000, &[b1], 1);
        let fh2 = FuzzyHash::compute(0x2000, &[b2], 1);
        let sim = fh1.similarity(&fh2);
        assert!((0.0..=1.0).contains(&sim));
    }

    #[test]
    fn test_fuzzy_hash_empty() {
        let fh1 = FuzzyHash::compute(0, &[], 2);
        let fh2 = FuzzyHash::compute(0, &[], 2);
        assert_eq!(fh1.similarity(&fh2), 1.0);
    }

    // --- FuzzyHashIndex ---

    #[test]
    fn test_fuzzy_index_insert_count() {
        let t = table();
        let b = BlockHash::compute(&["nop"], &t, false);
        let fh = FuzzyHash::compute(0x1000, &[b], 1);
        let mut idx = FuzzyHashIndex::new();
        idx.insert(fh);
        assert_eq!(idx.count(), 1);
    }

    #[test]
    fn test_fuzzy_index_query_exact() {
        let t = table();
        let b = BlockHash::compute(&["add", "ret"], &t, false);
        let fh = FuzzyHash::compute(0x1000, std::slice::from_ref(&b), 1);
        let query = FuzzyHash::compute(0x9999, &[b], 1);
        let mut idx = FuzzyHashIndex::new();
        idx.insert(fh);
        let results = idx.query(&query, 0.9);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0, 0x1000);
    }

    #[test]
    fn test_fuzzy_index_query_no_match() {
        let t = table();
        let b1 = BlockHash::compute(&["add"], &t, false);
        let b2 = BlockHash::compute(&["xor", "not", "neg"], &t, false);
        let fh = FuzzyHash::compute(0x1000, &[b1], 1);
        let query = FuzzyHash::compute(0, &[b2], 1);
        let mut idx = FuzzyHashIndex::new();
        idx.insert(fh);
        let results = idx.query(&query, 1.0);
        assert!(results.is_empty());
    }

    // --- mul_mod ---

    #[test]
    fn test_mul_mod_no_overflow() {
        let result = mul_mod(MOD - 1, MOD - 1);
        assert!(result < MOD);
    }

    #[test]
    fn test_mul_mod_identity() {
        assert_eq!(mul_mod(1, 5), 5);
    }

    // --- Additional PrimeTable tests ---

    #[test]
    fn test_table_add_prime() {
        assert_eq!(table().prime("add"), 71);
    }

    #[test]
    fn test_table_jmp_prime() {
        assert_eq!(table().prime("jmp"), 197);
    }

    #[test]
    fn test_table_push_prime() {
        assert_eq!(table().prime("push"), 43);
    }

    #[test]
    fn test_table_pop_prime() {
        assert_eq!(table().prime("pop"), 47);
    }

    #[test]
    fn test_table_lea_prime() {
        assert_eq!(table().prime("lea"), 439);
    }

    // --- BlockHash additional ---

    #[test]
    fn test_block_hash_owned_mnemonics() {
        let t = table();
        let mns: Vec<String> = vec!["nop".to_string(), "ret".to_string()];
        let h = BlockHash::compute_owned(&mns, &t, false);
        let expected = BlockHash::compute(&["nop", "ret"], &t, false);
        assert_eq!(h.value, expected.value);
    }

    #[test]
    fn test_block_hash_single_mnemonic() {
        let t = table();
        let h = BlockHash::compute(&["ret"], &t, false);
        assert_eq!(h.instr_count, 1);
        assert!(!h.is_empty());
    }

    // --- FunctionHash additional ---

    #[test]
    fn test_function_hash_empty_blocks() {
        let h = FunctionHash::from_blocks(0, &[]);
        assert_eq!(h.block_count, 0);
        assert_eq!(h.total_instrs, 0);
    }

    #[test]
    fn test_function_hash_different_addresses_same_hash() {
        let t = table();
        let b = BlockHash::compute(&["nop"], &t, false);
        let h1 = FunctionHash::from_blocks(0x1000, std::slice::from_ref(&b));
        let h2 = FunctionHash::from_blocks(0x9999, &[b]);
        // Address should not affect the hash
        assert_eq!(h1.value, h2.value);
    }

    // --- HashIndex additional ---

    #[test]
    fn test_hash_index_empty() {
        let idx = HashIndex::new();
        assert_eq!(idx.unique_count(), 0);
        assert_eq!(idx.function_count(), 0);
    }

    #[test]
    fn test_hash_index_lookup_miss() {
        let idx = HashIndex::new();
        assert!(idx.lookup(0xDEAD).is_empty());
    }

    // --- FuzzyHash additional ---

    #[test]
    fn test_fuzzy_hash_band_size_2() {
        let t = table();
        let b1 = BlockHash::compute(&["add", "sub"], &t, false);
        let b2 = BlockHash::compute(&["add", "sub"], &t, false);
        let b3 = BlockHash::compute(&["mul"], &t, false);
        let fh1 = FuzzyHash::compute(0, &[b1, b2.clone(), b3.clone()], 2);
        let fh2 = FuzzyHash::compute(0, &[b2, b3], 2);
        let sim = fh1.similarity(&fh2);
        assert!(sim > 0.0);
    }

    #[test]
    fn test_fuzzy_hash_address() {
        let fh = FuzzyHash::compute(0xCAFE, &[], 1);
        assert_eq!(fh.address, 0xCAFE);
    }

    #[test]
    fn test_fuzzy_hash_band_size_1() {
        let t = table();
        let b = BlockHash::compute(&["nop"], &t, false);
        let fh = FuzzyHash::compute(0, std::slice::from_ref(&b), 1);
        assert_eq!(fh.band_size, 1);
        assert_eq!(fh.bands.len(), 1);
    }

    // --- BinDiffMatcher tests ---

    #[test]
    fn test_matcher_empty() {
        let m = BinDiffMatcher::default();
        let (matches, ua, ub) = m.match_functions(&[], &[]);
        assert!(matches.is_empty() && ua.is_empty() && ub.is_empty());
    }

    #[test]
    fn test_matcher_exact_match() {
        let t = table();
        let b = BlockHash::compute(&["mov", "ret"], &t, false);
        let h1 = FunctionHash::from_blocks(0x1000, std::slice::from_ref(&b));
        let h2 = FunctionHash::from_blocks(0x2000, &[b]);
        let m = BinDiffMatcher::default();
        let (matches, _ua, _ub) = m.match_functions(&[h1], &[h2]);
        assert_eq!(matches.len(), 1);
        assert!(matches[0].exact);
    }

    // --- PrimeProductReport tests ---

    #[test]
    fn test_report_empty() {
        let r = PrimeProductReport::from_matcher_result(&[], &[], &[]);
        assert_eq!(r.binary_similarity(), 1.0);
    }

    // --- PrimeHistogram tests ---

    #[test]
    fn test_histogram_empty() {
        let h = PrimeHistogram::new();
        assert_eq!(h.total(), 0);
        assert!(h.most_common().is_none());
    }

    #[test]
    fn test_histogram_record() {
        let mut h = PrimeHistogram::new();
        h.record(2);
        h.record(2);
        h.record(3);
        assert_eq!(h.total(), 3);
        assert_eq!(h.most_common(), Some((2, 2)));
    }

    #[test]
    fn test_histogram_jaccard_equal() {
        let mut a = PrimeHistogram::new();
        let mut b = PrimeHistogram::new();
        a.record(2);
        b.record(2);
        assert_eq!(a.jaccard(&b), 1.0);
    }

    // --- PrimeFunctionDatabase tests ---

    #[test]
    fn test_db_empty() {
        let db = PrimeFunctionDatabase::new();
        assert_eq!(db.count(), 0);
    }

    #[test]
    fn test_db_insert_get() {
        let t = table();
        let b = BlockHash::compute(&["nop"], &t, false);
        let h = FunctionHash::from_blocks(0x1000, &[b]);
        let mut db = PrimeFunctionDatabase::new();
        db.insert(0x1000, h);
        assert!(db.get(0x1000).is_some());
    }

    #[test]
    fn test_db_stats() {
        let t = table();
        let b = BlockHash::compute(&["nop"], &t, false);
        let h = FunctionHash::from_blocks(0x1000, &[b]);
        let mut db = PrimeFunctionDatabase::new();
        db.insert(0x1000, h);
        let s = db.stats();
        assert_eq!(s.total, 1);
    }

    // --- MnemonicCategory tests ---

    #[test]
    fn test_mnemonic_category_mov() {
        assert_eq!(MnemonicCategory::classify("mov"), MnemonicCategory::Move);
    }

    #[test]
    fn test_mnemonic_category_call() {
        assert_eq!(
            MnemonicCategory::classify("call"),
            MnemonicCategory::Control
        );
    }

    #[test]
    fn test_mnemonic_category_add() {
        assert_eq!(
            MnemonicCategory::classify("add"),
            MnemonicCategory::Arithmetic
        );
    }

    #[test]
    fn test_mnemonic_category_nop() {
        assert_eq!(MnemonicCategory::classify("nop"), MnemonicCategory::System);
    }

    // --- MnemonicFrequencyTable tests ---

    #[test]
    fn test_freq_table_empty() {
        let t = MnemonicFrequencyTable::new();
        assert_eq!(t.total(), 0);
        assert_eq!(t.frequency("mov"), 0.0);
    }

    #[test]
    fn test_freq_table_record() {
        let mut t = MnemonicFrequencyTable::new();
        t.record("mov");
        t.record("mov");
        t.record("add");
        assert_eq!(t.total(), 3);
        assert!((t.frequency("mov") - 2.0 / 3.0).abs() < 1e-9);
    }

    #[test]
    fn test_freq_table_top_n() {
        let mut t = MnemonicFrequencyTable::new();
        for _ in 0..5 {
            t.record("mov");
        }
        for _ in 0..3 {
            t.record("add");
        }
        t.record("sub");
        let top = t.top_n(2);
        assert_eq!(top.len(), 2);
        assert_eq!(top[0].0, "mov");
    }

    // --- PrimeProductReport tests ---

    #[test]
    fn test_report_all_identical() {
        let t = table();
        let b1 = BlockHash::compute(&["add", "ret"], &t, false);
        let h1 = FunctionHash::from_blocks(0x1000, std::slice::from_ref(&b1));
        let h2 = FunctionHash::from_blocks(0x2000, &[b1]);
        let m = BinDiffMatcher::default();
        let (matches, ua, ub) = m.match_functions(&[h1], &[h2]);
        let r = PrimeProductReport::from_matcher_result(&matches, &ua, &ub);
        assert_eq!(r.identical_count, 1);
        assert!(r.binary_similarity() > 0.9);
    }

    // --- DatabaseStats display ---

    #[test]
    fn test_db_stats_display() {
        let db = PrimeFunctionDatabase::new();
        let s = db.stats();
        let d = s.to_string();
        assert!(d.contains("total=0"));
    }
}

// ── BlockHashSequence ─────────────────────────────────────────────────────────

/// An ordered sequence of block hashes, representing a function's CFG walk order.
///
/// Used for sequence-alignment-based matching as an alternative to set matching.
#[derive(Debug, Clone)]
pub struct BlockHashSequence {
    pub values: Vec<u64>,
    pub address: u64,
}

impl BlockHashSequence {
    /// Build from a function's block hashes.
    #[must_use]
    pub fn from_blocks(address: u64, blocks: &[BlockHash]) -> Self {
        Self {
            values: blocks.iter().map(|b| b.value).collect(),
            address,
        }
    }

    /// LCS-based similarity between two sequences.
    #[must_use]
    pub fn lcs_similarity(&self, other: &Self) -> f64 {
        let a = &self.values;
        let b = &other.values;
        if a.is_empty() && b.is_empty() {
            return 1.0;
        }
        if a.is_empty() || b.is_empty() {
            return 0.0;
        }
        let la = a.len().min(256);
        let lb = b.len().min(256);
        let mut dp = vec![vec![0usize; lb + 1]; la + 1];
        for i in 1..=la {
            for j in 1..=lb {
                dp[i][j] = if a[i - 1] == b[j - 1] {
                    dp[i - 1][j - 1] + 1
                } else {
                    dp[i - 1][j].max(dp[i][j - 1])
                };
            }
        }
        let lcs = dp[la][lb] as f64;
        2.0 * lcs / (la + lb) as f64
    }

    /// Length of the sequence.
    #[must_use]
    pub fn len(&self) -> usize {
        self.values.len()
    }

    /// Whether the sequence is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }
}
