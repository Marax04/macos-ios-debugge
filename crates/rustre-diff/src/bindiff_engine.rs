// bindiff_engine.rs — BinDiff-style function matching engine

use std::collections::{HashMap, HashSet};
use serde::{Deserialize, Serialize};

// ── Basic block hash ───────────────────────────────────────────────────────────

/// Prime product signature for a basic block: product of small primes mapped to opcode mnemonics
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct BlockSignature(pub u64);

impl BlockSignature {
    #[must_use] 
    pub fn from_instructions(instructions: &[InstructionInfo]) -> Self {
        const PRIMES: &[u64] = &[
            2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47,
            53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113,
            127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197,
            199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281,
        ];

        let mut product: u64 = 1;
        for insn in instructions {
            let idx = (insn.opcode_hash as usize) % PRIMES.len();
            product = product.wrapping_mul(PRIMES[idx]);
        }
        Self(product)
    }
}

/// CRC32-based hash of literal byte sequences in a basic block
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct BlockBytesHash(pub u32);

impl BlockBytesHash {
    #[must_use] 
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(crc32fast::hash(bytes))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstructionInfo {
    pub address: u64,
    pub opcode_hash: u32,
    pub mnemonic: String,
    pub operand_count: u8,
    pub is_call: bool,
    pub is_branch: bool,
    pub is_ret: bool,
    pub call_target: Option<u64>,
    pub branch_targets: Vec<u64>,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BasicBlock {
    pub start_address: u64,
    pub end_address: u64,
    pub instructions: Vec<InstructionInfo>,
    pub successors: Vec<u64>,
    pub predecessors: Vec<u64>,
    pub block_sig: BlockSignature,
    pub bytes_hash: BlockBytesHash,
    pub is_entry: bool,
    pub is_exit: bool,
}

impl BasicBlock {
    #[must_use] 
    pub const fn instruction_count(&self) -> usize {
        self.instructions.len()
    }

    #[must_use] 
    pub fn has_call(&self) -> bool {
        self.instructions.iter().any(|i| i.is_call)
    }

    #[must_use] 
    pub fn call_targets(&self) -> Vec<u64> {
        self.instructions
            .iter()
            .filter_map(|i| i.call_target)
            .collect()
    }
}

// ── Function representation ────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionInfo {
    pub address: u64,
    pub name: String,
    pub basic_blocks: Vec<BasicBlock>,
    pub cfg_hash: u64,
    pub call_graph_hash: u64,
    pub callee_addresses: Vec<u64>,
    pub caller_addresses: Vec<u64>,
    pub loop_count: usize,
    pub is_library: bool,
    pub is_thunk: bool,
    pub binary_id: usize,
}

impl FunctionInfo {
    #[must_use] 
    pub const fn block_count(&self) -> usize {
        self.basic_blocks.len()
    }

    #[must_use] 
    pub fn instruction_count(&self) -> usize {
        self.basic_blocks.iter().map(|b| b.instructions.len()).sum()
    }

    #[must_use] 
    pub fn edge_count(&self) -> usize {
        self.basic_blocks
            .iter()
            .map(|b| b.successors.len())
            .sum()
    }

    #[must_use] 
    pub fn compute_cfg_hash(&self) -> u64 {
        // Hash the control flow graph structure (not addresses)
        // For each block: (block_sig, sorted_successor_relative_offsets)
        let mut h = 0u64;
        let base = self.basic_blocks.first().map_or(0, |b| b.start_address);
        for block in &self.basic_blocks {
            h = h.wrapping_mul(0x9e37_79b9_7f4a_7c15);
            h ^= block.block_sig.0;
            for succ in &block.successors {
                let rel = succ.wrapping_sub(base);
                h = h.wrapping_add(rel.wrapping_mul(0x517c_c1b7_2722_0a95));
            }
        }
        h
    }

    #[must_use] 
    pub fn topological_signature(&self) -> Vec<u64> {
        // Topological sort of blocks, return sequence of block signatures
        let mut result = Vec::new();
        let mut visited: HashSet<u64> = HashSet::new();
        let mut stack: Vec<u64> = Vec::new();

        if let Some(entry) = self.basic_blocks.iter().find(|b| b.is_entry) {
            stack.push(entry.start_address);
        }

        let block_map: HashMap<u64, &BasicBlock> = self
            .basic_blocks
            .iter()
            .map(|b| (b.start_address, b))
            .collect();

        while let Some(addr) = stack.pop() {
            if visited.contains(&addr) {
                continue;
            }
            visited.insert(addr);
            if let Some(block) = block_map.get(&addr) {
                result.push(block.block_sig.0);
                for succ in block.successors.iter().rev() {
                    if !visited.contains(succ) {
                        stack.push(*succ);
                    }
                }
            }
        }
        result
    }
}

// ── Match result ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionMatch {
    pub primary_address: u64,
    pub primary_name: String,
    pub secondary_address: u64,
    pub secondary_name: String,
    pub similarity: f64,
    pub confidence: f64,
    pub match_type: MatchType,
    pub block_matches: Vec<BlockMatch>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MatchType {
    /// Exact same name in both binaries
    NameMatch,
    /// Identical hash (byte-perfect)
    HashMatch,
    /// CFG structure match
    CfgMatch,
    /// Prime product signature match
    PrimeProductMatch,
    /// Call graph neighbor propagation
    PropagatedMatch,
    /// Heuristic match (low confidence)
    HeuristicMatch,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockMatch {
    pub primary_block: u64,
    pub secondary_block: u64,
    pub similarity: f64,
}

// ── Diff engine ────────────────────────────────────────────────────────────────

pub struct BinDiffEngine {
    primary_functions: HashMap<u64, FunctionInfo>,
    secondary_functions: HashMap<u64, FunctionInfo>,
    primary_name_map: HashMap<String, u64>,
    secondary_name_map: HashMap<String, u64>,
}

/// A name a disassembler invented from an address, not a symbol read from the
/// binary. Two independently stripped builds each invent these, so they carry
/// no identity: `sub_1000` in one image and `sub_1000` in another are unrelated
/// code that merely landed at the same offset.
#[must_use]
pub fn is_synthetic_name(name: &str) -> bool {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return true;
    }
    const PREFIXES: &[&str] = &[
        "sub_", "loc_", "locret_", "unk_", "nullsub_", "j_", "off_", "byte_", "word_", "dword_",
        "qword_", "fn_", "func_", "FUN_", "LAB_", "SUB_",
    ];
    PREFIXES.iter().any(|p| trimmed.starts_with(p))
}

/// Index real symbol names to addresses. A name carried by more than one
/// function identifies nothing, so it is dropped rather than silently
/// resolving to whichever entry the iteration happened to visit last.
fn build_name_map(functions: &[FunctionInfo]) -> HashMap<String, u64> {
    let mut map: HashMap<String, u64> = HashMap::with_capacity(functions.len());
    let mut ambiguous: HashSet<&str> = HashSet::new();
    for f in functions {
        if is_synthetic_name(&f.name) {
            continue;
        }
        if map.insert(f.name.clone(), f.address).is_some() {
            ambiguous.insert(f.name.as_str());
        }
    }
    for name in ambiguous {
        map.remove(name);
    }
    map
}

impl BinDiffEngine {
    #[must_use]
    pub fn new(
        primary: Vec<FunctionInfo>,
        secondary: Vec<FunctionInfo>,
    ) -> Self {
        let primary_name_map = build_name_map(&primary);
        let secondary_name_map = build_name_map(&secondary);
        let primary_functions: HashMap<u64, FunctionInfo> =
            primary.into_iter().map(|f| (f.address, f)).collect();
        let secondary_functions: HashMap<u64, FunctionInfo> =
            secondary.into_iter().map(|f| (f.address, f)).collect();

        Self {
            primary_functions,
            secondary_functions,
            primary_name_map,
            secondary_name_map,
        }
    }

    #[must_use]
    pub fn diff(&self) -> DiffResult {
        let mut matches: Vec<FunctionMatch> = Vec::new();
        let mut matched_primary: HashSet<u64> = HashSet::new();
        let mut matched_secondary: HashSet<u64> = HashSet::new();

        self.pass1_name_matches(&mut matches, &mut matched_primary, &mut matched_secondary);
        self.pass2_hash_matches(&mut matches, &mut matched_primary, &mut matched_secondary);
        self.pass3_propagation(&mut matches, &mut matched_primary, &mut matched_secondary);
        self.pass4_heuristic(&mut matches, &mut matched_primary, &mut matched_secondary);

        // Collect unmatched
        let unmatched_primary: Vec<u64> = self
            .primary_functions
            .keys()
            .filter(|a| !matched_primary.contains(a))
            .copied()
            .collect();

        let unmatched_secondary: Vec<u64> = self
            .secondary_functions
            .keys()
            .filter(|a| !matched_secondary.contains(a))
            .copied()
            .collect();

        // Compute overall similarity score
        let total_funcs = f64::from(u32::try_from(
            self.primary_functions.len().max(self.secondary_functions.len()),
        ).unwrap_or(u32::MAX));
        let match_score = if total_funcs > 0.0 {
            matches.iter().map(|m| m.similarity).sum::<f64>() / total_funcs
        } else {
            0.0
        };

        DiffResult {
            matches,
            unmatched_primary,
            unmatched_secondary,
            match_score,
            primary_function_count: self.primary_functions.len(),
            secondary_function_count: self.secondary_functions.len(),
        }
    }

    fn pass1_name_matches(
        &self,
        matches: &mut Vec<FunctionMatch>,
        matched_primary: &mut HashSet<u64>,
        matched_secondary: &mut HashSet<u64>,
    ) {
        // Sorted so the emitted match order does not depend on `HashMap`
        // iteration order: the same pair of binaries must diff identically
        // on every run.
        let mut names: Vec<&String> = self.primary_name_map.keys().collect();
        names.sort_unstable();
        for name in names {
            let primary_addr = self.primary_name_map[name];
            if let Some(&secondary_addr) = self.secondary_name_map.get(name) {
                let pf = &self.primary_functions[&primary_addr];
                let sf = &self.secondary_functions[&secondary_addr];
                let sim = Self::compute_similarity(pf, sf);
                matches.push(FunctionMatch {
                    primary_address: primary_addr,
                    primary_name: pf.name.clone(),
                    secondary_address: secondary_addr,
                    secondary_name: sf.name.clone(),
                    similarity: sim,
                    confidence: 0.99,
                    match_type: MatchType::NameMatch,
                    block_matches: Self::match_blocks(pf, sf),
                });
                matched_primary.insert(primary_addr);
                matched_secondary.insert(secondary_addr);
            }
        }
    }

    fn pass2_hash_matches(
        &self,
        matches: &mut Vec<FunctionMatch>,
        matched_primary: &mut HashSet<u64>,
        matched_secondary: &mut HashSet<u64>,
    ) {
        // `cfg_hash == 0` is the value a `FunctionInfo` carries when the hash
        // was never computed. It is a sentinel, not a fingerprint: keying on it
        // pairs every un-hashed function with every other one.
        //
        // A hash carried by several unmatched primaries identifies none of them,
        // so it is dropped too — an arbitrary pick would be a coin flip stamped
        // with confidence 0.95.
        let mut primary_by_cfg: HashMap<u64, u64> = HashMap::new();
        let mut ambiguous_cfg: HashSet<u64> = HashSet::new();
        let mut primaries: Vec<&FunctionInfo> = self
            .primary_functions
            .values()
            .filter(|f| f.cfg_hash != 0 && !matched_primary.contains(&f.address))
            .collect();
        primaries.sort_unstable_by_key(|f| f.address);
        for f in primaries {
            if primary_by_cfg.insert(f.cfg_hash, f.address).is_some() {
                ambiguous_cfg.insert(f.cfg_hash);
            }
        }
        for h in &ambiguous_cfg {
            primary_by_cfg.remove(h);
        }

        let mut unmatched_s: Vec<u64> = Vec::new();
        // Counted once, not rescanned per candidate: this loop is otherwise
        // quadratic in the number of functions.
        let mut secondary_cfg_counts: HashMap<u64, usize> = HashMap::new();
        for f in self.secondary_functions.values() {
            if f.cfg_hash != 0 && !matched_secondary.contains(&f.address) {
                *secondary_cfg_counts.entry(f.cfg_hash).or_insert(0) += 1;
                unmatched_s.push(f.address);
            }
        }
        unmatched_s.sort_unstable();
        for s_addr in unmatched_s {
            let sf = &self.secondary_functions[&s_addr];
            // A secondary whose hash is shared with another unmatched secondary
            // cannot be told apart from it either.
            if secondary_cfg_counts.get(&sf.cfg_hash).copied().unwrap_or(0) > 1 {
                continue;
            }
            if let Some(&primary_addr) = primary_by_cfg.get(&sf.cfg_hash) {
                // The snapshot is taken once; a primary claimed earlier in this
                // very loop must not be handed out again. Matching is a partial
                // injection, not a fan-out.
                if matched_primary.contains(&primary_addr) {
                    continue;
                }
                let pf = &self.primary_functions[&primary_addr];
                let sim = Self::compute_similarity(pf, sf);
                matches.push(FunctionMatch {
                    primary_address: primary_addr,
                    primary_name: pf.name.clone(),
                    secondary_address: sf.address,
                    secondary_name: sf.name.clone(),
                    similarity: sim,
                    confidence: 0.95,
                    match_type: MatchType::CfgMatch,
                    block_matches: Self::match_blocks(pf, sf),
                });
                matched_primary.insert(primary_addr);
                matched_secondary.insert(sf.address);
            }
        }
    }

    fn pass3_propagation(
        &self,
        matches: &mut Vec<FunctionMatch>,
        matched_primary: &mut HashSet<u64>,
        matched_secondary: &mut HashSet<u64>,
    ) {
        let mut propagation_rounds = 0;
        loop {
            let mut new_matches = 0;
            let current_pairs: Vec<(u64, u64)> = matches
                .iter()
                .map(|m| (m.primary_address, m.secondary_address))
                .collect();
            for (paddr, saddr) in &current_pairs {
                let pf = &self.primary_functions[paddr];
                let sf = &self.secondary_functions[saddr];
                let p_callees: Vec<u64> = pf.callee_addresses.iter()
                    .filter(|a| !matched_primary.contains(a)).copied().collect();
                let s_callees: Vec<u64> = sf.callee_addresses.iter()
                    .filter(|a| !matched_secondary.contains(a)).copied().collect();
                if p_callees.len() == s_callees.len() && !p_callees.is_empty() {
                    for (&pc, &sc) in p_callees.iter().zip(s_callees.iter()) {
                        if let (Some(pcf), Some(scf)) = (
                            self.primary_functions.get(&pc),
                            self.secondary_functions.get(&sc),
                        ) && Self::block_count_compatible(pcf, scf) {
                            let sim = Self::compute_similarity(pcf, scf);
                            if sim > 0.7 {
                                matches.push(FunctionMatch {
                                    primary_address: pc,
                                    primary_name: pcf.name.clone(),
                                    secondary_address: sc,
                                    secondary_name: scf.name.clone(),
                                    similarity: sim,
                                    confidence: 0.80,
                                    match_type: MatchType::PropagatedMatch,
                                    block_matches: Self::match_blocks(pcf, scf),
                                });
                                matched_primary.insert(pc);
                                matched_secondary.insert(sc);
                                new_matches += 1;
                            }
                        }
                    }
                }
            }
            propagation_rounds += 1;
            if new_matches == 0 || propagation_rounds > 5 {
                break;
            }
        }
    }

    fn pass4_heuristic(
        &self,
        matches: &mut Vec<FunctionMatch>,
        matched_primary: &mut HashSet<u64>,
        matched_secondary: &mut HashSet<u64>,
    ) {
        let mut remaining_primary: Vec<&FunctionInfo> = self
            .primary_functions
            .values()
            .filter(|f| !matched_primary.contains(&f.address))
            .collect();
        let mut remaining_secondary: Vec<&FunctionInfo> = self
            .secondary_functions
            .values()
            .filter(|f| !matched_secondary.contains(&f.address))
            .collect();
        // Greedy best-match is order-sensitive twice over: which primary picks
        // first, and which secondary wins a tie. Address order makes both
        // reproducible instead of dependent on `HashMap` layout.
        remaining_primary.sort_unstable_by_key(|f| f.address);
        remaining_secondary.sort_unstable_by_key(|f| f.address);
        for pf in &remaining_primary {
            let mut best_sim = 0.6;
            let mut best_sf: Option<&FunctionInfo> = None;
            for sf in &remaining_secondary {
                if matched_secondary.contains(&sf.address) {
                    continue;
                }
                if !Self::block_count_compatible(pf, sf) {
                    continue;
                }
                let sim = Self::compute_similarity(pf, sf);
                if sim > best_sim {
                    best_sim = sim;
                    best_sf = Some(sf);
                }
            }
            if let Some(sf) = best_sf {
                matches.push(FunctionMatch {
                    primary_address: pf.address,
                    primary_name: pf.name.clone(),
                    secondary_address: sf.address,
                    secondary_name: sf.name.clone(),
                    similarity: best_sim,
                    confidence: 0.60,
                    match_type: MatchType::HeuristicMatch,
                    block_matches: Self::match_blocks(pf, sf),
                });
                matched_primary.insert(pf.address);
                matched_secondary.insert(sf.address);
            }
        }
    }

    fn block_count_compatible(pf: &FunctionInfo, sf: &FunctionInfo) -> bool {
        let pb = f64::from(u32::try_from(pf.block_count()).unwrap_or(u32::MAX));
        let sb = f64::from(u32::try_from(sf.block_count()).unwrap_or(u32::MAX));
        if pb == 0.0 && sb == 0.0 {
            return true;
        }
        let ratio = (pb - sb).abs() / pb.max(sb);
        ratio < 0.5 // within 50% block count
    }

    fn compute_similarity(pf: &FunctionInfo, sf: &FunctionInfo) -> f64 {
        let mut score = 0.0;
        let mut weights = 0.0;

        // Block count similarity (weight 0.2)
        let pb = f64::from(u32::try_from(pf.block_count()).unwrap_or(u32::MAX));
        let sb = f64::from(u32::try_from(sf.block_count()).unwrap_or(u32::MAX));
        if pb + sb > 0.0 {
            let block_sim = 1.0 - (pb - sb).abs() / (pb + sb);
            score += block_sim * 0.2;
        }
        weights += 0.2;

        // Instruction count similarity (weight 0.1)
        let pi = f64::from(u32::try_from(pf.instruction_count()).unwrap_or(u32::MAX));
        let si = f64::from(u32::try_from(sf.instruction_count()).unwrap_or(u32::MAX));
        if pi + si > 0.0 {
            let insn_sim = 1.0 - (pi - si).abs() / (pi + si);
            score += insn_sim * 0.1;
        }
        weights += 0.1;

        // CFG hash exact match (weight 0.4)
        if pf.cfg_hash == sf.cfg_hash && pf.cfg_hash != 0 {
            score += 0.4;
        }
        weights += 0.4;

        // Topological signature similarity (weight 0.2)
        let p_topo = pf.topological_signature();
        let s_topo = sf.topological_signature();
        let topo_sim = lcs_ratio(&p_topo, &s_topo);
        score = topo_sim.mul_add(0.2, score);
        weights += 0.2;

        // Callee count similarity (weight 0.1)
        let pc = f64::from(u32::try_from(pf.callee_addresses.len()).unwrap_or(u32::MAX));
        let sc = f64::from(u32::try_from(sf.callee_addresses.len()).unwrap_or(u32::MAX));
        if pc + sc > 0.0 {
            let callee_sim = 1.0 - (pc - sc).abs() / (pc + sc);
            score += callee_sim * 0.1;
        }
        weights += 0.1;

        if weights > 0.0 { score / weights * (0.2 + 0.1 + 0.4 + 0.2 + 0.1) } else { 0.0 }
    }

    fn match_blocks(pf: &FunctionInfo, sf: &FunctionInfo) -> Vec<BlockMatch> {
        let mut result = Vec::new();
        let mut matched_secondary: HashSet<u64> = HashSet::new();

        for pb in &pf.basic_blocks {
            let mut best_sim = 0.0;
            let mut best_sb_addr = None;

            for sb in &sf.basic_blocks {
                if matched_secondary.contains(&sb.start_address) {
                    continue;
                }
                let sim = Self::block_similarity(pb, sb);
                if sim > best_sim {
                    best_sim = sim;
                    best_sb_addr = Some(sb.start_address);
                }
            }

            if best_sim > 0.5
                && let Some(sb_addr) = best_sb_addr {
                    matched_secondary.insert(sb_addr);
                    result.push(BlockMatch {
                        primary_block: pb.start_address,
                        secondary_block: sb_addr,
                        similarity: best_sim,
                    });
                }
        }

        result
    }

    fn block_similarity(pb: &BasicBlock, sb: &BasicBlock) -> f64 {
        // Exact bytes hash match
        if pb.bytes_hash == sb.bytes_hash {
            return 1.0;
        }
        // Prime product match (structural)
        if pb.block_sig == sb.block_sig {
            return 0.85;
        }
        // Instruction count
        let pi = f64::from(u32::try_from(pb.instruction_count()).unwrap_or(u32::MAX));
        let si = f64::from(u32::try_from(sb.instruction_count()).unwrap_or(u32::MAX));
        if pi + si == 0.0 {
            return 1.0;
        }
        1.0 - (pi - si).abs() / (pi + si)
    }
}

fn lcs_ratio(a: &[u64], b: &[u64]) -> f64 {
    if a.is_empty() && b.is_empty() {
        return 1.0;
    }
    if a.is_empty() || b.is_empty() {
        return 0.0;
    }
    // DP LCS
    let m = a.len().min(50); // cap for performance
    let n = b.len().min(50);
    let a = &a[..m];
    let b = &b[..n];
    let mut dp = vec![vec![0usize; n + 1]; m + 1];
    for i in 1..=m {
        for j in 1..=n {
            dp[i][j] = if a[i - 1] == b[j - 1] {
                dp[i - 1][j - 1] + 1
            } else {
                dp[i - 1][j].max(dp[i][j - 1])
            };
        }
    }
    let lcs = dp[m][n];
    2.0 * f64::from(u32::try_from(lcs).unwrap_or(u32::MAX))
        / f64::from(u32::try_from(m + n).unwrap_or(u32::MAX))
}

// ── Diff result ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffResult {
    pub matches: Vec<FunctionMatch>,
    pub unmatched_primary: Vec<u64>,
    pub unmatched_secondary: Vec<u64>,
    pub match_score: f64,
    pub primary_function_count: usize,
    pub secondary_function_count: usize,
}

impl DiffResult {
    #[must_use] 
    pub const fn matched_count(&self) -> usize {
        self.matches.len()
    }

    #[must_use] 
    pub fn identical_count(&self) -> usize {
        self.matches
            .iter()
            .filter(|m| m.similarity >= 0.99)
            .count()
    }

    #[must_use] 
    pub fn changed_count(&self) -> usize {
        self.matches
            .iter()
            .filter(|m| m.similarity < 0.99)
            .count()
    }

    #[must_use] 
    pub const fn added_count(&self) -> usize {
        self.unmatched_secondary.len()
    }

    #[must_use] 
    pub const fn removed_count(&self) -> usize {
        self.unmatched_primary.len()
    }

    /// # Panics
    ///
    /// Panics if any `similarity` value is NaN (which cannot occur for well-formed matches).
    #[must_use]
    pub fn top_changed(&self, n: usize) -> Vec<&FunctionMatch> {
        let mut changed: Vec<&FunctionMatch> = self
            .matches
            .iter()
            .filter(|m| m.similarity < 0.99)
            .collect();
        changed.sort_by(|a, b| a.similarity.partial_cmp(&b.similarity).unwrap());
        changed.into_iter().take(n).collect()
    }

    #[must_use] 
    pub fn summary(&self) -> DiffSummary {
        DiffSummary {
            total_primary: self.primary_function_count,
            total_secondary: self.secondary_function_count,
            matched: self.matched_count(),
            identical: self.identical_count(),
            changed: self.changed_count(),
            added: self.added_count(),
            removed: self.removed_count(),
            similarity_score: self.match_score,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffSummary {
    pub total_primary: usize,
    pub total_secondary: usize,
    pub matched: usize,
    pub identical: usize,
    pub changed: usize,
    pub added: usize,
    pub removed: usize,
    pub similarity_score: f64,
}

// ── Tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_block(addr: u64, insns: &[(u32, &str)]) -> BasicBlock {
        let instructions: Vec<InstructionInfo> = insns
            .iter()
            .map(|&(hash, mnemonic)| InstructionInfo {
                address: addr,
                opcode_hash: hash,
                mnemonic: mnemonic.to_string(),
                operand_count: 2,
                is_call: mnemonic == "call",
                is_branch: mnemonic.starts_with('j'),
                is_ret: mnemonic == "ret",
                call_target: None,
                branch_targets: vec![],
                bytes: vec![],
            })
            .collect();
        let sig = BlockSignature::from_instructions(&instructions);
        BasicBlock {
            start_address: addr,
            end_address: addr + insns.len() as u64 * 4,
            instructions,
            successors: vec![],
            predecessors: vec![],
            block_sig: sig,
            bytes_hash: BlockBytesHash(0),
            is_entry: true,
            is_exit: false,
        }
    }

    fn make_func(addr: u64, name: &str, blocks: Vec<BasicBlock>) -> FunctionInfo {
        let cfg_hash = blocks.iter().map(|b| b.block_sig.0).fold(0u64, |a, x| a ^ x);
        FunctionInfo {
            address: addr,
            name: name.to_string(),
            basic_blocks: blocks,
            cfg_hash,
            call_graph_hash: 0,
            callee_addresses: vec![],
            caller_addresses: vec![],
            loop_count: 0,
            is_library: false,
            is_thunk: false,
            binary_id: 0,
        }
    }

    #[test]
    fn test_name_match() {
        let f1 = make_func(0x1000, "main", vec![make_block(0x1000, &[(1, "push"), (2, "mov")])]);
        let f2 = make_func(0x2000, "main", vec![make_block(0x2000, &[(1, "push"), (2, "mov")])]);
        let engine = BinDiffEngine::new(vec![f1], vec![f2]);
        let result = engine.diff();
        assert!(!result.matches.is_empty());
        assert!(matches!(result.matches[0].match_type, MatchType::NameMatch));
    }

    #[test]
    fn test_lcs_ratio() {
        let a = vec![1u64, 2, 3, 4];
        let b = vec![1u64, 2, 3, 4];
        assert!((lcs_ratio(&a, &b) - 1.0).abs() < 0.01);
        let c = vec![5u64, 6, 7];
        assert!(lcs_ratio(&a, &c) < 0.5);
    }

    #[test]
    fn test_block_signature() {
        let insns1 = vec![
            InstructionInfo { address: 0, opcode_hash: 1, mnemonic: "push".into(),
                operand_count: 1, is_call: false, is_branch: false, is_ret: false,
                call_target: None, branch_targets: vec![], bytes: vec![] },
        ];
        let insns2 = insns1.clone();
        assert_eq!(
            BlockSignature::from_instructions(&insns1),
            BlockSignature::from_instructions(&insns2),
        );
    }
}
