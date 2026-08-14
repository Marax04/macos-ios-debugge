// switch_detection.rs — Switch statement detection from LLIL patterns
// Part of rustre-il-passes crate
//
// Detects four switch patterns from LLIL control-flow graphs:
//   Pattern 1 — Jump table (indirect jump through table)
//   Pattern 2 — Binary search tree (balanced CMP+JCC tree)
//   Pattern 3 — Chained if-else (sequential CMP/JE for contiguous values)
//   Pattern 4 — String switch hash (switch on hash(arg))

use std::collections::{HashMap, HashSet, BTreeMap};
use std::fmt;

// ---------------------------------------------------------------------------
// Dependency stubs (types normally imported from the crate)
// ---------------------------------------------------------------------------

/// Machine address.
pub type Address = u64;

/// A LLIL basic block index within a function.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct BlockId(pub u32);

/// Minimal LLIL instruction for pattern matching.
#[derive(Debug, Clone)]
pub enum LlilInsn {
    /// Load from memory at address: (`result_size`, `base_reg`, `index_reg`, stride)
    Load {
        dest:   Option<String>,  // destination temp/register
        size:   u8,
        base:   u64,             // known base address (0 if unknown)
        index:  Option<String>,  // index register/temp name
        stride: u8,              // element size (4 or 8)
    },
    /// Indirect jump: jump to value in register/temp.
    IndirectJump { target: String },
    /// Conditional branch: if (cond) goto `true_target` else goto `false_target`.
    CondBranch {
        cond:         BranchCond,
        true_target:  Address,
        false_target: Address,
    },
    /// Compare register with constant.
    Compare { reg: String, value: i64, kind: CmpKind },
    /// Call to named function.
    Call { target: String },
    /// Nop / other (not relevant to switch detection).
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BranchCond {
    Equal,
    NotEqual,
    Less,
    LessEqual,
    Greater,
    GreaterEqual,
    Above,    // unsigned less than
    AboveEq,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CmpKind { Eq, Ne, Lt, Le, Gt, Ge }

/// A basic block in a LLIL control-flow graph.
#[derive(Debug, Clone)]
pub struct BasicBlock {
    pub id:           BlockId,
    pub start:        Address,
    pub end:          Address,
    pub instructions: Vec<LlilInsn>,
    pub successors:   Vec<BlockId>,
    pub predecessors: Vec<BlockId>,
}

impl BasicBlock {
    #[must_use] 
    pub fn last_insn(&self) -> Option<&LlilInsn> { self.instructions.last() }

    #[must_use] 
    pub fn is_cond_branch(&self) -> bool {
        matches!(self.last_insn(), Some(LlilInsn::CondBranch { .. }))
    }
}

/// A LLIL function body (collection of basic blocks).
#[derive(Debug, Clone)]
pub struct LlilFunction {
    pub blocks: Vec<BasicBlock>,
    pub entry:  BlockId,
    pub name:   String,
}

impl LlilFunction {
    #[must_use] 
    pub fn block(&self, id: BlockId) -> Option<&BasicBlock> {
        self.blocks.iter().find(|b| b.id == id)
    }

    #[must_use] 
    pub const fn block_count(&self) -> usize { self.blocks.len() }
}

// ---------------------------------------------------------------------------
// Switch information output
// ---------------------------------------------------------------------------

/// A single case of a detected switch statement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SwitchCase {
    /// The case value(s) that map to this target (may be multiple for "fall-through" groups).
    pub values: Vec<i64>,
    /// The target address of this case.
    pub target: Address,
}

/// Switch type that was detected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SwitchPattern {
    JumpTable,
    BinarySearch,
    ChainedIfElse,
    StringSwitchHash { hash_function: String },
}

impl fmt::Display for SwitchPattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::JumpTable            => write!(f, "jump-table"),
            Self::BinarySearch         => write!(f, "binary-search"),
            Self::ChainedIfElse        => write!(f, "chained-if-else"),
            Self::StringSwitchHash { hash_function } =>
                write!(f, "string-switch-hash({hash_function})"),
        }
    }
}

/// Fully reconstructed switch statement.
#[derive(Debug, Clone)]
pub struct SwitchInfo {
    /// The block containing the switch dispatch logic.
    pub dispatch_block: BlockId,
    /// The expression being switched on (register/variable name).
    pub switch_var:     String,
    /// All identified cases.
    pub cases:          Vec<SwitchCase>,
    /// The default case target address, if any.
    pub default_addr:   Option<Address>,
    /// Which pattern was used to identify this switch.
    pub pattern:        SwitchPattern,
    /// Source address of the jump table (Pattern 1 only).
    pub table_addr:     Option<Address>,
    /// Minimum and maximum case values (for range checking).
    pub value_range:    (i64, i64),
    /// Number of cases including default.
    pub case_count:     usize,
    /// Whether the switch variable has a bounds check before dispatch.
    pub has_bounds_check: bool,
    /// Element stride (in bytes) of the jump table, if discoverable.
    /// `Some(0)` means the stride could not be determined; `None` means the
    /// switch is not table-backed (e.g. chained-if-else).
    pub table_stride:   Option<u32>,
    /// Maximum index value the bounds check (if any) allows. Falls back to
    /// the number of detected table entries when there is no explicit check.
    pub max_index:      Option<i64>,
    /// `true` when the discovered case constants form a contiguous range
    /// `[min..=max]` with no gaps. Useful for downstream codegen that can
    /// emit a direct table lookup instead of a balanced search.
    pub is_contiguous:  bool,
    /// Fall-through target address of the dispatch block's terminating
    /// conditional branch when it is a comparison-style switch, if present.
    /// This is the "no-match" successor used by the binary-search and
    /// chained-if-else detectors when a comparison fails.
    pub false_target:   Option<Address>,
}

impl SwitchInfo {
    #[must_use] 
    pub fn is_dense(&self) -> bool {
        let (lo, hi) = self.value_range;
        let span = usize::try_from(hi - lo + 1).unwrap_or(0);
        self.cases.len() >= span * 3 / 4  // >= 75% density
    }

    #[must_use] 
    pub fn all_targets(&self) -> Vec<Address> {
        let mut targets: Vec<Address> = self.cases.iter().map(|c| c.target).collect();
        if let Some(def) = self.default_addr { targets.push(def); }
        targets.sort_unstable();
        targets.dedup();
        targets
    }
}

impl fmt::Display for SwitchInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "switch({}) [{}] {} cases, range {}..{}",
            self.switch_var, self.pattern, self.cases.len(),
            self.value_range.0, self.value_range.1)?;
        if let Some(def) = self.default_addr {
            write!(f, ", default@0x{def:x}")?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Memory model for jump table validation
// ---------------------------------------------------------------------------

/// Trait for reading from binary image sections during switch detection.
pub trait BinaryImage {
    fn read_u32_le(&self, addr: u64) -> Option<u32>;
    fn read_u64_le(&self, addr: u64) -> Option<u64>;
    fn is_executable(&self, addr: u64) -> bool;
    fn is_readable(&self, addr: u64) -> bool;
    fn section_range(&self, name: &str) -> Option<(u64, u64)>;
}

// ---------------------------------------------------------------------------
// Pattern 1 — Jump table detector
// ---------------------------------------------------------------------------

pub struct JumpTableDetector;

/// Configuration for jump table scanning.
#[derive(Debug, Clone)]
pub struct JumpTableConfig {
    /// Maximum number of entries to scan before giving up.
    pub max_entries:          usize,
    /// Minimum number of entries to accept as a valid jump table.
    pub min_entries:          usize,
    /// If true, require all entries to be in the text section.
    pub require_executable:   bool,
    /// Expected element size in bytes (4 for 32-bit relative, 8 for 64-bit absolute).
    pub element_size:         u8,
    /// Allow entries outside function bounds (for shared jump tables).
    pub allow_out_of_function: bool,
}

impl Default for JumpTableConfig {
    fn default() -> Self {
        Self {
            max_entries:           512,
            min_entries:           2,
            require_executable:    true,
            element_size:          8,
            allow_out_of_function: false,
        }
    }
}

impl JumpTableDetector {
    /// Try to detect a jump table pattern in the given block.
    ///
    /// Pattern: Load from [`table_base` + index * stride], then `IndirectJump`
    pub fn detect(
        block:     &BasicBlock,
        func:      &LlilFunction,
        image:     &dyn BinaryImage,
        config:    &JumpTableConfig,
    ) -> Option<SwitchInfo> {
        // Find an IndirectJump instruction
        let indirect_jump_reg = Self::find_indirect_jump(block)?;

        // Search backwards for a Load that feeds the IndirectJump register
        let (table_base, index_reg, stride) = Self::find_table_load(block, &indirect_jump_reg)?;

        if table_base == 0 { return None; }

        // Scan the jump table to extract case targets
        let entries = Self::scan_table(image, table_base, config)?;
        if entries.len() < config.min_entries { return None; }

        // Find bounds check block (predecessor with CMP + JGE/JA before dispatch)
        let bounds_info = Self::find_bounds_check(block, func);
        let default_addr = bounds_info.as_ref().and_then(|b| b.default_target);
        let has_bounds = bounds_info.is_some();
        let max_index = bounds_info.as_ref().map_or_else(|| i64::try_from(entries.len()).unwrap_or(i64::MAX), |b| b.max_value);

        let cases: Vec<SwitchCase> = entries.iter().enumerate()
            .map(|(i, &addr)| SwitchCase { values: vec![i64::try_from(i).unwrap_or(i64::MAX)], target: addr })
            .collect();

        let count = cases.len();
        let range = if count > 0 { (0i64, i64::try_from(count - 1).unwrap_or(i64::MAX)) } else { (0, 0) };

        Some(SwitchInfo {
            dispatch_block:   block.id,
            switch_var:       index_reg,
            cases,
            default_addr,
            pattern:          SwitchPattern::JumpTable,
            table_addr:       Some(table_base),
            value_range:      range,
            case_count:       count + usize::from(default_addr.is_some()),
            has_bounds_check: has_bounds,
            table_stride:     Some(stride.into()),
            max_index:        Some(max_index),
            // Jump tables are dense by construction.
            is_contiguous:    true,
            false_target:     None,
        })
    }

    fn find_indirect_jump(block: &BasicBlock) -> Option<String> {
        for insn in block.instructions.iter().rev() {
            if let LlilInsn::IndirectJump { target } = insn {
                return Some(target.clone());
            }
        }
        None
    }

    fn find_table_load(block: &BasicBlock, target_reg: &str) -> Option<(u64, String, u8)> {
        for insn in block.instructions.iter().rev() {
            if let LlilInsn::Load { dest: Some(dest), base, index: Some(idx), stride, .. } = insn
                && (dest == target_reg || dest.contains(target_reg))
                    && *base != 0 {
                        return Some((*base, idx.clone(), *stride));
                    }
        }
        None
    }

    fn scan_table(image: &dyn BinaryImage, base: u64, config: &JumpTableConfig) -> Option<Vec<u64>> {
        let mut entries = Vec::with_capacity(config.max_entries);
        let stride = u64::from(config.element_size);
        for i in 0..config.max_entries as u64 {
            let addr = base + i * stride;
            if !image.is_readable(addr) { break; }
            let target = if config.element_size == 4 {
                image.read_u32_le(addr).map(u64::from)?
            } else {
                image.read_u64_le(addr)?
            };
            if target == 0 { break; }
            if config.require_executable && !image.is_executable(target) { break; }
            entries.push(target);
        }
        if entries.len() >= config.min_entries { Some(entries) } else { None }
    }

    /// Look at predecessor blocks for a bounds check pattern:
    /// CMP index, `max_value` ; JGE/JAE `default_target`
    fn find_bounds_check(block: &BasicBlock, func: &LlilFunction) -> Option<BoundsCheckInfo> {
        for &pred_id in &block.predecessors {
            let pred = func.block(pred_id)?;
            for insn in pred.instructions.iter().rev() {
                if let LlilInsn::CondBranch { cond, true_target, false_target } = insn {
                    if matches!(cond, BranchCond::Above | BranchCond::GreaterEqual) {
                        return Some(BoundsCheckInfo {
                            default_target: Some(*true_target),
                            max_value:      0, // would come from preceding CMP
                        });
                    }
                    if matches!(cond, BranchCond::AboveEq) {
                        return Some(BoundsCheckInfo {
                            default_target: Some(*false_target),
                            max_value:      0,
                        });
                    }
                }
                if let LlilInsn::Compare { value, kind: CmpKind::Lt, .. } = insn {
                    // if (index < max_value) is the bounds check
                    let _ = value;
                }
            }
        }
        None
    }
}

#[derive(Debug)]
struct BoundsCheckInfo {
    default_target: Option<Address>,
    max_value:      i64,
}

// ---------------------------------------------------------------------------
// Pattern 2 — Binary search tree detector
// ---------------------------------------------------------------------------

pub struct BinarySearchDetector;

/// Node in the reconstructed BST.
#[derive(Debug)]
struct BstNode {
    block:          BlockId,
    cmp_value:      i64,
    left_block:     Option<BlockId>,   // taken when value < cmp_value
    right_block:    Option<BlockId>,   // taken when value > cmp_value
    equal_target:   Option<Address>,   // target when value == cmp_value
}

impl BinarySearchDetector {
    /// Detect a binary-search-tree switch pattern rooted at `root_block`.
    pub fn detect(
        root_block: BlockId,
        func:       &LlilFunction,
    ) -> Option<SwitchInfo> {
        // Walk the CFG from root_block, collecting CMP+JCC nodes
        let mut visited = HashSet::new();
        let mut nodes   = Vec::new();
        let mut leaves  = Vec::new();
        Self::walk(root_block, func, &mut visited, &mut nodes, &mut leaves);

        if nodes.len() < 2 { return None; }

        // Build a [`BTreeMap`] of dispatch block id → BST node for O(log n)
        // lookups while reasoning about left/right subtree containment.
        // Pruning rule: a node whose left and right children are both BST
        // nodes is an interior decision node; nodes with neither are leaves
        // and only contribute their equal_target as a case.
        let bst_index: BTreeMap<BlockId, &BstNode> =
            nodes.iter().map(|n| (n.block, n)).collect();
        let mut interior_count = 0usize;
        for n in &nodes {
            let l_is_node = n.left_block.is_some_and(|id| bst_index.contains_key(&id));
            let r_is_node = n.right_block.is_some_and(|id| bst_index.contains_key(&id));
            if l_is_node && r_is_node {
                interior_count += 1;
            }
        }
        // A genuine BST should have at least one interior node when total
        // nodes >= 3; otherwise the pattern is more likely chained-if-else.
        if nodes.len() >= 3 && interior_count == 0 {
            return None;
        }

        // Extract cases from BST leaf targets
        let mut cases: Vec<SwitchCase> = nodes.iter()
            .filter_map(|n| n.equal_target.map(|t| SwitchCase { values: vec![n.cmp_value], target: t }))
            .collect();

        // Add non-match leaf targets as potential default
        let case_targets: HashSet<Address> = cases.iter().map(|c| c.target).collect();
        let mut non_cases: Vec<Address> = leaves.iter()
            .filter(|&&addr| !case_targets.contains(&addr))
            .copied()
            .collect();
        non_cases.sort_unstable();
        non_cases.dedup();

        if cases.is_empty() { return None; }

        cases.sort_by_key(|c| c.values[0]);
        let values: Vec<i64> = cases.iter().map(|c| c.values[0]).collect();
        let (min_v, max_v) = (*values.first()?, *values.last()?);
        let count = cases.len();

        let switch_var = Self::extract_switch_var(func.block(root_block)?)?;

        // Detect whether the discovered case values form a contiguous range,
        // and propagate the BST root's "no-match" successor (the false_target
        // of its top-level conditional branch) so downstream passes can elide
        // the implicit default fall-through.
        let is_contiguous = values.windows(2).all(|w| w[1] - w[0] == 1);
        let root_false_target = func
            .block(root_block)
            .and_then(Self::extract_false_target);

        Some(SwitchInfo {
            dispatch_block:   root_block,
            switch_var,
            cases,
            default_addr:     non_cases.into_iter().next(),
            pattern:          SwitchPattern::BinarySearch,
            table_addr:       None,
            value_range:      (min_v, max_v),
            case_count:       count,
            has_bounds_check: false,
            table_stride:     None,
            max_index:        Some(max_v),
            is_contiguous,
            false_target:     root_false_target,
        })
    }

    /// Extract the `false_target` block id of a block's terminating
    /// [`LlilInsn::CondBranch`], if any. Wired through to
    /// [`SwitchInfo::false_target`] for the binary-search pattern.
    fn extract_false_target(block: &BasicBlock) -> Option<Address> {
        for insn in block.instructions.iter().rev() {
            if let LlilInsn::CondBranch { false_target, .. } = insn {
                return Some(*false_target);
            }
        }
        None
    }

    fn walk(
        id:       BlockId,
        func:     &LlilFunction,
        visited:  &mut HashSet<BlockId>,
        nodes:    &mut Vec<BstNode>,
        leaves:   &mut Vec<Address>,
    ) {
        if !visited.insert(id) { return; }
        let Some(block) = func.block(id) else { return };

        // Check if this block is a CMP + JCC node
        let cmp_val = Self::extract_cmp_value(block);
        let branch = Self::extract_branch(block);

        if let (Some(cmp), Some((eq_target, lt_block, gt_block, no_match_addr))) = (cmp_val, branch) {
            // `no_match_addr` is currently informational — recorded on the
            // top-level switch via [`extract_false_target`]; future range
            // analysis can use it to verify the predecessor branch lattice.
            let _ = no_match_addr;
            nodes.push(BstNode {
                block: id,
                cmp_value: cmp,
                left_block: lt_block,
                right_block: gt_block,
                equal_target: Some(eq_target),
            });
            // Recurse into left and right
            if let Some(lb) = lt_block  { Self::walk(lb, func, visited, nodes, leaves); }
            if let Some(rb) = gt_block  { Self::walk(rb, func, visited, nodes, leaves); }
        } else {
            // Leaf node
            leaves.push(block.start);
        }
    }

    fn extract_cmp_value(block: &BasicBlock) -> Option<i64> {
        for insn in &block.instructions {
            if let LlilInsn::Compare { value, .. } = insn { return Some(*value); }
        }
        None
    }

    fn extract_branch(
        block: &BasicBlock,
    ) -> Option<(Address, Option<BlockId>, Option<BlockId>, Address)> {
        // Look for a CondBranch with Equal condition to identify "equal" target
        for insn in block.instructions.iter().rev() {
            if let LlilInsn::CondBranch { cond, true_target, false_target } = insn
                && *cond == BranchCond::Equal {
                    // true_target = equal target (case target)
                    // false_target = address taken when the comparison fails
                    // successor blocks for less/greater come from block successors
                    let lt_block = block.successors.get(1).copied();
                    let gt_block = block.successors.first().copied();
                    return Some((*true_target, lt_block, gt_block, *false_target));
                }
        }
        None
    }

    fn extract_switch_var(block: &BasicBlock) -> Option<String> {
        for insn in &block.instructions {
            if let LlilInsn::Compare { reg, .. } = insn { return Some(reg.clone()); }
        }
        None
    }
}

// ---------------------------------------------------------------------------
// Pattern 3 — Chained if-else detector
// ---------------------------------------------------------------------------

pub struct ChainedIfElseDetector;

/// A run of consecutive CMP/JE blocks testing the same register.
#[derive(Debug)]
struct IfElseChain {
    /// The variable being compared.
    switch_var: String,
    /// (`constant_value`, `target_address`)
    comparisons: Vec<(i64, Address)>,
    /// The fallthrough target (default).
    default_target: Option<Address>,
}

impl ChainedIfElseDetector {
    #[must_use] 
    pub fn detect(
        entry_block: BlockId,
        func:        &LlilFunction,
    ) -> Option<SwitchInfo> {
        let chain = Self::collect_chain(entry_block, func)?;
        if chain.comparisons.len() < 2 { return None; }

        // Check if constants form an arithmetic sequence (contiguous switch)
        let mut vals: Vec<i64> = chain.comparisons.iter().map(|(v, _)| *v).collect();
        vals.sort_unstable();

        let is_contiguous = vals.windows(2).all(|w| w[1] - w[0] == 1);

        // Even non-contiguous sequences can be switches, but contiguous ones are stronger evidence
        let mut cases: Vec<SwitchCase> = chain.comparisons.iter()
            .map(|(v, t)| SwitchCase { values: vec![*v], target: *t })
            .collect();
        cases.sort_by_key(|c| c.values[0]);

        let (min_v, max_v) = (cases.first()?.values[0], cases.last()?.values[0]);
        let count = cases.len();

        Some(SwitchInfo {
            dispatch_block:   entry_block,
            switch_var:       chain.switch_var,
            cases,
            default_addr:     chain.default_target,
            pattern:          SwitchPattern::ChainedIfElse,
            table_addr:       None,
            value_range:      (min_v, max_v),
            case_count:       count + usize::from(chain.default_target.is_some()),
            has_bounds_check: false,
            table_stride:     None,
            max_index:        Some(max_v),
            is_contiguous,
            false_target:     None,
        })
    }

    fn collect_chain(start: BlockId, func: &LlilFunction) -> Option<IfElseChain> {
        let mut block_id = start;
        let mut chain = IfElseChain {
            switch_var:     String::new(),
            comparisons:    Vec::new(),
            default_target: None,
        };
        let mut visited: HashSet<BlockId> = HashSet::new();

        loop {
            if !visited.insert(block_id) { break; }
            let block = func.block(block_id)?;

            // Extract CMP reg, const; JE target pattern
            let (reg, val, eq_target) = Self::extract_cmp_je(block)?;

            // First iteration: set switch_var
            if chain.switch_var.is_empty() {
                chain.switch_var.clone_from(&reg);
            } else if chain.switch_var != reg {
                break; // different variable — chain ends
            }

            chain.comparisons.push((val, eq_target));

            // The "false" branch continues the chain (next CMP/JE block)
            // The "true" branch is the case target
            // Find the next block in the chain (successor that isn't eq_target)
            let next = block.successors.iter().copied()
                .find(|&s| func.block(s).is_some_and(|b| b.start != eq_target));

            match next {
                Some(n) => {
                    // Check if next block also has a CMP pattern on same reg
                    let next_block = func.block(n)?;
                    if Self::extract_cmp_je(next_block).is_some_and(|(r, _, _)| r == chain.switch_var) {
                        block_id = n;
                    } else {
                        // Next block is the default
                        chain.default_target = Some(next_block.start);
                        break;
                    }
                }
                None => break,
            }
        }

        if chain.comparisons.len() >= 2 { Some(chain) } else { None }
    }

    /// Extract (reg, `const_value`, `equal_target`) from a CMP; JE pattern.
    fn extract_cmp_je(block: &BasicBlock) -> Option<(String, i64, Address)> {
        let mut reg   = None;
        let mut val   = None;
        let mut eq_target = None;

        for insn in &block.instructions {
            match insn {
                LlilInsn::Compare { reg: r, value: v, kind: CmpKind::Eq } => {
                    reg = Some(r.clone());
                    val = Some(*v);
                }
                LlilInsn::CondBranch { cond: BranchCond::Equal, true_target, .. } => {
                    eq_target = Some(*true_target);
                }
                _ => {}
            }
        }

        match (reg, val, eq_target) {
            (Some(r), Some(v), Some(t)) => Some((r, v, t)),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Pattern 4 — String switch hash detector
// ---------------------------------------------------------------------------

/// Well-known string hash function names.
const KNOWN_HASH_FUNCTIONS: &[&str] = &[
    "std::hash",
    "djb2",
    "fnv1a",
    "fnv32",
    "crc32",
    "murmur3",
    "_hash_string",
    "hash_bytes",
    "str_hash",
    "compute_hash",
];

pub struct StringSwitchHashDetector;

impl StringSwitchHashDetector {
    /// Detect a string-switch-hash pattern.
    ///
    /// Pattern: Call `hash(str_arg)` → temp; switch on temp
    #[must_use] 
    pub fn detect(
        entry_block: BlockId,
        func:        &LlilFunction,
    ) -> Option<SwitchInfo> {
        let block = func.block(entry_block)?;
        let hash_fn = Self::find_hash_call(block)?;

        // Now look at successors for the actual switch dispatch
        // The switch on the hash value should appear within the next few blocks
        let mut switch_info = None;
        let mut to_visit = vec![entry_block];
        let mut visited  = HashSet::new();
        let mut depth    = 0;

        while let Some(bid) = to_visit.pop() {
            if !visited.insert(bid) || depth > 5 { continue; }
            depth += 1;
            let Some(b) = func.block(bid) else { continue };

            // Try to detect a nested switch (jump table or chained if-else) in b
            if let Some(mut info) = ChainedIfElseDetector::detect(bid, func) {
                info.pattern = SwitchPattern::StringSwitchHash { hash_function: hash_fn.clone() };
                switch_info = Some(info);
                break;
            }

            for &s in &b.successors { to_visit.push(s); }
        }

        if let Some(mut si) = switch_info {
            si.pattern = SwitchPattern::StringSwitchHash { hash_function: hash_fn };
            return Some(si);
        }
        None
    }

    fn find_hash_call(block: &BasicBlock) -> Option<String> {
        for insn in &block.instructions {
            if let LlilInsn::Call { target } = insn {
                // Lowercase once per call instruction, not once per known function.
                let lower = target.to_lowercase();
                for known in KNOWN_HASH_FUNCTIONS {
                    if lower.contains(known) {
                        return Some(target.clone());
                    }
                }
            }
        }
        None
    }
}

// ---------------------------------------------------------------------------
// Main switch detector
// ---------------------------------------------------------------------------

/// Configuration for the overall switch detector.
#[derive(Debug, Clone)]
pub struct SwitchDetectorConfig {
    pub jump_table:     JumpTableConfig,
    /// Minimum number of cases required for chained-if-else to be a switch.
    pub min_chain_len:  usize,
    /// Enable Pattern 4 (string hash switch).
    pub detect_hash:    bool,
}

impl Default for SwitchDetectorConfig {
    fn default() -> Self {
        Self {
            jump_table:    JumpTableConfig::default(),
            min_chain_len: 3,
            detect_hash:   true,
        }
    }
}

/// Detection result for a single candidate.
#[derive(Debug)]
pub struct DetectionResult {
    pub switch:     SwitchInfo,
    pub confidence: f64,   // 0.0..1.0
    pub notes:      Vec<String>,
}

impl DetectionResult {
    const fn new(switch: SwitchInfo, confidence: f64) -> Self {
        Self { switch, confidence, notes: Vec::new() }
    }

    fn with_note(mut self, note: impl Into<String>) -> Self {
        self.notes.push(note.into());
        self
    }
}

pub struct SwitchDetector {
    config: SwitchDetectorConfig,
}

impl SwitchDetector {
    #[must_use] 
    pub const fn new(config: SwitchDetectorConfig) -> Self { Self { config } }
    #[must_use] 
    pub fn default_config() -> Self { Self::new(SwitchDetectorConfig::default()) }

    /// Run all four detection patterns on the given function.
    /// Returns all detected switches (may be multiple per function).
    pub fn detect_all(
        &self,
        func:  &LlilFunction,
        image: &dyn BinaryImage,
    ) -> Vec<DetectionResult> {
        let mut results = Vec::new();
        let mut covered_blocks: HashSet<BlockId> = HashSet::new();

        for block in &func.blocks {
            if covered_blocks.contains(&block.id) { continue; }

            // Pattern 1: jump table
            if let Some(info) = JumpTableDetector::detect(block, func, image, &self.config.jump_table) {
                let confidence = Self::jump_table_confidence(&info);
                let note = format!("jump table at 0x{:x} ({} entries)",
                    info.table_addr.unwrap_or(0), info.cases.len());
                results.push(DetectionResult::new(info, confidence).with_note(note));
                covered_blocks.insert(block.id);
                continue;
            }

            // Pattern 2: binary search
            if let Some(info) = BinarySearchDetector::detect(block.id, func)
                && info.cases.len() >= self.config.min_chain_len {
                    let confidence = Self::bst_confidence(&info);
                    results.push(DetectionResult::new(info, confidence)
                        .with_note("binary search tree dispatch"));
                    covered_blocks.insert(block.id);
                    continue;
                }

            // Pattern 3: chained if-else
            if let Some(info) = ChainedIfElseDetector::detect(block.id, func)
                && info.cases.len() >= self.config.min_chain_len {
                    let confidence = Self::chain_confidence(&info);
                    results.push(DetectionResult::new(info, confidence)
                        .with_note("chained if-else"));
                    covered_blocks.insert(block.id);
                    continue;
                }

            // Pattern 4: string hash switch
            if self.config.detect_hash
                && let Some(info) = StringSwitchHashDetector::detect(block.id, func) {
                    results.push(DetectionResult::new(info, 0.7)
                        .with_note("string-hash switch (hash function pre-dispatch)"));
                    covered_blocks.insert(block.id);
                }
        }

        // Sort by block address for deterministic output
        results.sort_by_key(|r| r.switch.dispatch_block.0);
        results
    }

    fn jump_table_confidence(info: &SwitchInfo) -> f64 {
        let base: f64 = 0.85;
        let density_bonus: f64 = if info.is_dense() { 0.1 } else { 0.0 };
        let bounds_bonus: f64 = if info.has_bounds_check { 0.05 } else { 0.0 };
        (base + density_bonus + bounds_bonus).min(1.0_f64)
    }

    fn bst_confidence(info: &SwitchInfo) -> f64 {
        let base = 0.75;
        let size_bonus = (f64::from(u32::try_from(info.cases.len()).unwrap_or(u32::MAX)).log2() * 0.02).min(0.15);
        (base + size_bonus).min(1.0)
    }

    fn chain_confidence(info: &SwitchInfo) -> f64 {
        let (lo, hi) = info.value_range;
        let span = usize::try_from(hi - lo + 1).unwrap_or(0);
        let contiguous = info.cases.len() >= span;
        let base = if contiguous { 0.80 } else { 0.60 };
        let size_bonus = (f64::from(u32::try_from(info.cases.len()).unwrap_or(u32::MAX)) * 0.01).min(0.15);
        (base + size_bonus).min(1.0)
    }
}

// ---------------------------------------------------------------------------
// Integration with CFS structuring
// ---------------------------------------------------------------------------

/// Annotated switch case for CFS (Control Flow Structuring) input.
#[derive(Debug, Clone)]
pub struct CfsCase {
    pub values:  Vec<i64>,
    pub target:  Address,
    pub is_default: bool,
}

/// Convert a `SwitchInfo` to the form expected by the CFS pass.
#[must_use] 
pub fn switch_info_to_cfs(info: &SwitchInfo) -> Vec<CfsCase> {
    let mut cases: Vec<CfsCase> = info.cases.iter()
        .map(|c| CfsCase { values: c.values.clone(), target: c.target, is_default: false })
        .collect();
    if let Some(def) = info.default_addr {
        cases.push(CfsCase { values: vec![], target: def, is_default: true });
    }
    cases
}

// ---------------------------------------------------------------------------
// Statistics
// ---------------------------------------------------------------------------

#[derive(Debug, Default, Clone)]
pub struct SwitchDetectionStats {
    pub total_functions:    usize,
    pub functions_with_switch: usize,
    pub total_switches:     usize,
    pub total_cases:        usize,
    pub by_pattern:         HashMap<String, usize>,
    pub avg_case_count:     f64,
    pub max_case_count:     usize,
}

impl SwitchDetectionStats {
    pub fn accumulate(&mut self, results: &[DetectionResult]) {
        for r in results {
            let key = format!("{}", r.switch.pattern);
            *self.by_pattern.entry(key).or_insert(0) += 1;
            self.total_switches += 1;
            self.total_cases += r.switch.case_count;
            if r.switch.case_count > self.max_case_count {
                self.max_case_count = r.switch.case_count;
            }
        }
    }

    pub fn finalize(&mut self) {
        if self.total_switches > 0 {
            self.avg_case_count = f64::from(u32::try_from(self.total_cases).unwrap_or(u32::MAX)) / f64::from(u32::try_from(self.total_switches).unwrap_or(u32::MAX));
        }
    }
}

impl fmt::Display for SwitchDetectionStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "=== Switch Detection Stats ===")?;
        writeln!(f, "Functions: {}/{} have switches", self.functions_with_switch, self.total_functions)?;
        writeln!(f, "Total switches: {} (max {} cases)", self.total_switches, self.max_case_count)?;
        for (pattern, count) in &self.by_pattern {
            writeln!(f, "  {pattern}: {count}")?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// A simple fake BinaryImage for testing.
    struct FakeImage {
        data: Vec<u8>,
        base: u64,
        exec_range: (u64, u64),
    }

    impl FakeImage {
        fn new(base: u64, data: Vec<u8>, exec_lo: u64, exec_hi: u64) -> Self {
            FakeImage { data, base, exec_range: (exec_lo, exec_hi) }
        }
    }

    impl BinaryImage for FakeImage {
        fn read_u32_le(&self, addr: u64) -> Option<u32> {
            let off = addr.checked_sub(self.base)? as usize;
            let b = self.data.get(off..off+4)?;
            Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
        }
        fn read_u64_le(&self, addr: u64) -> Option<u64> {
            let off = addr.checked_sub(self.base)? as usize;
            let b = self.data.get(off..off+8)?;
            Some(u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]))
        }
        fn is_executable(&self, addr: u64) -> bool {
            addr >= self.exec_range.0 && addr < self.exec_range.1
        }
        fn is_readable(&self, addr: u64) -> bool {
            let off = addr.checked_sub(self.base).map_or(usize::MAX, |v| v as usize);
            off < self.data.len()
        }
        fn section_range(&self, _: &str) -> Option<(u64, u64)> { None }
    }

    fn make_func_with_chain() -> LlilFunction {
        // Block 0: CMP rax, 0; JE 0x1000
        // Block 1: CMP rax, 1; JE 0x1010
        // Block 2: CMP rax, 2; JE 0x1020
        // Block 3: default (0x1030)
        let b0 = BasicBlock {
            id: BlockId(0), start: 0x500, end: 0x510,
            instructions: vec![
                LlilInsn::Compare { reg: "rax".into(), value: 0, kind: CmpKind::Eq },
                LlilInsn::CondBranch { cond: BranchCond::Equal, true_target: 0x1000, false_target: 0x510 },
            ],
            successors: vec![BlockId(1)],
            predecessors: vec![],
        };
        let b1 = BasicBlock {
            id: BlockId(1), start: 0x510, end: 0x520,
            instructions: vec![
                LlilInsn::Compare { reg: "rax".into(), value: 1, kind: CmpKind::Eq },
                LlilInsn::CondBranch { cond: BranchCond::Equal, true_target: 0x1010, false_target: 0x520 },
            ],
            successors: vec![BlockId(2)],
            predecessors: vec![BlockId(0)],
        };
        let b2 = BasicBlock {
            id: BlockId(2), start: 0x520, end: 0x530,
            instructions: vec![
                LlilInsn::Compare { reg: "rax".into(), value: 2, kind: CmpKind::Eq },
                LlilInsn::CondBranch { cond: BranchCond::Equal, true_target: 0x1020, false_target: 0x530 },
            ],
            successors: vec![BlockId(3)],
            predecessors: vec![BlockId(1)],
        };
        let b3 = BasicBlock {
            id: BlockId(3), start: 0x1030, end: 0x1040,
            instructions: vec![LlilInsn::Other],
            successors: vec![],
            predecessors: vec![BlockId(2)],
        };
        LlilFunction {
            blocks: vec![b0, b1, b2, b3],
            entry:  BlockId(0),
            name:   "test_switch".into(),
        }
    }

    #[test]
    fn test_chained_if_else_detection() {
        let func = make_func_with_chain();
        let result = ChainedIfElseDetector::detect(BlockId(0), &func);
        assert!(result.is_some());
        let info = result.unwrap();
        assert_eq!(info.switch_var, "rax");
        assert_eq!(info.cases.len(), 3);
        assert_eq!(info.cases[0].values, vec![0i64]);
        assert_eq!(info.cases[1].values, vec![1i64]);
        assert_eq!(info.cases[2].values, vec![2i64]);
        assert_eq!(info.cases[0].target, 0x1000);
        assert_eq!(info.cases[1].target, 0x1010);
        assert_eq!(info.cases[2].target, 0x1020);
        assert_eq!(info.value_range, (0, 2));
    }

    #[test]
    fn test_switch_info_display() {
        let func = make_func_with_chain();
        let info = ChainedIfElseDetector::detect(BlockId(0), &func).unwrap();
        let s = format!("{}", info);
        assert!(s.contains("switch(rax)"));
        assert!(s.contains("3 cases"));
    }

    #[test]
    fn test_switch_info_is_dense() {
        let func = make_func_with_chain();
        let info = ChainedIfElseDetector::detect(BlockId(0), &func).unwrap();
        // All 3 values in range 0..=2 → dense
        assert!(info.is_dense());
    }

    #[test]
    fn test_switch_info_all_targets() {
        let func = make_func_with_chain();
        let info = ChainedIfElseDetector::detect(BlockId(0), &func).unwrap();
        let targets = info.all_targets();
        assert!(targets.contains(&0x1000));
        assert!(targets.contains(&0x1010));
        assert!(targets.contains(&0x1020));
    }

    #[test]
    fn test_jump_table_scan() {
        // Build a fake image with a 4-entry 64-bit jump table starting at 0x2000
        // Each entry points into exec range 0x1000..0x2000
        let mut data = vec![0u8; 0x2100];
        let entries: &[u64] = &[0x1000, 0x1100, 0x1200, 0x1300];
        for (i, &e) in entries.iter().enumerate() {
            let off = 0x2000 + i * 8;
            data[off..off+8].copy_from_slice(&e.to_le_bytes());
        }
        // 5th entry is 0 → terminates scan
        let image = FakeImage::new(0x0000, data, 0x1000, 0x2000);
        let config = JumpTableConfig { element_size: 8, min_entries: 2, max_entries: 32,
            require_executable: true, allow_out_of_function: true };
        let result = JumpTableDetector::scan_table(&image, 0x2000, &config);
        assert!(result.is_some());
        let tbl = result.unwrap();
        assert_eq!(tbl.len(), 4);
        assert_eq!(tbl[0], 0x1000);
        assert_eq!(tbl[3], 0x1300);
    }

    #[test]
    fn test_jump_table_too_short() {
        let data = vec![0u8; 256];
        let image = FakeImage::new(0, data, 0, 0);
        let config = JumpTableConfig { min_entries: 5, ..Default::default() };
        let result = JumpTableDetector::scan_table(&image, 0, &config);
        assert!(result.is_none());
    }

    #[test]
    fn test_detector_full_pass() {
        let func = make_func_with_chain();
        let data = vec![0u8; 256];
        let image = FakeImage::new(0, data, 0x1000, 0x2000);
        let det = SwitchDetector::default_config();
        let results = det.detect_all(&func, &image);
        // Should detect the chained if-else
        assert!(!results.is_empty());
        assert!(results.iter().any(|r| r.switch.pattern == SwitchPattern::ChainedIfElse));
    }

    #[test]
    fn test_cfs_conversion() {
        let func = make_func_with_chain();
        let info = ChainedIfElseDetector::detect(BlockId(0), &func).unwrap();
        let cfs = switch_info_to_cfs(&info);
        // make_func_with_chain has b3 as the fall-through default, so the detector
        // produces 3 explicit cases plus a default entry.
        assert_eq!(cfs.len(), 4);
        assert!(!cfs[0].is_default);
        assert!(cfs[3].is_default);
    }

    #[test]
    fn test_stats_accumulate() {
        let func = make_func_with_chain();
        let info = ChainedIfElseDetector::detect(BlockId(0), &func).unwrap();
        let results = vec![DetectionResult::new(info, 0.8)];
        let mut stats = SwitchDetectionStats::default();
        stats.accumulate(&results);
        assert_eq!(stats.total_switches, 1);
        assert!(stats.by_pattern.contains_key("chained-if-else"));
    }

    #[test]
    fn test_hash_detection_no_call() {
        // Block with no hash call → None
        let func = LlilFunction {
            blocks: vec![BasicBlock {
                id: BlockId(0), start: 0, end: 0x10,
                instructions: vec![LlilInsn::Other],
                successors: vec![], predecessors: vec![],
            }],
            entry: BlockId(0),
            name: "no_hash".into(),
        };
        let result = StringSwitchHashDetector::detect(BlockId(0), &func);
        assert!(result.is_none());
    }

    #[test]
    fn test_binary_search_single_block() {
        // Single block with a CMP but only one successor → not a BST switch
        let func = LlilFunction {
            blocks: vec![BasicBlock {
                id: BlockId(0), start: 0x400, end: 0x410,
                instructions: vec![
                    LlilInsn::Compare { reg: "rcx".into(), value: 5, kind: CmpKind::Eq },
                    LlilInsn::CondBranch { cond: BranchCond::Equal, true_target: 0x1000, false_target: 0x1100 },
                ],
                successors: vec![],
                predecessors: vec![],
            }],
            entry: BlockId(0),
            name: "single_cmp".into(),
        };
        let result = BinarySearchDetector::detect(BlockId(0), &func);
        // Only 1 comparison node → below threshold (min 2)
        assert!(result.is_none());
    }
}
