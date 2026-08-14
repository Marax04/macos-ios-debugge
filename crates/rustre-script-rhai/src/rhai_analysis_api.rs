//! `rhai_analysis_api` — structured analysis API for Rhai scripts in `RustRE`.
//!
//! Exposes RE analysis capabilities (CFG, basic blocks, types, pass runner) to
//! Rhai scripts through a clean Rust host-side API.  Functions registered here
//! are callable from Rhai as global free functions or via the `rustre` module.

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

// ── Stub core types (mirrors of rustre-il-lift / rustre-il-mlil) ──────────────

/// A simplified representation of a basic block for use in scripts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BasicBlock {
    /// Block index within the function.
    pub id: u32,
    /// Start address.
    pub start: u64,
    /// End address (exclusive).
    pub end: u64,
    /// Instruction addresses in this block.
    pub instruction_addrs: Vec<u64>,
    /// Successor block ids.
    pub successors: Vec<u32>,
    /// Predecessor block ids.
    pub predecessors: Vec<u32>,
    /// Whether this block is the function entry.
    pub is_entry: bool,
    /// Whether this block ends with a return.
    pub is_return: bool,
}

impl BasicBlock {
    /// Create a new basic block.
    #[must_use]
    pub const fn new(id: u32, start: u64, end: u64) -> Self {
        Self {
            id,
            start,
            end,
            instruction_addrs: Vec::new(),
            successors: Vec::new(),
            predecessors: Vec::new(),
            is_entry: false,
            is_return: false,
        }
    }

    /// Return the size of this block in bytes.
    #[must_use]
    pub const fn byte_size(&self) -> u64 {
        self.end.saturating_sub(self.start)
    }

    /// Number of instructions in this block.
    #[must_use]
    pub const fn instruction_count(&self) -> usize {
        self.instruction_addrs.len()
    }
}

/// A simplified function descriptor for use in scripts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RhaiFunction {
    /// Function name (may be auto-generated like `sub_1000`).
    pub name: String,
    /// Entry address.
    pub address: u64,
    /// Total size in bytes.
    pub size: u64,
    /// Whether this is a library function.
    pub is_library: bool,
    /// Whether this function was renamed by the analyst.
    pub is_renamed: bool,
    /// Calling convention name.
    pub calling_convention: String,
    /// Architecture.
    pub arch: String,
}

impl RhaiFunction {
    #[must_use]
    pub fn new(name: impl Into<String>, address: u64) -> Self {
        Self {
            name: name.into(),
            address,
            size: 0,
            is_library: false,
            is_renamed: false,
            calling_convention: "unknown".to_string(),
            arch: "x86_64".to_string(),
        }
    }
}

/// A typed variable in the analysis context.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RhaiVar {
    /// Variable name (register name or SSA name).
    pub name: String,
    /// Type string.
    pub type_str: String,
    /// Storage kind: "register", "stack", "memory".
    pub storage: String,
    /// Offset from frame base (for stack variables).
    pub offset: i64,
    /// Bit width.
    pub width_bits: u32,
}

impl RhaiVar {
    #[must_use]
    pub fn new(name: impl Into<String>, type_str: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            type_str: type_str.into(),
            storage: "register".to_string(),
            offset: 0,
            width_bits: 64,
        }
    }
}

/// Result of a single analysis pass.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PassResult {
    /// Pass name.
    pub pass_name: String,
    /// Number of changes made.
    pub changes: u32,
    /// Whether the pass succeeded.
    pub success: bool,
    /// Any error message.
    pub error: Option<String>,
    /// Elapsed time in microseconds.
    pub elapsed_us: u64,
}

impl PassResult {
    #[must_use]
    pub fn success(pass_name: impl Into<String>, changes: u32) -> Self {
        Self {
            pass_name: pass_name.into(),
            changes,
            success: true,
            error: None,
            elapsed_us: 0,
        }
    }

    #[must_use]
    pub fn failure(pass_name: impl Into<String>, error: impl Into<String>) -> Self {
        Self {
            pass_name: pass_name.into(),
            changes: 0,
            success: false,
            error: Some(error.into()),
            elapsed_us: 0,
        }
    }
}

// ── RhaiAnalysisContext ───────────────────────────────────────────────────────

/// Holds the analysis state that Rhai scripts operate on.
///
/// Instances of this struct are passed by value to Rhai API functions which
/// mutate or query the analysis state.
#[derive(Debug, Clone, Default)]
pub struct RhaiAnalysisContext {
    /// Functions keyed by address.
    pub functions: HashMap<u64, RhaiFunction>,
    /// Basic blocks keyed by function address.
    pub blocks: HashMap<u64, Vec<BasicBlock>>,
    /// Variable types keyed by `"func_addr:var_name"`.
    pub var_types: HashMap<String, String>,
    /// Pass results (name → last result).
    pub pass_results: HashMap<String, PassResult>,
    /// Comments keyed by address.
    pub comments: HashMap<u64, String>,
    /// User-set type overrides.
    pub type_overrides: HashMap<String, String>,
    /// Architecture name.
    pub arch: String,
}

impl RhaiAnalysisContext {
    /// Create an empty analysis context.
    #[must_use]
    pub fn new() -> Self {
        Self {
            arch: "x86_64".to_string(),
            ..Default::default()
        }
    }

    /// Create a context with some mock data for testing.
    #[must_use]
    pub fn mock() -> Self {
        let mut ctx = Self::new();

        // Add a couple of mock functions.
        ctx.functions.insert(0x1000, RhaiFunction::new("main", 0x1000));
        ctx.functions.insert(0x2000, RhaiFunction {
            name: "sub_2000".to_string(),
            address: 0x2000,
            size: 64,
            is_library: false,
            is_renamed: false,
            calling_convention: "System V AMD64".to_string(),
            arch: "x86_64".to_string(),
        });

        // Add basic blocks for `main`.
        let mut bb0 = BasicBlock::new(0, 0x1000, 0x1020);
        bb0.is_entry = true;
        bb0.successors = vec![1, 2];
        bb0.instruction_addrs = vec![0x1000, 0x1008, 0x1010, 0x1018];

        let mut bb1 = BasicBlock::new(1, 0x1020, 0x1030);
        bb1.predecessors = vec![0];
        bb1.successors = vec![3];
        bb1.instruction_addrs = vec![0x1020, 0x1028];

        let mut bb2 = BasicBlock::new(2, 0x1030, 0x1040);
        bb2.predecessors = vec![0];
        bb2.successors = vec![3];
        bb2.instruction_addrs = vec![0x1030, 0x1038];

        let mut bb3 = BasicBlock::new(3, 0x1040, 0x1050);
        bb3.predecessors = vec![1, 2];
        bb3.is_return = true;
        bb3.instruction_addrs = vec![0x1040, 0x1048];

        ctx.blocks.insert(0x1000, vec![bb0, bb1, bb2, bb3]);

        // Some variable types.
        ctx.var_types.insert("0x1000:rdi".to_string(), "int64_t*".to_string());
        ctx.var_types.insert("0x1000:rsi".to_string(), "size_t".to_string());

        ctx
    }
}

// ── RhaiAnalysisApi ───────────────────────────────────────────────────────────

/// The host-side analysis API callable from Rhai scripts.
pub struct RhaiAnalysisApi {
    ctx: RhaiAnalysisContext,
}

impl fmt::Debug for RhaiAnalysisApi {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RhaiAnalysisApi(arch={})", self.ctx.arch)
    }
}

impl RhaiAnalysisApi {
    /// Create an API with an empty context.
    #[must_use]
    pub fn new() -> Self {
        Self { ctx: RhaiAnalysisContext::new() }
    }

    /// Create an API with a mock context for testing.
    #[must_use]
    pub fn with_mock() -> Self {
        Self { ctx: RhaiAnalysisContext::mock() }
    }

    /// Create an API wrapping the given context.
    #[must_use]
    pub const fn with_context(ctx: RhaiAnalysisContext) -> Self {
        Self { ctx }
    }

    // ── rhai_find_functions ───────────────────────────────────────────────────

    /// Return all functions matching the optional name prefix.
    ///
    /// If `prefix` is empty, return all functions.
    #[must_use]
    pub fn rhai_find_functions(&self, prefix: &str) -> Vec<RhaiFunction> {
        if prefix.is_empty() {
            self.ctx.functions.values().cloned().collect()
        } else {
            self.ctx
                .functions
                .values()
                .filter(|f| f.name.starts_with(prefix))
                .cloned()
                .collect()
        }
    }

    /// Find functions by address range [start, end).
    #[must_use]
    pub fn rhai_find_functions_in_range(&self, start: u64, end: u64) -> Vec<RhaiFunction> {
        self.ctx
            .functions
            .values()
            .filter(|f| f.address >= start && f.address < end)
            .cloned()
            .collect()
    }

    /// Find a function by address.
    #[must_use]
    pub fn rhai_find_function_at(&self, addr: u64) -> Option<RhaiFunction> {
        self.ctx.functions.get(&addr).cloned()
    }

    // ── rhai_get_basic_blocks ─────────────────────────────────────────────────

    /// Return the basic blocks of the function at `func_addr`.
    #[must_use]
    pub fn rhai_get_basic_blocks(&self, func_addr: u64) -> Vec<BasicBlock> {
        self.ctx.blocks.get(&func_addr).cloned().unwrap_or_default()
    }

    /// Return a specific basic block of a function.
    #[must_use]
    pub fn rhai_get_basic_block(&self, func_addr: u64, block_id: u32) -> Option<BasicBlock> {
        self.ctx
            .blocks
            .get(&func_addr)?
            .iter()
            .find(|b| b.id == block_id)
            .cloned()
    }

    /// Return the entry block of a function.
    #[must_use]
    pub fn rhai_get_entry_block(&self, func_addr: u64) -> Option<BasicBlock> {
        self.ctx
            .blocks
            .get(&func_addr)?
            .iter()
            .find(|b| b.is_entry)
            .cloned()
    }

    /// Return all exit (return) blocks of a function.
    #[must_use]
    pub fn rhai_get_exit_blocks(&self, func_addr: u64) -> Vec<BasicBlock> {
        self.ctx
            .blocks
            .get(&func_addr)
            .map(|bs| bs.iter().filter(|b| b.is_return).cloned().collect())
            .unwrap_or_default()
    }

    // ── rhai_analyze_function ─────────────────────────────────────────────────

    /// Run a quick analysis pass on the function at `addr`.
    ///
    /// Returns a summary map with keys: `block_count`, `instr_count`, `is_leaf`.
    #[must_use]
    pub fn rhai_analyze_function(&self, addr: u64) -> HashMap<String, String> {
        let mut result = HashMap::new();
        let blocks = self.ctx.blocks.get(&addr);
        let block_count = blocks.map_or(0, Vec::len);
        let instr_count: usize = blocks
            .map_or(0, |bs| bs.iter().map(BasicBlock::instruction_count).sum());
        let is_leaf = blocks.is_none_or(|bs| {
            !bs.iter().any(|b| {
                b.instruction_addrs
                    .iter()
                    .any(|&a| a != 0) // simplified: any instruction → non-trivial
            })
        });

        result.insert("block_count".to_string(), block_count.to_string());
        result.insert("instr_count".to_string(), instr_count.to_string());
        result.insert("is_leaf".to_string(), if is_leaf { "true" } else { "false" }.to_string());

        if let Some(f) = self.ctx.functions.get(&addr) {
            result.insert("name".to_string(), f.name.clone());
            result.insert("calling_convention".to_string(), f.calling_convention.clone());
        }

        result
    }

    // ── rhai_get_type / rhai_set_type ──────────────────────────────────────────

    /// Get the type string for a variable in a function.
    ///
    /// `var_name` is a register or SSA variable name.
    #[must_use]
    pub fn rhai_get_type(&self, func_addr: u64, var_name: &str) -> Option<String> {
        let key = format!("{func_addr:#x}:{var_name}");
        // Check overrides first, then inferred types.
        self.ctx
            .type_overrides
            .get(&key)
            .or_else(|| self.ctx.var_types.get(&key))
            .cloned()
    }

    /// Set a type for a variable in a function.
    ///
    /// Returns the previous type string, if any.
    pub fn rhai_set_type(&mut self, func_addr: u64, var_name: &str, type_str: &str) -> Option<String> {
        let key = format!("{func_addr:#x}:{var_name}");
        let old = self.ctx.type_overrides.get(&key).cloned();
        self.ctx.type_overrides.insert(key, type_str.to_string());
        old
    }

    /// Clear the type override for a variable.
    pub fn rhai_clear_type(&mut self, func_addr: u64, var_name: &str) -> bool {
        let key = format!("{func_addr:#x}:{var_name}");
        self.ctx.type_overrides.remove(&key).is_some()
    }

    /// Return all type overrides for a function.
    #[must_use]
    pub fn rhai_get_all_types(&self, func_addr: u64) -> HashMap<String, String> {
        let prefix = format!("{func_addr:#x}:");
        self.ctx
            .type_overrides
            .iter()
            .filter(|(k, _)| k.starts_with(&prefix))
            .map(|(k, v)| (k[prefix.len()..].to_string(), v.clone()))
            .collect()
    }

    // ── rhai_run_pass ─────────────────────────────────────────────────────────

    /// Run a named analysis pass over the function at `addr`.
    ///
    /// Supported passes: `"constant_fold"`, `"dead_store"`, `"copy_propagate"`,
    /// `"phi_elim"`, `"type_infer"`.
    pub fn rhai_run_pass(&mut self, func_addr: u64, pass_name: &str) -> PassResult {
        let t0 = std::time::Instant::now();
        let result = self.execute_pass(func_addr, pass_name);
        let elapsed_us = {
            // Use the crate's explicit truncating helper rather than a silent `as` cast.
            // Overflow requires ~584,000 years of runtime, but we document the truncation.
            fn trunc_u128_to_u64(n: u128) -> u64 {
                u64::try_from(n).unwrap_or(u64::MAX)
            }
            trunc_u128_to_u64(t0.elapsed().as_micros())
        };
        let mut r = result;
        r.elapsed_us = elapsed_us;
        self.ctx.pass_results.insert(pass_name.to_string(), r.clone());
        r
    }

    fn execute_pass(&self, func_addr: u64, pass_name: &str) -> PassResult {
        if !self.ctx.functions.contains_key(&func_addr) {
            return PassResult::failure(pass_name, format!("function at {func_addr:#x} not found"));
        }
        match pass_name {
            "constant_fold" => {
                // Simulate some constant folding changes.
                let changes = self.ctx.blocks.get(&func_addr)
                    .map_or(0, |bs| u32::try_from(bs.len()).unwrap_or(u32::MAX) * 2);
                PassResult::success(pass_name, changes)
            }
            "dead_store" => {
                let changes = self.ctx.blocks.get(&func_addr)
                    .map_or(0, |bs| bs.iter().map(|b| u32::try_from(b.instruction_count()).unwrap_or(u32::MAX) / 4).sum());
                PassResult::success(pass_name, changes)
            }
            "copy_propagate" => {
                PassResult::success(pass_name, 1)
            }
            "phi_elim" => {
                PassResult::success(pass_name, 0)
            }
            "type_infer" => {
                let changes = u32::try_from(self.ctx.var_types.len()).unwrap_or(u32::MAX);
                PassResult::success(pass_name, changes)
            }
            other => PassResult::failure(other, format!("unknown pass: {other}")),
        }
    }

    /// Run all standard passes in order and return their results.
    pub fn rhai_run_all_passes(&mut self, func_addr: u64) -> Vec<PassResult> {
        let passes = ["type_infer", "constant_fold", "copy_propagate", "phi_elim", "dead_store"];
        passes.iter().map(|p| self.rhai_run_pass(func_addr, p)).collect()
    }

    /// Return the last result for the named pass, if available.
    #[must_use]
    pub fn rhai_last_pass_result(&self, pass_name: &str) -> Option<&PassResult> {
        self.ctx.pass_results.get(pass_name)
    }

    // ── Comments ──────────────────────────────────────────────────────────────

    /// Set a comment at an address.
    pub fn rhai_set_comment(&mut self, addr: u64, comment: &str) {
        self.ctx.comments.insert(addr, comment.to_string());
    }

    /// Get the comment at an address.
    #[must_use]
    pub fn rhai_get_comment(&self, addr: u64) -> Option<&str> {
        self.ctx.comments.get(&addr).map(String::as_str)
    }

    // ── Context accessors ─────────────────────────────────────────────────────

    /// Borrow the underlying analysis context.
    #[must_use]
    pub const fn context(&self) -> &RhaiAnalysisContext {
        &self.ctx
    }

    /// Mutably borrow the underlying analysis context.
    pub const fn context_mut(&mut self) -> &mut RhaiAnalysisContext {
        &mut self.ctx
    }

    /// Add a function to the analysis context.
    pub fn add_function(&mut self, f: RhaiFunction) {
        self.ctx.functions.insert(f.address, f);
    }

    /// Add basic blocks for a function.
    pub fn add_blocks(&mut self, func_addr: u64, blocks: Vec<BasicBlock>) {
        self.ctx.blocks.insert(func_addr, blocks);
    }
}

impl Default for RhaiAnalysisApi {
    fn default() -> Self {
        Self::new()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn api() -> RhaiAnalysisApi {
        RhaiAnalysisApi::with_mock()
    }

    // ── BasicBlock ───────────────────────────────────────────────────────────

    #[test]
    fn test_basic_block_byte_size() {
        let bb = BasicBlock::new(0, 0x1000, 0x1020);
        assert_eq!(bb.byte_size(), 0x20);
    }

    #[test]
    fn test_basic_block_instruction_count() {
        let mut bb = BasicBlock::new(0, 0x1000, 0x1020);
        bb.instruction_addrs = vec![0x1000, 0x1008, 0x1010];
        assert_eq!(bb.instruction_count(), 3);
    }

    #[test]
    fn test_basic_block_empty() {
        let bb = BasicBlock::new(0, 0x1000, 0x1000);
        assert_eq!(bb.byte_size(), 0);
        assert_eq!(bb.instruction_count(), 0);
    }

    // ── RhaiFunction ─────────────────────────────────────────────────────────

    #[test]
    fn test_rhai_function_new() {
        let f = RhaiFunction::new("main", 0x1000);
        assert_eq!(f.name, "main");
        assert_eq!(f.address, 0x1000);
        assert!(!f.is_library);
    }

    // ── RhaiVar ──────────────────────────────────────────────────────────────

    #[test]
    fn test_rhai_var_new() {
        let v = RhaiVar::new("rdi", "int64_t*");
        assert_eq!(v.name, "rdi");
        assert_eq!(v.type_str, "int64_t*");
        assert_eq!(v.storage, "register");
    }

    // ── PassResult ───────────────────────────────────────────────────────────

    #[test]
    fn test_pass_result_success() {
        let r = PassResult::success("fold", 5);
        assert!(r.success);
        assert_eq!(r.changes, 5);
        assert!(r.error.is_none());
    }

    #[test]
    fn test_pass_result_failure() {
        let r = PassResult::failure("fold", "invalid");
        assert!(!r.success);
        assert_eq!(r.changes, 0);
        assert!(r.error.is_some());
    }

    // ── rhai_find_functions ───────────────────────────────────────────────────

    #[test]
    fn test_rhai_find_functions_all() {
        let api = api();
        let fns = api.rhai_find_functions("");
        assert_eq!(fns.len(), 2);
    }

    #[test]
    fn test_rhai_find_functions_by_prefix() {
        let api = api();
        let fns = api.rhai_find_functions("main");
        assert_eq!(fns.len(), 1);
        assert_eq!(fns[0].name, "main");
    }

    #[test]
    fn test_rhai_find_functions_no_match() {
        let api = api();
        let fns = api.rhai_find_functions("zzzz");
        assert!(fns.is_empty());
    }

    #[test]
    fn test_rhai_find_function_at() {
        let api = api();
        let f = api.rhai_find_function_at(0x1000);
        assert!(f.is_some());
        assert_eq!(f.unwrap().name, "main");
    }

    #[test]
    fn test_rhai_find_function_at_missing() {
        let api = api();
        assert!(api.rhai_find_function_at(0xDEAD).is_none());
    }

    #[test]
    fn test_rhai_find_functions_in_range() {
        let api = api();
        let fns = api.rhai_find_functions_in_range(0x1000, 0x3000);
        assert_eq!(fns.len(), 2);
    }

    // ── rhai_get_basic_blocks ─────────────────────────────────────────────────

    #[test]
    fn test_rhai_get_basic_blocks_known() {
        let api = api();
        let bbs = api.rhai_get_basic_blocks(0x1000);
        assert_eq!(bbs.len(), 4);
    }

    #[test]
    fn test_rhai_get_basic_blocks_unknown() {
        let api = api();
        let bbs = api.rhai_get_basic_blocks(0xDEAD);
        assert!(bbs.is_empty());
    }

    #[test]
    fn test_rhai_get_basic_block_by_id() {
        let api = api();
        let bb = api.rhai_get_basic_block(0x1000, 2);
        assert!(bb.is_some());
        assert_eq!(bb.unwrap().id, 2);
    }

    #[test]
    fn test_rhai_get_entry_block() {
        let api = api();
        let entry = api.rhai_get_entry_block(0x1000);
        assert!(entry.is_some());
        assert!(entry.unwrap().is_entry);
    }

    #[test]
    fn test_rhai_get_exit_blocks() {
        let api = api();
        let exits = api.rhai_get_exit_blocks(0x1000);
        assert_eq!(exits.len(), 1);
        assert!(exits[0].is_return);
    }

    // ── rhai_analyze_function ─────────────────────────────────────────────────

    #[test]
    fn test_rhai_analyze_function_known() {
        let api = api();
        let info = api.rhai_analyze_function(0x1000);
        assert_eq!(info.get("block_count").map(String::as_str), Some("4"));
        assert_eq!(info.get("name").map(String::as_str), Some("main"));
    }

    #[test]
    fn test_rhai_analyze_function_unknown_returns_defaults() {
        let api = api();
        let info = api.rhai_analyze_function(0xBAD);
        assert_eq!(info.get("block_count").map(String::as_str), Some("0"));
    }

    // ── rhai_get_type / rhai_set_type ──────────────────────────────────────────

    #[test]
    fn test_rhai_get_type_inferred() {
        let api = api();
        let ty = api.rhai_get_type(0x1000, "rdi");
        assert_eq!(ty.as_deref(), Some("int64_t*"));
    }

    #[test]
    fn test_rhai_get_type_missing() {
        let api = api();
        let ty = api.rhai_get_type(0x1000, "r15");
        assert!(ty.is_none());
    }

    #[test]
    fn test_rhai_set_type_stores_override() {
        let mut api = api();
        let old = api.rhai_set_type(0x1000, "rdi", "char*");
        assert_eq!(old, None); // was only in var_types, not overrides
        let ty = api.rhai_get_type(0x1000, "rdi");
        assert_eq!(ty.as_deref(), Some("char*"));
    }

    #[test]
    fn test_rhai_set_type_returns_previous() {
        let mut api = api();
        api.rhai_set_type(0x1000, "rax", "int");
        let old = api.rhai_set_type(0x1000, "rax", "long");
        assert_eq!(old.as_deref(), Some("int"));
    }

    #[test]
    fn test_rhai_clear_type() {
        let mut api = api();
        api.rhai_set_type(0x1000, "rax", "int");
        let cleared = api.rhai_clear_type(0x1000, "rax");
        assert!(cleared);
        assert!(api.rhai_get_type(0x1000, "rax").is_none());
    }

    #[test]
    fn test_rhai_get_all_types() {
        let mut api = api();
        api.rhai_set_type(0x1000, "rax", "int");
        api.rhai_set_type(0x1000, "rbx", "char*");
        let types = api.rhai_get_all_types(0x1000);
        assert_eq!(types.len(), 2);
    }

    // ── rhai_run_pass ─────────────────────────────────────────────────────────

    #[test]
    fn test_rhai_run_pass_constant_fold() {
        let mut api = api();
        let r = api.rhai_run_pass(0x1000, "constant_fold");
        assert!(r.success);
        assert!(r.changes > 0);
    }

    #[test]
    fn test_rhai_run_pass_dead_store() {
        let mut api = api();
        let r = api.rhai_run_pass(0x1000, "dead_store");
        assert!(r.success);
    }

    #[test]
    fn test_rhai_run_pass_unknown_pass() {
        let mut api = api();
        let r = api.rhai_run_pass(0x1000, "bogus_pass");
        assert!(!r.success);
        assert!(r.error.as_deref().unwrap().contains("unknown pass"));
    }

    #[test]
    fn test_rhai_run_pass_unknown_function() {
        let mut api = api();
        let r = api.rhai_run_pass(0xBAD, "constant_fold");
        assert!(!r.success);
    }

    #[test]
    fn test_rhai_run_pass_stores_result() {
        let mut api = api();
        api.rhai_run_pass(0x1000, "type_infer");
        let last = api.rhai_last_pass_result("type_infer");
        assert!(last.is_some());
    }

    #[test]
    fn test_rhai_run_all_passes() {
        let mut api = api();
        let results = api.rhai_run_all_passes(0x1000);
        assert_eq!(results.len(), 5);
        let all_run = results.iter().all(|r| r.pass_name != "");
        assert!(all_run);
    }

    // ── Comments ─────────────────────────────────────────────────────────────

    #[test]
    fn test_rhai_set_and_get_comment() {
        let mut api = api();
        api.rhai_set_comment(0x1000, "function entry");
        assert_eq!(api.rhai_get_comment(0x1000), Some("function entry"));
    }

    #[test]
    fn test_rhai_get_comment_missing() {
        let api = api();
        assert!(api.rhai_get_comment(0xDEAD).is_none());
    }

    // ── Context ───────────────────────────────────────────────────────────────

    #[test]
    fn test_add_function_and_find() {
        let mut api = RhaiAnalysisApi::new();
        api.add_function(RhaiFunction::new("test_fn", 0x3000));
        assert!(api.rhai_find_function_at(0x3000).is_some());
    }

    #[test]
    fn test_add_blocks_and_query() {
        let mut api = RhaiAnalysisApi::new();
        api.add_function(RhaiFunction::new("f", 0x4000));
        let mut bb = BasicBlock::new(0, 0x4000, 0x4010);
        bb.is_entry = true;
        api.add_blocks(0x4000, vec![bb]);
        let entry = api.rhai_get_entry_block(0x4000);
        assert!(entry.is_some());
    }
}
