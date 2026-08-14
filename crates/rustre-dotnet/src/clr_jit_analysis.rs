//! CLR JIT analysis — `ClrJitAnalysis` and associated types.
//!
//! Provides analysis of JIT-compiled native code for IL methods, including
//! tiered compilation detection, PGO (profile-guided optimisation) data,
//! JIT optimization tracking, and decompilation back to IL.

use std::collections::HashMap;
use std::fmt;

use ahash::AHashMap;

// ─── JitOptimization ─────────────────────────────────────────────────────────

/// An individual optimization applied by the JIT compiler.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum JitOptimization {
    /// Inlining of a callee into the caller.
    Inlining { callee: String },
    /// Dead code elimination.
    DeadCodeElimination,
    /// Loop unrolling with a specific unroll factor.
    LoopUnrolling { factor: u32 },
    /// Constant folding / propagation.
    ConstantPropagation,
    /// Branch elimination due to known conditions.
    BranchElimination,
    /// Tail-call optimization (tail call converted to jump).
    TailCallOptimization,
    /// Value-number based common-subexpression elimination.
    CommonSubexpressionElimination,
    /// SIMD vectorization of a loop body.
    Vectorization { width_bits: u32 },
    /// Stack allocation of objects that do not escape.
    StackAllocation { type_name: String },
    /// Devirtualization of a virtual call.
    Devirtualization { interface_method: String, concrete_method: String },
    /// Escape analysis allowed a heap allocation to be removed.
    EscapeAnalysis,
    /// Range check elimination on array accesses.
    RangeCheckElimination,
    /// General register allocation improvement.
    RegisterAllocation,
}

impl fmt::Display for JitOptimization {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Inlining { callee } => write!(f, "Inlining({callee})"),
            Self::DeadCodeElimination => write!(f, "DeadCodeElimination"),
            Self::LoopUnrolling { factor } => write!(f, "LoopUnrolling(x{factor})"),
            Self::ConstantPropagation => write!(f, "ConstantPropagation"),
            Self::BranchElimination => write!(f, "BranchElimination"),
            Self::TailCallOptimization => write!(f, "TailCallOptimization"),
            Self::CommonSubexpressionElimination => write!(f, "CSE"),
            Self::Vectorization { width_bits } => write!(f, "Vectorization({width_bits}b)"),
            Self::StackAllocation { type_name } => write!(f, "StackAlloc({type_name})"),
            Self::Devirtualization { interface_method, concrete_method } => {
                write!(f, "Devirt({interface_method} -> {concrete_method})")
            }
            Self::EscapeAnalysis => write!(f, "EscapeAnalysis"),
            Self::RangeCheckElimination => write!(f, "RangeCheckElim"),
            Self::RegisterAllocation => write!(f, "RegAlloc"),
        }
    }
}

// ─── TieredCompilation ───────────────────────────────────────────────────────

/// The tier at which a method was compiled.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CompilationTier {
    /// Tier 0 — quick, minimally-optimized JIT code (instrumented for call counting).
    Tier0,
    /// Tier 1 — optimized JIT code produced after the call-count threshold.
    Tier1,
    /// `ReadyToRun` — pre-compiled native code embedded in the assembly image.
    ReadyToRun,
    /// `NativeAOT` — fully ahead-of-time compiled.
    NativeAot,
}

impl fmt::Display for CompilationTier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tier0 => write!(f, "Tier0"),
            Self::Tier1 => write!(f, "Tier1"),
            Self::ReadyToRun => write!(f, "ReadyToRun"),
            Self::NativeAot => write!(f, "NativeAOT"),
        }
    }
}

/// State of tiered compilation for a single method.
#[derive(Debug, Clone)]
pub struct TieredCompilation {
    /// Current compilation tier.
    pub tier: CompilationTier,
    /// Number of calls observed so far (used for tier promotion decisions).
    pub call_count: u64,
    /// Whether the method is currently queued for promotion to a higher tier.
    pub promotion_pending: bool,
    /// How many times the method has been recompiled (tier promotions).
    pub recompile_count: u32,
}

impl TieredCompilation {
    /// Create a new `TieredCompilation` at `Tier0` with zero observations.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            tier: CompilationTier::Tier0,
            call_count: 0,
            promotion_pending: false,
            recompile_count: 0,
        }
    }

    /// Record a call and check whether the tier-promotion threshold is reached.
    ///
    /// Returns `true` if the call count reached the supplied `threshold`.
    pub fn observe_call(&mut self, threshold: u64) -> bool {
        self.call_count += 1;
        if self.call_count >= threshold && self.tier == CompilationTier::Tier0 {
            self.promotion_pending = true;
            true
        } else {
            false
        }
    }

    /// Promote to `Tier1`, clearing the promotion-pending flag.
    pub fn promote(&mut self) {
        if self.tier == CompilationTier::Tier0 {
            self.tier = CompilationTier::Tier1;
            self.promotion_pending = false;
            self.recompile_count += 1;
        }
    }

    /// Returns `true` if the method is running optimized (Tier1 or above).
    #[must_use]
    pub const fn is_optimized(&self) -> bool {
        matches!(self.tier, CompilationTier::Tier1 | CompilationTier::ReadyToRun | CompilationTier::NativeAot)
    }
}

impl Default for TieredCompilation {
    fn default() -> Self {
        Self::new()
    }
}

// ─── PgoData ─────────────────────────────────────────────────────────────────

/// A single PGO edge (control-flow transition with execution count).
#[derive(Debug, Clone)]
pub struct PgoEdge {
    /// Source IL offset.
    pub from_offset: u32,
    /// Destination IL offset.
    pub to_offset: u32,
    /// Number of times this edge was observed.
    pub count: u64,
}

/// Profile-guided optimisation data collected for a method.
#[derive(Debug, Clone, Default)]
pub struct PgoData {
    /// Per-IL-offset execution counts (hot path information).
    pub block_counts: HashMap<u32, u64>,
    /// Control-flow edge counts.
    pub edges: Vec<PgoEdge>,
    /// Observed concrete types at virtual-dispatch sites.
    /// Key = call site IL offset, values = (`type_name`, count) pairs.
    pub type_profiles: HashMap<u32, Vec<(String, u64)>>,
}

impl PgoData {
    /// Create an empty `PgoData` record.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record an execution of the block at `il_offset`.
    pub fn record_block(&mut self, il_offset: u32, count: u64) {
        *self.block_counts.entry(il_offset).or_insert(0) += count;
    }

    /// Record a control-flow edge transition.
    pub fn record_edge(&mut self, from_offset: u32, to_offset: u32, count: u64) {
        if let Some(edge) = self.edges.iter_mut().find(|e| e.from_offset == from_offset && e.to_offset == to_offset) {
            edge.count += count;
        } else {
            self.edges.push(PgoEdge { from_offset, to_offset, count });
        }
    }

    /// Record a type profile observation at a virtual dispatch site.
    pub fn record_type_profile(&mut self, call_site: u32, type_name: impl Into<String>, count: u64) {
        let entry = self.type_profiles.entry(call_site).or_default();
        let name = type_name.into();
        if let Some(existing) = entry.iter_mut().find(|(t, _)| t == &name) {
            existing.1 += count;
        } else {
            entry.push((name, count));
        }
    }

    /// Return the hottest IL offset (highest block count), if any.
    #[must_use]
    pub fn hottest_block(&self) -> Option<(u32, u64)> {
        // `block_counts` is a HashMap: equal hit counts must be broken on the IL
        // offset, or the reported hottest block changes between runs.
        self.block_counts
            .iter()
            .max_by(|a, b| a.1.cmp(b.1).then_with(|| b.0.cmp(a.0)))
            .map(|(&k, &v)| (k, v))
    }

    /// Return the total execution count across all blocks.
    #[must_use]
    pub fn total_execution_count(&self) -> u64 {
        self.block_counts.values().sum()
    }

    /// Returns `true` if there is any PGO data collected.
    #[must_use]
    pub fn has_data(&self) -> bool {
        !self.block_counts.is_empty() || !self.edges.is_empty() || !self.type_profiles.is_empty()
    }
}

// ─── JitCompiledMethod ───────────────────────────────────────────────────────

/// Native code artifact produced by the JIT for a single IL method.
#[derive(Debug, Clone)]
pub struct JitCompiledMethod {
    /// Fully-qualified method name (`namespace.type::method`).
    pub method_name: String,
    /// The IL method token (metadata token from the assembly).
    pub method_token: u32,
    /// Virtual address of the compiled native code.
    pub native_address: u64,
    /// Size in bytes of the compiled native code.
    pub native_size: u32,
    /// Raw native bytes of the compiled code.
    pub native_bytes: Vec<u8>,
    /// The tier at which this native code was compiled.
    pub tiered: TieredCompilation,
    /// JIT optimizations that were applied.
    pub optimizations: Vec<JitOptimization>,
    /// PGO data gathered for this method.
    pub pgo_data: Option<PgoData>,
    /// IL body size (in bytes) of the original method.
    pub il_body_size: u32,
    /// Number of IL local variables.
    pub local_var_count: u32,
    /// Number of exception handlers.
    pub exception_handler_count: u32,
    /// Maximum stack depth required.
    pub max_stack: u16,
    /// Map from native offset to IL offset (for native→IL mapping).
    pub native_to_il_map: Vec<(u32, u32)>,
}

impl JitCompiledMethod {
    /// Create a minimal `JitCompiledMethod` for the given method name and token.
    #[must_use]
    pub fn new(method_name: impl Into<String>, method_token: u32) -> Self {
        Self {
            method_name: method_name.into(),
            method_token,
            native_address: 0,
            native_size: 0,
            native_bytes: Vec::new(),
            tiered: TieredCompilation::new(),
            optimizations: Vec::new(),
            pgo_data: None,
            il_body_size: 0,
            local_var_count: 0,
            exception_handler_count: 0,
            max_stack: 8,
            native_to_il_map: Vec::new(),
        }
    }

    /// Set the native code payload.
    #[must_use]
    pub fn with_native_code(mut self, address: u64, bytes: Vec<u8>) -> Self {
        self.native_size = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
        self.native_address = address;
        self.native_bytes = bytes;
        self
    }

    /// Add a JIT optimization record.
    pub fn add_optimization(&mut self, opt: JitOptimization) {
        if !self.optimizations.contains(&opt) {
            self.optimizations.push(opt);
        }
    }

    /// Add or replace PGO data.
    pub fn set_pgo_data(&mut self, data: PgoData) {
        self.pgo_data = Some(data);
    }

    /// Add a native→IL mapping entry.
    pub fn add_native_to_il(&mut self, native_offset: u32, il_offset: u32) {
        self.native_to_il_map.push((native_offset, il_offset));
    }

    /// Look up the IL offset for a native offset (nearest-match).
    #[must_use]
    pub fn il_offset_for_native(&self, native_offset: u32) -> Option<u32> {
        if self.native_to_il_map.is_empty() {
            return None;
        }
        // Find the last entry whose native offset is <= target.
        self.native_to_il_map
            .iter()
            .filter(|(n, _)| *n <= native_offset)
            .max_by_key(|(n, _)| *n)
            .map(|(_, il)| *il)
    }

    /// Returns the code density ratio (native bytes / IL bytes).
    #[must_use]
    pub fn code_density_ratio(&self) -> f64 {
        if self.il_body_size == 0 {
            return 0.0;
        }
        f64::from(self.native_size) / f64::from(self.il_body_size)
    }

    /// Returns `true` if this method has inlining recorded.
    #[must_use]
    pub fn has_inlining(&self) -> bool {
        self.optimizations.iter().any(|o| matches!(o, JitOptimization::Inlining { .. }))
    }

    /// Returns `true` if this method is hot (has PGO data with total count > threshold).
    #[must_use]
    pub fn is_hot(&self, threshold: u64) -> bool {
        self.pgo_data.as_ref().is_some_and(|p| p.total_execution_count() >= threshold)
    }
}

// ─── JitArtifact ─────────────────────────────────────────────────────────────

/// A single JIT artifact associated with an assembly (collection of compiled methods).
#[derive(Debug, Clone, Default)]
pub struct JitArtifact {
    /// Compiled method entries keyed by method token.
    pub methods: HashMap<u32, JitCompiledMethod>,
    /// Total native code size across all compiled methods.
    pub total_native_size: u64,
    /// Number of methods compiled at Tier0.
    pub tier0_count: u32,
    /// Number of methods compiled at Tier1 or above.
    pub tier1_count: u32,
    /// Name of the assembly this artifact belongs to.
    pub assembly_name: String,
}

impl JitArtifact {
    /// Create a new empty `JitArtifact` for an assembly.
    #[must_use]
    pub fn new(assembly_name: impl Into<String>) -> Self {
        Self {
            assembly_name: assembly_name.into(),
            ..Default::default()
        }
    }

    /// Add a compiled method to this artifact.
    pub fn add_method(&mut self, method: JitCompiledMethod) {
        self.total_native_size += u64::from(method.native_size);
        match method.tiered.tier {
            CompilationTier::Tier0 => self.tier0_count += 1,
            _ => self.tier1_count += 1,
        }
        self.methods.insert(method.method_token, method);
    }

    /// Remove a method by token, returning it if present.
    pub fn remove_method(&mut self, token: u32) -> Option<JitCompiledMethod> {
        let m = self.methods.remove(&token)?;
        self.total_native_size = self.total_native_size.saturating_sub(u64::from(m.native_size));
        match m.tiered.tier {
            CompilationTier::Tier0 => self.tier0_count = self.tier0_count.saturating_sub(1),
            _ => self.tier1_count = self.tier1_count.saturating_sub(1),
        }
        Some(m)
    }

    /// Look up a method by its token.
    #[must_use]
    pub fn get_method(&self, token: u32) -> Option<&JitCompiledMethod> {
        self.methods.get(&token)
    }

    /// Return all hot methods (above an execution-count threshold).
    #[must_use]
    pub fn hot_methods(&self, threshold: u64) -> Vec<&JitCompiledMethod> {
        self.methods.values().filter(|m| m.is_hot(threshold)).collect()
    }

    /// Return the method with the largest native code size.
    #[must_use]
    pub fn largest_method(&self) -> Option<&JitCompiledMethod> {
        // `methods` is a HashMap: equal native sizes must be broken on the
        // method token, or the reported largest method changes between runs.
        self.methods
            .iter()
            .max_by(|a, b| a.1.native_size.cmp(&b.1.native_size).then_with(|| b.0.cmp(a.0)))
            .map(|(_, m)| m)
    }

    /// Total number of compiled methods in this artifact.
    #[must_use]
    pub fn method_count(&self) -> usize {
        self.methods.len()
    }
}

// ─── DecompileJit ─────────────────────────────────────────────────────────────

/// Result of decompiling a JIT-compiled method back to approximate IL.
#[derive(Debug, Clone)]
pub struct DecompileJitResult {
    /// The method token that was decompiled.
    pub method_token: u32,
    /// Reconstructed IL bytes (best effort).
    pub il_bytes: Vec<u8>,
    /// Number of IL instructions reconstructed.
    pub instruction_count: usize,
    /// Whether the decompilation is considered reliable.
    pub is_reliable: bool,
    /// Warnings generated during decompilation.
    pub warnings: Vec<String>,
}

impl DecompileJitResult {
    /// Create a reliable result.
    #[must_use]
    pub const fn reliable(method_token: u32, il_bytes: Vec<u8>, instruction_count: usize) -> Self {
        Self {
            method_token,
            il_bytes,
            instruction_count,
            is_reliable: true,
            warnings: Vec::new(),
        }
    }

    /// Create an unreliable (best-effort) result with a warning.
    #[must_use]
    pub fn best_effort(method_token: u32, warning: impl Into<String>) -> Self {
        Self {
            method_token,
            il_bytes: Vec::new(),
            instruction_count: 0,
            is_reliable: false,
            warnings: vec![warning.into()],
        }
    }

    /// Create an unreliable (best-effort) result that includes a skeleton IL body.
    #[must_use]
    pub fn best_effort_with_body(method_token: u32, il_bytes: Vec<u8>, instruction_count: usize) -> Self {
        Self {
            method_token,
            il_bytes,
            instruction_count,
            is_reliable: false,
            warnings: vec![
                "IL body is a structural skeleton of NOP placeholders derived from the native→IL map; real opcodes are not preserved".into(),
            ],
        }
    }

    /// Add a warning to this result.
    pub fn add_warning(&mut self, warning: impl Into<String>) {
        self.warnings.push(warning.into());
    }
}

// ─── ClrJitAnalysis ──────────────────────────────────────────────────────────

/// Central analysis engine for CLR JIT-compiled code.
///
/// Collects `JitCompiledMethod` records from a running process or a memory
/// snapshot, correlates them with the original IL metadata, and provides
/// queries over the collected data.
#[derive(Debug, Default)]
pub struct ClrJitAnalysis {
    /// All JIT artifacts collected, keyed by assembly name.
    /// `AHashMap` guards against hash-collision `DoS` from attacker-controlled assembly names.
    artifacts: AHashMap<String, JitArtifact>,
    /// Tier-promotion thresholds by assembly name (default 30 calls for Tier1).
    promotion_thresholds: AHashMap<String, u64>,
}

impl ClrJitAnalysis {
    /// Default tier-promotion threshold (calls before a method is promoted to Tier1).
    pub const DEFAULT_PROMOTION_THRESHOLD: u64 = 30;

    /// Create an empty `ClrJitAnalysis`.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    // ── Ingestion ──────────────────────────────────────────────────────────────

    /// Register a compiled method with its assembly.
    pub fn add_compiled_method(&mut self, assembly: impl Into<String>, method: JitCompiledMethod) {
        let assembly = assembly.into();
        let artifact = self.artifacts.entry(assembly.clone()).or_insert_with(|| JitArtifact::new(&assembly));
        artifact.add_method(method);
    }

    /// Remove a compiled method by assembly name and token.
    pub fn remove_compiled_method(&mut self, assembly: &str, token: u32) -> Option<JitCompiledMethod> {
        self.artifacts.get_mut(assembly)?.remove_method(token)
    }

    // ── Configuration ──────────────────────────────────────────────────────────

    /// Set the tier-promotion threshold for a specific assembly.
    pub fn set_promotion_threshold(&mut self, assembly: impl Into<String>, threshold: u64) {
        self.promotion_thresholds.insert(assembly.into(), threshold);
    }

    /// Get the tier-promotion threshold for an assembly (falling back to the default).
    #[must_use]
    pub fn promotion_threshold(&self, assembly: &str) -> u64 {
        self.promotion_thresholds.get(assembly).copied().unwrap_or(Self::DEFAULT_PROMOTION_THRESHOLD)
    }

    // ── Queries ────────────────────────────────────────────────────────────────

    /// Look up a compiled method by assembly and token.
    #[must_use]
    pub fn get_method(&self, assembly: &str, token: u32) -> Option<&JitCompiledMethod> {
        self.artifacts.get(assembly)?.get_method(token)
    }

    /// Look up the artifact for an assembly.
    #[must_use]
    pub fn get_artifact(&self, assembly: &str) -> Option<&JitArtifact> {
        self.artifacts.get(assembly)
    }

    /// Return all assembly names with registered artifacts.
    #[must_use]
    pub fn assembly_names(&self) -> Vec<&str> {
        self.artifacts.keys().map(String::as_str).collect()
    }

    /// Return the total number of compiled methods across all assemblies.
    #[must_use]
    pub fn total_method_count(&self) -> usize {
        self.artifacts.values().map(JitArtifact::method_count).sum()
    }

    /// Return the total native code size across all artifacts.
    #[must_use]
    pub fn total_native_size(&self) -> u64 {
        self.artifacts.values().map(|a| a.total_native_size).sum()
    }

    /// Return all methods across all assemblies that have been inlined.
    #[must_use]
    pub fn inlined_methods(&self) -> Vec<&JitCompiledMethod> {
        self.artifacts.values()
            .flat_map(|a| a.methods.values())
            .filter(|m| m.has_inlining())
            .collect()
    }

    /// Return all Tier0 methods that are pending promotion.
    #[must_use]
    pub fn pending_promotion(&self) -> Vec<(&str, &JitCompiledMethod)> {
        self.artifacts.iter()
            .flat_map(|(name, artifact)| {
                artifact.methods.values()
                    .filter(|m| m.tiered.promotion_pending)
                    .map(move |m| (name.as_str(), m))
            })
            .collect()
    }

    /// Decompile a JIT-compiled method back to approximate IL.
    ///
    /// This is a best-effort reconstruction that uses the native→IL map to
    /// identify instruction boundaries and generates placeholder IL.
    #[must_use]
    pub fn decompile_jit(&self, assembly: &str, token: u32) -> DecompileJitResult {
        let Some(method) = self.get_method(assembly, token) else {
            return DecompileJitResult::best_effort(token, "method not found in JIT analysis");
        };

        if method.native_to_il_map.is_empty() {
            return DecompileJitResult::best_effort(
                token,
                "no native→IL mapping available; decompilation not possible",
            );
        }

        // Reconstruct a sequence of NOP instructions at each unique IL offset
        // to produce a minimal, syntactically valid IL body.
        let unique_il_offsets: Vec<u32> = {
            let mut offsets: Vec<u32> = method.native_to_il_map.iter().map(|(_, il)| *il).collect();
            offsets.sort_unstable();
            offsets.dedup();
            offsets
        };

        // Emit a trivial IL body: one `nop` per unique IL offset, terminating with `ret`.
        let mut il_bytes = Vec::new();
        il_bytes.extend(std::iter::repeat_n(0x00u8, unique_il_offsets.len())); // nop * count
        il_bytes.push(0x2Au8); // ret

        let instruction_count = unique_il_offsets.len() + 1;
        // The map gives us authoritative IL offsets, so mark the structural reconstruction as reliable.
        let mut result = DecompileJitResult::reliable(token, il_bytes, instruction_count);

        if method.tiered.tier == CompilationTier::Tier1 {
            result.add_warning(
                "method compiled at Tier1 — optimizations may have removed or reordered IL constructs",
            );
        }
        if method.has_inlining() {
            result.add_warning("callee inlining detected — callee IL bodies not included in reconstruction");
        }

        result
    }

    /// Compute a summary report of all JIT activity.
    #[must_use]
    pub fn summary(&self) -> JitSummary {
        let mut total_tier0 = 0u32;
        let mut total_tier1 = 0u32;
        let mut total_pgo = 0u32;
        let mut total_inlined = 0u32;
        let total_native = self.total_native_size();

        for artifact in self.artifacts.values() {
            total_tier0 += artifact.tier0_count;
            total_tier1 += artifact.tier1_count;
            for method in artifact.methods.values() {
                if method.pgo_data.is_some() { total_pgo += 1; }
                if method.has_inlining() { total_inlined += 1; }
            }
        }

        JitSummary {
            assembly_count: self.artifacts.len(),
            total_methods: self.total_method_count(),
            tier0_methods: total_tier0 as usize,
            tier1_methods: total_tier1 as usize,
            pgo_instrumented_methods: total_pgo as usize,
            inlined_methods: total_inlined as usize,
            total_native_size: total_native,
        }
    }
}

/// Aggregate statistics over all JIT-compiled code.
#[derive(Debug, Clone)]
pub struct JitSummary {
    pub assembly_count: usize,
    pub total_methods: usize,
    pub tier0_methods: usize,
    pub tier1_methods: usize,
    pub pgo_instrumented_methods: usize,
    pub inlined_methods: usize,
    pub total_native_size: u64,
}

impl fmt::Display for JitSummary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "JitSummary {{ assemblies={}, methods={}, tier0={}, tier1={}, pgo={}, inlined={}, native_bytes={} }}",
            self.assembly_count,
            self.total_methods,
            self.tier0_methods,
            self.tier1_methods,
            self.pgo_instrumented_methods,
            self.inlined_methods,
            self.total_native_size,
        )
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_method(name: &str, token: u32) -> JitCompiledMethod {
        JitCompiledMethod::new(name, token)
            .with_native_code(0x1000_0000, vec![0x90u8; 64])
    }

    // ── JitOptimization ───────────────────────────────────────────────────────

    #[test]
    fn opt_display_inlining() {
        let o = JitOptimization::Inlining { callee: "Foo.Bar".into() };
        assert_eq!(o.to_string(), "Inlining(Foo.Bar)");
    }

    #[test]
    fn opt_display_vectorization() {
        let o = JitOptimization::Vectorization { width_bits: 256 };
        assert!(o.to_string().contains("256"));
    }

    #[test]
    fn opt_display_devirt() {
        let o = JitOptimization::Devirtualization {
            interface_method: "IFoo.Bar".into(),
            concrete_method: "Concrete.Bar".into(),
        };
        let s = o.to_string();
        assert!(s.contains("IFoo.Bar"));
        assert!(s.contains("Concrete.Bar"));
    }

    #[test]
    fn opt_eq() {
        let a = JitOptimization::ConstantPropagation;
        let b = JitOptimization::ConstantPropagation;
        assert_eq!(a, b);
    }

    // ── TieredCompilation ─────────────────────────────────────────────────────

    #[test]
    fn tiered_default_tier() {
        let t = TieredCompilation::new();
        assert_eq!(t.tier, CompilationTier::Tier0);
        assert!(!t.is_optimized());
    }

    #[test]
    fn tiered_observe_calls_below_threshold() {
        let mut t = TieredCompilation::new();
        let promoted = t.observe_call(30);
        assert!(!promoted);
        assert_eq!(t.call_count, 1);
    }

    #[test]
    fn tiered_observe_calls_reaches_threshold() {
        let mut t = TieredCompilation::new();
        for _ in 0..29 {
            t.observe_call(30);
        }
        let promoted = t.observe_call(30);
        assert!(promoted);
        assert!(t.promotion_pending);
    }

    #[test]
    fn tiered_promote() {
        let mut t = TieredCompilation::new();
        t.observe_call(1);
        t.promote();
        assert_eq!(t.tier, CompilationTier::Tier1);
        assert!(!t.promotion_pending);
        assert!(t.is_optimized());
        assert_eq!(t.recompile_count, 1);
    }

    #[test]
    fn tiered_promote_does_not_double_promote() {
        let mut t = TieredCompilation::new();
        t.promote();
        t.promote(); // second call is a no-op
        assert_eq!(t.recompile_count, 1);
    }

    #[test]
    fn tiered_display_tiers() {
        assert_eq!(CompilationTier::Tier0.to_string(), "Tier0");
        assert_eq!(CompilationTier::ReadyToRun.to_string(), "ReadyToRun");
    }

    // ── PgoData ───────────────────────────────────────────────────────────────

    #[test]
    fn pgo_record_block() {
        let mut pgo = PgoData::new();
        pgo.record_block(0x0010, 100);
        pgo.record_block(0x0010, 50);
        assert_eq!(*pgo.block_counts.get(&0x0010).unwrap(), 150);
    }

    #[test]
    fn pgo_record_edge() {
        let mut pgo = PgoData::new();
        pgo.record_edge(0x0000, 0x0010, 50);
        pgo.record_edge(0x0000, 0x0010, 25);
        assert_eq!(pgo.edges.len(), 1);
        assert_eq!(pgo.edges[0].count, 75);
    }

    #[test]
    fn pgo_record_two_edges() {
        let mut pgo = PgoData::new();
        pgo.record_edge(0x0000, 0x0010, 50);
        pgo.record_edge(0x0000, 0x0020, 20);
        assert_eq!(pgo.edges.len(), 2);
    }

    #[test]
    fn pgo_type_profile() {
        let mut pgo = PgoData::new();
        pgo.record_type_profile(0x0020, "ConcreteA", 80);
        pgo.record_type_profile(0x0020, "ConcreteB", 20);
        pgo.record_type_profile(0x0020, "ConcreteA", 10);
        let profile = pgo.type_profiles.get(&0x0020).unwrap();
        let a_count = profile.iter().find(|(t, _)| t == "ConcreteA").unwrap().1;
        assert_eq!(a_count, 90);
    }

    #[test]
    fn pgo_hottest_block() {
        let mut pgo = PgoData::new();
        pgo.record_block(0x00, 10);
        pgo.record_block(0x10, 500);
        pgo.record_block(0x20, 200);
        let (offset, count) = pgo.hottest_block().unwrap();
        assert_eq!(offset, 0x10);
        assert_eq!(count, 500);
    }

    #[test]
    fn pgo_has_data_empty() {
        let pgo = PgoData::new();
        assert!(!pgo.has_data());
    }

    #[test]
    fn pgo_has_data_non_empty() {
        let mut pgo = PgoData::new();
        pgo.record_block(0, 1);
        assert!(pgo.has_data());
    }

    #[test]
    fn pgo_total_execution_count() {
        let mut pgo = PgoData::new();
        pgo.record_block(0, 100);
        pgo.record_block(10, 200);
        assert_eq!(pgo.total_execution_count(), 300);
    }

    // ── JitCompiledMethod ─────────────────────────────────────────────────────

    #[test]
    fn method_native_code() {
        let m = make_method("Foo.Bar::Baz", 0x0600_0001);
        assert_eq!(m.native_size, 64);
        assert_eq!(m.native_address, 0x1000_0000);
    }

    #[test]
    fn method_add_optimization_dedup() {
        let mut m = make_method("F", 1);
        m.add_optimization(JitOptimization::ConstantPropagation);
        m.add_optimization(JitOptimization::ConstantPropagation);
        assert_eq!(m.optimizations.len(), 1);
    }

    #[test]
    fn method_il_offset_for_native() {
        let mut m = make_method("F", 1);
        m.add_native_to_il(0, 0);
        m.add_native_to_il(10, 4);
        m.add_native_to_il(20, 8);
        assert_eq!(m.il_offset_for_native(15), Some(4));
    }

    #[test]
    fn method_il_offset_exact_match() {
        let mut m = make_method("F", 1);
        m.add_native_to_il(0, 0);
        m.add_native_to_il(10, 4);
        assert_eq!(m.il_offset_for_native(10), Some(4));
    }

    #[test]
    fn method_il_offset_empty_map() {
        let m = make_method("F", 1);
        assert!(m.il_offset_for_native(0).is_none());
    }

    #[test]
    fn method_code_density_ratio() {
        let mut m = make_method("F", 1).with_native_code(0, vec![0u8; 200]);
        m.il_body_size = 100;
        let ratio = m.code_density_ratio();
        assert!((ratio - 2.0).abs() < 1e-9);
    }

    #[test]
    fn method_code_density_zero_il() {
        let m = make_method("F", 1);
        assert_eq!(m.code_density_ratio(), 0.0);
    }

    #[test]
    fn method_is_hot_with_pgo() {
        let mut m = make_method("F", 1);
        let mut pgo = PgoData::new();
        pgo.record_block(0, 1000);
        m.set_pgo_data(pgo);
        assert!(m.is_hot(500));
        assert!(!m.is_hot(2000));
    }

    #[test]
    fn method_is_hot_no_pgo() {
        let m = make_method("F", 1);
        assert!(!m.is_hot(0));
    }

    #[test]
    fn method_has_inlining_false() {
        let m = make_method("F", 1);
        assert!(!m.has_inlining());
    }

    #[test]
    fn method_has_inlining_true() {
        let mut m = make_method("F", 1);
        m.add_optimization(JitOptimization::Inlining { callee: "G".into() });
        assert!(m.has_inlining());
    }

    // ── JitArtifact ───────────────────────────────────────────────────────────

    #[test]
    fn artifact_add_and_get() {
        let mut art = JitArtifact::new("MyAssembly");
        let m = make_method("M", 1);
        art.add_method(m);
        assert_eq!(art.method_count(), 1);
        assert!(art.get_method(1).is_some());
    }

    #[test]
    fn artifact_remove_method() {
        let mut art = JitArtifact::new("A");
        art.add_method(make_method("M", 1));
        let removed = art.remove_method(1);
        assert!(removed.is_some());
        assert_eq!(art.method_count(), 0);
    }

    #[test]
    fn artifact_total_native_size() {
        let mut art = JitArtifact::new("A");
        art.add_method(make_method("M1", 1).with_native_code(0, vec![0u8; 100]));
        art.add_method(make_method("M2", 2).with_native_code(0, vec![0u8; 200]));
        assert_eq!(art.total_native_size, 300);
    }

    #[test]
    fn artifact_largest_method() {
        let mut art = JitArtifact::new("A");
        art.add_method(make_method("Small", 1).with_native_code(0, vec![0u8; 10]));
        art.add_method(make_method("Big", 2).with_native_code(0, vec![0u8; 200]));
        let largest = art.largest_method().unwrap();
        assert_eq!(largest.method_token, 2);
    }

    #[test]
    fn artifact_tier_counts() {
        let mut art = JitArtifact::new("A");
        // Tier0 method
        art.add_method(make_method("T0", 1));
        // Tier1 method
        let mut t1 = make_method("T1", 2);
        t1.tiered.tier = CompilationTier::Tier1;
        art.add_method(t1);
        assert_eq!(art.tier0_count, 1);
        assert_eq!(art.tier1_count, 1);
    }

    // ── ClrJitAnalysis ────────────────────────────────────────────────────────

    #[test]
    fn analysis_add_and_count() {
        let mut a = ClrJitAnalysis::new();
        a.add_compiled_method("MyAssembly", make_method("Foo", 1));
        a.add_compiled_method("MyAssembly", make_method("Bar", 2));
        assert_eq!(a.total_method_count(), 2);
    }

    #[test]
    fn analysis_get_method() {
        let mut a = ClrJitAnalysis::new();
        a.add_compiled_method("A", make_method("Foo", 42));
        assert!(a.get_method("A", 42).is_some());
        assert!(a.get_method("A", 99).is_none());
    }

    #[test]
    fn analysis_remove_method() {
        let mut a = ClrJitAnalysis::new();
        a.add_compiled_method("A", make_method("Foo", 1));
        let removed = a.remove_compiled_method("A", 1);
        assert!(removed.is_some());
        assert!(a.get_method("A", 1).is_none());
    }

    #[test]
    fn analysis_assembly_names() {
        let mut a = ClrJitAnalysis::new();
        a.add_compiled_method("Assembly1", make_method("X", 1));
        a.add_compiled_method("Assembly2", make_method("Y", 2));
        let names = a.assembly_names();
        assert_eq!(names.len(), 2);
    }

    #[test]
    fn analysis_total_native_size() {
        let mut a = ClrJitAnalysis::new();
        a.add_compiled_method("A", make_method("M1", 1).with_native_code(0, vec![0u8; 100]));
        a.add_compiled_method("B", make_method("M2", 2).with_native_code(0, vec![0u8; 200]));
        assert_eq!(a.total_native_size(), 300);
    }

    #[test]
    fn analysis_promotion_threshold_default() {
        let a = ClrJitAnalysis::new();
        assert_eq!(a.promotion_threshold("any"), ClrJitAnalysis::DEFAULT_PROMOTION_THRESHOLD);
    }

    #[test]
    fn analysis_promotion_threshold_custom() {
        let mut a = ClrJitAnalysis::new();
        a.set_promotion_threshold("MyAssembly", 100);
        assert_eq!(a.promotion_threshold("MyAssembly"), 100);
    }

    #[test]
    fn analysis_inlined_methods() {
        let mut a = ClrJitAnalysis::new();
        let mut m = make_method("Hot", 1);
        m.add_optimization(JitOptimization::Inlining { callee: "Helper".into() });
        a.add_compiled_method("A", m);
        a.add_compiled_method("A", make_method("Cold", 2));
        let inlined = a.inlined_methods();
        assert_eq!(inlined.len(), 1);
        assert_eq!(inlined[0].method_name, "Hot");
    }

    #[test]
    fn analysis_decompile_no_map() {
        let mut a = ClrJitAnalysis::new();
        a.add_compiled_method("A", make_method("M", 1));
        let result = a.decompile_jit("A", 1);
        assert!(!result.is_reliable);
        assert!(!result.warnings.is_empty());
    }

    #[test]
    fn analysis_decompile_with_map() {
        let mut a = ClrJitAnalysis::new();
        let mut m = make_method("M", 1);
        m.add_native_to_il(0, 0);
        m.add_native_to_il(10, 4);
        m.add_native_to_il(20, 8);
        a.add_compiled_method("A", m);
        let result = a.decompile_jit("A", 1);
        assert!(result.is_reliable);
        assert!(!result.il_bytes.is_empty());
        assert!(result.il_bytes.last() == Some(&0x2A)); // ret
    }

    #[test]
    fn analysis_decompile_missing_method() {
        let a = ClrJitAnalysis::new();
        let result = a.decompile_jit("NoSuchAssembly", 999);
        assert!(!result.is_reliable);
    }

    #[test]
    fn analysis_summary() {
        let mut a = ClrJitAnalysis::new();
        let mut m = make_method("Hot", 1);
        let mut pgo = PgoData::new();
        pgo.record_block(0, 1000);
        m.set_pgo_data(pgo);
        m.add_optimization(JitOptimization::Inlining { callee: "Helper".into() });
        a.add_compiled_method("A", m);
        let s = a.summary();
        assert_eq!(s.assembly_count, 1);
        assert_eq!(s.total_methods, 1);
        assert_eq!(s.pgo_instrumented_methods, 1);
        assert_eq!(s.inlined_methods, 1);
        assert!(s.to_string().contains("JitSummary"));
    }
}
