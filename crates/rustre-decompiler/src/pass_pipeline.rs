//! Decompiler pass pipeline with dependency resolution, timing, and findings.
//!
//! Key types:
//! - [`DecompilerPass`] trait — name, priority, run.
//! - [`PassPipeline`] — orders passes by priority and resolves dependencies.
//! - [`PipelineResult`] — timing, applied passes, findings.
//! - Built-in passes: `TypeRecoveryPass`, `CallConventionPass`,
//!   `VariableRecoveryPass`, `LoopRecoveryPass`, `ControlFlowStructuringPass`.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;
use std::ops::Range;
use std::time::{Duration, Instant};

use crate::callconv_bridge::{detect_with_label, CallConvInference};
use crate::signature_recovery::{InstructionView, RecoveredParam, analyze_stack_frame};
use crate::variable_recovery_engine::{
    CallingConvention as RecoveryCC, InsnSummary, StructOnStackCandidate, VarKind, VarStorage,
    VariableRecoveryEngine,
};

// ---------------------------------------------------------------------------
// PassContext
// ---------------------------------------------------------------------------

/// Mutable context shared across all passes in a pipeline run.
#[derive(Debug)]
pub struct PassContext {
    /// Raw pseudo-code lines emitted so far.
    pub lines: Vec<String>,
    /// Annotations: key → value.
    pub annotations: HashMap<String, String>,
    /// Variables collected: name → type string.
    pub variables: HashMap<String, String>,
    /// Call sites (addresses).
    pub call_sites: Vec<u64>,
    /// Detected calling convention.
    pub calling_convention: Option<String>,
    /// Detected loop regions: (`start_offset`, `end_offset`).
    pub loops: Vec<(u64, u64)>,
    /// Whether structured control flow has been applied.
    pub is_structured: bool,
    /// Function address.
    pub address: u64,
    /// Function name.
    pub func_name: String,
    /// Raw instruction summaries for the function (drives real variable
    /// recovery). Empty if the caller does not seed them.
    pub raw_insns: Vec<InsnSummary>,
    /// Mnemonic + operand pairs aligned with `raw_insns`. Used by the
    /// signature/stack-frame analyzer which expects `InstructionView`s.
    pub raw_mnemonics: Vec<(u64, String, String)>,
    /// Address range of the detected prologue (start..end exclusive).
    pub prologue_range: Option<Range<u64>>,
    /// Address range of the detected epilogue (start..end exclusive).
    pub epilogue_range: Option<Range<u64>>,
    /// Recovered struct-on-stack candidates.
    pub struct_candidates: Vec<StructOnStackCandidate>,
    /// Mapping from stack offset to recovered `var_N` name.
    pub stack_rename: HashMap<i64, String>,
    /// Detected total frame size in bytes.
    pub frame_size: u32,
    /// Recovered parameters in source order. Populated by [`CallConventionPass`]
    /// from the analysis-callconv detector and consumed by downstream passes
    /// and the pseudocode emitter.
    pub params: Vec<RecoveredParam>,
    /// Whether the binary we are decompiling is a PE / Windows image.
    /// Defaults to `true` so PE-first workflows keep the MS-x64 spill layout.
    pub is_pe: bool,
    /// Architecture string fed to the calling-convention detector.
    pub arch: String,
    /// Detector confidence (0..=100+) from the most recent CC pass.
    pub cc_confidence: u32,
}

impl Default for PassContext {
    fn default() -> Self {
        Self {
            lines: Vec::new(),
            annotations: HashMap::new(),
            variables: HashMap::new(),
            call_sites: Vec::new(),
            calling_convention: None,
            loops: Vec::new(),
            is_structured: false,
            address: 0,
            func_name: String::new(),
            raw_insns: Vec::new(),
            raw_mnemonics: Vec::new(),
            prologue_range: None,
            epilogue_range: None,
            struct_candidates: Vec::new(),
            stack_rename: HashMap::new(),
            frame_size: 0,
            params: Vec::new(),
            is_pe: true,
            arch: "x86_64".to_string(),
            cc_confidence: 0,
        }
    }
}

impl PassContext {
    /// Create a fresh context for a function.
    #[must_use]
    pub fn new(address: u64, func_name: impl Into<String>) -> Self {
        Self {
            address,
            func_name: func_name.into(),
            ..Default::default()
        }
    }

    /// Set the binary-format hint used by the CC detector.
    #[must_use] 
    pub const fn with_pe(mut self, is_pe: bool) -> Self {
        self.is_pe = is_pe;
        self
    }

    /// Set the architecture hint used by the CC detector.
    #[must_use]
    pub fn with_arch(mut self, arch: impl Into<String>) -> Self {
        self.arch = arch.into();
        self
    }

    /// Emit a line of pseudo-code.
    pub fn emit(&mut self, line: impl Into<String>) {
        self.lines.push(line.into());
    }

    /// Set an annotation.
    pub fn annotate(&mut self, key: impl Into<String>, val: impl Into<String>) {
        self.annotations.insert(key.into(), val.into());
    }

    /// Get an annotation.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&str> {
        self.annotations.get(key).map(String::as_str)
    }

    /// Declare a variable.
    pub fn declare_var(&mut self, name: impl Into<String>, ty: impl Into<String>) {
        self.variables.insert(name.into(), ty.into());
    }

    /// Pseudo-code as a single string.
    #[must_use]
    pub fn pseudo_code(&self) -> String {
        self.lines.join("\n")
    }
}

// ---------------------------------------------------------------------------
// PassResult
// ---------------------------------------------------------------------------

/// Outcome of a single pass run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PassResult {
    /// Pass name.
    pub name: String,
    /// Whether the pass was applied (may be skipped when disabled).
    pub applied: bool,
    /// Elapsed wall time.
    pub elapsed_ms: u64,
    /// Pass-specific findings.
    pub findings: Vec<String>,
}

impl PassResult {
    fn skipped(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            applied: false,
            elapsed_ms: 0,
            findings: Vec::new(),
        }
    }

    fn ok(name: impl Into<String>, elapsed: Duration, findings: Vec<String>) -> Self {
        Self {
            name: name.into(),
            applied: true,
            elapsed_ms: u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX),
            findings,
        }
    }
}

// ---------------------------------------------------------------------------
// PipelineResult
// ---------------------------------------------------------------------------

/// The complete result of a [`PassPipeline::run`] invocation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineResult {
    /// Per-pass results.
    pub pass_results: Vec<PassResult>,
    /// Total elapsed time.
    pub total_ms: u64,
    /// Pseudo-code output.
    pub pseudo_code: String,
    /// Variables recovered.
    pub variables: HashMap<String, String>,
    /// Detected calling convention.
    pub calling_convention: Option<String>,
    /// Call sites found.
    pub call_sites: Vec<u64>,
    /// All findings across all passes.
    pub all_findings: Vec<String>,
}

impl PipelineResult {
    /// Number of passes that were applied.
    #[must_use]
    pub fn applied_count(&self) -> usize {
        self.pass_results.iter().filter(|p| p.applied).count()
    }

    /// The slowest pass.
    #[must_use]
    pub fn slowest_pass(&self) -> Option<&PassResult> {
        self.pass_results.iter().max_by_key(|p| p.elapsed_ms)
    }

    /// Return findings from a specific pass by name.
    #[must_use]
    pub fn findings_for(&self, name: &str) -> Vec<&str> {
        self.pass_results
            .iter()
            .filter(|p| p.name == name)
            .flat_map(|p| p.findings.iter().map(String::as_str))
            .collect()
    }
}

// ---------------------------------------------------------------------------
// PassConfig
// ---------------------------------------------------------------------------

/// Per-pass configuration: enable/disable and priority override.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PassConfig {
    /// Whether the pass is enabled (default true).
    pub enabled: bool,
    /// Priority override (higher = runs first).
    pub priority: Option<i32>,
}

impl Default for PassConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            priority: None,
        }
    }
}

// ---------------------------------------------------------------------------
// DecompilerPass trait
// ---------------------------------------------------------------------------

/// High-level decompiler transformation step that operates on accumulated
/// pseudo-code lines inside a [`PassContext`].
///
/// This is the **context-accumulation** pass interface used by [`PassPipeline`].
/// It is distinct from [`crate::DecompilerPass`], which is the
/// **instruction-level** pass interface used by [`crate::DecompilerPipeline`]
/// and receives raw [`rustre_core::arch::Instruction`] slices.
pub trait DecompilerPass: fmt::Debug + Send + Sync {
    /// Unique pass name.
    fn name(&self) -> &'static str;

    /// Execution priority — higher values run first (default 0).
    fn priority(&self) -> i32 {
        0
    }

    /// Names of passes that must run before this one.
    fn dependencies(&self) -> &'static [&'static str] {
        &[]
    }

    /// Apply the pass to `ctx`.  Returns findings (informational strings).
    fn run(&self, ctx: &mut PassContext) -> Vec<String>;

    /// Short description of what this pass does.
    fn description(&self) -> &'static str {
        ""
    }
}

// ---------------------------------------------------------------------------
// PassPipeline
// ---------------------------------------------------------------------------

/// Manages a collection of passes, resolves their dependency order, and runs them.
pub struct PassPipeline {
    passes: Vec<Box<dyn DecompilerPass>>,
    configs: HashMap<String, PassConfig>,
}

impl PassPipeline {
    /// Create an empty pipeline.
    #[must_use]
    pub fn new() -> Self {
        Self {
            passes: Vec::new(),
            configs: HashMap::new(),
        }
    }

    /// Create a pipeline pre-populated with all built-in passes.
    #[must_use]
    pub fn with_defaults() -> Self {
        let mut p = Self::new();
        p.add(Box::new(TypeRecoveryPass));
        p.add(Box::new(CallConventionPass));
        p.add(Box::new(VariableRecoveryPass));
        p.add(Box::new(LoopRecoveryPass));
        p.add(Box::new(JumpTableRecoveryPass));
        p.add(Box::new(ControlFlowStructuringPass));
        p
    }

    /// Register a pass.
    pub fn add(&mut self, pass: Box<dyn DecompilerPass>) {
        self.passes.push(pass);
    }

    /// Configure a specific pass.
    pub fn configure(&mut self, name: impl Into<String>, config: PassConfig) {
        self.configs.insert(name.into(), config);
    }

    /// Disable a pass by name.
    pub fn disable(&mut self, name: &str) {
        let cfg = self.configs.entry(name.to_string()).or_default();
        cfg.enabled = false;
    }

    /// Number of registered passes.
    #[must_use]
    pub fn pass_count(&self) -> usize {
        self.passes.len()
    }

    /// Names of all registered passes.
    #[must_use]
    pub fn pass_names(&self) -> Vec<&str> {
        self.passes.iter().map(|p| p.name()).collect()
    }

    /// Run the pipeline on `ctx`.
    ///
    /// Passes are executed in dependency-resolved, priority-descending order.
    /// Disabled passes are skipped.
    pub fn run(&self, ctx: &mut PassContext) -> PipelineResult {
        let start = Instant::now();
        let ordered = self.resolve_order();
        let mut pass_results = Vec::new();
        let mut all_findings = Vec::new();

        for &idx in &ordered {
            let pass = &self.passes[idx];
            let cfg = self.configs.get(pass.name());
            let enabled = cfg.is_none_or(|c| c.enabled);
            if !enabled {
                pass_results.push(PassResult::skipped(pass.name()));
                continue;
            }
            let t0 = Instant::now();
            let findings = pass.run(ctx);
            let elapsed = t0.elapsed();
            all_findings.extend(findings.iter().cloned());
            pass_results.push(PassResult::ok(pass.name(), elapsed, findings));
        }

        let total_ms = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);
        PipelineResult {
            pass_results,
            total_ms,
            pseudo_code: ctx.pseudo_code(),
            variables: ctx.variables.clone(),
            calling_convention: ctx.calling_convention.clone(),
            call_sites: ctx.call_sites.clone(),
            all_findings,
        }
    }

    /// Topological sort of passes respecting priority and dependencies.
    fn resolve_order(&self) -> Vec<usize> {
        let n = self.passes.len();
        let name_to_idx: HashMap<&str, usize> = self
            .passes
            .iter()
            .enumerate()
            .map(|(i, p)| (p.name(), i))
            .collect();

        // Build adjacency list (dep → dependents).
        let mut in_degree = vec![0usize; n];
        let mut graph: Vec<Vec<usize>> = vec![vec![]; n];

        for (i, pass) in self.passes.iter().enumerate() {
            for &dep in pass.dependencies() {
                if let Some(&j) = name_to_idx.get(dep) {
                    // j must run before i
                    graph[j].push(i);
                    in_degree[i] += 1;
                }
            }
        }

        // Kahn's algorithm — but use priority to break ties.
        let mut queue: VecDeque<usize> = (0..n).filter(|&i| in_degree[i] == 0).collect();

        // Sort queue by priority descending.
        let mut queue_sorted: Vec<usize> = std::mem::take(&mut queue).into_iter().collect();
        queue_sorted.sort_by(|&a, &b| self.effective_priority(b).cmp(&self.effective_priority(a)));
        queue.extend(queue_sorted);

        let mut order = Vec::with_capacity(n);
        while let Some(i) = queue.pop_front() {
            order.push(i);
            let mut ready: Vec<usize> = graph[i]
                .iter()
                .filter_map(|&j| {
                    in_degree[j] -= 1;
                    if in_degree[j] == 0 { Some(j) } else { None }
                })
                .collect();
            ready.sort_by(|&a, &b| self.effective_priority(b).cmp(&self.effective_priority(a)));
            for j in ready {
                queue.push_back(j);
            }
        }

        // If there are cycles, append remaining passes in priority order.
        if order.len() < n {
            let in_order: HashSet<usize> = order.iter().copied().collect();
            let mut rest: Vec<usize> = (0..n).filter(|i| !in_order.contains(i)).collect();
            rest.sort_by(|&a, &b| self.effective_priority(b).cmp(&self.effective_priority(a)));
            order.extend(rest);
        }

        order
    }

    fn effective_priority(&self, idx: usize) -> i32 {
        let pass = &self.passes[idx];
        let override_prio = self.configs.get(pass.name()).and_then(|c| c.priority);
        override_prio.unwrap_or_else(|| pass.priority())
    }
}

impl Default for PassPipeline {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for PassPipeline {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PassPipeline {{ passes: {} }}", self.passes.len())
    }
}

// ---------------------------------------------------------------------------
// Built-in passes
// ---------------------------------------------------------------------------

/// Recovers type information from register usage and common patterns.
#[derive(Debug)]
pub struct TypeRecoveryPass;

impl DecompilerPass for TypeRecoveryPass {
    fn name(&self) -> &'static str {
        "type_recovery"
    }
    fn priority(&self) -> i32 {
        90
    }
    fn dependencies(&self) -> &'static [&'static str] {
        &["variable_recovery"]
    }
    fn description(&self) -> &'static str {
        "Recover C types from register size/usage patterns"
    }

    fn run(&self, ctx: &mut PassContext) -> Vec<String> {
        let mut findings = Vec::new();
        // Infer pointer types from variables used with dereference patterns.
        let vars: Vec<String> = ctx.variables.keys().cloned().collect();
        for var in vars {
            let ty = ctx.variables[&var].clone();
            // Promote "int" → "int*" if the variable name looks like a pointer.
            if ty == "int64_t" && (var.starts_with("p_") || var.ends_with("_ptr")) {
                ctx.variables.insert(var.clone(), "void *".to_string());
                findings.push(format!("Promoted {var} to void*"));
            }
        }
        ctx.annotate("type_recovery_done", "1");
        findings
    }
}

/// Identifies the calling convention from register usage patterns.
///
/// NOTE: `PassPipeline` is instantiated only in `#[cfg(test)]` — this pass does
/// NOT run in the real decompilation chain. The live one is
/// `lib.rs::CallConventionInferencePass`, the first pass of
/// `DefaultPipelineFactory::standard`. This code is kept (working and tested,
/// not dead) deliberately: it must NOT be "wired up" as a second detector, or
/// two detectors would annotate the same context and disagree. If it is ever
/// connected, `CallConventionInferencePass` has to be retired in the same
/// change.
#[derive(Debug)]
pub struct CallConventionPass;

impl DecompilerPass for CallConventionPass {
    fn name(&self) -> &'static str {
        "call_convention"
    }
    fn priority(&self) -> i32 {
        80
    }
    fn dependencies(&self) -> &'static [&'static str] {
        &[]
    }
    fn description(&self) -> &'static str {
        "Identify calling convention from register usage"
    }

    fn run(&self, ctx: &mut PassContext) -> Vec<String> {
        let mut findings: Vec<String> = Vec::new();

        // Primary path: real CC detection via rustre-analysis-callconv.
        if let Some((label, inference)) =
            detect_with_label(&ctx.raw_mnemonics, ctx.is_pe, &ctx.arch)
        {
            ctx.calling_convention = Some(label.clone());
            ctx.annotate("calling_convention", &label);
            ctx.annotate("cc_pattern", &inference.pattern.name);
            ctx.cc_confidence = inference.confidence;
            populate_params(ctx, &inference);
            findings.push(format!(
                "Detected calling convention: {label} (pattern={}, score={}, params={})",
                inference.pattern.name,
                inference.confidence,
                inference.params.len()
            ));
            return findings;
        }

        // Fallback: pseudo-code grep heuristic for when raw_mnemonics are
        // missing (the detector requires a real instruction stream).
        let code = ctx.lines.join(" ");
        let cc = if code.contains("rdi") || code.contains("rsi") {
            "SysV_AMD64"
        } else if code.contains("rcx") || code.contains("rdx") {
            "Windows_x64"
        } else if code.contains("x0") || code.contains("x1") {
            "ARM64"
        } else if ctx.is_pe {
            "Windows_x64"
        } else {
            "SysV_AMD64"
        };
        ctx.calling_convention = Some(cc.to_string());
        ctx.annotate("calling_convention", cc);
        findings.push(format!("Detected calling convention (heuristic): {cc}"));
        findings
    }
}

/// Push inferred parameters into the [`PassContext`] state: stored as both
/// `ctx.params` and as register-storage entries in `ctx.variables` so the
/// pseudocode emitter sees them as first-class declarations.
fn populate_params(ctx: &mut PassContext, inference: &CallConvInference) {
    ctx.params.clone_from(&inference.params);
    for (idx, p) in inference.params.iter().enumerate() {
        let name = format!("param{idx}");
        ctx.variables.insert(name, p.ty.clone());
    }
}

/// Recovers local variables from stack-frame and register patterns.
///
/// This pass drives the real [`VariableRecoveryEngine`]: it consumes
/// `ctx.raw_insns` (if seeded), assigns monotonic `var_N` names to stack
/// locals, detects struct-on-stack candidates, identifies the prologue /
/// epilogue address range via [`analyze_stack_frame`], and rewrites
/// `[rsp+K]` / `[rbp-K]` operands inside `ctx.lines` to their named
/// variables. Prologue/epilogue lines are removed from the emitted output.
#[derive(Debug)]
pub struct VariableRecoveryPass;

/// Cheap [`InstructionView`] wrapper around `(mnemonic, operands)` tuples
/// stored on the [`PassContext`].
struct RawMnemonicView<'a> {
    mnemonic: &'a str,
    operands: &'a str,
}

impl InstructionView for RawMnemonicView<'_> {
    fn mnemonic(&self) -> &str { self.mnemonic }
    fn operands(&self) -> &str { self.operands }
    fn reads_register(&self, reg: &str) -> bool {
        let r = reg.to_ascii_lowercase();
        self.operands
            .split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
            .any(|tok| tok.eq_ignore_ascii_case(&r))
    }
    fn writes_register(&self, reg: &str) -> bool {
        if let Some((dst, _)) = self.operands.split_once(',') {
            let r = reg.to_ascii_lowercase();
            dst.split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
                .any(|tok| tok.eq_ignore_ascii_case(&r))
        } else {
            false
        }
    }
}

impl DecompilerPass for VariableRecoveryPass {
    fn name(&self) -> &'static str {
        "variable_recovery"
    }
    fn priority(&self) -> i32 {
        70
    }
    fn dependencies(&self) -> &'static [&'static str] {
        &["call_convention"]
    }
    fn description(&self) -> &'static str {
        "Recover stack locals as var_N, detect struct-on-stack, hide prologue/epilogue"
    }

    fn run(&self, ctx: &mut PassContext) -> Vec<String> {
        let cc = match ctx.calling_convention.as_deref() {
            Some("Windows_x64") => RecoveryCC::WindowsX64,
            Some("ARM64") => RecoveryCC::Arm64,
            Some("SysV_AMD64") => RecoveryCC::SysVAmd64,
            Some("Cdecl") => RecoveryCC::Cdecl,
            Some("Stdcall") => RecoveryCC::Stdcall,
            Some("Fastcall") => RecoveryCC::Fastcall,
            Some("Thiscall") => RecoveryCC::Thiscall,
            _ => RecoveryCC::Generic,
        };
        let (engine, mut findings) = drive_variable_engine(ctx, cc);
        let renames = engine.stack_locals_named();
        ctx.stack_rename.clear();
        for (offset, name, _) in &renames {
            ctx.stack_rename.insert(*offset, name.clone());
            ctx.declare_var(name, "uint64_t");
            findings.push(format!("Recovered stack local: {name} @ [rbp{offset:+}]"));
        }
        ctx.struct_candidates = engine.struct_candidates();
        for cand in &ctx.struct_candidates {
            findings.push(format!(
                "Struct candidate at [rbp{:+}] span={}B fields={}",
                cand.base_offset, cand.span, cand.fields.len()
            ));
        }
        let frame = detect_frame_ranges(ctx);
        let lines = std::mem::take(&mut ctx.lines);
        let mut seen_call_sites: HashSet<u64> = ctx.call_sites.iter().copied().collect();
        let mut new_lines: Vec<String> = Vec::with_capacity(lines.len());
        for line in lines {
            if line_is_prologue_or_epilogue(&line) { continue; }
            let rewritten = rewrite_stack_operands(&line, &ctx.stack_rename);
            if rewritten.contains("call ")
                && let Some(addr) = extract_hex_addr(&rewritten)
                && seen_call_sites.insert(addr) {
                ctx.call_sites.push(addr);
            }
            new_lines.push(rewritten);
        }
        ctx.lines = new_lines;
        ctx.annotate("variable_recovery_done", "1");
        ctx.annotate("frame_size", frame.frame_size.to_string());
        ctx.annotate("recovered_locals", renames.len().to_string());
        ctx.annotate("struct_candidates", ctx.struct_candidates.len().to_string());
        findings
    }
}

fn drive_variable_engine(ctx: &PassContext, cc: RecoveryCC) -> (VariableRecoveryEngine, Vec<String>) {
    let findings = Vec::new();
    let mut engine = VariableRecoveryEngine::new(cc);
    for insn in &ctx.raw_insns {
        if let Some(offset) = insn.stack_offset {
            engine.record_stack_access(offset, insn.access_size.max(1), insn.addr, insn.is_def);
        }
        if let Some(addr) = insn.global_addr {
            engine.record_global_access(addr, insn.access_size.max(1), insn.addr, insn.is_def);
        }
    }
    (engine, findings)
}

/// Case-insensitive (ASCII) `starts_with` that avoids allocating a lowercase copy.
fn starts_with_ignore_ascii_case(s: &str, prefix: &str) -> bool {
    s.len() >= prefix.len() && s.as_bytes()[..prefix.len()].eq_ignore_ascii_case(prefix.as_bytes())
}

/// Case-insensitive (ASCII) `contains` that avoids allocating a lowercase copy.
fn contains_ignore_ascii_case(haystack: &str, needle: &str) -> bool {
    !needle.is_empty()
        && haystack.len() >= needle.len()
        && haystack
            .as_bytes()
            .windows(needle.len())
            .any(|w| w.eq_ignore_ascii_case(needle.as_bytes()))
}

fn detect_frame_ranges(ctx: &mut PassContext) -> crate::signature_recovery::StackFrame {
    let views: Vec<RawMnemonicView> = ctx
        .raw_mnemonics
        .iter()
        .map(|(_, m, o)| RawMnemonicView { mnemonic: m.as_str(), operands: o.as_str() })
        .collect();
    let frame = analyze_stack_frame(&views);
    ctx.frame_size = frame.frame_size;
    let mut prologue_start: Option<u64> = None;
    let mut prologue_end: Option<u64> = None;
    for (addr, m, ops) in &ctx.raw_mnemonics {
        let is_prologue = m.eq_ignore_ascii_case("push")
            || (m.eq_ignore_ascii_case("mov")
                && starts_with_ignore_ascii_case(ops, "rbp,")
                && contains_ignore_ascii_case(ops, "rsp"))
            || (m.eq_ignore_ascii_case("sub") && starts_with_ignore_ascii_case(ops, "rsp,"))
            || (m.eq_ignore_ascii_case("endbr64") || m.eq_ignore_ascii_case("endbr32"));
        if is_prologue {
            if prologue_start.is_none() { prologue_start = Some(*addr); }
            prologue_end = Some(*addr + 1);
        } else {
            break;
        }
    }
    if let (Some(s), Some(e)) = (prologue_start, prologue_end) {
        ctx.prologue_range = Some(s..e);
        ctx.annotate("prologue_range", format!("{s:#x}..{e:#x}"));
    }
    let mut epi_start: Option<u64> = None;
    let mut epi_end: Option<u64> = None;
    for (addr, m, ops) in ctx.raw_mnemonics.iter().rev() {
        let is_epilogue = m.eq_ignore_ascii_case("ret")
            || m.eq_ignore_ascii_case("retn")
            || m.eq_ignore_ascii_case("leave")
            || m.eq_ignore_ascii_case("pop")
            || (m.eq_ignore_ascii_case("add") && starts_with_ignore_ascii_case(ops, "rsp,"));
        if is_epilogue {
            if epi_end.is_none() { epi_end = Some(*addr + 1); }
            epi_start = Some(*addr);
        } else {
            break;
        }
    }
    if let (Some(s), Some(e)) = (epi_start, epi_end) {
        ctx.epilogue_range = Some(s..e);
        ctx.annotate("epilogue_range", format!("{s:#x}..{e:#x}"));
    }
    frame
}

/// Heuristic: does this pseudo-code line correspond to a stack frame
/// prologue or epilogue instruction we should hide from the emitted C?
fn line_is_prologue_or_epilogue(line: &str) -> bool {
    let l = line.trim();
    // Common forms emitted by the disassembly-comment pass:
    //   "push rbp", "  // 0x...: push rbp", "sub rsp, 0x20", "mov rbp, rsp",
    //   "pop rbp", "leave", "add rsp, 0x20"
    let body = l.rsplit(':').next().unwrap_or(l).trim();
    let body = body.trim_start_matches("//").trim();
    body.eq_ignore_ascii_case("leave")
        || body.eq_ignore_ascii_case("ret")
        || body.eq_ignore_ascii_case("retn")
        || body.eq_ignore_ascii_case("pop rbp")
        || body.eq_ignore_ascii_case("push rbp")
        || starts_with_ignore_ascii_case(body, "push ")
            && (contains_ignore_ascii_case(body, "rbp") || contains_ignore_ascii_case(body, "rbx")
                || contains_ignore_ascii_case(body, "r12") || contains_ignore_ascii_case(body, "r13")
                || contains_ignore_ascii_case(body, "r14") || contains_ignore_ascii_case(body, "r15"))
        || starts_with_ignore_ascii_case(body, "pop ")
            && (contains_ignore_ascii_case(body, "rbp") || contains_ignore_ascii_case(body, "rbx")
                || contains_ignore_ascii_case(body, "r12") || contains_ignore_ascii_case(body, "r13")
                || contains_ignore_ascii_case(body, "r14") || contains_ignore_ascii_case(body, "r15"))
        || starts_with_ignore_ascii_case(body, "sub rsp,")
        || starts_with_ignore_ascii_case(body, "add rsp,")
        || body.eq_ignore_ascii_case("mov rbp, rsp")
        || body.eq_ignore_ascii_case("endbr64")
        || body.eq_ignore_ascii_case("endbr32")
}

/// Replace `[rbp-K]`, `[rsp+K]`, `[rbp+K]` mem references in `line` with
/// the matching `var_N` rename when the offset is in `rename`.
fn rewrite_stack_operands(line: &str, rename: &HashMap<i64, String>) -> String {
    if rename.is_empty() {
        return line.to_string();
    }
    let mut out = String::with_capacity(line.len());
    let bytes = line.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] == b'['
            && let Some(end_rel) = line[i + 1..].find(']')
        {
            let inner = &line[i + 1..i + 1 + end_rel];
            let inner_l = inner.to_ascii_lowercase();
            let base = if inner_l.contains("rbp") {
                Some("rbp")
            } else if inner_l.contains("rsp") {
                Some("rsp")
            } else {
                None
            };
            if base.is_some()
                && let Some(off) = parse_bracket_offset(inner)
                && let Some(name) = rename.get(&off)
            {
                out.push_str(name);
                i += 1 + end_rel + 1;
                continue;
            }
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    out
}

fn parse_bracket_offset(inner: &str) -> Option<i64> {
    let s = inner.replace(' ', "");
    let pos_plus = s.rfind('+');
    let pos_minus = s.rfind('-');
    let (sign, num_part) = match (pos_plus, pos_minus) {
        (Some(p), Some(m)) if p > m => (1i64, &s[p + 1..]),
        (Some(p), None) => (1i64, &s[p + 1..]),
        (_, Some(m)) => (-1i64, &s[m + 1..]),
        _ => return None,
    };
    let val = if let Some(hex) = num_part.strip_prefix("0x").or_else(|| num_part.strip_prefix("0X")) {
        i64::from_str_radix(hex, 16).ok()?
    } else {
        num_part.parse::<i64>().ok()?
    };
    Some(sign * val)
}

/// Public-facing summary of an engine-recovered stack-local variable.
#[derive(Debug, Clone)]
pub struct StackVarReport {
    pub name: String,
    pub offset: i64,
    pub max_width: u32,
    pub widths: Vec<u32>,
    pub is_param: bool,
}

impl StackVarReport {
    /// Build a report from a fully-driven [`VariableRecoveryEngine`].
    #[must_use]
    pub fn from_engine(engine: &VariableRecoveryEngine) -> Vec<Self> {
        let renames = engine.stack_locals_named();
        let mut by_offset: HashMap<i64, String> = HashMap::new();
        for (off, name, _) in &renames {
            by_offset.insert(*off, name.clone());
        }
        engine
            .vars()
            .iter()
            .filter_map(|v| match v.storage {
                VarStorage::StackOffset(o) => {
                    let widths: Vec<u32> = v.access_widths.iter().copied().collect();
                    let name = by_offset
                        .get(&o)
                        .cloned()
                        .unwrap_or_else(|| v.name.clone());
                    Some(Self {
                        name,
                        offset: o,
                        max_width: v.size,
                        widths,
                        is_param: matches!(v.kind, VarKind::StackParam),
                    })
                }
                _ => None,
            })
            .collect()
    }
}

/// Detects loop patterns (do-while, while, for) in the code.
#[derive(Debug)]
pub struct LoopRecoveryPass;

impl DecompilerPass for LoopRecoveryPass {
    fn name(&self) -> &'static str {
        "loop_recovery"
    }
    fn priority(&self) -> i32 {
        60
    }
    fn dependencies(&self) -> &'static [&'static str] {
        &["variable_recovery"]
    }
    fn description(&self) -> &'static str {
        "Detect loop patterns (while/do-while/for) in the code"
    }

    fn run(&self, ctx: &mut PassContext) -> Vec<String> {
        let mut findings = Vec::new();
        // Simple heuristic: look for backward JMP / CMP patterns.
        let code = ctx.lines.join("\n");
        let loop_indicators = ["jnz", "jne", "jg", "jge", "jl", "jle", "loop"];
        let code_lower = code.to_lowercase();
        for indicator in loop_indicators {
            if code_lower.contains(indicator) {
                ctx.loops.push((ctx.address, ctx.address + 0x100));
                findings.push(format!("Possible loop detected ({indicator} pattern)"));
                break; // one detection per function for heuristic
            }
        }
        ctx.annotate("loop_recovery_done", "1");
        findings
    }
}

/// Detects dense `switch` jump tables from the bounds-checked indirect-jump
/// idiom and records them on the context (non-destructive: annotations and
/// findings only, no rewrite of the emitted body).
#[derive(Debug)]
pub struct JumpTableRecoveryPass;

impl DecompilerPass for JumpTableRecoveryPass {
    fn name(&self) -> &'static str {
        "jump_table_recovery"
    }
    fn priority(&self) -> i32 {
        58
    }
    fn dependencies(&self) -> &'static [&'static str] {
        &["variable_recovery"]
    }
    fn description(&self) -> &'static str {
        "Detect dense switch jump tables from bounds-checked indirect jumps"
    }

    fn run(&self, ctx: &mut PassContext) -> Vec<String> {
        let mut findings = Vec::new();
        if let Some(jt) = crate::jump_table::detect_jump_table_raw(&ctx.raw_mnemonics) {
            ctx.annotate("jump_table_detected", "1");
            ctx.annotate("jump_table_index", &jt.index);
            ctx.annotate("jump_table_cases", jt.case_count.to_string());
            ctx.annotate("jump_table_jump_addr", format!("{:#x}", jt.jump_addr));
            if let Some(base) = jt.table_addr {
                ctx.annotate("jump_table_base", format!("{base:#x}"));
            }
            if let Some(def) = jt.default_target {
                ctx.annotate("jump_table_default", format!("{def:#x}"));
            }
            findings.push(format!(
                "Detected switch jump table: switch({}) with {} cases at {:#x}",
                jt.index, jt.case_count, jt.jump_addr
            ));
        }
        ctx.annotate("jump_table_recovery_done", "1");
        findings
    }
}

/// Applies structured control flow to the accumulated pseudo-code.
#[derive(Debug)]
pub struct ControlFlowStructuringPass;

impl DecompilerPass for ControlFlowStructuringPass {
    fn name(&self) -> &'static str {
        "control_flow_structuring"
    }
    fn priority(&self) -> i32 {
        50
    }
    fn dependencies(&self) -> &'static [&'static str] {
        &["variable_recovery", "loop_recovery"]
    }
    fn description(&self) -> &'static str {
        "Apply structured control flow (if/while/for) recovery"
    }

    fn run(&self, ctx: &mut PassContext) -> Vec<String> {
        // Wrap all lines in a function stub.
        let name = ctx.func_name.clone();
        let cc = ctx.calling_convention.as_deref().unwrap_or("unknown");
        let header = format!("// {name} @ {:#x} [CC={cc}]", ctx.address);

        // Variable declarations.
        let mut decls: Vec<String> = ctx
            .variables
            .iter()
            .map(|(n, t)| format!("  {t} {n};"))
            .collect();
        decls.sort();

        let inner = ctx.lines.drain(..).collect::<Vec<_>>();

        // If a jump table was detected, render its indirect jump as a readable
        // `switch (index) { ... }` skeleton instead of leaving raw asm.
        let switch_line = ctx.annotations.get("jump_table_detected").map(|_| {
            let index = ctx.annotations.get("jump_table_index").cloned().unwrap_or_default();
            let cases = ctx.annotations.get("jump_table_cases").cloned().unwrap_or_default();
            let base = ctx.annotations.get("jump_table_base").cloned().unwrap_or_else(|| "?".into());
            let def = ctx.annotations.get("jump_table_default").cloned().unwrap_or_else(|| "?".into());
            format!("switch ({index}) {{ /* {cases} cases; table @ {base}; default @ {def} */ }}")
        });

        ctx.emit(header);
        ctx.emit(format!("void {name}() {{"));
        for d in decls {
            ctx.emit(d);
        }
        for line in inner {
            match &switch_line {
                Some(sw) if is_indirect_jump_line(&line) => ctx.emit(format!("  {sw}")),
                _ => ctx.emit(format!("  {line}")),
            }
        }
        ctx.emit("}".to_string());
        ctx.is_structured = true;

        vec!["Control flow structuring applied".to_string()]
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// True when a pseudo-code line is an indirect `jmp` through a memory operand or
/// register (the tail of a jump-table dispatch), e.g. `jmp [0x401000 + eax*4]`.
fn is_indirect_jump_line(line: &str) -> bool {
    let l = line.trim().to_ascii_lowercase();
    l.starts_with("jmp ") && (l.contains('[') || !l[4..].trim().starts_with("0x"))
}

fn extract_hex_addr(s: &str) -> Option<u64> {
    let s = s.trim();
    // Find "0x..." or bare hex addresses.
    for word in s.split_whitespace() {
        let w = word.trim_end_matches(&[',', ';', ')'] as &[char]);
        if let Some(hex) = w.strip_prefix("0x").or_else(|| w.strip_prefix("0X"))
            && let Ok(v) = u64::from_str_radix(hex, 16) {
                return Some(v);
            }
    }
    None
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_ctx() -> PassContext {
        PassContext::new(0x401000, "test_func")
    }

    #[test]
    fn test_pass_context_new() {
        let ctx = make_ctx();
        assert_eq!(ctx.address, 0x401000);
        assert_eq!(ctx.func_name, "test_func");
    }

    #[test]
    fn test_pass_context_emit() {
        let mut ctx = make_ctx();
        ctx.emit("line1");
        ctx.emit("line2");
        assert_eq!(ctx.lines.len(), 2);
    }

    #[test]
    fn test_pass_context_annotate_get() {
        let mut ctx = make_ctx();
        ctx.annotate("key", "value");
        assert_eq!(ctx.get("key"), Some("value"));
    }

    #[test]
    fn test_pass_context_pseudo_code() {
        let mut ctx = make_ctx();
        ctx.emit("a = 1;");
        ctx.emit("b = 2;");
        assert_eq!(ctx.pseudo_code(), "a = 1;\nb = 2;");
    }

    #[test]
    fn test_pipeline_new_empty() {
        let p = PassPipeline::new();
        assert_eq!(p.pass_count(), 0);
    }

    #[test]
    fn test_pipeline_with_defaults() {
        let p = PassPipeline::with_defaults();
        assert_eq!(p.pass_count(), 6);
    }

    #[test]
    fn test_pipeline_pass_names() {
        let p = PassPipeline::with_defaults();
        let names = p.pass_names();
        assert!(names.contains(&"type_recovery"));
        assert!(names.contains(&"call_convention"));
        assert!(names.contains(&"jump_table_recovery"));
    }

    #[test]
    fn jump_table_pass_annotates_switch() {
        let mut ctx = make_ctx();
        ctx.raw_mnemonics = vec![
            (0x1000, "cmp".into(), "eax, 4".into()),
            (0x1003, "ja".into(), "0x1050".into()),
            (0x1009, "jmp".into(), "[0x401000 + eax*4]".into()),
        ];
        let findings = JumpTableRecoveryPass.run(&mut ctx);
        assert_eq!(ctx.annotations.get("jump_table_detected").map(String::as_str), Some("1"));
        assert_eq!(ctx.annotations.get("jump_table_cases").map(String::as_str), Some("5"));
        assert_eq!(ctx.annotations.get("jump_table_index").map(String::as_str), Some("eax"));
        assert!(findings.iter().any(|f| f.contains("switch(eax)")));
    }

    #[test]
    fn jump_table_switch_appears_in_output() {
        let mut ctx = make_ctx();
        ctx.raw_mnemonics = vec![
            (0x1000, "cmp".into(), "eax, 2".into()),
            (0x1003, "ja".into(), "0x1050".into()),
            (0x1009, "jmp".into(), "[0x401000 + eax*4]".into()),
        ];
        ctx.emit("cmp eax, 2");
        ctx.emit("ja 0x1050");
        ctx.emit("jmp [0x401000 + eax*4]");
        JumpTableRecoveryPass.run(&mut ctx);
        ControlFlowStructuringPass.run(&mut ctx);
        let out = ctx.lines.join("\n");
        assert!(out.contains("switch (eax)"), "output was:\n{out}");
        // The raw indirect jmp must not survive alongside the switch.
        assert!(!out.contains("jmp [0x401000"), "raw jmp leaked:\n{out}");
    }

    #[test]
    fn jump_table_pass_silent_without_table() {
        let mut ctx = make_ctx();
        ctx.raw_mnemonics = vec![
            (0x2000, "mov".into(), "eax, 1".into()),
            (0x2005, "ret".into(), String::new()),
        ];
        let findings = JumpTableRecoveryPass.run(&mut ctx);
        assert!(!ctx.annotations.contains_key("jump_table_detected"));
        assert!(findings.is_empty());
    }

    #[test]
    fn test_pipeline_run_default() {
        let pipeline = PassPipeline::with_defaults();
        let mut ctx = make_ctx();
        ctx.emit("mov rdi, 0x1");
        ctx.emit("call 0x402000");
        let result = pipeline.run(&mut ctx);
        assert_eq!(result.applied_count(), 6);
    }

    #[test]
    fn test_pipeline_result_total_ms() {
        let pipeline = PassPipeline::with_defaults();
        let mut ctx = make_ctx();
        let result = pipeline.run(&mut ctx);
        // Just check it's a reasonable value (< 10000 ms for a trivial pipeline).
        assert!(result.total_ms < 10_000);
    }

    #[test]
    fn test_pipeline_disable_pass() {
        let mut pipeline = PassPipeline::with_defaults();
        pipeline.disable("loop_recovery");
        let mut ctx = make_ctx();
        let result = pipeline.run(&mut ctx);
        let loop_result = result
            .pass_results
            .iter()
            .find(|p| p.name == "loop_recovery")
            .unwrap();
        assert!(!loop_result.applied);
    }

    #[test]
    fn test_call_convention_pass_sysv() {
        let pass = CallConventionPass;
        let mut ctx = make_ctx();
        ctx.emit("mov rdi, rbx");
        ctx.emit("mov rsi, rdx");
        let findings = pass.run(&mut ctx);
        assert!(!findings.is_empty());
        assert_eq!(ctx.calling_convention.as_deref(), Some("SysV_AMD64"));
    }

    #[test]
    fn test_call_convention_pass_windows() {
        let pass = CallConventionPass;
        let mut ctx = make_ctx();
        ctx.emit("mov rcx, rax");
        ctx.emit("mov rdx, rbx");
        let findings = pass.run(&mut ctx);
        assert_eq!(ctx.calling_convention.as_deref(), Some("Windows_x64"));
        assert!(!findings.is_empty());
    }

    #[test]
    fn test_variable_recovery_finds_locals() {
        let pass = VariableRecoveryPass;
        let mut ctx = make_ctx();
        ctx.calling_convention = Some("SysV_AMD64".to_string());
        ctx.emit("mov [rbp-0x10], rax");
        // Seed the raw-instruction summary the engine actually consumes;
        // post gap-B, recovery is driven from `raw_insns`, not from
        // emitted pseudo-code text. Offset -0x10 is a stack local
        // (negative = below frame pointer), so this should produce
        // both a finding and a declared variable.
        ctx.raw_insns.push(crate::variable_recovery_engine::InsnSummary {
            addr: 0x1000,
            mnemonic: "mov".to_string(),
            dst_reg: None,
            src_regs: vec!["rax".to_string()],
            stack_offset: Some(-0x10),
            access_size: 8,
            is_def: true,
            global_addr: None,
        });
        let findings = pass.run(&mut ctx);
        assert!(!findings.is_empty());
        assert!(!ctx.variables.is_empty());
    }

    #[test]
    fn test_variable_recovery_records_call_sites() {
        let pass = VariableRecoveryPass;
        let mut ctx = make_ctx();
        ctx.emit("call 0x402000");
        pass.run(&mut ctx);
        assert!(!ctx.call_sites.is_empty());
        assert_eq!(ctx.call_sites[0], 0x402000);
    }

    #[test]
    fn test_loop_recovery_detects_jnz() {
        let pass = LoopRecoveryPass;
        let mut ctx = make_ctx();
        ctx.emit("jnz 0x401010");
        let findings = pass.run(&mut ctx);
        assert!(!findings.is_empty());
        assert!(!ctx.loops.is_empty());
    }

    #[test]
    fn test_type_recovery_promotes_pointer() {
        let pass = TypeRecoveryPass;
        let mut ctx = make_ctx();
        ctx.variables
            .insert("p_data".to_string(), "int64_t".to_string());
        let findings = pass.run(&mut ctx);
        assert!(ctx.variables["p_data"] == "void *");
        assert!(!findings.is_empty());
    }

    #[test]
    fn test_control_flow_structuring_wraps() {
        let pass = ControlFlowStructuringPass;
        let mut ctx = make_ctx();
        ctx.emit("mov rax, 1;");
        ctx.calling_convention = Some("SysV_AMD64".to_string());
        pass.run(&mut ctx);
        let code = ctx.pseudo_code();
        assert!(code.contains("void test_func()"));
        assert!(code.contains('}'));
    }

    #[test]
    fn test_pipeline_result_findings_for() {
        let pipeline = PassPipeline::with_defaults();
        let mut ctx = make_ctx();
        ctx.emit("mov rcx, rax");
        let result = pipeline.run(&mut ctx);
        let findings = result.findings_for("call_convention");
        assert!(!findings.is_empty());
    }

    #[test]
    fn test_pipeline_result_slowest_pass() {
        let pipeline = PassPipeline::with_defaults();
        let mut ctx = make_ctx();
        let result = pipeline.run(&mut ctx);
        assert!(result.slowest_pass().is_some());
    }

    #[test]
    fn test_extract_hex_addr() {
        assert_eq!(extract_hex_addr("call 0x401000"), Some(0x401000));
        assert_eq!(extract_hex_addr("nop"), None);
    }

    #[test]
    fn test_pass_config_default() {
        let cfg = PassConfig::default();
        assert!(cfg.enabled);
    }

    #[test]
    fn test_pipeline_debug() {
        let p = PassPipeline::with_defaults();
        let s = format!("{p:?}");
        assert!(s.contains("PassPipeline"));
    }
}
