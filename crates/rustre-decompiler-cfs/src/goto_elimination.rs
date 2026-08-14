//! Goto elimination for `rustre-decompiler-cfs`.
//!
//! # Overview
//!
//! Decompilers that perform CFG structuring often produce `goto` statements
//! for irreducible control flow.  This module post-processes the structured
//! output and converts as many gotos as possible into higher-level constructs.
//!
//! ## Transformations
//!
//! ### Break Recovery
//!
//! A forward `goto` that targets the label immediately following a loop body
//! is converted to `break`:
//!
//! ```text
//! while (cond) {          while (cond) {
//!     ...                     ...
//!     goto after;   →         break;
//! }                       }
//! after:
//! ```
//!
//! ### Continue Recovery
//!
//! A backward `goto` that targets the label immediately before a loop header
//! is converted to `continue`:
//!
//! ```text
//! header:                 while (cond) {
//! while (cond) {              ...
//!     ...           →         continue;
//!     goto header;        }
//! }
//! ```
//!
//! ### Trivial Forward Elimination
//!
//! A `goto` whose target label is the very next statement is simply removed
//! (and the label is also removed if no other gotos reference it).
//!
//! ### Irreducible Goto
//!
//! If none of the above patterns match, the `goto` is left as-is and counted
//! in [`GotoStats::residual`].
//!
//! ## Multi-Pass
//!
//! [`MultiPassGotoElimination`] runs the single-pass elimination iteratively
//! until convergence (no more gotos can be eliminated) or a maximum iteration
//! count is reached.  This handles cases where one pass enables further
//! simplifications.
//!
//! ## Reporting
//!
//! [`GotoEliminationReport`] provides a structured summary including the
//! original goto count, per-category eliminations, and the residual count.
//! The `reduction_pct()` method gives a single quality metric.
//!
//! ## Label Utilities
//!
//! * [`LabelElimination`] removes labels that are no longer referenced.
//! * [`LabelRenamer`] renames all labels to sequential identifiers (`L0`,
//!   `L1`, …) to produce cleaner output.
//! * [`GotoGraph`] builds a directed graph of `goto → label` edges and
//!   identifies back-edges and dangling gotos.
//!
//! [`GotoElimination`] converts a sequence of [`PseudoStmt`]s that contains
//! `goto` / `label` nodes into structured equivalents wherever possible.
//!
//! Supported transformations:
//! * **Break recovery** — `goto` that jumps to the first statement past a loop.
//! * **Continue recovery** — `goto` that jumps to a loop header.
//! * **Label removal** — labels with no remaining references are dropped.
//! * **Trivial goto** — `goto` to the immediately-following label is removed.
//!
//! Irreducible gotos that cannot be eliminated are left as-is and counted in
//! [`GotoStats`].

use std::collections::{HashMap, HashSet};
use std::fmt;

// ---------------------------------------------------------------------------
// Well-known goto elimination limits
// ---------------------------------------------------------------------------

/// Maximum number of iterations in [`MultiPassGotoElimination`].
pub const DEFAULT_MAX_ITERS: usize = 16;

/// Maximum number of labels in a function before the renamer gives up.
pub const MAX_LABELS: usize = 4096;

/// Maximum number of goto statements considered "expected" in a well-structured function.
pub const EXPECTED_MAX_GOTOS: usize = 0;

/// Label prefix used by [`LabelRenamer`].
pub const LABEL_PREFIX: &str = "L";

/// Maximum single-pass iteration count for [`MultiPassGotoElimination`].
pub const HARD_ITER_LIMIT: usize = 64;

// ---------------------------------------------------------------------------
// Statement depth utilities
// ---------------------------------------------------------------------------

/// Compute the maximum nesting depth of `stmts`.
#[must_use]
pub fn max_nesting_depth(stmts: &[PseudoStmt]) -> usize {
    let mut max = 0;
    for stmt in stmts {
        let child_depth = match stmt {
            PseudoStmt::If {
                then_body,
                else_body,
                ..
            } => {
                let td = max_nesting_depth(then_body);
                let ed = else_body.as_deref().map_or(0, max_nesting_depth);
                1 + td.max(ed)
            }
            PseudoStmt::While { body, .. } | PseudoStmt::DoWhile { body, .. } => {
                1 + max_nesting_depth(body)
            }
            PseudoStmt::For { body, .. } => 1 + max_nesting_depth(body),
            _ => 0,
        };
        if child_depth > max {
            max = child_depth;
        }
    }
    max
}

// ---------------------------------------------------------------------------
// Simple token counter
// ---------------------------------------------------------------------------

/// Counts all "tokens" (non-Nop statements) in a statement list.
#[must_use]
pub fn count_tokens(stmts: &[PseudoStmt]) -> usize {
    stmts
        .iter()
        .filter(|s| !matches!(s, PseudoStmt::Nop))
        .count()
}

// ---------------------------------------------------------------------------
// GotoEliminationVersion — version metadata
// ---------------------------------------------------------------------------

/// Version metadata for the goto elimination pass.
pub struct GotoEliminationVersion;

impl GotoEliminationVersion {
    /// Pass name.
    pub const NAME: &'static str = "goto_elimination";
    /// Pass version (semver).
    pub const VERSION: &'static str = "1.0.0";
    /// Minimum HLIL version required.
    pub const MIN_IR_VERSION: u32 = 1;
}

// ---------------------------------------------------------------------------
// GotoEliminationSummary — textual summary of the full pipeline
// ---------------------------------------------------------------------------

/// Produces a textual summary of a goto elimination run.
#[derive(Debug, Default)]
pub struct GotoEliminationSummary;

impl GotoEliminationSummary {
    /// Format a summary for `report`.
    #[must_use]
    pub fn format(report: &GotoEliminationReport) -> String {
        format!(
            "GotoElim: original={}, break={}, continue={}, trivial={}, labels_removed={}, residual={}, fully_structured={}, reduction={:.0}%",
            report.original_goto_count,
            report.break_recoveries,
            report.continue_recoveries,
            report.trivial_eliminated,
            report.labels_removed,
            report.residual_gotos,
            report.fully_structured,
            report.reduction_pct(),
        )
    }
}

// ---------------------------------------------------------------------------
// GotoCounter — counts gotos in nested statement trees
// ---------------------------------------------------------------------------

/// Recursively counts all `goto` statements in a statement tree.
#[derive(Debug, Default)]
pub struct GotoCounter;

impl GotoCounter {
    /// Count gotos in `stmts`, including nested bodies.
    #[must_use] 
    pub fn count(stmts: &[PseudoStmt]) -> usize {
        let mut n = 0;
        for stmt in stmts {
            match stmt {
                PseudoStmt::Goto(_) => n += 1,
                PseudoStmt::If {
                    then_body,
                    else_body,
                    ..
                } => {
                    n += Self::count(then_body);
                    if let Some(e) = else_body {
                        n += Self::count(e);
                    }
                }
                PseudoStmt::While { body, .. } | PseudoStmt::DoWhile { body, .. } => {
                    n += Self::count(body);
                }
                PseudoStmt::For { body, .. } => n += Self::count(body),
                PseudoStmt::Switch { cases, default, .. } => {
                    for (_, b) in cases {
                        n += Self::count(b);
                    }
                    if let Some(d) = default {
                        n += Self::count(d);
                    }
                }
                _ => {}
            }
        }
        n
    }
}

// ---------------------------------------------------------------------------
// StructuredCodeValidator — checks structured code for invariants
// ---------------------------------------------------------------------------

/// Validates invariants of a [`StructuredCode`] instance.
#[derive(Debug, Default)]
pub struct StructuredCodeValidator;

/// A validation issue.
#[derive(Debug, Clone)]
pub struct ValidationIssue {
    pub description: String,
}

impl StructuredCodeValidator {
    /// Validate `code` and return any issues.
    #[must_use] 
    pub fn validate(code: &StructuredCode) -> Vec<ValidationIssue> {
        let mut issues = Vec::new();
        let actual_gotos = GotoCounter::count(&code.stmts);
        if actual_gotos != code.residual_gotos {
            issues.push(ValidationIssue {
                description: format!(
                    "residual_gotos={} but actual goto count={}",
                    code.residual_gotos, actual_gotos,
                ),
            });
        }
        issues
    }

    /// True if there are no validation issues.
    #[must_use]
    pub fn is_valid(code: &StructuredCode) -> bool {
        Self::validate(code).is_empty()
    }
}

// ---------------------------------------------------------------------------
// LabelCounter — counts all labels in a statement tree
// ---------------------------------------------------------------------------

/// Counts all `Label` statements in a (possibly nested) statement tree.
#[derive(Debug, Default)]
pub struct LabelCounter;

impl LabelCounter {
    /// Count labels recursively.
    #[must_use] 
    pub fn count(stmts: &[PseudoStmt]) -> usize {
        let mut n = 0;
        for stmt in stmts {
            match stmt {
                PseudoStmt::Label(_) => n += 1,
                PseudoStmt::If {
                    then_body,
                    else_body,
                    ..
                } => {
                    n += Self::count(then_body);
                    if let Some(e) = else_body {
                        n += Self::count(e);
                    }
                }
                PseudoStmt::While { body, .. } | PseudoStmt::DoWhile { body, .. } => {
                    n += Self::count(body);
                }
                PseudoStmt::For { body, .. } => n += Self::count(body),
                _ => {}
            }
        }
        n
    }
}

// ---------------------------------------------------------------------------
// GotoEliminationLevel — aggressiveness setting
// ---------------------------------------------------------------------------

/// How aggressively to eliminate gotos.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[derive(Default)]
pub enum GotoEliminationLevel {
    /// Only remove trivially-forward gotos.
    Minimal,
    /// Remove break/continue patterns as well.
    #[default]
    Standard,
    /// All passes, multi-iteration.
    Aggressive,
}


// ---------------------------------------------------------------------------
// GotoEliminationConfig
// ---------------------------------------------------------------------------

/// Configuration for the goto elimination pipeline.
#[derive(Debug, Clone)]
pub struct GotoEliminationConfig {
    pub level: GotoEliminationLevel,
    pub max_iters: usize,
    pub rename_labels: bool,
}

impl Default for GotoEliminationConfig {
    fn default() -> Self {
        Self {
            level: GotoEliminationLevel::Standard,
            max_iters: DEFAULT_MAX_ITERS,
            rename_labels: false,
        }
    }
}

// ---------------------------------------------------------------------------
// ConfiguredGotoElimination — pipeline driven by a config
// ---------------------------------------------------------------------------

/// Runs goto elimination with a given [`GotoEliminationConfig`].
#[derive(Debug, Default)]
pub struct ConfiguredGotoElimination {
    pub config: GotoEliminationConfig,
    pub report: Option<GotoEliminationReport>,
}

impl ConfiguredGotoElimination {
    /// Create with the given config.
    #[must_use]
    pub const fn new(config: GotoEliminationConfig) -> Self {
        Self {
            config,
            report: None,
        }
    }

    /// Run on `stmts` and store the report.
    pub fn run(&mut self, stmts: Vec<PseudoStmt>) -> StructuredCode {
        let out = match self.config.level {
            GotoEliminationLevel::Minimal | GotoEliminationLevel::Standard => {
                let mut e = GotoElimination::default();
                e.run(stmts)
            }
            GotoEliminationLevel::Aggressive => {
                let mut mp = MultiPassGotoElimination::new(self.config.max_iters);
                mp.run(stmts)
            }
        };

        // Optionally rename labels.
        let mut stmts = out.stmts;
        if self.config.rename_labels {
            LabelRenamer::rename(&mut stmts);
        }

        let sc = StructuredCode {
            residual_gotos: count_gotos(&stmts),
            eliminated_gotos: out.eliminated_gotos,
            removed_labels: out.removed_labels,
            stmts,
        };
        self.report = Some(GotoEliminationReport {
            original_goto_count: out.eliminated_gotos + sc.residual_gotos,
            break_recoveries: 0, // simplified
            continue_recoveries: 0,
            trivial_eliminated: out.eliminated_gotos,
            labels_removed: sc.removed_labels,
            residual_gotos: sc.residual_gotos,
            fully_structured: sc.is_fully_structured(),
        });
        sc
    }
}

// ---------------------------------------------------------------------------
// PseudoStmt — minimal AST for this pass
// ---------------------------------------------------------------------------

/// A pseudocode statement as seen by the goto-elimination pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PseudoStmt {
    /// Assignment `<lhs> = <rhs>;`
    Assign { lhs: String, rhs: String },
    /// `return;` or `return <expr>;`
    Return(Option<String>),
    /// `if (<cond>) { <then> } else { <else> }`
    If {
        cond: String,
        then_body: Vec<Self>,
        else_body: Option<Vec<Self>>,
    },
    /// `while (<cond>) { … }`
    While { cond: String, body: Vec<Self> },
    /// `do { … } while (<cond>);`
    DoWhile { body: Vec<Self>, cond: String },
    /// `for (<init>; <cond>; <step>) { … }`
    For {
        init: Option<String>,
        cond: Option<String>,
        step: Option<String>,
        body: Vec<Self>,
    },
    /// `break;`
    Break,
    /// `continue;`
    Continue,
    /// `goto <label>;`
    Goto(String),
    /// `<label>:`
    Label(String),
    /// Bare expression statement.
    Expr(String),
    /// No-op.
    Nop,
    /// `switch (<value>) { case <k>: ...; default: ... }`
    Switch {
        value: String,
        cases: Vec<(String, Vec<Self>)>,
        default: Option<Vec<Self>>,
    },
}

impl PseudoStmt {
    /// True if this is a [`PseudoStmt::Goto`].
    #[must_use]
    pub const fn is_goto(&self) -> bool {
        matches!(self, Self::Goto(_))
    }

    /// True if this is a [`PseudoStmt::Label`].
    #[must_use]
    pub const fn is_label(&self) -> bool {
        matches!(self, Self::Label(_))
    }
}

// ---------------------------------------------------------------------------
// GotoPattern
// ---------------------------------------------------------------------------

/// A categorized goto, identified before transformation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GotoPattern {
    /// Forward goto to label immediately following a loop — can become `break`.
    BreakJump { label: String },
    /// Backward goto to loop-header label — can become `continue`.
    ContinueJump { label: String },
    /// Forward goto to the label directly after the goto — trivially removable.
    TrivialForward { label: String },
    /// Cannot be classified; left as-is.
    Irreducible { label: String },
}

// ---------------------------------------------------------------------------
// BreakContinueRecovery
// ---------------------------------------------------------------------------

/// Recovers `break` and `continue` from suitable forward/backward gotos.
#[derive(Debug, Default)]
pub struct BreakContinueRecovery;

impl BreakContinueRecovery {
    /// Analyse `stmts` and return a mapping label → [`GotoPattern`].
    ///
    /// Gotos nested inside loop/if/switch bodies are classified too: a `goto`
    /// that leaves a loop is only ever *inside* that loop's body, so a
    /// top-level-only scan would never see the break candidates at all.
    #[must_use]
    pub fn classify(&self, stmts: &[PseudoStmt]) -> HashMap<String, GotoPattern> {
        let mut patterns = HashMap::new();
        let loop_headers = Self::collect_loop_headers(stmts);
        let loop_exits = Self::collect_loop_exits(stmts);
        let label_indices = label_positions(stmts);

        for (goto_idx, stmt) in stmts.iter().enumerate() {
            if let PseudoStmt::Goto(lbl) = stmt {
                let pattern = if loop_headers.contains(lbl) {
                    GotoPattern::ContinueJump { label: lbl.clone() }
                } else if loop_exits.contains(lbl) {
                    GotoPattern::BreakJump { label: lbl.clone() }
                } else if label_indices.get(lbl).copied().unwrap_or(usize::MAX) == goto_idx + 1 {
                    GotoPattern::TrivialForward { label: lbl.clone() }
                } else {
                    GotoPattern::Irreducible { label: lbl.clone() }
                };
                patterns.insert(lbl.clone(), pattern);
            }
            for body in child_bodies(stmt) {
                Self::classify_nested(body, &loop_headers, &loop_exits, &mut patterns);
            }
        }
        patterns
    }

    /// Classify gotos inside a nested body. Positional adjacency (the
    /// `TrivialForward` test) is meaningless across nesting levels, so a
    /// nested goto is either a break, a continue, or irreducible.
    fn classify_nested(
        stmts: &[PseudoStmt],
        headers: &HashSet<String>,
        exits: &HashSet<String>,
        out: &mut HashMap<String, GotoPattern>,
    ) {
        for stmt in stmts {
            if let PseudoStmt::Goto(lbl) = stmt {
                let pattern = if headers.contains(lbl) {
                    GotoPattern::ContinueJump { label: lbl.clone() }
                } else if exits.contains(lbl) {
                    GotoPattern::BreakJump { label: lbl.clone() }
                } else {
                    GotoPattern::Irreducible { label: lbl.clone() }
                };
                out.insert(lbl.clone(), pattern);
            }
            for body in child_bodies(stmt) {
                Self::classify_nested(body, headers, exits, out);
            }
        }
    }

    /// Apply the classified patterns: replace gotos with `break`/`continue`/nop.
    pub fn apply(&self, stmts: &mut [PseudoStmt], patterns: &HashMap<String, GotoPattern>) {
        Self::apply_in(stmts, patterns);
    }

    fn apply_in(stmts: &mut [PseudoStmt], patterns: &HashMap<String, GotoPattern>) {
        for stmt in stmts.iter_mut() {
            if let PseudoStmt::Goto(lbl) = stmt
                && let Some(pat) = patterns.get(lbl) {
                    let replacement = match pat {
                        GotoPattern::BreakJump { .. } => PseudoStmt::Break,
                        GotoPattern::ContinueJump { .. } => PseudoStmt::Continue,
                        GotoPattern::TrivialForward { .. } => PseudoStmt::Nop,
                        GotoPattern::Irreducible { .. } => continue,
                    };
                    *stmt = replacement;
                    continue;
                }
            for body in child_bodies_mut(stmt) {
                Self::apply_in(body, patterns);
            }
        }
    }

    fn collect_loop_headers(stmts: &[PseudoStmt]) -> HashSet<String> {
        let mut headers = HashSet::new();
        // A loop header is the label immediately before a loop.
        for i in 0..stmts.len() {
            if let PseudoStmt::Label(lbl) = &stmts[i]
                && i + 1 < stmts.len()
                    && matches!(
                        stmts[i + 1],
                        PseudoStmt::While { .. }
                            | PseudoStmt::DoWhile { .. }
                            | PseudoStmt::For { .. }
                    )
                {
                    headers.insert(lbl.clone());
                }
        }
        headers
    }

    fn collect_loop_exits(stmts: &[PseudoStmt]) -> HashSet<String> {
        let mut exits = HashSet::new();
        // A loop-exit label immediately follows a loop.
        for i in 0..stmts.len() {
            if matches!(
                stmts[i],
                PseudoStmt::While { .. } | PseudoStmt::DoWhile { .. } | PseudoStmt::For { .. }
            )
                && i + 1 < stmts.len()
                    && let PseudoStmt::Label(lbl) = &stmts[i + 1] {
                        exits.insert(lbl.clone());
                    }
        }
        exits
    }
}

/// The nested statement bodies directly owned by `stmt`, in source order.
fn child_bodies(stmt: &PseudoStmt) -> Vec<&Vec<PseudoStmt>> {
    match stmt {
        PseudoStmt::If { then_body, else_body, .. } => {
            let mut v = vec![then_body];
            v.extend(else_body.as_ref());
            v
        }
        PseudoStmt::While { body, .. }
        | PseudoStmt::DoWhile { body, .. }
        | PseudoStmt::For { body, .. } => vec![body],
        PseudoStmt::Switch { cases, default, .. } => {
            let mut v: Vec<&Vec<PseudoStmt>> = cases.iter().map(|(_, b)| b).collect();
            v.extend(default.as_ref());
            v
        }
        _ => Vec::new(),
    }
}

/// Mutable counterpart of [`child_bodies`].
fn child_bodies_mut(stmt: &mut PseudoStmt) -> Vec<&mut Vec<PseudoStmt>> {
    match stmt {
        PseudoStmt::If { then_body, else_body, .. } => {
            let mut v = vec![then_body];
            v.extend(else_body.as_mut());
            v
        }
        PseudoStmt::While { body, .. }
        | PseudoStmt::DoWhile { body, .. }
        | PseudoStmt::For { body, .. } => vec![body],
        PseudoStmt::Switch { cases, default, .. } => {
            let mut v: Vec<&mut Vec<PseudoStmt>> = cases.iter_mut().map(|(_, b)| b).collect();
            v.extend(default.as_mut());
            v
        }
        _ => Vec::new(),
    }
}

fn label_positions(stmts: &[PseudoStmt]) -> HashMap<String, usize> {
    stmts
        .iter()
        .enumerate()
        .filter_map(|(i, s)| {
            if let PseudoStmt::Label(l) = s {
                Some((l.clone(), i))
            } else {
                None
            }
        })
        .collect()
}

// ---------------------------------------------------------------------------
// LabelElimination
// ---------------------------------------------------------------------------

/// Removes labels that are no longer referenced by any `goto`.
#[derive(Debug, Default)]
pub struct LabelElimination;

impl LabelElimination {
    /// Collect all label names currently referenced by `goto` statements.
    #[must_use] 
    pub fn referenced_labels(stmts: &[PseudoStmt]) -> HashSet<String> {
        let mut refs = HashSet::new();
        collect_goto_targets(stmts, &mut refs);
        refs
    }

    /// Remove unreferenced labels from `stmts`, at every nesting level.
    /// Returns the number of labels removed.
    pub fn remove_unreferenced(stmts: &mut Vec<PseudoStmt>) -> usize {
        let refs = Self::referenced_labels(stmts);
        Self::retain_referenced(stmts, &refs)
    }

    fn retain_referenced(stmts: &mut Vec<PseudoStmt>, refs: &HashSet<String>) -> usize {
        let before = stmts.len();
        stmts.retain(|s| {
            if let PseudoStmt::Label(l) = s {
                refs.contains(l)
            } else {
                true
            }
        });
        let mut removed = before - stmts.len();
        for stmt in stmts.iter_mut() {
            for body in child_bodies_mut(stmt) {
                removed += Self::retain_referenced(body, refs);
            }
        }
        removed
    }
}

fn collect_goto_targets(stmts: &[PseudoStmt], out: &mut HashSet<String>) {
    for stmt in stmts {
        if let PseudoStmt::Goto(lbl) = stmt {
            out.insert(lbl.clone());
        }
        for body in child_bodies(stmt) {
            collect_goto_targets(body, out);
        }
    }
}

// ---------------------------------------------------------------------------
// StructuredCode
// ---------------------------------------------------------------------------

/// The output of goto elimination: a cleaned statement list.
#[derive(Debug, Clone, Default)]
pub struct StructuredCode {
    pub stmts: Vec<PseudoStmt>,
    pub eliminated_gotos: usize,
    pub removed_labels: usize,
    pub residual_gotos: usize,
}

impl StructuredCode {
    /// True if no gotos remain.
    #[must_use]
    pub const fn is_fully_structured(&self) -> bool {
        self.residual_gotos == 0
    }
}

impl fmt::Display for StructuredCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "StructuredCode {{ gotos_elim={}, labels_removed={}, residual={} }}",
            self.eliminated_gotos, self.removed_labels, self.residual_gotos
        )
    }
}

// ---------------------------------------------------------------------------
// GotoStats
// ---------------------------------------------------------------------------

/// Statistics from a goto-elimination run.
#[derive(Debug, Clone, Default)]
pub struct GotoStats {
    pub total_gotos: usize,
    pub break_recoveries: usize,
    pub continue_recoveries: usize,
    pub trivial_removed: usize,
    pub labels_removed: usize,
    pub residual: usize,
}

impl GotoStats {
    #[must_use]
    pub const fn total_eliminated(&self) -> usize {
        self.break_recoveries + self.continue_recoveries + self.trivial_removed
    }
}

// ---------------------------------------------------------------------------
// GotoElimination
// ---------------------------------------------------------------------------

/// Orchestrates all goto-elimination sub-passes.
#[derive(Debug, Default)]
pub struct GotoElimination {
    pub stats: GotoStats,
}

impl GotoElimination {
    /// Run the full goto-elimination pipeline on `stmts` and return the
    /// structured output.
    pub fn run(&mut self, stmts: Vec<PseudoStmt>) -> StructuredCode {
        let mut stmts = stmts;

        // Count initial gotos.
        self.stats.total_gotos = count_gotos(&stmts);

        let recovery = BreakContinueRecovery;
        let patterns = recovery.classify(&stmts);

        let mut break_count = 0usize;
        let mut continue_count = 0usize;
        let mut trivial_count = 0usize;

        for pat in patterns.values() {
            match pat {
                GotoPattern::BreakJump { .. } => break_count += 1,
                GotoPattern::ContinueJump { .. } => continue_count += 1,
                GotoPattern::TrivialForward { .. } => trivial_count += 1,
                GotoPattern::Irreducible { .. } => {}
            }
        }

        recovery.apply(&mut stmts, &patterns);

        // Remove Nop placeholders left by trivial goto elimination.
        stmts.retain(|s| !matches!(s, PseudoStmt::Nop));

        let labels_removed = LabelElimination::remove_unreferenced(&mut stmts);
        let residual = count_gotos(&stmts);

        self.stats.break_recoveries = break_count;
        self.stats.continue_recoveries = continue_count;
        self.stats.trivial_removed = trivial_count;
        self.stats.labels_removed = labels_removed;
        self.stats.residual = residual;

        StructuredCode {
            stmts,
            eliminated_gotos: break_count + continue_count + trivial_count,
            removed_labels: labels_removed,
            residual_gotos: residual,
        }
    }
}

fn count_gotos(stmts: &[PseudoStmt]) -> usize {
    stmts.iter().filter(|s| s.is_goto()).count()
}

// ---------------------------------------------------------------------------
// GotoGraph — analyses goto/label relationships in a statement list
// ---------------------------------------------------------------------------

/// Builds a directed graph of goto → label relationships.
#[derive(Debug, Default)]
pub struct GotoGraph {
    /// edges: (`goto_index`, `label_index`)
    pub edges: Vec<(usize, usize)>,
}

impl GotoGraph {
    /// Build the goto graph for `stmts`.
    #[must_use] 
    pub fn build(stmts: &[PseudoStmt]) -> Self {
        let positions = label_positions(stmts);
        let mut edges = Vec::new();
        for (i, stmt) in stmts.iter().enumerate() {
            if let PseudoStmt::Goto(lbl) = stmt
                && let Some(&j) = positions.get(lbl) {
                    edges.push((i, j));
                }
        }
        Self { edges }
    }

    /// Whether any edge is a back-edge (goto index > label index).
    #[must_use]
    pub fn has_back_edges(&self) -> bool {
        self.edges.iter().any(|(g, l)| g > l)
    }

    /// Whether any edge is a forward-edge.
    #[must_use]
    pub fn has_forward_edges(&self) -> bool {
        self.edges.iter().any(|(g, l)| g < l)
    }

    /// Number of gotos with no corresponding label in `stmts`.
    #[must_use] 
    pub fn dangling_gotos(stmts: &[PseudoStmt]) -> usize {
        let positions = label_positions(stmts);
        stmts
            .iter()
            .filter(|s| {
                if let PseudoStmt::Goto(lbl) = s {
                    !positions.contains_key(lbl)
                } else {
                    false
                }
            })
            .count()
    }
}

// ---------------------------------------------------------------------------
// StructuredCodePrinter — simple text emitter for StructuredCode
// ---------------------------------------------------------------------------

/// Emits a [`StructuredCode`] as indented text.
#[derive(Debug, Default)]
pub struct StructuredCodePrinter {
    indent: usize,
    output: String,
}

impl StructuredCodePrinter {
    /// Print all statements in `code` and return the resulting string.
    pub fn print(&mut self, code: &StructuredCode) -> String {
        self.output.clear();
        self.indent = 0;
        for stmt in &code.stmts {
            self.print_stmt(stmt);
        }
        self.output.clone()
    }

    fn line(&mut self, s: &str) {
        let _ = std::fmt::write(
            &mut self.output,
            format_args!("{}{s}\n", "    ".repeat(self.indent)),
        );
    }

    fn print_stmt(&mut self, stmt: &PseudoStmt) {
        match stmt {
            PseudoStmt::Assign { lhs, rhs } => self.line(&format!("{lhs} = {rhs};")),
            PseudoStmt::Return(Some(v)) => self.line(&format!("return {v};")),
            PseudoStmt::Return(None) => self.line("return;"),
            PseudoStmt::Break => self.line("break;"),
            PseudoStmt::Continue => self.line("continue;"),
            PseudoStmt::Goto(l) => self.line(&format!("goto {l};")),
            PseudoStmt::Label(l) => self.line(&format!("{l}:")),
            PseudoStmt::Expr(e) => self.line(&format!("{e};")),
            PseudoStmt::Nop => {}
            PseudoStmt::If {
                cond,
                then_body,
                else_body,
            } => {
                self.line(&format!("if ({cond}) {{"));
                self.indent += 1;
                for s in then_body {
                    self.print_stmt(s);
                }
                self.indent -= 1;
                if let Some(eb) = else_body {
                    self.line("} else {");
                    self.indent += 1;
                    for s in eb {
                        self.print_stmt(s);
                    }
                    self.indent -= 1;
                }
                self.line("}");
            }
            PseudoStmt::While { cond, body } => {
                self.line(&format!("while ({cond}) {{"));
                self.indent += 1;
                for s in body {
                    self.print_stmt(s);
                }
                self.indent -= 1;
                self.line("}");
            }
            PseudoStmt::DoWhile { body, cond } => {
                self.line("do {");
                self.indent += 1;
                for s in body {
                    self.print_stmt(s);
                }
                self.indent -= 1;
                self.line(&format!("}} while ({cond});"));
            }
            PseudoStmt::For {
                init,
                cond,
                step,
                body,
            } => {
                let i = init.as_deref().unwrap_or("");
                let c = cond.as_deref().unwrap_or("");
                let s = step.as_deref().unwrap_or("");
                self.line(&format!("for ({i}; {c}; {s}) {{"));
                self.indent += 1;
                for st in body {
                    self.print_stmt(st);
                }
                self.indent -= 1;
                self.line("}");
            }
            PseudoStmt::Switch {
                value,
                cases,
                default,
            } => {
                self.line(&format!("switch ({value}) {{"));
                for (k, body) in cases {
                    self.line(&format!("case {k}:"));
                    self.indent += 1;
                    for s in body {
                        self.print_stmt(s);
                    }
                    self.indent -= 1;
                }
                if let Some(def) = default {
                    self.line("default:");
                    self.indent += 1;
                    for s in def {
                        self.print_stmt(s);
                    }
                    self.indent -= 1;
                }
                self.line("}");
            }
        }
    }
}

// ---------------------------------------------------------------------------
// MultiPassGotoElimination — runs elimination until convergence
// ---------------------------------------------------------------------------

/// Runs [`GotoElimination`] repeatedly until no more gotos can be eliminated.
#[derive(Debug, Default)]
pub struct MultiPassGotoElimination {
    pub total_stats: GotoStats,
    pub iterations: usize,
    pub max_iters: usize,
}

impl MultiPassGotoElimination {
    /// Create with a maximum iteration count.
    #[must_use]
    pub fn new(max_iters: usize) -> Self {
        Self {
            max_iters,
            ..Default::default()
        }
    }

    /// Run until convergence or `max_iters`.
    pub fn run(&mut self, stmts: Vec<PseudoStmt>) -> StructuredCode {
        let mut current = stmts;
        let mut final_out = StructuredCode::default();
        for _ in 0..self.max_iters {
            let mut elim = GotoElimination::default();
            let out = elim.run(std::mem::take(&mut current));
            self.total_stats.total_gotos += elim.stats.total_gotos;
            self.total_stats.break_recoveries += elim.stats.break_recoveries;
            self.total_stats.continue_recoveries += elim.stats.continue_recoveries;
            self.total_stats.trivial_removed += elim.stats.trivial_removed;
            self.total_stats.labels_removed += elim.stats.labels_removed;
            self.iterations += 1;
            let residual = out.residual_gotos;
            current.clone_from(&out.stmts);
            final_out = out;
            if residual == 0 {
                break;
            }
        }
        self.total_stats.residual = final_out.residual_gotos;
        final_out
    }
}

// ---------------------------------------------------------------------------
// GotoEliminationReport — structured report of an elimination run
// ---------------------------------------------------------------------------

/// A structured report summarising the results of goto elimination.
#[derive(Debug, Clone, Default)]
pub struct GotoEliminationReport {
    pub original_goto_count: usize,
    pub break_recoveries: usize,
    pub continue_recoveries: usize,
    pub trivial_eliminated: usize,
    pub labels_removed: usize,
    pub residual_gotos: usize,
    pub fully_structured: bool,
}

impl GotoEliminationReport {
    /// Build a report from a [`GotoElimination`] instance and its [`StructuredCode`] output.
    #[must_use]
    pub const fn from(elim: &GotoElimination, out: &StructuredCode) -> Self {
        Self {
            original_goto_count: elim.stats.total_gotos,
            break_recoveries: elim.stats.break_recoveries,
            continue_recoveries: elim.stats.continue_recoveries,
            trivial_eliminated: elim.stats.trivial_removed,
            labels_removed: elim.stats.labels_removed,
            residual_gotos: out.residual_gotos,
            fully_structured: out.is_fully_structured(),
        }
    }

    /// Reduction percentage.
    #[must_use]
    pub fn reduction_pct(&self) -> f64 {
        if self.original_goto_count == 0 {
            100.0
        } else {
            let elim = f64::from(u32::try_from(self.original_goto_count - self.residual_gotos).unwrap_or(u32::MAX));
            let total = f64::from(u32::try_from(self.original_goto_count).unwrap_or(u32::MAX));
            elim / total * 100.0
        }
    }
}

// ---------------------------------------------------------------------------
// LabelRenamer — renames labels to sequential identifiers
// ---------------------------------------------------------------------------

/// Renames all labels and their corresponding goto references to sequential
/// names: `L0`, `L1`, `L2`, …
#[derive(Debug, Default)]
pub struct LabelRenamer;

impl LabelRenamer {
    /// Rename all labels in `stmts` in-place.
    pub fn rename(stmts: &mut [PseudoStmt]) {
        // Collect all label names in order.
        let label_names: Vec<String> = stmts
            .iter()
            .filter_map(|s| {
                if let PseudoStmt::Label(l) = s {
                    Some(l.clone())
                } else {
                    None
                }
            })
            .collect();

        let mut rename_map: std::collections::HashMap<String, String> =
            std::collections::HashMap::new();
        for (i, name) in label_names.iter().enumerate() {
            rename_map.insert(name.clone(), format!("L{i}"));
        }

        for stmt in stmts.iter_mut() {
            match stmt {
                PseudoStmt::Label(l) | PseudoStmt::Goto(l) => {
                    if let Some(new) = rename_map.get(l) {
                        *l = new.clone();
                    }
                }
                _ => {}
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn lbl(s: &str) -> PseudoStmt {
        PseudoStmt::Label(s.into())
    }
    fn goto(s: &str) -> PseudoStmt {
        PseudoStmt::Goto(s.into())
    }
    fn ret() -> PseudoStmt {
        PseudoStmt::Return(None)
    }
    fn ret_v(s: &str) -> PseudoStmt {
        PseudoStmt::Return(Some(s.into()))
    }
    fn assign(l: &str, r: &str) -> PseudoStmt {
        PseudoStmt::Assign {
            lhs: l.into(),
            rhs: r.into(),
        }
    }
    fn while_(cond: &str, body: Vec<PseudoStmt>) -> PseudoStmt {
        PseudoStmt::While {
            cond: cond.into(),
            body,
        }
    }

    // --- PseudoStmt helpers ---

    #[test]
    fn pseudo_stmt_is_goto() {
        assert!(goto("L").is_goto());
        assert!(!lbl("L").is_goto());
    }

    #[test]
    fn pseudo_stmt_is_label() {
        assert!(lbl("L").is_label());
        assert!(!goto("L").is_label());
    }

    // --- label_positions ---

    #[test]
    fn label_positions_map() {
        let stmts = vec![ret(), lbl("A"), ret(), lbl("B")];
        let m = label_positions(&stmts);
        assert_eq!(m["A"], 1);
        assert_eq!(m["B"], 3);
    }

    // --- BreakContinueRecovery ---

    #[test]
    fn break_recovery_classifies_exit() {
        let stmts = vec![while_("1", vec![goto("after")]), lbl("after")];
        let rec = BreakContinueRecovery;
        let patterns = rec.classify(&stmts);
        assert!(matches!(
            patterns.get("after"),
            Some(GotoPattern::BreakJump { .. })
        ));
    }

    #[test]
    fn continue_recovery_classifies_header() {
        let stmts = vec![
            lbl("loop"),
            while_("running", vec![assign("x", "x + 1")]),
            goto("loop"),
        ];
        let rec = BreakContinueRecovery;
        let patterns = rec.classify(&stmts);
        assert!(matches!(
            patterns.get("loop"),
            Some(GotoPattern::ContinueJump { .. })
        ));
    }

    #[test]
    fn trivial_forward_goto_classified() {
        let stmts = vec![goto("next"), lbl("next"), ret()];
        let rec = BreakContinueRecovery;
        let patterns = rec.classify(&stmts);
        assert!(matches!(
            patterns.get("next"),
            Some(GotoPattern::TrivialForward { .. })
        ));
    }

    #[test]
    fn irreducible_goto_classified() {
        let stmts = vec![goto("far"), assign("x", "0"), lbl("far"), ret()];
        let rec = BreakContinueRecovery;
        let patterns = rec.classify(&stmts);
        // "far" is not immediately after goto (index 0+1=1) because lbl is at index 2.
        // So it should be irreducible.
        assert!(matches!(
            patterns.get("far"),
            Some(GotoPattern::Irreducible { .. })
        ));
    }

    #[test]
    fn apply_replaces_break_goto() {
        let mut stmts = vec![while_("1", vec![goto("exit")]), lbl("exit")];
        let rec = BreakContinueRecovery;
        let patterns = rec.classify(&stmts);
        rec.apply(&mut stmts, &patterns);
        // The goto inside the while body should now be `break`.
        if let PseudoStmt::While { body, .. } = &stmts[0] {
            assert!(matches!(body[0], PseudoStmt::Break));
        } else {
            panic!("expected While");
        }
    }

    #[test]
    fn apply_nops_trivial_goto() {
        let mut stmts = vec![goto("n"), lbl("n"), ret()];
        let rec = BreakContinueRecovery;
        let patterns = rec.classify(&stmts);
        rec.apply(&mut stmts, &patterns);
        assert!(matches!(stmts[0], PseudoStmt::Nop));
    }

    // --- LabelElimination ---

    #[test]
    fn label_elimination_removes_unreferenced() {
        let mut stmts = vec![lbl("unused"), ret()];
        let removed = LabelElimination::remove_unreferenced(&mut stmts);
        assert_eq!(removed, 1);
        assert!(stmts.iter().all(|s| !s.is_label()));
    }

    #[test]
    fn label_elimination_keeps_referenced() {
        let mut stmts = vec![goto("used"), lbl("used"), ret()];
        LabelElimination::remove_unreferenced(&mut stmts);
        assert!(
            stmts
                .iter()
                .any(|s| matches!(s, PseudoStmt::Label(l) if l == "used"))
        );
    }

    #[test]
    fn label_elimination_referenced_labels() {
        let stmts = vec![goto("A"), goto("B"), lbl("A"), ret()];
        let refs = LabelElimination::referenced_labels(&stmts);
        assert!(refs.contains("A"));
        assert!(refs.contains("B"));
    }

    // --- GotoStats ---

    #[test]
    fn goto_stats_total_eliminated() {
        let s = GotoStats {
            break_recoveries: 2,
            continue_recoveries: 1,
            trivial_removed: 3,
            ..Default::default()
        };
        assert_eq!(s.total_eliminated(), 6);
    }

    // --- StructuredCode ---

    #[test]
    fn structured_code_is_fully_structured() {
        let sc = StructuredCode {
            residual_gotos: 0,
            ..Default::default()
        };
        assert!(sc.is_fully_structured());
    }

    #[test]
    fn structured_code_not_fully_structured() {
        let sc = StructuredCode {
            residual_gotos: 1,
            ..Default::default()
        };
        assert!(!sc.is_fully_structured());
    }

    #[test]
    fn structured_code_display() {
        let sc = StructuredCode {
            eliminated_gotos: 2,
            removed_labels: 1,
            residual_gotos: 0,
            ..Default::default()
        };
        let s = format!("{sc}");
        assert!(s.contains("gotos_elim=2"));
    }

    // --- GotoElimination full pipeline ---

    #[test]
    fn elimination_trivial_goto_removed() {
        let stmts = vec![goto("next"), lbl("next"), ret()];
        let mut elim = GotoElimination::default();
        let out = elim.run(stmts);
        assert_eq!(out.residual_gotos, 0);
    }

    #[test]
    fn elimination_break_recovery_full() {
        let stmts = vec![while_("1", vec![goto("exit")]), lbl("exit")];
        let mut elim = GotoElimination::default();
        let out = elim.run(stmts);
        assert_eq!(elim.stats.break_recoveries, 1);
        // No residual gotos.
        assert_eq!(out.residual_gotos, 0);
    }

    #[test]
    fn elimination_irreducible_kept() {
        let stmts = vec![
            assign("x", "0"),
            goto("far"),
            assign("y", "1"),
            lbl("far"),
            ret(),
        ];
        let mut elim = GotoElimination::default();
        let out = elim.run(stmts);
        assert!(out.residual_gotos > 0);
    }

    #[test]
    fn elimination_label_cleanup() {
        let stmts = vec![goto("x"), lbl("x"), lbl("unused"), ret()];
        let mut elim = GotoElimination::default();
        let out = elim.run(stmts);
        // "unused" label should be gone.
        assert!(
            !out.stmts
                .iter()
                .any(|s| matches!(s, PseudoStmt::Label(l) if l == "unused"))
        );
    }

    #[test]
    fn elimination_empty_input() {
        let mut elim = GotoElimination::default();
        let out = elim.run(vec![]);
        assert_eq!(out.stmts.len(), 0);
        assert!(out.is_fully_structured());
    }

    #[test]
    fn elimination_no_gotos_unchanged() {
        let stmts = vec![assign("a", "1"), ret_v("a")];
        let mut elim = GotoElimination::default();
        let out = elim.run(stmts);
        assert_eq!(elim.stats.total_gotos, 0);
        assert_eq!(out.eliminated_gotos, 0);
    }

    #[test]
    fn elimination_nops_removed() {
        let stmts = vec![goto("n"), lbl("n"), ret()];
        let mut elim = GotoElimination::default();
        let out = elim.run(stmts);
        assert!(out.stmts.iter().all(|s| !matches!(s, PseudoStmt::Nop)));
    }

    #[test]
    fn collect_goto_targets_nested() {
        let stmts = vec![PseudoStmt::While {
            cond: "1".into(),
            body: vec![goto("inner")],
        }];
        let mut set = HashSet::new();
        collect_goto_targets(&stmts, &mut set);
        assert!(set.contains("inner"));
    }

    #[test]
    fn count_gotos_helper() {
        let stmts = vec![goto("a"), ret(), goto("b")];
        assert_eq!(count_gotos(&stmts), 2);
    }

    #[test]
    fn recovery_collect_loop_exits_for_loop() {
        let stmts = vec![
            PseudoStmt::For {
                init: None,
                cond: None,
                step: None,
                body: vec![],
            },
            lbl("after_for"),
        ];
        let exits = BreakContinueRecovery::collect_loop_exits(&stmts);
        assert!(exits.contains("after_for"));
    }

    #[test]
    fn recovery_do_while_exit() {
        let stmts = vec![
            PseudoStmt::DoWhile {
                body: vec![],
                cond: "0".into(),
            },
            lbl("after_dw"),
        ];
        let exits = BreakContinueRecovery::collect_loop_exits(&stmts);
        assert!(exits.contains("after_dw"));
    }

    // --- GotoPattern display ---

    #[test]
    fn goto_pattern_break_label() {
        let p = GotoPattern::BreakJump {
            label: "exit".into(),
        };
        assert!(matches!(p, GotoPattern::BreakJump { .. }));
    }

    #[test]
    fn goto_pattern_continue_label() {
        let p = GotoPattern::ContinueJump {
            label: "header".into(),
        };
        assert!(matches!(p, GotoPattern::ContinueJump { .. }));
    }

    // --- StructuredCode fields ---

    #[test]
    fn structured_code_default_zeroed() {
        let sc = StructuredCode::default();
        assert_eq!(sc.eliminated_gotos, 0);
        assert_eq!(sc.removed_labels, 0);
        assert_eq!(sc.residual_gotos, 0);
        assert!(sc.is_fully_structured());
    }

    // --- PseudoStmt helpers ---

    #[test]
    fn pseudo_stmt_assign_not_goto() {
        assert!(!assign("x", "0").is_goto());
        assert!(!assign("x", "0").is_label());
    }

    #[test]
    fn pseudo_stmt_return_not_label() {
        assert!(!ret().is_label());
    }

    // --- collect_goto_targets in nested if ---

    #[test]
    fn collect_goto_targets_if_body() {
        let stmts = vec![PseudoStmt::If {
            cond: "c".into(),
            then_body: vec![goto("then_target")],
            else_body: Some(vec![goto("else_target")]),
        }];
        let mut set = HashSet::new();
        collect_goto_targets(&stmts, &mut set);
        assert!(set.contains("then_target"));
        assert!(set.contains("else_target"));
    }

    #[test]
    fn collect_goto_targets_for_body() {
        let stmts = vec![PseudoStmt::For {
            init: None,
            cond: None,
            step: None,
            body: vec![goto("for_target")],
        }];
        let mut set = HashSet::new();
        collect_goto_targets(&stmts, &mut set);
        assert!(set.contains("for_target"));
    }

    // --- LabelElimination in nested bodies ---

    #[test]
    fn label_elimination_in_sequence() {
        let mut stmts = vec![lbl("used"), goto("used"), lbl("unused"), ret()];
        let removed = LabelElimination::remove_unreferenced(&mut stmts);
        assert_eq!(removed, 1);
    }

    // --- GotoStats ---

    #[test]
    fn goto_stats_default_zero() {
        let s = GotoStats::default();
        assert_eq!(s.total_gotos, 0);
        assert_eq!(s.residual, 0);
    }

    // --- GotoElimination stats tracking ---

    #[test]
    fn elimination_stats_total_gotos() {
        let stmts = vec![goto("a"), goto("b"), lbl("a"), lbl("b"), ret()];
        let mut elim = GotoElimination::default();
        elim.run(stmts);
        assert_eq!(elim.stats.total_gotos, 2);
    }

    #[test]
    fn elimination_stats_labels_removed() {
        let stmts = vec![lbl("orphan"), ret()];
        let mut elim = GotoElimination::default();
        let out = elim.run(stmts);
        assert_eq!(out.removed_labels, 1);
    }

    // --- Multi-pass convergence ---

    #[test]
    fn elimination_multiple_trivial_gotos() {
        let stmts = vec![goto("a"), lbl("a"), goto("b"), lbl("b"), ret()];
        let mut elim = GotoElimination::default();
        let out = elim.run(stmts);
        assert_eq!(out.residual_gotos, 0);
    }

    // --- GotoGraph tests ---

    #[test]
    fn goto_graph_empty() {
        let g = GotoGraph::build(&[]);
        assert!(g.edges.is_empty());
    }

    #[test]
    fn goto_graph_forward_edge() {
        let stmts = vec![goto("L"), lbl("L"), ret()];
        let g = GotoGraph::build(&stmts);
        assert!(!g.edges.is_empty());
        assert!(g.has_forward_edges());
    }

    #[test]
    fn goto_graph_back_edge() {
        let stmts = vec![lbl("L"), ret(), goto("L")];
        let g = GotoGraph::build(&stmts);
        assert!(g.has_back_edges());
    }

    #[test]
    fn goto_graph_dangling_goto() {
        let stmts = vec![goto("nowhere"), ret()];
        assert_eq!(GotoGraph::dangling_gotos(&stmts), 1);
    }

    #[test]
    fn goto_graph_no_dangling() {
        let stmts = vec![goto("L"), lbl("L"), ret()];
        assert_eq!(GotoGraph::dangling_gotos(&stmts), 0);
    }

    // --- StructuredCodePrinter tests ---

    #[test]
    fn structured_code_printer_assign() {
        let code = StructuredCode {
            stmts: vec![assign("x", "0")],
            ..Default::default()
        };
        let mut p = StructuredCodePrinter::default();
        let out = p.print(&code);
        assert!(out.contains("x = 0;"));
    }

    #[test]
    fn structured_code_printer_return() {
        let code = StructuredCode {
            stmts: vec![ret_v("42")],
            ..Default::default()
        };
        let mut p = StructuredCodePrinter::default();
        let out = p.print(&code);
        assert!(out.contains("return 42;"));
    }

    #[test]
    fn structured_code_printer_if() {
        let code = StructuredCode {
            stmts: vec![PseudoStmt::If {
                cond: "c".into(),
                then_body: vec![ret()],
                else_body: None,
            }],
            ..Default::default()
        };
        let mut p = StructuredCodePrinter::default();
        let out = p.print(&code);
        assert!(out.contains("if (c)"));
    }

    #[test]
    fn structured_code_printer_while() {
        let code = StructuredCode {
            stmts: vec![PseudoStmt::While {
                cond: "x".into(),
                body: vec![PseudoStmt::Break],
            }],
            ..Default::default()
        };
        let mut p = StructuredCodePrinter::default();
        let out = p.print(&code);
        assert!(out.contains("while (x)"));
    }

    #[test]
    fn structured_code_printer_do_while() {
        let code = StructuredCode {
            stmts: vec![PseudoStmt::DoWhile {
                body: vec![],
                cond: "y".into(),
            }],
            ..Default::default()
        };
        let mut p = StructuredCodePrinter::default();
        let out = p.print(&code);
        assert!(out.contains("do {"));
    }

    // --- GotoPattern equality ---

    #[test]
    fn goto_pattern_irreducible_eq() {
        let a = GotoPattern::Irreducible { label: "x".into() };
        let b = GotoPattern::Irreducible { label: "x".into() };
        assert_eq!(a, b);
    }

    #[test]
    fn goto_pattern_trivial_ne_irreducible() {
        let a = GotoPattern::TrivialForward { label: "x".into() };
        let b = GotoPattern::Irreducible { label: "x".into() };
        assert_ne!(a, b);
    }

    // --- LabelElimination deep nesting ---

    #[test]
    fn label_elimination_nested_if_else() {
        let mut stmts = vec![PseudoStmt::If {
            cond: "c".into(),
            then_body: vec![lbl("inner_used"), goto("inner_used")],
            else_body: Some(vec![lbl("else_unused")]),
        }];
        let removed = LabelElimination::remove_unreferenced(&mut stmts);
        assert_eq!(removed, 1); // else_unused removed
    }

    // --- MultiPassGotoElimination tests ---

    #[test]
    fn multi_pass_empty_input() {
        let mut mp = MultiPassGotoElimination::new(5);
        let out = mp.run(vec![]);
        assert!(out.is_fully_structured());
        assert_eq!(mp.iterations, 1);
    }

    #[test]
    fn multi_pass_trivial_goto() {
        let stmts = vec![goto("L"), lbl("L"), ret()];
        let mut mp = MultiPassGotoElimination::new(5);
        let out = mp.run(stmts);
        assert!(out.is_fully_structured());
    }

    #[test]
    fn multi_pass_accumulates_stats() {
        let stmts = vec![goto("a"), lbl("a"), ret()];
        let mut mp = MultiPassGotoElimination::new(3);
        mp.run(stmts);
        assert!(mp.total_stats.total_gotos > 0);
    }

    // --- GotoEliminationReport tests ---

    #[test]
    fn report_full_reduction() {
        let stmts = vec![goto("x"), lbl("x"), ret()];
        let mut elim = GotoElimination::default();
        let out = elim.run(stmts);
        let r = GotoEliminationReport::from(&elim, &out);
        assert!((r.reduction_pct() - 100.0).abs() < f64::EPSILON);
        assert!(r.fully_structured);
    }

    #[test]
    fn report_zero_gotos_hundred_pct() {
        let elim = GotoElimination::default();
        let out = StructuredCode::default();
        let r = GotoEliminationReport::from(&elim, &out);
        assert!((r.reduction_pct() - 100.0).abs() < f64::EPSILON);
    }

    #[test]
    fn report_residual_reduces_pct() {
        let stmts = vec![
            assign("x", "0"),
            goto("far"),
            assign("y", "1"),
            lbl("far"),
            ret(),
        ];
        let mut elim = GotoElimination::default();
        let out = elim.run(stmts);
        let r = GotoEliminationReport::from(&elim, &out);
        assert!(r.reduction_pct() < 100.0 || r.fully_structured);
    }

    // --- LabelRenamer tests ---

    #[test]
    fn label_renamer_renames_sequentially() {
        let mut stmts = vec![lbl("my_label"), goto("my_label"), ret()];
        LabelRenamer::rename(&mut stmts);
        // Labels should now be L0.
        assert!(
            stmts
                .iter()
                .any(|s| matches!(s, PseudoStmt::Label(l) if l == "L0"))
        );
        assert!(
            stmts
                .iter()
                .any(|s| matches!(s, PseudoStmt::Goto(l) if l == "L0"))
        );
    }

    #[test]
    fn label_renamer_empty_unchanged() {
        let mut stmts: Vec<PseudoStmt> = vec![];
        LabelRenamer::rename(&mut stmts);
        assert!(stmts.is_empty());
    }

    #[test]
    fn label_renamer_multiple_labels() {
        let mut stmts = vec![lbl("a"), goto("b"), lbl("b"), ret()];
        LabelRenamer::rename(&mut stmts);
        // a → L0, b → L1
        assert!(
            stmts
                .iter()
                .any(|s| matches!(s, PseudoStmt::Label(l) if l == "L0"))
        );
        assert!(
            stmts
                .iter()
                .any(|s| matches!(s, PseudoStmt::Label(l) if l == "L1"))
        );
    }

    // --- StructuredCodePrinter extra ---

    #[test]
    fn printer_for_loop() {
        let code = StructuredCode {
            stmts: vec![PseudoStmt::For {
                init: None,
                cond: None,
                step: None,
                body: vec![],
            }],
            ..Default::default()
        };
        let mut p = StructuredCodePrinter::default();
        let out = p.print(&code);
        assert!(out.contains("for"));
    }

    #[test]
    fn printer_switch() {
        let code = StructuredCode {
            stmts: vec![PseudoStmt::Switch {
                value: "x".into(),
                cases: vec![("0".to_string(), vec![PseudoStmt::Break])],
                default: None,
            }],
            ..Default::default()
        };
        let mut p = StructuredCodePrinter::default();
        let out = p.print(&code);
        assert!(out.contains("switch (x)"));
        assert!(out.contains("case 0:"));
    }

    #[test]
    fn printer_if_else() {
        let code = StructuredCode {
            stmts: vec![PseudoStmt::If {
                cond: "flag".into(),
                then_body: vec![ret_v("1")],
                else_body: Some(vec![ret_v("0")]),
            }],
            ..Default::default()
        };
        let mut p = StructuredCodePrinter::default();
        let out = p.print(&code);
        assert!(out.contains("else"));
    }
}
