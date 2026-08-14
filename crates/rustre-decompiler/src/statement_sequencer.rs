//! Statement sequencer — orders, deduplicates, and structures a flat list of
//! HLIL statements into a coherent sequence suitable for pseudo-C emission.
//!
//! The sequencer resolves phi-node copies, merges consecutive assignments to
//! the same variable, detects compound expressions, and groups statements into
//! logical blocks.

use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;

// ─────────────────────────────────────────────────────────────────────────────
// Statement
// ─────────────────────────────────────────────────────────────────────────────

/// A single statement at the HLIL / pseudo-C level.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Statement {
    /// `lhs = rhs;`
    Assign { lhs: String, rhs: String },
    /// `*ptr = value;`
    Store { ptr: String, value: String },
    /// `lhs = *ptr;`
    Load { lhs: String, ptr: String },
    /// `func(args);`
    Call { func: String, args: Vec<String>, ret: Option<String> },
    /// `return value;`
    Return(Option<String>),
    /// `if (cond) goto label;`
    ConditionalBranch { cond: String, target: String },
    /// `goto label;`
    Goto(String),
    /// `: label`
    Label(String),
    /// A phi assignment: `var = phi(var#0, var#1, …)`.
    Phi { dest: String, sources: Vec<String> },
    /// No operation.
    Nop,
    /// Raw pseudo-C line (fallback for unrecognised patterns).
    Raw(String),
    /// A block comment.
    Comment(String),
}

impl Statement {
    /// Return `true` if this statement can be safely removed.
    #[must_use]
    pub const fn is_nop(&self) -> bool {
        matches!(self, Self::Nop)
    }

    /// Return `true` if this statement has side effects.
    #[must_use]
    pub const fn has_side_effects(&self) -> bool {
        matches!(
            self,
            Self::Store { .. }
                | Self::Call { .. }
                | Self::Return(_)
                | Self::ConditionalBranch { .. }
                | Self::Goto(_)
        )
    }

    /// Return the destination variable name if this is an assignment-like statement.
    #[must_use]
    pub const fn dest_var(&self) -> Option<&str> {
        match self {
            Self::Assign { lhs, .. } | Self::Load { lhs, .. } | Self::Phi { dest: lhs, .. } => {
                Some(lhs.as_str())
            }
            Self::Call { ret: Some(r), .. } => Some(r.as_str()),
            _ => None,
        }
    }

    /// Collect all variable names read by this statement (rhs uses).
    #[must_use]
    pub fn used_vars(&self) -> Vec<&str> {
        match self {
            Self::Assign { rhs, .. } => extract_idents(rhs),
            Self::Store { ptr, value } => {
                let mut v = extract_idents(ptr);
                v.extend(extract_idents(value));
                v
            }
            Self::Load { ptr, .. } => extract_idents(ptr),
            Self::Call { args, .. } => args.iter().flat_map(|a| extract_idents(a)).collect(),
            Self::Return(Some(v)) => extract_idents(v),
            Self::ConditionalBranch { cond, .. } => extract_idents(cond),
            Self::Phi { sources, .. } => sources.iter().flat_map(|s| extract_idents(s)).collect(),
            _ => Vec::new(),
        }
    }
}

fn extract_idents(s: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut start: Option<usize> = None;
    for (i, c) in s.char_indices() {
        if c.is_ascii_alphanumeric() || c == '_' {
            if start.is_none() {
                start = Some(i);
            }
        } else if let Some(s_) = start.take() {
            let tok = &s[s_..i];
            if !tok.chars().next().is_some_and(|c| c.is_ascii_digit()) {
                out.push(tok);
            }
        }
    }
    if let Some(s_) = start {
        let tok = &s[s_..];
        if !tok.chars().next().is_some_and(|c| c.is_ascii_digit()) {
            out.push(tok);
        }
    }
    out
}

impl fmt::Display for Statement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Assign { lhs, rhs } => write!(f, "{lhs} = {rhs};"),
            Self::Store { ptr, value } => write!(f, "*{ptr} = {value};"),
            Self::Load { lhs, ptr } => write!(f, "{lhs} = *{ptr};"),
            Self::Call { func, args, ret } => {
                let arg_str = args.join(", ");
                if let Some(r) = ret {
                    write!(f, "{r} = {func}({arg_str});")
                } else {
                    write!(f, "{func}({arg_str});")
                }
            }
            Self::Return(Some(v)) => write!(f, "return {v};"),
            Self::Return(None) => write!(f, "return;"),
            Self::ConditionalBranch { cond, target } => {
                write!(f, "if ({cond}) goto {target};")
            }
            Self::Goto(label) => write!(f, "goto {label};"),
            Self::Label(name) => write!(f, "{name}:"),
            Self::Phi { dest, sources } => {
                write!(f, "{dest} = phi({});", sources.join(", "))
            }
            Self::Nop => write!(f, "/* nop */"),
            Self::Raw(s) => write!(f, "{s}"),
            Self::Comment(s) => write!(f, "/* {s} */"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SequenceResult
// ─────────────────────────────────────────────────────────────────────────────

/// The result of sequencing a block of statements.
#[derive(Debug, Clone, Default)]
pub struct SequenceResult {
    /// The ordered, cleaned statement list.
    pub statements: Vec<Statement>,
    /// Number of statements removed by deduplication.
    pub removed_nops: usize,
    /// Number of phi nodes resolved.
    pub phi_resolved: usize,
    /// Number of consecutive assignments merged.
    pub merged_assignments: usize,
    /// Number of dead assignments eliminated.
    pub dead_eliminated: usize,
    /// Diagnostics produced during sequencing.
    pub diagnostics: Vec<String>,
}

impl SequenceResult {
    /// Return the sequenced pseudo-C code as a single string.
    #[must_use]
    pub fn to_pseudocode(&self, indent: usize) -> String {
        let pad = "  ".repeat(indent);
        self.statements
            .iter()
            .map(|s| format!("{pad}{s}"))
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Return `true` if there are no statements.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.statements.is_empty()
    }

    /// Return the number of statements.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.statements.len()
    }
}

impl fmt::Display for SequenceResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for s in &self.statements {
            writeln!(f, "  {s}")?;
        }
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// StatementSequencer
// ─────────────────────────────────────────────────────────────────────────────

/// Pass-enable flags for the statement sequencer.
#[derive(Debug, Clone)]
pub struct SequencerPassFlags {
    /// Remove NOP statements.
    pub remove_nops: bool,
    /// Resolve phi nodes into simple copy assignments.
    pub resolve_phi: bool,
    /// Eliminate dead assignments (def with no subsequent use).
    pub eliminate_dead: bool,
}

impl Default for SequencerPassFlags {
    fn default() -> Self {
        Self { remove_nops: true, resolve_phi: true, eliminate_dead: true }
    }
}

/// Options controlling sequencer behaviour.
#[derive(Debug, Clone)]
pub struct SequencerOptions {
    /// Flags for enabling individual sequencer passes.
    pub pass_flags: SequencerPassFlags,
    /// Merge consecutive assignments to the same variable.
    pub merge_consecutive: bool,
    /// Inline single-use temporaries into the consuming expression.
    pub inline_temps: bool,
    /// Maximum depth for constant folding.
    pub constant_fold_depth: usize,
    /// Emit comments describing eliminated / merged statements.
    pub emit_comments: bool,
}

impl Default for SequencerOptions {
    fn default() -> Self {
        Self {
            pass_flags: SequencerPassFlags::default(),
            merge_consecutive: false,
            inline_temps: true,
            constant_fold_depth: 2,
            emit_comments: false,
        }
    }
}

/// The statement sequencer — transforms and orders a flat statement list.
#[derive(Debug)]
pub struct StatementSequencer {
    options: SequencerOptions,
}

impl StatementSequencer {
    /// Create a new sequencer with default options.
    #[must_use]
    pub fn new() -> Self {
        Self { options: SequencerOptions::default() }
    }

    /// Create a sequencer with custom options.
    #[must_use]
    pub const fn with_options(options: SequencerOptions) -> Self {
        Self { options }
    }

    /// Return a reference to the current options.
    #[must_use]
    pub const fn options(&self) -> &SequencerOptions {
        &self.options
    }

    /// Sequence the given statements and return a [`SequenceResult`].
    #[must_use] 
    pub fn sequence(&self, stmts: Vec<Statement>) -> SequenceResult {
        let mut result = SequenceResult::default();
        let mut current = stmts;

        // Pass 1: remove NOPs.
        if self.options.pass_flags.remove_nops {
            let before = current.len();
            current.retain(|s| !s.is_nop());
            result.removed_nops = before - current.len();
        }

        // Pass 2: resolve phi nodes.
        if self.options.pass_flags.resolve_phi {
            let (resolved, count) = resolve_phi_nodes(current);
            current = resolved;
            result.phi_resolved = count;
        }

        // Pass 3: inline single-use temporaries.
        if self.options.inline_temps {
            current = inline_single_use_temps(current);
        }

        // Pass 4: constant fold simple expressions.
        if self.options.constant_fold_depth > 0 {
            current = constant_fold(current, self.options.constant_fold_depth);
        }

        // Pass 5: eliminate dead assignments.
        if self.options.pass_flags.eliminate_dead {
            let (elim, count) = eliminate_dead_assignments(current, self.options.emit_comments);
            current = elim;
            result.dead_eliminated = count;
        }

        // Pass 6: merge consecutive assignments.
        if self.options.merge_consecutive {
            let (merged, count) = merge_consecutive_assigns(current);
            current = merged;
            result.merged_assignments = count;
        }

        result.statements = current;
        result
    }
}

impl Default for StatementSequencer {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// sequence_block — public convenience function
// ─────────────────────────────────────────────────────────────────────────────

/// Convenience wrapper: sequence `stmts` with default options.
#[must_use]
pub fn sequence_block(stmts: Vec<Statement>) -> SequenceResult {
    StatementSequencer::new().sequence(stmts)
}

/// Sequence statements from multiple basic blocks in execution order.
///
/// Each entry is `(block_id, stmts)`. Blocks are drained in the order they
/// appear in `blocks`, but a [`VecDeque`] is used internally so callers may
/// extend the queue while sequencing (e.g. when CFS produces extra blocks on
/// the fly). The resulting [`SequenceResult`] aggregates per-block counts.
#[must_use]
pub fn sequence_blocks(blocks: Vec<(u32, Vec<Statement>)>) -> SequenceResult {
    let mut queue: VecDeque<(u32, Vec<Statement>)> = blocks.into();
    let mut agg = SequenceResult::default();
    let sequencer = StatementSequencer::new();
    while let Some((_bid, stmts)) = queue.pop_front() {
        let r = sequencer.sequence(stmts);
        agg.removed_nops += r.removed_nops;
        agg.phi_resolved += r.phi_resolved;
        agg.dead_eliminated += r.dead_eliminated;
        agg.merged_assignments += r.merged_assignments;
        agg.statements.extend(r.statements);
    }
    agg
}

// ─────────────────────────────────────────────────────────────────────────────
// Pass implementations
// ─────────────────────────────────────────────────────────────────────────────

/// Resolve phi nodes: for each phi(a, b, …) where all sources are the same
/// register family, emit `dest = first_source;`. Otherwise emit a comment.
fn resolve_phi_nodes(stmts: Vec<Statement>) -> (Vec<Statement>, usize) {
    let mut out = Vec::with_capacity(stmts.len());
    let mut count = 0;
    for stmt in stmts {
        if let Statement::Phi { dest, sources } = stmt {
            count += 1;
            if sources.len() == 1 || sources.iter().all(|s| s == &sources[0]) {
                out.push(Statement::Assign { lhs: dest, rhs: sources.into_iter().next().unwrap() });
            } else {
                // Emit a copy from the first source with a comment.
                let comment = format!("phi join: {}", sources.join(", "));
                let rhs = sources.into_iter().next().unwrap_or_default();
                out.push(Statement::Comment(comment));
                out.push(Statement::Assign { lhs: dest, rhs });
            }
        } else {
            out.push(stmt);
        }
    }
    (out, count)
}

/// Inline single-use temporaries: if a temp `t0` is defined once and used
/// exactly once in the immediately following statement, substitute its rhs
/// directly.
fn inline_single_use_temps(stmts: Vec<Statement>) -> Vec<Statement> {
    // Build def-count and use-count maps.
    let mut def_count: HashMap<String, usize> = HashMap::new();
    let mut use_count: HashMap<String, usize> = HashMap::new();
    let mut def_value: HashMap<String, String> = HashMap::new();

    for stmt in &stmts {
        if let Some(dest) = stmt.dest_var() {
            *def_count.entry(dest.to_string()).or_insert(0) += 1;
            if let Statement::Assign { rhs, .. } = stmt {
                def_value.insert(dest.to_string(), rhs.clone());
            }
        }
        for used in stmt.used_vars() {
            *use_count.entry(used.to_string()).or_insert(0) += 1;
        }
    }

    // Temporaries eligible for inlining: defined once, used once, starts with 't'.
    let inline_set: HashSet<String> = def_count
        .iter()
        .filter(|(k, v)| {
            let v = **v;
            v == 1
                && use_count.get(k.as_str()).copied().unwrap_or(0) == 1
                && (k.starts_with('t') || k.starts_with("tmp"))
        })
        .map(|(k, _)| k.clone())
        .collect();

    if inline_set.is_empty() {
        return stmts;
    }

    // Two-pass: first collect values, then inline.
    let mut out: Vec<Statement> = Vec::with_capacity(stmts.len());
    let mut skip: HashSet<usize> = HashSet::new();

    for (i, stmt) in stmts.iter().enumerate() {
        if skip.contains(&i) {
            continue;
        }
        // Skip definition statements for inlined temps.
        if let Some(dest) = stmt.dest_var()
            && inline_set.contains(dest) {
                skip.insert(i);
                continue;
            }
        // Substitute inlined temps in the current statement.
        let mut new_stmt = stmt.clone();
        for var in &inline_set {
            if let Some(val) = def_value.get(var) {
                new_stmt = substitute_var_in_stmt(new_stmt, var, val);
            }
        }
        out.push(new_stmt);
    }

    out
}

fn substitute_var_in_stmt(stmt: Statement, var: &str, value: &str) -> Statement {
    let subst = |s: String| -> String {
        // Word-boundary substitution.
        let mut out = String::new();
        let mut rest = s.as_str();
        while let Some(pos) = rest.find(var) {
            let before_ok = pos == 0 || {
                let b = rest.as_bytes()[pos - 1];
                !b.is_ascii_alphanumeric() && b != b'_'
            };
            let after = pos + var.len();
            let after_ok = after >= rest.len() || {
                let b = rest.as_bytes()[after];
                !b.is_ascii_alphanumeric() && b != b'_'
            };
            if before_ok && after_ok {
                out.push_str(&rest[..pos]);
                out.push_str(value);
            } else {
                out.push_str(&rest[..after]);
            }
            rest = &rest[after.min(rest.len())..];
        }
        out.push_str(rest);
        out
    };

    match stmt {
        Statement::Assign { lhs, rhs } => Statement::Assign { lhs, rhs: subst(rhs) },
        Statement::Store { ptr, value: v } => Statement::Store { ptr: subst(ptr), value: subst(v) },
        Statement::Load { lhs, ptr } => Statement::Load { lhs, ptr: subst(ptr) },
        Statement::Call { func, args, ret } => Statement::Call {
            func,
            args: args.into_iter().map(subst).collect(),
            ret,
        },
        Statement::Return(Some(v)) => Statement::Return(Some(subst(v))),
        Statement::ConditionalBranch { cond, target } => Statement::ConditionalBranch {
            cond: subst(cond),
            target,
        },
        other => other,
    }
}

/// Constant fold: replace numeric expressions like `0 + x` or `x * 1`.
fn constant_fold(stmts: Vec<Statement>, _depth: usize) -> Vec<Statement> {
    stmts.into_iter().map(fold_stmt).collect()
}

fn fold_stmt(stmt: Statement) -> Statement {
    match stmt {
        Statement::Assign { lhs, rhs } => Statement::Assign { lhs, rhs: fold_expr(rhs) },
        Statement::Store { ptr, value } => Statement::Store { ptr, value: fold_expr(value) },
        Statement::Return(Some(v)) => Statement::Return(Some(fold_expr(v))),
        other => other,
    }
}

fn fold_expr(expr: String) -> String {
    // Simple patterns only.
    let trimmed = expr.trim();
    // x + 0 → x
    if let Some(rest) = trimmed.strip_suffix("+ 0").or_else(|| trimmed.strip_suffix("+ 0x0")) {
        return rest.trim().to_string();
    }
    // 0 + x → x
    if let Some(rest) = trimmed.strip_prefix("0 + ").or_else(|| trimmed.strip_prefix("0x0 + ")) {
        return rest.to_string();
    }
    // x * 1 → x
    if let Some(rest) = trimmed.strip_suffix("* 1").or_else(|| trimmed.strip_suffix("* 0x1")) {
        return rest.trim().to_string();
    }
    // x ^ x → 0 (same operand both sides)
    if let Some(idx) = trimmed.find(" ^ ") {
        let lhs = trimmed[..idx].trim();
        let rhs = trimmed[idx + 3..].trim();
        if lhs == rhs {
            return "0".to_string();
        }
    }
    expr
}

/// Eliminate dead assignments: remove assignments whose dest is never used
/// after the assignment (within the block), unless they have side effects.
fn eliminate_dead_assignments(
    stmts: Vec<Statement>,
    emit_comments: bool,
) -> (Vec<Statement>, usize) {
    // Build a live-out set by scanning backwards.
    let n = stmts.len();
    let mut live: HashSet<String> = HashSet::new();
    let mut dead_indices: HashSet<usize> = HashSet::new();

    // If the block has no terminator / side-effecting statement, treat every
    // assignment as live: the block continues into another block that may
    // observe its definitions. Without a sink to anchor liveness, eliminating
    // here would drop assignments that callers still need.
    let has_terminator = stmts.iter().any(Statement::has_side_effects);
    if !has_terminator {
        return (stmts, 0);
    }

    // Always consider variables used in control-flow / returns live.
    for stmt in &stmts {
        if stmt.has_side_effects() {
            for v in stmt.used_vars() {
                live.insert(v.to_string());
            }
        }
    }

    // Backwards scan implementing `live_in = use ∪ (live_out \ def)`.
    //
    // The KILL must be applied before the GEN. Computing
    // `(live_out ∪ use) \ def` instead is a silent miscompilation for every
    // statement that both reads and writes the same variable (`acc = acc + 1`
    // — any accumulator or induction variable): the statement's own use is
    // killed by its own def, the variable looks dead on entry, and the earlier
    // initialising store is deleted, leaving a read of uninitialised memory.
    for i in (0..n).rev() {
        let stmt = &stmts[i];

        // KILL first — decide deadness against live_out (the live set as it
        // stands BEFORE this statement's own uses are added), then remove the
        // def, so a self-read is regenerated by the GEN step below.
        let mut is_dead = false;
        if let Some(dest) = stmt.dest_var() {
            if !live.contains(dest) && !stmt.has_side_effects() {
                is_dead = true;
                dead_indices.insert(i);
            } else {
                live.remove(dest);
            }
        }

        // GEN — a statement we just proved dead will be removed, so its uses
        // must not keep earlier definitions alive.
        if !is_dead {
            for v in stmt.used_vars() {
                live.insert(v.to_string());
            }
        }
    }

    let count = dead_indices.len();
    let out = stmts
        .into_iter()
        .enumerate()
        .flat_map(|(i, stmt)| {
            if dead_indices.contains(&i) {
                if emit_comments {
                    vec![Statement::Comment(format!("dead: {stmt}"))]
                } else {
                    vec![]
                }
            } else {
                vec![stmt]
            }
        })
        .collect();

    (out, count)
}

/// Merge consecutive assignments to the same variable:
/// `x = a; x = b;` → `x = b;` (only safe when `a` is a pure expression not used elsewhere).
fn merge_consecutive_assigns(stmts: Vec<Statement>) -> (Vec<Statement>, usize) {
    let mut out: Vec<Statement> = Vec::with_capacity(stmts.len());
    let mut count = 0;

    for stmt in stmts {
        if let Statement::Assign { lhs: ref new_lhs, .. } = stmt
            && let Some(Statement::Assign { lhs: prev_lhs, .. }) = out.last()
                && prev_lhs == new_lhs {
                    // Safe to replace only if prev rhs is not referenced elsewhere.
                    out.pop();
                    count += 1;
                }
        out.push(stmt);
    }

    (out, count)
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remove_nops() {
        let stmts = vec![
            Statement::Nop,
            Statement::Assign { lhs: "x".into(), rhs: "1".into() },
            Statement::Nop,
        ];
        let result = sequence_block(stmts);
        assert_eq!(result.removed_nops, 2);
        assert_eq!(result.statements.len(), 1);
    }

    #[test]
    fn phi_single_source() {
        let stmts = vec![Statement::Phi {
            dest: "x".into(),
            sources: vec!["a".into()],
        }];
        let result = sequence_block(stmts);
        assert_eq!(result.phi_resolved, 1);
        assert!(matches!(&result.statements[0], Statement::Assign { lhs, rhs } if lhs == "x" && rhs == "a"));
    }

    #[test]
    fn constant_fold_add_zero() {
        let stmts = vec![Statement::Assign {
            lhs: "y".into(),
            rhs: "x + 0".into(),
        }];
        let opts = SequencerOptions {
            pass_flags: SequencerPassFlags { remove_nops: false, resolve_phi: false, eliminate_dead: false },
            merge_consecutive: false,
            inline_temps: false,
            constant_fold_depth: 1,
            emit_comments: false,
        };
        let seq = StatementSequencer::with_options(opts);
        let result = seq.sequence(stmts);
        assert!(matches!(&result.statements[0], Statement::Assign { rhs, .. } if rhs == "x"));
    }

    #[test]
    fn dead_assignment_eliminated() {
        let stmts = vec![
            Statement::Assign { lhs: "dead".into(), rhs: "42".into() },
            Statement::Return(None),
        ];
        let result = sequence_block(stmts);
        assert_eq!(result.dead_eliminated, 1);
        assert_eq!(result.statements.len(), 1);
    }

    /// Backward liveness must be `live_in = use ∪ (live_out \ def)`, i.e. the
    /// def is killed BEFORE the statement's own uses are generated. With the
    /// wrong order (`(live_out ∪ use) \ def`) an accumulator's self-read is
    /// killed by its own write, so the initialising store `acc = 0` looks dead
    /// and is deleted — leaving `acc = acc + 1` reading uninitialised memory.
    #[test]
    fn self_referencing_accumulator_keeps_its_initialiser() {
        let stmts = vec![
            Statement::Assign { lhs: "acc".into(), rhs: "0".into() },
            Statement::Assign { lhs: "acc".into(), rhs: "acc + 1".into() },
            Statement::Return(Some("acc".into())),
        ];
        let result = sequence_block(stmts);
        assert_eq!(result.dead_eliminated, 0, "nothing here is dead: {:?}", result.statements);
        assert!(
            result.statements.iter().any(
                |s| matches!(s, Statement::Assign { lhs, rhs } if lhs == "acc" && rhs == "0")
            ),
            "initialiser `acc = 0` was wrongly eliminated: {:?}",
            result.statements
        );
    }

    /// The induction-variable form of the same bug: `i = i + 1` inside a loop
    /// body must not kill the live-in of `i` and delete `i = 0`.
    #[test]
    fn induction_variable_initialiser_survives() {
        let stmts = vec![
            Statement::Assign { lhs: "i".into(), rhs: "0".into() },
            Statement::Label("L".into()),
            Statement::Assign { lhs: "i".into(), rhs: "i + 1".into() },
            Statement::ConditionalBranch { cond: "i < 10".into(), target: "L".into() },
            Statement::Return(None),
        ];
        let result = sequence_block(stmts);
        assert!(
            result.statements.iter().any(
                |s| matches!(s, Statement::Assign { lhs, rhs } if lhs == "i" && rhs == "0")
            ),
            "`i = 0` was wrongly eliminated: {:?}",
            result.statements
        );
    }

    /// A genuinely dead self-referencing statement is still removed, and once
    /// removed its uses must not keep the earlier def alive.
    #[test]
    fn dead_self_referencing_chain_fully_eliminated() {
        let stmts = vec![
            Statement::Assign { lhs: "acc".into(), rhs: "0".into() },
            Statement::Assign { lhs: "acc".into(), rhs: "acc + 1".into() },
            Statement::Return(None),
        ];
        let result = sequence_block(stmts);
        assert_eq!(result.dead_eliminated, 2, "{:?}", result.statements);
    }

    #[test]
    fn to_pseudocode() {
        let result = SequenceResult {
            statements: vec![
                Statement::Assign { lhs: "x".into(), rhs: "1".into() },
                Statement::Return(Some("x".into())),
            ],
            ..Default::default()
        };
        let code = result.to_pseudocode(1);
        assert!(code.contains("x = 1;"));
        assert!(code.contains("return x;"));
    }

    #[test]
    fn statement_display() {
        let s = Statement::Call {
            func: "malloc".into(),
            args: vec!["16".into()],
            ret: Some("ptr".into()),
        };
        assert_eq!(s.to_string(), "ptr = malloc(16);");
    }
}
