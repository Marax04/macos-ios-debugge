//! Retroactive Print — Pernosco-style annotation-driven trace replay.
//!
//! The user annotates an address X with a format string and a list of
//! expression arguments (register names or memory derefs such as `*rsp`,
//! `rax+8`).  [`crate::live_script_context::retro_print`] walks the [`crate::omniscient_query::OmniscientIndex`] for every write
//! to X, evaluates each argument against the historical execution context
//! supplied by a [`crate::time_travel_debug::SnapshotReplayBackend`], and returns a
//! [`Vec<RetroPrintEntry>`] — one row per write — ordered most-recent-first.
//! The target process is never re-run.
//!
//! # Expression mini-language
//!
//! Supported expression atoms (subset of `expression_evaluator` grammar):
//! - Register names: `rax`, `rsp`, `rbp`, … (no `$` prefix required here)
//! - `$rax` — `$`-prefixed register names also accepted
//! - `*<reg>` — 8-byte little-endian read at the address stored in `<reg>`
//! - `<reg>+<offset>` — register + decimal/hex offset (for pointer arithmetic)
//! - `*(<reg>+<offset>)` — 8-byte deref of pointer + offset
//! - `<integer>` — literal u64 (decimal or `0x`-hex)
//!
//! Unknown registers and unmapped memory produce [`EvalResult::Err`].
//!
//! # Example
//! ```rust
//! use rustre_debug::retroactive_print::{retro_print, RetroAnnotation};
//! use rustre_debug::omniscient_query::{OmniscientIndex, MemoryWrite};
//! use rustre_debug::time_travel_debug::{SnapshotReplayBackend, TtdState, TracePosition};
//! use rustre_debug::ThreadId;
//! use rustre_core::address::Address;
//!
//! let mut idx = OmniscientIndex::new();
//! let mut replay = SnapshotReplayBackend::new();
//!
//! // Record one write to 0x1000 at sequence 5 from PC 0x401000.
//! idx.push(MemoryWrite {
//!     sequence: 5,
//!     address: Address::new(0x1000),
//!     size: 8,
//!     tid: ThreadId(1),
//!     writer_pc: Some(Address::new(0x401000)),
//!     source_address: None,
//! });
//! // Provide the historical state at that position.
//! let mut st = TtdState::new(TracePosition::new(5, 0), 0x401000, 0x7000);
//! st.regs.insert("rax".into(), 0x42);
//! replay.record(st);
//!
//! let ann = RetroAnnotation {
//!     address: 0x1000,
//!     format: "rax = {0}".into(),
//!     args: vec!["rax".into()],
//! };
//! let entries = retro_print(&idx, &replay, &ann, u64::MAX);
//! assert_eq!(entries.len(), 1);
//! assert!(entries[0].rendered.contains("0x42"));
//! ```

use std::collections::BTreeMap;

use rustre_core::address::Address;
use serde::{Deserialize, Serialize};

use crate::omniscient_query::{OmniscientIndex, MemoryWrite};
use crate::time_travel_debug::{SnapshotReplayBackend, TracePosition};

// ─────────────────────────────────────────────────────────────────────────────
// Public types
// ─────────────────────────────────────────────────────────────────────────────

/// A Pernosco-style retroactive print annotation.
///
/// The user attaches this to an address; every time the trace writes to that
/// address the format string is rendered with the evaluated arguments.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetroAnnotation {
    /// Memory address to watch for writes.
    pub address: u64,
    /// `printf`-style format string with `{0}`, `{1}`, … placeholders.
    pub format: String,
    /// Expressions to evaluate at each write (one per `{N}` placeholder).
    pub args: Vec<String>,
}

impl RetroAnnotation {
    /// Convenience constructor for the common single-expression case.
    #[must_use]
    pub fn simple(address: u64, expr: impl Into<String>) -> Self {
        let expr = expr.into();
        let format = format!("{{{}}}", 0);
        Self { address, format, args: vec![expr] }
    }
}

/// The result of evaluating a single expression in a historical context.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EvalResult {
    /// Successfully evaluated to a 64-bit integer.
    U64(u64),
    /// Raw bytes when the expression resolves to a memory slice.
    Bytes(Vec<u8>),
    /// Evaluation failed (unknown register, unmapped memory, parse error).
    Err(String),
}

impl EvalResult {
    #[must_use]
    pub fn as_display_string(&self) -> String {
        match self {
            Self::U64(v)   => format!("{v:#x}"),
            Self::Bytes(b) => b.iter().map(|x| format!("{x:02x}")).collect::<Vec<_>>().join(" "),
            Self::Err(e)   => format!("<error: {e}>"),
        }
    }
}

/// One entry in the retroactive print timeline — corresponds to one write to
/// the annotated address.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetroPrintEntry {
    /// Trace position of the write.
    pub position: TracePosition,
    /// PC of the instruction that performed the write, if known.
    pub writer_pc: Option<u64>,
    /// The write event itself (address, size, thread, …).
    pub write: MemoryWrite,
    /// Evaluated values for each expression in [`RetroAnnotation::args`].
    pub arg_values: Vec<EvalResult>,
    /// The rendered format string with `{N}` placeholders replaced.
    pub rendered: String,
}

// ─────────────────────────────────────────────────────────────────────────────
// HistoricalEvalContext — register + memory view at one trace position
// ─────────────────────────────────────────────────────────────────────────────

/// Read-only view of execution state at a historical trace position, combining
/// the register map from [`crate::time_travel_debug::SnapshotReplayBackend`] with the recorded memory
/// windows so expression evaluation can dereference pointers as of that moment.
pub struct HistoricalEvalContext<'a> {
    /// Register values at the position (from the recorded [`crate::time_travel_debug::TtdState`]).
    pub regs: &'a BTreeMap<String, u64>,
    /// PC at the position.
    pub pc: u64,
    /// SP at the position.
    pub sp: u64,
    /// Access to historical memory windows.
    replay: &'a SnapshotReplayBackend,
    /// The trace position, for memory look-ups.
    position: TracePosition,
}

impl<'a> HistoricalEvalContext<'a> {
    /// Read a register by name (case-insensitive).  Also accepts `pc`, `rip`,
    /// `sp`, `rsp` as aliases to the `pc`/`sp` fields when not in `regs`.
    #[must_use]
    pub fn read_reg(&self, name: &str) -> Option<u64> {
        let lower = name.trim_start_matches('$').to_ascii_lowercase();
        if let Some(&v) = self.regs.get(&lower) {
            return Some(v);
        }
        // canonical-register aliases
        match lower.as_str() {
            "pc" | "rip" | "eip" | "ip" => Some(self.pc),
            "sp" | "rsp" | "esp" => Some(self.sp),
            _ => None,
        }
    }

    /// Read 8 bytes (little-endian u64) from historical memory at `addr`.
    /// Returns `None` when the window is not recorded.
    #[must_use]
    pub fn read_u64_at(&self, addr: u64) -> Option<u64> {
        let bytes = self.replay.read_memory_at(self.position, addr, 8)?;
        let arr: [u8; 8] = bytes.try_into().ok()?;
        Some(u64::from_le_bytes(arr))
    }

    /// Read 4 bytes (little-endian u32) from historical memory at `addr`.
    #[must_use]
    pub fn read_u32_at(&self, addr: u64) -> Option<u32> {
        let bytes = self.replay.read_memory_at(self.position, addr, 4)?;
        let arr: [u8; 4] = bytes.try_into().ok()?;
        Some(u32::from_le_bytes(arr))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Expression evaluator (simple subset)
// ─────────────────────────────────────────────────────────────────────────────

/// Evaluate one expression string against a historical context.
///
/// Supported forms:
/// - `rax`, `$rax` — register read
/// - `*rax`, `*$rax` — 8-byte deref of register value
/// - `rax+8`, `rax+0x10` — register + offset (no deref)
/// - `*(rax+8)`, `*($rax+0x10)` — 8-byte deref of register + offset
/// - `0x1234`, `42` — integer literal
///
/// Nesting deeper than [`MAX_DEREF_DEPTH`] returns an error rather than
/// recursing: each leading `*` costs one stack frame, so an unbounded
/// expression string was a way to overflow the stack — which aborts the
/// process outright rather than raising a catchable panic.
#[must_use]
pub fn eval_expr(expr: &str, ctx: &HistoricalEvalContext<'_>) -> EvalResult {
    eval_expr_depth(expr, ctx, 0)
}

/// Maximum `*` deref nesting accepted by [`eval_expr`]. Real annotations
/// nest a handful of levels at most; the limit exists to bound recursion,
/// not to constrain legitimate expressions.
pub const MAX_DEREF_DEPTH: u32 = 32;

fn eval_expr_depth(expr: &str, ctx: &HistoricalEvalContext<'_>, depth: u32) -> EvalResult {
    let s = expr.trim();

    if depth > MAX_DEREF_DEPTH {
        return EvalResult::Err(format!(
            "expression nests deeper than the {MAX_DEREF_DEPTH}-level deref limit"
        ));
    }

    // Deref: `*(…)`
    if let Some(inner) = s.strip_prefix('*') {
        let inner = inner.trim();
        // `*(reg+offset)` or `*(reg)`
        let inner = if inner.starts_with('(') && inner.ends_with(')') {
            &inner[1..inner.len() - 1]
        } else {
            inner
        };
        let addr = match eval_expr_depth(inner, ctx, depth + 1) {
            EvalResult::U64(v) => v,
            other => return other,
        };
        return match ctx.read_u64_at(addr) {
            Some(v) => EvalResult::U64(v),
            None    => EvalResult::Err(format!("unmapped memory at {addr:#x}")),
        };
    }

    // `reg+offset` or `reg-offset`
    if let Some(pos) = find_addend_op(s) {
        let (reg_part, sign, off_part) = if s.as_bytes()[pos] == b'+' {
            (&s[..pos], 1i64, &s[pos + 1..])
        } else {
            (&s[..pos], -1i64, &s[pos + 1..])
        };
        let base = match ctx.read_reg(reg_part.trim()) {
            Some(v) => v,
            None    => return EvalResult::Err(format!("unknown register: {}", reg_part.trim())),
        };
        // `try_parse_literal` — the same parser used for a bare literal below —
        // reports a malformed number instead of turning it into 0. A silent 0
        // here would evaluate `reg+<garbage>` to the register itself and print a
        // plausible value for the wrong address.
        let Some(offset) = try_parse_literal(off_part.trim()) else {
            return EvalResult::Err(format!("invalid offset: {}", off_part.trim()));
        };
        let addr = (base as i64).wrapping_add(sign * offset as i64) as u64;
        return EvalResult::U64(addr);
    }

    // Integer literal
    if let Some(v) = try_parse_literal(s) {
        return EvalResult::U64(v);
    }

    // Plain register (possibly `$`-prefixed)
    match ctx.read_reg(s) {
        Some(v) => EvalResult::U64(v),
        None    => EvalResult::Err(format!("unknown register: {s}")),
    }
}

/// Find the index of the first `+` or `-` that separates `reg` from an
/// addend, skipping a leading `$` and the register name characters.
fn find_addend_op(s: &str) -> Option<usize> {
    let bytes = s.as_bytes();
    let start = if bytes.first() == Some(&b'$') { 1 } else { 0 };
    for (i, &b) in bytes[start..].iter().enumerate() {
        if (b == b'+' || b == b'-') && i + start > 0 {
            return Some(i + start);
        }
    }
    None
}

fn try_parse_literal(s: &str) -> Option<u64> {
    if s.starts_with("0x") || s.starts_with("0X") {
        let hex = &s[2..];
        u64::from_str_radix(hex, 16).ok()
    } else if s.chars().next().is_some_and(|c| c.is_ascii_digit()) {
        s.parse::<u64>().ok()
    } else {
        None
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Format string rendering
// ─────────────────────────────────────────────────────────────────────────────

/// Render a format string by substituting `{0}`, `{1}`, … placeholders with
/// the display representations of `values`.  Unrecognised placeholders are
/// left as-is.
#[must_use]
pub fn render_format(fmt: &str, values: &[EvalResult]) -> String {
    let mut out = fmt.to_owned();
    for (i, val) in values.iter().enumerate() {
        let placeholder = format!("{{{i}}}");
        out = out.replace(&placeholder, &val.as_display_string());
    }
    out
}

// ─────────────────────────────────────────────────────────────────────────────
// retro_print — core function
// ─────────────────────────────────────────────────────────────────────────────

/// Retroactive-print the annotated address over the trace.
///
/// Returns one [`RetroPrintEntry`] per write to `ann.address` at or before
/// sequence `before`, ordered **most-recent-first** (same order as
/// [`crate::omniscient_query::OmniscientIndex::who_wrote`]).
///
/// The `replay` backend supplies historical register and memory state.
/// When no [`crate::time_travel_debug::TtdState`] was recorded at the write's sequence, arg evaluation
/// falls back to returning [`EvalResult::Err`] for register reads.
#[must_use]
pub fn retro_print(
    index: &OmniscientIndex,
    replay: &SnapshotReplayBackend,
    ann: &RetroAnnotation,
    before: u64,
) -> Vec<RetroPrintEntry> {
    let address = Address::new(ann.address);
    let writes = index.who_wrote(address, before);

    let mut entries = Vec::with_capacity(writes.len());
    for write in writes {
        let pos = TracePosition::new(write.sequence, 0);
        // Try to get the recorded state at this position.
        let state_opt = replay.seek_immutable(pos);
        let entry = if let Some(ref state) = state_opt {
            let ctx = HistoricalEvalContext {
                regs:     &state.regs,
                pc:       state.pc,
                sp:       state.sp,
                replay,
                position: state.position,
            };
            let arg_values: Vec<EvalResult> =
                ann.args.iter().map(|expr| eval_expr(expr, &ctx)).collect();
            let rendered = render_format(&ann.format, &arg_values);
            RetroPrintEntry {
                position:  state.position,
                writer_pc: write.writer_pc.map(|a| a.as_u64()),
                write:     write.clone(),
                arg_values,
                rendered,
            }
        } else {
            // No historical state recorded — produce error entries.
            let arg_values: Vec<EvalResult> = ann.args.iter()
                .map(|_| EvalResult::Err("no historical state recorded at this position".into()))
                .collect();
            let rendered = render_format(&ann.format, &arg_values);
            RetroPrintEntry {
                position:  pos,
                writer_pc: write.writer_pc.map(|a| a.as_u64()),
                write:     write.clone(),
                arg_values,
                rendered,
            }
        };
        entries.push(entry);
    }
    entries
}

// ─────────────────────────────────────────────────────────────────────────────
// AnnotationStore — in-process annotation registry
// ─────────────────────────────────────────────────────────────────────────────

/// Monotonically increasing annotation identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct AnnotationId(pub u64);

/// An in-process store of active [`RetroAnnotation`]s, keyed by
/// [`AnnotationId`].  Each session holds one store; the MCP tools
/// `debug.retroactive_print_list` and `debug.retroactive_print_remove` operate
/// on it.
#[derive(Debug, Default)]
pub struct AnnotationStore {
    next_id: u64,
    entries: BTreeMap<u64, RetroAnnotation>,
}

impl AnnotationStore {
    /// Create an empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an annotation, returning its new [`AnnotationId`].
    pub fn insert(&mut self, ann: RetroAnnotation) -> AnnotationId {
        let id = self.next_id;
        self.next_id += 1;
        self.entries.insert(id, ann);
        AnnotationId(id)
    }

    /// Remove an annotation by ID.  Returns `true` if it was present.
    pub fn remove(&mut self, id: AnnotationId) -> bool {
        self.entries.remove(&id.0).is_some()
    }

    /// Iterate all (id, annotation) pairs.
    pub fn iter(&self) -> impl Iterator<Item = (AnnotationId, &RetroAnnotation)> {
        self.entries.iter().map(|(&k, v)| (AnnotationId(k), v))
    }

    /// Retrieve one annotation by ID.
    #[must_use]
    pub fn get(&self, id: AnnotationId) -> Option<&RetroAnnotation> {
        self.entries.get(&id.0)
    }

    /// Number of stored annotations.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// True when the store is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}


// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::omniscient_query::MemoryWrite;
    use crate::time_travel_debug::{SnapshotReplayBackend, TtdState, TracePosition};
    use crate::ThreadId;
    use rustre_core::address::Address;

    fn make_write(seq: u64, addr: u64, pc: u64) -> MemoryWrite {
        MemoryWrite {
            sequence: seq,
            address: Address::new(addr),
            size: 8,
            tid: ThreadId(1),
            writer_pc: Some(Address::new(pc)),
            source_address: None,
        }
    }

    fn make_state(seq: u64, pc: u64, sp: u64, rax: u64) -> TtdState {
        let mut st = TtdState::new(TracePosition::new(seq, 0), pc, sp);
        st.regs.insert("rax".into(), rax);
        st.regs.insert("rbx".into(), sp.wrapping_add(0x10));
        st
    }

    // ── retro_print basics ─────────────────────────────────────────────────

    #[test]
    fn retro_print_returns_one_entry_per_write() {
        let mut idx = OmniscientIndex::new();
        let mut replay = SnapshotReplayBackend::new();

        idx.push(make_write(5, 0x1000, 0x401000));
        idx.push(make_write(10, 0x1000, 0x401010));

        replay.record(make_state(5, 0x401000, 0x7000, 42));
        replay.record(make_state(10, 0x401010, 0x7000, 99));

        let ann = RetroAnnotation {
            address: 0x1000,
            format: "val={0}".into(),
            args: vec!["rax".into()],
        };
        let entries = retro_print(&idx, &replay, &ann, u64::MAX);
        assert_eq!(entries.len(), 2, "one entry per write");
        // Most-recent first.
        assert_eq!(entries[0].write.sequence, 10);
        assert_eq!(entries[1].write.sequence, 5);
    }

    #[test]
    fn retro_print_renders_register_correctly() {
        let mut idx = OmniscientIndex::new();
        let mut replay = SnapshotReplayBackend::new();

        idx.push(make_write(1, 0x2000, 0x401000));
        replay.record(make_state(1, 0x401000, 0x7000, 0xDEAD));

        let ann = RetroAnnotation {
            address: 0x2000,
            format: "rax={0}".into(),
            args: vec!["rax".into()],
        };
        let entries = retro_print(&idx, &replay, &ann, u64::MAX);
        assert_eq!(entries.len(), 1);
        assert!(entries[0].rendered.contains("0xdead"), "rendered: {}", entries[0].rendered);
    }

    #[test]
    fn retro_print_dollar_prefix_register() {
        let mut idx = OmniscientIndex::new();
        let mut replay = SnapshotReplayBackend::new();

        idx.push(make_write(3, 0x3000, 0x401000));
        replay.record(make_state(3, 0x401000, 0x7000, 7));

        let ann = RetroAnnotation {
            address: 0x3000,
            format: "{0}".into(),
            args: vec!["$rax".into()],
        };
        let entries = retro_print(&idx, &replay, &ann, u64::MAX);
        assert_eq!(entries[0].arg_values[0], EvalResult::U64(7));
    }

    #[test]
    fn retro_print_before_cutoff_respected() {
        let mut idx = OmniscientIndex::new();
        let mut replay = SnapshotReplayBackend::new();

        idx.push(make_write(1, 0x1000, 0x401000));
        idx.push(make_write(20, 0x1000, 0x401010));
        replay.record(make_state(1, 0x401000, 0x7000, 1));
        replay.record(make_state(20, 0x401010, 0x7000, 2));

        let ann = RetroAnnotation { address: 0x1000, format: "{0}".into(), args: vec!["rax".into()] };
        let entries = retro_print(&idx, &replay, &ann, 10 /* before seq 20 */);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].write.sequence, 1);
    }

    #[test]
    fn retro_print_no_historical_state_produces_err() {
        let mut idx = OmniscientIndex::new();
        let replay = SnapshotReplayBackend::new(); // empty — no states recorded

        idx.push(make_write(5, 0x1000, 0x401000));

        let ann = RetroAnnotation { address: 0x1000, format: "{0}".into(), args: vec!["rax".into()] };
        let entries = retro_print(&idx, &replay, &ann, u64::MAX);
        assert_eq!(entries.len(), 1);
        assert!(matches!(entries[0].arg_values[0], EvalResult::Err(_)));
    }

    // ── eval_expr ──────────────────────────────────────────────────────────

    fn make_ctx<'a>(
        replay: &'a SnapshotReplayBackend,
        regs: &'a std::collections::BTreeMap<String, u64>,
        pc: u64,
        sp: u64,
    ) -> HistoricalEvalContext<'a> {
        HistoricalEvalContext { regs, pc, sp, replay, position: TracePosition::new(0, 0) }
    }

    #[test]
    fn eval_register() {
        let replay = SnapshotReplayBackend::new();
        let mut regs = std::collections::BTreeMap::new();
        regs.insert("rax".into(), 100u64);
        let ctx = make_ctx(&replay, &regs, 0, 0);
        assert_eq!(eval_expr("rax", &ctx), EvalResult::U64(100));
        assert_eq!(eval_expr("$rax", &ctx), EvalResult::U64(100));
    }

    #[test]
    fn eval_register_plus_offset() {
        let replay = SnapshotReplayBackend::new();
        let mut regs = std::collections::BTreeMap::new();
        regs.insert("rsp".into(), 0x7000u64);
        let ctx = make_ctx(&replay, &regs, 0, 0x7000);
        assert_eq!(eval_expr("rsp+8", &ctx), EvalResult::U64(0x7008));
        assert_eq!(eval_expr("rsp+0x10", &ctx), EvalResult::U64(0x7010));
    }

    /// A malformed offset must be an error, not a silent `+0`.
    ///
    /// `parse_int` answered 0 for anything it could not parse, in BOTH its hex
    /// and decimal branches — while `try_parse_literal`, eight lines below in
    /// the same file, returns `Option` for exactly the same job. So a typo
    /// (`rsp+0xZZ`), a wrong prefix (`rsp+0b10`) or an overflowing offset
    /// silently became `rsp+0`: retroactive print then read a DIFFERENT address
    /// and displayed a perfectly plausible value for it. The user believes they
    /// are looking at `rsp+0x18` and is looking at `rsp`.
    ///
    /// The enclosing function already reports `EvalResult::Err` for an unknown
    /// register, so there was a correct channel for this all along.
    #[test]
    fn a_malformed_offset_is_an_error_not_a_silent_zero() {
        let replay = SnapshotReplayBackend::new();
        let regs = std::collections::BTreeMap::new();
        let ctx = make_ctx(&replay, &regs, 0, 0x7000);

        // Sanity: a well-formed offset still works, in both bases.
        assert_eq!(eval_expr("rsp+0x10", &ctx), EvalResult::U64(0x7010));
        assert_eq!(eval_expr("rsp+16", &ctx), EvalResult::U64(0x7010));

        for bad in ["rsp+0xZZ", "rsp+0b10", "rsp+", "rsp+99999999999999999999999", "rsp-0xQ"] {
            assert!(
                matches!(eval_expr(bad, &ctx), EvalResult::Err(_)),
                "{bad} must report an error rather than silently evaluating to the register itself"
            );
        }
    }

    #[test]
    fn eval_literal() {
        let replay = SnapshotReplayBackend::new();
        let regs = std::collections::BTreeMap::new();
        let ctx = make_ctx(&replay, &regs, 0, 0);
        assert_eq!(eval_expr("42", &ctx), EvalResult::U64(42));
        assert_eq!(eval_expr("0x1234", &ctx), EvalResult::U64(0x1234));
    }

    /// Each leading `*` in an annotation expression cost one stack frame,
    /// with no depth limit — so a user-supplied expression could overflow
    /// the stack. That is an ABORT, not a catchable panic: `catch_unwind`
    /// cannot contain it, so the whole debug process dies. Measured on the
    /// pre-fix logic: ~20_000 asterisks was enough (exit code 127), i.e. a
    /// 20 KB string through `debug.retroactive_print`.
    ///
    /// 200_000 here — ten times the measured crash threshold — so the test
    /// genuinely exercises the guard rather than sitting just under it.
    #[test]
    fn deeply_nested_deref_is_rejected_instead_of_overflowing_the_stack() {
        let regs = std::collections::BTreeMap::new();
        let replay = SnapshotReplayBackend::new();
        let ctx = make_ctx(&replay, &regs, 0x401000, 0x7fff_0000);

        let bomb = "*".repeat(200_000) + "rax";
        match eval_expr(&bomb, &ctx) {
            EvalResult::Err(msg) => {
                assert!(msg.contains("deref limit"), "unexpected error: {msg}");
            }
            other => panic!("expected a depth-limit error, got {other:?}"),
        }

        // The limit must not break ordinary nesting: a couple of levels
        // still evaluate normally (and fail only on the unknown register).
        if let EvalResult::Err(msg) = eval_expr("**rax", &ctx) {
            assert!(
                !msg.contains("deref limit"),
                "two levels must not hit the limit: {msg}"
            );
        }
    }

    #[test]
    fn eval_unknown_register_returns_err() {
        let replay = SnapshotReplayBackend::new();
        let regs = std::collections::BTreeMap::new();
        let ctx = make_ctx(&replay, &regs, 0, 0);
        assert!(matches!(eval_expr("r99", &ctx), EvalResult::Err(_)));
    }

    #[test]
    fn eval_deref_with_recorded_memory() {
        let mut replay = SnapshotReplayBackend::new();
        let pos = TracePosition::new(1, 0);
        // Write value 0xCAFEBABE_DEADBEEFu64 at address 0x5000.
        let bytes = 0xCAFE_BABE_DEAD_BEEFu64.to_le_bytes().to_vec();
        replay.record_memory(pos, 0x5000, bytes);
        let mut regs = std::collections::BTreeMap::new();
        regs.insert("rbp".into(), 0x5000u64);
        let ctx = HistoricalEvalContext { regs: &regs, pc: 0, sp: 0, replay: &replay, position: pos };
        assert_eq!(eval_expr("*rbp", &ctx), EvalResult::U64(0xCAFE_BABE_DEAD_BEEFu64));
    }

    // ── AnnotationStore ────────────────────────────────────────────────────

    #[test]
    fn annotation_store_insert_list_remove() {
        let mut store = AnnotationStore::new();
        let a1 = RetroAnnotation::simple(0x1000, "rax");
        let a2 = RetroAnnotation::simple(0x2000, "rbx");
        let id1 = store.insert(a1.clone());
        let id2 = store.insert(a2.clone());
        assert_eq!(store.len(), 2);

        let ids: Vec<_> = store.iter().map(|(id, _)| id).collect();
        assert!(ids.contains(&id1));
        assert!(ids.contains(&id2));

        assert!(store.remove(id1));
        assert_eq!(store.len(), 1);
        assert!(!store.remove(id1)); // already gone
    }

    #[test]
    fn annotation_store_get_returns_correct_annotation() {
        let mut store = AnnotationStore::new();
        let ann = RetroAnnotation::simple(0xABCD, "rsp");
        let id = store.insert(ann.clone());
        assert_eq!(store.get(id), Some(&ann));
        assert_eq!(store.get(AnnotationId(999)), None);
    }

    // ── render_format ──────────────────────────────────────────────────────

    #[test]
    fn render_format_substitutes_placeholders() {
        let vals = vec![EvalResult::U64(0x10), EvalResult::U64(0x20)];
        let s = render_format("a={0} b={1}", &vals);
        assert_eq!(s, "a=0x10 b=0x20");
    }

    #[test]
    fn render_format_unknown_placeholder_left_as_is() {
        let vals = vec![EvalResult::U64(1)];
        let s = render_format("{0} {2}", &vals);
        assert_eq!(s, "0x1 {2}");
    }
}
