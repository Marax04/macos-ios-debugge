//! Confidence with *evidence*.
//!
//! A bare `confidence: u8` tells a caller nothing actionable: 62 could mean
//! "three honest unresolved jumps" or "the signature is probably invented".
//! Those demand opposite responses, so this module keeps the reasons.
//!
//! The scoring here is the single source of truth: `crate::score_confidence`
//! delegates to [`score_with_evidence`] and returns `.score`, so the numeric
//! result cannot drift from the explanation.

use std::fmt;

/// One reason confidence was reduced, with the magnitude actually applied.
///
/// `penalty` is the points subtracted AFTER the per-signal cap, so the
/// evidence list always reconciles exactly with the final score.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub signal: Signal,
    /// Raw occurrence count observed (pre-cap), for reporting.
    pub count: i32,
    /// Points actually subtracted.
    pub penalty: i32,
}

/// The kinds of doubt this layer can currently detect.
///
/// Deliberately an exhaustive enum rather than a string: adding a signal
/// should be a typed, reviewed act, and consumers can match on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Signal {
    /// Unresolved indirect jump — real control-flow loss.
    UnresolvedJump,
    /// Unmodelled CPU flag placeholder.
    UnmodelledFlags,
    /// Lifter fell back to a raw-asm comment.
    RawAsmFallback,
    /// Structuring could not absorb the control flow.
    GotoSoup,
    /// Call through global data — unresolved import/symbol.
    UnresolvedCallTarget,
    /// Degenerate self-compare produced by naming collapse.
    DegenerateCompare,
    /// Nothing meaningful was recovered.
    EmptyBody,
    /// Declared parameters never referenced in the body.
    ///
    /// The phantom-parameter fingerprint. This is the only signal that can see
    /// a body which is syntactically perfect and compiles cleanly yet is
    /// confidently wrong — the failure class the recompilability metric is
    /// structurally blind to.
    PhantomParams,
    /// The LAST declared parameter is unreferenced.
    ///
    /// Stronger evidence than a generic unused parameter, and the distinction
    /// is empirical, not aesthetic. Win64 passes arguments in `rcx/rdx/r8/r9`;
    /// when arity recovery over-counts by mistaking a live `r9` for a
    /// parameter, the invented one lands **at the end**. Measured on this
    /// corpus, 3 of the first 4 flagged functions were exactly `a4` unused in
    /// a 4-argument signature.
    ///
    /// **MEASURED BASE RATE — do not assume this is rare: it fires on ~27% of
    /// parameterised functions (9/33 in `sample1_c`).** That is far too common
    /// for "an occasional ignored argument", and is itself the finding: it
    /// points at *systematic* trailing-arity over-recovery, which the
    /// published-prototype harness (16 functions) is far too small a sample to
    /// detect. Weighted only 5 precisely because it is common — it is a broad
    /// hint, not a narrow accusation.
    TrailingPhantomParam,
    /// Some instructions could not be modelled at the LLIL layer.
    ///
    /// Independent of the emitted text: the C can read perfectly while resting
    /// on an instruction whose real semantics were silently dropped.
    LowIlCoverage,
}

impl Signal {
    /// Short stable identifier, suitable for reports and machine consumption.
    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            Self::UnresolvedJump => "unresolved_jump",
            Self::UnmodelledFlags => "unmodelled_flags",
            Self::RawAsmFallback => "raw_asm_fallback",
            Self::GotoSoup => "goto_soup",
            Self::UnresolvedCallTarget => "unresolved_call_target",
            Self::DegenerateCompare => "degenerate_compare",
            Self::EmptyBody => "empty_body",
            Self::PhantomParams => "phantom_params",
            Self::TrailingPhantomParam => "trailing_phantom_param",
            Self::LowIlCoverage => "low_il_coverage",
        }
    }

    /// Whether this signal indicates the output may be *confidently wrong*
    /// (as opposed to visibly incomplete).
    ///
    /// The distinction matters to a caller: visible incompleteness is honest
    /// and can be worked around, whereas a silent-wrongness signal means the
    /// text looks fine and should not be trusted at face value.
    #[must_use]
    pub const fn is_silent_wrongness(self) -> bool {
        matches!(
            self,
            Self::PhantomParams
                | Self::TrailingPhantomParam
                | Self::LowIlCoverage
                | Self::DegenerateCompare
        )
    }
}

impl fmt::Display for Signal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.id())
    }
}

/// A scored function with the reasons behind the score.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfidenceReport {
    /// Final score, clamped to the same 15..=95 band the pipeline has always used.
    pub score: u8,
    /// Every signal that fired, in scoring order. Empty means nothing tripped.
    pub findings: Vec<Finding>,
}

impl ConfidenceReport {
    /// True when any firing signal indicates possible silent wrongness.
    #[must_use]
    pub fn has_silent_wrongness(&self) -> bool {
        self.findings.iter().any(|f| f.signal.is_silent_wrongness())
    }

    /// Human-readable one-line explanation, e.g.
    /// `62 (phantom_params×2 -14, goto_soup×3 -18)`.
    #[must_use]
    pub fn explain(&self) -> String {
        if self.findings.is_empty() {
            return format!("{} (no signals)", self.score);
        }
        let parts: Vec<String> = self
            .findings
            .iter()
            .map(|f| format!("{}×{} -{}", f.signal.id(), f.count, f.penalty))
            .collect();
        format!("{} ({})", self.score, parts.join(", "))
    }

    /// Fold in the LLIL-coverage penalty computed outside the text scorer.
    ///
    /// One-directional by construction: this can only lower `score`.
    pub fn apply_il_coverage(&mut self, coverage_pct: f64, penalty: u8) {
        if penalty == 0 {
            return;
        }
        self.score = self.score.saturating_sub(penalty);
        self.findings.push(Finding {
            signal: Signal::LowIlCoverage,
            // Coverage is a percentage; report it rounded so the evidence line
            // stays readable while remaining faithful to what was measured.
            count: coverage_pct.round() as i32,
            penalty: i32::from(penalty),
        });
    }
}

/// The function's declared parameter names, in signature order.
///
/// Empty when there is no recognisable signature or the parameter list is
/// `void`. Unnamed parameters (a bare `int`) are skipped rather than guessed.
#[must_use]
pub fn param_names(code: &str) -> Vec<&str> {
    // The signature is the first `… ( … ) {` line that is NOT a control-flow
    // header. Gating the keywords matters: `if (x) {` and `while (y) {` match
    // the same shape, a trap this codebase has hit before.
    let Some(sig) = code.lines().map(str::trim).find(|l| {
        l.ends_with(") {")
            && !l.starts_with("if")
            && !l.starts_with("for")
            && !l.starts_with("while")
            && !l.starts_with("switch")
            && !l.starts_with("else")
            && !l.starts_with("do")
    }) else {
        return Vec::new();
    };
    let (Some(open), Some(close)) = (sig.find('('), sig.rfind(')')) else {
        return Vec::new();
    };
    if close <= open {
        return Vec::new();
    }

    let mut out = Vec::new();
    for raw in sig[open + 1..close].split(',') {
        let p = raw.trim();
        if p.is_empty() || p == "void" || p == "..." {
            continue;
        }
        // Name = trailing identifier run (`__int64 a2` -> `a2`, `char *src` -> `src`).
        let name_start = p
            .rfind(|c: char| !crate::is_word_char(c as u8))
            .map_or(0, |i| i + 1);
        let name = &p[name_start..];
        if name.is_empty() || name.starts_with(|c: char| c.is_ascii_digit()) {
            continue;
        }
        out.push(name);
    }
    out
}

/// Positions (into [`param_names`]) of parameters never referenced in the body.
///
/// A parameter mentioned only by its own declaration occurs exactly once.
#[must_use]
pub fn unused_param_indices(code: &str) -> Vec<usize> {
    param_names(code)
        .iter()
        .enumerate()
        .filter(|(_, n)| crate::count_word_occurrences(code, n) <= 1)
        .map(|(i, _)| i)
        .collect()
}

/// Score `code` and record why.
///
/// This mirrors the historical `score_confidence` weights exactly — it IS the
/// implementation, not a parallel one — so the number and the explanation can
/// never disagree.
#[must_use]
pub fn score_with_evidence(code: &str) -> ConfidenceReport {
    let count = |needle: &str| i32::try_from(code.matches(needle).count()).unwrap_or(i32::MAX);
    let mut score: i32 = 92;
    let mut findings: Vec<Finding> = Vec::new();

    // Each entry: (signal, raw count, per-occurrence weight, cap).
    let apply = |findings: &mut Vec<Finding>,
                     score: &mut i32,
                     signal: Signal,
                     raw: i32,
                     weight: i32,
                     cap: i32| {
        if raw <= 0 {
            return;
        }
        let penalty = weight * raw.min(cap);
        *score -= penalty;
        findings.push(Finding { signal, count: raw, penalty });
    };

    // Unresolved indirect jump. Weight 12/cap 3 deliberately: at the old
    // weight (22) a function with 3 honest JUMPOUTs scored BELOW an
    // effectively-empty body, penalising honesty more than recovering nothing.
    apply(&mut findings, &mut score, Signal::UnresolvedJump, count("JUMPOUT"), 12, 3);
    apply(&mut findings, &mut score, Signal::UnmodelledFlags, count("(flags "), 12, 3);
    apply(
        &mut findings,
        &mut score,
        Signal::RawAsmFallback,
        count("bit test:") + count("/* "),
        6,
        5,
    );
    apply(&mut findings, &mut score, Signal::GotoSoup, count("goto loc_"), 6, 4);
    apply(
        &mut findings,
        &mut score,
        Signal::UnresolvedCallTarget,
        crate::count_off_calls(code),
        5,
        4,
    );
    apply(
        &mut findings,
        &mut score,
        Signal::DegenerateCompare,
        crate::count_degenerate_self_compares(code),
        18,
        3,
    );

    if crate::is_effectively_empty_body(code) {
        score -= 45;
        findings.push(Finding { signal: Signal::EmptyBody, count: 1, penalty: 45 });
    }

    let params = param_names(code);
    let unused = unused_param_indices(code);
    apply(
        &mut findings,
        &mut score,
        Signal::PhantomParams,
        i32::try_from(unused.len()).unwrap_or(i32::MAX),
        7,
        3,
    );
    // Extra weight when the unreferenced parameter is the LAST one — the
    // Win64 over-count fingerprint. Deliberately additive on top of
    // PhantomParams: trailing position is evidence *about* that finding, not a
    // separate defect, so it refines rather than replaces it.
    if !params.is_empty() && unused.last() == Some(&(params.len() - 1)) {
        score -= 5;
        findings.push(Finding { signal: Signal::TrailingPhantomParam, count: 1, penalty: 5 });
    }

    // Small credit for successfully structured switches. Not a "signal" — it
    // records recovered structure, so it carries no Finding.
    score += 2 * count("switch (").min(3);

    ConfidenceReport {
        score: u8::try_from(score.clamp(15, 95)).unwrap_or(15),
        findings,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clean_body_has_no_findings() {
        let r = score_with_evidence("__int64 f(int a1) {\n    return a1;\n}\n");
        assert!(r.findings.is_empty(), "unexpected findings: {:?}", r.findings);
        assert!(!r.has_silent_wrongness());
    }

    #[test]
    fn phantom_params_are_recorded_as_silent_wrongness() {
        let code = "__int64 f(int a1, int a2, int a3) {\n    return a1;\n}\n";
        let r = score_with_evidence(code);
        let f = r
            .findings
            .iter()
            .find(|f| f.signal == Signal::PhantomParams)
            .expect("phantom params must be recorded");
        assert_eq!(f.count, 2, "a2 and a3 are both unreferenced");
        assert_eq!(f.penalty, 14, "7 per param, under the cap");
        assert!(r.has_silent_wrongness(), "phantom params imply silent wrongness");
    }

    #[test]
    fn penalties_reconcile_with_the_score() {
        // The evidence must fully explain the distance from the 92 baseline
        // (no switch credit in this body).
        let code = "__int64 f(int a1, int a2) {\n    JUMPOUT(0x1234);\n}\n";
        let r = score_with_evidence(code);
        let total: i32 = r.findings.iter().map(|f| f.penalty).sum();
        assert_eq!(i32::from(r.score), (92 - total).clamp(15, 95));
    }

    #[test]
    fn il_coverage_can_only_lower() {
        let mut r = score_with_evidence("__int64 f(int a1) {\n    return a1;\n}\n");
        let before = r.score;
        r.apply_il_coverage(100.0, 0);
        assert_eq!(r.score, before, "a zero penalty must not change the score");
        r.apply_il_coverage(40.0, 10);
        assert!(r.score < before);
        assert!(r.has_silent_wrongness(), "low IL coverage is silent wrongness");
    }

    #[test]
    fn trailing_unused_param_fires_the_win64_overcount_signal() {
        // `a4` unused in a 4-arg signature: the exact shape measured on the
        // corpus when arity recovery mistakes a live r9 for a parameter.
        let code = "__int64 f(int a1, int a2, int a3, int a4) {\n    return a1 + a2 + a3;\n}\n";
        let r = score_with_evidence(code);
        assert!(r.findings.iter().any(|f| f.signal == Signal::TrailingPhantomParam));
    }

    #[test]
    fn interior_unused_param_does_not_fire_the_trailing_signal() {
        // `a2` ignored but `a3` used — a callback-style interior hole, which
        // is NOT the over-count fingerprint and must not be charged for it.
        let code = "__int64 f(int a1, int a2, int a3) {\n    return a1 + a3;\n}\n";
        let r = score_with_evidence(code);
        assert!(r.findings.iter().any(|f| f.signal == Signal::PhantomParams));
        assert!(
            !r.findings.iter().any(|f| f.signal == Signal::TrailingPhantomParam),
            "interior unused param must not be treated as trailing"
        );
    }

    #[test]
    fn param_names_reads_the_signature_not_a_loop_header() {
        let code = "void f(void) {\n    while (v1 < 10) {\n        v1++;\n    }\n}\n";
        assert!(param_names(code).is_empty());
    }

    #[test]
    fn explain_lists_every_firing_signal() {
        let code = "__int64 f(int a1, int a2) {\n    return a1;\n}\n";
        let e = score_with_evidence(code).explain();
        assert!(e.contains("phantom_params"), "explanation was: {e}");
    }
}
