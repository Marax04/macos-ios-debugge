//! Every named component of a Go symbol must survive into the output.
//!
//! Go has no oracle among the crate's dependencies, so a *loss* of information
//! has no external way to surface: the rendered string stays plausible, the
//! structured fields agree with each other, and nothing is fabricated — a
//! piece is simply missing. No property defined over the fields can see that.
//!
//! This invariant is defined over the *input* instead: split the symbol at
//! top-level dots (bracket-aware, so generic arguments stay whole), drop the
//! parts that are meant to disappear — closure markers `funcN`, nesting
//! indices, and the synthetic `go.shape.` qualifier — and require everything
//! else to appear in the rendered form.
//!
//! It found two defects that everything else missed:
//!   * `…init.OnceValue[go.shape.bool].func5` rendered `…init[bool]`, dropping
//!     the generic function's name (12 of 28 generic symbols);
//!   * `runtime.traceAdvance.func3.osyield.1` rendered
//!     `runtime.traceAdvance {closure-2 #3}`, dropping `osyield` — a named
//!     function nested *after* a closure marker, which the first fix missed.

/// Split at `.` only outside brackets, so `Map[a.b, c]` stays one component.
fn split_top_level(s: &str) -> Vec<&str> {
    let (mut out, mut depth, mut start) = (Vec::new(), 0i32, 0usize);
    for (i, c) in s.char_indices() {
        match c {
            '[' | '(' | '{' => depth += 1,
            ']' | ')' | '}' => depth -= 1,
            '.' if depth == 0 => {
                out.push(&s[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    out.push(&s[start..]);
    out
}

/// Compare ignoring whitespace: the renderer inserts a space after commas in
/// generic argument lists, which is presentation, not content.
fn flat(s: &str) -> String {
    s.chars().filter(|c| !c.is_whitespace()).collect()
}

#[test]
fn no_go_symbol_loses_a_named_component() {
    let mut checked = 0usize;
    let mut lost: Vec<(&str, String, String)> = Vec::new();

    for s in include_str!("data/real_symbols.txt").lines().map(str::trim) {
        // Linker sections, C names, MSVC symbols, and the `type:`/`go:`
        // metadata namespaces are excluded: the last two are deliberately
        // *rewritten* (`type:.eq.T` → `type descriptor for .eq.T`), so a
        // literal-containment check does not apply to them.
        if s.is_empty()
            || s.starts_with('.')
            || s.starts_with('_')
            || s.starts_with('?')
            || s.starts_with("type:")
            || s.starts_with("go:")
            || !s.contains('.')
        {
            continue;
        }
        let Some(r) = rustre_demangle::demangle(s) else {
            continue;
        };
        checked += 1;
        let out = flat(&r.demangled);
        for seg in split_top_level(s) {
            let stem = seg.trim_end_matches(|c: char| c.is_ascii_digit());
            let is_marker =
                matches!(stem, "func" | "deferwrap" | "gowrap") && stem.len() < seg.len();
            let is_index = !seg.is_empty() && seg.chars().all(|c| c.is_ascii_digit());
            if seg.is_empty() || is_marker || is_index {
                continue;
            }
            let want = flat(&seg.replace("go.shape.", ""));
            if !out.contains(&want) {
                lost.push((s, want, r.demangled.clone()));
                break;
            }
        }
    }

    println!("{checked} Go symbols checked for component completeness");
    assert!(
        checked > 1500,
        "only {checked} Go symbols reached the check — suite gone vacuous"
    );
    assert!(
        lost.is_empty(),
        "{} Go symbols lost a named component; first 5: {:#?}",
        lost.len(),
        &lost[..lost.len().min(5)]
    );
}

/// The two shapes that motivated this, asserted directly so the regression is
/// legible without reading the corpus.
#[test]
fn named_components_around_closure_markers_survive() {
    for (sym, needle) in [
        ("os.init.OnceValue[go.shape.bool].func5", "OnceValue"),
        ("runtime.traceAdvance.func3.osyield.1", "osyield"),
    ] {
        let r = rustre_demangle::demangle(sym).unwrap_or_else(|| panic!("{sym} must decode"));
        assert!(
            r.demangled.contains(needle),
            "{sym} -> {}, expected to keep {needle:?}",
            r.demangled
        );
    }
}

/// The inverse of completeness: the output must not invent names.
///
/// `every_named_component_survives` above catches **omission** — a component of
/// the input missing from the output. It cannot catch **invention**, which is the
/// Go backend's documented failure mode: correct strings with lying structured
/// fields, on the one ABI where no oracle can contradict a wrong answer.
///
/// So this asserts the other direction: every identifier-like token in the
/// rendered output must occur in the input, except the renderer's own vocabulary.
/// That exception list is the delicate part and is kept deliberately tiny — each
/// entry is a word the renderer *adds* by design, and every addition to the list
/// weakens the guard, so a new entry needs the same justification as a new
/// decode.
///
/// Measured when added: 2163 Go symbols, 334 tokens flagged, **two** distinct
/// causes, both intended (`closure` for a `funcN` marker, `descriptor` for the
/// `type:.` prefix). Zero invented names.
#[test]
fn no_go_rendering_invents_a_name() {
    /// Words the renderer contributes itself. Not names from the symbol.
    ///
    /// * `closure` — `…Value.func1` renders `… {closure-1 #1}`.
    /// * `descriptor`, `for` — `type:.eq.…` renders `type descriptor for .eq.…`.
    ///
    /// `type` needs no entry: the input spells it `type:`, so the token occurs
    /// in the input already. `for` does need one — it is exactly three
    /// characters and so reaches the threshold, which I initially got wrong and
    /// the test caught.
    const RENDERER_VOCABULARY: &[&str] = &["closure", "descriptor", "for"];

    let corpus = include_str!("data/real_symbols.txt");
    let mut checked = 0;
    let mut invented: Vec<String> = Vec::new();

    for s in corpus.lines().map(str::trim) {
        if s.is_empty() || !s.contains('.') || s.starts_with('.') {
            continue;
        }
        let Some(r) = rustre_demangle::demangle(s) else {
            continue;
        };
        if r.abi != rustre_demangle::ManglingAbi::Go {
            continue;
        }
        checked += 1;

        for tok in r
            .demangled
            .split(|c: char| !(c.is_alphanumeric() || c == '_'))
            .filter(|t| t.len() >= 3)
        {
            // Identifier-boundary match, not substring: `s.contains(tok)` would
            // find a short token incidentally inside a longer input name, so the
            // guard would pass vacuously exactly where invention is easiest to
            // miss. Same defect shape as the Swift local-name guard (iter 79).
            if RENDERER_VOCABULARY.contains(&tok) || input_has_identifier(s, tok) {
                continue;
            }
            invented.push(format!("{tok:?} in {} <- {s}", r.demangled));
            break;
        }
    }

    assert!(
        checked > 1500,
        "only {checked} Go symbols reached the check — suite gone vacuous"
    );
    assert!(
        invented.is_empty(),
        "{} Go renderings contain a name absent from their input; first 5: {:#?}",
        invented.len(),
        &invented[..invented.len().min(5)]
    );
}

/// Every rewrite the Go renderer performs must actually fire.
///
/// 1809 of the 3010 corpus decodes are identity echoes, and **all of them are
/// Go** — Itanium, MSVC and Rust produce none. That is faithful, not lazy: a Go
/// symbol like `errors.Is` needs no transformation. But an echo is only faithful
/// if the symbol carries nothing the renderer is supposed to rewrite, so this
/// checks the echo bucket for missed rewrites rather than trusting it.
///
/// Measured: of 1809 echoes, **zero** carry `go.shape.`, a `type:` prefix, or a
/// trailing `funcN` closure marker. The rewrite machinery is complete for the
/// markers it implements. Twenty carry `go:`, which is the open question recorded
/// in `go_namespace_symbols_report_a_compound_as_a_bare_name` below.
#[test]
fn no_echoed_go_symbol_carries_an_unrewritten_marker() {
    let mut echoes = 0;
    let mut missed: Vec<String> = Vec::new();

    for data in [
        include_str!("data/real_symbols.txt"),
        include_str!("data/pdb_symbols.txt"),
    ] {
        for s in data.lines().map(str::trim).filter(|l| !l.is_empty()) {
            let Some(r) = rustre_demangle::demangle(s) else {
                continue;
            };
            if r.demangled != s {
                continue;
            }
            echoes += 1;

            // `go.shape.` is stripped and `type:` becomes a rendered descriptor,
            // so neither may survive an echo.
            for marker in ["go.shape.", "type:"] {
                if s.contains(marker) {
                    missed.push(format!("{marker} un-rewritten in echo: {s}"));
                }
            }
            // A trailing `.funcN` is rendered as a closure.
            if let Some(d) = s.rsplit('.').next().and_then(|l| l.strip_prefix("func"))
                && !d.is_empty()
                && d.bytes().all(|b| b.is_ascii_digit())
            {
                missed.push(format!("closure marker un-rewritten in echo: {s}"));
            }
        }
    }

    assert!(echoes > 1500, "vacuous: only {echoes} echoes examined");
    assert!(missed.is_empty(), "{} missed rewrites: {:#?}", missed.len(), missed);
}

/// **Open decision — asserts the correct behaviour, which is not implemented.**
///
/// `DemanglingResult::function` is documented as "the bare function or variable
/// name (final component)". For Go's `go:` and `type:` namespaces it is not a
/// bare final component but the whole compound tail:
///
/// ```text
/// go:itab.*errors.errorString,error
///   function = "itab.*errors.errorString,error"
/// type:.eq.[2]runtime.Frame
///   function = ".eq.[2]runtime.Frame"
/// ```
///
/// The first is a kind marker plus a concrete type plus an interface type — an
/// itab is a *data* symbol, and no Go name can contain `,` or `*`. The second
/// starts with `.` and carries an array length. The contract violation is
/// decidable from the field's own doc; the correct value is not, because these
/// symbols have no single final component and the crate has no Go oracle.
///
/// Deliberately narrow: it does NOT demand a particular rendering, only that the
/// field stop claiming a compound is a bare name. `demangled` is fine — `type:`
/// already renders as `type descriptor for …`, and echoing `go:itab.…` is a
/// faithful echo rather than fabrication.
///
/// Note the tension with `structured_fields_are_balanced_and_named_on_every_abi`,
/// which pins that `function` is never empty over the corpora: "no function" is
/// therefore not available as an answer without changing the field to an
/// `Option`. That is the decision this needs.
#[test]
#[ignore = "function holds a compound tail for go:/type: symbols; the right value needs a decision"]
fn go_namespace_symbols_report_a_compound_as_a_bare_name() {
    for sym in [
        "go:itab.*errors.errorString,error",
        "go:itab.internal/poll.errNetClosing,error",
        "type:.eq.[2]runtime.Frame",
    ] {
        let f = rustre_demangle::demangle(sym)
            .unwrap_or_else(|| panic!("{sym} must decode"))
            .function;
        assert!(
            !f.contains(',') && !f.contains('*') && !f.starts_with('.') && !f.contains('['),
            "{sym}: function {f:?} is not a bare name"
        );
    }
}

/// Does `input` contain `needle` as a whole identifier?
///
/// Used by `no_go_rendering_invents_a_name`. Go symbols are dotted and slashed
/// paths, so identifier boundaries are the non-alphanumeric characters.
fn input_has_identifier(input: &str, needle: &str) -> bool {
    input
        .split(|c: char| !(c.is_alphanumeric() || c == '_'))
        .any(|t| t == needle)
}

/// The tightened matcher must actually be tighter.
///
/// `no_go_rendering_invents_a_name` used `input.contains(tok)` until iter 80. A
/// substring test accepts a token that merely occurs *inside* a longer input
/// name, so an invented short name would have been waved through precisely where
/// invention is hardest to spot. The guard passed either way over the corpus —
/// which is the point: **a loose check and a correct implementation look
/// identical from a green test**, so the strengthening has to be demonstrated
/// against the old behaviour rather than assumed.
///
/// Same defect shape as the Swift local-name guard fixed at iter 79, and found by
/// turning that finding on the rest of the crate's own checks.
#[test]
fn identifier_matching_rejects_what_substring_matching_accepted() {
    // Cases where the two rules disagree: `needle` occurs inside a longer
    // identifier, so `contains` says yes and boundary matching says no.
    let disagreeing = [
        ("runtime.mapassign", "map"),
        ("internal/godebug.Setting", "debug"),
        ("errors.errorString", "error"),
        ("sync/atomic.Pointer", "int"),
    ];
    let mut checked = 0;
    for (input, needle) in disagreeing {
        assert!(
            input.contains(needle),
            "premise: substring matching must accept {needle:?} in {input:?}"
        );
        assert!(
            !input_has_identifier(input, needle),
            "{needle:?} is not a whole identifier of {input:?}, but the matcher accepted it"
        );
        checked += 1;
    }
    assert!(checked == 4, "expected 4 disagreeing pairs, checked {checked}");

    // And it must still accept genuine components, or the guard would reject
    // every legitimate rendering.
    for (input, needle) in [
        ("runtime.mapassign", "mapassign"),
        ("runtime.mapassign", "runtime"),
        ("internal/godebug.Setting", "godebug"),
        ("internal/godebug.Setting", "internal"),
        ("sync/atomic.Pointer", "Pointer"),
        ("errors.errorString", "errorString"),
    ] {
        assert!(
            input_has_identifier(input, needle),
            "{needle:?} IS a component of {input:?} and must be accepted"
        );
    }
}
