//! One table: how every public demangling entry point compares with
//! `crate::demangle`.
//!
//! Six separate suites already measure individual entry points
//! (`cpp_demangler_agreement`, `itanium_native_accuracy`,
//! `rust_demangler_accuracy`, `unused_registry`, `unused_msvc_full`,
//! `path_equivalence`). Each answers "did *this* one drift?". None answers
//! "which door should a caller use?", which is the question that actually went
//! unanswered: five workspace crates picked entry points in good faith and
//! several picked badly — `rust_demangler::demangle_rust` is correct on 0 of
//! 135 real Rust v0 symbols, `ItaniumNativeDemangler` gets 37% of parameter
//! counts wrong.
//!
//! Run with `--nocapture` to read the table. The assertions are deliberately
//! few: this is a report first, a guard second.
//!
//! **Reading the `missing` column.** Entry points that return a `String` rather
//! than an `Option` are normalised with `(d != s).then_some(d)`, so a symbol
//! they echo back unchanged counts as `missing`. For Go that is *not* a
//! deficiency: the live path echoes those symbols too, identically — Go package
//! paths are already readable, and an identity echo is what both sides produce.
//! So `demangler_dispatcher`'s 1809 and `Demangler2`'s 2163 are Go echoes, not
//! failures. The column that names a defect is `differ`.
//!
//! Worth stating because the convention has already cost one measurement:
//! comparing an `Option`-returning door against a `String`-returning one makes
//! identical outputs look unequal, and the raw count read 2064 divergences
//! where 255 were real.

/// An entry point, restricted to the symbols it is meant to handle.
struct EntryPoint {
    name: &'static str,
    /// Which corpus symbols this entry point claims to serve.
    applies: fn(&str) -> bool,
    /// Its output, or `None` when it declines/errors.
    call: fn(&str) -> Option<String>,
}

fn is_itanium(s: &str) -> bool {
    (s.starts_with("_Z") || s.starts_with("__Z")) && !is_legacy_rust(s)
}
fn is_msvc(s: &str) -> bool {
    s.starts_with('?')
}
fn is_rust_v0(s: &str) -> bool {
    s.strip_prefix("_R")
        .and_then(|r| r.chars().next())
        .is_some_and(|c| matches!(c, 'N' | 'I' | 'C' | 'M' | 'X' | 'Y' | 'K' | 'B'))
}
const fn any(_: &str) -> bool {
    true
}

/// Legacy Rust reuses the Itanium prefix. `crate::demangle` drops the trailing
/// `::h<16 hex>` via the alternate formatter; several alternatives keep it.
/// That is presentation, not drift, so those symbols are excluded rather than
/// counted as disagreement.
fn is_legacy_rust(s: &str) -> bool {
    s.strip_suffix('E').is_some_and(|t| {
        t.rfind("17h").is_some_and(|i| {
            t[i + 3..].len() == 16 && t[i + 3..].chars().all(|c| c.is_ascii_hexdigit())
        })
    })
}

fn entry_points() -> Vec<EntryPoint> {
    vec![
        EntryPoint {
            name: "cpp_demangler::demangle_itanium",
            applies: is_itanium,
            call: |s| rustre_demangle::cpp_demangler::demangle_itanium(s).ok(),
        },
        EntryPoint {
            name: "cpp_demangler::demangle_msvc",
            applies: is_msvc,
            call: |s| rustre_demangle::cpp_demangler::demangle_msvc(s).ok(),
        },
        EntryPoint {
            name: "ItaniumNativeDemangler::demangle",
            applies: is_itanium,
            call: rustre_demangle::ItaniumNativeDemangler::demangle,
        },
        EntryPoint {
            name: "rust_demangler::demangle_rust",
            applies: is_rust_v0,
            call: |s| rustre_demangle::rust_demangler::demangle_rust(s).ok(),
        },
        EntryPoint {
            name: "demangler_dispatcher::auto_demangle",
            applies: any,
            call: |s| {
                let d = rustre_demangle::demangler_dispatcher::auto_demangle(s);
                (d != s).then_some(d)
            },
        },
        EntryPoint {
            name: "msvc_full::msvc_demangle",
            applies: is_msvc,
            call: |s| {
                let d = rustre_demangle::msvc_full::msvc_demangle(s);
                (d != s).then_some(d)
            },
        },
        // Two live doors the table was missing. Its stated purpose is "which
        // door should a caller use?", and it answered for five of seven.
        //
        // `Demangler2` backs the exported `batch_demangle` /
        // `batch_demangle_parallel`, which two wire tools in `rustre-mcp-tools`
        // call, and `classify.rs` routes through it internally.
        EntryPoint {
            name: "Demangler2::demangle",
            applies: any,
            call: |s| {
                let d = rustre_demangle::Demangler2::demangle(s).demangled;
                (d != s).then_some(d)
            },
        },
        // `itanium_full` has roughly eight uses from other crates. Measured in
        // detail by `itanium_full_accuracy.rs`; present here so the one table
        // that compares doors side by side is not missing a door.
        EntryPoint {
            name: "itanium_full::ItaniumDemangler::demangle",
            applies: is_itanium,
            call: |s| rustre_demangle::itanium_full::ItaniumDemangler::demangle(s).ok(),
        },
    ]
}

fn corpora() -> Vec<&'static str> {
    include_str!("data/real_symbols.txt")
        .lines()
        .chain(include_str!("data/pdb_symbols.txt").lines())
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect()
}

#[test]
fn report_entry_point_agreement() {
    let syms = corpora();
    println!(
        "\n{:<38} {:>7} {:>7} {:>7} {:>7}",
        "entry point", "scope", "agree", "differ", "missing"
    );
    println!("{}", "-".repeat(70));

    let mut better_than_live: Vec<&str> = Vec::new();

    for ep in entry_points() {
        let (mut scope, mut agree, mut differ, mut missing, mut extra) = (0, 0, 0, 0, 0);
        for s in syms.iter().filter(|s| (ep.applies)(s)) {
            let live = rustre_demangle::demangle(s).map(|r| r.demangled);
            let alt = (ep.call)(s);
            match (&live, &alt) {
                (Some(l), Some(a)) => {
                    scope += 1;
                    if l == a {
                        agree += 1;
                    } else {
                        differ += 1;
                    }
                }
                (Some(_), None) => {
                    scope += 1;
                    missing += 1;
                }
                (None, Some(_)) => extra += 1,
                (None, None) => {}
            }
        }
        println!(
            "{:<38} {scope:>7} {agree:>7} {differ:>7} {missing:>7}",
            ep.name
        );
        if extra > 0 {
            // Decoding something the live path cannot is either unused
            // capability or a stale false positive. Both are findings.
            better_than_live.push(ep.name);
            println!("{:<38} {extra} symbols only this path decodes", "");
        }
    }

    println!(
        "\nreference: crate::demangle — {} of {} corpus symbols, 0 defects\n",
        syms.iter()
            .filter(|s| rustre_demangle::demangle(s).is_some())
            .count(),
        syms.len()
    );

    // `demangler_registry` is the known case: it still claims `_RTC_Initialize`
    // and `_RTC_Terminate` as Rust through the loose `_R` rule fixed in the
    // live path. It is not in the table above precisely because it is not a
    // plain string entry point; see `tests/unused_registry.rs`.
    assert!(
        better_than_live.is_empty(),
        "these entry points decode symbols the live path does not, which is \
         either unused capability or a stale false positive: {better_than_live:#?}"
    );
}

/// The guard worth having: the healthy entry point must stay level with the
/// live path, and the known-bad ones must not quietly become the norm.
#[test]
fn healthy_entry_points_stay_level() {
    let syms = corpora();
    let itanium: Vec<&str> = syms.iter().copied().filter(|s| is_itanium(s)).collect();
    assert!(itanium.len() > 700, "suite gone vacuous");

    let disagreements = itanium
        .iter()
        .filter(|s| {
            let live = rustre_demangle::demangle(s).map(|r| r.demangled);
            let alt = rustre_demangle::cpp_demangler::demangle_itanium(s).ok();
            live.is_some() && live != alt
        })
        .count();

    assert_eq!(
        disagreements, 0,
        "cpp_demangler::demangle_itanium was the one alternative level with the \
         live path; {disagreements} symbols now differ"
    );
}
