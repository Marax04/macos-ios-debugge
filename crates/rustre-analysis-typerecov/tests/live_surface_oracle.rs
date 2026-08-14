//! Definitional oracles for the LIVE external surface of
//! `rustre-analysis-typerecov`:
//!
//! * `infer_function_signature` / `register_function_signature`
//!   (called from rustre-mcp-tools and rustre-mcp-server) — the confidence
//!   classification is re-derived from its documented DEFINITION, never from
//!   the implementation.
//! * `recover_structs` / `StructRecoveryEngine`
//!   (called from rustre-decompiler struct_field_recovery_pass) — whole-output
//!   invariants derived from the documented meaning of each field.
//! * `RecoveredType` display/serde (mcp-tools deserializes it with serde_json)
//!   — grammar and roundtrip properties.
//! * `IlValue::Const` width inference in `TypeConstraintGenerator`
//!   (used by rustre-decompiler lib.rs) — minimal-fitting-width definition.
//!
//! Each oracle is randomized with adversarial inputs and asserts its own
//! generator coverage. Determinism (same input → same output) is asserted
//! as a property, not papered over by sorting.

use rustre_analysis_typerecov::struct_recovery_engine::{recover_structs, FieldAccess};
use rustre_analysis_typerecov::type_constraint_generator::{
    ConstraintKind, IlValue, TypeConstraintGenerator,
};
use rustre_analysis_typerecov::{
    infer_function_signature, register_function_signature, Confidence, FunctionSignatureRecord,
    RecoveredType, TypeVar, _clear_function_signatures_for_test,
};

fn xs(s: &mut u64) -> u64 {
    let mut x = *s;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    *s = x;
    x
}

fn tv(n: u32) -> TypeVar {
    TypeVar::new(n)
}

// ─────────────────────────────────────────────────────────────────────────────
// Oracle 1: infer_function_signature confidence classification
//
// DEFINITION (doc comment on the confidence rules, §6.6):
//   High   — calling convention known AND every argument has a concrete
//            (non-Unknown) type.
//   Medium — only the calling convention is known (some arg Unknown, or
//            no cc-independent info).
//   Low    — calling convention unknown.
// Content passthrough: cc string, return display, arg names (empty → argN).
// ─────────────────────────────────────────────────────────────────────────────

/// Serialize registry-mutating tests within this binary.
static REG_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn random_concrete_type(s: &mut u64) -> RecoveredType {
    match xs(s) % 5 {
        0 => RecoveredType::Int {
            width: [1u8, 2, 4, 8][(xs(s) % 4) as usize],
            signed: xs(s) % 2 == 0,
        },
        1 => RecoveredType::Float { width: if xs(s) % 2 == 0 { 4 } else { 8 } },
        2 => RecoveredType::Pointer(Box::new(RecoveredType::Unknown)),
        3 => RecoveredType::Struct { name: format!("S{}", xs(s) % 4) },
        _ => RecoveredType::FnPtr { param_count: (xs(s) % 4) as usize },
    }
}

#[test]
fn oracle_infer_signature_confidence_matches_definition() {
    let _g = REG_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut s = 0xa11c_e5ed_0000_0001u64;
    // Coverage counters: the generator must hit all three classes.
    let (mut n_high, mut n_med, mut n_low) = (0usize, 0usize, 0usize);
    // Adversarial addresses included deliberately.
    let addrs = [0u64, 1, 0x1000, u64::MAX - 8, u64::MAX - 1, u64::MAX, i64::MAX as u64];

    for iter in 0..600 {
        _clear_function_signatures_for_test();
        let addr = addrs[(xs(&mut s) % addrs.len() as u64) as usize];

        let cc_known = xs(&mut s) % 2 == 0;
        let nargs = (xs(&mut s) % 4) as usize;
        let args: Vec<(String, RecoveredType)> = (0..nargs)
            .map(|i| {
                let name = if xs(&mut s) % 3 == 0 { String::new() } else { format!("p{i}") };
                let ty = if xs(&mut s) % 3 == 0 {
                    RecoveredType::Unknown
                } else {
                    random_concrete_type(&mut s)
                };
                (name, ty)
            })
            .collect();
        let record = FunctionSignatureRecord {
            calling_convention: cc_known.then(|| "microsoft-x64".to_string()),
            return_type: if xs(&mut s) % 2 == 0 { Some(random_concrete_type(&mut s)) } else { None },
            args: args.clone(),
        };
        register_function_signature(addr, record);

        // ORACLE from the definition (not from reading the implementation):
        let all_concrete = args.iter().all(|(_, t)| !matches!(t, RecoveredType::Unknown));
        let expected = if cc_known && all_concrete {
            Confidence::High
        } else if cc_known {
            Confidence::Medium
        } else {
            Confidence::Low
        };
        match expected {
            Confidence::High => n_high += 1,
            Confidence::Medium => n_med += 1,
            Confidence::Low => n_low += 1,
        }

        let sig = infer_function_signature(addr);
        assert_eq!(
            sig.confidence, expected,
            "iter {iter}: addr {addr:#x}, cc_known={cc_known}, args={args:?}"
        );
        // Content passthrough per the documented API.
        assert_eq!(sig.args.len(), args.len(), "iter {iter}: arg count changed");
        for (i, (spec, (name, ty))) in sig.args.iter().zip(args.iter()).enumerate() {
            let expected_name =
                if name.is_empty() { format!("arg{i}") } else { name.clone() };
            assert_eq!(spec.name, expected_name, "iter {iter}: arg {i} name");
            assert_eq!(spec.ty, ty.display_name(), "iter {iter}: arg {i} type display");
        }
        // Determinism: querying the same address again yields the same result.
        assert_eq!(sig, infer_function_signature(addr), "iter {iter}: non-deterministic");
    }
    _clear_function_signatures_for_test();
    assert!(
        n_high > 20 && n_med > 20 && n_low > 20,
        "generator failed to cover all confidence classes: H={n_high} M={n_med} L={n_low}"
    );
}

#[test]
fn oracle_infer_signature_unregistered_address_is_low_and_empty() {
    let _g = REG_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    _clear_function_signatures_for_test();
    for addr in [0u64, u64::MAX, 0xdead_beef_dead_beef] {
        let sig = infer_function_signature(addr);
        assert_eq!(sig.confidence, Confidence::Low);
        assert_eq!(sig.calling_convention, "unknown");
        assert_eq!(sig.return_type, "?");
        assert!(sig.args.is_empty());
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Oracle 2: recover_structs — whole-output invariants from the definitions
//
// DEFINITIONS (doc comments on RecoveredStruct / recover_structs):
//   * one struct per base_var whose access count ≥ min_access_count,
//     sorted by base_var;
//   * fields = one per distinct (offset, size) access key;
//     access_count = number of accesses with that key; has_write = OR;
//   * fields sorted by offset;
//   * total_size = max(offset + size) over fields (0 if none);
//   * has_padding ⟺ the union of field byte ranges does not cover
//     [0, total_size) contiguously ("padding gaps detected");
//   * has_overlaps ⟺ some pair of accesses with DIFFERENT (offset,size)
//     keys has intersecting byte ranges (identical accesses are the same
//     field, not a conflict).
// ─────────────────────────────────────────────────────────────────────────────

fn oracle_padding(fields: &[(u32, u8)], total_size: u64) -> bool {
    // Interval-union coverage of [0, total_size).
    let mut ivs: Vec<(u64, u64)> = fields
        .iter()
        .map(|&(o, sz)| (u64::from(o), u64::from(o) + u64::from(sz)))
        .collect();
    ivs.sort_unstable();
    let mut cursor = 0u64;
    for (a, b) in ivs {
        if a > cursor {
            return true;
        }
        cursor = cursor.max(b);
    }
    cursor < total_size
}

/// Takes ORIGINAL (offset,size) keys. Identity is judged on the original
/// key (two accesses are "the same field" only if offset AND size match);
/// byte ranges are the u32-saturated ranges the production code stores.
fn oracle_overlaps(keys: &[(u32, u8)]) -> bool {
    let sat_end = |o: u32, s: u8| u64::from(o.saturating_add(u32::from(s)));
    for i in 0..keys.len() {
        for j in (i + 1)..keys.len() {
            let (o1, s1) = keys[i];
            let (o2, s2) = keys[j];
            if (o1, s1) == (o2, s2) {
                continue;
            }
            let (a1, b1) = (u64::from(o1), sat_end(o1, s1));
            let (a2, b2) = (u64::from(o2), sat_end(o2, s2));
            if a1 < b2 && a2 < b1 {
                return true;
            }
        }
    }
    false
}

#[test]
fn oracle_recover_structs_matches_definitional_invariants() {
    let mut s = 0x57ee_1bea_4d5e_ed01u64;
    let mut saw_padding = 0usize;
    let mut saw_overlap = 0usize;
    let mut saw_filtered = 0usize;

    for iter in 0..800 {
        let n = (xs(&mut s) % 10) as usize; // includes empty input
        // Adversarial offsets: small dense ones plus u32::MAX-region.
        let accesses: Vec<FieldAccess> = (0..n)
            .map(|_| {
                let base = tv((xs(&mut s) % 3) as u32);
                let offset = match xs(&mut s) % 8 {
                    0 => u32::MAX,
                    1 => u32::MAX - 1,
                    2 => u32::MAX - 8,
                    _ => (xs(&mut s) % 16) as u32,
                };
                let size = [0u8, 1, 2, 4, 8][(xs(&mut s) % 5) as usize];
                if xs(&mut s) % 2 == 0 {
                    FieldAccess::read(base, offset, size, xs(&mut s))
                } else {
                    FieldAccess::write(base, offset, size, xs(&mut s))
                }
            })
            .collect();
        let min_count = 1 + (xs(&mut s) % 3) as usize;

        let structs = recover_structs(&accesses, 8, min_count, false);

        // Determinism: identical call → structurally identical output.
        let again = recover_structs(&accesses, 8, min_count, false);
        assert_eq!(format!("{structs:?}"), format!("{again:?}"), "iter {iter}: non-deterministic");

        // Grouping + threshold definition.
        let mut bases: Vec<u32> = accesses.iter().map(|a| a.base_var.0).collect();
        bases.sort_unstable();
        bases.dedup();
        let distinct_bases = bases.len();
        let expected_bases: Vec<u32> = bases
            .into_iter()
            .filter(|b| accesses.iter().filter(|a| a.base_var.0 == *b).count() >= min_count)
            .collect();
        let got_bases: Vec<u32> = structs.iter().map(|st| st.base_var.0).collect();
        assert_eq!(got_bases, expected_bases, "iter {iter}: grouping/sort/threshold");
        if expected_bases.len() < distinct_bases {
            saw_filtered += 1;
        }

        for st in &structs {
            let group: Vec<&FieldAccess> =
                accesses.iter().filter(|a| a.base_var == st.base_var).collect();

            // Field set = distinct (offset,size) keys; counts and writes.
            let mut expected_keys: Vec<(u32, u8)> =
                group.iter().map(|a| (a.byte_offset, a.size_bytes)).collect();
            expected_keys.sort_unstable();
            expected_keys.dedup();
            let mut got_keys: Vec<(u32, u8)> =
                st.fields.iter().map(|f| (f.offset, f.size)).collect();
            got_keys.sort_unstable();
            assert_eq!(got_keys, expected_keys, "iter {iter}: field key set");

            // Sorted by offset.
            for w in st.fields.windows(2) {
                assert!(w[0].offset <= w[1].offset, "iter {iter}: fields not sorted");
            }

            for f in &st.fields {
                let matching: Vec<&&FieldAccess> = group
                    .iter()
                    .filter(|a| a.byte_offset == f.offset && a.size_bytes == f.size)
                    .collect();
                assert_eq!(f.access_count, matching.len(), "iter {iter}: access_count");
                assert_eq!(
                    f.has_write,
                    matching.iter().any(|a| a.is_write),
                    "iter {iter}: has_write"
                );
            }

            // total_size definition (production saturates u32; keep inputs
            // whose true end fits or saturates identically).
            let expected_total: u32 = expected_keys
                .iter()
                .map(|&(o, sz)| o.saturating_add(u32::from(sz)))
                .max()
                .unwrap_or(0);
            assert_eq!(st.total_size, expected_total, "iter {iter}: total_size");

            // Padding definition (computed on the saturated ranges the
            // production code stores).
            let sat_keys: Vec<(u32, u8)> = expected_keys
                .iter()
                .map(|&(o, sz)| {
                    let end = o.saturating_add(u32::from(sz));
                    (o, u8::try_from(end - o).unwrap())
                })
                .collect();
            assert_eq!(
                st.has_padding,
                oracle_padding(&sat_keys, u64::from(expected_total)),
                "iter {iter}: has_padding, keys={expected_keys:?}"
            );
            if st.has_padding {
                saw_padding += 1;
            }

            // Overlap definition — original key identity, saturated ranges.
            assert_eq!(
                st.has_overlaps,
                oracle_overlaps(&expected_keys),
                "iter {iter}: has_overlaps, keys={expected_keys:?}"
            );
            if st.has_overlaps {
                saw_overlap += 1;
            }
        }
    }
    assert!(
        saw_padding > 30 && saw_overlap > 30 && saw_filtered > 30,
        "generator coverage too weak: padding={saw_padding} overlap={saw_overlap} filtered={saw_filtered}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Oracle 3: RecoveredType display grammar + serde roundtrip (live via
// serde_json::from_value in rustre-mcp-tools)
// ─────────────────────────────────────────────────────────────────────────────

fn random_type(s: &mut u64, depth: u8) -> RecoveredType {
    if depth == 0 {
        return RecoveredType::Unknown;
    }
    match xs(s) % 8 {
        0 => RecoveredType::Var(tv((xs(s) % 1000) as u32)),
        1 => RecoveredType::Int {
            width: [1u8, 2, 4, 8][(xs(s) % 4) as usize],
            signed: xs(s) % 2 == 0,
        },
        2 => RecoveredType::Float { width: if xs(s) % 2 == 0 { 4 } else { 8 } },
        3 => RecoveredType::Pointer(Box::new(random_type(s, depth - 1))),
        4 => RecoveredType::Array {
            element: Box::new(random_type(s, depth - 1)),
            count: (xs(s) % 100) as usize,
        },
        5 => RecoveredType::Struct { name: format!("S_{}", xs(s) % 8) },
        6 => RecoveredType::FnPtr { param_count: (xs(s) % 10) as usize },
        _ => RecoveredType::Unknown,
    }
}

#[test]
fn oracle_recovered_type_display_grammar_and_serde_roundtrip() {
    let mut s = 0xd15b_1a40_5eed_0001u64;
    let mut saw_ptr = 0usize;
    for iter in 0..1500 {
        let t = random_type(&mut s, 5);
        let d = t.display_name();

        // Grammar oracle from the documented meaning of each accessor:
        // is_pointer ⟺ Pointer variant ⟺ pointee() is Some, and the display
        // of a pointer is exactly '*' + display of pointee.
        assert_eq!(t.is_pointer(), t.pointee().is_some(), "iter {iter}: {t:?}");
        if let Some(inner) = t.pointee() {
            saw_ptr += 1;
            assert_eq!(d, format!("*{}", inner.display_name()), "iter {iter}: {t:?}");
        }
        assert_eq!(t.is_struct(), matches!(t, RecoveredType::Struct { .. }), "iter {iter}");
        if let RecoveredType::Int { width, signed } = &t {
            let expect = format!("{}{}", if *signed { "i" } else { "u" }, u32::from(*width) * 8);
            assert_eq!(d, expect, "iter {iter}");
        }
        // Determinism.
        assert_eq!(d, t.display_name(), "iter {iter}: display non-deterministic");

        // Serde roundtrip (the definition of a correct serialization):
        // to JSON value and back must be identity — this is exactly the path
        // mcp-tools uses (serde_json::from_value::<RecoveredType>).
        let v = serde_json::to_value(&t).expect("serialize");
        let back: RecoveredType = serde_json::from_value(v).expect("deserialize");
        assert_eq!(back, t, "iter {iter}: serde roundtrip not identity");
    }
    assert!(saw_ptr > 100, "generator coverage: only {saw_ptr} pointers seen");
}

// ─────────────────────────────────────────────────────────────────────────────
// Oracle 4: IlValue::Const minimal-width inference in the generator
//
// DEFINITION: a literal c gets an IsInteger constraint whose min_width is the
// SMALLEST w ∈ {1,2,4,8} such that c fits in a w-byte signed OR w-byte
// unsigned integer, with signed = (c < 0).
// ─────────────────────────────────────────────────────────────────────────────

fn oracle_min_width(c: i64) -> u8 {
    for w in [1u8, 2, 4, 8] {
        let bits = u32::from(w) * 8;
        let fits_signed = if bits == 64 {
            true
        } else {
            let min = -(1i64 << (bits - 1));
            let max = (1i64 << (bits - 1)) - 1;
            c >= min && c <= max
        };
        let fits_unsigned = if bits == 64 {
            c >= 0
        } else {
            c >= 0 && c < (1i64 << bits)
        };
        if fits_signed || fits_unsigned {
            return w;
        }
    }
    8
}

#[test]
fn oracle_const_literal_width_is_minimal_fitting_width() {
    // Boundary sweep + adversarial extremes.
    let mut cases: Vec<i64> = vec![
        0, 1, -1, i64::MIN, i64::MAX, i64::MAX - 1, i64::MIN + 1,
    ];
    for b in [8u32, 16, 32] {
        let umax = (1i64 << b) - 1;
        let smin = -(1i64 << (b - 1));
        let smax = (1i64 << (b - 1)) - 1;
        cases.extend([umax, umax + 1, smin, smin - 1, smax, smax + 1]);
    }
    let mut s = 0xc0de_5eed_c0de_5eedu64;
    for _ in 0..300 {
        cases.push(xs(&mut s) as i64);
    }
    // Generator coverage: all four widths must appear among expectations.
    let mut widths_seen = std::collections::BTreeSet::new();

    for &c in &cases {
        let expected_w = oracle_min_width(c);
        widths_seen.insert(expected_w);
        let mut g = TypeConstraintGenerator::new_64bit();
        let v = g.type_var_of(&IlValue::Const(c));
        let cs = g.into_constraints();
        let found = cs.iter().find_map(|k| match &k.kind {
            ConstraintKind::IsInteger { var, min_width, signed } if *var == v => {
                Some((*min_width, *signed))
            }
            _ => None,
        });
        let (w, signed) = found.unwrap_or_else(|| panic!("no IsInteger emitted for {c}"));
        assert_eq!(w, expected_w, "const {c}: width");
        // Signedness evidence, from the SPEC rather than from the
        // implementation: a negative literal proves the type is signed, a
        // non-negative one proves nothing (it fits both `iN` and `uN`).
        //
        // This assertion used to read `Some(c < 0)` — a verbatim copy of the
        // expression under test, so it could never disagree with it. That is
        // what let `signed: Some(false)` on non-negative literals survive, and
        // with it the SignednessConflict that failed unification for
        // `x = -1; x = 5`.
        let expected_signed = if c < 0 { Some(true) } else { None };
        assert_eq!(signed, expected_signed, "const {c}: signedness");
    }
    assert_eq!(
        widths_seen.into_iter().collect::<Vec<_>>(),
        vec![1, 2, 4, 8],
        "boundary sweep failed to cover all widths"
    );
}
