//! Exhaustive blitz tests for rustre-plugin-loader.
//!
//! Goals: exercise every public API surface, including currently
//! "dead-code" helpers (features, with_feature, transitive_deps, etc.),
//! and probe edge cases / adversarial inputs.

use std::collections::HashSet;
use std::time::Duration;

use rustre_plugin_loader::plugin_dependency_resolver::{
    DepGraph, Dependency, PluginDependencyResolver, ResolveError,
};
use rustre_plugin_loader::plugin_sandbox_runner::{
    AuditEntry, PluginSandboxRunner, ResourceUsage, SandboxConfig, SandboxError, SandboxPolicy,
};
use rustre_plugin_loader::plugin_version_checker::{
    CompatResult, PluginVersionChecker, SemanticVersion, VersionSpec,
};

// ── SemanticVersion parsing ──────────────────────────────────────────────────

#[test]
fn semver_parse_basic() {
    let v = SemanticVersion::parse("0.0.0").unwrap();
    assert_eq!(v.as_triple(), (0, 0, 0));
}

#[test]
fn semver_parse_with_v_prefix() {
    let v = SemanticVersion::parse("v10.20.30").unwrap();
    assert_eq!(v.as_triple(), (10, 20, 30));
}

#[test]
fn semver_parse_pre_release_dotted() {
    let v = SemanticVersion::parse("1.0.0-beta.5").unwrap();
    assert_eq!(v.pre.as_deref(), Some("beta.5"));
    assert!(v.build.is_none());
}

#[test]
fn semver_parse_build_only() {
    let v = SemanticVersion::parse("1.0.0+abc123").unwrap();
    assert_eq!(v.build.as_deref(), Some("abc123"));
    assert!(v.pre.is_none());
}

#[test]
fn semver_parse_pre_and_build() {
    let v = SemanticVersion::parse("2.3.4-rc.1+20250101").unwrap();
    assert_eq!(v.pre.as_deref(), Some("rc.1"));
    assert_eq!(v.build.as_deref(), Some("20250101"));
}

#[test]
fn semver_parse_too_few_parts() {
    assert!(SemanticVersion::parse("1").is_none());
    assert!(SemanticVersion::parse("1.2").is_none());
}

#[test]
fn semver_parse_empty() {
    assert!(SemanticVersion::parse("").is_none());
}

#[test]
fn semver_parse_negative() {
    assert!(SemanticVersion::parse("-1.0.0").is_none());
}

#[test]
fn semver_parse_nonnumeric() {
    assert!(SemanticVersion::parse("a.b.c").is_none());
    assert!(SemanticVersion::parse("1.x.0").is_none());
}

#[test]
fn semver_parse_max_u32() {
    let v = SemanticVersion::parse(&format!("{}.{}.{}", u32::MAX, u32::MAX, u32::MAX)).unwrap();
    assert_eq!(v.as_triple(), (u32::MAX, u32::MAX, u32::MAX));
}

#[test]
fn semver_parse_overflow_u32() {
    let too_big = u64::from(u32::MAX) + 1;
    assert!(SemanticVersion::parse(&format!("{too_big}.0.0")).is_none());
}

// ── SemanticVersion ordering / Display ───────────────────────────────────────

#[test]
fn semver_ordering_patch() {
    let a = SemanticVersion::release(1, 0, 0);
    let b = SemanticVersion::release(1, 0, 1);
    assert!(a < b);
}

#[test]
fn semver_ordering_minor_beats_patch() {
    let a = SemanticVersion::release(1, 0, 99);
    let b = SemanticVersion::release(1, 1, 0);
    assert!(b > a);
}

#[test]
fn semver_pre_release_lt_release() {
    let pre = SemanticVersion::parse("1.0.0-alpha").unwrap();
    let rel = SemanticVersion::release(1, 0, 0);
    assert!(pre < rel);
    assert!(rel > pre);
}

#[test]
fn semver_two_pre_releases_lex() {
    let a = SemanticVersion::parse("1.0.0-alpha").unwrap();
    let b = SemanticVersion::parse("1.0.0-beta").unwrap();
    assert!(a < b);
}

#[test]
fn semver_eq_consistency() {
    let a = SemanticVersion::release(1, 2, 3);
    let b = SemanticVersion::release(1, 2, 3);
    assert_eq!(a, b);
    assert_eq!(a.cmp(&b), std::cmp::Ordering::Equal);
}

#[test]
fn semver_display_release() {
    let v = SemanticVersion::release(1, 2, 3);
    assert_eq!(v.to_string(), "1.2.3");
}

#[test]
fn semver_display_with_pre_and_build() {
    let v = SemanticVersion::parse("1.2.3-alpha+meta").unwrap();
    assert_eq!(v.to_string(), "1.2.3-alpha+meta");
}

#[test]
fn semver_display_roundtrip_parse() {
    let v = SemanticVersion::parse("9.8.7-rc.2+sha.deadbeef").unwrap();
    let s = v.to_string();
    let v2 = SemanticVersion::parse(&s).unwrap();
    assert_eq!(v, v2);
}

// ── next_*/overflow ──────────────────────────────────────────────────────────

#[test]
fn next_patch_normal() {
    let v = SemanticVersion::release(1, 2, 3);
    assert_eq!(v.next_patch().unwrap(), SemanticVersion::release(1, 2, 4));
}

#[test]
fn next_minor_resets_patch() {
    let v = SemanticVersion::release(1, 2, 9);
    assert_eq!(v.next_minor().unwrap(), SemanticVersion::release(1, 3, 0));
}

#[test]
fn next_major_resets() {
    let v = SemanticVersion::release(1, 9, 9);
    assert_eq!(v.next_major().unwrap(), SemanticVersion::release(2, 0, 0));
}

#[test]
fn next_overflows_return_none() {
    let v = SemanticVersion::release(u32::MAX, u32::MAX, u32::MAX);
    assert!(v.next_patch().is_none());
    assert!(v.next_minor().is_none());
    assert!(v.next_major().is_none());
}

// ── is_compatible_with / is_stable ───────────────────────────────────────────

#[test]
fn is_stable_release() {
    assert!(SemanticVersion::release(1, 0, 0).is_stable());
}

#[test]
fn is_stable_pre_release() {
    let v = SemanticVersion::parse("1.0.0-alpha").unwrap();
    assert!(!v.is_stable());
}

#[test]
fn is_compatible_same_major_newer() {
    let host = SemanticVersion::release(1, 5, 0);
    let req = SemanticVersion::release(1, 2, 0);
    assert!(host.is_compatible_with(&req));
}

#[test]
fn is_compatible_same_major_older_fails() {
    let host = SemanticVersion::release(1, 1, 0);
    let req = SemanticVersion::release(1, 2, 0);
    assert!(!host.is_compatible_with(&req));
}

#[test]
fn is_compatible_major_mismatch() {
    let a = SemanticVersion::release(1, 0, 0);
    let b = SemanticVersion::release(2, 0, 0);
    assert!(!a.is_compatible_with(&b));
    assert!(!b.is_compatible_with(&a));
}

// ── VersionSpec parse + matches ──────────────────────────────────────────────

#[test]
fn spec_parse_all_operators() {
    assert!(matches!(VersionSpec::parse(">=1.0.0"), Some(VersionSpec::AtLeast(_))));
    assert!(matches!(VersionSpec::parse(">1.0.0"), Some(VersionSpec::GreaterThan(_))));
    assert!(matches!(VersionSpec::parse("<=1.0.0"), Some(VersionSpec::AtMost(_))));
    assert!(matches!(VersionSpec::parse("<1.0.0"), Some(VersionSpec::LessThan(_))));
    assert!(matches!(VersionSpec::parse("^1.0.0"), Some(VersionSpec::Compatible(_))));
    assert!(matches!(VersionSpec::parse("~1.0.0"), Some(VersionSpec::Approximately(_))));
    assert!(matches!(VersionSpec::parse("=1.0.0"), Some(VersionSpec::Exact(_))));
    assert!(matches!(VersionSpec::parse("*"), Some(VersionSpec::Any)));
    assert!(matches!(VersionSpec::parse(""), Some(VersionSpec::Any)));
    assert!(matches!(VersionSpec::parse("1.0.0"), Some(VersionSpec::AtLeast(_))));
}

#[test]
fn spec_parse_with_whitespace() {
    let s = VersionSpec::parse(">= 1.0.0").unwrap();
    assert_eq!(s, VersionSpec::AtLeast(SemanticVersion::release(1, 0, 0)));
}

#[test]
fn spec_parse_garbage() {
    assert!(VersionSpec::parse(">=garbage").is_none());
    assert!(VersionSpec::parse("!!!").is_none());
}

#[test]
fn spec_matches_greater_than_strict() {
    let s = VersionSpec::parse(">1.0.0").unwrap();
    assert!(!s.matches(&SemanticVersion::release(1, 0, 0)));
    assert!(s.matches(&SemanticVersion::release(1, 0, 1)));
}

#[test]
fn spec_matches_at_most() {
    let s = VersionSpec::parse("<=1.0.0").unwrap();
    assert!(s.matches(&SemanticVersion::release(1, 0, 0)));
    assert!(s.matches(&SemanticVersion::release(0, 9, 9)));
    assert!(!s.matches(&SemanticVersion::release(1, 0, 1)));
}

#[test]
fn spec_matches_less_than_strict() {
    let s = VersionSpec::parse("<2.0.0").unwrap();
    assert!(s.matches(&SemanticVersion::release(1, 9, 9)));
    assert!(!s.matches(&SemanticVersion::release(2, 0, 0)));
}

#[test]
fn spec_matches_tilde_minor_locked() {
    let s = VersionSpec::parse("~1.2.0").unwrap();
    assert!(s.matches(&SemanticVersion::release(1, 2, 0)));
    assert!(s.matches(&SemanticVersion::release(1, 2, 99)));
    assert!(!s.matches(&SemanticVersion::release(1, 3, 0)));
    assert!(!s.matches(&SemanticVersion::release(1, 1, 0)));
}

#[test]
fn spec_matches_caret_major_locked() {
    let s = VersionSpec::parse("^1.2.0").unwrap();
    assert!(s.matches(&SemanticVersion::release(1, 9, 9)));
    assert!(!s.matches(&SemanticVersion::release(2, 0, 0)));
    assert!(!s.matches(&SemanticVersion::release(1, 1, 9)));
}

#[test]
fn spec_kind_name_all_variants() {
    assert_eq!(VersionSpec::Any.kind_name(), "any");
    let v = SemanticVersion::release(1, 0, 0);
    assert_eq!(VersionSpec::Exact(v.clone()).kind_name(), "exact");
    assert_eq!(VersionSpec::AtLeast(v.clone()).kind_name(), "at_least");
    assert_eq!(VersionSpec::GreaterThan(v.clone()).kind_name(), "greater_than");
    assert_eq!(VersionSpec::AtMost(v.clone()).kind_name(), "at_most");
    assert_eq!(VersionSpec::LessThan(v.clone()).kind_name(), "less_than");
    assert_eq!(VersionSpec::Compatible(v.clone()).kind_name(), "compatible");
    assert_eq!(VersionSpec::Approximately(v).kind_name(), "approximately");
}

#[test]
fn spec_display_all() {
    let v = SemanticVersion::release(1, 0, 0);
    assert_eq!(VersionSpec::Any.to_string(), "*");
    assert_eq!(VersionSpec::Exact(v.clone()).to_string(), "=1.0.0");
    assert_eq!(VersionSpec::AtLeast(v.clone()).to_string(), ">=1.0.0");
    assert_eq!(VersionSpec::GreaterThan(v.clone()).to_string(), ">1.0.0");
    assert_eq!(VersionSpec::AtMost(v.clone()).to_string(), "<=1.0.0");
    assert_eq!(VersionSpec::LessThan(v.clone()).to_string(), "<1.0.0");
    assert_eq!(VersionSpec::Compatible(v.clone()).to_string(), "^1.0.0");
    assert_eq!(VersionSpec::Approximately(v).to_string(), "~1.0.0");
}

// ── PluginVersionChecker ─────────────────────────────────────────────────────

fn host(maj: u32, min: u32, pat: u32) -> PluginVersionChecker {
    PluginVersionChecker::new(SemanticVersion::release(maj, min, pat))
}

#[test]
fn checker_any_is_compatible() {
    assert_eq!(host(7, 7, 7).check_compat("*"), CompatResult::Compatible);
}

#[test]
fn checker_parse_error() {
    let r = host(1, 0, 0).check_compat("xx");
    assert!(matches!(r, CompatResult::ParseError { .. }));
    assert!(r.is_failure());
    assert!(!r.is_loadable());
}

#[test]
fn checker_major_mismatch_high() {
    let r = host(2, 0, 0).check_compat(">=1.0.0");
    assert!(matches!(r, CompatResult::MajorMismatch { plugin_requires: 1, host_has: 2 }));
}

#[test]
fn checker_major_mismatch_low() {
    let r = host(1, 0, 0).check_compat(">=2.0.0");
    assert!(matches!(r, CompatResult::MajorMismatch { .. }));
}

#[test]
fn checker_host_too_old() {
    let r = host(1, 0, 0).check_compat(">=1.5.0");
    match r {
        CompatResult::HostTooOld { required, found } => {
            assert_eq!(required.as_triple(), (1, 5, 0));
            assert_eq!(found.as_triple(), (1, 0, 0));
        }
        other => panic!("expected HostTooOld, got {other:?}"),
    }
}

#[test]
fn checker_host_too_new_at_most() {
    // Spec "<=1.0.0", host 1.5.0 — same major, spec doesn't match.
    // The reasonable classification is HostTooNew, not HostTooOld.
    let r = host(1, 5, 0).check_compat("<=1.0.0");
    assert!(
        matches!(r, CompatResult::HostTooNew { .. }),
        "host 1.5.0 against <=1.0.0 should be HostTooNew, got {r:?}"
    );
}

#[test]
fn checker_host_too_new_less_than() {
    let r = host(1, 5, 0).check_compat("<1.0.0");
    assert!(
        matches!(r, CompatResult::HostTooNew { .. }),
        "host 1.5.0 against <1.0.0 should be HostTooNew, got {r:?}"
    );
}

#[test]
fn checker_exact_satisfied() {
    let r = host(1, 0, 0).check_compat("=1.0.0");
    assert_eq!(r, CompatResult::Compatible);
}

#[test]
fn checker_compat_via_spec_any() {
    let r = host(1, 0, 0).check_compat_with_spec(&VersionSpec::Any);
    assert_eq!(r, CompatResult::Compatible);
}

#[test]
fn checker_dep_compat_ok() {
    let r = host(1, 0, 0).check_dep_compat("core", "1.5.0", "^1.0.0");
    assert_eq!(r, CompatResult::Compatible);
}

#[test]
fn checker_dep_compat_not_met() {
    let r = host(1, 0, 0).check_dep_compat("core", "0.9.0", ">=1.0.0");
    match r {
        CompatResult::DependencyNotMet { dep_name, .. } => assert_eq!(dep_name, "core"),
        other => panic!("expected DependencyNotMet, got {other:?}"),
    }
}

#[test]
fn checker_dep_compat_parse_error_version() {
    let r = host(1, 0, 0).check_dep_compat("core", "bogus", ">=1.0.0");
    assert!(matches!(r, CompatResult::ParseError { .. }));
}

#[test]
fn checker_dep_compat_parse_error_spec() {
    let r = host(1, 0, 0).check_dep_compat("core", "1.0.0", "xx");
    assert!(matches!(r, CompatResult::ParseError { .. }));
}

#[test]
fn checker_batch_preserves_order() {
    let c = host(1, 5, 0);
    let res = c.check_batch([
        ("a", ">=1.0.0"),
        ("b", ">=1.6.0"),
        ("c", "*"),
    ]);
    assert_eq!(res.len(), 3);
    assert_eq!(res[0].0, "a");
    assert_eq!(res[1].0, "b");
    assert_eq!(res[2].0, "c");
    assert!(res[0].1.is_loadable());
    assert!(res[1].1.is_failure());
    assert!(res[2].1.is_loadable());
}

#[test]
fn checker_filter_loadable() {
    let c = host(1, 5, 0);
    let v = c.filter_loadable([("ok", ">=1.0.0"), ("nope", ">=9.0.0")]);
    assert_eq!(v, vec!["ok"]);
}

#[test]
fn checker_is_upgrade() {
    let a = SemanticVersion::release(1, 0, 0);
    let b = SemanticVersion::release(1, 0, 1);
    assert!(PluginVersionChecker::is_upgrade(&a, &b));
    assert!(!PluginVersionChecker::is_upgrade(&b, &a));
    assert!(!PluginVersionChecker::is_upgrade(&a, &a));
}

#[test]
fn checker_compare_strs() {
    use std::cmp::Ordering;
    assert_eq!(PluginVersionChecker::compare("1.0.0", "1.0.0"), Some(Ordering::Equal));
    assert_eq!(PluginVersionChecker::compare("1.0.0", "2.0.0"), Some(Ordering::Less));
    assert_eq!(PluginVersionChecker::compare("bogus", "1.0.0"), None);
}

#[test]
fn compat_result_loadable_failure_exhaustive() {
    let cases = vec![
        (CompatResult::Compatible, true),
        (CompatResult::CompatibleWithWarning { reason: "x".into() }, true),
        (
            CompatResult::HostTooNew {
                tested_up_to: SemanticVersion::release(1, 0, 0),
                found: SemanticVersion::release(2, 0, 0),
            },
            true,
        ),
        (
            CompatResult::HostTooOld {
                required: SemanticVersion::release(2, 0, 0),
                found: SemanticVersion::release(1, 0, 0),
            },
            false,
        ),
        (
            CompatResult::MajorMismatch { plugin_requires: 1, host_has: 2 },
            false,
        ),
        (CompatResult::ParseError { raw: "x".into() }, false),
    ];
    for (r, loadable) in cases {
        assert_eq!(r.is_loadable(), loadable, "{r:?}");
        assert_eq!(r.is_failure(), !loadable, "{r:?}");
    }
}

#[test]
fn compat_result_display_includes_facts() {
    let r = CompatResult::DependencyNotMet {
        dep_name: "core".into(),
        required: VersionSpec::AtLeast(SemanticVersion::release(1, 0, 0)),
        found: SemanticVersion::release(0, 9, 0),
    };
    let s = r.to_string();
    assert!(s.contains("core") && s.contains("0.9.0"));
}

// ── DepGraph ─────────────────────────────────────────────────────────────────

#[test]
fn depgraph_empty() {
    let g = DepGraph::new();
    assert!(g.is_empty());
    assert_eq!(g.len(), 0);
}

#[test]
fn depgraph_register_updates_version() {
    let mut g = DepGraph::new();
    g.register_plugin("p", "1.0.0");
    assert_eq!(g.version_of("p"), Some("1.0.0"));
    g.register_plugin("p", "2.0.0");
    assert_eq!(g.version_of("p"), Some("2.0.0"));
    assert_eq!(g.len(), 1);
}

#[test]
fn depgraph_contains_and_names() {
    let mut g = DepGraph::new();
    g.register_plugin("a", "1.0.0");
    g.register_plugin("b", "1.0.0");
    assert!(g.contains("a"));
    let mut names: Vec<&str> = g.plugin_names();
    names.sort();
    assert_eq!(names, vec!["a", "b"]);
}

#[test]
fn depgraph_add_dependency_creates_node() {
    let mut g = DepGraph::new();
    g.add_dependency("a", Dependency::required("b", ">=1.0.0"));
    // a was inserted implicitly via add_dependency.
    assert!(g.contains("a"));
    assert_eq!(g.dependencies_of("a").len(), 1);
}

#[test]
fn depgraph_dependencies_of_unknown_returns_empty() {
    let g = DepGraph::new();
    assert!(g.dependencies_of("ghost").is_empty());
}

#[test]
fn depgraph_set_features_records() {
    // Exercises currently-dead `set_features` API.
    let mut g = DepGraph::new();
    g.register_plugin("p", "1.0.0");
    g.set_features("p", ["feat-a", "feat-b"]);
    // No public accessor — but call should not panic and graph state remains consistent.
    assert!(g.contains("p"));
}

#[test]
fn depgraph_transitive_deps_includes_self() {
    let mut g = DepGraph::new();
    g.register_plugin("a", "1.0.0");
    g.register_plugin("b", "1.0.0");
    g.register_plugin("c", "1.0.0");
    g.add_dependency("a", Dependency::required("b", ">=1.0.0"));
    g.add_dependency("b", Dependency::required("c", ">=1.0.0"));
    let mut t = g.transitive_deps("a");
    t.sort();
    assert_eq!(t, vec!["a".to_string(), "b".to_string(), "c".to_string()]);
}

#[test]
fn depgraph_transitive_deps_handles_cycle_without_loop() {
    let mut g = DepGraph::new();
    g.register_plugin("a", "1.0.0");
    g.register_plugin("b", "1.0.0");
    g.add_dependency("a", Dependency::required("b", ">=1.0.0"));
    g.add_dependency("b", Dependency::required("a", ">=1.0.0"));
    let mut t = g.transitive_deps("a");
    t.sort();
    assert_eq!(t, vec!["a".to_string(), "b".to_string()]);
}

// ── Dependency ───────────────────────────────────────────────────────────────

#[test]
fn dep_required_defaults() {
    let d = Dependency::required("x", ">=1.0.0");
    assert!(!d.optional);
    assert!(d.required_features.is_empty());
}

#[test]
fn dep_with_feature_appends() {
    // Exercises currently-dead `with_feature` API.
    let d = Dependency::required("x", ">=1.0.0")
        .with_feature("a")
        .with_feature("b");
    assert_eq!(d.required_features, vec!["a".to_string(), "b".to_string()]);
}

#[test]
fn dep_display_optional_tag() {
    let d = Dependency::optional("x", ">=1.0.0");
    assert!(d.to_string().contains("optional"));
    let r = Dependency::required("x", ">=1.0.0");
    assert!(!r.to_string().contains("optional"));
}

// ── PluginDependencyResolver ─────────────────────────────────────────────────

#[test]
fn resolver_empty_graph_ok() {
    let r = PluginDependencyResolver::new(DepGraph::new());
    assert!(r.resolve_order().unwrap().is_empty());
}

#[test]
fn resolver_single_plugin() {
    let mut g = DepGraph::new();
    g.register_plugin("solo", "1.0.0");
    let r = PluginDependencyResolver::new(g);
    assert_eq!(r.resolve_order().unwrap(), vec!["solo".to_string()]);
}

#[test]
fn resolver_chain_ordering() {
    let mut g = DepGraph::new();
    g.register_plugin("a", "1.0.0");
    g.register_plugin("b", "1.0.0");
    g.register_plugin("c", "1.0.0");
    g.add_dependency("b", Dependency::required("a", ">=1.0.0"));
    g.add_dependency("c", Dependency::required("b", ">=1.0.0"));
    let r = PluginDependencyResolver::new(g);
    let order = r.resolve_order().unwrap();
    let pos = |n: &str| order.iter().position(|s| s == n).unwrap();
    assert!(pos("a") < pos("b"));
    assert!(pos("b") < pos("c"));
}

#[test]
fn resolver_missing_dependency_required() {
    let mut g = DepGraph::new();
    g.register_plugin("a", "1.0.0");
    g.add_dependency("a", Dependency::required("nope", ">=1.0.0"));
    let r = PluginDependencyResolver::new(g);
    let e = r.resolve_order().unwrap_err();
    assert!(matches!(e, ResolveError::Missing { ref dep, .. } if dep == "nope"));
}

#[test]
fn resolver_version_mismatch() {
    let mut g = DepGraph::new();
    g.register_plugin("core", "0.5.0");
    g.register_plugin("p", "1.0.0");
    g.add_dependency("p", Dependency::required("core", ">=1.0.0"));
    let r = PluginDependencyResolver::new(g);
    let e = r.resolve_order().unwrap_err();
    assert!(matches!(e, ResolveError::VersionMismatch { .. }));
}

#[test]
fn resolver_cycle_two_node() {
    let mut g = DepGraph::new();
    g.register_plugin("a", "1.0.0");
    g.register_plugin("b", "1.0.0");
    g.add_dependency("a", Dependency::required("b", ">=1.0.0"));
    g.add_dependency("b", Dependency::required("a", ">=1.0.0"));
    let r = PluginDependencyResolver::new(g);
    let e = r.resolve_order().unwrap_err();
    assert!(matches!(e, ResolveError::Cycle(_)));
}

#[test]
fn resolver_self_cycle() {
    let mut g = DepGraph::new();
    g.register_plugin("a", "1.0.0");
    g.add_dependency("a", Dependency::required("a", ">=1.0.0"));
    let r = PluginDependencyResolver::new(g);
    let e = r.resolve_order().unwrap_err();
    assert!(matches!(e, ResolveError::Cycle(_)));
}

#[test]
fn resolver_optional_missing_lenient() {
    let mut g = DepGraph::new();
    g.register_plugin("a", "1.0.0");
    g.add_dependency("a", Dependency::optional("missing", ">=1.0.0"));
    let r = PluginDependencyResolver::new(g);
    assert!(r.resolve_order().is_ok());
}

#[test]
fn resolver_optional_missing_strict() {
    let mut g = DepGraph::new();
    g.register_plugin("a", "1.0.0");
    g.add_dependency("a", Dependency::optional("missing", ">=1.0.0"));
    let mut r = PluginDependencyResolver::new(g);
    r.strict_optional = true;
    let e = r.resolve_order().unwrap_err();
    assert!(matches!(e, ResolveError::OptionalUnavailable { .. }));
}

#[test]
fn resolver_optional_present_still_ordered() {
    let mut g = DepGraph::new();
    g.register_plugin("core", "1.0.0");
    g.register_plugin("p", "1.0.0");
    g.add_dependency("p", Dependency::optional("core", ">=1.0.0"));
    let r = PluginDependencyResolver::new(g);
    let order = r.resolve_order().unwrap();
    let pos_core = order.iter().position(|n| n == "core").unwrap();
    let pos_p = order.iter().position(|n| n == "p").unwrap();
    assert!(pos_core < pos_p, "present optional dep should still be ordered before dependent");
}

#[test]
fn resolver_dependents_of() {
    let mut g = DepGraph::new();
    g.register_plugin("core", "1.0.0");
    g.register_plugin("a", "1.0.0");
    g.register_plugin("b", "1.0.0");
    g.add_dependency("a", Dependency::required("core", ">=1.0.0"));
    g.add_dependency("b", Dependency::required("core", ">=1.0.0"));
    let r = PluginDependencyResolver::new(g);
    let mut deps = r.dependents_of("core");
    deps.sort();
    assert_eq!(deps, vec!["a".to_string(), "b".to_string()]);
}

#[test]
fn resolver_ready_to_load_basic() {
    let mut g = DepGraph::new();
    g.register_plugin("core", "1.0.0");
    g.register_plugin("p", "1.0.0");
    g.add_dependency("p", Dependency::required("core", ">=1.0.0"));
    let r = PluginDependencyResolver::new(g);
    let mut loaded: HashSet<String> = HashSet::new();
    let ready = r.ready_to_load(&["p"], &loaded);
    assert!(ready.is_empty());
    loaded.insert("core".to_string());
    let ready = r.ready_to_load(&["p"], &loaded);
    assert_eq!(ready, vec!["p"]);
}

#[test]
fn resolver_from_plugins_helper() {
    let plugins: Vec<(&str, &str, Vec<Dependency>)> = vec![
        ("core", "1.0.0", vec![]),
        ("p", "0.1.0", vec![Dependency::required("core", ">=1.0.0")]),
    ];
    let (resolver, order) = PluginDependencyResolver::from_plugins(plugins).unwrap();
    assert_eq!(resolver.graph().len(), 2);
    let pos_core = order.iter().position(|n| n == "core").unwrap();
    let pos_p = order.iter().position(|n| n == "p").unwrap();
    assert!(pos_core < pos_p);
}

#[test]
fn resolver_from_plugins_propagates_error() {
    let plugins: Vec<(&str, &str, Vec<Dependency>)> = vec![
        ("p", "1.0.0", vec![Dependency::required("ghost", ">=1.0.0")]),
    ];
    assert!(PluginDependencyResolver::from_plugins(plugins).is_err());
}

#[test]
fn resolver_validate_constraints_separately() {
    let mut g = DepGraph::new();
    g.register_plugin("core", "1.0.0");
    g.register_plugin("p", "1.0.0");
    g.add_dependency("p", Dependency::required("core", ">=1.0.0"));
    let r = PluginDependencyResolver::new(g);
    assert!(r.validate_constraints().is_ok());
}

// ── SandboxPolicy ────────────────────────────────────────────────────────────

#[test]
fn policy_default_denies_everything() {
    let p = SandboxPolicy::default();
    assert!(!p.allow_fs_read);
    assert!(!p.allow_network);
    assert!(!p.check_read_path("/tmp"));
    assert!(!p.check_host("example.com"));
}

#[test]
fn policy_permissive_allows_arbitrary() {
    let p = SandboxPolicy::permissive();
    assert!(p.check_read_path("/etc/passwd"));
    assert!(p.check_host("anything"));
}

#[test]
fn policy_deny_all_matches_default() {
    assert_eq!(SandboxPolicy::deny_all(), SandboxPolicy::default());
}

#[test]
fn policy_analysis_safe_only_reads() {
    let p = SandboxPolicy::analysis_safe();
    assert!(p.allow_fs_read);
    assert!(!p.allow_fs_write);
    assert!(!p.allow_network);
}

#[test]
fn policy_check_read_path_prefix_filter() {
    let mut p = SandboxPolicy::analysis_safe();
    p.allowed_read_paths = vec!["/safe/".into()];
    assert!(p.check_read_path("/safe/x.bin"));
    assert!(!p.check_read_path("/etc/passwd"));
}

#[test]
fn policy_check_host_wildcard() {
    let mut p = SandboxPolicy::permissive();
    p.allowed_hosts = vec!["*".into()];
    assert!(p.check_host("whatever"));
}

#[test]
fn policy_check_host_specific() {
    let mut p = SandboxPolicy::permissive();
    p.allowed_hosts = vec!["good.com".into()];
    assert!(p.check_host("good.com"));
    assert!(!p.check_host("bad.com"));
}

#[test]
fn policy_check_read_no_paths_means_any() {
    let mut p = SandboxPolicy::default();
    p.allow_fs_read = true;
    assert!(p.check_read_path("/anywhere"));
}

// ── SandboxConfig ────────────────────────────────────────────────────────────

#[test]
fn config_default_values() {
    let c = SandboxConfig::default();
    assert_eq!(c.max_wall_time, Duration::from_secs(30));
    assert_eq!(c.max_memory_bytes, 128 * 1024 * 1024);
    assert!(c.capture_output);
    assert!(!c.audit_api_calls);
}

#[test]
fn config_trusted_unlimited_memory() {
    let c = SandboxConfig::trusted();
    assert_eq!(c.max_memory_bytes, 0);
    assert!(c.policy.allow_fs_write);
}

#[test]
fn config_ephemeral_short_audit() {
    let c = SandboxConfig::ephemeral();
    assert_eq!(c.max_wall_time, Duration::from_millis(500));
    assert!(c.audit_api_calls);
    assert!(!c.policy.allow_fs_read);
}

#[test]
fn config_with_env_builder() {
    let c = SandboxConfig::default()
        .with_env("KEY", "val")
        .with_env("OTHER", "x");
    assert_eq!(c.env.get("KEY").map(String::as_str), Some("val"));
    assert_eq!(c.env.get("OTHER").map(String::as_str), Some("x"));
}

// ── ResourceUsage ────────────────────────────────────────────────────────────

#[test]
fn usage_any_limit_exceeded_memory() {
    let mut cfg = SandboxConfig::default();
    cfg.max_memory_bytes = 1024;
    let mut u = ResourceUsage::default();
    u.peak_memory_bytes = 2048;
    assert!(u.any_limit_exceeded(&cfg));
}

#[test]
fn usage_any_limit_exceeded_api_calls() {
    let mut cfg = SandboxConfig::default();
    cfg.max_api_calls = 100;
    let mut u = ResourceUsage::default();
    u.api_calls = 101;
    assert!(u.any_limit_exceeded(&cfg));
}

#[test]
fn usage_any_limit_exceeded_wall_time() {
    let mut cfg = SandboxConfig::default();
    cfg.max_wall_time = Duration::from_millis(1);
    let mut u = ResourceUsage::default();
    u.wall_time = Duration::from_millis(2);
    assert!(u.any_limit_exceeded(&cfg));
}

#[test]
fn usage_under_limits_ok() {
    let cfg = SandboxConfig::default();
    let u = ResourceUsage::default();
    assert!(!u.any_limit_exceeded(&cfg));
}

#[test]
fn usage_zero_memory_means_unlimited() {
    let mut cfg = SandboxConfig::default();
    cfg.max_memory_bytes = 0;
    let mut u = ResourceUsage::default();
    u.peak_memory_bytes = u64::MAX;
    assert!(!u.any_limit_exceeded(&cfg));
}

#[test]
fn usage_display_format() {
    let mut u = ResourceUsage::default();
    u.peak_memory_bytes = 2048;
    u.api_calls = 5;
    u.denied_calls = 1;
    let s = u.to_string();
    assert!(s.contains("mem=2KB"));
    assert!(s.contains("calls=5"));
    assert!(s.contains("denied=1"));
}

// ── PluginSandboxRunner ──────────────────────────────────────────────────────

#[test]
fn runner_basic_ok() {
    let r = PluginSandboxRunner::new();
    let c = SandboxConfig::default();
    let res = r.run_sandboxed("p", &c, || Ok("hello".into()));
    assert!(res.success);
    assert_eq!(res.return_value.as_deref(), Some("hello"));
}

#[test]
fn runner_captures_return_in_output_when_enabled() {
    let r = PluginSandboxRunner::new();
    let c = SandboxConfig::default();
    let res = r.run_sandboxed("p", &c, || Ok("captured".into()));
    assert_eq!(res.output, "captured");
}

#[test]
fn runner_no_capture_when_disabled() {
    let r = PluginSandboxRunner::new();
    let mut c = SandboxConfig::default();
    c.capture_output = false;
    let res = r.run_sandboxed("p", &c, || Ok("invisible".into()));
    assert_eq!(res.output, "");
    assert_eq!(res.return_value.as_deref(), Some("invisible"));
}

#[test]
fn runner_zero_api_calls_blocks() {
    let r = PluginSandboxRunner::new();
    let mut c = SandboxConfig::default();
    c.max_api_calls = 0;
    let res = r.run_sandboxed("p", &c, || Ok("never".into()));
    assert!(!res.success);
    assert!(matches!(res.error, Some(SandboxError::PolicyViolation(_))));
}

#[test]
fn runner_panic_caught_str() {
    let r = PluginSandboxRunner::new();
    let res = r.run_sandboxed("p", &SandboxConfig::default(), || -> Result<String, SandboxError> {
        panic!("boom-str");
    });
    match res.error {
        Some(SandboxError::PluginPanic(m)) => assert!(m.contains("boom-str")),
        other => panic!("expected PluginPanic, got {other:?}"),
    }
}

#[test]
fn runner_panic_caught_string() {
    let r = PluginSandboxRunner::new();
    let res = r.run_sandboxed("p", &SandboxConfig::default(), || -> Result<String, SandboxError> {
        panic!("{}", String::from("boom-string"));
    });
    assert!(matches!(res.error, Some(SandboxError::PluginPanic(_))));
}

#[test]
fn runner_wall_time_exceeded_reported() {
    let r = PluginSandboxRunner::new();
    let mut c = SandboxConfig::default();
    c.max_wall_time = Duration::from_millis(5);
    let res = r.run_sandboxed("p", &c, || {
        std::thread::sleep(Duration::from_millis(60));
        Ok("late".into())
    });
    assert!(!res.success, "should have flagged CPU time exceeded");
    assert!(matches!(res.error, Some(SandboxError::CpuTimeExceeded { .. })));
}

#[test]
fn runner_audit_log_populated_when_enabled() {
    let r = PluginSandboxRunner::new();
    let mut c = SandboxConfig::default();
    c.audit_api_calls = true;
    let res = r.run_sandboxed("audit", &c, || Ok("x".into()));
    assert!(res.success);
    assert!(!res.audit_log.is_empty(), "audit log should contain bookkeeping entry");
}

#[test]
fn runner_audit_log_empty_when_disabled() {
    let r = PluginSandboxRunner::new();
    let res = r.run_sandboxed("noaudit", &SandboxConfig::default(), || Ok("x".into()));
    assert!(res.audit_log.is_empty());
}

#[test]
fn runner_history_tracking() {
    let r = PluginSandboxRunner::new();
    for _ in 0..5 {
        r.run_sandboxed("h", &SandboxConfig::default(), || Ok("x".into()));
    }
    assert_eq!(r.run_count("h"), 5);
    assert_eq!(r.history_for("h").len(), 5);
}

#[test]
fn runner_history_unknown_plugin() {
    let r = PluginSandboxRunner::new();
    assert_eq!(r.run_count("nobody"), 0);
    assert!(r.history_for("nobody").is_empty());
}

#[test]
fn runner_clear_history() {
    let r = PluginSandboxRunner::new();
    r.run_sandboxed("h", &SandboxConfig::default(), || Ok("x".into()));
    assert_eq!(r.run_count("h"), 1);
    r.clear_history("h");
    assert_eq!(r.run_count("h"), 0);
}

#[test]
fn runner_cumulative_usage_sums_api_calls() {
    let r = PluginSandboxRunner::new();
    r.run_sandboxed("c", &SandboxConfig::default(), || Ok("a".into()));
    r.run_sandboxed("c", &SandboxConfig::default(), || Ok("b".into()));
    let cu = r.cumulative_usage("c");
    assert_eq!(cu.api_calls, 2);
}

#[test]
fn runner_cumulative_usage_sums_fs_bytes_written() {
    // Build synthetic history by directly manipulating runs: we can't push
    // resource usage from outside, so instead verify the field is summed by
    // checking that the function reads it back from the (empty) history.
    // The contract: every numeric field in ResourceUsage should be summed.
    // We can't write directly, so probe the implementation by running
    // a single ok run and asserting the cumulative usage matches the single
    // recorded usage's fs_bytes_written (both expected to be zero here).
    let r = PluginSandboxRunner::new();
    r.run_sandboxed("w", &SandboxConfig::default(), || Ok("x".into()));
    let cu = r.cumulative_usage("w");
    let hist = r.history_for("w");
    let expected: u64 = hist.iter().map(|u| u.fs_bytes_written).sum();
    assert_eq!(
        cu.fs_bytes_written, expected,
        "cumulative_usage should sum fs_bytes_written across history"
    );
}

#[test]
fn runner_check_fs_read_path_filter() {
    let mut c = SandboxConfig::default();
    c.policy.allow_fs_read = true;
    c.policy.allowed_read_paths = vec!["/ok/".into()];
    assert!(PluginSandboxRunner::check_fs_read(&c, "/ok/file"));
    assert!(!PluginSandboxRunner::check_fs_read(&c, "/bad/file"));
}

#[test]
fn runner_check_network_disabled() {
    let c = SandboxConfig::default();
    assert!(!PluginSandboxRunner::check_network(&c, "host"));
}

#[test]
fn runner_check_network_allowed() {
    let mut c = SandboxConfig::default();
    c.policy.allow_network = true;
    c.policy.allowed_hosts = vec!["host".into()];
    assert!(PluginSandboxRunner::check_network(&c, "host"));
    assert!(!PluginSandboxRunner::check_network(&c, "other"));
}

#[test]
fn runner_batch_collects_all() {
    let r = PluginSandboxRunner::new();
    let c = SandboxConfig::default();
    let tasks: Vec<Box<dyn FnOnce() -> Result<String, SandboxError>>> = vec![
        Box::new(|| Ok("1".into())),
        Box::new(|| Ok("2".into())),
        Box::new(|| Err(SandboxError::PolicyViolation("no".into()))),
    ];
    let results = r.run_batch("batch", &c, tasks);
    assert_eq!(results.len(), 3);
    assert!(results[0].success);
    assert!(results[1].success);
    assert!(!results[2].success);
    assert_eq!(r.run_count("batch"), 3);
}

#[test]
fn audit_entry_display_includes_status() {
    let e = AuditEntry {
        offset_ms: 12,
        api: "fs_read".into(),
        allowed: false,
        context: Some("/etc/passwd".into()),
    };
    let s = e.to_string();
    assert!(s.contains("deny"));
    assert!(s.contains("fs_read"));
    assert!(s.contains("/etc/passwd"));
    assert!(s.contains("+12ms"));
}

#[test]
fn sandbox_error_display_all_variants() {
    let cases = vec![
        SandboxError::CpuTimeExceeded { limit_ms: 1, elapsed_ms: 2 },
        SandboxError::MemoryExceeded { limit_bytes: 10, used_bytes: 20 },
        SandboxError::PolicyViolation("x".into()),
        SandboxError::PluginPanic("p".into()),
        SandboxError::Setup("s".into()),
        SandboxError::EntryNotFound("entry".into()),
    ];
    for e in cases {
        let s = e.to_string();
        assert!(!s.is_empty());
    }
}

#[test]
fn run_result_display_ok_and_err() {
    let ok = PluginSandboxRunner::new()
        .run_sandboxed("d", &SandboxConfig::default(), || Ok("v".into()));
    assert!(ok.to_string().contains("ok"));
    let err = PluginSandboxRunner::new().run_sandboxed("d", &SandboxConfig::default(), || {
        Err(SandboxError::Setup("x".into()))
    });
    assert!(err.to_string().contains("err"));
}
