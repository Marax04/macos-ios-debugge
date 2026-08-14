// Deep adversarial coverage for rustre-plugin-loader.

use std::collections::HashSet;
use std::sync::Arc;
use std::thread;
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

// ─── Seeded LCG ───────────────────────────────────────────────────────────────

struct Lcg(u64);
impl Lcg {
    fn new() -> Self {
        Self(0xDEAD_BEEF_CAFE_BABE)
    }
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0
    }
}

// ─── SemanticVersion ──────────────────────────────────────────────────────────

#[test]
fn sv_parse_roundtrip_50() {
    for major in 0u32..5 {
        for minor in 0u32..5 {
            for patch in 0u32..5 {
                let s = format!("{major}.{minor}.{patch}");
                let v = SemanticVersion::parse(&s).expect("parse");
                assert_eq!(v.as_triple(), (major, minor, patch));
                assert_eq!(v.to_string(), s);
            }
        }
    }
}

#[test]
fn sv_parse_with_v_prefix_roundtrip() {
    for i in 0..30 {
        let s = format!("v{}.{}.{}", i, i + 1, i + 2);
        let v = SemanticVersion::parse(&s).unwrap();
        assert_eq!(v.as_triple(), (i, i + 1, i + 2));
        // Display strips 'v'
        assert!(!v.to_string().starts_with('v'));
    }
}

#[test]
fn sv_parse_pre_release_and_build() {
    let v = SemanticVersion::parse("1.2.3-beta.1+build.42").unwrap();
    assert_eq!(v.pre.as_deref(), Some("beta.1"));
    assert_eq!(v.build.as_deref(), Some("build.42"));
    assert_eq!(v.to_string(), "1.2.3-beta.1+build.42");
}

#[test]
fn sv_parse_invalid_inputs() {
    assert!(SemanticVersion::parse("").is_none());
    assert!(SemanticVersion::parse("1").is_none());
    assert!(SemanticVersion::parse("1.2").is_none());
    assert!(SemanticVersion::parse("1.2.3.4").is_none());
    assert!(SemanticVersion::parse("a.b.c").is_none());
    assert!(SemanticVersion::parse("1.2.x").is_none());
    assert!(SemanticVersion::parse("-1.0.0").is_none());
}

#[test]
fn sv_parse_lcg_fuzz_never_panics() {
    let mut lcg = Lcg::new();
    for _ in 0..200 {
        let n = lcg.next();
        let s = format!("{}.{}.{}", n & 0xFF, (n >> 8) & 0xFF, (n >> 16) & 0xFF);
        // Should always parse a fully-numeric triple.
        let _ = SemanticVersion::parse(&s).expect("numeric triple");
        // Random bytes — must not panic.
        let bytes: [u8; 8] = n.to_le_bytes();
        let raw = String::from_utf8_lossy(&bytes).into_owned();
        let _ = SemanticVersion::parse(&raw);
    }
}

#[test]
fn sv_boundary_values() {
    let max = SemanticVersion::release(u32::MAX, u32::MAX, u32::MAX);
    assert_eq!(max.as_triple(), (u32::MAX, u32::MAX, u32::MAX));
    let zero = SemanticVersion::release(0, 0, 0);
    assert!(zero < max);
    assert_eq!(zero.as_triple(), (0, 0, 0));
}

#[test]
fn sv_ordering_total_50() {
    let versions: Vec<SemanticVersion> = (0..50)
        .map(|i| SemanticVersion::release(i / 25, (i / 5) % 5, i % 5))
        .collect();
    for (i, a) in versions.iter().enumerate() {
        for (j, b) in versions.iter().enumerate() {
            if i < j {
                assert!(a < b || (a == b));
            }
            // Symmetry / antisymmetry baseline.
            assert_eq!(a == b, b == a);
        }
    }
}

#[test]
fn sv_pre_release_lower_than_release_pairs() {
    for i in 0..30 {
        let base = SemanticVersion::release(1, 0, i);
        let pre = SemanticVersion::parse(&format!("1.0.{}-alpha", i)).unwrap();
        assert!(pre < base, "pre should be lower for {i}");
    }
}

#[test]
fn sv_is_compatible_with() {
    let host = SemanticVersion::release(1, 5, 0);
    assert!(host.is_compatible_with(&SemanticVersion::release(1, 0, 0)));
    assert!(!host.is_compatible_with(&SemanticVersion::release(2, 0, 0)));
    // Lower than baseline of same major is not compatible.
    assert!(!host.is_compatible_with(&SemanticVersion::release(1, 6, 0)));
}

#[test]
fn sv_is_stable() {
    assert!(SemanticVersion::release(1, 0, 0).is_stable());
    assert!(!SemanticVersion::parse("1.0.0-rc").unwrap().is_stable());
}

#[test]
fn sv_next_patch_minor_major_overflow() {
    assert!(SemanticVersion::release(0, 0, u32::MAX).next_patch().is_none());
    assert!(SemanticVersion::release(0, u32::MAX, 0).next_minor().is_none());
    assert!(SemanticVersion::release(u32::MAX, 0, 0).next_major().is_none());
    // Normal increments work.
    assert_eq!(
        SemanticVersion::release(1, 2, 3).next_patch().unwrap().as_triple(),
        (1, 2, 4)
    );
    assert_eq!(
        SemanticVersion::release(1, 2, 3).next_minor().unwrap().as_triple(),
        (1, 3, 0)
    );
    assert_eq!(
        SemanticVersion::release(1, 2, 3).next_major().unwrap().as_triple(),
        (2, 0, 0)
    );
}

#[test]
fn sv_eq_hash_consistency_30_pairs() {
    use std::collections::HashMap;
    let mut map: HashMap<String, SemanticVersion> = HashMap::new();
    for i in 0..30 {
        let v = SemanticVersion::release(i, i + 1, i + 2);
        let k = v.to_string();
        // Eq consistency: parse round-trip yields equal value.
        let parsed = SemanticVersion::parse(&k).unwrap();
        assert_eq!(v, parsed);
        map.insert(k, v);
    }
    assert_eq!(map.len(), 30);
}

// ─── VersionSpec ──────────────────────────────────────────────────────────────

#[test]
fn vs_parse_all_operators() {
    let ok = |s: &str| VersionSpec::parse(s).expect(s);
    assert!(matches!(ok(">=1.0.0"), VersionSpec::AtLeast(_)));
    assert!(matches!(ok(">1.0.0"), VersionSpec::GreaterThan(_)));
    assert!(matches!(ok("<=1.0.0"), VersionSpec::AtMost(_)));
    assert!(matches!(ok("<1.0.0"), VersionSpec::LessThan(_)));
    assert!(matches!(ok("^1.0.0"), VersionSpec::Compatible(_)));
    assert!(matches!(ok("~1.0.0"), VersionSpec::Approximately(_)));
    assert!(matches!(ok("=1.0.0"), VersionSpec::Exact(_)));
    assert!(matches!(ok("*"), VersionSpec::Any));
    assert!(matches!(ok(""), VersionSpec::Any));
    assert!(matches!(ok("1.0.0"), VersionSpec::AtLeast(_)));
}

#[test]
fn vs_parse_invalid_returns_none() {
    assert!(VersionSpec::parse(">=garbage").is_none());
    assert!(VersionSpec::parse("^x.y.z").is_none());
    assert!(VersionSpec::parse("~not.a.ver").is_none());
}

#[test]
fn vs_display_roundtrip_50() {
    let inputs: Vec<String> = (0..50)
        .map(|i| {
            let op = ["^", "~", ">=", "<=", "=", ">", "<"][i % 7];
            format!("{op}{}.{}.{}", i / 25, (i / 5) % 5, i % 5)
        })
        .collect();
    for s in &inputs {
        let spec = VersionSpec::parse(s).expect(s);
        let printed = spec.to_string();
        let reparsed = VersionSpec::parse(&printed).expect(&printed);
        assert_eq!(spec, reparsed);
    }
}

#[test]
fn vs_kind_name_all_variants() {
    let v = SemanticVersion::release(1, 0, 0);
    assert_eq!(VersionSpec::Any.kind_name(), "any");
    assert_eq!(VersionSpec::Exact(v.clone()).kind_name(), "exact");
    assert_eq!(VersionSpec::AtLeast(v.clone()).kind_name(), "at_least");
    assert_eq!(VersionSpec::GreaterThan(v.clone()).kind_name(), "greater_than");
    assert_eq!(VersionSpec::AtMost(v.clone()).kind_name(), "at_most");
    assert_eq!(VersionSpec::LessThan(v.clone()).kind_name(), "less_than");
    assert_eq!(VersionSpec::Compatible(v.clone()).kind_name(), "compatible");
    assert_eq!(VersionSpec::Approximately(v).kind_name(), "approximately");
}

#[test]
fn vs_matches_caret_tilde_boundaries() {
    let caret = VersionSpec::parse("^1.2.3").unwrap();
    assert!(caret.matches(&SemanticVersion::release(1, 2, 3)));
    assert!(caret.matches(&SemanticVersion::release(1, 99, 99)));
    assert!(!caret.matches(&SemanticVersion::release(2, 0, 0)));
    assert!(!caret.matches(&SemanticVersion::release(1, 2, 2)));

    let tilde = VersionSpec::parse("~1.2.3").unwrap();
    assert!(tilde.matches(&SemanticVersion::release(1, 2, 3)));
    assert!(tilde.matches(&SemanticVersion::release(1, 2, 99)));
    assert!(!tilde.matches(&SemanticVersion::release(1, 3, 0)));
    assert!(!tilde.matches(&SemanticVersion::release(1, 2, 2)));
}

#[test]
fn vs_lcg_fuzz_no_panic() {
    let mut lcg = Lcg::new();
    let prefixes = ["^", "~", ">=", "<=", ">", "<", "=", "*", "v", " "];
    for _ in 0..200 {
        let n = lcg.next();
        let p = prefixes[(n as usize) % prefixes.len()];
        let s = format!("{p}{}.{}.{}", n & 0xF, (n >> 4) & 0xF, (n >> 8) & 0xF);
        let _ = VersionSpec::parse(&s);
    }
}

// ─── PluginVersionChecker ─────────────────────────────────────────────────────

#[test]
fn pvc_check_compat_all_paths() {
    let host = SemanticVersion::release(1, 5, 0);
    let c = PluginVersionChecker::new(host);
    assert_eq!(c.check_compat("*"), CompatResult::Compatible);
    assert!(c.check_compat(">=1.0.0").is_loadable());
    assert!(matches!(c.check_compat(">=2.0.0"), CompatResult::MajorMismatch { .. }));
    assert!(matches!(c.check_compat(">=1.9.0"), CompatResult::HostTooOld { .. }));
    assert!(matches!(c.check_compat("???"), CompatResult::ParseError { .. }));
}

#[test]
fn pvc_check_compat_lcg_no_panic() {
    let mut lcg = Lcg::new();
    let checker = PluginVersionChecker::new(SemanticVersion::release(3, 4, 5));
    for _ in 0..100 {
        let n = lcg.next();
        let s = format!("{}.{}.{}", n & 0xFF, (n >> 8) & 0xFF, (n >> 16) & 0xFF);
        let _ = checker.check_compat(&s);
        let s2 = format!("^{}.{}.{}", n & 0xF, (n >> 4) & 0xF, (n >> 8) & 0xF);
        let _ = checker.check_compat(&s2);
    }
}

#[test]
fn pvc_check_dep_compat_paths() {
    let c = PluginVersionChecker::new(SemanticVersion::release(1, 0, 0));
    assert_eq!(c.check_dep_compat("d", "1.2.3", ">=1.0.0"), CompatResult::Compatible);
    assert!(matches!(
        c.check_dep_compat("d", "0.1.0", ">=1.0.0"),
        CompatResult::DependencyNotMet { .. }
    ));
    assert!(matches!(
        c.check_dep_compat("d", "bad", ">=1.0.0"),
        CompatResult::ParseError { .. }
    ));
    assert!(matches!(
        c.check_dep_compat("d", "1.0.0", ">=bad"),
        CompatResult::ParseError { .. }
    ));
}

#[test]
fn pvc_batch_filter_consistency() {
    let c = PluginVersionChecker::new(SemanticVersion::release(1, 5, 0));
    let reqs: Vec<(&str, &str)> = (0..30)
        .map(|i| {
            if i % 2 == 0 {
                ("ok", ">=1.0.0")
            } else {
                ("hi", ">=9.0.0")
            }
        })
        .collect();
    let results = c.check_batch(reqs.clone());
    assert_eq!(results.len(), 30);
    let loadable = c.filter_loadable(reqs);
    assert_eq!(loadable.len(), 15);
}

#[test]
fn pvc_compare_and_upgrade() {
    assert_eq!(
        PluginVersionChecker::compare("1.0.0", "2.0.0"),
        Some(std::cmp::Ordering::Less)
    );
    assert_eq!(PluginVersionChecker::compare("bad", "1.0.0"), None);
    let a = SemanticVersion::release(1, 0, 0);
    let b = SemanticVersion::release(1, 0, 1);
    assert!(PluginVersionChecker::is_upgrade(&a, &b));
    assert!(!PluginVersionChecker::is_upgrade(&b, &a));
    assert!(!PluginVersionChecker::is_upgrade(&a, &a));
}

#[test]
fn pvc_compat_result_loadable_failure_invariant() {
    let cases = [
        CompatResult::Compatible,
        CompatResult::CompatibleWithWarning { reason: "x".into() },
        CompatResult::HostTooOld {
            required: SemanticVersion::release(1, 0, 0),
            found: SemanticVersion::release(0, 9, 0),
        },
        CompatResult::HostTooNew {
            tested_up_to: SemanticVersion::release(1, 0, 0),
            found: SemanticVersion::release(2, 0, 0),
        },
        CompatResult::MajorMismatch {
            plugin_requires: 2,
            host_has: 1,
        },
        CompatResult::ParseError { raw: "x".into() },
    ];
    for r in &cases {
        assert_eq!(r.is_loadable(), !r.is_failure());
        // Display should not panic and produce non-empty output.
        assert!(!r.to_string().is_empty());
    }
}

// ─── DepGraph ─────────────────────────────────────────────────────────────────

#[test]
fn dep_dependency_constructors_and_features() {
    let req = Dependency::required("a", ">=1.0.0").with_feature("f1").with_feature("f2");
    assert_eq!(req.required_features.len(), 2);
    assert!(!req.optional);
    let opt = Dependency::optional("b", "*");
    assert!(opt.optional);
    assert!(opt.to_string().contains("optional"));
    assert!(!req.to_string().contains("optional"));
}

#[test]
fn dep_graph_basics() {
    let mut g = DepGraph::new();
    assert!(g.is_empty());
    assert_eq!(g.len(), 0);
    g.register_plugin("a", "1.0.0");
    g.register_plugin("b", "2.0.0");
    assert!(g.contains("a"));
    assert!(!g.contains("c"));
    assert_eq!(g.version_of("a"), Some("1.0.0"));
    assert_eq!(g.version_of("c"), None);
    assert_eq!(g.len(), 2);
    let mut names = g.plugin_names();
    names.sort();
    assert_eq!(names, vec!["a", "b"]);
}

#[test]
fn dep_graph_set_features() {
    let mut g = DepGraph::new();
    g.register_plugin("a", "1.0.0");
    g.set_features("a", ["x", "y", "z"]);
    // No direct getter for features, but operation must not panic.
    assert!(g.contains("a"));
}

#[test]
fn dep_graph_register_overrides_version() {
    let mut g = DepGraph::new();
    g.register_plugin("a", "1.0.0");
    g.register_plugin("a", "2.0.0");
    assert_eq!(g.version_of("a"), Some("2.0.0"));
}

#[test]
fn dep_graph_transitive_deps_includes_self() {
    let mut g = DepGraph::new();
    g.register_plugin("a", "1.0.0");
    g.register_plugin("b", "1.0.0");
    g.register_plugin("c", "1.0.0");
    g.add_dependency("a", Dependency::required("b", ">=1.0.0"));
    g.add_dependency("b", Dependency::required("c", ">=1.0.0"));
    let t = g.transitive_deps("a");
    assert!(t.contains(&"a".to_string()));
    assert!(t.contains(&"b".to_string()));
    assert!(t.contains(&"c".to_string()));
}

// ─── Resolver: state machine + bugs ───────────────────────────────────────────

fn lin_graph(n: usize) -> DepGraph {
    let mut g = DepGraph::new();
    for i in 0..n {
        g.register_plugin(format!("p{i}"), "1.0.0");
    }
    for i in 1..n {
        g.add_dependency(format!("p{i}"), Dependency::required(format!("p{}", i - 1), ">=1.0.0"));
    }
    g
}

#[test]
fn resolver_linear_chain_order() {
    let g = lin_graph(20);
    let r = PluginDependencyResolver::new(g);
    let order = r.resolve_order().unwrap();
    assert_eq!(order.len(), 20);
    for i in 1..20 {
        let prev = order.iter().position(|n| n == &format!("p{}", i - 1)).unwrap();
        let cur = order.iter().position(|n| n == &format!("p{i}")).unwrap();
        assert!(prev < cur, "prev {} < cur {} expected", prev, cur);
    }
}

#[test]
fn resolver_cycle_detection_minimal() {
    let mut g = DepGraph::new();
    g.register_plugin("a", "1.0.0");
    g.register_plugin("b", "1.0.0");
    g.add_dependency("a", Dependency::required("b", ">=1.0.0"));
    g.add_dependency("b", Dependency::required("a", ">=1.0.0"));
    let r = PluginDependencyResolver::new(g);
    assert!(matches!(r.resolve_order(), Err(ResolveError::Cycle(_))));
}

#[test]
fn resolver_self_cycle() {
    let mut g = DepGraph::new();
    g.register_plugin("a", "1.0.0");
    g.add_dependency("a", Dependency::required("a", ">=1.0.0"));
    let r = PluginDependencyResolver::new(g);
    assert!(matches!(r.resolve_order(), Err(ResolveError::Cycle(_))));
}

#[test]
fn resolver_missing_required() {
    let mut g = DepGraph::new();
    g.register_plugin("a", "1.0.0");
    g.add_dependency("a", Dependency::required("missing", ">=1.0.0"));
    let r = PluginDependencyResolver::new(g);
    match r.resolve_order().unwrap_err() {
        ResolveError::Missing { plugin, dep } => {
            assert_eq!(plugin, "a");
            assert_eq!(dep, "missing");
        }
        e => panic!("unexpected {e:?}"),
    }
}

#[test]
fn resolver_version_mismatch_lower() {
    let mut g = DepGraph::new();
    g.register_plugin("a", "1.0.0");
    g.register_plugin("dep", "0.5.0");
    g.add_dependency("a", Dependency::required("dep", ">=1.0.0"));
    let r = PluginDependencyResolver::new(g);
    assert!(matches!(r.resolve_order(), Err(ResolveError::VersionMismatch { .. })));
}

#[test]
fn resolver_optional_missing_nonstrict_ok() {
    let mut g = DepGraph::new();
    g.register_plugin("a", "1.0.0");
    g.add_dependency("a", Dependency::optional("missing", ">=1.0.0"));
    let r = PluginDependencyResolver::new(g);
    assert!(r.resolve_order().is_ok());
}

#[test]
fn resolver_optional_missing_strict_err() {
    let mut g = DepGraph::new();
    g.register_plugin("a", "1.0.0");
    g.add_dependency("a", Dependency::optional("missing", ">=1.0.0"));
    let mut r = PluginDependencyResolver::new(g);
    r.strict_optional = true;
    assert!(matches!(
        r.resolve_order(),
        Err(ResolveError::OptionalUnavailable { .. })
    ));
}

#[test]
fn resolver_empty_graph() {
    let r = PluginDependencyResolver::new(DepGraph::new());
    let order = r.resolve_order().unwrap();
    assert!(order.is_empty());
}

#[test]
fn resolver_from_plugins_helper() {
    let plugins: Vec<(&str, &str, Vec<Dependency>)> = vec![
        ("core", "1.0.0", vec![]),
        ("a", "1.0.0", vec![Dependency::required("core", ">=1.0.0")]),
        ("b", "1.0.0", vec![Dependency::required("a", ">=1.0.0")]),
    ];
    let (_r, order) = PluginDependencyResolver::from_plugins(plugins).unwrap();
    let pos = |n: &str| order.iter().position(|x| x == n).unwrap();
    assert!(pos("core") < pos("a"));
    assert!(pos("a") < pos("b"));
}

#[test]
fn resolver_dependents_and_ready_to_load() {
    let mut g = DepGraph::new();
    g.register_plugin("core", "1.0.0");
    g.register_plugin("x", "1.0.0");
    g.register_plugin("y", "1.0.0");
    g.add_dependency("x", Dependency::required("core", ">=1.0.0"));
    g.add_dependency("y", Dependency::required("core", ">=1.0.0"));
    let r = PluginDependencyResolver::new(g);
    let mut deps = r.dependents_of("core");
    deps.sort();
    assert_eq!(deps, vec!["x", "y"]);

    let mut loaded: HashSet<String> = HashSet::new();
    let candidates = ["x", "y"];
    // Nothing loaded yet — none ready.
    assert!(r.ready_to_load(&candidates, &loaded).is_empty());
    loaded.insert("core".into());
    let mut ready = r.ready_to_load(&candidates, &loaded);
    ready.sort();
    assert_eq!(ready, vec!["x", "y"]);
}

#[test]
fn resolver_validate_constraints_separately() {
    let mut g = DepGraph::new();
    g.register_plugin("a", "1.0.0");
    g.register_plugin("b", "1.0.0");
    g.add_dependency("a", Dependency::required("b", ">=1.0.0"));
    let r = PluginDependencyResolver::new(g);
    assert!(r.validate_constraints().is_ok());

    let mut g2 = DepGraph::new();
    g2.register_plugin("a", "1.0.0");
    g2.add_dependency("a", Dependency::required("missing", ">=1.0.0"));
    let r2 = PluginDependencyResolver::new(g2);
    assert!(r2.validate_constraints().is_err());
}

#[test]
fn resolver_diamond_topo_correct() {
    // a -> b, a -> c, b -> d, c -> d. d must come before a.
    let mut g = DepGraph::new();
    for p in ["a", "b", "c", "d"] {
        g.register_plugin(p, "1.0.0");
    }
    g.add_dependency("a", Dependency::required("b", ">=1.0.0"));
    g.add_dependency("a", Dependency::required("c", ">=1.0.0"));
    g.add_dependency("b", Dependency::required("d", ">=1.0.0"));
    g.add_dependency("c", Dependency::required("d", ">=1.0.0"));
    let r = PluginDependencyResolver::new(g);
    let order = r.resolve_order().unwrap();
    let pos = |n: &str| order.iter().position(|x| x == n).unwrap();
    assert!(pos("d") < pos("b"));
    assert!(pos("d") < pos("c"));
    assert!(pos("b") < pos("a"));
    assert!(pos("c") < pos("a"));
}

#[test]
fn resolve_error_display_all_variants() {
    let e1 = ResolveError::Missing { plugin: "a".into(), dep: "b".into() };
    let e2 = ResolveError::Cycle(vec!["a".into(), "b".into(), "a".into()]);
    let e3 = ResolveError::VersionMismatch {
        plugin: "p".into(),
        dep: "d".into(),
        required: ">=1.0.0".into(),
        found: "0.9.0".into(),
    };
    let e4 = ResolveError::OptionalUnavailable { plugin: "p".into(), dep: "d".into() };
    for e in [&e1, &e2, &e3, &e4] {
        assert!(!e.to_string().is_empty());
    }
    // Eq consistency.
    assert_eq!(e1.clone(), e1);
}

// ─── SandboxPolicy + SandboxConfig ────────────────────────────────────────────

#[test]
fn policy_permissive_and_deny_all() {
    let p = SandboxPolicy::permissive();
    assert!(p.allow_fs_read && p.allow_network && p.allow_subprocess);
    assert!(p.check_read_path("/anything"));
    assert!(p.check_host("anyhost"));

    let d = SandboxPolicy::deny_all();
    assert!(!d.allow_fs_read && !d.allow_network);
    assert!(!d.check_read_path("/x"));
    assert!(!d.check_host("h"));
}

#[test]
fn policy_analysis_safe_read_only() {
    let p = SandboxPolicy::analysis_safe();
    assert!(p.allow_fs_read);
    assert!(!p.allow_fs_write);
    assert!(!p.allow_network);
}

#[test]
fn policy_allowed_paths_and_hosts_filter() {
    let mut p = SandboxPolicy::default();
    p.allow_fs_read = true;
    p.allowed_read_paths = vec!["/safe/".into(), "/data/".into()];
    assert!(p.check_read_path("/safe/file.txt"));
    assert!(p.check_read_path("/data/x"));
    assert!(!p.check_read_path("/etc/passwd"));

    p.allow_network = true;
    p.allowed_hosts = vec!["example.com".into()];
    assert!(p.check_host("example.com"));
    assert!(!p.check_host("evil.com"));
    // Wildcard host.
    p.allowed_hosts.push("*".into());
    assert!(p.check_host("evil.com"));
}

#[test]
fn config_trusted_ephemeral_with_env() {
    let t = SandboxConfig::trusted();
    assert_eq!(t.max_memory_bytes, 0);
    assert!(t.policy.allow_network);
    let e = SandboxConfig::ephemeral();
    assert!(e.audit_api_calls);
    assert!(!e.policy.allow_network);
    let c = SandboxConfig::default().with_env("K", "V").with_env("A", "B");
    assert_eq!(c.env.get("K"), Some(&"V".to_string()));
    assert_eq!(c.env.get("A"), Some(&"B".to_string()));
}

#[test]
fn resource_usage_limit_check() {
    let mut cfg = SandboxConfig::default();
    cfg.max_memory_bytes = 1024;
    cfg.max_api_calls = 10;
    cfg.max_wall_time = Duration::from_secs(1);
    let mut u = ResourceUsage::default();
    assert!(!u.any_limit_exceeded(&cfg));
    u.peak_memory_bytes = 2048;
    assert!(u.any_limit_exceeded(&cfg));
    u.peak_memory_bytes = 0;
    u.api_calls = 100;
    assert!(u.any_limit_exceeded(&cfg));
    u.api_calls = 0;
    u.wall_time = Duration::from_secs(2);
    assert!(u.any_limit_exceeded(&cfg));
}

// ─── PluginSandboxRunner ──────────────────────────────────────────────────────

#[test]
fn runner_success_failure_panic_paths() {
    let r = PluginSandboxRunner::new();
    let cfg = SandboxConfig::default();
    let ok = r.run_sandboxed("p", &cfg, || Ok("ok".into()));
    assert!(ok.success);
    assert_eq!(ok.return_value.as_deref(), Some("ok"));

    let fail = r.run_sandboxed("p", &cfg, || Err(SandboxError::PolicyViolation("nope".into())));
    assert!(!fail.success);
    assert!(matches!(fail.error, Some(SandboxError::PolicyViolation(_))));

    let panicked = r.run_sandboxed("p", &cfg, || -> Result<String, SandboxError> { panic!("boom"); });
    assert!(!panicked.success);
    assert!(matches!(panicked.error, Some(SandboxError::PluginPanic(_))));
}

#[test]
fn runner_panic_string_payload() {
    let r = PluginSandboxRunner::new();
    let cfg = SandboxConfig::default();
    let res = r.run_sandboxed("p", &cfg, || -> Result<String, SandboxError> {
        let msg: String = String::from("string-panic");
        std::panic::panic_any(msg);
    });
    assert!(!res.success);
    match res.error {
        Some(SandboxError::PluginPanic(m)) => assert!(m == "string-panic" || m == "unknown panic"),
        e => panic!("expected PluginPanic, got {e:?}"),
    }
}

#[test]
fn runner_zero_api_calls_denied() {
    let r = PluginSandboxRunner::new();
    let mut cfg = SandboxConfig::default();
    cfg.max_api_calls = 0;
    let res = r.run_sandboxed("p", &cfg, || Ok("x".into()));
    assert!(!res.success);
    assert!(matches!(res.error, Some(SandboxError::PolicyViolation(_))));
}

#[test]
fn runner_history_and_clear() {
    let r = PluginSandboxRunner::new();
    let cfg = SandboxConfig::default();
    for _ in 0..5 {
        r.run_sandboxed("h", &cfg, || Ok("x".into()));
    }
    assert_eq!(r.run_count("h"), 5);
    assert_eq!(r.history_for("h").len(), 5);
    let cu = r.cumulative_usage("h");
    assert_eq!(cu.api_calls, 5);
    r.clear_history("h");
    assert_eq!(r.run_count("h"), 0);
    assert_eq!(r.history_for("h").len(), 0);
}

#[test]
fn runner_batch_run() {
    let r = PluginSandboxRunner::new();
    let cfg = SandboxConfig::default();
    let tasks: Vec<Box<dyn FnOnce() -> Result<String, SandboxError>>> = (0..10)
        .map(|i| -> Box<dyn FnOnce() -> Result<String, SandboxError>> {
            if i % 3 == 0 {
                Box::new(move || Err(SandboxError::PolicyViolation(format!("no {i}"))))
            } else {
                Box::new(move || Ok(format!("ok-{i}")))
            }
        })
        .collect();
    let results = r.run_batch("batch", &cfg, tasks);
    assert_eq!(results.len(), 10);
    let ok = results.iter().filter(|r| r.success).count();
    let bad = results.iter().filter(|r| !r.success).count();
    assert_eq!(ok + bad, 10);
    assert!(bad > 0);
}

#[test]
fn runner_capture_output_reflects_return_value() {
    let r = PluginSandboxRunner::new();
    let mut cfg = SandboxConfig::default();
    cfg.capture_output = true;
    let res = r.run_sandboxed("cap", &cfg, || Ok("hello".into()));
    assert!(res.success);
    assert_eq!(res.output, "hello");

    let mut cfg2 = SandboxConfig::default();
    cfg2.capture_output = false;
    let res2 = r.run_sandboxed("cap", &cfg2, || Ok("hidden".into()));
    assert!(res2.output.is_empty());
}

#[test]
fn runner_audit_log_populated() {
    let r = PluginSandboxRunner::new();
    let mut cfg = SandboxConfig::default();
    cfg.audit_api_calls = true;
    let res = r.run_sandboxed("audit", &cfg, || Ok("done".into()));
    assert!(res.success);
    assert!(!res.audit_log.is_empty(), "expected audit entries");
    let e = &res.audit_log[0];
    assert!(e.allowed);
    assert!(!e.to_string().is_empty());
}

#[test]
fn runner_check_fs_and_network_helpers() {
    let mut cfg = SandboxConfig::default();
    cfg.policy.allow_fs_read = true;
    cfg.policy.allowed_read_paths = vec!["/plug/".into()];
    assert!(PluginSandboxRunner::check_fs_read(&cfg, "/plug/a"));
    assert!(!PluginSandboxRunner::check_fs_read(&cfg, "/x"));

    cfg.policy.allow_network = true;
    cfg.policy.allowed_hosts = vec!["ok.io".into()];
    assert!(PluginSandboxRunner::check_network(&cfg, "ok.io"));
    assert!(!PluginSandboxRunner::check_network(&cfg, "bad.io"));
}

#[test]
fn runner_send_sync_threaded_stress() {
    let r = Arc::new(PluginSandboxRunner::new());
    let cfg = SandboxConfig::default();
    let mut handles = Vec::new();
    for t in 0..4 {
        let rr = Arc::clone(&r);
        let c = cfg.clone();
        handles.push(thread::spawn(move || {
            for i in 0..100 {
                let id = format!("th-{t}");
                let res = rr.run_sandboxed(&id, &c, move || Ok(format!("{t}-{i}")));
                assert!(res.success);
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
    let mut total = 0;
    for t in 0..4 {
        total += r.run_count(&format!("th-{t}"));
    }
    assert_eq!(total, 400);
}

#[test]
fn sandbox_error_display_all_variants() {
    let errs = [
        SandboxError::CpuTimeExceeded { limit_ms: 5, elapsed_ms: 10 },
        SandboxError::MemoryExceeded { limit_bytes: 100, used_bytes: 200 },
        SandboxError::PolicyViolation("x".into()),
        SandboxError::PluginPanic("p".into()),
        SandboxError::Setup("s".into()),
        SandboxError::EntryNotFound("e".into()),
    ];
    for e in &errs {
        assert!(!e.to_string().is_empty());
        // Eq round-trip.
        assert_eq!(e.clone(), e.clone());
    }
}

#[test]
fn audit_entry_display_with_context() {
    let e = AuditEntry {
        offset_ms: 42,
        api: "fs_read".into(),
        allowed: false,
        context: Some("/etc/passwd".into()),
    };
    let s = e.to_string();
    assert!(s.contains("deny"));
    assert!(s.contains("/etc/passwd"));
    assert!(s.contains("42ms"));
}

#[test]
fn resource_usage_display_format() {
    let u = ResourceUsage {
        wall_time: Duration::from_millis(123),
        peak_memory_bytes: 2048,
        api_calls: 7,
        denied_calls: 1,
        ..Default::default()
    };
    let s = u.to_string();
    assert!(s.contains("calls=7"));
    assert!(s.contains("denied=1"));
}
