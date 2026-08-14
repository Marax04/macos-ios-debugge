//! Blitz test suite for `rustre-plugin-host` — adversarial coverage of
//! public APIs across multiple submodules. Tests are intentionally narrow
//! and assertion-heavy to surface latent bugs.

use rustre_plugin_host::plugin_capability_model::{
    Capability, CapabilityChecker, CapabilityNegotiator, CapabilityPolicy, CapabilityProfile,
    CapabilityRequest, CapabilitySet, FileScope, NetworkScope, ResourceQuota, ResourceUsage,
};
use rustre_plugin_host::plugin_registry_v2::{
    DependencySpec, PluginCapability as RegCapability, PluginState as RegState, PluginVersion,
};
use rustre_plugin_host::plugin_sandbox::{Permission, PermissionSet};
use rustre_plugin_host::{
    DependencyGraph, ExtensionPoint, FilePluginRegistry, HostError, InProcessIpcDispatcher,
    Manifest33, PermissionRequest, PluginMetadata, PluginSandbox, SandboxConfig,
};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

// ── PluginVersion ───────────────────────────────────────────────────────────

#[test]
fn version_parse_valid() {
    let v = PluginVersion::parse("1.2.3").unwrap();
    assert_eq!((v.major, v.minor, v.patch), (1, 2, 3));
}

#[test]
fn version_parse_too_few_parts() {
    assert!(PluginVersion::parse("1.2").is_none());
    assert!(PluginVersion::parse("1").is_none());
    assert!(PluginVersion::parse("").is_none());
}

#[test]
fn version_parse_too_many_parts() {
    // splitn(3) → "1.2.3.4" would parse "3.4" as patch and fail. Verify it fails.
    assert!(PluginVersion::parse("1.2.3.4").is_none());
}

#[test]
fn version_parse_non_numeric() {
    assert!(PluginVersion::parse("a.b.c").is_none());
    assert!(PluginVersion::parse("1.x.3").is_none());
    assert!(PluginVersion::parse("-1.2.3").is_none());
}

#[test]
fn version_display_roundtrip() {
    let v = PluginVersion::new(10, 20, 30);
    assert_eq!(v.display(), "10.20.30");
    let parsed = PluginVersion::parse(&v.display()).unwrap();
    assert_eq!(parsed, v);
}

#[test]
fn version_satisfies_equal() {
    let v = PluginVersion::new(1, 2, 3);
    assert!(v.satisfies(&PluginVersion::new(1, 2, 3)));
}

#[test]
fn version_satisfies_higher_major() {
    let v = PluginVersion::new(2, 0, 0);
    assert!(v.satisfies(&PluginVersion::new(1, 99, 99)));
}

#[test]
fn version_satisfies_lower_major_fails() {
    let v = PluginVersion::new(1, 99, 99);
    assert!(!v.satisfies(&PluginVersion::new(2, 0, 0)));
}

#[test]
fn version_satisfies_patch_boundary() {
    let v = PluginVersion::new(1, 2, 2);
    assert!(!v.satisfies(&PluginVersion::new(1, 2, 3)));
    let v2 = PluginVersion::new(1, 2, 3);
    assert!(v2.satisfies(&PluginVersion::new(1, 2, 3)));
}

#[test]
fn reg_state_active_and_unload() {
    assert!(RegState::Active.is_active());
    assert!(!RegState::Registered.is_active());
    assert!(RegState::Active.can_unload());
    assert!(RegState::Suspended.can_unload());
    assert!(RegState::Failed.can_unload());
    assert!(!RegState::Registered.can_unload());
    assert!(!RegState::Unloaded.can_unload());
}

#[test]
fn dependency_spec_required_vs_optional() {
    let r = DependencySpec::required("a", PluginVersion::new(1, 0, 0));
    assert!(!r.optional);
    let o = DependencySpec::optional("a", PluginVersion::new(1, 0, 0));
    assert!(o.optional);
}

#[test]
fn reg_capability_default_description_empty() {
    let c = RegCapability::new("x", PluginVersion::new(1, 0, 0));
    assert_eq!(c.description, "");
    assert_eq!(c.name, "x");
}

// ── CapabilitySet / class-matching semantics ───────────────────────────────

#[test]
fn capset_unrestricted_always_denied() {
    let mut set = CapabilitySet::new();
    set.allow(Capability::Unrestricted);
    // documented behavior: Unrestricted is always Deny via check()
    assert_eq!(set.check(&Capability::Unrestricted), CapabilityPolicy::Deny);
    assert!(!set.is_allowed(&Capability::Unrestricted));
}

#[test]
fn capset_full_trusted_profile_unrestricted_still_denied() {
    // Even the "full_trusted" profile fails because check() short-circuits.
    let set = CapabilityProfile::full_trusted();
    assert!(!set.is_allowed(&Capability::Unrestricted));
}

#[test]
fn capset_default_deny() {
    let set = CapabilitySet::new();
    assert_eq!(
        set.check(&Capability::ProcessSpawn),
        CapabilityPolicy::Deny
    );
    assert!(!set.is_allowed(&Capability::ProcessSpawn));
}

#[test]
fn capset_explicit_allow_visible_via_check() {
    let mut set = CapabilitySet::new();
    set.allow(Capability::BinaryLoad);
    assert_eq!(set.check(&Capability::BinaryLoad), CapabilityPolicy::Allow);
    assert!(set.is_allowed(&Capability::BinaryLoad));
}

#[test]
fn capset_last_rule_wins_on_conflict() {
    // check() iterates in reverse — last inserted rule should win.
    let mut set = CapabilitySet::new();
    set.allow(Capability::BinaryLoad);
    set.deny(Capability::BinaryLoad);
    assert_eq!(set.check(&Capability::BinaryLoad), CapabilityPolicy::Deny);
}

#[test]
fn capset_class_match_propagates_policy() {
    // FileRead(Anywhere) is allowed → because the class-match uses
    // mem::discriminant, FileRead(ProjectOnly) should also be considered allowed.
    let mut set = CapabilitySet::new();
    set.allow(Capability::FileRead(FileScope::Anywhere));
    let pol = set.check(&Capability::FileRead(FileScope::ProjectOnly));
    assert_eq!(pol, CapabilityPolicy::Allow);
}

#[test]
fn capset_class_match_deny_blocks_other_scope() {
    // A deny on FileWrite(Anywhere) should propagate to FileWrite(TempOnly).
    let mut set = CapabilitySet::new();
    set.deny(Capability::FileWrite(FileScope::Anywhere));
    let pol = set.check(&Capability::FileWrite(FileScope::TempOnly));
    assert_eq!(pol, CapabilityPolicy::Deny);
}

#[test]
fn capset_contains_capability_index() {
    let mut set = CapabilitySet::new();
    assert!(!set.contains_capability(&Capability::BinaryLoad));
    set.allow(Capability::BinaryLoad);
    assert!(set.contains_capability(&Capability::BinaryLoad));
}

#[test]
fn capset_merge_brings_rules() {
    let mut a = CapabilitySet::new();
    a.allow(Capability::IpcSend);
    let mut b = CapabilitySet::new();
    b.allow(Capability::IpcReceive);
    a.merge(&b);
    assert!(a.is_allowed(&Capability::IpcSend));
    assert!(a.is_allowed(&Capability::IpcReceive));
}

#[test]
fn capset_all_allowed_and_denied_lists() {
    let mut set = CapabilitySet::new();
    set.allow(Capability::BinaryLoad);
    set.deny(Capability::ProcessSpawn);
    assert_eq!(set.all_allowed().len(), 1);
    assert_eq!(set.all_denied().len(), 1);
}

#[test]
fn capset_allow_with_reason_records_reason() {
    let mut set = CapabilitySet::new();
    set.allow_with_reason(Capability::BinaryLoad, "for analysis");
    assert!(set.is_allowed(&Capability::BinaryLoad));
}

#[test]
fn profile_readonly_analyst_denies_write() {
    let set = CapabilityProfile::readonly_analyst();
    assert!(!set.is_allowed(&Capability::BinaryModify));
    assert!(set.is_allowed(&Capability::BinaryLoad));
}

#[test]
fn profile_debugger_allows_debug() {
    let set = CapabilityProfile::debugger_plugin();
    assert!(set.is_allowed(&Capability::DebuggerAttach));
    assert!(set.is_allowed(&Capability::BreakpointSet));
}

// ── CapabilityChecker ──────────────────────────────────────────────────────

#[test]
fn checker_records_violation_on_deny() {
    let set = CapabilitySet::new();
    let mut checker = CapabilityChecker::new("p1".into(), set);
    assert!(checker.require(&Capability::ProcessSpawn).is_err());
    assert_eq!(checker.violations(), 1);
}

#[test]
fn checker_passes_on_allow() {
    let mut set = CapabilitySet::new();
    set.allow(Capability::BinaryLoad);
    let mut checker = CapabilityChecker::new("p1".into(), set);
    assert!(checker.require(&Capability::BinaryLoad).is_ok());
    assert_eq!(checker.violations(), 0);
}

#[test]
fn checker_summary_counts() {
    let mut set = CapabilitySet::new();
    set.allow(Capability::BinaryLoad);
    let mut checker = CapabilityChecker::new("p".into(), set);
    let _ = checker.require(&Capability::BinaryLoad);
    let _ = checker.require(&Capability::ProcessSpawn);
    let s = checker.summary();
    // BinaryLoad path is plain Allow, which doesn't append to audit_log.
    // Only the Deny is logged.
    assert_eq!(s.violations, 1);
    assert!(s.denied >= 1);
}

// ── CapabilityNegotiator ───────────────────────────────────────────────────

#[test]
fn negotiator_grants_required_when_allowed() {
    let mut base = CapabilitySet::new();
    base.allow(Capability::BinaryLoad);
    let neg = CapabilityNegotiator::new(base);
    let req = CapabilityRequest {
        plugin_id: "p".into(),
        required: vec![Capability::BinaryLoad],
        optional: vec![Capability::ProcessSpawn],
        justification: HashMap::new(),
    };
    let grant = neg.negotiate(&req);
    assert_eq!(grant.granted.len(), 1);
    assert_eq!(grant.denied.len(), 0);
}

#[test]
fn negotiator_denies_when_not_allowed() {
    let base = CapabilitySet::new();
    let neg = CapabilityNegotiator::new(base);
    let req = CapabilityRequest {
        plugin_id: "p".into(),
        required: vec![Capability::ProcessSpawn],
        optional: vec![],
        justification: HashMap::new(),
    };
    let grant = neg.negotiate(&req);
    assert_eq!(grant.denied.len(), 1);
}

// ── ResourceQuota / Usage ──────────────────────────────────────────────────

#[test]
fn quota_default_within_for_zero_usage() {
    let q = ResourceQuota::default();
    let u = ResourceUsage::default();
    assert!(u.is_within(&q));
    assert!(u.exceeds(&q).is_empty());
}

#[test]
fn quota_memory_exceeds() {
    let q = ResourceQuota::default();
    let u = ResourceUsage {
        memory_mb: q.max_memory_mb + 1,
        ..Default::default()
    };
    let v = u.exceeds(&q);
    assert!(!v.is_empty());
    assert!(v.iter().any(|m| m.contains("memory")));
}

#[test]
fn quota_runtime_none_means_unlimited() {
    let q = ResourceQuota {
        max_runtime_seconds: None,
        ..ResourceQuota::default()
    };
    let u = ResourceUsage {
        runtime_seconds: u64::MAX,
        ..Default::default()
    };
    // Other fields are zero, so the only potential violation is runtime which
    // is disabled. Expect no violations.
    assert!(u.is_within(&q));
}

#[test]
fn quota_all_fields_exceed() {
    let q = ResourceQuota::default();
    let u = ResourceUsage {
        memory_mb: u64::MAX,
        cpu_percent: 100.0,
        file_handles: u32::MAX,
        network_connections: u32::MAX,
        threads: u32::MAX,
        runtime_seconds: u64::MAX,
    };
    let v = u.exceeds(&q);
    assert!(v.len() >= 5);
}

// ── plugin_sandbox::PermissionSet ──────────────────────────────────────────

#[test]
fn perm_set_has_filesystem_prefix() {
    let p = PermissionSet::new().allow(Permission::FileSystem(PathBuf::from("/tmp")));
    assert!(p.has_filesystem(Path::new("/tmp/sub/file")));
    assert!(!p.has_filesystem(Path::new("/etc")));
}

#[test]
fn perm_set_unique_count_ignores_dupes() {
    let mut p = PermissionSet::new();
    p.grant(Permission::Network);
    p.grant(Permission::Network);
    p.grant(Permission::Ui);
    assert_eq!(p.len(), 3);
    assert_eq!(p.unique_count(), 2);
}

#[test]
fn perm_display_variants() {
    assert_eq!(Permission::Network.to_string(), "network");
    assert_eq!(Permission::Ui.to_string(), "ui");
    assert_eq!(
        Permission::Custom("x".into()).to_string(),
        "custom:x"
    );
    let fs = Permission::FileSystem(PathBuf::from("/tmp"));
    assert!(fs.to_string().starts_with("filesystem:"));
}

// ── PluginSandbox (from lib.rs §33) ────────────────────────────────────────

#[test]
fn plugin_sandbox_default_is_deny_all() {
    let s = PluginSandbox::default();
    assert!(!s.check_fs_read(Path::new("/")));
    assert!(!s.has_unsafe_ffi());
}

#[test]
fn plugin_sandbox_glob_doublestar_matches_anything() {
    let s = PluginSandbox::new(vec![PermissionRequest::FsRead {
        paths: vec!["**".into()],
    }]);
    assert!(s.check_fs_read(Path::new("/etc/passwd")));
    assert!(s.check_fs_read(Path::new("anything")));
}

#[test]
fn plugin_sandbox_network_star_wildcard() {
    let s = PluginSandbox::new(vec![PermissionRequest::Network {
        hosts: vec!["*".into()],
    }]);
    assert!(s.check_network("evil.example"));
    assert!(s.check_network(""));
}

// ── Manifest33 TOML ────────────────────────────────────────────────────────

#[test]
fn manifest_from_toml_missing_required_field_errors() {
    let toml = r#"name = "x""#; // missing version/author/etc
    let r = Manifest33::from_toml(toml);
    assert!(r.is_err());
}

#[test]
fn manifest_from_toml_with_permissions() {
    let toml = r#"
name = "p"
version = "1.0"
author = "a"
description = "d"
min_api_version = "0.1"
permissions = [{ kind = "unsafe_ffi" }]
"#;
    let m = Manifest33::from_toml(toml).unwrap();
    assert!(m.has_elevated_permissions());
}

#[test]
fn manifest_empty_string_fields_allowed() {
    let m = Manifest33::new("", "", "", "", "");
    assert!(m.to_toml().is_ok());
}

// ── PermissionRequest ───────────────────────────────────────────────────────

#[test]
fn permission_request_display_subprocess() {
    let p = PermissionRequest::Subprocess {
        commands: vec!["ls".into(), "cat".into()],
    };
    let s = p.to_string();
    assert!(s.contains("ls"));
    assert!(s.contains("cat"));
}

#[test]
fn permission_request_serde_all_variants() {
    let variants = vec![
        PermissionRequest::FsRead { paths: vec!["a".into()] },
        PermissionRequest::FsWrite { paths: vec![] },
        PermissionRequest::Network { hosts: vec!["h".into()] },
        PermissionRequest::Subprocess { commands: vec![] },
        PermissionRequest::FullMemoryAccess,
        PermissionRequest::UnsafeFfi,
    ];
    for v in variants {
        let j = serde_json::to_string(&v).unwrap();
        let back: PermissionRequest = serde_json::from_str(&j).unwrap();
        assert_eq!(v, back);
    }
}

// ── DependencyGraph ─────────────────────────────────────────────────────────

#[test]
fn dep_graph_topological_simple_chain() {
    let mut g = DependencyGraph::new();
    g.add_dependency("b", "a");
    g.add_dependency("c", "b");
    let order = g.topological_order().unwrap();
    let pos = |s: &str| order.iter().position(|x| x == s).unwrap();
    assert!(pos("a") < pos("b"));
    assert!(pos("b") < pos("c"));
}

#[test]
fn dep_graph_topological_cycle_detected() {
    let mut g = DependencyGraph::new();
    g.add_dependency("a", "b");
    g.add_dependency("b", "a");
    let r = g.topological_order();
    assert!(r.is_err(), "expected cycle error, got {:?}", r);
}

#[test]
fn dep_graph_self_cycle_detected() {
    let mut g = DependencyGraph::new();
    g.add_dependency("a", "a");
    let r = g.topological_order();
    assert!(r.is_err(), "self-cycle must be detected, got {:?}", r);
}

#[test]
fn dep_graph_check_dependencies_present() {
    let mut g = DependencyGraph::new();
    g.add_dependency("b", "a");
    assert!(g.check_dependencies("b", &["a".into()]).is_ok());
}

#[test]
fn dep_graph_check_dependencies_specific_missing_variant() {
    let mut g = DependencyGraph::new();
    g.add_dependency("b", "a");
    let r = g.check_dependencies("b", &[]);
    match r {
        Err(HostError::DependencyMissing(d)) => assert_eq!(d, "a"),
        other => panic!("expected DependencyMissing(\"a\"), got {:?}", other),
    }
}

// ── SandboxConfig adversarial ──────────────────────────────────────────────

#[test]
fn sandbox_config_allowed_hosts_empty_with_network_allows_any() {
    let cfg = SandboxConfig::permissive();
    assert!(cfg.allowed_hosts.is_empty());
    assert!(cfg.check_network("anything.example").is_ok());
}

#[test]
fn sandbox_config_serde_roundtrip() {
    let cfg = SandboxConfig::permissive();
    let j = serde_json::to_string(&cfg).unwrap();
    let back: SandboxConfig = serde_json::from_str(&j).unwrap();
    assert_eq!(back.allow_network, cfg.allow_network);
    assert_eq!(back.max_memory_mb, cfg.max_memory_mb);
}

// ── PluginMetadata edge cases ──────────────────────────────────────────────

#[test]
fn plugin_metadata_is_active_requires_all_conditions() {
    let m = Manifest33::new("x", "1", "a", "d", "0.1");
    let mut meta = PluginMetadata::new(m, PathBuf::from("/x"));
    assert!(!meta.is_active());
    meta.enabled = true;
    assert!(!meta.is_active()); // not loaded yet
    meta.mark_loaded();
    assert!(meta.is_active());
    meta.set_error("boom");
    assert!(!meta.is_active()); // error clears loaded
}

// ── FilePluginRegistry adversarial ─────────────────────────────────────────

#[test]
fn file_registry_ignores_non_toml_files() {
    let tmp = std::env::temp_dir().join("rustre_blitz_nontoml");
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).unwrap();
    std::fs::write(tmp.join("readme.txt"), "ignore me").unwrap();
    std::fs::write(tmp.join("data.json"), "{}").unwrap();
    let mut reg = FilePluginRegistry::new(tmp.clone());
    let count = reg.scan_directory().unwrap();
    assert_eq!(count, 0);
    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn file_registry_malformed_toml_skipped_not_errored() {
    let tmp = std::env::temp_dir().join("rustre_blitz_bad_toml");
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).unwrap();
    std::fs::write(tmp.join("bad.toml"), "this is = not [ valid").unwrap();
    let mut reg = FilePluginRegistry::new(tmp.clone());
    let r = reg.scan_directory();
    assert!(r.is_ok(), "scan should tolerate bad manifests, got {:?}", r);
    assert_eq!(r.unwrap(), 0);
    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn file_registry_scan_idempotent() {
    let tmp = std::env::temp_dir().join("rustre_blitz_idem");
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).unwrap();
    let manifest = r#"
name = "com.idem"
version = "1.0.0"
author = "a"
description = "d"
min_api_version = "0.1"
"#;
    std::fs::write(tmp.join("p.toml"), manifest).unwrap();
    let mut reg = FilePluginRegistry::new(tmp.clone());
    assert_eq!(reg.scan_directory().unwrap(), 1);
    // Second scan finds no NEW plugins.
    assert_eq!(reg.scan_directory().unwrap(), 0);
    assert_eq!(reg.len(), 1);
    let _ = std::fs::remove_dir_all(&tmp);
}

// ── InProcessIpcDispatcher concurrency / behavior ──────────────────────────

#[test]
fn ipc_dispatcher_reregister_replaces_handler() {
    let d = InProcessIpcDispatcher::new();
    d.register("m", |_| {
        Ok(rustre_plugin_api::PluginValue::String("v1".into()))
    });
    d.register("m", |_| {
        Ok(rustre_plugin_api::PluginValue::String("v2".into()))
    });
    let r = d
        .dispatch("m", rustre_plugin_api::PluginValue::Null)
        .unwrap();
    assert_eq!(r, rustre_plugin_api::PluginValue::String("v2".into()));
}

#[test]
fn ipc_dispatcher_is_send_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<InProcessIpcDispatcher>();
}

// ── ExtensionPoint coverage ────────────────────────────────────────────────

#[test]
fn extension_point_all_tags_unique_for_unit_variants() {
    let tags = [
        ExtensionPoint::Loader.tag(),
        ExtensionPoint::Architecture.tag(),
        ExtensionPoint::AnalysisPass.tag(),
        ExtensionPoint::DeobfPass.tag(),
        ExtensionPoint::Dissector.tag(),
        ExtensionPoint::MemPlugin.tag(),
        ExtensionPoint::Decompiler.tag(),
        ExtensionPoint::Theme.tag(),
        ExtensionPoint::View.tag(),
        ExtensionPoint::Workflow.tag(),
        ExtensionPoint::IntelProvider.tag(),
        ExtensionPoint::LlmBackend.tag(),
    ];
    let mut sorted = tags.to_vec();
    sorted.sort_unstable();
    let len_before = sorted.len();
    sorted.dedup();
    assert_eq!(len_before, sorted.len(), "tags collide: {:?}", tags);
}

#[test]
fn extension_point_eq_and_hash_consistent() {
    use std::collections::HashSet;
    let mut s: HashSet<ExtensionPoint> = HashSet::new();
    s.insert(ExtensionPoint::Loader);
    s.insert(ExtensionPoint::Loader); // duplicate
    s.insert(ExtensionPoint::Decompiler);
    assert_eq!(s.len(), 2);
    s.insert(ExtensionPoint::Action {
        name: "x".into(),
        menu: "y".into(),
    });
    s.insert(ExtensionPoint::Action {
        name: "x".into(),
        menu: "y".into(),
    });
    assert_eq!(s.len(), 3);
}

// ── NetworkScope / FileScope serde ─────────────────────────────────────────

#[test]
fn network_scope_serde_roundtrip() {
    let v = NetworkScope::SpecificHost("api.example".into());
    let j = serde_json::to_string(&v).unwrap();
    let back: NetworkScope = serde_json::from_str(&j).unwrap();
    assert_eq!(v, back);
}

#[test]
fn file_scope_serde_roundtrip() {
    let v = FileScope::ReadonlyPaths(vec!["/a".into(), "/b".into()]);
    let j = serde_json::to_string(&v).unwrap();
    let back: FileScope = serde_json::from_str(&j).unwrap();
    assert_eq!(v, back);
}
