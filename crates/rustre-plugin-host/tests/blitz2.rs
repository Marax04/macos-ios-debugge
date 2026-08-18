//! Deep adversarial integration tests for rustre-plugin-host.


use rustre_plugin_host::{
    DependencyGraph, ExtensionPoint, FilePluginRegistry, HostError, HostEvent,
    InProcessIpcDispatcher, Manifest33, NativePlugin, NativePluginRegistry, PermissionRequest,
    PluginEntry, PluginHost, PluginMetadata, PluginSandbox, PluginSource, SandboxConfig,
};
use rustre_plugin_api::{
    Plugin, PluginCapability, PluginError, PluginManifest, PluginMeta, PluginSettings, PluginValue, SettingValue, Version,
};
use parking_lot::RwLock;
use std::any::Any;
use std::path::{Path, PathBuf};
use std::sync::Arc;

// ── Test helpers ─────────────────────────────────────────────────────────────

#[derive(Debug)]
struct StubPlugin {
    meta: PluginMeta,
    version: Version,
    capability: PluginCapability,
}

impl StubPlugin {
    fn new(id: &str) -> Self {
        Self {
            meta: PluginMeta::new(id.to_string(), id.to_string(), PluginCapability::Loader),
            version: Version::new(1, 0, 0),
            capability: PluginCapability::Loader,
        }
    }
}

impl Plugin for StubPlugin {
    fn name(&self) -> &str {
        &self.meta.name
    }
    fn version(&self) -> &Version {
        &self.version
    }
    fn capabilities(&self) -> Vec<PluginCapability> {
        vec![self.capability.clone()]
    }
    fn manifest(&self) -> PluginManifest {
        PluginManifest::from_meta(self.meta.clone())
    }
    fn init(
        &self,
        _ctx: &mut rustre_plugin_api::PluginContext,
    ) -> Result<(), PluginError> {
        Ok(())
    }
    fn unload(&self, _ctx: &mut rustre_plugin_api::PluginContext) {}
    fn as_any(&self) -> &dyn Any {
        self
    }
}

fn inline(id: &str) -> PluginSource {
    PluginSource::Inline(Arc::new(RwLock::new(StubPlugin::new(id))))
}

struct Lcg(u64);
impl Lcg {
    fn new() -> Self {
        Self(0xDEAD_BEEF_CAFE_BABE)
    }
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        self.0
    }
}

// ── HostError ────────────────────────────────────────────────────────────────

#[test]
fn host_error_display_variants() {
    assert!(HostError::Load("x".into()).to_string().contains('x'));
    assert!(HostError::SymbolNotFound("s".into()).to_string().contains('s'));
    assert!(HostError::Ipc("i".into()).to_string().contains('i'));
    assert!(HostError::Timeout.to_string().contains("timeout"));
    assert!(HostError::Other("o".into()).to_string().contains('o'));
}

#[test]
fn host_error_from_anyhow_lcg_fuzz() {
    let mut lcg = Lcg::new();
    for _ in 0..60 {
        let s = format!("err-{}", lcg.next());
        let e: HostError = anyhow::anyhow!(s.clone()).into();
        assert!(matches!(e, HostError::Other(ref m) if m.contains("err-")));
    }
}

#[test]
fn host_error_from_plugin_error_chain() {
    let pe = PluginError::NotFound("nope".into());
    let he: HostError = pe.into();
    assert!(matches!(he, HostError::Plugin(_)));
    assert!(he.to_string().contains("nope"));
}

// ── PluginSource ─────────────────────────────────────────────────────────────

#[test]
fn plugin_source_display_dynlib_inline_builtin() {
    let dl = PluginSource::DynLib(PathBuf::from("/x/y.so"));
    assert!(dl.to_string().starts_with("dynlib:"));
    assert_eq!(inline("a").to_string(), "inline");
    assert_eq!(
        PluginSource::BuiltIn("b".into()).to_string(),
        "builtin:b"
    );
}

#[test]
fn plugin_source_debug_does_not_panic_on_inline() {
    let s = inline("debug-id");
    let _ = format!("{s:?}");
}

// ── SandboxConfig ────────────────────────────────────────────────────────────

#[test]
fn sandbox_config_default_denies() {
    let c = SandboxConfig::default();
    assert!(c.check_fs_read().is_err());
    assert!(c.check_network("h").is_err());
}

#[test]
fn sandbox_config_permissive_allows_any_host() {
    let c = SandboxConfig::permissive();
    assert!(c.check_fs_read().is_ok());
    assert!(c.check_network("anywhere.example").is_ok());
}

#[test]
fn sandbox_config_allowlist_enforced() {
    let mut c = SandboxConfig::permissive();
    c.allowed_hosts = vec!["good.com".into(), "ok.org".into()];
    assert!(c.check_network("good.com").is_ok());
    assert!(c.check_network("ok.org").is_ok());
    assert!(c.check_network("bad.net").is_err());
}

#[test]
fn sandbox_config_lcg_fuzz_check_network_never_panics() {
    let mut lcg = Lcg::new();
    let cfg = SandboxConfig::default();
    for _ in 0..120 {
        let host = format!("h{}.example", lcg.next() & 0xFFFF);
        let _ = cfg.check_network(&host);
    }
}

// ── DependencyGraph ──────────────────────────────────────────────────────────

#[test]
fn dependency_graph_empty_ok() {
    let g = DependencyGraph::new();
    assert!(g.check_dependencies("anything", &[]).is_ok());
    assert!(g.dependencies_of("nope").is_empty());
}

#[test]
fn dependency_graph_missing_dep_errors() {
    let mut g = DependencyGraph::new();
    g.add_dependency("p", "q");
    let r = g.check_dependencies("p", &[]);
    assert!(matches!(r, Err(HostError::DependencyMissing(d)) if d == "q"));
}

#[test]
fn dependency_graph_satisfied_chain() {
    let mut g = DependencyGraph::new();
    g.add_dependency("b", "a");
    g.add_dependency("c", "b");
    let loaded = vec!["a".into(), "b".into()];
    assert!(g.check_dependencies("c", &loaded).is_ok());
}

#[test]
fn dependency_graph_topo_order_contains_all_nodes() {
    let mut g = DependencyGraph::new();
    g.add_dependency("c", "b");
    g.add_dependency("b", "a");
    let order = g.topological_order().expect("acyclic");
    assert!(order.contains(&"a".to_string()));
    assert!(order.contains(&"b".to_string()));
    assert!(order.contains(&"c".to_string()));
    let pa = order.iter().position(|x| x == "a").unwrap();
    let pb = order.iter().position(|x| x == "b").unwrap();
    let pc = order.iter().position(|x| x == "c").unwrap();
    assert!(pa < pb && pb < pc, "topo: {order:?}");
}

#[test]
fn dependency_graph_cycle_detected() {
    let mut g = DependencyGraph::new();
    g.add_dependency("a", "b");
    g.add_dependency("b", "a");
    assert!(g.topological_order().is_err());
}

#[test]
fn dependency_graph_dependencies_of_listing() {
    let mut g = DependencyGraph::new();
    g.add_dependency("x", "y");
    g.add_dependency("x", "z");
    let mut deps = g.dependencies_of("x");
    deps.sort_unstable();
    assert_eq!(deps, vec!["y", "z"]);
}

// ── PermissionRequest ────────────────────────────────────────────────────────

#[test]
fn permission_request_kind_names_all() {
    assert_eq!(
        PermissionRequest::FsRead { paths: vec![] }.kind_name(),
        "fs_read"
    );
    assert_eq!(
        PermissionRequest::FsWrite { paths: vec![] }.kind_name(),
        "fs_write"
    );
    assert_eq!(
        PermissionRequest::Network { hosts: vec![] }.kind_name(),
        "network"
    );
    assert_eq!(
        PermissionRequest::Subprocess { commands: vec![] }.kind_name(),
        "subprocess"
    );
    assert_eq!(
        PermissionRequest::FullMemoryAccess.kind_name(),
        "full_memory_access"
    );
    assert_eq!(PermissionRequest::UnsafeFfi.kind_name(), "unsafe_ffi");
}

#[test]
fn permission_request_elevated_and_filesystem() {
    assert!(PermissionRequest::FullMemoryAccess.is_elevated());
    assert!(PermissionRequest::UnsafeFfi.is_elevated());
    assert!(!PermissionRequest::FsRead { paths: vec![] }.is_elevated());
    assert!(PermissionRequest::FsRead { paths: vec![] }.is_filesystem());
    assert!(PermissionRequest::FsWrite { paths: vec![] }.is_filesystem());
    assert!(!PermissionRequest::Network { hosts: vec![] }.is_filesystem());
    assert!(!PermissionRequest::FullMemoryAccess.is_filesystem());
}

#[test]
fn permission_request_eq_consistency_pairs() {
    let mut lcg = Lcg::new();
    for _ in 0..40 {
        let n = (lcg.next() & 0xF) as usize;
        let a = PermissionRequest::FsRead {
            paths: vec![format!("/p/{n}")],
        };
        let b = PermissionRequest::FsRead {
            paths: vec![format!("/p/{n}")],
        };
        assert_eq!(a, b);
    }
}

#[test]
fn permission_request_serde_json_roundtrip_each_variant() {
    let cases = vec![
        PermissionRequest::FsRead {
            paths: vec!["/a".into(), "/b".into()],
        },
        PermissionRequest::FsWrite {
            paths: vec!["/c".into()],
        },
        PermissionRequest::Network {
            hosts: vec!["x.com".into()],
        },
        PermissionRequest::Subprocess {
            commands: vec!["ls".into()],
        },
        PermissionRequest::FullMemoryAccess,
        PermissionRequest::UnsafeFfi,
    ];
    for p in cases {
        let j = serde_json::to_string(&p).unwrap();
        let q: PermissionRequest = serde_json::from_str(&j).unwrap();
        assert_eq!(p, q);
    }
}

#[test]
fn permission_request_display_includes_payload() {
    let p = PermissionRequest::Subprocess {
        commands: vec!["rm".into(), "mv".into()],
    };
    let s = p.to_string();
    assert!(s.contains("rm"));
    assert!(s.contains("mv"));
}

// ── ExtensionPoint ───────────────────────────────────────────────────────────

#[test]
fn extension_point_tag_table() {
    let cases: &[(ExtensionPoint, &str)] = &[
        (ExtensionPoint::Loader, "loader"),
        (ExtensionPoint::Architecture, "architecture"),
        (ExtensionPoint::AnalysisPass, "analysis_pass"),
        (ExtensionPoint::DeobfPass, "deobf_pass"),
        (ExtensionPoint::Dissector, "dissector"),
        (ExtensionPoint::MemPlugin, "mem_plugin"),
        (ExtensionPoint::Decompiler, "decompiler"),
        (ExtensionPoint::Theme, "theme"),
        (ExtensionPoint::View, "view"),
        (ExtensionPoint::Workflow, "workflow"),
        (ExtensionPoint::IntelProvider, "intel_provider"),
        (ExtensionPoint::LlmBackend, "llm_backend"),
    ];
    for (ep, tag) in cases {
        assert_eq!(ep.tag(), *tag);
    }
}

#[test]
fn extension_point_requires_ui_thread_categorization() {
    assert!(ExtensionPoint::Theme.requires_ui_thread());
    assert!(ExtensionPoint::View.requires_ui_thread());
    assert!(ExtensionPoint::Action {
        name: "n".into(),
        menu: "m".into()
    }
    .requires_ui_thread());
    for ep in [
        ExtensionPoint::Loader,
        ExtensionPoint::Architecture,
        ExtensionPoint::AnalysisPass,
        ExtensionPoint::Decompiler,
        ExtensionPoint::Workflow,
    ] {
        assert!(!ep.requires_ui_thread());
    }
}

#[test]
fn extension_point_display_payloaded() {
    let a = ExtensionPoint::Action {
        name: "Run".into(),
        menu: "File".into(),
    };
    assert_eq!(a.to_string(), "action(File/Run)");
    let m = ExtensionPoint::McpTool {
        tool_name: "T".into(),
    };
    assert_eq!(m.to_string(), "mcp_tool(T)");
}

#[test]
fn extension_point_serde_roundtrip_lcg() {
    let mut lcg = Lcg::new();
    for _ in 0..40 {
        let n = lcg.next();
        let ep = ExtensionPoint::McpTool {
            tool_name: format!("tool_{n}"),
        };
        let j = serde_json::to_string(&ep).unwrap();
        let back: ExtensionPoint = serde_json::from_str(&j).unwrap();
        assert_eq!(ep, back);
    }
}

// ── Manifest33 ───────────────────────────────────────────────────────────────

#[test]
fn manifest33_toml_roundtrip_fuzz() {
    let mut lcg = Lcg::new();
    for _ in 0..30 {
        let n = lcg.next() & 0xFFFF;
        let mut m = Manifest33::new(
            format!("com.x.{n}"),
            "1.0.0",
            "Author",
            "Desc",
            "0.1",
        );
        if n & 1 == 0 {
            m.permissions.push(PermissionRequest::UnsafeFfi);
        }
        if n & 2 == 0 {
            m.extension_points.push(ExtensionPoint::Loader);
        }
        let s = m.to_toml().unwrap();
        let back = Manifest33::from_toml(&s).unwrap();
        assert_eq!(back.name, m.name);
        assert_eq!(back.permissions.len(), m.permissions.len());
        assert_eq!(back.extension_points.len(), m.extension_points.len());
    }
}

#[test]
fn manifest33_from_toml_malformed_lcg() {
    let mut lcg = Lcg::new();
    for _ in 0..60 {
        let garbage = format!("===bad {} {}=\n[", lcg.next(), lcg.next());
        let r = Manifest33::from_toml(&garbage);
        assert!(r.is_err(), "garbage should not parse: {garbage}");
    }
}

#[test]
fn manifest33_from_toml_empty_string_errors() {
    assert!(Manifest33::from_toml("").is_err());
}

#[test]
fn manifest33_has_elevated_permissions() {
    let mut m = Manifest33::new("a", "1", "b", "c", "d");
    assert!(!m.has_elevated_permissions());
    m.permissions.push(PermissionRequest::FullMemoryAccess);
    assert!(m.has_elevated_permissions());
}

// ── PluginMetadata ───────────────────────────────────────────────────────────

#[test]
fn plugin_metadata_is_active_truth_table() {
    let m = Manifest33::new("a", "1", "b", "c", "d");
    let mut meta = PluginMetadata::new(m, PathBuf::from("/p"));
    assert!(!meta.is_active());
    meta.enabled = true;
    assert!(!meta.is_active());
    meta.mark_loaded();
    assert!(meta.is_active());
    meta.set_error("e");
    assert!(!meta.is_active());
    assert!(!meta.loaded);
    meta.mark_loaded();
    assert!(meta.load_error.is_none());
    assert!(meta.is_active());
}

#[test]
fn plugin_metadata_display_name_and_display_trait() {
    let m = Manifest33::new("com.disp", "1.0", "A", "D", "0.1");
    let meta = PluginMetadata::new(m, PathBuf::from("/x"));
    assert_eq!(meta.display_name(), "com.disp");
    assert!(meta.to_string().contains("com.disp"));
}

// ── PluginSandbox ────────────────────────────────────────────────────────────

#[test]
fn plugin_sandbox_deny_all_blocks_everything() {
    let s = PluginSandbox::deny_all();
    assert!(!s.check_fs_read(Path::new("/x")));
    assert!(!s.check_fs_write(Path::new("/x")));
    assert!(!s.check_network("h"));
    assert!(!s.check_subprocess("c"));
    assert!(!s.has_full_memory_access());
    assert!(!s.has_unsafe_ffi());
}

#[test]
fn plugin_sandbox_unrestricted_allows_everything_lcg() {
    let s = PluginSandbox::unrestricted();
    let mut lcg = Lcg::new();
    for _ in 0..50 {
        let p = PathBuf::from(format!("/r/{}", lcg.next()));
        assert!(s.check_fs_read(&p));
        assert!(s.check_fs_write(&p));
        assert!(s.check_network(&format!("h{}", lcg.next())));
        assert!(s.check_subprocess(&format!("c{}", lcg.next())));
    }
}

#[test]
fn plugin_sandbox_default_is_deny_all() {
    let s = PluginSandbox::default();
    assert!(s.allowed_permissions.is_empty());
    assert!(!s.check_network("anywhere"));
}

#[test]
fn plugin_sandbox_specific_path_exact_match_only() {
    let s = PluginSandbox::new(vec![PermissionRequest::FsRead {
        paths: vec!["/safe".into()],
    }]);
    assert!(s.check_fs_read(Path::new("/safe")));
    assert!(!s.check_fs_read(Path::new("/safe/sub")));
    assert!(!s.check_fs_read(Path::new("/unsafe")));
}

#[test]
fn plugin_sandbox_glob_double_star_matches_any_path() {
    let s = PluginSandbox::new(vec![PermissionRequest::FsWrite {
        paths: vec!["**".into()],
    }]);
    assert!(s.check_fs_write(Path::new("/anywhere/at/all")));
    assert!(s.check_fs_write(Path::new("/")));
}

#[test]
fn plugin_sandbox_network_wildcard_star_matches_any_host() {
    let s = PluginSandbox::new(vec![PermissionRequest::Network {
        hosts: vec!["*".into()],
    }]);
    let mut lcg = Lcg::new();
    for _ in 0..40 {
        let h = format!("h{}", lcg.next());
        assert!(s.check_network(&h));
    }
}

#[test]
fn plugin_sandbox_display_lists_perms() {
    let s = PluginSandbox::new(vec![
        PermissionRequest::UnsafeFfi,
        PermissionRequest::FullMemoryAccess,
    ]);
    let d = s.to_string();
    assert!(d.contains("unsafe_ffi"));
    assert!(d.contains("full_memory_access"));
}

// ── InProcessIpcDispatcher ───────────────────────────────────────────────────

#[test]
fn ipc_dispatcher_unknown_returns_err() {
    let d = InProcessIpcDispatcher::new();
    assert!(d.dispatch("missing", PluginValue::Null).is_err());
}

#[test]
fn ipc_dispatcher_register_and_dispatch_many() {
    let d = InProcessIpcDispatcher::new();
    for i in 0..50u64 {
        let signed = i64::try_from(i).expect("loop bound 50 fits in i64");
        d.register(format!("m{i}"), move |_| Ok(PluginValue::Int(signed)));
    }
    for i in 0..50u64 {
        let r = d.dispatch(&format!("m{i}"), PluginValue::Null).unwrap();
        assert_eq!(
            r,
            PluginValue::Int(i64::try_from(i).expect("loop bound 50 fits in i64"))
        );
    }
    assert_eq!(d.method_names().len(), 50);
}

#[test]
fn ipc_dispatcher_handler_can_return_err() {
    let d = InProcessIpcDispatcher::new();
    d.register("bad", |_| Err(HostError::Ipc("nope".into())));
    let r = d.dispatch("bad", PluginValue::Null);
    assert!(matches!(r, Err(HostError::Ipc(_))));
}

// ── PluginHost end-to-end ────────────────────────────────────────────────────

#[test]
fn host_load_then_unload_clears_registry() {
    let host = PluginHost::new_without_db();
    let id = host
        .load_plugin(inline("com.a"), PluginSettings::new())
        .unwrap();
    assert_eq!(id, "com.a");
    assert_eq!(host.active_count(), 1);
    host.unload_plugin("com.a").unwrap();
    assert_eq!(host.registry().count(), 0);
    assert!(host.health("com.a").is_none());
    assert!(host.get_settings("com.a").is_err());
}

#[test]
fn host_load_duplicate_short_id_rejected() {
    let host = PluginHost::new_without_db();
    host.load_plugin(inline("dup"), PluginSettings::new()).unwrap();
    let r = host.load_plugin(inline("dup"), PluginSettings::new());
    assert!(r.is_err());
}

#[test]
fn host_load_dynlib_unsupported_yields_load_err() {
    let host = PluginHost::new_without_db();
    let r = host.load_plugin(
        PluginSource::DynLib(PathBuf::from("/nope.so")),
        PluginSettings::new(),
    );
    assert!(matches!(r, Err(HostError::Load(_))));
}

#[test]
fn host_load_builtin_unknown_yields_load_err() {
    let host = PluginHost::new_without_db();
    let r = host.load_plugin(
        PluginSource::BuiltIn("nope".into()),
        PluginSettings::new(),
    );
    assert!(matches!(r, Err(HostError::Load(_))));
}

#[test]
fn host_unload_nonexistent_errors() {
    let host = PluginHost::new_without_db();
    let r = host.unload_plugin("ghost");
    assert!(r.is_err());
}

#[test]
fn host_suspend_resume_nonexistent_errors() {
    let host = PluginHost::new_without_db();
    assert!(host.suspend_plugin("ghost").is_err());
    assert!(host.resume_plugin("ghost").is_err());
}

#[test]
fn host_settings_update_round_trip() {
    let host = PluginHost::new_without_db();
    host.load_plugin(inline("s1"), PluginSettings::new()).unwrap();
    let mut s = PluginSettings::new();
    s.set("k", SettingValue::Int(42));
    host.update_settings("s1", s).unwrap();
    assert_eq!(host.get_settings("s1").unwrap().get_int("k"), Some(42));
}

#[test]
fn host_settings_update_unknown_id_errors() {
    let host = PluginHost::new_without_db();
    let r = host.update_settings("ghost", PluginSettings::new());
    assert!(r.is_err());
}

#[test]
fn host_sandbox_get_set_default_after_load() {
    let host = PluginHost::new_without_db();
    host.load_plugin(inline("sb"), PluginSettings::new()).unwrap();
    let cfg = host.get_sandbox("sb").unwrap();
    assert!(!cfg.allow_fs_read);
    host.set_sandbox("sb", SandboxConfig::permissive());
    assert!(host.sandbox_check_fs_read("sb").is_ok());
}

#[test]
fn host_sandbox_check_no_policy_allows() {
    let host = PluginHost::new_without_db();
    // No plugin loaded; absent policy is permissive.
    assert!(host.sandbox_check_fs_read("nobody").is_ok());
}

#[test]
fn host_record_error_increments_health() {
    let host = PluginHost::new_without_db();
    host.load_plugin(inline("h1"), PluginSettings::new()).unwrap();
    host.record_error("h1", "boom1");
    host.record_error("h1", "boom2");
    let h = host.health("h1").unwrap();
    assert_eq!(h.error_count, 2);
    assert!(!h.healthy);
}

#[test]
fn host_event_log_contains_loaded_then_unloaded() {
    let host = PluginHost::new_without_db();
    host.load_plugin(inline("ev"), PluginSettings::new()).unwrap();
    host.unload_plugin("ev").unwrap();
    let log = host.event_log();
    let loaded = log
        .iter()
        .any(|e| matches!(e, HostEvent::PluginLoaded(i) if i == "ev"));
    let unloaded = log
        .iter()
        .any(|e| matches!(e, HostEvent::PluginUnloaded(i) if i == "ev"));
    assert!(loaded && unloaded);
}

#[test]
fn host_events_matching_filter() {
    let host = PluginHost::new_without_db();
    host.load_plugin(inline("f1"), PluginSettings::new()).unwrap();
    let evs = host.events_matching("PluginLoaded");
    assert!(!evs.is_empty());
    for e in evs {
        assert!(e.to_string().starts_with("PluginLoaded"));
    }
}

#[test]
fn host_register_manifest_and_lookup() {
    let host = PluginHost::new_without_db();
    let meta = PluginMeta::new("m", "N", PluginCapability::Loader);
    let manifest = PluginManifest::from_meta(meta);
    host.register_manifest(manifest);
    assert_eq!(host.all_manifests().len(), 1);
    assert!(host.get_manifest("N@0.0.0").is_some());
    assert!(host.get_manifest("nope").is_none());
}

#[test]
fn host_in_memory_persists_entry_roundtrip() {
    let host = PluginHost::new_in_memory().unwrap();
    host.load_plugin(inline("p1"), PluginSettings::new()).unwrap();
    let entries = host.load_persisted_entries().unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].meta.id, "p1");
}

#[test]
fn host_load_persisted_entries_no_db_empty() {
    let host = PluginHost::new_without_db();
    assert!(host.load_persisted_entries().unwrap().is_empty());
}

#[test]
fn host_ipc_dispatch_logs_call_and_response() {
    let host = PluginHost::new_without_db();
    host.load_plugin(inline("ipc1"), PluginSettings::new()).unwrap();
    let d = Arc::new(InProcessIpcDispatcher::new());
    d.register("ping", |_| Ok(PluginValue::String("ok".into())));
    host.register_ipc("ipc1", d);
    let r = host.ipc_call("ipc1", "ping", PluginValue::Null).unwrap();
    assert_eq!(r, PluginValue::String("ok".into()));
    let log = host.event_log();
    assert!(log.iter().any(|e| matches!(e, HostEvent::IpcCall { .. })));
    assert!(log.iter().any(
        |e| matches!(e, HostEvent::IpcResponse { success, .. } if *success)
    ));
}

#[test]
fn host_ipc_no_dispatcher_errors() {
    let host = PluginHost::new_without_db();
    host.load_plugin(inline("ipc2"), PluginSettings::new()).unwrap();
    let r = host.ipc_call("ipc2", "ping", PluginValue::Null);
    assert!(matches!(r, Err(HostError::Ipc(_))));
}

// ── Send + Sync threaded stress ──────────────────────────────────────────────

#[test]
fn host_send_sync_threaded_load_many() {
    let host = Arc::new(PluginHost::new_without_db());
    let mut handles = Vec::new();
    for t in 0..4 {
        let h = host.clone();
        handles.push(std::thread::spawn(move || {
            for i in 0..100 {
                let id = format!("t{t}.p{i}");
                h.load_plugin(inline(&id), PluginSettings::new()).unwrap();
                let _ = h.health(&id);
                let _ = h.get_settings(&id);
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
    assert_eq!(host.active_count(), 4 * 100);
}

#[test]
fn ipc_dispatcher_send_sync_threaded() {
    let d = Arc::new(InProcessIpcDispatcher::new());
    d.register("inc", |v| match v {
        PluginValue::Int(n) => Ok(PluginValue::Int(n + 1)),
        _ => Err(HostError::Ipc("bad".into())),
    });
    let mut handles = Vec::new();
    for _ in 0..4 {
        let d = d.clone();
        handles.push(std::thread::spawn(move || {
            for i in 0..100i64 {
                let r = d.dispatch("inc", PluginValue::Int(i)).unwrap();
                assert_eq!(r, PluginValue::Int(i + 1));
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
}

// ── NativePluginRegistry ─────────────────────────────────────────────────────

struct DummyNative;
impl NativePlugin for DummyNative {
    fn manifest(&self) -> Manifest33 {
        Manifest33::new("com.n.d", "1.0", "A", "D", "0.1")
    }
    fn extension_points(&self) -> Vec<ExtensionPoint> {
        vec![ExtensionPoint::AnalysisPass]
    }
}

#[test]
fn native_registry_basic_lifecycle() {
    let mut r = NativePluginRegistry::new();
    assert!(r.is_empty());
    r.register(Box::new(DummyNative));
    assert_eq!(r.len(), 1);
    assert_eq!(r.manifests().len(), 1);
    assert_eq!(
        r.by_extension_point(&ExtensionPoint::AnalysisPass).len(),
        1
    );
    assert!(r.by_extension_point(&ExtensionPoint::Loader).is_empty());
}

#[test]
fn native_plugin_default_name_description() {
    let p = DummyNative;
    assert_eq!(p.name(), "com.n.d");
    assert_eq!(p.description(), "D");
}

// ── FilePluginRegistry ───────────────────────────────────────────────────────

#[test]
fn file_plugin_registry_scan_missing_dir_creates_it() {
    let tmp = std::env::temp_dir().join("rustre_blitz2_scan_missing");
    let _ = std::fs::remove_dir_all(&tmp);
    let mut r = FilePluginRegistry::new(tmp.clone());
    let n = r.scan_directory().unwrap();
    assert_eq!(n, 0);
    assert!(tmp.exists());
    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn file_plugin_registry_scan_ignores_non_toml() {
    let tmp = std::env::temp_dir().join("rustre_blitz2_scan_ignore");
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).unwrap();
    std::fs::write(tmp.join("readme.txt"), "hi").unwrap();
    std::fs::write(tmp.join("junk.json"), "{}").unwrap();
    let mut r = FilePluginRegistry::new(tmp.clone());
    assert_eq!(r.scan_directory().unwrap(), 0);
    assert_eq!(r.len(), 0);
    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn file_plugin_registry_scan_ignores_malformed_toml() {
    let tmp = std::env::temp_dir().join("rustre_blitz2_scan_malformed");
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).unwrap();
    std::fs::write(tmp.join("bad.toml"), "this is not =\nvalid {[").unwrap();
    let mut r = FilePluginRegistry::new(tmp.clone());
    assert_eq!(r.scan_directory().unwrap(), 0);
    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn file_plugin_registry_enable_disable_unknown_errors() {
    let mut r = FilePluginRegistry::new(PathBuf::from("/no/dir"));
    assert!(r.enable("x").is_err());
    assert!(r.disable("x").is_err());
}

#[test]
fn file_plugin_registry_plugin_dir_accessor() {
    let p = std::env::temp_dir().join("rustre_blitz2_dir_acc");
    let r = FilePluginRegistry::new(p.clone());
    assert_eq!(r.plugin_dir(), p.as_path());
}

// ── PluginEntry display ──────────────────────────────────────────────────────

#[test]
fn plugin_entry_display_contains_state() {
    let host = PluginHost::new_without_db();
    host.load_plugin(inline("disp"), PluginSettings::new()).unwrap();
    let entries = host.all_entries();
    let entry: &PluginEntry = entries.iter().find(|e| e.meta.id == "disp").unwrap();
    let s = entry.to_string();
    assert!(s.contains("disp"));
}
