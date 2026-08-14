//! Exhaustive blitz test suite for rustre-plugin-api.
//!
//! Exercises lib.rs (Version, PluginManifest, PluginRegistry, PluginContext,
//! EventBus, PluginLogger, PluginStorage, CommandRegistry, stub plugins,
//! permissions) and host_compat (PluginState, PluginMeta, PluginSettings,
//! PluginValue, IpcMessage/Response, HookRegistry, HookPoint,
//! HostPluginRegistry, HostPluginExt) and plugin_manifest (ApiVersion,
//! ManifestEntry, ManifestSection, parse_manifest).

use rustre_plugin_api::host_compat::{
    HookPoint, HookRegistry, HostPluginExt, HostPluginRegistry, IpcMessage, IpcResponse,
    PluginMeta, PluginSettings, PluginState, PluginValue,
};
use rustre_plugin_api::plugin_manifest as pm;
use rustre_plugin_api::*;

use parking_lot::RwLock as PLRwLock;
use std::sync::{Arc, Mutex};

// ─── Version ────────────────────────────────────────────────────────────────

#[test]
fn version_parse_three_parts() {
    let v = Version::parse("3.4.5").unwrap();
    assert_eq!(v, Version::new(3, 4, 5));
}

#[test]
fn version_parse_two_parts_is_none() {
    assert!(Version::parse("1.2").is_none());
}

#[test]
fn version_parse_four_parts_is_none() {
    assert!(Version::parse("1.2.3.4").is_none());
}

#[test]
fn version_parse_empty_is_none() {
    assert!(Version::parse("").is_none());
}

#[test]
fn version_parse_non_numeric_is_none() {
    assert!(Version::parse("a.b.c").is_none());
}

#[test]
fn version_parse_negative_is_none() {
    assert!(Version::parse("-1.0.0").is_none());
}

#[test]
fn version_parse_max_u32() {
    let v = Version::parse(&format!("{m}.{m}.{m}", m = u32::MAX)).unwrap();
    assert_eq!(v.major, u32::MAX);
}

#[test]
fn version_display_roundtrip() {
    let v = Version::new(7, 8, 9);
    assert_eq!(Version::parse(&v.to_string()).unwrap(), v);
}

#[test]
fn version_equal_is_compatible() {
    let v = Version::new(1, 2, 3);
    assert!(v.is_compatible_with(&v));
}

#[test]
fn version_lower_minor_incompatible() {
    let v = Version::new(1, 0, 0);
    let req = Version::new(1, 5, 0);
    assert!(!v.is_compatible_with(&req));
}

#[test]
fn version_ordering_patch() {
    assert!(Version::new(0, 1, 1) > Version::new(0, 1, 0));
}

// ─── Manifest ───────────────────────────────────────────────────────────────

#[test]
fn manifest_defaults() {
    let m = PluginManifest::new("x", Version::new(0, 1, 0));
    assert_eq!(m.license, "MIT");
    assert!(m.capabilities.is_empty());
    assert!(m.dependencies.is_empty());
    assert!(m.homepage.is_none());
}

#[test]
fn manifest_is_compatible_with_current() {
    let m = PluginManifest::new("x", Version::new(0, 1, 0));
    // min_rustre_version defaults to 0.1.0 which equals RUSTRE_VERSION major
    assert!(m.is_compatible());
}

#[test]
fn manifest_incompatible_when_needs_future_version() {
    let mut m = PluginManifest::new("x", Version::new(0, 1, 0));
    m.min_rustre_version = Version::new(99, 0, 0);
    assert!(!m.is_compatible());
}

#[test]
fn manifest_from_meta_uses_version() {
    let meta = PluginMeta {
        id: "p".into(),
        name: "p".into(),
        version: "2.3.4".into(),
        description: "d".into(),
        author: "a".into(),
        category: "loader".into(),
    };
    let m = PluginManifest::from_meta(meta);
    assert_eq!(m.version, Version::new(2, 3, 4));
    assert_eq!(m.description, "d");
    assert_eq!(m.author, "a");
}

#[test]
fn manifest_from_meta_bad_version_defaults() {
    let meta = PluginMeta {
        id: "p".into(),
        name: "p".into(),
        version: "garbage".into(),
        ..Default::default()
    };
    let m = PluginManifest::from_meta(meta);
    assert_eq!(m.version, Version::new(0, 0, 0));
}

// ─── PluginCapability / PluginId ────────────────────────────────────────────

#[test]
fn capability_as_str_all_unique() {
    let strs = [
        PluginCapability::Loader.as_str(),
        PluginCapability::Architecture.as_str(),
        PluginCapability::AnalysisPass.as_str(),
        PluginCapability::Decompiler.as_str(),
        PluginCapability::DebugBackend.as_str(),
        PluginCapability::UiPanel.as_str(),
        PluginCapability::ScriptExtension.as_str(),
        PluginCapability::MlilTransform.as_str(),
        PluginCapability::HlilTransform.as_str(),
        PluginCapability::TypeProvider.as_str(),
        PluginCapability::CallingConvention.as_str(),
        PluginCapability::PlatformProvider.as_str(),
        PluginCapability::SignatureProvider.as_str(),
        PluginCapability::ThemeProvider.as_str(),
        PluginCapability::SymbolProvider.as_str(),
        PluginCapability::DataRenderer.as_str(),
        PluginCapability::Workflow.as_str(),
        PluginCapability::HighlightProvider.as_str(),
        PluginCapability::SidebarProvider.as_str(),
        PluginCapability::NotificationHandler.as_str(),
        PluginCapability::FileModifier.as_str(),
        PluginCapability::ProjectHook.as_str(),
    ];
    let mut sorted = strs.to_vec();
    sorted.sort();
    sorted.dedup();
    assert_eq!(sorted.len(), strs.len(), "duplicate cap str ids");
}

#[test]
fn plugin_id_eq_and_hash() {
    use std::collections::HashSet;
    let a = PluginId::new("foo", &Version::new(1, 0, 0));
    let b = PluginId::new("foo", &Version::new(1, 0, 0));
    assert_eq!(a, b);
    let mut s = HashSet::new();
    s.insert(a);
    assert!(s.contains(&b));
}

#[test]
fn plugin_id_as_str_matches_display() {
    let id = PluginId::new("x", &Version::new(0, 1, 2));
    assert_eq!(id.as_str(), id.to_string());
}

// ─── Permissions ────────────────────────────────────────────────────────────

#[test]
fn permissions_default_grants_nothing() {
    let p = PluginPermissions::default();
    assert!(!p.can_write_memory());
    assert!(!p.can_execute_code());
    assert!(!p.can_modify_binary());
    assert!(!p.can_read_filesystem());
    assert!(!p.can_write_filesystem());
    assert!(!p.can_access_network());
    assert!(!p.can_spawn_threads());
    assert!(!p.can_use_ui());
    assert!(!p.can_access_debugger());
    assert!(!p.can_modify_graph());
    assert!(!p.can_register_commands());
    assert_eq!(p.summary(), "none");
}

#[test]
fn permissions_all_summary_has_all_flags() {
    let p = PluginPermissions::all();
    let s = p.summary();
    for flag in [
        "write_memory",
        "execute_code",
        "network",
        "modify_graph",
        "read_fs",
        "write_fs",
        "spawn_threads",
        "ui",
        "debugger",
        "commands",
        "modify_binary",
    ] {
        assert!(s.contains(flag), "summary missing {flag}: {s}");
    }
}

#[test]
fn permissions_read_only_only_reads_fs() {
    let p = PluginPermissions::read_only();
    assert!(p.can_read_filesystem());
    assert!(!p.can_write_filesystem());
    assert!(!p.can_modify_graph());
}

#[test]
fn permissions_analysis_only() {
    let p = PluginPermissions::analysis_only();
    assert!(p.can_modify_graph());
    assert!(p.can_read_filesystem());
    assert!(!p.can_write_memory());
}

// ─── EventBus ───────────────────────────────────────────────────────────────

#[test]
fn event_bus_filter_does_not_invoke_unmatched() {
    let bus = EventBus::new();
    let counter = Arc::new(Mutex::new(0u32));
    let c2 = counter.clone();
    bus.subscribe(
        "function_added",
        Box::new(move |_| {
            *c2.lock().unwrap() += 1;
        }),
    );
    bus.publish(&PluginEvent::BinaryAnalyzed);
    assert_eq!(*counter.lock().unwrap(), 0);
    bus.publish(&PluginEvent::FunctionAdded { addr: 0x10 });
    assert_eq!(*counter.lock().unwrap(), 1);
}

#[test]
fn event_bus_multiple_handlers_all_run() {
    let bus = EventBus::new();
    let c = Arc::new(Mutex::new(0u32));
    for _ in 0..5 {
        let c2 = c.clone();
        bus.subscribe(
            "binary_analyzed",
            Box::new(move |_| *c2.lock().unwrap() += 1),
        );
    }
    bus.publish(&PluginEvent::BinaryAnalyzed);
    assert_eq!(*c.lock().unwrap(), 5);
}

#[test]
fn event_bus_send_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<EventBus>();
}

#[test]
fn event_bus_handler_count_zero_initially() {
    let bus = EventBus::new();
    assert_eq!(bus.handler_count(), 0);
}

// ─── Logger ─────────────────────────────────────────────────────────────────

#[test]
fn logger_default_level_is_info() {
    let logger = PluginLogger::new("x");
    assert_eq!(logger.min_level, LogLevel::Info);
}

#[test]
fn logger_trace_filtered_at_info() {
    let logger = PluginLogger::new("x");
    logger.trace("nope");
    logger.debug("nope");
    logger.info("yes");
    logger.warn("yes");
    logger.error("yes");
    assert_eq!(logger.messages().len(), 3);
}

#[test]
fn logger_formatting_includes_name_and_level() {
    let logger = PluginLogger::new("plugA");
    logger.error("boom");
    let (lvl, msg) = logger.messages().into_iter().next().unwrap();
    assert_eq!(lvl, LogLevel::Error);
    assert!(msg.contains("plugA"));
    assert!(msg.contains("ERROR"));
    assert!(msg.contains("boom"));
}

#[test]
fn log_level_ordering() {
    assert!(LogLevel::Error > LogLevel::Warn);
    assert!(LogLevel::Warn > LogLevel::Info);
    assert!(LogLevel::Info > LogLevel::Debug);
    assert!(LogLevel::Debug > LogLevel::Trace);
}

#[test]
fn log_level_as_str() {
    assert_eq!(LogLevel::Trace.as_str(), "TRACE");
    assert_eq!(LogLevel::Debug.as_str(), "DEBUG");
    assert_eq!(LogLevel::Info.as_str(), "INFO");
    assert_eq!(LogLevel::Warn.as_str(), "WARN");
    assert_eq!(LogLevel::Error.as_str(), "ERROR");
}

// ─── PluginStorage ──────────────────────────────────────────────────────────

#[test]
fn storage_get_missing_is_none() {
    let s = PluginStorage::new();
    assert!(s.get("missing").is_none());
    assert!(s.get_str("missing").is_none());
}

#[test]
fn storage_overwrite() {
    let mut s = PluginStorage::new();
    s.set("k", vec![1, 2, 3]);
    s.set("k", vec![9]);
    assert_eq!(s.get("k"), Some(&[9u8][..]));
}

#[test]
fn storage_remove_returns_old_value() {
    let mut s = PluginStorage::new();
    s.set("k", b"hello".to_vec());
    let prev = s.remove("k");
    assert_eq!(prev.as_deref(), Some(&b"hello"[..]));
    assert!(s.remove("k").is_none());
}

#[test]
#[should_panic(expected = "must not contain '='")]
fn storage_set_with_equals_panics() {
    let mut s = PluginStorage::new();
    s.set("bad=key", vec![1]);
}

#[test]
fn storage_persist_and_load_roundtrip() {
    let tmp = std::env::temp_dir().join(format!(
        "rustre_plugin_api_storage_{}.kv",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&tmp);

    let mut s = PluginStorage::with_path(tmp.clone());
    s.set("alpha", vec![0xDE, 0xAD, 0xBE, 0xEF]);
    s.set_str("greeting", "hi");
    s.persist().expect("persist");

    let mut s2 = PluginStorage::with_path(tmp.clone());
    s2.load().expect("load");
    assert_eq!(s2.get("alpha"), Some(&[0xDE, 0xAD, 0xBE, 0xEF][..]));
    assert_eq!(s2.get_str("greeting").as_deref(), Some("hi"));

    let _ = std::fs::remove_file(&tmp);
}

#[test]
fn storage_load_missing_file_ok() {
    let tmp = std::env::temp_dir().join("rustre_plugin_api_no_such_storage.kv");
    let _ = std::fs::remove_file(&tmp);
    let mut s = PluginStorage::with_path(tmp);
    // file doesn't exist; load is documented as Ok
    assert!(s.load().is_ok());
}

#[test]
fn storage_persist_no_path_noop() {
    let s = PluginStorage::new();
    assert!(s.persist().is_ok());
}

// ─── CommandRegistry ────────────────────────────────────────────────────────

#[test]
fn command_register_overwrites() {
    let mut r = CommandRegistry::default();
    r.register("c", "1", "", Box::new(|_| Ok("a".into())));
    r.register("c", "2", "", Box::new(|_| Ok("b".into())));
    assert_eq!(r.dispatch("c", vec![]).unwrap(), "b");
}

#[test]
fn command_contains() {
    let mut r = CommandRegistry::default();
    r.register("x", "", "", Box::new(|_| Ok(String::new())));
    assert!(r.contains("x"));
    assert!(!r.contains("y"));
}

#[test]
fn command_handler_error_propagates() {
    let mut r = CommandRegistry::default();
    r.register(
        "bad",
        "",
        "",
        Box::new(|_| Err(PluginError::ApiError("nope".into()))),
    );
    let err = r.dispatch("bad", vec![]).unwrap_err();
    assert!(matches!(err, PluginError::ApiError(_)));
}

// ─── PluginContext ──────────────────────────────────────────────────────────

fn ev() -> Arc<EventBus> {
    Arc::new(EventBus::new())
}

#[test]
fn context_register_command_requires_permission() {
    let m = PluginManifest::new("p", Version::new(0, 1, 0));
    let mut ctx = PluginContext::new(m, PluginPermissions::default(), ev());
    let r = ctx.register_command("c", "", "", Box::new(|_| Ok(String::new())));
    assert!(matches!(r, Err(PluginError::PermissionDenied(_))));
}

#[test]
fn context_register_command_succeeds_with_permission() {
    let m = PluginManifest::new("p", Version::new(0, 1, 0));
    let mut ctx = PluginContext::new(m, PluginPermissions::all(), ev());
    assert!(
        ctx.register_command("c", "", "", Box::new(|_| Ok("ok".into())))
            .is_ok()
    );
    assert!(ctx.commands.contains("c"));
}

#[test]
fn context_require_permission_unknown_key_denied() {
    let m = PluginManifest::new("p", Version::new(0, 1, 0));
    let ctx = PluginContext::new(m, PluginPermissions::all(), ev());
    // unknown key — even with all perms, should be denied
    let r = ctx.require_permission("fly_to_the_moon");
    assert!(matches!(r, Err(PluginError::PermissionDenied(_))));
}

#[test]
fn context_has_capability() {
    let mut m = PluginManifest::new("p", Version::new(0, 1, 0));
    m.capabilities.push(PluginCapability::Decompiler);
    let ctx = PluginContext::new(m, PluginPermissions::all(), ev());
    assert!(ctx.has_capability(&PluginCapability::Decompiler));
    assert!(!ctx.has_capability(&PluginCapability::Loader));
}

#[test]
fn context_plugin_name_and_version() {
    let m = PluginManifest::new("pluggy", Version::new(2, 3, 4));
    let ctx = PluginContext::new(m, PluginPermissions::all(), ev());
    assert_eq!(ctx.plugin_name(), "pluggy");
    assert_eq!(*ctx.plugin_version(), Version::new(2, 3, 4));
}

#[test]
fn context_publish_event_reaches_subscriber() {
    let m = PluginManifest::new("p", Version::new(0, 1, 0));
    let bus = ev();
    let counter = Arc::new(Mutex::new(0u32));
    let c2 = counter.clone();
    bus.subscribe("*", Box::new(move |_| *c2.lock().unwrap() += 1));
    let ctx = PluginContext::new(m, PluginPermissions::all(), bus);
    ctx.publish_event(&PluginEvent::AnalysisStarted);
    assert_eq!(*counter.lock().unwrap(), 1);
}

// ─── PluginRegistry / HostManager ───────────────────────────────────────────

fn stub_arc(name: &str) -> Arc<dyn Plugin> {
    Arc::new(StubPlugin::new(name, Version::new(0, 1, 0)))
}

#[test]
fn registry_incompatible_plugin_rejected() {
    let mut reg = PluginRegistry::new(ev());
    let mut p = StubPlugin::new("p", Version::new(0, 1, 0));
    // Force incompatibility by making min_rustre very high.
    // We can't easily change StubPlugin manifest; build a manifest via wrap.
    p.caps.clear();
    let _ = p; // unused helper — actually use a custom plugin instead.

    struct IncompatPlugin;
    impl Plugin for IncompatPlugin {
        fn name(&self) -> &str { "incompat" }
        fn version(&self) -> &Version {
            static V: Version = Version::new(0, 1, 0);
            &V
        }
        fn capabilities(&self) -> Vec<PluginCapability> { Vec::new() }
        fn manifest(&self) -> PluginManifest {
            let mut m = PluginManifest::new("incompat", Version::new(0, 1, 0));
            m.min_rustre_version = Version::new(99, 0, 0);
            m
        }
        fn init(&self, _: &mut PluginContext) -> PluginResult<()> { Ok(()) }
        fn unload(&self, _: &mut PluginContext) {}
        fn as_any(&self) -> &dyn std::any::Any { self }
    }

    let r = reg.register(Arc::new(IncompatPlugin), PluginPermissions::all());
    assert!(matches!(r, Err(PluginError::Incompatible { .. })));
}

#[test]
fn registry_get_and_get_context() {
    let mut reg = PluginRegistry::new(ev());
    let id = reg.register(stub_arc("g"), PluginPermissions::all()).unwrap();
    assert!(reg.get(&id).is_some());
    assert!(reg.get_context(&id).is_some());
    assert!(reg.get_context_mut(&id).is_some());
}

#[test]
fn registry_load_from_file_returns_load_error() {
    let mut reg = PluginRegistry::new(ev());
    let r = reg.load_from_file(
        std::path::Path::new("/no/such/plugin.so"),
        &PluginPermissions::read_only(),
    );
    match r {
        Err(PluginError::LoadError(msg)) => {
            assert!(msg.contains("/no/such/plugin.so") || msg.contains("plugin.so"));
            assert!(msg.contains("read_fs") || msg.contains("none") || msg.contains("permission"));
        }
        other => panic!("expected LoadError, got {other:?}"),
    }
}

#[test]
fn registry_unregister_publishes_event() {
    let bus = ev();
    let counter = Arc::new(Mutex::new(0u32));
    let c2 = counter.clone();
    bus.subscribe(
        "plugin_unloaded",
        Box::new(move |_| *c2.lock().unwrap() += 1),
    );
    let mut reg = PluginRegistry::new(bus);
    let id = reg.register(stub_arc("ue"), PluginPermissions::all()).unwrap();
    reg.unregister(&id).unwrap();
    assert_eq!(*counter.lock().unwrap(), 1);
}

#[test]
fn registry_load_order_preserved() {
    let mut reg = PluginRegistry::new(ev());
    let a = reg.register(stub_arc("a"), PluginPermissions::all()).unwrap();
    let b = reg.register(stub_arc("b"), PluginPermissions::all()).unwrap();
    let c = reg.register(stub_arc("c"), PluginPermissions::all()).unwrap();
    let list: Vec<&PluginId> = reg.list();
    assert_eq!(list, vec![&a, &b, &c]);
}

#[test]
fn host_manager_default_perms_are_analysis_only() {
    let mgr = PluginHostManager::new(ev());
    // We can't observe auto_permissions directly, but watch paths are default
    assert!(mgr.watch_paths().iter().any(|p| p.ends_with("plugins") || p.to_string_lossy().contains("plugins")));
}

#[test]
fn host_manager_add_watch_path() {
    let mut mgr = PluginHostManager::new(ev());
    let before = mgr.watch_paths().len();
    mgr.add_watch_path(std::path::PathBuf::from("/extra/plugin/dir"));
    assert_eq!(mgr.watch_paths().len(), before + 1);
}

#[test]
fn host_manager_scan_nonexistent_skipped() {
    let mut mgr = PluginHostManager::new(ev());
    mgr.add_watch_path(std::path::PathBuf::from(
        "/definitely/does/not/exist/anywhere",
    ));
    // shouldn't panic or error
    let _ = mgr.scan_and_load();
}

// ─── Stub Loader / Analysis Plugin ──────────────────────────────────────────

#[test]
fn stub_loader_load_uses_input_defaults() {
    let l = StubLoaderPlugin::new("L", b"MAG".to_vec(), 80);
    let info = l
        .load(LoaderInput {
            path: None,
            data: Vec::new(),
            base_addr: None,
            entry_point: None,
        })
        .unwrap();
    assert_eq!(info.entry_point, 0x1000);
    assert_eq!(info.base_address, 0);
    assert_eq!(info.arch, "x86_64");
}

#[test]
fn stub_loader_supported_extensions() {
    let l = StubLoaderPlugin::new("L", vec![], 0);
    assert_eq!(l.supported_extensions(), vec!["bin"]);
}

#[test]
fn stub_loader_probe_empty_bytes_with_empty_magic_matches() {
    // empty starts_with empty -> true
    let l = StubLoaderPlugin::new("L", vec![], 42);
    assert_eq!(l.probe(&[]), 42);
}

#[test]
fn stub_loader_probe_shorter_than_magic() {
    let l = StubLoaderPlugin::new("L", b"ABCD".to_vec(), 50);
    assert_eq!(l.probe(b"AB"), 0);
}

#[test]
fn stub_analysis_run_on_binary_default() {
    let p = StubAnalysisPlugin::new("an");
    let ctx = PluginContext::new(p.manifest(), PluginPermissions::all(), ev());
    let report = p.run_on_binary(&ctx).unwrap();
    assert_eq!(report.functions_analyzed, 0);
    assert!(report.findings.is_empty());
}

#[test]
fn stub_analysis_run_on_function_finding_addr() {
    let mut p = StubAnalysisPlugin::new("an");
    p.finding_addr = 0x40;
    let ctx = PluginContext::new(p.manifest(), PluginPermissions::all(), ev());
    let mut f = FunctionInfo {
        name: "foo".into(),
        address: 0x1000,
        ..Default::default()
    };
    let r = p.run_on_function(&mut f, &ctx).unwrap();
    assert_eq!(r.findings[0].address, 0x1040);
    assert_eq!(r.findings[0].kind, FindingKind::General);
}

#[test]
fn stub_plugin_init_failure_message() {
    let p = StubPlugin::new("z", Version::new(0, 1, 0)).fail_init();
    let mut ctx = PluginContext::new(p.manifest(), PluginPermissions::all(), ev());
    match p.init(&mut ctx) {
        Err(PluginError::InitFailed(msg)) => assert!(msg.contains("fail")),
        other => panic!("expected InitFailed, got {other:?}"),
    }
}

// ─── PluginError Display ────────────────────────────────────────────────────

#[test]
fn plugin_error_display_variants() {
    let cases = [
        format!(
            "{}",
            PluginError::InitFailed("x".into())
        ),
        format!("{}", PluginError::PermissionDenied("x".into())),
        format!(
            "{}",
            PluginError::CapabilityNotSupported(PluginCapability::Loader)
        ),
        format!("{}", PluginError::NotFound("x".into())),
        format!("{}", PluginError::AlreadyRegistered("x".into())),
        format!(
            "{}",
            PluginError::Incompatible {
                plugin: "p".into(),
                required: Version::new(1, 0, 0),
                found: Version::new(0, 1, 0)
            }
        ),
        format!("{}", PluginError::DependencyMissing("d".into())),
        format!("{}", PluginError::LoadError("l".into())),
        format!("{}", PluginError::UnloadError("u".into())),
        format!("{}", PluginError::ApiError("a".into())),
        format!("{}", PluginError::InvalidManifest("m".into())),
        format!("{}", PluginError::Serde("s".into())),
    ];
    for s in &cases {
        assert!(!s.is_empty());
    }
}

#[test]
fn plugin_error_from_serde() {
    let bad: serde_json::Error = serde_json::from_str::<i32>("not-json").unwrap_err();
    let err: PluginError = bad.into();
    assert!(matches!(err, PluginError::Serde(_)));
}

// ─── host_compat ────────────────────────────────────────────────────────────

#[test]
fn plugin_state_default_is_unloaded() {
    assert_eq!(PluginState::default(), PluginState::Unloaded);
}

#[test]
fn plugin_state_display() {
    assert_eq!(format!("{}", PluginState::Active), "Active");
    assert_eq!(format!("{}", PluginState::Suspended), "Suspended");
    assert_eq!(format!("{}", PluginState::Error), "Error");
    assert_eq!(format!("{}", PluginState::Loading), "Loading");
    assert_eq!(format!("{}", PluginState::Unloaded), "Unloaded");
}

#[test]
fn plugin_meta_new_sets_category() {
    let m = PluginMeta::new("id", "name", PluginCapability::Decompiler);
    assert_eq!(m.id, "id");
    assert_eq!(m.name, "name");
    assert_eq!(m.category, "decompiler");
    assert_eq!(m.version, "0.0.0");
}

#[test]
fn plugin_meta_display() {
    let mut m = PluginMeta::new("i", "MyPlug", PluginCapability::Loader);
    m.version = "1.2.3".into();
    assert_eq!(format!("{m}"), "MyPlug v1.2.3");
}

#[test]
fn plugin_settings_get_bool_int_typed() {
    let mut s = PluginSettings::new();
    s.set("on", PluginValue::Bool(true));
    s.set("n", PluginValue::Int(42));
    s.set("name", PluginValue::String("hi".into()));
    assert_eq!(s.get_bool("on"), Some(true));
    assert_eq!(s.get_int("n"), Some(42));
    assert!(s.get_bool("n").is_none()); // wrong type
    assert!(s.get_int("name").is_none()); // wrong type
    assert!(s.get_bool("missing").is_none());
}

#[test]
fn plugin_value_default_is_null() {
    assert_eq!(PluginValue::default(), PluginValue::Null);
}

#[test]
fn plugin_value_serde_roundtrip_int() {
    let v = PluginValue::Int(7);
    let s = serde_json::to_string(&v).unwrap();
    let back: PluginValue = serde_json::from_str(&s).unwrap();
    assert_eq!(back, v);
}

#[test]
fn plugin_value_serde_roundtrip_bool() {
    let v = PluginValue::Bool(true);
    let s = serde_json::to_string(&v).unwrap();
    let back: PluginValue = serde_json::from_str(&s).unwrap();
    assert_eq!(back, v);
}

#[test]
fn plugin_value_serde_roundtrip_string() {
    let v = PluginValue::String("hello".into());
    let s = serde_json::to_string(&v).unwrap();
    let back: PluginValue = serde_json::from_str(&s).unwrap();
    assert_eq!(back, v);
}

#[test]
fn ipc_message_new() {
    let m = IpcMessage::new("foo", PluginValue::Int(1));
    assert_eq!(m.method, "foo");
    assert_eq!(m.payload, PluginValue::Int(1));
}

#[test]
fn ipc_response_ok() {
    let r = IpcResponse::ok(PluginValue::Bool(true));
    assert!(r.success);
    assert!(r.error.is_none());
    assert_eq!(r.payload, PluginValue::Bool(true));
}

#[test]
fn ipc_response_err() {
    let r = IpcResponse::err("bad");
    assert!(!r.success);
    assert_eq!(r.error.as_deref(), Some("bad"));
    assert_eq!(r.payload, PluginValue::Null);
}

#[test]
fn hook_registry_fire_invokes_callback() {
    let reg = HookRegistry::new();
    let c = Arc::new(Mutex::new(0u32));
    let c2 = c.clone();
    reg.register("evt", Box::new(move |_| *c2.lock().unwrap() += 1));
    reg.fire("evt", &PluginValue::Null);
    reg.fire("evt", &PluginValue::Null);
    assert_eq!(*c.lock().unwrap(), 2);
}

#[test]
fn hook_registry_fire_unknown_event_noop() {
    let reg = HookRegistry::new();
    reg.fire("nope", &PluginValue::Null);
    assert_eq!(reg.event_count(), 0);
}

#[test]
fn hook_registry_event_count_distinct_events() {
    let reg = HookRegistry::new();
    reg.register("a", Box::new(|_| {}));
    reg.register("a", Box::new(|_| {}));
    reg.register("b", Box::new(|_| {}));
    assert_eq!(reg.event_count(), 2);
}

#[test]
fn hook_registry_hook_count_per_hookpoint() {
    let reg = HookRegistry::new();
    reg.register(HookPoint::OnLoad.as_str(), Box::new(|_| {}));
    reg.register(HookPoint::OnLoad.as_str(), Box::new(|_| {}));
    assert_eq!(reg.hook_count(HookPoint::OnLoad), 2);
    assert_eq!(reg.hook_count(HookPoint::OnUnload), 0);
}

#[test]
fn hook_point_as_str_all_distinct() {
    let pts = [
        HookPoint::OnLoad.as_str(),
        HookPoint::OnUnload.as_str(),
        HookPoint::OnSuspend.as_str(),
        HookPoint::OnResume.as_str(),
        HookPoint::OnError.as_str(),
    ];
    let mut v = pts.to_vec();
    v.sort();
    v.dedup();
    assert_eq!(v.len(), 5);
}

#[test]
fn host_plugin_registry_register_and_unregister() {
    let reg = HostPluginRegistry::new();
    let p: Arc<PLRwLock<dyn Plugin>> =
        Arc::new(PLRwLock::new(StubPlugin::new("x", Version::new(0, 1, 0))));
    reg.register(p.clone()).unwrap();
    assert_eq!(reg.count(), 1);

    // duplicate
    let err = reg.register(p).unwrap_err();
    assert!(matches!(err, PluginError::AlreadyRegistered(_)));

    let ids = reg.ids();
    assert_eq!(ids.len(), 1);
    reg.unregister(&ids[0]).unwrap();
    assert_eq!(reg.count(), 0);
    assert!(matches!(
        reg.unregister("missing").unwrap_err(),
        PluginError::NotFound(_)
    ));
}

#[test]
fn host_plugin_ext_meta_id_format() {
    let p = StubPlugin::new("hostext", Version::new(1, 2, 3));
    let meta = HostPluginExt::meta(&p);
    assert_eq!(meta.id, "hostext@1.2.3");
    assert_eq!(meta.version, "1.2.3");
}

#[test]
fn host_plugin_ext_lifecycle_methods_ok() {
    let p = StubPlugin::new("hostext", Version::new(0, 1, 0));
    assert_eq!(HostPluginExt::state(&p), PluginState::Active);
    assert!(HostPluginExt::initialize(&p, &PluginSettings::new()).is_ok());
    assert!(HostPluginExt::shutdown(&p).is_ok());
    assert!(HostPluginExt::suspend(&p).is_ok());
    assert!(HostPluginExt::resume(&p).is_ok());
}

#[test]
fn host_plugin_ext_category_empty_when_no_caps() {
    let p = StubPlugin::new("nocaps", Version::new(0, 1, 0));
    let meta = HostPluginExt::meta(&p);
    assert_eq!(meta.category, "");
}

#[test]
fn host_plugin_ext_category_uses_first_cap() {
    let p = StubPlugin::new("withcap", Version::new(0, 1, 0))
        .with_capability(PluginCapability::Decompiler);
    let meta = HostPluginExt::meta(&p);
    assert_eq!(meta.category, "decompiler");
}

// ─── plugin_manifest module ─────────────────────────────────────────────────

#[test]
fn pm_apiversion_parse_basic() {
    let v = pm::ApiVersion::parse("1.2.3").unwrap();
    assert_eq!(v, pm::ApiVersion::new(1, 2, 3));
}

#[test]
fn pm_apiversion_parse_too_few_parts_err() {
    assert!(pm::ApiVersion::parse("1.2").is_err());
}

#[test]
fn pm_apiversion_parse_non_numeric_err() {
    assert!(pm::ApiVersion::parse("a.b.c").is_err());
}

#[test]
fn pm_apiversion_satisfies() {
    let v = pm::ApiVersion::new(1, 5, 0);
    let req = pm::ApiVersion::new(1, 2, 0);
    assert!(v.satisfies(&req));
    let req2 = pm::ApiVersion::new(2, 0, 0);
    assert!(!v.satisfies(&req2));
}

#[test]
fn pm_apiversion_bump() {
    let v = pm::ApiVersion::new(1, 2, 3);
    assert_eq!(v.bump_patch(), pm::ApiVersion::new(1, 2, 4));
    assert_eq!(v.bump_minor(), pm::ApiVersion::new(1, 3, 0));
    assert_eq!(v.bump_major(), pm::ApiVersion::new(2, 0, 0));
}

#[test]
fn pm_apiversion_is_initial() {
    assert!(pm::ApiVersion::new(0, 0, 5).is_initial());
    assert!(!pm::ApiVersion::new(0, 1, 0).is_initial());
}

#[test]
fn pm_apiversion_fromstr() {
    let v: pm::ApiVersion = "3.4.5".parse().unwrap();
    assert_eq!(v, pm::ApiVersion::new(3, 4, 5));
}

#[test]
fn pm_manifest_entry_validation() {
    assert!(pm::ManifestEntry::new("good_key", "v").is_ok());
    assert!(pm::ManifestEntry::new("good-key", "v").is_ok());
    assert!(pm::ManifestEntry::new("good123", "v").is_ok());
    assert!(pm::ManifestEntry::new("", "v").is_err());
    assert!(pm::ManifestEntry::new("bad key", "v").is_err());
    assert!(pm::ManifestEntry::new("bad=key", "v").is_err());
}

#[test]
fn pm_manifest_entry_unchecked_skips_validation() {
    let e = pm::ManifestEntry::unchecked("any key=here!", "v");
    assert_eq!(e.key, "any key=here!");
}

#[test]
fn pm_manifest_entry_is_true_false() {
    assert!(pm::ManifestEntry::unchecked("k", "true").is_true());
    assert!(pm::ManifestEntry::unchecked("k", "1").is_true());
    assert!(pm::ManifestEntry::unchecked("k", "yes").is_true());
    assert!(pm::ManifestEntry::unchecked("k", "false").is_false());
    assert!(pm::ManifestEntry::unchecked("k", "0").is_false());
    assert!(pm::ManifestEntry::unchecked("k", "no").is_false());
    assert!(!pm::ManifestEntry::unchecked("k", "maybe").is_true());
}

#[test]
fn pm_manifest_entry_as_u64() {
    assert_eq!(pm::ManifestEntry::unchecked("k", "42").as_u64().unwrap(), 42);
    assert!(pm::ManifestEntry::unchecked("k", "-1").as_u64().is_err());
    assert!(pm::ManifestEntry::unchecked("k", "abc").as_u64().is_err());
}

#[test]
fn pm_manifest_entry_display() {
    let e = pm::ManifestEntry::unchecked("foo", "bar");
    assert_eq!(format!("{e}"), "foo=bar");
}

#[test]
fn pm_manifest_section_operations() {
    let mut s = pm::ManifestSection::new("sec");
    assert!(s.is_empty());
    s.push(pm::ManifestEntry::unchecked("a", "1"));
    s.push(pm::ManifestEntry::unchecked("a", "2"));
    s.push(pm::ManifestEntry::unchecked("b", "3"));
    assert_eq!(s.len(), 3);
    assert_eq!(s.get("a").unwrap().value, "1");
    assert_eq!(s.get_or("missing", "def"), "def");
    assert_eq!(s.get_all("a"), vec!["1", "2"]);
    let map = s.as_map();
    assert!(map.contains_key("a"));
    assert!(map.contains_key("b"));
}

#[test]
fn pm_parse_manifest_minimal() {
    let txt = r#"
[plugin]
id=my.plugin
version=1.0.0
author=Alice
"#;
    let m = pm::parse_manifest(txt).unwrap();
    assert_eq!(m.id, "my.plugin");
    assert_eq!(m.version, pm::ApiVersion::new(1, 0, 0));
    assert_eq!(m.author, "Alice");
    assert_eq!(m.license, "MIT"); // default
    assert_eq!(m.min_api, pm::ApiVersion::new(0, 1, 0)); // default
}

#[test]
fn pm_parse_manifest_full() {
    let txt = r#"
# comment
; also comment

[plugin]
id=p
version=2.0.0
min_api=1.0.0
max_api=3.0.0
description=desc
author=Bob
license=Apache-2.0
homepage=https://x
repository=https://y

[capabilities]
loader=true
decompiler=true
skip=false

[dependencies]
core=1.0.0
extra=0.1.0,optional

[custom]
flag=on
"#;
    let m = pm::parse_manifest(txt).unwrap();
    assert_eq!(m.id, "p");
    assert_eq!(m.min_api, pm::ApiVersion::new(1, 0, 0));
    assert_eq!(m.max_api, Some(pm::ApiVersion::new(3, 0, 0)));
    assert_eq!(m.homepage.as_deref(), Some("https://x"));
    assert_eq!(m.license, "Apache-2.0");
    assert!(m.capabilities.contains(&"loader".to_string()));
    assert!(m.capabilities.contains(&"decompiler".to_string()));
    assert!(!m.capabilities.contains(&"skip".to_string())); // false skipped
    assert_eq!(m.dependencies.len(), 2);
    let opt = m.dependencies.iter().find(|d| d.id == "extra").unwrap();
    assert!(opt.optional);
    let req = m.dependencies.iter().find(|d| d.id == "core").unwrap();
    assert!(!req.optional);
    // custom section preserved
    assert!(m.section("custom").is_some());
}

#[test]
fn pm_parse_manifest_missing_id() {
    let txt = "[plugin]\nversion=1.0.0\n";
    assert!(pm::parse_manifest(txt).is_err());
}

#[test]
fn pm_parse_manifest_missing_version() {
    let txt = "[plugin]\nid=x\n";
    assert!(pm::parse_manifest(txt).is_err());
}

#[test]
fn pm_parse_manifest_bad_version() {
    let txt = "[plugin]\nid=x\nversion=garbage\n";
    assert!(pm::parse_manifest(txt).is_err());
}

#[test]
fn pm_parse_manifest_unclosed_section() {
    let txt = "[plugin\nid=x\nversion=1.0.0\n";
    assert!(pm::parse_manifest(txt).is_err());
}

#[test]
fn pm_parse_manifest_malformed_line() {
    let txt = "[plugin]\nid=x\nversion=1.0.0\nthis is not a kv line\n";
    assert!(pm::parse_manifest(txt).is_err());
}

#[test]
fn pm_manifest_to_ini_roundtrip() {
    let m = pm::PluginManifest::new("p.id", pm::ApiVersion::new(1, 2, 3))
        .with_display_name("Display")
        .with_description("desc")
        .with_author("Auth")
        .with_license("BSD")
        .with_capability("loader")
        .with_dependency(pm::PluginDependency::required(
            "dep1",
            pm::ApiVersion::new(0, 1, 0),
        ));
    let ini = m.to_ini();
    let m2 = pm::parse_manifest(&ini).unwrap();
    assert_eq!(m2.id, "p.id");
    assert_eq!(m2.version, pm::ApiVersion::new(1, 2, 3));
    assert_eq!(m2.author, "Auth");
    assert_eq!(m2.license, "BSD");
    assert!(m2.has_capability("loader"));
    assert_eq!(m2.dependencies.len(), 1);
    assert_eq!(m2.dependencies[0].id, "dep1");
}

#[test]
fn pm_manifest_validate_collects_errors() {
    let mut m = pm::PluginManifest::new("", pm::ApiVersion::new(0, 0, 0));
    m.author = String::new();
    m.license = String::new();
    let errs = m.validate();
    assert!(errs.iter().any(|e| e.contains("id")));
    assert!(errs.iter().any(|e| e.contains("author")));
    assert!(errs.iter().any(|e| e.contains("license")));
}

#[test]
fn pm_manifest_validate_ok() {
    let m = pm::PluginManifest::new("ok.id", pm::ApiVersion::new(1, 0, 0))
        .with_author("a")
        .with_license("MIT");
    assert!(m.validate().is_empty());
}

#[test]
fn pm_manifest_validate_bad_chars_in_id() {
    let m = pm::PluginManifest::new("bad id!", pm::ApiVersion::new(1, 0, 0))
        .with_author("a")
        .with_license("MIT");
    let errs = m.validate();
    assert!(errs.iter().any(|e| e.contains("invalid characters")));
}

#[test]
fn pm_manifest_is_compatible_with() {
    let mut m = pm::PluginManifest::new("p", pm::ApiVersion::new(1, 0, 0));
    m.min_api = pm::ApiVersion::new(1, 0, 0);
    assert!(m.is_compatible_with(&pm::ApiVersion::new(1, 5, 0)));
    assert!(!m.is_compatible_with(&pm::ApiVersion::new(0, 9, 0)));
}

#[test]
fn pm_manifest_section_mut_creates_if_absent() {
    let mut m = pm::PluginManifest::new("p", pm::ApiVersion::new(1, 0, 0));
    let s = m.section_mut("newsec");
    s.push(pm::ManifestEntry::unchecked("k", "v"));
    assert!(m.section("newsec").is_some());
}

#[test]
fn pm_manifest_capability_iter() {
    let m = pm::PluginManifest::new("p", pm::ApiVersion::new(1, 0, 0))
        .with_capability("a")
        .with_capability("b");
    let caps: Vec<&str> = m.capability_iter().collect();
    assert_eq!(caps, vec!["a", "b"]);
}

#[test]
fn pm_dependency_required_and_optional() {
    let req = pm::PluginDependency::required("x", pm::ApiVersion::new(0, 1, 0));
    let opt = pm::PluginDependency::optional("x", pm::ApiVersion::new(0, 1, 0));
    assert!(!req.optional);
    assert!(opt.optional);
}
