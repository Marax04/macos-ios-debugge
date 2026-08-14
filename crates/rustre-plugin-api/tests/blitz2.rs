// Adversarial deep test suite for rustre-plugin-api
use rustre_plugin_api::*;
use std::sync::Arc;

fn lcg() -> impl FnMut() -> u64 {
    let mut s: u64 = 0xDEAD_BEEF_CAFE_BABE;
    move || {
        s = s
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        s
    }
}

// ── Version ──────────────────────────────────────────────────────────────

#[test]
fn version_display_roundtrip_50() {
    let mut g = lcg();
    for _ in 0..50 {
        let a = (g() & 0xFFFF) as u32;
        let b = (g() & 0xFFFF) as u32;
        let c = (g() & 0xFFFF) as u32;
        let v = Version::new(a, b, c);
        let s = v.to_string();
        let parsed = Version::parse(&s).expect("must roundtrip");
        assert_eq!(parsed, v);
    }
}

#[test]
fn version_parse_invalid() {
    assert!(Version::parse("").is_none());
    assert!(Version::parse("1").is_none());
    assert!(Version::parse("1.2").is_none());
    assert!(Version::parse("1.2.3.4").is_none());
    assert!(Version::parse("a.b.c").is_none());
    assert!(Version::parse("1.2.x").is_none());
    assert!(Version::parse("-1.0.0").is_none());
}

#[test]
fn version_parse_boundaries() {
    assert_eq!(
        Version::parse("0.0.0").unwrap(),
        Version::new(0, 0, 0)
    );
    let max = u32::MAX;
    let s = format!("{max}.{max}.{max}");
    assert_eq!(Version::parse(&s).unwrap(), Version::new(max, max, max));
}

#[test]
fn version_compatible_same_major() {
    assert!(Version::new(1, 5, 0).is_compatible_with(&Version::new(1, 2, 0)));
    assert!(!Version::new(1, 1, 0).is_compatible_with(&Version::new(1, 2, 0)));
    assert!(!Version::new(2, 0, 0).is_compatible_with(&Version::new(1, 5, 0)));
}

#[test]
fn version_ordering_total() {
    let a = Version::new(1, 0, 0);
    let b = Version::new(1, 0, 1);
    let c = Version::new(1, 1, 0);
    let d = Version::new(2, 0, 0);
    assert!(a < b);
    assert!(b < c);
    assert!(c < d);
}

#[test]
fn version_hash_eq_pairs() {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut g = lcg();
    for _ in 0..30 {
        let a = Version::new((g() & 0xFF) as u32, (g() & 0xFF) as u32, (g() & 0xFF) as u32);
        let b = a.clone();
        let mut h1 = DefaultHasher::new();
        let mut h2 = DefaultHasher::new();
        assert_eq!(a, b);
        (a.major, a.minor, a.patch).hash(&mut h1);
        (b.major, b.minor, b.patch).hash(&mut h2);
        assert_eq!(h1.finish(), h2.finish());
    }
}

// ── PluginCapability ─────────────────────────────────────────────────────

#[test]
fn capability_as_str_unique() {
    let caps = [
        PluginCapability::Loader,
        PluginCapability::Architecture,
        PluginCapability::AnalysisPass,
        PluginCapability::Decompiler,
        PluginCapability::DebugBackend,
        PluginCapability::UiPanel,
        PluginCapability::ScriptExtension,
        PluginCapability::MlilTransform,
        PluginCapability::HlilTransform,
        PluginCapability::TypeProvider,
        PluginCapability::CallingConvention,
        PluginCapability::PlatformProvider,
        PluginCapability::SignatureProvider,
        PluginCapability::ThemeProvider,
        PluginCapability::SymbolProvider,
        PluginCapability::DataRenderer,
        PluginCapability::Workflow,
        PluginCapability::HighlightProvider,
        PluginCapability::SidebarProvider,
        PluginCapability::NotificationHandler,
        PluginCapability::FileModifier,
        PluginCapability::ProjectHook,
    ];
    let mut seen = std::collections::HashSet::new();
    for c in &caps {
        assert!(seen.insert(c.as_str()), "duplicate {}", c.as_str());
    }
}

#[test]
fn capability_eq_hash_consistency() {
    use std::collections::HashSet;
    let mut s = HashSet::new();
    s.insert(PluginCapability::Loader);
    s.insert(PluginCapability::Loader);
    assert_eq!(s.len(), 1);
    s.insert(PluginCapability::Decompiler);
    assert_eq!(s.len(), 2);
}

// ── PluginManifest ───────────────────────────────────────────────────────

#[test]
fn manifest_builder_chain() {
    let m = PluginManifest::new("p", Version::new(0, 1, 0))
        .with_description("d")
        .with_author("a")
        .with_capability(PluginCapability::Loader)
        .with_capability(PluginCapability::Decompiler)
        .with_dependency(PluginDependency {
            name: "dep".into(),
            version_req: ">=1".into(),
            optional: false,
        });
    assert_eq!(m.capabilities.len(), 2);
    assert_eq!(m.dependencies.len(), 1);
    assert_eq!(m.description, "d");
    assert_eq!(m.author, "a");
    assert_eq!(m.license, "MIT");
}

#[test]
fn manifest_compat_min_version() {
    let mut m = PluginManifest::new("p", Version::new(0, 1, 0));
    m.min_rustre_version = Version::new(0, 1, 0);
    assert!(m.is_compatible());
    m.min_rustre_version = Version::new(99, 0, 0);
    assert!(!m.is_compatible());
}

#[test]
fn manifest_from_meta_parses_version() {
    let meta = PluginMeta {
        id: "x".into(),
        name: "x".into(),
        version: "1.2.3".into(),
        description: "desc".into(),
        author: "auth".into(),
        category: String::new(),
    };
    let m = PluginManifest::from_meta(meta);
    assert_eq!(m.version, Version::new(1, 2, 3));
    assert_eq!(m.description, "desc");
    assert_eq!(m.author, "auth");
}

#[test]
fn manifest_from_meta_bad_version_defaults() {
    let meta = PluginMeta {
        id: "x".into(),
        name: "x".into(),
        version: "garbage".into(),
        description: String::new(),
        author: String::new(),
        category: String::new(),
    };
    let m = PluginManifest::from_meta(meta);
    assert_eq!(m.version, Version::new(0, 0, 0));
}

// ── PluginError ──────────────────────────────────────────────────────────

#[test]
fn plugin_error_display_variants() {
    let errs = vec![
        PluginError::InitFailed("x".into()),
        PluginError::PermissionDenied("p".into()),
        PluginError::CapabilityNotSupported(PluginCapability::Loader),
        PluginError::NotFound("n".into()),
        PluginError::AlreadyRegistered("r".into()),
        PluginError::Incompatible {
            plugin: "p".into(),
            required: Version::new(1, 0, 0),
            found: Version::new(0, 1, 0),
        },
        PluginError::DependencyMissing("dm".into()),
        PluginError::LoadError("l".into()),
        PluginError::UnloadError("ul".into()),
        PluginError::ApiError("api".into()),
        PluginError::InvalidManifest("im".into()),
        PluginError::Serde("se".into()),
    ];
    for e in errs {
        let s = format!("{e}");
        assert!(!s.is_empty());
    }
}

#[test]
fn plugin_error_from_serde() {
    let bad: Result<serde_json::Value, _> = serde_json::from_str("not json");
    let e: PluginError = bad.unwrap_err().into();
    assert!(matches!(e, PluginError::Serde(_)));
}

// ── PluginId ─────────────────────────────────────────────────────────────

#[test]
fn plugin_id_construction() {
    let id = PluginId::new("foo", &Version::new(1, 2, 3));
    assert_eq!(id.as_str(), "foo@1.2.3");
    assert_eq!(id.to_string(), "foo@1.2.3");
}

#[test]
fn plugin_id_hash_eq_30_pairs() {
    use std::collections::HashSet;
    let mut set = HashSet::new();
    let mut g = lcg();
    for _ in 0..30 {
        let n = format!("p{}", g() & 0xFFFF);
        let v = Version::new((g() & 0xFF) as u32, 0, 0);
        let a = PluginId::new(&n, &v);
        let b = PluginId::new(&n, &v);
        assert_eq!(a, b);
        set.insert(a);
    }
    assert!(set.len() <= 30);
}

// ── PluginPermissions ────────────────────────────────────────────────────

#[test]
fn permissions_default_is_none() {
    let p = PluginPermissions::default();
    assert_eq!(p.summary(), "none");
    assert!(!p.can_write_memory());
    assert!(!p.can_execute_code());
    assert!(!p.can_access_network());
    assert!(!p.can_modify_binary());
    assert!(!p.can_read_filesystem());
    assert!(!p.can_write_filesystem());
    assert!(!p.can_spawn_threads());
    assert!(!p.can_use_ui());
    assert!(!p.can_access_debugger());
    assert!(!p.can_modify_graph());
    assert!(!p.can_register_commands());
}

#[test]
fn permissions_all_all_true() {
    let p = PluginPermissions::all();
    assert!(p.can_write_memory());
    assert!(p.can_execute_code());
    assert!(p.can_access_network());
    assert!(p.can_modify_binary());
    assert!(p.can_read_filesystem());
    assert!(p.can_write_filesystem());
    assert!(p.can_spawn_threads());
    assert!(p.can_use_ui());
    assert!(p.can_access_debugger());
    assert!(p.can_modify_graph());
    assert!(p.can_register_commands());
    let sum = p.summary();
    for tok in [
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
        assert!(sum.contains(tok), "summary missing {tok}: {sum}");
    }
}

#[test]
fn permissions_readonly_and_analysis() {
    let p = PluginPermissions::read_only();
    assert!(p.can_read_filesystem());
    assert!(!p.can_write_filesystem());
    assert!(!p.can_modify_graph());
    let p2 = PluginPermissions::analysis_only();
    assert!(p2.can_read_filesystem());
    assert!(p2.can_modify_graph());
    assert!(!p2.can_write_filesystem());
}

// ── EventBus ─────────────────────────────────────────────────────────────

#[test]
fn event_bus_subscribe_publish() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let bus = EventBus::new();
    let c = Arc::new(AtomicUsize::new(0));
    let c2 = c.clone();
    bus.subscribe(
        "binary_opened",
        Box::new(move |_| {
            c2.fetch_add(1, Ordering::SeqCst);
        }),
    );
    bus.publish(&PluginEvent::BinaryOpened { path: "x".into() });
    bus.publish(&PluginEvent::BinaryAnalyzed);
    assert_eq!(c.load(Ordering::SeqCst), 1);
    assert_eq!(bus.handler_count(), 1);
}

#[test]
fn event_bus_wildcard() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let bus = EventBus::new();
    let c = Arc::new(AtomicUsize::new(0));
    let c2 = c.clone();
    bus.subscribe(
        "*",
        Box::new(move |_| {
            c2.fetch_add(1, Ordering::SeqCst);
        }),
    );
    bus.publish(&PluginEvent::AnalysisStarted);
    bus.publish(&PluginEvent::AnalysisFinished);
    bus.publish(&PluginEvent::FunctionAdded { addr: 0 });
    assert_eq!(c.load(Ordering::SeqCst), 3);
}

#[test]
fn event_bus_threaded_stress() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let bus: Arc<EventBus> = Arc::new(EventBus::new());
    let c = Arc::new(AtomicUsize::new(0));
    let c2 = c.clone();
    bus.subscribe(
        "*",
        Box::new(move |_| {
            c2.fetch_add(1, Ordering::SeqCst);
        }),
    );
    let mut handles = vec![];
    for _ in 0..4 {
        let b = bus.clone();
        handles.push(std::thread::spawn(move || {
            for _ in 0..100 {
                b.publish(&PluginEvent::BinaryAnalyzed);
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
    assert_eq!(c.load(Ordering::SeqCst), 400);
}

// ── LogLevel / Logger ────────────────────────────────────────────────────

#[test]
fn log_level_ordering_strings() {
    assert!(LogLevel::Trace < LogLevel::Debug);
    assert!(LogLevel::Debug < LogLevel::Info);
    assert!(LogLevel::Info < LogLevel::Warn);
    assert!(LogLevel::Warn < LogLevel::Error);
    assert_eq!(LogLevel::Trace.as_str(), "TRACE");
    assert_eq!(LogLevel::Error.as_str(), "ERROR");
}

#[test]
fn logger_min_level_filter() {
    let mut l = PluginLogger::new("p");
    l.min_level = LogLevel::Warn;
    l.info("hidden");
    l.debug("hidden");
    l.warn("shown");
    l.error("shown");
    let msgs = l.messages();
    assert_eq!(msgs.len(), 2);
    assert!(msgs[0].1.contains("shown"));
}

#[test]
fn logger_clear() {
    let l = PluginLogger::new("p");
    l.info("a");
    l.info("b");
    assert_eq!(l.messages().len(), 2);
    l.clear();
    assert_eq!(l.messages().len(), 0);
}

#[test]
fn logger_threaded_stress() {
    let l = Arc::new(PluginLogger::new("p"));
    let mut handles = vec![];
    for _ in 0..4 {
        let l2 = l.clone();
        handles.push(std::thread::spawn(move || {
            for i in 0..100 {
                l2.info(&format!("msg-{i}"));
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
    assert_eq!(l.messages().len(), 400);
}

// ── PluginStorage ────────────────────────────────────────────────────────

#[test]
fn storage_set_get_remove() {
    let mut s = PluginStorage::new();
    s.set("k", vec![1, 2, 3]);
    assert!(s.contains("k"));
    assert_eq!(s.get("k"), Some(&[1u8, 2, 3][..]));
    assert_eq!(s.remove("k"), Some(vec![1, 2, 3]));
    assert!(!s.contains("k"));
}

#[test]
fn storage_str_helpers() {
    let mut s = PluginStorage::new();
    s.set_str("k", "hello");
    assert_eq!(s.get_str("k").unwrap(), "hello");
}

#[test]
#[should_panic]
fn storage_key_with_equals_panics_should_panic() {
    let mut s = PluginStorage::new();
    s.set("a=b", vec![1]);
}

#[test]
fn storage_keys_listing() {
    let mut s = PluginStorage::new();
    s.set_str("a", "1");
    s.set_str("b", "2");
    s.set_str("c", "3");
    let mut keys = s.keys();
    keys.sort();
    assert_eq!(keys, vec!["a", "b", "c"]);
}

#[test]
fn storage_persist_and_load_roundtrip() {
    let tmp = std::env::temp_dir().join(format!("rustre-blitz2-store-{}.txt", std::process::id()));
    let mut s = PluginStorage::with_path(tmp.clone());
    s.set("hello", b"world".to_vec());
    s.set("ascii", vec![0, 1, 2, 255]);
    s.persist().unwrap();

    let mut s2 = PluginStorage::with_path(tmp.clone());
    s2.load().unwrap();
    assert_eq!(s2.get("hello"), Some(&b"world"[..]));
    assert_eq!(s2.get("ascii"), Some(&[0u8, 1, 2, 255][..]));
    let _ = std::fs::remove_file(tmp);
}

#[test]
fn storage_load_handles_missing_file() {
    let tmp = std::env::temp_dir().join("rustre-blitz2-doesnotexist-aaa.txt");
    let _ = std::fs::remove_file(&tmp);
    let mut s = PluginStorage::with_path(tmp);
    assert!(s.load().is_ok());
}

#[test]
fn storage_load_handles_malformed_lines() {
    let tmp =
        std::env::temp_dir().join(format!("rustre-blitz2-mal-{}.txt", std::process::id()));
    std::fs::write(&tmp, "noequals\nk=zz\nk2=4142\nodd=abc").unwrap();
    let mut s = PluginStorage::with_path(tmp.clone());
    s.load().unwrap();
    // k=zz: 'zz' is invalid hex => filter_map drops both bytes => empty vec
    assert_eq!(s.get("k"), Some(&[][..]));
    assert_eq!(s.get("k2"), Some(&[0x41u8, 0x42][..]));
    // odd-length: documented to produce empty bytes vec
    assert_eq!(s.get("odd"), Some(&[][..]));
    let _ = std::fs::remove_file(tmp);
}

#[test]
fn storage_fuzz_keys_values() {
    let mut g = lcg();
    let mut s = PluginStorage::new();
    for i in 0..50 {
        let key = format!("k{i}");
        let len = (g() % 32) as usize;
        let mut v = Vec::with_capacity(len);
        for _ in 0..len {
            v.push((g() & 0xFF) as u8);
        }
        s.set(&key, v.clone());
        assert_eq!(s.get(&key), Some(v.as_slice()));
    }
}

// ── CommandRegistry ──────────────────────────────────────────────────────

#[test]
fn command_registry_register_dispatch() {
    let mut cr = CommandRegistry::default();
    cr.register(
        "echo",
        "echoes",
        "echo <arg>",
        Box::new(|args| Ok(args.join(" "))),
    );
    assert!(cr.contains("echo"));
    assert_eq!(
        cr.dispatch("echo", vec!["hi".into(), "there".into()]).unwrap(),
        "hi there"
    );
}

#[test]
fn command_registry_dispatch_missing() {
    let cr = CommandRegistry::default();
    let r = cr.dispatch("nope", vec![]);
    assert!(matches!(r, Err(PluginError::NotFound(_))));
}

#[test]
fn command_registry_list() {
    let mut cr = CommandRegistry::default();
    cr.register("a", "da", "u", Box::new(|_| Ok(String::new())));
    cr.register("b", "db", "u", Box::new(|_| Ok(String::new())));
    let l = cr.list();
    assert_eq!(l.len(), 2);
}

// ── PluginContext ────────────────────────────────────────────────────────

fn make_ctx(perms: PluginPermissions) -> PluginContext {
    let m = PluginManifest::new("ctx", Version::new(0, 1, 0));
    PluginContext::new(m, perms, Arc::new(EventBus::new()))
}

#[test]
fn context_require_permission_denied() {
    let ctx = make_ctx(PluginPermissions::default());
    for p in [
        "write_memory",
        "execute_code",
        "access_network",
        "modify_graph",
        "read_filesystem",
        "write_filesystem",
        "spawn_threads",
        "use_ui",
        "access_debugger",
        "register_commands",
        "modify_binary",
    ] {
        assert!(matches!(
            ctx.require_permission(p),
            Err(PluginError::PermissionDenied(_))
        ));
    }
}

#[test]
fn context_require_permission_granted() {
    let ctx = make_ctx(PluginPermissions::all());
    for p in [
        "write_memory",
        "execute_code",
        "access_network",
        "modify_graph",
        "read_filesystem",
        "write_filesystem",
        "spawn_threads",
        "use_ui",
        "access_debugger",
        "register_commands",
        "modify_binary",
    ] {
        assert!(ctx.require_permission(p).is_ok(), "perm {p} failed");
    }
}

#[test]
fn context_require_permission_unknown() {
    let ctx = make_ctx(PluginPermissions::all());
    assert!(ctx.require_permission("bogus_perm").is_err());
}

#[test]
fn context_register_command_requires_perm() {
    let mut ctx = make_ctx(PluginPermissions::default());
    let r = ctx.register_command("c", "d", "u", Box::new(|_| Ok(String::new())));
    assert!(matches!(r, Err(PluginError::PermissionDenied(_))));

    let mut perms = PluginPermissions::default();
    perms.analysis.register_commands = true;
    let mut ctx = make_ctx(perms);
    let r = ctx.register_command("c", "d", "u", Box::new(|_| Ok("ok".into())));
    assert!(r.is_ok());
    assert!(ctx.commands.contains("c"));
}

#[test]
fn context_storage_helpers() {
    let mut ctx = make_ctx(PluginPermissions::all());
    ctx.store_data("k", vec![9, 9]);
    assert_eq!(ctx.retrieve_data("k"), Some(&[9u8, 9][..]));
    assert_eq!(ctx.plugin_name(), "ctx");
    assert_eq!(ctx.plugin_version(), &Version::new(0, 1, 0));
}

#[test]
fn context_publish_event_reaches_subscriber() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let bus = Arc::new(EventBus::new());
    let c = Arc::new(AtomicUsize::new(0));
    let c2 = c.clone();
    bus.subscribe(
        "*",
        Box::new(move |_| {
            c2.fetch_add(1, Ordering::SeqCst);
        }),
    );
    let ctx = PluginContext::new(
        PluginManifest::new("x", Version::new(0, 1, 0)),
        PluginPermissions::all(),
        bus.clone(),
    );
    ctx.publish_event(&PluginEvent::AnalysisStarted);
    assert_eq!(c.load(Ordering::SeqCst), 1);
}

#[test]
fn context_has_capability() {
    let m = PluginManifest::new("x", Version::new(0, 1, 0))
        .with_capability(PluginCapability::Decompiler);
    let ctx = PluginContext::new(m, PluginPermissions::default(), Arc::new(EventBus::new()));
    assert!(ctx.has_capability(&PluginCapability::Decompiler));
    assert!(!ctx.has_capability(&PluginCapability::Loader));
}

// ── PluginRegistry ───────────────────────────────────────────────────────

fn stub_arc(name: &str) -> Arc<dyn Plugin> {
    Arc::new(StubPlugin::new(name, Version::new(0, 1, 0)))
}

#[test]
fn registry_register_and_query() {
    let bus = Arc::new(EventBus::new());
    let mut reg = PluginRegistry::new(bus);
    let id = reg.register(stub_arc("foo"), PluginPermissions::all()).unwrap();
    assert_eq!(reg.count(), 1);
    assert!(reg.get(&id).is_some());
    assert!(reg.get_context(&id).is_some());
    assert!(reg.get_context_mut(&id).is_some());
    assert_eq!(reg.list().len(), 1);
    assert!(reg.find_by_name("foo").is_some());
    assert!(reg.find_by_name("nope").is_none());
}

#[test]
fn registry_duplicate_fails() {
    let mut reg = PluginRegistry::new(Arc::new(EventBus::new()));
    reg.register(stub_arc("dup"), PluginPermissions::all()).unwrap();
    let r = reg.register(stub_arc("dup"), PluginPermissions::all());
    assert!(matches!(r, Err(PluginError::AlreadyRegistered(_))));
}

#[test]
fn registry_incompatible_rejected() {
    let mut reg = PluginRegistry::new(Arc::new(EventBus::new()));
    let stub = StubPlugin::new("inc", Version::new(0, 1, 0));
    // Wrap by a plugin that returns a manifest with high min_rustre_version.
    struct Bad(StubPlugin);
    impl Plugin for Bad {
        fn name(&self) -> &str {
            self.0.name()
        }
        fn version(&self) -> &Version {
            self.0.version()
        }
        fn capabilities(&self) -> Vec<PluginCapability> {
            self.0.capabilities()
        }
        fn manifest(&self) -> PluginManifest {
            let mut m = self.0.manifest();
            m.min_rustre_version = Version::new(99, 0, 0);
            m
        }
        fn init(&self, ctx: &mut PluginContext) -> PluginResult<()> {
            self.0.init(ctx)
        }
        fn unload(&self, ctx: &mut PluginContext) {
            self.0.unload(ctx);
        }
        fn as_any(&self) -> &dyn std::any::Any {
            self
        }
    }
    let r = reg.register(Arc::new(Bad(stub)), PluginPermissions::all());
    assert!(matches!(r, Err(PluginError::Incompatible { .. })));
}

#[test]
fn registry_init_failure_propagates() {
    let mut reg = PluginRegistry::new(Arc::new(EventBus::new()));
    let p: Arc<dyn Plugin> =
        Arc::new(StubPlugin::new("bad", Version::new(0, 1, 0)).fail_init());
    let r = reg.register(p, PluginPermissions::all());
    assert!(matches!(r, Err(PluginError::InitFailed(_))));
}

#[test]
fn registry_unregister_removes() {
    let mut reg = PluginRegistry::new(Arc::new(EventBus::new()));
    let id = reg.register(stub_arc("x"), PluginPermissions::all()).unwrap();
    reg.unregister(&id).unwrap();
    assert_eq!(reg.count(), 0);
    assert!(reg.unregister(&id).is_err());
}

#[test]
fn registry_find_by_capability() {
    let mut reg = PluginRegistry::new(Arc::new(EventBus::new()));
    let p: Arc<dyn Plugin> = Arc::new(
        StubPlugin::new("loader", Version::new(0, 1, 0))
            .with_capability(PluginCapability::Loader),
    );
    reg.register(p, PluginPermissions::all()).unwrap();
    let found = reg.find_by_capability(&PluginCapability::Loader);
    assert_eq!(found.len(), 1);
    let empty = reg.find_by_capability(&PluginCapability::Decompiler);
    assert!(empty.is_empty());
}

#[test]
fn registry_load_from_file_unimplemented() {
    let mut reg = PluginRegistry::new(Arc::new(EventBus::new()));
    let r = reg.load_from_file(
        std::path::Path::new("nope.so"),
        &PluginPermissions::default(),
    );
    assert!(matches!(r, Err(PluginError::LoadError(_))));
}

// ── PluginHostManager ────────────────────────────────────────────────────

#[test]
fn host_manager_watch_paths() {
    let bus = Arc::new(EventBus::new());
    let mut m = PluginHostManager::new(bus);
    assert!(!m.watch_paths().is_empty());
    m.add_watch_path(std::path::PathBuf::from("./extra"));
    assert!(m.watch_paths().iter().any(|p| p.ends_with("extra")));
    m.set_default_permissions(PluginPermissions::all());
    // scan_and_load on possibly-missing paths must not panic
    let _ = m.scan_and_load();
}

#[test]
fn host_manager_register_plugin() {
    let bus = Arc::new(EventBus::new());
    let mut m = PluginHostManager::new(bus);
    let id = m
        .register_plugin(stub_arc("p1"), PluginPermissions::all())
        .unwrap();
    assert!(id.as_str().contains("p1"));
}

// ── Stub Loader / Analysis ───────────────────────────────────────────────

#[test]
fn stub_loader_probe_load() {
    let l = StubLoaderPlugin::new("L", b"\x7fELF".to_vec(), 90);
    assert_eq!(l.probe(b"\x7fELFxxx"), 90);
    assert_eq!(l.probe(b"MZxx"), 0);
    assert_eq!(l.probe(b""), 0);
    let info = l
        .load(LoaderInput {
            path: None,
            data: vec![],
            base_addr: Some(0x4000),
            entry_point: Some(0x4100),
        })
        .unwrap();
    assert_eq!(info.entry_point, 0x4100);
    assert_eq!(info.base_address, 0x4000);
    assert_eq!(l.supported_extensions(), vec!["bin"]);
}

#[test]
fn stub_loader_default_addrs() {
    let l = StubLoaderPlugin::new("L", b"M".to_vec(), 10);
    let info = l
        .load(LoaderInput {
            path: None,
            data: vec![],
            base_addr: None,
            entry_point: None,
        })
        .unwrap();
    assert_eq!(info.entry_point, 0x1000);
    assert_eq!(info.base_address, 0);
}

#[test]
fn stub_analysis_run_on_function() {
    let a = StubAnalysisPlugin::new("A");
    let mut fi = FunctionInfo {
        name: "f".into(),
        address: 0x1000,
        ..Default::default()
    };
    let ctx = make_ctx(PluginPermissions::all());
    let rep = a.run_on_function(&mut fi, &ctx).unwrap();
    assert_eq!(rep.findings.len(), 1);
    assert_eq!(rep.findings[0].address, 0x1000);
}

// ── PluginRegisterFn / Const ─────────────────────────────────────────────

#[test]
fn plugin_magic_constant() {
    assert_eq!(PLUGIN_MAGIC.len(), 8);
    assert_eq!(&PLUGIN_MAGIC[..7], b"RUSTREP");
    assert_eq!(PLUGIN_MAGIC[7], 0);
}

#[test]
fn rustre_version_constant() {
    assert_eq!(RUSTRE_VERSION, Version::new(0, 1, 0));
}

// ── Send + Sync ─────────────────────────────────────────────────────────

#[test]
fn send_sync_bounds() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<EventBus>();
    assert_send_sync::<Arc<EventBus>>();
    assert_send_sync::<PluginLogger>();
    assert_send_sync::<Version>();
    assert_send_sync::<PluginId>();
    assert_send_sync::<PluginCapability>();
}

// ── Version fuzz ─────────────────────────────────────────────────────────

#[test]
fn version_parse_fuzz_no_panic() {
    let mut g = lcg();
    for _ in 0..200 {
        let len = (g() % 12) as usize;
        let mut s = String::with_capacity(len);
        for _ in 0..len {
            let ch = match g() % 5 {
                0 => '.',
                1 => (b'0' + (g() % 10) as u8) as char,
                2 => (b'a' + (g() % 26) as u8) as char,
                3 => '-',
                _ => ' ',
            };
            s.push(ch);
        }
        let _ = Version::parse(&s);
    }
}
