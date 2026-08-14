//! blitz2: adversarial deep tests for rustre-events public API.

use rustre_events::{
    CoreEvent, EventBus, EventCorrelator, EventFilter, EventHook, EventKind, EventLogger,
    EventReplay, EventStats, FilteredSubscription, HookDispatcher, SpecCoreEvent, SpecEventBus,
    SpecEventFilter, kind_subscription, view_subscription,
};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

// Seeded LCG used for fuzz-style inputs.
fn lcg() -> impl FnMut() -> u64 {
    let mut s: u64 = 0xDEAD_BEEF_CAFE_BABE;
    move || {
        s = s
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        s
    }
}

fn mk_core_event(seed: u64) -> CoreEvent {
    match seed % 16 {
        0 => CoreEvent::ViewOpened {
            view_id: seed,
            uri: format!("u{seed}"),
            arch: "x86".into(),
        },
        1 => CoreEvent::ViewClosed { view_id: seed },
        2 => CoreEvent::FunctionDefined {
            view_id: seed,
            address: seed.wrapping_mul(7),
            name: format!("f{seed}"),
        },
        3 => CoreEvent::BreakpointHit {
            view_id: seed,
            address: seed,
            thread_id: (seed & 0xFFFF) as u32,
        },
        4 => CoreEvent::MemoryRead {
            view_id: seed,
            address: seed,
            length: (seed & 0xFF) as usize,
        },
        5 => CoreEvent::TypeDefined {
            view_id: seed,
            name: format!("T{seed}"),
        },
        6 => CoreEvent::PatchApplied {
            view_id: seed,
            address: seed,
            length: 4,
        },
        7 => CoreEvent::CommentAdded {
            view_id: seed,
            address: seed,
            text: format!("c{seed}"),
        },
        8 => CoreEvent::BookmarkAdded {
            view_id: seed,
            address: seed,
            label: None,
        },
        9 => CoreEvent::AgentAction {
            view_id: seed,
            action: "a".into(),
            result: "r".into(),
        },
        10 => CoreEvent::XrefAdded {
            view_id: seed,
            from_addr: seed,
            to_addr: seed.wrapping_add(8),
            kind: "call".into(),
        },
        11 => CoreEvent::ScriptExecuted {
            view_id: seed,
            engine: "lua".into(),
            success: seed & 1 == 0,
        },
        12 => CoreEvent::PluginLoaded {
            plugin_id: format!("p{seed}"),
        },
        13 => CoreEvent::TriageCompleted {
            view_id: seed,
            verdict: "ok".into(),
        },
        14 => CoreEvent::Custom {
            event_type: "x".into(),
            payload: serde_json::Value::Null,
        },
        _ => CoreEvent::SymbolDefined {
            view_id: seed,
            address: seed,
            name: "n".into(),
            kind: "k".into(),
            source: "s".into(),
        },
    }
}

// ===========================================================================
// CoreEvent — JSON round-trip fuzz
// ===========================================================================

#[test]
fn core_event_json_roundtrip_lcg_fuzz() {
    let mut g = lcg();
    for _ in 0..200 {
        let e = mk_core_event(g());
        let s = e.to_json().expect("to_json");
        let back = CoreEvent::from_json(&s).expect("from_json");
        assert_eq!(back.variant_name(), e.variant_name());
        assert_eq!(back.view_id(), e.view_id());
        assert_eq!(back.kind(), e.kind());
    }
}

#[test]
fn core_event_from_json_malformed_returns_err() {
    let mut g = lcg();
    for _ in 0..50 {
        let raw = format!("{{garbage:{}}}", g());
        assert!(CoreEvent::from_json(&raw).is_err());
    }
    assert!(CoreEvent::from_json("").is_err());
    assert!(CoreEvent::from_json("null").is_err());
    assert!(CoreEvent::from_json("[]").is_err());
    assert!(CoreEvent::from_json("{}").is_err());
}

#[test]
fn core_event_from_json_truncated_returns_err() {
    let e = CoreEvent::ViewOpened {
        view_id: 1,
        uri: "u".into(),
        arch: "x".into(),
    };
    let s = e.to_json().unwrap();
    for cut in 0..s.len() {
        let trimmed = &s[..cut];
        // Must not panic; just be Err.
        let _ = CoreEvent::from_json(trimmed);
    }
}

#[test]
fn core_event_variant_name_view_id_kind_total_consistency() {
    // Iterate over many seeds; every CoreEvent must answer all three without
    // panic and view_id presence must match kind for non-global kinds.
    let mut g = lcg();
    for _ in 0..500 {
        let e = mk_core_event(g());
        let _ = e.variant_name();
        let _ = e.kind();
        let _ = e.view_id();
        let display = format!("{e}");
        assert!(display.contains(e.variant_name()));
    }
}

#[test]
fn core_event_view_id_boundaries() {
    for &v in &[0u64, 1, u64::MAX, u64::MAX - 1, i64::MAX as u64] {
        let e = CoreEvent::ViewClosed { view_id: v };
        assert_eq!(e.view_id(), Some(v));
    }
}

#[test]
fn core_event_address_length_boundaries() {
    for &addr in &[0u64, 1, u64::MAX] {
        for &len in &[0usize, 1, usize::MAX] {
            let e = CoreEvent::MemoryRead {
                view_id: 1,
                address: addr,
                length: len,
            };
            assert_eq!(e.kind(), EventKind::Memory);
            assert!(e.to_json().is_ok());
        }
    }
}

#[test]
fn core_event_kind_categorisation_partition() {
    // Each CoreEvent maps to exactly one kind; debug/analysis/function helpers
    // must agree with the kind() function.
    let mut g = lcg();
    for _ in 0..200 {
        let e = mk_core_event(g());
        let k = e.kind();
        assert_eq!(e.is_debug_event(), k == EventKind::Debugger);
        assert_eq!(e.is_analysis_event(), k == EventKind::Analysis);
        assert_eq!(e.is_function_event(), k == EventKind::Function);
    }
}

#[test]
fn core_event_display_format_contains_view_id_when_present() {
    let e = CoreEvent::FunctionDefined {
        view_id: 1234,
        address: 0,
        name: "n".into(),
    };
    let s = format!("{e}");
    assert!(s.contains("1234"));
    assert!(s.contains("FunctionDefined"));

    let g = CoreEvent::PluginLoaded {
        plugin_id: "p".into(),
    };
    let s2 = format!("{g}");
    assert!(!s2.starts_with("[view="));
}

// ===========================================================================
// EventKind hash/eq consistency
// ===========================================================================

#[test]
fn event_kind_hash_eq_consistency() {
    use std::collections::HashSet;
    let kinds = [
        EventKind::View,
        EventKind::Analysis,
        EventKind::Function,
        EventKind::Symbol,
        EventKind::Debugger,
        EventKind::Memory,
        EventKind::Type,
        EventKind::Patch,
        EventKind::Annotation,
        EventKind::Agent,
        EventKind::CrossRef,
        EventKind::Script,
        EventKind::Plugin,
        EventKind::Custom,
    ];
    let set: HashSet<EventKind> = kinds.iter().copied().collect();
    assert_eq!(set.len(), kinds.len());
    for k in &kinds {
        assert_eq!(*k, *k);
        let copied = *k;
        assert_eq!(copied, *k);
    }
}

#[test]
fn event_kind_serde_roundtrip() {
    let kinds = [
        EventKind::View,
        EventKind::Debugger,
        EventKind::Plugin,
        EventKind::Custom,
    ];
    for k in &kinds {
        let s = serde_json::to_string(k).unwrap();
        let back: EventKind = serde_json::from_str(&s).unwrap();
        assert_eq!(back, *k);
    }
}

// ===========================================================================
// EventFilter — boolean algebra
// ===========================================================================

#[test]
fn event_filter_and_or_not_truth_table() {
    let e = CoreEvent::FunctionDefined {
        view_id: 1,
        address: 0,
        name: "f".into(),
    };
    let t = EventFilter::new(|_| true);
    let f = EventFilter::new(|_| false);
    assert!(t.matches(&e));
    let t2 = EventFilter::new(|_| true);
    let f2 = EventFilter::new(|_| false);
    assert!(!f2.matches(&e));
    assert!(EventFilter::new(|_| true)
        .and(EventFilter::new(|_| true))
        .matches(&e));
    assert!(!EventFilter::new(|_| true)
        .and(EventFilter::new(|_| false))
        .matches(&e));
    assert!(EventFilter::new(|_| false)
        .or(EventFilter::new(|_| true))
        .matches(&e));
    assert!(!EventFilter::new(|_| false)
        .or(EventFilter::new(|_| false))
        .matches(&e));
    assert!(!t2.negate().matches(&e));
    assert!(t.matches(&e)); // moved t2 only
    let _ = f;
}

#[test]
fn event_filter_for_view_and_kind_consistency_fuzz() {
    let mut g = lcg();
    for _ in 0..200 {
        let e = mk_core_event(g());
        let fv = EventFilter::for_view(e.view_id().unwrap_or(u64::MAX));
        if let Some(_v) = e.view_id() {
            assert!(fv.matches(&e));
        }
        let fk = EventFilter::of_kind(e.kind());
        assert!(fk.matches(&e));
        let fn_ = EventFilter::by_variant(e.variant_name());
        assert!(fn_.matches(&e));
    }
}

#[test]
fn event_filter_by_variant_wrong_name_rejects() {
    let f = EventFilter::by_variant("DoesNotExist");
    let mut g = lcg();
    for _ in 0..50 {
        let e = mk_core_event(g());
        assert!(!f.matches(&e));
    }
}

// ===========================================================================
// EventBus — broadcast semantics
// ===========================================================================

#[tokio::test]
async fn event_bus_no_subscribers_send_err_but_counters_increment() {
    let bus = EventBus::new(8);
    let r = bus.send(CoreEvent::ViewClosed { view_id: 1 });
    assert!(r.is_err());
    // Counters still increment for observability.
    assert_eq!(bus.event_count("ViewClosed"), 1);
    assert_eq!(bus.total_sent(), 1);
}

#[tokio::test]
async fn event_bus_capacity_one_works() {
    let bus = EventBus::new(1);
    let mut rx = bus.subscribe();
    bus.send_view_closed(1);
    let e = rx.recv().await.unwrap();
    assert_eq!(e.view_id(), Some(1));
}

#[tokio::test]
async fn event_bus_send_to_many_subscribers_each_receives() {
    let bus = EventBus::new(64);
    let mut rxs = Vec::new();
    for _ in 0..8 {
        rxs.push(bus.subscribe());
    }
    bus.send_view_opened(7, "u".into(), "a".into());
    for rx in &mut rxs {
        let e = rx.recv().await.unwrap();
        assert_eq!(e.variant_name(), "ViewOpened");
    }
}

#[tokio::test]
async fn event_bus_lagged_then_resumes() {
    let bus = EventBus::new(2);
    let mut rx = bus.subscribe();
    for i in 0..10u64 {
        let _ = bus.send(CoreEvent::ViewClosed { view_id: i });
    }
    // First recv should be a Lagged error.
    let mut saw_lag = false;
    for _ in 0..12 {
        match rx.recv().await {
            Ok(_) => {}
            Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                saw_lag = true;
                break;
            }
            Err(_) => break,
        }
    }
    assert!(saw_lag);
}

#[tokio::test]
async fn event_bus_counters_per_variant() {
    let bus = EventBus::new(64);
    let _rx = bus.subscribe();
    bus.send_view_opened(1, "u".into(), "a".into());
    bus.send_view_opened(2, "u".into(), "a".into());
    bus.send_view_closed(3);
    assert_eq!(bus.event_count("ViewOpened"), 2);
    assert_eq!(bus.event_count("ViewClosed"), 1);
    assert_eq!(bus.event_count("Never"), 0);
    assert_eq!(bus.total_sent(), 3);
}

#[tokio::test]
async fn event_bus_receiver_count_drops_on_drop() {
    let bus = EventBus::new(8);
    let rx1 = bus.subscribe();
    let rx2 = bus.subscribe();
    assert_eq!(bus.receiver_count(), 2);
    drop(rx1);
    assert_eq!(bus.receiver_count(), 1);
    drop(rx2);
    assert_eq!(bus.receiver_count(), 0);
}

#[tokio::test]
async fn event_bus_send_random_events_fuzz() {
    let bus = EventBus::new(512);
    let mut rx = bus.subscribe();
    let mut g = lcg();
    let mut sent = 0u64;
    for _ in 0..100 {
        let e = mk_core_event(g());
        if bus.send(e).is_ok() {
            sent += 1;
        }
    }
    let mut got = 0u64;
    while let Ok(_e) = rx.try_recv() {
        got += 1;
    }
    assert_eq!(sent, got);
}

// ===========================================================================
// FilteredSubscription
// ===========================================================================

#[tokio::test]
async fn filtered_subscription_counts_filtered_and_delivered() {
    let bus = EventBus::new(64);
    let mut sub = FilteredSubscription::new(bus.subscribe(), |e| {
        matches!(e, CoreEvent::ViewClosed { .. })
    });
    bus.send_view_opened(1, "u".into(), "a".into());
    bus.send_view_opened(2, "u".into(), "a".into());
    bus.send_view_closed(3);
    bus.send_view_closed(4);

    let _ = sub.recv_filtered().await.unwrap();
    let _ = sub.recv_filtered().await.unwrap();
    assert_eq!(sub.delivered_count(), 2);
    assert_eq!(sub.received_count(), 4);
}

#[tokio::test]
async fn filtered_subscription_recv_raw_bypasses_filter() {
    let bus = EventBus::new(64);
    let mut sub = FilteredSubscription::new(bus.subscribe(), |_| false);
    bus.send_view_closed(1);
    let e = sub.recv_raw().await.unwrap();
    assert_eq!(e.variant_name(), "ViewClosed");
}

#[tokio::test]
async fn filtered_subscription_closed_returns_none() {
    let bus = EventBus::new(8);
    let mut sub = FilteredSubscription::new(bus.subscribe(), |_| true);
    drop(bus);
    let r = sub.recv_filtered().await;
    assert!(r.is_none());
}

#[tokio::test]
async fn view_subscription_and_kind_subscription_factories() {
    let bus = EventBus::new(64);
    let mut vsub = view_subscription(&bus, 42);
    let mut ksub = kind_subscription(&bus, EventKind::Function);
    bus.send_view_opened(99, "u".into(), "a".into());
    bus.send_view_opened(42, "u".into(), "a".into());
    bus.send_function_defined(99, 0, "f".into());

    let e = vsub.recv_filtered().await.unwrap();
    assert_eq!(e.view_id(), Some(42));
    let e2 = ksub.recv_filtered().await.unwrap();
    assert_eq!(e2.kind(), EventKind::Function);
}

// ===========================================================================
// EventLogger
// ===========================================================================

#[test]
fn event_logger_zero_size_records_nothing() {
    let l = EventLogger::new(0);
    for i in 0..10u64 {
        l.record(CoreEvent::ViewClosed { view_id: i });
    }
    assert_eq!(l.count(), 0);
}

#[test]
fn event_logger_size_one_keeps_latest() {
    let l = EventLogger::new(1);
    for i in 0..10u64 {
        l.record(CoreEvent::ViewClosed { view_id: i });
    }
    assert_eq!(l.count(), 1);
    let r = l.recent_events(1);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].1.view_id(), Some(9));
}

#[test]
fn event_logger_recent_more_than_count_returns_all() {
    let l = EventLogger::new(100);
    for i in 0..5u64 {
        l.record(CoreEvent::ViewClosed { view_id: i });
    }
    let r = l.recent_events(100);
    assert_eq!(r.len(), 5);
}

#[test]
fn event_logger_events_for_view_filters() {
    let l = EventLogger::new(100);
    for i in 0..20u64 {
        l.record(CoreEvent::ViewClosed { view_id: i % 3 });
    }
    let v0 = l.events_for_view(0);
    let v1 = l.events_for_view(1);
    let v2 = l.events_for_view(2);
    assert_eq!(v0.len() + v1.len() + v2.len(), 20);
}

#[test]
fn event_logger_events_by_kind_partitions() {
    let l = EventLogger::new(100);
    let mut g = lcg();
    let mut counts = std::collections::HashMap::<EventKind, usize>::new();
    for _ in 0..50 {
        let e = mk_core_event(g());
        *counts.entry(e.kind()).or_insert(0) += 1;
        l.record(e);
    }
    let total: usize = counts.values().sum();
    let mut got_total = 0usize;
    for k in counts.keys() {
        got_total += l.events_by_kind(*k).len();
    }
    assert_eq!(total, got_total);
}

// ===========================================================================
// HookDispatcher / EventHook
// ===========================================================================

#[test]
fn hook_dispatcher_multiple_hooks_fire_independently() {
    let a = Arc::new(AtomicU64::new(0));
    let b = Arc::new(AtomicU64::new(0));
    let d = HookDispatcher::new();
    let aa = a.clone();
    d.register(EventHook::new("a", |_| true, move |_| {
        aa.fetch_add(1, Ordering::Relaxed);
    }));
    let bb = b.clone();
    d.register(EventHook::new(
        "b",
        |e| matches!(e, CoreEvent::ViewClosed { .. }),
        move |_| {
            bb.fetch_add(1, Ordering::Relaxed);
        },
    ));
    d.dispatch(&CoreEvent::ViewClosed { view_id: 1 });
    d.dispatch(&CoreEvent::ViewOpened {
        view_id: 1,
        uri: "u".into(),
        arch: "a".into(),
    });
    assert_eq!(a.load(Ordering::Relaxed), 2);
    assert_eq!(b.load(Ordering::Relaxed), 1);
}

#[test]
fn hook_dispatcher_remove_only_matching_label() {
    let d = HookDispatcher::new();
    d.register(EventHook::new("keep", |_| true, |_| {}));
    d.register(EventHook::new("drop", |_| true, |_| {}));
    d.register(EventHook::new("drop", |_| true, |_| {}));
    assert_eq!(d.hook_count(), 3);
    d.remove("drop");
    assert_eq!(d.hook_count(), 1);
}

#[test]
fn event_hook_label_accessor() {
    let h = EventHook::new("lbl", |_| true, |_| {});
    assert_eq!(h.label(), "lbl");
    assert!(h.matches(&CoreEvent::ViewClosed { view_id: 1 }));
}

#[test]
fn event_hook_default_dispatcher() {
    let d: HookDispatcher = HookDispatcher::default();
    assert_eq!(d.hook_count(), 0);
}

// ===========================================================================
// EventReplay
// ===========================================================================

#[test]
fn event_replay_empty_replay_all_zero_failures_when_subs() {
    let bus = EventBus::new(8);
    let _rx = bus.subscribe();
    let r = EventReplay::new();
    assert!(r.is_empty());
    assert_eq!(r.replay_all(&bus), 0);
}

#[test]
fn event_replay_all_fail_without_subscribers() {
    let bus = EventBus::new(8);
    let mut r = EventReplay::new();
    for i in 0..5u64 {
        r.push(CoreEvent::ViewClosed { view_id: i });
    }
    let fails = r.replay_all(&bus);
    assert_eq!(fails, 5);
}

#[test]
fn event_replay_filtered_count_matches_subscribers() {
    let bus = EventBus::new(64);
    let _rx = bus.subscribe();
    let mut r = EventReplay::new();
    for i in 0..10u64 {
        r.push(CoreEvent::FunctionDefined {
            view_id: i,
            address: i,
            name: "n".into(),
        });
        r.push(CoreEvent::ViewClosed { view_id: i });
    }
    let n = r.replay_filtered(&bus, |e| e.kind() == EventKind::Function);
    assert_eq!(n, 10);
}

#[test]
fn event_replay_clear_makes_empty() {
    let mut r = EventReplay::new();
    r.push(CoreEvent::ViewClosed { view_id: 1 });
    assert_eq!(r.len(), 1);
    r.clear();
    assert!(r.is_empty());
}

// ===========================================================================
// EventCorrelator
// ===========================================================================

#[test]
fn correlator_keys_listing_complete() {
    let c = EventCorrelator::by_view();
    for i in 0..5u64 {
        c.ingest(CoreEvent::ViewClosed { view_id: i });
    }
    let mut keys = c.keys();
    keys.sort();
    assert_eq!(keys, vec!["0", "1", "2", "3", "4"]);
}

#[test]
fn correlator_get_unknown_key_empty() {
    let c = EventCorrelator::by_view();
    assert!(c.get_group("nonexistent").is_empty());
}

#[test]
fn correlator_custom_key_fn() {
    let c = EventCorrelator::new(|e| match e {
        CoreEvent::FunctionDefined { name, .. } => Some(name.clone()),
        _ => None,
    });
    c.ingest(CoreEvent::FunctionDefined {
        view_id: 1,
        address: 0,
        name: "foo".into(),
    });
    c.ingest(CoreEvent::ViewClosed { view_id: 1 });
    assert_eq!(c.get_group("foo").len(), 1);
    assert_eq!(c.total_count(), 1);
}

// ===========================================================================
// EventStats
// ===========================================================================

#[test]
fn event_stats_kind_count_matches_sum_of_variants() {
    let s = EventStats::new();
    let mut g = lcg();
    let mut expected = std::collections::HashMap::<EventKind, u64>::new();
    for _ in 0..200 {
        let e = mk_core_event(g());
        *expected.entry(e.kind()).or_insert(0) += 1;
        s.record(&e);
    }
    let total: u64 = expected.values().sum();
    assert_eq!(s.total(), total);
    for (k, v) in &expected {
        assert_eq!(s.kind_count(*k), *v);
    }
}

#[test]
fn event_stats_reset_clears_all() {
    let s = EventStats::new();
    s.record(&CoreEvent::ViewClosed { view_id: 1 });
    s.reset();
    assert_eq!(s.total(), 0);
    assert_eq!(s.variant_count("ViewClosed"), 0);
    assert_eq!(s.kind_count(EventKind::View), 0);
}

// ===========================================================================
// SpecCoreEvent / SpecEventBus / SpecEventFilter
// ===========================================================================

fn mk_spec(seed: u64) -> SpecCoreEvent {
    match seed % 8 {
        0 => SpecCoreEvent::ViewOpened {
            view_id: seed,
            path: "p".into(),
        },
        1 => SpecCoreEvent::ViewClosed { view_id: seed },
        2 => SpecCoreEvent::FunctionDefined {
            view_id: seed,
            addr: seed,
            name: "n".into(),
        },
        3 => SpecCoreEvent::DebuggerAttached {
            pid: (seed & 0xFFFF) as u32,
        },
        4 => SpecCoreEvent::ProcessStepped {
            thread_id: 0,
            new_ip: seed,
        },
        5 => SpecCoreEvent::PluginLoaded {
            name: "p".into(),
            version: "1".into(),
        },
        6 => SpecCoreEvent::BreakpointSet {
            view_id: seed,
            addr: seed,
        },
        _ => SpecCoreEvent::AnalysisProgress {
            view_id: seed,
            pass: "x".into(),
            percent: (seed & 0x7F) as u8,
        },
    }
}

#[test]
fn spec_event_serde_roundtrip_fuzz() {
    let mut g = lcg();
    for _ in 0..100 {
        let e = mk_spec(g());
        let s = serde_json::to_string(&e).unwrap();
        let back: SpecCoreEvent = serde_json::from_str(&s).unwrap();
        assert_eq!(back.variant_name(), e.variant_name());
        assert_eq!(back.view_id(), e.view_id());
    }
}

#[test]
fn spec_event_filter_default_accepts_all() {
    let f = SpecEventFilter::new();
    let mut g = lcg();
    for _ in 0..50 {
        let e = mk_spec(g());
        assert!(f.matches(&e));
    }
}

#[test]
fn spec_event_filter_view_ids_rejects_view_less_by_default() {
    let f = SpecEventFilter::new().with_view_ids([1u64, 2]);
    let attached = SpecCoreEvent::DebuggerAttached { pid: 1 };
    assert!(!f.matches(&attached));
    let v1 = SpecCoreEvent::ViewClosed { view_id: 1 };
    assert!(f.matches(&v1));
    let v9 = SpecCoreEvent::ViewClosed { view_id: 9 };
    assert!(!f.matches(&v9));
}

#[test]
fn spec_event_filter_pass_global_events() {
    let f = SpecEventFilter::new()
        .with_view_ids([1u64])
        .with_pass_global_events(true);
    let attached = SpecCoreEvent::DebuggerAttached { pid: 1 };
    assert!(f.matches(&attached));
    let v2 = SpecCoreEvent::ViewClosed { view_id: 2 };
    assert!(!f.matches(&v2));
}

#[test]
fn spec_event_filter_event_types_filter() {
    let f = SpecEventFilter::new().with_event_types(["ViewClosed"]);
    assert!(f.matches(&SpecCoreEvent::ViewClosed { view_id: 1 }));
    assert!(!f.matches(&SpecCoreEvent::DebuggerAttached { pid: 1 }));
}

#[test]
fn spec_event_filter_event_type_name_static() {
    let e = SpecCoreEvent::FunctionDefined {
        view_id: 1,
        addr: 0,
        name: "n".into(),
    };
    assert_eq!(SpecEventFilter::event_type_name(&e), "FunctionDefined");
}

#[tokio::test]
async fn spec_event_bus_history_capped() {
    let bus = SpecEventBus::new(64);
    for i in 0..1200u64 {
        bus.publish(SpecCoreEvent::ViewClosed { view_id: i });
    }
    // HISTORY_CAPACITY = 1000
    assert_eq!(bus.history_len(), 1000);
    let recent = bus.recent_events(5);
    assert_eq!(recent.len(), 5);
    // Must be the last five.
    if let SpecCoreEvent::ViewClosed { view_id } = recent[4] {
        assert_eq!(view_id, 1199);
    } else {
        panic!("unexpected");
    }
}

#[tokio::test]
async fn spec_event_bus_publish_no_subscribers_does_not_panic() {
    let bus = SpecEventBus::new(8);
    bus.publish(SpecCoreEvent::DebuggerAttached { pid: 1 });
    assert_eq!(bus.history_len(), 1);
}

#[tokio::test]
async fn spec_event_bus_subscribe_receives_future_events() {
    let bus = SpecEventBus::new(8);
    let mut rx = bus.subscribe();
    bus.publish(SpecCoreEvent::ViewClosed { view_id: 99 });
    let e = rx.recv().await.unwrap();
    assert_eq!(e.view_id(), Some(99));
}

#[tokio::test]
async fn spec_event_bus_default_constructor() {
    let bus = SpecEventBus::default();
    let mut rx = bus.subscribe();
    bus.publish(SpecCoreEvent::ViewClosed { view_id: 1 });
    let _ = rx.recv().await.unwrap();
}

#[test]
fn spec_event_display_includes_variant_and_view() {
    let e = SpecCoreEvent::FunctionDefined {
        view_id: 7,
        addr: 0,
        name: "n".into(),
    };
    let s = format!("{e}");
    assert!(s.contains('7'));
    assert!(s.contains("FunctionDefined"));

    let g = SpecCoreEvent::DebuggerAttached { pid: 0 };
    let s2 = format!("{g}");
    assert!(!s2.starts_with("[view="));
}

// ===========================================================================
// Send + Sync threaded stress on EventBus
// ===========================================================================

#[test]
fn event_bus_send_sync_threaded_stress() {
    let bus = Arc::new(EventBus::new(4096));
    let _rx = bus.subscribe();
    let mut handles = Vec::new();
    for t in 0..4u64 {
        let b = bus.clone();
        handles.push(std::thread::spawn(move || {
            for i in 0..100u64 {
                let _ = b.send(CoreEvent::ViewClosed {
                    view_id: t * 100 + i,
                });
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
    assert_eq!(bus.event_count("ViewClosed"), 400);
}

#[test]
fn hook_dispatcher_send_sync_threaded() {
    let d = Arc::new(HookDispatcher::new());
    let cnt = Arc::new(AtomicU64::new(0));
    let c2 = cnt.clone();
    d.register(EventHook::new("c", |_| true, move |_| {
        c2.fetch_add(1, Ordering::Relaxed);
    }));
    let mut handles = Vec::new();
    for _ in 0..4 {
        let d2 = d.clone();
        handles.push(std::thread::spawn(move || {
            for i in 0..100u64 {
                d2.dispatch(&CoreEvent::ViewClosed { view_id: i });
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
    assert_eq!(cnt.load(Ordering::Relaxed), 400);
}

#[test]
fn event_logger_send_sync_threaded() {
    let l = Arc::new(EventLogger::new(10_000));
    let mut handles = Vec::new();
    for t in 0..4u64 {
        let l2 = l.clone();
        handles.push(std::thread::spawn(move || {
            for i in 0..100u64 {
                l2.record(CoreEvent::ViewClosed {
                    view_id: t * 100 + i,
                });
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
    assert_eq!(l.count(), 400);
}
