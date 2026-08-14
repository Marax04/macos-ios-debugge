//! Blitz integration tests for rustre-events public API.
//!
//! Exercises `CoreEvent`, `SpecCoreEvent`, `ExtEvent`, `EventBus`, `SpecEventBus`,
//! `EventFilter`, `SpecEventFilter`, `EventLogger`, `EventReplay`, `EventCorrelator`,
//! `EventStats`, `EventHook`, `HookDispatcher`, `FilteredSubscription`, `global_bus`.

use rustre_events::{
    CoreEvent, EventBus, EventCorrelator, EventFilter, EventHook, EventKind, EventLogger,
    EventReplay, EventStats, FilteredSubscription, HookDispatcher, SpecCoreEvent, SpecEventBus,
    SpecEventFilter, global_bus, kind_subscription, publish, subscribe_global, view_subscription,
};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime};

// ===========================================================================
// CoreEvent — variant_name / view_id / kind exhaustive coverage
// ===========================================================================

#[test]
fn ce_view_saved_view_id_and_name() {
    let e = CoreEvent::ViewSaved {
        view_id: 11,
        path: "/p".into(),
    };
    assert_eq!(e.view_id(), Some(11));
    assert_eq!(e.variant_name(), "ViewSaved");
    assert_eq!(e.kind(), EventKind::View);
}

#[test]
fn ce_analysis_failed_basic() {
    let e = CoreEvent::AnalysisFailed {
        view_id: 1,
        pass: "cfg".into(),
        error: "oom".into(),
    };
    assert_eq!(e.view_id(), Some(1));
    assert_eq!(e.kind(), EventKind::Analysis);
    assert!(e.is_analysis_event());
}

#[test]
fn ce_function_tagged_is_function_event() {
    let e = CoreEvent::FunctionTagged {
        view_id: 1,
        address: 0,
        tag: "vuln".into(),
    };
    assert!(e.is_function_event());
    assert_eq!(e.kind(), EventKind::Function);
}

#[test]
fn ce_symbol_imported_kind_is_symbol() {
    let e = CoreEvent::SymbolImported {
        view_id: 1,
        count: 100,
        source: "pdb".into(),
    };
    assert_eq!(e.kind(), EventKind::Symbol);
    assert_eq!(e.view_id(), Some(1));
}

#[test]
fn ce_debugger_detached_view_id_extract() {
    let e = CoreEvent::DebuggerDetached { view_id: 9 };
    assert_eq!(e.view_id(), Some(9));
    assert!(e.is_debug_event());
}

#[test]
fn ce_register_changed_is_debug() {
    let e = CoreEvent::RegisterChanged {
        view_id: 1,
        thread_id: 0,
        register: "rax".into(),
        value: 0xdead_beef,
    };
    assert!(e.is_debug_event());
    assert_eq!(e.kind(), EventKind::Debugger);
}

#[test]
fn ce_memory_variants_kind() {
    let a = CoreEvent::MemoryRead {
        view_id: 1,
        address: 0,
        length: 4,
    };
    let b = CoreEvent::MemoryWritten {
        view_id: 1,
        address: 0,
        length: 4,
    };
    let c = CoreEvent::MemoryPatched {
        view_id: 1,
        address: 0,
        length: 4,
    };
    let d = CoreEvent::MemoryMapped {
        view_id: 1,
        address: 0,
        length: 4096,
        name: "rx".into(),
    };
    for e in [a, b, c, d] {
        assert_eq!(e.kind(), EventKind::Memory);
        assert_eq!(e.view_id(), Some(1));
    }
}

#[test]
fn ce_type_variants_kind() {
    for e in [
        CoreEvent::TypeDefined {
            view_id: 1,
            name: "T".into(),
        },
        CoreEvent::TypeUpdated {
            view_id: 1,
            name: "T".into(),
        },
        CoreEvent::TypeDeleted {
            view_id: 1,
            name: "T".into(),
        },
        CoreEvent::TypeImported {
            view_id: 1,
            count: 10,
            source: "dwarf".into(),
        },
    ] {
        assert_eq!(e.kind(), EventKind::Type);
    }
}

#[test]
fn ce_annotation_variants_kind() {
    for e in [
        CoreEvent::CommentAdded {
            view_id: 1,
            address: 0,
            text: "x".into(),
        },
        CoreEvent::CommentRemoved {
            view_id: 1,
            address: 0,
        },
        CoreEvent::BookmarkAdded {
            view_id: 1,
            address: 0,
            label: Some("a".into()),
        },
        CoreEvent::BookmarkRemoved {
            view_id: 1,
            address: 0,
        },
    ] {
        assert_eq!(e.kind(), EventKind::Annotation);
    }
}

#[test]
fn ce_bookmark_added_optional_label_none() {
    let e = CoreEvent::BookmarkAdded {
        view_id: 1,
        address: 0,
        label: None,
    };
    let s = e.to_json().unwrap();
    let back = CoreEvent::from_json(&s).unwrap();
    if let CoreEvent::BookmarkAdded { label, .. } = back {
        assert!(label.is_none());
    } else {
        panic!("variant lost in roundtrip");
    }
}

#[test]
fn ce_agent_variants_kind() {
    for e in [
        CoreEvent::AgentAction {
            view_id: 1,
            action: "a".into(),
            result: "r".into(),
        },
        CoreEvent::AgentError {
            view_id: 1,
            action: "a".into(),
            error: "e".into(),
        },
        CoreEvent::AgentStarted {
            view_id: 1,
            agent_name: "g".into(),
        },
        CoreEvent::AgentStopped {
            view_id: 1,
            agent_name: "g".into(),
        },
    ] {
        assert_eq!(e.kind(), EventKind::Agent);
    }
}

#[test]
fn ce_xref_removed_kind() {
    let e = CoreEvent::XrefRemoved {
        view_id: 1,
        from_addr: 0x100,
        to_addr: 0x200,
    };
    assert_eq!(e.kind(), EventKind::CrossRef);
}

#[test]
fn ce_script_executed_kind() {
    let e = CoreEvent::ScriptExecuted {
        view_id: 1,
        engine: "py".into(),
        success: true,
    };
    assert_eq!(e.kind(), EventKind::Script);
}

#[test]
fn ce_plugin_variants_kind() {
    for e in [
        CoreEvent::PluginLoaded {
            plugin_id: "x".into(),
        },
        CoreEvent::PluginUnloaded {
            plugin_id: "x".into(),
        },
        CoreEvent::PluginError {
            plugin_id: "x".into(),
            error: "e".into(),
        },
    ] {
        assert_eq!(e.kind(), EventKind::Plugin);
        assert_eq!(e.view_id(), None);
    }
}

#[test]
fn ce_triage_completed_kind_is_custom() {
    // Per source, TriageCompleted maps to EventKind::Custom.
    let e = CoreEvent::TriageCompleted {
        view_id: 1,
        verdict: "clean".into(),
    };
    assert_eq!(e.kind(), EventKind::Custom);
    assert_eq!(e.view_id(), Some(1));
}

#[test]
fn ce_display_without_view_id() {
    let e = CoreEvent::PluginLoaded {
        plugin_id: "id".into(),
    };
    let s = format!("{e}");
    assert_eq!(s, "PluginLoaded");
}

#[test]
fn ce_display_with_view_id() {
    let e = CoreEvent::ViewClosed { view_id: 7 };
    let s = format!("{e}");
    assert!(s.contains("view=7"));
    assert!(s.contains("ViewClosed"));
}

// ===========================================================================
// CoreEvent JSON round-trip — multiple variants
// ===========================================================================

#[test]
fn ce_json_roundtrip_function_renamed() {
    let e = CoreEvent::FunctionRenamed {
        view_id: 9,
        address: 0xCAFE,
        old_name: "sub_CAFE".into(),
        new_name: "do_thing".into(),
    };
    let s = e.to_json().unwrap();
    let back = CoreEvent::from_json(&s).unwrap();
    match back {
        CoreEvent::FunctionRenamed {
            view_id,
            address,
            old_name,
            new_name,
        } => {
            assert_eq!(view_id, 9);
            assert_eq!(address, 0xCAFE);
            assert_eq!(old_name, "sub_CAFE");
            assert_eq!(new_name, "do_thing");
        }
        _ => panic!("roundtrip changed variant"),
    }
}

#[test]
fn ce_from_json_rejects_garbage() {
    let r = CoreEvent::from_json("{not json");
    assert!(r.is_err());
}

#[test]
fn ce_from_json_rejects_unknown_variant() {
    let r = CoreEvent::from_json(r#"{"NotARealVariant":{}}"#);
    assert!(r.is_err());
}

#[test]
fn ce_from_json_empty_string_err() {
    assert!(CoreEvent::from_json("").is_err());
}

// ===========================================================================
// EventFilter combinators
// ===========================================================================

#[test]
fn ef_and_short_circuits_to_false_on_mismatch() {
    let f = EventFilter::for_view(1).and(EventFilter::of_kind(EventKind::Plugin));
    // Plugin events have no view_id; so for_view(1) is false.
    let e = CoreEvent::PluginLoaded {
        plugin_id: "p".into(),
    };
    assert!(!f.matches(&e));
}

#[test]
fn ef_or_true_when_either_matches() {
    let f = EventFilter::for_view(1).or(EventFilter::of_kind(EventKind::Plugin));
    assert!(f.matches(&CoreEvent::PluginLoaded {
        plugin_id: "p".into()
    }));
    assert!(f.matches(&CoreEvent::ViewClosed { view_id: 1 }));
    assert!(!f.matches(&CoreEvent::ViewClosed { view_id: 2 }));
}

#[test]
fn ef_double_not_is_identity() {
    let f = EventFilter::for_view(5).negate().negate();
    assert!(f.matches(&CoreEvent::ViewClosed { view_id: 5 }));
    assert!(!f.matches(&CoreEvent::ViewClosed { view_id: 6 }));
}

#[test]
fn ef_new_custom_predicate() {
    let f = EventFilter::new(|e| e.variant_name().starts_with("Function"));
    assert!(f.matches(&CoreEvent::FunctionDefined {
        view_id: 1,
        address: 0,
        name: "f".into()
    }));
    assert!(!f.matches(&CoreEvent::ViewClosed { view_id: 1 }));
}

// ===========================================================================
// EventBus
// ===========================================================================

#[tokio::test]
async fn bus_counters_track_per_variant() {
    let bus = EventBus::new_default();
    let _rx = bus.subscribe();
    bus.send_view_closed(1);
    bus.send_view_closed(2);
    bus.send_function_defined(1, 0, "f".into());
    assert_eq!(bus.event_count("ViewClosed"), 2);
    assert_eq!(bus.event_count("FunctionDefined"), 1);
    assert_eq!(bus.event_count("NoSuchVariant"), 0);
    assert_eq!(bus.total_sent(), 3);
}

#[tokio::test]
async fn bus_send_without_subscribers_is_error_but_still_counted() {
    let bus = EventBus::new(8);
    let r = bus.send(CoreEvent::ViewClosed { view_id: 1 });
    assert!(r.is_err());
    // Counter is incremented before send, so it should still show 1.
    assert_eq!(bus.event_count("ViewClosed"), 1);
}

#[tokio::test]
async fn bus_receiver_count_tracks_drops() {
    let bus = EventBus::new(8);
    assert_eq!(bus.receiver_count(), 0);
    let rx1 = bus.subscribe();
    let rx2 = bus.subscribe();
    assert_eq!(bus.receiver_count(), 2);
    drop(rx1);
    assert_eq!(bus.receiver_count(), 1);
    drop(rx2);
    assert_eq!(bus.receiver_count(), 0);
}

#[tokio::test]
async fn bus_all_convenience_senders_emit_correct_variants() {
    let bus = EventBus::new(64);
    let mut rx = bus.subscribe();
    bus.send_view_opened(1, "u".into(), "x86".into());
    bus.send_view_closed(1);
    bus.send_function_defined(1, 0, "f".into());
    bus.send_function_renamed(1, 0, "a".into(), "b".into());
    bus.send_breakpoint_hit(1, 0, 0);
    bus.send_analysis_progress(1, "p".into(), 1);
    bus.send_analysis_completed(1, "p".into());
    bus.send_analysis_failed(1, "p".into(), "e".into());
    bus.send_symbol_defined(1, 0, "s".into(), "k".into(), "src".into());
    bus.send_plugin_loaded("pid".into());
    bus.send_custom("type".into(), serde_json::json!({"k":1}));
    bus.send_agent_action(1, "a".into(), "r".into());
    bus.send_xref_added(1, 0, 1, "call".into());
    bus.send_patch_applied(1, 0, 4);
    bus.send_script_executed(1, "py".into(), true);

    let expected = [
        "ViewOpened",
        "ViewClosed",
        "FunctionDefined",
        "FunctionRenamed",
        "BreakpointHit",
        "AnalysisProgress",
        "AnalysisCompleted",
        "AnalysisFailed",
        "SymbolDefined",
        "PluginLoaded",
        "Custom",
        "AgentAction",
        "XrefAdded",
        "PatchApplied",
        "ScriptExecuted",
    ];
    for want in expected {
        let e = rx.recv().await.unwrap();
        assert_eq!(e.variant_name(), want);
    }
}

#[tokio::test]
async fn bus_debug_shows_struct_name() {
    let bus = EventBus::new(4);
    let s = format!("{bus:?}");
    assert!(s.contains("EventBus"));
    assert!(s.contains("receivers"));
}

// ===========================================================================
// FilteredSubscription
// ===========================================================================

#[tokio::test]
async fn fs_received_and_delivered_counts() {
    let bus = EventBus::new(64);
    let mut sub = FilteredSubscription::new(bus.subscribe(), |e| {
        matches!(e, CoreEvent::ViewClosed { .. })
    });
    bus.send_view_opened(1, "u".into(), "a".into()); // filtered out
    bus.send_view_closed(1); // delivered
    bus.send_view_closed(2); // delivered
    sub.recv_filtered().await.unwrap();
    sub.recv_filtered().await.unwrap();
    assert_eq!(sub.delivered_count(), 2);
    assert!(sub.received_count() >= 3);
}

#[tokio::test]
async fn fs_recv_raw_bypasses_filter() {
    let bus = EventBus::new(16);
    let mut sub = FilteredSubscription::new(bus.subscribe(), |_| false);
    bus.send_view_closed(1);
    let raw = sub.recv_raw().await.unwrap();
    assert_eq!(raw.variant_name(), "ViewClosed");
}

#[tokio::test]
async fn fs_with_filter_via_event_filter() {
    let bus = EventBus::new(16);
    let mut sub = FilteredSubscription::with_filter(
        bus.subscribe(),
        EventFilter::of_kind(EventKind::View),
    );
    bus.send_plugin_loaded("p".into());
    bus.send_view_closed(1);
    let e = sub.recv_filtered().await.unwrap();
    assert_eq!(e.variant_name(), "ViewClosed");
}

#[tokio::test]
async fn fs_returns_none_on_channel_close() {
    let bus = EventBus::new(8);
    let mut sub = FilteredSubscription::new(bus.subscribe(), |_| true);
    drop(bus);
    assert!(sub.recv_filtered().await.is_none());
}

#[tokio::test]
async fn view_subscription_factory_filters_by_view() {
    let bus = EventBus::new(16);
    let mut sub = view_subscription(&bus, 7);
    bus.send_view_closed(1);
    bus.send_view_closed(7);
    let e = sub.recv_filtered().await.unwrap();
    assert_eq!(e.view_id(), Some(7));
}

#[tokio::test]
async fn kind_subscription_factory_filters_by_kind() {
    let bus = EventBus::new(16);
    let mut sub = kind_subscription(&bus, EventKind::Function);
    bus.send_view_closed(1);
    bus.send_function_defined(1, 0, "f".into());
    let e = sub.recv_filtered().await.unwrap();
    assert_eq!(e.kind(), EventKind::Function);
}

// ===========================================================================
// EventLogger
// ===========================================================================

#[test]
fn logger_recent_zero_returns_empty() {
    let l = EventLogger::new(10);
    l.record(CoreEvent::ViewClosed { view_id: 1 });
    let r = l.recent_events(0);
    assert_eq!(r.len(), 0);
}

#[test]
fn logger_recent_more_than_stored_returns_all() {
    let l = EventLogger::new(10);
    l.record(CoreEvent::ViewClosed { view_id: 1 });
    l.record(CoreEvent::ViewClosed { view_id: 2 });
    let r = l.recent_events(100);
    assert_eq!(r.len(), 2);
}

#[test]
fn logger_max_size_zero_drops_everything() {
    let l = EventLogger::new(0);
    l.record(CoreEvent::ViewClosed { view_id: 1 });
    // With max_size=0, len() >= 0 is always true so pop_front is called on empty,
    // then push_back happens — implementation pops first (no-op on empty), then pushes.
    // Source: `if guard.len() >= self.max_size { guard.pop_front(); }`. With max=0,
    // len()>=0 -> pop empty (no-op), then push. So count becomes 1, NOT 0.
    // This is a real surprising behaviour, but we encode the documented intent:
    // "retains at most max_size events" — max_size=0 should mean zero events kept.
    // If this fails, it's a bug.
    assert_eq!(l.count(), 0, "EventLogger with max_size=0 should retain zero events");
}

#[test]
fn logger_events_since_far_future_is_empty() {
    let l = EventLogger::new(10);
    l.record(CoreEvent::ViewClosed { view_id: 1 });
    let future = SystemTime::now() + Duration::from_secs(3600);
    let r = l.events_since(future);
    assert!(r.is_empty());
}

#[test]
fn logger_events_since_epoch_returns_all() {
    let l = EventLogger::new(10);
    l.record(CoreEvent::ViewClosed { view_id: 1 });
    l.record(CoreEvent::ViewClosed { view_id: 2 });
    let r = l.events_since(SystemTime::UNIX_EPOCH);
    assert_eq!(r.len(), 2);
}

#[test]
fn logger_events_for_view_no_match_is_empty() {
    let l = EventLogger::new(10);
    l.record(CoreEvent::ViewClosed { view_id: 1 });
    let r = l.events_for_view(999);
    assert!(r.is_empty());
}

#[test]
fn logger_events_by_kind_with_no_matches() {
    let l = EventLogger::new(10);
    l.record(CoreEvent::ViewClosed { view_id: 1 });
    let r = l.events_by_kind(EventKind::Memory);
    assert!(r.is_empty());
}

// ===========================================================================
// HookDispatcher
// ===========================================================================

#[test]
fn hook_matches_method() {
    let h = EventHook::new(
        "lbl",
        |e| matches!(e, CoreEvent::ViewClosed { .. }),
        |_| {},
    );
    assert!(h.matches(&CoreEvent::ViewClosed { view_id: 1 }));
    assert!(!h.matches(&CoreEvent::PluginLoaded {
        plugin_id: "x".into()
    }));
    assert_eq!(h.label(), "lbl");
}

#[test]
fn hook_debug_format() {
    let h = EventHook::new("my", |_| true, |_| {});
    let s = format!("{h:?}");
    assert!(s.contains("EventHook"));
    assert!(s.contains("my"));
}

#[test]
fn dispatcher_default_is_empty() {
    let d = HookDispatcher::default();
    assert_eq!(d.hook_count(), 0);
}

#[test]
fn dispatcher_remove_nonexistent_is_noop() {
    let d = HookDispatcher::new();
    d.register(EventHook::new("a", |_| true, |_| {}));
    d.remove("does-not-exist");
    assert_eq!(d.hook_count(), 1);
}

#[test]
fn dispatcher_fires_multiple_hooks_per_event() {
    let counter = Arc::new(AtomicU64::new(0));
    let d = HookDispatcher::new();
    for _ in 0..3 {
        let c = counter.clone();
        d.register(EventHook::new(
            "x",
            |_| true,
            move |_| {
                c.fetch_add(1, Ordering::Relaxed);
            },
        ));
    }
    d.dispatch(&CoreEvent::ViewClosed { view_id: 1 });
    assert_eq!(counter.load(Ordering::Relaxed), 3);
}

// ===========================================================================
// EventReplay
// ===========================================================================

#[test]
fn replay_len_and_is_empty() {
    let mut r = EventReplay::new();
    assert!(r.is_empty());
    assert_eq!(r.len(), 0);
    r.push(CoreEvent::ViewClosed { view_id: 1 });
    assert_eq!(r.len(), 1);
    assert!(!r.is_empty());
}

#[test]
fn replay_all_no_subscribers_counts_all_as_failures() {
    let bus = EventBus::new(8);
    let mut r = EventReplay::new();
    r.push(CoreEvent::ViewClosed { view_id: 1 });
    r.push(CoreEvent::ViewClosed { view_id: 2 });
    let fails = r.replay_all(&bus);
    assert_eq!(fails, 2);
}

#[test]
fn replay_filtered_with_predicate_false_sends_zero() {
    let bus = EventBus::new(8);
    let _rx = bus.subscribe();
    let mut r = EventReplay::new();
    r.push(CoreEvent::ViewClosed { view_id: 1 });
    r.push(CoreEvent::ViewClosed { view_id: 2 });
    let n = r.replay_filtered(&bus, |_| false);
    assert_eq!(n, 0);
}

// ===========================================================================
// EventCorrelator
// ===========================================================================

#[test]
fn correlator_custom_keys() {
    let c = EventCorrelator::new(|e| Some(format!("k_{}", e.variant_name())));
    c.ingest(CoreEvent::ViewClosed { view_id: 1 });
    c.ingest(CoreEvent::ViewClosed { view_id: 2 });
    assert_eq!(c.get_group("k_ViewClosed").len(), 2);
    let keys = c.keys();
    assert!(keys.contains(&"k_ViewClosed".to_string()));
}

#[test]
fn correlator_get_group_missing_returns_empty() {
    let c = EventCorrelator::by_view();
    assert_eq!(c.get_group("nope").len(), 0);
}

#[test]
fn correlator_debug() {
    let c = EventCorrelator::by_view();
    let s = format!("{c:?}");
    assert!(s.contains("EventCorrelator"));
}

// ===========================================================================
// EventStats
// ===========================================================================

#[test]
fn stats_unknown_variant_count_is_zero() {
    let s = EventStats::new();
    assert_eq!(s.variant_count("NoSuchThing"), 0);
    assert_eq!(s.kind_count(EventKind::Memory), 0);
}

#[test]
fn stats_records_separately_per_kind() {
    let s = EventStats::new();
    s.record(&CoreEvent::ViewClosed { view_id: 1 });
    s.record(&CoreEvent::PluginLoaded {
        plugin_id: "x".into(),
    });
    assert_eq!(s.kind_count(EventKind::View), 1);
    assert_eq!(s.kind_count(EventKind::Plugin), 1);
    assert_eq!(s.total(), 2);
}

// ===========================================================================
// SpecCoreEvent / SpecEventBus / SpecEventFilter
// ===========================================================================

#[test]
fn spec_filter_default_passes_global_false() {
    let f = SpecEventFilter::default();
    assert!(!f.pass_global_events);
    assert!(f.view_ids.is_none());
    assert!(f.event_types.is_none());
}

#[test]
fn spec_filter_view_ids_default_rejects_global_events() {
    // Per docs of SpecEventFilter: when view_ids is Some, events with no
    // view_id are REJECTED by default unless pass_global_events=true.
    let f = SpecEventFilter::new().with_view_ids([1u64]);
    let global = SpecCoreEvent::DebuggerAttached { pid: 1 };
    assert!(
        !f.matches(&global),
        "default view_ids filter should reject view-less events"
    );
}

#[test]
fn spec_filter_pass_global_events_opt_in() {
    let f = SpecEventFilter::new()
        .with_view_ids([1u64])
        .with_pass_global_events(true);
    assert!(f.matches(&SpecCoreEvent::DebuggerAttached { pid: 1 }));
    assert!(f.matches(&SpecCoreEvent::ViewClosed { view_id: 1 }));
    assert!(!f.matches(&SpecCoreEvent::ViewClosed { view_id: 2 }));
}

#[test]
fn spec_filter_empty_view_ids_rejects_all_view_events() {
    let f = SpecEventFilter::new().with_view_ids(std::iter::empty::<u64>());
    assert!(!f.matches(&SpecCoreEvent::ViewClosed { view_id: 1 }));
}

#[test]
fn spec_filter_empty_event_types_rejects_all() {
    let f = SpecEventFilter::new().with_event_types(std::iter::empty::<String>());
    assert!(!f.matches(&SpecCoreEvent::ViewClosed { view_id: 1 }));
}

#[test]
fn spec_event_json_roundtrip_patch_applied_bytes_preserved() {
    let e = SpecCoreEvent::PatchApplied {
        view_id: 1,
        addr: 0x10,
        old_bytes: vec![1, 2, 3, 0xff],
        new_bytes: vec![0xaa, 0xbb],
    };
    let s = serde_json::to_string(&e).unwrap();
    let back: SpecCoreEvent = serde_json::from_str(&s).unwrap();
    if let SpecCoreEvent::PatchApplied {
        old_bytes,
        new_bytes,
        ..
    } = back
    {
        assert_eq!(old_bytes, vec![1, 2, 3, 0xff]);
        assert_eq!(new_bytes, vec![0xaa, 0xbb]);
    } else {
        panic!("variant lost");
    }
}

#[test]
fn spec_event_display_no_view_id() {
    let e = SpecCoreEvent::ScriptOutput {
        source: "s".into(),
        message: "m".into(),
    };
    assert_eq!(format!("{e}"), "ScriptOutput");
}

#[tokio::test]
async fn spec_bus_default_constructible() {
    let bus = SpecEventBus::default();
    let mut rx = bus.subscribe();
    bus.publish(SpecCoreEvent::ViewClosed { view_id: 1 });
    assert!(rx.recv().await.is_ok());
}

#[test]
fn spec_bus_debug_has_fields() {
    let bus = SpecEventBus::new(16);
    let s = format!("{bus:?}");
    assert!(s.contains("SpecEventBus"));
    assert!(s.contains("history_len"));
}

#[tokio::test]
async fn spec_bus_recent_events_includes_event_published_with_no_subscribers() {
    let bus = SpecEventBus::new(8);
    // No subscriber.
    bus.publish(SpecCoreEvent::ViewClosed { view_id: 42 });
    let recent = bus.recent_events(10);
    assert_eq!(recent.len(), 1);
    assert_eq!(recent[0].view_id(), Some(42));
}

#[test]
fn spec_bus_recent_zero_returns_empty() {
    let bus = SpecEventBus::new(8);
    bus.publish(SpecCoreEvent::ViewClosed { view_id: 1 });
    assert_eq!(bus.recent_events(0).len(), 0);
}

// ===========================================================================
// global_bus
// ===========================================================================

#[tokio::test]
async fn global_bus_publish_delivers_to_subscriber() {
    let mut rx = subscribe_global();
    publish(SpecCoreEvent::ViewClosed { view_id: 12345 });
    // Drain until we find our marker; other tests may publish.
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    loop {
        assert!(
            std::time::Instant::now() <= deadline,
            "global_bus did not deliver our event"
        );
        if let Ok(Ok(SpecCoreEvent::ViewClosed { view_id: 12345 })) =
            tokio::time::timeout(Duration::from_millis(200), rx.recv()).await
        {
            return;
        }
    }
}

#[test]
fn global_bus_singleton_pointer_identity() {
    let p1 = global_bus() as *const _;
    let p2 = global_bus() as *const _;
    assert_eq!(p1, p2);
}

// ===========================================================================
// Send/Sync invariants
// ===========================================================================

#[test]
fn types_are_send_and_sync() {
    fn assert_ss<T: Send + Sync>() {}
    assert_ss::<CoreEvent>();
    assert_ss::<SpecCoreEvent>();
    assert_ss::<EventBus>();
    assert_ss::<SpecEventBus>();
    assert_ss::<EventLogger>();
    assert_ss::<EventStats>();
    assert_ss::<EventCorrelator>();
    assert_ss::<HookDispatcher>();
    assert_ss::<EventFilter>();
    assert_ss::<SpecEventFilter>();
}
