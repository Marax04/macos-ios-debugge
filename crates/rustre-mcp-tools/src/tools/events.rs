//! MCP wrappers for the rustre-events crate.
//! Extracted from `wire_tools.rs` by `workflow_split_wire_tools`.

use rustre_mcp_server::{McpError, ToolDefinition, ToolHandler, ToolResult};
use serde_json::{json, Value};
use async_trait::async_trait;

pub struct EventsBusNewDefaultTool;

pub struct EventsLoggerNewTool;

pub struct EventsStatsRecordTool;
impl EventsStatsRecordTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "events_stats_record".to_string(),
            description: "Construct rustre_events::EventStats, record a Custom event, return totals.".to_string(),
            input_schema: json!({"type":"object","properties":{}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for EventsStatsRecordTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let s = rustre_events::EventStats::new();
        let ev = rustre_events::CoreEvent::Custom { event_type: "probe".to_string(), payload: json!({}) };
        s.record(&ev);
        Ok(ToolResult::text(json!({
            "total": s.total(),
            "variant_count_Custom": s.variant_count("Custom"),
            "source": "rustre_events::EventStats::record",
        }).to_string()))
    }
}

pub struct EventsReplayPushTool;
impl EventsReplayPushTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "events_replay_push".to_string(),
            description: "Construct rustre_events::EventReplay, push one Custom event, return len/is_empty.".to_string(),
            input_schema: json!({"type":"object","properties":{}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for EventsReplayPushTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let mut r = rustre_events::EventReplay::new();
        r.push(rustre_events::CoreEvent::Custom { event_type: "probe".to_string(), payload: json!({}) });
        Ok(ToolResult::text(json!({
            "len": r.len(),
            "is_empty": r.is_empty(),
            "source": "rustre_events::EventReplay::push",
        }).to_string()))
    }
}

pub struct EventsHookDispatcherNewTool;
impl EventsHookDispatcherNewTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "events_hook_dispatcher_new".to_string(),
            description: "Construct a rustre_events::HookDispatcher and report its initial hook_count (0).".to_string(),
            input_schema: json!({"type":"object","properties":{}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for EventsHookDispatcherNewTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let d = rustre_events::HookDispatcher::new();
        Ok(ToolResult::text(json!({
            "hook_count": d.hook_count(),
            "source": "rustre_events::HookDispatcher::new",
        }).to_string()))
    }
}

pub struct EventsBusPublishCustomTool;

pub struct EventsClassifyVariantTool;

pub struct EventsViewSubscriptionTool;

pub struct EventsKindSubscriptionTool;

pub struct EventsBusSendViewClosedTool;

pub struct EventsBusSendPluginLoadedTool;

pub struct EventsSpecCoreEventVariantNameTool;

pub struct EventsSpecCoreEventViewIdDebuggerTool;

pub struct EventsCoreEventVariantNameTool;
impl EventsCoreEventVariantNameTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "events_core_event_variant_name".to_string(),
            description: "Return the CoreEvent variant name for a ViewOpened probe event.".to_string(),
            input_schema: json!({ "type": "object", "properties": {} }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for EventsCoreEventVariantNameTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let e = rustre_events::CoreEvent::ViewOpened { view_id: 1, uri: "x".into(), arch: "x86_64".into() };
        Ok(ToolResult::text(json!({
            "variant_name": e.variant_name(),
            "view_id": e.view_id(),
            "kind": format!("{:?}", e.kind()),
            "source": "rustre_events::CoreEvent::variant_name",
        }).to_string()))
    }
}

pub struct EventsCoreEventIsDebugEventTool;
impl EventsCoreEventIsDebugEventTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "events_core_event_is_debug_event".to_string(),
            description: "Check if a BreakpointHit CoreEvent is classified as a debug event.".to_string(),
            input_schema: json!({ "type": "object", "properties": {} }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for EventsCoreEventIsDebugEventTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let e = rustre_events::CoreEvent::BreakpointHit { view_id: 1, address: 0x400000, thread_id: 1 };
        Ok(ToolResult::text(json!({
            "is_debug_event": e.is_debug_event(),
            "is_analysis_event": e.is_analysis_event(),
            "is_function_event": e.is_function_event(),
            "source": "rustre_events::CoreEvent::is_debug_event",
        }).to_string()))
    }
}

pub struct EventsCoreEventJsonRoundtripTool;
impl EventsCoreEventJsonRoundtripTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "events_core_event_json_roundtrip".to_string(),
            description: "Serialize a CoreEvent to JSON and deserialize back, returning ok flag.".to_string(),
            input_schema: json!({ "type": "object", "properties": {} }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for EventsCoreEventJsonRoundtripTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let e = rustre_events::CoreEvent::FunctionDefined { view_id: 1, address: 0x1000, name: "main".into() };
        let s = e.to_json().map_err(|e| McpError::InvalidParams(e.to_string()))?;
        let back = rustre_events::CoreEvent::from_json(&s).map_err(|e| McpError::InvalidParams(e.to_string()))?;
        Ok(ToolResult::text(json!({
            "json_len": s.len(),
            "roundtrip_variant": back.variant_name(),
            "source": "rustre_events::CoreEvent::to_json",
        }).to_string()))
    }
}

pub struct EventsFilterForViewTool;
impl EventsFilterForViewTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "events_filter_for_view".to_string(),
            description: "Build EventFilter::for_view and test against matching/non-matching events.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": { "view_id": { "type": "integer", "minimum": 0 } },
                "required": ["view_id"]
            }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for EventsFilterForViewTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let view_id = args.get("view_id").and_then(Value::as_u64)
            .ok_or_else(|| McpError::InvalidParams("missing 'view_id'".into()))?;
        let f = rustre_events::EventFilter::for_view(view_id);
        let matching = rustre_events::CoreEvent::ViewOpened { view_id, uri: "x".into(), arch: "x86_64".into() };
        let non_matching = rustre_events::CoreEvent::ViewOpened { view_id: view_id.wrapping_add(1), uri: "y".into(), arch: "x86_64".into() };
        Ok(ToolResult::text(json!({
            "matches_expected": f.matches(&matching),
            "matches_other": f.matches(&non_matching),
            "source": "rustre_events::EventFilter::for_view",
        }).to_string()))
    }
}

pub struct EventsBusSendCustomTool;
impl EventsBusSendCustomTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "events_bus_send_custom".to_string(),
            description: "Create an EventBus, subscribe once, send a Custom event, return counters.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": { "event_type": { "type": "string" } },
                "required": ["event_type"]
            }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for EventsBusSendCustomTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let event_type = args.get("event_type").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'event_type'".into()))?.to_string();
        let bus = rustre_events::EventBus::new_default();
        let _rx = bus.subscribe();
        bus.send_custom(event_type, json!({}));
        Ok(ToolResult::text(json!({
            "total_sent": bus.total_sent(),
            "custom_count": bus.event_count("Custom"),
            "receiver_count": bus.receiver_count(),
            "source": "rustre_events::EventBus::send_custom",
        }).to_string()))
    }
}

pub struct EventsLoggerRecordAndCountTool;
impl EventsLoggerRecordAndCountTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "events_logger_record_and_count".to_string(),
            description: "Record N Custom events on an EventLogger and return count + recent_events sample.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "max_size": { "type": "integer", "minimum": 1 },
                    "n": { "type": "integer", "minimum": 0 }
                },
                "required": ["max_size", "n"]
            }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for EventsLoggerRecordAndCountTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let max_size = args.get("max_size").and_then(Value::as_u64)
            .ok_or_else(|| McpError::InvalidParams("missing 'max_size'".into()))? as usize;
        let n = args.get("n").and_then(Value::as_u64)
            .ok_or_else(|| McpError::InvalidParams("missing 'n'".into()))? as usize;
        let logger = rustre_events::EventLogger::new(max_size);
        for i in 0..n {
            logger.record(rustre_events::CoreEvent::Custom { event_type: format!("e{i}"), payload: json!({}) });
        }
        let sample = logger.recent_events(3);
        Ok(ToolResult::text(json!({
            "count": logger.count(),
            "sample_len": sample.len(),
            "source": "rustre_events::EventLogger::record",
        }).to_string()))
    }
}

pub struct EventsCorrelatorByViewTool;
impl EventsCorrelatorByViewTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "events_correlator_by_view".to_string(),
            description: "Ingest events into an EventCorrelator::by_view and return group stats.".to_string(),
            input_schema: json!({ "type": "object", "properties": {} }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for EventsCorrelatorByViewTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let c = rustre_events::EventCorrelator::by_view();
        c.ingest(rustre_events::CoreEvent::ViewOpened { view_id: 1, uri: "a".into(), arch: "x86_64".into() });
        c.ingest(rustre_events::CoreEvent::ViewOpened { view_id: 2, uri: "b".into(), arch: "x86_64".into() });
        c.ingest(rustre_events::CoreEvent::ViewClosed { view_id: 1 });
        Ok(ToolResult::text(json!({
            "keys": c.keys(),
            "total_count": c.total_count(),
            "group_1_len": c.get_group("1").len(),
            "source": "rustre_events::EventCorrelator::by_view",
        }).to_string()))
    }
}

pub struct EventsHookDispatcherRegisterTool;
impl EventsHookDispatcherRegisterTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "events_hook_dispatcher_register".to_string(),
            description: "Register a hook in HookDispatcher, dispatch a matching event, return hook_count.".to_string(),
            input_schema: json!({ "type": "object", "properties": {} }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for EventsHookDispatcherRegisterTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let d = rustre_events::HookDispatcher::new();
        let hook = rustre_events::EventHook::new("test", |_e| true, |_e| {});
        d.register(hook);
        let ev = rustre_events::CoreEvent::Custom { event_type: "x".into(), payload: json!({}) };
        d.dispatch(&ev);
        let before = d.hook_count();
        d.remove("test");
        Ok(ToolResult::text(json!({
            "hook_count_before_remove": before,
            "hook_count_after_remove": d.hook_count(),
            "source": "rustre_events::HookDispatcher::register",
        }).to_string()))
    }
}

pub struct EventsReplayFilteredTool;
impl EventsReplayFilteredTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "events_replay_filtered".to_string(),
            description: "Build EventReplay with 3 events, replay only Custom variants onto a subscribed bus.".to_string(),
            input_schema: json!({ "type": "object", "properties": {} }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for EventsReplayFilteredTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let mut r = rustre_events::EventReplay::new();
        r.push(rustre_events::CoreEvent::Custom { event_type: "a".into(), payload: json!({}) });
        r.push(rustre_events::CoreEvent::ViewClosed { view_id: 1 });
        r.push(rustre_events::CoreEvent::Custom { event_type: "b".into(), payload: json!({}) });
        let bus = rustre_events::EventBus::new_default();
        let _rx = bus.subscribe();
        let replayed = r.replay_filtered(&bus, |e| matches!(e, rustre_events::CoreEvent::Custom { .. }));
        Ok(ToolResult::text(json!({
            "replayed": replayed,
            "len": r.len(),
            "total_sent_after": bus.total_sent(),
            "source": "rustre_events::EventReplay::replay_filtered",
        }).to_string()))
    }
}

pub struct EventsStatsRecordManyTool;
impl EventsStatsRecordManyTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "events_stats_record_many".to_string(),
            description: "Record several events into EventStats and return variant + kind counts.".to_string(),
            input_schema: json!({ "type": "object", "properties": {} }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for EventsStatsRecordManyTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let s = rustre_events::EventStats::new();
        s.record(&rustre_events::CoreEvent::Custom { event_type: "a".into(), payload: json!({}) });
        s.record(&rustre_events::CoreEvent::Custom { event_type: "b".into(), payload: json!({}) });
        s.record(&rustre_events::CoreEvent::ViewClosed { view_id: 1 });
        Ok(ToolResult::text(json!({
            "total": s.total(),
            "custom_count": s.variant_count("Custom"),
            "view_kind_count": s.kind_count(rustre_events::EventKind::View),
            "source": "rustre_events::EventStats::record",
        }).to_string()))
    }
}

pub struct EventsCoreEventKindMemoryTool;
impl EventsCoreEventKindMemoryTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "events_core_event_kind_memory".to_string(),
            description: "Return the EventKind for a MemoryRead CoreEvent (expect Memory).".to_string(),
            input_schema: json!({ "type": "object", "properties": {} }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for EventsCoreEventKindMemoryTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let e = rustre_events::CoreEvent::MemoryRead { view_id: 7, address: 0x1000, length: 32 };
        Ok(ToolResult::text(json!({
            "kind": format!("{:?}", e.kind()),
            "variant": e.variant_name(),
            "view_id": e.view_id(),
            "source": "rustre_events::CoreEvent::kind",
        }).to_string()))
    }
}

pub struct EventsCoreEventDisplayFormattingTool;
impl EventsCoreEventDisplayFormattingTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "events_core_event_display_formatting".to_string(),
            description: "Format a CoreEvent via Display and return the string.".to_string(),
            input_schema: json!({ "type": "object", "properties": {} }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for EventsCoreEventDisplayFormattingTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let e = rustre_events::CoreEvent::FunctionRenamed { view_id: 3, address: 0x400, old_name: "a".into(), new_name: "b".into() };
        let scoped = format!("{e}");
        let unscoped = format!("{}", rustre_events::CoreEvent::PluginLoaded { plugin_id: "p".into() });
        Ok(ToolResult::text(json!({
            "scoped": scoped,
            "unscoped": unscoped,
            "source": "rustre_events::CoreEvent::fmt",
        }).to_string()))
    }
}

pub struct EventsFilterOfKindMatchesTool;
impl EventsFilterOfKindMatchesTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "events_filter_of_kind_matches".to_string(),
            description: "EventFilter::of_kind(Debugger) tested against a BreakpointHit and a ViewOpened.".to_string(),
            input_schema: json!({ "type": "object", "properties": {} }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for EventsFilterOfKindMatchesTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let f = rustre_events::EventFilter::of_kind(rustre_events::EventKind::Debugger);
        let hit = rustre_events::CoreEvent::BreakpointHit { view_id: 1, address: 0x1, thread_id: 1 };
        let view = rustre_events::CoreEvent::ViewOpened { view_id: 1, uri: "x".into(), arch: "x86_64".into() };
        Ok(ToolResult::text(json!({
            "matches_bp": f.matches(&hit),
            "matches_view": f.matches(&view),
            "source": "rustre_events::EventFilter::of_kind",
        }).to_string()))
    }
}

pub struct EventsFilterCombinatorsTool;
impl EventsFilterCombinatorsTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "events_filter_combinators".to_string(),
            description: "Exercise EventFilter::and/or/negate combinators and return match booleans.".to_string(),
            input_schema: json!({ "type": "object", "properties": {} }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for EventsFilterCombinatorsTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let a = rustre_events::EventFilter::for_view(1);
        let b = rustre_events::EventFilter::by_variant("ViewOpened");
        let both = a.and(b);
        let e = rustre_events::CoreEvent::ViewOpened { view_id: 1, uri: "x".into(), arch: "x86_64".into() };
        let neg = rustre_events::EventFilter::for_view(2).negate();
        let or_f = rustre_events::EventFilter::for_view(9)
            .or(rustre_events::EventFilter::by_variant("ViewOpened"));
        Ok(ToolResult::text(json!({
            "and_match": both.matches(&e),
            "negate_match": neg.matches(&e),
            "or_match": or_f.matches(&e),
            "source": "rustre_events::EventFilter::{and,or,negate}",
        }).to_string()))
    }
}

pub struct EventsBusEventCountersTool;
impl EventsBusEventCountersTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "events_bus_event_counters".to_string(),
            description: "Send several typed events onto an EventBus and return per-variant counters.".to_string(),
            input_schema: json!({ "type": "object", "properties": {} }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for EventsBusEventCountersTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let bus = rustre_events::EventBus::new_default();
        let _rx = bus.subscribe();
        bus.send_view_opened(1, "u".into(), "x86_64".into());
        bus.send_function_defined(1, 0x400, "main".into());
        bus.send_function_renamed(1, 0x400, "main".into(), "start".into());
        bus.send_analysis_progress(1, "pass".into(), 50);
        bus.send_analysis_completed(1, "pass".into());
        Ok(ToolResult::text(json!({
            "total_sent": bus.total_sent(),
            "func_defined": bus.event_count("FunctionDefined"),
            "func_renamed": bus.event_count("FunctionRenamed"),
            "analysis_completed": bus.event_count("AnalysisCompleted"),
            "source": "rustre_events::EventBus::event_count",
        }).to_string()))
    }
}

pub struct EventsBusSendBreakpointHitTool;
impl EventsBusSendBreakpointHitTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "events_bus_send_breakpoint_hit".to_string(),
            description: "Send a BreakpointHit event on the EventBus and verify counter increments.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "view_id": { "type": "integer", "minimum": 0 },
                    "address": { "type": "integer", "minimum": 0 },
                    "thread_id": { "type": "integer", "minimum": 0 }
                },
                "required": ["view_id", "address", "thread_id"]
            }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for EventsBusSendBreakpointHitTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let view_id = args.get("view_id").and_then(Value::as_u64)
            .ok_or_else(|| McpError::InvalidParams("missing 'view_id'".into()))?;
        let address = args.get("address").and_then(Value::as_u64)
            .ok_or_else(|| McpError::InvalidParams("missing 'address'".into()))?;
        let thread_id = args.get("thread_id").and_then(Value::as_u64)
            .ok_or_else(|| McpError::InvalidParams("missing 'thread_id'".into()))? as u32;
        let bus = rustre_events::EventBus::new_default();
        let _rx = bus.subscribe();
        bus.send_breakpoint_hit(view_id, address, thread_id);
        Ok(ToolResult::text(json!({
            "total_sent": bus.total_sent(),
            "bp_hit_count": bus.event_count("BreakpointHit"),
            "source": "rustre_events::EventBus::send_breakpoint_hit",
        }).to_string()))
    }
}

pub struct EventsLoggerEventsByKindTool;
impl EventsLoggerEventsByKindTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "events_logger_events_by_kind".to_string(),
            description: "Record mixed events on EventLogger and return count filtered by kind.".to_string(),
            input_schema: json!({ "type": "object", "properties": {} }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for EventsLoggerEventsByKindTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let logger = rustre_events::EventLogger::new(16);
        logger.record(rustre_events::CoreEvent::ViewOpened { view_id: 1, uri: "x".into(), arch: "x86_64".into() });
        logger.record(rustre_events::CoreEvent::ViewClosed { view_id: 1 });
        logger.record(rustre_events::CoreEvent::Custom { event_type: "c".into(), payload: json!({}) });
        let by_view = logger.events_by_kind(rustre_events::EventKind::View);
        let for_view_1 = logger.events_for_view(1);
        Ok(ToolResult::text(json!({
            "total": logger.count(),
            "view_kind": by_view.len(),
            "view_1": for_view_1.len(),
            "source": "rustre_events::EventLogger::events_by_kind",
        }).to_string()))
    }
}

pub struct EventsReplaySnapshotFromTool;
impl EventsReplaySnapshotFromTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "events_replay_snapshot_from".to_string(),
            description: "Snapshot EventLogger contents into EventReplay and replay_all onto a bus.".to_string(),
            input_schema: json!({ "type": "object", "properties": {} }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for EventsReplaySnapshotFromTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let logger = rustre_events::EventLogger::new(8);
        for i in 0..3u64 {
            logger.record(rustre_events::CoreEvent::ViewOpened { view_id: i, uri: format!("u{i}"), arch: "x86_64".into() });
        }
        let mut r = rustre_events::EventReplay::new();
        r.snapshot_from(&logger);
        let bus = rustre_events::EventBus::new_default();
        let _rx = bus.subscribe();
        let failures = r.replay_all(&bus);
        Ok(ToolResult::text(json!({
            "len": r.len(),
            "is_empty": r.is_empty(),
            "failures": failures,
            "total_sent": bus.total_sent(),
            "source": "rustre_events::EventReplay::snapshot_from",
        }).to_string()))
    }
}

pub struct EventsCorrelatorByVariantTool;
impl EventsCorrelatorByVariantTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "events_correlator_by_variant".to_string(),
            description: "EventCorrelator::by_variant groups events by variant name; returns group sizes.".to_string(),
            input_schema: json!({ "type": "object", "properties": {} }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for EventsCorrelatorByVariantTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let c = rustre_events::EventCorrelator::by_variant();
        c.ingest(rustre_events::CoreEvent::ViewOpened { view_id: 1, uri: "a".into(), arch: "x86_64".into() });
        c.ingest(rustre_events::CoreEvent::ViewOpened { view_id: 2, uri: "b".into(), arch: "x86_64".into() });
        c.ingest(rustre_events::CoreEvent::ViewClosed { view_id: 1 });
        let mut keys = c.keys();
        keys.sort();
        Ok(ToolResult::text(json!({
            "keys": keys,
            "view_opened_len": c.get_group("ViewOpened").len(),
            "view_closed_len": c.get_group("ViewClosed").len(),
            "total_count": c.total_count(),
            "source": "rustre_events::EventCorrelator::by_variant",
        }).to_string()))
    }
}

pub struct EventsStatsAllVariantCountsTool;
impl EventsStatsAllVariantCountsTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "events_stats_all_variant_counts".to_string(),
            description: "Record events into EventStats and return all_variant_counts + reset behaviour.".to_string(),
            input_schema: json!({ "type": "object", "properties": {} }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for EventsStatsAllVariantCountsTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let s = rustre_events::EventStats::new();
        s.record(&rustre_events::CoreEvent::ViewOpened { view_id: 1, uri: "u".into(), arch: "x86_64".into() });
        s.record(&rustre_events::CoreEvent::ViewClosed { view_id: 1 });
        s.record(&rustre_events::CoreEvent::ViewClosed { view_id: 2 });
        let counts_before = s.all_variant_counts();
        let total_before = s.total();
        s.reset();
        Ok(ToolResult::text(json!({
            "counts_before": counts_before,
            "total_before": total_before,
            "total_after_reset": s.total(),
            "source": "rustre_events::EventStats::all_variant_counts",
        }).to_string()))
    }
}

pub struct EventsFilteredSubscriptionCountersTool;
impl EventsFilteredSubscriptionCountersTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "events_filtered_subscription_counters".to_string(),
            description: "Create a FilteredSubscription and inspect its initial received/delivered counters.".to_string(),
            input_schema: json!({ "type": "object", "properties": {} }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for EventsFilteredSubscriptionCountersTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let bus = rustre_events::EventBus::new_default();
        let sub = rustre_events::FilteredSubscription::new(bus.subscribe(), |_e| true);
        let sub2 = rustre_events::FilteredSubscription::with_filter(bus.subscribe(), rustre_events::EventFilter::for_view(1));
        Ok(ToolResult::text(json!({
            "received": sub.received_count(),
            "delivered": sub.delivered_count(),
            "with_filter_received": sub2.received_count(),
            "source": "rustre_events::FilteredSubscription::new",
        }).to_string()))
    }
}

pub struct EventsBusNewWithCapacityTool;
impl EventsBusNewWithCapacityTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "events_bus_new_with_capacity".to_string(),
            description: "Construct rustre_events::EventBus::new(capacity) and report receiver_count.".to_string(),
            input_schema: json!({"type":"object","properties":{"capacity":{"type":"integer","minimum":1}},"required":["capacity"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for EventsBusNewWithCapacityTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        // Clamp to schema minimum (1) so a client sending capacity: 0 doesn't crash the underlying EventBus::new.
        let cap = args.get("capacity").and_then(Value::as_u64).unwrap_or(16).max(1) as usize;
        let bus = rustre_events::EventBus::new(cap);
        Ok(ToolResult::text(json!({"capacity":cap,"receiver_count":bus.receiver_count(),"total_sent":bus.total_sent(),"source":"rustre_events::EventBus::new"}).to_string()))
    }
}

pub struct EventsBusEventCountTool;
impl EventsBusEventCountTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "events_bus_event_count".to_string(),
            description: "Publish a ViewClosed then query event_count for that variant.".to_string(),
            input_schema: json!({"type":"object","properties":{"view_id":{"type":"integer"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for EventsBusEventCountTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let vid = args.get("view_id").and_then(Value::as_u64).unwrap_or(1);
        let bus = rustre_events::EventBus::new_default();
        let _rx = bus.subscribe();
        bus.send_view_closed(vid);
        Ok(ToolResult::text(json!({"view_closed_count":bus.event_count("ViewClosed"),"total_sent":bus.total_sent(),"source":"rustre_events::EventBus::event_count"}).to_string()))
    }
}

pub struct EventsFilterByVariantTool;
impl EventsFilterByVariantTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "events_filter_by_variant".to_string(),
            description: "Test EventFilter::by_variant matching against a ViewClosed event.".to_string(),
            input_schema: json!({"type":"object","properties":{"variant":{"type":"string"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for EventsFilterByVariantTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let variant = args.get("variant").and_then(Value::as_str).unwrap_or("ViewClosed");
        let filter = if variant == "ViewOpened" {
            rustre_events::EventFilter::by_variant("ViewOpened")
        } else {
            rustre_events::EventFilter::by_variant("ViewClosed")
        };
        let ev = rustre_events::CoreEvent::ViewClosed { view_id: 7 };
        Ok(ToolResult::text(json!({"variant":variant,"matches":filter.matches(&ev),"source":"rustre_events::EventFilter::by_variant"}).to_string()))
    }
}

pub struct EventsFilterNegateTool;
impl EventsFilterNegateTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "events_filter_negate".to_string(),
            description: "Negate an EventFilter::for_view and verify it excludes the matching view.".to_string(),
            input_schema: json!({"type":"object","properties":{"view_id":{"type":"integer"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for EventsFilterNegateTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let vid = args.get("view_id").and_then(Value::as_u64).unwrap_or(3);
        let f = rustre_events::EventFilter::for_view(vid).negate();
        let same = rustre_events::CoreEvent::ViewClosed { view_id: vid };
        let other = rustre_events::CoreEvent::ViewClosed { view_id: vid.wrapping_add(1) };
        Ok(ToolResult::text(json!({"view_id":vid,"matches_same":f.matches(&same),"matches_other":f.matches(&other),"source":"rustre_events::EventFilter::negate"}).to_string()))
    }
}

pub struct EventsHookMatchesAndLabelTool;
impl EventsHookMatchesAndLabelTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "events_hook_matches_and_label".to_string(),
            description: "Build EventHook, verify matches and label().".to_string(),
            input_schema: json!({"type":"object","properties":{"label":{"type":"string"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for EventsHookMatchesAndLabelTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let lbl = args.get("label").and_then(Value::as_str).unwrap_or("h").to_string();
        let hook = rustre_events::EventHook::new(lbl.clone(), |_e| true, |_e| {});
        let ev = rustre_events::CoreEvent::ViewClosed { view_id: 1 };
        Ok(ToolResult::text(json!({"label":hook.label(),"matches":hook.matches(&ev),"input_label":lbl,"source":"rustre_events::EventHook"}).to_string()))
    }
}

pub struct EventsHookDispatcherRemoveTool;
impl EventsHookDispatcherRemoveTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "events_hook_dispatcher_remove".to_string(),
            description: "Register two hooks then remove one by label; report hook_count before/after.".to_string(),
            input_schema: json!({"type":"object","properties":{}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for EventsHookDispatcherRemoveTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let d = rustre_events::HookDispatcher::new();
        d.register(rustre_events::EventHook::new("a", |_| true, |_| {}));
        d.register(rustre_events::EventHook::new("b", |_| true, |_| {}));
        let before = d.hook_count();
        d.remove("a");
        let after = d.hook_count();
        Ok(ToolResult::text(json!({"before":before,"after":after,"source":"rustre_events::HookDispatcher::remove"}).to_string()))
    }
}

pub struct EventsLoggerRecentEventsTool;
impl EventsLoggerRecentEventsTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "events_logger_recent_events".to_string(),
            description: "Record N events into EventLogger and query recent_events(k).".to_string(),
            input_schema: json!({"type":"object","properties":{"n":{"type":"integer"},"k":{"type":"integer"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for EventsLoggerRecentEventsTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let n = args.get("n").and_then(Value::as_u64).unwrap_or(5) as usize;
        let k = args.get("k").and_then(Value::as_u64).unwrap_or(3) as usize;
        let log = rustre_events::EventLogger::new(64);
        for i in 0..n {
            log.record(rustre_events::CoreEvent::ViewClosed { view_id: i as u64 });
        }
        let recent = log.recent_events(k);
        Ok(ToolResult::text(json!({"count":log.count(),"recent_len":recent.len(),"source":"rustre_events::EventLogger::recent_events"}).to_string()))
    }
}

pub struct EventsLoggerEventsForViewTool;
impl EventsLoggerEventsForViewTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "events_logger_events_for_view".to_string(),
            description: "Record events for two views, filter by events_for_view.".to_string(),
            input_schema: json!({"type":"object","properties":{"view_id":{"type":"integer"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for EventsLoggerEventsForViewTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let vid = args.get("view_id").and_then(Value::as_u64).unwrap_or(7);
        let log = rustre_events::EventLogger::new(32);
        log.record(rustre_events::CoreEvent::ViewClosed { view_id: vid });
        log.record(rustre_events::CoreEvent::ViewClosed { view_id: vid.wrapping_add(1) });
        log.record(rustre_events::CoreEvent::ViewClosed { view_id: vid });
        let for_v = log.events_for_view(vid);
        Ok(ToolResult::text(json!({"total":log.count(),"for_view":for_v.len(),"source":"rustre_events::EventLogger::events_for_view"}).to_string()))
    }
}

pub struct EventsLoggerClearAndCountTool;
impl EventsLoggerClearAndCountTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "events_logger_clear_and_count".to_string(),
            description: "Record then clear() an EventLogger; report count before/after.".to_string(),
            input_schema: json!({"type":"object","properties":{}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for EventsLoggerClearAndCountTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let log = rustre_events::EventLogger::new(8);
        log.record(rustre_events::CoreEvent::ViewClosed { view_id: 1 });
        log.record(rustre_events::CoreEvent::ViewClosed { view_id: 2 });
        let before = log.count();
        log.clear();
        Ok(ToolResult::text(json!({"before":before,"after":log.count(),"source":"rustre_events::EventLogger::clear"}).to_string()))
    }
}

pub struct EventsReplayIsEmptyTool;
impl EventsReplayIsEmptyTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "events_replay_new_is_empty".to_string(),
            description: "Construct EventReplay::new and query is_empty/len.".to_string(),
            input_schema: json!({"type":"object","properties":{}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for EventsReplayIsEmptyTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let r = rustre_events::EventReplay::new();
        Ok(ToolResult::text(json!({"is_empty":r.is_empty(),"len":r.len(),"source":"rustre_events::EventReplay::new"}).to_string()))
    }
}

pub struct EventsReplayClearTool;
impl EventsReplayClearTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "events_replay_clear".to_string(),
            description: "Push N events into EventReplay then clear it.".to_string(),
            input_schema: json!({"type":"object","properties":{"n":{"type":"integer"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for EventsReplayClearTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let n = args.get("n").and_then(Value::as_u64).unwrap_or(3) as usize;
        let mut r = rustre_events::EventReplay::new();
        for i in 0..n {
            r.push(rustre_events::CoreEvent::ViewClosed { view_id: i as u64 });
        }
        let before = r.len();
        r.clear();
        Ok(ToolResult::text(json!({"before":before,"after":r.len(),"source":"rustre_events::EventReplay::clear"}).to_string()))
    }
}

pub struct EventsStatsVariantCountTool;
impl EventsStatsVariantCountTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "events_stats_variant_count".to_string(),
            description: "Record events into EventStats and query variant_count.".to_string(),
            input_schema: json!({"type":"object","properties":{"n":{"type":"integer"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for EventsStatsVariantCountTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let n = args.get("n").and_then(Value::as_u64).unwrap_or(4);
        let s = rustre_events::EventStats::new();
        for i in 0..n {
            s.record(&rustre_events::CoreEvent::ViewClosed { view_id: i });
        }
        Ok(ToolResult::text(json!({"variant_count":s.variant_count("ViewClosed"),"total":s.total(),"source":"rustre_events::EventStats::variant_count"}).to_string()))
    }
}

pub struct EventsStatsKindCountResetTool;
impl EventsStatsKindCountResetTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "events_stats_kind_count_reset".to_string(),
            description: "Record then reset EventStats; verify kind_count returns to 0.".to_string(),
            input_schema: json!({"type":"object","properties":{}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for EventsStatsKindCountResetTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let s = rustre_events::EventStats::new();
        s.record(&rustre_events::CoreEvent::ViewClosed { view_id: 1 });
        let before = s.kind_count(rustre_events::EventKind::View);
        s.reset();
        Ok(ToolResult::text(json!({"before":before,"after":s.kind_count(rustre_events::EventKind::View),"total_after":s.total(),"source":"rustre_events::EventStats::reset"}).to_string()))
    }
}

pub struct EventsCoreEventIsAnalysisEventTool;
impl EventsCoreEventIsAnalysisEventTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "events_core_event_is_analysis_event".to_string(),
            description: "Test CoreEvent::is_analysis_event on AnalysisStarted vs ViewClosed.".to_string(),
            input_schema: json!({"type":"object","properties":{}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for EventsCoreEventIsAnalysisEventTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let a = rustre_events::CoreEvent::AnalysisStarted { view_id: 1, pass: "p".to_string() };
        let b = rustre_events::CoreEvent::ViewClosed { view_id: 1 };
        Ok(ToolResult::text(json!({"analysis":a.is_analysis_event(),"view":b.is_analysis_event(),"source":"rustre_events::CoreEvent::is_analysis_event"}).to_string()))
    }
}

pub struct EventsCoreEventIsFunctionEventTool;
impl EventsCoreEventIsFunctionEventTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "events_core_event_is_function_event".to_string(),
            description: "Test CoreEvent::is_function_event on FunctionDefined vs ViewClosed.".to_string(),
            input_schema: json!({"type":"object","properties":{}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for EventsCoreEventIsFunctionEventTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let a = rustre_events::CoreEvent::FunctionDefined { view_id: 1, address: 0x1000, name: "f".to_string() };
        let b = rustre_events::CoreEvent::ViewClosed { view_id: 1 };
        Ok(ToolResult::text(json!({"function":a.is_function_event(),"view":b.is_function_event(),"source":"rustre_events::CoreEvent::is_function_event"}).to_string()))
    }
}

pub struct EventsSpecBusNewHistoryTool;
impl EventsSpecBusNewHistoryTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "events_spec_bus_new_history".to_string(), description: "SpecEventBus::new + history_len/receiver_count".to_string(), input_schema: json!({"type":"object","properties":{"capacity":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait::async_trait] impl ToolHandler for EventsSpecBusNewHistoryTool { async fn call(&self, args: Value) -> Result<ToolResult, rustre_mcp_server::McpError> { let cap = args.get("capacity").and_then(Value::as_u64).unwrap_or(64) as usize; let bus = rustre_events::SpecEventBus::new(cap); Ok(ToolResult::text(json!({"history_len":bus.history_len(),"receiver_count":bus.receiver_count(),"source":"rustre_events::SpecEventBus::new"}).to_string())) } }

pub struct EventsSpecBusRecentEventsTool;
impl EventsSpecBusRecentEventsTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "events_spec_bus_recent_events".to_string(), description: "Publish n SpecCoreEvent::ViewClosed then return recent_events(k).".to_string(), input_schema: json!({"type":"object","properties":{"n":{"type":"integer"},"k":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait::async_trait] impl ToolHandler for EventsSpecBusRecentEventsTool { async fn call(&self, args: Value) -> Result<ToolResult, rustre_mcp_server::McpError> { let n = args.get("n").and_then(Value::as_u64).unwrap_or(5); let k = args.get("k").and_then(Value::as_u64).unwrap_or(3) as usize; let bus = rustre_events::SpecEventBus::new(1024); for i in 0..n { bus.publish(rustre_events::SpecCoreEvent::ViewClosed { view_id: i }); } let recent = bus.recent_events(k); Ok(ToolResult::text(json!({"history_len":bus.history_len(),"recent_len":recent.len(),"recent_names":recent.iter().map(|e| e.variant_name()).collect::<Vec<_>>(),"source":"rustre_events::SpecEventBus::recent_events"}).to_string())) } }

pub struct EventsSpecBusPublishAndReceiversTool;
impl EventsSpecBusPublishAndReceiversTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "events_spec_bus_publish_and_receivers".to_string(), description: "Subscribe, publish ViewOpened, report counts.".to_string(), input_schema: json!({"type":"object","properties":{"view_id":{"type":"integer"},"path":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait::async_trait] impl ToolHandler for EventsSpecBusPublishAndReceiversTool { async fn call(&self, args: Value) -> Result<ToolResult, rustre_mcp_server::McpError> { let view_id = args.get("view_id").and_then(Value::as_u64).unwrap_or(1); let path = args.get("path").and_then(Value::as_str).unwrap_or("/bin/x").to_string(); let bus = rustre_events::SpecEventBus::new(64); let _rx = bus.subscribe(); bus.publish(rustre_events::SpecCoreEvent::ViewOpened { view_id, path }); Ok(ToolResult::text(json!({"receiver_count":bus.receiver_count(),"history_len":bus.history_len(),"source":"rustre_events::SpecEventBus::publish"}).to_string())) } }

pub struct EventsSpecFilterViewIdsMatchesTool;
impl EventsSpecFilterViewIdsMatchesTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "events_spec_filter_view_ids_matches".to_string(), description: "SpecEventFilter::with_view_ids([id]) matches ViewClosed(test_id).".to_string(), input_schema: json!({"type":"object","required":["id","test_id"],"properties":{"id":{"type":"integer"},"test_id":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait::async_trait] impl ToolHandler for EventsSpecFilterViewIdsMatchesTool { async fn call(&self, args: Value) -> Result<ToolResult, rustre_mcp_server::McpError> { let id = args.get("id").and_then(Value::as_u64).ok_or_else(|| rustre_mcp_server::McpError::InvalidParams("missing 'id'".into()))?; let test_id = args.get("test_id").and_then(Value::as_u64).ok_or_else(|| rustre_mcp_server::McpError::InvalidParams("missing 'test_id'".into()))?; let f = rustre_events::SpecEventFilter::new().with_view_ids([id]); let ev = rustre_events::SpecCoreEvent::ViewClosed { view_id: test_id }; Ok(ToolResult::text(json!({"matches":f.matches(&ev),"source":"rustre_events::SpecEventFilter::with_view_ids"}).to_string())) } }

pub struct EventsSpecFilterEventTypesMatchesTool;
impl EventsSpecFilterEventTypesMatchesTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "events_spec_filter_event_types_matches".to_string(), description: "SpecEventFilter::with_event_types([type_name]) matches.".to_string(), input_schema: json!({"type":"object","required":["type_name"],"properties":{"type_name":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait::async_trait] impl ToolHandler for EventsSpecFilterEventTypesMatchesTool { async fn call(&self, args: Value) -> Result<ToolResult, rustre_mcp_server::McpError> { let type_name = args.get("type_name").and_then(Value::as_str).ok_or_else(|| rustre_mcp_server::McpError::InvalidParams("missing 'type_name'".into()))?.to_string(); let f = rustre_events::SpecEventFilter::new().with_event_types([type_name.clone()]); let fn_def = rustre_events::SpecCoreEvent::FunctionDefined { view_id: 1, addr: 0, name: "f".into() }; let vc = rustre_events::SpecCoreEvent::ViewClosed { view_id: 1 }; Ok(ToolResult::text(json!({"type_name":type_name,"matches_function_defined":f.matches(&fn_def),"matches_view_closed":f.matches(&vc),"source":"rustre_events::SpecEventFilter::with_event_types"}).to_string())) } }

pub struct EventsSpecFilterCombinedTool;
impl EventsSpecFilterCombinedTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "events_spec_filter_combined".to_string(), description: "SpecEventFilter view_ids+event_types combined.".to_string(), input_schema: json!({"type":"object","required":["vid","type_name"],"properties":{"vid":{"type":"integer"},"type_name":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait::async_trait] impl ToolHandler for EventsSpecFilterCombinedTool { async fn call(&self, args: Value) -> Result<ToolResult, rustre_mcp_server::McpError> { let vid = args.get("vid").and_then(Value::as_u64).ok_or_else(|| rustre_mcp_server::McpError::InvalidParams("missing 'vid'".into()))?; let type_name = args.get("type_name").and_then(Value::as_str).ok_or_else(|| rustre_mcp_server::McpError::InvalidParams("missing 'type_name'".into()))?.to_string(); let f = rustre_events::SpecEventFilter::new().with_view_ids([vid]).with_event_types([type_name.clone()]); let hit = rustre_events::SpecCoreEvent::BreakpointHit { view_id: vid, addr: 0xDEAD, thread_id: 0 }; Ok(ToolResult::text(json!({"matches_hit_same_view":f.matches(&hit),"type_name":type_name,"source":"rustre_events::SpecEventFilter"}).to_string())) } }

pub struct EventsSpecFilterPassGlobalTool;
impl EventsSpecFilterPassGlobalTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "events_spec_filter_pass_global".to_string(), description: "SpecEventFilter::with_pass_global_events probe.".to_string(), input_schema: json!({"type":"object","properties":{"pass":{"type":"boolean"}}}), parameters: Value::Null } } }
#[async_trait::async_trait] impl ToolHandler for EventsSpecFilterPassGlobalTool { async fn call(&self, args: Value) -> Result<ToolResult, rustre_mcp_server::McpError> { let pass = args.get("pass").and_then(Value::as_bool).unwrap_or(true); let f = rustre_events::SpecEventFilter::new().with_view_ids([1u64]).with_pass_global_events(pass); let ev = rustre_events::SpecCoreEvent::DebuggerAttached { pid: 100 }; Ok(ToolResult::text(json!({"pass_global":pass,"matches":f.matches(&ev),"source":"rustre_events::SpecEventFilter::with_pass_global_events"}).to_string())) } }

pub struct EventsGlobalBusPublishTool;
impl EventsGlobalBusPublishTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "events_global_bus_publish".to_string(), description: "Publish PluginLoaded to global_bus and read history_len.".to_string(), input_schema: json!({"type":"object","properties":{"name":{"type":"string"},"version":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait::async_trait] impl ToolHandler for EventsGlobalBusPublishTool { async fn call(&self, args: Value) -> Result<ToolResult, rustre_mcp_server::McpError> { let name = args.get("name").and_then(Value::as_str).unwrap_or("wire").to_string(); let version = args.get("version").and_then(Value::as_str).unwrap_or("0.0.0").to_string(); rustre_events::publish(rustre_events::SpecCoreEvent::PluginLoaded { name: name.clone(), version: version.clone() }); let bus = rustre_events::global_bus(); Ok(ToolResult::text(json!({"history_len":bus.history_len(),"published_name":name,"published_version":version,"source":"rustre_events::publish"}).to_string())) } }

pub struct EventsSpecCoreEventViewIdAgentTool;
impl EventsSpecCoreEventViewIdAgentTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "events_spec_core_event_view_id_agent".to_string(), description: "SpecCoreEvent::AgentAction view_id/variant_name.".to_string(), input_schema: json!({"type":"object","properties":{"view_id":{"type":"integer"},"action":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait::async_trait] impl ToolHandler for EventsSpecCoreEventViewIdAgentTool { async fn call(&self, args: Value) -> Result<ToolResult, rustre_mcp_server::McpError> { let view_id = args.get("view_id").and_then(Value::as_u64).unwrap_or(5); let action = args.get("action").and_then(Value::as_str).unwrap_or("decompile").to_string(); let ev = rustre_events::SpecCoreEvent::AgentAction { view_id, action, result: json!({"ok": true}) }; Ok(ToolResult::text(json!({"view_id":ev.view_id(),"variant_name":ev.variant_name(),"source":"rustre_events::SpecCoreEvent::AgentAction"}).to_string())) } }

pub struct EventsSpecCoreEventJsonRoundtripTool;
impl EventsSpecCoreEventJsonRoundtripTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "events_spec_core_event_json_roundtrip".to_string(), description: "SpecCoreEvent::FunctionDefined serde roundtrip.".to_string(), input_schema: json!({"type":"object","properties":{"view_id":{"type":"integer"},"addr":{"type":"integer"},"name":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait::async_trait] impl ToolHandler for EventsSpecCoreEventJsonRoundtripTool { async fn call(&self, args: Value) -> Result<ToolResult, rustre_mcp_server::McpError> { let view_id = args.get("view_id").and_then(Value::as_u64).unwrap_or(1); let addr = args.get("addr").and_then(Value::as_u64).unwrap_or(0x1000); let name = args.get("name").and_then(Value::as_str).unwrap_or("entry").to_string(); let ev = rustre_events::SpecCoreEvent::FunctionDefined { view_id, addr, name }; let s = serde_json::to_string(&ev).map_err(|e| rustre_mcp_server::McpError::InternalError(format!("serialize: {e}")))?; let back: rustre_events::SpecCoreEvent = serde_json::from_str(&s).map_err(|e| rustre_mcp_server::McpError::InternalError(format!("deserialize: {e}")))?; Ok(ToolResult::text(json!({"json_len":s.len(),"variant_name":back.variant_name(),"view_id":back.view_id(),"source":"rustre_events::SpecCoreEvent (serde)"}).to_string())) } }

pub struct EventsCorrelatorKeysAndTotalTool;
impl EventsCorrelatorKeysAndTotalTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "events_correlator_keys_and_total".to_string(), description: "EventCorrelator::by_view keys+total.".to_string(), input_schema: json!({"type":"object","properties":{"n":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait::async_trait] impl ToolHandler for EventsCorrelatorKeysAndTotalTool { async fn call(&self, args: Value) -> Result<ToolResult, rustre_mcp_server::McpError> { let n = args.get("n").and_then(Value::as_u64).unwrap_or(3); let c = rustre_events::EventCorrelator::by_view(); for i in 0..n { c.ingest(rustre_events::CoreEvent::ViewClosed { view_id: i }); } let mut keys = c.keys(); keys.sort(); Ok(ToolResult::text(json!({"keys":keys,"total":c.total_count(),"source":"rustre_events::EventCorrelator::by_view"}).to_string())) } }

pub struct EventsBusTotalSentVariantTool;
impl EventsBusTotalSentVariantTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "events_bus_total_sent_variant".to_string(), description: "EventBus send n ViewClosed and read total_sent + per-variant count.".to_string(), input_schema: json!({"type":"object","properties":{"n":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait::async_trait] impl ToolHandler for EventsBusTotalSentVariantTool { async fn call(&self, args: Value) -> Result<ToolResult, rustre_mcp_server::McpError> { let n = args.get("n").and_then(Value::as_u64).unwrap_or(3); let bus = rustre_events::EventBus::new_default(); let _rx = bus.subscribe(); for i in 0..n { bus.send_view_closed(i); } Ok(ToolResult::text(json!({"total_sent":bus.total_sent(),"view_closed_count":bus.event_count("ViewClosed"),"source":"rustre_events::EventBus::total_sent"}).to_string())) } }

pub struct EventsBusNewCapacityExtTool;
impl EventsBusNewCapacityExtTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "events_bus_new_capacity_ext".to_string(), description: "Construct EventBus::new(cap) via rustre_events::EventBus::new.".to_string(), input_schema: json!({"type":"object","properties":{"cap":{"type":"integer"}},"required":["cap"]}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for EventsBusNewCapacityExtTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let cap = usize::try_from(args.get("cap").and_then(Value::as_u64).unwrap_or(16).max(1)).unwrap_or(16); let bus = rustre_events::EventBus::new(cap); Ok(ToolResult::text(json!({"receiver_count":bus.receiver_count(),"total_sent":bus.total_sent(),"source":"rustre_events::EventBus::new"}).to_string())) } }

pub struct EventsBusSendSymbolDefinedExtTool;
impl EventsBusSendSymbolDefinedExtTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "events_bus_send_symbol_defined_ext".to_string(), description: "Send SymbolDefined via rustre_events::EventBus::send_symbol_defined.".to_string(), input_schema: json!({"type":"object","properties":{"view_id":{"type":"integer"},"address":{"type":"integer"},"name":{"type":"string"},"kind":{"type":"string"},"source":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for EventsBusSendSymbolDefinedExtTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let bus = rustre_events::EventBus::new_default(); let _rx = bus.subscribe(); let view_id = args.get("view_id").and_then(Value::as_u64).unwrap_or(1); let address = args.get("address").and_then(Value::as_u64).unwrap_or(0x1000); let name = args.get("name").and_then(Value::as_str).unwrap_or("sym").to_string(); let kind = args.get("kind").and_then(Value::as_str).unwrap_or("func").to_string(); let source = args.get("source").and_then(Value::as_str).unwrap_or("test").to_string(); bus.send_symbol_defined(view_id, address, name, kind, source); Ok(ToolResult::text(json!({"count":bus.event_count("SymbolDefined"),"total":bus.total_sent(),"source":"rustre_events::EventBus::send_symbol_defined"}).to_string())) } }

pub struct EventsBusSendAgentActionExtTool;
impl EventsBusSendAgentActionExtTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "events_bus_send_agent_action_ext".to_string(), description: "Send AgentAction via rustre_events::EventBus::send_agent_action.".to_string(), input_schema: json!({"type":"object","properties":{"view_id":{"type":"integer"},"action":{"type":"string"},"result":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for EventsBusSendAgentActionExtTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let bus = rustre_events::EventBus::new_default(); let _rx = bus.subscribe(); let view_id = args.get("view_id").and_then(Value::as_u64).unwrap_or(1); let action = args.get("action").and_then(Value::as_str).unwrap_or("rename").to_string(); let result = args.get("result").and_then(Value::as_str).unwrap_or("ok").to_string(); bus.send_agent_action(view_id, action, result); Ok(ToolResult::text(json!({"count":bus.event_count("AgentAction"),"total":bus.total_sent(),"source":"rustre_events::EventBus::send_agent_action"}).to_string())) } }

pub struct EventsBusSendXrefAddedExtTool;
impl EventsBusSendXrefAddedExtTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "events_bus_send_xref_added_ext".to_string(), description: "Send XrefAdded via rustre_events::EventBus::send_xref_added.".to_string(), input_schema: json!({"type":"object","properties":{"view_id":{"type":"integer"},"from":{"type":"integer"},"to":{"type":"integer"},"kind":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for EventsBusSendXrefAddedExtTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let bus = rustre_events::EventBus::new_default(); let _rx = bus.subscribe(); let view_id = args.get("view_id").and_then(Value::as_u64).unwrap_or(1); let from = args.get("from").and_then(Value::as_u64).unwrap_or(0x1000); let to = args.get("to").and_then(Value::as_u64).unwrap_or(0x2000); let kind = args.get("kind").and_then(Value::as_str).unwrap_or("call").to_string(); bus.send_xref_added(view_id, from, to, kind); Ok(ToolResult::text(json!({"count":bus.event_count("XrefAdded"),"total":bus.total_sent(),"source":"rustre_events::EventBus::send_xref_added"}).to_string())) } }

pub struct EventsBusSendPatchAppliedExtTool;
impl EventsBusSendPatchAppliedExtTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "events_bus_send_patch_applied_ext".to_string(), description: "Send PatchApplied via rustre_events::EventBus::send_patch_applied.".to_string(), input_schema: json!({"type":"object","properties":{"view_id":{"type":"integer"},"address":{"type":"integer"},"length":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for EventsBusSendPatchAppliedExtTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let bus = rustre_events::EventBus::new_default(); let _rx = bus.subscribe(); let view_id = args.get("view_id").and_then(Value::as_u64).unwrap_or(1); let address = args.get("address").and_then(Value::as_u64).unwrap_or(0x1000); let length = usize::try_from(args.get("length").and_then(Value::as_u64).unwrap_or(4)).unwrap_or(4); bus.send_patch_applied(view_id, address, length); Ok(ToolResult::text(json!({"count":bus.event_count("PatchApplied"),"total":bus.total_sent(),"source":"rustre_events::EventBus::send_patch_applied"}).to_string())) } }

pub struct EventsBusSendScriptExecutedExtTool;
impl EventsBusSendScriptExecutedExtTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "events_bus_send_script_executed_ext".to_string(), description: "Send ScriptExecuted via rustre_events::EventBus::send_script_executed.".to_string(), input_schema: json!({"type":"object","properties":{"view_id":{"type":"integer"},"engine":{"type":"string"},"success":{"type":"boolean"}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for EventsBusSendScriptExecutedExtTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let bus = rustre_events::EventBus::new_default(); let _rx = bus.subscribe(); let view_id = args.get("view_id").and_then(Value::as_u64).unwrap_or(1); let engine = args.get("engine").and_then(Value::as_str).unwrap_or("lua").to_string(); let success = args.get("success").and_then(Value::as_bool).unwrap_or(true); bus.send_script_executed(view_id, engine, success); Ok(ToolResult::text(json!({"count":bus.event_count("ScriptExecuted"),"total":bus.total_sent(),"source":"rustre_events::EventBus::send_script_executed"}).to_string())) } }

pub struct EventsBusSendAnalysisProgressExtTool;
impl EventsBusSendAnalysisProgressExtTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "events_bus_send_analysis_progress_ext".to_string(), description: "Send AnalysisProgress via rustre_events::EventBus::send_analysis_progress.".to_string(), input_schema: json!({"type":"object","properties":{"view_id":{"type":"integer"},"pass":{"type":"string"},"percent":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for EventsBusSendAnalysisProgressExtTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let bus = rustre_events::EventBus::new_default(); let _rx = bus.subscribe(); let view_id = args.get("view_id").and_then(Value::as_u64).unwrap_or(1); let pass = args.get("pass").and_then(Value::as_str).unwrap_or("cfg").to_string(); let percent = u8::try_from(args.get("percent").and_then(Value::as_u64).unwrap_or(50)).unwrap_or(50); bus.send_analysis_progress(view_id, pass, percent); Ok(ToolResult::text(json!({"count":bus.event_count("AnalysisProgress"),"total":bus.total_sent(),"source":"rustre_events::EventBus::send_analysis_progress"}).to_string())) } }

pub struct EventsBusSendFunctionRenamedExtTool;
impl EventsBusSendFunctionRenamedExtTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "events_bus_send_function_renamed_ext".to_string(), description: "Send FunctionRenamed via rustre_events::EventBus::send_function_renamed.".to_string(), input_schema: json!({"type":"object","properties":{"view_id":{"type":"integer"},"address":{"type":"integer"},"old":{"type":"string"},"new":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for EventsBusSendFunctionRenamedExtTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let bus = rustre_events::EventBus::new_default(); let _rx = bus.subscribe(); let view_id = args.get("view_id").and_then(Value::as_u64).unwrap_or(1); let address = args.get("address").and_then(Value::as_u64).unwrap_or(0x1000); let old = args.get("old").and_then(Value::as_str).unwrap_or("sub_1000").to_string(); let new = args.get("new").and_then(Value::as_str).unwrap_or("main").to_string(); bus.send_function_renamed(view_id, address, old, new); Ok(ToolResult::text(json!({"count":bus.event_count("FunctionRenamed"),"total":bus.total_sent(),"source":"rustre_events::EventBus::send_function_renamed"}).to_string())) } }

pub struct EventsBusSendAnalysisFailedExtTool;
impl EventsBusSendAnalysisFailedExtTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "events_bus_send_analysis_failed_ext".to_string(), description: "Send AnalysisFailed via rustre_events::EventBus::send_analysis_failed.".to_string(), input_schema: json!({"type":"object","properties":{"view_id":{"type":"integer"},"pass":{"type":"string"},"error":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for EventsBusSendAnalysisFailedExtTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let bus = rustre_events::EventBus::new_default(); let _rx = bus.subscribe(); let view_id = args.get("view_id").and_then(Value::as_u64).unwrap_or(1); let pass = args.get("pass").and_then(Value::as_str).unwrap_or("cfg").to_string(); let error = args.get("error").and_then(Value::as_str).unwrap_or("timeout").to_string(); bus.send_analysis_failed(view_id, pass, error); Ok(ToolResult::text(json!({"count":bus.event_count("AnalysisFailed"),"total":bus.total_sent(),"source":"rustre_events::EventBus::send_analysis_failed"}).to_string())) } }

pub struct EventsReplayReplayAllExtTool;
impl EventsReplayReplayAllExtTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "events_replay_replay_all_ext".to_string(), description: "Push n events, replay_all onto a fresh bus via rustre_events::EventReplay::replay_all.".to_string(), input_schema: json!({"type":"object","properties":{"n":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for EventsReplayReplayAllExtTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let n = args.get("n").and_then(Value::as_u64).unwrap_or(3); let mut replay = rustre_events::EventReplay::new(); for i in 0..n { replay.push(rustre_events::CoreEvent::ViewClosed { view_id: i }); } let bus = rustre_events::EventBus::new_default(); let _rx = bus.subscribe(); let failures = replay.replay_all(&bus); Ok(ToolResult::text(json!({"len":replay.len(),"is_empty":replay.is_empty(),"failures":failures,"bus_total":bus.total_sent(),"source":"rustre_events::EventReplay::replay_all"}).to_string())) } }

pub struct EventsStatsKindCountExtTool;
impl EventsStatsKindCountExtTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "events_stats_kind_count_ext".to_string(), description: "Record n ViewClosed events and inspect kind_count via rustre_events::EventStats::kind_count.".to_string(), input_schema: json!({"type":"object","properties":{"n":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for EventsStatsKindCountExtTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let n = args.get("n").and_then(Value::as_u64).unwrap_or(4); let stats = rustre_events::EventStats::new(); for i in 0..n { stats.record(&rustre_events::CoreEvent::ViewClosed { view_id: i }); } Ok(ToolResult::text(json!({"total":stats.total(),"kind_view":stats.kind_count(rustre_events::EventKind::View),"variant_view_closed":stats.variant_count("ViewClosed"),"source":"rustre_events::EventStats::kind_count"}).to_string())) } }

pub struct EventsBusSendViewOpenedTool;
impl EventsBusSendViewOpenedTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "events_bus_send_view_opened".to_string(), description: "EventBus::send_view_opened publishes ViewOpened.".to_string(), input_schema: json!({"type":"object","properties":{"view_id":{"type":"integer"},"uri":{"type":"string"},"arch":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait::async_trait]
impl ToolHandler for EventsBusSendViewOpenedTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let bus = rustre_events::EventBus::new_default(); let _rx = bus.subscribe(); let vid = args.get("view_id").and_then(Value::as_u64).unwrap_or(1); let uri = args.get("uri").and_then(Value::as_str).unwrap_or("/bin/x").to_string(); let arch = args.get("arch").and_then(Value::as_str).unwrap_or("x86_64").to_string(); bus.send_view_opened(vid, uri, arch); Ok(ToolResult::text(json!({"count":bus.event_count("ViewOpened"),"total":bus.total_sent(),"source":"rustre_events::EventBus::send_view_opened"}).to_string())) } }

pub struct EventsBusSendFunctionDefinedTool;
impl EventsBusSendFunctionDefinedTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "events_bus_send_function_defined".to_string(), description: "EventBus::send_function_defined publishes FunctionDefined.".to_string(), input_schema: json!({"type":"object","properties":{"view_id":{"type":"integer"},"address":{"type":"integer"},"name":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait::async_trait]
impl ToolHandler for EventsBusSendFunctionDefinedTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let bus = rustre_events::EventBus::new_default(); let _rx = bus.subscribe(); let vid = args.get("view_id").and_then(Value::as_u64).unwrap_or(1); let addr = args.get("address").and_then(Value::as_u64).unwrap_or(0x1000); let name = args.get("name").and_then(Value::as_str).unwrap_or("f").to_string(); bus.send_function_defined(vid, addr, name); Ok(ToolResult::text(json!({"count":bus.event_count("FunctionDefined"),"total":bus.total_sent(),"source":"rustre_events::EventBus::send_function_defined"}).to_string())) } }

pub struct EventsBusSendAnalysisCompletedTool;
impl EventsBusSendAnalysisCompletedTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "events_bus_send_analysis_completed".to_string(), description: "EventBus::send_analysis_completed publishes AnalysisCompleted.".to_string(), input_schema: json!({"type":"object","properties":{"view_id":{"type":"integer"},"pass":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait::async_trait]
impl ToolHandler for EventsBusSendAnalysisCompletedTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let bus = rustre_events::EventBus::new_default(); let _rx = bus.subscribe(); let vid = args.get("view_id").and_then(Value::as_u64).unwrap_or(1); let pass = args.get("pass").and_then(Value::as_str).unwrap_or("cfg").to_string(); bus.send_analysis_completed(vid, pass); Ok(ToolResult::text(json!({"count":bus.event_count("AnalysisCompleted"),"total":bus.total_sent(),"source":"rustre_events::EventBus::send_analysis_completed"}).to_string())) } }

pub struct EventsExtBusSendDiffCompletedTool;
impl EventsExtBusSendDiffCompletedTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "events_ext_bus_send_diff_completed".to_string(), description: "ExtEventBus::send_diff_completed publishes DiffCompleted.".to_string(), input_schema: json!({"type":"object","properties":{"a":{"type":"integer"},"b":{"type":"integer"},"matched":{"type":"integer"},"unmatched":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait::async_trait]
impl ToolHandler for EventsExtBusSendDiffCompletedTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let bus = rustre_events::ExtEventBus::new_default(); let a = args.get("a").and_then(Value::as_u64).unwrap_or(1); let b = args.get("b").and_then(Value::as_u64).unwrap_or(2); let m = args.get("matched").and_then(Value::as_u64).unwrap_or(3); let u = args.get("unmatched").and_then(Value::as_u64).unwrap_or(1); bus.send_diff_completed(a, b, m, u); Ok(ToolResult::text(json!({"variant_count":bus.variant_count("DiffCompleted"),"total":bus.total_published(),"source":"rustre_events::ExtEventBus::send_diff_completed"}).to_string())) } }

pub struct EventsExtBusSendFlirtMatchTool;
impl EventsExtBusSendFlirtMatchTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "events_ext_bus_send_flirt_match".to_string(), description: "ExtEventBus::send_flirt_match publishes FlirtMatch.".to_string(), input_schema: json!({"type":"object","properties":{"view_id":{"type":"integer"},"address":{"type":"integer"},"library":{"type":"string"},"name":{"type":"string"},"score":{"type":"number"}}}), parameters: Value::Null } } }
#[async_trait::async_trait]
impl ToolHandler for EventsExtBusSendFlirtMatchTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let bus = rustre_events::ExtEventBus::new_default(); let vid = args.get("view_id").and_then(Value::as_u64).unwrap_or(1); let addr = args.get("address").and_then(Value::as_u64).unwrap_or(0x1000); let lib = args.get("library").and_then(Value::as_str).unwrap_or("libc").to_string(); let name = args.get("name").and_then(Value::as_str).unwrap_or("strlen").to_string(); let score = args.get("score").and_then(Value::as_f64).unwrap_or(0.9) as f32; bus.send_flirt_match(vid, addr, lib, name, score); Ok(ToolResult::text(json!({"variant_count":bus.variant_count("FlirtMatch"),"total":bus.total_published(),"source":"rustre_events::ExtEventBus::send_flirt_match"}).to_string())) } }

pub struct EventsExtBusSendCoverageUpdatedTool;
impl EventsExtBusSendCoverageUpdatedTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "events_ext_bus_send_coverage_updated".to_string(), description: "ExtEventBus::send_coverage_updated publishes CoverageUpdated.".to_string(), input_schema: json!({"type":"object","properties":{"view_id":{"type":"integer"},"percent":{"type":"number"}}}), parameters: Value::Null } } }
#[async_trait::async_trait]
impl ToolHandler for EventsExtBusSendCoverageUpdatedTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let bus = rustre_events::ExtEventBus::new_default(); let vid = args.get("view_id").and_then(Value::as_u64).unwrap_or(1); let pct = args.get("percent").and_then(Value::as_f64).unwrap_or(50.0) as f32; bus.send_coverage_updated(vid, pct); Ok(ToolResult::text(json!({"variant_count":bus.variant_count("CoverageUpdated"),"total":bus.total_published(),"source":"rustre_events::ExtEventBus::send_coverage_updated"}).to_string())) } }

pub struct EventsExtBusSendWatchdogPingTool;
impl EventsExtBusSendWatchdogPingTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "events_ext_bus_send_watchdog_ping".to_string(), description: "ExtEventBus::send_watchdog_ping publishes WatchdogPing.".to_string(), input_schema: json!({"type":"object","properties":{"component":{"type":"string"},"latency_ms":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait::async_trait]
impl ToolHandler for EventsExtBusSendWatchdogPingTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let bus = rustre_events::ExtEventBus::new_default(); let comp = args.get("component").and_then(Value::as_str).unwrap_or("decompiler").to_string(); let lat = args.get("latency_ms").and_then(Value::as_u64).unwrap_or(15); bus.send_watchdog_ping(comp, lat); Ok(ToolResult::text(json!({"variant_count":bus.variant_count("WatchdogPing"),"total":bus.total_published(),"source":"rustre_events::ExtEventBus::send_watchdog_ping"}).to_string())) } }

pub struct EventsExtBusSendPeerConnectedTool;
impl EventsExtBusSendPeerConnectedTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "events_ext_bus_send_peer_connected".to_string(), description: "ExtEventBus::send_peer_connected publishes PeerConnected.".to_string(), input_schema: json!({"type":"object","properties":{"peer_id":{"type":"string"},"view_id":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait::async_trait]
impl ToolHandler for EventsExtBusSendPeerConnectedTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let bus = rustre_events::ExtEventBus::new_default(); let peer = args.get("peer_id").and_then(Value::as_str).unwrap_or("peer-1").to_string(); let vid = args.get("view_id").and_then(Value::as_u64).unwrap_or(1); bus.send_peer_connected(peer, vid); Ok(ToolResult::text(json!({"variant_count":bus.variant_count("PeerConnected"),"total":bus.total_published(),"source":"rustre_events::ExtEventBus::send_peer_connected"}).to_string())) } }

pub struct EventsExtBusSendAgentThinkingTool;
impl EventsExtBusSendAgentThinkingTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "events_ext_bus_send_agent_thinking".to_string(), description: "ExtEventBus::send_agent_thinking publishes AgentThinking.".to_string(), input_schema: json!({"type":"object","properties":{"view_id":{"type":"integer"},"agent":{"type":"string"},"thought":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait::async_trait]
impl ToolHandler for EventsExtBusSendAgentThinkingTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let bus = rustre_events::ExtEventBus::new_default(); let vid = args.get("view_id").and_then(Value::as_u64).unwrap_or(1); let ag = args.get("agent").and_then(Value::as_str).unwrap_or("planner").to_string(); let th = args.get("thought").and_then(Value::as_str).unwrap_or("...").to_string(); bus.send_agent_thinking(vid, ag, th); Ok(ToolResult::text(json!({"variant_count":bus.variant_count("AgentThinking"),"total":bus.total_published(),"source":"rustre_events::ExtEventBus::send_agent_thinking"}).to_string())) } }

pub struct EventsExtBusSendMcpToolResultTool;
impl EventsExtBusSendMcpToolResultTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "events_ext_bus_send_mcp_tool_result".to_string(), description: "ExtEventBus::send_mcp_tool_result publishes McpToolResult.".to_string(), input_schema: json!({"type":"object","properties":{"view_id":{"type":"integer"},"tool":{"type":"string"},"result":{"type":"string"},"success":{"type":"boolean"}}}), parameters: Value::Null } } }
#[async_trait::async_trait]
impl ToolHandler for EventsExtBusSendMcpToolResultTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let bus = rustre_events::ExtEventBus::new_default(); let vid = args.get("view_id").and_then(Value::as_u64).unwrap_or(1); let t = args.get("tool").and_then(Value::as_str).unwrap_or("noop").to_string(); let r = args.get("result").and_then(Value::as_str).unwrap_or("{}").to_string(); let ok = args.get("success").and_then(Value::as_bool).unwrap_or(true); bus.send_mcp_tool_result(vid, t, r, ok); Ok(ToolResult::text(json!({"variant_count":bus.variant_count("McpToolResult"),"total":bus.total_published(),"source":"rustre_events::ExtEventBus::send_mcp_tool_result"}).to_string())) } }

pub struct EventsExtBusSubscribeWithHistoryTool;
impl EventsExtBusSubscribeWithHistoryTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "events_ext_bus_subscribe_with_history".to_string(), description: "ExtEventBus::subscribe_with_history returns history snapshot + rx.".to_string(), input_schema: json!({"type":"object","properties":{"n":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait::async_trait]
impl ToolHandler for EventsExtBusSubscribeWithHistoryTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let bus = rustre_events::ExtEventBus::new_default(); let n = args.get("n").and_then(Value::as_u64).unwrap_or(3); for i in 0..n { bus.send_coverage_updated(i, i as f32); } let (hist, _rx) = bus.subscribe_with_history(); Ok(ToolResult::text(json!({"history_len":hist.len(),"receiver_count":bus.receiver_count(),"source":"rustre_events::ExtEventBus::subscribe_with_history"}).to_string())) } }

pub struct EventsExtBusVariantCountTool;
impl EventsExtBusVariantCountTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "events_ext_bus_variant_count".to_string(), description: "ExtEventBus::variant_count for a variant after publishing n events.".to_string(), input_schema: json!({"type":"object","properties":{"n":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait::async_trait]
impl ToolHandler for EventsExtBusVariantCountTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let bus = rustre_events::ExtEventBus::new_default(); let n = args.get("n").and_then(Value::as_u64).unwrap_or(4); for i in 0..n { bus.send_ttd_tick(1, i, 0); } Ok(ToolResult::text(json!({"variant_count":bus.variant_count("TtdTick"),"other":bus.variant_count("TtdBackward"),"source":"rustre_events::ExtEventBus::variant_count"}).to_string())) } }

pub struct EventsExtBusDroppedCountTool;
impl EventsExtBusDroppedCountTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "events_ext_bus_dropped_count".to_string(), description: "ExtEventBus::dropped_count returns dropped events (0 on fresh bus).".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait::async_trait]
impl ToolHandler for EventsExtBusDroppedCountTool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { let bus = rustre_events::ExtEventBus::new_default(); Ok(ToolResult::text(json!({"dropped":bus.dropped_count(),"total":bus.total_published(),"source":"rustre_events::ExtEventBus::dropped_count"}).to_string())) } }

pub struct EventsExtBusTotalPublishedTool;
impl EventsExtBusTotalPublishedTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "events_ext_bus_total_published".to_string(), description: "ExtEventBus::total_published increments after publish.".to_string(), input_schema: json!({"type":"object","properties":{"n":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait::async_trait]
impl ToolHandler for EventsExtBusTotalPublishedTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let bus = rustre_events::ExtEventBus::new_default(); let n = args.get("n").and_then(Value::as_u64).unwrap_or(5); for _ in 0..n { bus.send_watchdog_ping("x".to_string(), 1); } Ok(ToolResult::text(json!({"total":bus.total_published(),"source":"rustre_events::ExtEventBus::total_published"}).to_string())) } }

pub struct EventsExtBusRecentEventsTool;
impl EventsExtBusRecentEventsTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "events_ext_bus_recent_events".to_string(), description: "ExtEventBus::recent_events returns last k of history.".to_string(), input_schema: json!({"type":"object","properties":{"n":{"type":"integer"},"k":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait::async_trait]
impl ToolHandler for EventsExtBusRecentEventsTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let bus = rustre_events::ExtEventBus::new_default(); let n = args.get("n").and_then(Value::as_u64).unwrap_or(5); let k = usize::try_from(args.get("k").and_then(Value::as_u64).unwrap_or(3)).unwrap_or(3); for i in 0..n { bus.send_ttd_tick(1, i, 0); } let rec = bus.recent_events(k); Ok(ToolResult::text(json!({"recent_len":rec.len(),"history_len":bus.history_len(),"source":"rustre_events::ExtEventBus::recent_events"}).to_string())) } }

pub struct EventsExtBusNewDefaultTool;
impl EventsExtBusNewDefaultTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "events_ext_bus_new_default".to_string(), description: "Construct rustre_events::ExtEventBus::new_default and report totals.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for EventsExtBusNewDefaultTool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { let bus = rustre_events::ExtEventBus::new_default(); Ok(ToolResult::text(json!({"total_published":bus.total_published(),"history_len":bus.history_len(),"receiver_count":bus.receiver_count(),"dropped":bus.dropped_count(),"source":"rustre_events::ExtEventBus::new_default"}).to_string())) } }

pub struct EventsExtBusSendTtdTickTool;
impl EventsExtBusSendTtdTickTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "events_ext_bus_send_ttd_tick".to_string(), description: "Send TtdTick via rustre_events::ExtEventBus::send_ttd_tick.".to_string(), input_schema: json!({"type":"object","properties":{"view_id":{"type":"integer"},"tick":{"type":"integer"},"thread_id":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for EventsExtBusSendTtdTickTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let bus = rustre_events::ExtEventBus::new_default(); let _rx = bus.subscribe(); let view_id = args.get("view_id").and_then(Value::as_u64).unwrap_or(1); let tick = args.get("tick").and_then(Value::as_u64).unwrap_or(42); let thread_id = u32::try_from(args.get("thread_id").and_then(Value::as_u64).unwrap_or(0)).unwrap_or(0); bus.send_ttd_tick(view_id, tick, thread_id); Ok(ToolResult::text(json!({"count":bus.variant_count("TtdTick"),"total":bus.total_published(),"source":"rustre_events::ExtEventBus::send_ttd_tick"}).to_string())) } }

pub struct EventsExtBusSendTtdBackwardTool;
impl EventsExtBusSendTtdBackwardTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "events_ext_bus_send_ttd_backward".to_string(), description: "Send TtdBackward via rustre_events::ExtEventBus::send_ttd_backward.".to_string(), input_schema: json!({"type":"object","properties":{"view_id":{"type":"integer"},"tick":{"type":"integer"},"thread_id":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for EventsExtBusSendTtdBackwardTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let bus = rustre_events::ExtEventBus::new_default(); let _rx = bus.subscribe(); let view_id = args.get("view_id").and_then(Value::as_u64).unwrap_or(1); let tick = args.get("tick").and_then(Value::as_u64).unwrap_or(10); let thread_id = u32::try_from(args.get("thread_id").and_then(Value::as_u64).unwrap_or(0)).unwrap_or(0); bus.send_ttd_backward(view_id, tick, thread_id); Ok(ToolResult::text(json!({"count":bus.variant_count("TtdBackward"),"total":bus.total_published(),"source":"rustre_events::ExtEventBus::send_ttd_backward"}).to_string())) } }

pub struct EventsExtBusSendEmulationStepTool;
impl EventsExtBusSendEmulationStepTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "events_ext_bus_send_emulation_step".to_string(), description: "Send EmulationStep via rustre_events::ExtEventBus::send_emulation_step.".to_string(), input_schema: json!({"type":"object","properties":{"view_id":{"type":"integer"},"address":{"type":"integer"},"mnemonic":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for EventsExtBusSendEmulationStepTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let bus = rustre_events::ExtEventBus::new_default(); let _rx = bus.subscribe(); let view_id = args.get("view_id").and_then(Value::as_u64).unwrap_or(1); let address = args.get("address").and_then(Value::as_u64).unwrap_or(0x1000); let mnemonic = args.get("mnemonic").and_then(Value::as_str).unwrap_or("mov").to_string(); bus.send_emulation_step(view_id, address, mnemonic); Ok(ToolResult::text(json!({"count":bus.variant_count("EmulationStep"),"total":bus.total_published(),"source":"rustre_events::ExtEventBus::send_emulation_step"}).to_string())) } }

pub struct EventsExtBusSendEmulationStopTool;
impl EventsExtBusSendEmulationStopTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "events_ext_bus_send_emulation_stop".to_string(), description: "Send EmulationStop via rustre_events::ExtEventBus::send_emulation_stop.".to_string(), input_schema: json!({"type":"object","properties":{"view_id":{"type":"integer"},"reason":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for EventsExtBusSendEmulationStopTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let bus = rustre_events::ExtEventBus::new_default(); let _rx = bus.subscribe(); let view_id = args.get("view_id").and_then(Value::as_u64).unwrap_or(1); let reason = args.get("reason").and_then(Value::as_str).unwrap_or("done").to_string(); bus.send_emulation_stop(view_id, reason); Ok(ToolResult::text(json!({"count":bus.variant_count("EmulationStop"),"total":bus.total_published(),"source":"rustre_events::ExtEventBus::send_emulation_stop"}).to_string())) } }

pub struct EventsExtBusSendFuzzCrashTool;
impl EventsExtBusSendFuzzCrashTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "events_ext_bus_send_fuzz_crash".to_string(), description: "Send FuzzCrash via rustre_events::ExtEventBus::send_fuzz_crash.".to_string(), input_schema: json!({"type":"object","properties":{"view_id":{"type":"integer"},"input_hash":{"type":"string"},"crash_address":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for EventsExtBusSendFuzzCrashTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let bus = rustre_events::ExtEventBus::new_default(); let _rx = bus.subscribe(); let view_id = args.get("view_id").and_then(Value::as_u64).unwrap_or(1); let input_hash = args.get("input_hash").and_then(Value::as_str).unwrap_or("deadbeef").to_string(); let crash_address = args.get("crash_address").and_then(Value::as_u64).unwrap_or(0x4000); bus.send_fuzz_crash(view_id, input_hash, crash_address); Ok(ToolResult::text(json!({"count":bus.variant_count("FuzzCrash"),"total":bus.total_published(),"source":"rustre_events::ExtEventBus::send_fuzz_crash"}).to_string())) } }

pub struct EventsExtBusSendFuzzNewCoverageTool;
impl EventsExtBusSendFuzzNewCoverageTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "events_ext_bus_send_fuzz_new_coverage".to_string(), description: "Send FuzzNewCoverage via rustre_events::ExtEventBus::send_fuzz_new_coverage.".to_string(), input_schema: json!({"type":"object","properties":{"view_id":{"type":"integer"},"new_blocks":{"type":"integer"},"total_blocks":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for EventsExtBusSendFuzzNewCoverageTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let bus = rustre_events::ExtEventBus::new_default(); let _rx = bus.subscribe(); let view_id = args.get("view_id").and_then(Value::as_u64).unwrap_or(1); let new_blocks = args.get("new_blocks").and_then(Value::as_u64).unwrap_or(3); let total_blocks = args.get("total_blocks").and_then(Value::as_u64).unwrap_or(100); bus.send_fuzz_new_coverage(view_id, new_blocks, total_blocks); Ok(ToolResult::text(json!({"count":bus.variant_count("FuzzNewCoverage"),"total":bus.total_published(),"source":"rustre_events::ExtEventBus::send_fuzz_new_coverage"}).to_string())) } }

pub struct EventsExtBusSendMcpToolCallTool;
impl EventsExtBusSendMcpToolCallTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "events_ext_bus_send_mcp_tool_call".to_string(), description: "Send McpToolCall via rustre_events::ExtEventBus::send_mcp_tool_call.".to_string(), input_schema: json!({"type":"object","properties":{"view_id":{"type":"integer"},"tool_name":{"type":"string"},"params_json":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for EventsExtBusSendMcpToolCallTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let bus = rustre_events::ExtEventBus::new_default(); let _rx = bus.subscribe(); let view_id = args.get("view_id").and_then(Value::as_u64).unwrap_or(1); let tool_name = args.get("tool_name").and_then(Value::as_str).unwrap_or("t").to_string(); let params_json = args.get("params_json").and_then(Value::as_str).unwrap_or("{}").to_string(); bus.send_mcp_tool_call(view_id, tool_name, params_json); Ok(ToolResult::text(json!({"count":bus.variant_count("McpToolCall"),"total":bus.total_published(),"source":"rustre_events::ExtEventBus::send_mcp_tool_call"}).to_string())) } }

pub struct EventsExtBusSendDiffStartedTool;
impl EventsExtBusSendDiffStartedTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "events_ext_bus_send_diff_started".to_string(), description: "Send DiffStarted via rustre_events::ExtEventBus::send_diff_started.".to_string(), input_schema: json!({"type":"object","properties":{"view_id_a":{"type":"integer"},"view_id_b":{"type":"integer"},"algorithm":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for EventsExtBusSendDiffStartedTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let bus = rustre_events::ExtEventBus::new_default(); let _rx = bus.subscribe(); let view_id_a = args.get("view_id_a").and_then(Value::as_u64).unwrap_or(1); let view_id_b = args.get("view_id_b").and_then(Value::as_u64).unwrap_or(2); let algorithm = args.get("algorithm").and_then(Value::as_str).unwrap_or("bindiff").to_string(); bus.send_diff_started(view_id_a, view_id_b, algorithm); Ok(ToolResult::text(json!({"count":bus.variant_count("DiffStarted"),"total":bus.total_published(),"source":"rustre_events::ExtEventBus::send_diff_started"}).to_string())) } }

pub struct EventsExtBusMetricsSnapshotTool;
impl EventsExtBusMetricsSnapshotTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "events_ext_bus_metrics_snapshot".to_string(), description: "Publish two events then read metrics via rustre_events::ExtEventBus::metrics.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for EventsExtBusMetricsSnapshotTool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { let bus = rustre_events::ExtEventBus::new_default(); let _rx = bus.subscribe(); bus.send_ttd_tick(1, 1, 0); bus.send_emulation_stop(1, "ok".into()); let m = bus.metrics(); Ok(ToolResult::text(json!({"total_published":m.total_published,"history_len":m.history_len,"receiver_count":m.receiver_count,"dropped":m.dropped,"variants":m.by_variant.len(),"source":"rustre_events::ExtEventBus::metrics"}).to_string())) } }

#[must_use]
pub fn handlers() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    vec![
        (EventsBusNewDefaultTool::definition(), Box::new(EventsBusNewDefaultTool)),
        (EventsLoggerNewTool::definition(), Box::new(EventsLoggerNewTool)),
        (EventsStatsRecordTool::definition(), Box::new(EventsStatsRecordTool)),
        (EventsReplayPushTool::definition(), Box::new(EventsReplayPushTool)),
        (EventsHookDispatcherNewTool::definition(), Box::new(EventsHookDispatcherNewTool)),
        (EventsBusPublishCustomTool::definition(), Box::new(EventsBusPublishCustomTool)),
        (EventsClassifyVariantTool::definition(), Box::new(EventsClassifyVariantTool)),
        (EventsViewSubscriptionTool::definition(), Box::new(EventsViewSubscriptionTool)),
        (EventsKindSubscriptionTool::definition(), Box::new(EventsKindSubscriptionTool)),
        (EventsBusSendViewClosedTool::definition(), Box::new(EventsBusSendViewClosedTool)),
        (EventsBusSendPluginLoadedTool::definition(), Box::new(EventsBusSendPluginLoadedTool)),
        (EventsSpecCoreEventVariantNameTool::definition(), Box::new(EventsSpecCoreEventVariantNameTool)),
        (EventsSpecCoreEventViewIdDebuggerTool::definition(), Box::new(EventsSpecCoreEventViewIdDebuggerTool)),
        (EventsCoreEventVariantNameTool::definition(), Box::new(EventsCoreEventVariantNameTool)),
        (EventsCoreEventIsDebugEventTool::definition(), Box::new(EventsCoreEventIsDebugEventTool)),
        (EventsCoreEventJsonRoundtripTool::definition(), Box::new(EventsCoreEventJsonRoundtripTool)),
        (EventsFilterForViewTool::definition(), Box::new(EventsFilterForViewTool)),
        (EventsBusSendCustomTool::definition(), Box::new(EventsBusSendCustomTool)),
        (EventsLoggerRecordAndCountTool::definition(), Box::new(EventsLoggerRecordAndCountTool)),
        (EventsCorrelatorByViewTool::definition(), Box::new(EventsCorrelatorByViewTool)),
        (EventsHookDispatcherRegisterTool::definition(), Box::new(EventsHookDispatcherRegisterTool)),
        (EventsReplayFilteredTool::definition(), Box::new(EventsReplayFilteredTool)),
        (EventsStatsRecordManyTool::definition(), Box::new(EventsStatsRecordManyTool)),
        (EventsCoreEventKindMemoryTool::definition(), Box::new(EventsCoreEventKindMemoryTool)),
        (EventsCoreEventDisplayFormattingTool::definition(), Box::new(EventsCoreEventDisplayFormattingTool)),
        (EventsFilterOfKindMatchesTool::definition(), Box::new(EventsFilterOfKindMatchesTool)),
        (EventsFilterCombinatorsTool::definition(), Box::new(EventsFilterCombinatorsTool)),
        (EventsBusEventCountersTool::definition(), Box::new(EventsBusEventCountersTool)),
        (EventsBusSendBreakpointHitTool::definition(), Box::new(EventsBusSendBreakpointHitTool)),
        (EventsLoggerEventsByKindTool::definition(), Box::new(EventsLoggerEventsByKindTool)),
        (EventsReplaySnapshotFromTool::definition(), Box::new(EventsReplaySnapshotFromTool)),
        (EventsCorrelatorByVariantTool::definition(), Box::new(EventsCorrelatorByVariantTool)),
        (EventsStatsAllVariantCountsTool::definition(), Box::new(EventsStatsAllVariantCountsTool)),
        (EventsFilteredSubscriptionCountersTool::definition(), Box::new(EventsFilteredSubscriptionCountersTool)),
        (EventsBusNewWithCapacityTool::definition(), Box::new(EventsBusNewWithCapacityTool)),
        (EventsBusEventCountTool::definition(), Box::new(EventsBusEventCountTool)),
        (EventsFilterByVariantTool::definition(), Box::new(EventsFilterByVariantTool)),
        (EventsFilterNegateTool::definition(), Box::new(EventsFilterNegateTool)),
        (EventsHookMatchesAndLabelTool::definition(), Box::new(EventsHookMatchesAndLabelTool)),
        (EventsHookDispatcherRemoveTool::definition(), Box::new(EventsHookDispatcherRemoveTool)),
        (EventsLoggerRecentEventsTool::definition(), Box::new(EventsLoggerRecentEventsTool)),
        (EventsLoggerEventsForViewTool::definition(), Box::new(EventsLoggerEventsForViewTool)),
        (EventsLoggerClearAndCountTool::definition(), Box::new(EventsLoggerClearAndCountTool)),
        (EventsReplayIsEmptyTool::definition(), Box::new(EventsReplayIsEmptyTool)),
        (EventsReplayClearTool::definition(), Box::new(EventsReplayClearTool)),
        (EventsStatsVariantCountTool::definition(), Box::new(EventsStatsVariantCountTool)),
        (EventsStatsKindCountResetTool::definition(), Box::new(EventsStatsKindCountResetTool)),
        (EventsCoreEventIsAnalysisEventTool::definition(), Box::new(EventsCoreEventIsAnalysisEventTool)),
        (EventsCoreEventIsFunctionEventTool::definition(), Box::new(EventsCoreEventIsFunctionEventTool)),
        (EventsSpecBusNewHistoryTool::definition(), Box::new(EventsSpecBusNewHistoryTool)),
        (EventsSpecBusRecentEventsTool::definition(), Box::new(EventsSpecBusRecentEventsTool)),
        (EventsSpecBusPublishAndReceiversTool::definition(), Box::new(EventsSpecBusPublishAndReceiversTool)),
        (EventsSpecFilterViewIdsMatchesTool::definition(), Box::new(EventsSpecFilterViewIdsMatchesTool)),
        (EventsSpecFilterEventTypesMatchesTool::definition(), Box::new(EventsSpecFilterEventTypesMatchesTool)),
        (EventsSpecFilterCombinedTool::definition(), Box::new(EventsSpecFilterCombinedTool)),
        (EventsSpecFilterPassGlobalTool::definition(), Box::new(EventsSpecFilterPassGlobalTool)),
        (EventsGlobalBusPublishTool::definition(), Box::new(EventsGlobalBusPublishTool)),
        (EventsSpecCoreEventViewIdAgentTool::definition(), Box::new(EventsSpecCoreEventViewIdAgentTool)),
        (EventsSpecCoreEventJsonRoundtripTool::definition(), Box::new(EventsSpecCoreEventJsonRoundtripTool)),
        (EventsCorrelatorKeysAndTotalTool::definition(), Box::new(EventsCorrelatorKeysAndTotalTool)),
        (EventsBusTotalSentVariantTool::definition(), Box::new(EventsBusTotalSentVariantTool)),
        (EventsBusNewCapacityExtTool::definition(), Box::new(EventsBusNewCapacityExtTool)),
        (EventsBusSendSymbolDefinedExtTool::definition(), Box::new(EventsBusSendSymbolDefinedExtTool)),
        (EventsBusSendAgentActionExtTool::definition(), Box::new(EventsBusSendAgentActionExtTool)),
        (EventsBusSendXrefAddedExtTool::definition(), Box::new(EventsBusSendXrefAddedExtTool)),
        (EventsBusSendPatchAppliedExtTool::definition(), Box::new(EventsBusSendPatchAppliedExtTool)),
        (EventsBusSendScriptExecutedExtTool::definition(), Box::new(EventsBusSendScriptExecutedExtTool)),
        (EventsBusSendAnalysisProgressExtTool::definition(), Box::new(EventsBusSendAnalysisProgressExtTool)),
        (EventsBusSendFunctionRenamedExtTool::definition(), Box::new(EventsBusSendFunctionRenamedExtTool)),
        (EventsBusSendAnalysisFailedExtTool::definition(), Box::new(EventsBusSendAnalysisFailedExtTool)),
        (EventsReplayReplayAllExtTool::definition(), Box::new(EventsReplayReplayAllExtTool)),
        (EventsStatsKindCountExtTool::definition(), Box::new(EventsStatsKindCountExtTool)),
        (EventsBusSendViewOpenedTool::definition(), Box::new(EventsBusSendViewOpenedTool)),
        (EventsBusSendFunctionDefinedTool::definition(), Box::new(EventsBusSendFunctionDefinedTool)),
        (EventsBusSendAnalysisCompletedTool::definition(), Box::new(EventsBusSendAnalysisCompletedTool)),
        (EventsExtBusSendDiffCompletedTool::definition(), Box::new(EventsExtBusSendDiffCompletedTool)),
        (EventsExtBusSendFlirtMatchTool::definition(), Box::new(EventsExtBusSendFlirtMatchTool)),
        (EventsExtBusSendCoverageUpdatedTool::definition(), Box::new(EventsExtBusSendCoverageUpdatedTool)),
        (EventsExtBusSendWatchdogPingTool::definition(), Box::new(EventsExtBusSendWatchdogPingTool)),
        (EventsExtBusSendPeerConnectedTool::definition(), Box::new(EventsExtBusSendPeerConnectedTool)),
        (EventsExtBusSendAgentThinkingTool::definition(), Box::new(EventsExtBusSendAgentThinkingTool)),
        (EventsExtBusSendMcpToolResultTool::definition(), Box::new(EventsExtBusSendMcpToolResultTool)),
        (EventsExtBusSubscribeWithHistoryTool::definition(), Box::new(EventsExtBusSubscribeWithHistoryTool)),
        (EventsExtBusVariantCountTool::definition(), Box::new(EventsExtBusVariantCountTool)),
        (EventsExtBusDroppedCountTool::definition(), Box::new(EventsExtBusDroppedCountTool)),
        (EventsExtBusTotalPublishedTool::definition(), Box::new(EventsExtBusTotalPublishedTool)),
        (EventsExtBusRecentEventsTool::definition(), Box::new(EventsExtBusRecentEventsTool)),
        (EventsExtBusNewDefaultTool::definition(), Box::new(EventsExtBusNewDefaultTool)),
        (EventsExtBusSendTtdTickTool::definition(), Box::new(EventsExtBusSendTtdTickTool)),
        (EventsExtBusSendTtdBackwardTool::definition(), Box::new(EventsExtBusSendTtdBackwardTool)),
        (EventsExtBusSendEmulationStepTool::definition(), Box::new(EventsExtBusSendEmulationStepTool)),
        (EventsExtBusSendEmulationStopTool::definition(), Box::new(EventsExtBusSendEmulationStopTool)),
        (EventsExtBusSendFuzzCrashTool::definition(), Box::new(EventsExtBusSendFuzzCrashTool)),
        (EventsExtBusSendFuzzNewCoverageTool::definition(), Box::new(EventsExtBusSendFuzzNewCoverageTool)),
        (EventsExtBusSendMcpToolCallTool::definition(), Box::new(EventsExtBusSendMcpToolCallTool)),
        (EventsExtBusSendDiffStartedTool::definition(), Box::new(EventsExtBusSendDiffStartedTool)),
        (EventsExtBusMetricsSnapshotTool::definition(), Box::new(EventsExtBusMetricsSnapshotTool)),
    ]
}
