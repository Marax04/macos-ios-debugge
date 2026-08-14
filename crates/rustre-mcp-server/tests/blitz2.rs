//! Deep adversarial test suite (blitz2) for rustre-mcp-server.
//! Covers round-trip, seeded fuzzing, boundaries, state machines,
//! Send/Sync stress, and Hash/Eq consistency on the public surface.

use rustre_mcp_server::{
    BinaryRegistry, ClientId, ConnectionState, ContentBlock, JsonRpcError, JsonRpcRequest,
    JsonRpcResponse, McpError, McpResource, McpResourceContent, McpToolDef, McpToolError,
    McpToolHandler, McpTransportTrait, MockTransport, ResourceProvider, ServerConfig,
    ServerResponse, SessionDescriptor, SessionKind, SessionManager, ToolCategory, ToolExecutor,
    ToolResult, build_tool_catalog, parse_hex_addr, parse_request, require_number,
    require_string, validate_required_strings,
};
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};

// ───────────────────────── Seeded LCG ─────────────────────────

fn lcg() -> impl FnMut() -> u64 {
    let mut s: u64 = 0xDEAD_BEEF_CAFE_BABE;
    move || {
        s = s
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        s
    }
}

// ───────────────────────── parse_hex_addr fuzz / boundaries ─────────────────────────

#[test]
fn hex_addr_50_round_trips() {
    let mut g = lcg();
    for _ in 0..50 {
        let v = g();
        let s = format!("0x{v:x}");
        assert_eq!(parse_hex_addr(&s).unwrap(), v);
        let s2 = format!("{v:x}");
        assert_eq!(parse_hex_addr(&s2).unwrap(), v);
    }
}

#[test]
fn hex_addr_boundaries() {
    assert_eq!(parse_hex_addr("0").unwrap(), 0);
    assert_eq!(parse_hex_addr("1").unwrap(), 1);
    assert_eq!(parse_hex_addr("0xffffffff").unwrap(), u32::MAX as u64);
    assert_eq!(parse_hex_addr("0x100000000").unwrap(), 1u64 << 32);
    assert_eq!(parse_hex_addr("ffffffffffffffff").unwrap(), u64::MAX);
}

#[test]
fn hex_addr_fuzz_never_panics() {
    let mut g = lcg();
    let chars = b"0123456789abcdefABCDEFxX +-_GZ ";
    for _ in 0..200 {
        let len = (g() % 20) as usize;
        let mut s = String::new();
        for _ in 0..len {
            s.push(chars[(g() as usize) % chars.len()] as char);
        }
        let _ = parse_hex_addr(&s);
    }
}

#[test]
fn hex_addr_overflow_paths() {
    assert!(parse_hex_addr("0x10000000000000000").is_err());
    assert!(parse_hex_addr("ffffffffffffffff0").is_err());
}

// ───────────────────────── require_string / require_number ─────────────────────────

#[test]
fn require_string_50_random_keys() {
    let mut g = lcg();
    for _ in 0..50 {
        let key = format!("k{}", g() % 1000);
        let v = json!({ &key: "value" });
        assert_eq!(require_string(&v, &key).unwrap(), "value");
        assert!(require_string(&v, "missing_xyz_999").is_err());
    }
}

#[test]
fn require_number_boundaries() {
    assert_eq!(require_number(&json!({"n": 0}), "n").unwrap(), 0);
    assert_eq!(
        require_number(&json!({"n": u64::MAX}), "n").unwrap(),
        u64::MAX
    );
    assert!(require_number(&json!({"n": -1}), "n").is_err());
    assert!(require_number(&json!({"n": "5"}), "n").is_err());
    assert!(require_number(&json!({}), "n").is_err());
}

#[test]
fn validate_required_strings_accepts_number() {
    // doc says "string or number" (look at impl); ensure number is OK.
    assert!(validate_required_strings(&json!({"a": 7}), &["a"]).is_ok());
}

#[test]
fn validate_required_strings_rejects_object_and_array() {
    assert!(validate_required_strings(&json!({"a": {}}), &["a"]).is_err());
    assert!(validate_required_strings(&json!({"a": []}), &["a"]).is_err());
}

// ───────────────────────── parse_request fuzz / round-trip ─────────────────────────

#[test]
fn parse_request_round_trip_50() {
    let mut g = lcg();
    for _ in 0..50 {
        let id = g() as i64;
        let s = format!(
            r#"{{"jsonrpc":"2.0","id":{id},"method":"m{id}","params":{{"x":{}}}}}"#,
            g() % 1000
        );
        let req = parse_request(&s).expect("parse ok");
        assert_eq!(req.jsonrpc, "2.0");
        // `id` is an `Option` since the server learned to accept notifications;
        // this message HAS an id, so it must arrive as `Some`.
        assert_eq!(req.id, Some(json!(id)));
        assert!(req.method.starts_with('m'));
        // Re-serialize and re-parse for round trip.
        let s2 = serde_json::to_string(&req).unwrap();
        let req2: JsonRpcRequest = serde_json::from_str(&s2).unwrap();
        assert_eq!(req2.method, req.method);
    }
}

#[test]
fn parse_request_garbage_never_panics() {
    let mut g = lcg();
    for _ in 0..100 {
        let len = (g() % 64) as usize;
        let bytes: Vec<u8> = (0..len).map(|_| (g() & 0x7f) as u8).collect();
        let s = String::from_utf8_lossy(&bytes).to_string();
        let _ = parse_request(&s);
    }
}

#[test]
fn parse_request_truncated_errs() {
    assert!(parse_request("").is_err());
    assert!(parse_request("{").is_err());
    assert!(parse_request(r#"{"jsonrpc":"2.0""#).is_err());
}

// ───────────────────────── McpError code mapping ─────────────────────────

#[test]
fn mcp_error_codes_exhaustive() {
    assert_eq!(McpError::ParseError("x".into()).code(), -32700);
    assert_eq!(McpError::MethodNotFound("x".into()).code(), -32601);
    assert_eq!(McpError::InvalidParams("x".into()).code(), -32602);
    assert_eq!(McpError::InternalError("x".into()).code(), -32603);
    assert_eq!(McpError::ToolError("x".into()).code(), -32000);
    assert_eq!(
        McpError::Io(std::io::Error::other("e")).code(),
        -32001
    );
}

#[test]
fn json_rpc_error_constants_and_display() {
    assert_eq!(JsonRpcError::PARSE_ERROR, -32700);
    assert_eq!(JsonRpcError::INVALID_REQUEST, -32600);
    assert_eq!(JsonRpcError::METHOD_NOT_FOUND, -32601);
    assert_eq!(JsonRpcError::INVALID_PARAMS, -32602);
    assert_eq!(JsonRpcError::INTERNAL_ERROR, -32603);
    let e = JsonRpcError::method_not_found("foo");
    assert_eq!(e.code, -32601);
    assert!(e.to_string().contains("foo"));
    assert!(e.to_string().contains("-32601"));
}

// ───────────────────────── JsonRpcResponse ok / err round trip ─────────────────────────

#[test]
fn json_rpc_response_ok_round_trip_50() {
    let mut g = lcg();
    for _ in 0..50 {
        let id = json!(g() as i64);
        let result = json!({"v": g() % 100});
        let resp = JsonRpcResponse::ok(id.clone(), result.clone());
        assert_eq!(resp.id, id);
        assert_eq!(resp.result.as_ref().unwrap(), &result);
        assert!(resp.error.is_none());
        let s = serde_json::to_string(&resp).unwrap();
        let back: JsonRpcResponse = serde_json::from_str(&s).unwrap();
        assert_eq!(back.result.unwrap(), result);
    }
}

#[test]
fn json_rpc_response_err_carries_code() {
    let e = McpError::MethodNotFound("nope".into());
    let r = JsonRpcResponse::err(json!(1), &e);
    assert!(r.result.is_none());
    let je = r.error.unwrap();
    assert_eq!(je.code, -32601);
    assert!(je.message.contains("nope"));
}

// ───────────────────────── ToolResult ─────────────────────────

#[test]
fn tool_result_text() {
    let r = ToolResult::text("hi");
    assert!(!r.is_error);
    assert_eq!(r.content.len(), 1);
    matches!(&r.content[0], ContentBlock::Text { text } if text == "hi");
}

#[test]
fn tool_result_error_flag() {
    let r = ToolResult::error("bad");
    assert!(r.is_error);
}

#[test]
fn tool_result_json_serializes_value() {
    let r = ToolResult::json(&json!({"k":1}));
    if let ContentBlock::Text { text } = &r.content[0] {
        assert!(text.contains("\"k\""));
    } else {
        panic!("expected text");
    }
}

// ───────────────────────── ToolCategory Display ─────────────────────────

#[test]
fn tool_category_display_all_variants() {
    let pairs = [
        (ToolCategory::Project, "project"),
        (ToolCategory::Binary, "binary"),
        (ToolCategory::Analysis, "analysis"),
        (ToolCategory::Disasm, "disasm"),
        (ToolCategory::Decompile, "decompile"),
        (ToolCategory::Debugger, "debugger"),
        (ToolCategory::TimeTravel, "time_travel"),
        (ToolCategory::Instrumentation, "instrumentation"),
        (ToolCategory::Emulation, "emulation"),
        (ToolCategory::Symbolic, "symbolic"),
        (ToolCategory::Diff, "diff"),
        (ToolCategory::Forensics, "forensics"),
        (ToolCategory::Sandbox, "sandbox"),
        (ToolCategory::Yara, "yara"),
        (ToolCategory::Network, "network"),
        (ToolCategory::Mobile, "mobile"),
        (ToolCategory::DotNet, "dotnet"),
        (ToolCategory::ThreatIntel, "threat_intel"),
        (ToolCategory::KnowledgeGraph, "knowledge_graph"),
    ];
    for (c, s) in pairs {
        assert_eq!(c.to_string(), s);
    }
}

#[test]
fn tool_category_eq_consistency() {
    assert_eq!(ToolCategory::Project, ToolCategory::Project);
    assert_ne!(ToolCategory::Project, ToolCategory::Binary);
}

// ───────────────────────── SessionKind Display + Eq ─────────────────────────

#[test]
fn session_kind_display_round_trip() {
    let kinds = [
        (SessionKind::Project, "project"),
        (SessionKind::Debug, "debug"),
        (SessionKind::Forensics, "forensics"),
        (SessionKind::Emulation, "emulation"),
        (SessionKind::Recording, "recording"),
    ];
    for (k, s) in &kinds {
        assert_eq!(k.to_string(), *s);
    }
}

#[test]
fn session_kind_eq_pairs_30() {
    let kinds = [
        SessionKind::Project,
        SessionKind::Debug,
        SessionKind::Forensics,
        SessionKind::Emulation,
        SessionKind::Recording,
    ];
    let mut count = 0;
    for a in &kinds {
        for b in &kinds {
            if a == b {
                assert_eq!(a, b);
            } else {
                assert_ne!(a, b);
            }
            count += 1;
        }
    }
    assert!(count >= 25);
}

// ───────────────────────── SessionDescriptor / SessionManager ─────────────────────────

#[test]
fn session_descriptor_metadata() {
    let mut d = SessionDescriptor::new("s1".into(), SessionKind::Debug, 100);
    d.set_metadata("k", "v");
    assert_eq!(d.get_metadata("k"), Some("v"));
    assert_eq!(d.get_metadata("missing"), None);
}

#[test]
fn session_manager_create_remove_list() {
    let mut sm = SessionManager::new();
    let id1 = sm.create_session(SessionKind::Debug);
    let id2 = sm.create_session(SessionKind::Project);
    assert_ne!(id1, id2);
    assert_eq!(sm.session_count(), 2);
    assert!(sm.get_session(&id1).is_some());
    assert!(sm.remove_session(&id1));
    assert!(!sm.remove_session(&id1));
    assert_eq!(sm.session_count(), 1);
    let dbg_list = sm.sessions_by_kind(&SessionKind::Project);
    assert_eq!(dbg_list.len(), 1);
}

#[test]
fn session_manager_50_create_unique_ids() {
    let mut sm = SessionManager::new();
    let mut ids = std::collections::HashSet::new();
    for _ in 0..50 {
        let id = sm.create_session(SessionKind::Emulation);
        assert!(ids.insert(id));
    }
    assert_eq!(sm.session_count(), 50);
}

#[test]
fn session_manager_get_mut_modifies() {
    let mut sm = SessionManager::new();
    let id = sm.create_session(SessionKind::Debug);
    let s = sm.get_session_mut(&id).unwrap();
    s.set_metadata("k", "v");
    assert_eq!(sm.get_session(&id).unwrap().get_metadata("k"), Some("v"));
}

// ───────────────────────── ResourceProvider URI parsing ─────────────────────────

#[test]
fn resource_provider_make_and_parse_uri() {
    let uri = ResourceProvider::make_binary_uri("bin-0001", "info");
    assert_eq!(uri, "rustre://binary/bin-0001/info");
    let parts = ResourceProvider::parse_uri(&uri).unwrap();
    assert_eq!(parts.scheme, "rustre");
    assert_eq!(parts.entity_type, "binary");
    assert_eq!(parts.entity_id, "bin-0001");
    assert_eq!(parts.view.as_deref(), Some("info"));
}

#[test]
fn resource_provider_parse_no_view() {
    let parts = ResourceProvider::parse_uri("rustre://project/p1").unwrap();
    assert_eq!(parts.view, None);
}

#[test]
fn resource_provider_parse_invalid() {
    assert!(ResourceProvider::parse_uri("no-scheme").is_err());
    assert!(ResourceProvider::parse_uri("rustre://only").is_err());
}

#[test]
fn resource_provider_read_resource_known_types() {
    let bin = ResourceProvider::read_resource("rustre://binary/b1/info").unwrap();
    assert!(bin.is_text());
    assert!(bin.byte_len() > 0);
    let proj = ResourceProvider::read_resource("rustre://project/p1").unwrap();
    assert!(proj.is_text());
}

#[test]
fn resource_provider_read_unknown_entity_err() {
    let r = ResourceProvider::read_resource("rustre://other/x");
    assert!(matches!(r, Err(McpToolError::NotFound(_))));
}

#[test]
fn resource_provider_list_resources() {
    let v = ResourceProvider::list_resources("p1");
    assert_eq!(v.len(), 2);
    assert!(v.iter().all(|r| r.uri.contains("p1")));
}

#[test]
fn resource_provider_uri_fuzz_never_panics() {
    let mut g = lcg();
    for _ in 0..100 {
        let len = (g() % 40) as usize;
        let bytes: Vec<u8> = (0..len).map(|_| ((g() & 0x7f) | 0x20) as u8).collect();
        let s = String::from_utf8_lossy(&bytes).to_string();
        let _ = ResourceProvider::parse_uri(&s);
    }
}

// ───────────────────────── McpResourceContent ─────────────────────────

#[test]
fn mcp_resource_content_text_vs_binary() {
    let t = McpResourceContent::Text("hi".into());
    assert!(t.is_text());
    assert_eq!(t.as_text(), Some("hi"));
    assert_eq!(t.byte_len(), 2);
    let b = McpResourceContent::Binary(vec![1, 2, 3]);
    assert!(!b.is_text());
    assert_eq!(b.as_text(), None);
    assert_eq!(b.byte_len(), 3);
}

// ───────────────────────── ServerConfig builders ─────────────────────────

#[test]
fn server_config_builders_compose() {
    let cfg = ServerConfig::new()
        .with_host("0.0.0.0")
        .with_port(9999)
        .with_max_connections(7)
        .with_auth("tok");
    assert_eq!(cfg.host, "0.0.0.0");
    assert_eq!(cfg.port, 9999);
    assert_eq!(cfg.max_connections, 7);
    assert_eq!(cfg.auth_token.as_deref(), Some("tok"));
    assert_eq!(cfg.listen_addr(), "0.0.0.0:9999");
}

#[test]
fn server_config_default_listen_addr() {
    let cfg = ServerConfig::default();
    assert_eq!(cfg.listen_addr(), "127.0.0.1:3000");
}

#[test]
fn server_config_port_boundaries() {
    let c0 = ServerConfig::new().with_port(0);
    assert_eq!(c0.port, 0);
    let cmax = ServerConfig::new().with_port(u16::MAX);
    assert_eq!(cmax.port, u16::MAX);
}

// ───────────────────────── ConnectionState ─────────────────────────

#[test]
fn connection_state_display_and_eq() {
    assert_eq!(ConnectionState::Connecting.to_string(), "connecting");
    assert_eq!(ConnectionState::Connected.to_string(), "connected");
    assert_eq!(ConnectionState::Authenticated.to_string(), "authenticated");
    assert_eq!(ConnectionState::Disconnected.to_string(), "disconnected");
    assert_ne!(ConnectionState::Connected, ConnectionState::Disconnected);
}

#[test]
fn connection_state_machine_pairs() {
    let states = [
        ConnectionState::Connecting,
        ConnectionState::Connected,
        ConnectionState::Authenticated,
        ConnectionState::Disconnected,
    ];
    let mut hs = std::collections::HashSet::new();
    for s in &states {
        hs.insert(s.to_string());
    }
    assert_eq!(hs.len(), 4);
}

// ───────────────────────── ClientId Hash/Eq ─────────────────────────

#[test]
fn client_id_hash_eq_30_pairs() {
    use std::collections::HashSet;
    let mut g = lcg();
    let mut hs: HashSet<ClientId> = HashSet::new();
    let mut last = None;
    for _ in 0..30 {
        let v = g() & 0xffff;
        let cid = ClientId::new(v);
        assert_eq!(cid.value(), v);
        assert_eq!(cid, ClientId::new(v));
        if let Some(l) = last
            && l != v
        {
            assert_ne!(cid, ClientId::new(l));
        }
        last = Some(v);
        hs.insert(cid);
    }
    assert!(!hs.is_empty());
}

#[test]
fn client_id_display() {
    assert_eq!(ClientId::new(42).to_string(), "client-42");
    assert_eq!(ClientId::new(0).to_string(), "client-0");
}

// ───────────────────────── ServerResponse ─────────────────────────

#[test]
fn server_response_ok_and_err() {
    let cid = ClientId::new(1);
    let ok = ServerResponse::ok(cid, json!(1), json!({"x":1}));
    assert!(!ok.is_error());
    let er = ServerResponse::err(cid, json!(1), "bad");
    assert!(er.is_error());
    assert_eq!(er.error.as_deref(), Some("bad"));
}

// ───────────────────────── build_tool_catalog ─────────────────────────

#[test]
fn build_tool_catalog_nonempty_and_unique() {
    let catalog = build_tool_catalog();
    assert!(catalog.len() >= 10);
    let mut names = std::collections::HashSet::new();
    for t in &catalog {
        assert!(!t.name.is_empty());
        assert!(!t.description.is_empty());
        assert!(t.input_schema.is_object());
        assert!(names.insert(t.name.clone()), "dup tool: {}", t.name);
    }
}

#[test]
fn tool_def_to_tool_definition_round_trip() {
    let def = McpToolDef::new(
        "n",
        "d",
        json!({"type":"object"}),
        ToolCategory::Analysis,
    );
    let td = def.to_tool_definition();
    assert_eq!(td.name, "n");
    assert_eq!(td.description, "d");
    assert_eq!(td.input_schema, td.parameters);
}

// ───────────────────────── ToolExecutor ─────────────────────────

struct FixedHandler {
    n: &'static str,
    out: Value,
}
impl McpToolHandler for FixedHandler {
    fn name(&self) -> &str {
        self.n
    }
    fn execute(&self, _params: Value) -> Result<Value, McpToolError> {
        Ok(self.out.clone())
    }
}

struct FailHandler;
impl McpToolHandler for FailHandler {
    fn name(&self) -> &str {
        "fail"
    }
    fn execute(&self, _p: Value) -> Result<Value, McpToolError> {
        Err(McpToolError::ExecutionFailed("nope".into()))
    }
}

#[test]
fn tool_executor_register_and_dispatch() {
    let mut ex = ToolExecutor::new();
    ex.register(Box::new(FixedHandler {
        n: "alpha",
        out: json!(1),
    }));
    ex.register(Box::new(FixedHandler {
        n: "beta",
        out: json!("hi"),
    }));
    assert_eq!(ex.tool_count(), 2);
    let mut names = ex.tool_names();
    names.sort();
    assert_eq!(names, vec!["alpha", "beta"]);
    assert_eq!(ex.execute("alpha", json!({})).unwrap(), json!(1));
    assert!(matches!(
        ex.execute("missing", json!({})),
        Err(McpToolError::NotFound(_))
    ));
}

#[test]
fn tool_executor_propagates_handler_error() {
    let mut ex = ToolExecutor::new();
    ex.register(Box::new(FailHandler));
    assert!(matches!(
        ex.execute("fail", json!({})),
        Err(McpToolError::ExecutionFailed(_))
    ));
}

#[test]
fn tool_executor_default_empty() {
    let ex = ToolExecutor::default();
    assert_eq!(ex.tool_count(), 0);
}

// ───────────────────────── MockTransport ─────────────────────────

#[tokio::test]
async fn mock_transport_round_trip() {
    let mut t = MockTransport::new();
    t.enqueue("msg1");
    t.enqueue("msg2");
    assert_eq!(t.recv().await.unwrap().as_deref(), Some("msg1"));
    t.send("reply".into()).await.unwrap();
    let drained = t.drain_outbox();
    assert_eq!(drained, vec!["reply".to_string()]);
    assert_eq!(t.recv().await.unwrap().as_deref(), Some("msg2"));
    assert_eq!(t.recv().await.unwrap(), None);
}

// ───────────────────────── BinaryRegistry ─────────────────────────

#[test]
fn binary_registry_empty_state() {
    let r = BinaryRegistry::new();
    assert_eq!(r.list_ids().len(), 0);
    assert!(r.get("nope").is_none());
    assert!(r.view_id_for("nope").is_none());
}

#[test]
fn binary_registry_load_nonexistent_path_errs() {
    let mut r = BinaryRegistry::new();
    let err = r.load_file("/this/path/does/not/exist/xyz_blitz2");
    assert!(matches!(err, Err(McpToolError::ExecutionFailed(_))));
}

#[test]
fn binary_registry_load_unknown_format() {
    // write a tiny non-PE/non-ELF file to a temp path
    let tmp = std::env::temp_dir().join("blitz2_unknown.bin");
    std::fs::write(&tmp, b"not-a-binary-just-text").unwrap();
    let mut r = BinaryRegistry::new();
    let id = r.load_file(tmp.to_str().unwrap()).unwrap();
    let (_data, info) = r.get(&id).unwrap();
    assert_eq!(info.format, "Unknown");
    assert_eq!(info.arch, "unknown");
    assert!(r.view_id_for(&id).is_some());
    assert!(r.list_ids().contains(&id));
    let _ = std::fs::remove_file(&tmp);
}

#[test]
fn binary_registry_next_session_id_format_and_unique() {
    let mut r = BinaryRegistry::new();
    let mut ids = std::collections::HashSet::new();
    for _ in 0..10 {
        let id = r.next_session_id();
        assert!(id.starts_with("dbg-"));
        assert_eq!(id.len(), 8); // dbg- + 4 digits
        assert!(ids.insert(id));
    }
}

// ───────────────────────── Send/Sync stress ─────────────────────────

fn _assert_send_sync<T: Send + Sync>() {}

#[test]
fn types_are_send_sync() {
    _assert_send_sync::<ClientId>();
    _assert_send_sync::<ServerConfig>();
    _assert_send_sync::<ConnectionState>();
    _assert_send_sync::<ToolCategory>();
    _assert_send_sync::<SessionKind>();
    _assert_send_sync::<McpToolDef>();
}

#[test]
fn shared_binary_registry_threaded_stress() {
    let reg = Arc::new(Mutex::new(BinaryRegistry::new()));
    let mut handles = Vec::new();
    for t in 0..4 {
        let r = Arc::clone(&reg);
        handles.push(std::thread::spawn(move || {
            for i in 0..100 {
                let mut g = r.lock().unwrap();
                let s = g.next_session_id();
                assert!(s.starts_with("dbg-"));
                if i == 0 {
                    let _ = g.list_ids();
                }
                let _ = t;
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
    let total = reg.lock().unwrap().sessions.len();
    // sessions HashMap is separate; we only advanced session_counter.
    // Verify counter advanced 4*100 = 400 by checking last session id.
    let last = reg.lock().unwrap().next_session_id();
    assert_eq!(last, "dbg-0401");
    let _ = total;
}

#[test]
fn session_manager_threaded_create_via_mutex() {
    let sm = Arc::new(Mutex::new(SessionManager::new()));
    let mut handles = Vec::new();
    for _ in 0..4 {
        let s = Arc::clone(&sm);
        handles.push(std::thread::spawn(move || {
            for _ in 0..100 {
                let _id = s.lock().unwrap().create_session(SessionKind::Debug);
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
    assert_eq!(sm.lock().unwrap().session_count(), 400);
}

// ───────────────────────── McpResource basic ─────────────────────────

#[test]
fn mcp_resource_constructor_fields() {
    let r = McpResource::new("u", "n", "d", "m");
    assert_eq!(r.uri, "u");
    assert_eq!(r.name, "n");
    assert_eq!(r.description, "d");
    assert_eq!(r.mime_type, "m");
}
