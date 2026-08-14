//! Exhaustive black-box test suite for rustre-mcp-server.
//!
//! Targets: JSON-RPC parsing, helper validators, hex-addr parser,
//! ToolExecutor dispatch, SessionManager, ResourceProvider URI parsing,
//! ServerConfig builders, McpError code mapping, tool catalog,
//! MockTransport, BinaryRegistry loaders.

use rustre_mcp_server::{
    BinaryRegistry, ClientId, ConnectionState, ContentBlock, JsonRpcError, JsonRpcResponse,
    McpError, McpResource, McpResourceContent, McpToolDef, McpToolError, McpToolHandler,
    McpTransportTrait, MockTransport, ResourceProvider, ServerConfig, ServerError, ServerResponse,
    SessionDescriptor, SessionKind, SessionManager, ToolCategory, ToolDefinition, ToolExecutor,
    ToolResult, build_tool_catalog, parse_hex_addr, parse_request, require_number, require_string,
    validate_required_strings,
};
use serde_json::{Value, json};

// ───────────────────────── parse_hex_addr ─────────────────────────

#[test]
fn hex_addr_basic_lower_prefix() {
    assert_eq!(parse_hex_addr("0x401000").unwrap(), 0x40_1000);
}
#[test]
fn hex_addr_upper_prefix() {
    assert_eq!(parse_hex_addr("0X40").unwrap(), 0x40);
}
#[test]
fn hex_addr_no_prefix() {
    assert_eq!(parse_hex_addr("ff").unwrap(), 0xff);
}
#[test]
fn hex_addr_zero() {
    assert_eq!(parse_hex_addr("0x0").unwrap(), 0);
}
#[test]
fn hex_addr_u64_max() {
    assert_eq!(parse_hex_addr("ffffffffffffffff").unwrap(), u64::MAX);
}
#[test]
fn hex_addr_overflow_errs() {
    assert!(parse_hex_addr("0x1ffffffffffffffff").is_err());
}
#[test]
fn hex_addr_garbage_errs() {
    assert!(parse_hex_addr("zzz").is_err());
}
#[test]
fn hex_addr_empty_errs() {
    assert!(parse_hex_addr("").is_err());
}
#[test]
fn hex_addr_just_prefix_errs() {
    assert!(parse_hex_addr("0x").is_err());
}

// ───────────────────────── validate_required_strings ─────────────────────────

#[test]
fn validate_ok_when_all_present() {
    let v = json!({"a": "x", "b": 7});
    assert!(validate_required_strings(&v, &["a", "b"]).is_ok());
}
#[test]
fn validate_missing_key_errs() {
    let v = json!({"a": "x"});
    let e = validate_required_strings(&v, &["a", "b"]).unwrap_err();
    assert!(matches!(e, McpToolError::InvalidParams(_)));
}
#[test]
fn validate_wrong_type_errs() {
    let v = json!({"a": [1, 2]});
    assert!(validate_required_strings(&v, &["a"]).is_err());
}
#[test]
fn validate_bool_rejected() {
    let v = json!({"a": true});
    assert!(validate_required_strings(&v, &["a"]).is_err());
}
#[test]
fn validate_null_rejected() {
    let v = json!({"a": null});
    assert!(validate_required_strings(&v, &["a"]).is_err());
}
#[test]
fn validate_empty_required_ok() {
    assert!(validate_required_strings(&json!({}), &[]).is_ok());
}

// ───────────────────────── require_string / require_number ─────────────────────────

#[test]
fn require_string_ok() {
    assert_eq!(require_string(&json!({"k":"v"}), "k").unwrap(), "v");
}
#[test]
fn require_string_missing() {
    assert!(require_string(&json!({}), "k").is_err());
}
#[test]
fn require_string_wrong_type() {
    assert!(require_string(&json!({"k": 1}), "k").is_err());
}
#[test]
fn require_number_ok() {
    assert_eq!(require_number(&json!({"k": 42}), "k").unwrap(), 42);
}
#[test]
fn require_number_negative_rejected() {
    assert!(require_number(&json!({"k": -1}), "k").is_err());
}
#[test]
fn require_number_string_rejected() {
    assert!(require_number(&json!({"k": "1"}), "k").is_err());
}

// ───────────────────────── parse_request / JsonRpc ─────────────────────────

#[test]
fn parse_request_ok() {
    let r = parse_request(r#"{"jsonrpc":"2.0","id":1,"method":"x","params":{}}"#).unwrap();
    assert_eq!(r.method, "x");
    // `Some`: a request carries an id (a notification would be `None`).
    assert_eq!(r.id, Some(json!(1)));
}
#[test]
fn parse_request_bad_json() {
    let e = parse_request("not json").unwrap_err();
    assert!(matches!(e, McpError::ParseError(_)));
}
#[test]
fn parse_request_missing_method() {
    // "method" is required; should fail
    let r = parse_request(r#"{"jsonrpc":"2.0","id":1}"#);
    assert!(r.is_err());
}

#[test]
fn jsonrpc_error_codes() {
    assert_eq!(JsonRpcError::PARSE_ERROR, -32700);
    assert_eq!(JsonRpcError::INVALID_REQUEST, -32600);
    assert_eq!(JsonRpcError::METHOD_NOT_FOUND, -32601);
    assert_eq!(JsonRpcError::INVALID_PARAMS, -32602);
    assert_eq!(JsonRpcError::INTERNAL_ERROR, -32603);
}

#[test]
fn jsonrpc_error_constructors() {
    let mnf = JsonRpcError::method_not_found("foo");
    assert_eq!(mnf.code, -32601);
    assert!(mnf.message.contains("foo"));
    let p = JsonRpcError::parse_error();
    assert_eq!(p.code, -32700);
    let i = JsonRpcError::internal("oops");
    assert_eq!(i.code, -32603);
    assert!(i.message.contains("oops"));
}

#[test]
fn jsonrpc_error_display() {
    let e = JsonRpcError::new(-1, "bad");
    assert_eq!(format!("{e}"), "[-1] bad");
}

#[test]
fn jsonrpc_response_ok_and_err_roundtrip() {
    let ok = JsonRpcResponse::ok(json!(1), json!({"x":1}));
    let s = serde_json::to_string(&ok).unwrap();
    assert!(s.contains("\"jsonrpc\":\"2.0\""));
    assert!(s.contains("\"result\""));
    assert!(!s.contains("\"error\""));

    let err = JsonRpcResponse::err(json!(2), &McpError::ParseError("p".into()));
    let s2 = serde_json::to_string(&err).unwrap();
    assert!(s2.contains("\"error\""));
    assert!(!s2.contains("\"result\""));
}

// ───────────────────────── McpError codes ─────────────────────────

#[test]
fn mcperror_codes() {
    assert_eq!(McpError::ParseError("x".into()).code(), -32700);
    assert_eq!(McpError::MethodNotFound("x".into()).code(), -32601);
    assert_eq!(McpError::InvalidParams("x".into()).code(), -32602);
    assert_eq!(McpError::InternalError("x".into()).code(), -32603);
    assert_eq!(McpError::ToolError("x".into()).code(), -32000);
    let io = McpError::Io(std::io::Error::other("e"));
    assert_eq!(io.code(), -32001);
}

#[test]
fn mcptoolerror_to_mcperror() {
    let m: McpError = McpToolError::NotFound("x".into()).into();
    assert!(matches!(m, McpError::ToolError(_)));
}

// ───────────────────────── ToolResult / ContentBlock ─────────────────────────

#[test]
fn toolresult_text_constructors() {
    let t = ToolResult::text("hi");
    assert!(!t.is_error);
    assert_eq!(t.content.len(), 1);
    let e = ToolResult::error("bad");
    assert!(e.is_error);
    let j = ToolResult::json(&json!({"a":1}));
    if let ContentBlock::Text { text } = &j.content[0] {
        assert!(text.contains("\"a\""));
    } else {
        panic!("expected text block");
    }
}

#[test]
fn content_block_serde_tag() {
    let cb = ContentBlock::Text { text: "x".into() };
    let s = serde_json::to_string(&cb).unwrap();
    assert!(s.contains("\"type\":\"text\""));
    let cb2 = ContentBlock::Image {
        data: "d".into(),
        mime_type: "image/png".into(),
    };
    let s2 = serde_json::to_string(&cb2).unwrap();
    assert!(s2.contains("\"type\":\"image\""));
}

// ───────────────────────── ToolCategory display ─────────────────────────

#[test]
fn tool_category_display_round_trip() {
    let pairs = [
        (ToolCategory::Project, "project"),
        (ToolCategory::Binary, "binary"),
        (ToolCategory::Analysis, "analysis"),
        (ToolCategory::Disasm, "disasm"),
        (ToolCategory::Decompile, "decompile"),
        (ToolCategory::Debugger, "debugger"),
        (ToolCategory::TimeTravel, "time_travel"),
        (ToolCategory::Yara, "yara"),
        (ToolCategory::KnowledgeGraph, "knowledge_graph"),
    ];
    for (c, s) in pairs {
        assert_eq!(format!("{c}"), s);
    }
}

// ───────────────────────── McpToolDef ─────────────────────────

#[test]
fn mcptooldef_to_tool_definition() {
    let d = McpToolDef::new("n", "desc", json!({"a":1}), ToolCategory::Project);
    let td: ToolDefinition = d.to_tool_definition();
    assert_eq!(td.name, "n");
    assert_eq!(td.description, "desc");
    assert_eq!(td.input_schema, td.parameters);
}

// ───────────────────────── ToolExecutor ─────────────────────────

struct Echo;
impl McpToolHandler for Echo {
    fn name(&self) -> &str {
        "echo"
    }
    fn execute(&self, params: Value) -> Result<Value, McpToolError> {
        Ok(params)
    }
}
struct Boom;
impl McpToolHandler for Boom {
    fn name(&self) -> &str {
        "boom"
    }
    fn execute(&self, _p: Value) -> Result<Value, McpToolError> {
        Err(McpToolError::ExecutionFailed("nope".into()))
    }
}

#[test]
fn tool_executor_register_and_dispatch() {
    let mut ex = ToolExecutor::new();
    ex.register(Box::new(Echo));
    ex.register(Box::new(Boom));
    assert_eq!(ex.tool_count(), 2);
    let mut names = ex.tool_names();
    names.sort();
    assert_eq!(names, vec!["boom", "echo"]);
    let out = ex.execute("echo", json!({"x":1})).unwrap();
    assert_eq!(out, json!({"x":1}));
    let err = ex.execute("missing", json!(null)).unwrap_err();
    assert!(matches!(err, McpToolError::NotFound(_)));
    let err2 = ex.execute("boom", json!(null)).unwrap_err();
    assert!(matches!(err2, McpToolError::ExecutionFailed(_)));
}

#[test]
fn tool_executor_default_empty() {
    let ex = ToolExecutor::default();
    assert_eq!(ex.tool_count(), 0);
}

// ───────────────────────── SessionManager ─────────────────────────

#[test]
fn session_manager_lifecycle() {
    let mut sm = SessionManager::new();
    assert_eq!(sm.session_count(), 0);
    let id1 = sm.create_session(SessionKind::Debug);
    let id2 = sm.create_session(SessionKind::Project);
    assert_ne!(id1, id2);
    assert_eq!(sm.session_count(), 2);
    assert!(sm.get_session(&id1).is_some());
    sm.get_session_mut(&id1)
        .unwrap()
        .set_metadata("k", "v");
    assert_eq!(sm.get_session(&id1).unwrap().get_metadata("k"), Some("v"));
    assert_eq!(sm.sessions_by_kind(&SessionKind::Debug).len(), 1);
    assert_eq!(sm.sessions_by_kind(&SessionKind::Project).len(), 1);
    assert_eq!(sm.sessions_by_kind(&SessionKind::Forensics).len(), 0);
    assert!(sm.remove_session(&id1));
    assert!(!sm.remove_session(&id1));
    assert_eq!(sm.session_count(), 1);
    assert_eq!(sm.list_sessions().len(), 1);
}

#[test]
fn session_kind_display() {
    assert_eq!(format!("{}", SessionKind::Project), "project");
    assert_eq!(format!("{}", SessionKind::Debug), "debug");
    assert_eq!(format!("{}", SessionKind::Forensics), "forensics");
    assert_eq!(format!("{}", SessionKind::Emulation), "emulation");
    assert_eq!(format!("{}", SessionKind::Recording), "recording");
}

#[test]
fn session_descriptor_metadata_get_missing() {
    let s = SessionDescriptor::new("a".into(), SessionKind::Debug, 0);
    assert!(s.get_metadata("k").is_none());
}

// ───────────────────────── McpResourceContent ─────────────────────────

#[test]
fn resource_content_text_and_binary() {
    let t = McpResourceContent::Text("hello".into());
    assert!(t.is_text());
    assert_eq!(t.as_text(), Some("hello"));
    assert_eq!(t.byte_len(), 5);
    let b = McpResourceContent::Binary(vec![1, 2, 3]);
    assert!(!b.is_text());
    assert!(b.as_text().is_none());
    assert_eq!(b.byte_len(), 3);
}

// ───────────────────────── ResourceProvider ─────────────────────────

#[test]
fn resource_provider_parse_uri_ok() {
    let p = ResourceProvider::parse_uri("rustre://binary/bin-0001/info").unwrap();
    assert_eq!(p.scheme, "rustre");
    assert_eq!(p.entity_type, "binary");
    assert_eq!(p.entity_id, "bin-0001");
    assert_eq!(p.view.as_deref(), Some("info"));
}
#[test]
fn resource_provider_parse_uri_no_view() {
    let p = ResourceProvider::parse_uri("rustre://project/foo").unwrap();
    assert!(p.view.is_none());
}
#[test]
fn resource_provider_parse_uri_no_scheme() {
    assert!(ResourceProvider::parse_uri("nopath").is_err());
}
#[test]
fn resource_provider_parse_uri_missing_entity_id() {
    assert!(ResourceProvider::parse_uri("rustre://binary").is_err());
}
#[test]
fn resource_provider_make_uri_round_trip() {
    let uri = ResourceProvider::make_binary_uri("bin-1", "hex");
    let p = ResourceProvider::parse_uri(&uri).unwrap();
    assert_eq!(p.entity_id, "bin-1");
    assert_eq!(p.view.as_deref(), Some("hex"));
}
#[test]
fn resource_provider_list_resources() {
    let r = ResourceProvider::list_resources("proj-x");
    assert!(!r.is_empty());
    assert!(r.iter().any(|x| x.uri.contains("proj-x")));
}
#[test]
fn resource_provider_read_binary_stub() {
    let c = ResourceProvider::read_resource("rustre://binary/bin-1/info").unwrap();
    assert!(c.is_text());
    assert!(c.as_text().unwrap().contains("bin-1"));
}
#[test]
fn resource_provider_read_project_stub() {
    let c = ResourceProvider::read_resource("rustre://project/p1").unwrap();
    assert!(c.as_text().unwrap().contains("p1"));
}
#[test]
fn resource_provider_read_unknown_type() {
    let e = ResourceProvider::read_resource("rustre://weird/x").unwrap_err();
    assert!(matches!(e, McpToolError::NotFound(_)));
}
#[test]
fn resource_provider_read_bad_uri() {
    let e = ResourceProvider::read_resource("garbage").unwrap_err();
    assert!(matches!(e, McpToolError::InvalidParams(_)));
}

// ───────────────────────── ServerConfig ─────────────────────────

#[test]
fn server_config_defaults() {
    let c = ServerConfig::new();
    assert_eq!(c.host, "127.0.0.1");
    assert_eq!(c.port, 3000);
    assert_eq!(c.max_connections, 100);
    assert!(c.auth_token.is_none());
    assert_eq!(c.listen_addr(), "127.0.0.1:3000");
}
#[test]
fn server_config_builders() {
    let c = ServerConfig::default()
        .with_host("0.0.0.0")
        .with_port(8080)
        .with_max_connections(5)
        .with_auth("tok");
    assert_eq!(c.host, "0.0.0.0");
    assert_eq!(c.port, 8080);
    assert_eq!(c.max_connections, 5);
    assert_eq!(c.auth_token.as_deref(), Some("tok"));
    assert_eq!(c.listen_addr(), "0.0.0.0:8080");
}

// ───────────────────────── ClientId / ConnectionState ─────────────────────────

#[test]
fn client_id_display_and_value() {
    let c = ClientId::new(42);
    assert_eq!(c.value(), 42);
    assert_eq!(format!("{c}"), "client-42");
}
#[test]
fn client_id_eq_hash() {
    use std::collections::HashSet;
    let mut s = HashSet::new();
    s.insert(ClientId::new(1));
    s.insert(ClientId::new(1));
    s.insert(ClientId::new(2));
    assert_eq!(s.len(), 2);
}
#[test]
fn connection_state_display() {
    assert_eq!(format!("{}", ConnectionState::Connecting), "connecting");
    assert_eq!(format!("{}", ConnectionState::Connected), "connected");
    assert_eq!(
        format!("{}", ConnectionState::Authenticated),
        "authenticated"
    );
    assert_eq!(format!("{}", ConnectionState::Disconnected), "disconnected");
}

// ───────────────────────── ServerResponse ─────────────────────────

#[test]
fn server_response_ok_and_err() {
    let ok = ServerResponse::ok(ClientId::new(1), json!(7), json!("done"));
    assert!(!ok.is_error());
    let err = ServerResponse::err(ClientId::new(2), json!(7), "bad");
    assert!(err.is_error());
    assert_eq!(err.error.as_deref(), Some("bad"));
}

// ───────────────────────── ServerError display ─────────────────────────

#[test]
fn server_error_display() {
    let e = ServerError::Bind("x".into());
    assert!(format!("{e}").contains("bind"));
    let e2 = ServerError::Timeout("t".into());
    assert!(format!("{e2}").contains("timeout"));
}

// ───────────────────────── MockTransport ─────────────────────────

#[tokio::test]
async fn mock_transport_round_trip() {
    let mut t = MockTransport::new();
    t.enqueue("hello");
    t.enqueue("world");
    let a = t.recv().await.unwrap();
    let b = t.recv().await.unwrap();
    let c = t.recv().await.unwrap();
    assert_eq!(a.as_deref(), Some("hello"));
    assert_eq!(b.as_deref(), Some("world"));
    assert!(c.is_none());
    t.send("out1".into()).await.unwrap();
    t.send("out2".into()).await.unwrap();
    let drained = t.drain_outbox();
    assert_eq!(drained, vec!["out1", "out2"]);
    assert!(t.drain_outbox().is_empty());
}

// ───────────────────────── McpResource ─────────────────────────

#[test]
fn mcp_resource_new_serde() {
    let r = McpResource::new("u", "n", "d", "application/json");
    let s = serde_json::to_string(&r).unwrap();
    assert!(s.contains("\"uri\":\"u\""));
    assert!(s.contains("\"mime_type\":\"application/json\""));
}

// ───────────────────────── build_tool_catalog ─────────────────────────

#[test]
fn tool_catalog_nonempty_and_unique_names() {
    let cat = build_tool_catalog();
    assert!(
        cat.len() >= 30,
        "expected many tools, got {}",
        cat.len()
    );
    let mut names: Vec<&str> = cat.iter().map(|t| t.name.as_str()).collect();
    names.sort();
    let n = names.len();
    names.dedup();
    assert_eq!(
        names.len(),
        n,
        "duplicate tool names in catalog"
    );
}
#[test]
fn tool_catalog_well_known_tools_present() {
    let cat = build_tool_catalog();
    let names: std::collections::HashSet<&str> =
        cat.iter().map(|t| t.name.as_str()).collect();
    for expected in [
        "project.open",
        "binary.info",
        "binary.hexdump",
        "analyze.full",
        "disasm.at",
        "decompile.function",
        "debug.set_breakpoint",
        "yara.compile",
    ] {
        assert!(names.contains(expected), "missing tool: {expected}");
    }
}
#[test]
fn tool_catalog_schemas_are_objects_with_required() {
    let cat = build_tool_catalog();
    for tool in &cat {
        assert_eq!(
            tool.input_schema["type"], "object",
            "tool {} schema is not object",
            tool.name
        );
        assert!(
            tool.input_schema.get("properties").is_some(),
            "tool {} missing properties",
            tool.name
        );
    }
}

// ───────────────────────── BinaryRegistry ─────────────────────────

#[test]
fn binary_registry_new_empty() {
    let r = BinaryRegistry::new();
    assert!(r.list_ids().is_empty());
    assert!(r.get("nope").is_none());
    assert!(r.view_id_for("nope").is_none());
}

#[test]
fn binary_registry_load_nonexistent_file_errs() {
    let mut r = BinaryRegistry::new();
    let e = r
        .load_file("Z:/definitely/does/not/exist/binary.bin")
        .unwrap_err();
    assert!(matches!(e, McpToolError::ExecutionFailed(_)));
}

#[test]
fn binary_registry_session_id_format_and_unique() {
    let mut r = BinaryRegistry::new();
    let a = r.next_session_id();
    let b = r.next_session_id();
    assert_eq!(a, "dbg-0001");
    assert_eq!(b, "dbg-0002");
    assert_ne!(a, b);
}

#[test]
fn binary_registry_load_unknown_format_succeeds_as_unknown() {
    // Write a short non-PE/non-ELF file to a tempfile and load it.
    let tmp = std::env::temp_dir().join("rustre_mcp_blitz_unknown.bin");
    std::fs::write(&tmp, b"NOT_A_BINARY_AT_ALL_JUST_BYTES").unwrap();
    let mut r = BinaryRegistry::new();
    let id = r.load_file(tmp.to_str().unwrap()).unwrap();
    let (data, info) = r.get(&id).unwrap();
    assert_eq!(data.len(), 30);
    assert_eq!(info.format, "Unknown");
    assert_eq!(info.bits, 0);
    assert_eq!(info.image_base, 0);
    assert_eq!(info.entry_point, 0);
    assert_eq!(info.size, 30);
    assert!(info.sections.is_empty());
    assert!(!info.is_dll);
    assert!(!info.is_dotnet);
    assert_eq!(info.sha256.len(), 64); // hex sha256
    assert_eq!(r.list_ids().len(), 1);
    assert!(r.view_id_for(&id).is_some());
    let _ = std::fs::remove_file(&tmp);
}

#[test]
fn binary_registry_load_empty_file_no_panic() {
    let tmp = std::env::temp_dir().join("rustre_mcp_blitz_empty.bin");
    std::fs::write(&tmp, b"").unwrap();
    let mut r = BinaryRegistry::new();
    let id = r.load_file(tmp.to_str().unwrap()).unwrap();
    let (_, info) = r.get(&id).unwrap();
    assert_eq!(info.size, 0);
    assert_eq!(info.format, "Unknown");
    let _ = std::fs::remove_file(&tmp);
}

#[test]
fn binary_registry_load_short_mz_no_panic() {
    // Begins with "MZ" but is shorter than 0x40 -> should fall through to Unknown
    let tmp = std::env::temp_dir().join("rustre_mcp_blitz_shortmz.bin");
    std::fs::write(&tmp, b"MZ short").unwrap();
    let mut r = BinaryRegistry::new();
    let id = r.load_file(tmp.to_str().unwrap()).unwrap();
    let (_, info) = r.get(&id).unwrap();
    assert_eq!(info.format, "Unknown");
    let _ = std::fs::remove_file(&tmp);
}

#[test]
fn binary_registry_ids_are_sequential() {
    let tmp = std::env::temp_dir().join("rustre_mcp_blitz_seq.bin");
    std::fs::write(&tmp, b"AAAA").unwrap();
    let mut r = BinaryRegistry::new();
    let a = r.load_file(tmp.to_str().unwrap()).unwrap();
    let b = r.load_file(tmp.to_str().unwrap()).unwrap();
    assert_eq!(a, "bin-0001");
    assert_eq!(b, "bin-0002");
    assert_ne!(r.view_id_for(&a), r.view_id_for(&b));
    let _ = std::fs::remove_file(&tmp);
}
