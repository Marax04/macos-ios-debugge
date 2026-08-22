//! MCP wrappers for the rustre-net_proxy crate.
//! Extracted from `wire_tools.rs` by `workflow_split_wire_tools`.

use rustre_mcp_server::{McpError, ToolDefinition, ToolHandler, ToolResult};
use serde_json::{json, Value};
use async_trait::async_trait;
use crate::{args_to_bytes, hex_encode};

pub struct NetProxyHttpRequestLineParseTool;
impl NetProxyHttpRequestLineParseTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "net_proxy_http_request_line_parse".to_string(),
            description: "Parse an HTTP request line via rustre_net_proxy::HttpRequestLine::parse.".to_string(),
            input_schema: json!({ "type":"object", "properties":{ "line":{"type":"string"}}, "required":["line"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait::async_trait]
impl ToolHandler for NetProxyHttpRequestLineParseTool {
    async fn call(&self, args: Value) -> Result<ToolResult, rustre_mcp_server::McpError> {
        let line = args.get("line").and_then(|v| v.as_str()).unwrap_or("");
        match rustre_net_proxy::HttpRequestLine::parse(line) {
            Ok(r) => Ok(ToolResult::text(json!({
                "method": r.method.to_string(), "uri": r.uri, "version": r.version,
                "is_http11": r.is_http11(), "is_http2": r.is_http2(),
                "source": "rustre_net_proxy::HttpRequestLine::parse"
            }).to_string())),
            Err(e) => Err(rustre_mcp_server::McpError::InvalidParams(e.to_string())),
        }
    }
}

pub struct NetProxyHttpRequestLineIsHttp11Tool;
impl NetProxyHttpRequestLineIsHttp11Tool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "net_proxy_http_request_line_is_http11".to_string(),
            description: "Return true if parsed request line is HTTP/1.1.".to_string(),
            input_schema: json!({ "type":"object", "properties":{ "line":{"type":"string"}}, "required":["line"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait::async_trait]
impl ToolHandler for NetProxyHttpRequestLineIsHttp11Tool {
    async fn call(&self, args: Value) -> Result<ToolResult, rustre_mcp_server::McpError> {
        let line = args.get("line").and_then(|v| v.as_str()).unwrap_or("");
        let r = rustre_net_proxy::HttpRequestLine::parse(line)
            .map_err(|e| rustre_mcp_server::McpError::InvalidParams(e.to_string()))?;
        Ok(ToolResult::text(json!({ "is_http11": r.is_http11(),
            "source": "rustre_net_proxy::HttpRequestLine::is_http11" }).to_string()))
    }
}

pub struct NetProxyHttpRequestLineIsHttp2Tool;
impl NetProxyHttpRequestLineIsHttp2Tool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "net_proxy_http_request_line_is_http2".to_string(),
            description: "Return true if parsed request line is HTTP/2.".to_string(),
            input_schema: json!({ "type":"object", "properties":{ "line":{"type":"string"}}, "required":["line"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait::async_trait]
impl ToolHandler for NetProxyHttpRequestLineIsHttp2Tool {
    async fn call(&self, args: Value) -> Result<ToolResult, rustre_mcp_server::McpError> {
        let line = args.get("line").and_then(|v| v.as_str()).unwrap_or("");
        let r = rustre_net_proxy::HttpRequestLine::parse(line)
            .map_err(|e| rustre_mcp_server::McpError::InvalidParams(e.to_string()))?;
        Ok(ToolResult::text(json!({ "is_http2": r.is_http2(),
            "source": "rustre_net_proxy::HttpRequestLine::is_http2" }).to_string()))
    }
}

pub struct NetProxyHttpStatusLineParseTool;
impl NetProxyHttpStatusLineParseTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "net_proxy_http_status_line_parse".to_string(),
            description: "Parse an HTTP status line via rustre_net_proxy::HttpStatusLine::parse.".to_string(),
            input_schema: json!({ "type":"object", "properties":{ "line":{"type":"string"}}, "required":["line"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait::async_trait]
impl ToolHandler for NetProxyHttpStatusLineParseTool {
    async fn call(&self, args: Value) -> Result<ToolResult, rustre_mcp_server::McpError> {
        let line = args.get("line").and_then(|v| v.as_str()).unwrap_or("");
        match rustre_net_proxy::HttpStatusLine::parse(line) {
            Ok(s) => Ok(ToolResult::text(json!({
                "version": s.version, "code": s.code, "reason": s.reason,
                "source": "rustre_net_proxy::HttpStatusLine::parse"
            }).to_string())),
            Err(e) => Err(rustre_mcp_server::McpError::InvalidParams(e.to_string())),
        }
    }
}

pub struct NetProxyHttpStatusLineIsSuccessTool;
impl NetProxyHttpStatusLineIsSuccessTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "net_proxy_http_status_line_is_success".to_string(),
            description: "Return true if the parsed HTTP status line has a 2xx code.".to_string(),
            input_schema: json!({ "type":"object", "properties":{ "line":{"type":"string"}}, "required":["line"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait::async_trait]
impl ToolHandler for NetProxyHttpStatusLineIsSuccessTool {
    async fn call(&self, args: Value) -> Result<ToolResult, rustre_mcp_server::McpError> {
        let line = args.get("line").and_then(|v| v.as_str()).unwrap_or("");
        let s = rustre_net_proxy::HttpStatusLine::parse(line)
            .map_err(|e| rustre_mcp_server::McpError::InvalidParams(e.to_string()))?;
        Ok(ToolResult::text(json!({ "is_success": s.is_success(), "code": s.code,
            "source": "rustre_net_proxy::HttpStatusLine::is_success" }).to_string()))
    }
}

pub struct NetProxyHttpStatusLineIsRedirectTool;
impl NetProxyHttpStatusLineIsRedirectTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "net_proxy_http_status_line_is_redirect".to_string(),
            description: "Return true if the parsed HTTP status line has a 3xx code.".to_string(),
            input_schema: json!({ "type":"object", "properties":{ "line":{"type":"string"}}, "required":["line"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait::async_trait]
impl ToolHandler for NetProxyHttpStatusLineIsRedirectTool {
    async fn call(&self, args: Value) -> Result<ToolResult, rustre_mcp_server::McpError> {
        let line = args.get("line").and_then(|v| v.as_str()).unwrap_or("");
        let s = rustre_net_proxy::HttpStatusLine::parse(line)
            .map_err(|e| rustre_mcp_server::McpError::InvalidParams(e.to_string()))?;
        Ok(ToolResult::text(json!({ "is_redirect": s.is_redirect(), "code": s.code,
            "source": "rustre_net_proxy::HttpStatusLine::is_redirect" }).to_string()))
    }
}

pub struct NetProxyHttpStatusLineIsClientErrorTool;
impl NetProxyHttpStatusLineIsClientErrorTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "net_proxy_http_status_line_is_client_error".to_string(),
            description: "Return true if the parsed HTTP status line has a 4xx code.".to_string(),
            input_schema: json!({ "type":"object", "properties":{ "line":{"type":"string"}}, "required":["line"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait::async_trait]
impl ToolHandler for NetProxyHttpStatusLineIsClientErrorTool {
    async fn call(&self, args: Value) -> Result<ToolResult, rustre_mcp_server::McpError> {
        let line = args.get("line").and_then(|v| v.as_str()).unwrap_or("");
        let s = rustre_net_proxy::HttpStatusLine::parse(line)
            .map_err(|e| rustre_mcp_server::McpError::InvalidParams(e.to_string()))?;
        Ok(ToolResult::text(json!({ "is_client_error": s.is_client_error(), "code": s.code,
            "source": "rustre_net_proxy::HttpStatusLine::is_client_error" }).to_string()))
    }
}

pub struct NetProxyHttpStatusLineIsServerErrorTool;
impl NetProxyHttpStatusLineIsServerErrorTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "net_proxy_http_status_line_is_server_error".to_string(),
            description: "Return true if the parsed HTTP status line has a 5xx code.".to_string(),
            input_schema: json!({ "type":"object", "properties":{ "line":{"type":"string"}}, "required":["line"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait::async_trait]
impl ToolHandler for NetProxyHttpStatusLineIsServerErrorTool {
    async fn call(&self, args: Value) -> Result<ToolResult, rustre_mcp_server::McpError> {
        let line = args.get("line").and_then(|v| v.as_str()).unwrap_or("");
        let s = rustre_net_proxy::HttpStatusLine::parse(line)
            .map_err(|e| rustre_mcp_server::McpError::InvalidParams(e.to_string()))?;
        Ok(ToolResult::text(json!({ "is_server_error": s.is_server_error(), "code": s.code,
            "source": "rustre_net_proxy::HttpStatusLine::is_server_error" }).to_string()))
    }
}

pub struct NetProxyAclEntryAllowAllTool;
impl NetProxyAclEntryAllowAllTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "net_proxy_acl_entry_allow_all".to_string(),
            description: "Build the allow-all ACL entry and describe it.".to_string(),
            input_schema: json!({ "type":"object", "properties":{}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait::async_trait]
impl ToolHandler for NetProxyAclEntryAllowAllTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, rustre_mcp_server::McpError> {
        let e = rustre_net_proxy::AclEntry::allow_all();
        Ok(ToolResult::text(json!({
            "host_pattern": e.host_pattern, "port": e.port,
            "matches_example": e.matches("example.com", 443),
            "source": "rustre_net_proxy::AclEntry::allow_all"
        }).to_string()))
    }
}

pub struct NetProxyAclEntryDenyHostTool;
impl NetProxyAclEntryDenyHostTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "net_proxy_acl_entry_deny_host".to_string(),
            description: "Build a deny-host ACL entry and verify matches().".to_string(),
            input_schema: json!({ "type":"object", "properties":{ "host":{"type":"string"}, "port":{"type":"integer"}}, "required":["host"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait::async_trait]
impl ToolHandler for NetProxyAclEntryDenyHostTool {
    async fn call(&self, args: Value) -> Result<ToolResult, rustre_mcp_server::McpError> {
        let host = args.get("host").and_then(|v| v.as_str()).unwrap_or("");
        let port = args.get("port").and_then(Value::as_u64).unwrap_or(443) as u16;
        let e = rustre_net_proxy::AclEntry::deny_host(host);
        Ok(ToolResult::text(json!({
            "host_pattern": e.host_pattern, "matches": e.matches(host, port),
            "source": "rustre_net_proxy::AclEntry::deny_host"
        }).to_string()))
    }
}

pub struct NetProxyHttpConnectErrorResponseTool;
impl NetProxyHttpConnectErrorResponseTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "net_proxy_http_connect_error_response".to_string(),
            description: "Format an HTTP CONNECT error response via HttpConnectRequest::error_response.".to_string(),
            input_schema: json!({ "type":"object", "properties":{ "status":{"type":"integer"}, "msg":{"type":"string"}}, "required":["status","msg"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait::async_trait]
impl ToolHandler for NetProxyHttpConnectErrorResponseTool {
    async fn call(&self, args: Value) -> Result<ToolResult, rustre_mcp_server::McpError> {
        let status = args.get("status").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'status'".into()))? as u16;
        let msg = args.get("msg").and_then(|v| v.as_str()).unwrap_or("Bad Request");
        let resp = rustre_net_proxy::HttpConnectRequest::error_response(status, msg);
        Ok(ToolResult::text(json!({ "response": resp,
            "source": "rustre_net_proxy::HttpConnectRequest::error_response" }).to_string()))
    }
}

pub struct NetProxyHttpMethodDisplayTool;
impl NetProxyHttpMethodDisplayTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "net_proxy_http_method_display".to_string(),
            description: "Parse a method string and return its canonical Display form.".to_string(),
            input_schema: json!({ "type":"object", "properties":{ "method":{"type":"string"}}, "required":["method"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait::async_trait]
impl ToolHandler for NetProxyHttpMethodDisplayTool {
    async fn call(&self, args: Value) -> Result<ToolResult, rustre_mcp_server::McpError> {
        let m = args.get("method").and_then(|v| v.as_str()).unwrap_or("");
        let parsed = rustre_net_proxy::HttpMethod::from_str(m);
        Ok(ToolResult::text(json!({
            "input": m, "display": parsed.to_string(),
            "is_idempotent": parsed.is_idempotent(), "has_body": parsed.has_body(),
            "source": "rustre_net_proxy::HttpMethod::from_str"
        }).to_string()))
    }
}

pub struct NetProxyHexEncodeTool;

pub struct NetProxyHexDecodeTool;

pub struct NetProxyBase64DecodeTool;

pub struct NetProxyGlobMatchWireTool;

pub struct NetProxySimpleRegexMatchTool;

pub struct NetProxyDecodeContentEncodingTool;
impl NetProxyDecodeContentEncodingTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "net_proxy_decode_content_encoding".to_string(),
            description: "Decode gzip/deflate HTTP body via rustre_net_proxy::decode_content_encoding.".to_string(),
            input_schema: json!({"type":"object","required":["encoding"],"properties":{"bytes":{"type":"array","items":{"type":"integer"}},"hex":{"type":"string"},"encoding":{"type":"string"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for NetProxyDecodeContentEncodingTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let data = args_to_bytes(&args)?;
        let enc = args.get("encoding").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'encoding'".into()))?;
        let out = rustre_net_proxy::decode_content_encoding(&data, enc);
        Ok(ToolResult::text(json!({
            "input_len": data.len(),
            "output_len": out.len(),
            "output_hex": hex_encode(&out),
            "source": "rustre_net_proxy::decode_content_encoding",
        }).to_string()))
    }
}

pub struct NetProxyParseConnectTool;
impl NetProxyParseConnectTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "net_proxy_parse_connect".to_string(),
            description: "Parse HTTP CONNECT target via rustre_net_proxy::HttpProxy::parse_connect.".to_string(),
            input_schema: json!({"type":"object","required":["request"],"properties":{"request":{"type":"string"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for NetProxyParseConnectTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let req = args.get("request").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'request'".into()))?;
        let target = rustre_net_proxy::HttpProxy::parse_connect(req);
        Ok(ToolResult::text(json!({
            "target": target,
            "matched": target.is_some(),
            "source": "rustre_net_proxy::HttpProxy::parse_connect",
        }).to_string()))
    }
}

pub struct NetProxyParseRequestLineTool;
impl NetProxyParseRequestLineTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "net_proxy_parse_request_line".to_string(),
            description: "Parse HTTP request-line via rustre_net_proxy::HttpRequestLine::parse.".to_string(),
            input_schema: json!({"type":"object","required":["line"],"properties":{"line":{"type":"string"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for NetProxyParseRequestLineTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let line = args.get("line").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'line'".into()))?;
        match rustre_net_proxy::HttpRequestLine::parse(line) {
            Ok(rl) => Ok(ToolResult::text(json!({"ok":true,"method":format!("{}",rl.method),"uri":rl.uri,"version":rl.version,"source":"rustre_net_proxy::HttpRequestLine::parse"}).to_string())),
            Err(e) => Ok(ToolResult::text(json!({"ok":false,"error":format!("{e}"),"source":"rustre_net_proxy::HttpRequestLine::parse"}).to_string())),
        }
    }
}

pub struct NetProxyParseStatusLineTool;
impl NetProxyParseStatusLineTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "net_proxy_parse_status_line".to_string(),
            description: "Parse HTTP status-line via rustre_net_proxy::HttpStatusLine::parse.".to_string(),
            input_schema: json!({"type":"object","required":["line"],"properties":{"line":{"type":"string"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for NetProxyParseStatusLineTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let line = args.get("line").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'line'".into()))?;
        match rustre_net_proxy::HttpStatusLine::parse(line) {
            Ok(sl) => Ok(ToolResult::text(json!({"ok":true,"version":sl.version,"code":sl.code,"reason":sl.reason,"source":"rustre_net_proxy::HttpStatusLine::parse"}).to_string())),
            Err(e) => Ok(ToolResult::text(json!({"ok":false,"error":format!("{e}"),"source":"rustre_net_proxy::HttpStatusLine::parse"}).to_string())),
        }
    }
}

pub struct NetProxyMsToIso8601Tool;
impl NetProxyMsToIso8601Tool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "net_proxy_ms_to_iso8601".to_string(),
            description: "Convert Unix ms to ISO-8601 via rustre_net_proxy::HarExporter::ms_to_iso8601.".to_string(),
            input_schema: json!({"type":"object","required":["ms"],"properties":{"ms":{"type":"integer","minimum":0}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for NetProxyMsToIso8601Tool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let ms = args.get("ms").and_then(Value::as_u64)
            .ok_or_else(|| McpError::InvalidParams("missing 'ms'".into()))?;
        let s = rustre_net_proxy::HarExporter::ms_to_iso8601(ms);
        Ok(ToolResult::text(json!({"iso8601":s,"source":"rustre_net_proxy::HarExporter::ms_to_iso8601"}).to_string()))
    }
}

pub struct NetProxyHeadersToJsonTool;
impl NetProxyHeadersToJsonTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "net_proxy_headers_to_json".to_string(),
            description: "Serialize [name,value] header pairs to JSON via rustre_net_proxy::HarExporter::headers_to_json.".to_string(),
            input_schema: json!({"type":"object","required":["headers"],"properties":{"headers":{"type":"array","items":{"type":"array","items":{"type":"string"},"minItems":2,"maxItems":2}}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for NetProxyHeadersToJsonTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let arr = args.get("headers").and_then(Value::as_array)
            .ok_or_else(|| McpError::InvalidParams("missing 'headers'".into()))?;
        let mut pairs: Vec<(String, String)> = Vec::with_capacity(arr.len());
        for h in arr {
            let inner = h.as_array().ok_or_else(|| McpError::InvalidParams("header not array".into()))?;
            if inner.len() < 2 { return Err(McpError::InvalidParams("header pair needs 2".into())); }
            pairs.push((inner[0].as_str().unwrap_or("").to_string(), inner[1].as_str().unwrap_or("").to_string()));
        }
        let js = rustre_net_proxy::HarExporter::headers_to_json(&pairs);
        Ok(ToolResult::text(json!({"json":js,"count":pairs.len(),"source":"rustre_net_proxy::HarExporter::headers_to_json"}).to_string()))
    }
}

pub struct NetProxyHttpMethodFromStrTool;
impl NetProxyHttpMethodFromStrTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "net_proxy_http_method_from_str".to_string(),
            description: "Parse HTTP method string via rustre_net_proxy::HttpMethod::from_str.".to_string(),
            input_schema: json!({"type":"object","required":["method"],"properties":{"method":{"type":"string"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for NetProxyHttpMethodFromStrTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let m = args.get("method").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'method'".into()))?;
        let parsed = rustre_net_proxy::HttpMethod::from_str(m);
        Ok(ToolResult::text(json!({"method":format!("{}",parsed),"source":"rustre_net_proxy::HttpMethod::from_str"}).to_string()))
    }
}

pub struct NetProxyHttpConnectRequestParseTool;
impl NetProxyHttpConnectRequestParseTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "net_proxy_http_connect_request_parse".to_string(),
            description: "Parse full HTTP CONNECT request via rustre_net_proxy::HttpConnectRequest::parse.".to_string(),
            input_schema: json!({"type":"object","required":["raw"],"properties":{"raw":{"type":"string"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for NetProxyHttpConnectRequestParseTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let raw = args.get("raw").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'raw'".into()))?;
        match rustre_net_proxy::HttpConnectRequest::parse(raw) {
            Ok(r) => {
                let headers: Vec<Value> = r.headers.iter().map(|(n,v)| json!([n,v])).collect();
                Ok(ToolResult::text(json!({"ok":true,"host":r.host,"port":r.port,"http_version":r.http_version,"headers":headers,"source":"rustre_net_proxy::HttpConnectRequest::parse"}).to_string()))
            }
            Err(e) => Ok(ToolResult::text(json!({"ok":false,"error":format!("{e}"),"source":"rustre_net_proxy::HttpConnectRequest::parse"}).to_string())),
        }
    }
}

pub struct NetProxySimpleRegexMatchLenTool;

pub struct NetProxyInjectXffHeadersTool;

pub struct NetProxyHttpMethodIsIdempotentTool;
impl NetProxyHttpMethodIsIdempotentTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "net_proxy_http_method_is_idempotent".to_string(),
            description: "Return whether an HTTP method is idempotent via rustre_net_proxy::HttpMethod::is_idempotent.".to_string(),
            input_schema: json!({"type":"object","required":["method"],"properties":{"method":{"type":"string"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for NetProxyHttpMethodIsIdempotentTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let m = args.get("method").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'method'".into()))?;
        let method = rustre_net_proxy::HttpMethod::from_str(m);
        Ok(ToolResult::text(json!({"method": format!("{method}"), "is_idempotent": method.is_idempotent(), "source": "rustre_net_proxy::HttpMethod::is_idempotent"}).to_string()))
    }
}

pub struct NetProxyHttpMethodHasBodyTool;
impl NetProxyHttpMethodHasBodyTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "net_proxy_http_method_has_body".to_string(),
            description: "Return whether an HTTP method can carry a body via rustre_net_proxy::HttpMethod::has_body.".to_string(),
            input_schema: json!({"type":"object","required":["method"],"properties":{"method":{"type":"string"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for NetProxyHttpMethodHasBodyTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let m = args.get("method").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'method'".into()))?;
        let method = rustre_net_proxy::HttpMethod::from_str(m);
        Ok(ToolResult::text(json!({"method": format!("{method}"), "has_body": method.has_body(), "source": "rustre_net_proxy::HttpMethod::has_body"}).to_string()))
    }
}

pub struct NetProxyHttpStatusClassifyTool;
impl NetProxyHttpStatusClassifyTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "net_proxy_http_status_classify".to_string(),
            description: "Parse an HTTP status line and classify 2xx/3xx/4xx/5xx via rustre_net_proxy::HttpStatusLine.".to_string(),
            input_schema: json!({"type":"object","required":["line"],"properties":{"line":{"type":"string"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for NetProxyHttpStatusClassifyTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let line = args.get("line").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'line'".into()))?;
        match rustre_net_proxy::HttpStatusLine::parse(line) {
            Ok(s) => Ok(ToolResult::text(json!({"ok": true, "version": s.version, "code": s.code, "reason": s.reason, "is_success": s.is_success(), "is_redirect": s.is_redirect(), "is_client_error": s.is_client_error(), "is_server_error": s.is_server_error(), "source": "rustre_net_proxy::HttpStatusLine"}).to_string())),
            Err(e) => Ok(ToolResult::text(json!({"ok": false, "error": format!("{e}"), "source": "rustre_net_proxy::HttpStatusLine"}).to_string())),
        }
    }
}

pub struct NetProxyHttpRequestLineVersionTool;
impl NetProxyHttpRequestLineVersionTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "net_proxy_http_request_line_version".to_string(),
            description: "Parse an HTTP request line and return HTTP/1.1 and HTTP/2 flags via rustre_net_proxy::HttpRequestLine.".to_string(),
            input_schema: json!({"type":"object","required":["line"],"properties":{"line":{"type":"string"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for NetProxyHttpRequestLineVersionTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let line = args.get("line").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'line'".into()))?;
        match rustre_net_proxy::HttpRequestLine::parse(line) {
            Ok(rl) => Ok(ToolResult::text(json!({"ok": true, "method": format!("{}", rl.method), "uri": rl.uri, "version": rl.version, "is_http11": rl.is_http11(), "is_http2": rl.is_http2(), "source": "rustre_net_proxy::HttpRequestLine"}).to_string())),
            Err(e) => Ok(ToolResult::text(json!({"ok": false, "error": format!("{e}"), "source": "rustre_net_proxy::HttpRequestLine"}).to_string())),
        }
    }
}

pub struct NetProxyAclEntryMatchesTool;
impl NetProxyAclEntryMatchesTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "net_proxy_acl_entry_matches".to_string(),
            description: "Test if an ACL entry (deny_host) matches host:port via rustre_net_proxy::AclEntry::matches.".to_string(),
            input_schema: json!({"type":"object","required":["deny_host","host","port"],"properties":{"deny_host":{"type":"string"},"host":{"type":"string"},"port":{"type":"integer"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for NetProxyAclEntryMatchesTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let deny = args.get("deny_host").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'deny_host'".into()))?;
        let host = args.get("host").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'host'".into()))?;
        let port = args.get("port").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'port'".into()))? as u16;
        let entry = rustre_net_proxy::AclEntry::deny_host(deny);
        let allow_all = rustre_net_proxy::AclEntry::allow_all();
        Ok(ToolResult::text(json!({"deny_matches": entry.matches(host, port), "allow_all_matches": allow_all.matches(host, port), "source": "rustre_net_proxy::AclEntry::matches"}).to_string()))
    }
}

pub struct NetProxyAclEvaluateTool;
impl NetProxyAclEvaluateTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "net_proxy_acl_evaluate".to_string(),
            description: "Evaluate a small ACL (default Allow, deny_host entry) for host:port via rustre_net_proxy::ProxyAcl::evaluate.".to_string(),
            input_schema: json!({"type":"object","required":["deny_host","host","port"],"properties":{"deny_host":{"type":"string"},"host":{"type":"string"},"port":{"type":"integer"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for NetProxyAclEvaluateTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let deny = args.get("deny_host").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'deny_host'".into()))?;
        let host = args.get("host").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'host'".into()))?;
        let port = args.get("port").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'port'".into()))? as u16;
        let mut acl = rustre_net_proxy::ProxyAcl::new(rustre_net_proxy::AclAction::Allow);
        acl.add(rustre_net_proxy::AclEntry::deny_host(deny));
        let action = acl.evaluate(host, port);
        Ok(ToolResult::text(json!({"action": format!("{:?}", action), "len": acl.len(), "is_empty": acl.is_empty(), "source": "rustre_net_proxy::ProxyAcl::evaluate"}).to_string()))
    }
}

pub struct NetProxyHeaderRewriteSetTool;
impl NetProxyHeaderRewriteSetTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "net_proxy_header_rewrite_set".to_string(),
            description: "Apply a HeaderRewriteRule::set to a raw HTTP headers block via rustre_net_proxy.".to_string(),
            input_schema: json!({"type":"object","required":["name","value","headers"],"properties":{"name":{"type":"string"},"value":{"type":"string"},"headers":{"type":"string"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for NetProxyHeaderRewriteSetTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let name = args.get("name").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'name'".into()))?;
        let value = args.get("value").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'value'".into()))?;
        let headers = args.get("headers").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'headers'".into()))?;
        let rule = rustre_net_proxy::HeaderRewriteRule::set(name, value);
        let out = rule.apply(headers);
        Ok(ToolResult::text(json!({"output": out, "source": "rustre_net_proxy::HeaderRewriteRule::set"}).to_string()))
    }
}

pub struct NetProxyHeaderRewriteRemoveTool;
impl NetProxyHeaderRewriteRemoveTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "net_proxy_header_rewrite_remove".to_string(),
            description: "Apply a HeaderRewriteRule::remove to a raw HTTP headers block via rustre_net_proxy.".to_string(),
            input_schema: json!({"type":"object","required":["name","headers"],"properties":{"name":{"type":"string"},"headers":{"type":"string"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for NetProxyHeaderRewriteRemoveTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let name = args.get("name").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'name'".into()))?;
        let headers = args.get("headers").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'headers'".into()))?;
        let rule = rustre_net_proxy::HeaderRewriteRule::remove(name);
        let out = rule.apply(headers);
        Ok(ToolResult::text(json!({"output": out, "source": "rustre_net_proxy::HeaderRewriteRule::remove"}).to_string()))
    }
}

pub struct NetProxyHeaderRewriterApplyAllTool;
impl NetProxyHeaderRewriterApplyAllTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "net_proxy_header_rewriter_apply_all".to_string(),
            description: "Chain a set+remove rule via HeaderRewriter::apply_all over raw HTTP headers.".to_string(),
            input_schema: json!({"type":"object","required":["set_name","set_value","remove_name","headers"],"properties":{"set_name":{"type":"string"},"set_value":{"type":"string"},"remove_name":{"type":"string"},"headers":{"type":"string"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for NetProxyHeaderRewriterApplyAllTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let sn = args.get("set_name").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'set_name'".into()))?;
        let sv = args.get("set_value").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'set_value'".into()))?;
        let rn = args.get("remove_name").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'remove_name'".into()))?;
        let headers = args.get("headers").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'headers'".into()))?;
        let mut rw = rustre_net_proxy::HeaderRewriter::new();
        rw.add_rule(rustre_net_proxy::HeaderRewriteRule::set(sn, sv));
        rw.add_rule(rustre_net_proxy::HeaderRewriteRule::remove(rn));
        let out = rw.apply_all(headers);
        Ok(ToolResult::text(json!({"output": out, "source": "rustre_net_proxy::HeaderRewriter::apply_all"}).to_string()))
    }
}

pub struct NetProxySocks5UdpHeaderParseTool;
impl NetProxySocks5UdpHeaderParseTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "net_proxy_socks5_udp_header_parse".to_string(),
            description: "Parse a SOCKS5 UDP relay header via rustre_net_proxy::Socks5UdpHeader::parse.".to_string(),
            input_schema: json!({"type":"object","properties":{"bytes":{"type":"array","items":{"type":"integer"}},"hex":{"type":"string"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for NetProxySocks5UdpHeaderParseTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let data = args_to_bytes(&args)?;
        match rustre_net_proxy::Socks5UdpHeader::parse(&data) {
            Ok(h) => Ok(ToolResult::text(json!({"ok": true, "rsv": h.rsv, "frag": h.frag, "atyp": h.atyp, "dst_addr": h.dst_addr, "dst_port": h.dst_port, "source": "rustre_net_proxy::Socks5UdpHeader::parse"}).to_string())),
            Err(e) => Ok(ToolResult::text(json!({"ok": false, "error": format!("{e}"), "source": "rustre_net_proxy::Socks5UdpHeader::parse"}).to_string())),
        }
    }
}

pub struct NetProxyRateLimiterCheckTool;
impl NetProxyRateLimiterCheckTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "net_proxy_rate_limiter_check".to_string(),
            description: "Simulate a RateLimiter: try_connect and try_send_bytes via rustre_net_proxy::RateLimiter.".to_string(),
            input_schema: json!({"type":"object","required":["bytes_per_sec","max_connections","now_ms","bytes"],"properties":{"bytes_per_sec":{"type":"integer"},"max_connections":{"type":"integer"},"now_ms":{"type":"integer"},"bytes":{"type":"integer"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for NetProxyRateLimiterCheckTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let bps = args.get("bytes_per_sec").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'bytes_per_sec'".into()))?;
        let mc = args.get("max_connections").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'max_connections'".into()))? as usize;
        let now = args.get("now_ms").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'now_ms'".into()))?;
        let bytes = args.get("bytes").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'bytes'".into()))?;
        let rl = rustre_net_proxy::RateLimiter::new(bps, mc);
        let connected = rl.try_connect();
        let sent = rl.try_send_bytes(now, bytes);
        Ok(ToolResult::text(json!({"connected": connected, "sent": sent, "active_connections": rl.active_connections(), "bytes_this_window": rl.bytes_this_window(), "source": "rustre_net_proxy::RateLimiter"}).to_string()))
    }
}

pub struct NetProxySharedStatsOpsTool;
impl NetProxySharedStatsOpsTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "net_proxy_shared_stats_ops".to_string(),
            description: "Exercise SharedStats: inc_requests, inc_responses, inc_errors, inc_connections, snapshot via rustre_net_proxy::SharedStats.".to_string(),
            input_schema: json!({"type":"object","required":["req_bytes","resp_bytes"],"properties":{"req_bytes":{"type":"integer"},"resp_bytes":{"type":"integer"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for NetProxySharedStatsOpsTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let req_b = args.get("req_bytes").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'req_bytes'".into()))?;
        let resp_b = args.get("resp_bytes").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'resp_bytes'".into()))?;
        let s = rustre_net_proxy::SharedStats::new();
        s.inc_connections();
        s.inc_requests(req_b);
        s.inc_responses(resp_b);
        s.inc_errors();
        let snap = s.snapshot();
        Ok(ToolResult::text(json!({"requests": snap.requests, "bytes_in": snap.bytes_in, "bytes_out": snap.bytes_out, "errors": snap.errors, "connections": snap.connections, "source": "rustre_net_proxy::SharedStats::snapshot"}).to_string()))
    }
}

pub fn handlers() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    vec![
        (NetProxyHttpRequestLineParseTool::definition(), Box::new(NetProxyHttpRequestLineParseTool)),
        (NetProxyHttpRequestLineIsHttp11Tool::definition(), Box::new(NetProxyHttpRequestLineIsHttp11Tool)),
        (NetProxyHttpRequestLineIsHttp2Tool::definition(), Box::new(NetProxyHttpRequestLineIsHttp2Tool)),
        (NetProxyHttpStatusLineParseTool::definition(), Box::new(NetProxyHttpStatusLineParseTool)),
        (NetProxyHttpStatusLineIsSuccessTool::definition(), Box::new(NetProxyHttpStatusLineIsSuccessTool)),
        (NetProxyHttpStatusLineIsRedirectTool::definition(), Box::new(NetProxyHttpStatusLineIsRedirectTool)),
        (NetProxyHttpStatusLineIsClientErrorTool::definition(), Box::new(NetProxyHttpStatusLineIsClientErrorTool)),
        (NetProxyHttpStatusLineIsServerErrorTool::definition(), Box::new(NetProxyHttpStatusLineIsServerErrorTool)),
        (NetProxyAclEntryAllowAllTool::definition(), Box::new(NetProxyAclEntryAllowAllTool)),
        (NetProxyAclEntryDenyHostTool::definition(), Box::new(NetProxyAclEntryDenyHostTool)),
        (NetProxyHttpConnectErrorResponseTool::definition(), Box::new(NetProxyHttpConnectErrorResponseTool)),
        (NetProxyHttpMethodDisplayTool::definition(), Box::new(NetProxyHttpMethodDisplayTool)),
        (NetProxyHexEncodeTool::definition(), Box::new(NetProxyHexEncodeTool)),
        (NetProxyHexDecodeTool::definition(), Box::new(NetProxyHexDecodeTool)),
        (NetProxyBase64DecodeTool::definition(), Box::new(NetProxyBase64DecodeTool)),
        (NetProxyGlobMatchWireTool::definition(), Box::new(NetProxyGlobMatchWireTool)),
        (NetProxySimpleRegexMatchTool::definition(), Box::new(NetProxySimpleRegexMatchTool)),
        (NetProxyDecodeContentEncodingTool::definition(), Box::new(NetProxyDecodeContentEncodingTool)),
        (NetProxyParseConnectTool::definition(), Box::new(NetProxyParseConnectTool)),
        (NetProxyParseRequestLineTool::definition(), Box::new(NetProxyParseRequestLineTool)),
        (NetProxyParseStatusLineTool::definition(), Box::new(NetProxyParseStatusLineTool)),
        (NetProxyMsToIso8601Tool::definition(), Box::new(NetProxyMsToIso8601Tool)),
        (NetProxyHeadersToJsonTool::definition(), Box::new(NetProxyHeadersToJsonTool)),
        (NetProxyHttpMethodFromStrTool::definition(), Box::new(NetProxyHttpMethodFromStrTool)),
        (NetProxyHttpConnectRequestParseTool::definition(), Box::new(NetProxyHttpConnectRequestParseTool)),
        (NetProxySimpleRegexMatchLenTool::definition(), Box::new(NetProxySimpleRegexMatchLenTool)),
        (NetProxyInjectXffHeadersTool::definition(), Box::new(NetProxyInjectXffHeadersTool)),
        (NetProxyHttpMethodIsIdempotentTool::definition(), Box::new(NetProxyHttpMethodIsIdempotentTool)),
        (NetProxyHttpMethodHasBodyTool::definition(), Box::new(NetProxyHttpMethodHasBodyTool)),
        (NetProxyHttpStatusClassifyTool::definition(), Box::new(NetProxyHttpStatusClassifyTool)),
        (NetProxyHttpRequestLineVersionTool::definition(), Box::new(NetProxyHttpRequestLineVersionTool)),
        (NetProxyAclEntryMatchesTool::definition(), Box::new(NetProxyAclEntryMatchesTool)),
        (NetProxyAclEvaluateTool::definition(), Box::new(NetProxyAclEvaluateTool)),
        (NetProxyHeaderRewriteSetTool::definition(), Box::new(NetProxyHeaderRewriteSetTool)),
        (NetProxyHeaderRewriteRemoveTool::definition(), Box::new(NetProxyHeaderRewriteRemoveTool)),
        (NetProxyHeaderRewriterApplyAllTool::definition(), Box::new(NetProxyHeaderRewriterApplyAllTool)),
        (NetProxySocks5UdpHeaderParseTool::definition(), Box::new(NetProxySocks5UdpHeaderParseTool)),
        (NetProxyRateLimiterCheckTool::definition(), Box::new(NetProxyRateLimiterCheckTool)),
        (NetProxySharedStatsOpsTool::definition(), Box::new(NetProxySharedStatsOpsTool)),
    ]
}


impl NetProxySimpleRegexMatchLenTool {
    #[must_use]
    pub fn definition() -> rustre_mcp_server::ToolDefinition {
        rustre_mcp_server::ToolDefinition {
            name: "net_proxy_simple_regex_match_len".to_string(),
            description: "Return the match length of text against a simple regex pattern.".to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "required": ["pattern", "text"],
                "properties": {
                    "pattern": { "type": "string" },
                    "text":    { "type": "string" }
                }
            }),
            parameters: serde_json::Value::Null,
        }
    }
}

#[async_trait::async_trait]
impl rustre_mcp_server::ToolHandler for NetProxySimpleRegexMatchLenTool {
    async fn call(&self, args: serde_json::Value) -> Result<rustre_mcp_server::ToolResult, rustre_mcp_server::McpError> {
        let pattern = args.get("pattern").and_then(serde_json::Value::as_str)
            .ok_or_else(|| rustre_mcp_server::McpError::InvalidParams("missing pattern".into()))?;
        let text = args.get("text").and_then(serde_json::Value::as_str)
            .ok_or_else(|| rustre_mcp_server::McpError::InvalidParams("missing text".into()))?;
        let len = rustre_net_proxy::simple_regex_match_len(pattern, text);
        Ok(rustre_mcp_server::ToolResult::text(
            serde_json::json!({ "matched_len": len }).to_string(),
        ))
    }
}

impl NetProxyInjectXffHeadersTool {
    #[must_use]
    pub fn definition() -> rustre_mcp_server::ToolDefinition {
        rustre_mcp_server::ToolDefinition {
            name: "net_proxy_inject_xff_headers".to_string(),
            description: "Inject X-Forwarded-For and X-Forwarded-Host headers into a raw HTTP request.".to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "bytes": { "type": "array", "items": { "type": "integer" } },
                    "hex":   { "type": "string" },
                    "client_ip":  { "type": "string" },
                    "proxy_host": { "type": "string" }
                },
                "required": ["client_ip", "proxy_host"]
            }),
            parameters: serde_json::Value::Null,
        }
    }
}

#[async_trait::async_trait]
impl rustre_mcp_server::ToolHandler for NetProxyInjectXffHeadersTool {
    async fn call(&self, args: serde_json::Value) -> Result<rustre_mcp_server::ToolResult, rustre_mcp_server::McpError> {
        let mut data = crate::args_to_bytes(&args)?;
        let client_ip = args.get("client_ip").and_then(serde_json::Value::as_str)
            .ok_or_else(|| rustre_mcp_server::McpError::InvalidParams("missing client_ip".into()))?;
        let proxy_host = args.get("proxy_host").and_then(serde_json::Value::as_str)
            .ok_or_else(|| rustre_mcp_server::McpError::InvalidParams("missing proxy_host".into()))?;
        let injected = rustre_net_proxy::inject_xff_headers(&mut data, client_ip, proxy_host);
        Ok(rustre_mcp_server::ToolResult::text(
            serde_json::json!({
                "injected": injected,
                "output_hex": crate::hex_encode(&data),
                "output_len": data.len(),
            }).to_string(),
        ))
    }
}

