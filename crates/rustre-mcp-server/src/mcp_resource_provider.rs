//! MCP resource provider: expose binary data, analysis results, and disassembly
//! as MCP resources accessible via `resources/list` and `resources/read`.
//!
//! Resources have URIs of the form `rustre://<kind>/<path>`.
//! `McpResourceProvider` maintains a registry of registered resources and handles
//! subscription notifications when resource content changes.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

// ─── ResourceUri ─────────────────────────────────────────────────────────────

/// Typed wrapper around an MCP resource URI.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ResourceUri(pub String);

impl ResourceUri {
    /// Create a URI in the `rustre://binary/<name>` namespace.
    #[must_use] 
    pub fn binary(name: &str) -> Self {
        Self(format!("rustre://binary/{name}"))
    }

    /// Create a URI in the `rustre://analysis/<kind>/<name>` namespace.
    #[must_use] 
    pub fn analysis(kind: &str, name: &str) -> Self {
        Self(format!("rustre://analysis/{kind}/{name}"))
    }

    /// Create a URI in the `rustre://disasm/<addr>` namespace.
    #[must_use] 
    pub fn disasm(addr: u64) -> Self {
        Self(format!("rustre://disasm/0x{addr:x}"))
    }

    /// Create a URI in the `rustre://trace/<name>` namespace.
    #[must_use] 
    pub fn trace(name: &str) -> Self {
        Self(format!("rustre://trace/{name}"))
    }

    /// Create a URI in the `rustre://taint/<id>` namespace.
    #[must_use] 
    pub fn taint(id: u64) -> Self {
        Self(format!("rustre://taint/{id}"))
    }

    /// Parse the scheme from a URI string.
    #[must_use] 
    pub fn scheme(uri: &str) -> Option<&str> {
        uri.split("://").next()
    }

    /// Parse the path component (after <scheme://host>/).
    #[must_use] 
    pub fn path_component(uri: &str) -> Option<&str> {
        let after_scheme = uri.split("://").nth(1)?;
        after_scheme.split_once('/').map(|(_, p)| p)
    }

    /// Return the inner string.
    #[must_use] 
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for ResourceUri {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

// ─── ResourceMimeType ────────────────────────────────────────────────────────

/// Supported MIME types for resource content.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ResourceMimeType {
    ApplicationJson,
    TextPlain,
    ApplicationOctetStream,
    TextMarkdown,
    Custom(String),
}

impl ResourceMimeType {
    #[must_use] 
    pub const fn as_str(&self) -> &str {
        match self {
            Self::ApplicationJson => "application/json",
            Self::TextPlain => "text/plain",
            Self::ApplicationOctetStream => "application/octet-stream",
            Self::TextMarkdown => "text/markdown",
            Self::Custom(s) => s.as_str(),
        }
    }
}

// ─── ResourceContent ─────────────────────────────────────────────────────────

/// Content of a resource, either text or binary (base64-encoded).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ResourceContent {
    Text {
        uri: String,
        mime_type: String,
        text: String,
    },
    Blob {
        uri: String,
        mime_type: String,
        /// Base64-encoded binary data.
        blob: String,
    },
}

impl ResourceContent {
    /// Create a text resource content.
    pub fn text(uri: impl Into<String>, mime: &ResourceMimeType, text: impl Into<String>) -> Self {
        Self::Text {
            uri: uri.into(),
            mime_type: mime.as_str().into(),
            text: text.into(),
        }
    }

    /// Create a JSON text resource.
    pub fn json(uri: impl Into<String>, value: &Value) -> Self {
        Self::text(uri, &ResourceMimeType::ApplicationJson, value.to_string())
    }

    /// Create a plain text resource.
    pub fn plain(uri: impl Into<String>, text: impl Into<String>) -> Self {
        Self::text(uri, &ResourceMimeType::TextPlain, text)
    }

    /// Create a binary blob resource (base64).
    pub fn blob(uri: impl Into<String>, mime: &ResourceMimeType, data: &[u8]) -> Self {
        Self::Blob {
            uri: uri.into(),
            mime_type: mime.as_str().into(),
            blob: base64_encode(data),
        }
    }

    /// Serialize to the MCP content object format.
    #[must_use] 
    pub fn to_mcp_object(&self) -> Value {
        match self {
            Self::Text { uri, mime_type, text } => json!({
                "uri": uri,
                "mimeType": mime_type,
                "text": text
            }),
            Self::Blob { uri, mime_type, blob } => json!({
                "uri": uri,
                "mimeType": mime_type,
                "blob": blob
            }),
        }
    }

    /// Return the URI of this content.
    #[must_use] 
    pub const fn uri(&self) -> &str {
        match self {
            Self::Text { uri, .. } | Self::Blob { uri, .. } => uri.as_str(),
        }
    }
}

/// Minimal base64 encoder (no external dep).
fn base64_encode(data: &[u8]) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0];
        let b1 = chunk.get(1).copied().unwrap_or(0);
        let b2 = chunk.get(2).copied().unwrap_or(0);
        let n = (u32::from(b0) << 16) | (u32::from(b1) << 8) | u32::from(b2);
        out.push(CHARS[((n >> 18) & 0x3f) as usize] as char);
        out.push(CHARS[((n >> 12) & 0x3f) as usize] as char);
        out.push(if chunk.len() > 1 { CHARS[((n >> 6) & 0x3f) as usize] as char } else { '=' });
        out.push(if chunk.len() > 2 { CHARS[(n & 0x3f) as usize] as char } else { '=' });
    }
    out
}

// ─── ResourceDescriptor ──────────────────────────────────────────────────────

/// Metadata entry for a resource shown in `resources/list`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceDescriptor {
    pub uri: String,
    pub name: String,
    pub description: String,
    pub mime_type: String,
}

impl ResourceDescriptor {
    pub fn new(
        uri: impl Into<String>,
        name: impl Into<String>,
        description: impl Into<String>,
        mime: &ResourceMimeType,
    ) -> Self {
        Self {
            uri: uri.into(),
            name: name.into(),
            description: description.into(),
            mime_type: mime.as_str().into(),
        }
    }

    #[must_use] 
    pub fn to_json(&self) -> Value {
        json!({
            "uri": self.uri,
            "name": self.name,
            "description": self.description,
            "mimeType": self.mime_type
        })
    }
}

// ─── ResourceEntry ───────────────────────────────────────────────────────────

/// A registered resource with its descriptor and content factory.
struct ResourceEntry {
    descriptor: ResourceDescriptor,
    /// On-demand content builder. Takes optional query params, returns content.
    factory: Arc<dyn Fn(Option<&Value>) -> ResourceContent + Send + Sync>,
}

// ─── McpResourceProvider ─────────────────────────────────────────────────────

/// Provides MCP resources backed by `RustRE` analysis data.
pub struct McpResourceProvider {
    resources: Mutex<HashMap<String, ResourceEntry>>,
    /// Ordered list of URIs for deterministic listing.
    order: Mutex<Vec<String>>,
}

impl McpResourceProvider {
    /// Create an empty provider.
    #[must_use] 
    pub fn new() -> Self {
        Self {
            resources: Mutex::new(HashMap::new()),
            order: Mutex::new(Vec::new()),
        }
    }

    /// Create a provider with built-in `RustRE` resources.
    #[must_use] 
    pub fn with_rustre_defaults() -> Self {
        let provider = Self::new();
        provider.register_rustre_defaults();
        provider
    }

    /// Register a resource with an on-demand content factory.
    pub fn register(
        &self,
        descriptor: ResourceDescriptor,
        factory: impl Fn(Option<&Value>) -> ResourceContent + Send + Sync + 'static,
    ) {
        let uri = descriptor.uri.clone();
        self.resources.lock().unwrap().insert(
            uri.clone(),
            ResourceEntry {
                descriptor,
                factory: Arc::new(factory),
            },
        );
        let mut order = self.order.lock().unwrap();
        if !order.contains(&uri) {
            order.push(uri);
        }
    }

    /// Remove a resource by URI.
    pub fn unregister(&self, uri: &str) -> bool {
        let removed = self.resources.lock().unwrap().remove(uri).is_some();
        if removed {
            self.order.lock().unwrap().retain(|u| u != uri);
        }
        removed
    }

    /// Read a resource by URI with optional query parameters.
    pub fn read(&self, uri: &str, params: Option<&Value>) -> Option<ResourceContent> {
        let resources = self.resources.lock().unwrap();
        resources.get(uri).map(|entry| (entry.factory)(params))
    }

    /// List all registered resources.
    pub fn list(&self) -> Vec<ResourceDescriptor> {
        let resources = self.resources.lock().unwrap();
        let order = self.order.lock().unwrap();
        order
            .iter()
            .filter_map(|uri| resources.get(uri))
            .map(|e| e.descriptor.clone())
            .collect()
    }

    /// Build the MCP `resources/list` response.
    pub fn list_response(&self) -> Value {
        let entries: Vec<Value> = self.list().iter().map(ResourceDescriptor::to_json).collect();
        json!({ "resources": entries })
    }

    /// Build the MCP `resources/read` response for a URI.
    pub fn read_response(&self, uri: &str, params: Option<&Value>) -> Value {
        match self.read(uri, params) {
            Some(content) => json!({
                "contents": [content.to_mcp_object()]
            }),
            None => json!({
                "error": {
                    "code": -32002,
                    "message": format!("resource not found: {uri}")
                }
            }),
        }
    }

    /// Number of registered resources.
    pub fn len(&self) -> usize {
        self.resources.lock().unwrap().len()
    }

    /// True if no resources are registered.
    pub fn is_empty(&self) -> bool {
        self.resources.lock().unwrap().is_empty()
    }

    /// Register the standard set of RustRE-specific resources.
    fn register_rustre_defaults(&self) {
        // Binary sections resource
        self.register(
            ResourceDescriptor::new(
                ResourceUri::binary("sections").as_str(),
                "Binary Sections",
                "List of sections in the loaded binary",
                &ResourceMimeType::ApplicationJson,
            ),
            |_| {
                ResourceContent::json(
                    ResourceUri::binary("sections").as_str(),
                    &json!({ "sections": [] }),
                )
            },
        );

        // Binary imports resource
        self.register(
            ResourceDescriptor::new(
                ResourceUri::binary("imports").as_str(),
                "Binary Imports",
                "Imported symbols in the loaded binary",
                &ResourceMimeType::ApplicationJson,
            ),
            |_| {
                ResourceContent::json(
                    ResourceUri::binary("imports").as_str(),
                    &json!({ "imports": [] }),
                )
            },
        );

        // Binary exports resource
        self.register(
            ResourceDescriptor::new(
                ResourceUri::binary("exports").as_str(),
                "Binary Exports",
                "Exported symbols in the loaded binary",
                &ResourceMimeType::ApplicationJson,
            ),
            |_| {
                ResourceContent::json(
                    ResourceUri::binary("exports").as_str(),
                    &json!({ "exports": [] }),
                )
            },
        );

        // Taint analysis results resource
        self.register(
            ResourceDescriptor::new(
                ResourceUri::analysis("taint", "latest").as_str(),
                "Latest Taint Analysis",
                "Results of the most recent taint analysis run",
                &ResourceMimeType::ApplicationJson,
            ),
            |_| {
                ResourceContent::json(
                    ResourceUri::analysis("taint", "latest").as_str(),
                    &json!({ "findings": [], "source_count": 0 }),
                )
            },
        );

        // Disassembly at entry point
        self.register(
            ResourceDescriptor::new(
                ResourceUri::disasm(0).as_str(),
                "Entry Point Disassembly",
                "Disassembly starting at the binary entry point",
                &ResourceMimeType::TextPlain,
            ),
            |params| {
                let addr = params
                    .and_then(|p| p["address"].as_u64())
                    .unwrap_or(0);
                ResourceContent::plain(
                    ResourceUri::disasm(addr).as_str(),
                    format!("; Disassembly at 0x{addr:x}\n; (not yet wired to engine)"),
                )
            },
        );

        // Crypto detection results
        self.register(
            ResourceDescriptor::new(
                ResourceUri::analysis("crypto", "detections").as_str(),
                "Crypto Detection Results",
                "Cryptographic algorithm detections in the binary",
                &ResourceMimeType::ApplicationJson,
            ),
            |_| {
                ResourceContent::json(
                    ResourceUri::analysis("crypto", "detections").as_str(),
                    &json!({ "detections": [] }),
                )
            },
        );
    }
}

impl Default for McpResourceProvider {
    fn default() -> Self {
        Self::new()
    }
}

// ─── ChangeNotification ───────────────────────────────────────────────────────

/// Notification that a resource's content has changed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceChangeNotification {
    pub uri: String,
    pub timestamp_ns: u64,
    pub reason: String,
}

impl ResourceChangeNotification {
    pub fn new(uri: impl Into<String>, reason: impl Into<String>) -> Self {
        use std::time::{SystemTime, UNIX_EPOCH};
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        Self {
            uri: uri.into(),
            timestamp_ns: ts,
            reason: reason.into(),
        }
    }

    /// Build the MCP notification JSON.
    #[must_use] 
    pub fn to_notification(&self) -> Value {
        json!({
            "jsonrpc": "2.0",
            "method": "notifications/resources/updated",
            "params": {
                "uri": self.uri,
                "reason": self.reason
            }
        })
    }
}

/// A simple broadcast channel for resource change notifications.
pub struct ResourceChangePublisher {
    subscribers: Mutex<Vec<Arc<dyn Fn(ResourceChangeNotification) + Send + Sync>>>,
}

impl ResourceChangePublisher {
    #[must_use] 
    pub fn new() -> Self {
        Self {
            subscribers: Mutex::new(Vec::new()),
        }
    }

    /// Register a subscriber closure.
    pub fn subscribe(&self, cb: impl Fn(ResourceChangeNotification) + Send + Sync + 'static) {
        self.subscribers.lock().unwrap().push(Arc::new(cb));
    }

    /// Publish a change notification to all subscribers.
    pub fn publish(&self, notification: ResourceChangeNotification) {
        for sub in &*self.subscribers.lock().unwrap() {
            sub(notification.clone());
        }
    }

    /// Number of subscribers.
    pub fn subscriber_count(&self) -> usize {
        self.subscribers.lock().unwrap().len()
    }
}

impl Default for ResourceChangePublisher {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resource_uri_binary() {
        let uri = ResourceUri::binary("sections");
        assert_eq!(uri.as_str(), "rustre://binary/sections");
    }

    #[test]
    fn test_resource_uri_analysis() {
        let uri = ResourceUri::analysis("taint", "report");
        assert_eq!(uri.as_str(), "rustre://analysis/taint/report");
    }

    #[test]
    fn test_resource_uri_disasm() {
        let uri = ResourceUri::disasm(0x1000);
        assert_eq!(uri.as_str(), "rustre://disasm/0x1000");
    }

    #[test]
    fn test_resource_uri_path_component() {
        let uri = "rustre://binary/sections";
        assert_eq!(ResourceUri::path_component(uri), Some("sections"));
    }

    #[test]
    fn test_resource_uri_scheme() {
        assert_eq!(ResourceUri::scheme("rustre://binary/x"), Some("rustre"));
    }

    #[test]
    fn test_resource_content_text() {
        let c = ResourceContent::plain("rustre://test", "hello");
        match &c {
            ResourceContent::Text { text, .. } => assert_eq!(text, "hello"),
            _ => panic!("expected text"),
        }
    }

    #[test]
    fn test_resource_content_json() {
        let c = ResourceContent::json("rustre://test", &json!({"key": 1}));
        match &c {
            ResourceContent::Text { text, .. } => assert!(text.contains("key")),
            _ => panic!("expected text"),
        }
    }

    #[test]
    fn test_resource_content_blob() {
        let data = b"hello world";
        let c = ResourceContent::blob("rustre://test", &ResourceMimeType::ApplicationOctetStream, data);
        match &c {
            ResourceContent::Blob { blob, .. } => assert!(!blob.is_empty()),
            _ => panic!("expected blob"),
        }
    }

    #[test]
    fn test_resource_content_to_mcp_object() {
        let c = ResourceContent::plain("rustre://test", "text");
        let obj = c.to_mcp_object();
        assert_eq!(obj["uri"], "rustre://test");
        assert!(obj["text"].is_string());
    }

    #[test]
    fn test_provider_register_and_read() {
        let provider = McpResourceProvider::new();
        provider.register(
            ResourceDescriptor::new("rustre://test/res", "Test", "desc", &ResourceMimeType::TextPlain),
            |_| ResourceContent::plain("rustre://test/res", "content"),
        );
        let content = provider.read("rustre://test/res", None).unwrap();
        assert_eq!(content.uri(), "rustre://test/res");
    }

    #[test]
    fn test_provider_read_missing_returns_none() {
        let provider = McpResourceProvider::new();
        assert!(provider.read("rustre://missing", None).is_none());
    }

    #[test]
    fn test_provider_list() {
        let provider = McpResourceProvider::new();
        provider.register(
            ResourceDescriptor::new("rustre://a", "A", "", &ResourceMimeType::TextPlain),
            |_| ResourceContent::plain("rustre://a", ""),
        );
        provider.register(
            ResourceDescriptor::new("rustre://b", "B", "", &ResourceMimeType::TextPlain),
            |_| ResourceContent::plain("rustre://b", ""),
        );
        assert_eq!(provider.list().len(), 2);
    }

    #[test]
    fn test_provider_unregister() {
        let provider = McpResourceProvider::new();
        provider.register(
            ResourceDescriptor::new("rustre://del", "Del", "", &ResourceMimeType::TextPlain),
            |_| ResourceContent::plain("rustre://del", ""),
        );
        assert_eq!(provider.len(), 1);
        assert!(provider.unregister("rustre://del"));
        assert_eq!(provider.len(), 0);
        assert!(!provider.unregister("rustre://del"));
    }

    #[test]
    fn test_provider_list_response_shape() {
        let provider = McpResourceProvider::with_rustre_defaults();
        let resp = provider.list_response();
        let resources = resp["resources"].as_array().unwrap();
        assert!(!resources.is_empty());
        for r in resources {
            assert!(r["uri"].is_string());
            assert!(r["name"].is_string());
        }
    }

    #[test]
    fn test_provider_read_response_found() {
        let provider = McpResourceProvider::with_rustre_defaults();
        let uri = ResourceUri::binary("sections").to_string();
        let resp = provider.read_response(&uri, None);
        assert!(resp["contents"].as_array().is_some());
    }

    #[test]
    fn test_provider_read_response_not_found() {
        let provider = McpResourceProvider::new();
        let resp = provider.read_response("rustre://missing", None);
        assert!(resp["error"].is_object());
    }

    #[test]
    fn test_change_notification_to_json() {
        let n = ResourceChangeNotification::new("rustre://binary/sections", "reloaded");
        let j = n.to_notification();
        assert_eq!(j["method"], "notifications/resources/updated");
        assert_eq!(j["params"]["uri"], "rustre://binary/sections");
    }

    #[test]
    fn test_change_publisher_subscriber() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let pub_ = ResourceChangePublisher::new();
        let counter = Arc::new(AtomicUsize::new(0));
        let c = counter.clone();
        pub_.subscribe(move |_| {
            c.fetch_add(1, Ordering::Relaxed);
        });
        assert_eq!(pub_.subscriber_count(), 1);
        pub_.publish(ResourceChangeNotification::new("rustre://x", "test"));
        assert_eq!(counter.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_base64_encode_known() {
        let encoded = base64_encode(b"hello");
        assert_eq!(encoded, "aGVsbG8=");
    }

    #[test]
    fn test_base64_encode_empty() {
        assert_eq!(base64_encode(b""), "");
    }

    #[test]
    fn test_descriptor_to_json() {
        let d = ResourceDescriptor::new("rustre://x", "X", "desc", &ResourceMimeType::ApplicationJson);
        let j = d.to_json();
        assert_eq!(j["uri"], "rustre://x");
        assert_eq!(j["mimeType"], "application/json");
    }

    #[test]
    fn test_mime_type_as_str() {
        assert_eq!(ResourceMimeType::ApplicationJson.as_str(), "application/json");
        assert_eq!(ResourceMimeType::Custom("text/x-custom".into()).as_str(), "text/x-custom");
    }
}
