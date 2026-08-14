//! `mcp_resource_provider` — Resource provider for the MCP server.
//!
//! Provides binary analysis resources (disassembly, strings, symbols, imports)
//! as readable MCP resources, with a `rustre://` URI scheme.

use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;

// ─────────────────────────────────────────────────────────────────────────────
// Error
// ─────────────────────────────────────────────────────────────────────────────

/// Errors produced by the resource provider.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResourceError {
    /// No resource was found for the given URI.
    NotFound(String),
    /// The URI is syntactically invalid.
    InvalidUri(String),
    /// The resource content could not be generated.
    ContentError { uri: String, message: String },
    /// The MIME type is not supported.
    UnsupportedMime(String),
    /// The provider for the given scheme is not registered.
    NoProvider(String),
}

impl fmt::Display for ResourceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound(u) => write!(f, "resource not found: {u}"),
            Self::InvalidUri(u) => write!(f, "invalid URI: {u}"),
            Self::ContentError { uri, message } => {
                write!(f, "content error for '{uri}': {message}")
            }
            Self::UnsupportedMime(m) => write!(f, "unsupported MIME type: {m}"),
            Self::NoProvider(s) => write!(f, "no provider for scheme: {s}"),
        }
    }
}

impl std::error::Error for ResourceError {}

// ─────────────────────────────────────────────────────────────────────────────
// MimeType
// ─────────────────────────────────────────────────────────────────────────────

/// Well-known MIME types used in binary analysis resources.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum MimeType {
    /// `application/json`
    Json,
    /// `text/plain`
    PlainText,
    /// `text/markdown`
    Markdown,
    /// `application/octet-stream`
    Binary,
    /// `text/x-asm`
    Assembly,
    /// `text/x-csrc`
    CSrc,
    /// Custom MIME type string.
    Custom(String),
}

impl MimeType {
    /// Parse from a MIME type string.
    #[must_use]
    pub fn from_str(s: &str) -> Self {
        match s {
            "application/json" => Self::Json,
            "text/plain" => Self::PlainText,
            "text/markdown" => Self::Markdown,
            "application/octet-stream" => Self::Binary,
            "text/x-asm" => Self::Assembly,
            "text/x-csrc" => Self::CSrc,
            other => Self::Custom(other.to_string()),
        }
    }

    /// Return the MIME type string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Json => "application/json",
            Self::PlainText => "text/plain",
            Self::Markdown => "text/markdown",
            Self::Binary => "application/octet-stream",
            Self::Assembly => "text/x-asm",
            Self::CSrc => "text/x-csrc",
            Self::Custom(s) => s.as_str(),
        }
    }

    /// Return `true` if this MIME type is text-based.
    #[must_use]
    pub fn is_text(&self) -> bool {
        matches!(
            self,
            Self::Json | Self::PlainText | Self::Markdown | Self::Assembly | Self::CSrc
        ) || matches!(self, Self::Custom(s) if s.starts_with("text/"))
    }
}

impl fmt::Display for MimeType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ResourceUri — parsed URI
// ─────────────────────────────────────────────────────────────────────────────

/// A parsed `rustre://` resource URI.
///
/// # URI structure
/// ```text
/// rustre://<resource-type>/<binary-id>/<subpath>
/// ```
/// Examples:
/// - `rustre://binary/main.exe/info`
/// - `rustre://function/main.exe/0x140001000/disasm`
/// - `rustre://string/main.exe/all`
/// - `rustre://imports/main.exe`
/// - `rustre://symbols/main.exe/exports`
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ResourceUri {
    /// Full original URI string.
    pub raw: String,
    /// Resource type path segment (e.g. `"binary"`, `"function"`, `"string"`).
    pub resource_type: String,
    /// Binary identifier (e.g. `"main.exe"`).
    pub binary_id: String,
    /// Additional path components (everything after `binary_id`).
    pub subpath: Vec<String>,
}

impl ResourceUri {
    /// Parse a `rustre://` URI.
    ///
    /// # Errors
    /// Returns [`ResourceError::InvalidUri`] if the URI does not conform to
    /// the `rustre://` scheme or is missing required components.
    pub fn parse(uri: &str) -> Result<Self, ResourceError> {
        let rest = uri
            .strip_prefix("rustre://")
            .ok_or_else(|| ResourceError::InvalidUri(uri.to_string()))?;

        let parts: Vec<&str> = rest.split('/').collect();
        if parts.len() < 2 {
            return Err(ResourceError::InvalidUri(format!(
                "URI must have at least two path components: {uri}"
            )));
        }

        let resource_type = parts[0].to_string();
        let binary_id = parts[1].to_string();
        let subpath = parts[2..].iter().map(|s| s.to_string()).collect();

        if resource_type.is_empty() || binary_id.is_empty() {
            return Err(ResourceError::InvalidUri(format!(
                "empty path component in URI: {uri}"
            )));
        }

        Ok(Self {
            raw: uri.to_string(),
            resource_type,
            binary_id,
            subpath,
        })
    }

    /// Construct a URI from components.
    #[must_use]
    pub fn build(resource_type: &str, binary_id: &str, subpath: &[&str]) -> Self {
        let sub = subpath.join("/");
        let raw = if sub.is_empty() {
            format!("rustre://{resource_type}/{binary_id}")
        } else {
            format!("rustre://{resource_type}/{binary_id}/{sub}")
        };
        Self {
            raw,
            resource_type: resource_type.to_string(),
            binary_id: binary_id.to_string(),
            subpath: subpath.iter().map(|s| s.to_string()).collect(),
        }
    }

    /// Return the first subpath component, if present.
    #[must_use]
    pub fn first_subpath(&self) -> Option<&str> {
        self.subpath.first().map(|s| s.as_str())
    }

    /// Return the full subpath as a `/`-joined string.
    #[must_use]
    pub fn subpath_str(&self) -> String {
        self.subpath.join("/")
    }
}

impl fmt::Display for ResourceUri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.raw)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ResourceDef — static resource definition
// ─────────────────────────────────────────────────────────────────────────────

/// A static definition for a resource that the server advertises to clients.
#[derive(Debug, Clone)]
pub struct ResourceDef {
    /// Full resource URI.
    pub uri: String,
    /// Short display name.
    pub name: String,
    /// Human-readable description.
    pub description: String,
    /// MIME type of the resource content.
    pub mime_type: MimeType,
    /// Template variables present in the URI (e.g. `{binary_id}`).
    pub uri_template: bool,
}

impl ResourceDef {
    /// Create a concrete (non-template) resource definition.
    #[must_use]
    pub fn new(
        uri: impl Into<String>,
        name: impl Into<String>,
        description: impl Into<String>,
        mime_type: MimeType,
    ) -> Self {
        Self {
            uri: uri.into(),
            name: name.into(),
            description: description.into(),
            mime_type,
            uri_template: false,
        }
    }

    /// Create a URI-template resource definition.
    #[must_use]
    pub fn template(
        uri: impl Into<String>,
        name: impl Into<String>,
        description: impl Into<String>,
        mime_type: MimeType,
    ) -> Self {
        Self {
            uri: uri.into(),
            name: name.into(),
            description: description.into(),
            mime_type,
            uri_template: true,
        }
    }

    /// Serialise to the MCP `resources/list` entry format.
    #[must_use]
    pub fn to_mcp_entry(&self) -> serde_json::Value {
        let mut obj = serde_json::json!({
            "name": self.name,
            "description": self.description,
            "mimeType": self.mime_type.as_str(),
        });
        if self.uri_template {
            obj["uriTemplate"] = serde_json::Value::String(self.uri.clone());
        } else {
            obj["uri"] = serde_json::Value::String(self.uri.clone());
        }
        obj
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ResourceContent — the payload returned for a resource/read
// ─────────────────────────────────────────────────────────────────────────────

/// The content returned for a `resources/read` request.
#[derive(Debug, Clone)]
pub struct ResourceContent {
    /// URI that was requested.
    pub uri: String,
    /// MIME type of the content.
    pub mime_type: MimeType,
    /// Text content (for text MIME types).
    pub text: Option<String>,
    /// Binary content (base64-encoded for JSON wire format).
    pub blob: Option<Vec<u8>>,
}

impl ResourceContent {
    /// Create text content.
    #[must_use]
    pub fn text(uri: impl Into<String>, mime: MimeType, content: impl Into<String>) -> Self {
        Self {
            uri: uri.into(),
            mime_type: mime,
            text: Some(content.into()),
            blob: None,
        }
    }

    /// Create binary content.
    #[must_use]
    pub fn binary(uri: impl Into<String>, content: Vec<u8>) -> Self {
        Self {
            uri: uri.into(),
            mime_type: MimeType::Binary,
            text: None,
            blob: Some(content),
        }
    }

    /// Create JSON text content.
    #[must_use]
    pub fn json(uri: impl Into<String>, value: &serde_json::Value) -> Self {
        let text = serde_json::to_string_pretty(value).unwrap_or_default();
        Self::text(uri, MimeType::Json, text)
    }

    /// Serialise to the MCP `resources/read` response format.
    #[must_use]
    pub fn to_mcp_response(&self) -> serde_json::Value {
        let content = if let Some(ref txt) = self.text {
            serde_json::json!({
                "uri": self.uri,
                "mimeType": self.mime_type.as_str(),
                "text": txt,
            })
        } else if let Some(ref blob) = self.blob {
            serde_json::json!({
                "uri": self.uri,
                "mimeType": self.mime_type.as_str(),
                "blob": encode_base64(blob),
            })
        } else {
            serde_json::json!({ "uri": self.uri, "mimeType": self.mime_type.as_str() })
        };

        serde_json::json!({ "contents": [content] })
    }

    /// Return the text content length in bytes, or blob length if binary.
    #[must_use]
    pub fn content_len(&self) -> usize {
        if let Some(ref t) = self.text {
            t.len()
        } else if let Some(ref b) = self.blob {
            b.len()
        } else {
            0
        }
    }
}

/// Minimal base64 encoder (no external crate).
fn encode_base64(data: &[u8]) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity((data.len() + 2) / 3 * 4);
    let mut i = 0;
    while i + 2 < data.len() {
        let v = (data[i] as u32) << 16 | (data[i + 1] as u32) << 8 | data[i + 2] as u32;
        out.push(CHARS[((v >> 18) & 0x3F) as usize] as char);
        out.push(CHARS[((v >> 12) & 0x3F) as usize] as char);
        out.push(CHARS[((v >> 6) & 0x3F) as usize] as char);
        out.push(CHARS[(v & 0x3F) as usize] as char);
        i += 3;
    }
    if data.len() - i == 1 {
        let v = (data[i] as u32) << 16;
        out.push(CHARS[((v >> 18) & 0x3F) as usize] as char);
        out.push(CHARS[((v >> 12) & 0x3F) as usize] as char);
        out.push('=');
        out.push('=');
    } else if data.len() - i == 2 {
        let v = (data[i] as u32) << 16 | (data[i + 1] as u32) << 8;
        out.push(CHARS[((v >> 18) & 0x3F) as usize] as char);
        out.push(CHARS[((v >> 12) & 0x3F) as usize] as char);
        out.push(CHARS[((v >> 6) & 0x3F) as usize] as char);
        out.push('=');
    }
    out
}

// ─────────────────────────────────────────────────────────────────────────────
// ResourceHandler — callable function type
// ─────────────────────────────────────────────────────────────────────────────

/// A boxed handler that resolves a parsed URI to [`ResourceContent`].
pub type ResourceHandler =
    Arc<dyn Fn(&ResourceUri) -> Result<ResourceContent, ResourceError> + Send + Sync>;

// ─────────────────────────────────────────────────────────────────────────────
// ResourceProvider
// ─────────────────────────────────────────────────────────────────────────────

/// Manages MCP resource definitions and resolves `resources/read` requests.
///
/// Handlers are registered per `resource_type` (the first path component of
/// the `rustre://` URI). Each handler receives a fully-parsed [`ResourceUri`]
/// and returns the content or an error.
pub struct ResourceProvider {
    /// Static resource definitions advertised in `resources/list`.
    defs: parking_lot::RwLock<Vec<ResourceDef>>,
    /// Per-resource-type handlers.
    handlers: parking_lot::RwLock<HashMap<String, ResourceHandler>>,
    /// Whether to include URI templates in the listing.
    include_templates: bool,
}

impl fmt::Debug for ResourceProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ResourceProvider")
            .field("def_count", &self.defs.read().len())
            .field("handler_count", &self.handlers.read().len())
            .finish_non_exhaustive()
    }
}

impl ResourceProvider {
    /// Create a new, empty provider.
    #[must_use]
    pub fn new() -> Self {
        Self {
            defs: parking_lot::RwLock::new(Vec::new()),
            handlers: parking_lot::RwLock::new(HashMap::new()),
            include_templates: true,
        }
    }

    /// Control whether URI templates are included in the listing.
    #[must_use]
    pub fn with_templates(mut self, include: bool) -> Self {
        self.include_templates = include;
        self
    }

    // ── Definition registration ───────────────────────────────────────────

    /// Register a static resource definition.
    pub fn add_resource(&self, def: ResourceDef) {
        self.defs.write().push(def);
    }

    /// Register multiple resource definitions at once.
    pub fn add_resources(&self, defs: impl IntoIterator<Item = ResourceDef>) {
        let mut guard = self.defs.write();
        for d in defs {
            guard.push(d);
        }
    }

    /// Number of registered definitions.
    #[must_use]
    pub fn def_count(&self) -> usize {
        self.defs.read().len()
    }

    // ── Handler registration ──────────────────────────────────────────────

    /// Register a handler for the given `resource_type`.
    ///
    /// The handler is called for every `rustre://<resource_type>/...` URI.
    pub fn register_handler(&self, resource_type: impl Into<String>, handler: ResourceHandler) {
        self.handlers.write().insert(resource_type.into(), handler);
    }

    /// Number of registered handlers.
    #[must_use]
    pub fn handler_count(&self) -> usize {
        self.handlers.read().len()
    }

    // ── MCP protocol methods ──────────────────────────────────────────────

    /// Produce the `resources/list` response.
    #[must_use]
    pub fn list_resources(&self) -> serde_json::Value {
        let guard = self.defs.read();
        let resources: Vec<serde_json::Value> = guard
            .iter()
            .filter(|d| self.include_templates || !d.uri_template)
            .map(|d| d.to_mcp_entry())
            .collect();

        serde_json::json!({ "resources": resources })
    }

    /// Resolve a `resources/read` request for the given URI string.
    ///
    /// # Errors
    /// Returns [`ResourceError`] on parse failure, missing handler, or handler error.
    pub fn read_resource(&self, uri: &str) -> Result<ResourceContent, ResourceError> {
        let parsed = ResourceUri::parse(uri)?;
        let handler = self
            .handlers
            .read()
            .get(&parsed.resource_type)
            .cloned()
            .ok_or_else(|| ResourceError::NoProvider(parsed.resource_type.clone()))?;

        handler(&parsed)
    }

    // ── Built-in static providers ─────────────────────────────────────────

    /// Register all standard RustRE resource types with stub handlers that
    /// return placeholder JSON. Production callers replace these handlers with
    /// implementations that read from the live analysis engine.
    pub fn register_default_stubs(&self) {
        self.add_resources(default_resource_defs());

        let make_stub = |label: &'static str| -> ResourceHandler {
            Arc::new(move |uri: &ResourceUri| {
                Ok(ResourceContent::json(
                    uri.raw.clone(),
                    &serde_json::json!({
                        "resource_type": label,
                        "binary_id": uri.binary_id,
                        "subpath": uri.subpath_str(),
                        "note": "stub — replace handler with live implementation",
                    }),
                ))
            })
        };

        for rt in &[
            "binary", "function", "string", "symbol", "import", "export", "section",
        ] {
            self.register_handler(*rt, make_stub(rt));
        }
    }
}

impl Default for ResourceProvider {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Default resource definitions
// ─────────────────────────────────────────────────────────────────────────────

/// Return the standard set of RustRE resource definitions.
#[must_use]
pub fn default_resource_defs() -> Vec<ResourceDef> {
    vec![
        ResourceDef::template(
            "rustre://binary/{binary_id}/info",
            "Binary metadata",
            "Architecture, file type, entry point, sections, and flags for a loaded binary.",
            MimeType::Json,
        ),
        ResourceDef::template(
            "rustre://binary/{binary_id}/hex/{offset}/{length}",
            "Hex dump",
            "Raw bytes at the given virtual address displayed as a hex dump.",
            MimeType::PlainText,
        ),
        ResourceDef::template(
            "rustre://function/{binary_id}/{address}/disasm",
            "Function disassembly",
            "Disassembly listing for the function at the given virtual address.",
            MimeType::Assembly,
        ),
        ResourceDef::template(
            "rustre://function/{binary_id}/{address}/pseudo_c",
            "Function pseudo-C",
            "Decompiled pseudo-C source for the function at the given virtual address.",
            MimeType::CSrc,
        ),
        ResourceDef::template(
            "rustre://function/{binary_id}/{address}/cfg",
            "Control-flow graph",
            "Basic blocks and edges of the CFG for the function at the given address.",
            MimeType::Json,
        ),
        ResourceDef::template(
            "rustre://string/{binary_id}/all",
            "All strings",
            "All strings discovered in the binary (address, encoding, value).",
            MimeType::Json,
        ),
        ResourceDef::template(
            "rustre://symbol/{binary_id}/all",
            "All symbols",
            "All symbols (functions, globals, labels) in the binary.",
            MimeType::Json,
        ),
        ResourceDef::template(
            "rustre://import/{binary_id}/all",
            "Import table",
            "All imported functions and their thunk addresses.",
            MimeType::Json,
        ),
        ResourceDef::template(
            "rustre://export/{binary_id}/all",
            "Export table",
            "All exported symbols and their addresses.",
            MimeType::Json,
        ),
        ResourceDef::template(
            "rustre://section/{binary_id}/all",
            "Section list",
            "All sections with their virtual and file offsets, sizes, and permissions.",
            MimeType::Json,
        ),
    ]
}

// ─────────────────────────────────────────────────────────────────────────────
// ResourceProviderBuilder — fluent API
// ─────────────────────────────────────────────────────────────────────────────

/// Fluent builder for constructing a [`ResourceProvider`].
pub struct ResourceProviderBuilder {
    provider: ResourceProvider,
}

impl ResourceProviderBuilder {
    /// Create a new builder.
    #[must_use]
    pub fn new() -> Self {
        Self {
            provider: ResourceProvider::new(),
        }
    }

    /// Add a resource definition.
    #[must_use]
    pub fn resource(self, def: ResourceDef) -> Self {
        self.provider.add_resource(def);
        self
    }

    /// Register a handler.
    #[must_use]
    pub fn handler(self, resource_type: impl Into<String>, handler: ResourceHandler) -> Self {
        self.provider.register_handler(resource_type, handler);
        self
    }

    /// Finish and return the provider.
    #[must_use]
    pub fn build(self) -> ResourceProvider {
        self.provider
    }
}

impl Default for ResourceProviderBuilder {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_valid_uri() {
        let u = ResourceUri::parse("rustre://binary/foo.exe/info").unwrap();
        assert_eq!(u.resource_type, "binary");
        assert_eq!(u.binary_id, "foo.exe");
        assert_eq!(u.subpath, vec!["info"]);
    }

    #[test]
    fn parse_uri_no_subpath() {
        let u = ResourceUri::parse("rustre://import/bar.dll/all").unwrap();
        assert_eq!(u.resource_type, "import");
        assert_eq!(u.subpath, vec!["all"]);
    }

    #[test]
    fn parse_invalid_scheme_returns_error() {
        let e = ResourceUri::parse("http://foo/bar").unwrap_err();
        assert!(matches!(e, ResourceError::InvalidUri(_)));
    }

    #[test]
    fn build_uri() {
        let u = ResourceUri::build("function", "main.exe", &["0x1000", "disasm"]);
        assert_eq!(u.raw, "rustre://function/main.exe/0x1000/disasm");
    }

    #[test]
    fn mime_type_is_text() {
        assert!(MimeType::Json.is_text());
        assert!(MimeType::PlainText.is_text());
        assert!(!MimeType::Binary.is_text());
    }

    #[test]
    fn resource_content_mcp_response_text() {
        let c = ResourceContent::text("rustre://string/a/all", MimeType::Json, r#"{"x":1}"#);
        let resp = c.to_mcp_response();
        let contents = resp["contents"].as_array().unwrap();
        assert!(!contents.is_empty());
        assert_eq!(contents[0]["mimeType"], "application/json");
    }

    #[test]
    fn resource_content_binary_base64() {
        let c = ResourceContent::binary("rustre://binary/foo/hex", vec![0xDE, 0xAD, 0xBE, 0xEF]);
        let resp = c.to_mcp_response();
        let blob = resp["contents"][0]["blob"].as_str().unwrap();
        assert!(!blob.is_empty());
    }

    #[test]
    fn provider_read_with_stub() {
        let prov = ResourceProvider::new();
        prov.register_default_stubs();
        let content = prov
            .read_resource("rustre://binary/test.exe/info")
            .unwrap();
        assert!(content.text.is_some());
        assert_eq!(content.mime_type, MimeType::Json);
    }

    #[test]
    fn provider_no_handler_returns_no_provider_error() {
        let prov = ResourceProvider::new();
        let err = prov
            .read_resource("rustre://unknown/foo/bar")
            .unwrap_err();
        assert!(matches!(err, ResourceError::NoProvider(_)));
    }

    #[test]
    fn provider_list_includes_templates() {
        let prov = ResourceProvider::new();
        prov.register_default_stubs();
        let listing = prov.list_resources();
        let resources = listing["resources"].as_array().unwrap();
        assert!(!resources.is_empty());
    }

    #[test]
    fn base64_encode_roundtrip() {
        let data = b"Hello, MCP!";
        let encoded = encode_base64(data);
        assert!(!encoded.is_empty());
        assert!(encoded.len() > data.len());
    }

    #[test]
    fn resource_def_mcp_entry_template() {
        let d = ResourceDef::template(
            "rustre://fn/{id}/disasm",
            "fn_disasm",
            "desc",
            MimeType::Assembly,
        );
        let entry = d.to_mcp_entry();
        assert!(entry["uriTemplate"].as_str().is_some());
    }

    #[test]
    fn resource_def_mcp_entry_concrete() {
        let d = ResourceDef::new(
            "rustre://binary/a.out/info",
            "a.out info",
            "desc",
            MimeType::Json,
        );
        let entry = d.to_mcp_entry();
        assert!(entry["uri"].as_str().is_some());
    }
}
