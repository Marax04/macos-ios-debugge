//! `debug.ios_describe_object` — live Objective-C / Swift object inspection.
//!
//! Until now the two runtime-inspection entry points of the Apple backend —
//! `rustre_debug::ios::apple_debugger::AppleDebugger::describe_objc_object` and
//! `::describe_swift_object` — were reachable ONLY from Rust. They are what a
//! debugger's `po` does: given a pointer into a live target, walk the
//! Objective-C `isa` chain (or the Swift type-metadata word) and name the
//! object. No MCP tool exposed them, so from the MCP surface an iOS target's
//! object graph was invisible.
//!
//! This module wires them up. It drives the SAME code those two methods drive —
//! `rustre_debug::ios::objc_runtime::ObjcRuntime::describe` and
//! `rustre_debug::ios::swift_runtime::type_name` over a
//! `ReaderMemory`/`ObjcMemoryAdapter` — but feeds it memory through the live
//! `debug.*` session registry (`tools::debug::session_read_memory`) instead of
//! through an `AppleDebugger` handle. Two consequences, both deliberate:
//!
//! * the natural session to use is one from `debug.ios_attach` (that IS an
//!   `AppleDebugger`), so the intended path is exactly the Rust one;
//! * it is not *restricted* to that backend: an Objective-C/Swift process
//!   debugged locally on macOS answers too, because the inspectors need only
//!   `read_memory`. A backend that cannot read the pointer fails loudly.
//!
//! There is NO mock fallback. An unknown `session_id` is an error, an unmapped
//! `isa` is an error; nothing here invents a class name.

use rustre_mcp_server::{McpError, ToolDefinition, ToolHandler, ToolResult};
use serde_json::{json, Value};
use async_trait::async_trait;
use std::sync::Arc;
use anyhow::{Result as AnyhowResult, anyhow};

use rustre_debug::ios::objc_runtime::{ObjcAbi, ObjcRuntime, ReaderMemory};
use rustre_debug::ios::swift_runtime::{type_name, ObjcMemoryAdapter, SwiftMemoryReader};

// ---------------------------------------------------------------------------
// Argument helpers (same shapes the rest of the debug.* surface accepts)
// ---------------------------------------------------------------------------

fn req_str<'a>(args: &'a Value, key: &str) -> AnyhowResult<&'a str> {
    args.get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("missing required field '{key}'"))
}

/// Accept an address as a JSON integer, a hex string (`"0x1040"`) or a decimal
/// string — the three shapes MCP clients actually send.
fn coerce_u64(v: &Value) -> Option<u64> {
    if let Some(n) = v.as_u64() {
        return Some(n);
    }
    if let Some(f) = v.as_f64()
        && f >= 0.0 && f.fract() == 0.0 {
            return Some(f as u64);
        }
    let s = v.as_str()?.trim();
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        return u64::from_str_radix(hex, 16).ok();
    }
    s.parse::<u64>().ok()
}

fn req_u64(args: &Value, key: &str) -> AnyhowResult<u64> {
    args.get(key)
        .and_then(coerce_u64)
        .ok_or_else(|| anyhow!("missing required field '{key}' (integer or hex string)"))
}

// ---------------------------------------------------------------------------
// SyncFnTool — sync closure as an async ToolHandler (same adapter as siblings)
// ---------------------------------------------------------------------------

type SyncFn = Arc<dyn Fn(Value) -> AnyhowResult<Value> + Send + Sync>;

struct SyncFnTool {
    f: SyncFn,
}

#[async_trait]
impl ToolHandler for SyncFnTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        match (self.f)(args) {
            Ok(v) => Ok(ToolResult::text(v.to_string())),
            Err(e) => Err(McpError::InternalError(e.to_string())),
        }
    }
}

fn make_tool(
    name: &'static str,
    description: &'static str,
    schema: Value,
    f: impl Fn(Value) -> AnyhowResult<Value> + Send + Sync + 'static,
) -> (ToolDefinition, Box<dyn ToolHandler>) {
    let def = ToolDefinition {
        name: name.to_string(),
        description: description.to_string(),
        input_schema: schema,
        parameters: Value::Null,
    };
    (def, Box::new(SyncFnTool { f: Arc::new(f) }))
}

// ---------------------------------------------------------------------------
// Which runtime to ask
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RuntimeChoice {
    Objc,
    Swift,
    /// Try Objective-C first, then Swift; report which one answered.
    Auto,
}

impl RuntimeChoice {
    fn parse(s: &str) -> AnyhowResult<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "auto" | "" => Ok(Self::Auto),
            "objc" | "objective-c" | "objectivec" => Ok(Self::Objc),
            "swift" => Ok(Self::Swift),
            other => Err(anyhow!(
                "unknown runtime '{other}': expected one of 'auto', 'objc', 'swift'"
            )),
        }
    }
}

fn parse_abi(s: &str) -> AnyhowResult<ObjcAbi> {
    match s.trim().to_ascii_lowercase().as_str() {
        "arm64" | "arm64e" | "aarch64" | "" => Ok(ObjcAbi::Arm64),
        "x86_64" | "x64" | "amd64" => Ok(ObjcAbi::X86_64),
        other => Err(anyhow!(
            "unknown abi '{other}': expected 'arm64' or 'x86_64' \
             (isa masks and tagged-pointer layouts differ between them)"
        )),
    }
}

// ---------------------------------------------------------------------------
// The two describe paths
// ---------------------------------------------------------------------------

/// Objective-C description, the body of `AppleDebugger::describe_objc_object`
/// with the session as its memory source.
fn describe_objc(session_id: &str, ptr: u64, abi: ObjcAbi) -> Result<String, String> {
    let mem = reader(session_id);
    ObjcRuntime::new(&mem, abi)
        .describe(ptr)
        .map_err(|e| format!("objc describe {ptr:#x}: {e}"))
}

/// Swift type name, the body of `AppleDebugger::describe_swift_object`: the
/// type-metadata pointer sits in the object's first word, exactly where an
/// Objective-C object keeps its `isa`.
fn describe_swift(session_id: &str, ptr: u64) -> Result<String, String> {
    let mem = reader(session_id);
    let adapter = ObjcMemoryAdapter(&mem);
    let metadata = adapter
        .read_u64(ptr)
        .map_err(|e| format!("swift metadata at {ptr:#x}: {e}"))?;
    type_name(&adapter, metadata).map_err(|e| format!("swift type at {ptr:#x}: {e}"))
}

/// Memory source for the inspectors: every read goes to the live session.
///
/// A read for a session that does not exist returns `None`, which the
/// inspectors report as an unreadable address; callers check session existence
/// FIRST (see the handler) so that case never reaches here in practice.
fn reader(session_id: &str) -> ReaderMemory<impl Fn(u64, usize) -> Option<Vec<u8>> + '_> {
    ReaderMemory(move |addr: u64, len: usize| {
        crate::tools::debug::session_read_memory(session_id, addr, len).and_then(Result::ok)
    })
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/// Error for a `session_id` that is not a live debug session — worded like the
/// rest of the `debug.*` surface, and never substituted with a fabricated
/// description.
fn no_live_session(id: &str) -> anyhow::Error {
    anyhow!(
        "no live debug session '{id}'. Call debug.session_list to see open sessions, or \
         debug.ios_attach (remote Apple target) / debug.attach to create one. This tool has \
         no mock fallback: every name it returns is read from real target memory."
    )
}

#[must_use]
pub fn handlers_ios_describe() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    vec![make_tool(
        "debug.ios_describe_object",
        "Describe the Objective-C or Swift object at an address in a LIVE target, the way a \
         debugger's 'po' would: walks the objc isa chain (decoding tagged pointers without any \
         memory read) or reads the Swift type-metadata word and resolves its fully-qualified \
         nominal type name. Exposes rustre_debug::ios::AppleDebugger::describe_objc_object / \
         describe_swift_object, previously reachable only from the Rust API. Use runtime='auto' \
         (default) to try Objective-C then Swift, or pin it with 'objc'/'swift'. The intended \
         session comes from debug.ios_attach, but any live session whose backend can read the \
         pointer works. No mock fallback: an unknown session, an unmapped isa, or a Swift kind \
         with no nominal name (tuples, functions, existentials) is an explicit error.",
        json!({
            "type": "object",
            "required": ["session_id", "address"],
            "properties": {
                "session_id": {
                    "type": "string",
                    "description": "id from debug.ios_attach / debug.attach / debug.launch"
                },
                "address": {
                    "description": "pointer to the object (integer or '0x...' string)",
                    "type": ["integer", "string"]
                },
                "runtime": {
                    "type": "string",
                    "enum": ["auto", "objc", "swift"],
                    "description": "which runtime to ask; 'auto' tries objc then swift"
                },
                "abi": {
                    "type": "string",
                    "enum": ["arm64", "x86_64"],
                    "description": "objc ABI: isa mask + tagged-pointer layout (default arm64)"
                }
            },
            "additionalProperties": false
        }),
        |args| {
            let session_id = req_str(&args, "session_id")?.to_string();
            let ptr = req_u64(&args, "address")?;
            let choice = RuntimeChoice::parse(
                args.get("runtime").and_then(Value::as_str).unwrap_or("auto"),
            )?;
            let abi = parse_abi(args.get("abi").and_then(Value::as_str).unwrap_or("arm64"))?;

            // Session existence is checked BEFORE any describe attempt, so a
            // bad id can never be reported as an unreadable address.
            let backend = crate::tools::debug::session_backend_name(&session_id)
                .ok_or_else(|| no_live_session(&session_id))?;

            let base = json!({
                "session_id": session_id,
                "address": format!("{ptr:#x}"),
                "backend": backend,
                "abi": if abi == ObjcAbi::Arm64 { "arm64" } else { "x86_64" },
                "live": true,
            });
            let mut out = base.as_object().cloned().unwrap_or_default();

            match choice {
                RuntimeChoice::Objc => {
                    let desc = describe_objc(&session_id, ptr, abi).map_err(|e| anyhow!(e))?;
                    out.insert("runtime".into(), json!("objc"));
                    out.insert("description".into(), json!(desc));
                    out.insert("source".into(), json!(
                        "rustre_debug::ios::objc_runtime::ObjcRuntime::describe \
                         (AppleDebugger::describe_objc_object)"
                    ));
                }
                RuntimeChoice::Swift => {
                    let name = describe_swift(&session_id, ptr).map_err(|e| anyhow!(e))?;
                    out.insert("runtime".into(), json!("swift"));
                    out.insert("description".into(), json!(name));
                    out.insert("source".into(), json!(
                        "rustre_debug::ios::swift_runtime::type_name \
                         (AppleDebugger::describe_swift_object)"
                    ));
                }
                RuntimeChoice::Auto => match describe_objc(&session_id, ptr, abi) {
                    Ok(desc) => {
                        out.insert("runtime".into(), json!("objc"));
                        out.insert("detected".into(), json!(true));
                        out.insert("description".into(), json!(desc));
                        out.insert("source".into(), json!(
                            "rustre_debug::ios::objc_runtime::ObjcRuntime::describe \
                             (AppleDebugger::describe_objc_object)"
                        ));
                    }
                    Err(objc_err) => {
                        // Both failing is reported with BOTH reasons: which one
                        // matters depends on what the pointer really was.
                        let name = describe_swift(&session_id, ptr).map_err(|swift_err| {
                            anyhow!(
                                "neither runtime could describe {ptr:#x}; \
                                 objc: {objc_err}; swift: {swift_err}"
                            )
                        })?;
                        out.insert("runtime".into(), json!("swift"));
                        out.insert("detected".into(), json!(true));
                        out.insert("description".into(), json!(name));
                        out.insert("objc_error".into(), json!(objc_err));
                        out.insert("source".into(), json!(
                            "rustre_debug::ios::swift_runtime::type_name \
                             (AppleDebugger::describe_swift_object)"
                        ));
                    }
                },
            }
            Ok(Value::Object(out))
        },
    )]
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustre_mcp_server::ContentBlock;

    fn text_of(r: &ToolResult) -> String {
        match &r.content[0] {
            ContentBlock::Text { text } => text.clone(),
            _ => String::new(),
        }
    }

    /// The tool exists on the debug.* surface (registered, not just written).
    #[test]
    fn tool_is_registered_on_the_debug_surface() {
        let names: Vec<String> = crate::tools::debug::handlers()
            .into_iter()
            .map(|(d, _)| d.name)
            .collect();
        assert!(
            names.iter().any(|n| n == "debug.ios_describe_object"),
            "debug.ios_describe_object not registered; debug.* tools present: {names:?}"
        );
    }

    /// An unknown session must fail loudly, with no invented description.
    #[tokio::test]
    async fn unknown_session_fails_honestly() {
        for runtime in ["auto", "objc", "swift"] {
            let (_, h) = handlers_ios_describe().pop().expect("one tool");
            let res = h
                .call(json!({
                    "session_id": "definitely_not_a_session_zzz",
                    "address": "0x1000",
                    "runtime": runtime,
                }))
                .await;
            match res {
                Err(McpError::InternalError(msg)) => assert!(
                    msg.contains("no live debug session"),
                    "runtime={runtime}: wrong error: {msg}"
                ),
                Err(other) => panic!("runtime={runtime}: unexpected error kind: {other:?}"),
                Ok(r) => assert!(
                    r.is_error,
                    "runtime={runtime}: answered for a session that does not exist: {}",
                    text_of(&r)
                ),
            }
        }
    }

    /// A tagged pointer needs no memory at all, so the objc path could in
    /// principle answer without a session. It must still refuse: the answer
    /// would be a claim about a process the caller does not have.
    #[tokio::test]
    async fn tagged_pointer_still_needs_a_real_session() {
        let (_, h) = handlers_ios_describe().pop().expect("one tool");
        // 0xb000...29 shape: tagged NSNumber on arm64.
        let res = h
            .call(json!({
                "session_id": "no_such_session_for_tagged",
                "address": "0xb000000000000292",
                "runtime": "objc",
            }))
            .await;
        match res {
            Err(McpError::InternalError(msg)) => {
                assert!(msg.contains("no live debug session"), "wrong error: {msg}");
            }
            Err(other) => panic!("unexpected error kind: {other:?}"),
            Ok(r) => assert!(
                r.is_error,
                "described a tagged pointer without a session: {}",
                text_of(&r)
            ),
        }
    }

    /// Bad enum values are rejected by name, not silently defaulted.
    #[tokio::test]
    async fn bad_runtime_and_abi_are_rejected() {
        let (_, h) = handlers_ios_describe().pop().expect("one tool");
        let res = h
            .call(json!({"session_id": "x", "address": 1, "runtime": "python"}))
            .await;
        let msg = match res {
            Err(McpError::InternalError(m)) => m,
            other => panic!("expected rejection, got {other:?}"),
        };
        assert!(msg.contains("unknown runtime 'python'"), "got: {msg}");

        let (_, h) = handlers_ios_describe().pop().expect("one tool");
        let res = h
            .call(json!({"session_id": "x", "address": 1, "abi": "riscv"}))
            .await;
        let msg = match res {
            Err(McpError::InternalError(m)) => m,
            other => panic!("expected rejection, got {other:?}"),
        };
        assert!(msg.contains("unknown abi 'riscv'"), "got: {msg}");
    }

    #[test]
    fn runtime_choice_parsing() {
        assert_eq!(RuntimeChoice::parse("AUTO").unwrap(), RuntimeChoice::Auto);
        assert_eq!(RuntimeChoice::parse("").unwrap(), RuntimeChoice::Auto);
        assert_eq!(RuntimeChoice::parse(" objc ").unwrap(), RuntimeChoice::Objc);
        assert_eq!(
            RuntimeChoice::parse("Objective-C").unwrap(),
            RuntimeChoice::Objc
        );
        assert_eq!(RuntimeChoice::parse("Swift").unwrap(), RuntimeChoice::Swift);
        assert!(RuntimeChoice::parse("objectiveC++").is_err());
    }

    #[test]
    fn abi_parsing() {
        assert_eq!(parse_abi("arm64e").unwrap(), ObjcAbi::Arm64);
        assert_eq!(parse_abi("X86_64").unwrap(), ObjcAbi::X86_64);
        assert!(parse_abi("mips").is_err());
    }
}
