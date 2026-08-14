//! MCP wrappers for the rustre-frida crate.
//! Extracted from wire_tools.rs by workflow_split_wire_tools.

use rustre_mcp_server::{McpError, ToolDefinition, ToolHandler, ToolResult};
use serde_json::{json, Value};
use async_trait::async_trait;

pub struct FridaSessionInitialStateTool;

pub struct FridaMockStalkerEventsTool;

pub struct FridaDeviceDisplayTool;
impl FridaDeviceDisplayTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "frida_device_display".to_string(),
            description: "Format a Frida device descriptor (local/remote/usb) via its Display impl.".to_string(),
            input_schema: json!({
                "type": "object",
                "required": ["kind"],
                "properties": {
                    "kind": {"type": "string", "enum": ["local","remote","usb"]},
                    "value": {"type": "string"}
                }
            }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for FridaDeviceDisplayTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let kind = args.get("kind").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'kind'".into()))?;
        let value = args.get("value").and_then(Value::as_str).unwrap_or("").to_string();
        let dev = match kind {
            "local" => rustre_debug_frida::v2::FridaDevice::Local,
            "remote" => rustre_debug_frida::v2::FridaDevice::Remote(value),
            "usb" => rustre_debug_frida::v2::FridaDevice::Usb(value),
            _ => return Err(McpError::InvalidParams("bad kind".into())),
        };
        Ok(ToolResult::text(json!({
            "display": dev.to_string(),
            "source": "rustre_debug_frida::v2::FridaDevice"
        }).to_string()))
    }
}

pub struct FridaTargetLocalPidTool;
impl FridaTargetLocalPidTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "frida_target_local_pid".to_string(),
            description: "Build a FridaTarget for a local PID and report its fields.".to_string(),
            input_schema: json!({
                "type": "object",
                "required": ["pid"],
                "properties": {"pid": {"type": "integer", "minimum": 0}}
            }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for FridaTargetLocalPidTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let pid = args.get("pid").and_then(Value::as_u64)
            .ok_or_else(|| McpError::InvalidParams("missing 'pid'".into()))? as u32;
        let t = rustre_debug_frida::v2::FridaTarget::local_pid(pid);
        Ok(ToolResult::text(json!({
            "pid": t.pid,
            "process_name": t.process_name,
            "device": t.device.to_string(),
            "source": "rustre_debug_frida::v2::FridaTarget::local_pid"
        }).to_string()))
    }
}

pub struct FridaTargetLocalNameTool;
impl FridaTargetLocalNameTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "frida_target_local_name".to_string(),
            description: "Build a FridaTarget for a local process name.".to_string(),
            input_schema: json!({
                "type": "object",
                "required": ["name"],
                "properties": {"name": {"type": "string"}}
            }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for FridaTargetLocalNameTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let name = args.get("name").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'name'".into()))?;
        let t = rustre_debug_frida::v2::FridaTarget::local_name(name);
        Ok(ToolResult::text(json!({
            "pid": t.pid,
            "process_name": t.process_name,
            "device": t.device.to_string(),
            "source": "rustre_debug_frida::v2::FridaTarget::local_name"
        }).to_string()))
    }
}

pub struct FridaManagerAttachDetachTool;
impl FridaManagerAttachDetachTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "frida_manager_attach_detach".to_string(),
            description: "Create a FridaManager, attach a local-pid target, then detach; report counters.".to_string(),
            input_schema: json!({
                "type": "object",
                "required": ["pid"],
                "properties": {"pid": {"type": "integer", "minimum": 0}}
            }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for FridaManagerAttachDetachTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let pid = args.get("pid").and_then(Value::as_u64)
            .ok_or_else(|| McpError::InvalidParams("missing 'pid'".into()))? as u32;
        let mgr = rustre_debug_frida::v2::FridaManager::new();
        let sess = mgr.attach(rustre_debug_frida::v2::FridaTarget::local_pid(pid))
            .map_err(|e| McpError::InternalError(e.to_string()))?;
        let after_attach = mgr.session_count();
        let sid = sess.id;
        let attached = sess.is_attached();
        mgr.detach(sid).map_err(|e| McpError::InternalError(e.to_string()))?;
        let after_detach = mgr.session_count();
        Ok(ToolResult::text(json!({
            "session_id": sid,
            "attached": attached,
            "count_after_attach": after_attach,
            "count_after_detach": after_detach,
            "source": "rustre_debug_frida::v2::FridaManager"
        }).to_string()))
    }
}

pub struct FridaManagerAddInterceptorTool;
impl FridaManagerAddInterceptorTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "frida_manager_add_interceptor".to_string(),
            description: "Register an InterceptorRule with a FridaManager and report interceptor_count.".to_string(),
            input_schema: json!({
                "type": "object",
                "required": ["address"],
                "properties": {
                    "address": {"type": "integer"},
                    "on_enter": {"type": ["string","null"]},
                    "on_leave": {"type": ["string","null"]},
                    "id": {"type": "integer"}
                }
            }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for FridaManagerAddInterceptorTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let address = args.get("address").and_then(Value::as_u64)
            .ok_or_else(|| McpError::InvalidParams("missing 'address'".into()))?;
        let on_enter = args.get("on_enter").and_then(Value::as_str).map(String::from);
        let on_leave = args.get("on_leave").and_then(Value::as_str).map(String::from);
        let id = args.get("id").and_then(Value::as_u64).unwrap_or(1);
        let mgr = rustre_debug_frida::v2::FridaManager::new();
        mgr.add_interceptor(rustre_debug_frida::v2::InterceptorRule {
            address, on_enter, on_leave, id,
        });
        Ok(ToolResult::text(json!({
            "interceptor_count": mgr.interceptor_count(),
            "source": "rustre_debug_frida::v2::FridaManager::add_interceptor"
        }).to_string()))
    }
}

pub struct FridaStalkerEventDisplayTool;
impl FridaStalkerEventDisplayTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "frida_stalker_event_display".to_string(),
            description: "Format a StalkerEvent (call/block/compile) via its Display impl.".to_string(),
            input_schema: json!({
                "type": "object",
                "required": ["kind"],
                "properties": {
                    "kind": {"type": "string", "enum": ["call","block","compile"]},
                    "a": {"type": "integer"},
                    "b": {"type": "integer"}
                }
            }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for FridaStalkerEventDisplayTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let kind = args.get("kind").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'kind'".into()))?;
        let a = args.get("a").and_then(Value::as_u64).unwrap_or(0);
        let b = args.get("b").and_then(Value::as_u64).unwrap_or(0);
        let ev = match kind {
            "call" => rustre_debug_frida::v2::StalkerEvent::Call { from: a, to: b },
            "block" => rustre_debug_frida::v2::StalkerEvent::Block { start: a, end: b },
            "compile" => rustre_debug_frida::v2::StalkerEvent::Compile(a),
            _ => return Err(McpError::InvalidParams("bad kind".into())),
        };
        Ok(ToolResult::text(json!({
            "display": ev.to_string(),
            "source": "rustre_debug_frida::v2::StalkerEvent"
        }).to_string()))
    }
}

pub struct FridaSessionScriptCountTool;
impl FridaSessionScriptCountTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "frida_session_script_count".to_string(),
            description: "Build a FridaSession with N script ids, report is_attached and script_count.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "id": {"type": "integer"},
                    "pid": {"type": "integer"},
                    "scripts": {"type": "integer", "minimum": 0},
                    "attached": {"type": "boolean"}
                }
            }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for FridaSessionScriptCountTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let id = args.get("id").and_then(Value::as_u64).unwrap_or(1);
        let pid = args.get("pid").and_then(Value::as_u64).unwrap_or(0) as u32;
        let scripts = args.get("scripts").and_then(Value::as_u64).unwrap_or(0) as usize;
        let attached = args.get("attached").and_then(Value::as_bool).unwrap_or(false);
        let t = rustre_debug_frida::v2::FridaTarget::local_pid(pid);
        let mut s = rustre_debug_frida::v2::FridaSession::new(id, t);
        s.attached = attached;
        for i in 0..scripts { s.scripts.push(i as u64); }
        Ok(ToolResult::text(json!({
            "id": s.id,
            "attached": s.is_attached(),
            "script_count": s.script_count(),
            "source": "rustre_debug_frida::v2::FridaSession"
        }).to_string()))
    }
}

pub fn handlers() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    vec![
        (FridaSessionInitialStateTool::definition(), Box::new(FridaSessionInitialStateTool)),
        (FridaMockStalkerEventsTool::definition(), Box::new(FridaMockStalkerEventsTool)),
        (FridaDeviceDisplayTool::definition(), Box::new(FridaDeviceDisplayTool)),
        (FridaTargetLocalPidTool::definition(), Box::new(FridaTargetLocalPidTool)),
        (FridaTargetLocalNameTool::definition(), Box::new(FridaTargetLocalNameTool)),
        (FridaManagerAttachDetachTool::definition(), Box::new(FridaManagerAttachDetachTool)),
        (FridaManagerAddInterceptorTool::definition(), Box::new(FridaManagerAddInterceptorTool)),
        (FridaStalkerEventDisplayTool::definition(), Box::new(FridaStalkerEventDisplayTool)),
        (FridaSessionScriptCountTool::definition(), Box::new(FridaSessionScriptCountTool)),
    ]
}
