//! MCP wrappers for the rustre-adb crate.
//! Extracted from `wire_tools.rs` by `workflow_split_wire_tools`.

use rustre_mcp_server::{McpError, ToolDefinition, ToolHandler, ToolResult};
use serde_json::{json, Value};
use async_trait::async_trait;
use crate::{args_to_bytes};
use crate::wire_tools::{__adb_hex, __adb_state_from_str};

pub struct AdbComputeCrc32Tool;

pub struct AdbParseLogcatTool;

pub struct AdbEncodeMessageTool;

pub struct AdbDecodeMessageTool;

pub struct AdbParseLogcatLineTool;

pub struct AdbFilterByLevelTool;

pub struct AdbFilterByTagTool;

pub struct AdbGroupByTagTool;

pub struct AdbParseDevicesOutputTool;

pub struct AdbParseBriefLineTool;

pub struct AdbParseThreadtimeLineTool;

pub struct AdbShellEscapeTool;

pub struct AdbInstallSucceededTool;

pub struct AdbUninstallSucceededTool;

pub struct AdbParsePmListLineTool;
impl AdbParsePmListLineTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "adb_parse_pm_list_line".to_string(),
            description: "Parse a single `pm list packages [-f]` output line.".to_string(),
            input_schema: json!({"type":"object","required":["line"],"properties":{"line":{"type":"string"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for AdbParsePmListLineTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let line = args.get("line").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'line'".into()))?;
        let info = rustre_adb::parse_pm_list_line(line);
        Ok(ToolResult::text(json!({"package": info}).to_string()))
    }
}

pub struct AdbParsePmListOutputTool;
impl AdbParsePmListOutputTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "adb_parse_pm_list_output".to_string(),
            description: "Parse full `pm list packages` output.".to_string(),
            input_schema: json!({"type":"object","required":["output"],"properties":{"output":{"type":"string"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for AdbParsePmListOutputTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let output = args.get("output").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'output'".into()))?;
        let pkgs = rustre_adb::parse_pm_list_output(output);
        let n = pkgs.len();
        Ok(ToolResult::text(json!({"packages": pkgs, "count": n}).to_string()))
    }
}

pub struct AdbBuildInstallCommandTool;
impl AdbBuildInstallCommandTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "adb_build_install_command".to_string(),
            description: "Build a `pm install -r` shell command string.".to_string(),
            input_schema: json!({"type":"object","required":["remote_apk"],"properties":{"remote_apk":{"type":"string"},"options":{"type":"array","items":{"type":"string"}}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for AdbBuildInstallCommandTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let remote = args.get("remote_apk").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'remote_apk'".into()))?;
        let opts_owned: Vec<String> = args.get("options").and_then(Value::as_array)
            .map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_owned)).collect())
            .unwrap_or_default();
        let opts_ref: Vec<&str> = opts_owned.iter().map(String::as_str).collect();
        let cmd = rustre_adb::build_install_command(remote, &opts_ref);
        Ok(ToolResult::text(json!({"command": cmd}).to_string()))
    }
}

pub struct AdbBuildUninstallCommandTool;
impl AdbBuildUninstallCommandTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "adb_build_uninstall_command".to_string(),
            description: "Build a `pm uninstall` shell command string.".to_string(),
            input_schema: json!({"type":"object","required":["package"],"properties":{"package":{"type":"string"},"keep_data":{"type":"boolean"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for AdbBuildUninstallCommandTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let pkg = args.get("package").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'package'".into()))?;
        let keep = args.get("keep_data").and_then(Value::as_bool).unwrap_or(false);
        let cmd = rustre_adb::build_uninstall_command(pkg, keep);
        Ok(ToolResult::text(json!({"command": cmd}).to_string()))
    }
}

pub struct AdbMsgConnectTool;
impl AdbMsgConnectTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "adb_msg_connect".to_string(),
            description: "Build a CNXN ADB wire message.".to_string(),
            input_schema: json!({"type":"object","required":["system_id","banner"],"properties":{"system_id":{"type":"string"},"banner":{"type":"string"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for AdbMsgConnectTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let sid = args.get("system_id").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'system_id'".into()))?;
        let banner = args.get("banner").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'banner'".into()))?;
        let m = rustre_adb::adb_protocol::msg_connect(sid, banner);
        Ok(ToolResult::text(json!({"message": m}).to_string()))
    }
}

pub struct AdbMsgOpenTool;
impl AdbMsgOpenTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "adb_msg_open".to_string(),
            description: "Build an OPEN ADB wire message for a service.".to_string(),
            input_schema: json!({"type":"object","required":["local_id","service"],"properties":{"local_id":{"type":"integer"},"service":{"type":"string"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for AdbMsgOpenTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let lid = args.get("local_id").and_then(Value::as_u64)
            .ok_or_else(|| McpError::InvalidParams("missing 'local_id'".into()))? as u32;
        let service = args.get("service").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'service'".into()))?;
        let m = rustre_adb::adb_protocol::msg_open(lid, service);
        Ok(ToolResult::text(json!({"message": m}).to_string()))
    }
}

pub struct AdbMsgOkayTool;
impl AdbMsgOkayTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "adb_msg_okay".to_string(),
            description: "Build an OKAY ADB wire message.".to_string(),
            input_schema: json!({"type":"object","required":["local_id","remote_id"],"properties":{"local_id":{"type":"integer"},"remote_id":{"type":"integer"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for AdbMsgOkayTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let lid = args.get("local_id").and_then(Value::as_u64)
            .ok_or_else(|| McpError::InvalidParams("missing 'local_id'".into()))? as u32;
        let rid = args.get("remote_id").and_then(Value::as_u64)
            .ok_or_else(|| McpError::InvalidParams("missing 'remote_id'".into()))? as u32;
        let m = rustre_adb::adb_protocol::msg_okay(lid, rid);
        Ok(ToolResult::text(json!({"message": m}).to_string()))
    }
}

pub struct AdbMsgCloseTool;
impl AdbMsgCloseTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "adb_msg_close".to_string(),
            description: "Build a CLSE ADB wire message.".to_string(),
            input_schema: json!({"type":"object","required":["local_id","remote_id"],"properties":{"local_id":{"type":"integer"},"remote_id":{"type":"integer"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for AdbMsgCloseTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let lid = args.get("local_id").and_then(Value::as_u64)
            .ok_or_else(|| McpError::InvalidParams("missing 'local_id'".into()))? as u32;
        let rid = args.get("remote_id").and_then(Value::as_u64)
            .ok_or_else(|| McpError::InvalidParams("missing 'remote_id'".into()))? as u32;
        let m = rustre_adb::adb_protocol::msg_close(lid, rid);
        Ok(ToolResult::text(json!({"message": m}).to_string()))
    }
}

pub struct AdbMsgWriteTool;
impl AdbMsgWriteTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "adb_msg_write".to_string(),
            description: "Build a WRTE ADB wire message. Data may be hex string or byte array.".to_string(),
            input_schema: json!({"type":"object","required":["local_id","remote_id","data"],"properties":{"local_id":{"type":"integer"},"remote_id":{"type":"integer"},"data":{}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for AdbMsgWriteTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let lid = args.get("local_id").and_then(Value::as_u64)
            .ok_or_else(|| McpError::InvalidParams("missing 'local_id'".into()))? as u32;
        let rid = args.get("remote_id").and_then(Value::as_u64)
            .ok_or_else(|| McpError::InvalidParams("missing 'remote_id'".into()))? as u32;
        let data = args_to_bytes(args.get("data").unwrap_or(&Value::Null))?;
        let m = rustre_adb::adb_protocol::msg_write(lid, rid, data);
        Ok(ToolResult::text(json!({"message": m}).to_string()))
    }
}

pub struct AdbMsgAuthTool;
impl AdbMsgAuthTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "adb_msg_auth".to_string(),
            description: "Build an AUTH ADB wire message.".to_string(),
            input_schema: json!({"type":"object","required":["auth_type","data"],"properties":{"auth_type":{"type":"integer"},"data":{}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for AdbMsgAuthTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let at = args.get("auth_type").and_then(Value::as_u64)
            .ok_or_else(|| McpError::InvalidParams("missing 'auth_type'".into()))? as u32;
        let data = args_to_bytes(args.get("data").unwrap_or(&Value::Null))?;
        let m = rustre_adb::adb_protocol::msg_auth(at, data);
        Ok(ToolResult::text(json!({"message": m}).to_string()))
    }
}

pub struct AdbParseGetpropOutputTool;
impl AdbParseGetpropOutputTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "adb_parse_getprop_output".to_string(),
            description: "Parse `getprop` output into a key/value map.".to_string(),
            input_schema: json!({"type":"object","required":["output"],"properties":{"output":{"type":"string"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for AdbParseGetpropOutputTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let output = args.get("output").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'output'".into()))?;
        let map = rustre_adb::device_profiler::parse_getprop_output(output);
        let n = map.len();
        Ok(ToolResult::text(json!({"props": map, "count": n}).to_string()))
    }
}

pub struct AdbParseDevicesLongTool;
impl AdbParseDevicesLongTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "adb_parse_devices_long".to_string(),
            description: "Parse `adb devices -l` output into DeviceInfo entries.".to_string(),
            input_schema: json!({"type":"object","required":["output"],"properties":{"output":{"type":"string"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for AdbParseDevicesLongTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let output = args.get("output").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'output'".into()))?;
        let devs = rustre_adb::device_manager::parse_devices_long(output);
        let n = devs.len();
        Ok(ToolResult::text(json!({"devices": devs, "count": n}).to_string()))
    }
}

pub struct AdbMakeCloseTool;

pub struct AdbParseFeaturesTool;

pub struct AdbLogLevelAsCharTool;
impl AdbLogLevelAsCharTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "adb_log_level_as_char".to_string(),
            description: "Return the single glyph (V/D/I/W/E/F/S) for the given LogLevel name.".to_string(),
            input_schema: json!({
                "type":"object","required":["level"],
                "properties":{"level":{"type":"string","description":"Verbose|Debug|Info|Warning|Error|Fatal|Silent"}}
            }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for AdbLogLevelAsCharTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let level = args.get("level").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'level'".into()))?;
        let lvl: rustre_adb::LogLevel = match level {
            "Verbose"|"verbose"|"V"|"v" => rustre_adb::LogLevel::Verbose,
            "Debug"|"debug"|"D"|"d" => rustre_adb::LogLevel::Debug,
            "Info"|"info"|"I"|"i" => rustre_adb::LogLevel::Info,
            "Warning"|"warning"|"W"|"w" => rustre_adb::LogLevel::Warning,
            "Error"|"error"|"E"|"e" => rustre_adb::LogLevel::Error,
            "Fatal"|"fatal"|"F"|"f" => rustre_adb::LogLevel::Fatal,
            "Silent"|"silent"|"S"|"s" => rustre_adb::LogLevel::Silent,
            _ => return Err(McpError::InvalidParams(format!("unknown level {level}"))),
        };
        Ok(ToolResult::text(json!({"char": lvl.as_char().to_string()}).to_string()))
    }
}

pub struct AdbLogLevelSeverityTool;
impl AdbLogLevelSeverityTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "adb_log_level_severity".to_string(),
            description: "Return numeric severity (2..8) for a LogLevel name.".to_string(),
            input_schema: json!({"type":"object","required":["level"],"properties":{"level":{"type":"string"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for AdbLogLevelSeverityTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let level = args.get("level").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'level'".into()))?;
        let lvl: rustre_adb::LogLevel = match level {
            "Verbose"|"verbose"|"V"|"v" => rustre_adb::LogLevel::Verbose,
            "Debug"|"debug"|"D"|"d" => rustre_adb::LogLevel::Debug,
            "Info"|"info"|"I"|"i" => rustre_adb::LogLevel::Info,
            "Warning"|"warning"|"W"|"w" => rustre_adb::LogLevel::Warning,
            "Error"|"error"|"E"|"e" => rustre_adb::LogLevel::Error,
            "Fatal"|"fatal"|"F"|"f" => rustre_adb::LogLevel::Fatal,
            "Silent"|"silent"|"S"|"s" => rustre_adb::LogLevel::Silent,
            _ => return Err(McpError::InvalidParams(format!("unknown level {level}"))),
        };
        Ok(ToolResult::text(json!({"severity": lvl.severity()}).to_string()))
    }
}

pub struct AdbDeviceStateClassifyTool;
impl AdbDeviceStateClassifyTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "adb_device_state_classify".to_string(),
            description: "Classify a device state string (device/offline/unauthorized/...) into normalized name plus is_online/needs_auth flags.".to_string(),
            input_schema: json!({"type":"object","required":["state"],"properties":{"state":{"type":"string"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for AdbDeviceStateClassifyTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let s = args.get("state").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'state'".into()))?;
        let state: rustre_adb::DeviceState = match s.trim().to_ascii_lowercase().as_str() {
            "offline" => rustre_adb::DeviceState::Offline,
            "bootloader" => rustre_adb::DeviceState::Bootloader,
            "device" => rustre_adb::DeviceState::Device,
            "host" => rustre_adb::DeviceState::Host,
            "recovery" => rustre_adb::DeviceState::Recovery,
            "no permissions"|"no-permissions" => rustre_adb::DeviceState::NoPermissions,
            "sideload" => rustre_adb::DeviceState::Sideload,
            "unauthorized" => rustre_adb::DeviceState::Unauthorized,
            _ => rustre_adb::DeviceState::Unknown,
        };
        Ok(ToolResult::text(json!({
            "state": state.to_string(),
            "is_online": state.is_online(),
            "needs_auth": state.needs_auth(),
        }).to_string()))
    }
}

pub struct AdbMessageNewTool;
impl AdbMessageNewTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "adb_message_new".to_string(),
            description: "Build an AdbMessage from (command, arg0, arg1, data_hex) and return computed crc32/magic plus wire encoding.".to_string(),
            input_schema: json!({
                "type":"object","required":["command","arg0","arg1"],
                "properties":{
                    "command":{"type":"integer"},"arg0":{"type":"integer"},"arg1":{"type":"integer"},
                    "data_hex":{"type":"string"}
                }
            }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for AdbMessageNewTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let command = args.get("command").and_then(Value::as_u64)
            .ok_or_else(|| McpError::InvalidParams("missing 'command'".into()))? as u32;
        let arg0 = args.get("arg0").and_then(Value::as_u64)
            .ok_or_else(|| McpError::InvalidParams("missing 'arg0'".into()))? as u32;
        let arg1 = args.get("arg1").and_then(Value::as_u64)
            .ok_or_else(|| McpError::InvalidParams("missing 'arg1'".into()))? as u32;
        let data: Vec<u8> = if let Some(h) = args.get("data_hex").and_then(Value::as_str) {
            let clean: String = h.chars().filter(|c| !c.is_whitespace()).collect();
            (0..clean.len()).step_by(2)
                .map(|i| u8::from_str_radix(&clean[i..(i+2).min(clean.len())], 16).unwrap_or(0))
                .collect()
        } else { Vec::new() };
        let msg = rustre_adb::AdbMessage::new(command, arg0, arg1, data);
        let encoded = msg.encode();
        let hex_out: String = encoded.iter().map(|b| format!("{:02x}", b)).collect();
        Ok(ToolResult::text(json!({
            "command": msg.command,
            "command_name": msg.command_name(),
            "crc32": msg.crc32,
            "magic": msg.magic,
            "verify_crc": msg.verify_crc(),
            "hex": hex_out,
            "len": encoded.len(),
        }).to_string()))
    }
}

pub struct AdbMessageVerifyCrcTool;
impl AdbMessageVerifyCrcTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "adb_message_verify_crc".to_string(),
            description: "Recompute the ADB checksum for a payload and compare with a claimed crc32.".to_string(),
            input_schema: json!({
                "type":"object","required":["crc32","data_hex"],
                "properties":{"crc32":{"type":"integer"},"data_hex":{"type":"string"}}
            }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for AdbMessageVerifyCrcTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let crc32 = args.get("crc32").and_then(Value::as_u64)
            .ok_or_else(|| McpError::InvalidParams("missing 'crc32'".into()))? as u32;
        let h = args.get("data_hex").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'data_hex'".into()))?;
        let clean: String = h.chars().filter(|c| !c.is_whitespace()).collect();
        let data: Vec<u8> = (0..clean.len()).step_by(2)
            .map(|i| u8::from_str_radix(&clean[i..(i+2).min(clean.len())], 16).unwrap_or(0))
            .collect();
        let computed = rustre_adb::compute_crc32(&data);
        Ok(ToolResult::text(json!({
            "computed": computed,
            "claimed": crc32,
            "verified": computed == crc32,
        }).to_string()))
    }
}

pub struct AdbMessageCommandNameTool;
impl AdbMessageCommandNameTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "adb_message_command_name".to_string(),
            description: "Return the mnemonic (CNXN/AUTH/OPEN/OKAY/CLSE/WRTE/SYNC/UNKNOWN) for an ADB command word.".to_string(),
            input_schema: json!({"type":"object","required":["command"],"properties":{"command":{"type":"integer"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for AdbMessageCommandNameTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let command = args.get("command").and_then(Value::as_u64)
            .ok_or_else(|| McpError::InvalidParams("missing 'command'".into()))? as u32;
        let msg = rustre_adb::AdbMessage::new(command, 0, 0, Vec::new());
        Ok(ToolResult::text(json!({"name": msg.command_name()}).to_string()))
    }
}

pub struct AdbParseLogcatOutputTool;
impl AdbParseLogcatOutputTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "adb_parse_logcat_output".to_string(),
            description: "Parse multi-line logcat text into LogEntry records; returns count and entries.".to_string(),
            input_schema: json!({"type":"object","required":["text"],"properties":{"text":{"type":"string"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for AdbParseLogcatOutputTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let text = args.get("text").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'text'".into()))?;
        let entries = rustre_adb::parse_logcat_output(text);
        Ok(ToolResult::text(json!({
            "count": entries.len(),
            "entries": serde_json::to_value(&entries).unwrap_or(Value::Null),
        }).to_string()))
    }
}

pub struct AdbCommandConstantTool;
impl AdbCommandConstantTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "adb_command_constant".to_string(),
            description: "Return the u32 command word for an ADB mnemonic (CNXN/AUTH/OPEN/OKAY/CLSE/WRTE/SYNC).".to_string(),
            input_schema: json!({"type":"object","required":["name"],"properties":{"name":{"type":"string"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for AdbCommandConstantTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let name = args.get("name").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'name'".into()))?;
        let (cmd_u32, ok) = match name.to_ascii_uppercase().as_str() {
            "CNXN" => (rustre_adb::cmd::CNXN, true),
            "AUTH" => (rustre_adb::cmd::AUTH, true),
            "OPEN" => (rustre_adb::cmd::OPEN, true),
            "OKAY" => (rustre_adb::cmd::OKAY, true),
            "CLSE" => (rustre_adb::cmd::CLSE, true),
            "WRTE" => (rustre_adb::cmd::WRTE, true),
            "SYNC" => (rustre_adb::cmd::SYNC, true),
            _ => (0u32, false),
        };
        Ok(ToolResult::text(json!({"command": cmd_u32, "found": ok, "magic": cmd_u32 ^ 0xFFFF_FFFFu32}).to_string()))
    }
}

pub struct AdbBuildBannerTool;

pub struct AdbMakeOkayTool;

pub struct AdbMakeConnectTool;
impl AdbMakeConnectTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "adb_make_connect".to_string(),
            description: "Build an ADB CNXN message via rustre_adb::make_connect and return its hex encoding.".to_string(),
            input_schema: json!({"type":"object","required":["system_type","banner"],"properties":{"system_type":{"type":"string"},"banner":{"type":"string"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for AdbMakeConnectTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let st = args.get("system_type").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'system_type'".into()))?;
        let bn = args.get("banner").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'banner'".into()))?;
        let m = rustre_adb::make_connect(st, bn);
        let enc = m.encode();
        Ok(ToolResult::text(json!({"command":m.command,"command_name":m.command_name(),"hex":__adb_hex(&enc),"len":enc.len()}).to_string()))
    }
}

pub struct AdbMakeConnectDeviceTool;
impl AdbMakeConnectDeviceTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "adb_make_connect_device".to_string(),
            description: "Build an ADB CNXN device banner message via rustre_adb::protocol::make_connect_device.".to_string(),
            input_schema: json!({"type":"object","required":["serial","model"],"properties":{"serial":{"type":"string"},"model":{"type":"string"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for AdbMakeConnectDeviceTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let s = args.get("serial").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'serial'".into()))?;
        let mo = args.get("model").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'model'".into()))?;
        let m = rustre_adb::protocol::make_connect_device(s, mo);
        let enc = m.encode();
        Ok(ToolResult::text(json!({"command_name":m.command_name(),"hex":__adb_hex(&enc),"len":enc.len()}).to_string()))
    }
}

pub struct AdbMakeAuthTokenTool;
impl AdbMakeAuthTokenTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "adb_make_auth_token".to_string(),
            description: "Build an ADB AUTH TOKEN message via rustre_adb::make_auth_token.".to_string(),
            input_schema: json!({"type":"object","required":["token_hex"],"properties":{"token_hex":{"type":"string"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for AdbMakeAuthTokenTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let hx = args.get("token_hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'token_hex'".into()))?;
        let tok: Vec<u8> = crate::hex_decode(hx)?;
        let m = rustre_adb::make_auth_token(tok);
        let enc = m.encode();
        Ok(ToolResult::text(json!({"command_name":m.command_name(),"hex":__adb_hex(&enc),"len":enc.len()}).to_string()))
    }
}

pub struct AdbMakeAuthSignatureTool;
impl AdbMakeAuthSignatureTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "adb_make_auth_signature".to_string(),
            description: "Build an ADB AUTH SIGNATURE message via rustre_adb::make_auth_signature.".to_string(),
            input_schema: json!({"type":"object","required":["sig_hex"],"properties":{"sig_hex":{"type":"string"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for AdbMakeAuthSignatureTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let hx = args.get("sig_hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'sig_hex'".into()))?;
        let sig: Vec<u8> = crate::hex_decode(hx)?;
        let m = rustre_adb::make_auth_signature(sig);
        let enc = m.encode();
        Ok(ToolResult::text(json!({"command_name":m.command_name(),"hex":__adb_hex(&enc),"len":enc.len()}).to_string()))
    }
}

pub struct AdbMakeAuthPublicKeyTool;
impl AdbMakeAuthPublicKeyTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "adb_make_auth_public_key".to_string(),
            description: "Build an ADB AUTH RSAPUBLICKEY message via rustre_adb::make_auth_public_key.".to_string(),
            input_schema: json!({"type":"object","required":["pem"],"properties":{"pem":{"type":"string"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for AdbMakeAuthPublicKeyTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let pem = args.get("pem").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'pem'".into()))?;
        let m = rustre_adb::make_auth_public_key(pem);
        let enc = m.encode();
        Ok(ToolResult::text(json!({"command_name":m.command_name(),"hex":__adb_hex(&enc),"len":enc.len()}).to_string()))
    }
}

pub struct AdbMakeOpenTool;
impl AdbMakeOpenTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "adb_make_open".to_string(),
            description: "Build an ADB OPEN message for a service via rustre_adb::make_open.".to_string(),
            input_schema: json!({"type":"object","required":["local_id","service"],"properties":{"local_id":{"type":"integer"},"service":{"type":"string"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for AdbMakeOpenTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let lid = args.get("local_id").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'local_id'".into()))? as u32;
        let sv = args.get("service").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'service'".into()))?;
        let m = rustre_adb::make_open(rustre_adb::LocalId(lid), sv);
        let enc = m.encode();
        Ok(ToolResult::text(json!({"command_name":m.command_name(),"hex":__adb_hex(&enc),"len":enc.len()}).to_string()))
    }
}

pub struct AdbMakeWriteTool;
impl AdbMakeWriteTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "adb_make_write".to_string(),
            description: "Build an ADB WRITE message via rustre_adb::make_write.".to_string(),
            input_schema: json!({"type":"object","required":["local_id","remote_id","data_hex"],"properties":{"local_id":{"type":"integer"},"remote_id":{"type":"integer"},"data_hex":{"type":"string"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for AdbMakeWriteTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let lid = args.get("local_id").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'local_id'".into()))? as u32;
        let rid = args.get("remote_id").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'remote_id'".into()))? as u32;
        let hx = args.get("data_hex").and_then(Value::as_str).unwrap_or("");
        let data: Vec<u8> = crate::hex_decode(hx)?;
        let m = rustre_adb::make_write(rustre_adb::LocalId(lid), rustre_adb::RemoteId(rid), data);
        let enc = m.encode();
        Ok(ToolResult::text(json!({"command_name":m.command_name(),"hex":__adb_hex(&enc),"len":enc.len()}).to_string()))
    }
}

pub struct AdbCurrentMtimeTool;
impl AdbCurrentMtimeTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "adb_current_mtime".to_string(),
            description: "Return current unix mtime as u32 via rustre_adb::file_transfer::current_mtime.".to_string(),
            input_schema: json!({"type":"object","properties":{}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for AdbCurrentMtimeTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let t = rustre_adb::file_transfer::current_mtime();
        Ok(ToolResult::text(json!({"mtime":t}).to_string()))
    }
}

pub struct AdbEncodeStatRequestTool;
impl AdbEncodeStatRequestTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "adb_encode_stat_request".to_string(),
            description: "Encode a sync STAT request via rustre_adb::file_transfer::encode_stat_request.".to_string(),
            input_schema: json!({"type":"object","required":["path"],"properties":{"path":{"type":"string"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for AdbEncodeStatRequestTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let p = args.get("path").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'path'".into()))?;
        let buf = rustre_adb::file_transfer::encode_stat_request(p).map_err(|e| McpError::InternalError(format!("{e}")))?;
        Ok(ToolResult::text(json!({"hex":__adb_hex(&buf),"len":buf.len()}).to_string()))
    }
}

pub struct AdbEncodeListRequestTool;
impl AdbEncodeListRequestTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "adb_encode_list_request".to_string(),
            description: "Encode a sync LIST request via rustre_adb::file_transfer::encode_list_request.".to_string(),
            input_schema: json!({"type":"object","required":["path"],"properties":{"path":{"type":"string"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for AdbEncodeListRequestTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let p = args.get("path").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'path'".into()))?;
        let buf = rustre_adb::file_transfer::encode_list_request(p).map_err(|e| McpError::InternalError(format!("{e}")))?;
        Ok(ToolResult::text(json!({"hex":__adb_hex(&buf),"len":buf.len()}).to_string()))
    }
}

pub struct AdbEncodeDataChunkTool;
impl AdbEncodeDataChunkTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "adb_encode_data_chunk".to_string(),
            description: "Encode a sync DATA chunk via rustre_adb::file_transfer::encode_data_chunk.".to_string(),
            input_schema: json!({"type":"object","required":["data_hex"],"properties":{"data_hex":{"type":"string"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for AdbEncodeDataChunkTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let hx = args.get("data_hex").and_then(Value::as_str).unwrap_or("");
        let data: Vec<u8> = crate::hex_decode(hx)?;
        let buf = rustre_adb::file_transfer::encode_data_chunk(&data);
        Ok(ToolResult::text(json!({"hex":__adb_hex(&buf),"len":buf.len()}).to_string()))
    }
}

pub struct AdbEncodeDoneTool;
impl AdbEncodeDoneTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "adb_encode_done".to_string(),
            description: "Encode a sync DONE message via rustre_adb::file_transfer::encode_done.".to_string(),
            input_schema: json!({"type":"object","required":["mtime"],"properties":{"mtime":{"type":"integer"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for AdbEncodeDoneTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let m = args.get("mtime").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'mtime'".into()))? as u32;
        let buf = rustre_adb::file_transfer::encode_done(m);
        Ok(ToolResult::text(json!({"hex":__adb_hex(&buf),"len":buf.len()}).to_string()))
    }
}

pub struct AdbLogEntryParseBriefV2Tool;
impl AdbLogEntryParseBriefV2Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "adb_log_entry_parse_brief_v2".to_string(), description: "Parse a brief-format logcat line via rustre_adb::LogEntry::parse_brief.".to_string(), input_schema: json!({"type":"object","required":["line"],"properties":{"line":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for AdbLogEntryParseBriefV2Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
    let line = args.get("line").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'line'".into()))?;
    let e = rustre_adb::LogEntry::parse_brief(line);
    Ok(ToolResult::text(json!({"parsed": e.is_some(), "entry": e.map(|x| json!({"tag":x.tag,"pid":x.pid,"tid":x.tid,"level":x.level.as_char().to_string(),"message":x.message,"timestamp":x.timestamp})), "source":"rustre_adb::LogEntry::parse_brief"}).to_string()))
} }

pub struct AdbLogEntryParseAutoTool;
impl AdbLogEntryParseAutoTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "adb_log_entry_parse_auto".to_string(), description: "Parse a logcat line trying brief then threadtime via rustre_adb::LogEntry::parse.".to_string(), input_schema: json!({"type":"object","required":["line"],"properties":{"line":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for AdbLogEntryParseAutoTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
    let line = args.get("line").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'line'".into()))?;
    let e = rustre_adb::LogEntry::parse(line);
    Ok(ToolResult::text(json!({"parsed": e.is_some(), "entry": e.map(|x| json!({"tag":x.tag,"pid":x.pid,"tid":x.tid,"level":x.level.as_char().to_string(),"message":x.message,"timestamp":x.timestamp})), "source":"rustre_adb::LogEntry::parse"}).to_string()))
} }

pub struct AdbDeviceStateIsOnlineTool;
impl AdbDeviceStateIsOnlineTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "adb_device_state_is_online".to_string(), description: "Return whether a DeviceState is online via rustre_adb::DeviceState::is_online.".to_string(), input_schema: json!({"type":"object","required":["state"],"properties":{"state":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for AdbDeviceStateIsOnlineTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
    let s = args.get("state").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'state'".into()))?;
    let st = __adb_state_from_str(s);
    Ok(ToolResult::text(json!({"is_online": st.is_online(), "display": st.to_string(), "source":"rustre_adb::DeviceState::is_online"}).to_string()))
} }

pub struct AdbDeviceStateNeedsAuthTool;
impl AdbDeviceStateNeedsAuthTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "adb_device_state_needs_auth".to_string(), description: "Return whether a DeviceState needs auth via rustre_adb::DeviceState::needs_auth.".to_string(), input_schema: json!({"type":"object","required":["state"],"properties":{"state":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for AdbDeviceStateNeedsAuthTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
    let s = args.get("state").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'state'".into()))?;
    let st = __adb_state_from_str(s);
    Ok(ToolResult::text(json!({"needs_auth": st.needs_auth(), "display": st.to_string(), "source":"rustre_adb::DeviceState::needs_auth"}).to_string()))
} }

pub struct AdbShellResultSuccessTool;
impl AdbShellResultSuccessTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "adb_shell_result_success".to_string(), description: "Return success flag for a shell result via rustre_adb::ShellResult::success.".to_string(), input_schema: json!({"type":"object","properties":{"stdout":{"type":"string"},"exit_code":{"type":["integer","null"]}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for AdbShellResultSuccessTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
    let stdout = args.get("stdout").and_then(Value::as_str).unwrap_or("").to_string();
    let exit_code = args.get("exit_code").and_then(Value::as_i64).map(|v| v as i32);
    let r = rustre_adb::ShellResult { stdout, exit_code };
    Ok(ToolResult::text(json!({"success": r.success(), "source":"rustre_adb::ShellResult::success"}).to_string()))
} }

pub struct AdbMessageEncodeTool;
impl AdbMessageEncodeTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "adb_message_encode".to_string(), description: "Encode an AdbMessage to hex via rustre_adb::AdbMessage::encode.".to_string(), input_schema: json!({"type":"object","required":["command","arg0","arg1"],"properties":{"command":{"type":"integer"},"arg0":{"type":"integer"},"arg1":{"type":"integer"},"data_hex":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for AdbMessageEncodeTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
    let command = args.get("command").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'command'".into()))? as u32;
    let arg0 = args.get("arg0").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'arg0'".into()))? as u32;
    let arg1 = args.get("arg1").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'arg1'".into()))? as u32;
    let hx = args.get("data_hex").and_then(Value::as_str).unwrap_or("");
    let data: Vec<u8> = crate::hex_decode(hx)?;
    let m = rustre_adb::AdbMessage::new(command, arg0, arg1, data);
    let enc = m.encode();
    Ok(ToolResult::text(json!({"hex":__adb_hex(&enc),"len":enc.len(),"command_name":m.command_name(),"source":"rustre_adb::AdbMessage::encode"}).to_string()))
} }

pub struct AdbLocalClientInfoTool;
impl AdbLocalClientInfoTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "adb_local_client_info".to_string(), description: "Return host/port/timeout of the default local AdbClient via rustre_adb::local_client.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for AdbLocalClientInfoTool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
    let c = rustre_adb::local_client();
    Ok(ToolResult::text(json!({"host":c.host,"port":c.port,"timeout_secs":c.timeout.as_secs(),"source":"rustre_adb::local_client"}).to_string()))
} }

pub struct AdbVersionConstantTool;
impl AdbVersionConstantTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "adb_version_constant".to_string(), description: "Return the ADB_VERSION constant from rustre_adb.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for AdbVersionConstantTool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
    Ok(ToolResult::text(json!({"value": rustre_adb::ADB_VERSION, "hex": format!("{:08x}", rustre_adb::ADB_VERSION), "source":"rustre_adb::ADB_VERSION"}).to_string()))
} }

pub struct AdbMaxPayloadConstantTool;
impl AdbMaxPayloadConstantTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "adb_max_payload_constant".to_string(), description: "Return the ADB_MAX_PAYLOAD constant from rustre_adb.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for AdbMaxPayloadConstantTool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
    Ok(ToolResult::text(json!({"value": rustre_adb::ADB_MAX_PAYLOAD, "source":"rustre_adb::ADB_MAX_PAYLOAD"}).to_string()))
} }

pub struct AdbSyncMaxDataChunkTool;
impl AdbSyncMaxDataChunkTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "adb_sync_max_data_chunk".to_string(), description: "Return the sync_cmd::MAX_DATA_CHUNK constant from rustre_adb.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for AdbSyncMaxDataChunkTool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
    Ok(ToolResult::text(json!({"value": rustre_adb::sync_cmd::MAX_DATA_CHUNK, "source":"rustre_adb::sync_cmd::MAX_DATA_CHUNK"}).to_string()))
} }

pub struct AdbSyncCmdTagsTool;
impl AdbSyncCmdTagsTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "adb_sync_cmd_tags".to_string(), description: "Return the 4-byte sync command tags exposed by rustre_adb::sync_cmd.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for AdbSyncCmdTagsTool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
    use rustre_adb::sync_cmd::*;
    let f = |t: &[u8; 4]| String::from_utf8_lossy(t).into_owned();
    Ok(ToolResult::text(json!({
        "DENT": f(DENT), "RECV": f(RECV), "SEND": f(SEND), "STAT": f(STAT),
        "DATA": f(DATA), "DONE": f(DONE), "FAIL": f(FAIL), "OKAY": f(OKAY),
        "QUIT": f(QUIT), "LIST": f(LIST),
        "source":"rustre_adb::sync_cmd"
    }).to_string()))
} }

pub struct AdbCrc32RoundtripTool;
impl AdbCrc32RoundtripTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "adb_crc32_roundtrip".to_string(), description: "Compute ADB CRC32 via rustre_adb::compute_crc32, then verify by decoding an encoded message.".to_string(), input_schema: json!({"type":"object","properties":{"data_hex":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for AdbCrc32RoundtripTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
    let hx = args.get("data_hex").and_then(Value::as_str).unwrap_or("");
    let data: Vec<u8> = crate::hex_decode(hx)?;
    let crc = rustre_adb::compute_crc32(&data);
    let enc = rustre_adb::encode_message(rustre_adb::cmd::WRTE, 1, 2, &data);
    let dec = rustre_adb::decode_message(&enc).map_err(|e| McpError::InvalidParams(e.to_string()))?;
    Ok(ToolResult::text(json!({"crc32": crc, "verify_crc": dec.verify_crc(), "data_len": data.len(), "source":"rustre_adb::compute_crc32+encode_message+decode_message"}).to_string()))
} }

pub struct AdbServiceShellCmdTool;
impl AdbServiceShellCmdTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "adb_service_shell_cmd".to_string(), description: "Build a shell: service URL via rustre_adb::adb_protocol::services::shell_cmd.".to_string(), input_schema: json!({"type":"object","required":["cmd"],"properties":{"cmd":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for AdbServiceShellCmdTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let c = args.get("cmd").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'cmd'".into()))?; let s = rustre_adb::adb_protocol::services::shell_cmd(c); Ok(ToolResult::text(json!({"service":s,"source":"rustre_adb::adb_protocol::services::shell_cmd"}).to_string())) } }

pub struct AdbServiceTransportSerialTool;
impl AdbServiceTransportSerialTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "adb_service_transport_serial".to_string(), description: "Build a host:transport:<serial> URL via rustre_adb::adb_protocol::services::transport_serial.".to_string(), input_schema: json!({"type":"object","required":["serial"],"properties":{"serial":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for AdbServiceTransportSerialTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let sr = args.get("serial").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'serial'".into()))?; let s = rustre_adb::adb_protocol::services::transport_serial(sr); Ok(ToolResult::text(json!({"service":s,"source":"rustre_adb::adb_protocol::services::transport_serial"}).to_string())) } }

pub struct AdbServiceForwardTool;
impl AdbServiceForwardTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "adb_service_forward".to_string(), description: "Build a forward:<local>;<remote> URL via rustre_adb::adb_protocol::services::forward.".to_string(), input_schema: json!({"type":"object","required":["local","remote"],"properties":{"local":{"type":"string"},"remote":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for AdbServiceForwardTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let l = args.get("local").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'local'".into()))?; let r = args.get("remote").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'remote'".into()))?; let s = rustre_adb::adb_protocol::services::forward(l, r); Ok(ToolResult::text(json!({"service":s,"source":"rustre_adb::adb_protocol::services::forward"}).to_string())) } }

pub struct AdbServiceReverseTool;
impl AdbServiceReverseTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "adb_service_reverse".to_string(), description: "Build a reverse:forward:<remote>;<local> URL via rustre_adb::adb_protocol::services::reverse.".to_string(), input_schema: json!({"type":"object","required":["remote","local"],"properties":{"remote":{"type":"string"},"local":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for AdbServiceReverseTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let r = args.get("remote").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'remote'".into()))?; let l = args.get("local").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'local'".into()))?; let s = rustre_adb::adb_protocol::services::reverse(r, l); Ok(ToolResult::text(json!({"service":s,"source":"rustre_adb::adb_protocol::services::reverse"}).to_string())) } }

pub struct AdbMessageNoDataTool;
impl AdbMessageNoDataTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "adb_message_no_data".to_string(), description: "Build an AdbMessage with no payload via rustre_adb::adb_protocol::AdbMessage::no_data and return encoded length.".to_string(), input_schema: json!({"type":"object","required":["command","arg0","arg1"],"properties":{"command":{"type":"integer"},"arg0":{"type":"integer"},"arg1":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for AdbMessageNoDataTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let c = args.get("command").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'command'".into()))? as u32; let a0 = args.get("arg0").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'arg0'".into()))? as u32; let a1 = args.get("arg1").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'arg1'".into()))? as u32; let m = rustre_adb::adb_protocol::AdbMessage::no_data(c, a0, a1); let enc = m.encode(); Ok(ToolResult::text(json!({"command":m.command,"arg0":m.arg0,"arg1":m.arg1,"data_len":m.data.len(),"encoded_len":enc.len(),"source":"rustre_adb::adb_protocol::AdbMessage::no_data"}).to_string())) } }

pub struct AdbMessageDataStrTool;
impl AdbMessageDataStrTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "adb_message_data_str".to_string(), description: "Read AdbMessage.data as UTF-8 via rustre_adb::adb_protocol::AdbMessage::data_str.".to_string(), input_schema: json!({"type":"object","required":["command","arg0","arg1","data"],"properties":{"command":{"type":"integer"},"arg0":{"type":"integer"},"arg1":{"type":"integer"},"data":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for AdbMessageDataStrTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let c = args.get("command").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'command'".into()))? as u32; let a0 = args.get("arg0").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'arg0'".into()))? as u32; let a1 = args.get("arg1").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'arg1'".into()))? as u32; let d = args.get("data").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'data'".into()))?; let m = rustre_adb::adb_protocol::AdbMessage::new(c, a0, a1, d.as_bytes().to_vec()); match m.data_str() { Ok(s) => Ok(ToolResult::text(json!({"data_str":s,"len":s.len(),"source":"rustre_adb::adb_protocol::AdbMessage::data_str"}).to_string())), Err(e) => Err(McpError::InternalError(format!("data_str error: {e}"))) } } }

pub struct AdbConnectBannerParseTool;
impl AdbConnectBannerParseTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "adb_connect_banner_parse".to_string(), description: "Parse an ADB CNXN banner via rustre_adb::adb_protocol::ConnectBanner::parse.".to_string(), input_schema: json!({"type":"object","required":["raw"],"properties":{"raw":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for AdbConnectBannerParseTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let r = args.get("raw").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'raw'".into()))?; let b = rustre_adb::adb_protocol::ConnectBanner::parse(r); Ok(ToolResult::text(json!({"connection_type":b.connection_type,"serial":b.serial,"banner":b.banner,"features":b.features,"source":"rustre_adb::adb_protocol::ConnectBanner::parse"}).to_string())) } }

pub struct AdbConnectBannerHasFeatureTool;
impl AdbConnectBannerHasFeatureTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "adb_connect_banner_has_feature".to_string(), description: "Check if a parsed ConnectBanner advertises a feature via rustre_adb::adb_protocol::ConnectBanner::has_feature.".to_string(), input_schema: json!({"type":"object","required":["raw","feature"],"properties":{"raw":{"type":"string"},"feature":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for AdbConnectBannerHasFeatureTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let r = args.get("raw").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'raw'".into()))?; let f = args.get("feature").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'feature'".into()))?; let b = rustre_adb::adb_protocol::ConnectBanner::parse(r); Ok(ToolResult::text(json!({"has_feature":b.has_feature(f),"feature":f,"features":b.features,"source":"rustre_adb::adb_protocol::ConnectBanner::has_feature"}).to_string())) } }

pub struct AdbSyncEncodeStatTool;
impl AdbSyncEncodeStatTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "adb_sync_encode_stat".to_string(), description: "Encode an ADB sync STAT request via rustre_adb::adb_file_sync::AdbFileSync::encode_sync_stat.".to_string(), input_schema: json!({"type":"object","required":["path"],"properties":{"path":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for AdbSyncEncodeStatTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let p = args.get("path").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'path'".into()))?; let v = rustre_adb::adb_file_sync::AdbFileSync::encode_sync_stat(p); Ok(ToolResult::text(json!({"hex":__adb_hex(&v),"len":v.len(),"source":"rustre_adb::adb_file_sync::AdbFileSync::encode_sync_stat"}).to_string())) } }

pub struct AdbSyncEncodeListTool;
impl AdbSyncEncodeListTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "adb_sync_encode_list".to_string(), description: "Encode an ADB sync LIST request via rustre_adb::adb_file_sync::AdbFileSync::encode_sync_list.".to_string(), input_schema: json!({"type":"object","required":["path"],"properties":{"path":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for AdbSyncEncodeListTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let p = args.get("path").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'path'".into()))?; let v = rustre_adb::adb_file_sync::AdbFileSync::encode_sync_list(p); Ok(ToolResult::text(json!({"hex":__adb_hex(&v),"len":v.len(),"source":"rustre_adb::adb_file_sync::AdbFileSync::encode_sync_list"}).to_string())) } }

pub struct AdbSyncEncodeRecvTool;
impl AdbSyncEncodeRecvTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "adb_sync_encode_recv".to_string(), description: "Encode an ADB sync RECV request via rustre_adb::adb_file_sync::AdbFileSync::encode_sync_recv.".to_string(), input_schema: json!({"type":"object","required":["path"],"properties":{"path":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for AdbSyncEncodeRecvTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let p = args.get("path").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'path'".into()))?; let v = rustre_adb::adb_file_sync::AdbFileSync::encode_sync_recv(p); Ok(ToolResult::text(json!({"hex":__adb_hex(&v),"len":v.len(),"source":"rustre_adb::adb_file_sync::AdbFileSync::encode_sync_recv"}).to_string())) } }

pub struct AdbSyncEncodeQuitTool;
impl AdbSyncEncodeQuitTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "adb_sync_encode_quit".to_string(), description: "Encode an ADB sync QUIT request via rustre_adb::adb_file_sync::AdbFileSync::encode_quit.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for AdbSyncEncodeQuitTool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { let v = rustre_adb::adb_file_sync::AdbFileSync::encode_quit(); Ok(ToolResult::text(json!({"hex":__adb_hex(&v),"len":v.len(),"source":"rustre_adb::adb_file_sync::AdbFileSync::encode_quit"}).to_string())) } }

pub struct AdbServiceConstantsTool;
impl AdbServiceConstantsTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "adb_service_constants".to_string(), description: "Return string constants from rustre_adb::adb_protocol::services.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for AdbServiceConstantsTool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { use rustre_adb::adb_protocol::services::*; Ok(ToolResult::text(json!({"shell":SHELL,"sync":SYNC,"logcat":LOGCAT,"remount":REMOUNT,"reboot":REBOOT,"track_devices":TRACK_DEVICES,"version":VERSION,"devices":DEVICES,"devices_long":DEVICES_LONG,"transport_any":TRANSPORT_ANY,"source":"rustre_adb::adb_protocol::services"}).to_string())) } }

pub struct AdbProtocolStateMachineNewTool;
impl AdbProtocolStateMachineNewTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "adb_protocol_state_machine_new".to_string(), description: "Instantiate ProtocolStateMachine via rustre_adb::adb_protocol::ProtocolStateMachine::new.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for AdbProtocolStateMachineNewTool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { let sm = rustre_adb::adb_protocol::ProtocolStateMachine::new(); Ok(ToolResult::text(json!({"state":format!("{:?}", sm.state),"local_id":sm.local_id,"remote_id":sm.remote_id,"source":"rustre_adb::adb_protocol::ProtocolStateMachine::new"}).to_string())) } }

pub struct AdbProtocolDefaultPortTool;
impl AdbProtocolDefaultPortTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "adb_protocol_default_port".to_string(), description: "Return the ADB_DEFAULT_PORT constant from rustre_adb::adb_protocol.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for AdbProtocolDefaultPortTool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { Ok(ToolResult::text(json!({"value": rustre_adb::adb_protocol::ADB_DEFAULT_PORT, "source":"rustre_adb::adb_protocol::ADB_DEFAULT_PORT"}).to_string())) } }

pub struct AdbProtocolMaxDataTool;
impl AdbProtocolMaxDataTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "adb_protocol_max_data".to_string(), description: "Return the ADB_MAX_DATA constant from rustre_adb::adb_protocol.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for AdbProtocolMaxDataTool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { Ok(ToolResult::text(json!({"value": rustre_adb::adb_protocol::ADB_MAX_DATA, "source":"rustre_adb::adb_protocol::ADB_MAX_DATA"}).to_string())) } }

pub struct AdbProtocolVersionConstantTool;
impl AdbProtocolVersionConstantTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "adb_protocol_version_constant".to_string(), description: "Return PROTOCOL_VERSION and MAX_PAYLOAD from rustre_adb::adb_protocol.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for AdbProtocolVersionConstantTool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { Ok(ToolResult::text(json!({"protocol_version": rustre_adb::adb_protocol::PROTOCOL_VERSION, "max_payload": rustre_adb::adb_protocol::MAX_PAYLOAD, "source":"rustre_adb::adb_protocol::PROTOCOL_VERSION"}).to_string())) } }

pub struct AdbProtocolAuthConstantsTool;
impl AdbProtocolAuthConstantsTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "adb_protocol_auth_constants".to_string(), description: "Return AUTH_TOKEN/AUTH_SIGNATURE/AUTH_RSAPUBLICKEY constants from rustre_adb::adb_protocol.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for AdbProtocolAuthConstantsTool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { Ok(ToolResult::text(json!({"auth_token": rustre_adb::adb_protocol::AUTH_TOKEN,"auth_signature": rustre_adb::adb_protocol::AUTH_SIGNATURE,"auth_rsapublickey": rustre_adb::adb_protocol::AUTH_RSAPUBLICKEY,"source":"rustre_adb::adb_protocol"}).to_string())) } }

pub struct AdbProtocolCmdConstantsTool;
impl AdbProtocolCmdConstantsTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "adb_protocol_cmd_constants".to_string(), description: "Return CMD_SYNC/CNXN/AUTH/OPEN/OKAY/CLSE/WRTE/STAT constants from rustre_adb::adb_protocol.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for AdbProtocolCmdConstantsTool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { use rustre_adb::adb_protocol::*; Ok(ToolResult::text(json!({"cmd_sync":CMD_SYNC,"cmd_cnxn":CMD_CNXN,"cmd_auth":CMD_AUTH,"cmd_open":CMD_OPEN,"cmd_okay":CMD_OKAY,"cmd_clse":CMD_CLSE,"cmd_wrte":CMD_WRTE,"cmd_stat":CMD_STAT,"source":"rustre_adb::adb_protocol"}).to_string())) } }

pub struct AdbLogLevelDisplayTool;
impl AdbLogLevelDisplayTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "adb_log_level_display".to_string(), description: "Parse brief logcat line and report LogLevel Display/char/severity via rustre_adb::LogEntry::parse_brief.".to_string(), input_schema: json!({"type":"object","required":["line"],"properties":{"line":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for AdbLogLevelDisplayTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let line = args.get("line").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'line'".into()))?; let entry = rustre_adb::LogEntry::parse_brief(line).ok_or_else(|| McpError::InvalidParams("could not parse brief logcat line".into()))?; Ok(ToolResult::text(json!({"display": entry.level.to_string(),"char": entry.level.as_char().to_string(),"severity": entry.level.severity(),"tag": entry.tag,"pid": entry.pid,"source":"rustre_adb::LogLevel::Display"}).to_string())) } }

pub struct AdbRebootServiceConstantsTool;
impl AdbRebootServiceConstantsTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "adb_reboot_service_constants".to_string(), description: "Return REBOOT/REBOOT_BOOTLOADER/REBOOT_RECOVERY service string constants from rustre_adb::adb_protocol::services.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for AdbRebootServiceConstantsTool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { use rustre_adb::adb_protocol::services::*; Ok(ToolResult::text(json!({"reboot":REBOOT,"reboot_bootloader":REBOOT_BOOTLOADER,"reboot_recovery":REBOOT_RECOVERY,"source":"rustre_adb::adb_protocol::services"}).to_string())) } }

pub struct AdbMsgNoDataEncodedTool;
impl AdbMsgNoDataEncodedTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "adb_msg_no_data_encoded".to_string(), description: "Build AdbMessage::no_data + encode via rustre_adb::adb_protocol::AdbMessage::no_data.".to_string(), input_schema: json!({"type":"object","required":["command","arg0","arg1"],"properties":{"command":{"type":"integer"},"arg0":{"type":"integer"},"arg1":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for AdbMsgNoDataEncodedTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let cmd = args.get("command").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'command'".into()))? as u32; let a0 = args.get("arg0").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'arg0'".into()))? as u32; let a1 = args.get("arg1").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'arg1'".into()))? as u32; let m = rustre_adb::adb_protocol::AdbMessage::no_data(cmd, a0, a1); let enc = m.encode(); let hex: String = enc.iter().map(|b| format!("{:02x}", b)).collect(); Ok(ToolResult::text(json!({"hex": hex, "len": enc.len(), "source":"rustre_adb::adb_protocol::AdbMessage::no_data"}).to_string())) } }

pub struct AdbClientNewWithTimeoutTool;
impl AdbClientNewWithTimeoutTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "adb_client_new_with_timeout".to_string(), description: "Build AdbClient::new + with_timeout via rustre_adb::AdbClient.".to_string(), input_schema: json!({"type":"object","properties":{"host":{"type":"string"},"port":{"type":"integer"},"timeout_secs":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for AdbClientNewWithTimeoutTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let host = args.get("host").and_then(Value::as_str).unwrap_or("127.0.0.1").to_string(); let port = args.get("port").and_then(Value::as_u64).unwrap_or(5037) as u16; let secs = args.get("timeout_secs").and_then(Value::as_u64).unwrap_or(5); let c = rustre_adb::AdbClient::new(host, port).with_timeout(std::time::Duration::from_secs(secs)); Ok(ToolResult::text(json!({"host":c.host,"port":c.port,"timeout_secs":c.timeout.as_secs(),"source":"rustre_adb::AdbClient::with_timeout"}).to_string())) } }

pub struct AdbCmdAllConstantsTool;
impl AdbCmdAllConstantsTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "adb_cmd_all_constants".to_string(), description: "Return all wire-protocol command constants from rustre_adb::cmd.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for AdbCmdAllConstantsTool { async fn call(&self, _a: Value) -> Result<ToolResult, McpError> { use rustre_adb::cmd::*; Ok(ToolResult::text(json!({"CNXN":CNXN,"AUTH":AUTH,"OPEN":OPEN,"OKAY":OKAY,"CLSE":CLSE,"WRTE":WRTE,"SYNC":SYNC,"source":"rustre_adb::cmd"}).to_string())) } }

pub struct AdbMessageMagicFieldTool;
impl AdbMessageMagicFieldTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "adb_message_magic_field".to_string(), description: "Construct AdbMessage::new and return its magic field.".to_string(), input_schema: json!({"type":"object","required":["command"],"properties":{"command":{"type":"integer","minimum":0},"arg0":{"type":"integer","minimum":0},"arg1":{"type":"integer","minimum":0},"data_hex":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for AdbMessageMagicFieldTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let cmd = args.get("command").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'command'".into()))? as u32; let a0 = args.get("arg0").and_then(Value::as_u64).unwrap_or(0) as u32; let a1 = args.get("arg1").and_then(Value::as_u64).unwrap_or(0) as u32; let hx = args.get("data_hex").and_then(Value::as_str).unwrap_or(""); let data: Vec<u8> = (0..hx.len()).step_by(2).map(|i| u8::from_str_radix(hx.get(i..i+2).unwrap_or("00"), 16).unwrap_or(0)).collect(); let m = rustre_adb::AdbMessage::new(cmd, a0, a1, data); Ok(ToolResult::text(json!({"magic":m.magic,"crc32":m.crc32,"command_name":m.command_name(),"source":"rustre_adb::AdbMessage::new"}).to_string())) } }

pub struct AdbMessageCommandNameForU32Tool;
impl AdbMessageCommandNameForU32Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "adb_message_command_name_for_u32".to_string(), description: "Return command_name for a raw u32 via rustre_adb::AdbMessage::command_name.".to_string(), input_schema: json!({"type":"object","required":["command"],"properties":{"command":{"type":"integer","minimum":0}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for AdbMessageCommandNameForU32Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let cmd = args.get("command").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'command'".into()))? as u32; let m = rustre_adb::AdbMessage::new(cmd, 0, 0, Vec::new()); Ok(ToolResult::text(json!({"name":m.command_name(),"source":"rustre_adb::AdbMessage::command_name"}).to_string())) } }

pub struct AdbEncodeDecodeRoundtripV2Tool;
impl AdbEncodeDecodeRoundtripV2Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "adb_encode_decode_roundtrip_v2".to_string(), description: "Encode via rustre_adb::encode_message then decode via decode_message.".to_string(), input_schema: json!({"type":"object","required":["command"],"properties":{"command":{"type":"integer","minimum":0},"arg0":{"type":"integer","minimum":0},"arg1":{"type":"integer","minimum":0},"data_hex":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for AdbEncodeDecodeRoundtripV2Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let cmd = args.get("command").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'command'".into()))? as u32; let a0 = args.get("arg0").and_then(Value::as_u64).unwrap_or(0) as u32; let a1 = args.get("arg1").and_then(Value::as_u64).unwrap_or(0) as u32; let hx = args.get("data_hex").and_then(Value::as_str).unwrap_or(""); let data: Vec<u8> = (0..hx.len()).step_by(2).map(|i| u8::from_str_radix(hx.get(i..i+2).unwrap_or("00"), 16).unwrap_or(0)).collect(); let enc = rustre_adb::encode_message(cmd, a0, a1, &data); let dec = rustre_adb::decode_message(&enc).map_err(|e| McpError::InvalidParams(e.to_string()))?; Ok(ToolResult::text(json!({"encoded_len":enc.len(),"decoded_command":dec.command,"crc_ok":dec.verify_crc(),"source":"rustre_adb::encode_message+decode_message"}).to_string())) } }

pub struct AdbEncodeMessageLengthTool;
impl AdbEncodeMessageLengthTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "adb_encode_message_length".to_string(), description: "Return byte length of rustre_adb::encode_message output.".to_string(), input_schema: json!({"type":"object","required":["command"],"properties":{"command":{"type":"integer","minimum":0},"arg0":{"type":"integer","minimum":0},"arg1":{"type":"integer","minimum":0},"data_hex":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for AdbEncodeMessageLengthTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let cmd = args.get("command").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'command'".into()))? as u32; let a0 = args.get("arg0").and_then(Value::as_u64).unwrap_or(0) as u32; let a1 = args.get("arg1").and_then(Value::as_u64).unwrap_or(0) as u32; let hx = args.get("data_hex").and_then(Value::as_str).unwrap_or(""); let data: Vec<u8> = (0..hx.len()).step_by(2).map(|i| u8::from_str_radix(hx.get(i..i+2).unwrap_or("00"), 16).unwrap_or(0)).collect(); let enc = rustre_adb::encode_message(cmd, a0, a1, &data); Ok(ToolResult::text(json!({"length":enc.len(),"header":24,"payload":data.len(),"source":"rustre_adb::encode_message"}).to_string())) } }

pub struct AdbMessageCrcFieldTool;
impl AdbMessageCrcFieldTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "adb_message_crc_field".to_string(), description: "Construct AdbMessage::new and return its crc32 field plus verify_crc.".to_string(), input_schema: json!({"type":"object","required":["command"],"properties":{"command":{"type":"integer","minimum":0},"data_hex":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for AdbMessageCrcFieldTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let cmd = args.get("command").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'command'".into()))? as u32; let hx = args.get("data_hex").and_then(Value::as_str).unwrap_or(""); let data: Vec<u8> = (0..hx.len()).step_by(2).map(|i| u8::from_str_radix(hx.get(i..i+2).unwrap_or("00"), 16).unwrap_or(0)).collect(); let m = rustre_adb::AdbMessage::new(cmd, 0, 0, data); Ok(ToolResult::text(json!({"crc32":m.crc32,"verify":m.verify_crc(),"source":"rustre_adb::AdbMessage::new"}).to_string())) } }

pub struct AdbDeviceIsReadyFromLineTool;
impl AdbDeviceIsReadyFromLineTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "adb_device_is_ready_from_line".to_string(), description: "Parse `adb devices -l` output and return is_ready of the first device via rustre_adb::AdbDevice::is_ready.".to_string(), input_schema: json!({"type":"object","required":["output"],"properties":{"output":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for AdbDeviceIsReadyFromLineTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let out = args.get("output").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'output'".into()))?; let devs = rustre_adb::parse_devices_output(out); let first = devs.devices.first(); Ok(ToolResult::text(json!({"count":devs.devices.len(),"is_ready":first.map(|d| d.device.is_ready()),"serial":first.map(|d| d.device.serial.clone()),"source":"rustre_adb::AdbDevice::is_ready"}).to_string())) } }

pub struct AdbGroupByTagCountsTool;
impl AdbGroupByTagCountsTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "adb_group_by_tag_counts".to_string(), description: "Parse logcat output then group_by_tag; return count per tag via rustre_adb::group_by_tag.".to_string(), input_schema: json!({"type":"object","required":["output"],"properties":{"output":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for AdbGroupByTagCountsTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let out = args.get("output").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'output'".into()))?; let entries = rustre_adb::parse_logcat_output(out); let groups = rustre_adb::group_by_tag(&entries); let counts: std::collections::BTreeMap<String, usize> = groups.iter().map(|(k,v)| (k.clone(), v.len())).collect(); Ok(ToolResult::text(json!({"tags":counts.len(),"counts":counts,"source":"rustre_adb::group_by_tag"}).to_string())) } }

pub struct AdbLocalClientHostV2Tool;
impl AdbLocalClientHostV2Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "adb_local_client_host_v2".to_string(), description: "Return only the host field from rustre_adb::local_client().".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for AdbLocalClientHostV2Tool { async fn call(&self, _a: Value) -> Result<ToolResult, McpError> { let c = rustre_adb::local_client(); Ok(ToolResult::text(json!({"host":c.host,"source":"rustre_adb::local_client"}).to_string())) } }

pub struct AdbFilterByLevelCountTool;
impl AdbFilterByLevelCountTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "adb_filter_by_level_count".to_string(), description: "Parse logcat and return counts at/above each severity via rustre_adb::filter_by_level.".to_string(), input_schema: json!({"type":"object","required":["output"],"properties":{"output":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for AdbFilterByLevelCountTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let out = args.get("output").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'output'".into()))?; let entries = rustre_adb::parse_logcat_output(out); use rustre_adb::LogLevel::*; let count = |lvl: &rustre_adb::LogLevel| rustre_adb::filter_by_level(&entries, lvl).len(); Ok(ToolResult::text(json!({"total":entries.len(),"info_plus":count(&Info),"warning_plus":count(&Warning),"error_plus":count(&Error),"source":"rustre_adb::filter_by_level"}).to_string())) } }

pub fn handlers() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    vec![
        (AdbComputeCrc32Tool::definition(), Box::new(AdbComputeCrc32Tool)),
        (AdbParseLogcatTool::definition(), Box::new(AdbParseLogcatTool)),
        (AdbEncodeMessageTool::definition(), Box::new(AdbEncodeMessageTool)),
        (AdbDecodeMessageTool::definition(), Box::new(AdbDecodeMessageTool)),
        (AdbParseLogcatLineTool::definition(), Box::new(AdbParseLogcatLineTool)),
        (AdbFilterByLevelTool::definition(), Box::new(AdbFilterByLevelTool)),
        (AdbFilterByTagTool::definition(), Box::new(AdbFilterByTagTool)),
        (AdbGroupByTagTool::definition(), Box::new(AdbGroupByTagTool)),
        (AdbParseDevicesOutputTool::definition(), Box::new(AdbParseDevicesOutputTool)),
        (AdbParseBriefLineTool::definition(), Box::new(AdbParseBriefLineTool)),
        (AdbParseThreadtimeLineTool::definition(), Box::new(AdbParseThreadtimeLineTool)),
        (AdbShellEscapeTool::definition(), Box::new(AdbShellEscapeTool)),
        (AdbInstallSucceededTool::definition(), Box::new(AdbInstallSucceededTool)),
        (AdbUninstallSucceededTool::definition(), Box::new(AdbUninstallSucceededTool)),
        (AdbParsePmListLineTool::definition(), Box::new(AdbParsePmListLineTool)),
        (AdbParsePmListOutputTool::definition(), Box::new(AdbParsePmListOutputTool)),
        (AdbBuildInstallCommandTool::definition(), Box::new(AdbBuildInstallCommandTool)),
        (AdbBuildUninstallCommandTool::definition(), Box::new(AdbBuildUninstallCommandTool)),
        (AdbMsgConnectTool::definition(), Box::new(AdbMsgConnectTool)),
        (AdbMsgOpenTool::definition(), Box::new(AdbMsgOpenTool)),
        (AdbMsgOkayTool::definition(), Box::new(AdbMsgOkayTool)),
        (AdbMsgCloseTool::definition(), Box::new(AdbMsgCloseTool)),
        (AdbMsgWriteTool::definition(), Box::new(AdbMsgWriteTool)),
        (AdbMsgAuthTool::definition(), Box::new(AdbMsgAuthTool)),
        (AdbParseGetpropOutputTool::definition(), Box::new(AdbParseGetpropOutputTool)),
        (AdbParseDevicesLongTool::definition(), Box::new(AdbParseDevicesLongTool)),
        (AdbMakeCloseTool::definition(), Box::new(AdbMakeCloseTool)),
        (AdbParseFeaturesTool::definition(), Box::new(AdbParseFeaturesTool)),
        (AdbLogLevelAsCharTool::definition(), Box::new(AdbLogLevelAsCharTool)),
        (AdbLogLevelSeverityTool::definition(), Box::new(AdbLogLevelSeverityTool)),
        (AdbDeviceStateClassifyTool::definition(), Box::new(AdbDeviceStateClassifyTool)),
        (AdbMessageNewTool::definition(), Box::new(AdbMessageNewTool)),
        (AdbMessageVerifyCrcTool::definition(), Box::new(AdbMessageVerifyCrcTool)),
        (AdbMessageCommandNameTool::definition(), Box::new(AdbMessageCommandNameTool)),
        (AdbParseLogcatOutputTool::definition(), Box::new(AdbParseLogcatOutputTool)),
        (AdbCommandConstantTool::definition(), Box::new(AdbCommandConstantTool)),
        (AdbBuildBannerTool::definition(), Box::new(AdbBuildBannerTool)),
        (AdbMakeOkayTool::definition(), Box::new(AdbMakeOkayTool)),
        (AdbMakeConnectTool::definition(), Box::new(AdbMakeConnectTool)),
        (AdbMakeConnectDeviceTool::definition(), Box::new(AdbMakeConnectDeviceTool)),
        (AdbMakeAuthTokenTool::definition(), Box::new(AdbMakeAuthTokenTool)),
        (AdbMakeAuthSignatureTool::definition(), Box::new(AdbMakeAuthSignatureTool)),
        (AdbMakeAuthPublicKeyTool::definition(), Box::new(AdbMakeAuthPublicKeyTool)),
        (AdbMakeOpenTool::definition(), Box::new(AdbMakeOpenTool)),
        (AdbMakeWriteTool::definition(), Box::new(AdbMakeWriteTool)),
        (AdbCurrentMtimeTool::definition(), Box::new(AdbCurrentMtimeTool)),
        (AdbEncodeStatRequestTool::definition(), Box::new(AdbEncodeStatRequestTool)),
        (AdbEncodeListRequestTool::definition(), Box::new(AdbEncodeListRequestTool)),
        (AdbEncodeDataChunkTool::definition(), Box::new(AdbEncodeDataChunkTool)),
        (AdbEncodeDoneTool::definition(), Box::new(AdbEncodeDoneTool)),
        (AdbLogEntryParseBriefV2Tool::definition(), Box::new(AdbLogEntryParseBriefV2Tool)),
        (AdbLogEntryParseAutoTool::definition(), Box::new(AdbLogEntryParseAutoTool)),
        (AdbDeviceStateIsOnlineTool::definition(), Box::new(AdbDeviceStateIsOnlineTool)),
        (AdbDeviceStateNeedsAuthTool::definition(), Box::new(AdbDeviceStateNeedsAuthTool)),
        (AdbShellResultSuccessTool::definition(), Box::new(AdbShellResultSuccessTool)),
        (AdbMessageEncodeTool::definition(), Box::new(AdbMessageEncodeTool)),
        (AdbLocalClientInfoTool::definition(), Box::new(AdbLocalClientInfoTool)),
        (AdbVersionConstantTool::definition(), Box::new(AdbVersionConstantTool)),
        (AdbMaxPayloadConstantTool::definition(), Box::new(AdbMaxPayloadConstantTool)),
        (AdbSyncMaxDataChunkTool::definition(), Box::new(AdbSyncMaxDataChunkTool)),
        (AdbSyncCmdTagsTool::definition(), Box::new(AdbSyncCmdTagsTool)),
        (AdbCrc32RoundtripTool::definition(), Box::new(AdbCrc32RoundtripTool)),
        (AdbServiceShellCmdTool::definition(), Box::new(AdbServiceShellCmdTool)),
        (AdbServiceTransportSerialTool::definition(), Box::new(AdbServiceTransportSerialTool)),
        (AdbServiceForwardTool::definition(), Box::new(AdbServiceForwardTool)),
        (AdbServiceReverseTool::definition(), Box::new(AdbServiceReverseTool)),
        (AdbMessageNoDataTool::definition(), Box::new(AdbMessageNoDataTool)),
        (AdbMessageDataStrTool::definition(), Box::new(AdbMessageDataStrTool)),
        (AdbConnectBannerParseTool::definition(), Box::new(AdbConnectBannerParseTool)),
        (AdbConnectBannerHasFeatureTool::definition(), Box::new(AdbConnectBannerHasFeatureTool)),
        (AdbSyncEncodeStatTool::definition(), Box::new(AdbSyncEncodeStatTool)),
        (AdbSyncEncodeListTool::definition(), Box::new(AdbSyncEncodeListTool)),
        (AdbSyncEncodeRecvTool::definition(), Box::new(AdbSyncEncodeRecvTool)),
        (AdbSyncEncodeQuitTool::definition(), Box::new(AdbSyncEncodeQuitTool)),
        (AdbServiceConstantsTool::definition(), Box::new(AdbServiceConstantsTool)),
        (AdbProtocolStateMachineNewTool::definition(), Box::new(AdbProtocolStateMachineNewTool)),
        (AdbProtocolDefaultPortTool::definition(), Box::new(AdbProtocolDefaultPortTool)),
        (AdbProtocolMaxDataTool::definition(), Box::new(AdbProtocolMaxDataTool)),
        (AdbProtocolVersionConstantTool::definition(), Box::new(AdbProtocolVersionConstantTool)),
        (AdbProtocolAuthConstantsTool::definition(), Box::new(AdbProtocolAuthConstantsTool)),
        (AdbProtocolCmdConstantsTool::definition(), Box::new(AdbProtocolCmdConstantsTool)),
        (AdbLogLevelDisplayTool::definition(), Box::new(AdbLogLevelDisplayTool)),
        (AdbRebootServiceConstantsTool::definition(), Box::new(AdbRebootServiceConstantsTool)),
        (AdbMsgNoDataEncodedTool::definition(), Box::new(AdbMsgNoDataEncodedTool)),
        (AdbClientNewWithTimeoutTool::definition(), Box::new(AdbClientNewWithTimeoutTool)),
        (AdbCmdAllConstantsTool::definition(), Box::new(AdbCmdAllConstantsTool)),
        (AdbMessageMagicFieldTool::definition(), Box::new(AdbMessageMagicFieldTool)),
        (AdbMessageCommandNameForU32Tool::definition(), Box::new(AdbMessageCommandNameForU32Tool)),
        (AdbEncodeDecodeRoundtripV2Tool::definition(), Box::new(AdbEncodeDecodeRoundtripV2Tool)),
        (AdbEncodeMessageLengthTool::definition(), Box::new(AdbEncodeMessageLengthTool)),
        (AdbMessageCrcFieldTool::definition(), Box::new(AdbMessageCrcFieldTool)),
        (AdbDeviceIsReadyFromLineTool::definition(), Box::new(AdbDeviceIsReadyFromLineTool)),
        (AdbGroupByTagCountsTool::definition(), Box::new(AdbGroupByTagCountsTool)),
        (AdbLocalClientHostV2Tool::definition(), Box::new(AdbLocalClientHostV2Tool)),
        (AdbFilterByLevelCountTool::definition(), Box::new(AdbFilterByLevelCountTool)),
    ]
}


impl AdbBuildBannerTool {
    #[must_use]
    pub fn definition() -> rustre_mcp_server::ToolDefinition {
        rustre_mcp_server::ToolDefinition {
            name: "adb_build_banner".to_string(),
            description: "Build an ADB CNXN banner.".to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "required": ["system_type", "name"],
                "properties": {
                    "system_type": { "type": "string" },
                    "name":        { "type": "string" }
                }
            }),
            parameters: serde_json::Value::Null,
        }
    }
}

#[async_trait::async_trait]
impl rustre_mcp_server::ToolHandler for AdbBuildBannerTool {
    async fn call(&self, args: serde_json::Value) -> Result<rustre_mcp_server::ToolResult, rustre_mcp_server::McpError> {
        let system_type = args.get("system_type").and_then(serde_json::Value::as_str)
            .ok_or_else(|| rustre_mcp_server::McpError::InvalidParams("missing system_type".into()))?;
        let name = args.get("name").and_then(serde_json::Value::as_str)
            .ok_or_else(|| rustre_mcp_server::McpError::InvalidParams("missing name".into()))?;
        let banner = rustre_adb::build_banner(system_type, name, &[]);
        Ok(rustre_mcp_server::ToolResult::text(
            serde_json::json!({ "banner": banner, "len": banner.len() }).to_string(),
        ))
    }
}

impl AdbMakeOkayTool {
    #[must_use]
    pub fn definition() -> rustre_mcp_server::ToolDefinition {
        rustre_mcp_server::ToolDefinition {
            name: "adb_make_okay".to_string(),
            description: "Build an ADB OKAY message.".to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "required": ["local_id", "remote_id"],
                "properties": {
                    "local_id":  { "type": "integer" },
                    "remote_id": { "type": "integer" }
                }
            }),
            parameters: serde_json::Value::Null,
        }
    }
}

#[async_trait::async_trait]
impl rustre_mcp_server::ToolHandler for AdbMakeOkayTool {
    async fn call(&self, args: serde_json::Value) -> Result<rustre_mcp_server::ToolResult, rustre_mcp_server::McpError> {
        let local_id = args.get("local_id").and_then(serde_json::Value::as_u64)
            .ok_or_else(|| rustre_mcp_server::McpError::InvalidParams("missing local_id".into()))? as u32;
        let remote_id = args.get("remote_id").and_then(serde_json::Value::as_u64)
            .ok_or_else(|| rustre_mcp_server::McpError::InvalidParams("missing remote_id".into()))? as u32;
        let msg = rustre_adb::make_okay(rustre_adb::LocalId(local_id), rustre_adb::RemoteId(remote_id));
        let encoded = msg.encode();
        let hex_out: String = encoded.iter().map(|b| format!("{:02x}", b)).collect();
        Ok(rustre_mcp_server::ToolResult::text(serde_json::json!({
            "command": msg.command,
            "hex": hex_out,
            "len": encoded.len(),
        }).to_string()))
    }
}

