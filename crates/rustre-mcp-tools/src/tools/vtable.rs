//! MCP wrappers for the rustre-vtable crate.
//! Extracted from wire_tools.rs by workflow_split_wire_tools.

use rustre_mcp_server::{McpError, ToolDefinition, ToolHandler, ToolResult};
use serde_json::{json, Value};
use async_trait::async_trait;
use crate::wire_tools::{extract_byte_array};

pub struct VtableParseMsvcRttiTool;

pub struct VtableParseItaniumRttiTool;

pub struct VtableScanBinaryTool;

pub struct VtableMakePtrSectionTool;
impl VtableMakePtrSectionTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "vtable_make_ptr_section".to_string(),
            description: "Build a Section of little-endian pointers via rustre_analysis_vtable::make_ptr_section.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "base": { "type": "integer" },
                    "ptrs": { "type": "array", "items": { "type": "integer" } },
                    "executable": { "type": "boolean" }
                },
                "required": ["base", "ptrs"]
            }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for VtableMakePtrSectionTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let base = args.get("base").and_then(Value::as_u64)
            .ok_or_else(|| McpError::InvalidParams("missing 'base'".to_string()))?;
        let ptrs: Vec<u64> = args.get("ptrs").and_then(Value::as_array)
            .ok_or_else(|| McpError::InvalidParams("missing 'ptrs'".to_string()))?
            .iter().filter_map(Value::as_u64).collect();
        let executable = args.get("executable").and_then(Value::as_bool).unwrap_or(false);
        let s = rustre_analysis_vtable::make_ptr_section(base, &ptrs, executable);
        Ok(ToolResult::text(json!({
            "name": s.name,
            "base_address": s.base_address,
            "end_address": s.end_address(),
            "size": s.data.len(),
            "executable": s.executable,
            "readable": s.readable,
            "writable": s.writable,
            "source": "rustre_analysis_vtable::make_ptr_section",
        }).to_string()))
    }
}

pub struct VtableMakeStrSectionTool;
impl VtableMakeStrSectionTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "vtable_make_str_section".to_string(),
            description: "Build a Section holding one NUL-terminated string via rustre_analysis_vtable::make_str_section.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": { "base": { "type": "integer" }, "s": { "type": "string" } },
                "required": ["base", "s"]
            }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for VtableMakeStrSectionTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let base = args.get("base").and_then(Value::as_u64)
            .ok_or_else(|| McpError::InvalidParams("missing 'base'".to_string()))?;
        let s = args.get("s").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 's'".to_string()))?;
        let sec = rustre_analysis_vtable::make_str_section(base, s);
        Ok(ToolResult::text(json!({
            "name": sec.name,
            "base_address": sec.base_address,
            "end_address": sec.end_address(),
            "size": sec.data.len(),
            "source": "rustre_analysis_vtable::make_str_section",
        }).to_string()))
    }
}

pub struct VtableExtendsTool;
impl VtableExtendsTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "vtable_extends_check".to_string(),
            description: "Test whether vtable A extends B via rustre_analysis_vtable::vtable_extends.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "a_base": { "type": "integer" },
                    "a_entries": { "type": "array", "items": { "type": "integer" } },
                    "b_base": { "type": "integer" },
                    "b_entries": { "type": "array", "items": { "type": "integer" } }
                },
                "required": ["a_base", "a_entries", "b_base", "b_entries"]
            }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for VtableExtendsTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        fn build_vt(args: &Value, base_key: &str, entries_key: &str) -> Result<rustre_analysis_vtable::Vtable, McpError> {
            let base = args.get(base_key).and_then(Value::as_u64)
                .ok_or_else(|| McpError::InvalidParams(format!("missing '{}'", base_key)))?;
            let ents: Vec<u64> = args.get(entries_key).and_then(Value::as_array)
                .ok_or_else(|| McpError::InvalidParams(format!("missing '{}'", entries_key)))?
                .iter().filter_map(Value::as_u64).collect();
            let mut vt = rustre_analysis_vtable::Vtable::new(base);
            for (i, addr) in ents.iter().enumerate() {
                vt.add_entry(rustre_analysis_vtable::VtableEntry::new(i * 8, *addr));
            }
            Ok(vt)
        }
        let a = build_vt(&args, "a_base", "a_entries")?;
        let b = build_vt(&args, "b_base", "b_entries")?;
        let extends = rustre_analysis_vtable::vtable_extends(&a, &b);
        Ok(ToolResult::text(json!({
            "extends": extends,
            "a_entry_count": a.entry_count(),
            "b_entry_count": b.entry_count(),
            "source": "rustre_analysis_vtable::vtable_extends",
        }).to_string()))
    }
}

pub struct VtableDemangleMsvcNameTool;
impl VtableDemangleMsvcNameTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "vtable_demangle_msvc_name".to_string(),
            description: "Minimal MSVC RTTI name demangling via rustre_analysis_vtable::MsvcRttiDecoder::demangle_msvc.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": { "name": { "type": "string" } },
                "required": ["name"]
            }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for VtableDemangleMsvcNameTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let name = args.get("name").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'name'".to_string()))?;
        let out = rustre_analysis_vtable::MsvcRttiDecoder::demangle_msvc(name);
        Ok(ToolResult::text(json!({
            "demangled": out,
            "source": "rustre_analysis_vtable::MsvcRttiDecoder::demangle_msvc",
        }).to_string()))
    }
}

pub struct VtableSectionReadPtrTool;
impl VtableSectionReadPtrTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "vtable_section_read_ptr".to_string(),
            description: "Read a little-endian pointer at addr via rustre_analysis_vtable::Section::read_ptr.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "data": { "type": "array", "items": { "type": "integer" } },
                    "hex": { "type": "string" },
                    "base": { "type": "integer" },
                    "addr": { "type": "integer" },
                    "ptr_size": { "type": "integer" }
                },
                "required": ["base", "addr", "ptr_size"]
            }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for VtableSectionReadPtrTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let data = extract_byte_array(&args, "data", "hex")?;
        let base = args.get("base").and_then(Value::as_u64)
            .ok_or_else(|| McpError::InvalidParams("missing 'base'".to_string()))?;
        let addr = args.get("addr").and_then(Value::as_u64)
            .ok_or_else(|| McpError::InvalidParams("missing 'addr'".to_string()))?;
        let ptr_size = args.get("ptr_size").and_then(Value::as_u64)
            .ok_or_else(|| McpError::InvalidParams("missing 'ptr_size'".to_string()))? as usize;
        let sec = rustre_analysis_vtable::Section::new("blob", base, data);
        let v = sec.read_ptr(addr, ptr_size);
        Ok(ToolResult::text(json!({
            "value": v,
            "source": "rustre_analysis_vtable::Section::read_ptr",
        }).to_string()))
    }
}

pub struct VtableSectionReadCstrTool;
impl VtableSectionReadCstrTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "vtable_section_read_cstr".to_string(),
            description: "Read a NUL-terminated C string at addr via rustre_analysis_vtable::Section::read_cstr.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "data": { "type": "array", "items": { "type": "integer" } },
                    "hex": { "type": "string" },
                    "base": { "type": "integer" },
                    "addr": { "type": "integer" }
                },
                "required": ["base", "addr"]
            }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for VtableSectionReadCstrTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let data = extract_byte_array(&args, "data", "hex")?;
        let base = args.get("base").and_then(Value::as_u64)
            .ok_or_else(|| McpError::InvalidParams("missing 'base'".to_string()))?;
        let addr = args.get("addr").and_then(Value::as_u64)
            .ok_or_else(|| McpError::InvalidParams("missing 'addr'".to_string()))?;
        let sec = rustre_analysis_vtable::Section::new("blob", base, data);
        let v = sec.read_cstr(addr);
        Ok(ToolResult::text(json!({
            "value": v,
            "source": "rustre_analysis_vtable::Section::read_cstr",
        }).to_string()))
    }
}

pub struct VtableSectionReadI32Tool;
impl VtableSectionReadI32Tool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "vtable_section_read_i32".to_string(),
            description: "Read a little-endian i32 at addr via rustre_analysis_vtable::Section::read_i32.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "data": { "type": "array", "items": { "type": "integer" } },
                    "hex": { "type": "string" },
                    "base": { "type": "integer" },
                    "addr": { "type": "integer" }
                },
                "required": ["base", "addr"]
            }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for VtableSectionReadI32Tool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let data = extract_byte_array(&args, "data", "hex")?;
        let base = args.get("base").and_then(Value::as_u64)
            .ok_or_else(|| McpError::InvalidParams("missing 'base'".to_string()))?;
        let addr = args.get("addr").and_then(Value::as_u64)
            .ok_or_else(|| McpError::InvalidParams("missing 'addr'".to_string()))?;
        let sec = rustre_analysis_vtable::Section::new("blob", base, data);
        let v = sec.read_i32(addr);
        Ok(ToolResult::text(json!({
            "value": v,
            "source": "rustre_analysis_vtable::Section::read_i32",
        }).to_string()))
    }
}

pub struct VtableSectionReadU32Tool;
impl VtableSectionReadU32Tool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "vtable_section_read_u32".to_string(),
            description: "Read a little-endian u32 at addr via rustre_analysis_vtable::Section::read_u32.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "data": { "type": "array", "items": { "type": "integer" } },
                    "hex": { "type": "string" },
                    "base": { "type": "integer" },
                    "addr": { "type": "integer" }
                },
                "required": ["base", "addr"]
            }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for VtableSectionReadU32Tool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let data = extract_byte_array(&args, "data", "hex")?;
        let base = args.get("base").and_then(Value::as_u64)
            .ok_or_else(|| McpError::InvalidParams("missing 'base'".to_string()))?;
        let addr = args.get("addr").and_then(Value::as_u64)
            .ok_or_else(|| McpError::InvalidParams("missing 'addr'".to_string()))?;
        let sec = rustre_analysis_vtable::Section::new("blob", base, data);
        let v = sec.read_u32(addr);
        Ok(ToolResult::text(json!({
            "value": v,
            "source": "rustre_analysis_vtable::Section::read_u32",
        }).to_string()))
    }
}

pub struct VtableSectionRangeTool;
impl VtableSectionRangeTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "vtable_section_range".to_string(),
            description: "Compute end_address and contains(addr) for a Section blob.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "data": { "type": "array", "items": { "type": "integer" } },
                    "hex": { "type": "string" },
                    "base": { "type": "integer" },
                    "addr": { "type": "integer" }
                },
                "required": ["base"]
            }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for VtableSectionRangeTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let data = extract_byte_array(&args, "data", "hex").unwrap_or_default();
        let base = args.get("base").and_then(Value::as_u64)
            .ok_or_else(|| McpError::InvalidParams("missing 'base'".to_string()))?;
        let sec = rustre_analysis_vtable::Section::new("blob", base, data);
        let end = sec.end_address();
        let contains = args.get("addr").and_then(Value::as_u64).map(|a| sec.contains(a));
        Ok(ToolResult::text(json!({
            "base_address": sec.base_address,
            "end_address": end,
            "size": sec.data.len(),
            "contains": contains,
            "source": "rustre_analysis_vtable::Section",
        }).to_string()))
    }
}

pub struct VtableVmiFlagsDecodeTool;
impl VtableVmiFlagsDecodeTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "vtable_vmi_flags_decode".to_string(),
            description: "Decode Itanium __vmi_class_type_info::__flags bits via rustre_analysis_vtable::VmiFlags.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": { "flags": { "type": "integer" } },
                "required": ["flags"]
            }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for VtableVmiFlagsDecodeTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let flags = args.get("flags").and_then(Value::as_u64)
            .ok_or_else(|| McpError::InvalidParams("missing 'flags'".to_string()))? as u32;
        let f = rustre_analysis_vtable::VmiFlags(flags);
        Ok(ToolResult::text(json!({
            "flags": flags,
            "is_diamond_shaped": f.is_diamond_shaped(),
            "has_non_diamond_repeat": f.has_non_diamond_repeat(),
            "source": "rustre_analysis_vtable::VmiFlags",
        }).to_string()))
    }
}

pub struct VtableEntryDisplayTool;
impl VtableEntryDisplayTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "vtable_entry_display".to_string(),
            description: "Format a VtableEntry via its Display impl.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "offset": { "type": "integer" },
                    "target_address": { "type": "integer" },
                    "name": { "type": "string" }
                },
                "required": ["offset", "target_address"]
            }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for VtableEntryDisplayTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let offset = args.get("offset").and_then(Value::as_u64)
            .ok_or_else(|| McpError::InvalidParams("missing 'offset'".to_string()))? as usize;
        let target = args.get("target_address").and_then(Value::as_u64)
            .ok_or_else(|| McpError::InvalidParams("missing 'target_address'".to_string()))?;
        let e = if let Some(n) = args.get("name").and_then(Value::as_str) {
            rustre_analysis_vtable::VtableEntry::with_name(offset, target, n)
        } else {
            rustre_analysis_vtable::VtableEntry::new(offset, target)
        };
        Ok(ToolResult::text(json!({
            "display": e.to_string(),
            "source": "rustre_analysis_vtable::VtableEntry::Display",
        }).to_string()))
    }
}

pub struct VtableScannerConfiguredScanTool;
impl VtableScannerConfiguredScanTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "vtable_scanner_configured_scan".to_string(),
            description: "Run VtableScanner::new(ptr_size,min_slots)::scan on a blob.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "data": { "type": "array", "items": { "type": "integer" } },
                    "hex": { "type": "string" },
                    "base": { "type": "integer" },
                    "ptr_size": { "type": "integer" },
                    "min_slots": { "type": "integer" }
                },
                "required": ["base", "ptr_size", "min_slots"]
            }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for VtableScannerConfiguredScanTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let data = extract_byte_array(&args, "data", "hex")?;
        let base = args.get("base").and_then(Value::as_u64)
            .ok_or_else(|| McpError::InvalidParams("missing 'base'".to_string()))?;
        let ptr_size_raw = args.get("ptr_size").and_then(Value::as_u64)
            .ok_or_else(|| McpError::InvalidParams("missing 'ptr_size'".to_string()))?;
        // VtableScanner requires ptr_size to be 4 or 8; clamp 0/other to 8 (x86_64 default).
        let ptr_size = if ptr_size_raw == 4 || ptr_size_raw == 8 { ptr_size_raw as usize } else { 8 };
        let min_slots = (args.get("min_slots").and_then(Value::as_u64)
            .ok_or_else(|| McpError::InvalidParams("missing 'min_slots'".to_string()))?
            .max(1)) as usize;
        let scanner = rustre_analysis_vtable::VtableScanner::new(ptr_size, min_slots);
        let cands = scanner.scan(&data, base);
        Ok(ToolResult::text(json!({
            "count": cands.len(),
            "candidates": cands,
            "source": "rustre_analysis_vtable::VtableScanner::scan",
        }).to_string()))
    }
}

pub struct VtableAnalysisPassNameTool;
impl VtableAnalysisPassNameTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "vtable_analysis_pass_name".to_string(),
            description: "Return the AnalysisPass name for rustre_analysis_vtable::VtableAnalysisPass.".to_string(),
            input_schema: json!({ "type": "object", "properties": {} }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for VtableAnalysisPassNameTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        use rustre_analysis::AnalysisPass;
        let p = rustre_analysis_vtable::VtableAnalysisPass::new();
        Ok(ToolResult::text(json!({
            "name": p.name(),
            "source": "rustre_analysis_vtable::VtableAnalysisPass::name",
        }).to_string()))
    }
}

pub struct VtableIsItaniumMangledTool;

pub struct VtableIsMsvcMangledTool;

pub struct VtableEntryNewWireTool;
impl VtableEntryNewWireTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "vtable_entry_new_wire".to_string(), description: "Construct VtableEntry::new and return its fields.".to_string(), input_schema: json!({"type":"object","properties":{"offset":{"type":"integer"},"target_address":{"type":"integer"}},"required":["offset","target_address"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for VtableEntryNewWireTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let off = args.get("offset").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'offset'".into()))? as usize; let tgt = args.get("target_address").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'target_address'".into()))?; let e = rustre_analysis_vtable::VtableEntry::new(off, tgt); Ok(ToolResult::text(json!({"offset":e.offset,"target_address":e.target_address,"has_name":e.function_name.is_some(),"source":"rustre_analysis_vtable::VtableEntry::new"}).to_string())) } }

pub struct VtableNewAddEntryWireTool;
impl VtableNewAddEntryWireTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "vtable_new_add_entry_wire".to_string(), description: "Vtable::new + add_entry, return entry_count.".to_string(), input_schema: json!({"type":"object","properties":{"base":{"type":"integer"},"targets":{"type":"array","items":{"type":"integer"}}},"required":["base","targets"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for VtableNewAddEntryWireTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let base = args.get("base").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'base'".into()))?; let targets: Vec<u64> = args.get("targets").and_then(Value::as_array).map(|a| a.iter().filter_map(Value::as_u64).collect()).unwrap_or_default(); let mut vt = rustre_analysis_vtable::Vtable::new(base); for (i, t) in targets.iter().enumerate() { vt.add_entry(rustre_analysis_vtable::VtableEntry::new(i*8, *t)); } Ok(ToolResult::text(json!({"base":vt.base_address,"entry_count":vt.entry_count(),"method_count":vt.method_count(),"display":vt.to_string(),"source":"rustre_analysis_vtable::Vtable::add_entry"}).to_string())) } }

pub struct VtablePureVirtualDetectorWireTool;
impl VtablePureVirtualDetectorWireTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "vtable_pure_virtual_detector_wire".to_string(), description: "Check if a VtableEntry is a pure-virtual stub.".to_string(), input_schema: json!({"type":"object","properties":{"name":{"type":"string"},"address":{"type":"integer"},"stub_addresses":{"type":"array","items":{"type":"integer"}}},"required":["address"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for VtablePureVirtualDetectorWireTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let addr = args.get("address").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'address'".into()))?; let mut det = rustre_analysis_vtable::PureVirtualDetector::new(); if let Some(arr) = args.get("stub_addresses").and_then(Value::as_array) { for v in arr { if let Some(a) = v.as_u64() { det.add_stub_address(a); } } } let entry = if let Some(n) = args.get("name").and_then(Value::as_str) { rustre_analysis_vtable::VtableEntry::with_name(0, addr, n) } else { rustre_analysis_vtable::VtableEntry::new(0, addr) }; Ok(ToolResult::text(json!({"is_pure_virtual":det.is_pure_virtual(&entry),"address":addr,"source":"rustre_analysis_vtable::PureVirtualDetector::is_pure_virtual"}).to_string())) } }

pub struct VtableComparerDiffWireTool;
impl VtableComparerDiffWireTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "vtable_comparer_diff_wire".to_string(), description: "Diff two vtables (given as target arrays) via VtableComparer::diff.".to_string(), input_schema: json!({"type":"object","properties":{"original":{"type":"array","items":{"type":"integer"}},"patched":{"type":"array","items":{"type":"integer"}}},"required":["original","patched"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for VtableComparerDiffWireTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let orig: Vec<u64> = args.get("original").and_then(Value::as_array).map(|a| a.iter().filter_map(Value::as_u64).collect()).unwrap_or_default(); let patched: Vec<u64> = args.get("patched").and_then(Value::as_array).map(|a| a.iter().filter_map(Value::as_u64).collect()).unwrap_or_default(); let mut a = rustre_analysis_vtable::Vtable::new(0); for (i, t) in orig.iter().enumerate() { a.add_entry(rustre_analysis_vtable::VtableEntry::new(i*8, *t)); } let mut b = rustre_analysis_vtable::Vtable::new(0); for (i, t) in patched.iter().enumerate() { b.add_entry(rustre_analysis_vtable::VtableEntry::new(i*8, *t)); } let cmp = rustre_analysis_vtable::VtableComparer::new(); let diffs = cmp.diff(&a, &b); Ok(ToolResult::text(json!({"diff_count":diffs.len(),"is_identical":cmp.is_identical(&a,&b),"diffs":diffs,"source":"rustre_analysis_vtable::VtableComparer::diff"}).to_string())) } }

pub struct VtableStatsFromDatabaseWireTool;
impl VtableStatsFromDatabaseWireTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "vtable_stats_from_database_wire".to_string(), description: "Build a VtableDatabase from arrays of vtable target lists and compute VtableStats.".to_string(), input_schema: json!({"type":"object","properties":{"vtables":{"type":"array","items":{"type":"array","items":{"type":"integer"}}}},"required":["vtables"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for VtableStatsFromDatabaseWireTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let vts = args.get("vtables").and_then(Value::as_array).ok_or_else(|| McpError::InvalidParams("missing 'vtables'".into()))?; let mut db = rustre_analysis_vtable::VtableDatabase::new(); for (idx, v) in vts.iter().enumerate() { let mut vt = rustre_analysis_vtable::Vtable::new(0x1000 + idx as u64 * 0x100); if let Some(arr) = v.as_array() { for (i, e) in arr.iter().enumerate() { if let Some(t) = e.as_u64() { vt.add_entry(rustre_analysis_vtable::VtableEntry::new(i*8, t)); } } } db.add_vtable(vt); } let stats = rustre_analysis_vtable::VtableStats::from_database(&db); Ok(ToolResult::text(json!({"vtable_count":stats.vtable_count,"total_slots":stats.total_slots,"avg_slots":stats.avg_slots,"max_slots":stats.max_slots,"pure_virtual_count":stats.pure_virtual_count,"source":"rustre_analysis_vtable::VtableStats::from_database"}).to_string())) } }

pub struct VtableExtendsHeuristicWireTool;
impl VtableExtendsHeuristicWireTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "vtable_extends_heuristic_wire".to_string(), description: "Test if vtable b extends vtable a via vtable_extends prefix heuristic.".to_string(), input_schema: json!({"type":"object","properties":{"a":{"type":"array","items":{"type":"integer"}},"b":{"type":"array","items":{"type":"integer"}}},"required":["a","b"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for VtableExtendsHeuristicWireTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let av: Vec<u64> = args.get("a").and_then(Value::as_array).map(|a| a.iter().filter_map(Value::as_u64).collect()).unwrap_or_default(); let bv: Vec<u64> = args.get("b").and_then(Value::as_array).map(|a| a.iter().filter_map(Value::as_u64).collect()).unwrap_or_default(); let mut a = rustre_analysis_vtable::Vtable::new(0x1000); for (i, t) in av.iter().enumerate() { a.add_entry(rustre_analysis_vtable::VtableEntry::new(i*8, *t)); } let mut b = rustre_analysis_vtable::Vtable::new(0x2000); for (i, t) in bv.iter().enumerate() { b.add_entry(rustre_analysis_vtable::VtableEntry::new(i*8, *t)); } Ok(ToolResult::text(json!({"a_extends_b":rustre_analysis_vtable::vtable_extends(&a,&b),"b_extends_a":rustre_analysis_vtable::vtable_extends(&b,&a),"source":"rustre_analysis_vtable::vtable_extends"}).to_string())) } }

pub struct VtableBuilderEdgesWireTool;
impl VtableBuilderEdgesWireTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "vtable_builder_edges_wire".to_string(), description: "Build inheritance edges from a set of vtables via VtableBuilder::edges.".to_string(), input_schema: json!({"type":"object","properties":{"vtables":{"type":"array","items":{"type":"array","items":{"type":"integer"}}}},"required":["vtables"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for VtableBuilderEdgesWireTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let vts = args.get("vtables").and_then(Value::as_array).ok_or_else(|| McpError::InvalidParams("missing 'vtables'".into()))?; let mut builder = rustre_analysis_vtable::VtableBuilder::new(); for (idx, v) in vts.iter().enumerate() { let mut vt = rustre_analysis_vtable::Vtable::new(0x1000 + idx as u64 * 0x100); if let Some(arr) = v.as_array() { for (i, e) in arr.iter().enumerate() { if let Some(t) = e.as_u64() { vt.add_entry(rustre_analysis_vtable::VtableEntry::new(i*8, t)); } } } builder.add_vtable(vt); } let edges = builder.edges(); Ok(ToolResult::text(json!({"edge_count":edges.len(),"edges":edges,"source":"rustre_analysis_vtable::VtableBuilder::edges"}).to_string())) } }

pub struct VtableSetToJsonWireTool;
impl VtableSetToJsonWireTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "vtable_set_to_json_wire".to_string(), description: "Serialise a VtableSet to JSON via VtableSet::to_json.".to_string(), input_schema: json!({"type":"object","properties":{"vtables":{"type":"array","items":{"type":"array","items":{"type":"integer"}}}},"required":["vtables"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for VtableSetToJsonWireTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let vts = args.get("vtables").and_then(Value::as_array).ok_or_else(|| McpError::InvalidParams("missing 'vtables'".into()))?; let mut set = rustre_analysis_vtable::VtableSet::new(); for (idx, v) in vts.iter().enumerate() { let mut vt = rustre_analysis_vtable::Vtable::new(0x1000 + idx as u64 * 0x100); if let Some(arr) = v.as_array() { for (i, e) in arr.iter().enumerate() { if let Some(t) = e.as_u64() { vt.add_entry(rustre_analysis_vtable::VtableEntry::new(i*8, t)); } } } set.push(vt); } Ok(ToolResult::text(json!({"len":set.len(),"is_empty":set.is_empty(),"json":set.to_json(),"source":"rustre_analysis_vtable::VtableSet::to_json"}).to_string())) } }

pub struct VtableAbstractClassInferenceWireTool;
impl VtableAbstractClassInferenceWireTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "vtable_abstract_class_inference_wire".to_string(), description: "Infer abstract classes from a VtableDatabase via AbstractClassInference::infer.".to_string(), input_schema: json!({"type":"object","properties":{"vtables":{"type":"array","items":{"type":"array","items":{"type":"integer"}}},"stub_addresses":{"type":"array","items":{"type":"integer"}}},"required":["vtables"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for VtableAbstractClassInferenceWireTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let vts = args.get("vtables").and_then(Value::as_array).ok_or_else(|| McpError::InvalidParams("missing 'vtables'".into()))?; let mut det = rustre_analysis_vtable::PureVirtualDetector::new(); if let Some(arr) = args.get("stub_addresses").and_then(Value::as_array) { for v in arr { if let Some(a) = v.as_u64() { det.add_stub_address(a); } } } let mut db = rustre_analysis_vtable::VtableDatabase::new(); for (idx, v) in vts.iter().enumerate() { let mut vt = rustre_analysis_vtable::Vtable::new(0x1000 + idx as u64 * 0x100); if let Some(arr) = v.as_array() { for (i, e) in arr.iter().enumerate() { if let Some(t) = e.as_u64() { vt.add_entry(rustre_analysis_vtable::VtableEntry::new(i*8, t)); } } } db.add_vtable(vt); } let inference = rustre_analysis_vtable::AbstractClassInference::with_detector(det); let results = inference.infer(&db); Ok(ToolResult::text(json!({"count":results.len(),"results":results,"source":"rustre_analysis_vtable::AbstractClassInference::infer"}).to_string())) } }

pub struct VtableMiLayoutBuildWireTool;
impl VtableMiLayoutBuildWireTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "vtable_mi_layout_build_wire".to_string(), description: "Build a MultipleInheritanceLayout with sub-objects and inspect primary/secondary vtables.".to_string(), input_schema: json!({"type":"object","properties":{"derived":{"type":"string"},"object_size":{"type":"integer"},"subs":{"type":"array"}},"required":["derived","object_size","subs"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for VtableMiLayoutBuildWireTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let derived = args.get("derived").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'derived'".into()))?; let size = args.get("object_size").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'object_size'".into()))? as usize; let mut layout = rustre_analysis_vtable::MultipleInheritanceLayout::new(derived, size); if let Some(arr) = args.get("subs").and_then(Value::as_array) { for s in arr { let name = s.get("class_name").and_then(Value::as_str).unwrap_or("Base").to_string(); let off = s.get("offset").and_then(Value::as_u64).unwrap_or(0) as usize; let vta = s.get("vtable_address").and_then(Value::as_u64); let primary = s.get("is_primary").and_then(Value::as_bool).unwrap_or(false); layout.add_sub_object(rustre_analysis_vtable::SubObject { class_name: name, offset: off, vtable_address: vta, is_primary: primary }); } } Ok(ToolResult::text(json!({"derived_class":layout.derived_class,"object_size":layout.object_size,"base_count":layout.base_count(),"primary_vtable":layout.primary_vtable(),"secondary_vtables":layout.secondary_vtables(),"source":"rustre_analysis_vtable::MultipleInheritanceLayout"}).to_string())) } }

pub fn handlers() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    vec![
        (VtableParseMsvcRttiTool::definition(), Box::new(VtableParseMsvcRttiTool)),
        (VtableParseItaniumRttiTool::definition(), Box::new(VtableParseItaniumRttiTool)),
        (VtableScanBinaryTool::definition(), Box::new(VtableScanBinaryTool)),
        (VtableMakePtrSectionTool::definition(), Box::new(VtableMakePtrSectionTool)),
        (VtableMakeStrSectionTool::definition(), Box::new(VtableMakeStrSectionTool)),
        (VtableExtendsTool::definition(), Box::new(VtableExtendsTool)),
        (VtableDemangleMsvcNameTool::definition(), Box::new(VtableDemangleMsvcNameTool)),
        (VtableSectionReadPtrTool::definition(), Box::new(VtableSectionReadPtrTool)),
        (VtableSectionReadCstrTool::definition(), Box::new(VtableSectionReadCstrTool)),
        (VtableSectionReadI32Tool::definition(), Box::new(VtableSectionReadI32Tool)),
        (VtableSectionReadU32Tool::definition(), Box::new(VtableSectionReadU32Tool)),
        (VtableSectionRangeTool::definition(), Box::new(VtableSectionRangeTool)),
        (VtableVmiFlagsDecodeTool::definition(), Box::new(VtableVmiFlagsDecodeTool)),
        (VtableEntryDisplayTool::definition(), Box::new(VtableEntryDisplayTool)),
        (VtableScannerConfiguredScanTool::definition(), Box::new(VtableScannerConfiguredScanTool)),
        (VtableAnalysisPassNameTool::definition(), Box::new(VtableAnalysisPassNameTool)),
        (VtableIsItaniumMangledTool::definition(), Box::new(VtableIsItaniumMangledTool)),
        (VtableIsMsvcMangledTool::definition(), Box::new(VtableIsMsvcMangledTool)),
        (VtableEntryNewWireTool::definition(), Box::new(VtableEntryNewWireTool)),
        (VtableNewAddEntryWireTool::definition(), Box::new(VtableNewAddEntryWireTool)),
        (VtablePureVirtualDetectorWireTool::definition(), Box::new(VtablePureVirtualDetectorWireTool)),
        (VtableComparerDiffWireTool::definition(), Box::new(VtableComparerDiffWireTool)),
        (VtableStatsFromDatabaseWireTool::definition(), Box::new(VtableStatsFromDatabaseWireTool)),
        (VtableExtendsHeuristicWireTool::definition(), Box::new(VtableExtendsHeuristicWireTool)),
        (VtableBuilderEdgesWireTool::definition(), Box::new(VtableBuilderEdgesWireTool)),
        (VtableSetToJsonWireTool::definition(), Box::new(VtableSetToJsonWireTool)),
        (VtableAbstractClassInferenceWireTool::definition(), Box::new(VtableAbstractClassInferenceWireTool)),
        (VtableMiLayoutBuildWireTool::definition(), Box::new(VtableMiLayoutBuildWireTool)),
    ]
}
