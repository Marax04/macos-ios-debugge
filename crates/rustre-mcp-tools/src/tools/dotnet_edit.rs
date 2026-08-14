//! MCP wrappers for the rustre-dotnet_edit crate.
//! Extracted from wire_tools.rs by workflow_split_wire_tools.

use rustre_mcp_server::{McpError, ToolDefinition, ToolHandler, ToolResult};
use serde_json::{json, Value};
use async_trait::async_trait;
use crate::{hex_encode};

pub struct DotnetEditOpcodeByteSizeTool;

pub struct DotnetEditRecomputeOffsetsTool;

pub struct DotnetEditRenumberOffsetsTool;

pub struct DotnetEditEncodeInstructionsTool;

pub struct DotnetEditNopFillRangeTool;

pub struct DotnetEditIlBuilderNopTool;
impl DotnetEditIlBuilderNopTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "dotnet_edit_ilbuilder_nop".to_string(),
            description: "Emit a single nop CIL instruction via rustre_dotnet_edit::IlBuilder::nop.".to_string(),
            input_schema: json!({"type":"object","properties":{}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for DotnetEditIlBuilderNopTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let mut b = rustre_dotnet_edit::IlBuilder::new();
        b.nop();
        let instrs = b.build();
        let opcodes: Vec<String> = instrs.iter().map(|i| i.opcode.clone()).collect();
        Ok(ToolResult::text(json!({"opcodes":opcodes,"source":"rustre_dotnet_edit::IlBuilder::nop"}).to_string()))
    }
}

pub struct DotnetEditIlBuilderRetOpTool;
impl DotnetEditIlBuilderRetOpTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "dotnet_edit_ilbuilder_ret".to_string(),
            description: "Emit ret via rustre_dotnet_edit::IlBuilder::ret.".to_string(),
            input_schema: json!({"type":"object","properties":{}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for DotnetEditIlBuilderRetOpTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let mut b = rustre_dotnet_edit::IlBuilder::new();
        b.ret();
        let instrs = b.build();
        let opcodes: Vec<String> = instrs.iter().map(|i| i.opcode.clone()).collect();
        Ok(ToolResult::text(json!({"opcodes":opcodes,"source":"rustre_dotnet_edit::IlBuilder::ret"}).to_string()))
    }
}

pub struct DotnetEditIlBuilderCallTool;
impl DotnetEditIlBuilderCallTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "dotnet_edit_ilbuilder_call".to_string(),
            description: "Emit call token via rustre_dotnet_edit::IlBuilder::call.".to_string(),
            input_schema: json!({"type":"object","properties":{"token":{"type":"integer","minimum":0}},"required":["token"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for DotnetEditIlBuilderCallTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let v = args.get("token").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'token'".into()))? as u32;
        let mut b = rustre_dotnet_edit::IlBuilder::new();
        b.call(v);
        let instrs = b.build();
        let opcodes: Vec<String> = instrs.iter().map(|i| i.opcode.clone()).collect();
        Ok(ToolResult::text(json!({"token":v,"opcodes":opcodes,"source":"rustre_dotnet_edit::IlBuilder::call"}).to_string()))
    }
}

pub struct DotnetEditIlBuilderCallvirtTool;
impl DotnetEditIlBuilderCallvirtTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "dotnet_edit_ilbuilder_callvirt".to_string(),
            description: "Emit callvirt token via rustre_dotnet_edit::IlBuilder::callvirt.".to_string(),
            input_schema: json!({"type":"object","properties":{"token":{"type":"integer","minimum":0}},"required":["token"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for DotnetEditIlBuilderCallvirtTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let v = args.get("token").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'token'".into()))? as u32;
        let mut b = rustre_dotnet_edit::IlBuilder::new();
        b.callvirt(v);
        let instrs = b.build();
        let opcodes: Vec<String> = instrs.iter().map(|i| i.opcode.clone()).collect();
        Ok(ToolResult::text(json!({"token":v,"opcodes":opcodes,"source":"rustre_dotnet_edit::IlBuilder::callvirt"}).to_string()))
    }
}

pub struct DotnetEditIlBuilderNewobjTool;
impl DotnetEditIlBuilderNewobjTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "dotnet_edit_ilbuilder_newobj".to_string(),
            description: "Emit newobj token via rustre_dotnet_edit::IlBuilder::newobj.".to_string(),
            input_schema: json!({"type":"object","properties":{"token":{"type":"integer","minimum":0}},"required":["token"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for DotnetEditIlBuilderNewobjTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let v = args.get("token").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'token'".into()))? as u32;
        let mut b = rustre_dotnet_edit::IlBuilder::new();
        b.newobj(v);
        let instrs = b.build();
        let opcodes: Vec<String> = instrs.iter().map(|i| i.opcode.clone()).collect();
        Ok(ToolResult::text(json!({"token":v,"opcodes":opcodes,"source":"rustre_dotnet_edit::IlBuilder::newobj"}).to_string()))
    }
}

pub struct DotnetEditIlBuilderLdstrTool;
impl DotnetEditIlBuilderLdstrTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "dotnet_edit_ilbuilder_ldstr".to_string(),
            description: "Emit ldstr token via rustre_dotnet_edit::IlBuilder::ldstr.".to_string(),
            input_schema: json!({"type":"object","properties":{"token":{"type":"integer","minimum":0}},"required":["token"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for DotnetEditIlBuilderLdstrTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let v = args.get("token").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'token'".into()))? as u32;
        let mut b = rustre_dotnet_edit::IlBuilder::new();
        b.ldstr(v);
        let instrs = b.build();
        let opcodes: Vec<String> = instrs.iter().map(|i| i.opcode.clone()).collect();
        Ok(ToolResult::text(json!({"token":v,"opcodes":opcodes,"source":"rustre_dotnet_edit::IlBuilder::ldstr"}).to_string()))
    }
}

pub struct DotnetEditIlBuilderBrfalseSTool;
impl DotnetEditIlBuilderBrfalseSTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "dotnet_edit_ilbuilder_brfalse_s".to_string(),
            description: "Emit brfalse.s target via rustre_dotnet_edit::IlBuilder::brfalse_s.".to_string(),
            input_schema: json!({"type":"object","properties":{"target":{"type":"integer","minimum":0}},"required":["target"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for DotnetEditIlBuilderBrfalseSTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let v = args.get("target").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'target'".into()))? as u32;
        let mut b = rustre_dotnet_edit::IlBuilder::new();
        b.brfalse_s(v);
        let instrs = b.build();
        let opcodes: Vec<String> = instrs.iter().map(|i| i.opcode.clone()).collect();
        Ok(ToolResult::text(json!({"target":v,"opcodes":opcodes,"source":"rustre_dotnet_edit::IlBuilder::brfalse_s"}).to_string()))
    }
}

pub struct DotnetEditIlBuilderBrtrueSTool;
impl DotnetEditIlBuilderBrtrueSTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "dotnet_edit_ilbuilder_brtrue_s".to_string(),
            description: "Emit brtrue.s target via rustre_dotnet_edit::IlBuilder::brtrue_s.".to_string(),
            input_schema: json!({"type":"object","properties":{"target":{"type":"integer","minimum":0}},"required":["target"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for DotnetEditIlBuilderBrtrueSTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let v = args.get("target").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'target'".into()))? as u32;
        let mut b = rustre_dotnet_edit::IlBuilder::new();
        b.brtrue_s(v);
        let instrs = b.build();
        let opcodes: Vec<String> = instrs.iter().map(|i| i.opcode.clone()).collect();
        Ok(ToolResult::text(json!({"target":v,"opcodes":opcodes,"source":"rustre_dotnet_edit::IlBuilder::brtrue_s"}).to_string()))
    }
}

pub struct DotnetEditTokenRemapperRemapTool;
impl DotnetEditTokenRemapperRemapTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "dotnet_edit_token_remapper_remap".to_string(),
            description: "Record insert then remap a token via rustre_dotnet_edit::TokenRemapper.".to_string(),
            input_schema: json!({"type":"object","properties":{"table":{"type":"integer","minimum":0,"maximum":255},"insert_at":{"type":"integer","minimum":1},"total_rows":{"type":"integer","minimum":0},"token":{"type":"integer","minimum":0}},"required":["table","insert_at","total_rows","token"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for DotnetEditTokenRemapperRemapTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let table = args.get("table").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing table".into()))? as u8;
        let at = args.get("insert_at").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing insert_at".into()))? as u32;
        let total = args.get("total_rows").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing total_rows".into()))? as u32;
        let tok = args.get("token").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing token".into()))? as u32;
        let mut r = rustre_dotnet_edit::TokenRemapper::new();
        r.record_insert(table, at, total);
        let outv = r.remap_token(tok);
        Ok(ToolResult::text(json!({"original":tok,"remapped":outv,"len":r.len(),"is_empty":r.is_empty(),"source":"rustre_dotnet_edit::TokenRemapper::remap_token"}).to_string()))
    }
}

pub struct DotnetEditCloneMethodBodyTool;
impl DotnetEditCloneMethodBodyTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "dotnet_edit_clone_method_body".to_string(),
            description: "Clone a CIL method body via rustre_dotnet_edit::clone_method_body with an empty token map.".to_string(),
            input_schema: json!({"type":"object","properties":{"opcodes":{"type":"array","items":{"type":"string"}}},"required":["opcodes"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for DotnetEditCloneMethodBodyTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let arr = args.get("opcodes").and_then(Value::as_array).ok_or_else(|| McpError::InvalidParams("missing opcodes".into()))?;
        let instrs: Vec<rustre_dotnet::CilInstruction> = arr.iter().filter_map(|v| v.as_str()).enumerate().map(|(i, op)| rustre_dotnet::CilInstruction::simple(i as u32, op)).collect();
        let map: std::collections::HashMap<u32, u32> = std::collections::HashMap::new();
        let cloned = rustre_dotnet_edit::clone_method_body(&instrs, &map);
        let opcodes: Vec<String> = cloned.iter().map(|i| i.opcode.clone()).collect();
        Ok(ToolResult::text(json!({"count":opcodes.len(),"opcodes":opcodes,"source":"rustre_dotnet_edit::clone_method_body"}).to_string()))
    }
}

pub struct DotnetEditNewMethodEncodeSigTool;

pub struct DotnetEditManagedResourceIsPublicTool;

pub struct DotnetEditManagedResourceIsPublicWireTool;

pub struct DotnetEditNewMethodEncodeSigWireTool;

pub struct DotnetEditNewFieldPublicFieldWireTool;

pub struct DotnetEditNewFieldPublicStaticWireTool;

pub struct DotnetEditNewMethodInstanceVoidSigTool;
impl DotnetEditNewMethodInstanceVoidSigTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "dotnet_edit_new_method_instance_void_sig".to_string(),
            description: "Encoded method signature blob for a public instance void method with no parameters.".to_string(),
            input_schema: json!({"type":"object","properties":{"name":{"type":"string"}},"required":["name"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for DotnetEditNewMethodInstanceVoidSigTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let name = args.get("name").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'name'".into()))?;
        let desc = rustre_dotnet_edit::NewMethodDescriptor::instance_void(name);
        let sig = desc.encode_sig();
        Ok(ToolResult::text(json!({"name":name,"sig_hex":hex_encode(&sig),"sig_len":sig.len(),"source":"rustre_dotnet_edit::NewMethodDescriptor::instance_void"}).to_string()))
    }
}

pub struct DotnetEditNewFieldPublicSigTool;
impl DotnetEditNewFieldPublicSigTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "dotnet_edit_new_field_public_sig".to_string(),
            description: "Public instance field descriptor with its type signature blob.".to_string(),
            input_schema: json!({"type":"object","properties":{"name":{"type":"string"},"element_type":{"type":"integer"}},"required":["name","element_type"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for DotnetEditNewFieldPublicSigTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let name = args.get("name").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'name'".into()))?;
        let et = args.get("element_type").and_then(Value::as_u64)
            .ok_or_else(|| McpError::InvalidParams("missing 'element_type'".into()))? as u8;
        let d = rustre_dotnet_edit::NewFieldDescriptor::public_field(name, et);
        Ok(ToolResult::text(json!({"name":d.name,"flags":d.flags,"sig_hex":hex_encode(&d.type_sig),"source":"rustre_dotnet_edit::NewFieldDescriptor::public_field"}).to_string()))
    }
}

pub struct DotnetEditNewFieldStaticSigTool;
impl DotnetEditNewFieldStaticSigTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "dotnet_edit_new_field_static_sig".to_string(),
            description: "Public static field descriptor with its type signature blob.".to_string(),
            input_schema: json!({"type":"object","properties":{"name":{"type":"string"},"element_type":{"type":"integer"}},"required":["name","element_type"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for DotnetEditNewFieldStaticSigTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let name = args.get("name").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'name'".into()))?;
        let et = args.get("element_type").and_then(Value::as_u64)
            .ok_or_else(|| McpError::InvalidParams("missing 'element_type'".into()))? as u8;
        let d = rustre_dotnet_edit::NewFieldDescriptor::public_static(name, et);
        Ok(ToolResult::text(json!({"name":d.name,"flags":d.flags,"sig_hex":hex_encode(&d.type_sig),"source":"rustre_dotnet_edit::NewFieldDescriptor::public_static"}).to_string()))
    }
}

pub struct DotnetEditNewTypePublicClassTool;
impl DotnetEditNewTypePublicClassTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "dotnet_edit_new_type_public_class".to_string(),
            description: "Public class type descriptor (flags 0x101).".to_string(),
            input_schema: json!({"type":"object","properties":{"name":{"type":"string"},"namespace":{"type":"string"}},"required":["name","namespace"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for DotnetEditNewTypePublicClassTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let name = args.get("name").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'name'".into()))?;
        let ns = args.get("namespace").and_then(Value::as_str).unwrap_or("");
        let d = rustre_dotnet_edit::NewTypeDescriptor::public_class(name, ns);
        Ok(ToolResult::text(json!({"name":d.name,"namespace":d.namespace,"flags":d.flags,"source":"rustre_dotnet_edit::NewTypeDescriptor::public_class"}).to_string()))
    }
}

pub struct DotnetEditNewTypePublicInterfaceTool;
impl DotnetEditNewTypePublicInterfaceTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "dotnet_edit_new_type_public_interface".to_string(),
            description: "Public interface type descriptor (flags 0xA1).".to_string(),
            input_schema: json!({"type":"object","properties":{"name":{"type":"string"},"namespace":{"type":"string"}},"required":["name","namespace"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for DotnetEditNewTypePublicInterfaceTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let name = args.get("name").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'name'".into()))?;
        let ns = args.get("namespace").and_then(Value::as_str).unwrap_or("");
        let d = rustre_dotnet_edit::NewTypeDescriptor::public_interface(name, ns);
        Ok(ToolResult::text(json!({"name":d.name,"namespace":d.namespace,"flags":d.flags,"source":"rustre_dotnet_edit::NewTypeDescriptor::public_interface"}).to_string()))
    }
}

pub struct DotnetEditManagedResourceNewTool;
impl DotnetEditManagedResourceNewTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "dotnet_edit_managed_resource_new".to_string(),
            description: "Create a managed resource descriptor from a name and hex data payload.".to_string(),
            input_schema: json!({"type":"object","properties":{"name":{"type":"string"},"data_hex":{"type":"string"}},"required":["name"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for DotnetEditManagedResourceNewTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let name = args.get("name").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'name'".into()))?;
        // Absent `data_hex` is a declared default (an empty resource); a
        // PRESENT but malformed one is an error, not an empty resource.
        let data: Vec<u8> = args.get("data_hex").and_then(Value::as_str)
            .map(crate::hex_decode)
            .transpose()?
            .unwrap_or_default();
        let r = rustre_dotnet_edit::ManagedResource::new(name, data);
        Ok(ToolResult::text(json!({"name":r.name,"flags":r.flags,"data_len":r.data.len(),"is_public":r.is_public(),"source":"rustre_dotnet_edit::ManagedResource::new"}).to_string()))
    }
}

pub struct DotnetEditSignatureStripperTool;
impl DotnetEditSignatureStripperTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "dotnet_edit_signature_stripper_strip".to_string(),
            description: "Strip the strong-name signature from a .NET PE image (hex input).".to_string(),
            input_schema: json!({"type":"object","properties":{"image_hex":{"type":"string"}},"required":["image_hex"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for DotnetEditSignatureStripperTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let hex = args.get("image_hex").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'image_hex'".into()))?;
        // An invalid digit used to be dropped, shifting every later byte of the
        // image; `offset` is computed by the caller against the TRUE image, so
        // the patch then landed in the wrong place and the returned assembly was
        // silently corrupt. Refuse instead.
        let mut data: Vec<u8> = crate::hex_decode(hex)?;
        match rustre_dotnet_edit::SignatureStripper::strip(&mut data) {
            Ok(()) => Ok(ToolResult::text(json!({"ok":true,"image_len":data.len(),"image_hex":hex_encode(&data),"source":"rustre_dotnet_edit::SignatureStripper::strip"}).to_string())),
            Err(e) => Ok(ToolResult::text(json!({"ok":false,"error":e.to_string(),"source":"rustre_dotnet_edit::SignatureStripper::strip"}).to_string())),
        }
    }
}

pub struct DotnetEditIlValidatorValidateTool;
impl DotnetEditIlValidatorValidateTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "dotnet_edit_il_validator_validate".to_string(),
            description: "Validate a sequence of CIL opcode mnemonics and report diagnostics.".to_string(),
            input_schema: json!({"type":"object","properties":{"opcodes":{"type":"array","items":{"type":"string"}}},"required":["opcodes"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for DotnetEditIlValidatorValidateTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let arr = args.get("opcodes").and_then(Value::as_array)
            .ok_or_else(|| McpError::InvalidParams("missing 'opcodes'".into()))?;
        let instrs: Vec<rustre_dotnet::CilInstruction> = arr.iter().enumerate()
            .filter_map(|(i, v)| v.as_str().map(|s| rustre_dotnet::CilInstruction::simple(i as u32, s)))
            .collect();
        let diags = rustre_dotnet_edit::IlValidator::validate(&instrs);
        let is_valid = rustre_dotnet_edit::IlValidator::is_valid(&instrs);
        let ds: Vec<Value> = diags.iter().map(|d| json!({"msg": format!("{:?}", d)})).collect();
        Ok(ToolResult::text(json!({"count":ds.len(),"is_valid":is_valid,"diagnostics":ds,"source":"rustre_dotnet_edit::IlValidator::validate"}).to_string()))
    }
}

pub struct DotnetEditIlOptimizerRemoveNopsTool;
impl DotnetEditIlOptimizerRemoveNopsTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "dotnet_edit_il_optimizer_remove_nops".to_string(),
            description: "Remove nop instructions from a CIL opcode sequence.".to_string(),
            input_schema: json!({"type":"object","properties":{"opcodes":{"type":"array","items":{"type":"string"}}},"required":["opcodes"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for DotnetEditIlOptimizerRemoveNopsTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let arr = args.get("opcodes").and_then(Value::as_array)
            .ok_or_else(|| McpError::InvalidParams("missing 'opcodes'".into()))?;
        let instrs: Vec<rustre_dotnet::CilInstruction> = arr.iter().enumerate()
            .filter_map(|(i, v)| v.as_str().map(|s| rustre_dotnet::CilInstruction::simple(i as u32, s)))
            .collect();
        let out = rustre_dotnet_edit::IlOptimizer::remove_nops(&instrs);
        let ops: Vec<String> = out.iter().map(|i| i.opcode.clone()).collect();
        Ok(ToolResult::text(json!({"input_len":instrs.len(),"output_len":ops.len(),"opcodes":ops,"source":"rustre_dotnet_edit::IlOptimizer::remove_nops"}).to_string()))
    }
}

pub struct DotnetEditIlOptimizerEliminateDeadCodeTool;
impl DotnetEditIlOptimizerEliminateDeadCodeTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "dotnet_edit_il_optimizer_eliminate_dead_code".to_string(),
            description: "Eliminate unreachable code after unconditional control-flow terminators.".to_string(),
            input_schema: json!({"type":"object","properties":{"opcodes":{"type":"array","items":{"type":"string"}}},"required":["opcodes"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for DotnetEditIlOptimizerEliminateDeadCodeTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let arr = args.get("opcodes").and_then(Value::as_array)
            .ok_or_else(|| McpError::InvalidParams("missing 'opcodes'".into()))?;
        let instrs: Vec<rustre_dotnet::CilInstruction> = arr.iter().enumerate()
            .filter_map(|(i, v)| v.as_str().map(|s| rustre_dotnet::CilInstruction::simple(i as u32, s)))
            .collect();
        let out = rustre_dotnet_edit::IlOptimizer::eliminate_dead_code(&instrs);
        let ops: Vec<String> = out.iter().map(|i| i.opcode.clone()).collect();
        Ok(ToolResult::text(json!({"input_len":instrs.len(),"output_len":ops.len(),"opcodes":ops,"source":"rustre_dotnet_edit::IlOptimizer::eliminate_dead_code"}).to_string()))
    }
}

pub struct DotnetEditIlOptimizerOptimizeAllTool;
impl DotnetEditIlOptimizerOptimizeAllTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "dotnet_edit_il_optimizer_optimize_all".to_string(),
            description: "Run all CIL optimizer passes (nop removal, dead-code elimination, folding).".to_string(),
            input_schema: json!({"type":"object","properties":{"opcodes":{"type":"array","items":{"type":"string"}}},"required":["opcodes"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for DotnetEditIlOptimizerOptimizeAllTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let arr = args.get("opcodes").and_then(Value::as_array)
            .ok_or_else(|| McpError::InvalidParams("missing 'opcodes'".into()))?;
        let instrs: Vec<rustre_dotnet::CilInstruction> = arr.iter().enumerate()
            .filter_map(|(i, v)| v.as_str().map(|s| rustre_dotnet::CilInstruction::simple(i as u32, s)))
            .collect();
        let out = rustre_dotnet_edit::IlOptimizer::optimize_all(&instrs);
        let ops: Vec<String> = out.iter().map(|i| i.opcode.clone()).collect();
        Ok(ToolResult::text(json!({"input_len":instrs.len(),"output_len":ops.len(),"opcodes":ops,"source":"rustre_dotnet_edit::IlOptimizer::optimize_all"}).to_string()))
    }
}

pub struct DotnetEditIlBuilderRetTool;
impl DotnetEditIlBuilderRetTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "dotnet_edit_il_builder_ret".to_string(),
            description: "Build a minimal method body with a single ret and return encoded bytes.".to_string(),
            input_schema: json!({"type":"object","properties":{}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for DotnetEditIlBuilderRetTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let mut b = rustre_dotnet_edit::IlBuilder::new();
        b.ret();
        let instrs = b.build();
        let bytes = rustre_dotnet_edit::encode_instructions(&instrs);
        Ok(ToolResult::text(json!({"len":instrs.len(),"bytes_hex":hex_encode(&bytes),"source":"rustre_dotnet_edit::IlBuilder"}).to_string()))
    }
}

pub struct DotnetEditAssemblyPatcherPatchU32Tool;
impl DotnetEditAssemblyPatcherPatchU32Tool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "dotnet_edit_assembly_patcher_patch_u32".to_string(),
            description: "Patch a little-endian u32 at a file offset in a PE image (hex input).".to_string(),
            input_schema: json!({"type":"object","properties":{"image_hex":{"type":"string"},"offset":{"type":"integer"},"value":{"type":"integer"}},"required":["image_hex","offset","value"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for DotnetEditAssemblyPatcherPatchU32Tool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let hex = args.get("image_hex").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'image_hex'".into()))?;
        // See above: a dropped byte misaligns `offset` and corrupts the image.
        let img: Vec<u8> = crate::hex_decode(hex)?;
        let off = args.get("offset").and_then(Value::as_u64)
            .ok_or_else(|| McpError::InvalidParams("missing 'offset'".into()))? as usize;
        let val = args.get("value").and_then(Value::as_u64)
            .ok_or_else(|| McpError::InvalidParams("missing 'value'".into()))? as u32;
        let mut p = rustre_dotnet_edit::AssemblyPatcher::new(img);
        match p.patch_u32(off, val) {
            Ok(()) => {
                let out = p.into_bytes();
                Ok(ToolResult::text(json!({"ok":true,"image_len":out.len(),"image_hex":hex_encode(&out),"source":"rustre_dotnet_edit::AssemblyPatcher::patch_u32"}).to_string()))
            }
            Err(e) => Ok(ToolResult::text(json!({"ok":false,"error":e.to_string()}).to_string())),
        }
    }
}

pub struct DotnetEditIlPatchRemoveTool;
impl DotnetEditIlPatchRemoveTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "dotnet_edit_il_patch_remove".to_string(),
            description: "Apply an IlPatch::Remove at the given offset over a CIL opcode sequence.".to_string(),
            input_schema: json!({"type":"object","properties":{"opcodes":{"type":"array","items":{"type":"string"}},"offset":{"type":"integer"}},"required":["opcodes","offset"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for DotnetEditIlPatchRemoveTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let arr = args.get("opcodes").and_then(Value::as_array)
            .ok_or_else(|| McpError::InvalidParams("missing 'opcodes'".into()))?;
        let off = args.get("offset").and_then(Value::as_u64)
            .ok_or_else(|| McpError::InvalidParams("missing 'offset'".into()))? as u32;
        let mut instrs: Vec<rustre_dotnet::CilInstruction> = arr.iter().enumerate()
            .filter_map(|(i, v)| v.as_str().map(|s| rustre_dotnet::CilInstruction::simple(i as u32, s)))
            .collect();
        let patch = rustre_dotnet_edit::IlPatch::Remove { offset: off };
        match patch.apply(&mut instrs) {
            Ok(()) => {
                let ops: Vec<String> = instrs.iter().map(|i| i.opcode.clone()).collect();
                Ok(ToolResult::text(json!({"ok":true,"opcodes":ops,"len":ops.len(),"source":"rustre_dotnet_edit::IlPatch::Remove"}).to_string()))
            }
            Err(e) => Ok(ToolResult::text(json!({"ok":false,"error":e.to_string()}).to_string())),
        }
    }
}

pub struct DotnetEditIlOptimizerFoldConstStoresV2Tool;
impl DotnetEditIlOptimizerFoldConstStoresV2Tool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "dotnet_edit_il_optimizer_fold_const_stores_v2".to_string(),
            description: "Run IlOptimizer::fold_const_stores over a CIL opcode sequence.".to_string(),
            input_schema: json!({"type":"object","properties":{"opcodes":{"type":"array","items":{"type":"string"}}},"required":["opcodes"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for DotnetEditIlOptimizerFoldConstStoresV2Tool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let arr = args.get("opcodes").and_then(Value::as_array)
            .ok_or_else(|| McpError::InvalidParams("missing 'opcodes'".into()))?;
        let instrs: Vec<rustre_dotnet::CilInstruction> = arr.iter().enumerate()
            .filter_map(|(i, v)| v.as_str().map(|s| rustre_dotnet::CilInstruction::simple(i as u32, s)))
            .collect();
        let out = rustre_dotnet_edit::IlOptimizer::fold_const_stores(&instrs);
        let ops: Vec<String> = out.iter().map(|i| i.opcode.clone()).collect();
        Ok(ToolResult::text(json!({"input_len":instrs.len(),"output_len":ops.len(),"opcodes":ops,"source":"rustre_dotnet_edit::IlOptimizer::fold_const_stores"}).to_string()))
    }
}

pub struct DotnetEditIlOptimizerFoldConvI8V2Tool;
impl DotnetEditIlOptimizerFoldConvI8V2Tool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "dotnet_edit_il_optimizer_fold_conv_i8_v2".to_string(),
            description: "Run IlOptimizer::fold_conv_i8 over a CIL opcode sequence.".to_string(),
            input_schema: json!({"type":"object","properties":{"opcodes":{"type":"array","items":{"type":"string"}}},"required":["opcodes"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for DotnetEditIlOptimizerFoldConvI8V2Tool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let arr = args.get("opcodes").and_then(Value::as_array)
            .ok_or_else(|| McpError::InvalidParams("missing 'opcodes'".into()))?;
        let instrs: Vec<rustre_dotnet::CilInstruction> = arr.iter().enumerate()
            .filter_map(|(i, v)| v.as_str().map(|s| rustre_dotnet::CilInstruction::simple(i as u32, s)))
            .collect();
        let out = rustre_dotnet_edit::IlOptimizer::fold_conv_i8(&instrs);
        let ops: Vec<String> = out.iter().map(|i| i.opcode.clone()).collect();
        Ok(ToolResult::text(json!({"input_len":instrs.len(),"output_len":ops.len(),"opcodes":ops,"source":"rustre_dotnet_edit::IlOptimizer::fold_conv_i8"}).to_string()))
    }
}

pub struct DotnetEditIlBuilderLdcI4V2Tool;
impl DotnetEditIlBuilderLdcI4V2Tool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "dotnet_edit_il_builder_ldc_i4_v2".to_string(),
            description: "Emit ldc.i4 via IlBuilder with automatic opcode selection based on constant value.".to_string(),
            input_schema: json!({"type":"object","properties":{"value":{"type":"integer"}},"required":["value"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for DotnetEditIlBuilderLdcI4V2Tool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let v = args.get("value").and_then(Value::as_i64)
            .ok_or_else(|| McpError::InvalidParams("missing 'value'".into()))? as i32;
        let mut b = rustre_dotnet_edit::IlBuilder::new();
        b.ldc_i4(v);
        let cur = b.current_offset();
        let instrs = b.build();
        let ops: Vec<String> = instrs.iter().map(|i| i.opcode.clone()).collect();
        Ok(ToolResult::text(json!({"value":v,"opcodes":ops,"current_offset":cur,"source":"rustre_dotnet_edit::IlBuilder::ldc_i4"}).to_string()))
    }
}

pub struct DotnetEditIlBuilderLdargV2Tool;
impl DotnetEditIlBuilderLdargV2Tool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "dotnet_edit_il_builder_ldarg_v2".to_string(),
            description: "Emit ldarg via IlBuilder with automatic short-form selection.".to_string(),
            input_schema: json!({"type":"object","properties":{"index":{"type":"integer"}},"required":["index"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for DotnetEditIlBuilderLdargV2Tool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let idx = args.get("index").and_then(Value::as_u64)
            .ok_or_else(|| McpError::InvalidParams("missing 'index'".into()))? as u8;
        let mut b = rustre_dotnet_edit::IlBuilder::new();
        b.ldarg(idx);
        let cur = b.current_offset();
        let instrs = b.build();
        let ops: Vec<String> = instrs.iter().map(|i| i.opcode.clone()).collect();
        Ok(ToolResult::text(json!({"index":idx,"opcodes":ops,"current_offset":cur,"source":"rustre_dotnet_edit::IlBuilder::ldarg"}).to_string()))
    }
}

pub struct DotnetEditIlValidatorIsValidV2Tool;
impl DotnetEditIlValidatorIsValidV2Tool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "dotnet_edit_il_validator_is_valid_v2".to_string(),
            description: "Return whether the given CIL opcode sequence passes IlValidator::is_valid.".to_string(),
            input_schema: json!({"type":"object","properties":{"opcodes":{"type":"array","items":{"type":"string"}}},"required":["opcodes"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for DotnetEditIlValidatorIsValidV2Tool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let arr = args.get("opcodes").and_then(Value::as_array)
            .ok_or_else(|| McpError::InvalidParams("missing 'opcodes'".into()))?;
        let instrs: Vec<rustre_dotnet::CilInstruction> = arr.iter().enumerate()
            .filter_map(|(i, v)| v.as_str().map(|s| rustre_dotnet::CilInstruction::simple(i as u32, s)))
            .collect();
        let ok = rustre_dotnet_edit::IlValidator::is_valid(&instrs);
        Ok(ToolResult::text(json!({"is_valid":ok,"input_len":instrs.len(),"source":"rustre_dotnet_edit::IlValidator::is_valid"}).to_string()))
    }
}

pub struct DotnetEditManagedResourceNewFlagsV2Tool;
impl DotnetEditManagedResourceNewFlagsV2Tool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "dotnet_edit_managed_resource_new_flags_v2".to_string(),
            description: "Construct a ManagedResource and expose its default flags plus is_public.".to_string(),
            input_schema: json!({"type":"object","properties":{"name":{"type":"string"},"data_len":{"type":"integer"}},"required":["name"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for DotnetEditManagedResourceNewFlagsV2Tool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let name = args.get("name").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'name'".into()))?;
        let n = args.get("data_len").and_then(Value::as_u64).unwrap_or(0) as usize;
        let r = rustre_dotnet_edit::ManagedResource::new(name, vec![0u8; n]);
        Ok(ToolResult::text(json!({"name":r.name,"flags":r.flags,"is_public":r.is_public(),"data_len":r.data.len(),"source":"rustre_dotnet_edit::ManagedResource::new"}).to_string()))
    }
}

pub struct DotnetEditNewMethodStaticVoidFlagsV2Tool;
impl DotnetEditNewMethodStaticVoidFlagsV2Tool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "dotnet_edit_new_method_static_void_flags_v2".to_string(),
            description: "Return flags/impl_flags/body length of NewMethodDescriptor::static_void.".to_string(),
            input_schema: json!({"type":"object","properties":{"name":{"type":"string"}},"required":["name"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for DotnetEditNewMethodStaticVoidFlagsV2Tool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let name = args.get("name").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'name'".into()))?;
        let d = rustre_dotnet_edit::NewMethodDescriptor::static_void(name);
        let body_len = d.body.as_ref().map(std::vec::Vec::len).unwrap_or(0);
        Ok(ToolResult::text(json!({"name":d.name,"flags":d.flags,"impl_flags":d.impl_flags,"body_len":body_len,"source":"rustre_dotnet_edit::NewMethodDescriptor::static_void"}).to_string()))
    }
}

pub struct DotnetEditIlPatchReplaceV2Tool;
impl DotnetEditIlPatchReplaceV2Tool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "dotnet_edit_il_patch_replace_v2".to_string(),
            description: "Apply an IlPatch::Replace at the given offset over a CIL opcode sequence.".to_string(),
            input_schema: json!({"type":"object","properties":{"opcodes":{"type":"array","items":{"type":"string"}},"offset":{"type":"integer"},"new_opcode":{"type":"string"}},"required":["opcodes","offset","new_opcode"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for DotnetEditIlPatchReplaceV2Tool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let arr = args.get("opcodes").and_then(Value::as_array)
            .ok_or_else(|| McpError::InvalidParams("missing 'opcodes'".into()))?;
        let off = args.get("offset").and_then(Value::as_u64)
            .ok_or_else(|| McpError::InvalidParams("missing 'offset'".into()))? as u32;
        let new_op = args.get("new_opcode").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'new_opcode'".into()))?;
        let mut instrs: Vec<rustre_dotnet::CilInstruction> = arr.iter().enumerate()
            .filter_map(|(i, v)| v.as_str().map(|s| rustre_dotnet::CilInstruction::simple(i as u32, s)))
            .collect();
        let patch = rustre_dotnet_edit::IlPatch::Replace {
            offset: off,
            instruction: rustre_dotnet::CilInstruction::simple(off, new_op),
        };
        match patch.apply(&mut instrs) {
            Ok(()) => {
                let ops: Vec<String> = instrs.iter().map(|i| i.opcode.clone()).collect();
                Ok(ToolResult::text(json!({"ok":true,"opcodes":ops,"len":ops.len(),"source":"rustre_dotnet_edit::IlPatch::Replace"}).to_string()))
            }
            Err(e) => Ok(ToolResult::text(json!({"ok":false,"error":e.to_string()}).to_string())),
        }
    }
}

pub struct DotnetEditIlPatchPrependV2Tool;
impl DotnetEditIlPatchPrependV2Tool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "dotnet_edit_il_patch_prepend_v2".to_string(),
            description: "Apply an IlPatch::Prepend of the given opcodes over a CIL sequence.".to_string(),
            input_schema: json!({"type":"object","properties":{"opcodes":{"type":"array","items":{"type":"string"}},"new_opcodes":{"type":"array","items":{"type":"string"}}},"required":["opcodes","new_opcodes"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for DotnetEditIlPatchPrependV2Tool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let arr = args.get("opcodes").and_then(Value::as_array)
            .ok_or_else(|| McpError::InvalidParams("missing 'opcodes'".into()))?;
        let new_arr = args.get("new_opcodes").and_then(Value::as_array)
            .ok_or_else(|| McpError::InvalidParams("missing 'new_opcodes'".into()))?;
        let mut instrs: Vec<rustre_dotnet::CilInstruction> = arr.iter().enumerate()
            .filter_map(|(i, v)| v.as_str().map(|s| rustre_dotnet::CilInstruction::simple(i as u32, s)))
            .collect();
        let new_instrs: Vec<rustre_dotnet::CilInstruction> = new_arr.iter().enumerate()
            .filter_map(|(i, v)| v.as_str().map(|s| rustre_dotnet::CilInstruction::simple(i as u32, s)))
            .collect();
        let patch = rustre_dotnet_edit::IlPatch::Prepend { instructions: new_instrs };
        match patch.apply(&mut instrs) {
            Ok(()) => {
                let ops: Vec<String> = instrs.iter().map(|i| i.opcode.clone()).collect();
                Ok(ToolResult::text(json!({"ok":true,"opcodes":ops,"len":ops.len(),"source":"rustre_dotnet_edit::IlPatch::Prepend"}).to_string()))
            }
            Err(e) => Ok(ToolResult::text(json!({"ok":false,"error":e.to_string()}).to_string())),
        }
    }
}

pub struct DotnetEditIlPatchAppendV2Tool;
impl DotnetEditIlPatchAppendV2Tool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "dotnet_edit_il_patch_append_v2".to_string(),
            description: "Apply an IlPatch::Append of the given opcodes over a CIL sequence (before final ret).".to_string(),
            input_schema: json!({"type":"object","properties":{"opcodes":{"type":"array","items":{"type":"string"}},"new_opcodes":{"type":"array","items":{"type":"string"}}},"required":["opcodes","new_opcodes"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for DotnetEditIlPatchAppendV2Tool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let arr = args.get("opcodes").and_then(Value::as_array)
            .ok_or_else(|| McpError::InvalidParams("missing 'opcodes'".into()))?;
        let new_arr = args.get("new_opcodes").and_then(Value::as_array)
            .ok_or_else(|| McpError::InvalidParams("missing 'new_opcodes'".into()))?;
        let mut instrs: Vec<rustre_dotnet::CilInstruction> = arr.iter().enumerate()
            .filter_map(|(i, v)| v.as_str().map(|s| rustre_dotnet::CilInstruction::simple(i as u32, s)))
            .collect();
        let new_instrs: Vec<rustre_dotnet::CilInstruction> = new_arr.iter().enumerate()
            .filter_map(|(i, v)| v.as_str().map(|s| rustre_dotnet::CilInstruction::simple(i as u32, s)))
            .collect();
        let patch = rustre_dotnet_edit::IlPatch::Append { instructions: new_instrs };
        match patch.apply(&mut instrs) {
            Ok(()) => {
                let ops: Vec<String> = instrs.iter().map(|i| i.opcode.clone()).collect();
                Ok(ToolResult::text(json!({"ok":true,"opcodes":ops,"len":ops.len(),"source":"rustre_dotnet_edit::IlPatch::Append"}).to_string()))
            }
            Err(e) => Ok(ToolResult::text(json!({"ok":false,"error":e.to_string()}).to_string())),
        }
    }
}

pub struct DotnetEditIlPatchInsertBeforeTool;
impl DotnetEditIlPatchInsertBeforeTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "dotnet_edit_il_patch_insert_before".to_string(), description: "Apply IlPatch::InsertBefore at offset over a CIL opcode sequence.".to_string(), input_schema: json!({"type":"object","properties":{"opcodes":{"type":"array","items":{"type":"string"}},"new_opcodes":{"type":"array","items":{"type":"string"}},"offset":{"type":"integer"}},"required":["opcodes","new_opcodes","offset"]}), parameters: Value::Null } } }
#[async_trait::async_trait]
impl ToolHandler for DotnetEditIlPatchInsertBeforeTool {
    async fn call(&self, args: Value) -> Result<ToolResult, rustre_mcp_server::McpError> {
        let arr = args.get("opcodes").and_then(Value::as_array).ok_or_else(|| rustre_mcp_server::McpError::InvalidParams("missing 'opcodes'".into()))?;
        let new_arr = args.get("new_opcodes").and_then(Value::as_array).ok_or_else(|| rustre_mcp_server::McpError::InvalidParams("missing 'new_opcodes'".into()))?;
        let offset = u32::try_from(args.get("offset").and_then(Value::as_u64).unwrap_or(0)).unwrap_or(0);
        let mut instrs: Vec<rustre_dotnet::CilInstruction> = arr.iter().enumerate().filter_map(|(i,v)| v.as_str().map(|s| rustre_dotnet::CilInstruction::simple(i as u32, s))).collect();
        let new_instrs: Vec<rustre_dotnet::CilInstruction> = new_arr.iter().enumerate().filter_map(|(i,v)| v.as_str().map(|s| rustre_dotnet::CilInstruction::simple(i as u32, s))).collect();
        let patch = rustre_dotnet_edit::IlPatch::InsertBefore { offset, instructions: new_instrs };
        match patch.apply(&mut instrs) {
            Ok(()) => { let ops: Vec<String> = instrs.iter().map(|i| i.opcode.clone()).collect(); Ok(ToolResult::text(json!({"ok":true,"opcodes":ops,"len":ops.len(),"source":"rustre_dotnet_edit::IlPatch::InsertBefore"}).to_string())) }
            Err(e) => Ok(ToolResult::text(json!({"ok":false,"error":e.to_string()}).to_string())),
        }
    }
}

pub struct DotnetEditIlPatchInsertAfterTool;
impl DotnetEditIlPatchInsertAfterTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "dotnet_edit_il_patch_insert_after".to_string(), description: "Apply IlPatch::InsertAfter at offset.".to_string(), input_schema: json!({"type":"object","properties":{"opcodes":{"type":"array","items":{"type":"string"}},"new_opcodes":{"type":"array","items":{"type":"string"}},"offset":{"type":"integer"}},"required":["opcodes","new_opcodes","offset"]}), parameters: Value::Null } } }
#[async_trait::async_trait]
impl ToolHandler for DotnetEditIlPatchInsertAfterTool {
    async fn call(&self, args: Value) -> Result<ToolResult, rustre_mcp_server::McpError> {
        let arr = args.get("opcodes").and_then(Value::as_array).ok_or_else(|| rustre_mcp_server::McpError::InvalidParams("missing 'opcodes'".into()))?;
        let new_arr = args.get("new_opcodes").and_then(Value::as_array).ok_or_else(|| rustre_mcp_server::McpError::InvalidParams("missing 'new_opcodes'".into()))?;
        let offset = u32::try_from(args.get("offset").and_then(Value::as_u64).unwrap_or(0)).unwrap_or(0);
        let mut instrs: Vec<rustre_dotnet::CilInstruction> = arr.iter().enumerate().filter_map(|(i,v)| v.as_str().map(|s| rustre_dotnet::CilInstruction::simple(i as u32, s))).collect();
        let new_instrs: Vec<rustre_dotnet::CilInstruction> = new_arr.iter().enumerate().filter_map(|(i,v)| v.as_str().map(|s| rustre_dotnet::CilInstruction::simple(i as u32, s))).collect();
        let patch = rustre_dotnet_edit::IlPatch::InsertAfter { offset, instructions: new_instrs };
        match patch.apply(&mut instrs) {
            Ok(()) => { let ops: Vec<String> = instrs.iter().map(|i| i.opcode.clone()).collect(); Ok(ToolResult::text(json!({"ok":true,"opcodes":ops,"len":ops.len(),"source":"rustre_dotnet_edit::IlPatch::InsertAfter"}).to_string())) }
            Err(e) => Ok(ToolResult::text(json!({"ok":false,"error":e.to_string()}).to_string())),
        }
    }
}

pub struct DotnetEditIlPatchReplaceRangeTool;
impl DotnetEditIlPatchReplaceRangeTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "dotnet_edit_il_patch_replace_range".to_string(), description: "Apply IlPatch::ReplaceRange over [start,end).".to_string(), input_schema: json!({"type":"object","properties":{"opcodes":{"type":"array","items":{"type":"string"}},"new_opcodes":{"type":"array","items":{"type":"string"}},"start":{"type":"integer"},"end":{"type":"integer"}},"required":["opcodes","new_opcodes","start","end"]}), parameters: Value::Null } } }
#[async_trait::async_trait]
impl ToolHandler for DotnetEditIlPatchReplaceRangeTool {
    async fn call(&self, args: Value) -> Result<ToolResult, rustre_mcp_server::McpError> {
        let arr = args.get("opcodes").and_then(Value::as_array).ok_or_else(|| rustre_mcp_server::McpError::InvalidParams("missing 'opcodes'".into()))?;
        let new_arr = args.get("new_opcodes").and_then(Value::as_array).ok_or_else(|| rustre_mcp_server::McpError::InvalidParams("missing 'new_opcodes'".into()))?;
        let start = u32::try_from(args.get("start").and_then(Value::as_u64).unwrap_or(0)).unwrap_or(0);
        let end = u32::try_from(args.get("end").and_then(Value::as_u64).unwrap_or(0)).unwrap_or(0);
        let mut instrs: Vec<rustre_dotnet::CilInstruction> = arr.iter().enumerate().filter_map(|(i,v)| v.as_str().map(|s| rustre_dotnet::CilInstruction::simple(i as u32, s))).collect();
        let new_instrs: Vec<rustre_dotnet::CilInstruction> = new_arr.iter().enumerate().filter_map(|(i,v)| v.as_str().map(|s| rustre_dotnet::CilInstruction::simple(i as u32, s))).collect();
        let patch = rustre_dotnet_edit::IlPatch::ReplaceRange { start, end, instructions: new_instrs };
        match patch.apply(&mut instrs) {
            Ok(()) => { let ops: Vec<String> = instrs.iter().map(|i| i.opcode.clone()).collect(); Ok(ToolResult::text(json!({"ok":true,"opcodes":ops,"len":ops.len(),"source":"rustre_dotnet_edit::IlPatch::ReplaceRange"}).to_string())) }
            Err(e) => Ok(ToolResult::text(json!({"ok":false,"error":e.to_string()}).to_string())),
        }
    }
}

pub struct DotnetEditNewTypePublicClassProbeTool;
impl DotnetEditNewTypePublicClassProbeTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "dotnet_edit_new_type_public_class_probe".to_string(), description: "Build NewTypeDescriptor::public_class and probe name/namespace/flags.".to_string(), input_schema: json!({"type":"object","properties":{"name":{"type":"string"},"ns":{"type":"string"}},"required":["name","ns"]}), parameters: Value::Null } } }
#[async_trait::async_trait]
impl ToolHandler for DotnetEditNewTypePublicClassProbeTool {
    async fn call(&self, args: Value) -> Result<ToolResult, rustre_mcp_server::McpError> {
        let name = args.get("name").and_then(Value::as_str).unwrap_or("T");
        let ns = args.get("ns").and_then(Value::as_str).unwrap_or("N");
        let d = rustre_dotnet_edit::NewTypeDescriptor::public_class(name, ns);
        Ok(ToolResult::text(json!({"name":d.name,"namespace":d.namespace,"flags":d.flags,"iface_count":d.interfaces.len(),"has_base":d.base_type_name.is_some(),"source":"rustre_dotnet_edit::NewTypeDescriptor::public_class"}).to_string()))
    }
}

pub struct DotnetEditNewTypePublicInterfaceProbeTool;
impl DotnetEditNewTypePublicInterfaceProbeTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "dotnet_edit_new_type_public_interface_probe".to_string(), description: "Build NewTypeDescriptor::public_interface and probe flags/name.".to_string(), input_schema: json!({"type":"object","properties":{"name":{"type":"string"},"ns":{"type":"string"}},"required":["name","ns"]}), parameters: Value::Null } } }
#[async_trait::async_trait]
impl ToolHandler for DotnetEditNewTypePublicInterfaceProbeTool {
    async fn call(&self, args: Value) -> Result<ToolResult, rustre_mcp_server::McpError> {
        let name = args.get("name").and_then(Value::as_str).unwrap_or("I");
        let ns = args.get("ns").and_then(Value::as_str).unwrap_or("N");
        let d = rustre_dotnet_edit::NewTypeDescriptor::public_interface(name, ns);
        Ok(ToolResult::text(json!({"name":d.name,"namespace":d.namespace,"flags":d.flags,"iface_count":d.interfaces.len(),"source":"rustre_dotnet_edit::NewTypeDescriptor::public_interface"}).to_string()))
    }
}

pub struct DotnetEditNewMethodStaticVoidBodyTool;
impl DotnetEditNewMethodStaticVoidBodyTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "dotnet_edit_new_method_static_void_body".to_string(), description: "Build NewMethodDescriptor::static_void and report body opcodes.".to_string(), input_schema: json!({"type":"object","properties":{"name":{"type":"string"}},"required":["name"]}), parameters: Value::Null } } }
#[async_trait::async_trait]
impl ToolHandler for DotnetEditNewMethodStaticVoidBodyTool {
    async fn call(&self, args: Value) -> Result<ToolResult, rustre_mcp_server::McpError> {
        let name = args.get("name").and_then(Value::as_str).unwrap_or("M");
        let d = rustre_dotnet_edit::NewMethodDescriptor::static_void(name);
        let body_ops: Vec<String> = d.body.as_ref().map(|b| b.iter().map(|i| i.opcode.clone()).collect()).unwrap_or_default();
        Ok(ToolResult::text(json!({"name":d.name,"flags":d.flags,"impl_flags":d.impl_flags,"body":body_ops,"source":"rustre_dotnet_edit::NewMethodDescriptor::static_void"}).to_string()))
    }
}

pub struct DotnetEditNewMethodInstanceVoidBodyTool;
impl DotnetEditNewMethodInstanceVoidBodyTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "dotnet_edit_new_method_instance_void_body".to_string(), description: "Build NewMethodDescriptor::instance_void and report body/flags.".to_string(), input_schema: json!({"type":"object","properties":{"name":{"type":"string"}},"required":["name"]}), parameters: Value::Null } } }
#[async_trait::async_trait]
impl ToolHandler for DotnetEditNewMethodInstanceVoidBodyTool {
    async fn call(&self, args: Value) -> Result<ToolResult, rustre_mcp_server::McpError> {
        let name = args.get("name").and_then(Value::as_str).unwrap_or("M");
        let d = rustre_dotnet_edit::NewMethodDescriptor::instance_void(name);
        let body_ops: Vec<String> = d.body.as_ref().map(|b| b.iter().map(|i| i.opcode.clone()).collect()).unwrap_or_default();
        Ok(ToolResult::text(json!({"name":d.name,"flags":d.flags,"impl_flags":d.impl_flags,"body":body_ops,"source":"rustre_dotnet_edit::NewMethodDescriptor::instance_void"}).to_string()))
    }
}

pub struct DotnetEditNewFieldPublicStaticProbeTool;
impl DotnetEditNewFieldPublicStaticProbeTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "dotnet_edit_new_field_public_static_probe".to_string(), description: "Build NewFieldDescriptor::public_static and probe flags/type_sig.".to_string(), input_schema: json!({"type":"object","properties":{"name":{"type":"string"},"element_type":{"type":"integer"}},"required":["name","element_type"]}), parameters: Value::Null } } }
#[async_trait::async_trait]
impl ToolHandler for DotnetEditNewFieldPublicStaticProbeTool {
    async fn call(&self, args: Value) -> Result<ToolResult, rustre_mcp_server::McpError> {
        let name = args.get("name").and_then(Value::as_str).unwrap_or("F");
        let et = u8::try_from(args.get("element_type").and_then(Value::as_u64).unwrap_or(8)).unwrap_or(8);
        let d = rustre_dotnet_edit::NewFieldDescriptor::public_static(name, et);
        Ok(ToolResult::text(json!({"name":d.name,"flags":d.flags,"type_sig_len":d.type_sig.len(),"source":"rustre_dotnet_edit::NewFieldDescriptor::public_static"}).to_string()))
    }
}

pub struct DotnetEditEditTransactionLenTool;
impl DotnetEditEditTransactionLenTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "dotnet_edit_edit_transaction_len".to_string(), description: "Build EditTransaction, push N modifications, report len/is_empty.".to_string(), input_schema: json!({"type":"object","properties":{"count":{"type":"integer"}},"required":["count"]}), parameters: Value::Null } } }
#[async_trait::async_trait]
impl ToolHandler for DotnetEditEditTransactionLenTool {
    async fn call(&self, args: Value) -> Result<ToolResult, rustre_mcp_server::McpError> {
        let count = usize::try_from(args.get("count").and_then(Value::as_u64).unwrap_or(0)).unwrap_or(0);
        let mut t = rustre_dotnet_edit::EditTransaction::new();
        let empty_before = t.is_empty();
        for i in 0..count {
            t.add(rustre_dotnet_edit::Modification::RenameType { old: format!("T{i}"), new: format!("U{i}") });
        }
        Ok(ToolResult::text(json!({"empty_before":empty_before,"len":t.len(),"is_empty":t.is_empty(),"source":"rustre_dotnet_edit::EditTransaction::len"}).to_string()))
    }
}

pub struct DotnetEditManagedResourceDataLenTool;
impl DotnetEditManagedResourceDataLenTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "dotnet_edit_managed_resource_data_len".to_string(), description: "Build ManagedResource::new(name,data_hex) and report data len/is_public.".to_string(), input_schema: json!({"type":"object","properties":{"name":{"type":"string"},"data_hex":{"type":"string"}},"required":["name","data_hex"]}), parameters: Value::Null } } }
#[async_trait::async_trait]
impl ToolHandler for DotnetEditManagedResourceDataLenTool {
    async fn call(&self, args: Value) -> Result<ToolResult, rustre_mcp_server::McpError> {
        let name = args.get("name").and_then(Value::as_str).unwrap_or("r").to_string();
        // Absent `data_hex` stays an empty resource (declared default); a
        // present-but-malformed one is an error, not a shorter resource.
        let s = args.get("data_hex").and_then(Value::as_str).unwrap_or("");
        let data: Vec<u8> = crate::hex_decode(s)?;
        let r = rustre_dotnet_edit::ManagedResource::new(name, data);
        Ok(ToolResult::text(json!({"name":r.name,"flags":r.flags,"data_len":r.data.len(),"is_public":r.is_public(),"source":"rustre_dotnet_edit::ManagedResource::new"}).to_string()))
    }
}

pub struct DotnetEditNewMethodEncodeSigStaticTool;
impl DotnetEditNewMethodEncodeSigStaticTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "dotnet_edit_new_method_encode_sig_static".to_string(), description: "Encode signature for NewMethodDescriptor::static_void (calling-conv byte 0x00).".to_string(), input_schema: json!({"type":"object","properties":{"name":{"type":"string"}},"required":["name"]}), parameters: Value::Null } } }
#[async_trait::async_trait]
impl ToolHandler for DotnetEditNewMethodEncodeSigStaticTool {
    async fn call(&self, args: Value) -> Result<ToolResult, rustre_mcp_server::McpError> {
        let name = args.get("name").and_then(Value::as_str).unwrap_or("M");
        let d = rustre_dotnet_edit::NewMethodDescriptor::static_void(name);
        let sig = d.encode_sig();
        Ok(ToolResult::text(json!({"name":d.name,"sig_len":sig.len(),"first_byte":sig.first().copied().unwrap_or(0),"calling_conv_is_default":sig.first().copied()==Some(0x00),"source":"rustre_dotnet_edit::NewMethodDescriptor::encode_sig"}).to_string()))
    }
}

pub fn handlers() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    vec![
        (DotnetEditOpcodeByteSizeTool::definition(), Box::new(DotnetEditOpcodeByteSizeTool)),
        (DotnetEditRecomputeOffsetsTool::definition(), Box::new(DotnetEditRecomputeOffsetsTool)),
        (DotnetEditRenumberOffsetsTool::definition(), Box::new(DotnetEditRenumberOffsetsTool)),
        (DotnetEditEncodeInstructionsTool::definition(), Box::new(DotnetEditEncodeInstructionsTool)),
        (DotnetEditNopFillRangeTool::definition(), Box::new(DotnetEditNopFillRangeTool)),
        (DotnetEditIlBuilderNopTool::definition(), Box::new(DotnetEditIlBuilderNopTool)),
        (DotnetEditIlBuilderRetOpTool::definition(), Box::new(DotnetEditIlBuilderRetOpTool)),
        (DotnetEditIlBuilderCallTool::definition(), Box::new(DotnetEditIlBuilderCallTool)),
        (DotnetEditIlBuilderCallvirtTool::definition(), Box::new(DotnetEditIlBuilderCallvirtTool)),
        (DotnetEditIlBuilderNewobjTool::definition(), Box::new(DotnetEditIlBuilderNewobjTool)),
        (DotnetEditIlBuilderLdstrTool::definition(), Box::new(DotnetEditIlBuilderLdstrTool)),
        (DotnetEditIlBuilderBrfalseSTool::definition(), Box::new(DotnetEditIlBuilderBrfalseSTool)),
        (DotnetEditIlBuilderBrtrueSTool::definition(), Box::new(DotnetEditIlBuilderBrtrueSTool)),
        (DotnetEditTokenRemapperRemapTool::definition(), Box::new(DotnetEditTokenRemapperRemapTool)),
        (DotnetEditCloneMethodBodyTool::definition(), Box::new(DotnetEditCloneMethodBodyTool)),
        (DotnetEditNewMethodEncodeSigTool::definition(), Box::new(DotnetEditNewMethodEncodeSigTool)),
        (DotnetEditManagedResourceIsPublicTool::definition(), Box::new(DotnetEditManagedResourceIsPublicTool)),
        (DotnetEditManagedResourceIsPublicWireTool::definition(), Box::new(DotnetEditManagedResourceIsPublicWireTool)),
        (DotnetEditNewMethodEncodeSigWireTool::definition(), Box::new(DotnetEditNewMethodEncodeSigWireTool)),
        (DotnetEditNewFieldPublicFieldWireTool::definition(), Box::new(DotnetEditNewFieldPublicFieldWireTool)),
        (DotnetEditNewFieldPublicStaticWireTool::definition(), Box::new(DotnetEditNewFieldPublicStaticWireTool)),
        (DotnetEditNewMethodInstanceVoidSigTool::definition(), Box::new(DotnetEditNewMethodInstanceVoidSigTool)),
        (DotnetEditNewFieldPublicSigTool::definition(), Box::new(DotnetEditNewFieldPublicSigTool)),
        (DotnetEditNewFieldStaticSigTool::definition(), Box::new(DotnetEditNewFieldStaticSigTool)),
        (DotnetEditNewTypePublicClassTool::definition(), Box::new(DotnetEditNewTypePublicClassTool)),
        (DotnetEditNewTypePublicInterfaceTool::definition(), Box::new(DotnetEditNewTypePublicInterfaceTool)),
        (DotnetEditManagedResourceNewTool::definition(), Box::new(DotnetEditManagedResourceNewTool)),
        (DotnetEditSignatureStripperTool::definition(), Box::new(DotnetEditSignatureStripperTool)),
        (DotnetEditIlValidatorValidateTool::definition(), Box::new(DotnetEditIlValidatorValidateTool)),
        (DotnetEditIlOptimizerRemoveNopsTool::definition(), Box::new(DotnetEditIlOptimizerRemoveNopsTool)),
        (DotnetEditIlOptimizerEliminateDeadCodeTool::definition(), Box::new(DotnetEditIlOptimizerEliminateDeadCodeTool)),
        (DotnetEditIlOptimizerOptimizeAllTool::definition(), Box::new(DotnetEditIlOptimizerOptimizeAllTool)),
        (DotnetEditIlBuilderRetTool::definition(), Box::new(DotnetEditIlBuilderRetTool)),
        (DotnetEditAssemblyPatcherPatchU32Tool::definition(), Box::new(DotnetEditAssemblyPatcherPatchU32Tool)),
        (DotnetEditIlPatchRemoveTool::definition(), Box::new(DotnetEditIlPatchRemoveTool)),
        (DotnetEditIlOptimizerFoldConstStoresV2Tool::definition(), Box::new(DotnetEditIlOptimizerFoldConstStoresV2Tool)),
        (DotnetEditIlOptimizerFoldConvI8V2Tool::definition(), Box::new(DotnetEditIlOptimizerFoldConvI8V2Tool)),
        (DotnetEditIlBuilderLdcI4V2Tool::definition(), Box::new(DotnetEditIlBuilderLdcI4V2Tool)),
        (DotnetEditIlBuilderLdargV2Tool::definition(), Box::new(DotnetEditIlBuilderLdargV2Tool)),
        (DotnetEditIlValidatorIsValidV2Tool::definition(), Box::new(DotnetEditIlValidatorIsValidV2Tool)),
        (DotnetEditManagedResourceNewFlagsV2Tool::definition(), Box::new(DotnetEditManagedResourceNewFlagsV2Tool)),
        (DotnetEditNewMethodStaticVoidFlagsV2Tool::definition(), Box::new(DotnetEditNewMethodStaticVoidFlagsV2Tool)),
        (DotnetEditIlPatchReplaceV2Tool::definition(), Box::new(DotnetEditIlPatchReplaceV2Tool)),
        (DotnetEditIlPatchPrependV2Tool::definition(), Box::new(DotnetEditIlPatchPrependV2Tool)),
        (DotnetEditIlPatchAppendV2Tool::definition(), Box::new(DotnetEditIlPatchAppendV2Tool)),
        (DotnetEditIlPatchInsertBeforeTool::definition(), Box::new(DotnetEditIlPatchInsertBeforeTool)),
        (DotnetEditIlPatchInsertAfterTool::definition(), Box::new(DotnetEditIlPatchInsertAfterTool)),
        (DotnetEditIlPatchReplaceRangeTool::definition(), Box::new(DotnetEditIlPatchReplaceRangeTool)),
        (DotnetEditNewTypePublicClassProbeTool::definition(), Box::new(DotnetEditNewTypePublicClassProbeTool)),
        (DotnetEditNewTypePublicInterfaceProbeTool::definition(), Box::new(DotnetEditNewTypePublicInterfaceProbeTool)),
        (DotnetEditNewMethodStaticVoidBodyTool::definition(), Box::new(DotnetEditNewMethodStaticVoidBodyTool)),
        (DotnetEditNewMethodInstanceVoidBodyTool::definition(), Box::new(DotnetEditNewMethodInstanceVoidBodyTool)),
        (DotnetEditNewFieldPublicStaticProbeTool::definition(), Box::new(DotnetEditNewFieldPublicStaticProbeTool)),
        (DotnetEditEditTransactionLenTool::definition(), Box::new(DotnetEditEditTransactionLenTool)),
        (DotnetEditManagedResourceDataLenTool::definition(), Box::new(DotnetEditManagedResourceDataLenTool)),
        (DotnetEditNewMethodEncodeSigStaticTool::definition(), Box::new(DotnetEditNewMethodEncodeSigStaticTool)),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A malformed image must be REFUSED, never silently shortened.
    ///
    /// `offset` is computed by the caller against the true image. When a bad
    /// digit was dropped, every later byte shifted by one, so the patch landed
    /// at the wrong place and the tool returned a corrupt assembly with no
    /// indication anything had gone wrong — the worst outcome in this family,
    /// because the output is meant to be written back to disk.
    #[tokio::test]
    async fn a_malformed_image_is_refused_not_silently_shortened() {
        let tool = DotnetEditAssemblyPatcherPatchU32Tool;

        // Positive control: a well-formed image is still accepted.
        let ok = tool
            .call(json!({ "image_hex": "00112233445566778899aabb", "offset": 0, "value": 1 }))
            .await;
        assert!(ok.is_ok(), "a valid image must still be patched: {ok:?}");

        for bad in [
            "00112233zz5566778899aabb", // invalid digit in the middle
            "00112233445566778899aab",  // odd length
        ] {
            let err = tool
                .call(json!({ "image_hex": bad, "offset": 0, "value": 1 }))
                .await;
            assert!(
                err.is_err(),
                "malformed image '{bad}' was accepted instead of refused"
            );
        }
    }
}
