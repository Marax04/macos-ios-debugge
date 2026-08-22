//! MCP wrappers for the rustre-analysis-typerecov crate.
//! Manually authored 2026-07-12 to close the decompiler pipeline gap.

use rustre_mcp_server::{ToolDefinition, ToolHandler, ToolResult, McpError};
use serde_json::{json, Value};
use async_trait::async_trait;

// ── schema helpers ────────────────────────────────────────────────────────────

fn schema_addr() -> Value {
    json!({"type":"object","properties":{"addr":{"type":"integer","description":"Virtual address of the function"}},"required":["addr"]})
}
fn schema_recovered_type() -> Value {
    json!({"type":"object","properties":{"ty":{"type":"object","description":"Serialised RecoveredType"}},"required":["ty"]})
}
fn schema_typevar() -> Value {
    json!({"type":"object","properties":{"v":{"type":"integer","description":"Type variable id"}},"required":["v"]})
}

// ── wrappers ──────────────────────────────────────────────────────────────────

pub struct AnalysisTyperecovInferSigTool;
impl AnalysisTyperecovInferSigTool {
    #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "analysis_typerecov_infer_sig".to_string(), description: "Infer the function signature for the given virtual address.".to_string(), input_schema: schema_addr(), parameters: Value::Null } }
}
#[async_trait]
impl ToolHandler for AnalysisTyperecovInferSigTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let addr = args.get("addr").and_then(Value::as_u64)
            .ok_or_else(|| McpError::InvalidParams("missing 'addr'".into()))?;
        let sig = rustre_analysis_typerecov::infer_function_signature(addr);
        Ok(ToolResult::text(json!({
            "calling_convention": sig.calling_convention,
            "return_type": sig.return_type,
            "args": sig.args.iter().map(|a| json!({"name": a.name, "ty": a.ty})).collect::<Vec<_>>(),
            "confidence": format!("{:?}", sig.confidence),
            "source": "rustre_analysis_typerecov::infer_function_signature"
        }).to_string()))
    }
}

pub struct AnalysisTyperecovRegisterSigTool;
impl AnalysisTyperecovRegisterSigTool {
    #[must_use] pub fn definition() -> ToolDefinition {
        ToolDefinition { name: "analysis_typerecov_register_sig".to_string(),
            description: "Register a recovered function signature for the given address.".to_string(),
            input_schema: json!({"type":"object","properties":{"addr":{"type":"integer"},"calling_convention":{"type":"string"},"return_type":{"type":"string"},"args":{"type":"array","items":{"type":"object"}}},"required":["addr"]}),
            parameters: Value::Null }
    }
}
#[async_trait]
impl ToolHandler for AnalysisTyperecovRegisterSigTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let addr = args.get("addr").and_then(Value::as_u64)
            .ok_or_else(|| McpError::InvalidParams("missing 'addr'".into()))?;
        let cc = args.get("calling_convention").and_then(Value::as_str).map(str::to_string);
        let ret = args.get("return_type").and_then(Value::as_str)
            .map(|_s| rustre_analysis_typerecov::RecoveredType::Unknown);
        let raw_args: Vec<(String, rustre_analysis_typerecov::RecoveredType)> = args
            .get("args").and_then(Value::as_array).unwrap_or(&vec![])
            .iter()
            .map(|a| {
                let name = a.get("name").and_then(Value::as_str).unwrap_or("").to_string();
                (name, rustre_analysis_typerecov::RecoveredType::Unknown)
            })
            .collect();
        let record = rustre_analysis_typerecov::FunctionSignatureRecord {
            calling_convention: cc,
            return_type: ret,
            args: raw_args,
        };
        rustre_analysis_typerecov::register_function_signature(addr, record);
        Ok(ToolResult::text(json!({"ok":true,"addr":addr,"source":"rustre_analysis_typerecov::register_function_signature"}).to_string()))
    }
}

pub struct AnalysisTyperecovDisplayNameTool;
impl AnalysisTyperecovDisplayNameTool {
    #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "analysis_typerecov_display_name".to_string(), description: "Return the display name string for a serialised RecoveredType.".to_string(), input_schema: schema_recovered_type(), parameters: Value::Null } }
}
#[async_trait]
impl ToolHandler for AnalysisTyperecovDisplayNameTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let ty_val = args.get("ty").ok_or_else(|| McpError::InvalidParams("missing 'ty'".into()))?;
        let ty: rustre_analysis_typerecov::RecoveredType = serde_json::from_value(ty_val.clone())
            .map_err(|e| McpError::InvalidParams(format!("invalid RecoveredType: {e}")))?;
        Ok(ToolResult::text(json!({"display_name": ty.display_name(), "source":"rustre_analysis_typerecov::RecoveredType::display_name"}).to_string()))
    }
}

pub struct AnalysisTyperecovIsPointerTool;
impl AnalysisTyperecovIsPointerTool {
    #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "analysis_typerecov_is_pointer".to_string(), description: "Return whether a RecoveredType is a pointer.".to_string(), input_schema: schema_recovered_type(), parameters: Value::Null } }
}
#[async_trait]
impl ToolHandler for AnalysisTyperecovIsPointerTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let ty_val = args.get("ty").ok_or_else(|| McpError::InvalidParams("missing 'ty'".into()))?;
        let ty: rustre_analysis_typerecov::RecoveredType = serde_json::from_value(ty_val.clone())
            .map_err(|e| McpError::InvalidParams(format!("invalid RecoveredType: {e}")))?;
        Ok(ToolResult::text(json!({"is_pointer": ty.is_pointer(), "source":"rustre_analysis_typerecov::RecoveredType::is_pointer"}).to_string()))
    }
}

pub struct AnalysisTyperecovIsStructTool;
impl AnalysisTyperecovIsStructTool {
    #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "analysis_typerecov_is_struct".to_string(), description: "Return whether a RecoveredType is a struct.".to_string(), input_schema: schema_recovered_type(), parameters: Value::Null } }
}
#[async_trait]
impl ToolHandler for AnalysisTyperecovIsStructTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let ty_val = args.get("ty").ok_or_else(|| McpError::InvalidParams("missing 'ty'".into()))?;
        let ty: rustre_analysis_typerecov::RecoveredType = serde_json::from_value(ty_val.clone())
            .map_err(|e| McpError::InvalidParams(format!("invalid RecoveredType: {e}")))?;
        Ok(ToolResult::text(json!({"is_struct": ty.is_struct(), "source":"rustre_analysis_typerecov::RecoveredType::is_struct"}).to_string()))
    }
}

pub struct AnalysisTyperecovPointeeTool;
impl AnalysisTyperecovPointeeTool {
    #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "analysis_typerecov_pointee".to_string(), description: "Return the pointee type of a RecoveredType::Pointer, or null.".to_string(), input_schema: schema_recovered_type(), parameters: Value::Null } }
}
#[async_trait]
impl ToolHandler for AnalysisTyperecovPointeeTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let ty_val = args.get("ty").ok_or_else(|| McpError::InvalidParams("missing 'ty'".into()))?;
        let ty: rustre_analysis_typerecov::RecoveredType = serde_json::from_value(ty_val.clone())
            .map_err(|e| McpError::InvalidParams(format!("invalid RecoveredType: {e}")))?;
        let pointee = ty.pointee().map(|p| p.display_name());
        Ok(ToolResult::text(json!({"pointee": pointee, "source":"rustre_analysis_typerecov::RecoveredType::pointee"}).to_string()))
    }
}

pub struct AnalysisTyperecovTypeVarNewTool;
impl AnalysisTyperecovTypeVarNewTool {
    #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "analysis_typerecov_typevar_new".to_string(), description: "Construct a TypeVar from an integer id and return its display string.".to_string(), input_schema: schema_typevar(), parameters: Value::Null } }
}
#[async_trait]
impl ToolHandler for AnalysisTyperecovTypeVarNewTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let v = args.get("v").and_then(Value::as_u64)
            .ok_or_else(|| McpError::InvalidParams("missing 'v'".into()))? as u32;
        let tv = rustre_analysis_typerecov::TypeVar::new(v);
        Ok(ToolResult::text(json!({"id": tv.0, "display": tv.to_string(), "source":"rustre_analysis_typerecov::TypeVar::new"}).to_string()))
    }
}

pub struct AnalysisTyperecovConstraintGenTool;
impl AnalysisTyperecovConstraintGenTool {
    #[must_use] pub fn definition() -> ToolDefinition {
        ToolDefinition { name: "analysis_typerecov_constraint_gen_info".to_string(),
            description: "Return metadata about the TypeConstraintGenerator component.".to_string(),
            input_schema: json!({"type":"object","properties":{}}),
            parameters: Value::Null }
    }
}
#[async_trait]
impl ToolHandler for AnalysisTyperecovConstraintGenTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        Ok(ToolResult::text(json!({
            "component": "TypeConstraintGenerator",
            "description": "Walks IL statements and emits type constraints for the unifier.",
            "crate": "rustre_analysis_typerecov",
            "module": "type_constraint_generator",
            "source": "rustre_analysis_typerecov::TypeConstraintGenerator"
        }).to_string()))
    }
}

pub struct AnalysisTyperecovTypeUnifierTool;
impl AnalysisTyperecovTypeUnifierTool {
    #[must_use] pub fn definition() -> ToolDefinition {
        ToolDefinition { name: "analysis_typerecov_type_unifier_info".to_string(),
            description: "Return metadata about the TypeUnifier component.".to_string(),
            input_schema: json!({"type":"object","properties":{}}),
            parameters: Value::Null }
    }
}
#[async_trait]
impl ToolHandler for AnalysisTyperecovTypeUnifierTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        Ok(ToolResult::text(json!({
            "component": "TypeUnifier",
            "description": "Unifies type constraints via union-find to produce concrete RecoveredType assignments.",
            "crate": "rustre_analysis_typerecov",
            "module": "type_unifier",
            "source": "rustre_analysis_typerecov::TypeUnifier"
        }).to_string()))
    }
}

pub struct AnalysisTyperecovStructRecoveryTool;
impl AnalysisTyperecovStructRecoveryTool {
    #[must_use] pub fn definition() -> ToolDefinition {
        ToolDefinition { name: "analysis_typerecov_struct_recovery_info".to_string(),
            description: "Return metadata about the StructRecoveryEngine component.".to_string(),
            input_schema: json!({"type":"object","properties":{}}),
            parameters: Value::Null }
    }
}
#[async_trait]
impl ToolHandler for AnalysisTyperecovStructRecoveryTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        Ok(ToolResult::text(json!({
            "component": "StructRecoveryEngine",
            "description": "Recovers struct shapes from field-access patterns observed in the IL.",
            "crate": "rustre_analysis_typerecov",
            "module": "struct_recovery_engine",
            "source": "rustre_analysis_typerecov::StructRecoveryEngine"
        }).to_string()))
    }
}

pub struct AnalysisTyperecovRecoveredStructTool;
impl AnalysisTyperecovRecoveredStructTool {
    #[must_use] pub fn definition() -> ToolDefinition {
        ToolDefinition { name: "analysis_typerecov_recovered_struct_info".to_string(),
            description: "Return metadata about the RecoveredStruct type.".to_string(),
            input_schema: json!({"type":"object","properties":{}}),
            parameters: Value::Null }
    }
}
#[async_trait]
impl ToolHandler for AnalysisTyperecovRecoveredStructTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        Ok(ToolResult::text(json!({
            "component": "RecoveredStruct",
            "description": "Recovered struct: name + Vec<FieldAccess> (offset, size, access_kind).",
            "crate": "rustre_analysis_typerecov",
            "module": "struct_recovery_engine",
            "source": "rustre_analysis_typerecov::RecoveredStruct"
        }).to_string()))
    }
}

pub struct AnalysisTyperecovInferredSigTool;
impl AnalysisTyperecovInferredSigTool {
    #[must_use] pub fn definition() -> ToolDefinition {
        ToolDefinition { name: "analysis_typerecov_inferred_sig_info".to_string(),
            description: "Return metadata about the InferredSignature struct layout.".to_string(),
            input_schema: json!({"type":"object","properties":{}}),
            parameters: Value::Null }
    }
}
#[async_trait]
impl ToolHandler for AnalysisTyperecovInferredSigTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        Ok(ToolResult::text(json!({
            "component": "InferredSignature",
            "fields": ["calling_convention:String","return_type:String","args:Vec<ArgSpec>","confidence:Confidence"],
            "confidence_variants": ["Low","Medium","High"],
            "crate": "rustre_analysis_typerecov",
            "source": "rustre_analysis_typerecov::InferredSignature"
        }).to_string()))
    }
}

pub struct AnalysisTyperecovArgSpecTool;
impl AnalysisTyperecovArgSpecTool {
    #[must_use] pub fn definition() -> ToolDefinition {
        ToolDefinition { name: "analysis_typerecov_arg_spec_info".to_string(),
            description: "Return metadata about the ArgSpec struct (argument name + type string).".to_string(),
            input_schema: json!({"type":"object","properties":{}}),
            parameters: Value::Null }
    }
}
#[async_trait]
impl ToolHandler for AnalysisTyperecovArgSpecTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        Ok(ToolResult::text(json!({
            "component": "ArgSpec",
            "fields": ["name:String","ty:String"],
            "description": "One argument in an InferredSignature; ty is a human-readable type string.",
            "crate": "rustre_analysis_typerecov",
            "source": "rustre_analysis_typerecov::ArgSpec"
        }).to_string()))
    }
}

pub struct AnalysisTyperecovFieldAccessTool;
impl AnalysisTyperecovFieldAccessTool {
    #[must_use] pub fn definition() -> ToolDefinition {
        ToolDefinition { name: "analysis_typerecov_field_access_info".to_string(),
            description: "Return metadata about the FieldAccess struct (one field-access record from memory scan).".to_string(),
            input_schema: json!({"type":"object","properties":{}}),
            parameters: Value::Null }
    }
}
#[async_trait]
impl ToolHandler for AnalysisTyperecovFieldAccessTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        Ok(ToolResult::text(json!({
            "component": "FieldAccess",
            "fields": ["offset:u32","size:u32","access_kind:String"],
            "description": "Records a single field-access observation: byte offset, access size, and kind (Read/Write/Both).",
            "crate": "rustre_analysis_typerecov",
            "source": "rustre_analysis_typerecov::FieldAccess"
        }).to_string()))
    }
}

pub struct AnalysisTyperecovUnifyResultTool;
impl AnalysisTyperecovUnifyResultTool {
    #[must_use] pub fn definition() -> ToolDefinition {
        ToolDefinition { name: "analysis_typerecov_unify_result_info".to_string(),
            description: "Return metadata about the UnificationResult struct (resolved type assignments from constraint unification).".to_string(),
            input_schema: json!({"type":"object","properties":{}}),
            parameters: Value::Null }
    }
}
#[async_trait]
impl ToolHandler for AnalysisTyperecovUnifyResultTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        Ok(ToolResult::text(json!({
            "component": "UnificationResult",
            "description": "Maps TypeVar ids to their resolved RecoveredType after union-find unification.",
            "crate": "rustre_analysis_typerecov",
            "source": "rustre_analysis_typerecov::UnificationResult"
        }).to_string()))
    }
}

// ── registration ──────────────────────────────────────────────────────────────

#[must_use]
pub fn handlers() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    vec![
        (AnalysisTyperecovInferSigTool::definition(), Box::new(AnalysisTyperecovInferSigTool)),
        (AnalysisTyperecovRegisterSigTool::definition(), Box::new(AnalysisTyperecovRegisterSigTool)),
        (AnalysisTyperecovDisplayNameTool::definition(), Box::new(AnalysisTyperecovDisplayNameTool)),
        (AnalysisTyperecovIsPointerTool::definition(), Box::new(AnalysisTyperecovIsPointerTool)),
        (AnalysisTyperecovIsStructTool::definition(), Box::new(AnalysisTyperecovIsStructTool)),
        (AnalysisTyperecovPointeeTool::definition(), Box::new(AnalysisTyperecovPointeeTool)),
        (AnalysisTyperecovTypeVarNewTool::definition(), Box::new(AnalysisTyperecovTypeVarNewTool)),
        (AnalysisTyperecovConstraintGenTool::definition(), Box::new(AnalysisTyperecovConstraintGenTool)),
        (AnalysisTyperecovTypeUnifierTool::definition(), Box::new(AnalysisTyperecovTypeUnifierTool)),
        (AnalysisTyperecovStructRecoveryTool::definition(), Box::new(AnalysisTyperecovStructRecoveryTool)),
        (AnalysisTyperecovRecoveredStructTool::definition(), Box::new(AnalysisTyperecovRecoveredStructTool)),
        (AnalysisTyperecovInferredSigTool::definition(), Box::new(AnalysisTyperecovInferredSigTool)),
        (AnalysisTyperecovArgSpecTool::definition(), Box::new(AnalysisTyperecovArgSpecTool)),
        (AnalysisTyperecovFieldAccessTool::definition(), Box::new(AnalysisTyperecovFieldAccessTool)),
        (AnalysisTyperecovUnifyResultTool::definition(), Box::new(AnalysisTyperecovUnifyResultTool)),
    ]
}
