// Auto-generated wrappers for rustre-decompiler-type crate.
// Included from wire_tools.rs.

fn dt_parse_int_width(s: &str) -> Option<rustre_decompiler_expr::IntWidth> {
    use rustre_decompiler_expr::IntWidth::*;
    Some(match s {
        "I8" | "i8" => I8, "U8" | "u8" => U8,
        "I16" | "i16" => I16, "U16" | "u16" => U16,
        "I32" | "i32" => I32, "U32" | "u32" => U32,
        "I64" | "i64" => I64, "U64" | "u64" => U64,
        _ => return None,
    })
}

fn dt_parse_type(v: &Value) -> Option<rustre_decompiler_type::DecompType> {
    use rustre_decompiler_type::DecompType as T;
    let kind = v.get("kind").and_then(Value::as_str)?;
    Some(match kind {
        "void" => T::Void,
        "bool" => T::Bool,
        "int" => T::Int(dt_parse_int_width(v.get("width").and_then(Value::as_str)?)?),
        "float32" => T::Float32,
        "float64" => T::Float64,
        "cstr" => T::CStr,
        "unknown" => T::Unknown,
        "ptr" => T::Ptr(Box::new(dt_parse_type(v.get("pointee")?)?)),
        _ => return None,
    })
}

pub struct DecompilerTypeByteSizeTool;
impl DecompilerTypeByteSizeTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "decompiler_type_byte_size".to_string(),
            description: "Compute byte size of a DecompType tree.".to_string(),
            input_schema: json!({"type":"object","properties":{"type":{"type":"object"},"ptr_width":{"type":"integer"}},"required":["type"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for DecompilerTypeByteSizeTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let ty = dt_parse_type(args.get("type").ok_or_else(|| McpError::InvalidParams("missing 'type'".into()))?)
            .ok_or_else(|| McpError::InvalidParams("invalid type".into()))?;
        let pw = args.get("ptr_width").and_then(Value::as_u64).unwrap_or(8) as u8;
        Ok(ToolResult::text(json!({"byte_size": ty.byte_size_with_ptr_width(pw),"source":"rustre_decompiler_type::DecompType::byte_size_with_ptr_width"}).to_string()))
    }
}

pub struct DecompilerTypeCNameTool;
impl DecompilerTypeCNameTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "decompiler_type_c_name".to_string(),
            description: "Return a C-like type name for a DecompType tree.".to_string(),
            input_schema: json!({"type":"object","properties":{"type":{"type":"object"}},"required":["type"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for DecompilerTypeCNameTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let ty = dt_parse_type(args.get("type").ok_or_else(|| McpError::InvalidParams("missing 'type'".into()))?)
            .ok_or_else(|| McpError::InvalidParams("invalid type".into()))?;
        Ok(ToolResult::text(json!({"c_name": ty.c_name(),"source":"rustre_decompiler_type::DecompType::c_name"}).to_string()))
    }
}

pub struct DecompilerTypeIsPointerTool;
impl DecompilerTypeIsPointerTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "decompiler_type_is_pointer".to_string(),
            description: "Return true if the DecompType is pointer-like.".to_string(),
            input_schema: json!({"type":"object","properties":{"type":{"type":"object"}},"required":["type"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for DecompilerTypeIsPointerTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let ty = dt_parse_type(args.get("type").ok_or_else(|| McpError::InvalidParams("missing 'type'".into()))?)
            .ok_or_else(|| McpError::InvalidParams("invalid type".into()))?;
        Ok(ToolResult::text(json!({"is_pointer": ty.is_pointer(),"source":"rustre_decompiler_type::DecompType::is_pointer"}).to_string()))
    }
}

pub struct DecompilerTypeNamePrefixTool;
impl DecompilerTypeNamePrefixTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "decompiler_type_name_prefix".to_string(),
            description: "Return the variable-name prefix for a DecompType.".to_string(),
            input_schema: json!({"type":"object","properties":{"type":{"type":"object"}},"required":["type"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for DecompilerTypeNamePrefixTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let ty = dt_parse_type(args.get("type").ok_or_else(|| McpError::InvalidParams("missing 'type'".into()))?)
            .ok_or_else(|| McpError::InvalidParams("invalid type".into()))?;
        Ok(ToolResult::text(json!({"prefix": ty.name_prefix(),"source":"rustre_decompiler_type::DecompType::name_prefix"}).to_string()))
    }
}

pub struct DecompilerTypeRenameForTypeTool;
impl DecompilerTypeRenameForTypeTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "decompiler_type_rename_for_type".to_string(),
            description: "Generate a fresh variable name for the given DecompType.".to_string(),
            input_schema: json!({"type":"object","properties":{"type":{"type":"object"}},"required":["type"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for DecompilerTypeRenameForTypeTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let ty = dt_parse_type(args.get("type").ok_or_else(|| McpError::InvalidParams("missing 'type'".into()))?)
            .ok_or_else(|| McpError::InvalidParams("invalid type".into()))?;
        let mut r = rustre_decompiler_type::TypeAwareRenamer::new();
        Ok(ToolResult::text(json!({"name": r.rename(&ty),"source":"rustre_decompiler_type::TypeAwareRenamer::rename"}).to_string()))
    }
}

pub struct DecompilerTypeQualifierStringTool;
impl DecompilerTypeQualifierStringTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "decompiler_type_qualifier_string".to_string(),
            description: "Return C qualifier string (const/volatile/restrict).".to_string(),
            input_schema: json!({"type":"object","properties":{"const":{"type":"boolean"},"volatile":{"type":"boolean"},"restrict":{"type":"boolean"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for DecompilerTypeQualifierStringTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let mut q = rustre_decompiler_type::TypeQualifier::NONE;
        if args.get("const").and_then(Value::as_bool).unwrap_or(false) { q = q.with_const(); }
        if args.get("volatile").and_then(Value::as_bool).unwrap_or(false) { q = q.with_volatile(); }
        if args.get("restrict").and_then(Value::as_bool).unwrap_or(false) { q = q.with_restrict(); }
        Ok(ToolResult::text(json!({"qualifier": q.qualifier_string(),"is_const":q.is_const(),"is_volatile":q.is_volatile(),"is_restrict":q.is_restrict(),"source":"rustre_decompiler_type::TypeQualifier"}).to_string()))
    }
}

pub struct DecompilerTypeStructFieldAtTool;
impl DecompilerTypeStructFieldAtTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "decompiler_type_struct_field_at".to_string(),
            description: "Return the struct field covering the given byte offset.".to_string(),
            input_schema: json!({"type":"object","properties":{"name":{"type":"string"},"total_size":{"type":"integer"},"fields":{"type":"array"},"offset":{"type":"integer"}},"required":["fields","offset"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for DecompilerTypeStructFieldAtTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        use rustre_decompiler_type::{StructType, StructField};
        let name = args.get("name").and_then(Value::as_str).unwrap_or("S").to_string();
        let total_size = args.get("total_size").and_then(Value::as_u64).unwrap_or(0);
        let fields_v = args.get("fields").and_then(Value::as_array)
            .ok_or_else(|| McpError::InvalidParams("missing 'fields'".into()))?;
        let mut fields = Vec::new();
        for fv in fields_v {
            let off = fv.get("offset").and_then(Value::as_u64)
                .ok_or_else(|| McpError::InvalidParams("field.offset".into()))?;
            let fname = fv.get("name").and_then(Value::as_str).unwrap_or("f").to_string();
            let ty = dt_parse_type(fv.get("type").ok_or_else(|| McpError::InvalidParams("field.type".into()))?)
                .ok_or_else(|| McpError::InvalidParams("bad field type".into()))?;
            fields.push(StructField::new(off, fname, ty));
        }
        let st = StructType::new(name, fields, total_size);
        let offset = args.get("offset").and_then(Value::as_u64)
            .ok_or_else(|| McpError::InvalidParams("missing 'offset'".into()))?;
        let f = st.field_at(offset);
        Ok(ToolResult::text(json!({"field": f.map(|f| json!({"offset":f.offset,"name":f.name,"c_name":f.ty.c_name()})),"source":"rustre_decompiler_type::StructType::field_at"}).to_string()))
    }
}

pub struct DecompilerTypeEnvSetGetTool;
impl DecompilerTypeEnvSetGetTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "decompiler_type_env_set_get".to_string(),
            description: "Round-trip a variable through TypeEnvironment set/get.".to_string(),
            input_schema: json!({"type":"object","properties":{"var":{"type":"string"},"type":{"type":"object"}},"required":["var","type"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for DecompilerTypeEnvSetGetTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let var = args.get("var").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'var'".into()))?.to_string();
        let ty = dt_parse_type(args.get("type").ok_or_else(|| McpError::InvalidParams("missing 'type'".into()))?)
            .ok_or_else(|| McpError::InvalidParams("invalid type".into()))?;
        let mut env = rustre_decompiler_type::TypeEnvironment::new();
        env.set(&var, ty);
        let got = env.get(&var).cloned();
        Ok(ToolResult::text(json!({"stored": got.map(|t| t.c_name()),"source":"rustre_decompiler_type::TypeEnvironment"}).to_string()))
    }
}

pub struct DecompilerTypeRenameVariablesTool;
impl DecompilerTypeRenameVariablesTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "decompiler_type_rename_variables".to_string(),
            description: "Apply TypeAwareRenamer::rename_variables to a C snippet.".to_string(),
            input_schema: json!({"type":"object","properties":{"code":{"type":"string"}},"required":["code"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for DecompilerTypeRenameVariablesTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let code = args.get("code").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'code'".into()))?;
        let mut r = rustre_decompiler_type::TypeAwareRenamer::new();
        let env = rustre_decompiler_type::TypeEnvironment::new();
        let out = r.rename_variables(code, &env);
        Ok(ToolResult::text(json!({"renamed": out,"source":"rustre_decompiler_type::TypeAwareRenamer::rename_variables"}).to_string()))
    }
}

pub struct DecompilerTypeRenameAllTool;
impl DecompilerTypeRenameAllTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "decompiler_type_rename_all".to_string(),
            description: "Bulk-generate names for (name,type) pairs.".to_string(),
            input_schema: json!({"type":"object","properties":{"vars":{"type":"array"}},"required":["vars"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for DecompilerTypeRenameAllTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let arr = args.get("vars").and_then(Value::as_array)
            .ok_or_else(|| McpError::InvalidParams("missing 'vars'".into()))?;
        let mut pairs = Vec::new();
        for v in arr {
            let name = v.get("name").and_then(Value::as_str)
                .ok_or_else(|| McpError::InvalidParams("var.name".into()))?.to_string();
            let ty = dt_parse_type(v.get("type").ok_or_else(|| McpError::InvalidParams("var.type".into()))?)
                .ok_or_else(|| McpError::InvalidParams("bad var type".into()))?;
            pairs.push((name, ty));
        }
        let mut r = rustre_decompiler_type::TypeAwareRenamer::new();
        let map = r.rename_all(&pairs);
        let map_json: serde_json::Map<String, Value> = map.into_iter().map(|(k,v)| (k, Value::String(v))).collect();
        Ok(ToolResult::text(json!({"mapping": Value::Object(map_json),"source":"rustre_decompiler_type::TypeAwareRenamer::rename_all"}).to_string()))
    }
}

fn push_decompiler_type_extra_handlers(out: &mut Vec<(ToolDefinition, Box<dyn ToolHandler>)>) {
    out.push((DecompilerTypeByteSizeTool::definition(), Box::new(DecompilerTypeByteSizeTool)));
    out.push((DecompilerTypeCNameTool::definition(), Box::new(DecompilerTypeCNameTool)));
    out.push((DecompilerTypeIsPointerTool::definition(), Box::new(DecompilerTypeIsPointerTool)));
    out.push((DecompilerTypeNamePrefixTool::definition(), Box::new(DecompilerTypeNamePrefixTool)));
    out.push((DecompilerTypeRenameForTypeTool::definition(), Box::new(DecompilerTypeRenameForTypeTool)));
    out.push((DecompilerTypeQualifierStringTool::definition(), Box::new(DecompilerTypeQualifierStringTool)));
    out.push((DecompilerTypeStructFieldAtTool::definition(), Box::new(DecompilerTypeStructFieldAtTool)));
    out.push((DecompilerTypeEnvSetGetTool::definition(), Box::new(DecompilerTypeEnvSetGetTool)));
    out.push((DecompilerTypeRenameVariablesTool::definition(), Box::new(DecompilerTypeRenameVariablesTool)));
    out.push((DecompilerTypeRenameAllTool::definition(), Box::new(DecompilerTypeRenameAllTool)));
}
