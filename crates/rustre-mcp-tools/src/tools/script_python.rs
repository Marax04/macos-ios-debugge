//! MCP wrappers for the rustre-script_python crate.
//! Extracted from `wire_tools.rs` by `workflow_split_wire_tools`.

use rustre_mcp_server::{McpError, ToolDefinition, ToolHandler, ToolResult};
use serde_json::{json, Value};
use async_trait::async_trait;

pub struct ScriptPythonMarshalToAddressTool;

pub struct ScriptPythonMarshalToBytesTool;

pub struct ScriptPythonStubsStandardNamesTool;

pub struct ScriptPythonStubsGenerateStandardTool;

pub struct ScriptPythonPureExecuteTool;
impl ScriptPythonPureExecuteTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "script_python_pure_execute".to_string(),
            description: "Execute a Python script with the pure-Rust PythonEngine; return captured stdout, final value, and step count.".to_string(),
            input_schema: json!({
                "type": "object",
                "required": ["script"],
                "properties": {
                    "script": { "type": "string" },
                    "max_steps": { "type": "integer", "minimum": 1 }
                }
            }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for ScriptPythonPureExecuteTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let script = args.get("script").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'script'".into()))?;
        let mut engine = rustre_script_python::PythonEngine::new();
        if let Some(n) = args.get("max_steps").and_then(Value::as_u64) {
            engine.set_max_steps(n);
        }
        let mut scope = rustre_script_python::PyScope::new();
        let result = engine.execute(script, &mut scope)
            .map_err(|e| McpError::InternalError(format!("python: {e}")))?;
        Ok(ToolResult::text(json!({
            "output": scope.output_text(),
            "result": result.to_string(),
            "result_type": result.type_name(),
            "step_count": engine.step_count(),
        }).to_string()))
    }
}

pub struct ScriptPythonPureParseTool;
impl ScriptPythonPureParseTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "script_python_pure_parse".to_string(),
            description: "Parse a Python script with the pure-Rust engine; return the number of top-level statements.".to_string(),
            input_schema: json!({
                "type": "object",
                "required": ["script"],
                "properties": { "script": { "type": "string" } }
            }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for ScriptPythonPureParseTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let script = args.get("script").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'script'".into()))?;
        let engine = rustre_script_python::PythonEngine::new();
        let stmts = engine.parse(script)
            .map_err(|e| McpError::InternalError(format!("python parse: {e}")))?;
        Ok(ToolResult::text(json!({
            "top_level_stmt_count": stmts.len(),
            "ok": true,
        }).to_string()))
    }
}

pub struct ScriptPythonPureEvalIntTool;
impl ScriptPythonPureEvalIntTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "script_python_pure_eval_int".to_string(),
            description: "Execute a Python script with the pure-Rust engine and coerce the final value to i64.".to_string(),
            input_schema: json!({
                "type": "object",
                "required": ["script"],
                "properties": { "script": { "type": "string" } }
            }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for ScriptPythonPureEvalIntTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let script = args.get("script").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'script'".into()))?;
        let mut engine = rustre_script_python::PythonEngine::new();
        let mut scope = rustre_script_python::PyScope::new();
        let result = engine.execute(script, &mut scope)
            .map_err(|e| McpError::InternalError(format!("python: {e}")))?;
        let as_int = result.as_int();
        Ok(ToolResult::text(json!({
            "value": as_int,
            "found_int": as_int.is_some(),
            "type": result.type_name(),
        }).to_string()))
    }
}

pub struct ScriptPythonPureValueClassifyTool;
impl ScriptPythonPureValueClassifyTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "script_python_pure_value_classify".to_string(),
            description: "Classify a JSON value as a Python PyValue: return type_name, truthiness, len, display.".to_string(),
            input_schema: json!({
                "type": "object",
                "required": ["value"],
                "properties": { "value": {} }
            }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for ScriptPythonPureValueClassifyTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let v = args.get("value").ok_or_else(|| McpError::InvalidParams("missing 'value'".into()))?;
        let py = match v {
            Value::Null => rustre_script_python::PyValue::None,
            Value::Bool(b) => rustre_script_python::PyValue::Bool(*b),
            Value::Number(n) => {
                if let Some(i) = n.as_i64() { rustre_script_python::PyValue::Int(i) }
                else { rustre_script_python::PyValue::Float(n.as_f64().unwrap_or(0.0)) }
            }
            Value::String(s) => rustre_script_python::PyValue::Str(s.clone()),
            Value::Array(a) => {
                let items = a.iter().map(|x| match x {
                    Value::String(s) => rustre_script_python::PyValue::Str(s.clone()),
                    Value::Bool(b) => rustre_script_python::PyValue::Bool(*b),
                    Value::Number(n) => n.as_i64().map(rustre_script_python::PyValue::Int)
                        .unwrap_or(rustre_script_python::PyValue::None),
                    _ => rustre_script_python::PyValue::None,
                }).collect();
                rustre_script_python::PyValue::List(items)
            }
            Value::Object(_) => rustre_script_python::PyValue::Dict(vec![]),
        };
        Ok(ToolResult::text(json!({
            "type_name": py.type_name(),
            "is_truthy": py.is_truthy(),
            "len": py.len_val(),
            "is_empty": py.is_empty(),
            "display": py.to_string(),
        }).to_string()))
    }
}

pub struct ScriptPythonStubBuiltinNamesTool;
impl ScriptPythonStubBuiltinNamesTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "script_python_stub_builtin_names".to_string(),
            description: "Return sorted list of Python builtins pre-seeded in a fresh PyScope of the pure-Rust engine.".to_string(),
            input_schema: json!({ "type": "object", "properties": {} }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for ScriptPythonStubBuiltinNamesTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let scope = rustre_script_python::PyScope::new();
        let mut names: Vec<String> = scope.locals.keys().cloned().collect();
        names.sort();
        Ok(ToolResult::text(json!({
            "count": names.len(),
            "names": names,
        }).to_string()))
    }
}

pub struct ScriptPythonPureStepCostTool;
impl ScriptPythonPureStepCostTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "script_python_pure_step_cost".to_string(),
            description: "Execute a Python script and return the interpreter step count (proxy for CPU cost).".to_string(),
            input_schema: json!({
                "type": "object",
                "required": ["script"],
                "properties": {
                    "script": { "type": "string" },
                    "max_steps": { "type": "integer", "minimum": 1 }
                }
            }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for ScriptPythonPureStepCostTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let script = args.get("script").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'script'".into()))?;
        let mut engine = rustre_script_python::PythonEngine::new();
        if let Some(n) = args.get("max_steps").and_then(Value::as_u64) {
            engine.set_max_steps(n);
        }
        let mut scope = rustre_script_python::PyScope::new();
        let outcome = engine.execute(script, &mut scope);
        Ok(ToolResult::text(json!({
            "step_count": engine.step_count(),
            "ok": outcome.is_ok(),
            "error": outcome.as_ref().err().map(|e| e.to_string()),
        }).to_string()))
    }
}

pub struct ScriptPythonPureCollectLocalsTool;
impl ScriptPythonPureCollectLocalsTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "script_python_pure_collect_locals".to_string(),
            description: "Execute a Python script and return all local variable names, types, and string representations.".to_string(),
            input_schema: json!({
                "type": "object",
                "required": ["script"],
                "properties": { "script": { "type": "string" } }
            }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for ScriptPythonPureCollectLocalsTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let script = args.get("script").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'script'".into()))?;
        let mut engine = rustre_script_python::PythonEngine::new();
        let mut scope = rustre_script_python::PyScope::new();
        engine.execute(script, &mut scope)
            .map_err(|e| McpError::InternalError(format!("python: {e}")))?;
        let mut entries: Vec<(String, String, &'static str)> = scope.locals.iter()
            .map(|(k, v)| (k.clone(), v.to_string(), v.type_name()))
            .collect();
        entries.sort_by(|a, b| a.0.cmp(&b.0));
        let list: Vec<Value> = entries.into_iter().map(|(k, v, t)| json!({
            "name": k, "value": v, "type": t
        })).collect();
        Ok(ToolResult::text(json!({
            "count": list.len(),
            "locals": list,
        }).to_string()))
    }
}

pub struct ScriptPythonPyvalueIsTruthyTool;
impl ScriptPythonPyvalueIsTruthyTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "script_python_pyvalue_is_truthy".to_string(),
            description: "Python truthiness via PyValue::is_truthy.".to_string(),
            input_schema: json!({"type":"object","required":["value"],"properties":{"value":{}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for ScriptPythonPyvalueIsTruthyTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let v = args.get("value").ok_or_else(|| McpError::InvalidParams("missing 'value'".into()))?;
        let py = match v {
            Value::Null => rustre_script_python::PyValue::None,
            Value::Bool(b) => rustre_script_python::PyValue::Bool(*b),
            Value::Number(n) => n.as_i64().map(rustre_script_python::PyValue::Int)
                .unwrap_or_else(|| rustre_script_python::PyValue::Float(n.as_f64().unwrap_or(0.0))),
            Value::String(s) => rustre_script_python::PyValue::Str(s.clone()),
            Value::Array(_) => rustre_script_python::PyValue::List(vec![]),
            Value::Object(_) => rustre_script_python::PyValue::Dict(vec![]),
        };
        Ok(ToolResult::text(json!({
            "is_truthy": py.is_truthy(),
            "type_name": py.type_name(),
            "source": "rustre_script_python::PyValue::is_truthy",
        }).to_string()))
    }
}

pub struct ScriptPythonPyvalueLenTool;
impl ScriptPythonPyvalueLenTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "script_python_pyvalue_len".to_string(),
            description: "len() via PyValue::len_val.".to_string(),
            input_schema: json!({"type":"object","required":["value"],"properties":{"value":{}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for ScriptPythonPyvalueLenTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let v = args.get("value").ok_or_else(|| McpError::InvalidParams("missing 'value'".into()))?;
        let py = match v {
            Value::String(s) => rustre_script_python::PyValue::Str(s.clone()),
            Value::Array(a) => rustre_script_python::PyValue::List(
                a.iter().map(|_| rustre_script_python::PyValue::None).collect()),
            Value::Object(o) => rustre_script_python::PyValue::Dict(
                o.iter().map(|(k,_)| (rustre_script_python::PyValue::Str(k.clone()), rustre_script_python::PyValue::None)).collect()),
            _ => rustre_script_python::PyValue::None,
        };
        Ok(ToolResult::text(json!({
            "len": py.len_val(),
            "is_empty": py.is_empty(),
            "type_name": py.type_name(),
            "source": "rustre_script_python::PyValue::len_val",
        }).to_string()))
    }
}

pub struct ScriptPythonPyvalueAsIntTool;
impl ScriptPythonPyvalueAsIntTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "script_python_pyvalue_as_int".to_string(),
            description: "PyValue::as_int on JSON.".to_string(),
            input_schema: json!({"type":"object","required":["value"],"properties":{"value":{}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for ScriptPythonPyvalueAsIntTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let v = args.get("value").ok_or_else(|| McpError::InvalidParams("missing 'value'".into()))?;
        let py = match v {
            Value::Bool(b) => rustre_script_python::PyValue::Bool(*b),
            Value::Number(n) => {
                if let Some(i) = n.as_i64() { rustre_script_python::PyValue::Int(i) }
                else { rustre_script_python::PyValue::Float(n.as_f64().unwrap_or(0.0)) }
            }
            Value::String(s) => rustre_script_python::PyValue::Str(s.clone()),
            _ => rustre_script_python::PyValue::None,
        };
        Ok(ToolResult::text(json!({
            "as_int": py.as_int(),
            "type_name": py.type_name(),
            "source": "rustre_script_python::PyValue::as_int",
        }).to_string()))
    }
}

pub struct ScriptPythonPyscriptvalueTypeNameTool;
impl ScriptPythonPyscriptvalueTypeNameTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "script_python_pyscriptvalue_type_name".to_string(),
            description: "type_name for each PyScriptValue variant.".to_string(),
            input_schema: json!({"type":"object","properties":{}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for ScriptPythonPyscriptvalueTypeNameTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        use rustre_script_python::PyScriptValue as V;
        let variants = vec![V::None_, V::Bool(true), V::Int(0), V::Float(0.0),
            V::Str(String::new()), V::List(vec![]), V::Dict(vec![])];
        let names: Vec<&'static str> = variants.iter().map(|v| v.type_name()).collect();
        Ok(ToolResult::text(json!({"names":names,"count":names.len(),
            "source":"rustre_script_python::PyScriptValue::type_name"}).to_string()))
    }
}

pub struct ScriptPythonPyscriptvalueDisplayTool;
impl ScriptPythonPyscriptvalueDisplayTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "script_python_pyscriptvalue_display".to_string(),
            description: "PyScriptValue Display for JSON.".to_string(),
            input_schema: json!({"type":"object","required":["value"],"properties":{"value":{}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for ScriptPythonPyscriptvalueDisplayTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        use rustre_script_python::PyScriptValue as V;
        let v = args.get("value").ok_or_else(|| McpError::InvalidParams("missing 'value'".into()))?;
        let pv = match v {
            Value::Null => V::None_,
            Value::Bool(b) => V::Bool(*b),
            Value::Number(n) => n.as_i64().map(V::Int)
                .unwrap_or_else(|| V::Float(n.as_f64().unwrap_or(0.0))),
            Value::String(s) => V::Str(s.clone()),
            Value::Array(_) => V::List(vec![]),
            Value::Object(_) => V::Dict(vec![]),
        };
        Ok(ToolResult::text(json!({"display":pv.to_string(),"type_name":pv.type_name(),
            "is_none":pv.is_none(),"source":"rustre_script_python::PyScriptValue::fmt"}).to_string()))
    }
}

pub struct ScriptPythonPyscopeOutputTextTool;
impl ScriptPythonPyscopeOutputTextTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "script_python_pyscope_output_text".to_string(),
            description: "PyScope::output_text on pushed lines.".to_string(),
            input_schema: json!({"type":"object","required":["lines"],
                "properties":{"lines":{"type":"array","items":{"type":"string"}}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for ScriptPythonPyscopeOutputTextTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let lines: Vec<String> = args.get("lines").and_then(Value::as_array)
            .ok_or_else(|| McpError::InvalidParams("missing 'lines'".into()))?
            .iter().filter_map(|v| v.as_str().map(str::to_string)).collect();
        let mut scope = rustre_script_python::PyScope::new();
        scope.output.extend(lines.iter().cloned());
        let text = scope.output_text();
        Ok(ToolResult::text(json!({"output_text":text,"line_count":lines.len(),
            "source":"rustre_script_python::PyScope::output_text"}).to_string()))
    }
}

pub struct ScriptPythonPyscopeSetGetTool;
impl ScriptPythonPyscopeSetGetTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "script_python_pyscope_set_get".to_string(),
            description: "PyScope::set then get.".to_string(),
            input_schema: json!({"type":"object","required":["name","value"],
                "properties":{"name":{"type":"string"},"value":{"type":"integer"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for ScriptPythonPyscopeSetGetTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let name = args.get("name").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'name'".into()))?;
        let val = args.get("value").and_then(Value::as_i64)
            .ok_or_else(|| McpError::InvalidParams("missing 'value'".into()))?;
        let mut scope = rustre_script_python::PyScope::new();
        scope.set(name.to_string(), rustre_script_python::PyValue::Int(val));
        let got = scope.get(name).map(|v| v.to_string());
        Ok(ToolResult::text(json!({"name":name,"stored":val,"readback":got,
            "source":"rustre_script_python::PyScope::set"}).to_string()))
    }
}

pub struct ScriptPythonPyscopeBuiltinCountTool;
impl ScriptPythonPyscopeBuiltinCountTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "script_python_pyscope_builtin_count".to_string(),
            description: "Count builtins in fresh PyScope.".to_string(),
            input_schema: json!({"type":"object","properties":{}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for ScriptPythonPyscopeBuiltinCountTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let scope = rustre_script_python::PyScope::new();
        let total = scope.locals.len();
        let funcs = scope.locals.values().filter(|v| matches!(v, rustre_script_python::PyValue::Function(_))).count();
        Ok(ToolResult::text(json!({"total":total,"functions":funcs,
            "source":"rustre_script_python::PyScope::new"}).to_string()))
    }
}

pub struct ScriptPythonPureExecutePrintTool;
impl ScriptPythonPureExecutePrintTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "script_python_pure_execute_print".to_string(),
            description: "Execute Python, return print output.".to_string(),
            input_schema: json!({"type":"object","required":["script"],
                "properties":{"script":{"type":"string"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for ScriptPythonPureExecutePrintTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let script = args.get("script").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'script'".into()))?;
        let mut engine = rustre_script_python::PythonEngine::new();
        let mut scope = rustre_script_python::PyScope::new();
        let result = engine.execute(script, &mut scope);
        Ok(ToolResult::text(json!({"ok":result.is_ok(),
            "error":result.as_ref().err().map(|e| e.to_string()),
            "output":scope.output_text(),"step_count":engine.step_count(),
            "source":"rustre_script_python::PythonEngine::execute"}).to_string()))
    }
}

pub struct ScriptPythonPyvalueTypeNamesTool;
impl ScriptPythonPyvalueTypeNamesTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "script_python_pyvalue_type_names".to_string(),
            description: "Enumerate PyValue variants and type_name.".to_string(),
            input_schema: json!({"type":"object","properties":{}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for ScriptPythonPyvalueTypeNamesTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        use rustre_script_python::PyValue as V;
        let variants = vec![V::None, V::Bool(false), V::Int(0), V::Float(0.0),
            V::Str(String::new()), V::List(vec![]), V::Dict(vec![]), V::Tuple(vec![]),
            V::Bytes(vec![]), V::Function("f".to_string())];
        let names: Vec<&'static str> = variants.iter().map(|v| v.type_name()).collect();
        Ok(ToolResult::text(json!({"count":names.len(),"names":names,
            "source":"rustre_script_python::PyValue::type_name"}).to_string()))
    }
}

#[must_use]
pub fn handlers() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    vec![
        (ScriptPythonMarshalToAddressTool::definition(), Box::new(ScriptPythonMarshalToAddressTool)),
        (ScriptPythonMarshalToBytesTool::definition(), Box::new(ScriptPythonMarshalToBytesTool)),
        (ScriptPythonStubsStandardNamesTool::definition(), Box::new(ScriptPythonStubsStandardNamesTool)),
        (ScriptPythonStubsGenerateStandardTool::definition(), Box::new(ScriptPythonStubsGenerateStandardTool)),
        (ScriptPythonPureExecuteTool::definition(), Box::new(ScriptPythonPureExecuteTool)),
        (ScriptPythonPureParseTool::definition(), Box::new(ScriptPythonPureParseTool)),
        (ScriptPythonPureEvalIntTool::definition(), Box::new(ScriptPythonPureEvalIntTool)),
        (ScriptPythonPureValueClassifyTool::definition(), Box::new(ScriptPythonPureValueClassifyTool)),
        (ScriptPythonStubBuiltinNamesTool::definition(), Box::new(ScriptPythonStubBuiltinNamesTool)),
        (ScriptPythonPureStepCostTool::definition(), Box::new(ScriptPythonPureStepCostTool)),
        (ScriptPythonPureCollectLocalsTool::definition(), Box::new(ScriptPythonPureCollectLocalsTool)),
        (ScriptPythonPyvalueIsTruthyTool::definition(), Box::new(ScriptPythonPyvalueIsTruthyTool)),
        (ScriptPythonPyvalueLenTool::definition(), Box::new(ScriptPythonPyvalueLenTool)),
        (ScriptPythonPyvalueAsIntTool::definition(), Box::new(ScriptPythonPyvalueAsIntTool)),
        (ScriptPythonPyscriptvalueTypeNameTool::definition(), Box::new(ScriptPythonPyscriptvalueTypeNameTool)),
        (ScriptPythonPyscriptvalueDisplayTool::definition(), Box::new(ScriptPythonPyscriptvalueDisplayTool)),
        (ScriptPythonPyscopeOutputTextTool::definition(), Box::new(ScriptPythonPyscopeOutputTextTool)),
        (ScriptPythonPyscopeSetGetTool::definition(), Box::new(ScriptPythonPyscopeSetGetTool)),
        (ScriptPythonPyscopeBuiltinCountTool::definition(), Box::new(ScriptPythonPyscopeBuiltinCountTool)),
        (ScriptPythonPureExecutePrintTool::definition(), Box::new(ScriptPythonPureExecutePrintTool)),
        (ScriptPythonPyvalueTypeNamesTool::definition(), Box::new(ScriptPythonPyvalueTypeNamesTool)),
    ]
}
