//! `analysis_infer_types_path` — function-level type inference MCP tool.
//!
//! Loads a binary, decompiles the requested function to obtain its recovered
//! variable list, lifts those variables into a synthetic instruction stream
//! that the constraint-based [`rustre_analysis_type::TypeInferenceEngine`]
//! can solve, then returns a synthesised C signature together with per-local
//! `{name, type, confidence}` triples and an overall confidence band.

use async_trait::async_trait;
use rustre_mcp_server::{McpError, ToolDefinition, ToolHandler, ToolResult};
use serde_json::{json, Value};

pub struct InferTypesPathTool;

impl InferTypesPathTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "analysis_infer_types_path".to_string(),
            description:
                "Run type inference on a single function in a binary on disk. \
                 Loads the file, decompiles the requested function, lifts its \
                 recovered variables into the constraint solver, and returns a \
                 synthesised C signature with per-local types and confidence."
                    .to_string(),
            input_schema: json!({
                "type": "object",
                "required": ["path", "function_address"],
                "properties": {
                    "path":             { "type": "string",  "description": "Absolute path to the binary" },
                    "function_address": { "type": ["integer","string"], "description": "VA of the function (int or 0x-hex)" }
                }
            }),
            parameters: Value::Null,
        }
    }
}

#[async_trait]
impl ToolHandler for InferTypesPathTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        use rustre_analysis_type::{
            collect_constraints, InstrKind, TypeFact, TypeInferenceEngine, TypedInstr,
        };

        let path = args
            .get("path")
            .and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'path'".into()))?;
        let parse_va = |v: &Value| -> Option<u64> {
            v.as_u64().or_else(|| {
                v.as_str()
                    .and_then(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok())
            })
        };
        let func_va = args
            .get("function_address")
            .and_then(parse_va)
            .ok_or_else(|| McpError::InvalidParams("missing 'function_address'".into()))?;

        let binary_path = std::path::Path::new(path);
        let opts = rustre_decompiler::DecompOptions::default();
        let func = rustre_decompiler::decompile_function_from_binary(binary_path, func_va, opts)
            .map_err(|e| McpError::InternalError(format!("decompile failed: {e}")))?;

        // Seed the engine: each recovered variable becomes a `Const` whose
        // (size, signedness) is parsed from the decompiler's printed type.
        // The lattice `join` then promotes `Sized(n)` to a concrete int width
        // as soon as a HasType constraint arrives downstream.
        let mut engine = TypeInferenceEngine::new();
        let mut instrs: Vec<TypedInstr> = Vec::new();
        for v in &func.variables {
            let (bytes, signed) = type_str_to_size_sign(&v.type_str);
            instrs.push(TypedInstr {
                kind: InstrKind::Const {
                    dst: v.name.clone(),
                    bytes,
                    signed,
                },
            });
        }
        collect_constraints(&mut engine, &instrs);
        let assignment = engine
            .solve()
            .map_err(|e| McpError::InternalError(format!("type solve failed: {e}")))?;

        let mut locals_json: Vec<Value> = Vec::with_capacity(func.variables.len());
        let mut known = 0usize;
        let mut params: Vec<String> = Vec::new();
        for v in &func.variables {
            let fact = engine
                .type_of(&v.name, &assignment)
                .unwrap_or(TypeFact::Unknown);
            let ty_text = if fact.is_known() {
                fact.to_string()
            } else {
                v.type_str.clone()
            };
            let confidence = classify_confidence(&fact, &v.type_str);
            if confidence != "low" {
                known += 1;
            }
            if v.is_parameter {
                params.push(format!("{ty_text} {}", v.name));
            }
            locals_json.push(json!({
                "name": v.name,
                "type": ty_text,
                "confidence": confidence,
                "storage": format!("{}", v.storage),
                "is_parameter": v.is_parameter,
            }));
        }

        // Best-effort return-type sniff from the pseudo-code body.
        let mut ret_ty = "void".to_string();
        if let Some(idx) = func.pseudo_code.find("return ") {
            let tail = &func.pseudo_code[idx + 7..];
            if let Some(end) = tail.find(';') {
                let expr = tail[..end].trim();
                if expr.starts_with('"') {
                    ret_ty = "char *".into();
                } else if expr.starts_with("0x") || expr.parse::<i64>().is_ok() {
                    ret_ty = "int".into();
                } else if !expr.is_empty() {
                    ret_ty = "int".into();
                }
            }
        }

        let display_name = if func.name.is_empty() {
            format!("sub_{func_va:08x}")
        } else {
            func.name.clone()
        };
        let signature = format!(
            "{ret_ty} {display_name}({});",
            if params.is_empty() {
                "void".to_string()
            } else {
                params.join(", ")
            }
        );

        let overall = if func.variables.is_empty() {
            "low"
        } else {
            let ratio = (known as f32) / (func.variables.len() as f32);
            if ratio >= 0.75 {
                "high"
            } else if ratio >= 0.40 {
                "medium"
            } else {
                "low"
            }
        };

        Ok(ToolResult::text(
            json!({
                "binary_path":           path,
                "function_address":      func_va,
                "function_name":         func.name,
                "signature":             signature,
                "locals":                locals_json,
                "locals_total":          func.variables.len(),
                "locals_typed":          known,
                "confidence_overall":    overall,
                "decompiler_confidence": func.confidence,
            })
            .to_string(),
        ))
    }
}

/// Coarse mapping of a decompiler-printed type string to (size_bytes, signed).
fn type_str_to_size_sign(s: &str) -> (usize, bool) {
    let t = s.trim().to_ascii_lowercase();
    if t.contains('*') || t.contains("ptr") || t.contains("ref") {
        return (8, false);
    }
    if t.contains("i64") || t.contains("int64") || t.contains("long long") {
        return (8, true);
    }
    if t.contains("u64") || t.contains("uint64") || t.contains("size_t") || t.contains("qword") {
        return (8, false);
    }
    if t.contains("i32") || t.contains("int32") || t == "int" || t.contains("dword") {
        return (4, true);
    }
    if t.contains("u32") || t.contains("uint32") {
        return (4, false);
    }
    if t.contains("i16") || t.contains("int16") || t.contains("short") || t.contains("word") {
        return (2, true);
    }
    if t.contains("u16") || t.contains("uint16") {
        return (2, false);
    }
    if t.contains("i8") || t.contains("char") || t.contains("byte") {
        return (1, true);
    }
    if t.contains("u8") || t.contains("bool") {
        return (1, false);
    }
    (8, false)
}

fn classify_confidence(
    fact: &rustre_analysis_type::TypeFact,
    original: &str,
) -> &'static str {
    use rustre_analysis_type::TypeFact as T;
    match fact {
        T::Unknown => {
            let o = original.trim();
            if o.is_empty() || o == "?" || o.eq_ignore_ascii_case("unknown") {
                "low"
            } else {
                "medium"
            }
        }
        T::Sized(_) => "medium",
        T::SignedInt(_)
        | T::UnsignedInt(_)
        | T::Float(_)
        | T::Bool
        | T::Char
        | T::Pointer(_)
        | T::Array { .. }
        | T::Struct { .. } => "high",
    }
}
