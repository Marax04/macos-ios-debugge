//! MCP surface for the reconstruction layer: what a binary is made of, and how
//! much the emitted pseudo-code for a function can be trusted.
//!
//! These wrap `rustre_decompiler::reconstruction`, which is evidence-based by
//! contract: a verdict always ships the markers that produced it, and an
//! undetermined field is reported as `null` rather than guessed. The tools
//! below preserve that — they never substitute a default for a `None`.

use async_trait::async_trait;
use serde_json::{json, Value};

use rustre_decompiler::reconstruction::{confidence, toolchain};

use crate::{McpError, ToolDefinition, ToolHandler, ToolResult};

pub struct ReconstructionToolchainDetectPathTool;
pub struct ReconstructionToolchainDetectBytesTool;
pub struct ReconstructionConfidenceScoreTool;

/// Shared JSON shape for a detection verdict, so the path and bytes tools
/// cannot drift apart.
fn report_json(r: &toolchain::ToolchainReport) -> Value {
    json!({
        "language": r.language.map(toolchain::Language::id),
        "toolchain": r.toolchain.map(toolchain::Toolchain::id),
        "version": r.version,
        "markers": r.markers.iter().copied().collect::<Vec<_>>(),
        "explain": r.explain(),
        "source": "rustre_decompiler::reconstruction::toolchain::detect",
    })
}

impl ReconstructionToolchainDetectPathTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "reconstruction_toolchain_detect_path".to_string(),
            description: "Detect source language, producing toolchain and toolchain version for the binary at `path`. Scans raw image bytes, so it works on stripped binaries. `language`/`toolchain`/`version` are null when no rule matched — never a guess. Returns the markers that produced the verdict.".to_string(),
            input_schema: json!({
                "type": "object",
                "required": ["path"],
                "properties": { "path": { "type": "string" } }
            }),
            parameters: Value::Null,
        }
    }
}

#[async_trait]
impl ToolHandler for ReconstructionToolchainDetectPathTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let path = args
            .get("path")
            .and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'path'".into()))?;
        let data = std::fs::read(path)
            .map_err(|e| McpError::InternalError(format!("read {path}: {e}")))?;
        let r = toolchain::detect(&data);
        let mut out = report_json(&r);
        out["path"] = json!(path);
        Ok(ToolResult::text(out.to_string()))
    }
}

impl ReconstructionToolchainDetectBytesTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "reconstruction_toolchain_detect_bytes".to_string(),
            description: "Same detection as reconstruction_toolchain_detect_path, but over a hex-encoded byte string in `hex`. Useful for carved or in-memory images.".to_string(),
            input_schema: json!({
                "type": "object",
                "required": ["hex"],
                "properties": { "hex": { "type": "string" } }
            }),
            parameters: Value::Null,
        }
    }
}

#[async_trait]
impl ToolHandler for ReconstructionToolchainDetectBytesTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let hex = args
            .get("hex")
            .and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'hex'".into()))?;
        let clean: String = hex.chars().filter(|c| !c.is_whitespace()).collect();
        // Byte-index slicing below requires 1-byte chars: a multi-byte char
        // (e.g. a fullwidth digit) would panic on a non-char-boundary slice.
        if !clean.is_ascii() {
            return Err(McpError::InvalidParams("hex must be ASCII hex digits".into()));
        }
        if clean.len() % 2 != 0 {
            return Err(McpError::InvalidParams("hex has an odd number of digits".into()));
        }
        let data: Vec<u8> = (0..clean.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&clean[i..i + 2], 16))
            .collect::<Result<_, _>>()
            .map_err(|e| McpError::InvalidParams(format!("bad hex: {e}")))?;
        Ok(ToolResult::text(report_json(&toolchain::detect(&data)).to_string()))
    }
}

impl ReconstructionConfidenceScoreTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "reconstruction_confidence_score".to_string(),
            description: "Score emitted pseudo-C in `code` (15..=95) and return every doubt signal that fired, with counts and the points each subtracted. `has_silent_wrongness` flags signals such as phantom parameters that indicate confidently-wrong output which still compiles cleanly — the failure class a recompilability check cannot see.".to_string(),
            input_schema: json!({
                "type": "object",
                "required": ["code"],
                "properties": { "code": { "type": "string" } }
            }),
            parameters: Value::Null,
        }
    }
}

#[async_trait]
impl ToolHandler for ReconstructionConfidenceScoreTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let code = args
            .get("code")
            .and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'code'".into()))?;
        let r = confidence::score_with_evidence(code);
        Ok(ToolResult::text(
            json!({
                "score": r.score,
                "has_silent_wrongness": r.has_silent_wrongness(),
                "explain": r.explain(),
                "findings": r.findings.iter().map(|f| json!({
                    "signal": f.signal.id(),
                    "count": f.count,
                    "penalty": f.penalty,
                    "is_silent_wrongness": f.signal.is_silent_wrongness(),
                })).collect::<Vec<_>>(),
                "source": "rustre_decompiler::reconstruction::confidence::score_with_evidence",
            })
            .to_string(),
        ))
    }
}

#[must_use]
pub fn handlers() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    vec![
        (
            ReconstructionToolchainDetectPathTool::definition(),
            Box::new(ReconstructionToolchainDetectPathTool),
        ),
        (
            ReconstructionToolchainDetectBytesTool::definition(),
            Box::new(ReconstructionToolchainDetectBytesTool),
        ),
        (
            ReconstructionConfidenceScoreTool::definition(),
            Box::new(ReconstructionConfidenceScoreTool),
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn detect_bytes_reports_go_with_version() {
        // "..go1.25.1..runtime.goexit.." as hex.
        let hex = hex_of(b"..go1.25.1..runtime.goexit..");
        let out = ReconstructionToolchainDetectBytesTool
            .call(json!({ "hex": hex }))
            .await
            .expect("detect must succeed");
        let v: Value = serde_json::from_str(&text_of(&out)).unwrap();
        assert_eq!(v["language"], "go");
        assert_eq!(v["toolchain"], "go");
        assert_eq!(v["version"], "1.25.1");
    }

    #[tokio::test]
    async fn unknown_input_reports_null_not_a_guess() {
        let out = ReconstructionToolchainDetectBytesTool
            .call(json!({ "hex": hex_of(b"no markers whatsoever") }))
            .await
            .expect("detect must succeed");
        let v: Value = serde_json::from_str(&text_of(&out)).unwrap();
        assert!(v["language"].is_null(), "must not invent a language");
        assert!(v["toolchain"].is_null());
    }

    #[tokio::test]
    async fn odd_length_hex_is_rejected() {
        let err = ReconstructionToolchainDetectBytesTool.call(json!({ "hex": "abc" })).await;
        assert!(err.is_err(), "odd hex must not be silently truncated");
    }

    #[tokio::test]
    async fn non_ascii_hex_is_rejected_not_a_panic() {
        // Two fullwidth digits: 6 bytes, even length, non-char-boundary at 2.
        let err = ReconstructionToolchainDetectBytesTool
            .call(json!({ "hex": "ｆｆ" }))
            .await;
        assert!(err.is_err(), "non-ASCII hex must be a clean InvalidParams");
    }

    #[tokio::test]
    async fn confidence_flags_a_phantom_parameter() {
        // `a2` is declared but never referenced — the phantom-param fingerprint.
        // Brace style matters: the scorer finds the signature by looking for a
        // line ending in `) {`, which is exactly how the pipeline emits it
        // (verified against `tests/decompiler_corpus/out`). A test written with
        // the brace on its own line silently finds no parameters at all.
        let code = "__int64 __fastcall sub_1(__int64 a1, __int64 a2) {\n  return a1;\n}\n";
        let out = ReconstructionConfidenceScoreTool
            .call(json!({ "code": code }))
            .await
            .expect("score must succeed");
        let v: Value = serde_json::from_str(&text_of(&out)).unwrap();
        assert!(
            v["has_silent_wrongness"].as_bool().unwrap(),
            "an unreferenced trailing param must be reported as silent wrongness: {v}"
        );
    }

    fn hex_of(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    fn text_of(r: &ToolResult) -> String {
        serde_json::to_value(r)
            .ok()
            .and_then(|v| {
                v.get("content")
                    .and_then(|c| c.get(0))
                    .and_then(|c| c.get("text"))
                    .and_then(|t| t.as_str())
                    .map(str::to_owned)
            })
            .unwrap_or_else(|| format!("{r:?}"))
    }
}
