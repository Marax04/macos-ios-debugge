//! MCP wrappers for the rustre-decompiler crate.
//! Extracted from `wire_tools.rs` by `workflow_split_wire_tools`.

use rustre_mcp_server::{McpError, ToolDefinition, ToolHandler, ToolResult};
use serde_json::{json, Value};
use async_trait::async_trait;

pub struct DecompilerCoreBatchDecompileTool;

pub struct DecompilerCfsIdentifierTokensTool;
impl DecompilerCfsIdentifierTokensTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "decompiler_cfs_identifier_tokens".to_string(),
            description: "Tokenize a string into identifier-like tokens using \
                          rustre_decompiler_cfs::identifier_tokens."
                .to_string(),
            input_schema: json!({
                "type": "object",
                "properties": { "text": { "type": "string" } },
                "required": ["text"]
            }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for DecompilerCfsIdentifierTokensTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let text = args.get("text").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'text'".into()))?;
        let tokens = rustre_decompiler_cfs::identifier_tokens(text);
        Ok(ToolResult::text(json!({
            "count": tokens.len(),
            "tokens": tokens,
            "source": "rustre_decompiler_cfs::identifier_tokens",
        }).to_string()))
    }
}

pub struct DecompilerCfsBranchConditionTool;
impl DecompilerCfsBranchConditionTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "decompiler_cfs_branch_condition".to_string(),
            description: "Return the branch condition string of a basic block, if the block \
                          ends in a Branch statement. Input: { id, stmts: [str|{Branch|Raw|Return}] }."
                .to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "id": { "type": "integer" },
                    "stmts": { "type": "array" }
                }
            }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for DecompilerCfsBranchConditionTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        use rustre_decompiler_cfs::{BasicBlock, BlockId, Statement};
        let id = u32::try_from(args.get("id").and_then(Value::as_u64).unwrap_or(0)).unwrap_or(0);
        let mut stmts: Vec<Statement> = Vec::new();
        if let Some(arr) = args.get("stmts").and_then(Value::as_array) {
            for item in arr {
                if let Some(s) = item.as_str() {
                    stmts.push(Statement::Raw(s.to_string()));
                } else if let Some(obj) = item.as_object() {
                    if let Some(b) = obj.get("Branch").and_then(Value::as_str) {
                        stmts.push(Statement::Branch(b.to_string()));
                    } else if let Some(r) = obj.get("Raw").and_then(Value::as_str) {
                        stmts.push(Statement::Raw(r.to_string()));
                    } else if let Some(r) = obj.get("Return") {
                        stmts.push(Statement::Return(r.as_str().map(str::to_string)));
                    }
                }
            }
        }
        let bb = BasicBlock::new(BlockId::new(id)).with_stmts(stmts);
        let cond = rustre_decompiler_cfs::branch_condition(&bb);
        Ok(ToolResult::text(json!({
            "condition": cond,
            "source": "rustre_decompiler_cfs::branch_condition",
        }).to_string()))
    }
}

pub struct DecompilerCfsSccGroupsTool;
impl DecompilerCfsSccGroupsTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "decompiler_cfs_scc_groups".to_string(),
            description: "Structure a CFG via rustre_decompiler_cfs::ControlFlowStructurer and \
                          return loop_count (natural-loop / SCC cardinality). \
                          Input: { blocks: [{ id, successors: [u32] }], entry }."
                .to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "blocks": { "type": "array" },
                    "entry": { "type": "integer" }
                },
                "required": ["blocks"]
            }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for DecompilerCfsSccGroupsTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        use rustre_decompiler_cfs::{BasicBlock, BlockId, ControlFlowStructurer, Statement};
        let mut blocks: Vec<BasicBlock> = Vec::new();
        if let Some(arr) = args.get("blocks").and_then(Value::as_array) {
            for item in arr {
                let id = u32::try_from(item.get("id").and_then(Value::as_u64).unwrap_or(0)).unwrap_or(0);
                let succs: Vec<BlockId> = item
                    .get("successors")
                    .and_then(Value::as_array)
                    .map(|a| {
                        a.iter()
                            .filter_map(|v| v.as_u64().and_then(|n| u32::try_from(n).ok()).map(BlockId::new))
                            .collect()
                    })
                    .unwrap_or_default();
                let stmts: Vec<Statement> = if succs.is_empty() {
                    vec![Statement::Return(None)]
                } else if succs.len() >= 2 {
                    vec![Statement::Branch("c".to_string())]
                } else {
                    vec![]
                };
                blocks.push(BasicBlock::new(BlockId::new(id))
                    .with_stmts(stmts)
                    .with_successors(succs));
            }
        }
        if blocks.is_empty() {
            return Err(McpError::InvalidParams("blocks must be non-empty".into()));
        }
        let entry = args.get("entry").and_then(Value::as_u64)
            .and_then(|n| u32::try_from(n).ok())
            .map_or(blocks[0].id, BlockId::new);
        let ast = ControlFlowStructurer::new(blocks)
            .structure(entry)
            .map_err(|e| McpError::InternalError(format!("structure error: {e}")))?;
        Ok(ToolResult::text(json!({
            "loop_count": ast.loop_count,
            "goto_count": ast.goto_count,
            "source": "rustre_decompiler_cfs::ControlFlowStructurer::structure (analogue of scc_groups)",
        }).to_string()))
    }
}

pub struct DecompilerCVersionTool;
impl DecompilerCVersionTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "decompiler_c_version".to_string(),
            description: "Return the version string of the rustre-decompiler-c crate.".to_string(),
            input_schema: json!({ "type": "object", "properties": {} }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for DecompilerCVersionTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        Ok(ToolResult::text(json!({
            "version": rustre_decompiler_c::decompiler_c_version(),
            "source": "rustre_decompiler_c::decompiler_c_version",
        }).to_string()))
    }
}

pub struct DecompilerCSupportedLanguagesTool;
impl DecompilerCSupportedLanguagesTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "decompiler_c_supported_languages".to_string(),
            description: "List languages supported by rustre-decompiler-c output.".to_string(),
            input_schema: json!({ "type": "object", "properties": {} }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for DecompilerCSupportedLanguagesTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        Ok(ToolResult::text(json!({
            "languages": rustre_decompiler_c::supported_languages(),
            "source": "rustre_decompiler_c::supported_languages",
        }).to_string()))
    }
}

pub struct DecompilerCMaxDepthTool;
impl DecompilerCMaxDepthTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "decompiler_c_max_decompile_depth".to_string(),
            description: "Return the maximum decompile nesting depth used by rustre-decompiler-c.".to_string(),
            input_schema: json!({ "type": "object", "properties": {} }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for DecompilerCMaxDepthTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        Ok(ToolResult::text(json!({
            "max_decompile_depth": rustre_decompiler_c::max_decompile_depth(),
            "source": "rustre_decompiler_c::max_decompile_depth",
        }).to_string()))
    }
}

pub struct DecompilerLoadBinaryInfoTool;

pub struct DecompilerDetectFunctionsTool;

pub struct DecompilerDisassembleFunctionX86Tool;

pub struct DecompilerArchFromStrTool;

pub struct DecompilerOsFromPeFlagTool;

pub struct DecompilerCBraceStyleDefaultTool;

pub struct DecompilerCIndentMakeTool;

pub struct DecompilerCfsBlockIdDisplayTool;

pub struct DecompilerCfsAlgorithmDisplayTool;

pub struct DecompilerExprIntWidthBitsTool;

pub struct DecompilerExprIntWidthBytesTool;

pub struct DecompilerCacheInsertGetDcx1Tool;
impl DecompilerCacheInsertGetDcx1Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "decomp_cache_insert_get_dcx1".to_string(), description: "DecompilerCache insert+get+hit/miss+hit_rate via rustre_decompiler::DecompilerCache.".to_string(), input_schema: json!({"type":"object","properties":{"addr":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for DecompilerCacheInsertGetDcx1Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let addr = args.get("addr").and_then(Value::as_u64).unwrap_or(0x1000); let mut c = rustre_decompiler::DecompilerCache::new(4); let f = rustre_decompiler::DecompiledFunction::new(addr, "sub_x", "return 0;\n"); c.insert(f); let hit = c.get(addr).is_some(); let miss = c.get(addr.wrapping_add(1)).is_some(); Ok(ToolResult::text(json!({"len":c.len(),"is_empty":c.is_empty(),"hit":hit,"miss_lookup":miss,"hit_count":c.hit_count(),"miss_count":c.miss_count(),"hit_rate":c.hit_rate(),"source":"rustre_decompiler::DecompilerCache"}).to_string())) } }

pub fn handlers() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    vec![
        (DecompilerCoreBatchDecompileTool::definition(), Box::new(DecompilerCoreBatchDecompileTool)),
        (DecompilerCfsIdentifierTokensTool::definition(), Box::new(DecompilerCfsIdentifierTokensTool)),
        (DecompilerCfsBranchConditionTool::definition(), Box::new(DecompilerCfsBranchConditionTool)),
        (DecompilerCfsSccGroupsTool::definition(), Box::new(DecompilerCfsSccGroupsTool)),
        (DecompilerCVersionTool::definition(), Box::new(DecompilerCVersionTool)),
        (DecompilerCSupportedLanguagesTool::definition(), Box::new(DecompilerCSupportedLanguagesTool)),
        (DecompilerCMaxDepthTool::definition(), Box::new(DecompilerCMaxDepthTool)),
        (DecompilerLoadBinaryInfoTool::definition(), Box::new(DecompilerLoadBinaryInfoTool)),
        (DecompilerDetectFunctionsTool::definition(), Box::new(DecompilerDetectFunctionsTool)),
        (DecompilerDisassembleFunctionX86Tool::definition(), Box::new(DecompilerDisassembleFunctionX86Tool)),
        (DecompilerArchFromStrTool::definition(), Box::new(DecompilerArchFromStrTool)),
        (DecompilerOsFromPeFlagTool::definition(), Box::new(DecompilerOsFromPeFlagTool)),
        (DecompilerCBraceStyleDefaultTool::definition(), Box::new(DecompilerCBraceStyleDefaultTool)),
        (DecompilerCIndentMakeTool::definition(), Box::new(DecompilerCIndentMakeTool)),
        (DecompilerCfsBlockIdDisplayTool::definition(), Box::new(DecompilerCfsBlockIdDisplayTool)),
        (DecompilerCfsAlgorithmDisplayTool::definition(), Box::new(DecompilerCfsAlgorithmDisplayTool)),
        (DecompilerExprIntWidthBitsTool::definition(), Box::new(DecompilerExprIntWidthBitsTool)),
        (DecompilerExprIntWidthBytesTool::definition(), Box::new(DecompilerExprIntWidthBytesTool)),
        (DecompilerCacheInsertGetDcx1Tool::definition(), Box::new(DecompilerCacheInsertGetDcx1Tool)),
    ]
}
