//! MCP wrappers for the rustre-vsa crate.
//! Extracted from `wire_tools.rs` by `workflow_split_wire_tools`.

use rustre_mcp_server::{McpError, ToolDefinition, ToolHandler, ToolResult};
use serde_json::{json, Value};
use async_trait::async_trait;
use crate::wire_tools::{__vsa_si_from_args, __vsa_vals_arg};

pub struct VsaValueSetSingletonTool;

pub struct VsaStridedIntervalNewTool;

pub struct VsaValueSetIntervalWrapTool;
impl VsaValueSetIntervalWrapTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "rustre_vsa_valueset_interval".to_string(), description: "ValueSet::interval(lo,hi)".to_string(), input_schema: json!({"type":"object","properties":{"lo":{"type":"integer"},"hi":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for VsaValueSetIntervalWrapTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
    let lo = args.get("lo").and_then(Value::as_u64).unwrap_or(0);
    let hi = args.get("hi").and_then(Value::as_u64).unwrap_or(lo);
    let vs = rustre_analysis_vsa::ValueSet::interval(lo, hi);
    Ok(ToolResult::text(json!({"display": vs.to_string(), "is_top": vs.is_top(), "is_bottom": vs.is_bottom(), "source":"rustre_analysis_vsa::ValueSet::interval"}).to_string()))
} }

pub struct VsaValueSetStridedWrapTool;
impl VsaValueSetStridedWrapTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "rustre_vsa_valueset_strided".to_string(), description: "ValueSet::strided".to_string(), input_schema: json!({"type":"object","properties":{"lo":{"type":"integer"},"hi":{"type":"integer"},"stride":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for VsaValueSetStridedWrapTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
    let lo = args.get("lo").and_then(Value::as_u64).unwrap_or(0);
    let hi = args.get("hi").and_then(Value::as_u64).unwrap_or(lo);
    let stride = args.get("stride").and_then(Value::as_u64).unwrap_or(1);
    let vs = rustre_analysis_vsa::ValueSet::strided(lo, hi, stride);
    Ok(ToolResult::text(json!({"display": vs.to_string(), "source":"rustre_analysis_vsa::ValueSet::strided"}).to_string()))
} }

pub struct VsaValueSetAddWrapTool;
impl VsaValueSetAddWrapTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "rustre_vsa_valueset_add".to_string(), description: "ValueSet::add".to_string(), input_schema: json!({"type":"object","properties":{"a":{"type":"array"},"b":{"type":"array"}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for VsaValueSetAddWrapTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
    let a = rustre_analysis_vsa::ValueSet::Concrete(__vsa_vals_arg(&args, "a"));
    let b = rustre_analysis_vsa::ValueSet::Concrete(__vsa_vals_arg(&args, "b"));
    let r = a.add(&b);
    Ok(ToolResult::text(json!({"display": r.to_string(), "source":"rustre_analysis_vsa::ValueSet::add"}).to_string()))
} }

pub struct VsaValueSetSubWrapTool;
impl VsaValueSetSubWrapTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "rustre_vsa_valueset_sub".to_string(), description: "ValueSet::sub".to_string(), input_schema: json!({"type":"object","properties":{"a":{"type":"array"},"b":{"type":"array"}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for VsaValueSetSubWrapTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
    let a = rustre_analysis_vsa::ValueSet::Concrete(__vsa_vals_arg(&args, "a"));
    let b = rustre_analysis_vsa::ValueSet::Concrete(__vsa_vals_arg(&args, "b"));
    let r = a.sub(&b);
    Ok(ToolResult::text(json!({"display": r.to_string(), "source":"rustre_analysis_vsa::ValueSet::sub"}).to_string()))
} }

pub struct VsaValueSetBitwiseAndWrapTool;
impl VsaValueSetBitwiseAndWrapTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "rustre_vsa_valueset_bitwise_and".to_string(), description: "ValueSet::bitwise_and".to_string(), input_schema: json!({"type":"object","properties":{"a":{"type":"array"},"b":{"type":"array"}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for VsaValueSetBitwiseAndWrapTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
    let a = rustre_analysis_vsa::ValueSet::Concrete(__vsa_vals_arg(&args, "a"));
    let b = rustre_analysis_vsa::ValueSet::Concrete(__vsa_vals_arg(&args, "b"));
    let r = a.bitwise_and(&b);
    Ok(ToolResult::text(json!({"display": r.to_string(), "source":"rustre_analysis_vsa::ValueSet::bitwise_and"}).to_string()))
} }

pub struct VsaValueSetBitwiseOrWrapTool;
impl VsaValueSetBitwiseOrWrapTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "rustre_vsa_valueset_bitwise_or".to_string(), description: "ValueSet::bitwise_or".to_string(), input_schema: json!({"type":"object","properties":{"a":{"type":"array"},"b":{"type":"array"}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for VsaValueSetBitwiseOrWrapTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
    let a = rustre_analysis_vsa::ValueSet::Concrete(__vsa_vals_arg(&args, "a"));
    let b = rustre_analysis_vsa::ValueSet::Concrete(__vsa_vals_arg(&args, "b"));
    let r = a.bitwise_or(&b);
    Ok(ToolResult::text(json!({"display": r.to_string(), "source":"rustre_analysis_vsa::ValueSet::bitwise_or"}).to_string()))
} }

pub struct VsaValueSetContainsWrapTool;
impl VsaValueSetContainsWrapTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "rustre_vsa_valueset_contains".to_string(), description: "ValueSet::contains".to_string(), input_schema: json!({"type":"object","properties":{"vals":{"type":"array"},"v":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for VsaValueSetContainsWrapTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
    let vs = rustre_analysis_vsa::ValueSet::Concrete(__vsa_vals_arg(&args, "vals"));
    let v = args.get("v").and_then(Value::as_u64).unwrap_or(0);
    Ok(ToolResult::text(json!({"contains": vs.contains(v), "source":"rustre_analysis_vsa::ValueSet::contains"}).to_string()))
} }

pub struct VsaStridedIntervalSingletonWrapTool;
impl VsaStridedIntervalSingletonWrapTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "rustre_vsa_strided_interval_singleton".to_string(), description: "StridedInterval::singleton".to_string(), input_schema: json!({"type":"object","properties":{"v":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for VsaStridedIntervalSingletonWrapTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
    let v = args.get("v").and_then(Value::as_u64).unwrap_or(0);
    let si = rustre_analysis_vsa::StridedInterval::singleton(v);
    Ok(ToolResult::text(json!({"display": si.to_string(), "lo": si.lo, "hi": si.hi, "stride": si.stride, "is_singleton": si.is_singleton(), "source":"rustre_analysis_vsa::StridedInterval::singleton"}).to_string()))
} }

pub struct VsaStridedIntervalJoinWrapTool;
impl VsaStridedIntervalJoinWrapTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "rustre_vsa_strided_interval_join".to_string(), description: "StridedInterval::join".to_string(), input_schema: json!({"type":"object","properties":{"a_lo":{"type":"integer"},"a_hi":{"type":"integer"},"a_stride":{"type":"integer"},"b_lo":{"type":"integer"},"b_hi":{"type":"integer"},"b_stride":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for VsaStridedIntervalJoinWrapTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
    let a = __vsa_si_from_args(&args, "a_");
    let b = __vsa_si_from_args(&args, "b_");
    let r = a.join(&b);
    Ok(ToolResult::text(json!({"display": r.to_string(), "lo": r.lo, "hi": r.hi, "stride": r.stride, "source":"rustre_analysis_vsa::StridedInterval::join"}).to_string()))
} }

pub struct VsaStridedIntervalWidenWrapTool;
impl VsaStridedIntervalWidenWrapTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "rustre_vsa_strided_interval_widen".to_string(), description: "StridedInterval::widen".to_string(), input_schema: json!({"type":"object","properties":{"a_lo":{"type":"integer"},"a_hi":{"type":"integer"},"a_stride":{"type":"integer"},"b_lo":{"type":"integer"},"b_hi":{"type":"integer"},"b_stride":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for VsaStridedIntervalWidenWrapTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
    let old = __vsa_si_from_args(&args, "a_");
    let new_ = __vsa_si_from_args(&args, "b_");
    let r = old.widen(&new_);
    Ok(ToolResult::text(json!({"display": r.to_string(), "lo": r.lo, "hi": r.hi, "stride": r.stride, "is_top": r.is_top(), "source":"rustre_analysis_vsa::StridedInterval::widen"}).to_string()))
} }

pub struct VsaIsDefinitelyNullWrapTool;
impl VsaIsDefinitelyNullWrapTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "rustre_vsa_is_definitely_null".to_string(), description: "is_definitely_null".to_string(), input_schema: json!({"type":"object","properties":{"lo":{"type":"integer"},"hi":{"type":"integer"},"stride":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for VsaIsDefinitelyNullWrapTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
    let si = __vsa_si_from_args(&args, "");
    Ok(ToolResult::text(json!({"is_definitely_null": rustre_analysis_vsa::is_definitely_null(&si), "source":"rustre_analysis_vsa::is_definitely_null"}).to_string()))
} }

pub struct VsaMayBeOutOfBoundsWrapTool;
impl VsaMayBeOutOfBoundsWrapTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "rustre_vsa_may_be_out_of_bounds".to_string(), description: "may_be_out_of_bounds".to_string(), input_schema: json!({"type":"object","properties":{"lo":{"type":"integer"},"hi":{"type":"integer"},"stride":{"type":"integer"},"base":{"type":"integer"},"limit":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for VsaMayBeOutOfBoundsWrapTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
    let si = __vsa_si_from_args(&args, "");
    let base = args.get("base").and_then(Value::as_u64).unwrap_or(0);
    let limit = args.get("limit").and_then(Value::as_u64).unwrap_or(u64::MAX);
    Ok(ToolResult::text(json!({"may_be_out_of_bounds": rustre_analysis_vsa::may_be_out_of_bounds(&si, (base, limit)), "source":"rustre_analysis_vsa::may_be_out_of_bounds"}).to_string()))
} }

pub struct VsaValueSetTopTool;
impl VsaValueSetTopTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "vsa_valueset_top".to_string(), description: "Construct rustre_analysis_vsa::ValueSet::top().".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for VsaValueSetTopTool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { let vs = rustre_analysis_vsa::ValueSet::top(); Ok(ToolResult::text(json!({"display":format!("{}",vs),"is_top":vs.is_top(),"is_bottom":vs.is_bottom(),"source":"rustre_analysis_vsa::ValueSet::top"}).to_string())) } }

pub struct VsaValueSetBottomTool;
impl VsaValueSetBottomTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "vsa_valueset_bottom".to_string(), description: "Construct rustre_analysis_vsa::ValueSet::bottom().".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for VsaValueSetBottomTool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { let vs = rustre_analysis_vsa::ValueSet::bottom(); Ok(ToolResult::text(json!({"display":format!("{}",vs),"is_top":vs.is_top(),"is_bottom":vs.is_bottom(),"source":"rustre_analysis_vsa::ValueSet::bottom"}).to_string())) } }

pub struct VsaValueSetIntervalWireTool;
impl VsaValueSetIntervalWireTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "vsa_valueset_interval_wire".to_string(), description: "Construct rustre_analysis_vsa::ValueSet::interval(lo,hi).".to_string(), input_schema: json!({"type":"object","required":["lo","hi"],"properties":{"lo":{"type":"integer","minimum":0},"hi":{"type":"integer","minimum":0}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for VsaValueSetIntervalWireTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let lo = args.get("lo").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'lo'".into()))?; let hi = args.get("hi").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'hi'".into()))?; if lo > hi { return Err(McpError::InvalidParams("lo > hi".into())); } let vs = rustre_analysis_vsa::ValueSet::interval(lo, hi); Ok(ToolResult::text(json!({"display":format!("{}",vs),"is_top":vs.is_top(),"is_bottom":vs.is_bottom(),"contains_lo":vs.contains(lo),"source":"rustre_analysis_vsa::ValueSet::interval"}).to_string())) } }

pub struct VsaValueSetJoinIntervalsWireTool;
impl VsaValueSetJoinIntervalsWireTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "vsa_valueset_join_intervals_wire".to_string(), description: "Join two rustre_analysis_vsa::ValueSet intervals.".to_string(), input_schema: json!({"type":"object","required":["a_lo","a_hi","b_lo","b_hi"],"properties":{"a_lo":{"type":"integer","minimum":0},"a_hi":{"type":"integer","minimum":0},"b_lo":{"type":"integer","minimum":0},"b_hi":{"type":"integer","minimum":0}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for VsaValueSetJoinIntervalsWireTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let a_lo = args.get("a_lo").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'a_lo'".into()))?; let a_hi = args.get("a_hi").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'a_hi'".into()))?; let b_lo = args.get("b_lo").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'b_lo'".into()))?; let b_hi = args.get("b_hi").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'b_hi'".into()))?; if a_lo > a_hi || b_lo > b_hi { return Err(McpError::InvalidParams("lo > hi".into())); } let a = rustre_analysis_vsa::ValueSet::interval(a_lo, a_hi); let b = rustre_analysis_vsa::ValueSet::interval(b_lo, b_hi); let j = a.join(&b); Ok(ToolResult::text(json!({"display":format!("{}",j),"source":"rustre_analysis_vsa::ValueSet::join"}).to_string())) } }

pub struct VsaValueSetWidenIntervalsWireTool;
impl VsaValueSetWidenIntervalsWireTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "vsa_valueset_widen_intervals_wire".to_string(), description: "Widen a rustre_analysis_vsa::ValueSet interval toward another.".to_string(), input_schema: json!({"type":"object","required":["a_lo","a_hi","b_lo","b_hi"],"properties":{"a_lo":{"type":"integer","minimum":0},"a_hi":{"type":"integer","minimum":0},"b_lo":{"type":"integer","minimum":0},"b_hi":{"type":"integer","minimum":0}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for VsaValueSetWidenIntervalsWireTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let a_lo = args.get("a_lo").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'a_lo'".into()))?; let a_hi = args.get("a_hi").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'a_hi'".into()))?; let b_lo = args.get("b_lo").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'b_lo'".into()))?; let b_hi = args.get("b_hi").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'b_hi'".into()))?; if a_lo > a_hi || b_lo > b_hi { return Err(McpError::InvalidParams("lo > hi".into())); } let a = rustre_analysis_vsa::ValueSet::interval(a_lo, a_hi); let b = rustre_analysis_vsa::ValueSet::interval(b_lo, b_hi); let w = a.widen(&b); Ok(ToolResult::text(json!({"display":format!("{}",w),"is_top":w.is_top(),"source":"rustre_analysis_vsa::ValueSet::widen"}).to_string())) } }

pub struct VsaValueSetConcretizeStridedWireTool;
impl VsaValueSetConcretizeStridedWireTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "vsa_valueset_concretize_strided_wire".to_string(), description: "Concretize a rustre_analysis_vsa::ValueSet::strided up to a limit.".to_string(), input_schema: json!({"type":"object","required":["lo","hi","stride","limit"],"properties":{"lo":{"type":"integer","minimum":0},"hi":{"type":"integer","minimum":0},"stride":{"type":"integer","minimum":1},"limit":{"type":"integer","minimum":1}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for VsaValueSetConcretizeStridedWireTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let lo = args.get("lo").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'lo'".into()))?; let hi = args.get("hi").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'hi'".into()))?; let stride = args.get("stride").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'stride'".into()))?; let limit = args.get("limit").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'limit'".into()))? as usize; if lo > hi { return Err(McpError::InvalidParams("lo > hi".into())); } let vs = rustre_analysis_vsa::ValueSet::strided(lo, hi, stride); let vals = vs.concretize(limit); Ok(ToolResult::text(json!({"display":format!("{}",vs),"values":vals,"enumerated":vals.is_some(),"source":"rustre_analysis_vsa::ValueSet::concretize"}).to_string())) } }

pub struct VsaStridedIntervalJoinWireTool;
impl VsaStridedIntervalJoinWireTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "vsa_strided_interval_join_wire".to_string(), description: "Join two rustre_analysis_vsa::StridedInterval values.".to_string(), input_schema: json!({"type":"object","required":["a_lo","a_hi","a_stride","b_lo","b_hi","b_stride"],"properties":{"a_lo":{"type":"integer","minimum":0},"a_hi":{"type":"integer","minimum":0},"a_stride":{"type":"integer","minimum":1},"b_lo":{"type":"integer","minimum":0},"b_hi":{"type":"integer","minimum":0},"b_stride":{"type":"integer","minimum":1}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for VsaStridedIntervalJoinWireTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let a_lo = args.get("a_lo").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'a_lo'".into()))?; let a_hi = args.get("a_hi").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'a_hi'".into()))?; let a_stride = args.get("a_stride").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'a_stride'".into()))?; let b_lo = args.get("b_lo").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'b_lo'".into()))?; let b_hi = args.get("b_hi").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'b_hi'".into()))?; let b_stride = args.get("b_stride").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'b_stride'".into()))?; if a_lo > a_hi || b_lo > b_hi { return Err(McpError::InvalidParams("lo > hi".into())); } let a = rustre_analysis_vsa::StridedInterval::new(a_lo, a_hi, a_stride); let b = rustre_analysis_vsa::StridedInterval::new(b_lo, b_hi, b_stride); let j = a.join(&b); Ok(ToolResult::text(json!({"lo":j.lo,"hi":j.hi,"stride":j.stride,"display":format!("{}",j),"source":"rustre_analysis_vsa::StridedInterval::join"}).to_string())) } }

pub struct VsaStridedIntervalAddWireTool;
impl VsaStridedIntervalAddWireTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "vsa_strided_interval_add_wire".to_string(), description: "Add two rustre_analysis_vsa::StridedInterval values.".to_string(), input_schema: json!({"type":"object","required":["a_lo","a_hi","a_stride","b_lo","b_hi","b_stride"],"properties":{"a_lo":{"type":"integer","minimum":0},"a_hi":{"type":"integer","minimum":0},"a_stride":{"type":"integer","minimum":1},"b_lo":{"type":"integer","minimum":0},"b_hi":{"type":"integer","minimum":0},"b_stride":{"type":"integer","minimum":1}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for VsaStridedIntervalAddWireTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let a_lo = args.get("a_lo").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'a_lo'".into()))?; let a_hi = args.get("a_hi").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'a_hi'".into()))?; let a_stride = args.get("a_stride").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'a_stride'".into()))?; let b_lo = args.get("b_lo").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'b_lo'".into()))?; let b_hi = args.get("b_hi").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'b_hi'".into()))?; let b_stride = args.get("b_stride").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'b_stride'".into()))?; if a_lo > a_hi || b_lo > b_hi { return Err(McpError::InvalidParams("lo > hi".into())); } let a = rustre_analysis_vsa::StridedInterval::new(a_lo, a_hi, a_stride); let b = rustre_analysis_vsa::StridedInterval::new(b_lo, b_hi, b_stride); let r = a.add(&b); Ok(ToolResult::text(json!({"lo":r.lo,"hi":r.hi,"stride":r.stride,"display":format!("{}",r),"is_top":r.is_top(),"source":"rustre_analysis_vsa::StridedInterval::add"}).to_string())) } }

pub struct VsaIsDefinitelyNullWireTool;
impl VsaIsDefinitelyNullWireTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "vsa_is_definitely_null_wire".to_string(), description: "Return rustre_analysis_vsa::is_definitely_null on singleton(v).".to_string(), input_schema: json!({"type":"object","required":["value"],"properties":{"value":{"type":"integer","minimum":0}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for VsaIsDefinitelyNullWireTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let value = args.get("value").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'value'".into()))?; let si = rustre_analysis_vsa::StridedInterval::singleton(value); let is_null = rustre_analysis_vsa::is_definitely_null(&si); Ok(ToolResult::text(json!({"value":value,"is_definitely_null":is_null,"source":"rustre_analysis_vsa::is_definitely_null"}).to_string())) } }

pub struct VsaMayBeOutOfBoundsWireTool;
impl VsaMayBeOutOfBoundsWireTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "vsa_may_be_out_of_bounds_wire".to_string(), description: "Return rustre_analysis_vsa::may_be_out_of_bounds for a StridedInterval.".to_string(), input_schema: json!({"type":"object","required":["lo","hi","stride","base","limit"],"properties":{"lo":{"type":"integer","minimum":0},"hi":{"type":"integer","minimum":0},"stride":{"type":"integer","minimum":1},"base":{"type":"integer","minimum":0},"limit":{"type":"integer","minimum":0}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for VsaMayBeOutOfBoundsWireTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let lo = args.get("lo").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'lo'".into()))?; let hi = args.get("hi").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'hi'".into()))?; let stride = args.get("stride").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'stride'".into()))?; let base = args.get("base").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'base'".into()))?; let limit = args.get("limit").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'limit'".into()))?; if lo > hi { return Err(McpError::InvalidParams("lo > hi".into())); } let si = rustre_analysis_vsa::StridedInterval::new(lo, hi, stride); let oob = rustre_analysis_vsa::may_be_out_of_bounds(&si, (base, limit)); Ok(ToolResult::text(json!({"display":format!("{}",si),"may_be_out_of_bounds":oob,"source":"rustre_analysis_vsa::may_be_out_of_bounds"}).to_string())) } }

#[must_use]
pub fn handlers() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    vec![
        (VsaValueSetSingletonTool::definition(), Box::new(VsaValueSetSingletonTool)),
        (VsaStridedIntervalNewTool::definition(), Box::new(VsaStridedIntervalNewTool)),
        (VsaValueSetIntervalWrapTool::definition(), Box::new(VsaValueSetIntervalWrapTool)),
        (VsaValueSetStridedWrapTool::definition(), Box::new(VsaValueSetStridedWrapTool)),
        (VsaValueSetAddWrapTool::definition(), Box::new(VsaValueSetAddWrapTool)),
        (VsaValueSetSubWrapTool::definition(), Box::new(VsaValueSetSubWrapTool)),
        (VsaValueSetBitwiseAndWrapTool::definition(), Box::new(VsaValueSetBitwiseAndWrapTool)),
        (VsaValueSetBitwiseOrWrapTool::definition(), Box::new(VsaValueSetBitwiseOrWrapTool)),
        (VsaValueSetContainsWrapTool::definition(), Box::new(VsaValueSetContainsWrapTool)),
        (VsaStridedIntervalSingletonWrapTool::definition(), Box::new(VsaStridedIntervalSingletonWrapTool)),
        (VsaStridedIntervalJoinWrapTool::definition(), Box::new(VsaStridedIntervalJoinWrapTool)),
        (VsaStridedIntervalWidenWrapTool::definition(), Box::new(VsaStridedIntervalWidenWrapTool)),
        (VsaIsDefinitelyNullWrapTool::definition(), Box::new(VsaIsDefinitelyNullWrapTool)),
        (VsaMayBeOutOfBoundsWrapTool::definition(), Box::new(VsaMayBeOutOfBoundsWrapTool)),
        (VsaValueSetTopTool::definition(), Box::new(VsaValueSetTopTool)),
        (VsaValueSetBottomTool::definition(), Box::new(VsaValueSetBottomTool)),
        (VsaValueSetIntervalWireTool::definition(), Box::new(VsaValueSetIntervalWireTool)),
        (VsaValueSetJoinIntervalsWireTool::definition(), Box::new(VsaValueSetJoinIntervalsWireTool)),
        (VsaValueSetWidenIntervalsWireTool::definition(), Box::new(VsaValueSetWidenIntervalsWireTool)),
        (VsaValueSetConcretizeStridedWireTool::definition(), Box::new(VsaValueSetConcretizeStridedWireTool)),
        (VsaStridedIntervalJoinWireTool::definition(), Box::new(VsaStridedIntervalJoinWireTool)),
        (VsaStridedIntervalAddWireTool::definition(), Box::new(VsaStridedIntervalAddWireTool)),
        (VsaIsDefinitelyNullWireTool::definition(), Box::new(VsaIsDefinitelyNullWireTool)),
        (VsaMayBeOutOfBoundsWireTool::definition(), Box::new(VsaMayBeOutOfBoundsWireTool)),
    ]
}
