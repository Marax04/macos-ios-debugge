// Auto-generated extra ttd-recorder wire tools.
// Included from wire_tools.rs via `include!`.

pub struct TtdRecorderPositionNewTool;
impl TtdRecorderPositionNewTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "ttd_recorder_position_new".to_string(),
            description: "Construct a TtdPosition(major,minor).".to_string(),
            input_schema: json!({"type":"object","properties":{"major":{"type":"integer"},"minor":{"type":"integer"}},"required":["major","minor"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TtdRecorderPositionNewTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let major = args.get("major").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'major'".into()))?;
        let minor = args.get("minor").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'minor'".into()))?;
        let p = rustre_ttd_recorder::TtdPosition::new(major, minor);
        Ok(ToolResult::text(json!({"major":p.major,"minor":p.minor,"display":p.to_string(),"source":"rustre_ttd_recorder::TtdPosition::new"}).to_string()))
    }
}

pub struct TtdRecorderPositionIsBeforeTool;
impl TtdRecorderPositionIsBeforeTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "ttd_recorder_position_is_before".to_string(),
            description: "Check if position A comes strictly before B.".to_string(),
            input_schema: json!({"type":"object","properties":{"a_major":{"type":"integer"},"a_minor":{"type":"integer"},"b_major":{"type":"integer"},"b_minor":{"type":"integer"}},"required":["a_major","a_minor","b_major","b_minor"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TtdRecorderPositionIsBeforeTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let am = args.get("a_major").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'a_major'".into()))?;
        let an = args.get("a_minor").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'a_minor'".into()))?;
        let bm = args.get("b_major").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'b_major'".into()))?;
        let bn = args.get("b_minor").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'b_minor'".into()))?;
        let a = rustre_ttd_recorder::TtdPosition::new(am, an);
        let b = rustre_ttd_recorder::TtdPosition::new(bm, bn);
        Ok(ToolResult::text(json!({"a":a.to_string(),"b":b.to_string(),"is_before":a.is_before(&b),"source":"rustre_ttd_recorder::TtdPosition::is_before"}).to_string()))
    }
}

pub struct TtdRecorderPositionEarliestTool;
impl TtdRecorderPositionEarliestTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "ttd_recorder_position_earliest".to_string(),
            description: "Return earlier of two TtdPositions.".to_string(),
            input_schema: json!({"type":"object","properties":{"a_major":{"type":"integer"},"a_minor":{"type":"integer"},"b_major":{"type":"integer"},"b_minor":{"type":"integer"}},"required":["a_major","a_minor","b_major","b_minor"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TtdRecorderPositionEarliestTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let am = args.get("a_major").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'a_major'".into()))?;
        let an = args.get("a_minor").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'a_minor'".into()))?;
        let bm = args.get("b_major").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'b_major'".into()))?;
        let bn = args.get("b_minor").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'b_minor'".into()))?;
        let a = rustre_ttd_recorder::TtdPosition::new(am, an);
        let b = rustre_ttd_recorder::TtdPosition::new(bm, bn);
        let e = rustre_ttd_recorder::TtdPosition::earliest(&a, &b);
        Ok(ToolResult::text(json!({"earliest":e.to_string(),"major":e.major,"minor":e.minor,"source":"rustre_ttd_recorder::TtdPosition::earliest"}).to_string()))
    }
}

pub struct TtdRecorderConfigForPidTool;
impl TtdRecorderConfigForPidTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "ttd_recorder_config_for_pid".to_string(),
            description: "Build a default TtdRecordConfig for the given PID and validate it.".to_string(),
            input_schema: json!({"type":"object","properties":{"pid":{"type":"integer"},"output_dir":{"type":"string"}},"required":["pid","output_dir"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TtdRecorderConfigForPidTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let pid = args.get("pid").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'pid'".into()))? as u32;
        let output_dir = args.get("output_dir").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'output_dir'".into()))?;
        let cfg = rustre_ttd_recorder::TtdRecordConfig::for_pid(pid, output_dir);
        let v = cfg.validate();
        Ok(ToolResult::text(json!({"pid":pid,"output_dir":cfg.output_dir,"target":cfg.target_process.to_string(),"compression":cfg.compression.to_string(),"record_heap":cfg.record_heap,"valid":v.is_ok(),"error":v.err(),"source":"rustre_ttd_recorder::TtdRecordConfig::for_pid"}).to_string()))
    }
}

pub struct TtdRecorderFilterThreadAllowedTool;
impl TtdRecorderFilterThreadAllowedTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "ttd_recorder_filter_thread_allowed".to_string(),
            description: "Check whether a thread ID passes a TtdRecordFilter.".to_string(),
            input_schema: json!({"type":"object","properties":{"tid":{"type":"integer"},"include_threads":{"type":"array"},"exclude_threads":{"type":"array"}},"required":["tid"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TtdRecorderFilterThreadAllowedTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let tid = args.get("tid").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'tid'".into()))? as u32;
        let inc: Vec<u32> = args.get("include_threads").and_then(Value::as_array).map(|a| a.iter().filter_map(|x| x.as_u64().map(|n| n as u32)).collect()).unwrap_or_default();
        let exc: Vec<u32> = args.get("exclude_threads").and_then(Value::as_array).map(|a| a.iter().filter_map(|x| x.as_u64().map(|n| n as u32)).collect()).unwrap_or_default();
        let mut f = rustre_ttd_recorder::TtdRecordFilter::pass_all();
        f.include_threads = inc; f.exclude_threads = exc;
        Ok(ToolResult::text(json!({"tid":tid,"allowed":f.thread_allowed(tid),"source":"rustre_ttd_recorder::TtdRecordFilter::thread_allowed"}).to_string()))
    }
}

pub struct TtdRecorderFilterModuleAllowedTool;
impl TtdRecorderFilterModuleAllowedTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "ttd_recorder_filter_module_allowed".to_string(),
            description: "Check whether a module name passes a TtdRecordFilter.".to_string(),
            input_schema: json!({"type":"object","properties":{"name":{"type":"string"},"include_modules":{"type":"array"},"exclude_modules":{"type":"array"}},"required":["name"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TtdRecorderFilterModuleAllowedTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let name = args.get("name").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'name'".into()))?;
        let inc: Vec<String> = args.get("include_modules").and_then(Value::as_array).map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect()).unwrap_or_default();
        let exc: Vec<String> = args.get("exclude_modules").and_then(Value::as_array).map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect()).unwrap_or_default();
        let mut f = rustre_ttd_recorder::TtdRecordFilter::pass_all();
        f.include_modules = inc; f.exclude_modules = exc;
        Ok(ToolResult::text(json!({"name":name,"allowed":f.module_allowed(name),"source":"rustre_ttd_recorder::TtdRecordFilter::module_allowed"}).to_string()))
    }
}

pub struct TtdRecorderCompressionLevelDisplayTool;
impl TtdRecorderCompressionLevelDisplayTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "ttd_recorder_compression_level_display".to_string(),
            description: "List all CompressionLevel variants and their Display strings.".to_string(),
            input_schema: json!({"type":"object","properties":{}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TtdRecorderCompressionLevelDisplayTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        use rustre_ttd_recorder::CompressionLevel;
        let levels = vec![
            json!({"variant":"None","display":CompressionLevel::None.to_string()}),
            json!({"variant":"Fast","display":CompressionLevel::Fast.to_string()}),
            json!({"variant":"Default","display":CompressionLevel::Default.to_string()}),
            json!({"variant":"Best","display":CompressionLevel::Best.to_string()}),
        ];
        Ok(ToolResult::text(json!({"levels":levels,"source":"rustre_ttd_recorder::CompressionLevel::fmt"}).to_string()))
    }
}

pub struct TtdRecorderMetricsSummaryTool;
impl TtdRecorderMetricsSummaryTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "ttd_recorder_metrics_summary".to_string(),
            description: "Build a RecordingMetrics and return its summary.".to_string(),
            input_schema: json!({"type":"object","properties":{"events_recorded":{"type":"integer"},"file_size_bytes":{"type":"integer"},"elapsed_secs":{"type":"number"},"thread_count":{"type":"integer"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TtdRecorderMetricsSummaryTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let mut m = rustre_ttd_recorder::RecordingMetrics::default();
        m.events_recorded = args.get("events_recorded").and_then(Value::as_u64).unwrap_or(0);
        m.file_size_bytes = args.get("file_size_bytes").and_then(Value::as_u64).unwrap_or(0);
        m.elapsed_secs = args.get("elapsed_secs").and_then(Value::as_f64).unwrap_or(0.0);
        m.thread_count = args.get("thread_count").and_then(Value::as_u64).unwrap_or(0) as u32;
        Ok(ToolResult::text(json!({"summary":m.summary(),"display":m.to_string(),"source":"rustre_ttd_recorder::RecordingMetrics::summary"}).to_string()))
    }
}

pub struct TtdRecorderValidationIsPerfectTool;
impl TtdRecorderValidationIsPerfectTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "ttd_recorder_validation_is_perfect".to_string(),
            description: "Validate a TTD trace path and check ValidationResult::is_perfect.".to_string(),
            input_schema: json!({"type":"object","properties":{"path":{"type":"string"}},"required":["path"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TtdRecorderValidationIsPerfectTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let path = args.get("path").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'path'".into()))?;
        let vr = rustre_ttd_recorder::TtdTraceValidation::validate(path).map_err(|e| McpError::InternalError(format!("validate: {e}")))?;
        Ok(ToolResult::text(json!({"path":path,"is_valid":vr.is_valid,"is_perfect":vr.is_perfect(),"version":vr.version,"warnings":vr.warnings,"display":vr.to_string(),"source":"rustre_ttd_recorder::ValidationResult::is_perfect"}).to_string()))
    }
}

pub struct TtdRecorderScheduleShouldStopTool;
impl TtdRecorderScheduleShouldStopTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "ttd_recorder_schedule_should_stop".to_string(),
            description: "Evaluate a duration-bounded RecordingSchedule::should_stop.".to_string(),
            input_schema: json!({"type":"object","properties":{"max_secs":{"type":"integer"},"elapsed_secs":{"type":"integer"},"pos_major":{"type":"integer"},"pos_minor":{"type":"integer"}},"required":["max_secs","elapsed_secs"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TtdRecorderScheduleShouldStopTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let max = args.get("max_secs").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'max_secs'".into()))?;
        let el = args.get("elapsed_secs").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'elapsed_secs'".into()))?;
        let pm = args.get("pos_major").and_then(Value::as_u64).unwrap_or(0);
        let pn = args.get("pos_minor").and_then(Value::as_u64).unwrap_or(0);
        let sched = rustre_ttd_recorder::RecordingSchedule::for_duration(max);
        let pos = rustre_ttd_recorder::TtdPosition::new(pm, pn);
        let stop = sched.should_stop(pos, std::time::Duration::from_secs(el));
        Ok(ToolResult::text(json!({"max_secs":max,"elapsed_secs":el,"position":pos.to_string(),"should_stop":stop,"source":"rustre_ttd_recorder::RecordingSchedule::should_stop"}).to_string()))
    }
}

pub struct TtdRecorderEncryptorRoundtripTool;
impl TtdRecorderEncryptorRoundtripTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "ttd_recorder_encryptor_roundtrip".to_string(),
            description: "Encrypt then decrypt hex plaintext with a 32-byte hex key.".to_string(),
            input_schema: json!({"type":"object","properties":{"key_hex":{"type":"string"},"plaintext_hex":{"type":"string"}},"required":["key_hex","plaintext_hex"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TtdRecorderEncryptorRoundtripTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let key_hex = args.get("key_hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'key_hex'".into()))?;
        let pt_hex = args.get("plaintext_hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'plaintext_hex'".into()))?;
        // Decode key: if empty or wrong length, default to a 32-byte zero key.
        let raw_key = if key_hex.is_empty() {
            Vec::new()
        } else {
            // panic su lunghezza dispari prima di questa conversione.
            crate::hex_decode(key_hex)?
        };
        let key = if raw_key.len() == 32 { raw_key } else { vec![0u8; 32] };
        let pt = if pt_hex.is_empty() {
            Vec::new()
        } else {
            crate::hex_decode(pt_hex)?
        };
        let enc = rustre_ttd_recorder::TtdRecordEncryptor::new(key).map_err(|e| McpError::InternalError(format!("encryptor: {e}")))?;
        let ct = enc.encrypt(&pt).map_err(|e| McpError::InternalError(format!("encrypt: {e}")))?;
        let dec = enc.decrypt(&ct).map_err(|e| McpError::InternalError(format!("decrypt: {e}")))?;
        Ok(ToolResult::text(json!({"ciphertext_hex":hex_encode(&ct),"roundtrip_ok":dec==pt,"ciphertext_len":ct.len(),"source":"rustre_ttd_recorder::TtdRecordEncryptor::encrypt+decrypt"}).to_string()))
    }
}

pub struct TtdRecorderRingBufferOverflowTool;
impl TtdRecorderRingBufferOverflowTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "ttd_recorder_ring_buffer_overflow".to_string(),
            description: "Push N synthetic events into a RingBufferRecorder and inspect wrap-around behavior.".to_string(),
            input_schema: json!({"type":"object","properties":{"capacity":{"type":"integer"},"push_count":{"type":"integer"}},"required":["capacity","push_count"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TtdRecorderRingBufferOverflowTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let cap = args.get("capacity").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'capacity'".into()))? as usize;
        let n = args.get("push_count").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'push_count'".into()))?;
        let rb = rustre_ttd_recorder::RingBufferRecorder::new(cap);
        for i in 0..n {
            rb.push(rustre_ttd::TraceEvent {
                position: rustre_ttd::TracePosition::new(i, 0),
                thread_id: 1,
                kind: rustre_ttd::EventKind::MemRead { addr: 0x1000 + i, len: 8 },
            });
        }
        let len = rb.len();
        let empty = rb.is_empty();
        let snap_len = rb.snapshot().len();
        rb.clear();
        Ok(ToolResult::text(json!({"capacity":cap,"pushed":n,"len":len,"is_empty_before_clear":empty,"snapshot_len":snap_len,"len_after_clear":rb.len(),"source":"rustre_ttd_recorder::RingBufferRecorder"}).to_string()))
    }
}

pub fn register_ttd_recorder_extra_handlers(out: &mut Vec<(ToolDefinition, Box<dyn ToolHandler>)>) {
    out.push((TtdRecorderPositionNewTool::definition(), Box::new(TtdRecorderPositionNewTool)));
    out.push((TtdRecorderPositionIsBeforeTool::definition(), Box::new(TtdRecorderPositionIsBeforeTool)));
    out.push((TtdRecorderPositionEarliestTool::definition(), Box::new(TtdRecorderPositionEarliestTool)));
    out.push((TtdRecorderConfigForPidTool::definition(), Box::new(TtdRecorderConfigForPidTool)));
    out.push((TtdRecorderFilterThreadAllowedTool::definition(), Box::new(TtdRecorderFilterThreadAllowedTool)));
    out.push((TtdRecorderFilterModuleAllowedTool::definition(), Box::new(TtdRecorderFilterModuleAllowedTool)));
    out.push((TtdRecorderCompressionLevelDisplayTool::definition(), Box::new(TtdRecorderCompressionLevelDisplayTool)));
    out.push((TtdRecorderMetricsSummaryTool::definition(), Box::new(TtdRecorderMetricsSummaryTool)));
    out.push((TtdRecorderValidationIsPerfectTool::definition(), Box::new(TtdRecorderValidationIsPerfectTool)));
    out.push((TtdRecorderScheduleShouldStopTool::definition(), Box::new(TtdRecorderScheduleShouldStopTool)));
    out.push((TtdRecorderEncryptorRoundtripTool::definition(), Box::new(TtdRecorderEncryptorRoundtripTool)));
    out.push((TtdRecorderRingBufferOverflowTool::definition(), Box::new(TtdRecorderRingBufferOverflowTool)));
}
