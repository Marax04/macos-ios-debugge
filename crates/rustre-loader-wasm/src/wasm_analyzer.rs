// wasm_analyzer.rs — WebAssembly static analysis
// Call graph construction, reachability from exports, dead function detection,
// imported API categorization, string literal extraction, and complexity metrics.

use std::collections::{HashMap, HashSet, VecDeque};

// ---------------------------------------------------------------------------
// Input model (matches what wasm_binary_parser produces)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct AnalysisModule {
    pub import_funcs: Vec<ImportFunc>,
    pub defined_funcs: Vec<DefinedFunc>,
    pub exports: Vec<FuncExport>,
    pub data_segments: Vec<DataSeg>,
    pub start_func: Option<u32>,   // absolute function index
    pub total_mem_pages: u32,
}

#[derive(Debug, Clone)]
pub struct ImportFunc {
    pub module: String,
    pub name: String,
    pub func_index: u32,
}

#[derive(Debug, Clone)]
pub struct DefinedFunc {
    pub func_index: u32,           // absolute (import_funcs.len() + local offset)
    pub name: Option<String>,      // from Name section
    pub code: Vec<u8>,             // raw body bytes
    pub call_targets: Vec<u32>,    // direct call targets (func indices) extracted from bytecode
    pub indirect_call_count: u32,  // number of call_indirect sites
}

#[derive(Debug, Clone)]
pub struct FuncExport {
    pub name: String,
    pub func_index: u32,
}

#[derive(Debug, Clone)]
pub struct DataSeg {
    pub offset: Option<u32>,
    pub data: Vec<u8>,
}

// ---------------------------------------------------------------------------
// Fast call-target extractor operating on raw WASM body bytes
// ---------------------------------------------------------------------------

#[must_use] 
pub fn extract_call_targets(code: &[u8]) -> (Vec<u32>, u32) {
    let mut calls = Vec::new();
    let mut indirect_count = 0u32;
    let mut pos = 0usize;

    // Skip locals
    if pos >= code.len() { return (calls, indirect_count); }
    let (n_groups, adv) = read_leb_u32(&code[pos..]);
    pos += adv;
    for _ in 0..n_groups {
        if pos >= code.len() { break; }
        let (_, a) = read_leb_u32(&code[pos..]); pos += a;
        pos += 1; // valtype byte
    }

    while pos < code.len() {
        let op = code[pos]; pos += 1;
        match op {
            0x10 => {
                // call immediate
                let (idx, a) = read_leb_u32(&code[pos..]); pos += a;
                calls.push(idx);
            }
            0x11 => {
                // call_indirect
                let (_, a) = read_leb_u32(&code[pos..]); pos += a;
                let (_, b) = read_leb_u32(&code[pos..]); pos += b;
                indirect_count += 1;
            }
            // opcodes with no immediates
            0x00..=0x01 | 0x05 | 0x0B | 0x0F | 0x1A | 0x1B => {}
            // opcodes with one LEB
            0x02..=0x04 | 0x0C | 0x0D |
            0x20..=0x26 | 0x3F..=0x40 |
            0xD1 => { let (_, a) = read_leb_u32(&code[pos..]); pos += a; }
            // br_table: count + count labels + default
            0x0E => {
                let (cnt, a) = read_leb_u32(&code[pos..]); pos += a;
                for _ in 0..=cnt { let (_, a) = read_leb_u32(&code[pos..]); pos += a; }
            }
            // memory ops: two LEBs
            0x28..=0x3E => {
                let (_, a) = read_leb_u32(&code[pos..]); pos += a;
                let (_, b) = read_leb_u32(&code[pos..]); pos += b;
            }
            0x41 => { let (_, a) = read_leb_i32(&code[pos..]); pos += a; }
            0x42 => { let (_, a) = read_leb_i64(&code[pos..]); pos += a; }
            0x43 => { pos += 4; }
            0x44 => { pos += 8; }
            0xD0 => { pos += 1; } // ref.null + type byte
            0xD2 => { let (_, a) = read_leb_u32(&code[pos..]); pos += a; }
            0xFC => {
                let (sub, a) = read_leb_u32(&code[pos..]); pos += a;
                match sub {
                    8 | 12 | 14 => {
                        let (_, b) = read_leb_u32(&code[pos..]); pos += b;
                        let (_, c) = read_leb_u32(&code[pos..]); pos += c;
                    }
                    9 | 11 | 13 | 15..=17 => {
                        let (_, b) = read_leb_u32(&code[pos..]); pos += b;
                    }
                    _ => {}
                }
            }
            0xFD => {
                let (sub, a) = read_leb_u32(&code[pos..]); pos += a;
                match sub {
                    0..=11 | 84..=91 | 92..=93 => {
                        let (_, b) = read_leb_u32(&code[pos..]); pos += b;
                        let (_, c) = read_leb_u32(&code[pos..]); pos += c;
                        if (84..=91).contains(&sub) { pos += 1; } // lane
                    }
                    12 => { pos += 16; } // v128.const
                    13 => { pos += 16; } // shuffle
                    21..=34 => { pos += 1; } // lane immediates
                    _ => {}
                }
            }
            0xFE => {
                pos += 1; // sub-opcode byte
                let (_, a) = read_leb_u32(&code[pos..]); pos += a;
                let (_, b) = read_leb_u32(&code[pos..]); pos += b;
            }
            _ => {}
        }
    }
    (calls, indirect_count)
}

fn read_leb_u32(data: &[u8]) -> (u32, usize) {
    let mut result = 0u32;
    let mut shift = 0;
    for (i, &b) in data.iter().enumerate() {
        result |= u32::from(b & 0x7F) << shift;
        shift += 7;
        if b & 0x80 == 0 { return (result, i + 1); }
        if shift >= 35 { return (result, i + 1); }
    }
    (result, data.len())
}

fn read_leb_i32(data: &[u8]) -> (i32, usize) {
    let mut result = 0i32;
    let mut shift = 0i32;
    for (i, &b) in data.iter().enumerate() {
        result |= i32::from(b & 0x7F) << shift;
        shift += 7;
        if b & 0x80 == 0 {
            if shift < 32 && (b & 0x40) != 0 { result |= (-1i32) << shift; }
            return (result, i + 1);
        }
        if shift >= 35 { return (result, i + 1); }
    }
    (result, data.len())
}

fn read_leb_i64(data: &[u8]) -> (i64, usize) {
    let mut result = 0i64;
    let mut shift = 0i32;
    for (i, &b) in data.iter().enumerate() {
        result |= i64::from(b & 0x7F) << shift;
        shift += 7;
        if b & 0x80 == 0 {
            if shift < 64 && (b & 0x40) != 0 { result |= (-1i64) << shift; }
            return (result, i + 1);
        }
        if shift >= 63 { return (result, i + 1); }
    }
    (result, data.len())
}

// ---------------------------------------------------------------------------
// Call Graph
// ---------------------------------------------------------------------------

#[derive(Debug, Default)]
pub struct CallGraph {
    /// callee → set of callers
    pub callers: HashMap<u32, HashSet<u32>>,
    /// caller → set of callees
    pub callees: HashMap<u32, HashSet<u32>>,
    /// Functions with `call_indirect` sites
    pub indirect_callers: HashSet<u32>,
}

impl CallGraph {
    #[must_use] 
    pub fn build(module: &AnalysisModule) -> Self {
        let mut cg = Self::default();
        for f in &module.defined_funcs {
            let from = f.func_index;
            if f.indirect_call_count > 0 {
                cg.indirect_callers.insert(from);
            }
            for &to in &f.call_targets {
                cg.callees.entry(from).or_default().insert(to);
                cg.callers.entry(to).or_default().insert(from);
            }
        }
        cg
    }

    #[must_use] 
    pub fn callee_count(&self, func: u32) -> usize {
        self.callees.get(&func).map_or(0, std::collections::HashSet::len)
    }

    #[must_use] 
    pub fn caller_count(&self, func: u32) -> usize {
        self.callers.get(&func).map_or(0, std::collections::HashSet::len)
    }

    #[must_use] 
    pub fn all_funcs(&self) -> HashSet<u32> {
        let mut s = HashSet::new();
        for (&k, v) in &self.callees { s.insert(k); s.extend(v.iter().copied()); }
        s
    }

    /// Functions that call nothing and have no callers (isolated)
    #[must_use] 
    pub fn isolated_funcs(&self, module: &AnalysisModule) -> Vec<u32> {
        module.defined_funcs.iter().filter(|f| {
            self.callee_count(f.func_index) == 0 && self.caller_count(f.func_index) == 0
        }).map(|f| f.func_index).collect()
    }

    /// Detect simple direct recursion
    #[must_use] 
    pub fn recursive_funcs(&self) -> Vec<u32> {
        self.callees.iter().filter_map(|(&f, callees)| {
            if callees.contains(&f) { Some(f) } else { None }
        }).collect()
    }
}

// ---------------------------------------------------------------------------
// Reachability analysis
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub struct ReachabilityResult {
    pub reachable: HashSet<u32>,
    pub dead: HashSet<u32>,
    pub roots: Vec<u32>,
}

impl ReachabilityResult {
    #[must_use] 
    pub fn dead_count(&self) -> usize { self.dead.len() }
    #[must_use] 
    pub fn reachable_count(&self) -> usize { self.reachable.len() }
    #[must_use] 
    pub fn dead_ratio(&self) -> f64 {
        let total = self.dead.len() + self.reachable.len();
        if total == 0 { return 0.0; }
        self.dead.len() as f64 / total as f64
    }
}

#[must_use] 
pub fn compute_reachability(module: &AnalysisModule, cg: &CallGraph) -> ReachabilityResult {
    let mut roots = Vec::new();
    for exp in &module.exports { roots.push(exp.func_index); }
    if let Some(s) = module.start_func { roots.push(s); }

    let all_defined: HashSet<u32> = module.defined_funcs.iter().map(|f| f.func_index).collect();

    let mut reachable = HashSet::new();
    let mut queue = VecDeque::new();
    for &r in &roots { queue.push_back(r); reachable.insert(r); }

    while let Some(f) = queue.pop_front() {
        if let Some(callees) = cg.callees.get(&f) {
            for &callee in callees {
                if reachable.insert(callee) {
                    queue.push_back(callee);
                }
            }
        }
    }

    let dead = all_defined.difference(&reachable).copied().collect();
    ReachabilityResult { reachable, dead, roots }
}

// ---------------------------------------------------------------------------
// Import categorization
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ImportCategory {
    Wasi,
    EmscriptenEnv,
    EmscriptenAsi,
    Wasm4,
    Go,
    Rust,
    Custom(String),
}

impl ImportCategory {
    #[must_use] 
    pub const fn name(&self) -> &str {
        match self {
            Self::Wasi => "WASI",
            Self::EmscriptenEnv => "Emscripten (env)",
            Self::EmscriptenAsi => "Emscripten (asm)",
            Self::Wasm4 => "WASM-4",
            Self::Go => "Go",
            Self::Rust => "Rust",
            Self::Custom(s) => s.as_str(),
        }
    }

    #[must_use] 
    pub fn classify(module: &str, name: &str) -> Self {
        match module {
            "wasi_snapshot_preview1" | "wasi_unstable" => Self::Wasi,
            "env" => {
                if name.starts_with("emscripten_") || name.starts_with("_emscripten_")
                    || name == "memory" || name == "table" || name.starts_with("__memory_base")
                    || name.starts_with("__table_base") || name.starts_with("__stack_pointer") {
                    Self::EmscriptenEnv
                } else if name.starts_with("go.") || name == "runtime.wasmExit" {
                    Self::Go
                } else {
                    Self::Custom("env".to_string())
                }
            }
            "asm2wasm" => Self::EmscriptenAsi,
            "w4" => Self::Wasm4,
            "go" | "syscall/js" => Self::Go,
            "__wbindgen_placeholder__" | "wbindgen" => Self::Rust,
            other => Self::Custom(other.to_string()),
        }
    }
}

#[derive(Debug, Default)]
pub struct ImportAnalysis {
    pub by_category: HashMap<ImportCategory, Vec<u32>>,
    pub wasi_funcs: Vec<String>,
    pub emscripten_funcs: Vec<String>,
    pub unknown_funcs: Vec<(String, String, u32)>,
}

impl ImportAnalysis {
    #[must_use] 
    pub fn analyze(module: &AnalysisModule) -> Self {
        let mut ia = Self::default();
        for imp in &module.import_funcs {
            let cat = ImportCategory::classify(&imp.module, &imp.name);
            match &cat {
                ImportCategory::Wasi => ia.wasi_funcs.push(imp.name.clone()),
                ImportCategory::EmscriptenEnv | ImportCategory::EmscriptenAsi => {
                    ia.emscripten_funcs.push(imp.name.clone());
                }
                ImportCategory::Custom(_) => {
                    ia.unknown_funcs.push((imp.module.clone(), imp.name.clone(), imp.func_index));
                }
                _ => {}
            }
            ia.by_category.entry(cat).or_default().push(imp.func_index);
        }
        ia
    }

    #[must_use] 
    pub const fn is_wasi(&self) -> bool { !self.wasi_funcs.is_empty() }
    #[must_use] 
    pub const fn is_emscripten(&self) -> bool { !self.emscripten_funcs.is_empty() }
    #[must_use] 
    pub fn primary_abi(&self) -> &str {
        if self.is_wasi() { "WASI" }
        else if self.is_emscripten() { "Emscripten" }
        else if self.by_category.contains_key(&ImportCategory::Go) { "Go" }
        else if self.by_category.contains_key(&ImportCategory::Rust) { "Rust/wasm-bindgen" }
        else if self.by_category.contains_key(&ImportCategory::Wasm4) { "WASM-4 game" }
        else { "Unknown" }
    }
}

// ---------------------------------------------------------------------------
// String extraction from data segments
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct ExtractedString {
    pub offset: u32,        // byte offset within segment
    pub seg_index: usize,
    pub value: String,
    pub encoding: StringEncoding,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StringEncoding { Ascii, Utf8, WideLE }

#[must_use] 
pub fn extract_strings(module: &AnalysisModule, min_len: usize) -> Vec<ExtractedString> {
    let mut results = Vec::new();
    let min_len = min_len.max(4);

    for (seg_idx, seg) in module.data_segments.iter().enumerate() {
        let base_off = seg.offset.unwrap_or(0);
        // ASCII/UTF-8 scan
        let mut run_start = None;
        for (i, &b) in seg.data.iter().enumerate() {
            let printable = (0x20..0x7F).contains(&b) || b == b'\n' || b == b'\r' || b == b'\t';
            if printable {
                if run_start.is_none() { run_start = Some(i); }
            } else if let Some(start) = run_start.take() {
                let slice = &seg.data[start..i];
                if slice.len() >= min_len
                    && let Ok(s) = std::str::from_utf8(slice) {
                        results.push(ExtractedString {
                            offset: base_off + start as u32,
                            seg_index: seg_idx,
                            value: s.to_string(),
                            encoding: StringEncoding::Ascii,
                        });
                    }
            }
        }
        if let Some(start) = run_start {
            let slice = &seg.data[start..];
            if slice.len() >= min_len
                && let Ok(s) = std::str::from_utf8(slice) {
                    results.push(ExtractedString {
                        offset: base_off + start as u32,
                        seg_index: seg_idx,
                        value: s.to_string(),
                        encoding: StringEncoding::Ascii,
                    });
                }
        }

        // Wide LE scan (UTF-16LE: alternating ASCII + 0x00)
        let d = &seg.data;
        if d.len() >= (min_len * 2) {
            let mut wi = 0usize;
            while wi + 2 <= d.len() {
                let lo = d[wi];
                let hi = d[wi + 1];
                if (0x20..0x7F).contains(&lo) && hi == 0x00 {
                    let start = wi;
                    let mut chars = Vec::new();
                    while wi + 2 <= d.len() && d[wi] >= 0x20 && d[wi] < 0x7F && d[wi + 1] == 0x00 {
                        chars.push(d[wi] as char);
                        wi += 2;
                    }
                    if chars.len() >= min_len {
                        results.push(ExtractedString {
                            offset: base_off + start as u32,
                            seg_index: seg_idx,
                            value: chars.iter().collect(),
                            encoding: StringEncoding::WideLE,
                        });
                    }
                } else {
                    wi += 1;
                }
            }
        }
    }
    results
}

// ---------------------------------------------------------------------------
// Function complexity metrics
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct FuncMetrics {
    pub func_index: u32,
    pub code_bytes: usize,
    pub call_count: usize,
    pub indirect_call_count: u32,
    pub cyclomatic_complexity: u32,
    pub memory_ops: usize,
    pub branch_count: u32,
}

impl FuncMetrics {
    #[must_use] 
    pub fn compute(f: &DefinedFunc) -> Self {
        let mut branch_count = 0u32;
        let mut memory_ops = 0usize;
        let call_count = f.call_targets.len();

        // Quick scan for branch and memory opcodes
        let code = &f.code;
        let mut pos = 0usize;
        if !code.is_empty() {
            let (n, a) = read_leb_u32(code);
            pos += a;
            for _ in 0..n {
                if pos >= code.len() { break; }
                let (_, a2) = read_leb_u32(&code[pos..]); pos += a2;
                pos += 1;
            }
        }
        while pos < code.len() {
            let b = code[pos]; pos += 1;
            match b {
                0x02..=0x04 | 0x0C | 0x0D | 0x0E => { branch_count += 1; }
                0x28..=0x3E => { memory_ops += 1; }
                _ => {}
            }
        }
        // cyclomatic: branches + indirect calls + 1
        let cc = branch_count + f.indirect_call_count + 1;
        Self {
            func_index: f.func_index,
            code_bytes: f.code.len(),
            call_count,
            indirect_call_count: f.indirect_call_count,
            cyclomatic_complexity: cc,
            memory_ops,
            branch_count,
        }
    }
}

// ---------------------------------------------------------------------------
// Full analysis result
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub struct AnalysisResult {
    pub call_graph: CallGraph,
    pub reachability: ReachabilityResult,
    pub import_analysis: ImportAnalysis,
    pub strings: Vec<ExtractedString>,
    pub func_metrics: Vec<FuncMetrics>,
    pub suspicious_funcs: Vec<SuspiciousFunc>,
    pub summary: ModuleSummary,
}

#[derive(Debug, Clone)]
pub struct SuspiciousFunc {
    pub func_index: u32,
    pub reasons: Vec<String>,
    pub risk_score: u32,
}

#[derive(Debug, Default)]
pub struct ModuleSummary {
    pub total_funcs: u32,
    pub import_func_count: u32,
    pub defined_func_count: u32,
    pub exported_func_count: u32,
    pub dead_func_count: usize,
    pub dead_func_ratio: f64,
    pub total_code_bytes: usize,
    pub mean_code_bytes: f64,
    pub max_code_bytes: usize,
    pub max_complexity: u32,
    pub total_strings: usize,
    pub primary_abi: String,
    pub recursive_funcs: usize,
    pub indirect_call_sites: u32,
}

// ---------------------------------------------------------------------------
// Main analyzer
// ---------------------------------------------------------------------------

pub struct Analyzer;

impl Analyzer {
    pub fn analyze(module: &AnalysisModule) -> AnalysisResult {
        // Build call graph with extracted targets
        let mut module_with_targets = module.clone();
        for f in &mut module_with_targets.defined_funcs {
            if f.call_targets.is_empty() && !f.code.is_empty() {
                let (targets, indir) = extract_call_targets(&f.code);
                f.call_targets = targets;
                f.indirect_call_count = indir;
            }
        }

        let cg = CallGraph::build(&module_with_targets);
        let reachability = compute_reachability(&module_with_targets, &cg);
        let import_analysis = ImportAnalysis::analyze(&module_with_targets);
        let strings = extract_strings(&module_with_targets, 5);
        let func_metrics: Vec<_> = module_with_targets.defined_funcs.iter()
            .map(FuncMetrics::compute).collect();

        let suspicious_funcs = Self::detect_suspicious(&module_with_targets, &cg, &reachability, &func_metrics);
        let summary = Self::build_summary(&module_with_targets, &reachability, &func_metrics, &cg, &import_analysis, &strings);

        AnalysisResult {
            call_graph: cg,
            reachability,
            import_analysis,
            strings,
            func_metrics,
            suspicious_funcs,
            summary,
        }
    }

    fn detect_suspicious(
        module: &AnalysisModule,
        cg: &CallGraph,
        reach: &ReachabilityResult,
        metrics: &[FuncMetrics],
    ) -> Vec<SuspiciousFunc> {
        let mut out = Vec::new();
        let import_count = module.import_funcs.len() as u32;

        for m in metrics {
            let mut reasons = Vec::new();
            let mut score = 0u32;

            // Large function
            if m.code_bytes > 8192 {
                reasons.push(format!("large function ({} bytes)", m.code_bytes));
                score += 2;
            }

            // High cyclomatic complexity
            if m.cyclomatic_complexity > 20 {
                reasons.push(format!("high complexity ({})", m.cyclomatic_complexity));
                score += 3;
            }

            // Many indirect calls
            if m.indirect_call_count > 5 {
                reasons.push(format!("many call_indirect sites ({})", m.indirect_call_count));
                score += 2;
            }

            // Calls only imports (likely a thin shim or malicious wrapper)
            let callees = cg.callees.get(&m.func_index).cloned().unwrap_or_default();
            let all_imports = !callees.is_empty() && callees.iter().all(|&c| c < import_count);
            if all_imports && callees.len() > 3 {
                reasons.push(format!("calls {} imports only", callees.len()));
                score += 1;
            }

            // Dead but exports indirectly point to it
            if reach.dead.contains(&m.func_index) && cg.indirect_callers.contains(&m.func_index) {
                reasons.push("dead function referenced via call_indirect".to_string());
                score += 4;
            }

            // Many memory ops relative to size
            if m.code_bytes > 0 {
                let mem_density = m.memory_ops as f64 / m.code_bytes as f64;
                if mem_density > 0.15 {
                    reasons.push(format!("high memory operation density ({mem_density:.2})"));
                    score += 2;
                }
            }

            if !reasons.is_empty() {
                out.push(SuspiciousFunc {
                    func_index: m.func_index,
                    reasons,
                    risk_score: score,
                });
            }
        }

        out.sort_by(|a, b| b.risk_score.cmp(&a.risk_score));
        out
    }

    fn build_summary(
        module: &AnalysisModule,
        reach: &ReachabilityResult,
        metrics: &[FuncMetrics],
        cg: &CallGraph,
        ia: &ImportAnalysis,
        strings: &[ExtractedString],
    ) -> ModuleSummary {
        let total_code: usize = metrics.iter().map(|m| m.code_bytes).sum();
        let max_code = metrics.iter().map(|m| m.code_bytes).max().unwrap_or(0);
        let max_cc = metrics.iter().map(|m| m.cyclomatic_complexity).max().unwrap_or(0);
        let mean_code = if metrics.is_empty() { 0.0 } else { total_code as f64 / metrics.len() as f64 };
        let indirect: u32 = metrics.iter().map(|m| m.indirect_call_count).sum();

        ModuleSummary {
            total_funcs: module.import_funcs.len() as u32 + module.defined_funcs.len() as u32,
            import_func_count: module.import_funcs.len() as u32,
            defined_func_count: module.defined_funcs.len() as u32,
            exported_func_count: module.exports.len() as u32,
            dead_func_count: reach.dead_count(),
            dead_func_ratio: reach.dead_ratio(),
            total_code_bytes: total_code,
            mean_code_bytes: mean_code,
            max_code_bytes: max_code,
            max_complexity: max_cc,
            total_strings: strings.len(),
            primary_abi: ia.primary_abi().to_string(),
            recursive_funcs: cg.recursive_funcs().len(),
            indirect_call_sites: indirect,
        }
    }
}

// ---------------------------------------------------------------------------
// Textual report
// ---------------------------------------------------------------------------

#[must_use] 
pub fn generate_report(result: &AnalysisResult) -> String {
    let mut s = String::new();
    let sum = &result.summary;

    s.push_str("=== WASM Static Analysis Report ===\n\n");

    s.push_str("-- Module Summary --\n");
    s.push_str(&format!("  ABI/Runtime:       {}\n", sum.primary_abi));
    s.push_str(&format!("  Total functions:   {}\n", sum.total_funcs));
    s.push_str(&format!("  Imported:          {}\n", sum.import_func_count));
    s.push_str(&format!("  Defined:           {}\n", sum.defined_func_count));
    s.push_str(&format!("  Exported:          {}\n", sum.exported_func_count));
    s.push_str(&format!("  Dead functions:    {} ({:.1}%)\n",
        sum.dead_func_count, sum.dead_func_ratio * 100.0));
    s.push_str(&format!("  Total code bytes:  {}\n", sum.total_code_bytes));
    s.push_str(&format!("  Mean func size:    {:.1} bytes\n", sum.mean_code_bytes));
    s.push_str(&format!("  Max func size:     {} bytes\n", sum.max_code_bytes));
    s.push_str(&format!("  Max complexity:    {}\n", sum.max_complexity));
    s.push_str(&format!("  Indirect calls:    {}\n", sum.indirect_call_sites));
    s.push_str(&format!("  Recursive funcs:   {}\n", sum.recursive_funcs));
    s.push_str(&format!("  Extracted strings: {}\n", sum.total_strings));

    s.push_str("\n-- Import Categories --\n");
    for (cat, funcs) in &result.import_analysis.by_category {
        s.push_str(&format!("  {}: {} function(s)\n", cat.name(), funcs.len()));
    }

    if !result.import_analysis.wasi_funcs.is_empty() {
        s.push_str("\n-- WASI Imports --\n");
        for name in &result.import_analysis.wasi_funcs {
            s.push_str(&format!("  {name}\n"));
        }
    }

    if !result.reachability.dead.is_empty() {
        s.push_str("\n-- Dead Functions (sample, up to 20) --\n");
        let mut dead: Vec<u32> = result.reachability.dead.iter().copied().collect();
        dead.sort_unstable();
        for f in dead.iter().take(20) {
            s.push_str(&format!("  func {f}\n"));
        }
        if dead.len() > 20 {
            s.push_str(&format!("  ... and {} more\n", dead.len() - 20));
        }
    }

    if !result.suspicious_funcs.is_empty() {
        s.push_str("\n-- Suspicious Functions --\n");
        for sf in result.suspicious_funcs.iter().take(10) {
            s.push_str(&format!("  func {} (risk={}): {}\n",
                sf.func_index, sf.risk_score, sf.reasons.join("; ")));
        }
    }

    if !result.strings.is_empty() {
        s.push_str("\n-- Strings (sample, up to 30) --\n");
        for es in result.strings.iter().take(30) {
            let enc = match es.encoding {
                StringEncoding::Ascii => "ascii",
                StringEncoding::Utf8 => "utf8",
                StringEncoding::WideLE => "wide",
            };
            let preview: String = es.value.chars().take(80).collect();
            s.push_str(&format!("  [0x{:08x}] ({enc}) {:?}\n", es.offset, preview));
        }
        if result.strings.len() > 30 {
            s.push_str(&format!("  ... and {} more\n", result.strings.len() - 30));
        }
    }

    s
}

// ---------------------------------------------------------------------------
// Convenience builder for AnalysisModule from raw data
// ---------------------------------------------------------------------------

pub struct AnalysisModuleBuilder {
    m: AnalysisModule,
}

impl AnalysisModuleBuilder {
    #[must_use] 
    pub const fn new() -> Self {
        Self { m: AnalysisModule {
            import_funcs: Vec::new(),
            defined_funcs: Vec::new(),
            exports: Vec::new(),
            data_segments: Vec::new(),
            start_func: None,
            total_mem_pages: 0,
        }}
    }

    #[must_use] 
    pub fn import(mut self, module: &str, name: &str) -> Self {
        let idx = self.m.import_funcs.len() as u32;
        self.m.import_funcs.push(ImportFunc {
            module: module.to_string(),
            name: name.to_string(),
            func_index: idx,
        });
        self
    }

    #[must_use] 
    pub fn func(mut self, name: Option<&str>, code: Vec<u8>) -> Self {
        let base = self.m.import_funcs.len() as u32;
        let local = self.m.defined_funcs.len() as u32;
        let idx = base + local;
        let (targets, indirect) = extract_call_targets(&code);
        self.m.defined_funcs.push(DefinedFunc {
            func_index: idx,
            name: name.map(std::string::ToString::to_string),
            code,
            call_targets: targets,
            indirect_call_count: indirect,
        });
        self
    }

    #[must_use] 
    pub fn export(mut self, name: &str, func_index: u32) -> Self {
        self.m.exports.push(FuncExport { name: name.to_string(), func_index });
        self
    }

    #[must_use] 
    pub fn data(mut self, offset: Option<u32>, data: Vec<u8>) -> Self {
        self.m.data_segments.push(DataSeg { offset, data });
        self
    }

    #[must_use] 
    pub const fn start(mut self, idx: u32) -> Self { self.m.start_func = Some(idx); self }
    #[must_use] 
    pub const fn mem_pages(mut self, n: u32) -> Self { self.m.total_mem_pages = n; self }
    #[must_use] 
    pub fn build(self) -> AnalysisModule { self.m }
}

impl Default for AnalysisModuleBuilder {
    fn default() -> Self { Self::new() }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn simple_module() -> AnalysisModule {
        // func 0 = import
        // func 1 = defined: calls func 0
        // func 2 = defined: calls func 1 (reachable via export)
        // func 3 = defined: dead (no callers, no exports)
        let import_count = 1u32;
        let nop_body = vec![0x00u8, 0x0B]; // 0 locals, end
        // body that calls func 0
        let call_0 = vec![0x00u8, 0x10, 0x00, 0x0B]; // 0 locals, call 0, end
        // body that calls func 1
        let call_1 = vec![0x00u8, 0x10, 0x01, 0x0B];

        AnalysisModuleBuilder::new()
            .import("env", "external_fn")
            .func(Some("inner"), call_0.clone())
            .func(Some("exported_fn"), call_1.clone())
            .func(None, nop_body.clone()) // dead
            .export("exported_fn", import_count + 1)
            .data(Some(0x100), b"Hello, world! This is a test string.".to_vec())
            .build()
    }

    #[test]
    fn test_call_target_extraction() {
        let body = vec![0x00u8, 0x10, 0x05, 0x10, 0x0A, 0x0B];
        let (targets, indirect) = extract_call_targets(&body);
        assert_eq!(targets, vec![5, 10]);
        assert_eq!(indirect, 0);
    }

    #[test]
    fn test_call_graph() {
        let m = simple_module();
        let cg = CallGraph::build(&m);
        // func 1 (index 1) calls func 0
        assert!(cg.callees.get(&1).is_some_and(|s| s.contains(&0)));
    }

    #[test]
    fn test_reachability() {
        let m = simple_module();
        let cg = CallGraph::build(&m);
        let reach = compute_reachability(&m, &cg);
        // func 3 (index 3) should be dead
        assert!(reach.dead.contains(&3));
        // func 2 exported, should be reachable
        let export_idx = m.exports[0].func_index;
        assert!(reach.reachable.contains(&export_idx));
    }

    #[test]
    fn test_string_extraction() {
        let m = simple_module();
        let strings = extract_strings(&m, 4);
        assert!(!strings.is_empty());
        assert!(strings.iter().any(|s| s.value.contains("Hello")));
    }

    #[test]
    fn test_import_categorization() {
        let m = AnalysisModuleBuilder::new()
            .import("wasi_snapshot_preview1", "fd_write")
            .import("env", "emscripten_memcpy_js")
            .func(None, vec![0x00, 0x0B])
            .build();
        let ia = ImportAnalysis::analyze(&m);
        assert!(ia.is_wasi());
        assert_eq!(ia.primary_abi(), "WASI");
    }

    #[test]
    fn test_full_analysis() {
        let m = simple_module();
        let result = Analyzer::analyze(&m);
        assert_eq!(result.summary.import_func_count, 1);
        assert!(result.summary.dead_func_count > 0);
    }

    #[test]
    fn test_report_generation() {
        let m = simple_module();
        let result = Analyzer::analyze(&m);
        let report = generate_report(&result);
        assert!(report.contains("WASM Static Analysis Report"));
        assert!(report.contains("Dead Functions"));
    }
}
