//! `c_quality` — quality metrics for decompiled C pseudocode.
//!
//! Computes a set of scores and measurements that quantify how readable and
//! correct the decompiled output is:
//!
//! * **Complexity score**: cyclomatic complexity of the function.
//! * **Readability score**: 0–100 based on variable naming, line length,
//!   nesting depth, comment density, and goto frequency.
//! * **Naming quality**: ratio of non-auto-generated names to total names.
//! * **Structure score**: how well-structured the control flow is
//!   (gotos penalised, for/while preferred over naked gotos).
//! * **Type quality**: ratio of typed variables to total variables.

use serde::{Deserialize, Serialize};

// ─────────────────────────────────────────────────────────────────────────────
// QualityReport
// ─────────────────────────────────────────────────────────────────────────────

/// Complete quality report for a single decompiled function.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QualityReport {
    pub function_name: String,
    /// Cyclomatic complexity (`McCabe`).  1 = no branches.
    pub cyclomatic_complexity: u32,
    /// Overall readability score 0–100.
    pub readability_score: f32,
    /// Variable naming quality 0–100.
    pub naming_score: f32,
    /// Control-flow structure quality 0–100.
    pub structure_score: f32,
    /// Type annotation quality 0–100.
    pub type_quality_score: f32,
    /// Composite quality score 0–100 (weighted average).
    pub overall_score: f32,
    /// Detailed metrics.
    pub metrics: QualityMetrics,
}

impl QualityReport {
    /// Compute the overall score as a weighted average.
    pub fn compute_overall(&mut self) {
        self.overall_score = 0.15f32.mul_add(
            self.type_quality_score,
            0.35f32.mul_add(
                self.readability_score,
                0.25f32.mul_add(self.naming_score, 0.25 * self.structure_score),
            ),
        );
    }

    /// Return a grade letter for the overall score.
    #[must_use]
    pub fn grade(&self) -> &'static str {
        let s = self.overall_score;
        if s >= 90.0 { "A" }
        else if s >= 80.0 { "B" }
        else if s >= 70.0 { "C" }
        else if s >= 60.0 { "D" }
        else { "F" }
    }

    /// Format a one-line summary.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "{}: overall={:.1} ({}) cc={} read={:.1} name={:.1} struct={:.1} type={:.1}",
            self.function_name,
            self.overall_score,
            self.grade(),
            self.cyclomatic_complexity,
            self.readability_score,
            self.naming_score,
            self.structure_score,
            self.type_quality_score
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// QualityMetrics — raw counters
// ─────────────────────────────────────────────────────────────────────────────

/// Low-level counters collected during analysis.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct QualityMetrics {
    pub total_lines: usize,
    pub code_lines: usize,
    pub comment_lines: usize,
    pub blank_lines: usize,
    pub max_line_length: usize,
    pub avg_line_length: f32,
    pub max_nesting_depth: usize,
    pub avg_nesting_depth: f32,
    pub goto_count: usize,
    pub total_variables: usize,
    pub auto_named_variables: usize,
    pub typed_variables: usize,
    pub untyped_variables: usize,
    pub if_count: usize,
    pub loop_count: usize,
    pub switch_count: usize,
    pub function_call_count: usize,
    /// Lines that exceed the configured maximum line length.
    pub long_lines: usize,
    /// Deepest brace depth encountered.
    pub max_brace_depth: usize,
}

impl QualityMetrics {
    /// Comment density as a fraction of code lines.
    #[must_use]
    pub fn comment_density(&self) -> f32 {
        if self.code_lines == 0 {
            return 0.0;
        }
        f32::from(u16::try_from(self.comment_lines).unwrap_or(u16::MAX))
            / f32::from(u16::try_from(self.code_lines).unwrap_or(u16::MAX))
    }

    /// Ratio of non-auto-generated names.
    #[must_use]
    pub fn good_naming_ratio(&self) -> f32 {
        if self.total_variables == 0 {
            return 1.0;
        }
        1.0 - f32::from(u16::try_from(self.auto_named_variables).unwrap_or(u16::MAX))
            / f32::from(u16::try_from(self.total_variables).unwrap_or(u16::MAX))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// QualityConfig
// ─────────────────────────────────────────────────────────────────────────────

/// Configuration for the quality analyser.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QualityConfig {
    /// Maximum acceptable line length (default 120).
    pub max_line_length: usize,
    /// Maximum acceptable nesting depth before penalty (default 5).
    pub max_acceptable_depth: usize,
    /// Cyclomatic complexity threshold for "poor" score (default 20).
    pub complexity_threshold: u32,
    /// Penalty per goto statement in the structure score.
    pub goto_penalty: f32,
    /// Variable name prefixes that indicate auto-generated names.
    pub auto_name_prefixes: Vec<String>,
}

impl Default for QualityConfig {
    fn default() -> Self {
        Self {
            max_line_length: 120,
            max_acceptable_depth: 5,
            complexity_threshold: 20,
            goto_penalty: 5.0,
            auto_name_prefixes: vec![
                "var".to_string(),
                "tmp".to_string(),
                "arg".to_string(),
                "loc".to_string(),
                "sub_".to_string(),
                "v".to_string(),
                "a1".to_string(), "a2".to_string(), "a3".to_string(), "a4".to_string(),
            ],
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ComplexityAnalyser
// ─────────────────────────────────────────────────────────────────────────────

/// Computes `McCabe` cyclomatic complexity from C source text.
///
/// Formula: CC = 1 + number of decision points.
/// Decision points: `if`, `else if`, `while`, `for`, `do`, `case`, `&&`, `||`, ternary `?`.
pub struct ComplexityAnalyser;

impl ComplexityAnalyser {
    #[must_use]
    pub fn analyse(source: &str) -> u32 {
        let mut cc = 1u32; // base
        for line in source.lines() {
            let t = line.trim();
            // Skip comment lines.
            if t.starts_with("//") || t.starts_with("/*") || t.starts_with('*') {
                continue;
            }
            cc += Self::count_decision_points(t);
        }
        cc
    }

    fn count_decision_points(line: &str) -> u32 {
        let mut count = 0u32;

        // Keywords.
        for kw in &["if (", "if(", "while (", "while(", "for (", "for(", " do {", "do{", "else if"] {
            if line.contains(kw) {
                count += 1;
            }
        }

        // `case N:` — each case adds one decision point.
        if line.trim_start().starts_with("case ") && line.contains(':') {
            count += 1;
        }

        // Logical operators.
        count += u32::try_from(line.matches("&&").count()).unwrap_or(u32::MAX);
        count += u32::try_from(line.matches("||").count()).unwrap_or(u32::MAX);

        // Ternary.
        // We count `?` not inside string literals (best effort).
        let in_line = &line;
        let mut in_string = false;
        for ch in in_line.chars() {
            match ch {
                '"' => in_string = !in_string,
                '?' if !in_string => count += 1,
                _ => {}
            }
        }

        count
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// NestingAnalyser
// ─────────────────────────────────────────────────────────────────────────────

/// Tracks brace nesting depth across source lines.
pub struct NestingAnalyser;

impl NestingAnalyser {
    /// Returns `(max_depth, avg_depth_of_code_lines)`.
    #[must_use]
    pub fn analyse(source: &str) -> (usize, f32) {
        let mut depth = 0i32;
        let mut max_depth = 0usize;
        let mut total_depth = 0u64;
        let mut code_lines = 0u64;

        for line in source.lines() {
            let t = line.trim();
            if t.is_empty() || t.starts_with("//") || t.starts_with("/*") {
                continue;
            }

            // Count braces on this line.
            let opens = i32::try_from(t.chars().filter(|&c| c == '{').count()).unwrap_or(i32::MAX);
            let closes = i32::try_from(t.chars().filter(|&c| c == '}').count()).unwrap_or(i32::MAX);

            // If closing braces appear before opens, depth decreases first.
            depth -= closes.min(closes.max(0));
            depth = depth.max(0);

            let depth_usize = usize::try_from(depth).unwrap_or(0);
            if depth_usize > max_depth {
                max_depth = depth_usize;
            }

            total_depth += u64::from(depth.cast_unsigned());
            code_lines += 1;

            depth += opens;
            depth = depth.max(0);
        }

        let avg = if code_lines > 0 {
            f32::from(u16::try_from(total_depth).unwrap_or(u16::MAX))
                / f32::from(u16::try_from(code_lines).unwrap_or(u16::MAX))
        } else {
            0.0
        };

        (max_depth, avg)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// VariableNameAnalyser
// ─────────────────────────────────────────────────────────────────────────────

/// Analyses variable declarations for naming quality.
pub struct VariableNameAnalyser {
    pub auto_prefixes: Vec<String>,
}

impl VariableNameAnalyser {
    #[must_use]
    pub const fn new(auto_prefixes: Vec<String>) -> Self {
        Self { auto_prefixes }
    }

    /// Returns `(total_vars, auto_named_vars, typed_vars)`.
    #[must_use]
    pub fn analyse(&self, source: &str) -> (usize, usize, usize) {
        let mut total = 0usize;
        let mut auto_named = 0usize;
        let mut typed = 0usize;

        for line in source.lines() {
            let t = line.trim();
            // Look for variable declarations: `type name` or `type name = init;`
            if let Some((ty, name)) = Self::parse_decl(t) {
                total += 1;
                if !ty.is_empty() {
                    typed += 1;
                }
                if self.is_auto_name(&name) {
                    auto_named += 1;
                }
            }
        }

        (total, auto_named, typed)
    }

    fn parse_decl(stmt: &str) -> Option<(String, String)> {
        // Simple heuristic: lines ending with `;` that look like `type name`.
        let stmt = stmt.strip_suffix(';')?.trim();
        // Must not be an assignment or call.
        if stmt.starts_with("return") || stmt.starts_with("if")
            || stmt.starts_with("while") || stmt.starts_with("for")
            || stmt.starts_with("//") || stmt.starts_with("/*")
        {
            return None;
        }

        let known_types = [
            "int", "unsigned", "char", "void", "long", "short", "float",
            "double", "int32_t", "uint32_t", "int64_t", "uint64_t",
            "int8_t", "uint8_t", "int16_t", "uint16_t", "size_t", "bool",
            "DWORD", "HANDLE", "BOOL", "BYTE", "WORD", "LPVOID", "LPCSTR",
            "struct", "enum",
        ];

        // Try longer type names first so e.g. `int32_t` matches before `int`.
        let mut sorted_types = known_types.to_vec();
        sorted_types.sort_by_key(|s: &&str| std::cmp::Reverse(s.len()));
        for ty in sorted_types {
            if let Some(after) = stmt.strip_prefix(ty) {
                // Ensure the matched type is a whole token (followed by
                // whitespace, `*`, or end of string) so `int` doesn't swallow
                // the prefix of `int32_t`.
                let boundary_ok = after.is_empty()
                    || after.starts_with(|c: char| c.is_whitespace() || c == '*');
                if !boundary_ok {
                    continue;
                }
                let rest = after.trim();
                // Strip pointer stars.
                let rest = rest.trim_start_matches('*').trim();
                // Get name (up to space or `=`).
                let name_end = rest
                    .find(|c: char| !c.is_alphanumeric() && c != '_')
                    .unwrap_or(rest.len());
                let name = &rest[..name_end];
                if !name.is_empty() {
                    return Some((ty.to_string(), name.to_string()));
                }
            }
        }
        None
    }

    fn is_auto_name(&self, name: &str) -> bool {
        for prefix in &self.auto_prefixes {
            if name.starts_with(prefix.as_str()) {
                return true;
            }
        }
        // Single-letter names are considered auto (except common loop vars).
        if name.len() == 1 && !matches!(name, "i" | "j" | "k" | "n" | "p" | "s") {
            return true;
        }
        false
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ReadabilityAnalyser
// ─────────────────────────────────────────────────────────────────────────────

/// Computes a readability score 0–100.
///
/// Factors (weighted):
/// - Line length: penalty for lines > `max_line_length`.
/// - Nesting depth: penalty for deep nesting.
/// - Comment density: bonus for comments.
/// - Goto frequency: penalty.
/// - Cyclomatic complexity: penalty for high CC.
pub struct ReadabilityAnalyser {
    config: QualityConfig,
}

impl ReadabilityAnalyser {
    #[must_use]
    pub const fn new(config: QualityConfig) -> Self {
        Self { config }
    }

    #[must_use]
    pub fn analyse(&self, _source: &str, metrics: &QualityMetrics, cc: u32) -> f32 {
        let mut score = 100.0f32;

        // ── Line length penalty ───────────────────────────────────────────
        if metrics.code_lines > 0 {
            let long = f32::from(u16::try_from(metrics.long_lines).unwrap_or(u16::MAX));
            let code = f32::from(u16::try_from(metrics.code_lines).unwrap_or(u16::MAX));
            score = (long / code).mul_add(-20.0, score);
        }

        // ── Nesting depth penalty ─────────────────────────────────────────
        if metrics.max_nesting_depth > self.config.max_acceptable_depth {
            let excess = f32::from(u16::try_from(
                metrics.max_nesting_depth - self.config.max_acceptable_depth,
            ).unwrap_or(u16::MAX));
            score = excess.mul_add(-4.0, score);
        }

        // ── Goto penalty ──────────────────────────────────────────────────
        score = f32::from(u16::try_from(metrics.goto_count).unwrap_or(u16::MAX)).mul_add(-self.config.goto_penalty, score);

        // ── Complexity penalty ────────────────────────────────────────────
        if cc > self.config.complexity_threshold {
            let excess = cc - self.config.complexity_threshold;
            score = f32::from(u16::try_from(excess).unwrap_or(u16::MAX)).mul_add(-1.5, score);
        }

        // ── Comment density bonus ─────────────────────────────────────────
        let density = metrics.comment_density();
        // Optimal density 0.1–0.3.
        if density >= 0.05 {
            score += (density * 100.0).min(10.0);
        }

        score.clamp(0.0, 100.0)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// StructureScoreAnalyser
// ─────────────────────────────────────────────────────────────────────────────

/// Scores the structural quality of control flow.
pub struct StructureScoreAnalyser {
    pub goto_penalty: f32,
}

impl Default for StructureScoreAnalyser {
    fn default() -> Self {
        Self { goto_penalty: 5.0 }
    }
}

impl StructureScoreAnalyser {
    #[must_use]
    pub fn analyse(&self, source: &str) -> f32 {
        let mut score = 100.0f32;
        let mut goto_count = 0u32;
        let mut label_count = 0u32;
        let mut for_count = 0u32;
        let mut while_count = 0u32;

        for line in source.lines() {
            let t = line.trim();
            if t.starts_with("goto ") { goto_count += 1; }
            if t.ends_with(':') && !t.starts_with("case") && !t.starts_with("default") {
                label_count += 1;
            }
            if t.starts_with("for (") || t.starts_with("for(") { for_count += 1; }
            if t.starts_with("while (") || t.starts_with("while(") { while_count += 1; }
        }

        // Penalise gotos.
        score = f32::from(u16::try_from(goto_count).unwrap_or(u16::MAX)).mul_add(-self.goto_penalty, score);
        // Labels that aren't case/default are a sign of unstructured code.
        score = f32::from(u16::try_from(label_count).unwrap_or(u16::MAX)).mul_add(-3.0, score);
        // Bonus for for-loops (they're more readable than equivalent while loops).
        score = f32::from(u16::try_from(for_count).unwrap_or(u16::MAX)).mul_add(1.0, score);
        // Small bonus for while-loops: they're structured (preferable to
        // back-edge gotos), but less self-documenting than `for`.
        score = f32::from(u16::try_from(while_count).unwrap_or(u16::MAX)).mul_add(0.5, score);

        score.clamp(0.0, 100.0)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TypeQualityAnalyser
// ─────────────────────────────────────────────────────────────────────────────

/// Scores the quality of type annotations.
pub struct TypeQualityAnalyser;

impl TypeQualityAnalyser {
    #[must_use]
    pub fn analyse(source: &str) -> f32 {
        let mut typed = 0u32;
        let mut untyped = 0u32;

        for line in source.lines() {
            let t = line.trim();
            // Count variables declared with known-width types.
            let good_types = [
                "int32_t", "uint32_t", "int64_t", "uint64_t",
                "int8_t", "uint8_t", "int16_t", "uint16_t",
                "float", "double", "bool", "size_t",
                "DWORD", "HANDLE", "BOOL",
            ];
            let vague_types = ["int ", "unsigned ", "long ", "short ", "char "];

            for ty in &good_types {
                if t.contains(ty) && t.ends_with(';') { typed += 1; }
            }
            for ty in &vague_types {
                if t.starts_with(ty) && t.ends_with(';') { untyped += 1; }
            }
        }

        let total = typed + untyped;
        if total == 0 {
            return 50.0; // No information.
        }
        (f32::from(u16::try_from(typed).unwrap_or(u16::MAX))
            / f32::from(u16::try_from(total).unwrap_or(u16::MAX)))
            * 100.0
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// MetricsCollector
// ─────────────────────────────────────────────────────────────────────────────

/// Collects all raw metrics from source text.
pub struct MetricsCollector {
    max_line_length: usize,
}

impl MetricsCollector {
    #[must_use]
    pub const fn new(max_line_length: usize) -> Self {
        Self { max_line_length }
    }

    #[must_use]
    pub fn collect(&self, source: &str) -> QualityMetrics {
        let mut m = QualityMetrics::default();
        let mut total_len = 0u64;
        let mut total_depth = 0u64;
        let mut brace_depth = 0i32;

        for line in source.lines() {
            m.total_lines += 1;
            let t = line.trim();

            if t.is_empty() {
                m.blank_lines += 1;
                continue;
            }

            if t.starts_with("//") || t.starts_with("/*") || t.starts_with('*') {
                m.comment_lines += 1;
            } else {
                m.code_lines += 1;
            }

            let len = line.len();
            total_len += len as u64;
            if len > m.max_line_length {
                m.max_line_length = len;
            }
            if len > self.max_line_length {
                m.long_lines += 1;
            }

            // Brace depth.
            let opens = i32::try_from(t.chars().filter(|&c| c == '{').count()).unwrap_or(i32::MAX);
            let closes = i32::try_from(t.chars().filter(|&c| c == '}').count()).unwrap_or(i32::MAX);
            brace_depth += opens - closes;
            brace_depth = brace_depth.max(0);
            let bd_usize = usize::try_from(brace_depth).unwrap_or(0);
            if bd_usize > m.max_brace_depth {
                m.max_brace_depth = bd_usize;
            }
            if bd_usize > m.max_nesting_depth {
                m.max_nesting_depth = bd_usize;
            }
            total_depth += u64::from(brace_depth.cast_unsigned());

            // Control flow.
            if t.starts_with("if (") || t.starts_with("if(") { m.if_count += 1; }
            if t.starts_with("while (") || t.starts_with("while(")
                || t.starts_with("for (") || t.starts_with("for(")
                || t.starts_with("do {") || t.starts_with("do{")
            {
                m.loop_count += 1;
            }
            if t.starts_with("switch (") || t.starts_with("switch(") { m.switch_count += 1; }
            if t.starts_with("goto ") { m.goto_count += 1; }

            // Function calls (very rough heuristic: `identifier(`).
            m.function_call_count += count_calls_in_line(t);
        }

        if m.total_lines > 0 {
            m.avg_line_length = f32::from(u16::try_from(total_len).unwrap_or(u16::MAX))
                / f32::from(u16::try_from(m.total_lines).unwrap_or(u16::MAX));
        }
        if m.code_lines > 0 {
            m.avg_nesting_depth = f32::from(u16::try_from(total_depth).unwrap_or(u16::MAX))
                / f32::from(u16::try_from(m.code_lines).unwrap_or(u16::MAX));
        }

        m
    }
}

fn count_calls_in_line(line: &str) -> usize {
    // Count `identifier(` patterns.
    let mut count = 0;
    let bytes = line.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i].is_ascii_alphabetic() || bytes[i] == b'_' {
            let start = i;
            while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
                i += 1;
            }
            // Check for `(` following.
            if i < bytes.len() && bytes[i] == b'(' {
                // Ignore keywords.
                let name = &line[start..i];
                if !matches!(name, "if" | "while" | "for" | "switch" | "return" | "sizeof") {
                    count += 1;
                }
            }
        } else {
            i += 1;
        }
    }
    count
}

// ─────────────────────────────────────────────────────────────────────────────
// QualityAnalyser — orchestrator
// ─────────────────────────────────────────────────────────────────────────────

/// High-level analyser that produces a full [`QualityReport`].
#[derive(Default)]
pub struct QualityAnalyser {
    pub config: QualityConfig,
}


impl QualityAnalyser {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub const fn with_config(config: QualityConfig) -> Self {
        Self { config }
    }

    #[must_use]
    pub fn analyse(&self, func_name: &str, source: &str) -> QualityReport {
        let cc = ComplexityAnalyser::analyse(source);

        let collector = MetricsCollector::new(self.config.max_line_length);
        let mut metrics = collector.collect(source);

        let name_analyser = VariableNameAnalyser::new(self.config.auto_name_prefixes.clone());
        let (total_vars, auto_named, typed) = name_analyser.analyse(source);
        metrics.total_variables = total_vars;
        metrics.auto_named_variables = auto_named;
        metrics.typed_variables = typed;
        metrics.untyped_variables = total_vars.saturating_sub(typed);

        let (max_depth, avg_depth) = NestingAnalyser::analyse(source);
        metrics.max_nesting_depth = max_depth;
        metrics.avg_nesting_depth = avg_depth;

        let readability_analyser = ReadabilityAnalyser::new(self.config.clone());
        let readability_score = readability_analyser.analyse(source, &metrics, cc);

        let naming_score: f32 = if total_vars == 0 {
            100.0_f32
        } else {
            metrics.good_naming_ratio() * 100.0
        };

        let structure_analyser = StructureScoreAnalyser {
            goto_penalty: self.config.goto_penalty,
        };
        let structure_score = structure_analyser.analyse(source);

        let type_quality_score = TypeQualityAnalyser::analyse(source);

        let mut report = QualityReport {
            function_name: func_name.to_string(),
            cyclomatic_complexity: cc,
            readability_score,
            naming_score,
            structure_score,
            type_quality_score,
            overall_score: 0.0,
            metrics,
        };
        report.compute_overall();
        report
    }

    /// Analyse multiple functions and return aggregate stats.
    pub fn analyse_batch<'a>(
        &self,
        functions: impl Iterator<Item = (&'a str, &'a str)>,
    ) -> BatchQualityReport {
        let mut reports = Vec::new();
        for (name, src) in functions {
            reports.push(self.analyse(name, src));
        }
        BatchQualityReport::from_reports(reports)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// BatchQualityReport
// ─────────────────────────────────────────────────────────────────────────────

/// Aggregate quality statistics for a collection of functions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchQualityReport {
    pub reports: Vec<QualityReport>,
    pub avg_overall: f32,
    pub avg_complexity: f32,
    pub avg_readability: f32,
    pub worst_functions: Vec<String>,
    pub best_functions: Vec<String>,
}

impl BatchQualityReport {
    /// # Panics
    ///
    /// Panics if any `overall_score` is NaN (should not occur for well-formed reports).
    #[must_use]
    pub fn from_reports(mut reports: Vec<QualityReport>) -> Self {
        if reports.is_empty() {
            return Self {
                reports: Vec::new(),
                avg_overall: 0.0,
                avg_complexity: 0.0,
                avg_readability: 0.0,
                worst_functions: Vec::new(),
                best_functions: Vec::new(),
            };
        }

        let n = f32::from(u16::try_from(reports.len()).unwrap_or(u16::MAX));
        let avg_overall = reports.iter().map(|r| r.overall_score).sum::<f32>() / n;
        let avg_complexity = reports
            .iter()
            .map(|r| f32::from(u16::try_from(r.cyclomatic_complexity).unwrap_or(u16::MAX)))
            .sum::<f32>()
            / n;
        let avg_readability = reports.iter().map(|r| r.readability_score).sum::<f32>() / n;

        // Sort by overall score for best/worst.
        reports.sort_by(|a, b| a.overall_score.partial_cmp(&b.overall_score).unwrap());

        let worst_functions: Vec<String> = reports
            .iter()
            .take(3)
            .map(|r| r.function_name.clone())
            .collect();
        let best_functions: Vec<String> = reports
            .iter()
            .rev()
            .take(3)
            .map(|r| r.function_name.clone())
            .collect();

        Self {
            reports,
            avg_overall,
            avg_complexity,
            avg_readability,
            worst_functions,
            best_functions,
        }
    }

    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "{} functions: avg score={:.1}, avg CC={:.1}, avg readability={:.1}",
            self.reports.len(),
            self.avg_overall,
            self.avg_complexity,
            self.avg_readability
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn simple_fn() -> &'static str {
        r"int32_t add(int32_t a, int32_t b) {
    /* add two numbers */
    int32_t result = a + b;
    return result;
}"
    }

    fn goto_fn() -> &'static str {
        r"void bad_fn() {
    x = 1;
    goto label1;
    y = 2;
label1:
    goto label2;
label2:
    return;
}"
    }

    #[test]
    fn test_complexity_simple() {
        let cc = ComplexityAnalyser::analyse(simple_fn());
        assert_eq!(cc, 1, "simple function should have CC=1");
    }

    #[test]
    fn test_complexity_with_branches() {
        let src = "void f() {\n    if (x) { a(); }\n    while (y) { b(); }\n    if (z && w) {}\n}";
        let cc = ComplexityAnalyser::analyse(src);
        assert!(cc >= 4, "expected CC >= 4, got {cc}");
    }

    #[test]
    fn test_nesting_analyser() {
        let src = "{\n    {\n        {\n        }\n    }\n}";
        let (max, _avg) = NestingAnalyser::analyse(src);
        assert!(max >= 2, "expected max depth >= 2, got {max}");
    }

    #[test]
    fn test_naming_analyser_good() {
        let src = "    int32_t buffer_size = 100;\n    uint8_t byte_val = 0;\n";
        let analyser = VariableNameAnalyser::new(vec!["var".to_string(), "tmp".to_string()]);
        let (total, auto, _typed) = analyser.analyse(src);
        assert_eq!(auto, 0);
        assert!(total >= 2);
    }

    #[test]
    fn test_naming_analyser_auto_names() {
        let src = "    int32_t var1 = 0;\n    int32_t tmp2 = 1;\n";
        let analyser = VariableNameAnalyser::new(vec!["var".to_string(), "tmp".to_string()]);
        let (total, auto, _typed) = analyser.analyse(src);
        assert!(total >= 2);
        assert_eq!(auto, 2);
    }

    #[test]
    fn test_quality_analyser_full() {
        let qa = QualityAnalyser::new();
        let report = qa.analyse("add", simple_fn());
        assert_eq!(report.function_name, "add");
        assert!(report.overall_score >= 0.0 && report.overall_score <= 100.0);
        assert!(report.cyclomatic_complexity >= 1);
    }

    #[test]
    fn test_goto_penalises_structure() {
        let qa = QualityAnalyser::new();
        let good = qa.analyse("good", simple_fn());
        let bad = qa.analyse("bad", goto_fn());
        assert!(good.structure_score > bad.structure_score,
            "good={:.1} bad={:.1}", good.structure_score, bad.structure_score);
    }

    #[test]
    fn test_grade_high_score() {
        let report = QualityReport {
            function_name: "f".to_string(),
            cyclomatic_complexity: 1,
            readability_score: 95.0,
            naming_score: 95.0,
            structure_score: 95.0,
            type_quality_score: 95.0,
            overall_score: 95.0,
            metrics: QualityMetrics::default(),
        };
        assert_eq!(report.grade(), "A");
    }

    #[test]
    fn test_grade_low_score() {
        let report = QualityReport {
            function_name: "f".to_string(),
            cyclomatic_complexity: 50,
            readability_score: 20.0,
            naming_score: 10.0,
            structure_score: 30.0,
            type_quality_score: 20.0,
            overall_score: 20.0,
            metrics: QualityMetrics::default(),
        };
        assert_eq!(report.grade(), "F");
    }

    #[test]
    fn test_metrics_collector() {
        let collector = MetricsCollector::new(80);
        let m = collector.collect(simple_fn());
        assert!(m.total_lines >= 5);
        assert!(m.code_lines >= 3);
        assert!(m.comment_lines >= 1);
    }

    #[test]
    fn test_batch_report() {
        let qa = QualityAnalyser::new();
        let fns = vec![("add", simple_fn()), ("bad", goto_fn())];
        let batch = qa.analyse_batch(fns.into_iter());
        assert_eq!(batch.reports.len(), 2);
        assert!(!batch.worst_functions.is_empty());
    }

    #[test]
    fn test_type_quality_good_types() {
        let src = "int32_t x;\nuint64_t y;\nbool flag;\n";
        let score = TypeQualityAnalyser::analyse(src);
        assert!(score >= 50.0, "score={score}");
    }

    // ── Added comprehensive tests ─────────────────────────────────────────────

    #[test]
    fn complexity_empty_source_is_one() {
        // No decision points → CC = 1.
        assert_eq!(ComplexityAnalyser::analyse(""), 1);
        assert_eq!(ComplexityAnalyser::analyse("\n\n\n"), 1);
    }

    #[test]
    fn complexity_ignores_decision_keywords_in_comments() {
        let src = "// if (x) && (y)\n/* while (z) */\n* if (a)\nreturn 0;";
        assert_eq!(ComplexityAnalyser::analyse(src), 1);
    }

    #[test]
    fn complexity_counts_case_labels() {
        let src = "switch(x){\ncase 1: break;\ncase 2: break;\ndefault: break;\n}";
        let cc = ComplexityAnalyser::analyse(src);
        // 2 `case N:` decision points → CC >= 3.
        assert!(cc >= 3, "cc={cc}");
    }

    #[test]
    fn complexity_ignores_question_mark_in_strings() {
        let src = r#"const char *q = "what?";"#;
        // No real ternary; CC must stay 1.
        assert_eq!(ComplexityAnalyser::analyse(src), 1);
    }

    #[test]
    fn complexity_counts_ternary() {
        let src = "int x = a ? b : c;";
        assert!(ComplexityAnalyser::analyse(src) >= 2);
    }

    #[test]
    fn nesting_empty_input() {
        let (max, avg) = NestingAnalyser::analyse("");
        assert_eq!(max, 0);
        assert_eq!(avg, 0.0);
    }

    #[test]
    fn nesting_blank_and_comment_lines_ignored() {
        let (max, _) = NestingAnalyser::analyse("\n\n// comment\n/* block */\n");
        assert_eq!(max, 0);
    }

    #[test]
    fn nesting_deep_depth_tracked() {
        let mut src = String::new();
        for _ in 0..10 { src.push_str("{\n"); }
        for _ in 0..10 { src.push_str("}\n"); }
        let (max, _) = NestingAnalyser::analyse(&src);
        assert!(max >= 9, "max={max}");
    }

    #[test]
    fn naming_handles_pointer_declarations() {
        let analyser = VariableNameAnalyser::new(vec!["var".into()]);
        let (total, _auto, typed) = analyser.analyse("char *buffer = NULL;\nint **pp;\n");
        assert!(total >= 2, "total={total}");
        assert_eq!(typed, total);
    }

    #[test]
    fn naming_skips_control_flow_statements() {
        let analyser = VariableNameAnalyser::new(vec![]);
        let (total, _, _) = analyser.analyse("if (x);\nwhile(y);\nreturn 0;\nfor(;;);\n");
        assert_eq!(total, 0);
    }

    #[test]
    fn naming_int_does_not_swallow_int32_t() {
        // Regression: `int32_t` must be matched as a single type token, not
        // `int` followed by `32_t`.
        let analyser = VariableNameAnalyser::new(vec![]);
        let (total, _, typed) = analyser.analyse("int32_t my_int = 0;");
        assert_eq!(total, 1);
        assert_eq!(typed, 1);
    }

    #[test]
    fn naming_single_letter_loop_vars_not_auto() {
        let analyser = VariableNameAnalyser::new(vec!["var".into()]);
        let (_total, auto, _) = analyser.analyse("int i = 0;\nint j = 1;\nint k = 2;\n");
        assert_eq!(auto, 0, "i/j/k should not be flagged");
        let (_t2, auto2, _) = analyser.analyse("int x = 0;\n");
        assert_eq!(auto2, 1, "single-letter x should be flagged");
    }

    #[test]
    fn metrics_blank_and_comment_lines_counted() {
        let src = "// a\n\n/* b */\nint x = 1;\n";
        let m = MetricsCollector::new(80).collect(src);
        assert_eq!(m.total_lines, 4);
        assert_eq!(m.blank_lines, 1);
        assert!(m.comment_lines >= 2);
        assert!(m.code_lines >= 1);
    }

    #[test]
    fn metrics_long_lines_flagged() {
        let long = "a".repeat(200);
        let src = format!("int x;\n{long}\n");
        let m = MetricsCollector::new(80).collect(&src);
        assert_eq!(m.long_lines, 1);
        assert!(m.max_line_length >= 200);
    }

    #[test]
    fn metrics_function_calls_ignore_keywords() {
        let src = "if (foo(1)) { return bar(2); }\nwhile(baz()) { sizeof(int); }";
        let m = MetricsCollector::new(120).collect(src);
        // foo, bar, baz = 3 real calls. sizeof, if, while, return are excluded.
        assert_eq!(m.function_call_count, 3, "got {}", m.function_call_count);
    }

    #[test]
    fn metrics_goto_count_matches() {
        let m = MetricsCollector::new(120).collect(goto_fn());
        assert_eq!(m.goto_count, 2);
    }

    #[test]
    fn comment_density_zero_with_no_code() {
        let m = QualityMetrics::default();
        assert_eq!(m.comment_density(), 0.0);
    }

    #[test]
    fn good_naming_ratio_unity_when_no_vars() {
        let m = QualityMetrics::default();
        assert_eq!(m.good_naming_ratio(), 1.0);
    }

    #[test]
    fn structure_score_clamps_with_many_gotos() {
        let mut src = String::new();
        for i in 0..50 { src.push_str(&format!("goto L{i};\n")); }
        let s = StructureScoreAnalyser::default().analyse(&src);
        assert!((0.0..=100.0).contains(&s));
        assert_eq!(s, 0.0, "many gotos should clamp to 0");
    }

    #[test]
    fn type_quality_no_decls_is_neutral() {
        let s = TypeQualityAnalyser::analyse("");
        assert_eq!(s, 50.0);
    }

    #[test]
    fn type_quality_all_vague_types_low() {
        let s = TypeQualityAnalyser::analyse("int x;\nlong y;\nshort z;\n");
        assert!(s <= 25.0, "score={s}");
    }

    #[test]
    fn quality_report_grade_boundaries() {
        let base = QualityMetrics::default();
        let mk = |score| QualityReport {
            function_name: "f".into(),
            cyclomatic_complexity: 1,
            readability_score: score,
            naming_score: score,
            structure_score: score,
            type_quality_score: score,
            overall_score: score,
            metrics: base.clone(),
        };
        assert_eq!(mk(90.0).grade(), "A");
        assert_eq!(mk(89.999).grade(), "B");
        assert_eq!(mk(80.0).grade(), "B");
        assert_eq!(mk(70.0).grade(), "C");
        assert_eq!(mk(60.0).grade(), "D");
        assert_eq!(mk(0.0).grade(), "F");
    }

    #[test]
    fn quality_report_compute_overall_weighted() {
        let mut r = QualityReport {
            function_name: "f".into(),
            cyclomatic_complexity: 1,
            readability_score: 100.0,
            naming_score: 0.0,
            structure_score: 0.0,
            type_quality_score: 0.0,
            overall_score: 0.0,
            metrics: QualityMetrics::default(),
        };
        r.compute_overall();
        // Readability weight = 0.35 → exactly 35.
        assert!((r.overall_score - 35.0).abs() < 1e-3, "got {}", r.overall_score);
    }

    #[test]
    fn batch_quality_empty_is_safe() {
        let qa = QualityAnalyser::new();
        let batch = qa.analyse_batch(std::iter::empty());
        assert!(batch.reports.is_empty());
        assert_eq!(batch.avg_overall, 0.0);
        assert!(batch.worst_functions.is_empty());
        assert!(batch.best_functions.is_empty());
    }

    #[test]
    fn batch_quality_summary_mentions_count() {
        let qa = QualityAnalyser::new();
        let fns: Vec<(&str, &str)> = vec![("a", simple_fn()), ("b", simple_fn())];
        let batch = qa.analyse_batch(fns.into_iter());
        let s = batch.summary();
        assert!(s.contains("2 functions"));
    }

    #[test]
    fn report_summary_contains_function_name_and_grade() {
        let qa = QualityAnalyser::new();
        let r = qa.analyse("myfn", simple_fn());
        let s = r.summary();
        assert!(s.contains("myfn"));
        assert!(s.contains("cc="));
    }
}
