//! `rustre-agent-prompts`
//!
//! RE-specific prompt templates, prompt engineering utilities, and a
//! SQLite-backed few-shot example database for the `RustRE` agent framework.

pub mod analysis_prompt_builder;
pub mod chain_of_thought;
pub mod context_assembler;
pub mod context_builder;
pub mod few_shot_db;
pub mod few_shot_examples;
pub mod prompt_chain;
pub mod prompt_library;
pub mod prompt_optimizer;
pub mod prompt_template_engine;
pub mod prompt_templates;
pub mod prompts_re;
pub mod re_prompt_library;
pub mod result_parser;

use std::collections::HashMap;

use rusqlite::Connection;
use rustre_agent_llm::LlmBackend;
use serde::{Deserialize, Serialize};
use thiserror::Error;

// ─── Error ───────────────────────────────────────────────────────────────────

/// Errors from the prompt subsystem.
#[derive(Debug, Error)]
pub enum PromptError {
    #[error("missing template variable: {0}")]
    MissingVariable(String),

    #[error("template not found: {0}")]
    TemplateNotFound(String),

    #[error("database error: {0}")]
    DbError(String),

    #[error("serialization error: {0}")]
    SerializationError(String),

    #[error("chain error at step {step}: {message}")]
    ChainError { step: usize, message: String },
}

impl From<rusqlite::Error> for PromptError {
    fn from(e: rusqlite::Error) -> Self {
        Self::DbError(e.to_string())
    }
}

impl From<serde_json::Error> for PromptError {
    fn from(e: serde_json::Error) -> Self {
        Self::SerializationError(e.to_string())
    }
}

// ─── PromptTemplate ──────────────────────────────────────────────────────────

/// A named prompt template with variable placeholders.
/// Variables use `{{variable_name}}` syntax.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PromptTemplate {
    pub name: String,
    /// The prompt body; use `{{varname}}` for substitutions.
    pub template: String,
    /// Declared variable names (without braces).
    pub variables: Vec<String>,
    /// Optional system prompt prefix.
    pub system_prompt: String,
}

impl PromptTemplate {
    /// Create a new prompt template.
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        template: impl Into<String>,
        variables: Vec<String>,
        system_prompt: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            template: template.into(),
            variables,
            system_prompt: system_prompt.into(),
        }
    }

    /// Render this template with the provided variables, returning an error if
    /// any declared variable is missing from `vars`.
    pub fn render(&self, vars: &HashMap<String, String>) -> Result<String, PromptError> {
        PromptRenderer::render(&self.template, vars)
    }
}

// ─── PromptRenderer ──────────────────────────────────────────────────────────

/// Stateless renderer that substitutes `{{variable}}` placeholders.
pub struct PromptRenderer;

impl PromptRenderer {
    /// Substitute all `{{key}}` occurrences in `template` with values from `vars`.
    /// Returns an error if a placeholder key is absent from `vars`.
    pub fn render(template: &str, vars: &HashMap<String, String>) -> Result<String, PromptError> {
        let mut output = String::with_capacity(template.len());
        let mut i = 0usize;

        while i < template.len() {
            let rest = &template[i..];
            // Escape: `{{{{` -> literal `{{`
            if rest.starts_with("{{{{") {
                output.push_str("{{");
                i += 4;
                continue;
            }
            // Escape: `}}}}` -> literal `}}`
            if rest.starts_with("}}}}") {
                output.push_str("}}");
                i += 4;
                continue;
            }
            if rest.starts_with("{{") {
                let start = i + 2;
                let Some(end_rel) = template[start..].find("}}") else {
                    return Err(PromptError::MissingVariable("unclosed placeholder".into()));
                };
                let end = start + end_rel;
                let key = template[start..end].trim().to_string();
                let value = vars
                    .get(&key)
                    .cloned()
                    .ok_or_else(|| PromptError::MissingVariable(key.clone()))?;
                output.push_str(&value);
                i = end + 2;
                continue;
            }
            let ch = rest.chars().next().unwrap();
            output.push(ch);
            i += ch.len_utf8();
        }

        Ok(output)
    }

    /// Render with a map of `(key, value)` pairs.
    pub fn render_pairs(template: &str, pairs: &[(&str, &str)]) -> Result<String, PromptError> {
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect();
        Self::render(template, &map)
    }
}

// ─── Few-shot types ──────────────────────────────────────────────────────────

/// A single few-shot example used to guide the model.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FewShotExample {
    pub task_type: String,
    pub input: String,
    pub output: String,
    pub explanation: String,
}

// ─── FewShotDatabase ─────────────────────────────────────────────────────────

/// SQLite-backed store for few-shot examples.
pub struct FewShotDatabase {
    conn: parking_lot::Mutex<Connection>,
    /// In-memory embedding store: maps example id (as returned by `insert`) to its embedding.
    embeddings: parking_lot::Mutex<HashMap<String, Vec<f32>>>,
}

impl FewShotDatabase {
    /// Open (or create) a database at the given path.
    pub fn open(path: &str) -> Result<Self, PromptError> {
        let conn = Connection::open(path)?;
        let db = Self {
            conn: parking_lot::Mutex::new(conn),
            embeddings: parking_lot::Mutex::new(HashMap::new()),
        };
        db.init_schema()?;
        Ok(db)
    }

    /// Open an in-memory database (useful for testing).
    pub fn in_memory() -> Result<Self, PromptError> {
        let conn = Connection::open_in_memory()?;
        let db = Self {
            conn: parking_lot::Mutex::new(conn),
            embeddings: parking_lot::Mutex::new(HashMap::new()),
        };
        db.init_schema()?;
        Ok(db)
    }

    fn init_schema(&self) -> Result<(), PromptError> {
        self.conn.lock().execute_batch(
            "CREATE TABLE IF NOT EXISTS few_shot_examples (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                task_type   TEXT NOT NULL,
                input       TEXT NOT NULL,
                output      TEXT NOT NULL,
                explanation TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_task_type ON few_shot_examples(task_type);",
        )?;
        Ok(())
    }

    /// Insert a new few-shot example.
    pub fn insert(&self, example: &FewShotExample) -> Result<i64, PromptError> {
        let conn = self.conn.lock();
        conn.execute(
            "INSERT INTO few_shot_examples (task_type, input, output, explanation)
             VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![
                example.task_type,
                example.input,
                example.output,
                example.explanation
            ],
        )?;
        Ok(conn.last_insert_rowid())
    }

    /// Retrieve up to `limit` examples for a given task type.
    pub fn get_by_task(
        &self,
        task_type: &str,
        limit: usize,
    ) -> Result<Vec<FewShotExample>, PromptError> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(
            "SELECT task_type, input, output, explanation
             FROM few_shot_examples
             WHERE task_type = ?1
             LIMIT ?2",
        )?;
        let rows = stmt.query_map(rusqlite::params![task_type, limit as i64], |row| {
            Ok(FewShotExample {
                task_type: row.get(0)?,
                input: row.get(1)?,
                output: row.get(2)?,
                explanation: row.get(3)?,
            })
        })?;

        let mut examples = Vec::new();
        for row in rows {
            examples.push(row?);
        }
        Ok(examples)
    }

    // ── Embedding helpers ────────────────────────────────────────────────────

    /// Store an embedding vector for the example with the given `example_id`.
    ///
    /// `example_id` is typically the string form of the rowid returned by
    /// [`insert`](Self::insert), but any stable string key is accepted.
    pub fn embed_example(&self, example_id: &str, embedding: Vec<f32>) {
        self.embeddings
            .lock()
            .insert(example_id.to_string(), embedding);
    }

    /// Compute cosine similarity between two slices.
    ///
    /// Returns `0.0` when either slice is all-zeros or the lengths differ.
    fn cosine_similarity(a: &[f32], b: &[f32]) -> f32 {
        if a.len() != b.len() {
            return 0.0;
        }
        let dot: f32 = a.iter().zip(b.iter()).map(|(x, y)| x * y).sum();
        let norm_a: f32 = a.iter().map(|x| x * x).sum::<f32>().sqrt();
        let norm_b: f32 = b.iter().map(|x| x * x).sum::<f32>().sqrt();
        if norm_a == 0.0 || norm_b == 0.0 {
            return 0.0;
        }
        (dot / (norm_a * norm_b)).clamp(-1.0, 1.0)
    }

    /// Return the top-`k` examples whose stored embeddings are most similar
    /// to `query_embedding`, ranked by cosine similarity (highest first).
    ///
    /// Examples that have no stored embedding are skipped.  If fewer than `k`
    /// examples have embeddings, all of them are returned.
    pub fn find_similar(&self, query_embedding: &[f32], k: usize) -> Vec<FewShotExample> {
        // Collect (similarity, example_id) pairs for all stored embeddings.
        let emb_guard = self.embeddings.lock();
        let mut scored: Vec<(f32, String)> = emb_guard
            .iter()
            .map(|(id, vec)| (Self::cosine_similarity(query_embedding, vec), id.clone()))
            .collect();
        drop(emb_guard);

        // Sort by similarity descending, break ties by id for determinism.
        scored.sort_by(|a, b| {
            b.0.partial_cmp(&a.0)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then(a.1.cmp(&b.1))
        });
        scored.truncate(k);

        // Fetch the actual examples from SQLite for the top ids.
        let conn = self.conn.lock();
        let mut results = Vec::with_capacity(scored.len());
        for (_score, id) in &scored {
            // The id is the string representation of the SQLite rowid.
            if let Ok(rowid) = id.parse::<i64>() {
                let row = conn.query_row(
                    "SELECT task_type, input, output, explanation FROM few_shot_examples WHERE id = ?1",
                    rusqlite::params![rowid],
                    |row| {
                        Ok(FewShotExample {
                            task_type: row.get(0)?,
                            input: row.get(1)?,
                            output: row.get(2)?,
                            explanation: row.get(3)?,
                        })
                    },
                );
                if let Ok(example) = row {
                    results.push(example);
                }
            }
        }
        results
    }

    /// Populate the in-memory embedding store by calling `client.embed` for
    /// every example currently in the database.
    ///
    /// The key used is the string form of the `SQLite` rowid for each example.
    /// Any error returned by `embed` is propagated immediately.
    pub async fn populate_embeddings_from_llm(
        &self,
        client: &dyn LlmBackend,
    ) -> Result<(), PromptError> {
        // Fetch all examples with their rowids.
        // IMPORTANT: the `conn` MutexGuard is intentionally dropped at the end of
        // this block (before any `.await` point below).  Do NOT extend the borrow
        // of `conn` into the async section — parking_lot::Mutex is not Send and
        // holding the guard across an `.await` would block other sync callers on
        // the same thread pool.
        let rows: Vec<(i64, String)> = {
            let conn = self.conn.lock();
            let mut stmt =
                conn.prepare("SELECT id, task_type || ' ' || input FROM few_shot_examples")?;
            let rows = stmt.query_map([], |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
            })?;
            let mut result = Vec::new();
            for row in rows {
                result.push(row?);
            }
            result
        };

        for (rowid, text) in rows {
            let embedding = client
                .embed(&text)
                .await
                .map_err(|e| PromptError::DbError(e.to_string()))?;
            self.embed_example(&rowid.to_string(), embedding);
        }

        Ok(())
    }

    /// Delete all examples for a task type.
    pub fn delete_by_task(&self, task_type: &str) -> Result<usize, PromptError> {
        let count = self.conn.lock().execute(
            "DELETE FROM few_shot_examples WHERE task_type = ?1",
            rusqlite::params![task_type],
        )?;
        Ok(count)
    }

    /// Total number of stored examples.
    pub fn count(&self) -> Result<i64, PromptError> {
        let conn = self.conn.lock();
        let n: i64 = conn.query_row("SELECT COUNT(*) FROM few_shot_examples", [], |r| r.get(0))?;
        Ok(n)
    }
}

// ─── ContextBuilder ───────────────────────────────────────────────────────────

/// Builds a structured context string from binary analysis data.
pub struct ContextBuilder {
    sections: Vec<(String, String)>,
}

impl ContextBuilder {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            sections: Vec::new(),
        }
    }

    /// Add a named section.
    #[must_use]
    pub fn section(mut self, title: impl Into<String>, content: impl Into<String>) -> Self {
        self.sections.push((title.into(), content.into()));
        self
    }

    /// Add a disassembly section.
    #[must_use]
    pub fn disassembly(self, asm: impl Into<String>) -> Self {
        self.section("Disassembly", asm)
    }

    /// Add a decompiled code section.
    #[must_use]
    pub fn decompiled(self, code: impl Into<String>) -> Self {
        self.section("Decompiled Code", code)
    }

    /// Add a strings section.
    #[must_use]
    pub fn strings(self, strings: &[String]) -> Self {
        self.section("Strings", strings.join("\n"))
    }

    /// Add an imports section.
    #[must_use]
    pub fn imports(self, imports: &[String]) -> Self {
        self.section("Imports", imports.join("\n"))
    }

    /// Build the final context string.
    #[must_use]
    pub fn build(&self) -> String {
        self.sections
            .iter()
            .map(|(title, content)| format!("=== {title} ===\n{content}\n"))
            .collect::<Vec<_>>()
            .join("\n")
    }
}

impl Default for ContextBuilder {
    fn default() -> Self {
        Self::new()
    }
}

// ─── PromptChain ─────────────────────────────────────────────────────────────

/// A step in a prompt chain.
#[derive(Debug, Clone)]
pub struct ChainStep {
    pub template: PromptTemplate,
    /// Variables to inject from the previous step's output.
    /// Key = variable name in template, Value = "output" (previous step's output)
    /// or a static value.
    pub inject_output_as: Option<String>,
}

/// Executes a sequence of prompt renders where each step's rendered output
/// can be injected as a variable into the next step.
pub struct PromptChain {
    steps: Vec<ChainStep>,
}

impl PromptChain {
    #[must_use]
    pub const fn new() -> Self {
        Self { steps: Vec::new() }
    }

    /// Append a step to the chain.
    pub fn push(&mut self, template: PromptTemplate, inject_output_as: Option<String>) {
        self.steps.push(ChainStep {
            template,
            inject_output_as,
        });
    }

    /// Execute the chain with an initial variable set and a callback that
    /// receives the rendered prompt and returns a synthetic "LLM response"
    /// (in tests this can be a simple echo; in production it calls an LLM).
    pub fn execute<F>(
        &self,
        initial_vars: HashMap<String, String>,
        mut process_fn: F,
    ) -> Result<Vec<String>, PromptError>
    where
        F: FnMut(&str) -> String,
    {
        let mut vars = initial_vars;
        let mut outputs: Vec<String> = Vec::with_capacity(self.steps.len());

        for (i, step) in self.steps.iter().enumerate() {
            let rendered = step
                .template
                .render(&vars)
                .map_err(|e| PromptError::ChainError {
                    step: i,
                    message: e.to_string(),
                })?;

            let output = process_fn(&rendered);

            if let Some(key) = &step.inject_output_as {
                vars.insert(key.clone(), output.clone());
            }

            outputs.push(output);
        }

        Ok(outputs)
    }
}

impl Default for PromptChain {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Built-in prompt templates ────────────────────────────────────────────────

/// Returns the full catalogue of built-in RE prompt templates.
///
/// Renamed from `builtin_templates` to `builtin_prompt_templates` to avoid a
/// spurious graph edge to `rustre-hex-template::builtin_templates`, which returns
/// binary-format templates of a completely different type.
#[must_use]
pub fn builtin_prompt_templates() -> Vec<PromptTemplate> {
    vec![
        // ── analyze_function ──────────────────────────────────────────────
        PromptTemplate::new(
            "analyze_function",
            "Analyze the following function and describe its purpose, behaviour, and any notable patterns.\n\n\
             Function Name: {{function_name}}\n\
             Architecture: {{architecture}}\n\n\
             Disassembly:\n{{disassembly}}\n\n\
             Decompiled Code:\n{{decompiled_code}}\n\n\
             Provide a concise technical analysis including: purpose, key operations, \
             data structures accessed, called functions, and security-relevant behaviour.",
            vec![
                "function_name".to_string(),
                "architecture".to_string(),
                "disassembly".to_string(),
                "decompiled_code".to_string(),
            ],
            "You are an expert reverse engineer with deep knowledge of assembly language, \
             compiler output patterns, and binary analysis.",
        ),
        // ── rename_variables ──────────────────────────────────────────────
        PromptTemplate::new(
            "rename_variables",
            "Review the following decompiled code and suggest meaningful, descriptive names \
             for all variables, parameters, and local variables.\n\n\
             Decompiled Code:\n{{decompiled_code}}\n\n\
             Return a JSON object mapping old names to new names, e.g.:\n\
             {\"v1\": \"buffer_size\", \"v2\": \"file_handle\"}",
            vec!["decompiled_code".to_string()],
            "You are an expert reverse engineer specializing in recovering original variable \
             semantics from decompiler output.",
        ),
        // ── identify_vulnerability ────────────────────────────────────────
        PromptTemplate::new(
            "identify_vulnerability",
            "Analyze the following code for security vulnerabilities. Check for:\n\
             - Buffer overflows (stack and heap)\n\
             - Use-after-free / double-free\n\
             - Format string vulnerabilities\n\
             - Integer overflows/underflows\n\
             - Race conditions\n\
             - Command injection\n\
             - Out-of-bounds reads/writes\n\n\
             Code:\n{{code}}\n\n\
             For each vulnerability found, report: type, location, severity (Critical/High/Medium/Low), \
             and a brief explanation.",
            vec!["code".to_string()],
            "You are a vulnerability researcher specializing in binary exploitation and CVE analysis.",
        ),
        // ── recover_type ──────────────────────────────────────────────────
        PromptTemplate::new(
            "recover_type",
            "Based on the following decompiled code showing struct/object access patterns, \
             infer the layout of the accessed struct or class.\n\n\
             Decompiled Code:\n{{decompiled_code}}\n\n\
             Architecture: {{architecture}}\n\
             Pointer Size: {{pointer_size}} bytes\n\n\
             Produce a C-style struct definition that matches the observed field offsets and types.",
            vec![
                "decompiled_code".to_string(),
                "architecture".to_string(),
                "pointer_size".to_string(),
            ],
            "You are an expert in binary type recovery, struct layout inference, and reverse engineering.",
        ),
        // ── identify_algorithm ────────────────────────────────────────────
        PromptTemplate::new(
            "identify_algorithm",
            "Examine the following code and determine if it implements a known algorithm \
             (cryptographic, compression, hashing, encoding, etc.).\n\n\
             Code:\n{{code}}\n\n\
             If you identify an algorithm, provide: algorithm name, variant/mode, \
             confidence level, and key identifying characteristics you found.",
            vec!["code".to_string()],
            "You are an expert in cryptography, compression algorithms, and binary pattern recognition.",
        ),
        // ── explain_obfuscation ───────────────────────────────────────────
        PromptTemplate::new(
            "explain_obfuscation",
            "The following code appears to be obfuscated. Analyze it and:\n\
             1. Identify the obfuscation techniques used\n\
             2. Explain what the code actually does\n\
             3. Suggest how to deobfuscate it\n\n\
             Obfuscated Code:\n{{obfuscated_code}}\n\n\
             Obfuscation type hint (if known): {{obfuscation_hint}}",
            vec![
                "obfuscated_code".to_string(),
                "obfuscation_hint".to_string(),
            ],
            "You are an expert in code obfuscation, deobfuscation, and malware analysis.",
        ),
        // ── suggest_yara ──────────────────────────────────────────────────
        PromptTemplate::new(
            "suggest_yara",
            "Based on the following binary sample analysis, generate a YARA rule to detect \
             similar samples.\n\n\
             Sample Info:\n{{sample_info}}\n\n\
             Notable Strings:\n{{strings}}\n\n\
             Notable Byte Patterns:\n{{byte_patterns}}\n\n\
             Imports/Exports:\n{{imports_exports}}\n\n\
             Generate a well-commented YARA rule with meaningful meta fields and \
             both string-based and byte-pattern conditions.",
            vec![
                "sample_info".to_string(),
                "strings".to_string(),
                "byte_patterns".to_string(),
                "imports_exports".to_string(),
            ],
            "You are a threat intelligence analyst and YARA rule author with expertise in \
             malware signature development.",
        ),
        // ── identify_malware_behavior ─────────────────────────────────────
        PromptTemplate::new(
            "identify_malware_behavior",
            "Analyze the following execution trace or code and describe the malware's behaviour.\n\n\
             Trace/Code:\n{{trace_or_code}}\n\n\
             Known Context:\n{{context}}\n\n\
             Describe: persistence mechanisms, C2 communication, data exfiltration, \
             lateral movement, evasion techniques, and MITRE ATT&CK mappings.",
            vec!["trace_or_code".to_string(), "context".to_string()],
            "You are a malware analyst with expertise in dynamic and static malware analysis \
             and threat intelligence.",
        ),
        // ── write_ioc ─────────────────────────────────────────────────────
        PromptTemplate::new(
            "write_ioc",
            "Based on the following malware analysis, produce a comprehensive list of \
             Indicators of Compromise (IoCs).\n\n\
             Analysis:\n{{analysis}}\n\n\
             Format the output as JSON with categories: hashes, ips, domains, urls, \
             file_paths, registry_keys, mutexes, and other.",
            vec!["analysis".to_string()],
            "You are a threat intelligence analyst specializing in IoC extraction and \
             malware attribution.",
        ),
        // ── decompiler_review ─────────────────────────────────────────────
        PromptTemplate::new(
            "decompiler_review",
            "Review the following decompiler output and correct obvious errors or \
             improve readability.\n\n\
             Original Function Name: {{function_name}}\n\
             Decompiler: {{decompiler_name}}\n\n\
             Decompiled Output:\n{{decompiled_code}}\n\n\
             Provide: corrected code, explanation of changes, and any inferences about \
             the original source code style or language.",
            vec![
                "function_name".to_string(),
                "decompiler_name".to_string(),
                "decompiled_code".to_string(),
            ],
            "You are an expert reverse engineer with deep knowledge of decompiler output \
             artefacts, compiler optimizations, and C/C++ idioms.",
        ),
    ]
}

/// A registry of prompt templates, keyed by name.
pub struct TemplateRegistry {
    templates: HashMap<String, PromptTemplate>,
}

impl TemplateRegistry {
    /// Create a registry pre-populated with the built-in templates.
    #[must_use]
    pub fn with_builtins() -> Self {
        let mut reg = Self {
            templates: HashMap::new(),
        };
        for t in builtin_prompt_templates() {
            reg.register(t);
        }
        reg
    }

    /// Create an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self {
            templates: HashMap::new(),
        }
    }

    /// Register a template.
    pub fn register(&mut self, template: PromptTemplate) {
        self.templates.insert(template.name.clone(), template);
    }

    /// Retrieve a template by name.
    pub fn get(&self, name: &str) -> Result<&PromptTemplate, PromptError> {
        self.templates
            .get(name)
            .ok_or_else(|| PromptError::TemplateNotFound(name.to_string()))
    }

    /// Number of registered templates.
    #[must_use]
    pub fn len(&self) -> usize {
        self.templates.len()
    }

    /// True if no templates are registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.templates.is_empty()
    }
}

impl Default for TemplateRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── PromptRenderer ──────────────────────────────────────────────────────

    #[test]
    fn test_render_no_vars() {
        let result = PromptRenderer::render("Hello, world!", &HashMap::new()).unwrap();
        assert_eq!(result, "Hello, world!");
    }

    #[test]
    fn test_render_single_var() {
        let mut vars = HashMap::new();
        vars.insert("name".to_string(), "malloc".to_string());
        let result = PromptRenderer::render("Function: {{name}}", &vars).unwrap();
        assert_eq!(result, "Function: malloc");
    }

    #[test]
    fn test_render_multiple_vars() {
        let result = PromptRenderer::render_pairs(
            "{{a}} + {{b}} = {{c}}",
            &[("a", "1"), ("b", "2"), ("c", "3")],
        )
        .unwrap();
        assert_eq!(result, "1 + 2 = 3");
    }

    #[test]
    fn test_render_missing_var_error() {
        let vars = HashMap::new();
        let err = PromptRenderer::render("{{missing}}", &vars).unwrap_err();
        assert!(matches!(err, PromptError::MissingVariable(_)));
    }

    #[test]
    fn test_render_repeated_var() {
        let mut vars = HashMap::new();
        vars.insert("x".to_string(), "FOO".to_string());
        let result = PromptRenderer::render("{{x}} and {{x}}", &vars).unwrap();
        assert_eq!(result, "FOO and FOO");
    }

    // ── PromptTemplate ──────────────────────────────────────────────────────

    #[test]
    fn test_template_render() {
        let t = PromptTemplate::new("test", "Task: {{task}}", vec!["task".to_string()], "system");
        let mut vars = HashMap::new();
        vars.insert("task".to_string(), "analyze".to_string());
        assert_eq!(t.render(&vars).unwrap(), "Task: analyze");
    }

    // ── Built-in templates ──────────────────────────────────────────────────

    #[test]
    fn test_builtin_prompt_templates_count() {
        let templates = builtin_prompt_templates();
        assert!(
            templates.len() >= 9,
            "Expected at least 9 built-in templates"
        );
    }

    #[test]
    fn test_builtin_template_names() {
        let templates = builtin_prompt_templates();
        let names: Vec<&str> = templates.iter().map(|t| t.name.as_str()).collect();
        assert!(names.contains(&"analyze_function"));
        assert!(names.contains(&"rename_variables"));
        assert!(names.contains(&"identify_vulnerability"));
        assert!(names.contains(&"recover_type"));
        assert!(names.contains(&"identify_algorithm"));
        assert!(names.contains(&"explain_obfuscation"));
        assert!(names.contains(&"suggest_yara"));
        assert!(names.contains(&"identify_malware_behavior"));
        assert!(names.contains(&"write_ioc"));
    }

    #[test]
    fn test_builtin_analyze_function_render() {
        let reg = TemplateRegistry::with_builtins();
        let t = reg.get("analyze_function").unwrap();
        let mut vars = HashMap::new();
        vars.insert("function_name".to_string(), "sub_140001000".to_string());
        vars.insert("architecture".to_string(), "x86_64".to_string());
        vars.insert(
            "disassembly".to_string(),
            "push rbp\nmov rbp, rsp".to_string(),
        );
        vars.insert(
            "decompiled_code".to_string(),
            "void sub_140001000() {}".to_string(),
        );
        let rendered = t.render(&vars).unwrap();
        assert!(rendered.contains("sub_140001000"));
        assert!(rendered.contains("x86_64"));
    }

    // ── TemplateRegistry ────────────────────────────────────────────────────

    #[test]
    fn test_registry_with_builtins() {
        let reg = TemplateRegistry::with_builtins();
        assert!(reg.len() >= 9);
    }

    #[test]
    fn test_registry_get_not_found() {
        let reg = TemplateRegistry::new();
        let err = reg.get("nonexistent").unwrap_err();
        assert!(matches!(err, PromptError::TemplateNotFound(_)));
    }

    #[test]
    fn test_registry_register_and_get() {
        let mut reg = TemplateRegistry::new();
        let t = PromptTemplate::new("my_template", "{{x}}", vec!["x".to_string()], "sys");
        reg.register(t);
        assert_eq!(reg.len(), 1);
        assert!(!reg.is_empty());
        let got = reg.get("my_template").unwrap();
        assert_eq!(got.name, "my_template");
    }

    // ── ContextBuilder ──────────────────────────────────────────────────────

    #[test]
    fn test_context_builder_empty() {
        let ctx = ContextBuilder::new().build();
        assert!(ctx.is_empty());
    }

    #[test]
    fn test_context_builder_sections() {
        let ctx = ContextBuilder::new().section("Title", "Content").build();
        assert!(ctx.contains("=== Title ==="));
        assert!(ctx.contains("Content"));
    }

    #[test]
    fn test_context_builder_helpers() {
        let ctx = ContextBuilder::new()
            .disassembly("push rbp")
            .decompiled("int foo() { return 0; }")
            .strings(&["Hello".to_string(), "World".to_string()])
            .imports(&["malloc".to_string()])
            .build();
        assert!(ctx.contains("=== Disassembly ==="));
        assert!(ctx.contains("=== Decompiled Code ==="));
        assert!(ctx.contains("=== Strings ==="));
        assert!(ctx.contains("=== Imports ==="));
    }

    // ── FewShotDatabase ─────────────────────────────────────────────────────

    #[test]
    fn test_few_shot_db_insert_and_get() {
        let db = FewShotDatabase::in_memory().unwrap();
        let ex = FewShotExample {
            task_type: "rename_variables".to_string(),
            input: "int v1 = v2 + 3;".to_string(),
            output: "int counter = base_value + 3;".to_string(),
            explanation: "v1 increments a counter, v2 is a base value".to_string(),
        };
        let id = db.insert(&ex).unwrap();
        assert!(id > 0);

        let results = db.get_by_task("rename_variables", 10).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].input, "int v1 = v2 + 3;");
    }

    #[test]
    fn test_few_shot_db_count() {
        let db = FewShotDatabase::in_memory().unwrap();
        assert_eq!(db.count().unwrap(), 0);
        let ex = FewShotExample {
            task_type: "test".to_string(),
            input: "a".to_string(),
            output: "b".to_string(),
            explanation: "c".to_string(),
        };
        db.insert(&ex).unwrap();
        assert_eq!(db.count().unwrap(), 1);
    }

    #[test]
    fn test_few_shot_db_delete() {
        let db = FewShotDatabase::in_memory().unwrap();
        let ex = FewShotExample {
            task_type: "vuln".to_string(),
            input: "x".to_string(),
            output: "y".to_string(),
            explanation: "z".to_string(),
        };
        db.insert(&ex).unwrap();
        let deleted = db.delete_by_task("vuln").unwrap();
        assert_eq!(deleted, 1);
        assert_eq!(db.count().unwrap(), 0);
    }

    #[test]
    fn test_few_shot_db_filter_by_task() {
        let db = FewShotDatabase::in_memory().unwrap();
        for i in 0..5 {
            db.insert(&FewShotExample {
                task_type: "type_a".to_string(),
                input: format!("input_{i}"),
                output: format!("output_{i}"),
                explanation: "x".to_string(),
            })
            .unwrap();
        }
        db.insert(&FewShotExample {
            task_type: "type_b".to_string(),
            input: "b_in".to_string(),
            output: "b_out".to_string(),
            explanation: "b".to_string(),
        })
        .unwrap();

        let a_results = db.get_by_task("type_a", 3).unwrap();
        assert_eq!(a_results.len(), 3);
        let b_results = db.get_by_task("type_b", 10).unwrap();
        assert_eq!(b_results.len(), 1);
        let c_results = db.get_by_task("type_c", 10).unwrap();
        assert_eq!(c_results.len(), 0);
    }

    // ── PromptChain ─────────────────────────────────────────────────────────

    #[test]
    fn test_prompt_chain_single_step() {
        let mut chain = PromptChain::new();
        let t = PromptTemplate::new("step1", "Analyze: {{code}}", vec!["code".to_string()], "");
        chain.push(t, None);

        let mut vars = HashMap::new();
        vars.insert("code".to_string(), "int x = 1;".to_string());

        let outputs = chain
            .execute(vars, |prompt| format!("Result of: {prompt}"))
            .unwrap();
        assert_eq!(outputs.len(), 1);
        assert!(outputs[0].contains("int x = 1;"));
    }

    #[test]
    fn test_prompt_chain_output_forwarding() {
        let mut chain = PromptChain::new();
        let t1 = PromptTemplate::new("step1", "Step1: {{input}}", vec!["input".to_string()], "");
        let t2 = PromptTemplate::new(
            "step2",
            "Step2 using: {{previous}}",
            vec!["previous".to_string()],
            "",
        );
        chain.push(t1, Some("previous".to_string()));
        chain.push(t2, None);

        let mut vars = HashMap::new();
        vars.insert("input".to_string(), "hello".to_string());

        let outputs = chain.execute(vars, str::to_uppercase).unwrap();
        assert_eq!(outputs.len(), 2);
        // second step should contain the uppercased first output
        assert!(
            outputs[1].contains("STEP1: HELLO")
                || outputs[1].contains("step1: hello".to_uppercase().as_str())
        );
    }

    #[test]
    fn test_prompt_error_chain_error() {
        let e = PromptError::ChainError {
            step: 2,
            message: "bad var".to_string(),
        };
        assert!(e.to_string().contains("step 2"));
    }
}

// ─── Spec-required types ──────────────────────────────────────────────────────

/// A template variable declaration (spec).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateVar {
    pub name: String,
    pub default: Option<String>,
    pub required: bool,
}

impl TemplateVar {
    #[must_use]
    pub fn required(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            default: None,
            required: true,
        }
    }

    #[must_use]
    pub fn optional(name: impl Into<String>, default: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            default: Some(default.into()),
            required: false,
        }
    }
}

/// Spec-compliant prompt template with `TemplateVar` declarations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpecPromptTemplate {
    pub name: String,
    pub description: String,
    pub template: String,
    pub vars: Vec<TemplateVar>,
}

impl SpecPromptTemplate {
    #[must_use]
    pub fn new(name: impl Into<String>, template: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            description: String::new(),
            template: template.into(),
            vars: Vec::new(),
        }
    }

    #[must_use]
    pub fn with_var(mut self, v: TemplateVar) -> Self {
        self.vars.push(v);
        self
    }

    /// Render the template, substituting `{{var_name}}` placeholders.
    /// Returns an error if a required variable is missing.
    pub fn render(&self, vars: &HashMap<String, String>) -> Result<String, SpecPromptError> {
        let mut output = self.template.clone();
        for v in &self.vars {
            let placeholder = format!("{{{{{}}}}}", v.name);
            if output.contains(&placeholder) {
                let value = if let Some(val) = vars.get(&v.name) { val.clone() } else {
                    if v.required {
                        return Err(SpecPromptError::MissingVar(v.name.clone()));
                    }
                    v.default.clone().unwrap_or_default()
                };
                output = output.replace(&placeholder, &value);
            }
        }
        // Also substitute any ad-hoc vars not in the declared list.
        for (k, val) in vars {
            let placeholder = format!("{{{{{k}}}}}");
            output = output.replace(&placeholder, val);
        }
        Ok(output)
    }

    #[must_use]
    pub fn required_vars(&self) -> Vec<&TemplateVar> {
        self.vars.iter().filter(|v| v.required).collect()
    }
}

/// Spec-required prompt errors.
#[derive(Debug, thiserror::Error)]
pub enum SpecPromptError {
    #[error("missing required variable: {0}")]
    MissingVar(String),
    #[error("template not found: {0}")]
    NotFound(String),
    #[error("render error: {0}")]
    RenderError(String),
}

/// Spec-compliant prompt template registry.
pub struct PromptRegistry {
    pub templates: HashMap<String, SpecPromptTemplate>,
}

impl PromptRegistry {
    #[must_use]
    pub fn new() -> Self {
        let mut reg = Self {
            templates: HashMap::new(),
        };
        reg.load_builtins();
        reg
    }

    fn load_builtins(&mut self) {
        let builtins: Vec<(&str, &str)> = vec![
            (
                "disassembly_analysis",
                "Analyze disassembly at {{address}}:\n{{code}}\nIdentify: purpose, vulnerabilities, calling convention.",
            ),
            (
                "decompile_review",
                "Review decompiled code from {{binary}}:\n{{code}}\nIdentify: algorithm, data structures, bugs.",
            ),
            (
                "malware_classify",
                "Classify behavior:\nImports: {{imports}}\nStrings: {{strings}}\nBehavior: {{behavior}}\nProvide: family, capabilities, IOCs.",
            ),
            (
                "vuln_analysis",
                "Find vulnerabilities in {{func_name}}:\n{{code}}\nCheck: buffer overflows, UAF, integer overflows, format strings.",
            ),
            ("explain_code", "Explain this {{language}} code:\n{{code}}"),
            (
                "suggest_name",
                "Suggest name for function:\nDisasm: {{disasm}}\nCallers: {{callers}}\nStrings: {{strings}}",
            ),
        ];

        for (name, tmpl) in builtins {
            let t = SpecPromptTemplate::new(name, tmpl);
            self.templates.insert(name.to_string(), t);
        }
    }

    #[must_use]
    pub fn get(&self, name: &str) -> Option<&SpecPromptTemplate> {
        self.templates.get(name)
    }

    pub fn register(&mut self, t: SpecPromptTemplate) {
        self.templates.insert(t.name.clone(), t);
    }

    #[must_use]
    pub fn list_names(&self) -> Vec<String> {
        let mut names: Vec<String> = self.templates.keys().cloned().collect();
        names.sort();
        names
    }

    #[must_use]
    pub fn count(&self) -> usize {
        self.templates.len()
    }
}

impl Default for PromptRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod spec_tests {
    use super::*;

    #[test]
    fn test_template_var_required() {
        let v = TemplateVar::required("code");
        assert!(v.required);
        assert!(v.default.is_none());
    }

    #[test]
    fn test_template_var_optional() {
        let v = TemplateVar::optional("lang", "rust");
        assert!(!v.required);
        assert_eq!(v.default, Some("rust".to_string()));
    }

    #[test]
    fn test_spec_prompt_template_new() {
        let t = SpecPromptTemplate::new("test", "Hello {{name}}");
        assert_eq!(t.name, "test");
        assert!(t.vars.is_empty());
    }

    #[test]
    fn test_spec_prompt_template_with_var() {
        let t = SpecPromptTemplate::new("t", "{{x}}").with_var(TemplateVar::required("x"));
        assert_eq!(t.vars.len(), 1);
    }

    #[test]
    fn test_spec_prompt_render_ok() {
        let t =
            SpecPromptTemplate::new("t", "Hello {{name}}!").with_var(TemplateVar::required("name"));
        let mut vars = HashMap::new();
        vars.insert("name".to_string(), "world".to_string());
        assert_eq!(t.render(&vars).unwrap(), "Hello world!");
    }

    #[test]
    fn test_spec_prompt_render_missing_required() {
        let t = SpecPromptTemplate::new("t", "{{code}}").with_var(TemplateVar::required("code"));
        let vars = HashMap::new();
        let err = t.render(&vars).unwrap_err();
        assert!(matches!(err, SpecPromptError::MissingVar(_)));
    }

    #[test]
    fn test_spec_prompt_render_optional_default() {
        let t = SpecPromptTemplate::new("t", "lang: {{lang}}")
            .with_var(TemplateVar::optional("lang", "rust"));
        let vars = HashMap::new();
        assert_eq!(t.render(&vars).unwrap(), "lang: rust");
    }

    #[test]
    fn test_spec_prompt_required_vars() {
        let t = SpecPromptTemplate::new("t", "{{a}} {{b}}")
            .with_var(TemplateVar::required("a"))
            .with_var(TemplateVar::optional("b", "default"));
        let req = t.required_vars();
        assert_eq!(req.len(), 1);
        assert_eq!(req[0].name, "a");
    }

    #[test]
    fn test_prompt_registry_new_has_builtins() {
        let reg = PromptRegistry::new();
        assert_eq!(reg.count(), 6);
    }

    #[test]
    fn test_prompt_registry_list_names() {
        let reg = PromptRegistry::new();
        let names = reg.list_names();
        assert!(names.contains(&"disassembly_analysis".to_string()));
        assert!(names.contains(&"decompile_review".to_string()));
        assert!(names.contains(&"malware_classify".to_string()));
        assert!(names.contains(&"vuln_analysis".to_string()));
        assert!(names.contains(&"explain_code".to_string()));
        assert!(names.contains(&"suggest_name".to_string()));
    }

    #[test]
    fn test_prompt_registry_get_existing() {
        let reg = PromptRegistry::new();
        let t = reg.get("disassembly_analysis");
        assert!(t.is_some());
        assert_eq!(t.unwrap().name, "disassembly_analysis");
    }

    #[test]
    fn test_prompt_registry_get_missing() {
        let reg = PromptRegistry::new();
        assert!(reg.get("nonexistent").is_none());
    }

    #[test]
    fn test_prompt_registry_register_custom() {
        let mut reg = PromptRegistry::new();
        let t = SpecPromptTemplate::new("custom", "{{x}}");
        reg.register(t);
        assert_eq!(reg.count(), 7);
        assert!(reg.get("custom").is_some());
    }

    #[test]
    fn test_spec_prompt_error_display() {
        let e = SpecPromptError::MissingVar("code".to_string());
        assert!(e.to_string().contains("code"));
        let e2 = SpecPromptError::NotFound("tmpl".to_string());
        assert!(e2.to_string().contains("tmpl"));
        let e3 = SpecPromptError::RenderError("bad".to_string());
        assert!(e3.to_string().contains("bad"));
    }

    #[test]
    fn test_prompt_registry_default() {
        let reg = PromptRegistry::default();
        assert_eq!(reg.count(), 6);
    }

    #[test]
    fn test_disassembly_analysis_template_render() {
        let reg = PromptRegistry::new();
        let t = reg.get("disassembly_analysis").unwrap();
        let mut vars = HashMap::new();
        vars.insert("address".to_string(), "0x1000".to_string());
        vars.insert("code".to_string(), "push rbp".to_string());
        let rendered = t.render(&vars).unwrap();
        assert!(rendered.contains("0x1000"));
        assert!(rendered.contains("push rbp"));
    }

    #[test]
    fn test_malware_classify_template_render() {
        let reg = PromptRegistry::new();
        let t = reg.get("malware_classify").unwrap();
        let mut vars = HashMap::new();
        vars.insert("imports".to_string(), "WinExec".to_string());
        vars.insert("strings".to_string(), "cmd.exe".to_string());
        vars.insert("behavior".to_string(), "executes commands".to_string());
        let rendered = t.render(&vars).unwrap();
        assert!(rendered.contains("WinExec"));
    }
}

// ─── §31.6 Prompt Library ────────────────────────────────────────────────────
//
// The types below implement the full RE-specific prompt library described in
// spec §31.6.  They live alongside the older `PromptTemplate` / `TemplateRegistry`
// types to preserve backwards compatibility; the new rich types are exported
// from the `engine` sub-module as well as re-exported at crate root for
// convenience.

pub mod engine {
    use serde::{Deserialize, Serialize};
    use std::collections::HashMap;
    use std::path::Path;

    // ── PromptVariable ───────────────────────────────────────────────────────

    /// A declared variable inside a [`RichTemplate`].
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct PromptVariable {
        /// Variable name (used in `{{name}}` placeholders).
        pub name: String,
        /// Human-readable description of what to put here.
        pub description: String,
        /// Whether the variable must be supplied at render time.
        pub required: bool,
        /// Default value substituted when the variable is absent and not required.
        pub default: Option<String>,
    }

    impl PromptVariable {
        /// Create a required variable with no default.
        #[must_use]
        pub fn required(name: impl Into<String>, description: impl Into<String>) -> Self {
            Self {
                name: name.into(),
                description: description.into(),
                required: true,
                default: None,
            }
        }

        /// Create an optional variable with a default value.
        #[must_use]
        pub fn optional(
            name: impl Into<String>,
            description: impl Into<String>,
            default: impl Into<String>,
        ) -> Self {
            Self {
                name: name.into(),
                description: description.into(),
                required: false,
                default: Some(default.into()),
            }
        }
    }

    // ── PromptCategory ───────────────────────────────────────────────────────

    /// High-level category for grouping [`RichTemplate`] entries.
    #[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
    pub enum PromptCategory {
        /// Understand / rename a decompiled function.
        FunctionAnalysis,
        /// Classify malware families, capabilities, persistence.
        MalwareAnalysis,
        /// Find exploitable bugs in binaries.
        VulnerabilityResearch,
        /// Recover struct / class / enum definitions from access patterns.
        TypeRecovery,
        /// Detect crypto primitives, hash functions, PRNGs.
        CryptoIdentification,
        /// Plain-language explanation of decompiled or obfuscated code.
        ExplainCode,
        /// Suggest meaningful names for functions, variables, parameters.
        NameSuggestion,
        /// Diff two versions of a function to find patch deltas.
        CompareVersions,
        /// User-defined / catch-all.
        Custom,
    }

    // ── RichTemplate (spec name: PromptTemplate) ─────────────────────────────

    /// A fully-described RE prompt template (spec §31.6 `PromptTemplate`).
    ///
    /// Named `RichTemplate` here to avoid a name collision with the simpler
    /// `crate::PromptTemplate` that is used by the rest of the framework.
    /// It is re-exported as `PromptTemplate` from the `engine` module so callers
    /// that import from `rustre_agent_prompts::engine` get the spec-compliant name.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct RichTemplate {
        /// Stable identifier (e.g. `"analyze_function"`).
        pub id: String,
        /// Short human-readable name.
        pub name: String,
        /// One-paragraph description.
        pub description: String,
        /// The prompt body; use `{{var_name}}` for substitutions.
        pub template: String,
        /// Declared variables (may include optional variables with defaults).
        pub variables: Vec<PromptVariable>,
        /// High-level category.
        pub category: PromptCategory,
        /// When to use this template.
        pub use_case: String,
    }

    /// Spec §31.6 alias so `engine::PromptTemplate` refers to `RichTemplate`.
    pub type PromptTemplate = RichTemplate;

    // ── BUILTIN_PROMPTS ──────────────────────────────────────────────────────

    /// Returns the catalogue of 12+ built-in RE prompt templates defined in
    /// spec §31.6.
    #[must_use]
    pub fn builtin_prompts() -> Vec<RichTemplate> {
        vec![
            // 1. analyze_function ────────────────────────────────────────────
            RichTemplate {
                id: "analyze_function".into(),
                name: "Analyze Function".into(),
                description: "Full reverse-engineering analysis of a decompiled function: \
                              name suggestion, summary, parameter types, local variable names, \
                              and security notes."
                    .into(),
                template: "You are a binary analysis expert. Analyze the following decompiled \
function and provide:\n\
1. A meaningful function name\n\
2. What the function does (2-3 sentences)\n\
3. Parameter names and types\n\
4. Local variable names\n\
5. Any security concerns\n\n\
Decompiled code:\n\
{{code}}\n\n\
Xrefs from callers:\n\
{{callers}}\n\n\
Adjacent function names:\n\
{{neighbors}}"
                    .into(),
                variables: vec![
                    PromptVariable::required(
                        "code",
                        "Decompiled C/pseudo-C source of the function",
                    ),
                    PromptVariable::optional(
                        "callers",
                        "List of caller function names / addresses",
                        "(none)",
                    ),
                    PromptVariable::optional(
                        "neighbors",
                        "Names of adjacent functions in the binary",
                        "(none)",
                    ),
                ],
                category: PromptCategory::FunctionAnalysis,
                use_case: "Use when you want a comprehensive one-shot analysis of an unknown \
                           decompiled function including renaming suggestions."
                    .into(),
            },
            // 2. name_variables ──────────────────────────────────────────────
            RichTemplate {
                id: "name_variables".into(),
                name: "Name Variables".into(),
                description: "Suggest meaningful names for auto-generated variable / parameter \
                              identifiers (var_1, param_2, …) in decompiler output."
                    .into(),
                template: "Given this decompiled C code, suggest meaningful names for all \
variables (var_1, var_2, etc.) and parameters (param_1, etc.). \
Output a JSON object mapping old names to new names.\n\n\
Code:\n\
{{code}}\n\n\
Output format: {{\"var_1\": \"new_name\", ...}}"
                    .into(),
                variables: vec![PromptVariable::required("code", "Decompiled function body")],
                category: PromptCategory::NameSuggestion,
                use_case: "Apply after initial decompilation to convert machine-generated \
                           identifiers into readable names before deeper analysis."
                    .into(),
            },
            // 3. identify_algorithm ──────────────────────────────────────────
            RichTemplate {
                id: "identify_algorithm".into(),
                name: "Identify Algorithm".into(),
                description: "Detect whether a function implements a known algorithm \
                              (sort, hash, cipher, compression, encoding, …)."
                    .into(),
                template: "Analyze this function and determine if it implements a known \
algorithm (sorting, hashing, encryption, compression, etc.). \
If so, identify it precisely.\n\n\
Code:\n\
{{code}}\n\n\
Constants found: {{constants}}\n\n\
Answer with: algorithm name, confidence (0-100), evidence, and any variant details."
                    .into(),
                variables: vec![
                    PromptVariable::required("code", "Decompiled or disassembled function"),
                    PromptVariable::optional(
                        "constants",
                        "Magic numbers / constants found in the function",
                        "(none)",
                    ),
                ],
                category: PromptCategory::CryptoIdentification,
                use_case: "Use to fingerprint cryptographic primitives, well-known hash \
                           functions, compression routines, or encoding schemes."
                    .into(),
            },
            // 4. summarize_malware ────────────────────────────────────────────
            RichTemplate {
                id: "summarize_malware".into(),
                name: "Summarize Malware".into(),
                description: "Produce a structured malware report from observed behaviors, \
                              network IOCs, and API calls."
                    .into(),
                template: "You are a malware analyst. Given this binary's analysis data, \
provide a malware report:\n\n\
Behaviors observed:\n\
{{behaviors}}\n\n\
Networked IOCs:\n\
{{iocs}}\n\n\
API calls:\n\
{{api_calls}}\n\n\
Provide: malware family classification, capabilities, C2 details if present, \
persistence mechanisms, detection recommendations."
                    .into(),
                variables: vec![
                    PromptVariable::required("behaviors", "Observed runtime behaviors"),
                    PromptVariable::optional(
                        "iocs",
                        "Network indicators of compromise (IPs, domains, URLs)",
                        "(none)",
                    ),
                    PromptVariable::optional(
                        "api_calls",
                        "Imported or dynamically resolved API calls",
                        "(none)",
                    ),
                ],
                category: PromptCategory::MalwareAnalysis,
                use_case: "Use at the end of dynamic / static analysis to produce an \
                           analyst-facing malware report."
                    .into(),
            },
            // 5. find_vulnerability ──────────────────────────────────────────
            RichTemplate {
                id: "find_vulnerability".into(),
                name: "Find Vulnerability".into(),
                description: "Scan decompiled code for exploitable security vulnerabilities \
                              with severity ratings."
                    .into(),
                template: "Analyze this decompiled code for security vulnerabilities. Focus on:\n\
- Buffer overflows (unbounded string operations, size miscalculations)\n\
- Integer overflows/underflows\n\
- Use after free\n\
- Format string vulnerabilities\n\
- Injection risks\n\
- Logic bugs\n\n\
Code:\n\
{{code}}\n\n\
For each finding: location, vulnerability type, severity (Critical/High/Medium/Low), \
exploitation scenario."
                    .into(),
                variables: vec![PromptVariable::required(
                    "code",
                    "Decompiled function or code region to audit",
                )],
                category: PromptCategory::VulnerabilityResearch,
                use_case: "Use when hunting for exploitable bugs in a target function or \
                           module during a security assessment."
                    .into(),
            },
            // 6. compare_versions ─────────────────────────────────────────────
            RichTemplate {
                id: "compare_versions".into(),
                name: "Compare Versions".into(),
                description: "Diff two versions of the same function and explain the \
                              semantic changes (patch analysis, regression hunting)."
                    .into(),
                template:
                    "Compare these two versions of the same function and explain what changed:\n\n\
Version A ({{version_a}}):\n\
{{code_a}}\n\n\
Version B ({{version_b}}):\n\
{{code_b}}\n\n\
Explain: what was added, removed, or modified; if this appears to be a security patch; \
what bug was being fixed."
                        .into(),
                variables: vec![
                    PromptVariable::optional(
                        "version_a",
                        "Label for the older version (e.g. commit hash)",
                        "v1",
                    ),
                    PromptVariable::required("code_a", "Decompiled source of the older version"),
                    PromptVariable::optional("version_b", "Label for the newer version", "v2"),
                    PromptVariable::required("code_b", "Decompiled source of the newer version"),
                ],
                category: PromptCategory::CompareVersions,
                use_case: "Use to understand patch diffs, spot silent security fixes, or \
                           track regression introductions between binary releases."
                    .into(),
            },
            // 7. explain_obfuscation ──────────────────────────────────────────
            RichTemplate {
                id: "explain_obfuscation".into(),
                name: "Explain Obfuscation".into(),
                description: "Identify obfuscation techniques and recover the underlying \
                              program logic from obfuscated code."
                    .into(),
                template: "This code appears obfuscated. Explain what obfuscation techniques \
are being used and what the underlying logic might be:\n\n\
{{code}}\n\n\
Identify: obfuscation type, how to deobfuscate, what the true behavior is."
                    .into(),
                variables: vec![PromptVariable::required(
                    "code",
                    "Obfuscated function or code region",
                )],
                category: PromptCategory::ExplainCode,
                use_case: "Use against heavily obfuscated malware or protected code to \
                           understand what the code actually does."
                    .into(),
            },
            // 8. crypto_analysis ──────────────────────────────────────────────
            RichTemplate {
                id: "crypto_analysis".into(),
                name: "Crypto Analysis".into(),
                description: "Deep analysis of a cryptographic function: algorithm, mode, \
                              key size, and implementation correctness."
                    .into(),
                template:
                    "Analyze this function that appears to perform cryptographic operations.\n\n\
Code:\n\
{{code}}\n\
Constants: {{constants}}\n\n\
Determine: algorithm, mode of operation, key size, whether implementation is custom \
or standard library."
                        .into(),
                variables: vec![
                    PromptVariable::required("code", "Decompiled cryptographic function"),
                    PromptVariable::optional(
                        "constants",
                        "Numeric constants extracted from the function",
                        "(none)",
                    ),
                ],
                category: PromptCategory::CryptoIdentification,
                use_case: "Use when a function handles key material, ciphertext, or \
                           exhibits S-box / round-constant patterns."
                    .into(),
            },
            // 9. rop_chain_analysis ───────────────────────────────────────────
            RichTemplate {
                id: "rop_chain_analysis".into(),
                name: "ROP Chain Analysis".into(),
                description: "Analyze a sequence of ROP gadgets to understand the exploit \
                              payload's intent."
                    .into(),
                template: "Analyze this sequence of gadgets that may form a ROP chain:\n\
{{gadgets}}\n\n\
Determine: what the chain attempts to do, what registers/memory it uses, if this is \
a known exploit technique."
                    .into(),
                variables: vec![PromptVariable::required(
                    "gadgets",
                    "Ordered list of ROP gadgets with addresses and mnemonics",
                )],
                category: PromptCategory::VulnerabilityResearch,
                use_case: "Use to understand exploit payloads captured from crash dumps, \
                           network captures, or exploit samples."
                    .into(),
            },
            // 10. string_deobfuscation ────────────────────────────────────────
            RichTemplate {
                id: "string_deobfuscation".into(),
                name: "String Deobfuscation".into(),
                description: "Recover runtime-decoded strings by analyzing the decoder \
                              function and the encoded blobs."
                    .into(),
                template: "This function decodes strings at runtime. Analyze the decoding \
algorithm and if possible, decode the strings.\n\n\
Decoder function:\n\
{{code}}\n\n\
Encoded strings (hex):\n\
{{encoded_strings}}\n\n\
Identify: encoding method, key if any, decoded values if determinable."
                    .into(),
                variables: vec![
                    PromptVariable::required("code", "Decompiled string-decoding function"),
                    PromptVariable::optional(
                        "encoded_strings",
                        "Hex-encoded string blobs passed to the decoder",
                        "(none)",
                    ),
                ],
                category: PromptCategory::ExplainCode,
                use_case: "Use against malware that stores all strings in encoded form to \
                           evade static string scanning."
                    .into(),
            },
            // 11. type_inference ──────────────────────────────────────────────
            RichTemplate {
                id: "type_inference".into(),
                name: "Type Inference".into(),
                description: "Recover struct / class layout from memory access patterns \
                              observed in decompiler output."
                    .into(),
                template: "Given these memory access patterns, infer the data structure \
being accessed:\n\
{{access_patterns}}\n\n\
Suggest: struct definition with field names and types, array or pointer relationships, \
class hierarchy if applicable."
                    .into(),
                variables: vec![PromptVariable::required(
                    "access_patterns",
                    "Memory dereferences and field accesses from the decompiler",
                )],
                category: PromptCategory::TypeRecovery,
                use_case: "Use when a decompiler shows many `*(obj + offset)` patterns to \
                           reconstruct the underlying struct or class definition."
                    .into(),
            },
            // 12. mitre_mapping ───────────────────────────────────────────────
            RichTemplate {
                id: "mitre_mapping".into(),
                name: "MITRE ATT&CK Mapping".into(),
                description: "Map observed malware behaviors to MITRE ATT&CK tactics and \
                              techniques for threat-intelligence reporting."
                    .into(),
                template: "Given these malware behaviors, map them to MITRE ATT&CK tactics \
and techniques:\n\
{{behaviors}}\n\n\
For each behavior: ATT&CK tactic, technique ID and name, confidence."
                    .into(),
                variables: vec![PromptVariable::required(
                    "behaviors",
                    "Observed malware behaviors (persistence, C2, evasion, …)",
                )],
                category: PromptCategory::MalwareAnalysis,
                use_case: "Use at the conclusion of malware analysis to produce a structured \
                           ATT&CK report for threat-intelligence feeds or SIEM rules."
                    .into(),
            },
            // 13. function_naming ─────────────────────────────────────────────
            RichTemplate {
                id: "function_naming".into(),
                name: "Function Naming".into(),
                description: "Propose a descriptive name for an unknown function based on \
                              its behavior and call context."
                    .into(),
                template: "Suggest a concise, descriptive name for this function.\n\n\
Decompiled code:\n\
{{code}}\n\n\
Callers: {{callers}}\n\
Callees: {{callees}}\n\
Strings referenced: {{strings}}\n\n\
Respond with: suggested name (snake_case), confidence (0-100), rationale (1-2 sentences)."
                    .into(),
                variables: vec![
                    PromptVariable::required("code", "Decompiled function body"),
                    PromptVariable::optional(
                        "callers",
                        "Names / addresses of calling functions",
                        "(none)",
                    ),
                    PromptVariable::optional(
                        "callees",
                        "Names of functions called by this function",
                        "(none)",
                    ),
                    PromptVariable::optional(
                        "strings",
                        "String literals referenced in this function",
                        "(none)",
                    ),
                ],
                category: PromptCategory::NameSuggestion,
                use_case: "Use when you want a quick name suggestion without full analysis.".into(),
            },
            // 14. explain_code ────────────────────────────────────────────────
            RichTemplate {
                id: "explain_code".into(),
                name: "Explain Code".into(),
                description: "Plain-English explanation of what a decompiled or \
                              disassembled code block does."
                    .into(),
                template: "Explain this {{language}} code in plain English. \
Assume the reader is a security analyst who is not a compiler expert.\n\n\
{{code}}"
                    .into(),
                variables: vec![
                    PromptVariable::required("code", "Code block to explain"),
                    PromptVariable::optional(
                        "language",
                        "Language or notation (C, pseudo-C, x86 asm, …)",
                        "decompiled C",
                    ),
                ],
                category: PromptCategory::ExplainCode,
                use_case: "Use when you need a quick prose summary of a code block to \
                           include in a report or to share with a non-expert colleague."
                    .into(),
            },
        ]
    }

    // ── PromptEngine ─────────────────────────────────────────────────────────

    /// Errors produced by [`PromptEngine`].
    #[derive(Debug, thiserror::Error)]
    pub enum EngineError {
        #[error("template not found: {0}")]
        NotFound(String),
        #[error("missing required variable '{var}' for template '{template}'")]
        MissingVariable { template: String, var: String },
        #[error("I/O error: {0}")]
        Io(#[from] std::io::Error),
        #[error("JSON error: {0}")]
        Json(#[from] serde_json::Error),
        #[error("error: {0}")]
        Other(String),
    }

    impl From<anyhow::Error> for EngineError {
        fn from(e: anyhow::Error) -> Self {
            Self::Other(e.to_string())
        }
    }

    /// The main engine for the §31.6 prompt library.
    ///
    /// # Quick start
    /// ```ignore
    /// use rustre_agent_prompts::engine::PromptEngine;
    /// use std::collections::HashMap;
    ///
    /// let engine = PromptEngine::new();
    /// let mut vars = HashMap::new();
    /// vars.insert("code".to_string(), "int x = *(p + 8);".to_string());
    /// let prompt = engine.render("type_inference", &vars).unwrap();
    /// ```
    pub struct PromptEngine {
        templates: HashMap<String, RichTemplate>,
    }

    impl PromptEngine {
        /// Create a new engine pre-loaded with all built-in templates.
        #[must_use]
        pub fn new() -> Self {
            let mut engine = Self {
                templates: HashMap::new(),
            };
            for t in builtin_prompts() {
                engine.templates.insert(t.id.clone(), t);
            }
            engine
        }

        /// Load additional templates from a directory.
        ///
        /// Each file may be:
        /// - `.json` — a single [`RichTemplate`] or a `Vec<RichTemplate>`.
        /// - `.md`   — treated as a template with id = file stem, template = file
        ///   contents, no declared variables, category = `Custom`.
        ///
        /// Existing templates with the same `id` are **overwritten**.
        pub fn load_from_dir(&mut self, dir: &Path) -> Result<(), EngineError> {
            let entries = std::fs::read_dir(dir)?;
            for entry in entries.flatten() {
                let path = entry.path();
                let Some(ext) = path.extension().and_then(|e| e.to_str()) else {
                    continue;
                };

                match ext {
                    "json" => {
                        let content = std::fs::read_to_string(&path)?;
                        // Try array first, then single object.
                        if let Ok(templates) = serde_json::from_str::<Vec<RichTemplate>>(&content) {
                            for t in templates {
                                self.templates.insert(t.id.clone(), t);
                            }
                        } else if let Ok(t) = serde_json::from_str::<RichTemplate>(&content) {
                            self.templates.insert(t.id.clone(), t);
                        }
                        // Silently skip unrecognised JSON shapes.
                    }
                    "md" => {
                        let content = std::fs::read_to_string(&path)?;
                        let stem = path
                            .file_stem()
                            .and_then(|s| s.to_str())
                            .unwrap_or("custom")
                            .to_string();
                        let t = RichTemplate {
                            id: stem.clone(),
                            name: stem,
                            description: "Custom markdown template.".into(),
                            template: content,
                            variables: Vec::new(),
                            category: PromptCategory::Custom,
                            use_case: String::new(),
                        };
                        self.templates.insert(t.id.clone(), t);
                    }
                    _ => {}
                }
            }
            Ok(())
        }

        /// Retrieve a template by id.
        #[must_use]
        pub fn get(&self, id: &str) -> Option<&RichTemplate> {
            self.templates.get(id)
        }

        /// Register or replace a template.
        pub fn register(&mut self, template: RichTemplate) {
            self.templates.insert(template.id.clone(), template);
        }

        /// Render a template by id, substituting `{{var_name}}` placeholders.
        ///
        /// # Errors
        /// - [`EngineError::NotFound`] if `id` is unknown.
        /// - [`EngineError::MissingVariable`] if a required variable has no value
        ///   and no default.
        pub fn render(
            &self,
            id: &str,
            vars: &HashMap<String, String>,
        ) -> Result<String, EngineError> {
            let template = self
                .templates
                .get(id)
                .ok_or_else(|| EngineError::NotFound(id.to_string()))?;

            let mut output = template.template.clone();

            // First pass: substitute declared variables (respects required / default).
            for var in &template.variables {
                let placeholder = format!("{{{{{}}}}}", var.name);
                if !output.contains(&placeholder) {
                    continue;
                }
                let value = if let Some(v) = vars.get(&var.name) { v.clone() } else {
                    if var.required {
                        return Err(EngineError::MissingVariable {
                            template: id.to_string(),
                            var: var.name.clone(),
                        });
                    }
                    var.default.clone().unwrap_or_default()
                };
                output = output.replace(&placeholder, &value);
            }

            // Second pass: substitute any extra ad-hoc vars supplied by the caller.
            for (k, v) in vars {
                let placeholder = format!("{{{{{k}}}}}");
                output = output.replace(&placeholder, v);
            }

            Ok(output)
        }

        /// List all templates belonging to a given category.
        #[must_use]
        pub fn list_by_category(&self, cat: PromptCategory) -> Vec<&RichTemplate> {
            let mut result: Vec<&RichTemplate> = self
                .templates
                .values()
                .filter(|t| t.category == cat)
                .collect();
            result.sort_by(|a, b| a.id.cmp(&b.id));
            result
        }

        /// List all registered template ids in sorted order.
        #[must_use]
        pub fn list_ids(&self) -> Vec<String> {
            let mut ids: Vec<String> = self.templates.keys().cloned().collect();
            ids.sort();
            ids
        }

        /// Number of registered templates.
        #[must_use]
        pub fn len(&self) -> usize {
            self.templates.len()
        }

        /// True when no templates are registered.
        #[must_use]
        pub fn is_empty(&self) -> bool {
            self.templates.is_empty()
        }
    }

    impl Default for PromptEngine {
        fn default() -> Self {
            Self::new()
        }
    }

    // ── Tests ────────────────────────────────────────────────────────────────

    #[cfg(test)]
    mod engine_tests {
        use super::*;

        // ── builtin_prompts ─────────────────────────────────────────────────

        #[test]
        fn test_builtin_prompts_count() {
            let prompts = builtin_prompts();
            assert!(
                prompts.len() >= 12,
                "Expected at least 12 built-in prompts, got {}",
                prompts.len()
            );
        }

        #[test]
        fn test_builtin_prompt_ids() {
            let prompts = builtin_prompts();
            let ids: Vec<&str> = prompts.iter().map(|p| p.id.as_str()).collect();
            for expected in &[
                "analyze_function",
                "name_variables",
                "identify_algorithm",
                "summarize_malware",
                "find_vulnerability",
                "compare_versions",
                "explain_obfuscation",
                "crypto_analysis",
                "rop_chain_analysis",
                "string_deobfuscation",
                "type_inference",
                "mitre_mapping",
            ] {
                assert!(
                    ids.contains(expected),
                    "Missing built-in prompt: {expected}"
                );
            }
        }

        #[test]
        fn test_every_builtin_has_nonempty_fields() {
            for p in builtin_prompts() {
                assert!(!p.id.is_empty(), "Empty id");
                assert!(!p.name.is_empty(), "Empty name for {}", p.id);
                assert!(!p.description.is_empty(), "Empty description for {}", p.id);
                assert!(!p.template.is_empty(), "Empty template for {}", p.id);
                assert!(!p.use_case.is_empty(), "Empty use_case for {}", p.id);
            }
        }

        // ── PromptVariable ──────────────────────────────────────────────────

        #[test]
        fn test_prompt_variable_required() {
            let v = PromptVariable::required("code", "The decompiled code");
            assert!(v.required);
            assert!(v.default.is_none());
            assert_eq!(v.name, "code");
        }

        #[test]
        fn test_prompt_variable_optional() {
            let v = PromptVariable::optional("lang", "Language", "C");
            assert!(!v.required);
            assert_eq!(v.default, Some("C".to_string()));
        }

        // ── PromptEngine::new ───────────────────────────────────────────────

        #[test]
        fn test_engine_new_loads_builtins() {
            let engine = PromptEngine::new();
            assert!(engine.len() >= 12, "Expected >= 12, got {}", engine.len());
        }

        #[test]
        fn test_engine_is_not_empty() {
            assert!(!PromptEngine::new().is_empty());
        }

        // ── PromptEngine::get ───────────────────────────────────────────────

        #[test]
        fn test_engine_get_existing() {
            let engine = PromptEngine::new();
            let t = engine.get("analyze_function");
            assert!(t.is_some());
            assert_eq!(t.unwrap().id, "analyze_function");
        }

        #[test]
        fn test_engine_get_missing() {
            let engine = PromptEngine::new();
            assert!(engine.get("nonexistent_xyz").is_none());
        }

        // ── PromptEngine::render ────────────────────────────────────────────

        #[test]
        fn test_engine_render_analyze_function() {
            let engine = PromptEngine::new();
            let mut vars = HashMap::new();
            vars.insert("code".to_string(), "int v1 = param_1 + 1;".to_string());
            let rendered = engine.render("analyze_function", &vars).unwrap();
            assert!(rendered.contains("int v1 = param_1 + 1;"));
            // Optional vars should be replaced with their defaults.
            assert!(rendered.contains("(none)") || rendered.contains("binary analysis expert"));
        }

        #[test]
        fn test_engine_render_missing_required_var() {
            let engine = PromptEngine::new();
            // "code" is required for analyze_function; omit it.
            let vars = HashMap::new();
            let err = engine.render("analyze_function", &vars).unwrap_err();
            assert!(
                matches!(err, EngineError::MissingVariable { .. }),
                "Expected MissingVariable, got: {err:?}"
            );
        }

        #[test]
        fn test_engine_render_not_found() {
            let engine = PromptEngine::new();
            let err = engine
                .render("no_such_template", &HashMap::new())
                .unwrap_err();
            assert!(matches!(err, EngineError::NotFound(_)));
        }

        #[test]
        fn test_engine_render_optional_defaults() {
            let engine = PromptEngine::new();
            // "name_variables" only requires "code".
            let mut vars = HashMap::new();
            vars.insert("code".to_string(), "int var_1 = 0;".to_string());
            let rendered = engine.render("name_variables", &vars).unwrap();
            assert!(rendered.contains("int var_1 = 0;"));
        }

        #[test]
        fn test_engine_render_compare_versions() {
            let engine = PromptEngine::new();
            let mut vars = HashMap::new();
            vars.insert("code_a".to_string(), "strcpy(buf, src);".to_string());
            vars.insert(
                "code_b".to_string(),
                "strncpy(buf, src, sizeof(buf));".to_string(),
            );
            let rendered = engine.render("compare_versions", &vars).unwrap();
            assert!(rendered.contains("strcpy(buf, src);"));
            assert!(rendered.contains("strncpy(buf, src, sizeof(buf));"));
        }

        // ── PromptEngine::list_by_category ──────────────────────────────────

        #[test]
        fn test_engine_list_by_category_malware() {
            let engine = PromptEngine::new();
            let malware = engine.list_by_category(PromptCategory::MalwareAnalysis);
            assert!(
                !malware.is_empty(),
                "Expected at least one MalwareAnalysis template"
            );
            for t in &malware {
                assert_eq!(t.category, PromptCategory::MalwareAnalysis);
            }
        }

        #[test]
        fn test_engine_list_by_category_crypto() {
            let engine = PromptEngine::new();
            let crypto = engine.list_by_category(PromptCategory::CryptoIdentification);
            assert!(!crypto.is_empty());
        }

        #[test]
        fn test_engine_list_by_category_custom_empty() {
            let engine = PromptEngine::new();
            // No built-in template uses PromptCategory::Custom.
            let custom = engine.list_by_category(PromptCategory::Custom);
            assert!(custom.is_empty());
        }

        // ── PromptEngine::register ───────────────────────────────────────────

        #[test]
        fn test_engine_register_custom() {
            let mut engine = PromptEngine::new();
            let before = engine.len();
            engine.register(RichTemplate {
                id: "my_custom".into(),
                name: "My Custom".into(),
                description: "A custom template.".into(),
                template: "Analyze {{thing}}.".into(),
                variables: vec![PromptVariable::required("thing", "The thing to analyze")],
                category: PromptCategory::Custom,
                use_case: "Custom use.".into(),
            });
            assert_eq!(engine.len(), before + 1);
            assert!(engine.get("my_custom").is_some());
        }

        #[test]
        fn test_engine_register_overwrite() {
            let mut engine = PromptEngine::new();
            let original_len = engine.len();
            // Re-register an existing id — len should not change.
            engine.register(RichTemplate {
                id: "analyze_function".into(),
                name: "Overwritten".into(),
                description: "Overwritten description.".into(),
                template: "{{code}}".into(),
                variables: vec![PromptVariable::required("code", "code")],
                category: PromptCategory::FunctionAnalysis,
                use_case: "overwrite test".into(),
            });
            assert_eq!(engine.len(), original_len);
            assert_eq!(engine.get("analyze_function").unwrap().name, "Overwritten");
        }

        // ── PromptEngine::list_ids ───────────────────────────────────────────

        #[test]
        fn test_engine_list_ids_sorted() {
            let engine = PromptEngine::new();
            let ids = engine.list_ids();
            let mut sorted = ids.clone();
            sorted.sort();
            assert_eq!(ids, sorted, "list_ids() must return sorted ids");
        }

        // ── PromptCategory ───────────────────────────────────────────────────

        #[test]
        fn test_prompt_category_eq() {
            assert_eq!(
                PromptCategory::FunctionAnalysis,
                PromptCategory::FunctionAnalysis
            );
            assert_ne!(
                PromptCategory::FunctionAnalysis,
                PromptCategory::MalwareAnalysis
            );
        }

        // ── Default ──────────────────────────────────────────────────────────

        #[test]
        fn test_engine_default_same_as_new() {
            let a = PromptEngine::new();
            let b = PromptEngine::default();
            assert_eq!(a.len(), b.len());
        }

        // ── EngineError display ──────────────────────────────────────────────

        #[test]
        fn test_engine_error_not_found_display() {
            let e = EngineError::NotFound("foo".to_string());
            assert!(e.to_string().contains("foo"));
        }

        #[test]
        fn test_engine_error_missing_var_display() {
            let e = EngineError::MissingVariable {
                template: "tmpl".to_string(),
                var: "code".to_string(),
            };
            assert!(e.to_string().contains("code"));
            assert!(e.to_string().contains("tmpl"));
        }
    }
}

// ── Re-exports for convenience ───────────────────────────────────────────────

pub use engine::{
    EngineError, PromptCategory, PromptEngine, PromptVariable, RichTemplate, builtin_prompts,
};

// ── Chain-of-thought prompt builder ──────────────────────────────────────────

/// A step in a chain-of-thought prompt sequence.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CoTStep {
    /// Human-readable name for this reasoning step.
    pub name: String,
    /// The prompt text for this step; may use `{{var}}` substitutions.
    pub template: String,
    /// Variables expected by this step.
    pub variables: Vec<String>,
    /// Whether this step's output should be fed as `{{previous_output}}`
    /// into the next step.
    pub feed_forward: bool,
}

impl CoTStep {
    /// Construct a chain step.
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        template: impl Into<String>,
        variables: Vec<String>,
        feed_forward: bool,
    ) -> Self {
        Self {
            name: name.into(),
            template: template.into(),
            variables,
            feed_forward,
        }
    }

    /// Render this step given a variable map.
    pub fn render(
        &self,
        vars: &std::collections::HashMap<String, String>,
    ) -> Result<String, PromptError> {
        PromptRenderer::render(&self.template, vars)
    }
}

/// An ordered sequence of chain-of-thought steps.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CoTChain {
    /// Unique name for this chain.
    pub name: String,
    /// Description of the overall reasoning task.
    pub description: String,
    /// Ordered list of reasoning steps.
    pub steps: Vec<CoTStep>,
}

impl CoTChain {
    /// Build a new chain.
    #[must_use]
    pub fn new(name: impl Into<String>, description: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            description: description.into(),
            steps: Vec::new(),
        }
    }

    /// Append a step to the chain.
    pub fn push_step(&mut self, step: CoTStep) {
        self.steps.push(step);
    }

    /// Number of steps in the chain.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.steps.len()
    }

    /// True when the chain contains no steps.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.steps.is_empty()
    }
}

/// Pre-built chain-of-thought sequences for common RE tasks.
pub struct CoTLibrary {
    chains: std::collections::HashMap<String, CoTChain>,
}

/// Alias retained for historical naming (chain-oriented library).
pub type ChainLibrary = CoTLibrary;

impl CoTLibrary {
    /// Create the library pre-populated with built-in RE chains.
    #[must_use]
    pub fn new() -> Self {
        let mut lib = Self {
            chains: std::collections::HashMap::new(),
        };
        lib.register(Self::binary_triage_chain());
        lib.register(Self::vulnerability_hunt_chain());
        lib.register(Self::crypto_identification_chain());
        lib.register(Self::malware_classification_chain());
        lib.register(Self::protocol_recovery_chain());
        lib.register(Self::function_documentation_chain());
        lib.register(Self::struct_recovery_chain());
        lib.register(Self::packer_analysis_chain());
        lib
    }

    /// Register a chain (overwrites if the name already exists).
    pub fn register(&mut self, chain: CoTChain) {
        self.chains.insert(chain.name.clone(), chain);
    }

    /// Look up a chain by name.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&CoTChain> {
        self.chains.get(name)
    }

    /// List all chain names in sorted order.
    #[must_use]
    pub fn list_names(&self) -> Vec<&str> {
        let mut names: Vec<&str> = self.chains.keys().map(String::as_str).collect();
        names.sort_unstable();
        names
    }

    // ── Built-in chains ───────────────────────────────────────────────────────

    fn binary_triage_chain() -> CoTChain {
        let mut chain = CoTChain::new(
            "binary_triage",
            "Step-by-step triage of an unknown binary: format, architecture, entry, suspicious indicators.",
        );
        chain.push_step(CoTStep::new(
            "identify_format",
            "You are a reverse engineering assistant. Given the binary metadata below, identify the \
file format, target architecture, bitness, and probable operating system.\n\nBinary metadata:\n{{metadata}}\n\n\
Think step by step. Output a short structured summary with keys: format, arch, bits, os.",
            vec!["metadata".into()],
            true,
        ));
        chain.push_step(CoTStep::new(
            "assess_entry_point",
            "Based on the previous analysis:\n{{previous_output}}\n\nNow examine the entry point at \
address {{entry_addr}}. Disassembly:\n{{entry_disasm}}\n\nDescribe what the entry point does and whether \
it matches a known compiler or runtime startup pattern.",
            vec!["entry_addr".into(), "entry_disasm".into(), "previous_output".into()],
            true,
        ));
        chain.push_step(CoTStep::new(
            "import_assessment",
            "Previous findings:\n{{previous_output}}\n\nImport table:\n{{imports}}\n\n\
Categorize the imports by capability group (network, file I/O, process injection, crypto, anti-debug). \
Flag any imports that are commonly abused by malware.",
            vec!["imports".into(), "previous_output".into()],
            true,
        ));
        chain.push_step(CoTStep::new(
            "string_assessment",
            "Previous findings:\n{{previous_output}}\n\nStrings found in binary:\n{{strings}}\n\n\
Identify interesting strings (URLs, registry keys, file paths, mutex names, encoded blobs). \
Assess the overall suspicion level (low/medium/high/critical) with justification.",
            vec!["strings".into(), "previous_output".into()],
            true,
        ));
        chain.push_step(CoTStep::new(
            "final_report",
            "Synthesize all previous findings:\n{{previous_output}}\n\nProduce a concise triage report \
with sections: Summary, Capabilities, Indicators of Compromise, Recommended Next Steps.",
            vec!["previous_output".into()],
            false,
        ));
        chain
    }

    fn vulnerability_hunt_chain() -> CoTChain {
        let mut chain = CoTChain::new(
            "vulnerability_hunt",
            "Systematic vulnerability hunting: identify attack surface, data flows, unsafe patterns.",
        );
        chain.push_step(CoTStep::new(
            "identify_attack_surface",
            "You are a security researcher. Examine the function list below and identify functions \
that represent the binary's attack surface (network input parsers, file parsers, IPC handlers, etc.).\n\n\
Function list:\n{{function_list}}\n\nList the top 10 most interesting attack-surface functions with rationale.",
            vec!["function_list".into()],
            true,
        ));
        chain.push_step(CoTStep::new(
            "decompile_candidates",
            "Attack surface identified:\n{{previous_output}}\n\nDecompiled code for candidate function:\n{{code}}\n\n\
Identify unsafe patterns: unchecked arithmetic, unsafe memory operations (strcpy, memcpy without bounds), \
format string vulnerabilities, integer overflows, use-after-free patterns.",
            vec!["code".into(), "previous_output".into()],
            true,
        ));
        chain.push_step(CoTStep::new(
            "taint_analysis",
            "Potential vulnerabilities found:\n{{previous_output}}\n\nTaint analysis result for {{func_name}}:\n{{taint_result}}\n\n\
Trace attacker-controlled data from source to sink. Identify the shortest path to exploitation.",
            vec!["func_name".into(), "taint_result".into(), "previous_output".into()],
            true,
        ));
        chain.push_step(CoTStep::new(
            "poc_sketch",
            "Taint analysis complete:\n{{previous_output}}\n\nFor the most promising vulnerability, \
sketch a proof-of-concept exploitation strategy. Include: trigger condition, controlled data, target, \
and required constraints. Do NOT produce working exploit code.",
            vec!["previous_output".into()],
            false,
        ));
        chain
    }

    fn crypto_identification_chain() -> CoTChain {
        let mut chain = CoTChain::new(
            "crypto_identification",
            "Identify cryptographic algorithms from disassembly and constants.",
        );
        chain.push_step(CoTStep::new(
            "constant_scan",
            "Scan the following list of integer constants found in the binary and identify those that \
are characteristic of cryptographic algorithms (S-boxes, round constants, magic primes, etc.).\n\n\
Constants:\n{{constants}}\n\nFor each suspicious constant list: value (hex), algorithm, role.",
            vec!["constants".into()],
            true,
        ));
        chain.push_step(CoTStep::new(
            "structural_analysis",
            "Crypto constants found:\n{{previous_output}}\n\nDecompiled function:\n{{code}}\n\n\
Look for structural patterns: key schedule loops, round functions, S-box lookups, XOR-based diffusion, \
Feistel networks. Identify the algorithm or algorithm family.",
            vec!["code".into(), "previous_output".into()],
            true,
        ));
        chain.push_step(CoTStep::new(
            "mode_and_usage",
            "Algorithm identified:\n{{previous_output}}\n\nXref context (callers and callees):\n{{xref_context}}\n\n\
Determine the mode of operation (ECB/CBC/CTR/GCM etc.), key sizes, and how the crypto is used \
(encryption, decryption, hashing, signing, key derivation).",
            vec!["xref_context".into(), "previous_output".into()],
            false,
        ));
        chain
    }

    fn malware_classification_chain() -> CoTChain {
        let mut chain = CoTChain::new(
            "malware_classification",
            "Classify malware family, capabilities, and C2 mechanisms.",
        );
        chain.push_step(CoTStep::new(
            "capability_matrix",
            "You are a malware analyst. Based on the imports, exports, and strings listed below, \
build a capability matrix.\n\nImports:\n{{imports}}\nStrings:\n{{strings}}\n\n\
Use MITRE ATT&CK technique IDs where applicable. Output a markdown table: Capability | Evidence | ATT&CK TID.",
            vec!["imports".into(), "strings".into()],
            true,
        ));
        chain.push_step(CoTStep::new(
            "c2_extraction",
            "Capability matrix:\n{{previous_output}}\n\nNetwork-related decompiled code:\n{{network_code}}\n\n\
Extract C2 indicators: protocol, port, encoding, beacon interval, commands. List all hard-coded IPs/domains.",
            vec!["network_code".into(), "previous_output".into()],
            true,
        ));
        chain.push_step(CoTStep::new(
            "family_classification",
            "C2 analysis:\n{{previous_output}}\n\nYARA rule matches (if any):\n{{yara_matches}}\n\n\
Based on all evidence, classify the malware: family name (if known), category \
(RAT/stealer/ransomware/dropper/rootkit/wiper), confidence level, and distinguishing characteristics.",
            vec!["yara_matches".into(), "previous_output".into()],
            false,
        ));
        chain
    }

    fn protocol_recovery_chain() -> CoTChain {
        let mut chain = CoTChain::new(
            "protocol_recovery",
            "Recover binary protocol message formats and state machine from network-handling code.",
        );
        chain.push_step(CoTStep::new(
            "packet_parser_identification",
            "Examine the decompiled network parsing functions below and identify the top-level \
packet dispatch loop or message parser.\n\nFunctions:\n{{network_functions}}\n\n\
Identify the main dispatch function and describe the message framing (length-prefixed, delimiter-based, fixed-size).",
            vec!["network_functions".into()],
            true,
        ));
        chain.push_step(CoTStep::new(
            "message_format_recovery",
            "Parser identified:\n{{previous_output}}\n\nDecompiled parser code:\n{{parser_code}}\n\n\
Recover the message format as a C struct definition. Include field names, types, offsets, and endianness.",
            vec!["parser_code".into(), "previous_output".into()],
            true,
        ));
        chain.push_step(CoTStep::new(
            "state_machine",
            "Message format:\n{{previous_output}}\n\nState-related code:\n{{state_code}}\n\n\
Reconstruct the protocol state machine as a list of (current_state, message_type) -> next_state transitions.",
            vec!["state_code".into(), "previous_output".into()],
            false,
        ));
        chain
    }

    fn function_documentation_chain() -> CoTChain {
        let mut chain = CoTChain::new(
            "function_documentation",
            "Generate detailed documentation for a decompiled function.",
        );
        chain.push_step(CoTStep::new(
            "signature_inference",
            "Given the decompiled function below, infer the most accurate C function signature \
(return type, parameter names and types).\n\nDecompiled code:\n{{code}}\n\nOutput only the signature on one line.",
            vec!["code".into()],
            true,
        ));
        chain.push_step(CoTStep::new(
            "behavior_summary",
            "Function signature:\n{{previous_output}}\n\nDecompiled code:\n{{code}}\n\n\
Summarize what this function does in 2-4 sentences. Describe inputs, outputs, side effects, \
and any notable algorithms used.",
            vec!["code".into(), "previous_output".into()],
            true,
        ));
        chain.push_step(CoTStep::new(
            "doxygen_comment",
            "Signature and behavior:\n{{previous_output}}\n\nGenerate a Doxygen-style comment block \
for this function. Include @brief, @param for each parameter, @return, and @note for side effects.",
            vec!["previous_output".into()],
            false,
        ));
        chain
    }

    fn struct_recovery_chain() -> CoTChain {
        let mut chain = CoTChain::new(
            "struct_recovery",
            "Recover C struct definitions from decompiled code that uses heap objects or stack frames.",
        );
        chain.push_step(CoTStep::new(
            "access_pattern_collection",
            "Examine the decompiled code below and collect all field access patterns for the pointer \
variable(s) that represent an unknown struct.\n\nDecompiled code:\n{{code}}\n\n\
List accesses as: offset (hex), size (bytes), access type (read/write), inferred purpose.",
            vec!["code".into()],
            true,
        ));
        chain.push_step(CoTStep::new(
            "struct_definition",
            "Access patterns collected:\n{{previous_output}}\n\n\
Now synthesize a C struct definition that satisfies all observed accesses. Use `uint8_t` arrays for gaps. \
Add a brief comment on each field describing its inferred purpose.",
            vec!["previous_output".into()],
            true,
        ));
        chain.push_step(CoTStep::new(
            "validation",
            "Proposed struct:\n{{previous_output}}\n\nAdditional functions that use this struct:\n{{callers}}\n\n\
Validate the struct definition against these callers. Note any inconsistencies and propose corrections.",
            vec!["callers".into(), "previous_output".into()],
            false,
        ));
        chain
    }

    fn packer_analysis_chain() -> CoTChain {
        let mut chain = CoTChain::new(
            "packer_analysis",
            "Detect and analyze packer/protector, then guide unpacking.",
        );
        chain.push_step(CoTStep::new(
            "packer_detection",
            "Analyse the binary metadata and entropy data below to detect the packer or protector used.\n\n\
Metadata:\n{{metadata}}\nSection entropy:\n{{entropy}}\nPacker signatures:\n{{signatures}}\n\n\
Identify the packer name, version (if detectable), and protection features (anti-debug, anti-vm, code virtualization).",
            vec!["metadata".into(), "entropy".into(), "signatures".into()],
            true,
        ));
        chain.push_step(CoTStep::new(
            "unpack_strategy",
            "Packer identified:\n{{previous_output}}\n\nEntry point disassembly:\n{{entry_disasm}}\n\n\
Describe the unpacking strategy: OEP-finding approach, memory dump location, any patching required. \
Include the expected sequence of events during unpacking.",
            vec!["entry_disasm".into(), "previous_output".into()],
            true,
        ));
        chain.push_step(CoTStep::new(
            "post_unpack_analysis",
            "Unpacking strategy:\n{{previous_output}}\n\nUnpacked binary metadata:\n{{unpacked_metadata}}\n\n\
Compare the original and unpacked binaries. Confirm the unpacked binary is valid. \
Describe any remaining protections (import reconstruction needed, etc.).",
            vec!["unpacked_metadata".into(), "previous_output".into()],
            false,
        ));
        chain
    }
}

impl Default for CoTLibrary {
    fn default() -> Self {
        Self::new()
    }
}

// ── Few-shot example store ────────────────────────────────────────────────────

/// A single few-shot example: a task description paired with a model response.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct InlineExample {
    /// Identifier for the task type this example belongs to.
    pub task: String,
    /// The user message / instruction.
    pub user: String,
    /// The expected / ideal assistant response.
    pub assistant: String,
    /// Optional annotation or explanation.
    pub annotation: String,
}

impl InlineExample {
    /// Construct a new few-shot example.
    #[must_use]
    pub fn new(
        task: impl Into<String>,
        user: impl Into<String>,
        assistant: impl Into<String>,
        annotation: impl Into<String>,
    ) -> Self {
        Self {
            task: task.into(),
            user: user.into(),
            assistant: assistant.into(),
            annotation: annotation.into(),
        }
    }
}

/// In-memory store of few-shot examples grouped by task type.
pub struct InlineExampleStore {
    examples: std::collections::HashMap<String, Vec<InlineExample>>,
}

impl InlineExampleStore {
    /// Create the store pre-loaded with built-in RE examples.
    #[must_use]
    pub fn new() -> Self {
        let mut store = Self {
            examples: std::collections::HashMap::new(),
        };
        for ex in Self::builtin_examples() {
            store.add(ex);
        }
        store
    }

    /// Add an example to the store.
    pub fn add(&mut self, example: InlineExample) {
        self.examples
            .entry(example.task.clone())
            .or_default()
            .push(example);
    }

    /// Retrieve all examples for a given task type.
    #[must_use]
    pub fn get_examples(&self, task: &str) -> &[InlineExample] {
        self.examples.get(task).map_or(&[], Vec::as_slice)
    }

    /// Return up to `n` examples for a task, formatted as a conversation prefix.
    #[must_use]
    pub fn format_shots(&self, task: &str, n: usize) -> String {
        let examples = self.get_examples(task);
        let take = n.min(examples.len());
        let mut out = String::new();
        for ex in examples.iter().take(take) {
            out.push_str("User: ");
            out.push_str(&ex.user);
            out.push_str("\nAssistant: ");
            out.push_str(&ex.assistant);
            out.push_str("\n\n");
        }
        out
    }

    /// Total number of examples across all tasks.
    #[must_use]
    pub fn total_count(&self) -> usize {
        self.examples.values().map(Vec::len).sum()
    }

    /// List all task types in sorted order.
    #[must_use]
    pub fn task_types(&self) -> Vec<&str> {
        let mut types: Vec<&str> = self.examples.keys().map(String::as_str).collect();
        types.sort_unstable();
        types
    }

    fn builtin_examples() -> Vec<InlineExample> {
        vec![
            // ── function_rename ──────────────────────────────────────────────
            InlineExample::new(
                "function_rename",
                "The function at 0x401000 starts with:\n  push rbp\n  mov rbp, rsp\n  mov rdi, [rbp+arg_0]\n  call strlen\n  cmp rax, 0x20\n  jbe loc_error\n  call malloc\nSuggest a meaningful name.",
                "validate_and_alloc_string",
                "Pattern: checks string length, allocates on success — classic validation + allocation.",
            ),
            InlineExample::new(
                "function_rename",
                "Function imports: CreateFile, ReadFile, CloseHandle. Parameters: (path, out_buf, max_len). Returns size_t.",
                "read_file_to_buffer",
                "Straightforward file-read helper identified from Win32 API usage.",
            ),
            InlineExample::new(
                "function_rename",
                "Function contains a 256-byte S-box initialisation loop, XOR operations, and a rotate-right by 13 bits.",
                "rc4_initialize_sbox",
                "RC4 key-scheduling algorithm pattern.",
            ),
            // ── struct_field ─────────────────────────────────────────────────
            InlineExample::new(
                "struct_field",
                "At offset 0x0: 4-byte read into size comparison. At offset 0x8: pointer dereferenced and passed to free(). At offset 0x10: pointer passed to memcpy as destination.",
                "struct MyBuffer { uint32_t capacity; uint32_t _pad; void* data_ptr; void* secondary_ptr; };",
                "Classic buffer struct: capacity, padding for alignment, data pointer, secondary pointer.",
            ),
            InlineExample::new(
                "struct_field",
                "Offset 0x0: compared to magic 0xDEADBEEF. Offset 0x4: used as index into array. Offset 0x8-0x10: passed to send() as buf+len.",
                "struct Packet { uint32_t magic; uint32_t type_id; uint8_t payload[8]; };",
                "Network packet with magic header, type discriminant, and inline payload.",
            ),
            // ── vulnerability_assessment ─────────────────────────────────────
            InlineExample::new(
                "vulnerability_assessment",
                "Code: `memcpy(dst, src, user_controlled_len);` where dst is a 256-byte stack buffer.",
                "Stack buffer overflow. The attacker controls `user_controlled_len`; if it exceeds 256, data past `dst` is overwritten. This can corrupt saved return address — likely exploitable for arbitrary code execution.",
                "Classic stack BOF: fixed-size stack buffer + attacker-controlled copy length.",
            ),
            InlineExample::new(
                "vulnerability_assessment",
                "Code: `char* buf = malloc(count * sizeof(int));` where count is a 32-bit user value.",
                "Integer overflow leading to heap underallocation. If count >= 0x40000000, `count * 4` wraps to a small value, malloc returns an undersized buffer, and subsequent writes overflow the heap.",
                "Multiplication overflow before malloc — classic heap overflow precondition.",
            ),
            // ── crypto_identification ────────────────────────────────────────
            InlineExample::new(
                "crypto_identification",
                "Constants in function: 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0",
                "SHA-1. These are the five 32-bit initialisation constants (H0-H4) defined in FIPS 180-4.",
                "Exact SHA-1 IV constants.",
            ),
            InlineExample::new(
                "crypto_identification",
                "256-byte table starting with 0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5...",
                "AES SubBytes S-box. The table at these specific values is the Rijndael substitution box used in the AES SubBytes step.",
                "Exact AES S-box match (first 8 bytes confirm).",
            ),
            InlineExample::new(
                "crypto_identification",
                "32-bit XOR operations with constants 0x61707865, 0x3320646e, 0x79622d32, 0x6b206574",
                "ChaCha20/Salsa20 stream cipher. These are the ASCII 'expand 32-byte k' constant words used in the initial state setup.",
                "ChaCha20 constant 'expand 32-byte k' split into 4 little-endian words.",
            ),
            // ── malware_behavior ─────────────────────────────────────────────
            InlineExample::new(
                "malware_behavior",
                "Imports: CreateRemoteThread, VirtualAllocEx, WriteProcessMemory, OpenProcess. Target: lsass.exe",
                "Process injection into lsass.exe for credential dumping. The combination of OpenProcess(lsass), VirtualAllocEx, WriteProcessMemory, CreateRemoteThread is the classic reflective DLL injection chain. Likely credential harvesting (Mimikatz pattern).",
                "Classic process injection + LSASS targeting = credential theft.",
            ),
            InlineExample::new(
                "malware_behavior",
                "Function: enumerates running processes, compares names against a hardcoded list including 'wireshark.exe', 'procmon.exe', 'x64dbg.exe', 'procexp.exe'. Returns 1 if found.",
                "Anti-analysis detection routine. The function checks for common analysis tools (debuggers, process monitors, network sniffers) and likely terminates or alters behaviour when detected.",
                "Standard anti-sandbox/anti-debug tool enumeration.",
            ),
            // ── disasm_explanation ───────────────────────────────────────────
            InlineExample::new(
                "disasm_explanation",
                "0x401000: push rbp\n0x401001: mov rbp, rsp\n0x401004: sub rsp, 0x20\n0x401008: mov [rbp-0x18], rdi",
                "Standard x86-64 System V ABI function prologue. Saves the frame pointer, establishes a new stack frame 32 bytes deep, and spills the first integer argument (rdi) to the local variable at rbp-0x18.",
                "Textbook function prologue with one spilled argument.",
            ),
            InlineExample::new(
                "disasm_explanation",
                "0x4020A0: xor eax, eax\n0x4020A2: test rdi, rdi\n0x4020A5: je 0x4020B0\n0x4020A7: ...",
                "Null pointer check with early return. `xor eax, eax` zeroes the return value, then `test rdi, rdi` / `je` branches to the exit if the first argument (rdi) is null. Classic guard clause pattern.",
                "Zero return value + null check early exit.",
            ),
        ]
    }
}

impl Default for InlineExampleStore {
    fn default() -> Self {
        Self::new()
    }
}

// ── Output format helpers ─────────────────────────────────────────────────────

/// Formats in which the agent should produce its answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum OutputFormat {
    /// Plain markdown prose.
    Markdown,
    /// Strict JSON object (no surrounding prose).
    Json,
    /// C-style block comment suitable for insertion into source.
    CComment,
    /// YAML front matter followed by markdown body.
    YamlMarkdown,
    /// Numbered list of findings.
    NumberedList,
}

impl OutputFormat {
    /// Return the system prompt suffix that requests this format.
    #[must_use]
    pub const fn system_suffix(&self) -> &'static str {
        match self {
            Self::Markdown => "Format your response as structured Markdown with headers.",
            Self::Json => {
                "Output ONLY valid JSON — no prose, no markdown, no code fences. \
Your entire response must parse as a single JSON object or array."
            }
            Self::CComment => {
                "Format your entire response as a C block comment suitable for pasting \
into source code:\n/* ... */"
            }
            Self::YamlMarkdown => {
                "Begin your response with a YAML front matter block (--- ... ---) containing \
structured metadata, followed by a Markdown body."
            }
            Self::NumberedList => {
                "Format your response as a numbered list. Each item on a separate line: \
1. ...\n2. ..."
            }
        }
    }

    /// All available output formats.
    #[must_use]
    pub const fn all() -> &'static [Self] {
        &[
            Self::Markdown,
            Self::Json,
            Self::CComment,
            Self::YamlMarkdown,
            Self::NumberedList,
        ]
    }
}

impl std::fmt::Display for OutputFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Markdown => "markdown",
            Self::Json => "json",
            Self::CComment => "c_comment",
            Self::YamlMarkdown => "yaml_markdown",
            Self::NumberedList => "numbered_list",
        };
        write!(f, "{s}")
    }
}

// ── System prompt builder ─────────────────────────────────────────────────────

/// Constructs the system prompt that configures an LLM as a `RustRE` agent.
pub struct SystemPromptBuilder {
    role: String,
    capabilities: Vec<String>,
    constraints: Vec<String>,
    output_format: OutputFormat,
    custom_sections: Vec<(String, String)>,
}

impl SystemPromptBuilder {
    /// Create a builder with sensible RE defaults.
    #[must_use]
    pub fn new() -> Self {
        Self {
            role: "You are RustRE, an expert reverse engineering AI assistant with deep knowledge \
of binary analysis, vulnerability research, malware analysis, and low-level systems programming."
                .to_string(),
            capabilities: vec![
                "Disassemble and decompile binary code for x86, x86-64, ARM, ARM64, MIPS, RISC-V, and other architectures".into(),
                "Identify cryptographic algorithms, obfuscation patterns, and packing techniques".into(),
                "Trace data flows, identify vulnerabilities, and assess exploitability".into(),
                "Recover protocol formats, struct layouts, and type information from binary code".into(),
                "Classify malware and extract indicators of compromise".into(),
                "Generate structured analysis reports, renamed functions, and annotated decompiled code".into(),
            ],
            constraints: vec![
                "Always reason step by step before giving a final answer".into(),
                "Acknowledge uncertainty explicitly when confidence is low".into(),
                "Never produce working exploit code or functional malware payloads".into(),
                "Cite the specific binary evidence (addresses, bytes, constants) behind every claim".into(),
            ],
            output_format: OutputFormat::Markdown,
            custom_sections: Vec::new(),
        }
    }

    /// Override the role description.
    pub fn with_role(mut self, role: impl Into<String>) -> Self {
        self.role = role.into();
        self
    }

    /// Add a capability bullet point.
    pub fn add_capability(mut self, capability: impl Into<String>) -> Self {
        self.capabilities.push(capability.into());
        self
    }

    /// Add a constraint / guardrail.
    pub fn add_constraint(mut self, constraint: impl Into<String>) -> Self {
        self.constraints.push(constraint.into());
        self
    }

    /// Set the desired output format.
    #[must_use] 
    pub const fn with_output_format(mut self, fmt: OutputFormat) -> Self {
        self.output_format = fmt;
        self
    }

    /// Append a custom named section.
    pub fn add_section(mut self, title: impl Into<String>, body: impl Into<String>) -> Self {
        self.custom_sections.push((title.into(), body.into()));
        self
    }

    /// Render the final system prompt string.
    #[must_use]
    pub fn build(self) -> String {
        let mut out = String::new();

        // Role
        out.push_str("# Role\n");
        out.push_str(&self.role);
        out.push_str("\n\n");

        // Capabilities
        out.push_str("# Capabilities\n");
        for cap in &self.capabilities {
            out.push_str("- ");
            out.push_str(cap);
            out.push('\n');
        }
        out.push('\n');

        // Constraints
        out.push_str("# Constraints\n");
        for con in &self.constraints {
            out.push_str("- ");
            out.push_str(con);
            out.push('\n');
        }
        out.push('\n');

        // Tools (MCP capabilities)
        out.push_str("# Available Tools\n");
        out.push_str("You have access to the following RustRE MCP tools:\n");
        out.push_str("- `open_binary(path)` — Load a binary and return a view_id\n");
        out.push_str("- `list_functions(view_id, filter?)` — List all functions\n");
        out.push_str("- `get_disassembly(view_id, addr, length?)` — Disassemble at address\n");
        out.push_str("- `get_decompiled(view_id, addr)` — Decompile function at address\n");
        out.push_str("- `get_xrefs_to(view_id, addr)` — Cross-references to address\n");
        out.push_str("- `get_xrefs_from(view_id, addr)` — Cross-references from address\n");
        out.push_str("- `search_strings(view_id, pattern?)` — Find strings in binary\n");
        out.push_str("- `get_imports(view_id)` — Import table\n");
        out.push_str("- `get_exports(view_id)` — Export table\n");
        out.push_str("- `rename_function(view_id, addr, name)` — Rename a function\n");
        out.push_str("- `add_comment(view_id, addr, text, repeatable?)` — Add comment\n");
        out.push_str("- `set_type(view_id, addr, type_str)` — Set type at address\n");
        out.push_str("- `create_struct(view_id, name, fields)` — Create struct type\n");
        out.push_str("- `search_bytes(view_id, pattern)` — Byte pattern search (hex + ??)\n");
        out.push_str("- `patch_bytes(view_id, addr, hex)` — Patch bytes at address\n");
        out.push_str("- `run_analysis(view_id, pass)` — Run analysis pass\n");
        out.push_str("- `get_call_graph(view_id, root_addr, depth?)` — Call graph\n");
        out.push_str("- `find_similar_functions(view_id, addr, threshold?)` — Similar functions\n");
        out.push_str("- `run_yara(view_id, rule)` — Execute YARA rule\n");
        out.push_str("- `get_entropy(view_id, addr?, length?)` — Section entropy\n");
        out.push_str("- `emulate_function(view_id, addr, args, max_instrs?)` — Emulate function\n");
        out.push_str("- `symbolic_exec(view_id, addr, symbolize)` — Symbolic execution\n");
        out.push_str("- `diff_functions(view_id_a, addr_a, view_id_b, addr_b)` — Diff functions\n");
        out.push_str("- `get_type_info(view_id, name)` — Type information\n");
        out.push_str("- `list_segments(view_id)` — List binary segments\n");
        out.push_str("- `get_file_info(view_id)` — File metadata\n");
        out.push('\n');

        // Custom sections
        for (title, body) in &self.custom_sections {
            out.push_str("# ");
            out.push_str(title);
            out.push('\n');
            out.push_str(body);
            out.push_str("\n\n");
        }

        // Output format
        out.push_str("# Output Format\n");
        out.push_str(self.output_format.system_suffix());
        out.push('\n');

        out
    }
}

impl Default for SystemPromptBuilder {
    fn default() -> Self {
        Self::new()
    }
}

// ── Conversation history helper ───────────────────────────────────────────────

/// Role of a message in a conversation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum MessageRole {
    System,
    User,
    Assistant,
    Tool,
}

impl std::fmt::Display for MessageRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::System => write!(f, "system"),
            Self::User => write!(f, "user"),
            Self::Assistant => write!(f, "assistant"),
            Self::Tool => write!(f, "tool"),
        }
    }
}

/// A single message in a conversation.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ConversationMessage {
    pub role: MessageRole,
    pub content: String,
    /// Approximate token count (for budgeting).
    pub token_estimate: usize,
}

impl ConversationMessage {
    /// Construct a message and estimate its token count (rough: chars / 4).
    #[must_use]
    pub fn new(role: MessageRole, content: impl Into<String>) -> Self {
        let content = content.into();
        let token_estimate = (content.len() / 4).max(1);
        Self {
            role,
            content,
            token_estimate,
        }
    }
}

/// A sliding-window conversation history with token budget management.
pub struct ConversationHistory {
    messages: Vec<ConversationMessage>,
    /// Maximum total token budget before the history is trimmed.
    token_budget: usize,
    current_tokens: usize,
}

impl ConversationHistory {
    /// Create a new history with the given token budget.
    #[must_use]
    pub const fn new(token_budget: usize) -> Self {
        Self {
            messages: Vec::new(),
            token_budget,
            current_tokens: 0,
        }
    }

    /// Append a message, trimming old non-system messages if over budget.
    pub fn push(&mut self, msg: ConversationMessage) {
        self.current_tokens += msg.token_estimate;
        self.messages.push(msg);
        self.trim_to_budget();
    }

    /// Total estimated tokens currently in history.
    #[must_use]
    pub const fn token_count(&self) -> usize {
        self.current_tokens
    }

    /// All messages in chronological order.
    #[must_use]
    pub fn messages(&self) -> &[ConversationMessage] {
        &self.messages
    }

    /// Number of messages.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.messages.len()
    }

    /// True when history is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.messages.is_empty()
    }

    /// Remove all messages (preserving system prompt if present).
    pub fn clear(&mut self) {
        // Keep system message if first
        if self.messages.first().map(|m| m.role) == Some(MessageRole::System) {
            let sys = self.messages.remove(0);
            let sys_tokens = sys.token_estimate;
            self.messages.clear();
            self.current_tokens = sys_tokens;
            self.messages.insert(0, sys);
        } else {
            self.messages.clear();
            self.current_tokens = 0;
        }
    }

    fn trim_to_budget(&mut self) {
        // Never remove the system message (index 0 if it is system role)
        let system_count = usize::from(self.messages.first().map(|m| m.role) == Some(MessageRole::System));
        while self.current_tokens > self.token_budget && self.messages.len() > system_count + 1 {
            let removed = self.messages.remove(system_count);
            self.current_tokens = self.current_tokens.saturating_sub(removed.token_estimate);
        }
    }
}

impl Default for ConversationHistory {
    fn default() -> Self {
        Self::new(128_000)
    }
}

// ── Prompt variable injection helper ─────────────────────────────────────────

/// A type-safe map of prompt variables, built with a fluent API.
#[derive(Debug, Default, Clone)]
pub struct PromptVars(std::collections::HashMap<String, String>);

impl PromptVars {
    /// Create an empty variable map.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a variable.
    pub fn set(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.0.insert(key.into(), value.into());
        self
    }

    /// Insert a numeric variable (converted to string).
    pub fn set_int(self, key: impl Into<String>, value: i64) -> Self {
        self.set(key, value.to_string())
    }

    /// Insert a hex-formatted address variable.
    pub fn set_addr(self, key: impl Into<String>, addr: u64) -> Self {
        self.set(key, format!("0x{addr:x}"))
    }

    /// Consume and return the underlying `HashMap`.
    #[must_use]
    pub fn into_map(self) -> std::collections::HashMap<String, String> {
        self.0
    }

    /// Reference to the underlying `HashMap`.
    #[must_use]
    pub const fn as_map(&self) -> &std::collections::HashMap<String, String> {
        &self.0
    }
}

// ── Task prompt specialisations ───────────────────────────────────────────────

/// Pre-built task-specific prompts not covered by the engine's template system.
pub struct TaskPrompts;

impl TaskPrompts {
    /// Prompt asking the model to rename a function given its decompiled body.
    #[must_use]
    pub fn rename_function(addr: u64, decompiled: &str) -> String {
        format!(
            "Given the following decompiled function at address 0x{addr:x}, suggest a descriptive \
name that captures its purpose. Respond with ONLY the name — no explanation, no punctuation.\n\n\
```c\n{decompiled}\n```"
        )
    }

    /// Prompt asking for a vulnerability assessment of a decompiled function.
    #[must_use]
    pub fn assess_vulnerability(func_name: &str, decompiled: &str) -> String {
        format!(
            "You are a security researcher performing a code review of the decompiled function \
`{func_name}`. Identify all potential security vulnerabilities with severity (Critical/High/Medium/Low), \
CWE ID, brief description, and the exact code pattern responsible.\n\n\
```c\n{decompiled}\n```"
        )
    }

    /// Prompt asking the model to recover a struct from field accesses.
    #[must_use]
    pub fn recover_struct(object_name: &str, accesses: &str) -> String {
        format!(
            "Based on the following field access patterns for the object `{object_name}`, \
generate a C struct definition with appropriate field names, types, and sizes.\n\n\
Field accesses:\n{accesses}\n\n\
Output only the struct definition as valid C code."
        )
    }

    /// Prompt for generating a YARA rule from binary patterns.
    #[must_use]
    pub fn generate_yara(binary_name: &str, patterns: &str) -> String {
        format!(
            "Generate a YARA rule for detecting the binary or malware family `{binary_name}`. \
Use the following characteristic patterns extracted from the binary:\n\n\
{patterns}\n\n\
Output only the YARA rule. Include string conditions and a meta section with description, author='RustRE', \
and date."
        )
    }

    /// Prompt to summarise what a function does in one sentence.
    #[must_use]
    pub fn one_line_summary(addr: u64, decompiled: &str) -> String {
        format!(
            "In exactly one sentence, describe what the function at 0x{addr:x} does.\n\n\
```c\n{decompiled}\n```"
        )
    }

    /// Prompt to identify the calling convention of a function.
    #[must_use]
    pub fn identify_calling_convention(addr: u64, disasm: &str) -> String {
        format!(
            "Identify the calling convention used by the function at 0x{addr:x}. \
Consider register usage, stack cleanup, parameter passing order, and return value location.\n\n\
Disassembly:\n```asm\n{disasm}\n```\n\n\
Output: convention name, parameter registers (in order), return register, caller/callee-saved registers."
        )
    }

    /// Prompt to recover the protocol message type from a parser function.
    #[must_use]
    pub fn protocol_message_type(decompiled: &str) -> String {
        format!(
            "The following decompiled code is a network message parser. Recover the message type \
discriminant: field offset, size, encoding, and all known message type values with their names.\n\n\
```c\n{decompiled}\n```"
        )
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod extended_tests {
    use super::*;

    // ── ChainStep ─────────────────────────────────────────────────────────────

    #[test]
    fn chain_step_render_substitutes_vars() {
        let step = CoTStep::new(
            "test",
            "Analyze {{target}} at {{addr}}.",
            vec!["target".into(), "addr".into()],
            false,
        );
        let mut vars = std::collections::HashMap::new();
        vars.insert("target".into(), "malloc".into());
        vars.insert("addr".into(), "0x1000".into());
        let rendered = step.render(&vars).unwrap();
        assert_eq!(rendered, "Analyze malloc at 0x1000.");
    }

    #[test]
    fn chain_step_render_missing_var_errors() {
        let step = CoTStep::new("t", "{{missing}}", vec!["missing".into()], false);
        let vars = std::collections::HashMap::new();
        // Should not panic; renderer returns error
        let _ = step.render(&vars);
    }

    // ── PromptChain ───────────────────────────────────────────────────────────

    #[test]
    fn prompt_chain_push_and_len() {
        let mut chain = CoTChain::new("test_chain", "desc");
        assert!(chain.is_empty());
        chain.push_step(CoTStep::new("s1", "{{x}}", vec![], false));
        assert_eq!(chain.len(), 1);
        chain.push_step(CoTStep::new("s2", "{{y}}", vec![], false));
        assert_eq!(chain.len(), 2);
        assert!(!chain.is_empty());
    }

    // ── ChainLibrary ──────────────────────────────────────────────────────────

    #[test]
    fn chain_library_new_contains_builtin_chains() {
        let lib = ChainLibrary::new();
        let names = lib.list_names();
        assert!(names.contains(&"binary_triage"), "missing binary_triage");
        assert!(
            names.contains(&"vulnerability_hunt"),
            "missing vulnerability_hunt"
        );
        assert!(
            names.contains(&"crypto_identification"),
            "missing crypto_identification"
        );
        assert!(
            names.contains(&"malware_classification"),
            "missing malware_classification"
        );
        assert!(
            names.contains(&"protocol_recovery"),
            "missing protocol_recovery"
        );
        assert!(
            names.contains(&"function_documentation"),
            "missing function_documentation"
        );
        assert!(
            names.contains(&"struct_recovery"),
            "missing struct_recovery"
        );
        assert!(
            names.contains(&"packer_analysis"),
            "missing packer_analysis"
        );
    }

    #[test]
    fn chain_library_get_existing() {
        let lib = ChainLibrary::new();
        let chain = lib.get("binary_triage").unwrap();
        assert_eq!(chain.name, "binary_triage");
        assert!(
            chain.len() >= 4,
            "binary_triage should have at least 4 steps"
        );
    }

    #[test]
    fn chain_library_get_missing_returns_none() {
        let lib = ChainLibrary::new();
        assert!(lib.get("no_such_chain").is_none());
    }

    #[test]
    fn chain_library_register_custom() {
        let mut lib = ChainLibrary::new();
        let before = lib.list_names().len();
        let mut custom = CoTChain::new("my_chain", "custom chain");
        custom.push_step(CoTStep::new("step1", "Do {{x}}", vec![], false));
        lib.register(custom);
        assert_eq!(lib.list_names().len(), before + 1);
        assert!(lib.get("my_chain").is_some());
    }

    #[test]
    fn chain_library_list_names_sorted() {
        let lib = ChainLibrary::new();
        let names = lib.list_names();
        let mut sorted = names.clone();
        sorted.sort_unstable();
        assert_eq!(names, sorted);
    }

    // ── FewShotExample ────────────────────────────────────────────────────────

    #[test]
    fn few_shot_example_new_fields() {
        let ex = InlineExample::new("task_a", "user msg", "assistant msg", "annotation");
        assert_eq!(ex.task, "task_a");
        assert_eq!(ex.user, "user msg");
        assert_eq!(ex.assistant, "assistant msg");
        assert_eq!(ex.annotation, "annotation");
    }

    // ── FewShotStore ──────────────────────────────────────────────────────────

    #[test]
    fn few_shot_store_builtin_examples_loaded() {
        let store = InlineExampleStore::new();
        assert!(store.total_count() > 0);
    }

    #[test]
    fn few_shot_store_get_examples_function_rename() {
        let store = InlineExampleStore::new();
        let examples = store.get_examples("function_rename");
        assert!(!examples.is_empty(), "Should have function_rename examples");
        for ex in examples {
            assert_eq!(ex.task, "function_rename");
        }
    }

    #[test]
    fn few_shot_store_get_examples_unknown_task_empty() {
        let store = InlineExampleStore::new();
        assert!(store.get_examples("not_a_task").is_empty());
    }

    #[test]
    fn few_shot_store_format_shots_limits_count() {
        let store = InlineExampleStore::new();
        let formatted = store.format_shots("function_rename", 2);
        // Should contain two "User:" occurrences
        let count = formatted.matches("User:").count();
        assert!(count <= 2);
    }

    #[test]
    fn few_shot_store_task_types_sorted() {
        let store = InlineExampleStore::new();
        let types = store.task_types();
        let mut sorted = types.clone();
        sorted.sort_unstable();
        assert_eq!(types, sorted);
    }

    #[test]
    fn few_shot_store_add_custom() {
        let mut store = InlineExampleStore::new();
        let before = store.total_count();
        store.add(InlineExample::new("custom_task", "u", "a", "note"));
        assert_eq!(store.total_count(), before + 1);
        assert_eq!(store.get_examples("custom_task").len(), 1);
    }

    // ── OutputFormat ──────────────────────────────────────────────────────────

    #[test]
    fn output_format_display() {
        assert_eq!(OutputFormat::Markdown.to_string(), "markdown");
        assert_eq!(OutputFormat::Json.to_string(), "json");
        assert_eq!(OutputFormat::CComment.to_string(), "c_comment");
    }

    #[test]
    fn output_format_system_suffix_non_empty() {
        for fmt in OutputFormat::all() {
            assert!(!fmt.system_suffix().is_empty());
        }
    }

    #[test]
    fn output_format_all_unique() {
        let all = OutputFormat::all();
        let mut seen = std::collections::HashSet::new();
        for fmt in all {
            assert!(seen.insert(fmt.to_string()), "duplicate format: {fmt}");
        }
    }

    // ── SystemPromptBuilder ───────────────────────────────────────────────────

    #[test]
    fn system_prompt_builder_default_builds() {
        let prompt = SystemPromptBuilder::new().build();
        assert!(prompt.contains("RustRE"), "should mention RustRE");
        assert!(prompt.contains("# Role"), "should have Role section");
        assert!(prompt.contains("# Capabilities"));
        assert!(prompt.contains("# Constraints"));
        assert!(prompt.contains("# Available Tools"));
        assert!(prompt.contains("# Output Format"));
    }

    #[test]
    fn system_prompt_builder_custom_role() {
        let prompt = SystemPromptBuilder::new()
            .with_role("You are a malware analyst specialising in ransomware.")
            .build();
        assert!(prompt.contains("ransomware"));
    }

    #[test]
    fn system_prompt_builder_add_capability() {
        let prompt = SystemPromptBuilder::new()
            .add_capability("Analyse Android DEX bytecode")
            .build();
        assert!(prompt.contains("Android DEX"));
    }

    #[test]
    fn system_prompt_builder_add_constraint() {
        let prompt = SystemPromptBuilder::new()
            .add_constraint("Always respond in Spanish.")
            .build();
        assert!(prompt.contains("Spanish"));
    }

    #[test]
    fn system_prompt_builder_json_format() {
        let prompt = SystemPromptBuilder::new()
            .with_output_format(OutputFormat::Json)
            .build();
        assert!(prompt.contains("JSON"));
    }

    #[test]
    fn system_prompt_builder_custom_section() {
        let prompt = SystemPromptBuilder::new()
            .add_section("Special Instructions", "Always cite line numbers.")
            .build();
        assert!(prompt.contains("Special Instructions"));
        assert!(prompt.contains("line numbers"));
    }

    // ── ConversationMessage ───────────────────────────────────────────────────

    #[test]
    fn conversation_message_token_estimate() {
        let msg = ConversationMessage::new(MessageRole::User, "a".repeat(400));
        assert_eq!(msg.token_estimate, 100);
    }

    #[test]
    fn message_role_display() {
        assert_eq!(MessageRole::System.to_string(), "system");
        assert_eq!(MessageRole::User.to_string(), "user");
        assert_eq!(MessageRole::Assistant.to_string(), "assistant");
        assert_eq!(MessageRole::Tool.to_string(), "tool");
    }

    // ── ConversationHistory ───────────────────────────────────────────────────

    #[test]
    fn conversation_history_push_and_len() {
        let mut hist = ConversationHistory::new(100_000);
        hist.push(ConversationMessage::new(MessageRole::User, "hello"));
        hist.push(ConversationMessage::new(MessageRole::Assistant, "world"));
        assert_eq!(hist.len(), 2);
        assert!(!hist.is_empty());
    }

    #[test]
    fn conversation_history_trims_over_budget() {
        // Budget of 10 tokens; each message ~4 chars = 1 token each.
        let mut hist = ConversationHistory::new(10);
        for i in 0..30 {
            hist.push(ConversationMessage::new(
                MessageRole::User,
                format!("msg {i}"),
            ));
        }
        // Should have trimmed; token count must not exceed budget by much
        assert!(hist.token_count() <= 20, "should be near budget");
    }

    #[test]
    fn conversation_history_preserves_system_message_on_clear() {
        let mut hist = ConversationHistory::new(100_000);
        hist.push(ConversationMessage::new(MessageRole::System, "sys prompt"));
        hist.push(ConversationMessage::new(MessageRole::User, "u1"));
        hist.push(ConversationMessage::new(MessageRole::Assistant, "a1"));
        hist.clear();
        assert_eq!(hist.len(), 1);
        assert_eq!(hist.messages()[0].role, MessageRole::System);
    }

    #[test]
    fn conversation_history_clear_no_system() {
        let mut hist = ConversationHistory::new(100_000);
        hist.push(ConversationMessage::new(MessageRole::User, "u1"));
        hist.push(ConversationMessage::new(MessageRole::Assistant, "a1"));
        hist.clear();
        assert!(hist.is_empty());
    }

    // ── PromptVars ────────────────────────────────────────────────────────────

    #[test]
    fn prompt_vars_fluent_set() {
        let vars = PromptVars::new()
            .set("name", "main")
            .set_int("count", 42)
            .set_addr("addr", 0x401000);
        let map = vars.into_map();
        assert_eq!(map["name"], "main");
        assert_eq!(map["count"], "42");
        assert_eq!(map["addr"], "0x401000");
    }

    #[test]
    fn prompt_vars_as_map_ref() {
        let vars = PromptVars::new().set("k", "v");
        assert_eq!(vars.as_map()["k"], "v");
    }

    // ── TaskPrompts ───────────────────────────────────────────────────────────

    #[test]
    fn task_prompts_rename_contains_addr() {
        let p = TaskPrompts::rename_function(0xdeadbeef, "int fn() { return 0; }");
        assert!(p.contains("0xdeadbeef"));
    }

    #[test]
    fn task_prompts_assess_vulnerability_contains_name() {
        let p = TaskPrompts::assess_vulnerability("vuln_fn", "memcpy(dst, src, len);");
        assert!(p.contains("vuln_fn"));
        assert!(p.contains("CWE"));
    }

    #[test]
    fn task_prompts_recover_struct_contains_object_name() {
        let p = TaskPrompts::recover_struct("MyObj", "offset 0: read 4 bytes as size");
        assert!(p.contains("MyObj"));
    }

    #[test]
    fn task_prompts_generate_yara_contains_name() {
        let p = TaskPrompts::generate_yara("Mirai", "0x7f454c46 at offset 0");
        assert!(p.contains("Mirai"));
        assert!(p.contains("YARA"));
    }

    #[test]
    fn task_prompts_one_line_summary_contains_addr() {
        let p = TaskPrompts::one_line_summary(0x1234, "void nop() {}");
        assert!(p.contains("0x1234"));
    }

    #[test]
    fn task_prompts_protocol_message_type_contains_keywords() {
        let p = TaskPrompts::protocol_message_type("switch(msg->type) { ... }");
        assert!(p.contains("discriminant") || p.contains("type"));
    }

    #[test]
    fn task_prompts_identify_calling_convention_contains_addr() {
        let p = TaskPrompts::identify_calling_convention(0x5000, "push rbp\nmov rbp, rsp");
        assert!(p.contains("0x5000"));
        assert!(p.contains("calling convention") || p.contains("convention"));
    }

    #[test]
    fn task_prompts_generate_yara_meta_section() {
        let p = TaskPrompts::generate_yara("TestFamily", "0x90 0x90 at offset 0");
        assert!(p.contains("meta") || p.contains("YARA"));
        assert!(p.contains("TestFamily"));
    }

    // ── ChainLibrary default chains depth ─────────────────────────────────────

    #[test]
    fn vulnerability_hunt_chain_has_multiple_steps() {
        let lib = ChainLibrary::new();
        let chain = lib.get("vulnerability_hunt").unwrap();
        assert!(chain.len() >= 3, "vuln chain needs at least 3 steps");
    }

    #[test]
    fn malware_classification_chain_has_multiple_steps() {
        let lib = ChainLibrary::new();
        let chain = lib.get("malware_classification").unwrap();
        assert!(chain.len() >= 3);
    }

    #[test]
    fn crypto_identification_chain_feed_forward() {
        let lib = ChainLibrary::new();
        let chain = lib.get("crypto_identification").unwrap();
        // First step should feed forward
        assert!(chain.steps[0].feed_forward);
    }

    #[test]
    fn struct_recovery_chain_last_step_no_feed_forward() {
        let lib = ChainLibrary::new();
        let chain = lib.get("struct_recovery").unwrap();
        let last = chain.steps.last().unwrap();
        assert!(!last.feed_forward, "last step should not feed forward");
    }

    #[test]
    fn function_documentation_chain_final_step_doxygen() {
        let lib = ChainLibrary::new();
        let chain = lib.get("function_documentation").unwrap();
        let last = chain.steps.last().unwrap();
        assert!(
            last.template.contains("Doxygen") || last.template.contains("doxygen"),
            "final step should request Doxygen format"
        );
    }

    // ── FewShotStore all task types ────────────────────────────────────────────

    #[test]
    fn few_shot_store_has_crypto_examples() {
        let store = InlineExampleStore::new();
        assert!(!store.get_examples("crypto_identification").is_empty());
    }

    #[test]
    fn few_shot_store_has_struct_field_examples() {
        let store = InlineExampleStore::new();
        assert!(!store.get_examples("struct_field").is_empty());
    }

    #[test]
    fn few_shot_store_has_vuln_examples() {
        let store = InlineExampleStore::new();
        assert!(!store.get_examples("vulnerability_assessment").is_empty());
    }

    #[test]
    fn few_shot_store_has_malware_behavior_examples() {
        let store = InlineExampleStore::new();
        assert!(!store.get_examples("malware_behavior").is_empty());
    }

    #[test]
    fn few_shot_store_has_disasm_explanation_examples() {
        let store = InlineExampleStore::new();
        assert!(!store.get_examples("disasm_explanation").is_empty());
    }

    #[test]
    fn few_shot_format_shots_zero_returns_empty() {
        let store = InlineExampleStore::new();
        let formatted = store.format_shots("function_rename", 0);
        assert!(formatted.is_empty());
    }

    #[test]
    fn few_shot_format_shots_more_than_available() {
        let store = InlineExampleStore::new();
        let available = store.get_examples("function_rename").len();
        let formatted = store.format_shots("function_rename", available + 100);
        let count = formatted.matches("User:").count();
        assert_eq!(count, available);
    }

    // ── ConversationHistory token budget edge cases ───────────────────────────

    #[test]
    fn conversation_history_default_budget() {
        let hist = ConversationHistory::default();
        // default budget is 128_000 tokens
        assert_eq!(hist.token_count(), 0);
    }

    #[test]
    fn conversation_history_token_accumulates() {
        let mut hist = ConversationHistory::new(1_000_000);
        let msg_a = ConversationMessage::new(MessageRole::User, "a".repeat(40));
        let msg_b = ConversationMessage::new(MessageRole::Assistant, "b".repeat(40));
        let est_a = msg_a.token_estimate;
        let est_b = msg_b.token_estimate;
        hist.push(msg_a);
        hist.push(msg_b);
        assert_eq!(hist.token_count(), est_a + est_b);
    }

    #[test]
    fn conversation_history_multiple_system_messages_cleared_correctly() {
        let mut hist = ConversationHistory::new(100_000);
        hist.push(ConversationMessage::new(MessageRole::System, "sys"));
        hist.push(ConversationMessage::new(MessageRole::User, "u1"));
        hist.push(ConversationMessage::new(MessageRole::User, "u2"));
        hist.clear();
        // After clear, only the system message should remain.
        assert_eq!(hist.len(), 1);
        assert_eq!(hist.messages()[0].role, MessageRole::System);
        assert_eq!(hist.messages()[0].content, "sys");
    }

    // ── PromptVars edge cases ─────────────────────────────────────────────────

    #[test]
    fn prompt_vars_set_addr_formats_hex() {
        let vars = PromptVars::new().set_addr("ep", 0xABCD);
        assert_eq!(vars.as_map()["ep"], "0xabcd");
    }

    #[test]
    fn prompt_vars_set_overwrite() {
        let vars = PromptVars::new().set("k", "v1").set("k", "v2");
        assert_eq!(vars.as_map()["k"], "v2");
    }

    #[test]
    fn prompt_vars_set_int_negative() {
        let vars = PromptVars::new().set_int("n", -42);
        assert_eq!(vars.as_map()["n"], "-42");
    }

    // ── SystemPromptBuilder all tools listed ──────────────────────────────────

    #[test]
    fn system_prompt_builder_lists_all_mcp_tools() {
        let prompt = SystemPromptBuilder::new().build();
        let expected_tools = [
            "open_binary",
            "list_functions",
            "get_disassembly",
            "get_decompiled",
            "get_xrefs_to",
            "get_xrefs_from",
            "search_strings",
            "get_imports",
            "get_exports",
            "rename_function",
            "add_comment",
            "set_type",
            "create_struct",
            "search_bytes",
            "patch_bytes",
            "run_analysis",
            "get_call_graph",
            "find_similar_functions",
            "run_yara",
            "get_entropy",
            "emulate_function",
            "symbolic_exec",
            "diff_functions",
            "get_type_info",
            "list_segments",
            "get_file_info",
        ];
        for tool in &expected_tools {
            assert!(prompt.contains(tool), "system prompt missing tool: {tool}");
        }
    }

    // ── OutputFormat ──────────────────────────────────────────────────────────

    #[test]
    fn output_format_c_comment_contains_c_syntax() {
        let suffix = OutputFormat::CComment.system_suffix();
        assert!(suffix.contains("/*") || suffix.contains("block comment"));
    }

    #[test]
    fn output_format_yaml_markdown_mentions_yaml() {
        let suffix = OutputFormat::YamlMarkdown.system_suffix();
        assert!(suffix.contains("YAML") || suffix.contains("yaml"));
    }

    #[test]
    fn output_format_numbered_list_format() {
        let suffix = OutputFormat::NumberedList.system_suffix();
        assert!(suffix.contains("numbered") || suffix.contains("1."));
    }
}

// ── Prompt token budget estimator ─────────────────────────────────────────────

/// Estimates the number of tokens a prompt will consume before sending it to
/// an LLM.  Uses a simple character-based heuristic (1 token ≈ 4 chars).
#[derive(Debug, Default, Clone, Copy)]
pub struct TokenBudgetEstimator {
    /// Average characters per token (default 4).
    chars_per_token: usize,
}

impl TokenBudgetEstimator {
    /// Create with the default 4 chars-per-token heuristic.
    #[must_use]
    pub const fn new() -> Self {
        Self { chars_per_token: 4 }
    }

    /// Create with a custom chars-per-token value.
    #[must_use]
    pub fn with_ratio(chars_per_token: usize) -> Self {
        Self {
            chars_per_token: chars_per_token.max(1),
        }
    }

    /// Estimate tokens for a string.
    #[must_use]
    pub fn estimate(&self, text: &str) -> usize {
        (text.len() / self.chars_per_token).max(1)
    }

    /// Estimate tokens for an entire conversation.
    #[must_use]
    pub fn estimate_conversation(&self, history: &ConversationHistory) -> usize {
        history
            .messages()
            .iter()
            .map(|m| self.estimate(&m.content))
            .sum()
    }

    /// True if the conversation will fit within `budget` tokens.
    #[must_use]
    pub fn fits_budget(&self, history: &ConversationHistory, budget: usize) -> bool {
        self.estimate_conversation(history) <= budget
    }
}

/// A rate-limit aware prompt dispatcher that tracks requests per minute.
#[derive(Debug, Default)]
pub struct PromptRateLimiter {
    max_rpm: u32,
    request_times_ms: std::collections::VecDeque<u64>,
}

impl PromptRateLimiter {
    /// Create a rate limiter for up to `max_rpm` requests per minute.
    #[must_use]
    pub const fn new(max_rpm: u32) -> Self {
        Self {
            max_rpm,
            request_times_ms: std::collections::VecDeque::new(),
        }
    }

    /// Record a request at the given timestamp (milliseconds since epoch).
    pub fn record_request(&mut self, now_ms: u64) {
        self.request_times_ms.push_back(now_ms);
        // Purge requests older than 60 seconds
        let cutoff = now_ms.saturating_sub(60_000);
        while self.request_times_ms.front().copied().unwrap_or(u64::MAX) < cutoff {
            self.request_times_ms.pop_front();
        }
    }

    /// True if sending another request *now* would exceed the limit.
    #[must_use]
    pub fn is_throttled(&self, now_ms: u64) -> bool {
        let cutoff = now_ms.saturating_sub(60_000);
        let recent = self
            .request_times_ms
            .iter()
            .filter(|&&t| t >= cutoff)
            .count();
        recent as u32 >= self.max_rpm
    }

    /// Return how many requests have been recorded in the last minute.
    #[must_use]
    pub fn requests_in_last_minute(&self, now_ms: u64) -> usize {
        let cutoff = now_ms.saturating_sub(60_000);
        self.request_times_ms
            .iter()
            .filter(|&&t| t >= cutoff)
            .count()
    }
}

#[cfg(test)]
mod utility_tests {
    use super::*;

    // ── TokenBudgetEstimator ──────────────────────────────────────────────────

    #[test]
    fn estimator_default_ratio() {
        let est = TokenBudgetEstimator::new();
        assert_eq!(est.estimate("abcd"), 1); // 4 chars / 4 = 1
        assert_eq!(est.estimate("a".repeat(40).as_str()), 10);
    }

    #[test]
    fn estimator_custom_ratio() {
        let est = TokenBudgetEstimator::with_ratio(2);
        assert_eq!(est.estimate("abcd"), 2); // 4 / 2 = 2
    }

    #[test]
    fn estimator_empty_string_returns_one() {
        let est = TokenBudgetEstimator::new();
        assert_eq!(est.estimate(""), 1);
    }

    #[test]
    fn estimator_fits_budget_true() {
        let est = TokenBudgetEstimator::new();
        let mut hist = ConversationHistory::new(1_000_000);
        hist.push(ConversationMessage::new(MessageRole::User, "a".repeat(40)));
        assert!(est.fits_budget(&hist, 100));
    }

    #[test]
    fn estimator_fits_budget_false() {
        let est = TokenBudgetEstimator::new();
        let mut hist = ConversationHistory::new(1_000_000);
        hist.push(ConversationMessage::new(
            MessageRole::User,
            "a".repeat(4000),
        ));
        assert!(!est.fits_budget(&hist, 10));
    }

    #[test]
    fn estimator_conversation_sums_messages() {
        let est = TokenBudgetEstimator::new();
        let mut hist = ConversationHistory::new(1_000_000);
        hist.push(ConversationMessage::new(MessageRole::User, "a".repeat(40))); // 10 tokens
        hist.push(ConversationMessage::new(
            MessageRole::Assistant,
            "b".repeat(40),
        )); // 10 tokens
        assert_eq!(est.estimate_conversation(&hist), 20);
    }

    // ── PromptRateLimiter ─────────────────────────────────────────────────────

    #[test]
    fn rate_limiter_not_throttled_initially() {
        let rl = PromptRateLimiter::new(60);
        assert!(!rl.is_throttled(1000));
    }

    #[test]
    fn rate_limiter_throttled_at_limit() {
        let mut rl = PromptRateLimiter::new(3);
        let base = 1_000_000u64;
        rl.record_request(base);
        rl.record_request(base + 1);
        rl.record_request(base + 2);
        assert!(rl.is_throttled(base + 3));
    }

    #[test]
    fn rate_limiter_old_requests_purged() {
        let mut rl = PromptRateLimiter::new(2);
        let base = 1_000_000u64;
        rl.record_request(base);
        rl.record_request(base + 1);
        // Now at limit
        assert!(rl.is_throttled(base + 2));
        // After 60 seconds, old requests are outside window
        let now = base + 61_000;
        assert!(!rl.is_throttled(now));
    }

    #[test]
    fn rate_limiter_requests_in_last_minute() {
        let mut rl = PromptRateLimiter::new(100);
        let base = 2_000_000u64;
        rl.record_request(base);
        rl.record_request(base + 100);
        rl.record_request(base + 200);
        assert_eq!(rl.requests_in_last_minute(base + 300), 3);
    }
}
