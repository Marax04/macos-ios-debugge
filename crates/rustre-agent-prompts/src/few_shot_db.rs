// rustre-agent-prompts/src/few_shot_db.rs
//
// Few-shot example database — **dynamic, persistent** layer.
//   - Categorised examples (input: disasm/pseudocode → output: analysis/rename/classify)
//   - JSON-file backed persistence (SQLite comment kept for historical context)
//   - Cosine-similarity ranking against query embeddings (falls back to keyword overlap)
//   - JSONL import/export, per-db statistics, quality scores
//   - In-context few-shot injection helpers
//
// Distinct from `few_shot_examples`:
//   `few_shot_db` is runtime-mutable — add, remove, persist, and rank by embedding.
//   `few_shot_examples` is a compile-time static library with curated examples
//   and multiple formatting styles; use it when you don't need persistence.

use std::{
    collections::HashMap,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use thiserror::Error;

// ─────────────────────────────── Error ───────────────────────────────────────

#[derive(Debug, Error)]
pub enum FewShotError {
    #[error("database error: {0}")]
    Db(String),
    #[error("serialization error: {0}")]
    Serialize(String),
    #[error("example not found: {0}")]
    NotFound(String),
    #[error("embedding dimension mismatch: {0} vs {1}")]
    DimMismatch(usize, usize),
}

pub type FewShotResult<T> = Result<T, FewShotError>;

// ─────────────────────────────── Example category ────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExampleCategory {
    Malware,
    Legitimate,
    Crypto,
    Network,
    Packer,
    Vulnerability,
    Ctf,
    Protocol,
    Custom(String),
}

impl std::fmt::Display for ExampleCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Custom(s) => write!(f, "custom:{s}"),
            other => {
                let j = serde_json::to_value(other).unwrap_or_default();
                write!(f, "{}", j.as_str().unwrap_or("unknown"))
            }
        }
    }
}

// ─────────────────────────────── Example ─────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FewShotExample {
    pub id: String,
    pub category: ExampleCategory,
    pub task: String,       // e.g. "rename_function", "classify_malware"
    pub input: String,      // disasm / pseudocode / strings / etc.
    pub output: String,     // expected JSON or text output
    pub description: String,
    pub tags: Vec<String>,
    pub quality_score: f32, // 0.0–1.0, human-assigned quality
    pub created_ms: u64,
    pub source: String, // "builtin", "user", "imported"
    /// Embedding vector (not stored in DB, computed on demand).
    #[serde(skip)]
    pub embedding: Option<Vec<f32>>,
}

impl FewShotExample {
    pub fn new(
        category: ExampleCategory,
        task: impl Into<String>,
        input: impl Into<String>,
        output: impl Into<String>,
        description: impl Into<String>,
    ) -> Self {
        let id = format!("fs-{}-{}", now_ms(), next_seq());
        Self {
            id,
            category,
            task: task.into(),
            input: input.into(),
            output: output.into(),
            description: description.into(),
            tags: Vec::new(),
            quality_score: 1.0,
            created_ms: now_ms(),
            source: "user".to_owned(),
            embedding: None,
        }
    }

    pub fn builtin(
        category: ExampleCategory,
        task: impl Into<String>,
        input: impl Into<String>,
        output: impl Into<String>,
        description: impl Into<String>,
    ) -> Self {
        let mut e = Self::new(category, task, input, output, description);
        e.source = "builtin".to_owned();
        e
    }

    pub fn with_tags(mut self, tags: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.tags = tags.into_iter().map(|t| t.into()).collect();
        self
    }

    pub fn with_quality(mut self, q: f32) -> Self {
        // `f32::clamp` propagates NaN rather than sanitising it, so a NaN would
        // settle into the field and then lose every ranking comparison it takes
        // part in — the example would silently drop out of every selection.
        self.quality_score = if q.is_nan() { 0.0 } else { q.clamp(0.0, 1.0) };
        self
    }

    pub fn with_embedding(mut self, emb: Vec<f32>) -> Self {
        self.embedding = Some(emb);
        self
    }

    /// Format as an in-context example block.
    pub fn format_for_prompt(&self) -> String {
        format!(
            "<example description=\"{}\">\n<input>\n{}\n</input>\n<output>\n{}\n</output>\n</example>",
            self.description, self.input, self.output
        )
    }
}

fn next_seq() -> u64 {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    SEQ.fetch_add(1, Ordering::Relaxed)
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

// ─────────────────────────────── Similarity math ─────────────────────────────

fn cosine_similarity(a: &[f32], b: &[f32]) -> f32 {
    if a.len() != b.len() || a.is_empty() { return 0.0; }
    let dot: f32 = a.iter().zip(b).map(|(x, y)| x * y).sum();
    let na = a.iter().map(|x| x * x).sum::<f32>().sqrt();
    let nb = b.iter().map(|x| x * x).sum::<f32>().sqrt();
    if na == 0.0 || nb == 0.0 { 0.0 } else { dot / (na * nb) }
}

/// Simple TF-IDF-like keyword overlap similarity (fallback when no embeddings).
fn keyword_similarity(a: &str, b: &str) -> f32 {
    let tokens_a: std::collections::HashSet<&str> = a.split_whitespace().collect();
    let tokens_b: std::collections::HashSet<&str> = b.split_whitespace().collect();
    if tokens_a.is_empty() || tokens_b.is_empty() { return 0.0; }
    let inter = tokens_a.intersection(&tokens_b).count() as f32;
    let union = tokens_a.union(&tokens_b).count() as f32;
    inter / union
}

// ─────────────────────────────── Index ───────────────────────────────────────

/// In-memory index for fast similarity retrieval.
struct ExampleIndex {
    examples: Vec<FewShotExample>,
}

impl ExampleIndex {
    fn new() -> Self { Self { examples: Vec::new() } }

    fn add(&mut self, ex: FewShotExample) {
        // Replace if same id
        if let Some(pos) = self.examples.iter().position(|e| e.id == ex.id) {
            self.examples[pos] = ex;
        } else {
            self.examples.push(ex);
        }
    }

    fn remove(&mut self, id: &str) -> bool {
        let before = self.examples.len();
        self.examples.retain(|e| e.id != id);
        self.examples.len() < before
    }

    fn get(&self, id: &str) -> Option<&FewShotExample> {
        self.examples.iter().find(|e| e.id == id)
    }

    fn by_task(&self, task: &str) -> Vec<&FewShotExample> {
        self.examples.iter().filter(|e| e.task == task).collect()
    }

    fn by_category(&self, cat: &ExampleCategory) -> Vec<&FewShotExample> {
        self.examples.iter().filter(|e| &e.category == cat).collect()
    }

    /// Rank by cosine similarity if embeddings present, else by keyword overlap.
    fn rank_by_similarity(&self, query: &str, query_emb: Option<&[f32]>, task: Option<&str>, top_k: usize) -> Vec<(&FewShotExample, f32)> {
        let mut scored: Vec<(&FewShotExample, f32)> = self
            .examples
            .iter()
            .filter(|e| task.map_or(true, |t| e.task == t))
            .map(|e| {
                let score = if let (Some(qe), Some(ee)) = (query_emb, e.embedding.as_ref()) {
                    cosine_similarity(qe, ee)
                } else {
                    keyword_similarity(query, &e.input)
                };
                // Weight by quality score
                (e, score * e.quality_score)
            })
            .collect();
        scored.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        scored.truncate(top_k);
        scored
    }
}

// ─────────────────────────────── Persistence ─────────────────────────────────

/// JSON-file backed persistence (full SQLite would need rusqlite feature).
struct Persistence {
    path: PathBuf,
}

impl Persistence {
    fn new(path: PathBuf) -> Self { Self { path } }

    fn load(&self) -> FewShotResult<Vec<FewShotExample>> {
        if !self.path.exists() { return Ok(Vec::new()); }
        let bytes = std::fs::read(&self.path)
            .map_err(|e| FewShotError::Db(e.to_string()))?;
        serde_json::from_slice(&bytes)
            .map_err(|e| FewShotError::Serialize(e.to_string()))
    }

    fn save(&self, examples: &[FewShotExample]) -> FewShotResult<()> {
        let json = serde_json::to_vec_pretty(examples)
            .map_err(|e| FewShotError::Serialize(e.to_string()))?;
        std::fs::write(&self.path, &json)
            .map_err(|e| FewShotError::Db(e.to_string()))
    }
}

// ─────────────────────────────── FewShotDb ───────────────────────────────────

/// Main few-shot database.
pub struct FewShotDb {
    index: RwLock<ExampleIndex>,
    persistence: Option<Persistence>,
}

impl FewShotDb {
    pub fn in_memory() -> Self {
        let mut db = Self { index: RwLock::new(ExampleIndex::new()), persistence: None };
        db.load_builtins();
        db
    }

    pub fn with_file(path: impl Into<PathBuf>) -> FewShotResult<Self> {
        let p = Persistence::new(path.into());
        let examples = p.load()?;
        let mut idx = ExampleIndex::new();
        for e in examples { idx.add(e); }
        let mut db = Self { index: RwLock::new(idx), persistence: Some(p) };
        db.load_builtins();
        Ok(db)
    }

    fn load_builtins(&mut self) {
        for e in builtin_examples() {
            self.index.write().add(e);
        }
    }

    // ── CRUD ──────────────────────────────────────────────────────────────────

    pub fn add(&self, ex: FewShotExample) -> String {
        let id = ex.id.clone();
        self.index.write().add(ex.clone());
        if let Some(p) = &self.persistence {
            let examples: Vec<FewShotExample> = self.index.read().examples.clone();
            let _ = p.save(&examples);
        }
        id
    }

    pub fn get(&self, id: &str) -> Option<FewShotExample> {
        self.index.read().get(id).cloned()
    }

    pub fn remove(&self, id: &str) -> bool {
        let removed = self.index.write().remove(id);
        if removed {
            if let Some(p) = &self.persistence {
                let examples: Vec<FewShotExample> = self.index.read().examples.clone();
                let _ = p.save(&examples);
            }
        }
        removed
    }

    pub fn count(&self) -> usize { self.index.read().examples.len() }

    pub fn all(&self) -> Vec<FewShotExample> { self.index.read().examples.clone() }

    // ── Query ─────────────────────────────────────────────────────────────────

    pub fn by_task(&self, task: &str) -> Vec<FewShotExample> {
        self.index.read().by_task(task).into_iter().cloned().collect()
    }

    pub fn by_category(&self, cat: &ExampleCategory) -> Vec<FewShotExample> {
        self.index.read().by_category(cat).into_iter().cloned().collect()
    }

    /// Find the top-k most similar examples to the query.
    pub fn similar(
        &self,
        query: &str,
        query_embedding: Option<&[f32]>,
        task: Option<&str>,
        top_k: usize,
    ) -> Vec<(FewShotExample, f32)> {
        self.index
            .read()
            .rank_by_similarity(query, query_embedding, task, top_k)
            .into_iter()
            .map(|(e, s)| (e.clone(), s))
            .collect()
    }

    /// Build a few-shot prompt block from the top-k similar examples.
    pub fn few_shot_block(
        &self,
        query: &str,
        query_embedding: Option<&[f32]>,
        task: Option<&str>,
        top_k: usize,
        max_tokens: usize,
    ) -> String {
        let examples = self.similar(query, query_embedding, task, top_k);
        let mut block = String::new();
        let mut token_budget = max_tokens;

        for (ex, _score) in &examples {
            let chunk = ex.format_for_prompt();
            let cost = chunk.len() / 4; // rough token estimate
            if cost > token_budget { break; }
            token_budget -= cost;
            block.push_str(&chunk);
            block.push('\n');
        }
        block
    }

    /// Export all examples as JSONL.
    pub fn export_jsonl(&self) -> FewShotResult<String> {
        let examples = self.all();
        examples
            .iter()
            .map(|e| serde_json::to_string(e).map_err(|e| FewShotError::Serialize(e.to_string())))
            .collect::<Result<Vec<_>, _>>()
            .map(|lines| lines.join("\n"))
    }

    /// Import from JSONL.
    pub fn import_jsonl(&self, jsonl: &str) -> FewShotResult<usize> {
        let mut count = 0;
        for line in jsonl.lines() {
            let line = line.trim();
            if line.is_empty() { continue; }
            let ex: FewShotExample = serde_json::from_str(line)
                .map_err(|e| FewShotError::Serialize(e.to_string()))?;
            self.add(ex);
            count += 1;
        }
        Ok(count)
    }

    /// Statistics summary.
    pub fn stats(&self) -> DbStats {
        let examples = self.index.read().examples.clone();
        let mut by_category: HashMap<String, usize> = HashMap::new();
        let mut by_task: HashMap<String, usize> = HashMap::new();
        let with_embeddings = examples.iter().filter(|e| e.embedding.is_some()).count();
        let avg_quality = if examples.is_empty() { 0.0 }
            else { examples.iter().map(|e| e.quality_score).sum::<f32>() / examples.len() as f32 };

        for e in &examples {
            *by_category.entry(e.category.to_string()).or_insert(0) += 1;
            *by_task.entry(e.task.clone()).or_insert(0) += 1;
        }

        DbStats {
            total: examples.len(),
            with_embeddings,
            avg_quality,
            by_category,
            by_task,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbStats {
    pub total: usize,
    pub with_embeddings: usize,
    pub avg_quality: f32,
    pub by_category: HashMap<String, usize>,
    pub by_task: HashMap<String, usize>,
}

// ─────────────────────────────── Builtin examples ────────────────────────────

fn builtin_examples() -> Vec<FewShotExample> {
    vec![
        // ── rename_function ───────────────────────────────────────────────────
        FewShotExample::builtin(
            ExampleCategory::Legitimate,
            "rename_function",
            "void* sub_1040(void* dst, void* src, size_t n) { memcpy(dst, src, n); return dst; }",
            r#"{"new_name":"copy_buffer","description":"Wraps memcpy, copies n bytes from src to dst","confidence":0.97}"#,
            "simple memcpy wrapper",
        ),

        FewShotExample::builtin(
            ExampleCategory::Crypto,
            "rename_function",
            "// XOR each byte with key[i % key_len]\nvoid sub_2000(uint8_t* data, size_t len, const uint8_t* key, size_t key_len) { for (size_t i=0; i<len; i++) data[i] ^= key[i % key_len]; }",
            r#"{"new_name":"xor_decrypt","description":"XOR decryption with repeating key","confidence":0.96}"#,
            "xor cipher",
        ),

        FewShotExample::builtin(
            ExampleCategory::Malware,
            "rename_function",
            "HANDLE sub_3000() { return CreateMutexA(NULL, TRUE, \"Global\\\\MutexXYZ1337\"); }",
            r#"{"new_name":"create_singleton_mutex","description":"Creates a named mutex to prevent multiple instances","confidence":0.93}"#,
            "singleton mutex",
        ),

        FewShotExample::builtin(
            ExampleCategory::Legitimate,
            "rename_function",
            "int sub_4000(const char* s) { int n = 0; while(*s) { n = n*31 + *s++; } return n; }",
            r#"{"new_name":"djb2_hash","description":"DJB2 string hash (polynomial rolling hash)","confidence":0.95}"#,
            "djb2 hash",
        ),

        // ── classify_malware ─────────────────────────────────────────────────
        FewShotExample::builtin(
            ExampleCategory::Malware,
            "classify_malware",
            "Imports: CryptEncrypt,CryptGenKey,FindFirstFileA,DeleteFileA / Strings: '.encrypted','.pay_ransom'",
            r#"{"family":"ransomware","capabilities":["file_encryption","file_deletion"],"threat_level":"critical","confidence":0.94}"#,
            "ransomware indicators",
        ),

        FewShotExample::builtin(
            ExampleCategory::Malware,
            "classify_malware",
            "Imports: WSASocket,connect,send,recv,CreateThread / Strings: 'bot','cmd','shell'",
            r#"{"family":"backdoor/rat","capabilities":["remote_shell","c2_communication"],"threat_level":"high","confidence":0.91}"#,
            "RAT indicators",
        ),

        FewShotExample::builtin(
            ExampleCategory::Malware,
            "classify_malware",
            "Imports: GetAsyncKeyState,SetWindowsHookEx,OpenClipboard / Strings: 'keylog','passwords'",
            r#"{"family":"keylogger","capabilities":["keylogging","clipboard_stealing"],"threat_level":"high","confidence":0.93}"#,
            "keylogger",
        ),

        // ── identify_crypto ──────────────────────────────────────────────────
        FewShotExample::builtin(
            ExampleCategory::Crypto,
            "identify_crypto",
            "static const uint32_t S[256] = { 0xd76aa478, 0xe8c7b756, ... }; // MD5 T-table",
            r#"{"algorithm":"MD5","role":"hash","confidence":0.98}"#,
            "MD5 T-table",
        ),

        FewShotExample::builtin(
            ExampleCategory::Crypto,
            "identify_crypto",
            "// AES S-box: 0x63,0x7c,0x77,0x7b,...\nstatic const uint8_t sbox[256] = { 0x63, 0x7c, 0x77, 0x7b };",
            r#"{"algorithm":"AES","role":"encrypt","confidence":0.99}"#,
            "AES S-box",
        ),

        FewShotExample::builtin(
            ExampleCategory::Crypto,
            "identify_crypto",
            "// RC4 KSA\nfor (int i=0; i<256; i++) S[i]=i;\nfor (int j=0,i=0; i<256; i++) { j=(j+S[i]+key[i%klen])%256; swap(S[i],S[j]); }",
            r#"{"algorithm":"RC4","role":"encrypt","confidence":0.97}"#,
            "RC4 KSA",
        ),

        // ── identify_packer ──────────────────────────────────────────────────
        FewShotExample::builtin(
            ExampleCategory::Packer,
            "identify_packer",
            "ep_bytes: 60 BE 00 90 44 00 8D BE 00 80 FB FF 57 83 CD FF EB / section: UPX0 size=0 entropy=0 / UPX1 size=204800 entropy=7.8",
            r#"{"packer":"UPX","version":"3.x","confidence":0.97}"#,
            "UPX packed PE",
        ),

        FewShotExample::builtin(
            ExampleCategory::Packer,
            "identify_packer",
            "single .text section entropy=7.95 / imports: only kernel32.dll GetProcAddress LoadLibraryA / entry point: VM bytecode dispatcher",
            r#"{"packer":"VMProtect","version":"unknown","confidence":0.88}"#,
            "VMProtect indicators",
        ),

        // ── vulnerability_hunt ───────────────────────────────────────────────
        FewShotExample::builtin(
            ExampleCategory::Vulnerability,
            "hunt_vulnerability",
            "char buf[64]; gets(buf); // no length check",
            r#"{"vulnerabilities":[{"class":"stack_buffer_overflow","description":"gets() does not check buffer size","exploitability":"high","poc_sketch":"python3 -c \"print('A'*100)\" | ./target"}]}"#,
            "classic gets() overflow",
        ),

        FewShotExample::builtin(
            ExampleCategory::Vulnerability,
            "hunt_vulnerability",
            "size_t sz = user_input * sizeof(int); void* p = malloc(sz); // integer overflow when user_input is large",
            r#"{"vulnerabilities":[{"class":"integer_overflow","description":"Multiplication can overflow, causing undersized allocation","exploitability":"medium","poc_sketch":"send user_input=0x40000001"}]}"#,
            "integer overflow → heap overflow",
        ),

        // ── solve_ctf ────────────────────────────────────────────────────────
        FewShotExample::builtin(
            ExampleCategory::Ctf,
            "solve_ctf",
            "flag = input; for (int i=0; i<len; i++) flag[i] ^= 0x42; if (!strcmp(flag, expected)) win();",
            r#"{"flag":"CTF{xor_is_fun}","approach":"XOR each byte of expected with 0x42","script":"print(bytes(b ^ 0x42 for b in expected))","confidence":0.99}"#,
            "simple XOR CTF",
        ),

        // ── protocol_reversal ────────────────────────────────────────────────
        FewShotExample::builtin(
            ExampleCategory::Protocol,
            "reverse_protocol",
            "recv 4 bytes magic; recv 2 bytes cmd; recv 4 bytes length; recv length bytes payload; dispatch(cmd, payload);",
            r#"{"protocol_name":"custom_binary","framing":"magic+TLV","message_format":[{"field":"magic","type":"uint32","offset":0,"size":4},{"field":"cmd","type":"uint16","offset":4,"size":2},{"field":"length","type":"uint32","offset":6,"size":4},{"field":"payload","type":"bytes","offset":10,"size":-1}]}"#,
            "magic+TLV protocol",
        ),

        // ── behavior analysis ────────────────────────────────────────────────
        FewShotExample::builtin(
            ExampleCategory::Malware,
            "api_sequence_analysis",
            "OpenSCManager → CreateService → StartService → CloseServiceHandle",
            r#"{"behavior":"service_installation","category":"persistence","intent":"Install malware as a Windows service for persistence","confidence":0.93}"#,
            "service persistence",
        ),

        FewShotExample::builtin(
            ExampleCategory::Malware,
            "api_sequence_analysis",
            "NtQuerySystemInformation(SystemProcessInformation) → loop checking process names → match 'wireshark' → ExitProcess",
            r#"{"behavior":"sandbox_evasion","category":"anti_analysis","intent":"Detect analysis tools and exit","confidence":0.91}"#,
            "process name check evasion",
        ),

        // ── string decryption ────────────────────────────────────────────────
        FewShotExample::builtin(
            ExampleCategory::Malware,
            "decrypt_strings",
            "blobs: [0x41^0x1f, 0x42^0x1f, ...] / key: 0x1f / loop: for i: blob[i] ^= 0x1f",
            r#"{"algorithm":"single-byte XOR","key":"0x1f","decrypted_strings":["CreateRemoteThread","VirtualAlloc"],"script":"print(bytes(b ^ 0x1f for b in blob))"}"#,
            "single-byte XOR decryption",
        ),
    ]
}

// ─────────────────────────────── unit tests ──────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn db() -> FewShotDb { FewShotDb::in_memory() }

    #[test]
    fn builtin_examples_loaded() {
        let d = db();
        assert!(d.count() > 10);
    }

    #[test]
    fn add_and_get() {
        let d = db();
        let ex = FewShotExample::new(
            ExampleCategory::Legitimate,
            "rename_function",
            "void* memcpy_wrap(...){}",
            r#"{"new_name":"safe_copy"}"#,
            "test",
        );
        let id = d.add(ex.clone());
        let got = d.get(&id).unwrap();
        assert_eq!(got.task, "rename_function");
    }

    #[test]
    fn remove_example() {
        let d = db();
        let ex = FewShotExample::new(ExampleCategory::Ctf,"t","i","o","d");
        let id = d.add(ex);
        assert!(d.remove(&id));
        assert!(d.get(&id).is_none());
    }

    #[test]
    fn by_task_filter() {
        let d = db();
        let rename = d.by_task("rename_function");
        assert!(!rename.is_empty());
        assert!(rename.iter().all(|e| e.task == "rename_function"));
    }

    #[test]
    fn by_category_filter() {
        let d = db();
        let malware = d.by_category(&ExampleCategory::Malware);
        assert!(!malware.is_empty());
    }

    #[test]
    fn similar_keyword() {
        let d = db();
        let results = d.similar("AES S-box encryption", None, None, 3);
        assert!(!results.is_empty());
        // The AES example should score higher than unrelated examples
        assert!(results[0].1 > 0.0);
    }

    #[test]
    fn similar_embedding() {
        let d = db();
        // Add a custom example with a known embedding
        let ex = FewShotExample::new(
            ExampleCategory::Crypto,
            "identify_crypto",
            "AES round function",
            r#"{"algorithm":"AES"}"#,
            "aes test",
        ).with_embedding(vec![1.0, 0.0, 0.0]);
        d.add(ex);

        // Query with the same embedding — should get score ~1.0
        let results = d.similar("anything", Some(&[1.0, 0.0, 0.0]), None, 1);
        assert!(!results.is_empty());
        assert!((results[0].1 - 1.0).abs() < 0.01);
    }

    #[test]
    fn few_shot_block_non_empty() {
        let d = db();
        let block = d.few_shot_block("memcpy wrapper", None, Some("rename_function"), 3, 4096);
        assert!(block.contains("<example"));
        assert!(block.contains("</example>"));
    }

    #[test]
    fn export_and_import_jsonl() {
        let d = db();
        let jsonl = d.export_jsonl().unwrap();
        assert!(!jsonl.is_empty());
        let d2 = FewShotDb::in_memory();
        let imported = d2.import_jsonl(&jsonl).unwrap();
        assert!(imported > 0);
    }

    #[test]
    fn stats() {
        let d = db();
        let s = d.stats();
        assert!(s.total > 0);
        assert!(s.avg_quality > 0.0);
        assert!(!s.by_category.is_empty());
    }

    #[test]
    fn format_for_prompt() {
        let ex = FewShotExample::new(ExampleCategory::Ctf, "t", "input_text", "output_text", "desc");
        let formatted = ex.format_for_prompt();
        assert!(formatted.contains("<input>"));
        assert!(formatted.contains("input_text"));
        assert!(formatted.contains("</output>"));
    }

    #[test]
    fn cosine_sim_edge_cases() {
        assert_eq!(cosine_similarity(&[], &[]), 0.0);
        assert_eq!(cosine_similarity(&[0.0], &[1.0]), 0.0);
        assert!((cosine_similarity(&[1.0, 0.0], &[1.0, 0.0]) - 1.0).abs() < 1e-6);
    }

    #[test]
    fn keyword_sim_identical() {
        let s = "aes s-box encryption key schedule";
        assert!((keyword_similarity(s, s) - 1.0).abs() < 1e-6);
    }
}
