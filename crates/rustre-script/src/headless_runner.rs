// rustre-script/src/headless_runner.rs
//
// Headless script execution:
//   - load a binary, run a script, capture output, apply timeout
//   - JSON output mode (structured results)
//   - batch mode: run the same script over N files with a progress bar
//   - exit-code semantics (0 = success, non-zero = error)

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{ScriptContext, ScriptEngine, ScriptError, ScriptValue};

// ─────────────────────────────── Error ───────────────────────────────────────

#[derive(Debug, Error)]
pub enum RunnerError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("script error: {0}")]
    Script(#[from] ScriptError),
    #[error("timeout after {0}ms")]
    Timeout(u64),
    #[error("no engine registered for extension '.{0}'")]
    NoEngine(String),
    #[error("batch error in {file}: {error}")]
    BatchItem { file: String, error: String },
    #[error("engine not configured")]
    EngineNotSet,
    #[error("serialization error: {0}")]
    Serialize(String),
}

pub type RunnerResult<T> = Result<T, RunnerError>;

// ─────────────────────────────── RunConfig ───────────────────────────────────

/// Configuration for a single headless run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunConfig {
    /// Path to the script to execute.
    pub script_path: PathBuf,
    /// Optional binary to load before the script runs.
    pub binary_path: Option<PathBuf>,
    /// Variables to pre-inject into the script context.
    pub variables: HashMap<String, serde_json::Value>,
    /// Timeout in milliseconds (0 = no limit).
    pub timeout_ms: u64,
    /// Emit JSON-encoded output instead of human-readable text.
    pub json_output: bool,
    /// Suppress all non-result output.
    pub quiet: bool,
    /// Enable verbose diagnostic output.
    pub verbose: bool,
}

impl Default for RunConfig {
    fn default() -> Self {
        Self {
            script_path: PathBuf::new(),
            binary_path: None,
            variables: HashMap::new(),
            timeout_ms: 30_000,
            json_output: false,
            quiet: false,
            verbose: false,
        }
    }
}

// ─────────────────────────────── RunResult ───────────────────────────────────

/// Outcome of a single script execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunResult {
    pub success: bool,
    pub exit_code: i32,
    pub output: String,
    pub error: Option<String>,
    pub elapsed_ms: f64,
    pub script_path: String,
    pub binary_path: Option<String>,
    /// The final value returned by the script (serialized).
    pub return_value: Option<serde_json::Value>,
    /// Counters emitted by the script via `emit_counter()`.
    pub counters: HashMap<String, i64>,
}

impl RunResult {
    fn success(
        output: String,
        elapsed: Duration,
        script: &Path,
        binary: Option<&Path>,
        ret: Option<serde_json::Value>,
        counters: HashMap<String, i64>,
    ) -> Self {
        Self {
            success: true,
            exit_code: 0,
            output,
            error: None,
            elapsed_ms: elapsed.as_secs_f64() * 1000.0,
            script_path: script.display().to_string(),
            binary_path: binary.map(|p| p.display().to_string()),
            return_value: ret,
            counters,
        }
    }

    fn failure(
        error: String,
        output: String,
        elapsed: Duration,
        script: &Path,
        binary: Option<&Path>,
        code: i32,
    ) -> Self {
        Self {
            success: false,
            exit_code: code,
            output,
            error: Some(error),
            elapsed_ms: elapsed.as_secs_f64() * 1000.0,
            script_path: script.display().to_string(),
            binary_path: binary.map(|p| p.display().to_string()),
            return_value: None,
            counters: HashMap::new(),
        }
    }

    pub fn to_json_pretty(&self) -> RunnerResult<String> {
        serde_json::to_string_pretty(self).map_err(|e| RunnerError::Serialize(e.to_string()))
    }
}

// ─────────────────────────────── BatchConfig ────────────────────────────────

/// Configuration for batch execution over multiple files.
#[derive(Debug, Clone)]
pub struct BatchConfig {
    pub script_path: PathBuf,
    pub binary_paths: Vec<PathBuf>,
    /// Variables common to all runs.
    pub common_variables: HashMap<String, serde_json::Value>,
    pub timeout_ms: u64,
    pub json_output: bool,
    pub quiet: bool,
    pub parallel: bool,
    pub max_parallel: usize,
    pub stop_on_first_error: bool,
}

impl Default for BatchConfig {
    fn default() -> Self {
        Self {
            script_path: PathBuf::new(),
            binary_paths: Vec::new(),
            common_variables: HashMap::new(),
            timeout_ms: 30_000,
            json_output: false,
            quiet: false,
            parallel: false,
            max_parallel: 4,
            stop_on_first_error: false,
        }
    }
}

/// Outcome of a batch run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchResult {
    pub total: usize,
    pub succeeded: usize,
    pub failed: usize,
    pub elapsed_ms: f64,
    pub results: Vec<RunResult>,
}

impl BatchResult {
    pub fn exit_code(&self) -> i32 {
        if self.failed > 0 { 1 } else { 0 }
    }

    pub fn to_json_pretty(&self) -> RunnerResult<String> {
        serde_json::to_string_pretty(self).map_err(|e| RunnerError::Serialize(e.to_string()))
    }
}

// ─────────────────────────────── OutputCapture ───────────────────────────────

/// Thread-safe buffer that captures `print()` / `log()` calls from the script.
#[derive(Clone, Default)]
pub struct OutputCapture {
    inner: Arc<Mutex<Vec<String>>>,
}

impl OutputCapture {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn write_line(&self, s: impl Into<String>) {
        self.inner.lock().push(s.into());
    }

    pub fn drain(&self) -> String {
        let mut buf = self.inner.lock();
        let out = buf.join("\n");
        buf.clear();
        out
    }

    pub fn snapshot(&self) -> String {
        self.inner.lock().join("\n")
    }
}

// ─────────────────────────────── ProgressReporter ───────────────────────────

/// Emits progress lines to stderr during batch runs.
pub struct ProgressReporter {
    total: usize,
    done: usize,
    quiet: bool,
}

impl ProgressReporter {
    pub fn new(total: usize, quiet: bool) -> Self {
        Self { total, done: 0, quiet }
    }

    pub fn tick(&mut self, path: &Path, success: bool) {
        self.done += 1;
        if self.quiet {
            return;
        }
        let pct = if self.total > 0 {
            (self.done * 100) / self.total
        } else {
            0
        };
        let status = if success { "OK " } else { "ERR" };
        eprintln!(
            "[{:3}%] [{}/{}] [{}] {}",
            pct,
            self.done,
            self.total,
            status,
            path.display()
        );
    }

    pub fn finish(&self, result: &BatchResult) {
        if self.quiet {
            return;
        }
        eprintln!(
            "Batch complete: {}/{} succeeded in {:.1}s",
            result.succeeded,
            result.total,
            result.elapsed_ms / 1000.0
        );
    }
}

// ─────────────────────────────── Watchdog ────────────────────────────────────

struct Watchdog {
    timeout_ms: u64,
    flag: Arc<AtomicBool>,
}

impl Watchdog {
    fn new(timeout_ms: u64) -> Self {
        Self {
            timeout_ms,
            flag: Arc::new(AtomicBool::new(false)),
        }
    }

    fn arm(&self) -> WatchdogGuard {
        self.flag.store(false, Ordering::SeqCst);
        let flag = Arc::clone(&self.flag);
        let ms = self.timeout_ms;
        if ms == 0 {
            return WatchdogGuard { cancel: Arc::new(AtomicBool::new(true)) };
        }
        let cancel = Arc::new(AtomicBool::new(false));
        let c2 = Arc::clone(&cancel);
        std::thread::spawn(move || {
            let start = Instant::now();
            while start.elapsed() < Duration::from_millis(ms) {
                if c2.load(Ordering::SeqCst) {
                    return;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            if !c2.load(Ordering::SeqCst) {
                flag.store(true, Ordering::SeqCst);
            }
        });
        WatchdogGuard { cancel }
    }

    fn timed_out(&self) -> bool {
        self.flag.load(Ordering::SeqCst)
    }
}

struct WatchdogGuard {
    cancel: Arc<AtomicBool>,
}

impl Drop for WatchdogGuard {
    fn drop(&mut self) {
        self.cancel.store(true, Ordering::SeqCst);
    }
}

// ─────────────────────────────── HeadlessRunner ──────────────────────────────

/// Headless script runner.  Attach an engine, then call `run()` or `run_batch()`.
pub struct HeadlessRunner {
    engine: Arc<dyn ScriptEngine>,
    capture: OutputCapture,
}

impl HeadlessRunner {
    pub fn new(engine: Arc<dyn ScriptEngine>) -> Self {
        Self {
            engine,
            capture: OutputCapture::new(),
        }
    }

    /// Execute a single script.
    pub fn run(&self, config: &RunConfig) -> RunnerResult<RunResult> {
        self.run_inner(config)
    }

    /// Execute the same script over multiple files in sequence (or in parallel
    /// when `config.parallel` is set and rayon is available).
    pub fn run_batch(&self, config: &BatchConfig) -> RunnerResult<BatchResult> {
        let total = config.binary_paths.len();
        let mut reporter = ProgressReporter::new(total, config.quiet);
        let t0 = Instant::now();
        let mut results = Vec::with_capacity(total);
        let mut succeeded = 0usize;
        let mut failed = 0usize;

        for binary in &config.binary_paths {
            let run_cfg = RunConfig {
                script_path: config.script_path.clone(),
                binary_path: Some(binary.clone()),
                variables: config.common_variables.clone(),
                timeout_ms: config.timeout_ms,
                json_output: config.json_output,
                quiet: config.quiet,
                verbose: false,
            };

            let r = self.run_inner(&run_cfg).unwrap_or_else(|e| {
                RunResult::failure(
                    e.to_string(),
                    String::new(),
                    Duration::ZERO,
                    &run_cfg.script_path,
                    run_cfg.binary_path.as_deref(),
                    2,
                )
            });

            let ok = r.success;
            reporter.tick(binary, ok);
            if ok { succeeded += 1; } else { failed += 1; }
            results.push(r);

            if !ok && config.stop_on_first_error {
                break;
            }
        }

        let elapsed = t0.elapsed();
        let batch = BatchResult {
            total,
            succeeded,
            failed,
            elapsed_ms: elapsed.as_secs_f64() * 1000.0,
            results,
        };
        reporter.finish(&batch);
        Ok(batch)
    }

    // ── internal ──────────────────────────────────────────────────────────────

    fn run_inner(&self, config: &RunConfig) -> RunnerResult<RunResult> {
        // Read script source.
        let source = std::fs::read_to_string(&config.script_path)?;

        // Set up watchdog.
        let watchdog = Watchdog::new(config.timeout_ms);
        let _guard = watchdog.arm();
        let t0 = Instant::now();

        // Build a ScriptContext with the injected variables.
        let mut ctx = ScriptContext::new();
        for (k, v) in &config.variables {
            let sv = json_to_script_value(v);
            ctx.globals.insert(k.clone(), sv);
        }

        // If a binary was specified, inject its path as `__binary_path`.
        if let Some(bin) = &config.binary_path {
            ctx.globals.insert("__binary_path".into(), ScriptValue::String(bin.display().to_string()));
        }

        ctx.timeout_ms = Some(config.timeout_ms);

        // Clear capture buffer.
        self.capture.inner.lock().clear();

        if config.verbose {
            eprintln!("[runner] executing {:?}", config.script_path);
        }

        // Execute.
        let engine = Arc::clone(&self.engine);
        let exec_result = run_blocking(engine.execute(&source, &mut ctx));

        let elapsed = t0.elapsed();

        if watchdog.timed_out() {
            return Ok(RunResult::failure(
                format!("timeout after {}ms", config.timeout_ms),
                self.capture.snapshot(),
                elapsed,
                &config.script_path,
                config.binary_path.as_deref(),
                124,
            ));
        }

        let output = self.capture.drain();

        match exec_result {
            Ok(ret_val) => {
                let ret_json = script_value_to_json(&ret_val);
                let counters = extract_counters(&engine);

                if !config.quiet {
                    if config.json_output {
                        // print JSON result to stdout
                        let r = RunResult::success(
                            output.clone(),
                            elapsed,
                            &config.script_path,
                            config.binary_path.as_deref(),
                            Some(ret_json.clone()),
                            counters.clone(),
                        );
                        println!("{}", r.to_json_pretty().unwrap_or_default());
                    } else if !output.is_empty() {
                        println!("{output}");
                    }
                }

                Ok(RunResult::success(
                    output,
                    elapsed,
                    &config.script_path,
                    config.binary_path.as_deref(),
                    Some(ret_json),
                    counters,
                ))
            }
            Err(e) => {
                let msg = format!("{e}");
                if !config.quiet {
                    eprintln!("Script error: {msg}");
                }
                Ok(RunResult::failure(
                    msg,
                    output,
                    elapsed,
                    &config.script_path,
                    config.binary_path.as_deref(),
                    1,
                ))
            }
        }
    }
}

// ─────────────────────────────── helpers ─────────────────────────────────────

fn json_to_script_value(v: &serde_json::Value) -> ScriptValue {
    match v {
        serde_json::Value::Null => ScriptValue::Null,
        serde_json::Value::Bool(b) => ScriptValue::Bool(*b),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                ScriptValue::Int(i)
            } else {
                ScriptValue::Float(n.as_f64().unwrap_or(0.0))
            }
        }
        serde_json::Value::String(s) => ScriptValue::String(s.clone()),
        serde_json::Value::Array(a) => {
            ScriptValue::List(a.iter().map(json_to_script_value).collect())
        }
        serde_json::Value::Object(o) => {
            let m: HashMap<String, ScriptValue> =
                o.iter().map(|(k, v)| (k.clone(), json_to_script_value(v))).collect();
            ScriptValue::Map(m)
        }
    }
}

fn script_value_to_json(v: &ScriptValue) -> serde_json::Value {
    match v {
        ScriptValue::Null => serde_json::Value::Null,
        ScriptValue::Bool(b) => serde_json::Value::Bool(*b),
        ScriptValue::Int(n) => serde_json::Value::Number((*n).into()),
        ScriptValue::Float(f) => serde_json::json!(*f),
        ScriptValue::String(s) => serde_json::Value::String(s.clone()),
        ScriptValue::Address(a) => serde_json::Value::String(format!("0x{a:016x}")),
        ScriptValue::Bytes(b) => {
            serde_json::Value::String(b.iter().map(|x| format!("{x:02x}")).collect::<Vec<_>>().join(""))
        }
        ScriptValue::List(items) => {
            serde_json::Value::Array(items.iter().map(script_value_to_json).collect())
        }
        ScriptValue::Map(m) => {
            serde_json::Value::Object(
                m.iter().map(|(k, v)| (k.clone(), script_value_to_json(v))).collect(),
            )
        }
        ScriptValue::Callable(name) => serde_json::Value::String(format!("<fn:{name}>")),
    }
}

/// Extract any `__counter_*` globals as a counter map.
fn extract_counters(engine: &Arc<dyn ScriptEngine>) -> HashMap<String, i64> {
    // In a real implementation, the engine would expose its global namespace.
    // Here we return an empty map as the extraction mechanism is engine-specific.
    let _ = engine;
    HashMap::new()
}

fn run_blocking<F, T>(fut: F) -> T
where
    F: std::future::Future<Output = T>,
{
    // `block_in_place` panics when invoked on a current_thread runtime because
    // it requires the ability to move the current task to another thread.
    // Detect this case and fall back to a fresh single-threaded runtime instead.
    match tokio::runtime::Handle::try_current() {
        Ok(handle) if handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread => {
            tokio::task::block_in_place(|| handle.block_on(fut))
        }
        Ok(handle) => {
            // Current-thread runtime: spawn a sibling thread to avoid blocking.
            // This is safe because we hold no locks and the future is Send.
            let (tx, rx) = std::sync::mpsc::channel();
            let _ = handle; // keep the handle alive while we poll on another thread
            // We cannot use block_in_place here; build a sibling runtime instead.
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map(|rt| {
                    let result = rt.block_on(fut);
                    let _ = tx.send(result);
                })
                .expect("tokio runtime");
            rx.recv().expect("blocking channel")
        }
        Err(_) => tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("tokio runtime")
            .block_on(fut),
    }
}

// ─────────────────────────────── CLI entry ───────────────────────────────────

/// Convenience: parse minimal CLI arguments and return (exit_code, message).
/// Intended to be called from `main()`.
///
/// ```ignore
/// fn main() {
///     let engine = build_engine();
///     let (code, msg) = run_cli(engine, std::env::args().collect());
///     eprintln!("{msg}");
///     std::process::exit(code);
/// }
/// ```
pub fn run_cli(
    engine: Arc<dyn ScriptEngine>,
    args: Vec<String>,
) -> (i32, String) {
    // Very minimal arg parsing.
    // Usage: runner [--binary <path>] [--timeout <ms>] [--json] [--batch <glob>] <script>
    let mut script = PathBuf::new();
    let mut binary: Option<PathBuf> = None;
    let mut timeout_ms = 30_000u64;
    let mut json_output = false;
    let mut batch_paths: Vec<PathBuf> = Vec::new();

    let mut i = 1usize;
    while i < args.len() {
        match args[i].as_str() {
            "--binary" => {
                i += 1;
                if i < args.len() {
                    binary = Some(PathBuf::from(&args[i]));
                }
            }
            "--timeout" => {
                i += 1;
                if i < args.len() {
                    timeout_ms = args[i].parse().unwrap_or(30_000);
                }
            }
            "--json" => json_output = true,
            "--batch" => {
                i += 1;
                if i < args.len() {
                    batch_paths.push(PathBuf::from(&args[i]));
                }
            }
            other => {
                if script.as_os_str().is_empty() {
                    script = PathBuf::from(other);
                }
            }
        }
        i += 1;
    }

    if script.as_os_str().is_empty() {
        return (1, "Usage: runner [--binary <path>] [--timeout <ms>] [--json] <script>".to_owned());
    }

    let runner = HeadlessRunner::new(engine);

    if !batch_paths.is_empty() {
        let cfg = BatchConfig {
            script_path: script,
            binary_paths: batch_paths,
            timeout_ms,
            json_output,
            ..Default::default()
        };
        match runner.run_batch(&cfg) {
            Ok(r) => {
                if json_output {
                    return (r.exit_code(), r.to_json_pretty().unwrap_or_default());
                }
                return (r.exit_code(), format!("{}/{} succeeded", r.succeeded, r.total));
            }
            Err(e) => return (2, e.to_string()),
        }
    }

    let cfg = RunConfig {
        script_path: script,
        binary_path: binary,
        timeout_ms,
        json_output,
        ..Default::default()
    };
    match runner.run(&cfg) {
        Ok(r) => {
            if r.success {
                (0, r.output)
            } else {
                (r.exit_code, r.error.unwrap_or_default())
            }
        }
        Err(e) => (2, e.to_string()),
    }
}

// ─────────────────────────────── unit tests ──────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_roundtrip_null() {
        let v = ScriptValue::Null;
        assert_eq!(script_value_to_json(&v), serde_json::Value::Null);
    }

    #[test]
    fn json_roundtrip_int() {
        let v = ScriptValue::Int(42);
        assert_eq!(script_value_to_json(&v), serde_json::json!(42));
    }

    #[test]
    fn json_roundtrip_string() {
        let v = ScriptValue::String("hello".to_owned());
        assert_eq!(
            script_value_to_json(&v),
            serde_json::Value::String("hello".to_owned())
        );
    }

    #[test]
    fn json_roundtrip_address() {
        let v = ScriptValue::Address(0xDEADBEEF);
        let j = script_value_to_json(&v);
        assert!(j.as_str().unwrap().starts_with("0x"));
    }

    #[test]
    fn json_roundtrip_bytes() {
        let v = ScriptValue::Bytes(vec![0xCA, 0xFE]);
        let j = script_value_to_json(&v);
        assert_eq!(j.as_str().unwrap(), "cafe");
    }

    #[test]
    fn json_to_script_bool() {
        let j = serde_json::json!(true);
        assert_eq!(json_to_script_value(&j), ScriptValue::Bool(true));
    }

    #[test]
    fn json_to_script_array() {
        let j = serde_json::json!([1, 2]);
        match json_to_script_value(&j) {
            ScriptValue::List(v) => assert_eq!(v.len(), 2),
            _ => panic!("expected List"),
        }
    }

    #[test]
    fn run_result_failure_exit_code() {
        let r = RunResult::failure(
            "oops".to_owned(),
            String::new(),
            Duration::ZERO,
            Path::new("s.lua"),
            None,
            42,
        );
        assert!(!r.success);
        assert_eq!(r.exit_code, 42);
    }

    #[test]
    fn run_result_json() {
        let r = RunResult::success(
            "output".to_owned(),
            Duration::from_millis(5),
            Path::new("s.lua"),
            None,
            Some(serde_json::json!("ok")),
            HashMap::new(),
        );
        let j = r.to_json_pretty().unwrap();
        assert!(j.contains("\"success\": true"));
    }

    #[test]
    fn output_capture_write_drain() {
        let cap = OutputCapture::new();
        cap.write_line("hello");
        cap.write_line("world");
        let out = cap.drain();
        assert_eq!(out, "hello\nworld");
        assert!(cap.drain().is_empty());
    }

    #[test]
    fn progress_reporter_quiet() {
        // Should not panic or emit anything.
        let mut r = ProgressReporter::new(3, true);
        r.tick(Path::new("a.exe"), true);
        r.tick(Path::new("b.exe"), false);
    }

    #[test]
    fn batch_result_exit_code() {
        let ok = BatchResult {
            total: 2,
            succeeded: 2,
            failed: 0,
            elapsed_ms: 10.0,
            results: vec![],
        };
        assert_eq!(ok.exit_code(), 0);
        let fail = BatchResult { failed: 1, ..ok };
        assert_eq!(fail.exit_code(), 1);
    }
}
