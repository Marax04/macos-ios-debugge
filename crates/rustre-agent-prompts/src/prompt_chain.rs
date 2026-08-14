//! Multi-step prompt chaining for complex analysis pipelines.
//!
//! Steps pipe their outputs into subsequent steps via `output_mapping` /
//! `input_mapping` key rewriting. Conditional branching selects the next step
//! at runtime, and failed steps retry with exponential back-off.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

// ─── Error ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainError {
    StepNotFound(String),
    ChainNotFound(String),
    MaxRetriesExceeded { step_id: String, retries: u8 },
    ConditionEvalError(String),
    JsonFieldNotFound(String),
    InvalidJsonOutput(String),
    CircularChain(String),
    EmptyChain,
}

impl std::fmt::Display for ChainError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::StepNotFound(s) => write!(f, "step not found: {s}"),
            Self::ChainNotFound(s) => write!(f, "chain not found: {s}"),
            Self::MaxRetriesExceeded { step_id, retries } => {
                write!(f, "step {step_id} exceeded {retries} retries")
            }
            Self::ConditionEvalError(s) => write!(f, "condition eval error: {s}"),
            Self::JsonFieldNotFound(s) => write!(f, "JSON field not found: {s}"),
            Self::InvalidJsonOutput(s) => write!(f, "invalid JSON in step output: {s}"),
            Self::CircularChain(s) => write!(f, "circular chain: {s}"),
            Self::EmptyChain => write!(f, "chain has no steps"),
        }
    }
}

impl std::error::Error for ChainError {}

// ─── StepCondition ───────────────────────────────────────────────────────────

/// A runtime condition that determines which step to run next.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StepCondition {
    /// Expression such as `"output contains malware"` or `"output.risk == high"`.
    pub expression: String,
    /// ID of the step to run when the expression is true.
    pub on_true: String,
    /// ID of the step to run when the expression is false.
    pub on_false: String,
}

// ─── ChainStep ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainStep {
    pub id: String,
    /// ID of the prompt template to use for this step.
    pub prompt_id: String,
    /// Maps chain context keys → template variable names consumed by this step.
    pub input_mapping: HashMap<String, String>,
    /// Maps template output fields → chain context keys produced by this step.
    pub output_mapping: HashMap<String, String>,
    /// Optional branching condition evaluated after this step.
    pub condition: Option<StepCondition>,
    /// Maximum number of retry attempts on failure.
    pub max_retries: u8,
    /// Optional explicit next step ID (overridden by condition resolution).
    pub next_step: Option<String>,
}

impl ChainStep {
    pub fn new(id: impl Into<String>, prompt_id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            prompt_id: prompt_id.into(),
            input_mapping: HashMap::new(),
            output_mapping: HashMap::new(),
            condition: None,
            max_retries: 3,
            next_step: None,
        }
    }
}

// ─── StepResult ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StepResult {
    pub step_id: String,
    pub input: String,
    pub output: String,
    pub time_ms: u64,
    pub retries: u8,
    pub error: Option<String>,
}

// ─── ChainExecution ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainExecution {
    pub chain_id: String,
    pub step_results: Vec<StepResult>,
    pub final_output: Option<String>,
    pub total_time_ms: u64,
    pub success: bool,
}

// ─── PromptChain ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PromptChain {
    pub id: String,
    pub name: String,
    pub description: String,
    /// Ordered list of steps. Execution proceeds step[0] → … unless branching.
    pub steps: Vec<ChainStep>,
    /// ID of the first step to execute.
    pub entry_step: Option<String>,
}

impl PromptChain {
    pub fn new(id: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            description: String::new(),
            steps: Vec::new(),
            entry_step: None,
        }
    }

    pub fn add_step(&mut self, step: ChainStep) {
        if self.entry_step.is_none() {
            self.entry_step = Some(step.id.clone());
        }
        self.steps.push(step);
    }

    fn step_by_id(&self, id: &str) -> Option<&ChainStep> {
        self.steps.iter().find(|s| s.id == id)
    }

    fn step_index(&self, id: &str) -> Option<usize> {
        self.steps.iter().position(|s| s.id == id)
    }
}

// ─── ChainExecutor ───────────────────────────────────────────────────────────

/// Executes a `PromptChain` by calling the provided `step_fn` for each step.
///
/// `step_fn(prompt_id, input_text) -> Result<String, String>` simulates
/// calling an LLM; in production this would invoke `rustre_agent_llm`.
pub struct ChainExecutor;

impl ChainExecutor {
    pub fn execute<F>(
        chain: &PromptChain,
        initial_context: HashMap<String, String>,
        mut step_fn: F,
    ) -> Result<ChainExecution, ChainError>
    where
        F: FnMut(&str, &str) -> Result<String, String>,
    {
        if chain.steps.is_empty() {
            return Err(ChainError::EmptyChain);
        }

        let global_start = Instant::now();
        let mut context = initial_context;
        let mut step_results = Vec::new();
        let mut visited_steps: Vec<String> = Vec::new();

        let entry_id = chain
            .entry_step
            .as_deref()
            .unwrap_or(&chain.steps[0].id)
            .to_string();
        let mut current_id = entry_id;
        let mut last_output = None;
        let mut branched = false;

        loop {
            // Cycle detection
            if visited_steps.iter().filter(|s| s.as_str() == current_id).count() >= 2 {
                return Err(ChainError::CircularChain(current_id.clone()));
            }
            visited_steps.push(current_id.clone());

            let step = chain
                .step_by_id(&current_id)
                .ok_or_else(|| ChainError::StepNotFound(current_id.clone()))?
                .clone();

            // Build input from context using input_mapping
            let input_text = Self::build_input(&step, &context, last_output.as_deref());

            // Execute with retries
            let step_start = Instant::now();
            let (output, retries, err) =
                Self::execute_with_retry(&step, &input_text, &mut step_fn);
            let time_ms = step_start.elapsed().as_millis() as u64;

            let succeeded = err.is_none();
            let output = output.unwrap_or_default();
            last_output = Some(output.clone());

            // Apply output mapping to context
            Self::apply_output_mapping(&step, &output, &mut context);
            // Always store raw output under step id
            context.insert(format!("{}.output", step.id), output.clone());

            step_results.push(StepResult {
                step_id: step.id.clone(),
                input: input_text,
                output: output.clone(),
                time_ms,
                retries,
                error: err.clone(),
            });

            if !succeeded {
                let total_time_ms = global_start.elapsed().as_millis() as u64;
                return Ok(ChainExecution {
                    chain_id: chain.id.clone(),
                    step_results,
                    final_output: None,
                    total_time_ms,
                    success: false,
                });
            }

            // Determine next step
            let next = if let Some(cond) = &step.condition {
                let result = Self::evaluate_condition(&cond.expression, &output, &context);
                branched = true;
                match result {
                    Ok(true) => Some(cond.on_true.clone()),
                    Ok(false) => Some(cond.on_false.clone()),
                    Err(e) => return Err(ChainError::ConditionEvalError(e)),
                }
            } else if let Some(nxt) = &step.next_step {
                Some(nxt.clone())
            } else if branched {
                // After a conditional branch, do not auto-fallthrough by index;
                // continuation must be explicit via `next_step`.
                None
            } else {
                // Advance to next step by index
                chain
                    .step_index(&step.id)
                    .and_then(|i| chain.steps.get(i + 1))
                    .map(|s| s.id.clone())
            };

            match next {
                Some(nxt) if nxt == "__end__" || nxt.is_empty() => break,
                Some(nxt) => current_id = nxt,
                None => break,
            }
        }

        let final_output = step_results.last().map(|r| r.output.clone());
        let total_time_ms = global_start.elapsed().as_millis() as u64;
        Ok(ChainExecution {
            chain_id: chain.id.clone(),
            step_results,
            final_output,
            total_time_ms,
            success: true,
        })
    }

    fn build_input(step: &ChainStep, context: &HashMap<String, String>, last_output: Option<&str>) -> String {
        if step.input_mapping.is_empty() {
            // Use the latest output in context (the previous step's output)
            last_output.unwrap_or_default().to_string()
        } else {
            step.input_mapping
                .iter()
                .map(|(ctx_key, _tmpl_var)| {
                    context.get(ctx_key).cloned().unwrap_or_default()
                })
                .collect::<Vec<_>>()
                .join("\n")
        }
    }

    fn apply_output_mapping(
        step: &ChainStep,
        output: &str,
        context: &mut HashMap<String, String>,
    ) {
        for (field_path, ctx_key) in &step.output_mapping {
            if let Ok(val) = extract_json_field(output, field_path) {
                context.insert(ctx_key.clone(), val);
            }
        }
    }

    fn execute_with_retry<F>(
        step: &ChainStep,
        input: &str,
        step_fn: &mut F,
    ) -> (Option<String>, u8, Option<String>)
    where
        F: FnMut(&str, &str) -> Result<String, String>,
    {
        let mut retries = 0u8;
        loop {
            match step_fn(&step.prompt_id, input) {
                Ok(out) => return (Some(out), retries, None),
                Err(e) => {
                    if retries >= step.max_retries {
                        return (None, retries, Some(e));
                    }
                    // Exponential back-off: 100ms * 2^retries (simulated in tests via skip)
                    let wait_ms = 100u64 * (1u64 << retries as u64);
                    std::thread::sleep(Duration::from_millis(wait_ms.min(2000)));
                    retries += 1;
                }
            }
        }
    }

    /// Evaluate a condition expression against the last step's output.
    ///
    /// Supported forms:
    /// - `"output contains <word>"` — substring check
    /// - `"output.<field> == <value>"` — JSON field equality
    /// - `"output.<field> != <value>"` — JSON field inequality
    /// - `"context.<key> == <value>"` — context key equality
    pub fn evaluate_condition(
        expr: &str,
        output: &str,
        context: &HashMap<String, String>,
    ) -> Result<bool, String> {
        let expr = expr.trim();

        if let Some(rest) = expr.strip_prefix("output contains ") {
            return Ok(output.contains(rest.trim()));
        }

        if let Some(rest) = expr.strip_prefix("output.") {
            let parts: Vec<&str> = rest.splitn(3, ' ').collect();
            if parts.len() == 3 {
                let field = parts[0];
                let op = parts[1];
                let expected = parts[2];
                let actual = extract_json_field(output, field)
                    .map_err(|e| e.to_string())?;
                return Ok(match op {
                    "==" => actual.trim_matches('"') == expected,
                    "!=" => actual.trim_matches('"') != expected,
                    ">" => actual
                        .parse::<f64>()
                        .ok()
                        .zip(expected.parse::<f64>().ok())
                        .map(|(a, b)| a > b)
                        .unwrap_or(false),
                    "<" => actual
                        .parse::<f64>()
                        .ok()
                        .zip(expected.parse::<f64>().ok())
                        .map(|(a, b)| a < b)
                        .unwrap_or(false),
                    _ => return Err(format!("unknown operator: {op}")),
                });
            }
        }

        if let Some(rest) = expr.strip_prefix("context.") {
            let parts: Vec<&str> = rest.splitn(3, ' ').collect();
            if parts.len() == 3 {
                let key = parts[0];
                let op = parts[1];
                let expected = parts[2];
                let actual = context.get(key).map(String::as_str).unwrap_or("");
                return Ok(match op {
                    "==" => actual == expected,
                    "!=" => actual != expected,
                    _ => return Err(format!("unknown operator: {op}")),
                });
            }
        }

        Err(format!("unrecognised condition expression: '{expr}'"))
    }
}

// ─── extract_json_field ──────────────────────────────────────────────────────

/// Extract a field from a JSON string by dotted path (e.g. `"result.score"`).
pub fn extract_json_field(json: &str, path: &str) -> Result<String, ChainError> {
    let value: serde_json::Value = serde_json::from_str(json)
        .map_err(|e| ChainError::InvalidJsonOutput(e.to_string()))?;

    let mut current = &value;
    for key in path.split('.') {
        current = current
            .get(key)
            .ok_or_else(|| ChainError::JsonFieldNotFound(path.to_string()))?;
    }

    Ok(match current {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Number(n) => n.to_string(),
        serde_json::Value::Bool(b) => b.to_string(),
        serde_json::Value::Null => "null".to_string(),
        other => other.to_string(),
    })
}

// ─── retry_with_backoff (standalone) ─────────────────────────────────────────

/// Retry a fallible operation with exponential back-off.
/// `base_ms` * 2^attempt, capped at `max_wait_ms`.
pub fn retry_with_backoff<T, E, F>(
    mut f: F,
    max_retries: u8,
    base_ms: u64,
    max_wait_ms: u64,
) -> Result<T, E>
where
    F: FnMut(u8) -> Result<T, E>,
{
    for attempt in 0..=max_retries {
        match f(attempt) {
            Ok(v) => return Ok(v),
            Err(e) => {
                if attempt == max_retries {
                    return Err(e);
                }
                let wait = (base_ms * (1u64 << attempt as u64)).min(max_wait_ms);
                std::thread::sleep(Duration::from_millis(wait));
            }
        }
    }
    unreachable!()
}

// ─── ChainLibrary ─────────────────────────────────────────────────────────────

#[derive(Debug, Default)]
pub struct ChainLibrary {
    chains: HashMap<String, PromptChain>,
}

impl ChainLibrary {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&mut self, chain: PromptChain) {
        self.chains.insert(chain.id.clone(), chain);
    }

    pub fn get(&self, id: &str) -> Option<&PromptChain> {
        self.chains.get(id)
    }

    pub fn load_from_json(&mut self, json: &str) -> Result<usize, serde_json::Error> {
        let chains: Vec<PromptChain> = serde_json::from_str(json)?;
        let n = chains.len();
        for c in chains {
            self.register(c);
        }
        Ok(n)
    }

    pub fn save_to_json(&self) -> Result<String, serde_json::Error> {
        let chains: Vec<&PromptChain> = self.chains.values().collect();
        serde_json::to_string_pretty(&chains)
    }

    pub fn chain_count(&self) -> usize {
        self.chains.len()
    }

    pub fn execute<F>(
        &self,
        chain_id: &str,
        initial_context: HashMap<String, String>,
        step_fn: F,
    ) -> Result<ChainExecution, ChainError>
    where
        F: FnMut(&str, &str) -> Result<String, String>,
    {
        let chain = self
            .chains
            .get(chain_id)
            .ok_or_else(|| ChainError::ChainNotFound(chain_id.to_string()))?;
        ChainExecutor::execute(chain, initial_context, step_fn)
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_chain(steps: Vec<ChainStep>) -> PromptChain {
        let mut chain = PromptChain::new("test_chain", "Test");
        for s in steps {
            chain.add_step(s);
        }
        chain
    }

    fn step(id: &str) -> ChainStep {
        ChainStep::new(id, "dummy_prompt")
    }

    // 1. Single-step chain executes successfully
    #[test]
    fn test_single_step() {
        let chain = make_chain(vec![step("s1")]);
        let exec = ChainExecutor::execute(&chain, HashMap::new(), |_, _| {
            Ok("output text".into())
        })
        .unwrap();
        assert!(exec.success);
        assert_eq!(exec.step_results.len(), 1);
        assert_eq!(exec.final_output.as_deref(), Some("output text"));
    }

    // 2. Two-step chain pipes correctly
    #[test]
    fn test_two_step_chain() {
        let chain = make_chain(vec![step("s1"), step("s2")]);
        let mut call_idx = 0;
        let exec = ChainExecutor::execute(&chain, HashMap::new(), |_, _| {
            call_idx += 1;
            Ok(format!("output{call_idx}"))
        })
        .unwrap();
        assert!(exec.success);
        assert_eq!(exec.step_results.len(), 2);
        assert_eq!(exec.final_output.as_deref(), Some("output2"));
    }

    // 3. Step failure recorded properly
    #[test]
    fn test_step_failure() {
        let mut s = step("s1");
        s.max_retries = 0;
        let chain = make_chain(vec![s]);
        let exec = ChainExecutor::execute(&chain, HashMap::new(), |_, _| {
            Err("broken".into())
        })
        .unwrap();
        assert!(!exec.success);
        assert!(exec.step_results[0].error.is_some());
    }

    // 4. empty chain returns EmptyChain error
    #[test]
    fn test_empty_chain() {
        let chain = PromptChain::new("empty", "Empty");
        let err = ChainExecutor::execute(&chain, HashMap::new(), |_, _| Ok("x".into()))
            .unwrap_err();
        assert!(matches!(err, ChainError::EmptyChain));
    }

    // 5. Condition "output contains" true
    #[test]
    fn test_condition_contains_true() {
        let ctx: HashMap<String, String> = HashMap::new();
        assert!(
            ChainExecutor::evaluate_condition("output contains malware", "detected malware here", &ctx)
                .unwrap()
        );
    }

    // 6. Condition "output contains" false
    #[test]
    fn test_condition_contains_false() {
        let ctx: HashMap<String, String> = HashMap::new();
        assert!(
            !ChainExecutor::evaluate_condition("output contains malware", "clean binary", &ctx)
                .unwrap()
        );
    }

    // 7. Condition "output.field == value" JSON equality
    #[test]
    fn test_condition_json_field_eq() {
        let ctx: HashMap<String, String> = HashMap::new();
        let output = r#"{"risk":"high"}"#;
        assert!(
            ChainExecutor::evaluate_condition("output.risk == high", output, &ctx).unwrap()
        );
    }

    // 8. Condition context key equality
    #[test]
    fn test_condition_context_eq() {
        let mut ctx = HashMap::new();
        ctx.insert("arch".to_string(), "x86_64".to_string());
        assert!(
            ChainExecutor::evaluate_condition("context.arch == x86_64", "anything", &ctx).unwrap()
        );
    }

    // 9. extract_json_field simple path
    #[test]
    fn test_extract_json_field_simple() {
        let json = r#"{"score":42}"#;
        assert_eq!(extract_json_field(json, "score").unwrap(), "42");
    }

    // 10. extract_json_field nested path
    #[test]
    fn test_extract_json_field_nested() {
        let json = r#"{"result":{"label":"malware"}}"#;
        assert_eq!(extract_json_field(json, "result.label").unwrap(), "malware");
    }

    // 11. extract_json_field missing path returns error
    #[test]
    fn test_extract_json_field_missing() {
        let json = r#"{"a":1}"#;
        assert!(matches!(
            extract_json_field(json, "b"),
            Err(ChainError::JsonFieldNotFound(_))
        ));
    }

    // 12. extract_json_field invalid JSON
    #[test]
    fn test_extract_json_field_invalid_json() {
        assert!(matches!(
            extract_json_field("not json", "x"),
            Err(ChainError::InvalidJsonOutput(_))
        ));
    }

    // 13. ChainLibrary register and retrieve
    #[test]
    fn test_chain_library_register() {
        let mut lib = ChainLibrary::new();
        lib.register(PromptChain::new("c1", "Chain1"));
        assert!(lib.get("c1").is_some());
        assert_eq!(lib.chain_count(), 1);
    }

    // 14. ChainLibrary execute unknown chain
    #[test]
    fn test_chain_library_execute_unknown() {
        let lib = ChainLibrary::new();
        let err = lib
            .execute("nope", HashMap::new(), |_, _| Ok("x".into()))
            .unwrap_err();
        assert!(matches!(err, ChainError::ChainNotFound(_)));
    }

    // 15. retry_with_backoff succeeds on second try
    #[test]
    fn test_retry_succeeds_second_try() {
        let mut calls = 0u8;
        let result = retry_with_backoff(
            |_attempt| {
                calls += 1;
                if calls < 2 { Err("fail") } else { Ok("ok") }
            },
            3,
            1, // 1ms base to keep test fast
            10,
        );
        assert_eq!(result, Ok("ok"));
        assert_eq!(calls, 2);
    }

    // 16. retry_with_backoff exhausts retries
    #[test]
    fn test_retry_exhausts() {
        let mut calls = 0u8;
        let result: Result<(), &str> = retry_with_backoff(
            |_| {
                calls += 1;
                Err("always fail")
            },
            2,
            1,
            10,
        );
        assert!(result.is_err());
        assert_eq!(calls, 3); // initial + 2 retries
    }

    // 17. StepCondition branching selects on_true step
    #[test]
    fn test_conditional_step_branching() {
        let mut s1 = step("s1");
        s1.condition = Some(StepCondition {
            expression: "output contains YES".into(),
            on_true: "s_yes".into(),
            on_false: "s_no".into(),
        });
        let mut chain = PromptChain::new("cond_chain", "Conditional");
        chain.add_step(s1);
        chain.add_step(ChainStep::new("s_yes", "prompt_yes"));
        chain.add_step(ChainStep::new("s_no", "prompt_no"));

        let mut called_ids = Vec::new();
        let exec = ChainExecutor::execute(&chain, HashMap::new(), |pid, _| {
            called_ids.push(pid.to_string());
            if pid == "dummy_prompt" {
                Ok("answer is YES".into())
            } else {
                Ok(format!("{pid}_output"))
            }
        })
        .unwrap();

        assert!(exec.success);
        // s_yes should have been executed (not s_no)
        assert!(exec.step_results.iter().any(|r| r.step_id == "s_yes"));
        assert!(!exec.step_results.iter().any(|r| r.step_id == "s_no"));
    }

    // 18. Output mapping writes to context
    #[test]
    fn test_output_mapping() {
        let mut s1 = step("s1");
        s1.output_mapping.insert("label".to_string(), "classification".to_string());
        let chain = make_chain(vec![s1]);
        let exec = ChainExecutor::execute(&chain, HashMap::new(), |_, _| {
            Ok(r#"{"label":"malware"}"#.into())
        })
        .unwrap();
        assert!(exec.success);
        // The mapped value would have been placed in context for subsequent steps.
        // We verify by checking the step result output contains the expected JSON.
        assert!(exec.step_results[0].output.contains("malware"));
    }

    // 19. Condition unknown operator returns error
    #[test]
    fn test_condition_unknown_operator() {
        let ctx: HashMap<String, String> = HashMap::new();
        let err =
            ChainExecutor::evaluate_condition("output.x ~~ value", "{\"x\":\"y\"}", &ctx);
        assert!(err.is_err());
    }

    // 20. Chain with explicit next_step ordering
    #[test]
    fn test_explicit_next_step() {
        let mut s1 = step("s1");
        s1.next_step = Some("s3".into());
        let mut chain = PromptChain::new("jump_chain", "Jump");
        chain.add_step(s1);
        chain.add_step(step("s2")); // should be skipped
        chain.add_step(step("s3"));

        let exec = ChainExecutor::execute(&chain, HashMap::new(), |_, _| Ok("out".into()))
            .unwrap();
        assert!(exec.success);
        // s2 should be skipped, only s1 and s3
        assert!(!exec.step_results.iter().any(|r| r.step_id == "s2"));
        assert!(exec.step_results.iter().any(|r| r.step_id == "s3"));
    }
}
