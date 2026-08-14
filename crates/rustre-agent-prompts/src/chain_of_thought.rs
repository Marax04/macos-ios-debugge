//! Chain-of-thought reasoning templates for RE agent prompts.
//!
//! Provides [`CotTemplate`], [`ReasoningChain`], [`ReasoningStep`], and the
//! [`CotBuilder`] fluent API for constructing task-specific reasoning chains.

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::PromptError;

/// Cast `usize` to `f64` for averaging. Precision loss is acceptable in
/// statistical contexts; this helper isolates the cast for lint scope.
fn usize_as_f64(n: usize) -> f64 {
    n as f64
}

// ─── StepKind ────────────────────────────────────────────────────────────────

/// The logical role of a reasoning step.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum StepKind {
    /// Factual observation drawn from the binary artefact.
    Observation,
    /// A hypothesis derived from one or more observations.
    Hypothesis,
    /// Supporting evidence that strengthens or weakens a hypothesis.
    Evidence,
    /// A well-supported conclusion derived from the preceding steps.
    Conclusion,
    /// An intermediate deduction bridging observations and conclusions.
    Deduction,
    /// An action the analyst should take (e.g. "look up the constant in a DB").
    Action,
    /// A question to resolve before continuing.
    Question,
    /// A note or caveat.
    Note,
}

impl fmt::Display for StepKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Observation => "Observation",
            Self::Hypothesis => "Hypothesis",
            Self::Evidence => "Evidence",
            Self::Conclusion => "Conclusion",
            Self::Deduction => "Deduction",
            Self::Action => "Action",
            Self::Question => "Question",
            Self::Note => "Note",
        };
        write!(f, "{s}")
    }
}

// ─── ReasoningStep ───────────────────────────────────────────────────────────

/// A single step in a chain-of-thought reasoning sequence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReasoningStep {
    /// Logical role of this step.
    pub kind: StepKind,
    /// The content of this step.
    pub content: String,
    /// Optional confidence score 0.0–1.0.
    pub confidence: Option<f64>,
    /// Optional references to previous step indices.
    pub depends_on: Vec<usize>,
    /// Free-form tags for categorisation.
    pub tags: Vec<String>,
}

impl ReasoningStep {
    /// Create a simple step with no optional fields.
    #[must_use]
    pub fn simple(kind: StepKind, content: impl Into<String>) -> Self {
        Self {
            kind,
            content: content.into(),
            confidence: None,
            depends_on: Vec::new(),
            tags: Vec::new(),
        }
    }

    /// Create a step with a confidence score.
    #[must_use]
    pub fn with_confidence(kind: StepKind, content: impl Into<String>, confidence: f64) -> Self {
        Self {
            kind,
            content: content.into(),
            confidence: Some(confidence.clamp(0.0, 1.0)),
            depends_on: Vec::new(),
            tags: Vec::new(),
        }
    }

    /// Format this step as a markdown list item.
    #[must_use]
    pub fn to_markdown(&self, index: usize) -> String {
        let conf_str = self
            .confidence
            .map_or_else(String::new, |c| format!(" _(confidence: {:.0}%)_", c * 100.0));
        let dep_str = if self.depends_on.is_empty() {
            String::new()
        } else {
            let deps: Vec<String> = self
                .depends_on
                .iter()
                .map(|i| format!("#{}", i + 1))
                .collect();
            format!(" [→ {}]", deps.join(", "))
        };
        format!(
            "{}. **{}**{}{}: {}",
            index + 1,
            self.kind,
            conf_str,
            dep_str,
            self.content
        )
    }
}

// ─── ReasoningChain ──────────────────────────────────────────────────────────

/// An ordered sequence of reasoning steps.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReasoningChain {
    /// Human-readable title for this chain.
    pub title: String,
    /// Optional task description.
    pub task_description: String,
    /// The ordered steps.
    pub steps: Vec<ReasoningStep>,
    /// Metadata tags.
    pub tags: Vec<String>,
}

impl ReasoningChain {
    /// Create an empty chain.
    #[must_use]
    pub fn new(title: impl Into<String>) -> Self {
        Self {
            title: title.into(),
            task_description: String::new(),
            steps: Vec::new(),
            tags: Vec::new(),
        }
    }

    /// Add a step to the chain, returning its index.
    pub fn push(&mut self, step: ReasoningStep) -> usize {
        let idx = self.steps.len();
        self.steps.push(step);
        idx
    }

    /// Return all conclusions from this chain.
    #[must_use]
    pub fn conclusions(&self) -> Vec<&ReasoningStep> {
        self.steps
            .iter()
            .filter(|s| s.kind == StepKind::Conclusion)
            .collect()
    }

    /// Return all observations.
    #[must_use]
    pub fn observations(&self) -> Vec<&ReasoningStep> {
        self.steps
            .iter()
            .filter(|s| s.kind == StepKind::Observation)
            .collect()
    }

    /// Return steps with confidence at or above the threshold.
    #[must_use]
    pub fn high_confidence_steps(&self, threshold: f64) -> Vec<&ReasoningStep> {
        self.steps
            .iter()
            .filter(|s| s.confidence.is_some_and(|c| c >= threshold))
            .collect()
    }

    /// Format the entire chain as markdown.
    #[must_use]
    pub fn to_markdown(&self) -> String {
        let mut out = format!("# {}\n\n", self.title);
        if !self.task_description.is_empty() {
            out.push_str(&self.task_description);
            out.push_str("\n\n");
        }
        out.push_str("## Reasoning Steps\n\n");
        for (i, step) in self.steps.iter().enumerate() {
            out.push_str(&step.to_markdown(i));
            out.push('\n');
        }
        out
    }

    /// Return the number of steps.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.steps.len()
    }

    /// Return true if the chain has no steps.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.steps.is_empty()
    }

    /// Return average confidence across steps that have one set.
    #[must_use]
    pub fn average_confidence(&self) -> Option<f64> {
        let (sum, count) = self
            .steps
            .iter()
            .filter_map(|s| s.confidence)
            .fold((0.0f64, 0usize), |(acc, n), c| (acc + c, n + 1));
        if count == 0 {
            None
        } else {
            Some(sum / usize_as_f64(count))
        }
    }
}

// ─── CotTemplate ─────────────────────────────────────────────────────────────

/// A chain-of-thought template for a specific RE analysis task.
///
/// Templates contain step outlines with `{{variable}}` placeholders.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CotTemplate {
    /// Template identifier.
    pub id: String,
    /// Human-readable name.
    pub name: String,
    /// Ordered step outlines (kind + content template).
    pub step_templates: Vec<(StepKind, String)>,
    /// Required variables in the step templates.
    pub required_vars: Vec<String>,
}

impl CotTemplate {
    /// Create a new template.
    #[must_use]
    pub fn new(id: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            step_templates: Vec::new(),
            required_vars: Vec::new(),
        }
    }

    /// Add a step outline to the template.
    #[must_use]
    pub fn with_step(mut self, kind: StepKind, content_template: impl Into<String>) -> Self {
        self.step_templates.push((kind, content_template.into()));
        self
    }

    /// Render the template into a [`ReasoningChain`] by substituting variables.
    ///
    /// # Errors
    /// Returns [`PromptError::MissingVariable`] when a template placeholder
    /// remains unresolved after substitution.
    ///
    /// # Panics
    /// Panics only if internal invariants are violated (the `{{` index returned
    /// by `find` must be valid).
    pub fn render(&self, vars: &HashMap<String, String>) -> Result<ReasoningChain, PromptError> {
        let mut chain = ReasoningChain::new(&self.name);

        for (kind, tmpl) in &self.step_templates {
            let mut content = tmpl.clone();
            for (k, v) in vars {
                content = content.replace(&format!("{{{{{k}}}}}"), v);
            }
            // Check for unresolved variables
            if content.contains("{{") {
                let start = content.find("{{").unwrap();
                // Find `}}` that appears *after* `{{` to avoid a panic when `}}`
                // precedes `{{` in a malformed template string.
                let var_name = content[start + 2..].find("}}").map_or_else(
                    || content[start + 2..].to_owned(),
                    |end_rel| content[start + 2..start + 2 + end_rel].to_owned(),
                );
                return Err(PromptError::MissingVariable(var_name));
            }
            chain.push(ReasoningStep::simple(kind.clone(), content));
        }

        Ok(chain)
    }
}

// ─── CotBuilder ──────────────────────────────────────────────────────────────

/// Fluent builder for constructing [`ReasoningChain`] instances.
pub struct CotBuilder {
    chain: ReasoningChain,
}

impl CotBuilder {
    /// Start a new builder with the given title.
    #[must_use]
    pub fn new(title: impl Into<String>) -> Self {
        Self {
            chain: ReasoningChain::new(title),
        }
    }

    /// Set the task description.
    #[must_use]
    pub fn task(mut self, description: impl Into<String>) -> Self {
        self.chain.task_description = description.into();
        self
    }

    /// Add a step.
    #[must_use]
    pub fn observe(mut self, content: impl Into<String>) -> Self {
        self.chain
            .push(ReasoningStep::simple(StepKind::Observation, content));
        self
    }

    /// Add a hypothesis step.
    #[must_use]
    pub fn hypothesize(mut self, content: impl Into<String>) -> Self {
        self.chain
            .push(ReasoningStep::simple(StepKind::Hypothesis, content));
        self
    }

    /// Add an evidence step.
    #[must_use]
    pub fn evidence(mut self, content: impl Into<String>) -> Self {
        self.chain
            .push(ReasoningStep::simple(StepKind::Evidence, content));
        self
    }

    /// Add a conclusion step with confidence.
    #[must_use]
    pub fn conclude(mut self, content: impl Into<String>, confidence: f64) -> Self {
        self.chain.push(ReasoningStep::with_confidence(
            StepKind::Conclusion,
            content,
            confidence,
        ));
        self
    }

    /// Add a deduction step.
    #[must_use]
    pub fn deduce(mut self, content: impl Into<String>) -> Self {
        self.chain
            .push(ReasoningStep::simple(StepKind::Deduction, content));
        self
    }

    /// Add an action step.
    #[must_use]
    pub fn action(mut self, content: impl Into<String>) -> Self {
        self.chain
            .push(ReasoningStep::simple(StepKind::Action, content));
        self
    }

    /// Add a question step.
    #[must_use]
    pub fn ask(mut self, content: impl Into<String>) -> Self {
        self.chain
            .push(ReasoningStep::simple(StepKind::Question, content));
        self
    }

    /// Add a note.
    #[must_use]
    pub fn note(mut self, content: impl Into<String>) -> Self {
        self.chain
            .push(ReasoningStep::simple(StepKind::Note, content));
        self
    }

    /// Build the final chain.
    #[must_use]
    pub fn build(self) -> ReasoningChain {
        self.chain
    }
}

// ─── Task-specific chain constructors ────────────────────────────────────────

/// Returns a pre-built `CoT` chain for malware analysis.
#[must_use]
pub fn malware_analysis_chain() -> ReasoningChain {
    CotBuilder::new("Malware Analysis Chain")
        .task("Step-by-step chain of thought for analysing a potentially malicious binary.")
        .observe("Examine the file headers to determine architecture, OS target, and packer/protector signatures.")
        .observe("List all imported DLLs and API functions; note any suspicious or unusual imports.")
        .observe("Extract readable strings; look for IP addresses, URLs, registry keys, mutex names, and file paths.")
        .hypothesize("Based on imports and strings, form an initial hypothesis about the malware family and purpose.")
        .action("Compute hashes (MD5/SHA256/imphash) and query threat intelligence databases.")
        .evidence("Check for known signatures: PE section names, string patterns, or code sequences.")
        .deduce("Correlate import patterns with capability clusters (network, persistence, injection, crypto).")
        .observe("Locate the entry point and trace the main execution path in the decompiler.")
        .observe("Identify initialisation routines: C2 configuration decryption, anti-analysis checks.")
        .deduce("Map discovered capabilities to MITRE ATT&CK technique IDs.")
        .evidence("Cross-reference with public threat reports for corroborating evidence.")
        .conclude("Classify the malware family, version, and campaign with confidence rating.", 0.80)
        .note("Document all IOCs for defensive use: hashes, IPs, domains, mutex names, registry keys.")
        .build()
}

/// Returns a pre-built `CoT` chain for vulnerability discovery.
#[must_use]
pub fn vulnerability_discovery_chain() -> ReasoningChain {
    CotBuilder::new("Vulnerability Discovery Chain")
        .task("Systematic chain of thought for finding exploitable vulnerabilities in a function.")
        .observe("Identify all input parameters and trace which are attacker-controlled.")
        .observe("Map data flow from sources (function arguments, file reads, network input) to sinks (memory writes, function calls).")
        .hypothesize("Any input reaching a memory operation without bounds checking is a candidate vulnerability.")
        .action("For each memory operation, verify that a length or bounds check is present and correct.")
        .observe("Check integer operations for overflow/underflow before use as size arguments.")
        .observe("Check pointer dereferences for NULL or use-after-free conditions.")
        .deduce("Determine reachability: can the vulnerable path be triggered from an external interface?")
        .evidence("Identify any mitigations (ASLR, stack canaries, CFI) that would complicate exploitation.")
        .observe("Check for format string vulnerabilities in printf-family calls with user-controlled format arguments.")
        .deduce("Estimate exploitability: local vs. remote, privilege level, reliability, prerequisites.")
        .conclude("Rank vulnerabilities by severity and write a proof-of-concept trigger description.", 0.75)
        .note("Document for patch: root cause, fix, and regression test case.")
        .build()
}

/// Returns a pre-built `CoT` chain for protocol reverse engineering.
#[must_use]
pub fn protocol_re_chain() -> ReasoningChain {
    CotBuilder::new("Protocol Reverse Engineering Chain")
        .task("Systematic analysis of an unknown binary protocol.")
        .observe("Examine known-good packet captures: identify fixed magic bytes and version fields.")
        .observe("Measure packet length distributions; look for fixed-length headers and variable payloads.")
        .hypothesize("Form an initial hypothesis about the framing model (length-prefixed, delimiter-based, fixed-size).")
        .action("Group packets by apparent message type field; look for an enum or command byte.")
        .deduce("For each message type, map fields using offset statistics across multiple samples.")
        .observe("Look for TLV (type-length-value) structures within the payload region.")
        .evidence("Locate the parsing code in the binary; the parser is the ground truth for field semantics.")
        .observe("Identify checksum or MAC fields by looking for fields that change with payload content but not command type.")
        .deduce("Determine the byte order (big/little endian) from multi-byte integer fields.")
        .action("Write a Wireshark Lua dissector skeleton based on current understanding and validate against captures.")
        .observe("Look for compression or encryption; entropy analysis helps distinguish them.")
        .conclude("Produce a complete protocol specification with field table and state machine diagram.", 0.70)
        .note("Maintain a version history: protocol versions are often distinguishable by magic or version byte.")
        .build()
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cot_builder_basic() {
        let chain = CotBuilder::new("Test Chain")
            .observe("Observation 1")
            .hypothesize("Hypothesis 1")
            .conclude("Conclusion 1", 0.9)
            .build();
        assert_eq!(chain.len(), 3);
        assert_eq!(chain.title, "Test Chain");
    }

    #[test]
    fn test_cot_builder_conclusions() {
        let chain = CotBuilder::new("Test")
            .observe("Obs")
            .conclude("Conc 1", 0.8)
            .conclude("Conc 2", 0.6)
            .build();
        assert_eq!(chain.conclusions().len(), 2);
    }

    #[test]
    fn test_cot_builder_observations() {
        let chain = CotBuilder::new("Test")
            .observe("Obs 1")
            .observe("Obs 2")
            .conclude("Done", 1.0)
            .build();
        assert_eq!(chain.observations().len(), 2);
    }

    #[test]
    fn test_reasoning_step_confidence_clamp() {
        let step = ReasoningStep::with_confidence(StepKind::Conclusion, "test", 1.5);
        assert_eq!(step.confidence, Some(1.0));
        let step2 = ReasoningStep::with_confidence(StepKind::Conclusion, "test", -0.5);
        assert_eq!(step2.confidence, Some(0.0));
    }

    #[test]
    fn test_reasoning_chain_average_confidence() {
        let chain = CotBuilder::new("Test")
            .conclude("A", 0.8)
            .conclude("B", 0.6)
            .build();
        let avg = chain.average_confidence().unwrap();
        assert!((avg - 0.7).abs() < 1e-10);
    }

    #[test]
    fn test_reasoning_chain_no_confidence_none() {
        let chain = CotBuilder::new("Test").observe("No conf").build();
        assert!(chain.average_confidence().is_none());
    }

    #[test]
    fn test_reasoning_chain_high_confidence_steps() {
        let chain = CotBuilder::new("Test")
            .conclude("High", 0.9)
            .conclude("Low", 0.3)
            .build();
        let high = chain.high_confidence_steps(0.8);
        assert_eq!(high.len(), 1);
        assert_eq!(high[0].content, "High");
    }

    #[test]
    fn test_chain_to_markdown() {
        let chain = CotBuilder::new("My Analysis")
            .observe("Binary is PE32+")
            .conclude("Likely 64-bit malware", 0.9)
            .build();
        let md = chain.to_markdown();
        assert!(md.contains("My Analysis"));
        assert!(md.contains("PE32+"));
    }

    #[test]
    fn test_step_to_markdown() {
        let step = ReasoningStep::with_confidence(StepKind::Observation, "File is packed", 0.95);
        let md = step.to_markdown(0);
        assert!(md.contains("Observation"));
        assert!(md.contains("File is packed"));
        assert!(md.contains("95%"));
    }

    #[test]
    fn test_cot_template_render() {
        let tmpl = CotTemplate::new("test_tmpl", "Test Template").with_step(
            StepKind::Observation,
            "The function {{func_name}} takes {{n}} args.",
        );
        let mut vars = HashMap::new();
        vars.insert("func_name".to_owned(), "foo".to_owned());
        vars.insert("n".to_owned(), "3".to_owned());
        let chain = tmpl.render(&vars).unwrap();
        assert_eq!(chain.len(), 1);
        assert_eq!(chain.steps[0].content, "The function foo takes 3 args.");
    }

    #[test]
    fn test_cot_template_missing_var() {
        let tmpl = CotTemplate::new("t", "T").with_step(StepKind::Observation, "{{missing_var}}");
        let result = tmpl.render(&HashMap::new());
        assert!(matches!(result, Err(PromptError::MissingVariable(_))));
    }

    #[test]
    fn test_malware_analysis_chain_non_empty() {
        let chain = malware_analysis_chain();
        assert!(!chain.is_empty());
        assert!(!chain.conclusions().is_empty());
    }

    #[test]
    fn test_vulnerability_discovery_chain_non_empty() {
        let chain = vulnerability_discovery_chain();
        assert!(!chain.is_empty());
        assert!(!chain.conclusions().is_empty());
    }

    #[test]
    fn test_protocol_re_chain_non_empty() {
        let chain = protocol_re_chain();
        assert!(!chain.is_empty());
        assert!(!chain.conclusions().is_empty());
    }

    #[test]
    fn test_step_kind_display() {
        assert_eq!(format!("{}", StepKind::Observation), "Observation");
        assert_eq!(format!("{}", StepKind::Conclusion), "Conclusion");
        assert_eq!(format!("{}", StepKind::Hypothesis), "Hypothesis");
    }

    #[test]
    fn test_reasoning_chain_push_returns_index() {
        let mut chain = ReasoningChain::new("Test");
        let i0 = chain.push(ReasoningStep::simple(StepKind::Observation, "a"));
        let i1 = chain.push(ReasoningStep::simple(StepKind::Observation, "b"));
        assert_eq!(i0, 0);
        assert_eq!(i1, 1);
    }

    #[test]
    fn test_cot_builder_all_step_kinds() {
        let chain = CotBuilder::new("All kinds")
            .observe("obs")
            .hypothesize("hyp")
            .evidence("ev")
            .deduce("ded")
            .action("act")
            .ask("q?")
            .note("note")
            .conclude("conc", 0.9)
            .build();
        assert_eq!(chain.len(), 8);
    }

    #[test]
    fn test_reasoning_step_depends_on() {
        let mut step = ReasoningStep::simple(StepKind::Deduction, "deduced from 0 and 1");
        step.depends_on = vec![0, 1];
        let md = step.to_markdown(2);
        assert!(md.contains("#1"));
        assert!(md.contains("#2"));
    }

    #[test]
    fn test_chain_task_description() {
        let chain = CotBuilder::new("Title").task("This is the task").build();
        assert_eq!(chain.task_description, "This is the task");
        let md = chain.to_markdown();
        assert!(md.contains("This is the task"));
    }

    #[test]
    fn test_cot_template_multiple_steps() {
        let tmpl = CotTemplate::new("multi", "Multi")
            .with_step(StepKind::Observation, "Step A: {{a}}")
            .with_step(StepKind::Conclusion, "Step B: {{b}}");
        let mut vars = HashMap::new();
        vars.insert("a".to_owned(), "alpha".to_owned());
        vars.insert("b".to_owned(), "beta".to_owned());
        let chain = tmpl.render(&vars).unwrap();
        assert_eq!(chain.len(), 2);
        assert_eq!(chain.steps[0].kind, StepKind::Observation);
        assert_eq!(chain.steps[1].kind, StepKind::Conclusion);
    }

    #[test]
    fn test_malware_analysis_chain_has_observations() {
        let chain = malware_analysis_chain();
        assert!(!chain.observations().is_empty());
    }

    #[test]
    fn test_protocol_re_chain_has_actions() {
        let chain = protocol_re_chain();
        
        assert!(chain
            .steps
            .iter().any(|s| s.kind == StepKind::Action));
    }

    #[test]
    fn test_vuln_chain_deductions_present() {
        let chain = vulnerability_discovery_chain();
        
        assert!(chain
            .steps
            .iter().any(|s| s.kind == StepKind::Deduction));
    }
}
