//! MISP automation subsystem.
//!
//! Provides `MispAutomation`, `AutoCorrelation`, `AutoTagging`, `AutoExport`,
//! `WorkflowTrigger`, and `AutomationRule` for automating MISP workflows,
//! correlations, tagging policies, and scheduled exports.

use std::collections::HashMap;
pub use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

// ── Helpers ───────────────────────────────────────────────────────────────────

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn mock_uuid() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static CTR: AtomicU64 = AtomicU64::new(1);
    let n = CTR.fetch_add(1, Ordering::Relaxed);
    format!("auto-{n:016x}")
}

// ── AutomationError ───────────────────────────────────────────────────────────

/// Errors produced by the automation subsystem.
#[derive(Debug, Clone)]
pub enum AutomationError {
    /// The referenced rule does not exist.
    RuleNotFound(String),
    /// The rule definition is invalid.
    InvalidRule(String),
    /// Execution of a workflow failed.
    WorkflowFailed(String),
    /// Export operation failed.
    ExportFailed(String),
    /// A required field is missing.
    MissingField(String),
    /// Generic error.
    Other(String),
}

impl std::fmt::Display for AutomationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RuleNotFound(id) => write!(f, "rule not found: {id}"),
            Self::InvalidRule(msg) => write!(f, "invalid rule: {msg}"),
            Self::WorkflowFailed(msg) => write!(f, "workflow failed: {msg}"),
            Self::ExportFailed(msg) => write!(f, "export failed: {msg}"),
            Self::MissingField(field) => write!(f, "missing required field: {field}"),
            Self::Other(msg) => write!(f, "{msg}"),
        }
    }
}

impl std::error::Error for AutomationError {}

// ── AutomationCondition ───────────────────────────────────────────────────────

/// A single condition in an automation rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AutomationCondition {
    /// Attribute value contains the given string.
    ValueContains(String),
    /// Attribute type matches.
    TypeEquals(String),
    /// Event threat level >= threshold.
    ThreatLevelAtLeast(u8),
    /// Tag is present on the event or attribute.
    HasTag(String),
    /// Tag is absent.
    MissingTag(String),
    /// Attribute is flagged for IDS.
    IsIdsAttribute,
    /// Attribute has at least `n` sightings.
    MinSightings(u32),
    /// Event has been published.
    EventPublished,
    /// Composite AND of all sub-conditions.
    All(Vec<Self>),
    /// Composite OR of any sub-condition.
    Any(Vec<Self>),
}

/// Evaluation context for a rule condition.
#[derive(Debug, Clone, Default)]
pub struct ConditionContext {
    pub attribute_type: Option<String>,
    pub attribute_value: Option<String>,
    pub threat_level: u8,
    pub tags: Vec<String>,
    pub is_ids: bool,
    pub sightings: u32,
    pub event_published: bool,
}

impl AutomationCondition {
    /// Evaluate the condition against the given context.
    #[must_use]
    pub fn evaluate(&self, ctx: &ConditionContext) -> bool {
        match self {
            Self::ValueContains(s) => ctx
                .attribute_value
                .as_deref()
                .is_some_and(|v| v.contains(s.as_str())),
            Self::TypeEquals(t) => ctx.attribute_type.as_deref() == Some(t.as_str()),
            Self::ThreatLevelAtLeast(min) => ctx.threat_level <= *min,
            Self::HasTag(tag) => ctx.tags.iter().any(|t| t == tag),
            Self::MissingTag(tag) => !ctx.tags.iter().any(|t| t == tag),
            Self::IsIdsAttribute => ctx.is_ids,
            Self::MinSightings(n) => ctx.sightings >= *n,
            Self::EventPublished => ctx.event_published,
            Self::All(conds) => conds.iter().all(|c| c.evaluate(ctx)),
            Self::Any(conds) => conds.iter().any(|c| c.evaluate(ctx)),
        }
    }
}

// ── AutomationAction ──────────────────────────────────────────────────────────

/// An action to execute when a rule fires.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AutomationAction {
    /// Add a tag to the matched event/attribute.
    AddTag(String),
    /// Remove a tag.
    RemoveTag(String),
    /// Publish the event.
    PublishEvent,
    /// Mark attribute as IDS.
    SetIdsFlag(bool),
    /// Trigger a named workflow.
    TriggerWorkflow(String),
    /// Send an alert notification to a URL (mock).
    SendAlert { url: String, message: String },
    /// Export matched objects in the given format.
    Export { format: String, destination: String },
    /// Set a custom attribute.
    SetAttribute { name: String, value: String },
}

impl AutomationAction {
    /// Execute the action, returning a log message.
    #[must_use]
    pub fn execute(&self, context: &str) -> String {
        match self {
            Self::AddTag(t) => format!("[{context}] added tag '{t}'"),
            Self::RemoveTag(t) => format!("[{context}] removed tag '{t}'"),
            Self::PublishEvent => format!("[{context}] event published"),
            Self::SetIdsFlag(v) => format!("[{context}] IDS flag set to {v}"),
            Self::TriggerWorkflow(w) => format!("[{context}] workflow '{w}' triggered"),
            Self::SendAlert { url, message } => {
                format!("[{context}] alert sent to {url}: {message}")
            }
            Self::Export {
                format,
                destination,
            } => {
                format!("[{context}] exported as {format} to {destination}")
            }
            Self::SetAttribute { name, value } => {
                format!("[{context}] attribute '{name}' = '{value}'")
            }
        }
    }
}

// ── AutomationRule ────────────────────────────────────────────────────────────

/// An automation rule that fires when its condition matches.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutomationRule {
    /// Unique rule identifier.
    pub id: String,
    /// Human-readable name.
    pub name: String,
    /// Description.
    pub description: String,
    /// Whether this rule is active.
    pub enabled: bool,
    /// Condition that must be met.
    pub condition: AutomationCondition,
    /// Actions to execute when the condition is met.
    pub actions: Vec<AutomationAction>,
    /// Priority; lower numbers run first.
    pub priority: u32,
    /// Number of times this rule has fired.
    pub fire_count: u32,
    /// Last fired timestamp.
    pub last_fired: Option<u64>,
    /// Tags to categorise this rule.
    pub tags: Vec<String>,
}

impl AutomationRule {
    /// Create a minimal rule.
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        condition: AutomationCondition,
        actions: Vec<AutomationAction>,
    ) -> Self {
        Self {
            id: mock_uuid(),
            name: name.into(),
            description: String::new(),
            enabled: true,
            condition,
            actions,
            priority: 100,
            fire_count: 0,
            last_fired: None,
            tags: Vec::new(),
        }
    }

    /// Evaluate and, if matched, fire the rule's actions.
    ///
    /// Returns the log messages produced by fired actions.
    pub fn evaluate_and_fire(&mut self, ctx: &ConditionContext) -> Vec<String> {
        if !self.enabled || !self.condition.evaluate(ctx) {
            return Vec::new();
        }
        self.fire_count += 1;
        self.last_fired = Some(unix_now());
        let id = self.id.clone();
        self.actions.iter().map(|a| a.execute(&id)).collect()
    }

    /// Return `true` if this rule has ever fired.
    #[must_use]
    pub const fn has_fired(&self) -> bool {
        self.fire_count > 0
    }
}

// ── AutoCorrelation ───────────────────────────────────────────────────────────

/// Configuration and state for MISP's automated correlation engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutoCorrelation {
    /// Whether correlation runs automatically on new events.
    pub enabled: bool,
    /// Minimum number of overlapping attributes to create a correlation.
    pub min_overlap: u32,
    /// Attribute types excluded from correlation.
    pub excluded_types: Vec<String>,
    /// Maximum event age (days) to include in correlation runs.
    pub max_event_age_days: u32,
    /// Whether to correlate across different organisations.
    pub cross_org: bool,
    /// Timestamp of last correlation run.
    pub last_run: Option<u64>,
    /// Number of correlations found in last run.
    pub last_run_count: u32,
}

impl Default for AutoCorrelation {
    fn default() -> Self {
        Self {
            enabled: true,
            min_overlap: 1,
            excluded_types: vec!["comment".into(), "text".into()],
            max_event_age_days: 365,
            cross_org: true,
            last_run: None,
            last_run_count: 0,
        }
    }
}

impl AutoCorrelation {
    /// Create a new config with sensible defaults.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Simulate a correlation run over a set of events.
    ///
    /// Returns the number of correlations found (mock).
    pub fn run(&mut self, event_count: u32) -> u32 {
        if !self.enabled {
            return 0;
        }
        // Heuristic: expect ~0.3 correlations per event pair.
        let pairs = (u64::from(event_count) * u64::from(event_count.saturating_sub(1)) / 2) as u32;
        let correlations = (pairs as f32 * 0.3) as u32;
        self.last_run = Some(unix_now());
        self.last_run_count = correlations;
        correlations
    }

    /// Return `true` if a given attribute type is excluded from correlation.
    #[must_use]
    pub fn is_excluded(&self, attr_type: &str) -> bool {
        self.excluded_types.iter().any(|t| t == attr_type)
    }

    /// Add an excluded type.
    pub fn exclude_type(&mut self, attr_type: impl Into<String>) {
        let t = attr_type.into();
        if !self.excluded_types.contains(&t) {
            self.excluded_types.push(t);
        }
    }
}

// ── AutoTagging ───────────────────────────────────────────────────────────────

/// Policy for automatic tag assignment based on attribute content.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutoTaggingPolicy {
    /// Pattern to match in attribute values.
    pub pattern: String,
    /// Tag to apply when the pattern matches.
    pub tag: String,
    /// Whether the pattern is a regex (mock — treated as substring for now).
    pub is_regex: bool,
    /// Whether the tag should also be applied to the parent event.
    pub tag_event: bool,
}

impl AutoTaggingPolicy {
    /// Create a substring-match policy.
    #[must_use]
    pub fn substring(pattern: impl Into<String>, tag: impl Into<String>) -> Self {
        Self {
            pattern: pattern.into(),
            tag: tag.into(),
            is_regex: false,
            tag_event: false,
        }
    }

    /// Apply to event-level as well.
    #[must_use]
    pub const fn with_event_tag(mut self) -> Self {
        self.tag_event = true;
        self
    }

    /// Return `true` if the given value matches this policy's pattern.
    #[must_use]
    pub fn matches(&self, value: &str) -> bool {
        value.contains(self.pattern.as_str())
    }
}

/// Manager for automatic tagging policies.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct AutoTagging {
    /// Active policies.
    pub policies: Vec<AutoTaggingPolicy>,
    /// Tags applied in the last run (indicator → tags).
    pub last_results: HashMap<String, Vec<String>>,
}

impl AutoTagging {
    /// Create a new manager.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a tagging policy.
    pub fn add_policy(&mut self, policy: AutoTaggingPolicy) {
        self.policies.push(policy);
    }

    /// Evaluate all policies against a list of (`attribute_value`) strings,
    /// returning the unique set of tags to apply.
    #[must_use]
    pub fn evaluate(&self, values: &[&str]) -> Vec<String> {
        let mut tags: Vec<String> = Vec::new();
        for value in values {
            for policy in &self.policies {
                if policy.matches(value) && !tags.contains(&policy.tag) {
                    tags.push(policy.tag.clone());
                }
            }
        }
        tags
    }

    /// Run policies against a set of attributes and store the result.
    pub fn run(&mut self, indicator: impl Into<String>, values: &[&str]) {
        let tags = self.evaluate(values);
        self.last_results.insert(indicator.into(), tags);
    }

    /// Number of active policies.
    #[must_use]
    pub const fn policy_count(&self) -> usize {
        self.policies.len()
    }
}

// ── AutoExport ────────────────────────────────────────────────────────────────

/// Destination for an automated export.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportDestination {
    /// Unique destination name.
    pub name: String,
    /// Export format: "json", "csv", "stix", "misp-xml".
    pub format: String,
    /// Target URL or file path.
    pub target: String,
    /// Whether to include to_ids-only attributes.
    pub ids_only: bool,
    /// Additional format-specific options.
    pub options: HashMap<String, String>,
}

impl ExportDestination {
    /// Create a JSON export destination.
    #[must_use]
    pub fn json(name: impl Into<String>, target: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            format: "json".into(),
            target: target.into(),
            ids_only: false,
            options: HashMap::new(),
        }
    }

    /// Create a STIX 2.1 export destination.
    #[must_use]
    pub fn stix(name: impl Into<String>, target: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            format: "stix".into(),
            target: target.into(),
            ids_only: false,
            options: HashMap::new(),
        }
    }
}

/// Automated export manager.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct AutoExport {
    /// Registered destinations.
    pub destinations: Vec<ExportDestination>,
    /// Export run log (destination name → last timestamp).
    pub last_exports: HashMap<String, u64>,
    /// Whether export is globally enabled.
    pub enabled: bool,
}

impl AutoExport {
    /// Create a new manager with exports enabled.
    #[must_use]
    pub fn new() -> Self {
        Self {
            destinations: Vec::new(),
            last_exports: HashMap::new(),
            enabled: true,
        }
    }

    /// Add an export destination.
    pub fn add_destination(&mut self, dest: ExportDestination) {
        self.destinations.push(dest);
    }

    /// Simulate an export run to all enabled destinations.
    ///
    /// Returns the number of destinations exported to.
    pub fn run_all(&mut self) -> usize {
        if !self.enabled {
            return 0;
        }
        let now = unix_now();
        let count = self.destinations.len();
        for dest in &self.destinations {
            self.last_exports.insert(dest.name.clone(), now);
        }
        count
    }

    /// # Errors
    ///
    /// Returns an error if the operation fails.
    /// Export to a specific destination by name.
    pub fn run_destination(&mut self, name: &str) -> Result<(), AutomationError> {
        if !self.destinations.iter().any(|d| d.name == name) {
            return Err(AutomationError::ExportFailed(format!(
                "destination '{name}' not found"
            )));
        }
        self.last_exports.insert(name.to_string(), unix_now());
        Ok(())
    }

    /// Return the timestamp of the last export for the given destination.
    #[must_use]
    pub fn last_export(&self, name: &str) -> Option<u64> {
        self.last_exports.get(name).copied()
    }

    /// Number of destinations.
    #[must_use]
    pub const fn destination_count(&self) -> usize {
        self.destinations.len()
    }
}

// ── WorkflowTrigger ───────────────────────────────────────────────────────────

/// A MISP workflow trigger event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TriggerEvent {
    /// A new event was created.
    EventCreated,
    /// An attribute was added.
    AttributeAdded,
    /// An event was published.
    EventPublished,
    /// A sighting was added.
    SightingAdded,
    /// A tag was applied.
    TagApplied(String),
    /// A feed was pulled.
    FeedPulled,
    /// Custom trigger with a name.
    Custom(String),
}

impl TriggerEvent {
    /// Return the trigger name string.
    #[must_use]
    pub const fn name(&self) -> &str {
        match self {
            Self::EventCreated => "event-created",
            Self::AttributeAdded => "attribute-added",
            Self::EventPublished => "event-published",
            Self::SightingAdded => "sighting-added",
            Self::TagApplied(_) => "tag-applied",
            Self::FeedPulled => "feed-pulled",
            Self::Custom(n) => n.as_str(),
        }
    }
}

/// A registered workflow trigger.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowTrigger {
    /// Unique trigger ID.
    pub id: String,
    /// The event that activates this trigger.
    pub event: TriggerEvent,
    /// Name of the workflow to run.
    pub workflow_name: String,
    /// Whether this trigger is active.
    pub enabled: bool,
    /// Number of times triggered.
    pub fire_count: u32,
    /// Last triggered timestamp.
    pub last_triggered: Option<u64>,
    /// Optional filter: only fire when event matches this tag.
    pub filter_tag: Option<String>,
}

impl WorkflowTrigger {
    /// Create a new trigger.
    #[must_use]
    pub fn new(event: TriggerEvent, workflow_name: impl Into<String>) -> Self {
        Self {
            id: mock_uuid(),
            event,
            workflow_name: workflow_name.into(),
            enabled: true,
            fire_count: 0,
            last_triggered: None,
            filter_tag: None,
        }
    }

    /// Restrict this trigger to events with a specific tag.
    #[must_use]
    pub fn with_filter(mut self, tag: impl Into<String>) -> Self {
        self.filter_tag = Some(tag.into());
        self
    }

    /// Check whether this trigger fires for the given event and optional tags.
    #[must_use]
    pub fn matches(&self, event: &TriggerEvent, event_tags: &[String]) -> bool {
        if !self.enabled {
            return false;
        }
        if self.event != *event {
            return false;
        }
        if let Some(required_tag) = &self.filter_tag {
            return event_tags.iter().any(|t| t == required_tag);
        }
        true
    }

    /// Fire this trigger.
    pub fn fire(&mut self) -> String {
        self.fire_count += 1;
        self.last_triggered = Some(unix_now());
        format!(
            "trigger '{}' fired workflow '{}' (total: {})",
            self.id, self.workflow_name, self.fire_count
        )
    }
}

// ── MispAutomation ────────────────────────────────────────────────────────────

/// Top-level MISP automation coordinator, managing rules, tagging, exports,
/// correlation, and workflow triggers.
#[derive(Debug)]
pub struct MispAutomation {
    rules: Vec<AutomationRule>,
    correlation: AutoCorrelation,
    tagging: AutoTagging,
    exports: AutoExport,
    triggers: Vec<WorkflowTrigger>,
    /// Global automation on/off switch.
    pub enabled: bool,
    /// Log of all automation actions.
    log: Vec<AutomationLogEntry>,
}

/// A single entry in the automation log.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutomationLogEntry {
    pub timestamp: u64,
    pub rule_id: Option<String>,
    pub message: String,
    pub level: LogLevel,
}

/// Log severity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LogLevel {
    Info,
    Warning,
    Error,
}

impl Default for MispAutomation {
    fn default() -> Self {
        Self::new()
    }
}

impl MispAutomation {
    /// Create a new automation coordinator with defaults.
    #[must_use]
    pub fn new() -> Self {
        Self {
            rules: Vec::new(),
            correlation: AutoCorrelation::new(),
            tagging: AutoTagging::new(),
            exports: AutoExport::new(),
            triggers: Vec::new(),
            enabled: true,
            log: Vec::new(),
        }
    }

    // ── Rules ────────────────────────────────────────────────────────────────

    /// Register an automation rule.
    pub fn add_rule(&mut self, rule: AutomationRule) {
        self.rules.push(rule);
        self.rules.sort_by_key(|r| r.priority);
    }

    /// Remove a rule by ID.
    pub fn remove_rule(&mut self, id: &str) -> bool {
        let before = self.rules.len();
        self.rules.retain(|r| r.id != id);
        self.rules.len() < before
    }

    /// Evaluate all enabled rules against a context.
    ///
    /// Returns the combined action logs.
    pub fn evaluate_rules(&mut self, ctx: &ConditionContext) -> Vec<String> {
        if !self.enabled {
            return Vec::new();
        }
        let mut logs: Vec<String> = Vec::new();
        for rule in &mut self.rules {
            let fired = rule.evaluate_and_fire(ctx);
            logs.extend(fired);
        }
        for msg in &logs {
            self.log.push(AutomationLogEntry {
                timestamp: unix_now(),
                rule_id: None,
                message: msg.clone(),
                level: LogLevel::Info,
            });
        }
        logs
    }

    /// Return all rules.
    #[must_use]
    pub fn rules(&self) -> &[AutomationRule] {
        &self.rules
    }

    /// Find a rule by ID.
    #[must_use]
    pub fn find_rule(&self, id: &str) -> Option<&AutomationRule> {
        self.rules.iter().find(|r| r.id == id)
    }

    // ── Correlation ──────────────────────────────────────────────────────────

    /// Access the correlation config mutably.
    pub const fn correlation_mut(&mut self) -> &mut AutoCorrelation {
        &mut self.correlation
    }

    /// Run automatic correlation.
    pub fn run_correlation(&mut self, event_count: u32) -> u32 {
        self.correlation.run(event_count)
    }

    // ── Tagging ──────────────────────────────────────────────────────────────

    /// Access the tagging manager mutably.
    pub const fn tagging_mut(&mut self) -> &mut AutoTagging {
        &mut self.tagging
    }

    /// Apply auto-tagging to a list of attribute values.
    pub fn auto_tag(&mut self, indicator: &str, values: &[&str]) {
        self.tagging.run(indicator, values);
    }

    // ── Exports ──────────────────────────────────────────────────────────────

    /// Access the export manager mutably.
    pub const fn exports_mut(&mut self) -> &mut AutoExport {
        &mut self.exports
    }

    /// Run all exports.
    pub fn run_exports(&mut self) -> usize {
        self.exports.run_all()
    }

    // ── Triggers ─────────────────────────────────────────────────────────────

    /// Register a workflow trigger.
    pub fn add_trigger(&mut self, trigger: WorkflowTrigger) {
        self.triggers.push(trigger);
    }

    /// Fire all triggers matching the given event.
    pub fn emit(&mut self, event: &TriggerEvent, tags: &[String]) -> Vec<String> {
        let mut logs: Vec<String> = Vec::new();
        for trigger in &mut self.triggers {
            if trigger.matches(event, tags) {
                logs.push(trigger.fire());
            }
        }
        logs
    }

    /// Number of registered triggers.
    #[must_use]
    pub const fn trigger_count(&self) -> usize {
        self.triggers.len()
    }

    // ── Log ──────────────────────────────────────────────────────────────────

    /// Return a reference to the automation log.
    #[must_use]
    pub fn log(&self) -> &[AutomationLogEntry] {
        &self.log
    }

    /// Clear the log.
    pub fn clear_log(&mut self) {
        self.log.clear();
    }

    /// Number of rules.
    #[must_use]
    pub const fn rule_count(&self) -> usize {
        self.rules.len()
    }
}

// ── AutomationPolicy ──────────────────────────────────────────────────────────

/// Defines policy constraints for a `MispAutomation` deployment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutomationPolicy {
    /// Maximum rules allowed.
    pub max_rules: usize,
    /// Maximum export destinations.
    pub max_export_destinations: usize,
    /// Whether to allow publishing events automatically.
    pub allow_auto_publish: bool,
    /// Whether to allow network alerts.
    pub allow_network_alerts: bool,
    /// Required tag that every rule must include.
    pub required_tag_prefix: Option<String>,
    /// Whether to allow cross-organisation correlation.
    pub allow_cross_org: bool,
}

impl Default for AutomationPolicy {
    fn default() -> Self {
        Self {
            max_rules: 100,
            max_export_destinations: 10,
            allow_auto_publish: true,
            allow_network_alerts: false,
            required_tag_prefix: None,
            allow_cross_org: true,
        }
    }
}

impl AutomationPolicy {
    /// Create a restrictive policy (e.g. for GDPR-sensitive environments).
    #[must_use]
    pub fn restrictive() -> Self {
        Self {
            max_rules: 20,
            max_export_destinations: 3,
            allow_auto_publish: false,
            allow_network_alerts: false,
            required_tag_prefix: Some("approved:".into()),
            allow_cross_org: false,
        }
    }

    /// Validate a `MispAutomation` against this policy.
    #[must_use]
    pub fn validate(&self, ma: &MispAutomation) -> Vec<String> {
        let mut errors: Vec<String> = Vec::new();
        if ma.rule_count() > self.max_rules {
            errors.push(format!(
                "rule count {} exceeds maximum {}",
                ma.rule_count(),
                self.max_rules
            ));
        }
        if ma.exports.destination_count() > self.max_export_destinations {
            errors.push(format!(
                "export destinations {} exceed maximum {}",
                ma.exports.destination_count(),
                self.max_export_destinations
            ));
        }
        if !self.allow_auto_publish {
            for rule in ma.rules() {
                if rule
                    .actions
                    .iter()
                    .any(|a| matches!(a, AutomationAction::PublishEvent))
                {
                    errors.push(format!(
                        "rule '{}' contains PublishEvent action which is not allowed",
                        rule.name
                    ));
                }
            }
        }
        if !self.allow_network_alerts {
            for rule in ma.rules() {
                if rule
                    .actions
                    .iter()
                    .any(|a| matches!(a, AutomationAction::SendAlert { .. }))
                {
                    errors.push(format!(
                        "rule '{}' contains SendAlert action which is not allowed",
                        rule.name
                    ));
                }
            }
        }
        errors
    }

    /// Return `true` if the policy is satisfied.
    #[must_use]
    pub fn is_satisfied(&self, ma: &MispAutomation) -> bool {
        self.validate(ma).is_empty()
    }
}

// ── AutomationStats ───────────────────────────────────────────────────────────

/// Aggregate statistics for a `MispAutomation` instance.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AutomationStats {
    pub total_rules: usize,
    pub enabled_rules: usize,
    pub total_rule_fires: u32,
    pub tagging_policy_count: usize,
    pub export_destination_count: usize,
    pub trigger_count: usize,
    pub log_entries: usize,
}

impl AutomationStats {
    /// Compute stats from a `MispAutomation`.
    #[must_use]
    pub fn from_automation(ma: &MispAutomation) -> Self {
        Self {
            total_rules: ma.rule_count(),
            enabled_rules: ma.rules().iter().filter(|r| r.enabled).count(),
            total_rule_fires: ma.rules().iter().map(|r| r.fire_count).sum(),
            tagging_policy_count: ma.tagging.policy_count(),
            export_destination_count: ma.exports.destination_count(),
            trigger_count: ma.trigger_count(),
            log_entries: ma.log().len(),
        }
    }
}

// ── AutomationBuilder ─────────────────────────────────────────────────────────

/// Builder for composing a `MispAutomation` from a configuration.
#[derive(Debug, Default)]
pub struct AutomationBuilder {
    rules: Vec<AutomationRule>,
    tagging_policies: Vec<AutoTaggingPolicy>,
    export_destinations: Vec<ExportDestination>,
    triggers: Vec<WorkflowTrigger>,
    correlation_enabled: bool,
}

impl AutomationBuilder {
    /// Create an empty builder.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a rule.
    #[must_use]
    pub fn with_rule(mut self, rule: AutomationRule) -> Self {
        self.rules.push(rule);
        self
    }

    /// Add a tagging policy.
    #[must_use]
    pub fn with_tagging(mut self, policy: AutoTaggingPolicy) -> Self {
        self.tagging_policies.push(policy);
        self
    }

    /// Add an export destination.
    #[must_use]
    pub fn with_export(mut self, dest: ExportDestination) -> Self {
        self.export_destinations.push(dest);
        self
    }

    /// Add a workflow trigger.
    #[must_use]
    pub fn with_trigger(mut self, trigger: WorkflowTrigger) -> Self {
        self.triggers.push(trigger);
        self
    }

    /// Enable automatic correlation.
    #[must_use]
    pub const fn enable_correlation(mut self) -> Self {
        self.correlation_enabled = true;
        self
    }

    /// Build the `MispAutomation` instance.
    #[must_use]
    pub fn build(self) -> MispAutomation {
        let mut ma = MispAutomation::new();
        for rule in self.rules {
            ma.add_rule(rule);
        }
        for policy in self.tagging_policies {
            ma.tagging_mut().add_policy(policy);
        }
        for dest in self.export_destinations {
            ma.exports_mut().add_destination(dest);
        }
        for trigger in self.triggers {
            ma.add_trigger(trigger);
        }
        if !self.correlation_enabled {
            ma.correlation_mut().enabled = false;
        }
        ma
    }
}

// ── RuleEvaluator ─────────────────────────────────────────────────────────────

/// Evaluates a batch of `ConditionContext` objects against all rules and
/// returns a summary.
#[derive(Debug, Default)]
pub struct RuleEvaluator {
    /// Results: context index → log messages fired.
    pub results: Vec<Vec<String>>,
    /// Total number of rule fires across all contexts.
    pub total_fires: usize,
}

impl RuleEvaluator {
    /// Evaluate all contexts.
    pub fn evaluate_batch(ma: &mut MispAutomation, contexts: &[ConditionContext]) -> Self {
        let mut results = Vec::new();
        let mut total_fires = 0;
        for ctx in contexts {
            let logs = ma.evaluate_rules(ctx);
            total_fires += logs.len();
            results.push(logs);
        }
        Self {
            results,
            total_fires,
        }
    }

    /// Return contexts that triggered at least one rule.
    #[must_use]
    pub fn triggered_indices(&self) -> Vec<usize> {
        self.results
            .iter()
            .enumerate()
            .filter(|(_, logs)| !logs.is_empty())
            .map(|(i, _)| i)
            .collect()
    }

    /// Return `true` if any rule fired.
    #[must_use]
    pub const fn any_fired(&self) -> bool {
        self.total_fires > 0
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn simple_ctx() -> ConditionContext {
        ConditionContext {
            attribute_type: Some("sha256".into()),
            attribute_value: Some("deadbeef_evil_malware".into()),
            threat_level: 1,
            tags: vec!["tlp:red".into()],
            is_ids: true,
            sightings: 5,
            event_published: false,
        }
    }

    // ── AutomationCondition ──────────────────────────────────────────────────

    #[test]
    fn test_condition_value_contains_match() {
        let c = AutomationCondition::ValueContains("evil".into());
        assert!(c.evaluate(&simple_ctx()));
    }

    #[test]
    fn test_condition_value_contains_no_match() {
        let c = AutomationCondition::ValueContains("safe".into());
        assert!(!c.evaluate(&simple_ctx()));
    }

    #[test]
    fn test_condition_type_equals() {
        let c = AutomationCondition::TypeEquals("sha256".into());
        assert!(c.evaluate(&simple_ctx()));
    }

    #[test]
    fn test_condition_has_tag() {
        let c = AutomationCondition::HasTag("tlp:red".into());
        assert!(c.evaluate(&simple_ctx()));
    }

    #[test]
    fn test_condition_missing_tag() {
        let c = AutomationCondition::MissingTag("tlp:green".into());
        assert!(c.evaluate(&simple_ctx()));
    }

    #[test]
    fn test_condition_is_ids() {
        let c = AutomationCondition::IsIdsAttribute;
        assert!(c.evaluate(&simple_ctx()));
    }

    #[test]
    fn test_condition_min_sightings() {
        let c = AutomationCondition::MinSightings(5);
        assert!(c.evaluate(&simple_ctx()));
    }

    #[test]
    fn test_condition_min_sightings_fail() {
        let c = AutomationCondition::MinSightings(10);
        assert!(!c.evaluate(&simple_ctx()));
    }

    #[test]
    fn test_condition_all_pass() {
        let c = AutomationCondition::All(vec![
            AutomationCondition::IsIdsAttribute,
            AutomationCondition::HasTag("tlp:red".into()),
        ]);
        assert!(c.evaluate(&simple_ctx()));
    }

    #[test]
    fn test_condition_all_fail() {
        let c = AutomationCondition::All(vec![
            AutomationCondition::IsIdsAttribute,
            AutomationCondition::HasTag("tlp:green".into()),
        ]);
        assert!(!c.evaluate(&simple_ctx()));
    }

    #[test]
    fn test_condition_any_pass() {
        let c = AutomationCondition::Any(vec![
            AutomationCondition::HasTag("tlp:green".into()),
            AutomationCondition::HasTag("tlp:red".into()),
        ]);
        assert!(c.evaluate(&simple_ctx()));
    }

    #[test]
    fn test_condition_any_fail() {
        let c = AutomationCondition::Any(vec![
            AutomationCondition::HasTag("tlp:green".into()),
            AutomationCondition::HasTag("tlp:white".into()),
        ]);
        assert!(!c.evaluate(&simple_ctx()));
    }

    // ── AutomationAction ─────────────────────────────────────────────────────

    #[test]
    fn test_action_add_tag_log() {
        let a = AutomationAction::AddTag("malware".into());
        let log = a.execute("rule-1");
        assert!(log.contains("added tag 'malware'"));
    }

    #[test]
    fn test_action_publish_log() {
        let a = AutomationAction::PublishEvent;
        assert!(a.execute("rule-1").contains("published"));
    }

    #[test]
    fn test_action_export_log() {
        let a = AutomationAction::Export {
            format: "stix".into(),
            destination: "/tmp/out".into(),
        };
        let log = a.execute("rule-1");
        assert!(log.contains("exported") && log.contains("stix"));
    }

    // ── AutomationRule ───────────────────────────────────────────────────────

    #[test]
    fn test_rule_fires() {
        let mut rule = AutomationRule::new(
            "Test Rule",
            AutomationCondition::IsIdsAttribute,
            vec![AutomationAction::AddTag("auto-ids".into())],
        );
        let logs = rule.evaluate_and_fire(&simple_ctx());
        assert!(!logs.is_empty());
        assert_eq!(rule.fire_count, 1);
    }

    #[test]
    fn test_rule_disabled_no_fire() {
        let mut rule = AutomationRule::new(
            "Disabled",
            AutomationCondition::IsIdsAttribute,
            vec![AutomationAction::PublishEvent],
        );
        rule.enabled = false;
        let logs = rule.evaluate_and_fire(&simple_ctx());
        assert!(logs.is_empty());
        assert_eq!(rule.fire_count, 0);
    }

    #[test]
    fn test_rule_condition_not_met() {
        let mut rule = AutomationRule::new(
            "No Match",
            AutomationCondition::HasTag("tlp:green".into()),
            vec![AutomationAction::AddTag("x".into())],
        );
        let logs = rule.evaluate_and_fire(&simple_ctx());
        assert!(logs.is_empty());
    }

    #[test]
    fn test_rule_has_fired() {
        let mut rule = AutomationRule::new("R", AutomationCondition::IsIdsAttribute, vec![]);
        assert!(!rule.has_fired());
        rule.evaluate_and_fire(&simple_ctx());
        assert!(rule.has_fired());
    }

    // ── AutoCorrelation ──────────────────────────────────────────────────────

    #[test]
    fn test_auto_correlation_run() {
        let mut ac = AutoCorrelation::new();
        let count = ac.run(10);
        assert!(count > 0);
        assert!(ac.last_run.is_some());
    }

    #[test]
    fn test_auto_correlation_disabled() {
        let mut ac = AutoCorrelation::new();
        ac.enabled = false;
        assert_eq!(ac.run(100), 0);
    }

    #[test]
    fn test_auto_correlation_excluded_type() {
        let ac = AutoCorrelation::new();
        assert!(ac.is_excluded("comment"));
        assert!(!ac.is_excluded("sha256"));
    }

    #[test]
    fn test_auto_correlation_add_excluded() {
        let mut ac = AutoCorrelation::new();
        ac.exclude_type("url");
        assert!(ac.is_excluded("url"));
    }

    // ── AutoTagging ──────────────────────────────────────────────────────────

    #[test]
    fn test_auto_tagging_match() {
        let mut at = AutoTagging::new();
        at.add_policy(AutoTaggingPolicy::substring("evil", "malware"));
        let tags = at.evaluate(&["evil_hash_sample"]);
        assert!(tags.contains(&"malware".to_string()));
    }

    #[test]
    fn test_auto_tagging_no_match() {
        let mut at = AutoTagging::new();
        at.add_policy(AutoTaggingPolicy::substring("evil", "malware"));
        let tags = at.evaluate(&["safe_hash"]);
        assert!(tags.is_empty());
    }

    #[test]
    fn test_auto_tagging_multiple_policies() {
        let mut at = AutoTagging::new();
        at.add_policy(AutoTaggingPolicy::substring("ransom", "ransomware"));
        at.add_policy(AutoTaggingPolicy::substring("crypto", "miner"));
        let tags = at.evaluate(&["ransom_and_crypto_locker"]);
        assert!(tags.contains(&"ransomware".to_string()));
        assert!(tags.contains(&"miner".to_string()));
    }

    #[test]
    fn test_auto_tagging_run() {
        let mut at = AutoTagging::new();
        at.add_policy(AutoTaggingPolicy::substring("apt", "threat-actor"));
        at.run("ioc-1", &["apt28_dropper"]);
        assert!(at.last_results.contains_key("ioc-1"));
    }

    // ── AutoExport ───────────────────────────────────────────────────────────

    #[test]
    fn test_auto_export_run_all() {
        let mut ae = AutoExport::new();
        ae.add_destination(ExportDestination::json("out1", "/tmp/out1.json"));
        ae.add_destination(ExportDestination::stix("out2", "/tmp/out2.json"));
        assert_eq!(ae.run_all(), 2);
        assert!(ae.last_export("out1").is_some());
    }

    #[test]
    fn test_auto_export_disabled() {
        let mut ae = AutoExport::new();
        ae.enabled = false;
        ae.add_destination(ExportDestination::json("out", "/tmp/x.json"));
        assert_eq!(ae.run_all(), 0);
    }

    #[test]
    fn test_auto_export_run_destination_ok() {
        let mut ae = AutoExport::new();
        ae.add_destination(ExportDestination::json("out", "/tmp/x.json"));
        assert!(ae.run_destination("out").is_ok());
    }

    #[test]
    fn test_auto_export_run_destination_missing() {
        let mut ae = AutoExport::new();
        assert!(ae.run_destination("missing").is_err());
    }

    // ── WorkflowTrigger ──────────────────────────────────────────────────────

    #[test]
    fn test_trigger_fires_on_matching_event() {
        let mut t = WorkflowTrigger::new(TriggerEvent::EventCreated, "on_created");
        assert!(t.matches(&TriggerEvent::EventCreated, &[]));
        let log = t.fire();
        assert!(log.contains("on_created"));
        assert_eq!(t.fire_count, 1);
    }

    #[test]
    fn test_trigger_no_fire_wrong_event() {
        let t = WorkflowTrigger::new(TriggerEvent::EventPublished, "on_published");
        assert!(!t.matches(&TriggerEvent::EventCreated, &[]));
    }

    #[test]
    fn test_trigger_filter_tag_match() {
        let t = WorkflowTrigger::new(TriggerEvent::EventCreated, "wf").with_filter("tlp:red");
        let tags = vec!["tlp:red".to_string()];
        assert!(t.matches(&TriggerEvent::EventCreated, &tags));
    }

    #[test]
    fn test_trigger_filter_tag_no_match() {
        let t = WorkflowTrigger::new(TriggerEvent::EventCreated, "wf").with_filter("tlp:red");
        let tags = vec!["tlp:green".to_string()];
        assert!(!t.matches(&TriggerEvent::EventCreated, &tags));
    }

    #[test]
    fn test_trigger_disabled() {
        let mut t = WorkflowTrigger::new(TriggerEvent::EventCreated, "wf");
        t.enabled = false;
        assert!(!t.matches(&TriggerEvent::EventCreated, &[]));
    }

    // ── MispAutomation ───────────────────────────────────────────────────────

    #[test]
    fn test_misp_automation_add_rule_and_evaluate() {
        let mut ma = MispAutomation::new();
        ma.add_rule(AutomationRule::new(
            "Test",
            AutomationCondition::IsIdsAttribute,
            vec![AutomationAction::AddTag("auto".into())],
        ));
        let logs = ma.evaluate_rules(&simple_ctx());
        assert!(!logs.is_empty());
    }

    #[test]
    fn test_misp_automation_remove_rule() {
        let mut ma = MispAutomation::new();
        let rule = AutomationRule::new("R", AutomationCondition::IsIdsAttribute, vec![]);
        let id = rule.id.clone();
        ma.add_rule(rule);
        assert_eq!(ma.rule_count(), 1);
        assert!(ma.remove_rule(&id));
        assert_eq!(ma.rule_count(), 0);
    }

    #[test]
    fn test_misp_automation_disabled() {
        let mut ma = MispAutomation::new();
        ma.enabled = false;
        ma.add_rule(AutomationRule::new(
            "R",
            AutomationCondition::IsIdsAttribute,
            vec![],
        ));
        assert!(ma.evaluate_rules(&simple_ctx()).is_empty());
    }

    #[test]
    fn test_misp_automation_run_correlation() {
        let mut ma = MispAutomation::new();
        let count = ma.run_correlation(20);
        assert!(count > 0);
    }

    #[test]
    fn test_misp_automation_emit_trigger() {
        let mut ma = MispAutomation::new();
        ma.add_trigger(WorkflowTrigger::new(
            TriggerEvent::EventPublished,
            "publish_wf",
        ));
        let logs = ma.emit(&TriggerEvent::EventPublished, &[]);
        assert_eq!(logs.len(), 1);
        assert!(logs[0].contains("publish_wf"));
    }

    #[test]
    fn test_misp_automation_log_populated() {
        let mut ma = MispAutomation::new();
        ma.add_rule(AutomationRule::new(
            "R",
            AutomationCondition::IsIdsAttribute,
            vec![AutomationAction::AddTag("test".into())],
        ));
        ma.evaluate_rules(&simple_ctx());
        assert!(!ma.log().is_empty());
    }

    #[test]
    fn test_misp_automation_clear_log() {
        let mut ma = MispAutomation::new();
        ma.log.push(AutomationLogEntry {
            timestamp: unix_now(),
            rule_id: None,
            message: "test".into(),
            level: LogLevel::Info,
        });
        ma.clear_log();
        assert!(ma.log().is_empty());
    }

    #[test]
    fn test_misp_automation_auto_tag() {
        let mut ma = MispAutomation::new();
        ma.tagging_mut()
            .add_policy(AutoTaggingPolicy::substring("evil", "malware"));
        ma.auto_tag("hash1", &["evil_sample"]);
        assert!(ma.tagging.last_results.contains_key("hash1"));
    }

    #[test]
    fn test_misp_automation_run_exports() {
        let mut ma = MispAutomation::new();
        ma.exports_mut()
            .add_destination(ExportDestination::json("dest", "/tmp/x.json"));
        assert_eq!(ma.run_exports(), 1);
    }

    // ── AutomationStats ──────────────────────────────────────────────────────

    #[test]
    fn test_automation_stats_empty() {
        let ma = MispAutomation::new();
        let stats = AutomationStats::from_automation(&ma);
        assert_eq!(stats.total_rules, 0);
        assert_eq!(stats.total_rule_fires, 0);
    }

    #[test]
    fn test_automation_stats_with_rules() {
        let mut ma = MispAutomation::new();
        ma.add_rule(AutomationRule::new(
            "R1",
            AutomationCondition::IsIdsAttribute,
            vec![],
        ));
        ma.add_rule(AutomationRule::new(
            "R2",
            AutomationCondition::IsIdsAttribute,
            vec![],
        ));
        let stats = AutomationStats::from_automation(&ma);
        assert_eq!(stats.total_rules, 2);
        assert_eq!(stats.enabled_rules, 2);
    }

    #[test]
    fn test_automation_stats_after_fires() {
        let mut ma = MispAutomation::new();
        ma.add_rule(AutomationRule::new(
            "R",
            AutomationCondition::IsIdsAttribute,
            vec![],
        ));
        ma.evaluate_rules(&simple_ctx());
        let stats = AutomationStats::from_automation(&ma);
        assert_eq!(stats.total_rule_fires, 1);
    }

    // ── AutomationBuilder ────────────────────────────────────────────────────

    #[test]
    fn test_builder_creates_automation() {
        let ma = AutomationBuilder::new()
            .with_rule(AutomationRule::new(
                "R",
                AutomationCondition::IsIdsAttribute,
                vec![],
            ))
            .with_tagging(AutoTaggingPolicy::substring("evil", "malware"))
            .with_export(ExportDestination::json("out", "/tmp/x.json"))
            .with_trigger(WorkflowTrigger::new(TriggerEvent::EventCreated, "wf"))
            .enable_correlation()
            .build();
        assert_eq!(ma.rule_count(), 1);
        assert_eq!(ma.tagging.policy_count(), 1);
        assert_eq!(ma.exports.destination_count(), 1);
        assert_eq!(ma.trigger_count(), 1);
    }

    #[test]
    fn test_builder_correlation_disabled() {
        let ma = AutomationBuilder::new().build();
        // Without enable_correlation(), correlation is disabled.
        assert!(!ma.correlation.enabled);
    }

    // ── RuleEvaluator ────────────────────────────────────────────────────────

    #[test]
    fn test_rule_evaluator_batch() {
        let mut ma = MispAutomation::new();
        ma.add_rule(AutomationRule::new(
            "R",
            AutomationCondition::IsIdsAttribute,
            vec![AutomationAction::AddTag("auto".into())],
        ));
        let ctxs = vec![simple_ctx(), ConditionContext::default()];
        let eval = RuleEvaluator::evaluate_batch(&mut ma, &ctxs);
        assert!(eval.any_fired());
        let triggered = eval.triggered_indices();
        // Only the first context (which is an IDS attribute) should trigger.
        assert!(triggered.contains(&0));
    }

    #[test]
    fn test_rule_evaluator_no_fires() {
        let mut ma = MispAutomation::new();
        ma.add_rule(AutomationRule::new(
            "R",
            AutomationCondition::HasTag("tlp:green".into()),
            vec![],
        ));
        let ctxs = vec![simple_ctx()]; // simple_ctx has tlp:red, not green
        let eval = RuleEvaluator::evaluate_batch(&mut ma, &ctxs);
        assert!(!eval.any_fired());
    }

    // ── AutomationPolicy ─────────────────────────────────────────────────────

    #[test]
    fn test_policy_default_satisfied_empty() {
        let policy = AutomationPolicy::default();
        let ma = MispAutomation::new();
        assert!(policy.is_satisfied(&ma));
    }

    #[test]
    fn test_policy_max_rules_exceeded() {
        let policy = AutomationPolicy {
            max_rules: 1,
            ..Default::default()
        };
        let mut ma = MispAutomation::new();
        ma.add_rule(AutomationRule::new(
            "R1",
            AutomationCondition::IsIdsAttribute,
            vec![],
        ));
        ma.add_rule(AutomationRule::new(
            "R2",
            AutomationCondition::IsIdsAttribute,
            vec![],
        ));
        let errors = policy.validate(&ma);
        assert!(!errors.is_empty());
    }

    #[test]
    fn test_policy_no_auto_publish() {
        let policy = AutomationPolicy {
            allow_auto_publish: false,
            ..Default::default()
        };
        let mut ma = MispAutomation::new();
        ma.add_rule(AutomationRule::new(
            "publish_rule",
            AutomationCondition::IsIdsAttribute,
            vec![AutomationAction::PublishEvent],
        ));
        let errors = policy.validate(&ma);
        assert!(!errors.is_empty());
    }

    #[test]
    fn test_policy_restrictive() {
        let policy = AutomationPolicy::restrictive();
        assert!(!policy.allow_auto_publish);
        assert!(!policy.allow_cross_org);
        assert_eq!(policy.max_rules, 20);
    }

    #[test]
    fn test_policy_network_alerts_blocked() {
        let policy = AutomationPolicy {
            allow_network_alerts: false,
            ..Default::default()
        };
        let mut ma = MispAutomation::new();
        ma.add_rule(AutomationRule::new(
            "alert_rule",
            AutomationCondition::IsIdsAttribute,
            vec![AutomationAction::SendAlert {
                url: "http://x".into(),
                message: "alert".into(),
            }],
        ));
        let errors = policy.validate(&ma);
        assert!(!errors.is_empty());
    }
}
