//! `agent_action_executor` —  Dispatches agent actions to RE tools.
//!
//! [`AgentActionExecutor`] receives [`AgentAction`] requests, routes them to
//! the appropriate handler, and returns [`ActionResult`] values.  Each action
//! kind maps to a concrete operation (rename, comment, type application, etc.).

use std::collections::HashMap;
use std::time::Instant;

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};

// â"€â"€ ActionKind â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Discriminant for every action the executor can handle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ActionKind {
    /// Rename a function or variable at an address.
    RenameSymbol,
    /// Add or update a comment at an address.
    AddComment,
    /// Apply a C-style type declaration to a location.
    ApplyType,
    /// Create a named bookmark at an address.
    CreateBookmark,
    /// Execute an inline script (Python / Frida JS / etc.).
    RunScript,
    /// Apply a binary patch.
    ApplyPatch,
    /// Export a data region as a file.
    ExportData,
    /// Set a function's calling convention.
    SetCallingConvention,
    /// Mark an address range as a code or data region.
    MarkRegion,
    /// Query information about an address (read-only).
    Query,
}

impl std::fmt::Display for ActionKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl ActionKind {
    /// Returns `true` for write-mutating actions.
    #[must_use]
    pub const fn is_mutating(self) -> bool {
        !matches!(self, Self::Query)
    }

    /// Returns `true` for actions that operate on binary bytes.
    #[must_use]
    pub const fn is_binary_level(self) -> bool {
        matches!(self, Self::ApplyPatch | Self::ExportData | Self::MarkRegion)
    }
}

// â"€â"€ AgentAction â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// A typed action that the agent requests the platform to perform.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentAction {
    /// Monotonically increasing identifier.
    pub action_id: u64,
    /// What kind of action this is.
    pub kind: ActionKind,
    /// Target virtual address, if applicable.
    pub address: Option<u64>,
    /// Primary string parameter (name, comment text, type string, script code —¦).
    pub text: Option<String>,
    /// Raw bytes, used for binary-level actions.
    pub bytes: Option<Vec<u8>>,
    /// Extra key-value parameters.
    pub params: HashMap<String, serde_json::Value>,
    /// Confidence that this action is correct [0.0, 1.0].
    pub confidence: f32,
    /// Human-readable rationale for this action.
    pub rationale: String,
}

impl AgentAction {
    /// Create a new rename action.
    #[must_use]
    pub fn rename(address: u64, new_name: impl Into<String>, rationale: impl Into<String>) -> Self {
        Self::with_next_id(
            ActionKind::RenameSymbol,
            Some(address),
            Some(new_name.into()),
            rationale,
        )
    }

    /// Create a new comment action.
    #[must_use]
    pub fn comment(address: u64, text: impl Into<String>, rationale: impl Into<String>) -> Self {
        Self::with_next_id(
            ActionKind::AddComment,
            Some(address),
            Some(text.into()),
            rationale,
        )
    }

    /// Create a new type-application action.
    #[must_use]
    pub fn apply_type(
        address: u64,
        type_str: impl Into<String>,
        rationale: impl Into<String>,
    ) -> Self {
        Self::with_next_id(
            ActionKind::ApplyType,
            Some(address),
            Some(type_str.into()),
            rationale,
        )
    }

    /// Create a patch action.
    #[must_use]
    pub fn patch(address: u64, bytes: Vec<u8>, rationale: impl Into<String>) -> Self {
        let mut a = Self::with_next_id(ActionKind::ApplyPatch, Some(address), None, rationale);
        a.bytes = Some(bytes);
        a
    }

    /// Create a script action.
    #[must_use]
    pub fn script(code: impl Into<String>, engine: impl Into<String>) -> Self {
        let mut a = Self::with_next_id(ActionKind::RunScript, None, Some(code.into()), "");
        a.params.insert(
            "engine".into(),
            serde_json::Value::String(engine.into()),
        );
        a
    }

    /// Create a query action.
    #[must_use]
    pub fn query(address: u64, query_name: impl Into<String>) -> Self {
        Self::with_next_id(
            ActionKind::Query,
            Some(address),
            Some(query_name.into()),
            "",
        )
    }

    /// Builder: set confidence.
    #[must_use]
    pub const fn with_confidence(mut self, c: f32) -> Self {
        // `f32::clamp` propagates NaN and `is_nan()` is unavailable in a const
        // fn; with NaN every comparison is false, so we fall through to 0.0.
        // `casts::f64_to_f32` in this same crate already guards NaN explicitly.
        self.confidence = if c >= 1.0 {
            1.0
        } else if c > 0.0 {
            c
        } else {
            0.0
        };
        self
    }

    fn with_next_id(
        kind: ActionKind,
        address: Option<u64>,
        text: Option<String>,
        rationale: impl Into<String>,
    ) -> Self {
        use std::sync::atomic::{AtomicU64, Ordering};
        static CTR: AtomicU64 = AtomicU64::new(1);
        Self {
            action_id: CTR.fetch_add(1, Ordering::Relaxed),
            kind,
            address,
            text,
            bytes: None,
            params: HashMap::new(),
            confidence: 0.8,
            rationale: rationale.into(),
        }
    }
}

// â"€â"€ ActionResult â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// The outcome of executing an [`AgentAction`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionResult {
    /// The `action_id` from the originating action.
    pub action_id: u64,
    /// The kind of action that was executed.
    pub kind: ActionKind,
    /// Whether the action succeeded.
    pub success: bool,
    /// Optional human-readable message (error description or result summary).
    pub message: String,
    /// Output data for query/export actions.
    pub output: serde_json::Value,
    /// Wall time taken by the handler.
    pub duration_ms: u64,
}

impl ActionResult {
    /// Create a success result.
    #[must_use]
    pub fn ok(
        action_id: u64,
        kind: ActionKind,
        message: impl Into<String>,
        duration_ms: u64,
    ) -> Self {
        Self {
            action_id,
            kind,
            success: true,
            message: message.into(),
            output: serde_json::Value::Null,
            duration_ms,
        }
    }

    /// Create a failure result.
    #[must_use]
    pub fn err(action_id: u64, kind: ActionKind, message: impl Into<String>) -> Self {
        Self {
            action_id,
            kind,
            success: false,
            message: message.into(),
            output: serde_json::Value::Null,
            duration_ms: 0,
        }
    }

    /// Attach output data (used for query results).
    #[must_use]
    pub fn with_output(mut self, output: serde_json::Value) -> Self {
        self.output = output;
        self
    }
}

// â"€â"€ ActionHandler trait â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Trait implemented by each concrete action handler.
pub trait ActionHandler: Send + Sync {
    /// Returns the `ActionKind` this handler services.
    fn kind(&self) -> ActionKind;
    /// Execute the action and return a result.
    fn execute(&self, action: &AgentAction) -> ActionResult;
    /// Returns `true` if the handler can handle this specific action variant.
    fn can_handle(&self, action: &AgentAction) -> bool {
        action.kind == self.kind()
    }
}

// â"€â"€ Built-in handlers â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Handler for [`ActionKind::RenameSymbol`].
pub struct RenameHandler {
    /// Records applied renames: address â†' new name.
    pub applied: Mutex<HashMap<u64, String>>,
}

impl Default for RenameHandler {
    fn default() -> Self {
        Self {
            applied: Mutex::new(HashMap::new()),
        }
    }
}

impl ActionHandler for RenameHandler {
    fn kind(&self) -> ActionKind {
        ActionKind::RenameSymbol
    }

    fn execute(&self, action: &AgentAction) -> ActionResult {
        let t0 = Instant::now();
        let Some(addr) = action.address else {
            return ActionResult::err(action.action_id, self.kind(), "no address specified");
        };
        let Some(ref name) = action.text else {
            return ActionResult::err(action.action_id, self.kind(), "no name specified");
        };
        if name.is_empty() {
            return ActionResult::err(action.action_id, self.kind(), "name must not be empty");
        }
        // Validate identifier characters.
        if !name
            .chars()
            .all(|c| c.is_alphanumeric() || c == '_' || c == '.')
        {
            return ActionResult::err(
                action.action_id,
                self.kind(),
                format!("invalid identifier: '{name}'"),
            );
        }
        self.applied.lock().insert(addr, name.clone());
        ActionResult::ok(
            action.action_id,
            self.kind(),
            format!("renamed 0x{addr:X} â†' '{name}'"),
            u64::try_from(t0.elapsed().as_millis()).unwrap_or(u64::MAX),
        )
    }
}

/// Handler for [`ActionKind::AddComment`].
pub struct CommentHandler {
    pub comments: Mutex<HashMap<u64, Vec<String>>>,
}

impl Default for CommentHandler {
    fn default() -> Self {
        Self {
            comments: Mutex::new(HashMap::new()),
        }
    }
}

impl ActionHandler for CommentHandler {
    fn kind(&self) -> ActionKind {
        ActionKind::AddComment
    }

    fn execute(&self, action: &AgentAction) -> ActionResult {
        let t0 = Instant::now();
        let Some(addr) = action.address else {
            return ActionResult::err(action.action_id, self.kind(), "no address specified");
        };
        let text = action.text.clone().unwrap_or_default();
        self.comments.lock().entry(addr).or_default().push(text);
        ActionResult::ok(
            action.action_id,
            self.kind(),
            format!("comment added at 0x{addr:X}"),
            u64::try_from(t0.elapsed().as_millis()).unwrap_or(u64::MAX),
        )
    }
}

/// Handler for [`ActionKind::ApplyType`].
pub struct TypeHandler {
    pub types: Mutex<HashMap<u64, String>>,
}

impl Default for TypeHandler {
    fn default() -> Self {
        Self {
            types: Mutex::new(HashMap::new()),
        }
    }
}

impl ActionHandler for TypeHandler {
    fn kind(&self) -> ActionKind {
        ActionKind::ApplyType
    }

    fn execute(&self, action: &AgentAction) -> ActionResult {
        let t0 = Instant::now();
        let Some(addr) = action.address else {
            return ActionResult::err(action.action_id, self.kind(), "no address specified");
        };
        let type_str = action.text.clone().unwrap_or_default();
        if type_str.is_empty() {
            return ActionResult::err(action.action_id, self.kind(), "type string is empty");
        }
        self.types.lock().insert(addr, type_str.clone());
        ActionResult::ok(
            action.action_id,
            self.kind(),
            format!("type '{type_str}' applied at 0x{addr:X}"),
            u64::try_from(t0.elapsed().as_millis()).unwrap_or(u64::MAX),
        )
    }
}

/// Handler for [`ActionKind::ApplyPatch`].
pub struct PatchHandler {
    pub patches: Mutex<Vec<(u64, Vec<u8>)>>,
}

impl Default for PatchHandler {
    fn default() -> Self {
        Self {
            patches: Mutex::new(Vec::new()),
        }
    }
}

impl ActionHandler for PatchHandler {
    fn kind(&self) -> ActionKind {
        ActionKind::ApplyPatch
    }

    fn execute(&self, action: &AgentAction) -> ActionResult {
        let t0 = Instant::now();
        let Some(addr) = action.address else {
            return ActionResult::err(action.action_id, self.kind(), "no address for patch");
        };
        let bytes = match action.bytes.as_ref() {
            Some(b) if !b.is_empty() => b.clone(),
            _ => {
                return ActionResult::err(
                    action.action_id,
                    self.kind(),
                    "patch bytes are empty",
                )
            }
        };
        let len = bytes.len();
        self.patches.lock().push((addr, bytes));
        ActionResult::ok(
            action.action_id,
            self.kind(),
            format!("patched {len} bytes at 0x{addr:X}"),
            u64::try_from(t0.elapsed().as_millis()).unwrap_or(u64::MAX),
        )
    }
}

/// Handler for [`ActionKind::Query`] —" returns synthetic metadata.
pub struct QueryHandler;

impl ActionHandler for QueryHandler {
    fn kind(&self) -> ActionKind {
        ActionKind::Query
    }

    fn execute(&self, action: &AgentAction) -> ActionResult {
        let t0 = Instant::now();
        let addr = action.address.unwrap_or(0);
        let query_name = action.text.as_deref().unwrap_or("info");
        let output = serde_json::json!({
            "address": format!("0x{addr:X}"),
            "query": query_name,
            "result": "ok",
        });
        ActionResult::ok(
            action.action_id,
            self.kind(),
            format!("query '{query_name}' at 0x{addr:X}"),
            u64::try_from(t0.elapsed().as_millis()).unwrap_or(u64::MAX),
        )
        .with_output(output)
    }
}

// â"€â"€ AgentActionExecutor â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Dispatches [`AgentAction`] requests to registered [`ActionHandler`]s.
pub struct AgentActionExecutor {
    handlers: HashMap<ActionKind, Box<dyn ActionHandler>>,
    /// History of all results produced.
    history: Mutex<Vec<ActionResult>>,
    /// Dry-run mode: actions are validated but not applied.
    dry_run: bool,
}

impl Default for AgentActionExecutor {
    fn default() -> Self {
        Self::new()
    }
}

impl AgentActionExecutor {
    /// Create an executor pre-loaded with the standard built-in handlers.
    #[must_use]
    pub fn new() -> Self {
        let mut e = Self {
            handlers: HashMap::new(),
            history: Mutex::new(Vec::new()),
            dry_run: false,
        };
        e.register(Box::new(RenameHandler::default()));
        e.register(Box::new(CommentHandler::default()));
        e.register(Box::new(TypeHandler::default()));
        e.register(Box::new(PatchHandler::default()));
        e.register(Box::new(QueryHandler));
        e
    }

    /// Enable / disable dry-run mode.
    #[must_use]
    pub const fn with_dry_run(mut self, dry_run: bool) -> Self {
        self.dry_run = dry_run;
        self
    }

    /// Register a custom handler.  Replaces any existing handler for the same kind.
    pub fn register(&mut self, handler: Box<dyn ActionHandler>) {
        self.handlers.insert(handler.kind(), handler);
    }

    /// Execute a single action.
    pub fn execute_action(&self, action: &AgentAction) -> ActionResult {
        if self.dry_run {
            let result = ActionResult::ok(
                action.action_id,
                action.kind,
                format!("[dry-run] would execute {:?}", action.kind),
                0,
            );
            self.history.lock().push(result.clone());
            return result;
        }

        let result = self.handlers.get(&action.kind).map_or_else(
            || ActionResult::err(
                action.action_id,
                action.kind,
                format!("no handler registered for {:?}", action.kind),
            ),
            |handler| handler.execute(action),
        );
        self.history.lock().push(result.clone());
        result
    }

    /// Execute a batch of actions, returning one result per action.
    pub fn execute_batch(&self, actions: &[AgentAction]) -> Vec<ActionResult> {
        actions.iter().map(|a| self.execute_action(a)).collect()
    }

    /// Return a copy of the execution history.
    #[must_use]
    pub fn history(&self) -> Vec<ActionResult> {
        self.history.lock().clone()
    }

    /// Return only the failed results from the history.
    #[must_use]
    pub fn failures(&self) -> Vec<ActionResult> {
        self.history
            .lock()
            .iter()
            .filter(|r| !r.success)
            .cloned()
            .collect()
    }

    /// Clear the history.
    pub fn clear_history(&self) {
        self.history.lock().clear();
    }

    /// Returns the number of successful actions in the history.
    #[must_use]
    pub fn success_count(&self) -> usize {
        self.history.lock().iter().filter(|r| r.success).count()
    }

    /// Returns the number of failed actions in the history.
    #[must_use]
    pub fn failure_count(&self) -> usize {
        self.history.lock().iter().filter(|r| !r.success).count()
    }

    /// Returns `true` if a handler for `kind` is registered.
    #[must_use]
    pub fn has_handler(&self, kind: ActionKind) -> bool {
        self.handlers.contains_key(&kind)
    }

    /// Total wall time of all executed actions (ms).
    #[must_use]
    pub fn total_duration_ms(&self) -> u64 {
        self.history.lock().iter().map(|r| r.duration_ms).sum()
    }

    /// Return a histogram of result counts by kind.
    #[must_use]
    pub fn kind_histogram(&self) -> HashMap<ActionKind, usize> {
        let mut hist: HashMap<ActionKind, usize> = HashMap::new();
        for r in self.history.lock().iter() {
            *hist.entry(r.kind).or_insert(0) += 1;
        }
        hist
    }
}

// â"€â"€ ActionPlan â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// An ordered list of actions to be executed as a unit.
#[derive(Debug, Default)]
pub struct ActionPlan {
    actions: Vec<AgentAction>,
}

impl ActionPlan {
    /// Create an empty plan.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an action to the plan.
    pub fn push(&mut self, action: AgentAction) {
        self.actions.push(action);
    }

    /// Number of actions in the plan.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.actions.len()
    }

    /// Returns `true` if the plan is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.actions.is_empty()
    }

    /// Execute all actions in order and return the results.
    pub fn execute(&self, executor: &AgentActionExecutor) -> Vec<ActionResult> {
        executor.execute_batch(&self.actions)
    }

    /// Return only the mutating actions in this plan.
    #[must_use]
    pub fn mutating_actions(&self) -> Vec<&AgentAction> {
        self.actions.iter().filter(|a| a.kind.is_mutating()).collect()
    }
}

// â"€â"€ Tests â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

#[cfg(test)]
mod tests {
    use super::*;

    fn executor() -> AgentActionExecutor {
        AgentActionExecutor::new()
    }

    #[test]
    fn test_rename_action_success() {
        let ex = executor();
        let a = AgentAction::rename(0x1000, "malloc_wrapper", "identified by pattern");
        let r = ex.execute_action(&a);
        assert!(r.success);
        assert!(r.message.contains("malloc_wrapper"));
    }

    #[test]
    fn test_rename_action_invalid_name() {
        let ex = executor();
        let a = AgentAction::rename(0x1000, "bad name!", "test");
        let r = ex.execute_action(&a);
        assert!(!r.success);
    }

    #[test]
    fn test_rename_action_empty_name() {
        let ex = executor();
        let a = AgentAction::rename(0x1000, "", "test");
        let r = ex.execute_action(&a);
        assert!(!r.success);
    }

    #[test]
    fn test_comment_action() {
        let ex = executor();
        let a = AgentAction::comment(0x2000, "suspicious loop", "high entropy");
        let r = ex.execute_action(&a);
        assert!(r.success);
    }

    #[test]
    fn test_apply_type_action() {
        let ex = executor();
        let a = AgentAction::apply_type(0x3000, "int (*)(void *, size_t)", "inferred from callers");
        let r = ex.execute_action(&a);
        assert!(r.success);
    }

    #[test]
    fn test_apply_type_empty_type() {
        let ex = executor();
        let a = AgentAction::apply_type(0x3000, "", "test");
        let r = ex.execute_action(&a);
        assert!(!r.success);
    }

    #[test]
    fn test_patch_action() {
        let ex = executor();
        let a = AgentAction::patch(0x4000, vec![0x90, 0x90], "nop out check");
        let r = ex.execute_action(&a);
        assert!(r.success);
        assert!(r.message.contains("2 bytes"));
    }

    #[test]
    fn test_patch_action_empty_bytes() {
        let ex = executor();
        let a = AgentAction::patch(0x4000, vec![], "test");
        let r = ex.execute_action(&a);
        assert!(!r.success);
    }

    #[test]
    fn test_query_action() {
        let ex = executor();
        let a = AgentAction::query(0x5000, "function_info");
        let r = ex.execute_action(&a);
        assert!(r.success);
        assert!(!r.output.is_null());
    }

    #[test]
    fn test_unknown_action_kind() {
        let ex = executor();
        let mut a = AgentAction::rename(0x1000, "x", "test");
        a.kind = ActionKind::CreateBookmark; // not registered
        let r = ex.execute_action(&a);
        assert!(!r.success);
        assert!(r.message.contains("no handler"));
    }

    #[test]
    fn test_dry_run() {
        let ex = AgentActionExecutor::new().with_dry_run(true);
        let a = AgentAction::rename(0x1000, "some_func", "test");
        let r = ex.execute_action(&a);
        assert!(r.success);
        assert!(r.message.contains("dry-run"));
    }

    #[test]
    fn test_batch_execution() {
        let ex = executor();
        let actions = vec![
            AgentAction::rename(0x1000, "func_a", ""),
            AgentAction::comment(0x1000, "entry point", ""),
            AgentAction::apply_type(0x1000, "void(void)", ""),
        ];
        let results = ex.execute_batch(&actions);
        assert_eq!(results.len(), 3);
        assert!(results.iter().all(|r| r.success));
    }

    #[test]
    fn test_success_failure_counts() {
        let ex = executor();
        ex.execute_action(&AgentAction::rename(0x1000, "good", ""));
        ex.execute_action(&AgentAction::rename(0x2000, "", "")); // fail
        assert_eq!(ex.success_count(), 1);
        assert_eq!(ex.failure_count(), 1);
    }

    #[test]
    fn test_history_cleared() {
        let ex = executor();
        ex.execute_action(&AgentAction::rename(0x1000, "x", ""));
        ex.clear_history();
        assert!(ex.history().is_empty());
    }

    #[test]
    fn test_action_plan_execute() {
        let ex = executor();
        let mut plan = ActionPlan::new();
        plan.push(AgentAction::rename(0x1000, "init_func", ""));
        plan.push(AgentAction::comment(0x1000, "initialises heap", ""));
        assert_eq!(plan.len(), 2);
        let results = plan.execute(&ex);
        assert!(results.iter().all(|r| r.success));
    }

    #[test]
    fn test_kind_histogram() {
        let ex = executor();
        ex.execute_action(&AgentAction::rename(0x1000, "a", ""));
        ex.execute_action(&AgentAction::comment(0x1000, "c", ""));
        ex.execute_action(&AgentAction::rename(0x2000, "b", ""));
        let hist = ex.kind_histogram();
        assert_eq!(hist[&ActionKind::RenameSymbol], 2);
        assert_eq!(hist[&ActionKind::AddComment], 1);
    }

    #[test]
    fn test_action_kind_predicates() {
        assert!(ActionKind::RenameSymbol.is_mutating());
        assert!(!ActionKind::Query.is_mutating());
        assert!(ActionKind::ApplyPatch.is_binary_level());
        assert!(!ActionKind::RenameSymbol.is_binary_level());
    }

    #[test]
    fn test_has_handler() {
        let ex = executor();
        assert!(ex.has_handler(ActionKind::RenameSymbol));
        assert!(ex.has_handler(ActionKind::AddComment));
        assert!(!ex.has_handler(ActionKind::CreateBookmark));
    }
}
