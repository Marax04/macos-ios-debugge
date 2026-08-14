//! Step-by-step navigation over an execution trace.
//!
//! Implements `step_forward`, `step_backward`, `step_over`, `step_out`, `run_to_address`
//! with async cancel support via `CancellationToken`.

use std::collections::HashSet;
use std::sync::Arc;
use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use tokio::sync::{watch, Mutex};
use tokio_util::sync::CancellationToken;

use crate::{Address, NavError};

// ─── Trace Provider Trait ─────────────────────────────────────────────────────

/// Minimal interface that the step navigator requires from a trace backend.
#[async_trait::async_trait]
pub trait TraceProvider: Send + Sync {
    /// Total number of instructions in the trace.
    async fn len(&self) -> u64;

    /// Whether the trace is empty.
    async fn is_empty(&self) -> bool {
        self.len().await == 0
    }

    /// Instruction pointer at trace index `pos`.
    async fn ip_at(&self, pos: u64) -> Result<Address>;

    /// Is the instruction at `pos` a CALL instruction?
    async fn is_call(&self, pos: u64) -> Result<bool>;

    /// Is the instruction at `pos` a RET instruction?
    async fn is_ret(&self, pos: u64) -> Result<bool>;

    /// Call depth at `pos` (0 = outermost frame).
    async fn call_depth_at(&self, pos: u64) -> Result<u32>;
}

// ─── NavigatorState ──────────────────────────────────────────────────────────

/// Current position and metadata of the navigator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NavigatorState {
    /// Current position (instruction index).
    pub position: u64,
    /// Instruction pointer value.
    pub ip: Address,
    /// Call depth at current position.
    pub call_depth: u32,
    /// Whether we are at the first instruction.
    pub at_start: bool,
    /// Whether we are at the last instruction.
    pub at_end: bool,
}

// ─── StepResult ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StepResult {
    /// Moved to a new position.
    Moved(NavigatorState),
    /// Already at start/end, cannot move further.
    AtBoundary { at_start: bool },
    /// The trace contains no instructions.
    EmptyTrace,
    /// Cancelled by the caller.
    Cancelled,
    /// Hit a breakpoint while running.
    Breakpoint { state: NavigatorState },
}

// ─── Breakpoint set ──────────────────────────────────────────────────────────

#[derive(Default, Clone)]
pub struct BreakpointSet {
    addresses: HashSet<Address>,
}

impl BreakpointSet {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(&mut self, addr: Address) {
        self.addresses.insert(addr);
    }

    pub fn remove(&mut self, addr: Address) {
        self.addresses.remove(&addr);
    }

    #[must_use]
    pub fn contains(&self, addr: Address) -> bool {
        self.addresses.contains(&addr)
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.addresses.is_empty()
    }
}

// ─── StepNavigator ───────────────────────────────────────────────────────────

/// Configuration for the step navigator.
#[derive(Debug, Clone)]
pub struct StepNavigatorConfig {
    /// Maximum instructions to scan in `step_over` / `step_out` before giving up.
    pub max_scan_steps: u64,
    /// Polling interval for cancellation checks during long runs.
    pub cancel_check_interval: u64,
}

impl Default for StepNavigatorConfig {
    fn default() -> Self {
        Self { max_scan_steps: 10_000_000, cancel_check_interval: 10_000 }
    }
}

/// Step-by-step navigator over an execution trace.
pub struct StepNavigator {
    provider: Arc<dyn TraceProvider>,
    position: Arc<Mutex<u64>>,
    breakpoints: Arc<Mutex<BreakpointSet>>,
    config: StepNavigatorConfig,
    /// Broadcast channel for position updates.
    state_tx: watch::Sender<Option<NavigatorState>>,
    pub state_rx: watch::Receiver<Option<NavigatorState>>,
}

impl StepNavigator {
    pub fn new(provider: Arc<dyn TraceProvider>, config: StepNavigatorConfig) -> Self {
        let (tx, rx) = watch::channel(None);
        Self {
            provider,
            position: Arc::new(Mutex::new(0)),
            breakpoints: Arc::new(Mutex::new(BreakpointSet::new())),
            config,
            state_tx: tx,
            state_rx: rx,
        }
    }

    /// Read current position (no lock hold).
    pub async fn position(&self) -> u64 {
        *self.position.lock().await
    }

    /// Build `NavigatorState` for an arbitrary position.
    async fn state_at(&self, pos: u64) -> Result<NavigatorState> {
        let total = self.provider.len().await;
        let ip = self.provider.ip_at(pos).await?;
        let call_depth = self.provider.call_depth_at(pos).await?;
        Ok(NavigatorState {
            position: pos,
            ip,
            call_depth,
            at_start: pos == 0,
            at_end: total == 0 || pos >= total - 1,
        })
    }

    async fn set_position(&self, pos: u64) -> Result<NavigatorState> {
        *self.position.lock().await = pos;
        let s = self.state_at(pos).await?;
        let _ = self.state_tx.send(Some(s.clone()));
        Ok(s)
    }

    /// Add a breakpoint.
    pub async fn add_breakpoint(&self, addr: Address) {
        self.breakpoints.lock().await.add(addr);
    }

    /// Remove a breakpoint.
    pub async fn remove_breakpoint(&self, addr: Address) {
        self.breakpoints.lock().await.remove(addr);
    }

    // ─── Step Forward ─────────────────────────────────────────────────────

    /// Move one instruction forward.
    /// # Errors
    /// Returns an error if the operation fails.
    pub async fn step_forward(&self) -> Result<StepResult> {
        let total = self.provider.len().await;
        if total == 0 {
            return Ok(StepResult::EmptyTrace);
        }
        let pos = self.position().await;
        if pos + 1 >= total {
            return Ok(StepResult::AtBoundary { at_start: false });
        }
        let s = self.set_position(pos + 1).await?;
        Ok(StepResult::Moved(s))
    }

    // ─── Step Backward ────────────────────────────────────────────────────

    /// Move one instruction backward.
    /// # Errors
    /// Returns an error if the operation fails.
    pub async fn step_backward(&self) -> Result<StepResult> {
        let pos = self.position().await;
        if pos == 0 {
            return Ok(StepResult::AtBoundary { at_start: true });
        }
        let s = self.set_position(pos - 1).await?;
        Ok(StepResult::Moved(s))
    }

    // ─── Step Over ────────────────────────────────────────────────────────

    /// Step over: if current instruction is a CALL, skip until call returns.
    /// Otherwise behaves like `step_forward`.
    /// # Errors
    /// Returns an error if the operation fails.
    pub async fn step_over(&self, cancel: CancellationToken) -> Result<StepResult> {
        let total = self.provider.len().await;
        if total == 0 {
            return Ok(StepResult::EmptyTrace);
        }
        let pos = self.position().await;

        if pos + 1 >= total {
            return Ok(StepResult::AtBoundary { at_start: false });
        }

        if !self.provider.is_call(pos).await? {
            return self.step_forward().await;
        }

        // Current instruction is a CALL. Record depth and scan forward.
        let target_depth = self.provider.call_depth_at(pos).await?;
        let bp = self.breakpoints.lock().await.clone();

        let mut cur = pos + 1;
        let mut scanned = 0u64;
        loop {
            if cancel.is_cancelled() {
                return Ok(StepResult::Cancelled);
            }
            if cur >= total {
                // Trace ended without a matching return — go to end.
                let s = self.set_position(total - 1).await?;
                return Ok(StepResult::Moved(s));
            }
            let depth = self.provider.call_depth_at(cur).await?;
            let ip = self.provider.ip_at(cur).await?;

            if bp.contains(ip) {
                let s = self.set_position(cur).await?;
                return Ok(StepResult::Breakpoint { state: s });
            }

            if depth <= target_depth {
                let s = self.set_position(cur).await?;
                return Ok(StepResult::Moved(s));
            }

            cur += 1;
            scanned += 1;
            if scanned > self.config.max_scan_steps {
                return Err(anyhow!("step_over exceeded max scan steps"));
            }
            if scanned.is_multiple_of(self.config.cancel_check_interval) {
                tokio::task::yield_now().await;
            }
        }
    }

    // ─── Step Out ─────────────────────────────────────────────────────────

    /// Step out: run forward until the call depth decreases below current depth.
    /// # Errors
    /// Returns an error if the operation fails.
    pub async fn step_out(&self, cancel: CancellationToken) -> Result<StepResult> {
        let total = self.provider.len().await;
        if total == 0 {
            return Ok(StepResult::EmptyTrace);
        }
        let pos = self.position().await;

        if pos + 1 >= total {
            return Ok(StepResult::AtBoundary { at_start: false });
        }

        let current_depth = self.provider.call_depth_at(pos).await?;
        if current_depth == 0 {
            return Err(anyhow!("already at outermost call frame"));
        }

        let bp = self.breakpoints.lock().await.clone();
        let mut cur = pos + 1;
        let mut scanned = 0u64;

        loop {
            if cancel.is_cancelled() {
                return Ok(StepResult::Cancelled);
            }
            if cur >= total {
                let s = self.set_position(total - 1).await?;
                return Ok(StepResult::Moved(s));
            }
            let depth = self.provider.call_depth_at(cur).await?;
            let ip = self.provider.ip_at(cur).await?;

            if bp.contains(ip) {
                let s = self.set_position(cur).await?;
                return Ok(StepResult::Breakpoint { state: s });
            }

            if depth < current_depth {
                let s = self.set_position(cur).await?;
                return Ok(StepResult::Moved(s));
            }

            cur += 1;
            scanned += 1;
            if scanned > self.config.max_scan_steps {
                return Err(anyhow!("step_out exceeded max scan steps"));
            }
            if scanned.is_multiple_of(self.config.cancel_check_interval) {
                tokio::task::yield_now().await;
            }
        }
    }

    // ─── Run To Address ───────────────────────────────────────────────────

    /// Run forward until `ip == target`, or a breakpoint, or cancelled.
    /// # Errors
    /// Returns an error if the operation fails.
    pub async fn run_to_address(
        &self,
        target: Address,
        cancel: CancellationToken,
    ) -> Result<StepResult> {
        let total = self.provider.len().await;
        let start = self.position().await + 1;
        let bp = self.breakpoints.lock().await.clone();

        let mut cur = start;
        let mut scanned = 0u64;

        loop {
            if cancel.is_cancelled() {
                return Ok(StepResult::Cancelled);
            }
            if cur >= total {
                return Ok(StepResult::AtBoundary { at_start: false });
            }
            let ip = self.provider.ip_at(cur).await?;
            if ip == target {
                let s = self.set_position(cur).await?;
                return Ok(StepResult::Moved(s));
            }
            if bp.contains(ip) {
                let s = self.set_position(cur).await?;
                return Ok(StepResult::Breakpoint { state: s });
            }
            cur += 1;
            scanned += 1;
            if scanned > self.config.max_scan_steps {
                return Err(anyhow!("run_to_address exceeded max scan steps"));
            }
            if scanned.is_multiple_of(self.config.cancel_check_interval) {
                tokio::task::yield_now().await;
            }
        }
    }

    // ─── Reverse Run To Address ───────────────────────────────────────────

    /// Run backward until `ip == target`, or a breakpoint, or cancelled.
    /// # Errors
    /// Returns an error if the operation fails.
    pub async fn reverse_run_to_address(
        &self,
        target: Address,
        cancel: CancellationToken,
    ) -> Result<StepResult> {
        let start = self.position().await;
        if start == 0 {
            return Ok(StepResult::AtBoundary { at_start: true });
        }
        let bp = self.breakpoints.lock().await.clone();
        let mut cur = start - 1;
        let mut scanned = 0u64;

        loop {
            if cancel.is_cancelled() {
                return Ok(StepResult::Cancelled);
            }
            let ip = self.provider.ip_at(cur).await?;
            if ip == target {
                let s = self.set_position(cur).await?;
                return Ok(StepResult::Moved(s));
            }
            if bp.contains(ip) {
                let s = self.set_position(cur).await?;
                return Ok(StepResult::Breakpoint { state: s });
            }
            if cur == 0 {
                return Ok(StepResult::AtBoundary { at_start: true });
            }
            cur -= 1;
            scanned += 1;
            if scanned > self.config.max_scan_steps {
                return Err(anyhow!("reverse_run_to_address exceeded max scan steps"));
            }
            if scanned.is_multiple_of(self.config.cancel_check_interval) {
                tokio::task::yield_now().await;
            }
        }
    }

    // ─── Jump ─────────────────────────────────────────────────────────────

    /// Jump directly to a trace position.
    /// # Errors
    /// Returns an error if the operation fails.
    pub async fn jump_to(&self, pos: u64) -> Result<NavigatorState> {
        let total = self.provider.len().await;
        if total == 0 {
            return Err(NavError::Empty.into());
        }
        let pos = pos.min(total - 1);
        self.set_position(pos).await
    }

    /// Jump to time percentage (0.0 = start, 1.0 = end).
    /// # Errors
    /// Returns an error if the operation fails.
    pub async fn jump_to_percent(&self, pct: f64) -> Result<NavigatorState> {
        let total = self.provider.len().await;
        if total == 0 {
            return Err(NavError::Empty.into());
        }
        let pct = pct.clamp(0.0, 1.0);
        let max32 = u32::try_from(total - 1).unwrap_or(u32::MAX);
        let pct = pct.clamp(0.0, 1.0);
        if pct <= 0.0 { return self.set_position(0).await; }
        if pct >= 1.0 { return self.set_position(u64::from(max32)).await; }
        // f64::from(max32) * pct ∈ (0, u32::MAX); extract via bit manipulation (no lossy cast)
        let pos = u64::from(f64_to_u32_floor((f64::from(max32) * pct).round()));
        self.set_position(pos).await
    }

    // ─── Current state ────────────────────────────────────────────────────

    /// Get current navigator state.
    /// # Errors
    /// Returns an error if the operation fails.
    pub async fn current_state(&self) -> Result<NavigatorState> {
        let pos = self.position().await;
        self.state_at(pos).await
    }

    /// Snapshot of breakpoints.
    pub async fn breakpoint_list(&self) -> Vec<Address> {
        self.breakpoints.lock().await.addresses.iter().copied().collect()
    }
}

// ─── Float-to-integer helpers ─────────────────────────────────────────────────

/// Convert a non-negative `f64` to `u32` by flooring, saturating at `u32::MAX`.
/// Avoids unsafe code and clippy cast lints by performing explicit bounds checks.
fn f64_to_u32_floor(val: f64) -> u32 {
    // 2^32 as f64 is exactly representable.
    const TWO_POW_32: f64 = 4_294_967_296.0_f64;
    let floored = val.floor();
    if floored.is_nan() || floored <= 0.0 {
        0u32
    } else if floored >= TWO_POW_32 {
        u32::MAX
    } else {
        // floored ∈ [0, 2^32) — non-negative and in-range; bounds verified above.
        #[expect(clippy::cast_sign_loss, clippy::cast_possible_truncation,
                 reason = "bounds verified: floored >= 0.0 and floored < 2^32")]
        { floored as u32 }
    }
}

// ─── In-memory trace provider for testing ────────────────────────────────────

/// Simple vec-backed trace provider for unit tests.
pub struct VecTraceProvider {
    /// (ip, `is_call`, `is_ret`, `call_depth`)
    instructions: Vec<(Address, bool, bool, u32)>,
}

impl VecTraceProvider {
    #[must_use]
    pub const fn new(instructions: Vec<(Address, bool, bool, u32)>) -> Self {
        Self { instructions }
    }

    /// Build from a flat list of addresses, auto-computing call/ret/depth from
    /// a very simple heuristic: CALL if next depth > current, RET if next depth < current.
    #[must_use]
    pub fn from_addresses(ips: &[Address]) -> Self {
        let n = ips.len();
        let mut instructions = Vec::with_capacity(n);
        // Assign fake depths by treating every 3rd instruction as CALL+1 depth.
        let mut depth = 0u32;
        for (i, &ip) in ips.iter().enumerate() {
            let is_call = i % 7 == 6 && depth < 10;
            let is_ret = i % 11 == 10 && depth > 0;
            instructions.push((ip, is_call, is_ret, depth));
            if is_call {
                depth += 1;
            } else if is_ret && depth > 0 {
                depth -= 1;
            }
        }
        Self { instructions }
    }
}

#[async_trait::async_trait]
impl TraceProvider for VecTraceProvider {
    async fn len(&self) -> u64 {
        self.instructions.len() as u64
    }

    async fn ip_at(&self, pos: u64) -> Result<Address> {
        self.instructions
            .get(usize::try_from(pos).unwrap_or(usize::MAX))
            .map(|(ip, _, _, _)| *ip)
            .ok_or_else(|| anyhow!("position {pos} out of bounds"))
    }

    async fn is_call(&self, pos: u64) -> Result<bool> {
        Ok(self.instructions.get(usize::try_from(pos).unwrap_or(usize::MAX)).is_some_and(|(_, c, _, _)| *c))
    }

    async fn is_ret(&self, pos: u64) -> Result<bool> {
        Ok(self.instructions.get(usize::try_from(pos).unwrap_or(usize::MAX)).is_some_and(|(_, _, r, _)| *r))
    }

    async fn call_depth_at(&self, pos: u64) -> Result<u32> {
        Ok(self.instructions.get(usize::try_from(pos).unwrap_or(usize::MAX)).map_or(0, |(_, _, _, d)| *d))
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_nav(ips: Vec<Address>) -> StepNavigator {
        let provider = Arc::new(VecTraceProvider::from_addresses(&ips));
        StepNavigator::new(provider, StepNavigatorConfig::default())
    }

    #[tokio::test]
    async fn test_step_forward_backward() {
        let nav = make_nav(vec![0x1000, 0x1004, 0x1008, 0x100C]);
        assert_eq!(nav.position().await, 0);

        match nav.step_forward().await.unwrap() {
            StepResult::Moved(s) => assert_eq!(s.position, 1),
            _ => panic!(),
        }
        match nav.step_backward().await.unwrap() {
            StepResult::Moved(s) => assert_eq!(s.position, 0),
            _ => panic!(),
        }
        match nav.step_backward().await.unwrap() {
            StepResult::AtBoundary { at_start } => assert!(at_start),
            _ => panic!(),
        }
    }

    #[tokio::test]
    async fn test_jump_to() {
        let nav = make_nav(vec![0x1000, 0x1004, 0x1008, 0x100C]);
        let s = nav.jump_to(3).await.unwrap();
        assert_eq!(s.position, 3);
        assert!(s.at_end);
    }

    #[tokio::test]
    async fn test_run_to_address() {
        let nav = make_nav(vec![0x1000, 0x1004, 0x1008, 0x100C, 0x1010]);
        let cancel = CancellationToken::new();
        match nav.run_to_address(0x100C, cancel).await.unwrap() {
            StepResult::Moved(s) => assert_eq!(s.ip, 0x100C),
            _ => panic!(),
        }
    }

    #[tokio::test]
    async fn test_run_to_address_cancel() {
        let nav = make_nav((0u64..100).map(|i| 0x1000 + i * 4).collect());
        let cancel = CancellationToken::new();
        cancel.cancel();
        match nav.run_to_address(0x9999, cancel).await.unwrap() {
            StepResult::Cancelled => {}
            _ => panic!("expected Cancelled"),
        }
    }

    #[tokio::test]
    async fn test_jump_to_percent() {
        let nav = make_nav(vec![0x1000, 0x1004, 0x1008, 0x100C]);
        let s = nav.jump_to_percent(1.0).await.unwrap();
        assert_eq!(s.position, 3);
        let s2 = nav.jump_to_percent(0.0).await.unwrap();
        assert_eq!(s2.position, 0);
    }
}
