//! `emu_interrupt_controller` — Interrupt controller model for `rustre-emu`.
//!
//! Provides [`EmuInterruptController`], a generic programmable interrupt controller
//! (PIC) that models IRQ lines, priority arbitration, masking, enabling/disabling,
//! and acknowledgment.  Modelled loosely on the Intel 8259 PIC and ARM GIC.

use std::collections::{BTreeMap, VecDeque};

// ─────────────────────────────────────────────────────────────────────────────
// InterruptState
// ─────────────────────────────────────────────────────────────────────────────

/// State of a single interrupt line.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum InterruptState {
    /// The line is inactive (not asserted).
    Inactive,
    /// The line has been asserted and is pending (not yet acknowledged).
    Pending,
    /// The line has been acknowledged by the CPU and is being serviced.
    Active,
    /// The line has been masked by software and will not be forwarded.
    Masked,
}

impl std::fmt::Display for InterruptState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Inactive => "Inactive",
            Self::Pending => "Pending",
            Self::Active => "Active",
            Self::Masked => "Masked",
        };
        f.write_str(s)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// InterruptTrigger
// ─────────────────────────────────────────────────────────────────────────────

/// How an interrupt line is triggered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InterruptTrigger {
    /// Fires while the line is held high (level-triggered).
    Level,
    /// Fires on a rising edge (edge-triggered).
    Edge,
}

// ─────────────────────────────────────────────────────────────────────────────
// InterruptLine
// ─────────────────────────────────────────────────────────────────────────────

/// A single interrupt line managed by the controller.
#[derive(Debug, Clone)]
pub struct InterruptLine {
    /// IRQ number (0-based).
    pub irq: u32,
    /// Human-readable name (e.g. `"UART0"`, `"Timer1"`).
    pub name: String,
    /// Priority level (lower value = higher priority).
    pub priority: u32,
    /// Current state.
    pub state: InterruptState,
    /// Trigger mode.
    pub trigger: InterruptTrigger,
    /// Number of times this IRQ has been raised.
    pub raise_count: u64,
    /// Number of times this IRQ has been acknowledged.
    pub ack_count: u64,
    /// Physical level of the interrupt line (true = asserted).
    pub line_level: bool,
}

impl InterruptLine {
    /// Construct a new line in the `Inactive` state.
    #[must_use]
    pub fn new(irq: u32, name: impl Into<String>, priority: u32, trigger: InterruptTrigger) -> Self {
        Self {
            irq,
            name: name.into(),
            priority,
            state: InterruptState::Inactive,
            trigger,
            raise_count: 0,
            ack_count: 0,
            line_level: false,
        }
    }

    /// Return `true` if this line needs CPU attention.
    #[must_use]
    pub const fn needs_service(&self) -> bool {
        matches!(self.state, InterruptState::Pending)
    }

    /// Return `true` if the line is currently masked.
    #[must_use]
    pub const fn is_masked(&self) -> bool {
        matches!(self.state, InterruptState::Masked)
    }
}

impl std::fmt::Display for InterruptLine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "IRQ#{} ({}) prio={} state={}",
            self.irq, self.name, self.priority, self.state
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// IrqEvent
// ─────────────────────────────────────────────────────────────────────────────

/// A logged event in the interrupt controller's history.
#[derive(Debug, Clone)]
pub struct IrqEvent {
    /// Which IRQ triggered the event.
    pub irq: u32,
    /// What kind of event this was.
    pub kind: IrqEventKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IrqEventKind {
    /// The IRQ was raised.
    Raised,
    /// The IRQ was acknowledged by the CPU.
    Acknowledged,
    /// The IRQ was masked.
    Masked,
    /// The IRQ was unmasked.
    Unmasked,
    /// The IRQ was cleared (deasserted).
    Cleared,
}

impl std::fmt::Display for IrqEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "IrqEvent {{ irq={}, kind={:?} }}", self.irq, self.kind)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// EmuInterruptController
// ─────────────────────────────────────────────────────────────────────────────

/// A programmable interrupt controller (PIC) for emulation.
///
/// Supports:
/// * Up to 256 IRQ lines with individual priority and trigger-mode settings.
/// * Global interrupt enable / disable (CPU IF flag equivalent).
/// * Priority threshold: IRQs with priority ≥ threshold are suppressed.
/// * Edge vs. level triggering.
/// * Acknowledgment and end-of-interrupt (EOI) flow.
/// * Event log for debugging.
pub struct EmuInterruptController {
    /// Interrupt lines, keyed by IRQ number.
    lines: BTreeMap<u32, InterruptLine>,
    /// Global interrupt enable flag.
    global_enable: bool,
    /// Priority threshold — IRQs with priority ≥ this value are suppressed.
    priority_threshold: u32,
    /// Queue of pending IRQs (ordered by priority, then IRQ number).
    pending_queue: VecDeque<u32>,
    /// History of interrupt events.
    event_log: Vec<IrqEvent>,
    /// Maximum number of events kept in the log.
    log_capacity: usize,
    /// Total raises since reset.
    total_raises: u64,
    /// Total acknowledgments since reset.
    total_acks: u64,
}

impl EmuInterruptController {
    /// Create a controller with no lines registered and interrupts globally enabled.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            lines: BTreeMap::new(),
            global_enable: true,
            priority_threshold: u32::MAX,
            pending_queue: VecDeque::new(),
            event_log: Vec::new(),
            log_capacity: 1024,
            total_raises: 0,
            total_acks: 0,
        }
    }

    /// Set the event-log capacity.
    pub const fn set_log_capacity(&mut self, cap: usize) {
        self.log_capacity = cap;
    }

    // ── Line registration ────────────────────────────────────────────────────

    /// Register a new interrupt line.
    ///
    /// # Panics
    /// Panics if the IRQ number is already registered.
    pub fn register_line(
        &mut self,
        irq: u32,
        name: impl Into<String>,
        priority: u32,
        trigger: InterruptTrigger,
    ) {
        assert!(
            !self.lines.contains_key(&irq),
            "IRQ {irq} already registered"
        );
        self.lines
            .insert(irq, InterruptLine::new(irq, name, priority, trigger));
    }

    /// Convenience: register multiple lines from a slice of `(irq, name, priority)`.
    ///
    /// All lines default to edge-triggered.
    pub fn register_lines(&mut self, specs: &[(u32, &str, u32)]) {
        for &(irq, name, priority) in specs {
            self.register_line(irq, name, priority, InterruptTrigger::Edge);
        }
    }

    // ── Global control ───────────────────────────────────────────────────────

    /// Enable global interrupt delivery (equivalent to CPU `STI`).
    pub const fn global_enable(&mut self) {
        self.global_enable = true;
    }

    /// Disable global interrupt delivery (equivalent to CPU `CLI`).
    pub const fn global_disable(&mut self) {
        self.global_enable = false;
    }

    /// Return `true` if global interrupts are enabled.
    #[must_use]
    pub const fn is_globally_enabled(&self) -> bool {
        self.global_enable
    }

    /// Set the priority threshold.  IRQs with `priority >= threshold` are suppressed.
    pub const fn set_priority_threshold(&mut self, threshold: u32) {
        self.priority_threshold = threshold;
    }

    // ── IRQ operations ────────────────────────────────────────────────────────

    /// Assert (raise) IRQ `irq`.
    ///
    /// For level-triggered lines: sets the line level and moves to `Pending`.
    /// For edge-triggered lines: generates a one-shot `Pending` state.
    ///
    /// Does nothing if the IRQ is masked or not registered.
    ///
    /// # Errors
    /// Returns `None` if `irq` is not registered.
    pub fn raise_irq(&mut self, irq: u32) -> bool {
        let Some(line) = self.lines.get_mut(&irq) else {
            return false;
        };
        if matches!(line.state, InterruptState::Masked) {
            return false;
        }
        line.line_level = true;
        line.raise_count += 1;
        if line.state != InterruptState::Active {
            line.state = InterruptState::Pending;
        }
        self.total_raises += 1;
        self.log_event(IrqEvent { irq, kind: IrqEventKind::Raised });
        if !self.pending_queue.contains(&irq) {
            self.pending_queue.push_back(irq);
        }
        true
    }

    /// Deassert (clear) an IRQ line.
    ///
    /// Only relevant for level-triggered lines.
    pub fn clear_irq(&mut self, irq: u32) -> bool {
        let Some(line) = self.lines.get_mut(&irq) else {
            return false;
        };
        line.line_level = false;
        if matches!(line.state, InterruptState::Pending) {
            line.state = InterruptState::Inactive;
            self.pending_queue.retain(|&q| q != irq);
        }
        self.log_event(IrqEvent { irq, kind: IrqEventKind::Cleared });
        true
    }

    /// Mask IRQ `irq` (prevent it from becoming `Pending`).
    pub fn mask_irq(&mut self, irq: u32) -> bool {
        if let Some(line) = self.lines.get_mut(&irq) {
            if !matches!(line.state, InterruptState::Active) {
                line.state = InterruptState::Masked;
            }
            self.pending_queue.retain(|&q| q != irq);
            self.log_event(IrqEvent { irq, kind: IrqEventKind::Masked });
            true
        } else {
            false
        }
    }

    /// Unmask IRQ `irq`.
    ///
    /// If the physical line is still asserted (level-triggered), the IRQ moves
    /// back to `Pending`.
    pub fn unmask_irq(&mut self, irq: u32) -> bool {
        if let Some(line) = self.lines.get_mut(&irq) {
            if matches!(line.state, InterruptState::Masked) {
                if line.line_level && line.trigger == InterruptTrigger::Level {
                    line.state = InterruptState::Pending;
                    if !self.pending_queue.contains(&irq) {
                        self.pending_queue.push_back(irq);
                    }
                } else {
                    line.state = InterruptState::Inactive;
                }
            }
            self.log_event(IrqEvent { irq, kind: IrqEventKind::Unmasked });
            true
        } else {
            false
        }
    }

    // ── Interrupt delivery ────────────────────────────────────────────────────

    /// Check whether an interrupt should be delivered to the CPU.
    ///
    /// Returns the highest-priority pending IRQ that passes the global-enable
    /// and priority-threshold checks, or `None` if no such IRQ exists.
    #[must_use]
    pub fn next_pending(&self) -> Option<u32> {
        if !self.global_enable {
            return None;
        }
        // Find the highest-priority (lowest priority number) pending IRQ.
        self.pending_queue
            .iter()
            .filter_map(|&irq| {
                let line = self.lines.get(&irq)?;
                if matches!(line.state, InterruptState::Pending)
                    && line.priority < self.priority_threshold
                {
                    Some((irq, line.priority))
                } else {
                    None
                }
            })
            .min_by_key(|(irq, prio)| (*prio, *irq))
            .map(|(irq, _)| irq)
    }

    /// Acknowledge the IRQ — transitions it from `Pending` to `Active`.
    ///
    /// Returns `true` on success.
    pub fn acknowledge(&mut self, irq: u32) -> bool {
        if let Some(line) = self.lines.get_mut(&irq)
            && matches!(line.state, InterruptState::Pending) {
                line.state = InterruptState::Active;
                line.ack_count += 1;
                self.total_acks += 1;
                self.pending_queue.retain(|&q| q != irq);
                self.log_event(IrqEvent { irq, kind: IrqEventKind::Acknowledged });
                return true;
            }
        false
    }

    /// Send End-of-Interrupt (EOI) for IRQ `irq`.
    ///
    /// Moves the line from `Active` back to `Inactive` (or `Pending` again for
    /// level-triggered lines that are still asserted).
    pub fn eoi(&mut self, irq: u32) -> bool {
        if let Some(line) = self.lines.get_mut(&irq)
            && matches!(line.state, InterruptState::Active) {
                if line.trigger == InterruptTrigger::Level && line.line_level {
                    // Re-assert the pending state for level-triggered lines.
                    line.state = InterruptState::Pending;
                    if !self.pending_queue.contains(&irq) {
                        self.pending_queue.push_back(irq);
                    }
                } else {
                    line.state = InterruptState::Inactive;
                }
                return true;
            }
        false
    }

    // ── Query ─────────────────────────────────────────────────────────────────

    /// Return the state of IRQ `irq`.
    #[must_use]
    pub fn state_of(&self, irq: u32) -> Option<InterruptState> {
        self.lines.get(&irq).map(|l| l.state)
    }

    /// Return all IRQ lines currently in the `Pending` state.
    #[must_use]
    pub fn all_pending(&self) -> Vec<&InterruptLine> {
        self.lines
            .values()
            .filter(|l| matches!(l.state, InterruptState::Pending))
            .collect()
    }

    /// Return all registered interrupt lines.
    #[must_use]
    pub fn all_lines(&self) -> Vec<&InterruptLine> {
        self.lines.values().collect()
    }

    /// Return `true` if any IRQ is pending.
    #[must_use]
    pub fn any_pending(&self) -> bool {
        self.next_pending().is_some()
    }

    /// Number of registered IRQ lines.
    #[must_use]
    pub fn line_count(&self) -> usize {
        self.lines.len()
    }

    /// Reset all lines to `Inactive`.
    pub fn reset(&mut self) {
        for line in self.lines.values_mut() {
            line.state = InterruptState::Inactive;
            line.line_level = false;
        }
        self.pending_queue.clear();
    }

    /// Return the event log.
    #[must_use]
    pub fn event_log(&self) -> &[IrqEvent] {
        &self.event_log
    }

    /// Total raises since last reset.
    #[must_use]
    pub const fn total_raises(&self) -> u64 {
        self.total_raises
    }

    /// Total acknowledgments since last reset.
    #[must_use]
    pub const fn total_acks(&self) -> u64 {
        self.total_acks
    }

    fn log_event(&mut self, event: IrqEvent) {
        if self.event_log.len() >= self.log_capacity {
            self.event_log.remove(0);
        }
        self.event_log.push(event);
    }
}

impl Default for EmuInterruptController {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for EmuInterruptController {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EmuInterruptController")
            .field("lines", &self.lines.len())
            .field("global_enable", &self.global_enable)
            .field("pending", &self.pending_queue.len())
            .finish_non_exhaustive()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_pic() -> EmuInterruptController {
        let mut pic = EmuInterruptController::new();
        pic.register_line(0, "Timer", 0, InterruptTrigger::Edge);
        pic.register_line(1, "UART", 1, InterruptTrigger::Edge);
        pic.register_line(2, "GPIO", 2, InterruptTrigger::Level);
        pic
    }

    #[test]
    fn test_line_count() {
        let pic = make_pic();
        assert_eq!(pic.line_count(), 3);
    }

    #[test]
    fn test_raise_irq_makes_pending() {
        let mut pic = make_pic();
        assert!(pic.raise_irq(0));
        assert_eq!(pic.state_of(0), Some(InterruptState::Pending));
    }

    #[test]
    fn test_raise_unknown_irq_returns_false() {
        let mut pic = make_pic();
        assert!(!pic.raise_irq(99));
    }

    #[test]
    fn test_next_pending_highest_priority() {
        let mut pic = make_pic();
        pic.raise_irq(2); // prio=2
        pic.raise_irq(0); // prio=0 (highest)
        pic.raise_irq(1); // prio=1
        assert_eq!(pic.next_pending(), Some(0));
    }

    #[test]
    fn test_acknowledge_moves_to_active() {
        let mut pic = make_pic();
        pic.raise_irq(1);
        assert!(pic.acknowledge(1));
        assert_eq!(pic.state_of(1), Some(InterruptState::Active));
    }

    #[test]
    fn test_eoi_moves_to_inactive() {
        let mut pic = make_pic();
        pic.raise_irq(1);
        pic.acknowledge(1);
        pic.eoi(1);
        assert_eq!(pic.state_of(1), Some(InterruptState::Inactive));
    }

    #[test]
    fn test_mask_suppresses_pending() {
        let mut pic = make_pic();
        pic.mask_irq(0);
        assert!(!pic.raise_irq(0));
        assert_eq!(pic.state_of(0), Some(InterruptState::Masked));
        assert_eq!(pic.next_pending(), None);
    }

    #[test]
    fn test_unmask_restores_inactive() {
        let mut pic = make_pic();
        pic.mask_irq(1);
        pic.unmask_irq(1);
        assert_eq!(pic.state_of(1), Some(InterruptState::Inactive));
    }

    #[test]
    fn test_global_disable_hides_pending() {
        let mut pic = make_pic();
        pic.raise_irq(0);
        pic.global_disable();
        assert_eq!(pic.next_pending(), None);
        pic.global_enable();
        assert_eq!(pic.next_pending(), Some(0));
    }

    #[test]
    fn test_priority_threshold() {
        let mut pic = make_pic();
        pic.raise_irq(0); // prio=0
        pic.raise_irq(2); // prio=2
        // Suppress anything with priority >= 1
        pic.set_priority_threshold(1);
        // Only irq 0 (prio=0) should pass
        assert_eq!(pic.next_pending(), Some(0));
    }

    #[test]
    fn test_all_pending() {
        let mut pic = make_pic();
        pic.raise_irq(0);
        pic.raise_irq(2);
        let pending = pic.all_pending();
        assert_eq!(pending.len(), 2);
    }

    #[test]
    fn test_any_pending() {
        let mut pic = make_pic();
        assert!(!pic.any_pending());
        pic.raise_irq(1);
        assert!(pic.any_pending());
    }

    #[test]
    fn test_reset_clears_all() {
        let mut pic = make_pic();
        pic.raise_irq(0);
        pic.raise_irq(1);
        pic.reset();
        assert!(!pic.any_pending());
    }

    #[test]
    fn test_total_raises_and_acks() {
        let mut pic = make_pic();
        pic.raise_irq(0);
        pic.raise_irq(1);
        assert_eq!(pic.total_raises(), 2);
        pic.acknowledge(0);
        assert_eq!(pic.total_acks(), 1);
    }

    #[test]
    fn test_event_log() {
        let mut pic = make_pic();
        pic.raise_irq(0);
        pic.acknowledge(0);
        let log = pic.event_log();
        assert!(log.iter().any(|e| e.kind == IrqEventKind::Raised));
        assert!(log.iter().any(|e| e.kind == IrqEventKind::Acknowledged));
    }

    #[test]
    fn test_level_triggered_re_asserts_on_eoi() {
        let mut pic = make_pic();
        // GPIO is level-triggered at line 2
        pic.raise_irq(2); // line_level=true
        pic.acknowledge(2);
        pic.eoi(2);
        // Because line is still asserted, should go back to Pending
        assert_eq!(pic.state_of(2), Some(InterruptState::Pending));
    }

    #[test]
    fn test_clear_irq_level() {
        let mut pic = make_pic();
        pic.raise_irq(2);
        pic.clear_irq(2);
        assert_eq!(pic.state_of(2), Some(InterruptState::Inactive));
        assert_eq!(pic.next_pending(), None);
    }

    #[test]
    fn test_interrupt_line_display() {
        let l = InterruptLine::new(5, "USB", 3, InterruptTrigger::Edge);
        let s = l.to_string();
        assert!(s.contains("IRQ#5"));
        assert!(s.contains("USB"));
    }

    #[test]
    fn test_interrupt_state_display() {
        assert_eq!(InterruptState::Pending.to_string(), "Pending");
    }

    #[test]
    fn test_pic_debug() {
        let pic = make_pic();
        let s = format!("{pic:?}");
        assert!(s.contains("EmuInterruptController"));
    }

    #[test]
    fn test_register_lines_bulk() {
        let mut pic = EmuInterruptController::new();
        pic.register_lines(&[(0, "A", 0), (1, "B", 1), (2, "C", 2)]);
        assert_eq!(pic.line_count(), 3);
    }
}
