//! `cpu_tester` — Comprehensive test harness for 6502 / 65C02 / 65816.
//!
//! Provides [`TestCase`], [`TestRunner`], [`FlagChecker`], [`CycleCounter`],
//! and [`TestReport`].  Contains 100+ built-in test cases covering every
//! addressing mode and flag combination.

use crate::{Cpu6502State, CpuVariant, execute_one, status};
use std::collections::HashMap;
use std::fmt;

// ── CpuState snapshot (alias into existing type) ──────────────────────────────

/// Expected or initial CPU state snapshot.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StateSnapshot {
    pub a: u8,
    pub x: u8,
    pub y: u8,
    pub sp: u8,
    pub pc: u16,
    pub p: u8,
}

impl StateSnapshot {
    /// Construct from the CPU state.
    #[must_use]
    pub const fn from_cpu(s: &Cpu6502State) -> Self {
        Self {
            a: s.a,
            x: s.x,
            y: s.y,
            sp: s.sp,
            pc: s.pc,
            p: s.p,
        }
    }

    /// Apply this snapshot to a CPU state.
    pub const fn apply_to(&self, s: &mut Cpu6502State) {
        s.a = self.a;
        s.x = self.x;
        s.y = self.y;
        s.sp = self.sp;
        s.pc = self.pc;
        s.p = self.p;
    }

    /// Builder: set A.
    #[must_use]
    pub const fn with_a(mut self, a: u8) -> Self {
        self.a = a;
        self
    }
    /// Builder: set X.
    #[must_use]
    pub const fn with_x(mut self, x: u8) -> Self {
        self.x = x;
        self
    }
    /// Builder: set Y.
    #[must_use]
    pub const fn with_y(mut self, y: u8) -> Self {
        self.y = y;
        self
    }
    /// Builder: set SP.
    #[must_use]
    pub const fn with_sp(mut self, sp: u8) -> Self {
        self.sp = sp;
        self
    }
    /// Builder: set PC.
    #[must_use]
    pub const fn with_pc(mut self, pc: u16) -> Self {
        self.pc = pc;
        self
    }
    /// Builder: set P.
    #[must_use]
    pub const fn with_p(mut self, p: u8) -> Self {
        self.p = p;
        self
    }
}

// ── Memory patch ─────────────────────────────────────────────────────────────

/// A single memory write to apply before running a test.
#[derive(Debug, Clone)]
pub struct MemPatch {
    pub address: u16,
    pub value: u8,
}

impl MemPatch {
    #[must_use]
    pub const fn new(address: u16, value: u8) -> Self {
        Self { address, value }
    }
}

// ── TestCase ─────────────────────────────────────────────────────────────────

/// A single CPU test case: initial state, program bytes, expected final state.
#[derive(Debug, Clone)]
pub struct TestCase {
    /// Human-readable name (mnemonic + addressing mode description).
    pub name: String,
    /// CPU variant this test targets.
    pub variant: CpuVariant,
    /// CPU state before execution.
    pub initial_state: StateSnapshot,
    /// Program bytes placed at `initial_state.pc`.
    pub program: Vec<u8>,
    /// Memory patches applied *before* execution (additional to program bytes).
    pub mem_patches: Vec<MemPatch>,
    /// Expected CPU state after execution.
    pub expected_state: StateSnapshot,
    /// Expected memory reads/writes keyed by address.
    pub expected_mem: HashMap<u16, u8>,
    /// Expected cycle count (-1 means "don't check").
    pub expected_cycles: i32,
    /// Whether this test is expected to produce an error (e.g. illegal opcode
    /// when illegal decoding is disabled).
    pub expect_error: bool,
}

impl TestCase {
    /// Construct a minimal test case.
    #[must_use] 
    pub fn new(name: &str, program: Vec<u8>) -> Self {
        Self {
            name: name.to_owned(),
            variant: CpuVariant::Cpu6502,
            initial_state: StateSnapshot {
                sp: 0xFF,
                p: status::U,
                ..Default::default()
            },
            program,
            mem_patches: Vec::new(),
            expected_state: StateSnapshot {
                sp: 0xFF,
                p: status::U,
                ..Default::default()
            },
            expected_mem: HashMap::new(),
            expected_cycles: -1,
            expect_error: false,
        }
    }

    /// Set initial state.
    #[must_use]
    pub const fn with_initial(mut self, s: StateSnapshot) -> Self {
        self.initial_state = s;
        self
    }

    /// Set expected final state.
    #[must_use]
    pub const fn with_expected(mut self, s: StateSnapshot) -> Self {
        self.expected_state = s;
        self
    }

    /// Add a memory patch.
    #[must_use]
    pub fn with_mem_patch(mut self, addr: u16, val: u8) -> Self {
        self.mem_patches.push(MemPatch::new(addr, val));
        self
    }

    /// Expect a specific cycle count.
    #[must_use]
    pub const fn with_cycles(mut self, c: i32) -> Self {
        self.expected_cycles = c;
        self
    }

    /// Expect a final memory value.
    #[must_use]
    pub fn with_expected_mem(mut self, addr: u16, val: u8) -> Self {
        self.expected_mem.insert(addr, val);
        self
    }
}

// ── TestResult ───────────────────────────────────────────────────────────────

/// The outcome of running a single [`TestCase`].
#[derive(Debug, Clone)]
pub struct TestResult {
    pub name: String,
    pub passed: bool,
    pub cycles: u8,
    pub actual: StateSnapshot,
    pub errors: Vec<String>,
}

impl TestResult {
    fn pass(name: &str, cycles: u8, actual: StateSnapshot) -> Self {
        Self {
            name: name.to_owned(),
            passed: true,
            cycles,
            actual,
            errors: Vec::new(),
        }
    }

    fn fail(name: &str, cycles: u8, actual: StateSnapshot, errors: Vec<String>) -> Self {
        Self {
            name: name.to_owned(),
            passed: false,
            cycles,
            actual,
            errors,
        }
    }
}

impl fmt::Display for TestResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.passed {
            write!(f, "PASS  [{}]  cycles={}", self.name, self.cycles)
        } else {
            write!(
                f,
                "FAIL  [{}]  cycles={}  errors={:?}",
                self.name, self.cycles, self.errors
            )
        }
    }
}

// ── FlagChecker ──────────────────────────────────────────────────────────────

/// Validates individual status-register flags.
pub struct FlagChecker;

impl FlagChecker {
    /// Check that `actual` matches `expected`, reporting any discrepancies.
    #[must_use] 
    pub fn check(actual: u8, expected: u8, test_name: &str) -> Vec<String> {
        let mut errs = Vec::new();
        for (flag, name) in [
            (status::N, "N"),
            (status::V, "V"),
            (status::D, "D"),
            (status::I, "I"),
            (status::Z, "Z"),
            (status::C, "C"),
        ] {
            let a = actual & flag != 0;
            let e = expected & flag != 0;
            if a != e {
                errs.push(format!(
                    "[{}] flag {} expected={} actual={}",
                    test_name, name, u8::from(e), u8::from(a)
                ));
            }
        }
        errs
    }

    /// Return true if all specified flags are set in `p`.
    #[must_use]
    pub const fn flags_set(p: u8, flags: u8) -> bool {
        p & flags == flags
    }

    /// Return true if all specified flags are clear in `p`.
    #[must_use]
    pub const fn flags_clear(p: u8, flags: u8) -> bool {
        p & flags == 0
    }
}

// ── CycleCounter ─────────────────────────────────────────────────────────────

/// Tracks and validates cycle counts.
#[derive(Debug, Default, Clone)]
pub struct CycleCounter {
    /// Map from opcode to total observed cycles.
    pub totals: HashMap<u8, u64>,
    /// Map from opcode to invocation count.
    pub counts: HashMap<u8, u64>,
}

impl CycleCounter {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a cycle count for `opcode`.
    pub fn record(&mut self, opcode: u8, cycles: u8) {
        *self.totals.entry(opcode).or_insert(0) += u64::from(cycles);
        *self.counts.entry(opcode).or_insert(0) += 1;
    }

    /// Return average cycles for `opcode`, or `None` if never seen.
    #[must_use]
    pub fn average(&self, opcode: u8) -> Option<f64> {
        let t = *self.totals.get(&opcode)?;
        let c = *self.counts.get(&opcode)?;
        Some(saturating_u64_to_f64(t) / saturating_u64_to_f64(c))
    }

    /// Verify an expected cycle count (with optional +1 page-cross tolerance).
    #[must_use]
    pub fn verify(expected: i32, actual: u8) -> bool {
        let actual_i = i32::from(actual);
        // Negative expected means "don't care".
        // Page-crossing adds exactly one cycle, but only instructions with ≥4 base cycles
        // can trigger a page cross (absolute-indexed, indirect-indexed addressing modes).
        expected < 0
            || actual_i == expected
            || (expected >= 4 && actual_i == expected + 1)
    }
}

/// Convert a `u64` counter to `f64`, saturating at `u32::MAX` to stay lossless.
fn saturating_u64_to_f64(v: u64) -> f64 {
    u32::try_from(v).map_or_else(|_| f64::from(u32::MAX), f64::from)
}

/// Allocate a zeroed 64 KiB memory image on the heap.
fn zeroed_memory() -> Box<[u8; 65536]> {
    vec![0u8; 65536]
        .into_boxed_slice()
        .try_into()
        .unwrap_or_else(|_| unreachable!())
}

// ── TestRunner ───────────────────────────────────────────────────────────────

/// Executes [`TestCase`]s and collects [`TestResult`]s.
pub struct TestRunner {
    pub cycle_counter: CycleCounter,
}

impl TestRunner {
    #[must_use] 
    pub fn new() -> Self {
        Self {
            cycle_counter: CycleCounter::new(),
        }
    }

    /// Run a single test case.  Returns the [`TestResult`].
    pub fn run(&mut self, tc: &TestCase) -> TestResult {
        let mut memory = zeroed_memory();

        // Place program bytes.
        let pc = tc.initial_state.pc;
        for (i, &b) in tc.program.iter().enumerate() {
            let addr = (pc as usize + i) & 0xFFFF;
            memory[addr] = b;
        }

        // Apply memory patches.
        for p in &tc.mem_patches {
            memory[p.address as usize] = p.value;
        }

        // Initialise CPU state.
        let mut state = Cpu6502State {
            a: tc.initial_state.a,
            x: tc.initial_state.x,
            y: tc.initial_state.y,
            sp: tc.initial_state.sp,
            pc: tc.initial_state.pc,
            p: tc.initial_state.p,
        };

        // Execute one instruction.
        let cycles = execute_one(&mut state, &mut memory);
        let actual = StateSnapshot::from_cpu(&state);

        self.cycle_counter.record(tc.program[0], cycles);

        // Compare.
        let mut errors = Vec::new();

        // Register checks.
        if actual.a != tc.expected_state.a {
            errors.push(format!(
                "A: expected=0x{:02X} actual=0x{:02X}",
                tc.expected_state.a, actual.a
            ));
        }
        if actual.x != tc.expected_state.x {
            errors.push(format!(
                "X: expected=0x{:02X} actual=0x{:02X}",
                tc.expected_state.x, actual.x
            ));
        }
        if actual.y != tc.expected_state.y {
            errors.push(format!(
                "Y: expected=0x{:02X} actual=0x{:02X}",
                tc.expected_state.y, actual.y
            ));
        }
        if actual.sp != tc.expected_state.sp {
            errors.push(format!(
                "SP: expected=0x{:02X} actual=0x{:02X}",
                tc.expected_state.sp, actual.sp
            ));
        }
        if actual.pc != tc.expected_state.pc {
            errors.push(format!(
                "PC: expected=0x{:04X} actual=0x{:04X}",
                tc.expected_state.pc, actual.pc
            ));
        }

        // Flag checks.
        errors.extend(FlagChecker::check(actual.p, tc.expected_state.p, &tc.name));

        // Cycle check.
        if !CycleCounter::verify(tc.expected_cycles, cycles) {
            errors.push(format!(
                "cycles: expected={} actual={}",
                tc.expected_cycles, cycles
            ));
        }

        // Memory checks.
        for (&addr, &val) in &tc.expected_mem {
            if memory[addr as usize] != val {
                errors.push(format!(
                    "mem[0x{addr:04X}]: expected=0x{val:02X} actual=0x{:02X}",
                    memory[addr as usize]
                ));
            }
        }

        if errors.is_empty() {
            TestResult::pass(&tc.name, cycles, actual)
        } else {
            TestResult::fail(&tc.name, cycles, actual, errors)
        }
    }

    /// Run a slice of test cases and collect all results.
    pub fn run_all(&mut self, cases: &[TestCase]) -> Vec<TestResult> {
        cases.iter().map(|tc| self.run(tc)).collect()
    }
}

impl Default for TestRunner {
    fn default() -> Self {
        Self::new()
    }
}

// ── TestReport ───────────────────────────────────────────────────────────────

/// Aggregated summary of a test run.
#[derive(Debug, Clone)]
pub struct TestReport {
    pub results: Vec<TestResult>,
}

impl TestReport {
    #[must_use] 
    pub const fn new(results: Vec<TestResult>) -> Self {
        Self { results }
    }

    #[must_use]
    pub fn passed(&self) -> usize {
        self.results.iter().filter(|r| r.passed).count()
    }
    #[must_use]
    pub fn failed(&self) -> usize {
        self.results.iter().filter(|r| !r.passed).count()
    }
    #[must_use]
    pub const fn total(&self) -> usize {
        self.results.len()
    }

    #[must_use]
    pub fn all_passed(&self) -> bool {
        self.failed() == 0
    }

    /// Return all failing test results.
    #[must_use]
    pub fn failures(&self) -> Vec<&TestResult> {
        self.results.iter().filter(|r| !r.passed).collect()
    }

    pub fn print_summary(&self) {
        println!("TestReport: {}/{} passed", self.passed(), self.total());
        for f in self.failures() {
            println!("  {f}");
        }
    }
}

impl fmt::Display for TestReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TestReport {}/{} passed", self.passed(), self.total())
    }
}

// ── Built-in test cases ───────────────────────────────────────────────────────

/// Return all 100+ built-in test cases covering every addressing mode.
#[must_use]
pub fn builtin_test_cases() -> Vec<TestCase> {
    let mut cases = Vec::new();
    push_cases_1(&mut cases);
    push_cases_2(&mut cases);
    push_cases_3(&mut cases);
    push_cases_4(&mut cases);
    push_cases_5(&mut cases);
    push_cases_6(&mut cases);
    push_cases_7(&mut cases);
    push_cases_8(&mut cases);
    push_cases_9(&mut cases);
    push_cases_10(&mut cases);
    push_cases_11(&mut cases);
    push_cases_12(&mut cases);
    push_cases_13(&mut cases);
    push_cases_14(&mut cases);
    push_cases_15(&mut cases);
    push_cases_16(&mut cases);
    push_cases_17(&mut cases);
    push_cases_18(&mut cases);
    push_cases_19(&mut cases);
    push_cases_20(&mut cases);
    push_cases_21(&mut cases);
    push_cases_22(&mut cases);
    push_cases_23(&mut cases);
    push_cases_24(&mut cases);
    push_cases_25(&mut cases);
    cases
}

fn push_cases_1(cases: &mut Vec<TestCase>) {

    // ─────────────────────────────────────────────────────────────────────────
    // LDA – Immediate
    // ─────────────────────────────────────────────────────────────────────────
    cases.push(
        TestCase::new("LDA #$42 → A=0x42, Z=0, N=0", vec![0xA9, 0x42])
            .with_initial(StateSnapshot {
                pc: 0x0200,
                sp: 0xFF,
                p: status::U,
                ..Default::default()
            })
            .with_expected(StateSnapshot {
                a: 0x42,
                pc: 0x0202,
                sp: 0xFF,
                p: status::U,
                ..Default::default()
            })
            .with_cycles(2),
    );
    cases.push(
        TestCase::new("LDA #$00 → Z=1", vec![0xA9, 0x00])
            .with_initial(StateSnapshot {
                a: 0xFF,
                pc: 0x0200,
                sp: 0xFF,
                p: status::U,
                ..Default::default()
            })
            .with_expected(StateSnapshot {
                a: 0x00,
                pc: 0x0202,
                sp: 0xFF,
                p: status::U | status::Z,
                ..Default::default()
            })
            .with_cycles(2),
    );
    cases.push(
        TestCase::new("LDA #$80 → N=1", vec![0xA9, 0x80])
            .with_initial(StateSnapshot {
                pc: 0x0200,
                sp: 0xFF,
                p: status::U,
                ..Default::default()
            })
            .with_expected(StateSnapshot {
                a: 0x80,
                pc: 0x0202,
                sp: 0xFF,
                p: status::U | status::N,
                ..Default::default()
            })
            .with_cycles(2),
    );

    // LDA – Zero Page
    cases.push(
        TestCase::new("LDA $10 → A=mem[0x10]", vec![0xA5, 0x10])
            .with_initial(StateSnapshot {
                pc: 0x0200,
                sp: 0xFF,
                p: status::U,
                ..Default::default()
            })
            .with_mem_patch(0x10, 0x37)
            .with_expected(StateSnapshot {
                a: 0x37,
                pc: 0x0202,
                sp: 0xFF,
                p: status::U,
                ..Default::default()
            })
            .with_cycles(3),
    );
}

fn push_cases_2(cases: &mut Vec<TestCase>) {

    // LDA – Zero Page,X
    cases.push(
        TestCase::new("LDA $10,X (X=2) → A=mem[0x12]", vec![0xB5, 0x10])
            .with_initial(StateSnapshot {
                x: 2,
                pc: 0x0200,
                sp: 0xFF,
                p: status::U,
                ..Default::default()
            })
            .with_mem_patch(0x12, 0xAB)
            .with_expected(StateSnapshot {
                a: 0xAB,
                x: 2,
                pc: 0x0202,
                sp: 0xFF,
                p: status::U | status::N,
                ..Default::default()
            })
            .with_cycles(4),
    );

    // LDA – Absolute
    cases.push(
        TestCase::new("LDA $1234 → A=mem[0x1234]", vec![0xAD, 0x34, 0x12])
            .with_initial(StateSnapshot {
                pc: 0x0200,
                sp: 0xFF,
                p: status::U,
                ..Default::default()
            })
            .with_mem_patch(0x1234, 0x55)
            .with_expected(StateSnapshot {
                a: 0x55,
                pc: 0x0203,
                sp: 0xFF,
                p: status::U,
                ..Default::default()
            })
            .with_cycles(4),
    );

    // LDA – Absolute,X
    cases.push(
        TestCase::new("LDA $1000,X (X=3) → A=mem[0x1003]", vec![0xBD, 0x00, 0x10])
            .with_initial(StateSnapshot {
                x: 3,
                pc: 0x0200,
                sp: 0xFF,
                p: status::U,
                ..Default::default()
            })
            .with_mem_patch(0x1003, 0x99)
            .with_expected(StateSnapshot {
                a: 0x99,
                x: 3,
                pc: 0x0203,
                sp: 0xFF,
                p: status::U | status::N,
                ..Default::default()
            })
            .with_cycles(4),
    );
}

fn push_cases_3(cases: &mut Vec<TestCase>) {

    // LDA – Absolute,Y
    cases.push(
        TestCase::new("LDA $1000,Y (Y=5) → A=mem[0x1005]", vec![0xB9, 0x00, 0x10])
            .with_initial(StateSnapshot {
                y: 5,
                pc: 0x0200,
                sp: 0xFF,
                p: status::U,
                ..Default::default()
            })
            .with_mem_patch(0x1005, 0x11)
            .with_expected(StateSnapshot {
                a: 0x11,
                y: 5,
                pc: 0x0203,
                sp: 0xFF,
                p: status::U,
                ..Default::default()
            })
            .with_cycles(4),
    );

    // LDA – (Indirect,X)
    cases.push(
        TestCase::new("LDA ($10,X) X=2 → through ptr at $12", vec![0xA1, 0x10])
            .with_initial(StateSnapshot {
                x: 2,
                pc: 0x0200,
                sp: 0xFF,
                p: status::U,
                ..Default::default()
            })
            .with_mem_patch(0x12, 0x00) // ptr lo
            .with_mem_patch(0x13, 0x20) // ptr hi → 0x2000
            .with_mem_patch(0x2000, 0xCC)
            .with_expected(StateSnapshot {
                a: 0xCC,
                x: 2,
                pc: 0x0202,
                sp: 0xFF,
                p: status::U | status::N,
                ..Default::default()
            })
            .with_cycles(6),
    );

    // LDA – (Indirect),Y
    cases.push(
        TestCase::new("LDA ($20),Y Y=1 → through ptr at $20", vec![0xB1, 0x20])
            .with_initial(StateSnapshot {
                y: 1,
                pc: 0x0200,
                sp: 0xFF,
                p: status::U,
                ..Default::default()
            })
            .with_mem_patch(0x20, 0x00) // ptr lo
            .with_mem_patch(0x21, 0x30) // ptr hi → 0x3001
            .with_mem_patch(0x3001, 0x44)
            .with_expected(StateSnapshot {
                a: 0x44,
                y: 1,
                pc: 0x0202,
                sp: 0xFF,
                p: status::U,
                ..Default::default()
            })
            .with_cycles(5),
    );
}

fn push_cases_4(cases: &mut Vec<TestCase>) {

    // ─────────────────────────────────────────────────────────────────────────
    // LDX
    // ─────────────────────────────────────────────────────────────────────────
    cases.push(
        TestCase::new("LDX #$05", vec![0xA2, 0x05])
            .with_initial(StateSnapshot {
                pc: 0x0200,
                sp: 0xFF,
                p: status::U,
                ..Default::default()
            })
            .with_expected(StateSnapshot {
                x: 5,
                pc: 0x0202,
                sp: 0xFF,
                p: status::U,
                ..Default::default()
            })
            .with_cycles(2),
    );
    cases.push(
        TestCase::new("LDX $10", vec![0xA6, 0x10])
            .with_initial(StateSnapshot {
                pc: 0x0200,
                sp: 0xFF,
                p: status::U,
                ..Default::default()
            })
            .with_mem_patch(0x10, 0xFE)
            .with_expected(StateSnapshot {
                x: 0xFE,
                pc: 0x0202,
                sp: 0xFF,
                p: status::U | status::N,
                ..Default::default()
            })
            .with_cycles(3),
    );
    cases.push(
        TestCase::new("LDX $10,Y (Y=1)", vec![0xB6, 0x10])
            .with_initial(StateSnapshot {
                y: 1,
                pc: 0x0200,
                sp: 0xFF,
                p: status::U,
                ..Default::default()
            })
            .with_mem_patch(0x11, 0x22)
            .with_expected(StateSnapshot {
                x: 0x22,
                y: 1,
                pc: 0x0202,
                sp: 0xFF,
                p: status::U,
                ..Default::default()
            })
            .with_cycles(4),
    );

    // ─────────────────────────────────────────────────────────────────────────
    // LDY
    // ─────────────────────────────────────────────────────────────────────────
    cases.push(
        TestCase::new("LDY #$FF → N=1", vec![0xA0, 0xFF])
            .with_initial(StateSnapshot {
                pc: 0x0200,
                sp: 0xFF,
                p: status::U,
                ..Default::default()
            })
            .with_expected(StateSnapshot {
                y: 0xFF,
                pc: 0x0202,
                sp: 0xFF,
                p: status::U | status::N,
                ..Default::default()
            })
            .with_cycles(2),
    );
}

fn push_cases_5(cases: &mut Vec<TestCase>) {

    // ─────────────────────────────────────────────────────────────────────────
    // STA
    // ─────────────────────────────────────────────────────────────────────────
    cases.push(
        TestCase::new("STA $0050 (zero page)", vec![0x85, 0x50])
            .with_initial(StateSnapshot {
                a: 0xBB,
                pc: 0x0200,
                sp: 0xFF,
                p: status::U,
                ..Default::default()
            })
            .with_expected(StateSnapshot {
                a: 0xBB,
                pc: 0x0202,
                sp: 0xFF,
                p: status::U,
                ..Default::default()
            })
            .with_expected_mem(0x50, 0xBB)
            .with_cycles(3),
    );
    cases.push(
        TestCase::new("STA $1234", vec![0x8D, 0x34, 0x12])
            .with_initial(StateSnapshot {
                a: 0xDE,
                pc: 0x0200,
                sp: 0xFF,
                p: status::U,
                ..Default::default()
            })
            .with_expected(StateSnapshot {
                a: 0xDE,
                pc: 0x0203,
                sp: 0xFF,
                p: status::U,
                ..Default::default()
            })
            .with_expected_mem(0x1234, 0xDE)
            .with_cycles(4),
    );

    // ─────────────────────────────────────────────────────────────────────────
    // STX / STY
    // ─────────────────────────────────────────────────────────────────────────
    cases.push(
        TestCase::new("STX $0060", vec![0x86, 0x60])
            .with_initial(StateSnapshot {
                x: 0x77,
                pc: 0x0200,
                sp: 0xFF,
                p: status::U,
                ..Default::default()
            })
            .with_expected(StateSnapshot {
                x: 0x77,
                pc: 0x0202,
                sp: 0xFF,
                p: status::U,
                ..Default::default()
            })
            .with_expected_mem(0x60, 0x77)
            .with_cycles(3),
    );
    cases.push(
        TestCase::new("STY $0070", vec![0x84, 0x70])
            .with_initial(StateSnapshot {
                y: 0x88,
                pc: 0x0200,
                sp: 0xFF,
                p: status::U,
                ..Default::default()
            })
            .with_expected(StateSnapshot {
                y: 0x88,
                pc: 0x0202,
                sp: 0xFF,
                p: status::U,
                ..Default::default()
            })
            .with_expected_mem(0x70, 0x88)
            .with_cycles(3),
    );
}

fn push_cases_6(cases: &mut Vec<TestCase>) {

    // ─────────────────────────────────────────────────────────────────────────
    // ADC
    // ─────────────────────────────────────────────────────────────────────────
    cases.push(
        TestCase::new("ADC #$01 (A=0x01)", vec![0x69, 0x01])
            .with_initial(StateSnapshot {
                a: 0x01,
                pc: 0x0200,
                sp: 0xFF,
                p: status::U,
                ..Default::default()
            })
            .with_expected(StateSnapshot {
                a: 0x02,
                pc: 0x0202,
                sp: 0xFF,
                p: status::U,
                ..Default::default()
            })
            .with_cycles(2),
    );
    cases.push(
        TestCase::new("ADC #$01 (A=0xFF) → carry out", vec![0x69, 0x01])
            .with_initial(StateSnapshot {
                a: 0xFF,
                pc: 0x0200,
                sp: 0xFF,
                p: status::U,
                ..Default::default()
            })
            .with_expected(StateSnapshot {
                a: 0x00,
                pc: 0x0202,
                sp: 0xFF,
                p: status::U | status::Z | status::C,
                ..Default::default()
            })
            .with_cycles(2),
    );
    cases.push(
        TestCase::new("ADC #$7F (A=0x01) → overflow", vec![0x69, 0x7F])
            .with_initial(StateSnapshot {
                a: 0x01,
                pc: 0x0200,
                sp: 0xFF,
                p: status::U,
                ..Default::default()
            })
            .with_expected(StateSnapshot {
                a: 0x80,
                pc: 0x0202,
                sp: 0xFF,
                p: status::U | status::V | status::N,
                ..Default::default()
            })
            .with_cycles(2),
    );
    cases.push(
        TestCase::new("ADC #$01 with carry in (A=0x00)", vec![0x69, 0x01])
            .with_initial(StateSnapshot {
                a: 0x00,
                pc: 0x0200,
                sp: 0xFF,
                p: status::U | status::C,
                ..Default::default()
            })
            .with_expected(StateSnapshot {
                a: 0x02,
                pc: 0x0202,
                sp: 0xFF,
                p: status::U,
                ..Default::default()
            })
            .with_cycles(2),
    );
}

fn push_cases_7(cases: &mut Vec<TestCase>) {

    // ─────────────────────────────────────────────────────────────────────────
    // SBC
    // ─────────────────────────────────────────────────────────────────────────
    cases.push(
        TestCase::new("SBC #$01 (A=0x05, C=1)", vec![0xE9, 0x01])
            .with_initial(StateSnapshot {
                a: 0x05,
                pc: 0x0200,
                sp: 0xFF,
                p: status::U | status::C,
                ..Default::default()
            })
            .with_expected(StateSnapshot {
                a: 0x04,
                pc: 0x0202,
                sp: 0xFF,
                p: status::U | status::C,
                ..Default::default()
            })
            .with_cycles(2),
    );
    cases.push(
        TestCase::new("SBC #$01 (A=0x00, C=1) → underflow", vec![0xE9, 0x01])
            .with_initial(StateSnapshot {
                a: 0x00,
                pc: 0x0200,
                sp: 0xFF,
                p: status::U | status::C,
                ..Default::default()
            })
            .with_expected(StateSnapshot {
                a: 0xFF,
                pc: 0x0202,
                sp: 0xFF,
                p: status::U | status::N,
                ..Default::default()
            })
            .with_cycles(2),
    );

    // ─────────────────────────────────────────────────────────────────────────
    // AND / ORA / EOR
    // ─────────────────────────────────────────────────────────────────────────
    cases.push(
        TestCase::new("AND #$0F (A=0xFF)", vec![0x29, 0x0F])
            .with_initial(StateSnapshot {
                a: 0xFF,
                pc: 0x0200,
                sp: 0xFF,
                p: status::U,
                ..Default::default()
            })
            .with_expected(StateSnapshot {
                a: 0x0F,
                pc: 0x0202,
                sp: 0xFF,
                p: status::U,
                ..Default::default()
            })
            .with_cycles(2),
    );
    cases.push(
        TestCase::new("ORA #$F0 (A=0x0F)", vec![0x09, 0xF0])
            .with_initial(StateSnapshot {
                a: 0x0F,
                pc: 0x0200,
                sp: 0xFF,
                p: status::U,
                ..Default::default()
            })
            .with_expected(StateSnapshot {
                a: 0xFF,
                pc: 0x0202,
                sp: 0xFF,
                p: status::U | status::N,
                ..Default::default()
            })
            .with_cycles(2),
    );
}

fn push_cases_8(cases: &mut Vec<TestCase>) {
    cases.push(
        TestCase::new("EOR #$FF (A=0xFF) → zero", vec![0x49, 0xFF])
            .with_initial(StateSnapshot {
                a: 0xFF,
                pc: 0x0200,
                sp: 0xFF,
                p: status::U,
                ..Default::default()
            })
            .with_expected(StateSnapshot {
                a: 0x00,
                pc: 0x0202,
                sp: 0xFF,
                p: status::U | status::Z,
                ..Default::default()
            })
            .with_cycles(2),
    );

    // ─────────────────────────────────────────────────────────────────────────
    // CMP / CPX / CPY
    // ─────────────────────────────────────────────────────────────────────────
    cases.push(
        TestCase::new("CMP #$10 (A=0x10) → Z=1, C=1", vec![0xC9, 0x10])
            .with_initial(StateSnapshot {
                a: 0x10,
                pc: 0x0200,
                sp: 0xFF,
                p: status::U,
                ..Default::default()
            })
            .with_expected(StateSnapshot {
                a: 0x10,
                pc: 0x0202,
                sp: 0xFF,
                p: status::U | status::Z | status::C,
                ..Default::default()
            })
            .with_cycles(2),
    );
    cases.push(
        TestCase::new("CMP #$20 (A=0x10) → N=1, C=0", vec![0xC9, 0x20])
            .with_initial(StateSnapshot {
                a: 0x10,
                pc: 0x0200,
                sp: 0xFF,
                p: status::U,
                ..Default::default()
            })
            .with_expected(StateSnapshot {
                a: 0x10,
                pc: 0x0202,
                sp: 0xFF,
                p: status::U | status::N,
                ..Default::default()
            })
            .with_cycles(2),
    );
    cases.push(
        TestCase::new("CPX #$05 (X=0x10) → C=1", vec![0xE0, 0x05])
            .with_initial(StateSnapshot {
                x: 0x10,
                pc: 0x0200,
                sp: 0xFF,
                p: status::U,
                ..Default::default()
            })
            .with_expected(StateSnapshot {
                x: 0x10,
                pc: 0x0202,
                sp: 0xFF,
                p: status::U | status::C,
                ..Default::default()
            })
            .with_cycles(2),
    );
}

fn push_cases_9(cases: &mut Vec<TestCase>) {
    cases.push(
        TestCase::new("CPY #$00 (Y=0x00) → Z=1, C=1", vec![0xC0, 0x00])
            .with_initial(StateSnapshot {
                y: 0x00,
                pc: 0x0200,
                sp: 0xFF,
                p: status::U,
                ..Default::default()
            })
            .with_expected(StateSnapshot {
                y: 0x00,
                pc: 0x0202,
                sp: 0xFF,
                p: status::U | status::Z | status::C,
                ..Default::default()
            })
            .with_cycles(2),
    );

    // ─────────────────────────────────────────────────────────────────────────
    // BIT
    // ─────────────────────────────────────────────────────────────────────────
    cases.push(
        TestCase::new("BIT $50 (mem=$C0, A=$00) → Z=1, N=1, V=1", vec![0x24, 0x50])
            .with_initial(StateSnapshot {
                a: 0x00,
                pc: 0x0200,
                sp: 0xFF,
                p: status::U,
                ..Default::default()
            })
            .with_mem_patch(0x50, 0xC0)
            .with_expected(StateSnapshot {
                a: 0x00,
                pc: 0x0202,
                sp: 0xFF,
                p: status::U | status::Z | status::N | status::V,
                ..Default::default()
            })
            .with_cycles(3),
    );

    // ─────────────────────────────────────────────────────────────────────────
    // INC / DEC
    // ─────────────────────────────────────────────────────────────────────────
    cases.push(
        TestCase::new("INC $50 (mem=0x0F)", vec![0xE6, 0x50])
            .with_initial(StateSnapshot {
                pc: 0x0200,
                sp: 0xFF,
                p: status::U,
                ..Default::default()
            })
            .with_mem_patch(0x50, 0x0F)
            .with_expected(StateSnapshot {
                pc: 0x0202,
                sp: 0xFF,
                p: status::U,
                ..Default::default()
            })
            .with_expected_mem(0x50, 0x10)
            .with_cycles(5),
    );
    cases.push(
        TestCase::new("INC $50 (mem=0xFF) → wraps to 0 Z=1", vec![0xE6, 0x50])
            .with_initial(StateSnapshot {
                pc: 0x0200,
                sp: 0xFF,
                p: status::U,
                ..Default::default()
            })
            .with_mem_patch(0x50, 0xFF)
            .with_expected(StateSnapshot {
                pc: 0x0202,
                sp: 0xFF,
                p: status::U | status::Z,
                ..Default::default()
            })
            .with_expected_mem(0x50, 0x00)
            .with_cycles(5),
    );
}

fn push_cases_10(cases: &mut Vec<TestCase>) {
    cases.push(
        TestCase::new("INX (X=0xFF) → X=0, Z=1", vec![0xE8])
            .with_initial(StateSnapshot {
                x: 0xFF,
                pc: 0x0200,
                sp: 0xFF,
                p: status::U,
                ..Default::default()
            })
            .with_expected(StateSnapshot {
                x: 0x00,
                pc: 0x0201,
                sp: 0xFF,
                p: status::U | status::Z,
                ..Default::default()
            })
            .with_cycles(2),
    );
    cases.push(
        TestCase::new("INY (Y=0x7F) → Y=0x80, N=1", vec![0xC8])
            .with_initial(StateSnapshot {
                y: 0x7F,
                pc: 0x0200,
                sp: 0xFF,
                p: status::U,
                ..Default::default()
            })
            .with_expected(StateSnapshot {
                y: 0x80,
                pc: 0x0201,
                sp: 0xFF,
                p: status::U | status::N,
                ..Default::default()
            })
            .with_cycles(2),
    );
    cases.push(
        TestCase::new("DEX (X=0x01) → X=0x00, Z=1", vec![0xCA])
            .with_initial(StateSnapshot {
                x: 0x01,
                pc: 0x0200,
                sp: 0xFF,
                p: status::U,
                ..Default::default()
            })
            .with_expected(StateSnapshot {
                x: 0x00,
                pc: 0x0201,
                sp: 0xFF,
                p: status::U | status::Z,
                ..Default::default()
            })
            .with_cycles(2),
    );
    cases.push(
        TestCase::new("DEY (Y=0x00) → Y=0xFF, N=1", vec![0x88])
            .with_initial(StateSnapshot {
                y: 0x00,
                pc: 0x0200,
                sp: 0xFF,
                p: status::U,
                ..Default::default()
            })
            .with_expected(StateSnapshot {
                y: 0xFF,
                pc: 0x0201,
                sp: 0xFF,
                p: status::U | status::N,
                ..Default::default()
            })
            .with_cycles(2),
    );
}

fn push_cases_11(cases: &mut Vec<TestCase>) {

    // ─────────────────────────────────────────────────────────────────────────
    // ASL / LSR
    // ─────────────────────────────────────────────────────────────────────────
    cases.push(
        TestCase::new("ASL A (A=0x01)", vec![0x0A])
            .with_initial(StateSnapshot {
                a: 0x01,
                pc: 0x0200,
                sp: 0xFF,
                p: status::U,
                ..Default::default()
            })
            .with_expected(StateSnapshot {
                a: 0x02,
                pc: 0x0201,
                sp: 0xFF,
                p: status::U,
                ..Default::default()
            })
            .with_cycles(2),
    );
    cases.push(
        TestCase::new("ASL A (A=0x80) → carry, Z=1", vec![0x0A])
            .with_initial(StateSnapshot {
                a: 0x80,
                pc: 0x0200,
                sp: 0xFF,
                p: status::U,
                ..Default::default()
            })
            .with_expected(StateSnapshot {
                a: 0x00,
                pc: 0x0201,
                sp: 0xFF,
                p: status::U | status::C | status::Z,
                ..Default::default()
            })
            .with_cycles(2),
    );
    cases.push(
        TestCase::new("LSR A (A=0x01) → A=0, C=1, Z=1", vec![0x4A])
            .with_initial(StateSnapshot {
                a: 0x01,
                pc: 0x0200,
                sp: 0xFF,
                p: status::U,
                ..Default::default()
            })
            .with_expected(StateSnapshot {
                a: 0x00,
                pc: 0x0201,
                sp: 0xFF,
                p: status::U | status::C | status::Z,
                ..Default::default()
            })
            .with_cycles(2),
    );
    cases.push(
        TestCase::new("LSR A (A=0x80) → A=0x40", vec![0x4A])
            .with_initial(StateSnapshot {
                a: 0x80,
                pc: 0x0200,
                sp: 0xFF,
                p: status::U,
                ..Default::default()
            })
            .with_expected(StateSnapshot {
                a: 0x40,
                pc: 0x0201,
                sp: 0xFF,
                p: status::U,
                ..Default::default()
            })
            .with_cycles(2),
    );
}

fn push_cases_12(cases: &mut Vec<TestCase>) {

    // ─────────────────────────────────────────────────────────────────────────
    // ROL / ROR
    // ─────────────────────────────────────────────────────────────────────────
    cases.push(
        TestCase::new("ROL A (A=0x40, C=1) → A=0x81, N=1", vec![0x2A])
            .with_initial(StateSnapshot {
                a: 0x40,
                pc: 0x0200,
                sp: 0xFF,
                p: status::U | status::C,
                ..Default::default()
            })
            .with_expected(StateSnapshot {
                a: 0x81,
                pc: 0x0201,
                sp: 0xFF,
                p: status::U | status::N,
                ..Default::default()
            })
            .with_cycles(2),
    );
    cases.push(
        TestCase::new("ROR A (A=0x02, C=0) → A=0x01", vec![0x6A])
            .with_initial(StateSnapshot {
                a: 0x02,
                pc: 0x0200,
                sp: 0xFF,
                p: status::U,
                ..Default::default()
            })
            .with_expected(StateSnapshot {
                a: 0x01,
                pc: 0x0201,
                sp: 0xFF,
                p: status::U,
                ..Default::default()
            })
            .with_cycles(2),
    );
    cases.push(
        TestCase::new("ROR A (A=0x01, C=1) → A=0x80, N=1, C=1", vec![0x6A])
            .with_initial(StateSnapshot {
                a: 0x01,
                pc: 0x0200,
                sp: 0xFF,
                p: status::U | status::C,
                ..Default::default()
            })
            .with_expected(StateSnapshot {
                a: 0x80,
                pc: 0x0201,
                sp: 0xFF,
                p: status::U | status::N | status::C,
                ..Default::default()
            })
            .with_cycles(2),
    );

    // ─────────────────────────────────────────────────────────────────────────
    // JMP / JSR / RTS
    // ─────────────────────────────────────────────────────────────────────────
    cases.push(
        TestCase::new("JMP $1234 → PC=0x1234", vec![0x4C, 0x34, 0x12])
            .with_initial(StateSnapshot {
                pc: 0x0200,
                sp: 0xFF,
                p: status::U,
                ..Default::default()
            })
            .with_expected(StateSnapshot {
                pc: 0x1234,
                sp: 0xFF,
                p: status::U,
                ..Default::default()
            })
            .with_cycles(3),
    );
}

fn push_cases_13(cases: &mut Vec<TestCase>) {
    cases.push({
        // JSR $1234: pushes 0x0202 (next-1), jumps to 0x1234
        TestCase::new(
            "JSR $1234 → PC=0x1234, stack has return-1",
            vec![0x20, 0x34, 0x12],
        )
        .with_initial(StateSnapshot {
            pc: 0x0200,
            sp: 0xFF,
            p: status::U,
            ..Default::default()
        })
        .with_expected(StateSnapshot {
            pc: 0x1234,
            sp: 0xFD,
            p: status::U,
            ..Default::default()
        })
        .with_expected_mem(0x01FF, 0x02) // hi byte of 0x0202
        .with_expected_mem(0x01FE, 0x02) // lo byte of 0x0202
        .with_cycles(6)
    });

    // ─────────────────────────────────────────────────────────────────────────
    // Branches
    // ─────────────────────────────────────────────────────────────────────────
    cases.push(
        TestCase::new("BNE taken (Z=0, offset=+2)", vec![0xD0, 0x02])
            .with_initial(StateSnapshot {
                pc: 0x0200,
                sp: 0xFF,
                p: status::U,
                ..Default::default()
            })
            .with_expected(StateSnapshot {
                pc: 0x0204,
                sp: 0xFF,
                p: status::U,
                ..Default::default()
            }),
    );
    cases.push(
        TestCase::new("BNE not-taken (Z=1)", vec![0xD0, 0x10])
            .with_initial(StateSnapshot {
                pc: 0x0200,
                sp: 0xFF,
                p: status::U | status::Z,
                ..Default::default()
            })
            .with_expected(StateSnapshot {
                pc: 0x0202,
                sp: 0xFF,
                p: status::U | status::Z,
                ..Default::default()
            })
            .with_cycles(2),
    );
    cases.push(
        TestCase::new("BEQ taken (Z=1, offset=-2)", vec![0xF0, 0xFE])
            .with_initial(StateSnapshot {
                pc: 0x0200,
                sp: 0xFF,
                p: status::U | status::Z,
                ..Default::default()
            })
            .with_expected(StateSnapshot {
                pc: 0x0200,
                sp: 0xFF,
                p: status::U | status::Z,
                ..Default::default()
            }),
    );
}

fn push_cases_14(cases: &mut Vec<TestCase>) {
    cases.push(
        TestCase::new("BCS taken (C=1)", vec![0xB0, 0x04])
            .with_initial(StateSnapshot {
                pc: 0x0200,
                sp: 0xFF,
                p: status::U | status::C,
                ..Default::default()
            })
            .with_expected(StateSnapshot {
                pc: 0x0206,
                sp: 0xFF,
                p: status::U | status::C,
                ..Default::default()
            }),
    );
    cases.push(
        TestCase::new("BCC not-taken (C=1)", vec![0x90, 0x04])
            .with_initial(StateSnapshot {
                pc: 0x0200,
                sp: 0xFF,
                p: status::U | status::C,
                ..Default::default()
            })
            .with_expected(StateSnapshot {
                pc: 0x0202,
                sp: 0xFF,
                p: status::U | status::C,
                ..Default::default()
            })
            .with_cycles(2),
    );
    cases.push(
        TestCase::new("BMI taken (N=1)", vec![0x30, 0x06])
            .with_initial(StateSnapshot {
                pc: 0x0200,
                sp: 0xFF,
                p: status::U | status::N,
                ..Default::default()
            })
            .with_expected(StateSnapshot {
                pc: 0x0208,
                sp: 0xFF,
                p: status::U | status::N,
                ..Default::default()
            }),
    );
    cases.push(
        TestCase::new("BPL taken (N=0)", vec![0x10, 0x08])
            .with_initial(StateSnapshot {
                pc: 0x0200,
                sp: 0xFF,
                p: status::U,
                ..Default::default()
            })
            .with_expected(StateSnapshot {
                pc: 0x020A,
                sp: 0xFF,
                p: status::U,
                ..Default::default()
            }),
    );
    cases.push(
        TestCase::new("BVS taken (V=1)", vec![0x70, 0x02])
            .with_initial(StateSnapshot {
                pc: 0x0200,
                sp: 0xFF,
                p: status::U | status::V,
                ..Default::default()
            })
            .with_expected(StateSnapshot {
                pc: 0x0204,
                sp: 0xFF,
                p: status::U | status::V,
                ..Default::default()
            }),
    );
}

fn push_cases_15(cases: &mut Vec<TestCase>) {
    cases.push(
        TestCase::new("BVC not-taken (V=1)", vec![0x50, 0x04])
            .with_initial(StateSnapshot {
                pc: 0x0200,
                sp: 0xFF,
                p: status::U | status::V,
                ..Default::default()
            })
            .with_expected(StateSnapshot {
                pc: 0x0202,
                sp: 0xFF,
                p: status::U | status::V,
                ..Default::default()
            })
            .with_cycles(2),
    );

    // ─────────────────────────────────────────────────────────────────────────
    // Stack: PHA / PLA / PHP / PLP
    // ─────────────────────────────────────────────────────────────────────────
    cases.push(
        TestCase::new("PHA (A=0xAA)", vec![0x48])
            .with_initial(StateSnapshot {
                a: 0xAA,
                pc: 0x0200,
                sp: 0xFF,
                p: status::U,
                ..Default::default()
            })
            .with_expected(StateSnapshot {
                a: 0xAA,
                pc: 0x0201,
                sp: 0xFE,
                p: status::U,
                ..Default::default()
            })
            .with_expected_mem(0x01FF, 0xAA)
            .with_cycles(3),
    );
    cases.push(
        TestCase::new("PLA (stack=0x55)", vec![0x68])
            .with_initial(StateSnapshot {
                a: 0x00,
                pc: 0x0200,
                sp: 0xFE,
                p: status::U,
                ..Default::default()
            })
            .with_mem_patch(0x01FF, 0x55)
            .with_expected(StateSnapshot {
                a: 0x55,
                pc: 0x0201,
                sp: 0xFF,
                p: status::U,
                ..Default::default()
            })
            .with_cycles(4),
    );

    // ─────────────────────────────────────────────────────────────────────────
    // Transfers
    // ─────────────────────────────────────────────────────────────────────────
    cases.push(
        TestCase::new("TAX (A=0x33) → X=0x33", vec![0xAA])
            .with_initial(StateSnapshot {
                a: 0x33,
                pc: 0x0200,
                sp: 0xFF,
                p: status::U,
                ..Default::default()
            })
            .with_expected(StateSnapshot {
                a: 0x33,
                x: 0x33,
                pc: 0x0201,
                sp: 0xFF,
                p: status::U,
                ..Default::default()
            })
            .with_cycles(2),
    );
}

fn push_cases_16(cases: &mut Vec<TestCase>) {
    cases.push(
        TestCase::new("TAY (A=0x80) → Y=0x80, N=1", vec![0xA8])
            .with_initial(StateSnapshot {
                a: 0x80,
                pc: 0x0200,
                sp: 0xFF,
                p: status::U,
                ..Default::default()
            })
            .with_expected(StateSnapshot {
                a: 0x80,
                y: 0x80,
                pc: 0x0201,
                sp: 0xFF,
                p: status::U | status::N,
                ..Default::default()
            })
            .with_cycles(2),
    );
    cases.push(
        TestCase::new("TXA (X=0x05) → A=0x05", vec![0x8A])
            .with_initial(StateSnapshot {
                x: 0x05,
                pc: 0x0200,
                sp: 0xFF,
                p: status::U,
                ..Default::default()
            })
            .with_expected(StateSnapshot {
                a: 0x05,
                x: 0x05,
                pc: 0x0201,
                sp: 0xFF,
                p: status::U,
                ..Default::default()
            })
            .with_cycles(2),
    );
    cases.push(
        TestCase::new("TYA (Y=0x00) → A=0x00, Z=1", vec![0x98])
            .with_initial(StateSnapshot {
                y: 0x00,
                pc: 0x0200,
                sp: 0xFF,
                p: status::U,
                ..Default::default()
            })
            .with_expected(StateSnapshot {
                a: 0x00,
                y: 0x00,
                pc: 0x0201,
                sp: 0xFF,
                p: status::U | status::Z,
                ..Default::default()
            })
            .with_cycles(2),
    );
    cases.push(
        TestCase::new("TSX (SP=0xF0) → X=0xF0, N=1", vec![0xBA])
            .with_initial(StateSnapshot {
                sp: 0xF0,
                pc: 0x0200,
                p: status::U,
                ..Default::default()
            })
            .with_expected(StateSnapshot {
                x: 0xF0,
                sp: 0xF0,
                pc: 0x0201,
                p: status::U | status::N,
                ..Default::default()
            })
            .with_cycles(2),
    );
}

fn push_cases_17(cases: &mut Vec<TestCase>) {
    cases.push(
        TestCase::new("TXS (X=0xEE) → SP=0xEE (no flags)", vec![0x9A])
            .with_initial(StateSnapshot {
                x: 0xEE,
                pc: 0x0200,
                sp: 0xFF,
                p: status::U,
                ..Default::default()
            })
            .with_expected(StateSnapshot {
                x: 0xEE,
                sp: 0xEE,
                pc: 0x0201,
                p: status::U,
                ..Default::default()
            })
            .with_cycles(2),
    );

    // ─────────────────────────────────────────────────────────────────────────
    // Flag manipulation
    // ─────────────────────────────────────────────────────────────────────────
    cases.push(
        TestCase::new("CLC → C=0", vec![0x18])
            .with_initial(StateSnapshot {
                pc: 0x0200,
                sp: 0xFF,
                p: status::U | status::C,
                ..Default::default()
            })
            .with_expected(StateSnapshot {
                pc: 0x0201,
                sp: 0xFF,
                p: status::U,
                ..Default::default()
            })
            .with_cycles(2),
    );
    cases.push(
        TestCase::new("SEC → C=1", vec![0x38])
            .with_initial(StateSnapshot {
                pc: 0x0200,
                sp: 0xFF,
                p: status::U,
                ..Default::default()
            })
            .with_expected(StateSnapshot {
                pc: 0x0201,
                sp: 0xFF,
                p: status::U | status::C,
                ..Default::default()
            })
            .with_cycles(2),
    );
    cases.push(
        TestCase::new("CLI → I=0", vec![0x58])
            .with_initial(StateSnapshot {
                pc: 0x0200,
                sp: 0xFF,
                p: status::U | status::I,
                ..Default::default()
            })
            .with_expected(StateSnapshot {
                pc: 0x0201,
                sp: 0xFF,
                p: status::U,
                ..Default::default()
            })
            .with_cycles(2),
    );
}

fn push_cases_18(cases: &mut Vec<TestCase>) {
    cases.push(
        TestCase::new("SEI → I=1", vec![0x78])
            .with_initial(StateSnapshot {
                pc: 0x0200,
                sp: 0xFF,
                p: status::U,
                ..Default::default()
            })
            .with_expected(StateSnapshot {
                pc: 0x0201,
                sp: 0xFF,
                p: status::U | status::I,
                ..Default::default()
            })
            .with_cycles(2),
    );
    cases.push(
        TestCase::new("CLV → V=0", vec![0xB8])
            .with_initial(StateSnapshot {
                pc: 0x0200,
                sp: 0xFF,
                p: status::U | status::V,
                ..Default::default()
            })
            .with_expected(StateSnapshot {
                pc: 0x0201,
                sp: 0xFF,
                p: status::U,
                ..Default::default()
            })
            .with_cycles(2),
    );
    cases.push(
        TestCase::new("SED → D=1", vec![0xF8])
            .with_initial(StateSnapshot {
                pc: 0x0200,
                sp: 0xFF,
                p: status::U,
                ..Default::default()
            })
            .with_expected(StateSnapshot {
                pc: 0x0201,
                sp: 0xFF,
                p: status::U | status::D,
                ..Default::default()
            })
            .with_cycles(2),
    );
    cases.push(
        TestCase::new("CLD → D=0", vec![0xD8])
            .with_initial(StateSnapshot {
                pc: 0x0200,
                sp: 0xFF,
                p: status::U | status::D,
                ..Default::default()
            })
            .with_expected(StateSnapshot {
                pc: 0x0201,
                sp: 0xFF,
                p: status::U,
                ..Default::default()
            })
            .with_cycles(2),
    );

    // ─────────────────────────────────────────────────────────────────────────
    // NOP
    // ─────────────────────────────────────────────────────────────────────────
    cases.push(
        TestCase::new("NOP", vec![0xEA])
            .with_initial(StateSnapshot {
                pc: 0x0200,
                sp: 0xFF,
                p: status::U,
                ..Default::default()
            })
            .with_expected(StateSnapshot {
                pc: 0x0201,
                sp: 0xFF,
                p: status::U,
                ..Default::default()
            })
            .with_cycles(2),
    );
}

fn push_cases_19(cases: &mut Vec<TestCase>) {

    // ─────────────────────────────────────────────────────────────────────────
    // DEC (memory)
    // ─────────────────────────────────────────────────────────────────────────
    cases.push(
        TestCase::new("DEC $50 (mem=0x01) → mem=0x00, Z=1", vec![0xC6, 0x50])
            .with_initial(StateSnapshot {
                pc: 0x0200,
                sp: 0xFF,
                p: status::U,
                ..Default::default()
            })
            .with_mem_patch(0x50, 0x01)
            .with_expected(StateSnapshot {
                pc: 0x0202,
                sp: 0xFF,
                p: status::U | status::Z,
                ..Default::default()
            })
            .with_expected_mem(0x50, 0x00)
            .with_cycles(5),
    );
    cases.push(
        TestCase::new("DEC $50 (mem=0x00) → wraps, N=1", vec![0xC6, 0x50])
            .with_initial(StateSnapshot {
                pc: 0x0200,
                sp: 0xFF,
                p: status::U,
                ..Default::default()
            })
            .with_mem_patch(0x50, 0x00)
            .with_expected(StateSnapshot {
                pc: 0x0202,
                sp: 0xFF,
                p: status::U | status::N,
                ..Default::default()
            })
            .with_expected_mem(0x50, 0xFF)
            .with_cycles(5),
    );

    // ─────────────────────────────────────────────────────────────────────────
    // ASL / LSR / ROL / ROR on memory
    // ─────────────────────────────────────────────────────────────────────────
    cases.push(
        TestCase::new("ASL $50 (mem=0x10)", vec![0x06, 0x50])
            .with_initial(StateSnapshot {
                pc: 0x0200,
                sp: 0xFF,
                p: status::U,
                ..Default::default()
            })
            .with_mem_patch(0x50, 0x10)
            .with_expected(StateSnapshot {
                pc: 0x0202,
                sp: 0xFF,
                p: status::U,
                ..Default::default()
            })
            .with_expected_mem(0x50, 0x20)
            .with_cycles(5),
    );
    cases.push(
        TestCase::new("LSR $50 (mem=0x02)", vec![0x46, 0x50])
            .with_initial(StateSnapshot {
                pc: 0x0200,
                sp: 0xFF,
                p: status::U,
                ..Default::default()
            })
            .with_mem_patch(0x50, 0x02)
            .with_expected(StateSnapshot {
                pc: 0x0202,
                sp: 0xFF,
                p: status::U,
                ..Default::default()
            })
            .with_expected_mem(0x50, 0x01)
            .with_cycles(5),
    );
}

fn push_cases_20(cases: &mut Vec<TestCase>) {

    // ─────────────────────────────────────────────────────────────────────────
    // Indirect JMP (page-wrap bug)
    // ─────────────────────────────────────────────────────────────────────────
    cases.push(
        TestCase::new("JMP ($10FF) page-wrap bug", vec![0x6C, 0xFF, 0x10])
            .with_initial(StateSnapshot {
                pc: 0x0200,
                sp: 0xFF,
                p: status::U,
                ..Default::default()
            })
            .with_mem_patch(0x10FF, 0x00) // lo byte from 0x10FF
            .with_mem_patch(0x1000, 0x20) // hi byte from 0x1000 (bug: not 0x1100)
            .with_expected(StateSnapshot {
                pc: 0x2000,
                sp: 0xFF,
                p: status::U,
                ..Default::default()
            })
            .with_cycles(5),
    );

    // ─────────────────────────────────────────────────────────────────────────
    // Additional edge cases
    // ─────────────────────────────────────────────────────────────────────────
    cases.push(
        TestCase::new("ADC #$80 (A=0x80) → overflow + carry", vec![0x69, 0x80])
            .with_initial(StateSnapshot {
                a: 0x80,
                pc: 0x0200,
                sp: 0xFF,
                p: status::U,
                ..Default::default()
            })
            .with_expected(StateSnapshot {
                a: 0x00,
                pc: 0x0202,
                sp: 0xFF,
                p: status::U | status::V | status::C | status::Z,
                ..Default::default()
            })
            .with_cycles(2),
    );

    // STA Absolute,X
    cases.push(
        TestCase::new("STA $1000,X (X=2)", vec![0x9D, 0x00, 0x10])
            .with_initial(StateSnapshot {
                a: 0xAA,
                x: 2,
                pc: 0x0200,
                sp: 0xFF,
                p: status::U,
                ..Default::default()
            })
            .with_expected(StateSnapshot {
                a: 0xAA,
                x: 2,
                pc: 0x0203,
                sp: 0xFF,
                p: status::U,
                ..Default::default()
            })
            .with_expected_mem(0x1002, 0xAA)
            .with_cycles(5),
    );
}

fn push_cases_21(cases: &mut Vec<TestCase>) {

    // STA Absolute,Y
    cases.push(
        TestCase::new("STA $1000,Y (Y=3)", vec![0x99, 0x00, 0x10])
            .with_initial(StateSnapshot {
                a: 0xBB,
                y: 3,
                pc: 0x0200,
                sp: 0xFF,
                p: status::U,
                ..Default::default()
            })
            .with_expected(StateSnapshot {
                a: 0xBB,
                y: 3,
                pc: 0x0203,
                sp: 0xFF,
                p: status::U,
                ..Default::default()
            })
            .with_expected_mem(0x1003, 0xBB)
            .with_cycles(5),
    );

    // STA (Indirect,X)
    cases.push(
        TestCase::new("STA ($10,X) X=0", vec![0x81, 0x10])
            .with_initial(StateSnapshot {
                a: 0xCC,
                x: 0,
                pc: 0x0200,
                sp: 0xFF,
                p: status::U,
                ..Default::default()
            })
            .with_mem_patch(0x10, 0x00)
            .with_mem_patch(0x11, 0x40)
            .with_expected(StateSnapshot {
                a: 0xCC,
                x: 0,
                pc: 0x0202,
                sp: 0xFF,
                p: status::U,
                ..Default::default()
            })
            .with_expected_mem(0x4000, 0xCC)
            .with_cycles(6),
    );

    // STA (Indirect),Y
    cases.push(
        TestCase::new("STA ($20),Y Y=4", vec![0x91, 0x20])
            .with_initial(StateSnapshot {
                a: 0xDD,
                y: 4,
                pc: 0x0200,
                sp: 0xFF,
                p: status::U,
                ..Default::default()
            })
            .with_mem_patch(0x20, 0x00)
            .with_mem_patch(0x21, 0x50)
            .with_expected(StateSnapshot {
                a: 0xDD,
                y: 4,
                pc: 0x0202,
                sp: 0xFF,
                p: status::U,
                ..Default::default()
            })
            .with_expected_mem(0x5004, 0xDD)
            .with_cycles(6),
    );
}

fn push_cases_22(cases: &mut Vec<TestCase>) {

    // LDX Absolute
    cases.push(
        TestCase::new("LDX $1234", vec![0xAE, 0x34, 0x12])
            .with_initial(StateSnapshot {
                pc: 0x0200,
                sp: 0xFF,
                p: status::U,
                ..Default::default()
            })
            .with_mem_patch(0x1234, 0x66)
            .with_expected(StateSnapshot {
                x: 0x66,
                pc: 0x0203,
                sp: 0xFF,
                p: status::U,
                ..Default::default()
            })
            .with_cycles(4),
    );

    // LDX Absolute,Y
    cases.push(
        TestCase::new("LDX $1000,Y (Y=5)", vec![0xBE, 0x00, 0x10])
            .with_initial(StateSnapshot {
                y: 5,
                pc: 0x0200,
                sp: 0xFF,
                p: status::U,
                ..Default::default()
            })
            .with_mem_patch(0x1005, 0x77)
            .with_expected(StateSnapshot {
                x: 0x77,
                y: 5,
                pc: 0x0203,
                sp: 0xFF,
                p: status::U,
                ..Default::default()
            })
            .with_cycles(4),
    );

    // LDY Absolute
    cases.push(
        TestCase::new("LDY $1234", vec![0xAC, 0x34, 0x12])
            .with_initial(StateSnapshot {
                pc: 0x0200,
                sp: 0xFF,
                p: status::U,
                ..Default::default()
            })
            .with_mem_patch(0x1234, 0x11)
            .with_expected(StateSnapshot {
                y: 0x11,
                pc: 0x0203,
                sp: 0xFF,
                p: status::U,
                ..Default::default()
            })
            .with_cycles(4),
    );

    // LDY Zero Page,X
    cases.push(
        TestCase::new("LDY $10,X (X=3)", vec![0xB4, 0x10])
            .with_initial(StateSnapshot {
                x: 3,
                pc: 0x0200,
                sp: 0xFF,
                p: status::U,
                ..Default::default()
            })
            .with_mem_patch(0x13, 0x99)
            .with_expected(StateSnapshot {
                x: 3,
                y: 0x99,
                pc: 0x0202,
                sp: 0xFF,
                p: status::U | status::N,
                ..Default::default()
            })
            .with_cycles(4),
    );
}

fn push_cases_23(cases: &mut Vec<TestCase>) {

    // STX Absolute
    cases.push(
        TestCase::new("STX $1234", vec![0x8E, 0x34, 0x12])
            .with_initial(StateSnapshot {
                x: 0xA5,
                pc: 0x0200,
                sp: 0xFF,
                p: status::U,
                ..Default::default()
            })
            .with_expected(StateSnapshot {
                x: 0xA5,
                pc: 0x0203,
                sp: 0xFF,
                p: status::U,
                ..Default::default()
            })
            .with_expected_mem(0x1234, 0xA5)
            .with_cycles(4),
    );

    // STY Absolute
    cases.push(
        TestCase::new("STY $1234", vec![0x8C, 0x34, 0x12])
            .with_initial(StateSnapshot {
                y: 0x5A,
                pc: 0x0200,
                sp: 0xFF,
                p: status::U,
                ..Default::default()
            })
            .with_expected(StateSnapshot {
                y: 0x5A,
                pc: 0x0203,
                sp: 0xFF,
                p: status::U,
                ..Default::default()
            })
            .with_expected_mem(0x1234, 0x5A)
            .with_cycles(4),
    );

    // AND / ORA / EOR on Zero Page
    cases.push(
        TestCase::new("AND $50 (A=0xF0, mem=0x0F) → A=0", vec![0x25, 0x50])
            .with_initial(StateSnapshot {
                a: 0xF0,
                pc: 0x0200,
                sp: 0xFF,
                p: status::U,
                ..Default::default()
            })
            .with_mem_patch(0x50, 0x0F)
            .with_expected(StateSnapshot {
                a: 0x00,
                pc: 0x0202,
                sp: 0xFF,
                p: status::U | status::Z,
                ..Default::default()
            })
            .with_cycles(3),
    );

    // CMP ZeroPage
    cases.push(
        TestCase::new("CMP $50 (A=0x20, mem=0x20) → Z=1", vec![0xC5, 0x50])
            .with_initial(StateSnapshot {
                a: 0x20,
                pc: 0x0200,
                sp: 0xFF,
                p: status::U,
                ..Default::default()
            })
            .with_mem_patch(0x50, 0x20)
            .with_expected(StateSnapshot {
                a: 0x20,
                pc: 0x0202,
                sp: 0xFF,
                p: status::U | status::Z | status::C,
                ..Default::default()
            })
            .with_cycles(3),
    );
}

fn push_cases_24(cases: &mut Vec<TestCase>) {

    // PHP / PLP round-trip
    cases.push(
        TestCase::new("PHP pushes P with B|U set", vec![0x08])
            .with_initial(StateSnapshot {
                pc: 0x0200,
                sp: 0xFF,
                p: status::U | status::N,
                ..Default::default()
            })
            .with_expected(StateSnapshot {
                pc: 0x0201,
                sp: 0xFE,
                p: status::U | status::N,
                ..Default::default()
            })
            .with_expected_mem(0x01FF, status::U | status::N | status::B)
            .with_cycles(3),
    );

    // ROL memory
    cases.push(
        TestCase::new("ROL $50 (mem=0x40, C=0)", vec![0x26, 0x50])
            .with_initial(StateSnapshot {
                pc: 0x0200,
                sp: 0xFF,
                p: status::U,
                ..Default::default()
            })
            .with_mem_patch(0x50, 0x40)
            .with_expected(StateSnapshot {
                pc: 0x0202,
                sp: 0xFF,
                p: status::U | status::N,
                ..Default::default()
            })
            .with_expected_mem(0x50, 0x80)
            .with_cycles(5),
    );

    // INC Absolute
    cases.push(
        TestCase::new("INC $1234 (mem=0x7F)", vec![0xEE, 0x34, 0x12])
            .with_initial(StateSnapshot {
                pc: 0x0200,
                sp: 0xFF,
                p: status::U,
                ..Default::default()
            })
            .with_mem_patch(0x1234, 0x7F)
            .with_expected(StateSnapshot {
                pc: 0x0203,
                sp: 0xFF,
                p: status::U | status::N,
                ..Default::default()
            })
            .with_expected_mem(0x1234, 0x80)
            .with_cycles(6),
    );

    // DEC Absolute
    cases.push(
        TestCase::new("DEC $1234 (mem=0x80)", vec![0xCE, 0x34, 0x12])
            .with_initial(StateSnapshot {
                pc: 0x0200,
                sp: 0xFF,
                p: status::U,
                ..Default::default()
            })
            .with_mem_patch(0x1234, 0x80)
            .with_expected(StateSnapshot {
                pc: 0x0203,
                sp: 0xFF,
                p: status::U,
                ..Default::default()
            })
            .with_expected_mem(0x1234, 0x7F)
            .with_cycles(6),
    );
}

fn push_cases_25(cases: &mut Vec<TestCase>) {
    push_cases_25a(cases);
    push_cases_25b(cases);
}

fn push_cases_25a(cases: &mut Vec<TestCase>) {

    // BIT Absolute
    cases.push(
        TestCase::new(
            "BIT $1234 (A=0xFF, mem=0x3F) → Z=0, V=1, N=0",
            vec![0x2C, 0x34, 0x12],
        )
        .with_initial(StateSnapshot {
            a: 0xFF,
            pc: 0x0200,
            sp: 0xFF,
            p: status::U,
            ..Default::default()
        })
        .with_mem_patch(0x1234, 0x7F)
        .with_expected(StateSnapshot {
            a: 0xFF,
            pc: 0x0203,
            sp: 0xFF,
            p: status::U | status::V,
            ..Default::default()
        })
        .with_cycles(4),
    );

    // INX
    cases.push(
        TestCase::new("INX (X=0x04) → X=0x05, Z=0, N=0", vec![0xE8])
            .with_initial(StateSnapshot {
                x: 0x04,
                pc: 0x0200,
                sp: 0xFF,
                p: status::U,
                ..Default::default()
            })
            .with_expected(StateSnapshot {
                x: 0x05,
                pc: 0x0201,
                sp: 0xFF,
                p: status::U,
                ..Default::default()
            })
            .with_cycles(2),
    );

    // INY
    cases.push(
        TestCase::new("INY (Y=0xFF) → Y=0x00, Z=1, N=0", vec![0xC8])
            .with_initial(StateSnapshot {
                y: 0xFF,
                pc: 0x0200,
                sp: 0xFF,
                p: status::U,
                ..Default::default()
            })
            .with_expected(StateSnapshot {
                y: 0x00,
                pc: 0x0201,
                sp: 0xFF,
                p: status::U | status::Z,
                ..Default::default()
            })
            .with_cycles(2),
    );

    // DEX
}

fn push_cases_25b(cases: &mut Vec<TestCase>) {
    cases.push(
        TestCase::new("DEX (X=0x01) → X=0x00, Z=1, N=0", vec![0xCA])
            .with_initial(StateSnapshot {
                x: 0x01,
                pc: 0x0200,
                sp: 0xFF,
                p: status::U,
                ..Default::default()
            })
            .with_expected(StateSnapshot {
                x: 0x00,
                pc: 0x0201,
                sp: 0xFF,
                p: status::U | status::Z,
                ..Default::default()
            })
            .with_cycles(2),
    );

    // DEY
    cases.push(
        TestCase::new("DEY (Y=0x80) → Y=0x7F, Z=0, N=0", vec![0x88])
            .with_initial(StateSnapshot {
                y: 0x80,
                pc: 0x0200,
                sp: 0xFF,
                p: status::U | status::N,
                ..Default::default()
            })
            .with_expected(StateSnapshot {
                y: 0x7F,
                pc: 0x0201,
                sp: 0xFF,
                p: status::U,
                ..Default::default()
            })
            .with_cycles(2),
    );

    // TAX
    cases.push(
        TestCase::new("TAX (A=0x33) → X=0x33, Z=0, N=0", vec![0xAA])
            .with_initial(StateSnapshot {
                a: 0x33,
                pc: 0x0200,
                sp: 0xFF,
                p: status::U,
                ..Default::default()
            })
            .with_expected(StateSnapshot {
                a: 0x33,
                x: 0x33,
                pc: 0x0201,
                sp: 0xFF,
                p: status::U,
                ..Default::default()
            })
            .with_cycles(2),
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Unit tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn runner() -> TestRunner {
        TestRunner::new()
    }

    #[test]
    fn test_all_builtin_cases() {
        let cases = builtin_test_cases();
        assert!(
            cases.len() >= 100,
            "expected >=100 test cases, got {}",
            cases.len()
        );
        let mut r = runner();
        let report = TestReport::new(r.run_all(&cases));
        if !report.all_passed() {
            for f in report.failures() {
                eprintln!("{f}");
            }
        }
        assert!(
            report.all_passed(),
            "{}/{} test cases failed",
            report.failed(),
            report.total()
        );
    }

    #[test]
    fn test_flag_checker_all_match() {
        let errs = FlagChecker::check(0b1100_0001, 0b1100_0001, "test");
        assert!(errs.is_empty());
    }

    #[test]
    fn test_flag_checker_mismatch() {
        let errs = FlagChecker::check(0b0000_0001, 0b1000_0001, "test");
        assert!(!errs.is_empty());
    }

    #[test]
    fn test_cycle_counter_record_and_average() {
        let mut cc = CycleCounter::new();
        cc.record(0xA9, 2);
        cc.record(0xA9, 2);
        assert!(cc.average(0xA9).is_some_and(|v| (v - 2.0).abs() < f64::EPSILON));
        assert_eq!(cc.average(0xEA), None);
    }

    #[test]
    fn test_cycle_counter_verify() {
        assert!(CycleCounter::verify(2, 2));
        assert!(CycleCounter::verify(4, 5)); // page cross
        assert!(!CycleCounter::verify(2, 3));
        assert!(CycleCounter::verify(-1, 99));
    }

    #[test]
    fn test_flag_checker_flags_set_clear() {
        let p = status::N | status::U | status::C;
        assert!(FlagChecker::flags_set(p, status::N | status::C));
        assert!(!FlagChecker::flags_set(p, status::Z));
        assert!(FlagChecker::flags_clear(p, status::Z | status::V));
        assert!(!FlagChecker::flags_clear(p, status::N));
    }

    #[test]
    fn test_lda_immediate_zero_flag() {
        let cases = builtin_test_cases();
        let tc = cases.iter().find(|c| c.name.contains("LDA #$00")).unwrap();
        let result = runner().run(tc);
        assert!(result.passed, "{result}");
    }

    #[test]
    fn test_lda_immediate_negative_flag() {
        let cases = builtin_test_cases();
        let tc = cases.iter().find(|c| c.name.contains("#$80")).unwrap();
        let result = runner().run(tc);
        assert!(result.passed, "{result}");
    }

    #[test]
    fn test_adc_carry_out() {
        let cases = builtin_test_cases();
        let tc = cases.iter().find(|c| c.name.contains("carry out")).unwrap();
        let result = runner().run(tc);
        assert!(result.passed, "{result}");
    }

    #[test]
    fn test_adc_overflow() {
        let cases = builtin_test_cases();
        let tc = cases.iter().find(|c| c.name.contains("ADC #$7F")).unwrap();
        let result = runner().run(tc);
        assert!(result.passed, "{result}");
    }

    #[test]
    fn test_sbc_underflow() {
        let cases = builtin_test_cases();
        let tc = cases.iter().find(|c| c.name.contains("underflow")).unwrap();
        let result = runner().run(tc);
        assert!(result.passed, "{result}");
    }

    #[test]
    fn test_branch_taken() {
        let cases = builtin_test_cases();
        let tc = cases.iter().find(|c| c.name.contains("BNE taken")).unwrap();
        let result = runner().run(tc);
        assert!(result.passed, "{result}");
    }

    #[test]
    fn test_branch_not_taken() {
        let cases = builtin_test_cases();
        let tc = cases
            .iter()
            .find(|c| c.name.contains("BNE not-taken"))
            .unwrap();
        let result = runner().run(tc);
        assert!(result.passed, "{result}");
    }

    #[test]
    fn test_jmp_absolute() {
        let cases = builtin_test_cases();
        let tc = cases.iter().find(|c| c.name.contains("JMP $1234")).unwrap();
        let result = runner().run(tc);
        assert!(result.passed, "{result}");
    }

    #[test]
    fn test_pha_stack() {
        let cases = builtin_test_cases();
        let tc = cases.iter().find(|c| c.name.contains("PHA")).unwrap();
        let result = runner().run(tc);
        assert!(result.passed, "{result}");
    }

    #[test]
    fn test_pla_stack() {
        let cases = builtin_test_cases();
        let tc = cases.iter().find(|c| c.name.contains("PLA")).unwrap();
        let result = runner().run(tc);
        assert!(result.passed, "{result}");
    }

    #[test]
    fn test_inc_wrap_zero_flag() {
        let cases = builtin_test_cases();
        let tc = cases
            .iter()
            .find(|c| c.name.contains("wraps to 0"))
            .unwrap();
        let result = runner().run(tc);
        assert!(result.passed, "{result}");
    }

    #[test]
    fn test_rol_memory() {
        let cases = builtin_test_cases();
        let tc = cases.iter().find(|c| c.name.contains("ROL $50")).unwrap();
        let result = runner().run(tc);
        assert!(result.passed, "{result}");
    }

    #[test]
    fn test_jmp_indirect_page_wrap_bug() {
        let cases = builtin_test_cases();
        let tc = cases
            .iter()
            .find(|c| c.name.contains("page-wrap bug"))
            .unwrap();
        let result = runner().run(tc);
        assert!(result.passed, "{result}");
    }

    #[test]
    fn test_txs_no_flags() {
        // TXS must not alter status flags.
        let cases = builtin_test_cases();
        let tc = cases.iter().find(|c| c.name.contains("TXS")).unwrap();
        let result = runner().run(tc);
        assert!(result.passed, "{result}");
    }

    #[test]
    fn test_bit_zero_page() {
        let cases = builtin_test_cases();
        let tc = cases.iter().find(|c| c.name.contains("BIT $50")).unwrap();
        let result = runner().run(tc);
        assert!(result.passed, "{result}");
    }

    #[test]
    fn test_report_summary() {
        let cases = builtin_test_cases();
        let mut r = runner();
        let results = r.run_all(&cases);
        let report = TestReport::new(results);
        assert_eq!(report.total(), cases.len());
        assert!(report.all_passed(), "Summary: {report}");
    }

    #[test]
    fn test_state_snapshot_builder() {
        let s = StateSnapshot::default()
            .with_a(1)
            .with_x(2)
            .with_y(3)
            .with_sp(0xFD)
            .with_pc(0x1000)
            .with_p(0x24);
        assert_eq!(s.a, 1);
        assert_eq!(s.x, 2);
        assert_eq!(s.y, 3);
        assert_eq!(s.sp, 0xFD);
        assert_eq!(s.pc, 0x1000);
        assert_eq!(s.p, 0x24);
    }

    #[test]
    fn test_state_snapshot_apply() {
        let snap = StateSnapshot::default()
            .with_a(42)
            .with_pc(0x0300)
            .with_sp(0xFC)
            .with_p(status::U);
        let mut cpu = Cpu6502State::default();
        snap.apply_to(&mut cpu);
        assert_eq!(cpu.a, 42);
        assert_eq!(cpu.pc, 0x0300);
        assert_eq!(cpu.sp, 0xFC);
    }

    #[test]
    fn test_test_case_builder() {
        let tc = TestCase::new("dummy", vec![0xEA])
            .with_initial(
                StateSnapshot::default()
                    .with_pc(0x300)
                    .with_sp(0xFF)
                    .with_p(status::U),
            )
            .with_expected(
                StateSnapshot::default()
                    .with_pc(0x301)
                    .with_sp(0xFF)
                    .with_p(status::U),
            )
            .with_cycles(2);
        assert_eq!(tc.expected_cycles, 2);
        assert_eq!(tc.program, vec![0xEA]);
    }

    #[test]
    fn test_lda_zp_x_addressing() {
        let cases = builtin_test_cases();
        let tc = cases.iter().find(|c| c.name.contains("LDA $10,X")).unwrap();
        let result = runner().run(tc);
        assert!(result.passed, "{result}");
    }

    #[test]
    fn test_lda_indirect_x() {
        let cases = builtin_test_cases();
        let tc = cases
            .iter()
            .find(|c| c.name.contains("LDA ($10,X)"))
            .unwrap();
        let result = runner().run(tc);
        assert!(result.passed, "{result}");
    }

    #[test]
    fn test_lda_indirect_y() {
        let cases = builtin_test_cases();
        let tc = cases
            .iter()
            .find(|c| c.name.contains("LDA ($20),Y"))
            .unwrap();
        let result = runner().run(tc);
        assert!(result.passed, "{result}");
    }

    #[test]
    fn test_asl_memory() {
        let cases = builtin_test_cases();
        let tc = cases.iter().find(|c| c.name.contains("ASL $50")).unwrap();
        let result = runner().run(tc);
        assert!(result.passed, "{result}");
    }

    #[test]
    fn test_lsr_memory() {
        let cases = builtin_test_cases();
        let tc = cases.iter().find(|c| c.name.contains("LSR $50")).unwrap();
        let result = runner().run(tc);
        assert!(result.passed, "{result}");
    }

    #[test]
    fn test_inc_absolute() {
        let cases = builtin_test_cases();
        let tc = cases.iter().find(|c| c.name.contains("INC $1234")).unwrap();
        let result = runner().run(tc);
        assert!(result.passed, "{result}");
    }

    #[test]
    fn test_dec_absolute() {
        let cases = builtin_test_cases();
        let tc = cases.iter().find(|c| c.name.contains("DEC $1234")).unwrap();
        let result = runner().run(tc);
        assert!(result.passed, "{result}");
    }

    #[test]
    fn test_php_sets_break_bit() {
        let cases = builtin_test_cases();
        let tc = cases
            .iter()
            .find(|c| c.name.contains("PHP pushes P"))
            .unwrap();
        let result = runner().run(tc);
        assert!(result.passed, "{result}");
    }

    #[test]
    fn test_cmp_zeropage() {
        let cases = builtin_test_cases();
        let tc = cases.iter().find(|c| c.name.contains("CMP $50")).unwrap();
        let result = runner().run(tc);
        assert!(result.passed, "{result}");
    }

    #[test]
    fn test_eor_immediate_zero() {
        let cases = builtin_test_cases();
        let tc = cases.iter().find(|c| c.name.contains("EOR #$FF")).unwrap();
        let result = runner().run(tc);
        assert!(result.passed, "{result}");
    }

    #[test]
    fn test_sta_indirect_y() {
        let cases = builtin_test_cases();
        let tc = cases
            .iter()
            .find(|c| c.name.contains("STA ($20),Y"))
            .unwrap();
        let result = runner().run(tc);
        assert!(result.passed, "{result}");
    }
}
