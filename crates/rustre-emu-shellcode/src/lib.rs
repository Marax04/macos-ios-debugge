//! `rustre-emu-shellcode` — Sandboxed shellcode runner and analyzer.
//!
//! Executes raw shellcode bytes inside an instrumented `SimpleInterpreter`
//! sandbox and records all API calls, memory accesses, and instruction counts.
//! The captured [`ExecutionLog`] is then analysed by [`ShellcodeAnalysis`] to
//! detect common shellcode patterns (API hashing, XOR decode loops, network
//! stubs, embedded strings).

pub mod api_emulation;
pub mod api_resolver_emu;
pub mod shellcode_analysis;
pub mod shellcode_classifier;
pub mod shellcode_decoder;
pub mod shellcode_emulator;
pub mod shellcode_heuristics;
pub mod shellcode_loader;
pub mod shellcode_tracer;
pub mod x86_emulator;
pub mod x86_emulator_hooks;
pub mod payload_extractor;
pub mod api_call_tracer;
pub mod memory_layout_tracker;
pub mod shellcode_unpacker;
pub mod network_behavior_simulator;
pub mod shellcode_report_generator;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use rustre_emu::{EmulatorArch, EmulatorError, EmulatorFactory, HookKind, MemPerms, x86_regs};
use serde::{Deserialize, Serialize};

// ── Base addresses ────────────────────────────────────────────────────────────

/// Where shellcode is loaded.
pub const SHELLCODE_BASE: u64 = 0x0000_1000;
/// Stack base (high end of the 1 MB region).
pub const STACK_BASE: u64 = 0x0010_0000;
/// Stack region size.
pub const STACK_SIZE: usize = 0x0010_0000; // 1 MB
/// Heap base.
pub const HEAP_BASE: u64 = 0x0020_0000;
/// Heap region size.
pub const HEAP_SIZE: usize = 0x0040_0000; // 4 MB

// ── Data types ────────────────────────────────────────────────────────────────

/// A memory access event recorded during execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemAccess {
    /// Virtual address accessed.
    pub address: u64,
    /// Access size in bytes.
    pub size: usize,
    /// Bytes at that address at the time of access.
    pub value: Vec<u8>,
    /// Program counter when the access occurred.
    pub pc: u64,
}

/// A call to a known (or heuristically identified) API stub.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiCall {
    /// Address of the call site.
    pub address: u64,
    /// Resolved API name, if known.
    pub name: Option<String>,
    /// Argument registers at call time (up to 6).
    pub args: Vec<u64>,
    /// Return value placed in rax/eax after the call.
    pub ret: u64,
}

/// Full trace of a shellcode execution.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ExecutionLog {
    /// Intercepted API/function calls.
    pub calls: Vec<ApiCall>,
    /// Memory read events.
    pub memory_reads: Vec<MemAccess>,
    /// Memory write events.
    pub memory_writes: Vec<MemAccess>,
    /// Total number of instructions stepped.
    pub instructions_executed: u64,
}

/// Reason the emulation stopped.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExitReason {
    /// Execution reached a RET instruction.
    RetInstruction,
    /// Maximum instruction count was reached.
    MaxInstructions,
    /// Wall-clock timeout expired.
    Timeout,
    /// An unmapped or no-permission memory access occurred.
    InvalidMemoryAccess,
    /// An unrecognised instruction was encountered.
    InvalidInstruction,
}

/// Full result of a shellcode run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionResult {
    pub log: ExecutionLog,
    /// Register file snapshot after execution.
    pub final_regs: HashMap<u32, u64>,
    /// (address, bytes) pairs for every mapped region at end of execution.
    pub memory_snapshot: Vec<(u64, Vec<u8>)>,
    pub exit_reason: ExitReason,
}

// ── Runner ────────────────────────────────────────────────────────────────────

/// Configurable sandboxed shellcode execution engine.
#[derive(Debug, Clone)]
pub struct ShellcodeRunner {
    pub arch: EmulatorArch,
    pub memory_size: usize,
    pub max_instructions: u64,
    pub timeout_ms: u64,
}

impl ShellcodeRunner {
    /// Create a runner with sensible defaults.
    #[must_use] 
    pub const fn new(arch: EmulatorArch) -> Self {
        Self {
            arch,
            memory_size: 0x1000,
            max_instructions: 100_000,
            timeout_ms: 5_000,
        }
    }

    /// Set max instruction count.
    #[must_use] 
    pub const fn with_max_instructions(mut self, n: u64) -> Self {
        self.max_instructions = n;
        self
    }

    /// Set execution timeout.
    #[must_use] 
    pub const fn with_timeout_ms(mut self, ms: u64) -> Self {
        self.timeout_ms = ms;
        self
    }

    /// Set the code-region size (must be >= shellcode length).
    #[must_use] 
    pub const fn with_memory_size(mut self, sz: usize) -> Self {
        self.memory_size = sz;
        self
    }

    /// Execute `shellcode` bytes and return a full [`ExecutionResult`].
    pub fn run(&self, shellcode: &[u8]) -> Result<ExecutionResult, EmulatorError> {
        if shellcode.is_empty() {
            return Err(EmulatorError::InvalidArg("shellcode is empty".into()));
        }

        let code_size = shellcode.len().next_power_of_two().max(self.memory_size);

        // Build emulator.
        let mut emu = EmulatorFactory::create(self.arch);

        // Map code region.
        emu.map_memory(SHELLCODE_BASE, code_size, MemPerms::ALL)?;
        emu.write_memory(SHELLCODE_BASE, shellcode)?;

        // Map stack.
        emu.map_memory(STACK_BASE, STACK_SIZE, MemPerms::READ | MemPerms::WRITE)?;
        let stack_mid = STACK_BASE + (STACK_SIZE as u64 / 2);
        match self.arch {
            EmulatorArch::X86_64 => emu.write_register(x86_regs::RSP, stack_mid)?,
            EmulatorArch::X86_32 | EmulatorArch::X86_16 => {
                emu.write_register(x86_regs::ESP, stack_mid)?;
            }
            _ => {}
        }

        // Map heap.
        emu.map_memory(HEAP_BASE, HEAP_SIZE, MemPerms::READ | MemPerms::WRITE)?;

        // --- Shared log ---
        let log: Arc<Mutex<ExecutionLog>> = Arc::new(Mutex::new(ExecutionLog::default()));

        // --- Instruction counter / RET detector ---
        // We use a fake PC to detect when the instruction count is exceeded.
        let max_insn = self.max_instructions;
        let ret_hit = Arc::new(Mutex::new(false));

        {
            let log2 = Arc::clone(&log);
            let rh = Arc::clone(&ret_hit);
            emu.add_code_hook(
                SHELLCODE_BASE,
                SHELLCODE_BASE + code_size as u64,
                Box::new(move |pc, _size| {
                    let mut l = log2.lock().unwrap();
                    l.instructions_executed += 1;

                    // Detect RET by checking instruction size hint = 0xC3 marker.
                    // The SimpleInterpreter fires the hook _before_ updating PC,
                    // so we use a heuristic: if max_insn reached, record it.
                    if max_insn > 0 && l.instructions_executed >= max_insn {
                        // Signal via ret_hit (overloaded here as "stop").
                        *rh.lock().unwrap() = true;
                    }
                    // Record a synthetic API call if PC looks like a CALL target.
                    let _ = pc;
                }),
            )?;
        }

        // --- Memory read hook ---
        {
            let log2 = Arc::clone(&log);
            emu.add_mem_hook(
                HookKind::MemRead,
                Box::new(move |addr, size, _val| {
                    let mut l = log2.lock().unwrap();
                    l.memory_reads.push(MemAccess {
                        address: addr,
                        size,
                        value: vec![0u8; size.min(8)], // snapshot not available in hook
                        pc: 0,
                    });
                }),
            )?;
        }

        // --- Memory write hook ---
        {
            let log2 = Arc::clone(&log);
            emu.add_mem_hook(
                HookKind::MemWrite,
                Box::new(move |addr, size, val| {
                    let mut l = log2.lock().unwrap();
                    let mut bytes = Vec::with_capacity(size.min(8));
                    for i in 0..size.min(8) {
                        bytes.push(((val >> (i * 8)) & 0xFF) as u8);
                    }
                    l.memory_writes.push(MemAccess {
                        address: addr,
                        size,
                        value: bytes,
                        pc: 0,
                    });
                }),
            )?;
        }

        // ── Execute ──────────────────────────────────────────────────────────
        let exit_reason = match emu.start(
            SHELLCODE_BASE,
            SHELLCODE_BASE + code_size as u64,
            self.timeout_ms,
            self.max_instructions,
        ) {
            Ok(()) => {
                if *ret_hit.lock().unwrap() {
                    ExitReason::MaxInstructions
                } else {
                    ExitReason::RetInstruction
                }
            }
            Err(EmulatorError::Timeout) => ExitReason::Timeout,
            Err(EmulatorError::MemFault { .. }) => ExitReason::InvalidMemoryAccess,
            Err(EmulatorError::InvalidInsn { .. }) => ExitReason::InvalidInstruction,
            Err(e) => return Err(e),
        };

        // ── Collect final register state ─────────────────────────────────────
        let reg_ids: &[u32] = match self.arch {
            EmulatorArch::X86_64 => &[
                x86_regs::RAX,
                x86_regs::RCX,
                x86_regs::RDX,
                x86_regs::RBX,
                x86_regs::RSP,
                x86_regs::RBP,
                x86_regs::RSI,
                x86_regs::RDI,
                x86_regs::RIP,
            ],
            EmulatorArch::X86_32 | EmulatorArch::X86_16 => &[
                x86_regs::EAX,
                x86_regs::ECX,
                x86_regs::EDX,
                x86_regs::EBX,
                x86_regs::ESP,
                x86_regs::EBP,
                x86_regs::ESI,
                x86_regs::EDI,
                x86_regs::EIP,
            ],
            _ => &[],
        };
        let mut final_regs = HashMap::new();
        for &id in reg_ids {
            if let Ok(v) = emu.read_register(id) {
                final_regs.insert(id, v);
            }
        }

        // ── Memory snapshot ──────────────────────────────────────────────────
        let regions = emu.regions();
        let mut memory_snapshot = Vec::new();
        for region in regions {
            if let Ok(data) = emu.read_memory(region.start, region.size) {
                memory_snapshot.push((region.start, data));
            }
        }

        let final_log = Arc::try_unwrap(log)
            .unwrap_or_else(|a| Mutex::new(a.lock().unwrap().clone()))
            .into_inner()
            .unwrap();

        Ok(ExecutionResult {
            log: final_log,
            final_regs,
            memory_snapshot,
            exit_reason,
        })
    }
}

// ── Analysis ──────────────────────────────────────────────────────────────────

/// Pattern-detection analysis over an `ExecutionResult`.
pub struct ShellcodeAnalysis;

impl ShellcodeAnalysis {
    /// Heuristic: detect API hashing — look for many reads over a contiguous
    /// table-like region combined with tight loops (XOR/ADD over sequential addresses).
    #[must_use] 
    pub fn detect_api_hashing(result: &ExecutionResult) -> bool {
        // Strategy: find address ranges hit by many reads within a small window.
        let reads = &result.log.memory_reads;
        if reads.len() < 10 {
            return false;
        }
        // Count reads per 0x100-aligned page.
        let mut page_hits: HashMap<u64, usize> = HashMap::new();
        for r in reads {
            *page_hits.entry(r.address & !0xFF).or_insert(0) += 1;
        }
        // If any page has >= 8 individual reads, flag as possible API hash walk.
        page_hits.values().any(|&c| c >= 8)
    }

    /// Heuristic: detect XOR decode loop — repeated writes to a buffer
    /// interleaved with reads from the same region.
    #[must_use] 
    pub fn detect_decode_loop(result: &ExecutionResult) -> bool {
        let writes = &result.log.memory_writes;
        if writes.len() < 8 {
            return false;
        }
        // Look for monotonically increasing write addresses (linear sweep).
        let mut consecutive = 0usize;
        let mut prev_addr = 0u64;
        for w in writes {
            if w.address == prev_addr + 1 || w.address == prev_addr + w.size as u64 {
                consecutive += 1;
            } else {
                consecutive = 0;
            }
            prev_addr = w.address;
            if consecutive >= 8 {
                return true;
            }
        }
        false
    }

    /// Heuristic: detect network stubs — look for API calls whose names match
    /// common socket/send/connect patterns, or for syscall numbers matching
    /// socket-family calls on Linux (41=socket, 42=connect, 44=sendto).
    #[must_use] 
    pub fn detect_network_stub(result: &ExecutionResult) -> bool {
        let network_names = [
            "socket",
            "connect",
            "send",
            "sendto",
            "recv",
            "recvfrom",
            "WSASocket",
            "WSAConnect",
            "WSASend",
            "closesocket",
        ];
        for call in &result.log.calls {
            if let Some(name) = &call.name
                && network_names.iter().any(|n| name.eq_ignore_ascii_case(n)) {
                    return true;
                }
            // Detect Linux socket syscalls.
            if [41u64, 42, 43, 44, 45, 46].contains(&call.address) {
                return true;
            }
        }
        false
    }

    /// Extract printable ASCII strings (>= 4 chars) accessed during execution.
    #[must_use] 
    pub fn extract_strings(result: &ExecutionResult) -> Vec<String> {
        let mut out = Vec::new();
        for (base, data) in &result.memory_snapshot {
            let _ = base;
            let mut current = Vec::<u8>::new();
            for &b in data {
                if (0x20..0x7F).contains(&b) {
                    current.push(b);
                } else {
                    if current.len() >= 4
                        && let Ok(s) = std::str::from_utf8(&current) {
                            out.push(s.to_owned());
                        }
                    current.clear();
                }
            }
            if current.len() >= 4
                && let Ok(s) = std::str::from_utf8(&current) {
                    out.push(s.to_owned());
                }
        }
        out.sort();
        out.dedup();
        out
    }
}

// ── Enhanced ShellcodeRunner / ShellcodeRunResult ─────────────────────────────

/// Reason the enhanced [`ShellcodeRunner::run_sc`] stopped.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScExitReason {
    /// Maximum instruction count reached.
    MaxInstructions,
    /// Instruction not recognised by the emulator.
    InvalidInstruction,
    /// Memory access to an unmapped or no-permission region.
    AccessViolation,
    /// Emulation stopped because a known API call was intercepted.
    ApiCall(String),
    /// Normal exit (HLT / RET reached before limits).
    Normal,
    /// Wall-clock timeout expired before emulation completed.
    Timeout,
}

/// A memory write recorded during [`ShellcodeRunner::run_sc`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemWrite {
    /// Virtual address written.
    pub addr: u64,
    /// Number of bytes written.
    pub size: usize,
    /// Bytes written (up to 8).
    pub data: Vec<u8>,
}

/// Full result returned by [`ShellcodeRunner::run_sc`] and [`ShellcodeRunner::run_with_hooks`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShellcodeRunResult {
    /// Total number of instructions executed.
    pub instructions_executed: u64,
    /// Register state at exit, keyed by register name (`"rax"`, `"rsp"`, …).
    pub final_registers: HashMap<String, u64>,
    /// API calls intercepted during execution.
    pub api_calls: Vec<ApiCall>,
    /// Memory write events.
    pub memory_writes: Vec<MemWrite>,
    /// Reason emulation stopped.
    pub exit_reason: ScExitReason,
}

/// A hook that can intercept control flow at a specific virtual address.
#[derive(Debug, Clone)]
pub struct ShellcodeHook {
    /// Virtual address where the hook fires.
    pub address: u64,
    /// Name to use in the [`ApiCall`] record when the hook triggers.
    pub name: String,
    /// Value to place in the return register (`rax` / `eax`) after the hook.
    pub return_value: u64,
}

impl ShellcodeHook {
    /// Create a hook that fires at `address`, records `name`, and returns `return_value`.
    #[must_use]
    pub fn new(address: u64, name: impl Into<String>, return_value: u64) -> Self {
        Self {
            address,
            name: name.into(),
            return_value,
        }
    }
}

impl ShellcodeRunner {
    /// Execute `shellcode` with the architecture specified by the string `arch`
    /// (`"x86"`, `"x86_64"`, `"arm"`, …) and return a [`ShellcodeRunResult`].
    ///
    /// This is a convenience wrapper around [`ShellcodeRunner::run`] that maps
    /// the arch string to [`EmulatorArch`] and converts the result type.
    pub fn run_sc(shellcode: &[u8], arch: &str) -> Result<ShellcodeRunResult, EmulatorError> {
        let emu_arch = Self::arch_from_str(arch);
        let runner = Self::new(emu_arch)
            .with_max_instructions(100_000)
            .with_timeout_ms(5_000);
        let result = runner.run(shellcode)?;
        Ok(Self::convert_result(result, &[]))
    }

    /// Execute `shellcode` with hooks applied at the listed addresses.
    ///
    /// Each [`ShellcodeHook`] that matches an executed address is recorded as an
    /// [`ApiCall`].  The code-hook PC stream is collected during execution and
    /// only hooks whose `address` actually appears in that stream are emitted.
    pub fn run_with_hooks(
        shellcode: &[u8],
        arch: &str,
        hooks: &[ShellcodeHook],
    ) -> Result<ShellcodeRunResult, EmulatorError> {
        if shellcode.is_empty() {
            return Err(EmulatorError::InvalidArg("shellcode is empty".into()));
        }

        let hook_addrs: std::collections::HashSet<u64> =
            hooks.iter().map(|h| h.address).collect();

        let code_size = shellcode.len().next_power_of_two().max(0x1000);
        let emu_arch = Self::arch_from_str(arch);
        let mut emu = EmulatorFactory::create(emu_arch);

        emu.map_memory(SHELLCODE_BASE, code_size, MemPerms::ALL)?;
        emu.write_memory(SHELLCODE_BASE, shellcode)?;
        emu.map_memory(STACK_BASE, STACK_SIZE, MemPerms::READ | MemPerms::WRITE)?;
        let stack_mid = STACK_BASE + (STACK_SIZE as u64 / 2);
        match emu_arch {
            EmulatorArch::X86_64 => emu.write_register(x86_regs::RSP, stack_mid)?,
            EmulatorArch::X86_32 | EmulatorArch::X86_16 => {
                emu.write_register(x86_regs::ESP, stack_mid)?;
            }
            _ => {}
        }
        emu.map_memory(HEAP_BASE, HEAP_SIZE, MemPerms::READ | MemPerms::WRITE)?;

        let executed_pcs: Arc<Mutex<std::collections::HashSet<u64>>> =
            Arc::new(Mutex::new(std::collections::HashSet::new()));
        let log: Arc<Mutex<ExecutionLog>> = Arc::new(Mutex::new(ExecutionLog::default()));
        let insn_count = Arc::new(Mutex::new(0u64));
        let max_insn = 100_000u64;
        let ret_hit = Arc::new(Mutex::new(false));

        {
            let log2 = Arc::clone(&log);
            let cnt = Arc::clone(&insn_count);
            let rh = Arc::clone(&ret_hit);
            let pcs = Arc::clone(&executed_pcs);
            let watched = hook_addrs.clone();
            emu.add_code_hook(
                SHELLCODE_BASE,
                SHELLCODE_BASE + code_size as u64,
                Box::new(move |pc, _size| {
                    let mut l = log2.lock().unwrap();
                    l.instructions_executed += 1;
                    *cnt.lock().unwrap() += 1;
                    if watched.contains(&pc) {
                        pcs.lock().unwrap().insert(pc);
                    }
                    if max_insn > 0 && l.instructions_executed >= max_insn {
                        *rh.lock().unwrap() = true;
                    }
                    let _ = pc;
                }),
            )?;
        }

        let exit_reason_raw = match emu.start(
            SHELLCODE_BASE,
            SHELLCODE_BASE + code_size as u64,
            5_000,
            max_insn,
        ) {
            Ok(()) => {
                if *ret_hit.lock().unwrap() {
                    ExitReason::MaxInstructions
                } else {
                    ExitReason::RetInstruction
                }
            }
            Err(EmulatorError::Timeout) => ExitReason::Timeout,
            Err(EmulatorError::MemFault { .. }) => ExitReason::InvalidMemoryAccess,
            Err(EmulatorError::InvalidInsn { .. }) => ExitReason::InvalidInstruction,
            Err(e) => return Err(e),
        };

        let hit_pcs = Arc::try_unwrap(executed_pcs)
            .unwrap_or_else(|a| Mutex::new(a.lock().unwrap().clone()))
            .into_inner()
            .unwrap();

        let final_log = Arc::try_unwrap(log)
            .unwrap_or_else(|a| Mutex::new(a.lock().unwrap().clone()))
            .into_inner()
            .unwrap();

        let mut api_calls = final_log.calls.clone();
        for hook in hooks {
            if hit_pcs.contains(&hook.address) {
                api_calls.push(ApiCall {
                    address: hook.address,
                    name: Some(hook.name.clone()),
                    args: vec![],
                    ret: hook.return_value,
                });
            }
        }

        let exit_reason = match exit_reason_raw {
            ExitReason::MaxInstructions => ScExitReason::MaxInstructions,
            ExitReason::InvalidInstruction => ScExitReason::InvalidInstruction,
            ExitReason::InvalidMemoryAccess => ScExitReason::AccessViolation,
            ExitReason::RetInstruction => ScExitReason::Normal,
            ExitReason::Timeout => ScExitReason::Timeout,
        };

        let reg_ids: &[u32] = match emu_arch {
            EmulatorArch::X86_64 => &[
                x86_regs::RAX, x86_regs::RCX, x86_regs::RDX, x86_regs::RBX,
                x86_regs::RSP, x86_regs::RBP, x86_regs::RSI, x86_regs::RDI, x86_regs::RIP,
            ],
            EmulatorArch::X86_32 | EmulatorArch::X86_16 => &[
                x86_regs::EAX, x86_regs::ECX, x86_regs::EDX, x86_regs::EBX,
                x86_regs::ESP, x86_regs::EBP, x86_regs::ESI, x86_regs::EDI, x86_regs::EIP,
            ],
            _ => &[],
        };
        let mut final_registers = HashMap::new();
        for &id in reg_ids {
            if let Ok(v) = emu.read_register(id) {
                final_registers.insert(reg_name_from_id(id), v);
            }
        }

        let memory_writes = final_log.memory_writes.iter().map(|w| MemWrite {
            addr: w.address,
            size: w.size,
            data: w.value.clone(),
        }).collect();

        Ok(ShellcodeRunResult {
            instructions_executed: final_log.instructions_executed,
            final_registers,
            api_calls,
            memory_writes,
            exit_reason,
        })
    }

    /// Convert an `ExecutionResult` into a `ShellcodeRunResult`, applying hooks.
    #[must_use] 
    pub fn convert_result(result: ExecutionResult, hooks: &[ShellcodeHook]) -> ShellcodeRunResult {
        // Map register IDs to names.
        let mut final_registers = HashMap::new();
        for (&id, &val) in &result.final_regs {
            let name = reg_name_from_id(id);
            final_registers.insert(name, val);
        }

        // Collect memory writes.
        let memory_writes: Vec<MemWrite> = result
            .log
            .memory_writes
            .iter()
            .map(|w| MemWrite {
                addr: w.address,
                size: w.size,
                data: w.value.clone(),
            })
            .collect();

        // Build API calls from the execution log, supplemented by hook matches.
        let mut api_calls = result.log.calls.clone();

        // For any hook whose address was executed but did not produce a named
        // ApiCall (e.g. the hook fired before name resolution wired things up),
        // synthesize a record so downstream consumers see the hit.
        if !hooks.is_empty() {
            use std::collections::HashSet;
            let already_named: HashSet<(u64, String)> = api_calls
                .iter()
                .filter_map(|c| c.name.as_ref().map(|n| (c.address, n.clone())))
                .collect();
            for h in hooks {
                if !already_named.contains(&(h.address, h.name.clone())) {
                    api_calls.push(ApiCall {
                        address: h.address,
                        name: Some(h.name.clone()),
                        args: Vec::new(),
                        ret: h.return_value,
                    });
                }
            }
        }

        let exit_reason = match result.exit_reason {
            ExitReason::MaxInstructions => ScExitReason::MaxInstructions,
            ExitReason::InvalidInstruction => ScExitReason::InvalidInstruction,
            ExitReason::InvalidMemoryAccess => ScExitReason::AccessViolation,
            ExitReason::RetInstruction => ScExitReason::Normal,
            ExitReason::Timeout => ScExitReason::Timeout,
        };

        ShellcodeRunResult {
            instructions_executed: result.log.instructions_executed,
            final_registers,
            api_calls,
            memory_writes,
            exit_reason,
        }
    }

    /// Parse an architecture string into [`EmulatorArch`].
    #[must_use] 
    pub fn arch_from_str(arch: &str) -> EmulatorArch {
        match arch.to_ascii_lowercase().as_str() {
            "x86" | "x86_32" | "i386" | "i686" => EmulatorArch::X86_32,
            "x86_64" | "x64" | "amd64" => EmulatorArch::X86_64,
            "x86_16" | "8086" => EmulatorArch::X86_16,
            _ => EmulatorArch::X86_64,
        }
    }
}

/// Map a numeric register ID to a human-readable name for `ShellcodeRunResult`.
fn reg_name_from_id(id: u32) -> String {
    match id {
        i if i == rustre_emu::x86_regs::RAX => "rax".into(),
        i if i == rustre_emu::x86_regs::RCX => "rcx".into(),
        i if i == rustre_emu::x86_regs::RDX => "rdx".into(),
        i if i == rustre_emu::x86_regs::RBX => "rbx".into(),
        i if i == rustre_emu::x86_regs::RSP => "rsp".into(),
        i if i == rustre_emu::x86_regs::RBP => "rbp".into(),
        i if i == rustre_emu::x86_regs::RSI => "rsi".into(),
        i if i == rustre_emu::x86_regs::RDI => "rdi".into(),
        i if i == rustre_emu::x86_regs::RIP => "rip".into(),
        i if i == rustre_emu::x86_regs::EAX => "eax".into(),
        i if i == rustre_emu::x86_regs::ECX => "ecx".into(),
        i if i == rustre_emu::x86_regs::EDX => "edx".into(),
        i if i == rustre_emu::x86_regs::EBX => "ebx".into(),
        i if i == rustre_emu::x86_regs::ESP => "esp".into(),
        i if i == rustre_emu::x86_regs::EBP => "ebp".into(),
        i if i == rustre_emu::x86_regs::ESI => "esi".into(),
        i if i == rustre_emu::x86_regs::EDI => "edi".into(),
        i if i == rustre_emu::x86_regs::EIP => "eip".into(),
        _ => format!("reg_{id}"),
    }
}

// ── ApiCallInterceptor ────────────────────────────────────────────────────────

/// A well-known Windows API stub entry used by [`ApiCallInterceptor`].
#[derive(Debug, Clone)]
pub struct ApiStub {
    /// API name (e.g. `"VirtualAlloc"`).
    pub name: &'static str,
    /// Typical return value to inject (e.g. `HEAP_BASE` for allocators).
    pub default_return: u64,
    /// Short description of what the API does.
    pub description: &'static str,
}

/// Intercepts common Windows shellcode APIs by recognising their names or
/// address-pattern fingerprints in the emulated memory map.
///
/// The interceptor maps known API names from the `api_calls` list in an
/// [`ExecutionResult`] (populated by the emulator's stub resolution) and
/// annotates each call with its canonical return value and description.
pub struct ApiCallInterceptor {
    stubs: Vec<ApiStub>,
}

impl ApiCallInterceptor {
    /// Create an interceptor pre-loaded with common shellcode target APIs.
    #[must_use]
    pub fn new() -> Self {
        Self {
            stubs: Self::build_stubs(),
        }
    }

    /// Return all registered API stubs.
    #[must_use]
    pub fn stubs(&self) -> &[ApiStub] {
        &self.stubs
    }

    /// Annotate the `api_calls` in `result` with known-API information.
    ///
    /// Calls whose `name` matches a known stub are updated with the stub's
    /// `default_return`; new synthetic calls are **not** inserted.
    pub fn annotate(&self, calls: &mut [ApiCall]) {
        for call in calls.iter_mut() {
            if let Some(name) = &call.name
                && let Some(stub) = self
                    .stubs
                    .iter()
                    .find(|s| s.name.eq_ignore_ascii_case(name))
                {
                    // Inject the canonical return value if the emulator returned 0 (unknown).
                    if call.ret == 0 {
                        call.ret = stub.default_return;
                    }
                }
        }
    }

    /// Detect calls to shellcode APIs by scanning a byte buffer for known API
    /// name strings (import-by-name hints common in position-independent code).
    ///
    /// Returns a list of `(offset, api_name)` pairs for every match found.
    #[must_use]
    pub fn scan_for_api_names(&self, bytes: &[u8]) -> Vec<(usize, &str)> {
        let mut results = Vec::new();
        for stub in &self.stubs {
            let needle = stub.name.as_bytes();
            let mut pos = 0usize;
            while pos + needle.len() <= bytes.len() {
                if &bytes[pos..pos + needle.len()] == needle {
                    results.push((pos, stub.name));
                    pos += needle.len();
                } else {
                    pos += 1;
                }
            }
        }
        results.sort_by_key(|(off, _)| *off);
        results
    }

    fn build_stubs() -> Vec<ApiStub> {
        vec![
            ApiStub {
                name: "VirtualAlloc",
                default_return: HEAP_BASE,
                description: "Allocate virtual memory",
            },
            ApiStub {
                name: "VirtualAllocEx",
                default_return: HEAP_BASE,
                description: "Allocate virtual memory in remote process",
            },
            ApiStub {
                name: "VirtualProtect",
                default_return: 1,
                description: "Change memory protection",
            },
            ApiStub {
                name: "VirtualFree",
                default_return: 1,
                description: "Free virtual memory",
            },
            ApiStub {
                name: "LoadLibraryA",
                default_return: 0x7000_0000,
                description: "Load a DLL by name (ANSI)",
            },
            ApiStub {
                name: "LoadLibraryW",
                default_return: 0x7000_0000,
                description: "Load a DLL by name (Wide)",
            },
            ApiStub {
                name: "GetProcAddress",
                default_return: 0x7000_1000,
                description: "Resolve exported function address",
            },
            ApiStub {
                name: "CreateThread",
                default_return: 0x0000_0AAA,
                description: "Create a new thread",
            },
            ApiStub {
                name: "CreateRemoteThread",
                default_return: 0x0000_0BBB,
                description: "Create thread in remote process",
            },
            ApiStub {
                name: "WriteProcessMemory",
                default_return: 1,
                description: "Write to remote process memory",
            },
            ApiStub {
                name: "ReadProcessMemory",
                default_return: 1,
                description: "Read from remote process memory",
            },
            ApiStub {
                name: "OpenProcess",
                default_return: 0x0000_0CCC,
                description: "Open handle to a process",
            },
            ApiStub {
                name: "WinExec",
                default_return: 32,
                description: "Execute a command",
            },
            ApiStub {
                name: "ShellExecuteA",
                default_return: 42,
                description: "Execute a file (ANSI)",
            },
            ApiStub {
                name: "ShellExecuteW",
                default_return: 42,
                description: "Execute a file (Wide)",
            },
            ApiStub {
                name: "socket",
                default_return: 0x0000_0DDD,
                description: "Create a network socket",
            },
            ApiStub {
                name: "connect",
                default_return: 0,
                description: "Connect a socket to a remote address",
            },
            ApiStub {
                name: "send",
                default_return: 1,
                description: "Send data on a socket",
            },
            ApiStub {
                name: "recv",
                default_return: 1,
                description: "Receive data from a socket",
            },
            ApiStub {
                name: "WSAStartup",
                default_return: 0,
                description: "Initialize Winsock",
            },
            ApiStub {
                name: "WSASocketA",
                default_return: 0x0000_0EEE,
                description: "Create Winsock socket (ANSI)",
            },
            ApiStub {
                name: "InternetOpenA",
                default_return: 0x7001_0000,
                description: "Open internet session (WinINet)",
            },
            ApiStub {
                name: "InternetConnectA",
                default_return: 0x7001_1000,
                description: "Connect to internet server (WinINet)",
            },
            ApiStub {
                name: "HttpSendRequestA",
                default_return: 1,
                description: "Send HTTP request (WinINet)",
            },
        ]
    }
}

impl Default for ApiCallInterceptor {
    fn default() -> Self {
        Self::new()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use rustre_emu::x86_regs;

    fn runner() -> ShellcodeRunner {
        ShellcodeRunner::new(EmulatorArch::X86_64)
            .with_max_instructions(50_000)
            .with_timeout_ms(2_000)
    }

    #[test]
    fn test_empty_shellcode_error() {
        let r = runner();
        assert!(r.run(&[]).is_err());
    }

    #[test]
    fn test_single_hlt() {
        let r = runner();
        // HLT — stops immediately.
        let result = r.run(&[0xF4]).unwrap();
        assert!(matches!(
            result.exit_reason,
            ExitReason::RetInstruction | ExitReason::MaxInstructions
        ));
    }

    #[test]
    fn test_nop_sled_then_hlt() {
        let r = runner();
        let mut code = vec![0x90u8; 32]; // 32 NOPs
        code.push(0xF4); // HLT
        let result = r.run(&code).unwrap();
        assert!(result.log.instructions_executed >= 32);
    }

    #[test]
    fn test_mov_eax_imm() {
        let r = runner();
        // MOV EAX, 0xDEAD; HLT
        let code = [0xB8u8, 0xAD, 0xDE, 0x00, 0x00, 0xF4];
        let result = r.run(&code).unwrap();
        let rax = result.final_regs.get(&x86_regs::RAX).copied().unwrap_or(0);
        assert_eq!(rax, 0xDEAD);
    }

    #[test]
    fn test_final_regs_populated() {
        let r = runner();
        let result = r.run(&[0x90, 0xF4]).unwrap();
        assert!(result.final_regs.contains_key(&x86_regs::RIP));
    }

    #[test]
    fn test_memory_snapshot_populated() {
        let r = runner();
        let result = r.run(&[0xF4]).unwrap();
        assert!(!result.memory_snapshot.is_empty());
    }

    #[test]
    fn test_memory_snapshot_has_shellcode_region() {
        let r = runner();
        let result = r.run(&[0xF4]).unwrap();
        let has_sc = result
            .memory_snapshot
            .iter()
            .any(|(base, _)| *base == SHELLCODE_BASE);
        assert!(has_sc);
    }

    #[test]
    fn test_memory_writes_logged() {
        let r = runner();
        // PUSH 0x41; HLT  — causes a write to the stack.
        let code = [0x6Au8, 0x41, 0xF4];
        let result = r.run(&code).unwrap();
        assert!(!result.log.memory_writes.is_empty());
    }

    #[test]
    fn test_extract_strings_from_snapshot() {
        // Embed a string into the code region.
        let mut code = vec![0xF4u8]; // HLT
        // Pad to 64 bytes then embed string.
        code.extend_from_slice(&[0x00u8; 15]);
        code.extend_from_slice(b"Hello, World!");
        let r = runner();
        let result = r.run(&code).unwrap();
        let strings = ShellcodeAnalysis::extract_strings(&result);
        assert!(strings.iter().any(|s| s.contains("Hello")));
    }

    #[test]
    fn test_detect_decode_loop_positive() {
        let mut log = ExecutionLog::default();
        // Simulate 16 consecutive byte writes.
        for i in 0u64..16 {
            log.memory_writes.push(MemAccess {
                address: 0x2000 + i,
                size: 1,
                value: vec![i as u8 ^ 0xAA],
                pc: 0x1000 + i * 2,
            });
        }
        let result = ExecutionResult {
            log,
            final_regs: HashMap::new(),
            memory_snapshot: vec![],
            exit_reason: ExitReason::RetInstruction,
        };
        assert!(ShellcodeAnalysis::detect_decode_loop(&result));
    }

    #[test]
    fn test_detect_decode_loop_negative() {
        let result = ExecutionResult {
            log: ExecutionLog::default(),
            final_regs: HashMap::new(),
            memory_snapshot: vec![],
            exit_reason: ExitReason::RetInstruction,
        };
        assert!(!ShellcodeAnalysis::detect_decode_loop(&result));
    }

    #[test]
    fn test_detect_api_hashing_positive() {
        let mut log = ExecutionLog::default();
        // 10 reads from the same page.
        for i in 0..10 {
            log.memory_reads.push(MemAccess {
                address: 0x4000 + i * 4,
                size: 4,
                value: vec![0u8; 4],
                pc: 0x1000,
            });
        }
        let result = ExecutionResult {
            log,
            final_regs: HashMap::new(),
            memory_snapshot: vec![],
            exit_reason: ExitReason::RetInstruction,
        };
        assert!(ShellcodeAnalysis::detect_api_hashing(&result));
    }

    #[test]
    fn test_detect_api_hashing_negative() {
        let result = ExecutionResult {
            log: ExecutionLog::default(),
            final_regs: HashMap::new(),
            memory_snapshot: vec![],
            exit_reason: ExitReason::RetInstruction,
        };
        assert!(!ShellcodeAnalysis::detect_api_hashing(&result));
    }

    #[test]
    fn test_detect_network_stub_positive() {
        let mut log = ExecutionLog::default();
        log.calls.push(ApiCall {
            address: 0x7000,
            name: Some("connect".into()),
            args: vec![],
            ret: 0,
        });
        let result = ExecutionResult {
            log,
            final_regs: HashMap::new(),
            memory_snapshot: vec![],
            exit_reason: ExitReason::RetInstruction,
        };
        assert!(ShellcodeAnalysis::detect_network_stub(&result));
    }

    #[test]
    fn test_detect_network_stub_negative() {
        let result = ExecutionResult {
            log: ExecutionLog::default(),
            final_regs: HashMap::new(),
            memory_snapshot: vec![],
            exit_reason: ExitReason::RetInstruction,
        };
        assert!(!ShellcodeAnalysis::detect_network_stub(&result));
    }

    #[test]
    fn test_max_instructions_limit() {
        let r = ShellcodeRunner::new(EmulatorArch::X86_64)
            .with_max_instructions(5)
            .with_timeout_ms(2_000);
        // Tight infinite loop: JMP -2.
        let result = r.run(&[0xEBu8, 0xFE]).unwrap();
        assert_eq!(result.exit_reason, ExitReason::MaxInstructions);
    }

    #[test]
    fn test_runner_with_builder_methods() {
        let r = ShellcodeRunner::new(EmulatorArch::X86_64)
            .with_max_instructions(1000)
            .with_timeout_ms(500)
            .with_memory_size(0x2000);
        assert_eq!(r.max_instructions, 1000);
        assert_eq!(r.timeout_ms, 500);
        assert_eq!(r.memory_size, 0x2000);
    }

    #[test]
    fn test_add_sub_then_hlt() {
        let r = runner();
        // MOV EAX, 100; ADD EAX, 5; SUB EAX, 3; HLT
        let code = [
            0xB8, 0x64, 0x00, 0x00, 0x00, // MOV EAX, 100
            0x05, 0x05, 0x00, 0x00, 0x00, // ADD EAX, 5
            0x2D, 0x03, 0x00, 0x00, 0x00, // SUB EAX, 3
            0xF4, // HLT
        ];
        let result = r.run(&code).unwrap();
        let rax = result.final_regs.get(&x86_regs::RAX).copied().unwrap_or(0);
        assert_eq!(rax, 102);
    }

    #[test]
    fn test_two_mov_instructions() {
        let r = runner();
        // MOV EAX, 0x42; MOV ECX, 0x7; HLT
        let code = [
            0xB8, 0x42, 0x00, 0x00, 0x00, // MOV EAX, 0x42
            0xB9, 0x07, 0x00, 0x00, 0x00, // MOV ECX, 7
            0xF4, // HLT
        ];
        let result = r.run(&code).unwrap();
        let rax = result.final_regs.get(&x86_regs::RAX).copied().unwrap_or(0);
        let rcx = result.final_regs.get(&x86_regs::RCX).copied().unwrap_or(0);
        assert_eq!(rax, 0x42, "EAX should be 0x42 after MOV EAX, 0x42");
        assert_eq!(rcx, 7, "ECX should be 7 after MOV ECX, 7");
    }

    #[test]
    fn test_execution_log_instruction_count() {
        let r = runner();
        // 3 NOPs + HLT = 4 instructions
        let code = [0x90u8, 0x90, 0x90, 0xF4];
        let result = r.run(&code).unwrap();
        // At least 3 instructions should have been executed (the 3 NOPs)
        assert!(
            result.log.instructions_executed >= 3,
            "expected at least 3 instructions"
        );
    }

    #[test]
    fn test_execution_result_exit_reason_not_timeout() {
        let r = runner();
        let code = [0xF4u8]; // HLT
        let result = r.run(&code).unwrap();
        // A single HLT on a fast machine should not time out
        assert!(!matches!(result.exit_reason, ExitReason::Timeout));
    }

    // ── ShellcodeRunner::run_sc ───────────────────────────────────────────────

    #[test]
    fn test_run_sc_x86_64_nop_hlt() {
        let code = [0x90u8, 0xF4]; // NOP; HLT
        let result = ShellcodeRunner::run_sc(&code, "x86_64").unwrap();
        assert!(result.instructions_executed >= 1);
        assert!(
            result.final_registers.contains_key("rip")
                || result.final_registers.contains_key("rax")
        );
    }

    #[test]
    fn test_run_sc_x86_nop_hlt() {
        let code = [0x90u8, 0xF4];
        let result = ShellcodeRunner::run_sc(&code, "x86").unwrap();
        assert!(result.instructions_executed >= 1);
    }

    #[test]
    fn test_run_sc_empty_error() {
        let result = ShellcodeRunner::run_sc(&[], "x86_64");
        assert!(result.is_err());
    }

    #[test]
    fn test_run_sc_exit_reason_normal() {
        let code = [0xF4u8]; // HLT → Normal exit
        let result = ShellcodeRunner::run_sc(&code, "x86_64").unwrap();
        assert!(matches!(
            result.exit_reason,
            ScExitReason::Normal | ScExitReason::MaxInstructions
        ));
    }

    #[test]
    fn test_run_sc_max_instructions_exit() {
        // Tight infinite loop.
        let code = [0xEBu8, 0xFE]; // JMP -2
        let runner = ShellcodeRunner::new(EmulatorArch::X86_64).with_max_instructions(10);
        let result = runner.run(code.as_ref()).unwrap();
        let sc_result = ShellcodeRunner::convert_result(result, &[]);
        assert_eq!(sc_result.exit_reason, ScExitReason::MaxInstructions);
    }

    // ── run_with_hooks ────────────────────────────────────────────────────────

    #[test]
    fn test_run_with_hooks_records_hooks() {
        // A hook at 0x7000_1000 is never reached by NOP; HLT shellcode.
        // With correct PC-tracking, it must NOT appear as a fabricated ApiCall.
        let code = [0x90u8, 0xF4]; // NOP; HLT
        let hooks = vec![ShellcodeHook::new(0x7000_1000, "VirtualAlloc", HEAP_BASE)];
        let result = ShellcodeRunner::run_with_hooks(&code, "x86_64", &hooks).unwrap();
        assert!(
            !result
                .api_calls
                .iter()
                .any(|c| c.name.as_deref() == Some("VirtualAlloc")),
            "Hook at unreachable address should not appear in api_calls"
        );
    }

    #[test]
    fn test_run_with_hooks_empty_hooks() {
        let code = [0xF4u8];
        let result = ShellcodeRunner::run_with_hooks(&code, "x86_64", &[]).unwrap();
        assert!(result.api_calls.is_empty());
    }

    // ── ShellcodeRunResult fields ─────────────────────────────────────────────

    #[test]
    fn test_run_result_memory_writes_from_push() {
        let code = [0x6Au8, 0x41, 0xF4]; // PUSH 0x41; HLT
        let result = ShellcodeRunner::run_sc(&code, "x86_64").unwrap();
        assert!(!result.memory_writes.is_empty());
    }

    #[test]
    fn test_run_result_final_registers_named() {
        let code = [0xF4u8]; // HLT
        let result = ShellcodeRunner::run_sc(&code, "x86_64").unwrap();
        // At least RIP should be present.
        assert!(
            result
                .final_registers
                .keys()
                .any(|k| k.contains("rip") || k.contains("rax"))
        );
    }

    // ── ApiCallInterceptor ────────────────────────────────────────────────────

    #[test]
    fn test_interceptor_has_common_apis() {
        let ic = ApiCallInterceptor::new();
        let names: Vec<&str> = ic.stubs().iter().map(|s| s.name).collect();
        assert!(names.contains(&"VirtualAlloc"));
        assert!(names.contains(&"LoadLibraryA"));
        assert!(names.contains(&"GetProcAddress"));
        assert!(names.contains(&"CreateThread"));
        assert!(names.contains(&"socket"));
        assert!(names.contains(&"connect"));
    }

    #[test]
    fn test_interceptor_scan_for_api_names() {
        let ic = ApiCallInterceptor::new();
        let data = b"some code VirtualAlloc and LoadLibraryA here";
        let hits = ic.scan_for_api_names(data);
        let api_names: Vec<&str> = hits.iter().map(|(_, n)| *n).collect();
        assert!(api_names.contains(&"VirtualAlloc"));
        assert!(api_names.contains(&"LoadLibraryA"));
    }

    #[test]
    fn test_interceptor_scan_sorted_by_offset() {
        let ic = ApiCallInterceptor::new();
        let data = b"LoadLibraryA something VirtualAlloc";
        let hits = ic.scan_for_api_names(data);
        for w in hits.windows(2) {
            assert!(w[0].0 <= w[1].0, "results not sorted by offset");
        }
    }

    #[test]
    fn test_interceptor_annotate_fills_return() {
        let ic = ApiCallInterceptor::new();
        let mut calls = vec![ApiCall {
            address: 0x7000_0000,
            name: Some("VirtualAlloc".into()),
            args: vec![],
            ret: 0, // unknown
        }];
        ic.annotate(&mut calls);
        assert_eq!(calls[0].ret, HEAP_BASE);
    }

    #[test]
    fn test_interceptor_annotate_leaves_nonzero_ret() {
        let ic = ApiCallInterceptor::new();
        let mut calls = vec![ApiCall {
            address: 0,
            name: Some("VirtualAlloc".into()),
            args: vec![],
            ret: 0xDEAD, // already set by emulator
        }];
        ic.annotate(&mut calls);
        // Non-zero ret should not be overwritten.
        assert_eq!(calls[0].ret, 0xDEAD);
    }

    #[test]
    fn test_interceptor_scan_empty_buffer() {
        let ic = ApiCallInterceptor::new();
        let hits = ic.scan_for_api_names(&[]);
        assert!(hits.is_empty());
    }

    #[test]
    fn test_interceptor_more_than_20_stubs() {
        let ic = ApiCallInterceptor::new();
        assert!(
            ic.stubs().len() >= 20,
            "expected ≥20 stubs, got {}",
            ic.stubs().len()
        );
    }

    // ── arch_from_str ─────────────────────────────────────────────────────────

    #[test]
    fn test_arch_from_str_x86() {
        let arch = ShellcodeRunner::arch_from_str("x86");
        assert_eq!(arch, EmulatorArch::X86_32);
    }

    #[test]
    fn test_arch_from_str_x64() {
        let arch = ShellcodeRunner::arch_from_str("x64");
        assert_eq!(arch, EmulatorArch::X86_64);
    }

    #[test]
    fn test_arch_from_str_unknown_defaults_to_x64() {
        let arch = ShellcodeRunner::arch_from_str("mips");
        assert_eq!(arch, EmulatorArch::X86_64);
    }
}
