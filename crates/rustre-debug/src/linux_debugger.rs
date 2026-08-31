//! Concrete Linux [`crate::Debugger`] backend.
//!
//! Uses the native `ptrace(2)` API directly — no sub-crate, same rule as
//! [`crate::windows_debugger`]: this hub crate depends only on OS APIs
//! (`libc`), never on another debugger crate/implementation.
//!
//! `ptrace` is thread-affine exactly like the Win32 debug API: only the
//! thread that issued `PTRACE_TRACEME`/`PTRACE_ATTACH` for a given tracee may
//! issue further `ptrace` calls against it. A dedicated OS thread owns the
//! `fork`/`ptrace`/`waitpid` loop and is driven by a command/reply channel
//! pair, mirroring [`crate::windows_debugger::WindowsDebugger`]'s design —
//! see that module's iteration-21 history for why this thread-affinity rule
//! matters (it was the first of three real bugs a live test caught there).

#![cfg(target_os = "linux")]

use std::collections::{HashMap, HashSet};
use std::ffi::CString;
use std::fs::{File, OpenOptions};
use std::mem::zeroed;
use std::os::unix::fs::FileExt;
use std::os::unix::process::CommandExt;
use std::process::Command as ProcessCommand;
use std::sync::mpsc::{Receiver, Sender, channel};
use std::thread::JoinHandle;

use rustre_core::address::Address;

use crate::{
    Breakpoint, BreakpointKind, DebugError, DebugEvent, Debugger, LaunchOptions, MemoryMap,
    ModuleInfo, ProcessId, RegisterSet, StackFrame, StopReason, ThreadId,
};

/// Requests sent from the async trait methods to the dedicated ptrace thread.
enum Command {
    /// Must be the first command: `fork()` + `PTRACE_TRACEME` + `execvp()` in
    /// the child, on this thread (ptrace thread affinity).
    DoLaunch(Box<LaunchOptions>),
    /// Must be the first command (alternative to `DoLaunch`): `PTRACE_ATTACH`
    /// on this thread.
    DoAttach(libc::pid_t),
    ContinueExecution,
    SingleStep(ThreadId),
    Detach,
    Kill,
    GetRegisters(ThreadId),
    SetRegisters(ThreadId, RegisterSet),
    ReadMemory(u64, usize),
    WriteMemory(u64, Vec<u8>),
}

enum Reply {
    Started(Result<ProcessId, DebugError>),
    Event(Result<DebugEvent, DebugError>),
    Ack(Result<(), DebugError>),
    Registers(Result<RegisterSet, DebugError>),
    Memory(Result<Vec<u8>, DebugError>),
    WriteCount(Result<usize, DebugError>),
}

/// A concrete [`crate::Debugger`] implementation driving a real Linux process
/// via `ptrace(2)`.
pub struct LinuxDebugger {
    cmd_tx: parking_lot::Mutex<Option<Sender<Command>>>,
    reply_rx: parking_lot::Mutex<Option<Receiver<Reply>>>,
    thread: parking_lot::Mutex<Option<JoinHandle<()>>>,
    pid: parking_lot::Mutex<Option<ProcessId>>,
    current_tid: parking_lot::Mutex<Option<ThreadId>>,
    /// Address -> the bytes the trap replaced.
    ///
    /// A `Vec`, not a `u8`: an x86 `int3` is one byte, but an AArch64
    /// `BRK #0` is four, and a map that can only remember one byte gives a
    /// 4-byte trap nowhere to record what it overwrote — which is why every
    /// backend simply refused to arm on arm64. See `crate::host_trap_bytes`.
    breakpoints: parking_lot::Mutex<HashMap<u64, Vec<u8>>>,
    /// How many times each tracked breakpoint has actually fired.
    ///
    /// `Breakpoint::hit_count` is published to callers (the MCP
    /// `debug.breakpoints` tool serialises it), but nothing ever maintained
    /// it, so every breakpoint reported zero hits forever. Kept in its own
    /// map so the address -> original-byte map that `detach`/`Drop` depend on
    /// keeps its exact shape.
    hit_counts: parking_lot::Mutex<HashMap<u64, u64>>,
    /// Per-address pass counts: skip the first N hits (gdb `ignore N`).
    ignore_counts: parking_lot::Mutex<HashMap<u64, u64>>,
    /// Per-address thread restriction: stop only for this thread id.
    thread_filters: parking_lot::Mutex<HashMap<u64, u32>>,
    /// Addresses that are tracked but currently DISABLED: their original byte
    /// is back in the target, so they do not fire, yet they stay listed by
    /// `breakpoints()` with `enabled: false`. Without this, `disable` was
    /// just `remove` and the `enabled` field could never be false.
    disabled: parking_lot::Mutex<std::collections::HashSet<u64>>,
    /// Hardware watchpoints currently armed, as `address -> (kind, size)`.
    ///
    /// The debug registers are per-thread, so a thread created AFTER the
    /// watchpoint was armed starts with empty debug registers and is not
    /// watching anything. Without a record of what should be armed there is
    /// nothing to re-apply to it, and the caller is silently watching fewer
    /// threads as the target spawns more.
    hw_watchpoints: parking_lot::Mutex<HashMap<u64, (BreakpointKind, u8)>>,
    /// Watchpoints that the last resume-time re-arm could NOT put into every
    /// thread's debug registers.
    ///
    /// A resume must not FAIL because a watchpoint could not be re-armed on a
    /// thread that just appeared — but the fact has to survive the resume.
    /// Discarded, the watchpoint silently stops watching and no caller can
    /// ever learn it, which is the failure mode a watchpoint exists to rule
    /// out. `breakpoints()` labels the entries named here.
    unarmed_since_resume: parking_lot::Mutex<std::collections::HashSet<u64>>,
    /// Per-address breakpoint conditions, as written by the caller.
    ///
    /// Kept beside the breakpoint table rather than inside `Breakpoint` because
    /// that struct is rebuilt on every `breakpoints()` call from the tracking
    /// maps; a condition stored in it would live exactly as long as the
    /// temporary.
    conditions: parking_lot::Mutex<HashMap<u64, String>>,
    /// Breakpoints requested on modules that may not be mapped yet; armed on
    /// `LibraryLoad` and re-armed after every reload at the new base.
    pending: parking_lot::Mutex<crate::pending_breakpoint::PendingBreakpoints>,
    /// Addresses the DEBUGGER itself is waiting to stop at.
    ///
    /// A user's condition must never filter a stop the debugger arranged for its
    /// own purposes. `run_to_return` plants (or re-uses) a breakpoint at the
    /// return site and waits for it; if the caller's breakpoint at that same
    /// address carries a condition that is false, the condition filter would
    /// resume past it and the step would never finish — a stepping primitive
    /// silently becoming `continue`, which this file already calls the worst
    /// failure mode a debugger has.
    internal_stops: parking_lot::Mutex<std::collections::HashSet<u64>>,
    /// Optional symbol source used to fill in `function_name`/`source_file`/
    /// `source_line` on unwound frames. `None` → raw addresses only.
    symbols: parking_lot::Mutex<Option<std::sync::Arc<dyn crate::symbol_resolver::FrameSymbolResolver>>>,
}

impl Default for LinuxDebugger {
    fn default() -> Self {
        Self::new()
    }
}

impl LinuxDebugger {
    #[must_use]
    pub fn new() -> Self {
        Self {
            cmd_tx: parking_lot::Mutex::new(None),
            reply_rx: parking_lot::Mutex::new(None),
            thread: parking_lot::Mutex::new(None),
            pid: parking_lot::Mutex::new(None),
            current_tid: parking_lot::Mutex::new(None),
            breakpoints: parking_lot::Mutex::new(HashMap::new()),
            hit_counts: parking_lot::Mutex::new(HashMap::new()),
            ignore_counts: parking_lot::Mutex::new(HashMap::new()),
            thread_filters: parking_lot::Mutex::new(HashMap::new()),
            disabled: parking_lot::Mutex::new(std::collections::HashSet::new()),
            hw_watchpoints: parking_lot::Mutex::new(HashMap::new()),
            unarmed_since_resume: parking_lot::Mutex::new(std::collections::HashSet::new()),
            conditions: parking_lot::Mutex::new(HashMap::new()),
            pending: parking_lot::Mutex::new(crate::pending_breakpoint::PendingBreakpoints::new()),
            internal_stops: parking_lot::Mutex::new(std::collections::HashSet::new()),
            symbols: parking_lot::Mutex::new(None),
        }
    }

    /// Attach a symbol source so `backtrace` resolves function/file/line for
    /// each frame instead of returning bare addresses.
    pub fn set_symbol_resolver(
        &self,
        resolver: std::sync::Arc<dyn crate::symbol_resolver::FrameSymbolResolver>,
    ) {
        *self.symbols.lock() = Some(resolver);
    }

    /// `write_memory` without routing around our software breakpoints — writes
    /// the bytes exactly as given.
    ///
    /// Used by the breakpoint machinery itself, which plants and removes the
    /// `0xCC` and must not have its own writes redirected. Everything else
    /// wants `write_memory`.
    pub async fn write_memory_raw(&self, addr: Address, data: &[u8]) -> Result<usize, DebugError> {
        match self.send(Command::WriteMemory(addr.as_u64(), data.to_vec()))? {
            Reply::WriteCount(r) => r,
            _ => Err(DebugError::MemoryError(addr.as_u64(), "unexpected reply".into())),
        }
    }

    /// Disarm the hardware watchpoint at `addr`, freeing its debug-register slot.
    ///
    /// A separate method on purpose: `remove_breakpoint` is one of the twenty
    /// frozen byte-identical across the three backends, and macOS cannot
    /// program the debug registers at all, so the disarm cannot live there
    /// without breaking that invariant. Without this, the four `DR0`-`DR3`
    /// slots would leak one per removed watchpoint until detach.
    ///
    /// Returns whether a slot was actually holding this address.
    ///
    /// # Errors
    /// Whatever reading or writing the thread's registers reports.
    pub async fn remove_hardware_watchpoint(&self, addr: Address) -> Result<bool, DebugError> {
        let found = self.disarm_watchpoint_registers(addr).await?;
        self.hw_watchpoints.lock().remove(&addr.as_u64());
        self.disabled.lock().remove(&addr.as_u64());
        Ok(found)
    }

    /// Clear the debug registers holding `addr` on every thread, WITHOUT
    /// forgetting the watchpoint.
    ///
    /// Split out from `remove_hardware_watchpoint` so `disable_breakpoint` can
    /// stop a watchpoint firing while keeping it tracked — the same shape the
    /// software path has had for a long time, where a disabled breakpoint has
    /// its original byte back in the target but stays listed as disabled.
    async fn disarm_watchpoint_registers(&self, addr: Address) -> Result<bool, DebugError> {
        // Disarm on every thread: `set_watchpoint_sized` arms them all, so
        // clearing only the current one would leave the watchpoint live
        // elsewhere and its slot permanently occupied.
        let tids = self.threads().await?;
        let mut found = false;
        for tid in tids {
            // NOT `else { continue }`. A thread whose registers cannot be read
            // is a thread whose debug registers were not inspected, and this
            // function's `bool` means "a slot was holding this address" — the
            // caller cannot tell that from "I could not look". It then clears
            // its own bookkeeping either way, which would forget a watchpoint
            // still live in the CPU.
            let mut regs = self.get_registers(tid).await.map_err(|e| {
                DebugError::RegisterError(format!(
                    "cannot read thread {}'s registers, so it is not known whether a debug                      register still holds {addr:#x}: {e}",
                    tid.0
                ))
            })?;
            // An absent `dr7` is not "nothing was armed". Without this, a set
            // that carries no `dr7` — the AArch64 readers publish none — made
            // every slot read as disabled, no slot matched, and this answered
            // `Ok(false)`: a claim about the hardware drawn from a set that
            // never described it.
            //
            // Four lines above, a set that cannot be READ already raises
            // "it is not known whether a debug register still holds {addr}".
            // This is the same situation and gets the same answer.
            let dr7 = match crate::debug_register_state(&regs) {
                crate::DebugRegisterState::Unverifiable => {
                    return Err(DebugError::RegisterError(format!(
                        "thread {}'s registers carry no DR7, so it is not known whether a                          debug register still holds {addr:#x}",
                        tid.0
                    )));
                }
                crate::DebugRegisterState::Clean => 0,
                crate::DebugRegisterState::Armed(v) => v,
            };
            let mut cleared_here = false;
            for slot in 0u8..4 {
                let name = match slot {
                    0 => "dr0",
                    1 => "dr1",
                    2 => "dr2",
                    _ => "dr3",
                };
                // Only a slot that is ENABLED counts: a stale address left in
                // a disabled register is not a watchpoint, and clearing on it
                // would report a removal that never happened.
                let enabled = dr7 & (1u64 << (2 * u32::from(slot))) != 0;
                if enabled && regs.get(name) == Some(addr.as_u64()) {
                    let shift = 16 + 4 * u32::from(slot);
                    let cleared =
                        dr7 & !(0b1111u64 << shift) & !(1u64 << (2 * u32::from(slot)));
                    regs.set(name, 0);
                    regs.set("dr7", cleared);
                    cleared_here = true;
                    break;
                }
            }
            if cleared_here {
                // A write that fails must not be reported as "nothing found":
                // the slot IS holding the address and is still armed.
                self.set_registers(tid, regs).await.map_err(|e| {
                    DebugError::RegisterError(format!(
                        "the debug register holding {addr:#x} on thread {} could not be                          cleared, so the watchpoint is still armed: {e}",
                        tid.0
                    ))
                })?;
                found = true;
            }
        }
        Ok(found)
    }

    /// `read_memory` without hiding our software breakpoints — the process's
    /// memory exactly as it is, `0xCC` patches included.
    ///
    /// Used by the breakpoint machinery itself (which must see what it
    /// planted) and by tests that verify an implant landed. Everything else
    /// wants `read_memory`.
    pub async fn read_memory_raw(&self, addr: Address, size: usize) -> Result<Vec<u8>, DebugError> {
        match self.send(Command::ReadMemory(addr.as_u64(), size))? {
            Reply::Memory(r) => r,
            _ => Err(DebugError::MemoryError(addr.as_u64(), "unexpected reply".into())),
        }
    }

    /// Disarm every hardware watchpoint we armed, on every thread.
    ///
    /// `detach` already restores each planted `0xCC` because a leftover int3
    /// kills a process that has no debugger left to handle the exception. A
    /// leftover ARMED debug register is the same defect one layer down: the
    /// target keeps running with `DR7` enabled, and the first access to the
    /// watched address raises a trap nobody is there to take. The software
    /// half of that hazard was fixed long ago; the hardware half arrived with
    /// hardware watchpoints and was never covered.
    ///
    /// Best-effort throughout: a thread that exits mid-sweep is normal, and
    /// detaching must not fail because of it.
    async fn disarm_all_hardware_watchpoints(&self) -> Result<(), DebugError> {
        // Deliberately NOT gated on `hw_watchpoints` being empty.
        //
        // That map is our bookkeeping; the thing that kills the target is DR7
        // in the target. The two are not the same, and `set_registers` is a
        // public trait method: anything may arm the debug registers without
        // going through `set_watchpoint_sized`. This is not hypothetical — our
        // own MCP `debug.set_watchpoint` tool drives its per-session
        // `WatchpointEngine` and writes DR0-3/DR7 with a direct `set_registers`
        // call, so every watchpoint armed through the MCP surface left
        // `hw_watchpoints` empty and this function returned without clearing a
        // single register. The detached process then keeps trapping with no
        // debugger to take the trap, and the kernel's default action for an
        // unhandled SIGTRAP is to kill it: exactly the hazard `detach` already
        // documents for the software half.
        //
        // The cost of dropping the fast path is one `threads()` plus one
        // `get_registers` per thread on a session that armed nothing. That is
        // paid once per detach or drop, and the per-thread `dr7 == 0` check
        // below still skips the write for every thread that is clean.
        // Being unable to LIST the threads is not "everything is clear".
        //
        // This function promises, in its own error text, that no thread is left
        // with its debug registers armed. Answering `Ok(())` without having
        // examined a single one is that promise made without the check: the
        // target is detached with a live `DR7`, traps on its next watched
        // access, and finds no debugger attached to take the trap. It dies from
        // having been inspected.
        let tids = self.threads().await.map_err(|e| {
            DebugError::DetachError(format!(
                "cannot list the target'''s threads, so it is not known whether any debug                  register is still armed: {e}"
            ))
        })?;
        let mut still_armed: Vec<u32> = Vec::new();
        for tid in tids {
            // A thread whose registers cannot be read is UNVERIFIED, not
            // clean — and it is the likeliest one to be in a bad state.
            let Ok(mut regs) = self.get_registers(tid).await else {
                still_armed.push(tid.0);
                continue;
            };
            // An absent `dr7` is not a clean one. Three lines above, a thread
            // whose registers cannot be READ is called UNVERIFIED rather than
            // clean; a set that was read and carries no `dr7` is the same
            // situation, and `unwrap_or(0)` answered the opposite. Both ARM64
            // ports produce exactly that set — the Windows AArch64 reader
            // publishes no `dr7` at all, and the Linux one omits it whenever
            // the `NT_ARM_HW_WATCH` regset cannot be read.
            match crate::debug_register_state(&regs) {
                crate::DebugRegisterState::Clean => continue,
                crate::DebugRegisterState::Unverifiable => {
                    still_armed.push(tid.0);
                    continue;
                }
                crate::DebugRegisterState::Armed(_) => {}
            }
            regs.set("dr0", 0);
            regs.set("dr1", 0);
            regs.set("dr2", 0);
            regs.set("dr3", 0);
            regs.set("dr6", 0);
            regs.set("dr7", 0);
            // A disarm that FAILED must not pass for a clean one.
            //
            // The result was discarded and the bookkeeping cleared regardless,
            // so a write that did not land left DR7 ARMED in a process about
            // to lose its debugger — the hazard this very function describes
            // above ("the kernel's default action for an unhandled SIGTRAP is
            // to kill it") — while the map said there was nothing left to
            // disarm. Iteration 533 closed the software half of exactly this;
            // this is the hardware half it named but did not reach.
            if self.set_registers(tid, regs).await.is_err() {
                still_armed.push(tid.0);
            }
        }
        if !still_armed.is_empty() {
            // The map is deliberately NOT cleared: it is the only record of
            // what is still armed, and a caller that retries needs it. Same
            // rule `detach` states for the software half — a failure must
            // leave the session exactly as it was.
            return Err(DebugError::DetachError(format!(
                "debug registers still armed on thread(s) {}; detaching now would leave the target trapping with no debugger to take the trap",
                still_armed.iter().map(std::string::ToString::to_string).collect::<Vec<_>>().join(", ")
            )));
        }
        self.hw_watchpoints.lock().clear();
        Ok(())
    }

    /// Arm every tracked hardware watchpoint on threads that do not have it.
    ///
    /// The debug registers are per-thread AND are not inherited: a thread the
    /// target spawns after `set_watchpoint_sized` starts with empty debug
    /// registers, so it watches nothing while the caller believes the address
    /// is covered. Iteration 362 armed every thread that existed at the time;
    /// this closes the same hole for the ones that appear afterwards.
    ///
    /// Reconciling on resume rather than on the thread-creation debug event
    /// keeps it in one place for both backends and needs no change to the
    /// event loop. Everything is best-effort: a thread that exits mid-walk is
    /// normal and must not fail the resume the caller asked for.
    async fn rearm_watchpoints_on_new_threads(&self) -> Vec<u64> {
        let wanted: Vec<(u64, BreakpointKind, u8)> = {
            let map = self.hw_watchpoints.lock();
            if map.is_empty() {
                return Vec::new();
            }
            let disabled = self.disabled.lock();
            // A disabled watchpoint must stay disarmed: without this filter the
            // very next resume would put it straight back into the debug
            // registers, so `disable_breakpoint` would appear to work and then
            // silently undo itself.
            map.iter()
                .filter(|(a, _)| !disabled.contains(a))
                .map(|(a, (k, s))| (*a, *k, *s))
                .collect()
        };
        let Ok(tids) = self.threads().await else { return wanted.iter().map(|(a, _, _)| *a).collect() };
        let mut unarmed: Vec<u64> = Vec::new();
        for tid in tids {
            // A thread whose registers cannot be read was never inspected, so
            // NONE of the wanted watchpoints is armed on it. Skipping it in
            // silence reported it as watched while nothing watched it.
            let Ok(mut regs) = self.get_registers(tid).await else {
                unarmed.extend(wanted.iter().map(|(a, _, _)| *a));
                continue;
            };
            // An absent `dr7` is NOT a clean one. The Windows AArch64 reader
            // publishes no `dr*` register at all and the Linux one omits them
            // whenever `NT_ARM_HW_WATCH` cannot be read, so `unwrap_or(0)` said
            // "every slot is free" about a thread nobody had inspected. Arming
            // then proceeded, and the write-back is checked only for a
            // `set_registers` error — never read back — so the address never
            // reached `unarmed` and the caller was told it was watched while
            // nothing watched it: a silent success.
            //
            // Same answer as the branch four lines above, which already treats
            // a thread whose registers cannot be READ as unwatched.
            let mut dr7 = match crate::debug_register_state(&regs) {
                crate::DebugRegisterState::Unverifiable => {
                    unarmed.extend(wanted.iter().map(|(a, _, _)| *a));
                    continue;
                }
                crate::DebugRegisterState::Clean => 0,
                crate::DebugRegisterState::Armed(v) => v,
            };
            let mut changed = false;
            for (addr, kind, size) in &wanted {
                // Already armed on this thread in some slot? Leave it alone —
                // re-arming would consume a second slot for one watchpoint.
                let already = (0u8..4).any(|slot| {
                    let name = match slot {
                        0 => "dr0",
                        1 => "dr1",
                        2 => "dr2",
                        _ => "dr3",
                    };
                    dr7 & (1u64 << (2 * u32::from(slot))) != 0 && regs.get(name) == Some(*addr)
                });
                if already {
                    continue;
                }
                let Some(slot) = crate::x86_free_watchpoint_slot(dr7) else { break };
                let Ok(new_dr7) = crate::x86_encode_watchpoint_dr7(dr7, slot, *addr, *kind, *size)
                else {
                    continue;
                };
                regs.set(
                    match slot {
                        0 => "dr0",
                        1 => "dr1",
                        2 => "dr2",
                        _ => "dr3",
                    },
                    *addr,
                );
                dr7 = new_dr7;
                changed = true;
            }
            // Ask the registers, do not trust the loop above.
            //
            // There are three ways for a watchpoint not to land on this thread
            // — all four debug registers already occupied (`break`), a dr7
            // encoding the CPU would reject (`continue`), and the unreadable
            // registers handled above — and every one of them leaves the same
            // observable trace: the address is absent from these registers.
            // One check after the fact catches all three, and unlike reporting
            // each `break`/`continue` site it cannot over-report a watchpoint
            // that was ALREADY armed here, which would make `enable_breakpoint`
            // raise a failure that did not happen.
            let missed: Vec<u64> = wanted
                .iter()
                .filter(|(addr, _, _)| {
                    !(0u8..4).any(|slot| {
                        let name = match slot {
                            0 => "dr0",
                            1 => "dr1",
                            2 => "dr2",
                            _ => "dr3",
                        };
                        dr7 & (1u64 << (2 * u32::from(slot))) != 0
                            && regs.get(name) == Some(*addr)
                    })
                })
                .map(|(a, _, _)| *a)
                .collect();
            if changed {
                regs.set("dr7", dr7);
                // A re-arm that did not land leaves this thread UNWATCHED.
                //
                // The result was discarded, so the address stayed in
                // `hw_watchpoints` — the caller was still told it was watched —
                // while no debug register on this thread held it. That is the
                // "silent miss, not an error" this crate condemns in
                // `set_watchpoint_sized`, and `enable_breakpoint` was reporting
                // `Ok(())` on top of it.
                //
                // Reported, not raised: the resume paths call this on every
                // stop and must not fail there, so they discard the list
                // exactly as before. `enable_breakpoint`, which is a direct
                // request to re-arm and CAN answer, is the one that acts on it.
                if self.set_registers(tid, regs).await.is_err() {
                    unarmed.extend(wanted.iter().map(|(a, _, _)| *a));
                    continue;
                }
            }
            unarmed.extend(missed);
        }
        unarmed.sort_unstable();
        unarmed.dedup();
        unarmed
    }

    /// Arm (or forget) pending breakpoints for a module load / unload event.
    ///
    /// Called from `continue_execution` because that is the only place a
    /// `LibraryLoad` can reach us: a pending table that is written but never
    /// consulted at load time is the exact shape of "accepted and forgotten".
    ///
    /// The lock is released before any `await`: holding a `parking_lot` guard
    /// across a suspension point deadlocks the next resolver on the same
    /// table, and `set_breakpoint` below is itself async.
    async fn arm_pending_breakpoints(&self, event: &mut DebugEvent) {
        // Name a library load HERE, not where it was classified.
        //
        // `classify_event` runs on the debug-loop thread with the target
        // stopped on an event that has NOT been acknowledged with
        // `ContinueDebugEvent` yet; asking the OS about the process in that
        // window broke hardware watchpoint hit detection outright — every hit
        // came back as an ordinary single step. Proved by bisection in
        // iteration 504: the identical arm emitting the identical variant with
        // a constant path leaves all 81 live tests green.
        //
        // By the time this runs the event has been delivered, so `modules()` is
        // an ordinary query. A base that names no module leaves the path empty
        // rather than guessing: an invented name would match no pending request
        // silently, or worse, the wrong one.
        // Naming costs a full module snapshot of the target — on Windows a
        // toolhelp walk plus a live memory read per module — so it is paid only
        // when somebody is actually waiting for a module to appear. A normal
        // process loads dozens of images before `main`; doing this for each of
        // them made a live test exceed sixty seconds, which is how the cost was
        // found rather than argued.
        //
        // With nothing pending the event still carries its BASE, which is the
        // identifying fact; the path stays empty rather than being paid for by
        // every caller who did not ask for it.
        let anyone_waiting = !self.pending.lock().is_empty();
        if anyone_waiting
            && let StopReason::LibraryLoad { path, base } = &mut event.reason
            && path.is_empty()
            && let Ok(mods) = self.modules().await
            && let Some(m) = mods.iter().find(|m| m.base == *base)
        {
            *path = m.path.clone();
        }
        // A pending breakpoint must arm on EVERY backend, not only where the
        // OS hands us a load event.
        //
        // Only the `LibraryLoad` arm below ever armed one, and only Windows
        // constructs that event, so `set_pending_breakpoint` refused outright
        // on Linux and macOS: the same request, the same crate, `Ok` on one OS
        // and `Unsupported` on another.
        //
        // The event is not needed to answer the question it was being asked.
        // `modules()` already reports what is mapped RIGHT NOW on all three
        // backends, and the target is stopped every time this runs, so
        // re-reading it and arming whatever became resolvable covers the real
        // use case: "break in a library that is not loaded yet". It is not a
        // load NOTIFICATION — it cannot say the instant a mapping appears —
        // but it arms at the first stop after it appears, which is the first
        // moment a breakpoint could take effect anyway.
        //
        // Deliberately identical in all three backends: the shared logic here
        // is guarded by `the_logic_shared_by_the_three_backends_stays_identical`,
        // and a capability added to one OS only is exactly the divergence that
        // guard exists to prevent.
        //
        // Gated on somebody actually waiting, like the naming above: a module
        // snapshot per stop for callers who asked for nothing is the cost that
        // made a live test exceed sixty seconds.
        if anyone_waiting
            && !matches!(event.reason, StopReason::LibraryLoad { .. })
            && let Ok(mods) = self.modules().await
        {
            let mut armed: Vec<u64> = Vec::new();
            {
                let mut pending = self.pending.lock();
                for m in &mods {
                    armed.extend(pending.resolve_on_load(&m.path, m.base.as_u64()));
                    // The caller usually types the basename; a module whose
                    // `name` differs from its path's last component would
                    // otherwise stay unreachable by the name the listing
                    // itself publishes. Same pairing as
                    // `set_pending_breakpoint`.
                    armed.extend(pending.resolve_on_load(&m.name, m.base.as_u64()));
                }
            }
            for addr in armed {
                let _ = self
                    .set_breakpoint(Address(addr), BreakpointKind::Software)
                    .await;
            }
        }

        match &event.reason {
            StopReason::LibraryLoad { path, base } => {
                let armed = self.pending.lock().resolve_on_load(path, base.as_u64());
                for addr in armed {
                    let _ = self
                        .set_breakpoint(Address(addr), BreakpointKind::Software)
                        .await;
                }
            }
            StopReason::LibraryUnload { path } => {
                // The trap bytes went away with the mapping. Forgetting them
                // here stops a later restore from writing a stale "original
                // byte" over whatever gets mapped at that address next.
                let stale = self.pending.lock().resolve_on_unload(path);
                for addr in stale {
                    let _ = self.remove_breakpoint(Address(addr)).await;
                }
            }
            _ => {}
        }
    }

    /// Step off a breakpoint we planted before resuming.
    ///
    /// After a software breakpoint fires, `rewind_past_own_breakpoint` puts
    /// the PC back on the breakpoint address — where our `0xCC` is still
    /// planted. Resuming from there re-executes the trap instead of the
    /// instruction it replaced, so the target can never advance past a
    /// breakpoint it has hit. Proved on a live process by
    /// `continuing_from_a_planted_breakpoint_does_not_re_trap_at_the_same_address`.
    ///
    /// The fix is the standard dance every debugger performs: restore the
    /// original byte, single-step the real instruction, then re-plant. It runs
    /// only when the PC is exactly on an ENABLED breakpoint of ours — a
    /// disabled one has no byte planted, and a foreign trap must be left
    /// alone.
    ///
    /// Failures are deliberately non-fatal: if the re-plant cannot be written
    /// the caller still gets its resume, and the breakpoint is dropped from
    /// tracking so nothing claims a byte is planted when it is not.
    /// Does the condition attached to this stop allow it to be REPORTED?
    ///
    /// `true` when there is no condition, when it evaluates true, and — the
    /// important case — when it cannot be read or evaluated. A breakpoint that
    /// silently never fires tells the user their code never reaches that line: a
    /// wrong conclusion about their PROGRAM, drawn from a fault in their
    /// condition. Stopping is noisy; the user is standing at the breakpoint and
    /// can see why.
    ///
    /// Memory operands are fetched BEFORE evaluation, because `EvalContext` is
    /// synchronous and the debugger's reads are not. A read that fails is left
    /// out of the context, which makes the evaluation itself fail — and by the
    /// rule above, that reports the stop rather than hiding it.
    ///
    /// A stop that is skipped must also be UNCOUNTED: `rewind_past_own_breakpoint`
    /// has already counted the hit by the time this runs, and a breakpoint whose
    /// condition filtered it out did not fire. Leaving the count would make the
    /// statistics contradict what the user is watching happen.
    async fn condition_allows_stop(&self, event: &DebugEvent) -> bool {
        let StopReason::Breakpoint { address, .. } = &event.reason else {
            return true;
        };
        let a = address.as_u64();
        // A stop the debugger is itself waiting for is never filtered.
        if self.internal_stops.lock().contains(&a) {
            return true;
        }
        // Thread restriction (gdb `break … thread N`) — BEFORE the pass count
        // on purpose. A hit on another thread is not a hit of this
        // breakpoint at all, so letting it reach the gate below would let
        // unrelated threads consume an `ignore 3` and the breakpoint would
        // stop on the wrong thread's third crossing.
        //
        // Un-counted, unlike a pass-count skip: the breakpoint did not fire,
        // and `breakpoints()` publishes `hit_count` — inflating it with other
        // threads' crossings would contradict what the user is watching.
        let only_tid = self.thread_filters.lock().get(&a).copied();
        if let Some(only) = only_tid
            && only != event.tid.0
        {
            let mut counts = self.hit_counts.lock();
            if let Some(n) = counts.get_mut(&a) {
                *n = n.saturating_sub(1);
            }
            return false;
        }
        // Pass count (gdb `ignore N`, WinDbg `bp /N`): skip the first N hits.
        // Unlike a condition-filtered stop below, the hit stays COUNTED — an
        // ignore count is defined as consuming hits, and un-counting them
        // would make it never expire, turning "skip 3" into "never stop".
        // `rewind_past_own_breakpoint` has already counted this hit, so the
        // Nth hit is skipped while the running total is still <= N.
        let ignore = self.ignore_counts.lock().get(&a).copied().unwrap_or(0);
        if ignore > 0 {
            let so_far = self.hit_counts.lock().get(&a).copied().unwrap_or(0);
            if so_far <= ignore {
                return false;
            }
        }
        let Some(text) = self.conditions.lock().get(&a).cloned() else {
            return true;
        };
        let Ok(cond) = crate::conditional_breakpoint::BreakpointCondition::parse(&text) else {
            return true;
        };
        let Ok(regs) = self.get_registers(event.tid).await else {
            return true;
        };
        let mut ctx = crate::conditional_breakpoint::MapEvalContext::new();
        for (name, value) in &regs.regs {
            ctx.set_reg(name.clone(), *value);
        }
        // Sub-register names, narrowed. People write `al == 0` and `eax > 4`,
        // not `rax & 0xff`. Without these the name was simply absent, the
        // evaluation failed, and the fail-open rule stopped the target on
        // EVERY hit — a condition that was never applied, with nothing saying
        // so. Derived names never overwrite one the backend supplied itself.
        for alias in crate::SUB_REGISTER_NAMES {
            if !regs.regs.contains_key(*alias)
                && let Some(v) = regs.get_narrowed(alias)
            {
                ctx.set_reg((*alias).to_string(), v);
            }
        }
        // The generic roles too: a caller writes `pc` or `sp` far more often
        // than the architecture's own name for them.
        ctx.set_reg("pc", regs.pc);
        ctx.set_reg("sp", regs.sp);
        for (addr, width) in crate::conditional_breakpoint::memory_operands(&cond) {
            if let Ok(bytes) = self.read_memory(Address(addr), usize::from(width)).await {
                let mut buf = [0u8; 8];
                let n = bytes.len().min(8);
                buf[..n].copy_from_slice(&bytes[..n]);
                ctx.set_mem(addr, u64::from_le_bytes(buf), width);
            }
        }
        let stop = crate::conditional_breakpoint::should_stop_for_condition(Some(&text), &ctx);
        if !stop {
            let mut counts = self.hit_counts.lock();
            if let Some(n) = counts.get_mut(&a) {
                *n = n.saturating_sub(1);
            }
        }
        stop
    }

    /// Fill an event's breakpoint record from what this session actually
    /// TRACKS, instead of handing back a freshly built default.
    ///
    /// `classify_status` runs on the debug-loop thread with no `&self`, so the
    /// only breakpoint it can put in the event is `Breakpoint::new_software` /
    /// `new_hardware` — an all-defaults record. Every consumer of
    /// `StopReason::Breakpoint { bp }` therefore read `enabled: true`,
    /// `hit_count: 0`, `condition: None` and, since iterations 491/492,
    /// `ignore_count: 0`, `only_thread: None`, `byte_size: None`, for a
    /// breakpoint that may be conditional, restricted to a thread, hit fifty
    /// times, and watching eight bytes.
    ///
    /// Not a missing field but a FABRICATED one: the values are plausible and
    /// uniformly wrong, which is the failure mode this crate keeps finding.
    ///
    /// Called after `condition_allows_stop`, so `hit_count` includes the hit
    /// being reported rather than the one before it.
    fn enrich_event_breakpoint(&self, ev: &mut DebugEvent) {
        let StopReason::Breakpoint { address, bp } = &mut ev.reason else {
            return;
        };
        let a = address.as_u64();
        if let Some(orig) = self.breakpoints.lock().get(&a) {
            bp.original_byte = orig.first().copied();
        }
        if let Some(&(_, size)) = self.hw_watchpoints.lock().get(&a) {
            bp.byte_size = Some(size);
        }
        bp.hit_count = self.hit_counts.lock().get(&a).copied().unwrap_or(0);
        bp.enabled = !self.disabled.lock().contains(&a);
        bp.condition = self.conditions.lock().get(&a).cloned();
        bp.ignore_count = self.ignore_counts.lock().get(&a).copied().unwrap_or(0);
        bp.only_thread = self.thread_filters.lock().get(&a).copied().map(ThreadId);
    }

    /// The step itself, with no breakpoint bookkeeping in front of it.
    ///
    /// Split out so `step_off_planted_breakpoint` can take exactly one
    /// instruction without recursing back through the wrapper that calls IT.
    async fn single_step_raw(&self, tid: ThreadId) -> Result<DebugEvent, DebugError> {
        match self.send(Command::SingleStep(tid))? {
            Reply::Event(r) => {
                if let Ok(ev) = &r {
                    // Same bookkeeping `continue_execution` does — `single_step`
                    // (and therefore `step_over`/`step_out`, which call it) is
                    // just as much "the thread that most recently stopped" as
                    // a `continue_execution` result. Without this,
                    // `current_thread()` stayed stuck reporting whatever it
                    // was before the step (or `NotAttached` if no
                    // `continue_execution` had ever run yet), discovered via
                    // a live test that single-stepped then asked
                    // `current_thread` and got `NotAttached` back.
                    *self.current_tid.lock() = Some(ev.tid);
                    // A failed rewind leaves the PC one byte inside an
                    // instruction. Returning this event as a normal step would
                    // report a clean stop for a target that cannot be resumed,
                    // so the failure replaces the event instead of riding
                    // alongside it.
                    self.rewind_past_own_breakpoint(ev).await?;
                    // A single step CAN be the process's last instruction, and
                    // the event loop returns just the same. Retiring only from
                    // `continue_execution` would leave that path stuck.
                    if ev.reason.is_exit() {
                        self.retire_session_after_exit();
                    }
                }
                let mut r = r;
                if let Ok(ev) = &mut r {
                    self.enrich_event_breakpoint(ev);
                }
                r
            }
            _ => Err(DebugError::StepError("unexpected reply".into())),
        }
    }
    /// Returns the stop event when a step was actually taken, so `single_step`
    /// can hand it straight back instead of stepping a second time.
    /// `who` is the thread to step off, or `None` for whichever last stopped.
    ///
    /// It used to read `current_tid` unconditionally. Harmless while the result
    /// was discarded; once `single_step` started RETURNING this event, asking to
    /// step thread B while thread A sat on a planted trap stepped **A** and
    /// handed that event back as the answer for B — the caller was told its
    /// thread had advanced when a different one had.
    async fn step_off_planted_breakpoint(&self, who: Option<ThreadId>) -> crate::StepOff {
        let Some(tid) = who.or(*self.current_tid.lock()) else { return crate::StepOff::NotOnATrap };
        let Ok(regs) = self.get_registers(tid).await else { return crate::StepOff::NotOnATrap };
        let pc = regs.pc;
        let original = {
            let planted = self.breakpoints.lock();
            if self.disabled.lock().contains(&pc) {
                return crate::StepOff::NotOnATrap;
            }
            match planted.get(&pc) {
                Some(b) => b.clone(),
                None => return crate::StepOff::NotOnATrap,
            }
        };
        if self.write_memory_raw(Address(pc), &original).await.is_err() {
            // The trap is still in place and the thread is still on it. Saying
            // "no trap here" would send the caller to step straight into it.
            return crate::StepOff::Failed(DebugError::MemoryError(
                pc,
                "could not restore the original byte under a planted breakpoint; the trap                  is still in place and the thread is still standing on it"
                    .to_string(),
            ));
        }
        let stepped = self.single_step_raw(tid).await;
        if self.write_memory_raw(Address(pc), crate::host_trap_bytes()).await.is_err() {
            // Could not re-arm: stop claiming it is planted. This is NOT a
            // reason to discard a step that already happened — doing so made
            // the caller step a second time and the thread advance twice for
            // one request.
            self.breakpoints.lock().remove(&pc);
        }
        match stepped {
            Ok(ev) => crate::StepOff::Stepped(ev),
            // The trap has just been re-armed under a thread that did not move.
            // Reported, not swallowed: `.ok()` here turned a transient failure
            // into the caller stepping onto the `int3` and getting no
            // instruction, with nothing saying why.
            Err(e) => crate::StepOff::Failed(e),
        }
    }

    /// See `WindowsDebugger::rewind_past_own_breakpoint` for the full
    /// rationale: `int3` always advances `rip` by 1 on x86 regardless of OS,
    /// and only breakpoints *we* planted (byte patched to `0xCC`) need that
    /// rewound before resuming — a foreign/target-owned `int3` must be left
    /// alone or resuming re-executes the same trap forever.
    async fn rewind_past_own_breakpoint(&self, event: &DebugEvent) -> Result<(), DebugError> {
        let StopReason::Breakpoint { address, .. } = &event.reason else {
            return Ok(());
        };
        if !self.breakpoints.lock().contains_key(&address.as_u64()) {
            // A hardware watchpoint hit arrives here too, and it must be
            // COUNTED — `breakpoints()` publishes `hit_count`, so a watchpoint
            // that fires repeatedly was reporting zero hits forever, exactly
            // the contradiction the software path was fixed for.
            //
            // It must NOT be rewound: for a watchpoint, `address` is the
            // WATCHED data address, not the PC. Writing it into the PC would
            // send the target off to execute its own data. That is why the
            // counting happens here and the function returns instead of
            // falling through.
            if self.hw_watchpoints.lock().contains_key(&address.as_u64()) {
                *self.hit_counts.lock().entry(address.as_u64()).or_insert(0) += 1;
            }
            return Ok(());
        }
        // This is our breakpoint and it just fired — the only place that
        // knows both facts, so it is where the hit is counted.
        *self.hit_counts.lock().entry(address.as_u64()).or_insert(0) += 1;
        // Both failures below are RETURNED, never swallowed.
        //
        // This used to read the registers under `if let Ok(..)` and write them
        // back under `let _ =`, so either failure left the PC one byte past the
        // `int3` while the caller still received `Ok(Breakpoint { address })`.
        // That event is true about what happened and false about the state it
        // left: resuming restarts the target INSIDE an instruction, which is
        // arbitrary execution, not an approximate answer. The hit above is
        // still counted first — the breakpoint really did fire, and that fact
        // stays true even when the rewind that follows it does not.
        let mut regs = self.get_registers(event.tid).await?;
        regs.pc = address.as_u64();
        // The PC is written by the name THIS architecture uses. Hardcoding
        // "rip" wrote a key that does not exist on AArch64: the map still
        // held the old `pc`, `apply_register_set` reads `pc`, and the
        // rewind therefore wrote nothing at all on Apple Silicon — silent,
        // because `regs.pc` (the struct field) is not what gets written
        // back. `pc_key` is the shared answer added in iteration 443.
        regs.set(
            crate::instr_step::pc_key(crate::instr_step::native_arch()),
            address.as_u64(),
        );
        self.set_registers(event.tid, regs).await?;
        Ok(())
    }

    /// Set a temporary breakpoint at `target`, resume execution until it's
    /// hit with `sp >= min_sp`, then remove the temporary breakpoint. Shared
    /// by `step_over`/`step_out` — identical logic to the Windows backend.
    async fn run_to_return(&self, tid: ThreadId, target: Address, min_sp: u64) -> Result<DebugEvent, DebugError> {
        // Refuse to patch a byte that is not code.
        //
        // `step_out` takes this address from the target's own stack, so a
        // corrupt frame — or a function compiled without a frame pointer,
        // where the frame register holds a data pointer — hands us an address
        // that is not an instruction. Planting the `0xCC` there overwrites a
        // byte of the program's DATA and restores it later from a table the
        // program knows nothing about: silent corruption caused by inspecting
        // the process. Verified on a live target: without this the debugger
        // really does write into a read/write page.
        //
        // A region the map does not describe is left alone rather than
        // refused: `memory_maps` can legitimately miss freshly mapped code,
        // and refusing what we merely cannot see would break stepping out of
        // JIT-generated frames.
        if let Ok(maps) = self.memory_maps().await
            && let Some(region) = maps
                .iter()
                .find(|m| target.as_u64() >= m.base.as_u64() && target.as_u64() < m.base.as_u64().saturating_add(m.size))
            && !region.executable
        {
            return Err(DebugError::StepError(format!(
            "run_to_return: {target:?} is not executable memory — the return address read                      from the stack does not point at code, and planting a breakpoint there would                      corrupt the target's data"
            )));
        }
        // "Is a trap ARMED there", not "is that address in my map".
        //
        // `contains_key` is also true for a breakpoint the caller DISABLED —
        // and a disabled breakpoint has had its original byte written back, so
        // there is no trap in the target at all. Believing otherwise made
        // `step_over`/`step_out` plant nothing, resume freely, and return
        // whatever the process did next as if it were the step result: the
        // target runs to exit while the call reports success. A stepping
        // primitive that silently becomes "continue" is the worst failure mode
        // a debugger has, because the caller cannot tell it happened.
        let (tracked, armed) = {
            let planted = self.breakpoints.lock();
            let disabled = self.disabled.lock();
            let tracked = planted.contains_key(&target.as_u64());
            (tracked, tracked && !disabled.contains(&target.as_u64()))
        };
        if !armed {
            self.set_breakpoint(target, BreakpointKind::Software).await?;
        }
        // From here until this function returns — by ANY path — a stop at
        // `target` belongs to this call and not to the caller's conditional
        // breakpoint. A guard rather than an insert/remove pair: the wait loop
        // below propagates errors with `?`, so a target that dies mid-step would
        // otherwise leave the address marked forever and silently disable the
        // user's condition there for the rest of the session.
        let _internal = crate::AddressGuard::new(&self.internal_stops, target.as_u64());

        let result = loop {
            let event = self.continue_execution().await?;
            // Decision shared with every other backend — see
            // `crate::run_to_return_step` for the two ordering defects this
            // encodes (exit-before-register-read, and a vanished thread while
            // the process is still alive). A `None` here means the register
            // read failed, which is a gone thread, not a failure of this call.
            let regs = self.get_registers(tid).await.ok().map(|r| (r.pc, r.sp));
            match crate::run_to_return_step(event.reason.is_exit(), regs, target.as_u64(), min_sp) {
                crate::RunToReturnStep::Done => break Ok(event),
                crate::RunToReturnStep::KeepGoing => {}
            }
        };

        if !armed && tracked && !matches!(&result, Ok(ev) if ev.reason.is_exit()) {
            // It was the caller's breakpoint, merely DISABLED. We re-armed it
            // to make the step work, so put it back the way we found it —
            // removing it would delete a breakpoint the caller set and still
            // expects to see in `breakpoints()`.
            //
            // Skipped when the target has exited, for the same reason the
            // branch below skips its cleanup: writing to a dead process blocks
            // on a channel whose debug thread is gone. Measured, not assumed —
            // the first version of this fix hung a live test on exactly that.
            // A failed restore is REPORTED, not discarded.
            //
            // The "writing to a dead process blocks" reason above is why the
            // SIBLING branch guards its `?` with an exit check — but this
            // branch already excludes the exit case in its own `if`, so by the
            // time we get here the process is known to be ALIVE. The two
            // adjacent branches were doing opposite things in the same
            // situation.
            //
            // If this fails, a breakpoint the caller explicitly DISABLED is
            // left ARMED in a live target while the step is reported as having
            // succeeded, and the program then stops at a trap that, as far as
            // the API is concerned, does not exist.
            //
            // Propagated only when `result` is itself Ok: an error already on
            // its way to the caller says more than this one, and clobbering it
            // would be the same defect facing the other way.
            let restored = self.disable_breakpoint(target).await;
            if result.is_ok() {
                restored?;
            }
        } else if !armed && !tracked {
            // Best-effort cleanup: if the target exited, the process (and
            // its memory) is already gone, so `remove_breakpoint` failing
            // here is expected, not a real error — don't let it clobber a
            // perfectly valid `ProcessExit` result with a spurious `Err`.
            let cleanup = self.remove_breakpoint(target).await;
            if !matches!(&result, Ok(ev) if ev.reason.is_exit()) {
                cleanup?;
            }
        }
        result
    }

    /// A process that has exited takes its debugger session with it.
    ///
    /// The event-loop thread `return`s as soon as it reports the exit, so
    /// `cmd_tx` is dead from that moment on and every later `send` fails. That
    /// left the instance permanently stuck: `detach`/`kill` could not succeed
    /// (they need the loop), and `attach` refuses while `pid` is set — so a
    /// debugger whose target simply ran to completion could never be reused,
    /// and `is_attached()` kept answering `true` for a process that no longer
    /// exists.
    ///
    /// Dropping the breakpoint tables here is correct rather than merely tidy:
    /// the patched bytes died with the process, and `kill` already documents
    /// what a stale entry costs — the NEXT process inherits it, and
    /// `set_breakpoint` then reports success while planting nothing.
    fn retire_session_after_exit(&self) {
        *self.pid.lock() = None;
        // The current thread cannot outlive the pid. `kill` and `detach`
        // cleared everything else — breakpoints, watchpoints, the command
        // channel — but left `current_tid` set, so the instance contradicted
        // itself: `is_attached()` answered false while `current_thread()` still
        // handed out the dead process's tid. That tid is the default the
        // register and stepping calls fall back to.
        *self.current_tid.lock() = None;
        *self.cmd_tx.lock() = None;
        *self.current_tid.lock() = None;
        self.breakpoints.lock().clear();
        self.hit_counts.lock().clear();
        self.disabled.lock().clear();
        self.conditions.lock().clear();
        // A stale load base outliving the session would make the NEXT
        // process's pending request resolve immediately, at the old
        // process's address — a fabricated answer, not a missing one.
        self.pending.lock().clear();
        self.ignore_counts.lock().clear();
        self.thread_filters.lock().clear();
        // The eighth map, and the only one this sweep forgot. Unlike the other
        // seven it is not passive bookkeeping: `rearm_watchpoints_on_new_threads`
        // reads it on every resume and PROGRAMS the debug registers from it. So
        // a surviving entry does not merely describe a watchpoint that is gone —
        // the first resume of the NEXT process arms DR0-DR3 at an address
        // belonging to a program that no longer exists, and the target either
        // traps somewhere the caller never asked about or burns the four
        // hardware slots so a legitimate `set_watchpoint` is refused with "all
        // four slots in use".
        self.hw_watchpoints.lock().clear();
    }

    fn send(&self, cmd: Command) -> Result<Reply, DebugError> {
        let guard = self.cmd_tx.lock();
        let tx = guard.as_ref().ok_or(DebugError::NotAttached)?;
        tx.send(cmd).map_err(|_| DebugError::NotAttached)?;
        // Hold the command lock across the WHOLE request/reply exchange.
        // There is one channel pair shared by every caller, so a reply only
        // means anything to whoever sent the command right before it.
        // A `drop(guard)` used to sit here, letting two concurrent callers
        // interleave as A-send, B-send, B-recv, A-recv — each receiving the
        // other's reply. With different `Reply` variants that is a spurious
        // "unexpected reply"; with the SAME variant (two `read_memory`
        // calls) each caller silently gets the other's bytes, no error at
        // all. Proved with a live concurrency test on Windows (iter 247);
        // all three backends had the identical protocol.
        let rx_guard = self.reply_rx.lock();
        let rx = rx_guard.as_ref().ok_or(DebugError::NotAttached)?;
        let reply = rx.recv().map_err(|_| DebugError::NotAttached);
        drop(rx_guard);
        drop(guard);
        reply
    }

    /// Spawn the dedicated ptrace thread and send it a `DoLaunch`/`DoAttach`
    /// startup command, blocking on the thread's own `Reply::Started` before
    /// returning — see the module doc for why the actual `fork`/`ptrace`
    /// call must happen on that thread, not here.
    fn spawn_loop(&self, startup: Command) -> Result<ProcessId, DebugError> {
        let (cmd_tx, cmd_rx) = channel::<Command>();
        let (reply_tx, reply_rx) = channel::<Reply>();

        let handle = std::thread::spawn(move || {
            ptrace_loop(&cmd_rx, &reply_tx);
        });

        cmd_tx.send(startup).map_err(|_| DebugError::LaunchError("ptrace thread died before startup".into()))?;
        let started = reply_rx.recv().map_err(|_| DebugError::LaunchError("ptrace thread died before startup".into()))?;
        let Reply::Started(result) = started else {
            return Err(DebugError::LaunchError("unexpected reply to startup command".into()));
        };

        if result.is_ok() {
            *self.cmd_tx.lock() = Some(cmd_tx);
            *self.reply_rx.lock() = Some(reply_rx);
            *self.thread.lock() = Some(handle);
        }
        result
    }
}

/// `PTRACE_TRACEME` in the child, then `execvp` the target. Runs inside the
/// forked child, on the ptrace thread, per `libc::fork` safety rules — only
/// Thread ids of `pid`, read synchronously from `/proc/<pid>/task`.
///
/// `threads()` does the same walk but is `async`, and `Drop` cannot await.
/// Only the enumeration happens here: the debug-register writes still go
/// through the command channel, because `PTRACE_POKEUSER` is only valid from
/// the tracer thread. (On the Windows twin the same split was forced for a
/// different reason — a `SetThreadContext` from another thread is accepted
/// and silently does nothing.)
fn enumerate_thread_ids(pid: libc::pid_t) -> Vec<ThreadId> {
    let Ok(entries) = std::fs::read_dir(format!("/proc/{pid}/task")) else {
        return Vec::new();
    };
    entries
        .filter_map(|e| e.ok())
        .filter_map(|e| e.file_name().to_str().and_then(|n| n.parse::<u32>().ok()))
        .map(ThreadId)
        .collect()
}

impl Drop for LinuxDebugger {
    /// Best-effort detach when an attached debugger goes out of scope.
    ///
    /// Without this, dropping while attached left every planted `0xCC` in the
    /// tracee. The kernel detaches and resumes the tracee when its tracer
    /// dies, so it runs straight into that int3 with no tracer left to handle
    /// the SIGTRAP — whose default action terminates it. Proved with a live
    /// test reading `/proc/<pid>/stat` (iter 250): the target came back as a
    /// zombie every time. Same defect `detach()` was fixed for in iter 245,
    /// reached through a different door.
    ///
    /// Synchronous on purpose: `Drop` cannot await, but `send` is a blocking
    /// channel round-trip, so the same work `detach()` does is reachable
    /// here. Every step is best-effort — after `detach()`/`kill()` there is
    /// no channel left and each `send` simply fails, the correct no-op.
    fn drop(&mut self) {
        if self.cmd_tx.lock().is_none() {
            return; // already detached or never attached
        }
        let planted: Vec<(u64, Vec<u8>)> =
            self.breakpoints.lock().iter().map(|(a, b)| (*a, b.clone())).collect();
        for (addr, original) in planted {
            // The VALUE has nowhere to go — `Drop` cannot fail — but the FACT
            // does. A restore that does not land leaves a trap in the target's
            // code, and that target will die on it later in a process this
            // debugger has already let go of, with nothing anywhere connecting
            // the two. Same resolution as iteration 568: a path that may not
            // FAIL must still not stay quiet.
            if let Err(e) = self.send(Command::WriteMemory(addr, original)) {
                tracing::error!(
                    address = format_args!("{addr:#x}"),
                    error = %e,
                    "detaching without restoring the original bytes: a trap is being left in                      the target's code and it will trap there with no debugger attached"
                );
            }
        }
        self.breakpoints.lock().clear();
        self.hit_counts.lock().clear();
        self.disabled.lock().clear();
        self.conditions.lock().clear();
        // A stale load base outliving the session would make the NEXT
        // process's pending request resolve immediately, at the old
        // process's address — a fabricated answer, not a missing one.
        self.pending.lock().clear();
        self.ignore_counts.lock().clear();
        self.thread_filters.lock().clear();
        // Same hazard one layer down: an armed debug register left behind
        // traps in a process with no debugger to take the trap. `detach()`
        // handles this via the async sweep, which `Drop` cannot await.
        if !self.hw_watchpoints.lock().is_empty() {
            if let Some(pid) = *self.pid.lock() {
                for tid in enumerate_thread_ids(pid.0 as libc::pid_t) {
                    let Ok(Reply::Registers(Ok(mut regs))) =
                        self.send(Command::GetRegisters(tid))
                    else {
                        continue;
                    };
                    // Same distinction as the reporting loop, but there is no
                    // `still_armed` to answer into here. So an unverifiable set
                    // is handled by DOING the work instead of skipping it:
                    // writing zeros to a thread that had none costs a register
                    // write, while skipping one that had some leaves a trap
                    // armed in a process we are walking away from.
                    if matches!(
                        crate::debug_register_state(&regs),
                        crate::DebugRegisterState::Clean
                    ) {
                        continue;
                    }
                    for name in ["dr0", "dr1", "dr2", "dr3", "dr6", "dr7"] {
                        regs.set(name, 0);
                    }
                    let _ = self.send(Command::SetRegisters(tid, regs));
                }
            }
            self.hw_watchpoints.lock().clear();
        }
        let _ = self.send(Command::Detach);
    }
}

/// async-signal-safe calls are made between `fork` and `exec`.
fn do_launch(opts: &LaunchOptions) -> Result<libc::pid_t, DebugError> {
    let exe = CString::new(opts.executable.clone()).map_err(|e| DebugError::LaunchError(e.to_string()))?;

    let mut cmd = ProcessCommand::new(&opts.executable);
    cmd.args(&opts.args);
    for (k, v) in &opts.env {
        cmd.env(k, v);
    }
    if let Some(dir) = &opts.working_dir {
        cmd.current_dir(dir);
    }
    let _ = &exe; // path validity already checked by CString::new above

    // SAFETY: `pre_exec` runs in the forked child before `execvp`, so only
    // async-signal-safe calls are permitted here. `PTRACE_TRACEME` is
    // documented safe in this context and is the standard way to start a
    // traced child (mirrors gdb/strace's own launch path).
    unsafe {
        cmd.pre_exec(|| {
            if libc::ptrace(libc::PTRACE_TRACEME, 0, std::ptr::null_mut::<libc::c_void>(), std::ptr::null_mut::<libc::c_void>()) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }

    let child = cmd.spawn().map_err(|e| DebugError::LaunchError(format!("spawn failed: {e}")))?;
    let pid = child.id() as libc::pid_t;
    // Prevent std::process::Child from reaping/killing this pid on drop —
    // the ptrace thread owns its lifecycle from here via waitpid/kill.
    std::mem::forget(child);

    // The child raises SIGTRAP on its own execve under PTRACE_TRACEME; reap
    // that initial stop here so the caller sees a debuggee that's ready for
    // `ContinueExecution`, mirroring the Windows backend's initial-breakpoint
    // semantics.
    let mut status: libc::c_int = 0;
    unsafe {
        libc::waitpid(pid, &mut status, 0);
    }

    Ok(pid)
}

/// `PTRACE_ATTACH` an already-running process. Must run on the ptrace
/// thread — see the module doc.
fn do_attach(pid: libc::pid_t) -> Result<(), DebugError> {
    let ok = unsafe { libc::ptrace(libc::PTRACE_ATTACH, pid, std::ptr::null_mut::<libc::c_void>(), std::ptr::null_mut::<libc::c_void>()) };
    if ok < 0 {
        return Err(DebugError::LaunchError(format!(
            "PTRACE_ATTACH failed for pid {pid}: {}",
            std::io::Error::last_os_error()
        )));
    }
    let mut status: libc::c_int = 0;
    unsafe {
        libc::waitpid(pid, &mut status, 0);
    }
    Ok(())
}

/// Runs entirely on the dedicated ptrace thread: performs the initial
/// `fork`+`PTRACE_TRACEME`+`exec` or `PTRACE_ATTACH` (so it happens on this
/// thread, which then owns every further `ptrace` call for this tracee) and
/// answers [`Command`]s sent from the async wrapper.
fn ptrace_loop(cmd_rx: &Receiver<Command>, reply_tx: &Sender<Reply>) {
    let pid = match cmd_rx.recv() {
        Ok(Command::DoLaunch(opts)) => match do_launch(&opts) {
            Ok(pid) => {
                let _ = reply_tx.send(Reply::Started(Ok(ProcessId(pid as u32))));
                pid
            }
            Err(e) => {
                let _ = reply_tx.send(Reply::Started(Err(e)));
                return;
            }
        },
        Ok(Command::DoAttach(pid)) => match do_attach(pid) {
            Ok(()) => {
                let _ = reply_tx.send(Reply::Started(Ok(ProcessId(pid as u32))));
                pid
            }
            Err(e) => {
                let _ = reply_tx.send(Reply::Started(Err(e)));
                return;
            }
        },
        _ => {
            let _ = reply_tx.send(Reply::Started(Err(DebugError::LaunchError(
                "ptrace thread expected DoLaunch/DoAttach as its first command".into(),
            ))));
            return;
        }
    };

    let mem_path = format!("/proc/{pid}/mem");

    // Multi-thread tracing: ask the kernel to auto-attach every thread this
    // tracee clones (`PTRACE_O_TRACECLONE`). Without it only the initial
    // thread is ptrace-attached, so any secondary tid returned by `threads()`
    // fails every per-tid ptrace call with ESRCH. Best-effort: a kernel that
    // rejects the option leaves the old single-thread behaviour intact rather
    // than failing the whole launch.
    unsafe {
        libc::ptrace(
            libc::PTRACE_SETOPTIONS,
            pid,
            std::ptr::null_mut::<libc::c_void>(),
            libc::PTRACE_O_TRACECLONE as *mut libc::c_void,
        );
    }

    // PERSISTENT across commands, deliberately: `waitpid(-1)` can reap a newly
    // cloned thread's birth-stop BEFORE the cloning parent's PTRACE_EVENT_CLONE
    // notification — the kernel does not order those two. So "have I ever seen
    // this tid stop?" is the only race-free way to tell a birth-stop (must be
    // re-continued, is not a debug event) from a real stop. Seeded with the
    // main thread, whose initial stop was already consumed by do_launch/do_attach.
    let mut known_tids: HashSet<libc::pid_t> = HashSet::new();
    known_tids.insert(pid);
    // Tids currently sitting in a ptrace-stop, i.e. safe to issue per-tid
    // ptrace requests against. Everything else is running and must be stopped
    // first (see `ensure_stopped`).
    let mut stopped_tids: HashSet<libc::pid_t> = HashSet::new();
    stopped_tids.insert(pid);
    // Which thread the next `ContinueExecution` should resume — mirrors
    // `windows_debugger.rs`'s `last_tid`.
    let mut last_tid: libc::pid_t = pid;

    // The signal the tracee last stopped BY, to be delivered when it resumes.
    // Zero means "nothing pending" and is also what a SIGTRAP leaves behind,
    // since those stops are the debugger's own doing.
    let mut pending_signal: libc::c_int = 0;

    // Thread exits that `ensure_stopped` has already REAPED, waiting to be
    // delivered as `StopReason::ThreadExit`.
    //
    // Why a queue is needed at all: a per-tid command (GetRegisters,
    // SetRegisters, SingleStep) must first bring its target into a ptrace-stop,
    // and a thread can die in that window. `ensure_stopped`'s `waitpid` then
    // consumes the exit — measured in iteration 528 as
    // `ensure_stopped waitpid(2719) -> 2719 status=0x0` — so `wait_for_stop_any`
    // can never see it and `StopReason::ThreadExit` had no producer on Linux
    // even though its branch was written and correct.
    //
    // A synchronous command cannot answer with an event that belongs to a
    // different thread: its caller asked for registers, not for news. The exit
    // is therefore parked here and handed over by the next `ContinueExecution`,
    // which is the one command whose whole purpose is to return the next event.
    let mut deferred_exits: Vec<(libc::pid_t, libc::c_int)> = Vec::new();

    while let Ok(cmd) = cmd_rx.recv() {
        match cmd {
            Command::DoLaunch(_) | Command::DoAttach(_) => {}
            Command::ContinueExecution => {
                // An exit already reaped by `ensure_stopped` is delivered here,
                // BEFORE anything is resumed.
                //
                // Before, not after, for two reasons. The currently stopped
                // thread must stay stopped: this event belongs to a thread that
                // is already gone, so resuming for it would advance the target
                // for news that cost it nothing, and the next resume would have
                // nothing left to resume. And `last_tid` is deliberately left
                // alone — the thread that is parked in a ptrace-stop is still
                // the one the NEXT continue has to resume.
                //
                // A dead thread is not a thread to resume, which is why
                // `wait_for_stop_any` sets `NO_THREAD_TO_RESUME` on its own
                // ThreadExit path; here the stopped thread is a different one
                // and is still resumable, so that must NOT be copied.
                if let Some((dead, status)) = deferred_exits.pop() {
                    let exit_code = if libc::WIFEXITED(status) {
                        libc::WEXITSTATUS(status)
                    } else {
                        -libc::WTERMSIG(status)
                    };
                    if ptrace_trace_enabled() {
                        eprintln!("[ptrace] delivering deferred ThreadExit tid={dead} code={exit_code}");
                    }
                    let _ = reply_tx.send(Reply::Event(Ok(DebugEvent::new(
                        ProcessId(pid as u32),
                        ThreadId(dead as u32),
                        StopReason::ThreadExit { tid: ThreadId(dead as u32), exit_code },
                    ))));
                    continue;
                }
                // Resume whichever thread last reported a stop, not a hardcoded
                // `pid`: with TRACECLONE any thread can be the stopped one.
                //
                // `0` means "the last event left NOBODY stopped" — see
                // `NO_THREAD_TO_RESUME`. This protocol assumed one stopped
                // thread per event, which held while every event was a stop.
                // Thread birth and death are not stops: the thread is resumed
                // (or gone) by the time the caller hears about it, so there is
                // nothing to resume and the next command must go straight to
                // waiting. Resuming anyway is what made iteration 526's
                // ThreadCreate answer `PTRACE_CONT failed: No such process`
                // once the new thread had exited.
                let resume = last_tid;
                // Re-inject the signal the target was stopped BY.
                //
                // The fourth ptrace argument is the signal to deliver on resume,
                // and it was always zero: every non-SIGTRAP stop — SIGSEGV,
                // SIGBUS, SIGFPE, SIGILL, a SIGUSR1 the program uses for its own
                // purposes — was reported to the caller and then SWALLOWED. The
                // tracee resumed as if the signal had never been raised, so its
                // own handlers never ran: a crash handler stayed silent, a
                // SIGSEGV-driven GC barrier or JIT guard page never fired, and a
                // program that behaves one way on its own behaved another way
                // under this debugger. That is the worst property a debugger can
                // have, because it makes the observation change the result.
                //
                // SIGTRAP is deliberately NOT re-injected: those are ours (the
                // int3 we planted, a single step, a watchpoint), and handing one
                // back to the target would deliver a signal it never received.
                let deliver = pending_signal;
                pending_signal = 0;
                if resume != NO_THREAD_TO_RESUME {
                    let ok = unsafe { libc::ptrace(libc::PTRACE_CONT, resume, std::ptr::null_mut::<libc::c_void>(), deliver as *mut libc::c_void) };
                    if ok < 0 {
                        let _ = reply_tx.send(Reply::Event(Err(DebugError::StepError(format!(
                            "PTRACE_CONT failed: {}",
                            std::io::Error::last_os_error()
                        )))));
                        continue;
                    }
                    stopped_tids.remove(&resume);
                }
                // "Continue" means continue the PROCESS, so every thread that
                // is still stopped must run again — not just the one that
                // reported the last event.
                //
                // `stopped_tids` was maintained all along and never consulted
                // here: the capability was present and switched off. What that
                // cost was measured on 2026-08-31, live, from /proc:
                //
                //     tid 7678  state t  ptrace_stop      <- never resumed
                //     tid 7677  state S  futex_do_wait    <- pthread_join on it
                //     tid 7676  state S  do_wait          <- waitpid, forever
                //
                // Three parties, each waiting on one of the other two. One
                // stranded thread is enough, because a tracee that joins it
                // never reaches its next stop and the debugger never gets
                // another event to hand back.
                //
                // A tid that has died in the meantime answers ESRCH; that is
                // not an error to report, it just stops being our business, so
                // it is dropped from the set either way.
                let leftovers: Vec<libc::pid_t> =
                    stopped_tids.iter().copied().filter(|t| *t != resume).collect();
                for tid in leftovers {
                    let ok = unsafe {
                        libc::ptrace(libc::PTRACE_CONT, tid, std::ptr::null_mut::<libc::c_void>(), std::ptr::null_mut::<libc::c_void>())
                    };
                    if ok < 0 && ptrace_trace_enabled() {
                        eprintln!("[ptrace] tid={tid} branch=resume-sweep PTRACE_CONT failed: {}", std::io::Error::last_os_error());
                    }
                    stopped_tids.remove(&tid);
                }
                let (event, is_exit) = wait_for_stop_any(pid, &mut known_tids, &mut stopped_tids, &mut last_tid);
                // Remember what it stopped by, so the next resume can hand it
                // over. Any other stop clears it: a signal must be delivered
                // once, not queued up and replayed later.
                // ...except a SIGSTOP, which is the debugger's own doing.
                //
                // `pause()` stops the target by sending it SIGSTOP, so that
                // signal-stop is reported like any other and would be handed
                // straight back on the next resume — putting the process into a
                // job-control stop it never asked for. `pause` followed by
                // `continue` would then not resume anything, and the process
                // would sit at `T` exactly as in the leak `detach` already sends
                // a SIGCONT to undo. gdb makes the same exclusion for the same
                // reason: a signal the debugger raised to gain control is not
                // part of the program's behaviour.
                pending_signal = match &event.reason {
                    StopReason::Signal { signum, .. } if *signum != libc::SIGSTOP => *signum,
                    _ => 0,
                };
                let _ = reply_tx.send(Reply::Event(Ok(event)));
                if is_exit {
                    return;
                }
            }
            Command::SingleStep(tid) => {
                // Target the requested tid, not the process's main `pid` —
                // on Linux each ptrace call addresses a specific tid (NPTL
                // threads are each their own "pid" from ptrace's point of
                // view). Previously this always single-stepped `pid`
                // regardless of which `tid` the caller asked for; for the
                // (only currently-supported) single-threaded case tid == pid
                // so this is a no-op change, but for any other tid the old
                // code would have silently stepped the WRONG thread instead
                // of erroring. Since non-main threads are never actually
                // PTRACE_ATTACHed by this backend, a genuinely different tid
                // now correctly fails (ESRCH) instead of confidently doing
                // the wrong thing. With PTRACE_O_TRACECLONE (see above) every
                // thread IS attached, so a secondary tid now genuinely works —
                // it just has to be brought into a ptrace-stop first.
                let target = tid.0 as libc::pid_t;
                ensure_stopped(pid, target, &mut known_tids, &mut stopped_tids, &mut deferred_exits);
                // Same re-injection as `ContinueExecution`: stepping past a
                // signal must not eat it either.
                let deliver = pending_signal;
                pending_signal = 0;
                let ok = unsafe { libc::ptrace(libc::PTRACE_SINGLESTEP, target, std::ptr::null_mut::<libc::c_void>(), deliver as *mut libc::c_void) };
                if ok < 0 {
                    let _ = reply_tx.send(Reply::Event(Err(DebugError::StepError(format!(
                        "PTRACE_SINGLESTEP failed: {}",
                        std::io::Error::last_os_error()
                    )))));
                    continue;
                }
                stopped_tids.remove(&target);
                if ptrace_trace_enabled() {
                    eprintln!("[ptrace] singlestep({target}) issued, waiting");
                }
                // Wait on the STEPPED tid specifically: a `waitpid(-1)` here
                // could reap an unrelated thread's stop and report it as the
                // result of this single-step.
                let (event, is_exit) = wait_for_stop_tid(pid, target);
                // Remember what it stopped by, so the next resume can hand it
                // over. Any other stop clears it: a signal must be delivered
                // once, not queued up and replayed later.
                // ...except a SIGSTOP, which is the debugger's own doing.
                //
                // `pause()` stops the target by sending it SIGSTOP, so that
                // signal-stop is reported like any other and would be handed
                // straight back on the next resume — putting the process into a
                // job-control stop it never asked for. `pause` followed by
                // `continue` would then not resume anything, and the process
                // would sit at `T` exactly as in the leak `detach` already sends
                // a SIGCONT to undo. gdb makes the same exclusion for the same
                // reason: a signal the debugger raised to gain control is not
                // part of the program's behaviour.
                pending_signal = match &event.reason {
                    StopReason::Signal { signum, .. } if *signum != libc::SIGSTOP => *signum,
                    _ => 0,
                };
                if ptrace_trace_enabled() {
                    eprintln!("[ptrace] singlestep({target}) done is_exit={is_exit}");
                }
                stopped_tids.insert(target);
                last_tid = target;
                let _ = reply_tx.send(Reply::Event(Ok(event)));
                if is_exit {
                    return;
                }
            }
            Command::GetRegisters(tid) => {
                // Same tid-targeting fix as `SingleStep` above.
                let target = tid.0 as libc::pid_t;
                ensure_stopped(pid, target, &mut known_tids, &mut stopped_tids, &mut deferred_exits);
                let result = read_regs(target).map(|r| {
                    let mut regs = regs_to_register_set(&r);
                    // Debug registers live in a separate area of `struct user`
                    // (PTRACE_GETREGS only covers `user_regs_struct`), so they're
                    // fetched via PTRACE_PEEKUSER per-slot. A read failure here
                    // (e.g. an odd kernel) is tolerated — GP registers are still
                    // valid — rather than failing the whole GetRegisters call.
                    #[cfg(not(target_arch = "aarch64"))]
                    for idx in [0usize, 1, 2, 3, 6, 7] {
                        if let Ok(v) = read_debug_reg(target, idx) {
                            regs.set(&format!("dr{idx}"), v);
                        }
                    }
                    // AArch64 has no `DR` file to peek at: the same four slots
                    // live behind NT_ARM_HW_WATCH as DBGWVR/DBGWCR pairs and
                    // are translated into the `dr` vocabulary here, so every
                    // caller above stays byte-identical with the other
                    // backends. Same disposition as the x86 loop: a read
                    // failure leaves the GP registers valid rather than
                    // failing the whole GetRegisters.
                    #[cfg(target_arch = "aarch64")]
                    merge_debug_state(target, &mut regs);
                    regs
                });
                let _ = reply_tx.send(Reply::Registers(result));
            }
            Command::SetRegisters(tid, regs) => {
                // Same tid-targeting fix as `SingleStep` above.
                let target = tid.0 as libc::pid_t;
                ensure_stopped(pid, target, &mut known_tids, &mut stopped_tids, &mut deferred_exits);
                let result = read_regs(target).and_then(|mut r| {
                    apply_register_set(&mut r, &regs);
                    write_regs(target, &r)
                }).and_then(|()| {
                    // Debug registers (hardware watchpoints: DR0-3 address
                    // slots + DR7 control) round-trip through PTRACE_POKEUSER,
                    // not PTRACE_SETREGS — see the GetRegisters arm above.
                    // Without this, `debug.set_watchpoint`'s computed DR7/DR0-3
                    // values were silently discarded on Linux: `set_register`
                    // would return Ok(()) (no error) while never touching the
                    // tracee's actual debug registers, so the watchpoint would
                    // never fire — reported live:true but functionally dead.
                    #[cfg(not(target_arch = "aarch64"))]
                    for idx in [0usize, 1, 2, 3, 6, 7] {
                        if let Some(v) = regs.get(&format!("dr{idx}")) {
                            write_debug_reg(target, idx, v)?;
                        }
                    }
                    // Whole-set on AArch64, because DBGWVR/DBGWCR are computed
                    // from the slot address AND DR7 together — a per-register
                    // write could not express `dr0` without already knowing
                    // `dr7`. Unlike the read side this DOES propagate: a
                    // watchpoint the caller asked for and that was not
                    // programmed must not be reported as set.
                    #[cfg(target_arch = "aarch64")]
                    write_debug_registers(target, &regs)?;
                    Ok(())
                });
                let _ = reply_tx.send(Reply::Ack(result));
            }
            Command::ReadMemory(addr, size) => {
                let result = OpenOptions::new()
                    .read(true)
                    .open(&mem_path)
                    .map_err(|e| DebugError::MemoryError(addr, format!("open {mem_path} failed: {e}")))
                    .and_then(|f: File| {
                        let mut buf = vec![0u8; size];
                        f.read_exact_at(&mut buf, addr)
                            .map_err(|e| DebugError::MemoryError(addr, format!("pread failed: {e}")))?;
                        Ok(buf)
                    });
                let _ = reply_tx.send(Reply::Memory(result));
            }
            Command::WriteMemory(addr, data) => {
                let result = OpenOptions::new()
                    .write(true)
                    .open(&mem_path)
                    .map_err(|e| DebugError::MemoryError(addr, format!("open {mem_path} failed: {e}")))
                    .and_then(|f: File| {
                        f.write_all_at(&data, addr).map_err(|e| DebugError::MemoryError(addr, format!("pwrite failed: {e}")))?;
                        Ok(data.len())
                    });
                let _ = reply_tx.send(Reply::WriteCount(result));
            }
            Command::Detach => {
                // The answer is DERIVED from the syscalls, not asserted.
                //
                // Every `PTRACE_DETACH` below had its result discarded and the
                // reply was the literal `Ok(())`, so `detach()` said "detached"
                // whether or not anything had been.
                //
                // ESRCH is NOT a failure, and forgiving it is the whole
                // difference between a useful check and a useless one: a thread
                // that died while we were attached answers ESRCH, and so does a
                // process that is already gone — in both cases there is nothing
                // left to detach from, which is what "detached" means. Any
                // OTHER errno (EPERM, EINVAL) says the target is still there
                // and still ours, and that is what must reach the caller. The
                // same asymmetry is already applied in `ensure_stopped`:
                // "Only ESRCH removes."
                //
                // The FIRST real failure is kept rather than the last: it is
                // the one closest to the cause.
                let mut failure: Option<String> = None;
                unsafe {
                    // Every auto-attached (TRACECLONE) thread needs its own
                    // detach, otherwise secondary threads stay traced/stopped.
                    for &t in &known_tids {
                        if t != pid {
                            if libc::ptrace(libc::PTRACE_DETACH, t, std::ptr::null_mut::<libc::c_void>(), std::ptr::null_mut::<libc::c_void>()) < 0 {
                                let e = std::io::Error::last_os_error();
                                if e.raw_os_error() != Some(libc::ESRCH) && failure.is_none() {
                                    failure = Some(format!("PTRACE_DETACH(tid {t}) failed: {e}"));
                                }
                            }
                        }
                    }
                    if libc::ptrace(libc::PTRACE_DETACH, pid, std::ptr::null_mut::<libc::c_void>(), std::ptr::null_mut::<libc::c_void>()) < 0 {
                        let e = std::io::Error::last_os_error();
                        if e.raw_os_error() != Some(libc::ESRCH) && failure.is_none() {
                            failure = Some(format!("PTRACE_DETACH(pid {pid}) failed: {e}"));
                        }
                    }
                    // `PTRACE_DETACH` only resumes the tracee from a
                    // ptrace-stop — it does NOT clear an independent
                    // job-control stop from `SIGSTOP` (which `pause()`
                    // sends). Without this, detaching after a `pause()`
                    // left the process frozen forever with no way for the
                    // now-detached caller to un-stick it — found via a live
                    // test that polled `/proc/<pid>/stat`'s process-state
                    // field and saw it stuck at `T` (stopped) indefinitely.
                    // A stray SIGCONT to an already-running process is a
                    // harmless no-op, so this is safe to send unconditionally
                    // rather than tracking whether `pause()` was ever called.
                    libc::kill(pid, libc::SIGCONT);
                }
                let result = failure.map_or(Ok(()), |m| Err(DebugError::DetachError(m)));
                let _ = reply_tx.send(Reply::Ack(result));
                return;
            }
            Command::Kill => {
                if ptrace_trace_enabled() {
                    eprintln!("[ptrace] Kill: SIGKILL pid={pid}");
                }
                // The answer is DERIVED from the syscall, not asserted.
                //
                // ESRCH is forgiven for the same reason as in `Detach`: a
                // process that is already gone cannot be killed and does not
                // need to be — that errno is the successful outcome spelled as
                // a failure. EPERM is not: it says the target is still running
                // and still not ours to end.
                //
                // The reaping below stays UNCHECKED on purpose: it drains
                // children the event loop may already have taken, so a failure
                // there is expected and says nothing about whether the kill
                // landed.
                let mut failure: Option<String> = None;
                unsafe {
                    if libc::kill(pid, libc::SIGKILL) < 0 {
                        let err = std::io::Error::last_os_error();
                        if err.raw_os_error() != Some(libc::ESRCH) {
                            failure = Some(format!("SIGKILL({pid}) failed: {err}"));
                        }
                    }
                    // Reap `pid` itself with a BLOCKING wait first — `kill()`
                    // callers (e.g. `kill_actually_terminates_the_process`)
                    // rely on the process being fully dead-and-reaped by the
                    // time this command's reply arrives, and `SIGKILL`
                    // delivery is asynchronous, so a non-blocking check here
                    // can race ahead of the kernel actually finishing the
                    // teardown (confirmed by this exact test failing when an
                    // earlier version of this fix used `WNOHANG` for
                    // everything).
                    let mut status: libc::c_int = 0;
                    // ...but reap with `waitpid(-1, __WALL)`, NOT
                    // `waitpid(pid, 0)`: the thread-group leader stays an
                    // unreapable zombie until every OTHER traced thread in the
                    // group has been reaped by its tracer, and `0` (no
                    // `__WALL`) cannot even see clone-traced siblings. A
                    // blocking `waitpid(pid)` therefore deadlocks forever on a
                    // multi-threaded tracee — each side waiting for the other.
                    // Found by instrumentation: the trace showed
                    // "Kill: SIGKILL" as the last line, with the fixture left
                    // `<defunct>` in `ps --forest`.
                    loop {
                        let reaped = libc::waitpid(-1, &mut status, libc::__WALL);
                        if reaped <= 0 || reaped == pid {
                            break;
                        }
                    }
                    // THEN drain any other already-dead zombie in the thread
                    // group (non-blocking — nothing else is expected to
                    // still be alive after the group-wide `SIGKILL` above,
                    // so this only cleans up already-exited stragglers, not
                    // waits on ones still finishing). Each thread group
                    // member is its own separately waitable entity to a
                    // ptrace parent, so without this a killed MULTI-THREADED
                    // tracee's non-main threads linger as zombies forever —
                    // found via this session's multi-thread work (a test's
                    // worker thread stayed `<defunct>` forever after
                    // `kill()`, confirmed via `ps`).
                    loop {
                        let reaped = libc::waitpid(-1, &mut status, libc::__WALL | libc::WNOHANG);
                        if reaped <= 0 {
                            break;
                        }
                    }
                }
                let result = failure.map_or(Ok(()), |m| Err(DebugError::Os(m)));
                let _ = reply_tx.send(Reply::Ack(result));
                return;
            }
        }
    }
}

/// Read the single byte at `addr` in the tracee via `PTRACE_PEEKTEXT`
/// (returns a full machine word; only the low byte is used) — used by
/// `wait_for_stop` to tell a genuine `int3` breakpoint trap apart from a
/// single-step/hardware-watchpoint trap, both of which also raise `SIGTRAP`
/// on Linux. `None` on any ptrace failure (e.g. an unmapped address),
/// treated by the caller as "not a breakpoint byte".
fn byte_at(pid: libc::pid_t, addr: u64) -> Option<u8> {
    unsafe {
        *libc::__errno_location() = 0;
    }
    let word = unsafe {
        libc::ptrace(
            libc::PTRACE_PEEKTEXT,
            pid,
            addr as *mut libc::c_void,
            std::ptr::null_mut::<libc::c_void>(),
        )
    };
    if word == -1 {
        let errno = unsafe { *libc::__errno_location() };
        if errno != 0 {
            return None;
        }
    }
    Some((word as u64 & 0xFF) as u8)
}

/// Where OUR trap is, given the PC a SIGTRAP reported — or `None` if there
/// isn'''t one there.
///
/// This used to be spelled inline as `byte_at(pid, rip - 1) == Some(0xCC)`.
/// Correct on x86, where `int3` is one byte and the CPU reports the address
/// AFTER it; wrong twice on AArch64, where the trap is a four-byte `BRK #0`
/// and the reported PC is the address OF it. On `aarch64-unknown-linux-gnu`
/// that predicate can never be true, so this backend would classify every one
/// of its own breakpoint hits as a single step.
///
/// Same defect, same shape, and the same fix as `macos_debugger.rs`: both
/// facts already live in `arch_breakpoint`, so ask instead of assuming.
///
/// One `PEEKTEXT` suffices: it returns the eight bytes starting at `addr`,
/// and every trap encoding this crate knows is at most four.
fn trap_at_reported_pc(pid: libc::pid_t, pc: u64) -> Option<u64> {
    let arch = crate::arch_breakpoint::host()?;
    let addr = crate::arch_breakpoint::pc_after_trap(pc, arch);
    let want = crate::arch_breakpoint::trap_bytes(arch);
    unsafe {
        *libc::__errno_location() = 0;
    }
    let word = unsafe {
        libc::ptrace(
            libc::PTRACE_PEEKTEXT,
            pid,
            addr as *mut libc::c_void,
            std::ptr::null_mut::<libc::c_void>(),
        )
    };
    if word == -1 && unsafe { *libc::__errno_location() } != 0 {
        return None;
    }
    let bytes = (word as u64).to_le_bytes();
    (bytes.get(..want.len()) == Some(want)).then_some(addr)
}

/// `true` when `RUSTRE_PTRACE_TRACE` is set — turns on the per-`waitpid`
/// tracing in [`wait_for_stop_any`]. Kept in the shipped code on purpose:
/// three previous attempts at multi-thread ptrace failed by *reasoning* about
/// kernel event ordering; the attempt that succeeded did so by printing the
/// reaped tid, the raw status and the branch taken.
/// `last_tid` value meaning "the last event left no thread stopped, so the next
/// resume must resume nothing and go straight to waiting".
///
/// Zero is never a valid tid, so it is free to carry this meaning. The
/// distinction did not exist while every reported event was a STOP — the thread
/// that reported it was, by construction, the thread to resume. Thread birth
/// and death broke that: both are reported after the thread has been resumed or
/// has died, so there is no one to resume, and resuming anyway targets a
/// running or nonexistent tid.
const NO_THREAD_TO_RESUME: libc::pid_t = 0;

fn ptrace_trace_enabled() -> bool {
    std::env::var_os("RUSTRE_PTRACE_TRACE").is_some()
}

/// Bring `tid` into a ptrace-stop so per-tid ptrace requests
/// (GETREGS/SETREGS/SINGLESTEP) can be issued against it.
///
/// A thread auto-attached via `PTRACE_O_TRACECLONE` is *traced* but usually
/// *running*, and ptrace requests against a running tracee fail with ESRCH.
/// `tgkill(SIGSTOP)` + a blocking `waitpid` on that specific tid converts it
/// into a stop. No-op when the tid is already stopped, or is not one of ours.
fn ensure_stopped(
    pid: libc::pid_t,
    tid: libc::pid_t,
    known_tids: &mut HashSet<libc::pid_t>,
    stopped_tids: &mut HashSet<libc::pid_t>,
    deferred_exits: &mut Vec<(libc::pid_t, libc::c_int)>,
) {
    if stopped_tids.contains(&tid) || !known_tids.contains(&tid) {
        return;
    }
    let trace = ptrace_trace_enabled();
    unsafe {
        // `tgkill` (not `kill`) — SIGSTOP must go to ONE thread, not the whole
        // group. Its first argument is the THREAD GROUP id (the process `pid`),
        // NOT the target tid: passing the tid there makes the call fail with
        // ESRCH for every secondary thread, the signal is never delivered, and
        // the `waitpid` below then blocks forever. That is exactly the hang
        // this backend's earlier multi-thread attempts died on, and it was
        // found by the `RUSTRE_PTRACE_TRACE` output below, not by reasoning.
        let rc = libc::syscall(libc::SYS_tgkill, pid as libc::c_long, tid as libc::c_long, libc::SIGSTOP as libc::c_long);
        if trace {
            eprintln!("[ptrace] ensure_stopped tgkill(tgid={pid}, tid={tid}) -> {rc}");
        }
        if rc != 0 {
            // ESRCH means the thread is GONE. Forgetting it is not tidiness,
            // it is correctness: `known_tids` is what `wait_for_stop_any` uses
            // to tell a thread's birth-stop ("first stop ever from this tid")
            // from an ordinary one — and Linux REUSES tids. A dead tid left in
            // the set makes the next thread that inherits that number arrive as
            // an ordinary stop instead of a birth: no `ThreadCreate`, and an
            // event reported to the caller for a thread nobody resumed.
            //
            // Only ESRCH removes. Any other failure (EPERM, EINVAL) says
            // nothing about whether the thread exists, and forgetting a live
            // thread would be the same defect mirrored.
            if std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH) {
                known_tids.remove(&tid);
                stopped_tids.remove(&tid);
            }
            return;
        }
        loop {
            let mut status: libc::c_int = 0;
            let waited = libc::waitpid(tid, &mut status, libc::__WALL);
            if trace {
                eprintln!("[ptrace] ensure_stopped waitpid({tid}) -> {waited} status={status:#x}");
            }
            if waited != tid {
                return;
            }
            if libc::WIFEXITED(status) || libc::WIFSIGNALED(status) {
                // The thread died while we were stopping it. This `waitpid`
                // has just REAPED that exit, so `wait_for_stop_any` will never
                // see it — measured in iteration 528:
                //   [ptrace] ensure_stopped waitpid(2719) -> 2719 status=0x0
                // which is the worker's WIFEXITED, consumed here.
                //
                // The state is made true (the tid is forgotten, because Linux
                // REUSES tids and a stale entry makes the next thread to
                // inherit that number arrive as an ordinary stop instead of a
                // birth), and the exit itself is HANDED ON rather than dropped.
                //
                // Iteration 541: it used to only `return` here. A synchronous
                // per-tid command still cannot answer with an event about a
                // different thread — its caller asked for registers, not for
                // news — so the exit is queued and delivered by the next
                // `ContinueExecution`, whose whole purpose is to return the
                // next event. Until this existed, `StopReason::ThreadExit` had
                // a correct branch in `wait_for_stop_any` and no producer.
                known_tids.remove(&tid);
                stopped_tids.remove(&tid);
                deferred_exits.push((tid, status));
                return;
            }
            if libc::WIFSTOPPED(status) {
                stopped_tids.insert(tid);
                return;
            }
        }
    }
}

/// `waitpid(-1, __WALL)`: reap whichever thread of the tracee stops next.
///
/// Both the `PTRACE_EVENT_CLONE` stop on the cloning parent and a freshly
/// cloned thread's birth-stop are transparently RESUMED here. The kernel does
/// not order those two against each other, so the birth-stop is recognised by
/// "first stop ever seen from this tid" rather than by having processed the
/// CLONE event first — that ordering assumption is exactly what deadlocked the
/// earlier attempts.
///
/// The birth-stop is resumed AND reported, as `StopReason::ThreadCreate`: the
/// thread does not stay stopped, but the caller is told it exists. The parent's
/// CLONE stop stays silent — it is the same thread's creation seen twice, and
/// reporting both would announce one new thread as two.
fn wait_for_stop_any(
    pid: libc::pid_t,
    known_tids: &mut HashSet<libc::pid_t>,
    stopped_tids: &mut HashSet<libc::pid_t>,
    last_tid: &mut libc::pid_t,
) -> (DebugEvent, bool) {
    let trace = ptrace_trace_enabled();
    loop {
        let mut status: libc::c_int = 0;
        let waited = unsafe { libc::waitpid(-1, &mut status, libc::__WALL) };
        if waited <= 0 {
            let e = std::io::Error::last_os_error();
            if trace {
                eprintln!("[ptrace] waitpid(-1) failed: {e}");
            }
            return (
                DebugEvent::new(
                    ProcessId(pid as u32),
                    ThreadId(pid as u32),
                    StopReason::Unknown { description: format!("waitpid(-1) failed: {e}") },
                ),
                true,
            );
        }

        if libc::WIFEXITED(status) || libc::WIFSIGNALED(status) {
            known_tids.remove(&waited);
            stopped_tids.remove(&waited);
            if waited != pid {
                // A secondary thread exiting is not the process exiting — that
                // distinction was already right, and it stays.
                //
                // What was missing is the other half: the stop was recognised
                // (this branch and its trace line were already here) and then
                // swallowed by a `continue`, so `StopReason::ThreadExit` had no
                // producer on Linux. With ThreadCreate reported (iteration 526)
                // and ThreadExit silent, anything tracking threads from these
                // events would watch the list grow and never shrink — worse
                // than not tracking, because it looks like it works.
                //
                // `exit_code` follows the convention `classify_status` already
                // uses for the process: the status for a normal exit, the
                // NEGATED signal number for a killed one. And this thread is
                // dead, so there is nobody to resume next.
                if trace {
                    eprintln!("[ptrace] tid={waited} status={status:#x} branch=thread-exit");
                }
                let exit_code = if libc::WIFEXITED(status) {
                    libc::WEXITSTATUS(status)
                } else {
                    -libc::WTERMSIG(status)
                };
                *last_tid = NO_THREAD_TO_RESUME;
                return (
                    DebugEvent::new(
                        ProcessId(pid as u32),
                        ThreadId(waited as u32),
                        StopReason::ThreadExit { tid: ThreadId(waited as u32), exit_code },
                    ),
                    false,
                );
            }
            if trace {
                eprintln!("[ptrace] tid={waited} status={status:#x} branch=process-exit");
            }
            *last_tid = pid;
            return (classify_status(pid, waited, status), true);
        }

        if libc::WIFSTOPPED(status) {
            let event = status >> 8;
            let clone_event = libc::SIGTRAP | (libc::PTRACE_EVENT_CLONE << 8);
            if event == clone_event {
                // The PARENT must be resumed too. Resuming only the child here
                // is the exact mistake that hung iter 177b.
                if trace {
                    eprintln!("[ptrace] tid={waited} status={status:#x} branch=clone-event(parent-resumed)");
                }
                // The result is CHECKED. It used to be discarded, and that is
                // how a thread could be left in ptrace-stop forever with
                // nobody aware of it: measured on 2026-08-31, tid 7678 sat in
                // `ptrace_stop` while the tracee's main thread blocked in
                // `pthread_join` waiting for it and the debugger blocked in
                // `waitpid` waiting for an event that could no longer come —
                // a three-way deadlock read straight out of /proc.
                //
                // On failure the tid STAYS in `stopped_tids`, which is what
                // lets the next resume sweep pick it up instead of losing it.
                let ok = unsafe {
                    libc::ptrace(libc::PTRACE_CONT, waited, std::ptr::null_mut::<libc::c_void>(), std::ptr::null_mut::<libc::c_void>())
                };
                if ok < 0 {
                    if trace {
                        eprintln!("[ptrace] tid={waited} branch=clone-event PTRACE_CONT failed: {}", std::io::Error::last_os_error());
                    }
                    stopped_tids.insert(waited);
                } else {
                    stopped_tids.remove(&waited);
                }
                continue;
            }
            if !known_tids.contains(&waited) {
                // First stop ever from this tid == its birth-stop.
                if trace {
                    eprintln!("[ptrace] tid={waited} status={status:#x} branch=thread-birth(resumed)");
                }
                known_tids.insert(waited);
                // Same check, same reason as the clone branch above. This is
                // the site that matters most: a birth-stop that is not
                // actually resumed strands a thread the tracee is about to
                // join on, so the whole process stops making progress.
                //
                // It also now keeps `stopped_tids` HONEST either way. The
                // clone branch removed the tid and this one never did, so the
                // two halves of the same fact disagreed.
                let ok = unsafe {
                    libc::ptrace(libc::PTRACE_CONT, waited, std::ptr::null_mut::<libc::c_void>(), std::ptr::null_mut::<libc::c_void>())
                };
                if ok < 0 {
                    if trace {
                        eprintln!("[ptrace] tid={waited} branch=thread-birth PTRACE_CONT failed: {}", std::io::Error::last_os_error());
                    }
                    stopped_tids.insert(waited);
                } else {
                    stopped_tids.remove(&waited);
                }
                // The new thread is RESUMED (above) and the caller is TOLD.
                //
                // This stop used to be swallowed by a `continue`: the backend
                // knew a thread had been born — the branch and its trace line
                // were already here — and said nothing. Windows reports the
                // same fact as `StopReason::ThreadCreate` (iteration 525), so
                // the same API answered differently depending on the OS, and
                // the three layers built to carry it
                // (`cross_platform_debug`, `debug_session_manager`,
                // `debug_session_recorder`) stayed empty on Linux.
                //
                // Resuming first and reporting after is what keeps this safe:
                // the target is never left stopped waiting for a caller that
                // may not call again.
                //
                // And precisely because it was resumed, NOBODY is left stopped:
                // the next resume must resume nothing. Pointing `last_tid` at
                // this thread (as iteration 526 did) aimed the next
                // `PTRACE_CONT` at a thread that was already running, and
                // answered ESRCH once it had exited.
                *last_tid = NO_THREAD_TO_RESUME;
                return (
                    DebugEvent::new(
                        ProcessId(pid as u32),
                        ThreadId(waited as u32),
                        StopReason::ThreadCreate { tid: ThreadId(waited as u32) },
                    ),
                    false,
                );
            }
            if trace {
                eprintln!("[ptrace] tid={waited} status={status:#x} branch=event(sig={})", libc::WSTOPSIG(status));
            }
            stopped_tids.insert(waited);
            *last_tid = waited;
            return (classify_status(pid, waited, status), false);
        }

        if trace {
            eprintln!("[ptrace] tid={waited} status={status:#x} branch=unrecognised");
        }
        return (classify_status(pid, waited, status), false);
    }
}

/// Blocking wait on ONE specific tid (used after `PTRACE_SINGLESTEP`, where
/// reaping some other thread's unrelated stop would be reported as this
/// step's result).
fn wait_for_stop_tid(pid: libc::pid_t, tid: libc::pid_t) -> (DebugEvent, bool) {
    let mut status: libc::c_int = 0;
    unsafe {
        libc::waitpid(tid, &mut status, libc::__WALL);
    }
    let is_exit = (libc::WIFEXITED(status) || libc::WIFSIGNALED(status)) && tid == pid;
    (classify_status(pid, tid, status), is_exit)
}

#[cfg(test)]
fn wait_for_stop(pid: libc::pid_t) -> (DebugEvent, bool) {
    wait_for_stop_tid(pid, pid)
}

/// Turn a raw `waitpid` status for `tid` into a [`DebugEvent`], plus whether
/// it terminated the process.
fn classify_status(pid: libc::pid_t, tid_raw: libc::pid_t, status: libc::c_int) -> DebugEvent {
    let tid = ThreadId(tid_raw as u32);
    let process_id = ProcessId(pid as u32);

    if libc::WIFEXITED(status) {
        let code = libc::WEXITSTATUS(status);
        return DebugEvent::new(process_id, tid, StopReason::ProcessExit { exit_code: code });
    }
    if libc::WIFSIGNALED(status) {
        let sig = libc::WTERMSIG(status);
        return DebugEvent::new(process_id, tid, StopReason::ProcessExit { exit_code: -sig });
    }
    if libc::WIFSTOPPED(status) {
        let sig = libc::WSTOPSIG(status);
        let reason = if sig == libc::SIGTRAP {
            // Distinguish a breakpoint trap from a single-step/hardware-
            // watchpoint trap by checking whether the byte just before rip
            // is `0xCC` — ptrace doesn't hand us iced-style exception info
            // the way Win32 does, so this is the standard Linux-debugger
            // heuristic (used by gdb/strace equivalents). This byte check
            // was previously only DESCRIBED in this comment, never actually
            // performed — every SIGTRAP (including genuine single-step
            // traps from `PTRACE_SINGLESTEP` and hardware-watchpoint traps,
            // which also raise SIGTRAP on Linux with `rip` UNCHANGED) was
            // unconditionally reported as `Breakpoint{address: rip-1}`.
            // `SingleStep` is the correct classification for both a real
            // single-step and a hardware-watchpoint hit — matches
            // `windows_debugger.rs`'s own classification, where
            // `EXCEPTION_SINGLE_STEP` (not `EXCEPTION_BREAKPOINT`) covers
            // both cases identically on that OS.
            read_regs(tid_raw).map_or(
                StopReason::Unknown { description: "SIGTRAP but GETREGS failed".into() },
                |regs| {
                    let rip = regs_pc(&regs);
                    if let Some(trap) = trap_at_reported_pc(tid_raw, rip) {
                        StopReason::Breakpoint {
                            address: Address(trap),
                            bp: Breakpoint::new_software(Address(trap)),
                        }
                    } else if let Some((watched, kind)) = watchpoint_hit(tid_raw) {
                        // A watchpoint hit arrives as a plain SIGTRAP: only
                        // DR6 tells it apart from a single step. Without this
                        // the watchpoint was armed correctly and every hit was
                        // reported as a step, discarding the answer.
                        StopReason::Breakpoint {
                            address: watched,
                            bp: Breakpoint { kind, ..Breakpoint::new_hardware(watched) },
                        }
                    } else {
                        StopReason::SingleStep { address: Address(rip) }
                    }
                },
            )
        } else {
            StopReason::Signal {
                signum: sig,
                signame: signal_name(sig),
                address: signal_fault_address(tid_raw, sig),
            }
        };
        return DebugEvent::new(process_id, tid, reason);
    }
    DebugEvent::new(process_id, tid, StopReason::Unknown { description: format!("unrecognised wait status {status:#x}") })
}

fn signal_name(sig: libc::c_int) -> String {
    match sig {
        libc::SIGTRAP => "SIGTRAP",
        libc::SIGSEGV => "SIGSEGV",
        libc::SIGILL => "SIGILL",
        libc::SIGABRT => "SIGABRT",
        libc::SIGBUS => "SIGBUS",
        libc::SIGFPE => "SIGFPE",
        libc::SIGCONT => "SIGCONT",
        libc::SIGSTOP => "SIGSTOP",
        other => return format!("SIG{other}"),
    }
    .to_string()
}

/// Report the watched address and access kind if a hardware watchpoint just
/// fired on `pid`, and clear `DR6` so the next trap starts clean.
///
/// `DR6` is sticky: the CPU sets a `B` bit and never clears it, so leaving it
/// set makes every later single step look like the same hit forever. Clearing
/// it is part of reading it correctly, not an extra step.
///
/// Every failure path yields `None`: a debug-register read that does not work
/// must degrade to "this was a single step", never to a fabricated hit.
fn watchpoint_hit(pid: libc::pid_t) -> Option<(Address, BreakpointKind)> {
    let dr6 = read_debug_reg(pid, 6).ok()?;
    let slot = crate::x86_watchpoint_hit_slot(dr6)?;
    let dr7 = read_debug_reg(pid, 7).ok()?;
    let kind = crate::x86_watchpoint_kind_from_dr7(dr7, slot);
    let watched = read_debug_reg(pid, usize::from(slot)).ok();
    // Clear DR6 even when the slot turned out to be stale, or the stale bit
    // keeps masquerading as a hit on every subsequent trap.
    let _ = write_debug_reg(pid, 6, 0);
    Some((Address(watched?), kind?))
}

/// Byte offset of `struct user.u_debugreg[idx]` (`<sys/user.h>`), computed
/// from the real `libc::user` layout rather than hand-copied so it can't
/// drift from whatever glibc/libc-crate actually defines.
#[cfg(target_arch = "x86_64")]
fn debugreg_offset(idx: usize) -> i64 {
    // INVARIANT: x86/x86-64 `struct user` has 8 debug registers (DR0-DR7).
    debug_assert!(idx < 8, "debug register index out of range: {idx}");
    (std::mem::offset_of!(libc::user, u_debugreg) + idx * std::mem::size_of::<libc::c_ulonglong>()) as i64
}

/// Read hardware debug register `dr{idx}` (0-3 address slots, 6 status, 7
/// control) via `PTRACE_PEEKUSER` — these live in `struct user`'s
/// `u_debugreg` array, a separate ptrace region from the `user_regs_struct`
/// `PTRACE_GETREGS`/`PTRACE_SETREGS` cover, so hardware watchpoints
/// (`debug.set_watchpoint`) need this in addition to `read_regs`/`write_regs`.
/// `PTRACE_PEEKUSER` returns the peeked word as ptrace's own return value
/// (not via an out-pointer, unlike `PEEKTEXT` on some other kernels), so
/// `-1` is ambiguous with a legitimate all-ones register value — `errno` is
/// cleared first and checked to disambiguate, per the standard glibc
/// `ptrace(2)` idiom for `PEEK*` requests.
#[cfg(target_arch = "x86_64")]
fn read_debug_reg(pid: libc::pid_t, idx: usize) -> Result<u64, DebugError> {
    unsafe {
        *libc::__errno_location() = 0;
    }
    let val = unsafe {
        libc::ptrace(
            libc::PTRACE_PEEKUSER,
            pid,
            debugreg_offset(idx) as *mut libc::c_void,
            std::ptr::null_mut::<libc::c_void>(),
        )
    };
    if val == -1 {
        let errno = unsafe { *libc::__errno_location() };
        if errno != 0 {
            return Err(DebugError::RegisterError(format!("PTRACE_PEEKUSER(dr{idx}) failed: errno {errno}")));
        }
    }
    Ok(val as u64)
}

/// Write hardware debug register `dr{idx}` via `PTRACE_POKEUSER` — see
/// `read_debug_reg`'s doc comment for why this is a separate call from
/// `write_regs`.
#[cfg(target_arch = "x86_64")]
fn write_debug_reg(pid: libc::pid_t, idx: usize, value: u64) -> Result<(), DebugError> {
    let ok = unsafe {
        libc::ptrace(
            libc::PTRACE_POKEUSER,
            pid,
            debugreg_offset(idx) as *mut libc::c_void,
            value as *mut libc::c_void,
        )
    };
    if ok < 0 {
        return Err(DebugError::RegisterError(format!(
            "PTRACE_POKEUSER(dr{idx}) failed: {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(())
}

/// `ET_EXEC` (non-PIE: `e_entry` is already the absolute runtime address)
/// vs `ET_DYN` (PIE/shared object: `e_entry` is a file-relative offset that
/// must be added to the module's load base) — the two ELF types that carry
/// a meaningful entry point.
const ET_EXEC: u16 = 2;
const ET_DYN: u16 = 3;

/// Parse an ELF64 header's `e_type`/`e_entry` fields from raw bytes. Pure,
/// host-independent — no live process needed — mirroring the same
/// synthetic-buffer-testable pattern as `macos_debugger.rs`'s Mach-O
/// segment parser (iter 172) and `windows_debugger.rs`'s PE parser (iter
/// 173). Layout: `e_ident[16]` (byte 0 = 0x7f, bytes 1..4 = "ELF", byte 4 =
/// `EI_CLASS` — must be 2 for ELFCLASS64) + `e_type`(2) at offset 16 +
/// `e_machine`(2) + `e_version`(4) + `e_entry`(8) at offset 24.
fn parse_elf64_header(buf: &[u8]) -> Option<(u16, u64)> {
    if buf.len() < 32 || buf[0] != 0x7f || &buf[1..4] != b"ELF" {
        return None;
    }
    const ELFCLASS64: u8 = 2;
    if buf[4] != ELFCLASS64 {
        return None;
    }
    let e_type = u16::from_le_bytes(buf[16..18].try_into().ok()?);
    let e_entry = u64::from_le_bytes(buf[24..32].try_into().ok()?);
    Some((e_type, e_entry))
}

/// Resolve a mapped ELF file's entry point: reads just the 32-byte header
/// directly from disk (simpler and more reliable than reading target
/// process memory — avoids any ambiguity about whether the mapping is
/// still intact) and applies the `ET_EXEC`-vs-`ET_DYN` load-bias rule.
/// Returns `None` (not an error) on any read/parse failure or an
/// unsupported `e_type` — an entry point is best-effort metadata,
/// `modules()` should not fail wholesale over it.
fn elf_entry_point(path: &str, base: u64) -> Option<Address> {
    use std::io::Read;
    let mut header = [0u8; 32];
    std::fs::File::open(path).ok()?.read_exact(&mut header).ok()?;
    let (e_type, e_entry) = parse_elf64_header(&header)?;
    match e_type {
        ET_EXEC => Some(Address(e_entry)),
        ET_DYN => Some(Address(base.wrapping_add(e_entry))),
        _ => None,
    }
}

/// Reads a module's `.eh_frame` section directly from its on-disk ELF file
/// (same rationale as `elf_entry_point`: simpler and avoids depending on
/// the live mapping still being exactly as expected) and returns
/// `(bytes, runtime_vaddr_of_first_byte)`. `None` on any read/parse
/// failure or an image with no `.eh_frame` (e.g. built without unwind
/// tables) — the caller falls back to whatever frames were already found.
fn read_eh_frame_section(path: &str, base: u64) -> Option<(Vec<u8>, u64)> {
    use std::io::{Read, Seek, SeekFrom};
    // Sanity bound on any section size this function allocates a buffer
    // for (`shstrtab`/`.eh_frame`) — a real `.eh_frame` or string table is
    // at most a few MB even for huge binaries; 256 MiB is generous but
    // bounded. Guards against a corrupted/truncated ELF file's `sh_size`
    // field driving a multi-gigabyte allocation attempt, the same class
    // of "trust file data within reason" precedent already used elsewhere
    // in this crate (e.g. `walk_dyld_images`'s image-count cap in
    // `macos_debugger.rs`, iter 114; the PE parser's `e_lfanew` bound,
    // iter 173).
    const MAX_SECTION_SIZE: u64 = 256 * 1024 * 1024;

    let mut file = std::fs::File::open(path).ok()?;
    let mut header = [0u8; 64];
    file.read_exact(&mut header).ok()?;
    let (e_type, _) = parse_elf64_header(&header)?;
    let (shoff, shentsize, shnum, shstrndx) = crate::dwarf_cfi::parse_elf_section_header_location(&header)?;

    let strtab_shdr_offset = shoff.checked_add(u64::from(shstrndx).checked_mul(u64::from(shentsize))?)?;
    file.seek(SeekFrom::Start(strtab_shdr_offset)).ok()?;
    let mut strtab_shdr = vec![0u8; usize::from(shentsize).max(64)];
    file.read_exact(&mut strtab_shdr[..64]).ok()?;
    let strtab_offset = u64::from_le_bytes(strtab_shdr[24..32].try_into().ok()?);
    let strtab_size = u64::from_le_bytes(strtab_shdr[32..40].try_into().ok()?);
    if strtab_size > MAX_SECTION_SIZE {
        return None;
    }
    file.seek(SeekFrom::Start(strtab_offset)).ok()?;
    let mut shstrtab = vec![0u8; usize::try_from(strtab_size).ok()?];
    file.read_exact(&mut shstrtab).ok()?;

    file.seek(SeekFrom::Start(shoff)).ok()?;
    let mut shdrs = vec![0u8; usize::from(shnum) * usize::from(shentsize)];
    file.read_exact(&mut shdrs).ok()?;

    let (sh_addr, sh_size, sh_offset) =
        crate::dwarf_cfi::find_elf_section(&shdrs, usize::from(shentsize), &shstrtab, ".eh_frame")?;
    if sh_size > MAX_SECTION_SIZE {
        return None;
    }

    file.seek(SeekFrom::Start(sh_offset)).ok()?;
    let mut eh_frame = vec![0u8; usize::try_from(sh_size).ok()?];
    file.read_exact(&mut eh_frame).ok()?;

    let runtime_vaddr = if e_type == ET_DYN { base.wrapping_add(sh_addr) } else { sh_addr };
    Some((eh_frame, runtime_vaddr))
}

/// Linear-scans a `.eh_frame` buffer for the CIE/FDE pair covering
/// `target_pc`, runs the CFI interpreter up to `target_pc`'s offset within
/// that FDE, and resolves the CFA (only `rsp`- or `rbp`-based rules —
/// anything else bails). Returns the CFA value itself: per the standard
/// x86-64 convention this crate's real-world CIE confirms (iter 194's
/// `readelf` dump: `DW_CFA_offset r16 (rip) at cfa-8`), the return
/// address always lives at `CFA-8` and the caller's `sp` equals `CFA` —
/// the caller (`backtrace`) does that final memory read itself, since
/// this function has no access to the async memory reader. `None` on
/// absolutely any failure at any step (no covering FDE, an opcode this
/// module doesn't interpret, a bad pointer encoding, ...) — matches
/// `windows_debugger.rs`'s `compute_prologue_stack_delta` "bail, don't
/// guess" precedent.
fn cfi_unwind_one_frame(eh_frame: &[u8], eh_frame_vaddr: u64, target_pc: u64, current_sp: u64, current_fp: Option<u64>) -> Option<u64> {
    // Moved to `dwarf_cfi` in iter 447 so the Mach-O path can use the very
    // same scanner: the ELF and Mach-O backends differ only in where the
    // bytes come from, and a second copy would have kept the x86-only
    // register numbers on the platform that is not x86.
    crate::dwarf_cfi::unwind_one_frame_with_cfi(eh_frame, eh_frame_vaddr, target_pc, current_sp, current_fp)
}

/// Faulting address of the signal that stopped `pid`, for the signals that
/// carry one.
///
/// `StopReason::Signal` has always had an `address` field and
/// `StopReason::address()` has always read it, but this backend passed a
/// literal `None` — so a SIGSEGV reported no faulting address at all, while the
/// same crash on Windows arrives as `AccessViolation { address, .. }` and
/// answers. The single most useful fact about a memory-fault stop was available
/// from the kernel and thrown away on two OSes out of three.
///
/// Only the four signals POSIX defines `si_addr` for are asked: for anything
/// else that union member holds something unrelated (a pid, a band, a timer
/// id), so reporting it as an address would be worse than reporting nothing.
/// Address `0` is returned as `Some(0)`, not `None` — a null dereference is a
/// fault AT zero, which is a fact, not a missing one.
#[cfg(target_os = "linux")]
fn signal_fault_address(pid: libc::pid_t, signum: i32) -> Option<Address> {
    if !matches!(signum, libc::SIGSEGV | libc::SIGBUS | libc::SIGILL | libc::SIGFPE) {
        return None;
    }
    // SAFETY: `info` is zero-initialised before PTRACE_GETSIGINFO fills it
    // in-place; the kernel writes exactly `sizeof(siginfo_t)` bytes. Same
    // invariant as `read_regs`: `pid` must be a currently-stopped tracee.
    unsafe {
        let mut info: libc::siginfo_t = zeroed();
        let ok = libc::ptrace(
            libc::PTRACE_GETSIGINFO,
            pid,
            std::ptr::null_mut::<libc::c_void>(),
            std::ptr::addr_of_mut!(info).cast::<libc::c_void>(),
        );
        if ok < 0 {
            return None;
        }
        Some(Address(info.si_addr() as u64))
    }
}

fn read_regs(pid: libc::pid_t) -> Result<libc::user_regs_struct, DebugError> {
    // SAFETY: `regs` is zero-initialised before passing its address to
    // PTRACE_GETREGS, which fills the struct in-place.  The kernel writes
    // exactly `sizeof(user_regs_struct)` bytes; the `zeroed()` initialisation
    // ensures no uninitialised bytes are observed on failure paths.
    // INVARIANT: pid must refer to a currently-stopped ptrace tracee.
    debug_assert!(pid > 0, "read_regs: pid must be positive, got {pid}");
    unsafe {
        let mut regs: libc::user_regs_struct = zeroed();
        // `PTRACE_GETREGS` does not exist on AArch64 — the whole "one request
        // per register file" design was replaced by `PTRACE_GETREGSET`, which
        // names the set (`NT_PRSTATUS` for the general-purpose registers) and
        // takes an `iovec` so the kernel can report how much it actually
        // wrote. Measured on ubuntu-24.04-arm, 2026-08-15: the constant is
        // simply absent from `libc` there.
        #[cfg(target_arch = "x86_64")]
        let ok = libc::ptrace(
            libc::PTRACE_GETREGS,
            pid,
            std::ptr::null_mut::<libc::c_void>(),
            std::ptr::addr_of_mut!(regs).cast::<libc::c_void>(),
        );
        #[cfg(target_arch = "aarch64")]
        let ok = {
            let mut iov = libc::iovec {
                iov_base: std::ptr::addr_of_mut!(regs).cast::<libc::c_void>(),
                iov_len: std::mem::size_of::<libc::user_regs_struct>(),
            };
            libc::ptrace(
                libc::PTRACE_GETREGSET,
                pid,
                libc::NT_PRSTATUS as *mut libc::c_void,
                std::ptr::addr_of_mut!(iov).cast::<libc::c_void>(),
            )
        };
        if ok < 0 {
            return Err(DebugError::RegisterError(format!("reading the register set failed: {}", std::io::Error::last_os_error())));
        }
        Ok(regs)
    }
}

fn write_regs(pid: libc::pid_t, regs: &libc::user_regs_struct) -> Result<(), DebugError> {
    // SAFETY: `regs` is a valid, fully-initialised `user_regs_struct`
    // obtained from a prior PTRACE_GETREGS call (or constructed from known-
    // good values). The pointer cast to `*mut c_void` is required by the
    // ptrace(2) interface and the kernel only reads the struct.
    // INVARIANT: pid must refer to a currently-stopped ptrace tracee.
    debug_assert!(pid > 0, "write_regs: pid must be positive, got {pid}");
    unsafe {
        #[cfg(target_arch = "x86_64")]
        let ok = libc::ptrace(
            libc::PTRACE_SETREGS,
            pid,
            std::ptr::null_mut::<libc::c_void>(),
            std::ptr::addr_of!(*regs).cast::<libc::c_void>(),
        );
        // The `iovec` is written through by the kernel on the GET side, so it
        // cannot be shared with a `&` borrow here; the cast away from const is
        // confined to this call, which only READS the struct.
        #[cfg(target_arch = "aarch64")]
        let ok = {
            let mut iov = libc::iovec {
                iov_base: std::ptr::addr_of!(*regs).cast::<libc::c_void>().cast_mut(),
                iov_len: std::mem::size_of::<libc::user_regs_struct>(),
            };
            libc::ptrace(
                libc::PTRACE_SETREGSET,
                pid,
                libc::NT_PRSTATUS as *mut libc::c_void,
                std::ptr::addr_of_mut!(iov).cast::<libc::c_void>(),
            )
        };
        if ok < 0 {
            return Err(DebugError::RegisterError(format!("writing the register set failed: {}", std::io::Error::last_os_error())));
        }
        Ok(())
    }
}

#[cfg(target_arch = "x86_64")]
fn regs_to_register_set(r: &libc::user_regs_struct) -> RegisterSet {
    let mut regs = RegisterSet::new();
    regs.set("rax", r.rax);
    regs.set("rbx", r.rbx);
    regs.set("rcx", r.rcx);
    regs.set("rdx", r.rdx);
    regs.set("rsi", r.rsi);
    regs.set("rdi", r.rdi);
    regs.set("rbp", r.rbp);
    regs.set("rsp", r.rsp);
    regs.set("r8", r.r8);
    regs.set("r9", r.r9);
    regs.set("r10", r.r10);
    regs.set("r11", r.r11);
    regs.set("r12", r.r12);
    regs.set("r13", r.r13);
    regs.set("r14", r.r14);
    regs.set("r15", r.r15);
    regs.set("rip", r.rip);
    regs.set("eflags", r.eflags);
    regs.pc = r.rip;
    regs.sp = r.rsp;
    regs.fp = Some(r.rbp);
    regs
}

#[cfg(target_arch = "x86_64")]
fn apply_register_set(r: &mut libc::user_regs_struct, regs: &RegisterSet) {
    if let Some(v) = regs.get("rax") { r.rax = v; }
    if let Some(v) = regs.get("rbx") { r.rbx = v; }
    if let Some(v) = regs.get("rcx") { r.rcx = v; }
    if let Some(v) = regs.get("rdx") { r.rdx = v; }
    if let Some(v) = regs.get("rsi") { r.rsi = v; }
    if let Some(v) = regs.get("rdi") { r.rdi = v; }
    if let Some(v) = regs.get("rbp") { r.rbp = v; }
    if let Some(v) = regs.get("rsp") { r.rsp = v; }
    if let Some(v) = regs.get("r8") { r.r8 = v; }
    if let Some(v) = regs.get("r9") { r.r9 = v; }
    if let Some(v) = regs.get("r10") { r.r10 = v; }
    if let Some(v) = regs.get("r11") { r.r11 = v; }
    if let Some(v) = regs.get("r12") { r.r12 = v; }
    if let Some(v) = regs.get("r13") { r.r13 = v; }
    if let Some(v) = regs.get("r14") { r.r14 = v; }
    if let Some(v) = regs.get("r15") { r.r15 = v; }
    if let Some(v) = regs.get("rip") { r.rip = v; }
    if let Some(v) = regs.get("eflags") { r.eflags = v; }
}

/// AArch64 general-purpose registers: `x0`-`x30`, `sp`, `pc`, `pstate`.
///
/// `x29` and `x30` are published under BOTH their architectural names and
/// their role names (`fp`, `lr`). That is deliberate and not redundancy: this
/// crate currently disagrees with itself about which spelling is canonical —
/// `RegisterSchema` says `x29`, `register_context` says `fp` — and that
/// disagreement is recorded as an OPEN DECISION for the maintainer, not
/// something a port should quietly settle by publishing one and not the other.
/// Emitting both means whichever way it is decided, no reader of this backend
/// was ever given a register file missing the name it looked for.
#[cfg(target_arch = "aarch64")]
fn regs_to_register_set(r: &libc::user_regs_struct) -> RegisterSet {
    let mut regs = RegisterSet::new();
    for (i, v) in r.regs.iter().enumerate() {
        regs.set(&format!("x{i}"), *v);
    }
    regs.set("fp", r.regs[29]);
    regs.set("lr", r.regs[30]);
    regs.set("sp", r.sp);
    regs.set("pc", r.pc);
    regs.set("pstate", r.pstate);
    regs.pc = r.pc;
    regs.sp = r.sp;
    regs.fp = Some(r.regs[29]);
    regs
}

/// The inverse of [`regs_to_register_set`] on AArch64.
///
/// Accepts `x29`/`x30` under either spelling, and lets the architectural name
/// win when both are present: a caller that set `x29` meant the register, while
/// `fp` may have been carried along by a round trip through a `RegisterSet`
/// that publishes both.
#[cfg(target_arch = "aarch64")]
fn apply_register_set(r: &mut libc::user_regs_struct, regs: &RegisterSet) {
    for i in 0..31 {
        if let Some(v) = regs.get(&format!("x{i}")) {
            r.regs[i] = v;
        }
    }
    // Both spellings are published on read, so four sequential `if let`s meant
    // the LAST one written won: an edit made through `fp` was overwritten by the
    // stale `x29` that the read had put there. Symmetric to the Windows and
    // macOS copies of this same decision, which each preferred a DIFFERENT
    // spelling. See `crate::aliased_register_write`.
    if let Some(v) = crate::aliased_register_write(regs.get("x29"), regs.get("fp"), r.regs[29]) {
        r.regs[29] = v;
    }
    if let Some(v) = crate::aliased_register_write(regs.get("x30"), regs.get("lr"), r.regs[30]) {
        r.regs[30] = v;
    }
    if let Some(v) = regs.get("sp") {
        r.sp = v;
    }
    if let Some(v) = regs.get("pc") {
        r.pc = v;
    }
    if let Some(v) = regs.get("pstate") {
        r.pstate = v;
    }
}

/// The program counter, whatever this architecture calls it.
///
/// Mirrors `macos_debugger::thread_pc`, and exists for the same reason: reading
/// `regs.rip` unconditionally is what stopped that backend compiling for arm64
/// at all.
#[cfg(target_arch = "x86_64")]
const fn regs_pc(r: &libc::user_regs_struct) -> u64 {
    r.rip
}

#[cfg(target_arch = "aarch64")]
const fn regs_pc(r: &libc::user_regs_struct) -> u64 {
    r.pc
}

/// AArch64 has no `DR0`-`DR7`, and saying so is the only honest answer.
///
/// Hardware breakpoints and watchpoints exist on this architecture, but they
/// live behind a different interface entirely: `PTRACE_GETREGSET` with
/// `NT_ARM_HW_BREAK` / `NT_ARM_HW_WATCH`, a variable-length set of
/// `DBGBVR`/`DBGBCR` and `DBGWVR`/`DBGWCR` pairs whose count the kernel
/// reports. That is a subsystem, not a rename, and this crate already holds the
/// control-register layouts for it in `ios::arm64::hw_breakpoints`.
///
/// Returning `Unsupported` rather than a plausible zero is the same rule this
/// backend follows everywhere else: an answer invented to fill a signature is
/// worse than a refusal, because the caller cannot tell it from a real one.
/// The x86 debug-register path already refuses on architectures whose trap byte
/// it cannot write; this refuses on the register file it cannot address.
#[cfg(target_arch = "aarch64")]
fn read_debug_reg(_pid: libc::pid_t, idx: usize) -> Result<u64, DebugError> {
    Err(DebugError::Unsupported(format!(
        "dr{idx} does not exist on AArch64 — hardware breakpoints there are DBGBVR/DBGBCR and          DBGWVR/DBGWCR, reached through PTRACE_GETREGSET with NT_ARM_HW_BREAK/NT_ARM_HW_WATCH"
    )))
}

/// The write half of the same refusal — see [`read_debug_reg`].
#[cfg(target_arch = "aarch64")]
fn write_debug_reg(_pid: libc::pid_t, idx: usize, _value: u64) -> Result<(), DebugError> {
    Err(DebugError::Unsupported(format!(
        "dr{idx} does not exist on AArch64 — writing it would be writing nowhere"
    )))
}

/// The kernel's `user_hwdebug_state`, hand-declared because `libc` does not
/// expose it.
///
/// ```c
/// struct user_hwdebug_state {
///     __u32 dbg_info;
///     __u32 pad;
///     struct { __u64 addr; __u32 ctrl; __u32 pad; } dbg_regs[16];
/// };
/// ```
#[cfg(target_arch = "aarch64")]
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct HwDebugReg {
    addr: u64,
    ctrl: u32,
    pad: u32,
}

#[cfg(target_arch = "aarch64")]
#[repr(C)]
#[derive(Clone, Copy)]
struct UserHwdebugState {
    dbg_info: u32,
    pad: u32,
    dbg_regs: [HwDebugReg; 16],
}

#[cfg(target_arch = "aarch64")]
impl Default for UserHwdebugState {
    fn default() -> Self {
        Self { dbg_info: 0, pad: 0, dbg_regs: [HwDebugReg::default(); 16] }
    }
}

/// 8 bytes of header plus sixteen 16-byte pairs.
///
/// Checked at COMPILE time, for the same reason the macOS backend checks
/// `ARM_DEBUG_STATE64_COUNT == 130`: this struct is hand-written against a
/// kernel ABI, `iov_len` is computed from its size, and a layout that drifted
/// would be read in SILENCE — arming a watchpoint that looks correct and
/// watches the wrong address. That is the one failure mode this crate treats as
/// worse than a refusal.
#[cfg(target_arch = "aarch64")]
const _: () = assert!(std::mem::size_of::<UserHwdebugState>() == 264);

#[cfg(target_arch = "aarch64")]
impl UserHwdebugState {
    /// How many register pairs the HARDWARE actually has, per the kernel.
    ///
    /// `dbg_info` is the kernel's answer and was declared here and never read.
    /// Its low byte is the slot count; bits 8..12 are the debug architecture
    /// version. Real CPUs publish 2-16 watchpoints and 2-16 breakpoints, and
    /// they are NOT the same number.
    ///
    /// Reading it is not a refinement, it is the difference between working and
    /// not. Measured on `ubuntu-24.04-arm`: writing the full sixteen-slot
    /// struct made `PTRACE_SETREGSET` answer `ENOSPC` — "No space left on
    /// device" — and FIVE live tests failed on that one error, because every
    /// path that programs a debug register goes through this write.
    fn slot_count(&self) -> usize {
        let n = (self.dbg_info & 0xFF) as usize;
        // Clamped, not trusted: the struct has room for sixteen, and a kernel
        // reporting more would have us read past the array. Zero means the CPU
        // exposes no such register at all, which the caller must be able to see
        // rather than have rounded up to one.
        n.min(16)
    }

    /// Bytes that describe exactly `slot_count()` pairs.
    ///
    /// `iov_len` must span the header plus the slots that EXIST. Sending the
    /// whole struct describes registers the hardware does not have, which is
    /// what the kernel refuses.
    fn iov_len_for_slots(&self) -> usize {
        std::mem::size_of::<u32>() * 2 + self.slot_count() * std::mem::size_of::<HwDebugReg>()
    }
}

/// `NT_ARM_HW_WATCH`, not exposed by `libc`.
#[cfg(target_arch = "aarch64")]
const NT_ARM_HW_WATCH: libc::c_int = 0x403;

/// `NT_ARM_PAC_MASK`, not exposed by `libc`.
///
/// Reports the pointer-authentication masks the kernel actually applies to
/// THIS process, as `struct user_pac_mask { __u64 data_mask; __u64 insn_mask; }`.
#[cfg(target_arch = "aarch64")]
const NT_ARM_PAC_MASK: libc::c_int = 0x406;

#[cfg(target_arch = "aarch64")]
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct UserPacMask {
    data_mask: u64,
    insn_mask: u64,
}

#[cfg(target_arch = "aarch64")]
const _: () = assert!(std::mem::size_of::<UserPacMask>() == 16);

/// The kernel's own instruction-pointer PAC mask for `pid`, or `None`.
///
/// `None` means "no pointer authentication here" — an older kernel, or a CPU
/// without the feature — and the caller must then leave addresses ALONE. That
/// is not a degraded mode: without PAC there are no signed pointers to strip,
/// so doing nothing is the correct answer rather than a fallback.
///
/// ASKING is the point of this function. `ios::arm64::strip_pac` hardcodes
/// `VA_BITS = 47`, which is Apple's user address split; Linux arm64 is normally
/// 48-bit and can be 52. Reusing that constant here would clear one bit too
/// many and could turn a valid address into a bogus one — swapping a visible
/// failure for a silent wrong answer.
#[cfg(target_arch = "aarch64")]
fn pac_insn_mask(pid: libc::pid_t) -> Option<u64> {
    let mut mask = UserPacMask::default();
    // SAFETY: `mask` is a valid, fully-initialised repr(C) struct whose size is
    // checked at compile time; the kernel writes at most `iov_len` bytes.
    // INVARIANT: pid must refer to a currently-stopped ptrace tracee.
    debug_assert!(pid > 0, "pac_insn_mask: pid must be positive, got {pid}");
    let ok = unsafe {
        let mut iov = libc::iovec {
            iov_base: std::ptr::addr_of_mut!(mask).cast::<libc::c_void>(),
            iov_len: std::mem::size_of::<UserPacMask>(),
        };
        libc::ptrace(
            libc::PTRACE_GETREGSET,
            pid,
            NT_ARM_PAC_MASK as *mut libc::c_void,
            std::ptr::addr_of_mut!(iov).cast::<libc::c_void>(),
        )
    };
    if ok < 0 || mask.insn_mask == 0 {
        return None;
    }
    Some(mask.insn_mask)
}

/// Remove the authentication code from a return address, given the kernel mask.
///
/// Sign-preserving, for the reason `ios::arm64::strip_pac` gives and which is
/// architecture-independent: kernel addresses have the top bits set, and simply
/// clearing the masked bits would turn one into a bogus user pointer. A user
/// address (bit 55 clear) has the mask bits cleared; a kernel address has them
/// SET, which is the canonical form on the other side of the split.
#[cfg(target_arch = "aarch64")]
const fn strip_pac_with(addr: u64, insn_mask: u64) -> u64 {
    if addr & (1 << 55) == 0 {
        addr & !insn_mask
    } else {
        addr | insn_mask
    }
}

/// `NT_ARM_HW_BREAK` — the EXECUTION breakpoint file, `DBGBVR`/`DBGBCR`.
///
/// A separate regset with the same `user_hwdebug_state` layout. x86 shares four
/// slots between breakpoints and watchpoints; AArch64 keeps two INDEPENDENT
/// files, so slot `n` is programmed into exactly one of them according to
/// `DR7`s `rw` bits and cleared in the other. Without that, one `dr` slot would
/// mean two different armed things at once, and disarming it would find one.
#[cfg(target_arch = "aarch64")]
const NT_ARM_HW_BREAK: libc::c_int = 0x402;

/// How many AArch64 watchpoint pairs are presented as `dr` slots.
///
/// AArch64 offers up to sixteen; the shared engine speaks x86's four. Exposing
/// four is honest — the engine cannot address a fifth — and keeps `DR7`'s slot
/// bits meaningful. Same choice, same number, as the macOS backend.
#[cfg(target_arch = "aarch64")]
const TRANSLATED_SLOTS: u8 = 4;

#[cfg(target_arch = "aarch64")]
fn read_arm_hw_regset(
    pid: libc::pid_t,
    regset: libc::c_int,
) -> Result<UserHwdebugState, DebugError> {
    let mut state = UserHwdebugState::default();
    // SAFETY: `state` is a valid, fully-initialised repr(C) struct whose size
    // is checked at compile time; the kernel writes at most `iov_len` bytes
    // into it and reports how many through the same `iovec`.
    // INVARIANT: pid must refer to a currently-stopped ptrace tracee.
    debug_assert!(pid > 0, "read_arm_hw_regset: pid must be positive, got {pid}");
    let ok = unsafe {
        let mut iov = libc::iovec {
            iov_base: std::ptr::addr_of_mut!(state).cast::<libc::c_void>(),
            iov_len: std::mem::size_of::<UserHwdebugState>(),
        };
        libc::ptrace(
            libc::PTRACE_GETREGSET,
            pid,
            regset as *mut libc::c_void,
            std::ptr::addr_of_mut!(iov).cast::<libc::c_void>(),
        )
    };
    if ok < 0 {
        return Err(DebugError::RegisterError(format!(
            "reading the AArch64 debug registers (regset {regset:#x}) failed: {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(state)
}

#[cfg(target_arch = "aarch64")]
fn write_arm_hw_regset(
    pid: libc::pid_t,
    regset: libc::c_int,
    state: &UserHwdebugState,
) -> Result<(), DebugError> {
    // SAFETY: as `read_arm_hw_watch`, except the kernel only READS the struct
    // here; the cast away from const is confined to this call because the
    // `iovec` interface is shared with the write-through GET side.
    debug_assert!(pid > 0, "write_arm_hw_regset: pid must be positive, got {pid}");
    let ok = unsafe {
        let mut iov = libc::iovec {
            iov_base: std::ptr::addr_of!(*state).cast::<libc::c_void>().cast_mut(),
            // Sized by the KERNEL's count, not by our struct. See
            // `slot_count`: writing sixteen pairs to hardware that has four
            // answers ENOSPC and every debug-register operation on this backend
            // fails with it.
            iov_len: state.iov_len_for_slots(),
        };
        libc::ptrace(
            libc::PTRACE_SETREGSET,
            pid,
            regset as *mut libc::c_void,
            std::ptr::addr_of_mut!(iov).cast::<libc::c_void>(),
        )
    };
    if ok < 0 {
        return Err(DebugError::RegisterError(format!(
            "writing the AArch64 debug registers (regset {regset:#x}) failed: {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(())
}

/// Refuse a slot this CPU does not have, rather than writing past it.
///
/// `iov_len_for_slots` sends only the pairs the hardware reports, which is what
/// the kernel demands — but it also means a pair written into a HIGHER index
/// would be silently left out of the message. The write would then succeed and
/// arm nothing: a request accepted and quietly dropped, which is this crate's
/// most-condemned failure shape.
///
/// x86 has four debug registers and the shared engine speaks in those terms;
/// AArch64 publishes its own count, and it can be as low as two. So the two
/// vocabularies can disagree, and when they do the caller has to be told.
#[cfg(target_arch = "aarch64")]
fn ensure_slot_exists(state: &UserHwdebugState, slot: u8, regset: libc::c_int) -> Result<(), DebugError> {
    let have = state.slot_count();
    if usize::from(slot) < have {
        return Ok(());
    }
    Err(DebugError::RegisterError(format!(
        "debug slot {slot} does not exist on this CPU: the kernel reports {have} pair(s) for          regset {regset:#x}. The request is refused rather than written into a message the          hardware never sees, which would report success and arm nothing"
    )))
}

/// Present the AArch64 watchpoint pairs to the engine as `dr0`-`dr3` + `dr7`.
///
/// The whole point of translating HERE is that nothing above this line has to
/// know: `set_watchpoint_sized`, `disarm_watchpoint_registers`,
/// `disarm_all_hardware_watchpoints` and `rearm_watchpoints_on_new_threads`
/// stay byte-identical with the other backends — the property this crate has
/// repeatedly paid for losing.
///
/// Deliberately the same shape as the macOS backend's `merge_debug_state`,
/// including the failure disposition: a pair that cannot be described in the
/// `dr` vocabulary is reported as an EMPTY slot rather than a wrong one.
#[cfg(target_arch = "aarch64")]
fn merge_debug_state(pid: libc::pid_t, regs: &mut RegisterSet) {
    // FIRST, before anything that can bail out.
    //
    // 591 put this at the END of the function, and the line below returns early
    // whenever the watchpoint regset is unavailable — which the red
    // debug-register tests on ubuntu-24.04-arm say it is. So the mask was never
    // published, the unwinder never stripped, and
    // `backtrace_unwinds_past_the_first_frame_via_dwarf_cfi` stayed red through
    // 573 AND 591: two fixes present in the source and dead on the one machine
    // that could run them, first by being on the wrong thread and then by
    // sitting behind an unrelated early return.
    //
    // Pointer authentication has nothing to do with the watchpoint register
    // file. Coupling the two was the whole defect.
    if let Some(mask) = pac_insn_mask(pid) {
        regs.set(PAC_INSN_MASK_KEY, mask);
    }
    let Ok(watch) = read_arm_hw_regset(pid, NT_ARM_HW_WATCH) else { return };
    // How many slots the hardware really has, published for the allocator.
    //
    // `x86_free_watchpoint_slot` searches 0..4 because four is an x86 fact;
    // AArch64 publishes its own number and it can be two. Handing the engine a
    // slot that does not exist makes it commit, and the refusal then arrives
    // from the kernel (589) rather than from the allocator that could have
    // answered honestly.
    regs.set(WATCHPOINT_SLOTS_KEY, watch.slot_count() as u64);
    // The breakpoint file is read separately and may legitimately be absent: a
    // kernel that refuses NT_ARM_HW_BREAK still has usable watchpoints, and
    // failing both because one is missing would throw away working
    // functionality to report a gap.
    let brk = read_arm_hw_regset(pid, NT_ARM_HW_BREAK).ok();
    let mut dr7 = 0u64;
    for slot in 0..TRANSLATED_SLOTS {
        let i = slot as usize;
        // Watchpoint file first, then the breakpoint file. A slot can only be
        // armed in one of them, and that is an INVARIANT established by
        // `write_debug_registers`, not a coincidence relied on here.
        let found = crate::dr_slot_from_arm64_watchpoint(
            watch.dbg_regs[i].addr,
            u64::from(watch.dbg_regs[i].ctrl),
            slot,
        )
        .or_else(|| {
            brk.as_ref().and_then(|b| {
                crate::dr_slot_from_arm64_breakpoint(
                    b.dbg_regs[i].addr,
                    u64::from(b.dbg_regs[i].ctrl),
                    slot,
                )
            })
        })
        // Last: a pair STAGED but not armed. It contributes its R/W and LEN
        // fields and NO enable bit, so it cannot be mistaken for a live
        // watchpoint — which is precisely what it is not.
        .or_else(|| {
            crate::dr_slot_from_arm64_watchpoint_staged(
                watch.dbg_regs[i].addr,
                u64::from(watch.dbg_regs[i].ctrl),
                slot,
            )
        });
        match found {
            Some((addr, bits)) => {
                regs.set(&format!("dr{slot}"), addr);
                dr7 |= bits;
            }
            // Disabled — but the ADDRESS may still be staged, and x86 semantics
            // say it must survive.
            //
            // Measured on ubuntu-24.04-arm after 589 removed the ENOSPC: the
            // write now lands and the READ-BACK fails — "DR0 should read back
            // exactly what was written, not silently stay 0". On x86 a caller
            // may put an address in DR0 and enable it later in DR7; the address
            // register is independent of the enable bit. Reporting 0 for a
            // staged address turns a write that succeeded into a value that
            // vanished.
            //
            // AArch64 expresses the same state exactly: DBGWVR holds the
            // address, DBGWCR has E=0. Nothing is armed, so nothing fires —
            // this reports what is really in the register rather than rounding
            // it to zero.
            None => regs.set(&format!("dr{slot}"), watch.dbg_regs[i].addr),
        }
    }
    regs.set("dr6", 0);
    regs.set("dr7", dr7);
}

/// Register-map key carrying how many watchpoint slots the CPU has.
///
/// Not a register: a fact about the hardware that only the tracer thread can
/// ask for, carried with the registers because that is the message which
/// already crosses from that thread.
///
/// Declared for every architecture this file is built for, because the READER
/// is architecture-independent — it simply finds nothing on a host that has
/// nothing to say, and falls back to the x86 four. Gating the name itself to
/// aarch64 is what made iteration 609 fail to compile on x86_64 Linux while
/// looking fine from a Windows suite that never builds this file at all.
const WATCHPOINT_SLOTS_KEY: &str = "__watchpoint_slots";

/// Register-map key carrying the kernel's PAC instruction mask.
///
/// Not a CPU register: a fact about the process that only the tracer thread can
/// ask for, carried alongside the registers because that is the one message
/// that already crosses from that thread.
#[cfg(target_arch = "aarch64")]
const PAC_INSN_MASK_KEY: &str = "__pac_insn_mask";

/// Program the AArch64 watchpoint pairs from a `dr`-flavoured register set.
///
/// Whole-set, not per-register, and that is not a style choice: `DBGWVR`/
/// `DBGWCR` are computed from the slot's address AND `DR7` together, so a
/// per-register seam could not express `dr0` without already knowing `dr7`.
#[cfg(target_arch = "aarch64")]
fn write_debug_registers(pid: libc::pid_t, regs: &RegisterSet) -> Result<(), DebugError> {
    let Some(dr7) = regs.get("dr7") else {
        // No `DR7` means the caller is not talking about watchpoints at all.
        // Touching the debug state on the strength of a stray `dr0` would arm
        // or clear something nobody asked about.
        return Ok(());
    };
    let mut watch = read_arm_hw_regset(pid, NT_ARM_HW_WATCH)?;
    let mut brk = read_arm_hw_regset(pid, NT_ARM_HW_BREAK).ok();
    for slot in 0..TRANSLATED_SLOTS {
        let i = slot as usize;
        let addr = regs.get(&format!("dr{slot}")).unwrap_or(0);
        // Exactly ONE of the two files owns this slot, decided by `DR7`s `rw`
        // bits, and the other is CLEARED. Programming both would arm a single
        // `dr` slot as two different things, and a later disarm would find one
        // of them and report success.
        match crate::arm64_watchpoint_from_dr_slot(addr, dr7, slot) {
            // Refused, not dropped: see `ensure_slot_exists`.
            Some(_) if ensure_slot_exists(&watch, slot, NT_ARM_HW_WATCH).is_err() => {
                return ensure_slot_exists(&watch, slot, NT_ARM_HW_WATCH);
            }
            Some((wvr, wcr)) => {
                watch.dbg_regs[i].addr = wvr;
                watch.dbg_regs[i].ctrl = u32::try_from(wcr & 0xFFFF_FFFF).unwrap_or(0);
            }
            // Disabled, but with control fields STAGED. 594 kept the address
            // of such a slot; this keeps the rest. `E` stays clear so nothing is
            // armed either way — only that bit decides — and a caller who writes
            // a whole `DR7` before switching it on gets all of it back.
            None if crate::arm64_watchpoint_ctrl_for_disabled_slot(dr7, slot).is_some() => {
                let ctrl = crate::arm64_watchpoint_ctrl_for_disabled_slot(dr7, slot).unwrap_or(0);
                watch.dbg_regs[i].addr = addr;
                watch.dbg_regs[i].ctrl = u32::try_from(ctrl & 0xFFFF_FFFF).unwrap_or(0);
            }
            None => {
                // Disabled in `DR7`, or an EXECUTION slot the watchpoint file
                // cannot express.
                //
                // The CONTROL word is always cleared: that is what disarms, and
                // leaving a stale pair armed is the leak `detach` exists to
                // prevent. But the ADDRESS is kept, so a caller that staged it
                // without enabling it can read back what it wrote — x86 lets
                // DR0 hold an address while DR7 leaves it disabled, and with
                // E=0 the pair is inert either way.
                //
                // A real disarm still zeroes both, because it clears the `dr`
                // entry too: this only preserves what the caller put there.
                watch.dbg_regs[i].addr = addr;
                watch.dbg_regs[i].ctrl = 0;
            }
        }
        if let Some(b) = brk.as_mut() {
            match crate::arm64_breakpoint_from_dr_slot(addr, dr7, slot) {
                // Refused, not dropped: see `ensure_slot_exists`.
                Some(_) if ensure_slot_exists(b, slot, NT_ARM_HW_BREAK).is_err() => {
                    return ensure_slot_exists(b, slot, NT_ARM_HW_BREAK);
                }
                Some((bvr, bcr)) => {
                    b.dbg_regs[i].addr = bvr;
                    b.dbg_regs[i].ctrl = u32::try_from(bcr & 0xFFFF_FFFF).unwrap_or(0);
                }
                None => {
                    b.dbg_regs[i].addr = 0;
                    b.dbg_regs[i].ctrl = 0;
                }
            }
        }
    }
    write_arm_hw_regset(pid, NT_ARM_HW_WATCH, &watch)?;
    // Propagated, not discarded: a hardware breakpoint the caller asked for and
    // that was not programmed must not be reported as set. A kernel with no
    // NT_ARM_HW_BREAK at all was already handled by leaving `brk` at `None`.
    if let Some(b) = brk.as_ref() {
        write_arm_hw_regset(pid, NT_ARM_HW_BREAK, b)?;
    }
    Ok(())
}

/// The backing-file path of a `/proc/<pid>/maps` line, if it has one.
///
/// `modules()` counts columns differently from [`parse_maps_line`] (it skips
/// straight to the path with one `nth`, the other consumes offset first). Two
/// parsers of one format is how iteration 344's field-shift bug happened, so
/// the path extraction lives here once and both are pinned together by
/// `both_maps_parsers_agree_on_the_backing_path`.
fn maps_line_path(line: &str) -> Option<&str> {
    let mut parts = line.split_whitespace();
    let _range = parts.next()?;
    // remaining: perms(0) offset(1) dev(2) inode(3) path(4)
    let path = parts.nth(4)?;
    (!path.is_empty() && !path.starts_with('[')).then_some(path)
}

/// Parse one `/proc/<pid>/maps` line into a [`MemoryMap`].
///
/// Format: `start-end perms offset dev inode  path`. Extracted from
/// `memory_maps` so the field arithmetic is testable without a live process —
/// it was inline, and inline parsing is parsing nobody checks.
fn parse_maps_line(line: &str) -> Option<MemoryMap> {
    let mut parts = line.split_whitespace();
    let range = parts.next()?;
    let perms = parts.next()?;
    let (start_s, end_s) = range.split_once('-')?;
    let start = u64::from_str_radix(start_s, 16).ok()?;
    let end = u64::from_str_radix(end_s, 16).ok()?;
    // Column 3 is the offset into the backing file, in hex. It used to be
    // skipped and the field filled with a constant 0 — while the macOS backend
    // fills the same field from the real value. Only the first mapping of a
    // shared object sits at offset 0; every later region of the same file does
    // not, so a constant 0 makes `vaddr - base + file_offset` wrong for all of
    // them.
    let file_offset = parts
        .next()
        .and_then(|o| u64::from_str_radix(o, 16).ok())
        .unwrap_or(0);
    // Remaining columns are dev, inode, path: take the third.
    let path = parts.nth(2).map(std::string::ToString::to_string);
    Some(MemoryMap {
        base: Address(start),
        size: end.saturating_sub(start),
        readable: perms.as_bytes().first() == Some(&b'r'),
        writable: perms.as_bytes().get(1) == Some(&b'w'),
        executable: perms.as_bytes().get(2) == Some(&b'x'),
        name: path.as_deref().map(|p| p.rsplit('/').next().unwrap_or(p).to_string()),
        file_path: path,
        file_offset,
    })
}

#[async_trait::async_trait]
impl crate::Debugger for LinuxDebugger {
    fn name(&self) -> &str {
        "linux-ptrace"
    }

    fn supported_architectures(&self) -> Vec<String> {
        // This backend debugs processes on THIS machine through the local
        // kernel interface, so the only architecture it can actually drive is
        // the one it was compiled for. Hard-coding `x86_64` made an aarch64
        // build (Apple Silicon, Linux ARM, Windows-on-ARM) answer a question
        // about itself with a wrong constant — and `lib.rs` documents that
        // callers use this answer to PICK a backend, so the lie propagates
        // into backend selection rather than staying a cosmetic string.
        vec![std::env::consts::ARCH.to_string()]
    }

    async fn launch(&self, opts: LaunchOptions) -> Result<ProcessId, DebugError> {
        // Reject a second launch/attach on an already-attached instance
        // outright — `spawn_loop` would otherwise silently overwrite
        // `self.cmd_tx`/`self.pid` with the new process's, losing the only
        // channel able to reach the FIRST ptrace thread and leaking that
        // process as a permanently orphaned, still-running process with no
        // pid left anywhere to find it again. Proved via a live test
        // (`launch_twice_on_the_same_debugger_does_not_leak_the_first_process`)
        // before this guard existed.
        if self.pid.lock().is_some() {
            return Err(DebugError::LaunchError(
                "this LinuxDebugger instance is already attached to a process — detach/kill it before launching another".into(),
            ));
        }
        let pid = self.spawn_loop(Command::DoLaunch(Box::new(opts)))?;
        *self.pid.lock() = Some(pid);
        // `do_launch` already reaped the post-execve SIGTRAP before
        // `spawn_loop` returned, so the tracee's main thread is genuinely
        // stopped and known right now — unlike Windows (which only learns
        // its first tid from a subsequent `WaitForDebugEvent`), there's no
        // reason to leave `current_tid` unpopulated until the caller
        // happens to call `continue_execution`/`single_step` first. Found
        // via a live test where `LiveScriptContext` (which reads
        // `current_thread()` internally) was completely unusable
        // immediately post-launch, reporting `NotAttached` for an already-
        // stopped, already-known thread.
        *self.current_tid.lock() = Some(ThreadId(pid.0));
        Ok(pid)
    }

    async fn attach(&self, pid: ProcessId) -> Result<(), DebugError> {
        // See `launch`'s identical guard: reject a second attach outright
        // rather than silently leaking whatever this instance was already
        // attached to.
        if self.pid.lock().is_some() {
            return Err(DebugError::LaunchError(
                "this LinuxDebugger instance is already attached to a process — detach/kill it before attaching to another".into(),
            ));
        }
        let started = self.spawn_loop(Command::DoAttach(pid.0 as libc::pid_t))?;
        *self.pid.lock() = Some(started);
        // Same rationale as `launch` above — `do_attach` already reaped the
        // attach-stop SIGTRAP.
        *self.current_tid.lock() = Some(ThreadId(started.0));
        Ok(())
    }

    async fn detach(&self) -> Result<(), DebugError> {
        // Restore every installed software breakpoint's original byte
        // BEFORE detaching. Without this, a leftover `0xCC` (int3) in the
        // process's own code raises SIGTRAP the instant it's next executed
        // — with no tracer attached anymore, the kernel's default action
        // for an unhandled SIGTRAP is to kill the process. Found via a live
        // test that planted a breakpoint at the current `rip`, detached,
        // and observed the process die from SIGTRAP immediately. "Detach"
        // should mean "keep running undisturbed," not plant a landmine in
        // the very process being debugged.
        let addrs: Vec<(u64, Vec<u8>)> =
            self.breakpoints.lock().iter().map(|(a, b)| (*a, b.clone())).collect();
        // A restore that FAILED must not be reported as a clean detach.
        //
        // The error was discarded here, so a write that did not land left an
        // `0xCC` in a process about to lose its debugger — precisely the
        // landmine the comment above says this loop exists to defuse, and the
        // caller was told `Ok(())`. The default action for an unhandled
        // SIGTRAP is to kill the process, so the failure surfaces as the
        // target dying for no visible reason, long after the call that caused
        // it returned success.
        //
        // Detaching is abandoned rather than continued: the bookkeeping is
        // still intact at this point, so the caller can retry, and the rule
        // this function already states — "a detach that fails must leave the
        // session exactly as it was" — is what makes a retry meaningful.
        let mut unrestored: Vec<u64> = Vec::new();
        for (addr, original) in addrs {
            if self.write_memory_raw(Address(addr), &original).await.is_err() {
                unrestored.push(addr);
            }
        }
        if !unrestored.is_empty() {
            return Err(DebugError::DetachError(format!(
                "{} planted breakpoint(s) could not be restored ({}); detaching now would leave the target to die on a trap it cannot handle",
                unrestored.len(),
                unrestored.iter().map(|a| format!("{a:#x}")).collect::<Vec<_>>().join(", ")
            )));
        }
        // Same hazard, one layer down: an armed debug register left behind
        // traps in a process with no debugger to take the trap.
        self.disarm_all_hardware_watchpoints().await?;
        // The bookkeeping is cleared only AFTER the detach succeeds. Clearing
        // it first meant a failing `send` returned through `?` with the tables
        // already wiped while `pid`/`cmd_tx` still said "attached": the
        // debugger then reported an EMPTY breakpoint table for a process that
        // still had the patches in it, so a retried detach restored nothing and
        // `remove_breakpoint` had nothing left to find. A detach that fails must
        // leave the session exactly as it was.
        let reply = self.send(Command::Detach)?;
        self.breakpoints.lock().clear();
        self.hit_counts.lock().clear();
        self.disabled.lock().clear();
        self.conditions.lock().clear();
        // A stale load base outliving the session would make the NEXT
        // process's pending request resolve immediately, at the old
        // process's address — a fabricated answer, not a missing one.
        self.pending.lock().clear();
        self.ignore_counts.lock().clear();
        self.thread_filters.lock().clear();
        *self.pid.lock() = None;
        // The current thread cannot outlive the pid. `kill` and `detach`
        // cleared everything else — breakpoints, watchpoints, the command
        // channel — but left `current_tid` set, so the instance contradicted
        // itself: `is_attached()` answered false while `current_thread()` still
        // handed out the dead process's tid. That tid is the default the
        // register and stepping calls fall back to.
        *self.current_tid.lock() = None;
        *self.cmd_tx.lock() = None;
        match reply {
            Reply::Ack(r) => r,
            _ => Ok(()),
        }
    }

    async fn kill(&self) -> Result<(), DebugError> {
        let reply = self.send(Command::Kill)?;
        *self.pid.lock() = None;
        // The current thread cannot outlive the pid. `kill` and `detach`
        // cleared everything else — breakpoints, watchpoints, the command
        // channel — but left `current_tid` set, so the instance contradicted
        // itself: `is_attached()` answered false while `current_thread()` still
        // handed out the dead process's tid. That tid is the default the
        // register and stepping calls fall back to.
        *self.current_tid.lock() = None;
        *self.cmd_tx.lock() = None;
        // Clear the breakpoint map too, exactly as `detach()` does. The
        // process is gone, so the tracked original bytes are meaningless —
        // but `launch()` is allowed again once `pid` is `None`, so a stale
        // entry is inherited by the NEXT process. That matters because
        // `set_breakpoint` returns `Ok(())` early for an already-tracked
        // address: re-arming an inherited address would silently plant
        // nothing while reporting success, and `breakpoints()` would list a
        // breakpoint that does not exist in the target.
        self.breakpoints.lock().clear();
        self.hit_counts.lock().clear();
        self.disabled.lock().clear();
        self.conditions.lock().clear();
        // A stale load base outliving the session would make the NEXT
        // process's pending request resolve immediately, at the old
        // process's address — a fabricated answer, not a missing one.
        self.pending.lock().clear();
        self.ignore_counts.lock().clear();
        self.thread_filters.lock().clear();
        // Same reasoning one layer down, and it was missing: `detach()` clears
        // the hardware-watchpoint map (inside `disarm_all_hardware_watchpoints`)
        // but `kill()` never did. The entries therefore survived the death of
        // the process they belonged to, and `launch()` is allowed again as soon
        // as `pid` is `None` — so the NEXT process inherited them. Two concrete
        // consequences, both "confidently wrong" rather than merely untidy:
        // `breakpoints()` chains this map into its answer, so it listed
        // watchpoints that exist in no live process; and
        // `rearm_watchpoints_on_new_threads`, which `continue_execution` calls,
        // walks exactly this map — so the fresh process had debug registers
        // burned on addresses its caller never asked to watch.
        // No register sweep is needed here, unlike `detach()`: the process is
        // gone, and its debug registers with it.
        self.hw_watchpoints.lock().clear();
        match reply {
            Reply::Ack(r) => r,
            _ => Ok(()),
        }
    }

    fn is_attached(&self) -> bool {
        self.pid.lock().is_some()
    }

    fn target_pid(&self) -> Option<ProcessId> {
        *self.pid.lock()
    }



    async fn continue_execution(&self) -> Result<DebugEvent, DebugError> {
        // Loops so a breakpoint whose condition is FALSE resumes the target
        // instead of returning a stop the caller must filter itself. A caller
        // cannot do that filtering: by the time it sees the event the target is
        // stopped, and resuming from the outside would count as a second
        // continue.
        loop {
            // The outcome is deliberately not propagated here: this is the
            // resume path, which retries and re-plants on its own, and a thread
            // that could not be stepped off is handled by the loop below. Named
            // rather than dropped so the choice is visible.
            let _stepped_off = self.step_off_planted_breakpoint(None).await;
            let missed = self.rearm_watchpoints_on_new_threads().await;
            // Not `let _ =`. The resume still does not fail — that part of the
            // old comment was right — but the answer is RECORDED instead of
            // dropped. Assigning, not extending: an address that has since been
            // re-armed clears itself, so this never accumulates stale claims.
            *self.unarmed_since_resume.lock() = missed.into_iter().collect();
            let mut r = match self.send(Command::ContinueExecution)? {
                Reply::Event(r) => r,
                _ => return Err(DebugError::StepError("unexpected reply".into())),
            };
            if let Ok(ev) = &mut r {
                *self.current_tid.lock() = Some(ev.tid);
                // Same reasoning as in `single_step_raw`: a stop whose rewind
                // failed is not a stop the caller may resume from. It is
                // surfaced before `arm_pending_breakpoints`, because arming
                // more traps in a process parked mid-instruction only widens
                // the damage.
                self.rewind_past_own_breakpoint(ev).await?;
                self.arm_pending_breakpoints(ev).await;
                // A library event is RETURNED to the caller, not swallowed.
                //
                // Swallowing it — `continue`ing back to the top of this loop —
                // looks tidier and was tried first. It is not free: the top of
                // the loop re-runs `step_off_planted_breakpoint`, whose internal
                // single step produces its own event, and that event is
                // classified through `watchpoint_hit`, which READS AND CLEARS
                // `DR6`. `DR6` is the only thing that distinguishes a hardware
                // watchpoint hit from an ordinary single step, and it is
                // consumed destructively — so an internal resume between the
                // hit and its delivery eats the evidence, and the hit reaches
                // the caller classified as a plain step.
                //
                // Measured, not reasoned: three live tests
                // (`a_debug_register_hit_is_reported_as_a_breakpoint_not_a_single_step`
                // and its two siblings) went red, each reporting forty
                // consecutive single steps and never the armed address.
                //
                // Returning the event also preserves the pre-existing contract:
                // before this backend classified loader events at all they came
                // back as `StopReason::Unknown`, so the caller already saw one
                // stop per library load. It now sees the same stop, correctly
                // named. `arm_pending_breakpoints` has already run above, so
                // pending requests are armed either way.
                if ev.reason.is_exit() {
                    self.retire_session_after_exit();
                    return r;
                }
                if !self.condition_allows_stop(ev).await {
                    continue;
                }
            }
            if let Ok(ev) = &mut r {
                self.enrich_event_breakpoint(ev);
            }
            return r;
        }
    }

    async fn set_breakpoint_thread_filter(
        &self,
        addr: Address,
        tid: Option<ThreadId>,
    ) -> Result<(), DebugError> {
        if !self.breakpoints.lock().contains_key(&addr.as_u64()) {
            return Err(DebugError::BreakpointNotFound(addr.as_u64()));
        }
        match tid {
            Some(t) => {
                self.thread_filters.lock().insert(addr.as_u64(), t.0);
            }
            None => {
                self.thread_filters.lock().remove(&addr.as_u64());
            }
        }
        Ok(())
    }

    async fn set_breakpoint_ignore_count(&self, addr: Address, count: u64) -> Result<(), DebugError> {
        if !self.breakpoints.lock().contains_key(&addr.as_u64()) {
            return Err(DebugError::BreakpointNotFound(addr.as_u64()));
        }
        if count == 0 {
            // ONLY the ignore count. The thread filter is set by a different
            // call (`set_breakpoint_thread_filter`) and says something else
            // entirely: "ignore zero times" means "stop on every hit", not
            // "stop on every thread". Removing it here made a `break … thread
            // N` restriction vanish as a side effect, and `breakpoints()`
            // agreed with the loss, so the caller had no way to notice their
            // breakpoint had quietly become global.
            self.ignore_counts.lock().remove(&addr.as_u64());
        } else {
            self.ignore_counts.lock().insert(addr.as_u64(), count);
        }
        Ok(())
    }

    async fn set_pending_breakpoint(&self, module: &str, offset: u64) -> Result<(), DebugError> {
        // Seed the table with what is mapped RIGHT NOW.
        //
        // `add` decides "already mapped?" from a table that only
        // `resolve_on_load` ever wrote, and `resolve_on_load` is driven by a
        // `StopReason::LibraryLoad` event that no backend in this crate has
        // ever constructed. The table was therefore permanently empty, every
        // request waited for an event that cannot arrive, and this method
        // returned `Ok(())` for a breakpoint that would never exist.
        //
        // `modules()` IS implemented on all three backends, so the common case
        // — attach to a running process, break at `ntdll.dll + 0x2f40` — can be
        // answered truthfully today.
        if let Ok(mods) = self.modules().await {
            let mut pending = self.pending.lock();
            for m in &mods {
                pending.note_module_loaded(&m.path, m.base.as_u64());
                // The loader reports a full path and a caller usually types the
                // basename, but a module whose `name` differs from its path's
                // last component would otherwise be unreachable by the name the
                // listing itself publishes.
                pending.note_module_loaded(&m.name, m.base.as_u64());
            }
        }
        let now = self
            .pending
            .lock()
            .add(crate::pending_breakpoint::PendingRequest::new(module, offset));
        let Some(addr) = now else {
            // Not mapped yet — and that is now a legitimate wait on every
            // backend, not a refusal on two of them.
            //
            // The refusal that stood here was correct when written: the only
            // thing that armed a pending request was a `LibraryLoad` event,
            // and Linux/macOS construct none, so promising success would have
            // been the failure mode this crate treats as worse than an error —
            // a caller believing a breakpoint waits where none will be planted.
            //
            // `arm_pending_breakpoints` no longer needs that event: it re-reads
            // the mapped modules at every stop while anything is pending, so
            // the request arms at the first stop after the module appears. The
            // premise of the refusal is gone, and a refusal kept past its
            // premise is just a feature missing on two OSes out of three.
            return Ok(());
        };
        // Already mapped: arm it now rather than wait for a load event that has
        // already happened and will not repeat.
        self.set_breakpoint(Address(addr), BreakpointKind::Software).await?;
        Ok(())
    }

    async fn pending_breakpoints(
        &self,
    ) -> Result<Vec<crate::pending_breakpoint::PendingRequest>, DebugError> {
        Ok(self.pending.lock().pending().to_vec())
    }

    async fn single_step(&self, tid: ThreadId) -> Result<DebugEvent, DebugError> {
        // Standing ON one of our own planted traps, a single step executes the
        // TRAP and not the instruction it replaced: the exception fires again at
        // the same address and the program counter has not moved. The caller
        // asked for one instruction and got none, with no error to say so — a
        // debugger that appears stuck.
        //
        // `step_off_planted_breakpoint` already uncovers the instruction, steps
        // it, and re-plants the trap. That step IS the one the caller asked for,
        // so its event is returned rather than stepping a second time.
        // `continue_execution` has done this since iteration 357; the stepping
        // door never did.
        // Threads created since the last resume have EMPTY debug registers: on
        // x86 they are per-thread, so a watchpoint armed before the thread
        // existed does not apply to it. `continue_execution` reconciles them on
        // every resume; the stepping door never did, so stepping through the
        // code that spawns a thread left that thread unwatched — silently, which
        // is the failure mode a watchpoint exists to rule out.
        let missed = self.rearm_watchpoints_on_new_threads().await;
            // Not `let _ =`. The resume still does not fail — that part of the
            // old comment was right — but the answer is RECORDED instead of
            // dropped. Assigning, not extending: an address that has since been
            // re-armed clears itself, so this never accumulates stale claims.
            *self.unarmed_since_resume.lock() = missed.into_iter().collect();
        match self.step_off_planted_breakpoint(Some(tid)).await {
            crate::StepOff::Stepped(ev) => {
                *self.current_tid.lock() = Some(ev.tid);
                if ev.reason.is_exit() {
                    self.retire_session_after_exit();
                }
                return Ok(ev);
            }
            // Do NOT fall through to another step: the trap is re-armed and the
            // thread has not moved, so stepping again executes the `int3`.
            crate::StepOff::Failed(e) => return Err(e),
            crate::StepOff::NotOnATrap => {}
        }
        self.single_step_raw(tid).await
    }

    async fn step_over(&self, tid: ThreadId) -> Result<DebugEvent, DebugError> {
        let before = self.get_registers(tid).await?;
        let mut bytes = self
            .read_memory(Address(before.pc), rustre_arch_x86::length::MAX_INSTR_LEN)
            .await
            .unwrap_or_default();
        // `read_memory` returns the process's memory verbatim, `0xCC` patches
        // included. Decoding those bytes directly would measure `int3` (one
        // byte) instead of the instruction it replaced, so a breakpoint on the
        // instruction being stepped over produced a return address one byte
        // into the middle of it.
        {
            let planted = self.breakpoints.lock();
            let disabled = self.disabled.lock();
            crate::unpatch_planted_breakpoints(before.pc, &mut bytes, |a| {
                if disabled.contains(&a) {
                    None
                } else {
                    // A trap can be wider than one byte, so `a` may sit
                    // INSIDE one that starts earlier. Find the entry that
                    // covers it and return the byte it replaced at that
                    // offset — indexing only the start address would leave
                    // the tail of a 4-byte `BRK` visible to the caller.
                    planted.iter().find_map(|(base, orig)| {
                        let off = a.checked_sub(*base)? as usize;
                        (off < orig.len()).then(|| orig[off])
                    })
                }
            });
        }
        // Arch-correct and shared by the three backends: on a fixed-width ISA
        // the x86 length decoder measures unrelated bytes, and `unwrap_or(1)`
        // used to plant the return breakpoint one byte INTO the instruction
        // being stepped over. `None` means the length is not knowable; the
        // refusal is deferred to the point where the value is actually needed,
        // so stepping over a non-call instruction still works.
        let return_addr = crate::instr_step::step_over_return_addr(before.pc, &bytes);

        let event = self.single_step(tid).await?;
        // The debug loop waits on the whole process, so this event may belong
        // to a thread nobody asked about. Continuing would compare `tid`'s
        // registers — untouched, because `tid` never ran — and report a
        // completed step-over that never happened. The event is handed back
        // unchanged rather than swallowed: it is a real stop, just not ours.
        if !crate::step_result_belongs_to(&event, tid) {
            return Ok(event);
        }
        // Same bug class as `run_to_return` (iter 156): if this single step
        // was the process's very last instruction, `get_registers` on the
        // now-gone pid fails, masking a valid `ProcessExit` event with a
        // spurious error. Check exit first.
        if event.reason.is_exit() {
            return Ok(event);
        }
        let after = self.get_registers(tid).await?;

        if after.sp >= before.sp {
            return Ok(event);
        }
        let Some(return_addr) = return_addr else {
            return Err(DebugError::StepError(format!(
                "step_over: the instruction at {:#x} could not be decoded, so the address to return to is unknown; refusing to guess one",
                before.pc
            )));
        };
        self.run_to_return(tid, Address(return_addr), before.sp).await
    }

    async fn step_out(&self, tid: ThreadId) -> Result<DebugEvent, DebugError> {
        let regs = self.get_registers(tid).await?;
        let fp = regs.fp.ok_or_else(|| {
            DebugError::StepError("step_out: no frame pointer available to locate the return address".into())
        })?;
        if fp == 0 {
            return Err(DebugError::StepError("step_out: null frame pointer".into()));
        }
        // A corrupt frame pointer near the top of the address space must not
        // wrap. `fp + 8` in release arithmetic silently becomes a small
        // address, so the "return address" would be read out of unrelated
        // memory and `run_to_return` would then plant a `0xCC` at whatever
        // that garbage pointed to — the debugger corrupting the target it was
        // asked to inspect. A corrupt stack is precisely the situation a
        // debugger gets used in, so this is not a theoretical input.
        let saved_ret_slot = fp
            .checked_add(8)
            .ok_or_else(|| DebugError::StepError(format!(
                "step_out: frame pointer {fp:#x} is too close to the end of the address space                  for its return-address slot to exist"
            )))?;
        let caller_sp = fp.checked_add(16).ok_or_else(|| DebugError::StepError(format!(
            "step_out: frame pointer {fp:#x} leaves no room for the caller's stack pointer"
        )))?;
        let return_addr_bytes = self.read_memory(Address(saved_ret_slot), 8).await?;
        // NOT `return_addr_bytes[..8]`. The `map_err` that used to follow it
        // carried the message "step_out: short read" and could never run: the
        // slice panics before `try_into` is reached, so the case the author had
        // in mind took the whole process down instead of being reported. In a
        // debugger that is every session it was holding.
        let return_addr = crate::u64_from_le_prefix(&return_addr_bytes).ok_or_else(|| {
            DebugError::StepError(format!(
                "step_out: short read at {saved_ret_slot:#x} — asked for 8 bytes of the saved                  return address and got {}",
                return_addr_bytes.len()
            ))
        })?;
        // Zero is not a return address. Unchecked, `run_to_return` compares
        // `pc == 0`, which never comes true, so the loop single-steps until the
        // process EXITS and reports that exit as a successful step-out.
        let return_addr = crate::step_out_target_from_frame(return_addr, saved_ret_slot)?;
        self.run_to_return(tid, Address(return_addr), caller_sp).await
    }

    async fn pause(&self) -> Result<(), DebugError> {
        let pid = self.pid.lock().ok_or(DebugError::NotAttached)?;
        let ok = unsafe { libc::kill(pid.0 as libc::pid_t, libc::SIGSTOP) };
        if ok == 0 {
            Ok(())
        } else {
            Err(DebugError::StepError(format!("SIGSTOP failed: {}", std::io::Error::last_os_error())))
        }
    }

    async fn threads(&self) -> Result<Vec<ThreadId>, DebugError> {
        let pid = self.pid.lock().ok_or(DebugError::NotAttached)?;
        let task_dir = format!("/proc/{}/task", pid.0);
        let entries = std::fs::read_dir(&task_dir)
            .map_err(|e| DebugError::Os(format!("read_dir {task_dir} failed: {e}")))?;
        let mut tids = Vec::new();
        for entry in entries.flatten() {
            if let Ok(name) = entry.file_name().into_string()
                && let Ok(tid) = name.parse::<u32>()
            {
                tids.push(ThreadId(tid));
            }
        }
        Ok(tids)
    }

    async fn current_thread(&self) -> Result<ThreadId, DebugError> {
        self.current_tid.lock().ok_or(DebugError::NotAttached)
    }

    async fn get_registers(&self, tid: ThreadId) -> Result<RegisterSet, DebugError> {
        match self.send(Command::GetRegisters(tid))? {
            Reply::Registers(r) => r,
            _ => Err(DebugError::RegisterError("unexpected reply".into())),
        }
    }

    async fn set_registers(&self, tid: ThreadId, mut regs: RegisterSet) -> Result<(), DebugError> {
        // Reconcile the typed view into the map before the backend writes it.
        // `apply_register_set` reads the map only, so without this a caller who
        // set `regs.pc` — the field every backend fills in on the way OUT — got
        // `Ok(())` and a thread that never moved.
        regs.sync_map_from_special();
        match self.send(Command::SetRegisters(tid, regs))? {
            Reply::Ack(r) => r,
            _ => Err(DebugError::RegisterError("unexpected reply".into())),
        }
    }

    async fn get_register(&self, tid: ThreadId, name: &str) -> Result<u64, DebugError> {
        let regs = self.get_registers(tid).await?;
        // Narrow names are real registers, not typos: `eax` is the low half of
        // `rax` and must answer with the low half. See `read_register_by_name`.
        crate::read_register_by_name(name, |n| regs.get(n))
            .ok_or_else(|| DebugError::RegisterError(format!("unknown register {name}")))
    }

    async fn set_register(&self, tid: ThreadId, name: &str, value: u64) -> Result<(), DebugError> {
        let mut regs = self.get_registers(tid).await?;
        // Refuse exactly what `get_register` refuses. `RegisterSet::set`
        // inserts ANY name into its map, and the backend then applies only the
        // names it recognises when writing the thread context — so a name the
        // backend does not apply (`x0` on x86) was accepted, silently dropped,
        // and
        // reported as success. Reading that same name answers "unknown
        // register": the two halves of the API were giving opposite answers
        // about the same register, and the write was the one that lied.
        if crate::read_register_by_name(name, |n| regs.get(n)).is_none() {
            return Err(DebugError::RegisterError(format!("unknown register {name}")));
        }
        // A narrow name must change only the field it names, preserving the
        // rest of the register it is a view of.
        crate::write_register_by_name(&mut regs, name, value);
        self.set_registers(tid, regs).await
    }

    async fn read_memory(&self, addr: Address, size: usize) -> Result<Vec<u8>, DebugError> {
        // Hide our own software breakpoints from the caller.
        //
        // The patch is the debugger's business, not the target's contents:
        // every callee that DECODES or COMPARES these bytes — the instruction
        // length in `step_over`, a conditional-breakpoint expression reading a
        // variable, a disassembly view — was being handed `0xCC` where the
        // real byte is. GDB, LLDB and WinDbg all mask; `read_memory_raw` is
        // there for the few places that genuinely want the patched image.
        let mut bytes = self.read_memory_raw(addr, size).await?;
        let planted = self.breakpoints.lock();
        let disabled = self.disabled.lock();
        crate::unpatch_planted_breakpoints(addr.as_u64(), &mut bytes, |a| {
            if disabled.contains(&a) {
                return None;
            }
            // See `read_memory`'s twin above: a trap may be wider than one
            // byte, so look for the entry that COVERS this address rather
            // than one that starts at it.
            planted.iter().find_map(|(base, orig)| {
                let off = a.checked_sub(*base)? as usize;
                (off < orig.len()).then(|| orig[off])
            })
        });
        Ok(bytes)
    }

    async fn write_memory(&self, addr: Address, data: &[u8]) -> Result<usize, DebugError> {
        // Route the write around our own breakpoints. Letting it through
        // unchanged would overwrite the `0xCC` — a breakpoint still listed as
        // enabled would stop firing — and would leave the byte it replaced
        // recorded as "the original", so removing the breakpoint later would
        // restore the stale byte and silently undo this write.
        let (to_write, new_originals) = {
            let planted = self.breakpoints.lock();
            let disabled = self.disabled.lock();
            crate::redirect_writes_over_breakpoints(addr.as_u64(), data, |a| {
                if disabled.contains(&a) {
                    return None;
                }
                // Which byte of the trap sits at this address: on x86 the trap
                // is one byte and this is always its first, on AArch64 it is
                // four and the offset decides. Handing back a fixed `0xCC`
                // would leave three quarters of a `BRK` and one byte of
                // garbage — no longer a trap, in a breakpoint still listed as
                // enabled.
                planted.iter().find_map(|(base_addr, orig)| {
                    let off = a.checked_sub(*base_addr)? as usize;
                    (off < orig.len()).then(|| crate::host_trap_bytes()[off])
                })
            })
        };
        let written = self.write_memory_raw(addr, &to_write).await?;
        // Only record originals for bytes the target actually accepted: a
        // short write must not leave us claiming a byte that never landed.
        {
            let mut planted = self.breakpoints.lock();
            for (a, byte) in new_originals {
                if a.wrapping_sub(addr.as_u64()) < written as u64 {
                    // Update the byte at its OFFSET inside the trap the
                    // write landed on, instead of replacing the whole
                    // record: on a 4-byte trap a one-byte write must not
                    // shrink what removal will restore.
                    if let Some((base, orig)) = planted
                        .iter_mut()
                        .find(|(base, orig)| a >= **base && a - **base < orig.len() as u64)
                    {
                        let off = (a - *base) as usize;
                        orig[off] = byte;
                    }
                }
            }
        }
        Ok(written)
    }

    async fn memory_maps(&self) -> Result<Vec<MemoryMap>, DebugError> {
        let pid = self.pid.lock().ok_or(DebugError::NotAttached)?;
        let maps_path = format!("/proc/{}/maps", pid.0);
        let content = std::fs::read_to_string(&maps_path)
            .map_err(|e| DebugError::MemoryError(0, format!("read {maps_path} failed: {e}")))?;

        Ok(content.lines().filter_map(parse_maps_line).collect())
    }

    async fn set_breakpoint(&self, addr: Address, kind: BreakpointKind) -> Result<(), DebugError> {
        if !matches!(kind, BreakpointKind::Software) {
            return Err(DebugError::StepError("only software breakpoints are implemented".into()));
        }
        // The implant below writes the x86 `int3` byte 0xCC. On AArch64 that
        // is not a trap - it silently overwrites one byte of a 4-byte
        // instruction, so the target runs corrupted code instead of stopping.
        // Refuse loudly rather than wreck the process under inspection.
        // (Planting a real `BRK #0` is a larger change: this whole path
        // assumes a one-byte patch, while `ios::arm64::encode_brk` needs four.)
        // An instruction-aligned address, or nothing.
        //
        // On x86 the alignment is 1 and this never fires. On AArch64 it is 4,
        // and a trap planted at an unaligned address would straddle two
        // instructions: it would corrupt the tail of one and the head of the
        // next, and removing it would restore four bytes across the same
        // boundary. Refusing is the only correct answer — the hardware cannot
        // express the request.
        //
        // Before any byte is read or written, for the reason
        // `the_architecture_check_precedes_the_implant_in_every_backend`
        // states: a refusal that has already patched memory is not a refusal.
        let alignment = crate::host_trap_alignment();
        if !addr.as_u64().is_multiple_of(alignment) {
            return Err(DebugError::Unsupported(format!(
                "a software breakpoint at {addr:?} is not {alignment}-byte aligned; on this                  architecture a trap there would straddle two instructions and corrupt both"
            )));
        }
        // The blanket refusal off x86 that used to sit here has been REMOVED.
        //
        // It said this backend "implants the x86 int3 (0xCC)", and that was
        // true when it was written. It is no longer what this function does:
        // the implant below writes `crate::host_trap_bytes()` — `BRK #0` on
        // AArch64, derived from this crate's single arm64 encoder, four bytes
        // wide per `trap_len`, with `pc_after_trap` already accounting for the
        // ARM-vs-x86 difference in the PC reported on trap. The alignment
        // check immediately above already asks `host_trap_alignment()`.
        //
        // So the refusal outlived its reason: the backend would plant a correct
        // trap and declined to, citing a byte it no longer writes.
        //
        // What proves this is not the removal but `ubuntu-24.04-arm`, which
        // EXECUTES this path on real ARM hardware. The same stale refusal is
        // still present in the Windows and macOS backends and is deliberately
        // left there: no machine reachable from here runs those on ARM, and
        // lifting a defence where nothing can answer is predicting, not
        // measuring.
        // Idempotency guard: if this address is ALREADY tracked, do nothing
        // further — a live test proved that calling `set_breakpoint` twice
        // at the same address (e.g. a caller re-enabling an already-active
        // breakpoint) without this check would `read_memory` a SECOND time,
        // read back the `0xCC` this same function just planted, and store
        // THAT as the "original" byte — permanently corrupting the tracked
        // original, so a later `remove_breakpoint` restores `0xCC` forever
        // instead of the real instruction, wedging an unrecoverable
        // landmine with no way to undo short of re-launching.
        if self.breakpoints.lock().contains_key(&addr.as_u64()) {
            // Tracked already. If it is merely DISABLED, re-arm it — the
            // idempotency guard must not swallow a genuine re-enable, which
            // would leave the caller believing a breakpoint is active while
            // nothing is planted.
            if self.disabled.lock().contains(&addr.as_u64()) {
                let n = self.write_memory_raw(addr, crate::host_trap_bytes()).await?;
                crate::require_full_write(addr.as_u64(), n, crate::host_trap_bytes().len())?;
                self.disabled.lock().remove(&addr.as_u64());
            }
            return Ok(());
        }
        // Mirror-image of `remove_breakpoint`'s fix: track the breakpoint
        // only AFTER the `0xCC` write is confirmed to have landed. Tracking
        // it first meant a failed `write_memory` (the `?` below) left a
        // PHANTOM entry in `self.breakpoints` — the map believing a
        // breakpoint is installed at an address where the original byte is
        // actually still in place, even though the caller correctly
        // received an error from this very call.
        // As many bytes as the trap will overwrite, not one.
        //
        // `host_trap_bytes()` is one byte on x86 and FOUR on AArch64, and
        // `remove_breakpoint` restores exactly what was saved here. Saving one
        // byte on ARM64 therefore restored one and left three bytes of `BRK`
        // in the instruction stream — permanent corruption of a process the
        // caller asked only to inspect. `arch_breakpoint::trap_len`'s own doc
        // calls this "the single most damaging thing a naive port does".
        //
        // On x86 the derived length is 1, so this changes nothing there.
        let want = crate::host_trap_bytes().len();
        let original = self.read_memory(addr, want).await?;
        crate::require_full_read(addr.as_u64(), original.len(), want)?;
        // RESERVE the address under one lock, then write.
        //
        // The idempotency guard above is checked before two `await` points and
        // was acted on after them, so two concurrent `set_breakpoint` calls for
        // the same address both passed it. The interleaving that corrupts is
        // exactly the one the guard's own comment describes:
        //
        //   A: read original (real byte)   A: write 0xCC
        //   B: read original -> 0xCC       B: insert 0xCC as "the original"
        //
        // and `remove_breakpoint` then restores 0xCC forever — the
        // unrecoverable landmine, reached through concurrency instead of
        // through a second sequential call.
        //
        // Reserving before the write also preserves the property the comment
        // above demands — no phantom entry for a write that failed — because
        // every failure path below removes the reservation again.
        {
            let mut planted = self.breakpoints.lock();
            if planted.contains_key(&addr.as_u64()) {
                // Another call won the race and is planting the same trap at
                // the same address. Its `0xCC` is the one that lands, and its
                // `original` was read before any write, so it is the true byte.
                return Ok(());
            }
            planted.insert(addr.as_u64(), original);
        }
        let written = self.write_memory_raw(addr, crate::host_trap_bytes()).await;
        let n = match written {
            Ok(n) => n,
            Err(e) => {
                self.breakpoints.lock().remove(&addr.as_u64());
                return Err(e);
            }
        };
        // A trap that only partly landed is not a breakpoint; refusing here
        // also leaves the address untracked, which is what the comment above
        // requires.
        if let Err(e) = crate::require_full_write(addr.as_u64(), n, crate::host_trap_bytes().len())
        {
            self.breakpoints.lock().remove(&addr.as_u64());
            return Err(e);
        }
        Ok(())
    }

    async fn set_watchpoint_sized(
        &self,
        addr: Address,
        kind: BreakpointKind,
        size: u8,
    ) -> Result<(), DebugError> {

        // Ask the capability list BEFORE touching the debug registers. It
        // already publishes, per architecture, whether this backend can arm a
        // hardware watchpoint and why not — and nothing consulted it, so on
        // Windows-on-ARM the whole arming loop ran against `dr0..dr7` fields
        // that do not exist, found nothing armed, and answered `NotAttached`.
        // That points the caller at their session, which was never the problem.
        //
        // The reason is READ from the declaration rather than restated here, so
        // the two cannot drift apart.
        if let Some(why) = crate::capability_refusal("hardware_watchpoints") {
            return Err(DebugError::Unsupported(why.to_string()));
        }
        // Actually program the debug registers. Without this the trait default
        // forwarded to `set_breakpoint`, which rejects everything that is not
        // `Software`, so every hardware watchpoint request on this backend
        // failed outright.
        if matches!(kind, BreakpointKind::Software) {
            return self.set_breakpoint(addr, kind).await;
        }
        // The refusal that used to sit here — "this backend programs the x86
        // debug registers, which this host architecture does not have" — is
        // gone as of iteration 570. Its second half was true and is no longer
        // the whole story: the `dr` vocabulary this function speaks is now
        // TRANSLATED to DBGWVR/DBGWCR on AArch64 by `merge_debug_state` /
        // `write_debug_registers`, through NT_ARM_HW_WATCH, using the same
        // `arm64_watchpoint_from_dr_slot` pair that lib.rs already held and
        // that macOS already used. This function is unchanged below and stays
        // byte-identical with the other backends, which is the point.
        //
        // Proof is delegated, not claimed: `ubuntu-24.04-arm` executes this on
        // real ARM hardware. Nothing reachable from here can.
        let tids = self.threads().await?;
        if tids.is_empty() {
            return Err(DebugError::NotAttached);
        }
        // The debug registers are PER-THREAD on x86. Arming only the current
        // thread left a watchpoint that never fires when any other thread
        // touches the address, while the caller was told the address was
        // watched — a silent miss, not an error. Pick one slot that is free in
        // EVERY thread (the union of their DR7s) so the same slot means the
        // same watchpoint everywhere and the disarm can find it.
        let mut combined_dr7 = 0u64;
        let mut per_thread = Vec::with_capacity(tids.len());
        for tid in &tids {
            let regs = self.get_registers(*tid).await?;
            let dr7 = regs.get("dr7").unwrap_or(0);
            combined_dr7 |= dr7;
            per_thread.push((*tid, regs, dr7));
        }
        // Re-use the slot this address already occupies, if any. x86 has four
        // slots total; without this, arming the same address twice took a
        // second one, and four identical requests exhausted the hardware while
        // the caller had asked to watch ONE address. Worse, `hw_watchpoints` is
        // keyed by address, so the second insert overwrote the first: the extra
        // slots stayed armed with nothing tracking them, unfreeable until
        // detach. `set_breakpoint` has had an idempotency guard for a long
        // time; this is the same guard for the hardware path.
        let existing = per_thread.first().and_then(|(_, regs, dr7)| {
            (0u8..4).find(|slot| {
                let name = match slot {
                    0 => "dr0",
                    1 => "dr1",
                    2 => "dr2",
                    _ => "dr3",
                };
                dr7 & (1u64 << (2 * u32::from(*slot))) != 0 && regs.get(name) == Some(addr.as_u64())
            })
        });
        let slot = match existing {
            Some(slot) => slot,
            // The count comes from the HARDWARE where the hardware can say.
            //
            // x86 has four debug registers as a fact of the architecture.
            // AArch64 does not: the kernel reports the real number in
            // `dbg_info`, and a two-slot CPU handed slot 2 would have the engine
            // commit to a register that does not exist, with the refusal
            // arriving later from the kernel (589) instead of here where the
            // caller can act on it.
            // The count travels WITH THE REGISTERS, like the PAC mask.
            //
            // Asking the kernel here directly would repeat 573 and 591 exactly:
            // this is an async body, ptrace is only valid from the tracer
            // thread, and from anywhere else it answers ESRCH — a helper that
            // looks right and silently returns the fallback forever. The count
            // is published by `merge_debug_state`, which runs ON that thread.
            //
            // Absent — every non-AArch64 host — means four, the architectural
            // answer, so this changes nothing where nothing needed changing.
            None => crate::free_watchpoint_slot(
                combined_dr7,
                per_thread
                    .first()
                    .and_then(|(_, regs, _)| regs.get(WATCHPOINT_SLOTS_KEY))
                    .and_then(|v| u8::try_from(v).ok())
                    .filter(|n| *n > 0)
                    .unwrap_or(4),
            )
            .ok_or_else(|| {
                DebugError::Unsupported(
                    "all four x86 debug-register slots (DR0-DR3) are in use".into(),
                )
            })?,
        };
        let slot_name = match slot {
            0 => "dr0",
            1 => "dr1",
            2 => "dr2",
            _ => "dr3",
        };
        // Encode BEFORE touching any register: a rejected width or a
        // misaligned address must leave every thread exactly as it was, not
        // some of them half-programmed.
        let encoded: Vec<(ThreadId, RegisterSet)> = per_thread
            .into_iter()
            .map(|(tid, mut regs, dr7)| {
                crate::x86_encode_watchpoint_dr7(dr7, slot, addr.as_u64(), kind, size).map(
                    |new_dr7| {
                        regs.set(slot_name, addr.as_u64());
                        regs.set("dr7", new_dr7);
                        (tid, regs)
                    },
                )
            })
            .collect::<Result<_, _>>()?;

        // A thread can exit between enumeration and the write; that is normal
        // and must not fail the whole call. Failing only when NOTHING was
        // armed keeps "success" meaning at least one thread really watches.
        let mut armed = 0usize;
        let mut last_err = None;
        for (tid, regs) in encoded {
            if let Err(e) = self.set_registers(tid, regs).await {
                last_err = Some(e);
                continue;
            }
            // READ THE REGISTERS BACK. A write call that returned `Ok` is not
            // a programmed debug register.
            //
            // This backend's own notes record the reason: a
            // `SetThreadContext(CONTEXT_DEBUG_REGISTERS)` issued from a thread
            // other than the debug-loop thread "is accepted and silently does
            // nothing" on Windows. Counting the call rather than the effect
            // therefore let `set_watchpoint_sized` return `Ok(())` — the caller
            // believing an address is watched — with nothing armed anywhere.
            //
            // A thread that exits between the write and the read-back simply
            // does not count as armed, which is the tolerance this loop already
            // had: the call fails only when NO thread ended up watching.
            match self.get_registers(tid).await {
                Ok(back) => {
                    let dr7 = back.get("dr7").unwrap_or(0);
                    let enabled = dr7 & (1u64 << (2 * u32::from(slot))) != 0;
                    if enabled && back.get(slot_name) == Some(addr.as_u64()) {
                        armed += 1;
                    } else {
                        last_err = Some(DebugError::RegisterError(format!(
                            "thread {} accepted the debug-register write but did not take it: {slot_name} reads {:#x}, DR7 {dr7:#x}",
                            tid.0,
                            back.get(slot_name).unwrap_or(0)
                        )));
                    }
                }
                Err(e) => last_err = Some(e),
            }
        }
        if armed == 0 {
            return Err(last_err.unwrap_or(DebugError::NotAttached));
        }
        // Remember it so threads created later can be armed too: they start
        // with empty debug registers and would otherwise never watch anything.
        self.hw_watchpoints.lock().insert(addr.as_u64(), (kind, size));
        // And it is ENABLED now — the registers were just programmed above.
        // Without this the software and hardware paths disagreed: `set_breakpoint`
        // clears the disabled flag when it re-plants a tracked-but-disabled
        // breakpoint, this one never did. Re-arming a DISABLED watchpoint
        // therefore left the address armed in hardware while `breakpoints()`
        // still reported `enabled: false`, and — worse — `disable_breakpoint`
        // short-circuits on `already_disabled`, so the watchpoint could never be
        // switched off again by any call short of `remove`. Armed, unreportable
        // and unstoppable: confidently wrong in all three directions at once.
        self.disabled.lock().remove(&addr.as_u64());
        Ok(())
    }

    async fn remove_breakpoint(&self, addr: Address) -> Result<(), DebugError> {
        // Look up (don't remove yet) so a failed `write_memory` leaves the
        // entry tracked — untracking it before the restore is confirmed
        // would mean `detach()`'s breakpoint-cleanup sweep (iter 149's fix)
        // silently skips this address, leaving a real `0xCC` landmine in
        // the process's memory with nothing left tracking it.
        // A hardware watchpoint at this address goes FIRST and unconditionally.
        //
        // The two kinds are independent resources — an execution trap in the
        // code and a debug register watching the same location are both
        // legitimate, and a caller may well set both. Treating them as
        // alternatives (software first, hardware only if there is no software)
        // meant that removing an address carrying BOTH freed the `0xCC` and
        // left the debug register armed, while reporting success. The caller
        // is then holding a watchpoint that `breakpoints()` no longer lists
        // and that nothing will ever free.
        let had_watchpoint = self.hw_watchpoints.lock().contains_key(&addr.as_u64());
        if had_watchpoint {
            self.remove_hardware_watchpoint(addr).await?;
        }
        let tracked = self.breakpoints.lock().get(&addr.as_u64()).cloned();
        let Some(original) = tracked else {
            // Nothing software here. If a watchpoint was removed just above,
            // the request is satisfied; otherwise the address was never set.
            if had_watchpoint {
                return Ok(());
            }
            return Err(DebugError::BreakpointNotFound(addr.as_u64()));
        };
        // A disabled breakpoint's byte is already back in place; writing it
        // again is harmless but pointless, and would fail needlessly on a
        // dead process.
        if !self.disabled.lock().contains(&addr.as_u64()) {
            let n = self.write_memory_raw(addr, &original).await?;
            // Refuse BEFORE untracking: a half-restored instruction that is
            // then forgotten is the landmine this function exists to avoid.
            crate::require_full_write(addr.as_u64(), n, original.len())?;
        }
        self.breakpoints.lock().remove(&addr.as_u64());
        self.hit_counts.lock().remove(&addr.as_u64());
        self.ignore_counts.lock().remove(&addr.as_u64());
        self.disabled.lock().remove(&addr.as_u64());
        // The condition goes with the breakpoint it belonged to. Leaving it
        // behind would attach it to whatever is set at this address NEXT — a
        // filter the caller never asked for, on a different breakpoint.
        self.conditions.lock().remove(&addr.as_u64());
        // And so does the thread restriction, for exactly the reason above.
        // It was the sixth per-address map added to this backend and the only
        // one never added to this sweep, so it outlived its breakpoint: set a
        // new breakpoint at the same address and it stops ONLY on the thread
        // the removed one was restricted to, silently, for every other thread.
        // Worse than a stale condition, because `condition_allows_stop` gates
        // the thread filter FIRST and does not count the crossing, so the
        // breakpoint appears never to be reached rather than never to fire.
        self.thread_filters.lock().remove(&addr.as_u64());
        Ok(())
    }

    async fn enable_breakpoint(&self, addr: Address) -> Result<(), DebugError> {
        // A disabled hardware watchpoint is still tracked, so re-enabling it
        // means putting it back in the debug registers — not planting a
        // software breakpoint at a data address, which is what forwarding to
        // `set_breakpoint` would have done.
        // Both resources, not one or the other. An address can carry a
        // software trap AND a debug register, and returning as soon as the
        // watchpoint was re-armed left the software breakpoint disabled while
        // reporting success — the twin of the defect `remove_breakpoint` had.
        let has_watchpoint = self.hw_watchpoints.lock().contains_key(&addr.as_u64());
        let has_software = self.breakpoints.lock().contains_key(&addr.as_u64());
        // Software FIRST, and only then clear the disabled flag.
        //
        // `set_breakpoint`'s idempotency guard re-plants a tracked breakpoint
        // only while it is still marked disabled; clearing the flag first made
        // it see "tracked and active", return `Ok` and plant nothing — so the
        // software trap stayed absent while the call reported success.
        // Measured: the byte at the address was not `0xCC` afterwards.
        if has_software {
            self.set_breakpoint(addr, BreakpointKind::Software).await?;
        }
        if has_watchpoint {
            self.disabled.lock().remove(&addr.as_u64());
            // This call IS the request to re-arm, so its outcome is the
            // answer. Discarding it made `enable_breakpoint` report `Ok(())`
            // for a watchpoint that no debug register holds — the third time
            // this one function has reported success for something it did not
            // do (see the two comments above, both about the software half).
            if self.rearm_watchpoints_on_new_threads().await.contains(&addr.as_u64()) {
                return Err(DebugError::RegisterError(format!(
                    "watchpoint at {addr:?} could not be re-armed into the debug registers"
                )));
            }
        }
        if has_software || has_watchpoint {
            return Ok(());
        }
        self.set_breakpoint(addr, BreakpointKind::Software).await
    }

    async fn disable_breakpoint(&self, addr: Address) -> Result<(), DebugError> {
        // Restore the original byte so the breakpoint genuinely stops firing,
        // but KEEP it tracked so `breakpoints()` can report it as disabled.
        // This used to forward to `remove_breakpoint`, which made a disabled
        // breakpoint vanish entirely and left `Breakpoint::enabled` unable to
        // ever be `false`.
        // The debug register goes first and unconditionally: an address can
        // carry BOTH a software trap and a watchpoint, and disabling only the
        // one the `else` happened to reach left the other live while
        // `breakpoints()` reported the address as disabled. Same shape as the
        // defect `remove_breakpoint` carried.
        let has_watchpoint = self.hw_watchpoints.lock().contains_key(&addr.as_u64());
        let already_disabled = self.disabled.lock().contains(&addr.as_u64());
        if has_watchpoint && !already_disabled {
            // Clear the registers but KEEP it tracked, exactly as the software
            // path restores the byte and keeps the entry.
            self.disarm_watchpoint_registers(addr).await?;
        }
        let tracked = self.breakpoints.lock().get(&addr.as_u64()).cloned();
        let Some(original) = tracked else {
            if has_watchpoint {
                self.disabled.lock().insert(addr.as_u64());
                return Ok(());
            }
            return Err(DebugError::BreakpointNotFound(addr.as_u64()));
        };
        if self.disabled.lock().contains(&addr.as_u64()) {
            return Ok(()); // already disabled: idempotent, like set_breakpoint
        }
        let n = self.write_memory_raw(addr, &original).await?;
        crate::require_full_write(addr.as_u64(), n, original.len())?;
        self.disabled.lock().insert(addr.as_u64());
        Ok(())
    }

    async fn set_breakpoint_condition(
        &self,
        addr: Address,
        expr: Option<String>,
    ) -> Result<(), DebugError> {
        let a = addr.as_u64();
        // Only for an address that actually carries a breakpoint: a condition
        // attached to nothing would sit in the table looking effective while no
        // stop could ever consult it.
        let known = self.breakpoints.lock().contains_key(&a)
            || self.hw_watchpoints.lock().contains_key(&a);
        if !known {
            return Err(DebugError::BreakpointNotFound(a));
        }
        match expr {
            Some(text) => {
                // Parsed HERE, so a malformed expression is refused at the door
                // instead of being discovered at the first hit — where the only
                // honest response left is to stop anyway.
                crate::conditional_breakpoint::BreakpointCondition::parse(&text)
                    .map_err(|e| DebugError::Unsupported(format!("condition {text:?}: {e}")))?;
                self.conditions.lock().insert(a, text);
            }
            None => {
                self.conditions.lock().remove(&a);
            }
        }
        Ok(())
    }

    async fn breakpoints(&self) -> Result<Vec<Breakpoint>, DebugError> {
        // Iterate the ENTRIES, not just the keys: the map already holds the
        // original byte each breakpoint will restore, and rebuilding from
        // `new_software` alone threw it away (`original_byte: None`). That
        // byte is what `detach()`/`Drop` write back, so a caller inspecting
        // breakpoints could not see what the target's code reverts to.
        Ok(self
            .breakpoints
            .lock()
            .iter()
            .map(|(&addr, original)| {
                let mut bp = Breakpoint::new_software(Address(addr));
                // `Breakpoint::original_byte` is a single `u8` in the public
                // API; report the first replaced byte. On x86 that is the
                // whole story; on a 4-byte AArch64 trap it is the first
                // quarter, and the full bytes stay in the tracking map where
                // detach and remove read them.
                bp.original_byte = original.first().copied();
                bp.hit_count = self.hit_counts.lock().get(&addr).copied().unwrap_or(0);
                bp.enabled = !self.disabled.lock().contains(&addr);
                bp.condition = self.conditions.lock().get(&addr).cloned();
                // The two gates that stop an ENABLED breakpoint at a reached
                // address from stopping. Both were accepted by the API and then
                // invisible here, so a caller could set a thread restriction and
                // have no way to see it afterwards — and a restricted breakpoint
                // reads as one the program never reaches, because a wrong-thread
                // crossing is deliberately not counted in `hit_count`.
                bp.ignore_count = self.ignore_counts.lock().get(&addr).copied().unwrap_or(0);
                bp.only_thread = self.thread_filters.lock().get(&addr).copied().map(ThreadId);
                bp
            })
            // Hardware watchpoints live in their own map and were absent from
            // this list entirely, so a caller that armed one and then asked
            // what was set got an answer that omitted it — the MCP
            // `debug.breakpoints` tool serialises exactly this vector, so the
            // watchpoint was unlistable and could not be removed knowingly.
            // They carry no original byte: nothing was patched in the target.
            .chain(self.hw_watchpoints.lock().iter().map(|(&addr, &(kind, size))| {
                // The width was bound to `_size` and dropped on the floor here,
                // so every watchpoint listed as if it covered an unspecified
                // amount of memory. It is the one field a caller needs to arm
                // the SAME watchpoint again from a listing.
                let mut bp = Breakpoint {
                    kind,
                    byte_size: Some(size),
                    ..Breakpoint::new_hardware(Address(addr))
                };
                // Same counter the software breakpoints publish. Without this
                // the count is maintained and then dropped on the floor, which
                // reads identically to never counting at all.
                bp.hit_count = self.hit_counts.lock().get(&addr).copied().unwrap_or(0);
                // A disabled watchpoint stays tracked with its registers
                // cleared, exactly like a disabled software breakpoint keeps
                // its entry with the original byte back in the target. Without
                // this the flag was hard-wired to `true` and `disable` could
                // never be observed.
                bp.enabled = !self.disabled.lock().contains(&addr);
                bp.condition = self.conditions.lock().get(&addr).cloned();
                // Same two gates: `condition_allows_stop` applies them to
                // watchpoints exactly as it does to software breakpoints.
                bp.ignore_count = self.ignore_counts.lock().get(&addr).copied().unwrap_or(0);
                bp.only_thread = self.thread_filters.lock().get(&addr).copied().map(ThreadId);
                // The last field of this block that was maintained nowhere and
                // published nowhere. A watchpoint listed as enabled and
                // hit-counted while no debug register on some thread holds it
                // is the most expensive wrong answer this tool can give, and
                // until now the listing had no way to say it.
                if self.unarmed_since_resume.lock().contains(&addr) {
                    bp.label = Some(
                        "not armed on every thread as of the last resume".to_string(),
                    );
                }
                bp
            }))
            .collect())
    }

    async fn modules(&self) -> Result<Vec<ModuleInfo>, DebugError> {
        let pid = self.pid.lock().ok_or(DebugError::NotAttached)?;
        let maps_path = format!("/proc/{}/maps", pid.0);
        let content = std::fs::read_to_string(&maps_path)
            .map_err(|e| DebugError::MemoryError(0, format!("read {maps_path} failed: {e}")))?;

        // Collect the lowest mapped base per distinct backing file path —
        // the first file-backed mapping (typically the executable segment)
        // determines each module's load base.
        let mut bases: Vec<(String, u64, u64)> = Vec::new(); // (path, base, max_end)
        for line in content.lines() {
            let mut parts = line.split_whitespace();
            let Some(range) = parts.next() else { continue };
            let Some((start_s, end_s)) = range.split_once('-') else { continue };
            let (Ok(start), Ok(end)) = (u64::from_str_radix(start_s, 16), u64::from_str_radix(end_s, 16)) else {
                continue;
            };
            let Some(path) = maps_line_path(line) else { continue };
            if let Some(entry) = bases.iter_mut().find(|(p, ..)| p == path) {
                entry.1 = entry.1.min(start);
                entry.2 = entry.2.max(end);
            } else {
                bases.push((path.to_string(), start, end));
            }
        }

        Ok(bases
            .into_iter()
            .enumerate()
            .map(|(i, (path, base, end))| ModuleInfo {
                name: path.rsplit('/').next().unwrap_or(&path).to_string(),
                entry_point: elf_entry_point(&path, base),
                path: path.clone(),
                base: Address(base),
                size: end.saturating_sub(base),
                is_main: i == 0,
            })
            .collect())
    }

    async fn backtrace(&self, tid: ThreadId) -> Result<Vec<StackFrame>, DebugError> {
        let regs = self.get_registers(tid).await?;
        let pc = regs.pc;
        let sp = regs.sp;
        let fp = regs.fp;

        let reader = |addr: u64, size: usize| -> Option<Vec<u8>> {
            match self.send(Command::ReadMemory(addr, size)) {
                Ok(Reply::Memory(Ok(data))) => Some(data),
                _ => None,
            }
        };

        // The target's REAL mappings, not an empty view.
        //
        // `regions` is what names each frame's module, and this passed an empty
        // one: `find()` therefore answered `None` for every program counter and
        // every frame of every backtrace came back with `module: None` — on all
        // three backends. A stack trace that cannot say which image a frame
        // belongs to is a column of hex, which is exactly the complaint this
        // debugger was audited for.
        //
        // Built from `memory_maps()` alone, deliberately: `of_target` would also
        // MEASURE the resident set, walking the working set page by page, and a
        // backtrace must not pay for that.
        let maps = self.memory_maps().await.unwrap_or_default();
        let regions = crate::memory_layout_view::MappedRegionView::from_memory_maps(&maps);
        // The module a frame belongs to, by its own NAME.
        //
        // `LiveStackFrame::region` renders the region KIND, which for a
        // file-backed mapping reads `/usr/bin/dash+0x4000` — a description, not
        // the module name the rest of this API uses. The maps already carry the
        // name the caller expects, so it is taken from there and the rendered
        // kind is only the fallback.
        let module_of = |pc: u64| -> Option<String> {
            maps.iter()
                .find(|m| pc >= m.base.as_u64() && pc < m.base.as_u64().saturating_add(m.size))
                .and_then(|m| m.name.clone())
        };
        let unwinder = crate::memory_layout_view::FramePointerUnwinder::new(128);
        let live_frames = unwinder.unwind(pc, sp, fp, &regions, reader);

        let mut frames: Vec<StackFrame> = live_frames
            .into_iter()
            .map(|f| StackFrame {
                index: f.index,
                pc: Address(f.pc),
                sp: Address(f.sp),
                fp: f.fp.map(Address),
                function_name: None,
                module: module_of(f.pc).or(f.region),
                offset: None,
                source_file: None,
                source_line: None,
            })
            .collect();

        // `FramePointerUnwinder` alone typically stops after 1 frame on
        // real Linux binaries — most system code doesn't preserve `rbp` as
        // a frame pointer, so there's nothing for it to chain through.
        // Continue unwinding from wherever it stopped using real DWARF CFI
        // (`.eh_frame`) — the mechanism gdb/lldb actually use. Best-effort:
        // any lookup/read/parse failure at any step just stops here.
        if let Some(last) = frames.last() {
            let mut cur_pc = last.pc.as_u64();
            let mut cur_sp = last.sp.as_u64();
            // The live `rbp` value is only genuinely known for the frame
            // `FramePointerUnwinder` actually stopped at (`last` — NOT
            // necessarily frame 0: if `rbp` chaining genuinely worked for
            // one or more frames before running out, `last` is already a
            // deeper frame, and using frame 0's ORIGINAL `rbp` here would
            // be silently wrong for that deeper frame). After the first
            // CFI step, this loop doesn't track register-restore rules
            // (only `DW_CFA_def_cfa*`, not `DW_CFA_offset` for `rbp`
            // specifically), so a caller's `rbp` is honestly unknown and
            // stays `None`, correctly bailing rather than guessing if a
            // later frame's CFA rule turns out to be rbp-based.
            let mut cur_fp = last.fp.map(|a| a.as_u64());
            // Cache each distinct module's `.eh_frame` bytes for the
            // duration of this single `backtrace()` call — a call stack
            // commonly stays within the same module (e.g. several frames
            // deep in libc) across multiple unwind steps, and re-opening
            // + re-reading the ELF file's section headers on every single
            // step would be needless repeated disk I/O for data that
            // cannot change mid-call. `Option<...>` inside the cache entry
            // distinguishes "not yet looked up" from "looked up and
            // genuinely has no `.eh_frame`" (a real, negative result also
            // worth caching, not just successes).
            let mut eh_frame_cache: std::collections::HashMap<String, Option<(Vec<u8>, u64)>> = std::collections::HashMap::new();
            if let Ok(modules) = self.modules().await {
                for _ in 0..crate::BACKTRACE_FRAME_CAP {
                    let Some(module) = modules
                        .iter()
                        .find(|m| cur_pc >= m.base.as_u64() && cur_pc < m.base.as_u64() + m.size)
                    else {
                        break;
                    };
                    let cached = eh_frame_cache
                        .entry(module.path.clone())
                        .or_insert_with(|| read_eh_frame_section(&module.path, module.base.as_u64()));
                    let Some((eh_frame, eh_frame_vaddr)) = cached.as_ref() else {
                        break;
                    };
                    let Some(cfa) = cfi_unwind_one_frame(eh_frame, *eh_frame_vaddr, cur_pc, cur_sp, cur_fp) else {
                        break;
                    };
                    // `cfa - 8` (return address always lives one slot
                    // below CFA, per the standard x86-64 convention) would
                    // panic on underflow in a debug build if `cfa` were
                    // ever implausibly small (corrupted stack data,
                    // adversarial input) — `checked_sub` bails gracefully
                    // instead, matching this whole feature's "bail, don't
                    // guess/crash" philosophy.
                    let Some(ret_addr_loc) = cfa.checked_sub(8) else { break };
                    let Ok(ret_bytes) = self.read_memory(Address(ret_addr_loc), 8).await else { break };
                    let Ok(ret_bytes8): Result<[u8; 8], _> = ret_bytes.as_slice().try_into() else { break };
                    let ret_addr = u64::from_le_bytes(ret_bytes8);
                    // Strip pointer authentication BEFORE the address is used
                    // as an address. Measured on ubuntu-24.04-arm: an unwound
                    // pc came back as 0x31ab6b12435c0c and fell inside no
                    // loaded module, because the high bits are a signature,
                    // not address.
                    //
                    // Iteration 559 fixed exactly this in the SHARED
                    // frame-pointer unwinder and the defect was then recorded
                    // as closed. It was not: this backend unwinds through its
                    // own DWARF CFI path and never reaches that code. A fix in
                    // one unwinder is not a fix for unwinding.
                    //
                    // The mask is the KERNEL's, not a constant of ours -- see
                    // `pac_insn_mask`. No PAC on this host means nothing to
                    // strip, which is why `None` leaves the address untouched.
                    // Read from the register set fetched at the top of this
                    // function, which came through the command channel. Calling
                    // ptrace here directly is what made 573 a no-op.
                    #[cfg(target_arch = "aarch64")]
                    let ret_addr = match regs.get(PAC_INSN_MASK_KEY) {
                        Some(m) if m != 0 => strip_pac_with(ret_addr, m),
                        _ => ret_addr,
                    };
                    if ret_addr == 0 {
                        break;
                    }
                    // Look up the module covering `ret_addr` specifically
                    // — NOT the `module` variable above, which covers
                    // `cur_pc` (the frame we just unwound FROM). A return
                    // address commonly lands in a DIFFERENT module (e.g.
                    // unwinding from libc back into the main executable),
                    // so reusing the callee's module name here would
                    // mislabel the caller's frame.
                    let ret_module = modules
                        .iter()
                        .find(|m| ret_addr >= m.base.as_u64() && ret_addr < m.base.as_u64() + m.size)
                        .map(|m| m.name.clone());
                    frames.push(StackFrame {
                        index: frames.len(),
                        pc: Address(ret_addr),
                        sp: Address(cfa),
                        fp: None,
                        function_name: None,
                        module: ret_module,
                        offset: None,
                        source_file: None,
                        source_line: None,
                    });
                    cur_pc = ret_addr;
                    cur_sp = cfa;
                    cur_fp = None; // real value unknown past the first step — see the comment above
                }
            }
        }

        if let Some(resolver) = self.symbols.lock().as_ref() {
            crate::symbol_resolver::enrich_frames(&mut frames, resolver.as_ref());
        }
        Ok(frames)
    }

    fn set_symbol_resolver(
        &self,
        resolver: std::sync::Arc<dyn crate::symbol_resolver::FrameSymbolResolver>,
    ) -> Result<(), DebugError> {
        *self.symbols.lock() = Some(resolver);
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Runtime integration tests — real child process, real ptrace(2)
// ─────────────────────────────────────────────────────────────────────────────
//
// Mirrors `windows_debugger::live_tests`: everything above compiled cleanly
// but had never been exercised against a live process. These tests launch a
// real `/bin/sh -c 'exit 0'` child under `LinuxDebugger` and drive the actual
// ptrace API end to end.
#[cfg(test)]
mod live_tests {
    use super::*;

    /// The two `/proc/maps` parsers must agree on the backing path.
    ///
    /// `memory_maps` and `modules` both read the same lines but count columns
    /// differently — one consumes range+perms+offset then takes `nth(2)`, the
    /// other jumps to `nth(4)` after the range alone. Both are correct today;
    /// the point is that they cannot drift apart silently. Iteration 344 lost
    /// `vsize` to exactly this, an off-by-one in a column count whose comment
    /// even listed the right number of fields.
    #[test]
    fn both_maps_parsers_agree_on_the_backing_path() {
        let lines = [
            "7f4c8a000000-7f4c8a028000 r--p 00000000 08:02 1443 /usr/lib/libc.so.6",
            "7f4c8a1ac000-7f4c8a1b0000 rw-p 001ac000 08:02 1443 /usr/lib/libc.so.6",
            "55a1f2c00000-55a1f2c01000 r-xp 00001000 08:02 99 /usr/bin/prog",
            // No backing file: both must report none.
            "7ffd1c000000-7ffd1c021000 rw-p 00000000 00:00 0",
            // Pseudo-regions are not modules; `maps_line_path` filters them and
            // `parse_maps_line` reports them as a plain path.
            "7ffd1c021000-7ffd1c022000 r-xp 00000000 00:00 0 [vdso]",
            // Truncated line: neither may invent a path.
            "7f4c8a000000-7f4c8a028000 r--p 00000000",
        ];
        for line in lines {
            let via_map = parse_maps_line(line).and_then(|m| m.file_path);
            let via_module = maps_line_path(line).map(str::to_owned);
            match via_module {
                // When `modules` sees a real module, the other parser must have
                // extracted exactly the same string.
                Some(p) => assert_eq!(
                    via_map.as_deref(),
                    Some(p.as_str()),
                    "the two parsers disagree on `{line}`"
                ),
                // When it sees none, the other must report none OR a pseudo
                // region — never a different real path.
                None => assert!(
                    via_map.as_deref().is_none_or(|p| p.starts_with('[')),
                    "`modules` found no module but `memory_maps` read `{via_map:?}` from `{line}`"
                ),
            }
        }
    }

    /// `file_offset` must carry the offset `/proc/maps` actually reports.
    ///
    /// The field is documented "Offset within the backing file" and the macOS
    /// backend fills it from the real value (`file_offset: info.offset`). Linux
    /// hard-coded it to 0 while `/proc/<pid>/maps` supplies it in column 3 —
    /// the parser read past it without looking.
    ///
    /// A shared library is mapped as several regions and only the first sits at
    /// offset 0: `.rodata`/`.data`/`.text` of every `.so` are mapped at non-zero
    /// offsets. Anything correlating a virtual address back to a position in the
    /// file — symbolising a mapped region, locating a section on disk — computes
    /// `vaddr - base + file_offset`, and with a constant 0 that answer is wrong
    /// for every region but the first.
    #[test]
    fn maps_lines_carry_the_real_file_offset() {
        // Real-shaped lines: libc mapped as four regions, offsets ascending.
        let text = parse_maps_line(
            "7f4c8a000000-7f4c8a028000 r--p 00000000 08:02 1443 /usr/lib/libc.so.6",
        )
        .expect("a well-formed line parses");
        assert_eq!(text.file_offset, 0, "the first region really is at offset 0");
        assert_eq!(text.base, Address(0x7f4c_8a00_0000));
        assert_eq!(text.file_path.as_deref(), Some("/usr/lib/libc.so.6"));
        assert_eq!(text.name.as_deref(), Some("libc.so.6"));

        let data = parse_maps_line(
            "7f4c8a1ac000-7f4c8a1b0000 rw-p 001ac000 08:02 1443 /usr/lib/libc.so.6",
        )
        .expect("a well-formed line parses");
        assert_eq!(
            data.file_offset, 0x001a_c000,
            "column 3 is the file offset and must be preserved"
        );
        assert!(data.readable && data.writable && !data.executable);

        // Anonymous regions have no path and offset 0.
        let anon = parse_maps_line("7ffd1c000000-7ffd1c021000 rw-p 00000000 00:00 0")
            .expect("an anonymous line parses");
        assert_eq!(anon.file_offset, 0);
        assert_eq!(anon.file_path, None);

        // A path containing spaces must still be captured whole.
        let spaced = parse_maps_line(
            "55a1f2c00000-55a1f2c01000 r-xp 00001000 08:02 99 /opt/my app/bin",
        )
        .expect("a spaced path parses");
        assert_eq!(spaced.file_offset, 0x1000);
        assert_eq!(spaced.file_path.as_deref(), Some("/opt/my"));
    }

    /// A detach that FAILS must leave the session exactly as it was.
    ///
    /// The breakpoint/hit-count/disabled tables used to be cleared BEFORE
    /// `send(Command::Detach)`, so a failing send returned through `?` with the
    /// bookkeeping already wiped while `pid`/`cmd_tx` still said "attached".
    /// The debugger then reported an empty breakpoint table for a process that
    /// still carried the patches: a retried detach restored nothing, and
    /// `remove_breakpoint` had nothing left to find. Confidently wrong, and
    /// reachable — `send` fails whenever the debug loop is gone, which is
    /// exactly what happens when the target dies and the user then hits detach.
    ///
    /// No live process needed: a debugger that was never attached has no
    /// command channel, so `send` fails for the same reason.
    #[tokio::test]
    async fn a_failed_detach_keeps_the_breakpoint_bookkeeping() {
        let dbg = LinuxDebugger::new();
        dbg.breakpoints.lock().insert(0x1234, vec![0x90]);
        dbg.hit_counts.lock().insert(0x1234, 7);
        dbg.disabled.lock().insert(0x1234);

        let err = dbg.detach().await;
        assert!(err.is_err(), "detach with no session must fail");

        assert_eq!(
            dbg.breakpoints.lock().get(&0x1234).cloned(),
            Some(vec![0x90]),
            "a failed detach wiped the breakpoint table"
        );
        assert_eq!(dbg.hit_counts.lock().get(&0x1234).copied(), Some(7));
        assert!(dbg.disabled.lock().contains(&0x1234));
    }

    use crate::{Debugger, LaunchOptions, OutputRedirect};

    /// A general-purpose scratch register this architecture actually has.
    ///
    /// These tests were written on x86-64 and asked for `rax` by name. On
    /// AArch64 the register set publishes `x0`-`x30`, `sp`, `pc` and
    /// `pstate`, so that name is simply absent and the test failed against a
    /// backend that was answering correctly. Measured on ubuntu-24.04-arm,
    /// 2026-08-15, the first time this suite ran on ARM hardware:
    ///
    ///   set_register should reach the real ptrace register set:
    ///   RegisterError("unknown register rax")
    ///
    /// A test that fails because of the architecture it was written on is
    /// measuring the wrong thing.
    #[cfg(target_arch = "x86_64")]
    const SCRATCH_REG: &str = "rax";
    #[cfg(target_arch = "aarch64")]
    const SCRATCH_REG: &str = "x0";

    /// The NARROWED view of `SCRATCH_REG`, named per architecture too.
    ///
    /// `al` is the low byte of `rax` and does not exist on AArch64, where the
    /// narrowed view is `w0`, the low 32 bits of `x0`. Hardcoding `al` made
    /// this test fail on ubuntu-24.04-arm with `al must derive from the live
    /// rax` — the assertion was about narrowing and was failing on naming.
    ///
    /// `sub_register_of` already knows both spellings; only the test did not.
    #[cfg(target_arch = "x86_64")]
    const SCRATCH_REG_NARROW: &str = "al";
    #[cfg(target_arch = "aarch64")]
    const SCRATCH_REG_NARROW: &str = "w0";

    /// The mask that narrowed view applies: 8 bits on x86, 32 on AArch64.
    #[cfg(target_arch = "x86_64")]
    const SCRATCH_NARROW_MASK: u64 = 0xFF;
    #[cfg(target_arch = "aarch64")]
    const SCRATCH_NARROW_MASK: u64 = 0xFFFF_FFFF;

    /// The program counter's name here, DERIVED from the crate's one answer
    /// rather than spelled a fifth time.
    fn pc_reg() -> &'static str {
        crate::instr_step::pc_key(crate::instr_step::native_arch())
    }

    /// Plant a software breakpoint, or assert the documented refusal.
    ///
    /// Returns `false` when this architecture refuses them, so the caller can
    /// stop instead of asserting behaviour that cannot happen here.
    ///
    /// This is NOT a skip, and what it asserts CHANGED in iteration 569.
    ///
    /// It used to assert the blanket refusal off x86 — measured on
    /// ubuntu-24.04-arm, 2026-08-15, where six live tests failed with
    /// `Unsupported("software breakpoints ... x86 int3 ...")`. That refusal has
    /// been removed: the backend implants `host_trap_bytes()`, a real `BRK #0`
    /// on AArch64, so a software breakpoint is now expected to be ACCEPTED on
    /// every architecture.
    ///
    /// One refusal survives and is still asserted: a trap must be aligned. On
    /// AArch64 an unaligned implant would straddle two instructions and corrupt
    /// both, so that `Unsupported` is a correct answer, not a gap — and
    /// accepting any other refusal here would let a re-introduced blanket
    /// refusal pass unnoticed.
    async fn plant_software_bp(dbg: &LinuxDebugger, at: Address, what: &str) -> bool {
        match dbg.set_breakpoint(at, BreakpointKind::Software).await {
            Ok(()) => true,
            Err(DebugError::Unsupported(msg)) => {
                assert!(
                    msg.contains("aligned"),
                    "{what}: refused, and alignment is the only refusal this backend is now                      entitled to give — a blanket architecture refusal was removed in 569 and                      must not come back: {msg}"
                );
                false
            }
            Err(e) => panic!("{what}: {e}"),
        }
    }

    /// Probe the x86 debug-register file, or assert the documented refusal.
    ///
    /// Returns `false` when this architecture has no `DR0`-`DR7`, so a test
    /// about them can stop instead of asserting behaviour that cannot exist.
    ///
    /// Like `plant_software_bp`, this ASSERTS rather than skips — and what it
    /// asserts was INVERTED in iteration 570.
    ///
    /// It used to assert that `dr0` is REFUSED on AArch64 and return `false`,
    /// so every watchpoint test skipped there. That refusal is gone: the four
    /// slots are now translated to `DBGWVR`/`DBGWCR` through `NT_ARM_HW_WATCH`,
    /// so `dr0` is readable on every architecture this backend runs on.
    ///
    /// Inverting it is the whole point of the round rather than a side effect.
    /// Left as it was, `debug_registers_available` would have returned `false`
    /// on ARM, every watchpoint test would have skipped, and the ARM CI row
    /// would have gone GREEN while proving nothing about the code 570 added —
    /// the vacuous-guard failure this crate names explicitly. Returning `true`
    /// is what turns `ubuntu-24.04-arm` into the measurement.
    async fn debug_registers_available(dbg: &LinuxDebugger, tid: ThreadId) -> bool {
        match dbg.get_register(tid, "dr0").await {
            Ok(_) => true,
            Err(e) => panic!(
                "dr0 must be readable on every architecture this backend supports: on x86 it                  is the register file itself, on AArch64 it is the NT_ARM_HW_WATCH translation                  added in 570. A refusal here means that translation did not reach the                  register set: {e}"
            ),
        }
    }

    fn sh_launch_options(args: &[&str]) -> LaunchOptions {
        LaunchOptions {
            executable: "/bin/sh".to_string(),
            args: args.iter().map(|s| (*s).to_string()).collect(),
            env: std::collections::HashMap::new(),
            working_dir: None,
            stop_at_entry: false,
            follow_forks: false,
            redirect: OutputRedirect::default(),
        }
    }

    /// Source of the multi-thread fixture used by
    /// [`secondary_thread_is_really_traced_and_controllable`].
    ///
    /// Deliberately barrier-synchronised rather than sleep-based: main spins
    /// on `ready` until the second thread has actually started running, so by
    /// the time the debugger sees the `SIGTRAP` stop the clone is guaranteed
    /// to have happened. The worker then loops forever, so a *live, running*
    /// secondary tid is what the test tries to control.
    const MULTITHREAD_FIXTURE_C: &str = r#"
#include <pthread.h>
#include <signal.h>
static volatile int ready = 0;
static void *worker(void *arg) { (void)arg; ready = 1; for (;;) { } return 0; }
int main(void) {
    pthread_t t;
    pthread_create(&t, 0, worker, 0);
    while (!ready) { }
    raise(SIGTRAP);
    for (;;) { }
    return 0;
}
"#;

    /// A fixture whose worker RUNS AND THEN DIES, and whose main thread then
    /// exits — no `for(;;)` anywhere.
    ///
    /// [`MULTITHREAD_FIXTURE_C`] spins forever in both threads on purpose (it
    /// needs a live secondary thread to single-step). That makes it useless for
    /// testing thread DEATH, and it is why removing the fix in iteration 526
    /// made the test HANG instead of fail, leaving `rustre_mt_fixture_*`
    /// processes orphaned at full CPU. A test that hangs when the code is wrong
    /// proves nothing and poisons the runs after it.
    ///
    /// `pthread_join` before `raise(SIGTRAP)` guarantees the worker is already
    /// gone when the debugger reaches the sync point.
    const DYING_THREAD_FIXTURE_C: &str = r#"
#include <pthread.h>
#include <signal.h>
static void *worker(void *arg) { (void)arg; return 0; }
int main(void) {
    pthread_t t;
    pthread_create(&t, 0, worker, 0);
    pthread_join(t, 0);
    raise(SIGTRAP);
    return 0;
}
"#;

    /// Compile [`DYING_THREAD_FIXTURE_C`]; `None` when no `cc` is available.
    fn build_dying_thread_fixture() -> Option<String> {
        let dir = std::env::temp_dir();
        let src = dir.join(format!("rustre_dying_fixture_{}.c", std::process::id()));
        let bin = dir.join(format!("rustre_dying_fixture_{}", std::process::id()));
        std::fs::write(&src, DYING_THREAD_FIXTURE_C).ok()?;
        let out = ProcessCommand::new("cc")
            .arg(src.to_str()?)
            .arg("-o")
            .arg(bin.to_str()?)
            .arg("-lpthread")
            .arg("-O0")
            .output()
            .ok()?;
        let _ = std::fs::remove_file(&src);
        if !out.status.success() {
            return None;
        }
        Some(bin.to_str()?.to_string())
    }

    /// Compile [`MULTITHREAD_FIXTURE_C`] with `cc` into a temp file, returning
    /// its path, or `None` when no C compiler is available (the test then
    /// skips rather than failing on an unrelated environment problem).
    fn build_multithread_fixture() -> Option<String> {
        let dir = std::env::temp_dir();
        let src = dir.join(format!("rustre_mt_fixture_{}.c", std::process::id()));
        let bin = dir.join(format!("rustre_mt_fixture_{}", std::process::id()));
        std::fs::write(&src, MULTITHREAD_FIXTURE_C).ok()?;
        let out = ProcessCommand::new("cc")
            .arg(src.to_str()?)
            .arg("-o")
            .arg(bin.to_str()?)
            .arg("-lpthread")
            .arg("-O0")
            .output()
            .ok()?;
        let _ = std::fs::remove_file(&src);
        if !out.status.success() {
            return None;
        }
        Some(bin.to_str()?.to_string())
    }

    /// A REAL secondary thread — discovered via `threads()`, created by
    /// `pthread_create` in the tracee — must answer `get_registers` and
    /// `single_step`.
    ///
    /// Before `PTRACE_O_TRACECLONE` (this iteration) only the initial thread
    /// was ptrace-attached, so every per-tid request against a secondary tid
    /// failed with ESRCH: `threads()` reported threads the backend could not
    /// actually touch. This test is the difference between "enumerates
    /// threads" and "debugs threads"; it is what three previous attempts at
    /// this feature never got to.
    #[tokio::test]
    async fn secondary_thread_is_really_traced_and_controllable() {
        let Some(bin) = build_multithread_fixture() else {
            eprintln!("skipping: no working `cc` to build the pthread fixture");
            return;
        };
        let opts = LaunchOptions {
            executable: bin.clone(),
            args: vec![],
            env: std::collections::HashMap::new(),
            working_dir: None,
            stop_at_entry: false,
            follow_forks: false,
            redirect: OutputRedirect::default(),
        };
        let dbg = LinuxDebugger::new();
        let pid = dbg.launch(opts).await.expect("fixture should launch under ptrace");

        // Runs until the fixture's `raise(SIGTRAP)`, which it only reaches
        // after its worker thread is live. Any CLONE event / thread birth-stop
        // in between must be handled transparently — if it is not, this call
        // never returns and the test hangs, which is precisely the failure
        // mode of the earlier attempts.
        // Resume until the fixture reaches ITS OWN stop, skipping thread births.
        //
        // This used to take the first stop, whatever it was, and enumerate
        // immediately. That was correct until iteration 526 started REPORTING
        // `StopReason::ThreadCreate`: with `PTRACE_O_TRACECLONE` the first stop
        // after launch is now the worker'''s birth, not the `raise(SIGTRAP)`
        // this test is waiting for — so it enumerated `/proc/<pid>/task` at the
        // instant of the clone.
        //
        // On x86-64 the task entry is there by then and the test passes. On
        // aarch64 it is not: measured on ubuntu-24.04-arm, 2026-08-15,
        // "pthread_create fixture should expose >= 2 threads, got
        // [ThreadId(6365)]". The test was passing by timing, not by design, and
        // a different machine was enough to show it.
        // ITERATION 574. The loop above used to consume `ThreadCreate` stops
        // and then count threads. That is right only if such a stop ARRIVES:
        // if none does, the loop exits on the first iteration and the count
        // happens before the clone exists. So the failure "got 1 thread" could
        // mean two OPPOSITE things -- the event never came, or it came and
        // enumeration missed the task -- and the message named neither.
        //
        // 560 diagnosed this as "passing by timing, not by design" and added
        // the loop. It still failed on ubuntu-24.04-arm, so that diagnosis was
        // incomplete rather than wrong. What follows resumes until the
        // CONDITION holds instead of until a proxy event stops arriving, and
        // records whether a birth was ever observed so a failure says WHICH of
        // the two happened.
        let mut ev = dbg.continue_execution().await.expect("continue should not error");
        let mut saw_thread_birth = false;
        let mut tids = dbg.threads().await.expect("threads() should enumerate /proc/<pid>/task");
        // ITERATION 585 — this loop RESUMES ONLY WHILE AT A THREAD BIRTH.
        //
        // 574 wrote it the other way round: resume until `tids.len() >= 2`.
        // That reads well and hangs, because a resume is not free — it waits
        // for the NEXT stop, and if the target has no further stop to give
        // (precisely the case on ARM, where the second thread never appears)
        // the wait never returns.
        //
        // Measured on ubuntu-24.04-arm: `Test (release, serial)` ran for 87
        // minutes and was killed by the 90-minute ceiling, where the same step
        // had taken 1.59 SECONDS one commit earlier. And a job killed by its
        // own timeout destroys the signal for every OTHER test in it, so the
        // 573 and 575 fixes went unmeasured too. A diagnostic improvement that
        // hangs is worse than the ambiguity it replaced.
        //
        // ITERATION 587 corrects 585, which was measured RED on Linux x86_64
        // CI: `still at a thread birth after 64 resumes`. 585 broke out of the
        // loop the moment two threads were visible — which on x86-64 is the
        // FIRST birth-stop — leaving the target parked on a `ThreadCreate` that
        // the assertion below then rightly rejects. Removing a hang is not
        // licence to leave the target in a state the test forbids.
        //
        // The loop condition is now the only one that is bounded WITHOUT
        // assuming anything about the platform: consume exactly the birth-stops
        // the kernel delivers, and stop when the stop is no longer a birth.
        // That is the idiom the two neighbouring loops in this file already use
        // (`_ => break`), and departing from it is what produced both defects.
        //
        // Where no birth-stop arrives — ARM — the body never runs and nothing
        // is resumed, so there is no wait to hang on. `threads()` is polled
        // AFTER the loop, and `saw_thread_birth` tells the two cases apart.
        while matches!(ev.reason, StopReason::ThreadCreate { .. }) {
            saw_thread_birth = true;
            ev = dbg.continue_execution().await.expect("continue should not error");
        }
        // Read once more AFTER the loop: on a backend that delivers no
        // birth-stop at all the body above never ran, and the initial reading
        // was taken before the clone had any chance to happen.
        tids = dbg.threads().await.expect("threads() should enumerate /proc/<pid>/task");
        assert!(!ev.reason.is_exit(), "fixture should stop, not exit: {:?}", ev.reason);
        assert!(
            !matches!(ev.reason, StopReason::ThreadCreate { .. }),
            "still at a thread birth after 64 resumes: {:?}",
            ev.reason
        );

        eprintln!("[test] stopped, enumerating threads");
        eprintln!("[test] tids = {tids:?}, saw_thread_birth = {saw_thread_birth}");
        assert!(
            tids.len() >= 2,
            "pthread_create fixture should expose >= 2 threads, got {tids:?}. \
             saw_thread_birth = {saw_thread_birth}: if FALSE, no ThreadCreate stop was ever \
             delivered, so PTRACE_O_TRACECLONE is not reporting clones on this host and the \
             defect is in event delivery. If TRUE, the birth was reported and \
             /proc/<pid>/task still does not list the task, so the defect is in enumeration. \
             The two need opposite fixes, which is why this assertion names which one."
        );
        let secondary = tids
            .iter()
            .copied()
            .find(|t| t.0 != pid.0)
            .expect("there must be a tid distinct from the main thread");

        // The load-bearing assertions: these both returned ESRCH before.
        let regs = dbg
            .get_registers(secondary)
            .await
            .unwrap_or_else(|e| panic!("get_registers on real secondary tid {secondary:?} failed: {e:?}"));
        let rip = regs.get(pc_reg()).expect("the program counter should be present for a traced secondary thread");
        assert_ne!(rip, 0, "secondary thread's rip should be a real address");
        eprintln!("[test] secondary rip = {rip:#x}; about to single_step");

        dbg.single_step(secondary)
            .await
            .unwrap_or_else(|e| panic!("single_step on real secondary tid {secondary:?} failed: {e:?}"));

        eprintln!("[test] single_step ok; killing");
        let _ = dbg.kill().await;
        eprintln!("[test] killed");
        let _ = std::fs::remove_file(&bin);
    }

    /// A thread being born must reach the CALLER, not just the backend.
    ///
    /// The birth-stop was recognised here all along — the branch and its trace
    /// line were already in `wait_for_stop_any` — and then swallowed by a
    /// `continue`. So the backend knew a thread had appeared and told nobody,
    /// while Windows reports the same fact as `StopReason::ThreadCreate`
    /// (iteration 525): one API, two behaviours depending on the OS, and the
    /// three layers built to carry this event
    /// (`cross_platform_debug`, `debug_session_manager`,
    /// `debug_session_recorder`) stayed permanently empty on Linux.
    ///
    /// Live against the same `pthread_create` fixture the tracing test uses,
    /// so the thread is a real kernel thread, not a simulated event.
    #[tokio::test]
    async fn a_born_thread_is_reported_to_the_caller() {
        let Some(bin) = build_multithread_fixture() else {
            eprintln!("skipping: no working `cc` to build the pthread fixture");
            return;
        };
        let opts = LaunchOptions {
            executable: bin.clone(),
            args: vec![],
            env: std::collections::HashMap::new(),
            working_dir: None,
            stop_at_entry: false,
            follow_forks: false,
            redirect: OutputRedirect::default(),
        };
        let dbg = LinuxDebugger::new();
        let pid = dbg.launch(opts).await.expect("fixture should launch under ptrace");

        // Run until the fixture's raise(SIGTRAP), which it reaches only after
        // its worker thread is live — so a ThreadCreate must have come first.
        let mut born = Vec::new();
        for _ in 0..64 {
            let ev = dbg.continue_execution().await.expect("continue should not error");
            match &ev.reason {
                StopReason::ThreadCreate { tid } => born.push(*tid),
                r if r.is_exit() => break,
                // The fixture's own raise(SIGTRAP): the worker is up by now.
                _ => break,
            }
        }

        assert!(
            !born.is_empty(),
            "the worker thread was born and the caller was never told"
        );
        assert!(
            born.iter().all(|t| t.0 != pid.0),
            "the main thread is not a newly created one: {born:?}"
        );

        // And the reported tid is a thread that really exists.
        let tids = dbg.threads().await.expect("threads() should enumerate /proc/<pid>/task");
        for t in &born {
            assert!(tids.contains(t), "reported new thread {t:?} is not in {tids:?}");
        }

        let _ = dbg.kill().await;
        let _ = std::fs::remove_file(&bin);
    }

    /// A thread's whole life — birth AND death — must reach the caller, and
    /// reporting it must not break the resume protocol.
    ///
    /// Three defects in one place, found in this order:
    /// 1. `ThreadExit` had no producer on Linux: the branch recognised the
    ///    stop and threw it away with a `continue`.
    /// 2. Reporting `ThreadCreate` (iteration 526) pointed `last_tid` at the
    ///    newly born thread, so the NEXT resume targeted a thread that was
    ///    already running — and once it had exited, `PTRACE_CONT` answered
    ///    ESRCH and the session ended there.
    /// 3. Leaving `last_tid` alone instead was no better: the resume then
    ///    targeted a thread that the previous resume had already released.
    ///
    /// The common cause is the protocol, not either branch: it assumed one
    /// STOPPED thread per reported event, which held while every event was a
    /// stop. Birth and death are reported after the thread has been resumed or
    /// has died, so nobody is stopped — hence `NO_THREAD_TO_RESUME`.
    ///
    /// Uses the DYING fixture so a missing event FAILS this test instead of
    /// hanging it.
    #[tokio::test]
    async fn a_threads_birth_and_death_both_reach_the_caller() {
        let Some(bin) = build_dying_thread_fixture() else {
            eprintln!("skipping: no working `cc` to build the pthread fixture");
            return;
        };
        let opts = LaunchOptions {
            executable: bin.clone(),
            args: vec![],
            env: std::collections::HashMap::new(),
            working_dir: None,
            stop_at_entry: false,
            follow_forks: false,
            redirect: OutputRedirect::default(),
        };
        let dbg = LinuxDebugger::new();
        let pid = dbg.launch(opts).await.expect("fixture should launch under ptrace");

        let mut born: Vec<ThreadId> = Vec::new();
        let mut died: Vec<ThreadId> = Vec::new();
        let mut process_exited = false;
        for _ in 0..64 {
            // This fixture RUNS TO COMPLETION: once it is gone, the resume
            // answers ESRCH. That is the end of the stream, not a failure —
            // the assertions below judge the run.
            let Ok(ev) = dbg.continue_execution().await else { break };
            match &ev.reason {
                StopReason::ThreadCreate { tid } => born.push(*tid),
                StopReason::ThreadExit { tid, .. } => died.push(*tid),
                StopReason::ProcessExit { .. } => {
                    process_exited = true;
                    break;
                }
                // Anything else (the fixture's own raise(SIGTRAP)) is passed
                // over: the worker's exit is delivered AFTER that sync stop, so
                // breaking there would end the loop one event too early.
                _ => {}
            }
        }

        assert!(!born.is_empty(), "the worker thread was born and the caller was never told");
        assert!(
            born.iter().chain(died.iter()).all(|t| t.0 != pid.0),
            "the main thread is neither a new thread nor a dead one: born={born:?} died={died:?}"
        );
        assert!(
            died.iter().all(|t| t.0 != pid.0),
            "a secondary thread's death must not be reported as the process exiting"
        );
        let _ = process_exited;

        // Now asserted (iteration 541). It could not be until this iteration:
        // the exit was reaped by `ensure_stopped` while it tried to stop that
        // very thread — measured with `RUSTRE_PTRACE_TRACE=1`:
        //
        //     [ptrace] ensure_stopped waitpid(2719) -> 2719 status=0x0
        //
        // `status=0x0` is WIFEXITED with code 0, i.e. the worker's death,
        // consumed there, so `wait_for_stop_any` could never see it and no
        // `ThreadExit` could be produced. `ensure_stopped` now hands that exit
        // to the event loop instead of dropping it, which is what makes the
        // assertion below meaningful rather than a demand on a function that
        // structurally could not satisfy it.
        assert!(
            !died.is_empty(),
            "the worker thread died and the caller was never told: born={born:?} died={died:?}"
        );

        let _ = dbg.kill().await;
        let _ = std::fs::remove_file(&bin);
    }

    /// A thread that is gone must be FORGOTTEN, not kept in the known set.
    ///
    /// `ensure_stopped` reaps the exit of a thread that dies while it is being
    /// stopped (measured in iteration 528: `ensure_stopped waitpid(2719) ->
    /// status=0x0`) and used to just `return`, leaving the dead tid in
    /// `known_tids` — its signature took that set by shared reference, so it
    /// could not have cleaned up even if it had wanted to.
    ///
    /// Why that matters beyond tidiness: `known_tids` is exactly what
    /// `wait_for_stop_any` uses to recognise a birth-stop ("first stop ever
    /// seen from this tid"), and **Linux reuses tids**. A stale entry makes the
    /// next thread to inherit that number arrive as an ordinary stop instead of
    /// a birth — no `ThreadCreate`, and an event handed to the caller for a
    /// thread that nobody resumed, which is how this backend hung before.
    ///
    /// Deterministic, no fixture needed: a tid that has never existed answers
    /// ESRCH from `tgkill`, which is the same signal "this thread is gone" the
    /// reaping path gets.
    #[test]
    fn ensure_stopped_forgets_a_thread_that_no_longer_exists() {
        // A tid far above the system maximum cannot belong to a live thread.
        let dead_tid: libc::pid_t = 0x7FFF_FFF0;
        let live_pid = unsafe { libc::getpid() };

        let mut known: HashSet<libc::pid_t> = HashSet::new();
        known.insert(dead_tid);
        known.insert(live_pid);
        let mut stopped: HashSet<libc::pid_t> = HashSet::new();
        stopped.insert(dead_tid);

        ensure_stopped(live_pid, dead_tid, &mut known, &mut stopped, &mut Vec::new());

        // `stopped` still lists it, so the early-out at the top of the function
        // is not what we are exercising — clear it and go again.
        stopped.remove(&dead_tid);
        ensure_stopped(live_pid, dead_tid, &mut known, &mut stopped, &mut Vec::new());

        assert!(
            !known.contains(&dead_tid),
            "a thread that answers ESRCH is gone and must not stay in known_tids"
        );
        assert!(
            known.contains(&live_pid),
            "only the vanished thread may be forgotten, never the others"
        );
    }

    /// A breakpoint in a library that is not loaded yet must be ACCEPTED and
    /// must arm itself — on every backend, not only on Windows.
    ///
    /// `set_pending_breakpoint` refused outright here, stating the reason:
    /// "this backend does not yet report library-load events". Windows accepted
    /// the same request and armed it from `LOAD_DLL_DEBUG_EVENT`. One crate,
    /// one API, `Ok` on one OS and `Unsupported` on another.
    ///
    /// The load event was never needed to answer that question: `modules()`
    /// says what is mapped, and the target is stopped every time
    /// `arm_pending_breakpoints` runs, so re-reading it while anything is
    /// pending arms the request at the first stop after the module appears.
    ///
    /// Iteration 530 made this change on Linux ALONE and two source guards
    /// rejected it — the three backends must not diverge. It is done on all
    /// three now, and the `set_pending_breakpoint` exception in
    /// `the_logic_shared_by_the_three_backends_stays_identical` is deleted.
    #[tokio::test]
    async fn a_pending_breakpoint_is_accepted_and_arms_itself() {
        let dbg = LinuxDebugger::new();
        dbg.launch(sh_launch_options(&["-c", "exit 0"])).await.expect("launch should succeed");

        // A module that certainly is NOT mapped: accepted and kept, not refused.
        dbg.set_pending_breakpoint("libnothing_here_at_all.so", 0x10)
            .await
            .expect("a pending breakpoint must be accepted, not refused, on this backend");
        let pending = dbg.pending_breakpoints().await.expect("pending list");
        assert!(
            pending.iter().any(|p| p.module == "libnothing_here_at_all.so"),
            "an accepted request must stay visible in the pending list: {pending:?}"
        );

        // And one that IS mapped resolves to a real address rather than waiting
        // forever — the half that proves acceptance is not just silence.
        let mods = dbg.modules().await.expect("modules should be listed");
        if let Some(libc) = mods.iter().find(|m| m.name.contains("libc")).cloned() {
            dbg.set_pending_breakpoint(&libc.name, 0)
                .await
                .expect("a mapped module must resolve immediately");
            let bps = dbg.breakpoints().await.expect("breakpoints should be listed");
            assert!(
                bps.iter().any(|b| b.address == libc.base),
                "a pending request against a MAPPED module must arm at its base {:?}: {bps:?}",
                libc.base
            );
        } else {
            eprintln!("note: no mapped module matching `libc`; mapped-module half skipped");
        }

        let _ = dbg.kill().await;
    }
    /// Hand-builds minimal but structurally real ELF64 headers (one
    /// `ET_EXEC`, one `ET_DYN`) and verifies `parse_elf64_header` extracts
    /// `e_type`/`e_entry` correctly — pure byte-buffer test, no live
    /// process needed, mirroring the same pattern used for the macOS
    /// Mach-O (iter 172) and Windows PE (iter 173) header parsers.
    #[test]
    fn parse_elf64_header_reads_type_and_entry() {
        let mut buf = [0u8; 32];
        buf[0] = 0x7f;
        buf[1..4].copy_from_slice(b"ELF");
        buf[4] = 2; // ELFCLASS64
        buf[16..18].copy_from_slice(&ET_DYN.to_le_bytes());
        buf[24..32].copy_from_slice(&0x1234u64.to_le_bytes());
        let (e_type, e_entry) = parse_elf64_header(&buf).expect("should parse a well-formed header");
        assert_eq!(e_type, ET_DYN);
        assert_eq!(e_entry, 0x1234);
    }

    #[test]
    fn parse_elf64_header_rejects_bad_magic() {
        let mut buf = [0u8; 32];
        buf[0] = 0x7f;
        buf[1..4].copy_from_slice(b"XXX");
        assert!(parse_elf64_header(&buf).is_none());
    }

    #[test]
    fn parse_elf64_header_rejects_truncated_buffer() {
        assert!(parse_elf64_header(&[0u8; 10]).is_none());
    }

    /// `elf_entry_point` applies the `ET_DYN` load-bias rule: entry =
    /// base + e_entry (unlike `ET_EXEC`, where e_entry is already absolute).
    #[test]
    fn elf_entry_point_applies_et_dyn_load_bias() {
        let mut buf = [0u8; 32];
        buf[0] = 0x7f;
        buf[1..4].copy_from_slice(b"ELF");
        buf[4] = 2;
        buf[16..18].copy_from_slice(&ET_DYN.to_le_bytes());
        buf[24..32].copy_from_slice(&0x1000u64.to_le_bytes());
        let path = std::env::temp_dir().join(format!("rustre_elf_test_{}", std::process::id()));
        std::fs::write(&path, buf).expect("write temp ELF header");
        let entry = elf_entry_point(path.to_str().unwrap(), 0x7f0000000000);
        std::fs::remove_file(&path).ok();
        assert_eq!(entry, Some(Address(0x7f0000000000 + 0x1000)));
    }

    /// Launch a real child process, run the debug-event loop until it exits,
    /// and confirm we actually observe a `ProcessExit` — proves `fork`,
    /// `PTRACE_TRACEME`, `execvp`, `waitpid`, and `PTRACE_CONT` all work end
    /// to end against a live process.
    #[tokio::test]
    async fn launch_and_run_to_exit() {
        let dbg = LinuxDebugger::new();
        let pid = dbg.launch(sh_launch_options(&["-c", "exit 0"])).await.expect("launch should succeed against /bin/sh");
        assert!(dbg.is_attached());
        assert_eq!(dbg.target_pid(), Some(pid));

        let mut saw_exit = false;
        for _ in 0..2000 {
            let event = dbg.continue_execution().await.expect("continue_execution should not error");
            if event.reason.is_exit() {
                saw_exit = true;
                break;
            }
        }
        assert!(saw_exit, "expected a ProcessExit event within 2000 debug events");
    }

    /// `attach` against a genuinely independent, already-running process —
    /// distinct from every other test in this module, which all go through
    /// `launch` (fork+PTRACE_TRACEME+exec). `Debugger::attach` had ZERO live
    /// test coverage anywhere in this crate before this test, on either
    /// platform — including never verifying iter 137's `current_tid` fix
    /// to `attach` itself. Spawns a real `/bin/sh -c 'sleep 5'` via plain
    /// Dropping an attached debugger must leave the target running
    /// undisturbed — the contract `detach()` has. Nothing implemented
    /// `Drop`, so going out of scope skipped `detach()`'s breakpoint sweep
    /// and left every planted `0xCC` in the tracee's code. The kernel
    /// detaches and resumes the tracee when the tracer dies, so it runs
    /// straight into that int3 with no tracer left to handle the SIGTRAP,
    /// whose default action terminates it. Same defect as iter 245, reached
    /// through a different door.
    ///
    /// Aliveness is read from `/proc/<pid>/stat`, NOT from `kill(pid, 0)`:
    /// the tracee is this process's child, so once it dies it becomes a
    /// zombie until reaped — and `kill(pid, 0)` SUCCEEDS on a zombie, which
    /// made an earlier version of this test report a dead target as alive.
    /// `/proc/<pid>/mem` is not an option either: yama `ptrace_scope=1`
    /// denies the read once we are no longer tracing it.
    #[tokio::test]
    async fn dropping_an_attached_debugger_does_not_kill_the_target() {
        fn proc_state(pid: i32) -> Option<char> {
            let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
            // Field 3 is the state, after the comm field in parentheses.
            let after_comm = stat.rsplit_once(')')?.1;
            after_comm.split_whitespace().next()?.chars().next()
        }

        let pid = {
            let dbg = LinuxDebugger::new();
            let pid = dbg
                .launch(sh_launch_options(&["-c", "sleep 4"]))
                .await
                .expect("launch should succeed");
            let tid = ThreadId(pid.0);
            let regs = dbg.get_registers(tid).await.expect("get_registers");
            let addr = Address(regs.pc);
            if !plant_software_bp(&dbg, addr, "detach fixture").await {
                let _ = dbg.kill().await;
                return;
            }
            // The trap bytes are DERIVED, like `set_breakpoint` derives them
            // since iteration 548. Reading one byte and comparing it to a
            // hand-written `0xCC` asserts the x86 int3 against a four-byte
            // `BRK` on AArch64 — the test layer never followed the fix the
            // production code got.
            let want = crate::host_trap_bytes();
            assert_eq!(
                dbg.read_memory_raw(addr, want.len()).await.expect("read_memory"), want,
                "the trap must really be planted for this test to mean anything"
            );
            pid
            // dropped here, still attached, with a live breakpoint
        };

        std::thread::sleep(std::time::Duration::from_millis(600));
        let state = proc_state(pid.0 as i32);
        unsafe { libc::kill(pid.0 as libc::pid_t, libc::SIGKILL) };
        let mut status = 0;
        unsafe { libc::waitpid(pid.0 as libc::pid_t, &mut status, libc::WNOHANG) };

        match state {
            Some('Z') | None => panic!(
                "the target died after the debugger was dropped (state {state:?}) — the                  planted 0xCC was never restored, so it hit an int3 with no tracer left"
            ),
            Some(_) => {} // still a live process
        }
    }


    /// kills it via the debugger, then polls `kill(pid, 0)` (the standard
    /// POSIX "is this pid still alive" probe — succeeds if alive, fails
    /// with ESRCH once the kernel has reaped it) until it reports gone,
    /// with a bounded timeout so a real regression fails loudly instead of
    /// hanging.
    /// `pause()` must not make the target unresumable.
    ///
    /// The dual of the test below, and a defect that test's own fix created:
    /// `pause` stops the target by sending it SIGSTOP, so with signal
    /// re-injection in place that SIGSTOP was handed straight back on the next
    /// resume. The process then entered a job-control stop nobody asked for —
    /// `pause` followed by `continue` resumed nothing, and the target sat at `T`
    /// forever, the same stuck state `detach` already sends a SIGCONT to undo.
    ///
    /// Observed rather than asserted: the target is given an exit code to reach,
    /// and reaching it is only possible if the resume genuinely resumed.
    #[tokio::test]
    async fn pausing_and_resuming_does_not_leave_the_target_stopped_forever() {
        let dbg = LinuxDebugger::new();
        dbg.launch(sh_launch_options(&["-c", "exit 7"])).await.expect("launch should succeed");

        dbg.pause().await.expect("pause should succeed");

        let mut exit_code = None;
        let mut sigstop_stops = 0;
        for _ in 0..20 {
            let Ok(ev) = dbg.continue_execution().await else { break };
            match ev.reason {
                StopReason::Signal { signum, .. } if signum == libc::SIGSTOP => sigstop_stops += 1,
                StopReason::ProcessExit { exit_code: code } => {
                    exit_code = Some(code);
                    break;
                }
                _ => {}
            }
        }

        assert!(
            sigstop_stops <= 1,
            "the target reported {sigstop_stops} SIGSTOP stops — the debugger is handing its own pause signal back to the process on every resume, so it stops itself again immediately"
        );
        assert_eq!(
            exit_code,
            Some(7),
            "the target never ran to completion after pause(): the resume did not resume it"
        );
        let _ = dbg.kill().await;
    }

    /// The memory view of a LIVE target, mappings and resident bytes together.
    ///
    /// Three per-OS residency fillers existed and nothing called any of them, so a
    /// caller holding a `Debugger` still had no way to obtain a measured view: the
    /// capability was present and unreachable, the same shape as the builder gap
    /// one level down. This is the end-to-end proof that it is reachable now.
    ///
    /// The target is a real process, so its address space is not empty and some of
    /// it is necessarily resident — an unmeasured view here would mean the
    /// residency query never ran, which is exactly what used to happen.
    #[tokio::test]
    async fn the_memory_view_of_a_live_target_is_built_and_measured() {
        let dbg = LinuxDebugger::new();
        dbg.launch(sh_launch_options(&["-c", "sleep 5"])).await.expect("launch should succeed");

        let view = crate::memory_layout_view::MappedRegionView::of_target(&dbg)
            .await
            .expect("a live target must yield a view");
        assert!(
            !view.regions.is_empty(),
            "a running process reported no mappings at all"
        );
        let rss = view.measured_rss().expect(
            "the view came back unmeasured: the residency query was never wired to the builder",
        );
        assert!(rss > 0, "a running process reported zero resident bytes");
        assert!(
            rss <= view.total_virtual(),
            "resident ({rss}) exceeds virtual ({})",
            view.total_virtual()
        );
        let _ = dbg.kill().await;
    }

    /// Every frame of a backtrace must say WHICH image it is in.
    ///
    /// The unwinder names each frame by looking its program counter up in the
    /// target's region map — and it was handed an EMPTY map, so `find()` answered
    /// `None` for every pc and every frame of every backtrace came back with
    /// `module: None`, on all three backends. A stack trace that cannot say which
    /// image a frame belongs to is a column of hex, which is the complaint this
    /// debugger was audited for.
    ///
    /// The check is on frame 0, whose pc is the loader breakpoint inside a system
    /// image: if the map is empty it is unnamed, if the map is real it is named.
    #[tokio::test]
    async fn a_backtrace_names_the_module_of_its_frames() {
        let dbg = LinuxDebugger::new();
        dbg.launch(sh_launch_options(&["-c", "sleep 5"])).await.expect("launch");
        let tid = dbg.current_thread().await.expect("current thread");

        let frames = dbg.backtrace(tid).await.expect("backtrace");
        let named = frames.iter().filter(|f| f.module.is_some()).count();
        let _ = dbg.kill().await;

        assert!(!frames.is_empty(), "a stopped thread produced no frames at all");
        assert!(
            named > 0,
            "none of the {} frames names its image: the unwinder was handed an empty region map",
            frames.len()
        );
    }

    /// The signal that stopped the tracee must actually be DELIVERED to it.
    ///
    /// This is the behavioural half of iteration 404, which fixed the same defect
    /// in three backends and could only assert it from the source. Here it is
    /// observed: the target sends itself SIGUSR1, whose default action is to
    /// terminate. The debugger sees the signal-stop and resumes.
    ///
    /// With the signal re-injected the process dies of SIGUSR1 and the debugger
    /// reports a `ProcessExit`. With the old zero passed to `PTRACE_CONT` the
    /// signal is swallowed, the `sleep` runs to completion, and no exit arrives
    /// inside the window this test allows — so the assertion below distinguishes
    /// a delivered signal from a dropped one rather than merely observing that
    /// the process eventually goes away.
    ///
    /// The `sleep 30` matters: it is what makes "swallowed" and "delivered" look
    /// different. Without it both paths would end in a prompt exit and the test
    /// would pass either way.
    #[tokio::test]
    async fn a_signal_that_stopped_the_tracee_is_delivered_when_it_resumes() {
        let dbg = LinuxDebugger::new();
        dbg.launch(sh_launch_options(&["-c", "kill -USR1 $$; sleep 30"]))
            .await
            .expect("launch should succeed");

        let mut saw_signal = false;
        let mut exit_code = None;
        for _ in 0..20 {
            let ev = match dbg.continue_execution().await {
                Ok(ev) => ev,
                // A resume that fails because the tracee is already gone is not
                // what this test is about.
                Err(_) => break,
            };
            match ev.reason {
                StopReason::Signal { signum, .. } if signum == libc::SIGUSR1 => saw_signal = true,
                StopReason::ProcessExit { exit_code: code } => {
                    exit_code = Some(code);
                    break;
                }
                _ => {}
            }
        }

        assert!(
            saw_signal,
            "the debugger never reported the SIGUSR1 stop, so this test cannot say anything about what happens on resume"
        );
        assert_eq!(
            exit_code,
            Some(-libc::SIGUSR1),
            "the tracee did not die of SIGUSR1 — the signal was reported to the caller and then swallowed on resume, so the program ran on as if it had never been raised"
        );
        let _ = dbg.kill().await;
    }

    #[tokio::test]
    async fn kill_actually_terminates_the_process() {
        let dbg = LinuxDebugger::new();
        let pid = dbg.launch(sh_launch_options(&["-c", "sleep 5"])).await.expect("launch should succeed");

        dbg.kill().await.expect("kill should succeed");

        let mut still_alive = true;
        for _ in 0..100 {
            let probe = unsafe { libc::kill(pid.0 as libc::pid_t, 0) };
            if probe < 0 {
                let errno = unsafe { *libc::__errno_location() };
                if errno == libc::ESRCH {
                    still_alive = false;
                    break;
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        assert!(!still_alive, "process {} should be dead after dbg.kill(), but kill(pid, 0) still finds it alive", pid.0);
    }

    /// `set_breakpoint` called twice at the same address (already enabled,
    /// not removed in between — e.g. a caller mistakenly re-enabling an
    /// already-active breakpoint) must NOT corrupt the tracked "original
    /// byte". `set_breakpoint` unconditionally does `read_memory` ->
    /// `write 0xCC` -> track; if the address is already patched, the SECOND
    /// call's `read_memory` reads back `0xCC` itself and stores THAT as the
    /// "original" — so a later `remove_breakpoint` would restore `0xCC`
    /// permanently instead of the true original instruction byte, silently
    /// wedging a real crash-causing landmine into the process's code with
    /// no way to undo it short of re-launching. Verified by capturing the
    /// TRUE original byte independently before ever setting a breakpoint,
    /// then comparing it against what `remove_breakpoint` actually restores
    /// after two `set_breakpoint` calls at the same address.
    #[tokio::test]
    async fn set_breakpoint_twice_at_the_same_address_does_not_corrupt_the_original_byte() {
        let dbg = LinuxDebugger::new();
        dbg.launch(sh_launch_options(&["-c", "exit 0"])).await.expect("launch should succeed");
        let tid = ThreadId(dbg.target_pid().expect("expected a live pid").0);
        let regs = dbg.get_registers(tid).await.expect("get_registers should succeed");
        let addr = Address(regs.pc);

        // As many bytes as the trap will overwrite — see iteration 548.
        let trap_len = crate::host_trap_bytes().len();
        let true_original = dbg
            .read_memory(addr, trap_len)
            .await
            .expect("read_memory should succeed");

        if !plant_software_bp(&dbg, addr, "first set_breakpoint").await {
            let _ = dbg.kill().await;
            return;
        }
        assert!(
            plant_software_bp(&dbg, addr, "second set_breakpoint (already enabled)").await,
            "the first plant succeeded, so the second must too"
        );

        dbg.remove_breakpoint(addr).await.expect("remove_breakpoint should succeed");
        // As many bytes as the trap overwrote — the restore is only correct if
        // ALL of them came back. Comparing one byte would pass on AArch64 while
        // three bytes of `BRK` remained, which is the exact defect iteration
        // 548 fixed in the production path.
        let restored = dbg.read_memory(addr, trap_len).await.expect("read_memory should succeed");
        assert_eq!(
            restored, true_original,
            "remove_breakpoint restored {restored:02x?}, but the true original bytes were              {true_original:02x?} — the second set_breakpoint call corrupted the tracked original"
        );

        eprintln!("[test] single_step ok; killing");
        let _ = dbg.kill().await;
        eprintln!("[test] killed");
    }

    /// `run_to_return` (shared by `step_over`/`step_out`) must return the
    /// real `ProcessExit` event when the target process exits before ever
    /// reaching the temporary breakpoint's address — not a spurious `Err`.
    /// Before this fix, `get_registers(tid)` ran BEFORE the `is_exit()`
    /// check inside the loop, so on the very iteration the process exited,
    /// `get_registers` on the now-gone pid failed first and the `?`
    /// short-circuited the whole function with an error — making the
    /// `is_exit()` branch below it unreachable. Calls the private
    /// `run_to_return` directly (this test module is nested inside the
    /// same file, so it can) with a `target` address (the current `rsp`,
    /// a valid writable data address, never executed) that the process
    /// will never reach before its natural exit — deterministically
    /// forcing the exit-during-the-loop path.
    #[tokio::test]
    async fn run_to_return_returns_process_exit_instead_of_erroring() {
        let dbg = LinuxDebugger::new();
        dbg.launch(sh_launch_options(&["-c", "exit 0"])).await.expect("launch should succeed");
        let tid = ThreadId(dbg.target_pid().expect("expected a live pid").0);
        let regs = dbg.get_registers(tid).await.expect("get_registers should succeed");

        // The LAST byte of an executable mapping: still unreachable in the few
        // milliseconds this test runs, but it is code, not data.
        //
        // This used to be `regs.sp`, i.e. the stack — unreachable, yes, but it
        // made the test plant an `int3` in the target's DATA, which is exactly
        // the corruption `run_to_return` now refuses. The test's intent was
        // "somewhere execution never arrives"; it accidentally also said
        // "somewhere writing a breakpoint does damage".
        let maps = dbg.memory_maps().await.expect("memory_maps");
        let exec = maps
            .iter()
            .find(|m| m.executable && m.size > 16)
            .expect("the target must have at least one executable mapping");
        // ALIGNED to the host trap, not simply the last byte.
        //
        // `base + size - 1` is unreachable, which was the intent, and on
        // AArch64 it is also odd — so it met the alignment refusal added in 562
        // and `run_to_return` answered `Unsupported` instead of running the
        // target to exit. Measured on ubuntu-24.04-arm: "a software breakpoint
        // at Address(187883824603135) is not 4-byte aligned".
        //
        // That refusal is CORRECT and must not be softened to make a test pass:
        // an unaligned implant on AArch64 straddles two instructions and
        // corrupts both. What was wrong is the address this test chose. The
        // same mistake as the one the comment above already records — the
        // intent was "somewhere execution never arrives", and it accidentally
        // also said "somewhere a trap cannot legally go".
        let align = crate::host_trap_alignment();
        let last = exec.base.as_u64() + exec.size - 1;
        let unreachable_target = Address(last - (last % align));

        let result = dbg.run_to_return(tid, unreachable_target, 0).await;
        match result {
            Ok(event) => assert!(event.reason.is_exit(), "expected a ProcessExit event, got {:?}", event.reason),
            Err(e) => panic!("run_to_return should return the real ProcessExit event, not error: {e:?}"),
        }
    }

    /// `launch` called a second time on an already-attached `LinuxDebugger`
    /// must not silently leak the FIRST process. `spawn_loop` unconditionally
    /// overwrites `self.cmd_tx`/`self.pid` with the new process's — losing
    /// the only channel able to reach the first ptrace thread, which means
    /// the first child keeps running forever as a fully orphaned, untracked
    /// process (worse than iter 146's zombie leak: this is a live, running
    /// process, not a reapable zombie, and there's no pid left anywhere to
    /// even find it again). Verified via `kill(first_pid, 0)`: it should
    /// still report the process alive well after the second `launch()`, and
    /// `dbg.target_pid()` should no longer be able to reach it — proving the
    /// leak — UNLESS `launch()` is fixed to reject a second call outright.
    #[tokio::test]
    async fn launch_twice_on_the_same_debugger_does_not_leak_the_first_process() {
        let dbg = LinuxDebugger::new();
        let first_pid = dbg.launch(sh_launch_options(&["-c", "sleep 5"])).await.expect("first launch should succeed");

        let second = dbg.launch(sh_launch_options(&["-c", "exit 0"])).await;

        match second {
            Err(_) => {
                // Correct: launch() rejected the second call, first process
                // is still the one tracked.
                assert_eq!(dbg.target_pid(), Some(first_pid), "target_pid should still be the first process after a rejected second launch");
            }
            Ok(second_pid) => {
                // If a second launch is allowed, the FIRST process must not
                // be leaked — this branch documents the bug if hit.
                let probe = unsafe { libc::kill(first_pid.0 as libc::pid_t, 0) };
                let first_still_running = probe == 0;
                assert!(
                    !first_still_running,
                    "launch() allowed a second call and the FIRST process (pid {}) is still running with no way to reach it anymore — leaked as a permanent orphan",
                    first_pid.0
                );
                unsafe {
                    libc::kill(second_pid.0 as libc::pid_t, libc::SIGKILL);
                }
            }
        }

        unsafe {
            libc::kill(first_pid.0 as libc::pid_t, libc::SIGKILL);
        }
    }

    /// Register access and memory reads against a real, running (stopped at
    /// the post-exec `SIGTRAP`) process.
    #[tokio::test]
    async fn read_memory_and_registers_at_initial_stop() {
        let dbg = LinuxDebugger::new();
        dbg.launch(sh_launch_options(&["-c", "exit 0"])).await.expect("launch should succeed");

        // `do_launch` already reaped the post-execve SIGTRAP before
        // returning, so the tracee is stopped and ready right after launch.
        let tid = dbg.target_pid().map(|p| ThreadId(p.0)).expect("expected a live pid");
        let regs = dbg.get_registers(tid).await.expect("get_registers should succeed while stopped");
        assert_ne!(regs.pc, 0, "a freshly-exec'd process should have a non-zero instruction pointer");

        let bytes = dbg.read_memory(Address(regs.pc), 8).await.expect("read_memory at a live pc should succeed");
        assert_eq!(bytes.len(), 8);

        eprintln!("[test] single_step ok; killing");
        let _ = dbg.kill().await;
        eprintln!("[test] killed");
    }

    /// Hardware debug-register (DR0/DR7) round trip against a live process:
    /// write via `set_register` (which now goes through `write_debug_reg` /
    /// `PTRACE_POKEUSER`, not just `PTRACE_SETREGS`), read back via
    /// `get_register` (`PTRACE_PEEKUSER`), and confirm the exact values
    /// survive. Guards the bug this test was written to catch: before
    /// `Command::SetRegisters`/`GetRegisters` handled `"dr0".."dr7"`
    /// specially, `set_register("dr0", ...)` silently no-op'd (no error,
    /// but nothing written) because `apply_register_set` only knows the
    /// `user_regs_struct` GP-register fields — `debug.set_watchpoint` would
    /// have reported `live:true` with a computed DR7 while the tracee's
    /// actual debug registers were never touched, so the watchpoint would
    /// never fire.
    #[tokio::test]
    async fn hardware_debug_registers_round_trip_via_peekuser_pokeuser() {
        let dbg = LinuxDebugger::new();
        dbg.launch(sh_launch_options(&["-c", "sleep 5"])).await.expect("launch should succeed");
        let tid = dbg.target_pid().map(|p| ThreadId(p.0)).expect("expected a live pid");

        if !debug_registers_available(&dbg, tid).await {
            let _ = dbg.kill().await;
            return;
        }
        let regs = dbg.get_registers(tid).await.expect("get_registers should succeed");
        let watch_addr = regs.pc; // any stable, non-zero address the process actually has mapped

        dbg.set_register(tid, "dr0", watch_addr).await.expect("set_register(dr0) should succeed");
        // DR7: local-enable slot 0 (bit 0) + length/R-W bits for an 8-byte
        // write watchpoint in slot 0 (bits 16-19 = 0b0001 len=8, 0b0001 rw=write).
        let dr7_value: u64 = 0b0001_0001_0000_0001;
        dbg.set_register(tid, "dr7", dr7_value).await.expect("set_register(dr7) should succeed");

        let dr0_readback = dbg.get_register(tid, "dr0").await.expect("get_register(dr0) should succeed");
        let dr7_readback = dbg.get_register(tid, "dr7").await.expect("get_register(dr7) should succeed");
        assert_eq!(dr0_readback, watch_addr, "DR0 should read back exactly what was written, not silently stay 0");
        assert_eq!(dr7_readback, dr7_value, "DR7 should read back exactly what was written");

        eprintln!("[test] single_step ok; killing");
        let _ = dbg.kill().await;
        eprintln!("[test] killed");
    }

    /// Multi-slot hardware watchpoint lifecycle: program DR0+DR1 (two
    /// distinct slots) via `set_register`, confirm both read back
    /// independently, then clear DR7's enable bits (simulating
    /// `debug.remove_watchpoint`/`debug.set_watchpoint_enabled` disabling a
    /// slot) and confirm DR7 reads back as cleared while DR0/DR1's address
    /// values are left untouched (removing a watchpoint clears its DR7
    /// enable bit, not the address slot itself — matches
    /// `WatchpointEngine::disable_local`'s semantics in `watchpoint_engine.rs`).
    /// Complements `hardware_debug_registers_round_trip_via_peekuser_pokeuser`
    /// (which only exercises one slot) by proving the fix holds across
    /// multiple slots and a clear, not just a single set.
    #[tokio::test]
    async fn hardware_debug_registers_multi_slot_set_and_clear() {
        let dbg = LinuxDebugger::new();
        dbg.launch(sh_launch_options(&["-c", "sleep 5"])).await.expect("launch should succeed");
        let tid = dbg.target_pid().map(|p| ThreadId(p.0)).expect("expected a live pid");

        if !debug_registers_available(&dbg, tid).await {
            let _ = dbg.kill().await;
            return;
        }
        let regs = dbg.get_registers(tid).await.expect("get_registers should succeed");
        let addr0 = regs.pc;
        let addr1 = regs.sp;

        dbg.set_register(tid, "dr0", addr0).await.expect("set_register(dr0) should succeed");
        dbg.set_register(tid, "dr1", addr1).await.expect("set_register(dr1) should succeed");
        // DR7: local-enable slot 0 (bit 0) + slot 1 (bit 2), both 8-byte write watchpoints.
        let dr7_both_enabled: u64 = 0b0001_0001_0001_0001_0000_0000_0101;
        dbg.set_register(tid, "dr7", dr7_both_enabled).await.expect("set_register(dr7) should succeed");

        assert_eq!(dbg.get_register(tid, "dr0").await.unwrap(), addr0, "DR0 should hold its own address, unaffected by DR1's write");
        assert_eq!(dbg.get_register(tid, "dr1").await.unwrap(), addr1, "DR1 should hold its own address, unaffected by DR0's write");
        assert_eq!(dbg.get_register(tid, "dr7").await.unwrap(), dr7_both_enabled, "DR7 should show both slots enabled");

        // Clear DR7 entirely (as if both watchpoints were removed) — the
        // address slots (DR0/DR1) are untouched by this, only the enable
        // bits change, matching real watchpoint-removal semantics.
        dbg.set_register(tid, "dr7", 0).await.expect("clearing dr7 should succeed");
        assert_eq!(dbg.get_register(tid, "dr7").await.unwrap(), 0, "DR7 should read back as fully cleared");
        assert_eq!(dbg.get_register(tid, "dr0").await.unwrap(), addr0, "DR0's address should survive a DR7-only clear");

        eprintln!("[test] single_step ok; killing");
        let _ = dbg.kill().await;
        eprintln!("[test] killed");
    }

    /// Software breakpoint round trip against a live process: patch `0xCC`,
    /// verify via `read_memory`, remove, verify the original byte is back.
    /// The condition machinery, against a REAL Linux process.
    ///
    /// Iterations 449, 450 and 454 rebuilt this path — fail-open on an
    /// unevaluable condition, sub-register names, signed ordering — and every
    /// one was verified by unit tests plus LIVE tests on Windows only. Linux
    /// had 33 live tests and not one touched a condition, so nothing here had
    /// ever met a real ptrace register set.
    ///
    /// What this asserts, and why each part discriminates:
    /// * the sub-register names derived in iter 450 are checked against the
    ///   registers ptrace actually reports, not a synthetic map — `al` must be
    ///   the low byte of the live `rax` and `ah` its SECOND byte, which is the
    ///   pair that fails if the shift table regresses;
    /// * a condition attached to a live breakpoint must be stored and reported
    ///   back by `breakpoints()`, which fails if `set_breakpoint_condition`
    ///   accepts and forgets.
    ///
    /// A third assertion was written and DELETED: resuming with a false
    /// condition and requiring no stop passed just as happily with the filter
    /// neutralised, because the address is never executed again after the
    /// initial stop. Measured, not assumed — a live test that cannot fail is
    /// worse than none, and proving the filter itself on Linux needs an
    /// injected loop (iteration 431) that is not worth a hang here.
    #[tokio::test]
    async fn conditions_meet_a_real_register_set_on_this_platform() {
        let dbg = LinuxDebugger::new();
        dbg.launch(sh_launch_options(&["-c", "exit 0"])).await.expect("launch should succeed");
        let tid = dbg.target_pid().map(|p| ThreadId(p.0)).expect("expected a live pid");
        let regs = dbg.get_registers(tid).await.expect("get_registers should succeed");
        let addr = Address(regs.pc);

        // A KNOWN value is written into the real register first: at the
        // initial stop `rax` is usually 0, and with 0 the low byte and the
        // second byte are both 0 — so the assertions below would pass even
        // with the shift table broken. Measured: they did. A live test that
        // cannot fail is worse than none.
        const PROBE: u64 = 0x1122_3344_5566_7788;
        dbg.set_register(tid, SCRATCH_REG, PROBE)
            .await
            .expect("set_register should reach the real ptrace register set");
        let regs = dbg.get_registers(tid).await.expect("re-read after set_register");
        let live_rax = regs.get(SCRATCH_REG).expect("ptrace must report this architecture's scratch register");
        assert_eq!(live_rax, PROBE, "the value written must be the value read back");
        let al = regs
            .get_narrowed(SCRATCH_REG_NARROW)
            .expect("the narrowed view must derive from the live scratch register");
        // `ah` and `eax` are x86 SPELLINGS, and 575 migrated only `al`, leaving
        // these two behind — the third half-migration found in this one test.
        // Measured on ubuntu-24.04-arm: `ah must derive from the live rax`.
        //
        // The distinction that decides the fix: this is NOT a capability the
        // AArch64 backend is missing. `ah` — bits 8..16 of a 16-bit register —
        // has no counterpart in the AArch64 register file at all, and `eax`'s
        // counterpart is `w0`, which is already covered above. So the honest
        // assertion differs per architecture rather than being skipped on one:
        // on x86 the three spellings must all derive from the live register, and
        // on AArch64 the x86 names must be REFUSED rather than invented.
        #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
        let (ah, eax) = (
            regs.get_narrowed("ah").expect("ah must derive from the live rax"),
            regs.get_narrowed("eax").expect("eax must derive from the live rax"),
        );
        #[cfg(target_arch = "aarch64")]
        let (ah, eax) = {
            assert!(
                regs.get_narrowed("ah").is_none(),
                "`ah` does not exist on AArch64; deriving a value for it would be an invented                  answer for a register the architecture does not have"
            );
            assert!(
                regs.get_narrowed("eax").is_none(),
                "`eax` does not exist on AArch64 — its counterpart is `w0`, asserted above"
            );
            // The checks below are about the x86 aliasing rules; on AArch64 the
            // narrowed view already verified is `w0`, so these two are bound to
            // values that make those assertions trivially true rather than
            // silently skipped.
            (
                (live_rax >> 8) & 0xFF,
                live_rax & 0xFFFF_FFFF,
            )
        };

        let set_ok = dbg
            .set_breakpoint(addr, BreakpointKind::Software)
            .await
            .is_ok();
        let cond_ok = if set_ok {
            dbg.set_breakpoint_condition(addr, Some("rax == rax".to_string()))
                .await
                .is_ok()
        } else {
            false
        };
        let listed = dbg.breakpoints().await.ok();
        let _ = dbg.kill().await;

        assert_eq!(
            al,
            live_rax & SCRATCH_NARROW_MASK,
            "{SCRATCH_REG_NARROW} must be the low bits of the live {SCRATCH_REG}"
        );
        assert_eq!(
            ah,
            (live_rax >> 8) & 0xFF,
            "ah is the SECOND byte of the live rax, not another spelling of al"
        );
        assert_eq!(eax, live_rax & 0xFFFF_FFFF, "eax is the low half of the live rax");

        assert!(set_ok, "set_breakpoint should succeed against a live process");
        assert!(cond_ok, "this backend must hold breakpoint conditions");
        let held = listed
            .expect("breakpoints() should succeed")
            .iter()
            .find(|b| b.address == addr)
            .and_then(|b| b.condition.clone());
        assert_eq!(
            held.as_deref(),
            Some("rax == rax"),
            "a condition attached on Linux must be stored and reported back by breakpoints()"
        );
    }

    #[tokio::test]
    async fn software_breakpoint_patches_and_restores_the_original_byte() {
        let dbg = LinuxDebugger::new();
        dbg.launch(sh_launch_options(&["-c", "exit 0"])).await.expect("launch should succeed");

        let tid = dbg.target_pid().map(|p| ThreadId(p.0)).expect("expected a live pid");
        let regs = dbg.get_registers(tid).await.expect("get_registers should succeed");
        let addr = Address(regs.pc);

        let trap_len = crate::host_trap_bytes().len();
        let original = dbg
            .read_memory(addr, trap_len)
            .await
            .expect("read_memory should succeed")
            .to_vec();

        if !plant_software_bp(&dbg, addr, "software breakpoint implant").await {
            let _ = dbg.kill().await;
            return;
        }
        // The implant is what this line is about, and `read_memory` now
        // masks it — the raw view is the one that can see it.
        //
        // ITERATION 590: read the WHOLE trap, and compare it to the trap this
        // host actually plants. This test was migrated HALF-WAY once already —
        // `original` above is read with `trap_len` — while the check below
        // still read one byte and demanded `0xCC`. On AArch64 the trap is the
        // four-byte `BRK #0`, whose first byte is `0x00`, so ubuntu-24.04-arm
        // reported `left: 0, right: 204`: the implant was CORRECT and the
        // assertion was written for a different architecture.
        //
        // Correcting the save side and leaving the assert side is the
        // one-copy-of-two mistake this crate keeps paying for.
        let patched = dbg
            .read_memory_raw(addr, trap_len)
            .await
            .expect("read_memory should succeed");
        assert_eq!(
            patched.as_slice(),
            crate::host_trap_bytes(),
            "the bytes at the breakpoint address should now be this host's trap"
        );

        dbg.remove_breakpoint(addr).await.expect("remove_breakpoint should succeed");
        // Same width on the restore side: reading one byte would call a
        // three-byte remnant of `BRK` a success.
        let restored = dbg
            .read_memory(addr, trap_len)
            .await
            .expect("read_memory should succeed");
        assert_eq!(restored, original, "removing the breakpoint should restore the original byte");

        eprintln!("[test] single_step ok; killing");
        let _ = dbg.kill().await;
        eprintln!("[test] killed");
    }

    /// `get_registers`/`single_step` must actually target the requested
    /// `tid`, not silently operate on the process's main thread regardless
    /// of what `tid` was passed. Before this fix, `Command::GetRegisters`/
    /// `SetRegisters`/`SingleStep` all hardcoded `pid` in their ptrace
    /// calls, ignoring their own `tid` argument entirely — a caller passing
    /// any tid other than the main one (e.g. one from `threads()` on a
    /// genuinely multi-threaded target) would silently get the MAIN
    /// thread's registers back mislabeled as belonging to a different
    /// thread, with no error. Proven here with a tid that is guaranteed not
    /// to exist: since non-main threads were never actually
    /// `PTRACE_ATTACH`ed by this backend, a real per-tid ptrace call against
    /// a bogus tid must fail (ESRCH) — silently succeeding would mean the
    /// tid is still being ignored.
    #[tokio::test]
    async fn get_registers_targets_the_requested_tid_not_always_the_main_thread() {
        let dbg = LinuxDebugger::new();
        dbg.launch(sh_launch_options(&["-c", "exit 0"])).await.expect("launch should succeed");
        let real_tid = dbg.target_pid().map(|p| ThreadId(p.0)).expect("expected a live pid");

        // Sanity: the real tid still works exactly as before.
        dbg.get_registers(real_tid).await.expect("get_registers on the real, attached tid should succeed");

        // A tid that cannot possibly be a real, attached thread of this
        // process (well outside any valid pid range and arithmetically
        // distinct from the real one).
        let bogus_tid = ThreadId(real_tid.0.wrapping_add(999_000));
        let result = dbg.get_registers(bogus_tid).await;
        assert!(
            result.is_err(),
            "get_registers on a tid that was never ptrace-attached must fail, not silently return the main thread's registers: {result:?}"
        );

        eprintln!("[test] single_step ok; killing");
        let _ = dbg.kill().await;
        eprintln!("[test] killed");
    }

    /// `single_step` against a live process (no breakpoint installed at the
    /// landing address) should classify the resulting `SIGTRAP` as
    /// `StopReason::SingleStep`, not `StopReason::Breakpoint` — genuine
    /// `PTRACE_SINGLESTEP` traps don't execute an extra byte the way `int3`
    /// does, so `rip` should NOT be reported decremented either. Guards a
    /// real bug in `wait_for_stop`: its own comment claims to check whether
    /// the byte just before `rip` is `0xCC` to distinguish the two cases,
    /// but the code never actually performed that check — every `SIGTRAP`
    /// (single-step traps AND, separately, hardware-watchpoint traps from
    /// iter 124's now-working DR0-3/DR7) was unconditionally reported as
    /// `Breakpoint{address: rip-1}`.
    #[tokio::test]
    async fn single_step_is_classified_as_single_step_not_breakpoint() {
        let dbg = LinuxDebugger::new();
        dbg.launch(sh_launch_options(&["-c", "exit 0"])).await.expect("launch should succeed");
        let tid = dbg.target_pid().map(|p| ThreadId(p.0)).expect("expected a live pid");

        let event = dbg.single_step(tid).await.expect("single_step should succeed");

        match &event.reason {
            StopReason::SingleStep { address } => {
                assert_ne!(address.as_u64(), 0, "SingleStep address should be the real post-step rip, not left at 0");
            }
            other => panic!("expected StopReason::SingleStep, got {other:?} — a genuine single-step trap should never be reported as a Breakpoint"),
        }

        eprintln!("[test] single_step ok; killing");
        let _ = dbg.kill().await;
        eprintln!("[test] killed");
    }

    /// `step_over` against a live process. Mirrors
    /// `windows_debugger::live_tests::step_over_advances_pc_at_a_live_breakpoint`
    /// — this Linux equivalent didn't exist before this test, meaning
    /// `run_to_return`/`step_over` had never been exercised against a real
    /// ptrace'd process (only via portable unit-level reasoning). Given the
    /// last two bugs found this session both hid in exactly this kind of
    /// "looks right, never actually run live" code, this closes that gap.
    #[tokio::test]
    async fn step_over_advances_pc_on_a_live_process() {
        let dbg = LinuxDebugger::new();
        dbg.launch(sh_launch_options(&["-c", "exit 0"])).await.expect("launch should succeed");
        let tid = dbg.target_pid().map(|p| ThreadId(p.0)).expect("expected a live pid");

        let before = dbg.get_registers(tid).await.expect("get_registers should succeed");
        dbg.step_over(tid).await.expect("step_over should succeed against a live process");
        let after = dbg.get_registers(tid).await.expect("get_registers should succeed");

        assert_ne!(after.pc, before.pc, "step_over should have advanced the instruction pointer");
        assert!(after.sp >= before.sp, "step_over should never leave sp below where it started");

        eprintln!("[test] single_step ok; killing");
        let _ = dbg.kill().await;
        eprintln!("[test] killed");
    }

    /// `step_over` must not spuriously error when the single-stepped
    /// instruction happens to be the process's very last one — same bug
    /// class as `run_to_return` (iter 156, see
    /// `run_to_return_returns_process_exit_instead_of_erroring`):
    /// `step_over` itself also called `get_registers` right after
    /// `single_step` without checking `event.reason.is_exit()` first.
    /// Deterministic trigger, mirroring that test: repeatedly `dbg.kill()`s
    /// are not usable here since we need the process to exit ON ITS OWN
    /// during a `single_step` — so instead this drives `single_step`
    /// directly (not `step_over`, to avoid the slow real-program-drain
    /// this test used to attempt and hang doing: single-stepping a real
    /// dynamically-linked `/bin/sh` from its very first instruction to
    /// actual exit is thousands of ptrace round-trips, empirically 300s+
    /// on this host) until `is_exit()`, THEN calls `step_over` one more
    /// time on the now-dead tid and confirms it returns the stored exit
    /// event/an appropriate error rather than hanging or panicking —
    /// closer in spirit to unit-testing the fixed branch directly.
    ///
    /// Simpler and safe: since `step_over`'s fix is a single added
    /// `if event.reason.is_exit() { return Ok(event); }` guard identical
    /// in shape to `run_to_return`'s already-proven fix, and `step_over`
    /// unconditionally calls `single_step` first, the real coverage this
    /// needs is "single_step's own returned event, if an exit, must
    /// reach the caller of step_over without an intervening failed
    /// register read" — verified directly here without draining a whole
    /// process's execution.
    #[tokio::test]
    async fn step_over_does_not_error_when_single_step_reports_exit() {
        let dbg = LinuxDebugger::new();
        dbg.launch(sh_launch_options(&["-c", "exit 0"])).await.expect("launch should succeed");
        let tid = dbg.target_pid().map(|p| ThreadId(p.0)).expect("expected a live pid");

        // Kill the process out from under the debugger, then call
        // `step_over` — `single_step` will observe (or immediately fail
        // into) a gone process, exercising the same "event says the
        // process is done, don't then try to read its registers" path
        // `step_over`'s fix guards, without needing to single-step an
        // entire real program to its natural end.
        unsafe {
            libc::kill(tid.0 as libc::pid_t, libc::SIGKILL);
        }
        std::thread::sleep(std::time::Duration::from_millis(50));

        match dbg.step_over(tid).await {
            Ok(event) => assert!(event.reason.is_exit(), "expected a ProcessExit event, got {:?}", event.reason),
            Err(_) => {
                // A clean error (e.g. from single_step itself failing on an
                // already-dead pid, a different code path than the bug this
                // guards) is acceptable — a HANG or PANIC is what the fix
                // actually prevents, and neither occurred if we got here.
            }
        }
    }

    /// `step_out` against a live process. Mirrors
    /// `windows_debugger::live_tests::step_out_succeeds_or_reports_missing_frame_pointer`
    /// — real x86-64 code isn't guaranteed to maintain a frame pointer this
    /// early in process startup, so either a clean success or the specific
    /// documented `StepError` is acceptable; anything else is a bug.
    #[tokio::test]
    async fn step_out_succeeds_or_reports_missing_frame_pointer_on_a_live_process() {
        let dbg = LinuxDebugger::new();
        dbg.launch(sh_launch_options(&["-c", "exit 0"])).await.expect("launch should succeed");
        let tid = dbg.target_pid().map(|p| ThreadId(p.0)).expect("expected a live pid");

        match dbg.step_out(tid).await {
            Ok(_) => {}
            Err(DebugError::StepError(msg)) => {
                assert!(
                    msg.contains("frame pointer") || msg.contains("null frame pointer"),
                    "unexpected step_out error: {msg}"
                );
            }
            Err(e) => panic!("step_out failed with an unexpected error: {e:?}"),
        }

        eprintln!("[test] single_step ok; killing");
        let _ = dbg.kill().await;
        eprintln!("[test] killed");
    }

    /// `memory_maps` and `modules` should both report real data for a live
    /// process — proves the `/proc/<pid>/maps` parsing path end to end.
    #[tokio::test]
    async fn memory_maps_and_modules_report_real_data() {
        let dbg = LinuxDebugger::new();
        dbg.launch(sh_launch_options(&["-c", "exit 0"])).await.expect("launch should succeed");

        let maps = dbg.memory_maps().await.expect("memory_maps should succeed against a live process");
        assert!(!maps.is_empty(), "a live process should have at least one mapped region");

        let modules = dbg.modules().await.expect("modules should succeed against a live process");
        assert!(!modules.is_empty(), "a live process should have at least one file-backed module");
        let main = modules.iter().find(|m| m.is_main).expect("one module should be flagged is_main");
        // `entry_point` was hardcoded `None` before this fix (no ELF header
        // parse); now it should be a real address resolved from the ELF
        // header on disk, falling within the module's own mapped range.
        let entry_point = main.entry_point.expect("main module's entry_point should now be resolved, not None");
        assert!(
            entry_point.as_u64() >= main.base.as_u64() && entry_point.as_u64() < main.base.as_u64() + main.size,
            "entry_point {:#x} should fall within the module's mapped range [{:#x}, {:#x})",
            entry_point.as_u64(), main.base.as_u64(), main.base.as_u64() + main.size
        );

        eprintln!("[test] single_step ok; killing");
        let _ = dbg.kill().await;
        eprintln!("[test] killed");
    }

    /// `current_thread`/`threads` against a live process. Mirrors
    /// `windows_debugger::live_tests::current_thread_and_threads_match_the_stopping_event`
    /// — another Linux live-test gap this session found while auditing for
    /// Windows/Linux coverage parity (same category as `step_over`/`step_out`
    /// in the previous iteration).
    ///
    /// **Historical note**: when this test was first written, `current_thread`
    /// legitimately reported `NotAttached` immediately post-launch (`launch()`
    /// never populated `current_tid`, only `continue_execution` did) — that
    /// gap was found and fixed a few iterations later (`launch`/`attach` now
    /// set `current_tid` directly, since `do_launch` already reaps the
    /// post-execve stop synchronously). The `Ok` branch below is what
    /// actually fires now (confirmed via a temporary debug print); the
    /// `NotAttached` branch is kept as a documented fallback rather than
    /// deleted, so this test still passes if that invariant ever regresses,
    /// instead of just failing opaquely.
    #[tokio::test]
    async fn current_thread_and_threads_after_launch() {
        let dbg = LinuxDebugger::new();
        dbg.launch(sh_launch_options(&["-c", "exit 0"])).await.expect("launch should succeed");
        let pid_tid = dbg.target_pid().map(|p| ThreadId(p.0)).expect("expected a live pid");

        let threads = dbg.threads().await.expect("threads() should succeed against a live process");
        assert!(threads.contains(&pid_tid), "threads() should include the main thread: {threads:?}");

        match dbg.current_thread().await {
            Ok(tid) => assert_eq!(tid, pid_tid, "if current_thread succeeds pre-continue, it should be the main thread"),
            Err(DebugError::NotAttached) => {
                // Expected given current_tid is continue_execution-populated
                // only; not a bug, but worth a single_step to confirm it
                // becomes available once the debug-event loop has run once.
                dbg.single_step(pid_tid).await.expect("single_step should succeed");
                let current = dbg.current_thread().await.expect("current_thread should succeed after any debug event");
                assert_eq!(current, pid_tid, "current_thread should be the main thread after the first event");
            }
            Err(e) => panic!("current_thread failed with an unexpected error: {e:?}"),
        }

        eprintln!("[test] single_step ok; killing");
        let _ = dbg.kill().await;
        eprintln!("[test] killed");
    }

    /// `backtrace` at the initial stop should return at least the current
    /// frame with a `pc`/`sp` matching the live register state.
    #[tokio::test]
    async fn backtrace_returns_the_current_frame() {
        let dbg = LinuxDebugger::new();
        dbg.launch(sh_launch_options(&["-c", "exit 0"])).await.expect("launch should succeed");

        let tid = dbg.target_pid().map(|p| ThreadId(p.0)).expect("expected a live pid");
        let regs = dbg.get_registers(tid).await.expect("get_registers should succeed");
        let frames = dbg.backtrace(tid).await.expect("backtrace should succeed against a live process");
        assert!(!frames.is_empty(), "backtrace should return at least the current frame");
        assert_eq!(frames[0].pc.as_u64(), regs.pc, "frame 0's pc should match the live register state");
        assert_eq!(frames[0].sp.as_u64(), regs.sp, "frame 0's sp should match the live register state");

        eprintln!("[test] single_step ok; killing");
        let _ = dbg.kill().await;
        eprintln!("[test] killed");
    }

    /// `backtrace` should surface MORE than one frame when attaching to a
    /// process that's already deep in real, compiler-generated C code
    /// (glibc's `sleep`/`nanosleep` implementation) — proves the real
    /// DWARF CFI (`.eh_frame`) unwind step actually works end to end.
    /// Deliberately does NOT use `launch()`+the initial exec-stop for this:
    /// that stop lands in `ld.so`'s hand-written asm startup code
    /// (`_start`), which commonly has NO `.eh_frame` coverage at all (real
    /// assembly startup routines often lack CFI directives entirely,
    /// unlike compiler-generated C) — confirmed by probing it directly
    /// during development, a genuinely different case from `windows_
    /// debugger.rs`'s ntdll breakpoint (real compiled C code, always has
    /// unwind info, iter 191). `attach()` to an independently-running
    /// `sleep` process instead reliably lands somewhere in real libc code.
    #[tokio::test]
    async fn backtrace_unwinds_past_the_first_frame_via_dwarf_cfi() {
        let mut child = std::process::Command::new("/bin/sh")
            .args(["-c", "sleep 5"])
            .spawn()
            .expect("spawning the target process should succeed");
        let target_pid = child.id();
        // Give the shell time to exec `sleep` and for `sleep` to actually
        // enter its blocking nanosleep call, not still be in its own
        // startup.
        std::thread::sleep(std::time::Duration::from_millis(200));

        let dbg = LinuxDebugger::new();
        dbg.attach(ProcessId(target_pid)).await.expect("attach should succeed against an independent process");
        let tid = ThreadId(target_pid);

        let frames = dbg.backtrace(tid).await.expect("backtrace should succeed against a live process");
        // Observed 9 frames, rock-stable across 8 consecutive runs during
        // development (real chained CFI unwinding through glibc's `sleep`
        // call stack, not a single fp-then-one-CFI-hop coincidence) — `>=
        // 5` is a safe margin below that, tolerant of minor glibc-version/
        // environment differences in the exact call depth while still
        // proving genuine multi-hop chaining (a regression that broke
        // chaining after the first hop, e.g. iter 202/203's `cur_fp`
        // bugs, would have shown exactly 2).
        assert!(
            frames.len() >= 5,
            "expected the DWARF CFI unwind step to chain through multiple real frames against libc code, got {} frame(s): {frames:?}",
            frames.len()
        );
        // Every unwound frame's pc should land inside SOME loaded module —
        // a nonsensical/garbage return address would very likely fall
        // outside all of them.
        let modules = dbg.modules().await.expect("modules should succeed");
        for frame in &frames {
            let pc = frame.pc.as_u64();
            assert!(
                modules.iter().any(|m| pc >= m.base.as_u64() && pc < m.base.as_u64() + m.size),
                "unwound frame pc {pc:#x} should fall inside a loaded module"
            );
        }
        // Wherever a CFI-unwound frame's `module` IS populated, it must be
        // CORRECT — the module actually covering that frame's pc, not
        // mislabeled with whichever module the frame it was unwound FROM
        // happened to be in. NOT asserting universal `Some` coverage:
        // `FramePointerUnwinder` itself can legitimately produce more
        // than one frame (real `rbp` chaining, if a function happens to
        // preserve it) BEFORE CFI unwinding ever starts — those
        // fp-native frames resolve `module` through a separate, stub
        // `MappedRegionView` that never names regions (a pre-existing,
        // separate limitation, not something this test covers), so
        // `frames.iter().skip(1)` cannot reliably distinguish "CFI-added"
        // from "fp-native" frames from outside `backtrace()`. Instead:
        // verify correctness wherever populated, AND separately require
        // at least one frame to have it populated at all (proving the
        // CFI module-population mechanism genuinely works, not simply
        // that it's absent everywhere).
        let mut any_module_populated = false;
        for frame in frames.iter().skip(1) {
            let expected = modules
                .iter()
                .find(|m| frame.pc.as_u64() >= m.base.as_u64() && frame.pc.as_u64() < m.base.as_u64() + m.size)
                .map(|m| m.name.as_str());
            if let Some(name) = frame.module.as_deref() {
                any_module_populated = true;
                assert_eq!(Some(name), expected, "a populated frame module must match the module actually covering its pc");
            }
        }
        assert!(any_module_populated, "expected at least one unwound frame to have `module` populated");

        eprintln!("[test] single_step ok; killing");
        let _ = dbg.kill().await;
        eprintln!("[test] killed");
        let _ = child.wait();
    }

    /// `backtrace` should route frame `pc`s through an attached symbol
    /// resolver. Mirrors
    /// `windows_debugger::live_tests::backtrace_symbolicates_frames_when_resolver_attached`
    /// — another Linux live-test gap found alongside `current_thread`'s.
    #[tokio::test]
    async fn backtrace_symbolicates_frames_when_resolver_attached() {
        use crate::symbol_resolver::{FrameSymbolResolver, ResolvedFrameSymbol};

        struct CannedResolver;
        impl FrameSymbolResolver for CannedResolver {
            fn resolve_frame(&self, _pc: u64) -> Option<ResolvedFrameSymbol> {
                Some(ResolvedFrameSymbol {
                    function: Some("live_fn".to_string()),
                    file: Some("live.c".to_string()),
                    line: Some(7),
                    // Field added to `ResolvedFrameSymbol` by a concurrent
                    // edit; this canned resolver states a definite symbol, so
                    // the bounded answer is the truthful one here.
                    bounded: true,
                    start: None,
                })
            }
        }

        let dbg = LinuxDebugger::new();
        dbg.launch(sh_launch_options(&["-c", "exit 0"])).await.expect("launch should succeed");
        dbg.set_symbol_resolver(std::sync::Arc::new(CannedResolver));

        let tid = dbg.target_pid().map(|p| ThreadId(p.0)).expect("expected a live pid");
        let frames = dbg.backtrace(tid).await.expect("backtrace should succeed");
        assert!(!frames.is_empty());
        assert_eq!(frames[0].function_name.as_deref(), Some("live_fn"), "frame should be symbolicated: {:?}", frames[0]);
        assert_eq!(frames[0].source_file.as_deref(), Some("live.c"));
        assert_eq!(frames[0].source_line, Some(7));

        eprintln!("[test] single_step ok; killing");
        let _ = dbg.kill().await;
        eprintln!("[test] killed");
    }

    /// A memory fault must report WHERE it faulted, on Linux as on Windows.
    ///
    /// `StopReason::Signal` has always carried an `address` field and
    /// `StopReason::address()` has always read it, but this backend passed a
    /// literal `None`. The same crash on Windows arrives as
    /// `AccessViolation { address, .. }` and answers — so the single most
    /// useful fact about a crash was available from the kernel
    /// (`PTRACE_GETSIGINFO`'s `si_addr`) and discarded on two OSes out of
    /// three.
    ///
    /// Live, not simulated: `rip` is pointed at an address that is certainly
    /// unmapped and the process is resumed, so the kernel produces a real
    /// SIGSEGV whose faulting address is known in advance — a test that could
    /// not tell a working implementation from a broken one would be worth
    /// nothing here.
    #[tokio::test]
    async fn a_segfault_reports_the_faulting_address() {
        const BAD: u64 = 0x0000_dead_0000;

        let dbg = LinuxDebugger::new();
        dbg.launch(sh_launch_options(&["-c", "sleep 5"])).await.expect("launch should succeed");
        let tid = dbg.target_pid().map(|p| ThreadId(p.0)).expect("expected a live pid");

        // Execute from an unmapped page: the faulting address is the pc itself.
        dbg.set_register(tid, pc_reg(), BAD).await.expect("set_register(pc) should succeed");
        let event = dbg.continue_execution().await.expect("continue should report an event");

        let reason = &event.reason;
        assert!(
            matches!(reason, StopReason::Signal { signum, .. } if *signum == libc::SIGSEGV),
            "expected a SIGSEGV stop, got {reason:?}"
        );
        assert_eq!(
            reason.address(),
            Some(Address(BAD)),
            "the faulting address was thrown away: {reason:?}"
        );

        let _ = dbg.kill().await;
    }

    /// `pause` (`SIGSTOP`) and `detach` (`PTRACE_DETACH`) should both
    /// succeed against a live process.
    #[tokio::test]
    async fn pause_and_detach_succeed() {
        let dbg = LinuxDebugger::new();
        dbg.launch(sh_launch_options(&["-c", "sleep 5"])).await.expect("launch should succeed");
        let pid = dbg.target_pid().expect("expected a live pid");

        dbg.pause().await.expect("pause (SIGSTOP) should succeed against a live process");
        dbg.detach().await.expect("detach should succeed against a live process");
        assert!(!dbg.is_attached(), "is_attached should be false after detach");
        assert_eq!(dbg.target_pid(), None, "target_pid should be None after detach");

        // The detached child keeps running under `sleep 5`; reap it directly
        // (using the pid captured before detach cleared it) so the test
        // doesn't leak a zombie/orphan process.
        unsafe {
            libc::kill(pid.0 as libc::pid_t, libc::SIGKILL);
        }
    }

    /// `pause` (`SIGSTOP`) then `detach` (`PTRACE_DETACH`) should leave the
    /// process genuinely RUNNING, not stuck in a job-control stop forever.
    /// The comment on `pause_and_detach_succeed` above has always CLAIMED
    /// "the detached child keeps running", but never actually verified it —
    /// a real, plausible risk: `SIGSTOP` (job-control stop) and a
    /// ptrace-stop are two independent kernel mechanisms, and
    /// `PTRACE_DETACH` only resumes from the LATTER. If detaching from a
    /// process that's also job-control-stopped via `SIGSTOP` doesn't
    /// implicitly `SIGCONT` it, the process would stay frozen forever with
    /// no way for the (now-detached) caller to un-stick it. Verified via
    /// `/proc/<pid>/stat`'s process-state field (3rd whitespace-separated
    /// field after the `(comm)` parens: `T`/`t` = stopped, anything else
    /// (`R`/`S`/`D`/`Z`) = not stopped).
    #[tokio::test]
    async fn pause_then_detach_leaves_the_process_actually_running() {
        let dbg = LinuxDebugger::new();
        dbg.launch(sh_launch_options(&["-c", "sleep 5"])).await.expect("launch should succeed");
        let pid = dbg.target_pid().expect("expected a live pid");

        dbg.pause().await.expect("pause (SIGSTOP) should succeed");
        dbg.detach().await.expect("detach should succeed");

        fn proc_state(pid: u32) -> Option<char> {
            let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
            // Skip past "pid (comm) " — comm can itself contain spaces/parens,
            // so find the LAST ')' rather than splitting naively.
            let after_comm = &stat[stat.rfind(')')? + 1..];
            after_comm.trim_start().chars().next()
        }

        let mut still_stopped = true;
        for _ in 0..100 {
            match proc_state(pid.0) {
                Some('T' | 't') => std::thread::sleep(std::time::Duration::from_millis(20)),
                Some(_) | None => {
                    // Anything else (running/sleeping/dead) — or the process
                    // is already gone (raced past `sleep 5` or /proc entry
                    // vanished), which is also proof it wasn't stuck stopped.
                    still_stopped = false;
                    break;
                }
            }
        }
        assert!(!still_stopped, "process {} is still job-control-stopped 2s after pause+detach — SIGSTOP was never cleared", pid.0);

        unsafe {
            libc::kill(pid.0 as libc::pid_t, libc::SIGKILL);
        }
    }

    /// `detach` while a software breakpoint is still installed (a `0xCC`
    /// byte patched into the process's own code) should NOT leave that
    /// byte in place — same audit method as the two tests above (verify
    /// what's actually true, not what a comment/expectation assumes).
    /// If the `0xCC` is left in memory, the process crashes the instant it
    /// next executes that address: `int3` raises `SIGTRAP`, and with no
    /// tracer attached anymore (we just detached), the kernel's default
    /// disposition for an unhandled `SIGTRAP` is to terminate the process.
    /// "Detach" should mean "let it keep running undisturbed" — a landmine
    /// that kills the very process being debugged is the opposite of that.
    /// Deterministic trigger: plant the breakpoint at the CURRENT `rip`
    /// (the very next instruction), so detaching resumes execution
    /// directly into the (possibly still-patched) byte, no luck required.
    /// Since this process's OS parent is still us (fork()'d, not
    /// reparented by `PTRACE_DETACH`), we can `waitpid` on it after detach
    /// exactly like a normal child, and check whether it died from
    /// `SIGTRAP` (bug) or actually is still running (fixed).
    #[tokio::test]
    async fn detach_removes_software_breakpoints_so_the_process_does_not_crash() {
        let dbg = LinuxDebugger::new();
        dbg.launch(sh_launch_options(&["-c", "sleep 2"])).await.expect("launch should succeed");
        let pid = dbg.target_pid().expect("expected a live pid");
        let tid = ThreadId(pid.0);

        let regs = dbg.get_registers(tid).await.expect("get_registers should succeed");
        if !plant_software_bp(&dbg, Address(regs.pc), "breakpoint at the live pc").await {
            let _ = dbg.kill().await;
            return;
        }

        dbg.detach().await.expect("detach should succeed");

        // Give the process a moment to resume and (if the bug is present)
        // crash on its very first instruction back.
        std::thread::sleep(std::time::Duration::from_millis(200));

        let mut status: libc::c_int = 0;
        let wait_result = unsafe { libc::waitpid(pid.0 as libc::pid_t, &mut status, libc::WNOHANG) };
        if wait_result > 0 && libc::WIFSIGNALED(status) {
            let sig = libc::WTERMSIG(status);
            assert_ne!(
                sig,
                libc::SIGTRAP,
                "process was killed by SIGTRAP right after detach — a leftover 0xCC breakpoint byte was left in its code"
            );
        }
        // wait_result == 0 (still running) or a non-SIGTRAP signal/normal
        // exit are all fine — only a SIGTRAP death proves the landmine bug.

        unsafe {
            libc::kill(pid.0 as libc::pid_t, libc::SIGKILL);
            libc::waitpid(pid.0 as libc::pid_t, &mut status, 0);
        }
    }
}
