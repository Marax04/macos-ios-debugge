//! Concrete Windows [`crate::Debugger`] backend.
//!
//! Uses the Win32 debug API (`DebugActiveProcess`/`CreateProcess` with
//! `DEBUG_PROCESS`/`WaitForDebugEvent`/`ContinueDebugEvent`/`ReadProcessMemory`/
//! `WriteProcessMemory`) directly — no sub-crate, per the 2026-07-14 audit that
//! found every `impl Debugger` in the workspace was a `MockDebugger`, leaving
//! `rustre-debug` unable to drive a real, live process on any OS.
//!
//! The Win32 debug loop (`WaitForDebugEvent`/`ContinueDebugEvent`) is
//! thread-affine: only the thread that attached/launched the process may wait
//! for or continue its events. A dedicated OS thread owns that loop and is
//! driven by a command/response channel pair so the [`crate::Debugger`] trait's
//! `async` methods can be implemented without blocking the Tokio executor.

#![cfg(windows)]

use std::collections::HashMap;
use std::ffi::CString;
use std::mem::{size_of, zeroed};
use std::sync::mpsc::{Receiver, Sender, channel};
use std::thread::JoinHandle;

use winapi::shared::minwindef::{DWORD, FALSE, TRUE};
use winapi::um::debugapi::{
    ContinueDebugEvent, DebugActiveProcess, DebugActiveProcessStop, WaitForDebugEvent,
};
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};
use winapi::um::memoryapi::{ReadProcessMemory, VirtualQueryEx, WriteProcessMemory};
use winapi::um::psapi::GetMappedFileNameW;
use winapi::um::minwinbase::{
    CREATE_PROCESS_DEBUG_EVENT, CREATE_THREAD_DEBUG_EVENT, DEBUG_EVENT, EXCEPTION_DEBUG_EVENT,
    EXIT_PROCESS_DEBUG_EVENT, EXIT_THREAD_DEBUG_EVENT, LOAD_DLL_DEBUG_EVENT,
};
use winapi::um::processthreadsapi::{
    CreateProcessA, GetThreadContext, OpenProcess, OpenThread, PROCESS_INFORMATION,
    STARTUPINFOA, SetThreadContext, TerminateProcess,
};
use winapi::um::tlhelp32::{
    CreateToolhelp32Snapshot, MODULEENTRY32W, Module32FirstW, Module32NextW, TH32CS_SNAPMODULE,
    TH32CS_SNAPMODULE32, TH32CS_SNAPTHREAD, THREADENTRY32, Thread32First, Thread32Next,
};
use winapi::um::winbase::{DEBUG_PROCESS, DebugBreakProcess};
use winapi::um::winnt::{
    CONTEXT, CONTEXT_DEBUG_REGISTERS, CONTEXT_FULL, HANDLE, MEMORY_BASIC_INFORMATION, MEM_FREE, PAGE_EXECUTE,
    PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY, PAGE_READONLY,
    PAGE_READWRITE, PAGE_WRITECOPY, PROCESS_ALL_ACCESS, PROCESS_QUERY_INFORMATION,
    PROCESS_VM_READ, THREAD_ALL_ACCESS,
};

use rustre_core::address::Address;

use crate::{
    Breakpoint, BreakpointKind, DebugError, DebugEvent, Debugger, LaunchOptions, MemoryMap,
    ModuleInfo, ProcessId, RegisterSet, StackFrame, StopReason, ThreadId,
};

const DBG_CONTINUE: DWORD = 0x0001_0002;
/// "Not handled": pass the exception on to the application, which is what would
/// happen with no debugger attached.
const DBG_EXCEPTION_NOT_HANDLED: DWORD = 0x8001_0001;
const EXCEPTION_BREAKPOINT: DWORD = 0x8000_0003;
const EXCEPTION_SINGLE_STEP: DWORD = 0x8000_0004;

/// Requests sent from the async trait methods to the dedicated debug-loop thread.
enum Command {
    /// Must be the first command the thread receives: performs
    /// `CreateProcessA` with `DEBUG_PROCESS` *on this thread*, since Win32
    /// requires `WaitForDebugEvent` to be called by the same thread that
    /// created/attached the debuggee.
    DoLaunch(Box<LaunchOptions>),
    /// Must be the first command the thread receives (alternative to
    /// `DoLaunch`): performs `DebugActiveProcess` + `OpenProcess` on this
    /// thread, for the same reason.
    DoAttach(DWORD),
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

/// A concrete [`crate::Debugger`] implementation driving a real Windows process
/// via the native debug API.
pub struct WindowsDebugger {
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

impl Default for WindowsDebugger {
    fn default() -> Self {
        Self::new()
    }
}

impl WindowsDebugger {
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

    /// Resolve a loaded PE image's entry point by reading its `IMAGE_DOS_
    /// HEADER`/`IMAGE_NT_HEADERS64` directly out of the live process's
    /// memory at `base` (two `read_memory` calls: the fixed-size DOS header
    /// first to learn `e_lfanew`, then the NT-headers region at that
    /// offset) and feeding them through the pure, unit-tested
    /// [`parse_pe_entry_point_rva`]. Returns `None` (not an error) on any
    /// read/parse failure — an entry point is best-effort metadata, not
    /// something `modules()` should fail wholesale over.
    async fn pe_entry_point(&self, base: Address) -> Option<Address> {
        use crate::Debugger as _;
        let dos = self.read_memory(base, 0x40).await.ok()?;
        let e_lfanew = u32::from_le_bytes(dos.get(0x3C..0x40)?.try_into().ok()?);
        let nt = self.read_memory(Address(base.as_u64().wrapping_add(u64::from(e_lfanew))), 44).await.ok()?;
        let rva = parse_pe_entry_point_rva(&dos, &nt)?;
        Some(Address(base.as_u64().wrapping_add(u64::from(rva))))
    }

    /// Resolve a loaded PE image's `IMAGE_DIRECTORY_ENTRY_EXCEPTION` (the
    /// `.pdata` directory: x64 unwind info) as `(rva, size)`, by reading
    /// the DOS header (to find `e_lfanew`) then enough of the NT headers
    /// to reach the data-directory array (168 bytes covers the fixed
    /// `IMAGE_NT_HEADERS64` through directory index 3). Used by
    /// `backtrace`'s CFI-unwind step; returns `None` (not an error) if the
    /// image has no exception directory (e.g. an x86 binary) or any
    /// read/parse fails — backtrace falls back to whatever frames the
    /// frame-pointer unwinder already found rather than erroring out.
    async fn pe_exception_directory(&self, base: Address) -> Option<(u32, u32)> {
        use crate::Debugger as _;
        let dos = self.read_memory(base, 0x40).await.ok()?;
        let e_lfanew = u32::from_le_bytes(dos.get(0x3C..0x40)?.try_into().ok()?);
        let nt = self.read_memory(Address(base.as_u64().wrapping_add(u64::from(e_lfanew))), 168).await.ok()?;
        parse_pe_data_directory(&nt, 3)
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
            let dr7 = regs.get("dr7").unwrap_or(0);
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
            if regs.get("dr7").unwrap_or(0) == 0 {
                continue;
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
                still_armed.iter().map(|t| t.to_string()).collect::<Vec<_>>().join(", ")
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
            let mut dr7 = regs.get("dr7").unwrap_or(0);
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
        // A breakpoint exception we did NOT plant is not a breakpoint.
        //
        // `classify_event` turns every `EXCEPTION_BREAKPOINT` into
        // `StopReason::Breakpoint`, which is all a free function over the raw
        // event can do. Nothing corrected it afterwards, so three unrelated
        // things reached the caller as "you hit a software breakpoint":
        // `pause()` (which works by `DebugBreakProcess` injecting one), the
        // initial process breakpoint Windows always delivers, and a
        // `__debugbreak()` in the target's own code. The caller was handed a
        // full `Breakpoint` record — `hit_count: 0`, `enabled: true` — for a
        // breakpoint that does not exist at an address they never set.
        //
        // Linux and macOS report their own pause as `StopReason::Signal`. This
        // is the first place on Windows that HAS the planted table, so it is
        // where the record can be turned back into what actually happened.
        //
        // Hardware watchpoints are checked too: they arrive through this same
        // reason with the WATCHED address, and they are ours.
        let planted = self.breakpoints.lock().contains_key(&a)
            || self.hw_watchpoints.lock().contains_key(&a);
        if !planted {
            // LABELLED, not reclassified.
            //
            // Turning this into `StopReason::Exception` was tried first and
            // measured: six live tests and the MCP layer'''s `initial_stop_tid`
            // wait for a `Breakpoint` to know the process has stopped and is
            // ready, because Windows genuinely delivers a breakpoint there. The
            // variant is not the lie — the RECORD is. It claimed a planted
            // software breakpoint, with `enabled: true`, at an address the
            // caller never set.
            //
            // `original_byte` and `hit_count` are already truthful here (None
            // and 0), and now the label says so out loud instead of leaving it
            // to be inferred from two absent fields.
            bp.label = Some(
                "not planted by this debugger — DebugBreakProcess (pause), the initial                  process breakpoint, or a __debugbreak() in the target"
                    .to_string(),
            );
            bp.enabled = false;
            return;
        }
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
                    // Same bookkeeping `continue_execution` does — see
                    // `linux_debugger.rs`'s identical fix for the full
                    // rationale: `single_step` (and therefore
                    // `step_over`/`step_out`, which call it) is just as much
                    // "the thread that most recently stopped" as a
                    // `continue_execution` result, but this mutex was only
                    // ever updated from that one call site.
                    *self.current_tid.lock() = Some(ev.tid);
                    // A failed rewind leaves the PC one byte inside an
                    // instruction. Returning this event as a normal step would
                    // report a clean stop for a target that cannot be resumed,
                    // so the failure replaces the event instead of riding
                    // alongside it.
                    if let Err(e) = self.rewind_past_own_breakpoint(ev).await {
                        return Err(e);
                    }
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
    async fn step_off_planted_breakpoint(&self, who: Option<ThreadId>) -> Option<DebugEvent> {
        let Some(tid) = who.or(*self.current_tid.lock()) else { return None };
        let Ok(regs) = self.get_registers(tid).await else { return None };
        let pc = regs.pc;
        let original = {
            let planted = self.breakpoints.lock();
            if self.disabled.lock().contains(&pc) {
                return None;
            }
            match planted.get(&pc) {
                Some(b) => b.clone(),
                None => return None,
            }
        };
        if self.write_memory_raw(Address(pc), &original).await.is_err() {
            return None;
        }
        let stepped = self.single_step_raw(tid).await.ok();
        if self.write_memory_raw(Address(pc), crate::host_trap_bytes()).await.is_err() {
            // Could not re-arm: stop claiming it is planted.
            self.breakpoints.lock().remove(&pc);
            return None;
        }
        stepped
    }

    /// The CPU always advances `rip` past an executed `int3` *before* raising
    /// the breakpoint exception, so a stop always leaves the live context's
    /// `rip` one byte past the breakpoint address. For a breakpoint **we**
    /// planted (byte patched to `0xCC`, tracked in `self.breakpoints`), that's
    /// wrong for resuming — once the original byte is restored, execution
    /// must continue from the breakpoint address itself, not one byte in —
    /// so rewind `rip` back by one. For any *other* `int3` (e.g. the system's
    /// initial process breakpoint, or one hit inside a live INT3 in the
    /// target's own code), the current `rip` is exactly where execution
    /// should resume: the byte at that address is real code we never
    /// touched, and rewinding would just re-execute the same `int3` forever
    /// (confirmed by `live_tests::launch_and_run_to_exit` hanging until this
    /// was made conditional).
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
    /// hit with `sp >= min_sp` (guards against recursion re-entering the same
    /// address at a deeper stack level), then remove the temporary
    /// breakpoint. Shared by `step_over`/`step_out`.
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
        if let Ok(maps) = self.memory_maps().await {
            if let Some(region) = maps
                .iter()
                .find(|m| target.as_u64() >= m.base.as_u64() && target.as_u64() < m.base.as_u64().saturating_add(m.size))
                && !region.executable
            {
                return Err(DebugError::StepError(format!(
                    "run_to_return: {target:?} is not executable memory — the return address read                      from the stack does not point at code, and planting a breakpoint there would                      corrupt the target's data"
                )));
            }
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
            // Best-effort cleanup: the process is gone if it exited, so a
            // failed restore here shouldn't clobber a valid ProcessExit
            // result with a spurious error.
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
        // The command lock is held across the WHOLE request/reply exchange,
        // not just the send. There is one channel pair shared by every
        // caller, so a reply is only meaningful to whoever sent the command
        // immediately before it.
        //
        // Releasing the lock after `send` (a `drop(guard)` used to sit here)
        // let two concurrent callers interleave as A-send, B-send, B-recv,
        // A-recv — each receiving the other's reply. With different `Reply`
        // variants that surfaces as a spurious "unexpected reply"; with the
        // SAME variant (two `read_memory` calls) each caller silently gets
        // the other's bytes, no error at all. `WindowsDebugger` is
        // `Send + Sync` specifically so it can be driven concurrently, so
        // this was reachable — proved by a live test that hammered
        // `get_registers` and `read_memory` from two tasks at once.
        //
        // Serialising here costs nothing real: the debug-loop thread on the
        // other end processes one command at a time regardless.
        let guard = self.cmd_tx.lock();
        let tx = guard.as_ref().ok_or(DebugError::NotAttached)?;
        tx.send(cmd).map_err(|_| DebugError::NotAttached)?;
        let rx_guard = self.reply_rx.lock();
        let rx = rx_guard.as_ref().ok_or(DebugError::NotAttached)?;
        let reply = rx.recv().map_err(|_| DebugError::NotAttached);
        drop(rx_guard);
        drop(guard);
        reply
    }

    /// Spawn the dedicated debug-loop thread and send it a `DoLaunch`/`DoAttach`
    /// startup command, returning the resulting [`ProcessId`] once the thread
    /// reports back that it performed the actual Win32 attach/launch call on
    /// itself (required: `WaitForDebugEvent` must run on the same thread that
    /// called `CreateProcessA`/`DebugActiveProcess`).
    fn spawn_loop(&self, startup: Command) -> Result<ProcessId, DebugError> {
        let (cmd_tx, cmd_rx) = channel::<Command>();
        let (reply_tx, reply_rx) = channel::<Reply>();

        let handle = std::thread::spawn(move || {
            debug_loop(&cmd_rx, &reply_tx);
        });

        cmd_tx.send(startup).map_err(|_| DebugError::LaunchError("debug thread died before startup".into()))?;
        let started = reply_rx.recv().map_err(|_| DebugError::LaunchError("debug thread died before startup".into()))?;
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

/// Thread ids belonging to `pid`, enumerated synchronously via toolhelp.
///
/// `threads()` does the same walk but is `async`, and `Drop` cannot await.
/// Enumeration is the only part that can be done off the debug-loop thread:
/// writing the debug registers must still go through the command channel,
/// because a `SetThreadContext` issued from another thread is accepted and
/// then quietly does nothing — measured, not assumed, when the first version
/// of this fix failed its own test with `DR7` unchanged.
fn enumerate_thread_ids(pid: DWORD) -> Vec<ThreadId> {
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
    if snapshot == INVALID_HANDLE_VALUE {
        return Vec::new();
    }
    let mut out = Vec::new();
    let mut entry: THREADENTRY32 = unsafe { zeroed() };
    entry.dwSize = size_of::<THREADENTRY32>() as DWORD;
    let mut first = true;
    loop {
        let ok = if first {
            first = false;
            unsafe { Thread32First(snapshot, &mut entry) }
        } else {
            unsafe { Thread32Next(snapshot, &mut entry) }
        };
        if ok == FALSE {
            break;
        }
        if entry.th32OwnerProcessID == pid {
            out.push(ThreadId(entry.th32ThreadID));
        }
    }
    unsafe {
        CloseHandle(snapshot);
    }
    out
}

impl Drop for WindowsDebugger {
    /// Best-effort detach when an attached debugger goes out of scope.
    ///
    /// Without this, dropping while attached destroyed the debuggee: nothing
    /// detaches, the loop thread dies with its channels, and Windows tears
    /// the target down along with the debug port (kill-on-exit defaults to
    /// TRUE). A debugger disappearing must leave the target running
    /// undisturbed — exactly the contract `detach()` itself was fixed for,
    /// and exactly what `detach()`'s own breakpoint sweep protects.
    ///
    /// Everything here is synchronous on purpose: `Drop` cannot await, but
    /// `send` is a blocking channel round-trip, so the same work `detach()`
    /// does is reachable from here. Every step is best-effort — a debugger
    /// dropped after `detach()`/`kill()` has no channel left and each `send`
    /// simply fails, which is the correct no-op.
    fn drop(&mut self) {
        if self.cmd_tx.lock().is_none() {
            return; // already detached or never attached
        }
        // Restore every planted `0xCC` first, for the same reason `detach()`
        // does: a leftover int3 raises an exception in a process that no
        // longer has a debugger to handle it.
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
        // Same hazard one layer down, and the reason this cannot reuse
        // `disarm_all_hardware_watchpoints`: that one is async and `Drop`
        // cannot await. Left armed, the target traps on the watched address
        // with no debugger attached.
        if !self.hw_watchpoints.lock().is_empty() {
            if let Some(pid) = *self.pid.lock() {
                for tid in enumerate_thread_ids(pid.0) {
                    // Through the channel, exactly as `detach` does: the
                    // debug-loop thread is the one whose register writes the
                    // target actually takes.
                    let Ok(Reply::Registers(Ok(mut regs))) =
                        self.send(Command::GetRegisters(tid))
                    else {
                        continue;
                    };
                    if regs.get("dr7").unwrap_or(0) == 0 {
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

/// Performs `CreateProcessA` with `DEBUG_PROCESS`. Must run on the debug-loop
/// thread — see [`Command::DoLaunch`].
fn do_launch(opts: &LaunchOptions) -> Result<(DWORD, HANDLE), DebugError> {
    let exe = CString::new(opts.executable.clone()).map_err(|e| DebugError::LaunchError(e.to_string()))?;
    let mut cmdline = opts.executable.clone();
    for a in &opts.args {
        cmdline.push(' ');
        cmdline.push_str(a);
    }
    let mut cmdline_c =
        CString::new(cmdline).map_err(|e| DebugError::LaunchError(e.to_string()))?.into_bytes_with_nul();

    let mut si: STARTUPINFOA = unsafe { zeroed() };
    si.cb = size_of::<STARTUPINFOA>() as DWORD;
    let mut pi: PROCESS_INFORMATION = unsafe { zeroed() };

    let ok = unsafe {
        CreateProcessA(
            exe.as_ptr(),
            cmdline_c.as_mut_ptr().cast(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            FALSE,
            DEBUG_PROCESS,
            std::ptr::null_mut(),
            std::ptr::null(),
            &mut si,
            &mut pi,
        )
    };
    if ok == FALSE {
        return Err(DebugError::LaunchError(format!("CreateProcessA failed: {}", unsafe { GetLastError() })));
    }
    unsafe {
        CloseHandle(pi.hThread);
    }
    Ok((pi.dwProcessId, pi.hProcess))
}

/// Performs `DebugActiveProcess` + `OpenProcess`. Must run on the debug-loop
/// thread — see [`Command::DoAttach`].
fn do_attach(pid: DWORD) -> Result<HANDLE, DebugError> {
    let ok = unsafe { DebugActiveProcess(pid) };
    if ok == FALSE {
        return Err(DebugError::LaunchError(format!(
            "DebugActiveProcess failed for pid {}: {}",
            pid,
            unsafe { GetLastError() }
        )));
    }
    let handle = unsafe { OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid) };
    if handle.is_null() {
        return Err(DebugError::ProcessNotFound(pid));
    }
    Ok(handle)
}

/// Runs entirely on the dedicated debug thread: performs the initial
/// `CreateProcessA`/`DebugActiveProcess` (so it happens on this thread, which
/// then owns the `WaitForDebugEvent` loop) and answers [`Command`]s sent from
/// the async wrapper.
fn debug_loop(cmd_rx: &Receiver<Command>, reply_tx: &Sender<Reply>) {
    let (pid, process_handle) = match cmd_rx.recv() {
        Ok(Command::DoLaunch(opts)) => match do_launch(&opts) {
            Ok((pid, handle)) => {
                let _ = reply_tx.send(Reply::Started(Ok(ProcessId(pid))));
                (pid, handle)
            }
            Err(e) => {
                let _ = reply_tx.send(Reply::Started(Err(e)));
                return;
            }
        },
        Ok(Command::DoAttach(pid)) => match do_attach(pid) {
            Ok(handle) => {
                let _ = reply_tx.send(Reply::Started(Ok(ProcessId(pid))));
                (pid, handle)
            }
            Err(e) => {
                let _ = reply_tx.send(Reply::Started(Err(e)));
                return;
            }
        },
        _ => {
            let _ = reply_tx.send(Reply::Started(Err(DebugError::LaunchError(
                "debug thread expected DoLaunch/DoAttach as its first command".into(),
            ))));
            return;
        }
    };

    let mut last_tid: DWORD = 0;
    // The file handle the CURRENT event handed us, still owed back to Windows.
    //
    // Closed only AFTER `ContinueDebugEvent` acknowledges that event, never
    // while it is outstanding: iteration 504 established, by bisection, that
    // calling into the OS inside that window breaks hardware watchpoint hit
    // detection. `CloseHandle` on a file handle is very probably harmless
    // there, but "very probably" is exactly the reasoning that cost three live
    // tests last time, and deferring costs one `Option`.
    //
    // At most one is outstanding at a time, because the loop acknowledges the
    // previous event before waiting for the next.
    let mut owed_handle: Option<HANDLE> = None;
    // How the pending stop must be acknowledged.
    //
    // `DBG_CONTINUE` tells the target "handled, carry on"; every
    // `ContinueDebugEvent` here used it unconditionally. That is right for the
    // traps this debugger causes itself (our `int3`, a single step, a debug
    // register) and WRONG for anything else: a first-chance access violation, an
    // illegal instruction, a divide by zero were all swallowed, so the program's
    // own `__try` / `SetUnhandledExceptionFilter` handler never ran and the
    // faulting instruction simply re-executed. A program that catches its own
    // faults behaved differently under this debugger than on its own — the same
    // defect the two ptrace backends had by never re-injecting the signal.
    //
    // `DBG_EXCEPTION_NOT_HANDLED` is the "pass it to the application" answer, and
    // it is what detach uses too: we are leaving, so the fault is the
    // application's business.
    let mut continue_status: DWORD = DBG_CONTINUE;
    while let Ok(cmd) = cmd_rx.recv() {
        match cmd {
            Command::DoLaunch(_) | Command::DoAttach(_) => {
                // Only valid as the very first command; ignore if repeated.
            }
            Command::ContinueExecution => {
                // Ack any pending stop before resuming.
                if last_tid != 0 {
                    unsafe {
                        ContinueDebugEvent(pid, last_tid, continue_status);
                        if let Some(h) = owed_handle.take() {
                            CloseHandle(h);
                        }
                    }
                }
                let mut ev: DEBUG_EVENT = unsafe { zeroed() };
                let ok = unsafe { WaitForDebugEvent(&mut ev, u32::MAX) };
                if ok == FALSE {
                    let _ = reply_tx.send(Reply::Event(Err(DebugError::MemoryError(
                        0,
                        format!("WaitForDebugEvent failed: {}", unsafe { GetLastError() }),
                    ))));
                    continue;
                }
                last_tid = ev.dwThreadId;
                owed_handle = event_file_handle(&ev);
                let reason = classify_event(&ev);
                // Ours to swallow, or the application's to handle? Decided here,
                // where the exception code is still in hand, and applied by the
                // NEXT `ContinueDebugEvent`.
                continue_status = continue_status_for(&ev);
                let is_exit = matches!(reason, StopReason::ProcessExit { .. });
                let debug_event =
                    DebugEvent::new(ProcessId(ev.dwProcessId), ThreadId(ev.dwThreadId), reason);
                let _ = reply_tx.send(Reply::Event(Ok(debug_event)));
                if is_exit {
                    return;
                }
            }
            Command::SingleStep(tid) => {
                // Hardware single step is an x86 TRAP FLAG here, and AArch64
                // has no `EFlags` to put it in. Measured on `windows-11-arm`
                // after the 602 port removed the twenty-one `Dr` errors: this
                // was the one site left, "no field `EFlags` on type `CONTEXT`".
                //
                // REFUSED rather than guessed. Windows-on-ARM single steps
                // through a different mechanism entirely, and writing something
                // plausible into `Cpsr` would be inventing a stepping engine
                // from a field name — the shape this crate treats as worse than
                // an error, because a "step" that silently became a "continue"
                // would run the target past everything the caller wanted to
                // watch and report success.
                #[cfg(not(any(target_arch = "x86_64", target_arch = "x86")))]
                {
                    let _ = tid;
                    let _ = reply_tx.send(Reply::Event(Err(DebugError::Unsupported(
                        "single step on this backend sets the x86 trap flag in EFlags, which                          this architecture does not have; the AArch64 mechanism is not                          implemented, and continuing the target instead would run it past the                          instruction you asked to step"
                            .into(),
                    ))));
                    continue;
                }
                #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
                if let Some(ctx) = read_context(tid.0) {
                    let mut ctx = ctx;
                    ctx.EFlags |= 0x100; // TF (trap flag)
                    write_context(tid.0, &ctx);
                }
                if last_tid != 0 {
                    unsafe {
                        ContinueDebugEvent(pid, last_tid, continue_status);
                        if let Some(h) = owed_handle.take() {
                            CloseHandle(h);
                        }
                    }
                }
                let mut ev: DEBUG_EVENT = unsafe { zeroed() };
                let ok = unsafe { WaitForDebugEvent(&mut ev, u32::MAX) };
                if ok == FALSE {
                    let _ = reply_tx.send(Reply::Event(Err(DebugError::StepError(
                        "WaitForDebugEvent failed during single-step".into(),
                    ))));
                    continue;
                }
                last_tid = ev.dwThreadId;
                owed_handle = event_file_handle(&ev);
                let reason = classify_event(&ev);
                // Ours to swallow, or the application's to handle? Decided here,
                // where the exception code is still in hand, and applied by the
                // NEXT `ContinueDebugEvent`.
                continue_status = continue_status_for(&ev);
                let debug_event =
                    DebugEvent::new(ProcessId(ev.dwProcessId), ThreadId(ev.dwThreadId), reason);
                let _ = reply_tx.send(Reply::Event(Ok(debug_event)));
            }
            Command::GetRegisters(tid) => {
                let result = read_context(tid.0).map_or_else(
                    || Err(DebugError::RegisterError(format!("GetThreadContext failed for {tid}"))),
                    |ctx| Ok(context_to_register_set(&ctx)),
                );
                let _ = reply_tx.send(Reply::Registers(result));
            }
            Command::SetRegisters(tid, regs) => {
                let result = read_context(tid.0).map_or_else(
                    || Err(DebugError::RegisterError(format!("GetThreadContext failed for {tid}"))),
                    |mut ctx| {
                        apply_register_set(&mut ctx, &regs);
                        if write_context(tid.0, &ctx) {
                            Ok(())
                        } else {
                            Err(DebugError::RegisterError(format!("SetThreadContext failed for {tid}")))
                        }
                    },
                );
                let _ = reply_tx.send(Reply::Ack(result));
            }
            Command::ReadMemory(addr, size) => {
                let mut buf = vec![0u8; size];
                let mut read = 0usize;
                let ok = unsafe {
                    ReadProcessMemory(
                        process_handle,
                        addr as *const _,
                        buf.as_mut_ptr().cast(),
                        size,
                        &mut read,
                    )
                };
                let result = if ok == TRUE && read == size {
                    Ok(buf)
                } else {
                    // Say WHICH failure it was.
                    //
                    // "ReadProcessMemory failed" is the same sentence for
                    // causes a user must act on differently: `ERROR_PARTIAL_COPY`
                    // (299) means the range runs into unmapped memory and the
                    // address is nearly right; `ERROR_ACCESS_DENIED` (5) means
                    // protection; `ERROR_INVALID_HANDLE` (6) means the process
                    // is gone and every later call will fail too. This file
                    // already interpolates `GetLastError()` into seventeen other
                    // errors — these two, the ones a debugging session hits most
                    // often, were the ones that dropped it.
                    //
                    // The byte count goes with it: a partial copy that moved
                    // some bytes is a different situation from one that moved
                    // none, and the caller cannot tell them apart otherwise.
                    Err(DebugError::MemoryError(
                        addr,
                        format!(
                            "ReadProcessMemory failed: {read} of {size} bytes, GetLastError {}",
                            unsafe { GetLastError() }
                        ),
                    ))
                };
                let _ = reply_tx.send(Reply::Memory(result));
            }
            Command::WriteMemory(addr, data) => {
                let mut written = 0usize;
                let ok = unsafe {
                    WriteProcessMemory(
                        process_handle,
                        addr as *mut _,
                        data.as_ptr().cast(),
                        data.len(),
                        &mut written,
                    )
                };
                // A PARTIAL write is a failure, not a smaller success.
                //
                // `WriteProcessMemory` returns TRUE having written fewer bytes
                // than asked when the range runs into memory it cannot touch,
                // and `written` was handed straight back as `Ok`. Every caller
                // in this crate discards that count — `detach()` and
                // `remove_breakpoint` restore an original byte with
                // `write_memory_raw(addr, &original)` and look only at whether
                // it errored. So a half-completed restore reported success and
                // left the `0xCC` in the target: precisely the landmine
                // `detach` exists to remove, now invisible because the
                // bookkeeping was cleared on the strength of that `Ok`.
                //
                // Linux (`write_all_at`) and macOS (`mach_vm_write`, which is
                // all-or-nothing) both refuse already; this was the last
                // backend where a write meant something weaker than the others.
                let result = if ok == TRUE && written == data.len() {
                    Ok(written)
                } else if ok == TRUE {
                    Err(DebugError::MemoryError(
                        addr,
                        format!("short write: {written} of {} bytes writable at this address", data.len()),
                    ))
                } else {
                    Err(DebugError::MemoryError(
                        addr,
                        format!(
                            "WriteProcessMemory failed: {written} of {} bytes, GetLastError {}",
                            data.len(),
                            unsafe { GetLastError() }
                        ),
                    ))
                };
                let _ = reply_tx.send(Reply::WriteCount(result));
            }
            Command::Detach => {
                if last_tid != 0 {
                    unsafe {
                        ContinueDebugEvent(pid, last_tid, continue_status);
                        if let Some(h) = owed_handle.take() {
                            CloseHandle(h);
                        }
                    }
                }
                // The answer is DERIVED from the syscall, not asserted.
                //
                // `DebugActiveProcessStop` is what actually releases the
                // target. Its BOOL was discarded and the reply was the literal
                // `Ok(())`, so `detach()` said "detached" whether or not
                // anything had been — and Windows is the most expensive place
                // to be wrong about this: a process that stays debugged is
                // KILLED when its debugger exits, so the caller was told it had
                // let the target go and the target died with the debugger
                // instead.
                //
                // `last_os_error()` is read immediately, before `CloseHandle`,
                // because that call would overwrite it.
                //
                // The handle is closed either way: it is ours and leaks if we
                // keep it, and whether the detach succeeded says nothing about
                // whether we still need it.
                //
                // A process that has already EXITED does not reach here: the
                // event loop returns as soon as it reports the exit, so
                // `send(Command::Detach)` fails on a dead channel long before
                // this arm runs. There is therefore no "already gone" case to
                // forgive on this backend, unlike the ptrace ones.
                let stopped = unsafe { DebugActiveProcessStop(pid) };
                let last_err = std::io::Error::last_os_error();
                unsafe {
                    CloseHandle(process_handle);
                }
                let result = if stopped == 0 {
                    Err(DebugError::DetachError(format!(
                        "DebugActiveProcessStop({pid}) failed: {last_err}"
                    )))
                } else {
                    Ok(())
                };
                let _ = reply_tx.send(Reply::Ack(result));
                return;
            }
            Command::Kill => {
                // The answer is DERIVED from the syscall, not asserted.
                //
                // `TerminateProcess` returns a BOOL and it was thrown away, so
                // `kill()` reported success for a process that may still be
                // running — most plausibly when the handle lacks
                // PROCESS_TERMINATE, which fails with ERROR_ACCESS_DENIED and
                // leaves the target very much alive.
                //
                // `last_os_error()` is read before `CloseHandle`, which would
                // overwrite it. The handle is closed either way: it is ours,
                // and whether the kill worked says nothing about whether we
                // still need it.
                let terminated = unsafe { TerminateProcess(process_handle, 1) };
                let last_err = std::io::Error::last_os_error();
                unsafe {
                    CloseHandle(process_handle);
                }
                let result = if terminated == 0 {
                    Err(DebugError::Os(format!("TerminateProcess({pid}) failed: {last_err}")))
                } else {
                    Ok(())
                };
                let _ = reply_tx.send(Reply::Ack(result));
                return;
            }
        }
    }
}

/// Convert a NUL-terminated wide (UTF-16) buffer, as returned by the toolhelp
/// `*W` APIs, into a `String`, stopping at the first NUL.
fn wide_to_string(buf: &[u16]) -> String {
    let len = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..len])
}

/// Report the watched address and access kind if a hardware watchpoint just
/// fired on `tid`, and clear `DR6` so the next trap starts from a clean slate.
///
/// `DR6` is sticky: the CPU sets a `B` bit and never clears it, so leaving it
/// set makes every subsequent single step look like the same watchpoint hit
/// forever. Clearing it here is part of reading it correctly, not an extra.
/// Which hardware watchpoint fired, from the x86 debug registers.
///
/// Gated in 602: `DR6`/`DR7` do not exist in the AArch64 `CONTEXT`, whose debug
/// state is `Bcr`/`Bvr`/`Wcr`/`Wvr` — a different subsystem this backend does
/// not program. The ARM64 counterpart below answers `None`, which is true
/// rather than convenient: nothing armed a watchpoint there, so none can have
/// fired.
#[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
fn watchpoint_hit(tid: DWORD) -> Option<(Address, BreakpointKind)> {
    unsafe {
        let handle = OpenThread(THREAD_ALL_ACCESS, FALSE, tid);
        if handle.is_null() {
            return None;
        }
        let mut ctx: CONTEXT = std::mem::zeroed();
        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        if GetThreadContext(handle, &mut ctx) == 0 {
            CloseHandle(handle);
            return None;
        }
        let slot = crate::x86_watchpoint_hit_slot(ctx.Dr6);
        let hit = slot.and_then(|slot| {
            let kind = crate::x86_watchpoint_kind_from_dr7(ctx.Dr7, slot)?;
            let watched = match slot {
                0 => ctx.Dr0,
                1 => ctx.Dr1,
                2 => ctx.Dr2,
                _ => ctx.Dr3,
            };
            Some((Address(watched), kind))
        });
        if slot.is_some() {
            ctx.Dr6 = 0;
            ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
            let _ = SetThreadContext(handle, &ctx);
        }
        CloseHandle(handle);
        hit
    }
}

/// How the next `ContinueDebugEvent` must acknowledge this event.
///
/// `DBG_CONTINUE` means "handled": correct for the traps this debugger causes
/// (`EXCEPTION_BREAKPOINT` from our own `int3`, `EXCEPTION_SINGLE_STEP` from the
/// trap flag or a debug register) and for every non-exception event.
///
/// For anything else — an access violation, an illegal instruction, a divide by
/// zero — the answer must be `DBG_EXCEPTION_NOT_HANDLED`, which hands the
/// exception to the application's own handler exactly as would happen with no
/// debugger attached. Answering `DBG_CONTINUE` there told the target the fault
/// had been dealt with, so its `__try` block never ran and the faulting
/// instruction re-executed unchanged.
/// The AArch64 counterpart: nothing armed, so nothing fired.
///
/// `None` here is a MEASUREMENT, not a placeholder. `set_watchpoint_sized`
/// refuses on this architecture, so no watchpoint can be armed through this
/// backend, so no hit can be attributable to one. Reporting a hit would be
/// inventing an event; reporting an error would be claiming a failure that did
/// not happen.
#[cfg(target_arch = "aarch64")]
fn watchpoint_hit(_tid: DWORD) -> Option<(Address, BreakpointKind)> {
    None
}

fn continue_status_for(ev: &DEBUG_EVENT) -> DWORD {
    if ev.dwDebugEventCode != EXCEPTION_DEBUG_EVENT {
        return DBG_CONTINUE;
    }
    let code = unsafe { ev.u.Exception() }.ExceptionRecord.ExceptionCode;
    if code == EXCEPTION_BREAKPOINT || code == EXCEPTION_SINGLE_STEP {
        DBG_CONTINUE
    } else {
        DBG_EXCEPTION_NOT_HANDLED
    }
}

/// The file handle Windows HANDS US with an event, which the debugger owns.
///
/// `LOAD_DLL_DEBUG_INFO::hFile` and `CREATE_PROCESS_DEBUG_INFO::hFile` are
/// documented as the debugger's to close. Nothing here ever did: `hFile` did
/// not appear anywhere in this file, so the process leaked one file handle for
/// every image the target loaded, for the whole life of the session. A target
/// that loads and unloads plugins in a loop grows that leak without bound, and
/// it is invisible until the handle table is exhausted — at which point the
/// failures land on unrelated calls.
///
/// Returns `None` for a null or `INVALID_HANDLE_VALUE` handle: Windows is
/// entitled to hand over neither, and closing those is an error, not a tidy-up.
fn event_file_handle(ev: &DEBUG_EVENT) -> Option<HANDLE> {
    let h = match ev.dwDebugEventCode {
        LOAD_DLL_DEBUG_EVENT => unsafe { ev.u.LoadDll() }.hFile,
        CREATE_PROCESS_DEBUG_EVENT => unsafe { ev.u.CreateProcessInfo() }.hFile,
        _ => return None,
    };
    if h.is_null() || h == INVALID_HANDLE_VALUE {
        return None;
    }
    Some(h)
}

fn classify_event(ev: &DEBUG_EVENT) -> StopReason {
    match ev.dwDebugEventCode {
        EXIT_PROCESS_DEBUG_EVENT => {
            let info = unsafe { ev.u.ExitProcess() };
            StopReason::ProcessExit { exit_code: info.dwExitCode as i32 }
        }
        EXCEPTION_DEBUG_EVENT => {
            let info = unsafe { ev.u.Exception() };
            let code = info.ExceptionRecord.ExceptionCode as DWORD;
            let addr = Address(info.ExceptionRecord.ExceptionAddress as u64);
            match code {
                EXCEPTION_BREAKPOINT => {
                    StopReason::Breakpoint { address: addr, bp: Breakpoint::new_software(addr) }
                }
                EXCEPTION_SINGLE_STEP => {
                    // A watchpoint hit arrives as this very exception: only
                    // DR6 distinguishes it from a real single step. Without
                    // this the debugger armed the watchpoint correctly and
                    // then reported every hit as a plain step, throwing the
                    // answer away.
                    match watchpoint_hit(ev.dwThreadId) {
                        Some((watched, kind)) => StopReason::Breakpoint {
                            address: watched,
                            // `new_hardware` fixes the kind to an execution
                            // breakpoint; a watchpoint hit must carry the
                            // access kind DR7 actually holds, or the caller
                            // cannot tell a read watch from a write one.
                            bp: Breakpoint { kind, ..Breakpoint::new_hardware(watched) },
                        },
                        None => StopReason::SingleStep { address: addr },
                    }
                }
                0xC000_0005 => StopReason::AccessViolation {
                    // `ExceptionInformation[1]`, NOT `ExceptionAddress`.
                    //
                    // `ExceptionAddress` is the INSTRUCTION that faulted;
                    // `ExceptionInformation[1]` is the address the program
                    // tried to touch. This reported the former under a field
                    // whose sibling — `is_write`, read from
                    // `ExceptionInformation[0]` — describes the DATA access, so
                    // the pair contradicted itself: a read/write flag about one
                    // address attached to another.
                    //
                    // Linux answers the same crash with `si_addr`, which is the
                    // datum. One field name meant two different things
                    // depending on the OS, and neither errored: a caller
                    // comparing this against a buffer range simply got the code
                    // address and believed it.
                    //
                    // The instruction address is not lost -- it is the program
                    // counter, readable from the register set at this same stop.
                    address: Address(info.ExceptionRecord.ExceptionInformation[1] as u64),
                    is_write: info.ExceptionRecord.ExceptionInformation[0] == 1,
                },
                other => StopReason::Exception {
                    code: other,
                    address: Some(addr),
                    description: format!("exception code {other:#x}"),
                },
            }
        }
        // A library load carries only its BASE out of here.
        //
        // Resolving the name at this point is what broke the hardware
        // watchpoints: `GetMappedFileNameW` asks psapi about the traced
        // process while it is stopped on a debug event that has NOT yet been
        // acknowledged with `ContinueDebugEvent`, and three live tests went red
        // — every watchpoint hit came back classified as an ordinary single
        // step, because `DR6` no longer read as set. Proved by bisection
        // (iteration 504): the same arm emitting the same variant with a
        // constant path leaves all 81 live tests green.
        //
        // The base is all this function needs to know. The name is filled in by
        // `arm_pending_breakpoints`, from the async side, where the target has
        // been acquired and querying it is ordinary.
        //
        // UNLOAD is deliberately NOT classified: its event carries only an
        // address, so naming it would need a base->path table filled at load
        // time — and at load time this function no longer knows the name. It
        // stays `Unknown`, exactly as before, and `resolve_on_unload` stays
        // unused. Forgetting stale traps is a smaller concern than arming them
        // at all, and inventing a name here would be worse than not answering.
        LOAD_DLL_DEBUG_EVENT => {
            let info = unsafe { ev.u.LoadDll() };
            StopReason::LibraryLoad {
                path: String::new(),
                base: Address(info.lpBaseOfDll as u64),
            }
        }
        // Thread lifetime. `StopReason::ThreadCreate`/`ThreadExit` have existed
        // since the enum was written and THREE layers downstream are built to
        // carry them — `cross_platform_debug::DebugEventKind`,
        // `debug_session_manager::SessionEvent::ThreadCreated/ThreadExited`,
        // `debug_session_recorder` — but no backend has ever produced one.
        // Windows hands these events over unconditionally, and they were
        // landing in the `other` arm below as `Unknown { "debug event code 2" }`:
        // a debugger that cannot say when a thread appears cannot arm
        // breakpoints on new threads, cannot keep a thread list current, and
        // records "unknown" for every thread a multi-threaded target — i.e. any
        // real application — creates.
        //
        // Only fields of the DEBUG_EVENT itself are read. Nothing here queries
        // the traced process: doing that on an unacknowledged event is what
        // broke the hardware watchpoints in iteration 504, and that lesson
        // applies to this arm as much as to LOAD_DLL above.
        CREATE_THREAD_DEBUG_EVENT => StopReason::ThreadCreate { tid: ThreadId(ev.dwThreadId) },
        EXIT_THREAD_DEBUG_EVENT => StopReason::ThreadExit {
            tid: ThreadId(ev.dwThreadId),
            #[allow(clippy::cast_possible_wrap)]
            exit_code: unsafe { ev.u.ExitThread() }.dwExitCode as i32,
        },
        other => StopReason::Unknown { description: format!("debug event code {other}") },
    }
}

/// `winapi` 0.3.9's `CONTEXT` struct on x86_64 is missing the 16-byte
/// alignment the real Win32 `CONTEXT` requires (its source carries a
/// `// FIXME align 16` comment) — without it, the floating-point save area
/// inside `CONTEXT` can land at the wrong offset relative to what
/// `Get`/`SetThreadContext` expect, corrupting every field read after it
/// (observed: `Rip` reading back as `0`). Force the correct alignment with a
/// wrapper rather than relying on the crate's layout.
#[repr(C, align(16))]
struct AlignedContext(CONTEXT);

fn read_context(tid: DWORD) -> Option<CONTEXT> {
    unsafe {
        let handle = OpenThread(THREAD_ALL_ACCESS, FALSE, tid);
        if handle.is_null() {
            return None;
        }
        let mut aligned: AlignedContext = AlignedContext(zeroed());
        // CONTEXT_DEBUG_REGISTERS so Dr0-Dr7 round-trip through get/set —
        // required for hardware watchpoints. The flags stay in the struct, so
        // the later SetThreadContext writes the DRs back too.
        aligned.0.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS;
        let ok = GetThreadContext(handle, &mut aligned.0);
        CloseHandle(handle);
        if ok == TRUE { Some(aligned.0) } else { None }
    }
}

fn write_context(tid: DWORD, ctx: &CONTEXT) -> bool {
    unsafe {
        let handle = OpenThread(THREAD_ALL_ACCESS, FALSE, tid);
        if handle.is_null() {
            return false;
        }
        let mut aligned = AlignedContext(*ctx);
        // GetThreadContext leaves ContextFlags describing only the parts it
        // actually filled, which can drop CONTEXT_DEBUG_REGISTERS — and then
        // SetThreadContext silently skips DR0-DR7. Force the full set so
        // hardware-watchpoint DR writes land (bug found 2026-07-18).
        aligned.0.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS;
        let ok = SetThreadContext(handle, &aligned.0);
        CloseHandle(handle);
        let _ = &mut aligned; // keep alive/aligned through the call
        ok == TRUE
    }
}

#[cfg(target_arch = "x86_64")]
/// Read the x86-64 `CONTEXT` into the crate's register vocabulary.
///
/// Gated in iteration 602. Measured on `windows-11-arm`, the first run of the
/// CI row added in 597: this backend did NOT COMPILE for ARM64 at all —
/// `ctx.Dr6` is an "unknown field" there, and so are `Rip`, `EFlags` and the
/// twenty-one other x86 names below. Not "watchpoints are refused on ARM",
/// which is what the code said: the whole file was unbuildable for the target.
#[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
fn context_to_register_set(ctx: &CONTEXT) -> RegisterSet {
    let mut regs = RegisterSet::new();
    regs.set("rax", ctx.Rax);
    regs.set("rbx", ctx.Rbx);
    regs.set("rcx", ctx.Rcx);
    regs.set("rdx", ctx.Rdx);
    regs.set("rsi", ctx.Rsi);
    regs.set("rdi", ctx.Rdi);
    regs.set("rbp", ctx.Rbp);
    regs.set("rsp", ctx.Rsp);
    regs.set("r8", ctx.R8);
    regs.set("r9", ctx.R9);
    regs.set("r10", ctx.R10);
    regs.set("r11", ctx.R11);
    regs.set("r12", ctx.R12);
    regs.set("r13", ctx.R13);
    regs.set("r14", ctx.R14);
    regs.set("r15", ctx.R15);
    regs.set("rip", ctx.Rip);
    regs.set("eflags", u64::from(ctx.EFlags));
    regs.set("dr0", ctx.Dr0);
    regs.set("dr1", ctx.Dr1);
    regs.set("dr2", ctx.Dr2);
    regs.set("dr3", ctx.Dr3);
    regs.set("dr6", ctx.Dr6);
    regs.set("dr7", ctx.Dr7);
    // `RegisterSet` also has dedicated pc/sp/fp fields (used by callers like
    // `backtrace`/`step_over`/`step_out` instead of the named-register map) —
    // populate them here too, or they silently stay at their `0`/`None`
    // defaults even though the named registers are correct.
    regs.pc = ctx.Rip;
    regs.sp = ctx.Rsp;
    regs.fp = Some(ctx.Rbp);
    regs
}

/// The same, for the AArch64 `CONTEXT`.
///
/// Field names are READ from `winapi`'s own definition, not guessed: the union
/// `CONTEXT_u` holds `X0`-`X28`, `Fp` and `Lr`, with `Sp`, `Pc` and `Cpsr`
/// beside it. Guessing them would have been predicting where measuring was
/// available, which is the mistake this repo keeps paying for.
///
/// NO `dr0`-`dr7` here, and that is not an omission. AArch64 has no such
/// register file: its debug state is `Bcr`/`Bvr`/`Wcr`/`Wvr`, a different
/// subsystem this backend does not yet program, and `set_watchpoint_sized`
/// already refuses accordingly. Publishing zeroed `dr` entries would let the
/// shared watchpoint engine believe it had four free slots on a CPU that
/// exposes `ARM64_MAX_WATCHPOINTS = 2` and none through this path.
#[cfg(target_arch = "aarch64")]
fn context_to_register_set(ctx: &CONTEXT) -> RegisterSet {
    let mut regs = RegisterSet::new();
    // SAFETY: `CONTEXT_u` is a union of `[u64; 31]` and the named-register
    // struct; both members are plain integers of the same size, so reading the
    // named view of a kernel-filled context is always initialised.
    let x = unsafe { ctx.u.s() };
    regs.set("x0", x.X0);
    regs.set("x1", x.X1);
    regs.set("x2", x.X2);
    regs.set("x3", x.X3);
    regs.set("x4", x.X4);
    regs.set("x5", x.X5);
    regs.set("x6", x.X6);
    regs.set("x7", x.X7);
    regs.set("x8", x.X8);
    regs.set("x9", x.X9);
    regs.set("x10", x.X10);
    regs.set("x11", x.X11);
    regs.set("x12", x.X12);
    regs.set("x13", x.X13);
    regs.set("x14", x.X14);
    regs.set("x15", x.X15);
    regs.set("x16", x.X16);
    regs.set("x17", x.X17);
    regs.set("x18", x.X18);
    regs.set("x19", x.X19);
    regs.set("x20", x.X20);
    regs.set("x21", x.X21);
    regs.set("x22", x.X22);
    regs.set("x23", x.X23);
    regs.set("x24", x.X24);
    regs.set("x25", x.X25);
    regs.set("x26", x.X26);
    regs.set("x27", x.X27);
    regs.set("x28", x.X28);
    // `x29`/`x30` are the architectural names for the frame pointer and link
    // register; BOTH spellings are published because the crate has an open
    // question about which is canonical and answering it silently here would
    // decide it for everyone. Same choice the Linux port made in 552.
    regs.set("fp", x.Fp);
    regs.set("x29", x.Fp);
    regs.set("lr", x.Lr);
    regs.set("x30", x.Lr);
    regs.set("sp", ctx.Sp);
    regs.set("pc", ctx.Pc);
    regs.set("cpsr", u64::from(ctx.Cpsr));
    regs.pc = ctx.Pc;
    regs.sp = ctx.Sp;
    regs.fp = Some(x.Fp);
    regs
}

#[cfg(target_arch = "x86_64")]
fn apply_register_set(ctx: &mut CONTEXT, regs: &RegisterSet) {
    if let Some(v) = regs.get("rax") { ctx.Rax = v; }
    if let Some(v) = regs.get("rbx") { ctx.Rbx = v; }
    if let Some(v) = regs.get("rcx") { ctx.Rcx = v; }
    if let Some(v) = regs.get("rdx") { ctx.Rdx = v; }
    if let Some(v) = regs.get("rsi") { ctx.Rsi = v; }
    if let Some(v) = regs.get("rdi") { ctx.Rdi = v; }
    if let Some(v) = regs.get("rbp") { ctx.Rbp = v; }
    if let Some(v) = regs.get("rsp") { ctx.Rsp = v; }
    if let Some(v) = regs.get("r8") { ctx.R8 = v; }
    if let Some(v) = regs.get("r9") { ctx.R9 = v; }
    if let Some(v) = regs.get("r10") { ctx.R10 = v; }
    if let Some(v) = regs.get("r11") { ctx.R11 = v; }
    if let Some(v) = regs.get("r12") { ctx.R12 = v; }
    if let Some(v) = regs.get("r13") { ctx.R13 = v; }
    if let Some(v) = regs.get("r14") { ctx.R14 = v; }
    if let Some(v) = regs.get("r15") { ctx.R15 = v; }
    if let Some(v) = regs.get("rip") { ctx.Rip = v; }
    if let Some(v) = regs.get("eflags") { ctx.EFlags = v as u32; }
    if let Some(v) = regs.get("dr0") { ctx.Dr0 = v; }
    if let Some(v) = regs.get("dr1") { ctx.Dr1 = v; }
    if let Some(v) = regs.get("dr2") { ctx.Dr2 = v; }
    if let Some(v) = regs.get("dr3") { ctx.Dr3 = v; }
    if let Some(v) = regs.get("dr6") { ctx.Dr6 = v; }
    if let Some(v) = regs.get("dr7") { ctx.Dr7 = v; }
}

/// Write the crate's register vocabulary back into an AArch64 `CONTEXT`.
///
/// Accepts both spellings of the frame pointer and link register for the same
/// reason the reader publishes both: the crate has not decided whether `x29` or
/// `fp` is canonical, and a writer that took only one would quietly ignore a
/// caller who used the other — a set that reports success and changes nothing.
///
/// `dr0`-`dr7` are deliberately NOT accepted. They do not exist on this CPU,
/// and silently dropping them would be exactly that same failure: the shared
/// engine computes a `DR7` word, hands it over, and is told nothing went wrong.
/// `set_watchpoint_sized` refuses the request before it can get here.
#[cfg(target_arch = "aarch64")]
fn apply_register_set(ctx: &mut CONTEXT, regs: &RegisterSet) {
    // SAFETY: as `context_to_register_set` — both union members are plain
    // integer storage of the same size, and this writes the named view of a
    // context the kernel filled.
    let x = unsafe { ctx.u.s_mut() };
    macro_rules! set_x {
        ($($n:literal => $f:ident),* $(,)?) => {
            $( if let Some(v) = regs.get($n) { x.$f = v; } )*
        };
    }
    set_x! {
        "x0" => X0, "x1" => X1, "x2" => X2, "x3" => X3, "x4" => X4,
        "x5" => X5, "x6" => X6, "x7" => X7, "x8" => X8, "x9" => X9,
        "x10" => X10, "x11" => X11, "x12" => X12, "x13" => X13, "x14" => X14,
        "x15" => X15, "x16" => X16, "x17" => X17, "x18" => X18, "x19" => X19,
        "x20" => X20, "x21" => X21, "x22" => X22, "x23" => X23, "x24" => X24,
        "x25" => X25, "x26" => X26, "x27" => X27, "x28" => X28,
    }
    if let Some(v) = regs.get("fp").or_else(|| regs.get("x29")) { x.Fp = v; }
    if let Some(v) = regs.get("lr").or_else(|| regs.get("x30")) { x.Lr = v; }
    if let Some(v) = regs.get("sp") { ctx.Sp = v; }
    if let Some(v) = regs.get("pc") { ctx.Pc = v; }
    if let Some(v) = regs.get("cpsr") {
        ctx.Cpsr = u32::try_from(v & 0xFFFF_FFFF).unwrap_or(ctx.Cpsr);
    }
}

/// Extract a PE64 image's entry-point RVA from its `IMAGE_DOS_HEADER` (must
/// start with `MZ` and carry `e_lfanew` at offset `0x3C`) and the
/// `IMAGE_NT_HEADERS64` bytes read starting at that `e_lfanew` offset (must
/// start with the `PE\0\0` signature). Pure byte-buffer parser — no live
/// process needed — so it is directly unit-testable against a hand-built
/// synthetic header, mirroring the same host-independent-parser pattern
/// used for the macOS Mach-O segment-size parser (`macos_debugger.rs`,
/// iter 172).
///
/// Layout: `IMAGE_NT_HEADERS64` = `Signature`(4) + `IMAGE_FILE_HEADER`(20) +
/// `IMAGE_OPTIONAL_HEADER64` starting with `Magic`(2) + `MajorLinkerVersion`(1)
/// + `MinorLinkerVersion`(1) + `SizeOfCode`(4) + `SizeOfInitializedData`(4) +
/// `SizeOfUninitializedData`(4) + `AddressOfEntryPoint`(4) — so
/// `AddressOfEntryPoint` sits at byte offset `4 + 20 + 2+1+1+4+4+4 = 40`
/// within the NT-headers buffer.
fn parse_pe_entry_point_rva(dos_bytes: &[u8], nt_bytes: &[u8]) -> Option<u32> {
    if dos_bytes.len() < 0x40 || &dos_bytes[0..2] != b"MZ" {
        return None;
    }
    let e_lfanew = u32::from_le_bytes(dos_bytes[0x3C..0x40].try_into().ok()?);
    // Sanity bound: a real e_lfanew is a small offset into the file, not an
    // unbounded value — guards against a garbage read producing a huge
    // spurious offset elsewhere.
    if e_lfanew == 0 || e_lfanew > 0x1_0000 {
        return None;
    }
    if nt_bytes.len() < 44 || &nt_bytes[0..4] != b"PE\0\0" {
        return None;
    }
    Some(u32::from_le_bytes(nt_bytes[40..44].try_into().ok()?))
}

/// Extract one `IMAGE_DATA_DIRECTORY` (RVA, Size) from `IMAGE_NT_HEADERS64`'s
/// `OptionalHeader.DataDirectory[index]`. Pure byte-buffer parser, no live
/// process needed. Offset math: `DataDirectory` starts at
/// `Signature(4)+FileHeader(20)+OptionalHeader-fields-before-it(112) = 136`
/// bytes into the NT-headers buffer; each entry is 8 bytes (`RVA`(4) +
/// `Size`(4)). `index` 3 = `IMAGE_DIRECTORY_ENTRY_EXCEPTION` (`.pdata`, x64
/// unwind-info directory) — the only one this crate currently needs, but
/// the function is generic over `index` since the layout math is identical
/// for any of the 16 directory slots.
fn parse_pe_data_directory(nt_bytes: &[u8], index: usize) -> Option<(u32, u32)> {
    if nt_bytes.len() < 4 || &nt_bytes[0..4] != b"PE\0\0" {
        return None;
    }
    let offset = 136 + index * 8;
    if nt_bytes.len() < offset + 8 {
        return None;
    }
    let rva = u32::from_le_bytes(nt_bytes[offset..offset + 4].try_into().ok()?);
    let size = u32::from_le_bytes(nt_bytes[offset + 4..offset + 8].try_into().ok()?);
    if rva == 0 || size == 0 { None } else { Some((rva, size)) }
}

/// Binary-search a `.pdata` section (an array of 12-byte
/// `IMAGE_RUNTIME_FUNCTION_ENTRY` records: `BeginAddress`(4)/`EndAddress`(4)/
/// `UnwindInfoAddress`(4), all RVAs, SORTED by `BeginAddress` — a PE
/// structural guarantee, not an assumption this function makes unsafely)
/// for the entry covering `rva`. Pure byte-buffer parser.
fn find_runtime_function(pdata: &[u8], rva: u32) -> Option<(u32, u32, u32)> {
    const ENTRY_SIZE: usize = 12;
    let count = pdata.len() / ENTRY_SIZE;
    let mut lo = 0usize;
    let mut hi = count;
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        let off = mid * ENTRY_SIZE;
        let begin = u32::from_le_bytes(pdata[off..off + 4].try_into().ok()?);
        let end = u32::from_le_bytes(pdata[off + 4..off + 8].try_into().ok()?);
        if rva < begin {
            hi = mid;
        } else if rva >= end {
            lo = mid + 1;
        } else {
            let unwind_rva = u32::from_le_bytes(pdata[off + 8..off + 12].try_into().ok()?);
            return Some((begin, end, unwind_rva));
        }
    }
    None
}

/// Sum the total stack-pointer displacement an `UNWIND_INFO`'s prologue
/// pushes/allocates, so a caller past the prologue can compute the return
/// address's location relative to the CURRENT `rsp` (`current_rsp +
/// delta` = the `rsp` value the function had right after its prologue
/// finished pushing the return address on entry, i.e. one slot below
/// where the return address itself sits). Pure byte-buffer parser — no
/// live process needed.
///
/// **Deliberately bails out (`None`) rather than guess** for the cases
/// this minimal implementation doesn't handle: `UWOP_SET_FPREG` (a custom
/// frame pointer — needs tracking its established value, not just a
/// flat `rsp` delta), `UWOP_PUSH_MACHFRAME` (interrupt/exception frames —
/// a fundamentally different unwind shape), and chained unwind info
/// (`UNW_FLAG_CHAININFO`, version-2 `UWOP_EPILOG` codes). Only
/// `UWOP_PUSH_NONVOL` (+8 bytes) and `UWOP_ALLOC_SMALL`/`UWOP_ALLOC_LARGE`
/// (+their size) are interpreted — `UWOP_SAVE_NONVOL(_FAR)`/
/// `UWOP_SAVE_XMM128(_FAR)` are register-value saves that don't move
/// `rsp`, correctly skipped without affecting the delta. An empty-codes
/// `UNWIND_INFO` (a true leaf function) correctly returns `Some(0)`.
///
/// This assumes the caller is stopped PAST the function's prologue (true
/// for the common case of stopping somewhere in a function body, not at
/// its very first instruction) — the standard simplification unsophisticated
/// unwinders make; a fully correct implementation would also check
/// `SizeOfProlog` against the current offset into the function.
/// `pc_offset_in_function` is the current PC's byte offset from the start of
/// the function. Only unwind codes whose `CodeOffset` is at or below it have
/// executed and may contribute to the delta — `CodeOffset` is the offset of
/// the instruction *after* the one performing the operation, so `<=` is the
/// correct comparison here (unlike DWARF's row boundaries, iter 319). Pass a
/// large value to account for the entire prologue, i.e. for a PC in the body.
fn compute_prologue_stack_delta(unwind_info: &[u8], pc_offset_in_function: u64) -> Option<u64> {
    if unwind_info.len() < 4 {
        return None;
    }
    let version_flags = unwind_info[0];
    let version = version_flags & 0x07;
    let flags = version_flags >> 3;
    const UNW_FLAG_CHAININFO: u8 = 0x04;
    if version != 1 || (flags & UNW_FLAG_CHAININFO) != 0 {
        return None;
    }
    let count_of_codes = unwind_info[2] as usize;
    // unwind_info[3] low nibble is FrameRegister (non-zero when a frame
    // pointer register is used).  We do NOT bail here: UWOP_SET_FPREG
    // (opcode 3) merely records that the frame pointer was established; it
    // does not alter RSP.  We handle it below by skipping its single slot.
    let codes_start = 4;
    let codes_end = codes_start + count_of_codes * 2;
    if unwind_info.len() < codes_end {
        return None;
    }
    let mut delta: u64 = 0;
    let mut i = 0usize;
    while i < count_of_codes {
        let off = codes_start + i * 2;
        // Byte 0 of every code is its CodeOffset: the operation has executed
        // only if the PC has reached it. Codes that have not executed still
        // have to be SKIPPED correctly (their extra slots are present in the
        // buffer regardless), so this gates the delta, never the cursor.
        let code_offset = u64::from(unwind_info[off]);
        let executed = code_offset <= pc_offset_in_function;
        let op_info_byte = unwind_info[off + 1];
        let unwind_op = op_info_byte & 0x0F;
        let op_info = (op_info_byte >> 4) & 0x0F;
        match unwind_op {
            0 => {
                // UWOP_PUSH_NONVOL: one 8-byte push, no extra slots.
                if executed {
                    delta += 8;
                }
                i += 1;
            }
            1 => {
                // UWOP_ALLOC_LARGE: op_info 0 = one extra slot (size/8 as
                // u16); op_info 1 = two extra slots (size as u32).
                if op_info == 0 {
                    if i + 1 >= count_of_codes {
                        return None;
                    }
                    let slot_off = codes_start + (i + 1) * 2;
                    let raw = u16::from_le_bytes(unwind_info[slot_off..slot_off + 2].try_into().ok()?);
                    if executed {
                        delta += u64::from(raw) * 8;
                    }
                    i += 2;
                } else if op_info == 1 {
                    if i + 2 >= count_of_codes {
                        return None;
                    }
                    let slot_off = codes_start + (i + 1) * 2;
                    let raw = u32::from_le_bytes(unwind_info[slot_off..slot_off + 4].try_into().ok()?);
                    if executed {
                        delta += u64::from(raw);
                    }
                    i += 3;
                } else {
                    return None;
                }
            }
            2 => {
                // UWOP_ALLOC_SMALL: size = (op_info+1)*8, no extra slots.
                if executed {
                    delta += (u64::from(op_info) + 1) * 8;
                }
                i += 1;
            }
            4 => {
                // UWOP_SAVE_NONVOL: one extra slot, doesn't move rsp.
                if i + 1 >= count_of_codes {
                    return None;
                }
                i += 2;
            }
            5 => {
                // UWOP_SAVE_NONVOL_FAR: two extra slots, doesn't move rsp.
                if i + 2 >= count_of_codes {
                    return None;
                }
                i += 3;
            }
            8 => {
                // UWOP_SAVE_XMM128: one extra slot, doesn't move rsp.
                if i + 1 >= count_of_codes {
                    return None;
                }
                i += 2;
            }
            9 => {
                // UWOP_SAVE_XMM128_FAR: two extra slots, doesn't move rsp.
                if i + 2 >= count_of_codes {
                    return None;
                }
                i += 3;
            }
            3 => {
                // UWOP_SET_FPREG: establishes a frame pointer register from
                // the current RSP.  Occupies exactly one slot and does NOT
                // change RSP, so we skip without adding to delta.
                i += 1;
            }
            _ => {
                // UWOP_PUSH_MACHFRAME (10) or anything else unrecognized —
                // bail rather than guess.
                return None;
            }
        }
    }
    Some(delta)
}

/// Decode a `MEMORY_BASIC_INFORMATION::Protect` value into (r, w, x).
///
/// Extracted from `memory_maps` so the decoding is testable without a live
/// process — inline decoding is decoding nobody checks.
/// `ERROR_BAD_LENGTH`, the one snapshot failure that means "try again".
const ERROR_BAD_LENGTH: u32 = 24;

/// Take a toolhelp snapshot, retrying the failure Windows documents as
/// transient.
///
/// `CreateToolhelp32Snapshot` with `TH32CS_SNAPMODULE` fails with
/// `ERROR_BAD_LENGTH` while the target is still loading its module list — MSDN
/// says to call it again — and that window is exactly where a debugger looks:
/// right after `launch`, at the initial breakpoint, while the loader is still
/// working. Without a retry `modules()` returned a hard error for a perfectly
/// healthy process, and the caller had no way to tell that from a real failure.
///
/// Generic over the attempt so the policy is testable without a live process:
/// `attempt` returns the handle plus the `GetLastError()` value that went with it.
fn snapshot_with_retry<H: Copy + PartialEq>(
    invalid: H,
    max_attempts: usize,
    mut attempt: impl FnMut() -> (H, u32),
) -> Result<H, u32> {
    let mut last_err = 0;
    for _ in 0..max_attempts.max(1) {
        let (handle, err) = attempt();
        if handle != invalid {
            return Ok(handle);
        }
        last_err = err;
        if err != ERROR_BAD_LENGTH {
            // Anything else is a real failure: retrying would only stall.
            break;
        }
    }
    Err(last_err)
}

fn classify_protection(protect: u32) -> (bool, bool, bool) {
    // `Protect` carries the base protection in its low byte plus modifier
    // FLAGS ORed on top: PAGE_GUARD (0x100), PAGE_NOCACHE (0x200),
    // PAGE_WRITECOMBINE (0x400). Comparing the whole field for equality made a
    // guarded read/write page (0x104) match no base value at all, so it came
    // back with no permissions whatsoever — and every thread stack ends in a
    // guard page, so that misdescribed one region per thread in every process.
    let protect = protect & 0xFF;
    let readable = matches!(
        protect,
        PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READ
            | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY
    );
    let writable = matches!(
        protect,
        PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY
    );
    let executable = matches!(
        protect,
        PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY
    );
    (readable, writable, executable)
}

#[async_trait::async_trait]
impl crate::Debugger for WindowsDebugger {
    fn name(&self) -> &str {
        "windows-debugapi"
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
        // See `linux_debugger.rs`'s identical guard (found there first via
        // a live test): reject a second launch/attach on an already-
        // attached instance outright, rather than silently overwriting
        // `self.cmd_tx`/`self.pid` and leaking the first process as a
        // permanently orphaned, still-running process.
        if self.pid.lock().is_some() {
            return Err(DebugError::LaunchError(
                "this WindowsDebugger instance is already attached to a process — detach/kill it before launching another".into(),
            ));
        }
        let pid = self.spawn_loop(Command::DoLaunch(Box::new(opts)))?;
        *self.pid.lock() = Some(pid);
        Ok(pid)
    }

    async fn attach(&self, pid: ProcessId) -> Result<(), DebugError> {
        if self.pid.lock().is_some() {
            return Err(DebugError::LaunchError(
                "this WindowsDebugger instance is already attached to a process — detach/kill it before attaching to another".into(),
            ));
        }
        let started = self.spawn_loop(Command::DoAttach(pid.0))?;
        *self.pid.lock() = Some(started);
        Ok(())
    }

    async fn detach(&self) -> Result<(), DebugError> {
        // Restore every installed software breakpoint's original byte
        // BEFORE detaching — see `linux_debugger.rs`'s identical fix for
        // the full rationale (found there first via a live test): a
        // leftover `0xCC` in the process's own code raises an exception
        // the instant it's next executed, and with no debugger attached
        // anymore, that's fatal to the process. "Detach" should mean "keep
        // running undisturbed."
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
        *self.cmd_tx.lock() = None;
        match reply {
            Reply::Ack(r) => r,
            _ => Ok(()),
        }
    }

    async fn kill(&self) -> Result<(), DebugError> {
        let reply = self.send(Command::Kill)?;
        *self.pid.lock() = None;
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
            self.step_off_planted_breakpoint(None).await;
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
                if let Err(e) = self.rewind_past_own_breakpoint(ev).await {
                    return Err(e);
                }
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
            self.ignore_counts.lock().remove(&addr.as_u64());
        self.thread_filters.lock().remove(&addr.as_u64());
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
        if let Some(ev) = self.step_off_planted_breakpoint(Some(tid)).await {
            *self.current_tid.lock() = Some(ev.tid);
            if ev.reason.is_exit() {
                self.retire_session_after_exit();
            }
            return Ok(ev);
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
        // was the process's last instruction, `get_registers` on the
        // now-gone process fails, masking a valid `ProcessExit` event with
        // a spurious error. Check exit first.
        if event.reason.is_exit() {
            return Ok(event);
        }
        let after = self.get_registers(tid).await?;

        // `sp` shrinking is what identifies a `call`: it pushed a return
        // address. Anything else — including a jump, which moves `pc`
        // without touching `sp` — was fully executed by the single step.
        //
        // A preceding `after.sp >= before.sp && after.pc == return_addr`
        // branch used to sit here. It was dead: every input satisfying it
        // also satisfies the `sp` test below, so it could never change the
        // outcome, and its comment contradicted the one it sat above by
        // claiming a moved `pc` implies a call. Linux and macOS never had it.
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
        let return_addr = u64::from_le_bytes(
            return_addr_bytes[..8].try_into().map_err(|_| DebugError::StepError("step_out: short read".into()))?,
        );
        self.run_to_return(tid, Address(return_addr), caller_sp).await
    }

    async fn pause(&self) -> Result<(), DebugError> {
        let pid = self.pid.lock().ok_or(DebugError::NotAttached)?;
        unsafe {
            let handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid.0);
            if handle.is_null() {
                return Err(DebugError::StepError(format!(
                    "OpenProcess failed for pause: {}",
                    GetLastError()
                )));
            }
            let ok = DebugBreakProcess(handle);
            CloseHandle(handle);
            if ok == TRUE {
                Ok(())
            } else {
                Err(DebugError::StepError(format!("DebugBreakProcess failed: {}", GetLastError())))
            }
        }
    }

    async fn threads(&self) -> Result<Vec<ThreadId>, DebugError> {
        let pid = self.pid.lock().ok_or(DebugError::NotAttached)?;
        // Real enumeration via toolhelp, mirroring `modules()` above — the
        // previous implementation forwarded to `Command::Threads`, which only
        // ever reported the single last-known-stopping thread despite a
        // comment claiming toolhelp enumeration happened "by the caller" (it
        // never did, so multi-threaded targets silently lost every thread
        // but the one that most recently hit a debug event).
        let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
        if snapshot == INVALID_HANDLE_VALUE {
            return Err(DebugError::MemoryError(
                0,
                format!("CreateToolhelp32Snapshot failed: {}", unsafe { GetLastError() }),
            ));
        }
        let mut result = Vec::new();
        let mut entry: THREADENTRY32 = unsafe { zeroed() };
        entry.dwSize = size_of::<THREADENTRY32>() as DWORD;
        let mut first = true;
        loop {
            let ok = if first {
                first = false;
                unsafe { Thread32First(snapshot, &mut entry) }
            } else {
                unsafe { Thread32Next(snapshot, &mut entry) }
            };
            if ok == FALSE {
                break;
            }
            if entry.th32OwnerProcessID == pid.0 {
                result.push(ThreadId(entry.th32ThreadID));
            }
        }
        unsafe {
            CloseHandle(snapshot);
        }
        Ok(result)
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
        regs.get(name).ok_or_else(|| DebugError::RegisterError(format!("unknown register {name}")))
    }

    async fn set_register(&self, tid: ThreadId, name: &str, value: u64) -> Result<(), DebugError> {
        let mut regs = self.get_registers(tid).await?;
        // Refuse exactly what `get_register` refuses. `RegisterSet::set`
        // inserts ANY name into its map, and the backend then applies only the
        // names it recognises when writing the thread context — so a typo
        // (`eip` for `rip`, `x0` on x86) was accepted, silently dropped, and
        // reported as success. Reading that same name answers "unknown
        // register": the two halves of the API were giving opposite answers
        // about the same register, and the write was the one that lied.
        if regs.get(name).is_none() {
            return Err(DebugError::RegisterError(format!("unknown register {name}")));
        }
        regs.set(name, value);
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
        let handle = unsafe { OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid.0) };
        if handle.is_null() {
            return Err(DebugError::MemoryError(
                0,
                format!("OpenProcess failed for memory_maps: {}", unsafe { GetLastError() }),
            ));
        }
        let mut maps = Vec::new();
        let mut addr: u64 = 0;
        loop {
            let mut info: MEMORY_BASIC_INFORMATION = unsafe { zeroed() };
            let written = unsafe {
                VirtualQueryEx(handle, addr as *const _, &mut info, size_of::<MEMORY_BASIC_INFORMATION>())
            };
            if written == 0 {
                break;
            }
            if info.State != MEM_FREE {
                let (readable, writable, executable) = classify_protection(info.Protect);
                // `GetMappedFileNameW` resolves a region's backing file, if
                // any (device-namespace path, e.g. `\Device\HarddiskVolume3\
                // Windows\System32\ntdll.dll` — not translated to a drive
                // letter, but real, non-`None` data rather than nothing).
                // Anonymous/private regions (heap, stack) have no backing
                // file and correctly return 0 here, matching Linux's
                // `memory_maps` leaving `name`/`file_path` `None` for those.
                let mut file_path_buf = [0u16; 1024];
                let len = unsafe {
                    GetMappedFileNameW(
                        handle,
                        info.BaseAddress,
                        file_path_buf.as_mut_ptr(),
                        file_path_buf.len() as DWORD,
                    )
                };
                let file_path = (len > 0).then(|| wide_to_string(&file_path_buf[..len as usize]));
                let name = file_path.as_deref().map(|p| p.rsplit('\\').next().unwrap_or(p).to_string());

                maps.push(MemoryMap {
                    base: Address(info.BaseAddress as u64),
                    size: info.RegionSize as u64,
                    readable,
                    writable,
                    executable,
                    name,
                    file_path,
                    file_offset: 0,
                });
            }
            let next = (info.BaseAddress as u64).saturating_add(info.RegionSize as u64);
            if next <= addr {
                break;
            }
            addr = next;
        }
        unsafe {
            CloseHandle(handle);
        }
        Ok(maps)
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
        if addr.as_u64() % alignment != 0 {
            return Err(DebugError::Unsupported(format!(
                "a software breakpoint at {addr:?} is not {alignment}-byte aligned; on this                  architecture a trap there would straddle two instructions and corrupt both"
            )));
        }
        // The blanket refusal off x86 that used to sit here has been REMOVED.
        //
        // It said this backend "implants the x86 int3 (0xCC)", true when it was
        // written and no longer what this function does: the implant below
        // writes `crate::host_trap_bytes()` — `BRK #0` on AArch64, derived from
        // this crate's single arm64 encoder, four bytes wide per `trap_len`,
        // with `pc_after_trap` already accounting for the ARM-vs-x86 difference
        // in the PC reported on trap. The alignment check above already asks
        // `host_trap_alignment()`, and remains the one architecture-dependent
        // refusal this function is entitled to give.
        //
        // Removed in all THREE backends, not one. Scoping it to Linux was the
        // first instinct and it was wrong twice over: the trap derivation is
        // shared and identical, so the refusal is stale by the same argument
        // everywhere, and `the_logic_shared_by_the_three_backends_stays_identical`
        // exists precisely to stop a non-platform-specific divergence like that.
        //
        // Two of the three are PROVEN by runners that already exist and already
        // run: `ubuntu-24.04-arm` and `macos-14` (Apple Silicon) execute this
        // path on real ARM hardware. Windows-on-ARM has no runner here, so that
        // one is structurally identical and unproven — stated, not glossed.
        // Idempotency guard: calling this twice at the same address without
        // removing in between would otherwise `read_memory` the `0xCC`
        // this function itself just planted and store THAT as "original",
        // permanently corrupting the tracked byte — proved via a live test
        // on Linux (`set_breakpoint_twice_at_the_same_address_does_not_
        // corrupt_the_original_byte`); same code shape here.
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
        // See `linux_debugger.rs`'s identical fix: track only AFTER the
        // `0xCC` write is confirmed, so a failed write doesn't leave a
        // phantom tracked entry for a breakpoint that was never installed.
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
        // Actually program the debug registers. Without this the trait default
        // forwarded to `set_breakpoint`, which rejects everything that is not
        // `Software`, so every hardware watchpoint request on this backend
        // failed outright.
        if matches!(kind, BreakpointKind::Software) {
            return self.set_breakpoint(addr, kind).await;
        }
        if !cfg!(any(target_arch = "x86_64", target_arch = "x86")) {
            return Err(DebugError::Unsupported(
                "hardware watchpoints on this backend program the x86 debug registers,                  which this host architecture does not have".into(),
            ));
        }
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
            None => crate::x86_free_watchpoint_slot(combined_dr7).ok_or_else(|| {
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
        // See `linux_debugger.rs`'s identical fix: look up (don't remove
        // yet) so a failed `write_memory` leaves the entry tracked, rather
        // than untracking a breakpoint whose byte was never actually
        // restored — which would make `detach()`'s cleanup sweep silently
        // skip it.
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
        // Collect the raw toolhelp entries in their own block scope so every
        // non-`Send` raw-pointer local (`snapshot: HANDLE`, `entry:
        // MODULEENTRY32W`'s `hModule`) is fully dropped before the `.await`
        // below — `pe_entry_point` reads live process memory asynchronously,
        // and any of these still being *in scope* (regardless of being
        // logically unused) at that point makes this function's future
        // `!Send`.
        let mut modules = {
            let pid = self.pid.lock().ok_or(DebugError::NotAttached)?;
            // Retry ERROR_BAD_LENGTH: the loader may still be populating the
            // module list, which is precisely the moment a debugger asks.
            let snapshot = snapshot_with_retry(INVALID_HANDLE_VALUE, 8, || {
                let h = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid.0) };
                let e = if h == INVALID_HANDLE_VALUE { unsafe { GetLastError() } } else { 0 };
                (h, e)
            })
            .map_err(|e| DebugError::MemoryError(0, format!("CreateToolhelp32Snapshot failed: {e}")))?;
            let mut modules = Vec::new();
            let mut entry: MODULEENTRY32W = unsafe { zeroed() };
            entry.dwSize = size_of::<MODULEENTRY32W>() as DWORD;
            let mut first = true;
            loop {
                let ok = if first {
                    first = false;
                    unsafe { Module32FirstW(snapshot, &mut entry) }
                } else {
                    unsafe { Module32NextW(snapshot, &mut entry) }
                };
                if ok == FALSE {
                    break;
                }
                let name = wide_to_string(&entry.szModule);
                let path = wide_to_string(&entry.szExePath);
                modules.push(ModuleInfo {
                    is_main: modules.is_empty(),
                    name,
                    path,
                    base: Address(entry.modBaseAddr as u64),
                    size: u64::from(entry.modBaseSize),
                    entry_point: None,
                });
            }
            unsafe {
                CloseHandle(snapshot);
            }
            modules
        };
        for module in &mut modules {
            module.entry_point = self.pe_entry_point(module.base).await;
        }
        Ok(modules)
    }

    async fn backtrace(&self, tid: ThreadId) -> Result<Vec<StackFrame>, DebugError> {
        let regs = self.get_registers(tid).await?;
        let pc = regs.pc;
        let sp = regs.sp;
        let fp = regs.fp;

        // `send` blocks synchronously on the debug-loop thread's reply channel
        // (this backend has no true async I/O — every `async fn` here just
        // blocks the calling task on a channel recv), so it's safe to call
        // from the unwinder's synchronous reader closure.
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
        // real Windows code — ntdll's own routines don't reliably preserve
        // `rbp` as a frame pointer, so there's nothing for it to chain
        // through. Continue unwinding from wherever it stopped using the
        // x64 CFI (`.pdata`/`UNWIND_INFO`) the compiler actually emits —
        // the mechanism real Windows debuggers use. Best-effort: any
        // lookup/read/parse failure at any step just stops here, keeping
        // whatever frames were already found rather than erroring the
        // whole call.
        if let Some(last) = frames.last() {
            let mut cur_pc = last.pc.as_u64();
            let mut cur_sp = last.sp.as_u64();
            // Cache each distinct module's `.pdata` bytes for the
            // duration of this single `backtrace()` call — mirrors
            // `linux_debugger.rs`'s identical `.eh_frame` cache: a call
            // stack commonly stays within the same module across multiple
            // unwind steps, and re-reading the exception directory +
            // re-fetching its (potentially large) `.pdata` bytes from live
            // process memory on every single frame would be needless
            // repeated round-trips for data that cannot change mid-call.
            let mut pdata_cache: std::collections::HashMap<u64, Option<Vec<u8>>> = std::collections::HashMap::new();
            if let Ok(modules) = self.modules().await {
                for _ in 0..32 {
                    let Some(module) = modules
                        .iter()
                        .find(|m| cur_pc >= m.base.as_u64() && cur_pc < m.base.as_u64() + m.size)
                    else {
                        break;
                    };
                    let base = module.base.as_u64();
                    let Ok(rva) = u32::try_from(cur_pc - base) else { break };
                    if !pdata_cache.contains_key(&base) {
                        // Sanity bound on `exc_size` before it drives a
                        // buffer allocation + `ReadProcessMemory` call — a
                        // real `.pdata` directory is at most a few MB even
                        // for huge binaries; 256 MiB is generous but
                        // bounded. Guards against a corrupted PE's
                        // exception-directory size field driving a
                        // multi-gigabyte allocation attempt before the
                        // read even happens (matches `linux_debugger.rs`'s
                        // identical `.eh_frame` cap, iter 210).
                        const MAX_PDATA_SIZE: u32 = 256 * 1024 * 1024;
                        let pdata = match self.pe_exception_directory(module.base).await {
                            Some((exc_rva, exc_size)) if exc_size <= MAX_PDATA_SIZE => {
                                self.read_memory(Address(base + u64::from(exc_rva)), exc_size as usize).await.ok()
                            }
                            _ => None,
                        };
                        pdata_cache.insert(base, pdata);
                    }
                    let Some(pdata) = pdata_cache.get(&base).and_then(Option::as_ref) else { break };
                    let Some((func_begin, _, unwind_rva)) = find_runtime_function(pdata, rva) else { break };
                    // A real UNWIND_INFO is at most `4 + 2*255` (header +
                    // max unwind codes) bytes; 512 is a generous, safely
                    // over-sized single read.
                    let Ok(unwind_info) = self.read_memory(Address(base + u64::from(unwind_rva)), 512).await else {
                        break;
                    };
                    let Some(delta) =
                        compute_prologue_stack_delta(&unwind_info, u64::from(rva.saturating_sub(func_begin)))
                    else {
                        break;
                    };
                    // `cur_sp + delta` / `ret_addr_loc + 8` would panic on
                    // overflow in a debug build if `delta` were ever
                    // implausibly huge (corrupted stack data, adversarial
                    // input) — `checked_add` bails gracefully instead,
                    // matching this whole feature's "bail, don't
                    // guess/crash" philosophy.
                    let Some(ret_addr_loc) = cur_sp.checked_add(delta) else { break };
                    let Ok(ret_bytes) = self.read_memory(Address(ret_addr_loc), 8).await else { break };
                    let Ok(ret_bytes8): Result<[u8; 8], _> = ret_bytes.as_slice().try_into() else { break };
                    let ret_addr = u64::from_le_bytes(ret_bytes8);
                    if ret_addr == 0 {
                        break;
                    }
                    let Some(new_sp) = ret_addr_loc.checked_add(8) else { break };
                    // Look up the module covering `ret_addr` specifically
                    // — NOT the `module` variable above (covers `cur_pc`,
                    // the frame we just unwound FROM). A return address
                    // commonly lands in a DIFFERENT module, so reusing the
                    // callee's module name here would mislabel the
                    // caller's frame (same fix as `linux_debugger.rs`'s
                    // identical CFI loop).
                    let ret_module = modules
                        .iter()
                        .find(|m| ret_addr >= m.base.as_u64() && ret_addr < m.base.as_u64() + m.size)
                        .map(|m| m.name.clone());
                    frames.push(StackFrame {
                        index: frames.len(),
                        pc: Address(ret_addr),
                        sp: Address(new_sp),
                        fp: None,
                        function_name: None,
                        module: ret_module,
                        offset: None,
                        source_file: None,
                        source_line: None,
                    });
                    cur_pc = ret_addr;
                    cur_sp = new_sp;
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
// Runtime integration tests — real child process, real Win32 debug API
// ─────────────────────────────────────────────────────────────────────────────
//
// Everything above this point compiled cleanly but had never been exercised
// against a live process in any session (see `ENHANCEMENT_LOG.md` iteration
// 20's honesty caveat). These tests launch a real `cmd.exe` child under
// `WindowsDebugger` and drive the actual Win32 debug API end to end, so a
// mistake in event classification, context access, or memory R/W fails a test
// instead of silently only "compiling".
#[cfg(test)]
mod live_tests {
    use super::*;

    /// A snapshot must retry the transient failure, and only that one.
    ///
    /// `CreateToolhelp32Snapshot(TH32CS_SNAPMODULE)` fails with
    /// `ERROR_BAD_LENGTH` while the target is still building its module list;
    /// MSDN says to call it again. A debugger asks exactly then — right after
    /// `launch`, at the initial breakpoint — so without a retry `modules()`
    /// reported a hard error for a healthy process, indistinguishable from a
    /// real one.
    ///
    /// The policy must stay narrow: any OTHER error is a genuine failure and
    /// retrying it would just stall the caller.
    #[test]
    fn a_toolhelp_snapshot_retries_only_the_transient_failure() {
        const INVALID: i32 = -1;

        // Succeeds on the third attempt, as a loader race would.
        let mut n = 0;
        let got = snapshot_with_retry(INVALID, 8, || {
            n += 1;
            if n < 3 { (INVALID, ERROR_BAD_LENGTH) } else { (42, 0) }
        });
        assert_eq!(got, Ok(42));
        assert_eq!(n, 3, "it must keep trying while the error stays transient");

        // A different error is final: exactly one attempt, and it is reported.
        let mut n = 0;
        let got = snapshot_with_retry(INVALID, 8, || {
            n += 1;
            (INVALID, 5) // ERROR_ACCESS_DENIED
        });
        assert_eq!(got, Err(5), "a real failure must surface, not be retried away");
        assert_eq!(n, 1, "retrying a permanent error only stalls the caller");

        // Persistent transient error: bounded, and the error is preserved.
        let mut n = 0;
        let got = snapshot_with_retry(INVALID, 4, || {
            n += 1;
            (INVALID, ERROR_BAD_LENGTH)
        });
        assert_eq!(got, Err(ERROR_BAD_LENGTH));
        assert_eq!(n, 4, "the attempt count must be bounded");

        // The OLD behaviour, expressed as a single attempt: the same healthy
        // process that succeeds above is reported as a hard failure. This is
        // what the fix changes.
        let mut n = 0;
        let old_behaviour = snapshot_with_retry(INVALID, 1, || {
            n += 1;
            if n < 3 { (INVALID, ERROR_BAD_LENGTH) } else { (42, 0) }
        });
        assert_eq!(
            old_behaviour,
            Err(ERROR_BAD_LENGTH),
            "with one attempt the loader race surfaces as an error — the defect"
        );

        // First attempt succeeds: no retry at all.
        let mut n = 0;
        let got = snapshot_with_retry(INVALID, 8, || {
            n += 1;
            (7, 0)
        });
        assert_eq!((got, n), (Ok(7), 1));
    }

    /// `PAGE_GUARD` and friends are FLAGS ORed onto the protection, not values.
    ///
    /// The decoding compared `Protect` for exact equality against the eight base
    /// constants. But Windows ORs modifier bits into that same field:
    /// `PAGE_GUARD` (0x100), `PAGE_NOCACHE` (0x200), `PAGE_WRITECOMBINE` (0x400).
    /// A guarded read/write page reports `0x104`, which equals none of the base
    /// values, so the region came back as **not readable, not writable, not
    /// executable** — no permissions at all.
    ///
    /// This is not an exotic case: every thread's stack ends in a `PAGE_GUARD`
    /// page (that is how Windows grows stacks), so a memory map of any live
    /// process misdescribed one region per thread. Anything scanning for
    /// writable memory skipped them.
    #[test]
    fn protection_flags_do_not_hide_the_underlying_permissions() {
        // Plain values keep decoding as before.
        assert_eq!(classify_protection(PAGE_READONLY), (true, false, false));
        assert_eq!(classify_protection(PAGE_READWRITE), (true, true, false));
        assert_eq!(classify_protection(PAGE_EXECUTE_READ), (true, false, true));
        assert_eq!(classify_protection(PAGE_EXECUTE_READWRITE), (true, true, true));
        assert_eq!(classify_protection(0x01), (false, false, false), "PAGE_NOACCESS");

        // The same values with modifier flags must decode identically.
        const PAGE_GUARD: u32 = 0x100;
        const PAGE_NOCACHE: u32 = 0x200;
        const PAGE_WRITECOMBINE: u32 = 0x400;
        assert_eq!(
            classify_protection(PAGE_READWRITE | PAGE_GUARD),
            (true, true, false),
            "a guard page is still a read/write page — that is how thread stacks grow"
        );
        assert_eq!(
            classify_protection(PAGE_EXECUTE_READ | PAGE_NOCACHE),
            (true, false, true)
        );
        assert_eq!(
            classify_protection(PAGE_READWRITE | PAGE_WRITECOMBINE),
            (true, true, false)
        );
        assert_eq!(
            classify_protection(PAGE_READONLY | PAGE_GUARD | PAGE_NOCACHE),
            (true, false, false)
        );
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
    /// A committed, EXECUTABLE page in the target that nothing ever jumps to.
    ///
    /// Tests that need an "unreachable target" for `run_to_return` used to
    /// pass `regs.sp`. That is unreachable, but it is DATA: planting the
    /// breakpoint there wrote an `int3` into the target's stack, which is the
    /// corruption `run_to_return` now refuses outright. Executable memory
    /// keeps the tests' intent (never reached) without the damage.
    fn alloc_unreachable_code_page(dbg: &WindowsDebugger) -> u64 {
        use winapi::um::memoryapi::VirtualAllocEx;
        use winapi::um::winnt::{MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE};
        let pid = dbg.target_pid().expect("attached").0;
        unsafe {
            let h = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
            assert!(!h.is_null(), "OpenProcess should succeed");
            let p = VirtualAllocEx(
                h,
                std::ptr::null_mut(),
                4096,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE,
            );
            CloseHandle(h);
            assert!(!p.is_null(), "VirtualAllocEx should succeed");
            p as u64
        }
    }

    #[tokio::test]
    async fn a_failed_detach_keeps_the_breakpoint_bookkeeping() {
        let dbg = WindowsDebugger::new();
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

    /// Hand-builds a synthetic `IMAGE_NT_HEADERS64` buffer with a real
    /// `IMAGE_DIRECTORY_ENTRY_EXCEPTION` (index 3) entry at the correct
    /// byte offset (136 + 3*8 = 160) and verifies `parse_pe_data_directory`
    /// reads it back. Pure byte-buffer test.
    #[test]
    fn parse_pe_data_directory_reads_the_exception_directory() {
        let mut nt = vec![0u8; 200];
        nt[0..4].copy_from_slice(b"PE\0\0");
        nt[160..164].copy_from_slice(&0x2000u32.to_le_bytes()); // RVA
        nt[164..168].copy_from_slice(&0x300u32.to_le_bytes()); // Size
        let (rva, size) = parse_pe_data_directory(&nt, 3).expect("should parse");
        assert_eq!(rva, 0x2000);
        assert_eq!(size, 0x300);
    }

    #[test]
    fn parse_pe_data_directory_rejects_bad_signature() {
        let mut nt = vec![0u8; 200];
        nt[0..4].copy_from_slice(b"XXXX");
        assert!(parse_pe_data_directory(&nt, 3).is_none());
    }

    #[test]
    fn parse_pe_data_directory_treats_zero_entry_as_absent() {
        let mut nt = vec![0u8; 200];
        nt[0..4].copy_from_slice(b"PE\0\0");
        // RVA/Size left as 0 — a real PE with no exception directory (e.g.
        // an x86 binary, or one with no unwind info at all) encodes it
        // this way; must be treated as "absent," not a zero-sized region.
        assert!(parse_pe_data_directory(&nt, 3).is_none());
    }

    /// Hand-builds a small, sorted `.pdata` array (3 `RUNTIME_FUNCTION`
    /// entries) and verifies `find_runtime_function` locates the entry
    /// covering a given RVA via binary search, including RVAs that fall
    /// in the gaps between functions (correctly `None`) and at exact
    /// boundaries (`begin` inclusive, `end` exclusive). Pure byte-buffer
    /// test.
    #[test]
    fn find_runtime_function_locates_the_covering_entry() {
        fn entry(begin: u32, end: u32, unwind_rva: u32) -> [u8; 12] {
            let mut buf = [0u8; 12];
            buf[0..4].copy_from_slice(&begin.to_le_bytes());
            buf[4..8].copy_from_slice(&end.to_le_bytes());
            buf[8..12].copy_from_slice(&unwind_rva.to_le_bytes());
            buf
        }
        let mut pdata = Vec::new();
        pdata.extend_from_slice(&entry(0x1000, 0x1050, 0xA000));
        pdata.extend_from_slice(&entry(0x1050, 0x1200, 0xA010));
        pdata.extend_from_slice(&entry(0x2000, 0x2100, 0xA020));

        assert_eq!(find_runtime_function(&pdata, 0x1020), Some((0x1000, 0x1050, 0xA000)));
        assert_eq!(find_runtime_function(&pdata, 0x1050), Some((0x1050, 0x1200, 0xA010)), "begin is inclusive");
        assert_eq!(find_runtime_function(&pdata, 0x104F), Some((0x1000, 0x1050, 0xA000)), "end is exclusive");
        assert_eq!(find_runtime_function(&pdata, 0x2050), Some((0x2000, 0x2100, 0xA020)));
        assert_eq!(find_runtime_function(&pdata, 0x1900), None, "gap between functions");
        assert_eq!(find_runtime_function(&pdata, 0x500), None, "before the first entry");
        assert_eq!(find_runtime_function(&pdata, 0x3000), None, "after the last entry");
    }

    /// Hand-builds real `UNWIND_INFO` byte buffers for a few representative
    /// prologue shapes and verifies `compute_prologue_stack_delta`
    /// computes the correct total stack displacement, and correctly bails
    /// (`None`) for the shapes it deliberately doesn't handle. Pure
    /// byte-buffer test — this is the core correctness-critical piece of
    /// the whole feature, so it gets the most scrutiny.
    #[test]
    fn compute_prologue_stack_delta_handles_representative_prologues() {
        // Leaf function: version=1, flags=0, no codes at all.
        let leaf = [0x01u8, 0x00, 0x00, 0x00];
        assert_eq!(compute_prologue_stack_delta(&leaf, u64::MAX), Some(0));

        // `push rbx` (UWOP_PUSH_NONVOL, reg=3) + `push rsi` (reg=6): two
        // 1-node codes, no frame register, no extra slots. CodeOffset
        // bytes (byte 0 of each code) are irrelevant to this function.
        let mut two_pushes = vec![0x01u8, 0x00, 0x02, 0x00]; // version=1,flags=0; CountOfCodes=2; FrameRegister=0
        two_pushes.extend_from_slice(&[0x08, 0x60]); // push rsi (op=0, info=6), CodeOffset=8
        two_pushes.extend_from_slice(&[0x05, 0x30]); // push rbx (op=0, info=3), CodeOffset=5
        assert_eq!(compute_prologue_stack_delta(&two_pushes, u64::MAX), Some(16));

        // `sub rsp, 0x28` via UWOP_ALLOC_SMALL: info=(0x28/8)-1=4.
        let mut small_alloc = vec![0x01u8, 0x00, 0x01, 0x00];
        small_alloc.extend_from_slice(&[0x04, 0x42]); // op=2(alloc_small), info=4
        assert_eq!(compute_prologue_stack_delta(&small_alloc, u64::MAX), Some(0x28));

        // UWOP_ALLOC_LARGE, info=0: one extra u16 slot holding size/8.
        let mut large_alloc = vec![0x01u8, 0x00, 0x02, 0x00];
        large_alloc.extend_from_slice(&[0x04, 0x01]); // op=1(alloc_large), info=0
        large_alloc.extend_from_slice(&(0x100u16).to_le_bytes()); // size/8 = 0x100 -> size=0x800
        assert_eq!(compute_prologue_stack_delta(&large_alloc, u64::MAX), Some(0x800));

        // A frame register alone (FrameRegister != 0, no codes) does not
        // move RSP: UWOP_SET_FPREG only records that a frame pointer was
        // established, so the delta is still computable (here: 0).
        let fpreg = [0x01u8, 0x00, 0x00, 0x05]; // FrameRegister=5 (rbp)
        assert_eq!(compute_prologue_stack_delta(&fpreg, u64::MAX), Some(0));

        // A `SAVE_NONVOL` code (register save, doesn't move rsp) mixed
        // with a push — only the push should count.
        let mut save_and_push = vec![0x01u8, 0x00, 0x03, 0x00];
        save_and_push.extend_from_slice(&[0x0A, 0x44]); // op=4(save_nonvol), info=4
        save_and_push.extend_from_slice(&(0x10u16).to_le_bytes()); // offset/8 slot
        save_and_push.extend_from_slice(&[0x03, 0x50]); // push r13 (op=0, info=5)
        assert_eq!(compute_prologue_stack_delta(&save_and_push, u64::MAX), Some(8));

        // Chained unwind info (UNW_FLAG_CHAININFO, flags bit 0x04) must
        // bail rather than ignore the chain.
        let chained = [0x01u8 | (0x04 << 3), 0x00, 0x00, 0x00];
        assert_eq!(compute_prologue_stack_delta(&chained, u64::MAX), None);

        // Truncated buffer (claims more codes than are actually present).
        let truncated = [0x01u8, 0x00, 0x05, 0x00, 0x00, 0x00];
        assert_eq!(compute_prologue_stack_delta(&truncated, u64::MAX), None);
    }

    /// Unwind codes that have not executed yet must not be counted.
    ///
    /// Every `UNWIND_CODE` carries a `CodeOffset` — the prologue offset of the
    /// instruction *after* the one performing the operation — precisely so an
    /// unwinder can tell which operations have already happened at the current
    /// PC. This function ignored that byte and always returned the delta for
    /// the WHOLE prologue.
    ///
    /// That is wrong exactly where it matters most: a breakpoint on a function
    /// is normally placed at its entry point, offset 0, where nothing has been
    /// pushed and the return address sits at `[rsp]`. Adding the full prologue
    /// delta read the return address from somewhere inside the caller's frame
    /// instead — a wrong backtrace, with no error reported. This is the same
    /// defect the DWARF interpreter had at row boundaries (iter 319), in the
    /// Windows twin.
    #[test]
    fn unwind_codes_that_have_not_executed_yet_are_not_counted() {
        // push rbx        (1 byte,  CodeOffset 1)
        // sub  rsp, 0x28  (4 bytes, CodeOffset 9 — after `mov` etc.)
        // Codes are stored in descending CodeOffset order, as in real data.
        let mut ui = vec![0x01u8, 0x09, 0x02, 0x00];
        ui.extend_from_slice(&[0x09, 0x42]); // alloc_small 0x28, CodeOffset 9
        ui.extend_from_slice(&[0x01, 0x30]); // push rbx,     CodeOffset 1

        // At the entry point nothing has executed: the return address is at
        // [rsp] and the delta is 0.
        assert_eq!(
            compute_prologue_stack_delta(&ui, 0),
            Some(0),
            "at the entry point no prologue instruction has run yet"
        );
        // After the push, before the allocation.
        assert_eq!(compute_prologue_stack_delta(&ui, 1), Some(8));
        assert_eq!(compute_prologue_stack_delta(&ui, 8), Some(8));
        // Once the allocation has run, and anywhere in the body afterwards.
        assert_eq!(compute_prologue_stack_delta(&ui, 9), Some(0x30));
        assert_eq!(compute_prologue_stack_delta(&ui, 0x1000), Some(0x30));
    }

    /// An `UNWIND_INFO` whose last code claims slots that are not there must
    /// bail, not return a partial delta.
    ///
    /// `ALLOC_LARGE` checks that its extra slots fit within `CountOfCodes`;
    /// `SAVE_NONVOL`, `SAVE_NONVOL_FAR`, `SAVE_XMM128` and `SAVE_XMM128_FAR`
    /// did not — they just advanced the cursor by 2 or 3, which walked past
    /// the end and ended the loop with `Some(delta_so_far)`.
    ///
    /// This data comes from the memory of the process being debugged, so it
    /// can be truncated or corrupt. The module's stated rule is "bail rather
    /// than guess": a partial delta is a guess, and it silently produces a
    /// wrong return address instead of no backtrace.
    #[test]
    fn a_truncated_unwind_info_bails_instead_of_returning_a_partial_delta() {
        // Each case: CountOfCodes = 2, a push that contributes 8, then an
        // opcode needing more slots than remain.
        // `slots` counts the code itself plus the extra slots it consumes, so
        // a CountOfCodes of `slots - 1` is exactly one slot short.
        for (op, slots, name) in [
            (0x44u8, 2usize, "SAVE_NONVOL"),
            (0x45, 3, "SAVE_NONVOL_FAR"),
            (0x48, 2, "SAVE_XMM128"),
            (0x49, 3, "SAVE_XMM128_FAR"),
        ] {
            let count = slots - 1;
            let mut ui = vec![0x01u8, 0x08, u8::try_from(count).unwrap(), 0x00];
            ui.extend_from_slice(&[0x08, op]); // the code that needs extra slots
            // Physically present bytes for the declared count, so the failure
            // is the declared-slot shortfall and not the buffer-length check.
            ui.resize(4 + count * 2, 0);
            assert_eq!(
                compute_prologue_stack_delta(&ui, u64::MAX),
                None,
                "{name} declares extra slots that CountOfCodes does not cover; \
                 a partial delta is a wrong return address, not a backtrace"
            );
        }

        // A well-formed SAVE_NONVOL (its extra slot is inside CountOfCodes)
        // must still work: the guard must not reject valid data.
        let mut ok = vec![0x01u8, 0x08, 0x03, 0x00]; // CountOfCodes = 3
        ok.extend_from_slice(&[0x0A, 0x44]); // SAVE_NONVOL
        ok.extend_from_slice(&(0x10u16).to_le_bytes()); // its extra slot
        ok.extend_from_slice(&[0x01, 0x30]); // push rbx
        assert_eq!(compute_prologue_stack_delta(&ok, u64::MAX), Some(8));
    }

    /// Hand-builds a minimal but structurally real `IMAGE_DOS_HEADER` +
    /// `IMAGE_NT_HEADERS64` byte buffer and verifies
    /// `parse_pe_entry_point_rva` extracts the correct `AddressOfEntryPoint`
    /// — pure byte-buffer test, no live process needed, so this is
    /// verifiable independent of the live `modules_enumerates_the_main_
    /// executable` test above (which additionally proves the live-memory
    /// read side end to end).
    #[test]
    fn parse_pe_entry_point_rva_reads_the_real_offset() {
        let mut dos = vec![0u8; 0x40];
        dos[0..2].copy_from_slice(b"MZ");
        dos[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes()); // e_lfanew

        let mut nt = vec![0u8; 44];
        nt[0..4].copy_from_slice(b"PE\0\0"); // Signature
        // FileHeader (20 bytes) — contents irrelevant to entry-point parsing.
        // OptionalHeader: Magic(2) MajorLinkerVersion(1) MinorLinkerVersion(1)
        // SizeOfCode(4) SizeOfInitializedData(4) SizeOfUninitializedData(4)
        // AddressOfEntryPoint(4) at nt[40..44].
        nt[40..44].copy_from_slice(&0x1234u32.to_le_bytes());

        let rva = parse_pe_entry_point_rva(&dos, &nt).expect("should parse a well-formed header");
        assert_eq!(rva, 0x1234);
    }

    #[test]
    fn parse_pe_entry_point_rva_rejects_bad_dos_magic() {
        let mut dos = vec![0u8; 0x40];
        dos[0..2].copy_from_slice(b"XX");
        let nt = vec![0u8; 44];
        assert!(parse_pe_entry_point_rva(&dos, &nt).is_none());
    }

    #[test]
    fn parse_pe_entry_point_rva_rejects_bad_pe_signature() {
        let mut dos = vec![0u8; 0x40];
        dos[0..2].copy_from_slice(b"MZ");
        dos[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        let mut nt = vec![0u8; 44];
        nt[0..4].copy_from_slice(b"XXXX");
        assert!(parse_pe_entry_point_rva(&dos, &nt).is_none());
    }

    #[test]
    fn parse_pe_entry_point_rva_rejects_truncated_buffers() {
        assert!(parse_pe_entry_point_rva(&[0u8; 10], &[0u8; 44]).is_none());
        assert!(parse_pe_entry_point_rva(&[0u8; 0x40], &[0u8; 10]).is_none());
    }

    fn cmd_launch_options(args: &[&str]) -> LaunchOptions {
        LaunchOptions {
            executable: "C:\\Windows\\System32\\cmd.exe".to_string(),
            args: args.iter().map(|s| (*s).to_string()).collect(),
            env: std::collections::HashMap::new(),
            working_dir: None,
            stop_at_entry: false,
            follow_forks: false,
            redirect: OutputRedirect::default(),
        }
    }

    /// A thread appearing and going away must be SAID, not filed under
    /// "unknown".
    ///
    /// `StopReason::ThreadCreate`/`ThreadExit` have existed since the enum was
    /// written, and three layers downstream are built to carry them
    /// (`cross_platform_debug`, `debug_session_manager::SessionEvent`,
    /// `debug_session_recorder`) — yet NO backend had ever produced one.
    /// Windows delivers these events unconditionally and they were landing in
    /// the catch-all arm as `Unknown { "debug event code 2" }`.
    ///
    /// Live, against a real child: `cmd /C start /B` makes the shell spin up
    /// work of its own, and the loader's own threads arrive the same way. The
    /// assertion is on the CLASSIFICATION, not on how many threads Windows
    /// happens to create: if any thread event arrives it must be named, and
    /// none may still be reported as an unknown event code.
    #[tokio::test]
    async fn a_thread_appearing_is_classified_not_filed_as_unknown() {
        let dbg = WindowsDebugger::new();
        dbg.launch(cmd_launch_options(&["/C", "echo hi >NUL"]))
            .await
            .expect("launch should succeed against a real cmd.exe");

        let mut thread_events = 0usize;
        let mut unknown_thread_codes = Vec::new();
        for _ in 0..2000 {
            let event = dbg.continue_execution().await.expect("continue_execution should not error");
            match &event.reason {
                StopReason::ThreadCreate { .. } | StopReason::ThreadExit { .. } => {
                    thread_events += 1;
                }
                // 2 = CREATE_THREAD_DEBUG_EVENT, 4 = EXIT_THREAD_DEBUG_EVENT.
                // Seeing either here means the classifier let it through.
                StopReason::Unknown { description }
                    if description == "debug event code 2" || description == "debug event code 4" =>
                {
                    unknown_thread_codes.push(description.clone());
                }
                r if r.is_exit() => break,
                _ => {}
            }
        }

        assert!(
            unknown_thread_codes.is_empty(),
            "a thread event reached the caller unclassified: {unknown_thread_codes:?}"
        );
        assert!(
            thread_events > 0,
            "no thread lifetime event was observed at all, so this test proved nothing"
        );
    }

    /// Launch a real child process, run the debug-event loop until it exits,
    /// and confirm we actually observe a `ProcessExit` — proves
    /// `CreateProcessA`, the dedicated event-loop thread, `WaitForDebugEvent`,
    /// and `ContinueDebugEvent` all work end to end against a live process.
    #[tokio::test]
    async fn launch_and_run_to_exit() {
        let dbg = WindowsDebugger::new();
        let pid = dbg
            .launch(cmd_launch_options(&["/C", "exit", "0"]))
            .await
            .expect("launch should succeed against a real cmd.exe");
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

        // The process is gone, and so is the event loop that served it: every
        // later `send` fails. Reporting "attached" here is a claim about a
        // process that no longer exists, and it used to make the instance
        // permanently unusable — `detach`/`kill` need the dead loop, and
        // `attach` refuses while `pid` is set, so a debugger whose target
        // simply ran to completion could never be reused.
        assert!(
            !dbg.is_attached(),
            "a debugger whose target exited must not still report itself attached"
        );
        assert_eq!(dbg.target_pid(), None);

        // And the instance is genuinely reusable, which is the point.
        let second = dbg
            .launch(cmd_launch_options(&["/C", "exit", "0"]))
            .await
            .expect("the same debugger must be able to launch again after its target exited");
        assert_eq!(dbg.target_pid(), Some(second));
        let _ = dbg.kill().await;
    }

    /// `attach` against a genuinely independent, already-running process —
    /// distinct from every other test in this module, which all go through
    /// `launch` (`CreateProcessA` under `DEBUG_PROCESS`). `Debugger::attach`
    /// had ZERO live test coverage anywhere in this crate before this test,
    /// on either platform — mirrors
    /// `linux_debugger::live_tests::attach_to_an_independently_spawned_process`.
    /// Spawns a real, long-lived `ping` (present on every Windows install,
    /// loops for several seconds without needing a console/TTY — unlike
    /// `timeout.exe`, which refuses to run without interactive input) via
    /// plain `std::process::Command`, then `DebugActiveProcess`-attaches to
    /// it. Unlike Linux (whose `do_attach` synchronously reaps the
    /// attach-stop before `attach()` returns), Windows' `DebugActiveProcess`
    /// does NOT deliver any debug event synchronously — the first
    /// `WaitForDebugEvent` only happens inside `continue_execution`'s loop,
    /// so `current_thread()` is expected to still report `NotAttached`
    /// immediately post-attach here, and only succeed after the loop below
    /// reaches the first real event. This is a genuine platform difference
    /// (not a bug — see iter 139/142's memory notes on why the equivalent
    /// Linux fix does NOT apply to Windows).
    #[tokio::test]
    async fn attach_to_an_independently_spawned_process() {
        let mut child = std::process::Command::new("C:\\Windows\\System32\\PING.EXE")
            .args(["-n", "6", "127.0.0.1"])
            .spawn()
            .expect("spawning the target process should succeed");
        let target_pid = child.id();

        let dbg = WindowsDebugger::new();
        dbg.attach(ProcessId(target_pid)).await.expect("attach should succeed against an independent process");
        assert!(dbg.is_attached());
        assert_eq!(dbg.target_pid(), Some(ProcessId(target_pid)));

        // `current_thread` is unpopulated until the debug-event loop runs at
        // least once — a real platform difference from Linux, not a bug.
        assert!(matches!(dbg.current_thread().await, Err(DebugError::NotAttached)));

        let mut got_event = false;
        for _ in 0..50 {
            match dbg.continue_execution().await {
                Ok(event) => {
                    got_event = true;
                    if event.reason.is_exit() {
                        break;
                    }
                    let current = dbg.current_thread().await.expect("current_thread should succeed after any debug event");
                    assert_eq!(current, event.tid, "current_thread should match the thread that last stopped");
                    break;
                }
                Err(_) => break,
            }
        }
        assert!(got_event, "expected at least one debug event after attach");

        let _ = dbg.kill().await;
        let _ = child.kill();
        let _ = child.wait();
    }

    /// `detach` while a software breakpoint is still installed should NOT
    /// leave a leftover `0xCC` in the process's own code — same bug class
    /// (and same fix) as `linux_debugger.rs`'s
    /// `detach_removes_software_breakpoints_so_the_process_does_not_crash`,
    /// applied here by direct analogy: identical `breakpoints: HashMap<u64,u8>`
    /// patching structure, so the same landmine risk existed. Attaches to
    /// an independent, longer-lived `ping`, reaches a real debug event so
    /// there's a live `rip` to plant at, sets a breakpoint there, detaches,
    /// then polls `Child::try_wait()` briefly — if the landmine bug is
    /// present, the process crashes on its very next instruction (long
    /// before `ping`'s several-second natural run time), so any exit
    /// observed this quickly is proof of the bug, not coincidence.
    #[tokio::test]
    async fn detach_removes_software_breakpoints_so_the_process_does_not_crash() {
        let mut child = std::process::Command::new("C:\\Windows\\System32\\PING.EXE")
            .args(["-n", "6", "127.0.0.1"])
            .spawn()
            .expect("spawning the target process should succeed");

        let dbg = WindowsDebugger::new();
        dbg.attach(ProcessId(child.id())).await.expect("attach should succeed");

        let mut tid = None;
        for _ in 0..50 {
            match dbg.continue_execution().await {
                Ok(event) if !event.reason.is_exit() => {
                    tid = Some(event.tid);
                    break;
                }
                _ => break,
            }
        }
        let tid = tid.expect("expected at least one debug event after attach");

        let regs = dbg.get_registers(tid).await.expect("get_registers should succeed");
        dbg.set_breakpoint(Address(regs.pc), BreakpointKind::Software)
            .await
            .expect("set_breakpoint should succeed");

        dbg.detach().await.expect("detach should succeed");

        std::thread::sleep(std::time::Duration::from_millis(300));
        if let Ok(Some(status)) = child.try_wait() {
            panic!("process exited within 300ms of detach (status: {status:?}) — a leftover 0xCC breakpoint byte likely crashed it; `ping` runs for several seconds normally");
        }

        let _ = child.kill();
        let _ = child.wait();
    }

    /// `kill` should actually terminate the real OS process, not just close
    /// our handle to it. Same audit that found iter 146's Linux zombie-leak
    /// bug (`kill_actually_terminates_the_process`) — every other test here
    /// calls `dbg.kill()` purely as teardown, discarding the result, never
    /// checking the process actually died. Attaches (so a `std::process::Child`
    /// handle is available to independently verify termination via
    /// `try_wait`, without relying on the debugger's own bookkeeping) to a
    /// real `ping`, kills it through the debugger, and polls `child.try_wait()`
    /// until it reports the process exited.
    #[tokio::test]
    async fn kill_actually_terminates_the_process() {
        let mut child = std::process::Command::new("C:\\Windows\\System32\\PING.EXE")
            .args(["-n", "6", "127.0.0.1"])
            .spawn()
            .expect("spawning the target process should succeed");

        let dbg = WindowsDebugger::new();
        dbg.attach(ProcessId(child.id())).await.expect("attach should succeed");

        dbg.kill().await.expect("kill should succeed");

        let mut exited = false;
        for _ in 0..100 {
            match child.try_wait() {
                Ok(Some(_status)) => {
                    exited = true;
                    break;
                }
                Ok(None) => std::thread::sleep(std::time::Duration::from_millis(20)),
                Err(_) => break,
            }
        }
        assert!(exited, "process should have exited after dbg.kill(), but child.try_wait() never reported it gone");
        let _ = child.wait();
    }

    /// Attach the initial system breakpoint (delivered automatically under
    /// `DEBUG_PROCESS` right after the child image loads), then read the
    /// actual instruction bytes at the reported PC via `ReadProcessMemory` —
    /// proves register access and memory reads work against a real process.
    #[tokio::test]
    async fn initial_breakpoint_then_read_memory_and_registers() {
        let dbg = WindowsDebugger::new();
        dbg.launch(cmd_launch_options(&["/C", "exit", "0"]))
            .await
            .expect("launch should succeed");

        let mut hit_breakpoint = false;
        for _ in 0..50 {
            let event = dbg.continue_execution().await.expect("continue_execution should not error");
            if let StopReason::Breakpoint { address, .. } = event.reason {
                hit_breakpoint = true;
                let pc_at_breakpoint = address.as_u64();
                let regs = dbg.get_registers(event.tid).await.expect("get_registers should succeed while stopped");
                // This is the system's own initial-breakpoint `int3`, not one
                // we planted, so we never rewind `rip` for it (see
                // `rewind_past_own_breakpoint`'s doc comment) — the live
                // context's `rip` is genuinely one byte past the `int3`,
                // exactly as the real CPU left it.
                assert_eq!(
                    regs.pc,
                    pc_at_breakpoint + 1,
                    "RegisterSet.pc should be one byte past the reported breakpoint address (int3 semantics, un-rewound for a foreign breakpoint)"
                );
                let bytes = dbg
                    .read_memory(address, 16)
                    .await
                    .expect("read_memory at a live breakpoint address should succeed");
                assert_eq!(bytes.len(), 16);
                break;
            }
            if event.reason.is_exit() {
                break;
            }
        }
        assert!(hit_breakpoint, "expected the initial system breakpoint within 50 debug events");

        // Drain to exit so the debug thread's loop terminates cleanly.
        for _ in 0..2000 {
            match dbg.continue_execution().await {
                Ok(event) if event.reason.is_exit() => break,
                Ok(_) => continue,
                Err(_) => break,
            }
        }
    }

    /// Software breakpoint round trip: patch `0xCC` at the current PC via
    /// `set_breakpoint`, verify the byte actually changed via `read_memory`,
    /// then `remove_breakpoint` and verify the original byte comes back —
    /// proves `WriteProcessMemory`/`ReadProcessMemory` and the breakpoint
    /// bookkeeping work against a real process, not just the mock.
    #[tokio::test]
    async fn software_breakpoint_patches_and_restores_the_original_byte() {
        let dbg = WindowsDebugger::new();
        dbg.launch(cmd_launch_options(&["/C", "exit", "0"]))
            .await
            .expect("launch should succeed");

        // Wait for the initial breakpoint so the child is definitely stopped
        // and its image is mapped before we poke at its memory.
        let mut addr = None;
        for _ in 0..50 {
            let event = dbg.continue_execution().await.expect("continue_execution should not error");
            if let StopReason::Breakpoint { address, .. } = event.reason {
                addr = Some(address);
                break;
            }
            if event.reason.is_exit() {
                break;
            }
        }
        let addr = addr.expect("expected the initial system breakpoint");

        let original = dbg.read_memory(addr, 1).await.expect("read_memory should succeed").to_vec();

        dbg.set_breakpoint(addr, BreakpointKind::Software)
            .await
            .expect("set_breakpoint should succeed against a live process");
        // Same as the Linux twin: `read_memory` masks the implant now, so
        // the assertion below needs the raw view to mean anything.
        let patched = dbg.read_memory_raw(addr, 1).await.expect("read_memory should succeed");
        assert_eq!(patched[0], 0xCC, "byte at the breakpoint address should now be INT3");

        dbg.remove_breakpoint(addr).await.expect("remove_breakpoint should succeed");
        let restored = dbg.read_memory(addr, 1).await.expect("read_memory should succeed");
        assert_eq!(restored, original, "removing the breakpoint should restore the original byte");

        let _ = dbg.kill().await;
    }

    /// Two parallel `set_breakpoint` calls for one address must not corrupt
    /// the tracked original byte.
    ///
    /// HONEST STATUS: this is a regression PIN, not the proof of a bug. The
    /// invariant it asserts is real and worth holding, but it passes against
    /// the pre-reservation code too — measured, over 40 rounds and three
    /// separate runs. The window between `set_breakpoint`'s read and its write
    /// is a couple of channel round-trips wide and this harness never landed
    /// in it. What the reservation closes is a check-then-act across two
    /// `await` points; that the corruption is REACHABLE in practice is
    /// argued, not demonstrated.
    ///
    /// `send()` serialises each individual request/reply exchange, so the
    /// interleaving needs to fall between two exchanges, not inside one —
    /// which is why cooperative `join!` on a single-threaded runtime cannot
    /// produce it at all and even two worker threads rarely do.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn two_concurrent_set_breakpoints_do_not_corrupt_the_original_byte() {
        let dbg = std::sync::Arc::new(WindowsDebugger::new());
        dbg.launch(cmd_launch_options(&["/C", "exit", "0"]))
            .await
            .expect("launch should succeed");

        let mut addr = None;
        for _ in 0..50 {
            let event = dbg.continue_execution().await.expect("continue_execution should not error");
            if let StopReason::Breakpoint { address, .. } = event.reason {
                addr = Some(address);
                break;
            }
            if event.reason.is_exit() {
                break;
            }
        }
        let addr = addr.expect("expected the initial system breakpoint");

        let true_original = dbg.read_memory(addr, 1).await.expect("read_memory should succeed")[0];

        // Real parallelism, not cooperative interleaving: the awaits inside
        // `set_breakpoint` are blocking channel round-trips that never yield,
        // so `join!` on one task runs the first call to completion and the
        // race never happens. Two worker threads are what actually overlaps
        // them. Repeated, because the window is a few instructions wide.
        for _ in 0..40 {
            let d1 = std::sync::Arc::clone(&dbg);
            let d2 = std::sync::Arc::clone(&dbg);
            let h1 = tokio::spawn(async move { d1.set_breakpoint(addr, BreakpointKind::Software).await });
            let h2 = tokio::spawn(async move { d2.set_breakpoint(addr, BreakpointKind::Software).await });
            let _ = h1.await.expect("task 1 must not panic");
            let _ = h2.await.expect("task 2 must not panic");
            let listed = dbg.breakpoints().await.expect("breakpoints should succeed");
            let tracked = listed.iter().find(|bp| bp.address == addr).and_then(|bp| bp.original_byte);
            assert_eq!(
                tracked, Some(true_original),
                "the tracked original became {tracked:?} instead of {true_original:#x} — one call stored the other call's trap byte"
            );
            dbg.remove_breakpoint(addr).await.expect("remove_breakpoint should succeed");
        }
        dbg.set_breakpoint(addr, BreakpointKind::Software).await.expect("final set_breakpoint");

        // The tracked original is what `remove_breakpoint` will write back, so
        // read it through the public listing rather than inferring it.

        dbg.remove_breakpoint(addr).await.expect("remove_breakpoint should succeed");
        let restored = dbg.read_memory(addr, 1).await.expect("read_memory should succeed")[0];
        assert_eq!(
            restored, true_original,
            "remove_breakpoint restored {restored:#x} instead of {true_original:#x} — the landmine is planted"
        );

        let _ = dbg.kill().await;
    }
    /// Mirrors `linux_debugger::live_tests::set_breakpoint_twice_at_the_
    /// same_address_does_not_corrupt_the_original_byte` — this backend's
    /// `set_breakpoint` carries the identical idempotency guard (same code
    /// shape, same fix), but never had its own dedicated Windows-side live
    /// test proving it: without the guard, a second `set_breakpoint` call
    /// at an already-armed address would `read_memory` its own `0xCC` back
    /// as "the original byte", permanently corrupting the tracked restore
    /// value.
    #[tokio::test]
    async fn set_breakpoint_twice_at_the_same_address_does_not_corrupt_the_original_byte() {
        let dbg = WindowsDebugger::new();
        dbg.launch(cmd_launch_options(&["/C", "exit", "0"]))
            .await
            .expect("launch should succeed");

        let mut addr = None;
        for _ in 0..50 {
            let event = dbg.continue_execution().await.expect("continue_execution should not error");
            if let StopReason::Breakpoint { address, .. } = event.reason {
                addr = Some(address);
                break;
            }
            if event.reason.is_exit() {
                break;
            }
        }
        let addr = addr.expect("expected the initial system breakpoint");

        let true_original = dbg.read_memory(addr, 1).await.expect("read_memory should succeed")[0];

        dbg.set_breakpoint(addr, BreakpointKind::Software).await.expect("first set_breakpoint should succeed");
        dbg.set_breakpoint(addr, BreakpointKind::Software).await.expect("second set_breakpoint (already enabled) should succeed");

        dbg.remove_breakpoint(addr).await.expect("remove_breakpoint should succeed");
        let restored = dbg.read_memory(addr, 1).await.expect("read_memory should succeed")[0];
        assert_eq!(
            restored, true_original,
            "remove_breakpoint restored {restored:#x}, but the true original byte was {true_original:#x} — \
             the second set_breakpoint call corrupted the tracked original"
        );

        let _ = dbg.kill().await;
    }

    /// Launch a real child, wait for it to be stopped at the initial
    /// `pause` then `detach` must leave the target RUNNING — the Windows twin
    /// of `linux_debugger`'s `pause_then_detach_leaves_the_process_actually_
    /// running`, which Linux has had for a while and Windows never did.
    ///
    /// It is not a formality here: `DebugBreakProcess` works by injecting a
    /// thread that executes an `int3`. Detaching without consuming that
    /// exception hands a live `EXCEPTION_BREAKPOINT` to a process that no
    /// longer has a debugger — and the default disposition for an unhandled
    /// breakpoint exception is to terminate it. That is the same shape as the
    /// SIGSTOP-left-set defect the Linux test guards against.
    ///
    /// The existing `pause_succeeds_against_a_live_process` only asserts the
    /// Win32 call returns TRUE, which cannot see any of this.
    #[tokio::test]
    async fn pause_then_detach_leaves_the_process_actually_running() {
        use winapi::um::processthreadsapi::{GetExitCodeProcess, OpenProcess};
        use winapi::um::winnt::PROCESS_QUERY_INFORMATION;
        use winapi::um::minwinbase::STILL_ACTIVE;

        let dbg = WindowsDebugger::new();
        let pid = dbg
            .launch(cmd_launch_options(&["/C", "ping", "-n", "5", "127.0.0.1"]))
            .await
            .expect("launch should succeed");

        for _ in 0..50 {
            let ev = dbg.continue_execution().await.expect("continue_execution");
            if matches!(ev.reason, StopReason::Breakpoint { .. }) || ev.reason.is_exit() {
                break;
            }
        }

        dbg.pause().await.expect("pause should succeed");
        dbg.detach().await.expect("detach should succeed");

        // Two questions, not one. "Still alive" alone would also be true of a
        // process left permanently SUSPENDED, which is just as broken a
        // detach. `ping -n 5` runs for about four seconds and then exits on
        // its own, so a target that genuinely resumed must (a) still be there
        // shortly after the detach and (b) reach its own exit unaided.
        let state = |want_active: bool| unsafe {
            let h = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid.0);
            if h.is_null() {
                return !want_active; // gone
            }
            let mut code: DWORD = 0;
            let ok = GetExitCodeProcess(h, &mut code);
            CloseHandle(h);
            let active = ok == TRUE && code == STILL_ACTIVE as DWORD;
            active == want_active
        };

        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        let alive = state(true);

        // ...and it must make progress to its own termination, which a
        // suspended process never would.
        let mut exited_on_its_own = false;
        for _ in 0..120 {
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            if state(false) {
                exited_on_its_own = true;
                break;
            }
        }
        // Clean up regardless of the outcome.
        unsafe {
            let h = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid.0);
            if !h.is_null() {
                TerminateProcess(h, 1);
                CloseHandle(h);
            }
        }
        assert!(
            alive,
            "the target died right after pause+detach — the injected break-in exception              was left pending for a process with no debugger left to handle it"
        );
        assert!(
            exited_on_its_own,
            "the target survived but never reached its own exit — pause+detach left it              suspended, which is as broken as killing it"
        );
    }

    /// breakpoint (so it's guaranteed alive and debuggable), then call
    /// `pause` — proves `OpenProcess` + `DebugBreakProcess` work against a
    /// live process. `pause` requests an asynchronous break-in; we don't
    /// assert on a specific resulting event (that would race with the
    /// process's own execution), only that the Win32 call itself succeeds.
    #[tokio::test]
    async fn pause_succeeds_against_a_live_process() {
        let dbg = WindowsDebugger::new();
        dbg.launch(cmd_launch_options(&["/C", "exit", "0"]))
            .await
            .expect("launch should succeed");

        for _ in 0..50 {
            let event = dbg.continue_execution().await.expect("continue_execution should not error");
            if matches!(event.reason, StopReason::Breakpoint { .. }) || event.reason.is_exit() {
                break;
            }
        }

        dbg.pause().await.expect("pause (DebugBreakProcess) should succeed against a live process");

        // Drain to exit so the debug thread's loop terminates cleanly.
        for _ in 0..2000 {
            match dbg.continue_execution().await {
                Ok(event) if event.reason.is_exit() => break,
                Ok(_) => continue,
                Err(_) => break,
            }
        }
    }

    /// `memory_maps` should report at least one region for a live process,
    /// and the region containing the reported breakpoint address should be
    /// marked executable — proves `VirtualQueryEx` enumeration and the
    /// `PAGE_*` protection classification work end to end.
    #[tokio::test]
    async fn memory_maps_reports_real_regions() {
        let dbg = WindowsDebugger::new();
        dbg.launch(cmd_launch_options(&["/C", "exit", "0"]))
            .await
            .expect("launch should succeed");

        let mut bp_addr = None;
        for _ in 0..50 {
            let event = dbg.continue_execution().await.expect("continue_execution should not error");
            if let StopReason::Breakpoint { address, .. } = event.reason {
                bp_addr = Some(address);
                break;
            }
            if event.reason.is_exit() {
                break;
            }
        }
        let bp_addr = bp_addr.expect("expected the initial system breakpoint");

        let maps = dbg.memory_maps().await.expect("memory_maps should succeed against a live process");
        assert!(!maps.is_empty(), "a live process should have at least one mapped region");

        let containing = maps
            .iter()
            .find(|m| bp_addr.as_u64() >= m.base.as_u64() && bp_addr.as_u64() < m.base.as_u64() + m.size);
        let containing = containing.expect("the breakpoint address should fall inside a reported region");
        assert!(containing.executable, "the region containing code (ntdll) should be marked executable");
        // `file_path`/`name` were hardcoded `None` before this fix (no
        // `GetMappedFileNameW` call) — the region containing the initial
        // system breakpoint is inside ntdll.dll, a real file-backed mapping,
        // so it should now resolve to a real path.
        let file_path = containing.file_path.as_deref().expect("ntdll's region should have a resolved file_path");
        assert!(
            file_path.to_lowercase().contains("ntdll"),
            "expected the ntdll region's file_path to mention ntdll, got {file_path:?}"
        );
        assert!(
            containing.name.as_deref().is_some_and(|n| n.to_lowercase().contains("ntdll")),
            "expected the ntdll region's name to mention ntdll, got {:?}", containing.name
        );

        let _ = dbg.kill().await;
    }

    /// `modules` should enumerate at least the main executable (`cmd.exe`)
    /// for a live process, with a plausible non-zero base address — proves
    /// the `CreateToolhelp32Snapshot`/`Module32FirstW`/`Module32NextW` path
    /// and the wide-string conversion work end to end.
    #[tokio::test]
    async fn modules_enumerates_the_main_executable() {
        let dbg = WindowsDebugger::new();
        dbg.launch(cmd_launch_options(&["/C", "exit", "0"]))
            .await
            .expect("launch should succeed");

        // Give the loader a moment past the initial breakpoint so the main
        // module is fully registered before we snapshot it.
        for _ in 0..5 {
            let event = dbg.continue_execution().await.expect("continue_execution should not error");
            if event.reason.is_exit() {
                break;
            }
        }

        let modules = dbg.modules().await.expect("modules should succeed against a live process");
        assert!(!modules.is_empty(), "a live process should have at least the main module");
        let main = modules.iter().find(|m| m.is_main).expect("one module should be flagged is_main");
        assert!(main.base.as_u64() != 0, "the main module's base address should be non-zero");
        assert!(
            main.name.to_lowercase().contains("cmd"),
            "the main module's name should be cmd.exe, got {:?}",
            main.name
        );
        // `entry_point` was hardcoded `None` before this fix (no PE header
        // parse); now it should be a real RVA-resolved address inside the
        // module's own mapped range.
        let entry_point = main.entry_point.expect("main module's entry_point should now be resolved, not None");
        assert!(
            entry_point.as_u64() > main.base.as_u64() && entry_point.as_u64() < main.base.as_u64() + main.size,
            "entry_point {:#x} should fall within the module's mapped range [{:#x}, {:#x})",
            entry_point.as_u64(), main.base.as_u64(), main.base.as_u64() + main.size
        );

        let _ = dbg.kill().await;
    }

    /// Mirrors `linux_debugger::live_tests::launch_twice_on_the_same_
    /// debugger_does_not_leak_the_first_process` — this backend's `launch`
    /// carries the identical double-call guard (same code shape, same
    /// fix), but never had its own dedicated Windows-side live test: a
    /// second `launch()` on an already-attached instance must be rejected
    /// outright, not silently overwrite `self.pid`/`self.cmd_tx` and leak
    /// the first process as a permanently orphaned, still-running one.
    #[tokio::test]
    async fn launch_twice_on_the_same_debugger_does_not_leak_the_first_process() {
        let dbg = WindowsDebugger::new();
        let first_pid = dbg.launch(cmd_launch_options(&["/C", "ping", "-n", "3", "127.0.0.1"]))
            .await
            .expect("first launch should succeed");

        let second = dbg.launch(cmd_launch_options(&["/C", "exit", "0"])).await;
        assert!(second.is_err(), "a second launch() on an already-attached instance must be rejected");
        assert_eq!(
            dbg.target_pid(), Some(first_pid),
            "target_pid should still be the first process after a rejected second launch"
        );

        let _ = dbg.kill().await;
    }

    /// Mirrors `linux_debugger::live_tests::run_to_return_returns_process_
    /// exit_instead_of_erroring` — this backend's `run_to_return` (shared
    /// by `step_over`/`step_out`) carries the identical exit-check-before-
    /// get_registers fix (same code shape, same bug class), but never had
    /// its own dedicated live test proving it directly: once the target
    /// process exits, `get_registers` on the now-gone process fails, and
    /// checking that BEFORE the `is_exit()` check would make a legitimate
    /// `ProcessExit` unreachable, turning it into a spurious `Err` instead.
    #[tokio::test]
    async fn run_to_return_returns_process_exit_instead_of_erroring() {
        let dbg = WindowsDebugger::new();
        dbg.launch(cmd_launch_options(&["/C", "exit", "0"]))
            .await
            .expect("launch should succeed");

        let mut tid = None;
        for _ in 0..50 {
            let event = dbg.continue_execution().await.expect("continue_execution should not error");
            if matches!(event.reason, StopReason::Breakpoint { .. }) {
                tid = Some(event.tid);
                break;
            }
            if event.reason.is_exit() {
                break;
            }
        }
        let tid = tid.expect("expected the initial system breakpoint");
        let _regs = dbg.get_registers(tid).await.expect("get_registers should succeed");

        // An EXECUTABLE page the test allocates and nothing ever jumps to.
        // This used to be `regs.sp`, i.e. the stack — which made the test
        // plant an `int3` in the target's data, exactly the corruption
        // `run_to_return` now refuses. Unreachable it was; harmless it was
        // not.
        let unreachable_target = Address(alloc_unreachable_code_page(&dbg));

        let result = dbg.run_to_return(tid, unreachable_target, 0).await;
        match result {
            Ok(event) => assert!(event.reason.is_exit(), "expected a ProcessExit event, got {:?}", event.reason),
            Err(e) => panic!("run_to_return should return the real ProcessExit event, not error: {e:?}"),
        }
    }

    /// `send()` is a request/reply transaction over ONE channel pair, but it
    /// released the command lock before taking the reply lock. Two concurrent
    /// callers could therefore interleave as: A sends, B sends, B receives
    /// A's reply, A receives B's. When the two commands return DIFFERENT
    /// `Reply` variants that surfaces as a spurious "unexpected reply" error;
    /// when they return the SAME variant — two `read_memory` calls, say —
    /// each caller silently gets the OTHER one's bytes, with no error at all.
    /// `WindowsDebugger` is `Send + Sync` precisely so it can be driven
    /// concurrently, so this is reachable, not theoretical.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_commands_do_not_swap_each_others_replies() {
        use std::sync::Arc;

        let dbg = Arc::new(WindowsDebugger::new());
        dbg.launch(cmd_launch_options(&["/C", "ping", "-n", "5", "127.0.0.1"]))
            .await
            .expect("launch should succeed");

        let mut tid = None;
        for _ in 0..50 {
            let event = dbg.continue_execution().await.expect("continue_execution should not error");
            if matches!(event.reason, StopReason::Breakpoint { .. }) {
                tid = Some(event.tid);
                break;
            }
            if event.reason.is_exit() {
                break;
            }
        }
        let Some(tid) = tid else {
            let _ = dbg.kill().await;
            return; // process outran us; cannot set up the scenario
        };
        let regs = dbg.get_registers(tid).await.expect("get_registers should succeed");
        let probe = Address(regs.sp);

        // Two distinct commands whose replies are distinguishable, hammered
        // concurrently. Any crossed reply shows up as `unexpected reply`.
        let a = {
            let dbg = Arc::clone(&dbg);
            tokio::spawn(async move {
                for _ in 0..200 {
                    if let Err(e) = dbg.get_registers(tid).await {
                        return Err(format!("get_registers: {e:?}"));
                    }
                }
                Ok(())
            })
        };
        let b = {
            let dbg = Arc::clone(&dbg);
            tokio::spawn(async move {
                for _ in 0..200 {
                    if let Err(e) = dbg.read_memory(probe, 8).await {
                        return Err(format!("read_memory: {e:?}"));
                    }
                }
                Ok(())
            })
        };

        let (ra, rb) = (a.await.unwrap(), b.await.unwrap());
        let _ = dbg.kill().await;
        if let Err(e) = ra {
            panic!("concurrent caller A got a reply meant for B: {e}");
        }
        if let Err(e) = rb {
            panic!("concurrent caller B got a reply meant for A: {e}");
        }
    }

    /// Dropping an attached debugger must not KILL the target. Nothing
    /// implemented `Drop`, so a `WindowsDebugger` going out of scope while
    /// attached never detaches: the debug loop thread dies with the
    /// channels, and Windows tears the debuggee down with the debug port
    /// (kill-on-exit defaults to TRUE and nothing calls
    /// `DebugSetProcessKillOnExit(FALSE)`).
    ///
    /// That is the same contract violation `detach()` was fixed for: the
    /// debugger disappearing must leave the target running undisturbed, not
    /// destroy it. Observable: a ~4s `ping` must still be alive shortly
    /// after the debugger is dropped.
    #[tokio::test]
    async fn dropping_an_attached_debugger_does_not_kill_the_target() {
        use winapi::um::processthreadsapi::{GetExitCodeProcess, OpenProcess};
        use winapi::um::winnt::PROCESS_QUERY_INFORMATION;
        use winapi::um::minwinbase::STILL_ACTIVE;

        let pid = {
            let dbg = WindowsDebugger::new();
            let pid = dbg
                .launch(cmd_launch_options(&["/C", "ping", "-n", "5", "127.0.0.1"]))
                .await
                .expect("launch should succeed");
            for _ in 0..50 {
                let ev = dbg.continue_execution().await.expect("continue_execution");
                if matches!(ev.reason, StopReason::Breakpoint { .. }) || ev.reason.is_exit() {
                    break;
                }
            }
            pid
            // dropped here, still attached
        };

        tokio::time::sleep(std::time::Duration::from_millis(400)).await;
        let alive = unsafe {
            let h = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid.0);
            if h.is_null() {
                false
            } else {
                let mut code: DWORD = 0;
                let ok = GetExitCodeProcess(h, &mut code);
                CloseHandle(h);
                ok == TRUE && code == STILL_ACTIVE as DWORD
            }
        };
        assert!(
            alive,
            "the target was destroyed when the debugger was dropped — dropping a              debugger must leave the debuggee running, exactly as detach() does"
        );
    }

    /// `kill()` clears `pid` and `cmd_tx` but NOT the breakpoint map, while
    /// `detach()` does clear it. Since `launch()` is allowed again once
    /// `pid` is `None`, a second process launched on the same debugger
    /// inherits the DEAD process's breakpoint entries.
    ///
    /// That is not merely untidy: `set_breakpoint` has an idempotency guard
    /// (iter 153/180) that returns `Ok(())` when the address is already
    /// tracked. So re-arming an address left over from the previous process
    /// silently plants NOTHING while telling the caller it succeeded — and
    /// `breakpoints()` reports a breakpoint that does not exist in the
    /// target. Confidently wrong, which is the failure mode this crate
    /// hunts hardest.
    #[tokio::test]
    async fn kill_clears_breakpoints_so_the_next_process_does_not_inherit_them() {
        let dbg = WindowsDebugger::new();
        dbg.launch(cmd_launch_options(&["/C", "ping", "-n", "3", "127.0.0.1"]))
            .await
            .expect("launch should succeed");

        let mut tid = None;
        for _ in 0..50 {
            let ev = dbg.continue_execution().await.expect("continue_execution");
            if matches!(ev.reason, StopReason::Breakpoint { .. }) {
                tid = Some(ev.tid);
                break;
            }
            if ev.reason.is_exit() {
                break;
            }
        }
        let Some(tid) = tid else { return };
        let regs = dbg.get_registers(tid).await.expect("get_registers");
        let addr = Address(regs.pc);
        dbg.set_breakpoint(addr, BreakpointKind::Software)
            .await
            .expect("set_breakpoint");
        assert_eq!(dbg.breakpoints().await.expect("breakpoints").len(), 1);

        dbg.kill().await.expect("kill should succeed");

        assert!(
            dbg.breakpoints().await.expect("breakpoints").is_empty(),
            "the killed process's breakpoints are still tracked — the next launch on              this debugger inherits them, and re-arming one of those addresses hits              the idempotency guard and silently plants nothing"
        );

        // And the inherited state must not poison a fresh process either.
        dbg.launch(cmd_launch_options(&["/C", "exit", "0"]))
            .await
            .expect("relaunch after kill should succeed");
        assert!(
            dbg.breakpoints().await.expect("breakpoints").is_empty(),
            "a freshly launched process must start with no breakpoints"
        );
        let _ = dbg.kill().await;
    }

    /// A killed process must not bequeath its hardware watchpoints to the next one.
    ///
    /// `kill()` cleared the software-breakpoint map (iter 180) but left
    /// `hw_watchpoints` populated. Since `launch()` is allowed again as soon as
    /// `pid` is `None`, the fresh process started life owning watchpoints set on
    /// a corpse: `breakpoints()` listed them, and `rearm_watchpoints_on_new_threads`
    /// (reached from `continue_execution`) walks that very map and would arm the
    /// new process's threads on addresses its caller never named — spending scarce
    /// debug-register slots, and trapping on whatever happens to live there now.
    #[tokio::test]
    async fn kill_clears_hardware_watchpoints_so_the_next_process_does_not_inherit_them() {
        let dbg = WindowsDebugger::new();
        dbg.launch(cmd_launch_options(&["/C", "ping", "-n", "3", "127.0.0.1"]))
            .await
            .expect("launch should succeed");

        let mut tid = None;
        for _ in 0..50 {
            let ev = dbg.continue_execution().await.expect("continue_execution");
            if matches!(ev.reason, StopReason::Breakpoint { .. }) {
                tid = Some(ev.tid);
                break;
            }
            if ev.reason.is_exit() {
                break;
            }
        }
        let Some(tid) = tid else { return };

        let regs = dbg.get_registers(tid).await.expect("get_registers");
        let watch = Address(regs.sp & !7);
        dbg.set_watchpoint_sized(watch, BreakpointKind::DataWrite, 8)
            .await
            .expect("set_watchpoint_sized");
        assert_eq!(
            dbg.breakpoints().await.expect("breakpoints").len(),
            1,
            "the watchpoint must really be tracked, or this test proves nothing"
        );

        dbg.kill().await.expect("kill should succeed");

        assert!(
            dbg.breakpoints().await.expect("breakpoints").is_empty(),
            "the killed process's hardware watchpoints are still tracked — the next               launch inherits them and re-arms debug registers on threads whose               process never asked for a watchpoint"
        );

        dbg.launch(cmd_launch_options(&["/C", "exit", "0"]))
            .await
            .expect("relaunch after kill should succeed");
        assert!(
            dbg.breakpoints().await.expect("breakpoints").is_empty(),
            "a freshly launched process must start with no watchpoints"
        );
        let _ = dbg.kill().await;
    }

    /// Re-arming a DISABLED hardware watchpoint must mark it enabled again.
    ///
    /// The software path has cleared the `disabled` flag when re-planting a
    /// tracked-but-disabled breakpoint for a long time; `set_watchpoint_sized`
    /// never did. So `set` -> `disable` -> `set` left the address genuinely armed
    /// in the debug registers while `breakpoints()` reported `enabled: false`.
    ///
    /// The second-order consequence is the bad one: `disable_breakpoint`
    /// short-circuits on `already_disabled` and skips the register sweep, so from
    /// that point on NOTHING could switch the watchpoint off again except
    /// `remove` — a live watchpoint the caller has been told is off.
    #[tokio::test]
    async fn re_arming_a_disabled_watchpoint_reports_it_enabled_again() {
        let dbg = WindowsDebugger::new();
        dbg.launch(cmd_launch_options(&["/C", "ping", "-n", "4", "127.0.0.1"]))
            .await
            .expect("launch should succeed");

        let mut tid = None;
        for _ in 0..50 {
            let ev = dbg.continue_execution().await.expect("continue_execution");
            if matches!(ev.reason, StopReason::Breakpoint { .. }) {
                tid = Some(ev.tid);
                break;
            }
            if ev.reason.is_exit() {
                break;
            }
        }
        let Some(tid) = tid else { return };

        let regs = dbg.get_registers(tid).await.expect("get_registers");
        let watch = Address(regs.sp & !7);
        dbg.set_watchpoint_sized(watch, BreakpointKind::DataWrite, 8)
            .await
            .expect("set_watchpoint_sized");
        dbg.disable_breakpoint(watch).await.expect("disable_breakpoint");
        assert_eq!(
            dbg.get_register(tid, "dr7").await.expect("dr7") & 0b1111_1111,
            0,
            "disable must really clear the debug registers, or this test proves nothing"
        );

        dbg.set_watchpoint_sized(watch, BreakpointKind::DataWrite, 8)
            .await
            .expect("re-arming should succeed");
        assert_ne!(
            dbg.get_register(tid, "dr7").await.expect("dr7") & 0b1111_1111,
            0,
            "the re-armed watchpoint is not in the debug registers"
        );

        let listed = dbg.breakpoints().await.expect("breakpoints");
        let bp = listed
            .iter()
            .find(|b| b.address == watch)
            .expect("the watchpoint must still be listed");
        assert!(
            bp.enabled,
            "the watchpoint is armed in the debug registers but reported disabled — and\
             `disable_breakpoint` will now short-circuit on that stale flag, so nothing\
             short of `remove` can ever switch it off again"
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
        let dbg = WindowsDebugger::new();
        dbg.launch(cmd_launch_options(&["/C", "ping", "-n", "5", "127.0.0.1"]))
            .await
            .expect("launch should succeed");
        // Let the loader run, so the address space is populated.
        for _ in 0..50 {
            let ev = dbg.continue_execution().await.expect("continue_execution");
            if matches!(ev.reason, StopReason::Breakpoint { .. }) || ev.reason.is_exit() {
                break;
            }
        }

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

    /// A condition attached to a breakpoint must be REMEMBERED and REPORTED.
    ///
    /// `Breakpoint::condition` is documented as "only stop when this evaluates to
    /// true", and the backends had nowhere to put one: there was no way to attach
    /// a condition at all, so `breakpoints()` reported `None` for every entry and
    /// the field was decoration.
    ///
    /// The round trip is the test: attach, read it back, replace it, clear it,
    /// and — the part that bites — remove the breakpoint and check the condition
    /// went with it. A condition left behind would attach itself to whatever is
    /// set at that address next: a filter the caller never asked for, on a
    /// different breakpoint.
    #[tokio::test]
    async fn a_breakpoint_condition_is_stored_reported_and_removed_with_it() {
        let dbg = WindowsDebugger::new();
        dbg.launch(cmd_launch_options(&["/C", "ping", "-n", "4", "127.0.0.1"]))
            .await
            .expect("launch");
        let mut tid = None;
        for _ in 0..50 {
            let ev = dbg.continue_execution().await.expect("continue");
            if matches!(ev.reason, StopReason::Breakpoint { .. }) {
                tid = Some(ev.tid);
                break;
            }
            if ev.reason.is_exit() {
                break;
            }
        }
        let Some(tid) = tid else { return };
        let addr = Address(dbg.get_registers(tid).await.expect("regs").pc);
        dbg.set_breakpoint(addr, BreakpointKind::Software).await.expect("set");

        // A condition on an address with no breakpoint is refused.
        assert!(
            dbg.set_breakpoint_condition(Address(addr.as_u64() + 0x1000), Some("rax == 0".into()))
                .await
                .is_err(),
            "a condition was accepted for an address carrying no breakpoint, where nothing could ever consult it"
        );
        // So is one that cannot be parsed — refused at the door, not at the hit.
        assert!(
            dbg.set_breakpoint_condition(addr, Some("rax".into())).await.is_err(),
            "a malformed condition was stored, to be discovered only at the first hit"
        );

        dbg.set_breakpoint_condition(addr, Some("rax == 0".into())).await.expect("attach");
        let listed = dbg.breakpoints().await.expect("breakpoints");
        let bp = listed.iter().find(|b| b.address == addr).expect("listed");
        assert_eq!(
            bp.condition.as_deref(),
            Some("rax == 0"),
            "the condition was accepted and then not reported: the field stays decoration"
        );

        // Clearing works, and removal takes the condition with the breakpoint.
        dbg.set_breakpoint_condition(addr, None).await.expect("clear");
        dbg.set_breakpoint_condition(addr, Some("rcx != 1".into())).await.expect("reattach");
        dbg.remove_breakpoint(addr).await.expect("remove");
        dbg.set_breakpoint(addr, BreakpointKind::Software).await.expect("set again");
        let listed = dbg.breakpoints().await.expect("breakpoints");
        let bp = listed.iter().find(|b| b.address == addr).expect("listed");
        assert_eq!(
            bp.condition, None,
            "the old condition survived the removal and now filters a breakpoint the caller set fresh"
        );
        let _ = dbg.kill().await;
    }

    /// A conditional breakpoint must stop only when its condition holds.
    ///
    /// The behavioural proof the previous iteration could not build. Every earlier
    /// attempt failed for the same reason: the loader breakpoint executes ONCE, so
    /// "it did not stop again" is true whether or not the condition is read.
    ///
    /// So the loop is WRITTEN into the target — three bytes of `inc rax` and a two
    /// byte `jmp` back over them — and the program counter is pointed at it. The
    /// address is now executed over and over, which is exactly what a conditional
    /// breakpoint is for and what nothing in this suite could exercise before.
    /// Same approach as the manufactured page fault and the built protection seam:
    /// construct the situation instead of hunting for one.
    ///
    /// `rax == 3` is arithmetic the debugger cannot fake: it can only be true on
    /// the fourth pass. A debugger that ignores the condition reports the first
    /// pass, where `rax` is 0.
    #[tokio::test]
    async fn a_conditional_breakpoint_stops_only_when_its_condition_holds() {
        use winapi::um::memoryapi::VirtualAllocEx;
        use winapi::um::winnt::{MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE};

        let dbg = WindowsDebugger::new();
        dbg.launch(cmd_launch_options(&["/C", "ping", "-n", "9", "127.0.0.1"]))
            .await
            .expect("launch");
        let mut tid = None;
        for _ in 0..50 {
            let ev = dbg.continue_execution().await.expect("continue");
            if matches!(ev.reason, StopReason::Breakpoint { .. }) {
                tid = Some(ev.tid);
                break;
            }
            if ev.reason.is_exit() {
                break;
            }
        }
        let Some(tid) = tid else { return };
        let pid = dbg.target_pid().expect("attached").0;

        // A page of our own code in the target.
        let base = unsafe {
            let h = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
            assert!(!h.is_null(), "OpenProcess on our own debuggee");
            let p = VirtualAllocEx(
                h,
                std::ptr::null_mut(),
                0x1000,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE,
            );
            CloseHandle(h);
            assert!(!p.is_null(), "VirtualAllocEx");
            p as u64
        };
        // inc rax ; jmp -5  →  back to the inc, forever.
        dbg.write_memory(Address(base), &[0x48, 0xFF, 0xC0, 0xEB, 0xFB])
            .await
            .expect("write the loop");

        let mut regs = dbg.get_registers(tid).await.expect("regs");
        regs.set("rax", 0);
        regs.pc = base;
        regs.set("rip", base);
        dbg.set_registers(tid, regs).await.expect("point the thread at the loop");

        dbg.set_breakpoint(Address(base), BreakpointKind::Software).await.expect("set");
        dbg.set_breakpoint_condition(Address(base), Some("rax == 3".into()))
            .await
            .expect("attach the condition");

        // Everything is observed FIRST and the target is killed BEFORE any
        // assertion. This thread has been redirected into an infinite loop that
        // only this test knows about: a panic between here and the kill would
        // leave it spinning in a process nobody is going to stop. Measured, not
        // theorised — the first version asserted inline, and the failing run
        // hung until the process was killed by hand.
        // A WINDOW of resumes: the target has threads of its own and the debug
        // loop reports whichever stops first, so a single continue can return
        // somebody else's event. Assuming otherwise made this pass alone and
        // fail inside the full suite — the third test in this file to learn it.
        let mut observed = None;
        for _ in 0..12 {
            let Ok(e) = dbg.continue_execution().await else { break };
            if matches!(&e.reason, StopReason::Breakpoint { address, .. } if address.as_u64() == base)
            {
                observed = Some(dbg.get_register(e.tid, "rax").await.ok());
                break;
            }
            if e.reason.is_exit() {
                break;
            }
        }
        let _ = dbg.kill().await;

        let rax = observed
            .expect("expected the conditional breakpoint to fire at the injected loop")
            .expect("rax must be readable at the stop");
        assert_eq!(
            rax, 3,
            "the debugger stopped at pass {rax} of a breakpoint whose condition is `rax == 3`: the condition was not evaluated"
        );
    }

    /// A breakpoint hit repeatedly must be COUNTED repeatedly.
    ///
    /// `Breakpoint::hit_count` is published by `breakpoints()` and nothing had
    /// ever checked it against a target that hits the same address more than
    /// once — impossible until the injected loop existed, because the loader
    /// breakpoint fires exactly once.
    ///
    /// It matters more since conditional breakpoints landed: a stop filtered out
    /// by its condition is UN-counted on the way through, so the counter is now
    /// written by two paths that pull in opposite directions. This pins the
    /// simple case — no condition, three passes, three hits — which is what the
    /// un-counting must not disturb.
    #[tokio::test]
    async fn a_breakpoint_hit_three_times_reports_three_hits() {
        use winapi::um::memoryapi::VirtualAllocEx;
        use winapi::um::winnt::{MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE};

        let dbg = WindowsDebugger::new();
        dbg.launch(cmd_launch_options(&["/C", "ping", "-n", "9", "127.0.0.1"]))
            .await
            .expect("launch");
        let mut tid = None;
        for _ in 0..50 {
            let ev = dbg.continue_execution().await.expect("continue");
            if matches!(ev.reason, StopReason::Breakpoint { .. }) {
                tid = Some(ev.tid);
                break;
            }
            if ev.reason.is_exit() {
                break;
            }
        }
        let Some(tid) = tid else { return };
        let pid = dbg.target_pid().expect("attached").0;

        let base = unsafe {
            let h = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
            assert!(!h.is_null(), "OpenProcess");
            let p = VirtualAllocEx(
                h,
                std::ptr::null_mut(),
                0x1000,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE,
            );
            CloseHandle(h);
            assert!(!p.is_null(), "VirtualAllocEx");
            p as u64
        };
        dbg.write_memory(Address(base), &[0x48, 0xFF, 0xC0, 0xEB, 0xFB])
            .await
            .expect("write the loop");
        let mut regs = dbg.get_registers(tid).await.expect("regs");
        regs.set("rax", 0);
        regs.pc = base;
        regs.set("rip", base);
        dbg.set_registers(tid, regs).await.expect("point at the loop");
        dbg.set_breakpoint(Address(base), BreakpointKind::Software).await.expect("set");

        // Observe everything, THEN kill, THEN assert: this thread is in an
        // infinite loop only the test knows about, and a panic before the kill
        // would leave it spinning (measured in the previous iteration).
        // A WINDOW of resumes, not exactly three: the target has threads of its
        // own and the debug loop reports whichever stops first, so assuming the
        // next three events are all ours makes this pass alone and fail inside
        // the full suite. Measured twice, on two different tests.
        let mut stops = 0;
        for _ in 0..16 {
            let Ok(ev) = dbg.continue_execution().await else { break };
            if matches!(&ev.reason, StopReason::Breakpoint { address, .. } if address.as_u64() == base)
            {
                stops += 1;
                if stops == 3 {
                    break;
                }
            }
            if ev.reason.is_exit() {
                break;
            }
        }
        let counted = dbg
            .breakpoints()
            .await
            .ok()
            .and_then(|bps| bps.iter().find(|b| b.address.as_u64() == base).map(|b| b.hit_count));
        let _ = dbg.kill().await;

        assert_eq!(stops, 3, "the target did not come back to the breakpoint three times");
        assert_eq!(
            counted,
            Some(3),
            "the breakpoint stopped the program three times and reports {counted:?} hits"
        );
    }

    /// A watchpoint that fires repeatedly must count and locate every hit.
    ///
    /// `every_backend_counts_watchpoint_hits_without_rewinding_the_pc` has guarded
    /// this from the SOURCE for a long time; nothing had ever watched it happen,
    /// because no target in this suite wrote to the same address twice. The
    /// injected loop makes it possible: a store executed over and over, on an
    /// address the test chose.
    ///
    /// Two things are checked that a source guard cannot see: the reported
    /// address is the WATCHED one (not the program counter, which is the defect
    /// the Apple backend carried), and the count follows the number of stops.
    #[tokio::test]
    async fn a_watchpoint_hit_repeatedly_counts_and_locates_every_hit() {
        use winapi::um::memoryapi::VirtualAllocEx;
        use winapi::um::winnt::{MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE};

        let dbg = WindowsDebugger::new();
        dbg.launch(cmd_launch_options(&["/C", "ping", "-n", "9", "127.0.0.1"]))
            .await
            .expect("launch");
        let mut tid = None;
        for _ in 0..50 {
            let ev = dbg.continue_execution().await.expect("continue");
            if matches!(ev.reason, StopReason::Breakpoint { .. }) {
                tid = Some(ev.tid);
                break;
            }
            if ev.reason.is_exit() {
                break;
            }
        }
        let Some(tid) = tid else { return };
        let pid = dbg.target_pid().expect("attached").0;

        let base = unsafe {
            let h = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
            assert!(!h.is_null(), "OpenProcess");
            let p = VirtualAllocEx(
                h,
                std::ptr::null_mut(),
                0x1000,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE,
            );
            CloseHandle(h);
            assert!(!p.is_null(), "VirtualAllocEx");
            p as u64
        };
        // The scratch word lives in the same page, well past the code.
        let watched = base + 0x800;

        // mov rax, watched ; mov byte [rax], 1 ; jmp back
        let mut code = vec![0x48u8, 0xB8];
        code.extend_from_slice(&watched.to_le_bytes());
        code.extend_from_slice(&[0xC6, 0x00, 0x01]);
        // rel8 back over everything emitted so far, plus this 2-byte jump.
        let back = -((code.len() as i32) + 2);
        code.extend_from_slice(&[0xEB, (back as i8) as u8]);
        dbg.write_memory(Address(base), &code).await.expect("write the loop");

        let mut regs = dbg.get_registers(tid).await.expect("regs");
        regs.pc = base;
        regs.set("rip", base);
        dbg.set_registers(tid, regs).await.expect("point at the loop");
        dbg.set_watchpoint_sized(Address(watched), BreakpointKind::DataWrite, 1)
            .await
            .expect("arm a 1-byte write watchpoint");

        // Counted over a WINDOW of resumes, not over exactly two. The target is
        // `ping`, which has threads of its own, and the debug loop reports
        // whichever of them stops first: assuming the next two events are both
        // ours made this test pass alone and fail inside the full suite, where
        // the machine is busy. Measured, not guessed.
        let mut hits_at_watched = 0;
        for _ in 0..12 {
            let Ok(ev) = dbg.continue_execution().await else { break };
            if matches!(&ev.reason, StopReason::Breakpoint { address, .. } if address.as_u64() == watched)
            {
                hits_at_watched += 1;
                if hits_at_watched == 2 {
                    break;
                }
            }
            if ev.reason.is_exit() {
                break;
            }
        }
        let counted = dbg
            .breakpoints()
            .await
            .ok()
            .and_then(|bps| bps.iter().find(|b| b.address.as_u64() == watched).map(|b| b.hit_count));
        let _ = dbg.kill().await;

        assert_eq!(
            hits_at_watched, 2,
            "the watchpoint did not report the WATCHED address on both hits"
        );
        assert_eq!(
            counted,
            Some(2),
            "the watchpoint stopped the program twice and reports {counted:?} hits"
        );
    }

    /// `step_over` on a real `call` must land AFTER it, not inside the callee.
    ///
    /// The headline difference between step-over and step-into, and nothing had
    /// ever watched it happen on this backend: every earlier step test used
    /// whatever instruction the loader breakpoint happened to sit on, which is
    /// almost never a call. The injected program makes the situation instead of
    /// waiting for it.
    ///
    /// Layout, five instructions that also form a loop so the address stays live:
    /// ```text
    ///   base+0 : e8 05 00 00 00   call base+10
    ///   base+5 : 48 ff c0         inc rax        <- landing site of a step OVER
    ///   base+8 : eb f6            jmp base
    ///   base+10: c3               ret            <- landing site of a step INTO
    /// ```
    /// The two outcomes are different addresses, so the test cannot pass by
    /// accident.
    #[tokio::test]
    async fn step_over_a_call_lands_after_it_not_inside_it() {
        use winapi::um::memoryapi::VirtualAllocEx;
        use winapi::um::winnt::{MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE};

        let dbg = WindowsDebugger::new();
        dbg.launch(cmd_launch_options(&["/C", "ping", "-n", "9", "127.0.0.1"]))
            .await
            .expect("launch");
        let mut tid = None;
        for _ in 0..50 {
            let ev = dbg.continue_execution().await.expect("continue");
            if matches!(ev.reason, StopReason::Breakpoint { .. }) {
                tid = Some(ev.tid);
                break;
            }
            if ev.reason.is_exit() {
                break;
            }
        }
        let Some(tid) = tid else { return };
        let pid = dbg.target_pid().expect("attached").0;

        let base = unsafe {
            let h = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
            assert!(!h.is_null(), "OpenProcess");
            let p = VirtualAllocEx(
                h,
                std::ptr::null_mut(),
                0x1000,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE,
            );
            CloseHandle(h);
            assert!(!p.is_null(), "VirtualAllocEx");
            p as u64
        };
        dbg.write_memory(
            Address(base),
            &[
                0xE8, 0x05, 0x00, 0x00, 0x00, // call base+10
                0x48, 0xFF, 0xC0, // inc rax
                0xEB, 0xF6, // jmp base
                0xC3, // ret
            ],
        )
        .await
        .expect("write the program");

        let mut regs = dbg.get_registers(tid).await.expect("regs");
        regs.pc = base;
        regs.set("rip", base);
        dbg.set_registers(tid, regs).await.expect("point at the call");

        // A CALLER'S breakpoint at the return site, with a condition that is
        // never true. `step_over` plants (or re-uses) a breakpoint at exactly
        // that address and waits for it — so a condition filter that applied to
        // it would resume past the stop this call is waiting for, and the step
        // would run to exit instead of stepping. A stepping primitive that
        // silently becomes `continue` is the worst failure mode a debugger has,
        // and it is one the conditional-breakpoint work introduced.
        dbg.set_breakpoint(Address(base + 5), BreakpointKind::Software).await.expect("user bp");
        dbg.set_breakpoint_condition(Address(base + 5), Some("sp == 0".into()))
            .await
            .expect("never-true condition");

        // Observe, kill, then assert — the thread is in a loop only this test
        // knows about (iteration 431).
        let stepped = dbg.step_over(tid).await;
        let landed = dbg.get_register(tid, "rip").await.ok();
        let _ = dbg.kill().await;

        stepped.expect("step_over must succeed on a call");
        assert_eq!(
            landed,
            Some(base + 5),
            "step_over landed at {landed:?}: {} means it stepped INTO the callee instead of over the call",
            if landed == Some(base + 10) { "base+10" } else { "that" }
        );
    }

    /// A single step from ON a planted breakpoint must advance the program counter.
    ///
    /// Standing on one of our own `0xCC`, a step executes the TRAP and not the
    /// instruction it replaced: the exception fires again at the same address and
    /// the pc has not moved. The caller asked for one instruction and got none,
    /// with no error to say so — a debugger that appears stuck.
    ///
    /// `continue_execution` has stepped off its own traps since iteration 357;
    /// the stepping door never did, and nothing could show it until an address
    /// could be executed on demand.
    #[tokio::test]
    async fn a_single_step_from_a_planted_breakpoint_advances_the_program_counter() {
        use winapi::um::memoryapi::VirtualAllocEx;
        use winapi::um::winnt::{MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE};

        let dbg = WindowsDebugger::new();
        dbg.launch(cmd_launch_options(&["/C", "ping", "-n", "9", "127.0.0.1"]))
            .await
            .expect("launch");
        let mut tid = None;
        for _ in 0..50 {
            let ev = dbg.continue_execution().await.expect("continue");
            if matches!(ev.reason, StopReason::Breakpoint { .. }) {
                tid = Some(ev.tid);
                break;
            }
            if ev.reason.is_exit() {
                break;
            }
        }
        let Some(tid) = tid else { return };
        let pid = dbg.target_pid().expect("attached").0;

        let base = unsafe {
            let h = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
            assert!(!h.is_null(), "OpenProcess");
            let p = VirtualAllocEx(
                h,
                std::ptr::null_mut(),
                0x1000,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE,
            );
            CloseHandle(h);
            assert!(!p.is_null(), "VirtualAllocEx");
            p as u64
        };
        // inc rax ; jmp back — the address stays live, and `inc rax` is 3 bytes.
        dbg.write_memory(Address(base), &[0x48, 0xFF, 0xC0, 0xEB, 0xFB])
            .await
            .expect("write the loop");
        let mut regs = dbg.get_registers(tid).await.expect("regs");
        regs.set("rax", 0);
        regs.pc = base;
        regs.set("rip", base);
        dbg.set_registers(tid, regs).await.expect("point at the loop");
        dbg.set_breakpoint(Address(base), BreakpointKind::Software).await.expect("set");

        // Observe, kill, then assert (iteration 431: this thread is in a loop
        // only the test knows about).
        //
        // The step is retried while the debug loop hands back an event that
        // belongs to ANOTHER thread. `WaitForDebugEvent` reports for the whole
        // process, and the target (`cmd` running `ping`) has loader and worker
        // threads of its own: under a full parallel suite one of them can stop
        // first, and the returned event then says nothing about the thread this
        // test is stepping. That is what made this test fail twice in a whole-
        // suite run (iterations 463 and 474) while passing 12/12 alone.
        //
        // Bounded and strict on purpose: it does not accept a foreign event as
        // success, it just does not mistake it for OUR result.
        let mut stepped = Err(DebugError::StepError("no step attempted".into()));
        for _ in 0..5 {
            stepped = dbg.single_step(tid).await;
            match &stepped {
                Ok(ev) if ev.tid != tid => continue,
                _ => break,
            }
        }
        let after = dbg.get_register(tid, "rip").await.ok();
        let rax = dbg.get_register(tid, "rax").await.ok();
        let _ = dbg.kill().await;

        stepped.expect("single_step must succeed");
        assert_eq!(
            after,
            Some(base + 3),
            "the program counter is at {after:?} after a single step from a planted breakpoint: it executed the trap instead of the instruction and made no progress"
        );
        assert_eq!(
            rax,
            Some(1),
            "the instruction under the trap never ran"
        );
    }

    /// A thread created while STEPPING must inherit the watchpoints too.
    ///
    /// x86 debug registers are per-thread, so a watchpoint armed before a thread
    /// existed does not apply to it. `continue_execution` reconciles new threads
    /// on every resume; the stepping door did not, so stepping through the code
    /// that spawns a thread left that thread unwatched — and a watchpoint that
    /// silently does not cover a thread is worse than no watchpoint, because the
    /// caller is told the address is watched.
    ///
    /// The companion of `a_thread_created_after_the_watchpoint_still_inherits_it`,
    /// which proves the same thing for `continue_execution`. Only the resume door
    /// differs, which is the whole point.
    #[tokio::test]
    async fn a_thread_created_while_stepping_still_inherits_the_watchpoint() {
        use winapi::um::processthreadsapi::CreateRemoteThread;
        use winapi::um::synchapi::Sleep;

        let dbg = WindowsDebugger::new();
        dbg.launch(cmd_launch_options(&["/C", "ping", "-n", "5", "127.0.0.1"]))
            .await
            .expect("launch");
        let mut tid = None;
        for _ in 0..50 {
            let ev = dbg.continue_execution().await.expect("continue");
            if matches!(ev.reason, StopReason::Breakpoint { .. }) {
                tid = Some(ev.tid);
                break;
            }
            if ev.reason.is_exit() {
                break;
            }
        }
        let Some(tid) = tid else { return };

        // Armed while the second thread does not exist yet.
        let regs = dbg.get_registers(tid).await.expect("regs");
        let watch = Address(regs.sp & !7);
        dbg.set_watchpoint_sized(watch, BreakpointKind::DataWrite, 4)
            .await
            .expect("arm the watchpoint");

        let pid = dbg.target_pid().expect("attached").0;
        let new_tid = unsafe {
            let handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
            assert!(!handle.is_null(), "OpenProcess");
            let mut raw: DWORD = 0;
            let th = CreateRemoteThread(
                handle,
                std::ptr::null_mut(),
                0,
                Some(std::mem::transmute::<usize, unsafe extern "system" fn(*mut winapi::ctypes::c_void) -> DWORD>(
                    Sleep as *const () as usize,
                )),
                3000 as *mut _,
                0,
                &mut raw,
            );
            assert!(!th.is_null(), "CreateRemoteThread");
            CloseHandle(th);
            CloseHandle(handle);
            ThreadId(raw)
        };
        if !dbg.threads().await.expect("threads").contains(&new_tid) {
            return; // the injected thread already exited
        }

        // The reconciliation must happen through the STEPPING door, not a
        // resume: that is the difference this test exists for.
        let _ = dbg.single_step(tid).await;

        let dr7 = dbg.get_register(new_tid, "dr7").await.unwrap_or(0);
        let _ = dbg.kill().await;
        assert_ne!(
            dr7 & 0b1111_1111,
            0,
            "the thread created while stepping has empty debug registers: the watchpoint the caller armed does not cover it"
        );
    }

    /// Stepping thread B must not step thread A.
    ///
    /// `step_off_planted_breakpoint` read `current_tid` instead of the thread the
    /// caller named. Harmless while its result was discarded; once `single_step`
    /// began RETURNING that event (iteration 435), asking to step B while A sat
    /// on a planted trap stepped **A** and handed the event back as the answer
    /// for B — the caller was told its thread had advanced when a different one
    /// had. A debugger that steps the wrong thread and says nothing.
    ///
    /// Thread A is parked in an injected loop with a breakpoint on it, exactly
    /// the state that triggers the step-off. The check is on A's program
    /// counter: if it moved, the step went to the wrong thread.
    #[tokio::test]
    async fn stepping_one_thread_does_not_step_another() {
        use winapi::um::memoryapi::VirtualAllocEx;
        use winapi::um::processthreadsapi::CreateRemoteThread;
        use winapi::um::synchapi::Sleep;
        use winapi::um::winnt::{MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE};

        let dbg = WindowsDebugger::new();
        dbg.launch(cmd_launch_options(&["/C", "ping", "-n", "9", "127.0.0.1"]))
            .await
            .expect("launch");
        let mut tid_a = None;
        for _ in 0..50 {
            let ev = dbg.continue_execution().await.expect("continue");
            if matches!(ev.reason, StopReason::Breakpoint { .. }) {
                tid_a = Some(ev.tid);
                break;
            }
            if ev.reason.is_exit() {
                break;
            }
        }
        let Some(tid_a) = tid_a else { return };
        let pid = dbg.target_pid().expect("attached").0;

        let base = unsafe {
            let h = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
            assert!(!h.is_null(), "OpenProcess");
            let p = VirtualAllocEx(
                h,
                std::ptr::null_mut(),
                0x1000,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE,
            );
            CloseHandle(h);
            assert!(!p.is_null(), "VirtualAllocEx");
            p as u64
        };
        dbg.write_memory(Address(base), &[0x48, 0xFF, 0xC0, 0xEB, 0xFB])
            .await
            .expect("write the loop");
        let mut regs = dbg.get_registers(tid_a).await.expect("regs");
        regs.pc = base;
        regs.set("rip", base);
        // `rax` is the witness, NOT the program counter: the loop returns to
        // `base` after every pass, so A's pc reads `base` whether or not it ran.
        // Measured — the first version of this test checked the pc and passed
        // with the defect reintroduced.
        regs.set("rax", 0);
        dbg.set_registers(tid_a, regs).await.expect("park A on the loop");
        dbg.set_breakpoint(Address(base), BreakpointKind::Software).await.expect("set");

        let tid_b = unsafe {
            let h = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
            assert!(!h.is_null(), "OpenProcess");
            let mut raw: DWORD = 0;
            let th = CreateRemoteThread(
                h,
                std::ptr::null_mut(),
                0,
                Some(std::mem::transmute::<usize, unsafe extern "system" fn(*mut winapi::ctypes::c_void) -> DWORD>(
                    Sleep as *const () as usize,
                )),
                3000 as *mut _,
                0,
                &mut raw,
            );
            assert!(!th.is_null(), "CreateRemoteThread");
            CloseHandle(th);
            CloseHandle(h);
            ThreadId(raw)
        };
        if !dbg.threads().await.expect("threads").contains(&tid_b) {
            return; // the injected thread already exited
        }

        // Step B while A is the one sitting on the planted trap.
        let _ = dbg.single_step(tid_b).await;
        let a_rax = dbg.get_register(tid_a, "rax").await.ok();
        let _ = dbg.kill().await;

        assert_eq!(
            a_rax,
            Some(0),
            "thread A executed its `inc rax` while thread B was being stepped: the step-off used the last-stopped thread instead of the one the caller named"
        );
    }

    /// `step_out` must return to the CALLER, on a frame this test builds.
    ///
    /// `step_out` reads the return address from `[rbp+8]` and runs to it. Nothing
    /// had ever exercised that on this backend against a frame with known
    /// contents: the existing tests use whatever frame the loader breakpoint
    /// happens to sit in, where a wrong slot cannot be told from a right one.
    ///
    /// The frame is CONSTRUCTED, so every number is chosen and checkable:
    /// ```text
    ///   base+0 : e8 05 00 00 00   call base+10
    ///   base+5 : 48 ff c0         inc rax      <- the caller, where step_out must land
    ///   base+8 : eb f6            jmp base
    ///   base+10: c3               ret
    ///   rbp = F, [F+8] = base+5, rsp = F+16
    /// ```
    /// `[F+8]` holds exactly what the `call` will push, so the frame the
    /// debugger reads and the frame the CPU builds agree.
    #[tokio::test]
    async fn step_out_returns_to_the_caller_frame() {
        use winapi::um::memoryapi::VirtualAllocEx;
        use winapi::um::winnt::{MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE};

        let dbg = WindowsDebugger::new();
        dbg.launch(cmd_launch_options(&["/C", "ping", "-n", "9", "127.0.0.1"]))
            .await
            .expect("launch");
        let mut tid = None;
        for _ in 0..50 {
            let ev = dbg.continue_execution().await.expect("continue");
            if matches!(ev.reason, StopReason::Breakpoint { .. }) {
                tid = Some(ev.tid);
                break;
            }
            if ev.reason.is_exit() {
                break;
            }
        }
        let Some(tid) = tid else { return };
        let pid = dbg.target_pid().expect("attached").0;

        let base = unsafe {
            let h = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
            assert!(!h.is_null(), "OpenProcess");
            let p = VirtualAllocEx(
                h,
                std::ptr::null_mut(),
                0x1000,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE,
            );
            CloseHandle(h);
            assert!(!p.is_null(), "VirtualAllocEx");
            p as u64
        };
        dbg.write_memory(
            Address(base),
            &[0xE8, 0x05, 0x00, 0x00, 0x00, 0x48, 0xFF, 0xC0, 0xEB, 0xF6, 0xC3],
        )
        .await
        .expect("write the program");

        // The frame: rbp = F, return address at [F+8], caller's rsp = F+16.
        let frame = base + 0x600;
        dbg.write_memory(Address(frame + 8), &(base + 5).to_le_bytes())
            .await
            .expect("write the return address");

        let mut regs = dbg.get_registers(tid).await.expect("regs");
        regs.set("rax", 0);
        regs.set("rbp", frame);
        regs.fp = Some(frame);
        regs.set("rsp", frame + 16);
        regs.sp = frame + 16;
        regs.pc = base;
        regs.set("rip", base);
        dbg.set_registers(tid, regs).await.expect("install the frame");

        // A CORRUPT frame must be refused before anything is planted. A corrupt
        // stack is precisely the situation a debugger is used in, and planting a
        // trap at whatever a garbage pointer names would mean the debugger
        // corrupting the target it was asked to inspect.
        let mut bad = dbg.get_registers(tid).await.expect("regs");
        bad.set("rbp", 0);
        bad.fp = Some(0);
        dbg.set_registers(tid, bad).await.expect("install a null frame");
        let null_frame = dbg.step_out(tid).await;

        let mut top = dbg.get_registers(tid).await.expect("regs");
        top.set("rbp", u64::MAX - 3);
        top.fp = Some(u64::MAX - 3);
        dbg.set_registers(tid, top).await.expect("install a frame at the top");
        let wrapping_frame = dbg.step_out(tid).await;

        // Put the good frame back and do the real step.
        let mut regs = dbg.get_registers(tid).await.expect("regs");
        regs.set("rax", 0);
        regs.set("rbp", frame);
        regs.fp = Some(frame);
        regs.set("rsp", frame + 16);
        regs.sp = frame + 16;
        regs.pc = base;
        regs.set("rip", base);
        dbg.set_registers(tid, regs).await.expect("reinstall the frame");

        // Observe, kill, then assert (iteration 431).
        let out = dbg.step_out(tid).await;
        let landed = dbg.get_register(tid, "rip").await.ok();
        let _ = dbg.kill().await;

        assert!(
            null_frame.is_err(),
            "step_out accepted a NULL frame pointer and went looking for a return address at address 8"
        );
        assert!(
            wrapping_frame.is_err(),
            "step_out accepted a frame pointer whose return-address slot wraps past the end of the address space: the slot it read belongs to unrelated memory"
        );

        out.expect("step_out must succeed on a well-formed frame");
        assert_eq!(
            landed,
            Some(base + 5),
            "step_out landed at {landed:?} instead of the caller at base+5: the return address was read from the wrong slot, or the run-to-return stopped somewhere else"
        );
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
        let dbg = WindowsDebugger::new();
        dbg.launch(cmd_launch_options(&["/C", "ping", "-n", "5", "127.0.0.1"]))
            .await
            .expect("launch");
        let mut tid = None;
        for _ in 0..50 {
            let ev = dbg.continue_execution().await.expect("continue");
            if matches!(ev.reason, StopReason::Breakpoint { .. }) {
                tid = Some(ev.tid);
                break;
            }
            if ev.reason.is_exit() {
                break;
            }
        }
        let Some(tid) = tid else { return };

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

    /// A fault the debugger did not cause must reach the application.
    ///
    /// The behavioural half of the exception half of iteration 404, which could
    /// only be asserted from the source. `ContinueDebugEvent` used `DBG_CONTINUE`
    /// for everything, which tells the target "handled, carry on" — so a genuine
    /// access violation was swallowed, the faulting instruction re-executed, and
    /// the target faulted again, forever. The application's own handler (an SEH
    /// `__try`, `SetUnhandledExceptionFilter`, a crash reporter) never ran.
    ///
    /// The fault is MANUFACTURED rather than waited for, exactly as the
    /// protection-seam write test builds its own straddle: the program counter is
    /// pointed at an address that is certainly not mapped, so the very next
    /// instruction fetch faults. Waiting for a target to fault on its own would
    /// make the test depend on someone else's bug.
    ///
    /// The two outcomes are genuinely different, which is what makes this a test
    /// and not a demonstration: passed to the application, `cmd.exe` has no
    /// handler for it and dies, so a `ProcessExit` arrives; swallowed, the same
    /// first-chance exception repeats at the same address until the loop below
    /// gives up.
    #[tokio::test]
    async fn a_fault_the_debugger_did_not_cause_is_handed_to_the_application() {
        let dbg = WindowsDebugger::new();
        dbg.launch(cmd_launch_options(&["/C", "ping", "-n", "9", "127.0.0.1"]))
            .await
            .expect("launch should succeed");

        let mut tid = None;
        for _ in 0..50 {
            let ev = dbg.continue_execution().await.expect("continue_execution");
            if matches!(ev.reason, StopReason::Breakpoint { .. }) {
                tid = Some(ev.tid);
                break;
            }
            if ev.reason.is_exit() {
                break;
            }
        }
        let Some(tid) = tid else { return };

        // Somewhere no image is mapped and no allocation lives.
        const NOWHERE: u64 = 0x0000_DEAD_BEEF_0000;
        let mut regs = dbg.get_registers(tid).await.expect("get_registers");
        regs.pc = NOWHERE;
        regs.set("rip", NOWHERE);
        dbg.set_registers(tid, regs).await.expect("set_registers");

        let mut faults = 0usize;
        let mut exited = false;
        for _ in 0..12 {
            let Ok(ev) = dbg.continue_execution().await else { break };
            match ev.reason {
                StopReason::AccessViolation { .. } | StopReason::Exception { .. } => faults += 1,
                r if r.is_exit() => {
                    exited = true;
                    break;
                }
                _ => {}
            }
        }

        assert!(
            faults >= 1,
            "the target never faulted, so the redirected program counter did not take effect and this test proves nothing"
        );
        assert!(
            exited,
            "after {faults} faults the target was still alive: the exception is being acknowledged as HANDLED, so the faulting instruction re-executes forever and the application's own handler never sees it"
        );
        let _ = dbg.kill().await;
    }

    /// A write straddling into unwritable memory must fail, end to end.
    ///
    /// MEASURED, and the measurement changed what this test claims. It was
    /// written to prove the partial-write fix (`written == data.len()`), and it
    /// does NOT: with that check removed it still passes, because
    /// `WriteProcessMemory` validates the whole range against a `PAGE_NOACCESS`
    /// page up front and returns FALSE rather than writing the readable half.
    /// The fail-first evidence for that fix is the source guard
    /// `every_backend_refuses_a_partial_memory_write` in `lib.rs`.
    ///
    /// It is kept, relabelled, because it pins something real that nothing else
    /// covered: a write across a protection seam is refused rather than silently
    /// truncated, and the writable page is proved writable in the same run so
    /// the refusal is about the seam and not about the whole range. Leaving it
    /// under its original name would have been the worse outcome — a test that
    /// reads as coverage of a fix it cannot see.
    ///
    /// The straddle is BUILT, not hunted for: two pages allocated in the target,
    /// the second turned to `PAGE_NOACCESS`. Looking for a naturally-occurring
    /// boundary would make the test depend on the target's layout.
    #[tokio::test]
    async fn a_write_that_only_partly_lands_is_an_error_not_a_smaller_success() {
        use winapi::um::memoryapi::{VirtualAllocEx, VirtualProtectEx};
        use winapi::um::winnt::{MEM_COMMIT, MEM_RESERVE, PAGE_NOACCESS};

        let dbg = WindowsDebugger::new();
        dbg.launch(cmd_launch_options(&["/C", "ping", "-n", "5", "127.0.0.1"]))
            .await
            .expect("launch should succeed");

        let mut stopped = false;
        for _ in 0..50 {
            let ev = dbg.continue_execution().await.expect("continue_execution");
            if matches!(ev.reason, StopReason::Breakpoint { .. }) {
                stopped = true;
                break;
            }
            if ev.reason.is_exit() {
                break;
            }
        }
        if !stopped {
            return;
        }
        let pid = dbg.target_pid().expect("attached").0;

        // Two pages, then revoke the second one.
        let page = 0x1000usize;
        let base = unsafe {
            let h = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
            assert!(!h.is_null(), "OpenProcess on our own debuggee should succeed");
            let base = VirtualAllocEx(
                h,
                std::ptr::null_mut(),
                page * 2,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE,
            );
            assert!(!base.is_null(), "VirtualAllocEx should succeed");
            let mut old = 0u32;
            let ok = VirtualProtectEx(
                h,
                base.cast::<u8>().add(page).cast(),
                page,
                PAGE_NOACCESS,
                &mut old,
            );
            assert!(ok != 0, "VirtualProtectEx should succeed");
            CloseHandle(h);
            base as u64
        };

        // Eight bytes starting four before the seam: four land, four cannot.
        let seam = Address(base + page as u64 - 4);
        let err = dbg.write_memory(seam, &[0xAAu8; 8]).await;
        assert!(
            err.is_err(),
            "a write that could only place 4 of its 8 bytes reported success — a breakpoint restore doing this leaves an int3 in the target and clears the record of it"
        );

        // And the writable half is genuinely writable, so the failure above is
        // about the straddle and not about the whole range being unreachable.
        dbg.write_memory(Address(base), &[0xAAu8; 4])
            .await
            .expect("the first page must accept a write, or this test proves nothing");
        let _ = dbg.kill().await;
    }

    /// `step_out` must not write `0xCC` into the target's DATA.
    ///
    /// It reads a return address out of the stack and hands it to
    /// `run_to_return`, which plants a software breakpoint there — patching a
    /// byte in the target. Nothing checked that the address is executable. A
    /// frame pointer that does not point at a real frame (a corrupt stack, or
    /// a function compiled without one, where `rbp` holds a data pointer)
    /// therefore made the debugger overwrite a byte of the program's own data
    /// and restore it later from a table the program knows nothing about.
    ///
    /// Silent memory corruption caused by inspecting a process is the worst
    /// thing a debugger can do, because the bug it then shows you is its own.
    ///
    /// The frame is forged in memory this test owns, so a `0xCC` appearing
    /// there can only have come from this call.
    #[tokio::test]
    async fn step_out_does_not_plant_a_breakpoint_in_non_executable_memory() {
        use winapi::um::memoryapi::VirtualAllocEx;
        use winapi::um::winnt::{MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE};

        let dbg = WindowsDebugger::new();
        dbg.launch(cmd_launch_options(&["/C", "ping", "-n", "3", "127.0.0.1"]))
            .await
            .expect("launch should succeed");

        let mut tid = None;
        for _ in 0..50 {
            let ev = dbg.continue_execution().await.expect("continue_execution");
            if matches!(ev.reason, StopReason::Breakpoint { .. }) {
                tid = Some(ev.tid);
                break;
            }
            if ev.reason.is_exit() {
                break;
            }
        }
        let Some(tid) = tid else { return };

        // A read/write page the test owns: not executable, and nothing else in
        // the target touches it.
        let pid = dbg.target_pid().expect("attached").0;
        let scratch = unsafe {
            let h = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
            assert!(!h.is_null(), "OpenProcess should succeed");
            let p = VirtualAllocEx(
                h,
                std::ptr::null_mut(),
                4096,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE,
            );
            CloseHandle(h);
            assert!(!p.is_null(), "VirtualAllocEx should succeed");
            p as u64
        };

        // Forge a frame whose saved return address points into that same data
        // page — the shape a corrupt stack produces.
        dbg.write_memory(Address(scratch + 8), &scratch.to_le_bytes())
            .await
            .expect("write the forged return address");
        dbg.set_register(tid, "rbp", scratch).await.expect("rbp");

        let _ = dbg.step_out(tid).await;

        let byte = dbg.read_memory_raw(Address(scratch), 1).await.expect("read scratch")[0];
        assert_ne!(
            byte, 0xCC,
            "step_out planted an int3 at {scratch:#x}, which is read/write DATA — the debugger \
             corrupted the process it was asked to inspect"
        );
        let _ = dbg.kill().await;
    }

    /// Disabling an address that carries BOTH kinds must silence both.
    ///
    /// The twin of the removal defect, on `disable`/`enable`. Both reached the
    /// hardware path only through an `else`: with a software breakpoint also
    /// present, `disable` restored the byte and left the debug register ARMED
    /// while `breakpoints()` reported the address disabled, and `enable`
    /// returned as soon as it had re-armed the watchpoint, leaving the
    /// software trap absent. Either way the caller is told a state the target
    /// is not in.
    #[tokio::test]
    async fn disabling_an_address_silences_both_the_trap_and_the_watchpoint() {
        let dbg = WindowsDebugger::new();
        dbg.launch(cmd_launch_options(&["/C", "ping", "-n", "3", "127.0.0.1"]))
            .await
            .expect("launch should succeed");

        let mut tid = None;
        for _ in 0..50 {
            let ev = dbg.continue_execution().await.expect("continue_execution");
            if matches!(ev.reason, StopReason::Breakpoint { .. }) {
                tid = Some(ev.tid);
                break;
            }
            if ev.reason.is_exit() {
                break;
            }
        }
        let Some(tid) = tid else { return };

        let at = Address(alloc_unreachable_code_page(&dbg));
        dbg.set_breakpoint(at, BreakpointKind::Software).await.expect("software breakpoint");
        dbg.set_watchpoint_sized(at, BreakpointKind::DataWrite, 8)
            .await
            .expect("hardware watchpoint at the same address");
        assert_eq!(dbg.read_memory_raw(at, 1).await.expect("raw")[0], 0xCC);
        assert_ne!(dbg.get_register(tid, "dr7").await.expect("dr7") & 1, 0);

        dbg.disable_breakpoint(at).await.expect("disable_breakpoint");
        assert_ne!(
            dbg.read_memory_raw(at, 1).await.expect("raw")[0],
            0xCC,
            "disable left the software trap planted"
        );
        assert_eq!(
            dbg.get_register(tid, "dr7").await.expect("dr7") & 1,
            0,
            "disable restored the byte but left the debug register armed — the address is \
             reported as disabled while the watchpoint still fires"
        );

        dbg.enable_breakpoint(at).await.expect("enable_breakpoint");
        assert_eq!(
            dbg.read_memory_raw(at, 1).await.expect("raw")[0],
            0xCC,
            "enable re-armed the watchpoint and never put the software trap back"
        );
        assert_ne!(
            dbg.get_register(tid, "dr7").await.expect("dr7") & 1,
            0,
            "enable did not re-arm the watchpoint"
        );
        let _ = dbg.kill().await;
    }

    /// Removing an address that carries BOTH kinds must free both.
    ///
    /// A software breakpoint and a hardware watchpoint at one address are
    /// independent resources — an execution trap in the code and a debug
    /// register watching that location — and a caller may legitimately hold
    /// both. `remove_breakpoint` treated them as alternatives: software first,
    /// hardware only when there was no software. So removing an address with
    /// both restored the `0xCC`, reported success, and left the debug register
    /// armed. The caller is then holding a watchpoint that `breakpoints()` no
    /// longer lists and that nothing will ever free — one of the four slots
    /// gone until detach.
    ///
    /// Introduced by iteration 369, which taught removal about watchpoints but
    /// as an `else` branch.
    #[tokio::test]
    async fn removing_an_address_frees_both_the_trap_and_the_watchpoint() {
        let dbg = WindowsDebugger::new();
        dbg.launch(cmd_launch_options(&["/C", "ping", "-n", "3", "127.0.0.1"]))
            .await
            .expect("launch should succeed");

        let mut tid = None;
        for _ in 0..50 {
            let ev = dbg.continue_execution().await.expect("continue_execution");
            if matches!(ev.reason, StopReason::Breakpoint { .. }) {
                tid = Some(ev.tid);
                break;
            }
            if ev.reason.is_exit() {
                break;
            }
        }
        let Some(tid) = tid else { return };

        // One address, both kinds. The page is executable and 8-byte aligned,
        // so both a trap and a watchpoint are legal there.
        let at = Address(alloc_unreachable_code_page(&dbg));
        dbg.set_breakpoint(at, BreakpointKind::Software).await.expect("software breakpoint");
        dbg.set_watchpoint_sized(at, BreakpointKind::DataWrite, 8)
            .await
            .expect("hardware watchpoint at the same address");

        assert_eq!(
            dbg.read_memory_raw(at, 1).await.expect("raw")[0],
            0xCC,
            "the software trap must really be planted, or this test proves nothing"
        );
        assert_ne!(
            dbg.get_register(tid, "dr7").await.expect("dr7") & 1,
            0,
            "the watchpoint must really be armed, or this test proves nothing"
        );

        dbg.remove_breakpoint(at).await.expect("remove_breakpoint");

        assert_ne!(
            dbg.read_memory_raw(at, 1).await.expect("raw")[0],
            0xCC,
            "the software trap survived the removal"
        );
        assert_eq!(
            dbg.get_register(tid, "dr7").await.expect("dr7") & 1,
            0,
            "the removal freed the software trap and left the debug register armed — the \
             caller holds a watchpoint that breakpoints() no longer lists and nothing frees"
        );
        assert!(
            !dbg.breakpoints().await.expect("breakpoints").iter().any(|b| b.address == at),
            "the address is still listed after being removed"
        );
        let _ = dbg.kill().await;
    }

    /// A corrupt frame pointer must not make `step_out` plant a breakpoint at random.
    ///
    /// `step_out` reads the saved return address from `fp + 8`. In release
    /// arithmetic that wraps: a frame pointer near the end of the address
    /// space produces a SMALL address, the "return address" is read out of
    /// unrelated memory, and `run_to_return` then plants a `0xCC` at whatever
    /// that garbage pointed to — the debugger corrupting the process it was
    /// asked to inspect, with no error anywhere.
    ///
    /// A corrupt stack is exactly the situation a debugger is used in, so this
    /// input is not theoretical. The frame pointer is forced here rather than
    /// waited for, which is the only way to reach the case deterministically.
    #[tokio::test]
    async fn step_out_refuses_a_frame_pointer_that_would_wrap_the_address_space() {
        let dbg = WindowsDebugger::new();
        dbg.launch(cmd_launch_options(&["/C", "ping", "-n", "3", "127.0.0.1"]))
            .await
            .expect("launch should succeed");

        let mut tid = None;
        for _ in 0..50 {
            let ev = dbg.continue_execution().await.expect("continue_execution");
            if matches!(ev.reason, StopReason::Breakpoint { .. }) {
                tid = Some(ev.tid);
                break;
            }
            if ev.reason.is_exit() {
                break;
            }
        }
        let Some(tid) = tid else { return };

        // Nothing is planted yet: whatever `step_out` does next, any breakpoint
        // that appears was created by this call.
        let before = dbg.breakpoints().await.expect("breakpoints").len();

        dbg.set_register(tid, "rbp", u64::MAX - 4)
            .await
            .expect("rbp is a real register on this backend");

        // The error must name the FRAME POINTER. Without `checked_add` the call
        // still fails — but for the wrong reason: `fp + 8` wraps to a low
        // address and the failure comes from the memory read, which reports an
        // address the caller never asked about. Asserting only `is_err()` here
        // would pass either way, so this asserts the diagnosis.
        let err = dbg.step_out(tid).await.expect_err(
            "step_out accepted a frame pointer 4 bytes from the end of the address space",
        );
        let msg = err.to_string();
        assert!(
            msg.contains("frame pointer"),
            "step_out failed, but blamed something else: {msg}. The wrap happened and the error \
             describes a memory read at an address derived from it, not the corrupt frame pointer \
             that caused it."
        );

        let after = dbg.breakpoints().await.expect("breakpoints").len();
        assert_eq!(
            after, before,
            "step_out planted a breakpoint while failing — at an address derived from a wrapped \
             frame pointer, i.e. somewhere in the target chosen at random"
        );
        let _ = dbg.kill().await;
    }

    /// Writing an unknown register must fail, not silently do nothing.
    ///
    /// `RegisterSet::set` inserts ANY name into its map, and the backend then
    /// applies only the names it recognises when it writes the thread context.
    /// So `set_register(tid, "eip", …)` on x86-64 — a plausible typo for
    /// `rip` — was accepted, dropped, and reported as success. Reading that
    /// same name answers "unknown register": the two halves of the API gave
    /// opposite answers about the same register, and the write was the one
    /// that lied.
    ///
    /// It matters most for the callers that cannot see the discrepancy: the
    /// MCP `debug.set_register` tool and any script driving it get `Ok` and
    /// carry on believing the target changed.
    #[tokio::test]
    async fn setting_an_unknown_register_is_refused_like_reading_one() {
        let dbg = WindowsDebugger::new();
        dbg.launch(cmd_launch_options(&["/C", "ping", "-n", "3", "127.0.0.1"]))
            .await
            .expect("launch should succeed");

        let mut tid = None;
        for _ in 0..50 {
            let ev = dbg.continue_execution().await.expect("continue_execution");
            if matches!(ev.reason, StopReason::Breakpoint { .. }) {
                tid = Some(ev.tid);
                break;
            }
            if ev.reason.is_exit() {
                break;
            }
        }
        let Some(tid) = tid else { return };

        // A real register still works — otherwise this test would pass by
        // refusing everything.
        let before = dbg.get_register(tid, "rax").await.expect("rax is a real register");
        dbg.set_register(tid, "rax", before ^ 0x5A5A)
            .await
            .expect("writing a real register must still succeed");
        assert_eq!(
            dbg.get_register(tid, "rax").await.expect("rax"),
            before ^ 0x5A5A,
            "the write to a real register did not reach the target"
        );

        // The two halves must agree about a name that does not exist.
        for name in ["eip", "x0", "not_a_register"] {
            let read = dbg.get_register(tid, name).await;
            assert!(read.is_err(), "get_register({name}) should not invent a value");
            let write = dbg.set_register(tid, name, 0xDEAD).await;
            assert!(
                write.is_err(),
                "set_register({name}) reported success for a register the same backend says \
                 does not exist; nothing was written and the caller is not told"
            );
        }
        let _ = dbg.kill().await;
    }

    /// Arming the same address twice must not burn a second slot.
    ///
    /// x86 has exactly FOUR debug-register slots. `set_breakpoint` has had an
    /// explicit idempotency guard for a long time, but `set_watchpoint_sized`
    /// had none: each call took the next free slot, so four identical requests
    /// exhausted the hardware while the caller had asked to watch ONE address.
    ///
    /// The leak is worse than the exhaustion. `hw_watchpoints` is keyed by
    /// address, so the second insert overwrote the first: the registry knew
    /// about one watchpoint while three more slots were still armed, and the
    /// disarm path could only ever free one of them. The rest stayed occupied
    /// until detach, with nothing tracking them.
    #[tokio::test]
    async fn arming_the_same_watchpoint_twice_does_not_consume_two_slots() {
        let dbg = WindowsDebugger::new();
        dbg.launch(cmd_launch_options(&["/C", "ping", "-n", "3", "127.0.0.1"]))
            .await
            .expect("launch should succeed");

        let mut tid = None;
        for _ in 0..50 {
            let ev = dbg.continue_execution().await.expect("continue_execution");
            if matches!(ev.reason, StopReason::Breakpoint { .. }) {
                tid = Some(ev.tid);
                break;
            }
            if ev.reason.is_exit() {
                break;
            }
        }
        let Some(tid) = tid else { return };

        let regs = dbg.get_registers(tid).await.expect("get_registers");
        let watch = Address(regs.sp & !7);

        for attempt in 0..3 {
            dbg.set_watchpoint_sized(watch, BreakpointKind::DataWrite, 8)
                .await
                .unwrap_or_else(|e| panic!("arm #{attempt} of the same address failed: {e:?}"));
        }

        // Exactly one local-enable bit (L0..L3, bits 0/2/4/6) may be set.
        let dr7 = dbg.get_register(tid, "dr7").await.expect("dr7");
        let enabled_slots = (0u32..4).filter(|n| dr7 & (1u64 << (2 * n)) != 0).count();
        assert_eq!(
            enabled_slots, 1,
            "arming one address three times occupied {enabled_slots} of the four debug-register \
             slots (DR7={dr7:#x}); the extra ones are untracked and can never be freed"
        );

        // The registry must agree: one address, listed once.
        let listed = dbg.breakpoints().await.expect("breakpoints");
        let count = listed.iter().filter(|b| b.address == watch).count();
        assert_eq!(count, 1, "the same watchpoint is listed {count} times");

        // And the slots that were NOT burned must still be usable.
        let other = Address((regs.sp & !7).wrapping_sub(64));
        dbg.set_watchpoint_sized(other, BreakpointKind::DataWrite, 8)
            .await
            .expect("a second, different address should still find a free slot");
        let _ = dbg.kill().await;
    }

    /// A hardware watchpoint must be disable-able and re-enable-able.
    ///
    /// `breakpoints()` lists watchpoints with an `enabled` flag (iteration
    /// 368), and `remove_breakpoint` learned to accept them (369) — but
    /// `disable_breakpoint`/`enable_breakpoint` still answered
    /// `BreakpointNotFound`, so that flag was stuck at `true` with no way to
    /// change it. Same contradiction as 369, on the two twin methods.
    ///
    /// The subtle half is the re-arm: watchpoints are re-applied to threads on
    /// every resume (iteration 363), so without excluding disabled ones the
    /// next `continue_execution` would put the watchpoint straight back into
    /// the debug registers — `disable` would appear to work and then silently
    /// undo itself. That is what the resume in the middle of this test is for.
    #[tokio::test]
    async fn a_hardware_watchpoint_can_be_disabled_and_re_enabled() {
        let dbg = WindowsDebugger::new();
        dbg.launch(cmd_launch_options(&["/C", "ping", "-n", "4", "127.0.0.1"]))
            .await
            .expect("launch should succeed");

        let mut tid = None;
        for _ in 0..50 {
            let ev = dbg.continue_execution().await.expect("continue_execution");
            if matches!(ev.reason, StopReason::Breakpoint { .. }) {
                tid = Some(ev.tid);
                break;
            }
            if ev.reason.is_exit() {
                break;
            }
        }
        let Some(tid) = tid else { return };

        let regs = dbg.get_registers(tid).await.expect("get_registers");
        let watch = Address(regs.sp & !7);
        dbg.set_watchpoint_sized(watch, BreakpointKind::DataWrite, 8)
            .await
            .expect("set_watchpoint_sized");

        dbg.disable_breakpoint(watch).await.unwrap_or_else(|e| {
            panic!(
                "breakpoints() reports {watch:?} with an `enabled` flag but disable_breakpoint \
                 refused it with {e:?}, so the flag can never become false"
            )
        });
        assert_eq!(
            dbg.get_register(tid, "dr7").await.expect("dr7") & 1,
            0,
            "disable reported success but the debug register is still armed"
        );
        let listed = dbg.breakpoints().await.expect("breakpoints");
        let bp = listed.iter().find(|b| b.address == watch).expect("still tracked while disabled");
        assert!(!bp.enabled, "a disabled watchpoint still reports itself as enabled");

        // A resume must NOT resurrect it: watchpoints are re-armed on every
        // resume, and a disabled one has to be excluded from that.
        let _ = dbg.continue_execution().await;
        assert_eq!(
            dbg.get_register(tid, "dr7").await.expect("dr7") & 1,
            0,
            "resuming re-armed a disabled watchpoint — disable undid itself"
        );

        dbg.enable_breakpoint(watch).await.expect("enable_breakpoint");
        assert_ne!(
            dbg.get_register(tid, "dr7").await.expect("dr7") & 1,
            0,
            "enable reported success but nothing was put back in the debug registers"
        );
        let listed = dbg.breakpoints().await.expect("breakpoints");
        let bp = listed.iter().find(|b| b.address == watch).expect("still tracked");
        assert!(bp.enabled, "a re-enabled watchpoint still reports itself as disabled");

        // An address that is neither must still be an honest error.
        assert!(
            dbg.disable_breakpoint(Address(0xDEAD_0000)).await.is_err(),
            "disabling an address that was never set must still fail"
        );
        let _ = dbg.kill().await;
    }

    /// A hardware watchpoint that fires must be COUNTED.
    ///
    /// `breakpoints()` publishes `hit_count`, and hits were only ever counted
    /// for software breakpoints: a hardware watchpoint could stop the program
    /// again and again while reporting zero hits forever. That is the exact
    /// contradiction the software path was fixed for — statistics disagreeing
    /// with what the user is watching happen — left standing on the hardware
    /// path when it was added.
    ///
    /// An EXECUTION hardware breakpoint is used because it is the only kind
    /// whose hit is deterministic without symbols (measured in iteration 364:
    /// a write watch on a stack address went untouched for 60 instructions).
    /// Both go through the same counting path.
    #[tokio::test]
    async fn a_hardware_watchpoint_hit_is_counted_like_a_software_one() {
        let dbg = WindowsDebugger::new();
        dbg.launch(cmd_launch_options(&["/C", "ping", "-n", "3", "127.0.0.1"]))
            .await
            .expect("launch should succeed");

        let mut tid = None;
        for _ in 0..50 {
            let ev = dbg.continue_execution().await.expect("continue_execution");
            if matches!(ev.reason, StopReason::Breakpoint { .. }) {
                tid = Some(ev.tid);
                break;
            }
            if ev.reason.is_exit() {
                break;
            }
        }
        let Some(tid) = tid else { return };

        let regs = dbg.get_registers(tid).await.expect("get_registers");
        let at = Address(regs.pc);
        dbg.set_watchpoint_sized(at, BreakpointKind::Hardware, 1)
            .await
            .expect("set_watchpoint_sized");

        let listed = dbg.breakpoints().await.expect("breakpoints");
        let before = listed
            .iter()
            .find(|b| b.address == at)
            .map(|b| b.hit_count)
            .expect("the watchpoint should be listed");
        assert_eq!(before, 0, "a freshly armed watchpoint has not fired yet");

        // Reach the hit. Other events can arrive first, so walk a bounded
        // number of them (see iteration 366's note on why the first event is
        // not necessarily ours).
        let mut fired = false;
        for _ in 0..40 {
            let Ok(ev) = dbg.continue_execution().await else { break };
            if ev.reason.is_exit() {
                break;
            }
            if let StopReason::Breakpoint { address, .. } = ev.reason {
                if address == at {
                    fired = true;
                    break;
                }
            }
        }
        assert!(fired, "the hardware breakpoint never fired, so there is nothing to count");

        let listed = dbg.breakpoints().await.expect("breakpoints");
        let after = listed
            .iter()
            .find(|b| b.address == at)
            .map(|b| b.hit_count)
            .expect("the watchpoint should still be listed");
        assert!(
            after > before,
            "the watchpoint fired but still reports {after} hits — the published statistics \
             contradict what the caller just observed"
        );
        let _ = dbg.kill().await;
    }

    /// `remove_breakpoint` must remove what `breakpoints()` listed.
    ///
    /// Iteration 368 made hardware watchpoints appear in `breakpoints()`,
    /// which creates an obligation: the natural next call after seeing one in
    /// that list is `remove_breakpoint(addr)`. It answered
    /// `BreakpointNotFound` — the API saying "here it is" and "it does not
    /// exist" about the same address — while the debug register stayed armed
    /// and its slot stayed occupied.
    ///
    /// A caller who kept the address could still reach
    /// `remove_hardware_watchpoint`, but a caller who discovered the
    /// watchpoint through the list had no working way to remove it.
    #[tokio::test]
    async fn remove_breakpoint_also_removes_a_hardware_watchpoint_it_listed() {
        let dbg = WindowsDebugger::new();
        dbg.launch(cmd_launch_options(&["/C", "ping", "-n", "3", "127.0.0.1"]))
            .await
            .expect("launch should succeed");

        let mut tid = None;
        for _ in 0..50 {
            let ev = dbg.continue_execution().await.expect("continue_execution");
            if matches!(ev.reason, StopReason::Breakpoint { .. }) {
                tid = Some(ev.tid);
                break;
            }
            if ev.reason.is_exit() {
                break;
            }
        }
        let Some(tid) = tid else { return };

        let regs = dbg.get_registers(tid).await.expect("get_registers");
        let watch = Address(regs.sp & !7);
        dbg.set_watchpoint_sized(watch, BreakpointKind::DataWrite, 8)
            .await
            .expect("set_watchpoint_sized");

        // Discovered the way a caller would: through the list.
        let listed = dbg.breakpoints().await.expect("breakpoints");
        let addr = listed
            .iter()
            .find(|b| matches!(b.kind, BreakpointKind::DataWrite))
            .map(|b| b.address)
            .expect("the watchpoint should be listed (iteration 368)");

        dbg.remove_breakpoint(addr).await.unwrap_or_else(|e| {
            panic!(
                "breakpoints() listed {addr:?} but remove_breakpoint refused it with {e:?}; \
                 the watchpoint is still armed and its debug-register slot still taken"
            )
        });

        assert!(
            !dbg.breakpoints().await.expect("breakpoints").iter().any(|b| b.address == addr),
            "the watchpoint is still listed after being removed"
        );
        assert_eq!(
            dbg.get_register(tid, "dr7").await.expect("dr7") & 1,
            0,
            "remove_breakpoint reported success but the debug register is still armed"
        );

        // An address that is neither must still be an honest error, or this
        // change would have turned a real "not found" into silent success.
        let err = dbg.remove_breakpoint(Address(0xDEAD_0000)).await;
        assert!(err.is_err(), "removing an address that was never set must still fail");
        let _ = dbg.kill().await;
    }

    /// An armed hardware watchpoint must be visible in `breakpoints()`.
    ///
    /// Hardware watchpoints live in their own map (added in iteration 363) and
    /// were absent from `breakpoints()` entirely: a caller could arm one, ask
    /// what was set, and get an answer that silently omitted it. The MCP
    /// `debug.breakpoints` tool serialises exactly this vector, so the
    /// watchpoint was unlistable — and therefore could not be removed
    /// knowingly by anyone who had not kept the address themselves.
    ///
    /// A defect of omission: the list is not wrong about what it shows, it is
    /// wrong about claiming to be the set of what is armed.
    #[tokio::test]
    async fn breakpoints_lists_hardware_watchpoints_not_only_software_ones() {
        let dbg = WindowsDebugger::new();
        dbg.launch(cmd_launch_options(&["/C", "ping", "-n", "3", "127.0.0.1"]))
            .await
            .expect("launch should succeed");

        let mut tid = None;
        for _ in 0..50 {
            let ev = dbg.continue_execution().await.expect("continue_execution");
            if matches!(ev.reason, StopReason::Breakpoint { .. }) {
                tid = Some(ev.tid);
                break;
            }
            if ev.reason.is_exit() {
                break;
            }
        }
        let Some(tid) = tid else { return };

        let regs = dbg.get_registers(tid).await.expect("get_registers");
        let watch = Address(regs.sp & !7);
        dbg.set_watchpoint_sized(watch, BreakpointKind::DataWrite, 8)
            .await
            .expect("set_watchpoint_sized");

        let listed = dbg.breakpoints().await.expect("breakpoints");
        let found = listed
            .iter()
            .find(|b| b.address == watch)
            .unwrap_or_else(|| {
                panic!(
                    "an armed hardware watchpoint at {watch:?} is missing from breakpoints(); \
                     listed: {listed:?}. A caller cannot see, and therefore cannot remove, \
                     something the debugger has armed in the target."
                )
            });
        assert!(
            matches!(found.kind, BreakpointKind::DataWrite),
            "the watchpoint is listed as {:?}, not as the write watch that was armed — a caller \
             cannot tell it apart from a software breakpoint",
            found.kind
        );
        assert!(
            found.original_byte.is_none(),
            "a hardware watchpoint patches no byte, so reporting one invents a restore that \
             will never happen"
        );

        // Removing it must take it out of the list too, or the list grows
        // stale in the opposite direction.
        assert!(
            dbg.remove_hardware_watchpoint(watch).await.expect("remove_hardware_watchpoint"),
            "the watchpoint should have been found for removal"
        );
        let listed = dbg.breakpoints().await.expect("breakpoints");
        assert!(
            !listed.iter().any(|b| b.address == watch),
            "a removed watchpoint is still listed as armed"
        );
        let _ = dbg.kill().await;
    }

    /// Dropping the debugger must leave no armed debug register behind.
    ///
    /// `detach()` was fixed for this in iteration 366, but `Drop` is the path
    /// a real caller hits when a session ends by scope exit, a `?`, or a
    /// panic — and `Drop` cannot await, so it could not reuse that fix. Left
    /// armed, the target keeps running with `DR7` enabled and the first access
    /// to the watched address traps with no debugger to take it: the same
    /// hazard the `0xCC` sweep in `Drop` has guarded against for a long time,
    /// one layer down.
    #[tokio::test]
    async fn dropping_the_debugger_disarms_hardware_watchpoints() {
        use winapi::um::processthreadsapi::{GetThreadContext, OpenThread};

        let raw_tid = {
            let dbg = WindowsDebugger::new();
            dbg.launch(cmd_launch_options(&["/C", "ping", "-n", "6", "127.0.0.1"]))
                .await
                .expect("launch should succeed");

            let mut tid = None;
            for _ in 0..50 {
                let ev = dbg.continue_execution().await.expect("continue_execution");
                if matches!(ev.reason, StopReason::Breakpoint { .. }) {
                    tid = Some(ev.tid);
                    break;
                }
                if ev.reason.is_exit() {
                    break;
                }
            }
            let Some(tid) = tid else { return };

            let regs = dbg.get_registers(tid).await.expect("get_registers");
            let watch = Address(regs.sp & !7);
            dbg.set_watchpoint_sized(watch, BreakpointKind::DataWrite, 8)
                .await
                .expect("set_watchpoint_sized");
            assert_ne!(
                dbg.get_register(tid, "dr7").await.expect("dr7") & 1,
                0,
                "the watchpoint must really be armed, or this test proves nothing"
            );
            u32::try_from(tid.0).expect("thread id fits")
            // `dbg` is dropped here, with NO explicit detach.
        };

        // Read the debug registers directly: there is no debugger any more,
        // which is the whole point.
        let dr7 = unsafe {
            let h = OpenThread(THREAD_ALL_ACCESS, FALSE, raw_tid);
            if h.is_null() {
                return; // the target already exited; nothing to observe
            }
            let mut ctx: CONTEXT = std::mem::zeroed();
            ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
            let ok = GetThreadContext(h, &mut ctx);
            CloseHandle(h);
            if ok == 0 {
                return;
            }
            ctx.Dr7
        };
        assert_eq!(
            dr7 & 0b1111_1111,
            0,
            "dropping the debugger left debug registers armed (DR7={dr7:#x}) — the target now \
             traps on the watched address with nobody to handle it"
        );
    }

    /// Detach must leave no armed debug register behind.
    ///
    /// `detach` already restores every planted `0xCC`, because a leftover int3
    /// raises an exception in a process that has no debugger left to handle it
    /// — fatal. A leftover ARMED debug register is the same hazard one layer
    /// down, and it arrived with hardware watchpoints (iteration 361) without
    /// ever being covered: the target keeps running with `DR7` enabled and the
    /// first access to the watched address traps with nobody there to take it.
    ///
    /// The registers are read back through a fresh `OpenThread`, not through
    /// the debugger, because the debugger is gone by then — which is the whole
    /// point.
    #[tokio::test]
    async fn detach_disarms_hardware_watchpoints_so_the_target_does_not_trap_alone() {
        use winapi::um::processthreadsapi::{GetThreadContext, OpenThread};

        let dbg = WindowsDebugger::new();
        dbg.launch(cmd_launch_options(&["/C", "ping", "-n", "6", "127.0.0.1"]))
            .await
            .expect("launch should succeed");

        let mut tid = None;
        for _ in 0..50 {
            let ev = dbg.continue_execution().await.expect("continue_execution");
            if matches!(ev.reason, StopReason::Breakpoint { .. }) {
                tid = Some(ev.tid);
                break;
            }
            if ev.reason.is_exit() {
                break;
            }
        }
        let Some(tid) = tid else { return };

        let regs = dbg.get_registers(tid).await.expect("get_registers");
        let watch = Address(regs.sp & !7);
        dbg.set_watchpoint_sized(watch, BreakpointKind::DataWrite, 8)
            .await
            .expect("set_watchpoint_sized");
        assert_ne!(
            dbg.get_register(tid, "dr7").await.expect("dr7") & 1,
            0,
            "the watchpoint must really be armed, or this test proves nothing"
        );

        dbg.detach().await.expect("detach should succeed");

        // Read the debug registers directly: the debugger is detached now.
        let raw_tid = u32::try_from(tid.0).expect("thread id fits");
        let dr7 = unsafe {
            let h = OpenThread(THREAD_ALL_ACCESS, FALSE, raw_tid);
            assert!(!h.is_null(), "OpenThread should succeed on the still-running target");
            let mut ctx: CONTEXT = std::mem::zeroed();
            ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
            let ok = GetThreadContext(h, &mut ctx);
            CloseHandle(h);
            assert!(ok != 0, "GetThreadContext should succeed");
            ctx.Dr7
        };
        assert_eq!(
            dr7 & 0b1111_1111,
            0,
            "detach left debug registers armed (DR7={dr7:#x}) — the target now traps on the              watched address with no debugger to handle it"
        );
    }

    /// A WRITE watchpoint must fire when the target writes the address.
    ///
    /// Everything from iterations 361-364 is exercised end to end here for the
    /// first time: the slot encoding, arming across threads, re-arming a
    /// thread created afterwards, and the `DR6` decode that turns the trap
    /// into a reported hit. Until now only an EXECUTION hardware breakpoint
    /// had ever been seen to fire — the write path was reasoned about but
    /// never observed.
    ///
    /// The write is produced by injecting a thread whose start routine is
    /// `GetSystemTime`, which writes 16 bytes to the pointer it is handed.
    /// That makes the write land on an address this test chose, instead of
    /// waiting for the target to happen to touch one (measured in iteration
    /// 364: a stack address below `rsp` stayed untouched for 60 instructions,
    /// which left the test green while proving nothing).
    #[tokio::test]
    async fn a_write_watchpoint_fires_when_the_target_writes_the_address() {
        use winapi::um::memoryapi::VirtualAllocEx;
        use winapi::um::processthreadsapi::CreateRemoteThread;
        use winapi::um::winnt::{MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE, PAGE_READWRITE};

        let dbg = WindowsDebugger::new();
        dbg.launch(cmd_launch_options(&["/C", "ping", "-n", "5", "127.0.0.1"]))
            .await
            .expect("launch should succeed");

        let mut reached = false;
        for _ in 0..50 {
            let ev = dbg.continue_execution().await.expect("continue_execution");
            if matches!(ev.reason, StopReason::Breakpoint { .. }) {
                reached = true;
                break;
            }
            if ev.reason.is_exit() {
                break;
            }
        }
        if !reached {
            return;
        }

        let pid = dbg.target_pid().expect("attached").0;
        let handle = unsafe { OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid) };
        assert!(!handle.is_null(), "OpenProcess should succeed");

        // Memory the test owns, so nothing else in the target writes it and a
        // hit can only come from the write this test causes.
        let scratch = unsafe {
            VirtualAllocEx(
                handle,
                std::ptr::null_mut(),
                4096,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE,
            )
        };
        assert!(!scratch.is_null(), "VirtualAllocEx should succeed");
        let watch = Address(scratch as u64);
        assert_eq!(watch.as_u64() % 8, 0, "a fresh allocation is page-aligned");

        dbg.set_watchpoint_sized(watch, BreakpointKind::DataWrite, 8)
            .await
            .expect("set_watchpoint_sized");

        // A tiny injected stub does the write, so it lands exactly on the
        // address this test watches:
        //   48 89 C8              mov  rax, rcx      ; lpParameter
        //   48 C7 00 2A 00 00 00  mov  qword [rax], 42
        //   31 C0                 xor  eax, eax      ; thread exit code
        //   C3                    ret
        // Writing code rather than calling an existing export keeps this
        // independent of which winapi features happen to be enabled.
        const STUB: [u8; 13] = [
            0x48, 0x89, 0xC8, 0x48, 0xC7, 0x00, 0x2A, 0x00, 0x00, 0x00, 0x31, 0xC0, 0xC3,
        ];
        unsafe {
            let code = VirtualAllocEx(
                handle,
                std::ptr::null_mut(),
                4096,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE,
            );
            assert!(!code.is_null(), "VirtualAllocEx(RWX) should succeed");
            let mut written = 0usize;
            let ok = WriteProcessMemory(
                handle,
                code,
                STUB.as_ptr().cast(),
                STUB.len(),
                &mut written,
            );
            assert!(ok != 0 && written == STUB.len(), "the stub should be written whole");
            let th = CreateRemoteThread(
                handle,
                std::ptr::null_mut(),
                0,
                Some(std::mem::transmute::<usize, unsafe extern "system" fn(*mut winapi::ctypes::c_void) -> DWORD>(
                    code as usize,
                )),
                scratch,
                0,
                std::ptr::null_mut(),
            );
            assert!(!th.is_null(), "CreateRemoteThread should succeed");
            CloseHandle(th);
            CloseHandle(handle);
        }

        // Resume until the write happens. The injected thread was born AFTER
        // the arm, so this also depends on the re-arm from iteration 363.
        let mut hit = None;
        for _ in 0..80 {
            let Ok(ev) = dbg.continue_execution().await else { break };
            if ev.reason.is_exit() {
                break;
            }
            if let StopReason::Breakpoint { address, ref bp } = ev.reason {
                if address == watch {
                    hit = Some(bp.kind);
                    break;
                }
            }
        }

        let kind = hit.expect(
            "the target wrote the watched address and no watchpoint hit was reported — the              write path never fires, which no amount of correct DR programming makes up for",
        );
        assert!(
            matches!(kind, BreakpointKind::DataWrite),
            "the hit was reported as {kind:?}, not the write watch that was armed"
        );
        let _ = dbg.kill().await;
    }

    /// A debug-register hit must be REPORTED as one, not as a single step.
    ///
    /// On x86 a hardware breakpoint/watchpoint hit raises
    /// `EXCEPTION_SINGLE_STEP`, the same exception as a single step; only
    /// `DR6` tells them apart. Iterations 361-363 armed the registers
    /// correctly, and then every hit was classified as a plain `SingleStep` —
    /// the debugger did the hard part and discarded the answer on arrival.
    ///
    /// An EXECUTION hardware breakpoint at the current PC is used rather than
    /// a data watchpoint: parking the PC on it makes the hit deterministic
    /// without symbols, whereas waiting for the target to write a watched
    /// address is not reachable reliably (measured: a stack address below
    /// `rsp` was untouched for 60 instructions, which would leave this test
    /// passing without proving anything). Both go through the same `DR6`
    /// decode, which is what is under test.
    #[tokio::test]
    async fn a_debug_register_hit_is_reported_as_a_breakpoint_not_a_single_step() {
        let dbg = WindowsDebugger::new();
        dbg.launch(cmd_launch_options(&["/C", "ping", "-n", "3", "127.0.0.1"]))
            .await
            .expect("launch should succeed");

        let mut tid = None;
        for _ in 0..50 {
            let ev = dbg.continue_execution().await.expect("continue_execution");
            if matches!(ev.reason, StopReason::Breakpoint { .. }) {
                tid = Some(ev.tid);
                break;
            }
            if ev.reason.is_exit() {
                break;
            }
        }
        let Some(tid) = tid else { return };

        let regs = dbg.get_registers(tid).await.expect("get_registers");
        let at = Address(regs.pc);
        dbg.set_watchpoint_sized(at, BreakpointKind::Hardware, 1)
            .await
            .expect("an execution hardware breakpoint must be programmable");

        // `continue_execution` resumes every thread, so the next event is not
        // necessarily ours: a module load, or another thread stopping, can
        // arrive first — which made an earlier version of this test flaky.
        // Walk a bounded number of events looking for the hit, recording what
        // was seen so a failure says something useful.
        //
        // This does NOT weaken the test: if the hit never arrives, or arrives
        // classified as an ordinary single step (the defect), the walk ends
        // with nothing found and the panic below still fires.
        let mut hit = None;
        let mut seen = Vec::new();
        for _ in 0..40 {
            let Ok(ev) = dbg.continue_execution().await else { break };
            if ev.reason.is_exit() {
                seen.push("ProcessExit".to_string());
                break;
            }
            if let StopReason::Breakpoint { address, ref bp } = ev.reason {
                if address == at {
                    hit = Some(bp.kind);
                    break;
                }
            }
            seen.push(format!("{:?}", std::mem::discriminant(&ev.reason)));
        }
        let kind = hit.unwrap_or_else(|| {
            panic!(
                "the hardware breakpoint at {at:?} never produced a reported hit; events seen: {seen:?}. \
                 When DR6 is not consulted the hit arrives classified as an ordinary single step, \
                 so it is never recognised."
            )
        });
        assert!(
            matches!(kind, BreakpointKind::Hardware),
            "the hit was reported with kind {kind:?}, not the hardware breakpoint that was armed"
        );

        // DR6 must have been cleared, or this one hit keeps being re-reported
        // on every later trap.
        let dr6 = dbg.get_register(tid, "dr6").await.expect("dr6");
        assert_eq!(
            dr6 & 0b1111,
            0,
            "DR6 still holds the hit bit — every subsequent trap will look like this hit"
        );
        let _ = dbg.kill().await;
    }

    /// A thread born after the watchpoint must inherit it.
    ///
    /// The debug registers are per-thread and are NOT inherited: a thread the
    /// target spawns after `set_watchpoint_sized` starts with empty debug
    /// registers and watches nothing, while the caller still believes the
    /// address is covered. Iteration 362 armed every thread that existed at
    /// the time; this is the same hole for the ones that appear afterwards,
    /// and it is the one that matters in a real target, which spawns threads
    /// while you debug it.
    #[tokio::test]
    async fn a_thread_created_after_the_watchpoint_still_inherits_it() {
        use winapi::um::processthreadsapi::CreateRemoteThread;
        use winapi::um::synchapi::Sleep;

        let dbg = WindowsDebugger::new();
        dbg.launch(cmd_launch_options(&["/C", "ping", "-n", "5", "127.0.0.1"]))
            .await
            .expect("launch should succeed");

        let mut tid = None;
        for _ in 0..50 {
            let ev = dbg.continue_execution().await.expect("continue_execution");
            if matches!(ev.reason, StopReason::Breakpoint { .. }) {
                tid = Some(ev.tid);
                break;
            }
            if ev.reason.is_exit() {
                break;
            }
        }
        let Some(tid) = tid else { return };

        // Arm FIRST, while the second thread does not exist yet.
        let regs = dbg.get_registers(tid).await.expect("get_registers");
        let watch = Address(regs.sp & !7);
        dbg.set_watchpoint_sized(watch, BreakpointKind::DataWrite, 4)
            .await
            .expect("set_watchpoint_sized");

        let pid = dbg.target_pid().expect("attached").0;
        let handle = unsafe { OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid) };
        assert!(!handle.is_null(), "OpenProcess should succeed");
        let new_tid = unsafe {
            let mut raw: DWORD = 0;
            let th = CreateRemoteThread(
                handle,
                std::ptr::null_mut(),
                0,
                Some(std::mem::transmute::<usize, unsafe extern "system" fn(*mut winapi::ctypes::c_void) -> DWORD>(
                    Sleep as *const () as usize,
                )),
                3000 as *mut _,
                0,
                &mut raw,
            );
            assert!(!th.is_null(), "CreateRemoteThread should succeed");
            CloseHandle(th);
            CloseHandle(handle);
            ThreadId(raw)
        };
        if !dbg.threads().await.expect("threads").contains(&new_tid) {
            return; // the injected thread already exited
        }

        // The new thread has empty debug registers until we reconcile.
        let _ = dbg.continue_execution().await;

        let dr0 = dbg.get_register(new_tid, "dr0").await.expect("dr0 on the new thread");
        let dr7 = dbg.get_register(new_tid, "dr7").await.expect("dr7 on the new thread");
        assert_eq!(
            dr0,
            watch.as_u64(),
            "a thread created after the watchpoint is not watching the address — every write              it makes is missed while the caller believes the address is covered"
        );
        assert_eq!(dr7 & 1, 1, "the new thread's slot is not enabled");

        // Reconciling repeatedly must not consume a second slot for the same
        // watchpoint — otherwise four resumes exhaust DR0-DR3.
        let _ = dbg.continue_execution().await;
        let dr7_again = dbg.get_register(new_tid, "dr7").await.expect("dr7");
        assert_eq!(
            dr7_again & 0b1010_1010_1010_1010, 0,
            "re-arming allocated another slot for a watchpoint already armed"
        );
        assert_eq!(
            (dr7_again >> 2) & 1,
            0,
            "a second slot was consumed for the same watchpoint"
        );
        let _ = dbg.kill().await;
    }

    /// A watchpoint must cover every thread, not just the current one.
    ///
    /// The x86 debug registers are PER-THREAD. Arming only the thread that
    /// happens to be stopped left a watchpoint that never fires when any other
    /// thread touches the address, while the caller was told the address was
    /// watched. That is a silent miss, not an error — the shape this session
    /// has been hunting since iteration 356.
    ///
    /// A real second thread is injected with `CreateRemoteThread`, the same
    /// device `threads_enumerates_more_than_the_last_stopping_thread` uses.
    #[tokio::test]
    async fn a_watchpoint_covers_every_thread_not_just_the_stopped_one() {
        use winapi::um::processthreadsapi::CreateRemoteThread;
        use winapi::um::synchapi::Sleep;

        let dbg = WindowsDebugger::new();
        dbg.launch(cmd_launch_options(&["/C", "ping", "-n", "5", "127.0.0.1"]))
            .await
            .expect("launch should succeed");

        let mut tid = None;
        for _ in 0..50 {
            let ev = dbg.continue_execution().await.expect("continue_execution");
            if matches!(ev.reason, StopReason::Breakpoint { .. }) {
                tid = Some(ev.tid);
                break;
            }
            if ev.reason.is_exit() {
                break;
            }
        }
        let Some(tid) = tid else { return };

        let pid = dbg.target_pid().expect("attached").0;
        let handle = unsafe { OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid) };
        assert!(!handle.is_null(), "OpenProcess should succeed");
        // See `threads_enumerates_more_than_the_last_stopping_thread` for why
        // `Sleep` can stand in for a thread start routine here.
        let new_tid = unsafe {
            let mut raw: DWORD = 0;
            let th = CreateRemoteThread(
                handle,
                std::ptr::null_mut(),
                0,
                Some(std::mem::transmute::<usize, unsafe extern "system" fn(*mut winapi::ctypes::c_void) -> DWORD>(
                    Sleep as *const () as usize,
                )),
                3000 as *mut _,
                0,
                &mut raw,
            );
            assert!(!th.is_null(), "CreateRemoteThread should succeed");
            CloseHandle(th);
            CloseHandle(handle);
            ThreadId(raw)
        };

        let threads = dbg.threads().await.expect("threads");
        if !threads.contains(&new_tid) {
            return; // the injected thread already exited; nothing to prove
        }

        let regs = dbg.get_registers(tid).await.expect("get_registers");
        let watch = Address(regs.sp & !7);
        dbg.set_watchpoint_sized(watch, BreakpointKind::DataWrite, 4)
            .await
            .expect("set_watchpoint_sized");

        // The thread that was NOT stopped must be watching the same address in
        // the same slot.
        let dr0 = dbg.get_register(new_tid, "dr0").await.expect("dr0 on the second thread");
        let dr7 = dbg.get_register(new_tid, "dr7").await.expect("dr7 on the second thread");
        assert_eq!(
            dr0,
            watch.as_u64(),
            "the second thread is not watching the address — a write from it would be missed              while the caller believes the address is watched"
        );
        assert_eq!(dr7 & 1, 1, "the second thread's slot 0 is not enabled");

        // Disarming must clear it everywhere, or the slot leaks on the threads
        // that were skipped.
        assert!(
            dbg.remove_hardware_watchpoint(watch).await.expect("remove_hardware_watchpoint"),
            "the watchpoint was not found"
        );
        assert_eq!(
            dbg.get_register(new_tid, "dr7").await.expect("dr7") & 1,
            0,
            "the second thread still has the watchpoint armed after removal"
        );
        let _ = dbg.kill().await;
    }

    /// A hardware watchpoint must actually reach the debug registers.
    ///
    /// Before this, `set_watchpoint_sized` fell through to the trait default,
    /// which forwards to `set_breakpoint`, which rejects everything that is
    /// not `Software` — so every hardware watchpoint request on this backend
    /// failed with "only software breakpoints are implemented" even though
    /// `DR0`-`DR7` were already reachable through get/set_registers.
    #[tokio::test]
    async fn a_hardware_watchpoint_is_programmed_into_the_debug_registers() {
        let dbg = WindowsDebugger::new();
        dbg.launch(cmd_launch_options(&["/C", "ping", "-n", "3", "127.0.0.1"]))
            .await
            .expect("launch should succeed");

        let mut tid = None;
        for _ in 0..50 {
            let ev = dbg.continue_execution().await.expect("continue_execution");
            if matches!(ev.reason, StopReason::Breakpoint { .. }) {
                tid = Some(ev.tid);
                break;
            }
            if ev.reason.is_exit() {
                break;
            }
        }
        let Some(tid) = tid else { return };
        // A stack address, 8-byte aligned, that the target really owns.
        let regs = dbg.get_registers(tid).await.expect("get_registers");
        let watch = Address(regs.sp & !7);

        dbg.set_watchpoint_sized(watch, BreakpointKind::DataWrite, 4)
            .await
            .expect("a 4-byte write watchpoint must be programmable");

        let dr0 = dbg.get_register(tid, "dr0").await.expect("get_register(dr0)");
        let dr7 = dbg.get_register(tid, "dr7").await.expect("get_register(dr7)");
        assert_eq!(dr0, watch.as_u64(), "the watched address never reached DR0");
        assert_eq!(dr7 & 1, 1, "L0 is clear — the slot was never enabled");
        assert_eq!((dr7 >> 16) & 0b11, 0b01, "R/W0 does not say write");
        assert_eq!((dr7 >> 18) & 0b11, 0b11, "LEN0 does not say 4 bytes");

        // A second watchpoint must take the NEXT slot, not overwrite the first.
        let watch2 = Address((regs.sp & !7).wrapping_add(16));
        dbg.set_watchpoint_sized(watch2, BreakpointKind::DataReadWrite, 8)
            .await
            .expect("a second watchpoint must get its own slot");
        let dr1 = dbg.get_register(tid, "dr1").await.expect("get_register(dr1)");
        let dr0_again = dbg.get_register(tid, "dr0").await.expect("get_register(dr0)");
        assert_eq!(dr1, watch2.as_u64(), "the second watchpoint did not land in DR1");
        assert_eq!(dr0_again, watch.as_u64(), "the second watchpoint clobbered the first");

        // Invalid requests must leave the registers untouched, not
        // half-programmed.
        let before = dbg.get_register(tid, "dr7").await.expect("dr7");
        assert!(
            dbg.set_watchpoint_sized(watch, BreakpointKind::DataWrite, 3).await.is_err(),
            "a 3-byte watchpoint is not representable and must be refused"
        );
        assert_eq!(
            dbg.get_register(tid, "dr7").await.expect("dr7"),
            before,
            "a refused watchpoint still modified DR7"
        );

        // Disarming must free the slot, or the four DRs leak one per removed
        // watchpoint until detach.
        assert!(
            dbg.remove_hardware_watchpoint(watch).await.expect("remove_hardware_watchpoint"),
            "the watchpoint we just armed was not found in any slot"
        );
        let dr7 = dbg.get_register(tid, "dr7").await.expect("dr7");
        assert_eq!(dr7 & 1, 0, "L0 still set — the slot was not freed");
        assert_eq!(
            dbg.get_register(tid, "dr1").await.expect("dr1"),
            watch2.as_u64(),
            "freeing slot 0 disturbed the watchpoint in slot 1"
        );
        assert!(
            !dbg.remove_hardware_watchpoint(watch).await.expect("remove again"),
            "removing an already-removed watchpoint reported a removal that did not happen"
        );
        let _ = dbg.kill().await;
    }

    /// Writing over a planted breakpoint keeps it armed and is not undone.
    ///
    /// Two defects at once if the write goes through unchanged: it overwrites
    /// the `0xCC`, so a breakpoint still reported as enabled silently stops
    /// firing; and the byte it replaced remains recorded as "the original",
    /// so `remove_breakpoint` later restores the STALE byte and quietly
    /// reverts the caller's write. This checks both.
    #[tokio::test]
    async fn writing_over_a_planted_breakpoint_keeps_it_armed_and_survives_removal() {
        let dbg = WindowsDebugger::new();
        dbg.launch(cmd_launch_options(&["/C", "ping", "-n", "3", "127.0.0.1"]))
            .await
            .expect("launch should succeed");

        let mut tid = None;
        for _ in 0..50 {
            let ev = dbg.continue_execution().await.expect("continue_execution");
            if matches!(ev.reason, StopReason::Breakpoint { .. }) {
                tid = Some(ev.tid);
                break;
            }
            if ev.reason.is_exit() {
                break;
            }
        }
        let Some(tid) = tid else { return };
        let regs = dbg.get_registers(tid).await.expect("get_registers");
        let addr = Address(regs.pc);

        let original = dbg.read_memory(addr, 1).await.expect("read_memory")[0];
        dbg.set_breakpoint(addr, BreakpointKind::Software).await.expect("set_breakpoint");

        // A byte that is neither the original nor `int3`, so neither can be
        // mistaken for a successful write.
        let new_byte = original ^ 0x5A;
        assert_ne!(new_byte, 0xCC);
        dbg.write_memory(addr, &[new_byte]).await.expect("write_memory");

        assert_eq!(
            dbg.read_memory_raw(addr, 1).await.expect("raw")[0],
            0xCC,
            "the write overwrote our trap — the breakpoint is listed as enabled but cannot fire"
        );
        assert_eq!(
            dbg.read_memory(addr, 1).await.expect("read_memory")[0],
            new_byte,
            "the masked view must show what the caller wrote"
        );

        // Removing the breakpoint must restore what the CALLER wrote, not the
        // byte that was there before the write.
        dbg.remove_breakpoint(addr).await.expect("remove_breakpoint");
        assert_eq!(
            dbg.read_memory_raw(addr, 1).await.expect("raw")[0],
            new_byte,
            "removing the breakpoint restored a stale byte and undid the caller's write"
        );
        let _ = dbg.kill().await;
    }

    /// Reading memory must show the target's byte, not our breakpoint.
    ///
    /// `read_memory` used to return the process image verbatim, `0xCC`
    /// included. Everything downstream that decodes or compares those bytes
    /// then works on the debugger's own patch: `step_over`'s instruction
    /// length (iteration 358), a conditional-breakpoint expression reading a
    /// variable (`conditional_breakpoint.rs`), any disassembly view. The patch
    /// is the debugger's business, not the target's contents.
    ///
    /// A DISABLED breakpoint must not be masked: nothing is planted there, so
    /// masking it would invent a byte the process does not have.
    #[tokio::test]
    async fn read_memory_hides_our_breakpoints_and_raw_still_shows_them() {
        let dbg = WindowsDebugger::new();
        dbg.launch(cmd_launch_options(&["/C", "ping", "-n", "3", "127.0.0.1"]))
            .await
            .expect("launch should succeed");

        let mut tid = None;
        for _ in 0..50 {
            let ev = dbg.continue_execution().await.expect("continue_execution");
            if matches!(ev.reason, StopReason::Breakpoint { .. }) {
                tid = Some(ev.tid);
                break;
            }
            if ev.reason.is_exit() {
                break;
            }
        }
        let Some(tid) = tid else { return };
        let regs = dbg.get_registers(tid).await.expect("get_registers");
        let addr = Address(regs.pc);

        let original = dbg.read_memory(addr, 4).await.expect("read_memory");
        dbg.set_breakpoint(addr, BreakpointKind::Software).await.expect("set_breakpoint");

        assert_eq!(
            dbg.read_memory_raw(addr, 4).await.expect("raw")[0],
            0xCC,
            "the implant must really be in the process — otherwise this test proves nothing"
        );
        assert_eq!(
            dbg.read_memory(addr, 4).await.expect("read_memory"),
            original,
            "read_memory handed back our own 0xCC instead of the target's byte"
        );

        // Disabled: nothing planted, so nothing to hide.
        dbg.disable_breakpoint(addr).await.expect("disable_breakpoint");
        assert_eq!(
            dbg.read_memory(addr, 4).await.expect("read_memory"),
            dbg.read_memory_raw(addr, 4).await.expect("raw"),
            "a disabled breakpoint has no patch, so masked and raw reads must agree"
        );
        let _ = dbg.kill().await;
    }

    /// Resuming from a breakpoint we planted must actually make progress.
    ///
    /// When a software breakpoint fires, `rewind_past_own_breakpoint` puts the
    /// PC back on the breakpoint address — where our `0xCC` is STILL planted.
    /// Resuming from there re-executes the trap immediately, so the original
    /// instruction never runs and the target never advances past the first
    /// breakpoint it hits. "Continue after a breakpoint" is the single most
    /// common debugger operation, so this is not an edge case.
    ///
    /// The hit is forced rather than waited for: the PC is parked on an
    /// address we have patched, which makes the first hit deterministic
    /// without needing symbols to find a loop in the target.
    #[tokio::test]
    async fn continuing_from_a_planted_breakpoint_does_not_re_trap_at_the_same_address() {
        let dbg = WindowsDebugger::new();
        dbg.launch(cmd_launch_options(&["/C", "ping", "-n", "3", "127.0.0.1"]))
            .await
            .expect("launch should succeed");

        let mut tid = None;
        for _ in 0..50 {
            let ev = dbg.continue_execution().await.expect("continue_execution");
            if matches!(ev.reason, StopReason::Breakpoint { .. }) {
                tid = Some(ev.tid);
                break;
            }
            if ev.reason.is_exit() {
                break;
            }
        }
        let Some(tid) = tid else { return };
        let regs = dbg.get_registers(tid).await.expect("get_registers");
        let addr = Address(regs.pc);

        dbg.set_breakpoint(addr, BreakpointKind::Software).await.expect("set_breakpoint");
        // Park the PC on the patched address so the next resume is guaranteed
        // to hit OUR breakpoint.
        let mut regs = dbg.get_registers(tid).await.expect("get_registers");
        regs.pc = addr.as_u64();
        regs.set("rip", addr.as_u64());
        dbg.set_registers(tid, regs).await.expect("set_registers");

        let first = dbg.continue_execution().await.expect("continue_execution");
        let StopReason::Breakpoint { address: hit, .. } = first.reason else {
            let _ = dbg.kill().await;
            return; // never reached our breakpoint; nothing to assert about
        };
        assert_eq!(hit, addr, "the forced hit should be at the address we patched");

        // The defect: this resumes with `0xCC` still at the PC, so it traps
        // again at the very same address without executing the instruction.
        let second = dbg.continue_execution().await.expect("continue_execution");
        if let StopReason::Breakpoint { address: again, .. } = second.reason {
            assert_ne!(
                again, addr,
                "resuming from a planted breakpoint trapped again at the same address —                  the original instruction never ran, so the target cannot advance past                  any breakpoint it hits"
            );
        }
        let _ = dbg.kill().await;
    }

    /// `breakpoints()` iterates the tracking map's KEYS and rebuilds each
    /// entry with `Breakpoint::new_software`, which hardcodes
    /// `original_byte: None` — throwing away the value the very same map is
    /// holding. The byte is what `detach()`/`Drop` will write back, so a
    /// caller inspecting breakpoints cannot see what the target's code will
    /// be restored to, nor tell a real tracked breakpoint from a phantom one.
    ///
    /// Same class as iter 216: information that is available right there and
    /// is discarded on the way out.
    #[tokio::test]
    async fn breakpoints_report_the_original_byte_they_will_restore() {
        let dbg = WindowsDebugger::new();
        dbg.launch(cmd_launch_options(&["/C", "ping", "-n", "3", "127.0.0.1"]))
            .await
            .expect("launch should succeed");

        let mut tid = None;
        for _ in 0..50 {
            let ev = dbg.continue_execution().await.expect("continue_execution");
            if matches!(ev.reason, StopReason::Breakpoint { .. }) {
                tid = Some(ev.tid);
                break;
            }
            if ev.reason.is_exit() {
                break;
            }
        }
        let Some(tid) = tid else { return };
        let regs = dbg.get_registers(tid).await.expect("get_registers");
        let addr = Address(regs.pc);

        let before = dbg.read_memory(addr, 1).await.expect("read_memory")[0];
        dbg.set_breakpoint(addr, BreakpointKind::Software).await.expect("set_breakpoint");
        // The patch really landed, so `before` is genuinely the original.
        // `read_memory` now masks our patches, so verifying the IMPLANT needs
        // the raw view — that is what this assertion is about.
        assert_eq!(dbg.read_memory_raw(addr, 1).await.expect("read_memory")[0], 0xCC);

        let listed = dbg.breakpoints().await.expect("breakpoints");
        let bp = listed
            .iter()
            .find(|b| b.address == addr)
            .expect("the breakpoint we just set must be listed");
        assert_eq!(
            bp.original_byte,
            Some(before),
            "breakpoints() discards the original byte the tracking map holds — the              caller cannot see what detach/Drop will restore"
        );
        assert!(bp.enabled, "a tracked breakpoint is an active one");
        let _ = dbg.kill().await;
    }

    /// `Breakpoint::hit_count` is surfaced to MCP clients by
    /// `debug.breakpoints`, but no backend ever incremented it — every
    /// breakpoint reported zero hits forever, no matter how many times it
    /// actually fired. A number that looks meaningful and never is, on a
    /// user-facing surface.
    #[tokio::test]
    async fn breakpoints_count_the_hits_they_actually_take() {
        let dbg = WindowsDebugger::new();
        dbg.launch(cmd_launch_options(&["/C", "ping", "-n", "3", "127.0.0.1"]))
            .await
            .expect("launch should succeed");

        let mut tid = None;
        for _ in 0..50 {
            let ev = dbg.continue_execution().await.expect("continue_execution");
            if matches!(ev.reason, StopReason::Breakpoint { .. }) {
                tid = Some(ev.tid);
                break;
            }
            if ev.reason.is_exit() {
                break;
            }
        }
        let Some(tid) = tid else { return };
        let regs = dbg.get_registers(tid).await.expect("get_registers");
        let addr = Address(regs.pc);

        dbg.set_breakpoint(addr, BreakpointKind::Software).await.expect("set_breakpoint");
        assert_eq!(
            dbg.breakpoints().await.expect("breakpoints")[0].hit_count,
            0,
            "a freshly set breakpoint has taken no hits"
        );

        // The tracee resumes exactly onto the planted int3, so this must come
        // straight back as our breakpoint.
        let ev = dbg.continue_execution().await.expect("continue_execution");
        if !matches!(ev.reason, StopReason::Breakpoint { .. }) {
            let _ = dbg.kill().await;
            return; // did not land on our breakpoint; nothing to assert
        }

        let listed = dbg.breakpoints().await.expect("breakpoints");
        let bp = listed.iter().find(|b| b.address == addr).expect("still tracked");
        assert_eq!(
            bp.hit_count, 1,
            "the breakpoint was hit once but reports {} hits — hit_count is never              maintained, yet debug.breakpoints publishes it",
            bp.hit_count
        );
        let _ = dbg.kill().await;
    }

    /// The trait exposes four distinct operations — set / remove / enable /
    /// disable — but `disable_breakpoint` just forwarded to
    /// `remove_breakpoint`, so a disabled breakpoint VANISHED from
    /// `breakpoints()` instead of appearing with `enabled: false`. The
    /// `enabled` field could therefore never be `false`, and a caller could
    /// not tell "temporarily off" from "gone". `debug.breakpoints` publishes
    /// that field to MCP clients.
    ///
    /// Disabling must restore the original byte in the target (the
    /// breakpoint really stops firing) while KEEPING the entry tracked.
    #[tokio::test]
    async fn a_disabled_breakpoint_stays_listed_and_stops_firing() {
        let dbg = WindowsDebugger::new();
        dbg.launch(cmd_launch_options(&["/C", "ping", "-n", "3", "127.0.0.1"]))
            .await
            .expect("launch should succeed");

        let mut tid = None;
        for _ in 0..50 {
            let ev = dbg.continue_execution().await.expect("continue_execution");
            if matches!(ev.reason, StopReason::Breakpoint { .. }) {
                tid = Some(ev.tid);
                break;
            }
            if ev.reason.is_exit() {
                break;
            }
        }
        let Some(tid) = tid else { return };
        let regs = dbg.get_registers(tid).await.expect("get_registers");
        let addr = Address(regs.pc);

        let original = dbg.read_memory(addr, 1).await.expect("read_memory")[0];
        dbg.set_breakpoint(addr, BreakpointKind::Software).await.expect("set_breakpoint");
        assert_eq!(dbg.read_memory_raw(addr, 1).await.expect("read")[0], 0xCC);

        dbg.disable_breakpoint(addr).await.expect("disable_breakpoint");

        // The patch is really gone — a disabled breakpoint must not fire.
        assert_eq!(
            dbg.read_memory(addr, 1).await.expect("read")[0],
            original,
            "disabling must restore the original byte, or the breakpoint still fires"
        );
        // ...but it is still known, and reported as disabled.
        let listed = dbg.breakpoints().await.expect("breakpoints");
        let bp = listed.iter().find(|b| b.address == addr).unwrap_or_else(|| {
            panic!("a disabled breakpoint vanished from breakpoints() — `enabled` can                     never be false and disable is indistinguishable from remove")
        });
        assert!(!bp.enabled, "it is listed but still claims to be enabled");

        // Re-enabling must actually re-plant, NOT be swallowed by
        // `set_breakpoint`'s idempotency guard just because it is tracked.
        dbg.enable_breakpoint(addr).await.expect("enable_breakpoint");
        assert_eq!(
            dbg.read_memory_raw(addr, 1).await.expect("read")[0],
            0xCC,
            "re-enabling a tracked-but-disabled breakpoint planted nothing"
        );
        assert!(
            dbg.breakpoints().await.expect("breakpoints")
                .iter().find(|b| b.address == addr).expect("tracked").enabled
        );

        // And removing still works from either state.
        dbg.remove_breakpoint(addr).await.expect("remove_breakpoint");
        assert!(dbg.breakpoints().await.expect("breakpoints").is_empty());
        assert_eq!(dbg.read_memory(addr, 1).await.expect("read")[0], original);
        let _ = dbg.kill().await;
    }

    /// Stress version of the test above. That one exercises the exit race
    /// exactly once per run, which made a REAL bug look like environmental
    /// noise: `run_to_return` returned
    /// `RegisterError("GetThreadContext failed for TID(…)")` in roughly one
    /// run out of six, because the followed thread can die before the
    /// process's `ProcessExit` event is delivered — a window the `is_exit()`
    /// guard does not cover.
    ///
    /// Repeating the scenario turns a 1-in-6 flake into a near-certain
    /// failure pre-fix (1 - (5/6)^30 ≈ 99.6%), so the regression cannot come
    /// back disguised as a flake again.
    #[tokio::test]
    async fn run_to_return_survives_the_thread_exiting_before_the_process() {
        for attempt in 0..30 {
            let dbg = WindowsDebugger::new();
            dbg.launch(cmd_launch_options(&["/C", "exit", "0"]))
                .await
                .expect("launch should succeed");

            let mut tid = None;
            for _ in 0..50 {
                let event = dbg
                    .continue_execution()
                    .await
                    .expect("continue_execution should not error");
                if matches!(event.reason, StopReason::Breakpoint { .. }) {
                    tid = Some(event.tid);
                    break;
                }
                if event.reason.is_exit() {
                    break;
                }
            }
            // If the process outran us to exit, this attempt cannot set up
            // the scenario — skip it rather than failing for the wrong
            // reason. (The loop above is the only place that can happen.)
            let Some(tid) = tid else { continue };
            let Ok(_regs) = dbg.get_registers(tid).await else { continue };

            let unreachable_target = Address(alloc_unreachable_code_page(&dbg));
            match dbg.run_to_return(tid, unreachable_target, 0).await {
                Ok(event) => assert!(
                    event.reason.is_exit(),
                    "attempt {attempt}: expected a ProcessExit event, got {:?}",
                    event.reason
                ),
                Err(e) => panic!(
                    "attempt {attempt}: run_to_return must return the real ProcessExit \
                     event even when the followed thread dies first, not error: {e:?}"
                ),
            }
        }
    }

    /// Same class as `run_to_return_survives_the_thread_exiting_before_the_
    /// process` (iter 241): `step_over` guards `is_exit()` after the step,
    /// but then reads registers with `?`. If the followed thread dies while
    /// the process is still alive, that read fails and the error is
    /// propagated instead of the pending exit event. Stressed 30x because a
    /// single attempt is exactly how the sibling bug hid as "flakiness".
    #[tokio::test]
    async fn step_over_survives_the_thread_exiting_before_the_process() {
        for attempt in 0..30 {
            let dbg = WindowsDebugger::new();
            dbg.launch(cmd_launch_options(&["/C", "exit", "0"]))
                .await
                .expect("launch should succeed");

            let mut tid = None;
            for _ in 0..50 {
                let event = dbg
                    .continue_execution()
                    .await
                    .expect("continue_execution should not error");
                if matches!(event.reason, StopReason::Breakpoint { .. }) {
                    tid = Some(event.tid);
                    break;
                }
                if event.reason.is_exit() {
                    break;
                }
            }
            let Some(tid) = tid else { continue };

            // Step until the process runs out; every call must either report
            // progress or the exit, never a register-read error.
            for _ in 0..2000 {
                match dbg.step_over(tid).await {
                    Ok(ev) => {
                        if ev.reason.is_exit() {
                            break;
                        }
                    }
                    Err(e) => panic!(
                        "attempt {attempt}: step_over must not surface a register-read                          error when the followed thread goes away: {e:?}"
                    ),
                }
            }
        }
    }

    /// Mirrors `linux_debugger::live_tests::single_step_is_classified_as_
    /// single_step_not_breakpoint`. Windows classifies this via a
    /// genuinely different mechanism than Linux's byte-check heuristic —
    /// `classify_event` maps `EXCEPTION_SINGLE_STEP` directly to
    /// `StopReason::SingleStep` (a distinct exception code from
    /// `EXCEPTION_BREAKPOINT`, not inferred after the fact) — but that
    /// path never had a dedicated live test proving it either.
    #[tokio::test]
    async fn single_step_is_classified_as_single_step_not_breakpoint() {
        let dbg = WindowsDebugger::new();
        dbg.launch(cmd_launch_options(&["/C", "exit", "0"]))
            .await
            .expect("launch should succeed");

        let mut tid = None;
        for _ in 0..50 {
            let event = dbg.continue_execution().await.expect("continue_execution should not error");
            if matches!(event.reason, StopReason::Breakpoint { .. }) {
                tid = Some(event.tid);
                break;
            }
            if event.reason.is_exit() {
                break;
            }
        }
        let tid = tid.expect("expected the initial system breakpoint");

        let event = dbg.single_step(tid).await.expect("single_step should succeed");
        match &event.reason {
            StopReason::SingleStep { address } => {
                assert_ne!(address.as_u64(), 0, "SingleStep address should be the real post-step rip, not left at 0");
            }
            other => panic!("expected StopReason::SingleStep, got {other:?} — a genuine single-step trap should never be reported as a Breakpoint"),
        }

        let _ = dbg.kill().await;
    }

    /// Mirrors `linux_debugger::live_tests::hardware_debug_registers_
    /// round_trip_via_peekuser_pokeuser`. **History**: the first version of
    /// this test (iter 181) wrote DR0/DR7 via two SEPARATE `set_register`
    /// calls and found DR0 reading back as `0` — a real bug (iter 183):
    /// `set_register("dr7", ...)` does its own internal `get_registers`
    /// (which could read a stale, pre-write DR0) → modify → `set_registers`,
    /// clobbering the DR0 an earlier call had just set. That's now fixed at
    /// the production call site (`apply_watchpoint_registers` batches every
    /// DR field into one `set_registers` call, iter 183). This version
    /// applies the same batching AND uses a genuinely spec-correct DR7
    /// value: only `L0` (bit 0, slot-0 local enable) plus `R/W0`+`LEN0`
    /// (bits 16-19, a real 2-byte write watchpoint encoding) — the
    /// earlier diagnostic value additionally poked DR7 bits 10/12
    /// (Intel-reserved, not meaningful watchpoint configuration) and
    /// found THOSE specifically didn't round-trip; this version avoids
    /// asserting on reserved bits a real debugger would never rely on.
    #[tokio::test]
    async fn hardware_debug_registers_round_trip() {
        let dbg = WindowsDebugger::new();
        dbg.launch(cmd_launch_options(&["/C", "ping", "-n", "3", "127.0.0.1"]))
            .await
            .expect("launch should succeed");

        let mut tid = None;
        for _ in 0..50 {
            let event = dbg.continue_execution().await.expect("continue_execution should not error");
            if matches!(event.reason, StopReason::Breakpoint { .. }) {
                tid = Some(event.tid);
                break;
            }
            if event.reason.is_exit() {
                break;
            }
        }
        let tid = tid.expect("expected the initial system breakpoint");
        let event = dbg.single_step(tid).await.expect("single_step should succeed");
        let tid = event.tid;

        let mut regs = dbg.get_registers(tid).await.expect("get_registers should succeed");
        let watch_addr = regs.pc;

        regs.set("dr0", watch_addr);
        // L0 (bit 0, enable slot 0) | R/W0 = 0b01 write (bits 16-17) |
        // LEN0 = 0b01 two-byte (bits 18-19) — no reserved bits touched.
        let dr7_value: u64 = 1 | (0b01 << 16) | (0b01 << 18);
        regs.set("dr7", dr7_value);
        dbg.set_registers(tid, regs).await.expect("set_registers(dr0+dr7 combined) should succeed");

        let dr0_readback = dbg.get_register(tid, "dr0").await.expect("get_register(dr0) should succeed");
        let dr7_readback = dbg.get_register(tid, "dr7").await.expect("get_register(dr7) should succeed");
        assert_eq!(dr0_readback, watch_addr, "DR0 should read back exactly what was written, not silently stay 0");
        assert_eq!(dr7_readback, dr7_value, "DR7 should read back exactly what was written");

        let _ = dbg.kill().await;
    }

    /// `backtrace` at the initial breakpoint should return at least the
    /// current frame with a `pc` matching the live register state — proves
    /// the `FramePointerUnwinder` wiring (register fetch + synchronous
    /// memory-read closure) works against a real process, even though a deep
    /// unwind isn't guaranteed at the very first breakpoint (ntdll's
    /// initialization code is not guaranteed to preserve `rbp` there).
    #[tokio::test]
    async fn backtrace_returns_the_current_frame() {
        let dbg = WindowsDebugger::new();
        dbg.launch(cmd_launch_options(&["/C", "exit", "0"]))
            .await
            .expect("launch should succeed");

        let mut tid = None;
        for _ in 0..50 {
            let event = dbg.continue_execution().await.expect("continue_execution should not error");
            if matches!(event.reason, StopReason::Breakpoint { .. }) {
                tid = Some(event.tid);
                break;
            }
            if event.reason.is_exit() {
                break;
            }
        }
        let tid = tid.expect("expected the initial system breakpoint");

        let regs = dbg.get_registers(tid).await.expect("get_registers should succeed");
        let frames = dbg.backtrace(tid).await.expect("backtrace should succeed against a live process");
        assert!(!frames.is_empty(), "backtrace should return at least the current frame");
        assert_eq!(frames[0].pc.as_u64(), regs.pc, "frame 0's pc should match the live register state");
        assert_eq!(frames[0].sp.as_u64(), regs.sp, "frame 0's sp should match the live register state");

        let _ = dbg.kill().await;
    }

    /// `backtrace` at the initial system breakpoint should now return MORE
    /// than one frame — proves the CFI (`.pdata`/`UNWIND_INFO`) unwind step
    /// actually works end to end against real ntdll code. The initial
    /// breakpoint is hit deep inside ntdll's own startup call chain
    /// (`DbgBreakPoint` called by `LdrpDoDebuggerBreak` called by further
    /// loader routines), and ntdll's functions mostly do NOT preserve
    /// `rbp` as a frame pointer — `FramePointerUnwinder` alone reliably
    /// stops at frame 0 there (see `backtrace_returns_the_current_frame`,
    /// which deliberately only asserts `!frames.is_empty()` for exactly
    /// this reason). CFI unwinding doesn't depend on `rbp` at all, so it
    /// should succeed where the frame-pointer approach can't.
    #[tokio::test]
    async fn backtrace_unwinds_past_the_first_frame_via_cfi() {
        let dbg = WindowsDebugger::new();
        dbg.launch(cmd_launch_options(&["/C", "exit", "0"]))
            .await
            .expect("launch should succeed");

        let mut tid = None;
        for _ in 0..50 {
            let event = dbg.continue_execution().await.expect("continue_execution should not error");
            if matches!(event.reason, StopReason::Breakpoint { .. }) {
                tid = Some(event.tid);
                break;
            }
            if event.reason.is_exit() {
                break;
            }
        }
        let tid = tid.expect("expected the initial system breakpoint");

        let frames = dbg.backtrace(tid).await.expect("backtrace should succeed against a live process");
        assert!(
            frames.len() > 1,
            "expected CFI unwinding to find more than the current frame at ntdll's initial breakpoint, got {} frame(s): {frames:?}",
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
        // Every CFI-unwound frame (index 1 onward) should have its
        // `module` field populated with the module ACTUALLY covering that
        // frame's own pc, not left `None` or mislabeled with whichever
        // module the frame it was unwound FROM happened to be in.
        for frame in frames.iter().skip(1) {
            let name = frame.module.as_deref().expect("CFI-unwound frame should have module populated, not None");
            let expected = modules
                .iter()
                .find(|m| frame.pc.as_u64() >= m.base.as_u64() && frame.pc.as_u64() < m.base.as_u64() + m.size)
                .map(|m| m.name.as_str());
            assert_eq!(Some(name), expected, "frame module should match the module actually covering its pc");
        }

        let _ = dbg.kill().await;
    }

    /// With a symbol resolver attached, `backtrace` should fill each frame's
    /// `function_name`/`source_file`/`source_line` — proves the
    /// `symbol_resolver::enrich_frames` wiring runs against a live unwind.
    /// Uses a canned resolver (returns the same symbol for any PC) so the test
    /// doesn't depend on real PDB data for a dynamic address.
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
                    bounded: true,
                    start: None,
                })
            }
        }

        let dbg = WindowsDebugger::new();
        dbg.launch(cmd_launch_options(&["/C", "exit", "0"]))
            .await
            .expect("launch should succeed");
        dbg.set_symbol_resolver(std::sync::Arc::new(CannedResolver));

        let mut tid = None;
        for _ in 0..50 {
            let event = dbg.continue_execution().await.expect("continue_execution should not error");
            if matches!(event.reason, StopReason::Breakpoint { .. }) {
                tid = Some(event.tid);
                break;
            }
            if event.reason.is_exit() {
                break;
            }
        }
        let tid = tid.expect("expected the initial system breakpoint");

        let frames = dbg.backtrace(tid).await.expect("backtrace should succeed");
        assert!(!frames.is_empty());
        assert_eq!(frames[0].function_name.as_deref(), Some("live_fn"));
        assert_eq!(frames[0].source_file.as_deref(), Some("live.c"));
        assert_eq!(frames[0].source_line, Some(7));

        let _ = dbg.kill().await;
    }

    /// `step_over` at the initial breakpoint should make forward progress
    /// (pc changes, sp never below where it started) — proves the
    /// `instr_length`-based return-address computation and the plain
    /// (non-call) fast path both work against real ntdll code bytes.
    #[tokio::test]
    async fn step_over_advances_pc_at_a_live_breakpoint() {
        let dbg = WindowsDebugger::new();
        dbg.launch(cmd_launch_options(&["/C", "exit", "0"]))
            .await
            .expect("launch should succeed");

        let mut tid = None;
        for _ in 0..50 {
            let event = dbg.continue_execution().await.expect("continue_execution should not error");
            if matches!(event.reason, StopReason::Breakpoint { .. }) {
                tid = Some(event.tid);
                break;
            }
            if event.reason.is_exit() {
                break;
            }
        }
        let tid = tid.expect("expected the initial system breakpoint");

        let before = dbg.get_registers(tid).await.expect("get_registers should succeed");
        dbg.step_over(tid).await.expect("step_over should succeed against a live process");
        let after = dbg.get_registers(tid).await.expect("get_registers should succeed");

        assert_ne!(after.pc, before.pc, "step_over should have advanced the instruction pointer");
        assert!(after.sp >= before.sp, "step_over should never leave sp below where it started");

        let _ = dbg.kill().await;
    }

    /// `step_out` requires a live frame pointer to locate the return address
    /// — real x86-64 leaf/optimized code is not guaranteed to maintain one,
    /// so this test accepts either a successful step-out or the documented
    /// `DebugError::StepError` (no frame pointer available) as correct,
    /// while still proving the live `[rbp+8]` read path executes without
    /// corrupting the target when a frame pointer *is* present.
    #[tokio::test]
    async fn step_out_succeeds_or_reports_missing_frame_pointer() {
        let dbg = WindowsDebugger::new();
        dbg.launch(cmd_launch_options(&["/C", "exit", "0"]))
            .await
            .expect("launch should succeed");

        let mut tid = None;
        for _ in 0..50 {
            let event = dbg.continue_execution().await.expect("continue_execution should not error");
            if matches!(event.reason, StopReason::Breakpoint { .. }) {
                tid = Some(event.tid);
                break;
            }
            if event.reason.is_exit() {
                break;
            }
        }
        let tid = tid.expect("expected the initial system breakpoint");

        match dbg.step_out(tid).await {
            Ok(_) => {}
            Err(DebugError::StepError(msg)) => {
                assert!(msg.contains("frame pointer"), "unexpected step_out error: {msg}");
            }
            Err(e) => panic!("step_out failed with an unexpected error: {e:?}"),
        }

        let _ = dbg.kill().await;
    }

    /// `detach` should leave the debugger in a clean not-attached state and
    /// let the (now undebugged) child keep running — proves
    /// `DebugActiveProcessStop` succeeds against a live process.
    #[tokio::test]
    async fn detach_clears_attachment_state() {
        let dbg = WindowsDebugger::new();
        dbg.launch(cmd_launch_options(&["/C", "exit", "0"]))
            .await
            .expect("launch should succeed");
        assert!(dbg.is_attached());

        for _ in 0..5 {
            let event = dbg.continue_execution().await.expect("continue_execution should not error");
            if matches!(event.reason, StopReason::Breakpoint { .. }) || event.reason.is_exit() {
                break;
            }
        }

        dbg.detach().await.expect("detach should succeed against a live process");
        assert!(!dbg.is_attached(), "is_attached should be false after detach");
        assert_eq!(dbg.target_pid(), None, "target_pid should be None after detach");
    }

    /// `current_thread`/`threads` should reflect the thread that last caused
    /// a stop event, matching the `DebugEvent`'s own `tid`.
    #[tokio::test]
    async fn current_thread_and_threads_match_the_stopping_event() {
        let dbg = WindowsDebugger::new();
        dbg.launch(cmd_launch_options(&["/C", "exit", "0"]))
            .await
            .expect("launch should succeed");

        let mut event_tid = None;
        for _ in 0..50 {
            let event = dbg.continue_execution().await.expect("continue_execution should not error");
            if matches!(event.reason, StopReason::Breakpoint { .. }) {
                event_tid = Some(event.tid);
                break;
            }
            if event.reason.is_exit() {
                break;
            }
        }
        let event_tid = event_tid.expect("expected the initial system breakpoint");

        let current = dbg.current_thread().await.expect("current_thread should succeed once stopped");
        assert_eq!(current, event_tid, "current_thread should be the thread that last stopped");

        let threads = dbg.threads().await.expect("threads should succeed");
        assert!(threads.contains(&event_tid), "threads() should include the thread that last stopped");

        let _ = dbg.kill().await;
    }

    /// `threads()` must report every thread in the target, not just the one
    /// that last hit a debug event. The old implementation forwarded to
    /// `Command::Threads`, which only ever remembered `last_tid` from the
    /// debug-event loop — a genuinely second, never-stopped-at thread was
    /// invisible. Proven here by injecting a real second thread via
    /// `CreateRemoteThread` (which does not itself raise a debug event the
    /// loop thread would observe) and confirming `threads()` still finds it
    /// through direct toolhelp enumeration.
    #[tokio::test]
    async fn threads_enumerates_more_than_the_last_stopping_thread() {
        use winapi::um::processthreadsapi::CreateRemoteThread;
        use winapi::um::synchapi::Sleep;

        let dbg = WindowsDebugger::new();
        dbg.launch(cmd_launch_options(&["/C", "ping", "-n", "5", "127.0.0.1"]))
            .await
            .expect("launch should succeed");

        // Reach the initial system breakpoint so the process is fully up.
        let mut reached_initial_bp = false;
        for _ in 0..50 {
            let event = dbg.continue_execution().await.expect("continue_execution should not error");
            if matches!(event.reason, StopReason::Breakpoint { .. }) {
                reached_initial_bp = true;
                break;
            }
            if event.reason.is_exit() {
                break;
            }
        }
        assert!(reached_initial_bp, "expected the initial system breakpoint");

        let before = dbg.threads().await.expect("threads should succeed");

        let pid = dbg.target_pid().expect("should be attached").0;
        let handle = unsafe { OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid) };
        assert!(!handle.is_null(), "OpenProcess should succeed for a live child process");
        // Start routine: `Sleep(3000)` — the remote thread just needs to
        // stay alive long enough to be observed by toolhelp, it never needs
        // to run any meaningful code. `Sleep`'s single `DWORD` parameter and
        // `LPTHREAD_START_ROUTINE`'s single pointer-sized parameter share
        // the same calling-convention slot, so reusing `lpParameter` as the
        // millisecond count works despite the differing return type.
        let new_tid = unsafe {
            let mut tid: DWORD = 0;
            let thread_handle = CreateRemoteThread(
                handle,
                std::ptr::null_mut(),
                0,
                Some(std::mem::transmute::<usize, unsafe extern "system" fn(*mut winapi::ctypes::c_void) -> DWORD>(
                    Sleep as *const () as usize,
                )),
                3000 as *mut _,
                0,
                &mut tid,
            );
            assert!(!thread_handle.is_null(), "CreateRemoteThread should succeed");
            CloseHandle(thread_handle);
            CloseHandle(handle);
            tid
        };

        let after = dbg.threads().await.expect("threads should succeed");
        assert!(
            after.len() > before.len() || after.contains(&ThreadId(new_tid)),
            "threads() should observe the remotely-created thread (before={before:?}, after={after:?}, new_tid={new_tid})"
        );

        let _ = dbg.kill().await;
    }
}

#[cfg(test)]
mod stop_classification_tests {
    use super::*;

    /// A stop at an address we never planted is not OUR breakpoint.
    ///
    /// `classify_event` turns every `EXCEPTION_BREAKPOINT` into
    /// `StopReason::Breakpoint { bp: new_software(addr) }`, because it is a free
    /// function over the raw event and has no way to know. That is fine there —
    /// but nothing downstream corrected it, so three different things all
    /// arrived at the caller as "you hit a software breakpoint":
    ///
    ///   * `pause()`, which works by `DebugBreakProcess` injecting one;
    ///   * the initial process breakpoint Windows always delivers;
    ///   * a `__debugbreak()` in the target's own code.
    ///
    /// The user asked to pause and was told they had hit a breakpoint at an
    /// address they never set — a breakpoint that does not exist, described
    /// with a full `Breakpoint` record. Linux and macOS report their own pause
    /// as `StopReason::Signal`, which is honest.
    ///
    /// `enrich_event_breakpoint` is where this is fixable because it is the
    /// first place that HAS the planted-breakpoint table.
    #[test]
    fn a_stop_at_an_address_we_never_planted_is_not_reported_as_our_breakpoint() {
        let dbg = WindowsDebugger::new();
        let at = Address(0x7FF8_1234_5678);
        let mut ev = DebugEvent::new(
            ProcessId(1),
            ThreadId(1),
            StopReason::Breakpoint { address: at, bp: Breakpoint::new_software(at) },
        );
        dbg.enrich_event_breakpoint(&mut ev);
        let StopReason::Breakpoint { bp, .. } = &ev.reason else {
            panic!("the variant must stay Breakpoint — six live tests and the MCP initial-stop                     path wait for it, and Windows does deliver a breakpoint here");
        };
        assert!(
            bp.label.is_some(),
            "a breakpoint exception at an address absent from the planted table is described as              a breakpoint this debugger set, with nothing saying otherwise: {bp:?}"
        );
        assert!(!bp.enabled, "a breakpoint that was never planted cannot be enabled: {bp:?}");
    }

    /// ...and one we DID plant still is, so the fix is not simply refusing
    /// everything.
    #[test]
    fn a_stop_at_an_address_we_planted_is_still_our_breakpoint() {
        let dbg = WindowsDebugger::new();
        let at = Address(0x1000);
        dbg.breakpoints.lock().insert(at.as_u64(), vec![0x90]);
        let mut ev = DebugEvent::new(
            ProcessId(1),
            ThreadId(1),
            StopReason::Breakpoint { address: at, bp: Breakpoint::new_software(at) },
        );
        dbg.enrich_event_breakpoint(&mut ev);
        let StopReason::Breakpoint { bp, .. } = &ev.reason else {
            panic!("a breakpoint we planted must still be reported as one: {:?}", ev.reason)
        };
        assert!(bp.label.is_none(), "one of ours must not carry the not-ours label: {bp:?}");
    }
}
