//! Live-process coverage for the Linux backend's register and memory API.
//!
//! Every test here drives a REAL process (`/bin/sh`) under `ptrace`: launch,
//! stop at the post-`execve` `SIGTRAP`, then exercise
//! `get_registers`/`set_registers`/`get_register`/`set_register`,
//! `read_memory`/`write_memory` (including partial reads and read-back of
//! writes) and a live `memory_search` over the target's own address space.
//! Nothing here asserts on a structure built in memory — an in-memory
//! `RegisterSet` proves nothing about what `PTRACE_GETREGS` actually returned.
//!
//! ## What this file does NOT establish — see `live_linux_devac_regs_mem.rs`
//!
//! Measured by the falsification campaign (STATUS.md): 9 of these 14 bite on the
//! mutated ground truth. The five that do not are not the whole story, because
//! most of the nine bite on the crate's SELF-CONSISTENCY rather than on the
//! process. `write_memory_is_visible_to_a_subsequent_read_memory` compares this
//! backend's write with this backend's read; `..._returns_exactly_the_requested_
//! length_for_partial_sizes` compares a short read with a wider read of the same
//! address, an equality that holds for any content including zeroes; and
//! `set_register_then_get_register_round_trips_a_scratch_register` asks the
//! backend what it has just told the backend. None of the three names a value
//! that came from outside this crate.
//!
//! `live_linux_devac_regs_mem.rs` re-asserts each of those against a fixture
//! that PRINTS its own addresses and values before the breakpoint fires, and
//! closes the write direction through the program's own output. Those guards are
//! the ones to change when the behaviour changes; these remain as the cheap
//! smoke pass over `/bin/sh`.
#![cfg(target_os = "linux")]

use rustre_core::address::Address;
use rustre_debug::linux_debugger::LinuxDebugger;
use rustre_debug::memory_search::{MemorySearch, SearchOptions, SearchPattern, search_target};
use rustre_debug::{Debugger, LaunchOptions, OutputRedirect, ThreadId};

/// A launch of `/bin/sh` that stays alive long enough to be poked at.
fn sh(args: &[&str]) -> LaunchOptions {
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

/// Launch a live tracee and return the debugger plus the main thread id.
async fn live() -> (LinuxDebugger, ThreadId) {
    let dbg = LinuxDebugger::new();
    dbg.launch(sh(&["-c", "sleep 30"])).await.expect("launch should succeed");
    let tid = dbg.target_pid().map(|p| ThreadId(p.0)).expect("a live pid");
    (dbg, tid)
}

/// A freshly `execve`d process stopped by the debugger must expose a coherent
/// register file: a non-zero pc and sp, and the same values reachable both
/// through the typed fields and through the by-name map. Those are two views of
/// one hardware state; if they disagree, every consumer that picked the other
/// view is reading a different process than it thinks.
#[tokio::test]
async fn get_registers_returns_a_coherent_live_register_file() {
    let (dbg, tid) = live().await;
    let regs = dbg.get_registers(tid).await.expect("get_registers on a stopped tracee");

    assert_ne!(regs.pc, 0, "a freshly exec'd process must have a non-zero pc");
    assert_ne!(regs.sp, 0, "a freshly exec'd process must have a non-zero sp");
    assert_eq!(regs.get("rip"), Some(regs.pc), "map view of rip must equal the typed pc");
    assert_eq!(regs.get("rsp"), Some(regs.sp), "map view of rsp must equal the typed sp");

    let _ = dbg.kill().await;
}

/// `set_register` then `get_register` on a scratch register must return the
/// exact value written. This is the round trip the whole watchpoint/expression
/// stack rests on: a write that is accepted but never reaches the thread is
/// indistinguishable from success at the API boundary.
#[tokio::test]
async fn set_register_then_get_register_round_trips_a_scratch_register() {
    let (dbg, tid) = live().await;
    let magic: u64 = 0x0123_4567_89ab_cdef;

    dbg.set_register(tid, "r12", magic).await.expect("set_register(r12)");
    let back = dbg.get_register(tid, "r12").await.expect("get_register(r12)");
    assert_eq!(back, magic, "r12 must read back exactly what was written");

    // And the whole-set read must agree with the single-register read.
    let regs = dbg.get_registers(tid).await.expect("get_registers");
    assert_eq!(regs.get("r12"), Some(magic), "get_registers must see the same write");

    let _ = dbg.kill().await;
}

/// Writing a NARROW name must change only the bits that name covers. `ebx` is
/// the low half of `rbx`, so writing it must leave the high half intact —
/// treating `ebx` as a synonym for `rbx` silently destroys 32 bits of the
/// caller's state.
#[tokio::test]
async fn writing_a_narrow_register_name_preserves_the_rest_of_the_parent() {
    let (dbg, tid) = live().await;
    dbg.set_register(tid, "rbx", 0x1122_3344_5566_7788).await.expect("set rbx");
    dbg.set_register(tid, "ebx", 0xaabb_ccdd).await.expect("set ebx");

    let rbx = dbg.get_register(tid, "rbx").await.expect("get rbx");
    assert_eq!(rbx, 0x1122_3344_aabb_ccdd, "writing ebx must not clear the high half of rbx");
    let ebx = dbg.get_register(tid, "ebx").await.expect("get ebx");
    assert_eq!(ebx, 0xaabb_ccdd, "the narrow read must return only the low half");

    let _ = dbg.kill().await;
}

/// A register name this architecture does not have must be REFUSED by the
/// writer, not accepted and dropped. `x0` is AArch64; on x86-64 the reader
/// already answers "unknown register", and the two halves of the API must not
/// give opposite answers about the same name.
#[tokio::test]
async fn setting_an_unknown_register_name_is_an_error_not_a_silent_noop() {
    let (dbg, tid) = live().await;

    let write = dbg.set_register(tid, "x0", 0xdead).await;
    assert!(write.is_err(), "set_register on a nonexistent register must fail, got {write:?}");
    let read = dbg.get_register(tid, "x0").await;
    assert!(read.is_err(), "get_register on a nonexistent register must fail");

    let _ = dbg.kill().await;
}

/// `set_registers` writes a whole file back. Reading, mutating one entry and
/// writing must land on the live thread — the full-set path is what
/// `step_over`/`step_out` and every restore-after-breakpoint uses.
#[tokio::test]
async fn set_registers_writes_the_whole_file_back_to_the_live_thread() {
    let (dbg, tid) = live().await;
    let mut regs = dbg.get_registers(tid).await.expect("get_registers");
    let original_pc = regs.pc;

    regs.set("r13", 0x5a5a_5a5a_5a5a_5a5a);
    regs.set("r14", 0x0102_0304_0506_0708);
    dbg.set_registers(tid, regs).await.expect("set_registers");

    let back = dbg.get_registers(tid).await.expect("get_registers after write");
    assert_eq!(back.get("r13"), Some(0x5a5a_5a5a_5a5a_5a5a), "r13 must survive the full-set write");
    assert_eq!(back.get("r14"), Some(0x0102_0304_0506_0708), "r14 must survive the full-set write");
    assert_eq!(back.pc, original_pc, "an unrelated field must not be disturbed by the write");

    let _ = dbg.kill().await;
}

/// Partial reads: the length asked for is the length returned, for sizes that
/// are not multiples of the ptrace word. A backend that reads words and forgets
/// to trim returns 8 bytes for a 5-byte request, and every caller that slices
/// by the requested length then reads a byte it never asked for.
#[tokio::test]
async fn read_memory_returns_exactly_the_requested_length_for_partial_sizes() {
    let (dbg, tid) = live().await;
    let pc = dbg.get_registers(tid).await.expect("get_registers").pc;

    let full = dbg.read_memory(Address(pc), 64).await.expect("read 64 bytes at pc");
    assert_eq!(full.len(), 64, "a 64-byte read must return 64 bytes");

    for size in [1usize, 3, 5, 7, 8, 9, 15, 17] {
        let part = dbg
            .read_memory(Address(pc), size)
            .await
            .unwrap_or_else(|e| panic!("read of {size} bytes at pc failed: {e}"));
        assert_eq!(part.len(), size, "a {size}-byte read must return {size} bytes");
        assert_eq!(
            &part[..],
            &full[..size],
            "a partial read must be a prefix of the wider read of the same address"
        );
    }

    let _ = dbg.kill().await;
}

/// Reading unmapped memory must FAIL. Returning zeroes for a page that is not
/// there is the worst possible answer: the caller cannot tell "the target holds
/// zero" from "there is nothing here", and a disassembly of address 0 looks
/// like real code.
#[tokio::test]
async fn read_memory_at_an_unmapped_address_fails_instead_of_returning_zeroes() {
    let (dbg, _tid) = live().await;

    let r = dbg.read_memory(Address(0x10), 16).await;
    assert!(r.is_err(), "reading an unmapped address must error, got {:?}", r.map(|b| b.len()));

    let _ = dbg.kill().await;
}

/// Write-then-read-back on the live stack: the bytes the target holds after a
/// `write_memory` must be exactly the bytes handed in, and the reported count
/// must be the number actually written. This is the only check that separates
/// "the poke was issued" from "the process now holds these bytes".
#[tokio::test]
async fn write_memory_is_visible_to_a_subsequent_read_memory() {
    let (dbg, tid) = live().await;
    let sp = dbg.get_registers(tid).await.expect("get_registers").sp;
    // Below the stack pointer: mapped stack the stopped process is not using.
    let scratch = Address(sp - 512);
    let payload: Vec<u8> = (0u8..24).map(|b| b.wrapping_mul(7).wrapping_add(3)).collect();

    let written = dbg.write_memory(scratch, &payload).await.expect("write_memory to the stack");
    assert_eq!(written, payload.len(), "write_memory must report every byte it wrote");

    let back = dbg.read_memory(scratch, payload.len()).await.expect("read back");
    assert_eq!(back, payload, "the target must hold exactly the bytes written");

    // A second, shorter write at the same place must overwrite only its own span.
    dbg.write_memory(scratch, &[0xff, 0xfe]).await.expect("short write");
    let back2 = dbg.read_memory(scratch, payload.len()).await.expect("read back after short write");
    assert_eq!(&back2[..2], &[0xff, 0xfe], "the short write must land");
    assert_eq!(&back2[2..], &payload[2..], "the short write must not disturb bytes past its end");

    let _ = dbg.kill().await;
}

/// Writing to unmapped memory must fail rather than report success for bytes
/// that went nowhere — a caller that patches code at a bad address and is told
/// "ok" will believe its patch is live.
#[tokio::test]
async fn write_memory_at_an_unmapped_address_fails() {
    let (dbg, _tid) = live().await;

    let r = dbg.write_memory(Address(0x10), &[1, 2, 3, 4]).await;
    assert!(r.is_err(), "writing an unmapped address must error, got {r:?}");

    let _ = dbg.kill().await;
}

/// End-to-end memory search against the live target: plant a unique 24-byte
/// needle on the stack through `write_memory`, then let `search_target` walk
/// `memory_maps` and find it. The needle's address is known exactly, so this
/// checks the scan reports the RIGHT address, not merely "some hit" — and it
/// proves the search reads the live process rather than a cached image.
#[tokio::test]
async fn memory_search_finds_a_needle_just_written_into_the_live_target() {
    let (dbg, tid) = live().await;
    let sp = dbg.get_registers(tid).await.expect("get_registers").sp;
    let scratch = Address(sp - 1024);
    let needle: Vec<u8> = b"RUSTRE-LIVE-NEEDLE-24BYT".to_vec();
    assert_eq!(needle.len(), 24);

    dbg.write_memory(scratch, &needle).await.expect("plant the needle");
    let check = dbg.read_memory(scratch, needle.len()).await.expect("needle read-back");
    assert_eq!(check, needle, "the needle must be in the target before searching for it");

    let engine = MemorySearch::new(SearchOptions::default().with_max_results(64));
    let pattern = SearchPattern::bytes(needle.clone()).expect("pattern");
    let report = search_target(&engine, &dbg, &pattern).await.expect("search_target over the live target");

    assert!(
        report.results.iter().any(|r| r.address == scratch.0),
        "the scan must report the needle at {:#x}; got {} hits at {:?}, regions_searched={}, unreadable={}",
        scratch.0,
        report.results.len(),
        report.results.iter().map(|r| r.address).collect::<Vec<_>>(),
        report.regions_searched,
        report.regions_unreadable
    );
    assert!(report.bytes_scanned > 0, "a scan that found a match cannot have scanned zero bytes");

    let _ = dbg.kill().await;
}

/// `max_results` must actually stop the live scan: the report is capped and
/// flagged `truncated`. Without the flag, a caller cannot tell a capped scan
/// from an exhaustive one, and "only 2 matches exist" is the wrong conclusion.
#[tokio::test]
async fn memory_search_honours_max_results_and_flags_truncation() {
    let (dbg, tid) = live().await;
    let sp = dbg.get_registers(tid).await.expect("get_registers").sp;
    // Three copies of the same needle, 64 bytes apart.
    let needle = b"RUSTRE-TRUNC-NEEDLE".to_vec();
    for i in 0..3u64 {
        dbg.write_memory(Address(sp - 2048 + i * 64), &needle).await.expect("plant");
    }

    let engine = MemorySearch::new(SearchOptions::default().with_max_results(2));
    let pattern = SearchPattern::bytes(needle).expect("pattern");
    let report = search_target(&engine, &dbg, &pattern).await.expect("search_target");

    assert!(
        report.results.len() <= 2,
        "max_results=2 must cap the result list, got {}",
        report.results.len()
    );
    if report.results.len() == 2 {
        assert!(report.truncated, "a scan that hit its cap must say so");
    }

    let _ = dbg.kill().await;
}

/// A zero-length read is a degenerate but legal request: it must answer with an
/// empty buffer, not an error and not one word. Callers compute sizes
/// (`end - start`) and a zero is a normal outcome of that arithmetic; turning it
/// into a failure makes them treat an empty range as a broken target.
#[tokio::test]
async fn zero_length_read_and_write_are_degenerate_not_failures() {
    let (dbg, tid) = live().await;
    let sp = dbg.get_registers(tid).await.expect("get_registers").sp;

    let read = dbg.read_memory(Address(sp - 256), 0).await;
    assert!(read.is_ok(), "a zero-length read must succeed, got {read:?}");
    assert_eq!(read.unwrap().len(), 0, "a zero-length read must return zero bytes");

    let written = dbg.write_memory(Address(sp - 256), &[]).await;
    assert!(written.is_ok(), "a zero-length write must succeed, got {written:?}");
    assert_eq!(written.unwrap(), 0, "a zero-length write must report zero bytes written");

    let _ = dbg.kill().await;
}

/// A read that STARTS inside a mapped region and RUNS OFF its end into a hole
/// must not come back full-length: the tail bytes do not exist, and returning
/// them (as zeroes, or as stale words) hands the caller invented memory that is
/// indistinguishable from real content. Either an error or a short read is a
/// correct answer here; a full-length buffer is not.
#[tokio::test]
async fn a_read_running_off_the_end_of_a_mapping_does_not_return_invented_bytes() {
    let (dbg, _tid) = live().await;
    let maps = dbg.memory_maps().await.expect("memory_maps");

    // Find a readable region whose end is NOT the start of the next region:
    // the bytes just past it are a genuine hole.
    let mut boundary = None;
    for (i, m) in maps.iter().enumerate() {
        if !m.readable {
            continue;
        }
        let end = m.base.0 + m.size;
        let next_starts_here = maps.get(i + 1).is_some_and(|n| n.base.0 == end);
        if !next_starts_here {
            boundary = Some(end);
            break;
        }
    }
    let Some(end) = boundary else {
        eprintln!("[test] no isolated mapping boundary in this target; nothing to probe");
        let _ = dbg.kill().await;
        return;
    };

    // 8 bytes inside the mapping, 4096 past its end.
    let start = Address(end - 8);
    let want = 8 + 4096;
    match dbg.read_memory(start, want).await {
        Err(_) => {} // correct: refused rather than invented
        Ok(bytes) => assert!(
            bytes.len() < want,
            "read of {want} bytes starting {:#x} (mapping ends at {end:#x}) returned {} bytes — \
             the {} bytes past the mapping do not exist and must not be fabricated",
            start.0,
            bytes.len(),
            bytes.len() - 8
        ),
    }

    let _ = dbg.kill().await;
}

/// `write_memory` must reject an oversized write the same way, and must not
/// report more bytes written than the target could accept: a caller that trusts
/// the count will believe a patch landed in a page that does not exist.
#[tokio::test]
async fn a_write_running_off_the_end_of_a_mapping_does_not_over_report() {
    let (dbg, _tid) = live().await;
    let maps = dbg.memory_maps().await.expect("memory_maps");

    let mut boundary = None;
    for (i, m) in maps.iter().enumerate() {
        if !m.readable || !m.writable {
            continue;
        }
        let end = m.base.0 + m.size;
        let next_starts_here = maps.get(i + 1).is_some_and(|n| n.base.0 == end);
        if !next_starts_here {
            boundary = Some(end);
            break;
        }
    }
    let Some(end) = boundary else {
        eprintln!("[test] no isolated writable boundary in this target; nothing to probe");
        let _ = dbg.kill().await;
        return;
    };

    let data = vec![0x5au8; 8 + 4096];
    match dbg.write_memory(Address(end - 8), &data).await {
        Err(_) => {}
        Ok(n) => assert!(
            n < data.len(),
            "write of {} bytes ending {:#x} past the mapping end reported all {n} bytes written",
            data.len(),
            end
        ),
    }

    let _ = dbg.kill().await;
}
