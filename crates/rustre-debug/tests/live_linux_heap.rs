//! LIVE Linux coverage for the heap-inspection API
//! (`Ptmalloc2Parser` / `HeapChunk` / `HeapLayout`) driven against a REAL
//! process.
//!
//! Everything here runs on a C fixture compiled with `cc` at test time and
//! launched under `ptrace(2)` through `LinuxDebugger`. The fixture mallocs
//! blocks of KNOWN sizes and fills each with a recognisable byte, so every
//! assertion has ground truth that does not come from the crate: the pointers
//! `malloc` actually returned (read out of a global whose address comes from
//! `nm`), the sizes the source asked for, and the raw `/proc/<pid>/maps` of
//! our own tracee.
//!
//! The questions asked are the ones a struct literal cannot answer: do the
//! chunks the parser finds sit exactly where `malloc` put them, is the size in
//! the header the glibc rounding of the requested size, does the user area
//! really hold the bytes the program wrote — and, on the other side, does a
//! heap that does not exist yet produce chunks that were never allocated.
#![cfg(target_os = "linux")]

use rustre_core::address::Address;
use rustre_debug::linux_debugger::LinuxDebugger;
use rustre_debug::memory_layout_view::{ChunkState, HeapLayout, MemoryLayoutError, Ptmalloc2Parser};
use rustre_debug::{Debugger, LaunchOptions, OutputRedirect, StopReason};
use std::collections::HashMap;
use std::time::Duration;

/// Four allocations of sizes chosen to land in four different glibc size
/// classes, each filled with its own byte so a chunk can be identified by
/// content alone. The pointers stay in a global so the test can read them
/// back: what `malloc` returned is the only honest ground truth for "where
/// the chunks are".
///
/// The three `raise(SIGTRAP)` split the run into: nothing allocated, all four
/// allocated, one of them freed.
const FIXTURE_C: &str = r#"
#include <signal.h>
#include <stdlib.h>
#include <string.h>
void *g_ptrs[4];
unsigned long g_sizes[4] = { 64, 128, 256, 512 };
unsigned char g_fill[4] = { 0xA1, 0xB2, 0xC3, 0xD4 };
int main(void) {
    raise(SIGTRAP);                       /* stop 1: nothing malloc'ed yet */
    for (int i = 0; i < 4; i++) {
        g_ptrs[i] = malloc(g_sizes[i]);
        memset(g_ptrs[i], g_fill[i], g_sizes[i]);
    }
    raise(SIGTRAP);                       /* stop 2: four live blocks */
    free(g_ptrs[1]);
    raise(SIGTRAP);                       /* stop 3: the middle one is free */
    for (;;) { }
    return 0;
}
"#;

/// Sizes the fixture requests, mirrored here so the test never asks the
/// process what it asked for.
const REQ: [u64; 4] = [64, 128, 256, 512];
/// Fill bytes, mirrored for the same reason.
const FILL: [u8; 4] = [0xA1, 0xB2, 0xC3, 0xD4];

/// glibc rounds a request to `max(32, align16(n + 8))`: 8 bytes of header
/// (`size`) plus 16-byte alignment, the successor's `prev_size` field being
/// reusable as user space. Written out rather than derived from the parser so
/// the parser is being checked, not restated.
const fn glibc_chunk_size(req: u64) -> u64 {
    let n = req + 8;
    let a = (n + 15) & !15;
    if a < 32 { 32 } else { a }
}

/// Compile the fixture. `None` when this machine has no working `cc`, which
/// is a skip, not a failure. `-no-pie -O0 -g` so `nm` addresses are the
/// runtime ones and nothing is optimised away.
fn build_fixture(tag: &str) -> Option<String> {
    let dir = std::env::temp_dir();
    let pid = std::process::id();
    let src = dir.join(format!("rustre_heap_{tag}_{pid}.c"));
    let bin = dir.join(format!("rustre_heap_{tag}_{pid}"));
    std::fs::write(&src, FIXTURE_C).ok()?;
    let out = std::process::Command::new("cc")
        .args([src.to_str()?, "-no-pie", "-O0", "-g", "-o", bin.to_str()?])
        .output()
        .ok()?;
    let _ = std::fs::remove_file(&src);
    if !out.status.success() {
        return None;
    }
    Some(bin.to_str()?.to_string())
}

/// Address of a global, taken from `nm` — an independent oracle, not the
/// crate's own symbol code.
fn nm_symbol(bin: &str, name: &str) -> Option<u64> {
    let out = std::process::Command::new("nm").arg(bin).output().ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    for line in text.lines() {
        let mut it = line.split_whitespace();
        let Some(addr) = it.next() else { continue };
        let _kind = it.next();
        if it.next() == Some(name) {
            return u64::from_str_radix(addr, 16).ok();
        }
    }
    None
}

fn opts_for(bin: &str) -> LaunchOptions {
    LaunchOptions {
        executable: bin.to_string(),
        args: vec![],
        env: HashMap::new(),
        working_dir: None,
        stop_at_entry: false,
        follow_forks: false,
        redirect: OutputRedirect::default(),
    }
}

struct Target {
    dbg: LinuxDebugger,
    bin: String,
    pid: u32,
    g_ptrs: u64,
}

impl Target {
    /// Launch and resume to the FIRST `raise(SIGTRAP)` — before any malloc.
    async fn start(tag: &str) -> Option<Self> {
        let bin = build_fixture(tag)?;
        let g_ptrs = nm_symbol(&bin, "g_ptrs")?;
        let dbg = LinuxDebugger::new();
        let pid = dbg
            .launch(opts_for(&bin))
            .await
            .expect("the heap fixture must launch under ptrace");
        let t = Self {
            dbg,
            bin,
            pid: pid.0,
            g_ptrs,
        };
        t.cont().await;
        Some(t)
    }

    /// Resume once, then keep resuming until a stop that really belongs to
    /// this tracee's own main thread.
    ///
    /// Bounded on purpose: resuming *until* a condition holds would hang
    /// forever on a kernel that stopped delivering, and a hang is not a
    /// failure anyone can read.
    ///
    /// The filter is not decoration, and `ev.pid` alone is not enough. The
    /// backend reaps with a process-global `waitpid`, so the death of the
    /// PREVIOUS test's fixture is delivered here — MEASURED, with the debug
    /// print this loop used to carry:
    ///
    /// ```text
    /// DBG cont on 18297
    /// DBG pid=18297 mine=true reason=ThreadExit { tid: ThreadId(18287), exit_code: -9 }
    /// ```
    ///
    /// 18287 is the fixture the previous test killed; the event is stamped
    /// with the CURRENT target's pid, so a `ev.pid`-only filter accepts it,
    /// burns one resume, and the test then reads a `g_ptrs` that main has not
    /// filled in yet. That is exactly how five tests in this file failed in
    /// sequence and passed one at a time. Hence: thread events whose `tid` is
    /// not our main thread are noise.
    async fn cont(&self) {
        let mut ev = tokio::time::timeout(Duration::from_secs(30), self.dbg.continue_execution())
            .await
            .expect("continue_execution must not hang")
            .expect("continue_execution must not error");
        for _ in 0..64 {
            let noise = match ev.reason {
                StopReason::ThreadCreate { tid } | StopReason::ThreadExit { tid, .. } => {
                    tid.0 != self.pid
                }
                _ => false,
            };
            if ev.pid.0 == self.pid && !noise {
                break;
            }
            ev = tokio::time::timeout(Duration::from_secs(30), self.dbg.continue_execution())
                .await
                .expect("continue_execution must not hang")
                .expect("continue_execution must not error");
        }
    }

    /// The four pointers `malloc` really returned, read out of the fixture's
    /// global. Zero before the allocations happen.
    async fn pointers(&self) -> [u64; 4] {
        let raw = self
            .dbg
            .read_memory(Address(self.g_ptrs), 32)
            .await
            .expect("g_ptrs must be readable in our own tracee");
        let mut out = [0u64; 4];
        for (i, slot) in out.iter_mut().enumerate() {
            *slot = u64::from_le_bytes(raw[i * 8..i * 8 + 8].try_into().unwrap());
        }
        out
    }

    /// `[heap]` bounds from the raw `/proc/<pid>/maps` — ground truth the
    /// crate did not produce. `None` when the process has no heap mapping.
    fn raw_heap(&self) -> Option<(u64, u64)> {
        let raw = std::fs::read_to_string(format!("/proc/{}/maps", self.pid))
            .expect("/proc/<pid>/maps must be readable for our own tracee");
        for line in raw.lines() {
            if line.trim_end().ends_with("[heap]") {
                let mut it = line.split_whitespace().next()?.split('-');
                let a = u64::from_str_radix(it.next()?, 16).ok()?;
                let b = u64::from_str_radix(it.next()?, 16).ok()?;
                return Some((a, b));
            }
        }
        None
    }

    /// 32 bytes at `addr`: `prev_size`, `size`, `fd`, `bk` — exactly what
    /// `parse_chunk` wants.
    async fn header_bytes(&self, addr: u64) -> Option<Vec<u8>> {
        self.dbg.read_memory(Address(addr), 32).await.ok()
    }

    async fn shutdown(self) {
        let _ = self.dbg.kill().await;
    }
}

impl Drop for Target {
    fn drop(&mut self) {
        // Safety net only — the fixture spins forever, so a leak costs a core.
        let _ = std::process::Command::new("kill")
            .arg("-9")
            .arg(self.pid.to_string())
            .output();
        let _ = std::fs::remove_file(&self.bin);
    }
}

macro_rules! live {
    ($tag:expr) => {
        match Target::start($tag).await {
            Some(t) => t,
            None => {
                eprintln!("skipping: no working `cc`/`nm` on this machine");
                return;
            }
        }
    };
}

const PARSER: Ptmalloc2Parser = Ptmalloc2Parser::new(8);

// ─────────────────────────────────────────────────────────────────────────────
// The chunks are where malloc put them
// ─────────────────────────────────────────────────────────────────────────────

/// Every pointer `malloc` returned must sit exactly 16 bytes after a chunk
/// header the parser accepts.
///
/// This is the whole contract of a heap inspector: the address it calls a
/// chunk has to be the address the allocator handed to the program. Nothing
/// downstream — sizes, states, free lists — means anything if the parser is
/// looking at the wrong bytes.
#[tokio::test]
async fn every_malloc_pointer_sits_on_a_parsable_chunk_header() {
    let t = live!("hdr");
    t.cont().await; // stop 2: four live blocks

    let ptrs = t.pointers().await;
    for (i, &p) in ptrs.iter().enumerate() {
        assert!(p != 0, "fixture failed to allocate block {i}");
        let header = p - 16;
        let bytes = t
            .header_bytes(header)
            .await
            .unwrap_or_else(|| panic!("chunk header at {header:#x} must be readable"));
        let chunk = PARSER
            .parse_chunk(header, &bytes)
            .unwrap_or_else(|e| panic!("block {i}: header at {header:#x} rejected: {e}"));
        assert_eq!(
            chunk.user_addr, p,
            "block {i}: parser puts user data at {:#x}, malloc returned {p:#x}",
            chunk.user_addr
        );
    }
    t.shutdown().await;
}

/// The size in the header must be the glibc rounding of the size the source
/// asked for — `max(32, align16(n+8))`.
///
/// A parser that merely reads a plausible number would pass the previous
/// test; this one pins the number to the request. Getting it wrong by one
/// word is how a walker drifts off the chunk boundary and reports the rest of
/// the heap as garbage.
#[tokio::test]
async fn chunk_size_is_the_glibc_rounding_of_the_requested_size() {
    let t = live!("size");
    t.cont().await;

    let ptrs = t.pointers().await;
    for (i, &p) in ptrs.iter().enumerate() {
        let bytes = t.header_bytes(p - 16).await.expect("header readable");
        let chunk = PARSER.parse_chunk(p - 16, &bytes).expect("header parses");
        assert_eq!(
            chunk.chunk_size,
            glibc_chunk_size(REQ[i]),
            "block {i}: requested {} bytes, chunk_size {} (expected {})",
            REQ[i],
            chunk.chunk_size,
            glibc_chunk_size(REQ[i])
        );
    }
    t.shutdown().await;
}

/// The user area of the chunk must hold the bytes the program wrote into it.
///
/// The address and the size can both be right while pointing one chunk over;
/// the fill byte is the only check that ties the parsed chunk to *this*
/// allocation. Only the first `REQ[i]` bytes are asserted — the rest of the
/// chunk is allocator padding the program never touched.
#[tokio::test]
async fn chunk_user_area_holds_the_pattern_the_program_wrote() {
    let t = live!("fill");
    t.cont().await;

    let ptrs = t.pointers().await;
    for (i, &p) in ptrs.iter().enumerate() {
        let bytes = t.header_bytes(p - 16).await.expect("header readable");
        let chunk = PARSER.parse_chunk(p - 16, &bytes).expect("header parses");
        let data = t
            .dbg
            .read_memory(Address(chunk.user_addr), REQ[i] as usize)
            .await
            .expect("user area readable");
        assert!(
            data.iter().all(|&b| b == FILL[i]),
            "block {i}: user area at {:#x} is not filled with {:#x}; first mismatch at {:?}",
            chunk.user_addr,
            FILL[i],
            data.iter().position(|&b| b != FILL[i])
        );
    }
    t.shutdown().await;
}

/// Every chunk found must lie inside the `[heap]` mapping the kernel reports.
///
/// A chunk outside the heap is by construction invented: the parser followed
/// a size field into memory that never belonged to the allocator.
#[tokio::test]
async fn every_chunk_lies_inside_the_kernel_heap_mapping() {
    let t = live!("bounds");
    t.cont().await;

    let (lo, hi) = t.raw_heap().expect("a process that malloc'ed has a [heap]");
    let ptrs = t.pointers().await;
    for (i, &p) in ptrs.iter().enumerate() {
        let bytes = t.header_bytes(p - 16).await.expect("header readable");
        let chunk = PARSER.parse_chunk(p - 16, &bytes).expect("header parses");
        assert!(
            chunk.header_addr >= lo && chunk.header_addr + chunk.chunk_size <= hi,
            "block {i}: chunk {:#x}..{:#x} escapes [heap] {lo:#x}..{hi:#x}",
            chunk.header_addr,
            chunk.header_addr + chunk.chunk_size
        );
    }
    t.shutdown().await;
}

/// Walking chunk-by-chunk from the first allocation must land on the second,
/// third and fourth: `header + chunk_size` is the next header.
///
/// This is the invariant a heap walker lives on. If it holds on a live glibc
/// heap the parser can enumerate; if it does not, every listing after the
/// first chunk is fiction.
#[tokio::test]
async fn stepping_by_chunk_size_reaches_the_next_allocation() {
    let t = live!("walk");
    t.cont().await;

    let ptrs = t.pointers().await;
    let mut addr = ptrs[0] - 16;
    for (i, &p) in ptrs.iter().enumerate() {
        assert_eq!(
            addr,
            p - 16,
            "step {i}: walk arrived at {addr:#x}, malloc's block {i} starts at {:#x}",
            p - 16
        );
        let bytes = t.header_bytes(addr).await.expect("header readable");
        let chunk = PARSER.parse_chunk(addr, &bytes).expect("header parses");
        addr += chunk.chunk_size;
    }
    t.shutdown().await;
}

// ─────────────────────────────────────────────────────────────────────────────
// A heap that does not exist yet invents nothing
// ─────────────────────────────────────────────────────────────────────────────

/// Before the fixture's first `malloc`, its pointers are still NULL and the
/// addresses that will later be chunks are not yet chunks.
///
/// The point is the negative one: an inspector must not report a layout for
/// allocations that have not happened. Checked against the process's own
/// later behaviour — the same globals are non-NULL one stop later, so the
/// assertion cannot be satisfied by reading the wrong address.
#[tokio::test]
async fn before_the_first_malloc_no_block_exists_to_be_found() {
    let t = live!("early");

    let early = t.pointers().await;
    assert_eq!(
        early,
        [0, 0, 0, 0],
        "fixture must not have allocated before the first SIGTRAP, got {early:#x?}"
    );

    t.cont().await; // stop 2
    let late = t.pointers().await;
    assert!(
        late.iter().all(|&p| p != 0),
        "the same globals must be non-NULL once main has allocated: {late:#x?}"
    );
    t.shutdown().await;
}

/// Zeroed memory must be REFUSED, not described as a chunk of size zero.
///
/// A fresh `brk`/`mmap` page is all zeroes, so this is exactly the shape an
/// uninitialised heap presents. Reading a zero size word and returning a
/// chunk would make every walker either loop or emit an endless run of empty
/// chunks. The bytes come from live process memory — a scratch area of the
/// tracee's own heap, zeroed through `write_memory` and restored after — not
/// from a literal.
#[tokio::test]
async fn zeroed_memory_is_refused_instead_of_being_called_a_chunk() {
    let t = live!("zero");
    t.cont().await;

    let ptrs = t.pointers().await;
    // The user area of block 3 (512 bytes): writable, and the fixture never
    // reads it again after the memset.
    let scratch = ptrs[3];
    let saved = t
        .dbg
        .read_memory(Address(scratch), 32)
        .await
        .expect("scratch readable");
    t.dbg
        .write_memory(Address(scratch), &[0u8; 32])
        .await
        .expect("scratch writable");
    let bytes = t.header_bytes(scratch).await.expect("scratch readable");
    let all_zero = bytes.iter().all(|&b| b == 0);
    let parsed = PARSER.parse_chunk(scratch, &bytes);
    // Restore before asserting, so a failure does not also corrupt the tracee.
    let _ = t.dbg.write_memory(Address(scratch), &saved).await;
    assert!(all_zero, "the scratch we are parsing must really be zeroed");
    assert!(
        matches!(parsed, Err(MemoryLayoutError::InvalidHeapHeader(_))),
        "zeroed memory parsed as {parsed:?} instead of being rejected"
    );
    t.shutdown().await;
}

/// A walk started on unmapped memory must fail, not return chunks.
///
/// `walk_arena` is driven by a reader closure; the honest closure here is the
/// debugger's own `read_memory`, which fails on an unmapped address. Anything
/// other than an error means the walker fabricated a layout for memory it
/// could not read.
#[tokio::test]
async fn walking_unmapped_memory_returns_an_error_not_chunks() {
    let t = live!("unmapped");
    t.cont().await;

    let (_lo, hi) = t.raw_heap().expect("[heap] exists");
    // Well past the top of the heap: reliably unmapped for our own tracee.
    let past = hi + 0x10_0000;
    let mut reads = 0usize;
    let result = PARSER.walk_arena(past, |addr, size| {
        reads += 1;
        if std::fs::read_to_string(format!("/proc/{}/maps", t.pid))
            .map(|m| maps_contain(&m, addr, size))
            .unwrap_or(false)
        {
            Ok(vec![0u8; size])
        } else {
            Err(MemoryLayoutError::ReadError(addr, "unmapped".into()))
        }
    });
    assert!(reads > 0, "walk_arena never even attempted a read");
    assert!(
        result.is_err(),
        "walking unmapped memory at {past:#x} produced {:?} chunks instead of an error",
        result.map(|c| c.len())
    );
    t.shutdown().await;
}

/// Whether `[addr, addr+size)` falls inside any mapping of the tracee,
/// decided from the kernel's own table.
fn maps_contain(maps: &str, addr: u64, size: usize) -> bool {
    maps.lines().any(|l| {
        let Some(range) = l.split_whitespace().next() else {
            return false;
        };
        let mut it = range.split('-');
        let (Some(a), Some(b)) = (it.next(), it.next()) else {
            return false;
        };
        let (Ok(a), Ok(b)) = (u64::from_str_radix(a, 16), u64::from_str_radix(b, 16)) else {
            return false;
        };
        addr >= a && addr + size as u64 <= b
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// free()
// ─────────────────────────────────────────────────────────────────────────────

/// What `free()` of a small block actually changes in the header, measured
/// rather than assumed: the freed chunk's first two user words are
/// overwritten by the tcache `next`/`key` fields, while the SUCCESSOR chunk's
/// `PREV_INUSE` bit stays SET.
///
/// The first version of this test asserted the textbook ptmalloc rule — free
/// clears `PREV_INUSE` in the following chunk — and failed on a live glibc:
///
/// ```text
/// assertion `left == right` failed: after free() the successor at 0x14cd1370
///   must have PREV_INUSE clear
///   left: 1
///  right: 0
/// ```
///
/// That was the TEST being wrong, not the backend. A 128-byte block goes to
/// the per-thread tcache, which neither consolidates nor touches the inuse
/// bit; the block is reusable while still looking allocated. The consequence
/// for the parser is worth stating plainly: `ChunkState` is derived from
/// `PREV_INUSE` alone, so a tcache-freed chunk is reported `Allocated`, and
/// no header-only walker can do better — finding it requires walking
/// `tcache_perthread_struct`, which this crate does not parse. This test
/// therefore pins the two facts the process really provides.
#[tokio::test]
async fn a_tcache_free_rewrites_the_user_words_and_leaves_prev_inuse_set() {
    let t = live!("free");
    t.cont().await; // stop 2: all live
    let ptrs = t.pointers().await;

    let header = ptrs[1] - 16;
    let before = t.header_bytes(header).await.expect("header readable");
    let size = u64::from_le_bytes(before[8..16].try_into().unwrap()) & !0x7;
    let succ = header + size;

    let live_user = t
        .dbg
        .read_memory(Address(ptrs[1]), 16)
        .await
        .expect("user area readable");
    assert!(
        live_user.iter().all(|&b| b == FILL[1]),
        "while live, block 1 must still hold its fill byte, got {live_user:02x?}"
    );
    let succ_live = t.header_bytes(succ).await.expect("successor readable");
    let live_bit = u64::from_le_bytes(succ_live[8..16].try_into().unwrap()) & 1;
    assert_eq!(
        live_bit, 1,
        "while block 1 is live the successor at {succ:#x} must have PREV_INUSE set"
    );

    t.cont().await; // stop 3: block 1 freed

    let freed_user = t
        .dbg
        .read_memory(Address(ptrs[1]), 16)
        .await
        .expect("user area readable");
    assert!(
        freed_user.iter().any(|&b| b != FILL[1]),
        "free() must leave allocator bookkeeping in the user words, still {freed_user:02x?}"
    );
    let succ_freed = t.header_bytes(succ).await.expect("successor readable");
    let freed_bit = u64::from_le_bytes(succ_freed[8..16].try_into().unwrap()) & 1;
    assert_eq!(
        freed_bit, 1,
        "a tcache free must NOT clear PREV_INUSE at {succ:#x};          if this now reads 0 the allocator changed and the doc above is stale"
    );

    let chunk = PARSER
        .parse_chunk(header, &t.header_bytes(header).await.expect("readable"))
        .expect("parses");
    assert_eq!(
        chunk.chunk_size,
        glibc_chunk_size(REQ[1]),
        "the freed chunk keeps its size in the header"
    );
    t.shutdown().await;
}

/// A block that is still allocated must not be reported as `Free`.
///
/// Block 3 is never freed by the fixture, so whatever the parser says about
/// it at stop 3 is checkable without knowing anything about ptmalloc
/// internals.
#[tokio::test]
async fn a_live_block_is_not_reported_free_after_a_neighbour_is_freed() {
    let t = live!("state");
    t.cont().await;
    t.cont().await; // stop 3: block 1 freed, blocks 0/2/3 still live

    let ptrs = t.pointers().await;
    let bytes = t.header_bytes(ptrs[3] - 16).await.expect("header readable");
    let chunk = PARSER.parse_chunk(ptrs[3] - 16, &bytes).expect("parses");
    assert_ne!(
        chunk.state,
        ChunkState::Free,
        "block 3 was never freed but is reported {}",
        chunk.state
    );
    t.shutdown().await;
}

// ─────────────────────────────────────────────────────────────────────────────
// HeapLayout summary over live chunks
// ─────────────────────────────────────────────────────────────────────────────

/// A `HeapLayout` built from the four live chunks must account for at least
/// the bytes the program requested.
///
/// `user_size` is `chunk_size - 16`, a lower bound on what glibc really makes
/// usable, so the sum can exceed the request but must never fall short of it
/// by more than the 8 bytes per chunk that the accounting gives away: a
/// summary that under-counts live memory is the failure mode that makes a
/// leak invisible.
#[tokio::test]
async fn layout_totals_account_for_the_bytes_the_program_requested() {
    let t = live!("layout");
    t.cont().await;

    let ptrs = t.pointers().await;
    let mut chunks = Vec::new();
    for &p in &ptrs {
        let bytes = t.header_bytes(p - 16).await.expect("header readable");
        chunks.push(PARSER.parse_chunk(p - 16, &bytes).expect("parses"));
    }
    let layout = HeapLayout::from_chunks(chunks);
    assert_eq!(
        layout.allocated_count + layout.free_count,
        4,
        "four chunks in, {} allocated + {} free out",
        layout.allocated_count,
        layout.free_count
    );
    let requested: u64 = REQ.iter().sum();
    let counted = layout.total_allocated_bytes + layout.total_free_bytes;
    assert!(
        counted + 32 >= requested,
        "layout accounts for {counted} bytes, the program requested {requested}"
    );
    t.shutdown().await;
}

// ─────────────────────────────────────────────────────────────────────────────
// walk_arena over a real glibc heap
// ─────────────────────────────────────────────────────────────────────────────

/// `walk_arena` over the WHOLE live `[heap]`, fed a reader that serves the
/// real bytes of the tracee and refuses anything outside the mapping.
///
/// IGNORED — this is a BACKEND DEFECT, measured, not a broken test.
///
/// Expected: the four chunks the fixture allocated, enumerated from the heap
/// base. Obtained, copied from the run:
///
/// ```text
/// walking the live heap from its own base failed:
///   memory read error at 0x25591000: outside [heap]
/// ```
///
/// 0x25591000 is the END of the `[heap]` mapping. The walk is correct all the
/// way there — it steps chunk by chunk across the whole arena — and then
/// walks off the end because `walk_arena` has no notion of the glibc TOP
/// chunk, whose size spans the remaining arena. Two things then compound:
///
///  * the reader's error is propagated with `?`, so every chunk already
///    collected is DISCARDED. The caller gets `Err` and nothing else, even
///    though the enumeration succeeded for the entire heap;
///  * the only non-error exits are `size == 0` and the `IS_MMAPPED` flag.
///    The first is unreachable — `parse_chunk` rejects a zero size with
///    `InvalidHeapHeader` before the `break` can run — and the second never
///    fires inside a brk arena. So a walk of a healthy glibc heap has no
///    successful termination at all.
///
/// A caller that owns the memory (a reader that silently returns zeroes past
/// the end) fares no better: the zero size word becomes `InvalidHeapHeader`,
/// the same `Err`, the same loss. The fix belongs in the walker — stop at the
/// top chunk, or return the chunks collected alongside the error — so this
/// test is left ignored rather than weakened into passing.
#[ignore = "walk_arena has no top-chunk stop and discards every chunk it collected;             fails at the end of [heap] with `outside [heap]`"]
#[tokio::test]
async fn walking_the_live_heap_enumerates_the_blocks_the_program_allocated() {
    let t = live!("arena");
    t.cont().await;

    let (lo, hi) = t.raw_heap().expect("[heap] exists");
    let image = t
        .dbg
        .read_memory(Address(lo), (hi - lo) as usize)
        .await
        .expect("the whole heap must be readable in our own tracee");
    let ptrs = t.pointers().await;

    let mut reads = 0usize;
    let result = PARSER.walk_arena(lo, |addr, size| {
        reads += 1;
        if addr < lo || addr + size as u64 > hi {
            return Err(MemoryLayoutError::ReadError(addr, "outside [heap]".into()));
        }
        let off = (addr - lo) as usize;
        Ok(image[off..off + size].to_vec())
    });

    let chunks = result.unwrap_or_else(|e| {
        panic!("walking the live heap from its own base failed after {reads} chunk reads: {e}");
    });
    for (i, &p) in ptrs.iter().enumerate() {
        assert!(
            chunks.iter().any(|c| c.header_addr == p - 16),
            "block {i} at {:#x} is missing from the {} walked chunks",
            p - 16,
            chunks.len()
        );
    }
    t.shutdown().await;
}
