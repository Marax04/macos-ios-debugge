//! Live-process edge cases of `read_memory` / `write_memory` on the Linux backend.
//!
//! Every test here drives a REAL process: a C fixture compiled on the fly with
//! `cc -no-pie -O0 -g`, launched under `ptrace` and stopped at the post-`execve`
//! `SIGTRAP`. Nothing is asserted against a structure built in this process's
//! own memory — that would prove nothing about what `/proc/<pid>/mem` returned.
//!
//! The one rule every test below checks, in a different shape each time:
//! **never invent a byte, and never report a partial success as a complete
//! one.** A read that cannot deliver `size` bytes must fail rather than hand
//! back a short or zero-padded buffer; a write that lands on N of M bytes must
//! not answer `Ok(M)`.
//!
//! The fixture calls `alarm(60)` before blocking, so a test that panics before
//! its `kill()` still cannot leave a process running for more than a minute.
//!
//! Method note on region selection: the tracee is stopped at the `execve` trap
//! and has not executed a single instruction of `main`, so no address printed
//! by the fixture is available yet. Every address used below is therefore taken
//! from the live `/proc/<pid>/maps` through `memory_maps()`, which is real data
//! about this very process.
#![cfg(target_os = "linux")]

use rustre_core::address::Address;
use rustre_debug::linux_debugger::LinuxDebugger;
use rustre_debug::{Debugger, LaunchOptions, MemoryMap, OutputRedirect};

/// The fixture: a process that maps a read-only page of its own, then blocks
/// forever (under a 60 s alarm, so a leaked one still dies on its own).
const FIXTURE_C: &str = r#"
#include <unistd.h>
#include <sys/mman.h>
static const volatile char ro_marker[4096] __attribute__((aligned(4096))) =
    "RUSTRE_MEMORY_LIMITS_FIXTURE";
int main(void) {
    char *p = mmap(0, 4096, PROT_READ, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    (void)p; (void)ro_marker[0];
    alarm(60);
    for (;;) pause();
    return 0;
}
"#;

/// Compile the fixture into `dir` and return its path.
fn build_fixture(dir: &std::path::Path) -> String {
    let src = dir.join("fixture.c");
    std::fs::write(&src, FIXTURE_C).expect("write fixture source");
    let exe = dir.join("fixture");
    let out = std::process::Command::new("cc")
        .args(["-no-pie", "-O0", "-g", "-o"])
        .arg(&exe)
        .arg(&src)
        .output()
        .expect("cc must be available for a live-process test");
    assert!(out.status.success(), "cc failed: {}", String::from_utf8_lossy(&out.stderr));
    exe.to_string_lossy().into_owned()
}

/// Launch the fixture under ptrace and return the debugger plus its live maps.
async fn live(dir: &std::path::Path) -> (LinuxDebugger, Vec<MemoryMap>) {
    let exe = build_fixture(dir);
    let dbg = LinuxDebugger::new();
    dbg.launch(LaunchOptions {
        executable: exe,
        args: Vec::new(),
        env: std::collections::HashMap::new(),
        working_dir: None,
        stop_at_entry: false,
        follow_forks: false,
        redirect: OutputRedirect::default(),
    })
    .await
    .expect("launch of the compiled fixture should succeed");
    let maps = dbg.memory_maps().await.expect("memory_maps on a live tracee");
    assert!(!maps.is_empty(), "a live process must have mapped regions");
    (dbg, maps)
}

fn end_of(m: &MemoryMap) -> u64 {
    m.base.as_u64() + m.size
}

/// The first readable region with room to spare.
fn readable(maps: &[MemoryMap]) -> &MemoryMap {
    maps.iter().find(|m| m.readable && m.size >= 64).expect("some readable region")
}

/// The first gap between two mappings, i.e. an address that is mapped by
/// nothing at all.
fn first_gap(maps: &[MemoryMap]) -> Option<u64> {
    let mut sorted: Vec<&MemoryMap> = maps.iter().collect();
    sorted.sort_by_key(|m| m.base.as_u64());
    sorted.windows(2).find_map(|w| {
        let (a, b) = (w[0], w[1]);
        (end_of(a) < b.base.as_u64()).then(|| end_of(a))
    })
}

/// A zero-length read must succeed and return zero bytes.
///
/// This is the degenerate case of the rule the whole file checks: the only
/// honest answer to "give me nothing" is an empty buffer. Returning an error
/// would make callers special-case an empty range, and returning any byte at
/// all would be a byte nobody asked for.
#[tokio::test]
async fn a_zero_length_read_returns_exactly_zero_bytes() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (dbg, maps) = live(dir.path()).await;
    let base = readable(&maps).base;

    let got = dbg.read_memory(base, 0).await.expect("a zero-length read is not an error");
    assert!(got.is_empty(), "a zero-length read must return no bytes, got {}", got.len());

    let _ = dbg.kill().await;
}

/// An unaligned address is not an error, and it must not be silently rounded.
///
/// `/proc/<pid>/mem` is byte-addressed, so `base+1` means `base+1`. A backend
/// that aligned the request down would return the byte at `base` as if it were
/// the byte at `base+1` — an invented value that looks perfectly plausible.
/// Proven by comparing against an aligned read of the same span.
#[tokio::test]
async fn an_unaligned_read_returns_the_bytes_at_that_exact_address() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (dbg, maps) = live(dir.path()).await;
    let base = readable(&maps).base;

    let aligned = dbg.read_memory(base, 16).await.expect("aligned read");
    let unaligned =
        dbg.read_memory(Address::new(base.as_u64() + 1), 15).await.expect("unaligned read");
    assert_eq!(
        unaligned,
        aligned[1..],
        "the read at base+1 must equal the tail of the read at base, not a shifted or rounded copy"
    );

    let _ = dbg.kill().await;
}

/// A read of an address that is mapped by nothing must FAIL.
///
/// The buffer the backend allocates is zero-filled before the `pread`, so the
/// failure mode this guards against is not hypothetical: swallowing the error
/// would hand the caller a page of zeros indistinguishable from a real page of
/// zeros.
#[tokio::test]
async fn a_read_of_an_unmapped_address_fails_instead_of_returning_zeros() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (dbg, maps) = live(dir.path()).await;
    let Some(gap) = first_gap(&maps) else {
        let _ = dbg.kill().await;
        return; // No hole in this process's address space; nothing to assert.
    };

    let got = dbg.read_memory(Address::new(gap), 8).await;
    assert!(got.is_err(), "reading unmapped {gap:#x} must fail, got {got:?}");

    let _ = dbg.kill().await;
}

/// A read that starts inside a mapping and runs past its end must fail as a
/// whole — it must not return the prefix that happened to be readable.
///
/// This is the "partial success reported as complete" case in its purest form:
/// the first bytes are genuinely there, the rest are not, and a `Vec` of the
/// requested length carrying only a valid prefix is a lie about its tail.
#[tokio::test]
async fn a_read_straddling_the_end_of_a_mapping_fails_rather_than_truncating() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (dbg, maps) = live(dir.path()).await;
    // A region whose end is followed by a hole, so reading past it cannot
    // wander into a neighbour that happens to be mapped.
    let mut sorted: Vec<&MemoryMap> = maps.iter().collect();
    sorted.sort_by_key(|m| m.base.as_u64());
    let straddler = sorted.windows(2).find_map(|w| {
        let (a, b) = (w[0], w[1]);
        (a.readable && a.size >= 16 && end_of(a) < b.base.as_u64()).then_some(a)
    });
    let Some(region) = straddler else {
        let _ = dbg.kill().await;
        return;
    };

    let start = end_of(region) - 8;
    let got = dbg.read_memory(Address::new(start), 4096).await;
    assert!(
        got.is_err(),
        "a read from {start:#x} running past the end of the mapping at {:#x} must fail, got {} bytes",
        end_of(region),
        got.map(|b| b.len()).unwrap_or(0)
    );

    let _ = dbg.kill().await;
}

/// A very large read must fail cleanly, not return a short buffer.
///
/// 64 MiB from the last page of a region cannot be satisfied by any process
/// here. The size is deliberately large-but-bounded: the backend allocates the
/// caller's size BEFORE looking at the address, so an absurd length would
/// abort the debugger on allocation rather than exercise the read path.
#[tokio::test]
async fn an_enormous_read_fails_and_returns_no_partial_buffer() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (dbg, maps) = live(dir.path()).await;
    let region = readable(&maps);
    let start = end_of(region) - 8;

    let got = dbg.read_memory(Address::new(start), 64 * 1024 * 1024).await;
    match got {
        Err(_) => {}
        Ok(bytes) => panic!(
            "a 64 MiB read from {start:#x} must fail; it returned {} bytes instead",
            bytes.len()
        ),
    }

    let _ = dbg.kill().await;
}

/// A read crossing the boundary between two adjacent regions with DIFFERENT
/// permissions must either deliver both halves truthfully or fail.
///
/// The failure this excludes: returning the readable first half padded out to
/// the requested length. The prefix is therefore compared byte for byte with a
/// read confined to the first region, which is the only part whose value is
/// independently known.
#[tokio::test]
async fn a_read_across_a_permission_boundary_is_whole_or_fails() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (dbg, maps) = live(dir.path()).await;
    let mut sorted: Vec<&MemoryMap> = maps.iter().collect();
    sorted.sort_by_key(|m| m.base.as_u64());
    let pair = sorted.windows(2).find_map(|w| {
        let (a, b) = (w[0], w[1]);
        let adjacent = end_of(a) == b.base.as_u64();
        let differ =
            (a.readable, a.writable, a.executable) != (b.readable, b.writable, b.executable);
        (adjacent && differ && a.readable && a.size >= 8 && b.size >= 8).then_some((a, b))
    });
    let Some((first, second)) = pair else {
        let _ = dbg.kill().await;
        return;
    };

    let boundary = end_of(first);
    let tail =
        dbg.read_memory(Address::new(boundary - 8), 8).await.expect("tail of the first region");
    let spanning = dbg.read_memory(Address::new(boundary - 8), 16).await;
    match spanning {
        Err(_) => {
            // Legitimate when the neighbour is not readable: refusing is the
            // honest answer, and it is what this test is protecting.
            assert!(
                !second.readable,
                "the span failed even though the neighbour at {:#x} is readable",
                second.base.as_u64()
            );
        }
        Ok(bytes) => {
            assert_eq!(
                bytes.len(),
                16,
                "a successful read must deliver exactly the requested length"
            );
            assert_eq!(
                &bytes[..8],
                &tail[..],
                "the first half must be the real bytes of the first region"
            );
            assert!(
                second.readable,
                "a span into the non-readable region at {:#x} must not succeed",
                second.base.as_u64()
            );
        }
    }

    let _ = dbg.kill().await;
}

/// A zero-length write must succeed, count zero, and touch nothing.
///
/// Proven by reading the destination before and after: a write of no bytes
/// that nonetheless perturbs memory is worse than an error.
#[tokio::test]
async fn a_zero_length_write_changes_nothing_and_counts_zero() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (dbg, maps) = live(dir.path()).await;
    let target = maps
        .iter()
        .find(|m| m.readable && m.writable && m.size >= 32)
        .map(|m| m.base)
        .expect("a writable region");

    let before = dbg.read_memory(target, 16).await.expect("read before");
    let n = dbg.write_memory(target, &[]).await.expect("a zero-length write is not an error");
    assert_eq!(n, 0, "a zero-length write must report zero bytes written");
    let after = dbg.read_memory(target, 16).await.expect("read after");
    assert_eq!(before, after, "a zero-length write must not modify any byte");

    let _ = dbg.kill().await;
}

/// A write to an address mapped by nothing must FAIL, and must not report a
/// byte count.
///
/// `Ok(n)` here would be the write-side twin of returning zeros for an
/// unmapped read: the caller believes the target's state changed when nothing
/// was touched.
#[tokio::test]
async fn a_write_to_an_unmapped_address_fails_instead_of_counting_bytes() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (dbg, maps) = live(dir.path()).await;
    let Some(gap) = first_gap(&maps) else {
        let _ = dbg.kill().await;
        return;
    };

    let got = dbg.write_memory(Address::new(gap), &[0xAA; 8]).await;
    assert!(got.is_err(), "writing to unmapped {gap:#x} must fail, got {got:?}");

    let _ = dbg.kill().await;
}

/// A write to a page the target itself may only READ must be honest about its
/// outcome.
///
/// Two answers are correct and this test accepts both, because the choice is a
/// policy one: refuse (the page is read-only), or perform it the way `gdb`
/// patches `.text` — the kernel lets a ptracer write through `/proc/<pid>/mem`
/// with `FOLL_FORCE`. What is NOT acceptable is the third answer: `Ok(len)`
/// with the bytes not actually there, which is a partial success reported as a
/// complete one. The read-back is what separates the two.
#[tokio::test]
async fn a_write_to_a_read_only_page_either_fails_or_really_lands() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (dbg, maps) = live(dir.path()).await;
    let ro = maps
        .iter()
        .find(|m| m.readable && !m.writable && m.size >= 32)
        .map(|m| m.base)
        .expect("a read-only region (the fixture's own text/rodata)");

    let original = dbg.read_memory(ro, 8).await.expect("read the read-only page");
    let payload: [u8; 8] = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];

    match dbg.write_memory(ro, &payload).await {
        Err(_) => {
            let after = dbg.read_memory(ro, 8).await.expect("read back after the refused write");
            assert_eq!(
                after,
                original,
                "a write reported as failed must not have modified the page at {:#x}",
                ro.as_u64()
            );
        }
        Ok(n) => {
            assert_eq!(
                n,
                payload.len(),
                "the reported count must be the full payload, not a prefix"
            );
            let after = dbg.read_memory(ro, 8).await.expect("read back after the accepted write");
            assert_eq!(
                after,
                payload,
                "the write reported {n} bytes written to the read-only page at {:#x}, but the page still reads differently",
                ro.as_u64()
            );
            // Put the page back, so nothing downstream inherits a patched image.
            let _ = dbg.write_memory(ro, &original).await;
        }
    }

    let _ = dbg.kill().await;
}
