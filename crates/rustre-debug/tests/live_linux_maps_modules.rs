//! LIVE Linux coverage for `memory_maps()` / `modules()` as a *view of a moving
//! process*, not as a one-shot snapshot.
//!
//! Everything here drives a REAL process: a C fixture is compiled with `cc`
//! into a temp dir together with a small shared object, launched under
//! `ptrace(2)` through `LinuxDebugger`, stopped at a first `raise(SIGTRAP)`
//! BEFORE it `dlopen`s the library and again AFTER, so the two views can be
//! differenced. The questions asked are the ones a struct literal cannot
//! answer: does the map change when the target loads code at runtime, do the
//! r/w/x bits agree with the kernel region by region, are `[stack]` and
//! `[heap]` recognised, and is a region with no backing file ever promoted to
//! a module under an invented name.
#![cfg(target_os = "linux")]

use rustre_debug::linux_debugger::LinuxDebugger;
use rustre_debug::{Debugger, LaunchOptions, OutputRedirect, StopReason};
use std::collections::HashMap;
use std::time::Duration;

/// `raise(SIGTRAP)` twice around a `dlopen`, so the debugger sees the same
/// process before and after it gains a library. The heap allocation exists so
/// `[heap]` is really present: a process that never calls `malloc` legitimately
/// has no heap mapping, and asserting on one would be testing the fixture.
const FIXTURE_C: &str = r#"
#include <dlfcn.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
int main(int argc, char **argv) {
    volatile char *p = (char *)malloc(4096);
    p[0] = 1; p[4095] = 2;
    raise(SIGTRAP);                 /* stop 1: before the library exists */
    void *h = dlopen(argv[1], RTLD_NOW);
    if (!h) { fprintf(stderr, "dlopen failed\n"); }
    raise(SIGTRAP);                 /* stop 2: the library is mapped */
    for (;;) { }
    (void)argc; (void)h;
    return 0;
}
"#;

/// A writable global so the object gets an `rw-` region of its own, not only
/// the `r-x` text: the permission assertions below would be vacuous otherwise.
const LIB_C: &str = r#"
int rustre_live_counter = 7;
int rustre_live_bump(int n) { rustre_live_counter += n; return rustre_live_counter; }
"#;

/// Compile fixture + shared object. `None` when this machine has no working
/// `cc`, which is a skip, not a failure.
///
/// `-no-pie` so the executable's addresses are the ones `nm` would print;
/// `-O0 -g` so nothing the fixture does is optimised away.
fn build_fixture(tag: &str) -> Option<(String, String)> {
    let dir = std::env::temp_dir();
    let pid = std::process::id();
    let src = dir.join(format!("rustre_mm_{tag}_{pid}.c"));
    let lsrc = dir.join(format!("rustre_mmlib_{tag}_{pid}.c"));
    let bin = dir.join(format!("rustre_mm_{tag}_{pid}"));
    let lib = dir.join(format!("librustre_mm_{tag}_{pid}.so"));
    std::fs::write(&src, FIXTURE_C).ok()?;
    std::fs::write(&lsrc, LIB_C).ok()?;

    let lout = std::process::Command::new("cc")
        .args([
            lsrc.to_str()?,
            "-shared",
            "-fPIC",
            "-O0",
            "-g",
            "-o",
            lib.to_str()?,
        ])
        .output()
        .ok()?;
    let out = std::process::Command::new("cc")
        .args([
            src.to_str()?,
            "-no-pie",
            "-O0",
            "-g",
            "-o",
            bin.to_str()?,
            "-ldl",
        ])
        .output()
        .ok()?;
    let _ = std::fs::remove_file(&src);
    let _ = std::fs::remove_file(&lsrc);
    if !lout.status.success() || !out.status.success() {
        return None;
    }
    Some((bin.to_str()?.to_string(), lib.to_str()?.to_string()))
}

fn opts_for(bin: &str, lib: &str) -> LaunchOptions {
    LaunchOptions {
        executable: bin.to_string(),
        args: vec![lib.to_string()],
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
    lib: String,
    pid: u32,
}

impl Target {
    /// Launch and resume to the FIRST `raise(SIGTRAP)` — before `dlopen`.
    async fn start(tag: &str) -> Option<Self> {
        let (bin, lib) = build_fixture(tag)?;
        let dbg = LinuxDebugger::new();
        let pid = dbg
            .launch(opts_for(&bin, &lib))
            .await
            .expect("the dlopen fixture must launch under ptrace");
        let t = Self {
            dbg,
            bin,
            lib,
            pid: pid.0,
        };
        t.resume_past_noise().await;
        Some(t)
    }

    /// Resume once, then keep resuming while the stop is only a thread birth.
    ///
    /// Bounded on purpose: resuming *until* a condition holds would hang
    /// forever on a kernel that stops delivering, and a hang is not a failure
    /// anyone can read.
    async fn resume_past_noise(&self) {
        let mut ev = tokio::time::timeout(Duration::from_secs(30), self.dbg.continue_execution())
            .await
            .expect("continue_execution must not hang")
            .expect("continue_execution must not error");
        for _ in 0..64 {
            match ev.reason {
                StopReason::ThreadCreate { .. } => {
                    ev =
                        tokio::time::timeout(Duration::from_secs(30), self.dbg.continue_execution())
                            .await
                            .expect("continue_execution must not hang")
                            .expect("continue_execution must not error");
                }
                _ => break,
            }
        }
    }

    /// The raw `/proc/<pid>/maps` of the tracee, read independently of the
    /// crate — the ground truth every assertion here is checked against.
    fn raw_maps(&self) -> String {
        std::fs::read_to_string(format!("/proc/{}/maps", self.pid))
            .expect("/proc/<pid>/maps must be readable for our own tracee")
    }

    /// End the session through the debugger itself.
    ///
    /// Not politeness: the backend reaps with a process-global
    /// `waitpid(-1, __WALL)`, so a live event loop from a finished test can
    /// steal the next test's stops.
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
        let _ = std::fs::remove_file(&self.lib);
    }
}

macro_rules! live {
    ($tag:expr) => {
        match Target::start($tag).await {
            Some(t) => t,
            None => {
                eprintln!("skipping: no working `cc` on this machine");
                return;
            }
        }
    };
}

/// `(base, r, w, x)` for every line of a raw `/proc/<pid>/maps`, parsed here so
/// the crate's parser is compared against something it did not write.
fn raw_perms(raw: &str) -> HashMap<u64, (bool, bool, bool)> {
    raw.lines()
        .filter_map(|l| {
            let mut it = l.split_whitespace();
            let base = u64::from_str_radix(it.next()?.split('-').next()?, 16).ok()?;
            let p = it.next()?.as_bytes();
            Some((base, (p[0] == b'r', p[1] == b'w', p[2] == b'x')))
        })
        .collect()
}

// ─────────────────────────────────────────────────────────────────────────────
// dlopen
// ─────────────────────────────────────────────────────────────────────────────

/// The map is a VIEW, not a snapshot taken at launch: after the target
/// `dlopen`s a library, `memory_maps()` must show regions backed by that file
/// which were absent one stop earlier, and `modules()` must gain exactly that
/// module.
///
/// This is the property that makes the API usable on a live process at all. A
/// backend that cached `/proc/<pid>/maps` once would satisfy every static
/// assertion in the existing suite and still be unable to tell you where the
/// plugin you just loaded ended up — and every address in it would resolve to
/// "unknown".
#[tokio::test]
async fn dlopen_adds_the_library_to_maps_and_modules() {
    let t = live!("dlopen");

    let before = t
        .dbg
        .memory_maps()
        .await
        .expect("memory_maps() before dlopen");
    let mods_before = t.dbg.modules().await.expect("modules() before dlopen");
    assert!(
        !before
            .iter()
            .any(|m| m.file_path.as_deref() == Some(t.lib.as_str())),
        "the library must NOT be mapped before the fixture calls dlopen"
    );
    assert!(
        !mods_before.iter().any(|m| m.path == t.lib),
        "modules() must not list a library the process has not loaded yet"
    );

    // Run to the second raise(SIGTRAP): the library is now open.
    t.resume_past_noise().await;

    let after = t
        .dbg
        .memory_maps()
        .await
        .expect("memory_maps() after dlopen");
    let lib_regions: Vec<_> = after
        .iter()
        .filter(|m| m.file_path.as_deref() == Some(t.lib.as_str()))
        .collect();
    assert!(
        !lib_regions.is_empty(),
        "after dlopen the library must appear in memory_maps(); the target's own \
         /proc maps says:\n{}",
        t.raw_maps()
    );
    assert!(
        after.len() > before.len(),
        "loading a library adds mappings: {} regions before, {} after",
        before.len(),
        after.len()
    );

    let mods_after = t.dbg.modules().await.expect("modules() after dlopen");
    let lib_mod = mods_after
        .iter()
        .find(|m| m.path == t.lib)
        .expect("modules() must report the dlopened library");
    assert!(
        !lib_mod.is_main,
        "a dlopened library is not the main executable"
    );
    let base_name = std::path::Path::new(&t.lib)
        .file_name()
        .and_then(|s| s.to_str())
        .expect("the library path has a basename");
    assert_eq!(
        lib_mod.name, base_name,
        "the module name is the basename of its path"
    );

    // The reported base/size must really span every region of that file.
    let lo = lib_regions
        .iter()
        .map(|m| m.base.0)
        .min()
        .expect("at least one region");
    let hi = lib_regions
        .iter()
        .map(|m| m.base.0 + m.size)
        .max()
        .expect("at least one region");
    assert_eq!(
        lib_mod.base.0, lo,
        "the module base is the lowest mapping of the file"
    );
    assert_eq!(
        lib_mod.base.0 + lib_mod.size,
        hi,
        "the module extent must cover the file's highest mapping"
    );

    t.shutdown().await;
}

/// A freshly `dlopen`ed object must be mapped with the permission split any
/// loaded ELF has: at least one executable region (its text) and at least one
/// writable non-executable region (its data/GOT), and never a region that is
/// both writable and executable.
///
/// Permissions are what make an address answerable ("can I plant a breakpoint
/// here", "will a write fault"). A parser that filled the three bools from the
/// wrong column would still list the right bases and pass a base-only check.
#[tokio::test]
async fn dlopened_library_regions_carry_a_real_permission_split() {
    let t = live!("perm");
    t.resume_past_noise().await; // to stop 2 — library loaded

    let maps = t.dbg.memory_maps().await.expect("memory_maps()");
    let lib: Vec<_> = maps
        .iter()
        .filter(|m| m.file_path.as_deref() == Some(t.lib.as_str()))
        .collect();
    assert!(!lib.is_empty(), "the library must be mapped at stop 2");
    assert!(
        lib.iter().any(|m| m.executable && m.readable && !m.writable),
        "a loaded shared object has an r-x text region; got {:?}",
        lib.iter()
            .map(|m| (m.base.0, m.readable, m.writable, m.executable))
            .collect::<Vec<_>>()
    );
    assert!(
        lib.iter().any(|m| m.writable && !m.executable),
        "a loaded shared object has a writable data region; got {:?}",
        lib.iter()
            .map(|m| (m.base.0, m.readable, m.writable, m.executable))
            .collect::<Vec<_>>()
    );
    for m in &lib {
        assert!(
            !(m.writable && m.executable),
            "region {:#x} of {} is reported W+X, which the loader does not create",
            m.base.0,
            t.lib
        );
        assert!(m.size > 0, "a mapping of zero bytes is not a mapping: {m:?}");
    }

    t.shutdown().await;
}

// ─────────────────────────────────────────────────────────────────────────────
// permissions, region by region
// ─────────────────────────────────────────────────────────────────────────────

/// Every region's `readable`/`writable`/`executable` triple must equal the
/// kernel's own `perms` column for the SAME base — checked per region, not by
/// "some region is executable".
///
/// An aggregate check ("at least one r-x exists") passes even when the bits are
/// shifted by a column for every line, because some line will have the shifted
/// bit set anyway. Pairing base to base is what makes the comparison real.
#[tokio::test]
async fn every_region_permission_matches_the_kernel() {
    let t = live!("permmap");
    let raw = t.raw_maps();
    let maps = t.dbg.memory_maps().await.expect("memory_maps()");
    let truth = raw_perms(&raw);

    assert!(!maps.is_empty(), "a live process always has mappings");
    let mut compared = 0usize;
    for m in &maps {
        let Some(&(r, w, x)) = truth.get(&m.base.0) else {
            panic!(
                "memory_maps() reported base {:#x}, absent from /proc maps",
                m.base.0
            );
        };
        assert_eq!(
            (m.readable, m.writable, m.executable),
            (r, w, x),
            "permissions disagree at {:#x}: crate says r={} w={} x={}, kernel says r={r} w={w} x={x}",
            m.base.0,
            m.readable,
            m.writable,
            m.executable
        );
        compared += 1;
    }
    // Guard against a vacuous pass: the loop above proves nothing if the map
    // were empty, and the three flags must not be constant across the process.
    assert_eq!(
        compared,
        maps.len(),
        "every reported region must be compared"
    );
    assert!(
        maps.iter().any(|m| m.executable) && maps.iter().any(|m| !m.executable),
        "the executable bit must vary across a real process's regions"
    );
    assert!(
        maps.iter().any(|m| m.writable) && maps.iter().any(|m| !m.writable),
        "the writable bit must vary across a real process's regions"
    );

    t.shutdown().await;
}

// ─────────────────────────────────────────────────────────────────────────────
// stack and heap
// ─────────────────────────────────────────────────────────────────────────────

/// `[stack]` and `[heap]` must be recognised as such, be writable and not
/// executable, and cover the addresses they claim to: the stopped thread's SP
/// must fall inside the region named `[stack]`.
///
/// Naming a region is not enough — the name is only useful if it is attached to
/// the right address range. The SP cross-check is what makes "this is the
/// stack" verifiable rather than asserted.
#[tokio::test]
async fn stack_and_heap_are_recognised_and_placed_correctly() {
    let t = live!("stackheap");
    let raw = t.raw_maps();
    let maps = t.dbg.memory_maps().await.expect("memory_maps()");

    let stack = maps
        .iter()
        .find(|m| m.name.as_deref() == Some("[stack]"))
        .unwrap_or_else(|| panic!("no [stack] region reported; kernel says:\n{raw}"));
    assert!(
        stack.writable && stack.readable,
        "the stack is readable and writable: {stack:?}"
    );
    assert!(
        !stack.executable,
        "a modern kernel maps the stack non-executable: {stack:?}"
    );

    // The fixture mallocs before its first trap, so [heap] genuinely exists.
    assert!(
        raw.lines().any(|l| l.ends_with("[heap]")),
        "the fixture must have a heap by its first stop; kernel says:\n{raw}"
    );
    let heap = maps
        .iter()
        .find(|m| m.name.as_deref() == Some("[heap]"))
        .expect("the [heap] line exists in /proc, so memory_maps() must report it");
    assert!(
        heap.writable && heap.readable,
        "the heap is readable and writable: {heap:?}"
    );
    assert!(!heap.executable, "the heap must not be executable: {heap:?}");
    assert!(heap.size > 0, "a zero-length heap is not a heap");

    // The stopped thread's SP must land in the region called [stack].
    let tid = t.dbg.current_thread().await.expect("current_thread()");
    let regs = t.dbg.get_registers(tid).await.expect("get_registers()");
    assert!(
        regs.sp >= stack.base.0 && regs.sp < stack.base.0 + stack.size,
        "SP {:#x} is not inside the region named [stack] ({:#x}..{:#x})",
        regs.sp,
        stack.base.0,
        stack.base.0 + stack.size
    );

    t.shutdown().await;
}

// ─────────────────────────────────────────────────────────────────────────────
// pathless regions must not become modules
// ─────────────────────────────────────────────────────────────────────────────

/// A region with no backing file — anonymous memory, `[stack]`, `[heap]`,
/// `[vdso]`, `[vvar]` — must never be reported as a module, and every module
/// that IS reported must name a real file on disk.
///
/// The failure this guards against is an invented name: promoting `[heap]` to a
/// module called "heap", or synthesising `module_7f...` for anonymous memory,
/// makes every consumer (symbolication, address→module attribution)
/// confidently wrong, and unlike a missing module it produces no error to
/// notice.
#[tokio::test]
async fn pathless_regions_are_never_promoted_to_modules() {
    let t = live!("pathless");
    t.resume_past_noise().await; // library loaded too, so both kinds are present

    let maps = t.dbg.memory_maps().await.expect("memory_maps()");
    let mods = t.dbg.modules().await.expect("modules()");

    // The process really does contain pathless regions, otherwise this test
    // asserts over an empty set.
    let pathless: Vec<_> = maps
        .iter()
        .filter(|m| {
            m.file_path
                .as_deref()
                .is_none_or(|p| p.is_empty() || p.starts_with('['))
        })
        .collect();
    assert!(
        !pathless.is_empty(),
        "a live process always has anonymous or pseudo regions to test against"
    );

    for m in &mods {
        assert!(
            !m.path.is_empty(),
            "a module with an empty path was invented: {m:?}"
        );
        assert!(
            !m.path.starts_with('['),
            "the pseudo-region {} was promoted to a module: {m:?}",
            m.path
        );
        assert!(
            !m.name.starts_with('['),
            "a module was named after a pseudo-region: {m:?}"
        );
        assert!(
            m.path.starts_with('/'),
            "a module path must be absolute, not {:?}",
            m.path
        );
        assert!(
            std::path::Path::new(&m.path).exists(),
            "module {} claims a backing file that does not exist on disk",
            m.path
        );
        assert_ne!(m.base.0, 0, "a mapped module cannot be based at 0: {m:?}");
    }

    // No module may be based inside a region that has no file behind it.
    for m in &mods {
        if let Some(r) = maps
            .iter()
            .find(|r| m.base.0 >= r.base.0 && m.base.0 < r.base.0 + r.size)
        {
            assert!(
                r.file_path
                    .as_deref()
                    .is_some_and(|p| !p.is_empty() && !p.starts_with('[')),
                "module {} is based in a region with no backing file: {r:?}",
                m.name
            );
        }
    }

    // And each distinct backing file is reported exactly once.
    let mut paths: Vec<&str> = mods.iter().map(|m| m.path.as_str()).collect();
    paths.sort_unstable();
    let n = paths.len();
    paths.dedup();
    assert_eq!(paths.len(), n, "modules() must report each mapped file once");

    t.shutdown().await;
}

/// Every file-backed region in the map must belong to a reported module, and
/// every module's extent must contain each of its own regions.
///
/// `memory_maps()` and `modules()` read the SAME `/proc` lines with different
/// column counts, and that pair has drifted before. Loading a library at
/// runtime is the moment they can drift again, so the cross-check is done at
/// the post-`dlopen` stop.
#[tokio::test]
async fn every_file_backed_region_belongs_to_a_module() {
    let t = live!("cover");
    t.resume_past_noise().await;

    let maps = t.dbg.memory_maps().await.expect("memory_maps()");
    let mods = t.dbg.modules().await.expect("modules()");
    let mut checked = 0usize;
    for r in &maps {
        let Some(path) = r.file_path.as_deref() else {
            continue;
        };
        if path.starts_with('[') || path.is_empty() {
            continue;
        }
        let m = mods
            .iter()
            .find(|m| m.path == path)
            .unwrap_or_else(|| panic!("region {:#x} of {path} belongs to no module", r.base.0));
        assert!(
            r.base.0 >= m.base.0 && r.base.0 + r.size <= m.base.0 + m.size,
            "region {:#x}..{:#x} of {path} lies outside its module's extent {:#x}..{:#x}",
            r.base.0,
            r.base.0 + r.size,
            m.base.0,
            m.base.0 + m.size
        );
        checked += 1;
    }
    assert!(checked > 0, "a live process always has file-backed regions");

    t.shutdown().await;
}
