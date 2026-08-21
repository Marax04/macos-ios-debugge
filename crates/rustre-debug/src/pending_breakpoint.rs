//! `pending_breakpoint` — breakpoints on code that is not mapped yet.
//!
//! ## Why this exists
//!
//! "Break at `libssl.so + 0x2f40`" is only expressible once `libssl.so` is in
//! the address space. Every mature debugger therefore lets you ask *before* the
//! module exists and arms the trap at load time — gdb's pending breakpoints,
//! lldb's, WinDbg's `bu`. Without it, breaking on plugin, JIT-host or
//! lazily-`dlopen`ed code means racing the target by hand, which on a fast
//! startup path simply cannot be won.
//!
//! ## Discipline
//!
//! A request is matched against the **basename** of the loaded path, because
//! the loader reports a full path (`/usr/lib/libssl.so.3`,
//! `C:\Windows\System32\ntdll.dll`) while a human asks for `libssl.so.3` or
//! `ntdll.dll`. Matching is case-insensitive **only where the OS filesystem is**
//! (Windows and macOS), so `NTDLL.DLL` and `ntdll.dll` are one module there and
//! two distinct ones on Linux, which is the truth on each platform rather than
//! a convenient uniformity.
//!
//! Nothing here guesses an address: a request is resolved *only* when a load
//! event names its module, and [`PendingBreakpoints::resolve_on_load`] returns
//! the addresses it actually computed. A request whose module never loads stays
//! pending and is reported as such — it is never quietly dropped, and it never
//! becomes an address.

use std::collections::HashMap;

/// A breakpoint requested on a module that may not be loaded yet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingRequest {
    /// Module basename as the caller wrote it (`libssl.so.3`, `ntdll.dll`).
    pub module: String,
    /// Offset from the module's load base.
    pub offset: u64,
}

impl PendingRequest {
    /// A request for `offset` bytes into `module`.
    #[must_use]
    pub fn new(module: impl Into<String>, offset: u64) -> Self {
        Self { module: module.into(), offset }
    }
}

/// Basename of a loader-reported path, handling both separators.
///
/// A Windows debuggee reports `C:\Windows\System32\ntdll.dll` and a Linux one
/// `/usr/lib/libc.so.6`; splitting on only one separator leaves the other
/// platform's whole path as the "basename", which then matches nothing.
#[must_use]
pub fn module_basename(path: &str) -> &str {
    let after_slash = path.rsplit('/').next().unwrap_or(path);
    after_slash.rsplit('\\').next().unwrap_or(after_slash)
}

/// Whether module names compare case-insensitively on this target.
///
/// Windows and macOS ship case-insensitive filesystems by default; Linux does
/// not. Answering uniformly either way would be wrong on some platform.
#[must_use]
pub const fn module_names_are_case_insensitive() -> bool {
    cfg!(any(target_os = "windows", target_os = "macos"))
}

fn same_module(a: &str, b: &str) -> bool {
    if module_names_are_case_insensitive() {
        a.eq_ignore_ascii_case(b)
    } else {
        a == b
    }
}

/// The set of breakpoint requests waiting for their module.
#[derive(Debug, Default)]
pub struct PendingBreakpoints {
    requests: Vec<PendingRequest>,
    /// Load base of each module currently mapped, keyed by basename.
    loaded: HashMap<String, u64>,
}

impl PendingBreakpoints {
    /// An empty table.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a request.
    ///
    /// Returns `Some(address)` when the module is **already** loaded, so the
    /// caller can arm it immediately: a request made after the load must not
    /// wait for a reload that may never come. Returns `None` when it stays
    /// pending.
    pub fn add(&mut self, req: PendingRequest) -> Option<u64> {
        let already = self
            .loaded
            .iter()
            .find(|(name, _)| same_module(name, &req.module))
            .map(|(_, base)| *base);
        let resolved = already.and_then(|base| base.checked_add(req.offset));
        self.requests.push(req);
        resolved
    }

    /// Record that `path` is mapped at `base` WITHOUT arming anything.
    ///
    /// [`Self::add`] answers "is this module already here?" from `loaded`, and
    /// `loaded` was only ever written by [`Self::resolve_on_load`] — which is
    /// driven by a `StopReason::LibraryLoad` event that **no backend has ever
    /// constructed**. So `loaded` was permanently empty, `add` always answered
    /// "not yet", and every pending request waited for a load event that could
    /// not arrive: the whole feature reported success and did nothing.
    ///
    /// This lets a backend seed the table from `modules()`, which all three do
    /// implement, so a request naming a module that IS already mapped resolves
    /// straight away instead of waiting forever.
    ///
    /// Deliberately separate from `resolve_on_load`: seeding must not re-arm
    /// every request recorded so far, which is what a load event means and a
    /// snapshot does not.
    pub fn note_module_loaded(&mut self, path: &str, base: u64) {
        self.loaded.insert(module_basename(path).to_string(), base);
    }

    /// Requests still waiting for their module, in insertion order.
    #[must_use]
    pub fn pending(&self) -> &[PendingRequest] {
        &self.requests
    }

    /// Number of requests still waiting.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.requests.len()
    }

    /// Whether nothing is waiting.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.requests.is_empty()
    }

    /// Record that `path` was mapped at `base` and return the addresses that
    /// become armable because of it.
    ///
    /// Requests are **kept**, not consumed: a library can be unloaded and
    /// loaded again — at a different base, under ASLR — and a breakpoint the
    /// caller asked for must come back with it. Dropping the request on first
    /// resolution is the defect that makes a breakpoint work exactly once.
    ///
    /// An offset that would overflow the address space resolves to nothing
    /// rather than to a wrapped address.
    pub fn resolve_on_load(&mut self, path: &str, base: u64) -> Vec<u64> {
        let name = module_basename(path).to_string();
        let mut armed = Vec::new();
        for req in &self.requests {
            if same_module(&req.module, &name)
                && let Some(addr) = base.checked_add(req.offset)
            {
                armed.push(addr);
            }
        }
        self.loaded.insert(name, base);
        armed
    }

    /// Record that `path` was unmapped and return the addresses whose traps are
    /// now stale.
    ///
    /// The trap bytes went away with the mapping, so the caller must forget
    /// them; leaving them armed would report a hit for an address that no
    /// longer belongs to that module, or restore a "saved original byte" over
    /// whatever gets mapped there next.
    pub fn resolve_on_unload(&mut self, path: &str) -> Vec<u64> {
        let name = module_basename(path).to_string();
        let Some(base) = self
            .loaded
            .iter()
            .find(|(n, _)| same_module(n, &name))
            .map(|(n, b)| (n.clone(), *b))
        else {
            return Vec::new();
        };
        self.loaded.remove(&base.0);
        let base = base.1;
        self.requests
            .iter()
            .filter(|r| same_module(&r.module, &name))
            .filter_map(|r| base.checked_add(r.offset))
            .collect()
    }

    /// Drop every request for `module`, returning how many were removed.
    pub fn remove_module(&mut self, module: &str) -> usize {
        let before = self.requests.len();
        self.requests.retain(|r| !same_module(&r.module, module));
        before - self.requests.len()
    }

    /// Forget everything. Used when a session ends.
    pub fn clear(&mut self) {
        self.requests.clear();
        self.loaded.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basename_handles_both_path_separators() {
        assert_eq!(module_basename("/usr/lib/libc.so.6"), "libc.so.6");
        assert_eq!(
            module_basename(r"C:\Windows\System32\ntdll.dll"),
            "ntdll.dll"
        );
        assert_eq!(module_basename("libfoo.so"), "libfoo.so");
        // A mixed path is what a Windows debuggee under a POSIX-ish toolchain
        // actually reports; the last separator of either kind wins.
        assert_eq!(module_basename("C:/msys64/usr/bin/msys-2.0.dll"), "msys-2.0.dll");
    }

    /// A request made before the load must arm at the load, at the base the
    /// loader reports — not at the offset alone, which under ASLR points into
    /// unrelated memory or at nothing at all.
    #[test]
    fn a_request_resolves_at_the_reported_load_base() {
        let mut p = PendingBreakpoints::new();
        assert_eq!(p.add(PendingRequest::new("libssl.so.3", 0x2f40)), None);
        let armed = p.resolve_on_load("/usr/lib/x86_64-linux-gnu/libssl.so.3", 0x7f00_0000_0000);
        assert_eq!(armed, vec![0x7f00_0000_2f40]);
    }

    /// The defect this test exists to prevent: consuming the request on the
    /// first resolution makes the breakpoint work exactly once. A library that
    /// is unloaded and loaded again — a plugin host does this every reload —
    /// must get its trap back, at the NEW base.
    #[test]
    fn a_request_survives_unload_and_rearms_at_the_new_base() {
        let mut p = PendingBreakpoints::new();
        p.add(PendingRequest::new("plugin.dll", 0x100));
        assert_eq!(p.resolve_on_load(r"C:\app\plugin.dll", 0x1000), vec![0x1100]);

        let stale = p.resolve_on_unload(r"C:\app\plugin.dll");
        assert_eq!(stale, vec![0x1100], "the trap at the old base is now stale");

        // Reloaded elsewhere: the same request must resolve again, and to the
        // new address.
        assert_eq!(
            p.resolve_on_load(r"C:\app\plugin.dll", 0x9000),
            vec![0x9100],
            "the request was consumed on first use, so the breakpoint only ever worked once"
        );
        assert_eq!(p.len(), 1, "the request is kept, not duplicated");
    }

    /// Asking for a module that is already mapped must arm immediately. Waiting
    /// for a load event that already happened is an infinite wait dressed up as
    /// a pending breakpoint.
    #[test]
    fn a_request_for_an_already_loaded_module_resolves_immediately() {
        let mut p = PendingBreakpoints::new();
        p.resolve_on_load("/lib/libc.so.6", 0x4000);
        assert_eq!(p.add(PendingRequest::new("libc.so.6", 0x20)), Some(0x4020));
    }

    #[test]
    fn an_unrelated_load_arms_nothing() {
        let mut p = PendingBreakpoints::new();
        p.add(PendingRequest::new("libssl.so.3", 0x10));
        assert!(p.resolve_on_load("/lib/libcrypto.so.3", 0x5000).is_empty());
        assert_eq!(p.len(), 1, "the request stays pending, it is not dropped");
    }

    /// Case folding must follow the filesystem, not convenience.
    #[test]
    fn case_sensitivity_follows_the_platform() {
        let mut p = PendingBreakpoints::new();
        p.add(PendingRequest::new("NtDll.Dll", 0x10));
        let armed = p.resolve_on_load(r"C:\Windows\System32\ntdll.dll", 0x1000);
        if module_names_are_case_insensitive() {
            assert_eq!(armed, vec![0x1010]);
        } else {
            assert!(armed.is_empty(), "on a case-sensitive fs these are two files");
        }
    }

    /// An offset past the end of the address space resolves to nothing rather
    /// than wrapping to a small address, where a trap would be planted in
    /// whatever happens to live there.
    #[test]
    fn an_overflowing_offset_resolves_to_no_address() {
        let mut p = PendingBreakpoints::new();
        p.add(PendingRequest::new("m.so", u64::MAX));
        assert!(p.resolve_on_load("/m.so", 0x1000).is_empty());
    }

    /// A snapshot of what is mapped must let an already-loaded module resolve.
    ///
    /// `add` asks `loaded`, and `loaded` was only ever written by
    /// `resolve_on_load` — driven by a `LibraryLoad` event that no backend
    /// constructs. So it was permanently empty and every request, including one
    /// for a module sitting right there in `modules()`, waited forever while
    /// the API reported success.
    #[test]
    fn a_module_already_mapped_resolves_from_a_snapshot() {
        let mut p = PendingBreakpoints::new();
        p.note_module_loaded("/usr/lib/x86_64-linux-gnu/libssl.so.3", 0x7f00_0000_0000);
        assert_eq!(
            p.add(PendingRequest::new("libssl.so.3", 0x2f40)),
            Some(0x7f00_0000_2f40),
            "a module named by the snapshot must resolve immediately"
        );
    }

    /// Seeding is NOT a load event: it must not re-arm requests already made.
    ///
    /// Calling `resolve_on_load` to seed would return every matching request
    /// recorded so far, so refreshing the snapshot before each new request
    /// would re-plant every earlier one.
    #[test]
    fn noting_a_module_does_not_re_arm_earlier_requests() {
        let mut p = PendingBreakpoints::new();
        p.note_module_loaded("/lib/libc.so.6", 0x4000);
        p.add(PendingRequest::new("libc.so.6", 0x10));
        // A second snapshot of the same module: nothing is re-armed, because
        // nothing was loaded again.
        p.note_module_loaded("/lib/libc.so.6", 0x4000);
        assert_eq!(p.len(), 1);
        // A real load event, by contrast, DOES re-arm.
        assert_eq!(p.resolve_on_load("/lib/libc.so.6", 0x4000), vec![0x4010]);
    }

    /// A module the snapshot does not name stays unresolved, so the caller can
    /// be told the truth instead of a success.
    #[test]
    fn a_module_absent_from_the_snapshot_does_not_resolve() {
        let mut p = PendingBreakpoints::new();
        p.note_module_loaded("/lib/libc.so.6", 0x4000);
        assert_eq!(p.add(PendingRequest::new("libssl.so.3", 0x10)), None);
        assert_eq!(p.len(), 1, "the request is kept so it can arm later");
    }

    #[test]
    fn remove_module_and_clear_forget_requests() {
        let mut p = PendingBreakpoints::new();
        p.add(PendingRequest::new("a.so", 1));
        p.add(PendingRequest::new("a.so", 2));
        p.add(PendingRequest::new("b.so", 3));
        assert_eq!(p.remove_module("a.so"), 2);
        assert_eq!(p.len(), 1);
        p.clear();
        assert!(p.is_empty());
    }
}
